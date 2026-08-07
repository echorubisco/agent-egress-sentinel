#!/usr/bin/env python3
"""
Only agent-lineage traffic may seed the novelty baseline.

THE BUG (found by external review 2026-08-07). `_is_novel`'s own docstring asks
"Has any AGENT-LINEAGE flow gone to this destination before?" and the README
promises "a destination nothing in an agent lineage has contacted before". But
`observe()` recorded `_seen_dests[dest] = now` for EVERY flow it was handed, and
`aggregate_flows` hands it every non-AI flow on the machine -- browsers, EDR, OS
telemetry. So any destination Chrome had touched became "known" to the agent
path, which drops the floor from NOVEL_MIN_BYTES (0) to KNOWN_MIN_BYTES (64 KB).

Measured before the fix: floor 0 for an untouched destination, **65536 after one
chrome.exe flow to it**. An agent's 4 KB credential POST to that host went from
reported to discarded.

That is the MIN_BYTES=64KB bug again -- blind to exactly the payload class the
module exists to catch -- and it grew inside that bug's own fix. The root cause
was already written down: ROADMAP 2026-08-02 records that `aggregate_flows`
feeds every non-AI flow to `observe`, and the gate is applied at drain time. The
report path got gated on 08-02; the novelty baseline added on 08-03 sits on the
ungated side.

Run:  python3 tests/test_novelty_gate.py
"""
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import activity                                                      # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


DEST = "gist.githubusercontent.com"
T0 = 1_000_000.0
T = T0 + 200          # past NOVELTY_WARMUP_SEC (120); see note below

_dir = pathlib.Path(tempfile.mkdtemp())
_log = _dir / "activity.ndjson"
_log.write_text(json.dumps({"ts": T0, "pid": 1, "tool": "WebFetch",
                            "target": "example.com"}) + "\n", encoding="utf-8")


def rec():
    """A reconciler that is BORN in the past and ACTIVE.

    Both are load-bearing and both cost a wrong answer if forgotten -- verifying
    this bug took three attempts for exactly that reason. A reconciler born at
    `time.time()` is inside NOVELTY_WARMUP_SEC forever relative to a synthetic
    clock, so `_is_novel` returns False and every destination looks known; and
    `observe()` returns immediately unless `refresh()` has found a fresh
    declaration file, so nothing is recorded at all. Either mistake produces a
    clean-looking negative result from an instrument that measured nothing.
    """
    r = activity.Reconciler(path=_log, now=T0)
    r.refresh(now=T)
    assert r._active, "fixture broken: reconciler inactive, observe() would no-op"
    assert r._is_novel("never-seen.example", T), \
        "fixture broken: still inside novelty warmup, every dest reads as known"
    return r


# --- the regression ----------------------------------------------------------
control = rec()
check(control.floor_for(DEST, T) == control.NOVEL_MIN_BYTES,
      "an untouched destination is novel (floor 0)")

r = rec()
r.observe(4242, DEST, 300_000, now=T, name="chrome.exe", is_agent=False)
check(r.floor_for(DEST, T + 1) == r.NOVEL_MIN_BYTES,
      f"a BROWSER flow does not make the destination 'known' to the agent path "
      f"(floor is {r.floor_for(DEST, T + 1)}, want {r.NOVEL_MIN_BYTES})")

r = rec()
r.observe(777, DEST, 900_000, now=T, name="CSFalconService", is_agent=False)
check(r.floor_for(DEST, T + 1) == r.NOVEL_MIN_BYTES,
      "an EDR flow does not seed the baseline either -- on a real machine EDR "
      "and OS telemetry cover a large share of destinations, including shared "
      "CDN fronts")

r = rec()
r.observe(4242, DEST, 300_000, now=T, name="chrome.exe", is_agent=False)
check(4096 >= r.floor_for(DEST, T + 1),
      "an agent's 4 KB credential POST to a browser-visited host is still above "
      "the floor (SSH key 2-3 KB, cloud cred file ~4 KB, token a few hundred "
      "bytes -- the whole payload class this module exists for)")

# --- what must still hold ----------------------------------------------------
r = rec()
r.observe(100, DEST, 1000, now=T, name="claude", is_agent=True)
check(r.floor_for(DEST, T + 1) == r.KNOWN_MIN_BYTES,
      "an AGENT flow does seed the baseline -- a destination the agent already "
      "uses is genuinely not novel, and that is the noise control's whole job")

r = rec()
check(r.floor_for("brand-new.example", T) == r.NOVEL_MIN_BYTES,
      "an unrelated destination is unaffected")

# Novelty is frozen at observe time, deliberately: deciding it in drain() would
# always read 'seen', because the observation itself is what records it.
r = rec()
r.observe(100, DEST, 50, now=T, name="claude", is_agent=True)
pend = r._pending.get((100, DEST))
check(pend is not None and pend[4] is True,
      "the agent's FIRST flow to a destination is still frozen as novel at "
      "observe time, even though that same call records the destination")

# Default stays True so every existing caller and direct test is unchanged.
r = rec()
r.observe(100, DEST, 1000, now=T, name="claude")
check(r.floor_for(DEST, T + 1) == r.KNOWN_MIN_BYTES,
      "is_agent defaults to True, so callers that do not know the lineage keep "
      "the old behaviour rather than silently stopping the baseline")


def test_novelty_gate():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
