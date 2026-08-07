#!/usr/bin/env python3
"""
A disabled feature must not cost anything on the hot path.

THE REGRESSION (introduced by the 2026-08-07 novelty-gate fix, found by external
review the same day). That fix passed the agent verdict into `observe()`:

    self.recon.observe(pid, dest, delta, now, name=rname,
                       is_agent=bool(self._agent_for(rname, pid)[0]))

`is_agent=...` is an ARGUMENT, so it is evaluated before the call -- and
therefore before `observe()`'s own `if not self._active: return`. So the ancestry
walk ran for every flow even when reconciliation was off, which is the DEFAULT
state: nothing writes the declaration contract yet (PRE-FLIGHT §3).

Measured: 40 ordinary browser flows in one tick, reconciliation inactive, 40
`proctree.attribute` calls. Cold cache, each is the process plus up to six
ancestors, i.e. up to seven `ps` forks.

Three reasons this is not pedantry:
  - It silently undid an explicit decision. `sentinel.py` still carries the
    comment "P1-D preserved: cheap ledger/heuristic checks BEFORE the ps fork".
  - Its cost scales with pid churn, and pid churn IS the target workload: an
    agent shelling out to git/npm/curl/MCP is the entire reason proctree exists.
  - This project swapped to streaming nettop to take CPU from 10.7% to 1.8%,
    the change that "makes 1 s affordable for a menu-bar app". Per-flow forks at
    1 Hz eat that back.

The general lesson, which is why this file exists at all rather than a one-line
diff: **the cost a fix introduces was not measured alongside the fix.** Same
family as everything else in this repo's list -- an instrument that is not
watching the thing it changed -- but about cost, not correctness.

Run:  python3 tests/test_observe_cost.py
"""
import pathlib
import sys
import tempfile
import threading
import time
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import activity                                                      # noqa: E402
import proctree                                                      # noqa: E402
import sentinel as S                                                 # noqa: E402
import deadman                                                       # noqa: E402
from ledger import (DestLedger, CovertChannelDetector,               # noqa: E402
                    DestinationFanout)

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


def run(active, proxy=None, n=40):
    """ONE REAL `Sampler._tick`; returns the ancestry-walk count.

    Drives the actual `_tick`, not a copy of its observe closure. The first
    version of this file reimplemented that closure in the harness -- so it
    asserted the fix against a hand-written duplicate of the fix and passed on
    the UNFIXED code. A test that copies the logic under test measures nothing,
    which is the failure this whole file is about, committed inside it.
    """
    calls = {"n": 0}
    real_attr, real_beat = proctree.attribute, deadman.beat
    proctree.attribute = lambda name, pid, match: (
        calls.__setitem__("n", calls["n"] + 1), (None, None))[1]
    deadman.beat = lambda *_a, **_k: None
    try:
        d = pathlib.Path(tempfile.mkdtemp()) / "activity.ndjson"
        if active:
            d.write_text(
                '{"ts": 1, "pid": 1, "tool": "t", "target": "x.example"}\n',
                encoding="utf-8")

        s = S.Sampler.__new__(S.Sampler)
        s.sni = types.SimpleNamespace(domain_for_ip=lambda ip: "cdn.example.com")
        s.out, s.lock = [], threading.Lock()
        s.baseline, s.seen_ts, s.agent_cache, s.last_emit = {}, {}, {}, {}
        s.warmup = False
        s.ledger = DestLedger(burst_bytes=S.FLAG_BYTES, drain_rate=S.DRAIN_RATE)
        s.chan, s.fan = CovertChannelDetector(), DestinationFanout()
        s.recon = activity.Reconciler(path=d, proxy=proxy)
        s.recon_state, s.fallbacks = None, 0

        # A stream whose snapshot is n ordinary browser flows to one CDN.
        s.stream = S.NettopStream.__new__(S.NettopStream)
        s.stream._lock = threading.Lock()
        s.stream._latest = {("chrome", str(1000 + i), f"198.51.100.{i}", f"c{i}"):
                            (S.Bytes(5000, 0), time.time()) for i in range(n)}

        s._tick()
        assert s.recon.active is active, "fixture broken: wrong active state"
        return calls["n"]
    finally:
        proctree.attribute, deadman.beat = real_attr, real_beat


# --- the regression ----------------------------------------------------------
off = run(active=False)
check(off == 0,
      f"reconciliation OFF (the default -- nothing writes the contract yet) costs "
      f"ZERO ancestry walks over 40 flows, got {off}")

# --- positive control: the gate must not have turned the feature off ----------
# Asserting only "no walks when off" would be satisfied by never walking at all,
# which is this repo's signature failure. So the on-case is asserted too.
on = run(active=True)
check(on > 0,
      f"reconciliation ON still walks (got {on}) -- otherwise this test would be "
      f"satisfied by a gate that disabled the feature outright")
check(on == 40,
      f"and walks once per flow with a cold cache, not more (got {on})")

# --- the cache is what makes the ON case affordable --------------------------
one_pid = {"n": 0}
_real = proctree.attribute
proctree.attribute = lambda name, pid, match: (
    one_pid.__setitem__("n", one_pid["n"] + 1), ("claude", None))[1]
try:
    s = S.Sampler.__new__(S.Sampler)
    s.agent_cache = {}
    for _ in range(50):
        s._agent_for("claude", "4242")
finally:
    proctree.attribute = _real
check(one_pid["n"] == 1,
      f"50 lookups of one pid cost ONE walk (got {one_pid['n']}) -- the per-pid "
      f"cache is why the enabled path is affordable, and it is why the disabled "
      f"path being uncached mattered")

# --- proxy mode: the 'ai' branch has the same shape --------------------------
ai_off = run(active=False, proxy="127.0.0.1:8080")
check(ai_off == 0,
      "with a proxy configured but reconciliation still off, the 'ai' branch "
      "costs nothing either -- it was guarded on `proxy` but not on `active`")


def test_observe_cost():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
