#!/usr/bin/env python3
"""
L1 <-> L3 reconciliation (activity.Reconciler).

The three properties that decide whether this feature is safe to ship at all
each get an assertion, because each one, if wrong, fails in a way that looks
like working software:

  1. FAIL-SAFE OFF -- no activity file (or a stale one) must produce NOTHING.
     If absence of declarations meant "everything is unexplained", a missing
     integration would become an alert storm.
  2. DELAYED VERDICT -- a declaration appended just after the bytes must still
     count, so nothing is reported before SETTLE_SEC.
  3. VOLUME NEVER GATES on its own -- a matching destination with a modest
     declared size is context, and the only magnitude report is a gross excess.

Plus the two documented DEFEATS, asserted so nobody later mistakes them for
strength: a target-less declaration is a wildcard, and an unresolved IP degrades
to pid-only matching.

Run:  python3 tests/test_reconcile.py     (no network, no nettop, tmp files only)
"""
import json
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from activity import Reconciler, _host                              # noqa: E402

KB = 1024
MB = 1024 * 1024
fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


def write(path, recs, mtime=None):
    with open(path, "w") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    if mtime is not None:
        import os
        os.utime(path, (mtime, mtime))


# Fixed process tree: 200 is a child of 100. Injected, so no real pids involved.
TREE = {200: 100, 100: 1}


def anc(pid):
    chain, cur = [pid], pid
    while cur in TREE and TREE[cur] > 1:
        cur = TREE[cur]
        chain.append(cur)
    return chain


tmp = pathlib.Path(tempfile.mkdtemp(prefix="recon-"))
NOW = 1_700_000_000.0
# Every Reconciler in this file is born 300 s before NOW so the novelty
# warmup (120 s) has elapsed and the conditional byte floor is actually
# exercised. Without this the default `_born = time.time()` sits in the
# FUTURE relative to the fixed NOW, warmup never ends, every destination
# reads as known, and the whole novelty path is silently untested -- which is
# how the old MIN_BYTES assertion kept passing after the floor was replaced.
BORN = NOW - 300

# --- 1. FAIL-SAFE: no file at all -------------------------------------------
r = Reconciler(now=BORN, path=tmp / "missing.ndjson")
check(r.refresh(NOW) is False and r.active is False,
      "no activity file -> reconciliation INACTIVE")
r.observe("200", "evil.example", 50 * MB, NOW)
check(r.unexplained("200", NOW + 600, ancestors=anc) is None,
      "with no activity file, 50 MB to an undeclared host reports NOTHING "
      "(absence of L1 is not evidence about L3)")

# --- 2. FAIL-SAFE: file exists but is stale ---------------------------------
stale = tmp / "stale.ndjson"
write(stale, [{"ts": NOW - 9999, "pid": 100, "tool": "fetch"}],
      mtime=NOW - Reconciler.FRESH_SEC - 60)
r = Reconciler(now=BORN, path=stale)
check(r.refresh(NOW) is False,
      "activity file older than FRESH_SEC -> INACTIVE (a dead integration must "
      "not look like a healthy quiet one)")
r.observe("200", "evil.example", 50 * MB, NOW)
check(r.unexplained("200", NOW + 600, ancestors=anc) is None,
      "stale L1 reports nothing either")

# --- 3. the actual signal: agent traffic nobody declared --------------------
live = tmp / "live.ndjson"
write(live, [{"ts": NOW, "pid": 100, "tool": "fetch",
              "target": "https://docs.example.com/a/b?k=secret"}], mtime=NOW)
r = Reconciler(now=BORN, path=live)
check(r.refresh(NOW) is True, "fresh activity file -> ACTIVE")
r.observe("200", "collector.evil.invalid", 5 * MB, NOW)
hit = r.unexplained("200", NOW + 60, ancestors=anc)
check(hit is not None and hit[0] == "collector.evil.invalid"
      and "no declared activity" in hit[2],
      "5 MB to a host no declaration mentions IS reported (the core signal)")
check(hit is not None and "first-time destination" in hit[2],
      "and the note says the destination is a first-time one -- novelty is the "
      "prior that now decides the byte floor, so it belongs in the text")

# --- 4. DELAYED VERDICT ------------------------------------------------------
r = Reconciler(now=BORN, path=live)
r.refresh(NOW)
r.observe("200", "late.example", 5 * MB, NOW)
check(r.unexplained("200", NOW + 1, ancestors=anc) is None,
      "nothing is reported before SETTLE_SEC -- a declaration may land after "
      "the bytes, and judging on sight would manufacture 'undeclared'")
check(r.unexplained("200", NOW + Reconciler.SETTLE_SEC + 1,
                    ancestors=anc) is not None,
      "after SETTLE_SEC the same observation does settle and report")

# --- 5. ancestry is the join key --------------------------------------------
# Declared by pid 100; the bytes come out of its child 200. Must reconcile.
r = Reconciler(now=BORN, path=live)
r.refresh(NOW)
r.observe("200", "docs.example.com", 5 * MB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is None,
      "a declaration by the PARENT explains a CHILD's traffic "
      "(kiro-cli declares, curl transmits)")

# An unrelated pid with the same destination is NOT covered by that declaration.
r = Reconciler(now=BORN, path=live)
r.refresh(NOW)
r.observe("999", "docs.example.com", 5 * MB, NOW)
check(r.unexplained("999", NOW + 60, ancestors=lambda p: [p]) is not None,
      "the same destination from an UNRELATED pid is still unexplained -- the "
      "declaration is scoped to a lineage, not global")

# --- 6. subdomain / URL handling --------------------------------------------
check(_host("https://user:pw@API.Example.com:443/x?y=1") == "api.example.com",
      "_host strips scheme, userinfo, port, path and query, and lowercases "
      "(a full URL can carry secrets and we would only be logging it)")
r = Reconciler(now=BORN, path=live)
r.refresh(NOW)
r.observe("200", "cdn.docs.example.com", 5 * MB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is None,
      "a subdomain of the declared host reconciles")

# --- 7. VOLUME: context, not a gate -----------------------------------------
small = tmp / "small.ndjson"
write(small, [{"ts": NOW, "pid": 100, "tool": "post",
               "target": "api.example.com", "bytes": 2 * KB}], mtime=NOW)
r = Reconciler(now=BORN, path=small)
r.refresh(NOW)
r.observe("200", "api.example.com", 200 * KB, NOW)      # 100x, but small
check(r.unexplained("200", NOW + 60, ancestors=anc) is None,
      "a declared 2 KB POST measured at 200 KB does NOT report: 100x on a tiny "
      "base is what framing and connection reuse look like. Needs an absolute "
      "excess above EXCESS_MIN_BYTES too")
r = Reconciler(now=BORN, path=small)
r.refresh(NOW)
r.observe("200", "api.example.com", 40 * MB, NOW)
hit = r.unexplained("200", NOW + 60, ancestors=anc)
check(hit is not None and "totalling ~2 KB" in hit[2],
      "a declared 2 KB POST measured at 40 MB DOES report, and the text names "
      "the declared total -- this is the case presence-only matching misses")

# declared volume is SUMMED over matching declarations (many-to-many join).
# Two declared 30 MB uploads explain 55 MB on one keep-alive connection.
summed = tmp / "summed.ndjson"
write(summed, [{"ts": NOW, "pid": 100, "tool": "put",
                "target": "api.example.com", "bytes": 30 * MB},
               {"ts": NOW, "pid": 100, "tool": "put",
                "target": "api.example.com", "bytes": 30 * MB}], mtime=NOW)
r = Reconciler(now=BORN, path=summed)
r.refresh(NOW)
r.observe("200", "api.example.com", 55 * MB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is None,
      "declared bytes are SUMMED across matching declarations: 2x30 MB explains "
      "55 MB on one reused connection (comparing against a single call's size "
      "would invent an excess)")

# if ANY matching declaration omits `bytes`, the declared total is unknown ->
# no excess can be computed, so nothing is reported on volume.
partial = tmp / "partial.ndjson"
write(partial, [{"ts": NOW, "pid": 100, "tool": "post",
                 "target": "api.example.com", "bytes": 2 * KB},
                {"ts": NOW, "pid": 100, "tool": "put",
                 "target": "api.example.com"}], mtime=NOW)
r = Reconciler(now=BORN, path=partial)
r.refresh(NOW)
r.observe("200", "api.example.com", 40 * MB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is None,
      "one matching declaration without `bytes` disables the volume check for "
      "that destination -- the declared total is unknown, and silence beats a "
      "number we made up")

# --- 8. trickles are ignored -------------------------------------------------
r = Reconciler(now=BORN, path=live)
r.refresh(NOW)
r.observe("200", "tiny.example", 4 * KB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is not None,
      "REGRESSION FIX (2026-08-03): 4 KB to a FIRST-TIME destination IS now "
      "reported. The old assertion here pinned the opposite and was WRONG: a "
      "flat 64 KB floor made this tool blind to ~/.aws/credentials (~4 KB), an "
      "SSH private key (2-3 KB) and a bearer token -- exactly the payload class "
      "it exists to catch")

# The floor still exists, but only where the benign chatter actually is: a
# destination this lineage has already talked to.
r2 = Reconciler(now=BORN, path=live)
r2.refresh(NOW)
r2.observe("200", "known.example", 1 * KB, NOW)          # records the destination
check(r2.floor_for("known.example", NOW + 2) == Reconciler.KNOWN_MIN_BYTES,
      "a destination already seen keeps the 64 KB floor -- that is where the "
      "ordinary small-chatter noise actually lives")
check(r2.floor_for("never.example", NOW + 2) == Reconciler.NOVEL_MIN_BYTES,
      "a first-time destination has NO floor")
check(Reconciler(now=NOW, path=live).floor_for("x.example", NOW + 1)
      == Reconciler.KNOWN_MIN_BYTES,
      "NOVELTY WARMUP: inside the first 120 s of a run nothing counts as novel, "
      "so a restart does not fire on the entire steady state at once")

# --- 9. DOCUMENTED DEFEAT: target-less declaration is a wildcard ------------
wild = tmp / "wild.ndjson"
write(wild, [{"ts": NOW, "pid": 100, "tool": "bash"}], mtime=NOW)
r = Reconciler(now=BORN, path=wild)
r.refresh(NOW)
r.observe("200", "anywhere.invalid", 50 * MB, NOW)
hit = r.unexplained("200", NOW + 60, ancestors=anc)
check(hit is not None and "wildcard" in hit[2],
      "CHANGED 2026-08-03: a target-less declaration no longer silences a "
      "FIRST-TIME destination in silence. Still not an accusation, but it is "
      "SAID -- the old behaviour turned the documented wildcard defeat into an "
      "invisible off-switch: one target-less declare() and the reconciler went "
      "quiet leaving no trace it had been muted")

# On a destination already seen, a wildcard declaration is genuinely quiet.
# Downgrading is not the same as reporting everything.
rw = Reconciler(now=BORN, path=wild)
rw.refresh(NOW)
# Seed the novelty baseline directly: two observe() calls inside one window
# would NOT do it, because novelty is frozen at first sight and the second call
# just accumulates into the same record. Saying it as state is also clearer
# about what is under test.
rw._seen_dests["seen.invalid"] = NOW - 10
rw.observe("200", "seen.invalid", 50 * MB, NOW)
check(rw.unexplained("200", NOW + 61, ancestors=anc) is None,
      "a wildcard on an ALREADY-SEEN destination stays silent -- the downgrade "
      "is scoped to novelty, not applied to everything")

# --- 10. DOCUMENTED DEFEAT: unresolved IP degrades to pid-only -------------
r = Reconciler(now=BORN, path=live)
r.refresh(NOW)
r.observe("200", "203.0.113.9", 50 * MB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is None,
      "KNOWN DEFEAT: an unresolved destination is an IP, which can never match "
      "a declared host, so the check degrades to pid-presence only")

# --- 11. robustness: malformed lines must not kill the reader --------------
bad = tmp / "bad.ndjson"
with open(bad, "w") as fh:
    fh.write("not json\n")
    fh.write('{"ts": "nope", "pid": 1}\n')
    fh.write('{"pid": 100}\n')                              # no ts
    fh.write(json.dumps({"ts": NOW, "pid": 100, "tool": "ok",
                         "target": "good.example"}) + "\n")
    fh.write('{"ts": ' + str(NOW) + ', "pid": 100, "too')    # partial last line
import os
os.utime(bad, (NOW, NOW))
r = Reconciler(now=BORN, path=bad)
check(r.refresh(NOW) is True and r._malformed == 3,
      "three malformed lines counted, reader still active (a bad line must not "
      "take the sentinel down)")
r.observe("200", "good.example", 5 * MB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is None,
      "the one VALID line among the garbage still reconciles")
r.observe("200", "other.example", 5 * MB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is not None,
      "and a different host is still reported")

# --- 12. incremental tail: appended lines are picked up --------------------
grow = tmp / "grow.ndjson"
write(grow, [{"ts": NOW, "pid": 100, "tool": "a", "target": "one.example"}],
      mtime=NOW)
r = Reconciler(now=BORN, path=grow)
r.refresh(NOW)
before = len(r._decls)
with open(grow, "a") as fh:
    fh.write(json.dumps({"ts": NOW, "pid": 100, "tool": "b",
                         "target": "two.example"}) + "\n")
os.utime(grow, (NOW, NOW))
r.refresh(NOW)
check(len(r._decls) == before + 1,
      "an appended declaration is picked up incrementally (offset tailing, not "
      "a full re-read)")
r.observe("200", "two.example", 5 * MB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is None,
      "and the newly appended declaration explains traffic")

# --- 13. repeat suppression --------------------------------------------------
r = Reconciler(now=BORN, path=live)
r.refresh(NOW)
r.observe("200", "loud.example", 5 * MB, NOW)
check(r.unexplained("200", NOW + 60, ancestors=anc) is not None,
      "first unexplained flow reports")
check(r.unexplained("200", NOW + 61, ancestors=anc) is None,
      "the same (pid, dest) does not report again inside the window")

# --- 14. PROXY INVARIANT, imported from the sibling mitm-audit design -------
# The one verdict here that a declaration cannot argue with. Everything else in
# this file rests on self-reported lines, so an attacker who writes one
# plausible declaration is "explained". This rests on a property of the socket.
prox = tmp / "prox.ndjson"
write(prox, [{"ts": NOW, "pid": 100, "tool": "fetch",
              "target": "collector.evil.invalid", "bytes": 60 * MB}], mtime=NOW)
r = Reconciler(now=BORN, path=prox, proxy="127.0.0.1:8080")
r.refresh(NOW)
r.observe("200", "collector.evil.invalid", 50 * MB, NOW)
hit = r.unexplained("200", NOW + 60, ancestors=anc)
check(hit is not None and "declaration cannot exempt" in hit[2],
      "PROXY MODE: a perfectly matching declaration -- right host, declared "
      "size LARGER than observed -- does NOT explain direct egress when a proxy "
      "is configured. Under proxy mode agent traffic should be indistinguishable "
      "from loopback, and loopback never reaches the reconciler, so arriving "
      "here at all IS the finding")

r = Reconciler(now=BORN, path=prox, proxy="127.0.0.1:8080")
r.refresh(NOW)
r.observe("200", "tiny.invalid", 200, NOW)                 # 200 bytes
check(r.unexplained("200", NOW + 60, ancestors=anc) is not None,
      "and proxy mode has NO byte floor at all -- the invariant is structural, "
      "so 200 bytes is as much a violation as 200 MB")

check(Reconciler(now=BORN, path=prox).\
      _proxy is None,
      "proxy mode is OFF unless SENTINEL_PROXY (or the constructor arg) says "
      "otherwise -- it is opt-in because it presumes a launch-time setup")

r = Reconciler(now=BORN, path=prox, proxy="http://127.0.0.1:8080")
check(r._proxy == "127.0.0.1",
      "the proxy endpoint is normalised to a host the same way declarations are")

import shutil
shutil.rmtree(tmp, ignore_errors=True)


def test_reconcile():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
