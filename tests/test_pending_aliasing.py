#!/usr/bin/env python3
"""
Merging two connections to one host must not lose the reportable one.

THE BUG (found by external review 2026-08-07, hours after the fix it descends
from). `_pending` is keyed `(pid, dest)` -- no port, no protocol. Two connections
to the same host therefore merge into ONE record, and `port`/`proto` are written
only on the branch that CREATES the record. The merge branch never updates them.

So the structural exclusion added earlier that day reads whichever connection
happened to arrive first:

    QUIC (udp/443) first, then a real TCP/443 bypass  -> record says udp -> SILENT
    the same two in the other order                   -> record says tcp -> REPORTED

**A genuine proxy bypass is silently dropped because a QUIC packet to the same
host arrived first, and the order is nettop's, not the user's.** It is not a
contrived case: TCP/443 and UDP/443 to one host is what HTTP/3 looks like --
Google, Cloudflare, every large CDN -- and hosts like that are exactly the ones a
bypass would go to.

Same shape as the bug it descends from, one level up. That one lost the port
from the JOIN key (`_remote_host` stripped it); this one loses it from the
AGGREGATION key. Both times the dimension the decision needs was not in the key,
and both times the failure direction was discard -- the thing this module's own
header forbids.

THE FIX, and why this one rather than the other. Two options existed: put
(port, proto) into the `_pending` key, or upgrade on merge. Keying would split
one host's byte total across ports, which changes what the volume sub-check sees
-- a behaviour change wider than the bug. Upgrading on merge is one line and is
exactly the rule the module already states for unknown ports: **err toward
reporting.** The upgrade is ONE-WAY. A reportable connection overwrites an
unproxyable one; never the reverse.

Run:  python3 tests/test_pending_aliasing.py
"""
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import activity                                                      # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


NOW = 1_000_000.0
HOST = "cdn.example.com"


def run(events, dest=HOST):
    d = pathlib.Path(tempfile.mkdtemp()) / "a.ndjson"
    r = activity.Reconciler(path=d, proxy="127.0.0.1:8080", now=NOW - 1000)
    r.refresh(now=time.time())
    for port, proto, n in events:
        r.observe(4242, dest, n, now=NOW, name="claude", port=port, proto=proto)
    out = r.drain(now=NOW + r.SETTLE_SEC + 1, ancestors=lambda p, **k: [p])
    rec = r._pending.get((4242, dest))
    stored = (rec[5], rec[6]) if rec and len(rec) > 6 else None
    return stored, bool(out)


QUIC = (443, "udp", 500)
BYPASS = (443, "tcp", 50 * 1024 * 1024)

# --- the regression: order must not decide the verdict ------------------------
_, fired_a = run([QUIC, BYPASS])
check(fired_a,
      "QUIC arriving BEFORE a real TCP/443 bypass to the same host does not "
      "swallow it -- HTTP/3 makes that ordering ordinary, and it was silently "
      "deciding whether a bypass was reported")
_, fired_b = run([BYPASS, QUIC])
check(fired_b, "and the reverse order still reports (it always did)")
check(fired_a == fired_b,
      "the verdict is ORDER-INDEPENDENT -- nettop's output order is not "
      "something a user can see, so it must not change what is reported")

# --- the upgrade is one-way ---------------------------------------------------
stored, _ = run([BYPASS, QUIC])
check(stored == (443, "tcp"),
      f"a later QUIC packet does not DOWNGRADE a record that already holds a "
      f"reportable connection (got {stored}) -- upgrading both ways would just "
      f"move the coin flip to the other end of the tick")
stored, _ = run([QUIC, BYPASS])
check(stored == (443, "tcp"),
      f"and a reportable connection upgrades a record that held an unproxyable "
      f"one (got {stored})")

# --- what must not change -----------------------------------------------------
_, fired = run([QUIC])
check(not fired,
      "a host contacted ONLY over QUIC is still silent -- the structural "
      "exclusion is intact and this test is not a way of deleting it")
_, fired = run([(53, "udp", 500)])
check(not fired, "DNS-only is still silent")
_, fired = run([(53, "udp", 500), (443, "udp", 500)])
check(not fired,
      "two unproxyable connections to one host stay silent -- merging them must "
      "not manufacture a report either")
_, fired = run([BYPASS])
check(fired, "a lone TCP/443 bypass still reports")

# --- unknown ports keep erring toward reporting -------------------------------
_, fired = run([QUIC, (None, None, 500)])
check(fired,
      "an UNKNOWN port upgrades an unproxyable record too -- unknown is not "
      "excluded anywhere else in this module and must not become excluded here "
      "by the back door")
stored, _ = run([(None, None, 500), QUIC])
check(stored == (None, None),
      f"and QUIC does not downgrade an unknown one (got {stored})")


def test_pending_aliasing():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
