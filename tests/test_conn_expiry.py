#!/usr/bin/env python3
"""
A closing connection must not manufacture egress.

THE BUG (found by external review 2026-08-07, reproduced before this file
existed). `_latest` is keyed per connection, but `snapshot()` summed concurrent
connections to one destination BEFORE `aggregate_flows` computed the delta. So
when one connection closed and aged out of `_latest` after BASELINE_TTL, the sum
DROPPED -- and `_delta`'s counter-reset rule (`total < prev -> return total`)
read that drop as a socket reuse and counted the surviving connection's entire
cumulative as fresh egress.

Measured on the real path: two connections to one destination, 200 MB and 6 MB.
The 200 MB one closes. Five minutes later, with **zero bytes sent in between**,
a full RED alert fires naming 6 MB. The trigger is ordinary -- any agent holding
two connections to one non-allowlisted host, which is what an HTTP keep-alive
pool is -- and it fires five minutes after the traffic, when nothing is left on
screen to check it against.

PRE-FLIGHT's first line is that a false accusation is the only failure mode here
that damages a user. This was one, and it was manufactured from nothing.

The fix keys the delta on the connection, not on the destination: an expiring
connection is then just a key whose delta was always going to be zero.

Run:  python3 tests/test_conn_expiry.py
"""
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import sentinel as S                                                 # noqa: E402
from ledger import DestLedger                                        # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


NAME, PID, IP = "agentproc", "999", "203.0.113.77"
CONN_A = f"10.0.0.5:51000<->{IP}:443"
CONN_B = f"10.0.0.5:51001<->{IP}:443"
BIG, SMALL = 200 * 1024 * 1024, 6 * 1024 * 1024


def _stream():
    st = S.NettopStream.__new__(S.NettopStream)
    st._lock = threading.Lock()
    st._latest = {}
    return st


def _run(events):
    """events: [(t, {conn: out_bytes}, warmup)] -> (counted_bytes, red_alerts)"""
    st, baseline, led = _stream(), {}, DestLedger()
    counted, reds = [], []
    for t, conns, warmup in events:
        with st._lock:
            for c, b in conns.items():
                st._latest[(NAME, PID, IP, c)] = (S.Bytes(b, 0), t)
        snap = st.snapshot(now=t)

        def observe(pid, kind, dest, delta, ip=None):
            counted.append(delta)
            if kind != "ai" and led.add(pid, kind, dest, delta, now=t):
                reds.append((dest, delta))

        S.aggregate_flows(snap, baseline, lambda ip: "backup.example.com",
                          lambda d: False, observe=observe, warmup=warmup)
        for k, v in snap.items():
            baseline[k] = v
    return sum(counted), reds


# --- the regression ----------------------------------------------------------
# A and B open together; A closes and simply stops being refreshed; B keeps
# reporting the SAME cumulative throughout. Nothing is sent after t=0.
counted, reds = _run([
    (0,   {CONN_A: BIG, CONN_B: SMALL}, True),    # warmup: both cumulatives predate us
    (10,  {CONN_B: SMALL}, False),                # A closed; B unchanged
    (200, {CONN_B: SMALL}, False),                # still inside BASELINE_TTL
    (320, {CONN_B: SMALL}, False),                # A ages out -> the sum drops
])
check(counted == 0,
      f"a connection ageing out counts ZERO new bytes (got {counted / 1048576:.1f} MB "
      f"-- the surviving connection's whole cumulative was re-counted)")
check(reds == [],
      f"and therefore fires no alert (got {reds}) -- this is the false accusation "
      f"PRE-FLIGHT names as the only failure mode that damages a user")

# --- the behaviour that must survive the fix ---------------------------------
# Real new bytes on a surviving connection are still counted in full.
counted, _ = _run([
    (0,   {CONN_A: BIG, CONN_B: SMALL}, True),
    (10,  {CONN_B: SMALL}, False),
    (320, {CONN_B: SMALL}, False),                 # A expires
    (330, {CONN_B: SMALL + 3 * 1024 * 1024}, False),   # B really sends 3 MB
])
check(counted == 3 * 1024 * 1024,
      f"real bytes on the surviving connection are still counted exactly "
      f"(got {counted / 1048576:.1f} MB, want 3.0 MB)")

# A genuinely new connection to the same destination still contributes its whole
# cumulative -- that is the 2026-07-27 fix and it must not be undone here.
counted, _ = _run([
    (0,  {CONN_A: 1024}, True),
    (10, {CONN_A: 1024, CONN_B: 7 * 1024 * 1024}, False),
])
check(counted == 7 * 1024 * 1024,
      f"a NEW concurrent connection still contributes its full cumulative "
      f"(got {counted / 1048576:.1f} MB, want 7.0 MB) -- the 94.2% loss fixed on "
      f"2026-07-27 must not come back")

# Two live connections both growing: both deltas counted, neither lost.
counted, _ = _run([
    (0,  {CONN_A: 1024, CONN_B: 1024}, True),
    (10, {CONN_A: 1024 + 2 * 1024 * 1024, CONN_B: 1024 + 4 * 1024 * 1024}, False),
])
check(counted == 6 * 1024 * 1024,
      f"concurrent connections to one destination both count (got "
      f"{counted / 1048576:.1f} MB, want 6.0 MB) -- summing was introduced to fix "
      f"a real dropped-bytes bug and that fix must survive")

# A true counter reset on ONE connection (socket reuse) is still handled.
counted, _ = _run([
    (0,  {CONN_A: 10 * 1024 * 1024}, True),
    (10, {CONN_A: 8 * 1024 * 1024}, False),        # pid/socket reuse: went backwards
])
check(counted == 8 * 1024 * 1024,
      f"a real per-connection counter reset still counts the new cumulative "
      f"(got {counted / 1048576:.1f} MB, want 8.0 MB)")


def test_conn_expiry():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
