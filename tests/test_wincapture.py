#!/usr/bin/env python3
"""
The ETW -> flow-mapping translation (wincapture.py).

Everything here is the PURE half of the Windows byte-count source: which events
count, which direction they count in, what gets dropped, and how per-transfer
deltas become the cumulative mapping `sentinel.parse_flows` produces. The live
ETW session is a dozen lines that start and stop a trace; if it is broken it
produces no events at all. This is the half that can produce WRONG NUMBERS, so
this is the half with tests.

The load-bearing case is TcpCopy. Event ids 18 and 34 were the two most frequent
in a real 30 s trace and are receive-side copies; counting them as well as Recv
roughly doubles every inbound number while looking completely plausible.
Inbound bytes feed no rule, so nothing downstream would have caught it.

Run:  python3 tests/test_wincapture.py
"""
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import wincapture as W                                               # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


def ev(pid=4242, size=1000, daddr="93.184.216.34", dport=443,
       saddr="10.0.0.5"):
    return {"PID": pid, "size": size, "daddr": daddr, "dport": dport,
            "saddr": saddr, "sport": 50001, "seqnum": 1, "connid": 0}


# --- direction ---------------------------------------------------------------
check(W.translate(10, ev()) == (4242, "93.184.216.34", 1000, 0),
      "TCP IPv4 Send (10) counts as OUTBOUND")
check(W.translate(11, ev()) == (4242, "93.184.216.34", 0, 1000),
      "TCP IPv4 Recv (11) counts as INBOUND")
check(W.translate(26, ev()) == (4242, "93.184.216.34", 1000, 0),
      "TCP IPv6 Send (26) counts as OUTBOUND")
check(W.translate(42, ev()) == (4242, "93.184.216.34", 1000, 0),
      "UDP IPv4 Send (42) counts as OUTBOUND (DNS is in this stream)")

# --- which field holds the remote (found by the first live run) --------------
# TCP recv: daddr is the connection's remote. UDP recv: daddr is the PACKET's
# destination -- this host, or a multicast group -- and the peer is in saddr.
# Reading daddr for both produced `claude.exe -> <this machine's own LAN IP>`.
check(W.translate(11, ev(daddr="203.0.113.9", saddr="192.0.2.10"))
      == (4242, "203.0.113.9", 0, 1000),
      "TCP Recv (11) takes the remote from daddr (connection semantics)")
check(W.translate(27, ev(daddr="2001:db8:1::1", saddr="2001:db8::348"))
      == (4242, "2001:db8:1::1", 0, 1000),
      "TCP IPv6 Recv (27) takes the remote from daddr")
check(W.translate(43, ev(daddr="192.0.2.10", saddr="203.0.113.9"))
      == (4242, "203.0.113.9", 0, 1000),
      "UDP Recv (43) takes the remote from SADDR -- daddr is this host, and "
      "reading it attributed inbound DNS to the machine's own address")
check(W.translate(59, ev(daddr="2001:db8::348", saddr="2001:db8:1::1"))
      == (4242, "2001:db8:1::1", 0, 1000),
      "UDP IPv6 Recv (59) takes the remote from SADDR")
check(W.translate(58, ev(daddr="2001:db8:1::1", saddr="2001:db8::348"))
      == (4242, "2001:db8:1::1", 1000, 0),
      "UDP Send (58) still uses daddr -- only the RECV ids are swapped")

# --- the double-count trap ---------------------------------------------------
check(W.translate(18, ev()) is None,
      "TcpCopy IPv4 (18) is NOT counted -- it is a receive-side copy, and it "
      "was the 2nd most frequent id in a real trace")
check(W.translate(34, ev()) is None,
      "TcpCopy IPv6 (34) is NOT counted -- most frequent id in a real trace; "
      "counting it would have doubled every inbound number plausibly")
for eid in (12, 13, 28, 29):
    check(W.translate(eid, ev()) is None,
          f"connect/disconnect ({eid}) carries no transferred bytes")

# --- what must be dropped ----------------------------------------------------
check(W.translate(10, ev(daddr="127.0.0.1")) is None,
      "loopback is dropped (a local ollama pushing GB must not be counted)")
check(W.translate(10, ev(daddr="::1")) is None, "IPv6 loopback is dropped")
check(W.translate(10, ev(daddr="localhost")) is None, "'localhost' is dropped")

# Multicast was the single largest inbound source in the first 20 s live run.
# Each group would also have counted as a distinct destination in the per-pid
# fan-out counter -- the one detector that keys on breadth.
check(W.translate(43, ev(daddr="192.0.2.10", saddr="224.0.0.251")) is None,
      "IPv4 multicast (mDNS 224.0.0.251) is not a destination")
check(W.translate(59, ev(daddr="2001:db8::348", saddr="ff02::fb")) is None,
      "IPv6 multicast (mDNS ff02::fb) is not a destination")
check(W.translate(10, ev(daddr="239.255.255.250")) is None,
      "SSDP multicast is not a destination")
check(W.translate(10, ev(daddr="255.255.255.255")) is None,
      "broadcast is not a destination")
check(W.translate(10, ev(daddr="169.254.10.3")) is None,
      "IPv4 link-local is not a destination")
check(W.translate(10, ev(daddr="fe80::1234")) is None,
      "IPv6 link-local is not a destination")
check(W.translate(10, ev(daddr="0.0.0.0")) is None, "0.0.0.0 is not a destination")
check(W.translate(10, ev(daddr="::")) is None, "unspecified IPv6 is not a destination")

# Deliberately kept: an agent uploading to a NAS on the LAN IS egress from this
# machine, and dropping RFC1918 would blind the tool in the direction of "the
# attacker is already on your network".
check(W.translate(10, ev(daddr="192.168.1.50")) is not None,
      "private LAN unicast IS counted -- an upload to a NAS is still egress")
check(W.translate(10, ev(daddr="10.1.2.3")) is not None,
      "10/8 is counted for the same reason")
check(W.translate(10, ev(daddr="2606:4700:4700::1111")) is not None,
      "ordinary global IPv6 is counted (the 'ff'/'fe8' prefix test must not "
      "swallow addresses that merely start with a hex letter)")
check(W.translate(10, ev(daddr="fc00::1")) is not None,
      "IPv6 unique-local is counted, matching the RFC1918 decision")
check(W.translate(10, ev(size=0)) is None,
      "a zero-byte event adds nothing and is dropped (connect/teardown and DNS "
      "produce these constantly)")
check(W.translate(10, ev(size=-5)) is None, "a negative size is dropped")
check(W.translate(10, ev(pid=0)) is None, "pid 0 is not attributable")
check(W.translate(10, {}) is None, "a missing-field event returns None, not a raise")
check(W.translate(10, ev(size="not-a-number")) is None,
      "a non-numeric size returns None, not a raise")
check(W.translate(10, ev(daddr="")) is None, "an empty address is dropped")

# --- accumulation ------------------------------------------------------------
acc = W.FlowAccumulator(name_for_pid=lambda pid: f"proc{pid}")
for _ in range(3):
    acc.feed(10, ev(size=100))
acc.feed(11, ev(size=250))
snap = acc.snapshot()
check(snap == {("proc4242", 4242, "93.184.216.34"): W.Bytes(300, 250)},
      "per-transfer deltas accumulate into ONE cumulative row per (name,pid,ip)")

acc.feed(10, ev(size=100, daddr="198.51.100.7"))
check(len(acc.snapshot()) == 2,
      "a second destination for the same pid is a separate row (the fan-out "
      "counter is per-pid and needs distinct destinations)")

# The macOS path had to be fixed so a flow's FIRST sighting contributes its full
# byte count instead of only establishing a baseline; 94.2% of new-flow bytes
# were being discarded. Accumulating from zero makes that true by construction.
fresh = W.FlowAccumulator(name_for_pid=lambda p: "x")
fresh.feed(10, ev(size=5_000_000))
check(fresh.snapshot()[("x", 4242, "93.184.216.34")].out == 5_000_000,
      "a flow's first event contributes its FULL byte count, not zero "
      "(the 2026-07-27 first-sighting bug cannot recur on this source)")

# --- name resolution is cached ----------------------------------------------
calls = []


def counting_name(pid):
    calls.append(pid)
    return f"p{pid}"


c = W.FlowAccumulator(name_for_pid=counting_name)
for _ in range(50):
    c.feed(10, ev())
check(len(calls) == 1,
      "the pid->name lookup happens once per pid, not once per event "
      "(it runs inside the ETW callback at up to ~900 events/s)")

# --- bounded, and says so ----------------------------------------------------
small = W.FlowAccumulator(name_for_pid=lambda p: "x", max_keys=3)
for i in range(10):
    small.feed(10, ev(daddr=f"198.51.100.{i}"))
d = small.diagnostics()
check(d["flows"] == 3 and d["dropped_new_flows"] == 7,
      "new flows past the cap are dropped AND counted -- a monitor that "
      "quietly stops counting is indistinguishable from a quiet network")

# --- diagnostics can check the TcpCopy assumption ----------------------------
d = acc.diagnostics()["bytes_by_event_id"]
check(d.get(10) == 400 and d.get(11) == 250 and 18 not in d,
      "bytes are tracked per event id, so the TcpCopy exclusion can be checked "
      "against a known-size download instead of believed")

# --- the callback must never raise ------------------------------------------
try:
    boom = W.FlowAccumulator(name_for_pid=lambda p: 1 / 0)
    boom.feed(10, ev())
    check(True, "an exception inside the callback is swallowed (raising there "
                "kills the consumer thread and capture stops silently)")
except Exception as e:                                            # pragma: no cover
    check(False, f"callback raised {e!r}")

# --- thread safety -----------------------------------------------------------
t_acc = W.FlowAccumulator(name_for_pid=lambda p: "x")


def hammer():
    for _ in range(2000):
        t_acc.feed(10, ev(size=1))


threads = [threading.Thread(target=hammer) for _ in range(4)]
[t.start() for t in threads]
[t.join() for t in threads]
check(t_acc.snapshot()[("x", 4242, "93.184.216.34")].out == 8000,
      "concurrent feeds do not lose bytes (pywintrace calls back from its own "
      "consumer thread while the app tick reads a snapshot)")

# --- degradation -------------------------------------------------------------
check(W.available() in (True, False), "available() returns a bool, never raises")


def test_wincapture():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
