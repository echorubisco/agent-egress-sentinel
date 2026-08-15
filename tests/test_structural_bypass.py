#!/usr/bin/env python3
"""
The proxy invariant must not fire on traffic an HTTP proxy cannot carry.

THE FLOOD (2026-08-07, self-inflicted). Closing the FRESH_SEC gate made the
proxy invariant reachable for the first time -- and reachable meant it fired on
DNS, NTP, DHCP and QUIC, none of which an HTTP proxy can carry. Verified:
192.168.1.1, 8.8.8.8 and an NTP host all produced "proxy is configured but this
left the agent tree directly".

The first write-up of this said it *could not* be filtered, because
`_remote_host` strips the port before the reconciler sees it. That was wrong, and
wrong in the direction of giving up too early: the flow key is
`(name, pid, ip, conn)` and `conn` is nettop's own column --
`tcp4 10.0.0.5:51000<->203.0.113.77:443` -- which carries **both the remote port
and the protocol**. Nothing was lost; nobody had passed it on.

THE DISTINCTION THIS RESTORES, which is the whole point of the invariant:
"could not have been proxied" (UDP 443 is QUIC, 53 is DNS) versus "chose not to
be" (TCP 443 direct). Without the port those are the same event, and an invariant
that cannot tell them apart is not structural, it is just noisy.

FAIL-OPEN, DELIBERATELY. An unknown port does NOT get excluded. Excluding is
discarding, and this repo's own rule is that a control which discards is
indistinguishable from a detector that does not work. Unknown port therefore
errs toward reporting.

Run:  python3 tests/test_structural_bypass.py
"""
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import activity                                                      # noqa: E402
import sentinel as S                                                 # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


NOW = 1_000_000.0
PROXY = "127.0.0.1:8080"


def recon():
    d = pathlib.Path(tempfile.mkdtemp()) / "activity.ndjson"
    r = activity.Reconciler(path=d, proxy=PROXY, now=NOW - 1000)
    r.refresh(now=time.time())
    return r


def verdict(dest, port=None, proto=None):
    r = recon()
    r.observe(4242, dest, 500, now=NOW, name="claude", port=port, proto=proto)
    out = r.drain(now=NOW + r.SETTLE_SEC + 1, ancestors=lambda p, **k: [p])
    return out[0][4] if out else None


# --- the flood: structurally unproxyable traffic must be silent --------------
for dest, port, proto, what in (
        ("192.168.1.1", 53, "udp", "DNS to the router"),
        ("8.8.8.8", 53, "tcp", "DNS over TCP"),
        ("224.0.0.251", 5353, "udp", "mDNS"),
        ("1.2.3.4", 123, "udp", "NTP"),
        ("1.2.3.4", 67, "udp", "DHCP"),
        ("203.0.113.9", 443, "udp", "QUIC (UDP 443)")):
    check(verdict(dest, port, proto) is None,
          f"{what} does not trip the proxy invariant -- an HTTP proxy cannot "
          f"carry it, so it is not evidence of anything")

# --- and the finding must survive --------------------------------------------
v = verdict("203.0.113.9", 443, "tcp")
check(v is not None and "proxy is configured" in v,
      "TCP 443 straight to a real host DOES trip it -- the udp/tcp distinction "
      "is the entire difference between 'could not be proxied' and 'chose not "
      "to be', and losing it would make this test a way of silencing the detector")
v = verdict("203.0.113.9", 22, "tcp")
check(v is not None and "proxy is configured" in v,
      "SSH trips it too: an HTTP proxy cannot carry SSH either, but it is not on "
      "the frozen list and must not be quietly excused into it")

# --- fail-open on unknown -----------------------------------------------------
v = verdict("203.0.113.9", None, None)
check(v is not None,
      "an UNKNOWN port still trips the invariant -- excluding on missing data "
      "would be a discard, and a discard is indistinguishable from a broken "
      "detector; noise is the safe direction here")

# --- the port really is recoverable from the flow key -------------------------
for conn, want in (
        ("tcp4 10.0.0.5:51000<->203.0.113.77:443", (443, "tcp")),
        ("udp4 10.0.0.5:51000<->192.168.1.1:53", (53, "udp")),
        ("tcp6 fe80::1.5003<->2001:db8::9.443", (443, "tcp")),
        ("udp6 fe80::1.5003<->ff02::fb.5353", (5353, "udp")),
        ("garbage", (None, None)),
        ("", (None, None))):
    got = S._remote_port_proto(conn)
    check(got == want,
          f"port/proto parsed from the nettop connection column: {conn!r} -> {got}")

# --- end to end through aggregate_flows --------------------------------------
seen = []
S.aggregate_flows(
    {("claude", "1", "192.168.1.1", "udp4 10.0.0.5:5<->192.168.1.1:53"): S.Bytes(500, 0),
     ("claude", "1", "203.0.113.9", "tcp4 10.0.0.5:6<->203.0.113.9:443"): S.Bytes(500, 0)},
    {}, lambda ip: None, lambda d: False,
    observe=lambda pid, kind, dest, delta, ip, port=None, proto=None:
        seen.append((dest, port, proto)))
check(sorted(seen) == [("192.168.1.1", 53, "udp"), ("203.0.113.9", 443, "tcp")],
      f"aggregate_flows passes port and protocol through to the hook (got {seen})")


def test_structural_bypass():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
