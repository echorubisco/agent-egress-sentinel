#!/usr/bin/env python3
"""
Regression test for nettop parsing. The reviewer's key ask: stop gambling on
regressions every fix round -- pin the parser against a REAL nettop sample plus
synthetic edge cases (P0-B orphan mis-attribution, space/paren names, IPv6).

Run:  python3 tests/test_parse.py     (no rumps needed -- import is soft)
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sentinel import parse_flows, _byte_out_index   # noqa: E402

FIX = pathlib.Path(__file__).resolve().parent / "nettop_sample.txt"
fails = []


def dests(flows):
    """{(name, pid, ip): total_out} from the connection-keyed flow dict.

    Flow keys became (name, pid, ip, conn) on 2026-08-07 so that the byte delta
    is taken per connection -- summing concurrent connections before the delta
    let a closing connection manufacture egress (tests/test_conn_expiry.py).
    These assertions are about parsing and attribution, not key arity, so they
    collapse to the destination here.
    """
    out = {}
    for k, v in flows.items():
        d = (k[0], k[1], k[2])
        o = v.out if hasattr(v, "out") else v
        i = v.inb if hasattr(v, "inb") else 0
        p = out.get(d, (0, 0))
        out[d] = (p[0] + o, p[1] + i)
    return out




def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


# 1) header-derived bytes_out index (P1-G) on the real sample
real = FIX.read_text()
idx = _byte_out_index(real)
check(idx == 5, f"real fixture: bytes_out column index = {idx} (expect 5)")

# 2) real sample parses without exception and yields flows
flows = parse_flows(real)
check(isinstance(flows, dict) and len(flows) > 0,
      f"real fixture: parsed {len(flows)} flows")

# 3) space/paren process names are recognized as OWNERS (P0-B core)
HDR = "time,,interface,state,bytes_in,bytes_out,x\n"
space_case = HDR + (
    "t,Google Chrome Helper.200,,,0,0,x\n"
    "t,tcp4 10.0.0.1:5<->104.18.0.9:443,en0,Established,0,9000000,x\n"
)
f = parse_flows(space_case)
check(("Google Chrome Helper", "200", "104.18.0.9") in dests(f),
      "space-name process owns its connection (not skipped)")

# 4) P0-B orphan: an UNPARSEABLE row between a process and a connection must
#    reset ownership so the connection is NOT mis-attributed to the prior proc.
orphan_case = HDR + (
    "t,claude.100,,,0,0,x\n"
    "t,tcp4 10.0.0.1:5<->1.2.3.4:443,en0,Established,0,1000,x\n"   # legit: claude
    "t,--- garbage row no pid no arrows ---,,,0,0,x\n"             # unparseable
    "t,tcp4 10.0.0.1:6<->9.9.9.9:443,en0,Established,0,200000000,x\n"  # orphan
)
f = parse_flows(orphan_case)
check(("claude", "100", "1.2.3.4") in dests(f),
      "claude's own connection attaches")
check(("claude", "100", "9.9.9.9") not in f,
      "orphan connection after garbage row is NOT attached to claude (P0-B)")

# 5) IPv6 bracket stripped; '*:*' listen rows skipped
v6_case = HDR + (
    "t,someproc.300,,,0,0,x\n"
    "t,tcp6 [fe80::1]:5<->[2001:db8:1::1111]:443,en0,Established,0,7000000,x\n"
    "t,tcp4 127.0.0.1:9<->*:*,lo0,Listen,0,0,x\n"
)
f = parse_flows(v6_case)
check(("someproc", "300", "2001:db8:1::1111") in dests(f),
      "IPv6 remote parsed with brackets stripped")
check(not any(k[2] == "*" for k in f),
      "'*:*' listen row produced no flow")

def test_parse_regression():
    # pytest entry: the checks above ran at import; surface their verdict here
    # so `pytest` collects a real test instead of silently passing with zero.
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
