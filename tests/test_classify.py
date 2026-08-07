#!/usr/bin/env python3
"""
Semantic regression: parse mechanics were pinned by test_parse.py; this pins
CLASSIFICATION -- the layer that actually changes accusations on a real machine.
Every assertion here maps to a bug the real-machine fixture exposed:
  - kiro's 42MB flow must classify (kiro was invisible: not in AGENT_TOKENS)
  - localhost 7GB must be dropped (was counted -> ollama-style false amber)
  - two connections to the same dest must SUM (was overwritten by '=')
  - an orphan connection after a garbage row must NOT attach to the prior proc
  - IPv6 dot-port ('2001:db8::1.443') must parse (real nettop format, not [v6])
  - bytes to an AI endpoint must land in 'ai', never fire red
  - NETTOP_CMD must carry -n (the flag the whole join depends on)

Run:  python3 tests/test_classify.py     (no rumps/nettop needed)
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sentinel import parse_flows, aggregate_flows, NETTOP_CMD, FLAG_BYTES  # noqa: E402

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


def _is_lo(host):
    h = (host or "").lower()
    return h == "localhost" or h.startswith("127.") or h == "::1"


flows = parse_flows(FIX.read_text())

# Fake SNI: numeric IPs (what -n gives) resolve; the PTR hostname does NOT
# (demonstrating exactly why -n matters). 203.0.113.20 = non-AI exfil dest;
# 192.0.2.10 = an AI endpoint.
_SNI = {"203.0.113.20": "evil-exfil.com", "192.0.2.10": "api.anthropic.com"}
_AI = {"api.anthropic.com"}
resolve = lambda ip: _SNI.get(ip)          # noqa: E731
is_ai = lambda dom: dom in _AI             # noqa: E731

# baseline all-zero -> delta == this-tick bytes (simulate "new since last tick")
baseline = {k: 0 for k in flows}
per_pid = aggregate_flows(flows, baseline, resolve, is_ai)

# 1) loopback dropped: the 7GB ollama-agent lo0 flow never enters flows/per_pid
check(not any(_is_lo(k[2]) for k in flows),
      "loopback (127./::1/localhost) dropped from flows")
check(("ollama-agent", "4680") not in per_pid,
      "ollama-agent (localhost 7GB) produces NO classified traffic")

# 2) kiro is detected + classified nonai (was invisible pre-fix)
k = per_pid.get(("kiro-cli-chat", "26947"))
check(k is not None, "kiro-cli-chat present in per_pid")
check(bool(k) and k["nonai"] >= FLAG_BYTES and "evil-exfil.com" in k["dests"],
      "kiro's flow classified nonai -> evil-exfil.com (>= FLAG_BYTES)")

# 3) += accumulation: two conns to 203.0.113.20 summed (42460880 + 900000),
#    NOT just the last (900000)
check(bool(k) and k["nonai"] == 42460880 + 900000,
      "two conns to same dest are SUMMED, not overwritten")

# 4) PTR hostname (ec2-198-51-100-9...) does NOT resolve -> unresolved, proving
#    why -n is required (numeric would have joined)
check(bool(k) and k["unresolved"] > 0,
      "PTR-hostname dest stays unresolved (the -n rationale)")

# 5) AI-endpoint bytes land in 'ai', never nonai (no red)
c = per_pid.get(("claude", "100"))
check(bool(c) and c["ai"] == 1000 and c["nonai"] == 0,
      "claude's api.anthropic.com bytes -> ai bucket, zero nonai")

# 6) orphan after garbage row NOT attributed to claude
check(("claude", "100", "192.0.2.99") not in dests(flows),
      "orphan 192.0.2.99 (after garbage row) not attached to claude")

# 7) IPv6 dot-port parsed to the bare address
check(("someproc", "300", "2001:db8::1") in dests(flows),
      "IPv6 dot-port ('2001:db8::1.443') parsed to '2001:db8::1'")

# 8) the -n flag guard (the whole join depends on it)
check("-n" in NETTOP_CMD, "NETTOP_CMD includes -n (numeric IPs)")

def test_classify_regression():
    # pytest entry: the checks above ran at import; surface their verdict here
    # so `pytest` collects a real test instead of silently passing with zero.
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
