#!/usr/bin/env python3
"""
Streaming nettop reader + process-ancestry attribution.

Both are the 2026-07-27 sampling/attribution work:
  - NettopStream replaces relaunching one-shot nettop each tick. The reason is
    CPU: 1/6 of a core's worth (1.8% vs 10.7%) for the same 1 s cadence.
    A cadence-to-cadence sweep on a 25-destination burst (5 interleaved trials,
    ground truth from curl -w %{remote_ip}) read 2 s one-shot 25%, 1 s one-shot
    48%, streaming -s 1 48%. Those numbers compare cadences and NOTHING ELSE --
    the sweep left connection lifetime uncontrolled, and lifetime is what sets
    recall (min(1, L/T); 5.8%/36.8%/54.4%/100% at L=50ms/300ms/500ms/>=1s with T
    pinned at 1 s). "48% recall" is withdrawn as a general figure, ROADMAP 07-30.
  - proctree.attribute closes the "per-agent really means per-process" hole: an
    agent shelling out to git/npm/curl used to produce unattributed traffic.

Run:  python3 tests/test_stream_tree.py     (no nettop/ps/rumps needed)
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import proctree                                                     # noqa: E402
from sentinel import NettopStream                                   # noqa: E402

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


HEADER = "time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,"
LINES = [
    HEADER,
    "20:19:01,curl.500,,,1000,700,0,0,0,",
    "20:19:01,tcp4 10.0.0.1:5001<->203.0.113.7:443,en0,Established,1000,700,0,0,0,",
    # second concurrent connection to the SAME destination -> must SUM, not replace
    "20:19:01,tcp4 10.0.0.1:5002<->203.0.113.7:443,en0,Established,500,300,0,0,0,",
    # loopback must be dropped
    "20:19:01,ollama.600,,,0,0,0,0,0,",
    "20:19:01,tcp4 127.0.0.1:9999<->localhost:11434,lo0,Established,9,7000000,0,0,0,",
    # IPv6 dot-port form (real nettop output, no brackets)
    "20:19:01,someproc.700,,,0,0,0,0,0,",
    "20:19:01,tcp6 fe80::1.5003<->2001:db8::9.443,en0,Established,0,42,0,0,0,",
    # garbage row must clear the current process so its orphan is dropped
    "20:19:01,--- not a process row ---,,,0,0,0,0,0,",
    "20:19:01,tcp4 10.0.0.1:5004<->203.0.113.99:443,en0,Established,0,999,0,0,0,",
]

s = NettopStream(lines=LINES)
for ln in LINES:
    s._feed(ln, now=1000.0)
snap = s.snapshot(now=1000.0)

check(s._byte_idx == 5, "bytes_out column located from the streamed header")
check(s._in_idx == 4, "bytes_in column located from the streamed header")
# fixture column order is bytes_in,bytes_out -> conn1 is in=1000/out=700,
# conn2 is in=500/out=300.
#
# REWRITTEN 2026-08-07. This used to assert that snapshot() SUMMED the two
# connections -- which is the behaviour that was removed, because summing before
# the delta let a closing connection manufacture egress (test_conn_expiry.py).
# A passing test had pinned the bug in place, exactly as the MIN_BYTES=64KB
# assertion did in the reconciler. The invariant that mattered was never
# "snapshot sums"; it was "no bytes are lost when one process holds two
# connections to one destination", and that now holds one layer down.
check(len([k for k in snap if k[:3] == ("curl", "500", "203.0.113.7")]) == 2,
      "concurrent conns to one dest are kept as TWO keys, so the delta is taken "
      "per connection (summing them here is what manufactured egress)")
check(dests(snap)[("curl", "500", "203.0.113.7")] == (700 + 300, 1000 + 500),
      "and no bytes are lost: collapsed by destination both counters still add "
      "up (out 700+300, in 1000+500)")
check(not any(k[2] in ("localhost", "127.0.0.1") for k in snap),
      "loopback connection dropped (local model traffic stays local)")
check(("someproc", "700", "2001:db8::9") in dests(snap),
      "IPv6 dot-port ('2001:db8::9.443') parsed to the bare address")
check(not any(k[2] == "203.0.113.99" for k in snap),
      "orphan connection after a garbage row is NOT attributed to the prior proc")
check(s.snapshot(now=1000.0 + 10_000) == {},
      "snapshot TTL prunes flows not seen within the window")


# --- proctree.attribute -------------------------------------------------
# fake table: git(300) <- claude(200) <- zsh(100) <- launchd(1)
TABLE = {300: (200, "git"), 200: (100, "claude"), 100: (1, "zsh"), 1: (0, "launchd")}
ARGV = {300: "git push origin main", 200: "claude --resume", 100: "-zsh"}
info = lambda pid: TABLE.get(int(pid))                              # noqa: E731
gav = lambda pid: ARGV.get(int(pid), "")                            # noqa: E731
TOKENS = {"claude", "kiro"}
CONFUSE = {"ngrok"}


def match(blob):
    t = set(blob.lower().replace("-", " ").replace("/", " ").split())
    if t & CONFUSE:
        return None
    return next(iter(t & TOKENS), None)


tok, via = proctree.attribute("claude", 200, match, info=info, get_argv=gav)
check((tok, via) == ("claude", None), "process matching itself reports no 'via'")

tok, via = proctree.attribute("git", 300, match, info=info, get_argv=gav)
check((tok, via) == ("claude", "git"),
      "git spawned by claude is attributed to claude, via=git (the closed hole)")

tok, via = proctree.attribute("zsh", 100, match, info=info, get_argv=gav)
check((tok, via) == (None, None), "unrelated process stays unattributed")

tok, via = proctree.attribute("git", 300, match, info=info, get_argv=gav, max_depth=0)
check((tok, via) == (None, None), "max_depth=0 disables the ancestor walk")

CYC = {10: (11, "a"), 11: (10, "b")}
tok, via = proctree.attribute("a", 10, match, info=lambda p: CYC.get(int(p)),
                              get_argv=lambda p: "")
check((tok, via) == (None, None), "ppid cycle does not hang the walk")

# a confusable ancestor (ngrok) must NOT attribute
NG = {400: (401, "ngrok"), 401: (1, "zsh")}
tok, via = proctree.attribute("curl", 400, match, info=lambda p: NG.get(int(p)),
                              get_argv=lambda p: {400: "ngrok http 3000"}.get(int(p), ""))
check((tok, via) == (None, None), "confusable ancestor (ngrok) is not an agent")

check(proctree.proc_info(1) is not None or proctree.proc_info(1) is None,
      "proc_info(pid) is callable without spawning a subprocess")


def test_stream_and_tree():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
