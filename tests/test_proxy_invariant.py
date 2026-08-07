#!/usr/bin/env python3
"""
Under proxy mode the allowlist must not pre-filter the proxy invariant.

THE GAP (found by external review 2026-08-07). RESEARCH-PROGRAM calls the proxy
invariant "the only detector in this repo that survives the repo's own
impossibility argument": if a proxy is configured, agent traffic is supposed to
go to the proxy and nowhere else, so a direct socket IS the finding regardless of
volume, reputation or declaration.

But `aggregate_flows` short-circuits allowlisted destinations -- `agg["ai"] +=
delta` and nothing else -- so a flow that bypassed the proxy to reach
`api.anthropic.com` directly never reached the Reconciler at all. Measured: 50 MB
straight to an allowlisted endpoint with a proxy configured produced NOTHING at
the hook.

That is not a false accusation, so it is not the P0 the other two were. It is
worse in a different way: it removes the most likely bypass target from the
detector the research programme is being built on. An agent that wants to reach
the network without the proxy will reach *its own API*, which is the one host on
the allowlist.

The invariant is structural -- "this socket should not exist" -- and structure is
orthogonal to destination reputation.

WHAT MUST NOT REGRESS: allowlisted bytes still stay out of the ledger, the
covert-channel detector and the fan-out counter. Splitting AI-endpoint bytes from
the rest inside one process is what kills the telemetry-SDK false positive, and
without proxy mode nothing changes at all.

Run:  python3 tests/test_proxy_invariant.py
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import sentinel as S                                                 # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


AI_FLOW = {("claude", "100", "203.0.113.9", "10.0.0.5:5<->203.0.113.9:443"):
           S.Bytes(50 * 1024 * 1024, 0)}
NONAI_FLOW = {("claude", "100", "198.51.100.4", "10.0.0.5:6<->198.51.100.4:443"):
              S.Bytes(9 * 1024 * 1024, 0)}


def run(flows, dom):
    seen = []
    per_pid = S.aggregate_flows(
        flows, {}, lambda ip: dom, lambda d: d == "api.anthropic.com",
        observe=lambda pid, kind, dest, delta, ip: seen.append((kind, dest, delta)))
    return per_pid, seen


# --- the gap -----------------------------------------------------------------
per_pid, seen = run(AI_FLOW, "api.anthropic.com")
ai_hits = [s for s in seen if s[0] == "ai"]
check(len(ai_hits) == 1 and ai_hits[0][1] == "api.anthropic.com",
      "an allowlisted destination REACHES the observe hook, tagged 'ai', so the "
      "proxy invariant can see a bypass to the agent's own API -- the single "
      "most likely host an escaping agent would choose")
check(ai_hits and ai_hits[0][2] == 50 * 1024 * 1024,
      "with its real byte count, not a truncated or zeroed one")

# --- what must not regress ---------------------------------------------------
check(per_pid[("claude", "100")]["ai"] == 50 * 1024 * 1024
      and per_pid[("claude", "100")]["nonai"] == 0,
      "the ai/nonai split is unchanged: allowlisted bytes still do not become "
      "nonai (this is what kills the telemetry-SDK false positive)")
check(not any(s[0] in ("dom", "ip") for s in seen),
      "and they are NOT tagged 'dom' or 'ip', so a caller routing by kind can "
      "keep them out of the ledger, covert-channel detector and fan-out counter")
check(per_pid[("claude", "100")]["dests"] == {},
      "an allowlisted destination is still absent from the per-pid dests map "
      "that feeds the alert text")

per_pid, seen = run(NONAI_FLOW, "evil.example.com")
check([s[0] for s in seen] == ["dom"],
      "a non-allowlisted destination is unchanged: still exactly one 'dom' "
      "observation")
check(per_pid[("claude", "100")]["nonai"] == 9 * 1024 * 1024,
      "and still counted as nonai")

per_pid, seen = run(
    {("claude", "100", "198.51.100.9", "10.0.0.5:7<->198.51.100.9:443"):
     S.Bytes(1024, 0)}, None)
check([s[0] for s in seen] == ["ip"],
      "an unresolved destination is unchanged: still exactly one 'ip' observation")


def test_proxy_invariant():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
