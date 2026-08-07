#!/usr/bin/env python3
"""
First-observation semantics (the 2026-07-27 root-cause fix) + fan-out identity.

Before the fix, `delta = total - baseline.get(key, total)` meant a flow's first
sighting contributed ZERO. Measured consequences on a real host:
  - 94.2% of the outbound bytes of newly-opened flows were discarded
    (34 of 40 new flows contributed nothing at all), and
  - the fan-out counter recorded 0 of 25 real destinations, because a probe's
    outbound bytes are already final when the flow is first seen.

These tests pin the corrected rules and the IP-keyed fan-out identity.
Run:  python3 tests/test_baseline.py      (no rumps/nettop needed)
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sentinel import aggregate_flows, Bytes                         # noqa: E402

NO_SNI = lambda ip: None                                            # noqa: E731
NOT_AI = lambda dom: False                                          # noqa: E731
fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


def _un(per_pid, key=("claude", "100")):
    return per_pid.get(key, {}).get("unresolved", 0)


# 1) NEW flow (never in baseline) is counted in full -- the core fix. A 70 MB
#    single-sighting flow used to produce no entry at all.
one_shot = {("claude", "100", "203.0.113.9"): 70 * 1024 * 1024}
check(_un(aggregate_flows(one_shot, {}, NO_SNI, NOT_AI)) == 70 * 1024 * 1024,
      "flow seen once with empty baseline is counted IN FULL (was 0)")

# 2) A probe-sized new flow is counted (this is exactly the 0/25 fan-out case)
probe = {("claude", "100", "203.0.113.9"): 518}
check(_un(aggregate_flows(probe, {}, NO_SNI, NOT_AI)) == 518,
      "518-byte probe flow (bytes final at first sighting) is counted")

# 3) warmup=True still seeds only -- a cold sampler start must not dump the
#    pre-existing cumulative of every open socket as fresh egress.
check(_un(aggregate_flows(one_shot, {}, NO_SNI, NOT_AI, warmup=True)) == 0,
      "warmup=True seeds baseline without counting (no red on launch)")

# 4) normal growth across ticks: only the increment counts
grown = {("claude", "100", "203.0.113.9"): 1500}
check(_un(aggregate_flows(grown, {("claude", "100", "203.0.113.9"): 1000},
                          NO_SNI, NOT_AI)) == 500,
      "known flow contributes only its increment (1500-1000)")

# 5) counter reset (socket or pid reuse): total < previous -> count total, not a
#    negative (which the old code silently dropped, losing the new flow forever)
reset = {("claude", "100", "203.0.113.9"): 300}
check(_un(aggregate_flows(reset, {("claude", "100", "203.0.113.9"): 9999},
                          NO_SNI, NOT_AI)) == 300,
      "counter reset (total < previous) counts total, not skipped")

# 6) no double counting: same flow, same cumulative, second tick -> zero
same = {("claude", "100", "203.0.113.9"): 518}
check(_un(aggregate_flows(same, {("claude", "100", "203.0.113.9"): 518},
                          NO_SNI, NOT_AI)) == 0,
      "unchanged cumulative contributes nothing (no double count)")

# 7) fan-out identity is the IP even when SNI resolved the domain, so a service
#    counted as an IP before its SNI was known is not counted twice.
seen = []
aggregate_flows({("claude", "100", "203.0.113.9"): 900},
                {}, lambda ip: "cdn.example.com", NOT_AI,
                observe=lambda pid, kind, dest, delta, ip: seen.append((kind, dest, ip)))
check(seen == [("dom", "cdn.example.com", "203.0.113.9")],
      "observe() carries BOTH dest and ip (fan-out keys on ip, ledger on dest)")


# --- bytes_in goes through the SAME rule (added 2026-08-02) ----------------
# bytes_in sat one column left of bytes_out in every nettop header and was
# simply never read. It is context, not a gate: "a page read should not upload
# 5 MB" is a RATIO and we only had the numerator. These pin that the second
# counter obeys the identical first-observation rules -- one shared `_delta`,
# so the two cannot drift apart.
def _in(per_pid, key=("claude", "100")):
    return per_pid.get(key, {}).get("in", 0)


newf = {("claude", "100", "203.0.113.9"): Bytes(518, 300_000)}
check(_in(aggregate_flows(newf, {}, NO_SNI, NOT_AI)) == 300_000,
      "new flow's bytes_in counted IN FULL (same rule as bytes_out)")

check(_in(aggregate_flows(newf, {}, NO_SNI, NOT_AI, warmup=True)) == 0,
      "warmup contributes 0 for bytes_in too (no cold-start invention)")

grown_in = {("claude", "100", "203.0.113.9"): Bytes(1500, 9000)}
check(_in(aggregate_flows(grown_in,
                          {("claude", "100", "203.0.113.9"): Bytes(1000, 5000)},
                          NO_SNI, NOT_AI)) == 4000,
      "known flow yields only the bytes_in increment (9000-5000)")

mixed = {("claude", "100", "203.0.113.9"): Bytes(1500, 40)}
check(_in(aggregate_flows(mixed,
                          {("claude", "100", "203.0.113.9"): Bytes(1000, 5000)},
                          NO_SNI, NOT_AI)) == 40,
      "bytes_in counter reset detected INDEPENDENTLY of bytes_out")

check(_in(aggregate_flows(grown_in,
                          {("claude", "100", "203.0.113.9"): 1000},
                          NO_SNI, NOT_AI)) == 9000,
      "legacy int baseline = out-only; bytes_in has no prev so counts in full")

# Gating must be unchanged: bytes_in can never suppress or create a row.
only_down = {("claude", "100", "203.0.113.9"): Bytes(0, 5_000_000)}
check(_un(aggregate_flows(only_down, {}, NO_SNI, NOT_AI)) == 0
      and _in(aggregate_flows(only_down, {}, NO_SNI, NOT_AI)) == 0,
      "pure-download flow (0 out) is still dropped -- bytes_in cannot create a row")


def test_baseline_semantics():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
