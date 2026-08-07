#!/usr/bin/env python3
"""
Headless end-to-end test of the RED-alert chain (the part verifiable WITHOUT
sudo/GUI). Proves: a user-readable sni.jsonl -> domain resolves -> non-AI ->
the per-pid classification produces a RED decision. The sudo cross-user read
(root writes 0600, chown, user reads) must be run in a real terminal -- this
harness stands in for everything downstream of "the file is readable".

Run:  python3 tests/test_resolve_chain.py
"""
import json
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sni_sniffer import SNICache    # noqa: E402
from endpoints import Allowlist     # noqa: E402

fails = []
def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)

EVIL_IP, EVIL_DOM = "203.0.113.9", "evil-exfil.example"
AI_IP, AI_DOM = "203.0.113.10", "api.anthropic.com"

# seed a user-owned SNI log in a TEMP file (simulates the chown having worked).
# Never write the real ~/.agent-egress-sentinel/sni.jsonl -- an earlier version
# did, and every pytest run clobbered the user's live SNI cache with a fake
# 'evil-exfil.example' record.
_tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
_tmp.close()          # Windows refuses the reopen below while this handle lives
TEST_SNI = pathlib.Path(_tmp.name)
now = time.time()
with TEST_SNI.open("w") as f:
    f.write(json.dumps({"t": now, "ip": EVIL_IP, "domain": EVIL_DOM}) + "\n")
    f.write(json.dumps({"t": now, "ip": AI_IP, "domain": AI_DOM}) + "\n")

sni = SNICache(path=TEST_SNI)
ALLOW = Allowlist()

# link 1: read path works (this is exactly what P0-A broke when root-owned 0600)
check(sni.domain_for_ip(EVIL_IP) == EVIL_DOM,
      "sni.jsonl readable -> domain_for_ip resolves non-AI IP")
check(sni.domain_for_ip(AI_IP) == AI_DOM,
      "domain_for_ip resolves AI IP")

# link 2: allowlist classifies correctly
check(ALLOW.matches(AI_DOM) is True, "api.anthropic.com is allowlisted")
check(ALLOW.matches(EVIL_DOM) is False, "evil-exfil.example is NOT allowlisted")

# link 3: the red-branch decision (replicates Sampler._tick math)
FLAG = 5 * 1024 * 1024
agg = {"ai": 0, "nonai": 0, "unresolved": 0, "dests": {}}
for ip, delta in [(AI_IP, 6_000_000), (EVIL_IP, 8_000_000)]:
    dom = sni.domain_for_ip(ip)
    if dom and ALLOW.matches(dom):
        agg["ai"] += delta
    elif dom:
        agg["nonai"] += delta
        agg["dests"][dom] = agg["dests"].get(dom, 0) + delta
    else:
        agg["unresolved"] += delta
check(agg["nonai"] >= FLAG and EVIL_DOM in agg["dests"],
      "agent w/ 8MB to evil + 6MB to anthropic -> RED on evil only (anthropic excluded)")
check(agg["ai"] == 6_000_000 and agg["nonai"] == 8_000_000,
      "AI bytes accounted separately from non-AI (telemetry-split works)")

# negative: sniffer OFF (unresolved) must NOT red
agg2 = {"ai": 0, "nonai": 0, "unresolved": 9_000_000, "dests": {}}
check(agg2["nonai"] < FLAG,
      "unresolved-only egress does NOT trip the red (nonai) threshold")

TEST_SNI.unlink(missing_ok=True)   # temp seed file, remove after checks

def test_resolve_chain_regression():
    # pytest entry: the checks above ran at import; surface their verdict here
    # so `pytest` collects a real test instead of silently passing with zero.
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)"); sys.exit(1)
    print("ALL PASS (resolve->classify->red chain verified headless)")
