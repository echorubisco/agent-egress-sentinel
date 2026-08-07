#!/usr/bin/env python3
"""
harvest.py — turn measured traffic into allowlist seed data.

The YAML must be seeded from MEASUREMENT, not memory. Workflow:
  1) start the sniffer:   SENTINEL_IFACE=en0 sudo -E python3 sni_sniffer.py
  2) run ONE agent doing real work ~10 min (open a repo in Cursor and let it
     index; ask Claude Code to build; etc.)
  3) python3 harvest.py            # prints unique domains seen, most-frequent first
  4) hand-sort the real ones into ai_endpoints.yaml under that provider

This is also the first rehearsal of the observatory methodology: capture what
an agent actually touches, reproducibly, from outside the agent.

NOTE: harvest shows ALL SNIs seen while it ran — that includes your browser and
other apps. Sort by hand; only add domains an agent legitimately needs.
"""

import collections
import json

from paths import SNI_FILE


def main():
    if not SNI_FILE.exists():
        raise SystemExit(f"no capture yet: {SNI_FILE}\nrun sni_sniffer.py first")
    counts = collections.Counter()
    ips = collections.defaultdict(set)
    for line in SNI_FILE.read_text().splitlines():
        try:
            r = json.loads(line)
        except Exception:
            continue
        dom = r.get("domain")
        if dom:
            counts[dom] += 1
            if r.get("ip"):
                ips[dom].add(r["ip"])
    if not counts:
        raise SystemExit("no domains captured — is the sniffer running on the right -i?")
    print(f"# {len(counts)} unique domains observed (most frequent first)")
    print("# hand-sort the AI-agent ones into ai_endpoints.yaml (with a doc link)")
    print("# ⚠️ PRIVACY: this capture contains EVERY domain this machine touched")
    print("#    (browser, mail, internal tools). Sort by hand; add ONLY agent")
    print("#    endpoints. NEVER commit the raw capture (sni.jsonl) to a public")
    print("#    repo -- it is your machine's network fingerprint.\n")
    for dom, n in counts.most_common():
        print(f"    - {dom:45}  # seen {n}x, ips={len(ips[dom])}")


if __name__ == "__main__":
    main()
