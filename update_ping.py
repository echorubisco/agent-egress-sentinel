#!/usr/bin/env python3
"""
Update check — and the app's own egress, logged first.

This exists for one reason now: the FIRST line of the app's egress log is this
app's own outbound connection. "We monitor every outbound connection, including
our own" is a claim, and this is the smallest thing that makes it a demonstrable
one — you can see the tool report on itself before it reports on anything else.

WHAT THIS DELIBERATELY IS NOT (changed 2026-08-06). It used to point at a
Cloudflare Worker so the server could count unique source IPs as a crude
active-install number. That was an instrument for a demand experiment that no
longer exists (see LAUNCH-PREREGISTRATION.md, superseded), and an install count
is not worth an endpoint that logs who runs this. It is now a static JSON in
this repo served by raw.githubusercontent.com, which gives us no access logs at
all. There is no telemetry here and no way to add some without changing this
file. Nothing is sent but a User-Agent carrying the version.
"""

import urllib.request
import json

VERSION = "0.1.0"
# One string, used everywhere. Set it when the repo goes public -- PRE-FLIGHT.md
# has the one-liner that rewrites every occurrence in the tree.
REPO = "YOUR-GITHUB-USER/agent-egress-sentinel"
UPDATE_URL = f"https://raw.githubusercontent.com/{REPO}/main/version.json"
TIMEOUT = 5


def update_check_and_log(log):
    """Do the version ping and log it as our own egress (the trust act)."""
    log(f"SELF-EGRESS: update check -> {UPDATE_URL} "
        f"(this is us; we log our own connections too)")
    try:
        req = urllib.request.Request(
            UPDATE_URL,
            headers={"User-Agent": f"agent-egress-sentinel/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read().decode())
        latest = data.get("version", VERSION)
        # The response can also carry the latest ai_endpoints.yaml version, which
        # would make this a detection-content update channel rather than a
        # version banner. Not read in v0 -- pulling a live allowlist means this
        # endpoint decides what your machine treats as legitimate, which needs
        # signing before it needs convenience.
        if latest != VERSION:
            log(f"update available: {latest} (running {VERSION})")
            return latest
    except Exception as e:
        # Network off / endpoint not set yet — non-fatal for the skeleton.
        log(f"update check skipped: {e}")
    return None


if __name__ == "__main__":
    update_check_and_log(lambda s: print(s))
