#!/usr/bin/env python3
"""
Dead-man switch: treat the sentinel's own silence as a signal.

Why this exists. The menu-bar process runs as your user, with no launchd job and
no system extension -- that is what makes it uninstall cleanly, and it is also why
anything it watches can end it with one `kill`. A stopped sentinel looks exactly
like a quiet machine: green icon, no alerts. That failure mode is worse than a
missed alert, because it is silent.

WHO WATCHES THE WATCHER. The observer has to outrank the observed, or the same
`kill` takes both. We already have one process that does: the sniffer runs under
`sudo`, so a user-level agent cannot kill it. It therefore does the staleness
check, and reports to its own stdout/log -- one privilege level above the thing it
is checking.

WHAT THIS DOES AND DOES NOT DETECT -- read this before trusting it:
  - DETECTS: crash, OOM kill, an unhandled exception, the user quitting the app,
    and a naive `kill` by an agent that does not know about the heartbeat.
  - DETECTS: pid reuse / impersonation, because a beat carries (pid, start_time)
    and the root-side check verifies that exact process is still alive.
  - DOES NOT DETECT: an adaptive adversary that kills the sentinel and then keeps
    writing plausible beats. The heartbeat file is owned by the user, so anything
    running as that user can forge it. Closing that needs a secret the sentinel
    can use but the agent cannot read, which is not possible at equal privilege --
    it needs the privileged-helper design in ROADMAP, not this file.

Coverage gaps. On start the sentinel reads the previous beat; if it is old, that
window was unmonitored and is surfaced as an amber alert. "We were not watching
from T1 to T2" is a fact the user should see, not something to quietly resume past.
"""

import json
import os
import time

from paths import DATA_DIR
import proctree

HEARTBEAT = DATA_DIR / "heartbeat.json"

BEAT_STALE_SEC = 15          # a 1 s tick that has not beaten in 15 s is not alive
GAP_REPORT_SEC = 60          # only surface a coverage gap longer than this


def beat(now=None, path=None):
    """Record a live beat. Atomic write so a reader never sees a half file."""
    now = time.time() if now is None else now
    path = HEARTBEAT if path is None else path
    pid = os.getpid()
    rec = {"ts": now, "pid": pid, "start": proctree.proc_start(pid)}
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(rec))
        os.replace(tmp, path)
    except OSError:
        pass


def read_beat(path=None):
    path = HEARTBEAT if path is None else path
    try:
        rec = json.loads(path.read_text())
        return rec if isinstance(rec, dict) and "ts" in rec else None
    except (OSError, ValueError):
        return None


def coverage_gap(now=None, path=None, min_gap=GAP_REPORT_SEC):
    """Seconds of unmonitored time before this start, or None.

    Called once at startup: a previous beat that is older than min_gap means the
    machine ran unwatched for that long."""
    now = time.time() if now is None else now
    rec = read_beat(path)
    if not rec:
        return None
    gap = now - float(rec["ts"])
    return gap if gap >= min_gap else None


def stale_for(now=None, path=None):
    """Seconds since the last beat, or None when the beat is current/absent.

    This is the ROOT-SIDE check (the sniffer calls it). Returns a positive age
    when the sentinel should be beating but is not, INCLUDING the case where the
    claimed process is gone or has been replaced by a different process reusing
    its pid.
    """
    now = time.time() if now is None else now
    rec = read_beat(path)
    if not rec:
        return None                      # never started: nothing to be stale about
    age = now - float(rec["ts"])
    claimed_pid, claimed_start = rec.get("pid"), rec.get("start")
    if claimed_pid is not None:
        actual_start = proctree.proc_start(claimed_pid)
        if actual_start is None:
            return max(age, 0.0) or 0.001        # the process is gone -> stale now
        if claimed_start is not None and actual_start != claimed_start:
            return max(age, 0.0) or 0.001        # pid reused by a different process
    return age if age > BEAT_STALE_SEC else None
