#!/usr/bin/env python3
"""
Dead-man switch: silence as a signal.

The sentinel runs as the user with no launchd job, so anything it watches can kill
it, and a dead sentinel looks exactly like a quiet machine. These tests pin what
the heartbeat DOES catch (crash / naive kill / pid reuse / coverage gaps) and --
just as importantly -- assert the ONE thing it does not: an adversary that keeps
writing beats after killing the app. Documenting that as a passing test stops a
future reader from mistaking this for tamper-proof.

Run:  python3 tests/test_deadman.py
"""
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import deadman                                                      # noqa: E402
import proctree                                                     # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


def tmp():
    return pathlib.Path(tempfile.mkdtemp()) / "heartbeat.json"


# --- live beat ----------------------------------------------------------
p = tmp()
deadman.beat(now=1000.0, path=p)
rec = deadman.read_beat(p)
check(rec is not None and rec["ts"] == 1000.0, "beat is written and readable")
check(rec.get("pid") == __import__("os").getpid(),
      "beat carries the writer's pid (identity, not just a timestamp)")
check(rec.get("start") == proctree.proc_start(rec["pid"]),
      "beat carries the process START TIME, so pid reuse can't inherit identity")

# a fresh beat from a live process is NOT stale
check(deadman.stale_for(now=1000.0 + 2, path=p) is None,
      "recent beat from a living process -> not stale")

# --- staleness ----------------------------------------------------------
check(deadman.stale_for(now=1000.0 + 3600, path=p) is not None,
      "old beat -> stale (the app stopped beating)")

# process gone: claim a pid that cannot exist
p2 = tmp()
p2.write_text(json.dumps({"ts": 1000.0, "pid": 999_999_999, "start": 1}))
check(deadman.stale_for(now=1000.0 + 1, path=p2) is not None,
      "beat claiming a DEAD pid -> stale immediately, even with a fresh timestamp")

# pid reuse: real live pid, wrong start time
import os                                                           # noqa: E402
p3 = tmp()
p3.write_text(json.dumps({"ts": 1000.0, "pid": os.getpid(), "start": 1}))
check(deadman.stale_for(now=1000.0 + 1, path=p3) is not None,
      "beat whose start time does not match the live pid -> stale (impersonation)")

# no heartbeat at all is not 'stale' -- nothing ever claimed to be running
check(deadman.stale_for(now=1000.0, path=tmp()) is None,
      "absent heartbeat is not reported as stale (never started != died)")

# --- coverage gap -------------------------------------------------------
p4 = tmp()
deadman.beat(now=1000.0, path=p4)
check(deadman.coverage_gap(now=1000.0 + 3600, path=p4) is not None,
      "a stale prior beat is reported as a coverage gap at startup")
check(deadman.coverage_gap(now=1000.0 + 5, path=p4) is None,
      "a restart within the gap threshold is not reported as a gap")
check(deadman.coverage_gap(now=1000.0, path=tmp()) is None,
      "first ever run reports no gap")

# --- the honest limit: forged beats are NOT detected --------------------
p5 = tmp()
forged = {"ts": 1000.0, "pid": os.getpid(), "start": proctree.proc_start(os.getpid())}
p5.write_text(json.dumps(forged))
check(deadman.stale_for(now=1000.0 + 1, path=p5) is None,
      "KNOWN LIMIT: a beat forged with a live pid+start passes -- an adversary "
      "that kills the app and keeps beating is NOT detected (needs a privileged "
      "helper, see ROADMAP); this test exists so nobody assumes otherwise")


def test_deadman():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
