#!/usr/bin/env python3
"""
The Claude Code PreToolUse hook (hooks/claude_code_declare.py).

The whole hook is target extraction plus a pid walk, and both fail silently:

  - IT MUST NEVER INVENT A TARGET. A declaration with no `target` is a wildcard
    that marks the pid declared-active, i.e. an off-switch for reconciliation on
    that process. A hook that emitted one per Bash call would look like it was
    feeding the reconciler while switching it off. So "no host found" must mean
    "write nothing", and that is asserted here rather than left to the docstring
    -- this repo has already shipped one noise control that quietly deleted the
    signal it existed for (ROADMAP 2026-08-03).
  - IT MUST NOT WRITE SECRETS. Tool URLs carry tokens. declare.py reduces to a
    host before writing; the assertion here is end-to-end through the hook,
    because that is the path that actually runs.
  - IT MUST NEVER RAISE. It runs before every tool call.

Run:  python3 tests/test_hook_declare.py
"""
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "hooks"))
import claude_code_declare as hook                                   # noqa: E402

HOOK = pathlib.Path(__file__).resolve().parent.parent / "hooks" / "claude_code_declare.py"

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


# ---- target extraction: what gets declared -------------------------------
check(hook.targets("WebFetch", {"url": "https://docs.example.com/a"})
      == ["https://docs.example.com/a"],
      "WebFetch declares its url")
check(hook.targets("Bash", {"command": "curl -sL https://api.github.com/x"})
      == ["api.github.com"],
      "Bash declares a host inside a URL")
check(hook.targets("Bash", {"command": "git push git@github.com:me/r.git main"})
      == ["github.com"],
      "Bash declares an scp/ssh-style host")
check(hook.targets("Bash", {"command": "curl https://a.com/1 && curl https://a.com/2"})
      == ["a.com"],
      "duplicate hosts collapse to one declaration")

# ---- target extraction: what must NOT get declared -----------------------
check(hook.targets("Bash", {"command": "ls -la && pytest -q"}) == [],
      "Bash with no host declares NOTHING (never a target-less wildcard)")
check(hook.targets("Bash", {"command": ""}) == [],
      "empty Bash command declares nothing")
check(hook.targets("Read", {"file_path": "/etc/hosts"}) == [],
      "non-network tools declare nothing")
check(hook.targets("WebSearch", {"query": "x"}) == [],
      "WebSearch declares nothing (its egress is the allowlisted API endpoint)")
check(hook.targets("WebFetch", {}) == [],
      "WebFetch with no url declares nothing rather than a wildcard")

# ---- end-to-end through the real script ---------------------------------
def run(payload):
    """Feed the hook on stdin exactly as Claude Code does. Returns (rc, lines)."""
    import os
    import shutil
    import tempfile
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="hookdecl-"))
    env = dict(os.environ, HOME=str(tmp), USERPROFILE=str(tmp))
    env.pop("SENTINEL_DECLARE_PID", None)
    p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                       capture_output=True, text=True, env=env, timeout=30)
    out = tmp / ".agent-egress-sentinel" / "activity.ndjson"
    lines = [json.loads(x) for x in out.read_text().splitlines()] if out.exists() else []
    shutil.rmtree(tmp, ignore_errors=True)
    return p.returncode, lines


rc, lines = run({"tool_name": "WebFetch",
                 "tool_input": {"url": "https://docs.example.com/x?access_token=SECRET"}})
check(rc == 0, "hook exits 0 on a normal call")
check(len(lines) == 1, "one declaration written for one WebFetch")
if lines:
    rec = lines[0]
    check(rec.get("target") == "docs.example.com", "target reduced to a host")
    check("SECRET" not in json.dumps(rec), "the token in the url never reaches disk")
    check("bytes" not in rec,
          "no `bytes` field -- outbound size is unknown pre-call, so the volume "
          "sub-check is skipped rather than fed an invented number")
    check(set(rec) >= {"ts", "pid", "tool"}, "the three required contract fields are present")

rc, lines = run({"tool_name": "Bash", "tool_input": {"command": "make test"}})
check(rc == 0 and lines == [],
      "a hostless Bash call writes no line at all (the off-switch stays shut)")

for bad in ("not json", "", "[]", '{"tool_name": null}'):
    p = subprocess.run([sys.executable, str(HOOK)], input=bad,
                       capture_output=True, text=True, timeout=30)
    check(p.returncode == 0, f"hook exits 0 on malformed stdin: {bad!r}")


def test_hook_declare():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
