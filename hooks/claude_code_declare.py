#!/usr/bin/env python3
"""
Claude Code PreToolUse hook -> the L1 declaration contract.

This is the missing half of the reconciler. `activity.ndjson` has had a reader,
a contract, 35 assertions and zero producers since 2026-08-02, which is why the
reconciler's false-positive rate is the single largest unknown in this repo. This
is the producer. It is small on purpose.

INSTALL
    Add to ~/.claude/settings.json (or .claude/settings.json in a project):

      {
        "hooks": {
          "PreToolUse": [
            {
              "matcher": "WebFetch|Bash",
              "hooks": [
                { "type": "command",
                  "command": "python3 /ABS/PATH/TO/hooks/claude_code_declare.py" }
              ]
            }
          ]
        }
      }

    Then run the sentinel. Reconciliation switches itself on as soon as this file
    starts being written to, and back off after five idle minutes.

THE TWO THINGS THAT ARE EASY TO GET WRONG HERE
----------------------------------------------
1. THE PID IS NOT os.getpid(). The reconciler matches a declaration to traffic
   from the declared pid OR ANY DESCENDANT. This hook is a *child* of the agent,
   so declaring our own pid would match nothing: the agent's own WebFetch socket
   belongs to an ancestor, not a descendant. We walk up to the agent and declare
   ITS pid, which then covers both the agent's own sockets and anything it shells
   out to. Getting this backwards produces a hook that runs perfectly, writes
   well-formed lines, and reconciles zero traffic -- the exact failure mode this
   repo keeps rediscovering (see ROADMAP: "a discarding noise control and a
   detector that does not work are indistinguishable from the outside").

2. NO TARGET MEANS "SILENCE THIS PID", SO WE NEVER GUESS ONE. A declaration with
   no `target` is a wildcard: it marks the whole process declared-active. A hook
   that fired a target-less line on every Bash call would switch reconciliation
   off across the board while looking like it was feeding it. So when we cannot
   name a host we write NOTHING. A `bash` command with no host in it should not
   be opening sockets, and if it does, that is precisely the finding we want to
   survive. Under-declaring costs false positives, which are visible and
   enumerable; over-declaring costs silence, which is not.

WHAT IT DOES NOT DECLARE, AND WHY THAT IS THE POINT
    - No `bytes`. We do not know the outbound size before the call. Per the
      contract, a declaration without `bytes` skips the volume sub-check
      entirely rather than inventing a number. Presence matching still works.
    - Nothing for Read/Write/Edit/Glob/Grep (no network) or WebSearch (goes to
      the API endpoint, which is already on the allowlist).
    - Nothing for a Bash command whose host we could not parse. See point 2.

Never raises, never blocks a tool call, always exits 0. A monitoring side channel
that can break the thing it monitors is worse than no monitoring.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proctree                                                      # noqa: E402
from declare import declare                                          # noqa: E402
from endpoints import Allowlist                                      # noqa: E402

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_URL = re.compile(r"\bhttps?://([A-Za-z0-9._~-]+(?::\d+)?)")
_SCP = re.compile(r"\b[A-Za-z0-9._-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})[:/]")


def agent_pid():
    """The pid whose descendants will do the I/O, i.e. the agent, not us.

    Walks our own ancestry through proctree, so it works wherever Claude Code
    does. Process names come free with the walk and settle it on their own
    whenever the agent is named after itself (`claude`, `claude.exe`); command
    lines cost a fork, so they are fetched in one batch and only if the names
    were inconclusive -- an agent running as a bare `node`. This runs before
    every tool call, and six `ps` forks per call is not a price a monitoring
    side channel gets to charge.

    Falls back to the parent, which is the right answer whenever the agent
    spawns hooks directly. SENTINEL_DECLARE_PID overrides everything, for the
    case where an agent runs under a wrapper this cannot see through.
    """
    override = os.environ.get("SENTINEL_DECLARE_PID")
    if override:
        try:
            return int(override)
        except ValueError:
            pass

    parent = os.getppid()
    chain = proctree.ancestors(os.getpid())[1:]      # drop ourselves
    if not chain:                                    # no process table available
        return parent

    allow = Allowlist()
    tokens, confusables = allow.agent_tokens(), allow.confusables()

    def hit(blob):
        words = set(_TOKEN_SPLIT.split(blob.lower()))
        return not (words & confusables) and bool(words & tokens)   # ngrok != grok

    names = {p: (proctree.proc_info(p) or (0, ""))[1] for p in chain}
    for pid in chain:                                # nearest ancestor first
        if hit(names[pid]):
            return pid
    # Only now pay for command lines -- one batched call, and only when the
    # process names were inconclusive (an agent running as a bare `node`).
    cmds = proctree.argv_many(chain)
    for pid in chain:
        if hit(f"{names[pid]} {cmds.get(pid, '')}"):
            return pid
    return parent


def targets(tool, payload):
    """Hosts this call is about to contact. Empty when we cannot tell."""
    if tool == "WebFetch":
        url = payload.get("url")
        return [url] if url else []
    if tool == "Bash":
        cmd = payload.get("command") or ""
        seen, out = set(), []
        for host in _URL.findall(cmd) + _SCP.findall(cmd):
            if host not in seen:
                seen.add(host)
                out.append(host)
        return out
    return []


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        return
    tool = event.get("tool_name") or ""
    hosts = targets(tool, event.get("tool_input") or {})
    if not hosts:
        return
    pid = agent_pid()
    for host in hosts:
        declare(tool, target=host, pid=pid)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
