#!/usr/bin/env python3
"""
The AGENT side of the reconciliation contract: append one declaration.

Import it from a hook, or call it as a CLI from a shell wrapper:

    from declare import declare
    declare("fetch", target="https://docs.example.com/x", nbytes=len(body))

    python3 declare.py fetch docs.example.com 2048
    python3 declare.py bash                      # no target: see the warning

Deliberately dependency-free and about forty lines, because it has to run inside
someone else's agent process and must never be the reason that process fails.
Every error is swallowed: a monitoring side channel that can break the thing it
monitors is worse than no monitoring.

Atomicity: one `write()` of a single short line to a file opened O_APPEND is
atomic on POSIX below PIPE_BUF (4096 bytes here), so concurrent hooks in several
processes interleave whole lines rather than corrupting each other. Lines are
truncated to stay under that limit for exactly this reason.

WHAT TO PASS, AND THE ONE THING NOT TO DO
-----------------------------------------
`target` should be the destination the tool is about to contact. A URL is fine:
it is reduced to its HOST BEFORE anything is written, so a token in a query
string (`?access_token=`, a presigned S3 signature) never reaches the file. Only
the host is ever compared, so nothing is lost. `nbytes` is the outbound payload
size if you know it -- it lets the reader notice a declared 2 KB POST that
measured 40 MB.

Calling this with NO target marks the whole process as declared-active and
suppresses reconciliation for it. That is sometimes the honest thing to log (a
`bash` tool really can do anything), but it is also the easiest way to switch the
check off by accident. Prefer a target whenever one exists.
"""

import json
import os
import sys
import time

try:
    from paths import ACTIVITY_FILE as _DEFAULT
except Exception:                                        # standalone copy
    _DEFAULT = os.path.expanduser("~/.agent-egress-sentinel/activity.ndjson")

MAX_LINE = 4000                                          # stay under PIPE_BUF


def _host(target):
    """Reduce a URL to its host BEFORE writing.

    The reader also does this, but doing it here is the part that matters: the
    reader dropping a query string does not help if the query string is already
    sitting in a file on disk. A full URL routinely carries tokens
    (`?access_token=`, presigned S3 signatures), and this feature needs exactly
    none of it -- only the host is ever compared. So the secret is never written,
    rather than written and then ignored.
    """
    t = str(target).strip()
    if "//" in t:
        t = t.split("//", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if t.startswith("["):
        t = t[1:].split("]", 1)[0]
    elif t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t.lower().rstrip(".")


def declare(tool, target=None, nbytes=None, pid=None, path=None, ts=None):
    """Append one declaration. Returns True on success, False on any failure.

    Never raises. `pid` defaults to os.getpid(); pass the pid that will actually
    do (or spawn) the I/O if the hook runs somewhere else -- the reader matches a
    declaration to traffic from that pid OR any of its descendants.
    """
    rec = {"ts": float(time.time() if ts is None else ts),
           "pid": int(os.getpid() if pid is None else pid),
           "tool": str(tool)[:64]}
    if target is not None:
        h = _host(target)
        if h:
            rec["target"] = h[:255]
    if nbytes is not None:
        try:
            rec["bytes"] = int(nbytes)
        except (TypeError, ValueError):
            pass
    line = json.dumps(rec, separators=(",", ":"))
    if len(line) > MAX_LINE:                             # drop target, keep rest
        rec.pop("target", None)
        line = json.dumps(rec, separators=(",", ":"))
    try:
        p = _DEFAULT if path is None else path
        os.makedirs(os.path.dirname(str(p)), exist_ok=True)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        return True
    except Exception:
        return False                                     # never break the caller


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__.strip().splitlines()[0])
        print("usage: declare.py <tool> [target] [bytes]")
        sys.exit(2)
    ok = declare(sys.argv[1],
                 target=sys.argv[2] if len(sys.argv) > 2 else None,
                 nbytes=sys.argv[3] if len(sys.argv) > 3 else None)
    sys.exit(0 if ok else 1)
