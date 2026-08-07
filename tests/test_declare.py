#!/usr/bin/env python3
"""
The writer side of the reconciliation contract (declare.py).

Two properties get assertions because both fail in ways that are invisible in
normal use:

  - IT MUST NEVER RAISE. This runs inside somebody else's agent process. A
    monitoring side channel that can break the thing it monitors is worse than
    no monitoring, so an unwritable path must return False, not throw.
  - IT MUST NOT WRITE SECRETS. A tool's URL routinely carries a token
    (`?access_token=`, a presigned S3 signature). Only the host is ever compared,
    so the host is all that may be written -- the reader dropping a query string
    later does not help if it is already on disk.

Run:  python3 tests/test_declare.py
"""
import json
import os
import pathlib
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from declare import declare, _host                                  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


tmp = pathlib.Path(tempfile.mkdtemp(prefix="declare-"))
f = tmp / "activity.ndjson"


def lines():
    return [json.loads(x) for x in f.read_text().strip().split("\n") if x]


# --- secrets never reach disk ------------------------------------------------
check(declare("fetch", target="https://u:pw@API.Example.com:443/p?access_token=SEK",
              nbytes=2048, path=f) is True,
      "declare returns True on success")
raw = f.read_text()
check("SEK" not in raw and "access_token" not in raw,
      "a token in the query string is NOT written to the file (the URL is "
      "reduced to its host before anything is written)")
check("pw" not in raw and "/p" not in raw,
      "userinfo and path are not written either")
rec = lines()[0]
check(rec["target"] == "api.example.com",
      "what IS written is the lowercased host, which is all the reader compares")
check(rec["bytes"] == 2048 and rec["tool"] == "fetch" and rec["pid"] == os.getpid()
      and isinstance(rec["ts"], float),
      "required fields are present and typed (ts float, pid int)")

# --- optional fields ---------------------------------------------------------
declare("bash", path=f)
check("target" not in lines()[1] and "bytes" not in lines()[1],
      "a target-less declaration omits the key rather than writing null "
      "(the reader treats a missing target as a wildcard for the pid)")

# --- never raises ------------------------------------------------------------
# A path *under a regular file* is unopenable on every platform (ENOTDIR /
# NotADirectoryError). The previous probe was "/proc/definitely/not/writable/",
# which POSIX rejects but Windows happily creates as C:\proc\... -- so the check
# silently passed on the strength of the write succeeding.
_blocker = tmp / "iam-a-file"
_blocker.write_text("x")
check(declare("x", path=str(_blocker / "sub" / "a.ndjson")) is False,
      "an unwritable path returns False instead of raising -- this runs inside "
      "the agent's process and must never be the reason it fails")
check(declare("x", target=object(), path=f) is not None,
      "a junk target does not raise")
check(declare("x", nbytes="not-a-number", path=f) is True
      and "bytes" not in lines()[-1],
      "a non-numeric bytes value is dropped, not written and not raised on")

# --- long input is bounded ---------------------------------------------------
check(declare("t" * 500, target="h" * 5000 + ".example", nbytes=1, path=f) is True,
      "absurdly long tool/target still writes")
last = f.read_text().strip().split("\n")[-1]
check(len(last) < 4096,
      "the line stays under PIPE_BUF so concurrent O_APPEND writes from several "
      "hook processes interleave whole lines instead of corrupting each other")

# --- host normalisation edge cases ------------------------------------------
check(_host("[2001:db8::1]:443") == "2001:db8::1", "_host handles bracketed IPv6")
check(_host("Example.COM.") == "example.com", "_host lowercases and strips the "
      "root dot")
check(_host("host:8080") == "host", "_host strips a port")

shutil.rmtree(tmp, ignore_errors=True)


def test_declare():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
