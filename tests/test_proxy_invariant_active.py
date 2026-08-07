#!/usr/bin/env python3
"""
The proxy invariant must not depend on the declaration channel.

THE CONTRADICTION (found by external review 2026-08-07). `_verdict` runs the
proxy invariant FIRST and its comment says it is "the only verdict here a
declaration cannot argue with … this is the one place where 'but it was
declared' is not a defence." RESEARCH-PROGRAM §2 builds on it as "the only
detector in this repo that survives the repo's own impossibility argument".

But `observe()` and `drain()` both open with `if not self._active: return`, and
`_active` is `(now - activity.ndjson mtime) <= FRESH_SEC`. **So the one check
that needs no declarations was unreachable unless a declaration file existed and
had been written in the last 60 seconds** — which, per PRE-FLIGHT §3, is a file
nothing wrote at all until 2026-08-06.

Measured before the fix: proxy configured, no declaration file, a 50 MB flow
that skipped the proxy — `_pending` empty, `drain()` returns nothing. The
structural invariant never fired.

THE OTHER HALF, which is why this is not a one-line gate removal. With no
declaration channel there is nothing to reconcile against, so every flow would
match nothing and every flow would earn a "no declared activity" amber —
including the ones that correctly went TO the proxy. Opening the gate naively
turns a silent detector into a flood. Under proxy-without-declarations the
reconciler must emit the structural verdict and NOTHING else.

Run:  python3 tests/test_proxy_invariant_active.py
"""
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import activity                                                      # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


NOW = 1_000_000.0
PROXY = "127.0.0.1:8080"


def recon(proxy=None, with_file=False, stale=False):
    d = pathlib.Path(tempfile.mkdtemp()) / "activity.ndjson"
    if with_file:
        d.write_text('{"ts": %f, "pid": 1, "tool": "t", "target": "declared.example"}\n'
                     % NOW, encoding="utf-8")
    r = activity.Reconciler(path=d, proxy=proxy, now=NOW - 1000)
    # refresh() reads mtime from the real clock, so drive it with real time and
    # only use NOW for the observation timeline.
    r.refresh(now=time.time() + (10_000 if stale else 0))
    return r


def verdicts(r, dest, nbytes=50 * 1024 * 1024, pid=4242):
    r.observe(pid, dest, nbytes, now=NOW, name="claude")
    return [o[4] for o in r.drain(now=NOW + r.SETTLE_SEC + 1,
                                  ancestors=lambda p, **k: [p])]


# --- the regression: no declaration channel at all ---------------------------
r = recon(proxy=PROXY, with_file=False)
check(r.proxy and not r._active, "fixture: proxy configured, no declaration file")
out = verdicts(r, "evil.example.com")
check(any("proxy is configured" in v for v in out),
      f"the structural invariant FIRES with no declaration file present -- it is "
      f"the one verdict that does not depend on declarations, and it was gated "
      f"on them (got {out})")

# --- and it must not become a flood ------------------------------------------
r = recon(proxy=PROXY, with_file=False)
out = verdicts(r, "127.0.0.1")
check(out == [],
      f"a flow TO the proxy stays silent -- with no declaration channel there is "
      f"nothing to reconcile against, so 'no declared activity' must not be "
      f"emitted for correctly-proxied traffic (got {out})")

r = recon(proxy=PROXY, with_file=False)
out = verdicts(r, "evil.example.com")
check(len([v for v in out if "no declared activity" in v]) == 0,
      "and no declaration-based verdict is emitted at all while the channel is "
      "absent -- only the structural one")

# --- a stale channel is the same case ----------------------------------------
r = recon(proxy=PROXY, with_file=True, stale=True)
check(not r._active, "fixture: declaration file present but older than FRESH_SEC")
out = verdicts(r, "evil.example.com")
check(any("proxy is configured" in v for v in out),
      "a STALE declaration file does not silence the structural invariant either "
      "-- staleness is a statement about the integration, not about the socket")

# --- what must not change ----------------------------------------------------
r = recon(proxy=None, with_file=False)
out = verdicts(r, "evil.example.com")
check(out == [],
      "WITHOUT a proxy configured and without declarations, nothing is emitted -- "
      "the reconciler stays off unless fed, which is the shipped default")

r = recon(proxy=None, with_file=True)
out = verdicts(r, "undeclared.example")
check(any("no declared activity" in v for v in out),
      "with a live declaration channel and no proxy, ordinary reconciliation is "
      "unchanged")

r = recon(proxy=PROXY, with_file=True)
out = verdicts(r, "declared.example")
check(any("proxy is configured" in v for v in out),
      "under proxy mode a DECLARED destination still trips the invariant -- 'but "
      "it was declared' is explicitly not a defence here")


def test_proxy_invariant_active():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
