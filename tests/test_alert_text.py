#!/usr/bin/env python3
"""
Alert TEXT, end to end through Sampler._tick.

Why not just unit-test a formatter: until now the two `MB up / MB down` strings
were confirmed by grep only. Grep cannot catch the failure that actually
matters here -- `agg["in"]` being absent or the wrong type raises inside
_tick, and `run()` wraps _tick in `except Exception -> log(...)`, so the
symptom is NOT a crash. It is alerts that silently never appear. So these
tests drive the real _tick with an injected stream and assert an alert IS
produced and carries the right numbers.

Asymmetric fixtures throughout (out != in) so reading the wrong counter is
visible in the assertion rather than passing by coincidence.

Run:  python3 tests/test_alert_text.py      (no nettop, no sudo, no network)
"""
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import sentinel                                                     # noqa: E402
from sentinel import Bytes, RED, AMBER, ALLOW                       # noqa: E402

# deadman.beat writes the live heartbeat in ~/.agent-egress-sentinel. A unit
# test must not touch it: writing a beat here would tell the root-side sniffer
# the app is alive when it is not, which is the one thing the dead-man switch
# exists to detect.
#
# REBIND THE NAME, DO NOT MUTATE THE MODULE. `sentinel.deadman.beat = ...` would
# patch the shared module object, so tests/test_deadman.py -- collected after
# this file -- would exercise the stub and fail. Rebinding `sentinel.deadman`
# changes only the lookup inside sentinel's namespace; the real module is
# untouched and collection order stops mattering. (Found by running the full
# suite, not by running this file alone.)
_real_deadman = sentinel.deadman


class _NoBeat:
    @staticmethod
    def beat(*a, **k):
        pass

    @staticmethod
    def coverage_gap(*a, **k):
        return None


sentinel.deadman = _NoBeat

MB = 1024 * 1024
fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


class _Stream:
    """Stands in for NettopStream: _tick only calls .snapshot(now)."""

    def __init__(self, flows):
        self.flows = flows

    def snapshot(self, now):
        return dict(self.flows)


class _SNI:
    def __init__(self, table):
        self.table = table or {}

    def domain_for_ip(self, ip):
        return self.table.get(ip)


def alerts_for(flows, sni_table=None):
    """Run ONE real _tick and return the pushed [(color, msg, notify), ...].

    A fresh Sampler per call, so the per-(pid, kind) emit cooldown in _push
    never suppresses a later case in this file.
    """
    out = []
    s = sentinel.Sampler(_SNI(sni_table), out, threading.Lock())
    s.stream = _Stream(flows)
    s.warmup = False          # not a cold start -> the flow's bytes count
    # Real _agent_for forks `ps` and walks ancestry; identity is not what these
    # tests are about (test_resolve_chain covers it).
    s._agent_for = lambda name, pid: ("kiro", None)
    s._tick()
    return out


def only(alerts, color):
    return [m for c, m, _ in alerts if c == color]


# --- precondition: the "non-AI destination" really is outside the allowlist ---
EVIL = "collector.evil.invalid"
check(not ALLOW.matches(EVIL),
      f"precondition: {EVIL} is not an allowlisted AI endpoint "
      "(otherwise the red path below would be testing nothing)")

# --- 1. RED path: dom-resolved, non-AI, over the 5 MB burst -------------------
red = alerts_for({("kiro-cli", "4242", "203.0.113.9"): Bytes(out=6 * MB,
                                                             inb=2 * MB)},
                 {"203.0.113.9": EVIL})
red_msgs = only(red, RED)
check(len(red_msgs) == 1,
      "red path fires exactly one alert (not zero -- a raise inside _tick is "
      "swallowed by run(), so zero is the silent-failure signature)")
check(red_msgs and "6 MB up / 2.0 MB down" in red_msgs[0],
      "red text carries BOTH directions: '6 MB up / 2.0 MB down'")
check(red_msgs and "2.0 MB down" in red_msgs[0]
      and "6.0 MB down" not in red_msgs[0],
      "the down figure comes from bytes_in, not from bytes_out "
      "(asymmetric fixture makes a counter mix-up visible)")
check(red_msgs and EVIL in red_msgs[0],
      "red text names the destination")

# --- 2. AMBER path: unresolved IP ---------------------------------------------
amber = alerts_for({("kiro-cli", "4343", "198.51.100.7"): Bytes(out=7 * MB,
                                                                inb=3 * MB)},
                   {})
amber_msgs = only(amber, AMBER)
check(any("7 MB up / 3.0 MB down" in m for m in amber_msgs),
      "amber (unresolved-destination) text carries both directions too")
check(any("destination unresolved" in m for m in amber_msgs),
      "amber text still explains why there is no domain name")
check(not only(amber, RED),
      "an unresolved destination stays amber -- never red")

# --- 3. zero download must render, not crash or omit -------------------------
# This is the common case, not an edge case: measured agent flows run 19x-201x
# upload-skewed, so bytes_in is routinely a rounding error next to bytes_out.
zero_down = alerts_for({("kiro-cli", "4444", "203.0.113.9"): Bytes(out=6 * MB,
                                                                   inb=0)},
                       {"203.0.113.9": EVIL})
check(any("6 MB up / 0.0 MB down" in m for m in only(zero_down, RED)),
      "a flow with zero bytes_in still renders ('0.0 MB down'), no crash, "
      "no missing field")

# --- 4. bytes_in cannot CREATE an alert --------------------------------------
# test_baseline pins this at the aggregate level; pin it at the alert level too,
# because that is where a future 'ratio' rule would most plausibly leak in.
pure_down = alerts_for({("kiro-cli", "4545", "203.0.113.9"): Bytes(out=0,
                                                                   inb=80 * MB)},
                       {"203.0.113.9": EVIL})
check(pure_down == [],
      "80 MB downloaded with 0 bytes out produces NO alert at all -- "
      "bytes_in cannot manufacture an alert")

# --- 5. bytes_in cannot SUPPRESS one ----------------------------------------
# The other direction of the same guarantee: a huge download alongside the same
# 6 MB upload must not damp the red.
big_down = alerts_for({("kiro-cli", "4646", "203.0.113.9"): Bytes(out=6 * MB,
                                                                  inb=900 * MB)},
                      {"203.0.113.9": EVIL})
check(len(only(big_down, RED)) == 1,
      "a 900 MB download alongside the same 6 MB upload still fires red -- "
      "bytes_in cannot suppress an alert")
check(any("900.0 MB down" in m for m in only(big_down, RED)),
      "and the large download is reported in the text (900.0 MB down)")

# --- 6. KNOWN LIMIT, pinned deliberately ------------------------------------
# At one decimal place in MB, everything below ~50 KB of download renders as
# "0.0 MB down". Measured real ratios are 19x-201x, so a large share of genuine
# agent flows land in exactly that bucket: the down figure as FORMATTED is
# least informative precisely in the regime that dominates. This assertion
# exists so a reader does not mistake the printed 0.0 for "no inbound bytes",
# and so anyone who later builds a ratio rule sees the resolution floor first.
skewed = alerts_for({("kiro-cli", "4747", "203.0.113.9"): Bytes(out=6 * MB,
                                                                inb=40 * 1024)},
                    {"203.0.113.9": EVIL})
check(any("0.0 MB down" in m for m in only(skewed, RED)),
      "KNOWN LIMIT: a 150x-skewed flow (40 KB in) renders identically to a "
      "zero-download flow -- '0.0 MB down'. Not a bug; a formatting floor "
      "that a ratio rule must not read as zero")


sentinel.deadman = _real_deadman          # restore: no leakage past this module


# --- 7. reconciliation WIRING, end to end through _tick ----------------------
# These exist because the reconciler's unit tests all passed while the wiring was
# broken: the verdict was consulted inside the per-pid loop, which only visits
# processes with a positive byte delta in the current tick, so a flow that burst
# once and went quiet was silently dropped -- the exfil shape. Unit tests called
# drain() directly and could not see it. So the assertions that matter here are
# about the SECOND tick, with the flow already gone.
import json                                                         # noqa: E402
import os                                                           # noqa: E402
import tempfile                                                     # noqa: E402
import time                                                         # noqa: E402
import activity                                                     # noqa: E402

_tmp = pathlib.Path(tempfile.mkdtemp(prefix="alerts-recon-"))
_act = _tmp / "activity.ndjson"
_NOW = time.time()


def recon_alerts(decls, dest="collector.evil.invalid", attributed=True,
                 write_file=True):
    """Two ticks: bytes move on the first, the flow is GONE on the second."""
    sentinel.deadman = _NoBeat
    try:
        out = []
        pid = str(os.getpid())
        flows = {("curl", pid, "203.0.113.9"): Bytes(out=9 * MB, inb=1 * MB)}
        s = sentinel.Sampler(_SNI({"203.0.113.9": dest}), out,
                             threading.Lock())
        s.stream = _Stream(flows)
        s.warmup = False
        s._agent_for = (lambda n, p: ("kiro", "curl")) if attributed \
            else (lambda n, p: (None, None))
        s.recon = activity.Reconciler(path=_act)
        if write_file:
            with open(_act, "w") as fh:
                for d in decls:
                    fh.write(json.dumps(d) + "\n")
            os.utime(_act, (_NOW, _NOW))
        elif _act.exists():
            os.remove(_act)
        s._tick()                                    # bytes move
        for k in s.recon._pending:                   # let it settle
            s.recon._pending[k][0] -= activity.Reconciler.SETTLE_SEC * 2
        s.stream = _Stream({})                       # flow gone: per_pid empty
        s._tick()                                    # verdict must still land
        return [m for _c, m, _n in out]
    finally:
        sentinel.deadman = _real_deadman


_other = [{"ts": _NOW, "pid": os.getppid(), "tool": "fetch",
           "target": "docs.example.com"}]
_match = [{"ts": _NOW, "pid": os.getppid(), "tool": "fetch",
           "target": "collector.evil.invalid"}]

msgs = recon_alerts(_other)
check(any("does not reconcile" in m for m in msgs),
      "BURST-THEN-QUIET: an undeclared 9 MB flow is still reported on a later "
      "tick after the flow has vanished from the snapshot (this is the bug the "
      "reconciler's own unit tests could not see)")
check(any("kiro via curl" in m and "collector.evil.invalid" in m
          for m in msgs if "reconcile" in m),
      "the alert carries the agent label and the destination")

check(not any("does not reconcile" in m for m in recon_alerts(_match)),
      "a matching declaration silences it end to end")

check(not any("does not reconcile" in m
              for m in recon_alerts(_other, write_file=False)),
      "FAIL-SAFE through the wiring: with no activity file, the same 9 MB flow "
      "produces no reconciliation alert (other detectors still fire)")

check(any("MB up" in m for m in recon_alerts(_other, write_file=False)),
      "and the capacity ledger still fires in that case, so the silence is "
      "specific to reconciliation rather than a dead tick")

check(not any("does not reconcile" in m
              for m in recon_alerts(_other, attributed=False)),
      "EXPLICIT AGENT GATE: a process that does not attribute to an agent is "
      "not reported, because aggregate_flows feeds the reconciler EDR, browsers "
      "and OS telemetry too")

# --- 8. small payloads must be LEGIBLE, not rounded to nothing --------------
# Found by an end-to-end run right after the byte floor became conditional on
# novelty: a 4 KB credentials POST -- the exact case the fix exists to surface --
# rendered as "0.0 MB", which reads as nothing happened. Fixing detection and
# leaving the reporting unable to express it is the same mistake one layer up.
check(sentinel._fmt_bytes(4 * 1024) == "4.0 KB",
      "4 KB renders as '4.0 KB', not '0.0 MB' -- the payload class this tool "
      "exists to catch has to be readable in the alert")
check(sentinel._fmt_bytes(200) == "200 B",
      "a few hundred bytes (a bearer token) renders in bytes")
check(sentinel._fmt_bytes(9 * MB) == "9.0 MB" and
      sentinel._fmt_bytes(3 * 1024 * MB) == "3.00 GB",
      "MB and GB scales still render as before")

import shutil                                                       # noqa: E402
shutil.rmtree(_tmp, ignore_errors=True)


def test_alert_text():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
