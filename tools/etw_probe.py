#!/usr/bin/env python3
"""
Does Microsoft-Windows-Kernel-Network actually carry what a nettop replacement
needs, and what does it cost?

RUN THIS BEFORE ANY WINDOWS CAPTURE CODE IS WRITTEN. PLATFORMS.md claims the
provider gives per-flow byte counts with a pid, event-driven rather than sampled,
and therefore free of the min(1, L/T) recall bound that defines the macOS build.
That claim currently rests on documentation. This turns it into a measurement or
kills it, in about two minutes, using only built-in tools (logman + tracerpt --
no pywintrace, no driver install).

Four questions:
  1. Are pid, remote address, remote port and a byte count all on ONE event? If
     they are spread across events that must be joined, the design changes.
  2. What is the event rate and ETL growth under normal use? This would run
     continuously in a tray app; a provider emitting 50k events/s is not a
     background observer.
  3. Do SHORT-LIVED connections appear? This is the entire reason to prefer
     events over sampling. If a ~50 ms connection does not show up, the port
     buys nothing over nettop and PLATFORMS.md section 3 is wrong.
  4. Real NIC traffic, or loopback only?

NEEDS AN ELEVATED PROMPT -- ETW kernel providers are admin-only, the same shape
of trust-ask as the one `sudo` on macOS.

WHY PYTHON AND NOT POWERSHELL. This was a .ps1 first and PowerShell's execution
policy refused to load it, which is a pointless obstacle in front of a two-minute
measurement. python.exe invoking logman is not subject to that policy, the repo
is already Python, and this way the probe hands its own pid straight to the
summarizer instead of asking a human to copy it.

    python tools/etw_probe.py                # 30 s, generates its own traffic
    python tools/etw_probe.py --seconds 60   # longer
    python tools/etw_probe.py --no-traffic   # drive it with real work yourself
"""

import argparse
import ctypes
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.request

SESSION = "AgentEgressSentinelProbe"
PROVIDER = "Microsoft-Windows-Kernel-Network"
TARGETS = ["https://example.com", "https://www.iana.org", "https://api.github.com"]


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run(cmd, **kw):
    """Return CompletedProcess; never raise. Output text is localised, so only
    return codes and file existence are ever used to decide anything."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace", timeout=300, **kw)
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def short_lived_traffic(until):
    """Connect, send, close -- repeatedly.

    Deliberately short-lived: this is the regime where macOS sampling measured
    5.8% recall. urllib opens a fresh connection per request and does not keep it
    alive, which is what we want. Returns the number that actually completed,
    because "no traffic was generated" and "traffic was generated but not traced"
    both produce Q3=NO and must not be confused -- that is the same
    indistinguishable-failure shape this repo keeps finding.
    """
    done = 0
    while time.time() < until:
        for url in TARGETS:
            if time.time() >= until:
                break
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": "aes-etw-probe"})
            try:
                with urllib.request.urlopen(req, timeout=5):
                    done += 1
            except Exception:
                pass
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--no-traffic", action="store_true",
                    help="do not generate traffic; drive it with real work")
    ap.add_argument("--keep", action="store_true", help="keep the .etl and .xml")
    args = ap.parse_args()

    if not sys.platform.startswith("win"):
        print("Windows only.")
        return 1
    if not is_admin():
        # Absolute, not relative: this script is cwd-independent by design (it
        # locates the summarizer from __file__), so the retry line must be too.
        print("NOT ELEVATED. ETW kernel providers are admin-only.")
        print("Open PowerShell as Administrator (Win+X) and paste this one line:")
        print(f'    "{sys.executable}" "{pathlib.Path(__file__).resolve()}"')
        return 1

    out = pathlib.Path(tempfile.gettempdir())
    etl, xml = out / "aes-etw-probe.etl", out / "aes-etw-probe.xml"
    # A previous run that died mid-way leaves the session registered, and the
    # next start then fails with a confusing name-in-use error.
    run(["logman", "stop", SESSION, "-ets"])
    for p in (etl, xml):
        try:
            p.unlink()
        except OSError:
            pass

    print(f"starting trace: {PROVIDER} for {args.seconds}s")
    # level 4 = informational; keywords all-ones = everything the provider has.
    # The point of a probe is to see what exists; narrowing comes later.
    r = run(["logman", "start", SESSION, "-p", PROVIDER, "0xffffffffffffffff",
             "4", "-ets", "-o", str(etl), "-bs", "64", "-nb", "16", "256"])
    if r.returncode != 0:
        print(f"logman start failed (rc={r.returncode}):")
        print((r.stdout or "") + (r.stderr or ""))
        return 1

    started, generated = time.time(), None
    try:
        if not args.no_traffic:
            print("generating short-lived connections (this is Q3)")
            generated = short_lived_traffic(
                started + min(args.seconds - 2, 20))
            print(f"  {generated} completed from pid {os.getpid()}")
        left = args.seconds - (time.time() - started)
        if left > 0:
            print(f"  waiting {left:.0f}s more")
            time.sleep(left)
    finally:
        print("stopping trace")
        run(["logman", "stop", SESSION, "-ets"])

    if not etl.exists() or etl.stat().st_size == 0:
        print("no ETL produced -- nothing to say. Check that the session started.")
        return 1
    mb = etl.stat().st_size / (1024 * 1024)
    print(f"  ETL: {mb:.2f} MB over {args.seconds}s "
          f"-> {mb * 60 / args.seconds:.1f} MB/min   (Q2)")

    print("decoding to XML (tracerpt; the slow part)")
    r = run(["tracerpt", str(etl), "-o", str(xml), "-of", "XML", "-y"])
    if not xml.exists() or xml.stat().st_size == 0:
        print(f"tracerpt produced nothing (rc={r.returncode}):")
        print((r.stdout or "") + (r.stderr or ""))
        return 1
    print(f"  XML: {xml.stat().st_size / (1024 * 1024):.1f} MB")

    if generated == 0:
        print()
        print("WARNING: zero connections completed -- no network, or all targets")
        print("blocked. Q3 below is then meaningless: it cannot distinguish 'the")
        print("provider missed short connections' from 'there were none'. Re-run")
        print("with working DNS, or use --no-traffic and drive it by hand.")

    print()
    summarize = pathlib.Path(__file__).with_name("etw_probe_summarize.py")
    cmd = [sys.executable, str(summarize), str(xml),
           "--probe-pid", str(os.getpid())]
    if generated:
        # Ground truth for Q3. Without it the summarizer can only report how many
        # connections it saw, which is a number with nothing to compare against.
        cmd += ["--generated", str(generated)]
    rc = subprocess.run(cmd).returncode

    if not args.keep:
        for p in (etl, xml):
            try:
                p.unlink()
            except OSError:
                pass
    else:
        print(f"\nkept: {etl}\n      {xml}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
