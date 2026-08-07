#!/usr/bin/env python3
"""Measure real-host fan-out recall through the PRODUCTION pipeline.

Why this exists / what the earlier attempt got wrong
----------------------------------------------------
The 2026-07-27 "0/25 recall" run drove the load with a shell loop over `curl`.
DestinationFanout.fanout() filters `if p == pid` -- it is strictly PER PROCESS.
25 sequential curls are 25 pids holding one destination each, so that run could
never have fired the detector no matter how good the sampler was: it measured
the harness, not the detector.

This harness fixes the shape: ONE long-lived child process opens N connections
to N distinct remote hosts, so every destination accrues under a single pid --
which is the actual shape of scanning / lateral movement.

It also deliberately stays on the real production path:
  - real remote destinations over the real default route (NOT a VM's virtual
    interface), so the sampling recall measured is the one production sees
  - one long-lived NettopStream, TICK_SEC accounting -- the shipping sampler
  - aggregate_flows(..., warmup=) with a TTL-persisted baseline -- the shipping
    accounting rules, including the fixed first-observation semantics
  - DestinationFanout at shipping constants (nothing tuned for this test)

Port 80 plaintext is deliberate: SNI never resolves, so every destination takes
the `unresolved` branch and is keyed by IP -- the same path a scan takes.

Four numbers per trial, so any loss can be attributed to a layer:
  truth      distinct peer IPs the child actually connected to (getpeername)
  raw        distinct IPs for that pid present in any nettop snapshot
  accounted  distinct IPs that produced a positive delta (reached the ledger)
  state      distinct IPs held by DestinationFanout for that pid
  fired      whether fanout() returns a hit at the shipping MIN_DESTS
"""
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ledger import DestinationFanout                        # noqa: E402
from sentinel import NettopStream, aggregate_flows, TICK_SEC  # noqa: E402

# Chosen for IP diversity (own infra rather than one shared CDN edge) so the
# distinct-IP count does not collapse. Ground truth is measured, not assumed.
HOSTS = [
    "mit.edu", "stanford.edu", "berkeley.edu", "cmu.edu", "caltech.edu",
    "princeton.edu", "yale.edu", "cornell.edu", "columbia.edu", "uchicago.edu",
    "umich.edu", "utexas.edu", "washington.edu", "wisc.edu", "illinois.edu",
    "gatech.edu", "purdue.edu", "psu.edu", "osu.edu", "nyu.edu",
    "ox.ac.uk", "cam.ac.uk", "ethz.ch", "epfl.ch", "tudelft.nl",
    "uni-heidelberg.de", "u-tokyo.ac.jp", "kyoto-u.ac.jp", "nus.edu.sg",
    "unimelb.edu.au", "utoronto.ca", "ubc.ca", "mcgill.ca",
    "kernel.org", "debian.org", "archlinux.org", "freebsd.org", "openbsd.org",
    "gnu.org", "apache.org", "python.org", "postgresql.org", "nginx.org",
    "isc.org", "ietf.org", "iana.org", "w3.org", "rfc-editor.org",
    "nist.gov", "nasa.gov", "noaa.gov", "usgs.gov", "loc.gov", "cdc.gov",
    "nih.gov", "energy.gov", "census.gov", "gutenberg.org", "archive.org",
]

CHILD_SRC = r'''
import socket, sys, time, json
peers_out, hosts_in, mode = sys.argv[1], sys.argv[2], sys.argv[3]
peers, keep = [], []
for h in json.load(open(hosts_in)):
    try:
        s = socket.create_connection((h, 80), timeout=3)
        peers.append(s.getpeername()[0])
        s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + h.encode() +
                  b"\r\nUser-Agent: fanout-probe\r\nConnection: keep-alive\r\n\r\n")
        try:
            s.recv(256)
        except Exception:
            pass
        if mode == "hold":
            keep.append(s)        # leave open: spans >=1 sampling interval
        else:
            s.close()             # close immediately: the fast-scan shape
    except Exception:
        pass
json.dump(peers, open(peers_out, "w"))
# stay alive so the pid stays resolvable while the parent finishes accounting
time.sleep(40)
'''


MODE = os.environ.get("MODE", "seq")   # seq = close at once, hold = keep open


def trial(idx, stream, duration=34.0, connect_after=2.0):
    """One trial against an already-running stream. Fresh accounting state."""
    tmpd = tempfile.mkdtemp(prefix="fanout-")
    child_py = os.path.join(tmpd, "probe_child.py")
    hosts_js = os.path.join(tmpd, "hosts.json")
    peers_js = os.path.join(tmpd, "peers.json")
    open(child_py, "w").write(CHILD_SRC)
    json.dump(HOSTS, open(hosts_js, "w"))

    fan = DestinationFanout()
    baseline, seen_ts = {}, {}
    warmup = True                     # first tick only seeds, as in production
    raw_ips, accounted_ips = set(), set()
    child, cpid = None, None
    other_positive = 0                # negative control: pipeline is alive
    t0 = time.time()

    while time.time() - t0 < duration:
        now = time.time()
        if child is None and not warmup and now - t0 >= connect_after:
            child = subprocess.Popen([sys.executable, child_py, peers_js,
                                      hosts_js, MODE])
            cpid = str(child.pid)      # nettop keys pid as a STRING

        flows = stream.snapshot(now)
        if cpid:
            raw_ips.update(ip for (_n, pid, ip) in flows if pid == cpid)

        def observe(pid, kind, dest, delta, ip):
            nonlocal other_positive
            fan.observe(pid, ip, delta, now)
            if cpid and pid == cpid:
                accounted_ips.add(ip)
            else:
                other_positive += 1

        aggregate_flows(flows, baseline, lambda _ip: None, lambda _d: False,
                        observe=observe, warmup=warmup)
        warmup = False
        for k, v in flows.items():
            baseline[k] = v
            seen_ts[k] = now
        fan.gc(now)
        time.sleep(TICK_SEC)

    state = {d for (p, d) in fan._seen if p == cpid}
    hit = fan.fanout(cpid) if cpid else None
    try:
        truth = set(json.load(open(peers_js)))
    except Exception:
        truth = set()
    if child:
        child.kill()

    return {"trial": idx, "pid": cpid, "truth": len(truth), "raw": len(raw_ips),
            "accounted": len(accounted_ips), "state": len(state),
            "fired": bool(hit), "hit": hit, "control": other_positive}


def main():
    trials = int(os.environ.get("TRIALS", "3"))
    stream = NettopStream()
    stream.start()
    time.sleep(3)                     # let the stream produce a first sample
    print(f"MIN_DESTS={DestinationFanout.MIN_DESTS} "
          f"SMALL_BYTES={DestinationFanout.SMALL_BYTES} "
          f"WINDOW_SEC={DestinationFanout.WINDOW_SEC} TICK_SEC={TICK_SEC} "
          f"MODE={MODE}\n")

    rows = []
    for i in range(1, trials + 1):
        r = trial(i, stream)
        rows.append(r)
        print(f"trial {i}: truth={r['truth']:3d} raw={r['raw']:3d} "
              f"accounted={r['accounted']:3d} state={r['state']:3d} "
              f"fired={r['fired']}  (other-pid positive deltas: "
              f"{r['control']})", flush=True)

    def pct(a, b):
        return f"{100.0 * a / b:.1f}%" if b else "n/a"

    tt = sum(r["truth"] for r in rows)
    print(f"\n=== aggregate over {len(rows)} trials ===")
    print(f"ground-truth distinct peer IPs : {tt}")
    print(f"raw nettop visibility          : {sum(r['raw'] for r in rows)}"
          f"  {pct(sum(r['raw'] for r in rows), tt)}")
    print(f"reached accounting (>0 delta)  : {sum(r['accounted'] for r in rows)}"
          f"  {pct(sum(r['accounted'] for r in rows), tt)}")
    print(f"held in fan-out state          : {sum(r['state'] for r in rows)}"
          f"  {pct(sum(r['state'] for r in rows), tt)}")
    print(f"trials that fired              : "
          f"{sum(1 for r in rows if r['fired'])}/{len(rows)}")
    print(f"per-trial state counts         : {[r['state'] for r in rows]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
