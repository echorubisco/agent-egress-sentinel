#!/usr/bin/env python3
"""Sweep connection lifetime against the sampler to test one falsifiable model.

Model under test
----------------
    recall  ~=  min(1, L / T)
where L = how long a connection stays open and T = the sampling interval
(TICK/nettop -s, shipped at 1 s). Mechanism: nettop emits a sample every T
seconds; a connection alive over [a, a+L] is recorded iff some sample instant
falls inside that interval. With connection starts uncorrelated to sample phase
that probability is L/T, capped at 1.

Where the model came from (fit BEFORE this sweep, 2026-07-30):
    2 s cadence -> 25%  => implied L ~= 500 ms
    1 s cadence -> 48%  => implied L ~= 480 ms   (self-consistent; curl+TLS)
    1 s, L~50ms ->  5.8% vs predicted 5%          (fits)
    0.5 s       -> 72%  vs predicted ~98%         (does NOT fit)
Three of four points fit, so it is a heuristic, not a law. This sweep holds the
cadence FIXED at the shipped 1 s and varies L directly, which is the clean test
the earlier numbers never made: predictions are 30% / 50% / 100% / 100% for
L = 0.3 / 0.5 / 1.0 / 2.0 s.

Also instruments a secondary loss the earlier run exposed but did not explain:
in the fast-close regime raw sightings (15) exceeded accounted destinations (10).
Hypothesis: some connections are sampled mid-handshake, when bytes_out is still
0, and `aggregate_flows` drops them at `if delta <= 0: continue`. `zerobyte`
counts destinations that were seen but never carried a byte.

Everything runs on the shipping path: one long-lived child process (fan-out is
per-pid), real remote hosts over the real default route, NettopStream +
aggregate_flows(warmup, TTL baseline) + DestinationFanout at shipped constants.
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

from fanout_recall_experiment import HOSTS                  # noqa: E402

CHILD_SRC = r'''
import socket, sys, time, json
peers_out, hosts_in, hold = sys.argv[1], sys.argv[2], float(sys.argv[3])
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
        if hold < 0:
            keep.append(s)            # never close: concurrent/persistent shape
        else:
            if hold:
                time.sleep(hold)      # hold open for exactly L seconds
            s.close()
    except Exception:
        pass
json.dump(peers, open(peers_out, "w"))
time.sleep(45)                        # keep pid resolvable while parent finishes
'''


def run(hold, stream, hosts):
    """One pass at lifetime `hold` seconds (hold<0 = keep all open)."""
    tmpd = tempfile.mkdtemp(prefix="sweep-")
    child_py = os.path.join(tmpd, "probe_child.py")
    hosts_js = os.path.join(tmpd, "hosts.json")
    peers_js = os.path.join(tmpd, "peers.json")
    open(child_py, "w").write(CHILD_SRC)
    json.dump(hosts, open(hosts_js, "w"))

    per_conn = 0.35 + max(hold, 0.0)          # connect+send+recv overhead + hold
    connect_after, margin = 2.0, 9.0
    duration = connect_after + len(hosts) * per_conn + margin

    fan = DestinationFanout()
    baseline, seen_ts = {}, {}
    warmup = True
    raw_max = {}                               # ip -> max bytes_out ever sampled
    accounted = set()
    control = 0
    child, cpid = None, None
    t0 = time.time()

    while time.time() - t0 < duration:
        now = time.time()
        if child is None and not warmup and now - t0 >= connect_after:
            child = subprocess.Popen([sys.executable, child_py, peers_js,
                                      hosts_js, str(hold)])
            cpid = str(child.pid)              # nettop keys pid as a STRING

        flows = stream.snapshot(now)
        if cpid:
            for (_n, pid, ip), b in flows.items():
                if pid == cpid:
                    raw_max[ip] = max(raw_max.get(ip, 0), b)

        def observe(pid, kind, dest, delta, ip):
            nonlocal control
            fan.observe(pid, ip, delta, now)
            if cpid and pid == cpid:
                accounted.add(ip)
            else:
                control += 1

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
    return {"hold": hold, "truth": len(truth), "raw": len(raw_max),
            "zerobyte": sum(1 for b in raw_max.values() if b == 0),
            "accounted": len(accounted), "state": len(state),
            "fired": bool(hit), "control": control, "secs": round(duration)}


def main():
    holds = [float(x) for x in
             os.environ.get("HOLDS", "0.3,0.5,1.0,2.0").split(",")]
    hosts = HOSTS
    stream = NettopStream()
    stream.start()
    time.sleep(3)
    print(f"T (sampling interval) = {TICK_SEC}s | hosts={len(hosts)} | "
          f"MIN_DESTS={DestinationFanout.MIN_DESTS}\n")
    print(f"{'L (hold)':>9} {'truth':>6} {'raw':>5} {'0-byte':>7} "
          f"{'acct':>5} {'state':>6} {'recall':>7} {'pred':>6} {'fired':>6}")
    rows = []
    for h in holds:
        r = run(h, stream, hosts)
        rec = r["accounted"] / r["truth"] if r["truth"] else 0.0
        pred = min(1.0, h / TICK_SEC) if h >= 0 else 1.0
        rows.append((r, rec, pred))
        print(f"{h:>9.2f} {r['truth']:>6} {r['raw']:>5} {r['zerobyte']:>7} "
              f"{r['accounted']:>5} {r['state']:>6} {100*rec:>6.1f}% "
              f"{100*pred:>5.0f}% {str(r['fired']):>6}", flush=True)
    print("\nrecall = accounted / ground-truth distinct peer IPs "
          "(one pass per L, n = #hosts Bernoulli episodes)")
    print("pred   = min(1, L/T), the model under test")
    for r, rec, pred in rows:
        print(f"  L={r['hold']:>4}s  err={100*(rec-pred):+6.1f}pp  "
              f"control(other-pid positive deltas)={r['control']}  "
              f"wall={r['secs']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
