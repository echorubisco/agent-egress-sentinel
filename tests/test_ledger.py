#!/usr/bin/env python3
"""Tests for DestLedger + CovertChannelDetector (fake clock, no I/O)."""

import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from ledger import (DestLedger, CovertChannelDetector, DestinationFanout, MB)


# --- DestLedger ---------------------------------------------------------

def test_single_tick_burst_fires():
    """Old 5MB-in-one-tick behavior preserved: one big add breaches."""
    led = DestLedger(burst_bytes=5 * MB, drain_rate=128 * 1024)
    led.add("100", "dom", "transfer.sh", 5 * MB, now=1000.0)
    assert ("dom", "transfer.sh") in led.breaches("100", now=1000.0)


def test_slow_exfil_eventually_fires():
    """300KB per 2s tick (150KB/s > 128KB/s drain) fills the bucket.
    The old per-tick threshold NEVER fired on this."""
    led = DestLedger(burst_bytes=5 * MB, drain_rate=128 * 1024)
    t = 1000.0
    breached_at = None
    for i in range(600):                       # up to 20 min of ticks
        t += 2.0
        led.add("100", "dom", "evil.com", 300 * 1024, now=t)
        if led.breaches("100", now=t):
            breached_at = i
            break
    assert breached_at is not None, "slow exfil never fired"


def test_below_drain_rate_never_fires():
    """100KB per 2s tick (50KB/s < 128KB/s drain) never accumulates."""
    led = DestLedger(burst_bytes=5 * MB, drain_rate=128 * 1024)
    t = 1000.0
    for _ in range(600):
        t += 2.0
        led.add("100", "dom", "telemetry.example.com", 100 * 1024, now=t)
        assert not led.breaches("100", now=t)


def test_bucket_drains_and_clears():
    led = DestLedger(burst_bytes=5 * MB, drain_rate=128 * 1024)
    led.add("100", "dom", "transfer.sh", 5 * MB, now=1000.0)
    assert led.breaches("100", now=1000.0)
    # 5MB / 128KBps = 40s to drain fully
    assert not led.breaches("100", now=1000.0 + 60)


def test_breaches_isolated_per_pid():
    led = DestLedger(burst_bytes=5 * MB, drain_rate=128 * 1024)
    led.add("100", "dom", "evil.com", 6 * MB, now=1000.0)
    assert not led.breaches("200", now=1000.0)


def test_gc_drops_idle_buckets():
    led = DestLedger(burst_bytes=5 * MB, drain_rate=128 * 1024)
    led.add("100", "dom", "evil.com", 1 * MB, now=1000.0)
    led.gc(now=1000.0 + 300)
    assert led._buckets == {}


# --- CovertChannelDetector ----------------------------------------------

def test_beaconing_detected():
    """Bursts exactly every 30s with varying sizes -> timing channel."""
    det = CovertChannelDetector()
    t = 1000.0
    for i in range(10):
        det.observe("100", "c2.example.com", 10_000 + i * 3_777, now=t)
        t += 30.0
    hits = det.suspicious("100", now=t)
    assert hits and "beaconing" in hits[0][1]


def test_fixed_size_detected():
    """Same 4KB burst at irregular gaps -> size channel."""
    det = CovertChannelDetector()
    gaps = [0, 3, 9, 10, 20, 21, 33, 40, 47, 61]
    for g in gaps:
        det.observe("100", "c2.example.com", 4096, now=1000.0 + g)
    hits = det.suspicious("100", now=1000.0 + 61)
    assert hits and "fixed-size" in hits[0][1]


def test_continuous_bulk_transfer_not_flagged():
    """Every-tick (2s) regular deltas with varying sizes = bulk upload;
    that is the volume ledger's job, the channel detector must stay quiet."""
    det = CovertChannelDetector()
    t = 1000.0
    for i in range(20):
        det.observe("100", "bulk.example.com", 500_000 + i * 91_337, now=t)
        t += 2.0
    assert det.suspicious("100", now=t) == []


def test_too_few_events_not_flagged():
    det = CovertChannelDetector()
    for i in range(5):
        det.observe("100", "c2.example.com", 4096, now=1000.0 + i * 30)
    assert det.suspicious("100", now=1000.0 + 150) == []


def test_gc_prunes_stale_histories():
    det = CovertChannelDetector()
    det.observe("100", "old.example.com", 4096, now=1000.0)
    det.gc(now=1000.0 + 700)
    assert det._hist == {}


# --- DestinationFanout --------------------------------------------------

def test_fanout_fires_on_many_small_dests():
    """Scan/lateral shape: 30 hosts, 2KB each. This is exactly what the
    volume ledger CANNOT see -- no single bucket gets near 5MB."""
    fan = DestinationFanout()
    led = DestLedger(burst_bytes=5 * MB, drain_rate=128 * 1024)
    t = 1000.0
    for i in range(30):
        dest = f"10.0.0.{i}"
        fan.observe("100", dest, 2048, now=t)
        led.add("100", "ip", dest, 2048, now=t)
        t += 1.0
    hit = fan.fanout("100", now=t)
    assert hit and hit[0] >= 20
    assert not led.breaches("100", now=t), "ledger must stay silent (proves the gap)"


def test_fanout_quiet_below_threshold():
    fan = DestinationFanout()
    for i in range(10):                       # 10 dests < MIN_DESTS
        fan.observe("100", f"10.0.0.{i}", 2048, now=1000.0 + i)
    assert fan.fanout("100", now=1010.0) is None


def test_fanout_ignores_high_volume_dests():
    """A destination that moved real volume belongs to the ledger; counting it
    here would double-report a normal bulk upload as fan-out."""
    fan = DestinationFanout()
    for i in range(30):
        fan.observe("100", f"cdn{i}.example.com", 1 * MB, now=1000.0 + i)
    assert fan.fanout("100", now=1030.0) is None


def test_fanout_window_expires():
    fan = DestinationFanout()
    for i in range(30):
        fan.observe("100", f"10.0.0.{i}", 2048, now=1000.0 + i)
    assert fan.fanout("100", now=1000.0 + 30) is not None
    assert fan.fanout("100", now=1000.0 + 400) is None      # past WINDOW_SEC


def test_fanout_isolated_per_pid():
    fan = DestinationFanout()
    for i in range(30):
        fan.observe("100", f"10.0.0.{i}", 2048, now=1000.0 + i)
    assert fan.fanout("200", now=1030.0) is None


def test_fanout_gc_prunes():
    fan = DestinationFanout()
    fan.observe("100", "10.0.0.1", 2048, now=1000.0)
    fan.gc(now=1000.0 + 400)
    assert fan._seen == {}
