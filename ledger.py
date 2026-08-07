#!/usr/bin/env python3
"""
Per-destination leaky-bucket capacity ledger + metadata covert-channel
heuristics.

Replaces the flat "5 MB in one tick" threshold. Rationale (the
metadata-observable slice of arXiv:2605.20734's per-sink capacity ledger):
a fixed per-tick floor misses slow exfil -- 300 KB/tick forever never fires.
A leaky bucket keyed by (pid, dest) accumulates bytes and drains at a
constant rate, so:

  - a single-tick burst >= burst_bytes still fires immediately
    (old 5 MB behavior preserved), and
  - sustained egress above drain_rate eventually fills the bucket and fires,
    no matter how it is paced.

CovertChannelDetector flags two covert-channel signatures that are visible
WITHOUT payload inspection:

  - beaconing (timing channel): bursts at suspiciously regular intervals,
  - fixed-size bursts (size channel): the same small payload size repeated.

DestinationFanout covers the third shape, and it exists because of an explicit
gap found on 2026-07-27 (see ROADMAP): DestLedger is VOLUME-shaped -- one
destination, many bytes (built for Grok's 5.1 GB). The scan/lateral-movement
threat Thomas Ptacek describes is CARDINALITY-shaped -- many destinations, few
bytes each. No single bucket ever fills, so the ledger structurally cannot fire
on it. Fan-out counts distinct low-byte destinations per pid instead.

All three of these are heuristics -> they surface as AMBER, never red.
"""

import collections
import time

MB = 1024 * 1024


class DestLedger:
    """
    Leaky bucket per (pid, kind, dest).

    kind is "dom" (SNI-resolved domain) or "ip" (unresolved) so the caller
    can route breaches to red vs amber without re-resolving.
    Levels are lazily drained on access; no background thread.
    """

    def __init__(self, burst_bytes=5 * MB, drain_rate=128 * 1024):
        self.burst = burst_bytes          # level that triggers a breach
        self.rate = drain_rate            # bytes/sec leaked out of the bucket
        self._buckets = {}                # (pid, kind, dest) -> (level, last_ts)

    def _drained(self, level, last, now):
        return max(0.0, level - (now - last) * self.rate)

    def add(self, pid, kind, dest, nbytes, now=None):
        now = time.time() if now is None else now
        key = (pid, kind, dest)
        level, last = self._buckets.get(key, (0.0, now))
        level = self._drained(level, last, now) + nbytes
        self._buckets[key] = (level, now)
        return level

    def breaches(self, pid, now=None):
        """{(kind, dest): current_level} for this pid's buckets >= burst."""
        now = time.time() if now is None else now
        out = {}
        for (p, kind, dest), (level, last) in self._buckets.items():
            if p != pid:
                continue
            cur = self._drained(level, last, now)
            if cur >= self.burst:
                out[(kind, dest)] = cur
        return out

    def gc(self, now=None, idle_sec=120):
        """Drop buckets that have fully drained and been idle a while."""
        now = time.time() if now is None else now
        dead = [k for k, (level, last) in self._buckets.items()
                if self._drained(level, last, now) <= 0
                and now - last > idle_sec]
        for k in dead:
            del self._buckets[k]


class CovertChannelDetector:
    """
    Metadata-only covert-channel heuristics over per-tick byte deltas.

    We only see 2-second tick deltas, not individual messages, so this is
    deliberately coarse and amber-only:

      - beaconing: >= MIN_EVENTS bursts whose inter-burst gaps have a
        coefficient of variation < CV_MAX. Mean gap must exceed the tick
        cadence (MIN_GAP_SEC) -- a continuous bulk transfer produces
        regular every-tick deltas and is the volume ledger's job, not ours.
      - fixed-size: >= 70% of bursts land in the same 1-KB size bucket AND
        that size is small (< 64 KB). Large identical chunks are usually
        chunked uploads, which the volume ledger already catches.
    """

    MIN_EVENTS = 8
    WINDOW_SEC = 600
    CV_MAX = 0.15
    MIN_GAP_SEC = 4.0
    MODE_FRACTION = 0.7
    SMALL_KB = 64

    def __init__(self):
        self._hist = {}                   # (pid, dest) -> deque[(ts, nbytes)]

    def observe(self, pid, dest, nbytes, now=None):
        now = time.time() if now is None else now
        d = self._hist.setdefault((pid, dest),
                                  collections.deque(maxlen=64))
        d.append((now, nbytes))

    def suspicious(self, pid, now=None):
        """[(dest, human_reason)] for this pid's flows matching a signature."""
        now = time.time() if now is None else now
        hits = []
        for (p, dest), events in self._hist.items():
            if p != pid:
                continue
            ev = [(t, b) for t, b in events if now - t <= self.WINDOW_SEC]
            if len(ev) < self.MIN_EVENTS:
                continue
            reason = self._check(ev)
            if reason:
                hits.append((dest, reason))
        return hits

    def gc(self, now=None):
        now = time.time() if now is None else now
        dead = [k for k, d in self._hist.items()
                if not d or now - d[-1][0] > self.WINDOW_SEC]
        for k in dead:
            del self._hist[k]

    @classmethod
    def _check(cls, ev):
        times = [t for t, _ in ev]
        sizes = [b for _, b in ev]
        gaps = [b - a for a, b in zip(times, times[1:])]
        if gaps:
            mean_gap = sum(gaps) / len(gaps)
            if mean_gap >= cls.MIN_GAP_SEC:
                var = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
                cv = (var ** 0.5) / mean_gap if mean_gap else float("inf")
                if cv < cls.CV_MAX:
                    return (f"beaconing: {len(ev)} bursts every "
                            f"~{mean_gap:.0f}s (cv {cv:.2f})")
        buckets = collections.Counter(b // 1024 for b in sizes)
        mode_kb, n = buckets.most_common(1)[0]
        if n / len(sizes) >= cls.MODE_FRACTION and mode_kb < cls.SMALL_KB:
            return f"fixed-size bursts: {n}/{len(sizes)} at ~{mode_kb}KB"
        return None


class DestinationFanout:
    """
    Distinct-destination cardinality per pid over a sliding window.

    Shape complement to DestLedger:

        DestLedger        one dest, many bytes   (exfil / over-collection)
        DestinationFanout many dests, few bytes  (scan / lateral movement)

    Only destinations whose windowed total stays under SMALL_BYTES count: a
    destination that received real volume is the ledger's business, and
    counting it here would double-report a normal bulk upload as fan-out.

    AMBER-ONLY, and this is not squeamishness -- high cardinality is also the
    normal signature of `npm install`, `brew update`, a docs crawl, or an agent
    fetching 40 URLs a user asked it to read. There is no metadata-layer way to
    separate those from reconnaissance, so this reports "unusual breadth", never
    an accusation.

    Honest limit (documented in README): nettop only surfaces connections that
    moved bytes, so a bare SYN/connect scan (~0 bytes out per host) produces no
    countable flow at all. This fires on breadth that carries payloads --
    HTTP(S) probing, credential spraying, lateral requests -- not on port scans.
    """

    WINDOW_SEC = 300
    MIN_DESTS = 20                    # distinct low-byte dests inside the window
    SMALL_BYTES = 64 * 1024           # per-dest ceiling to still count as fan-out

    def __init__(self):
        self._seen = {}               # (pid, dest) -> [total_bytes, last_ts]

    def observe(self, pid, dest, nbytes, now=None):
        now = time.time() if now is None else now
        rec = self._seen.get((pid, dest))
        if rec is None or now - rec[1] > self.WINDOW_SEC:
            self._seen[(pid, dest)] = [nbytes, now]   # stale -> restart window
        else:
            rec[0] += nbytes
            rec[1] = now

    def fanout(self, pid, now=None):
        """(count, sample_dests) if this pid is above MIN_DESTS, else None."""
        now = time.time() if now is None else now
        dests = [dest for (p, dest), (total, last) in self._seen.items()
                 if p == pid and now - last <= self.WINDOW_SEC
                 and total <= self.SMALL_BYTES]
        if len(dests) < self.MIN_DESTS:
            return None
        return len(dests), sorted(dests)[:3]

    def gc(self, now=None):
        now = time.time() if now is None else now
        dead = [k for k, (_total, last) in self._seen.items()
                if now - last > self.WINDOW_SEC]
        for k in dead:
            del self._seen[k]
