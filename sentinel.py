#!/usr/bin/env python3
"""
Agent Egress Sentinel - weekend skeleton (per-flow attribution).

Flags the Grok tell: an AI coding-agent process pushing a large volume to a
destination that is NOT a known AI endpoint. Metadata only - no TLS decryption,
no root CA.

Attribution is MEASURED per-flow, not guessed. `nettop -x -L 1` (no -P) emits,
under each process row, one row PER CONNECTION carrying the remote IP AND that
connection's bytes_out, so we get (pid, dest_ip) -> bytes directly and can
split "bytes to AI endpoints" from "bytes to everything else" within one
process (kills the telemetry-SDK false positive).

Threading: a background thread does the blocking work (nettop + ps) and only
appends result dicts to a lock-guarded queue. The main-thread rumps.Timer drains
that queue and is the ONLY place that touches AppKit (title, notifications).

Run:  pip install rumps ; python3 sentinel.py
      (domains need: SENTINEL_IFACE=en0 sudo -E python3 sni_sniffer.py)
"""

import re
import sys
import time
import threading
import subprocess
import collections
import datetime

try:
    import rumps
    _HAS_RUMPS = True
except ImportError:
    _HAS_RUMPS = False

    class _RumpsStub:                # keeps the module importable for unit tests
        App = object                 # (parse_flows has no rumps dependency)

        @staticmethod
        def clicked(*_a, **_k):
            return lambda fn: fn

        class Timer:
            def __init__(self, *_a, **_k): ...
            def start(self): ...

        @staticmethod
        def alert(*_a, **_k): ...

        @staticmethod
        def notification(*_a, **_k): ...

    rumps = _RumpsStub()

from paths import LOG
from sni_sniffer import SNICache
from update_ping import update_check_and_log
from endpoints import Allowlist
import proctree
import deadman
import activity
import paths
from ledger import DestLedger, CovertChannelDetector, DestinationFanout

ALLOW = Allowlist()

# Detection content (agent tokens / confusables) lives in the manifest
# (ai_endpoints.yaml) next to the endpoint allowlist -- same governance + hot
# reload. ALLOW.agent_tokens()/confusables() read it (Python fallback in endpoints).
NETTOP_CMD = ["nettop", "-n", "-x", "-L", "1"]    # one-shot; kept as stream fallback
NETTOP_STREAM_CMD = ["nettop", "-n", "-x", "-L", "0", "-s", "1"]
#   -L 0 = logging mode, infinite samples; -s 1 = one sample per second.
#   Measured on a 25-destination burst (5 interleaved trials each, ground truth =
#   the remote IPs curl actually connected to via -w %{remote_ip}):
#       2 s one-shot (the old default)  25% destination recall,  5.4% of a core
#       1 s one-shot                    48%                     10.7%
#       0.5 s one-shot                  72%                     23%
#       streaming -s 1                  48%                      1.8%
#   Streaming buys no recall over relaunching at 1 s -- the gain is sampling
#   FREQUENCY, not the removal of launch gaps -- but it delivers that recall at a
#   sixth of the CPU, which is what makes 1 s affordable for a menu-bar app.
#   nettop rejects a fractional -s (0 samples emitted), so 1 s is the floor.
#   ⚠️ Those percentages are CADENCE-TO-CADENCE ONLY -- they are not "the" recall
#   of anything. That sweep varied the cadence while leaving connection LIFETIME
#   uncontrolled, and lifetime is what actually sets recall: recall ~= min(1, L/T).
#   Holding T at the shipped 1 s and controlling L directly gives 5.8% / 36.8% /
#   54.4% / 100% at L = 50 ms / 300 ms / 500 ms / >=1 s, same code, same machine.
#   So 48% was the connection lifetime of *that* workload (curl+TLS, ~0.5 s) in a
#   sampler's clothes; it is withdrawn as a general figure (ROADMAP 2026-07-30).
#   Streaming is chosen for CPU cost, not for recall.
#   -n: numeric IPs. Without it
#   nettop reverse-resolves to PTR names (ec2-...compute.amazonaws.com) that
#   never match the numeric-IP keys in the SNI cache -> the join silently dies
#   and every cloud dest falls to amber. The whole product hinges on this flag.
FLAG_BYTES = 5 * 1024 * 1024         # leaky-bucket burst size (single-tick red preserved)
DRAIN_RATE = 128 * 1024              # bytes/sec bucket drain; sustained egress above
#   this fills the bucket no matter how it is paced (kills the trickle blind spot
#   the old flat per-tick threshold had; see ledger.py + ROADMAP 07-17 night notes)
TICK_SEC = 1                         # accounting cadence; sampling frequency is
#   nettop's own -s 1 now, so a tick costs no fork -- 1 s is free. 1 s is also
#   the floor nettop allows. It does not "buy" a recall number: a flow is seen
#   iff a sample lands inside its lifetime, so shortening T raises recall only
#   for connections shorter than T, and nothing reachable by polling closes a
#   50 ms window -- that needs flow open/close events (eBPF / NetworkExtension).
BASELINE_TTL = 300                   # seconds a departed flow's cumulative is kept, so a
#   flow absent from one snapshot isn't re-counted from zero when it returns
UI_DRAIN_SEC = 0.5                   # main-thread queue drain cadence
DEDUPE_COOLDOWN = 30                 # seconds; per (pid, kind) to stop amber spam
UNATTRIBUTED_REPORT_AT = 25          # flows the attribution gate declined to
                                     # accuse before we report the COUNT. High
                                     # enough that a browser's steady state does
                                     # not chirp; low enough that a deputy
                                     # fetching a few dozen times is visible.
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_PORT_RE = re.compile(r"[.:]\d+$")   # trailing :port (v4/host) or .port (v6)

GREEN, AMBER, RED = "\U0001F7E2", "\U0001F7E1", "\U0001F534"


def log(line: str):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        with LOG.open("a") as f:
            f.write(f"{ts}  {line}\n")
    except Exception:
        pass


# --- nettop parsing -----------------------------------------------------
Bytes = collections.namedtuple("Bytes", "out inb")


def _byte_out_index(text: str) -> int:
    # P1-G: locate bytes_out from the header instead of hardcoding col 5;
    # nettop CSV layout drifts across macOS versions.
    for row in text.splitlines():
        cols = [c.strip() for c in row.split(",")]
        if "bytes_out" in cols:
            return cols.index("bytes_out")
    log("WARN nettop header has no 'bytes_out' column; falling back to index 5")
    return 5


def _byte_in_index(text: str) -> int:
    """Column index of bytes_in, or -1 when the header does not carry it.

    bytes_in has been sitting one column to the LEFT of bytes_out in every
    nettop header we have seen (verified 2026-08-02: time,,interface,state,
    bytes_in,bytes_out,...) and was simply never read. It is context, never a
    gate: the only reason to carry it is that "a page read should not upload
    5 MB" is a RATIO, and until now we only had the numerator -- 5 MB up with
    300 KB down and 5 MB up with 2 GB down were indistinguishable.
    -1 (absent) degrades to 0 rather than shifting any threshold.
    """
    for row in text.splitlines():
        cols = [c.strip() for c in row.split(",")]
        if "bytes_in" in cols:
            return cols.index("bytes_in")
    return -1


def _as_bytes(v):
    """Normalise a flow/baseline value to Bytes.

    A bare int means bytes_out only -- hand-built baselines in tests and any
    caller written before 2026-08-02 pass one, so they keep working unchanged.

    Caveat, stated rather than discovered later: an int baseline gives the
    in-counter prev=0 instead of prev=None, so on the single tick right after an
    upgrade (old int baseline, new Bytes sample) the download figure can be
    over-reported once. Harmless because bytes_in never gates anything -- but it
    is a real one-tick artefact, not a rounding detail.
    """
    return v if isinstance(v, tuple) else Bytes(v, 0)


def _delta(prev, total, warmup):
    """The three first-observation rules, for ONE cumulative counter.

    Factored out on purpose: the 94.2% new-flow byte loss fixed on 2026-07-27
    was exactly this logic being wrong once. Two hand-written copies (one per
    counter) would be two chances to get it wrong again, and a counter reset
    that landed on only one of them would be silent.
      prev is None and not warmup -> whole cumulative (connection is new)
      prev is None and warmup     -> 0 (sampler cold start; bytes predate us)
      total < prev                -> whole cumulative (socket/pid reuse reset)
      otherwise                   -> total - prev
    """
    if prev is None:
        return 0 if warmup else total
    if total < prev:
        return total
    return total - prev


def _remote_host(remote: str) -> str:
    """Strip the trailing port from a nettop remote endpoint. nettop uses
    'host:port' for IPv4/hostnames but 'v6addr.port' for IPv6 (dot separator,
    no brackets in real -n output, e.g. '::1.42050'); bracketed [v6]:port is
    handled defensively. The synthetic '[v6]:port' test form also works."""
    if remote.startswith("["):
        return remote[1:].split("]", 1)[0]
    return _PORT_RE.sub("", remote).strip("[]")


def _is_loopback(host: str) -> bool:
    # Drop local IPC (lo0). A local-model agent (ollama on 127.0.0.1:11434) can
    # push GB over loopback; counting it would amber-flag "local stays local".
    h = host.lower()
    return h == "localhost" or h.startswith("127.") or h == "::1"


def parse_flows(text: str):
    """
    Returns { (name, pid, dest_ip): Bytes(cumulative_out, cumulative_in) }.
    P0-B: connection rows are matched FIRST ('<->'); everything else is treated
    as a process row via rpartition('.') so names with spaces/parens
    ('Google Chrome Helper.1234', 'Code Helper (Plugin).567') are recognized.
    Unrecognized rows set cur=None so their orphan connections are dropped
    rather than mis-attributed to the previous process.
    """
    byte_idx = _byte_out_index(text)
    in_idx = _byte_in_index(text)
    flows = {}
    cur = None
    for row in text.splitlines():
        cols = row.split(",")
        if len(cols) <= byte_idx:
            continue
        c1 = cols[1].strip()
        if "<->" in c1:                                   # connection row FIRST
            if cur is None:
                continue
            remote = c1.split("<->", 1)[1].strip()
            if not remote or remote.startswith("*"):
                continue
            ip = _remote_host(remote)
            if not ip or ip == "*" or _is_loopback(ip):   # drop local IPC (lo0)
                continue
            try:
                b = int(cols[byte_idx]) if cols[byte_idx].strip() else 0
            except ValueError:
                b = 0
            bi = 0
            if 0 <= in_idx < len(cols):
                try:
                    bi = int(cols[in_idx]) if cols[in_idx].strip() else 0
                except ValueError:
                    bi = 0
            key = (cur[0], cur[1], ip)
            # += : one process can hold several connections to the SAME dest
            # (real fixture: Slack had 2 conns to one EC2). '=' dropped bytes.
            # Caveat: these are cumulative counters; when a big conn closes and a
            # new one to the same ip opens, one tick's delta may undercount --
            # acceptable vs permanently dropping a concurrent connection.
            prev = flows.get(key)
            flows[key] = (Bytes(prev.out + b, prev.inb + bi) if prev
                          else Bytes(b, bi))
        else:                                             # candidate process row
            name, _, pid = c1.rpartition(".")
            cur = (name, pid) if (name and pid.isdigit()) else None
    return flows


def aggregate_flows(flows, baseline, resolve_domain, is_ai, observe=None, warmup=False):
    """Per-process byte split (ai / nonai / unresolved) from per-flow deltas.
    Pure + injectable (resolve_domain, is_ai) so classification is unit-testable
    without nettop/rumps. Splitting AI-endpoint bytes from the rest within one
    process is what kills the telemetry-SDK false positive (small sentry.io
    bytes can't clear the floor; big api.anthropic.com bytes are excluded).
    `observe(pid, kind, dest, delta, ip)` (optional) feeds each non-AI/unresolved
    delta to the capacity ledger, covert-channel detector and fan-out counter
    without coupling this pure function to their state.

    First-observation semantics live in `_delta` (fixed 2026-07-27; measured
    94.2% byte loss and 0/25 fan-out recall before this) and are applied
    identically to bytes_out and bytes_in. nettop's counters are cumulative PER
    CONNECTION, so a key we have never seen is a connection that opened since the
    last sample: its whole cumulative IS egress that happened on our watch, and
    the old `baseline.get(key, total)` discarded all of it. Rules now:
      - key unseen and NOT warmup -> delta = total (count the new connection)
      - key unseen and warmup     -> delta = 0     (sampler cold start: those
        bytes predate us; counting them would fire a red on every launch)
      - total < previous          -> counter reset (socket/pid reuse) -> delta = total
      - otherwise                 -> delta = total - previous
    The caller must persist baseline across ticks with a TTL rather than
    replacing it, so a flow that vanishes from one snapshot and returns is not
    re-counted from zero (see Sampler._tick).
    """
    per_pid = collections.defaultdict(
        lambda: {"ai": 0, "nonai": 0, "unresolved": 0, "in": 0, "dests": {}})
    for (name, pid, ip), total in flows.items():
        tot = _as_bytes(total)
        prev = baseline.get((name, pid, ip))
        pv = _as_bytes(prev) if prev is not None else None
        # ONE rule, applied twice -- see _delta. Gating is unchanged: only the
        # egress delta can suppress a row, so adding bytes_in cannot move any
        # threshold. `in` is carried for context (the up/down ratio) only.
        delta = _delta(pv.out if pv is not None else None, tot.out, warmup)
        delta_in = _delta(pv.inb if pv is not None else None, tot.inb, warmup)
        if delta <= 0:
            continue
        dom = resolve_domain(ip)
        agg = per_pid[(name, pid)]
        agg["in"] += delta_in
        if dom is not None and is_ai(dom):
            agg["ai"] += delta
        elif dom is not None:
            agg["nonai"] += delta
            agg["dests"][dom] = agg["dests"].get(dom, 0) + delta
            if observe:
                observe(pid, "dom", dom, delta, ip)
        else:
            agg["unresolved"] += delta
            if observe:
                observe(pid, "ip", ip, delta, ip)
    return per_pid


class NettopStream(threading.Thread):
    """One persistent `nettop -L 0 -s 1` whose latest cumulative bytes_out per
    (name, pid, ip) is kept in memory. Replaces relaunching a one-shot nettop on
    every tick: same destination recall as a 1 s relaunch, at ~1/6 the CPU (see
    the NETTOP_STREAM_CMD note). Self-heals if nettop dies; the Sampler falls
    back to a one-shot sample for any tick where the stream has produced nothing.

    `lines` may be injected (any iterable of CSV lines) to unit-test the
    incremental parser without a subprocess.
    """

    def __init__(self, lines=None):
        super().__init__(daemon=True)
        self._latest = {}                 # (name, pid, ip) -> (bytes_out, last_ts)
        self._lock = threading.Lock()
        self._byte_idx = 5                # refined when a header row arrives
        self._in_idx = -1                 # bytes_in; -1 until a header says otherwise
        self._lines = lines               # injected source (tests) or None
        self.restarts = 0

    # --- parsing ---------------------------------------------------------
    def _feed(self, line, now=None):
        now = time.time() if now is None else now
        cols = line.split(",")
        if len(cols) > 1 and "bytes_out" in [c.strip() for c in cols]:
            hdr = [c.strip() for c in cols]
            self._byte_idx = hdr.index("bytes_out")
            self._in_idx = hdr.index("bytes_in") if "bytes_in" in hdr else -1
            return
        if len(cols) <= self._byte_idx:
            return
        c1 = cols[1].strip()
        if "<->" in c1:                                   # connection row
            if self._cur is None:
                return
            remote = c1.split("<->", 1)[1].strip()
            if not remote or remote.startswith("*"):
                return
            ip = _remote_host(remote)
            if not ip or ip == "*" or _is_loopback(ip):
                return
            try:
                b = int(cols[self._byte_idx]) if cols[self._byte_idx].strip() else 0
            except ValueError:
                return
            bi = 0
            if 0 <= self._in_idx < len(cols):
                try:
                    bi = int(cols[self._in_idx]) if cols[self._in_idx].strip() else 0
                except ValueError:
                    bi = 0
            key = (self._cur[0], self._cur[1], ip, c1)
            with self._lock:
                # Keyed by the FULL connection string (local endpoint included), so
                # two concurrent connections to one destination never overwrite each
                # other and no timing heuristic is needed to tell "same sample"
                # apart from "next sample". snapshot() sums them per destination,
                # matching parse_flows' += rule.
                self._latest[key] = (Bytes(b, bi), now)
        else:                                             # candidate process row
            name, _, pid = c1.rpartition(".")
            self._cur = (name, pid) if (name and pid.isdigit()) else None

    _cur = None

    def snapshot(self, now=None, ttl=None):
        """{(name,pid,ip): Bytes(out, inb)} for connections seen within ttl
        seconds, summed across concurrent connections to the same destination."""
        now = time.time() if now is None else now
        ttl = BASELINE_TTL if ttl is None else ttl
        out = {}
        with self._lock:
            stale = [k for k, (_b, ts) in self._latest.items() if now - ts > ttl]
            for k in stale:
                del self._latest[k]
            for (name, pid, ip, _conn), (b, _ts) in self._latest.items():
                k = (name, pid, ip)
                cur = out.get(k)
                out[k] = (Bytes(cur.out + b.out, cur.inb + b.inb) if cur
                          else Bytes(b.out, b.inb))
        return out

    # --- lifecycle -------------------------------------------------------
    def run(self):
        if self._lines is not None:                       # injected: test mode
            for ln in self._lines:
                self._feed(ln)
            return
        while True:
            try:
                p = subprocess.Popen(NETTOP_STREAM_CMD, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True)
                for line in p.stdout:
                    self._feed(line)
                p.wait()
            except Exception as e:
                log(f"ERROR nettop stream {e}")
            self.restarts += 1
            log(f"nettop stream ended; restarting (#{self.restarts})")
            time.sleep(2)


def _argv(pid: str) -> str:
    try:
        return subprocess.run(["ps", "-o", "command=", "-p", pid],
                              capture_output=True, text=True,
                              timeout=3).stdout.strip().lower()
    except Exception:
        return ""


# --- background sampler (no AppKit here) --------------------------------
class Sampler(threading.Thread):
    def __init__(self, sni: SNICache, out_queue, lock):
        super().__init__(daemon=True)
        self.sni = sni
        self.out = out_queue
        self.lock = lock
        self.baseline = {}
        self.seen_ts = {}            # (name,pid,ip) -> last time this flow was seen
        self.warmup = True           # first tick only seeds; see aggregate_flows
        self.agent_cache = {}        # (name,pid) -> agent token or None  (P1-D)
        self.last_emit = {}          # (pid, kind) -> ts                  (P1-F)
        self.ledger = DestLedger(burst_bytes=FLAG_BYTES, drain_rate=DRAIN_RATE)
        self.chan = CovertChannelDetector()
        self.fan = DestinationFanout()      # cardinality shape (scan/lateral)
        self.recon = activity.Reconciler()   # L1<->L3, amber-only, off unless fed
        self.recon_state = None              # last on/off state, to log transitions
        self.stream = NettopStream()        # persistent nettop; see NETTOP_STREAM_CMD
        self.fallbacks = 0

    def run(self):
        update_check_and_log(log)    # trust act: our own egress logged first
        self.stream.start()
        log("sentinel starting (per-flow attribution, streaming nettop)")
        # Coverage gap: if a previous run stopped and nothing was watching since,
        # say so instead of quietly resuming. A gap is a fact about what we did
        # NOT see, which is the whole point of the dead-man switch.
        gap = deadman.coverage_gap()
        if gap:
            mins = gap / 60
            self._push(AMBER,
                       f"INFO coverage gap: nothing was watching for "
                       f"{mins:.0f} min before this start (sentinel was not "
                       f"running). Egress during that window was not observed.",
                       None, "gap", "gap")
        while True:
            try:
                self._tick()
            except Exception as e:
                log(f"ERROR sample {e}")
            time.sleep(TICK_SEC)

    def _agent_for(self, name, pid):
        """(token, via) -- via is the child process name when the traffic came from
        a subprocess of an agent (git/npm/curl), None when the process matched
        itself. Cached per (name,pid): argv and ancestry are stable for a pid."""
        key = (name, pid)
        if key not in self.agent_cache:
            self.agent_cache[key] = proctree.attribute(name, pid, self._match)
        return self.agent_cache[key]

    def _match(self, blob):
        """Tokenise an identity string and return an agent token, or None.
        Policy lives here (confusable exclusion), not in proctree."""
        tokens = set(_TOKEN_SPLIT.split(blob.lower()))
        if tokens & ALLOW.confusables():
            return None
        return next(iter(tokens & ALLOW.agent_tokens()), None)

    def _push(self, color, msg, notify, pid, kind):
        now = time.time()
        if now - self.last_emit.get((pid, kind), 0) < DEDUPE_COOLDOWN:
            return                            # P1-F: cooldown per (pid, kind)
        self.last_emit[(pid, kind)] = now
        with self.lock:
            self.out.append((color, msg, notify))

    def _tick(self):
        now = time.time()
        # Dead-man beat FIRST: if anything below throws or hangs, the missing beat
        # is what the root-side sniffer reports. Silence has to cost something.
        deadman.beat(now)
        # L1 refresh BEFORE observing, so this tick's deltas are matched against
        # declarations that already exist. Log the on/off transition: silently
        # doing nothing is how a broken integration stays invisible.
        was = self.recon_state
        is_now = self.recon.refresh(now)
        if was is not None and was != is_now:
            log(f"INFO reconciliation {'active' if is_now else 'inactive'} "
                f"({paths.ACTIVITY_FILE})")
        self.recon_state = is_now
        flows = self.stream.snapshot(now)
        if not flows:
            # stream not producing (dead nettop, or a macOS build whose logging
            # mode behaves differently) -> fall back to a one-shot sample so the
            # app degrades instead of going silent.
            self.fallbacks += 1
            if self.fallbacks in (1, 10, 100):
                log(f"WARN nettop stream empty; one-shot fallback "
                    f"(#{self.fallbacks})")
            try:
                flows = parse_flows(
                    subprocess.run(NETTOP_CMD, capture_output=True,
                                   text=True, timeout=10).stdout)
            except Exception as e:
                # The fallback was supposed to be what keeps the app from going
                # silent, and until 2026-08-06 it was the thing that killed the
                # tick: no nettop binary raises FileNotFoundError, a hung one
                # raises TimeoutExpired, and neither was caught. Both are exactly
                # the conditions the fallback exists for. Found by running the
                # suite on a machine without nettop; it would fire identically on
                # a Mac where nettop is missing, renamed, or sandboxed away.
                if self.fallbacks in (1, 10, 100):
                    log(f"WARN one-shot fallback failed too ({e}); "
                        f"no flow data this tick")
                flows = {}

        # pid -> process name for THIS snapshot. Handed to the reconciler at
        # observe time because its verdict lands on a LATER tick, by which point
        # a short-lived flow's process may be absent from every snapshot.
        names = {p: n for (n, p, _ip) in flows}

        def observe(pid, kind, dest, delta, ip):
            self.ledger.add(pid, kind, dest, delta, now)
            self.chan.observe(pid, dest, delta, now)
            # Fan-out keys on the IP, ALWAYS. Feeding it `dest` (a domain when SNI
            # resolved, a raw IP when not) meant one service could be counted twice
            # across ticks as its SNI became known. IP is the measured join key and
            # is always present. Caveat: a CDN behind rotating addresses inflates
            # the count, and eTLD+1 collapsing is a v1 refinement.
            self.fan.observe(pid, ip, delta, now)
            # Reconciliation rides the SAME hook, but note it does NOT inherit the
            # agent gate: aggregate_flows feeds every non-AI flow here, so EDR,
            # browsers and OS telemetry arrive too. The gate is applied at drain
            # time below. Only the AI-endpoint exclusion is genuinely inherited.
            self.recon.observe(pid, dest, delta, now, name=names.get(pid, ""))

        per_pid = aggregate_flows(flows, self.baseline,
                                  self.sni.domain_for_ip, ALLOW.matches,
                                  observe=observe, warmup=self.warmup)
        self.warmup = False
        # Persist baseline with a TTL instead of replacing it. Replacing (the old
        # `= dict(flows)`) meant a flow missing from ONE snapshot looked brand new
        # on its return and, under the fixed first-observation rule, would be
        # re-counted from zero. Carrying it for BASELINE_TTL keeps that honest;
        # the TTL still reclaims dead keys and lets a reused pid start fresh.
        for k, v in flows.items():
            self.baseline[k] = v
            self.seen_ts[k] = now
        for k in [k for k, ts in self.seen_ts.items() if now - ts > BASELINE_TTL]:
            del self.seen_ts[k]
            self.baseline.pop(k, None)
        self.ledger.gc(now)
        self.chan.gc(now)
        self.fan.gc(now)
        self.recon.gc(now)

        for (name, pid), agg in per_pid.items():
            # P1-D preserved: cheap ledger/heuristic checks BEFORE the ps fork.
            breaches = self.ledger.breaches(pid, now)
            chan_hits = self.chan.suspicious(pid, now)
            fan_hit = self.fan.fanout(pid, now)
            if not breaches and not chan_hits and not fan_hit:
                continue
            agent, via = self._agent_for(name, pid)
            if not agent:
                continue
            label = f"{agent} via {via}" if via else agent
            dom_breaches = {d: lvl for (kind, d), lvl in breaches.items()
                            if kind == "dom"}
            ip_breaches = {d: lvl for (kind, d), lvl in breaches.items()
                           if kind == "ip"}
            if dom_breaches:
                dest = ", ".join(sorted(dom_breaches, key=dom_breaches.get,
                                        reverse=True)[:3])
                mb = sum(dom_breaches.values()) / 1024 / 1024
                ratio = (f"{agg['nonai'] / agg['ai']:.0f}x model-channel"
                         if agg["ai"] else "no model traffic this tick")
                # P1-4: "likely" -- SNI shared-IP resolution is a heuristic.
                down = agg["in"] / 1024 / 1024
                msg = (f"WARN {label} (pid {pid}) sustained {mb:.0f} MB up / "
                       f"{down:.1f} MB down (capacity ledger) to likely "
                       f"non-AI dest: {dest}  [{ratio}]")
                self._push(RED, msg, (label, dest, mb), pid, "red")
            elif ip_breaches:
                mb = sum(ip_breaches.values()) / 1024 / 1024
                msg = (f"INFO {label} (pid {pid}) sustained {mb:.0f} MB up / "
                       f"{agg['in'] / 1024 / 1024:.1f} MB down; destination "
                       f"unresolved - run sni_sniffer for domain names")
                self._push(AMBER, msg, None, pid, "amber")
            for dest, reason in chan_hits:
                # covert-channel signatures are heuristics -> amber ONLY, never red
                msg = (f"INFO {label} (pid {pid}) covert-channel heuristic "
                       f"to {dest}: {reason}")
                self._push(AMBER, msg, None, pid, "covert")
            if fan_hit:
                # cardinality shape: many dests, few bytes each -- the ledger
                # structurally cannot fire on this. AMBER ONLY: `npm install`
                # and a 40-URL read look identical at the metadata layer.
                n, sample = fan_hit
                msg = (f"INFO {label} (pid {pid}) unusual breadth: {n} distinct "
                       f"low-volume destinations in "
                       f"{DestinationFanout.WINDOW_SEC // 60} min "
                       f"(e.g. {', '.join(sample)}) - normal for a package "
                       f"install or a multi-URL read; worth a look if not")
                self._push(AMBER, msg, None, pid, "fanout")

        # Reconciliation is drained OUTSIDE the per-pid loop on purpose. That loop
        # only visits processes with a positive byte delta in THIS tick, while a
        # reconciliation verdict is deliberately delayed to a later one -- so
        # consulting it in there silently dropped exactly the burst-then-quiet
        # shape, i.e. the exfil shape. Found by an end-to-end check; the
        # reconciler's own unit tests called drain() directly and could not see it.
        for rpid, rname, rdest, rbytes, rnote in self.recon.drain(now):
            # Fail closed on the ACCUSATION, not on the OBSERVATION. This gate
            # used to `continue` in silence, and that silence was the mechanism
            # that made confused-deputy egress invisible: ask a pre-existing
            # daemon to fetch on your behalf and its socket is in no agent
            # lineage, so it vanished here without leaving a number behind. The
            # sibling mitm-audit design documents that gap in its README; this
            # one did not even count it. We still refuse to name a destination
            # or accuse a process we cannot attribute -- that is the
            # wrong-accusation failure this project keeps guarding against --
            # but we count it, and we say the count, so a deputy leaves a mark.
            ragent, rvia = self._agent_for(rname, rpid)
            if not ragent:
                self.recon.unattributed += 1
                continue
            rlabel = f"{ragent} via {rvia}" if rvia else ragent
            # AMBER ONLY and deliberately not an accusation: "nothing declared
            # this" is a statement about the DECLARATIONS, not about the traffic.
            # A partial integration, a tool that logs after it returns, or a
            # subprocess doing its own I/O all land here legitimately.
            msg = (f"INFO {rlabel} (pid {rpid}) {_fmt_bytes(rbytes)} "
                   f"to {rdest} does not reconcile with declared activity "
                   f"({rnote}). Expected if the agent-side hook does not cover "
                   f"this path; worth a look if it should")
            self._push(AMBER, msg, None, rpid, "unreconciled")

        # One aggregate line for everything the attribution gate refused to
        # accuse. Deliberately count-only -- no destination, no pid -- because
        # naming them is the accusation we are declining to make. Rate-limited
        # by the same per-(pid, kind) cooldown as everything else, with a
        # constant pseudo-pid so it cannot spam.
        if self.recon.unattributed >= UNATTRIBUTED_REPORT_AT:
            n = self.recon.unattributed
            self.recon.unattributed = 0
            self._push(AMBER,
                       f"INFO {n} settled egress flow(s) could not be "
                       f"attributed to any agent process lineage. Ordinary for "
                       f"OS/vendor telemetry and browsers -- but a "
                       f"confused-deputy exfil (agent asks a pre-existing "
                       f"daemon to fetch on its behalf) is also shaped exactly "
                       f"like this, and this counter is the only trace it "
                       f"leaves here",
                       None, "unattributed", "unattributed")


# --- main-thread UI: drains the queue only ------------------------------
def _fmt_bytes(n):
    """Scale-appropriate size, because the whole point is small payloads now.

    The reconciliation alert used a hard-coded MB with one decimal. That was
    fine while a 64 KB floor guaranteed nothing small ever reached it; the
    moment the floor became conditional on novelty, a 4 KB credentials POST --
    the exact case the fix exists to surface -- started rendering as "0.0 MB",
    which reads as nothing happened. Fixing detection and leaving the reporting
    unable to express it is the same mistake in a different layer.
    """
    n = float(n)
    for unit, step in (("B", 1024), ("KB", 1024 * 1024), ("MB", 1024 ** 3)):
        if n < step:
            v = n / (step / 1024)
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
    return f"{n / 1024 ** 3:.2f} GB"


class SentinelApp(rumps.App):
    def __init__(self):
        super().__init__(GREEN, quit_button="Quit")
        self.alerts = collections.deque(maxlen=50)
        self._queue = collections.deque()
        self._lock = threading.Lock()
        self.menu = ["Recent egress alerts", None, "Open log", "About"]
        self.sampler = Sampler(SNICache(), self._queue, self._lock)
        self.sampler.start()
        self.timer = rumps.Timer(self._drain, UI_DRAIN_SEC)
        self.timer.start()

    def _drain(self, _=None):
        while True:
            with self._lock:
                if not self._queue:
                    break
                color, msg, notify = self._queue.popleft()
            self.alerts.appendleft(msg)
            if color == RED or self.title != RED:
                self.title = color
            if notify:
                agent, dest, mb = notify
                try:
                    rumps.notification("Agent Egress Sentinel",
                                       f"{agent} -> {dest}",
                                       f"{mb:.0f} MB to a likely non-AI destination")
                except Exception as e:
                    log(f"(notification suppressed: {e})")

    @rumps.clicked("Recent egress alerts")
    def show_alerts(self, _):
        alerts = list(self.alerts)[:10]
        rumps.alert("Recent egress alerts",
                    "\n".join(alerts) if alerts else "No anomalies yet.")
        self.title = GREEN

    @rumps.clicked("Open log")
    def open_log(self, _):
        subprocess.run(["open", str(LOG)])

    @rumps.clicked("About")
    def about(self, _):
        rumps.alert("Agent Egress Sentinel",
                    "Metadata-only egress monitor for AI coding agents.\n"
                    "No TLS decryption, no root CA. We log our own update ping too.\n\n"
                    "Team version (audit log + compliance export) waitlist: see README.")


if __name__ == "__main__":
    if not _HAS_RUMPS:
        raise SystemExit("pip install rumps")
    SentinelApp().run()
