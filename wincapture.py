#!/usr/bin/env python3
"""
Windows byte-count source: ETW Microsoft-Windows-Kernel-Network -> the same
`{(name, pid, dest_ip): Bytes(out, inb)}` mapping `sentinel.parse_flows` builds
from `nettop`.

WHY THIS SHAPE. Everything above the capture layer -- ledger, fan-out, ancestry
attribution, reconciliation, alert text, and their tests -- consumes that one
mapping. Filling it is the entire Windows port; see PLATFORMS.md.

WHY ETW AND NOT A nettop EQUIVALENT. There isn't one. But the substitution is an
upgrade rather than a workaround, and this was measured, not assumed
(PLATFORMS.md section 3, 2026-08-06): the provider is **event-driven**, so the
`min(1, L/T)` recall bound that defines the macOS build does not apply. Measured
recall on deliberately short-lived connections: **361 observed / 301 made**. The
macOS sampler manages 5.8% at ~50 ms lifetimes.

CUMULATIVE, DELIBERATELY. ETW reports per-transfer DELTAS; nettop reports
cumulative counters and `sentinel` diffs them. This module accumulates, so the
consumer is unchanged. That is not a lossy adaptation -- a flow first seen here
starts at zero, so its first diff is its full byte count, which is exactly the
behaviour the macOS path had to be fixed into on 2026-07-27 ("Wrong #2", 94.2%
of new-flow bytes discarded). Starting from zero makes it true by construction.

DEPENDENCY. `pywintrace` (pip, pure Python, no compiled extension -- it is the
ctypes struct marshalling for OpenTrace/ProcessTrace/TDH, already correct).
Writing those structs by hand was the alternative; a wrong `EVENT_TRACE_LOGFILE`
layout fails as garbage fields rather than as an error, which is the worst
failure shape available here. Absent -> `available()` is False and the caller
degrades, it never raises on import.

STATUS: the pure translation below is unit-tested (tests/test_wincapture.py).
The live binding at the bottom needs an elevated prompt and is UNRUN.
"""

import collections
import threading

import proctree

Bytes = collections.namedtuple("Bytes", "out inb")   # must match sentinel.Bytes

PROVIDER_NAME = "Microsoft-Windows-Kernel-Network"
PROVIDER_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"

# Event ids, from the classic kernel network opcode set and confirmed present by
# tools/etw_probe.py on this machine.
#
# ONLY Send and Recv are counted. The two most frequent ids in a real 30 s trace
# were 18 and 34 -- TcpCopy, the receive-side copy -- and counting those as well
# as Recv would roughly DOUBLE every inbound number while looking entirely
# plausible. Inbound bytes feed no rule (see README: authorization is not a
# function of traffic volume), so a silent 2x there would have been unusually
# hard to notice. Excluded on the documented semantics of the opcode;
# `by_event_id` exists so the assumption can be checked against a known-size
# download rather than believed.
SEND_IDS = {10, 26, 42, 58}        # TCP v4, TCP v6, UDP v4, UDP v6
RECV_IDS = {11, 27, 43, 59}
DATA_IDS = SEND_IDS | RECV_IDS

# WHICH FIELD HOLDS THE REMOTE PEER. This provider is not consistent, and the
# first live run (2026-08-06) is what showed it:
#
#   TCP recv (11, 27)  -> `daddr` is the CONNECTION's remote.
#   UDP recv (43, 59)  -> `daddr` is the PACKET's destination, i.e. US, or a
#                         multicast group. The remote peer is in `saddr`.
#
# Reading `daddr` for all of them produced rows like `claude.exe -> 192.0.2.10`
# (this machine's own LAN address) and `chrome.exe -> 224.0.0.251` (mDNS). Both
# are nonsense destinations, and the multicast ones would have inflated the
# per-pid fan-out counter with peers that do not exist.
#
# Established by arithmetic, not by reading docs: per-event-id byte totals from
# that run close EXACTLY on the affected rows -- 43 = 3488+3488+284+416 = 7,676
# and 59 = 3411+3488+3488+38 = 10,425, all four addresses being either this host
# or a multicast group; while 11 = 4678+78 and 27 = 197+28 land on real remotes.
# That per-event-id breakdown existed only because the TcpCopy assumption needed
# a way to be checked; it caught a different bug instead.
REMOTE_IN_SADDR = {43, 59}

# Fields as TDH decodes them; verified present on 98-100% of events across three
# probe runs. `connid` is deliberately not here: it is present and CONSTANT AT 0
# on this provider, and keying on it once produced a confident wrong verdict.
F_PID, F_SIZE, F_DADDR, F_SADDR = "PID", "size", "daddr", "saddr"


def _is_loopback(host: str) -> bool:
    # Same rule as sentinel._is_loopback: a local-model agent (ollama on
    # 127.0.0.1) can push GB over loopback and must not be counted.
    h = (host or "").lower()
    return h == "localhost" or h.startswith("127.") or h == "::1"


def not_a_destination(host: str) -> bool:
    """True for addresses that cannot be an exfiltration destination.

    Loopback, plus three classes the macOS path never had to think about because
    `nettop`'s connection rows do not carry them, and which the first live ETW
    run surfaced immediately:

      - **multicast** (224.0.0.0/4, ff00::/8). mDNS service discovery was the
        single largest inbound source in a 20 s capture. Not a peer; and each
        group would have counted as a distinct destination in the per-pid
        fan-out counter, which is the one detector that keys on breadth.
      - **link-local** (169.254/16, fe80::/10) and **broadcast**. Same argument.
      - **unspecified** (0.0.0.0, ::).

    Private LAN unicast is deliberately NOT here. An agent uploading to a NAS at
    192.168.1.50 is egress from this machine, and dropping RFC1918 would create a
    blind spot in the direction of "the attacker is on your network". The cost is
    that DNS to the router shows up as a destination row; that is noise in the
    alert text, not a false accusation, and it matches what the macOS path does.
    """
    h = (host or "").strip().lower()
    if not h or h in ("::", "0.0.0.0", "255.255.255.255"):
        return True
    if _is_loopback(h):
        return True
    if ":" in h:                                   # IPv6
        return h.startswith("ff") or h.startswith("fe8") or \
            h.startswith("fe9") or h.startswith("fea") or h.startswith("feb")
    head, _, _ = h.partition(".")
    try:
        first = int(head)
    except ValueError:
        return False
    return 224 <= first <= 255 or h.startswith("169.254.")


def translate(event_id, data):
    """One ETW event -> (pid, remote_ip, out_bytes, in_bytes), or None.

    Pure. Everything platform-specific below this line is delivery; this is the
    part that decides what a byte count means, so it is the part with tests.

    Which field holds the remote depends on the event id -- see REMOTE_IN_SADDR.
    Returns None for anything that is not a data transfer, is not addressed to a
    possible destination, is malformed, or is zero-byte. Zero-byte events are
    real and frequent here (the provider covers DNS, and `size` is 0 on
    connect/teardown) and dropping them costs nothing.
    """
    if event_id not in DATA_IDS:
        return None
    field = F_SADDR if event_id in REMOTE_IN_SADDR else F_DADDR
    try:
        pid = int(data[F_PID])
        nbytes = int(data[F_SIZE])
        ip = str(data[field]).strip()
    except (KeyError, TypeError, ValueError):
        return None
    if nbytes <= 0 or pid <= 0 or not_a_destination(ip):
        return None
    if event_id in SEND_IDS:
        return pid, ip, nbytes, 0
    return pid, ip, 0, nbytes


class FlowAccumulator:
    """Per-transfer deltas -> the cumulative mapping the consumer expects.

    Thread-safe: pywintrace calls the event callback from its own consumer
    thread while the app's tick reads a snapshot.
    """

    def __init__(self, name_for_pid=None, max_keys=4096):
        # Injectable for tests, and because resolving a pid to a name costs a
        # process-table lookup that must not happen inside the event callback
        # more than once per pid.
        self._name_for = name_for_pid or self._default_name
        self._lock = threading.Lock()
        self._flows = {}                       # (name, pid, ip) -> [out, inb]
        self._names = {}                       # pid -> name, cached
        self._by_event = collections.Counter()  # event_id -> bytes, diagnostics
        self._dropped = 0
        self._max_keys = max_keys

    @staticmethod
    def _default_name(pid):
        rec = proctree.proc_info(pid)
        return rec[1] if rec else f"pid-{pid}"

    def name_for(self, pid):
        if pid not in self._names:
            if len(self._names) > self._max_keys:
                self._names.clear()            # pids are recycled; so is this
            self._names[pid] = self._name_for(pid)
        return self._names[pid]

    def feed(self, event_id, data):
        """Called once per ETW event. Must never raise: it runs on the consumer
        thread, and an exception there kills capture silently."""
        try:
            row = translate(event_id, data)
            if row is None:
                return
            pid, ip, out, inb = row
            key = (self.name_for(pid), pid, ip)
            with self._lock:
                self._by_event[event_id] += out + inb
                cur = self._flows.get(key)
                if cur is None:
                    if len(self._flows) >= self._max_keys:
                        # Bound memory. Reported, not silent: a monitor that
                        # quietly stops counting is the failure this repo is about.
                        self._dropped += 1
                        return
                    self._flows[key] = [out, inb]
                else:
                    cur[0] += out
                    cur[1] += inb
        except Exception:
            pass

    def snapshot(self):
        """{(name, pid, ip): Bytes(out, inb)} -- cumulative, same as parse_flows."""
        with self._lock:
            return {k: Bytes(v[0], v[1]) for k, v in self._flows.items()}

    def diagnostics(self):
        with self._lock:
            return {"flows": len(self._flows),
                    "dropped_new_flows": self._dropped,
                    "bytes_by_event_id": dict(self._by_event)}


# ------------------------------------------------------------------ live ---
def available():
    """True when the ETW source can actually be started here."""
    try:
        import etw            # noqa: F401  (pywintrace)
    except Exception:
        return False
    return True


class EtwFlowSource:
    """Live ETW session. UNRUN as of 2026-08-06 -- needs an elevated prompt.

    Deliberately thin: everything it does beyond starting and stopping a session
    is delegated to FlowAccumulator, which is tested. If this class is wrong, it
    is wrong in a way that produces no events at all rather than wrong numbers.
    """

    def __init__(self, accumulator=None):
        self.acc = accumulator or FlowAccumulator()
        self._job = None

    def start(self):
        import etw
        providers = [etw.ProviderInfo(PROVIDER_NAME, etw.GUID(PROVIDER_GUID))]
        self._job = etw.ETW(
            providers=providers,
            event_callback=lambda ev: self.acc.feed(ev[0], ev[1]),
            # Ask the provider for only the ids we count. Cheaper than filtering
            # in the callback, and it is the difference between processing the
            # 170-900 events/s the probe measured and a fraction of it.
            event_id_filters=sorted(DATA_IDS),
        )
        self._job.start()
        return self

    def stop(self):
        if self._job is not None:
            try:
                self._job.stop()
            finally:
                self._job = None

    def snapshot(self, _now=None):
        return self.acc.snapshot()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


if __name__ == "__main__":
    import sys
    import time

    if not available():
        print("pywintrace not installed:  pip install pywintrace")
        sys.exit(1)
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    print(f"capturing {secs}s (needs an elevated prompt) ...")
    src = EtwFlowSource().start()
    try:
        time.sleep(secs)
    finally:
        src.stop()
    flows = src.snapshot()
    for (name, pid, ip), b in sorted(flows.items(), key=lambda kv: -kv[1].out)[:20]:
        print(f"  {b.out:>12,} out {b.inb:>12,} in   {name}.{pid} -> {ip}")
    print(f"\n{len(flows)} flows")
    print(src.acc.diagnostics())
