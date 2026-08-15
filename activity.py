#!/usr/bin/env python3
"""
L1 <-> L3 reconciliation, v0. AMBER ONLY.

The question every other detector in this repo asks is "is this traffic
unusual?" -- volume, ratio, cardinality, timing. On 2026-08-02 that whole class
was shown to be unanswerable at this layer: whether a transfer was AUTHORISED is
not a function of the traffic. Ask an agent to bulk-POST a few hundred records
and the bytes are identical to an exfil. No threshold fixes that, because the
label is not a function of the observables.

So this asks a different question, one that IS answerable: **did anything
declare this at all?** Observed egress from an agent's process lineage, with no
corresponding declared activity in the window, is unexplained. That is a set
difference, not a threshold.

THE CONTRACT (agent side writes, we only read)
----------------------------------------------
Append-only NDJSON at paths.ACTIVITY_FILE. One JSON object per line:

    {"ts": 1754160000.0, "pid": 4242, "tool": "fetch",
     "target": "example.com", "bytes": 2048}

    ts      required, float epoch seconds, when the activity was declared
    pid     required, the pid declaring it (traffic may come from a DESCENDANT)
    tool    required, free text, only used to make the alert readable
    target  OPTIONAL host (or URL -- we keep the host and drop the rest)
    bytes   OPTIONAL declared outbound byte estimate

Why a contract instead of reading a vendor transcript directory: those are
undocumented and change without notice, they differ per install, and reading
them means reading the user's entire conversation to learn one thing. A hook or
wrapper on the agent side can append one line per tool call.

WHY `bytes` IS RECORDED BUT NEVER GATES (v0)
--------------------------------------------
Declared volume genuinely strengthens the check: declare 2 KB, observe 8 MB to
the same host, and the destination reconciles while the magnitude does not. That
partially covers the case presence alone misses -- payload hidden inside a
declared call. But it cannot be a threshold yet, for three measured/structural
reasons:

  1. Transport overhead is not in the declaration. TLS record framing, HTTP
     headers, retries and connection setup push observed ABOVE declared;
     compression pushes it BELOW. The honest ratio spread is wide.
  2. The largest egress term is not a tool call at all. For a coding agent the
     dominant upload is the inference request itself (context + files), which
     the tool layer never sees. Here that is handled by exclusion rather than
     estimation: AI-endpoint bytes are classified upstream and never reach this
     reconciler.
  3. The join is many-to-many. One connection can carry several declared calls
     (keep-alive), and one declared call can span several connections.

So `bytes` is carried into the alert TEXT as context. Putting an uncalibrated
magnitude into a threshold is exactly the mistake the ratio finding documented.

FALSE-POSITIVE CONTROLS: SUPPRESS BY DOWNGRADING, NOT BY DISCARDING
-------------------------------------------------------------------
Re-audited 2026-08-03 after a cross-vendor review panel. Ten controls existed
and ALL TEN were implemented as `continue` -- i.e. as silent discard. Two of them
were removing exactly the signal this module exists to produce:

  1. A flat 64 KB byte floor, chosen to avoid drowning in per-process chatter.
     But the payloads that matter here are small: ~/.aws/credentials is ~4 KB, an
     SSH private key 2-3 KB, a bearer token a few hundred bytes. The floor made
     the tool blind to its own threat model -- and a unit test asserted that
     blindness as if it were the contract. Now the floor is CONDITIONAL on
     destination novelty (no floor for a first-time destination), which is the
     prior this project already documented as stronger than volume.

  2. The agent-attribution gate returned in silence for any process not in an
     agent lineage. That silence WAS the mechanism that made confused-deputy
     egress invisible: ask a pre-existing daemon to fetch on your behalf and its
     socket is in nobody's lineage, so it vanished leaving no number behind. It
     is now counted and the count is reported (no destination, no pid -- naming
     them would be the accusation we decline to make).

The generalisable rule, and the reason to re-read this whenever a threshold is
added: a noise control that DISCARDS is indistinguishable from a detector that
does not work. Downgrade low-confidence findings; do not delete them. Both bugs
above were bought with the same currency -- quiet -- and both were paid for with
the primary signal.

Declared volume is still context and still never gates on its own: transport
framing, an unseen inference-request term, and a many-to-many join make it
uncalibratable here (details at EXCESS_FACTOR).

WHAT THIS CANNOT DO
-------------------
A declaration is self-reported. This catches traffic with NO declared
counterpart -- an unaware leaky agent, vendor telemetry inside an agent process,
an injected instruction that goes around the tool layer (`bash curl ...`). It
does NOT catch traffic hidden inside a plausible declaration: an adversary that
writes a consistent line first passes. Declared volume raises that cost (the
declaration must be inflated too, which is more conspicuous) without closing the
class. Same shape as the dead-man switch and as the NX-bit analogy: evasion gets
more expensive, the category stays open.

Two more specific defeats, both deliberate and both documented in the README:
  - A declaration with no `target` is a WILDCARD for that pid. It no longer
    silences a FIRST-TIME destination outright (that made the defeat an
    invisible off-switch); on a destination already seen it still goes quiet.
  - When SNI did not resolve, an observation carries only an IP, so host
    matching is impossible and the check degrades to pid-presence only.

Two gaps found by a review panel on 2026-08-03 that were NOT documented anywhere
before, and are not closable at this privilege level:

  - SUSPEND-AND-RESUME, not kill. `SIGSTOP` the user-owned sentinel, exfiltrate,
    `SIGCONT` it inside deadman.BEAT_STALE_SEC (15 s). No process dies, no
    restart happens, no coverage gap is recorded -- coverage_gap() is only read
    at startup. Strictly stronger than killing us, which at least leaves an
    absent icon and a stale beat behind.
  - CONFUSED DEPUTY / SIBLING PROCESS. Egress from a process that is not in any
    agent lineage is, by design, not accused. A pre-existing daemon (or a
    sibling spawned by the agent's parent) asked to fetch on the agent's behalf
    therefore produces no per-flow finding -- only the aggregate unattributed
    count. The sibling design (agent-mitm-audit) documents this same gap in its
    README; this module previously did not even count it.

Both need an independently privileged, event-driven observer and a tamper-evident
off-host trail to actually close -- the direction standard security-event-logging
guidance points, which this tool does not meet (its evidence lives in locally
writable files).
"""

import json
import os
import time

import paths
import proctree


# Ports an HTTP proxy structurally CANNOT carry. Frozen 2026-08-07; the
# cross-view harness uses the identical list, and widening either one after
# seeing data is how a measurement becomes a story.
#
# This exists because closing the FRESH_SEC gate made the proxy invariant
# reachable for the first time -- and reachable meant it fired on every DNS and
# NTP query on the machine. The distinction it restores is the invariant's whole
# content: "could not have been proxied" (udp/443 is QUIC, 53 is DNS) versus
# "chose not to be" (tcp/443 direct). Without it those are the same event.
#
# UNKNOWN PORT IS NOT EXCLUDED. Excluding on missing data is a discard, and this
# module's own header says a control that discards is indistinguishable from a
# detector that does not work. Unknown errs toward reporting.
STRUCTURAL_PORTS = {53: "dns", 5353: "mdns", 123: "ntp", 67: "dhcp", 68: "dhcp",
                    1900: "ssdp"}


def _unproxyable(port, proto):
    """True when no HTTP proxy could have carried this, so it is not evidence."""
    if port is None:
        return False                       # fail open -- see the note above
    if port in STRUCTURAL_PORTS:
        return True
    return (proto or "").lower() == "udp" and port == 443      # QUIC


def _host(target):
    """Host out of a bare host or a URL. We keep the host and drop path/query:
    a full URL can carry secrets, and we would only be logging it."""
    if not target:
        return None
    t = str(target).strip()
    if "//" in t:
        t = t.split("//", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0]
    if "@" in t:                       # strip userinfo before splitting the port
        t = t.rsplit("@", 1)[1]
    if t.startswith("["):              # [::1]:443
        t = t[1:].split("]", 1)[0]
    elif t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t.lower().rstrip(".") or None


class Reconciler:
    """Windowed L1 declarations vs observed L3 egress. Amber only.

    Three properties that make this safe to run at all:

    1. FAIL-SAFE OFF. If the activity file is missing, or has not been written
       within FRESH_SEC, reconciliation is INACTIVE and reports nothing. The
       alternative -- treating absence of declarations as "everything is
       unexplained" -- turns a missing integration into an alert storm, which is
       the single most likely way this feature would get uninstalled. Absence of
       L1 is not evidence about L3.

    2. DELAYED VERDICT. A flow is visible to us the moment it moves bytes, but
       the declaration for it may be appended a fraction of a second later (or
       the agent may log after the call returns). Judging on sight would
       manufacture "undeclared" for ordinary ordering. So an unexplained
       observation is held for SETTLE_SEC and re-checked before it can be
       reported.

    3. EXPLICIT AGENT GATE. An earlier version of this docstring claimed the
       reconciler inherited the agent-attribution filter for free. That was
       wrong: aggregate_flows feeds this hook for EVERY non-AI flow, and the
       agent gate is applied later, in the alert loop. So EDR, browsers and OS
       telemetry do reach observe(), and the caller must apply the agent gate at
       drain time -- sentinel does. Only the AI-endpoint exclusion is genuinely
       inherited, which matters because the inference request (the largest
       upload, and the one the tool layer never sees) is thereby excluded by
       classification instead of estimation.
    """

    FRESH_SEC = 60           # activity file must be this recent to be trusted
    WINDOW_SEC = 300         # a declaration covers traffic within this of its ts
    SETTLE_SEC = 20          # hold an unexplained observation this long

    # --- the byte floor, and why it is now conditional -----------------------
    # A flat 64 KB floor was a bug, not a tuning choice. This tool exists to
    # notice credential exfiltration, and the payloads that matter are SMALL:
    # ~/.aws/credentials is ~4 KB, an SSH private key 2-3 KB, a bearer token a
    # few hundred bytes. A flat floor was therefore blind to exactly the class
    # it was built for -- and a unit test asserted that blindness as if it were
    # the contract. Found 2026-08-03 by a cross-vendor review panel.
    #
    # The fix is not a lower floor (that drowns you in per-process chatter). It
    # is to make the floor conditional on DESTINATION NOVELTY, which is the
    # prior this project already documented as stronger than volume:
    #   - a destination nothing in an agent lineage has contacted before
    #     -> NO floor. 4 KB to a first-time host is the highest-quality signal
    #        this tool can produce.
    #   - a destination already seen -> keep the floor. THAT is where the
    #     benign small-chatter noise actually lives.
    NOVEL_MIN_BYTES = 0          # first-time destination: report any volume
    KNOWN_MIN_BYTES = 64 * 1024  # seen before: small traffic is ordinary
    # Novelty is per-run (there is no persisted baseline yet), so every
    # destination looks new right after a restart. Suppress that: during the
    # first NOVELTY_WARMUP_SEC of a Reconciler's life, destinations are RECORDED
    # but never counted as novel. Same shape as the sampler's cold-start warmup.
    NOVELTY_WARMUP_SEC = 120
    SEEN_TTL = 24 * 3600         # forget a destination after a day of silence

    EXCESS_FACTOR = 8
    EXCESS_MIN_BYTES = 5 * 1024 * 1024
    MAX_LINES = 5000         # cap on lines held from one read (bounded memory)

    # --- imported from the sibling mitm-audit design -------------------------
    # Set SENTINEL_PROXY=host:port when the agent is launched under an
    # HTTP(S)_PROXY pointing at a local interceptor. It turns on the one
    # invariant a declaration CANNOT exempt:
    #
    #   a correctly-proxied agent process tree has NO non-loopback egress.
    #
    # Everything reaching this reconciler is already non-loopback (parse_flows
    # drops loopback so a local ollama never alarms), so under proxy mode ANY
    # observed flow from an agent lineage is by construction a bypass. That
    # loopback filter was written for privacy and turns out to be what makes the
    # invariant expressible here at all.
    #
    # Why this matters: every other verdict in this file rests on self-reported
    # declarations, so an attacker who writes one plausible line is explained.
    # This one rests on a structural property of the socket, so writing
    # declarations does not help. It is the strongest signal available, and it
    # is off unless you opt in by launching under a proxy.
    PROXY_ENV = "SENTINEL_PROXY"

    def __init__(self, path=None, proxy=None, now=None):
        self.path = paths.ACTIVITY_FILE if path is None else path
        self._decls = []      # [(ts, pid, tool, host_or_None, bytes_or_None)]
        self._offset = 0      # byte offset for incremental tailing
        self._inode = None
        self._pending = {}    # (pid, dest) -> [first_ts, total_bytes, last_ts, name]
        self._reported = {}   # (pid, dest) -> ts   (suppress repeats)
        self._active = False  # whether L1 is present and fresh
        self._malformed = 0
        self._seen_dests = {}  # dest -> last_seen_ts   (novelty baseline)
        self._born = time.time() if now is None else now
        # Unattributed egress is COUNTED, not discarded -- see note in sentinel.
        self.unattributed = 0
        self._proxy = _host(proxy if proxy is not None
                            else os.environ.get(self.PROXY_ENV, "")) or None

    # --- novelty -------------------------------------------------------------
    @property
    def proxy(self):
        """The configured proxy host, or None. Public because sentinel decides
        whether to forward allowlisted flows here based on it: under proxy mode
        the structural invariant outranks the allowlist, otherwise it does not
        exist and forwarding them would only add noise."""
        return self._proxy

    def _is_novel(self, dest, now):
        """Has any agent-lineage flow gone to this destination before?

        Returns False during NOVELTY_WARMUP_SEC after start, because a fresh
        process legitimately sees every destination for the first time and
        treating that as signal would fire on the whole steady state at once.
        """
        if now - self._born < self.NOVELTY_WARMUP_SEC:
            return False
        last = self._seen_dests.get(dest)
        return last is None or now - last > self.SEEN_TTL

    def floor_for(self, dest, now=None):
        """The byte floor that applies to this destination right now."""
        now = time.time() if now is None else now
        return (self.NOVEL_MIN_BYTES if self._is_novel(dest, now)
                else self.KNOWN_MIN_BYTES)

    # --- L1 side ---------------------------------------------------------
    def refresh(self, now=None):
        """Tail the activity file. Returns True if L1 is present and fresh.

        Tolerates truncation and rotation (inode change or shrink -> restart from
        0). A half-written last line is left for the next read rather than
        counted as malformed, because append-only writers routinely get caught
        mid-line.
        """
        now = time.time() if now is None else now
        try:
            st = os.stat(self.path)
        except OSError:
            self._active = False
            return False
        if self._inode is not None and (st.st_ino != self._inode
                                        or st.st_size < self._offset):
            self._offset = 0                      # rotated or truncated
            self._decls = []
        self._inode = st.st_ino
        if st.st_size > self._offset:
            try:
                with open(self.path, "r", errors="replace") as fh:
                    fh.seek(self._offset)
                    data = fh.read()
                # keep a trailing partial line for next time
                if data and not data.endswith("\n"):
                    cut = data.rfind("\n")
                    data = data[:cut + 1] if cut >= 0 else ""
                self._offset += len(data.encode("utf-8", "replace"))
                for line in data.splitlines():
                    rec = self._parse(line)
                    if rec:
                        self._decls.append(rec)
            except OSError:
                pass
        # A file nobody writes to any more must not keep this active: a stale
        # integration would otherwise look identical to a healthy quiet one.
        self._active = (now - st.st_mtime) <= self.FRESH_SEC
        self._decls = [d for d in self._decls if now - d[0] <= self.WINDOW_SEC]
        if len(self._decls) > self.MAX_LINES:
            self._decls = self._decls[-self.MAX_LINES:]
        return self._active

    def _parse(self, line):
        line = line.strip()
        if not line:
            return None
        try:
            o = json.loads(line)
            ts = float(o["ts"])
            pid = str(o["pid"])
            tool = str(o.get("tool", "?"))[:64]
        except (ValueError, TypeError, KeyError):
            self._malformed += 1
            return None
        nb = o.get("bytes")
        try:
            nb = int(nb) if nb is not None else None
        except (ValueError, TypeError):
            nb = None
        return (ts, pid, tool, _host(o.get("target")), nb)

    @property
    def active(self):
        return self._active

    @property
    def malformed(self):
        return self._malformed

    # --- matching --------------------------------------------------------
    def _matches(self, pid, dest, now, ancestors=proctree.ancestors):
        """Every declaration that could explain (pid, dest), newest first.

        Returns a LIST, not the first hit, because the join is many-to-many: one
        keep-alive connection carries several declared calls, so the declared
        volume for a destination is the SUM over matching declarations, not any
        single one. Comparing an aggregate observation against one call's
        declared size manufactures a 100x excess out of ordinary connection
        reuse -- found by a test, and it is the gap this module's header names.

        `dest` is a domain when SNI resolved and an IP when it did not; an IP can
        never match a declared host, so those fall back to pid-presence only --
        stated here rather than buried, because the unresolved case is strictly
        weaker.
        """
        chain = {str(p) for p in ancestors(int(pid))} if str(pid).isdigit() \
            else {str(pid)}
        looks_like_host = not dest.replace(".", "").replace(":", "").isdigit() \
            and ":" not in dest
        out = []
        for ts, dpid, tool, host, nb in self._decls:
            if abs(now - ts) > self.WINDOW_SEC or dpid not in chain:
                continue
            if host is None:                       # wildcard: pid declared work
                out.append((ts, dpid, tool, None, nb))
            elif not looks_like_host:              # IP: pid-only match
                out.append((ts, dpid, tool, host, nb))
            elif dest == host or dest.endswith("." + host) \
                    or host.endswith("." + dest):
                out.append((ts, dpid, tool, host, nb))
        return out

    def observe(self, pid, dest, nbytes, now=None, name="", is_agent=True,
                port=None, proto=None):
        """Feed one non-AI egress delta. No verdict here -- see drain().

        `name` is carried so a verdict can still be attributed after the flow has
        gone quiet: the process may no longer appear in any later snapshot, and
        the whole point of the settle delay is that the verdict lands on a LATER
        tick than the bytes.

        `is_agent` gates exactly ONE thing: whether this destination seeds the
        novelty baseline. Added 2026-08-07 after external review. This method is
        handed EVERY non-AI flow on the machine -- browsers, EDR, OS telemetry --
        and `_seen_dests` was written unconditionally, so a host Chrome had
        touched became "known" to the agent path and its floor rose from
        NOVEL_MIN_BYTES (0) to KNOWN_MIN_BYTES (64 KB). Measured: an agent's 4 KB
        credential POST to such a host went from reported to discarded. That is
        the MIN_BYTES=64KB blindness a second time -- blind to the one payload
        class this module exists for -- grown inside that bug's own fix, on the
        ungated side of a root cause ROADMAP 2026-08-02 had already written down.

        Defaults True: a caller that does not know the lineage keeps the old
        behaviour, because a baseline that silently stops being seeded is a
        change in the other direction. sentinel passes the cached `_agent_for`
        verdict. See tests/test_novelty_gate.py.
        """
        # `_active or _proxy`, not `_active` alone. The proxy invariant in
        # _verdict() is explicitly the one check a declaration cannot argue
        # with -- and until 2026-08-07 it was unreachable unless a
        # declaration file existed AND had been touched within FRESH_SEC.
        # A structural invariant gated on the channel it is independent of.
        # See tests/test_proxy_invariant_active.py.
        if (not self._active and not self._proxy) or nbytes <= 0:
            return
        now = time.time() if now is None else now
        rec = self._pending.get((pid, dest))
        if rec is None or now - rec[2] > self.WINDOW_SEC:
            # Novelty is frozen HERE, at first sight, and only then is the
            # destination recorded. Deciding it later in drain() would always
            # read "seen", because this very observation is what recorded it.
            novel = self._is_novel(dest, now)
            # port/proto ride along so the proxy invariant can tell "could not
            # have been proxied" from "chose not to be" -- see _unproxyable.
            self._pending[(pid, dest)] = [now, nbytes, now, name, novel,
                                          port, proto]
        else:
            rec[1] += nbytes
            rec[2] = now
            if name:
                rec[3] = name
        if is_agent:
            self._seen_dests[dest] = now

    def drain(self, now=None, ancestors=proctree.ancestors):
        """[(pid, name, dest, bytes, note), ...] for every SETTLED unexplained flow.

        Deliberately independent of which processes are active in the current
        tick. The first version consulted this only for pids that had a positive
        byte delta in the tick being processed, which meant a flow that burst
        once and went quiet could never be reported: the settle delay guarantees
        the verdict happens on a later tick, and by then the pid was gone from
        that tick's aggregate. That is exactly the exfil shape (one burst, then
        silence), and it was a silent drop -- same class as the first-observation
        accounting bug of 2026-07-27. Caught by an end-to-end check, not by the
        unit tests, which called this directly.
        """
        # Same widening as observe(): under proxy mode the structural
        # verdict must still be reachable with no declaration channel.
        if not self._active and not self._proxy:
            return []
        now = time.time() if now is None else now
        out = []
        for (p, dest), rec in sorted(self._pending.items(),
                                     key=lambda kv: kv[1][0]):
            first, total, _last, name, novel = rec[:5]
            rport, rproto = (rec[5], rec[6]) if len(rec) > 6 else (None, None)
            if now - first < self.SETTLE_SEC:
                continue
            # Conditional floor. Under proxy mode there is NO floor at all: the
            # invariant being tested is structural (this socket should not
            # exist), and its volume is beside the point.
            floor = 0 if self._proxy else (
                self.NOVEL_MIN_BYTES if novel else self.KNOWN_MIN_BYTES)
            if total < floor:
                continue
            if now - self._reported.get((p, dest), 0) < self.WINDOW_SEC:
                continue
            verdict = self._verdict(p, dest, first, total, novel,
                                    ancestors=ancestors,
                                    port=rport, proto=rproto)
            if verdict is None:
                continue
            self._reported[(p, dest)] = now
            out.append((p, name, dest, total, verdict))
        return out

    def unexplained(self, pid, now=None, ancestors=proctree.ancestors):
        """Single-pid convenience wrapper over drain(). Kept for direct tests."""
        for p, _name, dest, total, note in self.drain(now, ancestors=ancestors):
            if p == pid:
                return dest, total, note
        return None

    def _verdict(self, p, dest, first, total, novel=False,
                 ancestors=proctree.ancestors, port=None, proto=None):
        """The note to report for one settled observation, or None if explained."""
        # (1) PROXY INVARIANT FIRST -- imported from the mitm-audit design, and
        # the only verdict here a declaration cannot argue with. If a proxy is
        # configured, agent-lineage traffic is supposed to be indistinguishable
        # from loopback traffic, and loopback never reaches this function. So
        # reaching it at all IS the finding. Checked before declarations on
        # purpose: this is the one place where "but it was declared" is not a
        # defence.
        # Structural exclusion, added the same day the flood was created. Closing
        # the FRESH_SEC gate made this invariant reachable for the first time, and
        # reachable meant it fired on every DNS and NTP query on the machine.
        #
        # The first write-up of that said it COULD NOT be filtered because the
        # port is stripped upstream. That was wrong and gave up too early: the
        # flow key carries nettop's own connection column, which has the remote
        # port and the protocol. Nothing was lost -- nobody had passed it on.
        # See sentinel._remote_port_proto and tests/test_structural_bypass.py.
        if (self._proxy and _host(dest) != self._proxy
                and not _unproxyable(port, proto)):
            return (f"proxy is configured ({self._proxy}) but this left the "
                    f"agent tree directly -- a declaration cannot exempt this")

        # No declaration channel -> nothing to reconcile against. Emitting
        # "no declared activity" here would turn a silent detector into a flood
        # the moment a proxy is configured, including for traffic that correctly
        # WENT to the proxy. Under proxy-without-declarations the structural
        # verdict above is the only thing this function may say.
        if not self._active:
            return None

        hits = self._matches(p, dest, first, ancestors=ancestors)
        novel_note = "first-time destination; " if novel else ""
        if not hits:
            return f"{novel_note}no declared activity"

        # (2) A target-less declaration used to return None here, i.e. it
        # silenced the pid in total SILENCE. That made the documented "wildcard
        # defeat" an invisible off-switch: a single `declare("bash")` and the
        # reconciler went quiet with no trace that it had been muted. Now it is
        # still not an accusation, but it is SAID. Downgrade, do not disappear.
        if all(h[3] is None for h in hits):
            if novel:
                return ("explained only by a declaration with no target "
                        "(wildcard), and this destination is a first-time one")
            return None      # known destination + wildcard -> genuinely quiet

        # (3) Declared volume is CONTEXT, never a gate on its own. If ANY
        # matching declaration omitted `bytes`, the declared total is unknown
        # and no excess can be computed: silence beats a number we made up.
        if any(nb is None for _t, _p, _tool, _h, nb in hits):
            return None
        declared = sum(nb for _t, _p, _tool, _h, nb in hits)
        if total > declared * self.EXCESS_FACTOR \
                and total - declared > self.EXCESS_MIN_BYTES:
            tool, host = hits[-1][2], hits[-1][3]
            return (f"{len(hits)} declaration(s) totalling "
                    f"~{declared / 1024:.0f} KB (latest {tool}"
                    f"{' to ' + host if host else ''})")
        return None

    def gc(self, now=None):
        now = time.time() if now is None else now
        for store in (self._pending, self._reported):
            for k in [k for k, v in store.items()
                      if now - (v[2] if isinstance(v, list) else v)
                      > self.WINDOW_SEC * 2]:
                del store[k]
        # The novelty baseline decays: a host contacted once a year ago should
        # not be permanently legitimate. Kept separate from the pending TTL
        # because it is a much longer horizon by design.
        for d in [d for d, ts in self._seen_dests.items()
                  if now - ts > self.SEEN_TTL]:
            del self._seen_dests[d]
