# PLATFORMS

_2026-08-06. What runs where, and what a Windows port actually costs._

The short version: **the logic is portable and now runs on Windows; the capture
layer is the entire job.** Everything this tool concludes is derived from two
measurements — per-process per-flow byte counts, and destination hostnames — and
both come from macOS-specific tools. Nothing above them cares what OS it is on.

---

## 1. Status

| Layer | macOS | Windows | Notes |
|---|---|---|---|
| Allowlist / classification (`endpoints.py`) | ✅ | ✅ | pure |
| Capacity ledger, fan-out (`ledger.py`) | ✅ | ✅ | pure |
| TLS ClientHello parsing (`tlsparse.py`) | ✅ | ✅ | pure |
| Reconciler (`activity.py`, `declare.py`) | ✅ | ✅ | pure once `paths.py` stopped importing `pwd` |
| Process ancestry (`proctree.py`) | ✅ libproc | ✅ Toolhelp32 | see §4 for the one behavioural difference |
| Claude Code hook (`hooks/`) | ✅ | ✅ | verified end-to-end: walks `python → bash×3 → claude.exe` and declares the agent's pid |
| Dead-man heartbeat (`deadman.py`) | ✅ | ✅ | needs `proc_start`, which the Windows backend supplies |
| Capture-file reading (`pcapreader.py`) | ✅ | ✅ | pcap + pcapng, pure Python, no `tcpdump` |
| Offline replay (`SENTINEL_PCAP=`) | ✅ | ✅ | runs anywhere as of 2026-08-06 |
| **Per-flow byte counts** | ✅ `nettop` | ✅ `wincapture.py` | live-verified 2026-08-06; one bug found and fixed — §5 |
| **Live hostname capture** | ✅ `tcpdump` SNI | ❌ | still the gap — §5 step 2 |
| Menu bar / tray UI | ✅ `rumps` | ❌ | `pystray` is the equivalent; small |

Test suite on Windows: **19 of 19 files green, 268 assertions.** It was 3 of 13
this morning — ten of those failures were one `import pwd` in `paths.py`, and the
last was `tcpdump -r` on the offline path.

---

## 2. What the port is not

It is not a rewrite. `sentinel.py` consumes `parse_flows()` output — a dict keyed
by `(process_name, pid, remote_ip)` with byte counters — and `SNICache` maps IP →
domain. Anything that can fill those two structures inherits the whole stack:
ledger, fan-out, ancestry attribution, reconciliation, alert text, and their
tests. **The interface to hit is two functions wide.**

---

## 3. The capture layer on Windows

### Byte counts — ETW, and it is better than what macOS has

There is no `nettop`. What exists, verified present on this machine via
`logman query providers`:

```
Microsoft-Windows-Kernel-Network   {7DD42A49-5329-4832-8DFD-43D979153A88}
Microsoft-Windows-TCPIP            {2F07E2EE-15DB-40F1-90EF-9D7BA282188A}
Microsoft-Windows-Winsock-AFD      {E53C6823-7BB8-44BB-90DC-3F86090D48A6}
```

**Measured 2026-08-06** (`tools/etw_probe.py`, 30 s runs, one Windows 11 desktop,
whole machine, all keywords at level 4). Three runs:

| | |
|---|---|
| events | 26,114 · 26,970 · 5,113 in 30 s → **170–900/s** |
| carrying pid + size + remote address | **98.1–100.0%** |
| ETL growth | **2.1–7.2 MB/min** |
| fields on every complete event | `PID` `size` `daddr` `saddr` `dport` `sport` `seqnum` `connid` |
| on a subset | `startime` `endtime` · `mss` `sackopt` `tsopt` `wsopt` `rcvwin` |

**The rate is a range, not a number, and the spread is 5x.** The third run made
*more* connections (301 vs 220) and produced *one fifth* the events. Background
traffic on the machine dominates the event count, so a single 30 s sample is not
a cost estimate — this table replaced a confident "870/s" taken from run one.

So **Q1 is YES, decisively**: one event carries pid, byte count and remote
address together — no join required, which is the thing that would have made
this a different and harder design. Three further observations that matter for a
consumer:

- **`connid` exists and is useless.** Present on 98% of events and **constant at
  0** across two 30 s runs. It is named like a connection identifier and is not
  one. Do not key a consumer on it; use the 4-tuple. (This cost a wrong verdict —
  see the box below.)
- **`startime`/`endtime` appear on a subset** — connection lifecycle events, not
  just data transfers. `L` would come out of the source instead of being
  controlled experimentally.
- **UDP is included.** The sample event was `dport 53` over IPv6, i.e. DNS. The
  macOS build sees TCP byte counts and reads hostnames from TLS SNI; this source
  covers name resolution in the same stream. It also means **`size` is sometimes
  0**, so a `delta <= 0` guard would discard those rows — the same shape as the
  zero-byte discard already measured on the macOS path.

Consuming it needs admin (`OpenTrace`/`ProcessTrace` via ctypes, or the
`pywintrace` package) — the same shape of trust-ask as the one `sudo` on macOS,
and the README's argument for that ask transfers unchanged.

Cost caveat, stated so it is not read as better than it is: 7.2 MB/min is the
**ETL**, and `tracerpt` expanded that to 39.5 MB of XML (~11x). Neither number is
what a real-time consumer would pay — it would never write an ETL or decode to
XML — but ~870 events/s is a real rate to process, and no CPU measurement of an
actual consumer exists yet.

**And this is the interesting part, now measured (see the box below).** ETW is
*event-driven*. macOS forced sampling (`nettop -s 1`), and sampling is where this
project's headline number comes from:

> recall ≈ `min(1, L/T)` in the per-connection lifetime `L`. Measured 5.8% at
> L≈50 ms, 100% at L≥1 s, with T pinned at the shipped 1 s.

**On an event source that bound does not exist.** Every flow is reported whether
it lived 50 ms or an hour, and byte counts arrive as deltas rather than
differences of a sampled cumulative — which also means the entire bug class
behind "Wrong #2" and "Wrong #3" (first-sighting suppression, 94.2% of new-flow
bytes discarded) is structurally absent, not fixed.

So the correct claim is narrower and more interesting than "this tool has 5.8%
recall against fast fan-out": **that number is a property of the observation
tooling available on macOS without a NetworkExtension, not of metadata-layer
observation.** The ROADMAP already lists flow events (eBPF / NetworkExtension) as
the v1 fix for exactly this, and on Windows that tier turns out to be reachable
without a kernel driver or a signed system extension — measured, not assumed.

This is the one finding here that is worth writing up independently of whether
the port ever ships: **a recall limit that was published as a property of the
approach is a property of one platform's tooling.** It took a 30-second probe on
a second OS to see it, and three tries to measure it correctly.

> **✅ Q3 ANSWERED 2026-08-06: 361 connections observed / 301 made = 120%.**
> Event-driven confirmed. Short connections are not being dropped, so
> `min(1, L/T)` does not bound this source and the claim above holds.
>
> Read it as a **floor test that passes comfortably**, not as an exact recall
> figure. The excess over 100% is DNS lookups and redirects, which are also
> connections. What it does *not* do is match the client's actual ephemeral ports
> against the observed set, so "we saw 361 tuples" does not strictly prove all
> 301 of ours were among them. An exact version would record the local port of
> every request and intersect. The result is strong — a source that dropped
> short connections would come in *under* 301, not over — but it is a bound, not
> an identity.
>
> **THREE MEASURES GOT HERE. TWO WERE WRONG, BOTH MINE.**
>
> **v1 — false positive.** Asked "did the probe's destinations appear?" and
> answered **YES on 3 distinct remotes out of 210 connections**: ~70 hits each.
> A sampler would have found all three too. The test was never in the regime
> where sampling fails (the macOS sweep used 57 destinations hit once each), so
> it passed for a reason unrelated to what it claimed. That is this project's own
> **Wrong #3** — a run that measured its harness — committed inside the tool
> built to prevent it.
>
> **v2 — false negative, and the more dangerous one.** Keyed on `connid`, which
> the field table above shows on 98% of events. Reported **1 seen / 220 made =
> 0%** and printed *"NOT SUPPORTED, this looks sampled, PLATFORMS.md is wrong,
> do not write code that depends on it."* **`connid` is constant at 0 on this
> provider.** The set had one element because nothing populates the field, not
> because connections were missed — while the same run attributed 2,375,878 bytes
> across 220 HEAD requests (~10.8 KB each, exactly TLS-handshake sized) and
> 26,970 events carrying `seqnum` in 30 s. A degenerate key made "we observed
> nothing" and "we cannot tell the observations apart" print as the same verdict,
> and that verdict would have killed a correct design decision.
>
> **v3 — the standard 4-tuple** `(saddr, sport, daddr, dport)`. The local
> ephemeral port is what actually differs between consecutive short connections.
> Floor test, not equality: DNS lookups and redirects are connections too, so
> >100% is the healthy result. Verified against synthetic traces to separate the
> real shape (225 tuples, connid=1, 3 remotes → 102%) from genuine sampling
> (12 tuples, same connid=1, same 3 remotes → 5%) — the two cases v1 and v2 each
> failed to tell apart. It now also prints the **cardinality of every candidate
> key**, so a degenerate one is visible instead of silently producing confidence.
>
> **The durable lesson, and the only reason this is written up rather than
> quietly fixed: before keying on a field, count its distinct values.** A name
> that sounds like an identifier is not evidence that it is one. Three iterations
> and the failure wore a different hat each time.
>
> v3 ran and returned 120%. Both wrong answers had pointed at the same
> conclusion by luck (v1) or against it by artefact (v2); neither was evidence.

### Hostnames — `pktmon`, built in

`pktmon` ships with Windows 10 1809+ and is present here, with `etl2pcap`. So:

```
pktmon start --capture  →  .etl  →  pktmon etl2pcap  →  .pcapng  →  tlsparse
```

The ClientHello parser needs no changes — it already reads packet bytes and is
already tested against public captures. The reader that gets bytes out of a
pcapng file without `tcpdump` now exists: `pcapreader.py`, §5 step 1, done.
What is left is the loop that drives `pktmon` and hands it the file.

Npcap + `windump` is the alternative and is a closer match to the current design
(streaming, live), at the cost of a third-party driver install — which is the
kind of dependency this tool's whole pitch argues against.

### Tray UI

`pystray` + `Pillow` (already installed here). `sentinel.py` already carries a
no-op shim for when `rumps` is missing, so the seam exists.

---

## 4. One real behavioural difference, already handled

**Windows does not reparent orphans.** On POSIX a child whose parent dies is
adopted by init and the ancestry walk terminates at pid 1. On Windows the child
keeps its numeric ppid, and once the OS recycles that number the field points at
an unrelated process. An attribution walk that trusts it would credit an agent's
egress to whatever inherited the number — the wrong-accusation failure this tool
exists to refuse.

`proctree._win_proc_info` rejects a claimed parent unless it is **older** than the
child; a recycled pid is necessarily younger. The guard lives in the platform
layer so that `ancestors()` and `attribute()` stay single-sourced — a second copy
of a walk is a second chance to get the termination conditions wrong, and that is
as true across an OS boundary as within one.

**Honest limit:** this guards a documented platform behaviour, not a measured
misattribution. How often the field is actually stale on a live desktop is
unknown here.

---

## 5. Recommended order, cheapest first

1. ~~A pure-Python pcap/pcapng reader.~~ **Done 2026-08-06** — `pcapreader.py`,
   ~230 lines, `tests/test_pcapreader.py` with 25 assertions. `tcpdump` is gone
   from the *offline* path: the suite is 14/14 on Windows, the SNI parser is
   testable anywhere, and the `pktmon` pipeline has something to hand its output
   to. Classic pcap (both byte orders, µs and ns) and pcapng (SHB/IDB/EPB/SPB,
   options present), Ethernet/VLAN/cooked/loopback/raw, IPv4 and IPv6.

   Worth recording: the dedicated test found a real bug the replay test could not.
   `test_pcap_replay` only ever exercises little-endian classic pcap over
   Ethernet over IPv4, because that is what its fixture writes — the pcapng
   section-header skip was off by four bytes and every pcapng file silently
   yielded zero packets. Zero packets from a capture parser is indistinguishable
   from a capture with no TLS in it, which is this repo's recurring failure shape
   in a new place.
2. **A `pktmon` → pcapng → SNI loop.** Batch, not streaming: capture N seconds,
   convert, parse, repeat. Ugly, works, no third-party driver. Gives Windows the
   *hostname* half.
3. **An ETW `Kernel-Network` consumer.** The byte half. **Written 2026-08-06:
   `wincapture.py` + `tests/test_wincapture.py` (29 assertions).** Produces the
   same `{(name, pid, ip): Bytes(out, inb)}` mapping `parse_flows` does.

   **First live run 2026-08-06, 20 s elevated: it works.** Real flows, correct
   attribution — `claude.exe.24320 -> 2600:1901:0:5ae7::` 11,649 bytes out,
   `chrome.exe`, `svchost.exe` — 15 flows, zero dropped, no TcpCopy ids present.

   > **And it was wrong, in a way only a live run could show.** This provider
   > does not use one convention for the remote peer:
   >
   > | | field holding the remote |
   > |---|---|
   > | TCP recv (11, 27) | `daddr` — the connection's remote |
   > | UDP recv (43, 59) | **`saddr`** — `daddr` is the *packet's* destination: this host, or a multicast group |
   >
   > Reading `daddr` throughout produced `claude.exe -> 192.168.1.157` (this
   > machine's own LAN address) and `chrome.exe -> 224.0.0.251` (mDNS). Nonsense
   > destinations — and each multicast group would have counted as a distinct
   > peer in the **per-pid fan-out counter**, the one detector that keys on
   > breadth.
   >
   > Settled by arithmetic on the run's own output, not by reading docs: the
   > per-event-id byte totals close **exactly** on the affected rows
   > (43 = 3488+3488+284+416 = 7,676; 59 = 3411+3488+3488+38 = 10,425 — every
   > address either this host or a multicast group), while 11 = 4678+78 and
   > 27 = 197+28 land on real remotes.
   >
   > That per-event-id breakdown existed only so the TcpCopy exclusion could be
   > checked rather than believed. It caught a different bug than the one it was
   > built for — which is the argument for exposing intermediate counts at all.
   >
   > Also added from the same run: multicast, link-local, broadcast and
   > unspecified addresses are not destinations. Private LAN unicast deliberately
   > still is — an agent uploading to a NAS is egress, and dropping RFC1918 would
   > blind the tool in the direction of "the attacker is already on your network".

   The pure translation — which events count, in which direction, which field
   holds the remote, what is dropped, how deltas become cumulative totals — is
   fully tested (45 assertions). The live session is a dozen lines: if it is
   wrong it yields no events, not wrong numbers, which is why the tests are
   where they are.

   Two more things worth knowing from writing it:

   - **A double-count trap.** Event ids 18 and 34 (`TcpCopy`, receive-side) were
     the two *most frequent* in a real trace. Counting them alongside `Recv`
     roughly doubles every inbound number — and inbound bytes feed no rule
     (authorization is not a function of traffic volume), so nothing downstream
     would have flagged it. Excluded, with per-event-id byte totals exposed so
     the assumption can be checked against a known-size download.
   - **"Wrong #2" cannot recur here.** The macOS path discarded 94.2% of
     new-flow bytes because a flow's first sighting only established a baseline.
     Accumulating from zero makes the first diff the full byte count by
     construction, not by a fix.

   Dependency: `pywintrace` (pure Python, no compiled extension). It is the
   ctypes marshalling for `OpenTrace`/`ProcessTrace`/TDH, already correct.
   Hand-writing `EVENT_TRACE_LOGFILE` was the alternative and a wrong layout
   fails as plausible garbage fields rather than as an error — chosen to avoid a
   silent-wrong-numbers risk, not to save typing.

   The probe below is what gated this and has now been run.

   `tools/etw_probe.py` exists for exactly that. Two minutes in an **elevated**
   prompt, built-in tools only (`logman`, `tracerpt` — no `pywintrace`, no
   driver install):

   ```
   python tools\etw_probe.py
   ```

   It captures, generates its own short-lived connections, decodes, and runs
   `etw_probe_summarize.py` on the result — no pid to copy by hand.

   It was a `.ps1` first, and PowerShell's execution policy refused to load it.
   That is a pointless obstacle in front of a two-minute measurement, and
   `python.exe` invoking `logman` is not subject to that policy, so the
   PowerShell version is gone rather than kept alongside — two implementations of
   one probe means one of them rots, and it would have been the blocked one.

   It answers whether one event really carries pid + bytes + remote address, what
   the event rate and ETL growth are under normal use, and — the one that decides
   the whole thing — whether the deliberately short-lived connections it generates
   show up at all. If they do not, this port inherits the same blind spot as
   sampling and §3's central claim above is wrong; better to learn that in two
   minutes than after a week of consumer code.

   One thing it is careful about, because it is the same failure shape as
   everything else here: **"no traffic was generated" and "traffic was generated
   but the provider did not trace it" both produce Q3 = NO.** The probe counts
   completed connections and says so loudly when that count is zero, rather than
   letting a dead network read as a negative result about ETW.

   Status: the summarizer's four verdict paths are tested against synthetic
   traces, the traffic generator is measured (69 short-lived connections in 8 s
   on this machine), and the non-elevated refusal path works. **The capture
   itself is unrun** — no elevation available here — so treat its first output as
   evidence, not as confirmation of anything written above.
4. **`pystray` tray app.** Cosmetic, last.

Steps 1–3 are where the substance is. Anyone stopping after 1 still gains
something.

---

## 6. Why bother

Under the current framing (see [PRE-FLIGHT.md](PRE-FLIGHT.md)) the largest open
question in this repo is the reconciler's real-machine false-positive rate, and
answering it needs one machine running both an agent and the sentinel. If the
agent lives on Windows, so must the sentinel. The port is not a distribution
play; it is what makes the measurement possible on the machine you actually use.
