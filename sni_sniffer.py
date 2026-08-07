#!/usr/bin/env python3
"""
SNI sniffer - turns connections into human-readable domains WITHOUT decryption,
by reading the cleartext Server Name from the TLS ClientHello.

Stores (time, dest_ip, domain) so sentinel.py can join by the REAL foreign IP a
process holds (from lsof), instead of guessing by time window. That join is the
difference between "cursor sent 6MB to cdn.xxx" (wrong - that was Chrome) and a
correct accusation. Accuracy is the whole product.

Run standalone as root:  sudo python3 sni_sniffer.py

Honest limits (keep in README):
  - Needs sudo/BPF. The ONE trust-ask; far smaller than a root CA (metadata,
    never payload). Open source, ~100 lines.
  - SNI is cleartext TODAY; Encrypted Client Hello (ECH) will hide it. Rare in
    2026, but this approach has a shelf life.
  - macOS tcpdump may not support '-i any' -> INTERFACE is configurable
    (try en0, or pktap). ServerHello is also 0x16, so cert-chain CA names
    (digicert etc.) can appear; de-dup + the IP-join filter most of it out.
"""

import json
import os
import re
import subprocess
import time

from paths import SNI_FILE, chown_to_invoking_user
from tlsparse import iter_packets, StreamAssembler
import deadman

INTERFACE = os.environ.get("SENTINEL_IFACE", "en0")  # macOS often rejects 'any'
PCAP = os.environ.get("SENTINEL_PCAP", "")           # offline replay (no sudo needed)
MAX_BYTES = 5 * 1024 * 1024   # rotate: this file is a plaintext domain log, cap it

# NOTE: sni.jsonl contains the domains of EVERY TLS connection on this machine
# while the sniffer runs (browser, mail, bank included), not just agents. It is
# chmod 0600 and size-capped, but it IS a local plaintext browsing record - the
# README says so. A future version should filter to agent-held IPs only.

_FILTER_HELLO = ("tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x16) "
                 "and (tcp[((tcp[12:1] & 0xf0) >> 2) + 5] = 0x01)")
#   Byte 0 of the record payload = 0x16 (handshake); byte 5 = handshake type 0x01
#   (ClientHello). The second clause was added 2026-07-27 after replaying public
#   Wireshark captures: filtering on 0x16 alone also matched ServerHello and
#   Certificate records, and one connection to example.com then produced 33
#   records including the cert's SAN list and the CA's own URLs
#   (crl3/crl4/cacerts.digicert.com). Since domain_for_ip is most-recent-wins per
#   IP, a later flow to that IP was being labelled `crl4.digicert.com` -- a wrong
#   accusation, measured. See tests/test_pcap_replay.py.

_FILTER_ALL_OUT = "tcp dst port 443"
#   REASSEMBLY MODE (SENTINEL_REASSEMBLE=1). A post-quantum ClientHello can exceed
#   the MTU; if the stack emits its large key_share before server_name, the SNI
#   lands in a continuation segment whose first byte is not 0x16, which the filter
#   above drops. Catching it means capturing every outbound 443 segment and
#   reassembling per stream -- and that is why this is OPT-IN, not the default:
#   BPF cannot express "the next segment of this stream", so there is no cheap
#   filter. A bulk upload's segments start with arbitrary ciphertext, so no
#   first-byte test excludes them. Cost is therefore proportional to ALL outbound
#   443 traffic, hex-dumped. Measured text amplification of `-x` on three public
#   captures: 3.1-3.4x the capture size (theory: 50 text bytes per 16 packet
#   bytes = 3.12x), so a 6 MB/s upload becomes ~19 MB/s of text through the pipe.
#   StreamAssembler retires a stream as soon as its first record is complete, so
#   memory is bounded -- the tcpdump output volume is not. Measure on your own
#   uplink before enabling this on a busy machine.
REASSEMBLE = os.environ.get("SENTINEL_REASSEMBLE", "") not in ("", "0")

# LIVE capture goes through tcpdump; OFFLINE replay does not (changed 2026-08-06).
# `-x` gives the packet bytes from the IP header on, so the SNI is parsed from the
# actual ClientHello structure instead of grepping tcpdump's ASCII rendering.
TCPDUMP = (["tcpdump", "-i", INTERFACE, "-s", "0", "-l", "-n", "-x"]
           + [_FILTER_ALL_OUT if REASSEMBLE else _FILTER_HELLO])
#
# Offline replay used `tcpdump -r`, which made the one path that needs no BPF, no
# sudo and no network still require a capture binary -- so the pure byte parsing
# this module is built on could only be tested where tcpdump exists, and a
# `pktmon` capture on Windows had nowhere to go. pcapreader reads the container
# directly and yields the same tuples. No BPF filter applies offline, so every
# packet arrives and the `dport != 443` test plus StreamAssembler do the
# selecting -- which is also what the reassembly path does live.
# Offline always reassembles: cost is irrelevant on a finite file.


def _packet_source():
    """(process_or_None, iterator of (src, sport, dst, dport, payload))."""
    if PCAP:
        import pcapreader
        return None, pcapreader.iter_packets(PCAP)
    proc = subprocess.Popen(TCPDUMP, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    return proc, iter_packets(proc.stdout)

# The ASCII hostname regex that used to live here is gone: replaying public
# captures showed it emitting certificate SANs, CA URLs and junk like '9g.nc'
# (2 of 6 extracted records). tlsparse.parse_client_hello_sni reads the
# server_name extension bytes instead. Header/hostname parsing now lives there.


def run_sniffer():
    # 0600: this is a plaintext domain log; don't leave it world/group readable.
    try:
        SNI_FILE.touch(mode=0o600, exist_ok=True)
        os.chmod(SNI_FILE, 0o600)
        chown_to_invoking_user(SNI_FILE)   # P0-A: keep readable by user-mode app
    except OSError:
        pass
    _proc, packets = _packet_source()
    asm = StreamAssembler()
    last_watch = 0.0
    for src, sport, dst, dport, payload in packets:
        # --- dead-man check (see deadman.py) -------------------------------
        # We run under sudo; the menu-bar app runs as the user. So we are the one
        # process a user-level agent cannot kill, which makes us the only sensible
        # place to notice that the app stopped. Reported loudly to stdout AND the
        # log, because the app's own UI is exactly what may be gone.
        now_w = time.time()
        if now_w - last_watch > 10:
            last_watch = now_w
            stale = deadman.stale_for(now_w)
            if stale:
                msg = (f"ALERT sentinel heartbeat stale for {stale:.0f}s -- the "
                       f"menu-bar app is not running (killed, crashed, or quit). "
                       f"Egress is NOT being classified right now.")
                print(msg, flush=True)
                try:
                    with (SNI_FILE.parent / "sentinel.log").open("a") as f:
                        f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')}  {msg}\n")
                except OSError:
                    pass
        # size-cap rotation: keep the tail, drop the head.
        try:
            if SNI_FILE.stat().st_size > MAX_BYTES:
                tail = SNI_FILE.read_text().splitlines()[-2000:]
                SNI_FILE.write_text("\n".join(tail) + "\n")
                os.chmod(SNI_FILE, 0o600)
                chown_to_invoking_user(SNI_FILE)   # write_text recreates -> re-chown
        except OSError:
            pass
        if dport != 443:                  # client -> server only
            continue
        hit = asm.feed((src, sport, dst, dport), payload)
        if not hit:
            continue
        host, ip = hit
        # One record per ClientHello, from the parsed server_name extension --
        # not from a regex over tcpdump's ASCII rendering. That grep produced
        # certificate SANs, CA URLs and junk like '9g.nc' (measured on public
        # captures); a byte offset either holds a hostname or it does not.
        rec = {"t": time.time(), "ip": ip, "domain": host}
        with SNI_FILE.open("a") as out:
            out.write(json.dumps(rec) + "\n")


class SNICache:
    """
    Resolves a foreign IP (from a measured flow) to a domain.
    HONEST CAVEAT: this is still a heuristic, not ground truth. A shared front
    IP (Cloudflare/GCP) hosts many domains, so 'most-recent SNI for this IP'
    can mislabel. Keyed on (ip, recency), not pure time-window, but it is not
    authoritative - alerts should read as 'likely', and content-layer proof is
    a paid-tier concern. Window kept short to reduce cross-domain bleed.
    """
    def __init__(self, window_sec: int = 60, path=None):
        self.window = window_sec
        self.path = path or SNI_FILE   # injectable so tests never touch the real log
        self._perm_warned = False

    def _recent(self):
        if not self.path.exists():
            return []
        cutoff = time.time() - self.window
        rows = []
        try:
            # seek-to-tail: read only the last chunk, not the whole file
            size = self.path.stat().st_size
            with self.path.open("rb") as f:
                if size > 262144:
                    f.seek(-262144, 2)
                    f.readline()              # drop partial line
                chunk = f.read().decode("utf-8", "ignore")
            for line in chunk.splitlines():
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if r.get("t", 0) >= cutoff:
                    rows.append(r)
        except PermissionError:
            # P0-A guard: sni.jsonl unreadable (root-owned) means the RED path is
            # silently dead. Do NOT swallow -- surface it loudly, once.
            if not self._perm_warned:
                self._perm_warned = True
                import sys
                sys.stderr.write(
                    f"[sentinel] FATAL: cannot read {self.path} (PermissionError) "
                    "-> domain resolution disabled, red alerts will NEVER fire. "
                    "Run the sniffer with `sudo -E` so it chowns the file back.\n")
                try:
                    from paths import LOG
                    with LOG.open("a") as lf:
                        lf.write(f"FATAL sni.jsonl PermissionError -> red path dead\n")
                except Exception:
                    pass
            return []
        except Exception:
            return []
        return rows

    def domain_for_ip(self, ip: str):
        # most-recent SNI seen for that dest IP
        for r in reversed(self._recent()):
            if r.get("ip") == ip and r.get("domain"):
                return r["domain"]
        return None


if __name__ == "__main__":
    print(f"[sni] iface={INTERFACE}  ->  {SNI_FILE}  (Ctrl-C to stop)")
    print("[sni] metadata only - no payload, no decryption")
    run_sniffer()
