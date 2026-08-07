#!/usr/bin/env python3
"""
Offline pcap replay: proves the post-quantum ClientHello blind spot instead of
citing it, and gives the SNI path a dataset-shaped test surface.

Why this exists. ROADMAP records that X25519MLKEM768 pushes a ClientHello past the
MTU, so the SNI lands in a continuation TCP segment. The sniffer's BPF filter
selects segments whose FIRST payload byte is 0x16, so a continuation segment is
dropped and its SNI never observed. That claim was a citation; this makes it a
measured, reproducible fact on this machine.

Two synthetic flows in one capture:
  A. single-segment ClientHello, SNI = single-segment.example   -> MUST be found
  B. ClientHello split over two segments, SNI in segment 2,
     SNI = fragmented-pq.example                                -> currently MISSED

`tcpdump -r` needs no BPF access, so this runs without sudo. The same mechanism
lets the sniffer be pointed at any public pcap: SENTINEL_PCAP=file python3
sni_sniffer.py

Run:  python3 tests/test_pcap_replay.py
"""
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


# --- minimal pcap / Ethernet / IPv4 / TCP writer (stdlib only) -----------
def _ipv4(src, dst, payload, ident):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0,
                      64, 6, 0, bytes(int(x) for x in src.split(".")),
                      bytes(int(x) for x in dst.split(".")))
    chk, s = 0, sum(struct.unpack("!10H", hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    chk = ~s & 0xFFFF
    return hdr[:10] + struct.pack("!H", chk) + hdr[12:] + payload


def _tcp(sport, dport, seq, payload):
    # data offset 5 (20 bytes), flags ACK|PSH, no checksum (tcpdump doesn't verify)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 0x50, 0x18,
                       8192, 0, 0) + payload


def _eth(payload):
    return b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00" + payload


def _client_hello(sni: bytes, pad: int = 0):
    """A STRUCTURALLY VALID TLS ClientHello carrying a server_name extension.

    It has to be valid now: the sniffer parses the ClientHello byte structure to
    the server_name extension instead of grepping tcpdump's ASCII rendering, so a
    hand-waved filler record is (correctly) rejected. That stricter fixture is the
    point -- the earlier version passed only because any hostname-shaped ASCII
    counted.

    `pad` is a padding extension emitted BEFORE server_name, standing in for a
    post-quantum key_share. That ordering is what pushes the SNI past the MTU; a
    stack that emits server_name first keeps its SNI in segment 1 and stays
    visible even without reassembly.
    """
    sni_ext_body = (struct.pack("!H", 3 + len(sni)) + b"\x00"
                    + struct.pack("!H", len(sni)) + sni)
    exts = b""
    if pad:
        exts += struct.pack("!HH", 0x0015, pad) + b"K" * pad      # padding ext
    exts += struct.pack("!HH", 0x0000, len(sni_ext_body)) + sni_ext_body
    body = (b"\x03\x03" + b"\xAA" * 32                           # version, random
            + b"\x20" + b"\xBB" * 32                             # session_id
            + struct.pack("!H", 2) + b"\x13\x01"                 # cipher_suites
            + b"\x01\x00"                                        # compression
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, raw in enumerate(packets):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(raw), len(raw)))
            f.write(raw)


SNI_OK = b"single-segment.example"
SNI_FRAG = b"fragmented-pq.example"


def _server_cert_record():
    """A handshake record that is NOT a ClientHello: handshake type 0x0b
    (Certificate), carrying the SAN list and CA URLs a real certificate embeds.
    Replaying public Wireshark captures showed these being logged as if the
    client had contacted them -- one example.com connection produced 33 records
    including crl3/crl4/cacerts.digicert.com. The filter must now drop this."""
    body = (b"\x0b\x00\x00\x00"
            b"cert-san-one.example cert-san-two.example "
            b"crl3.ca-infra.example cacerts.ca-infra.example")
    return b"\x16\x03\x03" + struct.pack("!H", len(body)) + body


# A: whole ClientHello (with SNI) in one segment starting with 0x16
pkt_a = _eth(_ipv4("10.0.0.5", "198.51.100.10",
                   _tcp(50001, 443, 1000, _client_hello(SNI_OK)), 1))
# C: a server Certificate record on the SAME destination IP as A. If it is parsed,
#    most-recent-wins makes 'crl3.ca-infra.example' the label for 198.51.100.10.
pkt_c = _eth(_ipv4("198.51.100.10", "10.0.0.5",
                   _tcp(443, 50001, 5000, _server_cert_record()), 4))
# B: PQ-sized ClientHello split in two. Segment 1 starts with 0x16 but carries
#    only the key-share padding; segment 2 carries the SNI and does NOT start
#    with 0x16, so the per-segment BPF filter drops it.
big = _client_hello(SNI_FRAG, pad=1600)
cut = 1400                                        # ~MTU
seg1, seg2 = big[:cut], big[cut:]
assert SNI_FRAG not in seg1 and SNI_FRAG in seg2, "fixture must put SNI in seg 2"
pkt_b1 = _eth(_ipv4("10.0.0.5", "198.51.100.20",
                    _tcp(50002, 443, 2000, seg1), 2))
pkt_b2 = _eth(_ipv4("10.0.0.5", "198.51.100.20",
                    _tcp(50002, 443, 2000 + len(seg1), seg2), 3))

cap = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False).name
write_pcap(cap, [pkt_a, pkt_b1, pkt_b2, pkt_c])

# --- replay through the REAL sniffer, writing to a temp sni log -----------
out = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name
env = dict(os.environ, SENTINEL_PCAP=cap)
root = pathlib.Path(__file__).resolve().parent.parent
driver = f"""
import os, pathlib, sys
sys.path.insert(0, {str(root)!r})
import paths
paths.SNI_FILE = pathlib.Path({out!r})
import sni_sniffer
sni_sniffer.SNI_FILE = pathlib.Path({out!r})
sni_sniffer.run_sniffer()
"""
r = subprocess.run([sys.executable, "-c", driver], env=env,
                   capture_output=True, text=True, timeout=60)
log = pathlib.Path(out).read_text() if pathlib.Path(out).exists() else ""

check(r.returncode == 0, f"offline replay ran (rc={r.returncode})")
check(SNI_OK.decode() in log,
      "single-segment ClientHello: SNI extracted from a pcap (offline path works)")
check("198.51.100.10" in log,
      "destination IP joined to that SNI (the IP->domain key the app needs)")
check(SNI_FRAG.decode() in log,
      "FRAGMENTED ClientHello: SNI RECOVERED by stream reassembly (was the "
      "measured PQ blind spot; see tlsparse.StreamAssembler)")
check("ca-infra.example" not in log,
      "server Certificate record is NOT harvested (no CA-URL false labels)")
check("cert-san-one.example" not in log,
      "certificate SAN entries are NOT logged as client destinations")
check(log.count("single-segment.example") == 1,
      "exactly one record per ClientHello, from the parsed server_name extension")

for p in (cap, out):
    try:
        os.unlink(p)
    except OSError:
        pass


def test_pcap_replay():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
