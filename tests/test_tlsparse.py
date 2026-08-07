#!/usr/bin/env python3
"""
Byte-accurate SNI parsing + TCP reassembly (tlsparse).

Replaces an ASCII regex that, measured on public Wireshark captures, produced
certificate SAN entries, CA infrastructure URLs, and junk hostnames (`9g.nc`,
`ft3.oq` -- 2 of 6 extracted records). A byte offset either holds a hostname or
it does not, so the noise goes to zero rather than being filtered down.

Run:  python3 tests/test_tlsparse.py
"""
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tlsparse import (parse_client_hello_sni, StreamAssembler,   # noqa: E402
                      iter_packets, MAX_STREAM_BUF)

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


def hello(sni=b"api.anthropic.com", pad=0, with_sni=True):
    exts = b""
    if pad:
        exts += struct.pack("!HH", 0x0015, pad) + b"K" * pad
    if with_sni:
        b = struct.pack("!H", 3 + len(sni)) + b"\x00" + struct.pack("!H", len(sni)) + sni
        exts += struct.pack("!HH", 0x0000, len(b)) + b
    body = (b"\x03\x03" + b"\xAA" * 32 + b"\x20" + b"\xBB" * 32
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


# --- parse_client_hello_sni ---------------------------------------------
check(parse_client_hello_sni(hello()) == "api.anthropic.com",
      "server_name extension parsed from a valid ClientHello")
check(parse_client_hello_sni(hello(pad=2000)) == "api.anthropic.com",
      "server_name found after a large preceding extension (PQ key_share shape)")
check(parse_client_hello_sni(hello(with_sni=False)) is None,
      "ClientHello without server_name yields None, not a guess")
check(parse_client_hello_sni(hello()[:40]) is None,
      "truncated record yields None (caller keeps buffering)")

# a ServerHello / Certificate record must never yield a hostname
cert = b"\x16\x03\x03" + struct.pack("!H", 40) + b"\x0b" + b"\x00" * 3 \
    + b"crl3.digicert.com cacerts.digicert.com"[:36]
check(parse_client_hello_sni(cert) is None,
      "Certificate record (handshake type 0x0b) yields None -- no CA-URL labels")

# the exact junk the ASCII grep used to emit must be impossible now
junk = b"\x16\x03\x01" + struct.pack("!H", 20) + b"\x01" + b"\x00" * 3 + b"9g.nc ft3.oq   "
check(parse_client_hello_sni(junk) is None,
      "random bytes that look like hostnames ('9g.nc') cannot be returned")

# robustness: malformed input must never raise (a crash here kills the sniffer)
raised = None
for bad in (b"", b"\x16", b"\x16\x03\x01\xff\xff", b"\x16\x03\x01\x00\x05\x01\xff\xff\xff\xff",
            bytes(range(256)), b"\x16\x03\x01" + b"\xff" * 200):
    try:
        parse_client_hello_sni(bad)
    except Exception as e:                                    # noqa: BLE001
        raised = f"{type(e).__name__}: {e}"
check(raised is None, f"malformed input never raises (got {raised})")

# --- StreamAssembler ----------------------------------------------------
KEY = ("10.0.0.5", 5001, "198.51.100.9", 443)
asm = StreamAssembler()
whole = hello(b"single.example")
check(asm.feed(KEY, whole) == ("single.example", "198.51.100.9"),
      "single-segment ClientHello resolves immediately")
check(asm.feed(KEY, whole) is None,
      "a retired stream does not emit twice for the same handshake")

asm2 = StreamAssembler()
frag = hello(b"fragmented.example", pad=2000)
K2 = ("10.0.0.5", 5002, "198.51.100.9", 443)
check(asm2.feed(K2, frag[:1400]) is None,
      "first segment alone yields nothing (SNI is past the MTU)")
check(asm2.feed(K2, frag[1400:]) == ("fragmented.example", "198.51.100.9"),
      "second segment completes the record -> SNI recovered (the PQ fix)")

asm3 = StreamAssembler()
K3 = ("10.0.0.5", 5003, "198.51.100.9", 443)
asm3.feed(K3, b"\x17\x03\x03" + b"\x00" * 50)          # application_data
check(K3 in asm3._done and K3 not in asm3._buf,
      "a non-handshake stream is retired at once (bulk upload isn't buffered)")

asm4 = StreamAssembler()
K4 = ("10.0.0.5", 5004, "198.51.100.9", 443)
asm4.feed(K4, b"\x16\x03\x01\xff\xff" + b"K" * (MAX_STREAM_BUF + 10))
check(K4 not in asm4._buf, "buffer cap retires a stream that never completes")

# --- iter_packets (tcpdump -x reconstruction) ---------------------------
ip = bytes([0x45, 0, 0, 44]) + b"\x00" * 5 + b"\x06" + b"\x00\x00" \
    + bytes([10, 0, 0, 5]) + bytes([198, 51, 100, 9])
tcp = struct.pack("!HHIIBBHHH", 5005, 443, 1, 1, 0x50, 0x18, 8192, 0, 0) + b"HI"
raw = ip + tcp
lines = ["10.0.0.5.5005 > 198.51.100.9.443: Flags [P.]"] + [
    "\t0x%04x:  %s" % (i, raw[i:i + 16].hex()) for i in range(0, len(raw), 16)]
pkts = list(iter_packets(lines + ["\n"]))
check(len(pkts) == 1 and pkts[0][:4] == ("10.0.0.5", 5005, "198.51.100.9", 443)
      and pkts[0][4] == b"HI",
      "tcpdump -x hex is reassembled into (src,sport,dst,dport,payload)")


def test_tlsparse():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
