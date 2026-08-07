#!/usr/bin/env python3
"""
The capture-file reader (pcapreader.py).

test_pcap_replay exercises exactly one path through this module -- little-endian
classic pcap, Ethernet, IPv4 -- because that is what its fixture writes. Every
other branch (byte order, nanosecond magic, pcapng, VLAN, IPv6, cooked capture,
loopback) is unexercised by it, and a container parser that silently yields zero
packets looks exactly like a capture with no TLS in it. That is this repo's
recurring failure shape: a control that discards is indistinguishable from a
detector that does not work. So each branch gets an assertion that a KNOWN
segment comes back out.

The two negative cases matter as much: a non-first IP fragment carries no TCP
header, and a UDP datagram is not TCP. Both must be dropped rather than parsed
into a plausible-looking tuple with garbage ports.

Run:  python3 tests/test_pcapreader.py
"""
import pathlib
import struct
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import pcapreader                                                    # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        fails.append(msg)


PAY = b"\x16\x03\x01hello-payload"


def tcp(sport=50001, dport=443, payload=PAY):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18,
                       8192, 0, 0) + payload


def ip4(payload, src="10.0.0.5", dst="198.51.100.10", frag=0, proto=6):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, frag,
                       64, proto, 0,
                       bytes(int(x) for x in src.split(".")),
                       bytes(int(x) for x in dst.split("."))) + payload


def ip6(payload, src=b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x05",
        dst=b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x0a", nxt=6):
    return struct.pack("!IHBB", 6 << 28, len(payload), nxt, 64) + src + dst + payload


def eth(payload, etype=0x0800):
    return b"\x11" * 6 + b"\x22" * 6 + struct.pack("!H", etype) + payload


def vlan(payload, etype=0x0800, vid=42):
    return (b"\x11" * 6 + b"\x22" * 6 + struct.pack("!H", 0x8100)
            + struct.pack("!HH", vid, etype) + payload)


def write_pcap(packets, linktype=1, endian="<", nano=False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    p = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    p.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype))
    for i, raw in enumerate(packets):
        p.write(struct.pack(endian + "IIII", 1700000000 + i, 0, len(raw), len(raw)))
        p.write(raw)
    p.close()
    return p.name


def write_pcapng(packets, linktype=1, endian="<"):
    bom = 0x1A2B3C4D
    p = tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False)
    shb = struct.pack(endian + "IIQ", bom, 0x00000001, 0xFFFFFFFFFFFFFFFF)
    p.write(struct.pack(endian + "II", 0x0A0D0D0A, 12 + len(shb)) + shb
            + struct.pack(endian + "I", 12 + len(shb)))
    idb = struct.pack(endian + "HHI", linktype, 0, 65535)
    p.write(struct.pack(endian + "II", 0x00000001, 12 + len(idb)) + idb
            + struct.pack(endian + "I", 12 + len(idb)))
    for raw in packets:
        pad = (-len(raw)) % 4
        body = struct.pack(endian + "IIIII", 0, 0, 0, len(raw), len(raw)) + raw + b"\x00" * pad
        p.write(struct.pack(endian + "II", 0x00000006, 12 + len(body)) + body
                + struct.pack(endian + "I", 12 + len(body)))
    p.close()
    return p.name


def got(path):
    return list(pcapreader.iter_packets(path))


def one(path):
    """The single expected tuple, or None -- so a branch yielding nothing fails."""
    r = got(path)
    return r[0] if len(r) == 1 else None


# --- classic pcap: both byte orders, both timestamp resolutions -----------
for endian, label in (("<", "little-endian"), (">", "big-endian")):
    for nano, res in ((False, "microsecond"), (True, "nanosecond")):
        t = one(write_pcap([eth(ip4(tcp()))], endian=endian, nano=nano))
        check(t == ("10.0.0.5", 50001, "198.51.100.10", 443, PAY),
              f"classic pcap, {label} {res} magic")

# --- pcapng: both byte orders --------------------------------------------
for endian, label in (("<", "little-endian"), (">", "big-endian")):
    t = one(write_pcapng([eth(ip4(tcp()))], endian=endian))
    check(t == ("10.0.0.5", 50001, "198.51.100.10", 443, PAY),
          f"pcapng SHB/IDB/EPB, {label}")

check(len(got(write_pcapng([eth(ip4(tcp())), eth(ip4(tcp(sport=50002)))]))) == 2,
      "pcapng block padding is handled (a second packet still parses)")

# Real pcapng files (what `pktmon etl2pcap` emits) carry OPTIONS after the fixed
# fields of IDB and EPB. The fixtures above have none, so without this the tests
# would only prove the reader handles files the tests themselves write.
_opt = struct.pack("<HH", 2, 4) + b"eth0" + struct.pack("<HH", 0, 0)   # if_name


def write_pcapng_with_options(packets, linktype=1):
    p = tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False)
    shb = struct.pack("<IIQ", 0x1A2B3C4D, 0x00000001, 0xFFFFFFFFFFFFFFFF) + _opt
    p.write(struct.pack("<II", 0x0A0D0D0A, 12 + len(shb)) + shb
            + struct.pack("<I", 12 + len(shb)))
    idb = struct.pack("<HHI", linktype, 0, 65535) + _opt
    p.write(struct.pack("<II", 0x00000001, 12 + len(idb)) + idb
            + struct.pack("<I", 12 + len(idb)))
    for raw in packets:
        pad = (-len(raw)) % 4
        body = (struct.pack("<IIIII", 0, 0, 0, len(raw), len(raw))
                + raw + b"\x00" * pad + _opt)
        p.write(struct.pack("<II", 0x00000006, 12 + len(body)) + body
                + struct.pack("<I", 12 + len(body)))
    p.close()
    return p.name


check(one(write_pcapng_with_options([eth(ip4(tcp()))]))
      == ("10.0.0.5", 50001, "198.51.100.10", 443, PAY),
      "pcapng with SHB/IDB/EPB options present (what a real capture looks like)")

# --- link layers ----------------------------------------------------------
check(one(write_pcap([vlan(ip4(tcp()))])) is not None,
      "802.1Q VLAN tag is skipped to reach the IP header")
check(one(write_pcap([ip4(tcp())], linktype=pcapreader.LINKTYPE_RAW)) is not None,
      "raw IP link type (no link header)")
check(one(write_pcap([b"\x02\x00\x00\x00" + ip4(tcp())],
                     linktype=pcapreader.LINKTYPE_NULL)) is not None,
      "BSD loopback 4-byte address family is skipped")
check(one(write_pcap([b"\x00" * 14 + b"\x08\x00" + ip4(tcp())],
                     linktype=pcapreader.LINKTYPE_LINUX_SLL)) is not None,
      "Linux cooked capture v1 (16-byte header)")
check(one(write_pcap([b"\x08\x00" + b"\x00" * 18 + ip4(tcp())],
                     linktype=pcapreader.LINKTYPE_LINUX_SLL2)) is not None,
      "Linux cooked capture v2 (20-byte header)")
check(got(write_pcap([eth(b"\x00" * 40, etype=0x0806)])) == [],
      "a non-IP ethertype (ARP) yields nothing rather than garbage")

# --- IPv6 -----------------------------------------------------------------
t = one(write_pcap([eth(ip6(tcp()), etype=0x86DD)]))
check(t is not None and t[0] == "2001:db8::5" and t[2] == "2001:db8::a"
      and t[4] == PAY,
      "IPv6 over Ethernet, addresses formatted with :: collapse")
hopbyhop = b"\x06\x00" + b"\x00" * 6                  # next=TCP, len=0 -> 8 bytes
t = one(write_pcap([eth(ip6(hopbyhop + tcp(), nxt=0), etype=0x86DD)]))
check(t is not None and t[3] == 443,
      "IPv6 hop-by-hop extension header is skipped to reach TCP")

# --- things that must NOT parse -------------------------------------------
check(got(write_pcap([eth(ip4(tcp(), proto=17))])) == [],
      "UDP is dropped, not decoded as TCP")
check(got(write_pcap([eth(ip4(tcp(), frag=100))])) == [],
      "a non-first IP fragment is dropped (it carries no TCP header)")
check(got(write_pcap([eth(ip4(b"\x00\x01\x02"))])) == [],
      "an IP packet too short for a TCP header is dropped")

# --- malformed input must not raise ---------------------------------------
bad = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
bad.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
bad.write(struct.pack("<IIII", 0, 0, 9999, 9999) + b"\x41" * 10)   # truncated
bad.close()
try:
    check(got(bad.name) == [], "a truncated record yields nothing and does not raise")
except Exception as e:                                             # pragma: no cover
    check(False, f"truncated record raised {e!r}")

empty = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
empty.close()
try:
    check(got(empty.name) == [], "an empty file yields nothing and does not raise")
except Exception as e:                                             # pragma: no cover
    check(False, f"empty file raised {e!r}")

junk = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
junk.write(b"not a capture file at all, just some bytes")
junk.close()
try:
    check(got(junk.name) == [], "an unrecognised magic yields nothing and does not raise")
except Exception as e:                                             # pragma: no cover
    check(False, f"junk file raised {e!r}")

# --- address formatting ---------------------------------------------------
check(pcapreader._ip6(b"\x00" * 15 + b"\x01") == "::1", "IPv6 loopback formats as ::1")
check(pcapreader._ip6(b"\x00" * 16) == "::", "all-zero IPv6 formats as ::")
check(pcapreader._ip4(b"\xc0\xa8\x00\x01") == "192.168.0.1", "IPv4 dotted quad")


def test_pcapreader():
    assert not fails, f"{len(fails)} failure(s): {fails}"


if __name__ == "__main__":
    print()
    if fails:
        print(f"{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("ALL PASS")
