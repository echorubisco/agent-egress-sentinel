#!/usr/bin/env python3
"""
Capture files -> the same (src, sport, dst, dport, tcp_payload) tuples that
`tlsparse.iter_packets` produces from `tcpdump -x` text.

WHY THIS EXISTS. Offline replay used to shell out to `tcpdump -r`, which meant
the *offline* path -- the one that needs no BPF, no sudo, and no network -- still
required a macOS/Linux capture binary. Two consequences, both bad:

  - The SNI parser could only be tested where tcpdump exists. It is pure byte
    parsing; there was no reason for that.
  - `pktmon`, which ships with Windows and can convert its captures to pcapng,
    had nowhere to hand its output. This is the missing adapter (see PLATFORMS.md).

Parsing a capture container is boring and total: a fixed header, then records.
Going through a subprocess to do it bought a text-encode/regex-decode round trip
and a platform dependency.

FORMATS. Classic pcap (both byte orders, microsecond and nanosecond) and pcapng
(SHB/IDB/EPB/SPB, per-interface link types). Link layers: Ethernet with VLAN
tags, Linux cooked v1/v2, BSD loopback, and raw IP. IPv4 and IPv6, TCP only --
this feeds a TLS ClientHello parser, and there is no TLS over anything else here.

SCOPE, deliberately. No IP fragment reassembly: a ClientHello arrives in TCP
segments, and TCP-level reassembly is StreamAssembler's job. An IP-fragmented
first segment would be missed, which is the same blind spot the live path has,
so the offline path does not pretend to be better than what it replays.

Never raises on malformed input. A truncated or corrupt capture yields fewer
packets, not a traceback -- this parses files from elsewhere by definition.
"""

import struct

# link types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_BSD = 12
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_RAW = 101
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

_RAWISH = {LINKTYPE_RAW, LINKTYPE_RAW_BSD, LINKTYPE_IPV4, LINKTYPE_IPV6}

_ETHERTYPE_IP4 = 0x0800
_ETHERTYPE_IP6 = 0x86DD
_VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)      # 802.1Q and QinQ stacking

_PROTO_TCP = 6
# IPv6 extension headers we can skip; each is (next_header, hdr_ext_len) framed.
_V6_SKIPPABLE = {0, 43, 60}                 # hop-by-hop, routing, dest options


def _ip4(b):
    """Dotted-quad without inet_ntop (which needs AF_INET6 support on Windows)."""
    return ".".join(str(x) for x in b)


def _ip6(b):
    parts = [f"{b[i] << 8 | b[i + 1]:x}" for i in range(0, 16, 2)]
    # Longest run of zero groups collapses to '::' (RFC 5952). Cosmetic, but the
    # SNI cache keys on this string and the byte source must agree with it.
    best_i = best_n = cur_i = cur_n = -1
    for i, p in enumerate(parts + ["x"]):
        if p == "0":
            cur_i, cur_n = (i, 1) if cur_n < 1 else (cur_i, cur_n + 1)
        else:
            if cur_n > best_n:
                best_i, best_n = cur_i, cur_n
            cur_n = 0
    if best_n > 1:
        return ":".join(parts[:best_i]) + "::" + ":".join(parts[best_i + best_n:])
    return ":".join(parts)


def strip_link(data, linktype):
    """Link-layer header -> the IP packet inside, or None."""
    try:
        if linktype == LINKTYPE_ETHERNET:
            if len(data) < 14:
                return None
            etype = int.from_bytes(data[12:14], "big")
            off = 14
            while etype in _VLAN_TPIDS and len(data) >= off + 4:
                etype = int.from_bytes(data[off + 2:off + 4], "big")
                off += 4
            if etype not in (_ETHERTYPE_IP4, _ETHERTYPE_IP6):
                return None
            return data[off:]
        if linktype in _RAWISH:
            return data
        if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
            return data[4:] if len(data) > 4 else None      # 4-byte address family
        if linktype == LINKTYPE_LINUX_SLL:
            if len(data) < 16:
                return None
            if int.from_bytes(data[14:16], "big") not in (_ETHERTYPE_IP4,
                                                          _ETHERTYPE_IP6):
                return None
            return data[16:]
        if linktype == LINKTYPE_LINUX_SLL2:
            if len(data) < 20:
                return None
            if int.from_bytes(data[0:2], "big") not in (_ETHERTYPE_IP4,
                                                        _ETHERTYPE_IP6):
                return None
            return data[20:]
    except Exception:
        return None
    return None


def parse_ip_tcp(pkt):
    """IP packet -> (src, sport, dst, dport, tcp_payload), or None."""
    try:
        if not pkt:
            return None
        ver = pkt[0] >> 4
        if ver == 4:
            if len(pkt) < 20:
                return None
            ihl = (pkt[0] & 0x0F) * 4
            if ihl < 20 or len(pkt) < ihl:
                return None
            if pkt[9] != _PROTO_TCP:
                return None
            # A non-first fragment carries no TCP header; see module docstring.
            if int.from_bytes(pkt[6:8], "big") & 0x1FFF:
                return None
            total = int.from_bytes(pkt[2:4], "big")
            if 20 <= total <= len(pkt):          # trust it only if it fits
                pkt = pkt[:total]
            src, dst = _ip4(pkt[12:16]), _ip4(pkt[16:20])
            rest = pkt[ihl:]
        elif ver == 6:
            if len(pkt) < 40:
                return None
            nxt, off = pkt[6], 40
            while nxt in _V6_SKIPPABLE and len(pkt) >= off + 8:
                nxt, off = pkt[off], off + (pkt[off + 1] + 1) * 8
            if nxt != _PROTO_TCP:
                return None
            src, dst = _ip6(pkt[8:24]), _ip6(pkt[24:40])
            rest = pkt[off:]
        else:
            return None

        if len(rest) < 20:
            return None
        sport = int.from_bytes(rest[0:2], "big")
        dport = int.from_bytes(rest[2:4], "big")
        doff = ((rest[12] & 0xF0) >> 4) * 4
        if doff < 20 or len(rest) < doff:
            return None
        return src, sport, dst, dport, rest[doff:]
    except Exception:
        return None


# ------------------------------------------------------------ containers ---
def _iter_pcap_raw(f, head):
    """Classic pcap -> (linktype, packet_bytes)."""
    if head[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif head[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        return
    rest = f.read(20)
    if len(rest) < 20:
        return
    linktype = struct.unpack(endian + "I", rest[16:20])[0]
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return
        _s, _u, incl, _orig = struct.unpack(endian + "IIII", rec)
        if incl > 16 * 1024 * 1024:              # refuse a corrupt length
            return
        data = f.read(incl)
        if len(data) < incl:
            return
        yield linktype, data


def _iter_pcapng_raw(f, head):
    """pcapng -> (linktype, packet_bytes). Link type is per interface."""
    f.seek(0)
    links = []                                   # interface id -> linktype
    endian = "<"
    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            return
        btype = struct.unpack(endian + "I", hdr[0:4])[0]
        if btype == 0x0A0D0D0A:                  # section header: sets byte order
            magic = f.read(4)
            if len(magic) < 4:
                return
            endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", hdr[4:8])[0]
            links = []                           # a new section restarts numbering
            if blen < 16:
                return
            # 12 bytes consumed so far (type + total_length + the 4-byte BOM);
            # total_length covers the whole block including its trailing copy.
            f.seek(blen - 12, 1)
            continue
        blen = struct.unpack(endian + "I", hdr[4:8])[0]
        if blen < 12 or blen > 64 * 1024 * 1024:
            return
        body = f.read(blen - 12)
        if len(body) < blen - 12:
            return
        f.read(4)                                # trailing total length
        if btype == 0x00000001 and len(body) >= 8:                   # IDB
            links.append(struct.unpack(endian + "H", body[0:2])[0])
        elif btype == 0x00000006 and len(body) >= 20:                # EPB
            iface, _hi, _lo, cap, _orig = struct.unpack(endian + "IIIII", body[:20])
            if cap <= len(body) - 20:
                yield (links[iface] if iface < len(links) else LINKTYPE_ETHERNET,
                       body[20:20 + cap])
        elif btype == 0x00000003 and len(body) >= 4:                 # SPB
            yield (links[0] if links else LINKTYPE_ETHERNET), body[4:]


def iter_raw_packets(path):
    """Yield (linktype, packet_bytes) from a pcap or pcapng file."""
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4:
            return
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng_raw(f, head)
        else:
            yield from _iter_pcap_raw(f, head)


def iter_packets(path):
    """Yield (src, sport, dst, dport, tcp_payload) -- tlsparse's tuple contract.

    Deliberately the same shape as tlsparse.iter_packets so the sniffer's loop,
    the StreamAssembler and every downstream test stay identical whether the
    bytes came off the wire through tcpdump or out of a file.
    """
    for linktype, data in iter_raw_packets(path):
        pkt = strip_link(data, linktype)
        if pkt is None:
            continue
        out = parse_ip_tcp(pkt)
        if out is not None:
            yield out


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: pcapreader.py <capture.pcap|.pcapng>")
        sys.exit(2)
    n = 0
    for src, sport, dst, dport, payload in iter_packets(sys.argv[1]):
        n += 1
        print(f"{src}.{sport} > {dst}.{dport}  {len(payload)} bytes")
    print(f"-- {n} TCP segments")
