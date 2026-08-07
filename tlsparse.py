#!/usr/bin/env python3
"""
Byte-accurate ClientHello SNI extraction, with TCP stream reassembly.

Why this replaces the ASCII grep. The old sniffer ran `tcpdump -A` and regexed
anything hostname-shaped out of the ASCII dump. Replaying public Wireshark test
captures measured two defects from that:

  1. Server certificate contents were harvested as if the client had contacted
     them -- one connection to example.com produced 33 records including the
     cert's SAN list and the CA's own URLs (crl3/crl4/cacerts.digicert.com).
     Fixed earlier by restricting the BPF filter to handshake type 0x01.
  2. Even inside a genuine ClientHello, TLS 1.3 random bytes (session id, key
     share) match the hostname regex and can PRECEDE the real SNI. 2 of 6
     records extracted from three public captures were noise like `9g.nc`,
     `ft3.oq`. No amount of regex tightening fixes that -- `nc` is a real ccTLD.

So: parse the actual bytes. Walk the ClientHello structure to extension 0x0000
(server_name) and read the hostname from its length-prefixed field. A hostname
either is at that offset or it is not; there is no scoring involved.

Reassembly. A post-quantum ClientHello (X25519MLKEM768) can exceed the MTU. If
the stack emits its large key_share before server_name, the SNI lands in a
continuation segment. `feed()` therefore buffers payload per TCP stream until the
record is complete, so a ClientHello split across any number of segments parses
once its bytes have all arrived.

Input format: `tcpdump -x` prints, per packet, the IP header onward as hex words.
`iter_packets()` turns that text stream into (src, dst, sport, dport, payload).
"""

import re

_HDR = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)")
_HEXLINE = re.compile(r"^\s+0x[0-9a-f]{4}:\s+((?:[0-9a-f]{2,4}\s*)+)")

MAX_STREAM_BUF = 16 * 1024      # a ClientHello never legitimately exceeds this
MAX_STREAMS = 512               # bound memory; oldest dropped first


def _hex_to_bytes(chunks):
    h = "".join(chunks).replace(" ", "")
    if len(h) % 2:
        h = h[:-1]
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b""


def iter_packets(lines):
    """Yield (src, sport, dst, dport, ip_payload_bytes) from `tcpdump -x` text."""
    hdr, chunks = None, []

    def flush():
        if hdr is None:
            return None
        raw = _hex_to_bytes(chunks)
        if len(raw) < 20:
            return None
        ihl = (raw[0] & 0x0F) * 4
        if ihl < 20 or len(raw) < ihl + 20:
            return None
        tcp = raw[ihl:]
        doff = ((tcp[12] & 0xF0) >> 4) * 4
        if doff < 20 or len(tcp) < doff:
            return None
        return hdr + (tcp[doff:],)

    for line in lines:
        m = _HEXLINE.match(line)
        if m:
            chunks.append(m.group(1))
            continue
        # a non-hex line ends the previous packet
        out = flush()
        if out:
            yield out
        hdr, chunks = None, []
        hm = _HDR.search(line)
        if hm:
            hdr = (hm.group(1), int(hm.group(2)), hm.group(3), int(hm.group(4)))
    out = flush()
    if out:
        yield out


def parse_client_hello_sni(buf: bytes):
    """Return the SNI hostname from a (possibly incomplete) TLS record buffer.

    Returns None when the buffer is not a ClientHello, has no server_name, or is
    still short -- the caller keeps buffering in the last case. Raises nothing:
    a malformed handshake must never take the sniffer down.
    """
    try:
        if len(buf) < 6 or buf[0] != 0x16:
            return None
        rec_len = int.from_bytes(buf[3:5], "big")
        body = buf[5:5 + rec_len]
        if len(body) < rec_len:            # incomplete record: keep buffering
            return None
        if not body or body[0] != 0x01:    # not a ClientHello
            return None
        i = 4                              # handshake header (type + 3-byte len)
        i += 2                             # client_version
        i += 32                            # random
        if i >= len(body):
            return None
        i += 1 + body[i]                   # session_id
        if i + 2 > len(body):
            return None
        i += 2 + int.from_bytes(body[i:i + 2], "big")        # cipher_suites
        if i + 1 > len(body):
            return None
        i += 1 + body[i]                                     # compression
        if i + 2 > len(body):
            return None
        ext_total = int.from_bytes(body[i:i + 2], "big")
        i += 2
        end = min(len(body), i + ext_total)
        while i + 4 <= end:
            etype = int.from_bytes(body[i:i + 2], "big")
            elen = int.from_bytes(body[i + 2:i + 4], "big")
            i += 4
            if etype == 0x0000:                              # server_name
                e = body[i:i + elen]
                if len(e) < 5:
                    return None
                # ServerNameList: 2-byte list len, then entries
                j = 2
                while j + 3 <= len(e):
                    ntype = e[j]
                    nlen = int.from_bytes(e[j + 1:j + 3], "big")
                    name = e[j + 3:j + 3 + nlen]
                    if ntype == 0 and len(name) == nlen and nlen > 0:
                        try:
                            return name.decode("idna") if max(name) > 127 \
                                else name.decode("ascii").lower()
                        except Exception:
                            return None
                    j += 3 + nlen
                return None
            i += elen
        return None
    except Exception:
        return None


class StreamAssembler:
    """Buffers outbound payload per TCP stream until a ClientHello parses.

    A stream is retired as soon as it yields an SNI, or once its buffer shows the
    first record is complete and simply has no server_name, or at MAX_STREAM_BUF.
    That keeps a bulk upload from being buffered forever after its handshake.
    """

    def __init__(self):
        self._buf = {}          # (src,sport,dst,dport) -> bytearray
        self._done = set()

    def feed(self, key, payload):
        """Returns (sni, dst_ip) once, or None."""
        if not payload or key in self._done:
            return None
        b = self._buf.setdefault(key, bytearray())
        b += payload
        if len(b) > MAX_STREAM_BUF:
            self._retire(key)
            return None
        if len(self._buf) > MAX_STREAMS:
            self._retire(next(iter(self._buf)))
        sni = parse_client_hello_sni(bytes(b))
        if sni:
            self._retire(key)
            return sni, key[2]
        # complete-but-no-SNI: stop buffering this stream
        if len(b) >= 5 and b[0] == 0x16:
            rec_len = int.from_bytes(bytes(b[3:5]), "big")
            if len(b) >= 5 + rec_len:
                self._retire(key)
        elif len(b) >= 1 and b[0] != 0x16:
            self._retire(key)          # not TLS handshake at all
        return None

    def _retire(self, key):
        self._buf.pop(key, None)
        self._done.add(key)
        if len(self._done) > MAX_STREAMS * 4:
            self._done.clear()
