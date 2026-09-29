#!/usr/bin/env python3
"""Orphan forensics: read a client-side capture and report double SYN-ACKs.

A connection stranded in the draining generation shows up on the wire as two
SYN-ACKs for one four-tuple with different sequence numbers: the old
generation answered the original SYN, the new one answered the retransmitted
SYN. What the client does next decides which entry becomes an orphan:

  * it acknowledges the first SYN-ACK it accepted -- the other generation's
    half-open entry can never be completed;
  * it abandons the connection -- both entries stay half-open.

Reads a pcap (no scapy, no tcpdump text parsing) and prints one line per
suspicious connection plus a summary. Runs on the client, where the capture
was taken.
"""

import struct
import sys

ETH_LEN = 14
VLAN_TPIDS = (0x8100, 0x88A8)


class Conn(object):
    __slots__ = ("syn", "synack", "honored", "rst", "first_ts", "port")

    def __init__(self, port):
        self.port = port
        self.syn = []            # (ts, seq) of the client's SYN and its retries
        self.synack = []         # (ts, seq) of every SYN-ACK seen
        self.honored = None      # ISS the client's first ACK/PSH acknowledged
        self.rst = 0
        self.first_ts = None


def packets(path):
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 24:
        return
    magic = blob[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        sys.stderr.write("unsupported pcap magic %r\n" % (magic,))
        return
    linktype = struct.unpack(endian + "I", blob[20:24])[0]
    off = 24
    n = len(blob)
    while off + 16 <= n:
        ts_sec, ts_frac, caplen, _origlen = struct.unpack(
            endian + "IIII", blob[off:off + 16])
        off += 16
        data = blob[off:off + caplen]
        off += caplen
        ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
        yield linktype, ts, data


def parse(linktype, data):
    """Return (src, sport, dst, dport, seq, ack, flags, payload_len)."""
    if linktype == 1:                                  # Ethernet
        if len(data) < ETH_LEN:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = ETH_LEN
        while etype in VLAN_TPIDS:
            if len(data) < off + 4:
                return None
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        if etype != 0x0800:
            return None
    elif linktype == 113:                              # Linux cooked
        if len(data) < 16:
            return None
        etype = struct.unpack("!H", data[14:16])[0]
        off = 16
        if etype != 0x0800:
            return None
    elif linktype == 101 or linktype == 228:           # raw IP
        off = 0
    else:
        return None
    if len(data) < off + 20:
        return None
    ver_ihl = data[off]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0f) * 4
    total = struct.unpack("!H", data[off + 2:off + 4])[0]
    if data[off + 9] != 6:
        return None
    src = ".".join(str(b) for b in data[off + 12:off + 16])
    dst = ".".join(str(b) for b in data[off + 16:off + 20])
    t = off + ihl
    if len(data) < t + 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", data[t:t + 12])
    doff = (data[t + 12] >> 4) * 4
    flags = data[t + 13]
    payload = max(0, total - ihl - doff)
    return src, sport, dst, dport, seq, ack, flags, payload


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: orphan_capture_analyze.py <pcap> [server-port]\n")
        return 2
    port = int(argv[2]) if len(argv) > 2 else 80
    conns = {}
    order = []
    for linktype, ts, data in packets(argv[1]):
        p = parse(linktype, data)
        if p is None:
            continue
        src, sport, dst, dport, seq, ack, flags, payload = p
        syn = flags & 0x02
        ackf = flags & 0x10
        rst = flags & 0x04
        if sport == port:                     # server -> client
            cport = dport
        elif dport == port:                   # client -> server
            cport = sport
        else:
            continue
        c = conns.get(cport)
        if c is None:
            c = conns[cport] = Conn(cport)
            order.append(cport)
        if c.first_ts is None:
            c.first_ts = ts
        if syn and ackf:
            c.synack.append((ts, seq))
        elif syn:
            c.syn.append((ts, seq))
        if rst:
            c.rst += 1
        if ackf and not syn and c.honored is None and sport != port:
            # The client's first post-handshake segment: its ack - 1 is the
            # ISS it accepted, which is what the stranded entry cannot match.
            c.honored = (ack - 1) & 0xffffffff

    dup = 0
    retransmit = 0
    reset = 0
    for cport in order:
        c = conns[cport]
        seqs = []
        for _ts, seq in c.synack:
            if seq not in seqs:
                seqs.append(seq)
        if len(seqs) > 1:
            dup += 1
            first = c.synack[0]
            second = c.synack[-1]
            which = "none"
            if c.honored is not None:
                if c.honored == seqs[0]:
                    which = "first"
                elif c.honored == seqs[-1]:
                    which = "last"
                else:
                    which = "other"
            print("DUP_SYNACK port=%d seqs=%s gap_ms=%.1f retransmits=%d "
                  "honored=%s rst=%d" % (
                      cport, ",".join(str(s) for s in seqs),
                      (second[0] - first[0]) * 1000.0, len(c.syn), which,
                      c.rst))
        elif len(c.syn) > 1 and not c.synack:
            retransmit += 1
            print("SYN_ONLY port=%d retransmits=%d (never answered)" % (
                cport, len(c.syn)))
        elif c.rst:
            reset += 1
    print("SUMMARY connections=%d dup_synack=%d syn_only=%d with_rst=%d" % (
        len(conns), dup, retransmit, reset))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
