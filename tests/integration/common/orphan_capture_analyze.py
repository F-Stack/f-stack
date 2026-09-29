#!/usr/bin/env python3
"""Orphan forensics: report double SYN-ACKs in a client-side capture.

A connection stranded in the draining generation shows up on the wire as one
four-tuple answered with two SYN-ACKs carrying different sequence numbers:
the draining generation answered the original SYN, the new generation
answered the retransmitted SYN. Only one of them can be completed, so the
other generation's half-open entry is orphaned.

The client reuses ephemeral ports at high connection rates, so a connection
is tracked as the packets between one client SYN and the next (a SYN with the
same sequence number is a retransmit of the connection in flight). Reads a
pcap directly -- no scapy, no tcpdump text parsing.
"""

import struct
import sys

SYN, ACK, RST, FIN = 0x02, 0x10, 0x04, 0x01


class Conn(object):
    __slots__ = ("port", "isn", "synack", "honored", "rst", "fin", "retrans")

    def __init__(self, port, isn):
        self.port = port
        self.isn = isn
        self.synack = []
        self.honored = None
        self.rst = 0
        self.fin = 0
        self.retrans = 0


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
    off, n = 24, len(blob)
    while off + 16 <= n:
        ts_sec, ts_frac, caplen, _origlen = struct.unpack(
            endian + "IIII", blob[off:off + 16])
        off += 16
        data = blob[off:off + caplen]
        off += caplen
        yield linktype, ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6), data


def parse(linktype, data):
    """Return (sport, dport, seq, ack, flags) for an IPv4/TCP packet."""
    if linktype == 1:                                   # Ethernet
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8):
            if len(data) < off + 4:
                return None
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        if etype != 0x0800:
            return None
    elif linktype == 113:                               # Linux cooked
        if len(data) < 16:
            return None
        if struct.unpack("!H", data[14:16])[0] != 0x0800:
            return None
        off = 16
    elif linktype in (101, 228):                        # raw IP
        off = 0
    else:
        return None
    if len(data) < off + 20:
        return None
    ver_ihl = data[off]
    if ver_ihl >> 4 != 4 or data[off + 9] != 6:
        return None
    ihl = (ver_ihl & 0x0f) * 4
    t = off + ihl
    if len(data) < t + 14:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", data[t:t + 12])
    return sport, dport, seq, ack, data[t + 13]


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: orphan_capture_analyze.py <pcap> [server-port]\n")
        return 2
    srv = int(argv[2]) if len(argv) > 2 else 80
    live = {}
    done = []
    for linktype, ts, data in packets(argv[1]):
        p = parse(linktype, data)
        if p is None:
            continue
        sport, dport, seq, ack, flags = p
        if sport == srv:
            cport, from_client = dport, False
        elif dport == srv:
            cport, from_client = sport, True
        else:
            continue
        cur = live.get(cport)
        if from_client and flags & SYN and not flags & ACK:
            if cur is not None and cur.isn == seq and not cur.synack:
                cur.retrans += 1                  # the SYN was retried
                continue
            if cur is not None:
                done.append(cur)
            cur = live[cport] = Conn(cport, seq)
        elif cur is None:
            continue
        if not from_client and flags & SYN and flags & ACK:
            cur.synack.append(seq)
        elif from_client and flags & ACK and not flags & SYN \
                and cur.honored is None:
            # The first post-handshake segment: ack - 1 is the ISS the
            # client accepted, i.e. the one the other generation cannot match.
            cur.honored = (ack - 1) & 0xffffffff
        if flags & RST:
            cur.rst += 1
        if flags & FIN:
            cur.fin += 1
    done.extend(live.values())

    dup = rst = never = retried = 0
    for c in done:
        if c.retrans:
            retried += 1
        seqs = []
        for s in c.synack:
            if s not in seqs:
                seqs.append(s)
        if len(seqs) > 1:
            dup += 1
            which = "none"
            if c.honored is not None:
                if c.honored == seqs[0]:
                    which = "first"
                elif c.honored == seqs[-1]:
                    which = "last"
                else:
                    which = "other"
            print("DUP_SYNACK port=%d isn=%u synack_seqs=%s retrans=%d "
                  "honored=%s rst=%d fin=%d" % (
                      c.port, c.isn, ",".join(str(s) for s in seqs),
                      c.retrans, which, c.rst, c.fin))
        elif not c.synack:
            never += 1
        elif c.rst:
            rst += 1
    print("SUMMARY connections=%d dup_synack=%d answered_then_rst=%d "
          "never_answered=%d syn_retransmitted=%d" % (
              len(done), dup, rst, never, retried))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
