#!/usr/bin/env python3
"""E2 decisive experiment client: hold N keep-alive HTTP connections to the
F-Stack DPDK NIC, poll each one periodically, and log per-connection liveness
so that the exact moment the primary process is killed can be correlated.
"""
import socket
import sys
import time

HOST = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
NCONN = int(sys.argv[3]) if len(sys.argv) > 3 else 20
DURATION = int(sys.argv[4]) if len(sys.argv) > 4 else 90
INTERVAL = 2.0

REQ = b"GET / HTTP/1.1\r\nHost: fstack\r\nConnection: keep-alive\r\n\r\n"

conns = []
for i in range(NCONN):
    lport = 20000 + i
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("", lport))
        s.settimeout(3.0)
        s.connect((HOST, PORT))
        conns.append([lport, s, True])
    except Exception as e:
        print("CONNECT_FAIL lport=%d err=%s" % (lport, e), flush=True)
        conns.append([lport, None, False])

alive0 = sum(1 for c in conns if c[2])
print("PHASE=setup established=%d/%d" % (alive0, NCONN), flush=True)

t0 = time.time()
rnd = 0
while time.time() - t0 < DURATION:
    rnd += 1
    ok, bad = [], []
    for c in conns:
        lport, s, alive = c
        if not alive:
            bad.append(lport)
            continue
        try:
            s.sendall(REQ)
            data = s.recv(65535)
            if data and data.startswith(b"HTTP/1.1 200"):
                ok.append(lport)
            else:
                c[2] = False
                bad.append(lport)
        except Exception:
            c[2] = False
            bad.append(lport)
    print("ROUND=%d t=%.1f ok=%d dead=%d ok_lports=%s dead_lports=%s"
          % (rnd, time.time() - t0, len(ok), len(bad),
             ",".join(map(str, ok)), ",".join(map(str, bad))), flush=True)
    time.sleep(INTERVAL)

print("PHASE=done final_ok=%d/%d" % (sum(1 for c in conns if c[2]), NCONN), flush=True)
