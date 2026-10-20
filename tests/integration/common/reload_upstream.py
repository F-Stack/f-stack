#!/usr/bin/env python3
"""Test upstream for the reverse-proxy case (rt32), run on the client.

usage: reload_upstream.py --server <bind_addr> --port <port>   serve
       reload_upstream.py md5                                   /big md5
  GET /ok          small body carrying the peer port
  GET /big         64 MiB deterministic body
  GET /slow?sec=N  8 KiB every 100 ms for N seconds
The harness runs it as a bounded reload_remote.py job.
"""
import hashlib
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BIG = 64 * 1024 * 1024
CHUNK = bytes((i * 7 + 3) & 0xFF for i in range(65536))


def big_md5():
    h = hashlib.md5()
    for _ in range(BIG // len(CHUNK)):
        h.update(CHUNK)
    return h.hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%.3f port=%d %s\n" % (time.time(), self.client_address[1],
                                               fmt % args))

    def _head(self, n):
        self.send_response(200)
        self.send_header("Content-Length", str(n))
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path.endswith("/big"):
            self._head(BIG)
            for _ in range(BIG // len(CHUNK)):
                self.wfile.write(CHUNK)
            return
        if u.path.endswith("/slow"):
            n = int(float(parse_qs(u.query).get("sec", ["10"])[0]) * 10)
            self._head(n * 8192)
            for _ in range(n):
                self.wfile.write(CHUNK[:8192])
                self.wfile.flush()
                time.sleep(0.1)
            return
        body = ("ok peer_port=%d" % self.client_address[1]).encode()
        self._head(len(body))
        self.wfile.write(body)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "md5":
        print(big_md5())
        return 0
    if len(sys.argv) != 5 or sys.argv[1] != "--server" \
            or sys.argv[3] != "--port":
        sys.stderr.write(__doc__)
        return 2
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((sys.argv[2], int(sys.argv[4])), Handler)
    print("UPSTREAM_READY port=%s" % sys.argv[4], flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
