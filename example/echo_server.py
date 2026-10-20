#!/usr/bin/env python3
# TCP echo server: send 1M timestamp messages to connected client.
# Based on issue #842 reproduction scenario.
import socket
import time
import sys
import signal

PORT = 12373
MSG_COUNT = int(1e6)

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', PORT))
    sock.listen(5)

    print(f"[server] listening on 0.0.0.0:{PORT}, will send {MSG_COUNT} messages", flush=True)

    while True:
        conn, addr = sock.accept()
        print(f"[server] connection from {addr}", flush=True)
        try:
            buf = conn.recv(1024)
            start = time.time()
            sent = 0
            for i in range(MSG_COUNT):
                conn.send((str(time.time_ns()) * 200).encode('utf-8'))
                sent += 1
            conn.close()
            elapsed = time.time() - start
            print(f"[server] sent {sent} messages in {elapsed:.3f}s", flush=True)
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[server] connection error after {sent} msgs: {e}", flush=True)
            try:
                conn.close()
            except:
                pass

if __name__ == '__main__':
    main()
