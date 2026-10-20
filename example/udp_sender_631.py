#!/usr/bin/env python3
"""UDP sender for issue #631 shutdown test.
Sends UDP packets to the F-Stack server at controlled intervals.
Usage: python3 udp_sender.py <target_ip> <port> [count] [interval_ms]
"""
import socket
import sys
import time

def main():
    if len(sys.argv) < 3:
        print("Usage: %s <target_ip> <port> [count] [interval_ms]" % sys.argv[0])
        sys.exit(1)

    target_ip = sys.argv[1]
    port = int(sys.argv[2])
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    interval_ms = int(sys.argv[4]) if len(sys.argv) > 4 else 200

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg = b"hello-631-" + b"0" * (48)  # 64 bytes total

    print("[sender] sending %d packets to %s:%d every %dms" % (count, target_ip, port, interval_ms))
    for i in range(count):
        sock.sendto(msg, (target_ip, port))
        print("[sender] sent pkt #%d (%d bytes)" % (i + 1, len(msg)))
        time.sleep(interval_ms / 1000.0)

    sock.close()
    print("[sender] done, sent %d packets" % count)

if __name__ == "__main__":
    main()
