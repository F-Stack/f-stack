#!/usr/bin/env python3
"""
Issue #481 test client: Send small TCP packets to trigger Ethernet padding.
Disables TCP timestamps to minimize packet size.

Usage: python3 padding_test_client.py <server_ip> <server_port>
"""
import socket
import sys
import time

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <server_ip> <server_port>")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Disable Nagle to send each packet immediately
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    # Disable TCP timestamps (if supported on this platform)
    try:
        # Linux: sysctl net.ipv4.tcp_timestamps=0 affects all sockets
        # Per-socket may not be possible, but try
        pass
    except:
        pass

    print(f"[CLIENT] connecting to {server_ip}:{server_port}")
    sock.connect((server_ip, server_port))
    print(f"[CLIENT] connected")

    # Send 1 byte - should create a 55-byte Ethernet frame (14+20+20+1)
    # which needs 5 bytes padding to reach 60
    data1 = b'A'
    print(f"[CLIENT] sending {len(data1)} byte: {data1.hex()}")
    sock.sendall(data1)

    # Wait for echo
    reply = sock.recv(1024)
    print(f"[CLIENT] received {len(reply)} bytes: {reply.hex()}")
    if len(reply) != len(data1):
        print(f"[CLIENT] WARNING: received {len(reply)} bytes but sent {len(data1)}!")
        print(f"[CLIENT] *** ISSUE #481 MAY BE PRESENT: padding bytes detected ***")

    time.sleep(0.5)

    # Send 6 bytes - 14+20+20+6 = 60, no padding needed (exactly 60)
    data2 = b'BCDEFG'
    print(f"[CLIENT] sending {len(data2)} bytes: {data2.hex()}")
    sock.sendall(data2)
    reply = sock.recv(1024)
    print(f"[CLIENT] received {len(reply)} bytes: {reply.hex()}")
    if len(reply) != len(data2):
        print(f"[CLIENT] WARNING: received {len(reply)} bytes but sent {len(data2)}!")

    time.sleep(0.5)

    # Send 2 bytes - 14+20+20+2 = 56, needs 4 bytes padding
    data3 = b'HI'
    print(f"[CLIENT] sending {len(data3)} bytes: {data3.hex()}")
    sock.sendall(data3)
    reply = sock.recv(1024)
    print(f"[CLIENT] received {len(reply)} bytes: {reply.hex()}")
    if len(reply) != len(data3):
        print(f"[CLIENT] WARNING: received {len(reply)} bytes but sent {len(data3)}!")
        print(f"[CLIENT] *** ISSUE #481 MAY BE PRESENT: padding bytes detected ***")

    time.sleep(0.5)

    # Close connection (FIN+ACK will be ~54 bytes, needs 6 bytes padding)
    print("[CLIENT] closing connection (FIN+ACK will have padding)")
    sock.shutdown(socket.SHUT_WR)
    time.sleep(1)
    sock.close()
    print("[CLIENT] done")

if __name__ == "__main__":
    main()
