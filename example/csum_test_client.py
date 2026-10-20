#!/usr/bin/env python3
import socket
import sys
import time

def test_connect(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((server_ip, server_port))
        print(f"[CLIENT] connected to {server_ip}:{server_port}")
        msg = b"hello-csum-test"
        sock.sendall(msg)
        print(f"[CLIENT] sent {len(msg)} bytes: {msg}")
        data = sock.recv(256)
        if data == msg:
            print(f"[CLIENT] PASS: received {len(data)} bytes echo: {data}")
            return True
        else:
            print(f"[CLIENT] FAIL: received {len(data) if data else 0} bytes, expected {len(msg)}")
            if data:
                print(f"[CLIENT]   got: {data}")
            return False
    except Exception as e:
        print(f"[CLIENT] FAIL: {e}")
        return False
    finally:
        sock.close()
        time.sleep(0.2)

if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "9.134.214.176"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 15200
    ok = test_connect(ip, port)
    sys.exit(0 if ok else 1)
