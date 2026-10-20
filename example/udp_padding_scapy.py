#!/usr/bin/env python3
"""
Issue #481 test: Send UDP packets with known small payload via scapy.
If Ethernet padding is not stripped, the F-Stack UDP server will receive
extra bytes beyond the payload.

Usage: sudo python3 udp_padding_scapy.py <target_ip> <target_port>
"""
import sys
from scapy.all import *

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])

    # Test 1: 1 byte payload - Ethernet frame = 14+20+8+1 = 43 bytes, needs 17 bytes padding
    payload1 = b'\x41'  # 'A'
    pkt1 = Ether() / IP(dst=target_ip) / UDP(dport=target_port, sport=12345) / Raw(load=payload1)
    print(f"[SCAPY] sending 1-byte UDP payload (frame will be padded to 60 bytes)")
    print(f"[SCAPY] payload hex: {payload1.hex()}")
    sendp(pkt1, iface="eth0", verbose=0)
    print(f"[SCAPY] sent test 1")

    import time
    time.sleep(0.5)

    # Test 2: 6 bytes payload - 14+20+8+6 = 48 bytes, needs 12 bytes padding
    payload2 = b'\x42\x43\x44\x45\x46\x47'  # 'BCDEFG'
    pkt2 = Ether() / IP(dst=target_ip) / UDP(dport=target_port, sport=12345) / Raw(load=payload2)
    print(f"[SCAPY] sending 6-byte UDP payload (frame will be padded to 60 bytes)")
    sendp(pkt2, iface="eth0", verbose=0)
    print(f"[SCAPY] sent test 2")

    time.sleep(0.5)

    # Test 3: 18 bytes payload - 14+20+8+18 = 60 bytes, no padding needed
    payload3 = b'\x48' * 18
    pkt3 = Ether() / IP(dst=target_ip) / UDP(dport=target_port, sport=12345) / Raw(load=payload3)
    print(f"[SCAPY] sending 18-byte UDP payload (no padding needed, exactly 60 bytes)")
    sendp(pkt3, iface="eth0", verbose=0)
    print(f"[SCAPY] sent test 3")

    time.sleep(0.5)

    # Test 4: 2 bytes payload - 14+20+8+2 = 44 bytes, needs 16 bytes padding
    payload4 = b'\x48\x49'  # 'HI'
    pkt4 = Ether() / IP(dst=target_ip) / UDP(dport=target_port, sport=12345) / Raw(load=payload4)
    print(f"[SCAPY] sending 2-byte UDP payload (frame will be padded to 60 bytes)")
    sendp(pkt4, iface="eth0", verbose=0)
    print(f"[SCAPY] sent test 4")

    print("[SCAPY] all tests sent. Check server log for received byte counts.")
    print("[SCAPY] If server receives exactly 1, 6, 18, 2 bytes → padding stripped (PASS)")
    print("[SCAPY] If server receives extra bytes → padding NOT stripped (FAIL, issue #481 present)")

if __name__ == "__main__":
    main()
