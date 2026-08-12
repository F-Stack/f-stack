# Issue #481 Test Plan and Environment

## 1. Test Environment

| Item | Config |
|------|--------|
| F-Stack version | 1.26 (dev branch) |
| FreeBSD version | 15.0 |
| DPDK version | 24.11.6 LTS |
| DPDK NIC IP | <DPDK_NIC_IP> |
| Kernel stack test IP | 127.0.0.1 |
| Client machine | f-stack-client (connected via ssh) |
| Client TCP timestamps | Disabled (net.ipv4.tcp_timestamps=0) |

## 2. Test Matrix

| Test ID | Protocol | Stack | Scenario | Method |
|---------|----------|-------|----------|--------|
| T1 | TCP | F-Stack | TCP small packets + padding | Python socket, disable TCP timestamps, send 1/6/2 bytes |
| T2 | UDP | F-Stack | UDP small packets + padding | Python socket send 1/6/2/18 bytes |

## 3. Test Programs

### 3.1 F-Stack TCP Padding Test Server (`padding_test_server.c`)

- F-Stack kqueue/kevent based TCP echo server
- Listens on port 15320
- Prints byte count and hex content after receiving data
- If padding is not stripped, extra bytes will be visible

### 3.2 F-Stack UDP Padding Test Server (`udp_padding_server.c`)

- F-Stack ff_run based UDP echo server
- Listens on port 15321
- Prints byte count and hex content after receiving data
- If padding is not stripped, extra bytes will be visible

### 3.3 Python TCP Client (`padding_test_client.py`)

- Connects to F-Stack TCP server
- Disables Nagle (TCP_NODELAY)
- Sends 1 byte, 6 bytes, 2 bytes sequentially
- Checks if echoed data is exact

### 3.4 Python UDP Client

- Inline Python script executed via ssh on f-stack-client
- Sends 1 byte, 6 bytes, 2 bytes, 18 bytes UDP packets sequentially
- Checks if F-Stack server received exact data

## 4. Ethernet Padding Calculation

Ethernet minimum frame size = 60 bytes (excluding FCS 4 bytes)

| Data Length | Ethernet Frame Composition | Frame Size | Padding Required |
|-------------|---------------------------|-----------|------------------|
| TCP 1 byte | 14+20+20+1 | 55 | 5 bytes |
| TCP 2 bytes | 14+20+20+2 | 56 | 4 bytes |
| TCP 6 bytes | 14+20+20+6 | 60 | 0 bytes |
| UDP 1 byte | 14+20+8+1 | 43 | 17 bytes |
| UDP 2 bytes | 14+20+8+2 | 44 | 16 bytes |
| UDP 6 bytes | 14+20+8+6 | 48 | 12 bytes |
| UDP 18 bytes | 14+20+8+18 | 60 | 0 bytes |

## 5. Key Configuration

### Client TCP Timestamps Disabled

```
ssh f-stack-client "sudo sysctl -w net.ipv4.tcp_timestamps=0"
```

TCP timestamp option adds 12 bytes to TCP header overhead, causing small packets to exceed 60 bytes, preventing padding. After disabling, TCP header = 20 bytes; 1-byte data packet = 55 bytes, triggering 5 bytes of padding.

### F-Stack Configuration

- `lro=0` (disable LRO, ensuring the non-LRO path is tested)
- `tx_csum_offoad_skip=0`
- `vlan_strip=1`
- `ipforwarding=0` (default, ensuring M_FASTFWD_OURS is not triggered)
