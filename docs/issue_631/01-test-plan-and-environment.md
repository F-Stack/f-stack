# Issue #631 Test Plan and Environment

## 1. Test Environment

| Item | Value |
|------|-------|
| F-Stack | 1.26 (dev branch, FreeBSD 15.0) |
| DPDK | 24.11.6 LTS |
| DPDK NIC IP | <DPDK_NIC_IP> (port0) |
| Test client | f-stack-client (<CLIENT_IP>) |
| Kernel stack test | 127.0.0.1 (lo) |
| Compile options | -O2 -g -DINET6 |

## 2. Network Topology

```
Python UDP sender (f-stack-client <CLIENT_IP>)
    ↓ UDP packets to <DPDK_NIC_IP>:15310
F-Stack UDP receiver (local DPDK NIC <DPDK_NIC_IP>)
    - ff_socket(SOCK_DGRAM) → ff_bind(:15310) → FIONBIO
    - loop: ff_recvfrom → count++
    - count==3: ff_shutdown(sockfd, how)
    - continue: check if ff_recvfrom returns 0 or data

Kernel stack comparison test (local 127.0.0.1):
    Python sender → 127.0.0.1:15310
    Kernel UDP receiver (socket/bind/recvfrom/shutdown)
```

## 3. Test Matrix

| Test ID | Stack Type | Socket Type | shutdown how | Expected Behavior | Actual Behavior | Result |
|---------|-----------|-------------|-------------|-------------------|-----------------|--------|
| T1 (x3) | F-Stack | UDP | SHUT_RD (0) | recvfrom→0 | recvfrom→0 (EOF) | ✅ PASS |
| T2 | F-Stack | UDP | SHUT_WR (1) | sendto→EPIPE | sendto→EPIPE | ✅ PASS |
| T5 | Kernel stack | UDP | SHUT_RD (0) | recvfrom→0 | Returns ENOTCONN, continues receiving | ❌ Kernel behavior |

## 4. Test Programs

### 4.1 F-Stack UDP Shutdown Test Program

**File**: `example/udp_shutdown_test.c`

Functionality:
- Creates UDP socket, binds to <DPDK_NIC_IP>:15310
- Sets FIONBIO non-blocking mode
- Calls ff_recvfrom in ff_run loop to receive data
- After receiving 3 packets, calls ff_shutdown(sockfd, how)
- Continues loop to observe subsequent behavior

Parameters:
- `--how=0|1|2`: shutdown mode (SHUT_RD/SHUT_WR/SHUT_RDWR)
- `--connect`: use ff_connect to connect to client (test connected UDP scenario)

### 4.2 Kernel Stack UDP Shutdown Comparison Program

**File**: `example/udp_shutdown_test_kernel.c`

Functionality: Same test logic as F-Stack version, using standard Linux socket API (socket/bind/recvfrom/shutdown)

### 4.3 Python UDP Sender

**File**: `example/udp_sender_631.py`

Functionality: Sends UDP packets at controlled intervals to target address

Usage: `python3 udp_sender_631.py <target_ip> <port> [count] [interval_ms]`

## 5. Key Technical Decisions

### 5.1 Non-Blocking Mode Choice

Uses `ff_ioctl(sockfd, FIONBIO, &nonblock)` to set non-blocking mode, instead of `MSG_DONTWAIT` flag.

Reason: Linux `MSG_DONTWAIT`=0x40 (64) and FreeBSD `MSG_DONTWAIT`=0x80 (128) values differ. F-Stack's `ff_recvfrom` passes flags directly to FreeBSD `kern_recvit`; using Linux values would cause flags to be misinterpreted.

### 5.2 Test Judgment Logic

- **SHUT_RD**: After shutdown, `recvfrom` returns 0 (EOF) = PASS; continues receiving data = FAIL
- **SHUT_WR**: After shutdown, `sendto` returns -1/EPIPE = PASS
- **SHUT_RDWR**: Both conditions met = PASS
