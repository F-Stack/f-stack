# Issue #631 Test Results and Data Analysis

## 1. T1: F-Stack UDP SHUT_RD (3 repeated tests)

### Test Conditions
- Server: F-Stack UDP socket bound to <DPDK_NIC_IP>:15310
- Client: f-stack-client sends 20 UDP packets, one every 200ms
- Shutdown trigger: after receiving 3 packets, call `ff_shutdown(sockfd, 0)`

### Run #1

```
[RECV] pkt #1: 58 bytes (loop=145319447)
[RECV] pkt #2: 58 bytes (loop=146766310)
[RECV] pkt #3: 58 bytes (loop=148217886)
[SHUTDOWN] calling ff_shutdown(sockfd, 0)...
[SHUTDOWN] ret=0 errno=11 (Resource temporarily unavailable)
[EOF] recvfrom returned 0 (loop=148217887 phase=1)
[RESULT] PASS: recvfrom returned 0 (EOF) after shutdown(how=0)
```

### Run #2

```
[RECV] pkt #3: 58 bytes (loop=74895251)
[SHUTDOWN] ret=0 errno=11 (Resource temporarily unavailable)
[RESULT] PASS: recvfrom returned 0 (EOF) after shutdown(how=0)
```

### Run #3

```
[RECV] pkt #3: 58 bytes (loop=75043986)
[SHUTDOWN] ret=0 errno=11 (Resource temporarily unavailable)
[RESULT] PASS: recvfrom returned 0 (EOF) after shutdown(how=0)
```

### Analysis

- `ff_shutdown(sockfd, 0)` returns 0 (success)
  - errno=11 (EAGAIN) is residual from previous recvfrom, not shutdown's return error
- After shutdown, the **next** `ff_recvfrom` immediately returns 0 (EOF)
- 3 tests with identical results
- **Conclusion: SHUT_RD works correctly on F-Stack UDP**

## 2. T2: F-Stack UDP SHUT_WR

### Test Conditions
- Same as T1, but `--how=1` (SHUT_WR)

### Result

```
[RECV] pkt #1: 58 bytes (loop=72049292)
[RECV] pkt #2: 58 bytes (loop=73492851)
[RECV] pkt #3: 58 bytes (loop=74935717)
[SHUTDOWN] calling ff_shutdown(sockfd, 1)...
[SHUTDOWN] ret=0 errno=11 (Resource temporarily unavailable)
[SEND-POST-SHUTDOWN] sendto ret=-1 errno=32 (Broken pipe)
[RESULT] PASS: no data received after 5000 idle loops (shutdown(how=1) effective)
```

### Analysis

- `ff_shutdown(sockfd, 1)` returns 0 (success)
- `ff_sendto` returns -1, errno=32 (EPIPE) after SHUT_WR — **send side correctly closed**
- **Conclusion: SHUT_WR works correctly on F-Stack UDP**

## 3. T5: Kernel Stack UDP SHUT_RD (Baseline Comparison)

### Test Conditions
- Server: Linux kernel UDP socket bound to 0.0.0.0:15310
- Client: Local Python sends 20 UDP packets to 127.0.0.1:15310, one every 200ms

### Result

```
[MAIN] kernel-stack test, shutdown_how=0
[MAIN] bound to 0.0.0.0:15310
[RECV] pkt #1: 58 bytes
[RECV] pkt #2: 58 bytes
[RECV] pkt #3: 58 bytes
[SHUTDOWN] calling shutdown(sockfd, 0)...
[SHUTDOWN] ret=-1 errno=107 (Transport endpoint is not connected)
[POST-SHUTDOWN] received 58 bytes after shutdown (post=1)
[POST-SHUTDOWN] received 58 bytes after shutdown (post=2)
[POST-SHUTDOWN] received 58 bytes after shutdown (post=3)
[POST-SHUTDOWN] received 58 bytes after shutdown (post=4)
[POST-SHUTDOWN] received 58 bytes after shutdown (post=5)
[RESULT] FAIL: still receiving data after shutdown(how=0)
```

### Analysis

- `shutdown(sockfd, 0)` returns -1, errno=107 (ENOTCONN)
- After shutdown, **continues receiving** 5 data packets
- **Conclusion: Linux kernel stack SHUT_RD does not work for unconnected UDP (returns ENOTCONN and continues receiving)**

## 4. Comparison Summary

| Test | shutdown Return | Subsequent recvfrom Behavior | Conclusion |
|------|----------------|----------------------------|------------|
| F-Stack UDP SHUT_RD | 0 (success) | Returns 0 (EOF) | ✅ Correct |
| F-Stack UDP SHUT_WR | 0 (success) | sendto returns EPIPE | ✅ Correct |
| Linux kernel UDP SHUT_RD | -1 (ENOTCONN) | Continues receiving data | ❌ Not effective |

**Key Difference**: F-Stack (FreeBSD 15.0)'s `udp_shutdown` even when returning `ENOTCONN`, still calls `sorflush` to set `SBS_CANTRCVMORE`, causing subsequent `recvfrom` to return EOF. Linux kernel returns `ENOTCONN` without modifying socket state and continues receiving data.

F-Stack's behavior is actually more aligned with user expectations (no more receiving after shutdown), and `ff_shutdown` returns 0 (success) instead of ENOTCONN.
