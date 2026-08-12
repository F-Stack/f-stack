# Issue #631 Investigation Overview

## 1. Issue Information

| Item | Content |
|------|---------|
| Issue | F-Stack/f-stack #631 |
| Title | ff_shutdown() not working on UDP sockets |
| Author | sarosharif |
| Date | 2021-12-29 |
| Status | Open |
| Problem | After calling `ff_shutdown(sockfd, 0)` (SHUT_RD) on a UDP socket, data can still be received; TCP works normally |

## 2. Conclusion Summary

**Issue #631 does not reproduce in the current F-Stack 1.26 + FreeBSD 15.0 + DPDK 24.11.6 environment.**

`ff_shutdown(SHUT_RD)` works correctly on UDP sockets:
- Returns 0 (success)
- Subsequent `ff_recvfrom` immediately returns 0 (EOF), no more data received
- 3 repeated tests with consistent results

Comparison testing shows F-Stack's behavior is actually better than the Linux kernel stack: Linux kernel returns `ENOTCONN` for unconnected UDP `shutdown(SHUT_RD)` and continues receiving data, while F-Stack returns 0 and correctly stops receiving.

## 3. Test Results Summary

| Test ID | Stack Type | how | shutdown Return | Subsequent Behavior | Result |
|---------|-----------|-----|-----------------|---------------------|--------|
| T1 (x3) | F-Stack | SHUT_RD | 0 | recvfrom→0 (EOF) | ✅ PASS |
| T2 | F-Stack | SHUT_WR | 0 | sendto→EPIPE | ✅ PASS |
| T5 | Kernel stack | SHUT_RD | -1 (ENOTCONN) | Continues receiving data | ❌ Kernel behavior |

## 4. Root Cause Analysis

### 4.1 Call Chain

```
ff_shutdown (lib/ff_syscall_wrapper.c:1862)
  → sys_shutdown → kern_shutdown (freebsd/kern/uipc_syscalls.c:1328)
    → soshutdown (freebsd/kern/uipc_socket.c:3673)
      → udp_shutdown (freebsd/netinet/udp_usrreq.c:1741)
        → sorflush (freebsd/kern/uipc_socket.c:3688)     [SHUT_RD]
          → socantrcvmore (freebsd/kern/uipc_sockbuf.c:408)
            → sets so->so_rcv.sb_state |= SBS_CANTRCVMORE
          → sbrelease(so, SO_RCV)
        → socantsendmore (SHUT_WR)
```

### 4.2 Key Findings

1. `udp_shutdown` returns `ENOTCONN` for unconnected UDP, but **still calls `sorflush(so)`** (`udp_usrreq.c:1768`)
2. `sorflush` calls `socantrcvmore` which sets the `SBS_CANTRCVMORE` flag
3. `soreceive_dgram` (`uipc_socket.c:3537`) checks `SBS_CANTRCVMORE` and returns 0 (EOF) when set
4. `kern_shutdown` (`uipc_syscalls.c:1349-1351`) converts `ENOTCONN` to 0 (because F-Stack's `p_osrel=0 < P_OSREL_SHUTDOWN_ENOTCONN=1100077`)

### 4.3 Differences from Older Versions

FreeBSD 15.0's `soshutdown` fully delegates to `pr_shutdown` (protocol callback), while older `soshutdown` handled `sorflush`/`socantsendmore` itself. `udp_shutdown` calls `sorflush` in all versions, but `soreceive_dgram`'s check for `SBS_CANTRCVMORE` is more complete in 15.0.

## 5. Recommendations

1. Issue #631 can be considered for closure, annotated "does not reproduce in latest version"
2. Recommend user upgrade to latest F-Stack dev branch (FreeBSD 15.0 + DPDK 24.11.6) and retry
3. If the problem persists, please provide complete config.ini and test code
