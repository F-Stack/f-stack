# 05 - Conclusions and Recommendations

> f-stack issue #1076: CC (Concurrent Connections) limiting investigation conclusions for high CPS scenarios
> Investigation date: 2026-08-10
> Document basis: Reports 00-04
> Status: Pending user review

---

## 1. Investigation Summary

### 1.1 Issue #1076 Core Problem Review

User built transparent proxy with f-stack; single-core ~13k CPS stress test observed:
1. CPU reaches 100%, TCP connection teardown can't keep up with new connection rate.
2. Active connections accumulate, each holding send/receive buffer mbufs.
3. mbuf pool exhausts, entire stack unresponsive (including ff_ipc tools).

User request: **proactive packet dropping (graceful degradation / backpressure)** at performance limit, not entire application unresponsive.

### 1.2 Key Findings

1. **FreeBSD native 4 CC limiting mechanisms fully usable in f-stack** (report 02 code-level confirmed):
   - maxsockets: UMA zone max enforcement chain complete (`uma_core.c:4461` → `zone_alloc_limit`)
   - ipfw limit: Tool-side compilation complete, kernel-side O_LIMIT handling complete, dynamic state tracking complete non-stub. Limit behavior = `IP_FW_DENY` (drop)
   - somaxconn: Backlog truncation complete, incomplete queue drops oldest, complete queue 1.5× check
   - syncache: Bucket full drops oldest + syncache_pause, zone exhaustion degrades to syncookies

2. **mbuf pool water level backpressure is the only missing item**: Receive path (`ff_dpdk_if.c process_packets`) has no `rte_mempool_avail` check. mbuf pool size is static formula.

3. **ff_ipc uses independent message_pool**: ff_ipc uses independent `message_pool` (`FF_MSG_POOL`), not directly dependent on `pktmbuf_pool`. But f-stack main loop may not reach ff_ipc message processing path (`process_msg_ring`) when mbuf exhausts, indirectly causing ff_ipc tools to be unavailable — consistent with issue #1076's "ff_ipc netstat also unavailable" symptom.

4. **User's configuration contradiction**: `maxsockets=1048576` (1M) far exceeds mbuf pool capacity (~8K~32K). This is the direct cause of mbuf exhausting before sockets.

5. **Hands-on testing not completed due to environment limitation**: DPDK NIC and f-stack-client not on same Layer 2 network. Code-level conclusions are highly reliable but hands-on effect pending verification.

---

## 2. FreeBSD Native CC Limiting Mechanism Availability Conclusions

### 2.1 Four Mechanisms Completeness Confirmation

| Mechanism | Code Completeness | Official Docs | Hands-on | Overall |
|-----------|------------------|-------------|----------|---------|
| maxsockets | Complete | Yes | Not completed | **Usable** (code-level confirmed) |
| ipfw limit | Complete | Yes | Not completed | **Usable** (code-level confirmed) |
| somaxconn | Complete | Yes | Not completed | **Usable** (code-level confirmed) |
| syncache | Complete | Yes | Not completed | **Usable** (code-level confirmed) |

### 2.2 Code-Level Verification Highlights

- **maxsockets**: `uma_zone_set_max(socket_zone, maxsockets)` at SYSINIT. `zone_alloc_item()` (`uma_core.c:4461`) checks `uz_max_items`, returns NULL on overflow → `socreate()` returns `ENOBUFS`.

- **ipfw limit**: `ff_ipfw` tool compiles limit syntax. Kernel `O_LIMIT` (`ip_fw2.c:2937`) calls `ipfw_dyn_install_state()`. Dynamic state tracking (`ip_fw_dynamic.c`) allocation/lookup/insert/aging all complete. At limit: `DPARENT_COUNT(p) >= limit` → NULL → `IP_FW_DENY`.

- **somaxconn**: `solisten_proto()` truncates backlog to `V_somaxconn`. Incomplete queue full drops oldest. Complete queue `3 * sol_qlimit / 2` check.

- **syncache**: `syncache_init()` sets hashsize/bucketlimit via tunables. `uma_zone_set_max(zone, hashsize * bucket_limit)`. Bucket full drops oldest + `syncache_pause`. Zone exhaustion degrades to syncookies or drops SYN.

---

## 3. Recommended Solution

### 3.1 Recommended: Solution C (Combined)

| Defense Line | Mechanism | Purpose | Code Changes |
|-------------|-----------|---------|-------------|
| 1st | ipfw limit | per-source fine-grained | None |
| 2nd | maxsockets | global socket hard limit | None |
| 3rd | syncache + somaxconn | half-open + accept queue | None |
| 4th (optional) | mbuf water level backpressure | direct mbuf pool protection | Minor (optional) |

**Rationale**: Defense in depth, zero-code to start, progressive enhancement, directly addresses root cause.

### 3.2 Configuration Example

**config.ini** (first three lines, zero-code):
```ini
[freebsd.boot]
kern.ipc.maxsockets=256
net.inet.tcp.syncache.hashsize=512
net.inet.tcp.syncache.bucketlimit=30

[freebsd.sysctl]
kern.ipc.somaxconn=128
```

**ff_ipfw rules**:
```bash
ff_ipfw add allow tcp from any to <DPDK_NIC_IP> 80 setup limit src-addr 50
```

---

## 4. Honest Boundaries

### 4.1 Unverified Parts

| Item | Status | Reason |
|------|--------|--------|
| High CPS mbuf exhaustion reproduction | Not completed | DPDK NIC L2 network unreachable |
| maxsockets limit-reached behavior | Not completed | Cannot generate enough connections |
| ipfw limit rule hands-on effect | Not completed | Cannot generate TCP connections |
| somaxconn/syncache limit behavior | Not completed | Same |
| mbuf water level threshold quantification | Not completed | Needs high CPS stress test env |

### 4.2 Applicability Conditions and Limitations

1. **maxsockets value depends on estimation**: Limits socket count, not mbuf consumption directly. Per-connection mbuf varies widely (idle ~12 vs full ~16384).
2. **ipfw limit can't prevent distributed accumulation**: Many different sources each under per-source limit but global total still accumulates. Needs maxsockets backstop.
3. **Solution B threshold needs hands-on testing**: `mbuf_low_watermark` reasonable value depends on mbuf pool size and connection pattern.
4. **Code-level ≠ hands-on effect**: Code paths verified complete but runtime behavior may be affected by other factors.
5. **ff_ipc mbuf dependency**: ff_ipc uses independent message_pool, but f-stack main loop may not reach ff_ipc processing path when mbuf exhausts.

---

## 5. Future Recommendations

### 5.1 For Hands-on Verification

Need to fix network environment: DPDK NIC and f-stack-client on same L2 network (virtual switch config), or migrate f-stack-client to DPDK NIC's network.

### 5.2 For Implementing Solution B (mbuf Water Level Backpressure)

| File | Line | Change |
|------|------|--------|
| `lib/ff_dpdk_if.c` | 2024 (process_packets entry) | Add mbuf water level check + SYN early drop |
| `lib/ff_dpdk_if.c` | New | `is_tcp_syn()` helper function |
| `lib/ff_config.c` / `ff_config.h` | New | Parse `mbuf_low_watermark` config |
| `config.ini` | `[dpdk]` section | New config item |

### 5.3 Items for User Review

1. **maxsockets target value**: Conservative 256, liberal 4096, or calculate from actual mbuf pool?
2. **Whether to enable Solution B (code change)**: ~20 lines lib code change acceptable?
3. **Whether to lower TCP buffers**: Lowering sendbuf_max/recvbuf_max limits per-connection mbuf peak but affects throughput.
4. **ipfw limit per-source value N**: Depends on client connection pattern. N=50? 100?
5. **Whether to fix test environment**: Network connectivity issue from report 04.
6. **Whether to update issue-ana entry**: Current entry is preliminary; this investigation deepened conclusions.
