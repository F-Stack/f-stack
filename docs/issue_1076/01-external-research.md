# 01 - External Research and Cross-Validation

> This document summarizes external research results for issue #1076 (CC limiting at high CPS), cross-validating FreeBSD native mechanisms, other userspace stack approaches, and DPDK backpressure practices.
> Research date: 2026-08-10
> Research method: web_search + web_fetch (FreeBSD official manual, nginx tuning docs, technical blogs, GitHub)

---

## 1. FreeBSD Native CC Limiting Mechanism Documentation Verification

### 1.1 maxsockets (Global Socket Count Hard Limit)

**Official documentation/sources**:
- FreeBSD manual pages / community docs: `kern.ipc.maxsockets` sets the maximum number of sockets the system can open.
- The value must be set at boot time (`/boot/loader.conf`), corresponding to f-stack's `config.ini [freebsd.boot]` section.

**Behavior**:
- When socket count reaches maxsockets limit, `socreate()` returns `ENOBUFS` or `ENFILE`.
- This is a UMA zone-level hard limit (`uma_zone_set_max`).

**F-stack correspondence**:
- F-stack's `config.ini` supports `kern.ipc.maxsockets` configuration (via `[freebsd.boot]` section).
- Issue #1076 user set `maxsockets=1048576` (1M), which is very large, meaning socket structures are unlikely to exhaust before mbufs.

**Key conclusion**: maxsockets is an effective global socket count limit, but issue #1076's problem is that maxsockets is set too large (1M), while the mbuf pool capacity is far smaller than what's needed to support 1M active TCP connections (each connection needs sendspace 64KB + recvspace 64KB = 128KB mbuf; 1M connections need ~128GB mbuf). **Lowering maxsockets to match mbuf pool capacity** may be the simplest native solution.

### 1.2 ipfw limit (per-source connection count limit)

**Official documentation**: FreeBSD manual page IPFW(8) — https://man.freebsd.org/cgi/man.cgi?ipfw

**Syntax**:
```
limit {src-addr | src-port | dst-addr | dst-port} N [:flowname]
```

**Behavior** (confirmed by official documentation):
- The firewall only allows N connections with the same parameter set specified in the rule.
- When N matching dynamic rules already exist, **new connection requests will not create new dynamic rules**, and thus will not pass state inspection (i.e., will be rejected/dropped).
- `limit` implies an **implicit `check-state`**, effective for all packets.
- Dynamic rules have a limited lifetime (controlled by sysctl variables), refreshed on each match.

**Typical usage**:
```bash
# Limit each source address to max 5 concurrent TCP connections
ipfw add allow tcp from any to any setup limit src-addr 5
```

**F-stack correspondence**:
- F-stack has compiled ipfw (`FF_IPFW=1`), tool side is `ff_ipfw`.
- Theoretically can use `ff_ipfw add allow tcp from any to any setup limit src-addr N` for per-source limiting.
- **To verify**: whether dynamic state tracking (`ip_fw_dynamic.c`) fully works in userspace stack.

**Key conclusion**: ipfw limit is FreeBSD's native per-source/per-dst connection count limiting mechanism. F-stack has ipfw code compiled in; theoretically usable but needs hands-on verification of dynamic state tracking completeness in userspace.

### 1.3 somaxconn (Accept Queue Limit)

**Official documentation**:
- nginx FreeBSD tuning docs: FreeBSD allows receiving 1.5 times the somaxconn limit before discarding new connections.
- FreeBSD default `SOMAXCONN=128`.

**Limitations**:
- Only limits listen backlog (accept queue depth), **does not limit total active accepted connections**.
- For issue #1076's scenario (connections established but teardown slow causing accumulation), somaxconn cannot directly help.

**Key conclusion**: somaxconn can be an auxiliary measure to limit burst connections, but has limited effect on issue #1076's core problem (active connection accumulation causing mbuf exhaustion).

### 1.4 nmbclusters (Network mbuf Cluster Limit)

**F-stack correspondence**:
- F-stack does not use kernel nmbclusters, but uses DPDK's `rte_mempool` (`pktmbuf_pool`).
- DPDK mbuf pool size is determined by formula in `ff_dpdk_if.c` (based on RX/TX queue size, burst size, dispatch ring size, KNI, etc.).
- F-stack lacks the proactive water level check and backpressure mechanism that kernel nmbclusters exhaustion provides.

**Key conclusion**: FreeBSD kernel's nmbclusters mechanism corresponds to f-stack's DPDK mbuf pool, but f-stack lacks the proactive backpressure when approaching exhaustion (dropping new SYNs).

---

## 2. Other Userspace Network Stack Approaches

### 2.1 mTCP

- Each CPU core has independent connection pool, avoiding shared fd space limitations.
- Per-core connection pool has fixed size; when full, `mtcp_epoll_accept()` no longer returns new connections (implicit CC limit).
- No explicit mbuf water level check or proactive packet drop mechanism found in mTCP paper.

### 2.2 Seastar

- Share-nothing architecture, each core runs an independent reactor.
- Connections managed by per-core TCP stack; connection count limited by per-core memory.
- No explicit CC limiting/backpressure mechanism documentation found.

---

## 3. DPDK mbuf Pool Backpressure Practices

### 3.1 DPDK rte_mempool Query Capabilities

**Available query APIs**:
- `rte_mempool_avail(mp)` — returns available objects in pool
- `rte_mempool_in_use_count(mp)` — returns used object count
- `rte_mempool_count(mp)` — returns total object count

**Community practices**:
- No standard "mbuf pool water level check + proactive packet drop" backpressure solution found in DPDK community.
- DPDK's design philosophy is "pre-allocate sufficiently large pool" rather than runtime backpressure.
- Some applications implement their own water level checks (periodically check `rte_mempool_avail`, reject new connections below threshold).

**F-stack correspondence**:
- F-stack can check `rte_mempool_avail(pktmbuf_pool)` in the receive path (`ff_dpdk_if.c`), dropping inbound SYN packets below threshold.
- This is a f-stack-specific minor change (requires lib code modification).

---

## 4. F-stack GitHub Related Issues/Discussions

- No other issues directly discussing mbuf exhaustion/CC limiting/backpressure found in F-Stack/f-stack repository besides #1076.
- Related issues (indirectly):
  - #93: CPS testing bottleneck from single client port limit and PCB lock contention
  - #410: Multi-core non-persistent connection CPS improvement bottleneck on client-side ephemeral ports
  - #868: Memory not released (DPDK hugepage pre-allocation + glibc ptmalloc2 deferred free)

---

## 5. Cross-Validation Conclusions

### 5.1 FreeBSD Native Mechanism Availability Assessment

| Mechanism | Official Docs Confirmed | F-stack Code Present | Expected Effect | Verification Priority |
|---|---|---|---|---|
| maxsockets | Yes | Yes (UMA zone max) | Limit global socket count; lower to prevent mbuf exhaustion | High (simplest) |
| ipfw limit | Yes (syntax+behavior) | Yes (FF_IPFW=1) | Per-source connection count limit; drop at limit | High (precise control) |
| somaxconn | Yes | Yes | Only accept queue; does not limit active connections | Low (auxiliary) |
| syncache | Yes | Yes | Only half-open connections | Low (auxiliary) |

### 5.2 Recommended Solution Direction

1. **Zero-code solution (pure config)**: Lower `maxsockets` to match mbuf pool capacity + `ipfw limit` for per-source fine-grained limiting.
2. **Minor change solution (mbuf water level backpressure)**: Check `rte_mempool_avail(pktmbuf_pool)` in `ff_dpdk_if.c` receive path; drop inbound SYN below threshold.
3. **Combined solution**: maxsockets as global hard limit + ipfw limit as per-source fine-grained limit + optional mbuf water level backpressure as last line of defense.

### 5.3 Honest Boundaries

- **ipfw limit dynamic state tracking completeness in userspace stack**: External docs confirm syntax and behavior, but userspace implementation completeness needs code-level verification (confirmed in report 02).
- **maxsockets UMA zone max enforcement in userspace**: Needs code-level verification of `uma_zone_set_max` logic in f-stack UMA implementation (confirmed in report 02).
- **mbuf water level backpressure threshold determination**: Requires hands-on testing to determine reasonable mbuf pool water level threshold (data provided in report 04).
- No DPDK community standard backpressure solution found externally, indicating this is an application-layer issue that f-stack needs to design itself.
