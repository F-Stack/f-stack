# 03 - Solution Design and Alternative Comparison

> f-stack issue #1076: CC (Concurrent Connections) limiting solution design for high CPS scenarios
> Design basis: 00-issue original, 01-external research, 02-code investigation, 04-handson test
> Design date: 2026-08-10
> Status: Solution design (pending user review), no code changes implemented

---

## 1. Solution Overview

Issue #1076's core problem: under single-core high CPS, TCP connection teardown can't keep up with new connection arrival rate; active connections accumulate, each consuming mbufs for send/receive buffers; eventually mbuf pool exhausts causing entire stack unresponsive.

Report 02 has code-confirmed that FreeBSD's 4 native CC limiting mechanisms (maxsockets / ipfw limit / somaxconn / syncache) are **fully usable** in f-stack. The only missing item is mbuf pool water level backpressure.

Based on these findings, three tiers of alternatives are designed:

| Tier | Solution | Code Changes | Core Mechanism | Applicable Scenario |
|------|---------|-------------|----------------|---------------------|
| Zero-code | Solution A | None | Lower maxsockets + ipfw limit + syncache tuning | Quick deployment with zero changes |
| Minor change | Solution B | ~20 lines in lib receive path | mbuf pool water level backpressure, drop SYN below threshold | Need direct mbuf pool protection |
| Combined | Solution C | None (or optional Solution B) | Solution A + Solution B (optional) | Recommended for production |

---

## 2. Solution A: Zero-Code (Pure Configuration Tuning)

### 2.1 Core Approach

Utilize f-stack's already-compiled FreeBSD native CC limiting mechanisms by adjusting `config.ini` + `ff_ipfw` rules, with **no code changes**.

Three lines of defense:

1. **maxsockets (global hard limit)**: Limit total socket count. Lower to match mbuf pool capacity.
2. **ipfw limit (per-source fine-grained limit)**: Limit concurrent connections per source address.
3. **syncache (half-open burst limit)**: Limit half-open connections during SYN flood/burst.

### 2.2 maxsockets Value Calculation Basis

**Recommended maxsockets calculation**:
```
maxsockets = (available mbuf count × safety factor 0.7) / estimated mbuf per connection
```

Example with mbuf pool 32768, ~16000 available, 12 mbuf per connection (idle):
```
maxsockets = 16000 × 0.7 / 12 ≈ 933 → round to 1024
```

Example with 64 mbuf per connection (conservative, including stack overhead):
```
maxsockets = 16000 × 0.7 / 64 ≈ 175 → round to 256
```

**Note**: maxsockets limits socket structure count (UMA zone), not directly mbuf consumption. A socket's send/receive buffer mbuf consumption is dynamic. maxsockets ensures **total connections don't grow unbounded** but cannot precisely prevent individual connection buffer bloat causing mbuf exhaustion. Therefore needs ipfw limit for per-source restriction.

### 2.3 Configuration Example

```ini
[freebsd.boot]
# Global socket count limit. Lower to match mbuf pool.
kern.ipc.maxsockets=4096

# syncache hash size and bucket limit. Limit half-open burst.
net.inet.tcp.syncache.hashsize=1024
net.inet.tcp.syncache.bucketlimit=50

[freebsd.sysctl]
# accept queue depth. Lower to match application accept rate.
kern.ipc.somaxconn=1024
```

### 2.4 ipfw limit Rule Example

```bash
# Limit each source address to max 100 concurrent TCP connections
ff_ipfw add allow tcp from any to <DPDK_NIC_IP> 80 setup limit src-addr 100

# Global concurrent connection limit (using all mask)
ff_ipfw add allow tcp from any to <DPDK_NIC_IP> setup limit all 5000
```

### 2.5 Pros / Cons / Applicable Scenarios

**Pros**: Zero code changes; uses verified FreeBSD native mechanisms; quick deployment.
**Cons**: maxsockets limits socket count, not mbuf consumption; can't protect mbuf pool itself.
**Applicable**: Want zero-change basic CC limiting; relatively uniform connection patterns.

---

## 3. Solution B: Minor Change (mbuf Pool Water Level Backpressure)

### 3.1 Core Approach

Add mbuf pool water level check in f-stack receive path. When `pktmbuf_pool` available mbufs fall below threshold, **proactively drop inbound SYN packets** (no SYN-ACK reply), preventing new connections from consuming mbufs, protecting existing connections and system components.

### 3.2 Insertion Point

**Recommended: `process_packets()` entry** (`ff_dpdk_if.c:2024`):
1. Before protocol stack, doesn't affect existing connections
2. Can check at burst level (per burst, not per packet)
3. Minimal code intrusion

### 3.3 Pseudocode

```c
/* Water level check at burst level */
int mbuf_low = 0;
if (!pkts_from_ring) {
    unsigned avail = rte_mempool_avail(pktmbuf_pool[qconf->socket_id]);
    if (avail < mbuf_low_watermark) {
        mbuf_low = 1;
    }
}

for (i = 0; i < count; i++) {
    /* Backpressure: drop SYN when low water level */
    if (mbuf_low && is_tcp_syn(data, len)) {
        ff_traffic.rx_dropped += rtem->nb_segs;
        rte_pktmbuf_free(rtem);
        continue;  /* Don't enter protocol stack, no SYN-ACK */
    }
    /* ... original process_packets logic ... */
}
```

### 3.4 Threshold Determination

```
mbuf_low_watermark = mbuf pool total capacity × 10%
```

Example: pool 32768 → threshold = 3276. Actual value needs stress testing.

### 3.5 Pros / Cons / Applicable Scenarios

**Pros**: Directly protects mbuf pool; protects existing connections (only drops SYN); threshold configurable.
**Cons**: Requires ~20 lines lib code change + recompile; threshold needs stress testing.
**Applicable**: Need direct mbuf pool protection; native mechanisms insufficient.

---

## 4. Solution C: Combined (Recommended)

### 4.1 Core Approach

Combine Solutions A and B for multi-layer defense:

| Defense Line | Mechanism | Purpose | Code Changes |
|-------------|-----------|---------|-------------|
| 1st | ipfw limit | per-source fine-grained limit | None |
| 2nd | maxsockets | global socket count hard limit | None |
| 3rd | syncache + somaxconn | half-open burst + accept queue | None |
| 4th (optional) | mbuf water level backpressure | last line, direct mbuf pool protection | Minor (optional) |

### 4.2 Configuration Example

**config.ini**:
```ini
[freebsd.boot]
kern.ipc.maxsockets=256
net.inet.tcp.syncache.hashsize=512
net.inet.tcp.syncache.bucketlimit=30

[freebsd.sysctl]
kern.ipc.somaxconn=128
```

**ff_ipfw rules** (loaded at startup):
```bash
ff_ipfw add allow tcp from any to <DPDK_NIC_IP> 80 setup limit src-addr 50
```

**mbuf water level backpressure (optional, Solution B)**:
```ini
[dpdk]
mbuf_low_watermark=3276
```

### 4.3 Defense Line Coordination Logic

```
New SYN arrives
    │
    ▼
[1st] ipfw limit check → per-source count > N? → Yes → IP_FW_DENY (drop)
    │ No ↓
[2nd] maxsockets check (at socreate) → global sockets > max? → Yes → ENOBUFS (reject)
    │ No ↓
[3rd] syncache check → bucket full? → Yes → drop oldest + syncache_pause
    │ No ↓
[4th, optional] mbuf water level → avail < threshold? → Yes → drop SYN (no SYN-ACK)
    │ No ↓
Normal connection establishment
```

### 4.4 Pros / Cons

**Pros**: Multi-layer defense; first three lines zero-code; progressive enhancement.
**Cons**: Multiple config items need tuning; maxsockets value depends on estimation.

---

## 5. Solution Comparison Table

| Dimension | Solution A (Zero-code) | Solution B (Minor change) | Solution C (Combined, Recommended) |
|-----------|----------------------|------------------------|--------------------------------|
| Code changes | None | ~20 lines (ff_dpdk_if.c) | None (or optional B) |
| Recompile | No | Yes | No (or optional) |
| Limit dimension | socket count + per-source | mbuf pool water level | All dimensions |
| Protect mbuf pool | Indirect (limit connections) | Direct (water level check) | Direct + indirect |
| Protect existing connections | Yes (new rejected) | Yes (only drop SYN) | Yes |
| Accuracy | Medium (socket count ≠ mbuf) | High (direct mbuf check) | High |
| Deployment difficulty | Low (config) | Medium (code + compile) | Low-Medium |
| Prevent single connection bloat | No | Yes | Yes |
| Prevent distributed accumulation | Partial (maxsockets backstop) | Yes | Yes |

---

## 6. Recommendation and Rationale

### 6.1 Recommended: Solution C (Combined)

**Rationale**:
1. **Defense in depth**: Multi-layer defense complements each other
2. **Zero-code to start**: First three lines use verified native mechanisms
3. **Progressive enhancement**: Deploy zero-code first, add Solution B if needed
4. **Directly addresses root cause**: Solution B's mbuf water level backpressure directly targets issue #1076's root cause (mbuf exhaustion)
5. **Manageable risk**: Code-level verification (report 02) confirms mechanisms A-D complete

### 6.2 Implementation Steps

| Step | Content | Prerequisite | Code Changes |
|------|---------|-------------|-------------|
| 1 | Deploy first three lines (lower maxsockets + ipfw limit + syncache/somaxconn) | None | None |
| 2 | Stress test, observe if mbuf exhaustion still occurs | Fix test env network | None |
| 3 | If still exhausting, implement Solution B (mbuf water level backpressure) | Code review + clean build + unit test | ~20 lines |
| 4 | Stress test to determine mbuf_low_watermark threshold | External high CPS traffic generator | None |
| 5 | Deploy complete Solution C | Steps 1-4 complete | None |

### 6.3 Items for User Review

1. **maxsockets target value**: Accept conservative 256, or liberal 4096, or calculate from actual mbuf pool?
2. **Whether to enable Solution B (code change)**: Accept ~20 lines lib code change?
3. **Whether to lower TCP buffers**: Lowering sendbuf_max/recvbuf_max limits per-connection mbuf peak but affects throughput.
4. **ipfw limit per-source value N**: Depends on client connection pattern. N=50? 100?
5. **Whether to fix test environment for hands-on verification**: Network connectivity issue from report 04.
