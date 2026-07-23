# F-Stack Software LRO Solution

> Document tier: Software LRO solution (software offload supplementary design 1)
> Design basis: `02-current-status-and-gap-analysis.md`, `04-solution-and-architecture-design.md` (hardware LRO path); this document focuses on **software LRO** (FreeBSD `tcp_lro.c`), as a supplementary/fallback path when hardware LRO is unavailable.
> Authoritative version: DPDK `dpdk-stable-24.11.6`, FreeBSD 15.0 port (`f-stack/freebsd/`).
> Iron rule: This round **does not write code, does not change lib, does not commit**, only produces an actionable solution. All code references include precise `file:line`; all conclusions involving specific PMD/runtime behavior are marked "**pending runtime validation**".

---

## 0. Why Software LRO Is Needed

### 0.1 Hardware LRO Limitations

Hardware LRO (`04-solution-and-architecture-design.md` section I) depends on NIC PMD advertising `RTE_ETH_RX_OFFLOAD_TCP_LRO` in `dev_info.rx_offload_capa` (`dpdk-stable-24.11.6/lib/ethdev/rte_ethdev.h:1556`). When any of the following conditions are met, hardware LRO is unavailable:

- **PMD doesn't support LRO offload**: e.g., local virtio (`03-external-research.md` 2.3: virtio offload capability limited by backend `VIRTIO_NET_F_HOST_TSO4/6`, `GUEST_TSO4/6` etc. feature negotiation; local actual test `guest_features=0x110ef8020` **doesn't include LRO/large-receive-related bits**) — **pending runtime validation**: whether `dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO` is 0 under local virtio.
- **Software forwarding/tunnel scenarios**: VxLAN etc. inner TCP cannot be aggregated by hardware.
- **Need LRO receive benefits in generic environments without dedicated hardware**.

Therefore software LRO is a **functionally equivalent supplement** to hardware LRO: CPU aggregates multiple packets from the same TCP flow into one large segment on the receive path before delivering to the protocol stack, reducing protocol stack per-packet processing overhead.

### 0.2 F-Stack Software LRO Current Status (Code Verified)

- **Already compiled**: `lib/Makefile:513` compiles `tcp_lro.c` (software LRO core is in the compilation unit).
- **No call sites**: All `lib/*.c` search for `tcp_lro_init` / `tcp_lro_rx` / `tcp_lro_queue_mbuf` / `tcp_lro_flush_all` etc. **hits 0** → software LRO is in a "**compiled but completely uncalled**" state.
- **Receive entry not connected**: `ff_veth_input` (`ff_dpdk_if.c:1707`) directly `ff_mbuf_gethdr` → `ff_veth_process_packet` → `if_input`, **no LRO aggregation step in between**.

**Conclusion**: The only substantive gap in software LRO = **not integrated into the `ff_veth_input` receive path**. API and core algorithm are ready, only missing "lifecycle management + receive path integration" two pieces of glue code.

---

## 1. tcp_lro API and struct lro_ctrl Lifecycle

### 1.1 Core API (`tcp_lro.c` / `tcp_lro.h`)

| API | Definition Location | Declaration | Purpose |
| --- | --- | --- | --- |
| `tcp_lro_init(struct lro_ctrl *)` | `tcp_lro.c:167` | `tcp_lro.h:215` | Simple init, internally calls `tcp_lro_init_args(lc, NULL, tcp_lro_entries, 0)` (`tcp_lro.c:170`, `lro_mbufs=0` → **classic mode**, no sort array) |
| `tcp_lro_init_args(struct lro_ctrl *, struct ifnet *, unsigned lro_entries, unsigned lro_mbufs)` | `tcp_lro.c:173` | `tcp_lro.h:216` | Full init, when `lro_mbufs>0` allocates sort array → **modern RSS sorted mode** |
| `tcp_lro_free(struct lro_ctrl *)` | `tcp_lro.c:491` | `tcp_lro.h:217` | Free `lro_ctrl` internal resources (hash table, mbuf array, active/free chains) |
| `tcp_lro_rx(struct lro_ctrl *, struct mbuf *, uint32_t csum)` | `tcp_lro.c:1426` | `tcp_lro.h:221` | **Classic mode** per-packet entry: directly attempts aggregation, on failure `tcp_lro_flush_active` (`tcp_lro.c:1441`) preserves order |
| `tcp_lro_queue_mbuf(struct lro_ctrl *, struct mbuf *)` | `tcp_lro.c:1448` | `tcp_lro.h:222` | **Modern mode** per-packet entry: queues mbuf into `lro_mbuf_data` array, triggers flush when full |
| `tcp_lro_flush_all(struct lro_ctrl *)` | `tcp_lro.c:1199` | `tcp_lro.h:219` | **Modern mode** batch-end aggregation: sorts array by flow (`tcp_lro_sort`) then aggregates per-flow |
| `tcp_lro_flush` (static) | `tcp_lro.c:1108` | internal | Single-flow aggregation落地: `tcp_lro_condense` + `tcp_flush_out_entry` |

### 1.2 struct lro_ctrl (`tcp_lro.h:161-181`)

```c
struct lro_ctrl {
    struct ifnet    *ifp;                 /* L162: bound interface, flush delivers via (*ifp->if_input)() */
    struct lro_mbuf_sort *lro_mbuf_data;  /* L163: modern mode sort array (NULL in classic mode) */
    struct bintime  lro_last_queue_time;  /* L164 */
    uint64_t        lro_queued;           /* L165: statistics */
    uint64_t        lro_flushed;          /* L166 */
    uint64_t        lro_bad_csum;         /* L167 */
    unsigned        lro_cnt;              /* L168: lro_entry count (active flow limit) */
    unsigned        lro_mbuf_count;       /* L169: currently queued mbuf count */
    unsigned        lro_mbuf_max;         /* L170: sort array capacity (=init_args lro_mbufs) */
    ...
    struct lro_head *lro_hash;            /* L177: flow hash buckets */
    struct lro_head lro_active;           /* L178: active aggregation flow chain */
    struct lro_head lro_free;             /* L179: free entry chain */
    uint8_t         lro_cpu_is_set;       /* L180 */
};
```

- **`ifp` required**: flush落地 delivers via `lc->ifp->if_input` (`tcp_lro.c:1252`). When software LRO is integrated into F-Stack, `ifp` must be bound to F-Stack's veth interface (i.e., `ctx->ifp`).
- **`lro_mbuf_data`**: Only allocated in modern mode; when `lro_mbuf_max=0` (`tcp_lro_init` default) it's NULL, `tcp_lro_queue_mbuf` will drop packets due to `lro_mbuf_max==0` (`tcp_lro.c:1453-1457`) → **classic mode prohibits queue_mbuf**.

### 1.3 Two Modes Comparison

| Dimension | Classic Mode (init + rx) | Modern RSS Sorted Mode (init_args + queue_mbuf + flush_all) |
| --- | --- | --- |
| Initialization | `tcp_lro_init(lc)` (`tcp_lro.c:167`, lro_mbufs=0) | `tcp_lro_init_args(lc, ifp, entries, mbufs>0)` (`tcp_lro.c:173`) |
| Per-packet entry | `tcp_lro_rx(lc, m, csum)` (`tcp_lro.c:1426`) **immediate aggregation attempt** | `tcp_lro_queue_mbuf(lc, m)` (`tcp_lro.c:1448`) **queue only** |
| Batch-end processing | Not needed (rx aggregates internally, fails → flush_active) | `tcp_lro_flush_all(lc)` (`tcp_lro.c:1199`) **sort then batch aggregate** |
| Sort array | Not used | Uses `lro_mbuf_data`, radix sort by flow seq (`tcp_lro_sort` `tcp_lro.c:1135`) improves aggregation rate |
| Ordering | rx fails → `tcp_lro_flush_active` (`tcp_lro.c:1441`) | flush_all groups by flow, cross-flow sort doesn't affect intra-flow ordering |
| **NULL bare-call risk** | **None** (`tcp_lro_rx` doesn't call `tcp_hpts_softclock`) | **Has** (`tcp_lro_flush_all:1261` bare-call, see section 3) |
| Applicable scenario | Single queue/simple aggregation | Hardware RSS already distributed, batch receive (iflib uses) |

**Key conclusion**: Classic mode (`tcp_lro_rx`) **does not trigger** `tcp_lro.c:1261`'s `tcp_hpts_softclock()` bare-call, is F-Stack's preferred integration path (see section 3).

### 1.4 iflib Golden Pattern (Reference Only, F-Stack Doesn't Use iflib)

FreeBSD's general driver framework iflib's software LRO usage is the "textbook pattern"; F-Stack **replicates its structure** when integrating (but doesn't use iflib itself):

| Phase | iflib Location | Action |
| --- | --- | --- |
| Field | `iflib.c:462` | One `struct lro_ctrl ifr_lc` per rxq (per-queue placement) |
| Initialization | `iflib.c:6035` | `tcp_lro_init_args(&rxq->ifr_lc, ...)` (once per rxq) |
| Gating | `iflib.c:2999` | `if (lro_enabled)` (only LRO when `IFCAP_LRO` enabled) |
| Per-packet | `iflib.c:3000` | `tcp_lro_queue_mbuf(&rxq->ifr_lc, m)` (modern mode queue) |
| Batch-end | `iflib.c:3029` | `tcp_lro_flush_all(&rxq->ifr_lc)` (flush at receive batch end) |
| Free | `iflib.c:6056` / `iflib.c:6079` | `tcp_lro_free(&rxq->ifr_lc)` (at rxq destruction) |

**Key differences between F-Stack and iflib**:
- iflib uses **modern mode** (queue_mbuf + flush_all), therefore hits `tcp_lro.c:1261` bare-call; in iflib environment `tcp_hpts_softclock` is a **real implementation** (not NULL), so no crash. **F-Stack's `tcp_hpts_softclock` is a NULL stub** (`ff_stub_14_extra.c:627`), directly replicating modern mode would crash (see section 3).
- iflib is multi-queue multi-threaded; F-Stack is **single-threaded run-to-completion** (each lcore exclusively owns a set of queues), `lro_ctrl` should be placed **per-lcore/per-port**, no locks needed.

---

## 2. F-Stack Software LRO Integration Solution

### 2.1 Receive Integration Point

- **Entry**: `ff_veth_input` (`ff_dpdk_if.c:1707`). Current flow:
  - `ff_dpdk_if.c:1710-1715`: when `rx_csum`, checks `RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD`, drops if bad.
  - `ff_dpdk_if.c:1720`: `ff_mbuf_gethdr(pkt, pkt->pkt_len, data, len, rx_csum)` builds FreeBSD mbuf header.
  - `ff_dpdk_if.c:1737-1751`: traverses `pkt->next` multi-segment chain.
  - `ff_dpdk_if.c:1753`: `ff_veth_process_packet(ctx->ifp, hdr)` → `if_input`.
- **Software LRO insertion point**: After `ff_mbuf_gethdr` (`ff_dpdk_if.c:1720`) **builds FreeBSD mbuf (`hdr`)**, before delivering to `if_input`, feed `hdr` (FreeBSD `struct mbuf *`) to `tcp_lro_rx` (classic mode); aggregation success is delivered later by LRO internally, aggregation failure/non-TCP is delivered by LRO internally or fallback logic via original `if_input`.

**Key constraint**: `tcp_lro_rx` parameter is **FreeBSD `struct mbuf *`** (not DPDK `rte_mbuf`). F-Stack receive path gets FreeBSD mbuf (`hdr`) after `ff_mbuf_gethdr`, so software LRO integration point must be **after** `ff_mbuf_gethdr`, after multi-segment chain attachment is complete (`hdr` is the complete mbuf chain head), then handed to LRO.

### 2.2 per-lcore/per-port lro_ctrl Placement

F-Stack single-threaded run-to-completion, each lcore exclusively owns queues, **no locks needed**. `lro_ctrl` placement:

| Phase | Placement Location (Design) | Action |
| --- | --- | --- |
| Definition | Add `struct lro_ctrl lro` to `ff_dpdk_if_context` or per-lcore/per-port context (one per port/lcore) | Corresponds to iflib `ifr_lc` (`iflib.c:462`) |
| Initialization | Port/lcore init path (`ff_dpdk_if.c` port setup or after `ff_veth` registration), only when software LRO switch enabled | `tcp_lro_init(&lro)` bind `lro.ifp = ctx->ifp` (**classic mode**) |
| Per-packet | `ff_veth_input` (after `ff_dpdk_if.c:1720`) | `tcp_lro_rx(&lro, hdr, 0)`; non-0 return (not aggregated/non-TCP) falls back to `ff_veth_process_packet` original path |
| Batch-end | At receive batch loop end (`ff_dpdk_process_packets` etc., after a batch of `rte_eth_rx_burst` processed) | In classic mode `tcp_lro_rx` already aggregates immediately; batch-end optionally calls `tcp_lro_flush_inactive` (`tcp_lro.h:218`, flushes timed-out incomplete flows by time), **do not call `tcp_lro_flush_all`** |
| Free | Port/lcore cleanup path | `tcp_lro_free(&lro)` |

> **`lro.ifp` binding**: After `tcp_lro_rx` aggregation success, `tcp_lro_flush` → `tcp_flush_out_entry` → finally delivers via `lc->ifp->if_input` (`tcp_lro.c:1252` is flush_all path delivery; classic flush path also depends on `ifp`). Therefore `lro.ifp` must be bound to F-Stack veth interface, consistent with `ctx->ifp`.

### 2.3 Classic Mode Integration Pseudocode (Design Description, Not Implementation Code)

```c
/* Inside ff_veth_input, after ff_mbuf_gethdr + multi-segment chain complete getting hdr */
if (ctx->sw_lro_enabled) {                       /* software LRO switch, see section 4 */
    /* hdr is complete FreeBSD mbuf chain head */
    if (tcp_lro_rx(&ctx->lro, (struct mbuf *)hdr, 0) == 0) {
        return;                                  /* taken over by LRO (aggregated or staged), no direct delivery */
    }
    /* non-0 return: non-TCP / cannot aggregate, tcp_lro_rx internally flush_active preserved order,
       here deliver remaining packets via original path */
}
ff_veth_process_packet(ctx->ifp, hdr);
```

- **Return value semantics** (`tcp_lro.c:1426-1445`): `tcp_lro_rx` returns 0 = entered LRO engine (later delivered by LRO flush); non-0 return = not LRO-able (e.g., non-TCP, bad csum), internally already `tcp_lro_flush_active` (`tcp_lro.c:1441`) preserved order, caller needs to deliver this packet itself.
- **csum parameter**: `tcp_lro_rx(lc, m, csum)` third param `csum` is pre-validated checksum. If F-Stack receive already validated by PMD (`rx_csum`), can pass 0 (meaning let LRO handle/trust); **pending runtime validation**: csum parameter impact on aggregation correctness.

---

## 3. ⚠ Key Risk: tcp_lro.c:1261 `tcp_hpts_softclock()` NULL Bare-Call

### 3.1 Risk Verification

- **Bare-call point**: `tcp_lro_flush_all` (`tcp_lro.c:1199`) function body end:
  ```c
  done:
      tcp_lro_rx_done(lc);
      tcp_hpts_softclock();   /* tcp_lro.c:1261 —— bare-call without null check */
      lc->lro_mbuf_count = 0;
  ```
- **Function pointer is NULL**: `tcp_hpts_softclock` is defined as NULL function pointer in F-Stack:
  ```c
  void (*tcp_hpts_softclock)(void) = NULL;   /* ff_stub_14_extra.c:627 */
  ```
- **Consequence**: If software LRO takes **modern mode** (`tcp_lro_flush_all`), executing `tcp_lro.c:1261` will **dereference NULL function pointer → crash**.

### 3.2 Classic Mode Natural Avoidance (Primary Basis)

- `tcp_lro_rx` (`tcp_lro.c:1426`) and its internal `tcp_lro_flush` (`tcp_lro.c:1108`) **do not contain** `tcp_hpts_softclock()` calls.
- `tcp_lro_flush` (`tcp_lro.c:1108-1122`) has another hpts-related function pointer `tcp_lro_flush_tcphpts` (`tcp_lro.h:220`):
  ```c
  if (tcp_lro_flush_tcphpts == NULL ||
      tcp_lro_flush_tcphpts(lc, le) != 0) {
      tcp_lro_condense(lc, le);         /* tcp_lro.c:1116: core aggregation */
      tcp_flush_out_entry(lc, le);      /* tcp_lro.c:1117: delivery */
  }
  ```
  When `tcp_lro_flush_tcphpts == NULL`, **safely falls back** to `tcp_lro_condense` (core aggregation can work completely without hpts). **Pending verification (coding phase read_file)**: whether `tcp_lro_flush_tcphpts` is also NULL in F-Stack (if NULL, classic flush path is completely safe).
- **Conclusion**: Classic mode (`tcp_lro_rx`) path **does not touch** `tcp_lro.c:1261`, is the cleanest solution to avoid NULL bare-call.

### 3.3 Three Candidate Handling Options Comparison

| Candidate | Approach | Pros | Cons | Applicable |
| --- | --- | --- | --- | --- |
| **A. Classic mode (preferred)** | Integrate using `tcp_lro_init` + `tcp_lro_rx`, **don't use** `tcp_lro_flush_all`; batch-end use `tcp_lro_flush_inactive` (doesn't contain 1261 bare-call) | Zero changes to `tcp_lro.c`; doesn't touch NULL bare-call; no lib intrusion | No sort aggregation, aggregation rate may be slightly lower than RSS sorted mode (F-Stack RSS already distributes to per-lcore, same lcore is same-flow, small impact) | **This round's preferred** |
| **B. Set safe stub for `tcp_hpts_softclock`** | In `ff_stub_14_extra.c:627` change NULL to an empty implementation `static void ff_hpts_softclock_noop(void){}`, pointer points to it | Allows subsequent use of modern mode; one change globally effective | Changing stub is changing lib (this round doesn't change code); whether empty implementation satisfies hpts semantics needs evaluation (current F-Stack has no hpts, empty implementation semantically equivalent to "no hpts timer advance", acceptable) | If modern mode needed in future |
| **C. Conditional null-check skip** | If must use `tcp_lro_flush_all`, can't insert null check without changing source code (1261 is inside function); can only change `tcp_lro.c:1261` to `if (tcp_hpts_softclock) tcp_hpts_softclock();` | Precise, minimal semantic change | **Modifying FreeBSD port source code** (`tcp_lro.c`), violates "don't modify FreeBSD port" convention, and future upstream sync has conflict risk | Least recommended |

**Recommendation**: **Option A (classic mode)**. Rationale: (1) zero lib changes, zero FreeBSD port changes; (2) completely bypasses `tcp_lro.c:1261` NULL bare-call from path; (3) F-Stack RSS already distributes same-flow packets to same lcore queue, classic mode aggregation rate loss is limited in per-lcore context. If subsequent performance baseline shows classic mode aggregation rate insufficient, then evaluate Option B (set safe stub then enable modern mode). Option C (modify FreeBSD port source) only as last resort.

---

## 4. Switch Coordination with Hardware LRO

> Complete software/hardware switch unified semantics see `13-software-hardware-offload-integration.md`; this section gives the software LRO side perspective.

### 4.1 When Software LRO Is Enabled

Three candidate strategies (recommendation details in document 13):

- **Strategy 1: Hardware preferred + software fallback (recommended)**: When `lro=1`, first detect hardware (`dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO`); if hardware supports, use hardware LRO, **don't enable software LRO**; if hardware doesn't support, fallback to enabling software LRO. User only needs one `lro` switch, auto-selecting optimal.
- **Strategy 2: Independent switch**: Add `sw_lro` independent switch, orthogonal to hardware `lro`, user explicitly controls. Flexible but user needs to understand two switches' combination semantics.
- **Strategy 3: Three-state lro**: `lro=0` off / `lro=1` hardware preferred + software fallback / `lro=2` force software. Semantics concentrated in one key but value semantics more obscure.

### 4.2 Software/Hardware Mutual Exclusion (Key)

**Hardware LRO and software LRO must be mutually exclusive, cannot stack**:

- When hardware LRO is enabled, PMD delivers already-**aggregated large segments** (`pkt->ol_flags & RTE_MBUF_F_RX_LRO`, large `pkt_len`). If再走 software `tcp_lro_rx`, it would double-aggregate already-aggregated large segments — semantic error, no gain, and may trigger LRO engine anomaly handling for超长 segments.
- Therefore: `ctx->sw_lro_enabled` and `hw_features.rx_lro` **mutually exclusive**. When hardware LRO (`rx_lro=1`) is effective, software LRO switch must be 0.

### 4.3 IFCAP_LRO Coordination

- `ff_veth.c:945-947` current code: `if (cfg->hw_features.rx_lro) if_setcapabilitiesbit(ifp, IFCAP_LRO, 0)` (**currently only driven by hardware `rx_lro`**).
- When software LRO is enabled, also need to declare `IFCAP_LRO` to protocol stack (so stack receives large segments per LRO semantics), so `IFCAP_LRO` setting condition should be extended to `hw_features.rx_lro || sw_lro_enabled` (see document 13 for unified switch design).

---

## 5. Software LRO Side Effects and Risks

### 5.1 Protocol Semantic Side Effects (External Research + FreeBSD Common Knowledge)

- **Loses per-segment arrival timestamps**: LRO merges multiple packets into one large segment, only retaining one packet's timestamp within aggregation, RTT measurement precision decreases, affecting TCP congestion control RTT sampling.
- **Loses/merges ECN bits**: Multiple segments' ECN (Explicit Congestion Notification) bits are merged during aggregation, congestion signals may be weakened or lost, affecting congestion response.
- **Impact on loss recovery**: Aggregated large segments obscure original packet boundaries, SACK/fast retransmit granularity becomes coarser.
- **Basic stack vs RACK/BBR**: FreeBSD basic TCP stack (non-RACK/BBR) software LRO takes "assemble large segments → inject interface layer `if_input`" path (this solution is this path); RACK/BBR has more fine-grained LRO/hpts coordination (depends on `tcp_lro_flush_tcphpts`/`tcp_hpts_softclock`, F-Stack currently stubs out). **F-Stack takes basic stack path**, doesn't involve hpts fine coordination.

### 5.2 Resource and Performance Side Effects

- **Memory**: `lro_ctrl`'s hash table, entry pool, (modern mode's) sort array occupy memory, one per lcore. Classic mode has no sort array, smaller memory overhead.
- **Latency**: Aggregation itself introduces queueing latency (waiting for same-flow subsequent packets); `tcp_lro_flush_inactive` timeout parameter determines max staging latency. For latency-sensitive scenarios (e.g., short connections, request-response) may be negative; for throughput-oriented large flows is positive.
- **Reordering**: `tcp_lro_rx` for non-aggregatable packets `tcp_lro_flush_active` (`tcp_lro.c:1441`) preserves order, but interleaving of aggregation and non-aggregation flows needs to ensure correct delivery order — **pending runtime validation**: ordering correctness under F-Stack single-threaded classic mode.

### 5.3 Risk Levels

| Risk | Level | Mitigation |
| --- | --- | --- |
| NULL bare-call crash (`tcp_lro.c:1261`) | High (if误用 modern mode) | Option A classic mode avoidance; default off |
| Congestion control/RTT precision degradation | Medium | Documentation; not recommended for latency-sensitive services |
| Ordering/reordering | Medium | Classic mode flush_active ordering; runtime validation |
| Memory overhead | Low | Classic mode no sort array; per-lcore controllable |
| Stacking with hardware LRO | Medium | 4.2强制 mutual exclusion |

---

## 6. Relationship with RSS Multi-Queue / Multi-Process

- **RSS orthogonal**: RSS distributes different flows to different queues/lcores by flow hash; software LRO aggregates flows received by each lcore within its **per-lcore `lro_ctrl`**. Since RSS guarantees "same-flow same-queue", same lcore is inherently same-flow packet聚集, classic mode can efficiently aggregate without cross-lcore sorting.
- **Multi-process (primary/secondary)**: Each process/lcore independently holds `lro_ctrl`, not shared (no locks needed). Secondary process integrates in its receive path per same switch (shared config `hw_features` + software LRO switch). **Pending runtime validation**: correctness and statistics aggregation of each lcore independent aggregation under multi-process.
- **Single-threaded run-to-completion advantage**: F-Stack has no interrupt context, no soft interrupts; receive batch processing is inherently "one batch `rte_eth_rx_burst` → per-packet processing → batch end", consistent with iflib's rxq batch structure; `tcp_lro_flush_inactive` can be placed at batch end, no concurrency risk.

---

## 7. Honest Boundary (Pending Runtime Validation Checklist)

1. Whether local virtio `dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO` is 0 (determines whether software LRO is the only LRO path).
2. Whether `tcp_lro_flush_tcphpts` (`tcp_lro.h:220`) is NULL in F-Stack (if so, classic flush path `tcp_lro.c:1114-1116` completely goes through `tcp_lro_condense`, safe).
3. What value `tcp_lro_rx` csum parameter (third param) should pass in F-Stack `rx_csum` already-validated scenario.
4. Classic mode aggregation rate under F-Stack single-threaded per-lcore (whether need to upgrade to modern mode + Option B safe stub).
5. Impact of aggregation-introduced latency on latency-sensitive services (`tcp_lro_flush_inactive` timeout parameter tuning).
6. Ordering correctness of interleaving aggregation and non-aggregation flows under single-threaded classic mode.
7. Correctness of each lcore independent aggregation under multi-process primary/secondary.

> All the above are runtime/subsequent milestone validation items, not tested this round. Test environment: DPDK dedicated NIC IP `9.134.214.176` (`ssh f-stack-client` side initiates), kernel stack testing via `127.0.0.1` on `lo`.

---

## 8. This Document's Conclusion Summary

1. **Software LRO's only gap = not integrated into `ff_veth_input` (`ff_dpdk_if.c:1707`)**. `tcp_lro.c` is compiled (`Makefile:513`), API and algorithm ready, only missing lifecycle management + receive integration glue.
2. **Preferred classic mode** (`tcp_lro_init` + `tcp_lro_rx` + `tcp_lro_flush_inactive`), per-lcore/per-port `lro_ctrl`, integration point after `ff_mbuf_gethdr` (`ff_dpdk_if.c:1720`).
3. **⚠ `tcp_lro.c:1261` `tcp_hpts_softclock()` NULL bare-call (`ff_stub_14_extra.c:627`) is the biggest risk**. **Recommend Option A (classic mode natural avoidance)**, Option B (set safe stub) as alternative, Option C (modify FreeBSD port source) only as last resort.
4. **Software/hardware LRO强制 mutually exclusive**: When hardware LRO effective, don't enable software LRO (avoid double aggregation). Switch coordination recommends "hardware preferred + software fallback" (see document 13 for details).
5. Software LRO has congestion control/RTT/latency side effects, **default off**, not recommended for latency-sensitive services.
