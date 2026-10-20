# 03 - Solution Design and Alternative Comparison

> Target: `/data/workspace/f-stack` (DPDK 24.11.6). Read-only, no modifications.
> Based on: 00 (requirements), 01 (external research), 02 (code investigation), 05 (experiments)

## Summary

For issue #1078 "primary slimming," this document presents main solution **S1 "primary-slim"** (new `[dpdk] primary_slim` switch; primary persists but holds no rx/tx queues, only does device config/shared object creation/control-plane message processing), compared with S0 (no change), S2 (primary exits), S3 (minimal queue retention), S4 (`thread_mode=1`), S5 (external daemon + layered recovery). S1's minimal runnable set: 4 code changes + 1 config item; full coverage including KNI and control-plane integrity: 9 changes.

## Key Conclusions

1. **S1 achieves both sub-goals** ((a) reduce probability, (b) narrow impact including recoverability): Per E2e (reproduced twice) — as long as ≥1 process holds `/dev/uioX` (refcnt ≥ 1), secondary can restart with primary absent. In primary-slim target state, primary crash → all data-plane secondaries remain → ① zero traffic loss (orphan queues eliminated); ② any crashed secondary can restart in place → **no full-group restart needed for data plane recovery**.

2. **S1 code basis holds**: Queue count/queueid/reta/dispatch_ring all driven by `pconf->nb_lcores` (`:836`, `:487-491`, `:801`, `:651`); removing primary's lcore → consistent shrink, orphan queues disappear at code level (B4 from `02`).

3. **Decision: primary-slim doesn't attach ifp** (`ff_dpdk_if_up()` stays 0 iterations). New risk found: `lcore_conf` is zero-initialized global array (`:126`); primary's `tx_queue_id[port]` always 0; if primary holds ifp and sends, `send_burst()` would `rte_eth_tx_burst(port, 0, ...)` (`:2378-2389`) — **colliding with secondary's tx queue 0** (non-MT-safe).

4. **Decision: primary simplified loop keeps `rte_timer_manage()` + `process_msg_ring()`**, skips TX drain and rx queue loop; add idle_sleep floor to avoid full-core spinning.

5. **Decision: primary-slim mode prohibits `rte_eal_cleanup()`** (`:2883-2884`) — would tear down secondary's EAL shared resources (N4 from `02`).

## I. Design Goals

| Sub-goal | Content | S1 Achievement |
|----------|---------|----------------|
| (a) Reduce probability | Primary doesn't run data plane | Achieved (statistical) |
| (b) Narrow impact | Primary crash doesn't take data plane | 100% achieved (existing + new traffic) |
| (c) Post-failure recovery | Can recover in place | Partially achieved (secondary yes, primary no per E10) |

## II. Solution Comparison

| Solution | Core Approach | Feasibility | Changes | Recommended? |
|----------|--------------|-------------|---------|-------------|
| **S1 primary-slim** | Primary persists, no queues | **Feasible** | 4-9 | **Yes (recommended)** |
| S0 no change | Status quo | N/A | 0 | No (doesn't solve issue) |
| S2 primary exits | Primary exits after init | **Infeasible** (DPDK hard constraints) | — | No |
| S3 minimal queue | Primary keeps 1 queue | Partial | ~6 | No (still has orphan queue) |
| S4 thread_mode=1 | Single-process multi-thread | Alternative | Large | Different direction |
| S5 external daemon | Daemon + layered recovery | Supplement | 0 code | Fallback |

## III. S1 Design Details

### 3.1 Minimal Runnable Set (4 changes)

| # | Location | Change | Unblocks |
|---|----------|--------|----------|
| 1 | `ff_dpdk_if.c:508-510` | `rte_exit` add `primary_slim && PRIMARY` condition | B1 |
| 2 | `ff_dpdk_if.c:535` | mbuf pool RX: `nb_rx_queue * nb_lcores` → `nb_ports * nb_lcores` | B3 |
| 3 | `ff_config.h` | New `primary_slim` field | Config |
| 4 | `ff_config.c` | New `MATCH("dpdk", "primary_slim")` | Config |

### 3.2 Full Set (9 changes, adds KNI + control-plane)

| # | Location | Change |
|---|----------|--------|
| 5 | `ff_dpdk_if.c:2883-2884` | Skip `rte_eal_cleanup()` for primary_slim+PRIMARY |
| 6 | `ff_dpdk_if.c` | Slim primary idle_sleep |
| 7 | `ff_dpdk_kni.c` | KNI owner parameterization |
| 8 | `ff_dpdk_if.c:2080` | Broadcast/multicast KNI gate → `!pkts_from_ring` |
| 9 | `ff_dpdk_if.c:2765` | `ff_kni_process()` outside rx loop |

### 3.3 Validation Chain

| ID | Validation | Error if violated |
|----|-----------|-------------------|
| V2 | `primary_slim=1` requires `nb_procs >= 2` | rte_exit |
| V4 | `primary_slim=1` mutually exclusive with `thread_mode=1` | rte_exit |
| V5 | `primary_slim=1` requires primary lcore not in any `lcore_list` | rte_exit |

## IV. Risk Assessment

| Risk | Description | Mitigation |
|------|-------------|-----------|
| R3 | Primary `tx_queue_id[port]` = 0, if attach ifp → tx queue 0 collision | Don't attach ifp (N6 confirmed) |
| R14 | Control-plane degraded state after primary crash | Opportunistic full-group restart |
| — | Slim primary full-core spinning | idle_sleep floor |

## V. Accurate Value Statement

> **primary-slim transforms "primary crash ⇒ must immediately full-group restart, ~1/N connections immediately interrupted" into "primary crash ⇒ zero data plane loss, business continues, crashed secondary can restart in place, cluster enters control-plane degraded state, can opportunistically full-group restart during planned maintenance window."**

**NOT promised**: "never need restart" (control-plane degraded state can't be fixed in place); "save a CPU core" (slim primary still spins unless idle_sleep); "primary is no longer single point" (only probability reduced).
