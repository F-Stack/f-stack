# 02 - Architecture Code Investigation and Blocking Point List

> Target: `/data/workspace/f-stack` (DPDK 24.11.6). Read-only investigation, no modifications.
> All `file:line` references verified by actual `read_file`/`grep -n`.

## Summary

This document enumerates all primary/secondary divergence points in f-stack `lib/`, `tools/`, verifying 8 hypothesized blocking points for issue #1078's "primary slimming" approach. Conclusion: **only 3 true hard blocks** (B1's `rte_exit`, B2's KNI config validation, B3's mbuf pool formula); B4's hypothesized "queue count/queueid misalignment" is **invalid** — queue count and RSS reta are driven by `pconf->nb_lcores`, automatically shrink when primary exits `lcore_list`, so orphan queues naturally disappear. 8 additional blocking points discovered beyond B1-B8.

## Key Conclusions

1. **B1 is the first hard wall**: `ff_dpdk_if.c:508-510` `rte_exit` on `nb_rx_queue == 0`; `init_lcore_conf()` is the first sub-step of `ff_dpdk_init()` (`:1682`).

2. **B4 invalid (important good news)**: `nb_queues` = `pconf->nb_lcores` (`:836`), not `nb_procs`; `queueid` = lcore's index in `lcore_list` (`:487-491`), fully decoupled from `proc_id`; `set_rss_table()` recalculates reta by same `nb_queues` (`:1169-1174`). Removing primary's lcore → queue count/queueid/reta/dispatch_ring consistently shrink.

3. **B3 partially valid**: mbuf pool formula RX term `nb_rx_queue * nb_lcores` (`:535`) depends on **this process's** queue count; pool only created by primary (`:571-590`). Primary queue count → 0 makes entire RX term zero, pool severely under-provisioned. Must change to sum by port's `nb_lcores`.

4. **KNI is primary strongly-bound**: `ff_kni_is_owner_thread()` ≡ `proc_type == primary` (`ff_dpdk_kni.c:93-97`); 7 call points depend on it.

5. **Runtime secondary doesn't depend on primary** (consistent with E1/E2): No `rte_mp_request`/`rte_mp_sendmsg` in `lib/`; hot path only uses `rte_eth_rx_burst`/`tx_burst`/`rte_ring_dequeue_burst`/`rte_mempool_get|put`. But **primary graceful exit calls `rte_eal_cleanup()`** (`:2884`) — breaks secondary.

## Task A: Primary/Secondary Responsibility Boundary

### A.1 All proc_type Check Points (12 total)

| # | File:Line | Context | Phase |
|---|-----------|---------|-------|
| 1 | `ff_dpdk_if.c:297` | `nb_dev_ports` assignment | Init |
| 2 | `ff_dpdk_if.c:571` | mempool creation (primary only) | Init |
| 3 | `ff_dpdk_if.c:624` | mbuf pool creation (primary only) | Init |
| 4 | `ff_dpdk_if.c:704` | message_pool creation (primary only) | Init |
| 5 | `ff_dpdk_if.c:1061` | `init_port_start` device config (primary only) | Init |
| 6 | `ff_dpdk_if.c:1189` | `set_rss_table` (primary only) | Init |
| 7 | `ff_dpdk_if.c:1707` | `init_clock` (primary only) | Init |
| 8 | `ff_dpdk_if.c:1760` | `ff_kern_chg_desc` (primary only) | Init |
| 9 | `ff_dpdk_if.c:3483` | `ff_dpdk_run` cleanup (primary only) | Exit |
| 10 | `ff_dpdk_kni.c:97` | `ff_kni_is_owner_thread()` definition | Runtime |
| 11 | `ff_memory.c:221` | `ff_mbuf_pool_create` (primary only) | Init |
| 12 | `tools/compat/ff_ipc.c:67` | `--proc-type=secondary` (indirect) | Tool |

## Task B: 8 Blocking Points Verification

| # | Blocking Point | Valid? | Solution |
|---|---------------|--------|----------|
| B1 | `rte_exit` on `nb_rx_queue==0` (`:508-510`) | **Yes (hard)** | Add `primary_slim` condition |
| B2 | KNI config validation requires primary in `lcore_list` | **Yes (hard)** | Parameterize KNI owner |
| B3 | mbuf pool formula depends on this process's queue count (`:535`) | **Yes (hard)** | Change to `nb_ports * nb_lcores` |
| B4 | Queue count/queueid misalignment | **No (invalid)** | Queues driven by `lcore_list`, auto-shrink |
| B5 | `ff_dpdk_if_up()` ifp attachment | Risk | Don't attach ifp for slim primary |
| B6 | `ff_kni_process()` inside rx loop | **Yes** | Move outside rx loop |
| B7 | `thread_mode` mutual exclusion | **Yes** | Add validation |
| B8 | `init_port_start` primary-only gate | Correct | Keep as-is |

## Task C: New Findings (N1-N8)

| # | Finding | Impact |
|---|---------|--------|
| N1 | `nb_dev_ports` incorrect on secondary side (`:79` comment) | KNI port_id calculation wrong |
| N2 | `total_nb_ports *= 2` gated by `ff_kni_is_owner_thread()` (`:821-825`) | If owner is secondary, primary doesn't configure virtio_user |
| N3 | `msg_ring` indexed by `proc_id` (`:698-700`) | Tools default proc_id=0 → if primary doesn't process msg_ring, tools fail |
| N4 | `rte_eal_cleanup()` in graceful exit (`:2884`) | Tears down EAL shared resources, breaks secondary |
| N5 | `ff_kern_chg_desc` primary-only (`:1760`) | Timer management only in primary |
| N6 | `ff_dpdk_if_up()` iterates `nb_tx_port` (`:1196`) | Slim primary has 0 tx_port → doesn't attach ifp |
| N7 | `dispatch_ring` count tied to `lcore_list` | Auto-shrinks correctly |
| N8 | `init_flow`/`fdir` primary-only (`:1196-1208`) | Correct, keep as-is |

## Task E: FP-1/FP-2 Device Runtime State

**FP-1** (`igb_uio.c:352-366`): `pci_clear_master()` only when last process closes uio fd (refcnt → 0)

**FP-2** (`virtio_ethdev.c:1949-1954`): Secondary early-exits, doesn't write `VIRTIO_CONFIG_STATUS_DRIVER_OK`

**Combined**: Once device DMA stopped, new secondary cannot restore. E2e proved: refcnt ≥ 1 → secondary restarts successfully.
