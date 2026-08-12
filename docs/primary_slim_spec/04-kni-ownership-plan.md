# 04 - KNI and Control-Plane Ownership Plan

> Target: `/data/workspace/f-stack` (DPDK 24.11.6). Read-only, no modifications.
> Revised 2026-08-10 per Q1/Q2/Q3 code verification + E4a decisive experiment: K4 (secondary as runtime KNI owner) is preferred, K3-corrected is fallback.

## Summary

After primary-slim (S1), primary no longer holds rx/tx queues, but KNI's `ff_kni_process()` is nested inside rx queue loop → KNI silently fails. This document provides complete KNI ownership dependency graph (distinguishing "must be primary" vs "can migrate"), 4 candidate paths K1/K2/K3-corrected/K4 evaluation, 6 control-plane operations' ownership and timing, `msg_ring`/tools ownership decisions, and `nb_dev_ports` semantic fix.

**K4 (secondary as runtime KNI owner) is preferred** per `11`'s Q1/Q2/Q3 code verification and E4a decisive experiment. K3-corrected (K3 + Q1/Q2 corrections) is fallback.

## Key Conclusions

1. **KNI's "must be primary" items are only two**: virtio_user port's `rte_eal_hotplug_add()` (`ff_dpdk_kni.c:474`) and its `dev_configure`/`dev_start` (via `ff_dpdk_if.c:1061-1063` gate). `kni_stat` allocation, `kni_ring_%u` consumption, virtio_user rx/tx burst **don't require primary identity**.

2. **K4 recommended** (per Q3 + E4a): Split `ff_kni_is_owner_thread()` into "init owner" (= primary) and "runtime owner" (= designated secondary). E4a verified: secondary discovers virtio_user0 via `VDEV_SCAN_REQ`, independently probes it, accesses shared KNI ring. Per Q3 §3.8: `kni_process_rx` L190's `queue_id` comes from owner's own rx queue → **K4 owner secondary directly uses own tx queue, no need for `kni_tx_ring`**.

3. **K3-corrected as fallback**: Primary keeps KNI (it's the configure/start owner, queue 0 uncontested). "Kernel → physical port" direction via new `kni_tx_ring` (`RING_F_SP_SC`). Per Q1: `kni_rp` is already `RING_F_SC_DEQ` single consumer, keep as-is. Per Q2: `kernel_packets_ratelimit` is owner-only, naturally single-point rate limiting.

4. **KNI inbound (physical → kernel) doesn't need primary to hold rx queue**: Each secondary receives on own rx queue → `ff_kni_enqueue()` → shared `kni_rp` ring → owner dequeues → writes virtio_user queue 0. **Must fix**: broadcast/multicast branch has owner gate (`ff_dpdk_if.c:2080`) — slim primary never receives → branch never executes → ARP/DHCP/IPv6 NS/RA/MLD/OSPF hello never enter kernel.

5. **`msg_ring` decision**: Primary's simplified loop continues consuming `msg_ring[0]`; tools default `proc_id=0` unchanged (backward compatibility).

6. **`nb_dev_ports` fix**: Primary publishes `rte_eth_dev_count_avail()` snapshot to shared memzone before hotplug; secondary lookups. **K4 prerequisite** (owner secondary needs it for `kni_stat[port_id]->port_id`).

## I. KNI Current Primary Binding Dependency Graph

### Must-be-primary (5 items)

| # | Location | Operation | DPDK Constraint |
|---|----------|-----------|-----------------|
| 1 | `ff_dpdk_kni.c:474` | `rte_eal_hotplug_add("vdev", ...)` | Secondary calls get forwarded to primary via IPC |
| 2 | `ff_dpdk_if.c:821-825` | `total_nb_ports *= 2` | If owner is secondary, primary doesn't configure virtio_user |
| 3 | `ff_dpdk_if.c:1061-1063` | `dev_configure`/`dev_start` | Explicit `!= PRIMARY` skip |
| 4 | `ff_dpdk_kni.c:484-486` | `rte_ring_create(kni_rp, RING_F_SC_DEQ)` | Creator must be unique |
| 5 | `ff_dpdk_kni.c:387` | `kni_stat` array allocation | Logically grouped with #1-4 |

### Can-migrate (3 items)

| # | Location | Operation | K4 Migration |
|---|----------|-----------|--------------|
| 6 | `ff_dpdk_kni.c:537` | `ff_kni_enqueue` error stats | Secondary allocates own `kni_stat` |
| 7 | `ff_dpdk_if.c:2080` | Broadcast/multicast clone | Gate → `!pkts_from_ring` |
| 8 | `ff_dpdk_if.c:2765` | `ff_kni_process()` call | Owner → designated secondary |

## II. Four Candidate Paths

### K1: Move KNI to secondary entirely
- **Infeasible**: Items 1-5 must be primary (DPDK hard constraints)

### K2: Secondary calls `rte_eal_hotplug_add`
- **Infeasible**: DPDK forwards to primary via IPC — doesn't reduce primary dependency, adds IPC overhead + N2 becomes real bug + vdev visibility depends on primary

### K3-corrected: Primary keeps KNI + `kni_tx_ring` for outbound
- Primary keeps virtio_user TX/RX (it's configure/start owner)
- "Kernel → physical" via new `kni_tx_ring` → secondary dequeues → uses own tx queue
- Per Q1: `kni_rp` stays `RING_F_SC_DEQ`, no multi-consumer needed
- Per Q2: `kernel_packets_ratelimit` owner-only, no rate scaling needed
- Changes: ~7-8 points + new ring

### K4: Secondary as runtime KNI owner (PREFERRED)
- Init: primary does hotplug + kni_stat + kni_rp + total_nb_ports*=2 + configure/start
- Init: designated secondary also allocates kni_stat, probes virtio_user (automatic)
- Runtime: designated secondary calls `ff_kni_process()`, directly uses own tx queue (no `kni_tx_ring` needed)
- E4a verified: secondary successfully discovers, probes, accesses virtio_user
- Changes: ~8-10 points (includes N2 fix + total_nb_ports condition + owner判定 + secondary kni_stat)
- **Core advantages**: No new ring, KNI owner crash only affects KNI (not control plane), recovery = restart that secondary

## III. K4 vs K3-corrected

| Dimension | K3-corrected | K4 |
|-----------|-------------|---|
| New ring | needed | **not needed** |
| N2 fix | can defer | mandatory |
| Owner crash impact | primary crash = KNI + control plane | secondary crash = KNI only |
| Recovery | full-group restart | restart that secondary |
| Changes | 7-8 | 8-10 |
| Core advantage | minimal changes | better fault isolation |
| Core disadvantage | KNI bound to primary | more prerequisites |

**Recommendation**: K4 if priority is "KNI independent of primary"; K3-corrected if "minimal changes, fastest delivery."

## IV. Control-Plane Operations (6 items, primary-only)

| # | Operation | Location | Must be primary? |
|---|-----------|----------|-----------------|
| 1 | `rte_timer_manage()` | `ff_dpdk_if.c:2722` | Yes (timer subsystem) |
| 2 | `process_msg_ring()` | `ff_dpdk_if.c:2701` | Yes (tools default proc_id=0) |
| 3 | KNI process | `ff_dpdk_if.c:2765` | K4: designated secondary |
| 4 | TX drain | `ff_dpdk_if.c:2728` | Skip (no tx queues) |
| 5 | rx queue loop | `ff_dpdk_if.c:2810` | Skip (no rx queues) |
| 6 | `rte_eal_cleanup()` | `ff_dpdk_if.c:2884` | Skip (would break secondary) |
