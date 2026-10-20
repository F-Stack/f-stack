# 11 - KNI Deep-Dive Investigation and Experiment Report

> Target: `/data/workspace/f-stack` (DPDK 24.11.6). Read-only investigation: no `lib/` code modified, no compilation, no commits.
> This document answers three challenges (Q1/Q2/Q3) to the first-round KNI proposal (doc `04`'s K3), with each conclusion supported by DPDK source code.

---

## Q1: kni_tx_ring Single Consumer Is Sufficient, No Multi-Consumer Needed

### Code Evidence

#### 1.1 kni_rp Ring Flag: RING_F_SC_DEQ (Single Consumer)

`ff_kni_alloc()` creates `kni_rp[port_id]` with `RING_F_SC_DEQ` flag (`ff_dpdk_kni.c:484-486`). `RING_F_SC_DEQ` = Single Consumer Dequeue. Only one consumer allowed on dequeue side; enqueue side allows multiple producers.

#### 1.2 Producer Side: All Receiving Processes

`ff_kni_enqueue()` has 3 call sites:
- Broadcast/multicast clone: `ff_dpdk_if.c:2080` with `ff_kni_is_owner_thread()` gate
- Unicast ALL_TO_KNI: `ff_dpdk_if.c:2094` — **no owner gate** — any process
- Unicast DEFAULT: `ff_dpdk_if.c:2102` — **no owner gate** — any process

**Inbound (physical port → kernel)**: `kni_rp` producers = all receiving processes. Consistent with ring flag (SC_DEQ only restricts consumer).

#### 1.3 Consumer Side: Only Owner (Primary), Single Consumer

`kni_process_tx()` (`ff_dpdk_kni.c:144-179`) is the only consumer, called via `ff_kni_process()` which has `ff_kni_is_owner_thread()` gate (`ff_dpdk_if.c:2765`).

#### 1.4 Conclusion

**kni_rp single-consumer design is correct and sufficient.** Consumer is always only owner. No need for multi-consumer.

---

## Q2: Ratelimit Needs No Change — Whoever Processes KNI Queue Does Rate Limiting

`kni_rate_limt` is a **per-process global variable**. Each f-stack process has its own independent instance.

- `console_packets_ratelimit` / `general_packets_ratelimit`: Per-process rate limiting in `ff_kni_enqueue()` — executed by each receiving process
- `kernel_packets_ratelimit`: Consumer-side rate limiting in `kni_process_tx()` — executed by KNI owner

Rate limiting counters reset every second in `main_loop`'s `rte_timer_manage()` callback (`ff_dpdk_if.c:2722-2724`).

### Conclusion

**Ratelimit mechanism is inherently per-process.** Whether KNI owner is primary or secondary, rate limiting naturally follows the owner. **No code changes needed.**

---

## Q3: Secondary Can Directly Handle KNI, No Need for Primary to Forward (K4)

### Call Site Inventory

`ff_kni_is_owner_thread()` has 8 call sites:

| # | File:Line | Context | Phase | Can Migrate? |
|---|-----------|---------|-------|--------------|
| 1 | `ff_dpdk_kni.c:93` | Definition | — | Entry point |
| 2 | `ff_dpdk_kni.c:387` | `ff_kni_init()`: allocate `kni_stat` | Init | **No** (DPDK) |
| 3 | `ff_dpdk_kni.c:434` | `ff_kni_alloc()`: `rte_eal_hotplug_add` | Init | **No** (DPDK) |
| 4 | `ff_dpdk_kni.c:484` | `ff_kni_alloc()`: create `kni_rp` ring | Init | **No** (unique creator) |
| 5 | `ff_dpdk_kni.c:537` | `ff_kni_enqueue()` error stats | Runtime | **Yes** |
| 6 | `ff_dpdk_if.c:822` | `total_nb_ports *= 2` | Init | **No** (DPDK) |
| 7 | `ff_dpdk_if.c:2080` | Broadcast/multicast clone | Runtime | **Yes** |
| 8 | `ff_dpdk_if.c:2765` | `ff_kni_process()` call | Runtime | **Yes** |

### Init Phase (Cannot Migrate — DPDK Hard Constraints)

5 call points must be primary:
- `rte_eal_hotplug_add`: secondary calls forwarded to primary via IPC
- `total_nb_ports *= 2`: if owner is secondary, primary doesn't configure virtio_user → KNI broken
- `dev_configure`/`dev_start`: explicitly skips non-PRIMARY

### Runtime Phase (Can Migrate)

3 call points can change to designated secondary.

### vdev Visibility

**Secondary can probe virtio_user devices** (`virtio_user_ethdev.c:525-547`):
- `rte_eth_dev_attach_secondary(name)` binds to primary-created ethdev
- `set_rxtx_funcs` sets rx/tx burst pointers
- `virtio_user_secondary_eth_dev_ops` (stats/info only, no configure/start)

**But**: secondary discovers vdevs via IPC to primary (`vdev_scan()` → `VDEV_SCAN_REQ`). Primary must be online.

### kni_process_rx Key Finding

`kni_process_rx()` L190: `rte_eth_tx_burst(port_id, queue_id, ...)` — TX to physical port using **this process's own queue** (`queue_id` from `qconf->rx_queue_list[i].queue_id`).

If owner is secondary, it uses its own TX queue — **no need for ring forwarding (K3's `kni_tx_ring`)**. This is K4's core advantage.

### K4 Prerequisites

| Prerequisite | Description |
|-------------|-------------|
| N2 fix (mandatory) | `nb_dev_ports` incorrect on secondary |
| `total_nb_ports *= 2` condition | Must change to just `enable_kni` |
| vdev visibility | Depends on primary online for rediscovery |
| Owner secondary crash | KNI interrupts; restart recovers |

### K4 vs K3-corrected

| Dimension | K3-corrected | K4 |
|-----------|-------------|---|
| New ring | needed | **not needed** |
| N2 fix | can defer | mandatory |
| Owner crash | primary crash = KNI + control plane down | secondary crash = KNI only |
| Recovery | full-group restart | restart that secondary |
| Changes | 7-8 | 8-10 |

---

## E4a Decisive Experiment Results (2026-08-10)

### Config
- `lcore_mask=3`, `[port0] lcore_list=0,1`, `[kni] enable=1 method=reject`
- No code changes, existing helloworld

### Primary Log
```
Port 1 MAC:20:90:6F:7D:5D:08    ← virtio_user port created!
Port 0 Link Up
f-stack-0: Successed to register dpdk interface
```

### Secondary Log
```
VDEV_BUS: vdev_action(): receive vdev, virtio_user0    ← Discovers virtio_user0!
VDEV_BUS: vdev_scan(): Received 1 vdevs
VDEV_BUS: Search driver to probe device virtio_user0   ← Probes virtio_user0!
create kni ring success
f-stack-0: Successed to register dpdk interface
```

### E4a Conclusion

| Item | Result |
|------|--------|
| Primary creates virtio_user port | ✅ |
| Secondary discovers via VDEV_SCAN_REQ | ✅ |
| Secondary independently probes virtio_user | ✅ |
| Secondary accesses shared KNI ring | ✅ |
| Secondary completes full init | ✅ |

**K4 verified feasible at code and runtime level.**

### E4b — K4 PoC Verification

K4 PoC patch (106 lines, 7 changes, 4 files): secondary as runtime KNI owner, primary as init owner. Both processes stable (2min+), veth0 exists, KNI ring accessible.

**K4 PoC verified successful.**

## Appendix: Code Evidence Index

| Evidence | File | Line |
|----------|------|------|
| `RING_F_SC_DEQ` flag | `ff_dpdk_kni.c` | 486 |
| `kni_rp` secondary lookup | `ff_dpdk_kni.c` | 491 |
| `ff_kni_enqueue` (no owner gate) | `ff_dpdk_if.c` | 2094, 2102 |
| Broadcast clone (owner gate) | `ff_dpdk_if.c` | 2080 |
| `kni_process_tx` (owner only) | `ff_dpdk_kni.c` | 144-179 |
| `ff_kni_process` call (owner gate) | `ff_dpdk_if.c` | 2765 |
| `kni_rate_limt` per-process | `ff_dpdk_kni.c` | 100 |
| Ratelimit in `ff_kni_enqueue` | `ff_dpdk_kni.c` | 513-527 |
| Ratelimit in `kni_process_tx` | `ff_dpdk_kni.c` | 156-165 |
| Ratelimit reset in `main_loop` | `ff_dpdk_if.c` | 2722-2724 |
| `ff_kni_is_owner_thread` definition | `ff_dpdk_kni.c` | 92-98 |
| `rte_eal_hotplug_add` | `ff_dpdk_kni.c` | 474 |
| `kni_stat[port_id]->port_id` | `ff_dpdk_kni.c` | 478 |
| `total_nb_ports *= 2` | `ff_dpdk_if.c` | 821-825 |
| `init_port_start` primary gate | `ff_dpdk_if.c` | 1061-1063 |
| `nb_dev_ports` comment | `ff_dpdk_if.c` | 79 |
| `kni_process_rx` tx_burst | `ff_dpdk_kni.c` | 190 |
| vdev secondary scan | `vdev.c` | 482-503 |
| vdev_action primary response | `vdev.c` | 408-463 |
| virtio_user secondary probe | `virtio_user_ethdev.c` | 525-547 |
| `eth_virtio_dev_init` secondary | `virtio_ethdev.c` | 1951-1953 |
| `set_rxtx_funcs` | `virtio_ethdev.c` | 1247-1310 |
| `virtio_user_secondary_eth_dev_ops` | `virtio_ethdev.c` | 657-666 |
