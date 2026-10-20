# M1-A Code-Path Verification: thread_mode=0 vs 1 Dual-Queue Differences + Root-Cause Location

> Prober: leader (pure read-only probing/aggregation role) + code-explorer subagent A
> Date: 2026-08-03
> Evidence rule: every conclusion carries `file:line`; items that cannot be statically judged are marked "requires runtime verification", with actual run output given below.

---

## 0. Prerequisite Facts (Basis of All Later Conclusions, All Code-Verified)

| Fact | Evidence |
|---|---|
| `parse_lcore_mask` writes bit-count into `nb_procs` and fills `proc_lcore[]` (mask=6 → `{1,2}`) | `lib/ff_config.c:110-141` |
| `port_cfgs[].nb_lcores` is fixed to `nb_procs`(=2) during ini parsing and copies `proc_lcore` | `lib/ff_config.c:566-572` |
| `thread_mode=1`'s collapse happens after all per-port validation: `nb_threads=nb_procs; nb_procs=1; proc_id=0; proc_mask=lcore_mask` | `lib/ff_config.c:1465-1484` |
| Therefore `nb_lcores==2` (queue count) equals `nb_threads==2`, while `nb_procs==1` | combination of the above two |
| DPDK main lcore = first enabled lcore (no `--main-lcore` passed) → with mask=6 it is lcore 1 | `dpdk-stable-24.11.6/lib/eal/common/eal_common_options.c` |
| All lcores (incl. main) run `main_loop` | `lib/ff_dpdk_if.c:2855` `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` |
| `ff_lcore_conf_idx()`: mode0 always 0; mode1 uses `rte_lcore_id()` | `lib/ff_memory.h:104-111` |

---

## 1. H6: dispatch_ring / msg_ring Allocated by nb_procs(=1) → Worker Accesses NULL Ring

**Conclusion: disproven (does not hold).**

- `init_dispatch_ring()`'s queue upper bound takes `pconf->nb_lcores` (=2), not `nb_procs`: `lib/ff_dpdk_if.c:643-660`
- `init_msg_ring()` explicitly picks `nb_threads` by thread_mode: `lib/ff_dpdk_if.c:692-694`
- Consumer-side indexing is legal: `process_dispatch_ring` uses `dispatch_ring[port_id][queue_id]` (`:2106`), `queue_id` comes from `init_lcore_conf`'s thread_mode branch 0/1 (`:441-448`); `process_msg_ring(qconf->proc_id)` (`:2784`), `lc->proc_id = ti` (`:433`)

**Runtime corroboration**: ff_log measured `dispatch_ring_p0_q0` / `dispatch_ring_p0_q1` both created successfully.

### 1.1 Incidental Conditional Defect Found (not triggered this round, suggested for later fix)

`init_mem_pool()`'s mempool creation loop upper bound is still `nb_procs`: `lib/ff_dpdk_if.c:548`

```c
for (i = 0; i < ff_global_cfg.dpdk.nb_procs; i++) {   /* thread_mode=1 → loops only once */
```

While `nb_mbuf` size calculation already correctly uses `nb_threads` (`:526-527`). Consequence: if a worker lcore is on a different NUMA socket than `proc_lcore[0]`, `pktmbuf_pool[worker_socket]` stays NULL and `init_port_start` fetching the pool by each queue's lcore socket (`:1062-1080`) gets NULL.
**This machine's lcores 1/2 are on the same socket (measured: ff_log only shows `create mbuf pool on socket 0`), so not triggered.**

---

## 2. H7: veth_ctx Main-Thread Entry and Worker Entry Misaligned/NULL/Duplicate-Created

**Conclusion: disproven.**

- `veth_ctx[RTE_MAX_LCORE][RTE_MAX_ETHPORTS]` is 2D-isolated by the lcore dimension, capacity sufficient
- workers create in `main_loop` indexed by `rte_lcore_id()` (`lib/ff_dpdk_if.c:2649-2664`), create only when `veth_ctx[lcore][port] == NULL`, no duplicates
- **Runtime corroboration**: `DBGVNET ... unit_eq=1` shows `ifunit_ref(if_name)`'s ifp equals `sc->ifp`, no misalignment

---

## 3. H8: KNI Ownership Swallows Port-80 SYN

**Conclusion: disproven for this scenario.**

- `ff_kni_is_owner_thread()`: under thread_mode=1, `rte_lcore_id() == proc_lcore[0]` (`lib/ff_dpdk_kni.c:92-98`), i.e. only lcore 1 is the owner
- `config.ini` is `kni.enable=1, method=reject, tcp_port=80,443` → `kni_accept=0`
- `process_packets`'s KNI branch (`lib/ff_dpdk_if.c:2081-2089`): only `FILTER_KNI && kni_accept` or `(FILTER_UNKNOWN || >=FILTER_OSPF) && !kni_accept` enters KNI. Port-80 TCP is `FILTER_KNI`, and `kni_accept=0` → **goes through `ff_veth_input`**, not KNI

---

## 4. H9: Worker vnet Has No Listen Socket

**Conclusion: disproven (the app side listens per thread).**

`example/main.c`:
- `kq`/`sockfd`/`sockfd6` are all `__thread` (`:22-28`)
- `init_thread()` per-thread does its own `ff_socket` + `SO_REUSEPORT` + `ff_bind` + `ff_listen` (`:62-140`)
- `loop()`'s first line calls `init_thread()` (`:144`), so every worker thread builds a listen socket
- **Runtime corroboration**: `helloworld.log` has `thread init success on lcore 1.` and `thread init success on lcore 2.`, both threads' listen succeeded

> But see Section 6: these sockets are **actually built in vnet0**, which is the real problem.

---

## 5. thread_mode=0 vs 1 Dual-Queue Path-Difference Comparison

| Dimension | thread_mode=0 (2 processes) | thread_mode=1 (2 threads) | Difference source? |
|---|---|---|---|
| `nb_procs` / `nb_threads` | 2 / 0 | 1 / 2 | No (everywhere already correctly adapted) |
| `lcore_conf` index | always 0 (`ff_lcore_conf_idx`) | `rte_lcore_id()` | No |
| queue allocation | 1 queue per process (measured p0→q0, p1→q1) | 1 queue per thread (q0/q1) | No |
| RSS config path | `if (dev_info.flow_type_rss_offloads)` whole block skipped (virtio) | **identical** | **No (key: both modes share the same "no RSS" path)** |
| `dispatch_ring` | by `nb_lcores`=2 | by `nb_lcores`=2 | No |
| `msg_ring` | by `nb_procs`=2 | by `nb_threads`=2 | No |
| mempool loop | `nb_procs`=2 (covers both lcore sockets) | `nb_procs`=1 (only covers lcore[0]'s socket) | Conditional (only cross-NUMA triggers) |
| KNI owner | primary process | `lcore==proc_lcore[0]` | No |
| **Protocol-stack instance** | per-process independent address space → independent vnet0, cred/prison0 one each | same process vnet0 + vnet_i, **sharing the unique prison0** | **Yes (root cause)** |

---

## 6. Root Cause (Code + Runtime Double-Verified)

### 6.1 Runtime Evidence

Temporary probes added in `lib/ff_veth.c` `ff_veth_setup_interface` / `ff_veth_setaddr` measured:

```
Main thread (f-stack-0.log):
DBGSOCK cret=0 so=0x7f9526f94400 so_vnet=0x37754ef0 curvnet=0x37754ef0 ioctl_ret=0
DBGVNET curvnet=0x37754ef0 ifp_vnet=0x37754ef0 ifp_fib=0 gw_ifa=0x37d1f240 self_ifa=0x37d1f240 unit_eq=1 flags=0x8803

worker   (helloworld.log):
DBGSOCK cret=0 so=0x7f9526f95c00 so_vnet=0x37754ef0 curvnet=0x7f952000eb10 ioctl_ret=0
DBGVNET curvnet=0x7f952000eb10 ifp_vnet=0x7f952000eb10 ifp_fib=0 gw_ifa=0 self_ifa=0 unit_eq=1 flags=0x8802
f-stack-0: ff_veth_set_gateway failed DBGERR=51
```

Interpretation:
- worker's `so_vnet=0x37754ef0` **equals the main thread's vnet0**, while `curvnet=0x7f952000eb10` is the worker's own vnet_2 → **inconsistent**
- `ioctl_ret=0` ("success"), but in the worker vnet `self_ifa=0` (`ifa_ifwithaddr(local IP)` not found), `gw_ifa=0` (`ifa_ifwithnet(gateway)` not found)
- `flags`: main thread `0x8803` includes `IFF_UP`(0x1), worker `0x8802` **lacks IFF_UP** (side effect of `if_up` never called)
- `DBGERR=51` = **ENETUNREACH** (`freebsd-src-releng-15.0/sys/sys/errno.h:114`), from `net/route.c:507` `rt_getifa_fib()`'s `info->rti_ifa == NULL`

### 6.2 Code Chain (all verified)

| Step | Location | Fact |
|---|---|---|
| 1 | `freebsd/net/vnet.c:336` | `curvnet = prison0.pr_vnet = vnet0 = vnet_alloc();` — prison0 permanently bound to vnet0 |
| 2 | `lib/ff_init_main.c:586-590` | worker cred: `p->p_ucred = crget(); ... cr_prison = &prison0;` |
| 3 | `freebsd/net/vnet.h:247` | `#define CRED_TO_VNET(cr) (cr)->cr_prison->pr_vnet` → **vnet0** |
| 4 | `freebsd/kern/uipc_socket.c:948` | `so = soalloc(CRED_TO_VNET(cred));` → all worker sockets' `so_vnet` = vnet0 |
| 5 | `freebsd/kern/uipc_socket.c:829-833` | `so->so_vnet = vnet;` (from the soalloc argument) |
| 6 | `freebsd/net/if.c:2908` | `ifioctl` starts with `CURVNET_SET(so->so_vnet);` → **switches to vnet0** |
| 7 | `lib/ff_veth.c:599-601` | `ff_veth_setaddr` uses `socreate()` + `ifioctl(so, SIOCAIFADDR, ...)` |
| 8 | consequence | worker's IP is added to **vnet0**'s `f-stack-0` (hence `ioctl_ret=0`); the ifp in the worker's own vnet_2 never gets an address |
| 9 | `lib/ff_veth.c:1028` → `lib/ff_veth.c:638` → `freebsd/net/route/route_ctl.c:756-757` → `freebsd/net/route.c:497,507` | `ff_veth_set_gateway`'s `rib_action(RTM_ADD)` executes in vnet_2 (not through a socket, directly using `curvnet`) → `ifa_ifwithroute` cannot find the on-link ifa → `ENETUNREACH` |

### 6.3 Why thread_mode=0 Has No Such Problem

Multi-process mode gives each process an independent address space, each with its own `prison0`, and each `prison0.pr_vnet = its own vnet0`, so `CRED_TO_VNET(cred) == curvnet` always holds. **Single-process multi-thread shares the unique `prison0` (global variable `ff_init_main.c:97`), which is exactly what exposes the mismatch.**

### 6.4 Impact Scope (not just routing)

All worker operations "entering the stack via sockets" are silently redirected to vnet0:
- `ff_veth_setaddr` / `ff_veth_setaddr6` / `ff_veth_setvaddr` (`ifioctl` path)
- `lo_set_defaultaddr()` (defined `lib/ff_freebsd_init.c:219-263`, `socreate` at `:255`, `ifioctl` at `:259`)
- **app-side `ff_socket`/`ff_bind`/`ff_listen`**: workers' listen PCBs all built in vnet0's PCB hash table, while the worker data plane `ff_veth_input` uses `ifp->if_vnet`(=vnet_2) as curvnet to look up PCBs → listen socket never found → no SYN-ACK

This exactly matches the measured "listen succeeds, client repeatedly retransmits SYN with no response".

---

## 7. Root-Cause Ranking

| Rank | Root cause | Nature |
|---|---|---|
| **1** | worker cred attached to `prison0` → `CRED_TO_VNET` always vnet0 → all socket/ifioctl operations redirected to vnet0 by `CURVNET_SET(so->so_vnet)` | **code + runtime double-verified** |
| 2 | `init_mem_pool` loop upper bound `nb_procs` (only cross-NUMA triggers) | code-verified, not triggered on this machine |
| 3 | virtio lacking RSS | **already disproven by E2 measurement** (thread_mode=0 dual-queue 231,570 req/s normal) |
