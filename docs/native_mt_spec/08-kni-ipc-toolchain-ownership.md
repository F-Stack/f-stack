# 08 KNI / IPC / Toolchain Ownership

> Source `_material_C_lifecycle.md §3`. Thread mode has no secondary process; KNI and toolchain ownership need redesign.

## 1. KNI Current State (primary-only)

- `ff_kni_init` (`ff_dpdk_kni.c:376-420`): `kni_stat` allocated only under `RTE_PROC_PRIMARY` (`:379-386`); `kni_rp`/`tcp_port_bitmap`/`udp_port_bitmap` named by `rte_lcore_id()` (`:388-419`) — KNI rings already carry the lcore dimension.
- `ff_kni_alloc` (`ff_dpdk_kni.c:422-449`): `kni_stat[port_id]` allocation likewise primary-only (`:426`).
- Main-loop KNI handling (`ff_dpdk_if.c:2660-2664`): `ff_kni_process` called only when `enable_kni && rte_eal_process_type()==RTE_PROC_PRIMARY`.
- Config validation (`ff_config.c:1392-1412`): requires the primary lcore in each port's lcore_list.

## 2. KNI Ownership Design (Thread Mode)

- Thread mode has no primary/secondary process concept; KNI should be **exclusively owned by a single designated thread (e.g. thread 0 / instance 0)** holding the KNI resources and running `ff_kni_process`.
- Existing `kni_rp`/bitmaps are already named by `rte_lcore_id()` (`ff_dpdk_kni.c:388-419`), naturally per-lcore;
- Changes needed: `kni_stat` global + runtime `RTE_PROC_PRIMARY` gating (`ff_dpdk_if.c:2661`, `ff_dpdk_kni.c:379/426`) changed to **owner-thread determination** (e.g. `rte_lcore_id()==kni_owner_lcore`);
- Config validation (`ff_config.c:1396-1411`) changes from "primary lcore" to "KNI owner thread's lcore".

## 3. IPC / Toolchain Current State (Strongly Depends on secondary)

- `tools/compat/ff_ipc.c`: `ff_ipc_init` (`:54-80`) **hardcodes `--proc-type=secondary`** (`:67`) + `-c1` (`:66`), looks up the message pool built by primary via `rte_mempool_lookup(FF_MSG_POOL)` (`:77`), selects the target process's ring with `ff_proc_id` (`:42`).
- sysctl/netstat/ifconfig/ipfw/ndp/route/arp/ngctl etc. (`tools/` subdirectories) all attach into primary shared memory as **secondary processes**, communicating with the stack via `msg_ring` (built `ff_dpdk_if.c:649-667`, consumed by `process_msg_ring` `:2278/2699`, handled by `handle_msg` `:2225`).
- **The toolchain strongly depends on the multi-process secondary model.**

## 4. IPC / Toolchain Ownership Design (Thread Mode)

Thread mode has no secondary process; the existing toolchain based on `--proc-type=secondary` (`ff_ipc.c:67`) **cannot be reused directly**. Three candidates (for the subsequent coding phase to decide; this round lists trade-offs):

| Candidate | Description | Pros | Cons |
|---|---|---|---|
| C1 Keep external tool processes | The thread-mode process still acts as primary, exposing old-secondary-compatible shared hugepages + msg_ring; external `ff_ipc` tools attach as before | Minimal toolchain change, backward compatible | Must ensure the thread-mode process still builds `FF_MSG_POOL`/`msg_ring` attachable externally |
| C2 Built-in management thread | Merge the management plane into a management thread in the same process, via in-process shared memory/direct calls | Saves cross-process IPC overhead, more share-nothing | Tools must be rewritten as in-thread interfaces; large change |
| C3 unix socket direct connection | Tools connect to the target thread's msg_ring via unix socket | Decouples the DPDK secondary dependency | New channel implementation |

- **Suggestion**: keep the `msg_ring[proc_id]` array structure unchanged (already per-lcore, `:177`); in thread mode each stack thread consumes its own msg_ring with its own lcore/proc_id; **prefer C1** (compatible with old tools, minimal change); list "full toolchain thread-ization" (C2/C3) as a separate follow-up sub-item.

## 5. tools/ Ownership Summary

| Component | Current dependency | Thread-mode ownership |
|---|---|---|
| KNI | primary process | owner thread exclusively |
| `msg_ring` | array by proc_id (already per-lcore) | each thread uses its own lcore index, keep |
| `ff_ipc`/sysctl/netstat etc. | `--proc-type=secondary` | C1 keep external processes (preferred) / C2/C3 follow-up |

> Conclusion: **KNI can be smoothly changed to owner-thread gating** (rings already per-lcore named); **the toolchain is the biggest compatibility gap of thread mode**, recommended to be explicitly listed as a separate sub-item in the spec, with C1 preferred for compatibility in the coding phase.
