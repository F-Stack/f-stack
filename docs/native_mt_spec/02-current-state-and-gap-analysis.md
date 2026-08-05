# 02 Current State and Gap Analysis

> Based on `lib/` code file:line. Material sources: `_material_A_globalstate.md`, `_material_B_dpdk.md`, `_material_C_lifecycle.md`.

## 1. Current State: Multi-Process Share-Nothing Model

### 1.1 One Process = One Lcore = One Stack Instance
- `ff_init()` (`ff_init.c:35-56`) serially calls `ff_load_config → ff_dpdk_init → ff_freebsd_init → ff_dpdk_if_up`, **running only once for the whole process**.
- Multi-core concurrency relies on **DPDK multi-process** (primary/secondary): each instance has one `proc_id`, configured via `proc_lcore[]`/`nb_procs` (`ff_config.c:79-139`), each process pinned to one lcore.
- `ff_dpdk_run()` (`ff_dpdk_if.c:2764-2773`): `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` + `rte_eal_mp_wait_lcore()`; but each process's coremask is a single bit (`ff_config.c:1151-1154`), so each process actually runs only one `main_loop`.
- In `main_loop` (`ff_dpdk_if.c:2585`), `qconf = &lcore_conf` takes the **global singleton**.
- Due to process isolation, `pcpup`/`lcore_conf`/`cc_cpu`/all `VNET_*` globals exist once per process, naturally share-nothing, never conflicting.

### 1.2 Configuration Model
- `struct ff_config.dpdk` (`ff_config.h:269-328`): `proc_type`(:272)/`lcore_mask`(:274)/`proc_mask`(:276)/`nb_procs`(:290)/`proc_id`(:291)/`proc_lcore`(:311).
- `parse_lcore_mask` (`ff_config.c:73-142`): number of set bits in lcore_mask = `nb_procs` (:139), each bit corresponds to one process on one lcore.
- proc_type validation only accepts primary/secondary/auto (`ff_config.c:1316-1321`).

### 1.3 Data-Plane/Control-Plane Rings
- `dispatch_ring[port][queue]` (data plane, `ff_dpdk_if.c:129`): `RING_F_SC_DEQ` (`:619`), multi-source lcores write, single owner reads (MP+SC).
- `msg_ring[RTE_MAX_LCORE]` (control-plane IPC, `:177`): `RING_F_SP_ENQ|RING_F_SC_DEQ` (`:670`), already array-ized by proc_id.
- mempool `pktmbuf_pool[NB_SOCKETS]` (`:125`) shared per NUMA socket, `cache_size=MEMPOOL_CACHE_SIZE` (`:540`), flag=0 (MP/MC).

### 1.4 KNI / Toolchain
- KNI strictly primary-only: `ff_kni_init/alloc` (`ff_dpdk_kni.c:379/426`), main loop (`ff_dpdk_if.c:2661`), config validation (`ff_config.c:1392-1412`).
- Toolchain (`tools/`) strongly depends on the secondary process: `ff_ipc_init` hardcodes `--proc-type=secondary` (`tools/compat/ff_ipc.c:67`), communicating with the stack via `msg_ring`.

## 2. Existing Thread Infrastructure (Reusable Positive Signals)

| Capability | file:line | Description |
|---|---|---|
| `pcurthread` TLS | `ff_compat.c:59` | Per-thread independent current-thread pointer, **already `__thread`**; `ff_api.h:55` extern |
| `ff_pthread_create` | `ff_thread.c:32-46` | Wraps pthread_create, propagates the parent thread's pcurthread to the child thread |
| `ff_adapt_user_thread_add/exit` | `ff_compat.c:96-128` | Creates an independent proc/thread context for user threads (independent fd table/cred/limit); comment marks "Only used by LD_PRELOAD mode" (`ff_compat.c:90`) |
| `ff_switch/restore_curthread` | `ff_compat.c:131-148` | Temporarily switches pcurthread |
| pcap per-thread | `ff_dpdk_pcap.c:55-57` | `static __thread` pattern reference |

**Key significance**: `curthread` is already TLS, precisely matching FreeBSD VNET's `curvnet=curthread->td_vnet` (`vnet.h:176`) — the biggest feasibility fulcrum for native multi-stack-instance.

## 3. Gap Analysis (What Is Missing for Native Multi-Stack-Instance)

| Gap | Current State | Goal | See |
|---|---|---|---|
| D1 Number of stack instances | One process, one instance | One process, N threads, N instances | `04` |
| D2 Initialization | `mi_startup`/SYSINIT one-shot, ticks after running (`ff_init_main.c:271`), cannot run N times | Independent initialization per thread (VNET_SYSINIT once per vnet + per-thread globals) | `04` |
| D3 Network-stack globals | Hundreds of `V_*` degenerate into process-level globals (no VIMAGE, `opt_global.h` has no VIMAGE) | Enable VIMAGE, isolate per-thread via `curvnet` | `03`/`05` |
| D4 f-stack self-made globals | `lcore_conf`/`pcpup`/`cc_cpu`/`thread0`/`msg_iov_tmp` global singletons | Per-thread-ize (arrays/`__thread`/per-instance) | `03` |
| D5 DPDK launch | One lcore per process | N lcores in one process (N-bit coremask) | `06` |
| D6 Config | No thread-mode field | Add thread_mode + nb_threads, opt-in mutual exclusion | `07` |
| D7 KNI | Gated by primary process | Gated by owner thread | `08` |
| D8 Toolchain | Depends on secondary process | Thread mode has no secondary; IPC needs redesign | `08` |

## 4. Adapter Current State (Objective Record, Not This Solution's Goal)

The LD_PRELOAD adaptation under `adapter/syscall/` (`FF_THREAD_SOCKET`/`FF_MULTI_SC` compile macros, `main_stack_thread_socket.c`, `ff_hook_syscall.c` worker_id mapping) is an **application-side** mechanism: it lets unmodified applications hijack socket calls via LD_PRELOAD and use the underlying **multi-process** f-stack in a multi-worker manner. It solves "how applications access f-stack", **not "the protocol stack itself runs multi-threaded"**. This round's goal is the latter; the adapter is out of scope of the solution, recorded here only to avoid confusing the two layers.
