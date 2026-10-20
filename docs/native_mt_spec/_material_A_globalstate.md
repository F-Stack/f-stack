# Material A: FreeBSD Stack Global-State Inventory + Feasibility of Per-Thread Independent Stack-Instance Initialization

> Produced by subagent A (code deep-dive). Goal: in-library native support for "N pthreads in a single process (each pinned to one lcore), each running an independent FreeBSD protocol-stack instance, share-nothing via per-thread-ization of global state".
> Iron rule: every conclusion carries file:line; cross-validation conflicts resolved in favor of code; read-only, no lib changes.
> Code baseline: `/data/workspace/f-stack/lib/` (FreeBSD 15.0 port).

---

## 0. Overall Background Conclusion (Must Read; Decides the Whole Route)

### 0.1 Current f-stack Is a "Multi-Process" Model, Not "Multi-Thread Multi-Stack"
- `ff_init()` (`ff_init.c:35-56`) serially calls `ff_load_config → ff_dpdk_init → ff_freebsd_init → ff_dpdk_if_up`, **running only once for the whole process**.
- Multi-core relies on **DPDK multi-process** (primary/secondary): each instance has one `proc_id`, configured via `proc_lcore[]` / `nb_procs` (`ff_config.c:79-139`), each process pinned to one lcore.
- `ff_dpdk_run()` (`ff_dpdk_if.c:2764-2773`): `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` + `rte_eal_mp_wait_lcore()`. **Note**: although mp_remote_launch is used, a single process usually runs `main_loop` on only one lcore (the other lcores belong to other secondary processes); inside `main_loop` (`ff_dpdk_if.c:2585`) `qconf = &lcore_conf` directly takes the **global singleton**.
- Precisely because of process isolation, `pcpup` / `lcore_conf` / `cc_cpu` / all `VNET_*` globals exist once per process, naturally share-nothing, **never conflicting**.

### 0.2 VIMAGE / VNET Is Not Compiled — the Largest Hidden Change Surface
- `lib/opt/opt_global.h` is only 5 lines (MUTEX_NOINLINE / RWLOCK_NOINLINE / SX_NOINLINE / DEV_RANDOM / NO_EVENTTIMERS), **no `VIMAGE`**.
- Across all of lib, `VNET_DEFINE / curvnet / rootvnet` hits only in `ff_ng_base.c` (netgraph); the protocol-stack main path has no VNET.
- **Consequence**: all globals defined by `VNET_DEFINE(...)` in the FreeBSD source — `V_ifnet`, `V_in_ifaddrhead`/`V_in6_ifaddr`, `V_tcbinfo`/`V_udbinfo` (PCB hash tables), `V_rt_tables` (routing/FIB), `V_ipport_*` (port allocation), and masses of protocol counters and timers — **all degrade to ordinary process-level global singletons** when compiled in f-stack. Under multi-thread multi-stack, these are read/written and trampled by N threads simultaneously; this is the **largest class of global state in this solution** (order of magnitude: hundreds).
- Evidence: `ff_freebsd_init.c:87` directly uses `V_ifnet` (no curvnet context); `ff_route.c:643,1411` uses `rt_tables_get_rnh(fibnum, saf)` (the FIB table is global under non-VNET).

### 0.3 Two Optional per-Thread Isolation Macro Routes
- **`__thread` (GCC TLS)**: already used in f-stack (see §3). Suitable for "one pointer/small struct per thread".
- **`RTE_PER_LCORE` / `RTE_DEFINE_PER_LCORE`**: provided by DPDK, indexed by lcore, semantically highly aligned with "each thread pinned to one lcore". **Currently 0 uses in lib** (grep confirmed).
- **Struct arrays indexed by lcore_id**: `pktmbuf_pool[NB_SOCKETS]` (`ff_dpdk_if.c:125`), `msg_ring[RTE_MAX_LCORE]` (`ff_dpdk_if.c:177`) already follow this pattern, usable as a paradigm.

---

## 1. Dimension 1: Complete FreeBSD Stack Global-State Inventory

> Grade: P0=definite crash/data corruption core target under multi-thread; P1=high-frequency read/write trampling; P2=one-shot at init, must ensure once or one per instance; P3=low-frequency/stats; P4=read-only or naturally safe.

### 1.1 Thread/Process Context Core (f-stack's Own Globals)

| Variable | file:line | Type | Currently per-thread | Suggested isolation | Change cost | Grade |
|---|---|---|---|---|---|---|
| `pcpup` | `ff_freebsd_init.c:69` | `struct pcpu *` (global singleton) | No | `RTE_PER_LCORE` or `__thread`; one pcpu per thread, PCPU_GET/SET goes through it | Medium (PCPU macro foundation depends on it, wide impact) | **P0** |
| `pcurthread` | `ff_compat.c:59` | `__thread struct thread *` | **Yes (already TLS)** | OK as-is, keep | None | P4 |
| `thread0` / `thread0_st` | `ff_init_main.c:98` (`thread0_storage thread0_st`) | global singleton struct | No | one thread0 per instance (per-thread-ized together with pcpu/proc0) | Medium | **P0** |
| `proc0` | `ff_init_main.c:96` | `struct proc` global singleton | No | one per instance | Medium | **P0** |
| `prison0` / `vmspace0` / `initproc` | `ff_init_main.c:97,99,100` | global singleton | No | one per instance (or share prison0 read-only, needs evaluation) | Low-medium | P1 |
| `msg_iov_tmp[UIO_MAXIOV]` | `ff_syscall_wrapper.c:225` | `static struct iovec[1024]` | **No (`/*__thread*/` deliberately commented out)** | restore `__thread` (it is a per-call temporary buffer, TLS naturally correct) | **Very low (uncomment)** | **P0** |
| `msg_iovlen_tmp` | `ff_syscall_wrapper.c:226` | `static size_t` (same, commented) | No | restore `__thread` | Very low | **P0** |

> **Note**: `msg_iov_tmp/msg_iovlen_tmp` are used at `ff_syscall_wrapper.c:864,893-897` (`recvmsg/sendmsg` paths), temporary per-syscall storage. The commented-out `__thread` shows the historical single-process single-thread assumption. **Under multi-thread this is a deterministic data-corruption target with near-zero fix cost — the #1 "low-hanging fruit" P0.**

### 1.2 DPDK Forwarding-Layer Globals (f-stack's Own)

| Variable | file:line | Type | per-thread | Suggested isolation | Change cost | Grade |
|---|---|---|---|---|---|---|
| `lcore_conf` | `ff_dpdk_if.c:123` | `struct lcore_conf` (global singleton) | No | `RTE_PER_LCORE` or array indexed by lcore_id `lcore_conf[RTE_MAX_LCORE]` | Medium (**referenced 30+ times**, see below) | **P0** |
| `lcore_conf` (external refs) | `ff_memory.c:71,395,414,459,510` | `extern` refs | — | change along with the above | — | P0 |
| `pktmbuf_pool[NB_SOCKETS]` | `ff_dpdk_if.c:125` | array (by socket index) | Partial (by socket not by thread) | threads on the same socket can share the mempool, but the mempool itself must be MT-safe (DPDK mempool is MT-safe) | Low | P2 |
| `stop_loop` | `ff_dpdk_if.c:87` | `static int` | No | one stop flag per thread / `__thread` | Low | P1 |
| `freebsd_clock` | `ff_dpdk_if.c:89` | `static struct rte_timer` | No | one timer per thread (each stack instance's own hardclock) | Low-medium | **P1** |
| `msg_ring[RTE_MAX_LCORE]` | `ff_dpdk_if.c:177` | array (by lcore index) | Yes (already by lcore) | keep | None | P4 |
| `veth_ctx[RTE_MAX_ETHPORTS]` | `ff_dpdk_if.c:179` | array (by port) | No (by port, not thread) | if threads share a port (RSS queue split) evaluate shared-read | Medium | P2 |
| `ff_top_status` / `ff_traffic` | `ff_dpdk_if.c:181,182` | `static struct` stats | No | one per thread then aggregate | Low | P3 |
| `ff_rss_tbl[]` / `ff_rss_tbl6[]` | `ff_dpdk_if.c:203,223` | `static struct[]` RSS reverse tables | No | one per thread (or read-only shared, depends on whether runtime-written) | Medium | P1 |
| `rss_thash_ctx/ready[RTE_MAX_ETHPORTS]` etc. | `ff_dpdk_if.c:137-139,158-160` | `static[]` by port | No | built once at init, read-only at runtime → shareable | Low | P3 |
| `dispatch_ring / packet_dispatcher(_with_context)` | `ff_dpdk_if.c:129-131` | `static` global callback/rings | No | one per thread or read-only shared | Low | P2 |
| `enable_kni / kni_accept / knictl_action` | `ff_dpdk_if.c:74-76` | globals | No | one per thread or read-only | Low | P2 |
| `numa_on / idle_sleep / pkt_tx_delay` | `ff_dpdk_if.c:80,82,83` | `static` (assigned at init, read-only at runtime) | No | read-only after init → shareable | Low | P4 |
| `rsskey / rsskey_len` | `ff_dpdk_if.c:120,121` | `static` (read-only) | No | read-only shared | None | P4 |

### 1.3 callout / Timer Subsystem (`ff_kern_timeout.c`, FreeBSD port)

| Variable | file:line | Type | per-thread | Suggested isolation | Change cost | Grade |
|---|---|---|---|---|---|---|
| `cc_cpu` | `ff_kern_timeout.c:180` | `struct callout_cpu` (global singleton; `CC_CPU()/CC_SELF()` all return it, see `:181,182`) | No | one callout_cpu per thread (each stack instance's independent callwheel/timer wheel) | **High** (callout subsystem core; all TCP/IP timers hang on it) | **P0** |
| `callwheelsize` / `callwheelmask` | `ff_kern_timeout.c:135` | `u_int` globals | No | one per instance (or shared read-only same value, but the callwheel itself must be one per instance) | Medium | **P1** |
| `timeout_cpu` | `ff_kern_timeout.c:187` | `static int` | No | one per instance | Low | P1 |
| `ncallout` | `ff_kern_timeout.c:107` | `static int` (sysctl RDTUN) | No | fixed at init, read-only | Low | P3 |
| `avg_depth/gcalls/lockcalls/mpcalls` | `ff_kern_timeout.c:93-104` | `static int` (only CALLOUT_PROFILING) | No | stats, only under profiling | Low | P4 |

> **Key**: `CC_CPU(cpu)` / `CC_SELF()` are hardcoded to `&cc_cpu` (`:181-182`), completely ignoring the passed cpu parameter. Multi-thread multi-stack must change to "take each thread's own callout_cpu by lcore_id/thread index", otherwise N stacks' timers (TCP retransmit, keepalive, TIME_WAIT, etc.) all serialize onto one callwheel — lock contention + logic corruption. **This is the second-hardest change bone after lcore_conf/pcpup.**

### 1.4 FreeBSD Kernel Port Process/Init Globals (`ff_init_main.c`)

| Variable | file:line | Type | per-thread | Suggested isolation | Change cost | Grade |
|---|---|---|---|---|---|---|
| `sysinit / sysinit_end` | `ff_init_main.c:123` | `struct sysinit **` globals | No | see §2 (one-shot ordering table; N executions problematic) | High | **P0** |
| `newsysinit / newsysinit_end` | `ff_init_main.c:124` | same | No | same | High | P0 |
| `null_sysvec` | `ff_init_main.c:301` | global struct (read-only constant-like) | No | read-only shared | None | P4 |
| `proctree_lock`(sx) | `ff_freebsd_init.c:68` | global lock | No | one lock per instance | Low | P2 |
| `uma_page_slab_hash / uma_page_mask` | `ff_freebsd_init.c:70,71` | UMA allocator global hash | No | UMA is the memory-allocator foundation, **extremely hard to per-thread**; suggest sharing the whole UMA layer + locking (whether current state is MT-safe needs runtime validation) | High/questionable | **P0(questionable)** |
| `physmem` | `ff_freebsd_init.c:74` | `long` | No | fixed at init, read-only | None | P4 |
| `all_cpus`(cpuset) | `ff_freebsd_init.c:72`(extern) | global | No | each instance sets its own cpu | Low | P2 |

### 1.5 `ff_compat.c` FreeBSD Globals

| Variable | file:line | Type | per-thread | Suggested isolation | Change cost | Grade |
|---|---|---|---|---|---|---|
| `rootvnode` | `ff_compat.c:62` | `struct vnode *` | No | f-stack does no real VFS, mostly placeholder; one per instance or shared NULL | Low | P3 |
| `allproc` / `allproc_lock` | `ff_compat.c:64,65` | process list + lock | No | one per instance (each stack's own proc0 chain) | Medium | P1 |
| `allprison / allprison_lock` | `ff_compat.c:66,67` | jail list + lock | No | one per instance or shared read-only | Low | P2 |
| `namei_zone` | `ff_compat.c:76` | `uma_zone_t` (link-time symbol, unreachable at runtime) | No | shared (unreachable path) | None | P4 |
| `async_io_version` | `ff_compat.c:70` | `int` | No | read-only | None | P4 |
| `seed` | `ff_compat.c:80` | `unsigned int` (arc4random seed) | No | `__thread` (avoid multi-thread rand_r contention) | Very low | P2 |
| `vttoif_tab[10]` | `ff_compat.c:84` | read-only table | No | read-only shared | None | P4 |

### 1.6 pcap (Comparison: Already-Correct per-Thread Paradigm)

| Variable | file:line | Type | per-thread | Note |
|---|---|---|---|---|
| `g_pcap_fp / seq / g_flen` | `ff_dpdk_pcap.c:55-57` | `static __thread` | **Yes** | proves f-stack already has the `__thread` per-thread convention, reusable |

### 1.7 VNET-Degraded Globals (§0.2, Largest Scale; Needs B/C Agent Cross-Check Against the FreeBSD Source Tree)
- Specific line numbers not listed (inside `freebsd-src-releng-15.0/sys/`, not f-stack/lib). Categories:
  - `V_ifnet` (ifnet list), `V_in_ifaddrhead` / `V_in6_ifaddr` (address tables)
  - `V_tcbinfo` / `V_udbinfo` (TCP/UDP PCB hash tables + locks)
  - `V_rt_tables` (routing/FIB, already referenced at `ff_route.c:643,1411`)
  - `V_ipport_lowfirstauto` and other port-allocation globals
  - Hundreds of protocol counters (`V_tcpstat` / `V_ipstat` / `V_ip6stat` ...)
- Uniform grade **P0-P1**: this is the share-nothing multi-stack **main battlefield**. For per-thread-ization: either enable VIMAGE so each thread's `curvnet` points to an independent vnet (huge engineering, and f-stack has emasculated the VNET infrastructure), or manually per-thread-ize this batch of globals one by one (astronomical count). **Suggestion: have the leader ask agents B/C to specifically inventory the VNET global list and evaluate the cost of "enable VIMAGE vs manual per-thread-ization".**

---

## 2. Dimension 2: Feasibility of Per-Thread Independent Stack-Instance Initialization (Core Difficulty)

### 2.1 The One-Shot Initialization Sequence (`ff_freebsd_init.c:124-192`)
`ff_freebsd_init()` is currently **process-level one-shot**:
1. `kern_setenv` (`:134-148`) — global env vars, N runs overwrite each other.
2. `pcpup = malloc(...)` + `pcpu_init` + `PCPU_SET(prvspace, pcpup)` + `CPU_SET(0, &all_cpus)` (`:152-155`) — **writes the global singleton `pcpup`**; after N executions only one pcpu survives, the rest leak/overwrite.
3. `ff_init_thread0()` (`:157` → `ff_compat.c:157-160`: `pcurthread = &thread0`) — points the TLS at the **global singleton thread0**. Multi-instance needs each to point at its own thread0.
4. `uma_startup1/2` + `uma_page_slab_hash` (`:162-167`) — **UMA allocator global init, inherently one-shot**. N runs re-initialize UMA and break the slab hash.
5. `mutex_init()` + **`mi_startup()`** (`:169-170`) — see §2.2, the hardest bone.
6. `sx_init(&proctree_lock)` (`:171`) — global lock, repeated init on N runs.
7. `lo_set_defaultaddr()` (`:187`) — configures loopback with 127.0.0.1, operating on the global `V_ifnet`.

### 2.2 `mi_startup()` / SYSINIT — Statically Determinable "Cannot Safely Run N Times" 【Hard Conclusion】
- `mi_startup()` (`ff_init_main.c:173-285`) walks the `sysinit_set` linker set, **executes each SYSINIT and ticks `(*sipp)->subsystem = SI_SUB_LAST`** (`:271`); after running, all entries are marked executed.
- On a second call: `if (sysinit == NULL)` (`:188`) no longer holds (assigned in the first call); in the sort loop **all entries already have subsystem SI_SUB_LAST**, and `:235-236` all `continue` skip → **the second `mi_startup()` actually does nothing**.
- **Consequence**: when N threads each call `ff_freebsd_init()` once, **only the first truly runs the protocol-stack subsystem init** (`domaininit`, `tcp_init`, `ip_init`, hash-table allocation, UMA zone creation ... all via SYSINIT); subsequent threads get **the one global stack state initialized by the first call**, never an independent instance.
- The SYSINIT table itself is a **process-level linker set shared by all threads** (`ff_init_main.c:122` `SET_DECLARE(sysinit_set, ...)`); a "per-thread sysinit table" is impossible without heavily hacking mi_startup.
- Among them, `SYSINIT(p0init, SI_SUB_INTRINSIC, ...)` (`ff_init_main.c:523`) initializes the **global singletons proc0/thread0**; `SYSINIT(callwheel_init, SI_SUB_CPU, ...)` (`ff_kern_timeout.c:279`) initializes the **global singleton cc_cpu**. These SYSINITs semantically "initialize the one global object once".

> **【Hard conclusion · statically determinable】**: the existing `ff_freebsd_init()` + `mi_startup()` + SYSINIT mechanism **cannot produce N independent protocol-stack instances by "calling once per thread"**. The first call does all real initialization and ticks the SYSINITs; subsequent calls spin idly. Multi-stack requires **restructuring the initialization architecture**, one of two routes:
> - **Route A (per-thread stack globals + init rework)**: per-thread-ize all stack globals (incl. §1 + §0.2's VNET-degraded globals), and change `mi_startup` to "run once per thread with a per-thread sysinit completion marker" (e.g. a per-thread sysinit tick bitmap, or init functions directly accepting a per-thread context pointer). Engineering: enormous.
> - **Route B (enable VIMAGE)**: enable FreeBSD VNET/VIMAGE, each thread's `curvnet` points to an independent vnet instance, reusing the kernel's mature multi-network-stack infrastructure. But f-stack currently **does not compile VIMAGE at all** (§0.2), and f-stack heavily emasculates FreeBSD (`ff_init_main.c` has large `#if 0` blocks); whether the VNET infrastructure can run in f-stack's userspace **cannot be statically determined; requires runtime validation**.

### 2.3 `ff_init` / `ff_run` Call-Site Status
- `ff_init()` (`ff_init.c:35`): no per-thread call design anywhere in lib; example calls it once at process startup.
- `ff_run()` (`ff_init.c:58-62`) → `ff_dpdk_run()` (`ff_dpdk_if.c:2764`) → `rte_eal_mp_remote_launch(main_loop,...)`. Although mp_remote_launch starts main_loop on all lcores, **main_loop takes `qconf=&lcore_conf` (global singleton)** — so even if multiple lcores physically run, they logically share one lcore_conf/stack globals: **not multi-stack, but multiple threads trampling one stack (will crash)**.
- Conclusion: `ff_init/ff_run` **are not a per-thread multi-stack design today**; the rework needs a new flow per thread: "pin lcore → build independent thread context → run independent ff_freebsd_init (after rework) → enter main_loop with each thread's own lcore_conf".

### 2.4 Honest-Boundary Marking
- 【Statically determinable, cannot run N times】: `mi_startup`/SYSINIT tick mechanism (§2.2), `pcpup`/`thread0`/`proc0` global-singleton overwrite, UMA one-shot init.
- 【Statically undeterminable, requires runtime validation】: (a) whether the UMA allocator is MT-safe under multi-thread concurrency (`uma_page_slab_hash` not per-thread); (b) if taking the VIMAGE route, whether f-stack's emasculated VNET infrastructure runs; (c) actual behavior of DPDK mempool/mbuf under multi-thread shared socket; (d) the hpts/tcp timer interaction after callout becomes multi-instance (`ff_kern_timeout.c:1252-1274`'s tcp_hpts_softclock special handling).

---

## 3. Dimension 3: Current Thread-Infrastructure Status

### 3.1 Existing per-Thread Capabilities
| Capability | file:line | Note |
|---|---|---|
| `pcurthread` TLS | `ff_compat.c:59` `__thread struct thread *pcurthread` | per-thread independent current-thread pointer, **already TLS**. `ff_api.h:55` extern declaration. |
| `ff_pthread_create` | `ff_thread.c:32-46` | wraps pthread_create, **propagates the parent thread's pcurthread to the child** (`data->parent = pcurthread`, child does `ff_set_thread(parent)`). `ff_api.h:182`. |
| `ff_init_thread0` | `ff_compat.c:157-160` | sets pcurthread to the global thread0. |
| `ff_adapt_user_thread_add/exit` | `ff_compat.c:96-128` | builds an independent proc/thread context for "user threads" (`ff_adapt_user_proc_add` in `ff_init_main.c:541-639`, incl. independent fd table `fdcopy`, independent cred, independent limit). `ff_api.h:481,483`. **Comment marks "Only used by LD_PRELOAD mode"** (`ff_compat.c:90`). |
| `ff_switch/restore_curthread` | `ff_compat.c:131-148` | temporarily switches pcurthread (LD_PRELOAD scenario). `ff_api.h:485,487`. |
| pcap per-thread | `ff_dpdk_pcap.c:55-57` | `static __thread` paradigm reference. |

### 3.2 Gaps (What Is Still Missing for Native Multi-Stack)
1. **Per-thread only has an independent thread/proc context, not an independent "stack instance"**: `ff_adapt_user_thread_add` builds thread+proc (fd table, cred, limit), **sharing the same protocol-stack globals** (PCB tables, routing, ifnet, callout). This only solves "each thread has an identity", not "each thread has an independent protocol stack".
2. **`ff_pthread_create` only propagates the parent thread pointer** (`ff_thread.c:44`), **does not**: pin lcore, build an independent stack instance, or run an independent ff_freebsd_init.
3. **No per-thread `pcpup` / `lcore_conf` / `cc_cpu` accessor**: all code directly references the global symbols (`&lcore_conf`, `&cc_cpu`, `pcpup`), with no "take each one's instance by current thread/lcore" indirection layer. A unified access macro/function (e.g. `ff_current_stack()`) must be introduced.
4. **No multi-stack lifecycle management**: no "create/destroy/registry table for N stack instances".
5. **VNET-degraded globals have no isolation layer** (§0.2): the main-battlefield gap.

---

## 4. Top-Target Ranking (for leader Decision)

| Rank | Target | file:line | Why the #1 P0 | Change cost |
|---|---|---|---|---|
| 0 (low-hanging fruit) | `msg_iov_tmp/msg_iovlen_tmp` | `ff_syscall_wrapper.c:225-226` | deterministic data corruption, and **restoring the commented-out `__thread` suffices** | Very low |
| 1 | `mi_startup`/SYSINIT one-shot mechanism | `ff_init_main.c:173-285`, `:271` | **the architecture-level blocker deciding whether multi-stack can exist** (statically determined cannot run N times) | Enormous |
| 2 | `lcore_conf` global singleton | `ff_dpdk_if.c:123` (30+ refs + `ff_memory.c`) | forwarding-layer core; multi-thread sharing crashes | Medium-large |
| 3 | `pcpup` / `thread0` / `proc0` singletons | `ff_freebsd_init.c:69`, `ff_init_main.c:96,98` | PCPU macro foundation + kernel identity objects | Medium |
| 4 | `cc_cpu` callout singleton | `ff_kern_timeout.c:180-182` | all TCP/IP timers share one wheel; lock contention + logic corruption | High |
| 5 | VNET-degraded globals (hundreds) | freebsd-src tree (`V_ifnet/V_tcbinfo/V_rt_tables/...`) | share-nothing main battlefield | Enormous (dedicated agent suggested) |
| 6 | UMA allocator global | `ff_freebsd_init.c:70-71,162-167` | allocator foundation; per-thread extremely hard; MT-safety questionable | High/requires runtime validation |

---

## 5. Cross-Validation Hints (for B/C Agents)
- §0.2's VNET-degraded globals' **specific line numbers are inside `freebsd-src-releng-15.0/sys/`**; this agent only inventoried the f-stack/lib-side reference points; agents B/C must go deeper into the freebsd source tree to complete the `VNET_DEFINE` inventory and evaluate the VIMAGE route.
- §2.4's four 【requires runtime validation】 conclusions cannot be statically determined by this agent; must be left to runtime or dedicated validation, **no speculation**.
