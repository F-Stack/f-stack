# Research Material B: Deep Dive on DPDK-Side Native Multi-Threading Integration Capabilities

> Produced by subagent B (explorer-dpdk). Direction: **in-library native support for N pthreads in a single process (each pinned to one lcore), each running an independent FreeBSD protocol-stack instance, share-nothing** (not the adapter route).
> All conclusions follow the code, each with `file:line`. Honestly marks "statically determinable" vs "requires runtime validation".
> Code baseline: `/data/workspace/f-stack/lib/`; DPDK cross-reference: `/data/workspace/dpdk-stable-24.11.6/`.

---

## I. DPDK Multi-Lcore Thread Launch Mechanism

### 1.1 Current f-stack Launch Path (Root Cause of Only One Lcore Running per Process)

`ff_dpdk_run()` → `rte_eal_mp_remote_launch`:

```
lib/ff_dpdk_if.c:2763  void ff_dpdk_run(loop_func_t loop, void *arg) {
lib/ff_dpdk_if.c:2765      struct loop_routine *lr = rte_malloc(...);
lib/ff_dpdk_if.c:2768      lr->loop = loop;
lib/ff_dpdk_if.c:2769      lr->arg  = arg;
lib/ff_dpdk_if.c:2770      rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);
lib/ff_dpdk_if.c:2771      rte_eal_mp_wait_lcore();
lib/ff_dpdk_if.c:2772      stop_clock();
```

Key point: **`rte_eal_mp_remote_launch` itself launches one `main_loop` on every EAL-registered lcore.**
A single process running only one lcore today is **not** a limitation of the launch API, but because the **coremask (EAL `-c`/`-l` argument) is a single bit**, so this process only registered 1 lcore.

DPDK-side semantics (cross-verified):
- `rte_eal_mp_remote_launch(f, arg, call_main)`: `dpdk-stable-24.11.6/lib/eal/include/rte_launch.h:99`
  Docs `:78-82`: *"Launch a function on all lcores. Check that each WORKER lcore is in a WAIT state, then call rte_eal_remote_launch() for each lcore."*
- `rte_eal_remote_launch(f, arg, worker_id)`: `rte_launch.h:67`
  Docs `:37-51`: sends a message to the specified worker lcore (in WAIT state); **that remote lcore = a pthread already created and core-pinned by EAL**; upon receiving the message it switches to RUNNING, calls `f(arg)`, and returns to WAIT after finishing.
- `rte_eal_wait_lcore(worker_id)`: `rte_launch.h:130`; `rte_eal_mp_wait_lcore()`: `rte_launch.h` (`:133` doc section) waits for all lcores to return to WAIT.

**Conclusion (statically determinable)**: `lcore = pthread + core pinning`, created once by EAL at `rte_eal_init` per the coremask. To launch N lcore threads in a single process, **the launch code needs almost no change**; you only need:
1. Give EAL an N-bit coremask in the startup args (e.g. `-l 0-3`) → EAL automatically creates N worker pthreads;
2. `rte_eal_mp_remote_launch(main_loop, ...)` automatically runs one `main_loop` on each of the N lcores (`ff_dpdk_if.c:2770`).

⇒ **The "thread creation" layer of launching multiple lcores in one process is natively provided by DPDK, and f-stack's existing code already has it.** The real change points are "whether the global state accessed inside each `main_loop` is per-lcore isolated" (see Sections II and IV).

### 1.2 TLS Nature of the lcore id (Natural Foundation for per-Thread Isolation)

- `rte_lcore_id()` definition: `dpdk-stable-24.11.6/lib/eal/include/rte_lcore.h:77-81`
  ```c
  static inline unsigned rte_lcore_id(void) { return RTE_PER_LCORE(_lcore_id); }
  ```
  That is, the lcore id itself is a **TLS (`__thread`) variable**; every EAL thread naturally knows which lcore it is, **no argument passing needed**.
- `RTE_LCORE_FOREACH(i)`: `rte_lcore.h:217-220`; `RTE_LCORE_FOREACH_WORKER(i)`: `rte_lcore.h:225-228` (iterate all / all but main running lcores).
- `rte_get_next_lcore(i, skip_main, wrap)`: `rte_lcore.h:212`.

**Significance**: after f-stack global state is per-thread-ized, each thread can use `rte_lcore_id()` or `lcore_conf.proc_id` as the **array subscript** to index its own instance, no lock, no argument passing. This is the core feasibility fulcrum of "native multi-thread share-nothing" (statically determinable).

`ff_dpdk_if.c:419` / `:1148` already use `rte_lcore_id()` (getting the socket, registering the timer).

---

## II. Per-Thread Independent RX/TX Queues and Independent Rings (Core)

### 2.1 `lcore_conf` — Currently a "Global Singleton", the #1 Obstacle to Multi-Threading

Struct definition: `lib/ff_memory.h:82-95`
```
lib/ff_memory.h:82   struct lcore_conf {
lib/ff_memory.h:83       uint16_t proc_id;
lib/ff_memory.h:84       uint16_t socket_id;
lib/ff_memory.h:85       uint16_t nb_queue_list[RTE_MAX_ETHPORTS];
lib/ff_memory.h:86       struct ff_port_cfg *port_cfgs;
lib/ff_memory.h:88       uint16_t nb_rx_queue;
lib/ff_memory.h:89       struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
lib/ff_memory.h:90       uint16_t nb_tx_port;
lib/ff_memory.h:91       uint16_t tx_port_id[RTE_MAX_ETHPORTS];
lib/ff_memory.h:92       uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
lib/ff_memory.h:93       struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];   // TX buffers per port
lib/ff_memory.h:95   } __rte_cache_aligned;
```
`struct lcore_rx_queue { port_id; queue_id; }`: `ff_memory.h:77-80`.

**Global singleton declaration**: `lib/ff_dpdk_if.c:123  struct lcore_conf lcore_conf;` (**not an array**).

All hot paths directly reference this one singleton:
- `main_loop`: `ff_dpdk_if.c:2585  qconf = &lcore_conf;`
- `ff_dpdk_if_up`: `ff_dpdk_if.c:2749  struct lcore_conf *qconf = &lcore_conf;`
- `process_packets`: `ff_dpdk_if.c:1905  struct lcore_conf *qconf = &lcore_conf;`
- `send_burst`/`send_single_packet` go through `qconf->tx_queue_id` / `tx_mbufs` (`:2305-2306`).

**Conclusion (statically determinable, #1 change point)**:
> `lcore_conf` is a **process-level global singleton**. If N lcores run `main_loop` simultaneously today, they **share one `lcore_conf`** (especially the `tx_mbufs` TX buffers and `tx_queue_id`), causing data races.
> **The native multi-thread rework must make `lcore_conf` per-lcore: `struct lcore_conf lcore_conf[RTE_MAX_LCORE]` (or `RTE_DEFINE_PER_LCORE`), with each `main_loop` indexing its own copy with `&lcore_conf[rte_lcore_id()]` (or proc_id).**
> Fortunately, the **queue ids and TX buffers inside the struct are already naturally per-lcore** (each lcore corresponds to one NIC queue); splitting into an array makes it share-nothing with no locks.

`init_lcore_conf()` (`ff_dpdk_if.c:400-467`) currently fills only one copy for **this process's single lcore_id** (`:424 lcore_id = proc_lcore[proc_id]`); under multi-thread it must fill one copy per lcore (loop / or each thread inits its own).

### 2.2 RX/TX Queue Allocation by Lcore Semantics

- Queue count = `pconf->nb_lcores` (number of lcores per port): `ff_dpdk_if.c:602 int nb_queues = pconf->nb_lcores;`
- `rte_eth_dev_configure(port, nb_queues, nb_queues, ...)`: `ff_dpdk_if.c:1006` (RX/TX queue count = lcore count).
- Per-queue setup: `ff_dpdk_if.c:1019-1037`, `q` from 0..nb_queues-1, `rte_eth_tx_queue_setup(port,q,...)` / `rte_eth_rx_queue_setup(port,q,...,mbuf_pool)`.
- The queue the current process claims: in `init_lcore_conf`, find its own `queueid=i` by `lcore_list[i]==lcore_id` (`ff_dpdk_if.c:436-440`), recorded into `rx_queue_list`/`tx_queue_id` (`:446-450`).

**Conclusion (statically determinable)**: DPDK **each NIC queue is inherently independent** (RSS hashes different flows to different queues); one lcore exclusively owns one RX queue + one TX queue. This "N queues ↔ N lcores" mapping **is itself the ideal model of a share-nothing data plane**. Under the current multi-process model each process claims one queue; converting to single-process multi-thread only requires each thread to claim the corresponding `queueid=i` in its own `lcore_conf[i]`; **the queue layer is naturally share-free, no NIC configuration logic change needed**.

### 2.3 dispatch_ring — Can `RING_F_SC_DEQ` (Single Consumer) Be Preserved?

Creation: `init_dispatch_ring()`
```
lib/ff_dpdk_if.c:129   static struct rte_ring **dispatch_ring[RTE_MAX_ETHPORTS];
lib/ff_dpdk_if.c:603   dispatch_ring[portid] = rte_zmalloc(... nb_queues pointers ...);
lib/ff_dpdk_if.c:615   for (queueid = 0; queueid < nb_queues; ++queueid) {
lib/ff_dpdk_if.c:618       dispatch_ring[portid][queueid] = create_ring(name_buf,
lib/ff_dpdk_if.c:619           DISPATCH_RING_SIZE, socketid, RING_F_SC_DEQ);
```
- Structure: `dispatch_ring[port][queue]`, **one ring per (port,queue)**, `nb_queues = nb_lcores` (`:602`).
- Flag: only `RING_F_SC_DEQ` (**single-consumer** dequeue), **no `RING_F_SP_ENQ`** (i.e. enqueue defaults to **MP multi-producer**).

**Consumer (single)**: `process_dispatch_ring(port,queue,...)` `ff_dpdk_if.c:2044`, `rte_ring_dequeue_burst(dispatch_ring[port][queue],...)` `:2049`. Each ring is dequeued only by "the lcore owning that queue" ⇒ **single consumer holds**.

**Producers (multi)**: in `process_packets`, packets not belonging to this queue are enqueued to the target queue's ring:
- User-dispatcher redirection: `ff_dpdk_if.c:1964 rte_ring_enqueue(dispatch_ring[port_id][ret], rtem);` (`ret != queue_id`, i.e. writing to **another lcore's** ring)
- ARP/NDP broadcast clones to all other queues: `ff_dpdk_if.c:1996 rte_ring_enqueue(dispatch_ring[port_id][j], mbuf_clone);` (`j != queue_id`)

That is: **each dispatch_ring is written by multiple lcores (source lcores) and read by a single lcore (owner)** ⇒ naturally an **MP + SC** model. The current flag `RING_F_SC_DEQ` (SC dequeue + default MP enqueue) **exactly matches**.

**Conclusion (statically determinable, key ruling)**:
> - **dispatch_ring must NOT be changed to SP (enqueue) under native multi-thread**: it is inherently a cross-thread distribution pipe of "multiple source lcores → single owner lcore"; multi-producer is an essential requirement, and the current **MP (default) + SC (`RING_F_SC_DEQ`) configuration remains correct and necessary under multi-thread — no change needed.**
> - Under the multi-process model these rings are visible cross-process via shared hugepages; converting to single-process multi-thread makes them **cross-thread shared in-process**, and `rte_ring`'s lock-free MP/SC semantics **apply equally to threads** (DPDK rings treat processes and threads identically — both are lock-free rings over shared memory). ⇒ **dispatch_ring migrates smoothly, flags unchanged.**

### 2.4 msg_ring — `RING_F_SP_ENQ | RING_F_SC_DEQ` (Single-Producer Single-Consumer) Semantics

Creation: `init_msg_ring()`
```
lib/ff_dpdk_if.c:170   struct ff_msg_ring { char ring_name[FF_MSG_NUM][...]; struct rte_ring *ring[FF_MSG_NUM]; } __rte_cache_aligned;
lib/ff_dpdk_if.c:177   static struct ff_msg_ring msg_ring[RTE_MAX_LCORE];   // already an array indexed by proc_id/lcore!
lib/ff_dpdk_if.c:667   for (i = 0; i < nb_procs; ++i) {
lib/ff_dpdk_if.c:670       msg_ring[i].ring[0] = create_ring(..., RING_F_SP_ENQ | RING_F_SC_DEQ);   // in ring
lib/ff_dpdk_if.c:678       msg_ring[i].ring[j] = create_ring(..., RING_F_SP_ENQ | RING_F_SC_DEQ);   // out rings
```
- `ring[0]` = external tool process → this stack thread (sysctl/ioctl requests in); `ring[1..]` = this stack thread → external tool (responses out).
- **`msg_ring` is already a `[RTE_MAX_LCORE]` array** (`:177`), **one independent in/out ring set per proc_id/lcore**.
- Consume: `process_msg_ring(proc_id, ...)` `ff_dpdk_if.c:2278`, `rte_ring_dequeue_burst(msg_ring[proc_id].ring[0],...)` `:2284`; in `main_loop`: `process_msg_ring(qconf->proc_id, ...)` `:2699`.
- Produce/respond: `handle_msg(msg, proc_id)` `:2225`, reply enqueued to `msg_ring[proc_id].ring[msg->msg_type]` `:2265`.

**Conclusion (statically determinable)**:
> `msg_ring` is **control-plane IPC** (f-stack stack process ↔ external `ff_ipc`/sysctl client tools), **not the data plane**. It is **already array-ized by proc_id** (`:177`); the SP/SC premise is "single external client ↔ single stack thread" 1:1.
> Converting to single-process multi-thread: each stack thread indexes `msg_ring[proc_id]` with its own `proc_id` (=lcore ordinal), **the array is naturally per-thread isolated, SP/SC semantics can be preserved as-is, no flag change needed**. External tools still find the corresponding thread's ring by proc_id.

---

## III. mempool / mbuf pool MT-Safety

### 3.1 f-stack-Side Creation

```
lib/ff_dpdk_if.c:125   struct rte_mempool *pktmbuf_pool[NB_SOCKETS];   // one pool per NUMA socket (not per-lcore)
lib/ff_dpdk_if.c:538   pktmbuf_pool[socketid] = rte_pktmbuf_pool_create(s, nb_mbuf,
lib/ff_dpdk_if.c:540       MEMPOOL_CACHE_SIZE, 0, data_room, socketid);
```
- Pools are shared by **NUMA socket** (`pktmbuf_pool[socketid]`); **all lcores on the same socket share one pool**.
- `cache_size = MEMPOOL_CACHE_SIZE` (`:540`, non-zero) — **key**: per-lcore cache enabled.
- Built once per socket: `:518-520 if (pktmbuf_pool[socketid] != NULL) continue;`

### 3.2 DPDK mempool MT-Safe Semantics (Cross-Verified, Decisive)

`dpdk-stable-24.11.6/lib/mempool/rte_mempool.h:28-32`:
> *"...usual mempool functions like `rte_mempool_get()` or `rte_mempool_put()` are designed to be called from an **EAL thread** due to the internal **per-lcore cache**. Due to the lack of caching, ... performance will suffer when called by **unregistered non-EAL threads**."*

- per-lcore cache struct: `rte_mempool.h:113` `void *objs[RTE_MEMPOOL_CACHE_MAX_SIZE * 2];`
- Default get/put is **MP/MC (multi-producer multi-consumer, lock-free)**; only with `RTE_MEMPOOL_F_SP_PUT`(`:289`)/`RTE_MEMPOOL_F_SC_GET`(`:296`) does it become single-ended. f-stack passes flag `0` when creating the pool (`ff_dpdk_if.c` has no SP/SC flag), i.e. **MP/MC default**.
- `cache_size` semantics: `rte_mempool.h:1031-1035`, per-lcore object cache reducing access to the common lock-free pool.

**Conclusion (statically determinable + partially requires runtime validation)**:
> - ✅ **Multiple lcore threads sharing the same `pktmbuf_pool[socketid]` is MT-safe** — precondition: (a) called from **EAL threads** (i.e. the lcore pthreads launched by `rte_eal_remote_launch`); (b) `cache_size > 0` at pool creation (f-stack satisfies, `MEMPOOL_CACHE_SIZE`, `:540`); (c) default MP/MC flags (f-stack satisfies, flag=0).
> - ✅ **No mempool correctness rework needed for multi-threading**: DPDK's per-lcore cache is indexed by `rte_lcore_id()` (TLS); each EAL thread automatically has an independent cache slice, naturally lock-free isolated. Under the native multi-thread model this mechanism **works out of the box**.
> - ✅ **No explicit `RTE_MEMPOOL_CACHE` needed** (per-lcore cache is built in via the `cache_size` parameter); `nb_mbuf` calculation already reserves per-lcore cache capacity by `nb_lcores * MEMPOOL_CACHE_SIZE` (`ff_dpdk_if.c:495`).
> - ⚠️ **Requires runtime validation**: (1) if future **non-EAL threads** (e.g. user callbacks creating their own pthreads) call `rte_pktmbuf_alloc`, they hit the shared-pool slow path and the thread must be confirmed `rte_thread_register`-ed. (2) With N threads sharing a pool, whether the total `nb_mbuf` suffices (the capacity formula in `init_mem_pool` `:491-501` scales linearly with `nb_lcores`; statically considered, but high-concurrency measurements need to observe `rte_mempool_avail_count`). (3) Cross-NUMA: each thread should be bound to its socket's pool to avoid remote access (the `numa_on` branch `:509-511` handles it, but the multi-thread pinning strategy needs runtime confirmation).

---

## IV. `RTE_PER_LCORE` Mechanism (Isolation Means for per-Thread-izing f-stack Global State)

DPDK provides per-lcore variable macros (essentially TLS): `dpdk-stable-24.11.6/lib/eal/include/rte_per_lcore.h`
```
rte_per_lcore.h:33   #define RTE_DEFINE_PER_LCORE(type, name)   __thread type per_lcore_##name
rte_per_lcore.h:39   #define RTE_DECLARE_PER_LCORE(type, name)  extern __thread type per_lcore_##name
rte_per_lcore.h:46   #define RTE_PER_LCORE(name)  (per_lcore_##name)
```
(The MSVC branch `:22-26` uses `__declspec(thread)`, same semantics.)

**Conclusion (statically determinable, important isolation means)**:
> - `RTE_DEFINE_PER_LCORE` **is compiler TLS (`__thread`) under the hood**, one independent copy per thread, zero lock, zero argument passing.
> - `rte_lcore_id()` itself is implemented with it (`rte_lcore.h:80 return RTE_PER_LCORE(_lcore_id)`).
> - **Usable as one of two candidate paths for per-thread-izing f-stack global state**:
>   - **Path A (array + rte_lcore_id index)**: `struct X x_arr[RTE_MAX_LCORE]`, accessed `x_arr[rte_lcore_id()]`. Pros: indexable by subscript from other threads/init code (e.g. dispatch/msg cross-thread scenarios), centralized memory layout, easy stats traversal (`RTE_LCORE_FOREACH`). Cons: needs manual `__rte_cache_aligned` to prevent false sharing. **Suitable for state like `lcore_conf`/`msg_ring` that "sometimes needs to be indexed by id from other threads".**
>   - **Path B (`RTE_DEFINE_PER_LCORE` / `__thread`)**: `RTE_DEFINE_PER_LCORE(struct X, x)`, accessed `RTE_PER_LCORE(x)`. Pros: true TLS, naturally isolated, no false sharing, fastest access. Cons: **other threads cannot directly access by id** (TLS is only visible to this thread). **Suitable for "pure thread-private FreeBSD global state that needs no reads by other threads"** (e.g. per-thread-izing many `V_xxx`/globals inside each protocol-stack instance — needs joint ruling with subagent A's FreeBSD global-state inventory).
> - **The two can be mixed**: cross-thread-visible state uses arrays (lcore_conf/dispatch_ring/msg_ring); pure thread-private state uses `__thread`.

---

## V. `process_msg_ring` / IPC — Simplification Space Under Single-Process Multi-Thread

### 5.1 Current IPC Path (Multi-Process)

- `main_loop` calls `process_msg_ring(qconf->proc_id, pkts_burst)` every round: `ff_dpdk_if.c:2699`.
- `process_msg_ring`: `ff_dpdk_if.c:2278-2295`, dequeues requests from `msg_ring[proc_id].ring[0]`, handling each via `handle_msg` (`:2291`).
- `handle_msg(msg, proc_id)`: `ff_dpdk_if.c:2225`, processes control requests like sysctl/ioctl/route, replying to the out ring (`:2265`).
- Peer: external tool processes (`ff_ipc` under `tools/`, SECONDARY processes) obtain the same-name ring on shared hugepages via `rte_ring_lookup` (the `else` branch of `create_ring`, `ff_dpdk_if.c:578`), delivering requests cross-process and receiving responses.

### 5.2 Simplification Conclusion Under Single-Process Multi-Thread

**Conclusion (statically determinable + design suggestion)**:
> - Both the **data plane (dispatch_ring) and control plane (msg_ring) degrade to "in-process cross-thread shared memory" under single-process multi-thread**; `rte_ring`'s lock-free semantics hold for threads too, **functionally the existing ring paths can be reused directly, no rewrite**.
> - **But there is simplification space**: if the external `ff_ipc` tools are also merged into the same process (as a management thread), then the "management thread → stack thread" control messages **can use in-process shared memory + direct function calls/lock-free rings instead of cross-process IPC**, saving the SECONDARY process attach, `rte_ring_lookup` by-name lookup, and cross-process serialization overhead.
> - **Minimal-change plan**: keep the `msg_ring[proc_id]` array structure unchanged (already per-lcore, `:177`); under single-process multi-thread each stack thread still consumes its own msg_ring with its own `proc_id`, SP/SC unchanged. External tools can still access via shared hugepages as independent processes (**best compatibility, smallest change**).
> - ⚠️ **Needs team ruling**: whether to also thread-ize the management plane (more aggressive, saves IPC) or keep external processes (small change, compatible with old tools) depends on the spec's trade-off between "share-nothing purity" and "backward compatibility".

---

## VI. Key Ruling Summary for the Leader (DPDK-Side Native Multi-Threading Feasibility)

| Dimension | Current state (file:line) | Native multi-thread change conclusion |
|---|---|---|
| **Launch N lcore threads** | `rte_eal_mp_remote_launch(main_loop,...)` `ff_dpdk_if.c:2770`; single lcore due to single-bit coremask | ✅ **launch layer almost zero change**: give an N-bit coremask, EAL auto-creates N core-pinned pthreads, `main_loop` automatically runs one each. The real work is global-state isolation. |
| **lcore_conf** | **global singleton** `ff_dpdk_if.c:123`; shared in `main_loop` `:2585` | ⛔ **#1 obstacle**: must become a per-lcore array `lcore_conf[RTE_MAX_LCORE]` (or `__thread`), each thread indexed by `rte_lcore_id()`/proc_id. The queue ids/TX buffers inside the struct are naturally per-lcore; splitting into an array makes it share-nothing. |
| **dispatch_ring (data plane)** | `RING_F_SC_DEQ` (MP+SC) `ff_dpdk_if.c:619`; multi-source lcore writes, single owner reads | ✅ **keep MP+SC unchanged**: multi-producer is an essential requirement (cross-lcore distribution); the current flags are correct; under multi-thread the ring's lock-free semantics apply as-is, smooth migration. |
| **msg_ring (control-plane IPC)** | `RING_F_SP_ENQ\|RING_F_SC_DEQ`, **already a `[RTE_MAX_LCORE]` array** `ff_dpdk_if.c:177` | ✅ **keep SP+SC unchanged**: already per-proc_id array-ized; each thread uses its own proc_id index, naturally isolated; optionally simplify further to in-process shared memory instead of cross-process IPC. |
| **mempool MT-safe** | per-socket shared `pktmbuf_pool[NB_SOCKETS]` `:125`, `cache_size=MEMPOOL_CACHE_SIZE` `:540`, flag=0(MP/MC) | ✅ **MT-safe out of the box**: DPDK per-lcore cache (`rte_mempool.h:28-32`) + MP/MC default, calling from EAL threads is naturally lock-free isolated, no rework needed. ⚠️ Capacity and non-EAL-thread calls need runtime validation. |
| **per-thread isolation means** | — | ✅ `RTE_DEFINE_PER_LCORE=__thread` (`rte_per_lcore.h:33`) + `rte_lcore_id()` (TLS, `rte_lcore.h:80`); cross-thread-visible state uses arrays, pure-private state uses `__thread`, coordinated with subagent A's FreeBSD global-state inventory. |

**One-line summary**: DPDK-side capability for "launch N threads + per-thread independent queues/rings/mempool" is **natively complete and most existing code is reusable** (launch/queue/ring/mempool all need no rewrite or merely keeping flags); **the only hard bone is making `lcore_conf` and other process-level global singletons per-lcore (array or `__thread`)** — the same class of work as per-thread-izing the FreeBSD protocol-stack global state (subagent A), sharing the `rte_lcore_id()`/`__thread` isolation mechanism.

> Honest boundary: all "conclusions (statically determinable)" in this material are based on verified code and DPDK headers; the items marked "⚠️ requires runtime validation" are mempool capacity, non-EAL-thread calls, NUMA pinning strategy, and NIC multi-queue RSS distribution balance under N-thread real running — these must be measured after coding.
