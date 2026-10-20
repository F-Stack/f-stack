# 06 DPDK Multi-Threading Integration

> Source `_material_B_dpdk.md` (with file:line) + DPDK 24.11.6 source cross-check. Conclusion: DPDK-side native capabilities are complete; changes concentrate on per-lcore-izing `lcore_conf`.

## 1. Launching N Lcore Threads in One Process

- `ff_dpdk_run()` → `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` (`ff_dpdk_if.c:2770`) + `rte_eal_mp_wait_lcore()` (`:2771`).
- `rte_eal_mp_remote_launch` (`dpdk-stable-24.11.6/lib/eal/include/rte_launch.h:99`) already launches a `main_loop` on **every EAL-registered lcore**. The current single lcore is because **each process's coremask is a single bit** (`ff_config.c:1151-1154`), not an API limitation.
- `lcore = pthread + core pinning` (`rte_launch.h:37-51`), created once by `rte_eal_init` according to the coremask.

**Change conclusion (statically determinable)**: in thread mode give EAL an N-bit coremask (e.g. `-l 0-3`); EAL automatically creates N pinned pthreads and `rte_eal_mp_remote_launch` automatically runs `main_loop` on each of the N lcores. **The launch layer needs almost zero change**; the real work is in global-state isolation.

## 2. TLS Nature of lcore id (Isolation Foundation)

- `rte_lcore_id() ≡ RTE_PER_LCORE(_lcore_id)` (`rte_lcore.h:77-81`) — the lcore id is itself a `__thread` variable; each thread naturally knows which lcore it is, no argument passing needed.
- `RTE_LCORE_FOREACH(i)` (`rte_lcore.h:217-220`) iterates running lcores.
- `ff_dpdk_if.c:419/1148` already use `rte_lcore_id()`.

**Significance**: each thread uses `rte_lcore_id()` as the array subscript to index its own instance state, lock-free and no argument passing.

## 3. lcore_conf per-lcore-ization (The Only Hard Bone)

- Struct def `ff_memory.h:82-95` (`proc_id`/`socket_id`/`nb_rx_queue`/`rx_queue_list`/`tx_queue_id`/`tx_mbufs`).
- **Global singleton** `struct lcore_conf lcore_conf;` (`ff_dpdk_if.c:123`, not an array). Hot paths all reference it: `main_loop`(`:2585`), `ff_dpdk_if_up`(`:2749`), `process_packets`(`:1905`), send path(`:2305-2306`).
- `init_lcore_conf()` (`:400-467`) currently fills only one copy per process's single lcore (`:424 lcore_id=proc_lcore[proc_id]`).

**Change**: make it `struct lcore_conf lcore_conf[RTE_MAX_LCORE]` (or `RTE_DEFINE_PER_LCORE`); each thread indexes `&lcore_conf[rte_lcore_id()]` (or proc_id). The queue ids/TX buffers inside the struct are naturally per-lcore; splitting into an array is share-nothing. At init, each thread fills its own copy.

## 4. RX/TX Queue Allocation (Naturally Share-Nothing)

- Number of queues = `pconf->nb_lcores` (`ff_dpdk_if.c:602`); `rte_eth_dev_configure(port, nb_queues, nb_queues,...)` (`:1006`).
- Each queue setup (`:1019-1037`); the current process claims `queueid=i` when `lcore_list[i]==lcore_id` (`:436-440`).
- **Conclusion**: one lcore exclusively owns one RX + one TX queue; "N queues ↔ N lcores" is inherently the ideal share-nothing model. Converting to single-process multi-thread only requires each thread to claim `queueid=i` in its own `lcore_conf[i]`; **NIC configuration logic needs no change**.

## 5. Ring Semantics (Unchanged)

| ring | Current flag | Conclusion |
|---|---|---|
| `dispatch_ring[port][queue]` (data plane) | `RING_F_SC_DEQ` (MP+SC) `ff_dpdk_if.c:619` | Multi-source lcore writes(`:1964,1996`), single owner reads(`:2049`) are intrinsic; **keep MP+SC**; `rte_ring` lock-free semantics apply as-is under multi-thread |
| `msg_ring[RTE_MAX_LCORE]` (control plane) | `RING_F_SP_ENQ\|RING_F_SC_DEQ` `:670`, already array-ized `:177` | Each thread uses its own proc_id index; **keep SP+SC** |

## 6. Mempool MT-safe (Usable Out of the Box)

- `pktmbuf_pool[socketid]` (`ff_dpdk_if.c:125`) shared per NUMA socket, `cache_size=MEMPOOL_CACHE_SIZE` (`:540`, non-zero), flag=0 (MP/MC default).
- DPDK semantics (`rte_mempool.h:28-32`): get/put rely on per-lcore cache (indexed by `rte_lcore_id()`); calling from **EAL threads** is naturally lock-free isolated.
- **Conclusion**: multiple lcores sharing the same socket's pool is **MT-safe, no change needed**. ⚠️ Requires runtime validation: whether capacity scaled with `nb_lcores` (`:495`) is enough, non-EAL-thread calls, NUMA pinning (`:509-511`).

## 7. RTE_PER_LCORE Isolation Method

- `RTE_DEFINE_PER_LCORE(t,n) ≡ __thread t per_lcore_##n` (`rte_per_lcore.h:33`).
- Two isolation paths: **array + `rte_lcore_id()` index** (cross-thread visible, for `lcore_conf`/`dispatch_ring`/`msg_ring`); **`RTE_DEFINE_PER_LCORE`/`__thread`** (pure private, for FreeBSD globals exclusively owned by this thread, in coordination with `03`).

## 8. IPC Simplification Space

- Under single-process multi-thread, both data-plane/control-plane rings degrade to in-process cross-thread sharing; `rte_ring`'s lock-free semantics hold for threads too, **functionally directly reusable**.
- Optional simplification: merge the external `ff_ipc` tools into the same process as management threads, replacing cross-process IPC with in-process shared memory/direct calls (less overhead but larger change); or keep external tool processes over shared hugepages (best compatibility). See `08`.

## 9. DPDK-Side Change List Summary

| Item | Change | Cost |
|---|---|---|
| Launch N lcores | N-bit coremask (config layer, `07`) | Very low |
| `lcore_conf` | singleton→per-lcore array | Medium-large |
| RX/TX queues | Each thread claims queueid | Low |
| dispatch_ring/msg_ring | Keep flags unchanged | None |
| mempool | No change | None (⚠️ capacity runtime validation) |
