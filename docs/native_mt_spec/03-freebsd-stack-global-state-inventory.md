# 03 FreeBSD Stack Global-State Inventory

> This inventory is the core work surface of the native multi-stack-instance modification. Source: `_material_A_globalstate.md` (with file:line).
> Severity: P0=definite crash/corruption under multi-thread, core target; P1=high-frequency read/write trampling; P2=one-shot at init/per-instance copy; P3=low-frequency/stats; P4=read-only or naturally safe.
> Isolation method: `__thread` (pure thread-private) / `RTE_PER_LCORE` (=`__thread`, DPDK semantics) / lcore_id-indexed arrays (when other threads must access by id) / VNET (network-stack virtualization, see §5).

## 1. Thread/Process Context Core (f-stack self-made globals)

| Variable | file:line | Type | Already per-thread | Suggested isolation | Change cost | Severity |
|---|---|---|---|---|---|---|
| `pcpup` | `ff_freebsd_init.c:69` | `struct pcpu *` singleton | No | `RTE_PER_LCORE`/`__thread`, one pcpu per thread | Medium (PCPU macro foundation) | **P0** |
| `pcurthread` | `ff_compat.c:59` | `__thread struct thread *` | **Yes** | Keep | None | P4 |
| `thread0`/`thread0_st` | `ff_init_main.c:98` | singleton struct | No | One per instance | Medium | **P0** |
| `proc0` | `ff_init_main.c:96` | `struct proc` singleton | No | One per instance | Medium | **P0** |
| `prison0`/`vmspace0`/`initproc` | `ff_init_main.c:97,99,100` | singleton | No | One per instance (prison0 or shared read-only needs evaluation) | Low-medium | P1 |
| `msg_iov_tmp[UIO_MAXIOV]` | `ff_syscall_wrapper.c:225` | `static struct iovec[1024]` (`__thread` commented out) | **No** | **Restore `__thread`** | **Very low** | **P0** |
| `msg_iovlen_tmp` | `ff_syscall_wrapper.c:226` | `static size_t` (same) | No | Restore `__thread` | Very low | **P0** |

> `msg_iov_tmp/msg_iovlen_tmp` are used by `recvmsg/sendmsg` (`ff_syscall_wrapper.c:864,893-897`), temporary storage per syscall; `__thread` was deliberately commented out (historical single-thread assumption). Definite data corruption under multi-thread; **restoring the commented-out `__thread` suffices** — the top low-hanging fruit.

## 2. DPDK Forwarding-Layer Globals (f-stack self-made)

| Variable | file:line | Type | Already per-thread | Suggested isolation | Change cost | Severity |
|---|---|---|---|---|---|---|
| `lcore_conf` | `ff_dpdk_if.c:123` | `struct lcore_conf` singleton (struct def `ff_memory.h:82-95`) | No | Array `lcore_conf[RTE_MAX_LCORE]` or `RTE_PER_LCORE`, indexed by `rte_lcore_id()` | Medium (**30+ references** + `ff_memory.c:71,395,414,459,510`) | **P0** |
| `stop_loop` | `ff_dpdk_if.c:87` | `static int` | No | Per-thread stop flag/`__thread` | Low | P1 |
| `freebsd_clock` | `ff_dpdk_if.c:89` | `static struct rte_timer` | No | One per thread (each stack's own hardclock) | Low-medium | **P1** |
| `pktmbuf_pool[NB_SOCKETS]` | `ff_dpdk_if.c:125` | array (per socket) | Partial | Threads on the same socket can share (mempool MT-safe) | Low | P2 |
| `msg_ring[RTE_MAX_LCORE]` | `ff_dpdk_if.c:177` | array (per lcore) | Yes | Keep | None | P4 |
| `veth_ctx[RTE_MAX_ETHPORTS]` | `ff_dpdk_if.c:179` | array (per port) | No (per port, not thread) | Multi-thread shared port needs shared-read evaluation | Medium | P2 |
| `ff_top_status`/`ff_traffic` | `ff_dpdk_if.c:181,182` | `static struct` stats | No | One per thread then aggregate | Low | P3 |
| `ff_rss_tbl[]`/`ff_rss_tbl6[]` | `ff_dpdk_if.c:203,223` | `static[]` RSS reverse tables | No | One per thread or shared read-only | Medium | P1 |
| `numa_on`/`idle_sleep`/`rsskey` etc. | `ff_dpdk_if.c:80,82,120` | assigned at init, read-only at runtime | No | Shared read-only | None | P4 |

> `nb_rx_queue`/`rx_queue_list`/`tx_queue_id`/`tx_mbufs` inside `struct lcore_conf` (`ff_memory.h:88-93`) are naturally per-lcore semantics (one NIC queue per lcore); splitting into an array is share-nothing with no locks needed.

## 3. callout/timer Subsystem (`ff_kern_timeout.c`)

| Variable | file:line | Type | Already per-thread | Suggested isolation | Change cost | Severity |
|---|---|---|---|---|---|---|
| `cc_cpu` | `ff_kern_timeout.c:180` | `struct callout_cpu` singleton (`CC_CPU()/CC_SELF()` all return it `:181,182`, ignoring the passed cpu) | No | One callout_cpu per thread (independent callwheel per instance) | **High** (all TCP/IP timers hang on it) | **P0** |
| `callwheelsize`/`callwheelmask` | `ff_kern_timeout.c:135` | `u_int` globals | No | One callwheel per instance | Medium | **P1** |
| `timeout_cpu` | `ff_kern_timeout.c:187` | `static int` | No | One per instance | Low | P1 |

> `CC_CPU(cpu)`/`CC_SELF()` are hardcoded to `&cc_cpu` (`:181-182`); must change to "take each callout_cpu by lcore_id/thread index", otherwise N stacks' timers serialize onto the same callwheel — lock contention + logic corruption. The second-hardest bone after `lcore_conf`/`pcpup`.

## 4. init/Process Globals (`ff_init_main.c` / `ff_freebsd_init.c` / `ff_compat.c`)

| Variable | file:line | Type | Severity | Suggestion |
|---|---|---|---|---|
| `sysinit/sysinit_end`/`newsysinit` | `ff_init_main.c:123,124` | SYSINIT ordering table | **P0** | One-shot table; running N times is problematic, see `04` |
| `uma_page_slab_hash`/`uma_page_mask` | `ff_freebsd_init.c:70,71` | UMA allocator hash | **P0(uncertain)** | UMA foundation is extremely hard to per-thread; suggest shared + lock; MT-safety **requires runtime validation** |
| `proctree_lock` | `ff_freebsd_init.c:68` | global sx lock | P2 | One per instance |
| `allproc`/`allproc_lock` | `ff_compat.c:64,65` | process list + lock | P1 | One per instance |
| `rootvnode` | `ff_compat.c:62` | `struct vnode *` | P3 | One per instance or shared NULL (f-stack does no real VFS) |
| `seed` | `ff_compat.c:80` | arc4random seed | P2 | `__thread` (avoid rand_r contention) |

## 5. VNET-Degraded Globals (Network-Stack Main Battlefield, Hundreds) — Native Solution

Without VIMAGE, all FreeBSD `VNET_DEFINE(...)` globals degrade into process-level ordinary globals (`vnet.h:429`); that is f-stack's current state. Categories:
- `V_ifnet` (ifnet list, referenced by `ff_freebsd_init.c:87`)
- `V_in_ifaddrhead`/`V_in6_ifaddr` (address tables)
- `V_tcbinfo`/`V_udbinfo` (TCP/UDP PCB hash tables + locks)
- `V_rt_tables` (routing/FIB, referenced by `ff_route.c:643,1411`)
- `V_ipport_*` (port allocation)
- Hundreds of protocol counters (`V_tcpstat`/`V_ipstat`/`V_ip6stat`...)

**Native isolation = enable VIMAGE**: `curvnet=curthread->td_vnet` (`vnet.h:176`), each thread `vnet_alloc()`s (`vnet.c:239`) one vnet, and this batch of globals is automatically isolated by the vnet data segment (`vnet.h:279-306`). See `04`/`05`. **This is the key to not manually `__thread`-izing hundreds of globals** — but whether VIMAGE runs in f-stack's emasculated userspace requires runtime validation (`09`/`11`).

## 6. Correctly per-thread Pattern References

| Variable | file:line | Description |
|---|---|---|
| `g_pcap_fp/seq/g_flen` | `ff_dpdk_pcap.c:55-57` | `static __thread`, proving f-stack already has a `__thread` per-thread convention to reuse |
| `pcurthread` | `ff_compat.c:59` | `__thread`, matches VNET `curvnet=td_vnet` |

## 7. Change-Scale Summary

- **P0 top targets**: `msg_iov_tmp` (very low), `mi_startup`/SYSINIT (very large, see `04`), `lcore_conf` (medium-large), `pcpup/thread0/proc0` (medium), `cc_cpu` (high), VNET-degraded globals (very large, native VNET coverage), UMA (high/needs runtime validation).
- **Overall strategy**: network-stack globals go VNET (one-shot VIMAGE enable covers hundreds); f-stack self-made DPDK/pcpu/callout globals go "lcore_id-indexed arrays or `__thread`"; pure temporary buffers go `__thread`.
