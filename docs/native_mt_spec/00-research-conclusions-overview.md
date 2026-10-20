# 00 Research Conclusions Overview

> This document is the conclusion-first overview of the research on f-stack native "single-process + multi-thread + multi-stack-instance". All technical assertions are based on `lib/` and FreeBSD/DPDK source code file:line.

## 0. Old Conclusion Invalidated

The previous spec (committed as `497e53e11`, `docs/multi_thread_spec/zh_cn/`) had **recommended the "multi-process + LD_PRELOAD adapter multi-worker"** route and downgraded native multi-threading to a high-risk alternative. **That recommendation is invalidated this round.** Per the user's explicit requirement, this version only demonstrates and designs the **in-library native (`lib/` layer) support for single-process multi-thread multi-stack-instance** implementation, **without the adapter route** (the adapter is recorded only as an objective record of the application-side current state).

## 1. One-Line Conclusion

f-stack is currently a "one process = one lcore = one stack instance" multi-process share-nothing model. To natively support "N pthreads in one process, each running an independent stack instance", **the technically preferred path = enabling FreeBSD native VNET/VIMAGE (each thread's `curthread->td_vnet` pointing to its own `vnet_alloc()`-ed stack instance) + separately per-thread-izing the non-VNET f-stack self-made globals (`lcore_conf`/`pcpup`/`cc_cpu`/`thread0`/`msg_iov_tmp`) + restructuring the one-shot initialization sequence + DPDK single-process launch of N lcore threads**. This modification is **feasible but with large engineering effort**, and has key uncertainties that must be runtime-validated (whether VIMAGE can run to completion in f-stack's emasculated userspace).

## 2. Three-Layer Feasibility at a Glance

| Layer | Conclusion | Key Evidence |
|---|---|---|
| **DPDK side** | ✅ Basically ready, small change | `rte_eal_mp_remote_launch`(`ff_dpdk_if.c:2770`) auto-launches N threads given an N-bit coremask; dispatch_ring keeps MP+SC(`:619`), msg_ring keeps SP+SC(already array-ized `:177`), mempool is MT-safe out of the box(`rte_mempool.h:28-32`). The only hard bone is the `lcore_conf` global singleton(`:123`) which needs to become a per-lcore array. |
| **FreeBSD network-stack globals** | ✅ Native solution exists (VNET) | Hundreds of `V_ifnet/V_tcbinfo/V_rt_tables/...` currently degenerate into process-level globals (no VIMAGE). After enabling VIMAGE, per-thread isolation follows `curvnet=curthread->td_vnet`(`vnet.h:176`), and `vnet_alloc()`(`vnet.c:239`) gives each thread a complete stack instance. |
| **f-stack self-made globals + init** | ⛔ Hard conclusion: cannot be initialized N times | `mi_startup`/SYSINIT finishes and ticks `SI_SUB_LAST`(`ff_init_main.c:271`); second call no-ops; `pcpup`/`thread0`/`cc_cpu`/`msg_iov_tmp` are all global singletons, requiring initialization-architecture restructuring + per-thread-ization. |

## 3. Recommended Implementation Path (native, not adapter)

**Main path (VNET-based native multi-stack-instance):**
1. Enable VIMAGE; each thread `vnet_alloc()`s one vnet and sets `curthread->td_vnet`, reusing kernel VNET data-segment virtualization to isolate hundreds of network-stack globals (see `04`, `05`).
2. Per-thread-ize the non-VNET f-stack self-made globals one by one (`lcore_conf`→array, `pcpup`/`thread0`/`proc0`→one per instance, `cc_cpu`→per-instance callout, `msg_iov_tmp`→restore `__thread`, see `03`).
3. Restructure initialization: `ff_init` is called once to do EAL + per-lcore instance state for N instances; each thread runs its own per-thread FreeBSD stack initialization (VNET_SYSINIT once per vnet); `rte_eal_mp_remote_launch` runs `main_loop` on N lcores (see `04`, `06`).
4. Config adds the `thread_mode` opt-in switch + `nb_threads`, mutually exclusive with multi-process mode, preserving multi-process zero regression (see `07`).
5. KNI is owned by a single owner thread; toolchain IPC is redesigned (see `08`).

**Rejected comparison (recorded only, not recommended):** "Shared single stack + fine-grained locking" violates f-stack's share-nothing lock-free philosophy and breaks SC/SP ring assumptions; comparison only.

**Not this solution:** LD_PRELOAD adapter multi-worker is application-side adaptation, not a stack-side native multi-threaded run model.

## 4. Top Modification Targets (by risk, see `03`/`10`)

| Rank | Target | file:line | Cost |
|---|---|---|---|
| 0 (low-hanging fruit) | `msg_iov_tmp/msg_iovlen_tmp` restore `__thread` | `ff_syscall_wrapper.c:225-226` | Very low |
| 1 (architecture blocker) | Restructure `mi_startup`/SYSINIT one-shot mechanism | `ff_init_main.c:173-285,271` | Very large |
| 2 | `lcore_conf` global singleton→per-lcore | `ff_dpdk_if.c:123`(30+ references) | Medium-large |
| 3 | `pcpup`/`thread0`/`proc0` singleton→per-instance | `ff_freebsd_init.c:69`, `ff_init_main.c:96,98` | Medium |
| 4 | `cc_cpu` callout singleton→per-instance callwheel | `ff_kern_timeout.c:180-182` | High |
| 5 | VNET-degraded globals (hundreds)→enable VIMAGE | `freebsd-src` tree | Very large (VNET native coverage) |
| 6 | UMA allocator global MT-safe | `ff_freebsd_init.c:70-71` | High/needs runtime validation |

## 5. Key Honest Boundaries (require runtime validation, no speculation)

1. Whether VIMAGE can run to completion in f-stack's heavily emasculated userspace (`vnet_alloc`/`VNET_SYSINIT`/data-segment relocation dependencies).
2. Actual behavior of `mi_startup`/UMA/protocol-stack initialization when executed N times after multi-thread restructuring.
3. Mempool multi-thread shared-pool capacity and non-EAL-thread call behavior, NUMA pinning strategy.
4. Interaction with the tcp_hpts timer after callout becomes multi-instance (`ff_kern_timeout.c:1252-1274`).

## 6. Section Index

| Doc | Content |
|---|---|
| `01` | Requirements spec (goals/boundaries/acceptance/terminology) |
| `02` | Current state and gap analysis (multi-process model + thread infrastructure + adapter current-state record) |
| `03` | FreeBSD stack global-state inventory (item-by-item file:line + isolation method + severity) |
| `04` | Stack-instance initialization mechanism design (mi_startup/SYSINIT/VNET_SYSINIT) |
| `05` | Solution and architecture design (VNET main path + data flow + rejected comparison) |
| `06` | DPDK multi-thread integration (launch/queue/ring/mempool/RTE_PER_LCORE) |
| `07` | Interface and configuration design (thread_mode/nb_threads/zero regression) |
| `08` | KNI-IPC-toolchain ownership |
| `09` | External and source cross-research (VNET/VIMAGE/mTCP/Seastar) |
| `10` | Milestones and work list (CM0-CMn, by risk) |
| `11` | Testing, performance baseline and risk compatibility |
| `12` | Spec review gate (issued by independent gatekeeper) |

## 7. issue #430 Positioning (mandatory research goal #9)

#430 "SOCK_STREAM [SOLVED] + Multi Thread (Pthread)" is an **application-side multi-threaded API-call** scenario (libuv+pthread+combined socket flag bits); current code `linux2freebsd_socket_flags`(`ff_syscall_wrapper.c:672-684`)/`ff_socket`(`:943`)/`ff_accept4`(`:1679`) already handles combined flag bits completely. It is "first-hand evidence of real users' demand for f-stack in a multi-threaded environment", but **it belongs to a different layer than this round's "stack-side native multi-threaded run model"**, so it is not the conclusion anchor of this round. External comment sections were not captured due to GitHub dynamic loading + API rate limiting; honestly marked, code is the source of truth.
