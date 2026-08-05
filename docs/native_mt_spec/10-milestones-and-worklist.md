# 10 Milestones and Worklist

> Ordered by increasing risk. Principles: start from low-hanging fruit and feasibility validation; high-risk items (VIMAGE, init restructure) get a PoC first before full implementation. Each milestone has a rollback point; the thread_mode switch defaults off to preserve multi-process zero regression.

## 1. Milestone Overview

| Milestone | Goal | Risk | Prerequisite |
|---|---|---|---|
| CM0 | Low-hanging fruit + scaffolding | Low | — |
| CM1 | Config-layer thread_mode switch (not wired to implementation) | Low | CM0 |
| CM2 | `lcore_conf` per-lcore-ization + DPDK launches N lcores | Medium | CM1 |
| CM3 | Per-thread-ize f-stack self-made foundation globals (pcpu/thread0/callout) | High | CM2 |
| CM4 | **VIMAGE feasibility PoC** (key blocker validation) | High/uncertain | CM3 |
| CM5 | Init restructure (ff_init once + per-thread stack-instance init) | Very high | CM4 |
| CM6 | KNI owner thread + toolchain IPC (C1 keep compatibility) | Medium | CM5 |
| CM7 | End-to-end integration + multi-process zero-regression + performance baseline | Medium | CM6 |

## 2. Work Breakdown (WBS)

### CM0 Low-Hanging Fruit + Scaffolding (low risk)
1. Restore `__thread` on `msg_iov_tmp/msg_iovlen_tmp` (`ff_syscall_wrapper.c:225-226`) — deterministic corruption fix, harmless in multi-process mode too.
2. Introduce a unified "current stack instance" access abstraction (e.g. `ff_cur_lcore_conf()` macro, temporarily equivalent to `&lcore_conf`) as an indirection layer for later per-lcore-ization.
3. Rollback point: pure `__thread` restore + abstraction macro, behavior unchanged.

### CM1 Config-Layer Switch (low risk, not wired to implementation)
1. Add `thread_mode`/`nb_threads` to `struct ff_config.dpdk` (`ff_config.h:269-328`).
2. `parse_lcore_mask` (`ff_config.c:73-142`) thread-mode branch (fill nb_threads, full-bit proc_mask); proc_type validation forces primary (`:1316-1321`); `--proc-type=`/`-c` concatenation forks (`:1151-1170`).
3. Mutual-exclusion validation: thread_mode=1 conflicts with secondary → error.
4. Rollback point: switch defaults 0, existing branches byte-identical.

### CM2 lcore_conf per-lcore + Launch N Lcores (medium risk)
1. `lcore_conf` singleton→`lcore_conf[RTE_MAX_LCORE]` (`ff_dpdk_if.c:123`), change 30+ reference points + `ff_memory.c` extern.
2. `init_lcore_conf` (`:400-467`) fills each thread's own copy.
3. Thread mode gives EAL an N-bit coremask; `rte_eal_mp_remote_launch` (`:2770`) launches N loops, each using `&lcore_conf[rte_lcore_id()]`.
4. Rollback point: with thread_mode=0, `lcore_conf[proc_id]` degenerates to a single copy.

### CM3 Foundation Global per-thread (high risk)
1. `pcpup` (`ff_freebsd_init.c:69`)→one pcpu per thread.
2. `thread0`/`proc0` (`ff_init_main.c:96,98`)→one per instance.
3. `cc_cpu` (`ff_kern_timeout.c:180`)→per-instance callout_cpu/callwheel; `CC_CPU/CC_SELF` (`:181-182`) changed to index by thread.
4. `stop_loop`/`freebsd_clock`/`seed` etc. P1 items per-thread.

### CM4 VIMAGE Feasibility PoC (key blocker)
1. Add `VIMAGE` to `opt_global.h`, evaluate the completeness of f-stack's compile-unit VNET infrastructure.
2. PoC: `vnet_alloc()` 2 instances in one process + set `td_vnet`, verify whether `VNET_SYSINIT` (tcp/ip/pcb) can run once per vnet and whether `V_tcbinfo`/`V_rt_tables` are isolated.
3. **Gate**: if the PoC fails, the VIMAGE route (B) switches to Route A (manual per-thread-ization of hundreds of `V_*`) — this is a major fork and must go to human decision.
4. ⚠️ This milestone's conclusion **requires runtime validation**; success must not be asserted statically.

### CM5 Init Restructure (very high risk)
1. Split `ff_init` (`ff_init.c:35`): global one-shot init (EAL/UMA/mutex/vnet0) + per-thread stack-instance init (vnet_alloc/td_vnet/VNET_SYSINIT/pcpu_i/thread0_i).
2. `mi_startup` (`ff_init_main.c:173-285`): non-vnet part once + vnet part per thread (depends on CM4 conclusion).
3. Each thread's entry chains: pin lcore→build context→stack init→`main_loop`.

### CM6 KNI + Toolchain (medium risk)
1. KNI gating changed from `RTE_PROC_PRIMARY` (`ff_dpdk_if.c:2661`, `ff_dpdk_kni.c:379/426`) to owner-thread determination; config validation (`ff_config.c:1396-1411`) changed to judge the owner lcore.
2. Toolchain prefers C1 (keep external tool processes attaching, see `08`).

### CM7 Integration + Regression + Baseline (medium risk)
1. End-to-end: lo 127.0.0.1 kernel-stack comparison + DPDK NIC 9.134.214.176 tested via f-stack-client (see `11`).
2. Full multi-process zero-regression regression (thread_mode=0).
3. Performance baseline: thread mode vs multi-process (see `11`).

## 3. Rollback and Gates

- Every milestone: thread_mode=0 must be byte-level zero-regression (one-vote veto).
- CM4 VIMAGE PoC is the route-fork gate: on failure, go to human decision on Route A/B.
- Run `make clean` before compiling after code changes; lib minimal comments; commit message in English 1-3 sentences; config.ini local test values not committed; rm/kill/chmod through the scripts.

## 4. Critical Path and Risk Notes

- **Critical path**: CM4 (VIMAGE feasibility) is the biggest global uncertainty, deciding Route A/B; PoC recommended as early as possible.
- CM5 (init restructure) is very high risk, depends on CM3/CM4 all being ready.
- Low-risk CM0/CM1 can land first to accumulate (the `msg_iov_tmp` fix is independently beneficial).
