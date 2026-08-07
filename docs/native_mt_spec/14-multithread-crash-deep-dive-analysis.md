# 14 Multi-Thread Crash Deep-Dive Staged Analysis (VIMAGE Isolation Direction)

> **Doc ID**: SPEC-NMT-14
> **Version**: v1 (staged, not complete)
> **Date**: 2026-07-29
> **Status**: 3-layer root causes identified; startup crash fixed (spinlock protects UMA per-CPU cache); wrk-load crash reverted because the rmlock global-lock direction deviated from the per-vnet isolation design; continuing deep-dive in the per-vnet isolation direction.
> **Follow-up progress**: per-vnet isolation implemented and crashes eliminated; the root cause of 2-thread performance collapse (worker clock gap) located and fixed; final bottleneck identified as virtio PMD lacking RSS support. See [15-worker-clock-gap-fix-and-virtio-rss-limitation.md](15-worker-clock-gap-fix-and-virtio-rss-limitation.md).
> **Evidence rule**: all crash locations, register values, and backtraces come from actual gdb run output; fabrication forbidden.

---

## 1. Background and Starting Point

Report 13 records: `thread_mode=1` 1 thread PASS (189,044 req/s); 2 threads crash at startup (gdb backtrace: `memset SIGSEGV at 0` ← `kqueue_kevent` ← `kern_kevent` ← `ff_kevent` ← `loop` at main.c:147). This stage deep-dives on that basis.

---

## 2. gdb Debugging History and 3-Layer Root Cause Identification

### 2.1 Root Cause A: UMA per-CPU cache sharing slot 0 with no lock contention (startup crash)

- **Symptom**: 2 threads crash with `memset SIGSEGV at 0` at startup; backtrace frame chain `uma_zalloc_pcpu_arg` → `vnet_mrtstat_init` → `vnet_alloc` → `ff_stack_thread_init`.
- **Root cause**: in `lib/include/vm/uma_int.h`, `critical_enter()/critical_exit()` are no-ops (`do {} while(0)`). All threads with `curcpu=0` share the `zone->uz_cpu[0]` per-CPU cache slot; `uma_zalloc_pcpu_arg` concurrently operates the same cache slot without critical-section protection, returning garbage pointers (including 0), and the subsequent `memset(NULL)` SIGSEGVs.
- **Fix**: `critical_enter/exit` changed to a spinlock based on `__sync_lock_test_and_set` (`uma_crit_lock` global variable defined in `ff_glue.c`), serializing UMA per-CPU cache access.
- **Validation**: 2-thread startup no longer crashes (helloworld enters the `ff_kevent` wait loop normally).
- **Retained state**: ✅ kept (this fix does not deviate from the per-vnet direction; it strengthens UMA infrastructure multi-thread safety).

### 2.2 Root Cause B: worker vnet_i mismatched with ifp->if_vnet=vnet0 (packet-processing crash)

- **Symptom**: no crash at startup, but crashes in `in_pcblookup_mbuf` ← `tcp_input` under wrk load.
- **Root cause**: the CM5-B original design has the worker call `vnet_alloc()` to create an independent `vnet_i` and bind `curthread->td_vnet = vnet_i`. But the DPDK NIC `ifp` is registered to `vnet0` (`ifp->if_vnet = vnet0`) in the main thread's `ff_freebsd_init`. When a packet enters via `ff_veth_input`, `ifp->if_vnet` (=vnet0) is used as `curvnet`, while the worker's socket/PCB live in `vnet_i`; `in_pcblookup_mbuf` looks up in the wrong vnet hash table → NULL pointer crash.
- **Temporary fix**: the worker does not call `vnet_alloc()`; it directly sets `curthread->td_vnet = vnet0` (sharing vnet0), eliminating the vnet mismatch.
- **Validation**: the `in_pcblookup_mbuf` crash under wrk load is eliminated (but root cause C appears).
- **Retained state**: ⚠️ kept as a temporary measure. **This loses per-vnet protocol-stack isolation**, not meeting the native-mt design goal. The real fix should give each worker an independent `vnet_i` and also register `ifp` to the corresponding vnet (or switch `curvnet` to the worker's `vnet_i` on the packet-processing path). See section 4.

### 2.3 Root Cause C: rmlock in ff_lock.c is a no-op (wrong direction, reverted)

- **Symptom**: after workers share vnet0, wrk load still crashes in `in_pcblookup_mbuf`.
- **Misjudged root cause**: in `lib/ff_lock.c`, `_rm_wlock/_rm_rlock/_rm_wunlock/_rm_runlock` are all no-ops; the PCB hash table `INP_INFO_RLOCK` (rmlock) has no lock protection → concurrent contention crash.
- **Wrong fix**: changed rmlock to a real mutex based on `mtx_lock/unlock(&rm->rm_lock_mtx)`.
- **Direction deviation**: **this fix deviates from the per-vnet isolation design**. native-mt's design is that each thread achieves protocol-stack isolation through an independent vnet; PCBs should be per-vnet independent (the `VNET_DEFINE` PCB hash table is one per vnet); a worker accesses only the PCBs in its own vnet, **and there should be no cross-thread shared PCB**. Introducing a global rmlock downgrades per-vnet isolation to global-share + lock, running counter to the design goal.
- **Revert status**: ✅ fully reverted `ff_lock.c` (`git diff` empty); rmlock restored to no-op.
- **Note**: root cause C's real cause is root cause B's temporary fix (workers sharing vnet0) making multiple workers genuinely share the same PCB hash table; only then does the no-op rmlock expose contention. **If per-vnet isolation is correctly implemented (each worker has an independent vnet_i), the PCB hash table is per-vnet independent, and the rmlock no-op is not a problem** (consistent with thread_mode=0 multi-process mode: each process has an independent vnet; rmlock is already a no-op there).

---

## 3. Implemented-and-Retained Change List

| File | Change | Purpose | Deviates from per-vnet? |
|---|---|---|---|
| `lib/ff_compat.c` | `malloc(sizeof(struct proc))` → `malloc(sizeof(struct thread))` | fix sizeof mismatch (allocating thread struct with proc size) | No |
| `lib/ff_dpdk_if.c` | `ff_stack_thread_init()` → `ff_stack_thread_init(rte_lcore_id())` | pass the actual lcore id as cpuid | No |
| `lib/ff_freebsd_init.c` | `ff_pcpu_thread_init/ff_stack_thread_init` gain `cpuid` parameter; `pcpu_init(pcpup, cpuid, ...)`; worker `curthread->td_vnet = vnet0` (temporary, no `vnet_alloc`) | per-thread pcpu init uses the real cpuid; temporarily eliminate the vnet mismatch | Partial (vnet0 sharing is temporary) |
| `lib/ff_glue.c` | define `volatile int uma_crit_lock` | UMA spinlock global variable | No |
| `lib/include/vm/uma_int.h` | `critical_enter/exit` changed to `__sync_lock_test_and_set` spinlock | serialize UMA per-CPU cache access (root cause A fix) | No |
| `lib/include/amd64/include/pcpu.h` | `#undef zpcpu_offset_cpu/zpcpu_base_to_offset/zpcpu_offset_to_base` | defensive undef (f-stack userspace has no `__pcpu` segment; avoid misusing macros containing `&__pcpu[0]`) | No |

---

## 4. Remaining Problem and Next Direction (per-vnet isolation)

### 4.1 Core Contradiction

The current temporary solution has all workers sharing `vnet0`; although it eliminates crashes, it **completely loses per-vnet protocol-stack isolation** — all workers share the same PCB/routing/socket lists, equivalent to "multi-thread sharing a single stack", which is not the native-mt design goal.

### 4.2 True per-vnet Isolation Solution (to be implemented)

To give each worker an independent `vnet_i` without crashing, the binding between `ifp->if_vnet` and the worker's `vnet_i` must be solved. Optional directions:

1. **Per-worker ifp registration**: each worker's `vnet_i` independently registers one `ifp` (`ifp->if_vnet = vnet_i`); packets entering via `ff_veth_input` select the corresponding `ifp` per worker. Requires changing `ff_veth.c`'s `ifp` management to per-vnet.
2. **curvnet switching on the packet-processing path**: at the `ff_veth_input` entry, `CURVNET_SET(worker_vnet_i)` before entering the stack, `CURVNET_RESTORE` on exit. Requires building a lcore → vnet mapping.
3. **ifp mounted to multiple vnets**: a single `ifp` mounted to all worker vnets (`ifp->if_vnet` changed to a per-vnet list); packet processing selects by the current thread's `curvnet`. High complexity, not recommended.

### 4.3 Rationality of the rmlock no-op

After per-vnet isolation is correctly implemented, each worker accesses only the PCB hash table in its own vnet, with no cross-thread sharing; the `rmlock` no-op is consistent with thread_mode=0 multi-process mode (each process has an independent vnet; rmlock is already a no-op). **Therefore rmlock need not become a real lock; the current revert is correct.**

### 4.4 Follow-up Work

- Research the binding mechanism between `ifp` and vnet in FreeBSD VIMAGE (`if_attach` / `if_vmove`).
- Design a per-worker-vnet `ifp` registration or `curvnet` switching solution.
- After implementation, re-run the 2/4-thread wrk load test (`ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://<DPDK_NIC_IP>:80/"`).

---

## 5. Currently Runnable State

- `thread_mode=0` (multi-process): unchanged, zero regression.
- `thread_mode=1` 1 thread: not tested (should match report 13, 189,044 req/s).
- `thread_mode=1` 2 threads: **no crash at startup** (root cause A fixed), but wrk load still crashes (root cause B's temporary fix introduced root cause C's illusion; true per-vnet isolation needed).
- `config.ini`: workspace contains local test values (`lcore_mask=30`, `thread_mode=1`, local IP, etc.), **not committed**.
