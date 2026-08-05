# M4-D Independent Code Review Report

> Reviewer: independent code-explorer subagent (read-only role, not the author of this round's code)
> Committer: leader (the subagent has no file-writing tool; content transcribed verbatim)
> Date: 2026-08-03
> Review method: read-only static review (search_content / read_file / read_lints) + leader re-check of key items

---

## 0. Prerequisite Fact Verification (Does the leader's Basis Hold) — **Holds**

| Assertion | Evidence |
|---|---|
| This build does not define `SMP`, `MAXCPU == 1` | `freebsd/amd64/include/param.h:60-66`; `lib/opt/opt_global.h:1-6` (only MUTEX_NOINLINE/RWLOCK_NOINLINE/SX_NOINLINE/DEV_RANDOM/NO_EVENTTIMERS/VIMAGE, no SMP); `lib/Makefile:70-177` has no `-DSMP` |
| `mp_ncpus=1`, `mp_maxid=0` | `lib/ff_glue.c:140,145`; `all_cpus` only bit0 (`lib/ff_freebsd_init.c:294`) |
| per-cpu arrays allocated for only 1 CPU | `freebsd/kern/subr_smr.c:597-605` (`for i<=mp_maxid`); `freebsd/vm/uma_core.c:2472-2474`; **`:2546-2548` `#ifndef SMP` directly strips the `UMA_ZONE_PCPU` flag** |
| non-0 cpuid makes `zpcpu_get()` go out of bounds | `freebsd/kern/subr_pcpu.c:96` → `freebsd/sys/pcpu.h:234-236,249-252` |
| `INVARIANTS` undefined (KASSERT compiled out) | `lib/Makefile` / `lib/opt/*.h` whole tree has no `INVARIANTS` |

### Corroborating Evidence (Additional Findings, Reinforcing the Necessity of Change 2)

- `freebsd/netinet/ip_id.c:270` `zpcpu_get(V_ip_id)` sits in the `else` branch (`:250`'s `V_ip_rfc6864 && IP_DF` hit skips that line), called by `ip_output.c:371` `ip_fillid()` → before the change, reaching that branch means offset=8192 out-of-bounds read/write.
- `lib/ff_kern_timeout.c:254` `timeout_cpu = PCPU_GET(cpuid)`; `:730-734` `if (cpu >= MAXCPU) panic("Invalid CPU in callout %d")`. Before the change, worker `c_cpu = 2 >= MAXCPU(1)` → any `callout_reset` should panic. And `timeout_cpu` is a **non-`__thread` static global** (`:190`); multiple workers writing different values is itself a race; after the change it uniformly becomes 0, deterministic.

---

## 1. Change 2 (`pcpu_init(pcpup, 0, ...)`)

### 1(a) `cpuid_to_pcpu[0]` Overwrite / `cpuhead` Chaining Multiple pcpu — **PASS (no actual error in this build)**

Exhaustively checked the readers of the three across `lib/Makefile`'s SRCS (`:339-377` KERN, `:413-445` NET, `:492-536` NETINET, `:539-567` NETINET6, `:649-650` VM):

- All `pcpu_find()` call sites (`subr_smp.c:386,990,997`, `subr_witness.c:2335`, `uipc_ktls.c:510,3305`, `sched_4bsd.c:1265`, `kern_clock.c:146,318`, `kern_pmc.c:361`, `kern_timeout.c:321`, `x86/*`, `arm*/*`) **are all not in SRCS** (note: what is compiled is `lib/ff_kern_timeout.c`, not `freebsd/kern/kern_timeout.c`).
- The only two call sites falling in compiled files are closed by FSTACK: `freebsd/vm/uma_core.c:1982` inside `#ifndef FSTACK` (`:1957` onward); `freebsd/netinet/tcp_hpts.c:2032` inside `#ifndef FSTACK` (`:2025`).
- `cpuhead` traversers (`kern_idle.c:62`, `kern_rmlock.c:846`, `subr_kdb.c:647`, `sched_4bsd.c:1208,1243`, `kern_racct.c:1247`, `local_apic.c:801`) are all not compiled.
- Direct `cpuid_to_pcpu[]` readers (`kern_rmlock.c:452,516`, `vfs_subr.c:1613`, `kern_membarrier.c:87,163`, `vm_kern.c:992`, `mp_x86.c:1293,1334`) are all not compiled.
- `dpcpu_init()`/`pcpu_destroy()` (`subr_pcpu.c:100-118,270-276`) have no callers in this build.

Conclusion: overwriting `cpuid_to_pcpu[0]` and chaining multiple items on `cpuhead` has **no readers in this build**, producing no actual error.

**NIT (fixed)**: `ff_pcpu_thread_init()` was originally called **before** the `init_lock` spinlock, while inside `pcpu_init()` the `cpuid_to_pcpu[0]=pcpu` (`subr_pcpu.c:91`) and `STAILQ_INSERT_TAIL(&cpuhead,...)` (`:92`) are lock-free global writes concurrent among workers, and the `cpuhead` list can be corrupted. Although harmless with no readers today, it is a landmine.
→ **leader fixed per suggestion**: `ff_pcpu_thread_init(cpuid)` moved into the `init_lock` critical section (`lib/ff_freebsd_init.c:185-187`, lock 185-186, call 187, release 216), zero performance impact (init path only).

### 1(b) Whether `PCPU_GET/PCPU_SET` Only Goes Through `__thread pcpup` — **PASS**

`lib/include/amd64/include/pcpu.h:33-53`: first `#undef __curthread/get_pcpu/PCPU_GET/PCPU_ADD/PCPU_INC/PCPU_PTR/PCPU_SET/zpcpu_offset_cpu/...`, then defines them as `(pcpup->pc_ ## member)`, with `pcpup` being `__thread` (defined at `lib/ff_freebsd_init.c:85`). `get_pcpu()` = `pcpup->pc_prvspace`, self-consistent with `PCPU_SET(prvspace, pcpup)`. **Completely unrelated to `cpuid_to_pcpu[]`**; the amd64 `%gs`-segment access path (`freebsd/amd64/include/pcpu.h:139-259,269-273`) is wholesale replaced on the F-Stack side by `#ifndef FSTACK`.

### 1(c) All Threads `pc_zpcpu_offset==0` → Shared UMA per-cpu cache / SMR Slot — **APPROVE_WITH_NITS (residual risk, recorded)**

Fact chain:
- `#ifndef SMP` strips `UMA_ZONE_PCPU` (`freebsd/vm/uma_core.c:2546-2548`), so `uma_zalloc_pcpu` actually allocates only 1 slot.
- `freebsd/netinet/in_pcb.c:615-617` `in_pcbstorage_init` creates the zone with `UMA_ZONE_SMR`; `:583` `pcbinfo->ipi_smr = uma_zone_get_smr(...)` → PCB lookup indeed goes through SMR (`smr_enter/smr_exit` inside `in_pcblookup_mbuf`, `in_pcb.c:1820,1839,1847,1854`).
- `freebsd/sys/smr.h:106-143` `smr_enter` does `atomic_add_acq_int(&smr->c_seq, ...)`, `smr_exit` sets `SMR_SEQ_INVALID`; `KASSERT(c_seq==0, recursion not supported)` is compiled out for lacking `INVARIANTS`.

Judgment: multiple workers sharing the same SMR per-cpu slot theoretically creates a window where thread A's `smr_exit` clears thread B's read-section marker → `smr_poll` wrongly concludes no readers → PCB recycled early (UAF).

But two points must be clear:
1. **This risk was not introduced by this round's change.** Before the change, non-0 offset → **guaranteed out-of-bounds** (measured SIGSEGV); after the change it is "legal but shared", a strict improvement.
2. Full elimination requires `mp_maxid > 0` and truly allocating per-cpu arrays by thread count (equivalent to making the f-stack kernel view SMP-aware), a separate and much larger scope than this fix.

**Measured stress validation (executed by leader)**: 8-thread 400-connection 60-second soak, 29.83M requests, 497,043 req/s, zero socket errors, zero Non-2xx, process alive. No UAF symptoms observed, but the static risk window objectively exists, recorded as a residual-risk item in doc 16 Section 8.

---

## 2. Change 3 (`ff_worker_prison_init`) Memory/Refcount Safety — **PASS (with NIT)**

Cross-checked `struct prison` at `freebsd/sys/jail.h:182-251`:

| Item | Conclusion | Evidence |
|---|---|---|
| `pr_cpuset` / `pr_root` directly sharing prison0 pointers without refcounting | **No actual risk**: per-worker prison lifetime equals the process (never `prison_free`/`prison_deref`), and prison0 is a static global (`lib/ff_init_main.c:97`) never freed, so no UAF or refcount imbalance exists | `prison_free` in `lib/ff_glue.c` is a no-op stub |
| `pr_ip4`/`pr_ip6`/`pr_prison_racct` | kept M_ZERO NULL, no readers in this build (`prison_check_ip4` etc. all stubs returning 0) | `lib/ff_glue.c:257-259,299-302` |
| `pr_id = -1` | **No risk**: no code treats it as a valid jid (the jail syscall family is not compiled; `kern_jail.c` not in SRCS) | `lib/Makefile` SRCS has no `kern_jail.c` |
| `PR_VNET` flag / `jailed()` | **No TCP/UDP data-plane behavior change** (see the correction below) | `freebsd/sys/jail.h:449`, `lib/ff_glue.c:286-290,299-302`, `freebsd/netinet/in_pcb.c:2743-2746` |

**Correction (found at the second gate; the original statement was wrong)**: the `jailed()` stub at `lib/ff_glue.c:346-352` is entirely inside `#if 0` (**not compiled**). What actually takes effect is the macro `freebsd/sys/jail.h:449` `#define jailed(cred) (cred->cr_prison != &prison0)`, so under per-worker prisons the worker cred's `jailed()` **is true**.

But the substantive conclusion still holds, verified item by item:
- **PCB insert/lookup ordering unaffected**: `in_pcbjailed()` (`freebsd/netinet/in_pcb.c:2743-2746`) goes through `prison_flag()`, and f-stack's `prison_flag` stub (`lib/ff_glue.c:286-290`) **completely ignores cred**, only returning `(flag & PR_HOST) != 0`; call sites pass `PR_IP4`/`PR_IP6`, so `in_pcbjailed` is always false, unrelated to the prison change.
- **The only `jailed()` reader in the compiled set is `freebsd/netinet/raw_ip.c:500`** (`in_jail.c` / `in6_jail.c` / `kern_jail.c` / `kern_cpuset.c` all not in `lib/Makefile` SRCS), affecting only raw IP + `IP_HDRINCL` paths; and the `prison_local_ip4` it calls is a stub returning 0 (`lib/ff_glue.c:299-302`).
- `jailed_without_vnet()` is indeed a stub always returning false (`lib/ff_glue.c:359-362`, not inside `#if 0`).

Conclusion: this prison change has **no behavior change** to the TCP/UDP data plane or PCB hash ordering; helloworld does not use raw IP, so this round's measurements are unaffected.
| List heads and mutex | `LIST_INIT(pr_children/pr_proclist/pr_descs)` + `mtx_init(pr_mtx)` all correctly initialized; **not** linked into `allprison`/prison0's children, avoiding global-list concurrency | new function body in `lib/ff_freebsd_init.c` |

**NIT**: after `malloc(..., M_ZERO | M_WAITOK)` it still checks `if (pr == NULL) return;`. Under `M_WAITOK` semantics it never returns NULL; the check is redundant but harmless (defensive writing, acceptable to keep).

---

## 3. thread_mode=0 Zero Regression — **PASS**

- Change 2 is a **no-op** for mode0: the main-thread path `lib/ff_freebsd_init.c:293` already calls `ff_pcpu_thread_init(0)`; the passed value was already 0, fully equivalent after changing to the constant 0.
- The worker path `:187` is only entered under `thread_mode=1` from `main_loop` (`lib/ff_dpdk_if.c:2649`); in mode0 the main thread returns directly at `:177-179` because `ff_stack_inited` was set in `ff_freebsd_init`.
- Change 1 is a `thread_mode` ternary; mode0 takes `nb_procs`, literally equivalent to the original code.
- Change 3 lives on the worker-exclusive path (inside `init_lock` critical section, body of `ff_stack_thread_init`), unreachable in mode0.

**Measured corroboration**: thread_mode=0 single process 209,946 / 209,367 req/s; double process 234,613 / 233,982 req/s, all consistent with the pre-fix baseline.

---

## 4. Data-Plane Zero-Lock Iron Rule — **PASS**

- All three changes sit on the initialization path: `init_mem_pool()` (after `rte_eal_init`, before `main_loop`), `ff_pcpu_thread_init()`, `ff_stack_thread_init()`.
- **No new lock inside** `main_loop`'s `while(1)` (the only `rte_spinlock` is the existing `ifp_create_lock`, taken only during the one-time `veth_ctx[lcore][port]==NULL` creation).
- `mtx_init(&pr->pr_mtx, ...)` only **initializes** the mutex, not locking; no data-plane path anywhere locks that `pr_mtx` (all prison-related functions are stubs).
- The `init_lock` spinlock is taken once per thread at startup; the `main_loop` steady-state never touches it.

---

## 5. Debug Residue — **PASS**

- `grep -rn "DBG\|dbg_" lib/ example/` zero hits.
- `git diff --stat` shows only `config.ini`, `lib/ff_dpdk_if.c`, `lib/ff_freebsd_init.c`; `lib/ff_veth.c`, `example/main.c`, `lib/ff_api.symlist` byte-identical to HEAD (`git diff --quiet` verified).
- (subagent declares: it has no git tool; this sub-item was re-checked by the leader.)

---

## 6. Comment Conventions — **PASS**

The two new comment blocks (6 lines above `ff_pcpu_thread_init`, 6 lines above `ff_worker_prison_init`, 2 lines after `vnet_alloc`) all target **genuinely non-obvious** mechanisms: the causal link of `MAXCPU==1` under non-SMP and `zpcpu_get` going out of bounds; the counter-intuitive fact that `CRED_TO_VNET` rather than `curvnet` decides a socket's vnet; and the ordering constraint that prison init must precede `lo_set_defaultaddr()`. No line re-describes "obvious at a glance" code; length is reasonable, compliant with the minimal-comment convention.

---

## 7. Change 1 Boundary — **PASS**

- `proc_lcore` is `uint16_t *` (`lib/ff_config.h:313`), filled in `parse_lcore_mask` with dual bounding by `idx < RTE_MAX_LCORE` (`lib/ff_config.c:110,116`), capacity sufficient.
- Under thread_mode=1, `proc_lcore[]` indeed stores each worker's lcore id: `parse_lcore_mask` writes in set-bit order and sets `nb_procs=count` (`:138`); the thread_mode collapse happens after (`:1465-1484`, `nb_threads = nb_procs; nb_procs = 1`), so `nb_threads == count == number of valid `proc_lcore[]` elements`, semantically correct.
- Type: `nb_pools` changed to `uint16_t` per suggestion (was `int`), consistent with loop variable `i` (`uint16_t`), eliminating the signed-comparison warning hazard; `nb_threads`/`nb_procs` are `int` (`:290,293`) but values ≤ `RTE_MAX_LCORE`, no truncation risk.

---

## Overall Verdict

**APPROVE_WITH_NITS**

- All 7 items PASS.
- Of the 2 NITs, 1(a)'s "`pcpu_init` not inside the lock" was fixed by the leader per suggestion and re-clean-built + re-measured PASS; 2's "NULL check after `M_WAITOK`" is harmless defensive writing, kept.
- 1(c)'s shared SMR slot is a residual risk that **already existed before the change and was improved by this fix from "guaranteed out-of-bounds" to "legal but shared"**, not introduced this round; must be explicitly recorded as a residual-risk item, and solved in the future as an independent project with "f-stack kernel view SMP-aware (`mp_maxid > 0` + truly allocating per-cpu arrays by thread count)".
