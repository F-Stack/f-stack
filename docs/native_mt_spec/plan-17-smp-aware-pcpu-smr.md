# plan-17: Making the f-stack Kernel View SMP-aware — Eliminating Worker-Shared SMR/UMA per-CPU Slots + Removing the Data-Plane Global Lock

> This document is this round's execution plan (the user requires "generate a complete plan.md first, then execute").
> All "verified facts" are confirmed by actually opening files, annotated with `file:line`; all "to-be-verified" items must not be speculated and must be filled in by subagents after measurement.

---

## 0. Task Definition

### 0.1 Problem Statement

Last round (commit `ff09a17b2`), to fix native-mt multi-thread crashes, the cpuid passed to `pcpu_init()` inside `ff_pcpu_thread_init()` was fixed to 0:

- Before the fix: workers used `rte_lcore_id()` (e.g. 2) as cpuid, but this build is non-SMP (`MAXCPU==1`, `mp_maxid==0`), so UMA/SMR per-cpu arrays are allocated for only 1 CPU → `zpcpu_get()` **guaranteed out-of-bounds** → measured SIGSEGV in `in_pcblookup_mbuf`.
- After the fix: all workers' `pc_zpcpu_offset` is 0 → multiple workers **legally but share** the same UMA per-CPU cache slot and the same SMR `c_seq` slot → a theoretical UAF window exists (SMR's per-CPU sequence numbers overwritten by multiple threads, possibly concluding a grace period ended early and recycling still-referenced PCBs).

This residual risk was honestly recorded in `16-multiqueue-comparison-experiment-and-root-cause-correction.md` Section 8.1. This round is its dedicated project.

### 0.2 This Round's Two Co-Equal Primary Goals (user confirmed `uma_crit_lock` removal is a primary goal, not optional)

- **G1**: make the f-stack kernel view SMP-aware — each worker gets a dense, independent pcpu slot; UMA/SMR per-cpu storage is split into slots by thread count; completely eliminate the theoretical UAF window of shared SMR slots.
- **G2**: after per-CPU slots are truly isolated, remove the data-plane global spinlock `uma_crit_lock` (`lib/include/vm/uma_int.h:45-52` replaces `critical_enter/exit` with a single global spinlock; **its actual scope is only translation units including `vm/uma_int.h`, see §1.4**), restoring the lock-free fast path of the UMA per-CPU cache.

### 0.3 Solution Orientation (user verdict: research first, then leader decides)

Do not presuppose a route; the following two candidates must be selected based on **compile/code evidence**, with the decision basis and fallback path written into the spec:

- **Candidate B (minimal intrusion)**: do not define `SMP`; only make per-cpu allocation split into slots by worker count + dense index per worker. Means: override `MAXCPU` + release the `UMA_ZONE_PCPU` stripping at `freebsd/vm/uma_core.c:2546` + set `mp_ncpus`/`mp_maxid` before UMA/SMR init + pass the dense index `0..N-1` to `pcpu_init`.
- **Candidate A (thorough)**: full-tree `-DSMP`. Closest to upstream semantics, but activates `smp_rendezvous`/`CPU_FOREACH`/`ipi_*`/`sched_pin` paths, likely requiring many stubs.

### 0.4 Validation Intensity (user verdict: standard)

`thread_mode=1` 1/2/4-thread matrix × multiple wrk rounds (`-t5 -c100 -d10s`) + 60s/400-connection soak (`-t8 -c400 -d60s`) + `thread_mode=0` single/double-process zero-regression comparison; additionally do a throughput comparison before/after removing `uma_crit_lock` (G2 is a primary goal; must have performance data support). No ASAN/valgrind special builds.

---

## 1. Verified Code Facts (This Round's Starting Point; Cannot Be Overturned Without New Evidence)

Repo root `/data/workspace/f-stack`, HEAD = `ff09a17b2`; reference trees `/data/workspace/freebsd-src-releng-15.0`, `/data/workspace/dpdk-stable-24.11.6`.

### 1.1 pcpu / zpcpu View

| Location | Fact |
|---|---|
| `lib/ff_freebsd_init.c:85` | `__thread struct pcpu *pcpup;` |
| `lib/ff_freebsd_init.c` `ff_pcpu_thread_init()` | `malloc(sizeof(struct pcpu),...)` → `pcpu_init(pcpup, 0, sizeof(struct pcpu))` → `PCPU_SET(prvspace, pcpup)`; the `cpuid` parameter is currently deliberately ignored |
| `lib/ff_freebsd_init.c:~187` | worker call site in `ff_stack_thread_init`, inside the `init_lock` spinlock critical section |
| `lib/ff_freebsd_init.c:~293` | main-thread call site `ff_pcpu_thread_init(0)` |
| `lib/include/amd64/include/pcpu.h:33-42` (undef), `:47-53` (`PCPU_*` redefinition), `:55-67` (`__curthread_ff`/`curthread` redefinition) | after `#include_next`, `#undef`s `__curthread`/`get_pcpu`/`PCPU_GET`/`PCPU_ADD`/`PCPU_INC`/`PCPU_PTR`/`PCPU_SET`/`zpcpu_offset_cpu`/`zpcpu_base_to_offset`/`zpcpu_offset_to_base` (10 items), and redefines `PCPU_*` to access via the `__thread pcpup`. **`zpcpu_offset_cpu` is undef'd and not redefined** |
| `freebsd/sys/pcpu.h:234-236` | `#ifndef zpcpu_offset_cpu` / `#define zpcpu_offset_cpu(cpu) (UMA_PCPU_ALLOC_SIZE * cpu)` / `#endif` |
| `freebsd/sys/pcpu.h:237-239,249-252,254-257` | `zpcpu_offset()` = `PCPU_GET(zpcpu_offset)`; `zpcpu_get(base)` = `base + zpcpu_offset()`; `zpcpu_get_cpu(base,cpu)` = `base + zpcpu_offset_cpu(cpu)` |
| `freebsd/kern/subr_pcpu.c:88-89,91-92,96` | `KASSERT(cpuid >= 0 && cpuid < MAXCPU, ...)` (compiled out because INVARIANTS undefined); `cpuid_to_pcpu[cpuid]=pcpu`; `STAILQ_INSERT_TAIL(&cpuhead,...)`; `pc_zpcpu_offset = zpcpu_offset_cpu(cpuid)` |
| `freebsd/kern/subr_pcpu.c:252,270-277,282-287` | `dpcpu_copy()` has an `#ifdef SMP` branch; `pcpu_destroy()` does `STAILQ_REMOVE`(:274) and clears `cpuid_to_pcpu[]`(:275)/`dpcpu_off[]`(:276); `pcpu_find(cpuid)` returns `cpuid_to_pcpu[cpuid]` |
| `lib/ff_dpdk_if.c:2649` | `ff_stack_thread_init(rte_lcore_id());` — **the current actual source of cpuid is `rte_lcore_id()`**; G1's dense-index change must land at this call site |
| `lib/ff_freebsd_init.c:294` | right after the main thread's `ff_pcpu_thread_init(0)` comes `CPU_SET(0, &all_cpus);` — `all_cpus` currently only contains CPU 0; must be synchronized once `mp_maxid>0` |
| `freebsd/amd64/include/pcpu_aux.h:47` (via `freebsd/sys/pcpu.h:223`) | `_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE, ...)` — `struct pcpu` must be exactly 4096 bytes; this assertion is a hard constraint when changing pcpu-related definitions |

### 1.2 MAXCPU / mp_ncpus / mp_maxid

- `freebsd/amd64/include/param.h:60-66`: `#ifdef SMP` → `MAXCPU 1024`; `#else` → **unconditionally** `#define MAXCPU 1`. So plain `-DMAXCPU=N` has no effect; `SMP` must be defined or an override header used.
- `lib/ff_glue.c:138-146`: `cpuset_t all_cpus;`(:138), `int mp_ncpus = 1;`(:140), `int mp_maxcpus = MAXCPU;`(:142), `volatile int smp_started;`(:144), `u_int mp_maxid;`(:145, BSS zero), `volatile int uma_crit_lock;`(:146).
- `lib/Makefile` does not define `-DSMP` (confirmed by grepping the CFLAGS/HOST_CFLAGS sections); `INVARIANTS` also undefined. **M1-C must do an exhaustive re-check of `mk/` and `lib/opt/opt_global.h`.**

### 1.3 UMA / SMR per-CPU Dependencies

- `freebsd/vm/uma_core.c:2546-2548`: `#ifndef SMP` → `keg->uk_flags &= ~UMA_ZONE_PCPU;` (non-SMP per-cpu zones degenerate to a single copy).
- `freebsd/vm/uma_core.c:3494-3516` `uma_zalloc_pcpu_arg()`: with `#ifdef SMP`, `MPASS(uz_flags & UMA_ZONE_PCPU)` and `for (i=0;i<=mp_maxid;i++) bzero(zpcpu_get_cpu(item,i), uz_size)`; `#else` only bzeroes one copy. `:3521-3536` `uma_zfree_pcpu_arg` is isomorphic (`MPASS` at `:3527`).
- `freebsd/vm/uma_core.c:1957` `#ifndef FSTACK` → per-CPU `vm_page_alloc_noobj` version of `pcpu_page_alloc` (`:1970 MPASS(bytes == (mp_maxid+1)*PAGE_SIZE)`, `:1975 for (cpu=0; cpu<=mp_maxid; cpu++)`); `:2082 #else` → fallback version `:2083-2089` (`*pflag=UMA_SLAB_KERNEL; return page_alloc(zone,bytes,domain,pflag,wait)`); `:2114 #endif`. Because `lib/Makefile:219 CFLAGS+= -DFSTACK`, **this build necessarily compiles the fallback version (statically verified, not to-be-verified)**. `lib/include/vm/uma_int.h:43 #undef UMA_MD_SMALL_ALLOC` affects the `UMA_USE_DMAP && !UMA_MD_SMALL_ALLOC` block at `uma_core.c:2116`/`:2208`, unrelated to this choice.
- `freebsd/sys/pcpu.h:221 #define UMA_PCPU_ALLOC_SIZE PAGE_SIZE`, `freebsd/amd64/include/param.h:92-93 PAGE_SHIFT 12 / PAGE_SIZE (1<<12)` → **4096**. Because `sys/pcpu.h:48` first includes f-stack's overridden `machine/pcpu.h` (whose `:40 #undef zpcpu_offset_cpu`), `sys/pcpu.h:234 #ifndef` holds → `zpcpu_offset_cpu(cpu) == 4096*cpu` (not the `&__pcpu[0]+...` version of `freebsd/amd64/include/pcpu.h:270`).
- `freebsd/vm/uma_core.c:2351-2356` is `KASSERT((uk_flags & UMA_ZONE_PCPU)==0 || (uk_size <= UMA_PCPU_ALLOC_SIZE && ...))`; **with `INVARIANTS` undefined the whole line compiles out; this build has no runtime protection**. The actually-effective PCPU logic in `keg_layout` is `:2472-2478`: `pages = atop(kl.slabsize); if (UMA_ZONE_PCPU) pages *= mp_maxid+1; keg->uk_ppera = pages;`.
- **`mp_maxid` timing hard constraint**: `freebsd/vm/uma_core.c:3179-3182` computes the zone structure size `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + ...` once at uma_startup; `:2472-2478` also scales the keg's `uk_ppera` by `mp_maxid+1`; `:2873 zone_update_caches`, `:5589/:5620/:5674` stat paths all traverse `uz_cpu[]` by `mp_maxid`. → **`mp_maxid` must be set before `uma_startup1/2` and never changed afterward**, otherwise `uz_cpu[i>0]` goes out of bounds (heap overflow).
- `freebsd/kern/subr_smr.c:583-609` `smr_create()`: `uma_zalloc_pcpu(smr_zone, M_WAITOK)`(:591) then `for (i=0;i<=mp_maxid;i++){ c=zpcpu_get_cpu(smr,i); c->c_seq=SMR_SEQ_INVALID; c->c_shared=s; }`(:598-605). `:623-631` `smr_init()`: `uma_zcreate("SMR CPU", sizeof(struct smr), ..., UMA_ZONE_PCPU)`.
  > **Key constraint**: `mp_maxid` and `UMA_ZONE_PCPU` must be modified **in pairs**. Raising only `mp_maxid` while the zone stays single-slot → that loop writes out of bounds.
- `freebsd/sys/smr.h:105-143` `smr_enter()` goes through `zpcpu_get(smr)`(:110); its `critical_enter()` is a **no-op** in non-UMA translation units (see §1.4).
- `freebsd/netinet/in_pcb.c:583,615-617` `ipi_smr = uma_zone_get_smr(...)`, `uma_zcreate(..., UMA_ALIGN_CACHE, UMA_ZONE_SMR)` — the PCB lookup path indeed goes through SMR, i.e. last round's SIGSEGV site.

### 1.4 Data-Plane Global Lock (G2 Target)

- `lib/include/vm/uma_int.h:45-52`:
  ```c
  extern volatile int uma_crit_lock;
  #define critical_enter() do { while (__sync_lock_test_and_set(&uma_crit_lock, 1)) ; } while(0)
  #define critical_exit()  do { __sync_lock_release(&uma_crit_lock); } while(0)
  ```
  The same file also stubs `sleepq_*`(:54-57)/`_vm_map_unlock`(:59), `#undef UMA_MD_SMALL_ALLOC`(:43), defines `UMA_PAGE_HASH`(:65)/`struct uma_page`(:67-74).
- **The lock's true scope (G2 argument core)**: `freebsd/sys/systm.h:179-193` non-KLD branch's inline `critical_enter()` function body is entirely excluded by `#ifndef FSTACK`(:186) → **under f-stack, `critical_enter/exit` themselves are no-ops**; the only macro-level override of `critical_enter` in the whole tree is `lib/include/vm/uma_int.h:46/50`. The `.c` files that include `vm/uma_int.h` and are in `lib/Makefile` SRCS are only `freebsd/vm/uma_core.c`(:650) and `lib/ff_freebsd_init.c` (`kern_malloc.c`/`subr_vmem.c`/`vm_page.c`/`uma_dbg.c`/`memguard.c`/`kern_switch.c` are not compiled).
  → Corollary: `uma_crit_lock` actually only serializes `uma_core.c`'s allocation fast path; `critical_enter()` in `smr_enter()`(smr.h:109) is a no-op, so **the SMR read side currently has zero preemption/concurrency protection**, and the shared `c_seq` slot is the only substantive risk. G2's equivalence argument should anchor on "each thread exclusively owns its per-CPU slot", **not "disable preemption"**; after lock removal, UMA simply returns to the same "empty critical section" semantics as other subsystems.
- Related commit `b90ddcba5` "Fix UMA per-CPU cache race and sizeof mismatch for native-mt multi-thread startup" — this global lock is likely a stopgap introduced to avoid the "shared pcpu slot" issue. **M1-A must `git show b90ddcba5` to establish the introduction motivation; guessing forbidden.**
- `lib/include/amd64/include/counter.h:38-62` completely de-per-cpu-izes counter(9) (`counter_u64_add`(:58-62) is `*c += inc`, `counter_u64_fetch_inline`(:43-47) is `*p`, `counter_enter/exit`(:38-39) no-ops); `freebsd/kern/subr_counter.c` has no `mp_maxid`/`CPU_FOREACH`/`zpcpu` traversal (only `:63 uma_zalloc_pcpu(pcpu_zone_8,...)`). → Raising `mp_maxid` will **not** make counter go out of bounds; the actual effect is multi-thread writes to the same slot causing stat contention and fetch only reading slot 0; must be recorded in the spec as a **known deviation**, not a memory-safety item.

---

## 2. Key Unknowns That Must Be Measured (M1 Deliverable; Speculation Forbidden)

| # | Unknown | Verification means |
|---|---|---|
| U1 | (**already statically verified**; `gcc -E` only as cross-confirmation) `zpcpu_offset_cpu(cpu) = 4096*cpu`, `UMA_PCPU_ALLOC_SIZE = PAGE_SIZE = 4096` | cross-confirm via `gcc -E` preprocessor output |
| U2 | (**compile branch already statically verified as `uma_core.c:2083-2089` fallback**, based on `-DFSTACK**) to be verified: whether f-stack's `page_alloc` can stably allocate `(mp_maxid+1)*PAGE_SIZE` and satisfy the `uk_ppera` assumption scaled by `keg_layout:2472-2478` | code review + runtime probes |
| U3 | distribution and count of all-tree `#ifdef SMP`/`#ifndef SMP`/`defined(SMP)` **within `lib/Makefile`'s actual SRCS list**; the list of symbols newly activated and missing after `-DSMP` | per actual `make` compile/link errors |
| U4 | whether all readers of `mp_maxid` (`CPU_FOREACH`, counter(9), `uma_core.c`, `subr_smr.c`, `subr_pcpu.c`, sysctl/netstat stats) are all safe after `mp_maxid>0`; whether `all_cpus`/`CPU_ABSENT`/`cpuset_t` (`CPU_SETSIZE` changes with MAXCPU affecting struct size and ABI) need synchronized init and full-tree rebuild | exhaustive grep + point-by-point code review |
| U5 | after dense indexing, whether `cpuid_to_pcpu[]`/`cpuhead` writes still need `init_lock` protection; whether runtime readers of `pcpu_find()`/`cpuhead` traversal exist (semantics changed; must be exhaustively re-verified) | grep + call-chain analysis |
| U6 | dense-index source: should be taken from the `ff_global_cfg.dpdk.proc_lcore[]` subscript (`lib/ff_config.c` ~110-141, ~1465-1490 `parse_lcore_mask` and thread_mode collapse logic), not `rte_lcore_id()`; must confirm the main thread (currently 0) and worker indices **do not collide**, giving a clear mapping plan | code review + runtime print evidence |
| U7 | whether the premise for removing `uma_crit_lock` holds: upstream relies on disabling preemption to guarantee no concurrency on the same CPU; userspace must argue equivalence (workers are 1:1 pinned polling threads without migration, but do the main thread/KNI/callout/`ff_veth` auxiliary paths also satisfy it) | per-path verification + load test |
| U8 | whether any path allocates/frees the same zone across threads (mbuf allocated on worker A, freed on B); safe after lock removal (upstream relies on the zone-level `uz_lock` for bucket exchange; must confirm f-stack did not stub out the zone lock) | code review + load test |
| **U9** (high) | **cross-translation-unit consistency of `MAXCPU`-sized arrays**: when candidate B overrides `MAXCPU` via an override header, do all TUs see the same value? Any TU missing the change creates a new out-of-bounds source. Basis: `freebsd/kern/subr_pcpu.c:76-77` `uintptr_t dpcpu_off[MAXCPU]; struct pcpu *cpuid_to_pcpu[MAXCPU];`, `lib/ff_kern_synch.c:59` `static uint8_t pause_wchan[MAXCPU];` (`:105` indexed by `curcpu`), `lib/ff_glue.c:142` `mp_maxcpus = MAXCPU`, `lib/ff_kern_timeout.c:730` `cpu >= MAXCPU` panic | per-TU preprocessing check + compile |
| **U10** (high) | **setting timing of `mp_maxid`** must be earlier than `uma_startup1/2` (all zones' `uz_cpu[]` sizes finalized there) and immutable afterward; must confirm the order of `mp_maxid` assignment point vs `uma_startup*`/`smr_init`/each `uma_zcreate` in the f-stack startup sequence | code review + runtime print |
| **U11** (high) | callout's cpuid semantics distort under dense indexing: `lib/ff_kern_timeout.c:183-185` `__thread struct callout_cpu cc_cpu; #define CC_CPU(cpu) &cc_cpu` (comment explicitly says "cpuid is always 0, MAXCPU=1"), `:190 static int timeout_cpu;` (**a non-`__thread` global yet written per thread**), `:254 timeout_cpu = PCPU_GET(cpuid);`, `:662/:1181 CC_CPU(timeout_cpu)`, `:1061/:1077 c->c_cpu = timeout_cpu;`, `:730-733 panic("Invalid CPU in callout %d")` | code review + runtime |
| **U12** (medium) | the dense pcpu id and `rte_lcore_id()` are **two index spaces**; must confirm no mixing point by point; DPDK `rte_mempool` per-lcore cache still uses `rte_lcore_id`, unrelated to UMA per-CPU slots (must write the boundary clearly in the spec). Basis: `lib/ff_dpdk_if.c:2649`, `:2745/:2841 veth_ctx[rte_lcore_id()][port_id]`, `:582-583`; `lib/Makefile:346,372-373` show `kern_mbuf.c`/`uipc_mbuf.c` are still compiled (UMA mbuf zone coexists with DPDK pool) | code review |
| **U13** (medium) | whether **threads without `pcpup`** can enter the UMA/SMR fast path: `lib/ff_thread.c:20-30/33-46` `ff_pthread_create` only inherits `pcurthread`, does not call `ff_pcpu_thread_init` → such threads have `pcpup == NULL`. The thread models of KNI (`lib/ff_dpdk_kni.c`, `lib/Makefile:36,90-91` already has `FF_KNI=1`)/`ff_veth`/DPDK service threads must be exhaustively verified | code review |
| **U14** (medium) | other readers of `mp_ncpus`: `lib/ff_ng_base.c:3249 numthreads = mp_ncpus;` (netgraph), `lib/ff_kern_timeout.c:1212-1216` (print only) | code review |
| **U15** (low) | DPCPU path: `dpcpu_init()` is defined only at `freebsd/kern/subr_pcpu.c:100`; no callers in `lib/` or `freebsd/kern/` (other dirs not exhaustively checked); but `pcpu_destroy():276` still writes `dpcpu_off[pc_cpuid]`, so it is still bound by U9's `MAXCPU` consistency constraint | code review |

---

## 3. Milestones and Gates

>Gate rules: any phase failure → **bounce back to the previous step for fix**; same step bounces up to **3 times**, beyond which stop and escalate to human decision; "remaining items" pass-with-disease not allowed. The leader maintains a bounce counter.

| Milestone | Content | Owner | Deliverable | Gate (must be a different agent) |
|---|---|---|---|---|
| **M0** | this plan.md written | leader (write) | this file | `gate-plan` (subagent reviews plan completeness and convention coverage) |
| **M1** | three parallel research tracks:<br>A code-path exhaustive probing (U1/U2/U4~U8 + U9~U15 + `git show b90ddcba5`)<br>B external-material cross-research<br>C dual-candidate route compile-feasibility evidence (U3, and separately register the HEAD-baseline warning count) | subagents `res-code`, `res-web`, `res-build` | `_m17_A_codepath.md` (**must fill in U1~U15 item by item; missing items fail the gate**), `_m17_B_external.md`, `_m17_C_buildprobe.md` | leader aggregation + `gate-design` re-checks the evidence chain |
| **M2** | solution verdict (B vs A) + detailed design → spec doc 17 | subagent `designer` (write) | `17-SMP-aware-pcpu视图与去全局锁.md` | subagent `gate-design` (reviews: evidence chain, file:line, boundary wording) |
| **M3** | coding milestone 1 (G1): SMP-aware per-cpu view + dense index; `make clean` then full build | subagent `coder` (write) | `lib/` code changes + clean-build-pass record | subagent `reviewer` (concurrency/memory/regression/comment conventions) |
| **M4** | coding milestone 2 (G2): remove `uma_crit_lock`; `make clean` then full build | subagent `coder` | `lib/` code changes + clean-build record | subagent `reviewer` |
| **M5** | runtime validation matrix (incl. pre/post-lock-removal throughput comparison) | subagent `tester` (different from coder) | `_m17_E_runtime.md` measured raw data | subagent `reviewer` re-checks data credibility (if the leader takes over test execution, data re-check must spawn a new subagent) |
| **M6** | doc finalization (backfill verdict/measurement/residual risks into spec 17) | subagent `designer` | updated doc 17 | subagent `gate-doc` (verifies each `file:line` and wording does not overstep the evidence boundary) |
| **M7** | local commit (G1/G2 two separate commits; English 1-3 sentences; `config.ini` local test values not committed) | leader | git commit | gate = `gate-doc` (re-checks commit scope and `git diff`); leader's own diff review is only a pre-commit self-check, not counted as a gate |

### 3.1 Role-Separation Iron Rule Implementation

- **Writer vs reviewer must be different agents**: `designer`↔`gate-design`/`gate-doc`; `coder`↔`reviewer`; `tester` differs from `coder`.
- The leader only handles **pure research/probing/aggregation/execution** (e.g. git operations, process start/stop, data aggregation); **if the leader takes over any "write", its review must spawn a new subagent**.
- M0: leader writes the plan → must be reviewed by subagent `gate-plan` (no leader self-review).

### 3.2 Timeout and Out-of-Band Probing Mechanism

- each subagent gets a minute-level timeout; the leader polls progress via `send_message` on a schedule.
- **Out-of-band probing first**: when messages are unanswered, directly read files the subagent should have produced (`docs/native_mt_spec/zh_cn/_m17_*.md`), `git status`, build artifact `lib/libfstack.a` mtime, log line counts, to judge whether it is actually running or abnormal.
- Exception fallback: ① leader takes over (subsequent review must spawn a new subagent); ② spawn a new subagent to re-run (the new agent's role must not overlap with the downstream review agent); ③ escalate per bounce≤3 to human.

---

## 4. Mandatory Conventions (checked per-phase gate item by item)

1. Deleting files must use `/data/workspace/rm_tmp_file.sh`; terminating processes must use `/data/workspace/kill_process.sh`; changing permissions must use `/data/workspace/chmod_modify.sh`. **Any shell command string (including comments and ssh remote commands) must not contain `rm`/`kill`/`pkill`/`killall`/`chmod`**. `make install`-type allowed.
2. After every code change, run `make clean` then a full rebuild (`lib/` and `example/` both), strictly no incremental builds; clean-build pass is the compile-validation basis.
3. `lib/` only very necessary comments; no long essays; no comments on self-explanatory code.
4. Commit message in English, 1-3 sentences; `config.ini`'s local test changes (`thread_mode`/`lcore_mask`/IP etc.) **not committed**; must review `git diff` before `git add`.
5. All actions actually executed; giving results without execution forbidden; code cross-validated against docs/external material; **actual code wins on conflict**.
6. agent team: leader must not exit early before all subagents finish; must have timeout + scheduled polling + out-of-band probing; exceptions must fall back; writer/reviewer must be different agents; gate failure bounces back to the previous step, same step max 3 times.
7. External research must give verifiable links; if not found, honestly write "no reliable source found"; **fabrication forbidden**.

---

## 5. Runtime Validation Environment (Verified Usable)

- This machine has dual NICs; the DPDK-exclusive NIC IP `9.134.214.176`; load testing must `ssh f-stack-client` then hit that IP with `/data/wrk/wrk`; kernel-stack testing uses `127.0.0.1`.
- Test program `/data/workspace/f-stack/example/helloworld`, config `/data/workspace/f-stack/config.ini`.
- Pitfalls hit last round (carried over):
  - a process launched by `(nohup ... &)` in a subshell gets reaped; must `setsid nohup ... < /dev/null &` for full detachment;
  - launching a secondary process must use an absolute path (`setsid` changes cwd semantics);
  - logs append to `example/helloworld.log`, `example/f-stack-0.log`; to read new content, first record the old line count then `tail -n +N`;
  - core dump is disabled (`/proc/sys/kernel/core_pattern`); catching crashes requires `setsid gdb -q -x <cmdfile>` under load.

### 5.1 Performance Regression Comparison Baseline (last round's measurement, same machine same client)

| Scenario | req/s |
|---|---|
| `thread_mode=1` 2 threads | 233,380 / 234,084 / 230,510 |
| `thread_mode=1` 1 thread | 209,483 / 209,739 |
| `thread_mode=0` 1 process | 209,946 / 209,367 |
| `thread_mode=0` 2 processes | 234,613 / 233,982 |
| 60s/400-connection soak | 497,043 req/s, 29.83M requests, zero socket errors, process alive |

---

## 6. Acceptance Criteria (Definition of Done)

- **DoD-1**: per-CPU slots truly isolated; **judgment means and formula**: add temporary probes in `ff_pcpu_thread_init()` printing `tid / dense_idx / pcpup->pc_cpuid / pcpup->pc_zpcpu_offset / mp_maxid`, and at SMR usage points print each worker's `&zpcpu_get(ipi_smr)->c_seq`; criteria: ① each worker's `pc_zpcpu_offset == 4096 * dense_idx` and `dense_idx <= mp_maxid`; ② pairwise `c_seq` address difference `== 4096 * Δidx` and all fall within `[base, base + (mp_maxid+1)*4096)`; ③ evidence taken from `example/helloworld.log` and written to `_m17_E_runtime.md`; probes removed after M5 or converted to `ff_log`.
- **DoD-2**: `uma_crit_lock` removed from `lib/` (or argue it cannot be removed with code-level basis + `reviewer` gate confirmation).
- **DoD-3**: `lib/` and `example/` clean build zero errors; **warning baseline = clean-build warning count of unchanged HEAD `ff09a17b2`'s `lib/`+`example/`** (M1-C measured `lib/` at 51 warnings; must be registered separately from candidate-route experiment warnings); must not increase after changes.
- **DoD-4**: 1/2/4-thread matrix + 60s soak all zero crashes, zero socket errors; `thread_mode=0` zero regression (throughput fluctuation vs baseline ≤5%).
- **DoD-5**: pre/post-lock-removal throughput comparison data recorded; **threshold**: post-removal throughput must not be lower than pre-removal (same machine same client, ≥3 rounds median, ±2% noise allowed); if no improvement, must still give a code-level conclusion explaining G2's correctness benefit, with `reviewer` gate confirming whether to keep the change.
- **DoD-6**: all conclusions in spec doc 17 backed by `file:line` or measured data; residual risks honestly recorded.
- **DoD-7**: two commits landed; `config.ini` local test values not committed (`git status` currently shows `M config.ini`; must review item by item and roll back local test values before committing).
- **DoD-8**: this round's temporary artifacts in the repo (`lib/_m17_probe_u1.c`, root `_m17_*.log`/`_m17_*.txt`/`_m17_uma_core.i` etc.) cleaned via `/data/workspace/rm_tmp_file.sh` before M7 or confirmed not committed.
