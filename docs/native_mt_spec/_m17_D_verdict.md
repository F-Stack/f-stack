# _m17_D: Leader Solution Verdict Record (M1 → M2)

> This document is the leader's route verdict based on the **measured evidence** of M1's three research tracks, serving as design input for M2's `designer` and the review baseline for `gate-design`.
> All bases point to M1 deliverable documents and `file:line`; anything not measured is explicitly marked.

Verdict time: 2026-08-04, HEAD: `ff09a17b2`, worktree state: M1-C probes restored by the leader; `lib/`, `freebsd/`, `example/` have no tracked-file changes.

---

## 1. Verdict: Adopt **Candidate A (whole-tree `-DSMP`)**

### 1.1 Decisive Bases (all measured/code-verified)

| Dimension | Candidate A | Candidate B | Source |
|---|---|---|---|
| Compile cost | **measured**: only 1 stub needed (`smp_topo`); `error 0`, `warning 51` (= HEAD baseline 51, zero new); both `lib` + `example` clean-builds pass, `helloworld` binary produced | **no compile numbers** (probes blocked by the `git checkout` gate; honestly recorded) | `_m17_C_buildprobe.md` §2.2/2.3/2.4 |
| Change surface | `lib/` 2 files, 2 sites; **upstream `freebsd/` tree 0 sites** | `lib/` 2 files + **upstream `freebsd/vm/uma_core.c` 4 sites** (`:2546`/`:3498`/`:3508`/`:3526`), strongly coupled; missing one produces no compile error | same §3.2/3.3 |
| Per-slot path consistency | `uma_core.c:2546/3498/3508/3526`, `subr_pcpu.c:252`'s SMP branches **automatically consistent** | must manually release each site; missing one = dirty memory/OOB | same |
| Spin-lock semantics risk | **disproven**: `lib/include/sys/mutex.h:31-48` `#undef`s all spin-lock macros after `#include_next`; `:59-76` redefines to `DO_NOTHING`/constant 1; definitions and callers of `spinlock_enter/exit` are all in `.c` not in SRCS → `-DSMP` is **semantically neutral** at the spin-lock layer | equally neutral | `_m17_gate_plan.md` §8.2 |
| `smp_topo` stub safety | **verified safe**: `tcp_hpts.c:1867-1871` already has `#else cpu_top = NULL`; `:1890 if (cpu_top == NULL) grp_cnt = 1`; `:1565 if (grp_cnt > 1)` only then dereferences `grps[]`; `:2095`'s `free(grps)` only on the module-unload path | — | leader measured (`tcp_hpts.c:1855-1935`, `:1548-1590`, `:2093-2097`) |
| Incidental correctness gain | `ck_md.h:95CK_MD_UMP` invalidated → CK **RMW** primitives regain the `lock` prefix. The only substantively affected TU is `ip_fw_dynamic.c` (`ck_pr_inc_32/dec_32/or_32/xor_32`); `ck_queue.h`/`net/if.c` all load/store unaffected; `ck_epoch` already stubbed by `ff_glue.c:1366-1404` | none | `_m17_gate_plan.md` §8.3 |
| Main cost | `sizeof(cpuset_t)` 8→**128** bytes, `cpuid_to_pcpu[]`/`dpcpu_off[]` 1→1024 slots, `netisr.c` several `malloc(...*MAXCPU)` (**pure BSS/heap growth, not a correctness issue**); CK `lock` prefix has a perf cost, to be quantified at M5 | slot count controllable (64) | `_m17_C_buildprobe.md` §0.3/2.4 |
| Upstream diff maintenance cost | low (high weight in the 13.0→15.0 upgrade context) | high | leader judgment |

### 1.2 Verdict Reasons

1. Candidate A's cost was **measured** to disprove plan §0.3's pessimistic prediction (predicted "many stubs needed"; measured **only 1**, and that stub returning `NULL` is **verbatim-equivalent** to upstream's `#else` branch).
2. Candidate B, marked "minimal intrusion" by the plan, **is actually more intrusive**: it must change upstream `uma_core.c` at 4 strongly-coupled sites. In the FreeBSD 13.0→15.0 upgrade project context, zero upstream-tree patches carry high weight.
3. Candidate A makes all `#ifdef SMP` per-slot paths self-consistent at once, avoiding candidate B's high risk of "missing one change = silent memory corruption".
4. Incidental fix of the potential atomicity defect of CK RMW lacking the `lock` prefix (zero cost, correct direction).

### 1.3 Honest Boundaries (must be relayed when M2 cites them)

- **Candidate B has no compile numbers**; its conclusions are code-review-level only; if a fallback to B is needed in the future, compile evidence must first be obtained.
- Candidate A's **runtime** behavior (whether slots are truly isolated, whether `uma_crit_lock` can be removed, throughput changes) is all unverified; M3/M5 must measure.
- The probe code must **not** directly sediment into product code: M3 implements it formally via `coder` under the `reviewer` gate (`_m17_gate_plan.md` §8.6-3).
- The **downgrade step** of `MAXCPU=1024` (internal to candidate A, still not touching the upstream tree): `-DSMP` + `#define MAXCPU 64` in `lib/opt/opt_global.h` (`freebsd/amd64/include/param.h:61-63`'s SMP branch carries `#ifndef MAXCPU` protection). Only enabled when M5 shows the cost unacceptable.

---

## 2. Mandatory Design Constraints for M2 (D constraints, all with measured bases)

| # | Constraint | Basis |
|---|---|---|
| **D1** | `MAXCPU ≥ N` (N = `nb_threads`) is G1's **hard precondition**: `subr_pcpu.c:77 cpuid_to_pcpu[MAXCPU]` gets written OOB at `:91` and overwrites the adjacent `cpuhead` (`:88`'s `KASSERT` compiled out because no `INVARIANTS`); `ff_kern_timeout.c:730 cpu >= MAXCPU` panics; `ff_kern_synch.c:59 pause_wchan[MAXCPU]` takes an OOB address (UB). Candidate A satisfies this automatically via `-DSMP` | `_m17_A_codepath.md` U9 |
| **D2** | **`mp_ncpus` / `mp_maxid` / `all_cpus` must be set together as a triple**, all before `ff_freebsd_init.c:301 uma_startup1()`. Reasons: ① `uma_core.c:3179-3182`'s zone size includes `sizeof(uma_cache)*(mp_maxid+1)`, fixed once at `uma_startup1`; changing `mp_maxid` afterward is a heap OOB; ② `subr_smr.c:598-605 smr_create()` writes per-slot by `mp_maxid`; ③ **`ip_fw_dynamic.c:3236 malloc(mp_ncpus * sizeof(void*))` and `:2086-2091 CPU_FOREACH(i){ dyn_hp_cache[cached_count++] = ... }` use different size/upper-bound bases** — raising only `mp_maxid`+`all_cpus` without `mp_ncpus` is a **heap overflow** (`FF_IPFW=1` compiled) | `_m17_A_codepath.md` U10; `_m17_gate_plan.md` §8.4 |
| **D3** | the dense number **uses an existing field**: `ff_dpdk_if.c:429-433 lc->proc_id = ti` (`ti` is `0..nb_threads-1`); workers take `ff_cur_lcore_conf()->proc_id` (`ff_memory.h:104-111`); `ff_dpdk_if.c:2649` changes `rte_lcore_id()` to the dense number, **landing as `ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0)`** (under thread_mode=0, `lcore_conf[0].proc_id` is the process number and must be gated, see `_m17_gate_design.md` E2); `ff_pcpu_thread_init()` must actually use the parameter (the original `:107` always passes 0) | `_m17_A_codepath.md` U6.1 |
| **D4** | the **main thread's slot must not collide with workers'**, and **do not rely on the unverified inference "EAL main lcore == `proc_lcore[0]`"** (`--main-lcore` can break it). Suggest the main thread also number by `proc_id`; `ff_freebsd_init.c:293`'s hardcoded 0 needs corresponding handling. `:294 CPU_SET(0,&all_cpus)` must expand to `0..N-1` | `_m17_A_codepath.md` U6.2 (incl. unverified item U6-a) |
| **D5** | `ff_kern_timeout.c:190 static int timeout_cpu;` must become `static __thread`: it is a matched pair with `:183 __thread struct callout_cpu cc_cpu` but missed `__thread`; `:254` is written by every thread; `:1061/:1077` would write another thread's cpuid into `c->c_cpu`; `:815 callout_schedule()` passes it back as cpu to the `:730` check | `_m17_A_codepath.md` U11 |
| **D6** | `ff_pcpu_thread_init()` should add a **runtime** upper-bound check (`cpuid <= mp_maxid` / `< mp_ncpus`), failing with `rte_exit`/`panic` — because `subr_pcpu.c:88`'s `KASSERT` is compiled out. libuinet's `uinet_pcpu_get()` does exactly `KASSERT(td_oncpu < mp_ncpus)` at the only slot-access entry | `_m17_B_external.md` §3.1(b)(i) |
| **D7** | `thread_mode=0` (multi-process) must be **zero regression**: with `nb_threads == 0` keep `mp_maxid=0`, `mp_ncpus=1`, `all_cpus` only bit 0 | `_m17_A_codepath.md` U6.2 |
| **D8** | G2's (removing `uma_crit_lock`) **real context**: ① `critical_enter/exit` are **already no-ops** in f-stack except for UMA TUs (`systm.h:186 #ifndef FSTACK`), `smr_enter()` was never protected by this lock → removing the lock **does not weaken any existing SMR protection**; ② **UMA's `ZONE_LOCK`/`ZDOM_LOCK`/`KEG_LOCK` and all `mtx` are already `((void)0)` in f-stack** (`lib/include/sys/mutex.h:57-85`; `kern_mutex.c` not in SRCS) → the zone/keg slow path **was always lock-free**; ③ but the global lock **practically compresses the slow-path concurrency window**; after removal, the contention window of `zdom`/keg/`uma_page` hash (`lib/include/vm/uma_int.h:105-126 vsetzoneslab`'s `LIST_INSERT_HEAD` also lock-free) enlarges. **`designer` must rule among G2-a (remove lock + add real locks to zone/keg) / G2-b (only remove lock + load-test validation, honestly recording residual risk) / G2-c (shrink the lock scope), with reasons**; also note the libuinet intermediate form "one lock per-cpu" rather than one global | `_m17_A_codepath.md` U7/U8; `_m17_B_external.md` §3.1(a) |
| **D9** | app threads created by `ff_pthread_create()` (`ff_thread.c:32-46`) have `__thread pcpup == NULL` (don't call `ff_pcpu_thread_init`); calling any `ff_*` dereferences NULL. **Must be clearly stated in the spec as "unsupported usage"**, or supported as a separate project via the "reserve K slots" scheme (which conflicts with D2's "`mp_maxid` must be finalized before `uma_startup1`", needs a config item) | `_m17_A_codepath.md` U13 |

## 3. Known Deviations / Residual Risks That Must Be Honestly Recorded in the Spec (not this round's fix targets)

1. **counter(9) has been de-per-CPU-ized** (`lib/include/amd64/include/counter.h:38-62`): multi-thread writes to the same slot (stat contention), fetch only reads slot 0 → stats inaccurate, **not a memory-safety issue**.
2. **`cache_drain_safe()`** (`uma_core.c:1497-1509`): `sched_bind()` is a stub (HEAD `ff_glue.c:1178`); after `mp_maxid>0`, that loop **drains the calling thread's own cache N times**, and other threads' caches are not reclaimed → only a reclamation-efficiency issue.
3. **ipfw DPCPU hazard pointer already invalid**: `dpcpu_init()` has no callers anywhere, `dpcpu_off[]` always 0 → all cpu DPCPU slots of `ip_fw_dynamic.c:224-226` **alias each other**; multiple workers share one HP slot. **Candidate A cannot fix this**; must be recorded (U15's severity raised from "low" to "medium").
4. **NUMA undefined** (`vm_ndomains = 1`, `ff_glue.c:83`) → all `#ifdef NUMA` cross-domain bucket paths in `uma_core.c` are not compiled, `uc_crossbucket` never loaded → only "cross-thread" needs handling, not "cross-domain".
5. **netisr swi / taskqueue / kproc / netgraph ngthread / so_splice do not create real threads** (`ff_kern_intr.c:84-107`, `ff_compat.c:162-177` all empty stubs) → the "each thread exclusively owns a slot" premise holds under standard usage.
6. **U6-a not verified**: "EAL main lcore == `proc_lcore[0]`" is a DPDK default-behavior inference; M5 must print `rte_get_main_lcore()`/`rte_lcore_id()`/`proc_id`/`pc_zpcpu_offset` to check (DoD-1 already includes it).

## 4. External Cross-Validation Key Points (consistent with code; code wins)

- **SMR's per-CPU `c_seq` slot exclusivity** is an upstream hard assumption; sharing causes early grace-period termination → UAF; and upstream has no standalone design document — the `subr_smr.c` top comment is authoritative (`_m17_B_external.md` §2.1/2.6).
- **libuinet** (FreeBSD 9.1 userspace stack) is an isomorphic existing implementation of candidate B: does not define `SMP`, `pcpu_init(&pcpup[i], i, ...)` with dense index, `CPU_SET(i,&all_cpus)` loop, per-CPU storage slotted by `mp_ncpus`, and keeps `uinet_pcpu_locks[MAXCPU]` (**one lock per-cpu**, comment `XXX temporary until final pcpu approach is determined`). **But libuinet has no SMR** (9.1 era); no precedent exists at the SMR layer (§3.1).
- **rump kernel** (NetBSD)'s "virtual CPU exclusively held by a thread" supports the thesis "thread-exclusive slots ≥ disabling preemption" (§3.2); Seastar/ANS are shared-nothing precedents (§3.3/3.4).
- **No reliable source found** (honestly recorded, no fabrication): f-stack community has no SMR/pcpu/-DSMP discussion; the mTCP paper original and OpenFastPath official design document were not obtained; "userspace multi-thread shared SMR slot causing UAF" has no public incident report (reasonable explanation: almost no other project ports FreeBSD 13+'s SMR into userspace multi-thread) (§1.4/§3.5).
