# 17 SMP-aware pcpu Views and Global-Lock Removal

> **Doc ID**: SPEC-NMT-17
> **Version**: v1 (M2 design draft)
> **Date**: 2026-08-04
> **Nature**: design specification (spec, not a patch). This document only defines "what to change, why, and how to verify"; it does not give the full patch text.
> **Code-fact baseline**: `git HEAD = ff09a17b2` (`/data/workspace/f-stack`). Reference trees `/data/workspace/freebsd-src-releng-15.0`, `/data/workspace/dpdk-stable-24.11.6`, comparison tree `/data/workspace/f-stack-13.0-baseline`.
> **Upstream source**: `16-multiqueue-comparison-experiment-and-root-cause-correction.md` §8.1 (residual-risk registration).
> **Input docs**: `plan-17-smp-aware-pcpu-smr.md` (task definition/U1~U15/DoD), `_m17_A_codepath.md` (M1-A code-path exhaustive probing), `_m17_B_external.md` (M1-B external cross-check), `_m17_C_buildprobe.md` (M1-C compile evidence), `_m17_gate_plan.md` (plan gate + §8 candidate-A semantic-risk independent verification), `_m17_D_verdict.md` (leader route verdict + D1~D9).

---

## 0. Reading Conventions and Writing Boundaries

### 0.1 Evidence-Strength Markers

Every fact in this document must fall into one of the following three levels; **unmarked assertions are not allowed**:

| Marker | Meaning |
|---|---|
| **【Code-verified】** | Confirmed by actually opening `file:line`, or directly proven by preprocessor/compile/link output |
| **【Measured】** | Has command output/compile numbers/run logs |
| **【Not-verified】** | Static inference or depends on runtime data; **must not be used as a verified fact**, must note the verification means and owning milestone |

### 0.2 Writing-Period Workspace State Declaration (important, for `gate-design` to check line numbers)

- All `file:line` in this document **follow HEAD `ff09a17b2`**.
- During the writing period (2026-08-04), the workspace's `lib/` contains **someone else's (M3 `coder`) in-progress G1 changes**: `git diff --stat -- lib/` measured as `lib/Makefile |4 ++++`, `lib/ff_dpdk_if.c | 8 +++++++-`, `lib/ff_dpdk_if.h | 1 +`, `lib/ff_freebsd_init.c | 48 ++++++++++---------`, `lib/ff_glue.c | 7 +++++++`, `lib/ff_kern_timeout.c | 2 +-`. **【Measured】**
- Therefore `lib/ff_dpdk_if.c`'s workspace line numbers are **+6 offset from HEAD** (the workspace inserted 6 lines of `ff_cur_proc_id()` after `:409`). References such as `ff_dpdk_if.c:2649`/`:2644`/`:2794`/`:2857` in this document are all **HEAD line numbers**.
- The author (`designer`) of this document **modified no source code**; the only file written is this document; all verification was read-only (`read_file` / `grep` / `cc -E` output to stdout only), **no `make` run, no temporary files created**.

### 0.3 This Document's Corrections to the M1 Docs (C1~C3 see §2.3 / §4.3.4 / §6.5; C4 = 4 `file:line` corrections, see §6.21-2)

| # | M1 doc original statement | This doc's correction (actual code wins) |
|---|---|---|
| **C1** | `_m17_A_codepath.md` §7.3: "`curcpu = PCPU_GET(cpuid) = pcpup->pc_cpuid` is a **thread-private constant**" | **Wrong.** `lib/include/sys/pcpu.h:32-34` `#undef curcpu` + `#define curcpu 0` hardcodes `curcpu` to the literal `0`, overriding `freebsd/sys/pcpu.h:218#define curcpu PCPU_GET(cpuid)`. → **UMA per-CPU cache does not go through the `zpcpu` offset; it goes through `uz_cpu[curcpu]`, so G1's dense `pc_cpuid` alone cannot isolate the UMA cache.** See §2.3 |
| **C2** | `_m17_A_codepath.md` §6.2 / `_m17_D_verdict.md` D4: suggested "main thread also takes the number via `proc_id`" | **Must add `thread_mode` gating.** `lib/ff_dpdk_if.c:460ff_cur_lcore_conf()->proc_id = ff_global_cfg.dpdk.proc_id;`【Code-verified】→ in `thread_mode=0`, a secondary process's `proc_id` is **1, 2, …** (not 0). Using `proc_id` without gating makes a multi-process secondary get `cpuid=1` while its `mp_maxid=0` → out of bounds, **breaking D7 zero regression**. See §4.3.4 |
| **C3** | `_m17_A_codepath.md` U9 #4: `lib/ff_kern_synch.c:59 pause_wchan[MAXCPU]` indexed by `curcpu` "takes address out of bounds (UB)" | **Must be restated conditionally.** Due to C1, `pause_wchan[curcpu]` (`:105`) **today is always `pause_wchan[0]`; no out-of-bounds exists**; out-of-bounds could only occur **after** this round makes `curcpu` per-thread, and candidate A's `MAXCPU=1024` already eliminates it. Severity unchanged (still needs `MAXCPU ≥ N`), but the causal chain must be written correctly |

### 0.4 One M1 Not-Verified Item Closed by This Document

**U16-a (whether `tcp_hpts` is genuinely active in f-stack) = active, closed.** 【Code-verified】 Evidence chain:

1. `lib/ff_dpdk_if.c:2794` calls `ff_tcp_hpts_softclock();` **unconditionally** in `main_loop` (comment `:2789-2793` explicitly says "f-stack has no userret to call it, and the hpts swi thread is a no-op").
2. `lib/ff_kern_timeout.c:1291-1296` `ff_tcp_hpts_softclock()` = `if (tcp_hpts_softclock != NULL) tcp_hpts_softclock();`.
3. `freebsd/netinet/tcp_hpts.c:2061 tcp_hpts_softclock = __tcp_run_hpts;` (inside `tcp_hpts_mod_load()`, `:1853`).
4. `freebsd/netinet/tcp_hpts.c:2142 DECLARE_MODULE(tcphpts, tcp_hpts_module, SI_SUB_SOFTINTR, SI_ORDER_ANY);` + `:2117-2118 case MOD_LOAD: tcp_hpts_mod_load();`; `freebsd/kern/kern_module.c:106-107 module_register_init()` (`:106` is the return-type line `void`, `:107` the function-name line) participates in compilation (`lib/Makefile` HEAD **`:347`** lists `kern_module.c`; with the M3 changes it is `:351` in the workspace — the `:351` gate-design reported is the workspace line, not conflicting with this doc's HEAD baseline), `lib/kern_module.o` exists → executed within `mi_startup()` (`lib/ff_freebsd_init.c:309`).

→ **Every worker's `main_loop` drives hpts**, so "N workers contending for one hpts instance" is not a paper risk. This directly supports the §4.3.2 verdict: **`mp_ncpus` must be raised to N in sync with `mp_maxid`**.

---

## 1. Background and Problem Statement

### 1.1 Upstream Source

`16-multiqueue-comparison-experiment-and-root-cause-correction.md` §8.1 registered a residual risk while fixing the native-mt multi-queue crash; original text (`:270-275`) key points:

> After the R2 fix, all workers' `pc_zpcpu_offset` is 0, so multiple workers **share the same** SMR per-CPU slot. Theoretical window: thread A's `smr_exit` setting `SMR_SEQ_INVALID` could clear thread B's read-section marker → `smr_poll` wrongly concludes no readers → PCB recycled early (UAF). …Full elimination requires making the f-stack kernel view SMP-aware (`mp_maxid > 0` + truly allocating per-CPU arrays by thread count), **recommended as a separate project**.

This document is the design spec of that separate project.

### 1.2 Three-State Evolution (Must Understand "Pre-fix guaranteed OOB / Post-fix legal but shared / Target exclusive")

| Stage | commit | cpuid to `pcpu_init()` | `MAXCPU`/`mp_maxid` | per-CPU slot state | Observed symptom |
|---|---|---|---|---|---|
| **T0 pre-fix** | `b90ddcba5` | `rte_lcore_id()` (sparse, can be 2) | 1 / 0 | **Guaranteed OOB**: `cpuid_to_pcpu[2]` crosses `cpuid_to_pcpu[MAXCPU=1]` (`freebsd/kern/subr_pcpu.c:77,91`); `pc_zpcpu_offset = 4096*2` crosses a zone allocated for only 1 CPU | **【Measured, doc-16 §1.2 R2】** `in_pcblookup_mbuf` SIGSEGV under load |
| **T1 current HEAD** | `ff09a17b2` | always `0` (`lib/ff_freebsd_init.c:107`) | 1 / 0 | **Legal but shared**: all threads `pc_zpcpu_offset == 0` → share the same SMR `c_seq` slot and the same `uz_cpu[0]` | No crash (60s/400-connection soak 497k req/s zero errors, doc-16 §8.1-3), but **the static UAF window objectively exists** |
| **T2 this round's goal** | this design | dense `0..N-1` | ≥N / N-1 | **Per-thread exclusive**: `pc_zpcpu_offset == 4096*i`, `uz_cpu[i]` thread-private | to be verified at M5 (DoD-1) |

**T1 is a strict improvement over T0** (legal access vs OOB access) — this must not be weakened in the text; but T1 still violates SMR's core invariant (§2.2), so it must advance to T2.

### 1.3 This Round's Goals

| Goal | Content | Milestone/commit |
|---|---|---|
| **G1** | Make the f-stack kernel view SMP-aware: each stack thread has a dense, independent pcpu slot; UMA/SMR per-CPU storage is slotted by thread count; **and make `curcpu` resolve to this thread** (new necessary condition from §2.3). Completely eliminate the theoretical UAF window of shared SMR slots and the race on shared `uz_cpu[0]` | M3 / commit-1 |
| **G2** | After slots are truly isolated, remove the data-plane global spinlock `uma_crit_lock` (`lib/include/vm/uma_int.h:45-52`), restoring the lock-free fast path of the UMA per-CPU cache | M4 / commit-2 (**independent commit, separately revertible**) |

**G1 → G2 is a hard dependency and the order is not swappable**: G2's correctness is entirely built on G1's invariant "each thread exclusively owns `uz_cpu[i]`" (§2.4, §4.7).

---

## 2. Code-Level Mechanism of the Problem

### 2.1 pcpu Slot Location Chain

**【Code-verified】** Full chain (HEAD line numbers):

```
lib/ff_freebsd_init.c:106   pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);   /* __thread, :85 */
lib/ff_freebsd_init.c:107   pcpu_init(pcpup, 0, sizeof(struct pcpu));               /* ★ the cpuid param is deliberately ignored */
freebsd/kern/subr_pcpu.c:90   pcpu->pc_cpuid = cpuid;
freebsd/kern/subr_pcpu.c:91   cpuid_to_pcpu[cpuid] = pcpu;                          /* array size MAXCPU, :77 */
freebsd/kern/subr_pcpu.c:92   STAILQ_INSERT_TAIL(&cpuhead, pcpu, pc_allcpu);        /* shared list, :78 */
freebsd/kern/subr_pcpu.c:96   pcpu->pc_zpcpu_offset = zpcpu_offset_cpu(cpuid);
```

Key macros' **final expansion values** (M1-A U1 measured with `gcc -E`; this doc cross-confirms the definition chain):

| Macro | Expansion | Value |
|---|---|---|
| `MAXCPU` | `freebsd/amd64/include/param.h:65` (`#else` branch **unconditionally** `#define MAXCPU 1`) | **1** |
| `UMA_PCPU_ALLOC_SIZE` | `freebsd/sys/pcpu.h:221` = `PAGE_SIZE` = `freebsd/amd64/include/param.h:92-93` `(1<<12)` | **4096** |
| `zpcpu_offset_cpu(cpu)` | `freebsd/sys/pcpu.h:235` (`:234 #ifndef` holds, because `lib/include/amd64/include/pcpu.h:40 #undef zpcpu_offset_cpu`) | **`4096 * cpu`** |
| `zpcpu_get(base)` | `freebsd/sys/pcpu.h:249-252` → `base + pcpup->pc_zpcpu_offset` | — |
| `PCPU_GET(m)` | `lib/include/amd64/include/pcpu.h:49` | `pcpup->pc_## m` |
| **`curcpu`** | **`lib/include/sys/pcpu.h:34`** | **literal `0` (see §2.3)** |

→ Because `lib/ff_freebsd_init.c:107` always passes 0, **every thread's `pc_zpcpu_offset` is 0**, and `zpcpu_get(x)` returns the same address for every thread.

### 2.2 Why Shared SMR Slots Constitute a UAF

**Upstream semantics (`_m17_B_external.md` §2.1 / §2.6, source text verifiable)**:

- `struct smr`'s `c_seq` has only two states "0(`SMR_SEQ_INVALID`) / non-0", **no nesting counter**; `smr_enter()` has `KASSERT(smr->c_seq == 0, "does not support recursion")`. f-stack **does not define `INVARIANTS`** (M1-A U1【Measured】), so that assertion **is compiled out** and corruption happens silently.
- `smr_exit()` **unconditionally** `atomic_store_rel_int(&smr->c_seq, SMR_SEQ_INVALID)`, without checking "was it me who entered".
- `smr_poll_cpu()`: `if (c_seq == SMR_SEQ_INVALID) break;` → that CPU is judged **no active readers**; in `smr_poll_scan()` `if (c_seq != SMR_SEQ_INVALID) rd_seq = SMR_SEQ_MIN(rd_seq, c_seq);` → INVALID slots do not participate in pulling `rd_seq` down.
- The GUS algorithm comment original text (top of `subr_smr.c`; upstream writes the design doc directly in the source): **"cpuB is not running and is considered to observe wr seq."** i.e. GUS's core invariant is "slot INVALID ⟺ no active reader on that CPU".

**Corruption chain under shared slots** (every link has source support; `_m17_B_external.md` §2.1 marked "source-semantics derivation"):

```
worker A: smr_enter()  -> c_seq = S1
worker B: smr_enter()  -> c_seq = S1 + S2 (amd64 goes through atomic_add_acq_int fast path, "accumulate" not "overwrite")
worker A: smr_exit()   -> c_seq = SMR_SEQ_INVALID   (B is still in the read section!)
writer:   smr_poll()   -> that slot INVALID -> judged no readers -> s_rd_seq advances to s_wr_seq
          uma_zfree_smr() judges grace period over -> PCB memory reused
worker B: still holds a pointer to that PCB  ==>  UAF
```

f-stack-side landing point【Code-verified】: `freebsd/netinet/in_pcb.c:583 ipi_smr = uma_zone_get_smr(pcbinfo->ipi_zone);`, `:615-617 uma_zcreate(..., UMA_ZONE_SMR)`; `freebsd/sys/smr.h:110 smr = zpcpu_get(smr);`. This is exactly the lookup path of the T0-stage SIGSEGV function `in_pcblookup_mbuf`.

**Another key existing fact** (M1-A U7 §7.1【Measured】, `cc -E freebsd/kern/subr_smr.c` then `grep -c uma_crit_lock == 0`): `subr_smr.c` does not include `vm/uma_int.h`; its `critical_enter()` comes from `freebsd/sys/systm.h`, where `:186 #ifndef FSTACK` excludes the whole function body → **under f-stack, `critical_enter/exit` themselves are no-ops**. → **The SMR read side today has zero serialization protection; `uma_crit_lock` never protected SMR**. This also shows: G1 is the only way to fix the UAF; G2 has zero impact on SMR.

### 2.3 【New finding this round】UMA per-CPU cache goes through another path: `curcpu`, not the `zpcpu` offset

This is a fact that all three M1 documents missed, but **determines G1's success**.

**（a）f-stack hardcodes `curcpu` to 0**【Code-verified】:

```c
/* lib/include/sys/pcpu.h:31-34 */
#include_next <sys/pcpu.h>
#undef curcpu

#define curcpu    0
```

It overrides upstream's `freebsd/sys/pcpu.h:218 #define curcpu PCPU_GET(cpuid)`. `lib/include/sys/pcpu.h` is indeed read by the preprocessor in real compilation (the 15-file override list measured by `_m17_C_buildprobe.md` §0.2 via the `gcc -M` dependency union of 248 TUs includes it).

**（b）UMA's per-CPU cache is all located by `uz_cpu[curcpu]`**【Code-verified, 11 sites】:
`freebsd/vm/uma_core.c:1452` (`cache_drain_safe_cpu`), `:3738`, `:3776`, `:3818`, `:3901`, `:4534`, `:4543`, `:4595`, `:4628`, `:4803`, `:4853` are all `cache = &zone->uz_cpu[curcpu];`.

**（c）Preprocessor cross-confirmation of final expansion**【Code-verified】: during the writing period, using the real compile flags transcribed from `_m17_A_codepath.md` §0, a **read-only** `cc -E` was run on `freebsd/vm/uma_core.c` (stdout only, no `make`); the **corresponding line in the output**:

```
cache = &zone->uz_cpu[0];
```

（**The preprocessor output's line numbers vary with compile flags and include expansion, and are not reproducible evidence, so they are not listed here.** What is reproducible: anyone re-running `cc -E` with the §0 flags of `_m17_A_codepath.md` should see `uz_cpu[0]`, not `uz_cpu[curcpu]`.)

The same output also verified `ZDOM_GET` expands to `(&((uma_zone_domain_t)&(zone)->uz_cpu[mp_maxid + 1])[domain])` (corresponding to `freebsd/vm/uma_int.h:529`), consistent with M1-A U4.1's "hard constraint H1".

> **Evidence-strength note (E6)**: that preprocessor artifact `_m17_uma_core.i` was cleaned per DP-10 and **not saved**, so it **cannot be re-checked afterward**; this item is therefore downgraded to 【Code-verified】 rather than 【Measured】 — its conclusion holds independently without that artifact (`lib/include/sys/pcpu.h:34`'s `#define curcpu 0` + 11 `uz_cpu[curcpu]` sites in `uma_core.c` are both statically verifiable facts), and it was independently verified by `gate-design`.

**（d）Conclusion (G1's necessary conditions are expanded)**:

- The SMR side locates via `zpcpu_get()` (`pc_zpcpu_offset`) → **dense `pc_cpuid` is enough to fix it**.
- The UMA per-CPU cache side locates via `curcpu` → **even with dense `pc_cpuid`, all threads still share `uz_cpu[0]`**.
- Therefore: **if G1 does not also make `curcpu` per-thread, then**
  1. DoD-1's UMA-side isolation criterion cannot pass (each thread's `&zone->uz_cpu[curcpu]` address is identical);
  2. **G2 would put the exact race that `b90ddcba5` fixed right back** — because `uma_crit_lock` is load-bearing today: it masks the race with global serialization precisely on the premise "all threads share `uz_cpu[0]`" (`b90ddcba5` commit message original: "Serialize UMA per-CPU cache access via spinlock in critical_enter/exit … to fix kqueue_kevent memset SIGSEGV at 0 on 2-thread startup", M1-A U7 part 1【Measured】).

→ Design-wise, "make `curcpu` per-thread" is listed as **G1's third mandatory item** (§4.5), alongside "dense `pc_cpuid`" and the "`mp_*` triple".

### 2.4 `uma_crit_lock`'s True Semantics and Scope (G2 argument anchor)

**【Code-verified】**

```c
/* lib/include/vm/uma_int.h:45-52 */
extern volatile int uma_crit_lock;
#define critical_enter() do { while (__sync_lock_test_and_set(&uma_crit_lock, 1)) ; } while(0)
#define critical_exit()  do { __sync_lock_release(&uma_crit_lock); } while(0)
```

| Fact | Basis |
|---|---|
| This macro only affects TUs including `vm/uma_int.h`; among the compile set (248 TUs) only **2** files include it: `freebsd/vm/uma_core.c` (`lib/Makefile:650`) and `lib/ff_freebsd_init.c`; and the latter has `grep -c 'critical_enter\|critical_exit'` = **0** | M1-A U10 §10.3【Measured】+ `_m17_gate_plan.md` §3-4 independently verified |
| → **`uma_crit_lock` in fact acts only on `freebsd/vm/uma_core.c`** | same |
| `critical_enter/exit` in `uma_core.c`: 21 sites total: `:1451,1464,3727,3744,3775,3817,3859,3891,3900,3916,3918,4541,4554,4558,4626,4649,4653,4827,4850,4872,4874` | this doc【Code-verified】 |
| **The slow path is already outside the critical section**: `:3859 critical_exit();` → `:3880 cache_fetch_bucket()` / `:3882 zone_alloc_bucket()`; `:3916 critical_exit();` → `:3917 zone_put_bucket()` → `:3918 critical_enter();`. The upstream comment at `:3867-3874` explicitly says "This requires the zdom lock, so we must drop the critical section" | this doc【Code-verified】, consistent with M1-A U7 §7.3's end |
| **f-stack stubs all of UMA's `mtx` locks to no-ops**: `lib/include/sys/mutex.h:57 #define DO_NOTHING ((void)0)`, `:59-72` define `__mtx_lock/__mtx_unlock/__mtx_lock_spin/__mtx_unlock_spin/_mtx_lock_flags/_mtx_unlock_flags/_mtx_lock_spin_flags/_mtx_unlock_spin_flags/thread_lock*/thread_unlock` all as `DO_NOTHING`, `:74-76` define the trylock family as constant `1`, `:85mtx_owned(m) (1)`; `freebsd/kern/kern_mutex.c` is not in `lib/Makefile` SRCS. → `ZONE_LOCK`/`ZDOM_LOCK`/`KEG_LOCK` preprocess to `((void)0)` | M1-A U8 §8.2【Measured】+ this doc checks `lib/include/sys/mutex.h:55-90` |

**This yields G2's equivalence-argument anchor (consistent with plan §1.4)**:

- Upstream `critical_enter()`'s role is "disable preemption on the same CPU ⇒ `uz_cpu[curcpu]` slot has no second execution flow inside the critical section". f-stack's `uma_crit_lock` is **not** the userspace stand-in for the upstream critical section; it is a global serialization lock added **for the shared `uz_cpu[0]` after `critical_enter` was already nop-ized**.
- So G2's correctness condition is "**each thread exclusively owns `uz_cpu[i]`**", **not** "disable preemption". This invariant is established by G1 (dense `pc_cpuid` + per-thread `curcpu` + 1:1 thread-to-slot binding that never migrates), and is **stronger than the upstream condition** (upstream slots by physical CPU and threads can migrate; f-stack slots by thread and migration is harmless).
- External precedent support (`_m17_B_external.md` §4.2/§4.3): upstream `uma_int.h` original "PCPU caches are protected by critical sections, and **may be accessed safely only from their associated CPU**" lists the "invariant" and the "maintenance means" together; counter(9) on amd64 has `counter_enter()` as a nop (architecture-level precedent); rump kernel's `kpreempt_disabled()` is always true, protecting per-CPU structures by "virtual CPU slots exclusively owned by threads" (long-maintained in the NetBSD tree); Seastar/ANS are industrial shared-nothing precedents. **But external precedents only support the general claim; they do not replace local verification** (same doc §4.2(b) explicitly lists gaps).

### 2.5 Current-State Table: Which Path Each per-CPU Consumer Uses

| Consumer | Location method | T1 (HEAD) actual behavior | After G1 (dense `pc_cpuid` + per-thread `curcpu`) |
|---|---|---|---|
| SMR `c_seq` (`freebsd/sys/smr.h:110`) | `zpcpu_get()` → `pc_zpcpu_offset` | all threads share one slot → **UAF window** | per-thread `4096*i` independent slot → window eliminated |
| SMR create/scan (`subr_smr.c:598-605`, `smr_poll_scan`'s `CPU_FOREACH`) | `zpcpu_get_cpu(smr,i)` + `mp_maxid` / `all_cpus` | initializes/scans only 1 slot | initializes and scans N slots (requires `mp_maxid`+`all_cpus` paired, D2/H4) |
| **UMA per-CPU cache** (11 `uz_cpu[curcpu]` sites in `uma_core.c`) | **`curcpu` (literal 0)** | **all threads share `uz_cpu[0]`**, serialized by `uma_crit_lock` | per-thread `uz_cpu[i]` → lock removable |
| UMA zone/keg slow path (`zdom`/keg/bucket zones) | zone-level shared structures | **lock-free** (all `mtx` stubbed), and outside the critical section | unchanged (not changed this round, see §6.1) |
| f-stack's own `uma_page` reverse hash (`lib/include/vm/uma_int.h:105-126vsetzoneslab`) | global hash table + `LIST_INSERT_HEAD`, **lock-free** | lock-free | unchanged (not changed this round; only G2's downgrade step L1 touches it, see §4.7.4) |
| counter(9) (`lib/include/amd64/include/counter.h:38-62`) | **fully de-per-CPU-ized** (`*c += inc`, only touches slot 0) | stat contention (not memory safety) | unchanged (§5-2) |
| callout (`lib/ff_kern_timeout.c:183-185`) | `__thread struct callout_cpu cc_cpu` + `CC_CPU(cpu)` ignores the argument | already thread-isolated; but `timeout_cpu` (`:190`) missed `__thread` | add `__thread` (D5, §4.6) |
| ipfw DPCPU hazard pointer (`ip_fw_dynamic.c:224-226`) | `DPCPU_PTR` → `dpcpu_off[]` always 0 | **all cpu slots alias each other** (`dpcpu_init()` has no callers) | **cannot be fixed this round** (§6.3) |
| DPDK `rte_mempool` per-lcore cache | `rte_lcore_id()` (**another index space**) | normal | unaffected (§5-5) |

---

## 3. Solution Selection and Verdict Basis

### 3.1 Candidate A vs Candidate B Measured Comparison

The route was already decided by the leader in `_m17_D_verdict.md` §1 as **candidate A (full-tree `-DSMP`)**. This document does not re-argue; it only relays the decisive basis and honestly relays the boundaries.

| Dimension | Candidate A (full-tree `-DSMP`) | Candidate B (no `SMP`, override `MAXCPU` + open upstream `#ifdef SMP`) | Source |
|---|---|---|---|
| Compile cost | **【Measured】** only 1 stub needed (`smp_topo`); `error 0`, `warning 51` (= HEAD baseline 51, **zero new**); `lib` + `example` both clean-build pass; `example/helloworld` binary produced (30,392,616 bytes) | **no compile numbers at all** (probing was blocked by the restore-authorization gate, honestly recorded) | `_m17_C_buildprobe.md` §2.2/§2.3/§3.1 |
| Change surface | `lib/` 2 files 2 sites, **0 sites in upstream `freebsd/` tree** | `lib/` 2 files (incl. new `lib/include/amd64/include/param.h`) + **4 sites in upstream `freebsd/vm/uma_core.c`** (`:2546`/`:3498`/`:3508`/`:3526`), four strongly coupled, a missed one compiles without error | same §3.2/§3.3 |
| Per-slot path consistency | `uma_core.c:2546/3498/3508/3526`, `subr_pcpu.c:252` SMP branches **automatically consistent** | must be manually opened site by site; one miss = dirty memory/OOB | same |
| Spin-lock semantics risk | **disproven, semantically neutral**: `lib/include/sys/mutex.h:31-48` `#undef`s all spin-lock macros after `#include_next`, `:59-76` redefines to `DO_NOTHING`/constant 1; the `.c` files defining and calling `spinlock_enter/exit` are not in SRCS | equally neutral | `_m17_gate_plan.md` §8.2 (independent verification) |
| `smp_topo` stub safety | **verified safe**: `tcp_hpts.c:1867-1871` already has `#else cpu_top = NULL`; `:1890 if (cpu_top == NULL) grp_cnt = 1`; `:1565 if (grp_cnt > 1)` only then dereferences `grps[]`; `:2095`'s `free(grps)` only on the module-unload path | — | `_m17_D_verdict.md` §1.1 (leader measured) |
| Incidental correctness gain | `ck_md.h:95 CK_MD_UMP` fails → CK **RMW** primitives regain the `lock` prefix. The only substantively affected TU is `ip_fw_dynamic.c` (`ck_pr_inc_32/dec_32/or_32/xor_32`); `ck_queue.h`/`net/if.c` are all load/store; `ck_epoch` is already stubbed by `ff_glue.c:1358-1396` (`:1358 ck_epoch_synchronize_wait` … `:1392 ck_epoch_init`); `contrib/ck/src/*.c` not compiled | none | `_m17_gate_plan.md` §8.3 (its cited `:1366-1404` corrected to `:1358-1396` after this doc's HEAD re-check) |
| Main cost | `sizeof(cpuset_t)` 8→**128** bytes; `cpuid_to_pcpu[]`/`dpcpu_off[]` from 1→1024 slots (8 KB each, **pure BSS growth**); several `malloc(...*MAXCPU)` in `netisr.c`; CK `lock` prefix has perf cost, to be quantified at M5 | slot count controllable (64) | `_m17_C_buildprobe.md` §0.3/§2.7 |
| Upstream diff maintenance cost | low (high weight in the 13.0→15.0 upgrade context) | high | leader judgment |

### 3.2 Verdict and Reasons (relayed from `_m17_D_verdict.md` §1.2)

**Route = Candidate A.** Four reasons:

1. Candidate A's cost **disproved by measurement** plan §0.3's pessimistic prediction (predicted "many stubs needed"; measured only **1**, and that stub returning `NULL` is character-identical to upstream's `#else` branch).
2. Candidate B, marked "minimal intrusion" by the plan, **is actually more intrusive**: it must change upstream `uma_core.c` at 4 strongly-coupled sites; in the FreeBSD 13.0→15.0 upgrade project context, zero patches to the upstream tree carry high weight.
3. Candidate A makes all `#ifdef SMP` per-slot paths self-consistent at once, avoiding Candidate B's high risk of "one missed site = silent memory corruption".
4. Incidental fix of the potential atomicity defect of CK RMW lacking the `lock` prefix (zero cost, correct direction).

**Supplement (this doc's new 5th reason)**: `-DSMP` raises `MAXCPU` to 1024, **incidentally** providing the necessary precondition for §4.5's "`curcpu` per-thread-ization" — `lib/ff_kern_synch.c:59 static uint8_t pause_wchan[MAXCPU];` is indexed by `:105 pause_wchan[curcpu]`; once `curcpu` becomes `0..N-1`, `MAXCPU ≥ N` is required. Candidate B could also satisfy this by overriding `MAXCPU` to 64, but candidate A needs no extra action.【Code-verified】

### 3.3 Honest Boundaries (must be relayed together, `_m17_D_verdict.md` §1.3)

- **Candidate B has no compile numbers**; all its conclusions are code-review level only; if a fallback to B is needed in the future, **compile evidence must be obtained first**.
- Candidate A's **runtime** behavior (whether slots are truly isolated, whether `uma_crit_lock` can be removed, throughput change) is **all unverified**; M3/M5 must measure. **【Not-verified】**
- M1-C's probe code must **not** directly sediment into product code: M3's `coder` implements it formally under the `reviewer` gate (`_m17_gate_plan.md` §8.6-3).
- Whether `-DSMP` changes other **non**-spin-lock/non-CK runtime semantics (e.g. `cpuset_t` 8→128 impact on pass-by-value/struct embedding): `_m17_gate_plan.md` §8.7 records **not-verified**. This doc judges by "`SRCS` (238 kernel TUs) all clean-rebuilt with consistent definitions; `HOST_SRCS` (10) contain no FreeBSD kernel headers (`_m17_C_buildprobe.md` §0.1)" that there is no cross-`.o` ABI tearing surface, but that judgment only covers **compile time**; runtime is backstopped by M5. **【Not-verified】**

### 3.4 Fallback Paths (three levels, by priority)

| # | Step | Trigger | Content | Basis |
|---|---|---|---|---|
| **R-1** | In-candidate-A downgrade (**still no upstream tree changes**) | M5 shows `MAXCPU=1024` memory cost or CK `lock`-prefix cost unacceptable | with `-DSMP`, `#define MAXCPU 64` inside `lib/opt/opt_global.h` | `freebsd/amd64/include/param.h:61-63`'s SMP branch has `#ifndef MAXCPU` protection and can be externally overridden (while the `#else` branch defines unconditionally — exactly why `-DMAXCPU=N` fails under non-SMP)【Code-verified】 |
| **R-2** | Fall back to candidate B | candidate A exposes uncontrollable runtime problems | implement per `_m17_C_buildprobe.md` §3.2's B-1…B-6, **must simultaneously** complete the B-2/B-4/B-6 paired changes, and additionally obtain compile evidence + extra argument on the residual surface of `subr_pcpu.c:252` dpcpu-copy semantics inconsistency | same |
| **R-3** | Escalate to human decision | both A and B fail at runtime, or the same step has bounced 3 times | stop per bounce≤3 and escalate | plan §3 gate rules |

---

## 4. Detailed Design

> This section gives change points and methods file by file, function by function, and aligns with D1~D9 one by one in §4.9.
> **Comment conventions**: all code comments required by this section must be "very necessary" (external interface contracts, non-obvious timing/boundary constraints). **Comments on self-explanatory code are strictly forbidden; long comments strictly forbidden.** Wherever "comment required" is marked below, comment points of **no more than 3 lines** are suggested.

### 4.1 `lib/Makefile`: Define `SMP`

**Change**: after `:219 CFLAGS+= -DFSTACK`, add

```make
CFLAGS+= -DSMP
```

**Reason and basis**:
- `freebsd/amd64/include/param.h:60-66`'s `#else` (non-SMP) branch **unconditionally** `#define MAXCPU 1`, so **plain `-DMAXCPU=N` has no effect** (it triggers macro redefined, failing under `-Werror`); `SMP` must be defined or an override header used.【Code-verified】
- Effectiveness already【Measured】: with `-DSMP`, `MAXCPU` changes from 1 to 1024 (`-dM -E`, `_m17_C_buildprobe.md` §0.3).
- Of the two equivalent entry points (`lib/opt/opt_global.h` or `lib/Makefile`'s `CFLAGS+=`), choose `Makefile`: co-located with existing switches like `-DFSTACK`/`-DFF_IPFW`/`-DINET6`, easy to search.【Basis】`_m17_C_buildprobe.md` §0.1
- **Scope note**: the kernel option only affects `SRCS` (238 kernel TUs), not `HOST_SRCS` (10 going through `HOST_C`, without `KERNEL_CFLAGS`, without FreeBSD kernel headers).【Code-verified】`lib/Makefile:179`, `_m17_C_buildprobe.md` §0.1

**Comment required (≤2 lines)**: explain that "`SMP` makes `MAXCPU` become 1024, so UMA/SMR per-CPU storage is slotted by stack-thread count; without it `MAXCPU==1` and all threads share slot 0". This is a "non-obvious compile-time constraint" and a necessary comment.

### 4.2 `lib/ff_glue.c`: `smp_topo()` Stub

**Change**: add the only stub (suggested placement right after the `:168-170 smp_topology` definition, co-located with `mp_ncpus`/`mp_maxid`/`all_cpus`/`smp_started`/`smp_disabled`):

```c
struct cpu_group *
smp_topo(void)
{
    return (NULL);
}
```

**Why only this 1 is needed**【Measured】: `_m17_C_buildprobe.md` §2.2/§2.4 — with `-DSMP`, `lib` clean-build `error 0`, `warning 51` (= baseline, zero new); symbol diff "new unresolved symbols = 1"; real-link measured `undefined reference` deduplicated to only `smp_topo`; linker original text:

```
../lib/libfstack.a(libfstack.ro): in function `tcp_hpts_modevent':
tcp_hpts.c:(.text+0x28ecc4): undefined reference to `smp_topo'
```

**Safety argument for returning `NULL`**【Code-verified】(the only caller is `tcp_hpts.c`):

| Location | Code | Conclusion |
|---|---|---|
| `freebsd/netinet/tcp_hpts.c:1867-1871` | `#ifdef SMP cpu_top = smp_topo(); #else cpu_top = NULL; #endif` | upstream **already has** a `NULL` branch; stub is **character-identical** to non-SMP behavior |
| `freebsd/netinet/tcp_hpts.c:1890` | `if (cpu_top == NULL) { tcp_pace.grp_cnt = 1; }` | explicit `NULL` handling; no dereference |
| `freebsd/netinet/tcp_hpts.c:1564-1572` | `if (tcp_pace.grp_cnt > 1) { ... CPU_ISSET(curcpu, &tcp_pace.grps[i]->cg_mask) ... }` | `grp_cnt == 1` → `grps[]` **not dereferenced**; `:1559 end = tcp_pace.rp_num_hptss` does not overflow |
| `freebsd/netinet/tcp_hpts.c:2095` | `#ifdef SMP free(tcp_pace.grps, M_TCPHPTS); #endif` | only the module-unload path; `free(NULL)` harmless when `grps` is NULL/unallocated |

**Comment required (≤2 lines)**: explain that "userspace has no CPU topology; callers must handle NULL, see `tcp_hpts.c:1890`". An external contract, necessary.

### 4.3 `lib/ff_freebsd_init.c`: Triple, Timing, Slot Numbering, Upper-Bound Check

#### 4.3.1 Timing Hard Constraint (D2 / H1 / H2)

**`mp_ncpus` / `mp_maxid` / `all_cpus` must be set together as a triple, all before `lib/ff_freebsd_init.c:301 uma_startup1()`.**【Code-verified】

Reasons (all three are "set late and it breaks"):

| # | Basis | Consequence |
|---|---|---|
| H1 | `freebsd/vm/uma_core.c:3179-3182`: `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + sizeof(struct uma_zone_domain)*vm_ndomains`, computed **once** in `uma_startup1()`; `freebsd/vm/uma_int.h:529ZDOM_GET(z,n) = &((uma_zone_domain_t)&(z)->uz_cpu[mp_maxid+1])[n]` (this doc's preprocess【Measured】confirms expansion); `uma_core.c:2472-2478 pages *= mp_maxid+1; uk_ppera = pages;` | raising `mp_maxid` later → `uz_cpu[i>0]` and `zdom` all out of bounds (heap overflow) |
| H2 | `freebsd/kern/subr_smr.c:598-605 for (i=0;i<=mp_maxid;i++){ c = zpcpu_get_cpu(smr,i); c->c_seq = SMR_SEQ_INVALID; ... }` (**no `#ifdef SMP`**), triggered via `mi_startup()` (`:309`): `in_pcbinfo_init` → `uma_zcreate(UMA_ZONE_SMR)` → `zone_ctor` → `smr_create()` | `mp_maxid` and `UMA_ZONE_PCPU` must be paired; candidate A automatically opens `uma_core.c:2546`'s PCPU stripping via `-DSMP`, self-consistent |
| D2/§8.4 | `freebsd/netpfil/ipfw/ip_fw_dynamic.c:3236 malloc(mp_ncpus * sizeof(void *), ...)` sized by **`mp_ncpus`**, while `:2086-2091 CPU_FOREACH(i) { dyn_hp_cache[cached_count++] = DYNSTATE_GET(i); }` iterates by **`mp_maxid` + `all_cpus`** (`freebsd/sys/smp.h:197-199`); `FF_IPFW=1` is compiled (`lib/Makefile:44`; `ip_fw_dynamic.c` in `NETIPFW_SRCS` at `:601`) | raising only `mp_maxid`+`all_cpus` without raising `mp_ncpus` → **heap overflow** |
| **H3** | **`uma_page_slab_hash`/`uma_page_mask` must also be set before `uma_startup1()`** — once `mp_maxid > 0`, zone-of-zones grows → slab becomes multi-page → `UMA_ZFLAG_VTOSLAB` set → f-stack's own `vsetzoneslab()` is called during `uma_startup1()` | **【Measured】** with `mp_maxid ≥ 2`, startup SIGSEGVs (100% reproducible). **Full mechanism, fix method and honest boundary in §4.10**; this item together with H1/H2 forms "G1's startup-timing contract" |

**Placement**: inside `ff_freebsd_init()`, before `:293` (i.e. between `:291 physmem = ...` and `:293 ff_pcpu_thread_init(0)`). At that point `ff_global_cfg.dpdk.nb_threads` has been determined by `ff_load_config()` (`lib/ff_init.c:39`, two levels earlier) and `ff_dpdk_init()` (`:43`) has finished `init_lcore_conf()`; the information is fully available.【Code-verified】

**Method (illustrative, ≤10 lines)**:

```c
nb_cpus = ff_global_cfg.dpdk.thread_mode ? ff_global_cfg.dpdk.nb_threads : 1;
if (nb_cpus < 1)
    nb_cpus = 1;
if (nb_cpus > MAXCPU)
    panic("nb_threads %d exceeds MAXCPU %d\n", nb_cpus, MAXCPU);
mp_ncpus = nb_cpus;
mp_maxid = nb_cpus - 1;
for (i = 0; i < nb_cpus; i++)
    CPU_SET(i, &all_cpus);
```

- Need `#include <sys/smp.h>` (`mp_ncpus`/`mp_maxid` declarations; `all_cpus` already extern at `:88`).
- The original `:294 CPU_SET(0, &all_cpus);` is replaced by the loop above (**not kept and then supplemented**, to avoid writing the same bitmap twice).
- **Comment required (≤3 lines)**: explain that "the three must be finalized before `uma_startup1()` and never changed afterward (UMA fixes zone sizes there by `mp_maxid`), and `mp_ncpus` must not lag behind `all_cpus` (`ip_fw_dynamic.c` sizes by `mp_ncpus` but iterates by `CPU_FOREACH`)". This is a typical timing constraint "impossible to understand without a comment"; a necessary comment.
- `panic` rather than silent clamping: because `freebsd/kern/subr_pcpu.c:88`'s `KASSERT(cpuid >= 0 && cpuid < MAXCPU, ...)` is **compiled out** without `INVARIANTS` (M1-A U1【Measured】), a runtime fallback is mandatory (D6).

#### 4.3.2 Whether `mp_ncpus` Rises with `mp_maxid` — Verdict: **raise to N**

**"Neither value-taking method overflows" holds, but the reason must be "writer-side bounded", not "reader-side modulo"** (this doc replaces the original argument wholesale per gate-design's mandatory-change F1; the original text wrongly said "every index of `rp_ent[]` independently takes modulo against `mp_ncpus`/`rp_num_hptss`", **disproven by measurement**).

**The disproving fact**【Code-verified】: inside `freebsd/netinet/tcp_hpts.c:569-579tcp_hpts_lock()` `:575 hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];` — **no modulo at all**. So `rp_ent[]`'s out-of-bounds safety **depends entirely on whether the value written to `t_hpts_cpu` is bounded**.

**Switch to "writer-side bounded" argument** (`t_hpts_cpu` has only 3 write sites in the whole tree, exhaustively enumerated):

| # | Write site | Value range | Basis |
|---|---|---|---|
| 1 | `tcp_hpts.c:606 tp->t_hpts_cpu = hpts_random_cpu();` (inside `tcp_hpts_init()`, `:605 if (t_hpts_cpu == HPTS_CPU_NONE)`) | `hpts_random_cpu()` (`:466-475`) is **double modulo** `(((ran & 0xffff) % mp_ncpus) % tcp_pace.rp_num_hptss)` (`:473`) → `< min(mp_ncpus, rp_num_hptss)` | 【Code-verified】 |
| 2 | `tcp_hpts.c:1542 tp->t_hpts_cpu = hpts_cpuid(tp, &failed);` (inside `tcp_set_hpts()`) | all return paths of `hpts_cpuid()` (`:1040-1099`) are bounded: `:1050` returns the previously set old value (inductively bounded); `:1067`/`:1078` return `hpts_random_cpu()` (same as above); `:1089 cpuid = inp->inp_flowid % mp_ncpus`; `:1059 return (0)`. **The `#ifdef RSS` (`:1064-1070`) and `#ifdef NUMA` (`:1085-1096`) blocks are not compiled** (`RSS` undefined, `NUMA` undefined, see §5-9) | 【Code-verified】 |
| 3 | `tcp_subr.c:2298 tp->t_hpts_cpu = HPTS_CPU_NONE;` (tcpcb init) | `HPTS_CPU_NONE == (uint16_t)-1 == 65535` (`freebsd/netinet/tcp_var.h:330`) → **this is a sentinel value, not a valid index**; see "⚠ existing invariant" below | 【Code-verified】 |

**About the `t_lro_cpu` branch (`:1056-1062`)**: even if `tcp_use_irq_cpu` is enabled (default **0**, `:286`, changeable via tunable `net.inet.tcp.use_irq`), **no out-of-bounds value is produced** — `tp->t_lro_cpu`'s only non-sentinel assignment is in `freebsd/netinet/tcp_lro_hpts.c:577`, and **that file does not participate in compilation** (HEAD `lib/Makefile:515`'s `NETINET_SRCS` only lists `tcp_lro.c`; `lib/tcp_lro_hpts.o` does not exist) ⇒ `t_lro_cpu` is always `HPTS_CPU_NONE` ⇒ it necessarily takes the `:1057-1060 { *failed = 1; return (0); }` **bounded** branch, and `:1061 return (tp->t_lro_cpu)` is unreachable.【Code-verified】

**`rp_num_hptss == mp_ncpus` and timing**【Code-verified】: `tcp_hpts.c:1864 ncpus = mp_ncpus ? mp_ncpus : MAXCPU;` → `:1872 tcp_pace.rp_num_hptss = ncpus;`; while `tcp_hpts_init` (module SYSINIT) is driven by `mi_startup()` (`lib/ff_freebsd_init.c:309`), **later** than the triple setting (§4.3.1, before `:301 uma_startup1()`) ⇒ the two are always equal; the writer-side double-modulo upper bound and the reader-side array size are **always equal**.

> **⚠ An existing invariant (must be honestly registered, but unrelated to this verdict)**: write site 3's `HPTS_CPU_NONE` (65535) is itself an out-of-bounds index; safety depends on "`tcp_hpts_init()` must replace it before any `tcp_hpts_lock()`". And `tcp_set_hpts()` happens to **first** `:1540 tcp_hpts_lock(tp)` (which internally does the `:575` fetch) **then** `:1542` assigns. This invariant is maintained by `rack.c:14368` / `bbr.c:9946` calling `tcp_hpts_init()` (both **are compiled**: HEAD `lib/Makefile:584-586`, `lib/rack.o`/`lib/bbr.o` exist); upstream comment `:596-600` also explicitly notes the pathological case of this path (syzkaller). **Key point: this risk is unrelated to the `mp_ncpus` value** — 65535 overflows equally with `mp_ncpus=1` (1 entry), so **G1 neither introduced nor aggravated it**; not handled this round.【Code-verified】

Once "no overflow" is established by the above writer-side argument, the remaining issue is the concurrency trade-off, and **this doc verdicts `mp_ncpus = N`** for two reasons:

1. **D2's ipfw heap overflow makes it mandatory**: if `mp_ncpus` stays 1 while `all_cpus` has N bits, `ip_fw_dynamic.c:2086-2091` writes N entries into the 1-slot `dyn_hp_cache`. Although triggering also requires "shared `dyn_hp` slot non-NULL" (i.e. ipfw dynamic rules actually used; `_m17_gate_plan.md` §8.7 records whether enabled as not-verified), this is a **conditional out-of-bounds that should not be left**.
2. **U16-a is closed as "hpts active" by this doc** (§0.4): `mp_ncpus=1` makes `tcp_pace.rp_num_hptss == 1`, and all N workers' `main_loop`s drive the same hpts instance; while `HPTS_TRYLOCK` = `mtx_trylock` is defined by `lib/include/sys/mutex.h:74-76` as **constant 1 (always "success")**, i.e. **no mutual exclusion at all**【Code-verified】. `mp_ncpus=N` makes `hpts_cpuid()` spread connections across N instances by `inp_flowid % mp_ncpus` (`tcp_hpts.c:1089`), significantly reducing that hot spot.

**Residue (must be honestly recorded, not fixed this round)**: even with `mp_ncpus=N`, `tcp_choose_hpts_to_run()` (`tcp_hpts.c:1574-1587`) still picks "the one not run for the longest" among `0..rp_num_hptss-1`, so two workers **can still pick the same hpts**; combined with `HPTS_TRYLOCK` always-true and the non-atomic guard at `:1599/:1608 if (hpts->p_hpts_active)`, a window for concurrent entry into the same hpts exists. **This is a pre-existing defect (worse under T1: N workers necessarily squeeze onto the single instance); G1 makes it lighter, not heavier**; not fixed this round, registered in §6.4. **【Not-verified】** its actual occurrence rate must be observed at M5 (suggest printing `tcp_pace.rp_num_hptss` and each `hpts->p_on_queue_cnt`).

**⚠ The cost of this verdict (forward reference)**: `mp_ncpus = N` makes the `tcp_hpts` instance count go from 1 to N (`tcp_hpts.c:1864/1872`), bringing **~+2.34 MiB × (N−1)** memory growth, plus the semantic mismatch of "all N instances' callouts hang on the main thread's callwheel yet are driven by each worker" and `p_mtx` having no real mutual exclusion. **These three points are fully registered as §6.19 (recorded as R6 in the native-mt concurrency risk list), and M5 is required to quantify the memory growth (§7.4).** This doc still maintains the `mp_ncpus = N` verdict because its benefits (eliminating D2's ipfw heap overflow, a **memory-safety** issue, + spreading the hpts hot spot) outweigh the above **resource and pre-existing-concurrency** costs; if M5 shows the memory growth unacceptable, the downgrade means in §3.4's R-1 (shrinking `MAXCPU`) **does not apply** (this growth is driven by runtime `mp_ncpus`, not `MAXCPU`); a separate evaluation of the combination "keep `mp_ncpus=1` + separately fix ipfw `dyn_hp_cache` size" would be needed — **that combination is not designed or verified this round**【Not-verified】.

#### 4.3.3 `ff_pcpu_thread_init()`: Actually Use the Parameter + Runtime Upper-Bound Check (D3 / D6)

**Current** (HEAD `:103-109`): the `cpuid` parameter is deliberately ignored and 0 is always passed to `pcpu_init()`; the comment at `:94-101` explicitly explains why "cpuid must stay 0" (non-SMP, `MAXCPU==1`).

**Method**:

```c
void
ff_pcpu_thread_init(int cpuid)
{
    if (cpuid < 0 || (u_int)cpuid > mp_maxid)
        panic("ff_pcpu_thread_init: cpuid %d out of range [0, %u]\n", cpuid, mp_maxid);

    pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);
    pcpu_init(pcpup, cpuid, sizeof(struct pcpu));
    PCPU_SET(prvspace, pcpup);
}
```

- The **upper bound uses runtime `mp_maxid`** (not compile-time `MAXCPU`), isomorphic to libuinet's `uinet_pcpu_get()` doing `KASSERT(td_oncpu < mp_ncpus)` at the only slot-access entry (`_m17_B_external.md` §3.1(b)(i)). D6 requirement.
- `malloc(sizeof(struct pcpu))` size **does not need changing**: `sizeof(struct pcpu)` measured **4096 both before and after `-DSMP`** (`_m17_C_buildprobe.md` §0.3), and `freebsd/amd64/include/pcpu_aux.h:47_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE)` is a compile-time hard constraint.【Measured + Code-verified】
- **The original comment at `:94-101` must be rewritten** (it states a constraint this round overturns). **Comment required (≤3 lines)**: explain "one pcpu per thread + dense cpuid ∈ [0, mp_maxid] is the precondition for non-overlapping UMA_ZONE_PCPU/SMR slots" and "the upper-bound check is deliberately kept because `subr_pcpu.c:88`'s KASSERT is compiled out".
- `pcpu_init()` stays inside the `init_lock` critical section (`:185-186` spin, `:216` release); **do not shrink that lock's scope**: with dense indexing, `cpuid_to_pcpu[cpuid]=pcpu` (`subr_pcpu.c:91`) writes different subscripts per thread, but `STAILQ_INSERT_TAIL(&cpuhead, ...)` (`:92`) operates the shared list's tail pointer and must be serialized; and `init_lock` also covers `ff_init_thread0()`/`ff_adapt_user_thread_add()`/`vnet_alloc()`/`lo_set_defaultaddr()` global operations (R1~R5 recorded in AI memory).【Basis】M1-A U5.1

#### 4.3.4 Main-Thread Slot Numbering (D4) — Including the C2 Correction

**Requirement (D4)**: the main thread's slot must not collide with workers', and **must not depend on the unverified inference "EAL main lcore == `proc_lcore[0]`"** (U6-a; `--main-lcore` can break it).

**Method**: change `:293 ff_pcpu_thread_init(0);` to

```c
ff_pcpu_thread_init(ff_global_cfg.dpdk.thread_mode ? ff_cur_proc_id() : 0);
```

where `ff_cur_proc_id()` is the new cross-TU numbering helper (see §4.4).

**Why `thread_mode` gating is mandatory (this doc's correction C2; M1 docs did not note it)**【Code-verified】:

- `lib/ff_dpdk_if.c:460` (the **non**-thread_mode branch of `init_lcore_conf()`): `ff_cur_lcore_conf()->proc_id = ff_global_cfg.dpdk.proc_id;`
- i.e. **in `thread_mode=0`, `proc_id` is the "process number"**: secondary processes are 1, 2, … (`:1645-1646` validates `proc_id < nb_procs`). And each `thread_mode=0` process is an independent address space with its own `mp_maxid=0`.
- Without gating using `proc_id` directly: in doc-16 §2.1 E2's "2 processes" scenario, the secondary would get `cpuid=1`, triggering §4.3.3's `panic` (lucky) or (without the upper-bound check) an out-of-bounds write to `cpuid_to_pcpu[1]` (disaster). → **directly violates D7 zero regression**.
- With gating: `thread_mode=0` always takes 0, `nb_cpus=1`, `mp_maxid=0`, `all_cpus` only bit 0 → **semantically equivalent to HEAD item by item**.

**Correctness under `thread_mode=1`**【Code-verified】: `lib/ff_dpdk_if.c:429-433` sets `lcore_conf[proc_lcore[ti]].proc_id = ti` for `ti in [0, nb_threads)`; the main thread is the EAL main lcore (necessarily in the coremask; under thread_mode `proc_mask == lcore_mask`, `lib/ff_config.c:1477-1481`), so `ff_cur_lcore_conf()->proc_id` necessarily falls in `[0, N)` and differs from every worker's. **This numbering is immune to `--main-lcore`**, so U6-a is downgraded from "solution dependency" to "observation item requiring only an M5 print check".

**Timing availability**【Code-verified】: `rte_eal_init()` completes inside `ff_dpdk_init()` (`lib/ff_init.c:43`), so the main thread calling `rte_lcore_id()` inside `ff_freebsd_init()` (`:47`) is valid; `lcore_conf[]` has also been filled by `init_lcore_conf()`.

#### 4.3.5 Relationship with `ff_stack_thread_init()` (unchanged)

`ff_stack_thread_init()` (`:170-217`) itself **needs no change**: it directly forwards the `cpuid` parameter to `ff_pcpu_thread_init()` (`:187`); the main thread, because `:82 static __thread int ff_stack_inited` is set to 1 at `:348`, enters `main_loop` and returns directly at `:177-178`, **not rebuilding pcpu**.【Code-verified】

### 4.4 `lib/ff_dpdk_if.c`: Dense-Index Usage (D3)

**Change 1**: `:2649ff_stack_thread_init(rte_lcore_id());` → **must have `thread_mode` gating**:

```c
ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0);
```

（**Code wins**: the actually-landed M3 code is exactly this form; this doc's earlier writing of only `qconf->proc_id` missed the gating, corrected per gate-design E2.)

**Why gating is also mandatory here (same source as §4.3.4's C2, but this is the second landing point; only changing one is not enough)**【Code-verified】: `lib/ff_dpdk_if.c:460` (the non-thread_mode branch of `init_lcore_conf()`) sets `lcore_conf[].proc_id` to the **process number** (`ff_global_cfg.dpdk.proc_id`; secondary processes are 1, 2, …, validated `< nb_procs` at `:1643-1651`), and each `thread_mode=0` process is an independent address space with its own `mp_maxid == 0`. Without gating here: if a secondary process actually reaches `ff_stack_thread_init()`, it would trigger §4.3.3's upper-bound `panic` (`ff_pcpu_thread_init: cpuid 1 out of range [0, 0]`) with `cpuid=1`, or (if the check were removed) write `cpuid_to_pcpu[1]` out of bounds — **directly breaking D7 zero regression**.

**⚠ Fragile coupling (must be explicitly registered, gate-design E2)**: even with the gating, `thread_mode=0` safety still **doubly depends** on the existing mechanism "`ff_stack_thread_init()` inside `main_loop` returns early" — `lib/ff_freebsd_init.c:82 static __thread int ff_stack_inited;` is set to 1 at `:348` in the main thread; `ff_stack_thread_init()` checks it at `:177-178` and returns directly【Code-verified】. That is: in `thread_mode=0`, the argument passed at `main_loop` (`ff_dpdk_if.c:2649`) **is never used**. This is a **redundant-but-fragile** structure with two mechanisms ("gating" and "early return") both backstopping; if either is changed in the future (e.g. making `ff_stack_inited` global, or letting `main_loop` re-init under `thread_mode=0`), the argument is immediately exposed. **Therefore DoD-4 (§7.4) explicitly requires `thread_mode=0` 1-process and 2-process to both be measured, confirming no `ff_pcpu_thread_init: cpuid ... out of range` in the logs** — not just static inference.

- `qconf` is already fetched at `:2644 qconf = ff_cur_lcore_conf();`, **zero extra overhead**.
- `rte_lcore_id()` is the **sparse** physical lcore number (e.g. `lcore_mask=6` → lcores 1, 2), a **different index space** from the dense `0..N-1` needed by pcpu slots; mixing them is exactly T0's out-of-bounds root cause.【Code-verified】M1-A U6.1

**Change 2**: add a numbering helper callable by kernel TUs (suggested placement before `init_lcore_conf()`):

```c
int
ff_cur_proc_id(void)
{
    return ff_cur_lcore_conf()->proc_id;
}
```

and declare it in `lib/ff_dpdk_if.h`.

**Why this function is needed**: `lib/ff_freebsd_init.c` is a kernel TU (with `KERNEL_CFLAGS` + `-nostdinc`), **cannot** include DPDK headers (`rte_lcore_id()`) and cannot reach `lcore_conf[]` (`static`, `lib/ff_dpdk_if.c:126`); while `ff_dpdk_if.c` belongs to `FF_HOST_SRCS` (goes through `HOST_C`, `lib/Makefile:179`). The signature `int (void)` involves no cross-compilation-definition-inconsistent type, a safe cross-TU boundary.【Code-verified】`_m17_C_buildprobe.md` §0.1

- **Comment required (≤1 line)**: at the declaration, explain "returns the calling thread's dense stack-instance index (`lcore_conf[].proc_id`)". An external interface contract.
- **Do not** change the semantics of `ff_lcore_conf_idx()`/`ff_cur_lcore_conf()` (`lib/ff_memory.h:104-111`): indexing `lcore_conf[]` by `rte_lcore_id()` is correct (`lcore_conf` is an array indexed by lcore id, `lib/ff_dpdk_if.c:126 lcore_conf[RTE_MAX_LCORE]`). **The boundary between the two index spaces must stay clear**: `lcore_conf[]`/`veth_ctx[][]`/`rte_mempool` use the lcore id; pcpu/UMA/SMR slots use `proc_id`.

### 4.5 `lib/include/sys/pcpu.h`: Make `curcpu` per-Thread (G1's Third Mandatory Item)

This is the only substantive addition of this doc relative to D1~D9; the basis is in §2.3.

**Change**: change `:34 #define curcpu 0` to resolve to this thread:

```c
#define curcpu    PCPU_GET(cpuid)
```

（`PCPU_GET` is already redefined by `lib/include/amd64/include/pcpu.h:49` to `pcpup->pc_ ## member`, so this is equivalent to `pcpup->pc_cpuid`; this is also exactly upstream's original definition at `freebsd/sys/pcpu.h:218`. `:32 #undef curcpu` must be kept to erase the upstream definition before giving the f-stack version, avoiding a redefined warning failing under `-Werror`.)

**All usage points that must be evaluated together** — the exhaustive scope is strictly limited to "occurrences of the identifier **`curcpu`** within the **actually compiled set**" (the compile set inferred back from `lib/*.o`; measured to appear in only 7 files). The two categories outside the scope but that must be explicitly excluded are at the end of this table ("exclusion" rows):

| # | Location | Usage | After `curcpu` becomes `0..N-1` | Judgment basis |
|---|---|---|---|---|
| 1 | `freebsd/vm/uma_core.c` × 11 (`:1452,3738,3776,3818,3901,4534,4543,4595,4628,4803,4853`) | `cache = &zone->uz_cpu[curcpu];` | **this is the purpose of the change**: each thread exclusively owns its cache slot; size allocated by `uma_startup1` per `mp_maxid+1` (H1) → no overflow | 【Code-verified】+ this doc's preprocess【Measured】 |
| 2 | `lib/ff_kern_synch.c:105` | `_sleep(&pause_wchan[curcpu], ...)`, `:59 static uint8_t pause_wchan[MAXCPU];` | needs `MAXCPU≥ N`: candidate A's 1024 satisfies it. (**Note**: today `curcpu==0` so **no out-of-bounds exists**; this corrects M1-A U9 #4's causal statement → C3) | 【Code-verified】 |
| 3 | `freebsd/netinet/tcp_timer.c:237,249` | two fallback `return (curcpu);` in `inp_to_cpuid()` | return value only used as the `cpu` argument to `callout_reset_sbt_on()` (`:896`/`:932`), judged by `lib/ff_kern_timeout.c:730cpu >= MAXCPU`; `MAXCPU=1024 ≥ N` → **no panic**; `CC_CPU(cpu)` ignores the argument (`:184`) → still takes this thread's `cc_cpu` | 【Code-verified】M1-A U11.3 |
| 4 | `freebsd/netinet/tcp_hpts.c:1587` | `return rp_ent[(curcpu % tcp_pace.rp_num_hptss)];` | **modulo** → no overflow | 【Code-verified】 |
| 5 | `freebsd/netinet/tcp_hpts.c:1566` | `CPU_ISSET(curcpu, &tcp_pace.grps[i]->cg_mask)` | inside `:1564 if (tcp_pace.grp_cnt > 1)`; `smp_topo()` returns NULL → `:1890 grp_cnt = 1` → **unreachable** | 【Code-verified】§4.2 |
| 6 | `freebsd/netinet/tcp_lro.c:1210,1216` | `if (lc->lro_last_cpu == curcpu) ... lc->lro_last_cpu = curcpu;` | pure heuristic comparison, no index; after per-thread it is **semantically more correct** (originally all threads thought they were on the same CPU) | 【Code-verified】 |
| 7 | `freebsd/net/netisr.c:839` | `*cpuidp = netisr_get_cpuid(curcpu);` | `netisr_get_cpuid()` (`:275-279`) = `nws_array[cpunumber % nws_count]` → **modulo**, no overflow. And this line is in the `NETISR_POLICY_CPU` + `NETISR_DISPATCH_HYBRID` branch, unreachable under f-stack (see below) | 【Code-verified】 |
| 8 | `freebsd/net/netisr.c:1172` | `if (cpuid != curcpu) goto queue_fallback;` | **unreachable**: `:151 #define NETISR_DISPATCH_POLICY_DEFAULT NETISR_DISPATCH_DIRECT`, `:153 netisr_dispatch_policy = NETISR_DISPATCH_POLICY_DEFAULT`, and `ip_nh`/`ip6_nh` have no `nh_dispatch` set (`RSS` undefined; `ip_input.c:139-149`, `ip6_input.c:138-148`) → `netisr_get_dispatch()` (`:781-790`) returns DIRECT → the `:1146-1153` branch directly `np_handler(m)` and `goto out_unlock`, returning **before `:1164`** | 【Code-verified】 |

**Two categories outside the exhaustive scope but that must be explicitly excluded (gate-design E7)**:

| # | Location | Why unaffected | Judgment basis |
|---|---|---|---|
| **Exclusion X1** | `freebsd/libkern/arc4random.c:212 chacha20 = &chacha20inst[curcpu];` | **this file does not participate in compilation**, so unaffected | `lib/Makefile` HEAD `:582`'s `LIBKERN_SRCS` only lists `arc4random_uniform.c`, **not `arc4random.c`**; `lib/arc4random.o` does not exist (`ls` measured `No such file`). (The `:586` gate-design reported is the workspace line including the M3 changes) |
| **Exclusion X2** | `freebsd/sys/callout.h:100-102/108-109/115-116/119-120`'s `callout_reset_sbt_curcpu` / `callout_reset_curcpu` / `callout_schedule_sbt_curcpu` / `callout_schedule_curcpu` macro family | **the macro names contain `curcpu` but the macro bodies do not go through `curcpu`**; they use `PCPU_GET(cpuid)` directly【Code-verified】→ they were already per-thread and **do not change because of this round**. Their only compiled user, `freebsd/kern/subr_taskqueue.c:368 callout_reset_sbt_curcpu(...)` (inside the `:366-367 tq_spin && tq_tcount == 1 && tq_threads[0] == curthread` branch), after G1 passes a dense cpuid (`0..N-1`), judged by `lib/ff_kern_timeout.c:730`'s `cpu >= MAXCPU`; `MAXCPU=1024 ≥ N` → **safe** (see also the U12-ish item in §6.20) | this doc measured grep |

> **Supplement** (eliminating the concern that "changing `curcpu` breaks netisr direct dispatch"): the `netisr_queue*` paths (`if_loop.c:357`, `ip_output.c:158/192`, `ip6_output.c:1045/1077`, `rtsock.c:2233`, `ip_divert.c:543/550`) go through `netisr_queue_src()` → `netisr_select_cpuid()`, and `:810 if (nws_count == 1) { *cpuidp = nws_array[0]; return (m); }` returns before reaching `:839` (`netisr_maxthreads` defaults 1, `:169`). → **the `curcpu` change has no effect on netisr core selection behavior.**【Code-verified】(but netisr has another DPCPU-alias issue unrelated to `curcpu`, see §6.15.)

**A newly introduced risk class + one mandatory exception (this doc corrects its original position per actual code)**: after `curcpu` changes from the literal 0 to `pcpup->pc_cpuid`, **evaluating `curcpu` at an execution point where `pcpup == NULL` dereferences NULL**. Two categories must be distinguished and **handled differently**:

**（i) "Bootstrap-window" class — a targeted fallback is mandatory (not optional)**【Code-verified】

`pause_wchan[curcpu]` in `lib/ff_kern_synch.c:105 pause_sbt()` is reachable **before this thread has built its pcpu**:

```
lib/ff_freebsd_init.c:106  pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);   /* pcpup still NULL */
lib/ff_glue.c:1067-1078malloc()'s M_WAITOK retry loop → :1070 pause("malloc", hz/100)
freebsd/sys/systm.h:485pause() → pause_sbt()
lib/ff_kern_synch.c:105pause_wchan[curcpu] → pcpup->pc_cpuid  ==> NULL dereference
lib/ff_freebsd_init.c:107  pcpu_init(pcpup, cpuid, ...)                /* only now built */
```

i.e. **once the `:106` `malloc` enters an OOM retry, `curcpu` is evaluated while `pcpup` is still NULL**. Before the change `curcpu ≡ 0` so harmless; after the change it necessarily crashes. Therefore the actual M3 code adds a targeted fallback at this site:

```c
/* Reachable from malloc()'s OOM retry before this thread has a pcpu. */
return (_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], NULL, 0, wmesg, sbt, pr, flags));
```

**This doc adopts that change** (code wins) and lists it in §8.2's commit-1 file list. It does **not** violate the fail-fast principle of (ii) below: it is a correctness fix for a **supported thread within the bootstrap window**, not a fallback for unsupported usage; degrading to slot 0 inside that window is safe (this thread owns no per-CPU state yet, and `pause_wchan[]` is only used as the wait-channel address for `_sleep`, carrying no data). Its comment is 1 line explaining "why reachable", conforming to the minimal-comment convention.

> **Also note**: `freebsd/vm/uma_core.c:5440 pause("umarclslp", hz)` goes through the same path, but it is on the `uma_reclaim` path, far later than pcpu construction, not in the bootstrap window.

**（ii) "Unsupported-thread" class — deliberately no fallback (fail-fast)**

- Main thread: `ff_pcpu_thread_init()` is one of the earliest actions in `ff_freebsd_init()` (`:293`, before `:299 kmem_malloc` / `:301 uma_startup1`) → **safe**.【Code-verified】
- Workers: `ff_pcpu_thread_init()` is the first action of `ff_stack_thread_init()` (`:187`) → **safe**.
- App threads created by `ff_pthread_create()` (`lib/ff_thread.c:33-45`): `ff_start_routine` (`:21-30`) only does `ff_set_thread(p_data->parent)` (`:16-19`), **does not call `ff_pcpu_thread_init`** → `pcpup == NULL`. Such threads **already crash today when calling any `ff_*` API that goes through SMR/`PCPU_GET`** (`zpcpu_get()` dereferences `pcpup->pc_zpcpu_offset`); this round expands the failure surface to "any UMA entry crashes". **Design verdict: no general NULL fallback** (a general fallback would disguise unsupported usage as runnable and necessarily cause multi-threaded slot sharing — exactly T1's problem); instead, per D9, clearly document it as **unsupported usage** (§5-1). **fail-fast is a deliberate choice.**
- DPDK internal threads (`eal-intr-thread`/telemetry): do not call `ff_*`/UMA (M1-A U13.2【Code-verified】: f-stack registers no `rte_service`) → unaffected.

**Why this change must be in the same G1 commit as §4.1/§4.3**: the premise of `curcpu` becoming `0..N-1` is that `uz_cpu[]` is allocated by `mp_maxid+1` and `MAXCPU ≥ N`. Splitting the three into separate commits produces "intermediate state that crashes" commits, violating the basic requirement that "every commit should compile independently and not introduce a known crash".

### 4.6 `lib/ff_kern_timeout.c`: Make `timeout_cpu` `__thread` (D5)

**Change**: `:190 static int timeout_cpu;` → `static __thread int timeout_cpu;`

**Basis**【Code-verified】:

- It is a matched pair with `:183 __thread struct callout_cpu cc_cpu;` (the same comment block `:180-182` describes both), with the semantics "the cpuid of this thread's callwheel", but it missed `__thread`.
- The only write site, `lib/ff_kern_timeout.c:254 timeout_cpu = PCPU_GET(cpuid);`, is in `ff_callout_thread_init()`, **executed by every thread** (main thread via `lib/ff_kern_timeout.c:285 ff_callout_thread_init();`, driven by `:287 SYSINIT(callwheel_init, SI_SUB_CPU, SI_ORDER_ANY, callout_callwheel_init, NULL);` in `mi_startup()`; workers via `lib/ff_freebsd_init.c:207`). With dense cpuid it gets overwritten to "the cpuid of the last thread to finish init" (written inside `init_lock` so no tearing, but the **final value corresponds to no single thread**).
- Consequence of not changing: `:1061 c->c_cpu = timeout_cpu;` (`callout_init`) and `:1077` (`_callout_init_lock`) write **another thread's cpuid** into `c->c_cpu`; later `:815 return callout_reset_on(c, to_ticks, c->c_func, c->c_arg, c->c_cpu);` passes it back as `cpu` to `:720 callout_reset_tick_on()` → the validity check at `:730-733`. Even if `MAXCPU=1024` does not panic, semantically it is the hidden error "thread A's callout remembers thread B's cpuid".
- Change cost **near zero**: `timeout_cpu` has no cross-thread semantic need; `:662` (`timeout(9)`) and `:1181` (`sysctl kern.callout_stat`) read it then pass it to `CC_CPU()`, and `CC_CPU(cpu)` (`:184`) **ignores the argument**, always returning this thread's `cc_cpu`.

**Option not taken (explicitly excluded)**: M1-A U11.4 "optional C" proposed changing `:730`'s `cpu >= MAXCPU` to `cpu > (int)mp_maxid`. **This doc verdicts: not doing it.** Reasons: ① after `MAXCPU=1024 ≥ N` that check no longer false-panics; ② it is existing f-stack semantics; changing it enlarges G1's diff and regression surface for only "closer to true semantics"; ③ if M5 hits that panic, it means a non-dense cpuid was passed in — **that panic is exactly the signal we want**; it should not be relaxed.

### 4.7 `lib/include/vm/uma_int.h`: G2's Implementation Form (D8 Verdict)

> **G2's hard precondition**: `curcpu` must already be per-thread (via §4.5). Otherwise removing `uma_crit_lock` would let all threads concurrently access the shared `uz_cpu[0]` unprotected, **equivalent to putting the race `b90ddcba5` fixed right back** (§2.3(d)2). Before M4 starts, `reviewer` must verify this precondition is met (criterion: in `lib/include/sys/pcpu.h`, `curcpu` is already `PCPU_GET(cpuid)`, and DoD-1 criterion ⑤ "each thread's UMA cache slot differs" has passed measurement).

#### 4.7.1 Verdict

**Adopt G2-b: change `critical_enter/exit` back to no-ops, leave the slow path untouched, validate by load test and honestly record residual risks.**

Specifically: delete `:45`'s `extern volatile int uma_crit_lock;` and the two macros at `:46-52`, changing them to

```c
#define critical_enter() do {} while(0)
#define critical_exit()  do {} while(0)
```

and delete `lib/ff_glue.c:146 volatile int uma_crit_lock;`.

- This is exactly the state **before** `b90ddcba5` (M1-A U7 part 1【Measured】diff original: `-#define critical_enter() do {} while(0)`).
- **Keep the macros rather than deleting them entirely**: `lib/include/vm/uma_int.h` still needs to override `freebsd/sys/systm.h`'s inline version after `#include_next <vm/uma_int.h>` (`:38`); although the latter is an empty function body under f-stack (`systm.h:186 #ifndef FSTACK`), keeping explicit empty macros avoids depending on the fragile assumption "upstream will always keep `#ifndef FSTACK`". **Comment required (≤2 lines)**: explain "f-stack has no preemption semantics; UMA per-CPU cache mutual exclusion is guaranteed by 'each thread exclusively owns a dense pcpu slot', see spec 17 §2.4".

#### 4.7.2 Why Not G2-a (remove lock + add real locks to zone/keg/`vsetzoneslab`)

Three code-level rejection reasons:

1. **UMA locks are sleep-capable semantics (`MTX_DEF`); adding spinlocks self-deadlocks.**【Code-verified】`freebsd/vm/uma_core.c:1725 msleep(zone, ZONE_LOCKPTR(zone), PVM, "zonedrain", 1);` — sleeps **while holding a zdom lock** (`ZONE_LOCKPTR(z)` see `freebsd/vm/uma_int.h:584`); both branches of `freebsd/vm/uma_int.h:540-548 KEG_LOCK_INIT` and `:566-574 ZDOM_LOCK_INIT` use `MTX_DEF | MTX_DUPOK` (`:544`/`:547`/`:570`/`:573`); `:586-587 ZONE_CROSS_LOCK_INIT` uses `MTX_DEF`; `uma_core.c:5433 sx_sleep(uma_reclaim, &uma_reclaim_lock, ...)`. → G2-a truly needs **sleepable mutex + condition variable**, i.e. de-stubbing f-stack's entire `mtx` layer (`lib/include/sys/mutex.h:59-85` stubs `__mtx_lock`/`_mtx_lock_flags`/`mtx_init`/`mtx_destroy`/`mtx_owned`/trylock family; `kern_mutex.c` not in SRCS; `lib/ff_lock.c` only provides init/destroy shells). That is a project-level change far beyond this round.
2. **Nested lock holding → a single global lock must self-deadlock; making each lock real depends on `mtx_init` genuinely working.**【Code-verified】`freebsd/vm/uma_int.h:582 ZONE_LOCK(z) = ZDOM_LOCK(ZDOM_GET((z), 0))`, `:551-552 KEG_LOCK(k,d) = ({ mtx_lock(KEG_LOCKPTR(k,d)); KEG_LOCKPTR(k,d); })`; the `zone_alloc_bucket` → `keg_alloc_slab` path and the `zone_put_bucket` path hold keg / zdom locks respectively and nest. Replacing both with one non-recursive global spinlock self-deadlocks.
3. **Directly conflicts with DoD-5**: adding locks to paths that **have no locks today** almost certainly lowers throughput, while DoD-5 requires "post-lock-removal throughput not lower than pre-removal (within ±2% noise)". Making G2 "net-add locks" makes that gate self-contradictory.

#### 4.7.3 Why Not G2-c (keep the lock but shrink it to wrap only bucket exchange) and libuinet's "one lock per-cpu"

- **G2-c is a misnomer**: bucket exchange is **already outside the critical section** (§2.4 table: `uma_core.c:3859 critical_exit()` → `:3880 cache_fetch_bucket()`/`:3882 zone_alloc_bucket()`; `:3916 critical_exit()` → `:3917 zone_put_bucket()`). So "shrink the lock to only wrap bucket exchange" is effectively "move the lock to a place that has no lock today = add a lock", falling back to G2-a's rejection reasons 1, 2, 3 (especially nesting and `msleep`).
- **libuinet's `uinet_pcpu_locks[MAXCPU]` (one lock per-cpu) is equivalent to no lock in f-stack**: after G1, threads and slots are 1:1 and never migrate; per-CPU locks have **zero contention**, leaving only one `lock xchg` fixed overhead with no mutual-exclusion benefit. libuinet's lock makes sense because it allows threads to migrate between virtual CPUs (`_m17_B_external.md` §3.1(a): comment `XXX temporary until final pcpu approach is determined`; §3.2 rump also allows migration, so CAS mutual exclusion is required); f-stack's model is **stronger** and does not need it. **So it is explicitly excluded.**

#### 4.7.4 G2's Downgrade Steps (if M5 load test fails)

`_m17_A_codepath.md` appendix A.2 has listed "how much the lock-free contention window of the zone/keg slow path + `vsetzoneslab` is enlarged after removing `uma_crit_lock`" as **U8-perf: static analysis cannot conclude; runtime data required**. This doc accepts that boundary and **pre-designs three steps** so that an M5 failure needs no redesign:

| Step | Trigger (observable) | Action | Basis / risk |
|---|---|---|---|
| **L0** | — | G2-b, **independent commit** (commit-2), separately `git revert`-able without affecting G1 | §4.7.1 |
| **L1** | **Trigger criterion (wholly rewritten per reviewer's M4 gate "mandatory-2"; original criterion (a) pointed at dead code and is void)**: **(c) promoted to primary — direct evidence of hash-structure anomaly**: in-bucket self-loop / duplicate `up_va` / **node count inconsistent with registration count** (see §4.7.5's early-detection formula, **no need to wait for a crash**). **(a′) secondary — the crash point must fall in one of**: ① `vtoslab()` (`uma_int.h:77-88`, `:87return (NULL)`) returning NULL then dereferenced, specifically `freebsd/vm/uma_core.c:4930 slab = vtoslab((vm_offset_t)item);` → `:4938 if (lock != KEG_LOCKPTR(keg, slab->us_domain))`'s `slab->us_domain`; or ② callers of `uma_core.c:5819 return (vtoslab((vm_offset_t)mem));` dereferencing the return value. **(b) corroboration — concurrency**: appears only under `thread_mode=1 && nb_threads ≥ 2`; not reproduced with 1 thread or `thread_mode=0` at the same load. **⛔ "crash at `uma_int.h:101/102`" must no longer be used as a criterion**: those two lines belong to `vtozoneslab()`, whose **only callers are `freebsd/kern/kern_malloc.c:943/1039/1136`, and that file is not in `lib/Makefile` SRCS (HEAD grep of `kern_malloc` zero hits; `lib/kern_malloc.o` does not exist) → `vtozoneslab()` is dead code in this build and those lines never execute**【Code-verified】. So what gate-design E9 called "ambiguity" is actually "**unreachable**"; the original criterion can never trigger | add a **dedicated** global spinlock (new variable, e.g. `uma_page_hash_lock`) **only to f-stack's own writer-side** `vsetzoneslab()` (`:105-126`), **touching no upstream lock macro** | smallest closure, **no nesting, no sleep** (the function body is only traversal + `malloc` + field writes + `LIST_INSERT_HEAD`). **But "just adding a lock" is not enough — implementation notes in §4.7.6** (reviewer G2-S2: compiler barrier / release store, and the tearing read in the `:115-118` "hit-then-modify" branch) |
| **L2** | L1 still fails, or L1 drops throughput below the DoD-5 threshold | `git revert` commit-2, **keeping G1**; write `uma_crit_lock`'s necessity back into the spec as a **conclusion** (DoD-2 allows "argue it cannot be removed with code-level basis + `reviewer` gate confirmation") | plan §6 DoD-2 original text |

**bounce discipline**: every failure of L0→L1→L2 counts as one M4 bounce; 3 accumulated bounces escalate to human decision per the convention; **no pass-with-disease**.

#### 4.7.5 L1's Early-Detection Formula (hash node count comparison, **no need to wait for a crash**)

The reviewer's M4 gate pointed out that judging a concurrent-insertion race solely by "crashing at some line" is both lagging and error-prone. So "**hash node-count comparison**" is set as the primary form of L1 criterion (c) — it directly determines "whether insertions were lost" **before any crash**.

**Detection principle** (basis in §6.2: this hash is **insert-only, never deleted**, so "registration count" and "actual node count" must be equal):

1. In `vsetzoneslab()`'s (`lib/include/vm/uma_int.h:105-126`) **insertion branch** (`:120-125`), add a diagnostic counter: `uma_page_inserts++` (use `__sync_fetch_and_add` during evaluation so the counter's own race does not mask the problem).
2. At a controlled point (e.g. in a probe before soak ends), traverse all `num_hash_buckets` (8192) buckets, sum actual node counts to get `n_actual`.
3. **Formula**: `n_actual == uma_page_inserts`.
   - `n_actual < uma_page_inserts` ⇒ **insertion lost** ⇒ L1 trigger (c) holds (concurrent race directly confirmed, no need to wait for a crash).
   - equal ⇒ no insertion loss (under that run's load).
4. Auxiliary criteria (done in the same traversal, very cheap): whether `up_va` repeats within a bucket; whether traversal self-loops (node count exceeding `uma_page_inserts` is abnormal).

**Nature**: this is **pure diagnostic code**, temporarily added only to evaluate whether L1 is needed, **entering no formal commit** (treated the same as the §8.3 probes). **【Not-verified】** not implemented this round (G2 has not reached the state needing L1).

#### 4.7.6 L1 Implementation Notes (reviewer G2-S2; **if L1 is adopted, both must be handled**)

**Adding a lock alone is insufficient to fix memory visibility and tearing reads**; when adopting L1, both of the following must be handled, otherwise "locked but still wrong":

1. **Writer-side publication needs a barrier / release store**: `:122-124` fills `up_va`/`up_slab`/`up_zone` first, then `:125` `LIST_INSERT_HEAD` publishes. Under x86-TSO **hardware** store ordering holds, but the **compiler** may reorder these plain stores (they have no dependencies between them). So at least a compiler barrier (`__compiler_membar()` / `atomic_thread_fence_rel()`) is required, or write `list_entry.le_next` as a release store. **This doc previously argued only hardware ordering without mentioning compiler ordering; corrected here.**
2. **The "hit-then-modify" branch has a tearing read**: `:115-118`'s `up->up_slab = slab; up->up_zone = zone;` is **in-place overwrite of an already-published node**. The read side `vtoslab()` (`:83-86`) may, between those two stores, read a combination of `up_slab` and `up_zone` **that does not belong to the same update**. **Adding a lock only on the writer side cannot eliminate this tearing** (the reader holds no lock). If L1 is adopted, one must decide: **(i)** the read side also enters the same lock; **(ii)** or change to "write new node + atomically replace pointer" publish-style update; **(iii)** or argue that in this build this branch is actually not triggered (**must be verified first**: whether `vsetzoneslab()`'s repeated registration of the same `va` actually happens — this doc has **not verified**).
   - Supplementary fact: `vtoslab()` only returns `up_slab`, **does not read `up_zone`** (`:85`), and the only `up_zone` reader, `vtozoneslab()`, is dead code in this build (§4.7.4's ⛔ note) ⇒ **that tearing read has no actual consumer in the current compile set**. This makes (iii) the cheapest option, but **during implementation one must re-verify `kern_malloc.c` is still not added to SRCS**. **【Code-verified】+【Not-verified (forward-looking)】**

#### 4.7.7 G2 Independence Requirement (hard)

- G2 **must** be an independent commit (commit-2), and `git revert`ing it must return the code to the **runnable** state of "G1 effective + global lock still present".
- Therefore G2's diff surface is limited to **2 files**: `lib/include/vm/uma_int.h` (`:45-52`) and `lib/ff_glue.c` (`:146`). **No other change may be mixed into commit-2.**
- The G1 commit (commit-1) **must not** touch `uma_crit_lock` as a side change: otherwise an G2 failure cannot be reverted alone and would also discard G1's gains.

### 4.8 `thread_mode=0` Zero-Regression Guarantee (D7)

| Guarantee point | Mechanism | Validation |
|---|---|---|
| `mp_ncpus`/`mp_maxid`/`all_cpus` | §4.3.1's `nb_cpus = thread_mode ? nb_threads : 1` → `mp_ncpus=1`, `mp_maxid=0`, `all_cpus` only bit 0, **value-identical** to HEAD (`:294 CPU_SET(0,&all_cpus)`, `ff_glue.c:140 mp_ncpus = 1`, `:145 mp_maxid` BSS 0) | DoD-4's `thread_mode=0` 1-process / 2-process comparison |
| pcpu cpuid (**main-thread path**, `ff_freebsd_init`) | §4.3.4's `thread_mode ? ff_cur_proc_id() : 0` → always 0 (**this is exactly what C2's correction is about**) | DoD-1 probe under `thread_mode=0` must print `dense_idx=0`, `pc_zpcpu_offset=0` |
| pcpu cpuid (**`main_loop` path**, `ff_dpdk_if.c:2649`, gate-design E2 requires completeness) | §4.4 change 1's `thread_mode ? qconf->proc_id : 0` → always 0. **Double insurance**: even if the gating fails, `ff_stack_thread_init()` inside `main_loop` returns early due to `__thread ff_stack_inited` (`ff_freebsd_init.c:82`, set to 1 at `:348` in the main thread), **the argument is never used**. **But this is fragile coupling**: in `thread_mode=0`, `lcore_conf[].proc_id` is the **process number** (`ff_dpdk_if.c:460`, secondary=1/2/…); once the gating is removed **and** the early-return mechanism changes (e.g. `ff_stack_inited` made global, or `main_loop` re-inits under `thread_mode=0`), a secondary process immediately hits the `mp_maxid==0` upper-bound check with `cpuid=1` | **static inference not accepted**: DoD-4 (§7.4) explicitly requires `thread_mode=0` **1-process and 2-process both measured**, confirming no `ff_pcpu_thread_init: cpuid ... out of range` in the logs; DoD-1 criterion ⑧ requires the secondary process to also print `dense_idx=0` |
| `curcpu` | `PCPU_GET(cpuid)` = `pcpup->pc_cpuid` = 0 → **same value** as the original literal 0 | same |
| `timeout_cpu` | single-stack thread, `__thread` and global have the same value | — |
| `MAXCPU` 1→1024 | only affects static array sizes and `sizeof(cpuset_t)` (8→128), **changes no single-process semantics**; full `SRCS` clean rebuild guarantees consistent definitions | DoD-3 (warnings not increased) + DoD-4 (throughput fluctuation ≤5%) |
| `-DSMP`'s CK `lock` prefix | single-process no concurrency → only tiny instruction overhead | DoD-4 throughput comparison |

**⚠The only point needing M5 confirmation**【Not-verified】: `-DSMP` makes `cpuset_t` 8→128 bytes and `MAXCPU`-related static arrays 1→1024 slots; theoretically a cache-locality impact. plan §5.1's `thread_mode=0` baselines are 209,946 / 209,367 req/s (1 process), 234,613 / 233,982 (2 processes); DoD-4 allows ≤5% fluctuation.

### 4.9 Alignment Check Table with D1~D9

| # | Constraint | This doc's landing | Status |
|---|---|---|---|
| **D1** | `MAXCPU ≥ N` is G1's hard precondition (`cpuid_to_pcpu[MAXCPU]` out-of-bounds write would overwrite the adjacent `cpuhead`; `ff_kern_timeout.c:730` panic; `pause_wchan[MAXCPU]`) | §4.1 (`-DSMP` → 1024) + §4.3.1's `nb_cpus > MAXCPU` panic | ✅ satisfied. **And correct C3**: `pause_wchan`'s UB does not exist today; `MAXCPU ≥ N` is only needed after the `curcpu` change |
| **D2** | `mp_ncpus`/`mp_maxid`/`all_cpus` triple set together, all before `uma_startup1()`; unsynced `mp_ncpus` causes the ipfw heap overflow | §4.3.1 (landing between `:291`~`:293`) + §4.3.2 (verdict `mp_ncpus = N`) | ✅ satisfied |
| **D3** | use the existing `lcore_conf[].proc_id` as the dense index; `ff_dpdk_if.c:2649` changes to `qconf->proc_id`; `ff_pcpu_thread_init()` actually uses the parameter | §4.4 change 1 + §4.3.3 | ✅ satisfied |
| **D4** | main-thread slot does not collide, and does not depend on "main lcore == `proc_lcore[0]`" | §4.3.4 (uses `ff_cur_proc_id()`, immune to `--main-lcore`) + §4.4 change 2 | ✅ satisfied, **with C2's `thread_mode` gating added** |
| **D5** | `timeout_cpu` must become `static __thread` | §4.6 | ✅ satisfied |
| **D6** | `ff_pcpu_thread_init()` adds a runtime upper-bound check (because `subr_pcpu.c:88`'s KASSERT is compiled out) | §4.3.3 (`cpuid < 0 \|\| cpuid > mp_maxid` → `panic`) | ✅ satisfied (upper bound uses runtime `mp_maxid`, isomorphic to libuinet) |
| **D7** | `thread_mode=0` zero regression: `mp_maxid=0`, `mp_ncpus=1`, `all_cpus` only bit 0 | §4.8 | ✅ satisfied |
| **D8** | designer must choose among G2-a/b/c with reasons + downgrade steps + independent commit | §4.7 (verdict G2-b; §4.7.2/§4.7.3 reject a/c and the libuinet form item by item; §4.7.4 three steps; §4.7.5 independent-commit requirement) | ✅ satisfied |
| **D9** | `ff_pthread_create()` threads have `pcpup == NULL`; must be clarified as "unsupported usage" or a separate project | §5-1 (clarified as unsupported, and why **no** NULL fallback) + §4.5's risk note | ✅ satisfied (choose "document as unsupported"; not the "reserve K slots" option; reason in §5-1) |
| **(supplement 1)** | **`curcpu` hardcoded to 0 → UMA per-CPU cache not isolated with `pc_cpuid`** | §2.3 (mechanism) + §4.5 (method + 7 usage-point enumeration) | 🆕 new in this doc, **outside D1~D9 but a G1 mandatory item** |
| **(supplement 2)** | **`uma_page_slab_hash` must be initialized before `uma_startup1()`** (G1 breaks the existing implicit assumption "hash can be initialized after UMA startup") | §4.10 (mechanism + method) + §6.22 (recorded as a pre-existing defect exposed by G1) | 🆕 **runtime-measured finding** (`mp_maxid ≥ 2` startup SIGSEGVs), a G1 mandatory item |

### 4.10 `uma_page_slab_hash` Initialization Timing (Timing Hard Constraint H3; **runtime-measured finding, fixed**)

> **Source and evidence strength**: this is a G1 regression found by **runtime measurement** during M3 (the `thread_mode=1` 3/4-thread configs **100% reproduce** startup SIGSEGV), with **stronger evidence than the other static-analysis conclusions of this doc**. On-site characteristics: crashes in `uma_startup1() → zone_alloc_item() → zone_import()`, **inside the main thread, workers not yet started**, unrelated to virtio/RSS; 1/2-thread configs normal. **【Measured】**

#### 4.10.1 Nature Determination (wording must be precise)

**This is not a logic error of G1, but an existing implicit assumption of f-stack broken by G1** — the assumption is: "`uma_page_slab_hash` can be initialized **after** `uma_startup1()`". It **only holds when `mp_maxid == 0`**: then the zone-of-zones' item is small enough → slab is always single-page → `UMA_ZFLAG_VTOSLAB` is never set → f-stack's own `vsetzoneslab()` is never called during `uma_startup1()`, so an unready hash is fine. G1 raising `mp_maxid` to N−1 eliminates that premise.

#### 4.10.2 Root-Cause Chain (point by point)

| # | Link | Basis |
|---|---|---|
| 1 | zone-of-zones' item size grows linearly with `mp_maxid`: `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache) * (mp_maxid + 1) + sizeof(struct uma_zone_domain) * vm_ndomains` | `freebsd/vm/uma_core.c:3179-3182`【Code-verified】. Each additional CPU **+128 bytes** (`sizeof(struct uma_cache) == 128`, verified by the §7.1 probe-measured `uma_cache` slot distance `0x80`【Measured】; note upstream `uma_int.h:280-281`'s comment "pads perfectly into 64 bytes" **conflicts with the local measurement; measurement wins**) |
| 2 | `keg_layout()`'s upgrade loop raises the slab from 1 page to 2 pages when efficiency is not enough: `:2440for ( ; ; i++)` → `:2441-2442 slabsize = ptoa(i)`; `:2466-2469`'s exit condition is "`kl.eff >= UMA_MIN_EFF`（`:2262`）**or** `!multipage_slabs` **or** `slabsize >= SLAB_MAX_SETSIZE*rsize` **or** carries `UMA_ZONE_PCPU\|UMA_ZONE_CONTIG` flag" → zone-of-zones **does not carry** the PCPU/CONTIG flags, so it really upgrades to multi-page | `freebsd/vm/uma_core.c:2436-2472`【Code-verified】 |
| 3 | after the slab becomes 2 pages, `UMA_ZFLAG_VTOSLAB` is set: `:2486-2491 if ((uk_flags & UMA_ZFLAG_OFFPAGE) != 0 \|\| (keg->uk_ipers - 1) * rsize >= PAGE_SIZE) { ... keg->uk_flags \|= UMA_ZFLAG_VTOSLAB; }` — the condition **never holds at single page, holds at two pages** | `freebsd/vm/uma_core.c:2486-2491`【Code-verified】 |
| 4 | `VTOSLAB` makes `keg_alloc_slab()` call f-stack's own `vsetzoneslab()` page by page **during `uma_startup1()`** | `freebsd/vm/uma_core.c:1822-1825` (registers page by page for `i < uk_ppera`)【Code-verified】 |
| 5 | while `vsetzoneslab()` uses `uma_page_slab_hash` / `uma_page_mask` directly, **with no NULL check** | `lib/include/vm/uma_int.h:107-126` (`:112 &uma_page_slab_hash[(va >> PAGE_SHIFT) & uma_page_mask]`)【Code-verified】 |
| 6 | but those two globals were originally allocated **later** than `uma_startup1()` in `lib/ff_freebsd_init.c` → **NULL dereference** | HEAD `lib/ff_freebsd_init.c:304-306` (after `:301 uma_startup1()`)【Code-verified】 |

**⚠ Honest boundary (keep `coder`'s wording strength; must not overstep)**: this doc **only asserts the mechanism holds + measured thresholds (`mp_maxid ≥ 2` necessarily crashes, `mp_maxid ≤ 1` does not)**; it does **not give an arithmetic derivation of "exactly N=3 overflows"**. Reason: `keg_layout_one()` for `UMA_ZFLAG_INTERNAL` format does `slabsize += PAGE_SIZE` and counts the inline slab header via `slab_ipers_hdr()`; manual derivation is error-prone. **No arithmetic threshold without runtime verification may be written into this doc.**【Not-verified】

#### 4.10.3 Method (landed)

Move the initialization of `uma_page_slab_hash` / `uma_page_mask` **wholesale to before `uma_startup1()`**. The order after landing (measured in the current workspace):

```
lib/ff_freebsd_init.c:380-382   num_hash_buckets = 8192; uma_page_slab_hash = kmem_malloc(...); uma_page_mask = ...;
lib/ff_freebsd_init.c:385       bootmem = kmem_malloc(boot_pages * PAGE_SIZE, M_ZERO);
lib/ff_freebsd_init.c:387       uma_startup1((vm_offset_t)bootmem);
```

**Feasibility basis**: that `boot_pages` `kmem_malloc()` was already **before** `uma_startup1()` (HEAD `lib/ff_freebsd_init.c:299`), directly proving **`kmem_malloc` is usable before UMA startup**; so moving another `kmem_malloc` to before the same position introduces no new dependency.【Code-verified】

**Comment requirement**: this site **must** have a comment (a "timing constraint impossible to understand without a comment"), but limited to **≤3 lines**, only explaining "must be before `uma_startup1()`: once `mp_maxid > 0`, zone-of-zones grows → slab becomes multi-page → `VTOSLAB` set → `vsetzoneslab()` is called during `uma_startup1()`". The current landed version's `:376-378` three-line comment meets this requirement.

**Also merge into §4.3.1's timing-hard-constraint family**: H1 (zone sizes fixed before `uma_startup1`), H2 (`mp_maxid` paired with `UMA_ZONE_PCPU`), **H3 (this section: `uma_page_slab_hash` must be before `uma_startup1()`)**. The three together form "G1's startup-timing contract".

**One benign pre-existing issue (not changed this round, only registered)**: `:381`'s allocation size is written as `sizeof(struct uma_page) * num_hash_buckets`, but the array element type is `struct uma_page_head` (`lib/include/vm/uma_int.h:74-76`, only 1 pointer = 8 bytes), not `struct uma_page` (`:67-72`, 4 fields = 32 bytes) → **over-allocates about 4x** (8192 buckets waste ~192 KB). This is a **pre-existing writing** (HEAD `:305` already so), only extra memory, no error; **not changed this round** (changing it is unrelated to G1 and enlarges the diff).【Code-verified】

---

## 5. Explicitly Not Done (Must Be Honest Boundaries)

### 5-1 `ff_pthread_create()`-Created Threads: Clarified as Unsupported Usage (D9)

- Mechanism【Code-verified】: `lib/ff_thread.c:33-45ff_pthread_create()` wraps `pthread_create`; the child thread's `ff_start_routine` (`:21-30`) does only `ff_set_thread(p_data->parent)` (`:16-19`), **does not call `ff_pcpu_thread_init`** → the child's `pcpup` is NULL.
- Consequence (also **pre-existing**, not introduced by G1): such threads **already crash today when entering any `ff_*` path using SMR/`PCPU_GET`** (`zpcpu_get()` dereferences `pcpup->pc_zpcpu_offset`); this round additionally makes **any UMA fast-path entry crash**.
- Design verdict: **do not provide a general NULL fallback**. Reasons: ① a fallback would make unsupported usage silently runnable while sharing slot 0 — exactly T1's problem — and would disguise the defect as a supported path; ② allocating a pcpu lazily for such threads introduces cross-thread slot-sharing semantics, conflicting with G1's core invariant. **fail-fast is a deliberate choice** (see §4.5's risk-note (ii)).
- Documentation: `01`-style terminology doc clarifies "application-side multi-threading ≠ stack-side multi-threaded run model" (§1-4 in this doc): threads created by `ff_pthread_create` **must not** call `ff_*` stack APIs; correct usage is one dedicated f-stack thread (or one process) per instance. **【Not-verified】** whether a formal runtime guard should be added (e.g. panic at `ff_pcpu_thread_init` when `pcpup != NULL`); leave to M6 spec decision.

### 5-2 counter(9) De-per-CPU-ization (Known Deviation, Not Changed This Round)

- `lib/include/amd64/include/counter.h:38-62` completely removes the per-cpu dimension (`counter_enter/exit` no-ops `:38-39`; `counter_u64_add_inline` `*c += inc` `:56-62`; `counter_u64_fetch_inline` `*p` `:43-47`), and `freebsd/kern/subr_counter.c` has **no `mp_maxid`/`CPU_FOREACH`/`zpcpu`** (only `:63 uma_zalloc_pcpu(pcpu_zone_8,...)`).
- G1 raising `mp_maxid` makes per-CPU slots **for all zones** (including `pcpu_zone_8` the counter backing store) go from 1 to N; `counter_u64_add` writes slot 0 only. **No out-of-bounds**; but it is cross-thread writes to the same slot → stat contention, and `counter_u64_fetch` reads only slot 0 → **counters under-count when other threads share them**. **Known deviation, not fixed this round** (fixing counter requires re-introducing the zpcpu dimension and per-zone slot traversal in subr_counter.c — a separate change with no relation to G1/G2).

### 5-3 ipfw DPCPU "Hazard Pointer" Alias (Cannot Be Fixed This Round)

- `freebsd/netpfil/ipfw/ip_fw_dynamic.c:224-226`, `:3236-3240`: `dyn_hp_slots = malloc(mp_ncpus * sizeof(void *), ...)` with `DPCPU_PTR(dyn_hp_slots)` resolving through `dpcpu_off[0] == 0`.
- Since `dpcpu_init()` has **no callers** in this build (M1-A U15), **all CPU slots alias each other** — a pre-existing semantic deviation, and a **conditional risk**: only if a dynamic-state object gets freed while the same slot is being re-used by another CPU would a wrong-read of `dyn_hp_cache` occur; in f-stack no `cpufn_free()` releases CPU slots (`ip_fw_dynamic.c:2261-2275` only adds (`:2271`) to the cache, never deletes), so in practice it may not trigger. **Not fixed this round** (§6.3), recorded as a memory-safety boundary; also note `ip_fw_dynamic.c` IS compiled (`FF_IPFW=1`, `lib/Makefile:44/601`).

### 5-4 CK RMW `lock` Prefix (Incidental Fix by Candidate A, Perf to Be Measured)

- `_m17_gate_plan.md` §8.3: `ck_md.h:95 CK_MD_UMP` fails → CK's RMW primitives regaining the `lock` prefix. Only `ip_fw_dynamic.c`'s `ck_pr_inc_32`/`dec_32`/`or_32`/`xor_32` are substantively affected; `ck_queue.h`/`net/if.c` are all load/store; `ck_epoch` already stubbed. Whether it is a real **perf** issue must be measured at M5 (DoD-4's ipfw-focused soak, or explicitly testing under high concurrency).

### 5-5 DPDK `rte_mempool` Uses the lcore-id Index Space (Unaffected, Boundary Clarified)

- `rte_mempool`'s per-lcore cache is indexed by `rte_lcore_id()` (a different, sparse space); f-stack passes `-c` (coremask) via `lib/ff_config.c:1151-1154`; `nb_mbuf` scales with `nb_threads` (`ff_dpdk_if.c:526-527`). G1's dense `proc_id` does not interact with it; per-lcore caches remain intact.

### 5-6 What This Round Does NOT Change (list)

1. **UMA zone/keg/bucket slow paths**: unchanged (all `mtx` still stubbed; bucket exchange still outside the critical section). §6.1.
2. **SMR algorithm itself**: unchanged (its own `critical_enter` is a no-op under f-stack, §2.4). Only the slot dimension changes.
3. **netisr dispatch policy**: stays DIRECT (there is no other choice under f-stack; RSS undefined; the `#ifdef RSS` blocks are not compiled). §6.15/§5-9.
4. **counter(9)**: not fixed this round (§5-2).
5. **tcp_hpts structure**: `mp_ncpus=N` makes instance count 1→N as a side effect; the callout-hanging semantic mismatch is registered (§6.19) but not structurally redesigned this round.
6. **`cpuset_t` ABI change**: with `-DSMP`, `cpuset_t` 8→128 bytes; compiled objects all re-built with consistent definitions (no cross-`.o` tearing); `HOST_SRCS` don't include kernel headers (§3.3).

---

## 6. Risk List (Per DoD-6, Each Risk Has an Owner and Fallback)

> **All risks are recorded in this document's §6 and are [statically derived]** unless explicitly marked 【Measured】. When a claim's evidence level is insufficient, it must be marked 【Not-verified】 rather than being silently treated as a fact. Owner = the milestone responsible for closing it.

| # | Risk | Severity | Evidence | Owner | Fallback/action | Status |
|---|---|---|---|---|---|---|
| **6.1** | UMA zone/keg slow path is lock-free after G2 removes `uma_crit_lock`; two threads entering `zone_alloc_bucket`/`zone_put_bucket`/`keg_alloc_slab`/`keg_free_slab` concurrently | Medium (pre-existing; G2 widens the window) | §4.7.2: bucket exchange **already outside** the critical section (`uma_core.c:3859/3916`), so the window already exists at T1; **no new window** | M4 | M4 gate "mandatory-2"; §4.7.4's L1/L2 steps; soak (`-t8 -c400 -d60s`) | **to be observed at M5 (DoD-4)** |
| **6.2** | f-stack's own `uma_page_slab_hash` (insert-only, never deleted) concurrent `LIST_INSERT_HEAD` under G2 → lost insertions → `vtoslab()` returns NULL → dereference NULL (note: `kern_malloc.c` callers of `vtozoneslab` are not compiled; see §4.7.4's ⛔ note) | High | `lib/include/vm/uma_int.h:105-126` (writer side has no lock); G1 makes the zone-of-zones multi-page so `vsetzoneslab` is genuinely active (§4.10) | M4 | §4.7.4's L1 (dedicated `uma_page_hash_lock` + §4.7.6's two items) / L2 (revert); §4.7.5's early-detection formula | **to be observed at M5 (DoD-4)** |
| **6.3** | ipfw DPCPU "hazard pointer" slot alias (pre-existing) | Medium (conditional) | §5-3; `ip_fw_dynamic.c:2086-2091 CPU_FOREACH` iterates `mp_maxid+1` slots but the array is 1 slot if `mp_ncpus=1` (fixed by §4.3.2's `mp_ncpus=N`) | M3 | §4.3.2's `mp_ncpus=N` already fixes the overflow; slot-alias semantics deviation remains, recorded | D2's overflow fixed; alias remains (§5-3) |
| **6.4** | `tcp_hpts` `HPTS_TRYLOCK` always true → no real mutual exclusion; two workers picking the same hpts (pre-existing, worse at T1, lighter at T2) | Medium | `lib/include/sys/mutex.h:74-76` constant 1; §4.3.2's residue; U16-a closed as active | M5 | observe `rp_num_hptss`/`p_on_queue_cnt` at M5; not fixed this round; registered in §6.19 | **【Not-verified】** occurrence rate; to be observed at M5 |
| **6.5** | **This doc's corrections to M1 docs (C1~C3)** — cross-doc consistency | — | §0.3 | gate-design already passed the C-corrected version | — | ✅ closed |
| **6.6** | `ff_cur_proc_id()` (`ff_dpdk_if.c`) calls `rte_lcore_id()` on the EAL main lcore; correct only if the main lcore is in the coremask | Low (contradicts U6-a's "not guaranteed") | §4.3.4 (U6-a downgraded to observation item) | M3 | DoD-1 probe on the main thread must print a valid `dense_idx` | ✅ closed |
| **6.7** | `-DSMP` increases `sizeof(cpuset_t)` 8→128; any TU with a **kernel header context** that still preprocesses `MAXCPU` inconsistently | Low | `_m17_C_buildprobe.md` §2.2: `error 0`, `warning 51` — measured no inconsistent-definition errors; full clean build | M3 | DoD-3's warning non-increase + full-tree clean build | ✅ closed at compile time; runtime M5 |
| **6.8** | Worker threads entering the UMA fast path **before** their pcpu is built (bootstrap window) — the `pause_wchan[curcpu]` NULL deref | High (introduced by G1) | §4.5 risk-note (i); `lib/ff_freebsd_init.c:106-107` ordering | M3 | §4.5's targeted fallback `pause_wchan[pcpup != NULL ? curcpu : 0]` | ✅ closed by the M3 landed change |
| **6.9** | netisr has an unused DPCPU-alias issue (independent of `curcpu`) | Medium | §6.15 | — | not fixed this round, recorded | open (boundary) |
| **6.10** | callout `callout_reset_sbt_on()` valid-cpu check at `:730-733`: after `curcpu` per-thread, other kernel TUs passing a **non-dense** cpuid may `panic("Invalid CPU in callout %d")` | Medium | §4.6; M1-A U11.3 (netisr/`tcp_timer.c:237/249` fallback paths both return bounded values) | M3 | `MAXCPU=1024` already satisfies; also make `timeout_cpu` `__thread` (§4.6); DoD-4 logs | **【Not-verified】** observed at M5 |
| **6.11** | UMA per-CPU cache slot distance under `mp_maxid>0` is not 4096 but `uz_size` granularity | Low (test-methodology) | §4.10.2 step 1 (measured `uma_cache` slot distance `0x80`) | M5 | DoD-1 criterion ⑥ uses the **measured** `&uz_cpu[1]-&uz_cpu[0]`; do not assume 4096 | ✅ closed (measured 128) |
| **6.12** | `pktmbuf_pool` / DPDK per-lcore cache mixed with the UMA mbuf zone: **two pools coexist** (DPDK pool allocates the header? — no, DPDK pool is pure packet buffer; UMA mbuf zone is f-stack's own) — no change, only boundary | — | §5-5; `lib/Makefile:346/372-373` `kern_mbuf.c`/`uipc_mbuf.c` still compiled | — | not changed this round | open (boundary) |
| **6.13** | `malloc()` with `M_WAITOK` inside the bootstrap window may go to `pause` before pcpu is ready — **the same bootstrap-window issue** | High | §4.5 (i) | M3 | §4.5's targeted fallback | ✅ closed |
| **6.14** | calling `critical_enter` (the `uma_crit_lock` macro) from `ff_freebsd_init.c` (a kernel TU including `vm/uma_int.h` but with no callers) | Low | §2.4: `grep -c` = 0 | — | not changed this round | closed |
| **6.15** | **netisr `curcpu` usage correctness** (concluded: no netisr core-selection effect) | Low | §4.5 supplement: `nws_count == 1` early-return path; RSS undefined so hybrid not compiled | M3 | not changed | closed |
| **6.16** | **`struct pcpu` size constraint**: `freebsd/amd64/include/pcpu_aux.h:47_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE)`; adding fields is forbidden | High (constraint) | §4.3.3: measured 4096 both before/after `-DSMP`; adding **any** field breaks compile | M3 | do not add fields; use existing fields | ✅ closed |
| **6.17** | **`cpuid_to_pcpu[]`/`cpuhead` concurrency**: M3 keeps `pcpu_init()` inside `init_lock`; a future shrinking of `init_lock` must revisit | Medium | M1-A U5.1 | M3/M6 | keep `init_lock` scope unchanged this round | ✅ closed (unchanged) |
| **6.18** | **`sysctl`/stats paths (`CPU_FOREACH`)** under `mp_maxid>0` | Low | H1/D2 basis (§4.3.1) | M3 | `all_cpus` all bits set (§4.3.1); `uz_cpu[]` sized by `mp_maxid+1`; no overflow | ✅ closed |
| **6.19** | **tcp_hpts instance 1→N side effects** (R6 in the native-mt concurrency risk list): ① `tcp_pace.rp_num_hptss == mp_ncpus` memory growth (≈2.34 MiB × (N−1)); ② **all N hpts instances' callouts hang on the main thread's callwheel** (because f-stack's callwheel is per-thread, `cc_cpu` __thread, while hpts is a global-timer-driven structure; whether the main thread's callwheel is driven **by each worker's `main_loop`** through `rte_timer_manage()` is the semantic mismatch); ③ `p_mtx` no real mutual exclusion (HPTS_TRYLOCK constant true) | Medium-High | §4.3.2 residue + U16-a | M5 | M5 must quantify memory growth (§7.4-②) and observe `p_on_queue_cnt`; structural redesign is out of scope this round | **【Not-verified】** |
| **6.20** | **callout `curcpu`/`CC_CPU(cpu)` ignores the argument**: after the `curcpu` change, all kernel TUs passing any `cpu` value still route to `&cc_cpu` (this thread's); whether any callout is **expected to run on a different thread's wheel** but actually runs on this thread's | Medium | §4.5 table #3 + M1-A U11.3 | M3 | `callout_reset_sbt_on()`'s `cpu` parameter check at `:730-733` (bounded) + `CC_CPU` ignores; no behavior change vs HEAD | closed (same behavior as HEAD) |
| **6.21** | **line-number drift between the spec and the actual landed code** (reviewer flagged 4 `file:line` errors) | — | §8.2 file list re-verified by reviewer | — | corrected in the final review round; this doc's `file:line` all re-verified at M6 | ✅ closed |
| **6.22** | **"globals used during `uma_startup1()` but initialized after it"** (this round's measured H3 was one instance; whether others exist) | High (unknown) | §4.10 (measured); M1-A U3.4 originally ruled "no other same-pattern global", but **after `mp_maxid>0` the zone-of-zones multi-page path executes more code, so the conclusion must be re-audited** | M3 | §4.10's measured fix; re-audit the "used-before-init" of the multi-page path once at M3 | **【Not-verified】** (must re-audit once at M3) |
| **6.23** | **Intermittent process crash under wrk stress (non-deterministic)** — observed during physical-machine manual verification (2026-08-06): functionality and performance tests both pass, but under repeated wrk runs the process occasionally crashes and exits (not every run; requires multiple runs to reproduce) | Medium (non-blocking for release, but should be investigated before production) | Physical-machine manual verification; excluded as a deterministic G1/G2 regression (all 1/2/3/4-thread + `thread_mode=0` tiers pass functionally and on throughput, see §7.4/§7.5) | Follow-up | **Not fixed this round.** Needs multiple reproductions → capture crash stack → root-cause. Possible causal links to §6.1 (lockless slow-path window), §6.3 (ipfw DPCPU aliasing), §6.19 (tcp_hpts 1→N callout ownership mismatch R6); client-side or hypervisor transient interference also not excluded (1-hour env drift of 2.6%~3.2% observed, see `_m17_F_runtime.md` Part 6 / Z7.2) | **【Not-verified】** |

---

## 7. Validation Plan (M5 Runtime Matrix; Standard Grade, All Actually Executed)

### 7.1 Slot-Isolation Verification (DoD-1) — Must Be Actually Measured

**Purpose**: verify G1's core invariant. Add temporary probes (or `ff_log`) in `ff_pcpu_thread_init()` (`lib/ff_freebsd_init.c:106-107`) printing per thread: `tid`, `dense_idx`, `pcpup->pc_cpuid`, `pcpup->pc_zpcpu_offset`, `mp_maxid`, and at an SMR usage point print each worker's `&zpcpu_get(ipi_smr)->c_seq`.

**Probe form**: a single-line `ff_log` (via `rte_log` or `printf`; must be removable at M6, `grep` zero hits).

**Judgment criteria (DoD-1) — each line printed by each thread must satisfy**:

| Criterion | Formula | Notes |
|---|---|---|
| ① | `pc_cpuid == dense_idx == curcpu` | the three must be equal per thread |
| ② | `pc_zpcpu_offset == 4096 * dense_idx` | `zpcpu_offset_cpu(cpu) = 4096*cpu` |
| ③ | pairwise `c_seq` address difference `== 4096 * Δidx` | and all within `[base, base + (mp_maxid+1)*4096)` |
| ④ | SMR slot distance == `mp_maxid+1` × 4096 | create `smr`'s backing zone sized by `mp_maxid+1` |
| ⑤ | `&zone->uz_cpu[i]` distance == `sizeof(struct uma_cache)` (**measured 128**, not 4096!) | must use the measured distance, see §4.10.2 |
| ⑥ | `uk_ppera == mp_maxid+1` | `keg_layout`'s `pages *= mp_maxid+1` |
| ⑦ | `all_cpus` has bits `0..mp_maxid` | `CPU_FOREACH` covers all slots |
| ⑧ | **`thread_mode=0` main and secondary processes: `dense_idx == 0`**, no `out of range` panic | zero-regression |

**Probe cleanup**: after M5, all probes removed (`grep -rn "DBG\|dense_idx\|ff_pcpu" lib/ example/` zero hits, or the used ones are converted to `ff_log` permanent stats); see §8.3.

### 7.2 Functional Matrix (V3)

- `thread_mode=1` × 1/2/4 threads × multiple rounds `wrk -t5 -c100 -d10s` (via `ssh f-stack-client` hitting `9.134.214.176`); every round no socket error, no crash, throughput grows with thread count.
- `thread_mode=0` 1 process / 2 processes comparison (zero regression).

### 7.3 Soak (V4)

`ssh f-stack-client "/data/wrk/wrk -t8 -c400 -d60s http://9.134.214.176:80/"` — compare with the previous round's 497,043 req/s; zero errors, process alive, throughput not lower than the baseline.

### 7.4 Additional Measurements (this round's specific items)

| # | Item | Criterion |
|---|---|---|
| ① | pre/post-`uma_crit_lock`-removal throughput comparison (same conditions, ≥3 rounds median, ±2% noise) | post-removal ≥ pre-removal (DoD-5); if lower, evaluate L1/L2 |
| ② | `mp_ncpus=N` memory growth (measure `tcp_pace.rp_num_hptss` value + RSS/hugepage with 1 vs 4 threads) | linear, acceptable; recorded in `_m17_E_runtime.md` |
| ③ | `thread_mode=1` 4-thread (currently the 3/4-thread config had the H3 startup crash — must not crash after the fix) | startup + load both pass |
| ④ | hpts spread observation (`rp_num_hptss`, per-instance `p_on_queue_cnt`) | record; no conclusion forced (§6.4/§6.19) |
| ⑤ | `ck_pr_*` `lock`-prefix impact (optional, ipfw-focused) | record (§5-4) |

### 7.5 Zero-Regression and Memory-Safety Regression Coverage

- `thread_mode=0` 1/2-process throughput within ±5% of the baseline (plan §5.1: 209,946/209,367; 234,613/233,982).
- No `ff_pcpu_thread_init: cpuid ... out of range` in logs (DoD-4).
- Soak zero crashes (DoD-4).

---

## 8. Milestones and Work Breakdown (M3/M4/M5/M6)

### 8.1 Milestone Overview

| Milestone | Content | Owner | Gate (must be a different agent) |
|---|---|---|---|
| **M0** | this plan.md | leader | `gate-plan` |
| **M1** | three parallel research tracks (A code-path probing / B external / C compile evidence) | `res-code`/`res-web`/`res-build` | leader aggregation + `gate-design` |
| **M2** | solution verdict + detailed design → this spec doc | `designer` | `gate-design` (evidence chain, file:line, boundary wording) |
| **M3** | G1 coding: SMP view + dense index + `curcpu` per-thread + `timeout_cpu` `__thread` + `uma_page_slab_hash` timing; `make clean` then full build | `coder` | `reviewer` (concurrency/memory/regression/comment conventions) |
| **M4** | G2 coding: remove `uma_crit_lock`; `make clean` then full build | `coder` | `reviewer` (incl. "mandatory-1/2") |
| **M5** | runtime matrix (§7) incl. pre/post-lock throughput | `tester` | `reviewer` (data credibility) |
| **M6** | doc finalization + gate-doc + two commits | `designer` + `gate-doc` | `gate-doc` (each `file:line`, wording within evidence boundary; commit scope) |

### 8.2 Commit Plan (Two Independent Commits, DoD-7)

**commit-1 (G1, 8 files)**:

| File | Change | Section |
|---|---|---|
| `lib/Makefile` | `CFLAGS+= -DSMP` | §4.1 |
| `lib/ff_glue.c` | add `smp_topo()` stub | §4.2 |
| `lib/ff_freebsd_init.c` | triple set + `panic` + `uma_page_slab_hash` timing move + `ff_pcpu_thread_init()` uses param + upper-bound check + main-thread slot number | §4.3, §4.10 |
| `lib/ff_dpdk_if.c` | `ff_cur_proc_id()` helper + `ff_stack_thread_init(thread_mode ? qconf->proc_id : 0)` | §4.4 |
| `lib/ff_dpdk_if.h` | declare `ff_cur_proc_id()` | §4.4 |
| `lib/ff_kern_timeout.c` | `timeout_cpu` → `static __thread` | §4.6 |
| `lib/include/sys/pcpu.h` | `curcpu` → `PCPU_GET(cpuid)` (+ keep `#undef curcpu`) | §4.5 |
| `lib/ff_kern_synch.c` | `pause_wchan[pcpup != NULL ? curcpu : 0]` bootstrap-window fallback | §4.5 |

**commit-2 (G2, 2 files)**:

| File | Change | Section |
|---|---|---|
| `lib/include/vm/uma_int.h` | `critical_enter/exit` → `do {} while(0)` + delete `extern volatile int uma_crit_lock;` (keep 3-line comment) | §4.7 |
| `lib/ff_glue.c` | delete `volatile int uma_crit_lock;` | §4.7 |

**Commit rules**: ① commit-1 must not touch `uma_crit_lock`; ② each commit must compile independently (`make clean` + full build); ③ `git add` before review `git diff`; `config.ini` local values not committed.

### 8.3 Debug Probes (Zero-Residue Rule)

- Evaluation-period probes: §7.1's slot-isolation probes (only during M3/M5, and §4.7.5's hash node-count diagnostic). **All removed before M6**, proven by `grep -rn "DBG\|dense_idx\|probe\|ff_pcpu" lib/ example/` zero hits.
- If probes need to be kept, they must be formalized as permanent `ff_log` stats under the `reviewer` gate, not ad-hoc prints.

### 8.4 Compile Validation (DoD-3)

- `cd lib && make clean && make -j$(nproc)` then `cd example && make clean && make`; **both zero errors**.
- **Warning baseline**: clean-build warning count of the unchanged HEAD `ff09a17b2`'s `lib/`+`example/` (M1-C measured `lib/` at 51); the changed state must not increase.

---

## 9. Evidence Index (Full File:line List; Data)

> All evidence below was verified by `read_file`/`grep`/`cc -E` during the writing period. Markers: 【Code-verified】 (opened directly), 【Measured】 (has output/logs), 【Not-verified】 (must not be used as verified facts).

**Spec-relevant file:line (HEAD baseline)**:

- `lib/Makefile`: `:219 CFLAGS+= -DFSTACK`, `:44 FF_IPFW=1`, `:179 HOST_C`, `:346/372-373 kern_mbuf.c/uipc_mbuf.c`, `:515 tcp_lro.c`, `:582 LIBKERN_SRCS`, `:584-586 rack.c/bbr.c`, `:601 ip_fw_dynamic.c`, `:650 uma_core.c`, `:305` (HEAD pre-change) `uma_page_slab_hash` init, `:287 SYSINIT(callwheel_init...)`, `:285 ff_callout_thread_init()`
- `lib/ff_freebsd_init.c`: `:85 __thread pcpup`, `:94-101` original comment, `:103-109 ff_pcpu_thread_init`, `:106-107`, `:170-217 ff_stack_thread_init`, `:177-178 ff_stack_inited early return`, `:82 static __thread int ff_stack_inited`, `:187`, `:207`, `:293 ff_pcpu_thread_init(0)`, `:294 CPU_SET(0,&all_cpus)`, `:299 bootmem kmem_malloc`, `:301 uma_startup1()`, `:304-306 uma_page_slab_hash init`, `:309 mi_startup()`, `:348 ff_stack_inited=1`, `:380-387 (workspace post-change) uma_page_slab_hash before uma_startup1`
- `lib/ff_glue.c`: `:132 volatile int ticks`, `:138-146 mp_* triple + uma_crit_lock`, `:146 volatile int uma_crit_lock`, `:1067-1078 malloc M_WAITOK pause`, `:1358-1396 ck_epoch stubs`
- `lib/ff_dpdk_if.c`: `:87 stop_loop`, `:89 freebsd_clock`, `:92 static __thread struct rte_timer freebsd_clock`, `:123 lcore_conf`, `:125 pktmbuf_pool`, `:126 lcore_conf[RTE_MAX_LCORE]`, `:177 msg_ring`, `:400-467 init_lcore_conf`, `:429-433 proc_id=ti`, `:460 proc_id=proc_id (non-thread_mode)`, `:526-527 nb_mbuf nb_threads`, `:643-660 init_dispatch_ring nb_lcores`, `:692-694 init_msg_ring nb_threads`, `:1009-1016 rss table size`, `:1062-1086 init_port_start`, `:1181-1196 init_clock`, `:1594 rte_eal_init`, `:1643-1651 proc_id<nb_procs`, `:1722 init_clock()`, `:1905 process_packets`, `:1964/1996 dispatch enqueue`, `:2049 dispatch dequeue`, `:2081-2089 kni reject`, `:2585 main_loop qconf`, `:2644 qconf=ff_cur_lcore_conf()`, `:2649 ff_stack_thread_init(rte_lcore_id())`, `:2657/2659 lock ops`, `:2660-2664 kni process`, `:2672-2826 while(1) body`, `:2770 rte_eal_mp_remote_launch`, `:2794 ff_tcp_hpts_softclock()`
- `lib/ff_dpdk_if.h`: new `ff_cur_proc_id()` declaration
- `lib/ff_dpdk_kni.c`: `:376-420 ff_kni_init`, `:379-386 primary-only kni_stat`, `:388-419 kni_rp/bitmaps by lcore_id`, `:422-449 ff_kni_alloc`, `:426 primary-only`
- `lib/ff_kern_timeout.c`: `:135 callwheelsize/mask`, `:180-182 cc_cpu + CC_CPU/CC_SELF`, `:183 __thread cc_cpu`, `:184 CC_CPU ignores arg`, `:187 timeout_cpu static`, `:190 static int timeout_cpu`, `:254 timeout_cpu=PCPU_GET(cpuid)`, `:339-349 callout_tick`, `:342 read-only ticks + write-only cc_softticks`, `:662 CC_CPU(timeout_cpu)`, `:720 callout_reset_tick_on`, `:730-733 cpu>=MAXCPU panic`, `:815 callout_reset_on c_cpu`, `:1061/1077 c_cpu=timeout_cpu`, `:1181 sysctl kern.callout_stat`, `:1252-1274 tcp_hpts interplay`, `:1291-1296 ff_tcp_hpts_softclock`, `:1212-1216 print only`
- `lib/ff_kern_synch.c`: `:59 static uint8_t pause_wchan[MAXCPU]`, `:105 pause_wchan[curcpu]`
- `lib/ff_memory.h`: `:82-95 struct lcore_conf`, `:104-111 ff_lcore_conf_idx/ff_cur_lcore_conf`
- `lib/ff_compat.c`: `:59 __thread pcurthread`, `:62 rootvnode`, `:64-65 allproc/allproc_lock`, `:80 seed`, `:90 adapter-only comment`, `:96-128 ff_adapt_user_thread_add/exit`, `:131-148 ff_switch/restore_curthread`, `:157-160 ff_init_thread0`
- `lib/ff_init_main.c`: `:96 proc0`, `:97 prison0`, `:98 thread0_st`, `:99 vmspace0`, `:100 initproc`, `:122-124 sysinit sets`, `:173-285 mi_startup`, `:188 if(sysinit==NULL)`, `:235-236 SI_SUB_LAST continue`, `:271 SI_SUB_LAST tick`, `:523 SYSINIT(p0init)`, `:586-590 worker cred (uifind/crget/prison0)`
- `lib/ff_thread.c`: `:16-19 ff_set_thread`, `:21-30 ff_start_routine`, `:33-45 ff_pthread_create`
- `lib/ff_syscall_wrapper.c`: `:225-226 msg_iov_tmp/len`, `:672-684 socket flags`, `:943 ff_socket`, `:1679 ff_accept4`
- `lib/include/sys/pcpu.h`: `:31-34 #undef curcpu + #define curcpu 0`
- `lib/include/amd64/include/pcpu.h`: `:33-53 PCPU_* redef`, `:40 #undef zpcpu_offset_cpu`, `:49 PCPU_GET`, `:55-67 curthread redef`
- `lib/include/vm/uma_int.h`: `:38 #include_next`, `:43 #undef UMA_MD_SMALL_ALLOC`, `:45 extern volatile int uma_crit_lock`, `:46-52 critical_enter/exit macros`, `:54-57 sleepq stubs`, `:59 _vm_map_unlock`, `:65 UMA_PAGE_HASH`, `:67-74 struct uma_page`, `:74-76 struct uma_page_head`, `:77-88 vtoslab`, `:83-86 vtoslab read`, `:87 return NULL`, `:101-102 vtozoneslab dead`, `:105-126 vsetzoneslab`, `:112 &uma_page_slab_hash[...]`, `:115-118 hit-then-modify`, `:120-125 insert branch`, `:122-125 fill then publish`, `:125 LIST_INSERT_HEAD`
- `lib/include/amd64/include/counter.h`: `:38-62 de-per-cpu`
- `lib/include/sys/mutex.h`: `:31-48 #undef spinlocks`, `:55-90 stubs`, `:57 DO_NOTHING`, `:59-76 lock/unlock stubs`, `:74-76 trylock constant 1`, `:85 mtx_owned(1)`
- `lib/include/sys/smp.h` (f-stack): `mp_ncpus`/`mp_maxid`/`all_cpus` declarations
- `lib/ff_lock.c`: rmlock no-ops
- `freebsd/sys/pcpu.h`: `:218 #define curcpu PCPU_GET(cpuid)`, `:221 UMA_PCPU_ALLOC_SIZE`, `:223 _Static_assert include`, `:234-236 zpcpu_offset_cpu`, `:237-239 zpcpu_offset`, `:249-252 zpcpu_get`, `:254-257 zpcpu_get_cpu`
- `freebsd/amd64/include/param.h`: `:60-66 MAXCPU 1/1024`, `:92-93 PAGE_SHIFT/PAGE_SIZE`
- `freebsd/amd64/include/pcpu_aux.h`: `:47 _Static_assert`
- `freebsd/kern/subr_pcpu.c`: `:76-77 dpcpu_off[MAXCPU]/cpuid_to_pcpu[MAXCPU]`, `:88-89 KASSERT`, `:91-92 cpuid_to_pcpu/cpuhead`, `:96 pc_zpcpu_offset`, `:100 dpcpu_init`, `:252 dpcpu_copy SMP`, `:270-277 pcpu_destroy`, `:274-276 STAILQ_REMOVE/cpuid_to_pcpu/dpcpu_off`
- `freebsd/vm/uma_core.c`: `:650 include uma_int.h`, `:1408 zone_dtor CPU_FOREACH`, `:1451/1464/3727/3744/3775/3817/3859/3891/3900/3916/3918/4541/4554/4558/4626/4649/4653/4827/4850/4872/4874 critical_enter/exit 21 sites`, `:1452/3738/3776/3818/3901/4534/4543/4595/4628/4803/4853 uz_cpu[curcpu] 11 sites`, `:1725 msleep`, `:1822-1825 vsetzoneslab per-page`, `:1957 #ifndef FSTACK`, `:1959 vm_page_alloc_noobj`, `:1970 MPASS bytes`, `:1975 cpu<=mp_maxid`, `:2082 #else`, `:2083-2089 page_alloc fallback`, `:2114/2116/2208 UMA_USE_DMAP`, `:2262 UMA_MIN_EFF`, `:2351-2356 KASSERT PCPU`, `:2436-2472 keg_layout upgrade`, `:2440 for(;;i++)`, `:2441-2442 slabsize=ptoa(i)`, `:2466-2469 exit condition`, `:2472-2478 pages*=mp_maxid+1, uk_ppera`, `:2486-2491 UMA_ZFLAG_VTOSLAB`, `:2546-2548 #ifndef SMP strip PCPU`, `:2577-2578/2588-2589 pcpu_page_alloc/free`, `:2873 zone_update_caches`, `:3179-3182 zsize`, `:3180 uz_cpu[mp_maxid+1]`, `:3494-3516 uma_zalloc_pcpu_arg`, `:3498/3508/3526 #ifdef SMP`, `:3505-3513 M_ZERO loop`, `:3521-3536 uma_zfree_pcpu_arg`, `:3859/3916 critical_exit outside`, `:3867-3874 comment`, `:3880 cache_fetch_bucket`, `:3882 zone_alloc_bucket`, `:3917 zone_put_bucket`, `:4930 vtoslab item`, `:4938 slab->us_domain`, `:5095-5127 CPU_FOREACH stats`, `:5433 sx_sleep`, `:5440 pause uma reclaim`, `:5589/5620/5674 uz_cpu stats`, `:5819 vtoslab mem`
- `freebsd/vm/uma_int.h` (upstream): `:280-281 comment pads 64 bytes` (**conflicts with local 128 measurement, measurement wins**), `:529 ZDOM_GET`, `:540-548 KEG_LOCK_INIT`, `:551-552 KEG_LOCK`, `:566-574 ZDOM_LOCK_INIT`, `:582 ZONE_LOCK`, `:584 ZONE_LOCKPTR`, `:586-587 ZONE_CROSS_LOCK_INIT`
- `freebsd/kern/subr_smr.c`: `:583-609 smr_create`, `:591 uma_zalloc_pcpu`, `:598-605 per-cpu init`, `:623-631 smr_init UMA_ZONE_PCPU`, `:432-440 smr_poll`
- `freebsd/sys/smr.h`: `:105-143 smr_enter`, `:106-160 SMR c_seq states`, `:109 critical_enter`, `:110 zpcpu_get`
- `freebsd/netinet/in_pcb.c`: `:583 ipi_smr`, `:615-617 UMA_ZONE_SMR`, `:1820-1888 UAF window relevant`, `:2743-2746 in_pcbjailed`
- `freebsd/netinet/tcp_hpts.c`: `:286 tcp_use_irq_cpu`, `:466-475 hpts_random_cpu`, `:569-579 tcp_hpts_lock`, `:575 rp_ent[tp->t_hpts_cpu]`, `:596-600 upstream comment`, `:605-606 t_hpts_cpu init`, `:1040-1099 hpts_cpuid`, `:1050 old value`, `:1056-1062 t_lro_cpu`, `:1059 return 0`, `:1064-1070 #ifdef RSS`, `:1085-1096 #ifdef NUMA`, `:1089 flowid%mp_ncpus`, `:1540/1542 tcp_set_hpts`, `:1559 end`, `:1564-1572 grp_cnt>1`, `:1566 CPU_ISSET(curcpu)`, `:1574-1587 tcp_choose_hpts_to_run`, `:1587 rp_ent[curcpu%rp_num_hptss]`, `:1599/1608 p_hpts_active guard`, `:1864 ncpus=mp_ncpus?:MAXCPU`, `:1867-1871 #ifdef SMP smp_topo else NULL`, `:1872 rp_num_hptss=ncpus`, `:1890 cpu_top==NULL grp_cnt=1`, `:2061 tcp_hpts_softclock=__tcp_run_hpts`, `:2095 free(grps)`, `:2117-2118 MOD_LOAD`, `:2142 DECLARE_MODULE`
- `freebsd/netinet/tcp_timer.c`: `:237/249 inp_to_cpuid fallback curcpu`, `:896/932 callout_reset_sbt_on`
- `freebsd/netinet/tcp_lro.c`: `:1210/1216 lro_last_cpu`
- `freebsd/netinet/tcp_subr.c`: `:2298 t_hpts_cpu=HPTS_CPU_NONE`
- `freebsd/netinet/tcp_var.h`: `:330 HPTS_CPU_NONE`
- `freebsd/netinet/tcp_lro_hpts.c`: `:577 t_lro_cpu assignment` (not compiled)
- `freebsd/net/if.c`: `:2908 ifioctl CURVNET_SET`
- `freebsd/net/route.c`: `:497/507 rt_getifa_fib`, `:751 rt_add_addr_clone`, `:756-757 rib_action`
- `freebsd/net/netisr.c`: `:151 NETISR_DISPATCH_POLICY_DEFAULT`, `:153 dispatch_policy`, `:169 netisr_maxthreads`, `:275-279 netisr_get_cpuid`, `:781-790 netisr_get_dispatch`, `:810 nws_count==1`, `:839 netisr_get_cpuid(curcpu)`, `:1146-1153 DIRECT branch`, `:1164 return before`, `:1172 cpuid!=curcpu`
- `freebsd/net/vnet.c`: `:336 curvnet=prison0.pr_vnet=vnet0`
- `freebsd/net/vnet.h`: `:176 curvnet=curthread->td_vnet`, `:247 CRED_TO_VNET`, `:398-458 !VIMAGE branch`, `:429 VNET_DEFINE≡t n`, `:442-444 VNET_SYSINIT ordinary`
- `freebsd/kern/uipc_socket.c`: `:829-833 so_vnet=vnet`, `:948 soalloc(CRED_TO_VNET(cred))`
- `freebsd/kern/kern_jail.c`: `:1814 pr_vnet=vnet_alloc`
- `freebsd/kern/kern_fork.c`: `:473-474 td_vnet`
- `freebsd/sys/jail.h`: `:449 jailed macro`
- `freebsd/sys/errno.h`: `:114 ENETUNREACH`
- `freebsd/sys/systm.h`: `:179-193 critical_enter inline`, `:186 #ifndef FSTACK`, `:485 pause`
- `freebsd/netpfil/ipfw/ip_fw_dynamic.c`: `:2086-2091 CPU_FOREACH dyn_hp_cache`, `:224-226 DPCPU_PTR`, `:2261-2275 cache add only`, `:3236 malloc(mp_ncpus)`, `:3240 DPCPU_PTR`
- `freebsd/kern/kern_malloc.c`: `:943/1039/1136 vtozoneslab` (**not in SRCS**)
- `freebsd/netinet/ip_id.c`: `:250/270 ip_id`, `:270 zpcpu_get(V_ip_id)`
- `freebsd/netinet/ip_output.c`: `:371 ip_fillid`
- `freebsd/sys/callout.h`: `:100-120 curcpu macro family` (macro bodies use `PCPU_GET(cpuid)`)
- `freebsd/kern/subr_taskqueue.c`: `:366-368 callout_reset_sbt_curcpu`
- `freebsd/libkern/arc4random.c`: `:212 chacha20inst[curcpu]` (**not in SRCS**)
- `dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c`: `:1840-1852 max_virtqueue_pairs`, `:2383-2387 VQ_PAIRS_SET`, `:2660-2669 reta_size`
- `dpdk-stable-24.11.6/lib/eal/include/rte_launch.h`: `:37-51 lcore=pthread+pinning`, `:99 rte_eal_mp_remote_launch`
- `dpdk-stable-24.11.6/lib/eal/include/rte_lcore.h`: `:77-81 rte_lcore_id TLS`, `:217-220 RTE_LCORE_FOREACH`
- `dpdk-stable-24.11.6/lib/eal/include/rte_per_lcore.h`: `:33 RTE_DEFINE_PER_LCORE`
- `dpdk-stable-24.11.6/lib/eal/include/rte_mempool.h`: `:28-32 MT-safe get/put`
- `freebsd-src-releng-13.0/sys/kern/subr_smr.c`: `:431-436`, `:591-611` (13.0 baseline SMR)
- `freebsd-src-releng-13.0/sys/net/vnet.c`/`vnet.h`: 13.0 baseline VNET comparison

**Note**: the `:586`/`:351` line numbers gate-design quoted in its M2 gate belong to the **workspace (with M3 changes)**; the §0.2 declaration makes them non-conflicting with this doc's HEAD baseline.
