# M17 M2 Design Document Gate Report (gate-design)

Reviewed object: `/data/workspace/f-stack/docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md`
Reviewer: `gate-design` (review only, no modification; **did not modify doc 17**, this file is this agent's only write)
Review basis: `_m17_D_verdict.md` (D1~D9 + §3 six residual risks), `_m17_gate_plan.md` (U1~U15 + §8), leader's 2 batches of new facts, **actual code as authority**

**Two-round review version record**
| Round | Version | Conclusion |
|---|---|---|
| Round 1 | `size=57578`, `mtime=13:50:11` (text ends at `<!-- SECTIONS_5_TO_9_MARKER -->` after §4.9) | **FAIL** (§5~§9 missing, 10 mandatory fixes) |
| **Round 2 (this report's conclusion)** | **`size=93635`, `mtime=13:57` (§0~§9 complete)** | **PASS-with-fixes** |

Verification strength: two rounds total measured about **85** `file:line`s. For files changed by `coder`, **uniformly used `git show HEAD:<file>` to verify HEAD original** (consistent with spec §0.2's declared line-number convention).

---

## 0. Conclusion

### **PASS-with-fixes**

- **Mandatory fixes 3** (F1~F3): all **do not block M3 continuation** (code has landed with correct conclusions), but **must be fixed before M4 starts**.
- **Suggestions 3** (F4~F6, nit level).
- Of round 1's 10 mandatory fixes: **E1/E3/E4/E9 resolved**, **E5 withdrawn by me** (was my error, see §4), E6/E7/E8/E10 partially resolved or not adopted → converged into this round's F1~F6.

### Key judgment points

| # | Review point designated by leader | Conclusion |
|---|---|---|
| 1 | Evidence chain authenticity / no overstepping | **PASS-with-fixes** (1 **premise fact error** → F1; rest ~85 consistent; evidence strength marking discipline good) |
| 2 | D1~D9 compliance | **PASS** (D1~D9 all satisfied; round 1's D7 gap filled by new version §7.1 criterion ⑧) |
| 3 | D8 (G2-b) verdict basis | **PASS** (three rejection reasons independently established item by item; slow-path window widening honestly recorded in §6.1) |
| 4 | Residual risks honestly recorded | **PASS-with-fixes** (verdict §3 six all landed; but missing netisr DPCPU → F2) |
| 5 | DoD-1 executability | **PASS** (§7.1 gives P1/P2 probe positions + 12 fields + **8 mechanically checkable criteria**, `tester` can directly execute; criteria ④/⑤ especially on point) |
| 6 | Comment convention (lib minimal comments) | **PASS** (spec everywhere gives ≤1~3 line limits; landed code measured 1~4 lines, no long prose) |

---

## 1. Review baseline: independent verification of D-constraint underlying facts (completed during waiting period, as judgment ruler)

| Fact | Verification result |
|---|---|
| `ff_freebsd_init.c:293/294/301/302` (HEAD) = `ff_pcpu_thread_init(0)` / `CPU_SET(0,&all_cpus)` / `uma_startup1()` / `uma_startup2()`; `:296 ff_init_thread0()`, `:308 mutex_init()`, `:309 mi_startup()` | ✓ all precise → **triple's only safe window = `:291`~`:293`**, consistent with spec §4.3.1 landing |
| `ff_dpdk_if.c` (HEAD) `:429/:433/:460/:2644/:2649/:2794` | ✓ all precise |
| `ff_kern_timeout.c` (HEAD) `:183/:190/:254/:662/:730/:815/:1061/:1077/:1181/:1291` | ✓ **10/10 precise** |
| **D8 lock collapse chain**: `uma_int.h:551-553 KEG_LOCK`, `:578-583 ZDOM_LOCK/ZONE_LOCK`, `:584 ZONE_LOCKPTR`, `:588-589 ZONE_CROSS_LOCK` → `mtx_lock` → `sys/mutex.h:386 → :451-452 → :417-418 _mtx_lock_flags` (`LOCK_DEBUG>0`) **or** `:428-429 __mtx_lock` (`==0`); `lib/include/sys/mutex.h:31-37 #undef` + `:59-65 DO_NOTHING` **both branches fully covered** | ✓ **D8 premise established** |
| `uma_core.c:1497-1509 cache_drain_safe`, `:1725 msleep(zone, ZONE_LOCKPTR(zone), PVM, "zonedrain", 1)`, `:5433 sx_sleep`, `uma_int.h:540 KEG_LOCK_INIT`/`:566 ZDOM_LOCK_INIT` (both `MTX_DEF\|MTX_DUPOK`) | ✓ precise |
| `tcp_hpts.c:1867-1871 / :1890 / :1564-1568 / :2061 / :2117 / :2142`, `kern_module.c:105-107`, `lib/Makefile:347 kern_module.c` (HEAD) | ✓ → `smp_topo()` returning NULL **safe**; U16-a "hpts active" holds |
| **C1 (this round's most critical new finding)**: `lib/include/sys/pcpu.h:31-34 #include_next` / `#undef curcpu` / `#define curcpu 0` (**original value confirmed by `git diff`**); upstream `freebsd/sys/pcpu.h:218 #define curcpu PCPU_GET(cpuid)`; `uma_core.c`'s **11** `uz_cpu[curcpu]`: `:1452,3738,3776,3818,3901,4534,4543,4595,4628,4803,4853` | ✓ **11/11 precise** → §2.3(d)'s conclusion holds: G1 alone with dense `pc_cpuid` **cannot** isolate UMA cache, G2 removing lock under this premise would **put back exactly the race `b90ddcba5` fixed** |
| §2.4's **21** `critical_enter/exit`: `:1451,1464,3727,3744,3775,3817,3859,3891,3900,3916,3918,4541,4554,4558,4626,4649,4653,4827,4850,4872,4874` | ✓ **21/21 all correct**; slow path indeed outside critical section (`:3859 critical_exit` → `:3880/3882`; `:3916` → `:3918`) |
| §4.5 impact point table: `ff_kern_synch.c:59/105`, `tcp_timer.c:237/249`, `tcp_hpts.c:1566/1587`, `tcp_lro.c:1210/1216`, `netisr.c:151/153/169/275-279/781/810/839/1146-1153/1164/1172` | ✓ **all correct** |
| §4.3.4's D4 immunity: `ff_config.c:1465-1484` (thread_mode: `proc_mask = strdup(lcore_mask)`, `nb_threads = nb_procs`) | ✓ holds (main thread must be in coremask → `lcore_conf[main_lcore].proc_id ∈ [0,N)`, immune to `--main-lcore`) |
| spec's cited `_m17_A_codepath.md` **U16 section** | ✓ **does exist** (`:948`) → spec citation valid (answering leader question 2①) |

---

## 2. Mandatory fixes (3)

### **F1 (mandatory ｜ premise fact error, but conclusion correct) §4.3.2's safety argument premise for `rp_ent[]` does not hold**

spec `:348` writes:
> M1-A U16 has established "neither indexing method goes out of bounds" (`rp_ent[]`'s **each index independently modulos `mp_ncpus`/`rp_num_hptss`**; ...)

**Measurement disproves this premise**: `rp_ent[]`'s index points total 7, of which **`freebsd/netinet/tcp_hpts.c:575 hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];` (`tcp_hpts_lock()`) has no modulo at all**. Others: `:1585 rp_ent[oldest_idx]` (loop upper bound `end = rp_num_hptss`), `:1587 rp_ent[curcpu % rp_num_hptss]` (modulo ✓), `:1922/1924/1925/2009/2077` (`i < rp_num_hptss` init/teardown loops ✓).

**But the conclusion (`mp_ncpus = N` does not go out of bounds) still holds**, just the reasoning must switch to **write-side bounded** —— I verified `t_hpts_cpu`'s **all** assignment points:

| Assignment point | Value | Boundedness |
|---|---|---|
| `freebsd/netinet/tcp_subr.c:2298` | `HPTS_CPU_NONE` (`tcp_var.h:330 ((uint16_t)-1)`) | Immediately rewritten by `tcp_hpts.c:604-609 tcp_hpts_init()` when `== HPTS_CPU_NONE` to `hpts_random_cpu()` |
| `tcp_hpts.c:606` | `hpts_random_cpu()` (`:467-474`) = `(((ran & 0xffff) % mp_ncpus) % tcp_pace.rp_num_hptss)` | **Double modulo** → independent of `mp_ncpus`/`rp_num_hptss` relationship, always safe ✓ |
| `tcp_hpts.c:1542` | `hpts_cpuid(tp, &failed)` (`:1040-1095`) four branches: ① `TF2_HPTS_CPU_SET` → return existing `t_hpts_cpu` (inductively bounded); ② `tcp_use_irq_cpu` → return `t_lro_cpu`, and `t_lro_cpu` **only assigned in uncompiled `tcp_lro_hpts.c`** → always `HPTS_CPU_NONE` → goes `*failed = 1; return (0)`; ③ `M_HASHTYPE_NONE` → `hpts_random_cpu()`; ④ otherwise `inp->inp_flowid % mp_ncpus` | ④'s safety depends on `rp_num_hptss == mp_ncpus`, guaranteed by `:1864 ncpus = mp_ncpus ? mp_ncpus : MAXCPU` + `:1872 tcp_pace.rp_num_hptss = ncpus` ✓ |

**And must add a timing argument (spec missing, is D2's additional benefit)**: `rp_num_hptss` is set in `tcp_hpts_mod_load()`, which via `DECLARE_MODULE` (`:2142`) → `module_register_init` (`kern_module.c:105-107`) → `mi_startup()` (`lib/ff_freebsd_init.c:309`) executes, **after** triple setting point (`:291`~`:293`) → necessarily sees final `mp_ncpus = N`.

**Suggested wording** (replace that sentence at `:348`):
> M1-A U16's conclusion "neither indexing method goes out of bounds" independently re-verified by `gate-design` **holds**, but **reasoning needs correction**: `rp_ent[]`'s indices do not all modulo —— `tcp_hpts.c:575 rp_ent[tp->t_hpts_cpu]` (`tcp_hpts_lock()`) **has no modulo**【code-established】. Real safety comes from **write-side bounded**: `t_hpts_cpu`'s all assignment points are `tcp_subr.c:2298` (`HPTS_CPU_NONE`, immediately rewritten by `tcp_hpts.c:604-609 tcp_hpts_init()`), `tcp_hpts.c:606 hpts_random_cpu()` (`:467-474`, `% mp_ncpus` then `% rp_num_hptss`, **double modulo**), `:1542 hpts_cpuid()` (`TF2_HPTS_CPU_SET` inductively bounded／`t_lro_cpu` always `HPTS_CPU_NONE` due to `tcp_lro_hpts.c` uncompiled, goes `*failed=1; return 0`／others go `hpts_random_cpu()` or `inp_flowid % mp_ncpus`). And `:1864/:1872` guarantees `rp_num_hptss == mp_ncpus`, and `rp_num_hptss` is initialized by `mi_startup()` (`ff_freebsd_init.c:309`) **after** triple setting (`:291`~`:293`) → all indices always `< N` under `mp_ncpus = N`【code-established】.

### **F2 (mandatory ｜ residual risk omission) §6 missing netisr's DPCPU alias**

Measured `grep "DPCPU_PTR(nws)"` in spec **zero hits**, §6.3 only records ipfw's DPCPU alias.
**Missed fact**【code-established】: `freebsd/net/netisr.c:1147 nwsp = DPCPU_PTR(nws);` (`netisr.c` compiled, HEAD `lib/Makefile:429`), because `dpcpu_init()` has zero callers, `dpcpu_off[]` and `pc_dynamic` always 0 (`freebsd/sys/pcpu.h:113-114/121/128`) → **N workers share same `nws`**. And it's **on per-packet hot path** (DIRECT dispatch) —— more frequently triggered than ipfw.
**Characterization (verified line by line, no exaggeration)**: DIRECT branch only increments two lockless counters (`:1149 npwp->nw_dispatched++`, `:1150 npwp->nw_handled++`) then calls handler (`:1151`), upstream comment `:1141-1142` self-states "Borrow the current CPU's stats", `netisr_internal.h:88` notes "written unlocked, but mostly from curcpu" → **only stat contention, not memory-safety issue**, same level as counter(9) (§5-2).
**Suggested wording** (new §6.15):
> ### 6.15 netisr's DPCPU alias (same type as §6.3, but on per-packet hot path)
> - **Basis**【code-established】: `freebsd/net/netisr.c:1147 nwsp = DPCPU_PTR(nws);` (HEAD `lib/Makefile:429` compiled). Because `dpcpu_init()` has zero callers, `dpcpu_off[]`/`pc_dynamic` always 0 → all workers share same `nws`.
> - **Impact scope**: DIRECT dispatch branch only increments `:1149/:1150` two lockless counters then calls handler (`:1151`), upstream comment `:1141-1142` "Borrow the current CPU's stats" → **only stat contention, no memory-safety issue**, same level as §5-2 counter(9).
> - **Fixed this round**: **No**, candidate A cannot fix (`-DSMP` does not create `dpcpu_init()` callers). Merged with §6.3 as "DPCPU independent project".

### **F3 (mandatory ｜ self-contradiction + exclusion missing) §4.5's "7 files" inconsistent with §9-14's list**

- `:442` writes "exhaustive within compile set, measured grep: **only appears in 7 files**", but `:852` (§9 evidence 14) actually lists **9 files** (extra `freebsd/netinet/ip_input.c:139-149`, `freebsd/netinet6/ip6_input.c:138-148`). Two places must be consistent.
- Also need to add **excluded items explanation**, otherwise gate cannot verify "exhaustive": `freebsd/libkern/arc4random.c:212 chacha20 = &chacha20inst[curcpu];` —— **not compiled** (HEAD `lib/Makefile` only lists `arc4random_uniform.c`, no `arc4random.c`), so excluded.
- Suggest changing section caliber to "**`curcpu` identifier** exhaustive within compile set (9 files); additionally 2 categories unaffected: `freebsd/sys/callout.h:100-120`'s `callout_*_curcpu` macro family directly uses `PCPU_GET(cpuid)` not via `curcpu` (its user `subr_taskqueue.c:368` see §6.13), and uncompiled file `arc4random.c:212`".

---

## 3. Suggestions (3, nit)

| # | Content | Suggestion |
|---|---|---|
| **F4** | §2.3(c) `:155-158` retains specific line numbers of preprocessing output (`11489:` / `13122:`). Methodology declared at `:30`/`:155` as "read-only `cc -E`, no files written, no `make` run" (**responding to my round 1 E6**), but those line numbers **are not reproducible/verifiable** (depend on compile params and header versions) | Suggest changing to "corresponding output line is `cache = &zone->uz_cpu[0];` (line numbers vary with compile params, not as verifiable evidence)". **Conclusion itself I independently established via C1, not overturned** |
| **F5** | §4.6 `:473` "main thread via `:285`" is bare line number | I verified its **correctness** (`lib/ff_kern_timeout.c:285` is indeed `ff_callout_thread_init();`, SYSINIT at `:287`, executed via `mi_startup()`). But alongside full path `lib/ff_freebsd_init.c:207` in same sentence, easy to misread as same file → suggest writing full `lib/ff_kern_timeout.c:285` (can add `:287 SYSINIT(callwheel_init, SI_SUB_CPU, ...)`) |
| **F6** | §6.5's fail-fast surface missed an OOM edge case (answering leader question 1③) | leader correctly excluded chicken-and-egg (`lib/ff_glue.c`'s `malloc()` → `ff_malloc()`, not via UMA; `kern_malloc.c` not in SRCS). **Residual edge**: `ff_glue.c:1076 pause("malloc", hz/100)` → `ff_kern_synch.c:105 &pause_wchan[curcpu]`, if `ff_pcpu_thread_init()`'s **first** `malloc(sizeof(struct pcpu))` happens to OOM, `pcpup` not yet built → `curcpu` dereferences NULL. **My judgment: acceptable** —— this is "startup OOM", won't start anyway, crashing here equals crashing elsewhere, and self-consistent with fail-fast verdict. Suggest §6.5 add a sentence to avoid M5 misjudging as G1 defect |

---

## 4. My errors in round 1 report (proactive correction, for leader and designer reconciliation)

designer's **C4 reverse correction in §6.14 all valid**, I re-verified item by item with `git show HEAD:` and **accept**:

| My original citation (`_m17_gate_plan.md` §8) | HEAD actual | Reason |
|---|---|---|
| `ff_glue.c` ck_epoch stub block `:1366-1404` | **`:1358-1396`** | I read **workspace with res-build probe patch** (`smp_topo` stub shifted lines +8) |
| `lib/Makefile`'s `ip_fw_dynamic.c` at `:604` | **`:601`** | Same (`-DSMP` probe line) |
| (Round 1 E5) `lib/Makefile:347 kern_module.c` should be `:351` | **`:347` was correct** | Same → **E5 fully withdrawn, spec correct** |
| (Round 1 §1.2 B1) `sched_bind` at `:1177-1181` | **`:1178`** | Same |

**Lesson internalized**: this round all verifications of changed `lib/` files uniformly use `git show HEAD:`. This also validates spec §0.2/§6.14-2's reminder necessity —— that reminder itself is **high quality**, recommend keeping in doc.

---

## 5. Round 1's 10 mandatory fixes convergence status

| Round 1 | Status |
|---|---|
| E1 (§5~§9 missing) | ✅ **resolved**: §5 nine exclusions, §6 fourteen risks, §7 DoD-1~8 (incl. 8 criteria), §8 milestones/two-commit plan/commit message English draft, §9 evidence index 36 items |
| E2 (§4.4 missing `thread_mode` gating / D7 unanalyzed) | ✅ **substantively resolved**: §7.1 criterion ⑧ explicitly requires "`thread_mode=0` 1-process and 2-process both run, secondary must also `dense_idx==0` (**C2 exposed here**)", D7 gap closed. `:408` still writes ungated `ff_stack_thread_init(qconf->proc_id)`, but **landed code is `thread_mode ? qconf->proc_id : 0`** → §8.2 commit plan caliber issue, recommend M6 backfill (no longer mandatory) |
| E3 (`curcpu` not landed) | ✅ **resolved**: `git diff lib/include/sys/pcpu.h` confirms `-#define curcpu 0` → `+#define curcpu PCPU_GET(cpuid)`; §8.2 commit-1 table includes this file; §6.14 honestly records process risk |
| E4 (`uma_int.h:583-586` line error) | ✅ **resolved**: `:501`/§9-19 both changed to `:540 KEG_LOCK_INIT` / `:566 ZDOM_LOCK_INIT`, and correctly added `ZONE_LOCKPTR(z)` see `:584` (I verified `:584` is indeed `ZONE_LOCKPTR`) |
| E5 (`Makefile:347`) | ⛔ **withdrawn** (see §4) |
| E6 (【measured】 not reproducible) | → downgraded to **F4** (methodology declared, only line numbers still not reproducible) |
| E7 (exhaustive needs exclusion) | → partially resolved (`subr_taskqueue.c:368` in §6.13 U12-ish ✓), remainder merged into **F3** |
| E8 (netisr DPCPU) | ❌ **not adopted** → **F2** (mandatory) |
| E9 (L1 criterion unreliable) | ✅ **resolved**: §6.2 now states "on miss `*slab = up->up_slab` directly segfaults on NULL `up` (this is L1 step's observable symptom)" |
| E10 (bare `:285`) | → downgraded to **F5** |

---

## 6. Special evaluation of new version's additions (leader's two high-risk additions)

### 6.1 §2.3 + §4.5 "`curcpu` per-thread-ization" —— **approved, and this round's most valuable addition**

- Original value `#define curcpu 0` confirmed by `git diff` (answering leader question 1 first sub-item).
- 11 UMA impact point line numbers **11/11 precise**; mechanism chain (`curcpu`→`uz_cpu[0]`→G2 lock removal puts back `b90ddcba5` race) **holds**.
- 8-category usage point list: **substantively exhaustive** (consistent with my independent grep of compile set results), only counting and exclusion explanation need fix (F3).
- Two "unreachable" arguments **both hold**: `netisr.c:839/1172` —— `:151/:153` defaults `NETISR_DISPATCH_DIRECT` + `:169 netisr_maxthreads = 1` + `:810 if (nws_count == 1)` early return + `:1146-1153` direct dispatch then `goto out_unlock`; `tcp_hpts.c:1566` —— `:1890 cpu_top == NULL → grp_cnt = 1`, `:1564 if (grp_cnt > 1)` only enters.
- fail-fast without NULL fallback: **acceptable** (§5-1's reason —— "adding slots needs `mp_maxid ≥ stack thread count + K`, directly conflicts with H1 'fixed before `uma_startup1()`'" —— is **code-level hard constraint**, holds). Only need to add OOM edge (F6).

### 6.2 §4.3.2 "`mp_ncpus` raised to N" —— **conclusion approved, argument premise needs fix (F1)**

- Cited `_m17_A_codepath.md` U16 section **does exist** (`:948`) → answering leader question 2①: **not citing nonexistent section**.
- leader question 2②'s suspicion **completely correct**: `:575 rp_ent[tp->t_hpts_cpu]` **indeed has no modulo**, spec's "each index independently modulos" is **wrong**. But I've re-established safety via **write-side bounded + timing** (see F1), so `mp_ncpus = N` verdict **can be retained**.
- Verdict's second reason (`mp_ncpus=1` would make N workers crowd the only hpts instance, and `HPTS_TRYLOCK` always true has no real mutual exclusion) **I independently established**: `tcp_hpts.c:218 #define HPTS_TRYLOCK(hpts) mtx_trylock(&(hpts)->p_mtx)` + `:1603 if (!HPTS_TRYLOCK(hpts))` + `lib/include/sys/mutex.h:74` `mtx_trylock_flags_ → 1` ✓.

---

## 7. Unverified boundary (honest declaration)

- §3.1 candidate A's compile numbers (`error 0`/`warning 51`/binary 30,392,616 bytes), §7.3's 51 baseline: **not re-run compile verification**.
- §2.2's SMR destruction chain (A/B interleaved UAF) is source-level semantic derivation, spec honestly marks source; I **did not verify** `smr_poll_cpu`/`smr_poll_scan` line by line.
- §2.3(c)'s preprocessing output line numbers: **cannot verify** (see F4), but conclusion independently established via C1.
- `_m17_A_codepath.md` U16 I only verified **section existence** and its two cited conclusions, **did not line-by-line verify that section's full text**.
- Whether ipfw dynamic rules are enabled at runtime (§6.3's honest boundary): **unverified**.
- Entirely **static review, no runtime validation**; DoD-1~DoD-5 actual results must be produced by `tester` at M5.

---

## 8. Handling suggestions for leader

1. **Can allow M3 to continue / must fix F1~F3 before starting M4**: F1 is "right conclusion, wrong reasoning", F2/F3 are recording completeness, none affect landed code correctness.
2. **Suggested order**: designer fixes F1~F3 (+ optional F4~F6) → I do **round 3** quick re-review (estimated only 3 spots) → `reviewer` reviews M3 code per final spec → M4.
3. **M2 bounce = 1/3** (round 1 FAIL counts 1; this round PASS-with-fixes doesn't count as bounce).
4. `_m17_D_verdict.md` §3.2's `ff_glue.c:1187` recommend changing to **`:1178`** per HEAD (consistent with designer's C4).
5. §8.2 commit plan's `ff_dpdk_if.c` change description recommend correcting to `thread_mode ? qconf->proc_id : 0` per **landed code** (see §5's E2 note).

---

# 9. Re-review (bounce=1) 【= leader-designated "re-review" section】

**Re-review baseline version: `size=125935`, `mtime=2026-08-04 14:24:05`, 1060 lines, 10 top-level sections (§0~§9)**
Reference: `_m17_F_runtime.md` (84,613 bytes, mtime **15:52:35**, 5 min earlier than spec), `_m17_gate_code_g1.md` (67,418 bytes, 15:05:06)
This round newly measured **21** `file:line`s (including 5 code-level independent verifications + 6 filesystem measurements); per leader's instruction did not re-run previously passed evidence chains.

## 9.1 Re-review conclusion

### **PASS** (no FAIL) + mandatory **6** (of which 2 are **M7 operation blocking points**) + nit 4

Reasons for **PASS** (strictly per leader's FAIL criteria):
- **No blocking design defects**: D1~D9 all satisfied; `reviewer` M4 gate "mandatory-2" and "G2-S1" **both fully implemented, and their premises I independently established**; §6 residual risks **7/7** complete.
- **No overstepping**: leader's FAIL criterion is "writing unverified/near-noise as definite conclusions". After checking item by item, spec **does not** have such overstepping —— instead it marks 3-thread outliers, `ipi_smr` base address consistency etc. as 【unverified】.
- Remaining 6 mandatory fixes **all textual** (1 fact error + 2 data backfill timeliness + 3 M7 operation details), don't affect landed code correctness, can be done at **M6** (designer backfill, `gate-doc` gatekeeping).

⚠ **F1 has been unmodified for 3 consecutive rounds** (see 10.2). **Recommend leader clarify: if F1 still unmodified at M6 backfill, `gate-doc` should directly FAIL.**

## 9.2 F1~F6 implementation verification

| # | Status | Basis |
|---|---|---|
| **F1** (`rp_ent[]` argument premise error) | ❌ **not fixed, still mandatory** | `:350` original text still "`rp_ent[]`'s **each index independently modulos `mp_ncpus`/`rp_num_hptss`**". I measured disproved: `freebsd/netinet/tcp_hpts.c:575 hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];` (`tcp_hpts_lock()`) **has no modulo**. Conclusion still holds, but reasoning must switch to **write-side bounded + timing** (full replacement wording see this report §2-F1, including `hpts_random_cpu()`'s double modulo `:467-474`, `t_lro_cpu` always `HPTS_CPU_NONE` due to `tcp_lro_hpts.c` uncompiled, `:1864/:1872` guarantees `rp_num_hptss == mp_ncpus`, and timing argument that `rp_num_hptss` is initialized by `mi_startup()` after triple) |
| **F2** (netisr DPCPU alias missing) | ✅ **fixed** | New §6.15, basis `netisr.c:236 DPCPU_DEFINE(struct netisr_workstream, nws);` (I measured `:236` ✓ precise) + `:1147`/`:1149`/`:1150`/`:1151`, characterized as "**pure stat counter contention, not memory-safety issue**, same level as counter(9)" → **consistent with my characterization**; and correctly states "candidate A cannot fix" "merged with §6.3 as DPCPU independent project" |
| **F3** (7 vs 9 file contradiction + exclusion) | ✅ **fixed** | `:456` now limits caliber to "**`curcpu` identifier**'s occurrences in actually compiled set (compile set inferred from `lib/*.o`)"; new "exclusion X1" row, with **correct HEAD line number** `lib/Makefile:582` (`LIBKERN_SRCS` only lists `arc4random_uniform.c`) + `ls lib/arc4random.o` non-existence measurement |
| **F4** (preprocessing line numbers not reproducible) | ⚠️ **not fixed (nit)** | `:158-159` still retains `11489:` / `13122:`. Conclusion unaffected (independently established via C1), suggest changing wording per this report §3-F4 |
| **F5** (bare `:285`) | ⚠️ **not fixed (nit)** | Still "main thread via `:285`". I verified its **content correct** (`lib/ff_kern_timeout.c:285` = `ff_callout_thread_init();`, SYSINIT at `:287`), only suggest writing full filename |
| **F6** (OOM edge) | ✅ **fixed and exceeded expectations** | Not only registered in doc, but added §4.5(i)'s **targeted fallback design**, and `coder` **landed**: `git diff lib/ff_kern_synch.c` = `pause_wchan[curcpu]` → `pause_wchan[pcpup != NULL ? curcpu : 0]` + 1 line necessary comment (`/* Reachable from malloc()'s OOM retry before this thread has a pcpu. */`) → comment convention compliant; §8.2 commit-1 list synchronized to include this file (8 files) |

## 9.3 Leader's three watchpoints

### Watchpoint 1: §6 complete coverage of 7 residual risks + accurate characterization —— **PASS (7/7)**

| verdict §3's 6 + my new 1 | Landing | Characterization verification |
|---|---|---|
| counter(9) stat contention | §6.7 | ✅ "stat accuracy issue, not memory-safety issue" —— accurate |
| `cache_drain_safe` repeated draining | §6.6 | ✅ "**only reclaim efficiency issue, no out-of-bounds, no memory unsafety**" + correctly adds "`curcpu` per-thread-ization **does not change** this conclusion" —— accurate |
| ipfw DPCPU alias | §6.3 | ✅ "candidate A cannot fix" + "`mp_ncpus=N` only eliminates `dyn_hp_cache`'s **heap overflow**, not the **alias**" —— accurate and to the point |
| NUMA not compiled | §6.16 | ✅ characterized as "**simplifying factor not risk**" and registers "if NUMA introduced in future, `uc_crossbucket`/`ZONE_CROSS_LOCK` (`uma_int.h:586-590`) become new shared points, G2 conclusion must re-argue" —— accurate, and goes further than verdict |
| various stub threads nonexistent | §6.17 | ✅ characterized as "G1's 'thread↔slot 1:1 never migrates' invariant's **premise for holding**", and clarifies "this invariant is product of current code form, not enforced constraint" —— accurate. Basis I measured: `ff_kern_intr.c:84-89 swi_add`→0, `:91-95 swi_sched` **empty**, `:97-101 swi_remove`→0, `:103-107 intr_event_bind`→`EOPNOTSUPP` ✓ line-precise |
| U6-a | §6.12 | ⚠️ characterization correct (downgraded from "plan dependency" to "observation item"), but its **fallback means inconsistent with actual probe** → see N1 |
| **netisr DPCPU (my E8)** | §6.15 | ✅ see F2 |

Also new §6.18/§6.19 two entries (see §9.4), making §6 total 21 subsections. **No omissions found**.

### Watchpoint 2: §7 consistent with `coder`'s actual probe + criteria executable —— **PASS-with-fixes (1 mandatory = N1)**

Verified against `_m17_E_coder_g1.md` §6 item by item:

| Comparison item | Conclusion |
|---|---|
| Probe landing (P1~P4) | ✅ §7.1 opening adds "alignment with `coder`'s implemented probes", 4 landing points, output format two lines **verbatim consistent** |
| Log landing | ✅ Changed to `coder`'s measured "**two files to check**: main thread P1+P4 in `example/f-stack-0.log`, worker P1+P3 in `example/helloworld.log`", and retains "append-write must record old line count before `tail -n +N`" —— **exactly what I was going to ask, absorbed** |
| `tid` semantics | ✅ Noted as `pthread_self()` handle, not OS tid, don't cross-reference with `ps -T` |
| `sizeof(struct uma_cache)` | ✅ Adopts `coder`'s `nm --print-size` measured **128 (0x80)**, and clarifies "upstream `uma_int.h:280-281` comment says 64 bytes, inconsistent with local measurement, measurement prevails" —— **handled well** (didn't blindly trust upstream comment) |
| **per-VNET absolute address comparison defect** | ✅ **fully absorbed**: §7.1's ⚠ section establishes `tcp_var.h:1308/:1315` + `lib/opt/opt_global.h:6 #define VIMAGE 1` + `vnet.h:305`, points out cross-thread absolute address subtraction "**mathematically invalid**", gives (a) add `smr_base`/`zone_base` two `%p` / (b) use canonical form (global `zone_mbuf` + offset criteria) two paths, and orders "**must not treat `0x1000`/`0x80` as DoD-1 passed evidence without confirming base address consistency**" —— **completely consistent** with my independent conclusion, wording more rigorous |
| Criteria ①~⑧ | ✅ all mechanically executable; ⑤/⑥ changed to "base consistent→absolute diff; base inconsistent→offset criteria" dual-branch form; ⑦ includes `MAXCPU` verification; ⑧ includes `thread_mode=0`'s 1-process + 2-process and secondary `dense_idx==0` |
| **⑨ (U2 supplementary criterion)** | ✅ new, and correctly points out "⑥ only proves adjacent thread slot distance 4096, **does not prove** this PCPU zone really allocated `(mp_maxid+1)×4096`; if only 1 page allocated, `dense_idx≥1`'s slot is out-of-bounds memory, short smoke may not crash", and gives feasible criteria "print that keg's `uk_ppera` (should == `mp_maxid+1`)" —— **very strong supplement**, turns U2 from "static undecided" to runtime-verifiable |
| D7 special | ✅ §7.4 new "D7 special (gate-design E2 required, cannot omit)", explicitly 1-process and 2-process both run, both logs `grep "out of range"`, and states "**fragile coupling**, **static inference not accepted**" |

**N1 (mandatory)**: §7.1's P1 "must print fields (9)" still includes `rte_lcore_id()` and `rte_get_main_lcore()`, but **actual probe only prints 7 fields, excluding these two** (`_m17_E_coder_g1.md` §6.3's format string); while §6.12 explicitly commits "fallback: DoD-1 probe prints `rte_get_main_lcore()`/`rte_lcore_id()`/`proc_id`/`pc_zpcpu_offset` **four-tuple verification**" → **this fallback currently cannot execute**.
**Suggested wording (choose one, recommend a)**:
> **(a)** When adding `smr_base`/`zone_base` in §7.1's ⚠ scheme (a), **also** add `rte_lcore_id()`/`rte_get_main_lcore()` (via host-side helper function, same side as `ff_probe_tid()`, 1 change total), making §6.12's U6-a verification executable;
> **(b)** Or change §6.12's fallback to "this round **does not verify** U6-a (actual probe doesn't print `rte_*` fields), only register as observation item; because §4.3.4's numbering doesn't depend on this inference, **doesn't affect correctness**".

### Watchpoint 3: §8 two-commit split —— **PASS (1 mandatory = N2, 1 suggestion = N3)**

- **Each commit independently compilable** ✅: commit-1's 8 files self-contained (`-DSMP` + `smp_topo` stub both in it, avoiding link missing symbol); commit-2 only changes `uma_int.h` + `ff_glue.c`. §7.3 requires both `make clean` then full compile.
- **No known crash introduced** ✅ and order correct: commit-1 **retains** `uma_crit_lock` while completing `curcpu` per-thread-ization → relative to HEAD is **strictly safer** (per-thread slots + lock still present); commit-2 removes lock, with §4.7 hard prerequisite "`curcpu` must already be per-thread, otherwise equals putting back `b90ddcba5`'s race". **This order is correct, no intermediate crash window.**
- **§8.2 list consistent with landed code** ✅: I measured `git status` now has **10 changed files** = list's 8 + probe's `lib/ff_host_interface.c`/`.h`, precise match with §8.2's footnote "probes not counted in this list"; new `lib/ff_kern_synch.c` landed (see F6).
- **N2 (mandatory ｜ operational risk)**: §8.3 requires "probes not in commit-1/commit-2" and "`git diff` confirms probes not in diff", but **gives no operation method**, and P1~P4 and G1's real changes **are in same file `lib/ff_freebsd_init.c`** → directly `git add lib/ff_freebsd_init.c` inevitably includes probes. Suggest adding:
  > Before commit-1 **must first remove all 5 `#if 1 /* M17 temporary probe */` blocks via forward modification** (`grep -rn "M17 temporary probe" lib/` lists all at once, including `ff_freebsd_init.c`'s P1~P4 and `ff_host_interface.c/.h`'s `ff_probe_tid()`), then whole-file `git add`; **not recommended** to use `git add -p` to split same file (easy to miss and leaves non-compilable intermediate state). If probes still needed post-M5 for reproduction, make as **independent temp commit** per §8.3 and revert after acceptance.
- **N3 (suggestion)**: §8 doesn't explicitly state "**commit-2 can be `git revert`ed alone without affecting G1**". Although "2 files, no other changes mixed in" implies it, suggest writing explicitly, as §4.7.4's step L2 (revert when cannot remove) operational guarantee.

## 9.4 §5~§9 new content fact verification (this round newly measured 18 spots, no factual errors found)

| New assertion | Verification result |
|---|---|
| **§6.18** "`net.isr.dispatch` must stay `direct`, otherwise silent packet loss" (source `reviewer`) | ✅ **full chain established**: `netisr.c:155-158 SYSCTL_PROC(_net_isr, OID_AUTO, dispatch, CTLTYPE_STRING \| CTLFLAG_RWTUN \| CTLFLAG_NEEDGIANT, ...)` ✓ (`RWTUN` confirms can be preset by tunable/`config.ini`); `:1172 if (cpuid != curcpu) goto queue_fallback;` ✓; `lib/ff_kern_intr.c:91-95 swi_sched(void *cookie, int flags) { }` ✓ **indeed empty function body** → "queued but no handler = silent packet loss" **holds**. And this is **not contradictory** to §4.5 table row 7/8's "default unreachable" (one talks default config, other talks post-config-change), doc self-explains this |
| **§6.19 (R6)** "hpts instance count 1→N memory + callout misattribution + no mutex" | ✅ **all basis precise**: `tcp_hpts.c:169 #define NUM_OF_HPTSI_SLOTS 102400` ✓, `:243-247 struct hptsh { TAILQ_HEAD(, tcpcb) head; uint32_t count; uint32_t gencnt; } *p_hptss;` ✓ (24-byte derivation reasonable: 16+4+4), `:1999 callout_init(&hpts->co, 1)` ✓, `:2010 hpts->p_cpu = i` ✓, `:2047-2049 callout_reset_sbt_on(..., hpts->p_cpu, ...)` ✓, HEAD `lib/Makefile:51 FF_TCPHPTS=1` ✓ + `:161 CFLAGS+= -DTCPHPTS -DRATELIMIT` ✓. **"N instances' callouts all hang on main thread's callwheel" misattribution argument holds** (`ff_kern_timeout.c:184 CC_CPU(cpu)` ignores arg, `tcp_hpts_init` executed by main thread during `mi_startup()`). Memory derivation honestly marked **【unverified (derivation)】** and requires M5 RSS measurement ✓ |
| §6.16 NUMA / §6.17 stub threads | ✅ basis precise (see §9.3 watchpoint 1) |
| §7.1's ⚠ per-VNET argument | ✅ `tcp_var.h:1308/:1315` ✓, `in_pcb.h:378 ipi_zone`/`:380 ipi_smr` ✓, `kern_mbuf.c:325 uma_zone_t zone_mbuf;` (**ordinary global, not VNET**) ✓ → spec choosing `zone_mbuf` as canonical form is **correct** |
| §4.5(i) bootstrap window fallback | ✅ design and landed code identical |
| Overstepping check | ✅ new content's evidence strength marking **discipline good**: §6.19 memory derivation marked 【unverified (derivation)】, §7.1-⑨ marked 【unverified】, §6.18 fallback marked 【unverified】, §6.12 downgraded to observation item. **No overstepping of writing static inference as "verified/measured"** |

## 9.5 My third self-correction

spec §4.5 "exclusion X1" points out: my round 2 F3's cited `lib/Makefile:586` (`arc4random_uniform.c`) is **workspace line number with M3 changes**, HEAD is actually **`:582`**. I re-verified with `git show HEAD:lib/Makefile \| grep -n arc4random` → **indeed `:582`, I was wrong, accept**.
This is my third time tripping over same type of issue (first two see this report §4). **Fully internalized**: this round §9's all 18 new measurements, for changed `lib/` files, uniformly `git show HEAD:` first then take line numbers.

## 9.6 Post-re-review mandatory fixes summary (3)

| # | Level | Content |
|---|---|---|
| **F1** | mandatory (premise fact error, conclusion correct) | §4.3.2 `:350`'s "`rp_ent[]` each index modulos" → switch to **write-side bounded + timing** argument (wording see this report §2-F1) |
| **N1** | mandatory (commitment inconsistent with implementation) | §7.1 P1's 9 fields vs actual probe 7 fields; §6.12's committed U6-a four-tuple verification currently **cannot execute** → add `rte_lcore_id()`/`rte_get_main_lcore()`, or downgrade §6.12 fallback |
| **N2** | mandatory (M7 operational risk) | §8.3 add "before commit must first forward-delete 5 `#if 1 /* M17 temporary probe */` blocks then whole-file `git add`" —— because P1~P4 and G1 changes are in same `ff_freebsd_init.c` |

Suggestions: **F4** (preprocessing line number wording), **F5** (`:285` write full filename), **N3** (explicitly write commit-2 can revert alone).

## 9.7 Re-review boundary

- Per leader's instruction **did not re-run** round 1/2's ~65 passed evidence chains; this round only measured 18 new spots.
- §6.19's "`sizeof(struct hptsh)` = 24 bytes → single instance 2.34 MiB" is struct layout derivation, spec marked 【unverified (derivation)】, I **did not measure with `sizeof`/`nm`**.
- §7.1's ⚠'s "`coder`'s smoke `0x1000`/`0x80` strongly suggests reading same `V_tcbinfo` twice" inference, spec marked 【unverified】; **I also cannot statically conclude** (need M5 add base address to determine whether "worker vnet data copied from vnet0 template without re-running `tcp_init`" or "`td_vnet` not effective"). This **must be closed by M5 measurement**.
- Entirely **static review, no runtime validation**.
- bounce count: M2 = **1/3** (round 1 FAIL counts 1; round 2 and this round both PASS-with-fixes, don't count as bounce).

---

# 10. Re-review (bounce 1 closeout)【= leader-designated "## 7 re-review" section】

**Re-review baseline version: `size=150518`, `mtime=2026-08-04 15:57:18`, 1191 lines, 10 top-level sections (§0~§9)**
Reference: `_m17_F_runtime.md` (84,613 bytes, mtime **15:52:35**, 5 min earlier than spec), `_m17_gate_code_g1.md` (67,418 bytes, 15:05:06)
This round newly measured **21** `file:line`s (including 5 code-level independent verifications + 6 filesystem measurements); per leader's instruction did not re-run previous rounds' passed evidence chains.

## 10.1 Re-review conclusion

### **PASS** (no FAIL) + mandatory **6** (of which 2 are **M7 operation blocking points**) + nit 4

Reasons for **PASS** (strictly per leader's FAIL criteria):
- **No blocking design defects**: D1~D9 all satisfied; `reviewer` M4 gate "mandatory-2" and "G2-S1" **both fully implemented, and their premises I independently established**; §6 residual risks **7/7** complete.
- **No overstepping**: leader's FAIL criterion is "writing unverified/near-noise as definite conclusions". After checking item by item, spec **does not** have such overstepping —— instead it marks 3-thread outliers, `ipi_smr` base address consistency etc. as 【unverified】.
- Remaining 6 mandatory fixes **all textual** (1 fact error + 2 data backfill timeliness + 3 M7 operation details), don't affect landed code correctness, can be done at **M6** (designer backfill, `gate-doc` gatekeeping).

⚠ **F1 has been unmodified for 3 consecutive rounds** (see 10.2). **Recommend leader clarify: if F1 still unmodified at M6 backfill, `gate-doc` should directly FAIL.**

## 10.2 Mandatory fixes (6)

### Mandatory-1 ｜ F1 third round unmodified (this doc's only factual error)

`:351` still is "…(`rp_ent[]`'s **each index independently modulos `mp_ncpus`/`rp_num_hptss`**…)".
I measured disproved in round 2 and gave replacement wording twice: `freebsd/netinet/tcp_hpts.c:575 hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];` (`tcp_hpts_lock()`) **has no modulo**. Conclusion (`mp_ncpus=N` no out-of-bounds) holds, but reasoning must switch to **write-side bounded + timing** (full wording see this report §2-F1).

### Mandatory-2 ｜ §7 not backfilled M5 part 3 (DoD-5 A/B cross-retest) —— leader's hard constraint this round

`_m17_F_runtime.md` (15:52, **5 min earlier than spec**) part 3 gives complete results, while spec §7.5 (`:1008-1016`) still has "pre-lock baseline: fully ready" + "post-lock **must redo**" pending tone, full `grep` for these numbers **zero hits**:

| M5 measured (`_m17_F_runtime.md`) | spec §7 current |
|---|---|
| `:1307` 2-thread **B−A = +0.50%**; `:1308` A-side cross-check **−0.41%** | missing |
| `:1322` 4-thread **B−A = +1.67%**; `:1323` A-side cross-check **+0.71%** | missing |
| `:1350-1351` soak **+0.87%** / **+1.78%** | missing |
| `:1331/:1337` 3-thread **+4.93%** "cannot directly trust…**not as DoD-5 judgment basis**" | missing |
| `:1362` verdict table "2-thread A/B cross 6 rounds each → PASS" | missing |

Also **must** write M5's honest boundary verbatim into §7 (I've checked each to source):
1. **+0.50%/+1.67% near noise floor, must not claim G2 brings definite performance improvement** (M5 `:1145` self-states "±2% extremely sensitive to machine state drift");
2. 3-thread **+4.93% not as judgment basis**, outlier root cause **unverified** (`:1337`, clues see §6.19/R6);
3. `[M17-PROBE]` missing line/concatenation pollution root cause **`ff_subr_prf.c:86` global unlocked `bufr[]`**;
4. **secondary probe not captured** (`:284`/`:657`: `example/f-stack-1.log` full 60 lines, `grep -c "M17-PROBE"` = 0, landing point not located) → 2-process D7 evidence **only covers primary**;
5. **`MAXCPU=1024`'s RSS not measured** (`:659`);
6. Whether `kmem_malloc` can stably get `(mp_maxid+1)` pages at large N **unverified**.

> Note: §7.6 already writes "M6 must backfill M5 measured data to §7 tables", i.e. designer's stance is to defer to milestone M6 —— this stance itself is compliant, so this item **not FAIL**; but M5 data was ready 5 min before spec landed, recommend immediate backfill, otherwise §7 enters M7 in "pending" form.

### Mandatory-3 ｜ `uk_ppera` 2-thread档's "pending/retest" expired

spec `:880` table 2-thread档 `⑨` = "pending (should == 2)", `:969` "2-thread档…**pending retest confirmation**"; while M5 `:846-847` **already measured** `[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=2 uk_rsize=8 mp_maxid=1` (`pcpu_zone_64` same).
→ Should change to 【measured】PASS, and upgrade §6.20/`:845`'s U2 closure from "4-thread measured" to "**2/3/4 three档 all measured**".

### Mandatory-4 ｜ §8.3 probe line numbers and count all expired (**M7 operation blocking point**)

spec `:1072` writes "`lib/ff_freebsd_init.c` (P1~P4 + P5, `:115`/`:134`/`:160`) + `lib/ff_host_interface.c`/`.h`".
**I measured `grep -rn "M17 temporary probe" lib/` = 6 spots**: `ff_host_interface.c:152`, `ff_host_interface.h:51`, `ff_freebsd_init.c:114`, `:122`, `:271`, `:432`.
→ spec's 3 line numbers only `:115`≈`:114` matches, `:134`/`:160` **completely inconsistent** with actual `:122`/`:271`/`:432` and misses 1. **Removing per current line numbers would miss → probes would enter commit.**
**Suggested wording**:
> Probes total **6 spots** (measured at writing: `ff_host_interface.c:152`, `ff_host_interface.h:51`, `ff_freebsd_init.c:114/:122/:271/:432`). **Line numbers drift with changes, M7 removal must use `grep -rn "M17 temporary probe" lib/`'s real-time output, re-run that `grep` after removal to confirm empty return.**

### Mandatory-5 ｜ §8 missing `ff_glue.c`'s hunk-level split explanation (**M7 operation blocking point**)

`lib/ff_glue.c` **appears in both commits simultaneously**: commit-1 adds `smp_topo()` stub, commit-2 deletes `:146 uma_crit_lock`. And **workspace has both changes simultaneously** (G2 landed) → commit-1 if whole-file `git add`, would bring G2's deletion in, **breaking "commit-2 can revert alone"**. spec currently has no related explanation (`grep "add -p"` zero hits).
**Suggested wording** (§8.3 or new §8.5):
> `lib/ff_glue.c` spans two commits, **commit-1 must use `git add -p lib/ff_glue.c` to stage only the `smp_topo()` hunk**, `uma_crit_lock`'s deletion left for commit-2; after `git add` use `git diff --cached lib/ff_glue.c` to verify. (Unlike §8.3's probe "whole-file delete then add" strategy, here must hunk-level split.)

And suggest adding two explicit statements in §8 (leader point 7; currently only `:511` mentions this principle when arguing `curcpu`):
> ① **Each commit independently compilable and introduces no known crash**: commit-1 retains `uma_crit_lock` and has completed `curcpu` per-thread + §4.10 timing fix → strictly safer than HEAD; commit-2 only removes lock, prerequisite see §4.7. ② **commit-2 can `git revert` alone without affecting G1** (only 2 files, no other changes mixed in), this is §4.7.4 step L2's operational guarantee.

### Mandatory-6 ｜ DoD-8 temp artifact list incomplete (**risk of mis-commit**)

spec `:1025` only lists `lib/_m17_probe_*.c/.o`, root `_m17_*.log/.txt/.i/_m17_dep/`, `example/*.log`. **Measured still has unlisted items**:

| Measured residual | Evidence |
|---|---|
| `example/helloworld_g1_prelock` (**30,392,704 bytes**, 15:00) | `ls -la` |
| `example/helloworld_g2_nolock` (**30,392,664 bytes**, 15:10) | `ls -la` |
| **`./config.m17_g2_2t.ini`, `./config.m17_g2_4t.ini` (f-stack repo root)** | `find . -name "config.m17*"` |
| `/tmp/m17ab_off.txt`, `/tmp/m17_e_cmd.sh`, `/tmp/m17_ffinit_before.c`, `/tmp/m17_g2_ex.log`, `/tmp/m17_g2_exclean.log` | `ls /tmp/m17*` |

**Risk**: root's two `config.m17_g2_*.ini` appear in `git status`, **risk of mis-commit**; two 30MB binaries if not cleaned occupy space long-term.
→ DoD-8 must supplement four categories, and clarify "all via `/data/workspace/rm_tmp_file.sh`" (except in-source probes, via forward modification).

## 10.3 nit (4, non-blocking)

| # | Content |
|---|---|
| nit-1 | `:158-159` preprocessing output line numbers `11489:`/`13122:` **third round unmodified** (non-reproducible evidence; conclusion independently established via C1) |
| nit-2 | `:473` bare `:285` **third round unmodified** (content correct = `lib/ff_kern_timeout.c:285`, only suggest writing full filename) |
| nit-3 | §6 subsection numbering **skips 6.13/6.14** (6.12 → 6.15). I `grep` confirmed **no dangling references**, purely cosmetic |
| nit-4 | §6.19 (R6) "single instance 2.34 MiB" still layout derivation 【unverified (derivation)】, M5 didn't measure RSS (same as mandatory-2 item 5), suggest in-place annotation |

## 10.4 Implemented items verification (leader points 1~5, 7, 8 item by item)

| leader point | Conclusion | Basis |
|---|---|---|
| **1. E1 complete + §6 covers 7 risks** | ✅ **PASS** | §5 ten exclusions, §6 **twenty-two** subsections, §7 eight DoDs, §8 four subsections, §9 thirty-plus evidence index all exist. **No dangling anchors**: full-text `§x.y` deduped and checked, `§10.3`/`§2.14-A/B`/`§5.1` are all **references to external docs** (M1-A U10 §10.3, `_m17_gate_code_g1.md` §2.14, plan §5.1), not internal anchors; `§5-1/§5-2/§5-5` all have corresponding entries in §5 table items 1/2/5. **7 residual risks 7/7**: counter→§6.7+§5-2, cache_drain_safe→§6.6, ipfw DPCPU→§6.3+§5-3, NUMA→§6.16+§5-9, stub threads→§6.17, U6-a→§6.12, **netisr DPCPU (my E8)→§6.15** |
| **2. E2** | ✅ **PASS (four echoes, exceeding requirement)** | `:416` gates `thread_mode ? qconf->proc_id : 0`; `:423` **dedicated section** "⚠ fragile coupling (must explicitly register, gate-design E2)" containing "double dependency `__thread ff_stack_inited` early return" complete derivation; `:606` D7 table adds `main_loop` row; `:1001` DoD-4 "D7 special (cannot omit)" requires 1+2 process measurement and both logs `grep "out of range"` |
| **3. E4~E9** | ✅ 5 fixed, 1 nit | E4 ✅ `:1126` is `uma_int.h:540`/`:566`; **E5 ✅ not broken by my erroneous suggestion** —— `:1131` still correct `lib/Makefile:347`; E6 ⚠ nit-1; E7 ✅ `:474` uses correct HEAD `:582` **and proactively corrects my `:586`**; E8 ✅ §6.15; E9 ✅ upgraded from "ambiguous" to "**unreachable/dead code**" (`:725-726`) |
| **4. `reviewer` mandatory-2** | ✅ **PASS (complete rewrite, premise I independently established)** | `:566` L1 criteria wholly rewritten: **(c) promoted to primary** (node count inconsistent with registration count, §4.7.5 gives early detection formula "no need to wait for crash"), **(a′)** crash point located at `vtoslab()` (`uma_int.h:77-88`, `:87 return NULL`)→`uma_core.c:4930`→`:4938 slab->us_domain` or `:5819`, **⛔ prohibited** "crash at `uma_int.h:101/102`". **My independent verification**: `vtozoneslab`'s only callers in whole tree are `freebsd/kern/kern_malloc.c:943/1039/1136`, and `git show HEAD:lib/Makefile \| grep kern_malloc` → **zero hits** ⇒ **indeed dead code, original criterion never triggers** ✓; `uma_core.c:4930`/`:5819` I `sed` measured **line-precise** ✓ |
| **5. G2-S1** | ✅ **PASS (I independently established)** | §6.1 `:714-716` writes two facts and **downgrades** ("possible memory corruption" → "insertion lost → `vtoslab()` returns NULL → caller dereference crash", fail-fast locatable). **Independent verification**: `grep -rn "LIST_REMOVE\|le_prev" lib/include/vm/uma_int.h lib/ff_freebsd_init.c` → **NONE**; that hash only has `:125 LIST_INSERT_HEAD` + `:84/:97/:111 LIST_FOREACH` ⇒ **insert-only never deleted, `le_prev` has no consumer, no UAF all hold** ✓ |
| **7. §8 commit plan** | ⚠ list correct, operation explanation missing (mandatory-4/-5) | commit-1 **8 files** list complete correct: includes **§4.10 `uma_page_slab_hash` advance** (`:1052`, and warns at `:1074` "**not a probe, must not delete with probes**" —— very on point), `ff_kern_synch.c` fallback (`:1057`), `curcpu` (`:1055`); commit-2 **only 2 files** and "no other changes mixed in". **commit message ✅ compliant**: English, commit-1 subject 1 sentence + body 2 sentences, commit-2 subject 1 sentence + body 1 sentence, all within 1~3 sentences, and explains `uma_page_slab_hash` advance reason |
| **8. DoD-8** | ⚠ principle correct, list/line numbers wrong | "probes must be forward-deleted, `rm_tmp_file.sh` not applicable" principle correct (`:1025`), but count/line numbers wrong (mandatory-4), artifact list incomplete (mandatory-6) |

## 10.5 Re-review boundary (honest declaration)

- Per leader's instruction **did not re-run** previous rounds' ~85 passed evidence chains; this round only did 21 new measurements.
- `_m17_F_runtime.md` I **only checked leader's named numbers and honest boundary sources** (`:284/:657/:659/:846-847/:1145/:1294-1362`), **did not line-by-line verify that 84KB report's full text**, **did not re-run any stress test**.
- §6.19's 2.34 MiB derivation, `ipi_smr` base address consistency (§7.1 ⚠), 3-thread outlier root cause: **all still unverified**, spec marking correct, I cannot statically conclude.
- Entirely **static review + filesystem read-only measurement, no runtime validation**.
- bounce count: M2 = **1/3** (only round 1 FAIL counts 1).

---

# 11. Closeout verification (gate-design closeout)

Verified object: committed spec = `git show 06396b501:docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md` (**166,343 bytes**)
Method: read-only verification (no tests or modifications), item-by-item confirming section 10's 6 mandatory fixes closed.

## 11.1 Six mandatory fixes all closed ✅

| Mandatory | Status | Committed version basis |
|---|---|---|
| **Mandatory-1 (F1, unmodified for 3 rounds)** | ✅ **closed** | `:352` **whole paragraph replaced** and explicitly states "original text wrongly claimed '`rp_ent[]`'s each index independently modulos `mp_ncpus`/`rp_num_hptss`', **that statement has been disproven by measurement**"; `:356-360` switches to **write-side bounded** argument, exhausts `t_hpts_cpu`'s full tree **3** write points, and gives `hpts_random_cpu()` (`:466-475`, `:473` double modulo) establishment —— consistent with my round 2 replacement wording (I verified `:467-474` vs their `:466-475` within tolerance) |
| **Mandatory-2 (§7 not backfilled M5 DoD-5)** | ✅ **closed** | committed version `grep "0.50%\|1.67%"` **hits 3 times** (original zero hits) |
| **Mandatory-3 (`uk_ppera` 2-thread expired)** | ✅ **closed** | `:909` and `:1055` both backfilled "post-lock slot isolation re-verification **completed in M5 part 3** (2/3/4-thread three档 + `thread_mode=0` degraded档 all PASS)" and marked 【measured】 |
| **Mandatory-4 (probe line numbers/count)** | ✅ **closed** | `:1068`/`:1130` explicitly "**all 6 spots** `#if 1 /* M17 temporary probe */`", and changed to use `grep -rn "M17 temporary probe" lib/` **zero hits** as acceptance criterion; after removal re-ran clean build and gave md5 `df05d2cd078d631ad2d8ee7caba8d387` |
| **Mandatory-5 (`ff_glue.c` cross-commit split)** | ✅ **closed, and handled more carefully than my suggestion** | `:1105`/`:1131` new "same file across commits must split by hunk", `reviewer` confirmed both commits **each independently compilable**, and explains **actual method used is not `git add -p`** (see its §8.3.1); also `:1130` gives a counter-argument I didn't think of —— for **probes within same commit** `git add -p` shouldn't be used, because it leaves **non-compilable intermediate state** in index like "probe called staged helper function whose definition isn't staged" |
| **Mandatory-6 (DoD-8 list incomplete)** | ✅ **closed** | `:1068` supplemented all four categories I measured: `example/helloworld_g1_prelock`, `example/helloworld_g2_nolock`, `config.m17_g2_2t.ini`, `config.m17_g2_4t.ini`, `/tmp/m17*`, and clarifies "all via `/data/workspace/rm_tmp_file.sh`", probes are source changes via forward modification; also adds an operational optimization I didn't raise: two binary copies **keep until M7's last step then delete**, for随时 re-checking DoD-5's A/B data |

## 11.2 commit message convention verification ✅

Three commits all **English** and within **1~3 sentences** (`c7996a94f` / `57b612d16` / `06396b501`), compliant; `c7996a94f`'s body fully explains "triple set before `uma_startup1()`", "dense pcpu id + per-thread `curcpu`", "`uma_page` slab hash advance initialization" three items, traceable to §4.3/§4.5/§4.10.

## 11.3 gate-design closeout declaration

- I produced **4 rounds** of gate conclusions in M2: round 1 **FAIL** (§5~§9 missing, 10 mandatory) → round 2 **PASS-with-fixes** (3 mandatory) → round 3 **PASS-with-fixes** → round 4 (bounce 1 closeout) **PASS** (6 mandatory) → this section confirms **all 6 closed**. **M2 bounce final = 1/3, did not hit limit.**
- I submitted **3 self-corrections** in this project (all due to误用 "workspace with probe patch" line numbers instead of HEAD: `ck_epoch` block, `ip_fw_dynamic.c`'s Makefile position, `arc4random_uniform.c`'s position; of which round 1's E5 suggestion was **erroneous suggestion**, `designer` correctly rejected it). Lesson written into this report §4 and §9.5, for future similar task reference: **for verifying line numbers of changed files, always `git show HEAD:<file>` first.**
- Unsubmitted materials: **none**. This report (§0~§11) is gate-design's complete record.
- Boundary reiterated: all my conclusions are **static review + filesystem read-only measurement**, **never did runtime validation**; all runtime conclusions per `tester`'s `_m17_F_runtime.md`.
