# _m17_gate_code_g2: G2 Code Gate Review (reviewer)

> Review object: `coder`'s **G2-b (remove `uma_crit_lock` global spinlock)**, self-report `_m17_G_coder_g2.md` (24,147 B, mtime 15:28).
> Role separation: write = `coder`, review = `reviewer` (this author). I **did not modify any source code**, only write this file. No `git commit`, no touching `config.ini`.
> All conclusions from **actually opening code / executing commands**; unverified items explicitly marked.

**Review baseline**: `git diff` final state; `git status --short freebsd/` output **empty** (upstream tree zero changes, measured).

---

## 0. Conclusion

# **PASS-with-fixes**

- **Blocking items: 0** → **does not block M5 post-lock retest**, can start immediately.
- **Mandatory fixes: 2** (1 code comment wording, 1 spec criterion), both P2, can parallel with M5.
- G2-b's **implementation faithful to spec §4.7 verdict**, `uma_crit_lock` deletion **thorough**, clean build and md5 **fully reconciled with coder**.
- I did **two independent paths of verification** for G2's core correctness argument, conclusion: **G2 zero impact on SMR** (provable), **UMA per-cpu cache invariant holds in all entry contexts** (provable); slow-path window widening is **real residual risk**, but I found two **risk-reducing facts** not recorded in spec (see §5.3), actual risk lower than spec's assumption.

---

## 1. Item-by-item review table

| # | Review item | Verdict | Basis |
|---|---|---|---|
| 1 | Change strictly equals spec §4.7's G2-b (macro vs inline equivalence) | **PASS** | §2 |
| 2 | `uma_crit_lock` deletion thoroughness (grep + nm/objdump) | **PASS** | §3 |
| 3 | G1/G2 change set separability (can cleanly split two commits) | **PASS** (cleanly splittable, plan see §4) | §4 |
| 4 | clean build re-verification + md5 reconciliation | **PASS** (md5 **consistent** with coder) | §6 |
| 5 | G2 correctness argument recheck (SMR + invariant all-context holding) | **PASS** (I proved via two independent paths) | §5 |
| 6 | L1/L2 downgrade criteria usability | **FAIL → mandatory-2** (L1 criterion (a) **unreachable**, not just ambiguous) | §7 |
| 7 | Comment convention | **FAIL → mandatory-1** (wording states a **wrong** reason) | §8 |
| 8 | M5 retest requirements | given (§9) | §9 |

---

## 2. Review item 1: Change strictly equals G2-b —— PASS

### 2.1 Change set = exactly 2 spots, verbatim consistent with spec §4.7.1's G2-b

`lib/include/vm/uma_int.h` (`+6/-8`): delete `extern volatile int uma_crit_lock;` and two spinlock macros, replace with `do {} while(0)` no-ops + 3-line comment.
`lib/ff_glue.c` (this file `+7/-1`, of which **`-1` is G2**): delete `:146 volatile int uma_crit_lock;`.

- **Did not擅自 become G2-a** (did not add real locks to `ZDOM_LOCK`/`KEG_LOCK`) ✓: full diff has no `mtx_init`/new lock variables.
- **Did not擅自 become G2-c** (did not shrink lock scope) ✓: thorough removal not narrowing.
- **Added no new locks** ✓: `grep` full diff no new `__sync_lock_test_and_set`/`pthread_mutex`/`mtx_*`.
- → **Faithfully implements G2-b** ✓

### 2.2 Keeping as "no-op macro" rather than "deleting macro" —— I judge this is **correct choice**, and both forms are **functionally equivalent** for `uma_core.c`

First establish "even falling back to upstream is no-op": `freebsd/sys/systm.h:179-193`:
- f-stack lib build: `_KERNEL` defined, `KLD_MODULE`/`KTR_CRITICAL`/`GENOFFSET` undefined → goes **`#else` branch's inline**; its body **entirely inside `#ifndef FSTACK`** → **FSTACK is empty function body** (even `atomic_interrupt_fence()` absent) ✓
- So "delete macro → fall back to inline" **also is no-op**, keeping empty macro in **generated code fully identical** (both zero instructions, zero barriers).

**Macro form vs inline form for `uma_core.c` fully equivalent —— my judgment: equivalent, three reasons, each I measured**:
1. **Syntactic position**: macro expands to `do {} while(0)` is a **statement**, cannot be used in expression position. I checked all 21 call sites of `uma_core.c` —— **all are statement positions** (form `\tcritical_enter();`), **no expression position usage** → macro form safe ✓
2. **No macro redefinition warning**: `systm.h` under current compile config goes **inline branch** (not `#define` branch), so `uma_int.h`'s `#define critical_enter()` **does not constitute macro redefinition** → no `-Wmacro-redefined`. Consistent with my measured warning count still **51** (zero new) ✓
3. **Barrier semantics**: both **contain no** compiler or memory barriers (inline version's `atomic_interrupt_fence()` excluded by `#ifndef FSTACK`) → **identical** constraint on compiler reordering ✓

**Reasons keeping empty macro is better than deleting (I support coder's choice)**: empty macro makes "intentionally no protection here" visible in `uma_int.h` and can attach comment; deleting macro would make readers think upstream's `td_critnest` semantics still present, needing two layers of `#ifdef` to confirm empty.

### 2.3 Macro change's **impact radius = `uma_core.c` single TU** (I independently converged, coder report didn't give this boundary)

`lib/include/vm/uma_int.h`'s macro only affects TUs that **include it**. Full tree includers: 7 files. Cross-filtered with `lib/Makefile` SRCS, **only 2 in compile set**: `uma_core.c` (`VM_SRCS`) and `lib/ff_freebsd_init.c` (`FF_SRCS`). And `ff_freebsd_init.c`'s `critical_enter|smr_enter` hit count = **0** (measured) → unaffected.
→ **G2's behavior change strictly limited to `uma_core.c`**, exactly the intended target, no spillover ✓

---

## 3. Review item 2: `uma_crit_lock` deletion thoroughness —— PASS

**Full repo grep (I reran, no dir exclusion, including `freebsd/`, `tools/`, `tests/`, `*.mk`)**: `grep -rn "uma_crit_lock" .` (excluding `.git/` and `docs/`) → **zero hits**. (grep validity self-check: same pattern in `docs/` hits 3 files normally → proves not false negative from wrong pattern ✓)

**Symbol-level verification (I ran, based on my own clean build)**: `nm libfstack.a | grep -c uma_crit_lock` → 0; `objdump -t libfstack.a | grep -c uma_crit_lock` → 0. **No TU still `extern`s it** ✓. `example/` link `undefined reference` count = **0** ✓.

→ Deletion **thorough**, coder's self-reported data independently re-verified by me **holds**.

---

## 4. Review item 3: G1/G2 change set separability —— PASS, cleanly splittable

`lib/ff_glue.c` is the only file carrying both G1 and G2 changes. I used `git diff -U0` for precise hunk boundaries: two hunks `@@ -146+145,0 @@` (G2: delete uma_crit_lock) and `@@ -171,0 +171,7 @@` (G1: add smp_topo stub), **~25 lines apart, zero context overlap** → `git add -p` presents as **two independent hunks**, separately stageable ✓.

**Recommended split plan (satisfies spec §4.7.5 + D8 independent commit requirement)**:
- **commit-1 (G1)**: `lib/Makefile`, `lib/ff_dpdk_if.c`, `lib/ff_dpdk_if.h`, `lib/ff_freebsd_init.c`, `lib/ff_kern_synch.c`, `lib/ff_kern_timeout.c`, `lib/include/sys/pcpu.h` (+ probe-related `lib/ff_host_interface.c/.h` if not yet removed), and `lib/ff_glue.c`'s **hunk 2 only** (`git add -p` select `s`/`y`).
- **commit-2 (G2)**: `lib/include/vm/uma_int.h` + `lib/ff_glue.c`'s **hunk 1 only**.

**Both commits independently compilable (I've derived)**:
- commit-1 landed intermediate state: `uma_int.h` still has `extern volatile int uma_crit_lock;` + spinlock macros, `ff_glue.c` still has its definition → **declaration/definition paired complete, compilable linkable** ✓
- commit-2 removes declaration and definition **simultaneously** → also paired complete ✓
→ Satisfies L0 step "commit-2 can `git revert` alone without affecting G1": revert only reverts `uma_int.h` full text and `ff_glue.c`'s `:146` one line, **no intersection with G1's `smp_topo` region (`:171+`), no conflict** ✓

**Commit order reminder (linked with G1 review's R-d)**: 6 `#if 1 /* M17 temporary probe */` probes must be removed after M5. If removed before commit-1, commit-1 doesn't include `ff_host_interface.c/.h`; if removed after M5, need third "cleanup commit". Suggest **M5 end → remove probes → then split commit-1/commit-2**, avoiding probe code entering product commit (DoD-8).

---

## 5. Review item 5: G2 correctness argument recheck (most critical)

### 5.1 "SMR read side never protected by `uma_crit_lock`" —— **holds**, I proved via **two independent paths** (stronger than coder's preprocessing line-number evidence)

`freebsd/sys/smr.h`'s `smr_enter()`/`smr_exit()` internally call `critical_enter()`/`critical_exit()` (`smr.h:109/167/178/218`). Question is **which version of `critical_enter` these call sites see**.

**Path A (caller perspective, decisive)**: compile set TUs calling `smr_enter`/`smr_exit` total 5. Each verified whether it includes `vm/uma_int.h`:

| TU | In SRCS | `grep -c uma_int.h` |
|---|---|---|
| `freebsd/netinet/in_pcb.c` | ✓ | **0** |
| `freebsd/netinet6/in6_pcb.c` | ✓ | **0** |
| `freebsd/netinet/tcp_hostcache.c` | ✓ | **0** |
| `freebsd/kern/subr_smr.c` | ✓ | **0** |
| `freebsd/kern/kern_descrip.c` | ✓ | **0** |

→ **All 0** → these TUs' `smr_enter()` expands `systm.h`'s **empty inline**, **never** `uma_crit_lock` spinlock ✓

**Path B (only affected TU's perspective)**: `uma_core.c` is the only TU where `critical_enter` was the spinlock. Measured its `smr_enter`/`smr_exit` call count = **0** (only uses `smr_poll`/`smr_wait`/`smr_advance`/`smr_create`/`smr_synchronize`, none contain critical section).

→ Two paths cross-confirm: **G2's impact on SMR provably zero**, not "probably doesn't affect" ✓ coder's conclusion correct.

### 5.2 "Each thread exclusively owns `uz_cpu[curcpu]`" invariant holds in **all** UMA entry contexts —— holds

**First correct a key argument basis (also mandatory-1's origin)**: upstream `critical_enter()`'s role is **disable preemption/migration**, guaranteeing `curcpu` invariant within critical section. f-stack's stack threads are **ordinary pthreads, preempted and migrated by Linux scheduler** —— so "userspace no preemption" is **wrong**. G2's real safety reason is:
> **f-stack's `curcpu` is already "thread-bound" not "CPU-bound"** (`lib/include/sys/pcpu.h:34 #define curcpu PCPU_GET(cpuid)` → `pcpup->pc_cpuid`, `pcpup` is `__thread`). So **preemption and migration don't change this thread's `curcpu` value**, critical section is **unnecessary** for "keeping `curcpu` stable".

Code corroboration: `uma_core.c:4534` takes `cache = &zone->uz_cpu[curcpu]` **before** `critical_enter()` (`:4541`), then `:4543` **takes again** —— upstream needs retake because migration changes `curcpu`; f-stack two takes **always equal**, retake harmless.

**Per-context verification of "no concurrent shared slot"**:

| # | UMA entry context | Concurrent with others? | Basis |
|---|---|---|---|
| 1 | Main thread `ff_freebsd_init()` → `uma_startup1/2` → `mi_startup()` **大量建 zone** | **No** | workers created by `ff_run()` → `ff_dpdk_run()` → `rte_eal_mp_remote_launch()`, and `ff_run()` called by app **after `ff_init()` returns** → **`mi_startup()` period only main thread in process** ✓ |
| 2 | Main thread `ff_dpdk_if_up()` (`ff_veth_attach` builds ifnet, goes UMA) | **No** | Also in `ff_init()`, before `ff_run()` ✓ |
| 3 | Worker entering `main_loop()` **after、`ff_stack_thread_init()` before** | Doesn't touch UMA | `main_loop` prologue (`ff_dpdk_if.c:2636-2655`) checked item by item: local declarations, `rte_get_tsc_hz()`, `qconf = ff_cur_lcore_conf()` (pure array indexing) → **no UMA calls** ✓ |
| 4 | Worker `ff_stack_thread_init()` | Slots ready | `ff_pcpu_thread_init(cpuid)` is first action after lock (`ff_freebsd_init.c:240-242`), then `ff_callout_thread_init`/`vnet_alloc`/`lo_set_defaultaddr` etc UMA calls ✓ and `pcpu_init` guarantees `pc_cpuid = cpuid` dense unique |
| 5 | Worker steady-state `main_loop` packet rx/tx | Each uses own slot | `curcpu` is thread constant, `ff_pcpu_thread_init`'s upper bound check (`:106-108`) guarantees `cpuid ≤ mp_maxid`, G1 measured 4-thread `uz_cpu` addresses common difference 128 pairwise distinct ✓ |
| 6 | `ff_pthread_create()` app threads (**D9**) | `pcpup == NULL` → fail-fast | **Documented as unsupported usage**: spec §5-1, §4.5, D8/D9 alignment table all clear "no general NULL fallback, fail-fast is deliberate choice", and **sole exception** retains my G1-suggested `pause_sbt()` bootstrap window targeted fallback (§4.5(i)) ✓ |
| 7 | DPDK internal threads (intr / telemetry etc) | Don't enter f-stack UMA | These threads don't call any `ff_*` stack API (**not exhaustively verified**, see §10-③) |

→ **Invariant holds in all supported contexts** ✓ G2's fast-path protection sufficient.

### 5.3 Slow-path window widening —— real residual risk, but I found **two risk-reducing facts not recorded in spec**

**Risk confirmed (consistent with D8 ③)**: f-stack's `ZONE_LOCK`/`ZDOM_LOCK`/`KEG_LOCK` and all `mtx` are `((void)0)` → zone/keg/`uma_page` hash slow path **already lockless**, previously only `uma_crit_lock` **incidentally** serialized. G2 removal widens window. This is designer's G2-b (accept + record + downgrade steps) context.

**But I found two risk-reducing facts (`uma_int.h` full text measured, spec §6.1/§6.2 not recorded)**:
1. **`uma_page` hash is "insert-only, never delete"**: full file only has `LIST_INSERT_HEAD` (`:123`), **no `LIST_REMOVE`** → nodes **never removed, never freed** → lockless readers **cannot read freed nodes (no UAF)**, worst case "miss a just-inserted node". This **fundamentally eliminates** the most dangerous class of concurrent fault (UAF / dangling pointer).
2. **`le_prev` back pointer never read**: `LIST_REMOVE` never used → even if concurrent insertion corrupts `le_prev`, no consumer → harmless.

→ **Actual worst failure mode converges to "insertion lost"**: two threads concurrently `LIST_INSERT_HEAD` on **same bucket**, one insertion may be overwritten (node orphaned but not freed) → that page not found in hash → `vtoslab()` returns **NULL** → caller dereferences NULL and crashes. **Note: crash point in `uma_core.c`, not `uma_int.h:101`** —— this directly overturns spec's L1 trigger criterion (see §7).

---

## 6. Review item 4: clean build re-verification (I ran) + md5 reconciliation —— PASS and **reconciliation consistent**

| Metric | My measured | coder self-reported | Threshold | Verdict |
|---|---|---|---|---|
| `lib` `make` return code | **0** | 0 | 0 | PASS |
| `lib` `grep -c "error:"` | **0** | 0 | 0 | PASS |
| `lib` `grep -c "warning:"` | **51** | 51 | ≤ 51 (HEAD baseline) | PASS (**lock removal zero new warning**) |
| `lib` `.o` count | **248** | — | 248 | PASS |
| `nm libfstack.a \| grep -c uma_crit_lock` | **0** | 0 | 0 | PASS |
| `example` `make` return code | **0** | 0 | 0 | PASS |
| `example` `error:` / `undefined reference` | **0** / **0** | 0 / — | 0 | PASS |
| `example/helloworld` size | **30,392,664** B | 30,392,664 B | — | **consistent** |
| **`example/helloworld` md5** | **`78c39a6f96e104412ce75351e402907b`** | `78c39a6f96e104412ce75351e402907b` | — | ✅ **fully consistent** |

**md5 reconciliation conclusion**: this round **coder and my md5 fully consistent**, unlike previous round (G1, coder `d49268db…` vs me `751a8153…`) mismatch. Combined with my G1 review §9.5's evidence "`helloworld` md5 reproducible, `libfstack.a` md5 not (ar embedded mtime)", this consistency constitutes valid evidence **"coder and reviewer built from same source state"** ✓ coder report §3.3's "md5 taken in same command sequence as `make clean`" effectively fixed previous round's process瑕疵.

**G1 change integrity check (I independently verified `--numstat`)**: `Makefile 4/0`, `ff_dpdk_if.c 7/1`, `ff_dpdk_if.h 1/0`, `ff_freebsd_init.c 101/14`, `ff_host_interface.c 8/0`, `ff_host_interface.h 4/0`, `ff_kern_synch.c 3/1`, `ff_kern_timeout.c 3/3`, `include/sys/pcpu.h 1/1` —— **all identical to G1 final state I verified in `_m17_gate_code_g1.md` §9**; `ff_glue.c` changed from `7/0` to `7/1` (new `-1` is G2 deletion). → **G2 is pure increment, G1 intact undisturbed** ✓

Temp logs cleaned via `/data/workspace/rm_tmp_file.sh`.

---

## 7. Review item 6: L1/L2 downgrade criteria usability —— **FAIL (mandatory-2)**

### 7.1 L1 trigger criterion (a) **unreachable**, so entire composite criterion **always false**

spec §4.7.4's L1 trigger criterion is "**(a)** crash point at `lib/include/vm/uma_int.h:101 *slab = up->up_slab;` or `:102` **and (b)** … **or (c)** …". `gate-design` E9's issue is "that line also crashes on lookup miss → ambiguous".

**My re-review conclusion stronger than E9: that line is never executed in this build.**

- `:101/:102` is in **`vtozoneslab()`** (current file `:88-101`, measured).
- `vtozoneslab()`'s **only callers in full repo are `freebsd/kern/kern_malloc.c:943/1039/1136`**, and **`kern_malloc.c` not in `lib/Makefile` SRCS** (`grep -c kern_malloc lib/Makefile` = **0**; f-stack's `malloc/free` implemented by `ff_glue.c:1067/1085`, goes host `ff_malloc`).
- → **`vtozoneslab()` is dead code**, `:101` **never executes**.
- → criterion (a) always false; and L1 requires "(a) and one of (b/c)" → **entire L1 trigger condition always false, L1 step can never start**.

(This conclusion consistent with my `_m17_gate_code_g1.md` §9.1's finding: I exhausted its callers to confirm whether `VTOSLAB` being set makes that defect reachable.)

### 7.2 Mandatory-2: L1 criterion fix suggestion (based on §5.3's derived real failure mode)

**Real failure chain** (`uma_page` hash insert-only ⟹ no UAF ⟹ worst is insertion lost): concurrent `LIST_INSERT_HEAD` loses one insertion → that page not found in hash → **`vtoslab()` (`uma_int.h:83-88`, returns `NULL` on miss) returns NULL** → caller dereferences NULL and crashes.
`vtoslab()`'s **active** callers (vs `vtozoneslab`, these two actually run):
- `uma_core.c:4930` (inside `zone_release()`, `__predict_true((zone->uz_flags & UMA_ZFLAG_VTOSLAB) != 0)` branch)
- `uma_core.c:5819` (`if (zone->uz_flags & UMA_ZFLAG_VTOSLAB) return (vtoslab((vm_offset_t)mem));`)

**Suggest changing (a) to (a')**:
> **(a')** crash/hang stack frame inside **`vtoslab()` (`lib/include/vm/uma_int.h:83-88`)** (linked-list self-loop or wild pointer read), **or** at `uma_core.c:4930` / `:5819` after getting `slab == NULL` and dereferencing (typical stack: `uma_zfree_arg` / `zone_release` / `zone_free_item`).

**(b) unchanged** ("only reproduces with `thread_mode=1` and `nb_threads ≥ 2`" still valid concurrency discriminator).
**(c) unchanged, and suggest promote to primary criterion**: bucket self-loop / duplicate `up_va` / node count inconsistent with `uk_ppera` cumulative registration count. Supplement more direct detection: **because never `LIST_REMOVE`, "registered page node count < cumulative `uk_ppera` expected count" directly proves insertion lost**, no need to wait for crash.

### 7.3 L1 memory ordering argument spec asked me to recheck —— **partially holds, must add compiler barrier**

spec §4.7.4 L1's argument (marked 【unverified (derivation)】 and "must `reviewer` recheck"): only add lock to writer-side `vsetzoneslab()`, reader-side no lock, reason is `:122-125` fills `up_va`/`up_slab`/`up_zone` then `LIST_INSERT_HEAD` publishes, x86-TSO store ordering holds, reader won't see half-initialized node.

**My judgment**:
- **Hardware level holds** ✓: x86-TSO disallows store→store reordering, if reader sees `lh_first == up`, necessarily sees prior `up->up_*` writes.
- **Compiler level doesn't hold** ✗: `LIST_INSERT_HEAD` (`sys/queue.h`) is **ordinary non-volatile, non-atomic** assignment, **no release semantics, no compiler barrier**. Compiler can legally sink `up->up_va = va` etc stores **below** `head->lh_first = up` (unobservable in single-thread semantics). Upstream uses `CK_LIST`/`ck_queue`'s `atomic_store_rel` exactly for this.
- **If adopt L1, minimal strengthening**: insert compiler barrier (`__compiler_membar()` / `atomic_thread_fence_rel()`) before `LIST_INSERT_HEAD`, or change publish write to `atomic_store_rel_ptr(&hash_list->lh_first, up)`.
- **Uncovered spot**: `vsetzoneslab()`'s **"hit-then-modify" branch** (`:117-121` in-place overwrite `up_slab`/`up_zone`) —— reader may read **torn combination** between two generations (`up_slab` new, `up_zone` old). Not a crash, but **returns mismatched (zone, slab) pair**. If adopt L1, should also cover (e.g. reader-side also locks, or change to "new node replace" not in-place modify).
- **Also record risk-reducing fact (§5.3)**: because never `LIST_REMOVE`, reader-side no lock **no UAF**, so "reader-side no lock" is **safer than spec's own argument claims**.

### 7.4 L2 criterion —— usable

L2 (`git revert` commit-2, keep G1, write `uma_crit_lock`'s necessity as conclusion back to spec, `reviewer` gate confirms) **depends on L1 failure or throughput below DoD-5**, doesn't depend on that unreachable line number → **criterion usable** ✓ and §4 confirmed commit-2 can cleanly revert.

---

## 8. Review item 7: Comment convention —— **FAIL (mandatory-1)**

New 3-line comment (`lib/include/vm/uma_int.h:44-47`):
```c
/*
 * No preemption in f-stack userspace; UMA per-cpu cache is protected by each
 * stack thread owning a distinct dense pcpu slot (spec 17 §2.4).
 */
```
- **Necessity**: ✓ necessary. This is "intentionally removed protection" location, no comment later people can't tell if it's accidental deletion.
- **Length**: ✓ 3 lines not verbose, compliant with minimal comment convention.
- **Accuracy**: ✗ **first clause "No preemption in f-stack userspace" is wrong statement**. f-stack's stack threads are ordinary pthreads, **will be preempted and migrated by Linux scheduler**; "userspace no preemption" doesn't hold. G2's real safety reason is **`curcpu` is already thread-bound not CPU-bound** (`lib/include/sys/pcpu.h:34` → `pcpup->pc_cpuid`, `pcpup` is `__thread`), so preemption/migration **doesn't change** this thread's `uz_cpu[]` slot (see §5.2, including `uma_core.c:4534` vs `:4543` two `curcpu` takes always equal code corroboration).

**Severity: mandatory (P2).** Same type as G1's mandatory-2 (`ff_kern_timeout.c` stale comment `cpuid is always 0, MAXCPU=1`) **same issue, same standard** —— wrong comments more harmful than no comments, and this carries "why can remove lock" this highest-risk decision's sole written basis, if later people remove other protections based on "no preemption" wrong premise would introduce real defects.

**Suggested fix (keep 3 lines)**:
```c
/*
 * curcpu is per-thread here (sys/pcpu.h), not per-CPU, so preemption cannot
 * change which uz_cpu[] slot this thread uses and no other thread uses it;
 * the dense pcpu slot is the whole protection (spec 17 §2.4).
 */
```

---

## 9. Review item 8: M5 post-lock must-rerun criteria (for leader to pass to `tester`)

**Core requirement: after G2 lock removal, slot isolation becomes UMA per-cpu cache's sole protection, so G1's slot criteria must all rerun, cannot reuse G1 round's data.**

**A. Slot isolation 5 criteria (per档位 2/3/4 threads each run once)** —— criteria same as `_m17_gate_code_g1.md` §9.4②, **note per-field stride**:
1. `pc_cpuid == dense_idx == curcpu`
2. `pc_zpcpu_offset == 4096 * dense_idx`
3. `smr_c_seq` forms arithmetic sequence with common difference **4096**
4. `uma_cache` forms arithmetic sequence with common difference **128** (`= sizeof(struct uma_cache)`) and pairwise distinct —— **⚠ not 4096, applying 4096 would misjudge FAIL**
5. `uk_ppera == mp_maxid + 1`

**B. G2-specific additions**:
6. **soak mandatory** (DoD-4, 60s / 400 connections): this is slow-path lockless window widening's **sole** detector (§5.3).
7. **Crash classification per corrected (a') criterion** (§7.2), **don't** compare against `uma_int.h:101` (that line unreachable).
8. **Suggest add a no-crash-needed direct detection**: after soak, count `uma_page_slab_hash` all bucket node counts, compare with cumulative `uk_ppera` expected registered page count; **because hash insert-only, inequality proves concurrent insertion lost** (earlier and more certain than waiting for crash).
9. **Throughput reconciliation**: compare with G1 round (pre-lock) same档位. coder self-tested 2-thread 219,241.92 req/s, 4-thread 391,271.39 req/s, but its §4.4 already self-limited "limited comparability" → **M5 must retest G1/G2 two versions under same methodology**, otherwise cannot serve as DoD-5 judgment.

**C. Version pin**: tested binary `example/helloworld` md5 must be **`78c39a6f96e104412ce75351e402907b`** (30,392,664 B); if not match, `make clean && make` first.

---

## 10. Unverified boundary (honest record)

1. **G2's runtime behavior I didn't personally run**: this round only static review + clean build + symbol verification. coder's self-tested throughput (2-thread 219,241.92 / 4-thread 391,271.39 req/s) and "no crash, slot isolation maintained" **I didn't reproduce**, and coder self-limited its comparability (§4.4) → all pending M5.
2. **Slow-path window widening actual severity unquantified**: §5.3 I converged worst failure mode to "insertion lost" and excluded UAF, but **to what degree widened, whether truly triggers under soak, static analysis cannot conclude** (consistent with spec §6.1 "U8-perf" honest marking).
3. **Whether DPDK internal threads (intr / telemetry / KNI etc) absolutely never enter f-stack UMA, I didn't exhaustively verify** (§5.2 table row 7). Judgment basis is "they don't call `ff_*` stack API", reasonable inference not exhaustive evidence.
4. **`sys/queue.h`'s `LIST_INSERT_HEAD` expansion I didn't verbatim open** (§7.3's compiler reordering argument based on "ordinary non-atomic assignment, no barrier" general fact); if designer wants to adopt L1, suggest re-open to confirm specific expansion.
5. **I didn't verify `git add -p`'s actual interaction result** (§4's split plan based on `git diff -U0` hunk boundary derivation, didn't actually execute stage —— per convention I don't do `git add`/`commit`).
6. **Spec full text I only rechecked §4.7 / §5-1 / §6.1 / §6.2 and D8/D9 alignment items**, didn't chapter-by-chapter review 906-line full text (that's `gate-design`'s scope).

---

## 11. Mandatory fix list

| # | Level | Location | Issue | Suggested fix |
|---|---|---|---|---|
| **Mandatory-1** | P2 · wrong comment statement | `lib/include/vm/uma_int.h:45` (`coder`) | "No preemption in f-stack userspace" **is wrong** (stack threads are ordinary pthreads, preempted/migrated). G2's real safety reason is `curcpu` **thread-bound not CPU-bound**. This carries "why can remove lock" written basis, wrong premise would mislead future maintainers to remove other protections | See §8's 3-line replacement text |
| **Mandatory-2** | P2 · spec criterion unreachable | spec §4.7.4's L1 trigger criterion (a) (`designer`) | Criterion (a) points to `uma_int.h:101`, but `vtozoneslab()` is **dead code** in this build (only caller `kern_malloc.c` not in SRCS) → **that line never executes → L1 never triggerable**. E9's "ambiguity" is actually "unreachable" | Change to §7.2's (a'): crash point in `vtoslab()` or `uma_core.c:4930`/`:5819` after getting `slab==NULL` and dereferencing; and promote (c) to primary criterion, add "hash node count comparison" early detection |

## 12. Suggested fixes (non-blocking)

| # | Content |
|---|---|
| G2-S1 | spec §6.1/§6.2 add §5.3's two **risk-reducing facts**: `uma_page` hash **insert-only** (no `LIST_REMOVE`) ⟹ no UAF, `le_prev` no consumer ⟹ worst failure converges to "insertion lost". This would实质 downgrade that risk's level |
| G2-S2 | If future adopt L1: must add compiler barrier / release store (§7.3), and handle `vsetzoneslab()`'s "hit-then-modify" branch torn read (§7.3 end) |
| G2-S3 | Commit order: suggest **M5 end → remove 6 probes (DoD-8) → then split commit-1(G1)/commit-2(G2)**, avoiding probes entering product commit; `ff_glue.c` use `git add -p` hunk split (§4) |
| G2-S4 | spec may add: G2's behavior change **strictly limited to `uma_core.c` single TU** (§2.3's impact radius convergence), making G2's risk surface much smaller than "global macro change" intuition |
| G2-S5 | `coder` report §2.2's "residual 4 `critical_enter/exit` from `smr.h`" wording suggest add: those 4 are `smr_enter/smr_exit`'s **inline function bodies**, and `uma_core.c` **never calls** these two functions (measured 0 hits) → reason stronger than "they're existing behavior" (§5.1 path B) |

---

## 13. Conclusion restated

- **M4 gate: PASS-with-fixes**, **mandatory 2** (both P2: 1 comment wording @coder, 1 spec criterion @designer), **blocking 0**.
- **Does not block M5 post-lock retest** —— can start immediately; two mandatory fixes parallel with M5.
- G2-b implementation faithful, deletion thorough, impact radius converged to `uma_core.c`, provably zero impact on SMR, fast-path invariant all-context holds, clean build and md5 **fully reconciled with coder** (error 0 / warning 51 / 248 `.o` / `helloworld` md5 `78c39a6f96e104412ce75351e402907b`).
- Only thing needing M5 runtime data to answer is **slow-path lockless window widening**, and I've converged its worst failure mode from "uncertain break chain" to "insertion lost", and gave **no-crash-needed** early detection (§9-B8).

---

# 14. Probe removal recheck (leader took over, reviewer reviewed)

> Role separation: `coder` unresponsive → **leader took over write** → this section by `reviewer` (sub-agent) reviewing, compliant with "write ≠ review" rule.
> This is **M7's last gate before commit**. All conclusions from my actually opening code / executing commands.
> I **did not modify any source code**, only write this file.

## 14.0 Conclusion

# **PASS** (with 1 mandatory, P3 · pure diff noise, **doesn't affect functionality, doesn't block commit**)

- Product changes **10 spots all fully retained**, verbatim checked none damaged.
- Probes **zero residual** (source layer 0 hits; `ff_host_interface.c`/`.h` verbatim back to HEAD).
- clean build and `helloworld` md5 **fully reconciled with leader**.
- **Commit split judged "correct and feasible"**, but I give **5 mandatory safety measures** (§14.4) —— of which 1 is must-do verification.
- Incidentally confirmed: my §11's **G2 mandatory-1 and mandatory-2 both closed** (§14.6).

## 14.1 Review item 1: Only removed probes, didn't damage product code —— **PASS (10/10 fully retained)**

Verbatim checked `git diff` full text, G1/G2 product changes **all in place**:

| # | Product change | Location (workspace) | Check |
|---|---|---|---|
| 1 | `-DSMP` | `lib/Makefile:221-223` (+2 lines comment) | ✓ in place |
| 2 | `smp_topo()` stub returns NULL | `lib/ff_glue.c:171-177` | ✓ in place |
| 3 | Triple `mp_ncpus`/`mp_maxid`/`all_cpus` + timing comment | `ff_freebsd_init.c:298-317` | ✓ in place |
| 4 | `uma_page_slab_hash` **advanced before `uma_startup1()`** | `ff_freebsd_init.c:322-330` before `:332-336`'s `uma_startup1`; original 3 lines deleted | ✓ in place (crash fix intact) |
| 5 | `ff_pcpu_thread_init` **actually uses parameter** + upper bound `panic` | `ff_freebsd_init.c:106-112` | ✓ in place |
| 6 | Main thread dense numbering (incl `thread_mode` gate) | `ff_freebsd_init.c:317` | ✓ in place |
| 6b | Worker dense numbering (incl `thread_mode` gate) | `ff_dpdk_if.c:2652` | ✓ in place |
| 6c | `ff_cur_proc_id()` definition + prototype | `ff_dpdk_if.c:412-417`, `ff_dpdk_if.h:81`, `ff_freebsd_init.c:73-74` | ✓ three places ready |
| 7 | `timeout_cpu` → `static __thread` + **corrected** comment | `ff_kern_timeout.c:190`; `:180-181` is G1 mandatory-2's corrected version | ✓ in place |
| 8 | `pause_wchan` fallback | `ff_kern_synch.c:105-107` | ✓ in place |
| 9 | `curcpu` per-thread | `lib/include/sys/pcpu.h:34` | ✓ in place |
| 10 | `critical_enter/exit` no-ops + delete `uma_crit_lock` (decl + def) | `uma_int.h:44-50` + `ff_glue.c` delete `:146` | ✓ in place |

**`ff_stack_thread_init()`'s CM5-B body not误伤**: that function region in `git diff` **completely no hunk** → verbatim same as HEAD → clean restore after removing probe calls ✓

## 14.2 Review item 2: No residual —— **PASS**

- **Source layer zero residual** (I reran): `grep -rn "M17\|ff_probe\|temporary probe" lib/ --include=*.c --include=*.h --include=Makefile` → **0 hits**. Full repo `grep -rn "ff_probe_tid\|ff_probe_slots\|ff_probe_pcpu_zone\|M17-PROBE" .` (excluding `.git/`, `docs/`, `*.log`, binaries) → **0 hits**
- **`ff_host_interface.c` / `.h` verbatim back to HEAD** ✓: `git --no-pager diff --stat lib/ff_host_interface.c lib/ff_host_interface.h` → **output empty**; and both files disappeared from `git status`'s modified list.
- **Binary layer residual gone with recompile** ✓: `nm libfstack.a | grep -c uma_crit_lock` → **0**; `nm libfstack.a | grep -c ff_probe` → **0**
- **Change set converged to 9 files**, `--numstat` consistent with leader self-report (76 insertions / 29 deletions).
- `git status --short freebsd/` → **empty** (upstream tree zero changes) ✓

## 14.3 Review item 3: clean build re-verification (I ran) —— **PASS, md5 consistent with leader**

| Metric | My measured | leader self-report | Threshold | Verdict |
|---|---|---|---|---|
| `lib` `make` return code | **0** | 0 | 0 | PASS |
| `lib` `grep -c "error:"` | **0** | 0 | 0 | PASS |
| `lib` `grep -c "warning:"` | **51** | 51 | ≤ 51 (HEAD baseline) | PASS (probe removal zero change) |
| `lib` `.o` count | **248** | — | 248 | PASS |
| `nm libfstack.a \| grep -c uma_crit_lock` | **0** | — | 0 | PASS |
| `nm libfstack.a \| grep -c ff_probe` | **0** | — | 0 | PASS (I added) |
| `example` `make` return code | **0** | 0 | 0 | PASS |
| `example` `error:` / `undefined reference` | **0** / **0** | 0 | 0 | PASS |
| `example/helloworld` size | **30,392,632** B | 30,392,632 B | — | **consistent** |
| **`example/helloworld` md5** | **`df05d2cd078d631ad2d8ee7caba8d387`** | `df05d2cd078d631ad2d8ee7caba8d387` | — | ✅ **fully consistent** |

Combined with my `_m17_gate_code_g1.md` §9.5's evidence "`helloworld` md5 reproducible", this consistency constitutes valid evidence "leader and reviewer built from same source state" ✓
Temp logs cleaned via `/data/workspace/rm_tmp_file.sh`.

## 14.4 Review item 4: Commit split feasibility —— **judgment: split method correct and feasible**, but must add 5 safety measures

### 14.4.1 Split method itself correct

leader's plan (commit-1 temporarily adds `volatile int uma_crit_lock;` back → commit 8 files; commit-2 deletes it → commit `ff_glue.c` + `uma_int.h`) **logically correct**, reasons:
- **commit-1's tree state self-consistent**: `uma_int.h` stays at HEAD (with `extern volatile int uma_crit_lock;` + spinlock macros) **requires** a definition, and temporarily re-added `ff_glue.c:146` provides it → **declaration/definition paired complete**, compile and link both hold.
- **commit-2 removes declaration and definition simultaneously** → also paired complete.
- **Two commits' union = current workspace state** (`ff_glue.c`'s temp line deleted back in commit-2) → final tree correct.

### 14.4.2 commit-1 compilability: evidence chain holds, **but that exact tree state never compiled → must verify**

- Supporting evidence: `-DSMP` + **HEAD version `uma_int.h` (spinlock macros)** combo in M3 period I **successfully clean built at least 3 times**; `uma_core.c`'s 21 `critical_enter/exit` all in statement positions, same as HEAD.
- But commit-1 = "G1 **with probes removed**", and **probe-removed G1 (pre-lock) state neither I nor leader have compiled separately** (we compiled "probes removed + post-lock" final state). Difference only in `ff_freebsd_init.c`'s probe blocks and `ff_host_interface.c/.h`, orthogonal to `uma_int.h`, **infer compilable**, but is inference.
- → **Mandatory measure S3 (see below)**: run `make clean && make` once when workspace is commit-1's state (before/after commit-1).

**Good news for bisect**: commit-1's semantic state = "G1 landed, lock not removed", exactly M5-tested `example/helloworld_g1_prelock` corresponding config → **that intermediate commit is runtime-verified state**, `git bisect` landing on it won't hit unverified combo.

### 14.4.3 commit-2 can `git revert` alone —— **holds**

commit-2 only touches two spots: `ff_glue.c`'s `:146` (1 line delete) and `uma_int.h:44-50` (macro block replace). `git revert commit-2` will re-add that line and restore spinlock macros. **G1's `smp_topo` region at `ff_glue.c:171+`, ~25 lines from `:146`, no context overlap** → revert won't touch G1 region, no conflict ✓ → **spec §4.7.4's L0 step (commit-2 can revert alone without affecting G1) holds**.

### 14.4.4 More stable alternative evaluation —— **conclusion: leader's method already optimal, no need to change**

I evaluated two "don't modify workspace" alternatives, **both inferior**:
- `git add -p`: **cannot non-interactively execute** (leader noted), excluded.
- `git diff lib/ff_glue.c` split hunk then `git apply --cached`: non-interactive ok, but **hunk line numbers offset risk** —— G1 hunk's head `@@ -171,0 +171,7 @@` is calculated under "G2's `-1` deletion applied" premise; applying alone to HEAD index would produce ±1 line offset, relies on `git apply` fuzzy matching, **more fragile**.
→ **Maintain leader's plan** (directly construct commit-1's file content = HEAD + `smp_topo` block), most intuitive, no line-number dependency.

### 14.4.5 Mandatory safety measures (5, S1/S3/S4 must-do)

| # | Measure | Reason |
|---|---|---|
| **S1** (must-do) | **First fix §14.5's mandatory (extra blank line), then start commit**. After fix use `git diff -w lib/ff_freebsd_init.c` compare with pre-fix —— if identical, proves that change is pure whitespace, zero semantic change, so M5 and smoke results **can directly reuse no retest needed**; but must **rerun one clean build for new md5** as M7's version pin (my `df05d2cd…` corresponds to **pre-fix** state) | Avoid committing diff noise to product history; also gives "no retest needed" strict argument |
| **S2** (must-do) | **Strictly prohibit `git add .` / `git add -A` / `git commit -a`**, must逐个 explicit path. `config.ini` is ` M` with local test values, any wildcard add brings it in | This repo has happened twice (AI memory 44404940: commits `4b605b02d`, `7b6bcca2f` both误带 local test values) |
| **S3** (must-do) | **Before commit-1 commit (when workspace is its state) run `make clean && make` once** (`lib/` + `example/`), confirm error 0 / warning 51 / 248 `.o` | §14.4.2: that exact tree state never compiled, cannot rely on inference alone |
| S4 (strongly recommended) | **After commit-2 do three end-to-end consistency checks**: ① `git status --short lib/` must be **clean** (proves temp re-added line actually deleted back); ② `git diff HEAD~2 --stat lib/` must equal **9 files / 75 insertions / 29 deletions** (post-blank-fix expected value); ③ `make clean && make` reproduce S1's recorded new md5 | End-to-end proof "two commits' union == reviewed final state", prevent temp edit residual |
| S5 (strongly recommended) | For each commit run `git show --stat <commit>`, visually confirm **no `config.ini`, no `.log`/binary/`*.ini` temp files** | Final commit content gatekeeping |

**commit message (per AI memory 73362122, English, 1-3 sentences) suggested**:
- commit-1: `Make the FreeBSD kernel view SMP-aware with per-thread dense pcpu slots.` + brief `-DSMP`, triple, dense numbering, `curcpu` per-thread, `uma_page_slab_hash` advance fix.
- commit-2: `Remove the global uma_crit_lock now that each stack thread owns a distinct per-cpu slot.`

## 14.5 Mandatory fix (1)

| # | Level | Location | Issue | Fix |
|---|---|---|---|---|
| **Mandatory-3** | **P3 · pure diff noise (doesn't affect functionality)** | `lib/ff_freebsd_init.c`, between `ff_stack_inited = 1;` and `return (0);` | Removing probe block left **one extra blank line**: HEAD here has **1** blank line, current workspace has **2** (I verified with `cat -A` and `git show HEAD:...` verbatim comparison). This produces a **pure whitespace diff hunk** `@@ -347,5 +375,6 @@` (1 line `+` blank), would enter product commit as meaningless noise | Delete one blank line, make that hunk **completely disappear**. Expected post-fix: `ff_freebsd_init.c`'s `--numstat` from **43/14 → 42/14**, `lib/` total from **76/29 → 75/29** |

> Severity note: doesn't affect any functionality, I judge **P3**, **doesn't block commit**; but since this project has consistent "zero unnecessary diff bytes" requirement (and I judged comment issues twice at same standard in G1/G2), cleanest to fix before commit. **If leader decides not to fix, I don't change to FAIL**, just note in commit message.

## 14.6 Incidental confirmation: my §11's 2 G2 mandatory fixes **both closed**

| Original mandatory | Status | Basis |
|---|---|---|
| **G2 mandatory-1** (`uma_int.h` comment "No preemption in f-stack userspace" wrong statement) | ✅ **fixed** | Current comment is "`curcpu` is per-thread here (sys/pcpu.h), not per-CPU, so preemption cannot change which `uz_cpu[]` slot this thread uses…" —— **verbatim consistent** with my §8's replacement text, wrong premise eliminated |
| **G2 mandatory-2** (spec §4.7.4's L1 criterion (a) points to dead code, never triggerable) | ✅ **fixed** | spec (mtime 16:21) §4.7.4's L1 criterion **wholly rewritten**: **(c) promoted to primary** (hash structure anomaly direct evidence + no-crash-needed early detection), **(a′) secondary** (crash point at `vtoslab()` / `uma_core.c:4930` / `:5819`), **(b) corroboration** (only `thread_mode=1 && nb_threads≥2` reproduces), and **⛔ explicit prohibition** reusing `uma_int.h:101/102` with "`vtozoneslab()` only caller `kern_malloc.c` not in SRCS ⇒ dead code" establishment. (Residual 2 `uma_int.h:101` mentions both in that ⛔ explanation text, correct usage not missed fix) |
| Suggestions G2-S1 / G2-S2 | ✅ both adopted | S1 (hash insert-only ⇒ no UAF, worst is insertion lost) see spec `:735`'s risk **downgrade** wording; S2 (compiler barrier / release store + "hit-then-modify" torn read) see §4.7.6 and `:610-611`, and designer further established "`vtoslab()` doesn't read `up_zone` ⇒ that torn read has no consumer in current compile set" |

## 14.7 Review item 5: Files not to enter commit (I fully enumerated)

**A. Tracked but absolutely must not enter (1)**
- **`config.ini`** (` M`, 14 insertions / 12 deletions): contains local test values `lcore_mask=6` / `thread_mode=1` / `idle_sleep=20` / `addr=9.134.214.176` etc. **Absolutely must not enter** (AI memory 44404940).

**B. Untracked temp artifacts —— all must not enter**
- **Binaries (5, note: these `.gitignore` don't cover!)**: `example/helloworld_g1_prelock`, `example/helloworld_g2_nolock`, `example/helloworld_zc_base`, `example/helloworld_zc_recv`, `example/helloworld_stacksel/helloworld_stacksel`
  > **Measured risk**: `example/helloworld` itself **already ignored by `.gitignore:12`**, but above **renamed/copied** binaries **not covered by any ignore rule** (`git check-ignore` no output for `helloworld_g1_prelock`) → once `git add .` would commit 5 ~30 MB binaries. This is S2's most real危害.
- **Logs (16)**: various `.log` files
- **Test configs (3)**: `config.m17_g2_2t.ini`, `config.m17_g2_4t.ini`, `config.test-dpdk24-multi.ini`
- **Other (3)**: `dkdns_ospf.sh`, `dpdk.bak-23.11.5/`, `.codebuddy/` (**note: per project convention this dir must not be deleted, but also must not be committed**)
- **`tests/unit/fixtures/valid_thread_mode.ini`**: possibly intentional new test fixture, but **unrelated to G1/G2** → should not mix into these two commits; if need commit, separate commit.

**C. Docs (14 untracked) —— suggest independent 3rd commit, don't mix into commit-1/commit-2**
I checked this repo's existing convention (`git ls-files docs/native_mt_spec/zh_cn/`): **numbered specs (`00-`…`16-`), `plan-16-…`, and `_m1_A_codepath.md`/`_m1_B_external.md`/`_m4_D_review.md`/`_material_*.md`这类 intermediate work docs all tracked** → shows **this project's convention确实 includes committing `_m*` process docs**. So these 14 files **conform to convention, can enter**, but please:
1. Put in **independent docs commit** (3rd), keep commit-1/commit-2 as pure code commits, for easy `git revert` and `git bisect`;
2. Before commit confirm `_m17_C_probe_diff_A.patch` is indeed content to keep (it's M1-period probe patch, if just process garbage can not commit).

## 14.8 Unverified boundary (honest record)

1. **I didn't compile commit-1's exact tree state** (§14.4.2) —— per convention I don't modify source, don't `git add`/`commit`, so cannot construct that intermediate state. "Compilable" conclusion is **inference based on evidence chain**, so making it **mandatory measure S3**.
2. **I didn't reproduce leader's smoke test** (2-thread 236,273.85 req/s, zero error, log no `M17|panic|Segmentation|assert`). I only did static check + clean build + symbol verification.
3. **Post-mandatory-3-fix md5 I cannot give in advance**: deleting blank line theoretically doesn't change generated code, but if `panic()`/assert macros embed `__LINE__`/`__FILE__` may change. So S1 requires **re-measure post-fix and use new value as pin**; `git diff -w` identical proves semantics unchanged.
4. **I didn't verbatim review spec full text** (906+ lines), §14.6 only rechecked §4.7.4 / §4.7.6 / §6 paragraphs directly related to my §11's two mandatory fixes.
5. **`tests/unit/fixtures/valid_thread_mode.ini`'s purpose I didn't verify** (whether intentional new test fixture).

## 14.9 Conclusion restated

- **Probe removal recheck: PASS.** Product changes 10/10 intact, probes zero residual, `ff_host_interface.c/.h` verbatim back to HEAD, clean build and md5 **fully reconciled with leader** (error 0 / warning 51 / 248 `.o` / `helloworld` `df05d2cd078d631ad2d8ee7caba8d387`).
- **Mandatory 1 (mandatory-3, P3 pure whitespace noise)**, **doesn't block commit**; suggest fix before commit and re-pin md5 per S1.
- **Commit split: correct and feasible** (commit-1 tree self-consistent, commit-2 can `git revert` alone, L0 step holds), must execute **S1/S3/S4 three must-do verifications**, and strictly follow **S2 "prohibit wildcard `git add`"** —— this repo has 5 30MB-class binaries not covered by `.gitignore`, wildcard add's consequences most severe.
- My §11's **2 G2 mandatory + 2 suggestions all closed** → **M7 commit conditions ready**.