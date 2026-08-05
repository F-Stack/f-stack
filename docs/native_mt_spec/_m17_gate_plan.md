# M17 Plan Gate Review Report (gate-plan)

Reviewed object: `/data/workspace/f-stack/docs/native_mt_spec/zh_cn/plan-17-SMP-aware-pcpu-smr.md`
Reviewer: `gate-plan` (review only, no modification; this file is this agent's only write)
Review method: item-by-item `read_file` / `search_content` actually opening code for verification; unverified items explicitly marked "未核实" (unverified), no speculation.
Repository state self-check: `git log -1` = `ff09a17b2` ✓ consistent with plan §1 declaration; `b90ddcba5` exists and its message matches plan §1.4 citation **verbatim** ✓.

---

## 1. Conclusion

**PASS-with-fixes**

- No blocking defects: target coverage complete, convention coverage 10/10, milestone role separation has no "self-write self-review", most `file:line` facts are true.
- But there exist **2 factual errors** (§1.3 `pcpu_page_alloc` compile-switch attribution error; `UMA_PCPU_ALLOC_SIZE` marked "to be located" but actually statically determinable), **1 misleading wording** (calling `KASSERT` a "judgment"), **1 G2 core fact missing** (`critical_enter` is already a no-op in non-UMA TUs in f-stack), and **6 key unknowns omitted that would cause rework** (especially MAXCPU-sized array cross-TU consistency, the timing hard constraint that `mp_maxid` must precede `uma_startup`, and callout global `timeout_cpu` contention).
- Mandatory corrections: **10 items** (F1~F10, see Section 4). After fixing, M1 can proceed directly without a second bounce (bounce count recommended as M0's 1st bounce).

---

## 2. Item-by-Item Review Results

| # | Review item | Conclusion | Basis summary |
|---|---|---|---|
| 1 | file:line citation authenticity | **PASS-with-fixes** | 22 facts verified item by item: 18 fully consistent (including 8 line-accurate hits); 2 factual errors (F1/F2); 1 misleading wording (F3); 8 line deviations within ±5 but recommended to correct (F8) |
| 2 | Target completeness (G1+G2) | **PASS** | §0.2 clearly states "two parallel main goals"; G2 has independent milestone M4, independent acceptance DoD-2 and performance comparison DoD-5, independent fact section §1.4; §0.4 explicitly requires pre/post-lock throughput comparison |
| 3 | Convention coverage | **PASS (10/10)** | §4.1 three scripts + prohibit raw commands in shell strings; §4.2 make clean first (both `lib/` and `example/`); §4.3 lib minimal comments; §4.4 commit English 1-3 sentences + config.ini not committed + review diff before `git add`; §4.5 no speculation, code as authority; §4.6 write/review separation + bounce≤3 + leader no early exit + timeout polling + bypass detection (details in §3.1/§3.2); §4.7 external sources must provide verifiable links |
| 4 | Unknowns sufficiency | **FAIL (must supplement)** | U1~U8 direction correct and U4 already includes `cpuset_t`/`CPU_SETSIZE` ABI, U6 includes dense index source, U7 includes auxiliary paths, U8 includes cross-thread alloc/free; but 6 items omitted (recommended U9~U15, see Section 5), of which U9/U10/U11 are "must supplement or rework" level |
| 5 | Milestone and gate self-consistency | **PASS-with-fixes** | M0~M6 all write/review heterogeneous, no self-write self-review (see table below); only M7 and M5 gate attribution wording needs tightening (F10) |
| 6 | Acceptance criteria testability | **PASS-with-fixes** | DoD-2/4/6/7 testable; DoD-1 lacks executable means (most important); DoD-3 lacks warning baseline anchor; DoD-5 lacks pass threshold; lacks temp artifact cleanup item (F10) |

### 2.1 Review item 1 details (line-by-line verification)

Verified **consistent** (PASS):

| plan citation | actual verification | verdict |
|---|---|---|
| `ff_freebsd_init.c:85` `__thread struct pcpu *pcpup;` | actual line 85 verbatim | ✓ |
| `ff_pcpu_thread_init()` three steps | actual 103-109: `malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO)` → `pcpu_init(pcpup, 0, sizeof(struct pcpu))` → `PCPU_SET(prvspace, pcpup)`; comment 98-101 explicitly states cpuid must be 0 | ✓ |
| `:~187` worker call site inside `init_lock` critical section | `ff_stack_thread_init` starts at 171; `init_lock` declared 175, spins 185-186; `ff_pcpu_thread_init(cpuid)` at **187** | ✓ precise |
| `:~293` main thread `ff_pcpu_thread_init(0)` | actual **293** | ✓ precise |
| `pcpu.h:28-46` 10 `#undef` + `PCPU_*` redefinitions + `zpcpu_offset_cpu` undef but no redefinition | `#undef` actually 33-42 (10 items fully matching plan's list); `PCPU_GET/ADD/INC/PTR/SET` redefinitions 47-53; no `zpcpu_offset_cpu` definition after in file (69 lines total) | ✓ content consistent |
| `freebsd/sys/pcpu.h:235-236` `#ifndef zpcpu_offset_cpu` / `#define ... (UMA_PCPU_ALLOC_SIZE * cpu)` | actual `#ifndef` 234, `#define` 235, `#endif` 236 | ✓ |
| `sys/pcpu.h` `zpcpu_offset()`/`zpcpu_get`/`zpcpu_get_cpu` | `zpcpu_offset` 237-239; `zpcpu_get` 249-252; `zpcpu_get_cpu` **254-257** | ✓ content consistent |
| `subr_pcpu.c:88,91-92,96` | 88-89 `KASSERT(cpuid >= 0 && cpuid < MAXCPU, ...)`; 91 `cpuid_to_pcpu[cpuid]=pcpu`; 92 `STAILQ_INSERT_TAIL`; 96 `pc_zpcpu_offset = zpcpu_offset_cpu(cpuid)` | ✓ line-precise |
| `subr_pcpu.c:252,269-287` | 252 `#ifdef SMP` (`dpcpu_copy`); `pcpu_destroy` 270-277 (274 `STAILQ_REMOVE`, 275 clears `cpuid_to_pcpu`, 276 clears `dpcpu_off`); `pcpu_find` 282-287 | ✓ |
| `amd64/include/param.h:60-66` | 60 `#ifdef SMP`, 62 `MAXCPU 1024`, 64 `#else`, 65 unconditional `#define MAXCPU 1`, 66 `#endif` | ✓ line-precise |
| `lib/Makefile` no `-DSMP`, no `INVARIANTS` | `SMP|INVARIANTS|MAXCPU` zero hits in entire file; only 219 `CFLAGS+= -DFSTACK`, 222/226 `FSTACK_ZC_*`. Supplementary evidence: `lib/opt/` also zero hits for `SMP|INVARIANTS` | ✓ (M1-C still needs to cover `mk/`) |
| `uma_core.c:2546-2548` `#ifndef SMP` strips `UMA_ZONE_PCPU` | 2546/2547/2548 line-by-line consistent, and not inside any `#ifndef FSTACK` block | ✓ |
| `uma_core.c:3494-3516` / `:3526` | `uma_zalloc_pcpu_arg` 3494-3516 (3498 `#ifdef SMP`, 3501 `MPASS`, 3509-3510 `for(i=0;i<=mp_maxid;i++) bzero(zpcpu_get_cpu(...))`, 3512 `#else` single copy); `uma_zfree_pcpu_arg` 3521-3536 (`MPASS` at 3527) | ✓ content consistent |
| `uma_core.c:1959-1990` per-CPU version contains `MPASS(bytes == (mp_maxid+1)*PAGE_SIZE)` | function 1958-; `MPASS` 1970; `for (cpu=0; cpu<=mp_maxid; cpu++)` 1975; `CPU_ABSENT` 1976 | ✓ content consistent (**attribution error see F1**) |
| `uma_core.c:2084-2089` fallback implementation | actual 2083-2089 (2087 `*pflag=UMA_SLAB_KERNEL;` 2088 `return page_alloc(...)`) | ✓ |
| `subr_smr.c:583-609` `smr_create` | 583-609; 591 `uma_zalloc_pcpu(smr_zone, M_WAITOK)`; 598-605 `for(i=0;i<=mp_maxid;i++){ zpcpu_get_cpu; c_seq=SMR_SEQ_INVALID; c_shared=s; ...}` | ✓ precise |
| `subr_smr.c:625-632` `smr_init` `UMA_ZONE_PCPU` | actual 623-631, `uma_zcreate("SMR CPU", sizeof(struct smr), ..., UMA_ZONE_PCPU)` at 629-630 | ✓ content consistent |
| `sys/smr.h:106-143` `smr_enter` via `zpcpu_get(smr)` | function 105-143, `zpcpu_get` at 110 | ✓ (**key fact missing see F4**) |
| `in_pcb.c:583,615-617` | 583 `pcbinfo->ipi_smr = uma_zone_get_smr(pcbinfo->ipi_zone);`; 615-617 `uma_zcreate(..., UMA_ALIGN_CACHE, UMA_ZONE_SMR)` | ✓ precise |
| `uma_int.h:45-52` global spinlock code block | 45 `extern volatile int uma_crit_lock;`, 46-49 `critical_enter`, 50-52 `critical_exit`, verbatim consistent with plan's cited block; same file 43 `#undef UMA_MD_SMALL_ALLOC`, 54-57 sleepq stub, 59 `_vm_map_unlock`, 65 `UMA_PAGE_HASH`, 67-74 `struct uma_page` | ✓ |
| `ff_glue.c` global variable group | 138 `cpuset_t all_cpus;`, 140 `int mp_ncpus = 1;`, 142 `int mp_maxcpus = MAXCPU;`, 144 `volatile int smp_started;`, 145 `u_int mp_maxid;` (no init = BSS zero), 146 `volatile int uma_crit_lock;` | ✓ content consistent |
| `counter.h:44` `counter_u64_fetch_inline()` | actual 43-47 defined under `#ifdef IN_SUBR_COUNTER_C` (41), function body `return (*p);`, `counter_u64_fetch_inline` name at 44 | ✓ (**inference strength needs fix, see F6**) |
| `b90ddcba5` message | `git log` output = "Fix UMA per-CPU cache race and sizeof mismatch for native-mt multi-thread startup" | ✓ verbatim consistent |

Verified **inconsistent / needs correction** (see Section 4 F1~F3, F8 for details).

### 2.2 Review item 5 details (write/review heterogeneous verification)

| Milestone | Write | Review | Heterogeneous? |
|---|---|---|---|
| M0 | leader | `gate-plan` | ✓ (this report is the evidence) |
| M1 | `res-code`/`res-web`/`res-build` | leader aggregation + `gate-design` | ✓ |
| M2 | `designer` | `gate-design` | ✓ |
| M3 | `coder` | `reviewer` | ✓ |
| M4 | `coder` | `reviewer` | ✓ |
| M5 | `tester` (≠coder) | leader aggregation + `reviewer` | ✓ (reviewer not involved in producing data) |
| M6 | `designer` | `gate-doc` | ✓ |
| M7 | leader (commit) | leader review diff + `gate-doc` | ⚠ wording needs tightening (F10-d) |

§3.1 already states "if leader takes over any 'write' role, review must spawn a new sub-agent", self-consistent with §3.2 fallback paths ①②③ ✓.

---

## 3. Key corrections for review item 1 (must be authoritative)

1. **`pcpu_page_alloc`'s compile switch is not `UMA_MD_SMALL_ALLOC` but `FSTACK`, and the conclusion is statically determinable**:
   - `freebsd/vm/uma_core.c:1957` `#ifndef FSTACK` → per-CPU version (1958-…); `:2082` `#else` → fallback version `:2083-2089`; `:2114` `#endif` (intermediate 1966/1968, 1979/1981/1990 `NUMA` conditions all balanced; verification method: full listing of `^#(if|ifdef|ifndef|else|elif|endif)` for that file then paired).
   - `lib/Makefile:219` `CFLAGS+= -DFSTACK` → **necessarily compiles the 2083-2089 fallback version**, no preprocessing needed to guess.
   - `#undef UMA_MD_SMALL_ALLOC` is actually at `lib/include/vm/uma_int.h:43` (plan wrote 44), and it affects the `:2116`/`:2208` `#if defined(UMA_USE_DMAP) && !defined(UMA_MD_SMALL_ALLOC)` block, **unrelated to `pcpu_page_alloc` selection**.
2. **`UMA_PCPU_ALLOC_SIZE` already located**: `freebsd/sys/pcpu.h:221` `#define UMA_PCPU_ALLOC_SIZE PAGE_SIZE`; `freebsd/amd64/include/param.h:92-93` `PAGE_SHIFT 12` / `PAGE_SIZE (1<<PAGE_SHIFT)` → **4096**.
   The expansion chain is also established: `sys/pcpu.h:48` first `#include <machine/pcpu.h>` (f-stack override header, whose `:40` `#undef zpcpu_offset_cpu`), so `:234 #ifndef` holds → ultimately `zpcpu_offset_cpu(cpu) == 4096*cpu` (not the `amd64/include/pcpu.h:270` `&__pcpu[0]+...` version). Additional constraint: `freebsd/amd64/include/pcpu_aux.h:47` `_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE)` (introduced by `sys/pcpu.h:223`) → `struct pcpu` must be exactly 4096 bytes.
3. **`keg_layout`'s `uk_size <= UMA_PCPU_ALLOC_SIZE` is part of `KASSERT`**: `uma_core.c:2351-2356`, compiled out entirely without `INVARIANTS` → this "protection" **does not exist** in this build. The actually effective PCPU logic in `keg_layout` is `:2472-2478`: `pages = atop(kl.slabsize); if (UMA_ZONE_PCPU) pages *= mp_maxid + 1; keg->uk_ppera = pages;`.
4. **`critical_enter`'s actual scope (G2 argumentation core, completely missing from plan)**:
   - `freebsd/sys/systm.h:179-193`: the non-KLD branch's inline `critical_enter()` body is excluded entirely by `#ifndef FSTACK` (186) → **no-op under f-stack**; `critical_exit()` isomorphic (195-).
   - The macro-level override of `critical_enter` across the tree is only at `lib/include/vm/uma_int.h:46/50` (`search_content` full repo `define\s+critical_enter` only hits uma_int.h and systm.h).
   - Of the 11 `.c` files that include `vm/uma_int.h`, only `freebsd/vm/uma_core.c` (:650) and `lib/ff_freebsd_init.c` are in `lib/Makefile` SRCS; `kern_malloc.c`/`subr_vmem.c`/`vm_page.c`/`uma_dbg.c`/`memguard.c`/`kern_switch.c` have **zero hits** in `lib/Makefile` (not compiled).
   - Implication (favorable to G2, must be written into spec): `uma_crit_lock` actually only serializes `uma_core.c`'s allocation fast path; `smr_enter()` (smr.h:109)'s `critical_enter()` is a **no-op** in TUs like `in_pcb.c` → the SMR read side currently has **no** preemption/concurrency protection, sharing the `c_seq` slot is the only real risk, consistent with §0.1's statement; also shows "after removing `uma_crit_lock`, UMA merely returns to the same 'empty critical section' semantics as other subsystems", so the equivalence argument's anchor should be "each thread exclusively owns a per-cpu slot" rather than "disabling preemption".
5. **counter(9) conclusion strength**: `lib/include/amd64/include/counter.h` has completely de-per-cpu'd counter (`counter_u64_add` 58-62 `*c += inc`; fetch 43-47 `*p`; zero 49-53 `*c=0`; `counter_enter/exit` 38-39 no-ops), and `freebsd/kern/subr_counter.c` has **zero hits** for `mp_maxid|CPU_FOREACH|zpcpu`, the only per-cpu trace is `:63 uma_zalloc_pcpu(pcpu_zone_8, ...)`. → After `mp_maxid` is raised, counter path **will not go out of bounds**; the real impact is multi-threaded writes to the same slot causing stat contention and fetch only reading slot 0.

---

## 4. Mandatory Correction List (10 items, with suggested wording)

> F1~F4 are factual/conclusion-level (must fix), F5~F7 are fact supplements, F8 is line-number correction, F9~F10 are unknowns and acceptance.

**F1 (factual error, must fix)** §1.3 item 3.
Suggested replacement:
> - `freebsd/vm/uma_core.c:1957` `#ifndef FSTACK` → per-CPU `vm_page_alloc_noobj` version `pcpu_page_alloc` (`:1970 MPASS(bytes == (mp_maxid+1)*PAGE_SIZE)`, `:1975 for (cpu=0; cpu<=mp_maxid; cpu++)`); `:2082 #else` → fallback version `:2083-2089` (`return page_alloc(zone,bytes,domain,pflag,wait)`). Because `lib/Makefile:219 CFLAGS+= -DFSTACK`, **this build necessarily compiles the fallback version (statically established, not pending verification)**. `lib/include/vm/uma_int.h:43 #undef UMA_MD_SMALL_ALLOC` affects `uma_core.c:2116`/`:2208`'s `UMA_USE_DMAP && !UMA_MD_SMALL_ALLOC` block, unrelated to this selection.

**F2 (factual error, must fix)** §1.3 item 4 "`UMA_PCPU_ALLOC_SIZE` definition location pending".
Suggested replacement:
> - `freebsd/sys/pcpu.h:221 #define UMA_PCPU_ALLOC_SIZE PAGE_SIZE`, `freebsd/amd64/include/param.h:92-93 PAGE_SHIFT 12 / PAGE_SIZE (1<<12)` → **4096**. Because `sys/pcpu.h:48` first includes f-stack's override `machine/pcpu.h` (whose `:40 #undef zpcpu_offset_cpu`), `sys/pcpu.h:234 #ifndef` holds → `zpcpu_offset_cpu(cpu) == 4096*cpu` (not `freebsd/amd64/include/pcpu.h:270` version). Also `freebsd/amd64/include/pcpu_aux.h:47` (introduced by `sys/pcpu.h:223`) `_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE)` requires `struct pcpu` to be exactly 4096 bytes.

Also downgrade **U1** to confirmatory verification:
> U1 (statically established, `gcc -E` only for cross-confirmation): `zpcpu_offset_cpu(cpu) = 4096*cpu`, `UMA_PCPU_ALLOC_SIZE = PAGE_SIZE = 4096`.

**F3 (misleading wording, must fix)** §1.3 item 5 "`keg_layout` has … judgment".
Suggested replacement:
> - `freebsd/vm/uma_core.c:2351-2356` is `KASSERT((uk_flags & UMA_ZONE_PCPU)==0 || (uk_size <= UMA_PCPU_ALLOC_SIZE && ...))`, **compiled out entirely without `INVARIANTS`, this build has no such runtime protection**. The actually effective PCPU logic in `keg_layout` is `:2472-2478`: `pages = atop(kl.slabsize); if (UMA_ZONE_PCPU) pages *= mp_maxid+1; keg->uk_ppera = pages;`.

**F4 (G2 key fact missing, must supplement)** §1.4 add one item (wording see Section 3 item 4 full text), must at least include: `systm.h:179-193`'s `#ifndef FSTACK` no-op, `uma_crit_lock`'s actual coverage only `uma_core.c` (+`ff_freebsd_init.c`), `smr_enter()` not protected by this lock, and the resulting G2 equivalence argument anchor.

**F5 (timing hard constraint, must supplement)** §1.3 add, with corresponding new U10:
> - `freebsd/vm/uma_core.c:3179-3182`: zone struct size `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + ...` is computed once during **uma_startup**; `:2472-2478` keg's `uk_ppera` also scales by `mp_maxid+1`; `:2873 zone_update_caches`, `:5589/:5620/:5674` stats paths all traverse `uz_cpu[]` by `mp_maxid`. → **`mp_maxid` must be set before `uma_startup1/2` and never changed after, otherwise `uz_cpu[i>0]` out of bounds (heap overflow)**.

**F6 (conclusion strength, must fix)** §1.4 last item counter-related, suggested replacement:
> - `lib/include/amd64/include/counter.h:38-62` completely de-per-cpu's counter(9) (`counter_u64_add` is `*c += inc`, `counter_u64_fetch_inline` (43-47) is `*p`, `counter_enter/exit` no-ops), `freebsd/kern/subr_counter.c` has no `mp_maxid`/`CPU_FOREACH` traversal (only `:63 uma_zalloc_pcpu(pcpu_zone_8,...)`). → After `mp_maxid` is raised, counter **will not go out of bounds**; the actual impact is multi-threaded writes to the same slot causing stat contention and fetch only reading slot 0, must be recorded as known deviation not memory-safety issue in spec.

**F7 (fact supplement, must supplement)** §1.1 table add two rows:
> | `lib/ff_dpdk_if.c:2649` | `ff_stack_thread_init(rte_lcore_id());` —— **the actual source of cpuid is `rte_lcore_id()`**, G1's dense index change must land at this call site |
> | `lib/ff_freebsd_init.c:294` | main thread `ff_pcpu_thread_init(0)` immediately followed by `CPU_SET(0, &all_cpus);` —— `all_cpus` currently only contains CPU 0, must sync after `mp_maxid>0` |

**F8 (line-number correction, recommended to fix all at once)**
`ff_glue.c:143-147` → `138-146`; `uma_int.h:44` (`#undef UMA_MD_SMALL_ALLOC`) → `:43`; `subr_smr.c:625-632` (`smr_init`) → `:623-631`; `uma_core.c:3526` (`uma_zfree_pcpu_arg`) → `:3521-3536` (`MPASS` at `:3527`); `lib/include/amd64/include/pcpu.h:28-46` → `:33-42` (undef) + `:47-53` (redefinition) + `:55-67` (`__curthread_ff`/`curthread` redefinition, plan only wrote undef not redefinition); `sys/pcpu.h:235-236` → `:234-236`; `:239-240` → `:237-239`, and add `zpcpu_get_cpu` actually at `:254-257`; `subr_pcpu.c:88` KASSERT condition should be written in full `cpuid >= 0 && cpuid < MAXCPU`.

**F9 (unknowns supplement, must supplement)** Add U9~U15, full text see Section 5.

**F10 (acceptance criteria, must fix)**
- (a) **DoD-1 must provide means and formulas**, suggested:
  > DoD-1: in `ff_pcpu_thread_init()` (temporary probe, cleaned up after M5 per §4.1 via `/data/workspace/rm_tmp_file.sh` or converted to `ff_log`) print `tid / dense_idx / pcpup->pc_cpuid / pcpup->pc_zpcpu_offset / mp_maxid`, and after `smr_create()` print each worker's `&zpcpu_get(ipi_smr)->c_seq`; criteria: ① each worker `pc_zpcpu_offset == 4096 * dense_idx` and `dense_idx <= mp_maxid`; ② pairwise `c_seq` address difference `== 4096 * Δidx` and all within `[base, base + (mp_maxid+1)*4096)`; ③ log evidence from `example/helloworld.log` and persisted to `_m17_E_runtime.md`.
- (b) **DoD-3** add warning baseline anchor (repo root already has untracked `_m17_build_base.log`, `_m17_base_clean.log` as baseline): "M1-C recorded clean build warning count as baseline, post-change `grep -c warning:` must not increase".
- (c) **DoD-5** add threshold and failure handling: "post-lock throughput must not be lower than pre-lock (same machine/client, ≥3 rounds median, allow ±2% noise); if no improvement post-lock, still must provide code-level conclusion explaining G2's correctness benefit, and `reviewer` gate confirms whether to keep".
- (d) **M7 gate attribution** tightened to: "gate = `gate-doc` (review commit scope and `git diff`); leader's own diff review is only pre-commit self-check, not counted as gate"; similarly M5 add "if leader takes over test execution, data review must spawn new sub-agent".
- (e) **Add DoD-8**: "repo temp artifacts (currently existing: `lib/_m17_probe_u1.c`, root `_m17_base_clean.log`/`_m17_build_base.log`/`_m17_srcpaths.txt`/`_m17_srcset.txt`/`_m17_uma_core.i`/`a.log`, `example/*.log`, etc.) must be cleaned via `/data/workspace/rm_tmp_file.sh` or confirmed not committed before M7; `config.ini` is currently in modified state (`git status` shows `M config.ini`), must review item by item before commit and roll back local test values".

---

## 5. Recommended New Unknowns List (U9~U15)

| # | Unknown | Code basis (actually verified) | Priority |
|---|---|---|---|
| **U9** | **Cross-TU consistency** of MAXCPU-sized arrays: when candidate B rewrites `MAXCPU` via override header, do all TUs see the same value? Any TU missed creates a new out-of-bounds source | `freebsd/kern/subr_pcpu.c:76-77` `uintptr_t dpcpu_off[MAXCPU]; struct pcpu *cpuid_to_pcpu[MAXCPU];`; `lib/ff_kern_synch.c:59` `static uint8_t pause_wchan[MAXCPU];` (`:105` indexed by `curcpu`); `lib/ff_glue.c:142` `int mp_maxcpus = MAXCPU;`; `lib/ff_kern_timeout.c:730` `cpu >= MAXCPU` panic check; `freebsd/amd64/include/param.h:60-66` non-SMP branch is **unconditional** `#define MAXCPU 1` (override needs `#undef` first) | **High** |
| **U10** | **Setting timing** of `mp_maxid`: must be before `uma_startup1/2` (all zone `uz_cpu[]` sizes fixed here), and immutable after; must confirm f-stack startup sequence: `mp_maxid` assignment point vs `uma_startup*`/`smr_init`/each `uma_zcreate` ordering | `uma_core.c:3179-3182` (`zsize` includes `sizeof(struct uma_cache)*(mp_maxid+1)`), `:2472-2478` (`uk_ppera *= mp_maxid+1`), `:2873 zone_update_caches`, `:5589/:5620/:5674` stats traversal; `subr_smr.c:598` loop | **High** |
| **U11** | callout cpuid semantics distortion under dense index: `timeout_cpu` is a **non-`__thread` global** written by every thread; `CC_CPU/CC_SELF` ignore cpu arg; `cpu >= MAXCPU` check panics | `lib/ff_kern_timeout.c:183-185` (`__thread struct callout_cpu cc_cpu; #define CC_CPU(cpu) &cc_cpu`, comment explicitly says "cpuid is always 0, MAXCPU=1"), `:190 static int timeout_cpu;`, `:254 timeout_cpu = PCPU_GET(cpuid);`, `:662/:1181 CC_CPU(timeout_cpu)`, `:1061/:1077 c->c_cpu = timeout_cpu;`, `:730-733 panic("Invalid CPU in callout %d")` | **High** |
| **U12** | Dense pcpu id and `rte_lcore_id()` form **two index spaces**, must confirm no mixing per point; DPDK side `rte_mempool` per-lcore cache still uses `rte_lcore_id()`, unrelated to UMA per-cpu slots (must write clear boundary in spec to avoid mistaking mbuf pool for UMA issue) | `lib/ff_dpdk_if.c:2649` (cpuid source), `:2745/:2841 veth_ctx[rte_lcore_id()][port_id]`, `:582-583 rte_pktmbuf_pool_create(..., MEMPOOL_CACHE_SIZE, ...)`, `:536/:600 nb_lcores*MEMPOOL_CACHE_SIZE`; also `lib/Makefile:346,372-373` shows `kern_mbuf.c`/`uipc_mbuf.c` **are compiled** (UMA mbuf zone and DPDK pool coexist, U8's cross-thread free risk is real) | Medium |
| **U13** | **Threads without `pcpup`** that may enter UMA/SMR fast path: `ff_pthread_create` only inherits `pcurthread`, does not do `ff_pcpu_thread_init` → such threads have `pcpup == NULL`; after G2 lock removal, must exhaust "which threads hold a valid pcpup" first | `lib/ff_thread.c:20-30` (`ff_start_routine` only does `ff_set_thread(p_data->parent)`), `:33-46 ff_pthread_create`; `lib/ff_freebsd_init.c:177-187` (only threads going through `ff_stack_thread_init` build pcpu). KNI / `ff_veth` / DPDK service thread models **unverified**, must supplement in M1-A | Medium |
| **U14** | Other readers of `mp_ncpus` (plan U4 list omission) | `lib/ff_ng_base.c:3249 numthreads = mp_ncpus;` (netgraph), `lib/ff_kern_timeout.c:1212-1216` (print only) | Medium |
| **U15** | DPCPU path can be determined as low-risk but needs a one-sentence conclusion to avoid M1 repetition: `dpcpu_init()` only defined at `freebsd/kern/subr_pcpu.c:100`, **no callers** in `lib/` and `freebsd/kern/` (other dirs not exhaustively verified); but `pcpu_destroy():276` still writes `dpcpu_off[pc_cpuid]`, so still subject to U9's `MAXCPU` consistency constraint | `subr_pcpu.c:76,100,276`; `lib/*.c` `dpcpu_init|DPCPU_` zero hits | Low |

Regarding the four candidate omissions named by leader, responding one by one:
1. `cpuset_t`/`CPU_SETSIZE` ABI —— **plan already covers** (U4 parenthetical), no need to add; just supplement one basis (`lib/ff_freebsd_init.c:294 CPU_SET(0,&all_cpus)`, `lib/ff_glue.c:138`).
2. `dpcpu` path —— verified as low-risk, see **U15** (give conclusion not leave blank).
3. Whether `ff_veth`/KNI/callout threads go through UMA fast path —— callout established as **deterministic issue** (**U11**); `ff_veth`/KNI thread models **unverified**, into **U13**.
4. DPDK `rte_mempool` and UMA relationship —— into **U12** (and established UMA mbuf zone and DPDK pool coexist).

---

## 6. Unverified Items (Honest Boundary)

- Whether `mk/` dir and `example/Makefile` inject `-DSMP`/`-DINVARIANTS` elsewhere: only verified `lib/Makefile` and `lib/opt/`, **not exhaustive** (plan §1.2 already lists it as M1-C task, keep).
- Whether `dpcpu_init()` has callers in other `freebsd/` subdirs (e.g. `amd64/`, `net*/`): **not exhaustively verified** (only checked `lib/` and `freebsd/kern/`).
- KNI (`lib/ff_dpdk_kni.c`, `FF_KNI=1` enabled at `lib/Makefile:36,90-91`) and `ff_veth` thread ownership, whether they reach UMA fast path: **unverified**.
- §5.1 performance baseline: cross-checked with `16-多队列对照实验与根因纠偏.md:79-95`, E4/E5-a/E5-c and soak (497k req/s, 29,834,366 requests/1.00m) **consistent** ✓; `thread_mode=0` 1 process `209,946/209,367` (E5-b) not hit in this grep's lines, **not verbatim verified**.
- Runtime behavior (DoD-1/U2 actual allocation sizes, pre/post-lock throughput): this gate is static review, **no runtime verification done**.

---

Review completion time: 2026-08-04. This report only states verified facts and mandatory corrections; plan.md modifications are executed by leader (write/review separation).

---

## 7. Re-review (bounce=1)

Re-review scope: only verify whether F1~F10 are correctly implemented + whether new factual errors are introduced (per leader's instruction, not re-running full file:line).
Re-review method: re-read the revised `plan-17-SMP-aware-pcpu-smr.md` completely, compare verbatim with this report's Section 3/4/5 verified facts; re-align leader's newly written line numbers (`uma_core.c:2114`, `ff_kern_timeout.c:662/:1181`, `lib/Makefile:650`, `ff_dpdk_if.c:582-583`, `counter.h:58-62`, `uma_int.h:54-57/59/65/67-74`) with first-round retained original grep/read results.

### 7.1 Conclusion

**PASS**

F1~F10 **all correctly implemented (10/10)**, wording matches my suggested or more precise, **no newly introduced factual errors, no overstepping of evidence boundary**.
Remaining 1 medium traceability gap (R1) + 3 nits (R2~R4), **none constitute bounce**; R1 recommended to fill with one line before spawning M1 sub-agents.

### 7.2 F1~F10 implementation verification table

| Item | Landing | Verification result |
|---|---|---|
| **F1** | §1.3 item 3 (`:68`) | ✓ correct. `uma_core.c:1957 #ifndef FSTACK` / `:1970 MPASS` / `:1975` loop / `:2082 #else` / `:2083-2089` fallback / `:2114 #endif` / `lib/Makefile:219 -DFSTACK` all consistent with measurement; "statically established, not pending verification" wording accurate; `uma_int.h:43 #undef UMA_MD_SMALL_ALLOC` corrected and clearly "unrelated to this selection" and correctly points to `:2116`/`:2208`'s `UMA_USE_DMAP && !UMA_MD_SMALL_ALLOC` block |
| **F2** | §1.3 item 4 (`:69`) + U1 (`:97`) | ✓ correct. `sys/pcpu.h:221` / `param.h:92-93` / `4096` / `sys/pcpu.h:48` first includes override header / override header `:40 #undef` / `sys/pcpu.h:234 #ifndef` holds / excludes `amd64/include/pcpu.h:270` version —— expansion chain complete; U1 downgraded to "statically established, `gcc -E` only for cross-confirmation" |
| **F3** | §1.3 item 5 (`:70`) | ✓ correct. Clearly states `:2351-2356` is `KASSERT` and "compiled out without INVARIANTS, this build has no such runtime protection"; added actually effective logic `:2472-2478 pages *= mp_maxid+1; uk_ppera = pages` |
| **F4** | §1.4 new item (`:86-87`) | ✓ correct and complete. `systm.h:179-193` + `:186 #ifndef FSTACK` no-op ✓; macro-level override only `uma_int.h:46/50` ✓; SRCS TUs including `vm/uma_int.h` are only `uma_core.c` (`lib/Makefile:650`) and `ff_freebsd_init.c`, and names `kern_malloc.c/subr_vmem.c/vm_page.c/uma_dbg.c/memguard.c/kern_switch.c` as not compiled ✓; `smr_enter()` (smr.h:109) not protected by this lock, "SMR read side currently has no preemption/concurrency protection" ✓; G2 equivalence argument anchor changed to "each thread exclusively owns per-cpu slot" not "disable preemption" ✓. Also §1.3 `:74` adds cross-reference (`smr.h:105-143`, `:110`), front-to-back self-consistent |
| **F5** | §1.3 new item (`:71`) + U10 (`:106`) | ✓ correct. `uma_core.c:3179-3182` zsize fixed / `:2472-2478` / `:2873 zone_update_caches` / `:5589/:5620/:5674` stats traversal / "must be set before `uma_startup1/2` and immutable after, otherwise `uz_cpu[i>0]` out of bounds (heap overflow)" —— matches measurement item by item; U10 listed as "High" priority |
| **F6** | §1.4 last item (`:89`) | ✓ correct. `counter.h:38-62` (`counter_u64_add:58-62`, `counter_u64_fetch_inline:43-47`, `counter_enter/exit:38-39`) + `subr_counter.c` no `mp_maxid`/`CPU_FOREACH`/`zpcpu` traversal, only `:63 uma_zalloc_pcpu(pcpu_zone_8,...)`; conclusion changed to "will not go out of bounds; actual impact is stat contention + fetch only reads slot 0, **known deviation** not memory-safety issue" —— strength accurate |
| **F7** | §1.1 new 3 rows (`:54-56`) | ✓ correct. `ff_dpdk_if.c:2649 ff_stack_thread_init(rte_lcore_id())` and points out "G1 change must land at this call site" ✓; `ff_freebsd_init.c:294 CPU_SET(0,&all_cpus)` ✓; `pcpu_aux.h:47` (via `sys/pcpu.h:223`) `_Static_assert(sizeof(struct pcpu)==UMA_PCPU_ALLOC_SIZE)` "must be exactly 4096 bytes" ✓ |
| **F8** | §1.1/§1.2/§1.3 multiple | ✓ mostly all implemented (1 missed, see R2). Corrected: `ff_glue.c:138-146` with per-variable line annotation ✓; `pcpu.h:33-42` (undef, 10 items annotated)/`:47-53`/`:55-67` ✓; `sys/pcpu.h:234-236`, `:237-239,249-252,254-257` ✓; `subr_pcpu.c:88-89` KASSERT condition written in full `cpuid >= 0 && cpuid < MAXCPU` ✓, `:252,270-277,282-287` with `:274/:275/:276` detailed ✓; `subr_smr.c:583-609` (detail `:591`/`:598-605`), `:623-631` ✓; `smr.h:105-143` (`:110`) ✓; `uma_int.h` detail `:43/:54-57/:59/:65/:67-74` ✓ |
| **F9** | Section 2 U9~U15 (`:105-111`) | ✓ correct and complete. All 7 items written with priority (U9/U10/U11 high, U12/U13/U14 medium, U15 low); all code bases verified item by item: `subr_pcpu.c:76-77`, `ff_kern_synch.c:59`+`:105`, `ff_glue.c:142`, `ff_kern_timeout.c:730` (U9); `ff_kern_timeout.c:183-185/:190/:254/:662/:1181/:1061/:1077/:730-733` retaining "non-`__thread` global written by every thread" key characterization (U11); `ff_dpdk_if.c:2649/:2745/:2841/:582-583`+`lib/Makefile:346,372-373` (U12); `ff_thread.c:20-30/33-46`+`lib/Makefile:36,90-91` (U13); `ff_ng_base.c:3249`+`ff_kern_timeout.c:1212-1216` (U14); `subr_pcpu.c:100/:276` (U15). U2 also downgraded and correctly references `keg_layout:2472-2478` |
| **F10** | §6 + §3 table | ✓ all implemented. (a) DoD-1 has probe position, 5 print fields, 3 criteria (including `pc_zpcpu_offset == 4096*dense_idx`, `c_seq` address diff `== 4096*Δidx`, within `[base, base+(mp_maxid+1)*4096)`), evidence path and probe exit method ✓; (b) DoD-3 has warning baseline (wording see R3) ✓; (c) DoD-5 has "must not be lower than pre-lock, ≥3 rounds median, ±2% noise" + handling when no improvement ✓; (d) M5 gate tightened to `reviewer` (removed leader aggregation) and added "if leader takes over testing, data review spawns new sub-agent", M7 gate explicitly `gate-doc`, leader self-review only pre-commit self-check ✓; (e) new DoD-8 temp artifact cleanup (`lib/_m17_probe_u1.c`, root `_m17_*` etc.), DoD-7 adds `M config.ini` pre-commit rollback ✓ |

### 7.3 New error check

Item-by-item comparison of all newly added/rewritten line numbers and qualitative statements, **no newly introduced factual errors**:
- All new line numbers (`uma_core.c:2114`, `lib/Makefile:650`, `ff_kern_timeout.c:662/:1181`, `ff_dpdk_if.c:582-583`, `counter.h:58-62`, `uma_int.h:54-57/59/65/67-74`) are consistent with first-round retained results.
- No "measured/verified" false claims: F1/F2's "statically established" is limited to **static** (preprocessing-level) conclusions, U2's runtime portion not mislabeled as established, wording does not overstep boundary.
- §0.3 candidate B's "set `mp_ncpus`/`mp_maxid` before UMA/SMR init" now forms evidence closure with §1.3 `:71` + U10, no conflict.
- Gate table changes do not break write/review heterogeneity: M0~M7 re-verified still **all heterogeneous, no self-write self-review**.

### 7.4 Remaining items (no bounce)

| # | Level | Content | Suggested wording |
|---|---|---|---|
| **R1** | Medium (recommend fill before M1 spawn) | **New U9~U15 not assigned to milestone owners**: §3 table M1 row still says "A code path exhaustive probing (U1/U2/U4/U5/U6/U7/U8 + `git show b90ddcba5`)", U9~U15 have no owner, M1 deliverables easily miss items (leader verbally assigned U3→`res-build`, U13/U15→`res-code` in messages, but plan text doesn't reflect) | M1-A change to "U1/U2/U4~U8 + U9~U15 (U3 to C)", and add in deliverables "`_m17_A_codepath.md` must backfill U1~U15 item by item, missing items fail gate" |
| **R2** | nit (within ±5 tolerance) | §1.3 `:67` still says `:3526 uma_zfree_pcpu_arg`, F8's suggested `:3521-3536` (`MPASS` at `:3527`) not implemented | Change to "`:3521-3536` `uma_zfree_pcpu_arg` isomorphic (`MPASS` at `:3527`)" |
| **R3** | nit | DoD-3 anchors warning baseline at "M1-C recorded clean build", but M1-C is **dual-candidate route compile evidence** (including `-DSMP` experiment), its warning count shouldn't be baseline | Change to "baseline = unchanged HEAD `ff09a17b2`'s `lib/`+`example/` clean build warning count (M1-C must separately record this baseline, separate from candidate route experiment warnings)" |
| **R4** | nit | §0.2 G2 description "replace all UMA `critical_enter/exit` with single global spinlock" alongside §1.4's precise scope is slightly easy to misread as whole tree | Add at sentence end "(actual scope only TUs including `vm/uma_int.h`, see §1.4 for details)" |

### 7.5 Re-review boundary

- This re-review **did not** re-run full file:line verification (per leader's instruction), first-round's 22 verified facts use first-round conclusions.
- The 3 unverified items in Section 6 (`mk/`'s `-DSMP` injection, `dpcpu_init` callers in other dirs, KNI/`ff_veth` thread ownership) have been transferred by leader to `res-build` (U3) and `res-code` (U13/U15), this agent will not follow up.
- Still **no runtime verification**; DoD-1/DoD-5 feasibility is static judgment (probe means and criteria are code-level implementable), actual data must be produced by `tester` at M5.

Re-review completion time: 2026-08-04 (bounce=1/3, no further bounce this round).

---

## 8. Candidate A Semantic Risk Independent Verification (M1-C post-review, providing basis for M2 verdict)

Verifier: `gate-plan` (independent verification, did not reference `res-build`'s reasoning, only compared conclusions with its report)
Method: actually opened `lib/ff_lock.c`, `lib/include/sys/mutex.h`, `freebsd/sys/mutex.h`, `lib/Makefile`, `lib/ff_glue.c`, `freebsd/contrib/ck/include/{ck_md.h,ck_pr.h,ck_queue.h,gcc/x86_64/ck_pr.h}`, `freebsd/net/if.c`, `freebsd/netpfil/ipfw/ip_fw_dynamic.c`, `freebsd/sys/{pcpu.h,smp.h,ck.h}`, `lib/ff_subr_epoch.c` for item-by-item verification.
`lib/include/sys/_mutex.h`: **does not exist** (`lib/include/sys/` only has `mutex.h`, confirmed by file search), so the verification request for this file automatically fails, does not affect conclusion.

### 8.1 Conclusion summary

| Risk | Conclusion |
|---|---|
| Risk 1 (`-DSMP` switches spin lock expansion) | **Invalid —— candidate A introduces no new spin lock semantic changes** (code-level established). But established an existing prerequisite fact: under f-stack **all** spin mutexes and `thread_lock` are already no-ops |
| Risk 2 (`CK_MD_UMP` invalid → restore `lock` prefix) | **Partially valid**: the only substantively affected TU is `ip_fw_dynamic.c` (RMW operations missing `lock` prefix). `-DSMP` is a "eliminate potential defect" correctness benefit, but **must not claim fixing a reproduced bug**; `CK_LIST`/`CK_SLIST`/`CK_STAILQ`/`net/if.c`/`ck_epoch` all **unaffected** |
| **New finding (more severe than above two)** | `ip_fw_dynamic.c`'s DPCPU + `CPU_FOREACH` **directly conflicts with G1**, has **heap overflow** path; must fix U14/U15 grading, and write "`mp_ncpus`/`mp_maxid`/`all_cpus` triple must be synchronized" as design constraint |
| **Process finding** | M1-C's probe changes (`-DSMP` + `smp_topo` stub) **currently still active in workspace**, affecting plan §1.2 fact timeliness, DoD-3 baseline caliber and write/review separation, must handle at M2 |

### 8.2 Risk 1: `-DSMP`'s spin lock expansion switch —— disproven (no new risk)

Verified facts:

1. `freebsd/sys/mutex.h`'s `#ifdef SMP` sites do exist as res-build described:
   - `:110-117`: `#ifdef SMP` only declares `_mtx_lock_spin_cookie()` prototype (no definition, no calls).
   - `:185-193`: `#ifdef SMP` → `#define _mtx_lock_spin(m,v,o,f,l) _mtx_lock_spin_cookie(&(m)->mtx_lock, v)`.
   - `:254-307`: `#ifdef SMP` → `__mtx_lock_spin` = `spinlock_enter()` + `_mtx_obtain_lock_fetch()` + failure to `_mtx_lock_spin()`; `#else` (:280) → `spinlock_enter()` + inline recursion count. Both branches contain `spinlock_enter()`.
2. **But f-stack's override header wipes these macros after `#include_next`**: `lib/include/sys/mutex.h:29` `#include_next <sys/mutex.h>` → `:31-34` `#undef __mtx_lock/__mtx_unlock/__mtx_lock_spin/__mtx_unlock_spin`, `:36-39` `#undef _mtx_lock_spin_flags/_mtx_unlock_spin_flags`, `:41-44` `#undef thread_lock*/thread_unlock`, `:46-48` `#undef mtx_trylock_flags_/_mtx_trylock_spin_flags/__mtx_trylock_spin`; then `:59-62` redefined as `DO_NOTHING` (`:57 ((void)0)`), `:69-72` `thread_lock*/thread_unlock` → `DO_NOTHING`, `:74-76` trylock family → constant `1`.
   → **Whether or not `SMP` is defined, `spinlock_enter()`/`_mtx_lock_spin_cookie()` have no call sites**; `:185`/`:254` branch differences are completely bypassed, `:110` is just an unreferenced prototype.
3. Cross-verification (link side): full repo `spinlock_enter|spinlock_exit` **definitions** only appear in **uncompiled** files like `freebsd/{arm,arm64}/*/machdep.c`; **no definitions in `lib/`** (only prototype in `.i` preprocessing output). All `.c` calling `spinlock_enter()` (`subr_smp.c`, `kern_mutex.c`, `kern_synch.c`, `kern_timeout.c`, `kern_time.c`, `kern_clocksource.c`, `sched_4bsd.c`, `sched_ule.c`, `kern_shutdown.c`, `x86/isa/atpic.c`, various `machdep.c`) are **all not in SRCS** in `lib/Makefile` (f-stack uses `ff_kern_synch.c` (:279)/`ff_kern_timeout.c` (:280) instead). If there were call sites, baseline build would have failed linking long ago.
4. `lib/ff_lock.c` full text (449 lines) read: **does not define** `spinlock_enter/exit`, nor `_mtx_lock_spin_cookie`; it provides `lock_class_*`, `ff_mtx_init`, `Giant`, and stubs `_rm_*`/`_sx_*` all as no-ops/constant returns (`:251-279`, `:325-360`). `lock_class_mtx_spin` (:402-408)'s `lc_lock/lc_unlock` are even `printf("...called!")` (`:386-397`, comment `XXX should never be used`).

Conclusion: **Risk 1 disproven. Candidate A is semantically neutral at spin lock level** (this also explains res-build's observed "zero new missing symbols (except `smp_topo`)").

Incidentally established two existing facts valuable to G1/U11 (recommended to write into spec, not introduced by candidate A):
- **All spin mutexes under f-stack are no-ops** → `lib/ff_kern_timeout.c:186-188`'s `CC_LOCK/CC_UNLOCK` (`mtx_lock_spin`) are effectively unlocked, callout's thread isolation **entirely depends on** `__thread struct callout_cpu cc_cpu` (:183), consistent with U11's judgment and stronger.
- `thread_lock/thread_unlock` also no-ops → any upstream assumption relying on `td_lock` serialization does not hold under f-stack.

### 8.3 Risk 2: `CK_MD_UMP` and `lock` prefix —— partially valid, only `ip_fw_dynamic.c` substantively affected

1. `CK_MD_UMP`'s **only** effect established: `freebsd/contrib/ck/include/gcc/x86_64/ck_pr.h:54-58` `#ifdef CK_MD_UMP → #define CK_PR_LOCK_PREFIX` (empty) / `#else → "lock "`. Affected are all **RMW** primitives: `cmpxchg16b` (:208/:501/:527), `ck_pr_faa_*` (:293), `ck_pr_inc/dec_*` (:327/:339), `ck_pr_add/sub/and/or/xor_*` (:381), `ck_pr_cas_*` (:419/:433/:448/:461), `ck_pr_bt*` (:587).
2. **`CK_MD_UMP` does not affect memory barriers**: generic `ck_pr.h` has **zero hits** for `CK_MD_UMP`; barriers determined by `:142-164`'s `#elif defined(CK_MD_TSO)` branch (mostly `CK_PR_FENCE_NOOP`), and `ck_md.h:113/:116` defines `CK_MD_TSO`. x86_64 side `CK_PR_FENCE(T,I)` (:71-76) only generates `ck_pr_fence_strict_##T`. → Unrelated to UMP.
3. Compiled CK users inventory (all measured):
   - `freebsd/contrib/ck/src/*.c` (`ck_epoch.c`/`ck_ht.c`/`ck_hs.c`/`ck_rhs.c`/`ck_array.c`/`ck_hp.c`/`ck_ec.c`/`ck_barrier_*.c`) **none compiled**: `lib/Makefile` only references `contrib/ck/include` header path at `:14`, no `ck_*.c` in SRCS.
   - `ck_epoch` already fully stubbed: `lib/ff_glue.c:1366-1404` implements `ck_epoch_synchronize_wait`/`ck_epoch_poll_deferred`/`_ck_epoch_addref`/`_ck_epoch_delref`/`ck_epoch_register`/`ck_epoch_init` as no-ops/always-true; `lib/ff_subr_epoch.c` (lib/Makefile:281) has **zero hits** for `ck_epoch|ck_pr_|ck_stack`; `ck_epoch.h` has **zero hits** for `ck_pr_`. → epoch path unrelated to UMP.
   - `ck_queue.h` (`freebsd/sys/ck.h:6-8` included under `_KERNEL`)'s 34 CK primitive uses are **all** `ck_pr_load_ptr`/`ck_pr_store_ptr`/`ck_pr_fence_store` (`:143-435`), **no RMW**. → `CK_LIST/CK_SLIST/CK_STAILQ` (heavily used in `in_pcb.c` etc, `lib/Makefile:501` compiled) **unaffected by UMP** on x86_64.
   - `freebsd/net/if.c` (`lib/Makefile:419` compiled) 5 CK uses (`:373,:404` `ck_pr_load_ptr`, `:592,:602,:678` `ck_pr_store_ptr`) **all load/store**. → Unaffected.
   - **`freebsd/netpfil/ipfw/ip_fw_dynamic.c` (`lib/Makefile:604` compiled, `FF_IPFW=1` see `:44`/`:115`) is the only substantively affected**, and uses RMW: `ck_pr_dec_32` (:155,:376), `ck_pr_inc_32` (:157,:290,:378), `ck_pr_xor_32` (:982), `ck_pr_or_32` (:984,:1001).
4. **Accurate** answer to "is this currently a bug" (avoiding overstepping):
   - In terms of machine semantics, **yes**: non-SMP build compiles these `inc/dec/or/xor` as **lock-prefix-less** RMW, multi-threaded concurrent same-address would lose updates/state bits.
   - But in terms of f-stack native-mt's **actual shared surface**: `V_dyn_*`, `DPARENT`, `dyn_data` are mostly **per-VNET** data, and CM5-B gives each worker its own `vnet_i`, so these counters/state bits are **mostly not cross-thread shared** under current design, may not reproduce.
   - So spec should state: **candidate A restoring `lock` prefix is a "eliminate potential atomicity defect" correctness benefit (zero cost, correct direction), but cannot claim fixing a reproduced bug**; also must record "if per-worker vnet isolation is abandoned in future or shared-vnet ipfw usage is introduced, this defect immediately becomes a real bug".

### 8.4 New finding (high value): ipfw's DPCPU + `CPU_FOREACH` directly conflicts with G1

This is more severe than 8.2/8.3, and **existing U1~U15 all do not cover it**:

1. **DPCPU is actually used by compiled TU**: `ip_fw_dynamic.c:224 DPCPU_DEFINE_STATIC(void *, dyn_hp)`, `:225 DYNSTATE_GET(cpu) = ck_pr_load_ptr(DPCPU_ID_PTR((cpu), dyn_hp))`, `:226 DYNSTATE_PROTECT(v) = ck_pr_store_ptr(DPCPU_PTR(dyn_hp), (v))`.
   → My first-round U15 judgment needs **split correction**: "`dpcpu_init()` has no callers" **still holds**; but "DPCPU path low-risk" **does not hold**, must upgrade U15 from "low" to "medium".
2. **Because `dpcpu_init()` is never called, all cpu's DPCPU slots alias each other**: `freebsd/sys/pcpu.h:113-114 _DPCPU_PTR(b,n) = (typeof)*((b) + (uintptr_t)&DPCPU_NAME(n))`, `:121 DPCPU_PTR(n) = _DPCPU_PTR(PCPU_GET(dynamic), n)`, `:128 DPCPU_ID_PTR(i,n) = _DPCPU_PTR(dpcpu_off[(i)], n)`. And `pc_dynamic` is zeroed by `pcpu_init()`'s `bzero` and never set, `dpcpu_off[]` always 0 → **all threads, all cpu ids point to same `&DPCPU_NAME(dyn_hp)` master copy**.
   → ipfw dynamic state's hazard-pointer mechanism **already failed** under multi-threading (all workers share one HP slot), and `-DSMP` **cannot fix** this. Combined with `:228 DYNSTATE_CRITICAL_ENTER() = critical_enter()` being a no-op in that TU (§1.4/F4 established), HP read side has no protection.
3. **G1's specific heap overflow path (must be written as design constraint in spec)**:
   - `ip_fw_dynamic.c:3236` `dyn_hp_cache = malloc(mp_ncpus * sizeof(void *), M_IPFW, M_WAITOK|M_ZERO)` —— size by **`mp_ncpus`** (f-stack always 1, `lib/ff_glue.c:140`, and **no one raises it by thread count**: I first-round verified its readers are only `ff_ng_base.c:3249`, `ff_kern_timeout.c:1212-1216`).
   - `:2086-2091` `cached_count = 0; CPU_FOREACH(i) { dyn_hp_cache[cached_count] = DYNSTATE_GET(i); if (... != NULL) cached_count++; }` —— loop upper bound by **`mp_maxid` + `all_cpus`** (`freebsd/sys/smp.h:197-199 CPU_FOREACH(i) = for (i=0;i<=mp_maxid;i++) if (!CPU_ABSENT(i))`, `:187 CPU_ABSENT(x) = !CPU_ISSET(x,&all_cpus)`).
   - → If G1 raises `mp_maxid` and `CPU_SET`s N workers into `all_cpus`, but **does not synchronously raise `mp_ncpus`**, the loop will consecutively write `dyn_hp_cache[0..N-1]` into a buffer with only **1** slot → **heap overflow**.
   - Trigger conditions (honest boundary, all three must hold): ① `all_cpus` has ≥ 2 cpus; ② at that moment shared `dyn_hp` slot is non-NULL (i.e. ipfw dynamic rules actually used, a reader has set HP); ③ `mp_ncpus` not synchronously raised. If ipfw dynamic rules not used, `DYNSTATE_GET` always NULL, `cached_count` always 0, only writes index 0, no trigger.
4. **Design constraint derived (recommend M2 spec list as D-constraint, and backfill U14)**: `mp_ncpus`, `mp_maxid`, `all_cpus` **must be set as a synchronized triple** (and per U10 all before `uma_startup1/2`); any plan changing only one or two introduces new out-of-bounds/missed-traversal. This is a **common** constraint for both candidate A and candidate B.

### 8.5 Wording corrections for `_m17_C_buildprobe.md` (2 places)

| Location | Original problem | Suggested fix |
|---|---|---|
| `_m17_C_buildprobe.md:169` | "its dependencies are pre-stubbed by f-stack (`spinlock_enter`/`_mtx_lock_spin_cookie` etc. covered by `lib/ff_lock.c`, `lib/include/sys/mutex.h`)" —— **attribution inaccurate**: `lib/ff_lock.c` full text does not define these two symbols, `lib/` has no `spinlock_enter` definition at all | Change to "its **call sites** are all eliminated by `lib/include/sys/mutex.h:31-76`'s `#undef` + redefine as `DO_NOTHING` after `#include_next`, and all `.c` calling `spinlock_enter()` are not in `lib/Makefile` SRCS, so neither branch generates references to these symbols" |
| `_m17_C_buildprobe.md:172` | "is a **runtime semantic change**, needs `res-code` verification" —— conclusion should update | Change to "per `gate-plan` independent verification **disproven**: because f-stack override header wiped all spin lock macros, `-DSMP` is **semantically neutral** at spin lock level (see `_m17_gate_plan.md` §8.2 for details)" |

### 8.6 Process finding: M1-C probe changes still active in workspace (must handle at M2)

Verified **current workspace** state (not HEAD):
- `lib/Makefile:221-222`: `# _M17_PROBE_A: temporary build probe, to be reverted` + `CFLAGS+= -DSMP` (**active**).
- `lib/ff_glue.c:162-169`: `/* _M17_PROBE_A: temporary build probe, to be reverted */` + `#ifdef SMP struct cpu_group *smp_topo(void) { return (NULL); } #endif` (**active**).

Impact and handling suggestions (3):
1. **Fact timeliness**: plan §1.2's "`lib/Makefile` does not define `-DSMP`" now only holds for HEAD `ff09a17b2`, not for workspace. M2 spec citing this fact must add "(HEAD `ff09a17b2`; M1-C probe period workspace temporarily added `-DSMP`)" qualifier, otherwise `gate-design`/`gate-doc` review will judge as factual error.
2. **DoD-3 baseline caliber**: 51 warning baseline must explicitly be "**HEAD clean build without probe patch**"; if that number was measured during `-DSMP` active period, must re-measure. Recommend plan add a measurement precondition in DoD-3.
3. **Write/review separation**: these two are `res-build` (research role) written into `lib/` code. If M2 verdicts candidate A, **must not** let probe code directly sediment as product code, must have M3 `coder` formally rewrite (whether `smp_topo` returning `NULL` is safe needs argumentation: `tcp_hpts.c:1868 cpu_top = smp_topo()` getting NULL then dereference risk must be verified) and pass `reviewer` gate; if verdicts candidate B, must revert these two before M2 ends (git-level revert/forward fix, not applicable to `rm_tmp_file.sh`).

### 8.7 Unverified boundary

- Whether `smp_topo()` returning `NULL` causes `freebsd/netinet/tcp_hpts.c:1868` and downstream to dereference that pointer: **unverified** (recommend listing as candidate A must-check, to `res-code` or M3 `coder`).
- Whether ipfw dynamic rules are actually enabled at runtime in this project (`config.ini`/runtime rule set): **unverified**, so 8.4's heap overflow is "if conditions hold then triggers" static conclusion, not reproduced defect.
- Whether `-DSMP` changes other **non** spin lock/CK runtime semantics (e.g. `cpuset_t` 8→128 causing pass-by-value/struct-embed ABI changes to already-compiled DPDK side): **unverified**, beyond this two-delegation scope, recommend listing as supplementary verification before M2 verdict.
- This section entirely **static verification, no runtime validation**.

Independent verification completion time: 2026-08-04.
