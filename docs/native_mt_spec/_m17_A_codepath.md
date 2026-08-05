# M17-A: Code-Path Exhaustive Probing (res-code Research Deliverable)

> This document is the M1-A deliverable of plan-17. All conclusions come from **actually executed** commands / actually opened files, annotated with `file:line` or command-output excerpts.
> Items not verified are clearly marked "not verified" + reason + suggested follow-up means, **with no speculative assertions**.
>
> Repo: `/data/workspace/f-stack`, `git log --oneline -1` = `ff09a17b2 Fix native-mt multi-thread multi-queue: give each worker its own prison ...` (measured output).
>
> **The author of this document modified no source code.** The temporary files created for the preprocessor evidence (`lib/_m17_probe_u1.c`, `_m17_probe_u1.i`, `_m17_uma_core.i`, `_m17_srcset.txt`, `_m17_allc.txt`, `_m17_srcpaths.txt`) were cleaned via `/data/workspace/rm_tmp_file.sh` after the research finished.

---

## 0. Evidence Baseline: the Real Compile Command Line

Using `make -n -B uma_core.o` (print-only, no `make` run) to capture the real compile command of a FreeBSD source file in `lib/`:

```
cc -c -O2 -fno-strict-aliasing -frename-registers -pipe -Wno-maybe-uninitialized \
  -std=c99 -Wall ... -fno-common -finline-limit=8000 --param inline-unit-growth=100 \
  --param large-function-growth=1000 -DFF_IPFW -DINET -Wno-error=stringop-overflow \
  -Wno-error=stringop-overread -Wno-error=array-bounds -Wno-error=format \
  -Wno-error=format-extra-args -Wno-error=cast-qual -DINET6 -DTCPHPTS -DRATELIMIT \
  -DFF_LOOPBACK_SUPPORT -DFSTACK -fstack-protector -D__FreeBSD__ -D_KERNEL \
  -DHAVE_KERNEL_OPTION_HEADERS -include opt_global.h -fno-builtin \
  -I/data/workspace/f-stack/lib/include -undef -imacros filtered_predefined_macros.h \
  -nostdinc -I. -I/data/workspace/f-stack/lib/../freebsd -I. \
  -I/data/workspace/f-stack/lib/../freebsd/contrib/ck/include -I./machine_include -I./opt \
  -Werror -Wno-unused-variable .../freebsd/vm/uma_core.c -o uma_core.o
```

Corresponds to `mk/kern.pre.mk:75` `NORMAL_C`. Key points (constraining the later solution):

- **No `-DSMP`**, **no `-DINVARIANTS`** (confirmed by U1 preprocessing measurement below).
- `-DFSTACK` present — this is the switch f-stack uses for conditional trimming inside FreeBSD source, **more critical than the `lib/include/` override headers** (see U1).
- `-nostdinc` + `-undef` + `-imacros filtered_predefined_macros.h`; `-I${lib}/include` comes before `-I${freebsd}` → override headers take effect via `#include_next`.
- `-DFF_IPFW -DINET -DINET6 -DTCPHPTS -DRATELIMIT -DFF_LOOPBACK_SUPPORT` all enabled; **`FF_KERNEL_COEXIST` not enabled** (`lib/Makefile:60` commented out).

> **⚠ Reproducibility note (important)**: all `cc -E` preprocessing in this document was run by **explicitly hand-writing the above parameter list** (not via `make`); the baseline is **the pristine HEAD `ff09a17b2` compile configuration**.
> During the writing of this document, another agent (`res-build`, responsible for M1-C compile feasibility) had added **temporary compile probes** to the worktree: `lib/Makefile:221-223 # _M17_PROBE_A ... CFLAGS+= -DSMP` and `lib/ff_glue.c:161-169 #ifdef SMP struct cpu_group *smp_topo(void) { return (NULL); } #endif` (measured `git diff --stat` = `lib/Makefile |3 +++`, `lib/ff_glue.c | 9 +++++++++`, both comments carrying "temporary build probe, to be reverted").
> Therefore **running `make -n` now would show an extra `-DSMP`**, inconsistent with the command line copied in Section 0 of this document. **All conclusions in this document (especially U1's `SMP = not_defined`) describe the pristine configuration** — which is exactly the "pre-change baseline" M2's verdict needs. `res-build`'s probe changes do not belong to this agent; this agent modified no source and does not clean up others' probe files.

---

## C-Correction (Important): `curcpu` Is Hardcoded to `0` in f-stack, and the UMA per-CPU Cache **Does Not Go Through `zpcpu_get()`**

> **This item was discovered by `designer`, re-checked by `leader`, and independently verified by this agent using `git show` + `grep`.**
> **It overturns one key inference in U7.3 and corrects one judgment in U9 #4 of this document. The original erroneous statements are kept below with per-item correction marks, so later readers do not misuse them.**

### C.1 The Fact (measured)

`lib/include/sys/pcpu.h` (f-stack's override header, **HEAD `ff09a17b2` version**, `git show HEAD:lib/include/sys/pcpu.h` measured):
```
31:#include_next <sys/pcpu.h>
32:#undef curcpu
34:#define curcpu    0          ← ★ hardcoded to the literal 0
```
It overrides upstream's `freebsd/sys/pcpu.h:218 #define curcpu PCPU_GET(cpuid)` (measured in the same file `:216-222`).

While **UMA's per-CPU cache is all located by `zone->uz_cpu[curcpu]`, 11 sites in total** (measured `grep -c 'uz_cpu\[curcpu\]' freebsd/vm/uma_core.c` = **11**):
```
freebsd/vm/uma_core.c:1452, 3738, 3776, 3818, 3901, 4534, 4543, 4595, 4628, 4803, 4853
        cache = &zone->uz_cpu[curcpu];
```
**They do not go through `zpcpu_get()` / `pc_zpcpu_offset` at all.**

### C.2 The Correct Causal Chain Derived from This (replacing U7.3's wrong inference)

f-stack's per-CPU location actually has **two mutually independent mechanisms**:

| Mechanism | Location method | Used by | Behavior at HEAD baseline |
|---|---|---|---|
| **A. `zpcpu_get()` family** | `base + pcpup->pc_zpcpu_offset`, `pc_zpcpu_offset = 4096*cpuid` (`subr_pcpu.c:96` + U1) | **SMR** (`smr_enter/exit` in `freebsd/sys/smr.h`, `subr_smr.c:439 zpcpu_get_cpu`), counter-zone allocation side | all workers' `pc_cpuid==0` → offsets all 0 → **share the same `c_seq` slot** (doc-16 §8.1's UAF window) |
| **B. `curcpu` family** | `zone->uz_cpu[curcpu]`, and `curcpu` **is the literal 0** | **all 11 fast/slow-path entries of the UMA per-CPU cache** | **no matter what `pc_cpuid` is, all threads always use `uz_cpu[0]`** |

**Therefore**:
1. **The real root cause of `b90ddcba5` introducing `uma_crit_lock` is mechanism B** — multi-thread sharing `uz_cpu[0]`, **unrelated** to `pc_zpcpu_offset`. This also explains why `ff09a17b2` still **must keep that global lock** after changing cpuid back to 0: changing cpuid has zero effect on mechanism B.
2. **Only giving `pcpu_init()` a dense cpuid (mechanism A) cannot isolate the UMA per-CPU cache.** **G1 must also change `curcpu` back to upstream semantics**, i.e. `lib/include/sys/pcpu.h:34` from `#define curcpu 0` to `#define curcpu PCPU_GET(cpuid)`.
   — Measured: `coder` has implemented this in the worktree (current `lib/include/sys/pcpu.h:34` = `#define curcpu    PCPU_GET(cpuid)`), **consistent with this section's conclusion**.
3. **G2's (removing `uma_crit_lock`) precondition must therefore be rewritten as "both mechanism A and mechanism B achieve per-thread exclusivity"** — neither can be missing. The "thread-context exhaustive" in U7 §7.2 and U13's conclusion (only the main thread + N-1 workers enter UMA, all having `pcpup`) **are unaffected and still hold**; only U7.3's inference that "dense slots suffice" is affected.

### C.3 Exhaustive Impact Scope of Changing `curcpu` from `0` to `PCPU_GET(cpuid)` (within the compile set of 254 files, measured `grep -n -H -w curcpu`)

| # | Location | Usage | Safe after change? |
|---|---|---|---|
| 1 | `freebsd/vm/uma_core.c` 11 sites | `&zone->uz_cpu[curcpu]` | **Safe and is the purpose of this change**. Precondition: `uz_cpu[]` allocated by `mp_maxid+1` (`uma_core.c:3180`), `zone_update_caches()` initialized per slot (`:2873-2875`) → i.e. **H1 must hold** (`mp_maxid` finalized before `uma_startup1`) |
| 2 | `lib/ff_kern_synch.c:105` | `_sleep(&pause_wchan[curcpu], ...)`, `:59 static uint8_t pause_wchan[MAXCPU];` | after the change the index becomes `0..N-1` → **must have `MAXCPU ≥ N`** (otherwise taking an out-of-array address; only taking the address, not dereferencing, so no crash, but the address would be confused with adjacent static variables). **This corrects U9 #4's basis**: at HEAD baseline `curcpu==0`, so this site **was not out-of-bounds**; the OOB risk is **introduced by** the `curcpu` change |
| 3 | `freebsd/netinet/tcp_timer.c:237` and `:249` | two fallback `return (curcpu);` in `inp_to_cpuid()` | after the change returns `0..N-1`, then passed as the `cpu` argument to `callout_reset_sbt_on()` (`tcp_timer.c:896,932`) → hits `lib/ff_kern_timeout.c:730 cpu >= MAXCPU` check → **must have `MAXCPU ≥ N`**. **This is a new trigger path for U11's conclusion** (U11 originally only listed the `% (mp_maxid+1)` path; these two `curcpu` fallbacks also produce non-0 values) |
| 4 | `freebsd/netinet/tcp_hpts.c:1587` | `rp_ent[(curcpu % tcp_pace.rp_num_hptss)]` | **Safe** (modulo). Consistent with U16 |
| 5 | `freebsd/netinet/tcp_hpts.c:1566` | `CPU_ISSET(curcpu, &tcp_pace.grps[i]->cg_mask)` | only reachable in the `grp_cnt > 1` branch, and `cpu_top == NULL → grp_cnt = 1` (`:1890`, U16 §16.5) → **unreachable** |
| 6 | `freebsd/netinet/tcp_lro.c:1210,1216` | `if (lc->lro_last_cpu == curcpu) ... lc->lro_last_cpu = curcpu;` | **Safe**. `lro_last_cpu` only flows to `t_lro_cpu` via `tcp_lro_hpts.c:576-577`, and that file **is not compiled** (U16 §16.4 measured `ls lib/tcp_lro_hpts.o` = No such file) → enters no array index |
| 7 | `freebsd/net/netisr.c:839` | `*cpuidp = netisr_get_cpuid(curcpu);`, and `netisr.c:277-279netisr_get_cpuid(u_int cpunumber) { return (nws_array[cpunumber % nws_count]); }` | **Safe** (modulo). Note: `nws_count` 0 would divide by zero, but that is unrelated to `curcpu` and is existing behavior (and `swi_add()` is an empty stub; the netisr path does not actually run, U7-b) |
| 8 | `freebsd/net/netisr.c:1172` | `if (cpuid != curcpu)` | comparison only, safe |
| — | `freebsd/netinet/tcp_timer.c:243`, `freebsd/netinet/tcp_hpts.c:1073` | comments | not applicable |

**C.3 summary**: after changing `curcpu` back to `PCPU_GET(cpuid)`, the newly added hard constraint is still only **`MAXCPU ≥ N`** (introduced by #2 and #3, merged with the existing U9/U11 conclusion into one); **no new array-OOB risk is introduced**; the other 6 sites are modulo or pure comparison.

### C.4 Specific Assertions in This Document Affected by This Correction (marked per item)

| Location | Original assertion | After correction |
|---|---|---|
| U7 §7.3 2nd bullet | "under dense indexing + 1:1 exclusive slot per thread, `curcpu = PCPU_GET(cpuid) = pcpup->pc_cpuid`... `&zone->uz_cpu[curcpu]` is therefore thread-private → **holds**" | **premise does not hold**: at HEAD baseline `curcpu` is the literal `0`. That conclusion only holds **after simultaneously** changing `lib/include/sys/pcpu.h:34` to `#define curcpu PCPU_GET(cpuid)`. A correction mark was added in place at §7.3 |
| U9 #4 (`pause_wchan[MAXCPU]`) | "`&pause_wchan[i]` (i≤N-1) goes out of the array…" | at HEAD baseline **no OOB** (`curcpu==0`); the OOB risk is introduced by the `curcpu` change. **The requirement `MAXCPU ≥ N` is unchanged**, but the attribution must change. Marked in place in the U9 table |
| U8 §8.4 point 2 | "`uma_crit_lock` currently has the side effect of greatly shrinking the slow-path concurrency window… this explains why `b90ddcba5` adding this lock "fixed" the SIGSEGV" | **reinforcement, not overturn**: what the lock truly protects is the **necessary** conflict of "all threads sharing `uz_cpu[0]`" (mechanism B), not a probabilistic slow-path race. Supplemented in place in §8.4 |
| U1 / U2 / U4 / U5 / U6 / U10 / U11 / U13 / U14 / U15 / U16 | — | **unaffected** (U1's conclusions on `zpcpu_offset_cpu`/`zpcpu_get` remain fully correct for **mechanism A (SMR)**) |

---

## U1 Final Expansion Value of `zpcpu_offset_cpu` and the Actual Numeric Value of `UMA_PCPU_ALLOC_SIZE`

> This section's conclusions apply to the "mechanism A (`zpcpu_get()` family, used by SMR)" of **C-Correction §C.2**, unaffected by the `curcpu` correction.

### Conclusion (all proven by `gcc -E` preprocessing, not speculation)

| Macro | Final expansion | Value |
|---|---|---|
| `MAXCPU` | `1` | **1** |
| `PAGE_SIZE` | `(1<<12)` | **4096** |
| `CACHE_LINE_SIZE` | `(1 << 6)` | 64 |
| `UMA_PCPU_ALLOC_SIZE` | `(1<<12)` | **4096 (== PAGE_SIZE, confirmed)** |
| `zpcpu_offset_cpu(cpu)` | `((1<<12) * cpu)` | **4096 * cpu** |
| `zpcpu_offset()` | `((pcpup->pc_zpcpu_offset))` | f-stack `__thread pcpup` version |
| `zpcpu_get(base)` | `({ __typeof(base) _ptr = (void *)((char *)(base) + ((pcpup->pc_zpcpu_offset))); _ptr; })` | — |
| `zpcpu_get_cpu(base,3)` | `({... (char *)(base) + ((1<<12) * 3) ... })` | base + 12288 |
| `PCPU_GET(cpuid)` | `(pcpup->pc_cpuid)` | f-stack override |
| `PCPU_SET(zpcpu_offset,7)` | `(pcpup->pc_zpcpu_offset = (7))` | f-stack override |
| `curthread` | `__curthread_ff()` | f-stack override |
| `CPU_SETSIZE` | `1` | **1** |
| `zpcpu_base_to_offset(base)` | `(base)` (identity) | `freebsd/sys/pcpu.h:242` default version effective |
| `SMP` | **not_defined** | — |
| `INVARIANTS` | **not_defined** | — |
| `UMA_MD_SMALL_ALLOC` | **not_defined** | `#undef`-ed by `lib/include/vm/uma_int.h:43` |

### Evidence

1. Preprocessor probe (temporary file `lib/_m17_probe_u1.c`, copied from Section 0's real parameters, only `-c` → `-E`) measured output:

```
PROBE_MAXCPU = 1;
PROBE_PAGE_SIZE = (1<<12);
PROBE_CACHE_LINE_SIZE = (1 << 6);
PROBE_UMA_PCPU_ALLOC_SIZE = (1<<12);
PROBE_ZPCPU_OFFSET_CPU_0 = ((1<<12) * 0);
PROBE_ZPCPU_OFFSET_CPU_1 = ((1<<12) * 1);
PROBE_ZPCPU_OFFSET_CPU_N = ((1<<12) * nnn);
PROBE_ZPCPU_OFFSET = ((pcpup->pc_zpcpu_offset));
PROBE_ZPCPU_GET = ({ __typeof(basep) _ptr = (void *)((char *)(basep) + ((pcpup->pc_zpcpu_offset))); _ptr; });
PROBE_ZPCPU_GET_CPU = ({ __typeof(basep) _ptr = (void *)((char *)(basep) + ((1<<12) * 3)); _ptr; });
PROBE_PCPU_GET_CPUID = (pcpup->pc_cpuid);
PROBE_PCPU_SET_ZOFF = (pcpup->pc_zpcpu_offset = (7));
PROBE_CURTHREAD = __curthread_ff();
PROBE_CPU_SETSIZE = 1;
PROBE_SMP_IS = not_defined;
PROBE_INVARIANTS_IS = not_defined;
PROBE_UMA_MD_SMALL_ALLOC_IS = not_defined;
PROBE_ZPCPU_BASE_TO_OFFSET_DEFINED = yes;
PROBE_ZPCPU_BASE_TO_OFFSET = (basep);
```

2. Definition chain (confirmed by opening the files):
   - `freebsd/sys/pcpu.h:221` `#define UMA_PCPU_ALLOC_SIZE PAGE_SIZE`
   - `freebsd/sys/pcpu.h:234-236` `#ifndef zpcpu_offset_cpu` / `#define zpcpu_offset_cpu(cpu) (UMA_PCPU_ALLOC_SIZE * cpu)` → **measured: this default definition is the one in effect**.
   - `freebsd/amd64/include/param.h`'s `PAGE_SIZE` = `(1<<PAGE_SHIFT)`, `PAGE_SHIFT=12` → 4096 (corroborated by preprocessing output `(1<<12)`).

### One Correction to a plan Assumption (important)

plan-17 §1.1 wrote "`lib/include/amd64/include/pcpu.h:28-46` `#undef zpcpu_offset_cpu` then not redefined; need to confirm the effective one is `freebsd/sys/pcpu.h:236`" — the conclusion **holds**, but the real reason is not that `#undef`:

- `freebsd/amd64/include/pcpu.h:269-273`:
  ```c
  #ifndef FSTACK
  #define zpcpu_offset_cpu(cpu)	((uintptr_t)&__pcpu[0] + UMA_PCPU_ALLOC_SIZE * cpu)
  #define zpcpu_base_to_offset(base) (void *)((uintptr_t)(base) - (uintptr_t)&__pcpu[0])
  #define zpcpu_offset_to_base(base) (void *)((uintptr_t)(base) + (uintptr_t)&__pcpu[0])
  #endif
  ```
  Because the compile command carries `-DFSTACK`, **these three macros are never defined in the amd64 machine header**. So the three `#undef`s in `lib/include/amd64/include/pcpu.h:40-42` (introduced by `b90ddcba5`, see U7) are **redundant** in the current configuration; the real gatekeeper is `#ifndef FSTACK`.

### Impact on the Solution

- `zpcpu_offset_cpu(cpu) = 4096*cpu`, `zpcpu_get(base) = base + pcpup->pc_zpcpu_offset`: as long as `pcpu_init(pcpup, i, ...)` passes dense `i`, `pc_zpcpu_offset` naturally becomes `4096*i` (`freebsd/kern/subr_pcpu.c:96`), **no macro change needed**. This is a key convenience condition for candidate B.
- **The per-CPU allocation granularity is hardcoded to 4096 bytes/CPU** (not `roundup(uz_size, cacheline)`). So an N-thread pcpu zone's each item must be at least `N*4096` bytes; consistent with `keg_layout`'s `pages *= mp_maxid + 1` (`uma_core.c:2474`).
- `MAXCPU == 1` is **unconditionally** given by `freebsd/amd64/include/param.h`'s `#else` (non-SMP) branch; `CPU_SETSIZE == 1`. See U4's ABI discussion.
- `INVARIANTS` undefined → `subr_pcpu.c:88`'s `KASSERT(cpuid < MAXCPU)`, `uma_core.c:2351` `keg_layout`'s PCPU KASSERT, `uma_core.c:1970/2183`'s `MPASS` **all compiled out**, so "out-of-bounds" is not stopped by assertions, only silently trampling memory (exactly how last round's SIGSEGV happened). **This means solution correctness cannot rely on assertions; it must be guaranteed by code structure.**

---

## U2 Which `pcpu_page_alloc` Is Actually Compiled + `page_alloc` Capability

### Conclusion

1. **The compiled one is `freebsd/vm/uma_core.c:2083-2089`'s fallback version** (`*pflag = UMA_SLAB_KERNEL; return page_alloc(...)`); the per-CPU `vm_page_alloc_noobj` version at `:1959` is **not compiled**.
   - The boundary is not `UMA_MD_SMALL_ALLOC`, but `freebsd/vm/uma_core.c:1957`'s **`#ifndef FSTACK`** (`:2082` is its `#else`).
2. **But this path is actually dead code today**: `keg_ctor()` at `freebsd/vm/uma_core.c:2546-2548` `#ifndef SMP` → `keg->uk_flags &= ~UMA_ZONE_PCPU;` strips the PCPU flag, so `:2577`'s `else if (keg->uk_flags & UMA_ZONE_PCPU) keg->uk_allocf = pcpu_page_alloc;` never matches; all kegs fall to `:2582` `page_alloc`.
3. f-stack's `page_alloc` foundation is **anonymous `mmap`**, which can stably allocate arbitrary `bytes` (including `(mp_maxid+1)*PAGE_SIZE`), returning **page-aligned, virtually-contiguous** regions — which exactly satisfies the contiguity assumption of `zpcpu_offset_cpu(cpu)=4096*cpu` (upstream `pcpu_page_alloc` also `pmap_qenter`s each CPU's physical page into **contiguous KVA**).

### Evidence

1. Preprocessing measurement (`cc -E` of the whole `uma_core.c`, output `_m17_uma_core.i`), `grep -n pcpu_page_alloc`:
   ```
   10578:static void *pcpu_page_alloc(uma_zone_t, vm_size_t, int, uint8_t *, int);
   11869:pcpu_page_alloc(uma_zone_t zone, vm_size_t bytes, int domain, uint8_t *pflag,
   12170:  keg->uk_allocf = pcpu_page_alloc;
   12238:  keg->uk_allocf = pcpu_page_alloc;
   ```
   `sed -n '11860,11880p'` measured function body:
   ```
   # 2083 "/data/workspace/f-stack/lib/../freebsd/vm/uma_core.c"
   static void *
   pcpu_page_alloc(uma_zone_t zone, vm_size_t bytes, int domain, uint8_t *pflag,
       int wait)
   {
    *pflag = 0x04;
    return page_alloc(zone, bytes, domain, pflag, wait);
   }
   ```
   The `# 2083` line marker directly confirms it is the `:2084` version.
2. Compiled-object symbols (`nm lib/uma_core.o`) measured:
   ```
                    U kmem_malloc_domainset
   0000000000000330 t page_alloc
   0000000000001210 t pcpu_page_alloc
   ```
   Both are local symbols; `pcpu_page_alloc` is small (right after `page_alloc`), consistent with the fallback version.
3. Allocation chain: `freebsd/vm/uma_core.c:1946-1955` `page_alloc()` → `kmem_malloc_domainset(DOMAINSET_FIXED(domain), bytes, wait)` (preprocessed to `kmem_malloc_domainset((&domainset_fixed[(domain)]), bytes, wait)`) → `lib/ff_glue.c:1250-1253`:
   ```c
   kmem_malloc_domainset(struct domainset *ds, vm_size_t size, int flags)
   { return (kmem_malloc(size, flags)); }
   ```
   → `lib/ff_glue.c:1025-1032`:
   ```c
   void * kmem_malloc(vm_size_t bytes, int flags)
   {
       void *alloc = ff_mmap(NULL, bytes, ff_PROT_READ|ff_PROT_WRITE,
                             ff_MAP_ANON|ff_MAP_PRIVATE, -1, 0);
       if ((flags & M_ZERO) && alloc != NULL) bzero(alloc, bytes);
       return (alloc);
   }
   ```
4. `keg_layout`'s layout for PCPU kegs (`freebsd/vm/uma_core.c:2472-2479`):
   ```c
   pages = atop(kl.slabsize);
   if ((keg->uk_flags & UMA_ZONE_PCPU) != 0)
           pages *= mp_maxid + 1;
   keg->uk_rsize = rsize; keg->uk_ipers = kl.ipers; keg->uk_ppera = pages;
   ```
   plus `:2406-2407` (PCPU kegs disallow inline slab headers), `:2466-2469` (PCPU kegs skip multipage iteration), `:2486-2492` (OFFPAGE picks `UMA_ZFLAG_HASH` or `UMA_ZFLAG_VTOSLAB` by `UMA_ZONE_NOTPAGE`).

### Impact / Risk on the Solution (incl. unverified items)

- **Candidate B, if keeping `UMA_ZONE_PCPU` (releasing `:2546`), makes the slab size `N*PAGE_SIZE`, going through `pcpu_page_alloc` → `page_alloc` → `mmap(N*4096)`. Functionally feasible** (mmap is naturally contiguous and page-aligned); **cost**: loses NUMA affinity (upstream allocates physical pages near each CPU); acceptable for this project's single-machine single-NUMA scenario.
- **⚠ Unverified item U2-a (must go to M1-C/M3 for compile+runtime validation)**: whether every page of a `uk_ppera > 1` slab is registered in f-stack's **`UMA_PAGE_HASH` reverse table** (`lib/include/vm/uma_int.h:65-126`: `vtoslab/vtozoneslab/vsetzoneslab`, hashed per page by `va >> PAGE_SHIFT & uma_page_mask`). `vtoslab()` uses `up_va == (va & ~(PAGE_SIZE-1))` to match **a single page** exactly, so a multi-page slab must call `vsetzoneslab` once per page. I could not fully pin down the correspondence between the `vsetzoneslab` call sites in `uma_core.c` and "per-page registration of multi-page slabs" by static reading (the `UMA_ZFLAG_VTOSLAB` path vs the `UMA_ZFLAG_HASH` path fork a lot). **Suggested means**: during M3, add temporary probes after `smr_create()`/`counter_u64_alloc()`, calling `vtoslab()` on each page of the `item` and asserting non-NULL; or directly load-test on `uma_zfree_pcpu` to see whether `vtozoneslab` gets a NULL `up` and crashes (`uma_int.h:101`'s `*slab = up->up_slab` would segfault on a NULL `up`).
- **⚠ Unverified item U2-b**: `uma_page_slab_hash`'s bucket count is determined by `lib/ff_freebsd_init.c:305` `kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO)`; I did not verify line-by-line the value of `num_hash_buckets` and the setting of `uma_page_mask` (must read `ff_freebsd_init.c` 290-320 in full). If pcpu zones explode the slab page count, hash chains get longer (performance), not a correctness issue.
- **`vsetzoneslab()` (`lib/include/vm/uma_int.h:105-126`) internally `malloc` + `LIST_INSERT_HEAD` with no lock**. This is an f-stack-owned global mutable structure; see U8's concurrency discussion.

---

## U7 (Part 1) The Motivation for `uma_crit_lock` — `git show b90ddcba5` Measured

### Conclusion

`uma_crit_lock` was introduced as a **stopgap serialization** to fix the **SIGSEGV of memset to address 0 in `kqueue_kevent` at 2-thread startup**; in the same commit, the worker's `pcpu_init` used `rte_lcore_id()` (**sparse and possibly ≥ MAXCPU=1**). That is: **this global lock and "the worker used an invalid/shared pcpu slot" are two sides of the same fix**; the lock itself was to mask the race caused by non-isolated per-CPU slots.

### Evidence (`git --no-pager show b90ddcba5` actual output excerpts)

commit message:
```
Fix UMA per-CPU cache race and sizeof mismatch for native-mt multi-thread startup

- Serialize UMA per-CPU cache access via spinlock in critical_enter/exit
  (uma_int.h + uma_crit_lock in ff_glue.c) to fix kqueue_kevent memset
  SIGSEGV at 0 on 2-thread startup.
- Fix malloc(sizeof(struct proc)) -> sizeof(struct thread) in ff_compat.c.
- Pass rte_lcore_id() as cpuid to ff_pcpu_thread_init/ff_stack_thread_init
  for per-thread pcpu init.
- Worker temporarily shares vnet0 (skips vnet_alloc) ...
- Reverted rmlock global lock attempt ...
```

Changed files (`--stat`): `lib/ff_compat.c` (2), `lib/ff_dpdk_if.c` (4), `lib/ff_freebsd_init.c` (18), `lib/ff_glue.c` (1), `lib/include/amd64/include/pcpu.h` (3), `lib/include/vm/uma_int.h` (10) + 1 doc.

Key diffs:
```diff
--- a/lib/include/vm/uma_int.h
-#define critical_enter() do {} while(0)
-#define critical_exit()  do {} while(0)
+extern volatile int uma_crit_lock;
+#define critical_enter() do { \
+    while (__sync_lock_test_and_set(&uma_crit_lock, 1)) \
+        ; \
+} while(0)
+#define critical_exit()  do { \
+    __sync_lock_release(&uma_crit_lock); \
+} while(0)
```
```diff
--- a/lib/ff_glue.c
 u_int mp_maxid;
+volatile int uma_crit_lock;
```
```diff
--- a/lib/ff_freebsd_init.c
-ff_pcpu_thread_init(void) {pcpu_init(pcpup, 0, sizeof(struct pcpu)); }
+ff_pcpu_thread_init(int cpuid) { pcpu_init(pcpup, cpuid, sizeof(struct pcpu)); }
...
-    ff_pcpu_thread_init();
+    ff_pcpu_thread_init(0);
     CPU_SET(0, &all_cpus);
```
```diff
--- a/lib/ff_dpdk_if.c
-    ff_stack_thread_init();
+    ff_stack_thread_init(rte_lcore_id());
```
```diff
--- a/lib/include/amd64/include/pcpu.h
 #undef PCPU_SET
+#undef zpcpu_offset_cpu
+#undef zpcpu_base_to_offset
+#undef zpcpu_offset_to_base
```

### Three Verifiable Facts (directly relevant to the G2 decision)

1. **Before `b90ddcba5`, `critical_enter/exit` were already no-ops** (`do {} while(0)`). That is, the f-stack single-thread era had no preemption-disabling semantics at all; the global lock is **newly added** serialization, not "restoring upstream semantics".
2. **The lock's granularity is "global serialization of the whole UMA fast path"**: `critical_enter/exit` are called from many places in `uma_core.c` (`cache_alloc*`/`cache_free*`/`uma_zalloc_smr`/`uma_zfree_smr` etc.), and the `uma_int.h` macros are **translation-unit-level replacement**; every `.c` including `vm/uma_int.h` is affected.
3. **`ff09a17b2` (current HEAD) changed cpuid back to 0** but **did not** revert this global lock. So the current combination is "shared slot + global lock": the lock protects UMA cache mutual exclusion, but **cannot** fix the SMR `c_seq` slot being overwritten across threads (`smr_enter/smr_exit` in `freebsd/sys/smr.h` go through `zpcpu_get(smr)`, whose reads/writes are not all within the `critical_enter/exit` macro coverage of UMA — see U7 Part 2).

---

## U4 Exhaustive Reader List of `mp_maxid`/`mp_ncpus`/`mp_maxcpus`/`all_cpus`

### Method (scoped to the actually-compiled source-file set)

`lib/Makefile`'s `SRCS` is a multi-segment make variable, hard to statically parse; so a **stronger evidence approach** was used: infer directly from the **existing `.o` files** in the `lib/` directory (real products of the last full build):

```
cd /data/workspace/f-stack/lib && ls *.o | wc -l     ->  248
```
Map the 248 `.o`s back to `.c`, then resolve **254 paths** within `lib/` + `freebsd/` (>248 because a few basenames exist in multiple directories, e.g. `in_cksum.c`; a **conservative over-approximation** — it can only over-report, never miss), forming `_m17_srcpaths.txt`; all subsequent greps are scoped to that list.

> Note: in `lib/Makefile`, `subr_counter.c` (line 357), `subr_pcpu.c` (363), `subr_smr.c` (367), `uma_core.c` (`VM_SRCS`, 650) **are all in `KERN_SRCS`/`VM_SRCS`** and their `.o`s exist, so counter(9)/pcpu/SMR/UMA all participate in compilation.

### 4.1 All Readers of `mp_maxid` (measured grep output, 24 sites)

| Location | Usage | Safe after `mp_maxid>0`? |
|---|---|---|
| `lib/ff_glue.c:145` | definition `u_int mp_maxid;` (BSS=0) | write point, needs change |
| `lib/ff_glue.c:151` | `SYSCTL_INT(_kern_smp, maxid, ...)` | safe (read-only export) |
| `freebsd/vm/uma_int.h:529` | **`#define ZDOM_GET(z,n) (&((uma_zone_domain_t)&(z)->uz_cpu[mp_maxid + 1])[n])`** | **⚠ most dangerous: see "hard constraint H1" below** |
| `freebsd/vm/uma_core.c:3180` | `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + sizeof(struct uma_zone_domain)*vm_ndomains` (`uma_startup1`) | safe **only if H1** |
| `freebsd/vm/uma_core.c:2873` | `zone_update_caches()`: `for (i=0;i<=mp_maxid;i++) cache_set_uz_size(&zone->uz_cpu[i],...)` | safe **only if H1** |
| `freebsd/vm/uma_core.c:562,583,674` | UMA stats / `uz_cpu` traversal | same |
| `freebsd/vm/uma_core.c:2474` | `keg_layout`: `pages *= mp_maxid + 1` (PCPU kegs only) | safe (paired with U2) |
| `freebsd/vm/uma_core.c:1970,2183` | `MPASS(bytes == (mp_maxid+1)*PAGE_SIZE)` | compiled out (`INVARIANTS` undefined), and 1970 is in the uncompiled `#ifndef FSTACK` section |
| `freebsd/vm/uma_core.c:1975` | uncompiled `#ifndef FSTACK` section | not applicable |
| `freebsd/vm/uma_core.c:3509` | `uma_zalloc_pcpu_arg`'s `#ifdef SMP` branch `for (i=0;i<=mp_maxid;i++) bzero(zpcpu_get_cpu(...))` | **not compiled** (`SMP` undefined) → currently only `bzero(item, uz_size)` one copy. **⚠ see "hard constraint H2"** |
| `freebsd/vm/uma_core.c:5589,5620,5637,5674,5684,5787` | `sysctl vm.zone*` stats (`malloc((mp_maxid+1)*...)`, `ush_maxcpus`) | safe (self-adapts by `mp_maxid`) |
| `freebsd/kern/subr_smr.c:598` | `smr_create()`: `for (i=0;i<=mp_maxid;i++){c=zpcpu_get_cpu(smr,i); c->c_seq=...;}` | **⚠ see "hard constraint H2"** |
| `freebsd/kern/uipc_socket.c:449,1636` | `so_splice`'s `mallocarray(mp_maxid+1,...)` and `wq_index % (mp_maxid+1)` | safe; and `splice_init()` is **lazy** (`uipc_socket.c:435-450`, only triggered on first `SO_SPLICE` use), not triggered in f-stack scenarios |
| `freebsd/net/netisr.c:1038-1039` | `KASSERT(cpuid <= mp_maxid)` | compiled out |
| `freebsd/netinet/tcp_timer.c:246-248` | `inp_to_cpuid()`: `cpuid = inp->inp_flowid % (mp_maxid+1); if (!CPU_ABSENT(cpuid)) return cpuid;` | **needs attention**: the return value ultimately goes to `callout_reset_*_on(..., cpu, ...)`. f-stack's `lib/ff_kern_timeout.c:184-185` `#define CC_CPU(cpu) &cc_cpu` / `CC_SELF() &cc_cpu` **ignores the cpu argument**, returning this thread's `__thread cc_cpu`, so behavior unchanged; but `lib/ff_kern_timeout.c:730` has `else if ((cpu >= MAXCPU) || ((CC_CPU(cpu))->cc_inited == 0)) panic("Invalid CPU in callout %d", cpu);` — **if `MAXCPU` stays 1 while `mp_maxid` is raised to N-1, `inp_to_cpuid()` returns 1..N-1, triggering the `cpu >= MAXCPU` panic**. ⚠ see "hard constraint H3" |

### 4.2 All Readers of `mp_ncpus` (measured, 16 sites)

| Location | Usage | After raising to N |
|---|---|---|
| `lib/ff_glue.c:140` | `int mp_ncpus = 1;` | write point |
| `lib/ff_kern_timeout.c:1212,1215,1216` | only as a divisor in `printf` | safe (any non-0) |
| `lib/ff_ng_base.c:3249` | `numthreads = mp_ncpus;` (netgraph worker count) | **needs evaluation**: makes netgraph start N workers; `FF_NETGRAPH=1` enabled |
| `freebsd/net/netisr.c:1308,1309,1312` | clamps `netisr_maxthreads` upper bound; **`netisr.c:169` `static int netisr_maxthreads = 1;` default 1** | safe (default unchanged, only the allowed upper bound grows) |
| `freebsd/netinet/tcp_hpts.c:473,1089,1864` | `cpuid = ... % mp_ncpus` picking an hpts slot | **needs evaluation**: `TCPHPTS` enabled (`-DTCPHPTS`). `tcp_hpts.c:1864 uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;` decides `rp_num_hptss`; raising it creates N hpts instances |
| `freebsd/netpfil/ipfw/ip_fw_dynamic.c:3236` | `malloc(mp_ncpus * sizeof(void*))` | safe (allocated by value) |
| `freebsd/vm/uma_core.c:5042` | `nb = bpcpu * mp_ncpus + bpdom * vm_ndomains;` (bucket prewarm count) | safe (only affects pre-allocation amount) |
| `freebsd/kern/subr_lock.c:149` | `lc->max = min(lock_roundup_2(mp_ncpus)*256, SHRT_MAX)` | safe |

> **Conclusion**: `mp_ncpus` and `mp_maxid` **can be decoupled** (this has been thoroughly established by **U16 §16.2~16.4 from the "does it overflow" angle**: decoupling does not make `tcp_pace.rp_ent[]` overflow, because `hpts_cpuid()` uses `% mp_ncpus` (`tcp_hpts.c:1089`) while `inp_to_cpuid()` uses `% (mp_maxid+1)` (`tcp_timer.c:246`), **two independent numberings**). If only per-CPU slot isolation is needed, **raising only `mp_maxid` (+`all_cpus`) while keeping `mp_ncpus` at 1** can avoid the knock-on effects of `ff_ng_base.c:3249` (measured no impact, see U14) and `tcp_hpts.c:1864`; **but it makes N workers share the same lock-free hpts queue**. The trade-off is in **U16 §16.6**, **which `designer` must explicitly rule on**.

### 4.3 `mp_maxcpus` / `all_cpus`

- `mp_maxcpus`: only `lib/ff_glue.c:142` (`= MAXCPU`) and `:154` (sysctl export). **No functional readers**, safe.
- `all_cpus`: only 3 sites — `lib/ff_glue.c:138` definition, `lib/ff_freebsd_init.c:88` extern, **`lib/ff_freebsd_init.c:294` `CPU_SET(0, &all_cpus);`**.
  - **⚠ hard constraint H4**: `CPU_FOREACH(i)` preprocesses (measured) to
    ```c
    for((i) = 0; (i) <= mp_maxid; (i)++) if (!(!(CPU_ISSET(i, &all_cpus))))
    ```
    i.e. **`mp_maxid` and the `all_cpus` bitmap must be set in pairs**. Raising only `mp_maxid` without `CPU_SET(i,&all_cpus)` makes every `CPU_FOREACH` silently skip 1..N-1 (stats undercounted, `cache_drain` misses reclamation, `smr_poll_scan` **misses other threads' `c_seq` → directly causes SMR to conclude the grace period ended early → UAF**, worse than the status quo).

### 4.4 ABI Consistency of `cpuset_t` / `CPU_SETSIZE`

- Preprocess measured `CPU_SETSIZE == 1` (= `MAXCPU`). `cpuset_t` = `struct { unsigned long __bits[howmany(CPU_SETSIZE, _NCPUBITS)]; }`, `howmany(1,64)=1` → **8 bytes**.
- **Raising `MAXCPU` from 1 to any `2..64` keeps `sizeof(cpuset_t)` at 8 bytes** (`howmany(64,64)=1`), ABI unchanged; **only 65 and above make it 16 bytes**. This round's thread count is far below 64.
- `cpuset_t` appears at cross-translation-unit interface points (measured grep; only 4 sites in the compile set): `lib/ff_glue.c:138` / `lib/ff_freebsd_init.c:88` (the same global), `freebsd/kern/subr_taskqueue.c:705,808` (`taskqueue_start_threads_cpuset()`/`_in_proc()`'s `cpuset_t *mask` parameter).
- **Conclusion**: as long as `MAXCPU≤ 64`, `cpuset_t` size is unchanged, **no cross-`.o` ABI risk**; but `struct pcpu`/`struct uma_zone` etc. **do** change runtime layout with `mp_maxid` (not compile-time), so the whole tree must be `make clean` re-built (also consistent with the existing mandatory convention). Additionally, `freebsd/kern/subr_pcpu.c:76-77`'s `uintptr_t dpcpu_off[MAXCPU]; struct pcpu *cpuid_to_pcpu[MAXCPU];` are **compile-time** `MAXCPU`-sized arrays → **`MAXCPU` must be ≥ thread count**, otherwise `pcpu_init()`'s `cpuid_to_pcpu[cpuid]=pcpu` (`subr_pcpu.c:91`) writes directly out of bounds (and `KASSERT` is compiled out, so no error). This is one of last round's SIGSEGV mechanisms.

### 4.5 counter(9): OOB / Under-Counting After Raising `mp_maxid`

**Conclusion: counter(9) has been completely "de-per-CPU-ized" in f-stack; raising `mp_maxid` brings no OOB risk, but introduces "allocation grows, access still uses only slot 0" waste plus an already-existing data race.**

Evidence (`lib/include/amd64/include/counter.h`, f-stack override):
```c
:38-39#define counter_enter() do {} while (0)     /* upstream is critical_enter() */
        #define counter_exit()  do {} while (0)
:43-47  static inline uint64_t counter_u64_fetch_inline(uint64_t *p) { return (*p); }
:49-53  static inline void counter_u64_zero_inline(counter_u64_t c) { *c = 0; }
:56#define counter_u64_add_protected(c, i)  counter_u64_add(c, i)
:58-62  static inline void counter_u64_add(counter_u64_t c, int64_t inc) { *c += inc; }
```
i.e. **`counter_u64_add/fetch/zero` do not go through `zpcpu_get()` at all; they only read/write the 0th slot pointed to by the base pointer** (compare the upstream implementation at `freebsd/i386/include/counter.h:101,123,157,169`, which uses `+ UMA_PCPU_ALLOC_SIZE * cpu`). `freebsd/kern/subr_counter.c:46-57`'s `counter_u64_zero/fetch` only delegate to these inlines, so **there is no `CPU_FOREACH` aggregation**.

- OOB risk: **none** (always touches only slot 0).
- Allocation side: `subr_counter.c:63` `counter_u64_alloc()` = `uma_zalloc_pcpu(pcpu_zone_8, flags|M_ZERO)`; `pcpu_zone_8` is created with `UMA_ZONE_PCPU` at `freebsd/kern/subr_pcpu.c:148-149`. If the PCPU stripping at `uma_core.c:2546` is released, every counter occupies `N*4096` bytes (**every** counter!) — f-stack has many counters (2 per zone + per-stack stats), **memory amplification needs evaluation**.
- Race: `*c += inc` is non-atomic, multiple threads sharing the same u64 → **already exists today** as lost stat counts (not a memory-safety issue). This round does not change that status quo.

### 4.6 Three Hard Constraints (Mandatory Requirements for the Solution)

- **H1 (`mp_maxid` must be finalized before the first zone is created and never change afterward)**: `ZDOM_GET` (`freebsd/vm/uma_int.h:529`) locates the zone-domain array with `uz_cpu[mp_maxid+1]`, while the zone's actual byte count is computed at `uma_startup1()` (`uma_core.c:3179-3181`) from the then-current `mp_maxid`. Measured call order: `lib/ff_freebsd_init.c:301 uma_startup1()` → `:302 uma_startup2()` (contains `uma_core.c:3233 smr_init()`) → `:309 mi_startup()` (runs `SYSINIT(pcpu_zones, SI_SUB_COUNTER,...)`, `SYSINIT(netisr_*)`, each `counter_u64_sysinit`, `in_pcbinfo_init`→`smr_create`). **So `mp_maxid`/`all_cpus` must be set before `ff_freebsd_init.c:301`** (see U6 for timing).
- **H2 (`mp_maxid` and `UMA_ZONE_PCPU` must be paired)**: `smr_create()` (`subr_smr.c:598-605`) unconditionally does `for (i=0;i<=mp_maxid;i++) zpcpu_get_cpu(smr,i)->c_seq=...`, **with no `#ifdef SMP`**. If only `mp_maxid` is raised while `keg_ctor` (`uma_core.c:2546-2548`) still strips `UMA_ZONE_PCPU`, then the "SMR CPU" zone's each item is only `sizeof(struct smr)` bytes and this loop **writes out of bounds over an `N*4096`-byte range** — more dangerous than the status quo. Similarly, `uma_zalloc_pcpu_arg`'s `M_ZERO` only `bzero`s one copy (`:3512`, because `SMP` undefined); if the zone becomes N slots, slots 1..N-1 are **not zeroed** (a recycled memory returned by `uma_zalloc` would have dirty `c_seq`) → the `#ifdef SMP` branch at `:3508` must also be released or changed to judge by `uz_flags & UMA_ZONE_PCPU`.
- **H3 (`MAXCPU` must be ≥ thread count, and the `ff_kern_timeout.c:730` `cpu >= MAXCPU` panic must be re-checked)**: `subr_pcpu.c:76-77`'s `dpcpu_off[MAXCPU]`/`cpuid_to_pcpu[MAXCPU]` are compile-time fixed-size; `tcp_timer.c:246` produces `1..mp_maxid` cpuid values fed to callout. **If the "raise `mp_maxid` but not `MAXCPU`" approach is used, these two sites crash immediately**.
- **H4 (the `all_cpus` bitmap must stay in sync with `mp_maxid`)**: see 4.3.

---

## U5 Write Protection and Runtime Readers of `cpuid_to_pcpu[]`/`cpuhead`/`dpcpu_off[]` After Dense Indexing

### 5.1 Write Points and Existing Protection

`pcpu_init()` (`freebsd/kern/subr_pcpu.c:83-97`) writes three globals:
```c
:90  pcpu->pc_cpuid = cpuid;
:91  cpuid_to_pcpu[cpuid] = pcpu;             /* after dense indexing each thread writes a different subscript */
:92  STAILQ_INSERT_TAIL(&cpuhead, pcpu, pc_allcpu);   /* shared list head/tail pointer */
:96  pcpu->pc_zpcpu_offset = zpcpu_offset_cpu(cpuid);
```
Existing protection: `lib/ff_freebsd_init.c:175` `static volatile int init_lock = 0;` + `:185-186` `while (__sync_lock_test_and_set(&init_lock,1));` … `:216 __sync_lock_release(&init_lock);`, serializing everything from `ff_pcpu_thread_init` through `lo_set_defaultaddr()` (comment at `:181-184`).

**Conclusion: `init_lock` must still be kept.** Reasons (code-level):
- `cpuid_to_pcpu[cpuid]=pcpu` writes **different** subscripts per thread after dense indexing; that single line alone no longer needs a lock;
- but **`STAILQ_INSERT_TAIL(&cpuhead, ...)` (`:92`) operates the shared `cpuhead.stqh_last` — a classic concurrent linked-list insertion, must be serialized**;
- and `init_lock` covers far more than `pcpu_init`: `ff_init_thread0()`, `ff_adapt_user_thread_add()` (GIANT_REQUIRED; global ops like `uifind(0)`/`crget`/`EVENTHANDLER_INVOKE`, recorded as R1~R5 in AI memory 84914768), `vnet_alloc()` (runs VNET_SYSINIT), `lo_set_defaultaddr()` (`socreate`+`ifioctl`). **These are unrelated to this round's U5 but equally depend on the lock**.
- Therefore the recommendation: **do not shrink the `init_lock` scope** (don't touch it this round); G1/G2's gains come from the data plane, not the startup path.

### 5.2 Exhaustive Runtime Readers of `pcpu_find()` / `cpuhead` / `dpcpu_off[]` (within the compile set)

| Reader | Location | Really compiled/runs? | Data plane? |
|---|---|---|---|
| `pcpu_find()` | `freebsd/vm/uma_core.c:1982` | **not compiled** (inside the `#ifndef FSTACK` `pcpu_page_alloc`, and further wrapped in an `#else NUMA` branch) | — |
| `pcpu_find()` | `freebsd/netinet/tcp_hpts.c:2032` | **not compiled** (measured: the line sits inside an `#ifndef FSTACK` section, see `tcp_hpts.c:2025 #ifndef FSTACK`) | — |
| `pcpu_find()` | `freebsd/kern/subr_pcpu.c:105` (`dpcpu_init`) | function compiled but **no callers** (grepping `dpcpu_init` over the 254-file list only hits the definition itself) | no |
| `pcpu_find()` | `freebsd/kern/subr_pcpu.c:402,417` | inside `#ifdef DDB` (`:340`/`:393` sections); `lib/opt/opt_ddb.h` **is an empty file** → `DDB` undefined → not compiled | — |
| `STAILQ_FOREACH(&cpuhead)` | `freebsd/net/netisr.c:1334` | inside `#ifdef EARLY_AP_STARTUP` (`:1333`); `EARLY_AP_STARTUP` undefined (not in compile command, not in `lib/opt/opt_global.h`) → **not compiled**; actually goes `:1341pc = get_pcpu();` | — |
| `STAILQ_FOREACH(&cpuhead)` | `freebsd/net/netisr.c:1356` (`netisr_start`) | compiled; `SYSINIT(netisr_start, SI_SUB_SMP, SI_ORDER_MIDDLE)` (`:1365`) → runs inside `mi_startup()`, **before workers create their pcpu**; at that point `cpuhead` has only the main thread's entry; and `netisr_maxthreads` defaults 1 (`netisr.c:169`) → starts only 1 | no (startup period) |
| `dpcpu_off[]` read | `subr_pcpu.c:257` (`dpcpu_copy`'s `#ifdef SMP` branch) | **not compiled**; goes `:263 memcpy((void *)(dpcpu_off[0] + ...))` | no |
| `dpcpu_off[]` read | `subr_pcpu.c:298,315,332` (`sysctl_dpcpu_*`) | compiled, sysctl only | no |
| `pcpu_destroy()` write | `subr_pcpu.c:269-277` | compiled, **no callers** (f-stack threads never exit) | no |

**Conclusion**: **`pcpu_find()` and `cpuhead` have no data-plane (packet/connection-processing) readers in f-stack's current configuration**; the startup-period reader (`netisr_start`) finishes before workers create their pcpu. So dense indexing will not let any runtime reader see a "half-initialized" `cpuid_to_pcpu[]`. **The only synchronization that must remain is the `cpuhead` insertion (covered by `init_lock`).**

⚠ **Unverified item U5-a**: `netisr_start` at SYSINIT time only sees the main thread's pcpu — this is a **static timing inference** (`mi_startup()` at `ff_freebsd_init.c:309`; workers' `ff_stack_thread_init` comes after `ff_dpdk_run`→`main_loop`). **Suggested**: print `nws_count` and the `cpuhead` length at M5 runtime to confirm.

---

## U6 Dense-Index Source and Call Timing

### 6.1 The Ready-Made Dense Index: `lcore_conf[].proc_id` (already exists, no new field needed)

Measured code chain:

1. `lib/ff_config.c:116-118` (`parse_lcore_mask`):
   ```c
   for (j = 0; j < BITS_PER_HEX && idx < RTE_MAX_LCORE; j++, idx++) {
       if ((1 << j) & val) {
           proc_lcore[count] = idx;      /* count is the dense subscript, idx is the sparse lcore id */
   ```
   `:139 cfg->dpdk.nb_procs = count;` → **`proc_lcore[0..count-1]` is the "dense index → lcore id" mapping table**.
2. `lib/ff_config.c:1465-1484` (thread_mode collapse):
   ```c
   if (cfg->dpdk.thread_mode) {
       ... proc_type = "primary";
       cfg->dpdk.nb_threads = cfg->dpdk.nb_procs;   /* thread count = lcore_mask bit count */
       cfg->dpdk.nb_procs = 1;
       cfg->dpdk.proc_id = 0;
       proc_mask = strdup(lcore_mask);              /* expose all bits to EAL */
   }
   ```
3. `lib/ff_dpdk_if.c:427-455` (`init_lcore_conf`, thread_mode branch):
   ```c
   for (ti = 0; ti < ff_global_cfg.dpdk.nb_threads; ti++) {
       uint16_t lcore_id = ff_global_cfg.dpdk.proc_lcore[ti];
       struct lcore_conf *lc = &lcore_conf[lcore_id];
       lc->proc_id = ti;                /* ★ the dense index 0..N-1 already lands in lcore_conf */
   ```
4. `lib/ff_memory.h:104-111`:
   ```c
   static inline unsigned ff_lcore_conf_idx(void)
   { return ff_global_cfg.dpdk.thread_mode ? rte_lcore_id() : 0; }
   #define ff_cur_lcore_conf() (&lcore_conf[ff_lcore_conf_idx()])
   ```

**Conclusion U6-1**: a worker in `main_loop` can directly use **`ff_cur_lcore_conf()->proc_id`** to get the dense index `0..N-1`; **no new variable needed**, **do not use `rte_lcore_id()`** (sparse). `lib/ff_dpdk_if.c:2649` currently passes `rte_lcore_id()`; it should pass `ff_cur_lcore_conf()->proc_id` (or `qconf->proc_id`, `qconf` already fetched at `:2644`).

### 6.2 Slot Mapping of the Main Thread and Workers (Collision Analysis)

Measured facts:
- `lib/ff_dpdk_if.c:2857` `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);` → **the EAL main lcore also executes `main_loop`**, i.e. thread_mode=1's N threads = 1 main-lcore thread + (N-1) EAL worker threads.
- The main thread, during `ff_init()` (`lib/ff_init.c:39-53`: `ff_load_config` → `ff_dpdk_init` → `ff_freebsd_init` → `ff_dpdk_if_up`), already ran `ff_pcpu_thread_init(0)` at `lib/ff_freebsd_init.c:293` and set `ff_stack_inited = 1` at `:348`; so after entering `main_loop`, `ff_stack_thread_init()` returns directly at `:177-178`, **not rebuilding pcpu**.
- The main thread's `proc_id`: the EAL main lcore is the first enabled lcore in the coremask (under thread_mode `proc_mask == lcore_mask`), i.e. `proc_lcore[0]` → `lcore_conf[proc_lcore[0]].proc_id == 0`.

**Suggested mapping (no collision)**:

| Thread | pcpu cpuid (=`zpcpu` slot) | Obtained by |
|---|---|---|
| main thread (= EAL main lcore = `proc_lcore[0]`) | **0** | keep `ff_freebsd_init.c:293`'s `ff_pcpu_thread_init(0)` unchanged |
| worker `i` (`proc_lcore[i]`, i=1..N-1) | **i** | `ff_stack_thread_init(ff_cur_lcore_conf()->proc_id)`, and `ff_pcpu_thread_init()` actually uses the parameter |

- Slot count: `mp_maxid = nb_threads - 1`, `mp_ncpus` (whether to raise in sync see the freedom discussion in 4.2), `CPU_SET(i,&all_cpus) for i in 0..nb_threads-1`, `MAXCPU ≥ nb_threads`.
- thread_mode=0 (multi-process): `nb_threads == 0`, keep `mp_maxid=0`, `MAXCPU` behavior unchanged → **zero regression**.

⚠ **Unverified item U6-a**: "the EAL main lcore always equals `proc_lcore[0]`" is inferred from DPDK's default "main lcore = lowest coremask bit", **not runtime-verified**, and breaks if `--main-lcore` is passed in the future. **Suggested**: do not rely on this inference; in `ff_freebsd_init()` also use `ff_cur_lcore_conf()->proc_id` to get the main thread's number (under thread_mode=1), or print the `rte_get_main_lcore()`/`rte_lcore_id()`/`proc_id`/`pc_zpcpu_offset` tuple at M5 (DoD-1 already requires). If the main thread's `proc_id != 0`, the table above still holds (the main thread takes its own `proc_id`, still no collision); only `ff_freebsd_init.c:293`'s hardcoded 0 needs changing.

### 6.3 Actual Call Timing of `ff_pcpu_thread_init` Relative to `uma_startup`/`smr_init`/`ff_freebsd_init` (measured)

```
app main()
└─ ff_init()                                   lib/ff_init.c:36
   ├─ ff_load_config()                          :39   ← nb_threads / proc_lcore[] determined here
   ├─ ff_dpdk_init()                :43   ← EAL init + init_lcore_conf(lc->proc_id=ti)
   │     + init_mem_pool + init_msg_ring
   ├─ ff_freebsd_init()                         :47
   │  ├─ ff_pcpu_thread_init(0)                 ff_freebsd_init.c:293   ← main-thread pcpu
   │  ├─ CPU_SET(0, &all_cpus)                  :294
   │  ├─ ff_init_thread0()                      :296
   │  ├─ uma_startup1(bootmem)                  :301   ★ computes zsize by mp_maxid (uma_core.c:3179-3181)
   │  ├─ uma_startup2()                         :302   ★ contains smr_init() (uma_core.c:3233)
   │  ├─ uma_page_slab_hash table built         :304-306
   │  ├─ mutex_init(); mi_startup()             :308-309 ★ runs all SYSINITs:
   │  │        SYSINIT(pcpu_zones, SI_SUB_COUNTER)  subr_pcpu.c:157  → pcpu_zone_4..64
   │  │        each counter_u64_sysinit / COUNTER_U64_DEFINE_EARLY
   │  │        SYSINIT(netisr_init, SI_SUB_SOFTINTR) / SYSINIT(netisr_start, SI_SUB_SMP)
   │  │        in_pcbinfo_init → uma_zcreate(UMA_ZONE_SMR) → smr_create()  (in_pcb.c:583,615-617)
   │  ├─ curthread->td_vnet = vnet0              :317
   │  ├─ lo_set_defaultaddr()                    :342
   │  └─ ff_stack_inited = 1                     :348
   └─ ff_dpdk_if_up()                           :51
app ff_run(loop, arg)
└─ ff_dpdk_run()   lib/ff_dpdk_if.c:2851
   └─ rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)   :2857
      └─ main_loop (one thread per lcore, incl. the main lcore)
         └─ ff_stack_thread_init(rte_lcore_id())            :2649
            └─ init_lock critical section ff_freebsd_init.c:185-216
               └─ ff_pcpu_thread_init(cpuid)  :187   ← worker pcpu (currently always 0)
```

**Conclusion U6-2 (key timing constraint)**: the `mp_maxid` / `all_cpus` / `MAXCPU`-related settings **must be done before `ff_freebsd_init.c:301 uma_startup1()`** (at the latest, at the start of the `ff_freebsd_init()` function body, around `:291-294`), because:
- `uma_startup1` uses `mp_maxid` to fix the byte size of **all zones** (H1);
- `uma_startup2` → `smr_init()` creates the "SMR CPU" zone;
- `smr_create()` in `mi_startup()` (`ipi_smr`) already writes N slots by `mp_maxid` (H2).

While `nb_threads` is already known at `ff_load_config()` (earlier), and `ff_dpdk_init()` is also earlier than `ff_freebsd_init()`, **information availability is not a problem**.

---

## U7 (Part 2) Premise Argument for Removing `uma_crit_lock`

### 7.1 The Actual Semantics of `critical_enter/exit` in f-stack (preprocessing measured)

```
PROBE_CRITICAL_ENTER = do { while (__sync_lock_test_and_set(&uma_crit_lock, 1)) ; } while(0);
PROBE_CRITICAL_EXIT  = do { __sync_lock_release(&uma_crit_lock); } while(0);
```
Note this is **the `lib/include/vm/uma_int.h:46-52` macro**, whose scope is "any translation unit `#include`-ing `<vm/uma_int.h>`". Among the 254 compiled files it is mainly `freebsd/vm/uma_core.c`.

**U7-a verified (this round's additional measurement)**: `cc -E` of `freebsd/kern/subr_smr.c` alone (same Section 0 parameters) then
```
grep -c 'uma_crit_lock' _m17_smr.i    ->   0
```
i.e. **`critical_enter/exit` in `subr_smr.c` have nothing to do with `uma_crit_lock`** (it does not include `vm/uma_int.h`). What it gets is `freebsd/sys/systm.h:~200-210`'s definitions, preprocessed (measured) to **empty function bodies**:
```c
static __inline void critical_enter(void) { }     /* function body hollowed out by f-stack */
static __inline void critical_exit(void)  { }     /* #210 "freebsd/sys/systm.h" */
```
**Two key corollaries**:
1. **SMR's read sections (`smr_enter`/`smr_exit`/`smr_poll`) today have zero serialization protection.** Combined with "all workers' `pc_zpcpu_offset` are 0 → share the same `c_seq` slot", **the UAF theoretical window recorded in doc-16 §8.1 genuinely exists at the code level** (not caught by `uma_crit_lock`). This directly supports G1's necessity.
2. **Removing `uma_crit_lock` will not weaken any existing SMR protection** (it never protected SMR).
3. Incidentally: `freebsd/kern/subr_counter.c`'s `counter_enter/exit` are also emptied by f-stack (`lib/include/amd64/include/counter.h:38-39`), same reasoning.

### 7.2 Exhaustive Execution Contexts That Enter the UMA Alloc/Free Fast Path

| Context | Exists? (measured basis) | Calls `ff_pcpu_thread_init` → has independent pcpu slot? |
|---|---|---|
| **main thread** (= EAL main lcore, also runs `main_loop`) | yes | yes, `ff_freebsd_init.c:293` (cpuid 0) |
| **worker threads**×(N-1) | yes, `rte_eal_mp_remote_launch(..., CALL_MAIN)` (`ff_dpdk_if.c:2857`) | yes, `ff_dpdk_if.c:2649` → `ff_freebsd_init.c:187` |
| **KNI thread** | **no independent thread**. `lib/ff_dpdk_kni.c:93-96` `ff_kni_is_owner_thread()` = `rte_lcore_id() == proc_lcore[0]`; KNI send/receive executes sequentially inside `main_loop` by the owner thread | reuses the owner thread's pcpu |
| **callout / timer thread** | **no independent thread**. `lib/ff_kern_timeout.c:183-185` `__thread struct callout_cpu cc_cpu; #define CC_CPU(cpu) &cc_cpu`, each thread's own callwheel; `ff_hardclock()`/`ff_tcp_hpts_softclock()` called periodically by `main_loop` | reuses the owning thread's pcpu |
| **`ff_veth` send/receive** | inside `main_loop` context (`ff_veth.c`'s `ff_veth_input`/`if_transmit` called directly by workers) | reuses the worker pcpu |
| **control-plane `ff_msg`/IPC** | handled inside `main_loop` (`init_msg_ring` builds the rings; messages consumed in the loop) | reuses the worker pcpu |
| **netisr swi thread** | **does not exist**. `lib/ff_kern_intr.c:84-89swi_add(){ return 0; }`, `:91-95 swi_sched(){ }`, `:97-101 swi_remove(){ return 0; }`, `:103-107 intr_event_bind(){ return EOPNOTSUPP; }` — **all empty stubs, neither creating threads nor scheduling**. So `netisr_start_swi` is ineffectual; the netisr softirq path does not actually run (U7-b verified) | not applicable |
| **`taskqueue` / netgraph / kproc threads** | **do not exist**. `lib/ff_compat.c:162-169 kproc_kthread_add(...){ return 0; }`, `:171-177 kthread_add(...){ return 0; }` — **empty stubs, create no OS threads** (U7-c verified). Therefore `lib/ff_ng_base.c:3253 kproc_kthread_add(ngthread,...)` (even with `mp_ncpus` raised to N), `freebsd/kern/subr_taskqueue.c`'s `taskqueue_start_threads*`, and `so_splice`'s `splice_work_thread` **will not actually start threads** | not applicable |
| **`so_splice` kthread** | same; and `splice_init()` is a lazy init on first `SO_SPLICE` use (`uipc_socket.c:435-441`); f-stack has no `SO_SPLICE` users | not triggered |
| **app-created threads (`ff_pthread_create`)** | API exists: `lib/ff_thread.c:32-45`; `ff_start_routine` only does `ff_set_thread(p_data->parent)` (`ff_thread.c:16,26`), **does not call `ff_pcpu_thread_init`** | **⚠ high risk: such threads have `__thread pcpup == NULL`**. Any `PCPU_GET(...)` dereferences NULL. Unrelated to this round's G2 (crashes today), but **must be clearly written in the spec as "unsupported usage"**, otherwise the "each thread exclusively owns a pcpu slot" premise fails at the API level |
| **DPDK's own rte threads** (intr thread, telemetry, eal-intr-thread) | DPDK internal threads exist, but **do not enter the f-stack protocol stack** (do not call `ff_*`/UMA) | not applicable |

### 7.3 Is "Each Thread Exclusively Owns a pcpu Slot" Equivalent to Upstream's Preemption-Disabling Semantics

- Upstream `critical_enter()`'s role: on the same CPU, disable preemption → guarantee that `zone->uz_cpu[curcpu]`'s slot has **no second execution flow** accessing it concurrently inside the critical section.
- Userspace equivalent condition: **"the same pcpu slot is accessed by only one thread at any moment"**.
  - Under "dense indexing + 1:1 exclusive slot per thread", `curcpu = PCPU_GET(cpuid) = pcpup->pc_cpuid` is a **thread-private constant** (`pcpup` is `__thread`, `ff_freebsd_init.c:85`), so `&zone->uz_cpu[curcpu]` is thread-private → **holds**, and **does not depend on whether the thread is core-pinned or migrated by the OS** (this is stronger than upstream's "same CPU" condition, because slots are allocated by thread rather than by physical CPU).
    > 🔴 **【C-Correction】this bullet's premise does not hold at the HEAD `ff09a17b2` baseline.** Measured `git show HEAD:lib/include/sys/pcpu.h`'s `:32 #undef curcpu` / `:34 #define curcpu 0` — **`curcpu` is the literal `0`, not `PCPU_GET(cpuid)`**. So dense `pc_cpuid` **does not** make `zone->uz_cpu[curcpu]` thread-private; all threads always use `uz_cpu[0]`.
    > This bullet's conclusion **only holds after simultaneously changing `lib/include/sys/pcpu.h:34` to `#define curcpu PCPU_GET(cpuid)`** (`coder` already implemented it in the worktree). The complete causal chain and impact scope are in **C-Correction §C.2/§C.3**. Discovered by `designer`, re-checked by `leader`, independently verified by this agent.
  - Other readers of `uz_cpu[]`: `cache_drain()` (`uma_core.c:1408-1423`, on zone teardown), `zone_update_caches()` (`:2873`, on zone creation/flag update), sysctl stats (`:5096,5112,5127,5526,5593`, `atomic_load_64`). The first two are at startup/teardown; the last is stats (tolerable inconsistency).
  - **Non-equivalent cases**: as long as a path exists where "two threads share the same pcpu slot". Two **classes** measured:
    1. **app threads created by `ff_pthread_create`** (end of the 7.2 table): `pcpup == NULL`, worse than "sharing a slot" (already a bug today).
    2. **⚠ Unverified U7-b/U7-c's netisr swi / taskqueue kthreads**: if they were real OS threads without calling `ff_pcpu_thread_init`, they would likewise have `pcpup == NULL`.

- **There is also a hazard independent of pcpu slots (directly relevant to G2)**: the `critical_enter/exit` global lock **incidentally** serializes part of the UMA fast path's access to zone-level shared structures. After removing it, only the "per-CPU cache hit" path is truly lock-free-safe; **the zone/keg slow path after a fast-path miss was already executed after `critical_exit()`** (e.g. `uma_core.c:3880-3891`: `cache_fetch_bucket` / `zone_alloc_bucket` are outside the critical section, `:3891` re-enters `critical_enter()`), **so the slow path is not protected by this lock today** — see U8.

**Conclusion U7**: the **necessary-and-sufficient premise** for removing `uma_crit_lock` is:
1. every thread entering UMA has an **independent and valid** pcpu slot (→ G1 must land first, with `MAXCPU`/`mp_maxid`/`all_cpus` consistent, H1~H4);
2. no thread that skipped `ff_pcpu_thread_init` enters UMA (**must resolve U7-b/U7-c, and explicitly document in the spec that `ff_pthread_create` threads must not call f-stack APIs or must be given pcpu initialization**);
3. the slow path's concurrency safety is argued separately (see U8; **conclusion: removing the lock does not lower the slow path's protection level, because it was never protected by it**).

---

## U8 Cross-Thread Alloc/Free of the Same Zone + Whether UMA Zone-Level Locks Are Stubbed

### 8.1 Conclusion (the most important one)

**f-stack stubs all of UMA's `mtx` locks to no-ops. `ZONE_LOCK`/`ZDOM_LOCK`/`KEG_LOCK` all expand to `((void)0)`.** So the answer to "after removing `critical_enter`, is bucket exchange still lock-protected" is: **no, and it isn't now either** — the zone/keg slow path in f-stack **has always been lock-free**.

### 8.2 Evidence (preprocessing measured, `lib/_m17_probe_u8.c`, same Section 0 parameters)

```
PROBE_MTX_LOCK        = ((void)0);
PROBE_MTX_UNLOCK      = ((void)0);
PROBE_MTX_LOCK_SPIN   = ((void)0);
PROBE_MTX_UNLOCK_SPIN = ((void)0);
PROBE_MTX_ASSERT      = (void)0;
PROBE_ZONE_LOCK       = ((void)0);
PROBE_ZONE_UNLOCK     = ((void)0);
PROBE_ZDOM_LOCK       = ((void)0);
PROBE_KEG_LOCK        = ({ ((void)0); (struct mtx *)&(kkk)->uk_domain[(0)].ud_lock; });
PROBE_KEG_UNLOCK      = ((void)0);
PROBE_CRITICAL_ENTER  = do { while (__sync_lock_test_and_set(&uma_crit_lock, 1)) ; } while(0);
PROBE_CRITICAL_EXIT= do { __sync_lock_release(&uma_crit_lock); } while(0);
```

Source: `lib/include/sys/mutex.h` (f-stack override)
```c
:31-55  #undef __mtx_lock / __mtx_unlock / __mtx_lock_spin / __mtx_unlock_spin
        #undef _mtx_lock_flags / _mtx_unlock_flags / _mtx_lock_spin_flags / _mtx_unlock_spin_flags
        #undef thread_lock / thread_unlock / mtx_trylock_flags_ / mtx_init / mtx_destroy / mtx_owned
:57     #define DO_NOTHING ((void)0)
:59-67  #define __mtx_lock(...) DO_NOTHING   ... all DO_NOTHING
:74-76  #define mtx_trylock_flags_(m,o,f,l) 1     /* trylock always "succeeds" */
:85     #define mtx_owned(m) (1)
```
And `ZONE_LOCK`/`KEG_LOCK`'s original definitions are indeed built on `mtx_lock` (`freebsd/vm/uma_int.h:539-554,582-584`):
```c
:551-552 #define KEG_LOCK(k, d)  ({ mtx_lock(KEG_LOCKPTR(k, d)); KEG_LOCKPTR(k, d); })
:582     #define ZONE_LOCK(z)    ZDOM_LOCK(ZDOM_GET((z), 0))
```
`freebsd/kern/kern_mutex.c` **is not in `lib/Makefile`'s `KERN_SRCS`** (measured no entry in `lib/Makefile:339-377`), and there is no `kern_mutex.o`, corroborating that mutex fully goes through override macros; `lib/ff_lock.c` only provides **init/destroy** shells like `ff_mtx_init`/`mtx_sysinit`/`_mtx_destroy`, not locking.

### 8.3 Cross-Thread Alloc/Free of the Same Zone Paths

**They exist, and in large numbers.** f-stack's zones are **shared across the whole process** (`uma_zcreate` in `mi_startup()` by the main thread, not per-worker), so:

| zone | allocator | free-er | cross-thread? |
|---|---|---|---|
| mbuf / mbuf_cluster (`freebsd/kern/kern_mbuf.c`, in the compile set) | receive thread = that queue's worker | send completion/`m_freem` usually on the same worker; but **loopback (`FF_LOOPBACK_SUPPORT=1`), `if_bridge`, `netgraph`, KNI (concentrated on the owner thread)** can cause cross-thread | **yes (paths exist)** |
| socket / pcb / tcpcb / syncache (`in_pcb.c`, `tcp_subr.c`, `tcp_syncache.c`) | each worker has its own vnet (`ff_freebsd_init.c:209-214` per-worker `vnet_alloc()` + independent prison), so connections don't cross workers | same | by design **no**, but **the zone itself is shared** (zones are not per-vnet) |
| `pcpu_zone_8` (counter) / "SMR CPU" / "SMR SHARED" | mostly main thread (during `mi_startup`) | very rare frees | basically no |
| bucket zones (`uma_core.c:486-511bucket_alloc` / `:514 bucket_free`) | **any worker** (on fast-path miss) | **any worker** | **yes, and it's a hot path** |

**Key point**: even if business objects (socket/pcb) don't cross threads, **the bucket and slab layers necessarily cross threads**: worker A's cache miss takes a bucket from the zone's shared `zdom`/keg, and worker B's full cache returns a bucket to the same `zdom`. These operations go through `zone_fetch_bucket`/`zone_put_bucket`/`keg_alloc_slab`, protected by `ZDOM_LOCK`/`KEG_LOCK` — **and those two locks are no-ops**.

Meanwhile f-stack's own `vsetzoneslab()` (`lib/include/vm/uma_int.h:105-126`) does `malloc` a `struct uma_page` and `LIST_INSERT_HEAD(hash_list, up, list_entry)` on every new slab, **also lock-free**; concurrent insertions into the same hash bucket break the chain.

### 8.4 Impact on the Solution (**this round's most important risk-ruling point**)

1. **Removing `uma_crit_lock` does not "make an originally-locked bucket exchange lock-free"** — it was already lock-free (8.2/8.3). So G2 holds in the "introduces no new risk" sense: G2 only removes serialization of the **per-CPU cache fast path**, whose mutual exclusion is guaranteed by "thread-exclusive slots" after G1.
2. **But `uma_crit_lock` currently has the practical side effect of "greatly shrinking the slow-path concurrency window"**: because the window between a fast-path miss and refill is squeezed by this lock, the probability of two workers entering the zone/keg slow path simultaneously is significantly reduced (not eliminated). **After removal, the lock-free contention window of `zdom`/keg/`uma_page` hash is enlarged**, and load tests may expose the chain-break/double-free currently masked by probability.
   - **This explains why `b90ddcba5` adding the lock "fixed" `kqueue_kevent`'s SIGSEGV**: it fixed both the shared-`uz_cpu[0]` race (the real cause) and incidentally suppressed the slow-path race.
   > 🔵 **【C-Correction · reinforcement】** The "shared `uz_cpu[0]`" in the parentheses above was originally inferred from "all `pc_cpuid` are 0"; **the actual cause is stronger**: `curcpu` is hardcoded to the literal `0` at `lib/include/sys/pcpu.h:34`, so **regardless of `pc_cpuid`, all threads necessarily land on `uz_cpu[0]`** (`uma_core.c`'s 11 `&zone->uz_cpu[curcpu]` sites). That is, this lock protects a **necessary conflict** rather than a probabilistic race — which also explains why `ff09a17b2` must keep it after changing cpuid back to 0. → **G2's precondition must be written as "both mechanism A (`zpcpu_get`/SMR) and mechanism B (`curcpu`/UMA cache) achieve per-thread exclusivity"**, see C-Correction §C.2. This paragraph's judgment about "slow-path window enlargement" **is unchanged**; still needs M5 load testing (unverified item U8-perf).
3. **Therefore `designer` should consider: G2 is not as simple as "delete the macro"**; at minimum it must rule among the following (this doc only gives evidence, not the ruling):
   - **G2-a**: `critical_enter/exit` → `do {} while(0)` (back to before `b90ddcba5`), and **add real locks to `ZDOM_LOCK`/`KEG_LOCK`/`vsetzoneslab`** (change `lib/include/sys/mutex.h`'s `mtx_lock` no-ops to real spin/`pthread_mutex`, at least for UMA translation units). Granularity drops from "one global" to "one per-zone/per-keg" → both safe and concurrency gains.
   - **G2-b**: `critical_enter/exit` → `do {} while(0)`, slow path untouched (accept the status quo), validated only by load tests. **Risk covered by load tests; must be honestly recorded as a residual risk in the spec.**
   - **G2-c**: keep the global lock but shrink it to only wrap bucket exchange.
4. **Auxiliary fact (lowers difficulty)**: `lib/ff_glue.c:83 int __read_mostly vm_ndomains = 1;` and **`NUMA` is undefined** (not in the compile command nor in `lib/opt/opt_global.h`; measured `lib/opt/opt_global.h` content is only `MUTEX_NOINLINE / RWLOCK_NOINLINE / SX_NOINLINE / DEV_RANDOM / NO_EVENTTIMERS / VIMAGE`). So all `#ifdef NUMA` **cross-domain bucket paths in `uma_core.c` are compiled out** (`:1009,3926,3941,4161,4173,4189,4519,4536,4546,4622,4636,4662,4758,4812`), `itemdomain` is always 0 (`:4535,4621`), and `uc_crossbucket` is never loaded (its only loading point `:1009-1014` is inside `#ifdef NUMA`). **→ the cross-domain complexity layer does not exist; only "cross-thread" needs handling.**
5. **One non-fatal anomaly in `cache_drain_safe()`** (`uma_core.c:1497-1509`): `CPU_FOREACH(cpu) { sched_bind(curthread, cpu); cache_drain_safe_cpu(...); }`, and `lib/ff_glue.c:1187 sched_bind()` is a stub; `cache_drain_safe_cpu()` uses `&zone->uz_cpu[curcpu]` (`:1452`). → after `mp_maxid>0`, this loop **drains the calling thread's own cache N times**, and other threads' caches are never reclaimed. **Impact: only incomplete reclamation (memory-reclaim efficiency), no OOB, no memory unsafety.** Suggested: record as a known limitation.

---

## U9 Exhaustive List of `MAXCPU`-Sized / `MAXCPU`-Bounded Sites

**Method**: `grep -n -H -w MAXCPU` over the 254-file compile set (measured output already quoted in U4). Judge per site "what happens if thread count N > MAXCPU".

| # | Location | Form | Consequence of keeping `MAXCPU` at 1 while cpuid becomes 0..N-1 | Needed action |
|---|---|---|---|---|
| 1 | `freebsd/kern/subr_pcpu.c:76` | `uintptr_t dpcpu_off[MAXCPU];` | `pcpu_destroy()` writing `dpcpu_off[pc_cpuid]=0` (`:276`) would write OOB; but `pcpu_destroy` has **zero callers** in the compile set and `dpcpu_init` also zero callers → not actually triggered | `MAXCPU ≥ N` makes it fully safe |
| 2 | `freebsd/kern/subr_pcpu.c:77` | `struct pcpu *cpuid_to_pcpu[MAXCPU];` | **`pcpu_init()` `:91 cpuid_to_pcpu[cpuid]=pcpu` directly writes 8 bytes × (N-1) positions OOB**, overwriting the adjacent `cpuhead` (`:78`) → silent memory corruption (`:88`'s `KASSERT` compiled out because `INVARIANTS` undefined, no error) | **must have `MAXCPU ≥ N` (blocking)** |
| 3 | `freebsd/kern/subr_pcpu.c:88` | `KASSERT(cpuid >= 0 && cpuid < MAXCPU, ...)` | compiled out, **provides no protection** | cannot rely on it |
| 4 | `lib/ff_kern_synch.c:59` + `:105` | `static uint8_t pause_wchan[MAXCPU];` / `pause_sbt()` → `_sleep(&pause_wchan[curcpu], ...)` | 🔴**【C-Correction】attribution fix**: at HEAD baseline `curcpu` is the literal `0` (`lib/include/sys/pcpu.h:34`), so this site **was not OOB**; it always takes `pause_wchan[0]`. The OOB risk is **introduced only after `curcpu` becomes `PCPU_GET(cpuid)`**: then the index becomes `0..N-1`, `&pause_wchan[i]` goes out of the array, but **only the address is taken, not dereferenced** (used only as a unique wait channel), so no crash; the risk is address confusion with adjacent static variables. Also measured: `lib/ff_kern_synch.c:108-113wakeup()` has an empty body; actual impact approaches 0 | **conclusion unchanged: must have `MAXCPU ≥ N`** (eliminate UB) |
| 5 | `lib/ff_kern_timeout.c:730` | `else if ((cpu >= MAXCPU) \|\| ((CC_CPU(cpu))->cc_inited == 0)) panic("Invalid CPU in callout %d", cpu);` | **will panic** (see U11) | **must have `MAXCPU ≥ N` (blocking)** |
| 6 | `lib/ff_glue.c:142` | `int mp_maxcpus = MAXCPU;` | only sysctl export (`:154`), no functional readers | none |
| 7 | `freebsd/netinet/tcp_hpts.c:316` | `int cpu[MAXCPU];` (`struct hpts_domain_info` member) | write point at `tcp_hpts.c:2036hpts_domains[domain].cpu[count]=i`, inside an `#ifndef FSTACK` section (`:2025`) → **not compiled** | none (but watch out if released in the future) |
| 8 | `freebsd/netinet/tcp_hpts.c:1864` | `uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;` | just a value fetch deciding `rp_num_hptss`; if `mp_ncpus` stays 1, completely unchanged | bound to the `mp_ncpus` decision |
| 9 | `freebsd/net/netisr.c:243` | `static u_int nws_array[MAXCPU];` | writes inside `netisr_start_swi()`, index `nws_count` (≤ `netisr_maxthreads`, default 1, `netisr.c:169`); and `swi_add()` is an empty stub (`lib/ff_kern_intr.c:84-89`) | none |
| 10 | `freebsd/net/netisr.c:1432,1457,1486,1516` | `malloc(... * MAXCPU ...)` + `KASSERT(counter <= MAXCPU)` | sysctl stats path; `malloc` growing with `MAXCPU` only uses more memory | none |
| 11 | `freebsd/amd64/include/pcpu_aux.h:47` | `_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE, "fix pcpu size");` | **unrelated to MAXCPU, but an important compile-time guarantee**: since `lib/uma_core.o` etc. compiled successfully, `sizeof(struct pcpu) == 4096` holds (`freebsd/amd64/include/pcpu.h:104 char __pad[2900] /* pad to UMA_PCPU_ALLOC_SIZE */`). So `lib/ff_freebsd_init.c:106 malloc(sizeof(struct pcpu), ...)` allocates exactly 4096 bytes per thread | none |

**U9 conclusion**: there are **3 blocking** `MAXCPU`-sized/bounded sites (#2 `cpuid_to_pcpu[]`, #5 callout panic, #4 `pause_wchan[]`'s UB). Therefore **any "raise cpuid to 0..N-1" solution must simultaneously raise `MAXCPU` to ≥ N** (`freebsd/amd64/include/param.h:60-66`'s `#else`(non-SMP) branch **unconditionally** `#define MAXCPU 1`, so `-DSMP` or an override header in `lib/include/` is required; note `lib/include/sys/param.h` currently just `#include_next`s through, changing no values). And with `MAXCPU ≤ 64`, `sizeof(cpuset_t)` is unchanged (U4.4), **suggest picking a value slightly larger than the max thread count (e.g. 16 or 64) and fixing it once to avoid repeated ABI changes**.

---

## U10 The Current Assignment Point of `mp_maxid` and the Precise Call Order of `uma_startup1/2`, `smr_init`

### 10.1 Where `mp_maxid` Is Assigned Today — **Answer: nowhere**

Measured (U4.1's grep output): `mp_maxid` appears in only 3 places in the compile set:
- `lib/ff_glue.c:145` `u_int mp_maxid;` — **definition only, no initializer** (BSS → 0)
- `lib/ff_glue.c:151` `SYSCTL_INT(_kern_smp, OID_AUTO, maxid, ...)` — read-only export
- the other 21 sites are all **readers**

**Conclusion U10-1**: `mp_maxid` stays 0 throughout, **no runtime assignment point at all**. Therefore this round **must add** an assignment point. Likewise `mp_ncpus` has only `lib/ff_glue.c:140 int mp_ncpus = 1;` as its static initializer, no runtime assignment; `all_cpus`'s only write is `lib/ff_freebsd_init.c:294 CPU_SET(0, &all_cpus);`.

### 10.2 Precise Call Order (measured, verifiable level by level with file:line)

```
app main()
└─ ff_init(argc, argv)lib/ff_init.c:36
   ├─ ff_load_config(argc, argv)                           :39
   │     └─ ff_parse_args → parse_lcore_mask(ff_config.c:73-142)
   │        → proc_lcore[0..count-1], nb_procs=count       ff_config.c:118,139
   │        → thread_mode collapse: nb_threads=nb_procs, nb_procs=1, proc_id=0
   │ff_config.c:1465-1484
   │        ★ at this moment nb_threads(=N) is determined — the earliest point mp_maxid can be set
   ├─ ff_dpdk_init(...)                                     :43
   │     ├─ rte_eal_init(...)
   │     ├─ init_lcore_conf()  → lcore_conf[proc_lcore[ti]].proc_id = ti
   │     │                                                  ff_dpdk_if.c:429-433
   │     ├─ init_mem_pool()   (builds N mbuf pools by nb_threads)
   │     │                                                  ff_dpdk_if.c:526-527,547-551
   │     └─ init_msg_ring()   (builds N rings by nb_threads) ff_dpdk_if.c:692-694
   ├─ ff_freebsd_init()                                     :47
   │  │《《《the mp_maxid / mp_ncpus / all_cpus / MAXCPU assignments must land before here or at the very start of this function》》》
   │  ├─ kern_setenv("kern.hz", ...) / boot env / sysctl     ff_freebsd_init.c:274-289
   │  ├─ physmem = ...                                       :291
   │  ├─ ff_pcpu_thread_init(0)         ← main-thread pcpu    :293   ★ currently the param is ignored, always 0 (:107)
   │  ├─ CPU_SET(0, &all_cpus)                               :294   ★ only bit 0 set
   │  ├─ ff_init_thread0()                                   :296
   │  ├─ bootmem = kmem_malloc(16*PAGE_SIZE, M_ZERO)         :298-299
   │  ├─ uma_startup1((vm_offset_t)bootmem)                  :301
   │  │     └─ uma_core.c:3175-3182
   │  │            ksize = sizeof(uma_keg) + sizeof(uma_domain)*vm_ndomains
   │  │            zsize = sizeof(uma_zone)
   │  │                    + sizeof(struct uma_cache)*(mp_maxid + 1)   ★★★ H1
   │  │                    + sizeof(struct uma_zone_domain)*vm_ndomains
   │  │            → byte sizes of zones/kegs/zone-of-zones fixed here
   │  ├─ uma_startup2()                                      :302
   │  │     └─ uma_core.c:3223-3234
   │  │            slabzones[0]/[1], hashzone, bucket_init()
   │  │            smr_init()                uma_core.c:3233
   │  │              └─ subr_smr.c:624-632
   │  │                   uma_zcreate("SMR SHARED", ...)
   │  │                   uma_zcreate("SMR CPU", sizeof(struct smr), ...,
   │  │                               UMA_ZONE_PCPU)   ★ the PCPU flag gets
   │  │                               stripped by keg_ctor(uma_core.c:2546-2548) under !SMP
   │  ├─ uma_page_slab_hash = kmem_malloc(8192 * sizeof(uma_page)); uma_page_mask=8191
   │  │                :304-306
   │  ├─ mutex_init()                                        :308
   │  ├─ mi_startup()                                        :309   ★ runs all SYSINITs:
   │  │     SI_SUB_COUNTER : SYSINIT(pcpu_zones, ...)  subr_pcpu.c:157
   │  │                       → pcpu_zone_4/8/16/32/64 = uma_zcreate(..., UMA_ZONE_PCPU)
   │  │                                subr_pcpu.c:146-155
   │  │     each COUNTER_U64_DEFINE_EARLY / counter_u64_sysinit
   │  │                       → counter_u64_alloc() = uma_zalloc_pcpu(pcpu_zone_8,...)
   │  │                                                 subr_counter.c:63,227-233
   │  │     SI_SUB_SOFTINTR : SYSINIT(netisr_init)netisr.c:1344
   │  │     SI_SUB_SMP      : SYSINIT(netisr_start)     netisr.c:1365
   │  │     SI_SUB_PROTO_*  : in_pcbinfo_init → uma_zcreate(..., UMA_ZONE_SMR)
   │  │                       → zone_ctor: uz_smr = smr_create(...)  uma_core.c:3023-3024
   │  │→ smr_create: for(i=0;i<=mp_maxid;i++)
   │  │                            zpcpu_get_cpu(smr,i)->c_seq=...   subr_smr.c:598-605  ★★★ H2
   │  │                       ipi_smr = uma_zone_get_smr(...)        in_pcb.c:583,615-617
   │  │     SI_SUB_*        : callout_callwheel_init (global size pass)
   │  │                + ff_callout_thread_init (main-thread callwheel)
   │  │                                          ff_kern_timeout.c:247-259,262
   │  ├─ curthread->td_vnet = vnet0                          :317
   │  ├─ V_tcp_do_ecn = ...                                  :324
   │  ├─ sx_init(&proctree_lock) / ff_fdused_range            :326-327
   │  ├─ config sysctls one by one kernel_sysctlbyname       :329-340
   │  ├─ lo_set_defaultaddr()                                :342
   │  └─ ff_stack_inited = 1   (main-thread marker, so main_loop skips duplicate init) :348
   └─ ff_dpdk_if_up()                                        :51

app ff_run(loop, arg)   →  ff_dpdk_run()      lib/ff_dpdk_if.c:2851
└─ rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)        ff_dpdk_if.c:2857
   └─ main_loop（**one thread per EAL lcore, incl. the main lcore**）
      ├─ qconf = ff_cur_lcore_conf()                         ff_dpdk_if.c:2644
      ├─ ff_stack_thread_init(rte_lcore_id())                ff_dpdk_if.c:2649
      │    ├─ if (ff_stack_inited) return;   ← main thread returns here directly ff_freebsd_init.c:177-178
      │    ├─ while(__sync_lock_test_and_set(&init_lock,1)); :185-186
      │    ├─ ff_pcpu_thread_init(cpuid)                     :187   ← worker pcpu (**currently always 0**, :107)
      │    ├─ ff_init_thread0(); td_i = ff_adapt_user_thread_add(&thread0)
      │    │                                                 :195-198
      │    ├─ff_callout_thread_init()                       :207
      │    │     └─ timeout_cpu = PCPU_GET(cpuid)  ★ see U11  ff_kern_timeout.c:254
      │    ├─ v = vnet_alloc(); curthread->td_vnet = v       :209-210
      │    ├─ ff_worker_prison_init(td_i, v)                 :214
      │    ├─ lo_set_defaultaddr()                           :215
      │    └─ __sync_lock_release(&init_lock)                :216
      └─ data-plane loop (receive/protocol stack/send/ff_hardclock/ff_msg/KNI)
```

### 10.3 Conclusion

- **`mp_maxid` / `all_cpus` / `MAXCPU` (compile-time) must be finalized before `lib/ff_freebsd_init.c:301uma_startup1()`**. The most natural landing point is the start of `ff_freebsd_init()` around `:291-294` (expand `CPU_SET(0,&all_cpus)` to `for (i=0;i<N;i++) CPU_SET(i,&all_cpus)`, and set `mp_maxid = N-1`). At that point `ff_global_cfg.dpdk.nb_threads` is already determined by `ff_load_config()` (two levels earlier), **information fully available**.
- **Changing `mp_maxid` after `ff_freebsd_init()` necessarily breaks** (H1: zone sizes fixed; H2: `smr_create` already wrote slots by the old value).
- **`uma_crit_lock` macro coverage (supplementing the U7 leftover)**: `lib/include/vm/uma_int.h` is the override of `vm/uma_int.h`; only translation units `#include`-ing `<vm/uma_int.h>` are affected. Measured `grep -l 'vm/uma_int.h' $(cat _m17_srcpaths.txt)` over the 254-file set **hits only 2 files**:
  ```
  lib/ff_freebsd_init.c
  freebsd/vm/uma_core.c
  ```
  **Fully consistent** with the gate-plan conclusion provided by the leader. Additional measurement: `grep -c 'critical_enter\|critical_exit' lib/ff_freebsd_init.c` = **0**, i.e. that file introduces the macros but has **no call sites** → **`uma_crit_lock` in fact acts only on `freebsd/vm/uma_core.c`**.

---

## U11 callout's cpuid Semantics (**high priority; this round's clearest blocking defect**)

### 11.1 Conclusion (three points)

1. **`timeout_cpu` is a non-`__thread` file-level global yet written by every thread. After dense cpuid it gets overwritten to "the cpuid of the last thread to finish `ff_callout_thread_init()`"** (because that call is inside the `init_lock` critical section, writes are serialized and not torn, but **the final value is indeterminate and corresponds to no single thread**).
2. **`lib/ff_kern_timeout.c:730`'s `panic("Invalid CPU in callout %d")` will be triggered** — as long as `MAXCPU` stays 1 and any cpuid ≥ 1 is passed into `callout_reset_tick_on`. The trigger path is **on the data plane and necessarily happens** (see 11.3). If `MAXCPU` is raised to ≥ N, then `cpu >= MAXCPU` no longer holds, and the second condition `(CC_CPU(cpu))->cc_inited == 0` also doesn't hold because `CC_CPU(cpu)` **ignores the argument** and always returns the calling thread's own initialized `cc_cpu` → **no panic**.
3. **`timeout_cpu` should become `__thread`** (together with clarifying `c->c_cpu`'s semantics). Reasons and cost in 11.4.

### 11.2 Evidence: All Read/Write Points of `timeout_cpu` (measured `grep -n 'c_cpu\|timeout_cpu\|cc_inited' lib/ff_kern_timeout.c`)

```
169:    u_int cc_inited;                        /* struct callout_cpu member */
183:__thread struct callout_cpu cc_cpu;         /* ★ one callwheel per thread */
184:#define CC_CPU(cpu)    &cc_cpu              /* ★ completely ignores the cpu argument */
185:#define CC_SELF()      &cc_cpu
190:static int timeout_cpu;                     /* ★ a non-__thread global variable */
252:    memset(CC_SELF(), 0, sizeof(cc_cpu));   /* ff_callout_thread_init() */
254:    timeout_cpu = PCPU_GET(cpuid);          /* ★ every thread writes this global */
255:    cc = CC_CPU(timeout_cpu);               /*but still fetches its own cc_cpu */
258:    callout_cpu_init(cc, timeout_cpu);      /*   cpu only used for the snprintf name */
300:    cc->cc_inited = 1;                      /* inside callout_cpu_init() */
367:        cpu = c->c_cpu;                     /* callout_lock(): cc = CC_CPU(cpu) still ignores */
370:        if (cpu == c->c_cpu)
662:    cc = CC_CPU(timeout_cpu);               /* timeout(9), fetches its own cc_cpu */
731:           ((CC_CPU(cpu))->cc_inited == 0)) /* ★ the second condition of the panic check */
756:        cpu = c->c_cpu;
815:    return callout_reset_on(c, to_ticks, c->c_func, c->c_arg, c->c_cpu);  /* ★ passes c_cpu back as cpu */
1061:    c->c_cpu = timeout_cpu;                 /* callout_init() */
1077:    c->c_cpu = timeout_cpu;                 /* _callout_init_lock() */
1181:    cc = CC_CPU(timeout_cpu);               /* sysctl kern.callout_stat */
1257: * Worker-thread clock: only advances this thread's own callwheel ...
```

In `callout_cpu_init()` (measured function body) the `cpu` parameter is only used for `snprintf(cc->cc_ktr_event_name, ..., "callwheel cpu %d", cpu)`, **not for any addressing**; `if (cc->cc_callout == NULL) return;  /* Only cpu0 handles timeout(9) */` also only checks the pointer, not the cpu value.

In `callout_lock()` (measured function body) `cpu = c->c_cpu; cc = CC_CPU(cpu);` — because `CC_CPU` ignores the argument, **it always locks the calling thread's own `cc_cpu`**; `if (cpu == c->c_cpu) break;` is always true (no migration).

**In summary**: the value of `timeout_cpu` / `c->c_cpu` in f-stack has **no effect on "which callwheel is used"** (that is decided by `__thread cc_cpu`). Their **only** real effect is being passed into `callout_reset_tick_on()` and participating in the `:730` validity check.

### 11.3 Will the `:730` panic Trigger — Yes, and necessarily on the data plane

`lib/ff_kern_timeout.c:719-734`:
```c
int
callout_reset_tick_on(struct callout *c, int to_ticks, void (*ftn)(void *),
    void *arg, int cpu, int flags)
{
    ...
    if (cpu == -1) {
        ignore_cpu = 1;
    } else if ((cpu >= MAXCPU) ||
           ((CC_CPU(cpu))->cc_inited == 0)) {
        /* Invalid CPU spec */
        panic("Invalid CPU in callout %d", cpu);
    }
```
Macro chain (`freebsd/sys/callout.h:96-120`):
- `callout_reset(c,...)` / `callout_reset_sbt(...)` / `callout_schedule_sbt(...)` → **cpu = -1**, safe.
- `callout_reset_curcpu` / `callout_reset_sbt_curcpu` / `callout_schedule_sbt_curcpu` / `callout_schedule_curcpu` → **cpu = `PCPU_GET(cpuid)`**, after dense indexing = this thread's number i.
- `callout_reset_on(c,...,cpu)` / `callout_reset_sbt_on(...,cpu,...)` / `callout_schedule_on(...,cpu)` → given by the caller.
- `lib/ff_kern_timeout.c:815 callout_schedule(c,ticks)` → passes **`c->c_cpu`** (= a `timeout_cpu` snapshot from some `callout_init`).

Real call sites in the compile set passing non--1 cpu (measured grep, excluding `ff_kern_timeout.c` itself):

| Call site | cpu passed | data plane? | under dense cpuid + `MAXCPU==1` |
|---|---|---|---|
| `freebsd/kern/kern_event.c:790-791` `kqtimer_sched_callout()` → `callout_reset_sbt_on(&kc->c, ..., kc->cpuid, C_ABSOLUTE)`, with `kern_event.c:935 kc->cpuid = PCPU_GET(cpuid);` | this thread's dense number i | **yes** (EVFILT_TIMER / kqueue) | **panics**. ⚠ Especially note: `b90ddcba5` fixed exactly the **SIGSEGV on the `kqueue_kevent` path**; this path is strongly kqueue-related |
| `freebsd/netinet/tcp_timer.c:894-896` and `:931-933` → `callout_reset_sbt_on(&tp->t_callout, ..., inp_to_cpuid(inp), C_ABSOLUTE)`, with `inp_to_cpuid()` (`tcp_timer.c:246-249`) = `inp->inp_flowid % (mp_maxid + 1)`, returned as-is if `CPU_ABSENT` passes | `0..mp_maxid` | **yes** (every TCP connection's timer, one of the hottest paths) | **panics** (as long as `mp_maxid>0` and some connection's flowid % (N) != 0) |
| `freebsd/netinet/tcp_hpts.c:1025-1027,1645-1647, 1807-1809, 2047-2049` → `callout_reset_sbt_on(&hpts->co, ..., hpts->p_cpu, ...)` | `0..rp_num_hptss-1` (see below) | **yes** (`TCPHPTS` enabled `-DTCPHPTS`) | **panics** when `p_cpu >= MAXCPU`; `rp_num_hptss` upper bound comes from `tcp_hpts.c:1864 ncpus = mp_ncpus ? mp_ncpus : MAXCPU` → **if `mp_ncpus` stays 1 then `p_cpu` is always 0, safe** |
| `freebsd/kern/subr_taskqueue.c:368` → `callout_reset_sbt_curcpu(&timeout_task->c, ...)` = `PCPU_GET(cpuid)` | this thread's dense number i | depends on taskqueue usage; `taskqueue_enqueue_timeout*` has callers in f-stack | **panics** (if reached) |
| `freebsd/netpfil/ipfw/ip_fw_dynamic.c:2843` → `callout_reset_on(&V_dyn_timeout, hz, dyn_tick, vnetx, 0)` | constant **0** | yes (`FF_IPFW=1`) | safe (0 < MAXCPU=1) |

> **Clarification of `p_cpu = 0xffff` (originally U11-a, now verified this round, not a risk)**: `tcp_hpts.c:1997 hpts->p_cpu = 0xffff;` and `:2010 hpts->p_cpu = i;` **sit in two different for loops** (measured `sed -n '1900,1915p;2000,2016p'`: `:2008for (i = 0; i < tcp_pace.rp_num_hptss; i++) { hpts = tcp_pace.rp_ent[i]; hpts->p_cpu = i;` is the second loop). In the first loop, `0xffff` is just a placeholder; right after comes `:1999 callout_init(&hpts->co, 1);` (`callout_init` only writes `c->c_cpu = timeout_cpu`, **does not call `callout_reset_tick_on`**), and before any `callout_reset_sbt_on`, `:2010` overwrites it with `i`. **So `0xffff` is never passed down as a callout cpu and does not constitute a panic risk.**
> Also measured: `tcp_hpts.c:2002-2003 if (vm_ndomains == 1 && tcp_bind_threads == 2) tcp_bind_threads = 0;`, and `lib/ff_glue.c:83 vm_ndomains = 1` → `tcp_bind_threads` never takes 2; the `:2025 #ifndef FSTACK` section is moreover uncompiled.

**Conclusion 11.3**: the two **necessary data-plane** paths `kern_event.c:790` and `tcp_timer.c:894/931` will immediately panic after dense cpuid. → **`MAXCPU ≥ N` is a hard precondition of G1** (consistent with U9).

> 🔴 **【C-Correction · new trigger path】** `inp_to_cpuid()` besides the `:246 % (mp_maxid + 1)` path has two fallbacks `return (curcpu);` (`freebsd/netinet/tcp_timer.c:237` and `:249`). At HEAD baseline `curcpu` is the literal `0` (`lib/include/sys/pcpu.h:34`), so these two always return 0 and are safe; but **after `curcpu` becomes `PCPU_GET(cpuid)` they return `0..N-1`**, equally flowing into `:896/:932`'s `callout_reset_sbt_on()` → equally landing on `ff_kern_timeout.c:730`'s `cpu >= MAXCPU` check. **This only adds a third trigger path for "`MAXCPU ≥ N`"; the conclusion is unchanged.** The complete `curcpu` impact scope is in C-Correction §C.3.

### 11.4 Fix Suggestions (this doc only gives basis and options, not the ruling)

- **Mandatory A**: raise `MAXCPU` to ≥ thread count (otherwise the `:730` panic + `cpuid_to_pcpu[]` OOB).
- **Mandatory B**: `static int timeout_cpu;` (`:190`) **should become `static __thread int timeout_cpu;`**. Basis:
  - Its only semantics is "the cpuid of this thread's callwheel", assigned per thread by `:254 timeout_cpu = PCPU_GET(cpuid)`; it is essentially thread-private (a matched pair with the adjacent `__thread struct callout_cpu cc_cpu;` (`:183`); `cc_cpu` is already `__thread`, `timeout_cpu` missed it).
  - Consequence of not changing: `callout_init()`/`_callout_init_lock()` (`:1061,:1077`) write **another thread's cpuid** into `c->c_cpu`; later `callout_schedule()` (`:815`) passes it back as cpu to `callout_reset_tick_on` → even if `MAXCPU` is large enough not to panic, semantically it is "thread A's callout remembers thread B's cpuid", a hidden error; meanwhile `timeout(9)` (`:662`) and `sysctl kern.callout_stat` (`:1181`) read someone else's `timeout_cpu` (though lucky-harmless because `CC_CPU` ignores the argument).
  - Cost of `__thread`: **near zero**. `timeout_cpu` has no cross-thread semantic need; after the change `c->c_cpu` always equals the cpuid of the thread that created the callout, and the value `callout_schedule()` passes back is necessarily valid (`< N≤ MAXCPU`).
- **Optional C (more thorough)**: since `CC_CPU(cpu)` always ignores `cpu` and `callout_lock()`'s migration loop is always true, consider changing the `:728-734` validity check to `if (cpu != -1 && cpu > (int)mp_maxid) panic(...)` (use runtime `mp_maxid` rather than compile-time `MAXCPU`), decoupling from the specific `MAXCPU` value and closer to real semantics. **But this changes existing f-stack semantics; `designer`/`reviewer` must rule.**

---

## U13 Threads Without `pcpup` / Without Exclusive Slots (G2's Lock-Removal Precondition)

### 13.1 Conclusion

**Under standard usage like `helloworld` (not calling `ff_pthread_create`), the only threads entering the UMA/SMR fast path are "main thread + (N-1) workers", all of which built `pcpup` via `ff_pcpu_thread_init()` and can achieve 1:1 exclusive slots → G2's precondition holds.**
**But there is an API-level gap: app threads created by `ff_pthread_create()` have `pcpup == NULL`; once they call any `ff_*` protocol-stack API they dereference NULL (crashes today, unrelated to this round but must go into the spec's "unsupported usage").**

### 13.2 Per-Thread-Model Verification

| Thread model | Measured basis | Has `pcpup`? | Exclusive slot? | Enters UMA/SMR? |
|---|---|---|---|---|
| **main thread** (app `main`, also the EAL main lcore, also runs `main_loop`) | `lib/ff_init.c:36-56` → `ff_freebsd_init()`; `lib/ff_freebsd_init.c:293 ff_pcpu_thread_init(0)`; `:348 ff_stack_inited=1` makes it skip duplicate init in `main_loop` (`:177-178`) | yes | under dense scheme occupies slot 0 | yes (builds all zones at startup; runs its own data plane at runtime) |
| **EAL worker threads**×(N-1) | `lib/ff_dpdk_if.c:2857 rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` → `:2649 ff_stack_thread_init(rte_lcore_id())` → `lib/ff_freebsd_init.c:187 ff_pcpu_thread_init(cpuid)` | yes | under dense scheme occupies slots 1..N-1 | yes (hot path) |
| **KNI** | **no independent thread**. `lib/ff_dpdk_kni.c:93-97`:<br>`ff_kni_is_owner_thread(void){ if (ff_global_cfg.dpdk.thread_mode) return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0]; ... }`, used at `:387,:434,:484,:537` for "only the owner thread does KNI's common part"; each lcore's own rings named by `rte_lcore_id()` (`:396-415`). `ff_kni_process()` (`:502`) called by `main_loop` | reuses the owning worker's | yes | yes (but via the owning worker's slot) |
| **`ff_veth` send/receive** | `ff_veth.c`'s `ff_veth_input`/`ff_veth_transmit` called directly by `main_loop` (no thread-creation code; grep in `lib/ff_veth.c` for `pthread_create`/`kthread` is empty) | reuses worker's | yes | yes |
| **callout / timer** | **no independent thread**. `lib/ff_kern_timeout.c:183-185 __thread struct callout_cpu cc_cpu; #define CC_CPU(cpu) &cc_cpu`; `ff_hardclock()`/`ff_hardclock_worker()`/`ff_tcp_hpts_softclock()` called periodically by `main_loop` (extern decls at `lib/ff_dpdk_if.c:186-188` + calls in the loop) | reuses worker's | yes | yes |
| **netisr swi /ithread** | **no thread**. `lib/ff_kern_intr.c:84-89 swi_add(){return 0;}`, `:91-95 swi_sched(){}`, `:97-101 swi_remove(){return 0;}`, `:103-107 intr_event_bind(){return EOPNOTSUPP;}` all empty stubs | — | — | no (path does not run) |
| **kthread / kproc / taskqueue / netgraph ngthread / so_splice** | **no thread**. `lib/ff_compat.c:162-169 kproc_kthread_add(...){ return 0; }`, `:171-177 kthread_add(...){ return 0; }` all empty stubs; `lib/ff_glue.c:1019-1023 kproc_exit(){ panic(...) }`, `lib/ff_compat.c:179-183 kthread_exit(){ panic(...) }` show these paths are not expected to run. So `lib/ff_ng_base.c:3253 kproc_kthread_add(ngthread,...)`, `freebsd/kern/subr_taskqueue.c`'s `taskqueue_start_threads*`, `freebsd/kern/uipc_socket.c:463-465`'s `splice_work_thread` **will not really start threads** | — | — | no |
| **DPDK's own threads** (`eal-intr-thread`, telemetry, service lcores) | DPDK EAL internal threads. **f-stack registers no rte_service** (grep for `rte_service_component_register`/`rte_service_lcore` in `lib/*.c` outside the 254-file set is 0 hits); EAL interrupt threads only handle link status/VFIO etc., not calling `ff_*`/UMA | none | — | no |
| **app threads `ff_pthread_create`** | `lib/ff_thread.c:32-46`: `ff_pthread_create()` sets `data->parent = pcurthread` then `pthread_create(thread, attr, ff_start_routine, data)`; `ff_start_routine` (`:20-30`) only does `ff_set_thread(p_data->parent)` (`:16-18`, i.e. `pcurthread = other`) → **does not call `ff_pcpu_thread_init()`; `__thread pcpup` stays NULL** | **none (NULL)** | — | **crashes if calling any `ff_*` protocol-stack API** (`PCPU_GET(x)` expands to `(pcpup->pc_x)`, see U1) |

### 13.3 Impact on G2

- **Precondition 1 (threads and slots 1:1)**: holds under standard usage. And because `pcpup` is `__thread` (`lib/ff_freebsd_init.c:85`) and `curcpu = PCPU_GET(cpuid) = pcpup->pc_cpuid` is a thread-private constant, "exclusive" **does not depend on core pinning and is unaffected by OS migration** — stronger than upstream `critical_enter()`'s "no preemption within the same CPU".
- **Precondition 2 (no thread with `pcpup==NULL` enters UMA)**: **holds, but depends on the convention "the app does not use `ff_pthread_create` + does not call `ff_*` in it"**. Suggest the spec gives an either/or: (a) explicitly document as unsupported; (b) add `ff_pcpu_thread_init(<new slot>)` in `ff_start_routine` (`lib/ff_thread.c:20-30`), but this **requires reserving extra slots** (`mp_maxid` must be ≥ thread count + app thread count), conflicting with H1's "`mp_maxid` must be finalized before `uma_startup1`" (app thread count is unknown at startup) → **(b) needs a "reserve K extra slots" config item**. This is a design point `designer` must rule on.

---

## U14 `lib/ff_ng_base.c:3249 numthreads = mp_ncpus;` — One-Sentence Conclusion

**No actual impact.** After `lib/ff_ng_base.c:3249 numthreads = mp_ncpus;`, `:3253` uses `kproc_kthread_add(ngthread, NULL, &p, &td, ...)` to start netgraph workers, and `lib/ff_compat.c:162-169 kproc_kthread_add()` is an **empty stub returning 0, creating no threads**; so even raising `mp_ncpus` from 1 to N only enlarges the loop variable, calling `kproc_kthread_add` a few more times and returning 0 unchanged, **creating no threads and allocating no per-CPU resources**. (If `mp_ncpus` stays 1 in the future (the freedom suggested in U4.2), then even that doesn't change.)

## U15 Does `dpcpu_init()` Have Callers in Other `freebsd/` Subdirectories — One-Sentence Conclusion

**No.** Grepping `dpcpu_init` over the 254 actually-compiled files only hits `freebsd/kern/subr_pcpu.c:100` (the definition itself), **zero call sites**. Supplementary: over the whole `freebsd/` tree (not limited to the compile set) there is only `subr_pcpu.c`'s definition and `freebsd/sys/pcpu.h`'s declaration; upstream would call it from `amd64/amd64/mp_machdep.c`/`machdep.c`, which **are not in `lib/Makefile`'s SRCS** (`MACHINE_SRCS` only has `in_cksum.c`, see `lib/Makefile:409-410`). Therefore `dpcpu_off[]` stays 0 throughout; DPCPU dynamic per-CPU storage is **completely unenabled** in f-stack, and raising `mp_maxid` has no effect on it (`subr_pcpu.c:263 dpcpu_copy()` goes the `#else` branch `memcpy((void *)(dpcpu_off[0] + (uintptr_t)s), s, size)` — note `dpcpu_off[0]==0` means copying to `s` itself, an existing no-op behavior; this round does not change it).

---

## U16 (Leader's Required Answer) Must `mp_ncpus` Rise in Sync with `mp_maxid` — **Explicit Conclusion**

>This section answers the freedom left by U4.2. The leader's OOB concern: `rp_ent[]` is allocated only by `mp_ncpus`, while `inp_to_cpuid()` returns `% (mp_maxid+1)`; does inconsistency overflow?

### 16.1 Conclusion (**definitive**)

**`mp_ncpus` can safely stay 1; it does not need to rise in sync with `mp_maxid`. `tcp_pace.rp_ent[]` will not overflow.**

**Root reason (one sentence)**: `inp_to_cpuid()` (`tcp_timer.c:229-253`, based on `mp_maxid+1`) **is never used to index `rp_ent[]`**; it has only 2 usage points in the whole tree, both as the `cpu` argument to `callout_reset_sbt_on()`. While **every** index source of `rp_ent[]` independently takes modulo against `mp_ncpus` / `rp_num_hptss`.

### 16.2 Evidence 1: All Usage Points of `inp_to_cpuid()` (whole-tree grep, not just the compile set)

```
freebsd/netinet/tcp_var.h:1477:int inp_to_cpuid(struct inpcb *inp);          /* declaration */
freebsd/netinet/tcp_timer.c:229: inp_to_cpuid(struct inpcb *inp)              /* definition */
freebsd/netinet/tcp_timer.c:896:     tp, inp_to_cpuid(inp), C_ABSOLUTE);     /* callout_reset_sbt_on's cpu argument */
freebsd/netinet/tcp_timer.c:932:     precision, tcp_timer_enter, tp, inp_to_cpuid(inp),   /* same */
```
**4 total; 2 are declaration/definition, 2 are callout `cpu` arguments. Zero intersection with `rp_ent[]`/`t_hpts_cpu`.**

### 16.3 Evidence 2: `rp_ent[]`'s Size and **All** Index Sources (exhaustive)

Size (`freebsd/netinet/tcp_hpts.c`):
```c
:1864  uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;
:1872  tcp_pace.rp_num_hptss = ncpus;
:1885  sz = (tcp_pace.rp_num_hptss * sizeof(struct tcp_hpts_entry *));
:1886  tcp_pace.rp_ent = malloc(sz, M_TCPHPTS, M_WAITOK | M_ZERO);
:1887  sz = (sizeof(uint32_t) * tcp_pace.rp_num_hptss);
:1888  tcp_pace.cts_last_ran = malloc(sz, M_TCPHPTS, M_WAITOK);
:1921-1925  for (i = 0; i < tcp_pace.rp_num_hptss; i++) { rp_ent[i] = malloc(...); ... }
```

All index points (measured `grep -n 'rp_ent\|rp_num_hptss' freebsd/netinet/tcp_hpts.c`):

| Index point | Index expression | Could be ≥ `rp_num_hptss`? |
|---|---|---|
| `:575` `tcp_hpts_lock()` | `rp_ent[tp->t_hpts_cpu]` | **no** — all assignment points of `t_hpts_cpu` are in 16.4 |
| `:1585` `tcp_choose_hpts_to_run()` | `rp_ent[oldest_idx]`, `oldest_idx` from `for (i = start; i < end; i++)`, `:1559 end = tcp_pace.rp_num_hptss` (when `grp_cnt>1`, `end = cg_last+1`, but `:1890 cpu_top==NULL → grp_cnt=1`, see 16.5) | no |
| `:1587` same else branch | `rp_ent[(curcpu % tcp_pace.rp_num_hptss)]` | no (modulo) |
| `:1922,1924,1925` | `for (i=0;i<rp_num_hptss;i++)` | no |
| `:2009` | `for (i=0;i<rp_num_hptss;i++)` | no |
| `:2077` | `for (int i=0;i<rp_num_hptss;i++)` | no |

### 16.4 Evidence 3: **All** Assignment Points of `tp->t_hpts_cpu` (whole-tree grep)

```
freebsd/netinet/tcp_var.h:328uint16_t t_hpts_cpu;   /* CPU chosen by hpts_cpuid(). */
freebsd/netinet/tcp_var.h:330   #define HPTS_CPU_NONE ((uint16_t)-1)
freebsd/netinet/tcp_subr.c:2298 tp->t_hpts_cpu = HPTS_CPU_NONE;           /* tcpcb init */
freebsd/netinet/tcp_hpts.c:606  tp->t_hpts_cpu = hpts_random_cpu();       /* tcp_hpts_init() */
freebsd/netinet/tcp_hpts.c:1542 tp->t_hpts_cpu = hpts_cpuid(tp, &failed); /* tcp_set_hpts() */
```

Per-site judgment:

1. **`:606` `hpts_random_cpu()`** — `tcp_hpts.c:473`:
   ```c
   cpuid = (((ran & 0xffff) % mp_ncpus) % tcp_pace.rp_num_hptss);
   ```
   **double modulo**, result always `< rp_num_hptss`. **Unrelated to `mp_maxid`**. Safe.
   （`tcp_hpts_init()` at `:604-609`: `if (__predict_true(tp->t_hpts_cpu == HPTS_CPU_NONE)) tp->t_hpts_cpu = hpts_random_cpu();` — guarantees `HPTS_CPU_NONE(=0xffff)` does not remain to be indexed at `:575`.)
2. **`:1542` `hpts_cpuid()`** — `tcp_hpts.c:1040-1099` full body measured; four return paths:
   - `:1049-1051` `if (tp->t_flags2 & TF2_HPTS_CPU_SET) return (tp->t_hpts_cpu);` → returns the **previous** already-valid value (induction-safe).
   - `:1056-1062` `if (tcp_use_irq_cpu) { if (tp->t_lro_cpu == HPTS_CPU_NONE) { *failed = 1; return (0); } return (tp->t_lro_cpu); }`
     - `tcp_hpts.c:286 static int tcp_use_irq_cpu = 0;` (default off, only `:373 TUNABLE_INT("net.inet.tcp.use_irq", ...)` enables).
     - and `t_lro_cpu`'s only assignment is `freebsd/netinet/tcp_lro_hpts.c:576-577`, and **`tcp_lro_hpts.c` is not in `lib/Makefile`'s `NETINET_SRCS`** (`lib/Makefile:515` only has `tcp_lro.c`); measured `ls lib/tcp_lro_hpts.o` → **No such file** (`lib/tcp_lro.o` exists). → `t_lro_cpu` is always `HPTS_CPU_NONE` → even with `use_irq` on it takes `*failed=1; return 0;`. Safe.
   - `:1064-1070` `#ifdef RSS` branch — `RSS` undefined (not in compile command nor `lib/opt/opt_global.h`), **not compiled**.
   - `:1076-1079` `if (inp->inp_flowtype == M_HASHTYPE_NONE) return (hpts_random_cpu());` → same as 1, safe.
   - `:1085-1096` main branch: `#ifdef NUMA... #endif` wraps `cpuid = inp->inp_flowid % mp_ncpus;` (`:1089`). **`NUMA` undefined**, so the `#ifdef NUMA` `if/else` skeleton is stripped, leaving the bare `cpuid = inp->inp_flowid % mp_ncpus;` → **uses `mp_ncpus`, not `mp_maxid`** → always `< mp_ncpus == rp_num_hptss`. Safe.
   >★ **This is the key line of this section**: `tcp_hpts.c:1089` uses `% mp_ncpus`, while `tcp_timer.c:246` uses `% (mp_maxid + 1)`. They are **two different numberings**; the former indexes `rp_ent[]`, the latter only feeds callout. So `mp_ncpus` and `mp_maxid` **are allowed to be inconsistent**.
3. **`:2298` `HPTS_CPU_NONE`** — sentinel only; enters `:575`'s indexing path after being replaced by `tcp_hpts_init()` (`:604-609`).
   - ⚠ only residue: `:549 MPASS(hpts->p_cpu == tp->t_hpts_cpu);` and `:1539 hpts = tcp_hpts_lock(tp);` (in `tcp_set_hpts()`, **locking before** changing `t_hpts_cpu`) both rely on "`t_hpts_cpu` is already valid on entry". `MPASS` is compiled out because `INVARIANTS` undefined, providing no protection; but the assignment timing is guaranteed by `tcp_hpts_init()` (same upstream; **not a problem introduced this round**).

### 16.5 Incidental Collection (leader's out-of-band verification; this section cross-confirms)

- **`smp_topo()` returning NULL is safe**: `tcp_hpts.c:1867-1871` `#ifdef SMP cpu_top = smp_topo(); #else cpu_top = NULL; #endif`; `:1890 if (cpu_top == NULL) { tcp_pace.grp_cnt = 1; }` handles it explicitly. This section's measured `sed -n '1855,1930p'` output is consistent. → if taking candidate A (`-DSMP`) with `res-build`'s NULL-returning `smp_topo` stub, **behavior is equivalent to non-SMP**; `grp_cnt=1` → `tcp_choose_hpts_to_run()`'s `end = rp_num_hptss` (`:1559`), no `cg_first/cg_last` OOB risk.
- **`hpts->p_cpu = 0xffff` (`:1997`) is a transient value**: the **second** `for` loop at `:2008-2010` immediately does `hpts = tcp_pace.rp_ent[i]; hpts->p_cpu = i;`, and `:2047 callout_reset_sbt_on(..., hpts->p_cpu, ...)` comes after; `#ifndef FSTACK` only covers `:2025-2041` (NUMA pinning section); `p_cpu = i` is in the compile scope. **U11-a closed; no panic.** (Consistent with the clarification block in U11 §11.3.)
- **`smp_started` has no semantic risk**: in the compile set only `lib/ff_glue.c:219 active = smp_started;` (sysctl handler) reads it; `kern_clocksource.c`/`kern_cpu.c`/`sched_4bsd.c`/`sched_ule.c`/`subr_atomic64.c`/`subr_smp.c` are all not in `lib/Makefile`'s SRCS. → `-DSMP` introduces no `smp_started` semantic risk.

### 16.6 Impact on the Solution (ruling basis `designer` can cite directly)

| Option | Safe (memory/OOB)? | Side effects |
|---|---|---|
| **`mp_maxid = N-1`, `mp_ncpus` stays 1** | **Safe** (16.1~16.4 verified) | `tcp_pace.rp_num_hptss == 1` → **N workers share 1 hpts instance**. And `struct tcp_hpts_entry`'s `HPTS_LOCK` is `mtx` (**no-op**, U8) → **multiple workers concurrently operating the same hpts queue with no lock protection**. ⚠ This is a **real new concurrency hot spot/risk** (not OOB, but linked-list contention). Also `ff_ng_base.c:3249 numthreads = mp_ncpus` has no impact (U14) |
| **`mp_maxid = N-1`, `mp_ncpus = N`** | **Safe** (`rp_num_hptss == N`, index and size consistent), **but requires `MAXCPU ≥ N`** (otherwise `hpts->p_cpu = i` (`:2010`) into `callout_reset_sbt_on` (`:1025/1645/1807/2047`) triggers `ff_kern_timeout.c:730`'s panic — see U11) | each worker an independent hpts instance (`hpts_cpuid()` spreads by `inp_flowid % mp_ncpus`), **the concurrency hot spot naturally resolves**; cost is N copies of `p_hptss` (`asz = sizeof(struct hptsh) * NUM_OF_HPTSI_SLOTS`, `:1920,1924`) memory + the `netisr_maxthreads` upper bound released (default still 1, `netisr.c:169`) + `ff_ng_base.c:3249`'s loop variable grows (but `kproc_kthread_add` is an empty stub, U14 no impact) |

**This section's suggestion (for ruling, not the ruling itself)**: from the "introduce no new lock-free concurrency hot spot" angle, **raising `mp_ncpus = N` and `mp_maxid = N-1` in sync is more consistent** (each worker exclusively owns one hpts instance, matching this round's G1 "per-thread isolation" theme); keeping `mp_ncpus` at 1, though **not overflowing**, makes N workers contend on the same lock-free hpts queue.
⚠ **Unverified item U16-a**: `tcp_hpts`'s actual activity in f-stack. `tcp_hpts_thread` is registered by `swi_add()`, and `lib/ff_kern_intr.c:84-89 swi_add(){ return 0; }` is an empty stub, `swi_sched()` also empty — so the hpts **swi thread does not run at all**; but `__tcp_run_hpts()` (`:1592`)/`tcp_choose_hpts_to_run()` may be driven directly by `lib/ff_dpdk_if.c`'s `ff_tcp_hpts_softclock()` (`ff_dpdk_if.c:188` extern declaration) inside `main_loop`. **If indeed driven by `main_loop`, the "N workers contending for the same hpts" risk is real**; if hpts is actually completely inactive (e.g. only the rack/bbr stacks use it while the default stack is newreno), the risk is 0. **Suggested means**: read `ff_tcp_hpts_softclock()`'s definition and call condition in `lib/ff_dpdk_if.c` + print `hpts->p_on_queue_cnt`/`tcp_pace.rp_num_hptss` at M5 runtime. **This item directly decides the pros/cons of the two options in the table; `designer` should have an agent close it before M2.**

---

## Appendix A: Unverified-Item Summary (Forbidden to Use as Verified Facts in the Spec)

### A.1 Items **Newly Verified This Round**, Moved Out of "Unverified"

| # | Original question | Verified conclusion | Evidence |
|---|---|---|---|
| U2-a | Is every page of a multi-page slab (`uk_ppera>1`) registered **per page** in f-stack's `UMA_PAGE_HASH` reverse table | **Yes, per page, no problem** | `freebsd/vm/uma_core.c:1822-1825`: `if (keg->uk_flags & UMA_ZFLAG_VTOSLAB) for (i = 0; i < keg->uk_ppera; i++) vsetzoneslab((vm_offset_t)mem + (i * PAGE_SIZE), zone, slab);` — calls `vsetzoneslab` for **each page** of the slab, exactly matching `lib/include/vm/uma_int.h:85 up_va == (va & ~(PAGE_SIZE-1))`'s single-page exact match. And PCPU kegs necessarily carry `UMA_ZFLAG_OFFPAGE` (`uma_core.c:2406-2407` excludes inline slab headers, `:2426` gives OFFPAGE) → via `:2486-2491` get `UMA_ZFLAG_VTOSLAB` (`pcpu_zone_*`/"SMR CPU" all without `UMA_ZONE_NOTPAGE`). **The only residue is the concurrency issue**: `vsetzoneslab()`'s `malloc` + `LIST_INSERT_HEAD` is lock-free (see U8) |
| U2-b | `uma_page_slab_hash` bucket count / `uma_page_mask` | **values verified** | `lib/ff_freebsd_init.c:304-306`: `num_hash_buckets = 8192; uma_page_slab_hash = kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO); uma_page_mask = num_hash_buckets - 1;` → 8192 buckets, mask=8191. Releasing PCPU makes slab page counts ×N, only lengthening hash chains (**pure performance**, not correctness) |
| U7-a | Is `subr_smr.c`'s `critical_enter/exit` the `uma_crit_lock` | **No**; and it is an **empty function body** | `cc -E freebsd/kern/subr_smr.c` then `grep -c uma_crit_lock` = **0**; `freebsd/sys/systm.h:~200-210`'s `critical_enter/exit` preprocess to empty bodies (see U7 §7.1) |
| U7-b | Does netisr swi actually start OS threads | **No** | `lib/ff_kern_intr.c:84-89 swi_add(){return 0;}`, `:91-95 swi_sched(){}`, `:97-101 swi_remove(){return 0;}`, `:103-107 intr_event_bind(){return EOPNOTSUPP;}` |
| U7-c | Do `kproc_kthread_add`/`kthread_add` really create threads | **No** | `lib/ff_compat.c:162-169`, `:171-177` both `return 0;` empty stubs; `:180-183 kthread_exit(){panic(...)}`, `lib/ff_glue.c:1029-1032 kproc_exit(){panic(...)}` corroborate these paths are not expected to run |
| U11-a | Is `tcp_hpts.c:1997 p_cpu = 0xffff` passed down as a callout cpu | **No** (two different for loops; `:2010 p_cpu = i` overwrites it before any `callout_reset_sbt_on`) | see U11 §11.3's clarification block (`sed -n '1900,1915p;2000,2016p'` measured) |
| U10 | current assignment point of `mp_maxid` | **no assignment point anywhere** (`lib/ff_glue.c:145` BSS definition only) | see U10 §10.1 |
| U16 | does `tcp_pace.rp_ent[]` overflow with `mp_maxid=N-1` and `mp_ncpus=1` | **No** (every index of `rp_ent[]` independently takes modulo against `mp_ncpus`/`rp_num_hptss`; `inp_to_cpuid()` has only 2 usage points in the whole tree, both only as callout cpu arguments) | see U16 §16.2~16.4 |
| (leader out-of-band) | is `smp_topo()` returning NULL safe | **Safe**, `tcp_hpts.c:1890 if (cpu_top == NULL) { grp_cnt = 1; }` handles it explicitly | see U16 §16.5, cross-confirmed with this doc's `sed -n '1855,1930p'` measurement |
| (leader out-of-band) | does `smp_started` introduce semantic risk after `-DSMP` | **No**; in the compile set only `lib/ff_glue.c:219` reads it (sysctl handler) | see U16 §16.5 |

> **Note for `designer`**: U7-a / U7-b / U7-c have been **verified and closed** in table A.1; the corresponding body sections are §7.1 (`_m17_smr.i`'s `grep -c uma_crit_lock == 0`), §7.2 and §13.2 (`lib/ff_kern_intr.c:84-107`, `lib/ff_compat.c:162-177`). **Please do not cite them as "unverified".**
>
> 🔴 **Also please read the "C-Correction" section of this document first** (located before U1): `curcpu` is hardcoded to `0` at HEAD baseline (`lib/include/sys/pcpu.h:34`); the UMA per-CPU cache goes through `uz_cpu[curcpu]` (`uma_core.c` 11 sites) and **not through `zpcpu_get()`**. This fact was discovered by `designer`, re-checked by `leader`, independently verified by this agent, **overturning one inference in U7 §7.3** (marked in place), and correcting U9 #4's attribution. **G1 must also change `curcpu`; changing only `pcpu_init()`'s dense cpuid is insufficient to isolate the UMA per-CPU cache.**

### A.2 Items **Still Not Verified** (must enter the spec with "not verified" wording)

| # | Unverified content | Reason | Suggested follow-up |
|---|---|---|---|
| U5-a | whether `netisr_start` (`SYSINIT... SI_SUB_SMP`, `netisr.c:1365`) truly finishes before workers build their pcpu | static timing inference (`mi_startup()` at `ff_freebsd_init.c:309`; workers' `ff_stack_thread_init` comes after `ff_dpdk_run`); not runtime-verified | print `nws_count` and `cpuhead` length at M5. **Note**: even if the inference is wrong, because `swi_add()` is an empty stub (U7-b), the actual impact approaches 0 |
| U6-a | is the EAL main lcore necessarily `proc_lcore[0]` (→ main thread `proc_id == 0`) | DPDK default-behavior inference, not runtime-verified; `--main-lcore` can break it | print the `rte_get_main_lcore()`/`rte_lcore_id()`/`proc_id`/`pc_zpcpu_offset` tuple at M5 (DoD-1 requires). **The solution should not rely on this inference**: the main thread can also take its own slot via `ff_cur_lcore_conf()->proc_id` |
| U12-ish | is `freebsd/kern/subr_taskqueue.c:368 callout_reset_sbt_curcpu` really reached under f-stack | callers of `taskqueue_enqueue_timeout*` not exhausted (the taskqueue thread does not exist, but `callout_reset` may still be called) | grep the callers of `taskqueue_enqueue_timeout`; or observe at M5 whether the `:730` panic triggers |
| U8-perf | how much the lock-free contention window of the zone/keg slow path + `vsetzoneslab` enlarges after removing `uma_crit_lock`, and whether chain-break shows under load | **static analysis cannot conclude; runtime data required** | M5 high-concurrency soak (`-t8 -c400 -d60s`) + pre/post-lock-removal comparison; if needed, temporarily add real locks to `ZDOM_LOCK`/`KEG_LOCK`/`vsetzoneslab` for A/B |
| U3 | all-tree `#ifdef SMP` distribution and symbols newly activated/missing after `-DSMP` | **not this task's responsibility** (taken by `res-build`'s M1-C) | see `_m17_C_buildprobe.md` |
| **U16-a** | whether `tcp_hpts` is truly active in f-stack (is `__tcp_run_hpts()` driven by `main_loop`'s `ff_tcp_hpts_softclock()`) | `swi_add()`/`swi_sched()` are empty stubs → the hpts swi thread does not run; but `lib/ff_dpdk_if.c:188` has `extern void ff_tcp_hpts_softclock(void);`; its definition and call condition not read | read `ff_tcp_hpts_softclock()`'s definition + `main_loop` call condition; print `tcp_pace.rp_num_hptss` and `hpts->p_on_queue_cnt` at M5. **This item directly decides the pros/cons of the two `mp_ncpus` options in the U16.6 table; suggested to close before M2** |

### A.3 Design Points Raised by This Document That `designer` Must Explicitly Rule On (not unverified, but to-be-decided)

1. **Whether `mp_ncpus` rises together with `mp_maxid`** — **U16 already closed the "safety" question: neither value-taking overflows**. What remains is the **concurrency trade-off**: `mp_ncpus=1` → N workers share 1 lock-free hpts queue (new hot spot); `mp_ncpus=N` → one hpts instance per worker (more consistent), but requires `MAXCPU ≥ N`. See U16.6 table + unverified item U16-a.
2. **What value to pick for `MAXCPU`** (U9: must be ≥ thread count; ≤64 keeps `cpuset_t` ABI unchanged; suggest fixing once like 16/64).
3. **Making `timeout_cpu` `__thread`** (U11.4 mandatory B) and whether to also change `ff_kern_timeout.c:730`'s check from `MAXCPU` to `mp_maxid` (U11.4 optional C).
4. **Disposition of `ff_pthread_create` threads** (U13.3): document as unsupported, or add `ff_pcpu_thread_init` + reserve K extra slots (the latter conflicts with H1's "`mp_maxid` must be finalized before `uma_startup1`", needs a config item).
5. **G2's three routes (G2-a/b/c)** (U8.4): whether to also add real locks to `ZDOM_LOCK`/`KEG_LOCK`/`vsetzoneslab`.
6. **Memory amplification of releasing `UMA_ZONE_PCPU`** (U4.5): each counter goes from an 8-byte slot to an `N*4096`-byte slab; f-stack has many counters; the total must be estimated.

## Appendix B: Temporary Files Used by This Document (cleaned)

`lib/_m17_probe_u1.c`, `lib/_m17_probe_u1.i`, `lib/_m17_probe_u8.c`, `lib/_m17_probe_u8.i`, `_m17_uma_core.i`, `_m17_smr.i`, `_m17_srcset.txt`, `_m17_allc.txt`, `_m17_srcpaths.txt`
— all deleted via `/data/workspace/rm_tmp_file.sh` (measured output `[OK] all 9 path(s) trashed to /data/workspace/.trash/20260804-051411-923376`), **this agent modified no source code**.

> Note: the residual `M lib/Makefile`, `M lib/ff_glue.c`, `?? lib/_m17_probe_build.c/.o`, `?? _m17_A_clean.log` in `git status` **belong to `res-build` (M1-C)'s compile probes** (see the reproducibility note in Section 0), **not this agent's changes; this agent does not clean them up**.
