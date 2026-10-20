# _m17_gate_code_g1: G1 Code Gate Review (reviewer)

> Review object: `coder`'s G1 (SMP-aware per-cpu view + dense index) changes, **including round 2 after leader bounce 1/3**.
> Review method: all conclusions from **actually opening code / executing commands**. Unverified items explicitly marked "unverified".
> I **did not modify any source code**, only write this file. No `git commit`, no touching `config.ini`.

---

## 0. Review baseline (snapshot)

At review start I captured baseline as `coder` round 1 (`lib/` 6 files); during review `coder` round 2 landed (added `lib/include/sys/pcpu.h`, revised `ff_dpdk_if.c` / `ff_freebsd_init.c`). **This report's final judgment targets round 2**.

| File | `git diff --numstat` (round 2, final) | mtime |
|---|---|---|
| `lib/Makefile` | +4 / -0 | 2026-08-04 13:36:29 |
| `lib/ff_glue.c` | +7 / -0 | 13:36:38 |
| `lib/ff_dpdk_if.h` | +1 / -0 | 13:40:06 |
| `lib/ff_kern_timeout.c` | +1 / -1 | 13:38:19 |
| `lib/include/sys/pcpu.h` | +1 / -1 | 13:53:21 |
| `lib/ff_dpdk_if.c` | +7 / -1 | 13:53:38 |
| `lib/ff_freebsd_init.c` | +36 / -10 | 13:53:47 |

**Key: my clean build executed at 13:58:55 / 13:59:14, after all source file mtime (latest 13:53:47) → my compile numbers fully cover round 2 final state, no rerun needed.**

`git status --short freebsd/` output **empty** → upstream tree zero changes, confirmed.
`config.ini` is ` M` but is user's local test change, unrelated to this round (I didn't touch it).

---

## 1. Item-by-item review table (1~16)

| # | Review item | Verdict | Basis (file:line, all workspace final line numbers) |
|---|---|---|---|
| 1 | D2 triple and timing | **PASS** | see §2.1 |
| 2 | D7 thread_mode=0 zero regression | **PASS (but "verbatim equivalent" wording inaccurate)** | see §2.2 |
| 3 | thread_mode=0's `qconf->proc_id` defect | **PASS (fixed in round 2)**; original defect "mandatory fix" | see §2.3 |
| 4 | D4 main thread numbering | **PASS (no collision established)** | see §2.4 |
| 5 | D5 `timeout_cpu` → `__thread` | **PASS**; but stale comment (mandatory fix) | see §2.5 |
| 6 | D6 upper bound check | **PASS** | see §2.6 |
| 7 | D1 / `-DSMP` scope and `smp_topo` stub | **PASS** | see §2.7 |
| 8 | Cross-TU (`ff_cur_proc_id`) | **PASS** | see §2.8 |
| 9 | lib minimal comment convention | **mostly PASS**, 1 mandatory (stale comment) + 1 suggestion | see §2.9 |
| 10 | clean build authenticity (I ran myself) | **PASS** | see §3 |
| 11 | DoD-1 verifiability | **FAIL → coder must add temp probe** | see §2.11 |
| 12 | Concurrency/memory risk (`pcpu_init` global write) | **PASS** | see §2.12 |
| 13 | `curcpu` per-thread-ization | **PASS (round 2 implemented, `#undef` retained)** | see §2.13 |
| 14 | `curcpu` all usage points out-of-bounds recheck (I exhausted myself) | **PASS (no OOB)**, but found 2 semantic changes unrecorded | see §2.14 |
| 15 | `pcpup == NULL` evaluating `curcpu` | **FAIL → 1 mandatory (1 line)** | see §2.15 |
| 16 | Intermediate state (`curcpu` per-thread + global lock still present) self-consistency | **PASS (self-consistent and strictly safer)** | see §2.16 |

---

## 2. Item-by-item basis

### 2.1 D2 triple and timing —— PASS

- Triple all set: `ff_freebsd_init.c:314 mp_ncpus = nb_cpus;`, `:315 mp_maxid = nb_cpus - 1;`, `:316-317 for (i=0;i<nb_cpus;i++) CPU_SET(i,&all_cpus);`
- **Strictly before `uma_startup1()`**: triple at `:314-317`, `uma_startup1((vm_offset_t)bootmem)` at **`:331`**, `mi_startup()` at `:339`.
- **No modification after**: `grep` all `lib/` and compile set, `mp_ncpus` / `mp_maxid` write points only `ff_glue.c:140/145` (definition init) and here; `all_cpus` write points only `ff_glue.c:138` (definition) and here. `freebsd/kern/subr_smp.c` (upstream changes these three) **not in `lib/Makefile` SRCS**, confirmed.
- Verified `uma_core.c:3179-3181` (inside `uma_startup1()`): `zsize = sizeof(struct uma_zone) + (sizeof(struct uma_cache) * (mp_maxid + 1)) + (sizeof(struct uma_zone_domain) * vm_ndomains);`
- **More severe layer than verdict D2 (my new finding, D doc didn't record)**: `freebsd/vm/uma_int.h:507 struct uma_cache uz_cpu[];` is flexible array, and `:528-529 ZDOM_GET(z,n) = &((uma_zone_domain_t)&(z)->uz_cpu[mp_maxid + 1])[n]` —— **domain array immediately follows last cpu cache, and uses `mp_maxid+1` to locate**. So if `mp_maxid` is raised after `uma_startup1()`, not only heap overflow, but also `uz_cpu[]` and `zdom[]` **region overlap**. Current code timing correct, this risk doesn't hold, but this constraint's rigidity should be written into spec.
- Verified `subr_smr.c:598-605 smr_create()`: per-slot write depends on `mp_maxid` finalized ✓.
- Verified D2's ipfw heap overflow point: `ip_fw_dynamic.c:3236 malloc(mp_ncpus * sizeof(void *), ...)`, `:2087 CPU_FOREACH(i)`. This round makes `mp_ncpus == mp_maxid + 1 == popcount(all_cpus)`, three consistent → `cached_count ≤ mp_ncpus`, **no overflow** ✓.

### 2.2 D7 thread_mode=0 zero regression —— PASS (but report wording needs correction)

`thread_mode == 0` → `nb_cpus = 1` → `mp_ncpus = 1`, `mp_maxid = 0`, `all_cpus` only bit 0, `ff_pcpu_thread_init(0)` → `pcpu_init(pcpup, 0, ...)` → `pc_cpuid = 0`, `pc_zpcpu_offset = 0`. **All four consistent with pre-change ✓**

**But `coder` report §1.3's "verbatim equivalent to pre-change" is inaccurate** (I measured 4 non-equivalent differences, and `-DSMP` itself takes effect for thread_mode=0):

1. `uma_core.c:2546-2548 #ifndef SMP keg->uk_flags &= ~UMA_ZONE_PCPU;` —— now **no longer strips** `UMA_ZONE_PCPU`. Subsequent `:2473-2474 pages *= mp_maxid + 1` (=×1), `:2577-2578 uk_allocf = pcpu_page_alloc`. Compiled is `:2084`'s **FSTACK version** `pcpu_page_alloc`, body `return page_alloc(...)` → equivalent to original path, but **not same code path**.
2. CK: `-DSMP` makes `CK_MD_UMP` invalid → `ip_fw_dynamic.c`'s `ck_pr_*` RMW gets `lock` prefix (stronger semantics, performance cost).
3. Memory: `cpuset_t` 8→128 bytes, `cpuid_to_pcpu[1024]`/`dpcpu_off[1024]`, `nws_array[MAXCPU]`, `pause_wchan[MAXCPU]`.
4. `curcpu` changes from literal `0` to memory load `pcpup->pc_cpuid`, and introduces a new NULL dereference window (see §2.15).

→ **Report must fix**: D7 is hard constraint, M5's thread_mode=0 regression criteria must be based on accurate description.

### 2.3 ⚠ Key check: thread_mode=0's `qconf->proc_id` —— round 1 was defect, round 2 fixed

**① Is this value really never used? —— Measured: indeed not, but conclusion chain narrower than `coder` report.**

- `ff_stack_inited` is `__thread` (`ff_freebsd_init.c:86`), main thread sets at **`ff_freebsd_init()`'s last line `:378`**.
- Call sequence: `ff_init()` = `ff_load_config` → `ff_dpdk_init` → `ff_freebsd_init` → `ff_dpdk_if_up`; `main_loop` by `ff_run()` → `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` starts **after**. → main thread entering `main_loop` has `ff_stack_inited == 1` → `ff_stack_thread_init()` early returns ✓
- **And thread_mode=0 has no second thread running `main_loop`**: `parse_lcore_mask()` sets `proc_mask` to **single bit** in non-thread_mode → EAL each process only 1 lcore → `rte_eal_mp_remote_launch` only runs main lcore.

**② Should add explicit protection? —— Verdict: mandatory fix (round 1), round 2 implemented.**

Reason (round 1 if not fixed): `ff_lcore_conf_idx()` in thread_mode=0 **always returns 0**, while `init_lcore_conf()` non-thread_mode branch `ff_cur_lcore_conf()->proc_id = ff_global_cfg.dpdk.proc_id;` → secondary process has `lcore_conf[0].proc_id == 1/2/…`. Once `ff_stack_inited`'s setting timing is broken by future change, `ff_pcpu_thread_init(1)` hits new `:110` upper bound check (`1 > mp_maxid==0`) and **`panic` terminates process** —— from "silently correct" to "startup hang". Unacceptable to leave fixable隐患 to future.

**Round 2 measured fixed**: `ff_dpdk_if.c:2655 ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0);` ✓ PASS.

### 2.4 D4 main thread numbering —— PASS, and "no collision" independently established

- **`rte_lcore_id()` available during `ff_freebsd_init()`**: `rte_eal_init` before `init_lcore_conf()` (`ff_dpdk_if.c:1657-1660` → `:1678`), and `ff_dpdk_init` entirely before `ff_freebsd_init` ✓
- **`lcore_conf[rte_lcore_id()].proc_id` already assigned**: thread_mode branch `ff_dpdk_if.c:435-439 for (ti=0; ti<nb_threads; ti++) { lcore_id = proc_lcore[ti]; lcore_conf[lcore_id].proc_id = ti; }` ✓
- **Can main thread's `proc_id` collide with worker? —— No.** Key is `nb_threads` always equals `lcore_mask`'s bit count:
  - `ff_config.c:139 cfg->dpdk.nb_procs = count;` (bit count); no independent `nb_procs` config entry.
  - `ff_config.c:1477-1478 nb_threads = nb_procs; nb_procs = 1;`, `:1480-1482 proc_mask = strdup(lcore_mask)`.
  → **EAL's lcore set ≡ `lcore_mask` bit set ≡ `{proc_lcore[0..nb_threads-1]}`, three identical**.
  → Main thread whichever EAL lcore (including future `--main-lcore`), must be some `proc_lcore[k]`, gets `proc_id == k` (valid dense value); each worker gets own lcore's `proc_id`, one lcore one value mutually distinct → **globally unique, no collision** ✓
  → Main thread is also "worker k" (`CALL_MAIN`), two numbering sources same, and `main_loop` early returns → **no double `pcpu_init()`, no occupying two slots** ✓

### 2.5 D5 `timeout_cpu` —— code PASS; comment mandatory fix

- `ff_kern_timeout.c:190 static __thread int timeout_cpu;` ✓ changed.
- Necessity: `:254 timeout_cpu = PCPU_GET(cpuid);` executed by each thread; `c->c_cpu = timeout_cpu` written to callout.
- **`:815 callout_schedule()`'s returned `c->c_cpu` necessarily valid**: → `:730-733` check `cpu >= MAXCPU` (1024) doesn't panic; `CC_CPU(cpu)` = `&cc_cpu` (`:184`, **ignores arg**) → returns **calling thread's own** `__thread cc_cpu`, whose `cc_inited` set by `ff_callout_thread_init()` ✓
- **Cross-thread semantics**: `:184-185 #define CC_CPU(cpu) &cc_cpu` / `#define CC_SELF() &cc_cpu` both ignore cpu arg, so `:662`/`:1181` etc. **always calling thread's own callwheel**, no cross-thread access → no new data race. Semantics is "whoever schedules owns", `c_cpu` degrades to pure record field.
- **Mandatory fix (comment)**: `ff_kern_timeout.c:180-182`'s comment is now **false statement**: `cpuid is always 0, MAXCPU=1` after G1 **both false**. And this is sole written basis for "CC_CPU ignoring arg is safe", leaving it would mislead future maintainers.

### 2.6 D6 upper bound check —— PASS

`ff_freebsd_init.c:110-112`: `if (cpuid < 0 || (u_int)cpuid > mp_maxid) panic(...)`.
- **Covers `cpuid > mp_maxid`** ✓; **covers negative** ✓ (first checks `cpuid < 0`, then `(u_int)` cast, order correct).
- This check necessary: `subr_pcpu.c:88-89 KASSERT` compiled out without `INVARIANTS`, OOB would silently corrupt `dpcpu_off[]` / `cpuid_to_pcpu[]` / adjacent `cpuhead`.
- **Is `panic` usable**: usable and correct. `ff_freebsd_init.c` already uses `panic` at `:286` (existing precedent), and this file is kernel-mode TU (`-nostdinc`), **cannot include DPDK headers** → `rte_exit()` unavailable. `panic` provided by `ff_subr_prf.c`, already linked.
- `:306-307 if (nb_cpus > MAXCPU) panic(...)`: `coder` self-assessed #7 says "actually unreachable". I agree with retaining (provides fail-loud for `MAXCPU=64` downgrade step), **not redundant**.

### 2.7 D1 / MAXCPU / `-DSMP` scope / `smp_topo` stub —— PASS

- **`-DSMP` only added in `lib/Makefile:221-223`** ✓; `git status --short freebsd/` **empty** → upstream tree zero changes.
- `MAXCPU`: `param.h:60-66`, `#ifdef SMP` → `1024`; `#else` → `1`. So `-DSMP` makes `MAXCPU` 1→1024, with `#ifndef` guard (downgrade step available) ✓
- **`-DSMP`'s actual behavior impact surface** (I independently exhausted): compile set only has 3 `.c` + several headers:
  - `kern/subr_pcpu.c:252-264` `dpcpu_copy()`: SMP branch `CPU_FOREACH` + `if (dpcpu==0) continue`; `dpcpu_off[]` always 0 → **no-op**. Non-SMP branch `memcpy(s,s,size)` → **also no-op**. Equivalent ✓
  - `vm/uma_core.c:2546/3498/3508/3526`: `:2546` no longer strips `UMA_ZONE_PCPU` (G1's prerequisite); `:3509-3510` per-slot zero ✓
  - `netinet/tcp_hpts.c:1867-1871`: `cpu_top = smp_topo()` vs `NULL` → see below
  - `sys/smp.h`, `sys/mutex.h`: function declarations only / covered by `lib/include/sys/mutex.h` ✓
  Non-SRCS therefore **unaffected** high-risk files: `kern/subr_smp.c`, `kern/kern_mutex.c`, `kern/kern_timeout.c`, `kern/kern_intr.c`, `kern/kern_synch.c`, `kern/subr_epoch.c`, `kern/init_main.c`, `kern/sched_*.c`, `kern/subr_turnstile.c`, `kern/kern_clocksource.c`, `net/iflib.c`, `netinet/sctp_*.c`, `libkern/arc4random.c`, `x86/*`, `amd64/amd64/*`.
- **`smp_topo()` stub returning NULL safety —— I independently established**: `tcp_hpts.c:1867-1871`: `#ifdef SMP cpu_top = smp_topo(); #else cpu_top = NULL; #endif` → returning NULL **verbatim equivalent to original `#else` branch** ✓; `:1889-1891 if (cpu_top == NULL) { tcp_pace.grp_cnt = 1; }` → `grp_cnt == 1`, `tcp_pace.grps` **never `malloc`**; `:1564-1572 if (tcp_pace.grp_cnt > 1)` → condition false → **`grps[]` never dereferenced** ✓; `:2026-2041` inside `#ifndef FSTACK` → **not compiled** ✓
- `ff_glue.c` landing reasonable: already `#include <sys/smp.h>` and defines `mp_ncpus`/`mp_maxid`/`all_cpus`/`smp_started`/`smp_cpus`/`smp_topology`, same symbol ownership ✓

### 2.8 Cross-TU issue —— PASS

- **Existing convention**: `ff_freebsd_init.c:49 #include "ff_host_interface.h"` —— already calls `HOST_SRCS`'s `ff_host_interface.c` functions; `ff_glue.c:77`, `ff_kern_synch.c:56` same. `ff_glue.c:1067-1083 malloc()` calling `ff_malloc()` is typical example. So "kernel-mode TU calling host TU functions" is **existing architecture convention**, this change opens no new paradigm ✓
- **Does `-DSMP` only affecting `SRCS` not `HOST_SRCS` cause inconsistency —— measured no**:
  - `MAXCPU` / `cpuset_t` **do not appear in `ff_cur_proc_id()`'s signature** (`int (void)`) ✓
  - I grepped all `HOST_SRCS` for `cpuset_t|MAXCPU` → **zero hits** ✓
  - `HOST_INCLUDES = -I.` (`lib/Makefile:78`), host TU **doesn't see `freebsd/sys/*.h`** ✓
  - `struct lcore_conf` (`ff_memory.h:60-95`) has no `cpuset_t`, no `[MAXCPU]` array ✓

### 2.9 lib minimal comment convention —— mostly PASS, 1 mandatory + 1 suggestion

**Mandatory (1)**: `ff_kern_timeout.c:180-182`'s stale comment —— see §2.5. Hard convention (wrong comments more harmful than no comments), and `coder` didn't address in two rounds.

**Suggested simplification (1)**: `ff_freebsd_init.c:319-323` (4 lines) can compress to 2 lines: `/* Main thread is itself an EAL lcore worker (CALL_MAIN), so it takes its own dense slot; thread_mode=0 has one stack per process -> slot 0. */`

**Judged as "necessary, should keep"**: `lib/Makefile:221-222` (2 lines, `-DSMP`'s motivation non-intuitive), `ff_freebsd_init.c:73` (1 line, cross-TU `extern` semantics), `ff_freebsd_init.c:98-102` (3 lines, upper bound check necessity), `ff_freebsd_init.c:309-313` (4 lines, `uma_startup1` timing constraint), `ff_glue.c:172` (1 line, caller must handle NULL). Round 2 already compressed `ff_pcpu_thread_init`'s comment from 8 to 3 lines ✓.

### 2.11 DoD-1 verifiability —— **FAIL: coder must add temp probe**

Current code has **no** means to print `pc_zpcpu_offset` / `pc_cpuid` (full `lib/` grep `pc_zpcpu_offset` zero hits), M5 `tester` cannot verify DoD-1.

**I first made DoD-1's static side solid**:
- `subr_pcpu.c:97 pcpu->pc_zpcpu_offset = zpcpu_offset_cpu(cpuid);`, `sys/pcpu.h:235 #define zpcpu_offset_cpu(cpu) (UMA_PCPU_ALLOC_SIZE * cpu)`, `:221 #define UMA_PCPU_ALLOC_SIZE PAGE_SIZE` → **`pc_zpcpu_offset == 4096 * cpuid` holds by code** ✓
- **UMA per-cpu zone indeed allocates `(mp_maxid+1) × 4096`** (I established): `uma_core.c:2472-2476`: `pages = atop(kl.slabsize); if (UMA_ZONE_PCPU) pages *= mp_maxid + 1; keg->uk_ppera = pages;` → PCPU keg's `uk_ppera = mp_maxid+1` pages ✓
- **`coder`'s U2 question (compiled is `:1959` or `:2084`'s `pcpu_page_alloc`) I concluded: it's `:2084`'s FSTACK version**. `:1958`'s upstream version inside `#ifndef FSTACK`. FSTACK version body `return page_alloc(...)`. **Important byproduct**: upstream version `:1982 pc = pcpu_find(cpu)` (inside `#ifdef NUMA`) **not compiled**, so no "boot-time calling `pcpu_find()` on not-yet-created worker slots → NULL dereference" risk ✓

**Still need coder to add temp probe**:
1. **At `ff_freebsd_init.c`'s `ff_pcpu_thread_init()` end** (kernel TU, `printf` available): `printf("[G1probe] tid=%lu cpuid=%d zpcpu_off=%zu mp_ncpus=%d mp_maxid=%u\n", ...);` → directly covers DoD-1 "each worker `pc_zpcpu_offset == 4096*dense_idx` and distinct".
2. **At `ff_dpdk_if.c`'s `main_loop()` after `ff_stack_thread_init()` call** (host TU, DPDK API available): `printf("[G1probe] lcore=%u main_lcore=%u proc_id=%d\n", rte_lcore_id(), rte_get_main_lcore(), qconf->proc_id);` → covers U6-a and §2.4's "no collision" runtime confirmation.
3. **UMA cache isolation (DoD-1 criterion ⑤)**: suggest printing at `ff_stack_thread_init()` end any known pcpu zone's `&zone->uz_cpu[curcpu]` address.

Probe must be **temporary**, removed by `coder` after M5 and clean build re-run.

### 2.12 Concurrency/memory risk —— PASS

`subr_pcpu.c:84-98 pcpu_init()`'s global writes: `:91 cpuid_to_pcpu[cpuid] = pcpu;`, `:92 STAILQ_INSERT_TAIL` (both non-atomic).
- **Worker path protected by `init_lock`** ✓: `ff_freebsd_init.c:183 static volatile int init_lock = 0;`, `:193-194 while (__sync_lock_test_and_set(&init_lock, 1)) ;`, `:195 ff_pcpu_thread_init(cpuid);`, `:224 __sync_lock_release(&init_lock);` —— `pcpu_init` strictly within critical section.
- **Main thread path completes before any worker** ✓: main thread's `ff_pcpu_thread_init()` at `ff_freebsd_init():324`, no lock; but worker threads created by `ff_run()` → `rte_eal_mp_remote_launch()`, **after `ff_init()` returns** → main thread writing `cpuid_to_pcpu[k]` has no concurrent writer. No lock is safe.

### 2.13 `curcpu` per-thread-ization —— PASS

`lib/include/sys/pcpu.h` final state (diff measured): `#include_next <sys/pcpu.h>` / `#undef curcpu` / `-#define curcpu 0` / `+#define curcpu PCPU_GET(cpuid)`.
- **`#undef curcpu` retained** ✓ —— otherwise would conflict with upstream `freebsd/sys/pcpu.h:218`. Note: after this round's change both are **text-identical**, even if `#undef` missed it's just benign redefinition, but retaining is correct.
- `PCPU_GET(member)` = `(pcpup->pc_ ## member)` (`lib/include/amd64/include/pcpu.h:49`) → `curcpu` = `pcpup->pc_cpuid`, per-thread ✓
- **This change's necessity I independently confirm**: `uma_core.c`'s 11 `cache = &zone->uz_cpu[curcpu];` **don't go through `zpcpu_get()`**, so dense `pc_cpuid` alone cannot isolate UMA per-cpu cache. `designer`'s §2.3/§4.5 conclusion holds.
- My clean build (13:58) **already includes** this change, no new warnings ✓

### 2.14 `curcpu` all usage points OOB recheck —— PASS (no OOB), but 2 semantic changes unrecorded

I grep'd `curcpu` exhaustively across `lib/` and `freebsd/{kern,net,netinet,netinet6,netpfil,netgraph,vm,libkern}`, cross-filtered with `lib/Makefile` SRCS. **Compile set's `curcpu` usage points complete list (8 files / 19 spots)**:

| Location | Index object and size | OOB verdict |
|---|---|---|
| `lib/ff_kern_synch.c:105` | `pause_wchan[curcpu]`, `:59` size `MAXCPU`=1024 | **safe**; but NULL risk, see §2.15 |
| `freebsd/vm/uma_core.c` ×11 (`:1452,3738,3776,3818,3901,4534,4543,4595,4628,4803,4853`) | `zone->uz_cpu[curcpu]`, flexible array, size `mp_maxid+1` | **safe** (`curcpu ≤ mp_maxid`, guaranteed by `:110` upper bound check) ✓ |
| `freebsd/netinet/tcp_hpts.c:1587` | `rp_ent[curcpu % rp_num_hptss]` | **safe** (modulo); `rp_num_hptss = ncpus` = N > 0 ✓ |
| `freebsd/netinet/tcp_hpts.c:1566` | `CPU_ISSET(curcpu, &grps[i]->cg_mask)` | **unreachable** (`grp_cnt` always 1) ✓ |
| `freebsd/netinet/tcp_timer.c:237,249` | `return (curcpu);` | **safe** (return ≤ `mp_maxid`, consumer modulo/ignores) ✓ |
| `freebsd/netinet/tcp_lro.c:1210,1216` | `lc->lro_last_cpu == curcpu` / assignment | **safe** (pure comparison/record, no index) ✓ |
| `freebsd/net/netisr.c:839` | `netisr_get_cpuid(curcpu)` → `nws_array[cpunumber % nws_count]` | **safe** (modulo); but see "semantic change A" |
| `freebsd/net/netisr.c:1172` | `if (cpuid != curcpu) goto queue_fallback;` | no index; but see "semantic change A" |
| `freebsd/kern/subr_taskqueue.c:368` | `callout_reset_sbt_curcpu(...)` | **unverified as `curcpu` evaluation point** (macro definition not found in `callout.h`); **doesn't constitute OOB risk** (`:730` has `cpu >= MAXCPU` fallback + `CC_CPU` ignores arg) |

**Not compiled** (verified one by one not in SRCS): `kern/sched_ule.c`, `kern/subr_intr.c`, `kern/kern_timeout.c`, `kern/kern_clock.c`, `kern/init_main.c`, `kern/kern_synch.c`, `kern/subr_epoch.c`, `kern/kern_clocksource.c`, `kern/kern_time.c`, `kern/vfs_subr.c`, `kern/subr_smp.c`, `net/iflib.c`, `netinet/tcp_lro_hpts.c`, `libkern/arc4random.c`.

**Semantic change A (new finding, suggest record in spec known risk) —— netisr HYBRID policy's queue fallback**
- Default path **unaffected**: `netisr.c:151` defaults `NETISR_DISPATCH_DIRECT`, `:787-789` returns DIRECT → `:1146-1153` unconditionally direct dispatch, **`:839`/`:1172`'s `curcpu` unreachable** ✓
- **But `net.isr.dispatch` is adjustable sysctl** (`:155-157`). If set to `hybrid`: `:810-811 if (nws_count == 1) *cpuidp = nws_array[0];` → for worker N≠0, `:1172 cpuid != curcpu` **holds** → `goto queue_fallback` → netisr queue path, and f-stack's swi is empty stub → **packets queued but no handler**.
- Before change `curcpu ≡ 0 == nws_array[0]` → always equal → direct dispatch, **never hits**. So this is `curcpu` per-thread-ization's **newly introduced** conditional risk.
- Suggest: spec explicitly state "`net.isr.dispatch` must stay `direct`, must not set `hybrid`/`deferred`".

**Semantic change B (new finding, suggest record in spec + M5 observation) —— `tcp_hpts` instance count 1 → N**
`tcp_hpts.c:1864 ncpus = mp_ncpus ? mp_ncpus : MAXCPU` → `:1872 rp_num_hptss = ncpus`. Before change `mp_ncpus==1` → 1 hpts; now **N**. `:1921-2000` allocates each i a `tcp_hpts_entry` + `p_hptss` and `callout_init`; `:2048-2050 callout_reset_sbt_on`.
- Memory: per-hpts `p_hptss` array × N, worth M5 quantifying (`FF_TCPHPTS=1` default on).
- Semantics: `tcp_hpts_init()` executed by **main thread** during `mi_startup()` → N callouts all on **main thread's `__thread cc_cpu` callwheel** (`CC_CPU` ignores arg); while `__tcp_run_hpts()` → `:1587 rp_ent[curcpu % N]` selected by **each worker** → "worker N driven hpts entry, its callout belongs to main thread callwheel" misattribution. `hpts->p_mtx` is `MTX_DEF` and f-stack all `mtx` are `((void)0)` → **no real mutual exclusion**. Currently CM5-B's Giant serialization masks this, but this is CM6/CM7 lock-shrinking's明确 risk point, suggest R6.

### 2.15 `pcpup == NULL` evaluating `curcpu` —— **FAIL: 1 mandatory (1 line)**

**"Chicken-and-egg" main path: excluded (I independently re-verified)**
- `ff_glue.c:1067-1083 malloc()` body directly `alloc = ff_malloc(size);`, **not via UMA** ✓
- `freebsd/kern/kern_malloc.c` **not in SRCS** (`grep -c kern_malloc lib/Makefile` = **0**) ✓
- So `ff_pcpu_thread_init():114 malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO)` won't reach `uz_cpu[curcpu]` ✓
- Statements before `ff_pcpu_thread_init()` have no `curcpu`/`PCPU_GET` ✓
- `uma_startup1()` at `:331`, after `:324` ✓; `kmem_malloc` at `:329`, also after ✓

**Residual edge: does exist, judged "mandatory fix"**
- Path: `ff_glue.c:1076 pause("malloc", hz/100)` → `ff_kern_synch.c:105 return (_sleep(&pause_wchan[curcpu], ...));` → evaluate `curcpu` = `pcpup->pc_cpuid`, **`pcpup == NULL` segfaults**.
- Trigger condition: `ff_malloc()` returns NULL and `M_WAITOK`, and within window where `pcpup` still NULL —— i.e. `ff_freebsd_init():284-298`'s `kern_setenv` series, or `ff_pcpu_thread_init():114`'s own malloc; and **D9 scenario: app threads created by `ff_pthread_create()`** (never call `ff_pcpu_thread_init`) reaching any `pause()`/UMA path.
- **Divergence from leader's initial judgment (my independent judgment)**: leader thinks "today `curcpu==0` also reaches an unreasonable wchan, is existing fragility". I verified **different nature**: before change `curcpu` is **literal 0**, `&pause_wchan[0]` is valid address, `_sleep` returns normally, retry loop works → **original code works correctly in this edge**; after change becomes **deterministic segfault**. This is round-2 `curcpu` change's **newly introduced usability regression**, not existing fragility.
- Severity: **P2 (mandatory, non-blocking)**. Trigger probability low (OOM / D9 unsupported usage), but fix cost 1 line, no side effects, and it turns "graceful retry" into "crash", violates least surprise.
- **Minimal fix (recommended)**: `lib/ff_kern_synch.c:105` → `return (_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], NULL, 0, wmesg, sbt, pr, flags));` (1 line; `pcpup` defined at `ff_freebsd_init.c:89`, `ff_kern_synch.c` needs `extern __thread struct pcpu *pcpup;` or via `sys/pcpu.h`).
- Regarding spec's "no fallback, fail-fast" verdict: **for D9 (app thread misusing `ff_*`) I agree with fail-fast** —— NULL dereference there immediately exposes unsupported usage, better than silently sharing slot 0. **But `pause()` OOM retry path doesn't apply**: that's not "misuse", it's normal code's normal branch under pressure. Suggest verdict refined to "D9 misuse fail-fast; but internal bootstrap-period `pause()` add minimal fallback".

### 2.16 Intermediate state self-consistency (`curcpu` per-thread + `uma_crit_lock` still present) —— PASS

- Current state: `lib/include/vm/uma_int.h:45-52`'s `uma_crit_lock` global spinlock **still present**, G2 not implemented ✓
- Self-consistency derivation:
  - Before change = "all threads share `uz_cpu[0]` **+** global lock serializes" → data structure integrity **completely depends on** this global lock.
  - Now = "each thread exclusively owns `uz_cpu[cpuid]` **+** global lock still serializes" → both isolation and serialization, **strictly safer**, introduces no new contention.
  - Future G2 = "exclusive slots **-** global lock" → slot isolation becomes **sole** protection.
  → Therefore **G1 (including `curcpu` per-thread) is G2's hard prerequisite**: if G2 done first while `curcpu` still 0, would put back `b90ddcba5`'s fixed crash. `designer`'s §4.5 conclusion I re-verified holds.
- Conclusion: intermediate state **self-consistent, can safely enter M5 runtime verification** (safer but still serialized) ✓
- Incidental (`coder` self-assessed risk #3): `smp_started`/`smp_cpus` not synced —— I exhausted its consumers, **only hit is `ff_glue.c:217 active = smp_started;`** (sysctl handler) and `:165`'s SYSCTL declaration, i.e. **pure `kern.smp.active` display value**, no functional consumers → **judged no change needed**.

---

## 3. clean build measured numbers (I executed, not citing coder)

**Command (strict `make clean` first, no incremental)**:
```
cd /data/workspace/f-stack/lib     && make clean && make -j16
cd /data/workspace/f-stack/example && make clean && make
```

### 3.1 `lib/`

| Metric | My measured | Threshold | Verdict |
|---|---|---|---|
| `make clean` return code | 0 | — | — |
| `make` return code | **0** | 0 | PASS |
| `grep -c "error:"` | **0** | 0 | PASS |
| `grep -c "warning:"` | **51** | ≤ 51 (HEAD baseline) | PASS (zero new) |
| `.o` count | **248** | 248 | PASS |
| `libfstack.a` | generated, **7,002,076** bytes | generated | PASS |

### 3.2 `example/`

| Metric | My measured | Verdict |
|---|---|---|
| `make clean` return code | 0 | — |
| `make` return code | **0** | PASS |
| `grep -c "error:"` | **0** | PASS |
| `grep -c "undefined reference"` | **0** | PASS (`smp_topo` is only new symbol, supplemented) |
| `grep -c "warning:"` | **0** | PASS |
| `helloworld` | generated, **30,392,672** bytes | PASS |
| `helloworld_epoll` | generated, **30,386,072** bytes | PASS |

### 3.3 Differences from coder's numbers (explained, not issue)

`libfstack.a`: mine 7,002,076 vs coder 7,003,932 (−1,856); `helloworld`: mine 30,392,672 vs coder 30,392,712 (−40).
Reason: coder's numbers from **round 1** (`curcpu` still `0`), mine from **round 2** (`curcpu` = `PCPU_GET(cpuid)`). `curcpu` changing from literal to memory load changes 11 UMA hot path codegen. **Difference direction and magnitude reasonable, and error/warning/`.o` count three fully consistent** → considered consistent ✓

Temp logs cleaned via `/data/workspace/rm_tmp_file.sh`.

---

## 4. Mandatory fix list (sorted by severity)

> No FAIL-level (blocking M5) defects. All 4 below can be fixed before or parallel with M5.

| # | Level | Location | Issue | Suggested fix |
|---|---|---|---|---|
| **M1** | P2 · usability regression | `lib/ff_kern_synch.c:105` | `pause_wchan[curcpu]` **deterministic segfault** when `pcpup == NULL` (before change was valid `pause_wchan[0]`). Covers bootstrap-period OOM retry and D9 app threads | `&pause_wchan[pcpup != NULL ? curcpu : 0]` (1 line) |
| **M2** | P2 · stale comment (hard convention) | `lib/ff_kern_timeout.c:180-182` | comment still says `cpuid is always 0, MAXCPU=1` —— after G1 **both false**, sole written basis for "CC_CPU ignoring cpu arg is safe" | Change to: `/* Per-thread callout_cpu: CC_CPU/CC_SELF ignore the cpu arg and always return the calling thread's own callwheel. */` (2 lines) |
| **M3** | P2 · doc accuracy | `_m17_E_coder_g1.md` §1.3 | "thread_mode=0 **verbatim equivalent**" doesn't hold. Measured 4 non-equivalent differences. D7 is hard constraint, M5 regression criteria would miss test items | Change to "**logical value equivalent** (`mp_ncpus=1`/`mp_maxid=0`/`all_cpus`=bit0/slot 0/`zpcpu_offset=0`), but 4 non-equivalent differences exist, M5 needs regression" |
| **M4** | P2 · blocks DoD-1 verification | `lib/ff_freebsd_init.c` `ff_pcpu_thread_init()` + `lib/ff_dpdk_if.c` `main_loop()` | Currently **no** means to print `pc_zpcpu_offset`/`pc_cpuid`, M5 `tester` cannot verify DoD-1 | Add **temporary** probes per §2.11's 3 items, remove after M5 and rerun clean build |

## 5. Suggested fixes (non-blocking)

| # | Location | Content |
|---|---|---|
| S1 | spec known risk + `ff_config.c` validation (optional) | **netisr HYBRID fallback risk**: if `net.isr.dispatch` set to `hybrid`/`deferred`, worker N≠0 goes `queue_fallback` while f-stack swi is empty stub → packets unhandled. Default `direct` unaffected. Suggest spec list as unsupported config |
| S2 | spec residual risk list (suggest R6) | **`tcp_hpts` instance count 1→N**: N hpts entries + N `p_hptss` arrays (memory); N callouts all on **main thread** callwheel, while `rp_ent[curcpu % N]` selected by each worker → CM6/CM7 Giant-shrinking risk point |
| S3 | spec known deviation | `kern.smp.active` still reports 0 (`smp_started`/`smp_cpus` not synced). I exhausted confirmed **no functional consumers**, display deviation only, **code no change needed** |
| S4 | spec D2 strengthen wording | D2's consequence beyond "heap overflow": `uma_int.h:528-529 ZDOM_GET` uses `uz_cpu[mp_maxid+1]` → `mp_maxid` changed after `uma_startup1()` would make `uz_cpu[]` and `zdom[]` **region overlap** |
| S5 | `lib/ff_freebsd_init.c:319-323` | 4-line comment can compress to 2 lines (§2.9) |
| S6 | D9 verdict refinement | "no fallback, fail-fast" valid for D9 misuse; but shouldn't cover internal bootstrap-period `pause()` retry path (see M1) |

## 6. Unverified boundary (honest record)

1. **All runtime behavior unverified**: I only did static code review + clean build. "Each worker `pc_zpcpu_offset` distinct", "UMA per-cpu zone actually allocates `(mp_maxid+1)×4096`", "EAL main lcore and `proc_lcore[0]` actual relationship (U6-a)" all need M5 measurement.
2. **`subr_taskqueue.c:368 callout_reset_sbt_curcpu`'s macro definition location unverified**: I grepped zero hits in `callout.h`. Argued it doesn't constitute OOB risk (`:730` has `cpu >= MAXCPU` fallback + `CC_CPU` ignores arg), but macro source unlocated.
3. **`-DSMP`'s impact surface I exhausted via "SRCS cross-filter", but didn't `cc -E` verify each of 238 TUs' preprocessing**.
4. **Performance overhead unquantified**: CK RMW's `lock` prefix, `curcpu` from constant to memory load, `MAXCPU=1024`'s BSS/heap growth, `tcp_hpts`×N —— all pending M5 baseline.
5. **Build targets outside `example/` unverified** (e.g. `tools/`, `tests/unit/`). Task only required `lib` + `example`.
6. **`config.ini`'s ` M` state I didn't check content** (per convention don't touch), but need remind leader: before M7 commit must review `git diff config.ini` per AI memory 44404940, remove local test values.

---

## 7. Conclusion

# **PASS-with-fixes**

- **Mandatory fixes: 4** (M1 segfault edge / M2 stale comment / M3 report "verbatim equivalent" wording / M4 DoD-1 probe missing), all **P2**, no FAIL-level defects.
- **Suggested fixes: 6** (S1~S6, mainly spec semantic changes and residual risks to record).
- **Blocks M5 runtime verification: No.** D1~D7, D9 all satisfied; `-DSMP`'s behavior impact surface exhausted and controllable; clean build independently reproduced by me (`lib` error 0 / warning 51 / 248 `.o` / `libfstack.a` 7,002,076B; `example` error 0 / undefined 0 / `helloworld` 30,392,672B).
- **Sole prerequisite**: **M4 (temp probe) must land before M5 starts**, otherwise `tester` cannot verify DoD-1 criteria, M5 becomes weak "didn't crash = pass" verification. M1/M2/M3 can fix parallel with M5.

---

## 8. Supplemental review: `coder` round 3 (DoD-1 probe) —— received after this report landed, re-reviewed

Round 3 landed at **14:01:42 ~ 14:02:17** (after my §3 build at 13:58), adding `lib/ff_host_interface.c` +8 / `lib/ff_host_interface.h` +4, `lib/ff_freebsd_init.c` from +36/-10 to **+67/-10**. **Content is exactly my mandatory M4 (DoD-1 probe).**

### 8.1 Probe content and landing recheck —— PASS

| Probe | Location | Print fields | Verdict |
|---|---|---|---|
| `[M17-PROBE]` | `ff_freebsd_init.c:114-119` (`ff_pcpu_thread_init()` end) | `tid` / `dense_idx` / `pc_cpuid` / `pc_zpcpu_offset` / `mp_ncpus` / `mp_maxid` / `curcpu` | **Fully covers DoD-1 main criteria** ✓ better coverage than my §2.11 suggestion (added `pc_cpuid` and `curcpu` for cross-check) |
| `[M17-PROBE-SLOT]` | `ff_freebsd_init.c:122-137` defined; called at `:245` (worker) and `:404` (main) | `dense_idx` / `zpcpu_get(V_tcbinfo.ipi_smr)` / `&V_tcbinfo.ipi_zone->uz_cpu[curcpu]` | **Covers DoD-1 criterion ⑤ (UMA cache isolation) + SMR slot isolation** ✓ more direct than my suggestion |
| `ff_probe_tid()` | `ff_host_interface.c:152-158` (host TU), prototype `ff_host_interface.h:51-53` | `(uint64_t)pthread_self()` | Landing correct (kernel TU can't get `pthread_self`, uses existing host accessor convention) ✓ |

**Timing safety (my key risk check) —— measured safe**: `ff_probe_slots()` touches `V_tcbinfo` (VIMAGE via `curthread->td_vnet` dereference). Measured both call sites after `td_vnet` ready:
- worker path: `ff_pcpu_thread_init` `:215` → `ff_init_thread0()` `:223` → `curthread->td_vnet = v` `:238` → **probe `:245`** ✓
- main path: `ff_pcpu_thread_init` `:347` → `ff_init_thread0()` `:349` → `mi_startup()` `:362` → `curthread->td_vnet = vnet0` `:370` → **probe `:404`** ✓
- `[M17-PROBE]` printf only uses `pcpup` (just built) and ordinary globals, **doesn't touch `curthread`/vnet** ✓
- Both probes wrapped in `#if 1 /* M17 temporary probe ... remove after M5 */`, removal points clear ✓

### 8.2 Round 3 clean build (I re-executed, covering probe)

| Metric | Round 3 measured | Threshold | Verdict |
|---|---|---|---|
| `lib` `make` return code | **0** | 0 | PASS |
| `lib` `grep -c "error:"` | **0** | 0 | PASS |
| `lib` `grep -c "warning:"` | **51** | ≤ 51 | PASS (zero new) |
| `lib` `.o` count | **248** | 248 | PASS |
| `libfstack.a` | **7,003,564** bytes | generated | PASS |
| `example` `make` return code | **0** | 0 | PASS |
| `example` `error:` / `undefined reference` | **0** / **0** | 0 | PASS |
| `helloworld` | **30,392,704** bytes | generated | PASS |

Temp logs cleaned via `/data/workspace/rm_tmp_file.sh`.

### 8.3 Mandatory fix status update (as of 14:09)

| # | Status | Basis |
|---|---|---|
| **M4** (DoD-1 probe) | ✅ **fixed** | Round 3 landed + my re-review PASS + clean build PASS (§8.1/§8.2) |
| **M3** (report "verbatim equivalent" wording) | ⚠️ **pending recheck** | `_m17_E_coder_g1.md` mtime 14:06:09, not verbatim checked yet |
| **M1** (`ff_kern_synch.c:105` NULL deref) | ❌ **not fixed** | `lib/ff_kern_synch.c` mtime still **2026-03-20 18:48:54** (never touched this round) |
| **M2** (`ff_kern_timeout.c:180-182` stale comment) | ❌ **not fixed** | `lib/ff_kern_timeout.c` mtime still **13:38:19** (round 1 timestamp, comment untouched) |

### 8.4 Conclusion unchanged: **PASS-with-fixes**, and **doesn't block M5**

- Original "sole prerequisite before M5 start" (M4) **lifted** → **M5 runtime verification can start immediately**.
- Remaining **M1 / M2** (1~2 lines each) + **M3** (doc wording) can fix parallel with M5, don't block.
- New reminder: after M5 `coder` must remove both `#if 1 /* M17 temporary probe */` probes and `ff_probe_tid()` (incl. `.h` prototype), and **rerun clean build** confirming return to error 0 / warning 51 / 248 `.o`.

---

## 9. Re-review (bounce 3): M3 gate final conclusion

> bounce count reached **3/3 limit**, so this section strictly distinguishes "**blocking items**" from "**non-blocking residual risks**", only truly blocking ones are FAIL.
> Re-review baseline: `git diff` final state, `lib/ff_freebsd_init.c` mtime **14:52:12**, `_m17_E_coder_g1.md` mtime **14:54:33**; `git status --short freebsd/` still **empty** (upstream tree zero changes).

### 9.1 Crash fix (`uma_page_slab_hash` advance) —— PASS, and I judge the fix **safe and thorough**

**Root cause chain I independently re-verified, holds** (leader's analysis correct, only one line offset):
- `uma_core.c:2485-2491` (leader noted `:2486-2492`, **actual 2485-2491**, offset 1): `if ((keg->uk_flags & UMA_ZFLAG_OFFPAGE) != 0 || (keg->uk_ipers - 1) * rsize >= PAGE_SIZE) { ... keg->uk_flags |= UMA_ZFLAG_VTOSLAB; }`
- `uma_core.c:1821-1824` (inside `keg_alloc_slab()`, guarded by `UMA_ZFLAG_VTOSLAB`): `for (i = 0; i < keg->uk_ppera; i++) vsetzoneslab((vm_offset_t)mem + (i * PAGE_SIZE), zone, slab);`
- `lib/include/vm/uma_int.h:104-107`: `vsetzoneslab()`'s first line is `hash_list = &uma_page_slab_hash[UMA_PAGE_HASH(va)];` → `uma_page_slab_hash == NULL` **immediately NULL derefs** ✓ consistent with `tester`'s stack (`uma_startup1 → zone_alloc_item → zone_import`).

#### ① `kmem_malloc` available at this point —— holds, with stronger basis

`lib/ff_glue.c:1032-1039`: `kmem_malloc` **directly goes through host `ff_mmap`, not via UMA, doesn't read `uma_page_slab_hash`** ✓ So it's available at any point before UMA bootstrap. Stronger than leader's positional precedent: **it's implementation-level dependency-free**. Also: `vsetzoneslab()`'s internal hash insert uses `malloc(sizeof(*up), M_DEVBUF, M_WAITOK)` → `ff_glue.c:1067`'s `malloc` → `ff_malloc`, **also doesn't recurse into UMA** → fix has no self-recursion risk ✓

#### ② After advance, only improves never worsens —— holds

| Window | Before change | After change |
|---|---|---|
| `mp_maxid == 0` (thread_mode=0) | `VTOSLAB` never set → **never touches** hash table → NULL table harmless | Table ready but equally **never touched** → **behavior verbatim equivalent, D7 zero regression unaffected** ✓ |
| `mp_maxid >= 2` | `VTOSLAB` set → `uma_startup1()`'s `vsetzoneslab()` → **NULL deref crash** | Table ready → normal insert ✓ |

→ One-way improvement, no "worsening" path. **And I confirm this fix doesn't affect thread_mode=0's zero-regression conclusion** (§2.2 still holds).

#### ③ Is there any path calling `vsetzoneslab` before hash table init —— **fix thorough**

- Full tree exhaustive: `uma_page_slab_hash`'s **only write point is 1** (`ff_freebsd_init.c:381`); **read points only in** `lib/include/vm/uma_int.h`'s 3 inlines (`vtoslab`/`vtozoneslab`/`vsetzoneslab`).
- These 3 inlines' **actual callers in compile set are only `uma_core.c`**: `:1824 vsetzoneslab`, `:4930 vtoslab`, `:5819 vtoslab`. All are UMA runtime, **necessarily after `uma_startup1()`** (`:385-387`).
- New position (`:379-383`) **before** statements checked item by item **none reach UMA**: `kern_setenv` (→ host `malloc`), `physmem` assignment, triple setting, `ff_pcpu_thread_init()` (→ host `malloc` + `printf`), `ff_init_thread0()` (function body only `pcurthread = &thread0;`).
- Between new position and `uma_startup1()` only `boot_pages` / `bootmem = kmem_malloc(...)` (host mmap).
→ **No path calls `vsetzoneslab` before hash table init, fix thorough** ✓

**Incidental new finding (good news, no action needed)**: f-stack's override `vtozoneslab()` (`lib/include/vm/uma_int.h:91-102`) has `LIST_FOREACH` then **dereferences `*slab = up->up_slab` without checking `up != NULL`**. I worried `VTOSLAB` now being set would make it reachable, so exhausted its callers: **only `freebsd/kern/kern_malloc.c:943/1039/1136`, and `kern_malloc.c` not in SRCS** (`grep -c kern_malloc lib/Makefile` = **0**) → that function is **dead code, zero risk**, no new exposure this round.

#### ④ `sizeof(struct uma_page)` vs `struct uma_page_head` type mismatch —— **judgment: don't touch this round (agree with leader), but give definitive conclusion**

Measured both structs (`lib/include/vm/uma_int.h:67-74`):
- `struct uma_page` = `LIST_ENTRY` (2 pointers =16B) + `vm_offset_t` (8) + `uma_slab_t` (8) + `uma_zone_t` (8) = **40 B**
- `struct uma_page_head` = `LIST_HEAD` (1 pointer `lh_first`) = **8 B**

→ Actually allocates `40 × 8192 = 327,680 B`, actually needs `8 × 8192 = 65,536 B` → **over-allocates 5x**.

**Conclusion: this is "over-allocate" not "under-allocate", so purely memory waste (~256 KB / per stack instance), no OOB or correctness risk.** This behavior is verbatim-moved existing writing. **Not fixing this round is correct**: ① no correctness risk; ② mixing with crash fix in same change would confuse concerns; ③ independent tech debt. **Suggest recording as residual risk R-a** (fix: `sizeof(struct uma_page_head)`; note at multi-instance 256KB×N, worth fixing in thread_mode=1).

### 9.2 Mandatory 1 (`pause_wchan` fallback) —— PASS, implementation correct

`lib/ff_kern_synch.c:102-108`:
```c
    /* Reachable from malloc()'s OOM retry before this thread has a pcpu. */
    return (_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], NULL, 0, wmesg,
        sbt, pr, flags));
```
- **Semantic equivalence** ✓: when `pcpup != NULL` takes `curcpu` (= `pcpup->pc_cpuid`), consistent with original; when NULL falls back to slot 0, restoring pre-change valid behavior.
- **`pcpup` declaration acquisition legal** ✓: `lib/include/amd64/include/pcpu.h:45 extern __thread struct pcpu *pcpup;` —— same declaration source as `curcpu`/`PCPU_GET` (`:49`), visible via `<sys/param.h>`/`<sys/proc.h>` → `<sys/pcpu.h>` → `machine/pcpu.h` chain. **No new include, none needed** (this file already uses `curcpu`, i.e. already depends on same declaration).
- **No new warning** ✓: clean build warning count still **51** (§9.5).
- Comment 1 line, explains "why reachable" (non-obvious), compliant with minimal comment convention ✓.

### 9.3 Mandatory 2 (stale comment) —— PASS; §2.9 suggested simplification also handled

- `lib/ff_kern_timeout.c:180-182` changed to: `/* Per-thread callout_cpu: each stack instance drives its own callwheel. CC_CPU/CC_SELF ignore the cpu arg and return the calling thread's own instance, so c_cpu is only a record of which thread armed the callout. */` → Deleted `cpuid is always 0, MAXCPU=1` two false statements, and added accurate semantics of `c_cpu` degrading to "records who armed callout" —— **consistent with my §2.5's measured conclusion** ✓
- **§2.9 suggested simplification of `ff_freebsd_init.c:319-323` (4 lines) compressed to 2 lines** ✓: `/* Main thread is itself an EAL lcore worker (CALL_MAIN), so it takes its own dense slot; thread_mode=0 has one stack per process -> slot 0. */`
- New comment recheck: `ff_kern_synch.c` 1 line (necessary), `ff_freebsd_init.c:376-380` hash table advance 5 lines (explains highly non-intuitive `VTOSLAB` trigger chain and rigid timing, **necessary, keep**), `ff_probe_pcpu_zone`'s U2 explanation 5 lines (temp probe code, removed with probe, acceptable). **Comment convention: PASS.**

### 9.4 Probe re-review (leader's 3 sub-questions)

#### ① Probe doesn't change any control flow —— confirmed

- `[M17-PROBE]` (`ff_freebsd_init.c:114-119`): pure `printf`, only reads `pcpup`/`cpuid`/`mp_ncpus`/`mp_maxid`/`curcpu` and host-side `ff_probe_tid()`. **No branch, no assignment, no return value effect** ✓
- `ff_probe_slots()` (`:122-137`): two local vars + two `if (... != NULL)` **only for self-read protection**, doesn't affect caller; end `printf` ✓
- `ff_probe_pcpu_zone()` (`:139-163`): local array + `continue` skipping NULL zone/keg, pure read `uk_ppera`/`uk_rsize` ✓
- 3 call sites all statement-level insertion, **doesn't change any existing statement's order or condition** ✓

#### ② Evidence validity —— **object acquisition correct, but two fields' "stride" differ, `tester` criteria must be per-field** (this section's key)

Object selection **correct**:
- `zpcpu_get(V_tcbinfo.ipi_smr)` = `base + pcpup->pc_zpcpu_offset` → directly proves **SMR per-cpu slot isolation**;
- `&V_tcbinfo.ipi_zone->uz_cpu[curcpu]` → directly proves **UMA per-cpu cache slot isolation**, i.e. the gap `designer` §2.3/§4.5 pointed out that G1 round 1 missed ✓ taking exactly that gap itself.

**⚠ But `uz_cpu[]`'s stride is `sizeof(struct uma_cache)`, not `UMA_PCPU_ALLOC_SIZE`.** I established via `tester`'s measured logs (same 4-thread run):

| dense_idx | `pc_zpcpu_offset` | `smr_c_seq` | `uma_cache` |
|---|---|---|---|
| 0 (main) | 0 | `0x7f861477fc80` | `0x7f8614758980` |
| 1 | 4096 | `0x7f8614780c80` | `0x7f8614758a00` |
| 2 | 8192 | `0x7f8614781c80` | `0x7f8614758a80` |
| 3 | 12288 | `0x7f8614782c80` | `0x7f8614758b00` |
| **adjacent diff** | **+4096** | **+0x1000 = 4096** | **+0x80 = 128** |

→ `smr_c_seq` stride **4096** (`= UMA_PCPU_ALLOC_SIZE = PAGE_SIZE`, because `zpcpu_get` adds `pc_zpcpu_offset`);
→ `uma_cache` stride **128** (`= sizeof(struct uma_cache)`, `struct uma_cache` three `uma_cache_bucket` (16B) + 2×`uint64_t` = 64B then `UMA_ALIGN` to 128).

**Therefore: if `tester` applies "pairwise differ by `4096*Δidx`" to `uma_cache`, would get "differs by 128 not 4096" and misjudge FAIL.** Correct criteria:
1. `pc_cpuid == dense_idx == curcpu`
2. `pc_zpcpu_offset == 4096 * dense_idx`
3. `smr_c_seq` forms arithmetic sequence with common difference **4096** (equivalent to `smr_c_seq(i) - smr_c_seq(0) == 4096*i`)
4. `uma_cache` forms arithmetic sequence with common difference **128** and **pairwise distinct** (isolation's substantive requirement is "distinct", common difference is only corroboration)
5. `uk_ppera == mp_maxid + 1`

Above 4 slots all **precisely hold** at 1~4 → **DoD-1's evidence has been actually produced by existing probe, not just "probe in place"**.

#### ③ Easy one-time removal —— confirmed, DoD-8 satisfiable

All probes uniformly wrapped in `#if 1 /* M17 temporary probe ... */... #endif`, total **6 spots**: `ff_freebsd_init.c` 4 spots (`:114-119` scalar probe, `:122-163` two probe function definitions, `:267-269` worker call, `:428-431` main call) + `ff_host_interface.c:152-158` (`ff_probe_tid`) + `ff_host_interface.h:51-53` (prototype).
`grep -rn "M17 temporary probe" lib/` exhausts, **one-time removal feasible** ✓
**Must remove before M7 and rerun clean build**, confirming return to error 0 / warning 51 / 248 `.o` (noted as R-d).

#### ④ `[M17-PROBE-ZONE]` value credibility —— credible, with **self-check**

- `kg = zones[i]->uz_keg` is that zone's own keg pointer, `uk_ppera`/`uk_rsize` directly from that keg ✓
- **Self-check (what makes me judge credible not just "looks right")**: printed `uk_rsize` **self-consistent** with zone name —— `pcpu_zone_8` → `uk_rsize=8`, `pcpu_zone_64` → `uk_rsize=64`. If `uz_keg` was wrong or aliased to other keg, `rsize` couldn't match both zones' nominal sizes.
- **Dual working point cross-verification**: `mp_maxid=3 → uk_ppera=4` and `mp_maxid=1 → uk_ppera=2` → **`uk_ppera == mp_maxid + 1` holds at two different档位 simultaneously**, fully consistent with `uma_core.c:2472-2474 pages *= mp_maxid + 1`.
- → **U2 first directly established**: `UMA_ZONE_PCPU` zone really allocates `(mp_maxid+1)` pages, `zpcpu_offset_cpu(cpu)=4096*cpu` falls within allocated range, **not OOB reading adjacent memory** ✓ My §2.11's statically-derivable conclusion now has runtime evidence.

### 9.5 clean build re-verification (I ran, round 4)

| Metric | My measured | Threshold | Verdict |
|---|---|---|---|
| `lib` `make clean` / `make` return code | 0 / **0** | 0 | PASS |
| `lib` `grep -c "error:"` | **0** | 0 | PASS |
| `lib` `grep -c "warning:"` | **51** | ≤ 51 (HEAD baseline) | PASS —— **probe zero new warning**, consistent with coder report |
| `lib` `.o` count | **248** | 248 | PASS |
| `libfstack.a` size | 7,004,036 B | generated | PASS |
| `example` `make` return code | **0** | 0 | PASS |
| `example` `error:` / `undefined reference` | **0** / **0** | 0 | PASS |
| `helloworld` | **30,392,704** B | generated | PASS |
| `helloworld_epoll` | **30,386,112** B | generated | PASS |

#### Version judgment md5 (for `tester`)

```
751a8153d3b200229cff99b3fa7650b0  example/helloworld
0d31850c7e447b140ea0a43647d07915  example/helloworld_epoll
```

**⚠ Inconsistent with coder report's `d49268db…`, and I did reproducibility verification:**
- I did **two** complete clean builds consecutively, `helloworld`'s md5 **identical both times** (`751a8153…`) → **`helloworld`'s md5 is reproducible**, can serve as version judgment.
- Same two builds' `libfstack.a` md5 **different** → confirms leader's judgment: `.a`'s `ar` embedded mtime **not reproducible**, **cannot serve as version judgment** ✓
- Since `helloworld` reproducible but coder's value differs from mine, **indicates coder's reported md5 came from different source state** (`ff_freebsd_init.c` mtime **14:52:12** later than its build, report mtime 14:54:33). Process瑕疵, not code defect.
- **Requirement**: `tester` must use **`751a8153d3b200229cff99b3fa7650b0`** as tested version; if binary md5 doesn't match, must rerun `make clean && make` first (noted as R-c).

### 9.6 Probe output missing line (`dense_idx=2`'s `[M17-PROBE]`) —— **judgment: printf output lost, not thread didn't reach**

**Conclusion basis (code-level sufficient proof, not speculation)**: `ff_stack_thread_init()`'s order is `init_lock` acquire → **`ff_pcpu_thread_init(cpuid)` (contains `[M17-PROBE]`)** → `ff_callout_thread_init` → `vnet_alloc` → `lo_set_defaultaddr` → **`ff_probe_slots(cpuid)` (i.e. `[M17-PROBE-SLOT]`)** → `__sync_lock_release`.
→ Two probes in **same critical section**, and `[M17-PROBE]` **strictly before** `[M17-PROBE-SLOT]`.
→ **`[M17-PROBE-SLOT] dense_idx=2` exists ⟹ that thread necessarily executed `[M17-PROBE]`'s printf.** So not "thread didn't reach probe".

**Statistical corroboration (non-deterministic ⇒ output layer issue)**: Two 4-thread runs, **only one** lost idx=2's PROBE line → non-deterministic → output layer.

**Loss mechanism (located to code)**: `lib/ff_subr_prf.c:86 char bufr[PRINTF_BUFR_SIZE];` is a **global, non-`__thread`, unlocked** line buffer. Worker probes are serialized in `init_lock`, but **main thread and other threads' `printf` outside `init_lock`** concurrently write same `bufr[]`, causing whole line overwritten/lost. This is **f-stack existing defect, not introduced this round**.

**Severity: non-blocking** (probe reliability issue, doesn't affect product code correctness). Suggestions for `tester`:
1. Use **`[M17-PROBE-SLOT]` appearing N lines with distinct `dense_idx`** as "N threads all completed init" completeness criterion;
2. If some档 missing lines, **rerun once** (non-deterministic);
3. Don't judge FAIL due to missing lines —— missing lines only mean log lost.
(Noted as R-b. Optional improvement: make `bufr` `__thread`, but independent issue, not in M3 scope.)

### 9.7 M3 gate final conclusion

# **PASS**

**Blocking items: 0.** I re-verified leader's 6 items, all pass: crash fix's 4 sub-questions (①②③④) all hold and **fix thorough**; mandatory 1/mandatory 2 implementation correct; §2.9 suggested simplification handled; probe doesn't change control flow, evidence object correct, one-time removable, `[M17-PROBE-ZONE]` credible and first directly establishes U2; clean build independently reproduced by me (error 0 / warning **51** = HEAD baseline / 248 `.o`). **M3 can close, no need for human decision.**

**Non-blocking residual items (suggest recording in spec residual risk, don't block M3 close)**:

| # | Content | Level |
|---|---|---|
| **R-a** | `ff_freebsd_init.c:381` uses `sizeof(struct uma_page)` (40B) not `sizeof(struct uma_page_head)` (8B) for hash bucket allocation → **over-allocates** 5x, wastes ~256 KB/instance. **Over-allocate so memory-safe**, existing writing verbatim-moved | Low (tech debt; worth fixing in thread_mode=1 multi-instance) |
| **R-b** | `ff_subr_prf.c:86` global unlocked `bufr[]` → probe (and all `printf`) **may lose whole line**. Existing defect | Low (affects probe reliability, not product correctness) |
| **R-c** | coder's reported `helloworld` md5 (`d49268db…`) inconsistent with current workspace build (`751a8153…`); I proved that md5 **reproducible**, so coder's value from different source state | Medium (process; `tester` must pin version by my md5) |
| **R-d** | 6 `#if 1 /* M17 temporary probe */` probes must be removed before M7 and rerun clean build (DoD-8) | Medium (must do before release) |
| **R-e** | **`tester` criteria must be per-field**: `smr_c_seq` common difference **4096**, `uma_cache` common difference **128** (`sizeof(struct uma_cache)`). Applying uniform `4096*Δidx` would misjudge FAIL | **High (would cause misjudgment, must communicate to tester before M5)** |
| R-f | §2.14's semantic change A (`net.isr.dispatch` must stay `direct`) / B (hpts instance count 1→N, suggest R6) —— leader已 dispatched to `designer` | Medium (doc) |

### 9.8 G2 release conclusion

# **G2 can start**

`gate-design` E3's hard prerequisite **satisfied**, basis (static + runtime dual):

1. **Static**: `lib/include/sys/pcpu.h:31-34` final state is `#include_next <sys/pcpu.h>` / `#undef curcpu` (retained ✓) / `#define curcpu PCPU_GET(cpuid)`. `PCPU_GET(member)` = `(pcpup->pc_ ## member)` → `curcpu` already **per-thread** ✓
2. **Runtime evidence (new, stronger than static)**: `tester`'s logs show 4-thread档 `curcpu` measured values **0/1/2/3 and each consistent with respective `dense_idx`, `pc_cpuid`**; corresponding `uz_cpu[curcpu]` addresses form arithmetic sequence with common difference 128, **pairwise distinct** → **UMA per-cpu cache has truly been slotted by thread** (this is the gap `designer` pointed out, G1 round 1 missed, now closed) ✓
3. **G2's safety premise holds**: after G2 removes `uma_crit_lock`, slot isolation becomes **sole** protection. Now evidence isolation effective (point 2) + `uk_ppera == mp_maxid+1` guarantees slots fall within allocated range (§9.4④) → removing global lock won't regress to `b90ddcba5`'s fixed crash.

**Two附带 requirements for G2** (don't affect release):
- G2 independent commit (`designer`'s D8 verdict G2-b + L0/L1/L2 downgrade steps), don't mix with this round's G1;
- After G2 completion must **re-run** §9.4②'s 5 criteria (post-lock slot isolation is sole protection, must retest not reuse this round's data).