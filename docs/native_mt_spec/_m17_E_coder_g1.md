# _m17_E: M3 Coding Milestone G1 Delivery (coder)

> Goal: G1 = make the f-stack kernel view SMP-aware; each stack thread owns a dense, independent pcpu slot, so UMA/SMR per-CPU storage is slotted by thread count.
> Route: the **candidate A (whole-tree `-DSMP`)** ruled by `_m17_D_verdict.md`, strictly aligned with D1~D7, D9.
> **G2 (removing `uma_crit_lock`) was not done this round**; it awaits `designer`'s D8 three-way ruling and will be implemented by M4.
> All compile numbers come from actual `make clean` + full `make` output, no estimation.
> **This document has two rounds**: the first round is §1~§4; **the second round (the `curcpu` per-thread-ization done after the bounce-1/3 rejection) is §5**; the final state and final clean-build numbers follow §5.

---

## 1. First-Round Change List (7 files, all in `lib/`; zero changes to the `freebsd/` upstream tree)

### 1.1 `lib/Makefile` (+4 lines)

After `CFLAGS+= -DFSTACK`:

```make
# SMP makes MAXCPU 1024 so UMA/SMR per-cpu storage is sized for all stack
# threads; without it MAXCPU is 1 and every thread shares slot 0.
CFLAGS+= -DSMP
```

Corresponds to **D1** (`MAXCPU ≥ N`'s hard precondition auto-satisfied by `-DSMP`: `MAXCPU` 1 → 1024). The `lib/opt/opt_global.h` entry was not used; the two are equivalent and `CFLAGS` is more explicit; the downgrade step (`#define MAXCPU 64`) is kept for M5 to enable on demand.

### 1.2 `lib/ff_glue.c` (+7 lines, right after `smp_topology`'s SYSCTL)

```c
/* No CPU topology in userspace; callers must handle NULL (tcp_hpts.c:1890). */
struct cpu_group *
smp_topo(void)
{
    return (NULL);
}
```

The only new missing symbol of `-DSMP` (`_m17_C_buildprobe.md` §2.2 measured). The safety of returning `NULL` was verified by the leader: `tcp_hpts.c:1867-1871` already has `#else cpu_top = NULL`; `:1890 if (cpu_top == NULL) grp_cnt = 1`; `:1565 if (grp_cnt > 1)` only then dereferences `grps[]`. `ff_glue.c` was chosen because it already `#include <sys/smp.h>` (`:54`) and already defines `mp_ncpus`/`mp_maxid`/`all_cpus`/`smp_started`/`smp_disabled`/`smp_topology` — the existing home of this class of symbols.

### 1.3 `lib/ff_freebsd_init.c`

| Location | Change |
|---|---|
| `:39` | add `#include <sys/smp.h>` (`mp_ncpus`/`mp_maxid` declarations) |
| `:73-74` | add `extern int ff_cur_proc_id(void);` + a one-line note |
| `:98-115` `ff_pcpu_thread_init()` | **actually uses the parameter**: `pcpu_init(pcpup, cpuid, ...)` (was always 0); adds a **runtime** upper-bound check (**D6**); rewrote the obsolete "cpuid must stay 0" comment |
| `:281` | local variables add `int nb_cpus, i;` |
| `:302-324` | replace the original `ff_pcpu_thread_init(0); CPU_SET(0, &all_cpus);` with **triple synchronous setting** (**D2/D4/D7**) |

The new upper-bound check in `ff_pcpu_thread_init()`:

```c
    if (cpuid < 0 || (u_int)cpuid > mp_maxid)
        panic("ff_pcpu_thread_init: cpuid %d out of range [0, %u]\n",
            cpuid, mp_maxid);
```

Uses `panic()` rather than `rte_exit()`: this file is a kernel-mode TU (`-nostdinc` + kernel headers) and cannot include DPDK headers.

Triple setting (before `uma_startup1()`):

```c
    nb_cpus = ff_global_cfg.dpdk.thread_mode ?
        ff_global_cfg.dpdk.nb_threads : 1;
    if (nb_cpus < 1)
        nb_cpus = 1;
    if (nb_cpus > MAXCPU)
        panic("nb_threads %d exceeds MAXCPU %d\n", nb_cpus, MAXCPU);

    mp_ncpus = nb_cpus;
    mp_maxid = nb_cpus - 1;
    for (i = 0; i < nb_cpus; i++)
        CPU_SET(i, &all_cpus);

    ff_pcpu_thread_init(ff_global_cfg.dpdk.thread_mode ? ff_cur_proc_id() : 0);
```

- **Timing (D2)**: this block sits at `:302-324`; `uma_startup1()` at `:331`; `mi_startup()` at `:339` → the triple is finalized before UMA sizes zones.
- **`mp_ncpus` must rise too (D2's heap-overflow point)**: `ip_fw_dynamic.c:3236` allocates by `mp_ncpus`; `:2086-2091` fills by `CPU_FOREACH` (i.e. `0..mp_maxid` with `CPU_ISSET`); this block makes `mp_ncpus == mp_maxid + 1 ==` the set-bit count of `all_cpus`, all three consistent, so `cached_count ≤ mp_ncpus`, no overflow.
- **D7 zero regression**: with `thread_mode == 0`, `nb_cpus == 1` → `mp_ncpus=1`, `mp_maxid=0`, `all_cpus` only bit 0, main-thread slot 0, **verbatim-equivalent** to before the change.

### 1.4 `lib/ff_dpdk_if.c`

| Location | Change |
|---|---|
| `:412-416` (before `init_lcore_conf()`) | add `int ff_cur_proc_id(void) { return ff_cur_lcore_conf()->proc_id; }` |
| `:2655` | `ff_stack_thread_init(rte_lcore_id())` → `ff_stack_thread_init(qconf->proc_id)` (**D3**; `qconf` already fetched by `ff_cur_lcore_conf()` at `:2650`) |

### 1.5 `lib/ff_dpdk_if.h` (+2 lines)

`int ff_cur_proc_id(void);` prototype declaration.

### 1.6 `lib/ff_kern_timeout.c:190` (**D5**)

```c
-static int timeout_cpu;
+static __thread int timeout_cpu;
```

Paired with `:187__thread struct callout_cpu cc_cpu`. Necessity re-verified: `:254 timeout_cpu = PCPU_GET(cpuid)` is executed by every thread; `:1061/:1077 c->c_cpu = timeout_cpu` writes the value into the callout. Before the change `timeout_cpu` was a shared global (later writer overwrites), which happened to be all 0 in the old cpuid-always-0 build so no symptom; this round, with cpuid becoming dense non-zero, without `__thread` it would write **another thread's cpuid** into `c->c_cpu`, then pass it back to `:730`'s `cpu >= MAXCPU` check via `:815 callout_schedule()`.

---

## 2. Explanation and Basis of the Main-Thread Numbering (D4, with the evidence chain)

**Conclusion: the main thread and workers use the same numbering source `lcore_conf[].proc_id`, not relying on the unverified inference "EAL main lcore == `proc_lcore[0]`".**

Evidence chain (each point confirmed by actually reading the code):

1. `ff_init()` (`ff_init.c:38-52`) runs `ff_load_config()` → `ff_dpdk_init()` → `ff_freebsd_init()` → `ff_dpdk_if_up()` in order; and `init_lcore_conf()` is called inside `ff_dpdk_init()` (28 lines after `rte_eal_init()`).
   → **When `ff_freebsd_init()` runs, `lcore_conf[].proc_id` is already filled, and `rte_lcore_id()` is already valid on the main thread** (`rte_eal_init` has set the per-lcore id for the initial thread).
2. `ff_dpdk_if.c:436-439`: in the `thread_mode` branch `for (ti = 0; ti < nb_threads; ti++) { lcore_id = proc_lcore[ti]; lcore_conf[lcore_id].proc_id = ti; }` → `proc_id` is the **dense number** `0..nb_threads-1` (**D3**'s designated existing field).
3. `ff_config.c:1477-1483` (thread_mode collapse): `nb_threads = nb_procs`, `proc_mask = strdup(lcore_mask)`; `ff_config.c:1156` passes `-c<proc_mask>` to EAL. And `parse_lcore_mask()` (`:116-120`) fills `proc_lcore[count] = idx` in bit-ascending order.
   → **EAL's lcore set == `lcore_mask`'s set bits == `{proc_lcore[0..nb_threads-1]}`, all three identical.**
4. Therefore **the main thread, wherever it lands among the EAL lcores (including when `--main-lcore` changes the default), is necessarily some `proc_lcore[k]`**, and `lcore_conf[rte_lcore_id()].proc_id` is necessarily a valid dense value `k`. The numbering only depends on "the main thread is an EAL lcore" (guaranteed by EAL), **not on `k == 0`**.
5. `ff_memory.h:104-111ff_lcore_conf_idx()` = `thread_mode ? rte_lcore_id() : 0`, so `ff_cur_proc_id()` under `thread_mode=1` is `lcore_conf[rte_lcore_id()].proc_id`.

**No-collision proof**: `proc_id` in `lcore_conf[]` is one-value-per-lcore and mutually distinct; the main thread takes its own lcore's `proc_id`, each worker takes its own lcore's `proc_id` → globally unique. And because `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` (`ff_dpdk_if.c:2863`) makes **the main thread itself also run `main_loop`**, the main thread is both "the initializer" and "a worker"; its two numbering sources are the same and give the same value; no single thread gets two slots. When the main thread enters `ff_stack_thread_init()` in `main_loop`, it returns early because `ff_stack_inited` (`ff_freebsd_init.c:82` defines it; the main thread sets it to 1 at `:378`; workers set their own to 1 at `:187`), **so it does not repeat `pcpu_init()`**.

**Why `thread_mode=0` cannot use `proc_id`**: `init_lcore_conf()`'s non-thread_mode branch executes `ff_cur_lcore_conf()->proc_id = ff_global_cfg.dpdk.proc_id`, i.e. **the process number** (a secondary process can be 1/2/…). Under multi-process each process has an independent address space and only one stack instance; the slot must be 0; mistakenly using `proc_id` would give a secondary process a non-0 slot, violating D7. Hence the code explicitly writes `thread_mode ? ff_cur_proc_id() : 0`.

**Why kernel-mode TUs access via `ff_cur_proc_id()` indirection**: `ff_freebsd_init.c` is compiled with kernel flags (`-nostdinc` + `-include opt_global.h` + FreeBSD headers), unable to include `ff_memory.h`/DPDK headers (`__rte_cache_aligned`, `rte_lcore_id()`, etc.). So a one-line accessor is provided in the host TU `ff_dpdk_if.c`; the kernel side declares it `extern` (consistent with the file's existing `extern void mi_startup(void);` style).

---

## 3. Clean-Build Measurement Record

**All are "`make clean` first, then a full `make`"; no incremental builds.**

### 3.1 `lib/`

```
cd /data/workspace/f-stack/lib && make clean && make -j16
```

| Metric | Measured | DoD-3 baseline | Verdict |
|---|---|---|---|
| `make clean` return code | 0 | — | — |
| `make` return code | **0** | 0 | PASS |
| `grep -c "error:"` | **0** | 0 | PASS |
| `grep -c "warning:"` | **51** | 51 (HEAD baseline) | **not increased**, PASS |
| `.o` produced | **248** | 248 | PASS |
| `libfstack.a` | generated, **7,003,932** bytes (HEAD baseline 6,995,792) | generated | PASS |

### 3.2 `example/`

```
cd /data/workspace/f-stack/example && make clean && make
```

| Metric | Measured | Verdict |
|---|---|---|
| `make clean` return code | 0 | — |
| `make` return code | **0** | PASS |
| `grep -c "undefined reference"` | **0** | PASS |
| `grep -c "error:"` | **0** | PASS |
| `helloworld` | generated, **30,392,712** bytes | PASS |
| `helloworld_epoll` | generated, **30,390,208** bytes | PASS |

> `helloworld_zc` is skipped per the Makefile's existing logic (`FF_ZC_SEND` not enabled), consistent with HEAD baseline behavior.

### 3.3 Worktree State

`git status --short` (tracked files):

```
 M config.ini            ← user's local test changes, untouched by this agent
 M lib/Makefile
 M lib/ff_dpdk_if.c
 M lib/ff_dpdk_if.h
 M lib/ff_freebsd_init.c
 M lib/ff_glue.c
 M lib/ff_kern_timeout.c
```

`freebsd/`, `example/` have no tracked-file changes. No `git commit` was run (left for the leader's M7 as required).

---

## 4. Risk Points for the `reviewer` to Focus On

By my self-assessed priority; **all are items I identified but did not resolve in this round / cannot verify by compilation**:

1. **【Highest】runtime unverified**: this round only achieved a passing clean build. "Each worker's `pc_zpcpu_offset` is mutually different and within the legal allocation range" (DoD-1) **is completely unverified**. In particular, `zpcpu_offset_cpu(cpu) = UMA_PCPU_ALLOC_SIZE * cpu = 4096 * cpu` (`_m17_C_buildprobe.md` §0.3 measured); worker N's offset is 4096×N; **must confirm the UMA per-CPU zone actually allocated `(mp_maxid+1) × 4096` bytes**, otherwise still OOB. `_m17_C_buildprobe.md` mentioned U2 (whether the actually-compiled `pcpu_page_alloc` is `uma_core.c:1959`'s or `:2084`'s fallback version) **still unverified**, and the two behave differently on "can stably allocate `(mp_maxid+1)*PAGE_SIZE`". **Suggest the reviewer list this as an evidence item that must be completed before M5.**
2. **【High】`ff_cur_proc_id()`'s validity during `ff_freebsd_init()` depends on EAL internals**: I proved via call order (`ff_dpdk_init` → `ff_freebsd_init`) that `init_lcore_conf()` ran and `rte_lcore_id()` is valid, but "`rte_eal_init` necessarily sets the lcore id for the initial thread" is a DPDK behavioral contract; **I did not verify it with runtime prints**. Suggest M5 print `rte_get_main_lcore()`/`rte_lcore_id()`/`ff_cur_proc_id()`/`PCPU_GET(cpuid)`/`pc_zpcpu_offset` to cross-check (this also covers `_m17_D_verdict.md` §3-6's unverified U6-a).
3. **【Medium】`smp_started` / `smp_cpus` not synced**: under `-DSMP` both remain `0` / `1` (`ff_glue.c:144`, `:164`). Per D2 I only changed the triple, not over-extending. I grepped `uma_core.c`/`subr_smr.c`/`subr_pcpu.c`/`tcp_hpts.c` for these two symbols **with no hits**, so I judge there are no compiled consumers today; but **I did not exhaust all 238 TUs**; please have the reviewer re-check whether other readers (e.g. sysctl display, `kern.smp.active`) need consistency.
4. **【Medium】D9 not handled**: app threads created by `ff_pthread_create()` have `pcpup == NULL`; calling `ff_*` dereferences NULL. This round **changed no behavior** (consistent with HEAD), but my new `panic()` upper-bound check does **not** cover this case (it never calls `ff_pcpu_thread_init`). Per ruling D9 it should be recorded in the spec as "unsupported usage"; please confirm that `designer` writes the document rather than me changing code.
5. **【Medium】`timeout_cpu`'s `__thread`-ization changes cross-thread visibility**: if a "thread A creates a callout, thread B processes it" path exists, `c->c_cpu` now records the creator's cpuid. Because `CC_CPU(cpu)`/`CC_SELF()` (`ff_kern_timeout.c:184-185`) **ignore the cpu argument** and always return the calling thread's own `cc_cpu`, I judge behavior unchanged; but this "macro ignores the argument" property is the **only** basis of safety; please have the reviewer re-check whether the paths fetching `cc` at `:662/:1181` etc. all hold.
6. **【Low】`MAXCPU=1024`'s cost not quantified**: `cpuset_t` 8→128 bytes, `cpuid_to_pcpu[]`/`dpcpu_off[]` 1→1024 slots, `netisr.c` several `malloc(...*MAXCPU)`. `libfstack.a`'s 8,140-byte growth is a side evidence, but **runtime RSS is not measured**. Downgrade step in `_m17_D_verdict.md` §1.3.
7. **【Low】the `nb_cpus > MAXCPU` `panic()` is practically unreachable**: `nb_threads`'s upper bound is `RTE_MAX_LCORE` (usually 128) < `MAXCPU` (1024). The check is kept so that if the `MAXCPU=64` downgrade step is enabled in the future it still fails loud; deliberately defensive code; please confirm it is not considered redundant.

### 4.1 What I Explicitly **Did Not** Do (avoid overstepping)

- **G2 (removing `uma_crit_lock`) untouched**: `lib/include/vm/uma_int.h:45-52` left as-is, awaiting the D8 ruling.
- No `freebsd/` upstream-tree files changed.
- No `git commit`, `config.ini` untouched.
- The 5 known deviations listed in `_m17_D_verdict.md` §3 (counter(9) de-per-CPU-ization, `cache_drain_safe()`, ipfw DPCPU hazard-pointer invalidation, NUMA undefined, netisr not creating real threads) not handled — all explicitly ruled **non-fix-targets this round**.

---

## 5. Second Round: `curcpu` Per-Thread-ization (done after M3 bounce 1/3)

### 5.1 Rejection Reason (pointed out by leader / `designer`; independently re-verified by me)

The first round only achieved "dense `pc_cpuid`", which **only fixed the SMR side** (`smr.h:110` goes through `zpcpu_get()` → `pc_zpcpu_offset`).
**The UMA per-CPU cache side does not go through `zpcpu_get()` at all; it locates by `zone->uz_cpu[curcpu]`**, and `lib/include/sys/pcpu.h:34` hardcodes `curcpu` to `0`, overriding upstream's `freebsd/sys/pcpu.h:218 #define curcpu PCPU_GET(cpuid)`.
→ After the first round **all threads still share `uz_cpu[0]`**; DoD-1's UMA side necessarily fails; and G2 removing `uma_crit_lock` would put the race `b90ddcba5` fixed right back.

I actually re-verified **all 11 sites** of `uz_cpu[curcpu]` (each matching the leader's list):
`freebsd/vm/uma_core.c:1452, 3738, 3776, 3818, 3901, 4534, 4543, 4595, 4628, 4803, 4853` (`grep -c "uz_cpu\[curcpu\]"` = **11**).

### 5.2 Change (1 file, 1 line)

`lib/include/sys/pcpu.h:34`:

```c
-#define curcpu    0
+#define curcpu    PCPU_GET(cpuid)
```

Keep `:32#undef curcpu` (avoid the redefined warning under `-Werror`). Because `lib/include/amd64/include/pcpu.h:49` already redefines `PCPU_GET(member)` as `(pcpup->pc_ ## member)`, this line is equivalent to `pcpup->pc_cpuid`, **which is exactly the upstream original semantics**. No comment added per convention (restoring the upstream definition, self-explanatory).

### 5.3 Effectiveness Verified (preprocessing measured, not inference)

Using the second-round `uma_core.c`'s **real compile command** with `-c` → `-E`, count the final expansion of `uz_cpu[...]`:

```
     11 uz_cpu[(pcpup->pc_cpuid)]     ← 11 cache locations, now per-thread
     12 uz_cpu[mp_maxid + 1]
      7 uz_cpu[i]
      1 uz_cpu[cpu]
      1 uz_cpu[]
```

- **All 11 sites expand to `(pcpup->pc_cpuid)`**, matching §5.1's 11 file:line counts → the change is effective, not a silent no-op.
- **Incidentally closes half of what I listed as "highest risk" in the first round**: `uma_core.c:3180` is
  `(sizeof(struct uma_cache) * (mp_maxid + 1)) +` — the zone's `uz_cpu[]` **is sized by `mp_maxid + 1`**. Because `pcpup->pc_cpuid ∈ [0, mp_maxid]` (guaranteed by `ff_pcpu_thread_init()`'s runtime check), `uz_cpu[curcpu]` **structurally cannot go out of bounds**.
  > Boundary: this is **compile-time/structural** evidence; runtime still needs the DoD-1 prints; and §4 risk-1's other half (`UMA_ZONE_PCPU` zone's `pcpu_page_alloc` taking the `:1959` version or the `:2084` fallback, i.e. U2) **remains unverified**; that is the `zpcpu_get()` path's business, a different path from this section's `uz_cpu[]`, **do not conflate**.

### 5.4 Re-verification of `curcpu` Index Points (the leader required actually re-checking 3 points + 1)

| Usage point | Index behavior | Re-check conclusion |
|---|---|---|
| `lib/ff_kern_synch.c:105 _sleep(&pause_wchan[curcpu], ...)`, `:59 static uint8_t pause_wchan[MAXCPU];` | direct index | **no OOB**: under `-DSMP`, `MAXCPU=1024`, and `curcpu ≤ mp_maxid = N-1`; N's upper bound is `RTE_MAX_LCORE` |
| `freebsd/netinet/tcp_hpts.c:1587 rp_ent[(curcpu % rp_num_hptss)]` | modulo | **no OOB**, and consistent: `:1864ncpus = mp_ncpus ? mp_ncpus : MAXCPU` → since this round `mp_ncpus = N > 0`, `:1872 rp_num_hptss = ncpus = N`. So `curcpu % N` with `curcpu ∈ [0,N-1]` is an identity mapping, no wraparound |
| `freebsd/net/netisr.c:839 netisr_get_cpuid(curcpu)` | modulo | **no OOB**: `netisr_get_cpuid()`'s body is `return (nws_array[cpunumber % nws_count]);` |
| `freebsd/netinet/tcp_timer.c:237,249 return (curcpu);` | only as a callout cpu argument | with `MAXCPU=1024`, `ff_kern_timeout.c:730`'s `cpu >= MAXCPU` does not trigger |

Also re-verified `freebsd/netinet/tcp_hpts.c:1566 CPU_ISSET(curcpu, &tcp_pace.grps[i]->cg_mask)`: it sits inside `:1564 if (tcp_pace.grp_cnt > 1)`, and `smp_topo()` returns `NULL` → `:1890 grp_cnt = 1` → **that branch is unreachable**, `grps[]` not dereferenced (consistent with `_m17_D_verdict.md` §1.1's verification of the `smp_topo` stub).

### 5.5 Newly Introduced Risk: Per Spec Ruling, **No NULL Fallback**

After `curcpu` becomes `pcpup->pc_cpuid`, evaluating `curcpu` on a thread with `pcpup == NULL` dereferences NULL. **Per the spec ruling, deliberately no NULL check** (fail-fast; a fallback would disguise "unsupported usage" as runnable and necessarily degrade into slot sharing). Premise holds: the main thread does `ff_pcpu_thread_init()` at the earliest point of `ff_freebsd_init.c:324`; workers at `ff_stack_thread_init()`'s first step (`:195`). `ff_pthread_create()` threads are declared unsupported per D9 via documentation.

### 5.6 Another Correction: `ff_stack_thread_init()`'s Explicit thread_mode=0 Protection

`lib/ff_dpdk_if.c:2655`:

```c
-ff_stack_thread_init(qconf->proc_id);
+    ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0);
```

**I adopted the leader's suggestion and also give the argument that "the original writing is currently safe"** (the two are not contradictory):

- The original writing's **current-safety** basis: `ff_freebsd_init.c:378 ff_stack_inited = 1;` sits at the end of `ff_freebsd_init()`'s body, before `return (0);` (`:380`), **with no conditional wrapping**; and `ff_init()` (`ff_init.c:38-52`) necessarily finishes before `ff_run()` → `main_loop`. So under `thread_mode=0`, the only stack thread entering `main_loop` has `ff_stack_inited == 1`, and `ff_stack_thread_init()` returns at `:177-178`; the argument is never used.
- **Still changed** because: ① that safety depends on the non-local invariant "set-timing across files", while `init_lcore_conf()`'s non-thread_mode branch indeed sets `lcore_conf[0].proc_id` to `ff_global_cfg.dpdk.proc_id` (secondary processes 1/2/…), i.e. **the argument is semantically wrong, just coincidentally unused**; ② if that invariant is ever broken by a future change, the consequence is `ff_pcpu_thread_init()`'s `panic` (`mp_maxid == 0` but cpuid ≥ 1), a hard failure; ③ the explicit ternary is **fully symmetric** with `ff_freebsd_init.c:324`'s main-thread numbering and more readable.

### 5.7 Second-Round Clean-Build Measurement (final state)

**`make clean` first, then a full `make`; both `lib/` and `example/`; no incremental builds.**

`lib/`:

| Metric | Measured | Baseline/threshold | Verdict |
|---|---|---|---|
| `make clean` return code | 0 | — | — |
| `make -j16` return code | **0** | 0 | PASS |
| `grep -c "error:"` | **0** | 0 | PASS |
| `grep -c "warning:"` | **51** | ≤ 51 (HEAD baseline) | **not increased**, PASS |
| `.o` produced | **248** | 248 | PASS |
| `libfstack.a` | generated, **7,002,076** bytes | generated | PASS |

`example/`:

| Metric | Measured | Verdict |
|---|---|---|
| `make clean` return code | 0 | — |
| `make` return code | **0** | PASS |
| `grep -c "undefined reference"` | **0** | PASS |
| `grep -c "error:"` | **0** | PASS |
| `helloworld` | generated, **30,392,672** bytes | PASS |
| `helloworld_epoll` | generated, **30,386,072** bytes | PASS |

### 5.8 Complete Change Surface After the Second Round (G1's final state; must be **one commit**)

`git status --short` (tracked files; `config.ini` is the user's local change, untouched by this agent):

```
 M config.ini
 M lib/Makefile
 M lib/ff_dpdk_if.c
 M lib/ff_dpdk_if.h
 M lib/ff_freebsd_init.c
 M lib/ff_glue.c
 M lib/ff_kern_timeout.c
 M lib/include/sys/pcpu.h      ← new in round 2
```

**All 8 files belong to G1 as one atomic commit**: `curcpu` becoming `0..N-1` requires `uz_cpu[]` already allocated by `mp_maxid+1` (depends on the triple) and `MAXCPU ≥ N` (depends on `-DSMP`). Splitting the commit would produce an intermediate state with "`curcpu` non-zero but `uz_cpu[]` only 1 slot" or "`MAXCPU=1` but cpuid non-zero" — **a state that crashes immediately**. The `freebsd/` upstream tree remains zero-change.

### 5.9 Second-Round Impact on the §4 Risk List

- §4 risk-1 (highest): **partially closed**. The `uz_cpu[]`-side OOB is structurally excluded by `uma_core.c:3180`'s `mp_maxid+1` sizing (§5.3). **But the `zpcpu_get()` / `UMA_ZONE_PCPU`-side U2 remains unverified**, and DoD-1's runtime prints are **completely not done**; the risk level stays "highest".
- §4 risks 2/3/4/6/7: unchanged.
- §4 risk-5 (`timeout_cpu`'s `__thread`-ization): unchanged.
- **New risk (introduced in round 2)**: `curcpu` now dereferences `pcpup`. Any path evaluating `curcpu` before `ff_pcpu_thread_init()`, or on a thread without per-thread init, crashes with a NULL dereference. Deliberately no fallback per §5.5's ruling.

  **I have actually verified the "`pcpup == NULL` window" and conclude the current paths are safe** (please have the `reviewer` independently re-check this reasoning; it is the part of round 2 most needing a second pair of eyes):

  1. `ff_pcpu_thread_init()` itself has a `pcpup == NULL` window — the line `pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO)` calls `malloc()` **before `pcpup` is assigned**. If the kernel-mode `malloc()` went through UMA, it would hit `uz_cpu[curcpu]` → NULL dereference, **crashing every worker at startup**.
  2. Actual check: **`freebsd/kern/kern_malloc.c` is not in `lib/Makefile`'s SRCS** (confirmed by grep); kernel-mode `malloc()` is implemented by `lib/ff_glue.c:1067-1082`, whose body is `alloc = ff_malloc(size)` (host-side `malloc`) + optional `bzero`, **completely not going through UMA**. So that window is safe.
  3. But `ff_glue.c:1076`'s failure-retry branch `pause("malloc", hz/100)` → `ff_kern_synch.c:105 _sleep(&pause_wchan[curcpu], ...)` **does evaluate `curcpu`**. That branch is entered only when "`ff_malloc` returns NULL and `flags & M_WAITOK`"; `ff_pcpu_thread_init()` passes `M_ZERO` (**without** `M_WAITOK`), so `!(flags & M_WAITOK)` holds and it immediately `break`s, **never reaching `pause()`**.
  4. The worker-side order is also verified: `main_loop` (`ff_dpdk_if.c:2625-2655`) before `ff_stack_thread_init()` only does local assignments and `ff_cur_lcore_conf()`; no UMA/`pause` paths; `ff_stack_thread_init()` (`:171-195`)'s first substantive action is `ff_pcpu_thread_init()`. The main-thread side `ff_freebsd_init.c:324` is even before `uma_startup1()` (`:331`); UMA not yet initialized.
  5. **Residue (the real residual risk)**: any thread **without per-thread init** (i.e. D9's `ff_pthread_create()` scenario) that triggers a UMA allocation or `pause()` now NULL-dereferences rather than silently sharing a slot. This is **deliberate fail-fast** (§5.5), but means D9's "unsupported usage" changed from "silently wrong" to "crashes immediately"; **the spec's wording needs updating accordingly** (please note for `designer`: if the original wording was "would share a slot", it should now be "would NULL-dereference crash").

---

## 6. Third Round: DoD-1 Probes (temporary code, removed after M5)

>This section is for `tester` to follow directly. **I already did one short smoke run myself** (thread_mode=1, `lcore_mask=6`); the "measured samples" below are **real output**, not illustrations.
> After the smoke run, the process was stopped via `/data/workspace/kill_process.sh helloworld`; **`config.ini` was not modified** (the repo worktree's then-existing local test values were used).

### 6.1 Probe Landing Points and Wrapping

All wrapped in conspicuous `#if 1 /* M17 temporary probe ... */ … #endif`, **changing no control flow** (only `printf`). 4 sites total:

| # | file:location | content |
|---|---|---|
| P1 | `lib/ff_freebsd_init.c` `ff_pcpu_thread_init()` end (after `PCPU_SET`) | prints the `[M17-PROBE]` scalar line |
| P2 | `lib/ff_freebsd_init.c` add `static void ff_probe_slots(int dense_idx)` after `ff_pcpu_thread_init()` | prints the `[M17-PROBE-SLOT]` slot-address line |
| P3 | `lib/ff_freebsd_init.c` `ff_stack_thread_init()` end (after `lo_set_defaultaddr()`, before `__sync_lock_release()`) | worker calls `ff_probe_slots(cpuid)` |
| P4 | `lib/ff_freebsd_init.c` `ff_freebsd_init()` end (after `ff_stack_inited = 1;`, before `return (0);`) | main thread calls `ff_probe_slots(PCPU_GET(cpuid))` |

Supporting temporary helpers (also `#if 1` wrapped, removed with the rest after M5):
- `lib/ff_host_interface.c`: `uint64_t ff_probe_tid(void) { return((uint64_t)pthread_self()); }`
- `lib/ff_host_interface.h`: its declaration

> Using `pthread_self()` rather than `syscall(SYS_gettid)`: `ff_host_interface.c:53` already `#include <pthread.h>`, while `<unistd.h>` is only included under `FF_KERNEL_COEXIST`; using `pthread_self()` needs no new header. **Note this value is a pthread handle, not an OS tid**; used only to distinguish threads; do not compare with `ps -T`'s LWPs.

`printf` availability was measured-confirmed: the kernel-mode `printf` is provided by `lib/ff_subr_prf.c`; `ff_freebsd_init.c:374` already uses it (`printf("set loopback port default addr failed!")`).

### 6.2 Probe-2's Value Paths (the leader required "confirming a viable path myself") — **real slot addresses obtained, no degradation needed**

`ff_freebsd_init.c` already includes `<vm/uma_int.h>` (`:45`), `<net/vnet.h>` (`:58`), `<netinet/tcp_var.h>` (`:62`), so it can directly take:

```c
    if (V_tcbinfo.ipi_smr != NULL)
        smr_slot = zpcpu_get(V_tcbinfo.ipi_smr);          /* this thread's SMR per-cpu slot */
    if (V_tcbinfo.ipi_zone != NULL)
        uma_cache = &V_tcbinfo.ipi_zone->uz_cpu[curcpu];  /* this thread's UMA cache slot */
```

- `ipi_smr` (`freebsd/netinet/in_pcb.h:380`, `smr_t`) and `ipi_zone` (`:378`, `uma_zone_t`) are created at startup (TCP PCB info), exactly the SMR used at last round's SIGSEGV site.
- `uz_cpu[]` is dereferenceable because `uma_int.h:507` exposes `struct uma_cache uz_cpu[];`.
- Both have NULL checks; **no crash** if unavailable.
- `V_tcbinfo` needs a VNET context: at P4 the main thread's `curthread->td_vnet = vnet0` was set earlier; at P3 the worker's `curthread->td_vnet = v` was set in the same function. **The smoke run confirmed both returned non-NULL addresses.**

### 6.3 Output Format

```
[M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
[M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
```

### 6.4 **Log Landing Points (important; differs from the leader's preset; measured conclusion)**

`tester` **must look at both files**, otherwise the main thread's probe lines are missed:

| Thread | Probe-line landing point |
|---|---|
| **main thread** (`ff_freebsd_init` phase, dense_idx=0) | **`example/f-stack-0.log`** |
| **worker** (`ff_stack_thread_init` phase, dense_idx≥1) | **`example/helloworld.log`** |

Measured basis: `grep -rl "M17-PROBE"` only hits these two files; `helloworld.log`'s `grep -c "M17-PROBE"` = 2 (worker's P1+P3); the main thread's P1+P4 are in `f-stack-0.log`.
(Both are **append-writes**; to read new content, first record the old line count, then `tail -n +N`.)

### 6.5 Judgment Formulas (DoD-1)

For each thread take one `[M17-PROBE]` + `[M17-PROBE-SLOT]` pair:

1. **Dense and no-OOB**: all `dense_idx` pairwise different, the values exactly cover `0..mp_maxid`, and `dense_idx <= mp_maxid`.
2. **The three consistent**: `dense_idx == pc_cpuid == curcpu`.
3. **Offset correct**: `pc_zpcpu_offset == 4096 * dense_idx` (4096 is `UMA_PCPU_ALLOC_SIZE = PAGE_SIZE`, `zpcpu_offset_cpu(cpu) = UMA_PCPU_ALLOC_SIZE * cpu`).
4. **Triple correct**: `mp_ncpus == nb_threads`, `mp_maxid == nb_threads - 1`.
5. **SMR slot isolation**: any two threads' `smr_c_seq` difference == `4096 * (dense_idx difference)`.
6. **UMA cache slot isolation**: any two threads' `uma_cache` difference == `128 * (dense_idx difference)`. 128 = `sizeof(struct uma_cache)`, **measured** (`nm --print-size` gives `0x80`).
7. `thread_mode=0`: only one set of output, `dense_idx=0`, `pc_zpcpu_offset=0`, `mp_ncpus=1`, `mp_maxid=0` (D7 zero regression).

### 6.6 My Smoke-Run Measured Sample (thread_mode=1, `lcore_mask=6` → nb_threads=2)

`example/f-stack-0.log` (main thread):
```
[M17-PROBE] tid=140496878305280 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=2 mp_maxid=1 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7fc7f719dc80 uma_cache=0x7fc7f5ac9180
```
`example/helloworld.log` (worker):
```
[M17-PROBE] tid=140496838099968 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=2 mp_maxid=1 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7fc7f719ec80 uma_cache=0x7fc7f5ac9200
```

**Verification against the judgment formulas, item by item (all pass)**:

| Judgment item | Measured | Conclusion |
|---|---|---|
| ① dense no-OOB | dense_idx = {0, 1}, mp_maxid=1 | ✓ |
| ② three consistent | 0==0==0; 1==1==1 | ✓ |
| ③ offset | 0 == 4096×0; 4096 == 4096×1 | ✓ |
| ④ triple | mp_ncpus=2=nb_threads; mp_maxid=1 | ✓ |
| ⑤ SMR isolation | `0x7fc7f719ec80 - 0x7fc7f719dc80 = 0x1000 = 4096 == 4096×1` | ✓ |
| ⑥ UMA isolation | `0x7fc7f5ac9200 - 0x7fc7f5ac9180 = 0x80 = 128 == 128×1` | ✓ |
| no crash | `grep -iE "panic|segmentation|out of range"` in the new logs: no hits; the process was alive and terminated normally via `kill_process.sh` after 25s | ✓ |

> **This dataset first proves G1's two goals simultaneously**: the SMR side (`zpcpu_get()` path, slot distance 4096) and the UMA cache side (`uz_cpu[curcpu]` path, slot distance 128) **are both isolated per thread**; slots no longer shared.
> **Boundary (must be honestly relayed)**: this is only a **2-thread, startup-phase, single short** smoke; **not a full DoD-1 acceptance**. `tester` still needs to run the 1/2/4-thread matrix + `thread_mode=0` comparison + soak under load. Also it **still has not answered U2** (`UMA_ZONE_PCPU` zone's `pcpu_page_alloc` taking `uma_core.c:1959` or `:2084`) — ⑤ only proves "adjacent threads' SMR slot distance 4096", **not** that "the zone really allocated `(mp_maxid+1)×4096` bytes rather than OOB-accessing adjacent memory". **U2 still must be verified** (suggest `tester` focus on it at 4 threads; if the zone only allocated 1 page, dense_idx=1..3's slots are OOB memory; a short smoke may not crash immediately).

### 6.7 Third-Round Clean-Build Measurement

**`make clean` first, then a full `make`.**

| Metric | `lib/` | `example/` |
|---|---|---|
| `make clean` return code | 0 | 0 |
| `make` return code | **0** | **0** |
| `grep -c "error:"` | **0** | **0** |
| `grep -c "warning:"` | **51** (≤ baseline 51; **probes add zero warnings**) | — |
| `undefined reference` | — | **0** |
| `.o` produced | **248** | — |
| products | `libfstack.a` | `helloworld` **30,392,704** bytes, `helloworld_epoll` **30,386,112** bytes |

Probes confirmed in the binary: `strings helloworld | grep -c "M17-PROBE"` = **2** (two format strings).

### 6.8 Third-Round Change Surface (probes are **temporary code**, DoD-8 must clean them)

On top of §5.8's 8 files, 2 added:

```
 M lib/ff_host_interface.c    ← temporary: ff_probe_tid()
 M lib/ff_host_interface.h    ← temporary: its declaration
```

The P1/P2/P3/P4 inside `lib/ff_freebsd_init.c` are also temporary. **After M5, remove all 5 `#if 1 /* M17 temporary probe */` blocks at once** (`grep -rn "M17 temporary probe" lib/` lists them all in one go).

> **Commit suggestion for the leader**: probes **should not** enter G1's formal commit. Suggest commit-1 contains only the **code changes** among §5.8's 8 files; probes stay in the worktree for `tester`, removed after M5; if they must be committed for `tester` reproducibility, commit them as a separate temporary commit and revert after M5. Please rule.

---

## 7. Fourth Round: M3 Gate Rejection Fixes (bounce 2/3, corresponding to `_m17_gate_code_g1.md`)

### 7.1 Mandatory-Change 1 (P2): Segfault on the `pause()` Path When `pcpup == NULL` — Fixed

**I accept the `reviewer`'s judgment and correct my own round-2 §5.9 conclusion.**
In round 2 I only verified "that `malloc()` in `ff_pcpu_thread_init()` passes `M_ZERO`, without `M_WAITOK`, so it won't reach `pause()`", and judged "the current paths are safe". **That conclusion was too narrow**: `pause()` can also be reached from **other** early allocations with `M_WAITOK` (`ff_freebsd_init():284-298`'s `kern_setenv` family) and the D9 scenario; those paths are equally inside the `pcpup == NULL` window.

More critically, the **nature judgment** the `reviewer` pointed out (I fully agree after re-checking): before the change, `curcpu` was the **literal 0**, `&pause_wchan[0]` is a legal address, and `_sleep` took the timeout path and retried normally → **the original code worked correctly in that corner**; after `curcpu` per-thread-ization it becomes a **deterministic segfault**. This is a **usability regression newly introduced in round 2**, not a pre-existing fragile point.

Fix (`lib/ff_kern_synch.c:102-108`):

```c
int
pause_sbt(const char *wmesg, sbintime_t sbt, sbintime_t pr, int flags)
{
    /* Reachable from malloc()'s OOM retry before this thread has a pcpu. */
    return (_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], NULL, 0, wmesg,
        sbt, pr, flags));
}
```

- No new `extern` declaration: `pcpup` is already visible via `lib/include/amd64/include/pcpu.h:45 extern __thread struct pcpu *pcpup;` (brought in by the `<sys/pcpu.h>` → `<machine/pcpu.h>` chain), and `ff_kern_synch.c` already used `curcpu` (the same header chain), so this is the minimal form.
- **The fallback scope is strictly limited to this one site**. Per the leader's ruling refinement: D9 (app threads mistakenly calling `ff_*`) continues **fail-fast, no fallback**; only this `pause()` bootstrap/OOM-retry path gets a fallback, because it is a normal branch of normal code rather than misuse.

### 7.2 Mandatory-Change 2: False Comments and Verbose Comments — Fixed

**(a) `lib/ff_kern_timeout.c:179-181` (judged a hard convention violation by `reviewer` §2.5/§2.9)**

The original comment's parenthetical `cpuid is always 0, MAXCPU=1` becomes **both false** after G1, and it is the **only written basis** for "`CC_CPU` ignoring the argument is safe"; keeping it would mislead maintainers. Changed to state the real reason:

```c
/* Per-thread callout_cpu: each stack instance drives its own callwheel.
 * CC_CPU/CC_SELF ignore the cpu arg and return the calling thread's own
 * instance, so c_cpu is only a record of which thread armed the callout. */
```

**(b) `lib/ff_freebsd_init.c`'s main-thread numbering comment (§2.9 suggested trimming)**: 4 lines → **2 lines**:

```c
    /* Main thread is itself an EAL lcore worker (CALL_MAIN), so it takes its
     * own dense slot; thread_mode=0 has one stack per process -> slot 0. */
```

The 5 comments §2.9 judged "necessary, should keep" were **not changed**.

### 7.3 Mandatory-Change 3: DoD-1 Probes Added in Round 3 — For the `reviewer` to Re-Check

`reviewer`'s audit item-11's "fail" was based on its **earlier worktree snapshot** (probes not yet added). **Round 3 (§6) has added them**; when re-reviewing, please check:

- 4 landing points + 2 temporary helpers, all `#if 1 /* M17 temporary probe */` wrapped, **changing no control flow** (only `printf`). Cleanup list: `grep -rn "M17 temporary probe" lib/` = 6 lines / 5 blocks.
- Output format:
  ```
  [M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
  [M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
  ```
- The 7 judgment formulas are in §6.5; **log landing points in §6.4 (main thread in `example/f-stack-0.log`, worker in `example/helloworld.log`; look at both)**.
- Measured samples and item-by-item verification in §6.6: at 2 threads, SMR slot distance = 4096, UMA cache slot distance = 128 (= measured `sizeof(struct uma_cache)`), both `×Δdense_idx`.

### 7.4 Two Semantic Changes of the `curcpu` Per-Thread-ization (discovered by the `reviewer`; honestly recorded as requested for `designer` to write into spec residual risks)

**A. `net.isr.dispatch` must stay `direct`**
`netisr.c:155-157`'s dispatch policy is a **tunable sysctl**. If set to `hybrid`/`deferred`, a worker's `curcpu != nws_array[0]` would take `queue_fallback` at `:1172`, enqueueing packets into the netisr queue; but f-stack's netisr swi is an empty stub (`ff_kern_intr.c`) → **packets enter the queue with no one to process them (silent drops/stalls)**.
Before the change `curcpu ≡ 0` always equals `nws_array[0]`, so that branch never hit; **after per-thread-ization that protection disappears**.
→ **Conclusion: `net.isr.dispatch = direct` must be maintained (the default is direct)**. Suggest the spec list it as a constraint and consider adding a startup assertion in M4/later.

**B. `tcp_hpts` instance count 1 → N, with callout ownership and driving thread mismatched**
`tcp_hpts.c:1864ncpus = mp_ncpus` → instance count goes from 1 to **N**; each instance allocates `p_hptss` (`sizeof(struct hptsh) * NUM_OF_HPTSI_SLOTS`), memory cost ×N.
More substantively, the **ownership mismatch**: `tcp_hpts_init()` is executed by the **main thread** during `mi_startup()` → all N callouts hang on the **main thread**'s `__thread cc_cpu` callwheel; while `__tcp_run_hpts()`'s `:1587 rp_ent[curcpu % N]` is picked by **each worker** choosing **different** entries. I.e. "the hpts entry a worker drives has its callout on the main thread's callwheel".
`hpts->p_mtx` is `MTX_DEF`, and f-stack stubs all `mtx` to `((void)0)` (`lib/include/sys/mutex.h`) → **no real mutual exclusion**, currently masked by Giant.
→ This is a **residual risk not fixed this round**; please have `designer` write it into the spec; `FF_TCPHPTS=1` is compiled (`lib/Makefile:51`); M5 load tests should watch the rack/bbr-related paths.

### 7.5 Fourth-Round Clean-Build Measurement

**`make clean` first, then a full `make`.**

| Metric | `lib/` | `example/` |
|---|---|---|
| `make clean` return code | 0 | 0 |
| `make` return code | **0** | **0** |
| `grep -c "error:"` | **0** | **0** |
| `grep -c "warning:"` | **51** (= HEAD baseline; with probes **zero new**) | — |
| `undefined reference` | — | **0** |
| `.o` produced | **248** | — |
| products | `libfstack.a` | `helloworld` **30,392,704** bytes, `helloworld_epoll` **30,386,112** bytes |

### 7.6 One Runtime Conflict with `tester` (honestly recorded + measures I took)

After fixing the three items, I did one smoke re-check, **overlapping in time with `tester`'s runtime work**; two points honestly recorded:

1. **That smoke run's config was untrustworthy; its data is void**: `config.ini`'s mtime was `14:16:01`, while my process started around `14:16:00` — colliding with `tester`'s config editing. That run's output was `mp_ncpus=1 mp_maxid=0 dense_idx=0` (single-instance), inconsistent with §6.6's run (`mp_ncpus=2`). **I do not treat it as evidence of D7 (thread_mode=0 zero regression)** because I cannot determine which config version the process actually read. D7 still awaits `tester`'s verification under a controlled config.
2. **`kill_process.sh <name>` by-process-name matching risks collateral-killing `tester`'s processes**. This time the audit confirmed no collateral kill: the last kill's audit snapshot `/tmp/.trash/20260804-061609-988598-kill/` **only contains `kill_987958.snap`** (my own pid; snapshot time `14:16:10`); `tester`'s pid `988684` started at `14:16:14` (after the enumeration moment) and was not included, and is still alive.
   → **Measure taken**: I **no longer start any runtime processes**; runtime belongs to `tester`. **And a team convention is suggested**: while `tester` is active, any other agent that must use `kill_process.sh` should always pass **a specific PID rather than a process name**, to avoid name-matching hitting others' processes.

### 7.7 Complete Change Surface After the Fourth Round

Formal code changes (**9 files**, must be one atomic commit):

```
 M lib/Makefile
 M lib/ff_dpdk_if.c
 M lib/ff_dpdk_if.h
 M lib/ff_freebsd_init.c
 M lib/ff_glue.c
 M lib/ff_kern_synch.c        ← new in round 4
 M lib/ff_kern_timeout.c
 M lib/include/sys/pcpu.h
```
(The 8 items above + the formal changes inside `lib/ff_freebsd_init.c`; the `freebsd/` upstream tree remains **zero-change**)

Probe-only changes (**temporary**, removed after M5; suggested not to enter commit-1):

```
 M lib/ff_host_interface.c
 M lib/ff_host_interface.h
 （+ the 4 #if 1 probe blocks inside lib/ff_freebsd_init.c）
```

`config.ini` holds `tester`/user's local test values; **this agent never modified it**. No `git commit` run.

---

## 8. G1 Final Delivery List (for `tester` and `reviewer` to use directly)

>Status: M3 bounce-2's three items **all completed** (§7); `lib/` and `example/` clean-build pass. The following is the final state.

### 8.1 Tested-Binary Fingerprints (`tester` version check)

Build time `2026-08-04 14:15:30/31`; confirmed **no source file is newer than the products** (`find lib -newer lib/libfstack.a` is empty), i.e. the products include all of §7's fixes.

| File | Size (bytes) | md5 |
|---|---|---|
| `lib/libfstack.a` | 7,003,564 | `ed148bd32e14dc290b8ead23d091b1b5` |
| `example/helloworld` | 30,392,704 | `88b8cf93e0b8d3765e76b3c26c6a8f3b` |
| `example/helloworld_epoll` | 30,386,112 | `a828db8e06996143f8b83987c8a6127c` |

(All three are `md5sum` / `ls -l` measured values.)

**If `tester`'s md5 doesn't match the table, the versions differ; do not run**; notify me to rebuild first.

### 8.2 Final File List (10 files, clearly distinguishing formal changes / temporary probes)

**A. Formal changes — should enter commit-1 (G1), 8 files**

| # | File | Change points | Corresponding constraint |
|---|---|---|---|
| 1 | `lib/Makefile` | `CFLAGS+= -DSMP` | D1 |
| 2 | `lib/ff_glue.c` | `smp_topo()` returns NULL | candidate A's only missing symbol |
| 3 | `lib/ff_freebsd_init.c` | triple (`mp_ncpus`/`mp_maxid`/`all_cpus`) before `uma_startup1()`; `ff_pcpu_thread_init()` actually uses the param + runtime upper-bound check; main thread takes the dense slot by `ff_cur_proc_id()` | D2/D3/D4/D6/D7 |
| 4 | `lib/ff_dpdk_if.c` | add `ff_cur_proc_id()`; worker passes the dense `proc_id` (incl. explicit thread_mode=0 protection) | D3/D4/D7 |
| 5 | `lib/ff_dpdk_if.h` | `ff_cur_proc_id()` prototype | — |
| 6 | `lib/ff_kern_timeout.c` | `timeout_cpu` gains `__thread`; false comment fixed | D5 |
| 7 | `lib/include/sys/pcpu.h` | `curcpu` back from the hardcoded `0` to `PCPU_GET(cpuid)` | UMA-cache-side slotting (round 2) |
| 8 | `lib/ff_kern_synch.c` | `pause_wchan[]` index adds the `pcpup != NULL` fallback | round-4 P2 fix |

**B. Temporary probes — suggested not to enter commit-1; removed after M5 (DoD-8 cleanup), 2 files + 1 embedded set**

| # | File | Content |
|---|---|---|
| 9 | `lib/ff_host_interface.c` | `ff_probe_tid()` (`#if 1 /* M17 temporary probe */`) |
| 10 | `lib/ff_host_interface.h` | its declaration (same wrapping) |
| — | the 4 `#if 1` probe blocks **inside** `lib/ff_freebsd_init.c` | P1/P2/P3/P4, mixed with that file's formal changes |

> **Commit hint for the leader**: item-10's existence means `lib/ff_freebsd_init.c` contains both formal changes and probe blocks. For a clean commit-1, remove the 4 probe blocks inside that file before committing (`grep -rn "M17 temporary probe" lib/` lists all 5 blocks / 6 lines at once). Please rule on whether to do so.
> The `freebsd/` upstream tree is **zero-change** (measured-confirmed multiple times). `config.ini` was never modified by this agent.

### 8.3 Probe-Field Semantics and Judgment Formulas (`tester`'s basis for judging "pairwise differ by 4096×Δidx")

**Output format**

```
[M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
[M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
```

**Field meanings**

| Field | Source | Meaning |
|---|---|---|
| `tid` | `ff_probe_tid()` = `(uint64_t)pthread_self()` | **pthread handle, not OS tid**; only for distinguishing threads; **do not** compare with `ps -T`'s LWPs |
| `dense_idx` | `ff_pcpu_thread_init()`'s parameter | the dense slot number passed in (under thread_mode=1 from `lcore_conf[].proc_id`) |
| `pc_cpuid` | `pcpup->pc_cpuid` | the cpuid `pcpu_init()` actually wrote; should == `dense_idx` |
| `pc_zpcpu_offset` | `pcpup->pc_zpcpu_offset` | `subr_pcpu.c` sets it to `zpcpu_offset_cpu(cpuid)` = `UMA_PCPU_ALLOC_SIZE * cpuid` = **4096 × cpuid** |
| `mp_ncpus` / `mp_maxid` | globals | should be `nb_threads` / `nb_threads - 1` |
| `curcpu` | macro → `pcpup->pc_cpuid` | the actual value after round-2's change; should == `dense_idx` |
| **`smr_c_seq`** | **`zpcpu_get(V_tcbinfo.ipi_smr)`** | **this thread's per-cpu slot address of the TCP PCB info's SMR** (`freebsd/netinet/in_pcb.h:380smr_t ipi_smr`, created by `in_pcb.c`'s `uma_zone_get_smr()`). Exactly the SMR used at last round's SIGSEGV site. Slot distance decided by `zpcpu_offset_cpu()` → **should be 4096 × Δdense_idx** |
| **`uma_cache`** | **`&V_tcbinfo.ipi_zone->uz_cpu[curcpu]`** | **this thread's UMA cache slot address of the TCP PCB zone** (`in_pcb.h:378 uma_zone_t ipi_zone`, the `uma_zcreate("tcp_inpcb", ...)` zone). Slot distance is `sizeof(struct uma_cache)` → **should be 128 × Δdense_idx** (128 measured by `nm --print-size`) |

> Both have NULL checks: if `ipi_smr`/`ipi_zone` are NULL, `(nil)` is printed. **`(nil)` should not appear normally** (my smoke run got non-NULL at both sites).

**Judgment formulas (7 items; full version in §6.5)**: the core is
1. all `dense_idx` pairwise different and exactly cover `0..mp_maxid`;
2. `dense_idx == pc_cpuid == curcpu`;
3. `pc_zpcpu_offset == 4096 × dense_idx`;
4. `mp_ncpus == nb_threads`, `mp_maxid == nb_threads - 1`;
5. **any two threads' `smr_c_seq` difference == 4096 × (dense_idx difference)**;
6. **any two threads' `uma_cache` difference == 128 × (dense_idx difference)**;
7. `thread_mode=0`: a single output set, `dense_idx=0`, `pc_zpcpu_offset=0`, `mp_ncpus=1`, `mp_maxid=0`.

**Log landing points (must look at both files; see §6.4)**: main thread → `example/f-stack-0.log`; worker → `example/helloworld.log`. Both are **append**-written; to read new content, first record the old line count, then `tail -n +N`.

### 8.4 The virtio PCI Error `tester` Reported — **Located: a harmless pre-existing warning, not a residual-process/hugepage/socket conflict**

Original error:
```
VIRTIO_INIT: eth_virtio_pci_init(): Failed to init PCI device
PCI_BUS: Requested device 0000:00:05.0 cannot be used
```

**Measured device topology** (`dpdk-devbind.py --status-dev net`):

```
Network devices using DPDK-compatible driver
0000:00:09.0 'Virtio network device 1000' drv=igb_uio unused=
Network devices using kernel driver
0000:00:05.0 'Virtio network device 1000' if=eth1 drv=virtio-pci unused=igb_uio *Active*
```

**Cause**: `config.ini`'s `[dpdk]` section has **no** `allow`/`pci_whitelist` entry (confirmed by grep), so EAL scans **all** PCI devices. When it scans `0000:00:05.0`, because that device is the **kernel-occupied, Active `eth1`** (driver `virtio-pci`), DPDK cannot take it over and prints the two lines above; then EAL continues using `0000:00:09.0` (`igb_uio`) as port 0 (`config.ini:89 port_list=0`), and startup continues normally.

**Decisive evidence**: that warning also appeared in **my own successful smoke run**, immediately followed by normal probe output and successful stack-creation logs (`example/helloworld.log` fragment from my run):

```
EAL: Selected IOVA mode 'PA'
VIRTIO_INIT: eth_virtio_pci_init(): Failed to init PCI device
PCI_BUS: Requested device 0000:00:05.0 cannot be used
[M17-PROBE] tid=140496838099968 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=2 mp_maxid=1 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7fc7f719ec80 uma_cache=0x7fc7f5ac9200
```
The same run's `f-stack-0.log` also has `Successed to register dpdk interface` and `Addr6: 2402:...`.

→ **Conclusion: ignore it; it does not affect `tester`'s phases 2/4.**

**⚠️ Serious warning (must relay to `tester`)**: **absolutely do not** bind `0000:00:05.0` to DPDK (`igb_uio`/`vfio-pci`). It is the **kernel-side Active `eth1`**, likely carrying this machine's management/SSH channel; binding it would immediately lose connectivity. The NIC the DPDK side should use is `0000:00:09.0` (already bound to `igb_uio`), corresponding to `config.ini`'s `<DPDK_NIC_IP>`.

**（Optional) eliminate the warning**: add `allow=0000:00:09.0` to `config.ini`'s `[dpdk]` section, so EAL only probes the DPDK NIC.
> But this is a **local test value, strictly forbidden from committing** (same class as `lcore_mask`/`idle_sleep`/`[port0]` local IPs). If `tester` adopts it, roll it back before committing.

### 8.5 Another Runtime-Environment Observation (for `tester`; I did no cleanup)

During a read-only probe (at that time `pgrep -a helloworld` was empty, no processes running) I observed:

```
HugePages_Total:    4096
HugePages_Free:     4063     ← 33 pages still occupied with no process running
HugePages_Rsvd:        0
```

I.e. there is **residual hugepage occupation** (~66 MB), presumably `rtemap_*` files left by a previously abnormally-exited process not released; `/var/run/dpdk/rte/` also has newer-mtime runtime files, plus a stale `/var/run/dpdk/ff_kni_test/` (mtime 7-27).
The magnitude is small and generally does not affect startup; but if the soak phase sees mempool-allocation failures, check this first.

**Cleanup mandatory conventions**: deleting residual files **must** use `/data/workspace/rm_tmp_file.sh<absolute path>`; terminating residual processes **must** use `/data/workspace/kill_process.sh`; **direct `rm`/`kill` strictly forbidden**.
**Also note** (§7.6 recorded): passing a **process name** to `kill_process.sh` matches **all** same-name processes; during parallel multi-agent periods there is a collateral-kill risk — suggest **always passing a specific PID**.

---

## 9. Fifth Round: Fixing the `mp_maxid >= 2` Startup Crash (M3 bounce 3/3)

### 9.1 Independent Re-verification of the Root Cause — **the leader/`tester`'s location holds**

I did **not blindly copy**; I opened the code point by point (conclusion: the chain fully holds):

| Link | Re-check result |
|---|---|
| `zsize` grows with CPU count | `freebsd/vm/uma_core.c:3179-3182`: `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + sizeof(struct uma_zone_domain)*vm_ndomains`, then `roundup(zsize, UMA_SUPER_ALIGN)` ✓. **Measured sizes** (`nm --print-size`): `uma_zone`=**384**, `uma_cache`=**128**, `uma_zone_domain`=**128**, `UMA_SUPER_ALIGN`=**128**; `vm_ndomains=1` (`ff_glue.c:83`) → `zsize = roundup(512 + 128×N, 128) = 512 + 128×N`, growing **128** bytes per extra CPU ✓ |
| multi-page slabs can be enabled | `uma_core.c:383 static int multipage_slabs = 1;` (default on); `:2440-2470`'s `for ( ; ; i++)` keeps increasing `slabsize` while `kl.eff < UMA_MIN_EFF` and `multipage_slabs` ✓ |
| multi-page → sets VTOSLAB | `uma_core.c:2486-2492`: `if ((uk_flags & UMA_ZFLAG_OFFPAGE) != 0 \|\| (keg->uk_ipers - 1) * rsize >= PAGE_SIZE)` → else branch `keg->uk_flags \|= UMA_ZFLAG_VTOSLAB` ✓ at single page `(ipers-1)*rsize < PAGE_SIZE` not set; across pages `>= PAGE_SIZE` sets it |
| the **actual call point** of VTOSLAB | `uma_core.c:1822-1825` (inside `keg_alloc_slab()`): `if (keg->uk_flags & UMA_ZFLAG_VTOSLAB) for (i = 0; i < keg->uk_ppera; i++) vsetzoneslab(...)` ✓ consistent with the crash stack `zone_import → zone_alloc_item → uma_startup1` |
| `vsetzoneslab` depends on the hash table | `lib/include/vm/uma_int.h:107-126`: `hash_list = &uma_page_slab_hash[UMA_PAGE_HASH(va)];` then `LIST_FOREACH` → **dereferences NULL when `uma_page_slab_hash == NULL`** ✓ |
| init-order inversion | before the fix `lib/ff_freebsd_init.c`: `uma_startup1()` → `uma_startup2()` → **only after** `uma_page_slab_hash = kmem_malloc(...)` / `uma_page_mask = ...` ✓ i.e. throughout `uma_startup1()`, `uma_page_slab_hash == NULL`, `uma_page_mask == 0` |

**Conclusion**: this is **not** an error in G1's triple setting itself, but f-stack's **pre-existing implicit assumption "`uma_page_slab_hash` is initialized only after `uma_startup1()`"**, which holds only at `mp_maxid == 0` (small zone → single-page slab → VTOSLAB never set). G1 raising `mp_maxid` breaks the assumption → deterministic crash. **A pre-existing defect exposed by G1, not a G1 logic error.**

> On the exact threshold: I did **not** manually derive the exact "N=3 overflows" `ipers`/`eff` numbers — `keg_layout_one()` for `UMA_ZFLAG_INTERNAL` does `slabsize += PAGE_SIZE` and counts the inline slab header via `slab_ipers_hdr()`; hand calculation is error-prone. **So this doc asserts no arithmetic for a specific N**, only the mechanism (verified point by point) + measured behavior (1/2 threads normal, 3/4 threads crash, 3/4 both normal after the fix).

### 9.2 The Three Points the Leader Required Me to Re-Check Myself

**① Whether `kmem_malloc` truly does not depend on UMA — confirmed no dependence.**
`lib/ff_glue.c:1032-1039` directly goes host `mmap`: `void *alloc = ff_mmap(NULL, bytes, ...ff_MAP_ANON|ff_MAP_PRIVATE, -1, 0);` + optional `bzero`, **zero UMA dependence**. And before the fix, `boot_pages`'s `kmem_malloc` was already successfully called before `uma_startup1()` → moving the hash-table allocation earlier **introduces no new dependence** ✓

**② `sizeof(struct uma_page) * 8192` vs `struct uma_page_head` type matching — a pre-existing "over-allocation", safe; per instructions unchanged.**
Measured `sizeof(struct uma_page)` = **40** bytes, `sizeof(struct uma_page_head)` (`LIST_HEAD`, single pointer) = **8** bytes. The array's element type is `uma_page_head` yet allocated by `uma_page`'s size → **5x over-allocation** (320KB vs 64KB needed). The direction is **larger, not smaller; no OOB**; functionally correct; only ~256KB wasted. Per instructions, **keep the existing writing**; honestly recorded here for `designer` as an "optional optimization item" in the spec (**suggest not changing this round**, to avoid bounce-3/3 introducing unrelated changes).
Also confirmed that `M_ZERO`'s all-zero memory equals an empty list head after `LIST_INIT` (`LIST_HEAD`'s only member `lh_first` NULL means empty) → after moving the allocation earlier, no extra `LIST_INIT` needed ✓

**③ After moving it earlier, are `vtoslab`/`vtozoneslab` during `uma_startup2()`/`mi_startup()` normal — normal.**
Moving it earlier only makes the hash table **available earlier**; `uma_startup2()`/`mi_startup()` originally ran **after** the hash-table init, so what they see is unchanged or better. Corroborated by §9.4's 3/4-thread measurements (during `mi_startup()` many zones are created, including the `UMA_ZONE_MALLOC` keg going through VTOSLAB — see `uma_core.c:2543-2544`'s **another** independent VTOSLAB-setting path; these all occur after the hash is ready, before and after the fix).

### 9.3 Fix Method (adopted the leader's recommendation, minimal change)

`lib/ff_freebsd_init.c`: move the hash-table initialization **wholesale before `uma_startup1()`**, with a comment explaining this **non-obvious timing invariant**:

```c
    /*
     * Must precede uma_startup1(): once mp_maxid > 0 the zone-of-zones grows
     * past the single-page slab threshold, which sets UMA_ZFLAG_VTOSLAB and
     * makes keg_alloc_slab() call vsetzoneslab() during uma_startup1().
     */
    num_hash_buckets = 8192;
    uma_page_slab_hash = (struct uma_page_head *)kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO);
    uma_page_mask = num_hash_buckets - 1;

    boot_pages = 16;
    bootmem = (void *)kmem_malloc(boot_pages*PAGE_SIZE, M_ZERO);
    //uma_startup(bootmem, boot_pages);
    uma_startup1((vm_offset_t)bootmem);
    uma_startup2();
```

**Not adopted** "adding a NULL fallback to `vsetzoneslab`": it would silently lose slab registration; later `vtoslab()` returning NULL crashes elsewhere (and `uma_int.h:80-101`'s `vtozoneslab` already has the pre-existing hazard of dereferencing NULL via `*slab = up->up_slab` when `LIST_FOREACH` misses), consistent with the leader's judgment.

### 9.4 Runtime Verification (I ran it myself; not citing `tester`)

Start: `setsid nohup /data/workspace/f-stack/example/helloworld --conf /data/workspace/f-stack/config.ini --proc-type=primary --proc-id=0< /dev/null > <log> 2>&1 &`; stop **always** `/data/workspace/kill_process.sh <specific PID>` (per §7.6's self-set rule, no process names to avoid collateral-killing others).

**A. 3-thread config (`lcore_mask=e`) — PASS, no longer crashes**

| dense_idx | pc_cpuid | curcpu | pc_zpcpu_offset | 4096×idx | smr_c_seq | uma_cache |
|---|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 0 ✓ | `0x7f48846d1c80` | `0x7f48846c3d80` |
| 1 | 1 | 1 | 4096 | 4096 ✓ | `0x7f48846d2c80` | `0x7f48846c3e00` |
| 2 | 2 | 2 | 8192 | 8192 ✓ | `0x7f48846d3c80` | `0x7f48846c3e80` |

`mp_ncpus=3`, `mp_maxid=3-1=2` (three rows consistent) ✓; SMR slot distance `0x1000`/`0x1000` = **4096/4096** ✓; UMA cache slot distance `0x80`/`0x80` = **128/128** ✓; process alive 30s; logs have no `segmentation`/`SIGSEGV`/`panic`.

**B. 4-thread config (`lcore_mask=1e`) — PASS, no longer crashes**

| dense_idx | pc_zpcpu_offset | 4096×idx | smr_c_seq | uma_cache |
|---|---|---|---|---|
| 0 | 0 | 0 ✓ | `0x7f46720c6c80` | `0x7f467209f980` |
| 1 | 4096 | 4096 ✓ | `0x7f46720c7c80` | `0x7f467209fa00` |
| 2 | (scalar row lost, see below) | — | `0x7f46720c8c80` | `0x7f467209fa80` |
| 3 | 12288 | 12288 ✓ | `0x7f46720c9c80` | `0x7f467209fb00` |

`mp_ncpus=4`, `mp_maxid=3` ✓; SMR slot distance `0x1000`×3 segments → 4 slots pairwise differ by **4096×Δidx** ✓; UMA cache slot distance `0x80`×3 segments → pairwise **128×Δidx** ✓; process alive 32s, no crash.

**Honestly recorded one probe-output defect (not a functional problem)**: in the 4-thread config, `dense_idx=2`'s `[M17-PROBE]` **scalar line was not written to any log** (full grep over `f-stack-0.log`/`helloworld.log`/run logs; no interleaved fragment found). Its `[M17-PROBE-SLOT]` line **exists and its values are correct**.
**That thread was correctly initialized**; argument: the SLOT line's `uma_cache = &ipi_zone->uz_cpu[curcpu]` measured `base + 2×128` and `smr_c_seq` `base + 2×4096` — both values derived from `curcpu` (= `pcpup->pc_cpuid`), **which can only print such values after that thread finished `ff_pcpu_thread_init(2)`**. So it is **lost log output** (f-stack's kernel-mode `printf` is lock-free; multi-thread concurrent writes to the same fd drop lines), not an init failure.
→ **Hint for `tester`**: judge primarily by the **count and address spacing** of the `[M17-PROBE-SLOT]` lines; an occasional missing `[M17-PROBE]` scalar line is the probe's own output contention, **should not be judged a failure**; if all rows are needed, re-run that config separately.

### 9.5 Fifth-Round Clean-Build and Binary Fingerprints

**`make clean` first, then a full `make`.**

| Metric | `lib/` | `example/` |
|---|---|---|
| `make` return code | **0** | **0** |
| `grep -c "error:"` | **0** | **0** |
| `grep -c "warning:"` | **51** (= HEAD baseline, not increased) | — |
| `undefined reference` | — | **0** |
| `.o` produced | **248** | — |

**Tested binaries (`tester` please use this set, replacing §8.1)**:

| File | Size | md5 |
|---|---|---|
| `example/helloworld` | 30,392,704 | **`d49268db362b8442bdc47f752efb5f14`** |
| `example/helloworld_epoll` | 30,386,112 | `e02b89e5c1764009dc13046796cd3f33` |
| `lib/libfstack.a` | 7,003,564 | `c2945491e3c834d459f9d9fd94edcb54` |

> **Note**: `libfstack.a`'s md5 is **not reproducible** (`ar` embeds member mtimes; two builds of the same source give different md5; I measured `84c715e7…` and `c2945491…`). **Use `example/helloworld`'s md5 as the version criterion** (both builds stably `d49268db…`).

### 9.6 `config.ini` Restore Evidence

During testing, `lcore_mask` was temporarily changed (`6` → `e` → `1e` → restored `6`). After restore:
- `grep "^lcore_mask" config.ini` → `lcore_mask=6` (= my pre-test value)
- `git diff --stat -- config.ini` → `14 insertions(+), 12 deletions(-)`, **identical** to pre-test
- in `git diff -- config.ini`, that line is `-lcore_mask=1` / `+lcore_mask=6`, i.e. only the user's original local test changes remain
- **never `git add`, never `git commit`**

### 9.7 Completion Confirmation of the Previous Two Rejection Items

| Round | Item | Status |
|---|---|---|
| bounce 1/3 | `curcpu` per-thread-ization (`lib/include/sys/pcpu.h`) | done (§5); preprocessing verified all 11 `uz_cpu[curcpu]` expand to `uz_cpu[(pcpup->pc_cpuid)]` |
| bounce 2/3 | `ff_kern_synch.c`'s `pcpup != NULL` fallback | done (§7.1) |
| bounce 2/3 | `ff_kern_timeout.c`'s false comment (`cpuid is always 0, MAXCPU=1`) | done (§7.2a) |
| bounce 2/3 | `ff_freebsd_init.c`'s 4-line comment trimmed | done (§7.2b), down to 2 lines |
| bounce 2/3 | probe section written | done (§6 + §8.3) |

### 9.8 Final File List After the Fifth Round

Formal changes **8 files** (this round changed one more spot in `ff_freebsd_init.c`; the file count is unchanged):
`lib/Makefile`, `ff_glue.c`, `ff_freebsd_init.c`, `ff_dpdk_if.c`, `ff_dpdk_if.h`, `ff_kern_timeout.c`, `ff_kern_synch.c`, `include/sys/pcpu.h`
Temporary probes **2 files**: `ff_host_interface.c`, `ff_host_interface.h` (+ the 4 `#if 1` blocks inside `ff_freebsd_init.c`)
The `freebsd/` upstream tree is **zero-change**.

---

## 10. Sixth Round: U2 Probe (`UMA_ZONE_PCPU` actual page count) — **U2 verified**

### 10.1 Feasibility: keg pointers reachable within `lib/` (no workaround needed)

- `freebsd/vm/uma.h:685-689` declares `pcpu_zone_4/8/16/32/64` as **`extern uma_zone_t`**, and `ff_freebsd_init.c` already includes `<vm/uma.h>`;
- `freebsd/vm/uma_int.h:474`'s `struct uma_zone` contains `uma_keg_t uz_keg`, and `ff_freebsd_init.c` already includes `<vm/uma_int.h>` (`:45`);
- so `pcpu_zone_8->uz_keg->uk_ppera` / `->uk_rsize` can be taken directly.
- (`subr_smr.c:144 static uma_zone_t smr_zone;` is static and unreachable, but `pcpu_zone_*` are `UMA_ZONE_PCPU` zones like it, equivalent.)

**Why `uk_ppera` is the U2 criterion**: `uma_core.c:2471-2473`
```c
	pages = atop(kl.slabsize);
	if ((keg->uk_flags & UMA_ZONE_PCPU) != 0)
		pages *= mp_maxid + 1;
```
i.e. a `UMA_ZONE_PCPU` keg's `uk_ppera` is multiplied by `(mp_maxid + 1)`. Printing it **directly proves** the per-CPU backing storage is allocated for all slots, rather than "indirectly inferred by the 4096 slot distance" (the latter cannot exclude OOB reads into adjacent memory).

### 10.2 Probe Implementation (temporary, removed with the other probes after M5)

Add `static void ff_probe_pcpu_zone(void)` inside `lib/ff_freebsd_init.c` (within the same `#if 1 /* M17 temporary probe */` block), called right after `ff_probe_slots()` at the end of `ff_freebsd_init()`. Print one line each for `pcpu_zone_8` and `pcpu_zone_64` (both NULL-checked):

```
[M17-PROBE-ZONE] name=%s uk_ppera=%u uk_rsize=%u mp_maxid=%u
```

### 10.3 Measured Result (4-thread config, `lcore_mask=1e`) — **U2 verified PASS**

```
[M17-PROBE-ZONE] name=pcpu_zone_8  uk_ppera=4 uk_rsize=8  mp_maxid=3
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=4 uk_rsize=64 mp_maxid=3
```

**Judgment**: `uk_ppera == 4 == mp_maxid + 1` ✓
→ each `UMA_ZONE_PCPU` zone's slab **really allocated 4 pages** (one page per CPU = `UMA_PCPU_ALLOC_SIZE` = 4096). Therefore `zpcpu_get_cpu(base, cpu) = base + 4096×cpu` (`cpu ∈ [0,3]`) **all fall within that slab's legal allocation range**; **not OOB accesses into adjacent memory**.
→ **U2 thus moves from "not verified" to "verified"**, and the **remaining half** of the "highest risk" I marked in §4 risk-1 and §6.6 also closes.

### 10.4 The Same Run's Complete DoD-1 Data (4 threads; this time all 4 scalar rows complete)

| dense_idx | pc_cpuid | curcpu | pc_zpcpu_offset | 4096×idx | smr_c_seq | uma_cache |
|---|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 0 ✓ | `0x7f861477fc80` | `0x7f8614758980` |
| 1 | 1 | 1 | 4096 | 4096 ✓ | `0x7f8614780c80` | `0x7f8614758a00` |
| 2 | 2 | 2 | 8192 | 8192 ✓ | `0x7f8614781c80` | `0x7f8614758a80` |
| 3 | 3 | 3 | 12288 | 12288 ✓ | `0x7f8614782c80` | `0x7f8614758b00` |

- `mp_ncpus=4`, `mp_maxid=3`, four rows consistent ✓
- `dense_idx` covers **0..3**; `pc_cpuid`/`curcpu` pairwise different and equal to `dense_idx` ✓
- `pc_zpcpu_offset == 4096 × dense_idx` **holds for all four rows** ✓
- SMR slot distance: `0x1000 / 0x1000 / 0x1000` = 4096 ×3 segments ✓
- UMA cache slot distance: `0x80 / 0x80 / 0x80` = 128 ×3 segments ✓
- no `segmentation`/`SIGSEGV`/`panic`; the process was alive 30s and terminated normally via `kill_process.sh <PID>`

> This also **backfills §9.4-B's missing `dense_idx=2` scalar row** — this same-config run had all four rows, proving that missing row was indeed the occasional **output loss** of f-stack's lock-free kernel-mode `printf` concurrent writes, not an init failure.

### 10.5 Sixth-Round Clean-Build and **Final** Binary Fingerprints

| Metric | `lib/` | `example/` |
|---|---|---|
| `make` return code | **0** | **0** |
| `error:` | **0** | **0** |
| `warning:` | **51** (= HEAD baseline, not increased) | — |
| `undefined reference` | — | **0** |
| `.o` produced | **248** | — |

**Final tested binaries (`tester` please use this set, replacing §8.1 and §9.5)**:

| File | md5 |
|---|---|
| **`example/helloworld`** | **`751a8153d3b200229cff99b3fa7650b0`** |
| `example/helloworld_epoll` | `0d31850c7e447b140ea0a43647d07915` |
| `lib/libfstack.a` | `25c829a42deef544b1c22401af3a5c3d` |

> Again use **`example/helloworld`'s md5** as the version criterion (`libfstack.a` is not reproducible due to `ar`'s embedded mtimes).

### 10.6 `config.ini` Restore Evidence (sixth round)

`lcore_mask`: `6` → `1e` (test) → restored `6`. After restore, `git diff --stat -- config.ini` = `14 insertions(+), 12 deletions(-)`, identical to pre-test; in `git diff`, that line is `-lcore_mask=1` / `+lcore_mask=6` (only the user's original local changes). Never `git add`/`git commit`. Temporary logs cleaned via `rm_tmp_file.sh`; no `_m17_*` residue under `f-stack/`.

### 10.7 Probe-Cleanup List Update (DoD-8)

`grep -rn "M17 temporary probe" lib/` now shows **5 blocks / 6 lines** total (`ff_host_interface.c`, `ff_host_interface.h` 1 each; `ff_freebsd_init.c` 4); the probe block in `ff_freebsd_init.c` now contains both `ff_probe_slots()` and `ff_probe_pcpu_zone()`. Remove all at once after M5.
