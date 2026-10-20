# M17-B External Research: SMP-aware per-CPU Views / SMR Exclusivity / Userspace per-CPU Emulation / Removing the Global Lock

> Researcher: `res-web` (external cross-research agent, team `ff-smp-aware`)
> Date: 2026-08-04
> Task source: team-lead (plan-17 M1-B)
> The previous external research (`_m1_B_external.md`) was on **virtio-net multi-queue inbound distribution**; no overlap with this round, and this document does not repeat its content.
>
> **Boundary declaration**:
> 1. This agent **modified no source code**, only wrote this file.
> 2. Every conclusion is followed by `Source: <URL>`. Anything that is **mechanism derivation** (not direct literature statements) is explicitly marked.
> 3. Statements that may conflict with f-stack's actual code are marked "**needs code cross-validation (code wins)**".
> 4. Items with no reliable source are honestly written "**no reliable source found**", with no fabricated URLs or content.
>
> **Progress**: this document was written in batches. Current status is in the "Write Progress" section at the end.
> **Section-order note**: section numbers `§1~§5` correspond to team-lead's 5 research directions (numbers kept unchanged for cross-reference). Because it was written in two batches, the physical order is **§1 → §2 → §5 → §3 → §4 → §6 (knowledge boundaries) → §7 (source list)**.

---

## 0. TL;DR (mapped to plan-17's U numbering)

| # | Conclusion | Confidence | Section |
|---|---|---|---|
| E1 | **SMR's per-CPU `c_seq` slot exclusivity is a hard assumption**, and upstream doubly guarantees it with `critical_enter()` (preemption + migration disabled) + `KASSERT(c_seq == 0)` (no recursion). When two threads share the same `c_seq` slot, **in a non-INVARIANTS build the assertion is compiled out**, thread A's `smr_exit()` clears thread B's still-in-read-section `c_seq` to `SMR_SEQ_INVALID` → `smr_poll_scan()` judges that CPU inactive → advances `s_rd_seq` early → **UMA reuses memory early → UAF**. This fully matches plan-17 §0.1's "theoretical UAF window" judgment, and can be verified line-by-line in upstream source | High (upstream source original + man page) | §2.1, §2.2 |
| E2 | `smr_enter()`/`smr_exit()` **themselves contain** `critical_enter()`/`critical_exit()`; callers do **not** need extra preemption-disabling; the man page explicitly says "context switching is disabled within the read section, the thread is pinned to the current CPU" | High (smr.h source + smr(9)) | §2.2 |
| E3 | `UMA_ZONE_PCPU` semantics: "one allocation produces `mp_ncpus` shadow copies"; uma(9) **explicitly requires `zpcpu_get()` to be accessed within `critical_enter()/critical_exit()`**. This means G2 (removing `uma_crit_lock`) cannot be simply equated with "upstream has no lock either" — upstream has preemption-disabling, f-stack userspace does not; equivalence must be argued separately | High (uma(9) original example code) | §2.3 |
| E4 | `smr_create()`'s `for (i = 0; i <= mp_maxid; i++)` and `smr_poll_scan()`'s `CPU_FOREACH(i)` are the upstream basis for "`mp_maxid` and `UMA_ZONE_PCPU` must be modified in pairs"; `counter(9)`'s `counter_u64_fetch()` also "traverses all per-CPU fields" | High (upstream source + counter(9)) | §2.4, §2.5 |
| E5 | **Userspace `MAXCPU` being 1 is FreeBSD upstream's deliberate design**: the official commit message states directly: "in userspace `MAXCPU` is usually 1 because setting it to a larger machine-dependent value is conditioned on defining `SMP`, which userspace generally does not." This is exactly the cause of f-stack's current state (`#else → MAXCPU 1`) | High (FreeBSD official commit message original) | §5.1 |
| E6 | `cpuset_t` width is determined by `CPU_SETSIZE`; **kernel-side `CPU_SETSIZE == MAXCPU`**; changing `MAXCPU` changes `cpuset_t`'s struct size → changes the layout of every struct containing `cpuset_t` → **KBI break**, requiring a full-tree rebuild. When FreeBSD officially raised amd64 MAXCPU from 256 to 1024, it was done in one shot before the 14.0 release precisely because of ABI/KBI stability constraints | High (cpuset(9) + commit + official quarterly report) | §5.2, §5.3 |
| E7 | f-stack official repo: **no issue or PR discussion found at all** about SMR / UMA per-CPU slots / `pcpu_init` cpuid / MAXCPU / defining SMP. The only relevant issue found (#27, 2017) is 7 years old, based on FreeBSD 11, "running the protocol stack single-process multi-threaded → `curthread` NULL → segfault", **different era and code base from this round**, and the comment section could not be fetched | Medium-high (multiple searches no result + a single old issue) | §1 |
| E8 | "How other userspace FreeBSD/NetBSD stacks fake a per-CPU view" — **some directions have no reliable source**, see per-item markings in §3 | — | §3 |

---

## 1. Direction 1: f-stack Official/Community Discussions on "Single-Process Multi-Thread", "per-CPU", "UMA/SMR"

### 1.1 The Only Directly Relevant Issue Found: #27 (2017-06-05, Closed)

**Source**: https://github.com/F-Stack/f-stack/issues/27

Fetched issue **body** key points (paraphrased from the original):

- The asker (`taoswords`) concluded from `start.sh` that f-stack is a "single-process single-core-bound" model and tried to change it to "1 process + multi-core + multi-thread":
  `sudo ./demo ./config.ini -c 0x3 --proc-type=primary --num-procs=1 --proc-id=0`
- The protocol stack **segfaulted**.
- GDB conclusion: the **`curthread`** passed to `ff_syscall_wrapper` is 0 (NULL); calling `ff_epoll_create` → `ff_kqueue` on the slave core crashes.
- Question: why is `curthread` 0 on the slave core, and where is it assigned in the code.

**Important limitation (honestly declared)**: this fetch **only got the issue body; the comment section failed to load** (the page repeatedly showed "There was an error while loading. Please reload this page."). Therefore **the f-stack maintainers' specific reply cannot be confirmed; this document makes no speculation**.

> Relation to this round: #27's symptom (`curthread == NULL`) is the **per-thread `pcpup`/`curthread` not initialized** problem; f-stack's current state (`__thread struct pcpu *pcpup` + `ff_pcpu_thread_init()`) already solved that layer; this round solves the **deeper "pcpu slot sharing"** problem. **#27 cannot be a reference for this round's solution.**

### 1.2 f-stack Official Documentation on the pcpu/curthread Porting

**Source**: F-Stack Development Guide (community repost)
- https://rtoax.blog.csdn.net/article/details/107987976
- https://www.codeleading.com/article/50794435172/

That Development Guide explicitly lists in its "FreeBSD protocol-stack porting change points" checklist (original English items):

```
pcpu
curthread
proc0
thread0, initialization
```

And (Chinese community paraphrase, source below) the scope of changes:

> 1) Scheduling: removed kernel threads, interrupt threads, timer threads, sched, sleep, etc. from the FreeBSD Network Stack.
> 2) Locks: trimmed the various lock operations (mtx, rw, rm, sx, cond) of the FreeBSD Network Stack.
> 3) Memory management: refactored phymem, uma_page_slab_hash and other memory-management modules.
> 4) Globals: optimized pcpu, curthread and other global variables.

**Source**:
- https://blog.csdn.net/21cnbao/article/details/105803864 (2020-04-27)
- https://blog.csdn.net/gitblog_01019/article/details/148549951 (2025-06-10)
- https://zhuanlan.zhihu.com/p/376144528 (2021-05-28)

**Cross-validation significance**: these materials **corroborate that "f-stack deliberately trimmed and single-instance-ized UMA / pcpu / locks" is its original design orientation** (not an incidental defect), so plan-17 §1.4's practices — replacing `critical_enter/exit` with a global spinlock in `uma_int.h`, `#undef UMA_MD_SMALL_ALLOC`, the self-made `uma_page` hash — are consistent with that orientation.
**Needs code cross-validation (code wins)**: the above are second-hand Chinese blog summaries without `file:line`; the **specific scope** of "refactored uma_page_slab_hash" and "trimmed the various locks" must be pinned down by `res-code` in local code; blog descriptions are not authoritative.

### 1.3 Third-Party Practices of Making f-stack Multithreaded

- Zhihu《Turning F-Stack into a Multi-Threaded Library》(2025-02) — https://zhuanlan.zhihu.com/p/21075875679
  **This fetch failed (HTTP 403 Forbidden, Zhihu anti-crawler)**. The search-result snippet only shows background text like "F-Stack provides posix-api... but most existing applications are multithreaded", **nothing about per-CPU / UMA / SMR / MAXCPU**.
  **Honest declaration: the article body could not be obtained this time; no citation-level conclusions are made.**
- 《Using the Photon Coroutine Library with F-Stack to Simplify DPDK Application Development》 — https://developer.aliyun.com/article/1208390 (2023-05-10)
  That article goes the **coroutine / multi-execution-unit** direction, a different problem layer from "the per-CPU view of multiple threads sharing one protocol-stack instance". **Not a reference for this round.**

### 1.4 Searching "SMR / UMA per-CPU slots / pcpu_init cpuid / MAXCPU / -DSMP" in the f-stack Community

**No reliable source found.** Searches covered:
- GitHub F-Stack/f-stack issues and PRs (keyword combinations: `multi-thread` / `single process multiple cores` / `per-cpu` / `UMA` / `SMR` / `pcpu` / `MAXCPU` / `SMP` / `curthread`);
- f-stack.org official site and Development Guide;
- Chinese tech communities (CSDN / Zhihu / cnblogs / Jianshu / Tencent Cloud community / Aliyun developer community).

**Conclusion: no public material discusses "making f-stack's kernel view SMP-aware / giving each worker an independent pcpu slot / removing the UMA global spinlock".** This round is a no-precedent change; **do not expect external sources to provide a ready-made solution; local code evidence is the only basis**.

Also note an **era fact**: the f-stack official site and README describe its port as based on **FreeBSD 11.0 stable** (source: http://f-stack.org/ ; https://github.com/F-Stack/f-stack). This repo has been upgraded to **FreeBSD 15.0**. **SMR (GUS) was introduced in the FreeBSD 12/13 era (2019–2020, Jeffrey Roberson)** (copyright years in the §2 source originals), so **all FreeBSD-11-based f-stack public experience predates SMR** — explaining why the community has no precedent.
Source: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c (file header `Copyright (c) 2019,2020 Jeffrey Roberson`); http://f-stack.org/

---

## 2. Direction 2: FreeBSD Upstream Semantics (SMR / UMA_ZONE_PCPU / mp_maxid / MAXCPU)

> All source references in this section are from the raw text of the `main` branch of the official GitHub mirror `freebsd/freebsd-src` (`cgit.freebsd.org` has Anubis anti-crawling; fetch failed; switched to the mirror).
> **Needs code cross-validation (code wins)**: this repo's reference tree is `releng/15.0`, while the references below are from `main`. SMR's core logic shows no structural changes between 13→15→main (the key points referenced here — `critical_enter`/`c_seq`/`mp_maxid` loops), but **specific line numbers and details must be re-checked by `res-code` in `/data/workspace/freebsd-src-releng-15.0`**.

### 2.1 SMR's Exclusivity Assumption on the per-CPU `c_seq` Slot — Verified in Upstream Source

**Source**: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/sys/smr.h

`struct smr` (per-CPU state, allocated via `zpcpu`):

```c
struct smr {
    smr_seq_t    c_seq;      /* the write sequence observed by this CPU; 0 (SMR_SEQ_INVALID) = not in a read section */
    smr_shared_t c_shared;
    int c_deferred, c_limit, c_flags;
};
```

`smr_enter()` original (key three lines):

```c
static inline void
smr_enter(smr_t smr)
{
    critical_enter();/* ① disable preemption, pin the thread to the current CPU */
    smr = zpcpu_get(smr);                /* ② fetch this CPU's struct smr */

    KASSERT((smr->c_flags & SMR_LAZY) == 0, ...);
    KASSERT(smr->c_seq == 0, ("smr_enter(%s) does not support recursion.", ...));

#if defined(__amd64__) || defined(__i386__)
    atomic_add_acq_int(&smr->c_seq, smr_shared_current(smr->c_shared));
#else
    atomic_store_int(&smr->c_seq, smr_shared_current(smr->c_shared));
    atomic_thread_fence_seq_cst();
#endif
}
```

`smr_exit()` original:

```c
static inline void
smr_exit(smr_t smr)
{
    smr = zpcpu_get(smr);
    CRITICAL_ASSERT(curthread);
    KASSERT((smr->c_flags & SMR_LAZY) == 0, ...);
    KASSERT(smr->c_seq != SMR_SEQ_INVALID, ("smr_exit(%s) not in a smr section.", ...));

    atomic_store_rel_int(&smr->c_seq, SMR_SEQ_INVALID);   /* unconditionally clear to INVALID */
    critical_exit();
}
```

**Three hard pieces of evidence for the exclusivity assumption**:

1. **The x86 fast path relies on "on entry `c_seq` must be 0"**. The source comment explains: because `SMR_SEQ_INVALID == 0`, on entering a read section `c_seq` is necessarily 0, so one `atomic_add_acq_int` (locked add) can simultaneously "write the sequence" and "provide a total-order barrier".
   → **If the slot is shared**: when thread B enters, `c_seq` was already set non-0 by thread A; `atomic_add` **adds A's sequence + B's sequence**, producing a **completely meaningless sequence value** (neither what B wants to observe nor A's value). This is worse corruption than "overwrite": the value may be far larger than `s_wr_seq`.
   > Marked as "source-semantics derivation": the source comment establishes the causal relation between the premise "on entry must be 0" and the `atomic_add` optimization; "under a shared slot the add accumulates into garbage" is the direct arithmetic consequence when that premise is violated, **a derivation, not a direct literature statement**. **Needs code cross-validation (code wins)**: f-stack's compile target is amd64, so it takes exactly the `atomic_add_acq_int` branch; `res-code` must confirm the `__amd64__` branch is indeed compiled in.

2. **The no-recursion assertion**: `KASSERT(smr->c_seq == 0, "does not support recursion")`. `c_seq` has only "0 / non-0" two states, **no nesting counter**. Two threads sharing a slot is semantically equivalent to "recursive entry" — which upstream explicitly forbids.
   → **The fatal point**: `KASSERT` compiles to nothing in a build **without `INVARIANTS`** (plan-17 §1.2 already verified f-stack does not define `INVARIANTS`), so this assertion that should have caught the problem **does not exist** in f-stack; corruption only appears as silent memory damage.

3. **`smr_exit()` unconditionally clears `SMR_SEQ_INVALID`**, with no "was it me who entered" check.
   → **UAF chain (derivation, but every link has source support)**:
   `worker A: smr_enter()` → `c_seq = S1`
   `worker B: smr_enter()` → `c_seq = S1 + S2` (or overwritten to `S2` on non-x86 paths)
   `worker A: smr_exit()` → `c_seq = SMR_SEQ_INVALID` (**B is still in the read section**)
   writer `smr_poll()` → `smr_poll_cpu()` sees `c_seq == SMR_SEQ_INVALID` → `break`, that CPU judged **inactive** (equivalent to "already observed wr_seq") → `smr_poll_scan()` advances `s_rd_seq` to `s_wr_seq` → `uma_zfree_smr()` judges the grace period over → **memory reused while B still holds a pointer to it → UAF**.

**`smr_poll_cpu()` original (proving "INVALID ⇒ that CPU has no active readers")**:

```c
static smr_seq_t
smr_poll_cpu(smr_t c, smr_seq_t s_rd_seq, smr_seq_t goal, bool wait)
{
    smr_seq_t c_seq;

    c_seq = SMR_SEQ_INVALID;
    for (;;) {
        c_seq = atomic_load_int(&c->c_seq);
        if (c_seq == SMR_SEQ_INVALID)
            break;                       /* ← judge that cpu not in a read section */
        ...
    }
    return (c_seq);
}
```

And in `smr_poll_scan()`:

```c
        if (c_seq != SMR_SEQ_INVALID)
            rd_seq = SMR_SEQ_MIN(rd_seq, c_seq);   /* INVALID cpus do not participate in pulling down rd_seq */
```

Source (all three excerpts): https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c

**Consistency with plan-17 §0.1**: plan-17 wrote "SMR's per-CPU sequence numbers are overwritten by multiple threads, possibly concluding the grace period ended early and recycling still-referenced PCBs" — **direction fully correct**. This section supplements: on amd64 the mechanism is not simply "overwrite" but `atomic_add` **accumulation**, and the more direct path triggering early reclamation is **`smr_exit()` clearing another in-read-section thread's slot to INVALID**. Suggested that spec 17 adopt the latter description (more precise and verifiable line-by-line).

### 2.2 Does `smr_enter/smr_exit` Require Preemption-Disabling, and Why

**Answer: yes, and `smr_enter()` itself does `critical_enter()`; callers need no extra.**

The smr(9) man page (FreeBSD 15.0, 2023-01-17, author Mark Johnston; algorithm author Jeff Roberson) states clearly in the Readers section:

- **context switching is disabled** within the read section;
- readers therefore **cannot acquire blocking mutexes** (such as `mutex(9)`);
- a direct consequence is **the thread is pinned to the current CPU for the entire read section** (no thread migration);
- `smr_enter()` **never blocks**; it has acquire semantics, `smr_exit()` has release semantics;
- `smr_enter()`/`smr_exit()` **only operate on per-CPU data**, which is the source of their performance advantage; writers must **scan all CPUs' per-CPU state** to detect active readers.
- **Nesting is not allowed**.

Source: https://man.freebsd.org/cgi/man.cgi?query=smr&sektion=9&manpath=FreeBSD+15.0-RELEASE

**Why it is needed** (the `smr.h` source comments focus on memory ordering and do not discuss critical-section necessity verbatim; the following three are **source-based generalizations**, marked as derivations):

1. **Guarantee that `smr_enter()` and `smr_exit()` operate on the same per-CPU state**. If the thread is preempted and migrates to another CPU between them, `zpcpu_get()` returns a **different** `struct smr`: one side leaves a non-zero `c_seq` residue (permanently blocking `rd_seq`, unbounded memory growth), the other side gets wrongly zeroed (early reclaim → UAF).
2. **Guarantee that read sections are short and bounded**. `smr_poll_scan()` takes the minimum of each CPU's `c_seq` to decide the reclaimable sequence; if a reader can be scheduled out for a long time, `rd_seq` gets stuck.
3. **Constrain usage**: within the critical section one may not sleep or take sleepable locks, making the "0/non-0" two-state `c_seq` design safe.

The write side also relies on the critical section, and upstream gives an **explicit reason comment**:

```c
    /*
     * Use a critical section so that we can avoid ABA races
     * caused by long preemption sleeps.
     */
    success = true;
    critical_enter();
```
(`smr_poll()`)

And `smr_advance()`:

```c
    SMR_ASSERT_NOT_ENTERED(smr);
    atomic_thread_fence_rel();
    critical_enter();
    self = zpcpu_get(smr);
    ...
    critical_exit();
```

While `smr_lazy_advance()`, `smr_default_advance()`, `smr_poll_scan()` all start with **`CRITICAL_ASSERT(curthread)`** — i.e. upstream wrote "must be in a critical section" as an assertion.
Source: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c

> **Direct implication for G2 (important)**: plan-17 §1.4 records that f-stack replaces the `critical_enter/exit` macros with a global spinlock in `lib/include/vm/uma_int.h`. If that override were **globally visible** (rather than limited to UMA translation units), then `smr.h`'s `critical_enter()` would also be replaced with grabbing the global lock — serializing **SMR read sections** too. **Needs code cross-validation (code wins)**: the **actual scope** of that macro override (whether `subr_smr.c`/`smr.h`'s translation units see it) must be verified by `res-code` with `gcc -E` preprocessing; this directly decides whether SMR read sections lose all protection after G2 removes the global lock.

### 2.3 `UMA_ZONE_PCPU` Semantics and the Precondition of `zpcpu_get`

uma(9) man page (FreeBSD 15.0, 2023-01-16) original key points:

- **`UMA_ZONE_PCPU` semantics**: **one allocation** from such a zone produces **`mp_ncpu` shadow copies**, each privately owned by one CPU.
- **Access method**: take the base address returned by the allocation plus "current CPU ID × `sizeof(struct pcpu)`" to get this CPU's copy; actual code uses the `zpcpu_get()` macro, and it **must be accessed within a critical section**. The man page's example code:

  ```c
  foo_zone = uma_zcreate(..., UMA_ZONE_PCPU);
  foo_base = uma_zalloc(foo_zone, ...);
  ...
  critical_enter();
  foo_pcpu = (foo_t *)zpcpu_get(foo_base);
  /* do something with foo_pcpu */
  critical_exit();
  ```

- **Restriction**: `M_ZERO` **cannot** be used with `uma_zalloc()` on PCPU zones; per-CPU memory needing zero-initialization must use the `uma_zalloc_pcpu()` family with `M_ZERO`.
- `uma_zalloc_pcpu()` / `uma_zfree_pcpu()` **allocate/free `mp_ncpu` shadow copies** per the above semantics.
- **`UMA_ZONE_SMR`**: items in the zone are synchronized with smr(9); a `smr_t` is automatically associated at creation, retrievable via `uma_zone_get_smr()`. `uma_zone_set_smr()` can associate an existing SMR structure, **must be called before any allocation from that zone**.
- `uma_zfree_smr()` **waits for all active readers that may be accessing the item to exit their read sections before reclaiming memory**.
- Each zone maintains **per-CPU caches** with linear scalability on SMP systems; the number of items cached in per-CPU caches is bounded; an unbounded cache quickly satisfies per-CPU cache misses.
- Reclaim semantics: `UMA_RECLAIM_DRAIN` empties the unbounded cache but **free items in per-CPU caches stay put**; `UMA_RECLAIM_DRAIN_CPU` additionally reclaims per-CPU caches.

Source: https://man.freebsd.org/cgi/man.cgi?query=uma&sektion=9&manpath=FreeBSD+15.0-RELEASE

**Three key implications for this round**:

1. **`mp_ncpus` and `mp_maxid` are the only basis for per-CPU allocation size**; plan-17 §1.3's constraint "`mp_maxid` and `UMA_ZONE_PCPU` must be modified in pairs" **receives positive support from official documentation**.
2. **The official docs explicitly require `zpcpu_get()` to be used in a critical section**. So G2 "removing `uma_crit_lock`" is documentation-semantically equivalent to "removing the protection upstream requires", and **must be argued by "each thread exclusively owns a slot + no thread migration"** (see §4), not by "upstream's UMA fast path is lock-free" — upstream's fast path is not unprotected; it relies on preemption-disabling.
3. `UMA_ZONE_SMR` + `uma_zfree_smr()`'s "wait for active readers" is exactly the last link of §2.1's UAF chain; **the semantics of the PCB reclaim path close here**.

### 2.4 Upstream Constraints of `mp_maxid` / `mp_ncpus` / `cpuid_to_pcpu[]`

**（a）`smr_create()` explicitly initializes by `mp_maxid` "all CPUS, not just those running"**:

```c
smr_t
smr_create(const char *name, int limit, int flags)
{
    ...
    s   = uma_zalloc(smr_shared_zone, M_WAITOK);
    smr = uma_zalloc_pcpu(smr_zone, M_WAITOK);

    s->s_name = name;
    s->s_rd_seq = s->s_wr.seq = SMR_SEQ_INIT;
    s->s_wr.ticks = ticks;

    /* Initialize all CPUS, not just those running. */
    for (i = 0; i <= mp_maxid; i++) {
        c = zpcpu_get_cpu(smr, i);
        c->c_seq = SMR_SEQ_INVALID;
        c->c_shared = s;
        c->c_deferred = 0;
        c->c_limit = limit;
        c->c_flags = flags;
    }
    atomic_thread_fence_seq_cst();
    return (smr);
}
```

`smr_init()`:

```c
void
smr_init(void)
{
    smr_shared_zone = uma_zcreate("SMR SHARED", sizeof(struct smr_shared),
        NULL, NULL, NULL, NULL, (CACHE_LINE_SIZE * 2) - 1, 0);
    smr_zone = uma_zcreate("SMR CPU", sizeof(struct smr),
        NULL, NULL, NULL, NULL, (CACHE_LINE_SIZE * 2) - 1, UMA_ZONE_PCPU);
}
```

Source: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c
**Consistent with the `releng/15.0` facts recorded in plan-17 §1.3** (plan-17 records `:583-609`, `:625-632`), no conflict.

**（b）`smr_poll_scan()` uses `CPU_FOREACH(i)` + `zpcpu_get_cpu(smr, i)` to scan all CPUs**:

```c
    rd_seq = s_wr_seq;
    CPU_FOREACH(i) {
        c_seq = smr_poll_cpu(zpcpu_get_cpu(smr, i), s_rd_seq, goal, wait);
        if (c_seq != SMR_SEQ_INVALID)
            rd_seq = SMR_SEQ_MIN(rd_seq, c_seq);
    }
```

Source: same as above.

> **Key implication for this round (needs code cross-validation, code wins)**: `CPU_FOREACH` upstream depends on the `all_cpus` cpuset and `CPU_ABSENT`. plan-17 §1.2 records f-stack defines `cpuset_t all_cpus;` (BSS zero) around `lib/ff_glue.c:143-147`. **If `all_cpus` is all-0, then `CPU_FOREACH` may traverse no CPU at all** (depending on its non-SMP expansion) — then `smr_poll_scan()` advances `rd_seq` directly to `s_wr_seq`, **equivalent to "SMR completely disabled, immediate reclamation"**, far more severe than "slot sharing". `res-code` **must** use `gcc -E` to pin down `CPU_FOREACH`'s actual expansion under f-stack's non-SMP build and verify whether `all_cpus` is initialized. This is **this round's highest-priority to-be-verified item** (this document marks it as derivation, no conclusion).
> Upstream `CPU_FOREACH` is defined in `sys/sys/smp.h` (not `sys/cpuset.h`) — the cpuset(9) man page's macro list does **not** include `CPU_FOREACH`, corroborating this.
> Source: https://man.freebsd.org/cgi/man.cgi?query=cpuset&sektion=9&manpath=FreeBSD+15.0-RELEASE

**（c）`zpcpu_offset_cpu` / `pcpu(9)`**:
**The `pcpu(9)` man page was not found** (no such section-9 page on man.freebsd.org; smr(9)/uma(9)/counter(9)/cpuset(9) all exist). The semantics of `zpcpu_get`/`zpcpu_get_cpu`/`zpcpu_offset_cpu` **have source code as the only authoritative reference** (`sys/sys/pcpu.h`); plan-17 §1.1 already recorded them with `file:line`; not repeated here. **Honest declaration: no man page exists for pcpu(9).**

### 2.5 `counter(9)`: Semantics of Another per-CPU Consumer (corresponds to plan-17 §1.4's end)

counter(9) man page (FreeBSD 15.0, 2025-06-19, authors Gleb Smirnoff / Konstantin Belousov) original key points:

- counters are implemented by **per-CPU data fields**, specially aligned to avoid false sharing; **allocation uses `UMA_ZONE_PCPU` uma(9) zones**.
- Updates **only touch the current CPU's private field**, so concurrent updates are **lossless**, without atomic(9), usable in any non-interrupt context.
- `counter_u64_add()` architecture differences:
  - **amd64**: the update is a **single instruction without lock semantics** on the current CPU's private data, therefore **naturally safe against preemption and interrupts**;
  - i386: uses `cmpxchg8` when available, providing equivalent guarantees;
  - **some other architectures**: updating counters **requires critical(9) sections**.
- Bulk updates use `counter_enter()` / `counter_u64_add_protected()` / `counter_exit()`; `counter_enter()` **expands to a critical(9) section on some machines and a nop on others**.
- `counter_u64_fetch()`: **traverses all per-CPU fields** and sums them for a snapshot, not guaranteed to reflect a point-in-time value.
- `counter_u64_zero()`: zeroes (sysctl write zeroes it).

Source: https://man.freebsd.org/cgi/man.cgi?query=counter&sektion=9&manpath=FreeBSD+15.0-RELEASE

**Implications for this round**:
1. On amd64 `counter_u64_add()` is a **single non-lock instruction**, so **even if multiple threads share the same per-CPU slot, the worst consequence is "lost/inaccurate stat counts", not memory corruption**. This explains why plan-17 §1.4 lists counter as "must verify no-OOB and no under-count" rather than a crash risk.
2. `counter_u64_fetch()` traverses all per-CPU fields → **after `mp_maxid` is raised, if counter's per-CPU allocation did not grow in sync, fetch reads out of bounds**. Same class of problem as §2.4's "paired modification" constraint; must be in the U4 verification list.
3. `subr_smr.c` itself uses many counters (`COUNTER_U64_DEFINE_EARLY(advance)` / `poll` / `poll_scan` / `poll_fail`, and `counter_u64_add_protected()` inside `smr_poll_scan()`) — i.e. **SMR and counter are two per-CPU consumers on the same chain in f-stack, and must be changed together**.
Source: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c

### 2.6 SMR (GUS) Design-Document-Level Description — the Algorithm Comment at the Top of `subr_smr.c` (original excerpt)

Upstream writes SMR's design document directly in the source comment (**no separate design document or wiki page**; this document searched the FreeBSD wiki / mailing lists and found no standalone design document; **honest declaration: no reliable standalone SMR design document found; the source comment is the authoritative design description**).

Key original excerpts:

> **Global Unbounded Sequences (GUS)**
> This is a novel safe memory reclamation technique inspired by epoch based reclamation from Samy Al Bahra's concurrency kit which in turn was based on work described in: Fraser, K. 2004. Practical Lock-Freedom. PhD Thesis, University of Cambridge Computing Laboratory. And shares some similarities with: Wang, Stamler, Parmer. 2016 Parallel Sections: Scaling System-Level Data-Structures
>
> The basic approach is to maintain a monotonic write sequence number that is updated on some application defined granularity. **Readers record the most recent write sequence number they have observed.** A shared read sequence number records the lowest sequence number observed by any reader as of the last poll. **Any write older than this value has been observed by all readers and memory can be reclaimed.** Like Epoch we also **detect idle readers by storing an invalid sequence number in the per-cpu state when the read section exits.** Like Parsec we establish a global write clock that is used to mark memory on free.
>
> ... **Readers never advance any sequence number, they only observe them.**
>
> This mechanism is primarily intended to be used in coordination with UMA. By integrating with the allocator we avoid all of the callout queue machinery and are provided with an efficient way to batch sequence advancement and waiting. **The allocator accumulates a full per-cpu cache of memory before advancing the sequence.**

And the diagram's original text:

>```
>0                          UINT_MAX
>  | -------------------- sequence number space -------------------- |
>              ^ rd seq                            ^ wr seq
>              | ----- valid sequence numbers ---- |
>                ^cpuA  ^cpuC
>  | -- free -- | --------- deferred frees -------- | ---- free ---- |
> ```
> In this example cpuA has the lowest sequence number and poll can advance rd seq. **cpuB is not running and is considered to observe wr seq.**
> **Freed memory that is tagged with a sequence number between rd seq and wr seq can not be safely reclaimed because cpuA may hold a reference to it.** Any other memory is guaranteed to be unreferenced.

Source: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c

**"cpuB is not running and is considered to observe wr seq" is the most critical upstream sentence of this round**: it makes clear GUS's core assumption — **"a CPU's slot being INVALID ⟺ no active reader on that CPU"**. In f-stack's current state, multiple workers sharing one slot breaks the right half of this "⟺" (slot INVALID but still active readers) — **this is the root cause of the UAF, and it is a violation of GUS's fundamental algorithm invariant, not an implementation detail**.

Also note that the `SMR_LAZY` grace-period explanation in `subr_smr.c` depends on **hardclock / per-CPU periodic clock interrupts**:

> Hardclock is responsible for advancing ticks on a single CPU while **every CPU receives a regular clock interrupt.** The clock interrupts are flushing the store buffers and any speculative loads that may violate our invariants. Because these interrupts are not synchronized we must wait one additional tick in the future to be certain that all processors have had their state synchronized by an interrupt.

**Needs code cross-validation (code wins)**: f-stack userspace has **no "per-CPU periodic clock interrupt"** (plan-17's doc 15 "worker clock gap fix" is exactly this class of problem). If any zone in f-stack uses `SMR_LAZY`, its grace-period assumption **does not hold** in userspace. `res-code` should check whether the SMR actually used by f-stack is `SMR_LAZY` (`in_pcb.c`'s `ipi_smr` goes through `uma_zone_get_smr`; the default flags must be pinned down).

---

## 5. Direction 5: `cpuset_t` / `CPU_SETSIZE` ABI Impact of `MAXCPU` Changes; Why `#else` Hard-Sets MAXCPU to 1

> Numbering follows team-lead's direction numbers (directions 3, 4 in a later batch).

### 5.1 Why `MAXCPU` Is Always 1 in Userspace / Non-SMP — Directly Answered by a FreeBSD Official Commit Message

**Source**: FreeBSD commit `87767249233f` (stable/13, cherry-picked from main `8232a1eddadd`), author Brooks Davis, Author Date 2022-09-23, Reviewed by cem/jhb, Differential D36679
Link: https://lists.freebsd.org/archives/dev-commits-src-all/2022-September/017116.html

Original commit-message key points:

> The maximum CPU number representable by `cpuset_t` is determined by **`CPU_SETSIZE`**. In the kernel it is equal to **`MAXCPU`**; in userspace it equals **`CPU_MAXSIZE`** unless `CPU_SETSIZE` is defined first before including `sys/_cpuset.h`. `CPU_MAXSIZE` is **256**; **in userspace `MAXCPU` is usually 1 because setting it to a larger machine-dependent (MD) value is conditioned on defining `SMP` (which userspace generally does not)**.

**This is the official explanation of plan-17 §1.2's `freebsd/amd64/include/param.h:60-66` "`#ifdef SMP → MAXCPU 1024`; `#else → MAXCPU 1`"**: the large `MAXCPU` value is an **MD constant conditioned on `SMP`**; the `#else` branch's `MAXCPU 1` was originally the **degraded value for userspace compilation** (and historically non-SMP kernels), to keep `MAXCPU`-dimensioned static arrays from bloating in userspace.

That commit also describes a **trap** (original generalization): userspace code interpreting cpuset width by `MAXCPU` gets **1 instead of 256**, causing iteration, mask-operation, or assertion errors. **f-stack is exactly the hybrid scenario "compiling kernel code in userspace", naturally stepping on this trap** — fully corresponding to plan-17 §0.1's record "this build is non-SMP (`MAXCPU==1`, `mp_maxid==0`), UMA/SMR per-cpu arrays allocated for only 1 CPU → `zpcpu_get()` necessarily out of bounds".

The typical structure of `sys/sys/_cpuset.h` (given in that commit's analysis; **marked: an explanatory restatement of the header structure; the local `freebsd-src-releng-15.0/sys/sys/_cpuset.h` original wins**):

```c
#ifdef _KERNEL
#define CPU_SETSIZE   MAXCPU        /* kernel: follows the platform MAXCPU */
#endif
#define CPU_MAXSIZE   256           /* maximum possible ABI width */
#ifndef CPU_SETSIZE                 /* default when userspace does not define it */
#define CPU_SETSIZE   CPU_MAXSIZE   /* = 256 */
#endif
```

**A direct hint for candidate B (overriding `MAXCPU`)**: since `CPU_SETSIZE` has a `#ifndef` guard, **userspace can override by `#define CPU_SETSIZE <value>` before including `sys/_cpuset.h`** (the commit message explicitly mentions this mechanism). But warns: once the width changes, `cpuset_t`'s size changes; when interacting with the kernel, the matching `setsize` argument must be used, otherwise ABI mismatch.
> **Needs code cross-validation (code wins)**: f-stack is entirely userspace and does not interact with a real FreeBSD kernel, so the "kernel ABI mismatch" concern **does not apply**; but **"f-stack's own `lib/` and `example/` must use the same `CPU_SETSIZE`/`MAXCPU` and be fully rebuilt" still holds** (otherwise f-stack's internal struct layouts are inconsistent). This is the technical necessity of plan-17's mandatory convention 2 "run `make clean` then a full rebuild after code changes" in this round — **not process pedantry, but a KBI-level hard requirement**.

### 5.2 `cpuset_t` Width Is Determined by `CPU_SETSIZE` (cpuset(9) Official)

cpuset(9) (FreeBSD 15.0, footer 2025-08-07; macros by Jeff Roberson; man page by Conrad Meyer) original key points:

- the cpuset(9) macro family is built on **bitset(9)**, **one bit per CPU**.
- **the maximum number of CPUs representable by `cpuset_t` is `CPU_SETSIZE`**; an individual CPU is referenced by index **0 through `CPU_SETSIZE - 1`**.
- `CPUSET_FSET` with `CPUSET_T_INITIALIZER()` expresses "all CPUs set":
  ```c
  cpuset_t myset;
  myset = CPUSET_T_INITIALIZER(CPUSET_FSET);  /* all CPUs */
  ```
- CAVEATS: `CPU_FFS()` returns a **1-indexed** result (0 for an empty set); when passed as a `cpu_idx` to other macros, **1 must be subtracted first**.
- The man page **never mentions `MAXCPU`** (corrected to `CPU_SETSIZE` by the §5.1 commit), **nor includes `CPU_FOREACH`** (which is in `sys/sys/smp.h`).

Source: https://man.freebsd.org/cgi/man.cgi?query=cpuset&sektion=9&manpath=FreeBSD+15.0-RELEASE

**Implications for this round**:
- `MAXCPU: 1 → N` ⇒ `CPU_SETSIZE: 1 → N` ⇒ **`cpuset_t` goes from 1 bit (1 byte/1 long) to N bits** ⇒ the layout of every struct embedding `cpuset_t` (e.g. `struct pcpu`, a `struct thread`'s affinity fields, the `all_cpus` global) **changes**.
- Therefore candidate B "override `MAXCPU`" **is not a local change; it is a whole-tree KBI change**.
- `CPUSET_T_INITIALIZER(CPUSET_FSET)` is the **upstream idiom for initializing `all_cpus`**, usable as a reference for f-stack completing `all_cpus` (plan-17 U4). **Needs code cross-validation (code wins)**: whether and where f-stack's currently-BSS-zero `all_cpus` (plan-17 §1.2) should be initialized to `0..N-1` must be determined by `res-code` from `CPU_FOREACH`'s actual expansion.

### 5.3 FreeBSD's Official Experience Raising MAXCPU: Why "Large MAXCPU" Has a Cost and How ABI/KBI Constrains It

**Source**: FreeBSD quarterly status report 2023Q2《Increasing MAXCPU》, author Ed Maste (sponsored by the FreeBSD Foundation), last modified 2023-07-18; related review https://reviews.freebsd.org/D36838 (*amd64: Bump MAXCPU to 1024 (from 256)*)
Link: https://www.freebsd.org/status/report-2023-04-2023-06/maxcpu/

Original (English) key passages:

> The default amd64 and arm64 FreeBSD kernel configurations currently support a maximum of 256 CPUs. A custom kernel can be built with support for larger core counts by setting the MAXCPU kernel option. ...
> **A number of changes have been made to support a larger default MAXCPU, including fixing the userland maximum for cpuset_t at 1024. Changes have also been made to avoid static MAXCPU-sized arrays, replacing them with on-demand memory allocation.**
> Additional work is required to continue reducing static allocations sized by MAXCPU and addressing scalability bottlenecks on very high core count systems, but the goal is to release FreeBSD 14 with a **stable ABI and KBI** with support for large CPU counts.

**Four verifiable facts**:
1. amd64/arm64 **default `MAXCPU` is 256** (not 1024); 1024 is the target value pushed in 14.x.
   > **Needs code cross-validation (code wins)**: plan-17 §1.2 records f-stack's reference tree `freebsd/amd64/include/param.h`'s `#ifdef SMP` branch as `MAXCPU 1024`. This does not contradict "default 256" (256 was the state at the 2023 report; 1024 was the project's target, landed in `releng/15.0` as 1024), but **the concrete value is governed by the local `freebsd-src-releng-15.0`**.
2. **The userspace `cpuset_t` upper bound was fixed at 1024** (completed item) — i.e. upstream chose "decouple userspace from kernel `MAXCPU`", not "userspace follows `MAXCPU`".
3. **Upstream is systematically eliminating "static `MAXCPU`-sized arrays" in favor of on-demand allocation** — directly **referential for this round**: if candidate B only changes `MAXCPU` from 1 to N (N = worker count, typically ≤ 16), **the static-array bloat cost is negligible** — a natural advantage of the f-stack scenario over upstream (upstream must consider 1024 cores; f-stack only needs single-digit workers).
4. **ABI/KBI stability is upstream's biggest constraint**; it must be done in one shot before a major release.

**Enlightenment for this round's solution choice (derivation, marked as analysis not literature conclusion)**:
- Upstream's experience shows `MAXCPU` is a **compile-time constant and part of the KBI**. So candidate B (overriding `MAXCPU`) in f-stack must achieve: `lib/`, `example/`, and any user code including f-stack headers, **all fully rebuilt with the same `MAXCPU` definition**.
- Upstream's "the main cost of large MAXCPU is static arrays and cache locality" indicates: setting `MAXCPU` to a **just-sufficient small value** (like 8/16/32) fits the f-stack scenario better than 1024 — getting dense slots while avoiding struct bloat. **But this does not constitute a judgment that candidate B beats candidate A** — candidate A (`-DSMP`) also activates `smp_rendezvous`/`ipi_*`/`sched_pin` paths, whose cost can only be quantified by `res-build` with the actual compile-error list (plan-17 U3).

---

## 3. Direction 3: How Other Userspace Kernel/Protocol-Stack Ports Handle "the per-CPU View Under Multi-Threading"

>This section has the **most direct reference value** of this round: two **highly isomorphic existing implementations of candidate B** were found (libuinet, rump kernel), both with source originals.

### 3.1 libuinet (FreeBSD 9.1 userspace stack) — **an existing implementation almost fully isomorphic to candidate B**

**Project positioning** (source: https://github.com/pkelsey/libuinet ):
- A userspace library port of the FreeBSD **9.1-RELEASE** TCP/IP stack, heavily borrowing Kip Macy's earlier **libplebnet**;
- Packet I/O via netmap or libpcap;
- README **does not describe** kernel-environment emulation, thread model, or SMP/per-CPU handling (**honest declaration: nothing relevant at the README level**), so all conclusions below come from **source originals**.

#### （a）`lib/libuinet/uinet_subr_smp.c`: A Complete Implementation of Userspace "Fake SMP"

**Source**: https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_smp.c
(copyright: Kip Macy 2010 / Patrick Kelsey 2013; comment notes `Derived in part from libplebnet's pn_glue.c.`)

Key facts (generalized from source original):

| Item | libuinet's approach |
|---|---|
| `mp_ncpus` | **an ordinary variable, assigned by external init code** (this file does not assign 1; BSS default 0) — i.e. **parameterized multiple "CPUs", not hardcoded 1 CPU** |
| `mp_maxcpus` | `= MAXCPU` (compile-time constant), comment `/* export this for libkvm consumers. */` |
| `mp_maxid` | only declared and exported via sysctl, **not assigned in this file**, set externally |
| `all_cpus` | in `mp_start()`, set bit by bit with `CPU_SET(i, &all_cpus)` in a loop (`i = 0 … mp_ncpus-1`); comment `/* This is used in modules that need to work in both SMP and UP. */` |
| `smp_started` | declared `volatile int`, **never set to 1** → kernel code depending on `if (smp_started)` all take the UP path |
| per-CPU storage | `pcpup = malloc(sizeof(struct pcpu) * mp_ncpus, M_DEVBUF, M_ZERO)`; on failure `panic("Failed to allocate PCPU space for %d cpus\n")` |
| dense-index init | loop `i`: `CPU_SET(i, &all_cpus)` → **`pcpu_init(&pcpup[i], i, sizeof(struct pcpu))`** → `malloc(DPCPU_SIZE, ...)` → `dpcpu_init(dpcpu, i)` → `mtx_init(&uinet_pcpu_locks[i], ...)` |
| registration timing | `SYSINIT(cpu_mp, SI_SUB_CPU, SI_ORDER_THIRD, mp_start, NULL);`; startup prints `"UINET multiprocessor subsystem configured with %d CPUs\n"` |
| missing SMP facilities | no `smp_rendezvous*`, no `stop_cpus/restart_cpus`, no `forward_signal`, no IPI, no `smp_topology`, no `kern.smp.active/cpus/disabled/topology` sysctls |
| a key XXX comment | in front of `uinet_pcpu_locks[MAXCPU]` (one `MTX_DEF｜MTX_RECURSE` mutex per CPU): **`/* XXX temporary until final pcpu approach is determined */`** |

**Direct value for this round (four points)**:

1. **Candidate B's approach has been practiced by libuinet and is its official implementation**: do not define `SMP` (`smp_started` always 0, no rendezvous/IPI), but **per-CPU storage slotted by `mp_ncpus` + `pcpu_init()` with dense index `0..N-1` + `all_cpus` set bit by bit**. This maps item-by-item to plan-17 §0.3 candidate B's four means (override `MAXCPU` / release `UMA_ZONE_PCPU` stripping / set `mp_ncpus`/`mp_maxid` / `pcpu_init` with dense index).
2. **`all_cpus` must be explicitly set**, which positively answers the concern raised by plan-17 U4 and this doc §2.4: libuinet explicitly writes the `CPU_SET(i, &all_cpus)` loop. **Needs code cross-validation (code wins)**: f-stack's current `all_cpus` is BSS zero (plan-17 §1.2); it must be completed, otherwise `CPU_FOREACH` semantics are unclear.
3. **`mp_maxcpus = MAXCPU` and `mp_ncpus` are two different quantities**, strictly distinguished by libuinet: `MAXCPU` is the compile-time upper bound (deciding `cpuset_t` width and static array sizes), `mp_ncpus`/`mp_maxid` are the runtime actual counts. Candidate B needs to handle **both**.
4. The **`XXX temporary until final pcpu approach is determined`** comment shows that even the libuinet author treats "userspace pcpu scheme" as an undecided difficulty, and **kept a per-CPU mutex as a safety net**.
   > ⚠️ **This item was partially corrected by §3.1(d) (2026-08-04 batch-2 supplementary verification)**: `uinet_pcpu_locks[MAXCPU]` **is unrelated to UMA** — libuinet's UMA uses **two other global locks** (`bucket_lock`, `page_slab_hash_lock`, see §3.1(d)). Therefore **the inference "libuinet protects UMA with one per-CPU lock" is wrong; the fallback path "G2 can degrade to one lock per worker" this doc originally proposed has no libuinet endorsement**. `uinet_pcpu_locks[]`'s real purpose was still not verified this round (does not appear in UMA-related files).

#### （b）`lib/libuinet/uinet_subr_pcpu.c`: Where cpuid Comes From + Userspace Handling of DPCPU

**Source**: https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_pcpu.c (copyright Patrick Kelsey 2013)

**（i）How cpuid is taken (direct reference for this round's U6)**:

```c
struct pcpu *
uinet_pcpu_get(void)
{
	KASSERT(curthread->td_oncpu < mp_ncpus,
		("curthread->td_oncpu >= mp_ncpus"));
	return (&pcpup[curthread->td_oncpu]);
}
```

Key points:
- The CPU number comes from **`curthread->td_oncpu`**, a **software-maintained "virtual CPU number"**, **not** a real hardware CPU number like `sched_getcpu()`/APIC ID/`rte_lcore_id()`;
- `pcpup` is an **array** (`&pcpup[...]`), so structurally supports `mp_ncpus > 1`;
- **with a `KASSERT(td_oncpu < mp_ncpus)` boundary assertion** — this is the **concrete practice** for team-lead's question "when binding `curcpu`/pcpu to TLS in userspace, how to guarantee the per-cpu array doesn't go out of bounds": **assert the upper bound at the only slot-access entry, with the upper bound being runtime `mp_ncpus` (not compile-time `MAXCPU`)**.
- The file has **no TLS at all** (no `__thread`, no `pthread_getspecific`); the location path is "thread → `curthread` → `td_oncpu` → array subscript". Whether `curthread` itself is TLS belongs to the thread layer; not in this file.

> **Difference from f-stack (important; `res-code` must rule)**: f-stack uses `__thread struct pcpu *pcpup;` (plan-17 §1.1, `ff_freebsd_init.c:85`), i.e. **directly puts the pcpu pointer in TLS**, while libuinet uses "`td_oncpu` subscript + global array".
> - f-stack's **advantage**: `PCPU_GET` has one less indirection and does not depend on `curthread` being initialized;
> - f-stack's **risk**: `pcpup` is **independently malloc'd** (plan-17 §1.1: `malloc(sizeof(struct pcpu),...)`), **not a member of one contiguous array**. But `zpcpu_get()` uses `pc_zpcpu_offset` (computed by `zpcpu_offset_cpu(cpuid)` in `pcpu_init`), **whose correctness only depends on cpuid's density and the per-CPU zone's allocation size, unrelated to whether `pcpup` itself is contiguous**. Therefore f-stack's TLS scheme and dense indexing **do not conflict**.
> - **But**: `subr_pcpu.c`'s `cpuid_to_pcpu[cpuid] = pcpu` and `STAILQ_INSERT_TAIL(&cpuhead,...)` (plan-17 §1.1 recorded `file:line`) chain these **scattered malloc'd pcpus** into the global table; whether readers of `pcpu_find()` and `cpuhead` traversal exist must still be exhaustively verified per plan-17 U5. **This document draws no out-of-bounds conclusion.**
> - **A portable "no-OOB" practice suggestion (analysis, not literature conclusion)**: following libuinet, add a **runtime upper-bound check** (`cpuid < mp_ncpus` and `cpuid <= mp_maxid`) in f-stack's `PCPU_*`/`zpcpu_*` override macros or `ff_pcpu_thread_init()`, failing with `panic`/`rte_exit`. More reliable than relying on the compiled-out `KASSERT(cpuid < MAXCPU)` (plan-17 §1.1 records `subr_pcpu.c:88`, void because `INVARIANTS` undefined).

**（ii）Userspace difficulty of DPCPU (f-stack may hit the same)**:

libuinet uses **runtime registration + manual assembly of a contiguous area** to replace the kernel's linker set:

```c
struct dpcpu_definition dpcpu_definitions[DPCPU_MAX_DEFINITIONS];
unsigned int dpcpu_num_definitions;
unsigned int dpcpu_total_size;
unsigned char *dpcpu_init_area;
```

`uinet_dpcpu_init()`: `malloc(dpcpu_total_size, M_DEVBUF, M_ZERO|M_WAITOK)` (on failure `panic("Could not allocate DPCPU init area\n")`) → iterate registered items `memcpy(&dpcpu_init_area[def->copyoffset], def->addr, def->copysize)`.

The only substantive comment in the file explains the motivation:

> "Copy all of the registered data structures to a contiguous area, as the implementation in subr_pcpu.c expects."

**Implication for this round**: kernel `DPCPU_DEFINE()` relies on the linker placing variables into a contiguous `set_pcpu` section (`DPCPU_START`/`DPCPU_STOP`); **a userspace shared library cannot reliably depend on such section layout**. plan-17 §1.1 already noted `subr_pcpu.c:252`'s `dpcpu_copy()` has an `#ifdef SMP` branch and `:269-287`'s `pcpu_destroy()` clears `dpcpu_off[]`.
**Needs code cross-validation (code wins)**: whether f-stack uses DPCPU (`DPCPU_DEFINE`/`DPCPU_GET`/`dpcpu_init`), and if so whether its linker set works in f-stack's static library, is a `res-code` verification item. If f-stack actually has DPCPU consumers going through `dpcpu_init(dpcpu, i)`, then **candidate B has one more per-CPU-count-sized allocation path besides UMA/SMR**. This doc only flags the risk, no conclusion.

#### （c）libuinet's Other Porting-Layer Files (for locating the same-class problems)

Directory `lib/libuinet/` contains these same-class glue files (source: https://github.com/pkelsey/libuinet/tree/master/lib/libuinet ):
`uinet_subr_pcpu.c`, `uinet_subr_smp.c`, `uinet_sched.c`, `uinet_kern_kthread.c`, `uinet_kern_proc.c`, `uinet_kern_synch.c`, `uinet_kern_intr.c`, `uinet_host_interface.c`, `uinet_uma_int.c` (UMA), `uinet_kern_mutex.c`/`rwlock`/`rmlock`/`sx`/`condvar`, and **`override_include/`** (a directory overriding FreeBSD headers, isomorphic to f-stack's `lib/include/` override mechanism).

**Note**: libuinet has a separate `uinet_uma_int.c`, i.e. it **also** does userspace rework of UMA. **Its content was not fetched this time**; **honest declaration: whether libuinet's UMA per-CPU cache is also locked/unlocked was not verified this round**. If the leader considers this point critical, `https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_uma_int.c` can be fetched additionally.

> **Major era-difference reminder**: libuinet is based on **FreeBSD 9.1**, which **has no SMR** (SMR introduced 2019–2020). So libuinet only solved the pcpu/UMA layer; **no precedent exists at the SMR layer**. f-stack 15.0's SMR problem **does not exist in libuinet** and cannot be validated from libuinet.

#### （d）`lib/libuinet/uinet_uma_int.c`: How libuinet Actually Protects UMA — **Verified (supplementary batch, directly useful for the G2-form ruling)**

**Source**: https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_uma_int.c (copyright Patrick Kelsey 2013, BSD 2-clause)
> This item was marked "not verified this round" in §3.1(c); the source original has now been fetched and verified.

**（i）Does it override `critical_enter`/`critical_exit`? — No.**
The file **does not contain** `critical_enter` / `critical_exit` / `critical_nesting` or related macros at all. libuinet did not take f-stack's path of "redefining `critical_enter/exit` as lock-grabbing" (f-stack see plan-17 §1.4 `lib/include/vm/uma_int.h:45-52`), but **introduced explicit lock primitives directly in the UMA porting layer**.

**（ii）Protection of the UMA per-CPU cache/bucket: one "global" mutex, not per-CPU locks.**

```c
struct mtx bucket_lock;

static void thread_bucket_lock_init(void) {
        mtx_init(&bucket_lock, "bucket lock", NULL, MTX_DEF);
}
void thread_bucket_lock(void)   { mtx_lock(&bucket_lock);   }
void thread_bucket_unlock(void) { mtx_unlock(&bucket_lock); }
```

Key points:
- **Only a single** `struct mtx bucket_lock` (a global variable, lock name `"bucket lock"`, `MTX_DEF`); **no lock array in the file** (no `mtx bucket_lock[MAXCPU]`).
- Named **`thread_bucket_lock`** rather than `cpu_bucket_lock` — hinting libuinet's mental model is "**per-thread bucket**" rather than "per-CPU cache", serializing bucket access with one global lock.
- **`uinet_pcpu_locks[]` does not appear in this file at all.** ⇒ the original inference in §3.1(a) item 4 ("libuinet protects UMA with one per-CPU lock") **is disproven** and was corrected there.

**（iii）The `uma_page`/slab reverse-lookup hash: protected by "another independent global lock".**

```c
struct mtx page_slab_hash_lock;
int uma_page_mask;
struct uma_page_head *uma_page_slab_hash;

static void uma_page_slab_hash_lock_init(void) {
        mtx_init(&page_slab_hash_lock, "uma page slab hash lock", NULL, MTX_DEF);
}
void uma_page_slab_hash_lock(void)   { mtx_lock(&page_slab_hash_lock);   }
void uma_page_slab_hash_unlock(void) { mtx_unlock(&page_slab_hash_lock); }
```

This is **structurally same-origin** with f-stack's approach: plan-17 §1.4 already records f-stack's `lib/include/vm/uma_int.h` also `#undef UMA_MD_SMALL_ALLOC`, defines `UMA_PAGE_HASH` and `struct uma_page` — i.e. **both projects, because userspace cannot get the slab reverse pointer from `vm_page`, use a global "page address → slab" hash table instead**.

**（iv）The only comment (an init-order XXX)**:

```c
/*
 * XXX this should really be handled by SYSINIT I think.  Although it works
 * out with the current port, calling mtx_init() before mutex_init() is
 * called is technically wrong.
 */
```
Both init functions run via `__attribute__((constructor))` before `main`, to complete `mtx_init()` earlier than the subsystem's `mutex_init()`; the author admits this is technically incorrect.

**（v）This file does not contain the `uma_zalloc`/`uma_zfree` fast-path code**; it only provides the above two lock primitives for the UMA core to call. **Honest declaration: the actual call sites of these two locks (in the libuinet-version `uma_core.c` or `uinet_uma_int.h`) were not fetched and verified this round; whether "libuinet grabs `bucket_lock` on every `uma_zalloc` fast path" cannot be confirmed; no speculation.**

##### Four Direct Implications for the G2-Form Ruling

| # | Conclusion | Strength |
|---|---|---|
| **L1** | **libuinet is not a "per-CPU lock" precedent but a "global lock" precedent**. It is at the **same conservativeness level** as f-stack's current state (a single global `uma_crit_lock`), only f-stack implements it by redefining `critical_enter`, libuinet by explicit lock functions. ⇒ **the candidate form "libuinet-style one lock per-CPU" for G2 has no literature basis; suggest removing it from the candidate set** (unless other grounds exist) | High (source original) |
| **L2** | **libuinet splits "bucket protection" and "uma_page slab-hash protection" into two independent locks**, with a clear reason: `uma_page_slab_hash` is a **genuinely cross-thread-shared global data structure** (page address → slab reverse table), **not per-CPU data**, so the invariant "each thread exclusively owns a per-CPU slot" **provides zero protection for it**. ⇒ **strongly supports G2-a (remove the `critical_enter` lock + add real locks for the truly shared structures) over G2-b (only remove the lock)**: f-stack's `uma_crit_lock` is likely defending two things at once, and the `UMA_PAGE_HASH` half **must keep some real lock no matter how clean G1 is** | High (source original + f-stack-side same-origin structure already recorded in plan-17 §1.4) |
| **L3** | directly echoes X3 (`git show b90ddcba5` original motivation): plan-17 §1.4 already lists "concurrency on f-stack's self-made `uma_page` hash" as one possible real motivation of `uma_crit_lock`. libuinet's implementation shows **this possibility has high prior probability** (an analogous project independently dedicated a lock to that hash). ⇒ suggest `res-code`, when doing X3, **specifically check whether `uma_crit_lock` covers the `UMA_PAGE_HASH` lookup/insertion paths** | Medium-high (same-origin structural analogy, derivation) |
| **L4** | libuinet uses `__attribute__((constructor))` to solve "the lock must be usable before `mutex_init()`" and self-evaluates it as technically wrong. If G2-a needs new per-zone/hash locks, f-stack hits the **same init-order problem** (the lock must be ready before the first UMA allocation, and UMA predates most SYSINITs). ⇒ suggest `designer` explicitly handle this ordering in the G2-a design, possibly using statically initialized `pthread_mutex`/`rte_spinlock` (**no dynamic init needed**) to bypass it, rather than copying the constructor trick | Medium (engineering analogy, a suggestion) |

> **Overall (for the leader to rule between G2-a/b/c)**: this verification result **pushes the balance toward G2-a**. The core reason is L2 — the "per-CPU slot exclusivity" invariant **can only protect per-CPU data (`uma_cache`/`uc_*bucket`)**, providing **zero protection** for f-stack's self-made `UMA_PAGE_HASH` global hash; and currently these two are coincidentally blocked by the same `uma_crit_lock`. Therefore "only remove the lock" (G2-b) is **unsafe before confirming whether `uma_crit_lock` also protects `UMA_PAGE_HASH`**. **This is another independent reason that X3 must be answered at the code level first.** (Note: L2/L3/L4 contain derivation and suggestion elements, marked per-item; L1 and the source facts are direct statements.)

### 3.2 rump kernel (NetBSD userspace) — **"thread exclusively owns a virtual CPU slot"**: the strongest external precedent

**Source**: NetBSD `sys/rump/librump/rumpkern/scheduler.c` (`$NetBSD: scheduler.c,v 1.55 2023/10/05 19:41:07 ad Exp $`, copyright Antti Kantee 2010, 2011)
Link: https://raw.githubusercontent.com/NetBSD/src/trunk/sys/rump/librump/rumpkern/scheduler.c

**（a）Mechanism: rump kernel has N "virtual CPUs"; a host thread must first "seize" a virtual CPU to run kernel code**

```c
static struct rumpcpu {
	/* needed in fastpath */
	struct cpu_info *rcpu_ci;
	void *rcpu_prevlwp;
	/* needed in slowpath */
	struct rumpuser_mtx *rcpu_mtx;
	struct rumpuser_cv *rcpu_cv;
	int rcpu_wanted;
	...
	int rcpu_align[0] __aligned(CACHE_LINE_SIZE);
} rcpu_storage[MAXCPUS];

static inline struct rumpcpu *
cpuinfo_to_rumpcpu(struct cpu_info *ci)
{
	return &rcpu_storage[cpu_index(ci)];
}
```

i.e. **`rcpu_storage[MAXCPUS]` is a "dense array indexed by virtual CPU number", each entry cache-line aligned**; the virtual CPU count is decided by `rump_scheduler_init(int numcpu)`; `rump_cpus_bootstrap()` additionally does an upper-bound clamp **`if (num > MAXCPUS) num = MAXCPUS;`** and prints
`"CPU limit: %d wanted, %d (MAXCPUS) available (adjusted)"`, `cpu_setmodel("rumpcore (virtual)")`.

`rump_schedule()`'s function comment directly states the design goal:

> `rump_schedule: ensure that the calling host thread has a valid lwp context. ie. ensure that curlwp != NULL. Also, ensure that there **a 1:1 mapping between the lwp and rump kernel cpu**.`

`rump_schedule_cpu_interlock()`'s comment and implementation:

> `Schedule a CPU. This optimizes for the case where we schedule the same thread often, and we have nCPU >= nFrequently-Running-Thread (where CPU is virtual rump cpu, not host CPU).`

```c
	rcpu = cpuinfo_to_rumpcpu(l->l_target_cpu);
	if (atomic_cas_ptr(&rcpu->rcpu_prevlwp, l, RCPULWP_BUSY) == l) {
		...
		goto fastlane;         /* I was the last user of this virtual CPU: reuse directly */
	}
	...
	for (;;) {
		old = atomic_swap_ptr(&rcpu->rcpu_prevlwp, RCPULWP_WANTED);
		if (old != RCPULWP_BUSY && old != RCPULWP_WANTED) {
			if (atomic_cas_ptr(&rcpu->rcpu_prevlwp,
			    RCPULWP_WANTED, RCPULWP_BUSY) == RCPULWP_WANTED)
				break;      /* seized an idle virtual CPU */
		}
		if (domigrate && !bound) {... rcpu = getnextcpu(); continue; }
		rcpu->rcpu_wanted++;
		rumpuser_cv_wait_nowrap(rcpu->rcpu_cv, rcpu->rcpu_mtx);
		rcpu->rcpu_wanted--;
	}
```

Release (`rump_unschedule_cpu1()`): `old = atomic_swap_ptr(&rcpu->rcpu_prevlwp, l);`, broadcasting `rumpuser_cv_broadcast()` if there are waiters.

**Core semantics**: the virtual CPU slot is **mutually-exclusively held** by the **BUSY/WANTED state machine of `rcpu_prevlwp` + atomic CAS** — **at any moment a virtual CPU slot is held by only one lwp (host thread)**. This is a **completely different route** from "protecting per-CPU data by forbidding host preemption": rump **does not forbid the host thread being preempted**, but **guarantees the slot is semantically exclusive**, so the host kernel scheduling the thread out is **harmless** (other threads cannot get this slot).

**（b）How rump handles "preemption-disabling": constantize the kernel preemption semantics to "always disabled"**

```c
bool
kpreempt(uintptr_t where)
{
	return false;
}

/*
 * There is no kernel thread preemption in rump currently.  But call
 * the implementing macros anyway in case they grow some side-effects
 * down the road.
 */
void kpreempt_disable(void) { KPREEMPT_DISABLE(curlwp); }
void kpreempt_enable(void)  { KPREEMPT_ENABLE(curlwp);  }

bool
kpreempt_disabled(void)
{
#if 0
	const lwp_t *l = curlwp;
	return l->l_nopreempt != 0 || l->l_stat == LSZOMB ||
	    (l->l_flag & LW_IDLE) != 0 || cpu_kpreempt_disabled();
#endif
	/* XXX: emulate cpu_kpreempt_disabled() */
	return true;
}

void preempt(void) { yield(); }
bool preempt_needed(void) { return false; }
void preempt_point(void) { }
```

**This is the most substantial external precedent of this round**: a mature userspace kernel port maintained in the upstream NetBSD tree for over a decade, whose approach is
**"from the kernel code's perspective preemption is permanently disabled (`kpreempt_disabled()` always returns `true`, `kpreempt()` always `false`, `preempt_needed()` always `false`); the real mutual exclusion is provided by 'the virtual CPU slot being exclusively held by a thread'"**.

**（c）Comparison with f-stack native-mt (analysis, marked as derivation)**

| Dimension | rump kernel | f-stack native-mt target state (candidate B) |
|---|---|---|
| slot array | `rcpu_storage[MAXCPUS]`, cache-line aligned | UMA/SMR per-CPU zones slotted by `mp_maxid+1` |
| slot ownership | **dynamic exclusive**: a thread CAS-seizes a virtual CPU at runtime, may migrate (`domigrate`/`getnextcpu()`), but exclusive at any moment | **static 1:1 permanent binding**: worker i ↔ slot i, no migration |
| protection means | atomic CAS state machine + mutex/cv (**does not forbid host preemption**) | intended to rely on "1:1 binding + no migration" (**also does not forbid host preemption**) |
| upper-bound protection | `if (num > MAXCPUS) num = MAXCPUS;` | suggest following libuinet with a runtime `cpuid < mp_ncpus` assertion |
| strictness | weaker (allows migration, hence CAS mutual exclusion required) | **stronger** (permanent binding ⇒ naturally exclusive, theoretically no CAS needed) |

**Conclusion (derivation)**: f-stack's intended "each worker exclusively owns a dense slot, never migrates" is **stronger** than rump's "dynamic exclusivity + migratable". Since the weaker rump model has proven usable without forbidding host preemption (long-term maintenance in the NetBSD tree), **the stronger f-stack model will not be worse on the same dimension**.
**But this does not constitute a sufficiency proof for G2** — because:
- rump's virtual CPU is **kernel-code execution right itself** (without a virtual CPU you cannot run kernel code), while f-stack's pcpu slot **is only a data slot**; f-stack's workers do **not** have a "must seize the slot before entering the protocol stack" gate;
- therefore f-stack must additionally prove: **every execution flow touching per-CPU slots corresponds 1:1 with some fixed slot**. This is exactly the "main thread / KNI / callout / `ff_veth` auxiliary paths" problem listed in plan-17 U7 — **external precedents cannot substitute for this local verification**.

### 3.3 Seastar / ScyllaDB — "shared-nothing + thread core-pinning + per-core allocator"

**Source**: Seastar official tutorial (authors Nadav Har'El, Avi Kivity; ScyllaDB official repo master branch `doc/tutorial.md`)
Link: https://raw.githubusercontent.com/scylladb/seastar/master/doc/tutorial.md

Original key points:
- **Motivation**: the cost of cross-core shared data (atomic instructions, cache line bouncing, memory barriers) is far higher than core-local access; the text explicitly states **"non-scalable programming practices (such as locking) can severely destroy performance on multi-core"**.
- **Share-nothing SMP architecture**: on an SMP system **each core runs completely independently**; **memory, data structures, and CPU time are not shared**; inter-core communication uses **explicit message passing**; a Seastar core is often called a **shard**.
- **Thread core-pinning**: one thread per CPU (engine); **each engine thread is pinned (like `taskset(1)`) to a different hardware thread**; `-c` specifies the thread count; requesting only 2 threads guarantees pinning to **different physical cores** (avoiding same-core hyperthread competition); **starting more threads than hardware threads is disallowed**.
- **per-core memory allocator**: each thread **pre-allocates a large memory block** (located on its own NUMA node) **and uses only that block for allocations**.
- **Corollary-level original text**: since Seastar objects are **always used by a single CPU**, `seastar::shared_ptr`/`lw_shared_ptr` reference-count increments/decrements **need no atomic operations**, being ordinary core-local integer operations; standard `std::shared_ptr` **should not be used in sharded Seastar applications**.

**Source (supplementary, ScyllaDB official product page)**: https://www.scylladb.com/product/technology/shard-per-core-architecture/
> each shard-per-core has dedicated resources and its own custom schedulers for CPU and I/O processing. Using the Seastar framework, ScyllaDB runs **one application thread per core** and relies on **explicit message passing**.

**Value for this round**: Seastar provides **industrial-grade endorsement of the thesis "thread-to-core 1:1 binding ⇒ data structures can be completely lock-free, even reference counting needs no atomics"**. This is **isomorphic in inference form** to G2's goal (removing `uma_crit_lock`): `exclusivity + no migration ⇒ no mutual-exclusion primitive needed`.
**Limitation (honest declaration)**: Seastar is a **self-developed** shared-nothing runtime, **not a port of existing kernel code**, so it has **no** constraint like "kernel code internally implicitly requires `critical_enter` semantics". It **supports the general thesis "1:1 binding can remove locks" but cannot prove "FreeBSD UMA/SMR's concrete implementation remains correct after removing `critical_enter`"** — the latter can only rely on §4's upstream code semantics + local verification.

### 3.4 DPDK ANS (`ansyun/dpdk-ans`) — per-lcore Independent TCP Stack, Lock-Free, but Layered Sharing

**Source**: https://github.com/ansyun/dpdk-ans

README's explicit architecture (original key points):
- **per-lcore independent instances at the TCP layer** ("Support multicore tcp stack, per tcp stack per lcore"); **IP / ARP / ICMP layers shared across lcores**.
- **"Each lcore has own TCP stack, free lock"** — the per-lcore TCP path is **lock-free**.
- Flow affinity **depends on NIC RSS**: "same TCP flow are handled in the same lcore"; **without RSS**, it suggests modifying `ans_main.c` to **reserve one lcore for receiving + software RSS distribution**.
- References the FreeBSD implementation but **replaces kernel primitives with DPDK primitives**: `ANS use dpdk mbuf, ring, memzone, mempool, timer, spinlock` — i.e. **DPDK `rte_mempool` replaces UMA/zone, `rte_timer` replaces callout, `rte_spinlock` replaces mutex/rwlock**.
- Performance: 1 lcore → 2 lcore CPS goes from 105,860 → 204,512 req/s (near-linear).

**Value and limitations for this round**:
- **Value**: proves "per-lcore independent stack + lock-free" is a mainstream choice in production DPDK stacks; and it gives the common practice of "software secondary distribution without RSS" (consistent with the previous round's `_m1_B_external.md` §5 conclusion).
- **Limitation (honest declaration)**: ANS is **not a port of FreeBSD code but a "reference-FreeBSD reimplementation"** and replaces the whole UMA with `rte_mempool`. So **it completely sidesteps this round's problem** (no UMA per-CPU cache, no SMR, no `struct pcpu`). **ANS has no direct reference value for "how to make FreeBSD's per-CPU view SMP-aware".**
- README **does not explain** how FreeBSD's per-CPU structures (`curcpu`, per-CPU caches, pcbinfo hash partitioning) were specifically rewritten; **honest declaration: not verified**.

### 3.5 Items with No Reliable Source Found (honest declaration)

| Search target | Result |
|---|---|
| **rump kernel's official book**《Flexible Operating System Internals: The Design and Implementation of the Anykernel and Rump Kernels》(Kantee, 2012), the chapters on virtual CPUs / per-CPU | **fetch failed** (`http://www.fixup.fi/misc/rumpkernel-book/rumpkernel-bookv2-web.pdf` request aborted/timed out). Switched to the **upstream source original** (§3.2) as the authoritative basis; source is more verifiable, so no retry. |
| **mTCP paper** (NSDI 2014) original statements on "per-core stack + thread core-pinning + no shared data structures" | **no reliable source found**. Multiple searches only returned second-hand CSDN blogs (mentioning `struct mtcp_context` / `struct mtcp_thread_context` doing "multi-thread resource isolation", source https://blog.csdn.net/gitblog_01026/article/details/156748380 ); **the paper original or an official doc page was not obtained**. And mTCP is a self-developed stack, not a FreeBSD port; low relevance to this round; **not used as a basis**. |
| **OpenFastPath / ODP** per-core and lock model | **no reliable source found**. Searches only returned a CSDN "FAQ solutions" article (build-dependency content, https://blog.csdn.net/gitblog_00880/article/details/143679925 ); **no official design document obtained**. **Not used as a basis.** |
| **glue (other FreeBSD userspace glue projects besides f-stack)** per-CPU handling | **no reliable source found**. Besides libuinet / libplebnet (the latter absorbed by libuinet, see §3.1's comment `Derived in part from libplebnet's pn_glue.c`), no other verifiable same-class project found. |
| **libuinet's UMA rework details** (does `uinet_uma_int.c` also add locks / how does it handle per-CPU cache) | **verified (batch-2 supplementary)**, see §3.1(d): **does not override `critical_enter`; uses one global `bucket_lock` + a separate `page_slab_hash_lock`**. **Still unverified** is only the **actual call sites** of these two locks in the libuinet-version `uma_core.c`/`uinet_uma_int.h` (i.e. whether every `uma_zalloc` fast path grabs `bucket_lock`), **no speculation**. |
| **published bug reports/incident records** of "userspace multi-thread shared SMR slot causing UAF" | **no reliable source found**. Searching FreeBSD bugzilla / mailing lists / GitHub found no same-class reports — a reasonable explanation: **almost no other project ports FreeBSD 13+'s SMR into a userspace multi-threaded environment** (libuinet stopped at 9.1, ANS does not use UMA, rump is NetBSD without SMR). This round's UAF argument **can only rely on §2's upstream source-semantics derivation**; no external incident case to cite. |

---

## 4. Direction 4: Correctness of the UMA per-CPU Cache Fast Path in Userspace Without "Preemption-Disabling" Semantics

### 4.1 Upstream's Authoritative Statement on "Why per-CPU Cache Needs No Lock" — `uma_int.h` Original

**Source**: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/vm/uma_int.h
(copyright: Jeffrey Roberson 2002–2019; Bosko Milekic 2004, 2005)

The **decisive sentence** of the file-top overview comment:

> "The **PCPU caches are protected by critical sections**, and **may be accessed safely only from their associated CPU**, while the Zones backed by the same Keg all share a common Keg lock (to coalesce contention on the backing slabs)."

The comment before `struct uma_cache`:

> "The uma_cache structure is allocated for each cpu for every zone type. **This optimizes synchronization out of the allocator fast path.**"

The allocation hierarchy (the comment's allocation order):

```
1) Per-CPU cache
2) Per-domain cache of buckets
3) Slab from any of N kegs
4) Backend page provider
```

Struct definition:

```c
struct uma_cache {
	struct uma_cache_bucket uc_freebucket;   /* Bucket we're freeing to */
	struct uma_cache_bucket uc_allocbucket;  /* Bucket to allocate from */
	struct uma_cache_bucket uc_crossbucket;  /* cross domain bucket */
	uint64_t uc_allocs;
	uint64_t uc_frees;
} UMA_ALIGN;
```

With a comment explaining the cache-line layout intent:

> "The cache structure **pads perfectly into 64 bytes** so we use spare bits from the embedded cache buckets to store information from the zone and **keep all fast-path allocations accessing a single per-cpu line**."

**Another important fact**: the lock macros defined by `uma_int.h` are **only the three classes** keg / zone-domain / cross-domain (`KEG_LOCK`, `ZDOM_LOCK`/`ZONE_LOCK`, `ZONE_CROSS_LOCK`), **no lock macro for the per-CPU cache at all**. From the negative direction this verifies: upstream's **only** means of protecting the per-CPU cache is the critical section.

**Upstream semantics of cross-CPU frees (corresponds to plan-17 U8)**: the `uma_int.h` comment writes

> "…frees may happen on any CPU and these are returned to the **CPU-local cache regardless of the originating domain**."

i.e. **"free on whichever CPU → that CPU's local cache"** — upstream **allows** "A allocates, B frees", and **does not require** the item to be returned to the original CPU.
**Implication for this round**: the "mbuf allocated on worker A, freed on B" concern of plan-17 U8 **is legal under upstream semantics**, because a free only touches **the free-er's own** per-CPU cache. **The precondition remains "every execution flow has its own exclusive cache slot"** — exactly the precondition G1 must establish.
**Needs code cross-validation (code wins)**: whether f-stack stubs `uz_lock`/`ZDOM_LOCK`/`ZONE_CROSS_LOCK` too (plan-17 U8's original question) must be verified by `res-code`; if zone-level locks are stubbed empty, then the bucket-exchange path (between the per-CPU cache and the zone bucket list) loses protection, **which is a separate independent defect unrelated to per-CPU slots**.

**Auxiliary source (second-hand, corroboration only)**: DeepWiki's FreeBSD UMA write-up:
> "**Per-CPU Cache**: The allocator first checks the local CPU's cache (`uma_cache`) to satisfy the request **without locking**." / "Objects freed to an SMR zone are not immediately reused. They are placed in a deferred state until the SMR subsystem confirms that no threads hold references to the memory. This is critical for networking structures like pcb (Protocol Control Blocks) where high-performance lookups occur without global locks."
Source: https://deepwiki.com/freebsd/freebsd-src/4.3-uma-(universal-memory-allocator)
（**Note: DeepWiki is an AI-generated third-party write-up, not an official document**; used only to corroborate conclusions already verified by official source/man pages in §2/§4, **not an independent basis**. It also confirms "PCB lookup is a key SMR consumer", consistent with plan-17 §1.3's `in_pcb.c:583,615-617` facts.)

### 4.2 Cross-Validation of the Core Thesis: "Upstream `critical_enter` Guards Against, after Preemption on the Same CPU, Another Thread Accessing the Same per-CPU Slot; If Userspace Has One Slot Per Thread, Preemption Is Harmless"

**Ruling: on the "mutual exclusion of per-CPU data slots" dimension, this thesis receives positive support from upstream docs and source; but as a sufficient condition for "may remove `uma_crit_lock`", it is incomplete — three gaps remain, requiring local verification.**

#### （a）Evidence supporting the thesis (three items, all verifiable)

1. **`uma_int.h`'s original puts two things together**: "protected by critical sections" **and** "may be accessed safely **only from their associated CPU**". The second clause gives the **ownership invariant** (a cache is accessed only by the CPU it belongs to), while the critical section is the **means of maintaining this invariant** in the kernel environment of "threads may migrate and be preempted", not the invariant itself.
   → **If userspace establishes that invariant directly with "thread ↔ slot 1:1 permanent binding, never migrating", the means of maintaining it is no longer necessary.**
   Source: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/vm/uma_int.h
   *（Note: this step is **semantic derivation** — upstream does not say in one sentence "if the invariant can be established by other means, the critical section can be omitted". The derivation chain is clear with originals for each link, but **it is a derivation, not a direct literature statement**.)*
2. **`counter(9)` provides an isomorphic official precedent**: counter is also `UMA_ZONE_PCPU`-allocated per-CPU data, and the man page explicitly states **on amd64 `counter_u64_add()` is a single non-lock instruction, naturally safe against preemption and interrupts**, so **on amd64 `counter_enter()` expands to a nop rather than a critical section** ("expands to a critical(9) section on some machines, a nop on others").
   → **Shows upstream itself admits: when the access is architecturally atomic/single-instruction, per-CPU data needs no critical section.** In other words, the critical section is **not** a metaphysical requirement of per-CPU data, but targets the specific threat model "multi-instruction sequences + migratable".
   Source: https://man.freebsd.org/cgi/man.cgi?query=counter&sektion=9&manpath=FreeBSD+15.0-RELEASE
3. **rump kernel is an engineering precedent** (§3.2): `kpreempt_disabled()` **always returns true**, `kpreempt()` always false, protecting per-CPU structures by "the virtual CPU slot being exclusively held by a thread" rather than **by forbidding host preemption**; and it is a long-maintained implementation in the NetBSD upstream tree.
   Source: https://raw.githubusercontent.com/NetBSD/src/trunk/sys/rump/librump/rumpkern/scheduler.c

#### （b）The three gaps where the thesis is **insufficient** to support G2 (require local verification; this doc draws no conclusion)

| # | Gap | Why external material cannot resolve | Assigned to |
|---|---|---|---|
| **X1** | **whether "all execution flows touching per-CPU slots" correspond 1:1 with some fixed slot**. plan-17 U7 already lists the main thread / KNI / callout / `ff_veth` auxiliary paths. If **any** execution flow exists without an exclusive slot, or drifting across slots (e.g. some pthread not calling `ff_pcpu_thread_init()`, or multiple logical tasks reusing one thread while expecting different slots), the invariant breaks | f-stack-specific code structure; no external precedent | `res-code` (U7 per-path verification) + `tester` (load test) |
| **X2** | **the actual scope of the `critical_enter/exit` macro override**. If `lib/include/vm/uma_int.h`'s macro override is also seen by `smr.h`/`subr_smr.c`/`counter.h` translation units, removing it **simultaneously** removes SMR write-side (`smr_advance`/`smr_poll`) and counter protection; and SMR's write-side critical section has an upstream **explicit independent reason** — the `smr_poll()` comment: **"Use a critical section so that we can avoid ABA races caused by long preemption sleeps."** This reason **is unrelated to per-CPU slot ownership** — it concerns "sequence-number ABA" — and **cannot** be covered by the "thread-exclusive slot" argument | upstream only says "prevent ABA caused by long preemption sleep"; whether it holds in f-stack userspace depends on how long f-stack threads are scheduled out by the OS vs `SMR_SEQ_MAX_DELTA` (`UINT_MAX/4`), **must be measured/code-analyzed** | `res-code` (`gcc -E` to pin the scope) + `designer` (decide whether the SMR write side needs substitute protection) |
| **X3** | **the original motivation for `uma_crit_lock`**. plan-17 §1.4 already requires `git show b90ddcba5` to pin it down. **If it originally solved not "shared pcpu slots" but something else** (e.g. concurrency on f-stack's self-made `uma_page` hash, or on the `page_alloc` path after `#undef UMA_MD_SMALL_ALLOC`), then even after G1 the lock **still cannot be removed** | that commit is f-stack's private history; external material has nothing | `res-code` (M1-A must-do item) |

#### （b-2）X2 Conclusion Backfill (`res-code` verified with code; synchronized during the leader's polling on 2026-08-04)

Code facts verified by `res-code`: **`freebsd/sys/systm.h:186`'s `#ifndef FSTACK` makes f-stack's whole-tree `critical_enter()/critical_exit()` themselves no-ops (nops)**; only **UMA translation units** are covered by `lib/include/vm/uma_int.h:46/50`'s global spinlock. **Code wins**; this document's original X2 assumption "macro-override scope unknown" is overturned; three conclusions are accordingly corrected:

1. **SMR's read side (`smr_enter`/`smr_exit`) and write side (`smr_advance`/`smr_poll`/`smr_poll_scan`) currently have no critical-section protection at all in f-stack** (`critical_enter` is a nop; `CRITICAL_ASSERT` is likewise void because `INVARIANTS` is undefined). Therefore §4.2(b)'s original X2 worry "removing `uma_crit_lock` would incidentally weaken SMR write-side protection" **does not hold** — G2 has **zero impact** on SMR; the SMR-side risk is **pre-existing**, an independent problem unrelated to G2.
2. Accordingly, **T5 (SMR sequence ABA) is not a gate item for G2**, but a **pre-existing risk to be evaluated independently of G1**: the "ABA caused by long preemption sleep" that upstream guards against with `critical_enter` has never been guarded in f-stack. Fortunately `smr_poll_cpu()` has a built-in soft fallback (original comment: "There is a race described in smr.h:smr_enter that can lead to a stale seq value but not stale data access. If we find a value out of range here we pin it to the current min…", with `if (SMR_SEQ_LT(c_seq, s_rd_seq)) c_seq = s_rd_seq;`), and the comment notes that race "is only likely to happen on hypervisor or with a system management interrupt". **A userspace thread being scheduled out by the OS is qualitatively the same class as a hypervisor vm-exit**, so that soft fallback happens to cover this scenario; but it only guarantees "no stale-data access", not eliminating §2.1's **fundamental break** of "shared slot → `smr_exit` wrongly clears INVALID".
   Source: https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c
3. **G2's true semantics are clarified**: `uma_crit_lock` is not "the userspace stand-in for the upstream critical section", but **a global serialization lock f-stack added specifically for the UMA per-CPU cache after `critical_enter` was nop-ized**. So G2 = "remove this patch lock and return to the nop semantics consistent with the rest of the tree" — its correctness **relies entirely on the 'each thread exclusively owns a slot' invariant G1 establishes**, unrelated to SMR. This makes G1→G2's dependency **cleaner** than plan-17's original wording (derivation, marked as analysis).

**Remaining to-be-verified (only two items)**: X1 (the exhaustive path verification that execution flows and slots are 1:1), X3 (`b90ddcba5`'s original motivation).

### 4.3 Threat-Model Table Under "Each Thread Exclusively Owns a Slot, Never Migrates"

| Threat | Holds under "each thread exclusive slot, never migrates"? | Basis |
|---|---|---|
| **T1: after preemption, another thread accesses the same per-CPU slot** | **does not hold** (the core of the thesis; slot exclusivity eliminates it) | `uma_int.h` "only from their associated CPU"; rump precedent |
| **T2: after preemption, the same thread continues on another CPU, causing `zpcpu_get()` to return a different slot** | **does not hold**. f-stack's slot index comes from a **software quantity** (`__thread pcpup` / dense worker number), **not** a real hardware CPU number, so the thread still accesses its own slot even after being migrated to another physical core | libuinet's `uinet_pcpu_get()` uses `curthread->td_oncpu` (a software virtual CPU number) rather than a hardware CPU number; f-stack uses a TLS pointer (plan-17 §1.1) |
| **T3: preemption lengthens the critical section; per-CPU cache data in a mid-inconsistent state is seen by others** | **does not hold** (nobody can see it — the slot is exclusive); but **`uma_reclaim(UMA_RECLAIM_DRAIN_CPU)`-class paths traverse all CPUs' caches**, which is **cross-slot access**, needing separate verification | uma(9): `UMA_RECLAIM_DRAIN_CPU` "reclaims all cached items (including per-CPU)"; `UMA_RECLAIM_DRAIN` leaves "free items in per-CPU caches untouched" |
| **T4: preemption lengthens the SMR read section; `rd_seq` stuck → memory growth** | **holds and cannot be eliminated by slot exclusivity**. This is a **performance/memory** problem, not a correctness problem, but in extreme cases triggers `smr_advance()`'s mandatory `smr_wait()` (busy loop) when `SMR_SEQ_DELTA(goal, s_rd_seq) >= SMR_SEQ_MAX_DELTA` | `subr_smr.c`'s `smr_default_advance()` original |
| **T5: preemption causes SMR sequence ABA** | **possibly holds**, see X2 in the table above. Upstream explicitly uses this as an independent reason for `critical_enter` | `smr_poll()` comment "avoid ABA races caused by long preemption sleeps" |
| **T6: `SMR_LAZY`'s grace period depends on "per-CPU periodic clock interrupts"** | **does not hold in userspace** (no per-CPU clock interrupts). **Must check whether f-stack uses `SMR_LAZY`** | `subr_smr.c` `SMR_LAZY_GRACE` comment original (see §2.6) |

> **Summary (for the leader's ruling, corrected per X2's code verification)**: team-lead's thesis — "upstream `critical_enter` guards against, after preemption on the same CPU, another thread accessing the same per-CPU slot; if userspace has one slot per thread, preemption is harmless" — **is correct for T1/T2/T3**, with triple support from upstream original text (`uma_int.h` "may be accessed safely only from their associated CPU") + counter(9) architecture-level precedent + rump/Seastar engineering precedents. Therefore:
> - **G1 (each thread exclusively owns a dense slot) is G2's necessary precondition**, and this thesis is fully proven;
> - **G2 (removing `uma_crit_lock`) is risk-free on the "coupling with SMR" dimension** (X2 verified `critical_enter` is a whole-tree nop; G2 has zero impact on SMR);
> - **G2's remaining gates are only two**: X1 (whether all execution flows touching per-CPU slots each exclusively own one fixed slot — incl. main thread/KNI/callout/`ff_veth`) and X3 (whether `b90ddcba5`'s original motivation was indeed "shared pcpu slot" rather than `uma_page` hash / `page_alloc` concurrency). Both are f-stack-private code problems; **external material cannot substitute for local verification**.
> - **T4 (`rd_seq` stuck → memory growth) / T5 (SMR sequence ABA) / T6 (`SMR_LAZY` clock assumption) are pre-existing SMR-side risks, causally unrelated to G2**, and should be recorded in spec 17 as independent risk items (T6 requires checking whether f-stack actually uses `SMR_LAZY`).

### 4.3 Precedents of "Thread ↔ Slot 1:1 Binding + No Migration" Replacing the Critical Section

| Project | Precedent? | Concrete form | Source |
|---|---|---|---|
| **rump kernel (NetBSD)** | **yes, and the closest** | virtual CPU slot `rcpu_storage[MAXCPUS]` **exclusively held** by an lwp via atomic CAS; `kpreempt_disabled()` always true | https://raw.githubusercontent.com/NetBSD/src/trunk/sys/rump/librump/rumpkern/scheduler.c |
| **Seastar / ScyllaDB** | **yes (stronger form)** | threads pinned to cores, shared-nothing, per-core allocator; **even reference counting uses no atomics** | https://raw.githubusercontent.com/scylladb/seastar/master/doc/tutorial.md ；https://www.scylladb.com/product/technology/shard-per-core-architecture/ |
| **DPDK ANS** | **yes (but sidesteps the problem)** | per-lcore independent TCP stack "free lock"; **but UMA is wholly replaced by `rte_mempool`** | https://github.com/ansyun/dpdk-ans |
| **libuinet** | **no — a weak signal on the counter side**: establishes dense slots and runtime boundary assertions, but UMA still relies on **one global `bucket_lock`** for serialization (plus a separate `page_slab_hash_lock`), **not** using "slot exclusivity" to replace locks; and `uinet_pcpu_locks[MAXCPU]` is marked `XXX temporary until final pcpu approach is determined` (its purpose unrelated to UMA, not verified this round) | see §3.1(a)(d) | https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_smp.c ；https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_uma_int.c |
| **FreeBSD upstream counter(9)** | **yes (architecture-level)** | on amd64 `counter_enter()` is a **nop**, because single-instruction updates are naturally safe against preemption | https://man.freebsd.org/cgi/man.cgi?query=counter&sektion=9&manpath=FreeBSD+15.0-RELEASE |
| **Material refuting the thesis** | **not found**. Searches found nothing arguing "even with one per-CPU slot per thread, preemption must still be forbidden for UMA per-CPU cache correctness" | — | honest declaration: no counter-example source |

**Note the libuinet row is a "weak signal"**: a same-class project, after establishing dense slots, **still kept a per-CPU lock** and marked the pcpu scheme "not finalized". This **cannot prove** removing the lock is infeasible (that lock's purpose is unverified and may be unrelated to UMA), but **is enough to require G2 to be backed by measured data, not passed by inference alone** (consistent with plan-17 §0.4's "G2 is a primary goal, requiring performance-data support").

---

## 6. Explicit Knowledge Boundaries (No Out-of-Bounds Conclusions)

1. **Zero f-stack community discussion of this round's problem**: no public material involves "f-stack + SMR / SMP-aware pcpu / removing the UMA global lock". Issue #27 (2017, FreeBSD-11 era, comment section not loaded) **is not a reference**. This round has no precedent.
2. **No userspace precedent at the SMR layer**: libuinet stopped at FreeBSD 9.1 (no SMR), ANS does not use UMA/SMR, rump is NetBSD (no SMR). **f-stack is (per public material) the first project porting FreeBSD 13+ SMR into a userspace multi-threaded environment**; SMR conclusions can only rely on upstream source-semantics derivation + local evidence, **with no external incident case to cite**.
3. **All source references in this document are from the `main` branch of `freebsd/freebsd-src`** (because `cgit.freebsd.org` has Anubis anti-crawling and could not be fetched). This repo's reference tree is `releng/15.0`; **line numbers and details must be re-checked by `res-code` in `/data/workspace/freebsd-src-releng-15.0`**; the key points referenced here (`critical_enter` location, `c_seq` semantics, `mp_maxid` loops, `CPU_FOREACH` scan, `uma_int.h` comments) show no structural changes between 13→15→main, but **this judgment itself also needs code verification**.
4. **No `pcpu(9)` man page exists** (no such section-9 page on man.freebsd.org). The semantics of `zpcpu_get`/`zpcpu_offset_cpu`/`UMA_PCPU_ALLOC_SIZE` **have source as the only authority** (`sys/sys/pcpu.h`, `sys/vm/uma.h`). The §4.1 `uma_int.h` analysis mentions `UMA_PCPU_ALLOC_SIZE` is defined in `sys/vm/uma.h` and equals `PAGE_SIZE` — **that point has already been verified by `res-code` in local code as `UMA_PCPU_ALLOC_SIZE = PAGE_SIZE = 4096`, `zpcpu_offset_cpu(cpu) = 4096 * cpu` (plan-17 U1 closed)**, consistent with the external material cited here, no conflict; **if any later external material disagrees, code wins**.
5. **`CPU_FOREACH`'s actual expansion under f-stack's non-SMP build, and whether `all_cpus` is all-0, this document could not determine** (§2.4 marked as this round's highest-priority to-be-verified item). If `CPU_FOREACH` traverses nothing, `smr_poll_scan()` pushes `rd_seq` straight to `s_wr_seq` ⇒ **SMR equivalent to fully disabled** — far more severe than slot sharing. **This document only flags it, no conclusion.**
6. **The parts that are mechanism/semantic derivations (not direct literature statements)** are marked per-location in the body, mainly: §2.1's `atomic_add` accumulation consequence and UAF chain, §2.4's `CPU_FOREACH` risk, §3.1's f-stack/libuinet difference analysis and the "one lock per worker" fallback suggestion, §3.2's rump comparison table and conclusion, §4.2(a)1's "invariant vs maintenance means" derivation, and §4.2 summary's "change the macro to nop rather than delete" suggestion.
7. **Items with no reliable source found** are centrally listed in §3.5, plus §1.3 (Zhihu article 403), §1.4 (no f-stack community discussion), §2.6 (no standalone SMR design document), §4.3's last row (no material refuting the thesis). **None were fabricated substitutes.**
8. **No shell commands executed, no source files modified**; this agent only wrote this file.

---

## 7. Unified Source List (Verifiable)

**FreeBSD official man pages**
1. `smr(9)` (FreeBSD 15.0, 2023-01-17; algorithm Jeff Roberson, man page Mark Johnston) — https://man.freebsd.org/cgi/man.cgi?query=smr&sektion=9&manpath=FreeBSD+15.0-RELEASE
2. `uma(9)` (FreeBSD 15.0, 2023-01-16) — https://man.freebsd.org/cgi/man.cgi?query=uma&sektion=9&manpath=FreeBSD+15.0-RELEASE
3. `counter(9)` (FreeBSD 15.0, 2025-06-19; Gleb Smirnoff / Konstantin Belousov) — https://man.freebsd.org/cgi/man.cgi?query=counter&sektion=9&manpath=FreeBSD+15.0-RELEASE
4. `cpuset(9)` (FreeBSD 15.0, 2025-08-07; macros Jeff Roberson, man page Conrad Meyer) — https://man.freebsd.org/cgi/man.cgi?query=cpuset&sektion=9&manpath=FreeBSD+15.0-RELEASE
5. **`pcpu(9)`: does not exist** (honest declaration)

**FreeBSD upstream source (`freebsd/freebsd-src` main-branch raw)**
6. `sys/kern/subr_smr.c` (GUS algorithm comment, `smr_create`/`smr_poll`/`smr_poll_scan`/`smr_advance`, `SMR_LAZY_GRACE`) — https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c
7. `sys/sys/smr.h` (`struct smr`, `smr_enter`/`smr_exit` implementation and `critical_enter`) — https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/sys/smr.h
8. `sys/vm/uma_int.h` ("PCPU caches are protected by critical sections… only from their associated CPU", `struct uma_cache`, lock-macro list) — https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/vm/uma_int.h
9. (fetch failed, rerouted) `cgit.freebsd.org/src/plain/sys/kern/subr_smr.c` — blocked by Anubis anti-crawling; content not obtained

**FreeBSD official commit / project report**
10. commit `87767249233f` (stable/13, MFC `8232a1eddadd`) *cpuset(9): Refer to CPU_SETSIZE not MAXCPU*, Brooks Davis, 2022-09-23, D36679 — https://lists.freebsd.org/archives/dev-commits-src-all/2022-September/017116.html
11. FreeBSD quarterly status report 2023Q2《Increasing MAXCPU》, Ed Maste, 2023-07-18 — https://www.freebsd.org/status/report-2023-04-2023-06/maxcpu/
12. Phabricator D36838 *amd64: Bump MAXCPU to 1024 (from 256)* (cited only, body not fetched) — https://reviews.freebsd.org/D36838

**Other userspace kernel/protocol-stack ports (source originals)**
13. libuinet `lib/libuinet/uinet_subr_smp.c` (Kip Macy 2010 / Patrick Kelsey 2013) — https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_smp.c
14. libuinet `lib/libuinet/uinet_subr_pcpu.c` (Patrick Kelsey 2013) — https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_pcpu.c
14a. libuinet `lib/libuinet/uinet_uma_int.c` (Patrick Kelsey 2013; global `bucket_lock` + separate `page_slab_hash_lock`, **does not** override `critical_enter`) — https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_uma_int.c
15. libuinet repo README (FreeBSD 9.1 baseline, netmap/libpcap, libplebnet lineage) — https://github.com/pkelsey/libuinet
16. libuinet `lib/libuinet/` directory listing — https://github.com/pkelsey/libuinet/tree/master/lib/libuinet
17. NetBSD `sys/rump/librump/rumpkern/scheduler.c` (rev1.55, 2023-10-05; Antti Kantee 2010, 2011) — https://raw.githubusercontent.com/NetBSD/src/trunk/sys/rump/librump/rumpkern/scheduler.c
18. rump kernel official site — https://rumpkernel.github.io/
19. Antti Kantee《Rump File Systems: Kernel Code Reborn》USENIX ATC 2009 (background only, not used for any conclusion in this doc) — https://www.usenix.org/legacy/event/usenix09/tech/full_papers/kantee/kantee.pdf
20. rump kernel book PDF (**fetch failed/timed out, not used**) — http://www.fixup.fi/misc/rumpkernel-book/rumpkernel-bookv2-web.pdf

**Seastar / ScyllaDB**
21. Seastar tutorial (Nadav Har'El, Avi Kivity; official repo master) — https://raw.githubusercontent.com/scylladb/seastar/master/doc/tutorial.md
22. ScyllaDB《Shard-per-Core Architecture》 — https://www.scylladb.com/product/technology/shard-per-core-architecture/

**DPDK ANS**
23. `ansyun/dpdk-ans` README (per-lcore TCP stack, free lock, DPDK primitive replacement) — https://github.com/ansyun/dpdk-ans

**f-stack related**
24. F-Stack Issue #27 (2017-06-05, Closed, **comment section not loaded**) — https://github.com/F-Stack/f-stack/issues/27
25. F-Stack official site (port of FreeBSD 11.0 stable) — http://f-stack.org/
26. F-Stack repo — https://github.com/F-Stack/f-stack
27. F-Stack Development Guide community repost (listing `pcpu` / `curthread` / `proc0` / `thread0` change items) — https://rtoax.blog.csdn.net/article/details/107987976｜https://www.codeleading.com/article/50794435172/
28. 《基于dpdk 的用户态协议栈 f-stack 实现分析》(2020-04-27, four-class change-point summary) — https://blog.csdn.net/21cnbao/article/details/105803864
29. 《F-Stack 高性能网络框架开发指南》(2025-06-10, same summary) — https://blog.csdn.net/gitblog_01019/article/details/148549951
30. 《用户态 TCP 协议栈及 dpdk 用户态协议栈 f-stack》(2021-05-28) — https://zhuanlan.zhihu.com/p/376144528
31. 《将 F-Stack 改造为多线程库》(2025-02, **fetch failed HTTP 403, its content unused**) — https://zhuanlan.zhihu.com/p/21075875679
32. 《使用 Photon 协程库与 F-Stack 简化 DPDK 应用开发》(2023-05-10, coroutine direction, different problem layer) — https://developer.aliyun.com/article/1208390

**Third-party write-ups (corroboration only, not an independent basis)**
33. DeepWiki《UMA (Universal Memory Allocator)》(**AI-generated third-party write-up**) — https://deepwiki.com/freebsd/freebsd-src/4.3-uma-(universal-memory-allocator)

**Search targets with no reliable source obtained** (see §3.5, §1.3, §1.4, §2.6, §4.3)
- mTCP paper original's per-core/no-sharing statements
- OpenFastPath / ODP official design document
- the **actual call sites** of `bucket_lock`/`page_slab_hash_lock` in the libuinet-version `uma_core.c` / `uinet_uma_int.h` (`uinet_uma_int.c` itself verified, see §3.1(d))
- libuinet `uinet_pcpu_locks[MAXCPU]`'s real purpose (confirmed unrelated to UMA)
- published bug reports of "userspace multi-thread shared SMR slot causing UAF"
- material refuting "1:1 binding can replace the critical section"
- a standalone SMR design document (the source comment is authoritative)

---

## Write Progress

- [x] Direction 1 (f-stack official/community) — §1, **done**
- [x] Direction 2 (FreeBSD upstream SMR/UMA/mp_maxid/MAXCPU semantics) — §2, **done**
- [x] Direction 3 (other userspace FreeBSD/NetBSD stack-port experiences) — §3, **done** (incl. §3.5 no-source list)
- [x] Direction 4 (correctness of the UMA per-CPU fast path without userspace preemption-disabling) — §4, **done**
- [x] Direction 5 (`cpuset_t`/`CPU_SETSIZE`/MAXCPU ABI) — §5, **done**
- [x] Knowledge boundaries (§6) and unified source list (§7) — **done**

> Batch-1 written: 2026-08-04 (§1/§2/§5); batch-2 (final): 2026-08-04 (§3/§4/§6/§7);
> batch-3 supplement: 2026-08-04 — backfilled the leader's 1st-poll code-verified results (§4.2(b-2) X2 conclusion backfill, §6 boundary item-4 `UMA_PCPU_ALLOC_SIZE`);
> batch-4 supplement: 2026-08-04 — completed the leader's 2nd-poll optional item, adding **§3.1(d) libuinet `uinet_uma_int.c` verification** (and accordingly **correcting** §3.1(a) item-4's wrong inference, §4.3's libuinet row, §3.5's unverified list, §7's source list).
> **This agent's research is fully complete; no unfinished items.** If the leader later wants additional directions (e.g. the actual call sites of the two locks in the libuinet-version `uma_core.c`, `smr_types.h` macro semantics), a new assignment can be made.

---

## 8. Final Backfill and Currency Statement (2026-08-04, appended by `res-web` at task close-out)

This round has closed: the verdict is **candidate A (whole-tree `-DSMP`)**, landed in commits `c7996a94f` (G1), `57b612d16` (G2), `06396b501` (spec 17 and all research/gate material). To prevent later readers from misreading this document's premises, three **final facts from the team's code evidence, conflicting with some of this document's inference premises**, are backfilled here. **Code/measurement always wins; the corresponding reasoning paragraphs in this document are to be considered superseded.**

| # | Final fact (source: team-internal `res-code`/`designer`/`res-build`/`tester` code & measurement) | Affects which part of this document |
|---|---|---|
| **F1** | **`curcpu` is hardcoded to 0 in f-stack; the UMA per-CPU cache does not go through `zpcpu_get()`** (discovered by `designer`; the key point deciding G1's success). | **Supersedes this document's §4 implicit premise.** §4.1/§4.2 argued under the assumption "the UMA per-CPU cache is indexed by slot via `zpcpu_get()`", deriving T1/T2/T3. That premise **does not hold** in f-stack's actual code: the UMA cache's index path and SMR's `zpcpu_get()` path **are two different paths**. So §4's reasoning that "slot exclusivity ⇒ UMA fast path safe" **must defer to `designer`'s code-level argument in spec 17**; this document's §4 retains only the reference value of "what upstream semantics are" (§4.1's `uma_int.h` original citation remains valid and was adopted). |
| **F2** | **all of f-stack's UMA `mtx` are no-ops**, and **`mp_maxid` has no assignment point at all** (verified by `res-code`). | **Strengthens and partially supersedes §4.1's last paragraph and §3.1(d)'s L2/L3**. This document once suggested "if f-stack stubs `uz_lock`/`ZDOM_LOCK`/`ZONE_CROSS_LOCK` empty, that is an independent defect" — now confirmed **they are indeed all no-ops**. Also, `mp_maxid` having no assignment point turns this document's §2.4 warning "`mp_maxid` and `UMA_ZONE_PCPU` must be modified in pairs" from "potential risk" into "confirmed gap" in the f-stack scenario. The final G2 adopted the **G2-b** form; this document's §3.1(d)-recommended G2-a was not adopted — **the `designer`'s G2-b ruling and the `reviewer`'s double-approval basis win**; this document's L2 point "`UMA_PAGE_HASH` is a truly shared structure; slot exclusivity provides zero protection for it" still holds; its disposition is in spec 17. |
| **F3** | **candidate A's cost was disproven by `res-build`'s measurement as "only 1 `smp_topo` stub needed"**; also `tester` caught a **3/4-thread `uma_startup1()` deterministic crash** that static analysis had not foreseen at all. | **Supersedes §5.3's last-paragraph reservation "candidate A's cost can only be quantified by the actual compile-error list"** (that reservation's direction was correct; the measured result is the cost is far lower than expected). It also confirms §6 boundary items 1 and 2's self-limitation was necessary — **external material cannot foresee runtime defects in f-stack's private code; the `uma_startup1()` crash is exactly such an example.** |

**This document's positioning (final)**: its **external facts and upstream-semantics references** (§2 SMR/UMA/counter/cpuset semantics, §3 libuinet/rump/Seastar/ANS precedents, §5 MAXCPU/cpuset ABI) were adopted at the gate; §2.1 (SMR per-CPU slot exclusivity) is cited as the core basis of G1's necessity argument, and §3.1/§3.2 (libuinet dense-index evidence, rump thread-exclusive-virtual-CPU) are written into design constraint D6 and the G2 fallback-form discussion. Its **reasoning and suggestions** (marked "derivation"/"analysis suggestion" per-location in the body) that conflict with table F1~F3 **all defer to code/measurement and are no longer used as a basis**. The "no reliable source found" items in §3.5/§6/§7 remain unchanged, not retrospectively written.

> `res-web` delivery complete; no unwritten material.
