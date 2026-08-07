# M17 / M4 —— G2 Implementation Record (`coder`)

> Task: per spec `17-SMP-aware-pcpu视图与去全局锁.md` §4.7's **D8 verdict = G2-b**, change `lib/include/vm/uma_int.h`'s `critical_enter/exit` override macros back to no-ops, slow path untouched.
> All compile and runtime numbers from **actual execution**, no estimation. Unverified items marked 【unverified】.
> This doc pairs with `_m17_E_coder_g1.md` (G1); G1 changes this round **not touched**.

---

## 0. Conclusion summary

| Item | Result |
|---|---|
| G2-b implementation | ✅ complete, form verbatim consistent with spec §4.7.1 (`do {} while(0)`) |
| **M4 gate mandatory-1 (comment wrong premise)** | ✅ **fixed**: deleted "No preemption in f-stack userspace", changed to "`curcpu` per-thread → preemption/migration doesn't change slot ownership" |
| **mandatory-1 post-fix re-verification** | ✅ re-clean build: error 0 / warning 51 / `.o` 248; **md5 unchanged, byte-identical** (pure comment change) |
| **G2-S5 (SMR residual 4 spots' stronger reason)** | ✅ **supplemented**: `uma_core.c`'s `smr_enter/smr_exit` measured **0 hits**, those 4 spots are inline function bodies never called |
| **G2-S3 (probe removal)** | ✅ **completed**: third party removed at 16:22:10, 16:40:46 fixed one blank line, full rebuild; **all criteria turned green** |
| **Post-removal product** | `example/helloworld` = `df05d2cd078d631ad2d8ee7caba8d387`, 30,392,632 bytes; `strings \| grep -c M17-PROBE` = **0**; **md5 verbatim consistent with pre-fix expected** |
| **Commit status** | ✅ commit-2 `57b612d16` = **exactly 2 files** (`ff_glue.c` + `uma_int.h`); commit-1 `c7996a94f` = 8 files; **`ff_glue.c`'s hunk-level split correctly done → G2 can revert alone**; both commits no `freebsd/` paths |
| **`tester` #9 closing regression** | ✅ **PASS** (two-sided ±2%): 2T −0.24% / 4T +0.06% / tm0-1p +2.10% / tm0-2p −2.96% |
| **Criteria system** | 11 criteria + 3 hardening, converged with `tester` over 6 rounds; **two over-estimates corrected by measurement** |
| Changed file count | **2** (`lib/include/vm/uma_int.h`, `lib/ff_glue.c`), per §4.7.5 hard limit |
| `uma_crit_lock` full-tree references | **0** (grep confirmed before deleting definition) |
| `lib/` clean build | rc=0, **error 0**, **warning 51** (= HEAD baseline), `.o` **248** |
| `example/` clean build | rc=0, error 0, `undefined reference` **0** |
| `example/helloworld` md5 | **`78c39a6f96e104412ce75351e402907b`** (30,392,664 bytes) |
| Pre-lock comparison binary | `example/helloworld_g1_prelock` = **`751a8153d3b200229cff99b3fa7650b0`** (30,392,704 bytes) |
| Post-lock copy | `example/helloworld_g2_nolock` = **`78c39a6f96e104412ce75351e402907b`** (byte-identical to `helloworld`) |
| Self-test 2-thread | ✅ startup no crash + 10s wrk **219,241.92 req/s** |
| Self-test 4-thread | ✅ startup no crash + 10s wrk **391,271.39 req/s** |
| R-a (`sizeof(struct uma_page)` over-allocation) | **not fixed this round**, recorded as tech debt |
| S5 (4-line comment compress to 2 lines) | **not done this round** |
| R-d (6 probes) | not removed (per leader instruction retained for `tester`) |

---

## 1. Change content (verbatim)

### 1.1 `lib/include/vm/uma_int.h` (`:45-52` → `:45-50`)

Before:

```c
extern volatile int uma_crit_lock;
#define critical_enter() do { \
    while (__sync_lock_test_and_set(&uma_crit_lock, 1)) \
        ; \
} while(0)
#define critical_exit()  do { \
    __sync_lock_release(&uma_crit_lock); \
} while(0)
```

After (**M4 gate mandatory-1 post-fix final form**):

```c
/*
 * curcpu is per-thread here (sys/pcpu.h), not per-CPU, so preemption cannot
 * change which uz_cpu[] slot this thread uses and no other thread uses it;
 * the dense pcpu slot is the whole protection (spec 17 §2.4).
 */
#define critical_enter() do {} while(0)
#define critical_exit()  do {} while(0)
```

- Form verbatim consistent with spec §4.7.1's target code, didn't自行 change to other form.
- **Keep empty macro not completely delete**: per §4.7.1's requirement. Reason is not depending on "`freebsd/sys/systm.h:186 #ifndef FSTACK` always exists" fragile assumption.
- **Comment 3 lines**, satisfies §4.7.1's "must comment" and minimal comment convention. Content explains "`curcpu` is per-thread not per-CPU → preemption neither changes this thread's `uz_cpu[]` slot, nor lets other threads use it → dense pcpu slot is entire protection", and points to spec 17 §2.4.

#### 1.1.1 【M4 gate mandatory-1】 First version comment's wrong premise and fix (honest record)

My submitted first version comment's first sentence was `No preemption in f-stack userspace`, **this is wrong statement**, `reviewer` judged as mandatory-1 (P2), I **accept**:

- f-stack's stack threads are **ordinary pthreads**, preempted and migrated by Linux scheduler; "userspace no preemption" doesn't hold.
- G2's real safety reason is **`curcpu` thread-bound not CPU-bound** (`lib/include/sys/pcpu.h:34 #define curcpu PCPU_GET(cpuid)` → `pcpup->pc_cpuid`, `pcpup` is `__thread`). So invariant "same `uz_cpu[i]` slot only one thread accesses at any time" **doesn't depend on whether preempted or migrated** —— this condition is **stronger** than upstream FreeBSD's "same CPU disable preemption", not weaker.
- Severity: this comment is "why can remove lock" this highest-risk decision's **sole written basis**. If later people remove other protections based on "no preemption" wrong premise, would introduce real defect. Same type as G1's mandatory-2: wrong comments more harmful than no comments.
- Post-fix re-ran clean build per §3.5, **binary byte-identical** (pure comment change).

### 1.2 `lib/ff_glue.c` (delete `:146`)

```c
 volatile int smp_started;
 u_int mp_maxid;
-volatile int uma_crit_lock;
```

**Pre-delete full-tree reference check** (grep before delete): `grep -rn "uma_crit_lock" --include=*.c --include=*.h --include=*.S --include=Makefile* --include=*.mk .` → only 4 hits in these 2 files, **zero references elsewhere**, **including `freebsd/` upstream tree**. Post-delete secondary verification: `nm libfstack.a | grep -c uma_crit_lock` = 0.

### 1.3 Change set separability (§4.7.5)

**Must correct one fact for leader**: leader's message said "G1 and G2's changes land in different files, naturally separable" —— **this statement is inaccurate**. `lib/ff_glue.c` **simultaneously** carries G1 and G2 changes:

| File | G1 change | G2 change |
|---|---|---|
| `lib/Makefile` | `-DSMP` | — |
| `lib/ff_dpdk_if.c` / `.h` | `ff_cur_proc_id()` etc | — |
| `lib/ff_freebsd_init.c` | triple / slots / hash timing | — |
| `lib/ff_kern_synch.c` / `ff_kern_timeout.c` / `lib/include/sys/pcpu.h` | `curcpu` / `timeout_cpu` / `pause_wchan` | — |
| **`lib/ff_glue.c`** | **`smp_topo()` stub (new 7 lines near `:168`)** | **delete `:146`'s `uma_crit_lock`** |
| **`lib/include/vm/uma_int.h`** | — | **`critical_enter/exit` → no-ops** |

**But still separable**, basis is `git diff` measured these two land in **two non-adjacent hunks**:

```
lib/ff_glue.c
@@ -143,7 +143,6 @@   ← G2 (delete uma_crit_lock)
@@ -169,6 +168,13 @@  ← G1 (smp_topo stub)
```

Two hunks ~25 lines apart, no overlapping context → split commit needs **hunk-level staging** for `lib/ff_glue.c` (`git add -p` or `git apply --cached` single hunk), cannot whole-file `git add`. **Please leader note this at M7 commit**: if whole-file `git add` `ff_glue.c` to commit-1, G2 cannot revert alone, violates §4.7.5.

Per leader instruction **did not execute `git commit`**. Current workspace is "G1 + G2 both applied" uncommitted state.

---

## 2. Semantic equivalence basis (why lock removal ≠ "no protection")

### 2.1 Post-lock UMA fast-path expansion form【measured】

Using `-E` preprocess `uma_core.c` (compile command from this round build log line 867, only changing `-c` to `-E`):

| Check item | Result |
|---|---|
| `__sync_lock_test_and_set` occurrence count | **0** (pre-change was lock's core instruction) |
| `uma_crit_lock` occurrence count | **0** |
| Our `uma_int.h` override macro enters preprocessing output position | Line **9736** |
| `do {} while(0)` occurrence count (all after line 9736) | **26** |

→ **`uma_core.c` body's `critical_enter/exit` call sites all expanded to empty statements**, no more atomic instructions.

### 2.2 Residual 4 `critical_enter/exit` are existing behavior, unrelated to G2【measured】

Preprocessing output still has 4 **non-macro-expanded** calls:

```
2777:void critical_enter_KBI(void);      ← declaration only, not call
2796:critical_enter(void)← systm.h's inline definition (#ifndef FSTACK already emptied)
2808:critical_exit(void)                 ← same
6960: critical_enter();   ← freebsd/sys/smr.h inline function (smr_enter)
6990: critical_exit();← same
7001: critical_enter();   ← same (smr_exit side)
7041: critical_exit();
```

- These 4 call sites are in `freebsd/sys/smr.h`, and `smr.h` in preprocessing order **before** (6960 < 9736) our `uma_int.h`'s macro definition → they bind to `systm.h`'s **inline empty function**, **identical before and after change**.
- **Stronger reason (`reviewer` suggested G2-S5, this round supplemented and verified)**: these 4 are not call sites at all, but `smr_enter()` / `smr_exit()` two inline functions' **function bodies**; and `uma_core.c` **never calls these two functions** —— measured `grep -cE "smr_enter|smr_exit" freebsd/vm/uma_core.c` = **0**. `uma_core.c`'s actual SMR interfaces are only write-side/management-side 6: `smr_advance(` ×3, `smr_poll(` ×2, `smr_create(` ×1, `smr_init(` ×1, `smr_synchronize(` ×1, `smr_wait(` ×1, **none are read-side `smr_enter/smr_exit`**. And these 6 are **cross-TU external function calls** (implemented in `freebsd/kern/subr_smr.c`, that TU compiled without our `lib/include/vm/uma_int.h`, unaffected by override macros).
  → So those 4 inline function bodies in this TU **never instantiated called**, "what they expand to" has **no effect** on `uma_core.c`'s generated code. This is stronger than "they bind to systm.h's empty function": former doesn't depend on `systm.h:186 #ifndef FSTACK`'s current state.
- This is consistent with `_m17_gate_plan.md` item 93's established fact: **SMR read-side's `critical_enter()` was always no-op, never protected by `uma_crit_lock`**. → **G2 zero impact on SMR**.

### 2.3 Therefore G2's correctness landing

Post-lock UMA per-cpu cache's sole protection is G1's established invariant "**each stack thread exclusively owns a dense pcpu slot, and thread↔slot 1:1 never migrates**". This round §4's runtime data is direct evidence that this invariant **post-lock** still holds (`reviewer` required: post-lock cannot reuse pre-lock data).

---

## 3. clean build measured

**Both `lib/` and `example/` directories `make clean` first then full `make`, no incremental compile** (compliant with clean-build convention).

### 3.1 `lib/`

| Metric | Measured | Threshold / baseline | Verdict |
|---|---|---|---|
| `make clean` return code | **0** | — | — |
| `make -j16` return code | **0** | 0 | PASS |
| `grep -c 'error:'` | **0** | 0 | PASS |
| `grep -c 'warning:'` | **51** | ≤ 51 (HEAD baseline) | **no increase**, PASS |
| `.o` output | **248** | 248 | PASS |
| `libfstack.a` | generated, **7,000,540** bytes | generated | PASS |

### 3.2 `example/`

| Metric | Measured | Verdict |
|---|---|---|
| `make clean` return code | **0** | — |
| `make` return code | **0** | PASS |
| `grep -c 'error:'` | **0** | PASS |
| `grep -c 'undefined reference'` | **0** | PASS |
| `nm libfstack.a \| grep -c uma_crit_lock` | **0** | symbol indeed gone |

### 3.3 md5 (**taken in same command sequence as `make clean`**, avoiding previous round's version mismatch)

```
$ cd /data/workspace/f-stack/example && make clean && make && ls -l helloworld && md5sum helloworld helloworld_g1_prelock
-rwxr-xr-x 1 root root 30392664 Aug  4 15:10 helloworld
78c39a6f96e104412ce75351e402907b  helloworld
751a8153d3b200229cff99b3fa7650b0  helloworld_g1_prelock
```

| Binary | md5 | Size | mtime | Meaning |
|---|---|---|---|---|
| `example/helloworld` | `78c39a6f96e104412ce75351e402907b` | 30,392,664 | 2026-08-04 15:10:44 | Current = G1+G2 (post-lock) |
| `example/helloworld_g2_nolock` | `78c39a6f96e104412ce75351e402907b` | 30,392,664 | 2026-08-04 15:10:44 | Post-lock copy (`cp -p`) |
| `example/helloworld_g1_prelock` | `751a8153d3b200229cff99b3fa7650b0` | 30,392,704 | 2026-08-04 15:00:57 | **Pre-lock** (G1-only, `uma_crit_lock` still present) |

**About previous round md5 mismatch (honest record)**: my previous round reported `d49268db…` inconsistent with `reviewer`'s `751a8153…`. This round started **before any changes** by taking md5 of unchanged binary, getting **`751a8153d3b200229cff99b3fa7650b0`** —— **consistent with `reviewer`'s value**. Therefore can determine: `reviewer`'s value is correct, my previous round's reported value came from an earlier intermediate build, is my reporting error, not source state divergence. This round put `md5sum` into `make clean && make`'s same command sequence per requirement, preventing re-mismatch.

**Harder version judgment than md5** (`tester` proposed, this text adopts and rechecks):

```
$ grep -c "uma_crit_lock" helloworld_g1_prelock   → 1   ← pre-lock, symbol present
$ grep -c "uma_crit_lock" helloworld_g2_nolock    → 0   ← post-lock, symbol gone
```

md5 only proves "whether two are same", symbol presence/absence directly proves "whether this is pre-lock or post-lock".

### 3.4 G1 change integrity check

`git diff --stat`: `config.ini` 26 (user local, untouched), `lib/Makefile` 4 (G1 -DSMP intact), `ff_dpdk_if.c` 8 (G1 intact), `ff_dpdk_if.h` 1 (G1 intact), `ff_freebsd_init.c` 115 (G1 intact), `ff_glue.c` 8 (G1 smp_topo + G2 delete lock), `ff_host_interface.c` 8 (G1 probe), `ff_host_interface.h` 4 (G1 probe), `ff_kern_synch.c` 4 (G1 intact), `ff_kern_timeout.c` 6 (G1 intact), `include/sys/pcpu.h` 2 (G1 curcpu intact), `include/vm/uma_int.h` 14 (G2).

- `-DSMP` still present (build log line 867's actual compile command shows `-DFSTACK -DSMP`).
- `lib/include/sys/pcpu.h`'s `curcpu` → `PCPU_GET(cpuid)` untouched.
- `freebsd/` upstream tree **zero changes**.
- **`config.ini` this agent全程 untouched** (self-test used separately-stored independent config, see §4.1), compliant with config.ini commit constraint.

### 3.5 【M4 gate mandatory-1】 Post-comment-fix re-verification clean build (2026-08-04 15:48)

`lib/` and `example/` **each `make clean` then full rebuild again**, `md5sum` still taken in same command sequence:

| Metric | Pre-fix (15:10) | Post-fix (15:48) | Verdict |
|---|---|---|---|
| `lib/` make clean rc / make rc | 0 / 0 | **0 / 0** | PASS |
| `lib/` `error:` | 0 | **0** | PASS |
| `lib/` `warning:` | 51 | **51** | no increase, PASS |
| `lib/` `.o` count | 248 | **248** | consistent |
| `libfstack.a` bytes | 7,000,540 | **7,000,540** | consistent |
| `example/` make clean rc / make rc | 0 / 0 | **0 / 0** | PASS |
| `example/` `error:` / `undefined reference` | 0 / 0 | **0 / 0** | PASS |
| `example/helloworld` bytes | 30,392,664 | **30,392,664** | consistent |
| **`example/helloworld` md5** | `78c39a6f96e104412ce75351e402907b` | **`78c39a6f96e104412ce75351e402907b`** | **unchanged** |
| `strings helloworld \| grep -c M17-PROBE` | 3 | **3** | probes intact |
| `nm lib/libfstack.a \| grep -c uma_crit_lock` | 0 | **0** | symbol still absent |

**Key conclusion: md5 unchanged, byte-identical** (`cmp -s helloworld helloworld_g2_nolock` → identical). Because mandatory-1 is **pure C comment** change, doesn't enter preprocessing output's code part → generated code completely identical.

→ **`tester`'s running `helloworld_g2_nolock` copy no need to update, its post-lock matrix data no need to invalidate**.

**Incidental finding (important, avoided one incident)**: when executing leader's required `cp -p helloworld helloworld_g2_nolock` got **`cp: cannot create regular file 'helloworld_g2_nolock': Text file busy`**, `fuser` / `ps` verified as **`tester` was currently executing that copy** (PID 1067944, running 33s).

- Because md5 was already unchanged, **I didn't retry `cp`, nor force overwrite in any way** (overwriting executing binary would破坏 `tester`'s ongoing stress test).
- Record general lesson: **must check usage before writing to `tester`'s in-use copy path**. `cp` was luckily blocked by kernel's ETXTBSY protection, but if using `install`/`cat >` etc truncating writes, would directly ruin `tester`'s running process and this round's data.

---

## 4. Self-test (runtime)

### 4.1 Method and collision avoidance

- **Don't modify `config.ini`**: separately store two self-test dedicated configs (content identical to `config.ini` except `lcore_mask`, `md5sum` verified 2-thread档 consistent with `config.ini`):
  - `/data/workspace/f-stack/config.m17_g2_2t.ini` (`lcore_mask=6` → 2 threads, `thread_mode=1`)
  - `/data/workspace/f-stack/config.m17_g2_4t.ini` (`lcore_mask=1e` → 4 threads, `thread_mode=1`)
- **Coordinate with `tester` before using machine**: first send_message requesting exclusive window, `tester` explicitly replied "now ok" and `ps` no residual before starting.
- **Process termination all via `/data/workspace/kill_process.sh <specific PID>`** (not process name, avoid误伤).
- **Probe output destination pitfall (this round hit and resolved)**: app's `printf` doesn't go to shell redirect target file, but to f-stack's own log `example/helloworld.log` and `example/f-stack-0.log`. To ensure unambiguous data attribution, use **byte-offset isolation**: record two logs' `wc -c` before start, use `tail -c +$((OFF+1))` after run to only take this run's new part.

### 4.2 2-thread档 (post-lock)

Process alive 106s, `nlwp=5`, no crash, no panic.

| dense_idx | tid | pc_cpuid | pc_zpcpu_offset | curcpu | `smr_c_seq` (SMR slot) | `uz_cpu[curcpu]` (UMA cache slot) |
|---|---|---|---|---|---|---|
| 0 | 140363320057856 | 0 | 0 | 0 | `0x7fa8e1cc7c80` | `0x7fa8e1ca7180` |
| 1 | 140363278877696 | 1 | 4096 | 1 | `0x7fa8e1cc8c80` | `0x7fa8e1ca7200` |

- SMR slot distance = `0x1000` = **4096** ✓ (= `UMA_PCPU_ALLOC_SIZE`)
- UMA cache slot distance = `0x80` = **128** ✓ (= `sizeof(struct uma_cache)`), two slots **distinct** ✓
- `dense_idx == pc_cpuid == curcpu` three consistent ✓
- `[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=2 / name=pcpu_zone_64 uk_ppera=2`, `mp_maxid=1` → **`uk_ppera == mp_maxid + 1`** ✓
- 10s wrk (`f-stack-client`上 `/data/wrk/wrk -t2 -c100 -d10s http://<DPDK_NIC_IP>/`): **219,241.92 req/s**, `2194165 requests / 0 error`, post-stress log zero new anomalies.

### 4.3 4-thread档 (post-lock)

Process alive 76s, `nlwp=7`, no crash, no panic.

| dense_idx | pc_cpuid | pc_zpcpu_offset | curcpu | `smr_c_seq` | `uz_cpu[curcpu]` |
|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | `0x7efdbaaf4c80` | `0x7efdbaad0980` |
| 1 | 1 | 4096 | 1 | `0x7efdbaaf5c80` | `0x7efdbaad0a00` |
| 2 | (scalar line lost, see below) | — | — | `0x7efdbaaf6c80` | `0x7efdbaad0a80` |
| 3 | 3 | 12288 | 3 | `0x7efdbaaf7c80` | `0x7efdbaad0b00` |

- SMR slots: 4 addresses form **common difference 4096** arithmetic sequence ✓
- UMA cache slots: 4 addresses form **common difference 128** arithmetic sequence, **pairwise distinct** ✓
- `uk_ppera=4`, `mp_maxid=3` → **`uk_ppera == mp_maxid + 1`** ✓
- **`dense_idx=2`'s `[M17-PROBE]` scalar line lost again** (`[M17-PROBE-SLOT]` line present). Same reason as G1 §7: probe uses lockless `printf`, multi-thread simultaneous write to same FILE* can lose/interleave whole line. **This is probe's own observation defect, not tested logic's problem** —— that thread's `SLOT` line addresses exactly fall on arithmetic sequence's 3rd term, reverse-derive `pc_zpcpu_offset=8192`, `curcpu=2`, self-consistent. **【derivation, not direct measurement】**
- 10s wrk (`-t4 -c200 -d10s`): **391,271.39 req/s**, `3921039 requests / 0 error`, post-stress new log zero panic / zero segfault.
  - Note: log keyword scan once hit `fault`, line-by-line check confirmed **false positive** —— matched ipfw init line `... de**fault** to accept ...`. Confirmed no real fault.

### 4.4 Self-test throughput numbers' comparability limitation (important)

**My wrk numbers cannot be directly compared with `tester`'s matrix, cannot be used for DoD-5 judgment**:
- I used `-t2 -c100 -d10s` / `-t4 -c200 -d10s` (short, low concurrency), purpose only "stress the lockless alloc path a bit confirm no crash";
- `tester`'s pre-lock matrix (2-thread median 235,845 req/s, 4-thread 248,961 req/s, soak 2/4-thread 499,223/487,968 req/s) used its own params and round count caliber.
- My 4-thread 391k明显 higher than `tester`'s 4-thread 248k, **almost certainly wrk param/connection count difference** not G2 benefit, **must not claim performance gain**. DoD-5's formal judgment must be given by `tester` with same-caliber A/B cross-retest.

### 4.5 Incidental observation (for `designer`/`reviewer` attention)

4-thread档 log appeared: `TCP Hpts created 4 swi interrupt threads and bound 0 to cpus`. This is consistent with G1 residual risk list's "`tcp_hpts` instance count 1→N with `mp_ncpus`" record, **now observable fact** (`mp_ncpus=4` → 4 hpts swi threads), no longer just static inference. This round didn't change any hpts code; `bound 0 to cpus` says no core binding, whether need handling请 `designer` verdict.

---

## 5. Alignment with spec §4.7 item by item

| spec requirement | Implementation |
|---|---|
| §4.7 hard prerequisite: `curcpu` already per-thread + DoD-1 criterion ⑤ passed | confirmed by `reviewer` in M3 gate; this round §4.2/§4.3 **post-lock** re-measured PASS |
| §4.7.1 change to `do {} while(0)` no-ops | ✅ verbatim consistent |
| §4.7.1 delete `uma_crit_lock` definition | ✅ (grep full-tree zero refs before delete) |
| §4.7.1 keep empty macro not completely delete | ✅ (and measured confirmed `systm.h:186 #ifndef FSTACK` current state) |
| §4.7.1 must comment (short) | ✅ substantive text 3 lines; first version comment premise wrong, fixed per M4 gate mandatory-1 (§1.1.1) |
| §4.7.1 slow path untouched | ✅ didn't touch `ZDOM_LOCK`/`KEG_LOCK`/`vsetzoneslab`/`uma_page_slab_hash` any |
| §4.7.2 / §4.7.3 don't do G2-a / G2-c | ✅ no new locks, no per-cpu locks |
| §4.7.4 step L0 | ✅ currently at L0 (didn't trigger L1/L2) |
| §4.7.5 diff surface limited to 2 files, can revert alone | ✅ 2 files; **but `ff_glue.c` needs hunk-level split, see §1.3** |

---

## 6. `reviewer` suggestions' handling (honest record)

### 6.1 R-a (`lib/ff_freebsd_init.c:381` uses `sizeof(struct uma_page)` not `sizeof(struct uma_page_head)`) —— **not fixed this round**

Judgment basis (**and corrected `reviewer` and leader's impact estimate**):

1. **Memory safety**: `sizeof(struct uma_page)` (40B) > `sizeof(struct uma_page_head)` (8B), is **over-allocation**, only waste no OOB.
2. **Waste doesn't scale with thread count** —— this allocation is in `ff_freebsd_init()`, and `ff_freebsd_init()` **executes once per process** (main thread), `uma_page_slab_hash` is **process-global single table**, worker threads don't each allocate. So under `thread_mode=1` whether 2 or 16 threads, waste is always `8192 × (40 − 8) = 262,144` bytes ≈ **256KB / process**, **not 256KB / thread**.
3. Therefore **`reviewer`'s suggested "worth fixing in thread_mode=1 multi-instance" motivation doesn't hold** (multi-threading doesn't放大 it), I **cannot prove it causes actual problems in multi-threading** —— per leader's "unless you can prove it causes actual problems in multi-threading, I lean not fix" instruction, **not fixed this round**.
4. Additional reason: it's not in G2's 2-file diff surface (§4.7.5 explicitly "any other change must not mix into commit-2"), fixing it would need to attach to commit-1, and commit-1's G1 gate already PASS, change would invalidate gate product and binary md5, need re-run gate. Benefit (256KB) far less than cost.

→ **Recorded as tech debt**: `lib/ff_freebsd_init.c:381` hash bucket array over-allocates 5x (40B/bucket vs should be 8B/bucket), wastes 256KB/process, memory-safe, not this round introduced. Suggest fixing in independent cleanup commit, and simultaneously review whether `num_hash_buckets=8192` fixed value still appropriate for large-memory/multi-thread.

### 6.2 S5 (`lib/ff_freebsd_init.c:319-323`'s 4-line comment compress to 2 lines) —— **not done this round**

Same as §6.1 point 4: that file is **G1 (commit-1)**'s change surface, G1 gate already PASS, binary md5 already independently verified by `tester` and used for A/B comparison. **Compressing 2 lines comment to invalidate G1 gate product and two comparison binaries, cost clearly disproportionate**. Suggest merging into pre-M7 probe removal change (which needs rebuild + rerun clean build anyway).

If leader/`reviewer` think must do this round, please明示, I will连带 re-produce G1/G2 two binaries and update all md5, and notify `tester` to invalidate current comparison.

### 6.3 R-d (6 `#if 1 /* M17 temporary probe */` probes) —— per instruction **not removed**

Verified in G2 binary probes **intact usable** (`tester` post-lock needs rerun slot isolation verification):

```
$ strings example/helloworld | grep "M17-PROBE"
[M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
[M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
[M17-PROBE-ZONE] name=%s uk_ppera=%u uk_rsize=%u mp_maxid=%u
```

Wait for leader to notify after M5 end to remove (DoD-8), post-removal must rerun clean build.

---

## 7. DoD-8 cleanup list (this round's new temp artifacts)

Before M7 must use `/data/workspace/rm_tmp_file.sh` to clean (**strictly no direct `rm`**):

| Path | Description | Cleanable when |
|---|---|---|
| `/data/workspace/f-stack/example/helloworld_g1_prelock` | Pre-lock comparison binary | **After `tester` explicitly confirms A/B cross + post-lock slot re-verification all done** |
| `/data/workspace/f-stack/example/helloworld_g2_nolock` | Post-lock comparison binary | same |
| `/data/workspace/f-stack/config.m17_g2_2t.ini` | Self-test config (2-thread) | After self-test ends |
| `/data/workspace/f-stack/config.m17_g2_4t.ini` | Self-test config (4-thread) | After self-test ends |
| `/data/workspace/f-stack/example/m17_g2_2t.log`, `m17_g2_4t.log` | Self-test stdout redirect logs | After self-test ends |

(G1's 6 probes are **code** changes, by R-d go "remove + rebuild" process, not in this table.)

### 7.1 【G2-S3】 Post-M5 closing order (`reviewer` suggestion, leader confirmed)

**Must follow this order, otherwise probes would mix into product commit**:

1. M5 fully ends (`tester`'s post-lock matrix + A/B cross + slot re-verification all complete);
2. **leader notifies me**后, I remove 6 `#if 1 /* M17 temporary probe */` probes (DoD-8's code part);
3. I then run one **`lib/` + `example/` clean build**, and in same command sequence give **new `example/helloworld` md5** (probe removal truly changes generated code, md5 **must change**, unlike this round's comment change);
4. Then leader splits **commit-1(G1) / commit-2(G2)**, where `lib/ff_glue.c` uses `git add -p` hunk split;
5. Clean this table's temp binaries and configs/logs (via `rm_tmp_file.sh`).

**Must confirm `tester` has no process running before removing** (this round已 hit `Text file busy`, see §3.5).

### 7.2 Probe removal criteria system (11 + 3 hardening) and failure boundaries

Criteria converged over 6 rounds with `tester`. **This section's value is not the list itself, but each criterion's "what it cannot prove"** —— below §7.3 records two over-estimates corrected by measurement.

| # | Criterion | Baseline → Expected |
|---|---|---|
| 1 | `diff --new-line-format='%L' --old-line-format='' --unchanged-line-format='' BEFORE AFTER > f`, **must `rc≤1` and `wc -c` = 0** | 0 / 0 / 0 |
| 2 | `git diff lib/ff_host_interface.c lib/ff_host_interface.h` | non-empty → **completely empty** (byte-identical to HEAD) |
| 3 | Three-file line counts | 438/625/206 → **379/617/202** |
| 4 | Leading `}` count (ffinit / hi.c) | 7/52 → **5/51** |
| 5 | `grep -rl "M17" lib/` (whole dir, incl `.o`/`.a`) | 5 → **no output** |
| 6 | `nm lib/libfstack.a` probe symbols | 2 → **0** |
| 7 | `strings <product> \| grep -c M17-PROBE` | 3 → **0** |
| 8 | `lib/`+`example/` **both clean build**, rc=0 / error 0 / **warning = 51** (≠51 also fails) | PASS |
| 9 | `tester` closing regression (2T/4T/tm=0), **two-sided ±2%** | PASS |
| 10 | ① `git status --porcelain lib/` **set comparison** (not count) 11→9; ② `^??` 0→0; ③ `freebsd/ example/ tools/` tracked changes 0→0; ④ full-repo tracked 12→10 | all |
| 11 | `md5sum -c` 8 "files not to be touched this time" | 8/8 OK |
| hardening | `git diff --summary lib/` (mode change / new / delete / rename) | empty → empty |

**Criteria before-side at `/data/workspace/m17_judge_baseline/` (outside repo)**.

- **Why must be outside repo**: putting in-repo would make `git status --porcelain lib/ | grep -c '^??'` from 0 to non-0, **directly breaking criterion #10-② —— criteria themselves invalidate criteria**.
- **Why must migrate from `/tmp`** (`tester` proposed): `/tmp` is system-cleaned, lost on reboot; once cleaned, #1/#11 directly can't run.
- **`cp -p` preserving mtime gives a byproduct旁证**: `ff_freebsd_init.c` since 14:52, `ff_host_interface.c/.h` since 14:01 unchanged —— mutually independent corroboration with "source not touched".

**【Hard rule】 Prohibit refreshing baseline to make criteria pass.** #1/#11/#10-① baselines taken from `reviewer`-reviewed state (M3/M4 gates covered those 8 files). If `reviewer`'s required new change causes #11 FAIL, **must first get leader or `reviewer` written approval and explain reason** before re-collecting; re-collect must record "old baseline value, new baseline value, re-collect reason, approver" four items. **Unilateral baseline refresh equals deleting that criterion.**

**【Semantic boundary】 #11 only proves "not touched by this probe removal", doesn't prove "content is correct".** Content correctness is M3/M4 gate's responsibility, the two **cannot substitute for each other**.

**【Stop condition】 #1 / #3 / #4 / #10 / #11 any one doesn't match, immediately stop and report leader and `tester`, prohibit continuing with "other criteria all passed" excuse.**

### 7.3 Removal actuals: third party executed, criteria 10/11 pass, #3 doesn't match (this agent stopped per stop condition)

**Fact**: `lib/ff_freebsd_init.c` mtime **16:22:10**, then full rebuild (`.o` 16:22:29~45, `libfstack.a` 16:22:45, `example/helloworld` 16:22:55). **This agent never executed removal action** (last source change was 15:4x's gate mandatory-1, only changed `uma_int.h` comment). **Actual executor待 leader confirmation**.

**Discovery path worth recording**: this agent originally just wanted to check P3 adjacent `__sync_lock_release(&init_lock);` whether at line 274, result `grep -n init_lock` reported 179/189/220, **line numbers don't match 14:52's reading**, then discovered file changed. i.e.: **this time "line number drift" byproduct signal exposed the change, not any criterion actively alarmed** —— criteria were run after the fact.

| # | Measured | Verdict |
|---|---|---|
| 1 | rc=1, new **0 bytes** (3 files) | ✅ pure deletion holds |
| 2 | empty | ✅ byte-identical to HEAD |
| **3** | **380** / 617 / 202 (expected 379/617/202) | ❌ **off by 1 line** |
| 4 | 5 / 51 | ✅ (but see correction below) |
| 5 | no output | ✅ |
| 8 | `.o` **248/248 all at 16:22** (16s span parallel), none residual old mtime → **full rebuild** | ✅ |
| 9 | PASS, see §7.4 | ✅ |
| 10 | 9 / 0 / 10 / 0 | ✅ |
| 11 | **8/8 OK** | ✅ G2 deliverable not误伤 |

**#3's 1-line deviation located**: current `ff_freebsd_init.c` **lines 377, 378 are adjacent blank lines** (after `ff_stack_inited = 1;`). Cause is deleting P4 block时 **didn't delete adjacent original 436 blank line**, so original 431 and 436 two blank lines are adjacent. **Pure format blemish, no semantic impact**.

**This agent didn't self-repair**, per §7.2's stop condition (#3 in stop condition). Already three times requested leader verdict "fix or not", and gave suggestion: **fix**. Reason is not that blank line itself, but —— **leaving a long-term FAIL stop criterion would make "stop condition" itself something habitually ignorable**, its harm greater than one extra blank line.

**Fix action's built-in verification (md5 expected)**: if verdict fix, expected clean build后 `helloworld` md5 **still `df05d2cd078d631ad2d8ee7caba8d387`**, basis three:
1. **`lib/` compile without `-g`** (`lib/Makefile:31`'s `DEBUG=` whole line commented; actual command `cc -c -O2 -fno-strict-aliasing …` no `-g`). **This most key**: if with `-g`, deleting a blank line would shift DWARF line table, `.o` must byte-change, md5 must change, **even if codegen completely identical**.
2. `ff_freebsd_init.c` **no `__LINE__`/`__FILE__`** (grep no hits); `panic()` at line 106, before blank line and doesn't embed line number; `KASSERT` compiled out without `INVARIANTS`.
3. **Empirical precedent**: gate mandatory-1 was pure comment change, clean build后 md5 byte-identical (§3.5). Comments and blank lines are both "doesn't affect generated code" change category.

→ So: **md5 consistent with expected → fix confirmed no side effect, and `tester`'s #9 result can directly reuse; md5 if inconsistent → contradicts above three bases, is abnormal signal needing stop and investigate**.

### 7.3.1 Follow-up actuals: blank line fixed, md5 expected confirmed, commit done

**Timeline (all mtime/git measured)**:
```
16:40:46  lib/ff_freebsd_init.c changed again (third party) → 380 → 379 lines, adjacent blank lines gone
16:42:19  ff_freebsd_init.o rebuilt 16:42:42 libfstack.a      16:42:44 example/helloworld
thereafter      commit done (workspace lib/ no modified)
```

**① This agent's md5 expected confirmed (§7.3's three bases hold)**
```
post-fix + rebuild example/helloworld = df05d2cd078d631ad2d8ee7caba8d387   ← verbatim consistent with expected
```
→ Deleting blank line **indeed didn't change generated code** (`lib/` no `-g`, no `__LINE__`, comment-change empirical precedent three bases得到实证 support).
→ **`tester`'s #9 closing regression target (md5 `df05d2cd…`) and final commit product byte-identical → #9 result fully valid for final product, no rerun needed.** This is this round's most important closure: **closing regression tested exactly the commit product itself, not its approximate.**

**This md5 expected's evidence nature (`tester` pointed out, worth noting separately)**: this expected was written **before fix action happened** (see §7.3 and `_m17_F_runtime.md` part 4 Y4-2), is **pre-event prediction confirmed by post-event data**, not post-event explanation. So §7.3's three bases are **prediction-tested reasoning**, not "plausible reasoning" —— this property is more valuable on evidence chain than the conclusion itself.

**Independent recheck**: above md5/byte count/line count/commit list, `tester`已 used read-only commands to self-run once, results item-by-item consistent with this text (its record see `_m17_F_runtime.md` part 5). **This round both sides' every number was independently re-computed by the other, no single-party transcription adopted.**

**② Criteria final state (post-commit rerun)**
| # | Expected | Measured | Verdict |
|---|---|---|---|
| 1 | 0 bytes ×3, rc≤1 | rc=1, **0 / 0 / 0** | ✅ |
| 2 | empty | **0 bytes** | ✅ |
| **3** | **379 / 617 / 202** | **379 / 617 / 202** | ✅ **turned green** (was 380) |
| 4 | 5 / 51 | 5 / 51 | ✅ |
| 5 | no output | **0 files** | ✅ |
| 11 | 8/8 OK | **8/8 OK** | ✅ |
| hardening | `git diff --summary lib/` empty | **0 bytes** | ✅ |
| supplement | adjacent blank line scan | **none** | ✅ |
| **10** | 9 / 0 / 10 / 0 | **0 / 0 / 1 / 0** | ⚠ **baseline invalid due to commit** (see below)|

**#10's baseline invalid post-commit —— this is exactly consistent with §8 risk 10's pre-registration**, not意外: `git status --porcelain lib/` from 9 to 0 (lib/ all committed), full-repo tracked changes from 10 to 1 (only `config.ini`). **#10's post-commit equivalent form** should change to checking commits themselves:

```
commit-2 57b612d16  "Drop the global uma_crit_lock spinlock ..."
          → lib/ff_glue.c、lib/include/vm/uma_int.h  ← exactly 2 files, per spec §4.7.5 hard limit
commit-1  c7996a94f  "Make the f-stack kernel view SMP-aware for native-mt ..."
          → lib/Makefile、ff_dpdk_if.c、ff_dpdk_if.h、ff_freebsd_init.c、ff_glue.c、
             ff_kern_synch.c、ff_kern_timeout.c、include/sys/pcpu.h   ← 8 files
both commits contain no freebsd/ paths     ← "upstream tree zero changes" invariant re-confirmed at commit layer
lib/ff_host_interface.c / .h not in either commit ← probes fully removed, both files byte-identical to HEAD
```

**③ `ff_glue.c`'s hunk-level split correctly done** —— this is the risk point this agent raised in §1.3 and repeatedly reminded: `lib/ff_glue.c` **simultaneously** appears in commit-1 and commit-2, showing commit时确实按 hunk split (`git add -p`) not whole-file `git add`. **Therefore commit-2 (G2) can be `git revert`ed alone, spec §4.7.5's separability requirement satisfied.**

### 7.4 `tester`'s #9 closing regression: PASS, and ABA rescued one misjudgment

**#9已 changed from single-sided to two-sided judgment** (`tester` proposed, this agent rechecked its argument holds): 4 probe blocks all in startup path (P1 per thread once, P3 per worker once, P4 whole process once, P2 function definition only), **zero on packet path → per-packet overhead zero → semantic expectation is "throughput completely unchanged" not "not worse"**. Therefore **higher同样 suspicious** (may have误删 real working logic), single-sided criterion would misjudge this as PASS.

**Result (data source: `tester`)**: 2-thread **−0.24%**, 4-thread **+0.06%**, tm=0 1-process **+2.10%**, tm=0 2-process −2.96% (weak evidence已标注) → **PASS**. Hang check all档 pass (process alive + `curl`=200 + `NLWP` 5/7/4/4+3, new log `panic|assert|segmentation` all 0). **Runtime empirical probes indeed gone**: each档 new log `grep -c M17-PROBE` = **0** (part 3 same position must have 4~5).

**#9's one failure mode (this agent proposed,已 incorporated into `tester` judgment rules)**: P3 block adjacent to `__sync_lock_release(&init_lock);` (`init_lock` for worker serialization, see `ff_freebsd_init.c:179/189/220`). If误删 that line, consequence is **next worker startup永久 blocks —— manifests as "hang" not "crash"**. So "no traffic after startup / process hang / `wrk` can't connect" all judge **FAIL, must not treat as environment jitter retry**. This time that line intact (3 references all present, runtime also no blocking).

**ABA same-window comparison rescued one FAIL misjudgment (important methodological conclusion)**: if per pre-registered **single-point** criterion, 4-thread档 no-probe merged 6-round median 247,068.79 vs part 3 baseline 254,913.26 = **−3.08%**, outside two-sided interval `[249,815, 260,011]` → **would judge FAIL**. But ABA shows:
```
A1 no-probe 242,102.55 (first block low)│ B with-probe 248,303.61 │ A2 no-probe 248,459.02 (vs B diff +0.06%)
```
**With-probe version `g2_nolock` (md5 unchanged, same config, same client) in same window only achieved 248,303.61, vs its own part 3's 254,913.26 also low −2.59%** → gap from machine environment drift, unrelated to code.

→ **Methodological conclusion (suggest extending to this project's all performance criteria)**: under ±2% magnitude criteria, cross-tens-of-minutes "single-point comparison with old baseline" is unreliable, must same-window cross + use "same unchanged binary" retest to quantify drift. This round's environment drifted 2.6%~3.2% within 1 hour,已 exceeded criterion's own tolerance.

**And must be ABA not AB —— A block must repeat twice.** Basis is the following self-falsification: looking only at `A1(242,102) vs B(248,303)`, A low 2.5%, looks like "no-probe version slower",正好 absorbable by "binary 32 bytes smaller → layout/i-cache alignment change" this plausible explanation; **only when A2(248,459) appears, vs B diff +0.06%, can attribute A1's lowness to first-block warmup not code**. **If designed AB not ABA, that wrong attribution would enter spec as "conclusion".**

**`tester` proactively recorded one self-falsification** (this text如实 transcribes): it pre-registered an attribution before looking at data —— "binary 32 bytes smaller → layout/i-cache alignment change". That attribution was **directly disproven** by A2 block (248,459 ≈ B's 248,303), real cause is first-block warmup + environment drift. **This text retains that wrong attribution without erasing, value is letting future people know which explanations were excluded by data, not re-stepping on them.**

### 7.5 Two over-estimated criteria corrected by measurement (must pass to `reviewer`, avoid over-reliance)

**Correction 1: #4 (leading `}` count) is blind to "equivalent replacement", proof power weaker than original assessment.**
`diff`'s deletion list shows, this deletion was **original line 120 `}` (`ff_pcpu_thread_init()`'s closing, real code)**, while **retained original line 163 `}` (`ff_probe_pcpu_zone()`'s closing, probe code)**. This **is exactly** the worst form #4 was designed to prevent —— "误删 one `}` then leave/add one from elsewhere to balance" —— and **#4's count is still 5, completely invisible**.

This case **actually harmless**: both deletion methods produce identical net text (`PCPU_SET(...);` followed by `}`), is `diff`'s line-alignment ambiguity not actual wrong deletion, both sides已 read original confirmed. But conclusion must correct: **what真正 catches this risk is #1 (subsequence/pure-deletion criterion), #4 only auxiliary**.

**Attribution honest record: this is `tester` proposed idea, this agent adopted and attached wrong argument, is双方共同 over-estimate**, not recorded as single-party issue (`tester`曾 proactively took responsibility, this agent didn't accept).

**Correction 2: #1 and #3's division of labor is finer than originally described —— #1 catches "didn't add", #3 catches "didn't under-delete", opposite directions, both indispensable.**
`#1 = 0` only guarantees after is before's subsequence (no new/modified lines), **it cannot guarantee "what should be deleted was deleted clean"**. This round #3 off by 1 line while #1 = 0, is exactly this division's instance.
**And: we repeatedly预判 "new blank line is this task's structural blind spot", position prediction right, direction guessed wrong** —— actual偏差 was "under-delete blank line" not "over-add blank line".

### 7.6 Criteria system's closure argument (for `reviewer` recheck completeness)

```
lib/ 11 modified files = should-change 3 + shouldn't-change 8        (3+8=11, precise alignment with #10-① baseline)
content layer: #1 (those 3: pure deletion) + #11 (those 8: verbatim unchanged)        → covers all 11 files' content
set layer: #10 ①②③④                                              → covers "is there a 12th file affected"
product layer: #5#6 #7 #8                → covers "product truly gone + truly full rebuild"
runtime layer: #9                                                → covers "no crash / no hang / no per-packet overhead change"
```
**Before #11 introduced, content layer only covered 3/11** —— i.e. `lib/include/vm/uma_int.h` (**G2's entire deliverable**), `lib/ff_glue.c` (G2 delete lock + G1 `smp_topo`), `lib/include/sys/pcpu.h` (G1 `curcpu` per-thread, **lock-removal safety's root**)当时**zero criteria protection**.

**Known remaining blind spots (honest registration)**:
1. **Criteria only cover "probe removal" this one action**. If any change happens after criteria run, before commit, need rerun #1/#3/#4/#10/#11 to be valid. Criteria window = "after removal, before `git commit`".
2. **Post-probe-removal DoD-1's slot isolation cannot be directly verified** (probes gone can't read `pc_zpcpu_offset`/`smr_c_seq`/`uk_ppera`). #9 only proves "no crash, no throughput regression", **cannot re-prove slot isolation**. DoD-1's evidence can only cite probe-containing version's data, **and depends on "probe removal is pure deletion, doesn't change formal logic" this premise** —— that premise is borne by #1 + #11 + `reviewer`'s line-by-line diff recheck together, **cannot rely only on runtime test**.

---

## 8. Residual risks and unverified items

| # | Item | Strength |
|---|---|---|
| 1 | **Whether slow-path lockless window widens enough to break `uma_page_slab_hash` chain**: this round only ran 10s wrk, **didn't do soak**. spec §4.7.4's L1 trigger criterion needs `tester`'s 60s/400-connection soak to test | 【unverified】, consistent with `_m17_A_codepath.md` appendix A.2's U8-perf |
| 2 | **`dense_idx=2`'s scalar probe line lost**: 4-thread档 that thread's `pc_zpcpu_offset`/`curcpu` is reverse-derived from SLOT line addresses | 【derivation】. If `reviewer` requires direct measurement, need to add lock to probe `printf` or use per-thread buffer |
| 3 | **Whether performance improved unknown**: my wrk caliber differs from `tester`, not comparable. DoD-5 conclusion can only be given by `tester`'s A/B cross. If no improvement, per plan §DoD-5 need argue retention with "correctness benefit" | 【pending `tester`】 |
| 4 | **`tcp_hpts` 4 swi threads and not core-bound** (§4.5): G1-introduced `mp_ncpus=N` side effect, this round measured confirmed exists, not handled | 【measured exists, impact not assessed】 |
| 5 | **`net.isr.dispatch` must stay `direct`** (G1 residual risk, unchanged): if changed to deferred, netisr threads have no `pcpup`, post-lock would go from "silent shared slot" to "NULL deref crash" | 【statically established, not runtime verified】 |
| 6 | **D9 scenario's failure mode changed** (G1已 recorded, G2 doesn't change conclusion): `ff_pthread_create()` threads have `pcpup == NULL`, now immediate crash not silent error | 【statically established】 |
| 7 | **Probe removal's actual executor not confirmed**: 16:22:10's change not by this agent, this text cannot testify for it. `reviewer`'s line-by-line diff recheck therefore **cannot be omitted** —— it is that action's sole independent evidence | 【pending leader confirmation】 |
| 8 | **#3 still in FAIL state** (one adjacent blank line, `ff_freebsd_init.c:377-378`). Fix plan and md5 expected see §7.3, pending leader verdict. **Before it's handled or `reviewer`书面 approves as known deviation, criteria system not fully green** | 【located, pending verdict】 |
| 9 | **Performance criteria's methodological risk (new, from §7.4's measurement)**: this round's environment drifted **2.6%~3.2%** within 1 hour, **exceeds ±2% criterion's own tolerance**. Any cross-tens-of-minutes "single-point comparison with old baseline" may give wrong PASS/FAIL; must same-window ABA + use same unchanged binary to quantify drift. This round exactly avoided one FAIL misjudgment by ABA | 【measured established】 |
| 10 | **Criteria window is "after removal, before `git commit`"**: #10-④'s `12 → 10` baseline invalid post-commit. If any change happens in this window, #1/#3/#4/#10/#11 must all rerun | 【process constraint】 |
| 11 | **`config.ini` compliance established, but throughput absolute values not reproducible** (this agent independently re-verified, not taking transcription): `git diff --cached` empty, both commits don't contain `config.ini` → **not-in-commit convention satisfied**. But workspace `config.ini` differs from repo default in **performance-relevant** ways, where `idle_sleep=0 → 20` changes polling/yield behavior, and `_m17_F_runtime.md`'s all throughput absolute values were measured under this config. → **DoD-5's percentage conclusions safe** (A/B both same config, diff unaffected), but **236,033 / 254,913 such absolute values cannot be reproduced after `config.ini` reverted to default**. Suggest固定 recording measurement-time effective config in `_m17_F_runtime.md` (at least `lcore_mask` / `thread_mode` / `idle_sleep`), otherwise later audit can only rerun, cannot recompute | 【measured established, suggest留痕】 |
| 12 | **16:22 probe removal and 16:40 blank-line fix executor identity not confirmed**: this agent declares not by it, `tester` also declares not by it. So these two changes lack executor's self-testimony, **`reviewer`'s line-by-line diff recheck is their sole independent evidence, cannot be omitted**. Criteria before-side `/data/workspace/m17_judge_baseline/` should be retained until that recheck complete | 【pending leader investigation】 |