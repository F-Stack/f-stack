# M17 Pre-commit Gate (reviewer2 independent recheck)

- Reviewer: `reviewer2` (review only; this round no `git add` / `git commit` / `git checkout` / `git stash`)
- Review object: leader's takeover "temp probe removal" + "G1/G2 two-stage commit split plan"
- Repo: `/data/workspace/f-stack`, HEAD = `ff09a17b2`
- Review time: 2026-08-04
- All conclusions from **actually executing commands / opening files**; unverified items explicitly marked.

---

# Overall conclusion: **PASS-with-fixes —— can commit**

- **Blocking items: 0.**
- **Mandatory fixes: 1 (R2-1, pure blank-line noise, deleting doesn't affect codegen, md5 must still be `df05d2cd…`; see §7).**
- **Suggestions: 3 (R2-S1 more stable commit method, R2-S2 spec 17 doc not in commit, R2-S3 tracked unit test references untracked fixture; see §8).**

Operation conclusion for leader: **first do §7's 1-line blank cleanup (no rebuild needed, md5 unchanged), then commit per §5's split plan**; strongly recommend §8 R2-S1's `git apply --cached` method replacing "manually add back/re-delete `uma_crit_lock` line".

| # | Review item | Conclusion | Section |
|---|---|---|---|
| 1 | Only removed probes, G1/G2 product changes fully retained and semantically correct | **PASS** | §1 |
| 2 | No probe residual, `ff_host_interface.c/.h` verbatim back to HEAD | **PASS** | §2 |
| 3 | clean build re-verification (self-run) + md5 reconciliation | **PASS (md5/byte count fully consistent with leader)** | §3 |
| 4 | Commit split plan (①compilable ②revertible ③better method) | **PASS (①②hold, ③gives better method)** | §5 |
| 5 | Commit scope check (`config.ini` absolutely not in + temp artifact list) | **PASS (list see §6)** | §6 |
| 6 | commit message convention (English, 1-3 sentences, concise) | **commit-2 PASS; commit-1 too long → give concise version** | §9 |
| 7 | Pure blank-line noise | **FAIL → mandatory R2-1** | §7 |

---

## 1. Review item 1: Only removed probes, product changes fully retained

Basis: `git --no-pager diff --stat lib/` + `git --no-pager diff -U6/-U8 lib/<file>` opened each.

```
 lib/Makefile             |  4 ++++
 lib/ff_dpdk_if.c         |  8 ++++++-
 lib/ff_dpdk_if.h         |  1 +
 lib/ff_freebsd_init.c    | 57 ++++++++++++++++++++++++++++++++++++------------
 lib/ff_glue.c            |  8 ++++++-
 lib/ff_kern_synch.c      |  4 +++-
 lib/ff_kern_timeout.c    |  6 ++---
 lib/include/sys/pcpu.h   |  2 +-
 lib/include/vm/uma_int.h | 15 ++++++-------
 9 files changed, 76 insertions(+), 29 deletions(-)
```

**File set = 8 (G1) + `include/vm/uma_int.h` (G2) = 9**, fully consistent with `_m17_E_coder_g1.md` §5.8's G1 final state (8 files, excluding `ff_host_interface.c/.h`) + G2, no extra files.

### 1.1 G1 item-by-item check (leader's 8 items, all in place)

| Item | Expected | Measured diff | Verdict |
|---|---|---|---|
| a | `lib/Makefile` add `-DSMP` | `+CFLAGS+= -DSMP` (incl 2 lines necessary comment) | ✓ |
| b | `ff_glue.c` add `smp_topo()` returning NULL stub | `+struct cpu_group * smp_topo(void) { return (NULL); }`, comment names `tcp_hpts.c:1890` must handle NULL | ✓ |
| c | Set triple before `uma_startup1()` | `mp_ncpus = nb_cpus; mp_maxid = nb_cpus - 1; for (i...) CPU_SET(i, &all_cpus);` before `ff_pcpu_thread_init()` and `uma_startup1()`; `nb_cpus` from `thread_mode ? nb_threads : 1`, with `<1` clamp and `>MAXCPU` panic | ✓ |
| d | `uma_page_slab_hash`/`uma_page_mask` advanced before `uma_startup1()` | Original 3 lines deleted, same 3 lines moved before `boot_pages = 16;`; with 3-line comment explaining "`mp_maxid>0` → zone-of-zones exceeds single-page threshold → `UMA_ZFLAG_VTOSLAB` → `keg_alloc_slab()` calls `vsetzoneslab()` within `uma_startup1()`" = 3/4-thread crash root cause | ✓ |
| e | `ff_pcpu_thread_init()` actually uses parameter + runtime upper bound panic | `pcpu_init(pcpup, cpuid, ...)` (was hardcoded `0`); prefixed `if (cpuid < 0 || (u_int)cpuid > mp_maxid) panic(...)`; old stale comment wholly replaced with correct reason | ✓ |
| f | Main thread uses dense `ff_cur_proc_id()` | `ff_pcpu_thread_init(ff_global_cfg.dpdk.thread_mode ? ff_cur_proc_id() : 0);`, and added `extern int ff_cur_proc_id(void);` + `#include <sys/smp.h>` at file top | ✓ |
| g | `ff_dpdk_if.c/.h` new `ff_cur_proc_id()`, `main_loop` passes dense number | `ff_dpdk_if.c:412-416` defines `return ff_cur_lcore_conf()->proc_id;`; `ff_dpdk_if.h:81` adds prototype; `main_loop`: `ff_stack_thread_init(rte_lcore_id())` → `ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0)` | ✓ |
| h | `ff_kern_timeout.c` `timeout_cpu` → `__thread` | `-static int timeout_cpu;` / `+static __thread int timeout_cpu;`; G1 gate's "mandatory-2" stale comment changed to correct statement | ✓ |
| i | `ff_kern_synch.c` `pause_wchan[curcpu]` add `pcpup != NULL` fallback | `_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], ...)` + 1-line comment | ✓ |
| j | `include/sys/pcpu.h` `#define curcpu 0` → `PCPU_GET(cpuid)` | `-#define curcpu    0` / `+#define curcpu    PCPU_GET(cpuid)` | ✓ |

### 1.2 G2 item-by-item check

| Item | Measured | Verdict |
|---|---|---|
| `uma_int.h` `critical_enter/exit` → no-ops | `#define critical_enter() do {} while(0)` / `critical_exit()` same | ✓ |
| `uma_int.h` delete `extern volatile int uma_crit_lock;` | deleted | ✓ |
| `ff_glue.c` delete `volatile int uma_crit_lock;` definition | deleted | ✓ |
| **No dangling refs in full tree** | `grep -rn "uma_crit_lock" . --include=*.c --include=*.h` → **0 hits** (incl `freebsd/`, `example/`, `tools/`, `tests/`) | ✓ |
| G2 gate "mandatory-1" (comment wrong statement) landed? | New comment is "`curcpu` is per-thread here (sys/pcpu.h), not per-CPU, so preemption cannot change which `uz_cpu[]` slot this thread uses…" —— no more "No preemption in f-stack userspace" wrong premise | ✓ |
| G2 gate "mandatory-2" (spec §4.7.4 L1 criterion (a) unreachable) landed? | `17-...md:585` wholly rewritten to (c) primary + (a′) crash point at `vtoslab()` / `uma_core.c:4930` / `:5819`, with ⛔ noting `vtozoneslab()` is dead code | ✓ |

### 1.3 Semantic correctness spot-check (I independently established)

1. **`ff_cur_proc_id()` available at `ff_freebsd_init()` time** —— established available: `ff_init.c:43,47,51` order is `ff_dpdk_init()` → `ff_freebsd_init()` → `ff_dpdk_if_up()`, and `init_lcore_conf()` at `ff_dpdk_if.c:1674` already assigns `lcore_conf[lcore_id].proc_id = ti` (`:439`).
2. **Dense numbering** —— `ff_memory.h:105-108 ff_lcore_conf_idx()` = `thread_mode ? rte_lcore_id() : 0`; `init_lcore_conf()` thread_mode branch assigns `proc_id = ti` for `ti = 0..nb_threads-1` → **`proc_id` naturally dense `[0, nb_threads-1]`**, self-consistent with `mp_maxid = nb_cpus - 1` upper bound check.
3. **Upper bound check's `mp_maxid` assigned before use** —— main path: triple assignment before `ff_pcpu_thread_init()` call; worker path: `ff_stack_thread_init()` → `ff_pcpu_thread_init()` in `main_loop`, far after `ff_freebsd_init()`. ✓
4. **Main thread and `main_loop` numbering consistent** —— `main_loop` uses `qconf->proc_id`, same source as `ff_cur_proc_id()`; main thread as EAL main lcore also enters `main_loop`, but `ff_stack_inited = 1` skips duplicate init. ✓
5. **`thread_mode=0` degraded path verbatim equivalent** —— `nb_cpus=1` → `mp_ncpus=1`/`mp_maxid=0`/`all_cpus={0}`; `ff_pcpu_thread_init(0)`; `ff_lcore_conf_idx()` always 0; `curcpu = PCPU_GET(cpuid) = 0`. Consistent with pre-change. ✓

**Review item 1 verdict: PASS.**

---

## 2. Review item 2: No probe residual

| Check | Command | Result | Verdict |
|---|---|---|---|
| `M17` marker | `grep -rn "M17" lib/ --include=*.c --include=*.h \| wc -l` | **0** | ✓ |
| `ff_probe` function | `grep -rn "ff_probe" lib/ --include=*.c --include=*.h \| wc -l` | **0** | ✓ |
| `PROBE` (incl existing FreeBSD code) | `grep -rn "M17\|ff_probe\|PROBE" lib/ --include=*.c --include=*.h` | 78 lines, but **all verified as upstream existing code** (`*_PROBE*` method macros, `SDT_PROBES_ENABLED()`, `SDT_PROBE_DEFINE1/SDT_PROBE1`). **9 changed files `grep -c 'M17\|ff_probe'` all 0** | ✓ (no M17 probe residual) |
| Probe log statement residual | `git --no-pager diff lib/ \| grep "^+" \| grep -i "probe\|M17\|fprintf\|printf\|stderr"` | **empty** | ✓ |
| `ff_host_interface.c/.h` verbatim back to HEAD | `git --no-pager diff lib/ff_host_interface.c lib/ff_host_interface.h \| wc -c` | **0 bytes**; both files **don't appear** in `git status --short` | ✓ |

**Review item 2 verdict: PASS.** Probe removal thorough, satisfies G1 gate R-d and DoD-8 "probes must not enter product commit".

---

## 3. Review item 3: clean build re-verification (reviewer2 self-run, `make clean` first)

```
cd /data/workspace/f-stack/lib     && make clean && make -j16
cd /data/workspace/f-stack/example && make clean && make
```

| Metric | reviewer2 measured | Expected / leader value | Verdict |
|---|---|---|---|
| `lib` exit code | **0** | 0 | ✓ |
| `lib` `grep -c "error:"` | **0** | 0 | ✓ |
| `lib` `grep -c "warning:"` | **51** | 51 (HEAD baseline) | ✓ **zero new warning** |
| `example` exit code | **0** | 0 | ✓ |
| `example` `error:` / `warning:` | **0 / 0** | 0 / 0 | ✓ |
| `example` `undefined reference` | **0** | 0 | ✓ |
| `example/helloworld` md5 | **`df05d2cd078d631ad2d8ee7caba8d387`** | leader measured `df05d2cd078d631ad2d8ee7caba8d387` | ✓ **byte-identical** |
| `example/helloworld` byte count | **30392632** | 30,392,632 | ✓ |

Original logs cleaned via `/data/workspace/rm_tmp_file.sh` after review.

**Review item 3 verdict: PASS.** I reproduced **exact same md5 and byte count as leader** in **independent clean build** —— proves: (a) build reproducible; (b) current workspace is exactly leader's reported code; (c) warning count back to HEAD baseline 51, probe removal left no codegen-affecting residue.

> **Unverified (honest mark)**: HEAD baseline `warning = 51` I **didn't self-checkout HEAD to retest** (this round prohibits `git checkout`), citing previous reviewer's independently reproduced value. My measured 51 equals it.

---

## 4. Commit split plan's factual basis (two intermediate binaries' existence)

This is key evidence for §5 ①, not speculation:

```
$ ls -l example/helloworld_g1_prelock example/helloworld_g2_nolock
-rwxr-xr-x 30392704 Aug  4 15:00 example/helloworld_g1_prelock
-rwxr-xr-x 30392664 Aug  4 15:10 example/helloworld_g2_nolock
$ md5sum ...
751a8153d3b200229cff99b3fa7650b0  example/helloworld_g1_prelock
78c39a6f96e104412ce75351e402907b  example/helloworld_g2_nolock
```

- `helloworld_g1_prelock` (md5 `751a8153…`) = **G1 + `uma_crit_lock` still present (pre-lock)**, symbol-level criterion `uma_crit_lock` count **1**. **This binary not only compiled/linked successfully, but was fully run and PASS by tester** (1/2/3/4 threads + `thread_mode=0` each档 DoD-1/4 PASS).
- `helloworld_g2_nolock` (md5 `78c39a6f…`) = `uma_crit_lock` count **0** = post-lock, also cross-retested.
- Three byte counts self-consistent: `g1_prelock` 30,392,704 > `g2_nolock` 30,392,664 > current product 30,392,632 —— first two contain probes, current product probes removed, **decreasing as expected**.

> **Residual risk for leader (non-blocking)**: runtime DoD all PASS tested binary was **probe-containing** `751a8153…` / `78c39a6f…`; about-to-commit `df05d2cd…` (post-probe-removal) **not runtime smoked**. I judge **non-blocking**: (a) probes are pure print, doesn't change control flow; (b) probe's only landing `ff_host_interface.c/.h` now **0 byte diff**, other 9 files diff **zero new print statements**; (c) post-removal clean build error0 / warning back to baseline 51 / undefined 0. **Suggest but not mandatory**: post-commit have `tester` use `df05d2cd…` for 1-min `thread_mode=1` 2-thread startup smoke.

---

## 5. Review item 4: Commit split plan verdict

leader's plan (because `git add -p` cannot non-interactively execute):
- **commit-1 (G1)**: temporarily add `volatile int uma_crit_lock;` back to `ff_glue.c` → `git add lib/Makefile lib/ff_glue.c lib/ff_freebsd_init.c lib/ff_dpdk_if.c lib/ff_dpdk_if.h lib/ff_kern_synch.c lib/ff_kern_timeout.c lib/include/sys/pcpu.h` → commit (at this point `uma_int.h` still HEAD version).
- **commit-2 (G2)**: then delete that line → `git add lib/ff_glue.c lib/include/vm/uma_int.h` → commit.

### ① Is commit-1's tree state really compilable —— **yes, holds (and empirically run PASS)**

- **Static self-consistency established**: commit-1 tree's `uma_int.h` = HEAD version, with `extern volatile int uma_crit_lock;` + spinlock macros; `ff_glue.c` has temporarily re-added `volatile int uma_crit_lock;` **definition**. Declaration side and definition side **paired present** → compile-time symbol visible, link-time resolvable, no `undefined reference`.
- **No third-party reference in full tree**: `grep -rn "uma_crit_lock"` currently 0 hits ⇒ this symbol's **declaration and definition only appear in these two files**.
- **Empirical**: commit-1's tree state (G1 + pre-lock `uma_int.h`) is exactly `helloworld_g1_prelock` (md5 `751a8153…`)'s corresponding code version, **that version was fully compiled and run PASS by tester** (§4). So commit-1 is not "never-compiled intermediate state".
- **Semantic safety**: commit-1 tree's `curcpu` already `PCPU_GET(cpuid)` (dense, per-thread distinct), while `critical_enter/exit` still global spinlock —— this is **more conservative than final state** (extra serialization, no missing protection), won't introduce commit-2's才修 defect.

### ② Can commit-2 `git revert` alone without affecting G1 —— **yes**

- commit-2 only touches 2 files, 3 spots total: `uma_int.h`'s `extern` deletion + 2 macro rewrites; `ff_glue.c`'s 1 line deletion.
- `ff_glue.c`'s hunk isolation established: `git --no-pager diff lib/ff_glue.c | grep -c "^@@"` = **2**, two hunks respectively hunk1 `@@ -138,17 +138,16 @@` (G2: delete uma_crit_lock) and hunk2 `@@ -164,16 +163,23 @@` (G1: add smp_topo stub), ~25 lines apart, **no context overlap** → `git revert commit-2`'s reverse application of hunk1 won't touch commit-1's `smp_topo()`, cleanly applicable.
- Post-revert tree = G1-only + pre-lock `uma_int.h` = same code version as `helloworld_g1_prelock` = **empirically compilable runnable state**. ✓ Satisfies DoD-5 fallback gate requirement.

### ③ Is there a more stable method —— **yes, see §8 R2-S1 (recommend replacing leader's manual edit method)**

leader's manual add-back/re-delete method is **result-correct**, but has two avoidable operational risks: (a) needs two manual workspace file edits, if second delete forgotten or wrong line, **final HEAD would be inconsistent with verified `df05d2cd…` code**; (b) mid-way workspace is "neither commit-1 nor final" third state. R2-S1 gives equivalent method not modifying workspace, pure index operation.

**Review item 4 verdict: PASS.** ①②hold, ③has better method but original plan also safely executable (must配合 §8 R2-S1's final md5 regression check).

---

## 6. Review item 5: Commit scope check

### 6.1 **Absolutely must not enter (tracked but polluted by local test values)**

| File | Status | Measured pollution items | Handling |
|---|---|---|---|
| `config.ini` | ` M` | `lcore_mask` `1`→**`6`**; `#thread_mode=0`→**`thread_mode=1`**; `idle_sleep` `0`→**`20`**; `#fstack_log_level=0`→**`fstack_log_level=7`**、`#fstack_log_file_prefix`→**uncommented**; `[port0]` `addr` `192.168.1.2`→**`<DPDK_NIC_IP>`** (plus `#addr=<KERNEL_NIC_IP>`), `netmask`→`255.255.248.0`, `broadcast`→`<BROADCAST_IP>`, `gateway`→`<GATEWAY_IP>`; `#addr6/#prefix_len/#gateway6`→**uncommented with local `2402:4e00:…` / `prefix_len=128` / `fe80::feee:…`** (plus `#gateway6=::1`) | **Never `git add`**. All 8 items are local dual-NIC test env values, **none M17-feature-related** (M17 has no config additions). Per mandatory convention (AI memory 44404940) must keep out of commit. |

**Verdict: `config.ini` item-by-item verified —— 100% local env residual, zero feature-related changes, confirmed never enter commit.** Post-commit should remain ` M`.

### 6.2 Untracked temp artifacts not to enter (`??`)

**Binaries/intermediates** (note `example/helloworld` already ignored by `.gitignore:12`, but below **not ignored**, `git check-ignore` no output for `helloworld_g1_prelock`):
- `example/helloworld_g1_prelock`, `example/helloworld_g2_nolock` (M17 comparison copies, 30MB-class)
- `example/helloworld_zc_base`, `example/helloworld_zc_recv`, `example/helloworld_stacksel/helloworld_stacksel` (past leftover 30MB-class binaries)
- `dpdk.bak-23.11.5/` (entire DPDK backup dir)

**Logs**: various `.log` files (16), plus my this round's `_m17_r2_lib.log`, `_m17_r2_ex.log` (**cleaned**).

**Test config copies**: `config.m17_g2_2t.ini`, `config.m17_g2_4t.ini`, `config.test-dpdk24-multi.ini` (all contain local IP/lcore values).

**Other**: `.codebuddy/` (IDE data dir, **must not delete**, but also **must not commit**), `dkdns_ospf.sh` (unrelated external script).

### 6.3 **Items needing leader's separate decision, don't mix into commit-1/2 `??`**

| File | Description | Suggestion |
|---|---|---|
| `docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md` | **M17 main spec, currently untracked**; while `00-`~`16-` **all 17 numbered specs tracked** → convention says 17th should continue | **Suggest independent commit-3 (docs)**, see §8 R2-S2 |
| `docs/native_mt_spec/zh_cn/_m17_A_codepath.md`等 12 `_m17_*.md` + `plan-17-*.md` + `_m17_C_probe_diff_A.patch` | Process work docs. Historical precedent of committing (`_m1_A_codepath.md`/`_m1_B_external.md`/`_m4_D_review.md` tracked), also大量 untracked | leader decision; **don't mix into commit-1/2** |
| `tests/unit/fixtures/valid_thread_mode.ini` | **Tracked** `tests/unit/test_ff_config.c:1169/1204` references it, but fixture itself untracked → current repo's unit test is **broken** for new cloners | **Suggest independent commit to fix**, see §8 R2-S3; **don't mix into commit-1/2** |

### 6.4 Operational hard constraint

**Strictly prohibit `git add -A` / `git add .` / `git add lib/`** (latter would bring potential untracked in `lib/`). **Must逐个 explicitly list §5 plan's 9 file paths**. leader's plan is already explicit path list ✓.

**Review item 5 verdict: PASS (list above).**

---

## 7. Mandatory R2-1 (sole mandatory, P3 · pure blank-line noise)

**Location**: `lib/ff_freebsd_init.c` function `ff_freebsd_init()` end.

**Issue**: `git --no-pager diff`'s last hunk is a **pure blank-line addition** (`@@ -344,8 +372,9 @@`'s isolated `+`), measured (`tail -12 … | cat -A`):

```
    ff_stack_inited = 1;
<blank>
<blank>
    return (0);
}
```

i.e. **two consecutive blank lines** between `ff_stack_inited = 1;` and `return (0);`. This is probe removal residual, **zero semantic/codegen contribution**, zero-value diff noise, violates "minimal diff / only change necessary" engineering constraint.

**Fix**: Delete **1 blank line**, restore single blank separator.

**Verification gate (leader self-prove, no need for another review round)**: that change is whitespace-only, **doesn't affect any codegen**. So after leader fixes, rerun clean build, `example/helloworld`'s md5 **must still be `df05d2cd078d631ad2d8ee7caba8d387`, byte count still 30392632**; if md5 changes in any way, means误删 non-whitespace content, **must immediately stop commit and report**.

> If leader judges this not worth a modification window, can **downgrade to "suggestion" and commit directly** —— it doesn't constitute functionality/correctness risk. I've handled as "PASS-with-fixes" in conclusion, **doesn't block commit**.

---

## 8. Suggested fixes (non-blocking)

### R2-S1 (strongly recommended): Use `git apply --cached` replacing "manually add back then delete",全程 no workspace modification

`ff_glue.c` happens to have only 2 hunks with G1/G2 each one (§5② established), so `git add -p`'s non-interactive equivalent is **generate patch per hunk then stage only G1 hunk**:

1. Export that file's patch: `git --no-pager diff lib/ff_glue.c > /data/workspace/f-stack/_r2_glue.patch`
2. Use text editor to **only keep hunk2** (`@@ -164,16 +163,23 @@`, i.e. `smp_topo()` addition), save as `_r2_glue_g1.patch` (keep `diff --git` / `--- a/` / `+++ b/` three-line header)
3. commit-1: `git add lib/Makefile lib/ff_freebsd_init.c lib/ff_dpdk_if.c lib/ff_dpdk_if.h lib/ff_kern_synch.c lib/ff_kern_timeout.c lib/include/sys/pcpu.h` + `git apply --cached /data/workspace/f-stack/_r2_glue_g1.patch` → `git commit`
4. commit-2: `git add lib/ff_glue.c lib/include/vm/uma_int.h` → `git commit` (at this point `ff_glue.c` index remaining is exactly hunk1's deletion)
5. Cleanup: `/data/workspace/rm_tmp_file.sh /data/workspace/f-stack/_r2_glue.patch /data/workspace/f-stack/_r2_glue_g1.patch`

**Advantage**: workspace file **never modified**, so no "forgot to delete temp line back" window, final HEAD necessarily equals verified `df05d2cd…` code.

**If leader still uses original manual method**, must add hard check: after commit-2 execute `git status --short lib/` (should **only empty**) + `make clean && make` rebuild, **confirm md5 still `df05d2cd078d631ad2d8ee7caba8d387`**.

### R2-S2: M17 spec doc not in commit plan

`docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md` currently `??`, while `00-`~`16-` all numbered specs tracked. If this code commit doesn't include 17th, repo will have "code landed, design basis missing" gap, and commit message's "spec 17 §2.4 / §4.7" references in-repo **point to nonexistent file**. **Suggest追加 commit-3 (docs-only)**. **Non-blocking** commit-1/2.

### R2-S3: Tracked unit test references untracked fixture (existing defect, not M17-introduced)

`tests/unit/test_ff_config.c:1169` and `:1204` both reference `tests/unit/fixtures/valid_thread_mode.ini`, but that fixture **untracked**. → New cloners running unit tests would fail missing file. Is earlier `thread_mode` config commit's omission, **unrelated to M17**. Suggest independent small commit to fix, **don't mix into** commit-1/2.

---

## 9. Review item 6: commit message verdict

Convention: **English, 1-3 sentences, simple summary of what done**.

### commit-1 —— **FAIL (too long)**

leader's draft is **single 61-word sentence**, cramming 5 parallel technical details + 1 effect statement, is "detailed technical description" not "simple summary". **Suggest concise version (2 sentences, subject ≤72 chars)**:

```
Make the f-stack kernel view SMP-aware for native-mt

Define SMP and set mp_ncpus/mp_maxid/all_cpus from nb_threads before
uma_startup1(), and give each stack thread a dense pcpu id with a
per-thread curcpu. Each thread now owns disjoint UMA/SMR per-cpu slots
instead of sharing slot 0.
```

(If leader thinks crash fix must be留痕 in message, can replace second sentence with `Also move the uma_page slab hash init before uma_startup1(), which fixes the 3/4-thread startup crash.`, total still 3 sentences, within convention limit.)

### commit-2 —— **PASS**

Original 2 sentences, pure English, accurately summarizes "remove global spinlock + `critical_enter/exit` return to no-op + consistent with rest of userspace stack", and matches code reality. **No modification needed.** Only optional微调: change `now that each stack thread owns a distinct per-cpu slot` to `now that curcpu is per-thread` closer to G2 gate mandatory-1's corrected real reason, but original also not wrong, **not mandatory**.

---

## 10. This round's honest boundary (unverified items)

1. HEAD baseline `warning = 51` I didn't self-checkout to retest (this round prohibits `git checkout`), citing previous reviewer's independently reproduced value; my measured 51 equals it.
2. Didn't run any runtime test (not in my scope, and `config.ini` in local test state); `df05d2cd…` binary runtime smoke see §4's suggestion.
3. Didn't verbatim redo G1/G2 code gate; I only did §1.3's independent spot-check + two mandatory fixes' landing confirmation.
4. commit-1/commit-2 I **didn't actually execute** (per assignment prohibited), ①② are static judgment + §4's intermediate binary empirical support; **true final checkpoint is §8 R2-S1's final md5 regression**.

---

## 11. Leader's execution checklist (in order)

1. (Mandatory R2-1) Delete extra 1 blank line in `lib/ff_freebsd_init.c` end.
2. `cd lib && make clean && make -j16 && cd ../example && make clean && make` → verify md5 still `df05d2cd078d631ad2d8ee7caba8d387`, bytes 30392632. **If not, stop.**
3. Per §8 R2-S1's `git apply --cached` method (or original manual method) commit commit-1, commit-2; commit message use §9's commit-1 concise version + commit-2 original.
4. **Confirm `config.ini` not `git add`ed**: `git status --short config.ini` post-commit should still be ` M`; `git show --stat HEAD` / `HEAD~1` **must not contain `config.ini`**.
5. (Suggest) commit-3 add spec 17 doc; (suggest) independent small commit add `tests/unit/fixtures/valid_thread_mode.ini`.
6. (Suggest) Have `tester` use final binary for 1-min `thread_mode=1` 2-thread startup smoke.
7. Clean §6.2's temp logs/binaries (via `/data/workspace/rm_tmp_file.sh`, note **keep** `.codebuddy/`).

---

# 15. Spec M6 closeout recheck (`17-SMP-aware-pcpu视图与去全局锁.md`)

- Recheck object: `docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md`, **158,383 bytes / mtime 16:21**
- Scope: **only check leader's designated F1/N1/N2 three spots + runtime conclusion consistency**, didn't re-review full text
- Code baseline: spec §0 self-states `T1 current HEAD = ff09a17b2` (pre G1/G2 commit)

## 15.0 Conclusion

| Object | Conclusion |
|---|---|
| **F1 (§4.3.2 `rp_ent[]` argument)** | **PASS** —— switched to "write-side bounded", and its 7 facts I each independently verified via code |
| **N1 (§7.1 probe 7 fields + §6.12 U6-a downgrade)** | **PASS** |
| **N2 (§8.3 commit operation method)** | **PASS** (另 found 1 spot inconsistent with actual execution method, listed as suggestion S3) |
| **Runtime conclusion consistency / exaggeration** | **No exaggeration, no conflict with `_m17_F_runtime.md`** —— but **found 3 spots M5 "part 3" measured conclusions not backfilled**, violates spec's own §7.6 DoD-6 |

### **Doc commit gate: FAIL —— must backfill 3 before commit** (mandatory D1/D2/D3, all mechanical backfill, data ready, no code, no retest)

> **Note**: This is **unrelated to §1~§14's code commit gate PASS**, code already committed (`c7996a94f` / `57b612d16`), this section only blocks **doc** commit.
>
> **bounce count reminder**: `designer` previously bounced 2 rounds by `gate-design`, this is **3rd bounce** (still within bounce≤3 convention). But this round's 3 mandatory fixes **different nature** —— not analysis errors, but pure "copy existing measured numbers into table". **If 3rd fix still doesn't pass, per convention must escalate to human decision, no more looping.**

## 15.1 F1: §4.3.2 `rp_ent[]` argument —— **PASS**

`sed -n '350,380p'` read that section. **Wrong premise explicitly voided and wholly replaced**: opening states "**reason must be 'write-side bounded', not 'read-side modulo'**…original text wrongly claimed '`rp_ent[]`'s each index independently modulos', **that statement has been disproven by measurement**".

**I didn't take doc's self-statement, but each independently verified (all hit)**:

| spec assertion | My measured | Verdict |
|---|---|---|
| `tcp_hpts.c:575` no modulo | `sed -n '569,580p'` → `hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];`, **indeed no modulo** | ✓ |
| `hpts_random_cpu()` `:473` double modulo | `sed -n '466,476p'` → `cpuid = (((ran & 0xffff) % mp_ncpus) % tcp_pace.rp_num_hptss);` | ✓ verbatim |
| `hpts_cpuid()` `:1089` `inp_flowid % mp_ncpus` | actual read → `cpuid = inp->inp_flowid % mp_ncpus;`, context is `#ifdef NUMA` wrapped | ✓ |
| `t_lro_cpu` branch `:1057-1060` bounded | actual read confirms `if (tcp_use_irq_cpu) { if (tp->t_lro_cpu == HPTS_CPU_NONE) { *failed = 1; return (0); } return (tp->t_lro_cpu); }` | ✓ |
| `tcp_lro_hpts.c` not compiled ⇒ `t_lro_cpu` always `HPTS_CPU_NONE` | `grep -n "tcp_lro" lib/Makefile` → **only `tcp_lro.c` one line**; `ls lib/tcp_lro_hpts.o` → **No such file** | ✓ |
| `t_hpts_cpu` only 3 write points in full tree | `grep -rn "t_hpts_cpu *=" freebsd/ --include=*.c` → exactly 3 assignments | ✓ |
| `HPTS_CPU_NONE == (uint16_t)-1`, `tcp_var.h:330` | `grep -n` → `330:#define HPTS_CPU_NONE ((uint16_t)-1)` | ✓ line-precise |
| `rp_num_hptss == mp_ncpus` (`:1864`/`:1872`) | actual read → `:1864 uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;`, `:1872 tcp_pace.rp_num_hptss = ncpus;` | ✓ |
| `rack.o`/`bbr.o` both compiled | `ls lib/rack.o lib/bbr.o` → **both exist** | ✓ |

**F1 verdict: PASS, no mandatory.**

## 15.2 N1: §7.1 probe fields + §6.12 U6-a —— **PASS**

- **§7.1 field count corrected** (`:930`): explicitly states "P1 actually prints fields (**7**, verbatim consistent with landed probe format string)". `:939` restates 7 field full names, with `:915`'s format string **field-by-field matching**. ✓
- **§6.12 U6-a downgraded** (`:806-811`): "**Status change: from 'plan dependency' downgraded to pure observation item**" + "**This round handling: this round doesn't verify U6-a.**", and gives correct reason "because §4.3.4's numbering doesn't depend on 'EAL main lcore == `proc_lcore[0]`' inference". ✓
- **Circumstantial evidence and verification boundary cleanly drawn**: `:810` marks `lcore_mask=6`'s `dense_idx=0/1` measured as "**only circumstantial evidence reverse-derived from `dense_idx`, doesn't constitute U6-a verification**" and marks 【unverified】. ✓ No exaggeration.

**N1 verdict: PASS, no mandatory.**

## 15.3 N2: §8.3 commit operation method —— **PASS** (with 1 suggestion)

`:1096-1105` new §8.3.1 "two split scenarios, methods **different**":

| Scenario | spec's method | Check |
|---|---|---|
| Same-commit probes vs formal changes | "**Must first forward-delete all probe blocks, then whole-file `git add`**" + post-delete **must `make clean` rerun full compile + smoke**; and gives **don't use `git add -p`** reason | ✓ complete |
| Cross-commit same file (`ff_glue.c`) | "use `git add -p` split by hunk", explains two at **different positions, mutually independent** | ✓ distinction in place |

Also `:1094` specially added mis-delete prevention: "§4.10's `uma_page_slab_hash` advance **is not probe**, but **must-commit formal fix**…when cleaning probes **must not** delete it together". ✓

**N2 verdict: PASS.** Suggestion see §15.5 S3 (`git add -p` inconsistent with actual execution method, need supplement).

## 15.4 Runtime conclusion consistency —— **no exaggeration, but found 3 not backfilled (mandatory D1/D2/D3)**

### 15.4.1 Consistency/exaggeration: **all PASS**

Item-by-item comparing spec's "已实测" with `_m17_F_runtime.md` (using `search_content` precise number comparison):

| spec location | spec number | `_m17_F_runtime.md` | Verdict |
|---|---|---|---|
| `:1008` 3-thread pre-lock 6-round median | **240,802.74** req/s, incl 2 outliers | `:1331` same **240,802.74** | ✓ consistent |
| `:1011` `thread_mode=0` 1 process | pre-fix **+0.03%** / post-fix **+0.05%** | `:1059` `209,825.01` vs `209,710 → +0.05%` | ✓ consistent |
| `:1012` `thread_mode=0` 2 processes | pre-fix **−1.25%** / post-fix **+2.38%** | `:1060` `236,871.31` vs `231,360 → +2.38%` | ✓ consistent |
| `:1015` DoD-4 overall | **PASS**, six档 zero crash zero socket error | `:1118` DoD-4 **PASS**, wording consistent | ✓ consistent |
| `:900-904` DoD-1 five档 snapshot | all PASS, slot distance 128 / 4096, `uk_ppera` 3/4 measured, **2-thread档 marked "pending (should == 2)"** | R1.2~R1.4 consistent; 2-thread档 indeed no `uk_ppera` | ✓ consistent, **didn't write uncollected as passed** |
| `:1013` RSS memory comparison | **"still pending collection"** | indeed no RSS data | ✓ honestly marked |
| `:896` / `:909` tested binary attribution | md5 `751a8153…` = **G2 pre-lock** | X0 symbol-level criterion: `g1_prelock` `uma_crit_lock` count 1 | ✓ consistent |

**No exaggeration or conflict with runtime doc found.** Specifically: **`+0.50%` / `+1.67%` / `+4.93%` these three numbers "zero hits" in spec full text**. → So leader's concern "whether noise boundary retained" —— **premise doesn't hold: spec根本 doesn't have these numbers yet**. **No exaggeration risk, also means backfill not done** (see below).

### 15.4.2 Mandatory D1 (P1): §7.5 DoD-5 not backfilled M5 "part 3" verdict conclusion

`:1026-1034` current state is still **pre-change plan text** —— **no post-lock measured results**.

And `_m17_F_runtime.md` part 3 gives complete verdict:
- `:1362` **2-thread A/B cross 6 rounds each**: pre-lock `234,867.29` → post-lock `236,032.94` = **+0.50%**, PASS
- `:1363` **4-thread A/B cross 6 rounds each**: `250,734.43` → `254,913.26` = **+1.67%**, PASS
- `:1369` **3-thread sequential (not judgment basis)**: `240,802.74` → `252,683.63` = **+4.93%**, reference only
- `:1371` **DoD-5 verdict: PASS**, A-side cross-check deviation only −0.41% / +0.71%
- `:1373` **Honest boundary**: "+0.50% and +1.67% magnitudes **near noise floor**, I don't claim 'G2 brought definite performance improvement', can only give…**post-lock throughput not lower than pre-lock, DoD-5 threshold satisfied**"

**Must backfill, and must retain above two boundaries verbatim.** Suggest designer copy below text appended to §7.5:

```
- **Measured conclusion (M5 part 3 A/B cross-retest, `_m17_F_runtime.md` X4.1): DoD-5 PASS.**【measured】

| 档位 | Method | Pre-lock median (req/s) | Post-lock median (req/s) | Diff | Verdict |
|---|---|---|---|---|---|
| 2-thread | A/B cross 6 rounds each | 234,867.29 | 236,032.94 | **+0.50%** | PASS |
| 4-thread | A/B cross 6 rounds each | 250,734.43 | 254,913.26 | **+1.67%** | PASS |
| 3-thread | sequential, **not judgment basis** | 240,802.74 | 252,683.63 | +4.93% | reference only |

- **Honest boundary (must not delete)**: +0.50% / +1.67% **near noise floor**, **don't claim G2 brought definite performance improvement**;
  supportable conclusion only "post-lock throughput not lower than pre-lock, DoD-5 threshold satisfied".
- **3-thread +4.93% cannot be directly trusted**: pre-lock that档 6 rounds contain two outliers (143k / 205k) lowering median,
  while post-lock 3-round range only 0.25%; that diff likely mainly from outliers not G2 benefit.
- **A/B cross method necessity**: ±2% criterion extremely sensitive to machine state drift; A-side cross-check with R5 existing median
  deviation −0.41% / +0.71%, proving this round no drift.
```

### 15.4.3 Mandatory D2 (P1): §7.1(1) and §7.2's "post-lock pending retest" expired

- `:909` §7.1 qualifier (1) still writes: "**post-lock must re-verify slot isolation**" —— tone is **incomplete TODO**.
- But `_m17_F_runtime.md` **X1 section completed that re-verification**: `:1179` "X1. Post-lock DoD-1 slot isolation re-verification", `:1292` "**post-lock DoD-1 in 2/3/4-thread three档 all PASS**".
- Similarly `:991-994` §7.2 DoD-2 still only has criteria, no measured conclusion; and that criterion **now verifiable** —— I this round §1.2 measured `grep -rn "uma_crit_lock" . --include=*.c --include=*.h` = **0 hits**.

**Consequence**: if spec committed as-is, readers would mistakenly think "post-lock slot isolation not yet verified" "DoD-2 not yet confirmed". **Substantive misleading**, violates spec's own §7.6 DoD-6.

**Fix**: §7.1 qualifier (1) change to "（1）This snapshot data all 'G2 pre-lock'; **post-lock slot isolation re-verification completed in M5 part 3 (`_m17_F_runtime.md` X1: 2/3/4-thread three档 + `thread_mode=0` degraded档 all PASS)**". §7.2 add a line "**Measured: `grep -rn "uma_crit_lock" lib/ freebsd/` zero hits, `critical_enter/exit` already `do {} while(0)` → DoD-2 PASS.**【measured】"

### 15.4.4 Mandatory D3 (P2): §7.4 table's 3-thread/4-thread rows without post-lock data, duplicate contradiction with D1 table

`:1008`/`:1009`'s "baseline" column writes **pre-lock** results, but column header is "baseline (plan §5.1【measured】)", would coexist with §7.5's new table post-D1-backfill without cross-reference. **Fix (minimal)**: at `:1008`/`:1009` two row ends each add "post-lock data see §7.5".

## 15.5 Suggested fixes (non-blocking)

- **S1**: Add leader's pre-commit smoke to §7.4 or §7.5 —— `df05d2cd…` `wrk -t5 -c100 -d10s` = **236,273.85 req/s**, vs X4.1's post-lock 2-thread median 236,032.94 diff **+0.10%**, zero error. **High value**: only data from "about-to-commit binary".
- **S2**: §8.4's two commit message drafts and **actual commits** (`c7996a94f` / `57b612d16`) wording differs. Suggest §8.4 opening add "below are drafts; actual commits see `c7996a94f` / `57b612d16`".
- **S3 (corresponds N2)**: §8.3.1 second row specifies `ff_glue.c` use **`git add -p`** hunk split, but **actual execution wasn't so** —— `git add -p` only interactive. Suggest add: "**`git add -p` needs interaction, non-interactive scenario equivalent methods two: ① this round's actual 'temporarily retain → commit → re-delete' forward edit; ② `git diff <file>` export patch then only keep target hunk, `git apply --cached` (see `_m17_gate_final.md` §8 R2-S1).**"
- **S4 (verified as non-defect)**: spec's `lib/Makefile:515` (`tcp_lro.c`), `:584-586` (`rack.c`/`bbr.c`), `:346` (`kern_mbuf.c`) etc line numbers, in **current workspace/new HEAD** all **+4 lines** (because G1's `-DSMP` inserts 4 lines near `:218`). But spec §0 explicitly pin