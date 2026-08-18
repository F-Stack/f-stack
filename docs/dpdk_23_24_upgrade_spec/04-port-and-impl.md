# 04 — Port & Implementation Plan

> Document version: v0.1 (2026-06-09)
> Parent plan: `plan.md`
> Upstream documents: `00 / 01 / 02`
> Research inputs: diff-comparator + dpdk-23-patch-scout + dpdk-24-analyzer three-way parallel research results (measured)

---

## 1. Implementation Overview

This spec splits "full-tree replacement + 3-patch re-application" into **6 milestones (M1~M6)**, advanced rhythmically by the leader + coder roles (activated in Phase 2). Each milestone has an independent `bounce counter` (≤ 3), exceeding which triggers escalation pause.

```
┌────┐  ┌────┐  ┌────┐  ┌────┐  ┌────┐  ┌─────────────┐
│ M1 │→ │ M2 │→ │ M3 │→ │ M4 │→ │ M5 │→ │ M6 M-Final  │
│base│  │tree│  │patch│ │glue│  │test│  │ docs+commit │
│line│  │repl│  │re-ap│ │fix │  │accp│  │             │
└────┘  └────┘  └────┘  └────┘  └────┘  └─────────────┘
```

| Milestone | Priority | Main Deliverable | Bounce Limit |
|---|---|---|---|
| **M1** baseline capture | P0 | 23.11.5 compile + performance baseline archived (CSV) | 1 |
| **M2** full-tree replacement | P0 | `replace:` commit; 24.11.6 tree in place; dpdk/build compiles 0 errors | 3 |
| **M3** 3-patch re-application | P0 | `port:` commit (merged form, see plan §4.4); 3 patches apply trivially on the 24.11.6 tree | 3 |
| **M4** F-Stack glue fixes | P1 | `lib/ff_dpdk_*.c` + `lib/ff_memory.c` compile + necessary include additions (e.g. R-D11) | 3 |
| **M5** test acceptance | P0 | TC-A ~ TC-G all PASS (see 06-test) | 3 |
| **M6** M-Final | P1 | top-level doc version sync + execution-log + final commit | 1 |

---

## 2. M1 — 23.11.5 Baseline Capture

### 2.1 Purpose

Before touching dpdk/, capture the 23.11.5 baseline data of (a) compile metrics and (b) performance baselines, as the reference for post-upgrade comparison.

### 2.2 Steps

#### Step 2.2.1 Compile Metric Capture

```bash
cd /data/workspace/f-stack/dpdk
# build/ already exists (measured), no meson setup needed
ninja -C build -j$(nproc) 2>&1 | tee /tmp/m1_dpdk_23_build.log
echo "errors: $(grep -ic 'error:' /tmp/m1_dpdk_23_build.log)"
echo "warnings: $(grep -ic 'warning' /tmp/m1_dpdk_23_build.log)"
ls -l build/lib/librte_eal.a build/lib/librte_ethdev.a
du -sh build/

cd /data/workspace/f-stack/lib
make clean && make 2>&1 | tee /tmp/m1_lib_build.log
ls -l libfstack.a

cd /data/workspace/f-stack/example
make 2>&1 | tee /tmp/m1_example_build.log
ls -l helloworld helloworld_zc helloworld_epoll
```

Archive to `dpdk_23_24_upgrade_spec/baseline_data/m1_23_baseline.txt`.

#### Step 2.2.2 Performance Baseline Capture

```bash
# use the existing phase-5b harness
cd /data/workspace/f-stack
tools/sbin/p5b_perf_matrix.sh --config 23-baseline 2>&1 | tee /tmp/m1_perf_23.log

# Key metrics:
# - TC1 (100 short connections): median wall time
# - TC2 (1000 short connections): median wall time
# - TC-nginx (single process + 100 short connections): median
```

Archive to `baseline_data/m1_23_perf.csv`.

### 2.3 Acceptance Criteria

| AC | Content | PASS Condition |
|---|---|---|
| M1-AC1 | dpdk/build/ compiles | exit=0 / 0 errors |
| M1-AC2 | lib/libfstack.a compiles | exit=0 / 0 errors |
| M1-AC3 | example/* compiles | exit=0; 3 binaries produced |
| M1-AC4 | performance data capture complete | TC1/TC2/TC-nginx, 3 trials each |

---

## 3. M2 — Full-Tree Replacement 23.11.5 → 24.11.6

### 3.1 Purpose

Execute the full-tree replacement per plan §4.1, producing the first `replace:` commit.

### 3.2 Steps

```bash
# Step 1: back up the current 23.11.5 mirror
cd /data/workspace/f-stack
mv dpdk dpdk.bak-23.11.5

# Step 2: full-tree copy of 24.11.6 upstream
cp -a /data/workspace/dpdk-stable-24.11.6 dpdk

# Note: cp -a does not copy the .ci/.editorconfig etc. dotfiles of the
# original dpdk-stable-24.11.6 (if they exist) — consistent with F-Stack's
# existing dpdk/ directory policy

# Step 3: verify version numbers
cat dpdk/VERSION dpdk/ABI_VERSION
# Expected: VERSION=24.11.6, ABI_VERSION=25.0

# Step 4: regenerate build
cd dpdk
meson setup build 2>&1 | tee /tmp/m2_meson_setup.log
ninja -C build -j$(nproc) 2>&1 | tee /tmp/m2_dpdk_24_build.log
echo "errors: $(grep -ic 'error:' /tmp/m2_dpdk_24_build.log)"

# Step 5: back up patches (for M3 use, **4**)
mkdir -p /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches
cd /data/workspace/f-stack
git format-patch -1 29c7d5835 -o /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/   # 0001 (new, supplementary identification after user feedback 2026-06-09 14:50)
git format-patch -1 5f3768c63 -o /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/   # 0002
git format-patch -1 62f1c34df -o /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/   # 0003
git format-patch -1 92718178b -o /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/   # 0004

# Step 6: stage + commit (replace: type)
cd /data/workspace/f-stack
git add dpdk/
git -c user.email=harness@local -c user.name="dpdk-replace-leader" commit -m "replace: bump F-Stack embedded DPDK from 23.11.5 to 24.11.6 LTS (tree replace)

Pristine integration of upstream DPDK 24.11.6 LTS into f-stack/dpdk/. F-Stack
local patches (29c7d5835 + 5f3768c63 + 62f1c34df + 92718178b) are NOT in
this commit; they will be re-applied in the immediately-following 'port:'
commit per plan.md §4.4 (single merged 'port:' commit per DP-A8). Patch list
updated 3 -> 4 after user 2026-06-09 14:50 KNI feedback uncovered patch-scout's
missed identification of 29c7d5835.

Versions:
  upstream: VERSION=24.11.6, ABI_VERSION=25.0
  previous: VERSION=23.11.5, ABI_VERSION=24.0

lib/ count: 57 -> 59 (+argparse +ptr_compress, both opt-in, F-Stack 0 ref).

Backed up old tree to f-stack/dpdk.bak-23.11.5/ (kept until M5 PASS).
F-Stack patches saved as git format-patch under
/data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/.

Local commit only; no push."
```

### 3.3 Acceptance Criteria

| AC | Content | PASS Condition |
|---|---|---|
| M2-AC1 | `dpdk/VERSION + ABI_VERSION` | `24.11.6 + 25.0` |
| M2-AC2 | `meson setup build` exit | 0 |
| M2-AC3 | `ninja -C build` compile | exit=0 / 0 errors |
| M2-AC4 | 4 patches archived | `ls /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/*.patch` should show 4 |
| M2-AC5 | git commit landed | `git log -1 --format='%h %s'` shows the `replace:` commit |

### 3.4 Risks

| ID | Risk | mitigation |
|---|---|---|
| M2-R1 | meson setup build fails due to insufficient toolchain versions | upgrade meson / ninja / gcc (adjusted per the 02 §3.8 measurement) |
| M2-R2 | ~~KNI removed in 24.11.6 causing lib/Makefile FF_KNI=1 build failure~~ | **closed (user feedback 2026-06-09 14:50)**: F-Stack's FF_KNI is a ring + virtio_user self-implementation unrelated to DPDK librte_kni; FF_KNI=1 still builds/links fine on 24.11.6 (see 02 §3.6) |
| M2-R3 | enable_kmods defaults to false in meson_options.txt, so igb_uio is not built (24.11 vs 23.11 default difference) | measure in Phase 2; if the default became false, modify meson_options.txt when re-applying patches in M3 |

---

## 4. M3 — 4-Patch Re-application (**revised 3→4 after user feedback 2026-06-09 14:50**)

### 4.1 Purpose

Apply the 4 F-Stack historical patches onto the 24.11.6 tree, producing the second `port:` commit (merged form, see plan §4.4). **The 4th patch (`29c7d5835`) was missed in patch-scout's first report**, supplemented by measurement after the user hinted the KNI truth (see 02 §2.4).

### 4.2 Re-application Order and Strategy (chronological by commit time)

#### Step 4.2.0 Re-apply 29c7d5835 (Remove redundant dpdk files) — **new**

```bash
cd /data/workspace/f-stack
git apply --check /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0001-Remove-redundant-dpdk-files.patch
```

Expected results:
- most hunks automatically N/A (24.11.6 upstream already lacks KNI / old igb_uio)
- some hunks apply OK (liquidio / acc200 / nfp / idpf / flow_classify / server_node_efd / Windows EAL log etc. redundant files — 24.11.6 upstream may still have them)
- a few hunks fail (24.11.6 internal redundant files renamed/moved) → coder adjusts as appropriate: (a) skip the hunk (upstream proactively deleted) (b) adjust the path

→ **Key**: the purpose of re-applying this patch is to **keep F-Stack's consistent lean dpdk/ mirror policy**; the KNI / igb_uio parts are automatically skipped. **User's key intent** (hinted 2026-06-09 14:50):
- ✅ keep `FF_KNI=1` (F-Stack's self-implemented ring + virtio_user KNI path, unrelated to DPDK librte_kni)
- ✅ remove the KNI kernel-module code from dpdk/ (naturally achieved — 24.11.6 upstream never had it + the 29c7d5835 re-application keeps it deleted)
- ✅ dpdk/ keeps only the single igb_uio kernel module (restored by re-applying 5f3768c63, see §4.2.1)

#### Step 4.2.1 Re-apply 5f3768c63 (igb_uio + freebsd rte_os.h)

```bash
cd /data/workspace/f-stack
git apply --check /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0001-Sync-DPDK-s-modifies.patch
# Expected: apply --check all OK; if freebsd rte_os.h already has the 13.1+ adaptation the hunk may skip
git apply /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0001-Sync-DPDK-s-modifies.patch
```

Expected results:
- the `dpdk/kernel/linux/` subtree added as a whole (24.11.6 upstream never had linux/, so the added files apply trivially)
- the `dpdk/kernel/meson.build` linux-reference hunk applies OK
- the FreeBSD 13.1+ hunk of `dpdk/lib/eal/freebsd/include/rte_os.h` applies OK

On hunk failure → bounce → coder manual rebase.

#### Step 4.2.2 Re-apply 62f1c34df (rte_timer_meta_init)

```bash
git apply --check /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0002-Fix-infinite-loop-when-restarting-DPDK-secondary-process.patch
git apply /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0002-Fix-infinite-loop-when-restarting-DPDK-secondary-process.patch
```

Expected:
- the hunks of `dpdk/lib/timer/rte_timer.c` + `rte_timer.h` may have slightly shifted context due to 24.11.6's `__rte_cache_aligned` macro position adjustment, but the semantics apply trivially
- the `f-stack/lib/ff_dpdk_if.c:910` call-site hunk applies OK

On hunk failure (typical: `__rte_cache_aligned` context-line mismatch) → coder manually adjusts the patch context lines and re-applies.

#### Step 4.2.3 Re-apply 92718178b (eal_bus_cleanup PRIMARY guard)

```bash
git apply --check /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0003-dpdk-eal-fix-secondary-process-calling-eal_bus_cleanup.patch
git apply /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0003-dpdk-eal-fix-secondary-process-calling-eal_bus_cleanup.patch
```

Expected **higher probability of hunk failure**:
- 24.11.6's `rte_eal_cleanup()` call order has been adjusted (`rte_service_finalize()` moved earlier, `eal_lcore_var_cleanup()` added)
- F-Stack's original patch assumed the 23.11.5 call order; the coder needs to rebase to the 24.11.6 new order
- equivalence self-check: there must be the `if (rte_eal_process_type() == RTE_PROC_PRIMARY)` guard before the `eal_bus_cleanup()` call, and only this one call site is guarded

#### Step 4.2.4 Equivalence Self-Check

After re-applying the 3 patches, verify each patch diff:

```bash
# For 5f3768c63
diff <(git show 5f3768c63 -- 'dpdk/**' | grep '^[+-]' | grep -v '^[+-]\{3\}') \
     <(git diff HEAD --staged -- 'dpdk/kernel/' 'dpdk/lib/eal/freebsd/' | grep '^[+-]' | grep -v '^[+-]\{3\}')
# Expected: only context-line differences, no semantic differences

# For 62f1c34df
# same as above, targets dpdk/lib/timer/ + lib/ff_dpdk_if.c
```

#### Step 4.2.5 Merge Commit

```bash
cd /data/workspace/f-stack
# stage all changes (dpdk/kernel/linux/ whole subtree + dpdk/lib/timer/ + dpdk/lib/eal/{linux,freebsd}/ + lib/ff_dpdk_if.c)
git add dpdk/ lib/ff_dpdk_if.c
git -c user.email=harness@local -c user.name="dpdk-port-leader" commit -m "port: re-apply F-Stack local DPDK patches onto 24.11.6 (4 patches: redundant cleanup + igb_uio + rte_timer + eal secondary)

Re-applies 4 historical F-Stack patches that landed on top of DPDK 23.11.5 to
the freshly-replaced upstream 24.11.6 tree per plan.md §4.4 (single-commit
merge per user 2026-06-09 14:36 directive). Patch list updated 3 -> 4 after
user 2026-06-09 14:50 KNI feedback uncovered patch-scout's missed identification
of 29c7d5835.

Patches re-applied (chronological):

  29c7d5835 (2025-01-10) Remove redundant dpdk files (310 files, -43195)
    Strategy: keep F-Stack's lean dpdk/ mirror; KNI / igb_uio parts
    auto-N/A in 24.11.6 (upstream already lacks them); other redundant
    drivers (liquidio / acc200 / nfp / idpf / flow_classify /
    server_node_efd / Windows EAL log / etc.) re-applied where 24.11.6
    upstream still ships them.
    Net result on 24.11.6 tree: dpdk/ contains only the F-Stack-needed
    libs and drivers, and 'kernel/' contains only igb_uio after step 5f3768c63.

  5f3768c63 (2025-10-31) Sync DPDK's modifies
    - dpdk/kernel/linux/igb_uio/{igb_uio.c, compat.h, Kbuild, Makefile, meson.build}
    - dpdk/kernel/linux/meson.build (re-introduced)
    - dpdk/kernel/meson.build (point to linux/)
    - dpdk/lib/eal/freebsd/include/rte_os.h
    Reason: DPDK upstream removed igb_uio in 21.05; F-Stack maintains its
    own (Copyright 2010-2017 Intel) ported from <=20.11. FreeBSD 13.1+
    CPU_AND/CPU_OR 3-arg adaptation is F-Stack-specific.

  62f1c34df (2026-01-16) Fix infinite loop when restarting DPDK secondary process
    - dpdk/lib/timer/rte_timer.c (+13: rte_timer_meta_init() body)
    - dpdk/lib/timer/rte_timer.h (+8: declaration)
    - lib/ff_dpdk_if.c:910 (+1: rte_timer_meta_init() call)
    Reason: lib/timer in 24.11.6 has 0 logical changes (only macro position
    adjustment, ABI offset preserved). Patch trivially applies.

  92718178b (2026-03-18) dpdk/eal: fix secondary process calling eal_bus_cleanup()
    - dpdk/lib/eal/linux/eal.c (+12 / -1: PRIMARY guard around eal_bus_cleanup())
    Reason: 24.11.6 stable still unconditionally calls eal_bus_cleanup() in
    rte_eal_cleanup(). Real upstream fix in DPDK 25.07 commit 4bc53f8f0d64,
    NOT backported to 24.11.6. Patch rebased to fit 24.11.6 new call order.

KNI clarification (per user 2026-06-09 14:50 feedback):
  F-Stack's 'KNI' (lib/ff_dpdk_kni.c) is a ring + virtio_user user-space
  exception path with ZERO dependency on DPDK librte_kni. lib/Makefile:34
  comment 'No DPDK KNI support on FreeBSD' + 'Enable KNI, via virtio only,
  no longer support rte_kni.ko' makes this explicit. FF_KNI=1 retained.
  No DPDK lib/kni or kernel/linux/kni in upgraded dpdk/ (already deleted
  in 29c7d5835, also absent in 24.11.6 upstream). Only kernel module
  remaining in dpdk/kernel/linux/ is igb_uio (per 5f3768c63).

Equivalence check passed: each patch's semantic delta vs the original commit
matches except for context-line offsets caused by upstream's neighboring
changes.

Build verified: dpdk/build/ + lib/libfstack.a + example/* all compile clean.

Local commit only; no push."
```

### 4.3 Acceptance Criteria

| AC | Content | PASS Condition |
|---|---|---|
| M3-AC1 | 4 patches applied successfully (including partial N/A) | each `git apply` exit=0; the trivially-N/A KNI/igb_uio parts of 29c7d5835 do not count as failure |
| M3-AC2 | equivalence self-check | 4-patch diff vs historical commits differ only in context lines |
| M3-AC3 | dpdk/build compiles | exit=0 / 0 errors |
| M3-AC4 | KNI subtree verification | `ls dpdk/lib/kni/ dpdk/kernel/linux/kni/` should both return No such file or directory |
| M3-AC5 | igb_uio subtree verification | `ls dpdk/kernel/linux/igb_uio/` should contain igb_uio.c + compat.h + Kbuild + Makefile + meson.build |
| M3-AC6 | git commit landed | `git log -1` shows the `port:` commit |

### 4.4 Risks

| ID | Risk | mitigation |
|---|---|---|
| M3-R1 | 92718178b hunk fails due to the 24.11.6 call-order change | coder manually rebases, aligned with 24's new `rte_service_finalize()` / `eal_lcore_var_cleanup()` |
| M3-R2 | KNI / old igb_uio / multiple redundant drivers in 29c7d5835 are absent in 24.11.6 upstream | `git apply --3way` automatically skips N/A hunks; the equivalence self-check tolerates this |
| M3-R3 | some redundant files in 24.11.6 have been renamed / moved | some hunks fail; coder as appropriate: (a) skip the hunk (upstream proactively deleted) (b) adjust the path (upstream renamed) |
| M3-R4 | freebsd rte_os.h in 5f3768c63 already has an equivalent hunk in 24.11 upstream | skip the hunk (`git apply --3way` auto-merges), the equivalence self-check should not fail |
| M3-R5 | igb_uio needs new compat for kernel 6.x compatibility | discovered at Phase 2 compile time, appended as a separate `fix:` commit (per plan §4.4 exception clause) |

---

## 5. M4 — F-Stack Glue Fixes

### 5.1 Purpose

Fix the compile errors (if any) of `lib/ff_dpdk_*.c` + `lib/ff_memory.c` under the 24.11.6 ABI.

### 5.2 Known Potential Fix Points (based on 02 + diff-comparator measurement)

| Fix Point | Trigger Condition | Handling |
|---|---|---|
| **rte_ip.h trap** (R-D11) | `lib/ff_dpdk_*.c` directly uses fields of `struct rte_ipv4_hdr` / `struct rte_ipv6_hdr` | grep + add `#include <rte_ip4.h>` or `<rte_ip6.h>` |
| **rte_eth_bond_*** | 23 already `_members_get` (verified by diff-comparator), no rename needed | skip |
| **rte_mbuf field adjustments** | 24.11.6 mbuf file-level only +`mbuf_log.h`; struct offsets pending compile verification | adjust per signature on compile errors |
| **eal_lcore_var-class symbols** | 0 references in F-Stack, no impact | skip |

### 5.3 Steps

```bash
cd /data/workspace/f-stack/lib
make clean && make 2>&1 | tee /tmp/m4_lib_build.log
echo "errors: $(grep -ic 'error:' /tmp/m4_lib_build.log)"

# fix any errors per the 02 §3.7 + diff-comparator Q4 table
# usually an #include <rte_ip4.h> or similar minimal patch

cd ../example
make 2>&1 | tee /tmp/m4_example_build.log
```

### 5.4 Acceptance Criteria

| AC | Content | PASS Condition |
|---|---|---|
| M4-AC1 | lib/libfstack.a compiles | exit=0 / 0 errors |
| M4-AC2 | warnings not exceeding the freebsd-15 baseline | ≤ 62 (baseline 57 + 5) |
| M4-AC3 | example/* compiles | exit=0; 3 binaries produced |

### 5.5 Commit Strategy

If M4 needs to modify F-Stack glue files (`lib/ff_dpdk_*.c` or `ff_memory.c`), an independent `fix:` commit (per the plan §4.4 exception clause):

```bash
git -c user.email=harness@local -c user.name="dpdk-glue-fix" commit -m "fix: adapt f-stack glue layer to DPDK 24.11.6 ABI

Minor source-level adjustments in lib/ff_dpdk_*.c required because of
DPDK 24.11.6 internal refactoring:

  - lib/ff_dpdk_if.c: add #include <rte_ip4.h> to access struct rte_ipv4_hdr
    (24.11 split rte_ip.h into rte_ip4.h + rte_ip6.h, 21.6 KB -> 210 B stub)
  - <other minor changes here>

No behavioral change; equivalent to upstream rte_ip.h at 23.11.5 era.
Local commit only; no push."
```

If M4 needs no source modification (ideal case), skip this commit.

---

## 6. M5 — Test Acceptance

### 6.1 Scope

See `06-test-and-acceptance-spec.md` for details. This section only lists the milestone-level PASS/FAIL matrix.

| Gate | Test | Time Cap | Failure Handling |
|---|---|---|---|
| **G3.A** | helloworld single-process function (HTTP 200 + 100 short connections) | 10 min | bounce → coder |
| **G3.B** | helloworld single-process performance (curl-bench 100 + 1000 short connections, 3 trials) | 30 min | observation label or coder |
| **G3.C** | nginx single-process function (HTTP 200 + 100 short connections) | 15 min | bounce → coder |
| **G3.D** | nginx single-process performance (wrk if available else curl loop) | 30 min | observation or coder |
| **G3.E** | nginx multi-process function (worker_processes 4 + curl + reload + worker exit test) | 30 min | bounce → coder (verify 92718178b + 62f1c34df still effective) |
| **G3.F** | nginx multi-process wrk **functional** (functionality only, no horizontal scaling) | 15 min | bounce → coder |
| **G3.G** | F-Stack phase-2 + vlan-test historical capability single-pass smoke | 60 min | observation or split into an independent phase |

### 6.2 Acceptance Criteria

See the subsections of §G3 in 06-test-and-acceptance-spec.md.

---

## 7. M6 — M-Final Doc Sync and Final Commit

### 7.1 Purpose

Land the 23.11.5 → 24.11.6 upgrade facts into the top-level docs + KB, and form the execution-log to wrap up the whole project.

### 7.2 Steps

#### Step 7.2.1 Top-Level Doc Sync

| File | Modification |
|---|---|
| `docs/README.md:256` | `DPDK version: 23.11.5 (unchanged — C-3 constraint)` → `DPDK version: 24.11.6 (LTS upgrade 2026-06-09)` + KB version 1.2 → 1.3 |
| `docs/01-LAYER1-ARCHITECTURE.md` | grep for DPDK version anchors and sync them all to 24.11.6; add an anchor referencing this spec |
| `docs/zh_cn/01-LAYER1-ARCHITECTURE.md` | sync the Chinese version |
| `docs/F-Stack_Knowledge_Base_Summary.md` + zh_cn | sync the DPDK version |
| `docs/freebsd_13_to_15_upgrade_spec/zh_cn/00-project-closure.md` | add a DPDK upgrade anchor to the §3.3 performance baseline footnote (if applicable) |

#### Step 7.2.2 Write the Execution Log

`docs/dpdk_23_24_upgrade_spec/execution-log.md` (new), containing:
- the M1~M6 full timeline
- per-milestone bounce counts
- the 23 vs 24 performance baseline comparison table
- known leftover follow-ups (DP-Cx)
- compliance self-check (0 direct rm/kill/chmod calls)

#### Step 7.2.3 Backup

`/data/workspace/dpdk-stable-24.11.6/f-stack-lib/test-configs/dpdk-23-24-upgrade/` mirrors all 7 spec documents (same pattern as the freebsd project).

#### Step 7.2.4 Final Commit

```bash
git -c user.email=harness@local -c user.name="dpdk-upgrade-finalizer" commit -m "docs(M-Final): close DPDK 23.11.5 -> 24.11.6 LTS upgrade project

Final wrap-up commit for the DPDK upgrade. Covers:

  - All 7 spec docs (plan + 6 spec) under docs/dpdk_23_24_upgrade_spec/
  - Top-tier 3-tier architecture doc DPDK version anchors synced to 24.11.6
  - docs/README.md KB version bumped 1.2 -> 1.3
  - Project execution-log with M1~M6 timeline + perf baseline comparison
  - Pristine spec backup to dpdk-stable-24.11.6/f-stack-lib/

Workspace mandate compliance: 0 direct rm/kill/chmod throughout the entire
upgrade lifecycle (all via wrapper scripts).

Local commit only; no push."
```

### 7.3 Acceptance Criteria

| AC | Content | PASS Condition |
|---|---|---|
| M6-AC1 | all top-level docs synced | grep `23.11.5` in docs/README + three-layer architecture docs = 0 hits |
| M6-AC2 | execution-log written | `docs/dpdk_23_24_upgrade_spec/execution-log.md` ≥ 100 lines |
| M6-AC3 | backup complete | `dpdk-stable-24.11.6/f-stack-lib/test-configs/dpdk-23-24-upgrade/` contains all 7 documents |
| M6-AC4 | KG auto reindex done | `cat .gitnexus/meta.json` after commit: `lastCommit` = M-Final commit hash |

---

## 8. Cross-Milestone Concerns

### 8.1 Workspace Mandatory Rules (every milestone must comply)

- Deletion: `/data/workspace/rm_tmp_file.sh` (**forbidden**: raw `rm`)
- Process termination: `/data/workspace/kill_process.sh` (**forbidden**: raw `kill / pkill / killall`)
- Permission changes: `/data/workspace/chmod_modify.sh` (**forbidden**: raw `chmod`)
- Local commit only, **no push** (the user decides push timing)

### 8.2 Commit Form Summary (3-4 commits total)

| # | Type | Content | Source |
|---|---|---|---|
| 1 | `replace:` | full-tree replacement 23.11.5 → 24.11.6 | M2 |
| 2 | `port:` | 4-patch re-application merged (merged form, per plan §4.4 + DP-A8; patch count revised 3→4 after user feedback 2026-06-09 14:50 KNI) | M3 |
| 3 (optional) | `fix:` | source modifications required in the F-Stack glue layer due to 24.11 ABI adjustments (e.g. `#include <rte_ip4.h>`); skipped if M4 has no source changes | M4 |
| 4 | `docs(M-Final):` | top-level doc sync + execution-log + backup | M6 |

### 8.3 Backup and Rollback Strategy

| Backup Target | Retention |
|---|---|
| `f-stack/dpdk.bak-23.11.5/` | after all M5 PASS, cleanup timing decided by the user (via `rm_tmp_file.sh`) |
| `dpdk-stable-24.11.6/f-stack-lib/patches/` 3 patches | kept permanently |
| `dpdk-stable-24.11.6/f-stack-lib/test-configs/dpdk-23-24-upgrade/` 7 specs | kept permanently |

Rollback: if M2 ~ M5 hit escalation pause and cannot recover, `git reset --hard <pre-M2 HEAD>` + `mv dpdk dpdk.failed-24-attempt && mv dpdk.bak-23.11.5 dpdk` immediately restores the 23.11.5 state.

---

## 9. Timeline Estimate (reference only, non-binding)

| Milestone | Estimated Turns |
|---|---|
| M1 baseline capture | 1-2 |
| M2 full-tree replacement | 2-3 (including KNI / igb_uio / kmods measurement decisions) |
| M3 3-patch re-application | 3-5 (92718178b likely needs a rebase) |
| M4 glue fixes | 1-3 (depends on the R-D11 measurement) |
| M5 test acceptance | 5-8 |
| M6 M-Final | 2-3 |
| **Total** | **14-24 turns** |

---

## 10. Document Meta-Information

- **Status**: v0.1 DRAFT — pending gate-keeper review
- **Next**: read `06-test-and-acceptance-spec.md` for the specific test and acceptance criteria
