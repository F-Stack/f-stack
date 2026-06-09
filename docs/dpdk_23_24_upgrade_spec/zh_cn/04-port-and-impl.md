# 04 — 移植与实施计划（Port & Implementation Plan）

> 文档版本：v0.1（2026-06-09）
> Parent plan：`plan.md`
> 上游文档：`00 / 01 / 02`
> 调研输入：diff-comparator + dpdk-23-patch-scout + dpdk-24-analyzer 三路并行调研结果（实测）

---

## 1. 实施总览

本 spec 把"整树替换 + 3 patch 重打"拆分为 **6 个里程碑（M1~M6）**，由 leader + coder 角色（阶段二激活）按节奏推进。每个里程碑独立 `bounce counter`（≤ 3 次），超限触发 escalation 暂停。

```
┌────┐  ┌────┐  ┌────┐  ┌────┐  ┌────┐  ┌─────────────┐
│ M1 │→ │ M2 │→ │ M3 │→ │ M4 │→ │ M5 │→ │ M6 M-Final  │
│基线│  │替换│  │重打│  │胶水│  │测试│  │ 文档+commit │
│采集│  │ 树 │  │patch│ │修复│  │验收│  │             │
└────┘  └────┘  └────┘  └────┘  └────┘  └─────────────┘
```

| 里程碑 | 优先级 | 主要交付 | Bounce 上限 |
|---|---|---|---|
| **M1** baseline 采集 | P0 | 23.11.5 编译 + 性能 baseline 落档（CSV）| 1 |
| **M2** 整树替换 | P0 | `replace:` commit；24.11.6 树就位；dpdk/build 编译 0 errors | 3 |
| **M3** 3 patch 重打 | P0 | `port:` commit（合并形态，详 plan §4.4）；3 patch 在 24.11.6 树上 trivially apply | 3 |
| **M4** F-Stack 胶水修复 | P1 | `lib/ff_dpdk_*.c` + `lib/ff_memory.c` 编译通过 + 必要的 include 补全（如 R-D11）| 3 |
| **M5** 测试验收 | P0 | TC-A ~ TC-G 全 PASS（详 06-test）| 3 |
| **M6** M-Final | P1 | 顶层 doc 版本号同步 + execution-log + 最终 commit | 1 |

---

## 2. M1 — 23.11.5 baseline 采集

### 2.1 目的

在动 dpdk/ 之前，采集 23.11.5 baseline 的（a）编译指标 和（b）性能基线 数据，作为升级后对照基准。

### 2.2 步骤

#### Step 2.2.1 编译指标采集

```bash
cd /data/workspace/f-stack/dpdk
# build/ 已存在（实测），无需 meson setup
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

落档至 `dpdk_23_24_upgrade_spec/zh_cn/baseline_data/m1_23_baseline.txt`。

#### Step 2.2.2 性能基线采集

```bash
# 使用 phase-5b 既有 harness
cd /data/workspace/f-stack
tools/sbin/p5b_perf_matrix.sh --config 23-baseline 2>&1 | tee /tmp/m1_perf_23.log

# 关键指标：
# - TC1 (100 短连): median wall time
# - TC2 (1000 短连): median wall time
# - TC-nginx (单进程 + 100 短连): median
```

落档至 `baseline_data/m1_23_perf.csv`。

### 2.3 验收标准

| AC | 内容 | PASS 条件 |
|---|---|---|
| M1-AC1 | dpdk/build/ 编译 | exit=0 / 0 errors |
| M1-AC2 | lib/libfstack.a 编译 | exit=0 / 0 errors |
| M1-AC3 | example/* 编译 | exit=0；3 binaries 产出 |
| M1-AC4 | 性能数据采集完整 | TC1/TC2/TC-nginx 各 3 trials |

---

## 3. M2 — 整树替换 23.11.5 → 24.11.6

### 3.1 目的

按 plan §4.1 执行整树替换，产生第一个 `replace:` commit。

### 3.2 步骤

```bash
# Step 1: 备份当前 23.11.5 镜像
cd /data/workspace/f-stack
mv dpdk dpdk.bak-23.11.5

# Step 2: 整树拷贝 24.11.6 upstream
cp -a /data/workspace/dpdk-stable-24.11.6 dpdk

# 注意：cp -a 不会拷贝原始 dpdk-stable-24.11.6 的 .ci/.editorconfig 等
# dotfile（如果它们存在）— 这与 F-Stack 既有 dpdk/ 目录的策略一致

# Step 3: 验证版本号
cat dpdk/VERSION dpdk/ABI_VERSION
# 期望: VERSION=24.11.6, ABI_VERSION=25.0

# Step 4: 重新生成 build
cd dpdk
meson setup build 2>&1 | tee /tmp/m2_meson_setup.log
ninja -C build -j$(nproc) 2>&1 | tee /tmp/m2_dpdk_24_build.log
echo "errors: $(grep -ic 'error:' /tmp/m2_dpdk_24_build.log)"

# Step 5: 备份 patch（待 M3 用，**4 个**）
mkdir -p /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches
cd /data/workspace/f-stack
git format-patch -1 29c7d5835 -o /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/   # 0001 (新增, 由 user 2026-06-09 14:50 反馈后补识别)
git format-patch -1 5f3768c63 -o /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/   # 0002
git format-patch -1 62f1c34df -o /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/   # 0003
git format-patch -1 92718178b -o /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/   # 0004

# Step 6: stage + commit (replace: 类型)
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

### 3.3 验收标准

| AC | 内容 | PASS 条件 |
|---|---|---|
| M2-AC1 | `dpdk/VERSION + ABI_VERSION` | `24.11.6 + 25.0` |
| M2-AC2 | `meson setup build` exit | 0 |
| M2-AC3 | `ninja -C build` 编译 | exit=0 / 0 errors |
| M2-AC4 | 4 patch 已落档 | `ls /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/*.patch` 应 4 个 |
| M2-AC5 | git commit 落地 | `git log -1 --format='%h %s'` 显示 `replace:` commit |

### 3.4 风险

| ID | 风险 | mitigation |
|---|---|---|
| M2-R1 | meson setup build 因工具链版本不足失败 | 升级 meson / ninja / gcc（按 02 §3.8 实测后调整）|
| M2-R2 | ~~KNI 在 24.11.6 已删除导致 lib/Makefile FF_KNI=1 build 失败~~ | **已闭环（user 2026-06-09 14:50 反馈）**：F-Stack 的 FF_KNI 是 ring + virtio_user 自实现，与 DPDK librte_kni 无关；FF_KNI=1 在 24.11.6 上仍正常 build / 链接（详 02 §3.6）|
| M2-R3 | meson_options.txt 中 enable_kmods 默认为 false，导致 igb_uio 不被编译（24.11 vs 23.11 默认值差异） | 阶段二实测；如默认变为 false，M3 patch 重打时同步修改 meson_options.txt |

---

## 4. M3 — 4 patch 重打（**user 2026-06-09 14:50 反馈后修订：3→4**）

### 4.1 目的

把 F-Stack 历史 4 patch 应用到 24.11.6 树上，产生第二个 `port:` commit（合并形态，详 plan §4.4）。**第 4 个 patch（`29c7d5835`）是 patch-scout 第一次报告漏识别**，由 user 提示 KNI 真相后实测补全（详 02 §2.4）。

### 4.2 重打顺序与策略（按 commit 时间正序）

#### Step 4.2.0 重打 29c7d5835（Remove redundant dpdk files）— **新增**

```bash
cd /data/workspace/f-stack
git apply --check /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0001-Remove-redundant-dpdk-files.patch
```

预期结果：
- 大部分 hunk 自动 N/A（24.11.6 上游已无 KNI / 旧版 igb_uio）
- 部分 hunk apply OK（liquidio / acc200 / nfp / idpf / flow_classify / server_node_efd / Windows EAL log 等 redundant — 24.11.6 上游可能仍存在）
- 少量 hunk fail（24.11.6 内部 redundant 文件改名/移位）→ coder 视情况调整：(a) 跳过该 hunk（上游已主动删）(b) 调整路径

→ **关键**：本 patch 重打的目的是**保持 F-Stack 一贯 lean dpdk/ 镜像策略**；KNI / igb_uio 部分自动跳过。**user 关键意图**（2026-06-09 14:50 提示）：
- ✅ 保留 `FF_KNI=1`（F-Stack 自实现的 ring + virtio_user KNI 路径，与 DPDK librte_kni 无关）
- ✅ 移除 dpdk/ 中的 KNI 内核模块代码（自然实现 — 24.11.6 上游本就无 + 29c7d5835 重打保持）
- ✅ dpdk/ 仅保留 igb_uio 一个内核模块（由 5f3768c63 重打恢复，详 §4.2.1）

#### Step 4.2.1 重打 5f3768c63（igb_uio + freebsd rte_os.h）

```bash
cd /data/workspace/f-stack
git apply --check /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0001-Sync-DPDK-s-modifies.patch
# 期望：apply --check 全部 OK；如 freebsd rte_os.h 已含 13.1+ 适配则 hunk 可能跳过
git apply /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0001-Sync-DPDK-s-modifies.patch
```

预期结果：
- `dpdk/kernel/linux/` 子树整体添加（24.11.6 上游本就无 linux/，故 add 文件 trivially apply）
- `dpdk/kernel/meson.build` 添加 linux 引用 hunk apply OK
- `dpdk/lib/eal/freebsd/include/rte_os.h` 的 FreeBSD 13.1+ hunk apply OK

如 hunk fail → bounce → coder 手动 rebase。

#### Step 4.2.2 重打 62f1c34df（rte_timer_meta_init）

```bash
git apply --check /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0002-Fix-infinite-loop-when-restarting-DPDK-secondary-process.patch
git apply /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0002-Fix-infinite-loop-when-restarting-DPDK-secondary-process.patch
```

预期：
- `dpdk/lib/timer/rte_timer.c` + `rte_timer.h` 的 hunk 可能因 24.11.6 的 `__rte_cache_aligned` 宏位置调整而上下文略有偏差，但语义 trivially apply
- `f-stack/lib/ff_dpdk_if.c:910` 调用点 hunk apply OK

如 hunk fail（典型：`__rte_cache_aligned` 上下文行不匹配）→ coder 手动调整 patch 上下文行重新 apply。

#### Step 4.2.3 重打 92718178b（eal_bus_cleanup PRIMARY 守护）

```bash
git apply --check /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0003-dpdk-eal-fix-secondary-process-calling-eal_bus_cleanup.patch
git apply /data/workspace/dpdk-stable-24.11.6/f-stack-lib/patches/0003-dpdk-eal-fix-secondary-process-calling-eal_bus_cleanup.patch
```

预期 **较高概率 hunk fail**：
- 24.11.6 的 `rte_eal_cleanup()` 调用顺序已调整（`rte_service_finalize()` 移到前面，新增 `eal_lcore_var_cleanup()`）
- F-Stack 原 patch 假设 23.11.5 的调用顺序，需要 coder rebase 到 24.11.6 新顺序
- 等价性自检：`eal_bus_cleanup()` 调用前必须有 `if (rte_eal_process_type() == RTE_PROC_PRIMARY)` 守护，且仅守护此 1 处调用

#### Step 4.2.4 等价性自检

对 3 patch 重打后，逐 patch diff 验证：
```bash
# 对 5f3768c63
diff <(git show 5f3768c63 -- 'dpdk/**' | grep '^[+-]' | grep -v '^[+-]\{3\}') \
     <(git diff HEAD --staged -- 'dpdk/kernel/' 'dpdk/lib/eal/freebsd/' | grep '^[+-]' | grep -v '^[+-]\{3\}')
# 期望：仅有上下文行差异，没有语义差异

# 对 62f1c34df
# 同上，目标为 dpdk/lib/timer/ + lib/ff_dpdk_if.c
```

#### Step 4.2.5 合并 commit

```bash
cd /data/workspace/f-stack
# stage 所有改动（dpdk/kernel/linux/ 整子树 + dpdk/lib/timer/ + dpdk/lib/eal/{linux,freebsd}/ + lib/ff_dpdk_if.c）
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

### 4.3 验收标准

| AC | 内容 | PASS 条件 |
|---|---|---|
| M3-AC1 | 4 patch apply 成功（含部分 N/A）| 各 `git apply` exit=0；29c7d5835 KNI/igb_uio 部分 trivially N/A 不算 fail |
| M3-AC2 | 等价性自检 | 4 patch diff vs 历史 commit 仅上下文差异 |
| M3-AC3 | dpdk/build 编译 | exit=0 / 0 errors |
| M3-AC4 | KNI 子树验证 | `ls dpdk/lib/kni/ dpdk/kernel/linux/kni/` 应均返回 No such file or directory |
| M3-AC5 | igb_uio 子树验证 | `ls dpdk/kernel/linux/igb_uio/` 应含 igb_uio.c + compat.h + Kbuild + Makefile + meson.build |
| M3-AC6 | git commit 落地 | `git log -1` 显示 `port:` commit |

### 4.4 风险

| ID | 风险 | mitigation |
|---|---|---|
| M3-R1 | 92718178b 因 24.11.6 调用顺序变化 hunk fail | coder 手动 rebase，配合 24 新增的 `rte_service_finalize()` / `eal_lcore_var_cleanup()` |
| M3-R2 | 29c7d5835 中 KNI / 旧 igb_uio / 多个 redundant driver 在 24.11.6 上游本就无 | `git apply --3way` 自动跳过 N/A hunk；等价性自检容许此情况 |
| M3-R3 | 24.11.6 中部分 redundant files 命名 / 位置已变 | 部分 hunk fail；coder 视情况：(a) 跳过该 hunk（上游已主动删）(b) 调整路径（上游改名）|
| M3-R4 | 5f3768c63 中 freebsd rte_os.h 在 24.11 上游已含等效 hunk | 跳过该 hunk（`git apply --3way` 自动 merge），等价性自检不应 fail |
| M3-R5 | igb_uio 因 kernel 6.x 兼容性需要新增 compat | 阶段二编译期发现，单独追加 `fix:` commit（按 plan §4.4 例外条款）|

---

## 5. M4 — F-Stack 胶水修复

### 5.1 目的

修复 `lib/ff_dpdk_*.c` + `lib/ff_memory.c` 在 24.11.6 ABI 下的编译错误（如有）。

### 5.2 已知潜在修复点（基于 02 + diff-comparator 实测）

| 修复点 | 触发条件 | 处理 |
|---|---|---|
| **rte_ip.h 陷阱** (R-D11) | `lib/ff_dpdk_*.c` 直接使用 `struct rte_ipv4_hdr` / `struct rte_ipv6_hdr` 字段 | grep + 补 `#include <rte_ip4.h>` 或 `<rte_ip6.h>` |
| **rte_eth_bond_*** | 23 已是 `_members_get`（diff-comparator 已验证），无需改名 | 跳过 |
| **rte_mbuf 字段调整** | 24.11.6 mbuf 文件级仅 +`mbuf_log.h`，结构体偏移待编译验证 | 编译错误时按签名调整 |
| **eal_lcore_var 类符号** | F-Stack 0 引用，无影响 | 跳过 |

### 5.3 步骤

```bash
cd /data/workspace/f-stack/lib
make clean && make 2>&1 | tee /tmp/m4_lib_build.log
echo "errors: $(grep -ic 'error:' /tmp/m4_lib_build.log)"

# 如有 error 按 02 §3.7 + diff-comparator Q4 表对应修复
# 通常是 #include <rte_ip4.h> 或类似的 minimal patch

cd ../example
make 2>&1 | tee /tmp/m4_example_build.log
```

### 5.4 验收标准

| AC | 内容 | PASS 条件 |
|---|---|---|
| M4-AC1 | lib/libfstack.a 编译 | exit=0 / 0 errors |
| M4-AC2 | warnings 不超过 freebsd-15 baseline | ≤ 62（baseline 57 + 5）|
| M4-AC3 | example/* 编译 | exit=0；3 binaries 产出 |

### 5.5 commit 策略

如 M4 需要修改 F-Stack 胶水文件（`lib/ff_dpdk_*.c` 或 `ff_memory.c`），独立 `fix:` commit（per plan §4.4 例外条款）：

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

如 M4 无需任何源码修改（理想情况），跳过此 commit。

---

## 6. M5 — 测试验收

### 6.1 范围

详见 `06-test-and-acceptance-spec.md`。本节仅列里程碑级别 PASS/FAIL 矩阵。

| Gate | 测试 | 上限耗时 | 失败处理 |
|---|---|---|---|
| **G3.A** | helloworld 单进程功能（HTTP 200 + 100 短连）| 10 min | bounce → coder |
| **G3.B** | helloworld 单进程性能（curl-bench 100 + 1000 短连，3 trials）| 30 min | observation 标签或 coder |
| **G3.C** | nginx 单进程功能（HTTP 200 + 100 短连）| 15 min | bounce → coder |
| **G3.D** | nginx 单进程性能（wrk if available else curl loop）| 30 min | observation 或 coder |
| **G3.E** | nginx 多进程功能（worker_processes 4 + curl + reload + worker exit 测试）| 30 min | bounce → coder（验证 92718178b + 62f1c34df 仍有效）|
| **G3.F** | nginx 多进程 wrk **功能**（仅功能，无水平扩展）| 15 min | bounce → coder |
| **G3.G** | F-Stack phase-2 + vlan-test 历史能力 single-pass smoke | 60 min | observation 或拆分独立 phase |

### 6.2 验收标准

详见 06-test-and-acceptance-spec.md §G3 各子节。

---

## 7. M6 — M-Final 文档同步与最终 commit

### 7.1 目的

把 23.11.5 → 24.11.6 升级事实落进顶层 doc + KB，同时形成 execution-log 收尾整个项目。

### 7.2 步骤

#### Step 7.2.1 顶层 doc 同步

| 文件 | 修改 |
|---|---|
| `docs/README.md:256` | `DPDK version: 23.11.5 (unchanged — C-3 constraint)` → `DPDK version: 24.11.6 (LTS upgrade 2026-06-09)` + KB 版本 1.2 → 1.3 |
| `docs/01-LAYER1-ARCHITECTURE.md` | grep 找 DPDK 版本 anchor 全部 sync 到 24.11.6；新增 anchor 引用本 spec |
| `docs/zh_cn/01-LAYER1-ARCHITECTURE.md` | 同步中文版 |
| `docs/F-Stack_Knowledge_Base_Summary.md` + zh_cn | DPDK 版本同步 |
| `docs/freebsd_13_to_15_upgrade_spec/zh_cn/00-project-closure.md` | §3.3 性能基线注脚加 DPDK 升级 anchor（如适用）|

#### Step 7.2.2 写 execution log

`docs/dpdk_23_24_upgrade_spec/zh_cn/execution-log.md`（新增），包含：
- M1~M6 全程 timeline
- 各里程碑 bounce 计数
- 性能基线 23 vs 24 对比表
- 已知遗留 follow-up（DP-Cx）
- compliance 自查（rm/kill/chmod 0 直接调用）

#### Step 7.2.3 备份

`/data/workspace/dpdk-stable-24.11.6/f-stack-lib/test-configs/dpdk-23-24-upgrade/` 镜像所有 7 篇 spec 文档（与 freebsd 项目同款）。

#### Step 7.2.4 最终 commit

```bash
git -c user.email=harness@local -c user.name="dpdk-upgrade-finalizer" commit -m "docs(M-Final): close DPDK 23.11.5 -> 24.11.6 LTS upgrade project

Final wrap-up commit for the DPDK upgrade. Covers:

  - All 7 spec docs (plan + 6 spec) under docs/dpdk_23_24_upgrade_spec/zh_cn/
  - Top-tier 3-tier architecture doc DPDK version anchors synced to 24.11.6
  - docs/README.md KB version bumped 1.2 -> 1.3
  - Project execution-log with M1~M6 timeline + perf baseline comparison
  - Pristine spec backup to dpdk-stable-24.11.6/f-stack-lib/

Workspace mandate compliance: 0 direct rm/kill/chmod throughout the entire
upgrade lifecycle (all via wrapper scripts).

Local commit only; no push."
```

### 7.3 验收标准

| AC | 内容 | PASS 条件 |
|---|---|---|
| M6-AC1 | 顶层 doc 全部 sync | grep `23.11.5` 在 docs/README + 三层架构 doc 中 0 hits |
| M6-AC2 | execution-log 写入 | `docs/dpdk_23_24_upgrade_spec/zh_cn/execution-log.md` ≥ 100 行 |
| M6-AC3 | 备份完整 | `dpdk-stable-24.11.6/f-stack-lib/test-configs/dpdk-23-24-upgrade/` 含全部 7 篇 |
| M6-AC4 | KG 自动 reindex 完成 | commit 后 `cat .gitnexus/meta.json` 中 `lastCommit` = M-Final commit hash |

---

## 8. 跨里程碑横切关注点

### 8.1 工作区强制规约（每里程碑必须遵守）

- 删除：`/data/workspace/rm_tmp_file.sh`（**禁** raw `rm`）
- 进程终止：`/data/workspace/kill_process.sh`（**禁** raw `kill / pkill / killall`）
- 权限变更：`/data/workspace/chmod_modify.sh`（**禁** raw `chmod`）
- Local commit only，**禁 push**（用户决定 push 时机）

### 8.2 commit 形态总结（共 3-4 个 commit）

| # | 类型 | 内容 | 来源 |
|---|---|---|---|
| 1 | `replace:` | 整树替换 23.11.5 → 24.11.6 | M2 |
| 2 | `port:` | 4 patch 重打合并（合并形态，per plan §4.4 + DP-A8；patch 数量 3→4 由 user 2026-06-09 14:50 KNI 反馈后修订） | M3 |
| 3 (可选) | `fix:` | F-Stack 胶水层因 24.11 ABI 调整必须的源码修改（如 `#include <rte_ip4.h>`）；如 M4 无源码修改则跳过 | M4 |
| 4 | `docs(M-Final):` | 顶层 doc sync + execution-log + 备份 | M6 |

### 8.3 备份与回滚策略

| 备份目标 | 保留期 |
|---|---|
| `f-stack/dpdk.bak-23.11.5/` | M5 全 PASS 后由用户决策清理（用 `rm_tmp_file.sh`）|
| `dpdk-stable-24.11.6/f-stack-lib/patches/` 3 patch | 永久保留 |
| `dpdk-stable-24.11.6/f-stack-lib/test-configs/dpdk-23-24-upgrade/` 7 spec | 永久保留 |

回滚：如 M2 ~ M5 发生 escalation 暂停且无法恢复，`git reset --hard <pre-M2 HEAD>` + `mv dpdk dpdk.failed-24-attempt && mv dpdk.bak-23.11.5 dpdk` 立即恢复 23.11.5 状态。

---

## 9. 时间线估算（仅参考，不约束）

| 里程碑 | 估算回合 |
|---|---|
| M1 baseline 采集 | 1-2 |
| M2 整树替换 | 2-3（含 KNI / igb_uio / kmods 实测决策）|
| M3 3 patch 重打 | 3-5（92718178b 大概率需 rebase）|
| M4 胶水修复 | 1-3（取决于 R-D11 实测）|
| M5 测试验收 | 5-8 |
| M6 M-Final | 2-3 |
| **合计** | **14-24 回合** |

---

## 10. 文档元信息

- **状态**：v0.1 DRAFT — 待 gate-keeper 评审
- **下一步**：阅读 `06-test-and-acceptance-spec.md` 了解测试与验收的具体标准
