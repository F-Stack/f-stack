# 00 — 项目概览与术语表

> 文档语言：中文（首版）
> 系列文档根目录：`/data/workspace/f-stack/docs/dpdk_23_24_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-06-09）
> Parent plan：`plan.md`

---

## 1. 项目一句话定义

把 **F-Stack** 当前内嵌的 **DPDK 23.11.5 LTS** 升级到 **DPDK 24.11.6 LTS**，并产出可被工程团队与后续 AI 代理直接执行的中文 Spec 文档集。

> 本 Spec 阶段只产文档，不动代码；真正的整树替换、3 patch 重打、测试由 `04-port-and-impl.md` 定义的阶段二执行。

---

## 2. 项目背景

### 2.1 F-Stack 与 DPDK 的依赖关系

F-Stack 是把 FreeBSD 内核协议栈剥离出来跑在 DPDK 用户态的工程：DPDK 提供 NIC I/O、lcore 多线程、mbuf 池、ring 队列等基础设施，F-Stack 在其上承载 FreeBSD 的 TCP/IP/IPFW/NETGRAPH。F-Stack 与 DPDK 的接口集中在 `lib/ff_dpdk_if.c`（主胶水）+ `lib/ff_dpdk_pcap.c` + `lib/ff_dpdk_kni.c` + `lib/ff_memory.c`（page-array）四个文件。

### 2.2 F-Stack 内嵌 DPDK 模式

- F-Stack 仓库 `dpdk/` 子目录是完整 DPDK 23.11.5 镜像（57 lib、含 `build/` 编译产物，与 upstream 23.11.5 顶层结构一致，仅缺 `.ci/.editorconfig/.github/.mailmap` 4 个 dotfile）。
- F-Stack `lib/libfstack.a` 默认以 static lib 形式链接 DPDK，不依赖系统包管理。
- F-Stack 在 `dpdk/` 内累积了 3 个本地 patch（详见 §5.1）。

### 2.3 升级驱动力

- **23.11 LTS 与 24.11 LTS 的对齐**：DPDK LTS 周期约 1 年，24.11.6（2026-06）是当前最新 stable LTS。停在 23.11 远离上游驱动 / PMD / 性能优化。
- **`92718178b` patch 在上游的状态**：F-Stack 的 secondary 进程 cleanup fix 已等待 25.07 上游 fix 才能彻底消除（实测 24.11.6 stable 未合）。本次升级仅消除 23 vs 24 的 API 表面差异，但 `92718178b` 仍需 backport（24.11.6 内 `eal_bus_cleanup()` 仍是 PRIMARY/SECONDARY 不分的无条件调用）。
- **新 lib 评估**：24.07 引入 `argparse` + `ptr_compress`（HiSilicon / Arm 提交），F-Stack 完全不引用，零成本。

---

## 3. 范围边界

### 3.1 IN-SCOPE（本 Spec 系列覆盖）

| 范围 | 实测规模 |
|---|---|
| `f-stack/dpdk/`（升级目标，整树替换 23.11.5 → 24.11.6） | 整树（与 dpdk-stable-24.11.6 完全对齐 + 重打 3 个 F-Stack 历史 patch）|
| F-Stack 在 `dpdk/` 的本地 patch（3 commit） | 5f3768c63 + 62f1c34df + 92718178b |
| F-Stack 胶水文件 | `lib/ff_dpdk_if.c` + `lib/ff_dpdk_pcap.c` + `lib/ff_dpdk_kni.c` + `lib/ff_memory.c`（行级核查 24.11.6 ABI 兼容）|
| 测试 | helloworld 单进程功能+性能；nginx 单进程功能+性能；nginx 多进程 curl + wrk **功能** |

### 3.2 OUT-OF-SCOPE（本 Spec 系列**不**覆盖）

| 范围 | 不覆盖原因 |
|---|---|
| 实际整树替换与 3 patch 重打 | 仅 Spec 阶段；阶段二独立执行 |
| 性能基线物理机重测 | CVM ssh round-trip ~6 ms 决定单进程吞吐上限；多进程水平扩展由 user 后续物理机环境完成 |
| 24.11 KNI 子系统重启用 | 与本次升级解耦；如上游 KNI 在 24.11.6 仍存在，FF_KNI=1 维持现状 |
| argparse / ptr_compress 启用 | 24.07 新引入，F-Stack 0 引用，零成本不启用 |
| Git push | 仅本地 commit；push 时机由用户决定 |
| 英文版 Spec | 待中文版人工审计后再考虑（与 freebsd_13_to_15_upgrade_spec 同款约定）|
| 与 phase-2 启用的 7 个 FF_* flag 的回归矩阵 | 仅在 06-test 中作 single-pass smoke 验证，不做完整 5×3 矩阵 |

---

## 4. 三个源码根目录（实测）

| 路径 | 角色 | 版本 |
|---|---|---|
| `/data/workspace/dpdk-stable-23.11.5/` | DPDK 23.11.5 upstream 原版 | VERSION=23.11.5, ABI_VERSION=24.0 |
| `/data/workspace/dpdk-stable-24.11.6/` | DPDK 24.11.6 upstream 原版（升级目标）| VERSION=24.11.6, ABI_VERSION=25.0 |
| `/data/workspace/f-stack/dpdk/` | F-Stack 内嵌当前 DPDK | VERSION=23.11.5, ABI_VERSION=24.0（与 upstream 一致 + 3 个本地 patch）|

---

## 5. F-Stack 当前 DPDK 修改清单（实测）

### 5.1 4 个历史 patch 完整覆盖（**user 2026-06-09 14:50 反馈后修订：3→4**）

经 dpdk-23-patch-scout 实测 + user 反馈补识别：F-Stack 在 `dpdk/` 内的本地修改 = 4 个 commit 完全覆盖（patch-scout 第一次报告漏识别 `29c7d5835`，因 `diff -rq | head -25` 截断未捕获 redundant files 删除清单）。

| commit | 时间 | 内容分类 | 文件 | 升级时是否需迁移 |
|---|---|---|---|---|
| `29c7d5835` | 2025-01-10 | **Remove redundant dpdk files**（user 反馈后补识别）| 310 文件 / -43195 行（KNI / 旧 igb_uio / liquidio / acc200 / nfp / idpf / flow_classify / Windows EAL log / 等冗余清理）| **必须重打** — 24.11.6 中 KNI / 旧 igb_uio 自动 N/A（上游已无），其他 redundant 按需删除以保持 lean dpdk/ 镜像 |
| `5f3768c63` | 2025-10-31 | igb_uio 内核模块 + FreeBSD 13.1+ 适配 | `dpdk/kernel/linux/{igb_uio/{igb_uio.c, compat.h, Kbuild, Makefile, meson.build}, meson.build}` + `dpdk/lib/eal/freebsd/include/rte_os.h` | **必须重打** — 24.11.6 上游无 igb_uio（DPDK 21.05 移除），且 FreeBSD 13.1+ CPU_AND/CPU_OR 适配是 F-Stack 独有 |
| `62f1c34df` | 2026-01-16 | secondary 进程 restart 死循环 fix | `dpdk/lib/timer/rte_timer.c` + `rte_timer.h`（新增 `rte_timer_meta_init()`）+ `f-stack/lib/ff_dpdk_if.c:910`（调用点）| **必须重打** — lib/timer 在 24.11.6 上游零行变化；F-Stack 独有需求 |
| `92718178b` | 2026-03-18 | secondary 进程调用 eal_bus_cleanup() 守护 | `dpdk/lib/eal/linux/eal.c`（rte_eal_cleanup 内 `eal_bus_cleanup()` 调用前加 `if (rte_eal_process_type() == RTE_PROC_PRIMARY)` 守护）| **必须重打** — 24.11.6 stable 未含等效 fix；上游真正 fix 在 25.07 commit `4bc53f8f0d64`，未 backport 到 24.11.6 |

### 5.2 F-Stack 不引用的新 lib

`lib/argparse/` + `lib/ptr_compress/` 在 F-Stack 0 引用（实测 grep `rte_argparse|rte_ptr_compress|argparse\.h|ptr_compress\.h` 在 `f-stack/lib/` 与 `f-stack/example/` 下均 0 命中）。

---

## 6. 术语表（Glossary）

| 术语 | 含义 |
|---|---|
| **DPDK** | Data Plane Development Kit；Intel 开源的用户态网络驱动框架 |
| **DPDK LTS** | Long-Term Support 分支；每 12 个月发布，stable 维护 ~2 年 |
| **`f-stack/dpdk/`** | F-Stack 仓库内嵌的 DPDK 镜像（当前 23.11.5）|
| **`dpdk-stable-23.11.5/24.11.6`** | DPDK 官方 stable 分支的 release tarball / git checkout |
| **VERSION / ABI_VERSION** | DPDK 顶层两个版本文件；前者是用户可见版本，后者是 SONAME 编号（24.0 = 23.x 兼容族；25.0 = 24.11+ 兼容族）|
| **rte 层** | DPDK 公开 API 名空间（lib/<X>/rte_*.h）；F-Stack 通过 rte_* 与 DPDK 交互 |
| **整树替换** | `cp -a /data/workspace/dpdk-stable-24.11.6/* f-stack/dpdk/` 一次性把 24.11.6 上游树替换 23.11.5；适合 LTS-to-LTS 升级 |
| **3 patch 重打** | 把 F-Stack 历史 commit `5f3768c63 + 62f1c34df + 92718178b` 中的修改重新应用到 24.11.6 树上 |
| **Primary / Secondary process** | DPDK 多进程模式；primary 持有 NIC，secondary 通过共享 hugepage 与之通信（F-Stack 的 nginx 多 worker、`tools/sbin/ipfw` 等都是 secondary）|
| **EAL** | Environment Abstraction Layer；DPDK 启动 / lcore / hugepage / 设备扫描的核心子系统 |
| **`rte_timer_meta_init()`** | F-Stack 在 lib/timer/ 中新增的内部函数（commit `62f1c34df`）；声明 "For f-stack internal use only"，不导出 ABI |
| **`eal_bus_cleanup()` PRIMARY 守护** | F-Stack commit `92718178b` 在 `rte_eal_cleanup()` 内对 `eal_bus_cleanup()` 调用加 `if (rte_eal_process_type() == RTE_PROC_PRIMARY)` 包裹，避免 secondary 进程退出时去 reset 共享设备 |
| **`igb_uio`** | Intel 1Gb UIO kernel module；DPDK 21.05 已从 upstream 移除，F-Stack 沿用 ≤20.11 的版本作为 vfio-pci 的备选 |
| **rte_ip.h 陷阱** | 24.11 把 `rte_ip.h` 内容（21.6 KB）拆分到 `rte_ip4.h` + `rte_ip6.h`，仅保留 210B stub include；F-Stack 包含 `<rte_ip.h>` 仍能编译，但若依赖具体 IPv4/IPv6 结构需要补 include |
| **argparse / ptr_compress** | DPDK 24.07 新增的两个 opt-in lib（命令行参数解析 / 32-16 位指针压缩）；F-Stack 0 引用 |
| **phase-5b 方法学** | F-Stack 既有性能基线方法学（`tools/sbin/p5b_perf_matrix.sh` + curl-bench + 3 trials + 跨配置 delta + ssh round-trip ~6 ms 上限说明）|

---

## 7. 4 项核心决策（已落定，由 plan.md 多轮 q&a 确认）

| # | 决策 | 决定 | 来源 |
|---|---|---|---|
| 1 | Agent team 拓扑 | Leader + 5 子 agent | plan.md §2 |
| 2 | DPDK 替换策略 | 整树替换（备份 + cp -a + 3 patch 重打）| plan.md §4，DP-A2 |
| 3 | 测试矩阵组织 | 单 spec doc `06-test-and-acceptance-spec.md` | plan.md §0.2，q3=A |
| 4 | spec 文档体系规模 | 7 篇精简（合并 02+03 + 合并 04+05）| plan.md §0.2，q4=B |
| 5 | 3 patch 重打 commit 形态 | 合并到一个 `port:` commit，独立于 `replace:` commit | plan.md §4.4，DP-A8 |

---

## 8. 阅读顺序建议

| 角色 | 顺序 |
|---|---|
| 项目经理 / 架构 reviewer | 00 → 01 → 06 → 99 |
| 实施工程师 | 00 → 02 → 04 → 06 |
| 后续 AI 代理（拾取阶段二任务） | 04 → 02 → 06 |

---

## 9. 文档元信息

- **作者**：Leader（主对话内执行）
- **协作输入**：dpdk-23-patch-scout / dpdk-24-analyzer / diff-comparator 三路并行调研（已完成）
- **审查**：gate-keeper（待 Phase 4 出具 `99-review-report.md`）
- **校验**：所有数字均来自实测命令输出；非实测的推断在术语表与本节注明来源
- **下一步**：阅读 `01-requirements-spec.md` 了解本次升级要解决/不解决的具体问题
