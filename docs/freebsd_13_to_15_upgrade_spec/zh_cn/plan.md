# F-Stack FreeBSD 13.0 → 15.0 升级 Spec 工作计划（Plan）

> 文档语言：中文（首版）。英文版待人工审计完成后再考虑。
> 输出根目录：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 计划版本：v0.1（2026-05-26）
> 工作方式：**Harness 工程化 + Spec 驱动 + 混合 Agent Team**（leader 在主对话规划与汇总，重活通过 `code-explorer` 子代理并行 spawn）

---

## 0. 计划目标

把 F-Stack 当前依附的 FreeBSD 13.0-RELEASE 内核协议栈与用户态工具集，升级到 FreeBSD 15.0-RELEASE，并产出一套**可被工程团队和后续 AI 代理直接执行**的中文 Spec 文档集。本计划只覆盖"**Spec 文档生成**"阶段，不包括真正的代码迁移与编译验证（那是后续阶段）。

### 输出 Deliverables（最终需写入 `freebsd_13_to_15_upgrade_spec/zh_cn/`）

| # | 文件名 | 角色 |
|---|---|---|
| 1 | `plan.md` | **本文档**，工作计划与 agent team 构成（先产出） |
| 2 | `00-overview-and-glossary.md` | 项目概览 + 关键术语表 + 范围边界 |
| 3 | `01-requirements-spec.md` | 升级需求规约：要解决什么问题、不解决什么问题、验收标准 |
| 4 | `02-architecture-analysis.md` | 当前架构分析：F-Stack 对 13.0 的所有改造点全景 |
| 5 | `03-freebsd-15-changes.md` | FreeBSD 13.0 → 14 → 15 关键变更清单（kernel / 网络 / mbuf / ABI / netlink / mips 移除等） |
| 6 | `04-diff-and-port-strategy.md` | 13.0 ↔ 15.0 差异分析 + 移植策略（按 sys 子目录与 ff_* 胶水分组） |
| 7 | `05-implementation-plan.md` | 详细实施计划（里程碑、任务、人 / agent 分配、风险与回滚） |
| 8 | `06-test-and-acceptance-spec.md` | 测试与验收 Spec（编译矩阵、单元测试、回归测试、性能基线） |
| 9 | `99-review-report.md` | reviewer 出具的一致性 / 完整性 / 风险覆盖度审查报告 |

> 该文档结构借鉴 `docs/ld_preload_ring_spec/` 的命名风格，与之并列存放但完全独立。

---

## 1. 工作区现状与边界（实测，非猜测）

### 1.1 三个源码根目录

| 路径 | 角色 | 版本 | 数据来源 |
|---|---|---|---|
| `/data/workspace/freebsd-src-releng-13.0/` | 社区版 FreeBSD 13.0 完整源 | `REVISION=13.0 BRANCH=RELEASE-p2` | 实测 `sys/conf/newvers.sh` |
| `/data/workspace/freebsd-src-releng-15.0/` | 社区版 FreeBSD 15.0 完整源 | `REVISION=15.0 BRANCH=RELEASE-p9` | 实测 `sys/conf/newvers.sh` |
| `/data/workspace/f-stack/` | F-Stack 工程根 | 基于 freebsd-13.0 改造 | 实测 |

### 1.2 13.0 原始备份（已存在）

`/data/workspace/freebsd-src-releng-13.0/f-stack-lib/`（18837 个文件）

- `f-stack-lib/freebsd/` —— F-Stack 启动时从 freebsd-13.0/sys/ 拷贝的"原始未修改副本"（25 个子目录，与 `f-stack/freebsd/` 顶层完全对齐）
- `f-stack-lib/tools/` —— F-Stack 启动时从 freebsd-13.0/(tools+sbin+usr.sbin) 拷贝的"原始未修改副本"（22 个子目录，与 `f-stack/tools/` 顶层完全对齐）

### 1.3 15.0 原始备份（**本计划需要创建**）

`/data/workspace/freebsd-src-releng-15.0/f-stack-lib/`（**当前不存在**）

需要：
1. 创建 `f-stack-lib/freebsd/`，按 `13.0/f-stack-lib/freebsd/` 的子目录清单从 `freebsd-src-releng-15.0/sys/` 拷贝对应内容（处理 15.0 新增的 netlink、移除的 mips）
2. 创建 `f-stack-lib/tools/`，按 `13.0/f-stack-lib/tools/` 的子目录清单从 `freebsd-src-releng-15.0/{tools,sbin,usr.sbin}/` 拷贝对应内容

### 1.4 F-Stack 已改造目录（本次升级的核心对象）

| 目录 | 文件数 | 与 13.0 原始备份的差异 | 角色 |
|---|---|---|---|
| `f-stack/freebsd/` | 全量 sys 子集 | **102 处文件差异**（含 LICENSE / resource.rc 等元数据噪声） | FreeBSD kernel 协议栈的 F-Stack 化裁剪与适配 |
| `f-stack/tools/` | 全量 user-space 工具子集 | **163 处文件差异** | netstat / ifconfig / ipfw / route / arp / ngctl 等的 F-Stack 化（走 IPC 与 fstack 实例通信） |
| `f-stack/lib/` | 466 个文件 | 不来源于 freebsd-src，自己的 user-space 库 | f-stack 自身代码 + 编译产物 |

### 1.5 `f-stack/lib/` 内需要纳入升级的范围（**q2 修正后的精确边界**）

由 `f-stack/lib/Makefile` 实测：

- `FF_SRCS+=` 列入的 **21 个 `ff_*.c`**（链接进 f-stack kernel 部分）：`ff_compat.c / ff_glue.c / ff_freebsd_init.c / ff_init_main.c / ff_kern_condvar.c / ff_kern_environment.c / ff_kern_intr.c / ff_kern_subr.c / ff_kern_synch.c / ff_kern_timeout.c / ff_subr_epoch.c / ff_lock.c / ff_syscall_wrapper.c / ff_subr_prf.c / ff_vfs_ops.c / ff_veth.c / ff_route.c / ff_ng_base.c / ff_ngctl.c`（NETGRAPH 条件） + 2 个隐式
- `FF_HOST_SRCS+=` 列入的 **9 个 `ff_*.c`**（user-space host 侧）：`ff_host_interface.c / ff_thread.c / ff_config.c / ff_ini_parser.c / ff_dpdk_if.c / ff_dpdk_pcap.c / ff_epoll.c / ff_log.c / ff_init.c`（+ `ff_dpdk_kni.c / ff_memory.c` 条件编译）
- **`ff_*.h` 共 14 个**：`ff_api.h / ff_config.h / ff_dpdk_if.h / ff_dpdk_kni.h / ff_dpdk_pcap.h / ff_epoll.h / ff_errno.h / ff_event.h / ff_host_interface.h / ff_ini_parser.h / ff_log.h / ff_memory.h / ff_msg.h / ff_veth.h`
- **总计：30 个 `ff_*.c` + 14 个 `ff_*.h` = 44 个文件**（实测 `ls ff_*.{c,h}` 数量一致）

> 这些是 F-Stack 自己写的胶水代码，它们引用 FreeBSD kernel 头与符号（`#include <sys/...>`、`#include <net/...>`、`#include <netinet/...>` 等）。当 kernel 13→15 升级时，这些胶水文件需要相应跟着改 —— 它们不能从社区代码"拷贝过来"，因为社区版没有 `ff_*.c`，但**它们里面的接口调用要从社区版 15.0 的新接口里"移植 + 适配"过来**（这是 q2 用户原始描述里的关键语义：*"f-stack/lib 目录下的 ff_\*.c ff_\*.h 等部分代码和接口需要从社区版本代码中移植到本目录下，也需要同时升级"*）。

### 1.6 13.0 ↔ 15.0 sys 顶层差异（实测）

- **删除**：`sys/freebsd/`（13.0 有的 sys 子目录，与 f-stack/freebsd 同名但**无关**） / `sys/mips/`（mips 架构在 15.0 整体移除）
- **新增**：`sys/netlink/`（15.0 引入 Linux netlink 兼容层，路由/链路管理新接口） / `README.md`

---

## 2. Agent Team 构成（混合模式）

```
                       ┌──────────────────────────────────────┐
                       │       Leader（主对话内执行）           │
                       │  - 总体编排、Spec 写作、质量门         │
                       │  - 持有全局上下文与决策权              │
                       └────────────┬─────────────────────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  │                 │                 │
                  ▼                 ▼                 ▼
        ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
        │ Sub-Agent A:    │ │ Sub-Agent B:    │ │ Sub-Agent C:    │
        │ Analyzer-13     │ │ Analyzer-15     │ │ Diff-Comparator │
        │ (code-explorer) │ │ (code-explorer) │ │ (code-explorer) │
        │                 │ │                 │ │                 │
        │ 调研 f-stack 对 │ │ 调研 15.0 关键  │ │ 13↔15 sys/tools │
        │ 13.0 的所有改造 │ │ 变更与新增接口  │ │ 文件级差异聚合  │
        └─────────────────┘ └─────────────────┘ └─────────────────┘
                                    │
                                    ▼
                       ┌──────────────────────────────────────┐
                       │  Spec-Writer（主对话内 Leader 兼任） │
                       │  把三路结果整合为 7 份 Spec 文档      │
                       └────────────┬─────────────────────────┘
                                    │
                                    ▼
                       ┌──────────────────────────────────────┐
                       │  Reviewer（主对话内 Leader 兼任）    │
                       │  对 7 份 spec 做一致性/完整性/风险审 │
                       │  覆盖度审查，写 99-review-report.md  │
                       └──────────────────────────────────────┘
```

### 2.1 Leader（主对话内执行）

- **职责**：总体编排、节奏控制、子代理任务分派与结果验收、Spec 文档撰写、最终质量审查
- **技能**：调用 `task → code-explorer` 子代理、`web_search` / `web_fetch` 拉外网资料、按 `harness-engineering-orchestrator` 的节奏（discovery → analysis → spec → review）推进
- **可用 skill**：
  - `harness-engineering-orchestrator`（节奏与产物结构）
  - `spec-driven`（Specify → Design → Tasks 思路指导 spec 写作）
  - `claw-multi-agent`（子代理并行编排参考）
  - `c-pro` / `c-precision-surgery`（后续真正动 C 代码时使用，当前 Spec 阶段不直接调用）

### 2.2 Sub-Agent A：Analyzer-13（code-explorer 子代理）

- **职责**：彻底盘点 f-stack 对 FreeBSD 13.0 的所有改造点
- **输入**：
  - `/data/workspace/freebsd-src-releng-13.0/f-stack-lib/freebsd/`（原始备份）
  - `/data/workspace/f-stack/freebsd/`（改造后版本）
  - `/data/workspace/freebsd-src-releng-13.0/f-stack-lib/tools/`（原始备份）
  - `/data/workspace/f-stack/tools/`（改造后版本）
  - `/data/workspace/f-stack/lib/Makefile`（VPATH 与 SRCS 清单）
  - `/data/workspace/f-stack/lib/ff_*.c` & `ff_*.h`（44 个文件）
  - `/data/workspace/f-stack/docs/`（已有的 3 层架构文档与知识图谱，作为参考）
- **输出**：分类的改造点清单（按 sys 子目录 / tools 子目录 / ff_* 胶水文件 三组），每条含 文件路径 + 改造类型 + 一句话动机
- **不做**：不写代码、不修改任何文件

### 2.3 Sub-Agent B：Analyzer-15（code-explorer + web 调研）

- **职责**：盘点 FreeBSD 15.0（含 14.0 中间版本）相对 13.0 的关键变更，重点关注影响 F-Stack 的部分
- **输入**：
  - `/data/workspace/freebsd-src-releng-15.0/sys/`（含 `netlink/` 等新增）
  - `freebsd.org` 官方 release notes（13.0R / 14.0R / 14.1R / 14.4R / 15.0R / 15.1R）
  - GitHub `freebsd/freebsd-src` 仓库的 release 标签 commit 与 wiki
  - 技术博客与中文社区资料（FreeBSD 14/15 重大变更汇总）
- **输出**：变更清单，分为：
  - **架构级**：mips 移除 / pkgbase / 抗量子加密 / inotify
  - **协议栈级**：netlink 子系统、TCP RACK 默认、kernel TLS、mbuf 结构变化、wifi 栈
  - **ABI 级**：syscall 表、struct 布局、KPI/KBI 变更
  - **构建级**：clang/llvm 版本要求、Makefile 体系变化
- **不做**：不写代码、不直接修 spec 文档

### 2.4 Sub-Agent C：Diff-Comparator（code-explorer 子代理）

- **职责**：在 sys 子目录与 tools 子目录粒度上，**实测**社区 13.0 vs 社区 15.0 的差异规模与热点
- **输入**：
  - `/data/workspace/freebsd-src-releng-13.0/sys/{kern,net,netinet,netinet6,netipsec,netgraph,netpfil,opencrypto,vm,libkern,crypto,amd64,arm64,x86}/`
  - `/data/workspace/freebsd-src-releng-15.0/sys/{kern,net,netinet,netinet6,netipsec,netgraph,netpfil,opencrypto,vm,libkern,crypto,amd64,arm64,x86}/`
  - 同样对比 tools / sbin / usr.sbin 中对应子集（参考 `f-stack-lib/tools/` 清单）
- **输出**：
  - 各子目录的文件级 diff 统计（新增 / 删除 / 修改 文件数）
  - 与 `f-stack/lib/Makefile` 中 `FF_SRCS+KERN_SRCS+NET_SRCS+...` 实际链接的源文件的**交集热点**（即"f-stack 真正会被影响的具体文件清单"）
- **不做**：不做内容级 diff（行级），那是后续真正实施阶段的事

### 2.5 Spec-Writer & Reviewer（主对话内 Leader 兼任）

- **Spec-Writer**：用三个子代理的结果产出 7 份 spec
- **Reviewer**：对 7 份 spec 做：
  - 一致性（同一概念在不同文档中说法一致）
  - 完整性（覆盖范围与 q2 修正后的边界匹配）
  - 风险覆盖度（13→14→15 所有重大变更都有对应章节）
  - 可执行性（implementation-plan 中的任务能否被后续 AI agent 直接拾取）
  - 输出审查报告 `99-review-report.md`

---

## 3. 执行步骤（按时间顺序）

### Phase 1：基础物料就绪（Leader 主对话内执行）

- [x] **Step 1.1**：探查与确认工作区现状（已完成，事实见本文档 §1）
- [x] **Step 1.2**：创建输出目录 `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`（已完成）
- [x] **Step 1.3**：产出本 `plan.md`（当前步骤）
- [x] **Step 1.4**：创建 `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/` 目录，并按 13.0/f-stack-lib/ 的子目录清单从 15.0 源拷贝对应内容（**已完成 2026-05-26**）
  - 子步骤 1.4.1：先计算 13.0/f-stack-lib/freebsd/ 各子目录在 15.0/sys/ 是否存在（mips 已删需特殊处理）
  - 子步骤 1.4.2：先计算 13.0/f-stack-lib/tools/ 各子目录在 15.0/{tools,sbin,usr.sbin,lib,usr.bin}/ 是否存在
  - 子步骤 1.4.3：执行拷贝；处理 mips 缺失（不拷贝，与 15.0 上游事实一致）/ netlink 新增（拷贝，反映 15.0 事实）
  - 子步骤 1.4.4：生成拷贝清单与差异报告 `freebsd-src-releng-15.0/f-stack-lib/INVENTORY.md`

#### Step 1.4 执行结果摘要（2026-05-26 17:30 完成）

| 维度 | 结果 |
|---|---|
| 总文件数 | **25 044**（freebsd 24 593 + tools 451；不含 INVENTORY.md） |
| freebsd/ 顶层项数 | 25（24 子目录 + Makefile） |
| tools/ 顶层项数 | 22（与 13.0 备份顶层完全一致） |
| 拷贝工具 | `cp -a`（保留 mtime / 权限 / 符号链接） |
| 行尾格式 | LF（INVENTORY.md 实测无 CRLF 标记） |

**8 项执行参数全部应用**：
- mips/ → 跳过（与 15.0 上游事实一致）
- netlink/ → 拷贝（来自 15.0/sys/netlink/，39 文件）
- knictl/ + traffic/ + top/ → 从 13.0 占位（f-stack 自实现工具）
- compat/ + sbin/ → 从 13.0 占位（f-stack-lib 自带辅助目录，实测不存在于 freebsd-src 上游）
- lib.mk + Makefile + opts.mk + prog.mk + README.md → 从 13.0 占位（f-stack-lib 自带辅助文件）
- 12 个 freebsd 原生 tools 子目录 → 来自 15.0 的 sbin/ usr.sbin/ usr.bin/ lib/ 之一（详见 INVENTORY.md §2.1）
- 23 个 freebsd 原生 sys 子目录 → 全部来自 15.0/sys/ 同名子目录
- Makefile（freebsd/）→ 从 13.0 占位（f-stack-lib 自带索引）

**特殊发现（已记入 INVENTORY.md）**：
- `libxo/` 13.0 备份 404 文件远超 15.0 上游 14 文件，13.0 端疑似包含完整 contrib 源（含测试样例与 doc），后续 04-diff 阶段需评估是否瘦身
- `contrib/` 14 659 处差异为最大头，需重点排优先级
- `sbin/` 在 13.0 端为空目录（仅 1 个隐藏元数据），保持占位

详见：`/data/workspace/freebsd-src-releng-15.0/f-stack-lib/INVENTORY.md`

### Phase 2：并行调研（spawn 3 个 code-explorer 子代理）

- [ ] **Step 2.1**：spawn Sub-Agent A（Analyzer-13），输出存入 leader 临时内存
- [ ] **Step 2.2**：spawn Sub-Agent B（Analyzer-15），同时跑 + 调用 `web_search` / `web_fetch` 抓 release notes
- [ ] **Step 2.3**：spawn Sub-Agent C（Diff-Comparator），实测 13↔15 sys / tools 子目录差异

> Step 2.1 / 2.2 / 2.3 在同一个回合 batch 内并行 spawn（最大化效率），结果汇聚后再进入 Phase 3。

### Phase 3：产出 7 份 Spec 文档（Leader 兼 Spec-Writer 在主对话内）

按 §0 表中编号顺序产出：

1. `00-overview-and-glossary.md`
2. `01-requirements-spec.md`
3. `02-architecture-analysis.md`（吸收 Analyzer-13 输出）
4. `03-freebsd-15-changes.md`（吸收 Analyzer-15 输出）
5. `04-diff-and-port-strategy.md`（吸收 Diff-Comparator 输出 + Analyzer-13/15 交叉）
6. `05-implementation-plan.md`（含里程碑 M1-M5 的任务拆分）
7. `06-test-and-acceptance-spec.md`

### Phase 4：Reviewer 审查（Leader 兼 Reviewer）

- [ ] **Step 4.1**：reviewer 通读 7 份 spec，按 §2.5 的 4 维标准生成 `99-review-report.md`
- [ ] **Step 4.2**：如 review 发现 P0 / P1 问题，spec-writer 立即返修；P2 问题列入"待后续讨论"

### Phase 5：交付汇报

- [ ] **Step 5.1**：汇总：8 份文档 + 1 份 review report 的清单与字数
- [ ] **Step 5.2**：明确告知**本计划不做 git 提交、不做代码修改**，所有产物仅为 spec 文档

---

## 4. 风险与关键决策点

### 4.1 已识别风险（待 Spec 文档逐一展开）

| ID | 风险 | 优先级 | 来源 |
|---|---|---|---|
| R-001 | 15.0 移除 mips 架构 —— f-stack/freebsd/mips/ 子目录何去何从 | P2 | 实测 sys 顶层 diff |
| R-002 | 15.0 新增 netlink 子系统 —— 是否需要 port 进 f-stack 内核协议栈 | P1 | 实测 sys 顶层 diff |
| R-003 | 14→15 的 mbuf 结构调整 —— 影响 `uipc_mbuf.c`、`kern_mbuf.c`、所有 `if_*.c` | **P0** | 待 Analyzer-15 / web 调研确认 |
| R-004 | 14→15 的 TCP RACK 默认化 —— f-stack/freebsd/netinet/tcp_stacks/ 已含 RACK，需对齐新版接口 | P1 | 待 Analyzer-15 确认 |
| R-005 | 15.0 base 系统转 pkgbase —— 不影响 F-Stack 的内核源裁剪，但影响开发环境 | P3 | release notes 已确认 |
| R-006 | 15.0 移除 wlan 接口的旧接口 / kernel TLS API 变化 | P2 | 待 Analyzer-15 确认 |
| R-007 | 14→15 ABI break —— f-stack 用户态 libff 的 ABI 需要重新审视 | P1 | 待 Analyzer-15 确认 |
| R-008 | 13.0/f-stack-lib 与 f-stack 当前实际改造可能存在"漂移"（102 处差异中含部分元数据噪声） | P2 | 实测 |
| R-009 | clang/llvm 版本要求 14→15 已有提升 —— 影响构建 | P2 | release notes |
| R-010 | 15.0 引入 inotify、抗量子加密 —— 与 f-stack 无直接交集，但需在 spec 中明确"out of scope" | P3 | release notes |

### 4.2 关键决策点（在 Phase 3 写 spec 时必须给出明确选择）

| DP | 决策内容 | 默认倾向 |
|---|---|---|
| DP-1 | 是否在升级中删除 f-stack/freebsd/mips/ | 倾向"删除"（15.0 已无对应上游） |
| DP-2 | 是否把 15.0 的 sys/netlink/ 引入 f-stack/freebsd/ | 倾向"暂不引入"（属于增值能力，本次只做"对齐"不做"扩能"） |
| DP-3 | f-stack/freebsd 是否直接全量同步到 15.0/sys 子集，还是渐进式（先 kern/ 再 net/ 再 netinet/ ...） | 倾向"渐进式"，分 5 个里程碑（详见 05-implementation-plan.md） |
| DP-4 | f-stack/lib/ff_*.c 的升级是否与 f-stack/freebsd 同步完成 | 必须**同步**（否则编译不过） |
| DP-5 | f-stack/tools/ 的升级是否独立里程碑 | 倾向"独立里程碑 M4"（与 kernel 部分解耦） |

---

## 5. 与 F-Stack 既有文档的关系

- 复用：`docs/01-LAYER1-ARCHITECTURE.md` / `docs/F-Stack_Architecture_Layer1_System_Overview.md` 的源码目录全景
- 复用：`docs/F-Stack_Architecture_Layer2_Interface_Specification.md` 的接口清单
- 复用：`docs/KNOWLEDGE_GRAPH_WIKI.md` 的依赖关系图
- **不复用**：`docs/ld_preload_ring_spec/`（LD_PRELOAD ring IPC 专项，与本次完全无关）
- **不影响**：`adapter/syscall/README.md` 等 LD_PRELOAD 相关文档（升级 freebsd kernel 部分不直接涉及 adapter/syscall，但 f-stack/lib/ff_syscall_wrapper.c 是交集点，spec 中需点到）

---

## 6. 外部资料调研清单（待 Analyzer-15 执行）

| 类型 | 来源 | 重点 |
|---|---|---|
| 官方 release notes | https://www.freebsd.org/releases/13.0R/relnotes/ | 13.0 基线 |
| 官方 release notes | https://www.freebsd.org/releases/14.0R/relnotes/ | 14.0 重大变更 |
| 官方 release notes | https://www.freebsd.org/releases/15.0R/relnotes/ | 15.0 重大变更 |
| GitHub | F-Stack/f-stack issues | 社区是否已有 freebsd 14/15 升级讨论 |
| GitHub | F-Stack/f-stack wiki | 升级相关 wiki 页面 |
| GitHub | freebsd/freebsd-src 的 release/15.0.0 tag | 关键 commit |
| 中文博客 / 公众号 | "FreeBSD 15 重大变化"、"FreeBSD 14 网络栈"等关键词 | 中文社区视角 |
| 知乎 / sysgeek / ithome | FreeBSD 15.0 正式发布相关 | 综合 |
| DeepWiki | https://deepwiki.com/F-Stack/f-stack | F-Stack 自动生成的架构 wiki |

---

## 7. 不在本计划范围内的事

| 内容 | 说明 |
|---|---|
| 实际代码迁移 | 仅产出 spec；真正动代码是后续阶段 |
| 编译验证 | 不构建任何 binary |
| 性能测试 | 不跑任何 benchmark |
| Git 提交 | 仅写文件到工作区，不做 add/commit/push（与你过往一致的约束） |
| 英文版 spec | 待人工审计中文版后再考虑 |
| 升级路径外的新能力 | netlink port、抗量子加密等增值能力，**仅列入"未来增强建议"，不在本次实施范围** |

---

## 8. 节奏控制（按 harness-engineering-orchestrator 风格）

- **本计划即 "Plan 阶段产物"**，下一步进入 "Discovery + Analysis"（Phase 1.4 + Phase 2）
- 每个 Phase 结束有一次明确的"Gate"：把本 Phase 产物给用户过目，得到 GO 信号后再进入下一 Phase
- **本回合**：产出 plan.md（已完成本文档）→ 等用户确认 plan → 进入 Phase 1.4

---

> **下一步等待用户确认本 plan.md，然后开始执行 Phase 1.4（创建 15.0/f-stack-lib/ 并拷贝原始备份）。**
