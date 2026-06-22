# 00 — 项目概览与术语表

> English version: ../00-overview-and-glossary.md

> 文档语言：中文（首版）
> 系列文档根目录：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-26）

---

## 1. 项目一句话定义

把 **F-Stack** 工程当前依附的 **FreeBSD 13.0-RELEASE** 内核协议栈与配套用户态工具集，升级到 **FreeBSD 15.0-RELEASE**，并产出一套可被工程团队与后续 AI 代理直接执行的中文 Spec 文档集。

> 本 Spec 阶段只产文档，不动代码；真正的代码迁移由 `05-implementation-plan.md` 定义的后续阶段执行。

---

## 2. 项目背景

F-Stack 是把 FreeBSD 内核协议栈剥离出来跑在 DPDK 用户态的工程：

- **思路**：把 FreeBSD `sys/` 子集（kern / net / netinet / netinet6 / netipsec / netgraph / vm / libkern / opencrypto / ...）抽出来，用一组胶水文件（`ff_*.c`）替换掉与 host 内核紧耦合的部分（VFS / 进程 / 信号 / kvm / AIO / RACCT / kpilite / unmapped mbuf / extpg / SWI taskqueue 等），再用 DPDK 提供 NIC I/O 与 lcore 多线程，让协议栈作为单进程库（`libff`）运行。
- **现状**：F-Stack 当前对齐的 FreeBSD 上游版本是 **13.0-RELEASE-p2**（`/data/workspace/freebsd-src-releng-13.0/sys/conf/newvers.sh` 实测）。
- **驱动力**：FreeBSD 15.0-RELEASE 已于 2025 年正式发布（`REVISION=15.0 BRANCH=RELEASE-p9`），中间跨过 14.0/14.1/14.2/14.3/14.4 共 6 个版本。两版之间发生了多处 P0 级 KBI/KPI 破坏（pr_usrreqs 合并 / inpcb 转 SMR / if_t 不透明化 / mbuf 字段调整 / netlink 新增 / mips 移除 / RACK 默认化），同时 clang/llvm 工具链从 11.x 升到 19.x。继续停在 13.0 会越来越远离上游安全/性能/驱动支持。

---

## 3. 范围边界

### 3.1 IN-SCOPE（本 Spec 系列覆盖）

| 范围 | 实测规模 |
|---|---|
| `f-stack/freebsd/`（kernel 协议栈裁剪子集） | 25 个顶层子目录，与 13.0 备份相比 **102 处文件差异**，其中实质改造 ~50 个文件 |
| `f-stack/tools/`（用户态工具 F-Stack 化） | 22 个顶层子目录，与 13.0 备份相比 **163 处文件差异** |
| `f-stack/lib/` 中的 `ff_*.c` 与 `ff_*.h`（胶水文件） | **30 个 `.c` + 14 个 `.h` = 44 个文件**（由 `f-stack/lib/Makefile` 的 `FF_SRCS+FF_HOST_SRCS` 实测划定） |

### 3.2 OUT-OF-SCOPE（本 Spec 系列**不**覆盖）

| 范围 | 不覆盖原因 |
|---|---|
| 实际代码迁移与编译验证 | 仅 Spec 阶段；后续阶段单独立项执行 |
| 性能 benchmark / 压测 | 不构建 binary，不跑测试 |
| Git 提交 / push | 仅写工作区文件 |
| 英文版 Spec | 待中文版人工审计后再考虑 |
| FreeBSD 15.0 新增能力的"扩能" port（如 netlink port、ML-KEM 抗量子加密、inotify、抗量子 TLS） | 本次只做"对齐"不做"扩能"；新能力仅列入"未来增强建议" |
| F-Stack `adapter/syscall/`（LD_PRELOAD ring IPC 部分） | 与 freebsd kernel 升级无直接关系，由独立 spec 系列 `docs/ld_preload_ring_spec/` 覆盖 |

---

## 4. 三个源码根目录（实测）

| 路径 | 角色 | 版本 |
|---|---|---|
| `/data/workspace/freebsd-src-releng-13.0/` | 社区版 FreeBSD 13.0 完整源 | `REVISION=13.0 BRANCH=RELEASE-p2` |
| `/data/workspace/freebsd-src-releng-15.0/` | 社区版 FreeBSD 15.0 完整源 | `REVISION=15.0 BRANCH=RELEASE-p9` |
| `/data/workspace/f-stack/` | F-Stack 工程根 | 基于 freebsd-13.0 改造 |

### 4.1 13.0 原始备份（已存在，只读基线）

`/data/workspace/freebsd-src-releng-13.0/f-stack-lib/`
- `f-stack-lib/freebsd/` — 25 子目录，对应 F-Stack `freebsd/` 顶层
- `f-stack-lib/tools/` — 22 子目录，对应 F-Stack `tools/` 顶层

### 4.2 15.0 原始备份（Phase 1.4 已创建）

`/data/workspace/freebsd-src-releng-15.0/f-stack-lib/`
- `f-stack-lib/freebsd/` — 24 子目录 + Makefile（23 个 freebsd 原生 + 新增 netlink，缺 mips）
- `f-stack-lib/tools/` — 22 子目录（12 个 freebsd 原生 + 3 个 f-stack 自带工具占位 + 2 个 f-stack-lib 自带辅助目录 + 5 个辅助文件）
- `f-stack-lib/INVENTORY.md` — 完整清单

---

## 5. 术语表（Glossary）

| 术语 | 中文 | 解释 |
|---|---|---|
| **F-Stack** | F-Stack | 腾讯开源、把 FreeBSD 协议栈跑在 DPDK 用户态的高性能网络框架 |
| **`f-stack-lib/`** | 13.0/15.0 原始备份 | F-Stack 启动时拷贝的、未经修改的 freebsd-src 子集，作为 diff 与升级的基线 |
| **`ff_*.c` / `ff_*.h`** | F-Stack 胶水文件 | F-Stack 自己实现的、替换 host 内核功能的 wrapper（共 44 个） |
| **`FSTACK-stub`** | F-Stack 短路 stub | 改造手法：`#ifndef FSTACK` 包住函数体短路到空实现 |
| **`FSTACK-altimpl`** | F-Stack 备选实现 | 改造手法：`#ifdef FSTACK ... #else` 走另一份实现 |
| **`IPC-replace`** | IPC 接管 | tools 改造手法：用 `ff_ipc_*` 替换 raw socket / sysctl 与 fstack 实例通信 |
| **`FSTACK_ZC_SEND`** | F-Stack 零拷贝发送 | F-Stack 在 `uipc_mbuf.c` 中新增的 zero-copy 路径宏 |
| **DPDK** | Data Plane Development Kit | Intel 开源的用户态网络驱动框架，F-Stack 的运行基座 |
| **KPI** | Kernel Programming Interface | 内核源码层接口（函数签名、宏） |
| **KBI** | Kernel Binary Interface | 内核二进制层接口（结构体布局、syscall 表） |
| **VNET** | Virtualized Network Stack | FreeBSD 的网络栈虚拟化机制 |
| **SMR** | Safe Memory Reclamation | FreeBSD 14/15 用来替换部分 epoch 场景的安全内存回收机制 |
| **`pr_usrreqs`** | 协议用户请求向量表 | 13.0 时代 socket protocol 接口；15.0 已合并入 `struct protosw` |
| **`if_t`** | ifnet 不透明访问句柄 | 13.0 在 `sys/net/if_var.h` 已有 `typedef struct ifnet * if_t;` 但内核 API 仍以 `struct ifnet *` 暴露；15.0 将该 typedef 上提到 `sys/net/if.h`（仍是 `typedef struct ifnet *if_t`，**不是** `void *`），并把 `if_alloc()` 等内核 API 改用 `if_t`，配套提供 `if_get*/if_set*` 访问函数。"不透明化"是 API 契约层语义：外部代码应通过访问函数操作，不应直接依赖字段布局。详见 `03-freebsd-15-changes.md §3.3` |
| **inpcbgroup** | inpcb 分组哈希 | 13.0 epoch 保护，15.0 改为 SMR |
| **netlink（FreeBSD）** | netlink 兼容子系统 | 15.0 新增（实际 14.0 引入），Linux netlink 兼容层，sys/netlink/ |
| **RACK** | Recent ACKnowledgment | FreeBSD 14/15 默认开启的 TCP 重传算法栈 |
| **mips** | MIPS 架构 | 14.0 整体从 base 移除，影响 F-Stack `freebsd/mips/` 子目录 |
| **`__FreeBSD_version`** | FreeBSD 版本宏 | 13.0 = `1300139`；15.0 = `1500068` |
| **`SYS_MAXSYSCALL`** | 最大 syscall 号 | 13.0 = 580；15.0 = 599（13→15 净新增 22 项 + 删除 3 项；新增代表：`fspacectl`、`kqueuex`、`membarrier`、`timerfd_create/gettime/settime`、`inotify_add_watch_at`、`inotify_rm_watch`、`jail_remove_jd` 等；删除：`gssd_syscall`、`sbrk`、`sstk`。完整清单见 `03-freebsd-15-changes.md` §2.4） |
| **pkgbase** | base 系统包化 | 15.0 可选发布形态，与 F-Stack 无关 |
| **`m_pkthdr` / `m_ext`** | mbuf 头与外存指针 | 14→15 字段调整 |
| **`mb_unmapped_*` / `pcpu_page_alloc`** | unmapped mbuf 路径 | F-Stack 屏蔽的 host VM 依赖 |
| **`kpilite.h`** | KPI 轻量层头 | F-Stack 屏蔽，避免对 host module 体系的依赖 |
| **`libff`** | F-Stack 用户态库 | 由 `ff_*.c` + 链接进来的 freebsd `*_SRCS` 编译成的 .a |
| **`KERN_SRCS` / `NET_SRCS` / `NETINET_SRCS` ...** | F-Stack Makefile 链接清单 | `f-stack/lib/Makefile` 中的源文件列表，决定"哪些 freebsd 源文件真正参与 libff 编译" |
| **里程碑 M1-M5** | M1=基础设施 / M2=kern / M3=网络栈 / M4=边缘子系统 / M5=tools+ff_* | 见 `05-implementation-plan.md` |
| **P0 / P1 / P2 / P3** | 风险/优先级标 | P0 必修阻塞编译/运行；P1 编译可过但语义需验证；P2 非核心路径；P3 信息留档 |

---

## 6. 与 F-Stack 既有文档的关系

| 既有文档 | 本 Spec 系列的复用方式 |
|---|---|
| `docs/01-LAYER1-ARCHITECTURE.md` | 复用源码目录全景（在 `02-architecture-analysis.md`） |
| `docs/F-Stack_Architecture_Layer1_System_Overview.md` | 复用系统层架构图（同上） |
| `docs/F-Stack_Architecture_Layer2_Interface_Specification.md` | 复用接口清单（同上） |
| `docs/KNOWLEDGE_GRAPH_WIKI.md` | 复用依赖关系图（同上） |
| `docs/ld_preload_ring_spec/` | **不复用**：LD_PRELOAD ring IPC 是另一条独立工作流 |
| `adapter/syscall/README.md` | **不直接复用**：但 `ff_syscall_wrapper.c` 是交集点，会在 `02-architecture-analysis.md` §3 点到 |

---

## 7. 8 项核心决策（已落定，由 `plan.md` 多轮 q&a 确认）

| # | 决策项 | 决定 | 落定文档 |
|---|---|---|---|
| 1 | Spec 输出目录 | `f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/` | plan.md §0 |
| 2 | 覆盖范围 | f-stack/freebsd 全 + f-stack/tools 全 + f-stack/lib 的 30 .c + 14 .h | plan.md §1.5 |
| 3 | 风险记录粒度 | 13→14 + 14→15 全量重大变更 | plan.md §4 |
| 4 | 执行方式 | 混合 Agent Team：Leader 主对话 + 3 个 code-explorer 子代理并行 | plan.md §2 |
| 5 | mips/ 处置 | 跳过，不进 15.0 备份；同时 04-diff 阶段计划删除 `f-stack/freebsd/mips/` | INVENTORY.md / plan.md Step 1.4 |
| 6 | netlink/ 处置 | 拷入 15.0 备份；spec DP-2 决定**暂不引入** `f-stack/freebsd/`（仅"对齐"，不做"扩能"） | INVENTORY.md / plan.md §4.2 DP-2 |
| 7 | f-stack 自带工具（knictl/traffic/top）处置 | 从 13.0 备份占位拷贝；升级走单独里程碑 M5 | INVENTORY.md |
| 8 | 拷贝策略 | `cp -a` 保留 mtime / 权限 / 符号链接 | INVENTORY.md |

---

## 8. 阅读顺序建议

| 角色 | 顺序 |
|---|---|
| 项目经理 / 架构 reviewer | 00 → 01 → 05 → 06 → 99 |
| 实施工程师 | 00 → 03 → 04 → 05 → 02 |
| 后续 AI 代理（拾取任务） | 04 → 05 → 02 → 06 |
| 风险审计 | 01 → 03 → 99 |
| **gap 决策（13.0 FSTACK 定制未移植扫描）** | **04 §11**（2026-06 补充；#1/#2 详细方案见 `../../ff_rss_check_opt_spec/zh_cn/` R-E） |

---

## 9. 文档元信息

- **作者**：Agent Team Leader（主对话内执行）
- **协作**：Sub-Agent A/B/C（已通过 code-explorer 子代理完成）
- **审查**：Reviewer（已于 2026-05-26 出 `99-review-report.md`；2026-05-28 增补独立审计 v0.2 `98-independent-audit-report.md` 及 6 项必修修订）
- **校验**：所有数字均来自实测命令输出；非实测的推断在文末"7. 8 项核心决策" 表格中标注来源
- **下一步**：阅读 `01-requirements-spec.md` 了解本次升级要解决/不解决的具体问题
