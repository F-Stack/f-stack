# 01 — 升级需求规约（Requirements Spec）

> English version: ../01-requirements-spec.md

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-26）
> 前序：`00-overview-and-glossary.md`

---

## 1. 文档目的

明确"F-Stack 从 FreeBSD 13.0 升级到 15.0"这一项目**要解决的问题、不解决的问题、验收标准、约束**，作为后续所有 Spec 与实施工作的合同性输入。

---

## 2. 用户故事（Top-Level）

> **作为** F-Stack 工程的代码维护者，
> **我希望** F-Stack 跟随 FreeBSD 上游升级到 15.0-RELEASE，
> **以便** 持续吃到上游协议栈的安全修复、性能优化（如 RACK 默认化）、新硬件支持，不至于让 F-Stack 长期停留在 13.0 而越来越远离上游。
>
> **验收**：升级后 `libff.a` 能正常编译、`fstack` 主程序能跑起来 + 通过原有功能用例集；保留 F-Stack 特有的所有改造点（DPDK 集成、IPC 工具、ff_* 胶水、零拷贝 mbuf 扩展）。

---

## 3. 功能性需求（FR）

### FR-1 内核协议栈对齐 15.0 上游
**ID**：FR-1
**描述**：`f-stack/freebsd/` 子树中的所有 freebsd-src 文件（非 F-Stack 改造文件、非元数据），其内容须与 `freebsd-src-releng-15.0/sys/` 对应文件**字节级一致**（或当 F-Stack 有改造时，"基线 = 15.0 上游"而不是"基线 = 13.0 上游"）。
**验收**：
- `diff -rq f-stack/freebsd/<subdir> freebsd-src-releng-15.0/sys/<subdir>` 的差异**只能**是 F-Stack 自家改造点（每一处差异都必须能在 `02-architecture-analysis.md` §1.2/§1.3/§1.4 中找到对应改造类型标签）
- 不允许出现"既不是 F-Stack 改造、也不是 15.0 上游"的"幽灵差异"

### FR-2 用户态工具对齐 15.0 上游
**ID**：FR-2
**描述**：`f-stack/tools/` 中的 12 个 freebsd 原生工具子目录（arp / ifconfig / ipfw / libmemstat / libnetgraph / libutil / libxo / ndp / netstat / ngctl / route / sysctl），其上游基线须切换到 15.0；F-Stack 的 `IPC-replace` 与 `Makefile-fstack` 改造手法须在新基线上重新应用。
**验收**：同 FR-1，但范围是 tools/。

### FR-3 ff_* 胶水文件接口同步升级
**ID**：FR-3
**描述**：`f-stack/lib/` 下 30 个 `ff_*.c` + 14 个 `ff_*.h` 中所有 **引用 FreeBSD kernel 符号或头文件** 的代码，须更新为 15.0 等价接口。
**典型对应点**：
- `ff_kern_intr.c` 与 `kern_intr.c` 的接口对齐
- `ff_subr_epoch.c` 与 `subr_epoch.c` 的接口对齐
- `ff_syscall_wrapper.c` 与 `kern/sys_generic.c` + `uipc_syscalls.c` 中 `sendit/recvit` 外部可见声明对齐
- `ff_veth.c` 与 `if_t` 不透明化（FR-1 中 §P0 KBI 破坏 #3）后的访问函数对齐
- `ff_route.c` 与新的 rib/nexthop 结构对齐
- `ff_glue.c` 与 `protosw` 合并 `pr_usrreqs` 后的新签名对齐
**验收**：
- `f-stack/lib/Makefile` 在 15.0 基线上完整链接通过（FR-5 验收条件覆盖）
- 所有 `#include <sys/...>` 在 15.0 头文件下不报路径找不到 / 符号未定义

### FR-4 mips 架构清理
**ID**：FR-4
**描述**：因 15.0 整体移除 mips 架构，`f-stack/freebsd/mips/` 整子目录须从 F-Stack 工程中删除；所有 `Makefile / mk` 中 `mips`-相关条件分支须清理。
**验收**：
- `find f-stack/freebsd/mips -type f` 返回空
- `grep -rE '\bmips\b' f-stack/freebsd/conf f-stack/lib/Makefile` 只剩注释或无命中

### FR-5 编译验收
**ID**：FR-5
**描述**：在升级完成的代码上，`make` 与 `make install`（按 F-Stack 现有 build 流程）须 **0 错误、0 新增 warning**（相对 13.0 baseline 的 warning 集合）。
**验收**：
- `libff.a` 生成成功
- 12 个 tools 二进制全部生成（ff_arp / ff_ifconfig / ff_ipfw / ff_ndp / ff_netstat / ff_ngctl / ff_route / ff_sysctl 等）
- 3 个 f-stack 自带工具（knictl / traffic / top）维持原状（不属于本次 freebsd 部分升级，但不能因 freebsd 升级被打挂）
- 任何 warning 增量须在 `99-review-report.md` 中显式说明并标 P2/P3

### FR-6 运行时验收
**ID**：FR-6
**描述**：升级后的 `fstack` 主程序 + 配套 tools 须能完成 F-Stack 现有的基本网络功能用例（详见 `06-test-and-acceptance-spec.md`）：
- 单 lcore 启动、网卡绑定、IP 配置
- TCP echo 服务收发
- UDP echo 服务收发
- ifconfig / netstat / ipfw / route 子命令查询与配置
**验收**：详见 `06-test-and-acceptance-spec.md` §3 的 9 个用例。

### FR-7 保留 F-Stack 特有扩展
**ID**：FR-7
**描述**：以下 F-Stack 特有的"非标"扩展须在升级后**完整保留**，不能被"对齐上游"误删：
- `FSTACK_ZC_SEND` 零拷贝 mbuf 发送路径（在 `uipc_mbuf.c` `m_uiotombuf`）
- RSS 端口范围扩展（在 `in_pcb.c`）
- TCP RACK/BBR 的 F-Stack 改 module name（防与上游冲突）
- ff_ipc.c/ff_ipc.h 用户态工具 IPC 桥
**验收**：升级后这些代码段仍然存在；用 `grep -rE 'FSTACK_ZC_SEND|ff_ipc'` 命中数不少于升级前

---

## 4. 非功能性需求（NFR）

### NFR-1 性能不退化
**描述**：升级后 F-Stack 在相同硬件 / 相同负载下的吞吐 / 延迟指标，相对升级前**不退化 > 5%**（衡量基线由现有 benchmark 决定，详见 `06-test-and-acceptance-spec.md` §5）。
**说明**：升级带来的性能**提升**（如 RACK 默认化的吞吐提升）作为额外收益记录。

### NFR-2 文档可执行性
**描述**：本 Spec 系列产出的 7 份文档须能被后续 AI 代理直接拾取并执行实施任务。
**验收**：
- 每个 spec 文档的小节都有"路径"、"实测命令"、"期望产物"
- `04-diff-and-port-strategy.md` 中的 port 任务列表可被 c-precision-surgery skill 直接消化
- `05-implementation-plan.md` 中每个里程碑的任务清单可被 spec-driven skill 直接拾取

### NFR-3 风险全覆盖
**描述**：13→14 + 14→15 的所有重大变更（架构级 / 协议栈级 / ABI 级 / 构建级），在 `03-freebsd-15-changes.md` 中至少有一条记录。
**验收**：reviewer 在 `99-review-report.md` 中按 P0-P3 列出全量 → 与本 spec FR/NFR 交叉，0 漏项。

### NFR-4 可回滚
**描述**：升级实施须保留可回滚到 13.0 基线的能力（git 分支或工作区双备份）。
**验收**：实施方案中含"回滚命令清单"（详见 `05-implementation-plan.md` §6）。

### NFR-5 向后兼容（向后不再 13.0）
**描述**：F-Stack 升级到 15.0 后，**不**承诺再支持 13.0 基线。在升级里程碑 M5 完成后，13.0 基线相关代码即为"历史代码"。
**说明**：这是显式不兼容声明，避免维护双版本的开销。

---

## 5. 约束（Constraints）

### C-1 不引入 15.0 新增能力（"对齐"≠"扩能"）
**描述**：以下 15.0 新增能力即使在 sys/ 子树中**有源文件**，本次升级也**不**把它们引入 `f-stack/freebsd/`：
- `sys/netlink/`（Linux netlink 兼容子系统，10 个 .c）
- 抗量子加密（ML-KEM 等）
- inotify（syscall 593/594）
- timerfd（syscall 585/586/587）
- kqueuex（syscall 583）
- membarrier（syscall 584）
**说明**：保留为"未来增强建议"，但本次实施不动。
**对应决策点**：DP-2（详见 `plan.md` §4.2 与 `05-implementation-plan.md` §决策点表）

### C-2 不动 LD_PRELOAD ring IPC 部分
**描述**：`f-stack/adapter/syscall/` 由 `docs/ld_preload_ring_spec/` 独立工作流覆盖，本次升级不动它。
**例外**：`f-stack/lib/ff_syscall_wrapper.c` 是交集点（同时被 freebsd 升级和 ld_preload 影响），由 FR-3 覆盖。

### C-3 不变更 DPDK 依赖
**描述**：DPDK 版本保持现有 LTS 不动；如 FreeBSD 15.0 升级需要更新 DPDK，作为 P2 风险记录，但不在本次范围内。

### C-4 不动 Git
**描述**：本 Spec 系列与后续实施均**不**做 `git add / commit / push`。所有产物仅写到工作区。

### C-5 文档语言：中文
**描述**：本系列首版仅中文；英文版待中文人工审计后再考虑。

### C-6 编译器门槛
**描述**：宿主机编译器须 ≥ **GCC 9 / clang 12**（来自 Analyzer-15 调研：FreeBSD 14.0 已要求 GCC 9；15.0 内核已用 C11 `_Atomic`/`atomic_load_explicit`）。

---

## 6. 验收标准矩阵

| 类别 | 标准 | 量化 | 文档 |
|---|---|---|---|
| 代码 | FR-1 freebsd/ 对齐 | diff -rq 仅含改造点 | `04-diff-and-port-strategy.md` |
| 代码 | FR-2 tools/ 对齐 | diff -rq 仅含改造点 | `04-diff-and-port-strategy.md` |
| 代码 | FR-3 ff_* 接口同步 | 编译 0 错误 | `02-architecture-analysis.md` §3 + `04` §3 |
| 代码 | FR-4 mips 清理 | find 返回空 | `05-implementation-plan.md` M1 |
| 构建 | FR-5 编译验收 | 0 错误、0 新增 warning | `06-test-and-acceptance-spec.md` §2 |
| 运行 | FR-6 运行时验收 | 9 个用例全过 | `06-test-and-acceptance-spec.md` §3 |
| 代码 | FR-7 保留扩展 | grep 命中数 ≥ 升级前 | `04-diff-and-port-strategy.md` §5 |
| 性能 | NFR-1 不退化 > 5% | benchmark 对比 | `06-test-and-acceptance-spec.md` §5 |
| 文档 | NFR-2 可执行性 | spec 含路径/命令/产物 | `99-review-report.md` |
| 文档 | NFR-3 风险全覆盖 | 0 漏项 | `99-review-report.md` |
| 实施 | NFR-4 可回滚 | 回滚清单存在 | `05-implementation-plan.md` §6 |

---

## 7. 关键决策点（Decision Points 摘要，正式版在 05）

| DP | 决策内容 | 默认倾向 | 影响范围 |
|---|---|---|---|
| DP-1 | 是否删除 `f-stack/freebsd/mips/` | **删除** | FR-4 |
| DP-2 | 是否把 15.0 的 sys/netlink/ 引入 f-stack/freebsd/ | **暂不引入** | C-1 |
| DP-3 | 直接全量同步 vs 渐进式 | **渐进式 M1-M5** | `05-implementation-plan.md` |
| DP-4 | f-stack/lib/ff_*.c 是否与 f-stack/freebsd 同步升级 | **必须同步** | FR-3 |
| DP-5 | f-stack/tools/ 升级是否独立里程碑 | **独立 M5** | `05-implementation-plan.md` |

---

## 8. 假设（Assumptions）

| ID | 假设 | 失效后果 |
|---|---|---|
| A-1 | `freebsd-src-releng-15.0/` 已是 15.0-RELEASE-p9 稳定基线 | 失效则需重新拷贝 15.0 备份（Phase 1.4 重做） |
| A-2 | F-Stack 现有 build 流程在 13.0 基线上 0 错误 | 失效则不能区分"升级引入的错误"与"既存错误" |
| A-3 | DPDK LTS 版本与 FreeBSD 15.0 兼容 | 失效则需评估 DPDK 升级 |
| A-4 | F-Stack 不引入 SMP / VNET 新调用边界 | 失效则需扩 FR-3 范围 |

---

## 9. 风险一览（详见 `03-freebsd-15-changes.md`）

> 此处仅列 ID 与一句话，完整论证在 03。

| ID | 风险 | 优先级 |
|---|---|---|
| R-001 | 15.0 移除 mips 架构 | P2 |
| R-002 | 15.0 新增 netlink 子系统 | P1（DP-2 暂不引入，仍记风险） |
| R-003 | 14→15 mbuf 结构调整 | **P0** |
| R-004 | 14→15 TCP RACK 默认化 + tcp_stacks 改动 | P1 |
| R-005 | 15.0 base 转 pkgbase | P3 |
| R-006 | 15.0 wlan / kernel TLS API 变化 | P2 |
| R-007 | 14→15 ABI break | P1 |
| R-008 | 13.0/f-stack-lib 与 f-stack 现状漂移（102 处含噪声） | P2 |
| R-009 | clang/llvm 14→15 提升 | P2 |
| R-010 | 15.0 inotify / 抗量子加密 | P3 (out of scope) |
| **R-011** | **15.0 `pr_usrreqs` 合并入 `protosw`** | **P0** |
| **R-012** | **15.0 `inpcb` epoch → SMR 改造** | **P0** |
| **R-013** | **15.0 `ifnet` 不透明化为 `if_t`** | **P0** |

> R-011/R-012/R-013 是 Analyzer-15 实测发现的、之前 plan.md §4.1 未列出的 P0 风险，由本 spec 补足。

---

## 10. 输入物（升级依赖的物料，已全部就绪）

| 物料 | 路径 | 状态 |
|---|---|---|
| 13.0 上游源 | `/data/workspace/freebsd-src-releng-13.0/` | 已存在 |
| 15.0 上游源 | `/data/workspace/freebsd-src-releng-15.0/` | 已存在 |
| 13.0 备份 | `/data/workspace/freebsd-src-releng-13.0/f-stack-lib/` | 已存在 |
| 15.0 备份 | `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/` | Phase 1.4 已创建 |
| F-Stack 现状 | `/data/workspace/f-stack/` | 已存在 |
| 既有架构文档 | `/data/workspace/f-stack/docs/01-LAYER1-ARCHITECTURE.md` 等 | 已存在 |

---

## 11. 输出物（本 Spec 阶段最终交付，9 份全部已交付）

> 状态截至 2026-05-28：全部 9 份已交付（2026-05-26 完成 Phase 1-5），并在 2026-05-28 追加独立审计 v0.2（98-independent-audit-report.md）及 6 项必修修订。详见 `99-review-report.md` §1（体量表）与 §12（修订记录）。

| # | 文件 | 状态 |
|---|---|---|
| 1 | `plan.md` | 已交付（2026-05-26；§1.3/§8 状态 2026-05-28 已订正） |
| 2 | `00-overview-and-glossary.md` | 已交付（2026-05-26；§5 syscall/if_t 2026-05-28 已订正） |
| 3 | **`01-requirements-spec.md`** | **本文档**（2026-05-26 交付；§11 状态 2026-05-28 已订正） |
| 4 | `02-architecture-analysis.md` | 已交付（2026-05-26） |
| 5 | `03-freebsd-15-changes.md` | 已交付（2026-05-26；§1/§2.4/§3.3 2026-05-28 已订正） |
| 6 | `04-diff-and-port-strategy.md` | 已交付（2026-05-26；§1/§2 2026-05-28 已重写为实测版本） |
| 7 | `05-implementation-plan.md` | 已交付（2026-05-26） |
| 8 | `06-test-and-acceptance-spec.md` | 已交付（2026-05-26；§4.2 if_t 2026-05-28 已订正） |
| 9 | `99-review-report.md` | 已交付（2026-05-26；§7/§10/§12 2026-05-28 已扩展） |
| 10 | `98-independent-audit-report.md` | 独立审计 v0.2（2026-05-26 19:45 出报告，2026-05-28 完成 6 项必修修订） |
