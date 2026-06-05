# 98 — Independent Audit Report（独立审计报告）

> English version: ../98-independent-audit-report.md

> 审计对象：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/` 下 9 份 Spec 文档，以及 Phase 1.4 产物 `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/INVENTORY.md`
> 审计时间：2026-05-26 19:45
> 审计方式：独立复读文档 + 抽样核验本地源码事实 + 一致性/完整性/可执行性审查
> 审计结论：**有条件通过（Conditional Pass）**。文档结构完整、方向正确，但存在若干 P1 级事实与可执行性问题，建议修订后再作为实施阶段唯一输入。

---

## 1. 审计范围

### 1.1 已审计文件

| # | 文件 |
|---|---|
| 1 | `plan.md` |
| 2 | `00-overview-and-glossary.md` |
| 3 | `01-requirements-spec.md` |
| 4 | `02-architecture-analysis.md` |
| 5 | `03-freebsd-15-changes.md` |
| 6 | `04-diff-and-port-strategy.md` |
| 7 | `05-implementation-plan.md` |
| 8 | `06-test-and-acceptance-spec.md` |
| 9 | `99-review-report.md` |
| 10 | `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/INVENTORY.md` |

### 1.2 抽样核验的源码事实

| 事实项 | 核验路径 | 结论 |
|---|---|---|
| 13.0/15.0 `newvers.sh` 版本 | `freebsd-src-releng-{13.0,15.0}/sys/conf/newvers.sh` | 与文档一致：13.0 `RELEASE-p2`，15.0 `RELEASE-p9` |
| `__FreeBSD_version` | `sys/sys/param.h` | 与文档一致：13.0 `1300139`，15.0 `1500068` |
| 13.0/15.0 syscall 最大号 | `sys/sys/syscall.h` | **文档中 13.0 部分错误**：实际 13.0 `SYS_MAXSYSCALL=580`，不是 574 |
| `protosw` / `pr_usrreqs` | `sys/sys/protosw.h` | 文档方向正确：15.0 已无 `pr_usrreqs` 字段，方法合入 `struct protosw` |
| `if_t` 定义 | `sys/net/if.h` / `sys/net/if_var.h` | **文档局部错误**：15.0 是 `typedef struct ifnet *if_t`，不是 `typedef void *if_t` |
| `inpcb` SMR | `sys/netinet/in_pcb.h` | 文档方向正确：15.0 `inpcb` 明确含 SMR 注释与 `smr_seq_t inp_smr` |
| `ff_*.c` / `ff_*.h` 物理文件数 | `f-stack/lib/` | 与文档一致：30 个 `.c` + 14 个 `.h` |
| `FF_SRCS` / `FF_HOST_SRCS` 变量分解 | `f-stack/lib/Makefile` | **文档局部不准确**：物理总数对，但 Makefile 变量分解/默认与条件项描述不严谨 |

---

## 2. 总体评价

### 2.1 优点

1. **文档体系完整**：从概览、需求、架构、上游变化、diff/port 策略、实施计划到验收规范均已覆盖。
2. **Phase 1.4 物料扎实**：15.0 `f-stack-lib/` 与 `INVENTORY.md` 已经建立，且 mips/netlink/top/knictl/traffic 等边界有明确决策。
3. **关键风险方向正确**：`pr_usrreqs` 合并、`inpcb` SMR、`if_t`/ifnet 访问方式、mbuf、routing/rib/nexthop、mips 移除均被识别。
4. **实施拆分可读性好**：M1-M5 里程碑、T-* 任务、Gate、回滚方案已经形成可执行骨架。
5. **测试验收有雏形**：06 中编译矩阵、9 个 TC、性能基线和 Gate 总表可作为 QA 继续细化的基础。

### 2.2 主要不足

1. **部分关键事实错误**：尤其是 13.0 syscall 最大号、`if_t` 类型定义。
2. **部分统计来源不够硬**：04 中差异统计使用"大小变化启发式"，但 99 中又声明"所有数字均有实测出处"，需要降级为估算或重新跑 `diff -rq`。
3. **Makefile SRCS 清单不全**：04 以"实际链接清单"名义给出，但 `NET_SRCS`/`NETINET_SRCS` 等仍使用"典型/省略号"，不满足后续实施的精确输入要求。
4. **状态字段明显过期**：plan、01、99 中仍保留 Phase 1.4 前或 Phase 5 前的状态，影响文档可信度。
5. **任务数/P0 数不一致**：04、05、99 对 P0 任务与总任务数的口径不同，虽然有解释，但仍不适合作为实施看板直接使用。

---

## 3. P1 级问题（建议实施前必须修订）

### P1-001：13.0 syscall 最大号与新增 syscall 列表错误

| 项 | 内容 |
|---|---|
| 位置 | `00-overview-and-glossary.md` §5；`03-freebsd-15-changes.md` §1、§2.4 |
| 文档现状 | 声称 13.0 `SYS_MAXSYSCALL=574`，最大号 `SYS_sigfastblock=573`；并把 `__realpathat`、`close_range`、`rpctls_syscall`、`__specialfd`、`aio_writev`、`aio_readv` 等列为 15.0 新增 |
| 实测事实 | 13.0 `sys/sys/syscall.h` 中已经有 `SYS___realpathat=574`、`SYS_close_range=575`、`SYS_rpctls_syscall=576`、`SYS___specialfd=577`、`SYS_aio_writev=578`、`SYS_aio_readv=579`，且 `SYS_MAXSYSCALL=580`；15.0 为 `SYS_MAXSYSCALL=599` |
| 影响 | 03 §2.4 的 syscall 增量判断不准确；00 术语表中的 `SYS_MAXSYSCALL` 说明错误；R-010 的范围描述需重算 |
| 建议 | 改为：13.0 `SYS_MAXSYSCALL=580`，15.0 `SYS_MAXSYSCALL=599`，13→15 真正新增区间从 `fspacectl=580` 到 `jail_remove_jd=598`（同时注意 580 是 15 中的 syscall 号，不是 13 的 max） |
| 严重度 | **P1**【已修订 2026-05-28，详见 `99-review-report.md` §12.1】 |

### P1-002：`if_t` 类型定义表述错误

| 项 | 内容 |
|---|---|
| 位置 | `00-overview-and-glossary.md` §5；`03-freebsd-15-changes.md` §3.3；`06-test-and-acceptance-spec.md` §4.2 |
| 文档现状 | 声称 15.0 `typedef void *if_t`，并把 `if_t` 描述为完全 `void *` 不透明句柄 |
| 实测事实 | 15.0 `sys/net/if.h` 中是 `typedef struct ifnet *if_t`；`sys/net/if_var.h` 提供大量 `if_get*` / `if_set*` 访问函数，确实体现了访问方式不透明化，但类型并非 `void *` |
| 影响 | `ff_veth.c` 适配策略会受误导：不是所有类型转换都应按 `void *` 处理，仍需遵守 `struct ifnet *` 语义与内核访问函数约束 |
| 建议 | 统一改为："15.0 将 ifnet 访问方式进一步抽象为 `if_t`（实际 typedef 为 `struct ifnet *`），外部代码应优先通过 `if_get*` / `if_set*` 访问函数操作，不应直接依赖字段布局" |
| 严重度 | **P1**【已修订 2026-05-28，详见 `99-review-report.md` §12.2】 |

### P1-003：04 的 diff 统计可信度不足，且与 99 的"实测"声明冲突

| 项 | 内容 |
|---|---|
| 位置 | `04-diff-and-port-strategy.md` §1；`99-review-report.md` §7 |
| 文档现状 | 04 明确写了"启发式：大小变化即 MOD"，但 99 又声明"所有数字均有实测出处"，并把这些统计作为任务排期依据 |
| 审计判断 | "大小变化启发式"可以作为探索估算，但不能等价于 `diff -rq` 的文件级事实；尤其是大小不变但内容不同会漏报，大小变化但语义无关会误判 |
| 影响 | 04 §1 的 MOD 数、04 §9 的任务规模、05 §3 的排期都可能偏差；如果后续直接按这些数字安排人力，风险较大 |
| 建议 | 实施前增加一个 `04a-verified-diff-stats.md` 或修订 04：用真实 `diff -rq` / checksum 重新生成 DEL/NEW/MOD；当前 04 §1 标注为"估算"而非"实测" |
| 严重度 | **P1**【已修订 2026-05-28，详见 `99-review-report.md` §12.3】 |

### P1-004：`f-stack/lib/Makefile` 的实际链接清单没有全量展开

| 项 | 内容 |
|---|---|
| 位置 | `04-diff-and-port-strategy.md` §2.2-§2.5；`05-implementation-plan.md` M2/M3 任务 |
| 文档现状 | 04 §2 声称是"F-Stack 实际链接清单"，但 `NET_SRCS`、`NETINET_SRCS`、`NETINET6_SRCS`、`LIBKERN_SRCS` 等只写了"典型"并使用 `...` |
| 实测事实 | `f-stack/lib/Makefile` 中 `NET_SRCS` 实际包含 `bpf.c`、`if_bridge.c`、`if_dead.c`、`if_vxlan.c`、`in_fib.c`、`route_tables.c`、`nhop.c`、`nhop_ctl.c` 等多项，04 中未完整列出；`NETINET_SRCS`、`NETINET6_SRCS` 也未全量展开 |
| 影响 | 后续 AI 代理按 04 拾取任务会漏掉实际参与编译的源文件；M3 的"网络栈全量升级"验收缺少精确 checklist |
| 建议 | 从 `f-stack/lib/Makefile` 重新抽取所有 `*_SRCS+=`，按变量完整落表；条件项（`FF_NETGRAPH`、`FF_IPFW`、`FF_IPSEC`、`FF_INET6`、`FF_EXTRA_TCP_STACKS`、`FF_KNI`、`FF_USE_PAGE_ARRAY`）单独列明 |
| 严重度 | **P1**【已修订 2026-05-28，详见 `99-review-report.md` §12.4】 |

### P1-005：外部资料引用缺可复核证据

| 项 | 内容 |
|---|---|
| 位置 | `03-freebsd-15-changes.md` 多处；`plan.md` §6 |
| 文档现状 | 多处引用 FreeBSD Release Notes / clang 版本 / pkgbase / KTLS 等，但没有逐条给 URL、摘录、抓取时间；原计划要求 Analyzer-15 跑 `web_search` / `web_fetch` |
| 审计判断 | 本地源码事实较充分，但外部 release notes 证据链不足；尤其是 14.3/14.4/15.1 时间线、工具链版本、pkgbase 等非本地源码事实，不宜仅靠记忆写入 |
| 影响 | 03 的"外部资料调研"达不到可审计标准；后续人工 review 难以复核来源 |
| 建议 | 增加 `03-appendix-sources.md` 或在 03 每条外部事实后追加 URL + 引文片段 + 抓取日期；无法验证的条目标为"待核验" |
| 严重度 | **P1**【已修订 2026-05-28，详见 `99-review-report.md` §12.6】 |

### P1-006：文档状态过期，当前交付状态与内容不一致

| 项 | 内容 |
|---|---|
| 位置 | `plan.md` §1.3 / §3 / §8；`01-requirements-spec.md` §11；`99-review-report.md` §10 |
| 文档现状 | `plan.md` 仍写 15.0 `f-stack-lib/` 当前不存在、Phase 2-5 未完成、下一步等待确认 Phase 1.4；`01` 仍写 02-06/99 待出；`99` 仍写 Phase 5 待完成 |
| 实际状态 | 目录中 00-06 + 99 均已存在，Phase 1.4 已完成，用户当前要求的是再次独立审计 |
| 影响 | 项目经理/实施代理阅读时会误判当前项目阶段，尤其是 plan.md 作为入口文档时风险较高 |
| 建议 | 增加"当前状态"段或修订所有过期状态：Phase 2/3/4/5 已完成；`plan.md` §1.3 改为"已创建，详见 Step 1.4"；01 §11 改为全量已交付 |
| 严重度 | **P1**【已修订 2026-05-28，详见 `99-review-report.md` §12.5】 |

---

## 4. P2 级问题（建议一并修订）

### P2-001：优先级口径不统一

| 位置 | 问题 |
|---|---|
| `plan.md` §4.1 vs `03` §2.1/§7 | mips 在 plan 中是 P2，在 03 中升为 P0 |
| `03` §3.7 | heading 是 `[P1] kernel TLS API 变化`，表内优先级是 P2 |
| `03` §3.8 | heading 是 `[P1] routing 表结构变更`，表内优先级是 P0 |
| `04` §9 vs `05` §3 vs `99` §4.2 | P0 任务数分别出现 24、18、19 三种口径 |

**建议**：定义两个不同维度：`风险等级` 与 `任务优先级`。mips 作为"上游事实"可 P2，但作为"必须清理任务"可 P0；需在表头写清楚。【已修订 2026-05-28，详见 `99-review-report.md` §12.7】

### P2-002：DP-5 的里程碑描述冲突

| 位置 | 问题 |
|---|---|
| `plan.md` §4.2 DP-5 | 写 tools 升级倾向"独立里程碑 M4" |
| `01` §7 / `05` §1.2 | 写 tools 升级是独立 M5 |

**建议**：统一为 M5，并在 `plan.md` 修订。

### P2-003：`ff_*.c` 变量分解不严谨

| 项 | 内容 |
|---|---|
| 文档现状 | 多处写 `FF_SRCS=21`、`FF_HOST_SRCS=9`、"+2 隐式" |
| 实测情况 | `Makefile` 中默认 `FF_SRCS` 为 17 个；`FF_NETGRAPH` 条件下再加 2 个；`FF_HOST_SRCS` 默认 9 个，`FF_KNI` / `FF_USE_PAGE_ARRAY` / Linux 非 FreeBSD 条件会再加 `ff_dpdk_kni.c` 或 `ff_memory.c`；物理文件数 30 个 `.c` 是正确的 |
| 建议 | 所有文档统一成："物理范围 30 `.c` + 14 `.h`；Makefile 默认/条件编译分解见 02 附表" |

### P2-004：06 中"12 个 tools 二进制"表述不准确

| 位置 | `06-test-and-acceptance-spec.md` §2.2 |
| 问题 | 12 个 freebsd 原生 tools 子目录包含 `libmemstat`、`libnetgraph`、`libutil`、`libxo` 等库目录，不全是二进制；表中列了 `ff_libmemstat` 这种可能并不存在的工具二进制 |
| 建议 | 改成"12 个 tools/lib 目标全部生成：8 个用户态命令 + 4 个库目标 + 3 个 F-Stack 自带工具"，并用实际 Makefile target 名称替换示例 |【已修订 2026-05-28，详见 `99-review-report.md` §12.9】

### P2-005：FR-7 验收命令过粗

| 位置 | `01-requirements-spec.md` FR-7；`04` §5 |
| 问题 | `grep -rE 'FSTACK_ZC_SEND|ff_ipc'` 无法覆盖 RSS 端口范围扩展、TCP RACK/BBR module name 改名等全部特有扩展 |
| 建议 | 为每个扩展定义独立 grep/编译/运行验收项，例如 `tcp_rack_fstack`、`tcp_bbr_fstack`、RSS lport 相关宏/函数、`ff_ipc_*` API 等 |

### P2-006：05 的回滚方案使用大量目录级 `cp -a`，风险较高

| 位置 | `05-implementation-plan.md` §6 |
| 问题 | 不使用 Git 的约束合理，但目录级 `cp -a /data/workspace/f-stack /data/workspace/f-stack-M<N>-done` 会产生大量副本，且容易遗漏权限/软链/磁盘空间问题 |
| 建议 | 至少补充：磁盘容量检查、manifest/checksum、备份目录命名规则、清理策略；如允许，建议用只读 tarball 或 `rsync -a --delete --dry-run` 预演 |

### P2-007：测试用例还停留在模板级，缺少可直接执行命令

| 位置 | `06` §3 |
| 问题 | TC-01..TC-09 只有名称与模板，未指定实际 F-Stack 示例程序、配置文件、网卡绑定命令、预期 stdout 关键字 |
| 建议 | 在 06 增加每个 TC 的"最小配置文件路径 + 命令 + 预期输出"，否则 QA 仍需二次设计测试方案 |【已修订 2026-05-28，详见 `99-review-report.md` §12.10】

---

## 5. P3 级问题（信息项 / 文档整洁度）

| ID | 问题 | 建议 |
|---|---|---|
| P3-001 | `99-review-report.md` 行数与体量未自填，且自身行数无法在表中体现 | 可在最终交付前更新一次体量表 |
| P3-002 | `03` §8 的 14.4/15.1 时间线属于外部事实，当前未给来源 | 加 URL 或标"待核验" |
| P3-003 | `04` §1 中 `amd64`/`arm64`/`x86` 统计的是架构目录子集还是完整目录不明确 | 表头补充统计口径 |
| P3-004 | `plan.md` §6 外部调研清单只列了部分 14.x release notes（缺 14.1/14.2/14.3/14.4 完整 URL） | 补齐或说明只抽样 |
| P3-005 | 术语表中 `RACK` 描述为"默认开启"，但 03 又写"默认 TCP 栈仍是 freebsd default"，语义略冲突 | 改成"RACK 进入 base 并成熟化，是否默认由运行时 knob 决定"更稳妥 |

---

## 6. 修订建议清单（按优先级）

### 6.1 必修修订（建议先做）

1. 修正 13.0 syscall 最大号与 13→15 syscall 增量列表。【已完成 2026-05-28，详见 `99-review-report.md` §12.1】
2. 修正 `if_t` 类型定义，保留"访问方式不透明化"但去掉 `void *` 说法。【已完成 2026-05-28，详见 `99-review-report.md` §12.2】
3. 重新生成真实 `diff -rq` / checksum 的 `04` 统计，或把现有统计全部降级为估算。【已完成 2026-05-28，详见 `99-review-report.md` §12.3】
4. 从 `f-stack/lib/Makefile` 重新抽取全量 `*_SRCS` 表，替换 04 的省略号版本。【已完成 2026-05-28，详见 `99-review-report.md` §12.4】
5. 清理文档状态：plan/01/99 中所有"待完成/下一步等待 Phase 1.4"的过期表述。【已完成 2026-05-28，详见 `99-review-report.md` §12.5】
6. 给 03 外部事实补 URL + 引文 + 抓取日期，或将不可核验条目标为"待核验"。【已完成 2026-05-28，详见 `99-review-report.md` §12.6】

### 6.2 推荐修订

1. 统一 P0/P1/P2/P3 口径，区分风险等级与任务优先级。【已完成 2026-05-28，详见 `99-review-report.md` §12.7】
2. 统一 57/75/18/19/24 等任务数字口径，给一个唯一"实施任务台账"。【已完成 2026-05-28，详见 `99-review-report.md` §12.8】
3. 修正 tools 编译目标描述，明确哪些是命令、哪些是库、哪些是 F-Stack 自带工具。【已完成 2026-05-28，详见 `99-review-report.md` §12.9】
4. 扩充 06 中 TC-01..09 的实际命令与预期输出。【已完成 2026-05-28，详见 `99-review-report.md` §12.10】
5. 把 `99-review-report.md` 改名或新增"自审报告"说明，避免与本独立审计报告混淆。【已完成 2026-05-28，详见 `99-review-report.md` §12.11；保留原文件名，新增 99 §0 文档定位声明】

---

## 7. Go / No-Go 判断

| 维度 | 判断 |
|---|---|
| 作为 Spec 草案 | **GO**：结构完整，核心方向正确 |
| 作为实施阶段唯一输入 | **NO-GO（暂缓）**：需先修复 P1-001 到 P1-006 |
| 作为人工评审材料 | **GO**：问题已足够聚焦，适合进入人工技术评审 |
| 作为 AI agent 自动拾取任务输入 | **Conditional GO**：仅建议先拾取低风险文档修订任务；暂不建议直接拾取 C 代码迁移任务 |

---

## 8. 最终结论

本次独立审计认为：

1. 这套 Spec 文档的**总体架构是成立的**，已覆盖 F-Stack 从 FreeBSD 13.0 升级到 15.0 的主要维度。
2. `pr_usrreqs`、`inpcb/SMR`、`if_t`、mbuf、routing/rib/nexthop、mips 移除等核心风险识别方向正确。
3. 但文档中存在若干**实施前必须修正的事实与口径问题**，尤其是 syscall 增量、`if_t` 定义、diff 统计可信度、Makefile 链接清单不全、状态过期、外部来源证据不足。
4. 建议先完成一轮"审计修订版 v0.2"，再进入真正的 M1 代码实施阶段。

**审计结论：有条件通过（Conditional Pass）；实施前需完成 P1 修订。**
---

## 9. 修订后最终签字（2026-05-28）

| 项 | 内容 |
|---|---|
| 状态 | **✅ 评审通过（APPROVED）—— 条件性通过的所有条件均已满足** |
| §6.1 必修修订（6 项）| 全部完成。详见 `99-review-report.md` §12.1（syscall）/ §12.2（if_t）/ §12.3（04 §1 diff）/ §12.4（04 §2 SRCS）/ §12.5（状态字段）/ §12.6（外部来源） |
| §6.2 推荐修订（5 项）| 全部完成。详见 `99-review-report.md` §12.7（优先级两维度）/ §12.8（任务数台账）/ §12.9（tools 目标）/ §12.10（TC 命令）/ §12.11（99 与 98 角色） |
| 后续发现修订 | R-12/R-13：`15.0/f-stack-lib/tools/compat/include/` 全量重新基线化（详见 99 §12.12） |
| 升级判定 | 本审计 §7 \"作为 Spec 草案 = GO\" 基础上，§6.1 + §6.2 全部 11 项闭合后升级为 **\"无条件通过 / Final Pass\"**。spec 系列冻结为 v0.3，可作为 M1 实施阶段唯一输入基线。 |
| 残留非阻塞项 | 03 §10.2 的 8 条外部 URL 待核验项由 M1 准备阶段补完（不阻塞）；75 任务追踪表（99 §6）由 M1 实施阶段自然填充。 |

**最终结论（修订版 v0.3）**：**✅ 评审通过（APPROVED）。**
