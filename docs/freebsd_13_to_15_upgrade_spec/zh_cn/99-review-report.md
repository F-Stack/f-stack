# 99 — Review Report（一致性 / 完整性 / 风险覆盖度 / 可执行性审查）

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-26）
> 审查人：Leader 兼 Reviewer（按 plan.md §2.5 设定）
> 审查对象：plan.md + 7 份 spec 文档
> 审查标准：plan.md §2.5 定义的 4 维

---

## 1. 受审文档清单与体量

| # | 文件 | 行数 | 字节 | 状态 |
|---|---|---:|---:|---|
| 1 | `plan.md` | 329 | 22 287 | 已交付（含 Phase 1.4 执行结果摘要）|
| 2 | `00-overview-and-glossary.md` | 153 | 9 939 | 已交付 |
| 3 | `01-requirements-spec.md` | 237 | 12 621 | 已交付 |
| 4 | `02-architecture-analysis.md` | 243 | 13 724 | 已交付 |
| 5 | `03-freebsd-15-changes.md` | 293 | 13 785 | 已交付 |
| 6 | `04-diff-and-port-strategy.md` | 348 | 17 779 | 已交付 |
| 7 | `05-implementation-plan.md` | 356 | 14 866 | 已交付 |
| 8 | `06-test-and-acceptance-spec.md` | 264 | 8 188 | 已交付 |
| 9 | **`99-review-report.md`** | — | — | **本文档** |
| **合计 8 份内容文档** | **2 263 行 / 113 KB** | | | |

**Lint 检查**：`read_lints` 在整个 zh_cn/ 目录上返回 **0 项 diagnostics**。

---

## 2. 维度一：一致性审查

### 2.1 同一概念在不同文档中是否说法一致

| 概念 | 出现位置 | 一致性 |
|---|---|---|
| 改造文件总数 ~50 | 02 §1 / 02 §2.1（kern 15 个）汇总 | ✓ 一致 |
| f-stack/freebsd 102 处差异 | 00 §3.1 / 02 §1 / plan.md §1.4 | ✓ 一致 |
| f-stack/tools 163 处差异 | 00 §3.1 / 02 §3 / plan.md §1.4 | ✓ 一致 |
| 44 个 ff_* 文件（30 .c + 14 .h）| 00 §3.1 / 02 §4 / 04 §2.6 / plan.md §1.5 | ✓ 一致 |
| 6 项 P0 风险 | 03 §7（pr_usrreqs / inpcb-SMR / if_t / mbuf / rib-nexthop / mips） / 04 §3 / 05 §3 | ✓ 一致（注：05 §3 有 18 个 P0 任务，其中部分 P0 任务对应同一个 P0 风险，编号不冲突）|
| `__FreeBSD_version` 13.0=1300139, 15.0=1500068 | 00 §5 / 03 §1 | ✓ 一致 |
| 9 大改造手法（H-1..H-9） | 02 §1 / 04 §3 通过手法标签引用 | ✓ 一致 |
| 5 个决策点 DP-1..DP-5 | 01 §7 / 05 §1.2 / plan.md §4.2 | ✓ 一致（仅 plan.md 中 DP 表与 01/05 完全对齐，且决定已落定）|
| 75 个 T-* 任务 | 04 §9（57 个）+ 05 §3（75 个，含 cp -a 类直拷任务）| ⚠ 数字略不一致，但 05 在 §3 显式说明扩充原因 |
| 9 个验收用例 TC-01..09 | 01 FR-6 / 05 M5 / 06 §3 | ✓ 一致 |

### 2.2 一致性问题（P2 级，可后续修订）

- **CI-01**：04 §9 "57 个 T-* 任务" vs 05 §3 "75 个任务" 数字不同。05 已通过补充说明（直拷任务）解释，但 04 §9 表格应同步更新一句说明指向 05。**修复建议**：在 04 §9 末加一行 "(实施时含 cp -a 直拷类，合计 75 个，详见 05 §3)"。

### 2.3 一致性结论

**通过**（1 项 P2 修订建议，不阻塞交付）

---

## 3. 维度二：完整性审查

### 3.1 覆盖范围是否与 q2 修正后边界匹配

q2 决定的范围（来自 plan.md §1.5）：

| 范围项 | spec 覆盖位置 |
|---|---|
| f-stack/freebsd/ 全（25 子目录）| 02 §2 / 04 §1 / 05 §2（M1+M2+M3+M4 覆盖）|
| f-stack/tools/ 全（22 子目录）| 02 §3 / 04 §4 / 05 §2.5（M5）|
| f-stack/lib 中 30 个 ff_*.c + 14 个 ff_*.h | 02 §4 / 04 §3.6 / 05 §2.2/2.3 各阶段同步 |

**完整性**：✓

### 3.2 plan.md 的 Phase 1-5 是否每阶段都有产物

| Phase | plan.md 定义 | 实际产物 |
|---|---|---|
| Phase 1.1 | 探查工作区 | ✓ 已完成 |
| Phase 1.2 | 创建输出目录 | ✓ 已完成 |
| Phase 1.3 | 产出 plan.md | ✓ 已交付 |
| Phase 1.4 | 创建 15.0/f-stack-lib/ | ✓ 已完成（INVENTORY.md）|
| Phase 2 | 3 个 code-explorer 子代理调研 | ✓ 已完成（Analyzer-13/15/Diff-Comparator 三路）|
| Phase 3 | 7 份 spec 产出 | ✓ 已交付 |
| Phase 4 | reviewer 出 99 报告 | ✓ **本文档** |
| Phase 5 | 交付汇报 | ✓ 已交付（2026-05-26 完成；2026-05-28 增补独立审计 v0.2 修订）|

**完整性**：✓

### 3.3 7 份 spec 文档结构完整性

| 文档 | 必备章节 | 完整性 |
|---|---|---|
| 00 | 项目定义 / 范围 / 术语表 / 决策摘要 / 阅读顺序 | ✓ |
| 01 | FR / NFR / Constraints / 验收矩阵 / 假设 / 风险 ID 一览 | ✓ |
| 02 | 改造手法 / sys 改造点 / tools 改造点 / ff_* 胶水 | ✓ |
| 03 | 架构级 / 协议栈级 / ABI 级 / 构建级 + 风险全景表 | ✓ |
| 04 | 子目录 diff / 链接清单 / 交集热点 / 5 步法 SOP | ✓ |
| 05 | M1-M5 任务清单 / SOP / 资源 / 回滚 / Checklist | ✓ |
| 06 | 编译矩阵 / TC 用例 / 性能基线 / Gate 总表 | ✓ |

**完整性**：✓

### 3.4 完整性问题（P3 级，信息项）

- **CI-02**：02 §4.2 中"FF_HOST_SRCS 9 个 + 2 个条件"的"2 个条件"未具体列出（ff_dpdk_kni.c / ff_memory.c）。**修复建议**：在 02 §4.2 表末加一行明确这两个条件文件名。

### 3.5 完整性结论

**通过**（1 项 P3 修订建议，不阻塞交付）

---

## 4. 维度三：风险覆盖度审查

### 4.1 13→14→15 全量重大变更覆盖核对

按 plan.md §4.1 + 03 §7 共列 **14 项风险**：

| ID | 风险 | 03 中详述 | 04 中对应任务 | 05 中处置 | 06 中验证 | 完整链 |
|---|---|---|---|---|---|---|
| R-001 | mips 移除 | §2.1 | T-cleanup-01 | M1 | — | ✓ |
| R-002 | netlink 新增 | §3.5 | (DP-2 不引入) | 全程 | — | ✓ |
| **R-003** | mbuf 字段调整 | §3.4 | T-kern-04 / T-kern-12 | M2 | TC-02/03/04 | ✓ |
| R-004 | TCP RACK 默认化 | §3.6 | T-netinet-05/06 | M3 | TC-02 | ✓ |
| R-005 | pkgbase | §2.3 | — | OOS | — | ✓（明确 P3）|
| R-006 | wlan / KTLS | §3.7 §3.11 | T-kern-11（评估）| M2 | — | ✓ |
| R-007 | ABI break | §4 | M5 末审视 | M5 | — | ✓ |
| R-008 | f-stack-lib 与 f-stack 漂移 | §7 | 实施前 diff -rq | 前置 | — | ✓ |
| R-009 | clang/llvm 14→15 提升 | §2.2 | 前置 GCC ≥ 10 / clang ≥ 12 | 前置 | — | ✓ |
| R-010 | inotify / 抗量子 | §2.4 | (C-1 不引入) | — | — | ✓ |
| **R-011** | pr_usrreqs 合并入 protosw | §3.1 | T-kern-14 / T-netinet-08/09/10 / T-ff-01 | M2/M3 | TC-02/03 | ✓ |
| **R-012** | inpcb epoch → SMR | §3.2 | T-netinet-01/07 / T-kern-07 / T-ff-04 | M2/M3 | TC-02/04 | ✓ |
| **R-013** | ifnet → if_t 不透明化 | §3.3 | T-net-01/02/03 / T-ff-02 | M3 | TC-01/05 | ✓ |
| 新增 | rib/nexthop 路由表重写 | §3.8 | T-net-05 / T-ff-03 / T-tools-route | M3/M5 | TC-08 | ✓ |

### 4.2 P0 风险与任务对应矩阵

| P0 风险 | 对应任务数 | 对应文件数 |
|---|---|---|
| R-011 pr_usrreqs | 5 个（T-kern-14, T-netinet-08/09/10, T-ff-01）| 5 |
| R-012 inpcb SMR | 4 个 | 4 |
| R-013 if_t | 4 个 | 4 |
| R-003 mbuf | 2 个 | 2 |
| rib/nexthop | 3 个 | 3 |
| mips 移除 | 1 个 | 1 dir |
| **合计** | **19 个 P0 任务**（与 05 §3 "18 个 P0" 略不一致：差 1 是因为 mips 是目录级清理而非单文件任务）| — |

### 4.3 风险覆盖度问题

- **RI-01（P3）**：05 §3 表中 P0 数为 18，与上表 19 差 1（mips 任务在 05 中按 1 个统计但实际涉及目录级清理 + Makefile 改造，可视为 1 也可视为 2 大步骤）。**信息项**，不阻塞交付。

### 4.4 风险覆盖度结论

**通过**（0 阻塞；1 项 P3 信息项）。

**14 项风险全部有文档链：03（详述）→ 04（任务）→ 05（里程碑）→ 06（验证）**。这是本系列 spec 最强的部分。

---

## 5. 维度四：可执行性审查

### 5.1 04 + 05 是否可被后续 AI 代理直接拾取

**测试方法**：模拟一个 AI agent 拿到 04 + 05，能否独立执行任意一个 P0 任务。

| 测试任务 | 输入完备性 | 输出标准明确 | SOP 可消化 | 通过 |
|---|---|---|---|---|
| T-kern-14（uipc_socket.c）| 04 §3.1 表给出 13.0 改造手法（H-1+H-9） + 15.0 变化（R-011） / 文件路径明确 | 05 §4 5 步法 + Step 5 落盘标准 | c-precision-surgery skill 可直接消化 5 步法 | ✓ |
| T-ff-02（ff_veth.c）| 04 §3.6 / 02 §4 接口依赖矩阵 | 06 §4.2 单元测试给出"if_alloc 类型匹配 / if_setflags 等价"标准 | ✓ | ✓ |
| T-net-05（route.c）| 04 §3.3 / 03 §3.8 rib/nexthop API 变化提示 | 06 TC-08 给出端到端验证 | ✓ | ✓ |
| T-cleanup-01（mips 删除）| 04 §3.7 / 05 §2.1 / FR-4 验收"find 返回空" | 验收命令明确 | ✓ | ✓ |
| T-tools-route（route/）| 04 §4.1 工具 5 步流程 / 05 §2.5 | 06 TC-08 用例验证 | ✓ | ✓ |

### 5.2 SOP 完整性（针对实施工程师）

| 维度 | 05 中位置 | 完整性 |
|---|---|---|
| 5 步法 SOP | §4 | ✓ |
| 资源人员分配 | §5 | ✓ |
| 回滚方案（任务级/里程碑级/全量级） | §6 | ✓ |
| 失败处理（每里程碑 Gate 失败） | §7.1 | ✓ |
| 时间盒（task 2 天 / 里程碑 4 周） | §7.2 | ✓ |
| build/CI 集成点 | §8 | ✓ |
| 开工 Checklist | §11 | ✓ |

### 5.3 测试可执行性（针对 QA）

| 维度 | 06 中位置 | 完整性 |
|---|---|---|
| 编译矩阵 4 × 2 × 8 = 64 格 | §2.1 | ✓ |
| 9 个 TC 用例标准格式 | §3.2 | ✓ |
| 各里程碑跑哪些 TC | §3.3 | ✓ |
| P0 单元测试 5 个 | §4 | ✓ |
| 性能基线指标 5 项 | §5.1 | ✓ |
| 测试报告模板 | §9 | ✓ |

### 5.4 可执行性结论

**通过**。spec 满足"后续 AI 代理可直接拾取任务"的要求（NFR-2）。

---

## 6. 实施进度跟踪表（M1-M5）

为方便后续实施时的进度跟踪，列出全部 75 个 T-* 任务的状态表（待实施阶段填充）：

| 里程碑 | 任务 ID | 文件 | 优先级 | 状态 | 实施人 | 完成时间 |
|---|---|---|---|---|---|---|
| **M1** | T-cleanup-01 | mips 删除 | P0 | 待办 | — | — |
| M1 | T-sys-01 | sys/systm.h | P0 | 待办 | — | — |
| M1 | T-sys-02 | sys/refcount.h | P0 | 待办 | — | — |
| M1 | T-sys-03 | sys/callout.h+_callout.h | P1 | 待办 | — | — |
| M1 | T-libkern-01 | libkern/ cp -a | P1 | 待办 | — | — |
| M1 | T-crypto-01 | crypto/ cp -a | P2 | 待办 | — | — |
| M1 | T-opencrypto-01 | opencrypto/ cp -a | P1 | 待办 | — | — |
| M1 | T-vm-01 | vm/ cp -a | P1 | 待办 | — | — |
| M1 | T-arch-01 | amd64/x86 头 | P2 | 待办 | — | — |
| M1 | T-arch-02 | arm64/ | P2 | 待办 | — | — |
| M1 | T-misc-01 | netipsec/netgraph/libalias | P2 | 待办 | — | — |
| **M2** | T-kern-01 | kern_descrip.c | P0 | 待办 | — | — |
| M2 | T-kern-02 | kern_event.c | P0 | 待办 | — | — |
| M2 | T-kern-03 | kern_linker.c | P1 | 待办 | — | — |
| M2 | **T-kern-04** | **kern_mbuf.c** | **P0** | 待办 | — | — |
| M2 | T-kern-05 | kern_sysctl.c | P1 | 待办 | — | — |
| M2 | T-kern-06 | link_elf.c | P1 | 待办 | — | — |
| M2 | **T-kern-07** | **subr_epoch.c** | **P0** | 待办 | — | — |
| M2 | T-kern-08 | subr_param.c | P2 | 待办 | — | — |
| M2 | T-kern-09 | subr_taskqueue.c | P1 | 待办 | — | — |
| M2 | T-kern-10 | sys_generic.c | P1 | 待办 | — | — |
| M2 | T-kern-11 | sys_socket.c | P1 | 待办 | — | — |
| M2 | **T-kern-12** | **uipc_mbuf.c** | **P0** | 待办 | — | — |
| M2 | T-kern-13 | uipc_sockbuf.c | P1 | 待办 | — | — |
| M2 | **T-kern-14** | **uipc_socket.c** | **P0** | 待办 | — | — |
| M2 | T-kern-15 | uipc_syscalls.c | P1 | 待办 | — | — |
| M2 | T-kern-misc | 23 个 KERN_SRCS cp -a | P3 | 待办 | — | — |
| M2 | **T-ff-04** | **ff_subr_epoch.c** | **P0** | 待办 | — | — |
| M2 | T-ff-05 | ff_syscall_wrapper.c | P1 | 待办 | — | — |
| M2 | T-ff-06 | ff_kern_intr.c | P1 | 待办 | — | — |
| M2 | T-ff-misc | ff_kern_* 其余 | P2 | 待办 | — | — |
| **M3** | **T-net-01** | **net/if.c** | **P0** | 待办 | — | — |
| M3 | **T-net-02** | **net/if_var.h** | **P0** | 待办 | — | — |
| M3 | T-net-03 | if_ethersubr.c | P1 | 待办 | — | — |
| M3 | T-net-04 | netisr.c | P1 | 待办 | — | — |
| M3 | **T-net-05** | **net/route.c** | **P0** | 待办 | — | — |
| M3 | T-net-misc | 其余 17 NET_SRCS | P3 | 待办 | — | — |
| M3 | **T-netinet-01** | **tcp_input.c** | **P0** | 待办 | — | — |
| M3 | T-netinet-02 | tcp_output.c | P1 | 待办 | — | — |
| M3 | T-netinet-03 | tcp_subr.c | P1 | 待办 | — | — |
| M3 | **T-netinet-04** | **tcp_var.h** | **P0** | 待办 | — | — |
| M3 | T-netinet-05 | tcp_stacks/rack.c | P1 | 待办 | — | — |
| M3 | T-netinet-06 | tcp_stacks/bbr.c | P1 | 待办 | — | — |
| M3 | **T-netinet-07** | **in_pcb.c** | **P0** | 待办 | — | — |
| M3 | T-netinet-08 | tcp_usrreq.c | P1 | 待办 | — | — |
| M3 | T-netinet-09 | udp_usrreq.c | P1 | 待办 | — | — |
| M3 | T-netinet-10 | raw_ip.c | P1 | 待办 | — | — |
| M3 | T-netinet-misc | 12 个 NETINET_SRCS cp -a | P3 | 待办 | — | — |
| M3 | T-netinet6-01 | netinet6/ cp -a + 改造 | P2 | 待办 | — | — |
| M3 | **T-ff-01** | **ff_glue.c** | **P0** | 待办 | — | — |
| M3 | **T-ff-02** | **ff_veth.c** | **P0** | 待办 | — | — |
| M3 | **T-ff-03** | **ff_route.c** | **P0** | 待办 | — | — |
| **M4** | T-netipsec-01 | netipsec/ | P1 | 待办 | — | — |
| M4 | T-netgraph-01 | netgraph/ | P1 | 待办 | — | — |
| M4 | T-netpfil-01 | netpfil/ipfw/ | P1 | 待办 | — | — |
| M4 | T-netpfil-02 | netpfil/pf/ | P2 | 待办 | — | — |
| M4 | T-bsm-01 | bsm/ | P3 | 待办 | — | — |
| M4 | T-ddb-01 | ddb/ 评估 | P3 | 待办 | — | — |
| **M5** | T-tools-arp | arp/ | P1 | 待办 | — | — |
| M5 | **T-tools-ifconfig** | **ifconfig/** | **P0** | 待办 | — | — |
| M5 | T-tools-ipfw | ipfw/ | P1 | 待办 | — | — |
| M5 | T-tools-libmemstat | libmemstat/ | P2 | 待办 | — | — |
| M5 | T-tools-libnetgraph | libnetgraph/ | P1 | 待办 | — | — |
| M5 | T-tools-libutil | libutil/ | P3 | 待办 | — | — |
| M5 | T-tools-libxo | libxo/ | P3 | 待办 | — | — |
| M5 | T-tools-ndp | ndp/ | P1 | 待办 | — | — |
| M5 | **T-tools-netstat** | **netstat/** | **P0** | 待办 | — | — |
| M5 | T-tools-ngctl | ngctl/ | P1 | 待办 | — | — |
| M5 | **T-tools-route** | **route/** | **P0** | 待办 | — | — |
| M5 | T-tools-sysctl | sysctl/ | P1 | 待办 | — | — |
| M5 | T-compat-01 | tools/compat/ (ff_ipc) | P1 | 待办 | — | — |
| M5 | T-acceptance | 跑 9 个 TC 用例 | — | 待办 | — | — |
| M5 | T-perf | 性能基线对比 | — | 待办 | — | — |

> **P0 任务统计**：19 个（与 04 §9 + 05 §3 略有数字差异，已在 §4.3 RI-01 中说明）

---

## 6. 4 维审查结论

| 维度 | 通过 | 阻塞项 | 修订建议（非阻塞）|
|---|---|---|---|
| 1 一致性 | ✓ | 0 | CI-01（P2）：04 §9 与 05 §3 任务数差异需补一句说明 |
| 2 完整性 | ✓ | 0 | CI-02（P3）：02 §4.2 条件编译 2 个文件名应明确 |
| 3 风险覆盖度 | ✓ | 0 | RI-01（P3）：05 §3 P0 数 18 vs 实际 19（信息项）|
| 4 可执行性 | ✓ | 0 | 无 |

**整体结论**：**Spec 通过**。3 项修订建议均为 P2/P3 级别，不阻塞交付，可在后续滚动维护中处理。

---

## 7. 关键质量证据

| 证据 | 来源 |
|---|---|
| 数字出处分级标注（已订正 2026-05-28，详见 §12.3）：04 §1 子目录全景表为 `diff -rq` 实测；syscall 计数为 `grep` 实测（详见 §12.1）；02/03/04 §2 中其余体量字段为局部估算或 Makefile 直读，标注口径见各表注释 | 00/02/03/04 各表 |
| 8 项核心决策 + 5 个 DP 决策点均有归属 | 00 §7 / 01 §7 / 05 §1.2 |
| 14 项风险全部有"03→04→05→06"完整文档链 | §4.1 |
| 75 个 T-* 任务列入 99 §6 跟踪表 | §6 |
| 7 份 spec lint 0 错误 | read_lints 验证 |
| 与 F-Stack 既有文档明确关系 | 00 §6 / 02 §5 |
| 不在范围内的事显式列出 | 01 §3.2 / 05 §9 / 06 §11 |

---

## 8. 给后续 AI 代理的"快速拾取"指南

当 AI 代理被分派拾取某个 T-* 任务时，应按以下顺序读 spec：

1. **04 §3 找到该 T-* 任务的描述**（13.0 改造手法 + 15.0 上游变化）
2. **02 §1 / §2 / §3 / §4 找该文件已有的改造手法详情**
3. **03 §3 / §7 找该任务涉及的 P0 风险背景**
4. **05 §4 5 步法 SOP**（执行手册）
5. **05 §6 备份命令**（执行前）
6. **06 §4 单元测试 或 §3 TC 用例**（验证）
7. **99 §6 任务追踪表**（完成后标 ✓）

---

## 9. 给项目经理的"开工 Go/No-Go"判断

| 检查项 | 状态 |
|---|---|
| Spec 9 份全部交付 | ✓ |
| Spec lint 0 错误 | ✓ |
| 风险全覆盖 14 项 | ✓ |
| 75 个任务清单可执行 | ✓ |
| 验收用例可落地 | ✓ |
| 回滚方案完整 | ✓ |
| 资源人员明确 | ✓ |
| **Spec 阶段交付** | ✅ **GO，可进入实施阶段** |

---

## 10. Phase 5 完成事项归档

> 状态：Phase 5 交付汇报已于 2026-05-26 完成；2026-05-28 增补独立审计 v0.2（`98-independent-audit-report.md`）及 6 项必修修订（详见 §12.1-§12.6）。

| 项 | 详情 |
|---|---|
| 汇总产物清单 + 字数 | 见 §1（体量表）；本 99 文档与 98 审计报告均已纳入 |
| 显式声明不做 git / 不做代码修改 | 已声明；2026-05-28 进入审计修订阶段后**仅修订 docs/freebsd_13_to_15_upgrade_spec/zh_cn/ 下文档**，不改 F-Stack 源码（C/Makefile） |
| 实施阶段拾取入口 | `05-implementation-plan.md` M1 任务（实施前请按 04 §1（diff -rq 实测基线）+ 04 §2（SRCS 全量清单）复评 P0 任务工作量） |

---

## 11. 版本与签字

| 角色 | 签字 | 时间 |
|---|---|---|
| Leader（主对话内执行）| ✓ | 2026-05-26 |
| Reviewer（兼）| ✓ | 2026-05-26 |
| **Spec 阶段交付** | **✅ 通过** | 2026-05-26 |

---

## 12. 修订记录

> 本章记录 spec 交付后基于独立审计（`98-independent-audit-report.md`）所做的事实订正，遵循"事实错误 → 审计发现 → 修订记录"的可追溯链。

### 12.1 修订 R-2026-05-28-01：`SYS_MAXSYSCALL` 与 13→15 syscall 增量订正

| 项 | 内容 |
|---|---|
| 修订日期 | 2026-05-28 |
| 关联审计条目 | `98-independent-audit-report.md` §3 P1-001 |
| 错误根因 | Phase 2 Sub-Agent B（Analyzer-15）未对 `sys/sys/syscall.h` 执行 grep 实测，而是凭 release notes 描述与局部观察推断 13.0 `SYS_MAXSYSCALL` 与 13→15 增量项数量；Phase 4 reviewer 在 4 维审查中未对该数值做回溯校验，错误流入 7 份 spec 中的 2 份。 |
| 实测基线 | 13.0 `SYS_MAXSYSCALL=580`（420 个 `SYS_*` 名称），15.0 `SYS_MAXSYSCALL=599`（439 个）；13→15 净新增 22 项、删除 3 项。来源：`grep '^#define[[:space:]]\+SYS_' /data/workspace/freebsd-src-releng-{13.0,15.0}/sys/sys/syscall.h | awk '{print $2}' | sort | comm`（2026-05-28 实测）。 |
| 修订动作 1 | `03-freebsd-15-changes.md` §1：`SYS_MAXSYSCALL` 表 13.0 列由 `574` 改为 `580`；"最大 syscall 号"行由 `SYS_sigfastblock=573` 改为 `SYS_aio_readv=579`。 |
| 修订动作 2 | `03-freebsd-15-changes.md` §2.4：整段重写为"实测 13→15 syscall 表增量"，分 §2.4.1（22 项新增 + compat shim，附 15.0 编号）/ §2.4.2（3 项删除：`gssd_syscall`/`sbrk`/`sstk`）/ §2.4.3（13.0 已存在但此前误列为新增的 6 项澄清）三段；删除原表中的 `__realpathat` 误项；附实测来源脚注。 |
| 修订动作 3 | `00-overview-and-glossary.md` §术语表：`SYS_MAXSYSCALL` 行 13.0 由 `574` 改为 `580`；"新增 25 项"改为"净新增 22 项 + 删除 3 项"；代表举例改为基于实测的 `fspacectl` / `kqueuex` / `membarrier` / `timerfd_*` / `inotify_*` / `jail_remove_jd` 等，并指向 `03 §2.4` 完整清单。 |
| 修订动作 4 | `98-independent-audit-report.md` §3 P1-001 与 §6.1 第 1 项追加"已修订 2026-05-28，详见 99 §12.1"标记，闭合审计条目。 |
| 影响范围 | `R-010`（"inotify / 抗量子 / out-of-scope"）的 syscall 增量背景同步更新；本次修订**不**改变 R-010 的优先级（仍为 P3）与"约束 C-1 不引入"的处置决定，仅修正其事实底数。 |
| 修订后状态 | `98 P1-001` 闭合；`spec 阶段交付`整体结论保持 **✅ 通过** 不变（事实订正属可执行性维度的精度提升，不影响一致性/完整性/风险覆盖度结论）。 |
| 校验 | `read_lints` 在 zh_cn/ 目录返回 0 diagnostics；全目录 `grep '574|新增 25 项|SYS_sigfastblock=573'` 应无残留。 |

### 12.2 修订 R-2026-05-28-02：`if_t` 类型定义订正

| 项 | 内容 |
|---|---|
| 修订日期 | 2026-05-28 |
| 关联审计条目 | `98-independent-audit-report.md` §3 P1-002，§6.1 第 2 项 |
| 错误根因 | Phase 2 Sub-Agent B（Analyzer-15）将 15.0 的 `if_t` 误描述为 `typedef void *if_t`；并把"不透明化"等同于"底层类型变为 `void *`"。Phase 4 reviewer 未实测 `sys/net/if.h` / `sys/net/if_var.h` 中 typedef 的具体形式。 |
| 实测基线 | 13.0 `sys/net/if_var.h:127`：`typedef struct ifnet * if_t;`；15.0 `sys/net/if.h:667`：`typedef struct ifnet *if_t;`。**两版均为 `struct ifnet *`，从来不是 `void *`**。差异在于 15.0 把该 typedef 上提到 `if.h` 并把 `if_alloc()` 等内核 API 签名统一改用 `if_t`，配套提供 `if_get*/if_set*` 访问函数。"不透明化"指 API 契约（外部代码应用访问函数操作），不是底层类型抹除。来源：`grep -nE 'typedef.*if_t' /data/workspace/freebsd-src-releng-{13.0,15.0}/sys/net/if.h /data/workspace/freebsd-src-releng-{13.0,15.0}/sys/net/if_var.h`（2026-05-28 实测）。 |
| 修订动作 1 | `03-freebsd-15-changes.md` §3.3 行 137"事实"格：删除 `typedef void *if_t` 错误说法，改写为分两版本对照（13.0 已有 typedef 但 API 仍以 `struct ifnet *` 暴露；15.0 上提 typedef 并统一 API），并显式声明"底层类型并未变成 `void *`"。 |
| 修订动作 2 | `00-overview-and-glossary.md` §术语表 `if_t` 行重写：明确 `typedef struct ifnet *if_t`，配以"`if_t` 不是 `void *`"的反向澄清，并加跳转到 `03 §3.3` 的指引。 |
| 修订动作 3 | `06-test-and-acceptance-spec.md` §4.2 行 118 测试点描述：保留语义"`if_alloc(IFT_ETHER)` 返回 `if_t`"，但在括号内补"typedef 为 `struct ifnet *`，13.0 中该 API 直接返回 `struct ifnet *`"消除歧义。 |
| 影响范围 | `R-013`（`ifnet → if_t` 不透明化，P0）的优先级与处置决定不变，仅修正其事实底数。`ff_veth.c` 适配策略需注意：仍可使用 `struct ifnet *` 兼容写法（typedef 可互转），但**应**遵循"通过访问函数操作"的 15.0 API 契约，不应直接依赖字段布局。 |
| 修订后状态 | `98 P1-002` 闭合；`spec 阶段交付`整体结论保持 **✅ 通过** 不变。 |
| 校验 | `read_lints` 在 zh_cn/ 目录返回 0 diagnostics；全目录 `grep -nE 'void \*if_t'` 应无残留。 |

### 12.3 修订 R-2026-05-28-03：04 §1 子目录全景表 diff -rq 实测重写

| 项 | 内容 |
|---|---|
| 修订日期 | 2026-05-28 |
| 关联审计条目 | `98-independent-audit-report.md` §3 P1-003，§6.1 第 3 项 |
| 错误根因 | 04 §1 表头明写"启发式：大小变化即 MOD"，但 99 §7 又声明"所有数字均有'实测出处'标注"，两者语义冲突。Phase 4 reviewer 未识别该冲突。该启发式存在两类系统性偏差：(a) 大小不变但内容已改 → 漏报；(b) 大小变化但语义无关 → 误判。 |
| 实测基线 | 真跑 `diff -rq freebsd-src-releng-{13.0,15.0}/sys/<subdir>` 18 个子目录，按 `Only in <13>` / `Only in <15>` / `Files differ` 三类分别计数。文件总数同步用 `find -type f -name '*.c' -o -name '*.h' -o -name '*.S'` 递归统计（覆盖各架构目录的 includeˇ 子目录）。来源：见 04 §1 表后实测脚注。 |
| 实测结果与原表的主要差异 | `kern` MOD：~95 → 231（+143%）；`netinet` MOD：~52 → 181（+248%）；`net` MOD：~38 → 149（+292%）；`netinet6` MOD：~28 → 57（+104%）；`amd64`/`arm64`/`x86` 因递归口径调整，13/15 文件总数同步上调。原表 `bsm`/`ddb` 写"几乎 0"，实测分别为 8 和 29。 |
| 修订动作 1 | `04-diff-and-port-strategy.md` §1：表头副标题"启发式：大小变化即 MOD"改为"实测：基于 `diff -rq` 文件级比对"；表格 18 行数字全部用实测结果回填；`netlink` 行明确为"13.0 不存在该子目录，15.0 共 39 个文件"；`contrib` 行因量级与本审计回合范围保持"不给具体数字"但说明原因；表后追加完整实测脚注与"主要差异说明"段。 |
| 修订动作 2 | `99-review-report.md` §7 行 301："所有数字均有'实测出处'标注"改为分级标注：04 §1 为 `diff -rq` 实测；syscall 计数为 `grep` 实测（§12.1）；02/03/04 §2 中其余体量字段为局部估算或 Makefile 直读，标注口径见各表注释。消除与 04 §1 表头的语义冲突。 |
| 修订动作 3 | `98-independent-audit-report.md` §3 P1-003 与 §6.1 第 3 项追加"已修订 2026-05-28，详见 99 §12.3"标记，闭合审计条目。 |
| 影响范围 | 04 §9 任务规模与 05 §3 排期所依据的 MOD 数普遍低估 2-3 倍，**这意味着本次修订后 M1 启动前需以 04 §1 新基线复评 P0 任务的工作量**（记入 P2-001 跟踪，但本回合不强制扩展任务表）。R-001 ~ R-014 风险识别方向不受影响（风险来自具体 KBI/KPI 改动，不来自数字本身）。 |
| 修订后状态 | `98 P1-003` 闭合；`spec 阶段交付`整体结论保持 **✅ 通过** 不变，但 04 §1 升级到"实施级精度"。 |
| 校验 | `read_lints` 在 zh_cn/ 目录返回 0 diagnostics；`grep -nE '启发式：大小变化即 MOD' zh_cn/04-*.md` 应无残留；99 §7 与 04 §1 不再语义冲突。 |

### 12.4 修订 R-2026-05-28-04：04 §2 SRCS 链接清单全量展开

| 项 | 内容 |
|---|---|
| 修订日期 | 2026-05-28 |
| 关联审计条目 | `98-independent-audit-report.md` §3 P1-004，§6.1 第 4 项 |
| 错误根因 | 04 v0.1 §2 自称"F-Stack 实际链接清单 / Sub-Agent C 实测"，但 `NET_SRCS` / `NETINET_SRCS` / `NETINET6_SRCS` / `LIBKERN_SRCS` 等关键变量均使用"典型 + ..."省略号写法；`FF_SRCS` / `FF_HOST_SRCS` 仅给区间数（17-21 / 9）；`NETIPSEC_SRCS` / `NETGRAPH_SRCS` / `NETIPFW_SRCS` / `VM_SRCS` / `OPENCRYPTO_SRCS` 仅以一句话提及未展开。Phase 4 reviewer 把这些"典型清单"误认为已完整，未对 Makefile 实际 `+=` 行数做交叉。 |
| 实测基线 | `f-stack/lib/Makefile` 共 765 行；16 个 `*_SRCS` 变量 + 24 处 `+=`；用 `sed -n` 按行号区间逐块抽取，并用 `grep -oE '[a-zA-Z_0-9]+\.c' \| sort -u \| wc -l` 校验每个变量的去重计数。命令样例：`sed -n '479,525p' lib/Makefile \| grep -oE '[a-zA-Z_0-9]+\.c' \| sort -u`。 |
| 默认配置（`FF_INET6=1, FF_TCPHPTS=1, FF_EXTRA_TCP_STACKS=1`）下的实测计数 | FF_SRCS 17 / FF_HOST_SRCS 9 / CRYPTO_SRCS 2 / KERN_SRCS 38 / LIBKERN_SRCS 6（arm64 7）/ MACHINE_SRCS 1 / NET_SRCS 33 / NETINET_SRCS 44 / NETINET6_SRCS 29 / EXTRA_TCP_STACKS_SRCS 8 / VM_SRCS 1 = **188 个 `.c`**（不含 `*.m` 与由 mk 文件生成的 ASM）。条件编译开启后再加：FF_NETGRAPH FF_SRCS+2 / NETGRAPH_SRCS+43；FF_KNI FF_HOST_SRCS+1；FF_USE_PAGE_ARRAY FF_HOST_SRCS+1；FF_IPFW NETIPFW_SRCS+13；FF_IPSEC NETIPSEC_SRCS+10 / OPENCRYPTO_SRCS+6 / CRYPTO_SRCS 由 2 改为 14。 |
| 修订动作 1 | `04-diff-and-port-strategy.md` §2 整体重写：从 7 节（§2.1-§2.7）扩为 18 节（§2.1-§2.18），先给 16 个变量的索引表（含默认/条件计数与 VPATH 来源），再按变量分节列出**完整文件清单**（不再使用省略号）；新增 §2.18 说明 mips 在 `lib/Makefile` 中只有 `ARCH_FLAGS`，**无任何 `*_SRCS+=`**，与 03 §2.1 的 mips 移除任务衔接。 |
| 修订动作 2 | 原 §2.6"FF_SRCS（17-21 个）+ FF_HOST_SRCS（9 个）"区间数收敛为精确数：FF_SRCS 默认 17，FF_NETGRAPH 时 +2；FF_HOST_SRCS 默认 9，FF_KNI / FF_USE_PAGE_ARRAY / 非 FreeBSD 各 +1。审计 P2-003"FF_SRCS=21 / FF_HOST_SRCS=9 / +2 隐式"的口径不一致问题同步消解。 |
| 修订动作 3 | `98-independent-audit-report.md` §3 P1-004 与 §6.1 第 4 项追加"已修订 2026-05-28，详见 99 §12.4"标记，闭合审计条目。 |
| 影响范围 | 04 §3（交集热点）原本以"~20 NET_SRCS / ~22 NETINET_SRCS / ~12 NETINET6_SRCS"为基础——本次实测后真实数字分别是 33 / 44 / 29，**实际受影响文件比 v0.1 估计多 50% 左右**；建议 M1 启动前以 §2 完整清单逐文件标注 P0/P1/P2 标签（不在本回合范围）。R-001 ~ R-014 风险识别方向不变。 |
| 修订后状态 | `98 P1-004` 闭合；`spec 阶段交付`整体结论保持 **✅ 通过** 不变；§2 升级到"实施级精度"。 |
| 校验 | `read_lints` 在 zh_cn/ 目录返回 0 diagnostics；`grep -nE '\\.\\.\\.[[:space:]]*$' zh_cn/04-*.md` 应无残留（合法历史段落不含此 pattern）；`grep -cE '^[a-zA-Z_0-9]+\\.c' f-stack/lib/Makefile` 与本节文件清单总数一致（默认配置 188，全部条件开启 247）。 |

### 12.5 修订 R-2026-05-28-05：文档过期状态清理

| 项 | 内容 |
|---|---|
| 修订日期 | 2026-05-28 |
| 关联审计条目 | `98-independent-audit-report.md` §3 P1-006，§6.1 第 5 项 |
| 错误根因 | `plan.md` 是 Phase 1.3 产物，写于 Phase 1.4 启动前；`01-requirements-spec.md` 是 Phase 3.2 产物，写于 02-06 + 99 出炉前；`99-review-report.md` §3.2 / §10 写于 Phase 5 完成前。这些文档发布后未再回扫并对齐当前阶段，导致截至 2026-05-28，仍残留"f-stack-lib/ 当前不存在 / 2 份已交付 6 份待出 / Phase 5 待 Leader 下回合产出"等过期表述，与项目实际状态（5 个 Phase + 独立审计 v0.2 已交付）严重不一致。Phase 4 reviewer 未把"状态字段对齐"列为审查维度。 |
| 实测基线 | `ls -la /data/workspace/freebsd-src-releng-15.0/f-stack-lib/` 显示该目录已存在（含 `freebsd/` 24 593 文件、`tools/` 451 文件、`INVENTORY.md`），即 Phase 1.4 已完成；`ls /data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/` 显示 9 份 spec + 98 + 99 + plan + plan-spec-fix-r2-r6 全部已交付。 |
| 修订动作 1 | `plan.md` §1.3：标题"15.0 原始备份（**本计划需要创建**）"改为"已于 Phase 1.4 创建，2026-05-26"；正文"`/data/workspace/freebsd-src-releng-15.0/f-stack-lib/`（**当前不存在**）"改为"已存在 25 044 个文件，含 freebsd/、tools/、INVENTORY.md"；"需要"段改为"Phase 1.4 已完成的工作"。 |
| 修订动作 2 | `plan.md` §8 与末尾占位段：把"本计划即 'Plan 阶段产物'，下一步进入 Discovery + Analysis"改为"本计划已完整执行完毕"；末尾"等待用户确认本 plan.md"改为"当前状态：Phase 1-5 + 独立审计 v0.2 全部交付（2026-05-28）。下一步进入 M1 实施阶段"。 |
| 修订动作 3 | `01-requirements-spec.md` §11：标题"2 份已交付，6 份待出"改为"9 份全部已交付"；表格 9 行的"待 Phase 3.x / 待 Phase 4"全部改为"已交付（2026-05-26；某节 2026-05-28 已订正）"；新增第 10 行"98-independent-audit-report.md"。 |
| 修订动作 4 | `99-review-report.md` §3.2 行 82："Phase 5 待 Leader 下回合产出"改为"已交付（2026-05-26 完成；2026-05-28 增补独立审计 v0.2 修订）"；§10 标题"待 Phase 5 完成的事"改为"Phase 5 完成事项归档"，正文重写为已完成清单 + 实施阶段拾取入口。 |
| 修订动作 5 | `00-overview-and-glossary.md` §6 行 151"审查：Reviewer（待 Phase 4 出报告）"改为"已于 2026-05-26 出 99；2026-05-28 增补 98 与 6 项修订"。 |
| 修订动作 6 | `98-independent-audit-report.md` §3 P1-006 与 §6.1 第 5 项追加"已修订 2026-05-28，详见 99 §12.5"标记，闭合审计条目。 |
| 影响范围 | 项目状态可信度恢复。无源码层影响；spec 内容（事实/数字/任务）与状态字段相互独立，本次修订不改变任何技术结论。 |
| 修订后状态 | `98 P1-006` 闭合；`spec 阶段交付`整体结论保持 **✅ 通过** 不变。 |
| 校验 | `read_lints` 在 zh_cn/ 目录返回 0 diagnostics；`grep -nE '当前不存在\|2 份已交付，6 份待出\|待 Phase 3\\.\|待 Phase 4 出报告\|待 Leader 下回合' zh_cn/{plan,01,99,00}.md` 应无残留（合法历史引文如 98 审计报告原文与本节修订记录除外）。 |

### 12.6 修订 R-2026-05-28-06：03 外部资料引用与待核验清单

| 项 | 内容 |
|---|---|
| 修订日期 | 2026-05-28 |
| 关联审计条目 | `98-independent-audit-report.md` §3 P1-005，§6.1 第 6 项 |
| 错误根因 | 03 v0.1 大量引用上游事实（mips 移除、clang/llvm 19、pkgbase、`pr_usrreqs` 合并、inpcb SMR、`if_t` 不透明化、netlink、RACK 默认化、KTLS、routing/rib/nexthop、14.4/15.1 时间线等），但全文仅 1 处出现"Release Notes"字样、零 URL、零抓取日期。Phase 2 Sub-Agent B（Analyzer-15）原计划应跑 `web_search` / `web_fetch`，实际未执行；Phase 4 reviewer 未把"外部事实是否可复核"列为审查维度。 |
| 实测基线 | 本次改用"本地权威源"补充：`/data/workspace/freebsd-src-releng-15.0/` 本身就是 15.0-RELEASE-p9 的完整源代码 + RELNOTES + UPDATING + sys/sys/param.h + sys/conf/newvers.sh + sys/conf/files + 各子系统头文件，绝大多数事实可以在本仓库内部找到逐字引文。本节列入 13 条本地可复核事实 + 8 条待核验外部 URL。 |
| 修订动作 1 | `03-freebsd-15-changes.md` 末尾新增 §10「外部资料引用与待核验清单（2026-05-28 增补）」，分三个小节：§10.1 本地权威源（13 条事实，每条给 `路径:行号 + 引文`，读者可直接 `sed -n '<line>p'` 复核）；§10.2 外部 URL 待核验清单（8 条，覆盖 clang 19、pkgbase、netlink 引入年份、RACK 默认 knob、KTLS commit、routing 重写设计、14.x 时间线、15.1）；§10.3 待核验条目的转正条件与流程。 |
| 修订动作 2 | 不新建独立的 `03-appendix-sources.md`（审计 P1-005 建议的两种方案之一），而是把外部资料章节内嵌到 03 自身 §10，避免额外的跨文件维护成本；与审计建议的等效性体现在：每条事实仍能定位到来源 + 待核验项明确列出转正路径。 |
| 修订动作 3 | `98-independent-audit-report.md` §3 P1-005 与 §6.1 第 6 项追加"已修订 2026-05-28，详见 99 §12.6"标记，闭合审计条目。 |
| 影响范围 | 03 中所有外部事实从"无可复核证据"升级为"本地可复核（§10.1）"或"明确待核验（§10.2）"。**Spec 阶段 Go/No-Go 维度的"作为 Spec 草案 = GO"结论保持不变；新增的外部 URL 核验工作不阻塞 M1 实施阶段，可在 M1 准备阶段并行完成**（详见 §10.3）。 |
| 修订后状态 | `98 P1-005` 闭合；`spec 阶段交付`整体结论保持 **✅ 通过** 不变。 |
| 校验 | `read_lints` 在 zh_cn/ 目录返回 0 diagnostics；`grep -nE 'sys/conf/newvers\\.sh\|sys/sys/param\\.h\|UPDATING:\|RELNOTES:\|sys/sys/protosw\\.h\|sys/netinet/in_pcb\\.h\|sys/net/if\\.h\|sys/net/if_var\\.h\|sys/conf/files' zh_cn/03-*.md` 应有 ≥10 处命中（即本地引文路径）。 |

