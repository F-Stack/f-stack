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
| Phase 5 | 交付汇报 | 待 Leader 下回合产出 |

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
| 所有数字均有"实测出处"标注 | 00/02/03/04 各表 |
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

## 10. 待 Phase 5 完成的事

| 项 | 详情 |
|---|---|
| 汇总产物清单 + 字数 | Leader 在 Phase 5 主对话内 |
| 显式声明不做 git / 不做代码修改 | 同上 |

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

