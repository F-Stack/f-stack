# 01 — 需求规格说明

> 文档版本：v0.1（2026-06-09 17:50 UTC+8）
> Author：spec-author
> 范围：F-Stack lib/ FF_HOST_SRCS 11 文件 CMocka 单元测试框架

---

## 1. 文档目的

本 spec 列出本任务（仅 spec 阶段）的：(1) 功能需求 FR-U-x；(2) 非功能需求 NFR-U-x；(3) 风险 R-U-x；(4) 决策 DP-U-x；(5) 验收门禁 G1-G4；(6) 启动条件。所有 ID 都被其余 spec 文档（02 / 04 / 06 / 99）引用。

---

## 2. 功能需求（FR-U-x）

### 2.1 spec 文档级（FR-U-1..3）

| ID | 描述 | 验收标准 |
|---|---|---|
| **FR-U-1** | 7 篇中文 spec 文档全部落盘到 `docs/unit_test_spec/zh_cn/` | `ls docs/unit_test_spec/zh_cn/*.md \| wc -l` ≥ 7（plan + 6 spec）|
| **FR-U-2** | 6 篇 tracked spec 中每篇 line 引用全部实测准确 | gate-keeper 抽样 ≥10 处 cross-check 实测命中率 = 100% |
| **FR-U-3** | spec 04 含 Unity → CMocka API 映射表，行数 ≥15 | grep `assert_int_equal\\|assert_string_equal` ≥15 行 |

### 2.2 测试范围级（FR-U-4..6）

| ID | 描述 | 验收标准 |
|---|---|---|
| **FR-U-4** | spec 02 含 FF_HOST_SRCS 11 文件全清单 + P0/P1/P2/P3 分层 | spec 02 §2 / §3 表格行数 11；分层合计 = 11 |
| **FR-U-5** | spec 04 含 mock 策略矩阵：11 文件 × 4 依赖类型（rte/pthread/sys/printf）| spec 04 §7 表格 ≥11 × 4 = 44 cell 实测填充 |
| **FR-U-6** | spec 06 含 P0/P1 文件的 TC-U-* 用例草案 | spec 06 §3 + §4 用例总数 ≥25；每 P0 文件 ≥10；每 P1 文件 ≥6 |

### 2.3 方法论级（FR-U-7..9）

| ID | 描述 | 验收标准 |
|---|---|---|
| **FR-U-7** | 测试用例命名遵循 `test_<func>_<scenario>` 风格（c-unittest-expert.mdc 方法论）| spec 06 抽样 5 例命名格式合规 |
| **FR-U-8** | 边界覆盖至少包含：空输入 / 极端长度 / 非法字符 / NULL 指针 / 重复 key 5 类 | spec 06 §5 边界覆盖表 ≥5 行 |
| **FR-U-9** | 致命函数处理（rte_exit / rte_panic / exit / abort）有显式 wrap 策略 | spec 04 §8 含 `__wrap_*` + `longjmp` / `mock_assert` 处理代码片段 |

---

## 3. 非功能需求（NFR-U-x）

### 3.1 质量属性（NFR-U-1..3）

| ID | 描述 | 阈值 |
|---|---|---|
| **NFR-U-1** | spec 文档 grounded 度 | 每篇 ≥80% 论述带 line 引用或代码片段，gate-keeper cross-check 抽样命中率 100% |
| **NFR-U-2** | spec 间一致性 | 跨 5 篇 spec 的 line 号、术语、决策ID、风险ID、TC-ID 100% 一致 |
| **NFR-U-3** | 行数预算遵守度 | 每篇 spec 实际行数在预算 ±20% 内（plan §0.2）|

### 3.2 测试体系质量（NFR-U-4..6，是阶段二+ 的 NFR，本阶段 spec 中描述）

| ID | 描述 | 阈值 |
|---|---|---|
| **NFR-U-4** | 单元测试可移植性 | 仅依赖 `pkg-config cmocka`，0 私有 patch；可在 TencentOS 4.4 + Ubuntu 22.04 + RHEL 9 上 ≥98% 用例 PASS |
| **NFR-U-5** | 单测耗时 | P0 + P1 全套 < 30s（粗估，spec 04 §10 列具体 budget）|
| **NFR-U-6** | 与 lib/ build 解耦度 | `tests/unit/` 独立 Makefile，**不改 `lib/Makefile` 一行**，**不依赖 lib/libfstack.a 整体链接**（避免拉入 FreeBSD kernel 子集）|

### 3.3 工程合规（NFR-U-7..8）

| ID | 描述 | 阈值 |
|---|---|---|
| **NFR-U-7** | 0 直接 rm/kill/chmod 调用 | 全 spec 阶段 commit / log 内检索 `rm[^_t]\\|^kill\\b\\|^chmod\\b` 命中数 = 0 |
| **NFR-U-8** | local commit only | spec 阶段 1 commit；不 push；plan.md 按 .gitignore 不入库 |

---

## 4. 风险登记（R-U-x，已与 plan §5 同步）

> 等级：High = 项目级阻塞 / Mid = 阶段级阻塞 / Low = 微调风险

| ID | 风险 | 等级 | mitigation | 检测时机 |
|---|---|---|---|---|
| **R-U-1** | DPDK rte_* 大量 mock 工作量爆炸（ff_dpdk_if.c 173 个 rte_ 调用）| **High** | P2 留 follow-up；spec 04 §7 仅给"纯函数子集"mock 计划 | mock-strategist Phase 2 ✓ |
| **R-U-2** | FreeBSD-host 编译差异 | Mid | spec 04 §6 列 host-only 编译矩阵；测试 Makefile 用 `uname -s` guard | spec 04 撰写时 |
| **R-U-3** | CMocka 1.1.7 vs 1.1.5/1.1.0 API 差异 | Low | spec 04 §2 锁版本 ≥1.1.7；`pkg-config --modversion cmocka` 校验 | 阶段二落地时 |
| **R-U-4** | DPDK 24.11.6 升级后 rte_* 函数签名变化 | Mid | spec 04 §7 mock 矩阵每条标注"DPDK 24.11.6 verified" | gate-keeper review |
| **R-U-5** | ff_config.c 11 handler 全 static 不可直接测 | **High（已闭环）** | spec 06 §3.4 给"端到端 .ini fixture + `#include \"ff_config.c\"` 双策略"；优先端到端 | target-prioritizer Phase 2 ✓ 已闭环 |
| **R-U-6** | ff_ini_parser.c 是 BSD-licensed 第三方 inih 代码，单测意义有限 | Mid | spec 06 §3 显式标注"测 F-Stack 集成层封装 + inih 状态机覆盖"；不重测 inih 内部 | spec 06 撰写时 |
| **R-U-7** | mock-strategist 与 target-prioritizer 输出冲突 | Low | Phase 3 spec-author 起草时统一；gate-keeper Phase 4 cross-check | Phase 3-4 |
| **R-U-8** | 测试可执行文件链接 libfstack.a 触发 FreeBSD kernel 子集编译爆炸 | **High** | spec 04 §5 明确"仅链接被测 .o + 必要 stub"策略；不链整个 libfstack.a | spec 04 撰写时 |
| **R-U-9** | gate-keeper bounce ≥4 触发 escalation | Low | bounce 上限 = 3；≥4 写 ESCALATION-INFO.md | Phase 4 |
| **R-U-10** | iwiki / 外网 F-Stack CMocka 资料稀缺 | Low | 显式标注 "no match"；以 CMocka 官方 + Samba / libssh / DPDK app/test/ CMocka 实践为参考 | reviewer/spec-author |
| **R-U-11** | 覆盖率工具与 CMocka flag 冲突 | Low | spec 04 §6 给 `-fprofile-arcs -ftest-coverage` 与 CMocka 兼容编译参数 | 阶段二落地时 |
| **R-U-12** | 工作区强制规约违规（直接 rm/kill/chmod）| **零容忍** | 所有 spec 中 wrapper 调用显式标注；reviewer compliance gate | 全过程 |
| **R-U-13** | rte_exit / rte_panic 不 wrap 导致单测进程被杀（**新增**）| **High** | spec 04 §8 强制 `__wrap_rte_exit` + `__wrap_rte_panic` + `mock_assert(false)` 替换 | mock-strategist Phase 2 ✓ |
| **R-U-14** | ff_log_open_set / ff_log_close 依赖 `ff_global_cfg` 全局变量（**新增**）| Mid | spec 06 §3.2 给 ff_global_cfg fixture 模板 | spec 06 撰写时 |

---

## 5. 决策点（DP-U-x，与 plan §4 同步）

### 5.1 已决策（spec 阶段不再讨论）

| ID | 决策 | 取值 | 来源 |
|---|---|---|---|
| **DP-U-1** | 目录命名 | `docs/unit_test_spec/zh_cn/` | 用户对话明确 |
| **DP-U-2** | 文档语言 | 中文（英文延迟）| 用户原始需求 |
| **DP-U-3** | spec 篇数 | 7 篇精简 | plan_create |
| **DP-U-4** | 测试框架 | CMocka 1.1.7（已就位）| 用户决策 |
| **DP-U-5** | 方法论参考 | `c-unittest-expert.mdc` Unity-based 但 API 映射 CMocka | 用户原始需求 §6 |
| **DP-U-6** | 测试目录 | `f-stack/tests/unit/` | GNU 项目惯例 |
| **DP-U-7** | Build 系统 | 独立 GNU Makefile + pkg-config | 与 lib/Makefile 风格一致 |
| **DP-U-8** | Bounce 上限 | 3 | 与 vlan-test / dpdk-23-24 一致 |
| **DP-U-9** | KG 处理 | reviewer 直接 query MCP，不 reindex | spec 阶段不改代码 |
| **DP-U-10** | 备份目录 | `f-stack/.spec-backup/unit-test-spec/` | 仓库内本地 backup（详 plan §6）|
| **DP-U-11** | scope | FF_HOST_SRCS 11 文件；KERN_SRCS out-of-scope | §1.2 实测 |

### 5.2 在 Phase 2 调研后闭环的（DP-U-Bx）

| ID | 决策 | 取值 | 闭环来源 |
|---|---|---|---|
| **DP-U-B1** | P1 范围 | `ff_host_interface.c` + `ff_epoll.c` + `ff_config.c`（端到端）| target-prioritizer Phase 2 |
| **DP-U-B2** | `ff_dpdk_kni.c` 优先级 | **P2**（极高 mock 复杂度，仅可拆纯函数测）| mock-strategist + target-prioritizer Phase 2 |
| **DP-U-B3** | DPDK rte_* mock 边界 | CMocka `__wrap_*` 链接器替换；致命函数（rte_exit/panic）用 mock_assert 替换；非致命纯函数（rte_eal_process_type 等）用 will_return | mock-strategist Phase 2 |
| **DP-U-B4** | 覆盖率工具 P0 阶段是否接入 | **不接入**（仅 spec 列 NFR 指标，阶段三才落地）| 简化 P0 起步 |
| **DP-U-B5** | tests/unit/ 子目录划分 | 按 src 文件名（`tests/unit/test_ff_ini_parser.c` / `test_ff_log.c` 等）| 简化追踪 |
| **DP-U-B6** | `make test` / `make check` 标准 target | spec 04 §6 提供 `make test`（默认）+ `make check`（含 valgrind）| GNU 风格 |
| **DP-U-B7** | TC-U-* 用例数下限 | 每 P0 文件 ≥10；每 P1 文件 ≥6（FR-U-6） | spec 06 |
| **DP-U-B8 (新增)** | P0 重新选定 | **`ff_ini_parser.c` + `ff_log.c`** | target-prioritizer 调整：原 plan §1.1 列 `ff_config.c parser handlers 子集` 因全 static 不可直接测，改入 P1 端到端 |

### 5.3 留作阶段二/三决策（spec 阶段不闭环）

| ID | 决策 | 时机 |
|---|---|---|
| **DP-U-C1** | CI 集成（GitHub Actions / 公司内部 CI）| 阶段五 |
| **DP-U-C2** | Mutation testing（mutpy / mull）| 阶段五 |
| **DP-U-C3** | nginx_fstack / helloworld 集成测试扩展 | 阶段五 |
| **DP-U-C4** | ff_dpdk_if.c 纯函数子集测试落地（4 个候选：`ff_rss_check` / `ff_rss_tbl_get_portrange` / `ff_in_pcbladdr` / `ff_get_tsc_ns`）| 阶段五 |

---

## 6. 验收门禁（Gx，与 plan §3.4 同步）

| Gate | 检查 | PASS 条件 |
|---|---|---|
| **G1 spec 落盘** | `ls docs/unit_test_spec/zh_cn/` ≥ 7 markdown 文件 | 7 篇全部存在 + 行数在预算 ±20% |
| **G2 cross-check** | gate-keeper 抽样 ≥10 处 line 引用实测 | 命中率 = 100% |
| **G3 4 维评分** | 一致性 / 完整性 / 风险覆盖度 / 可执行性 4 维评 | 全 ≥A（4 分制）|
| **G4 compliance** | grep `^rm \\|^kill \\|^chmod ` 直接调用 | 整个 spec 阶段 commit / log = 0 命中 |

---

## 7. 启动条件（spec 阶段已满足）

| 条件 | 状态 |
|---|---|
| ✅ CMocka 1.1.7 已通过 dnf 安装 | 上对话确认 |
| ✅ workspace skill 全就位（c-unittest-expert.mdc / spec-driven / harness-engineering-orchestrator）| 已 grep |
| ✅ KG 已就位（`.gitnexus/`）| 已 ls |
| ✅ docs 三层架构 + 既有 spec 模板就位 | 已 ls |
| ✅ git working tree clean | 已 git status |
| ✅ 工作区 wrapper 脚本可用 | 已 ls -l |

---

**文档结束（v0.1）**
