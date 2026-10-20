# 00 — 项目总览与术语表

> 文档版本：v0.1（2026-06-09 17:45 UTC+8）
> Author：spec-author（基于 Phase 2 三路调研材料起草）
> 适用范围：F-Stack v1.26（FreeBSD 15.0 移植 + DPDK 24.11.6 LTS）lib/ 目录胶水代码（FF_HOST_SRCS）的 CMocka 单元测试框架

---

## 1. 项目背景

F-Stack 是一个 user-space TCP/IP 协议栈，将 FreeBSD 网络栈移植到 user-space 并基于 DPDK 提供高性能数据面能力。截至 2026-06-09，F-Stack 已完成两次大型升级（FreeBSD 13.0 → 15.0 + DPDK 23.11.5 → 24.11.6 LTS），但**始终缺乏单元测试框架**：

- `f-stack/` 仓库根目录无 `tests/` / `test/`
- `lib/*.c` 中无 `#ifdef TEST` / `#ifdef UNITTEST` 守卫
- 现有的运行时验证依赖：(a) helloworld primary 起栈 + curl smoke、(b) nginx_fstack 多 worker 烟测、(c) phase-5b perf 矩阵
- 这些是**集成测试**，覆盖 lib 层 glue 代码的纯函数 / 字符串处理 / 协议解析等"小逻辑"成本极高

→ 本项目首次为 F-Stack lib 层引入**真正的单元测试**（基于 CMocka 1.1.7），从最易切入的胶水代码开始，逐步建立可持续演进的测试体系。

## 2. 项目目标

| ID | 目标 | 阶段 |
|---|---|---|
| **G-A** | 为 F-Stack lib/ host 侧胶水代码（FF_HOST_SRCS 11 文件）建立 **CMocka 单元测试框架 spec** | **本任务（spec 阶段）**|
| **G-B** | 阶段二：搭建 `tests/unit/` 工程骨架 + 第一个 hello-world test | 后续 |
| **G-C** | 阶段三：P0 用例落地（`ff_ini_parser.c` + `ff_log.c`）| 后续 |
| **G-D** | 阶段四：P1 扩展（`ff_host_interface.c` + `ff_epoll.c` + `ff_config.c` 端到端）| 后续 |
| **G-E** | 阶段五：P2 follow-up（DPDK 重依赖文件）+ CI 集成 + 覆盖率守门 | 后续 |

**本任务范围 = 仅 G-A**，产出 7 篇中文 spec 文档（含 plan + 6 spec），不写测试代码、不动 `lib/*.c`、不改 `lib/Makefile`。

## 3. 范围（Scope / Out-of-Scope）

### 3.1 In-Scope

- ✅ FF_HOST_SRCS 罗列的 **11 个胶水代码文件**（详 02 §2）
- ✅ CMocka 1.1.7 框架集成方案 spec
- ✅ `tests/unit/` 目录结构 + Makefile 草案 spec
- ✅ DPDK rte_* / pthread / epoll / printf 4 类外部依赖的 mock 策略矩阵
- ✅ 第一批 P0 测试用例草案（TC-U-*）
- ✅ Unity → CMocka API 映射表（参考 `c-unittest-expert.mdc` 方法论）

### 3.2 Out-of-Scope

- ❌ KERN_SRCS（kernel 子集移植代码）单元测试 — 共 ~20 个 `ff_veth.c` / `ff_glue.c` / `ff_route.c` / `ff_kern_*.c` / `ff_subr_*.c` / `ff_syscall_wrapper.c` 文件，本质是 FreeBSD kernel 子集，host 端不直接编译，单测意义低且 mock 工作量爆炸
- ❌ 集成测试（已由 helloworld + nginx + vlan-test 覆盖）
- ❌ 性能测试（已由 phase-5b 矩阵覆盖）
- ❌ 物理机环境测试（user 自行做）
- ❌ CI 集成（DP-U-C1 留阶段五）
- ❌ Mutation testing（DP-U-C2 留阶段五）
- ❌ 英文版 spec（DP-U-2 决策为延迟到人工审计完成后）
- ❌ 测试代码、Makefile 真正落地（属阶段二+ G-B）

## 4. 与既有体系的关系

### 4.1 与 docs/ 三层架构的关系

| 三层架构 doc | 本任务关系 |
|---|---|
| `docs/01-LAYER1-ARCHITECTURE.md` | 本任务的 11 文件全部属于 L1 列出的 `lib/ff_dpdk_*.c` + `lib/ff_config.c` + `lib/ff_*.c` 胶水层；spec 02 用 L1 文件路径作为 anchor 锚点 |
| `docs/02-LAYER2-INTERFACES.md` | 本任务的"非 static 公开 API"清单与 L2 接口规约 1:1 对应；spec 02/06 引用 L2 函数签名 |
| `docs/03-LAYER3-FUNCTIONS.md` | 本任务的 static helper / inih handler 清单与 L3 函数索引交叉验证 |

**spec 完成后，由 commit 阶段最小化追加 anchor 行**到 L1（与 dpdk-23-24 / vlan-test 同款模式），不在本 spec 阶段动 `docs/01-LAYER*.md`。

### 4.2 与既有 spec 项目的关系

| 项目 | 时间 | 模式 | 沿用 |
|---|---|---|---|
| `freebsd_13_to_15_upgrade_spec/` | 2025-2026 | 9 篇完整模式 | 备份目录命名风格 / commit 模板 |
| `dpdk_23_24_upgrade_spec/` | 2026-06-09 | **7 篇精简模式** | **本任务沿用** |
| `unit_test_spec/` (本任务) | 2026-06-09 17:35 | 7 篇精简模式 | — |

### 4.3 与 c-unittest-expert.mdc rule 的关系

`workspace/.codebuddy/rules/c-unittest-expert.mdc` 是 **Unity-based** 中文方法论 rule，本任务**复用其方法论**（test 命名 / setup-teardown / 断言粒度 / 边界覆盖），但 **API 全部映射为 CMocka 形式**。spec 04 §3 给出 **Unity → CMocka API 映射表**（≥15 行）。

## 5. 术语表

| 术语 | 定义 |
|---|---|
| **CMocka** | 一个面向 C 语言的轻量级单元测试框架（v1.1.7 已通过 `dnf install libcmocka libcmocka-devel` 就位），主页 https://cmocka.org/，特性：内置 mock + setjmp 子进程隔离 + group fixture |
| **FF_HOST_SRCS** | `lib/Makefile` 中定义的 host-side 源文件列表（line 272-291 + line 568-572），共 11 个 `.c` 文件，host 端直接编译，区别于 KERN_SRCS（FreeBSD 内核子集移植代码） |
| **glue 代码 / 胶水代码** | F-Stack 中介于 user-space TCP/IP 栈与 DPDK PMD 之间的转换层代码，主要在 lib/ff_dpdk_*.c / lib/ff_config.c 等文件中，是本任务的测试目标 |
| **mock** | 用 CMocka `__wrap_*` 链接器标志或 `mock()` 宏替换被测代码调用的外部函数，控制其返回值与参数验证 |
| **fixture** | CMocka `cmocka_unit_test_setup_teardown` 中的 setup/teardown 闭包，用于在每个测试前后准备/清理资源（如临时 .ini 文件、伪 ff_global_cfg 等） |
| **assertion** | CMocka 提供的 `assert_int_equal` / `assert_string_equal` / `assert_non_null` 等宏，验证被测代码的输出 |
| **inih** | `ff_ini_parser.c` 内嵌的 BSD-licensed 第三方 INI parser（https://github.com/benhoyt/inih），F-Stack 配置文件解析的底层 |
| **handler** | `ff_config.c` 中 11 个 `*_cfg_handler` 函数（全 static），是 inih `ini_handler` 协议下的 callback，用于 parse 每个 `[section] key=value` |
| **P0/P1/P2/P3** | 测试优先级分层：P0=立即落地（最高 ROI）/ P1=第二批（高 ROI）/ P2=follow-up（中 ROI）/ P3=暂不测（低 ROI） |
| **TC-U-x** | 单元测试用例 ID（unit test case），sphere 06 中编号 |
| **FR-U-x** | 功能需求 ID（functional requirement, unit-test），spec 01 中编号 |
| **NFR-U-x** | 非功能需求 ID，spec 01 中编号 |
| **R-U-x** | 风险 ID，spec 01 中编号 |
| **DP-U-x** | 决策点 ID（decision point），spec 01 + plan §4 中编号 |
| **G1-G4** | 验收门禁（acceptance gate），spec 01 §8 中定义 |
| **bounce** | gate-keeper 评审打回机制，上限 3 次（DP-U-8），≥4 写 ESCALATION-INFO.md |

## 6. 关键决策摘要（详细见 spec 01 §7）

| ID | 决策 | 取值 |
|---|---|---|
| DP-U-1 | 目录命名 | `docs/unit_test_spec/zh_cn/` |
| DP-U-2 | 文档语言 | 中文（英文延迟）|
| DP-U-3 | spec 篇数 | 7 篇精简（沿用 dpdk_23_24 模式）|
| DP-U-4 | 测试框架 | CMocka 1.1.7 |
| DP-U-6 | 测试目录 | `f-stack/tests/unit/` |
| DP-U-7 | Build 系统 | 独立 GNU Makefile + pkg-config |
| DP-U-11 | scope | FF_HOST_SRCS 11 文件；KERN_SRCS out-of-scope |
| DP-U-12 (修订) | P0 | **`ff_ini_parser.c` + `ff_log.c`**（target-prioritizer Phase 2 调整后；原 plan 列 ff_config.c 因 handlers 全 static 改入 P1） |

## 7. 交付物清单（spec 阶段）

| # | 文件 | 行数预算 | 状态 |
|---|---|---|---|
| 1 | `plan.md` | 354 ✓ | local-only ✓ |
| 2 | `00-overview-and-glossary.md`（本文）| ≤200 | 起草中 |
| 3 | `01-requirements-spec.md` | ≤250 | 待写 |
| 4 | `02-current-architecture-and-targets.md` | ≤450 | 待写 |
| 5 | `04-cmocka-framework-and-impl.md` | ≤500 | 待写 |
| 6 | `06-test-cases-and-acceptance.md` | ≤450 | 待写 |
| 7 | `99-review-report.md` | ≤350 | 待写 |

## 8. 工作区强制规约（再次声明）

- 禁止直接 `rm/kill/chmod`；全部走 `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`
- 禁止猜测；所有 line 引用必须实测；reviewer cross-check ≥10 处
- 中文 spec；英文延迟到人工审计完成后
- local commit only；不 push

---

**文档结束（v0.1）**
