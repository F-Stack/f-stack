# 07 测试与性能基线规格

> **文档编号**：SPEC-KE-07
> **版本**：v3（范式修正重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：本特性（单 API+标记选栈/config 默认开关/客户端选栈/双模式）的单元/集成/性能基线测试方案与门禁标准。
> **对齐**：F-Stack 既有测试体系 `tests/unit`（Unity，*.c + *.ini）、`tests/integration`、覆盖率 `tests/run_full_coverage.sh`（lcov，`tests/full_coverage_report/`）。

---

## 1. 测试分层

| 层级 | 目录 | 框架/方式 | 覆盖目标 |
|---|---|---|---|
| 单元测试 | `tests/unit/`（新增选栈用例） | Unity（对齐既有 `*.c`+`*.ini`） | 标记选栈/归属判定/config 解析/事件合并 |
| 集成测试 | `tests/integration/` | 端到端进程 + 本机工具 | 服务端本机直访、客户端连本机/外部、双栈并存 |
| 性能基线 | `tests/`（性能脚本） | 压测 + 对比 | 默认/开启选栈的回归对比 |

---

## 2. 单元测试用例（Unity）

| 编号 | 用例 | 断言 | 对应需求 |
|---|---|---|---|
| UT-1 | `socket(SOCK_STREAM\|SOCK_KERNEL)`（hook） | 返回内核 fd，`is_fstack_fd==false` | FR-1/FR-6 |
| UT-2 | `socket(SOCK_STREAM)` 默认 | 走 F-Stack，`is_fstack_fd==true` | FR-6 |
| UT-3 | `type` 同置 `SOCK_KERNEL\|SOCK_FSTACK` | 按优先级走 F-Stack（`ff_hook_socket:387` 条件不成立） | 边界/`05 §8` |
| UT-4 | config `default_stack=kernel` + 不带标记 | 默认走内核栈 | FR-5 |
| UT-5 | config `default_stack=kernel` + 带 `SOCK_FSTACK` | app 标记覆盖，走 F-Stack | FR-5/优先级 |
| UT-6 | `ini_parse_handler` 解析 `[stack] default_stack` | 正确填充 `ff_config.stack.default_to_kernel` | FR-5 |
| UT-7 | 原生 `ff_socket(SOCK_KERNEL)`（补强后） | 走内核栈（补强前记录恒 F-Stack，`02 §5`/D4） | FR-6 |
| UT-8 | 客户端 `connect` fd 归属路由 | 内核 fd → `ff_linux_connect`；F-Stack fd → F-Stack | FR-3/FR-4 |
| UT-9 | `epoll_wait(maxevents=1)` | 返回 `-EINVAL`（对照 `:2212-2218`） | 边界 |
| UT-10 | epoll 同时注册内核 fd 与 F-Stack fd | 两类事件均返回不丢失 | FR-7 |
| UT-11 | `close` 内核侧 fd | 两栈资源联动释放、无泄漏（对照 `:1874-1883`） | FR-8 |
| UT-12 | 编译开关关闭 / 默认 F-Stack | 行为等价纯 F-Stack，零开销 | NFR-1/FR-9 |

> 用例落地参照 `tests/unit/` 既有 `*.c`+`*.ini` 组织；可按需引用 `[skill:c-unittest-expert]`（Unity）规范。

---

## 3. 集成测试用例

| 编号 | 场景 | 步骤 | 通过标准 | 对应需求 |
|---|---|---|---|---|
| IT-1 | 服务端本机 curl 直访 | 启动示例（`SOCK_KERNEL` 内核栈监听）→ 本机 `curl 127.0.0.1:port` / `curl <host_ip>` | HTTP 200 | FR-1 |
| IT-2 | 本机 ping | `ping <host_ip>` | 有回包 | FR-2 |
| IT-3 | **客户端连本机服务** | 本机起 server（内核栈）→ F-Stack app（`SOCK_KERNEL`）`connect 127.0.0.1`/本机 IP | 连接建立、收发正常 | FR-3 |
| IT-4 | **客户端连外部内核服务** | F-Stack app（`SOCK_KERNEL`）`connect <外部内核栈服务>` | 连接建立、收发正常 | FR-4 |
| IT-5 | config 默认栈 | 改 config `default_stack=kernel` 重启 → 不带标记的 socket 走内核 | 默认栈生效；标记可覆盖 | FR-5 |
| IT-6 | 多进程差异化 | 两进程用不同 config（fstack/kernel 默认） | 各自默认栈独立生效 | NFR-6 |
| IT-7 | 双栈并存 | 同进程内 F-Stack 业务监听 + 内核栈管理监听 | 业务走 DPDK NIC、管理走内核，互不干扰 | FR-6/FR-7 |
| IT-8 | 长稳/泄漏 | 大量短连接反复开关（含客户端） | fd 数稳定、无泄漏 | FR-8 |

> 进程清理用 `/data/workspace/kill_process.sh`，临时文件用 `/data/workspace/rm_tmp_file.sh`，权限调整用 `/data/workspace/chmod_modify.sh`。

---

## 4. 性能基线

| 编号 | 指标 | 方法 | 门禁 |
|---|---|---|---|
| PERF-1 | F-Stack 业务路径回归 | 关闭选栈/默认 F-Stack vs 基线 | 吞吐/时延偏差 ≤ 噪声阈值（NFR-2） |
| PERF-2 | 开启选栈业务路径回归 | 内核侧监听空载，压测 F-Stack 业务 | 业务快路径无显著回归 |
| PERF-3 | 原生 `ff_socket` 补强开销 | 标记识别分支对默认路径的影响 | 默认路径零/可忽略开销（NFR-1） |
| PERF-4 | 事件合并延迟 | 内核事件取用节流（`:2324+`）对延迟影响 | 延迟在可接受区间 |
| PERF-5 | 内核侧管理面/客户端吞吐 | 本机 curl 并发 / 客户端 connect 压测 | 满足管理面预期（非高速路径） |

---

## 5. 覆盖率与门禁标准

- 复用 `tests/run_full_coverage.sh`（lcov）统计本特性改动（`ff_config.{c,h}` 新增段、`ff_socket` 标记分支、`ff_hook_*` 选栈路径）覆盖率。
- **门禁标准**：
  1. UT 全通过、新增代码行覆盖率达既有项目标准。
  2. IT-1~IT-8 全通过（服务端本机直访 + 客户端连本机/外部 + config 默认 + 多进程 实测成功）。
  3. PERF-1/PERF-2/PERF-3 业务快路径与默认路径无回归。
  4. 关闭/默认 F-Stack 时与纯 F-Stack 行为/性能一致（NFR-1/2）。
- 任一项失败 → 按 plan 的 bounce 规约打回上一里程碑修复（同一步骤 ≤3 次，超限转人工）。

---

## 6. 交叉验证要求
- 所有测试需**实际执行取证**（日志/抓包/覆盖率报告），禁止臆测。
- 测试断言中引用的代码行号与实际代码一致，冲突以代码为准。
- 客户端用例须实测 `connect` 经内核栈到达（抓包确认走内核而非 DPDK 网卡）。
