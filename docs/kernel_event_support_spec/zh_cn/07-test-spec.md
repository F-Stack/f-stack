# 07 测试与性能基线规格

> **文档编号**：SPEC-KE-07
> **版本**：v2（全量重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：连接级选栈增强 lib 的单元/集成/性能基线测试方案与门禁标准。
> **对齐**：F-Stack 既有测试体系 `tests/unit`（Unity，*.c + *.ini）、`tests/integration`、覆盖率 `tests/run_full_coverage.sh`（lcov，`tests/full_coverage_report/`）。

---

## 1. 测试分层

| 层级 | 目录 | 框架/方式 | 覆盖目标 |
|---|---|---|---|
| 单元测试 | `tests/unit/`（新增 `ff_local` 用例） | Unity（对齐既有 `*.c`+`*.ini`） | 选栈/归属判定/事件合并逻辑 |
| 集成测试 | `tests/integration/` | 端到端进程 + 本机工具 | 本机 ping/curl 直访、双栈并存 |
| 性能基线 | `tests/`（性能脚本） | 压测 + 对比 | 关闭/开启本能力的回归对比 |

---

## 2. 单元测试用例（Unity）

| 编号 | 用例 | 断言 | 对应需求 |
|---|---|---|---|
| UT-1 | `ff_local_socket(belong_to_host=1)` | 返回内核栈 fd，`ff_local_fd_owner==FF_OWNER_HOST` | FR-1/FR-5 |
| UT-2 | `ff_local_socket(belong_to_host=0)` | 走 F-Stack，归属 `FF_OWNER_FSTACK` | FR-3/FR-5 |
| UT-3 | `ff_local_epoll_wait(maxevents=1)` | 返回 `-EINVAL`（对照 `ff_hook_syscall.c:2212-2218`） | 边界 |
| UT-4 | epoll 同时注册内核 fd 与 F-Stack fd | 两类事件均被返回且不丢失 | FR-4 |
| UT-5 | `close` 内核侧 fd | 两栈资源联动释放、无泄漏（对照 `:1874-1883`） | FR-6 |
| UT-6 | `FF_LOCAL_STACK` 未定义编译 | `ff_local_*` 退化、行为等价纯 F-Stack | NFR-1/FR-7 |
| UT-7 | 内核/F-Stack 地址端口冲突 | 返回 `-EADDRINUSE`，不静默 | 边界 |

> 用例落地参照 `tests/unit/` 既有 `*.c`+`*.ini` 组织；可按需引用 `[skill:c-unittest-expert]`（Unity）规范。

---

## 3. 集成测试用例

| 编号 | 场景 | 步骤 | 通过标准 | 对应需求 |
|---|---|---|---|---|
| IT-1 | 本机 curl 直访内核栈监听 | 启动示例（内核栈侧监听）→ 本机 `curl 127.0.0.1:port` / `curl <host_ip>` | HTTP 200 | FR-1 |
| IT-2 | 本机 ping | `ping <host_ip>` | 有回包 | FR-2 |
| IT-3 | 双栈并存 | 同进程内 F-Stack 业务监听 + 内核栈管理监听 | 业务走 DPDK NIC、管理走内核，互不干扰 | FR-3/FR-4 |
| IT-4 | 长稳/泄漏 | 大量短连接反复开关 | fd 数稳定、无泄漏（`ff_local_get_stats`） | FR-6 |

> 进程清理用 `/data/workspace/kill_process.sh`，临时文件用 `/data/workspace/rm_tmp_file.sh`。

---

## 4. 性能基线

| 编号 | 指标 | 方法 | 门禁 |
|---|---|---|---|
| PERF-1 | F-Stack 业务路径回归 | `FF_LOCAL_STACK` 关闭 vs 基线 | 吞吐/时延偏差 ≤ 噪声阈值（NFR-2） |
| PERF-2 | 开启本能力业务路径回归 | 仅内核侧监听空载，压测 F-Stack 业务 | 业务快路径无显著回归 |
| PERF-3 | 事件合并延迟 | 测内核事件取用节流（对照 `ff_hook_syscall.c:2333-2336`）对延迟影响 | 延迟在可接受区间 |
| PERF-4 | 内核侧管理面吞吐 | 本机 curl 并发 | 满足管理面预期（非高速路径） |

---

## 5. 覆盖率与门禁标准

- 复用 `tests/run_full_coverage.sh`（lcov）统计 `ff_local.{h,c}` 覆盖率。
- **门禁标准**：
  1. UT 全通过、新增代码行覆盖率达既有项目标准。
  2. IT-1~IT-4 全通过（本机 ping/curl 实测直访成功）。
  3. PERF-1/PERF-2 业务快路径无回归。
  4. 关闭开关时与纯 F-Stack 行为/性能一致（NFR-1/2）。
- 任一项失败 → 按 plan 的 bounce 规约打回上一里程碑修复（同一步骤 ≤3 次，超限转人工）。

---

## 6. 交叉验证要求
- 所有测试需**实际执行取证**（日志/抓包/覆盖率报告），禁止臆测。
- 测试断言中引用的代码行号与实际代码一致，冲突以代码为准。
