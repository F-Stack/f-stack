# 07 测试与性能基线规格

> **文档编号**：SPEC-KE-07
> **版本**：v4（共存范式返工重写）
> **日期**：2026-06-16
> **状态**：编写中
> **作用域**：本特性（双栈共存：hook FF_KERNEL_EVENT + 原生统一事件 + config 共存开关 + 客户端共存）的单元/集成/性能基线测试方案与门禁标准。
> **对齐**：`tests/unit`（**cmocka**，*.c + *.ini）、`tests/integration`、覆盖率 `tests/run_full_coverage.sh`（lcov）。

---

## 1. 测试分层

| 层级 | 目录 | 框架/方式 | 覆盖目标 |
|---|---|---|---|
| 单元测试 | `tests/unit/` | cmocka | config 共存开关解析、fd 归属、原生受管内核 fd、事件合并边界、零回归 |
| 集成测试 | `tests/integration/` 或 demo | 端到端进程 + 本机工具 | **同进程双栈共存**：F-Stack 业务 + 内核监听被本机直访 + 客户端连本机/外部 |
| 性能基线 | `tests/` | 压测 + 对比 | 共存开/关对 **F-Stack 业务快路径** 无回归 |

---

## 2. 单元测试用例（cmocka）

| 编号 | 用例 | 断言 | 对应需求 |
|---|---|---|---|
| UT-1 | `ini_parse_handler` 解析 `[stack] kernel_coexist=1/0` | 正确填充 `ff_config.stack.kernel_coexist` | FR-9 |
| UT-2 | config 缺 `[stack]` | 默认 `kernel_coexist=0`（纯 F-Stack） | FR-9/NFR-1 |
| UT-3 | 原生 `ff_socket` 默认/`SOCK_FSTACK` | 走 F-Stack（逐字节零回归，路径不变） | FR-1/NFR-1 |
| UT-4 | 原生 `ff_socket(SOCK_KERNEL)`（共存启用） | 建受管内核 fd 并登记归属（`is_*_kernel_fd==true`） | FR-7 |
| UT-5 | 原生 `ff_socket(SOCK_KERNEL)`（共存禁用） | 按约定报错或退化（不静默旁路 F-Stack） | 边界/`05 §8` |
| UT-6 | fd 归属判定 | 受管内核 fd 与 F-Stack fd 正确区分 | FR-8 |
| UT-7 | 原生 `ff_epoll_ctl` 分流 | 内核 fd→宿主 epoll；F-Stack fd→kqueue | FR-6 |
| UT-8 | 原生 `ff_epoll_wait` 合并 | 同时返回两栈事件、不丢失 | FR-6 |
| UT-9 | `type` 同置 `SOCK_KERNEL\|SOCK_FSTACK` | 按优先级走 F-Stack | 边界 |
| UT-10 | `ff_close` 受管内核 fd | 联动释放、清归属表、无泄漏 | FR-8 |
| UT-11 | hook 模式 `maxevents=1` | 返回 `-EINVAL`（`:2212-2218`） | 边界 |
| UT-12 | 共存关闭 / 默认 | 行为等价纯 F-Stack | NFR-1/NFR-3 |

> 落地参照 `tests/unit/` 既有 `*.c`+`*.ini`（cmocka）组织。

---

## 3. 集成测试用例（同进程双栈共存为核心）

| 编号 | 场景 | 步骤 | 通过标准 | 对应需求 |
|---|---|---|---|---|
| IT-1 | **同进程双栈并存** | 启动 demo：同一进程内 F-Stack 业务监听（默认）+ `SOCK_KERNEL` 内核监听 | 两监听均建立；F-Stack 业务经 NIC、内核监听经内核 | FR-1/FR-2/FR-6 |
| IT-2 | 服务端本机直访内核监听 | 本机 `curl 127.0.0.1:<kport>` / `curl <host_ip:kport>` | HTTP 200（同时业务监听仍在位） | FR-2 |
| IT-3 | 本机 ping | `ping <host_ip>` | 有回包 | FR-3 |
| IT-4 | 客户端连本机服务 | demo 内 `SOCK_KERNEL` 客户端 `connect 127.0.0.1`/本机 IP | 连接建立、收发正常；业务客户端仍走 F-Stack | FR-4 |
| IT-5 | 客户端连外部内核服务 | `SOCK_KERNEL` 客户端 `connect <外部内核服务>` | 连接建立、收发正常 | FR-5 |
| IT-6 | config 共存开关 | `kernel_coexist=0` 重启 → `SOCK_KERNEL` 按约定不旁路 | 关闭时纯 F-Stack | FR-9/NFR-1 |
| IT-7 | 多进程差异化 | 两进程不同 config（共存开/关） | 各自独立生效 | NFR-6 |
| IT-8 | 长稳/泄漏 | 大量短连接反复开关（含两栈） | fd 数稳定、无泄漏 | FR-8 |

> 进程清理用 `/data/workspace/kill_process.sh`，临时文件用 `/data/workspace/rm_tmp_file.sh`，权限用 `/data/workspace/chmod_modify.sh`。

---

## 4. 性能基线

| 编号 | 指标 | 方法 | 门禁 |
|---|---|---|---|
| PERF-1 | **F-Stack 业务快路径回归** | 共存关闭 vs 共存启用但只压 F-Stack 业务 | 吞吐/时延偏差 ≤ 噪声阈值（NFR-2） |
| PERF-2 | 默认路径零开销 | 共存分支对默认/`SOCK_FSTACK` 路径影响 | 零/可忽略（NFR-1） |
| PERF-3 | 内核侧旁路吞吐 | 本机 curl 并发内核监听 / 客户端 connect | 满足管理面预期（非高速路径） |
| PERF-4 | 事件合并延迟 | 内核事件节流对延迟影响 | 可接受区间 |

> **注**：v3 的「纯内核 loopback bench」口径已作废（它根本没跑 F-Stack）。v4 性能核心是**证明共存不拖累 F-Stack 业务快路径**。

---

## 5. 覆盖率与门禁标准

- 复用 `tests/unit/run_coverage.sh`/`tests/run_full_coverage.sh`（lcov）统计本特性改动覆盖率。
- **门禁标准**：
  1. UT 全通过、新增代码行覆盖率达既有标准。
  2. IT-1（同进程双栈并存）+ IT-2~IT-5（直访/ping/客户端）实测成功（环境不具备真实 NIC 时，F-Stack 业务面 skip+实测证据，内核侧 loopback 必测）。
  3. PERF-1/PERF-2 F-Stack 业务快路径与默认路径无回归。
  4. 共存关闭/默认时与纯 F-Stack 行为/性能一致（NFR-1/NFR-3）。
- 任一项失败 → bounce 打回上一里程碑（同步骤≤3 次，超限转人工）。

---

## 6. 交叉验证要求
- 所有测试实际执行取证（日志/抓包/覆盖率），禁止臆测。
- **必须实测证明 F-Stack 业务面在共存下仍在位、未被旁路**（NFR-3）。
- 客户端用例须实测 `connect` 经内核栈到达（抓包确认走内核而非 DPDK 网卡）。
