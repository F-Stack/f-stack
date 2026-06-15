# 09 实现版 Plan：本地 socket/fd/event 支持（M1-M6）

> **文档编号**：SPEC-KE-09（实现阶段计划）
> **日期**：2026-06-15
> **状态**：执行中
> **依据**：本目录 v3 spec（00-08）；行号以实际代码为准，gatekeeper 复核。

---

## 0. 范围与门禁（用户确认）

- **M1-M6 全做**：标记标准化 / 服务端内核栈监听 / 客户端 connect 选栈 / config.ini 全局默认开关 / 原生 `ff_socket` 标记识别 / 双栈事件+可观测 / 测试与性能基线。
- **硬门禁（无条件全绿）**：编译通过 + cmocka 单测全绿 + 覆盖率 G8 达标。
- **目标门禁**：尽力实搭 DPDK 运行时实跑集成（curl/ping/客户端 connect）与性能基线；确不具备真实 NIC/大页时按 skip 并附**实测失败证据（命令+输出）**。
- **NFR-1 零回归**：默认/`SOCK_FSTACK` 路径与改造前逐字节一致。

---

## 1. Agent Team 拓扑（harness + spec 驱动）

| Agent | 角色 | 职责 |
|---|---|---|
| **Leader** | 统筹+执笔+裁决 | 全局编排、改码、门禁裁决、commit、bounce 计数 |
| **build** | 编译（只读取证+实跑构建） | 编译 lib / libff_syscall.so / tests，报告错误 |
| **unit-test** | 单测编写 | cmocka 用例（`test_ff_config` 扩展 + 原生 `ff_socket` 标记用例） |
| **review** | 代码评审（只读） | 最小 diff/零回归/风格/规约核验 |
| **test** | 集成/性能 | 示例 + 端到端 + 性能基线实跑或 skip+证据 |
| **gatekeeper** | 门禁（只读） | 逐条断言 + 门禁条目核验，FAIL 打回 |

**门禁回退**：任一阶段失败打回上一步；**同一步骤 bounce ≤3 次**，超限**停止转人工**；bounce 记入 `08`。

---

## 2. 改造点（实测锚点，以代码为准）

| 里程碑 | 文件 | 改动 |
|---|---|---|
| M3 | `lib/ff_config.h:253` | `struct ff_config` 增 `struct { int default_to_kernel; } stack;`（仿 kni 段 :310-319） |
| M3 | `lib/ff_config.c:956` `ini_parse_handler` | 增 `MATCH("stack","default_stack")` 解析 `fstack`/`kernel`；`ff_default_config:1346` memset 0→默认 fstack 自动成立；必要时加校验 |
| M3 | `config.ini`（项目根） | 增 `[stack] default_stack=fstack` 示例段 |
| M1 | 对外头文件（`lib/ff_api.h:63+` 或新增 `ff_stack_select.h`） | 暴露 `SOCK_KERNEL`/`SOCK_FSTACK` 选栈约定 + 语义/优先级注释 |
| M4 | `lib/ff_syscall_wrapper.c:912` `ff_socket` | 入口加 `SOCK_KERNEL && !SOCK_FSTACK` 识别分支（内核 socket 等价路径）；默认/`SOCK_FSTACK` 走原 `linux2freebsd_socket_flags:668`→`sys_socket` 逐字节零开销 |
| M5/M1/M2 | `adapter/syscall/ff_hook_syscall.c` | 复核固化选栈（`:387-390`）/connect（`:858`）/双栈事件（`:2324+`）；胶水层按 `ff_global_cfg.stack.default_to_kernel` 注入默认；可观测 `ff_stack_get_stats` |
| M6 | `tests/unit/test_ff_config.c` + `Makefile` | `[stack]` 解析/默认/优先级 cmocka 用例；新增原生 `ff_socket` 标记用例并入 P 分组 |
| M6 | `example/`、`tests/integration/` | 双栈示例 + 端到端（curl/ping/client-connect/config 默认/多进程） |
| 文档 | `07-test-spec.md` | Unity→cmocka 校正 |

---

## 3. 关键设计决策

- **复用优先**：hook 模式选栈已实现，本轮以"复核固化 + 标准化 + 补齐"为主。
- **标记优先级**：`选栈 = app标记 ?? config默认 ?? F-Stack`，与 `ff_hook_socket:387`（`SOCK_KERNEL && !SOCK_FSTACK`）一致。
- **M4 边界（如实记录）**：本轮在 `ff_socket` 入口实现 `SOCK_KERNEL` 识别分支；原生模式下后续 `ff_bind/ff_listen/...` 的内核 fd 全链路归属路由属更大改造，按 spec 作为边界/后续项明确标注，避免误导。
- **可达性分层**：M3/M4 走 cmocka 单测（host 编译、无需 DPDK 运行时）；M1/M2/M5 端到端走集成（DPDK 运行时，优先 `vdev`+`--no-huge` 规避物理 NIC/大页）。

---

## 4. 执行步骤（对应 plan 待办）
1. prep-plan-team（本文 + 建团）。
2. impl-config-marker：M3+M1（config/marker/header）+ 编译。
3. impl-native-hook：M4 + M5/M1/M2 hook 固化 + 编译 lib 与 libff_syscall.so。
4. unit-tests：cmocka 单测全绿 + G8。
5. integration-perf：示例 + 集成/性能实跑或 skip+证据。
6. gate-review：门禁核验，FAIL 打回（≤3 转人工），更新 07/08。
7. commit-cleanup：英文简短 commit + 清理。

## 5. 工作区脚本规约
删文件 `/data/workspace/rm_tmp_file.sh`；停进程 `/data/workspace/kill_process.sh`；改权限 `/data/workspace/chmod_modify.sh`；`make install` 类（非直接 chmod）可执行。
