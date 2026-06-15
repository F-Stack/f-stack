# 测试方案：单元 / 集成 / 性能基线（07-test-spec.md）

> **文档编号**：SPEC-KE-07
> **版本**：v0.1 草稿
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：本地 socket/fd/event 访问 lib 的测试设计与门禁标准
> **现有测试体系**：`tests/unit/`（Unity 风格 `.c` + `.ini`）、`tests/integration/`、`tests/run_full_coverage.sh`、`tests/full_coverage_report/`

---

## 1. 测试分层与对齐

| 层次 | 位置（建议） | 框架/方式 | 对齐现状 |
|---|---|---|---|
| 单元测试 | `tests/unit/` | Unity（与现有一致） | 既有 14 个 `.c` + 35 个 `.ini` |
| 集成测试 | `tests/integration/` | 脚本 + 真实 F-Stack 实例 | 既有目录 |
| 性能基线 | 独立基线脚本 + 报告 | pktgen/iperf/ping/curl 计量 | 参照 `ld_preload_ring_spec` 性能分析范式 |
| 覆盖率 | `tests/run_full_coverage.sh` | lcov → `full_coverage_report/` | 复用 |

## 2. 单元测试（UT）

聚焦**纯函数/可隔离逻辑**，mock DPDK/内核依赖：

| 用例 | 验证点 | 锚点 |
|---|---|---|
| UT-1 端口位图 set/get | tcp/udp 端口位图置位与查询正确 | `ff_dpdk_kni.c:59-69`（`set_bit/get_bit`、`*_port_bitmap`） |
| UT-2 method→kni_accept 映射 | `accept`→1、`reject`→0 | `ff_dpdk_if.c:547-551` |
| UT-3 action 字符串→枚举 | `get_kni_action` 解析 | `ff_dpdk_if.c:552` + `ff_msg.h:118-123` |
| UT-4 `handle_knictl_msg` 状态机 | SET 各 action 切换、GET 回读 | `ff_dpdk_if.c:1960-1977` |
| UT-5 `ff_local_*` 参数校验 | 非法 proto/越界端口/空指针 | `05-interface-design.md §2` |
| UT-6 secondary 行为 | 连接级/创建口接口在 secondary 返回不支持 | `ff_dpdk_if.c:609-611` |

**门禁**：UT 全通过；新增代码行覆盖率 ≥ 既有基线（由 `run_full_coverage.sh` 出报告）。

## 3. 集成测试（IT）

需真实 DPDK + virtio-user 环境（`/dev/vhost-net`、hugepage、特权）：

| 用例 | 步骤 | 期望 |
|---|---|---|
| IT-1 本机 ping | 启用 `[kni] enable=1,method=reject`，本机 `ping <nic_ip>` | 通（ICMP 经 virtio-user 入内核） |
| IT-2 本机 curl | 对未列入业务端口的服务 `curl` | 成功 |
| IT-3 业务端口仍走 fstack | `method=reject` 下业务端口流量不进内核 | fstack 正常处理、KNI 计数 0 |
| IT-4 运行时切换 | `ff_local_set_action(ALL_TO_KNI/ALL_TO_FF/DEFAULT)` | 分流行为即时改变（`ff_dpdk_if.c:1792-1801`） |
| IT-5 端口热更新 | `ff_local_rule_set` 增删端口 | 新规则生效 |
| IT-6 依赖缺失 | 卸载 `vhost_net`/无权限 | `ff_local_init` 明确报错、业务不受影响 |
| IT-7（M4）双栈事件 | `ff_local_epoll_*` 同时收内核 fd 与 fstack 事件 | 事件正确合并（参照 `ff_hook_syscall.c:2324-2399`） |

**门禁**：IT-1~IT-6 全通过；IT-7 在 M4 启用时通过。

## 4. 性能基线（PERF）

| 指标 | 方法 | 门禁 |
|---|---|---|
| PERF-1 业务快路径回归 | KNI 关闭 vs 开启（`ALL_TO_FF`）对比 pps/吞吐/时延 | 关闭时**零回归**；开启 `ALL_TO_FF` 回归 ≤ 既有 KNI 基线 |
| PERF-2 分流检查开销 | `method=reject` 下业务流量 pps | 在限速默认关闭时开销可量化、可接受 |
| PERF-3 内核侧吞吐 | virtio-user 路径 ping 时延 / curl 吞吐 | 满足管理面可用性（非高性能目标） |
| PERF-4 限速生效 | 配置 `console_packets_ratelimit`/`general_packets_ratelimit`/`kernel_packets_ratelimit` | 实测速率不超阈值（`config.ini:265-267`） |

**采集**：记录环境（CPU/网卡/DPDK 版本 23.11.5 或 24.11.6/内核）、方法、原始数据与图表，留档（参照 `ld_preload_ring_spec` 的离线分析文档范式）。

## 5. 交叉验证要求
- 所有"期望经内核"的用例须以 `tcpdump -i vethX` 或内核计数器实测确认，不臆测。
- KNI 计数（`kni_interface_stats`，`ff_dpdk_kni.c:72-87`）作为分流正确性的客观证据。

## 6. 测试门禁汇总（进入 M5 验收的标准）
1. UT 全绿 + 覆盖率不降；
2. IT-1~IT-6 全绿（M4 时含 IT-7）；
3. PERF-1 零回归为**硬门禁**；
4. 所有结果有实测留痕（命令、输出、计数器/抓包）。
