# F-Stack Issue #842 调研计划

> **Issue**: [#842 Extremely Bad Latency on TCP Connection for receiving Data](https://github.com/F-Stack/f-stack/issues/842)
> **状态**: Open（无评论，无标签，2024-09-23 由 winstonzhao 提交）
> **本轮目标**: 在物理机上复现场景，对比内核 vs F-Stack TCP 客户端接收大量数据的延迟，定位根因（配置级 vs 代码级），必要时修复并回归测试，产出中文 spec 文档。

---

## 1. Issue 背景与核心问题

### 1.1 问题描述

F-Stack TCP 客户端接收大量数据时，延迟约为原生 Linux 内核的 **3.75 倍**（F-Stack ~7.5s vs Linux ~2s）。

### 1.2 测试场景

- **Server**: Python TCP echo server，发送 100 万条时间戳消息（`str(time.time_ns()) * 200`，每条约 3800 字节）
- **Kernel client**: 标准 Linux socket + epoll(ET) + recv，测量首尾延迟差
- **F-Stack client**: ff_socket/ff_connect/ff_epoll/ff_recv，同样的业务逻辑
- **Buffer**: 4096 字节

### 1.3 关键线索

Issue 作者**已使用优化配置**（idle_sleep=0, pkt_tx_delay=0, delayed_ack=0, recvspace=1677721, bbr, hz=100），F-Stack 仍慢 3.75 倍。这暗示可能存在代码级问题，而非纯配置问题。

### 1.4 相关 Issue

| Issue | 状态 | 结论 |
| --- | --- | --- |
| #540 | closed | 正确配置下 F-Stack 26μs vs 内核 36μs（F-Stack 更快） |
| #659 | closed | pkt_tx_delay=100 + delayed_ack=1 导致转发不稳定 |
| #664 | closed | pingpong 场景 delayed_ack=1 是主要瓶颈 |
| #811 | closed | 接收无延迟（burst 读取即注入协议栈），发送有 TX drain 机制 |
| #842 | **open** | 官方确认已收到报告，将测试排查，暂无结论 |

---

## 2. 测试环境

### 2.1 网络拓扑

| 角色 | 机器 | IP | 网卡 |
| --- | --- | --- | --- |
| Python echo server | f-stack-client | <CLIENT_IP> | eth1 |
| F-Stack client | 本机 | <DPDK_NIC_IP> | DPDK NIC (port0) |
| Kernel client | 本机 | <DPDK_NIC_IP> | eth1 (内核栈) |
| Kernel client (lo) | 本机 | 127.0.0.1 | lo |

### 2.2 软件版本

- F-Stack: 1.26（FreeBSD 15.0 + DPDK 23.11.5）
- Python: 3.11.6 (f-stack-client)
- GCC: 默认 -O2（lib/Makefile DEBUG 行已注释）

### 2.3 当前 config.ini 关键参数

| 参数 | 当前值 | #842 优化值 |
| --- | --- | --- |
| idle_sleep | 20 | 0 |
| pkt_tx_delay | 100 | 0 |
| delayed_ack | 1 | 0 |
| recvspace | 8192 | 1677721 |
| sendspace | 16384 | 1677721 |
| cc.algorithm | cubic | bbr |
| KNI | 注释掉 | 无配置 |

---

## 3. 测试矩阵

| 测试 | 栈 | idle_sleep | pkt_tx_delay | delayed_ack | recvspace | 编译 | 目的 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T1 | Kernel | N/A | N/A | N/A | N/A | -O2 | 内核基线 |
| T2 | F-Stack | 20 | 100 | 1 | 8192 | -O2 | 当前配置基线 |
| T3 | F-Stack | 0 | 0 | 0 | 1677721 | -O2 | #842 优化配置 |
| T4 | F-Stack | 0 | 0 | 0 | 8192 | -O2 | 隔离 recvspace |
| T5 | F-Stack | 0 | 0 | 1 | 8192 | -O2 | 隔离 delayed_ack |
| T6 | F-Stack | 20 | 100 | 1 | 8192 | -O0 | 验证 -O0 影响 |

**每项测试运行 3 次取中位数。** T1-T3 核心对比，T4-T5 参数隔离，T6 编译优化验证。

---

## 4. 代码分析目标

### 4.1 接收路径

```
NIC RX Queue
  → rte_eth_rx_burst (MAX_PKT_BURST=32)
  → process_packets (逐包, count=1)
    → protocol_filter
    → ff_veth_input (rte_mbuf → FreeBSD mbuf)
      → ff_mbuf_gethdr (分配新 mbuf header)
      → if_input → FreeBSD TCP/IP 栈
        → soreceive → kern_recvit → ff_recv (用户态)
```

**关键文件**:
- `lib/ff_dpdk_if.c:2748-2790` — RX burst + process_packets 逐包处理
- `lib/ff_veth.c` — ff_veth_input: rte_mbuf → FreeBSD mbuf 转换
- `lib/ff_syscall_wrapper.c:1499-1544` — ff_recv → kern_recvit

### 4.2 TX drain 机制（影响 ACK 延迟）

- `lib/ff_config.h:56` — `#define BURST_TX_DRAIN_US 100`
- `lib/ff_dpdk_if.c:83-84` — `idle_sleep` / `pkt_tx_delay` 静态变量
- `lib/ff_dpdk_if.c:2643-2645` — `drain_tsc` 计算
- `lib/ff_dpdk_if.c:2728-2743` — TX drain 逻辑

### 4.3 main_loop 调度

- `lib/ff_dpdk_if.c:2806-2809` — 用户回调门控: `(!idle || cur_tsc - usch_tsc >= drain_tsc)`
- `lib/ff_dpdk_if.c:2812-2813` — idle_sleep 逻辑

### 4.4 待确认问题

1. ACK 是否走 TX drain 路径（而非直接发送）？
2. 高吞吐场景下 `idle` 是否始终为 0（不触发 idle_sleep）？
3. process_packets 逐包处理（count=1）是否可优化为批量？
4. ff_veth_input 的 mbuf 转换开销在高吞吐下占比多大？
5. example/Makefile 的 -O0 是否影响 F-Stack 客户端公平性？

---

## 5. Agent Team 分工

### 5.1 Leader（主 agent）

- 统筹全局，轮询等待子 agent
- 亲自执行：环境搭建、测试运行、plan.md 生成（纯规划单一角色）
- 严禁：子 agent 全部完成前提前退出
- 超时探测：对子 agent 设置分钟级超时，定时轮询 + 旁路探测（读产出文件）

### 5.2 子 agent 分工

| Agent | 角色 | 任务 |
| --- | --- | --- |
| code-analyzer | 代码探测 | 深度分析接收路径/TX drain/main_loop 代码级瓶颈 |
| doc-writer | 文档撰写 | 生成 spec 文档 00-04 |
| doc-reviewer | 文档审核 | 审核 spec 文档，门禁检查 |

**角色分离铁律**: 写代码/文档 与 审核 必须不同 agent。

### 5.3 回退补救

- 子 agent 超时无响应 → 旁路探测（读产出文件）确认状态
- 子 agent 输出错误 → leader 接管（后续审核 spawn 新 agent）
- 连续打回 ≤3 次 → 转人工决策

---

## 6. 里程碑

| # | 里程碑 | 产出 | 依赖 |
| --- | --- | --- | --- |
| M0 | 生成 plan.md | 本文件 | - |
| M1 | 环境搭建 | Python server + 测试客户端 + 连通性验证 | M0 |
| M2 | 基线测试 | T1-T3 延迟数据 | M1 |
| M3 | 深度代码分析 | 接收路径瓶颈分析报告 | M2 |
| M4 | 参数隔离+修复 | T4-T6 数据 + 修复（如有） | M3 |
| M5 | 回归测试 | 零回归确认 | M4 |
| M6 | 文档产出 | spec 00-04 + issue-ana 更新 | M5 |

---

## 7. 规约合规

- rm → `/data/workspace/rm_tmp_file.sh`
- kill → `/data/workspace/kill_process.sh`
- chmod → `/data/workspace/chmod_modify.sh`
- 改代码先 `make clean` 再编译
- config.ini 本地测试值不入库
- lib 最小注释
- commit message 英文 1-3 句
- 实际执行不臆测，代码为准，交叉验证

---

## 8. 预期结论

- **场景 A**: -O2 + 优化配置后 F-Stack 接近内核（差距 <20%）→ 根因为配置+编译优化，更新 issue-ana.md
- **场景 B**: 优化配置后仍慢 2x+ → 代码级瓶颈，实施修复 + 回归测试 + 更新文档
- **场景 C**: F-Stack 优于内核 → 更新 issue-ana.md，结论为 issue 描述场景在本环境不复现
