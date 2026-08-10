# 00 - issue #1076 原文与需求解析

> issue: https://github.com/F-Stack/f-stack/issues/1076
> 标题: F-STACK BEHAVIOR AT HIGH CPS
> 状态: 🟢 open（截至 2026-08-10）
> 作者: Sai-Raveendra-Kandregula
> 提出日期: 2026-06-16
> F-Stack 版本: 1.24

---

## 1. issue 原文摘要

### 1.1 场景描述

用户使用 f-stack 构建透明代理应用，在单核（single lcore）下进行高 CPS（Connections Per Second）压测。观察到以下现象链：

1. **单核 ~13k CPS 时 CPU 达到 100%**。
2. 超过该 CPS 后，**连接删除（teardown）出现延迟**——新连接到达速度超过 TCP 栈处理连接拆除的速度。
3. **活跃连接数持续堆积**——每个活跃连接持有发送/接收缓冲区的 mbuf。
4. **mbuf 池耗尽**——所有可用 mbuf 被堆积的活跃连接消耗殆尽。
5. **整个栈无响应**——包括 `ff_ipc` 工具（如 `ff_ipc netstat`），因为这些工具也依赖 mbuf 进行进程间通信。

### 1.2 用户诉求

> "If I did hit the maximum performance of my application, I would like to drop packets instead of my app getting unresponsive."

即：当达到应用性能极限时，**期望主动丢包（优雅降级 / backpressure）**，而非整个应用无响应。

### 1.3 用户配置

issue 中给出的关键配置参数：

| 参数 | 值 | 说明 |
|---|---|---|
| `dispatch_ring_size` | 16384 | dispatch ring 大小 |
| `rx_queue_size` / `tx_queue_size` | 4096 | 收发队列大小 |
| `hz` | 1000000 | FreeBSD 时钟频率（1MHz） |
| `kern.ipc.maxsockets` | 1048576 | 全局 socket 数上限（1M） |
| `net.inet.tcp.syncache.hashsize` | 32768 | syncache 哈希桶数 |
| `net.inet.tcp.tcbhashsize` | 262144 | TCB 哈希桶数 |
| `net.inet.tcp.sendspace` / `recvspace` | 65536 | TCP 发送/接收缓冲区初始大小 |
| `net.inet.tcp.sendbuf_max` / `recvbuf_max` | 16777216 | TCP 发送/接收缓冲区最大值（16MB） |

### 1.4 官方回复摘要

issue 仍处于 open 状态，官方给出了以下分析与建议：

- **根因确认**：单核 CPU 达 100% 时，TCP 栈连接拆除跟不上新连接到达速度，活跃连接堆积，每个连接持有发送/接收缓冲区的 mbuf，mbuf 池耗尽后整个栈无响应（含 `ff_ipc` 工具，因其也需 mbuf 通信）。
- **F-Stack 目前没有内置 backpressure 机制**在接近 mbuf 耗尽时自动丢弃新连接。
- **建议**：
  1. 水平扩展（主要方案）——增加 lcore 分散 CPS 负载。
  2. 增大 memory（hugepage）配置扩大 mbuf 池。
  3. 非 RACK/BBR 场景降低 `hz` 到 1000（减少定时器开销）。
  4. 应用层连接数限制 + RST 拒绝新连接实现优雅降级。
  5. memif 接口需软件 RSS 配合多 lcore 扩展。

---

## 2. 需求拆解

### 2.1 核心需求

用户要求调研**并发连接数（CC, Concurrent Connections）限制方案**，使 f-stack 在高 CPS 场景下能够优雅降级，而非整体无响应。

### 2.2 需求分层

| 层级 | 需求 | 优先级 |
|---|---|---|
| L1 | 验证当前版本是否仍存在 issue 描述的场景 | 必须（前置） |
| L2 | 调研 FreeBSD 协议栈自带的 CC 限制机制是否可用 | 必须（用户明确要求优先） |
| L3 | 若原生机制可用，给出使用方法与测试结果 | 必须 |
| L4 | 若原生机制不足，设计 f-stack 架构级 CC 限制方案 | 备选 |
| L5 | 方案交用户审核 | 必须 |

### 2.3 本轮范围边界

- **本轮仅做调研与方案设计**，不落地正式代码改造。
- 实机测试仅用于验证 issue 场景是否仍存在、以及原生机制的实际效果。
- 文档仅生成中文版，放 `docs/issue_1076/zh_cn/`。

---

## 3. 成功判据

| 编号 | 判据 | 验证方式 |
|---|---|---|
| SC-1 | 明确当前版本是否仍存在 issue 场景（mbuf 耗尽→栈无响应） | 实机压测 E1 |
| SC-2 | 代码级确认 maxsockets / ipfw limit / somaxconn / syncache 在 f-stack 用户态栈中的完整性 | 代码探测报告 02 |
| SC-3 | 实机测试原生机制的实际效果（是否有效限制连接数、达限行为） | 实机测试 E2~E5 |
| SC-4 | 给出推荐方案（零代码 / 小改动 / 组合方案），含配置示例与权衡分析 | 方案设计文档 03 |
| SC-5 | 文档经独立审核 agent 门禁通过 | 审核门禁报告 06 |
| SC-6 | 更新中英文 issue-ana 的 #1076 条目 | issue-ana 更新 |

---

## 4. issue-ana 现有条目

issue-ana 中已有 #1076 的初步条目（中文 `docs/zh_cn/f-stack-issue-ana.md:1444-1446`，英文 `docs/f-stack-issue-ana.md:1440-1442`），结论为：

- 根因：mbuf 耗尽，无 backpressure 机制。
- 建议：水平扩展 / 增大 mbuf 池 / 降低 hz / 应用层限制。

本轮调研将在此基础上**深化**：验证原生 CC 限制机制的可用性、实机测试效果、并给出更具体的方案设计。

---

## 5. 相关 issue 交叉参考

| issue | 关联点 |
|---|---|
| #93 | CPS 测试瓶颈来自单 client 端口数上限和内核 PCB 锁竞争 |
| #410 | 多核非持久连接 CPS 提升瓶颈在客户端侧临时端口 |
| #519 | CPS 基准测试（nginx reuseport） |
| #649 | 低延迟实时配置（`pkt_tx_delay=0` / `idle_sleep=0` / `delayed_ack=0` / `hz=1000`） |
| #868 | 内存不释放（DPDK hugepage 预分配 + glibc ptmalloc2 延迟释放） |
