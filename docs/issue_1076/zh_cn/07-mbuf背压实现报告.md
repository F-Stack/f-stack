# 07 - mbuf 水位背压实现报告

> f-stack issue #1076: 方案 B（mbuf 水位背压）代码实现
> 实现时间：2026-08-10
> 前置文档：00-06 号文档（调研、方案设计、审核门禁）

---

## 1. 实现概述

在 `process_packets()` 收包入口添加 mbuf 池水位检查：当可用 mbuf 数低于配置阈值 `mbuf_low_watermark` 时，丢弃 TCP SYN 包（不回 SYN-ACK），防止新连接继续消耗 mbuf 导致整个栈无响应。已建立连接的数据包不受影响。

**设计原则**：
- 默认禁用（`mbuf_low_watermark=0`），零回归
- 仅丢弃 SYN（新连接发起包），不影响已有连接
- 仅对 RX burst 收到的包生效，跳过 dispatch ring 分发的包
- per-packet 检查，`rte_mempool_avail_count` 开销可忽略

---

## 2. 代码变更

### 2.1 修改文件清单

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `lib/ff_dpdk_if.c` | 新增函数 + 修改 | `is_tcp_syn()` 辅助函数 + `process_packets()` 入口水位检查 |
| `lib/ff_config.h` | 新增字段 | `struct ff_config.dpdk` 添加 `mbuf_low_watermark` |
| `lib/ff_config.c` | 新增解析 + 默认值 | `MATCH("dpdk","mbuf_low_watermark")` + 默认值 0 |
| `config.ini` | 新增注释 | `# mbuf_low_watermark=0`（不入库） |

### 2.2 is_tcp_syn() 函数

位置：`lib/ff_dpdk_if.c`，`process_packets()` 之前

功能：解析 Ethernet/VLAN/IPv4/IPv6/TCP 头，判断是否为纯 SYN 包（SYN=1, ACK=0）。

解析流程：
1. 检查最小长度（Ethernet header）
2. 解析 Ethernet header，跳过 VLAN tag（与 `protocol_filter` 相同模式）
3. IPv4：检查 `next_proto_id == IPPROTO_TCP`，按 IHL 偏移定位 TCP header
4. IPv6：检查 `proto == IPPROTO_TCP`，按固定 40 字节偏移定位 TCP header
5. 检查 TCP flags：`(SYN_FLAG | ACK_FLAG) == SYN_FLAG`（纯 SYN，非 SYN-ACK）

安全检查：
- 每层解析前验证剩余长度，防止越界读
- IPv4 IHL 最小值检查（`>= sizeof(struct rte_ipv4_hdr)`）
- IPv6 不处理扩展头（简化设计，SYN 包通常无扩展头）

### 2.3 process_packets() 水位检查

位置：`lib/ff_dpdk_if.c`，`process_packets()` 内 for 循环中，`data`/`len` 提取之后、流量统计之前

逻辑：
```c
if (!pkts_from_ring && ff_global_cfg.dpdk.mbuf_low_watermark > 0 &&
    rte_mempool_avail_count(pktmbuf_pool[qconf->socket_id]) <
        ff_global_cfg.dpdk.mbuf_low_watermark &&
    is_tcp_syn(data, len)) {
    ff_traffic.rx_dropped += rtem->nb_segs;
    rte_pktmbuf_free(rtem);
    continue;
}
```

条件说明：
- `!pkts_from_ring`：跳过 dispatch ring 分发的包（已被前一个 lcore 处理过）
- `mbuf_low_watermark > 0`：仅当用户显式配置时启用
- `rte_mempool_avail_count(...) < watermark`：当前 lcore socket 的 mbuf 池可用数低于阈值
- `is_tcp_syn(data, len)`：该包是 TCP SYN（新连接发起）

命中后：计入 `rx_dropped`，释放 mbuf，跳过后续协议栈处理。

### 2.4 配置项

| 配置项 | 位置 | 类型 | 默认值 | 说明 |
|--------|------|------|--------|------|
| `mbuf_low_watermark` | `[dpdk]` 段 | unsigned | 0 | 0=禁用；>0 时低于该值的可用 mbuf 数触发 SYN 丢弃 |

---

## 3. 编译与测试

### 3.1 编译验证

- **make clean**：通过 `rm_tmp_file.sh` 清理 258 个中间产物（.o/生成文件）+ machine_include 目录
- **make**：完整编译通过，exit code 0，无 warning/error
- **helloworld 链接**：成功生成 helloworld 二进制

### 3.2 启动测试

- helloworld primary 进程启动成功
- FreeBSD 栈初始化完整（79 行日志，含全部 sysctl 设置）
- 无 error/fail/panic/segfault 消息
- `mbuf_low_watermark=0`（默认禁用），新代码路径不执行，零回归

### 3.3 未完成的测试

| 项目 | 原因 |
|------|------|
| 高 CPS 下 mbuf 耗尽场景复现 | DPDK 网卡与 f-stack-client 二层网络不通（同 04 报告） |
| 水位背压触发验证 | 需高 CPS 压测环境 |
| `mbuf_low_watermark` 阈值量化 | 需实测确定合理值 |

---

## 4. 与方案设计的对应关系

05 报告 `5.2 如需实现 mbuf 水位背压（方案 B）` 中列出的修改位置：

| 报告中的位置 | 实际实现位置 | 一致性 |
|-------------|-------------|--------|
| `lib/ff_dpdk_if.c` 2024 行（process_packets 入口） | `process_packets()` 内 for 循环，data/len 提取后 | ✅ |
| 新增 `is_tcp_syn()` 辅助函数 | `process_packets()` 之前 | ✅ |
| `lib/ff_config.c` / `ff_config.h` 新增配置项 | `MATCH("dpdk","mbuf_low_watermark")` + `unsigned mbuf_low_watermark` | ✅ |
| `config.ini` `[dpdk]` 段新增 | `# mbuf_low_watermark=0` 注释 | ✅ |

---

## 5. 使用指南

### 5.1 启用方法

在 `config.ini` 的 `[dpdk]` 段添加：

```ini
[dpdk]
mbuf_low_watermark=3276
```

建议初始值为 mbuf 池总容量的 10%，需根据实际压测调整。

### 5.2 配合其他机制

本实现是方案 C（组合方案）的第四道防线，建议同时启用：

1. **maxsockets**（`[freebsd.boot]` 段）：全局 socket 数硬限
2. **ipfw limit**：per-source 并发连接限制
3. **somaxconn / syncache**：半连接和 accept 队列限制
4. **mbuf_low_watermark**（本实现）：mbuf 池水位背压

---

## 6. 代码 diff 摘要

```
lib/ff_config.h:  +1 line  (mbuf_low_watermark 字段)
lib/ff_config.c:  +3 lines (MATCH 分支 + 默认值)
lib/ff_dpdk_if.c: +57 lines (is_tcp_syn 函数 48 行 + 水位检查 9 行)
config.ini:       +2 lines (注释，不入库)
```

总计：约 61 行新增代码，0 行删除，零格式抖动。
