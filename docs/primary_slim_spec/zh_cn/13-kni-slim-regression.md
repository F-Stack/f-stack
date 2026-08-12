# 13. primary_slim=1 + KNI 开启时数据通路断裂修复

## 1. 问题现象

`primary_slim=1` + KNI `enable=1` + `owner_proc_id=1` 配置下：

- HTTP（TCP/80 数据面）正常，`http_code=200`，延迟约 1.3ms
- ping（ICMP，经 KNI 转发到 kernel）100% 丢包
- `veth0` 接口存在但 RX 统计不增长（包未到达 tap device）

对照组 `primary_slim=1` + KNI 关闭时 ping 0% 丢包、HTTP 200，问题仅在 KNI 开启时出现。

## 2. 根因定位

### 2.1 初始假设（被推翻）

假设 `primary_slim=1` 时 primary 在 `init_lcore_conf()` early return（`ff_dpdk_if.c:541-546`）跳过了 `init_kni()`，导致 KNI vdev/ring 未创建。

**实测推翻**：primary 的 f-stack lib 日志含 `VDEV_BUS: vdev_probe virtio_user0` 和 `ff_kni_alloc` 输出，`veth0` 接口也存在，证明 `init_kni()` 在 primary 中正常执行。

### 2.2 真实根因：virtio_user vdev 多进程 TX 限制

secondary 调用 `rte_eth_tx_burst(Port 1 = virtio_user0)` 返回成功（32 包），但包**未实际到达 veth0（tap device）**。

`init_port_start()` 中 `total_nb_ports *= 2`（包含 virtio_user Port 1）**仅对 PRIMARY 生效**（`ff_dpdk_if.c:865-868`），secondary 的 `total_nb_ports = nb_ports`（仅物理端口），secondary 在端口循环中 `continue` 跳过 `dev_configure`/`queue_setup`/`dev_start`（`:1106-1108`）。

因此 secondary 侧 Port 1（virtio_user0）的 TX 队列未初始化，`rte_eth_tx_burst` 虽返回成功但写入无效 virtqueue，包被静默丢弃。这是 DPDK virtio_user PMD 的多进程限制——virtio_user 的 virtqueue 不能被未配置队列的 secondary 进程共享使用。

### 2.3 为什么 HTTP 正常但 ping 不通

- **HTTP（TCP）**：reject 模式下，TCP 匹配 `tcp_port` 列表 → 不经 KNI → f-stack 直接处理 → 正常
- **ping（ICMP）**：ICMP 不在 filter case 中 → reject 模式下送 `ff_kni_enqueue` → KNI ring → secondary `kni_process_tx` → `rte_eth_tx_burst(Port 1)` → 丢失

## 3. 第一阶段修复：primary 执行 KNI process

### 3.1 核心思路

KNI vdev（virtio_user0）由 primary 创建（`rte_eal_hotplug_add`，DPDK 硬约束仅 primary）。因此 KNI 的 runtime TX/RX（`ff_kni_process`）也应由 primary 执行。

修改 `main_loop()` 中的 KNI process 门控：`primary_slim=1` 时由 primary 执行 `ff_kni_process`。

### 3.2 引入的竞态问题

此修复解决了 KNI 不通的问题，但引入了**跨进程 TX queue0 竞态**：

`ff_kni_process(pid, 0, ...)` 中 `kni_process_rx` 调 `rte_eth_tx_burst(Port0, queue_id=0)` 将 kernel 回复包注入物理网卡。但 `primary_slim=1` 时 primary 无 queue，queue0 归属第一个 secondary worker（`lcore_list[0]`）。

两个进程并发操作同一 TX queue 会导致 desc ring 损坏、mbuf 泄漏。DPDK 多进程模型中每个 TX queue 只能由一个进程独占使用，无进程级锁保护。

## 4. 第二阶段修复：inject ring 消除竞态

### 4.1 方案选型

| 方案 | 思路 | 可行性 |
|------|------|--------|
| A. ring 转发 | primary 不直接 TX Port0，enqueue 到专用 ring，owner secondary dequeue 后用自己的 queue TX | ✓ 可行 |
| B. 预留专用 queue | nb_queues+1，KNI 用最后一个 queue，RSS 不分发到该 queue | ✗ 本地 virtio 不支持 RSS，无法隔离额外 rx queue |
| C. rx!=tx | rx=N, tx=N+1 | ✗ virtio PMD 按 max(rx,tx) 分配 vq，未 setup 的 rx queue 会被后端写入导致 crash |

方案 B 依赖 RSS RETA 隔离额外 rx queue。本地 virtio_user（vhost-kernel backend）不报告 `VIRTIO_NET_F_RSS`，`flow_type_rss_offloads=0`，f-stack 跳过 RSS 配置。无 RSS 时 vhost backend 向所有启用 qp 分发，无法阻止流量到额外 rx queue → desc ring 满 → backpressure。方案 B 不可行。

方案 A 是唯一可行的竞态消除方案。

### 4.2 inject ring 机制

新增 `kni_inject_rp[port_id]` 共享 ring，用于 primary→owner secondary 的 KNI RX 包转发：

```
kni_process_rx (primary):
  rx from veth0 → enqueue to kni_inject_rp

ff_kni_inject_process (owner secondary):
  dequeue from kni_inject_rp → rte_eth_tx_burst(Port0, own_queue)
```

primary 不再直接调 `rte_eth_tx_burst(Port0, q0)`，消除跨进程 queue 共享。

### 4.3 代码修改

**`lib/ff_dpdk_kni.c`**：

1. 新增全局 `kni_inject_rp` 数组，在 `ff_kni_init` 中分配（同 `kni_rp` 模式）
2. 在 `ff_kni_alloc` 中创建/lookup `kni_inject_rp[port_id]` ring（primary create，secondary lookup）
3. `kni_process_rx`：`primary_slim && PRIMARY` 时 redirect 到 inject ring 而非直接 `rte_eth_tx_burst`
4. 新增 `ff_kni_inject_process`：owner secondary dequeue + tx_burst 到 Port0

**`lib/ff_dpdk_kni.h`**：

声明 `ff_kni_inject_process`

**`lib/ff_dpdk_if.c`**：

`main_loop()` KNI 段新增 owner secondary inject 路径：

```c
if (ff_global_cfg.dpdk.primary_slim &&
    ff_kni_is_runtime_owner() &&
    rte_eal_process_type() != RTE_PROC_PRIMARY) {
    for (i = 0; i < qconf->nb_tx_port; i++) {
        uint16_t pid = qconf->tx_port_id[i];
        ff_kni_inject_process(pid,
            qconf->tx_queue_id[pid], pkts_burst, MAX_PKT_BURST);
    }
}
```

### 4.4 零回归保证

| 场景 | 行为 | 回归风险 |
|------|------|---------|
| `primary_slim=0` | `kni_process_rx` 走原路径（直接 tx_burst），inject ring 存在但不用 | 零 |
| `primary_slim=1` + KNI 关闭 | `enable_kni=0`，整个 KNI 块跳过 | 零 |
| `primary_slim=1` + KNI 开启 | primary redirect 到 inject ring，owner secondary drain | 修复路径 |

## 5. 测试验证

### 5.1 KNI 开启 + primary_slim=1（inject ring 修复后）

配置：`primary_slim=1`，`[kni] enable=1 method=reject owner_proc_id=1`，`lcore_list=1`

从 `<CLIENT_IP>` 测试：

```
ping -c 5 <DPDK_NIC_IP>
5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/mdev = 0.512/0.895/1.329/0.268 ms

curl http://<DPDK_NIC_IP>/
http_code=200 time=0.000665s
```

ICMP（经 KNI inject ring）和 HTTP（f-stack 直连）同时正常。

### 5.2 KNI 关闭 + primary_slim=1（回归测试）

配置：`primary_slim=1`，`[kni] enable=0`，`lcore_list=1`

```
ping -c 3 <DPDK_NIC_IP>
3 packets transmitted, 3 received, 0% packet loss
rtt min/avg/max/mdev = 0.246/0.263/0.290/0.019 ms

curl http://<DPDK_NIC_IP>/
http_code=200 time=0.001347s
```

零回归确认。

### 5.3 测试环境说明

本机 `<KERNEL_NIC_IP>`（eth1）与 veth0 同属 `/21` 子网，路由冲突导致 kernel `rp_filter` 丢弃 ICMP reply。测试时需设 `rp_filter=0`：

```bash
sysctl -w net.ipv4.conf.veth0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
```

此为测试环境 workaround，非代码修复部分。生产环境 veth0 与 eth1 通常不同子网，无此问题。

## 6. 修复后数据通路（primary_slim=1 + KNI 开启）

```
ICMP request 入站：
  client → 物理网卡(Port0) → secondary rx_burst(q0)
    → ff_kni_enqueue → KNI ring
    → primary kni_process_tx: ring dequeue
    → rte_eth_tx_burst(Port1=virtio_user0, q0)
    → veth0(tap) → kernel 协议栈 → 生成 ICMP reply

ICMP reply 出站（inject ring 路径）：
  kernel → veth0(tap) → virtio_user0
    → primary kni_process_rx: rte_eth_rx_burst(Port1, q0)
    → rte_ring_enqueue_burst(kni_inject_rp)    [primary 不直接 TX Port0]
    → owner secondary ff_kni_inject_process:
      rte_ring_dequeue_burst(kni_inject_rp)
      rte_eth_tx_burst(Port0, own_queue)       [secondary 自己的 queue]
    → 物理网卡 → client
```

关键点：
- secondary 负责 `ff_kni_enqueue`（数据面收包后入队 KNI ring）
- primary 负责 `ff_kni_process`（virtio_user0 TX/RX，因 vdev 仅 primary 合法操作）
- KNI RX 包经 `kni_inject_rp` ring 转发给 owner secondary，由其用自己的 TX queue 发出
- 消除跨进程共享 TX queue0 的竞态

## 7. 涉及文件

| 文件 | 修改类型 | 说明 |
|------|---------|------|
| `lib/ff_dpdk_kni.c` | MODIFY | 新增 `kni_inject_rp` 数组/ring、`ff_kni_inject_process` 函数；`kni_process_rx` 在 primary_slim 时 redirect 到 inject ring |
| `lib/ff_dpdk_kni.h` | MODIFY | 声明 `ff_kni_inject_process` |
| `lib/ff_dpdk_if.c` | MODIFY | `main_loop()` KNI 段：primary 执行 `ff_kni_process`；owner secondary 执行 `ff_kni_inject_process` |

## 8. 调试方法

定位 virtio_user 多进程 TX 问题的关键证据：

1. `veth0` RX 统计不增长 → TX 路径（f-stack → veth0）断裂
2. `kni_process_tx: tx_burst=32` 但 `veth0` RX 不变 → `rte_eth_tx_burst` "假成功"
3. secondary 的 `total_nb_ports=1`（不含 Port 1）→ secondary 未配置 virtio_user 队列
4. primary 的 `total_nb_ports=2`（含 Port 1）→ primary 是 virtio_user 合法操作者

竞态定位：
5. `ff_kni_process(pid, 0, ...)` 中 queue_id 硬编码为 0
6. `primary_slim=1` 时 queue0 归属 secondary worker0，非 primary
7. primary 的 `kni_process_rx` 调 `rte_eth_tx_burst(Port0, q0)` → 跨进程共享 queue
8. DPDK PMD `tx_burst` 无进程级锁 → desc ring 损坏风险
