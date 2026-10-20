# DPDK 硬件层分析：端口 / mbuf / rxmode 配置缺口

> 本文分析 f-stack 在 DPDK 端口初始化/配置阶段与 MTU/大帧相关的实现现状。所有引用为实际代码 `文件:行号`（`lib/ff_dpdk_if.c`，DPDK 24.11.6）。

## 1. 无 rte_eth_dev_set_mtu 调用

对 `lib/ff_dpdk_if.c` 全文检索 `mtu` / `rte_eth_dev_set_mtu` / `max_rx_pkt_len` / `jumbo` / `RTE_ETHER_MTU`：**0 命中**（仅命中 `rte_pktmbuf_pool_create`、`rte_eth_dev_configure`、`rxmode.offloads` 等无关 MTU 的项）。

结论：**f-stack 从不调用 `rte_eth_dev_set_mtu`**，端口 MTU 始终是 PMD 的默认值（标准以太网 1500），且协议栈层的 `if_mtu` 软件值与硬件 MTU **无任何联动**。

## 2. mbuf 池按标准帧大小创建

`lib/ff_dpdk_if.c`：
```c
425:        if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
426:            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
427:            pktmbuf_pool[socketid] =
428:                rte_pktmbuf_pool_create(s, nb_mbuf,
429:                    MEMPOOL_CACHE_SIZE, 0,
430:                    RTE_MBUF_DEFAULT_BUF_SIZE, socketid);   // 每 mbuf 数据区 2048B
431:        } else {
432:            ... rte_mempool_lookup(s);   // secondary 复用
433:        }
```

- `RTE_MBUF_DEFAULT_BUF_SIZE = 2048`（DPDK 定义 = `RTE_PKTMBUF_HEADROOM(128) + 1920`，实际可承载数据区约 1920B）。
- 该值足以承载标准以太网帧（1500 + 14 头 + FCS/overhead），但**远不足以承载 jumbo frame（9000+）**。
- 无按大 MTU 放大 `data_room_size`，也未启用分段接收（scatter），故单 mbuf 无法承载大帧。

## 3. 端口 rxmode 无 jumbo / max_rx_pkt_len 配置

`lib/ff_dpdk_if.c` 端口配置段（约 L700-923）中 `port_conf.rxmode` 的设置：
```c
733:      port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;          // RSS
781-782:  ... RTE_ETH_RX_OFFLOAD_VLAN_STRIP                       // VLAN strip
787:      port_conf.rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_KEEP_CRC;
791-793:  ... DEV_RX_OFFLOAD_TCP_LRO                              // LRO(条件)
799-803:  ... RTE_ETH_RX_OFFLOAD_CHECKSUM                        // 校验和
807-809:  ... RTE_ETH_RX_OFFLOAD_TIMESTAMP                       // 时间戳
```
```c
856:      ret = rte_eth_dev_configure(port_id, nb_queues, nb_queues, &port_conf);
...
885:          rxq_conf.offloads = port_conf.rxmode.offloads;
886:          ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd, ...);
```

- `rxmode` 中**没有** `mtu` 字段设置（DPDK 24.x 中 `rte_eth_dev_configure` 会用 `port_conf.rxmode.mtu`，f-stack 未赋值→取默认 `RTE_ETHER_MTU=1500`）。
- **没有** jumbo 相关 offload（如 `RTE_ETH_RX_OFFLOAD_SCATTER`）用于接收大帧分段。
- 因此 DPDK 端口以标准 1500 MTU 初始化，PMD 收发大帧的能力未被开启。

> 注：本机 DPDK 网卡为 virtio，其 jumbo/scatter 能力受 PMD 限制；即便 f-stack 代码补齐上述配置，还需 PMD 与底层网卡/vSwitch 共同支持才能真正启用 jumbo（详见 `04-外网调研.md`）。

## 4. 对外接口无 MTU 项

- `lib/ff_api.h`：检索 `mtu` = 0 命中，**无对外 MTU 设置/获取接口**。
- `config.ini`：检索 `mtu`/`jumbo` = 0 命中，**无 MTU 配置项**。

即 f-stack 既未在初始化时读取任何 MTU 配置，也未暴露编程接口供上层设置硬件 MTU。

## 小结（DPDK 硬件层）

| 检查项 | 现状 | 影响 |
|---|---|---|
| `rte_eth_dev_set_mtu` | 从不调用 | 软件 `if_mtu` 不下发硬件 |
| mbuf `data_room_size` | 固定 2048（`RTE_MBUF_DEFAULT_BUF_SIZE`） | 无法承载 >~1920B 大帧 |
| `rxmode.mtu` / jumbo offload | 未设置（取默认 1500） | 端口按标准帧初始化 |
| scatter（分段接收） | 未启用 | 单 mbuf 无法拼接大帧 |
| `config.ini` MTU 项 / `ff_api` MTU 接口 | 无 | 无配置/编程入口 |

**结论**：DPDK 硬件层完全没有 MTU 接线与 jumbo 支持。这与协议栈层的 1500 上限共同构成"减小 MTU 可用、增大 MTU 不支持"的软硬件断层（详见 `03-软硬件断层与差异分析.md`）。
