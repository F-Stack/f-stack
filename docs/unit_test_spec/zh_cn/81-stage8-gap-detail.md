# Stage-8 Gap Detail（逐文件 taken=0 / dead 分支清单）

> 数据源：`tests/unit/coverage.info` 实测（plan §1 同口径）
> 本文随执行迭代更新「状态」列（OPEN → COVERED / EXCL / DEFER）

## A. ff_config.c（154 missing：130 taken=0 + 24 dead）

| 簇 | 行号 | 条件 | 手段 | 状态 |
|---|---|---|---|---|
| C1 lcore-mask | L96/103/106/113/121/131/132/133/135 | parse_lcore_mask 各进制/位/边界 | fixtures + argv -p | OPEN |
| C2 dpdk-args | L175-215 | channel/promiscuous/numa/tx-delay 等 | fixtures | OPEN |
| C3 port/vlan | L356/360/390/417/702/724 | handler 分流/上界/vip | fixtures | OPEN |
| C4 kni-method | L1271 | accept/reject/默认三分支 | fixtures | OPEN |
| C5 lcore-dedup | L1113/1331/1332/1336 | slave_port_list / lcore_list 去重 | fixtures | OPEN |
| C-OOM | 24 dead | strdup/calloc NULL | --wrap (Phase 3) | OPEN |

## B. ff_dpdk_kni.c（45 missing：14 taken=0 + 31 dead）

| 簇 | 行号 | 手段 | 状态 |
|---|---|---|---|
| K1 enqueue | L513/521×4/522/529 | 满环 ret<0 + process_type | OPEN |
| K2 init-oom | L383/394/402/410 | --wrap=rte_zmalloc (Phase 3) | OPEN |
| K3 init-flow | L121/334/379 | 造数据 | OPEN |
| K4 process-tx | L142/148/149/161/163 | --wrap=rte_eth_tx_burst (Phase 4) | **DEFER-S9**（见下）|
| K5 process-rx | L181/183/185 | --wrap=rte_eth_rx_burst (Phase 4) | **DEFER-S9** |
| K6 alloc | L426/435/466/476/480/486 | integ/全mock (Phase 7) | **DEFER-S9** |

> **Phase 4 实测结论（交叉验证 /usr/local/include）**：`rte_eth_tx_burst`（rte_ethdev.h:6395）、`rte_eth_rx_burst`、`rte_ring_dequeue_burst`（rte_ring.h:811）均为 `static inline`。`--wrap` 仅对链接期符号有效，对已内联进 `ff_dpdk_kni.o` 的函数无效。故 K4/K5/K6 的 `--wrap` 主方案**不可行**，需真 PMD（net_null/net_ring vdev）+ rte_eal_hotplug_add 的整合套件。按 plan §6 决策降级为 **FU-S9-KNI-PROCESS-INTEG**（Stage-9）。

## C. 小文件

| 文件 | 行号 | 条件 | 手段 | 状态 |
|---|---|---|---|---|
| ff_ini_parser | L107/121×3/133/155/158 | BOM 第3字节 / &&!error | STOP_ON_FIRST 真死? Phase 5 验 | OPEN |
| ff_dpdk_pcap | L118 | while 多段 mbuf | 多段 mbuf (Phase 5) | OPEN |
| ff_epoll | L113 | data=0 && !EV_EOF 组合 | 造 kev (Phase 5) | OPEN |
| ff_host_interface | L176/209 | clock_gettime assert fail | --wrap (Phase 6) | OPEN |
