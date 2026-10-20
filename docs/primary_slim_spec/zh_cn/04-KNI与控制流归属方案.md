# 04-KNI 与控制流归属方案

> 修订记录：2026-08-07 据leader E2e 实测（refcnt≥1 时 secondary 可在 primary 缺席下重启成功）上调 S1 裁决、下调 S5 为兜底、新增未决问题 A4。
> 修订记录（同日追加）：据 leader E10 实测（primary 不可原地重新拉起）A4 已闭环（详见 `03` §7.3）；本文据 T4 补充 K3 与"primary 必须常驻"的协同点，并明确 **KNI 入向报文由各 secondary 在自有 rx 队列收取后经 `kni_rp` ring 交给 primary**（K3 不需要 primary 持有物理口 rx 队列），同时**新发现**广播/多播分支 `lib/ff_dpdk_if.c:2080` 的 owner 门禁在 slim 下会导致广播包永不入KNI，必须一并修正。
> 修订记录：2026-08-07（第三次）据门禁审核修正广播/多播 KNI 门禁行号 2081 → 2080。同批复核并修正另两处 off-by-one：`pkts_from_ring` 判定在 `:2055`（原写 `2056`）、其块范围 `2055-2077`（原写 `2056-2078`）；单播分支起点在 `:2091`（原写 `2092-2109`，起点少算一行）。
> 修订记录：2026-08-07（第四次）据门禁报告 R1/R4 复核 04 内残留的 2081→2080、2056-2078→2055-2077（复核结果：第三次修订已全部生效、正文零残留，仅本修订记录中作为叙述保留旧值），去除对 01 的硬编码行数引用，并在 §2.3 改动清单表格上方补充"以代码文本匹配为准、行号仅作辅助定位"的实现者提示。
> 修订记录：2026-08-10（第五次）据用户对第一轮 K3 的三个质疑 Q1/Q2/Q3（详见 `11-KNI深化调研与实验报告.md`）及 E4a 决定性实验结果修订：(1) 据 Q1 删除 K3 风险表中"推荐多消费者消除单点"的过度设计（`kni_rp` 已是 `RING_F_SC_DEQ` 单消费者，保持不动）；(2) 据 Q2 删除"按 `nb_lcores` 折算 ratelimit 默认值"的过度设计（`kernel_packets_ratelimit` 在 `kni_process_tx` 中只有 owner 执行，天然单点限速）；(3) 据 Q3 及 E4a 实验结果（secondary 通过 `VDEV_SCAN_REQ` 成功发现并 probe primary 创建的 virtio_user 口、可访问共享 KNI ring）新增 K4 方案（secondary 作运行时 KNI owner），并据 `11` §3.8 的关键发现——`kni_process_rx` 的 L190 `rte_eth_tx_burst(port_id, queue_id, ...)` 中 `queue_id` 来自 owner 自己的 rx 队列，owner 若为 secondary 可直接用自己的 tx 队列发出、**不需要新增 `kni_tx_ring`**——将 K4 列为首选，K3-corrected（= K3 + Q1/Q2 纠正）降为退备方案。

> 对象：`/data/workspace/f-stack`（DPDK 24.11.6）。**本轮只读不改**：未修改代码、未编译、未提交。
> 行号标注规则：`引自 02` = 沿用 `02-架构代码探测与阻塞点清单.md` 的坐实结论；`已复核` = 本文档作者用`read_file` 重新读过该行；`引自 11` = 沿用 `11-KNI深化调研与实验报告.md` 的坐实结论（含 E4a 实测数据）。

## 摘要

primary-slim（见 `03`的 S1）后 primary 不再持有 rx/tx 队列，而 KNI 的轮询函数 `ff_kni_process()` 恰好嵌套在 rx 队列循环内 ⇒ KNI 静默失效。本文给出 KNI 的完整归属依赖图（区分「必须 primary」与「可迁移」）、四条候选路径 K1/K2/K3-corrected/K4 的逐条评估、仅 primary 生效的 6 项控制面操作的归属与时序重排、`msg_ring`/tools 的归属裁决，以及 `nb_dev_ports` 语义修正方案。

据 `11` 的 Q1/Q2/Q3 代码坐实及 E4a 决定性实验（2026-08-10 实测，secondary 成功通过 `VDEV_SCAN_REQ` 发现并 probe primary 创建的 virtio_user 口、可访问共享 KNI ring），**K4（secondary 作运行时 KNI owner）为首选方案**，K3-corrected（K3 + Q1/Q2 纠正）为退备方案。

## 关键结论

1. **KNI 里真正"必须 primary"的只有两件事**：virtio_user 口的 `rte_eal_hotplug_add()`（`lib/ff_dpdk_kni.c:474`，已复核）与该口的 `dev_configure`/`dev_start`（经 `lib/ff_dpdk_if.c:1061-1063` 的门禁，引自 02）。`kni_stat` 分配、`kni_ring_%u` 消费、virtio_user 的 rx/tx burst **都不要求 primary 身份**。
2. **K2 的关键卡点已查证：`rte_eal_hotplug_add()` 在 secondary 中是"可调用但会转交primary"**——`rte_dev_probe()` 在非primary 分支直接 `eal_dev_hotplug_request_to_primary()`（`dpdk-stable-24.11.6/lib/eal/common/eal_common_dev.c:244-259`，已复核），primary 侧由 `handle_secondary_request` → `local_dev_probe()` 真正attach 并反向同步给所有 secondary（`hotplug_mp.c:101-112`、`442-455`，已复核）。**所以 K2 不被 DPDK 封死，但它并不减少对 primary 的依赖**（仍需 primary 存活，且 `01` §1.2.1 已确认 primary 是 IPC 唯一服务端），却要额外承担 N2 的 `nb_dev_ports` 语义漂移变成真 bug、`total_nb_ports` 条件失效、以及 secondary 对 vdev 口可见性依赖 `VDEV_SCAN_REQ`（`01` §1.2.4）三项代价 ⇒ **推荐度最低**。
3. **推荐 K4 为首选**（据 `11` Q3 + E4a 实测）：将 `ff_kni_is_owner_thread()` 拆分为"init owner"（= primary，执行 hotplug/kni_stat 分配/kni_rp 创建/total_nb_ports*=2/dev_configure/dev_start）与"runtime owner"（= 指定 secondary，执行 `ff_kni_process()`/广播多播克隆入队）。**E4a 已实测验证**：secondary 通过 `VDEV_SCAN_REQ` 成功发现 primary 创建的 virtio_user0 口（`VDEV_BUS: receive vdev, virtio_user0` + `Received 1 vdevs`）、独立 probe 该口（`Search driver to probe device virtio_user0`）、成功访问共享 KNI ring（`create kni ring success`）。据 `11` §3.8 的关键发现——`kni_process_rx` 的 L190 `rte_eth_tx_burst(port_id, queue_id, ...)` 中 `queue_id` 来自 owner 自己的 rx 队列——**K4 的 owner secondary 直接用自己的 tx 队列发出，不需要新增 `kni_tx_ring`**。K4 的核心优势：不需要新增 ring（少一跳延迟、少一个 ring 管理）、KNI owner 崩溃只影响 KNI 不影响控制面、恢复只需重启该 secondary（可原地重启，`03` E2e 已证）。
4. **K3-corrected 为退备方案**（K3 + Q1/Q2 纠正）：primary 继续独占 virtio_user 口的收发（它是该口的 configure/start 者，队列 0 无人竞争，**不需要物理口队列**），「内核 → 物理口」方向经新增 `kni_tx_ring`（单生产者 primary → 单消费者一个 secondary，`RING_F_SP_SC`）交给某 secondary 用其自有 tx 队列发出。**与"primary 必须常驻"天然协同**：据 `03` 的 E2e/E10 修订，primary-slim 下 primary 本就必须常驻，把 KNI owner 继续留在 primary 不引入新的存活性依赖。据 Q1 纠正：`kni_rp` 已是 `RING_F_SC_DEQ` 单消费者，保持不动，**不需要改为多消费者**；据 Q2 纠正：`kernel_packets_ratelimit` 在 `kni_process_tx` 中只有 owner 执行，**天然单点限速，不需要按 `nb_lcores` 折算默认值**。
5. **KNI 入向报文（物理口 → 内核）不需要 primary 持有物理口 rx 队列**（T4 明确答案）：该方向由**各 secondary 在自己的 rx 队列上收包后 `ff_kni_enqueue()` 入共享 ring `kni_rp[port_id]`**，owner（K4=指定 secondary / K3-corrected=primary）从 ring dequeue 后写 virtio_user 口 queue 0。单播分支本就无 owner 门禁（`lib/ff_dpdk_if.c:2091-2109`，已复核）。**但必改一处**：广播/多播分支有 owner 门禁（`lib/ff_dpdk_if.c:2080`的 `if (enable_kni && ff_kni_is_owner_thread())`，已复核），slim primary 永不收包 ⇒ 该分支一次都不执行 ⇒ **ARP 请求、DHCP、IPv6 NS/RA/MLD、OSPF hello 等广播/多播报文永远不会进内核**，KNI 管理面半瘸。改法见 §2.3 第5 点（K3-corrected）与 §2.4 第6 点（K4）。
6. **`msg_ring`裁决：primary 精简循环继续消费 `msg_ring[0]`，tools 默认 `proc_id=0` 保持不变**（向后兼容优先）；不采用"把 tools 默认指向第一个收包进程"的方案。
7. **`nb_dev_ports` 修正裁决**：由 primary 在 hotplug **之前**把 `rte_eth_dev_count_avail()` 快照发布到共享 memzone，secondary lookup 读取；不采用"改成只统计配置里的物理口"（会破坏 virtio_user 口 id 基址语义）。**K4 前置必做**（owner secondary 需要 `nb_dev_ports` 算 `kni_stat[port_id]->port_id`），K3-corrected 可延后（`nb_dev_ports` 只在 primary 侧使用）。

---

## 一、KNI 当前 primary 强绑定的完整依赖图

### 1.1 归属链（基于 `02` 的 A.3 与 C.3，行号已逐条复核）

```
【owner 判定（一切的根）】
ff_kni_is_owner_thread()                              lib/ff_dpdk_kni.c:92-98   [已复核]
├─ thread_mode=1 → rte_lcore_id() == cfg.dpdk.proc_lcore[0]           95-96
└─ thread_mode=0 → rte_eal_process_type() == RTE_PROC_PRIMARY97← 强绑定源头

【初始化链】
ff_dpdk_init:1690-1695enable_kni = cfg.kni.enable; init_kni()       [已复核]
└─ init_kni()                lib/ff_dpdk_if.c:756-781   [已复核]
   ├─ nb_ports = nb_dev_ports                758   ★N8/N2
   ├─ knictl_action = get_kni_action(...)765
   ├─ ff_kni_init(nb_ports, tcp_port, udp_port)                      767
   │  └─ lib/ff_dpdk_kni.c:384-428[已复核]
   │     ├─ [owner] kni_stat = rte_zmalloc("kni:stat", ptr*nb_ports) 387-394◆可迁移
   │     ├─ kni_rp   = rte_zmalloc("kni::ring_%d", ptr*nb_ports)396-405  （每进程私有）
   │     ├─ tcp/udp_port_bitmap rte_zmalloc 8192 ×2                  407-421（每进程私有）
   │     └─ kni_set_bitmap(...)                                      423-427
   ├─ (死代码) mbuf_pool 局部变量声明后未使用                        770-771  ★N8[已复核]
   ├─ nb_ports = cfg.dpdk.nb_ports   ← 同名变量二次赋值              773      ★N8
   └─ for i<nb_ports: ff_kni_alloc(port_id, socket_id, i, KNI_QUEUE_SIZE)  775-778
      └─ lib/ff_dpdk_kni.c:430-499                                          [已复核]
         ├─ [owner] kni_stat[port_id] = rte_zmalloc("kni:stat_lcore") 438-450◆可迁移
         ├─ [owner] rte_eth_macaddr_get(port_id)                     453-456 ◆可迁移(只读)
         ├─ [owner] rte_eal_hotplug_add("vdev","virtio_user%u",
         │          "path=/dev/vhost-net,queues=1,queue_size=%u,
         │           iface=veth%d,mac=...")                          462-476■必须 primary
         ├─ [owner] kni_stat[port_id]->port_id = port_idx+nb_dev_ports478    ★N2 依赖点
         ├─ ring_name = "kni_ring_%u"（按 port_id，与 proc 无关）    481-482
         └─ [owner] rte_ring_create(RING_F_SC_DEQ)
            [非owner] rte_ring_lookup                               484-495 ◆可迁移(创建者)

【端口配置链】
init_port_start()lib/ff_dpdk_if.c:812-...  [已复核]
├─ [enable_kni && owner] total_nb_ports *= 2821-825■必须 primary(见2.4)
├─ virtio_user 口：u_port_id = i-nb_ports+nb_dev_ports; nb_queues = 1 842-847 ★N2 依赖点
└─ if (!PRIMARY) continue → dev_configure/queue_setup/dev_start      1061-1148 ■必须 primary

【运行期：物理口 → 内核（KNI 代码里叫 tx 方向）】★入向报文的收取者 = 各secondary，不需要 primary 有 rx 队列
process_packets()                                   lib/ff_dpdk_if.c:1975-... （引自 02）
├─ [广播/多播 && owner] 克隆 → ff_kni_enqueue()2080-2087 ★★slim 下必改（见2.3 第5 点）
└─ [单播 && enable_kni] 无 owner 门禁，任何进程都可入队              2091-2109 （已是"任意进程"，已复核）
   └─ ff_kni_enqueue()lib/ff_dpdk_kni.c:510-543[已复核]
      ├─ ratelimit 判定513-527
      ├─ rte_ring_enqueue(kni_rp[port_id], pkt)                       529-532 ← 共享 ring，跨进程
      └─ error: [owner] kni_stat[port_id]->rx_dropped++               536-540◆可迁移

【运行期：轮询与转发（只有 owner 执行）】
main_loop: for (i < qconf->nb_rx_queue) { ... }      lib/ff_dpdk_if.c:2759-2801 [已复核]
└─ if (enable_kni && ff_kni_is_owner_thread())
   ff_kni_process(port_id, queue_id, pkts_burst, MAX_PKT_BURST)2764-2768★致命点
   └─ ff_kni_process()                             lib/ff_dpdk_kni.c:501-507  [已复核]
      ├─ kni_process_tx(port_id, queue_id, ...)                       505→ 144-179
      │  ├─ rte_ring_dequeue_burst(kni_rp[port_id], ...)              150
      │  ├─ kernel_packets ratelimit                                  156-165
      │  └─ rte_eth_tx_burst(kni_stat[port_id]->port_id, 0, ...)      167  → virtio_user 口
      │     └─ ◆只需 virtio_user 口的 queue 0，**不需要物理口队列**
      └─ kni_process_rx(port_id, queue_id, ...)                       506 → 181-202
         ├─ rte_eth_rx_burst(kni_stat[port_id]->port_id, 0, ...)      187  ← virtio_user 口
         │  └─ ◆只需 virtio_user 口的 queue 0
         └─ rte_eth_tx_burst(port_id, queue_id, ...)                  190  → 物理口
            └─ ★★queue_id 来自 owner 自己的 rx 队列（引自 11 §3.8）
               ├─ K3-corrected 改造点：改为 enqueue `kni_tx_ring`，由指定 secondary 消费
               └─ K4 改造点：owner=secondary 时直接用自己的 tx 队列发出，不需要 ring

【控制面：knictl】
tools（--proc-type=secondary，ff_proc_id 默认 0）
└─ handle_knictl_msg()lib/ff_dpdk_if.c:2259-2288 （引自 02）
   └─ 只改进程内静态 knictl_action（lib/ff_dpdk_if.c:77）→ 需对每个 proc_id 分别下发
```

### 1.2 「必须 primary」vs「可迁移」判定表

| 环节 | 位置 | 判定 | 依据 |
|---|---|---|---|
| virtio_user 口 `rte_eal_hotplug_add()` | `lib/ff_dpdk_kni.c:474`（已复核） | **必须由 primary 实际执行**（secondary 调用会被EAL 转交 primary） | `rte_dev_probe()` 的非 primary 分支 `eal_dev_hotplug_request_to_primary()`（`eal_common_dev.c:244-259`，已复核）；primary 侧 `local_dev_probe()`（`hotplug_mp.c:101-102`，已复核） |
| virtio_user 口 `dev_configure`/`queue_setup`/`dev_start` | `lib/ff_dpdk_if.c:1061-1148`（引自 02） | **必须 primary** | secondary 被 `1061-1063` 的 `continue` 跳过；DPDK 不允许 secondary 做设备配置 |
| `total_nb_ports *= 2`（把 virtio_user 口纳入配置循环） | `lib/ff_dpdk_if.c:821-825`（已复核） | **必须在 primary 上成立** | 目前条件是 `enable_kni && ff_kni_is_owner_thread()`；owner 一旦迁到 secondary，**primary 就不再配置 virtio_user 口** ⇒ 该口永远不start ⇒ KNI 全废。这是 K2 的隐藏致命点，必须把条件改为仅 `enable_kni`（在 primary 上恒真） |
| `kni_stat` / `kni_stat[port_id]` 分配 | `lib/ff_dpdk_kni.c:387-394`、`438-450`（已复核） | **可迁移**（纯 `rte_zmalloc` 统计结构，无设备语义） | 无 DPDK 身份要求 |
| `rte_eth_macaddr_get(port_id)` | `lib/ff_dpdk_kni.c:453-456`（已复核） | **可迁移**（只读查询，secondary 允许） | 与 `ff_dpdk_if_get_mtu()` 同类（`lib/ff_dpdk_if.c:288-292`，已复核，两边都跑） |
| `kni_ring_%u` 创建者 | `lib/ff_dpdk_kni.c:484-492`（已复核） | **可迁移**（但创建者必须唯一）；建议**留在 primary** | ring 名按 `port_id` 而非 `proc_id`，与身份无关；留在 primary 可复用现有 `create/lookup` 对称结构 |
| `ff_kni_enqueue()`（入ring） | `lib/ff_dpdk_kni.c:510-543`（已复核） | **已是"任意进程"**（`529` 的 enqueue 无 owner 门禁） | 只有 `536-540` 的错误统计路径引用 `kni_stat`，需gate 或改为owner-only 统计 |
| **广播/多播 → KNI 的克隆入队** | `lib/ff_dpdk_if.c:2080-2087`（已复核） | **必须迁出primary（slim 下必改）** | 条件为 `enable_kni && ff_kni_is_owner_thread()`；slim primary 的 `nb_rx_queue == 0` ⇒ 从不进入 `process_packets()` ⇒ **广播/多播永不入 KNI ring**。改法：把门禁换成 `enable_kni && !pkts_from_ring`（`pkts_from_ring` 是 `process_packets()` 现有形参，`2055` 已在用，已复核），即"从线上收到该包的那个进程负责克隆一份给 KNI"，恰好一份、不重复、不依赖任何进程身份 |
| virtio_user 口的 rx/tx burst | `lib/ff_dpdk_kni.c:167`、`187`（已复核） | **可迁移**（只要该口已由 primary configure+start，且 `nb_queues=1` 的queue 0 只有一个消费者） | 与物理口 secondary 收发同理（现状多进程已在生产使用） |
| **物理口 tx burst（内核 → 网卡方向）** | `lib/ff_dpdk_kni.c:190`（已复核） | **必须由"持有该物理口 tx 队列的进程"执行** | `queue_id` 来自 `main_loop` 的 rx 队列循环（`2760-2766`，已复核）。slim primary 没有任何物理口队列 ⇒ **这是 KNI 与 primary-slim 的唯一硬冲突点** |
| `ff_kni_process()` 调用位置 | `lib/ff_dpdk_if.c:2764-2768`（已复核） | **必须移出 rx 队列循环** | 否则 (i) slim primary 队列数 0 ⇒ 一次不调用；(ii) owner 的队列数会决定 KNI 轮询频率（既有设计缺陷） |
| `knictl_action`下发 | `lib/ff_dpdk_if.c:77`、`2259-2288`（引自 02） | 进程私有，**需对每个 proc_id 分别下发** | 既有行为，与本方案无关 |

---

## 二、KNI 三条候选路径评估

> 三条路径**不预设答案**，逐条给出改动量、可行性、与 B2 校验的冲突程度、风险、推荐度。

### 2.1 K1：KNI 留在 primary，为其单独保留一个最小 rx/tx 队列（与 `03` 的 S3 呼应）

**做法**：primary 仍在每个 port 的 `lcore_list` 中（因此持有 queueid=0 的一对 rx/tx 队列），KNI 归属与代码基本保持现状；通过改 reta 让业务流量不落到 primary 的队列（`03` S3 的做法），primary 的队列只用于 KNI 的「内核 → 物理口」发送与极少量入向管理包。

**代码改动清单**：

| 位置 | 改法 | 量|
|---|---|---|
| `lib/ff_dpdk_if.c:787-809` `set_rss_table()`（已复核） | `reta_conf[i].reta[j] = hash++ % nb_queues`（`801`）改为跳过 primary 的 queueid（例如 `1 + hash % (nb_queues-1)`，前提是 primary 恒为 `lcore_list[0]`） | ~5 行 |
| `lib/ff_dpdk_if.c:1167-1175`（引自 02） | `nb_queues > 1` 的边界改为 `nb_queues > 2`（因为要留出primary 的队列） | ~2 行 |
| `lib/ff_dpdk_if.c:2764-2768`（已复核） | `ff_kni_process()` 移出 rx 循环（避免轮询频率耦合） | ~8 行 |
| `lib/ff_config.c:1419-1435`（已复核） | **不改**（primary 仍在 `lcore_list` 中，B2 校验天然满足） | 0 |
| `lib/ff_dpdk_if.c:508-510` | **不改**（primary 有队列，不触发 B1） | 0 |
| `lib/ff_dpdk_if.c:535` | **不改**（primary 有队列，池公式不归零） | 0 |

**可行性结论**：**可行且改动最小**。不触发 B1/B2/B3/N5/N6 中的任何一个，MTU/ifp/tools/msg_ring 全部保持现状。

**与 B2 配置校验的冲突程度**：**零冲突**（B2 要求的正是"primary 在每个 port 的 `lcore_list` 中"）。

**风险**：
- reta 改造风险：`hash % (n-1) + 1` 的分布均匀性、与`symmetric_rss`（`lib/ff_config.h:309`，已复核）的兼容性需实测；且 `set_rss_table()` 整体被 `#if !defined(FF_FLOW_ISOLATE) && !defined(FF_FLOW_IPIP)` 包住（`lib/ff_dpdk_if.c:785-810`，已复核）⇒ 这两个宏开启时方案失效。
- **孤儿队列未真正消除**：primary 崩溃后它的队列仍在，落到该队列的（少量）管理流量黑洞化。子目标 (b) 只是近似达成。
- primary 仍跑完整 `process_packets()` 路径 ⇒ 子目标 (a) 的收益远小于 K3/S1。

**推荐度**：**中（作为 `kni.enable=1` 的快速兜底）**。如果项目要求"KNI 必须可用且不接受 KNI 代码改造风险"，K1 是唯一低风险选项，但它本质上是 S3 而不是 S1。

---

### 2.2 K2：KNI 归属迁移到指定 secondary

**做法**：新增 `[kni] owner_proc_id`（默认 0= primary，保持现状），`ff_kni_is_owner_thread()` 改为 `ff_cur_proc_id() == cfg.kni.owner_proc_id`；owner secondary 承担 `kni_stat` 分配、`kni_ring_%u` 消费、virtio_user 收发、物理口 tx（用它自己的队列）。

**关键卡点查证（`rte_eal_hotplug_add()` 在 secondary 是否可用）—— 已查DPDK 源码，结论如下**：

1. `rte_eal_hotplug_add()` 只是 `rte_dev_probe()` 的包装（`dpdk-stable-24.11.6/lib/eal/common/eal_common_dev.c:149-165`，已复核）。
2. `rte_dev_probe()` 在**非 primary** 进程中不本地 attach，而是把请求发给 primary：
   ```c
   // dpdk-stable-24.11.6/lib/eal/common/eal_common_dev.c:244-259（已复核）
   if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
       ret = eal_dev_hotplug_request_to_primary(&req);
       if (ret != 0) { EAL_LOG(ERR, "Failed to send hotplug request to primary"); return -ENOMSG; }
       if (req.result != 0) EAL_LOG(ERR, "Failed to hotplug add device");
       return req.result;
   }
   ```
3. primary 侧由 `eal_mp_dev_hotplug_init()` 注册的 `handle_secondary_request`（`hotplug_mp.c:442-455`，已复核）接收，并因"IPC 回调线程里不能做sync IPC（会死锁）"而委派给**中断线程**执行（`hotplug_mp.c:211-215`，已复核）；`__handle_secondary_request()` 中 `EAL_DEV_REQ_TYPE_ATTACH` 分支先`local_dev_probe(req->devargs, &dev)`（primary 自己 attach），再 `eal_dev_hotplug_request_to_secondary()` 同步给全部 secondary（`hotplug_mp.c:101-112`，已复核）。

**因此结论是**：`rte_eal_hotplug_add()` **在 secondary 中可以调用、且语义正确**（最终由 primary 完成 attach 并同步全体），**但它并不解除对 primary 的依赖**——primary 必须存活且 IPC 通道可用。也就是说，把 hotplug 调用点从 primary 挪到 secondary，**收益为零、复杂度为正**。

**与 N2 的叠加（`02` 已预警，此处坐实其后果）**：

- `nb_dev_ports` 在 secondary 侧"不正确"是源码自承的（`lib/ff_dpdk_if.c:79` 的注释 `/* primary is correct, secondary is not correct, but no impact now*/`，引自 02）。
- 它当前"无影响"的唯一原因是两个使用点都在 owner(=primary) 分支内：`kni_stat[port_id]->port_id = port_idx + nb_dev_ports`（`lib/ff_dpdk_kni.c:478`，已复核）与 `u_port_id = i - nb_ports + nb_dev_ports`（`lib/ff_dpdk_if.c:844`，已复核）。
- **owner 一旦迁到 secondary，`478` 就在 secondary 上执行 ⇒ `nb_dev_ports` 偏大（把 primary 已hotplug 出来的 virtio_user 口也数进去）⇒ `kni_stat[port_id]->port_id` 指向错误 port⇒ `167`/`187` 的收发打到错误设备**。这是真 bug，必须先做第五节的 N2 修正。

**另一个隐藏致命点（本文新发现）**：`init_port_start()` 的 `total_nb_ports *= 2` 条件是 `enable_kni && ff_kni_is_owner_thread()`（`lib/ff_dpdk_if.c:821-825`，已复核）。owner 迁到 secondary 后，**primary 的 `total_nb_ports` 不再翻倍 ⇒ primary 不会对 virtio_user 口做 `dev_configure`/`dev_start`（`1061-1148`）⇒ 该口永远处于未启动状态 ⇒ owner secondary 的 `rte_eth_tx_burst(kni_stat[]->port_id, 0, ...)` 全失败**。必须把该条件改为仅 `enable_kni`（在 primary 上恒真），并让 owner secondary 也进入 virtio_user 口的循环（但被 `1061` 门禁跳过配置，只做本进程侧的准备）。

**代码改动清单**：

| 位置 | 改法 |
|---|---|
| `lib/ff_config.h:337-346`（kni 结构，已复核） | 新增 `int owner_proc_id;` |
| `lib/ff_config.c:1085-1086`（`MATCH("kni","enable")` 旁，已复核） | 新增 `MATCH("kni","owner_proc_id")` 解析 |
| `lib/ff_config.c:1419-1435`（已复核） | 校验对象从 primary lcore 改为 `proc_lcore[cfg->kni.owner_proc_id]` |
| `lib/ff_dpdk_kni.c:92-98`（已复核） | owner 判定改为 `ff_cur_proc_id() == cfg.kni.owner_proc_id` |
| `lib/ff_dpdk_kni.c:430-479`（已复核） | 拆成 creator（primary：hotplug + ring create）与 poller（owner secondary：`kni_stat` + 收发）两段 |
| `lib/ff_dpdk_if.c:821-825`（已复核） | 条件改为仅 `enable_kni`（**否则 virtio_user 口不被配置**） |
| `lib/ff_dpdk_if.c:79`、`421-423`、`758`、`844`；`lib/ff_dpdk_kni.c:478` | N2 修正（前置必做） |
| `lib/ff_dpdk_if.c:2764-2768`（已复核） | `ff_kni_process()` 移出 rx 循环 |
| `lib/ff_dpdk_if.c:2079-2088`（引自 02） | 广播/多播克隆入队的 owner 门禁语义复核 |

**可行性结论**：**技术上可行，但性价比最差**。它没有解除对 primary 的依赖（hotplug 仍由 primary 实际执行），却引入 N2 真 bug 修复、`total_nb_ports` 条件修正、creator/poller 拆分三项额外风险；且把 KNI 轮询负担压到某个收包 secondary 上，会让该 secondary 的数据面性能与其他 secondary 不对称（`06` 需专门对照）。

**与 B2 配置校验的冲突程度**：**中**（需重写 `1419-1435` 的校验对象，但方向明确）。

**推荐度**：**低（不推荐；除非将来出现"primary 必须完全不碰任何 ethdev"的硬需求）**。

---

### 2.3 K3-corrected：primary 保留 KNI 但不碰物理口队列，「内核 → 物理口」方向经 ring 借道 secondary（退备方案）

> K3-corrected = 原 K3 + Q1/Q2 纠正。据 `11` Q1：`kni_rp` 已是 `RING_F_SC_DEQ` 单消费者，保持不动，不需要改为多消费者。据 `11` Q2：`kernel_packets_ratelimit` 在 `kni_process_tx` 中只有 owner 执行，天然单点限速，不需要按 `nb_lcores` 折算默认值。E4a 已通过 K4 实测（§2.4），K4 为首选，本方案降为退备。

**做法（退备方案）**：

1. **保留 KNI owner = primary**（`ff_kni_is_owner_thread()` 不改，`lib/ff_dpdk_kni.c:92-98`）。
2. **`ff_kni_process()` 从 rx 队列循环移到循环之外**（`lib/ff_dpdk_if.c:2764-2768` → 移到 `2803` 的 `process_msg_ring()` 附近），改为按 port 遍历而不是按 (port, queue) 遍历，并去掉 `queue_id` 参数依赖。这样 slim primary（`nb_rx_queue == 0`）也会每轮驱动一次 KNI。
3. **tx 方向（f-stack → 内核）零改动**：`kni_process_tx()` 只用 `rte_ring_dequeue_burst(kni_rp[port_id])` + `rte_eth_tx_burst(kni_stat[port_id]->port_id, 0, ...)`（`lib/ff_dpdk_kni.c:150`、`167`，已复核），**目标是 virtio_user 口的 queue 0，不需要物理口队列**。primary 是该口的 configure/start 者、且`nb_queues = 1`（`lib/ff_dpdk_if.c:845`，已复核）只有 primary 一个使用者 ⇒ 合法无竞争。
4. **rx 方向（内核 → 物理口）改造**：`kni_process_rx()` 的 `rte_eth_rx_burst(kni_stat[port_id]->port_id, 0, ...)`（`187`）保留在 primary；但把随后的 `rte_eth_tx_burst(port_id, queue_id, ...)`（`190`，已复核）改为 **`rte_ring_enqueue_burst(kni_tx_ring[port_id], ...)`**，新增一个由 primary 创建、由**某个指定 secondary**（建议 `lcore_list[0]` 对应的进程，即 queueid=0 的那个）消费的 ring；该 secondary 在自己的 `main_loop` 里 dequeue 后用**自己的 tx 队列**发出。
5. **入向方向（物理口 → 内核）：明确由各 secondary 收取，primary 不需要物理口 rx 队列**（T4 要求讲清的点）。链路为「secondary 在自有 rx 队列 `rte_eth_rx_burst` 收到包 → `process_packets()` 判定该包应给内核 → `ff_kni_enqueue()` 入**共享** ring `kni_rp[port_id]`（`lib/ff_dpdk_kni.c:529-532`，已复核）→ primary 的 `kni_process_tx()` 从该 ring dequeue（`150`）→ `rte_eth_tx_burst(kni_stat[port_id]->port_id, 0, ...)` 写 virtio_user 口（`167`）→ 内核 veth」。因此 **K3 既不需要 primary 的物理口 tx 队列（第3 点），也不需要 primary 的物理口 rx 队列**——primary 只碰 virtio_user 口。
   **但必须同时修一处（本文新发现）**：广播/多播分支的 owner 门禁 `if (enable_kni && ff_kni_is_owner_thread())`（`lib/ff_dpdk_if.c:2080`，已复核）在 slim 下**永不成立**（primary 不进`process_packets()`），会导致 ARP 请求、DHCP、IPv6 NS/RA/MLD、OSPF hello 等**广播/多播报文完全不进内核**，KNI 只剩单播可用。改法：把该条件改为 `if (enable_kni && !pkts_from_ring)`。理由：广播包由收到它的进程通过 `dispatch_ring` 克隆给其余队列（`lib/ff_dpdk_if.c:2055-2077`，已复核，仅在 `!pkts_from_ring` 时执行），因此"`!pkts_from_ring`"精确等价于"我是从线上收到该包的那个进程"⇒ 恰好产生**一份** KNI 副本（与现状"只有 owner 入队一份"的份数语义一致），且不依赖任何进程身份。**若错误地改成仅 `enable_kni`，则 N 个进程各入一份 ⇒ 内核收到 N 份重复广播包**，务必避免。

**为什么这是最干净的（退备方案视角）**：

- primary **完全不接触物理口的任何队列**（tx 与 rx 都不需要，见改造点3 与 5）⇒ 与 `03` 的 S1 严格一致，B1/B3/B4 的收缩逻辑与"无孤儿队列"结论全部保持；
- **与"primary 必须常驻"天然协同**（据 `03` 的 E2e/E10 修订新增）：S1 下primary 本就必须常驻（IPC 服务端 / 扩堆代理 / 中断承担者，且是 uio refcnt 贡献者之一），把 KNI owner 留在 primary **不引入任何新的存活性依赖**——KNI 能力的可用期恰好与控制面其他能力同生共死，无需为 KNI 单独设计 owner failover；而 K2 把 owner 迁到 secondary 反而制造了"控制面能力分散在两个进程"的新故障组合。
- KNI 的管理面（内核旁路：SSH/ARP/ICMP/路由协议等）**双向都通**；
- KNI 的关键控制包路径仍集中在 primary（与现状一致，行为可预期），不产生 K2 那样的 secondary 性能不对称（新增的只是一个 ring 消费，成本与既有 `dispatch_ring`（`lib/ff_dpdk_if.c:664-668`，已复核）同量级）；
- 复用既有的 `create_ring()`（`lib/ff_dpdk_if.c:615-635`，已复核，primary create / secondary lookup 已封装好）与 `process_dispatch_ring()` 的消费模式，无新机制。
- **相对 K4 的劣势**：需要新增 `kni_tx_ring`（多一跳延迟、多一个 ring 管理）；KNI 与 primary 绑定（primary 崩溃 = KNI 断且不可原地恢复，`03` E10 已证，必须等计划内全组重启）。

**代码改动清单**：

> 给实现者的定位提示：下表行号仅作辅助定位，**以代码文本匹配为准**（如广播/多播门禁请匹配 `if (enable_kni && ff_kni_is_owner_thread())` 语句本身）。仓库后续提交会使行号漂移，改动前请先 grep 确认。

| 位置 | 改法 | 估计量 |
|---|---|---|
| `lib/ff_dpdk_if.c:638-679` `init_dispatch_ring()` 旁 | 新增 `init_kni_tx_ring()`：per-port 建 `kni_tx_ring_p%d`（用 `create_ring()`，`RING_F_SP_SC`：单生产者 primary → 单消费者一个 secondary），在 `ff_dpdk_init()` 的 `1686` 之后调用 | ~30 行 |
| `lib/ff_dpdk_kni.c:181-202` `kni_process_rx()` | `190` 的 `rte_eth_tx_burst(port_id, queue_id, ...)` 改为 `rte_ring_enqueue_burst(kni_tx_ring[port_id], ...)`；入 ring 失败按现有 `191-197` 的丢弃/统计逻辑处理 | ~15 行 |
| `lib/ff_dpdk_kni.c:501-507` `ff_kni_process()` | 去掉 `queue_id` 参数依赖（tx 侧本就`__rte_unused`，见 `145`，已复核；rx 侧改造后也不再需要） | ~5 行 |
| `lib/ff_dpdk_if.c:2764-2768` |调用点移出 rx 循环，改为「若 `enable_kni &&ff_kni_is_owner_thread()`，按 `cfg.dpdk.nb_ports` 遍历调用一次」 | ~12 行 |
| `lib/ff_dpdk_if.c:2756-2801` 内新增 | 指定 secondary（`tx_queue_id[port] == 0` 的那个）在 rx 循环里 dequeue `kni_tx_ring[port_id]` 并 `send_burst`/`rte_eth_tx_burst` | ~20 行 |
| `lib/ff_dpdk_if.c:2080`（已复核） | **广播/多播 → KNI 的门禁**从 `enable_kni && ff_kni_is_owner_thread()` 改为 `enable_kni && !pkts_from_ring`（否则 slim 下广播/多播永不入 KNI；详见 2.3 第5 点） | ~2 行 |
| `lib/ff_config.c:1419-1435` | KNI 校验改为：`primary_slim=1` 时**不再要求** primary 在 `lcore_list` 中，但要求至少有一个 secondary（即 `nb_lcores >= 1`）来承担 `kni_tx_ring` 消费与入向收包 | ~8 行 |
| `lib/ff_dpdk_if.c:535` mbuf 公式 | 视 ring 深度决定是否把 `kni_tx_ring` 计入（现有公式已含 `P*KNI_MBUF_MAX + P*KNI_QUEUE_SIZE`，`543-546`，已复核，可复用其预算） | ~2 行 |

**可行性结论**：**有条件可行，作为退备方案**。前置条件：(i) virtio_user 口必须仍被 primary configure/start —— 由于 owner 仍是 primary，`821-825` 的 `total_nb_ports *= 2` 条件天然满足，**不需要改**（这是 K3-corrected 相对 K2 的优势，也是相对 K4 的优势——K4 必须改该条件）；(ii) `nb_dev_ports` 语义仍只在 primary 侧使用 ⇒ **N2 不被激活，可延后修**（相对 K2/K4 的优势——K4 前置必做 N2 修正）。

**与 B2 配置校验的冲突程度**：**低**。B2 的校验目的是"保证 primary 有队列以便驱动 `ff_kni_process()`"；K3 让 `ff_kni_process()` 不再需要队列，因此该校验的**前提消失**，改为"至少一个 secondary"即可。

**风险**：
- 新增一跳 ring ⇒ 内核 → 网卡方向多一次 enqueue/dequeue，延迟增加（管理面流量，可接受），且 ring 满时会丢包（需按现有 `kni_stat[port_id]->tx_dropped` 统计口径记账）。
- 消费者选择逻辑需明确且稳定：若选中的 secondary 崩溃，KNI 的 rx 方向会中断。`kni_tx_ring` 采用 `RING_F_SP_SC`（单生产者 primary → 单消费者一个 secondary），与 `kni_rp` 的 `RING_F_SC_DEQ` 单消费者设计一致（引自 11 §1.4 Q1 纠正：`kni_rp` 的单消费者是正确且充分的，不需要改为多消费者）。
- KNI 轮询频率从"每 rx 队列一次"变为"每轮一次"，在多队列场景下频率下降（对管理面无实质影响，但需在 `08` 的用例里覆盖 KNI 吞吐）。
- **广播/多播入队门禁改造的副作用（伴随 2.3 第 5 点）**：`ff_kni_enqueue()` 的 ratelimit 计数 `kni_rate_limt` 是**进程内全局**（`lib/ff_dpdk_kni.c:100`，已复核，每轮在 `lib/ff_dpdk_if.c:2701-2727` 复位）。门禁从"只有 owner 入队"改为"从线上收到该包的进程入队"后，入队者从 1 个进程变为 N 个进程，`console/general_packets_ratelimit` 是每进程配额（引自 11 §2.5 Q2 纠正），N 个进程各自一份 ⇒ **聚合限速放大约 N 倍**。但这不是 ratelimit 代码本身的问题，`kernel_packets_ratelimit` 在 `kni_process_tx` 中只有 owner 执行，**天然单点限速，不需要按 `nb_lcores` 折算默认值**（引自 11 §2.5 Q2 纠正）。`console/general_packets_ratelimit` 的聚合放大通过调整配置值即可，需 `08` 用例验证内核侧不被压垮。

**推荐度**：**中（退备方案，K4 为首选）**。K3-corrected 改动更小、风险更低，但接受 KNI 与 primary 绑定的代价（primary 崩溃 = KNI 断且不可原地恢复，`03` E10 已证）。K4 vs K3-corrected 的选择判据见 §2.5。

### 2.4 K4：secondary 作运行时 KNI owner（首选方案）

> K4 据 `11` Q3 + E4a 决定性实验（2026-08-10 实测）确立。E4a 已验证 secondary 通过 `VDEV_SCAN_REQ` 成功发现 primary 创建的 virtio_user 口、独立 probe 该口、成功访问共享 KNI ring。据 `11` §3.8 的关键发现——`kni_process_rx` 的 L190 `rte_eth_tx_burst(port_id, queue_id, ...)` 中 `queue_id` 来自 owner 自己的 rx 队列——**K4 的 owner secondary 直接用自己的 tx 队列发出，不需要新增 `kni_tx_ring`**。

**核心思路**：将 `ff_kni_is_owner_thread()` 拆分为两个概念：
- **init owner**（= primary）：执行 hotplug、`kni_stat` 分配、`kni_rp` 创建、`total_nb_ports *= 2`、`dev_configure`/`dev_start`
- **runtime owner**（= 指定 secondary）：执行 `ff_kni_process()`、广播/多播克隆入队

**K4 数据流**：

| 方向 | 谁做 | 路径 | 是否需新 ring |
| --- | --- | --- | --- |
| 物理口→内核 | 各 secondary 收包 → `ff_kni_enqueue()` → `kni_rp`（共享，`RING_F_SC_DEQ`） → runtime owner dequeue → `rte_eth_tx_burst(virtio_user_port, 0, ...)` | 否 |
| 内核→物理口 | runtime owner `rte_eth_rx_burst(virtio_user_port, 0, ...)` → `rte_eth_tx_burst(physical_port, own_queue_id, ...)` | **否！用自己的 tx 队列** |

**关键代码依据**（引自 11 §3.8）：`kni_process_rx()` 的 L190 `rte_eth_tx_burst(port_id, queue_id, ...)` 中，`port_id` 是物理口、`queue_id` 来自 `qconf->rx_queue_list[i].queue_id`（`lib/ff_dpdk_if.c:2761`，已复核），即**该进程自己的物理口 rx 队列 id**。若 owner 是 secondary，它用自己的 tx 队列发出——**不需要借道 ring（K3-corrected 的 `kni_tx_ring`）**。这是 K4 相对 K3-corrected 的核心优势。

**E4a 实测验证**（引自 11 §E4a 决定性结论）：

| 验证项 | 结果 | 证据 |
| --- | --- | --- |
| Primary 创建 virtio_user 口 | ✅ 成功 | `Port 1 MAC:20:90:6F:7D:5D:08` |
| Secondary 通过 `VDEV_SCAN_REQ` 发现 virtio_user 口 | ✅ 成功 | `VDEV_BUS: receive vdev, virtio_user0` + `Received 1 vdevs` |
| Secondary 独立 probe virtio_user 口 | ✅ 成功 | `VDEV_BUS: Search driver to probe device virtio_user0` |
| Secondary 访问共享 KNI ring | ✅ 成功 | `create kni ring success` |
| Secondary 完成完整初始化 | ✅ 成功 | `Successed to register dpdk interface` |

结合代码分析（引自 11 §3.7）：
- Secondary 通过 `rte_eth_dev_attach_secondary(name)` 绑定到 primary 创建的 ethdev（`virtio_user_ethdev.c:525-547`，已复核）
- `eth_virtio_dev_init` → `set_rxtx_funcs` 设置 rx/tx burst 函数指针（`virtio_ethdev.c:1951-1953`，已复核）
- `virtio_user_secondary_eth_dev_ops` 提供 secondary 专用 dev_ops（`virtio_ethdev.c:657-666`，已复核，不含 configure/start）
- **Secondary 可以对 virtio_user 口做 `rte_eth_rx_burst`/`rte_eth_tx_burst`**

**K4 需解决的问题（全部有代码依据，引自 11 §3.2-§3.5）**：

1. **N2 修正（前置必做）**：`nb_dev_ports` 在 secondary 侧"不正确"是源码自承的（`lib/ff_dpdk_if.c:79` 的注释 `/* primary is correct, secondary is not correct, but no impact now*/`，已复核）。owner secondary 需要 `nb_dev_ports` 算 `kni_stat[port_id]->port_id = port_idx + nb_dev_ports`（`lib/ff_dpdk_kni.c:478`，已复核），必须先按 §5 的方案修正（primary 发布到共享 memzone，secondary lookup 读取）。
2. **`total_nb_ports *= 2` 条件修正**：当前条件是 `enable_kni && ff_kni_is_owner_thread()`（`lib/ff_dpdk_if.c:821-825`，已复核）。owner 迁到 secondary 后，**primary 的 `total_nb_ports` 不再翻倍 ⇒ primary 不会对 virtio_user 口做 `dev_configure`/`dev_start`（`1061-1148`）⇒ 该口永远处于未启动状态 ⇒ owner secondary 的 `rte_eth_tx_burst(kni_stat[]->port_id, 0, ...)` 全失败**。必须把该条件改为仅 `enable_kni`（在 primary 上恒真）。
3. **`ff_kni_is_owner_thread()` 改造**：`lib/ff_dpdk_kni.c:92-98`（已复核），改为 `ff_cur_proc_id() == cfg.kni.owner_proc_id`。
4. **secondary 在 `ff_kni_alloc()` 中也分配 `kni_stat[port_id]`**：`lib/ff_dpdk_kni.c:434-479`（已复核）当前只有 owner（primary）分配。owner secondary 也需要分配自己的 `kni_stat[port_id]` 并设 `port_id = port_idx + nb_dev_ports`（前提：N2 已修正）。
5. **`ff_kni_process()` 调用移出 rx 循环**：`lib/ff_dpdk_if.c:2764-2768`（已复核），避免 KNI 轮询频率与队列数耦合（K3-corrected 也需要）。
6. **广播/多播门禁改为 `!pkts_from_ring`**：`lib/ff_dpdk_if.c:2080`（已复核），与 K3-corrected 相同（详见 §2.3 第 5 点的改法与理由）。
7. **B2 校验调整**：`lib/ff_config.c:1419-1435`（已复核），校验对象从 primary lcore 改为 `proc_lcore[cfg->kni.owner_proc_id]`。

**代码改动清单**：

> 给实现者的定位提示：下表行号仅作辅助定位，**以代码文本匹配为准**。仓库后续提交会使行号漂移，改动前请先 grep 确认。

| 位置 | 改法 | 估计量 |
|---|---|---|
| `lib/ff_config.h:337-346`（kni 结构，已复核） | 新增 `int owner_proc_id;` | ~1 行 |
| `lib/ff_config.c:1085-1086`（`MATCH("kni","enable")` 旁，已复核） | 新增 `MATCH("kni","owner_proc_id")` 解析 | ~2 行 |
| `lib/ff_dpdk_kni.c:92-98`（已复核） | owner 判定改为 `ff_cur_proc_id() == cfg.kni.owner_proc_id` | ~3 行 |
| `lib/ff_dpdk_if.c:821-825`（已复核） | 条件改为仅 `enable_kni`（否则 primary 不配置 virtio_user 口） | ~2 行 |
| `lib/ff_dpdk_kni.c:434-479`（已复核） | owner secondary 也分配 `kni_stat[port_id]` 并设 `port_id`（前提：N2 已修正） | ~15 行 |
| `lib/ff_dpdk_if.c:79`、`421-423`、`758`、`844`；`lib/ff_dpdk_kni.c:478` | N2 修正（前置必做，见 §5） | ~15 行 |
| `lib/ff_dpdk_if.c:2764-2768`（已复核） | `ff_kni_process()` 调用移出 rx 循环，改为按 `cfg.dpdk.nb_ports` 遍历调用一次 | ~12 行 |
| `lib/ff_dpdk_if.c:2080`（已复核） | 广播/多播 → KNI 的门禁从 `enable_kni && ff_kni_is_owner_thread()` 改为 `enable_kni && !pkts_from_ring` | ~2 行 |
| `lib/ff_config.c:1419-1435`（已复核） | 校验对象从 primary lcore 改为 `proc_lcore[cfg->kni.owner_proc_id]` | ~8 行 |

**可行性结论**：**可行，首选方案**。E4a 已实测验证 secondary 能发现、probe virtio_user 口并访问共享 KNI ring。代码分析（引自 11 §3.7）确认 secondary 可对 virtio_user 口做 rx/tx burst。前置条件：(i) N2 修正（primary 发布 `nb_dev_ports` 到共享 memzone）；(ii) `total_nb_ports *= 2` 条件改为仅 `enable_kni`；(iii) primary 在线（vdev 可见性依赖，见风险）。

**与 B2 配置校验的冲突程度**：**中**。需重写 `1419-1435` 的校验对象（从 primary lcore 改为 `proc_lcore[cfg->kni.owner_proc_id]`），但方向明确。

**风险**：
- **vdev 可见性依赖 primary 在线**（引自 11 §3.6）：secondary 通过 IPC 向 primary 索取 vdev 列表（`vdev.c:482-503`，已复核）。owner secondary 重启时需要 primary 在线才能重新发现 virtio_user 口。primary 退出后新起的 secondary 无法发现 virtio_user 口。**但已 probe 且已 start 的口不依赖 primary 在线做 rx/tx burst**（引自 11 §3.7，需 E4b 实测确认）。
- **owner secondary 崩溃后 KNI 中断**：K4 的 KNI 能力绑定在指定 secondary 上，该 secondary 崩溃则 KNI 中断。**但恢复只需重启该 secondary**（可原地重启，`03` E2e 已证），不需要等计划内全组重启（相对 K3-corrected 的优势——K3-corrected 下 primary 崩溃 = KNI 断且不可原地恢复，`03` E10 已证）。
- **改动面较大**：需 N2 修正 + `total_nb_ports` 条件修正 + owner 判定改造 + secondary `kni_stat` 分配，共 8~10 处改动（相对 K3-corrected 的 7~8 处）。
- **广播/多播入队门禁改造的副作用**：与 K3-corrected 相同（见 §2.3 风险段），`console/general_packets_ratelimit` 是每进程配额，N 个进程各自一份 ⇒ 聚合限速放大约 N 倍。`kernel_packets_ratelimit` 在 `kni_process_tx` 中只有 owner 执行，天然单点限速（引自 11 §2.5 Q2 纠正）。

**推荐度**：**高（首选）**。E4a 已通过，K4 在架构上更干净（不需要新 ring、故障隔离更好、恢复只需重启 secondary）。

---

### 2.5 四路径对比小结

| 路径 | primary 是否碰物理口队列 | 是否消除孤儿队列 | 是否需修 N2 | 是否需改 `total_nb_ports` 条件 | 是否需新 ring | 改动点数（估） | 推荐度 |
|---|---|---|---|---|---|---|---|
| **K1** 保留最小队列 | **是**（1 对队列） | ⚠️ 部分 | 否 | 否 | 否 | 3~4 | 中（KNI 必开时的兜底） |
| **K2** owner 迁 secondary | 否（primary 完全不碰） | ✅ 是 | **是（前置必做）** | **是（否则 KNI 全废）** | 否 | 9+ | **低（不推荐）** |
| **K3-corrected** primary 留 KNI + ring 借道 | 否（**rx/tx 都不碰**，只碰 virtio_user 口） | ✅ 是 | 否（可延后） | 否 | **是**（`kni_tx_ring`，`RING_F_SP_SC`） | 7~8（含广播/多播门禁 1 处） | **中（退备）** |
| **K4** secondary 作 runtime owner | 否（primary 只做 init，不碰任何队列） | ✅ 是 | **是（前置必做）** | **是**（改为仅 `enable_kni`） | **否** | 8~10（含 N2 修正） | **高（首选，E4a 已通过）** |

**K4 vs K3-corrected 选择判据**：

| 判据 | K4 | K3-corrected |
|---|---|---|
| E4a 实测 | ✅ 已通过 | 不依赖（primary 自己用 virtio_user 口） |
| 是否需新增 ring | 否 | 是（`kni_tx_ring`，多一跳延迟） |
| KNI owner 崩溃影响 | 只影响 KNI，数据面与控制面不受影响 | primary 崩溃 = KNI 断 + 控制面全断（IPC/扩堆/中断同失） |
| KNI 恢复 | 重启该 secondary 即可（可原地重启） | 必须等计划内全组重启（primary 不可原地拉回，E10 已证） |
| 前置依赖 | N2 修正 + `total_nb_ports` 条件修正 | 无（N2 可延后、`total_nb_ports` 天然满足） |
| 改动量 | 8~10 处 | 7~8 处 |
| vdev 可见性依赖 | 依赖 primary 在线（secondary 重启时） | 无（primary 自己创建并使用） |

**裁决：K4 为首选**（E4a 已通过）。K3-corrected 为退备方案（若 K4 的前置依赖 N2 修正或 `total_nb_ports` 条件修正遇到不可逾越的障碍，可回退到 K3-corrected）。

---

## 三、仅 primary 生效的控制面操作：归属与时序重排

>逐项给出「谁执行 / 何时执行 / primary 瘦身后如何保证不丢能力 / 改动要点」。

### 3.1 MTU 设置（`lib/ff_dpdk_if.c:294-325`，结合 N5）

- **现状**：`297-298` 的 `if (rte_eal_process_type() != RTE_PROC_PRIMARY) return 0;`（已复核）—— secondary **静默成功**，且 `ctx->mtu = mtu`（`323`）在门禁之后 ⇒ secondary 连本地缓存都不更新。
- **primary-slim 后的问题（N5 升级为功能回归）**：slim primary 无 ifp（`03` 2.3 改动 #4 裁决）⇒ `ff_dpdk_if_set_mtu()` 在 primary 上**永远不会被调用**（没有 ifp 就没有 `SIOCSIFMTU` 的落点）；而在 secondary 上被调用时静默 `return 0` ⇒ **`ff_ifconfig <if> mtu 9000` 在任何进程上都是"假成功"**，MTU 巨帧特性（已交付）失效。
- **设计（分两档，建议 P1 先落地、P2 排入 `07`）**：

| 档 | 设计 | 谁执行 | 何时执行 | 改动要点 |
|---|---|---|---|---|
| **P1（必做，2 行）** | 把 `297-298` 的 `return 0` 改为 `return EPERM` | 无人执行硬件操作，但**失败对用户可见** | 运行期 | `lib/ff_dpdk_if.c:297-298`。风险：可能改变非 slim 多进程场景下 `ff_ifconfig` 的既有返回值 ⇒ 建议用 `ff_global_cfg.dpdk.primary_slim` 门控，只在 slim 下返回 `EPERM`，保证零回归 |
| **P2（完整，排入 `07`）** | 新增 msg 类型（例如 `FF_DEVCTL`），secondary 把 MTU 请求经 `msg_ring[0]` 转发给 slim primary，由 primary 调`rte_eth_dev_set_mtu()`；成功后各 secondary 更新自己的 `ctx->mtu` | primary 执行硬件操作；各 secondary 更新本地缓存 | 运行期 | 改动点：`lib/ff_msg.h` 新增类型；`handle_msg()` 分派（`lib/ff_dpdk_if.c:2298-2340`，已复核）新增 case；`lib/ff_dpdk_if.c:294-325` 拆成"转发"与"执行"两个函数；`tools/ff_ifconfig`侧可不改（仍走ioctl → msg） |

- **必须在文档中警示的固有代价**：`302-318`（已复核）的 `-EBUSY` 分支会 `rte_eth_dev_stop()` → `set_mtu` → `rte_eth_dev_start()`。**在多进程下这会瞬断全部 secondary 的队列**（设备是共享的）。这不是 slim 引入的问题，但 P2 会让它更容易被触发 ⇒ 建议 P2 实现时在执行前打WARNING 并在文档里标注"运行期改 MTU 属于全局中断操作"。

### 3.2 link status（`lib/ff_dpdk_if.c:1189-1191` → `354-411`，结合 N7）

- **现状**：primary-only，仅在 `init_port_start()` 末尾执行**一次**（引自 02；`354` 的函数定义已复核）。全库无运行期 LSC 回调注册。
- **primary 瘦身后**：**无影响**。primary 本就是唯一的 `dev_start()`执行者（`1148`，引自 02），启动期检查链路正是它该做的事。
- **归属裁决**：**保留在 primary，不改**。
- **N7 的既有缺陷与归属修正（据 `01` §1.2.5 修正本文初稿）**：运行期 link down/up 无人感知（primary 退出后更明显）。**本轮不改**；若要补，**必须注册在 slim primary 侧，不能注册在 secondary**——DPDK 官方明确 "The delivery of interrupts, such as Ethernet device link status interrupts, do not work in secondary processes. All interrupts are triggered inside the primary process only."（引自 `01` §1.2.5，`doc/guides/prog_guide/multi_proc_support.rst:174-177`）。
  > **勘误留档**：本文档初稿曾建议"若要补，应在某个 secondary 侧注册 `RTE_ETH_EVENT_INTR_LSC` 回调（而不是 slim primary，因为 primary 可能先挂）"。据上述官方约束，该建议**错误且不可行**，现予撤回。正确设计：LSC 回调只能由 slim primary 承担；这也进一步说明"primary 必须常驻"（若 primary 挂了，链路事件感知能力本就随之丧失，属既有单点，不是本方案可解的问题）。

### 3.3 flow isolate（`lib/ff_dpdk_if.c:1707-1715`）

- **现状**：primary-only 门禁完好（`1707` 的 `if (rte_eal_process_type() == RTE_PROC_PRIMARY)`，已复核），在 `init_port_start()` **之前**执行（`1718`，已复核）。
- **primary 瘦身后**：**无影响**，天然属于 primary。**不改**。
- **但需注意与 S1 结论的交互（`03` R12）**：`FF_FLOW_ISOLATE` 开启时 `set_rss_table()` 整体被编译掉（`lib/ff_dpdk_if.c:785-810` 的 `#if !defined(...)`，已复核）⇒ "reta 自动收缩 ⇒ 无孤儿队列"的论证在该配置下不适用，需靠 `create_tcp_flow()` 的 `nb_queues = pconf->nb_lcores` 收缩（引自 02 B5）。

### 3.4 ipip flow（`lib/ff_dpdk_if.c:1760-1768`）

- **现状**：primary-only 门禁完好（`1760`，已复核），在 `init_port_start()` **之后**执行。规则数按 `pconf->nb_lcores` 逐队列建（`1449`/`1455`，引自 02）。
- **primary 瘦身后**：**无影响**，且规则数会随 `nb_lcores` 收缩自动正确。**不改**。

### 3.5 RSS thash ctx（`lib/ff_dpdk_if.c:3478-3540`，`FF_RSS_DIAG`）

- **现状**：`ff_rss_thash_ctx_init()` 是 primary-only（`3483-3484`，已复核），读 `ff_cur_lcore_conf()->nb_queue_list[port_id]`（`3490`，已复核），在 `init_port_start()` 之后由`1734-1736`（已复核）调用；而 `ff_rss_thash_build_key()` 的调用点（`920-923`，引自 02）在 `1061` 门禁**之前**，两边都跑。
- **primary 瘦身后**：slim primary 的 `nb_queue_list[port_id]` 为 0（因 `505` 的赋值从未执行，已复核）⇒ `3502` 的 `nbq > 0` 不成立 ⇒ **reta 一致性诊断被静默跳过**（仅诊断能力损失）。
- **改动要点（S 级）**：把 `3490` 改为读 `ff_global_cfg.dpdk.port_cfgs[port_id].nb_lcores`（全局真值，与本进程队列无关），诊断即可在 slim 下继续有效。1 行。
- **谁执行 / 何时**：仍是 primary，仍在 `init_port_start()` 之后。**时序不变**。

### 3.6 `init_flow()` / `fdir_add_tcp_flow()` 缺门禁（N3）

- **现状（已复核）**：`init_flow(0, 80)` 在 `1745`、`fdir_add_tcp_flow(0, 0, FF_FLOW_INGRESS, 0, 80)` 在 `1777`，**两者都没有** `rte_eal_process_type()` 判断，与相邻的 `1707`/`1760`（有门禁）不对称。
- **primary 瘦身后**：不变糟也不变好，但 secondary 数量增加会放大"重复安装 rte_flow 规则 / 告警刷屏 / secondary 越权设备操作"。
- **改动要点（O 级，各 2 行）**：补`if (rte_eal_process_type() == RTE_PROC_PRIMARY)` 包裹，与 `1707`/`1760` 对齐。
- **谁执行 / 何时**：补门禁后 = primary，`init_port_start()` 之后（时序不变）。

### 3.7 归属汇总表

| 控制面项 | 谁执行（slim 后） | 何时执行 | 能力是否会丢 | 改动 |
|---|---|---|---|---|
| MTU 设置 | P1：无人（但报错可见）／P2：primary（经 msg 转发） | 运行期 | P1 会丢运行期改 MTU 能力；P2 不丢 | `297-298`（+ P2 的 msg 链路） |
| link status检查 | primary | 启动期一次 | 不丢 | 不改 |
| flow isolate | primary | `init_port_start()` 前 | 不丢 | 不改 |
| ipip flow | primary | `init_port_start()` 后 | 不丢 | 不改 |
| RSS thash 诊断 | primary | `init_port_start()` 后 | 诊断会丢（除非改 `3490`） | `3490` 1 行 |
| `init_flow` / `fdir` | 现状：所有进程；建议：primary | `init_port_start()` 后 | 不丢（但有越权与重复告警） | 各 2 行门禁 |
| KNI 收发 | 见第二节 **K4（首选）**：init owner=primary（hotplug/dev_configure/dev_start）+ runtime owner=指定 secondary（virtio_user 口双向收发 + 用自己 tx 队列发出）+ 各 secondary（物理口**入向**收包并入 `kni_rp` ring）。退备 K3-corrected：primary（virtio_user 口双向）+ 各 secondary（物理口**入向**收包并入 `kni_rp` ring）+ 指定 secondary（经 `kni_tx_ring` 消费物理口**出向** tx） | 运行期每轮 | 不丢（K4 或 K3-corrected，含广播/多播门禁修正）／完全丢（不做任何改造） | 见 §2.4（K4）/ §2.3（K3-corrected） |

---

## 四、`msg_ring` / tools 归属方案（N1）

### 4.1 两个候选与裁决

| 候选 | 内容 | 优点 | 缺点 |
|---|---|---|---|
| **甲（推荐）** | **slim primary 精简循环继续消费 `msg_ring[0]`**；tools 的默认 `ff_proc_id = 0`（`tools/compat/ff_ipc.c:42`，已复核）**保持不变** | (1) 零工具改动、零脚本兼容性破坏；(2) 成本极低——`process_msg_ring()` 在 rx 循环**之外**（`lib/ff_dpdk_if.c:2803`，已复核），slim primary 天然会执行它，**不需要写一行代码**；(3) `proc_id=0 ⇒ primary` 这个运维心智模型不变 | primary 无 ifp ⇒在 primary 上执行 `ff_ifconfig`/`ff_route` 会看不到接口/操作无对象（属预期，见 4.3） |
| **乙** | 把 tools 默认 `ff_proc_id` 改为"第一个收包进程"（slim 下= 1） | 让默认命令落在有ifp 的进程上，`ff_ifconfig`/`ff_route` 默认可用 | (1) **破坏向后兼容**：`ff_top`/`ff_traffic`/`ff_sysctl` 都是 **per-proc** 数据（`handle_top_msg`/`handle_traffic_msg`，`lib/ff_dpdk_if.c:2186-2258`，已复核），默认值一改，所有既有脚本采到的就是"另一个进程"的数据而**不自知**；(2) tools 编译时不知道运行时是否 slim（`config.ini` 由 `-c` 传入，但默认值在`ff_ipc.c:42` 是编译期常量）⇒ 需要读配置才能决定，复杂度上升；(3) `knictl` 的 `knictl_action` 是进程私有（`lib/ff_dpdk_if.c:77`，引自 02），本就需要逐 proc 下发，改默认值无助于此 |

**裁决：采用候选甲**。理由：向后兼容优先，且候选甲的代码改动量为 **0**（S1 的 primary 常驻设计已自动满足），这也是选S1 而非 S2 的实质收益之一（见 `03` 2.4）。

### 4.2 需要配套的说明与可选增强

- **必做（文档级）**：在运维手册中明确分类：
  - 可在 primary（默认 `-p` 缺省）执行：`ff_sysctl`（读栈参数）、`ff_top`（看 primary 自身负载，slim 下应接近全idle）、`ff_ngctl`/`ff_ipfw`（若其操作对象是进程内栈状态）。
  - **必须带 `-p <收包进程 id>`**：`ff_ifconfig`（无 ifp）、`ff_route`（无接口的路由无意义）、`ff_traffic`（primary 无收发包，数值恒 0）、`ff_knictl`（需逐进程下发）。
- **可选增强（O 级，排入 `07`）**：在 `FF_TOP` 或新增的 msg 响应里带一个 `is_slim_primary` 标志位，让工具在目标进程是 slim primary 时打印一行提示（例如 `note: proc 0 is a slim primary (no queues/ifp); use -p <id> for interface/traffic commands`）。这比改默认值安全得多。

### 4.3 `msg_ring` 容量与生命周期的既有风险（不因本方案变化，但需记录）

- `msg_ring` 是全库唯一按 `proc_id` 索引的共享对象（`02` B6 表），数量 = `nb_procs`（`lib/ff_dpdk_if.c:698-700`，已复核）；`message_pool` 容量 = `MSG_RING_SIZE * 2 * nb_rings`（`706`，已复核）。
- primary 被强杀时 in-flight 的 msg 对象永久泄漏（消费者才`rte_mempool_put`，`2346`，已复核）——沿用 `02` 开放问题 5，**S1 不改善此项**。slim primary 处理的消息更少，泄漏概率相应降低（次要收益）。

---

## 五、`nb_dev_ports` 语义修正方案（N2 / N8）

### 5.1 现状与语义

```c
// lib/ff_dpdk_if.c:79（引自 02）
int nb_dev_ports = 0;   /* primary is correct, secondary is not correct, but no impact now*/
```
```c
// lib/ff_dpdk_if.c:421-426（已复核）
if (nb_dev_ports == 0) {
    nb_dev_ports = rte_eth_dev_count_avail();
}
if (nb_dev_ports == 0) {
    rte_exit(EXIT_FAILURE, "No probed ethernet devices\n");
}
```

- 它在 `init_lcore_conf()`（`ff_dpdk_init()` 第一步，`1682`，已复核）做一次 `rte_eth_dev_count_avail()` 快照。
- **语义应当是「hotplug virtio_user 口之前，机器上探测到的物理设备总数」**，因为它被当作 **virtio_user 口 id 的基址**使用：
  - `kni_stat[port_id]->port_id = port_idx + nb_dev_ports`（`lib/ff_dpdk_kni.c:478`，已复核）
  - `u_port_id = i - nb_ports + nb_dev_ports`（`lib/ff_dpdk_if.c:844`，已复核）
- **漂移成因**：KNI 的 `rte_eal_hotplug_add()`（`lib/ff_dpdk_kni.c:474`）发生在 `init_kni()`（`1693`，已复核）**之后**，会增加端口数。secondary 若在 primary 完成 hotplug 之后启动，其 `rte_eth_dev_count_avail()` 会把 virtio_user 口也数进去 ⇒ 偏大。

### 5.2 三个候选修正方式与裁决

| 候选 | 做法 | 评价 |
|---|---|---|
| **甲（否决）** | 改成"只统计配置里的物理口"（`ff_global_cfg.dpdk.nb_ports`） | **破坏语义**。`nb_dev_ports` 是 **id 基址**，必须等于 EAL 探测到的物理设备总数；配置里使用的 port 数可能小于探测总数（例如机器有 2 张卡但只用 1 张），改后 virtio_user 的 port id 会与已存在的物理口 id 撞车 |
| **乙（否决）** | 用 `max_portid + 1` 代替 | 只在"物理口 id 从 0 连续编号且全部被配置使用"时正确，无普适性 |
| **丙（推荐）** | **primary 在 hotplug 之前把快照值发布到共享内存，secondary 读取**：primary 在 `init_lcore_conf()`（`421-423`）拿到 `rte_eth_dev_count_avail()` 后，`rte_memzone_reserve("ff_nb_dev_ports", ...)` 写入；secondary 走 `rte_memzone_lookup()` 读取，失败则退回本地 `rte_eth_dev_count_avail()`（保持向后兼容） | **语义精确、改动集中、与既有 primary-create/secondary-lookup 模式一致**（`02` B8 已有 6 类同构对象）。缺点：新增一个共享对象，需要处理 lookup 失败与版本兼容 |

**裁决：候选丙。**

### 5.3 改动清单与影响面

| 位置 | 改法 |
|---|---|
| `lib/ff_dpdk_if.c:79` | 保留全局变量，但删掉"secondary is not correct"注释（问题被修掉后注释失效） |
| `lib/ff_dpdk_if.c:421-426`（已复核） | primary：`nb_dev_ports = rte_eth_dev_count_avail()` 后 `rte_memzone_reserve` 发布；secondary：先 `rte_memzone_lookup` 取值，失败再本地统计并打 WARNING |
| `lib/ff_dpdk_kni.c:478`（已复核） | 无需改代码，取值自动变正确 |
| `lib/ff_dpdk_if.c:844`（已复核） | 同上 |
| `lib/ff_dpdk_if.c:758`（已复核） | `ff_kni_init(nb_ports=nb_dev_ports, ...)` 用它给 `kni_stat`/`kni_rp` 数组定长（`lib/ff_dpdk_kni.c:388-405`，已复核）。数组按 `port_id` 索引，因此**必须**按 `nb_dev_ports` 定长才安全 —— 修正后仍正确，且在 secondary 上也正确（现状 secondary 偏大 ⇒ 多分配，不越界；修正后精确） |

**影响面判断**：
- **当前无功能变化**（两处使用点都在 primary 分支内，`nb_dev_ports` 本来就正确）；
- **前置价值**：K2 路线（owner 迁 secondary）**必须**先做本修正，否则 `478` 会算错；**K4 路线同样必须先做本修正**（owner secondary 需要 `nb_dev_ports` 算 `kni_stat[port_id]->port_id`，引自 11 §3.5）；K3-corrected 路线可延后做（`03` 5.2 的步骤 8 已把它排在 KNI 改造之前）。

### 5.4 N8 的可读性问题（O 级，可与 5.3 一并做）

`init_kni()`（`lib/ff_dpdk_if.c:756-781`，已复核）中：

1. 同名变量 `nb_ports` 先取 `nb_dev_ports`（`758`）、中途在 `773` 被重新赋值为 `ff_global_cfg.dpdk.nb_ports`，两个语义共用一个名字 ⇒ 建议重命名为 `nb_dev_ports_snapshot` / `nb_cfg_ports`。
2. `770-771` 的 `struct rte_mempool *mbuf_pool = pktmbuf_pool[socket_id];` **声明后从未使用**（`ff_kni_alloc()` 不接收 mempool 参数，见 `lib/ff_dpdk_kni.c:430-432`，已复核）⇒ 死代码，建议删除。

---

## 六、未决问题 / `01` 提供的 DPDK 侧约束与假设复核

> **`01-外网调研与交叉验证.md` 的状态**：本文档开始写作时为空，定稿前再次读取已完成（内容以 `01` 现行版本为准，本文不写死其行数以免随修订漂移）。已据其内容修正本文 §3.2（LSC 回调归属，见该节勘误留档），并在下表复核 D/E/F 三处假设（与 `03` 第七节的 A/B/C 并列）。
>
> **`01` 中与本文直接相关的硬约束**：
> - **所有中断只在 primary 内触发**（`01` §1.2.5，`multi_proc_support.rst:174-177`）⇒ 已用于修正 §3.2；K3-corrected 下 KNI owner 留在 primary，与"中断只在 primary"的归属一致。K4 下 KNI owner 是 secondary，但 KNI 不依赖中断（轮询模式），不受此约束影响。
> - **primary 是 IPC 唯一服务端**（`01` §1.2.1，`eal_common_proc.c:750-751`）⇒ 印证 K2 的核心批评：把 hotplug 调用点挪到 secondary 并不解除对 primary 的依赖。K4 保留 init owner=primary（hotplug 仍由 primary 执行），不违反此约束。
> - **vdev bus 的 secondary scan 需向 primary 索取设备清单**（`01` §1.2.4，`drivers/bus/vdev/vdev.c:388-503`）⇒ KNI 的 virtio_user 口属 vdev bus，secondary 侧对该口的可见性依赖 primary 在线。**E4a 已实测验证**（引自 11 E4a）：secondary 通过 `VDEV_SCAN_REQ` 成功发现 virtio_user0 口。这是假设 D 的风险来源，E4a 已坐实其成立。
> - **`01` §1.4.1 第2 项的判断需修正**：原判断"该口不属于 secondary 的收包路径 ⇒ 佐证 K3 的设计（virtio_user 口只由 primary 使用，secondary 无需看见它）"在 K3-corrected 下成立，但在 **K4 下不成立**——K4 的 runtime owner secondary 需要看到并使用 virtio_user 口。E4a 已证明 secondary 能通过 `VDEV_SCAN_REQ` 看到 primary 创建的 virtio_user 口（前提：primary 在线）。

| 编号 | 假设 | 复核结果 | 若结论相反 |
|---|---|---|---|
| **假设 D** | **secondary 可以对 primary 已`dev_configure`+`dev_start` 的 virtio_user 口做 `rte_eth_rx_burst`/`tx_burst`**（**K2/K4 的前提；K3-corrected 不依赖此项**，因为 virtio_user 侧仍由 primary 收发） | **✅ E4a 已实测成立**（引自 11 §3.7 + E4a）。secondary 通过 `VDEV_SCAN_REQ` 成功发现 primary 创建的 virtio_user0 口（`VDEV_BUS: receive vdev, virtio_user0` + `Received 1 vdevs`）、独立 probe 该口（`Search driver to probe device virtio_user0`）、成功访问共享 KNI ring（`create kni ring success`）。代码层面：secondary 通过 `rte_eth_dev_attach_secondary(name)` 绑定（`virtio_user_ethdev.c:525-547`），`eth_virtio_dev_init` → `set_rxtx_funcs` 设置 rx/tx burst 函数指针（`virtio_ethdev.c:1951-1953`），`virtio_user_secondary_eth_dev_ops` 提供 secondary 专用 dev_ops（`virtio_ethdev.c:657-666`，不含 configure/start）。**K4 可行性坐实**。限制：vdev 可见性依赖 primary 在线（secondary 重启时需 primary 响应 `VDEV_SCAN_REQ`） | 假设不成立则 K4 不可行，回退到 K3-corrected |
| **假设 E** | **`rte_memzone_reserve`/`rte_memzone_lookup` 是发布 `nb_dev_ports` 快照的合规手段**（5.2 候选丙） | **仍未决**。`01` 未涉及 memzone 的多进程语义；f-stack 已大量使用 primary-create/secondary-lookup 模式（`02` B8 的 6 类对象），memzone 是 DPDK 标准共享手段，但未查证 24.11.6 是否有额外要求。**注意**：`01` §1.2.2 指出 secondary 无法自行扩堆 ⇒ memzone **必须由 primary 创建**（本方案正是如此），secondary 只 lookup，符合约束。**K4 前置必做** | 改用其他发布渠道（例如共享 struct，或让 secondary 通过 `rte_eth_dev_get_name_by_port()` 逐口识别 virtio_user 自行推导） |
| **假设 F** | **primary 只做 virtio_user 口收发、完全不碰物理口队列，DPDK 层面无阻碍**（K3-corrected 的核心前提） | **✅ E4a 间接验证**（引自 11 E4a）。E4a 中 primary 成功创建并启动 virtio_user 口（`Port 1 MAC:...`），primary 与 secondary 都完成了完整初始化。**K4 下此假设不再关键**（K4 的 primary 只做 init，runtime owner 是 secondary）。K3-corrected 仍依赖此假设，但 E4a 已证明 primary 能独立配置 virtio_user 口 | K3-corrected 需退化为 K1（primary 保留物理口最小队列） |

### 其他未决问题

1. **~~K3 的 `kni_tx_ring` 消费者选择~~**（已关闭，据 `11` Q1 纠正）：`kni_rp`（物理口→内核方向）已是 `RING_F_SC_DEQ` 单消费者，正确且充分，不需要改为多消费者。K3-corrected 的 `kni_tx_ring` 采用 `RING_F_SP_SC`（单生产者 primary → 单消费者一个 secondary），与 `kni_rp` 的单消费者设计一致。K4 不需要 `kni_tx_ring`。
2. **KNI 轮询频率从"每 rx 队列一次"降为"每轮一次"的实际影响**（管理面吞吐、SSH 交互延迟），需 E4b（KNI 功能基线实验，`11` §E4a 已列出 E4b-E4f 待做）实测。
3. **`ff_kni_enqueue()` 的错误统计路径**（`lib/ff_dpdk_kni.c:536-540`，已复核）在非 owner 进程上会跳过统计 ⇒ 全局丢包数偏小。是否需要把 `kni_stat` 改为共享（primary 创建、全进程可写）以获得准确统计，待定（涉及跨进程原子累加）。
4. **`knictl_action` 的逐进程下发**（`lib/ff_dpdk_if.c:77`、`2259-2288`）在 slim 下是否需要"广播"语义（一条命令下发到所有 proc），属工具侧增强，本轮不设计。
5. **`FF_FLOW_ISOLATE`/`FF_FLOW_IPIP` 与 KNI 同时开启时的 rte_flow 规则是否会把管理流量误导到 secondary 队列**（导致 KNI 收不到 ARP/ICMP），需实测。
6. **MTU P2 方案中 `dev_stop/dev_start` 期间各secondary 的队列可用性**（`lib/ff_dpdk_if.c:302-318`，已复核）需实测确认恢复行为，否则运行期改 MTU 可能导致 secondary 永久失能。
7. **广播/多播门禁改造（`lib/ff_dpdk_if.c:2080` → `!pkts_from_ring`）的份数与限速语义需实测**（E4d 用例）：确认内核侧每个广播/多播报文恰好收到一份（不重不漏），且 `console/general_packets_ratelimit` 由 1 个进程分摊到 N 个进程后聚合限速放大约 N 倍是否可接受（引自 `11` §2.5 Q2 纠正：`kernel_packets_ratelimit` 在 `kni_process_tx` 中只有 owner 执行，天然单点限速，不受影响；涉及 `console_packets_ratelimit`/`general_packets_ratelimit` 默认值，`lib/ff_config.h:339-341`，已复核）。
8. **K4 的 vdev 可见性边界**（据 `11` §3.6 + E4a 新增）：owner secondary 重启时需要 primary 在线才能重新发现 virtio_user 口（`vdev_scan` 的 IPC 请求）。primary 缺席时 owner secondary 能否重新 probe virtio_user 口？**预期失败**（vdev scan 无 primary 响应），需 E4b 实测确认。但已 probe 且已 start 的口不依赖 primary 在线做 rx/tx burst（引自 `11` §3.7），也需 E4b 实测确认。
9. **K4 的 owner secondary 崩溃恢复**（据 `11` §3.10 + E4a 新增）：owner secondary 崩溃后 KNI 中断，重启该 secondary 可恢复 KNI（前提：primary 在线、vdev 可见）。需 E4b 实测确认恢复路径。
10. **~~KNI 与 primary 存活期绑定~~**（K3-corrected 下的风险，K4 下已缓解）：K3-corrected 下 KNI 能力随 primary 崩溃一并丧失，且 `03` §7.3 已实测 primary 不可原地拉回 ⇒ 恢复 KNI 必须等计划内全组重启。**K4 下此风险已缓解**：KNI owner 是 secondary，可原地重启恢复（前提：primary 在线）。若某些部署把 KNI 当作**管理通道**（SSH 走 KNI），则 K3-corrected 下 primary 崩溃会同时失去管理通道，属需在运维手册显著标注的风险；K4 下此风险降级为"owner secondary 崩溃 = KNI 临时中断，重启即恢复"。
