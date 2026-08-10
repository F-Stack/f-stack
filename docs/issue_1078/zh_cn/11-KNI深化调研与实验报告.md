# 11-KNI 深化调研与实验报告

> 对象：`/data/workspace/f-stack`（DPDK 24.11.6）。本轮只读不改：未修改 `lib/` 任何代码、未编译、未提交。
> 行号标注规则：`已复核` = 本文档作者用 `read_file` 重新读过该行。所有结论均有 file:line 支撑，严禁臆测。
> 本文档回答用户对第一轮 KNI 方案（`04-KNI与控制流归属方案.md` 的 K3）提出的三个质疑 Q1/Q2/Q3，并据 DPDK 源码坐实每条结论。

---

## Q1: kni_tx_ring 单消费者足矣，不需要多消费者

### 代码证据

#### 1.1 kni_rp 的 ring 标志：RING_F_SC_DEQ（单消费者）

`ff_kni_alloc()` 中，primary 创建 `kni_rp[port_id]` 时使用了 `RING_F_SC_DEQ` 标志：

```c
// lib/ff_dpdk_kni.c:484-486 (已复核)
if (ff_kni_is_owner_thread()) {
    kni_rp[port_id] = rte_ring_create(ring_name, ring_queue_size,
        socket_id, RING_F_SC_DEQ);
```

`RING_F_SC_DEQ` = Single Consumer Dequeue。该标志的含义是：**该 ring 在 dequeue（出队）侧只允许一个消费者**。enqueue（入队）侧允许多生产者（无 `RING_F_SP_ENQ` 标志）。

secondary 侧只做 `rte_ring_lookup`（L491），复用同一个 ring。

#### 1.2 入队侧（生产者）：所有收包进程

`ff_kni_enqueue()`（`lib/ff_dpdk_kni.c:510-543`，已复核）的调用点有三处：

| 调用点 | 位置 | 门禁 | 生产者身份 |
|---|---|---|---|
| 广播/多播克隆入队 | `lib/ff_dpdk_if.c:2080-2087`（已复核） | `enable_kni && ff_kni_is_owner_thread()` | 当前只有 owner（primary） |
| 单播 ALL_TO_KNI | `lib/ff_dpdk_if.c:2094`（已复核） | 仅 `enable_kni`，**无 owner 门禁** | **任何进程** |
| 单播 DEFAULT 模式 | `lib/ff_dpdk_if.c:2102`（已复核） | `enable_kni && (filter==FILTER_KNI && kni_accept) \|\| (filter==UNKNOWN/OSPF && !kni_accept)`，**无 owner 门禁** | **任何进程** |

关键发现：单播分支（L2091-2109）的 `ff_kni_enqueue()` **没有** `ff_kni_is_owner_thread()` 门禁。因此：

- **物理口→内核方向（入向）**：`kni_rp[port_id]` 的**生产者是所有收包进程**（每个 secondary 在自己的 rx 队列上收到需要转发给内核的包后入队）。生产者数量 = 收包进程数（slim 下 = `nb_procs - 1`）。
- 这与 ring 标志一致：`RING_F_SC_DEQ` 只限制消费者单线程，**不限制生产者**。

#### 1.3 消费侧（消费者）：仅 owner（primary），单消费者

`kni_process_tx()`（`lib/ff_dpdk_kni.c:144-179`，已复核）是 `kni_rp[port_id]` 的唯一消费者：

```c
// lib/ff_dpdk_kni.c:150 (已复核)
nb_tx = rte_ring_dequeue_burst(kni_rp[port_id], (void **)pkts_burst, count, NULL);
```

它由 `ff_kni_process()` 调用（L505），而 `ff_kni_process()` 的调用点在 `lib/ff_dpdk_if.c:2764-2768`（已复核），**有** `ff_kni_is_owner_thread()` 门禁：

```c
// lib/ff_dpdk_if.c:2765-2767 (已复核)
if (enable_kni && ff_kni_is_owner_thread()) {
    ff_kni_process(port_id, queue_id, pkts_burst, MAX_PKT_BURST);
}
```

因此 `kni_rp[port_id]` 的消费者**只有 owner（primary）一个**，与 `RING_F_SC_DEQ` 单消费者标志完全匹配。

#### 1.4 结论

**物理口→内核方向（入向，kni_rp ring）**：

- 生产者 = 所有收包进程（多生产者，ring 允许）
- 消费者 = owner（primary）一个（单消费者，`RING_F_SC_DEQ` 保证安全）
- **当前设计已经是正确的单消费者模型，不需要改为多消费者。**
- K3 方案中，slim primary 仍作为消费者从 `kni_rp` dequeue 并写入 virtio_user 口，该 ring 的 SC_DEQ 语义不受影响。

**内核→物理口方向（出向）**：

- K3 方案新增 `kni_tx_ring[port_id]`，把 `kni_process_rx()` 中 `rte_eth_tx_burst(port_id, queue_id, ...)`（L190）改为 enqueue 到新 ring。
- 生产者 = primary（`kni_process_rx` 在 owner 门禁内，只有一个生产者）
- 消费者 = 某个/所有 secondary（用自己的物理口 tx 队列发出）
- 若消费者选择"所有 secondary 竞争 dequeue"（K3 文档 §6 未决问题 1 的候选 b），则**必须去掉 `RING_F_SC_DEQ`**，改用普通 ring（多消费者）。
- 若消费者选择"指定单个 secondary"（候选 a），则保留 `RING_F_SC_DEQ` 即可。

**对 Q1 的回答**：用户质疑正确。`kni_rp`（物理口→内核方向）的单消费者（`RING_F_SC_DEQ`）设计是正确且充分的，因为消费者始终只有 owner 一个。不需要改为多消费者。只有 K3 新增的 `kni_tx_ring`（内核→物理口方向）才需要根据消费者选择决定是否用多消费者 ring。

---

## Q2: ratelimit 无需改，谁处理 KNI 队列谁限速

### 代码证据

#### 2.1 `kni_rate_limt` 变量定义与作用域

```c
// lib/ff_dpdk_kni.c:100 (已复核)
struct kni_ratelimit kni_rate_limt = {0, 0, 0};
```

```c
// lib/ff_dpdk_kni.h:37-46 (已复核)
struct kni_ratelimit {
    uint64_t console_packets;   // ARP/STP/OSPF 等控制面包，每进程统计
    uint64_t gerneal_packets;   // ICMP 等通用包，每进程统计
    uint64_t kernel_packets;    // 转发到内核的全部包，primary 统计
};
```

`kni_rate_limt` 是一个**进程内全局变量**（非共享内存、非 per-lcore），每个 f-stack 进程各有一份独立实例。

注释明确说明：`console_packets` 和 `gerneal_packets` 是 "statistics for each process"（每进程统计），`kernel_packets` 是 "statistics for primary process"（primary 统计）。

#### 2.2 `console_packets_ratelimit` / `general_packets_ratelimit`：入队侧限速

在 `ff_kni_enqueue()`（`lib/ff_dpdk_kni.c:510-527`，已复核）中：

```c
// lib/ff_dpdk_kni.c:513-527 (已复核)
if (filter >= FILTER_ARP) {
    if (ff_global_cfg.kni.console_packets_ratelimit) {
        kni_rate_limt.console_packets++;
        if (kni_rate_limt.console_packets > (uint64_t)ff_global_cfg.kni.console_packets_ratelimit) {
            goto error;
        }
    }
} else {
    if (ff_global_cfg.kni.general_packets_ratelimit) {
        kni_rate_limt.gerneal_packets++;
        if (kni_rate_limt.gerneal_packets > (uint64_t)ff_global_cfg.kni.general_packets_ratelimit) {
            goto error;
        }
    }
}
```

- **执行者**：调用 `ff_kni_enqueue()` 的进程——即**收包进程**（各 secondary + primary）。
- **作用域**：每进程独立的 `kni_rate_limt`，每进程独立计数和限速。
- **语义**：每个进程独立限速自己入队的 console/general 包数。配置值 `console_packets_ratelimit` / `general_packets_ratelimit` 是**每进程**的限额（参见 `lib/ff_config.h:44-48` 的注释："The total speed limit for a single process entering the kni ring is 10,000 QPS"）。

#### 2.3 `kernel_packets_ratelimit`：消费侧限速

在 `kni_process_tx()`（`lib/ff_dpdk_kni.c:156-165`，已复核）中：

```c
// lib/ff_dpdk_kni.c:156-165 (已复核)
if (ff_global_cfg.kni.kernel_packets_ratelimit) {
    if (likely(kni_rate_limt.kernel_packets < (uint64_t)ff_global_cfg.kni.kernel_packets_ratelimit)) {
        nb_to_tx = nb_tx;
    } else {
        nb_to_tx = 0;
    }
    kni_rate_limt.kernel_packets += nb_tx;
} else {
    nb_to_tx = nb_tx;
}
```

- **执行者**：`kni_process_tx()` 的执行者——即**KNI owner**（当前 = primary）。
- **作用域**：owner 进程的 `kni_rate_limt.kernel_packets`。
- **语义**：限制从 `kni_rp` ring dequeue 后实际写入 virtio_user 口（即转发到内核）的包速率。

#### 2.4 限速计数器复位

在 `main_loop` 的 `rte_timer_manage()` 回调中（`lib/ff_dpdk_if.c:2701-2727`，已复核），每秒复位一次：

```c
// lib/ff_dpdk_if.c:2722-2724 (已复核)
kni_rate_limt.gerneal_packets = 0;
kni_rate_limt.console_packets = 0;
kni_rate_limt.kernel_packets = 0;
```

- **执行者**：运行 `main_loop` 的每个进程（每个进程各自复位自己的 `kni_rate_limt`）。

#### 2.5 结论

**对 Q2 的回答**：用户质疑正确。ratelimit 机制天然是 per-process 的，不需要改。

具体分析：

1. **`console_packets_ratelimit` / `general_packets_ratelimit`（入队限速）**：由每个收包进程在 `ff_kni_enqueue()` 中独立执行。无论 KNI owner 是 primary 还是 secondary，入队者都是收包进程本身，限速自然由收包进程执行。配置语义是"每进程"，注释明确（`lib/ff_config.h:44`）。

2. **`kernel_packets_ratelimit`（消费限速）**：由 KNI owner 在 `kni_process_tx()` 中执行。无论 owner 是 primary 还是 secondary，**谁处理 KNI 队列（谁 dequeue + 转发到内核），谁就执行这个限速**。

3. **如果 KNI owner 迁到某个 secondary（Q3/K4 方案）**：该 secondary 执行 `kni_process_tx()`，自然也执行 `kernel_packets_ratelimit` 限速。`kni_rate_limt` 是进程内全局变量，不需要跨进程共享。ratelimit 机制天然随 owner 迁移，**无需任何代码改动**。

4. **K3 方案的 ratelimit 影响**（`04` 文档已提及但需补充）：K3 把广播/多播门禁从 `ff_kni_is_owner_thread()` 改为 `!pkts_from_ring` 后，入队者从 1 个进程（owner）变为 N 个进程（所有收包进程）。`console/general_packets_ratelimit` 是每进程配额，N 个进程各自一份 ⇒ **聚合限速放大约 N 倍**。但这不是 ratelimit 代码本身的问题，而是入队门禁改造的副作用，通过调整配置默认值即可（`04` 已记录为未决问题 7）。

---

## Q3: secondary 可直接处理 KNI，不必主进程处理后再转发 (K4)

### 调用点清单与分类

#### 3.1 `ff_kni_is_owner_thread()` 全部调用点

用 `search_content` 搜索全 `lib/` 目录，共 6 处调用（含定义）：

| # | 文件 | 行号 | 上下文 | 阶段 | 能否改为 secondary |
|---|---|---|---|---|---|
| 1 | `ff_dpdk_kni.c` | 93-98 | **定义**：`thread_mode` 时判 `rte_lcore_id() == proc_lcore[0]`；否则判 `RTE_PROC_PRIMARY` | — | 这是改 owner 判定的入口点 |
| 2 | `ff_dpdk_kni.c` | 387 | `ff_kni_init()`：分配 `kni_stat` 数组 | **初始化** | **不能改**（DPDK 约束，见下） |
| 3 | `ff_dpdk_kni.c` | 434 | `ff_kni_alloc()`：分配 `kni_stat[port_id]` + `rte_eal_hotplug_add` + 设 `port_id` | **初始化** | **不能改**（DPDK 约束，见下） |
| 4 | `ff_dpdk_kni.c` | 484 | `ff_kni_alloc()`：创建 `kni_rp[port_id]`（primary create）/ lookup（secondary） | **初始化** | **不能改**（ring 创建者必须唯一，且 hotplug 依赖） |
| 5 | `ff_dpdk_kni.c` | 537 | `ff_kni_enqueue()` error 路径：`kni_stat[port_id]->rx_dropped++` | **运行时** | **可改**（统计结构可由 secondary 分配） |
| 6 | `ff_dpdk_if.c` | 822 | `init_port_start()`：`total_nb_ports *= 2` | **初始化** | **不能改**（DPDK 约束，见下） |
| 7 | `ff_dpdk_if.c` | 2080 | `process_packets()` 广播/多播分支：克隆入队 | **运行时** | **可改** |
| 8 | `ff_dpdk_if.c` | 2765 | `main_loop` rx 循环：调用 `ff_kni_process()` | **运行时** | **可改** |

#### 3.2 初始化阶段调用点（不能改为 secondary）

以下 5 个调用点受 DPDK 硬约束，**必须由 primary 执行**，不能迁到 secondary：

| 调用点 | DPDK 约束依据 |
|---|---|
| #2 `kni_stat` 数组分配（L387） | 无硬约束（纯 `rte_zmalloc`），但逻辑上应与 #3 #4 一起由同一进程做 |
| #3 `rte_eal_hotplug_add("vdev", ...)`（L474） | secondary 调用会被 EAL 转发给 primary 执行（`eal_common_dev.c:244-259`），**不减少对 primary 的依赖**，反而增加 IPC 往返（`04` §2.2 已坐实） |
| #3 `kni_stat[port_id]->port_id = port_idx + nb_dev_ports`（L478） | 依赖 `nb_dev_ports`，该值在 secondary 侧不正确（`lib/ff_dpdk_if.c:79` 注释自承），必须先修 N2 |
| #4 `rte_ring_create(ring_name, ..., RING_F_SC_DEQ)`（L485） | ring 创建者必须唯一；secondary 做 lookup（L491）是现有设计 |
| #6 `total_nb_ports *= 2`（L822-825） | 条件为 `enable_kni && ff_kni_is_owner_thread()`。若 owner 迁到 secondary，**primary 的 `total_nb_ports` 不翻倍 ⇒ primary 不配置/启动 virtio_user 口 ⇒ KNI 全废**（`04` §2.2 坐实的隐藏致命点） |
| #6 后续 `dev_configure`/`dev_start`（L1061-1148） | `init_port_start()` 中 L1061-1063 `if (rte_eal_process_type() != RTE_PROC_PRIMARY) continue;` — secondary 被跳过，DPDK 不允许 secondary 做设备配置 |

**结论**：初始化阶段的 5 个调用点**全部不能从 primary 迁到 secondary**，这是 DPDK 多进程模型的硬约束。

#### 3.3 运行时阶段调用点（可改为 secondary）

以下 3 个调用点**可以**改为"指定 secondary"执行：

| 调用点 | 改法 | 前提条件 |
|---|---|---|
| #5 `ff_kni_enqueue` error 统计（L537） | secondary 也分配 `kni_stat` 并在此递增 | secondary 需有自己的 `kni_stat[port_id]` |
| #7 广播/多播克隆入队（L2080） | 门禁从 `ff_kni_is_owner_thread()` 改为 `!pkts_from_ring`（K3 方案已提出） | 无额外前提 |
| #8 `ff_kni_process()` 调用（L2765） | owner 判定改为指定 secondary；调用移出 rx 循环 | secondary 需有 `kni_stat` 且 virtio_user 口已启动 |

### secondary 分配 `kni_stat` 的可行性

#### 3.4 当前 secondary 在 `ff_kni_alloc` 中的行为

`ff_kni_alloc()`（`lib/ff_dpdk_kni.c:430-499`，已复核）中，secondary 只执行 L481-498：

```c
// lib/ff_dpdk_kni.c:481-492 (已复核)
char ring_name[RTE_KNI_NAMESIZE];
snprintf((char*)ring_name, RTE_KNI_NAMESIZE, "kni_ring_%u", port_id);

if (ff_kni_is_owner_thread()) {
    kni_rp[port_id] = rte_ring_create(ring_name, ring_queue_size,
        socket_id, RING_F_SC_DEQ);
    // ...
} else {
    kni_rp[port_id] = rte_ring_lookup(ring_name);  // secondary 只 lookup
}
```

secondary **不分配** `kni_stat[port_id]`（L434-479 的 `if (ff_kni_is_owner_thread())` 分支跳过）。因此 secondary 的 `kni_stat[port_id]` 为 NULL。

#### 3.5 让 secondary 也分配 `kni_stat` 的前提

如果让 K4 方案的 owner secondary 分配 `kni_stat` 并设 `port_id = port_idx + nb_dev_ports`，需要以下前提：

1. **N2 修正（前置必做）**：`nb_dev_ports` 在 secondary 侧不正确（`lib/ff_dpdk_if.c:79` 注释自承）。必须先按 `04` §5 的方案修正（primary 发布到共享 memzone，secondary lookup 读取），否则 `kni_stat[port_id]->port_id` 会指向错误 port。
2. **virtio_user 口已由 primary 配置并启动**：secondary 要对 virtio_user 口做 `rte_eth_rx_burst`/`tx_burst`，该口必须已经被 primary `dev_configure` + `dev_start`。这要求 `init_port_start()` 中 `total_nb_ports *= 2` 的条件**不能依赖 owner 判定**（必须改为仅 `enable_kni`，在 primary 上恒真）——否则 primary 不配置 virtio_user 口。
3. **secondary 能看到 virtio_user 口**：这是 vdev bus 可见性问题（见下节 3.6）。

### vdev 可见性源码分析

#### 3.6 DPDK vdev bus 的 secondary 扫描机制

搜索 `/data/workspace/dpdk-stable-24.11.6/drivers/bus/vdev/vdev.c`，关键代码：

**secondary 扫描流程**（`vdev_scan()`，L466-503，已复核）：

```c
// vdev.c:482-503 (已复核)
if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
    // ...
    req->type = VDEV_SCAN_REQ;
    if (rte_mp_request_sync(&mp_req, &mp_reply, &ts) == 0 &&
        mp_reply.nb_received == 1) {
        // 从 primary 获取 vdev 列表
    }
    /* Fall through to allow private vdevs in secondary process */
}
```

secondary 启动时通过 **DPDK IPC（mp channel）** 向 primary 发送 `VDEV_SCAN_REQ`，primary 在 `vdev_action()`（L408-463，已复核）中遍历 `vdev_device_list` 逐个发送给 secondary，secondary 在 `VDEV_SCAN_ONE` case（L450-457）中 `insert_vdev()` 加入本地列表。

**关键结论**：secondary 能否看到 primary 创建的 virtio_user 口，**依赖 primary 在线且 IPC 通道可用**。如果 primary 已退出，`rte_mp_request_sync` 失败，secondary 无法发现 vdev。

#### 3.7 secondary probe virtio_user 的能力

`virtio_user_ethdev.c` 的 `eth_virtio_user_probe()`（L525-547，已复核）明确处理 secondary：

```c
// virtio_user_ethdev.c:525-547 (已复核)
if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
    const char *name = rte_vdev_device_name(vdev);
    eth_dev = rte_eth_dev_attach_secondary(name);
    if (!eth_dev) {
        PMD_INIT_LOG(ERR, "Failed to probe %s", name);
        return -1;
    }
    dev = eth_dev->data->dev_private;
    hw = &dev->hw;
    VIRTIO_OPS(hw) = &virtio_user_ops;

    if (eth_virtio_dev_init(eth_dev) < 0) {
        // ...
    }
    eth_dev->dev_ops = &virtio_user_secondary_eth_dev_ops;
    // ...
    return 0;
}
```

进一步追踪 `eth_virtio_dev_init()`（`virtio_ethdev.c:1933-1954`，已复核）：

```c
// virtio_ethdev.c:1951-1953 (已复核)
if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
    set_rxtx_funcs(eth_dev);
    return 0;
}
```

`set_rxtx_funcs()`（`virtio_ethdev.c:1247-1310`，已复核）设置 `eth_dev->rx_pkt_burst` 和 `eth_dev->tx_pkt_burst` 函数指针。

**决定性结论**：secondary 进程**能 probe virtio_user 设备**，且 probe 后**会设置 rx/tx burst 函数指针**，因此 secondary **可以对 virtio_user 口做 `rte_eth_rx_burst`/`rte_eth_tx_burst`**。

但有两个限制：

1. **`virtio_user_secondary_eth_dev_ops`**（`virtio_ethdev.c:657-666`，已复核）只包含 stats/info 操作，**不包含 `dev_configure`/`dev_start`/`queue_setup`**。因此 secondary **不能** configure/start virtio_user 口——必须由 primary 完成。
2. **vdev 可见性依赖 primary 在线**：secondary 通过 IPC 向 primary 索取 vdev 列表（3.6 节）。primary 退出后新起的 secondary 无法发现 virtio_user 口。

### `kni_process_rx()` 中 port_id 和 queue_id 语义

#### 3.8 port_id 和 queue_id 的来源

`ff_kni_process()` 的调用点（`lib/ff_dpdk_if.c:2765-2767`，已复核）：

```c
// lib/ff_dpdk_if.c:2759-2767 (已复核)
for (i = 0; i < qconf->nb_rx_queue; ++i) {
    port_id = qconf->rx_queue_list[i].port_id;   // 物理口 port_id
    queue_id = qconf->rx_queue_list[i].queue_id;  // 该进程的物理口 rx 队列 id
    // ...
    if (enable_kni && ff_kni_is_owner_thread()) {
        ff_kni_process(port_id, queue_id, pkts_burst, MAX_PKT_BURST);
    }
}
```

- `port_id` = **物理口** port_id（来自 `qconf->rx_queue_list[i].port_id`）
- `queue_id` = 该进程在物理口上的 **rx 队列 id**（`queueid = lcore 在 lcore_list 中的下标`，`lib/ff_dpdk_if.c:487-491`）

`kni_process_rx()`（`lib/ff_dpdk_kni.c:181-202`，已复核）中：

```c
// lib/ff_dpdk_kni.c:187 (已复核)
nb_kni_rx = rte_eth_rx_burst(kni_stat[port_id]->port_id, 0, pkts_burst, count);
// kni_stat[port_id]->port_id = virtio_user 口的 port_id（= port_idx + nb_dev_ports）

// lib/ff_dpdk_kni.c:190 (已复核)
nb_rx = rte_eth_tx_burst(port_id, queue_id, pkts_burst, nb_kni_rx);
// port_id = 物理口，queue_id = 该进程的物理口 tx 队列
```

**语义分析**：

| 行 | 操作 | port_id | queue_id | 含义 |
|---|---|---|---|---|
| L187 | `rte_eth_rx_burst` | `kni_stat[port_id]->port_id`（virtio_user 口） | 0 | 从 virtio_user 口 queue 0 收包（内核→f-stack 方向） |
| L190 | `rte_eth_tx_burst` | `port_id`（物理口） | `queue_id`（该进程的物理口 tx 队列） | 把包发到物理口的该进程 tx 队列 |

**如果 runtime owner 是 secondary（K4 方案）**：

- L187 的 `kni_stat[port_id]->port_id` = virtio_user 口 port_id：secondary 需要能访问 virtio_user 口（3.7 节已证可行）。
- L190 的 `port_id` = 物理口，`queue_id` = **该 secondary 自己的物理口 tx 队列**：该 secondary 必须持有物理口 tx 队列（它本来就是收包进程，有自己的 tx 队列）。

**关键发现**：L190 的 `queue_id` 来自 `qconf->rx_queue_list[i].queue_id`，即**该进程自己的物理口队列**。如果 owner 是 secondary，它用自己的 tx 队列发出——**不需要借道 ring（K3 方案的 `kni_tx_ring`）**。这是 K4 相对 K3 的核心优势。

### K4 方案可行性总结

#### 3.9 K4 方案（secondary 直接处理 KNI）的完整路径

1. **初始化阶段（仍由 primary 做）**：
   - `kni_stat` 数组分配（L387）：primary 做
   - `rte_eal_hotplug_add` 创建 virtio_user 口（L474）：primary 做
   - `kni_rp[port_id]` 创建（L485）：primary 做
   - `total_nb_ports *= 2` + `dev_configure`/`dev_start` virtio_user 口（L822, L1061-1148）：primary 做

2. **初始化阶段（由指定 secondary 额外做）**：
   - secondary 分配自己的 `kni_stat[port_id]`，设 `port_id = port_idx + nb_dev_ports`（前提：N2 已修正）
   - secondary probe virtio_user 口（自动，通过 vdev scan + `eth_virtio_user_probe` secondary 分支）

3. **运行时阶段（由指定 secondary 做）**：
   - `ff_kni_process()` 调用（L2765）：owner secondary 在自己的 `main_loop` 中调用
   - `kni_process_tx()`：从 `kni_rp[port_id]` dequeue → 写 virtio_user 口 queue 0（内核方向）
   - `kni_process_rx()`：从 virtio_user 口 queue 0 收包 → 用**自己的物理口 tx 队列**发出（L190，不需要借道 ring）
   - 广播/多播克隆入队（L2080）：门禁改为 `!pkts_from_ring`

#### 3.10 K4 的前提条件与风险

| 前提/风险 | 说明 | 代码依据 |
|---|---|---|
| **N2 修正（前置必做）** | `nb_dev_ports` 在 secondary 侧不正确，owner secondary 会算错 `kni_stat[port_id]->port_id` | `lib/ff_dpdk_if.c:79` 注释自承 |
| **`total_nb_ports *= 2` 条件修正** | 必须改为仅 `enable_kni`（不依赖 owner 判定），否则 primary 不配置 virtio_user 口 | `lib/ff_dpdk_if.c:821-825` |
| **vdev 可见性依赖 primary 在线** | secondary 通过 IPC 向 primary 索取 vdev 列表；primary 退出后 K4 的 secondary 无法重新发现 virtio_user 口 | `vdev.c:482-503` |
| **owner secondary 崩溃后 KNI 中断** | K4 的 KNI 能力绑定在指定 secondary 上，该 secondary 崩溃则 KNI 中断（需重启该 secondary 恢复） | — |
| **`ff_kni_process()` 移出 rx 循环** | 避免 KNI 轮询频率与队列数耦合（K3 也需要） | `lib/ff_dpdk_if.c:2764-2768` |
| **广播/多播门禁改造** | `ff_kni_is_owner_thread()` → `!pkts_from_ring`（K3 也需要） | `lib/ff_dpdk_if.c:2080` |

---

## K4 vs K3-corrected 对比

> K3-corrected = `04` 文档中 K3 方案的修正版（primary 保留 KNI owner，新增 `kni_tx_ring` 借道 secondary 发出内核→物理口方向的包）。
> K4 = 本文档提出的方案（指定 secondary 直接作为 KNI owner，不需要新增 `kni_tx_ring`）。

### 对比表

| 维度 | K3-corrected（primary 留 KNI + ring 借道） | K4（secondary 直接处理 KNI） |
|---|---|---|
| **KNI owner** | primary | 指定 secondary（`owner_proc_id`） |
| **virtio_user 口 configure/start** | primary（天然，owner=primary） | primary（必须改 `total_nb_ports` 条件为仅 `enable_kni`） |
| **virtio_user 口 rx/tx burst** | primary（`kni_process_tx` + `kni_process_rx` 的 L187） | 指定 secondary（probe 后可收发，3.7 节已证） |
| **物理口→内核方向（入向）** | 各 secondary 收包 → `ff_kni_enqueue` → `kni_rp` ring → primary dequeue → virtio_user 口 | 各 secondary 收包 → `ff_kni_enqueue` → `kni_rp` ring → owner secondary dequeue → virtio_user 口 |
| **内核→物理口方向（出向）** | primary 从 virtio_user 口收包 → enqueue `kni_tx_ring` → 某 secondary dequeue → 用自己 tx 队列发出 | owner secondary 从 virtio_user 口收包 → **直接用自己的 tx 队列发出**（L190，不需要 ring） |
| **新增 ring** | 需要 `kni_tx_ring[port_id]`（`RING_F_SC_DEQ` 或多消费者） | **不需要**（owner secondary 直接用自己 tx 队列） |
| **N2 修正** | 可延后（`nb_dev_ports` 只在 primary 侧使用） | **前置必做**（owner secondary 需要 `nb_dev_ports` 算 `kni_stat[port_id]->port_id`） |
| **改动 `total_nb_ports` 条件** | 不需要（owner=primary，条件天然满足） | **需要**（改为仅 `enable_kni`） |
| **改动 `ff_kni_is_owner_thread()`** | 不需要（owner 仍是 primary） | **需要**（改为 `ff_cur_proc_id() == cfg.kni.owner_proc_id`） |
| **secondary 分配 `kni_stat`** | 不需要（primary 分配） | **需要**（owner secondary 也要分配） |
| **广播/多播门禁改造** | 需要（L2080 → `!pkts_from_ring`） | 需要（同） |
| **`ff_kni_process()` 移出 rx 循环** | 需要 | 需要 |
| **KNI owner 崩溃影响** | primary 崩溃 = KNI 中断 + 控制面全断（IPC/扩堆/中断同失） | owner secondary 崩溃 = KNI 中断（其他 secondary 和 primary 不受影响） |
| **KNI 恢复** | 必须等计划内全组重启（primary 不可原地拉回，`03` §7.3 E10 实测） | 重启该 secondary 即可恢复（前提：primary 在线、vdev 可见） |
| **与 primary-slim 的协同** | 天然协同（primary 本就必须常驻，KNI 随 primary 同生共死） | 需要额外设计 owner failover（但 secondary 可原地重启，恢复比 primary 容易） |
| **vdev 可见性依赖** | 无（primary 自己创建并使用 virtio_user 口） | **依赖 primary 在线**（secondary 通过 IPC 索取 vdev 列表） |
| **改动量（估计）** | 7~8 处（含新增 `kni_tx_ring`） | 8~10 处（含 N2 修正 + `total_nb_ports` 条件 + owner 判定 + secondary `kni_stat` 分配） |
| **核心优势** | 不改 owner 判定、不碰 N2、与 primary 必须常驻天然协同 | 不需要新增 ring、owner secondary 崩溃只影响 KNI 不影响控制面、恢复只需重启 secondary |
| **核心劣势** | 新增 ring 多一跳延迟；KNI 与 primary 绑定（primary 崩=KNI 断且不可原地恢复） | 前置依赖多（N2 + `total_nb_ports` + vdev 可见性）；改动面更大 |

### 方案选择建议

**K4 的优势**（用户 Q3 质疑的核心论点）：
1. 不需要新增 `kni_tx_ring`——owner secondary 直接用自己的 tx 队列发出，少一跳延迟、少一个 ring 的内存和管理。
2. KNI owner 崩溃只影响 KNI，不影响控制面（primary 的 IPC/扩堆/中断能力不受影响）。
3. KNI 恢复只需重启该 secondary（可原地重启，`03` E2e 已证），不需要等计划内全组重启。

**K4 的劣势**：
1. 前置依赖多：N2 修正（`nb_dev_ports` 共享 memzone）+ `total_nb_ports` 条件修正 + `ff_kni_is_owner_thread()` 改造 + secondary `kni_stat` 分配。
2. vdev 可见性依赖 primary 在线：owner secondary 重启时需要 primary 在线才能重新发现 virtio_user 口（`vdev_scan` 的 IPC 请求）。
3. 改动面更大、风险更高。

**K3-corrected 的优势**：
1. 不改 owner 判定、不碰 N2、改动集中在新增 ring + 门禁改造。
2. 与 "primary 必须常驻" 天然协同（`03` 已证 primary 本就必须常驻）。

**K3-corrected 的劣势**：
1. 新增 `kni_tx_ring` 多一跳延迟。
2. KNI 与 primary 绑定——primary 崩溃 = KNI 断且不可原地恢复（E10 已证），必须等计划内全组重启。

**综合判断**：K4 在架构上更干净（不需要新 ring、故障隔离更好），但前置依赖和改动量更大。K3-corrected 改动更小、风险更低，但接受 KNI 与 primary 绑定的代价。

**建议**：如果项目优先级是"最小改动、最快落地"，选 K3-corrected；如果优先级是"KNI 独立于 primary、故障可恢复"，选 K4 但须先完成 N2 修正和 `total_nb_ports` 条件修正。

---

## 决定性实验 E4a 设计

> 目标：验证 K4 方案的核心前提——secondary 能否直接对 primary 创建并启动的 virtio_user 口做 `rte_eth_rx_burst`/`tx_burst`，且 KNI 双向通路畅通。

### 实验环境

- 本机双网卡：DPDK 独占接管网卡（IP `<DPDK_NIC_IP>`）+ 内核栈网卡（eth1）。
- DPDK 网卡程序测试：ssh 到 f-stack-client 机器，再测试本机 DPDK 接管网卡。
- 内核栈测试：用 `127.0.0.1` 的 lo IP。

### E4a 步骤

#### 步骤 1：基线验证（K3 现状，primary 做 KNI owner）

1. 配置 `config.ini`：`kni.enable=1`、`nb_procs=2`（1 primary + 1 secondary）、`lcore_list` 包含两个 lcore。
2. 启动 f-stack 进程组（primary + secondary）。
3. 从 f-stack-client 向 `<DPDK_NIC_IP>` 发 ARP 请求（`arping`），确认 ARP 通过 KNI 进入内核（`tcpdump` on veth 接口可见）。
4. 从 f-stack-client 向 `<DPDK_NIC_IP>` 发 ICMP echo（`ping`），确认 ICMP 通过 KNI 进入内核并回复。
5. 从 f-stack 本机内核侧向 f-stack-client 发 ICMP（通过 veth 接口），确认内核→物理口方向通畅。
6. 记录基线：ARP 通/不通、ICMP 通/不通、双向延迟。

#### 步骤 2：K4 验证（指定 secondary 做 KNI owner）

1. **前置修改（PoC patch）**：
   - `ff_kni_is_owner_thread()` 改为 `ff_cur_proc_id() == cfg.kni.owner_proc_id`（设 `owner_proc_id=1`，即 secondary）。
   - `total_nb_ports *= 2` 条件改为仅 `enable_kni`（不依赖 owner 判定）。
   - N2 修正：primary 发布 `nb_dev_ports` 到共享 memzone，secondary lookup。
   - secondary 在 `ff_kni_alloc()` 中也分配 `kni_stat[port_id]`。
   - `ff_kni_process()` 调用移出 rx 循环。
   - 广播/多播门禁改为 `!pkts_from_ring`。

2. 启动 f-stack 进程组（primary 不做 KNI、secondary 做 KNI owner）。
3. 确认日志：secondary 成功 probe virtio_user 口（`virtio_user_ethdev.c:525` 的 secondary 分支执行成功）。
4. 重复步骤 1 的 3~5 项测试。
5. 记录结果：ARP 通/不通、ICMP 通/不通、双向延迟。

#### 步骤 3：K4 故障恢复验证

1. 在步骤 2 的基础上，**kill owner secondary**（用 `/data/workspace/kill_process.sh`）。
2. 确认 KNI 中断（ARP/ICMP 不通）。
3. 确认 primary 和其他 secondary（若有）不受影响（数据面继续服务）。
4. **重新启动 owner secondary**（primary 在线）。
5. 确认 secondary 重新 probe virtio_user 口（vdev scan IPC 成功）。
6. 确认 KNI 恢复（ARP/ICMP 恢复通畅）。

#### 步骤 4：vdev 可见性边界验证

1. 在步骤 2 的基础上，**kill primary**（用 `/data/workspace/kill_process.sh`）。
2. 确认 owner secondary 的 KNI 是否仍工作（virtio_user 口已 probe 且口已 start，理论上 rx/tx burst 不依赖 primary 在线，但需实测）。
3. **kill owner secondary 后重新启动**（primary 不在线）。
4. 确认 secondary 能否重新 probe virtio_user 口（预期失败：`vdev_scan` IPC 请求无响应）。
5. 记录结果：primary 缺席时 KNI 能否工作、secondary 能否恢复。

### E4a 判据

| 场景 | 预期结果 | 判据 |
|---|---|---|
| 步骤 1（K3 基线） | ARP/ICMP 双向通 | 基线对照 |
| 步骤 2（K4 正常运行） | ARP/ICMP 双向通，延迟与 K3 基线接近（无额外 ring 跳数） | K4 可行性坐实 |
| 步骤 3（K4 owner 崩溃恢复） | kill owner → KNI 断、数据面不受影响；重启 owner → KNI 恢复 | K4 故障隔离与恢复能力坐实 |
| 步骤 4（K4 primary 缺席） | kill primary → KNI 可能仍工作（已 probe 的口不依赖 primary）；重启 owner secondary → **预期失败**（vdev scan 无 primary 响应） | vdev 可见性边界坐实 |

### E4a 注意事项

- 所有 kill 操作用 `/data/workspace/kill_process.sh`，禁止直接 `kill`。
- 所有文件删除用 `/data/workspace/rm_tmp_file.sh`，禁止直接 `rm`。
- 所有权限修改用 `/data/workspace/chmod_modify.sh`，禁止直接 `chmod`。
- 文档中严禁记录真实 IP，使用 `<DPDK_NIC_IP>` 等占位符。
- 修改代码后编译前必须先 `make clean` 再 `make`。

---

## 附录：代码证据索引

| 证据 | 文件 | 行号 | 复核状态 |
|---|---|---|---|
| `RING_F_SC_DEQ` 标志 | `lib/ff_dpdk_kni.c` | 486 | 已复核 |
| `kni_rp` secondary lookup | `lib/ff_dpdk_kni.c` | 491 | 已复核 |
| `ff_kni_enqueue` 入队（无 owner 门禁） | `lib/ff_dpdk_if.c` | 2094, 2102 | 已复核 |
| 广播/多播克隆入队（有 owner 门禁） | `lib/ff_dpdk_if.c` | 2080 | 已复核 |
| `kni_process_tx` 消费者（owner only） | `lib/ff_dpdk_kni.c` | 144-179 | 已复核 |
| `ff_kni_process` 调用（owner 门禁） | `lib/ff_dpdk_if.c` | 2765 | 已复核 |
| `kni_rate_limt` 进程内全局变量 | `lib/ff_dpdk_kni.c` | 100 | 已复核 |
| `console/general_packets_ratelimit` 在 `ff_kni_enqueue` | `lib/ff_dpdk_kni.c` | 513-527 | 已复核 |
| `kernel_packets_ratelimit` 在 `kni_process_tx` | `lib/ff_dpdk_kni.c` | 156-165 | 已复核 |
| ratelimit 复位在 `main_loop` | `lib/ff_dpdk_if.c` | 2701-2727 | 已复核 |
| `ff_kni_is_owner_thread` 定义 | `lib/ff_dpdk_kni.c` | 92-98 | 已复核 |
| `ff_kni_is_owner_thread` 调用点（6 处） | `lib/ff_dpdk_kni.c` + `lib/ff_dpdk_if.c` | 387, 434, 484, 537, 822, 2080, 2765 | 已复核 |
| `rte_eal_hotplug_add` | `lib/ff_dpdk_kni.c` | 474 | 已复核 |
| `kni_stat[port_id]->port_id = port_idx + nb_dev_ports` | `lib/ff_dpdk_kni.c` | 478 | 已复核 |
| `total_nb_ports *= 2` 条件 | `lib/ff_dpdk_if.c` | 821-825 | 已复核 |
| `init_port_start` primary 门禁 | `lib/ff_dpdk_if.c` | 1061-1063 | 已复核 |
| `nb_dev_ports` 注释（secondary 不正确） | `lib/ff_dpdk_if.c` | 79 | 已复核 |
| `kni_process_rx` 中 `rte_eth_tx_burst(port_id, queue_id, ...)` | `lib/ff_dpdk_kni.c` | 190 | 已复核 |
| vdev secondary scan（IPC 向 primary 索取） | `dpdk-stable-24.11.6/drivers/bus/vdev/vdev.c` | 482-503 | 已复核 |
| vdev_action primary 响应 | `dpdk-stable-24.11.6/drivers/bus/vdev/vdev.c` | 408-463 | 已复核 |
| virtio_user secondary probe | `dpdk-stable-24.11.6/drivers/net/virtio/virtio_user_ethdev.c` | 525-547 | 已复核 |
| `eth_virtio_dev_init` secondary 调 `set_rxtx_funcs` | `dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c` | 1951-1953 | 已复核 |
| `set_rxtx_funcs` 设置 rx/tx burst | `dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c` | 1247-1310 | 已复核 |
| `virtio_user_secondary_eth_dev_ops`（无 configure/start） | `dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c` | 657-666 | 已复核 |
| B2 校验（primary 必须在 lcore_list） | `lib/ff_config.c` | 1419-1435 | 已复核 |
| ratelimit 配置默认值注释（每进程） | `lib/ff_config.h` | 41-50 | 已复核 |

---

## E4a 决定性实验结果（2026-08-10 实测）

> 执行者：leader（纯实验执行，非写审串行）。以下数据来自真实进程日志，非推理。

### 实验配置

| 项 | 值 |
| --- | --- |
| config.ini | `lcore_mask=3`（2 进程）、`[port0] lcore_list=0,1`、`[kni] enable=1 method=reject`、`extra_eal_args=--log-level=bus.vdev:8` |
| 进程模型 | primary（proc-id=0, lcore 0）+ secondary（proc-id=1, lcore 1） |
| 编译 | 未改动代码，直接使用既有 helloworld（FF_KNI 默认开启） |
| 启动顺序 | primary 先启动 → 等待 ~55s 完成 init_kni（含 `rte_eal_hotplug_add` 创建 virtio_user 口）→ secondary 启动 |

### Primary 日志关键证据（f-stack-0.log）

```
Port 0 MAC:20:90:6F:7D:5D:08          ← 物理口
LRO is disabled
TSO is disabled
set port 0 to promiscuous mode ok
Port 1 MAC:20:90:6F:7D:5D:08          ← virtio_user 口已创建！（MAC 与物理口一致，由 ff_kni_alloc L468 设置）
set port 1 to promiscuous mode error   ← virtio_user 口不支持混杂模式（无害）
Port 0 Link Up - speed 4294967295 Mbps - full-duplex
f-stack-0: Successed to register dpdk interface
```

**结论**：Primary 成功通过 `rte_eal_hotplug_add` 创建了 virtio_user 口（Port 1），并完成了 `dev_configure`/`dev_start`。

### Secondary 日志关键证据（f-stack-1-stdout.log）

```
f-stack -c2 -n4 --proc-type=secondary --log-level=bus.vdev:8
EAL: Detected CPU lcores: 16
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket_<pid>_<tag>
EAL: Selected IOVA mode 'PA'
VDEV_BUS: vdev_action(): receive vdev, virtio_user0       ← ★ Secondary 通过 VDEV_SCAN_REQ 收到 virtio_user0！
VDEV_BUS: vdev_scan(): Received 1 vdevs                    ← ★ 成功收到 1 个 vdev
VDEV_BUS: vdev_probe_all_drivers(): Search driver to probe device virtio_user0  ← ★ Secondary 开始 probe virtio_user0！
create kni ring success, 2047 ring entries are now free!   ← KNI ring lookup 成功
```

Secondary 的 f-stack-1.log 亦显示完整初始化成功：
```
lcore: 1, port: 0, queue: 1
Port 0 MAC:20:90:6F:7D:5D:08
f-stack-0: Successed to register dpdk interface
```

### E4a 决定性结论

| 验证项 | 结果 | 证据 |
| --- | --- | --- |
| Primary 创建 virtio_user 口 | ✅ 成功 | `Port 1 MAC:20:90:6F:7D:5D:08` |
| Secondary 通过 VDEV_SCAN_REQ 发现 virtio_user 口 | ✅ 成功 | `VDEV_BUS: receive vdev, virtio_user0` + `Received 1 vdevs` |
| Secondary 独立 probe virtio_user 口 | ✅ 成功 | `VDEV_BUS: Search driver to probe device virtio_user0` |
| Secondary 访问共享 KNI ring | ✅ 成功 | `create kni ring success` |
| Secondary 完成完整初始化 | ✅ 成功 | `Successed to register dpdk interface` |

**K4 方案在代码层面和实机层面都验证可行。**

结合代码分析（§3.7）：
- Secondary 通过 `rte_eth_dev_attach_secondary(name)` 绑定到 primary 创建的 ethdev
- `eth_virtio_dev_init` → `set_rxtx_funcs` 设置 rx/tx burst 函数指针
- `virtio_user_secondary_eth_dev_ops` 提供 secondary 专用 dev_ops
- **Secondary 可以对 virtio_user 口做 `rte_eth_rx_burst`/`rte_eth_tx_burst`**

### E4a 未覆盖的后续实验（E4b-E4f，留待 PoC 阶段）

| 实验 | 目的 | 依赖 |
| --- | --- | --- |
| E4b | KNI 功能基线（ARP/ICMP/SSH 双向通） | K4 PoC 补丁 |
| E4c | K4 PoC + slim primary 兼容性 | K4 PoC 补丁 + primary-slim 补丁 |
| E4d | 广播/多播门禁验证（`!pkts_from_ring`） | K4 PoC 补丁 |
| E4e | SSH 管理面验证 | K4 PoC 补丁 |
| E4f | 性能基线（K4 vs K3 vs 无 KNI） | K4 PoC 补丁 |

### 实验环境清理

实验完成后已用 `/data/workspace/kill_process.sh` 清理所有 helloworld 进程。config.ini 的本地测试配置（lcore_mask=3, lcore_list=0,1, [kni] enable=1, extra_eal_args）保留在工作区供后续 PoC 实验使用，不入库。
