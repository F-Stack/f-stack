# M1-B 外网调研：virtio-net 在 DPDK 多队列下的入向包分发机制

> 调研人：extern-researcher（外网资料调研 agent）
> 时间：2026-08-03
> 任务来源：team-lead（native-mt-fix 团队）
> 边界声明：本文只做资料调研与代码交叉核对，**未修改任何代码文件**。文中每条结论均标注来源；凡外网资料与本地代码冲突处，一律标注「**以代码为准**」。搜不到可靠来源的条目如实写「未找到可靠来源」。

---

## 0. 结论速览（TL;DR）

| # | 结论 | 置信度 | 依据 |
|---|---|---|---|
| C1 | 只协商 `VIRTIO_NET_F_MQ`（无 `VIRTIO_NET_F_RSS`）时，**guest 完全无法控制入向分发**；进哪个 rx virtqueue 由 host 后端单方面决定 | 高（代码+官方文档+DPDK维护者邮件） | §1、§2 |
| C2 | host 为 **vhost-net + tap** 时，分发由内核 `tun` 驱动的 automatic flow steering 决定：**出方向（guest→host）学习、入方向（host→guest）查表** | 高（内核源码原文） | §1.1 |
| C3 | tun 表未命中时**不是固定进队列 0**，而是 `txq = ((u64)hash * numqueues) >> 32` 按对称哈希比例散列。KVM wiki「fallback 到第一个队列」是 2012 年设计稿的旧描述，**以内核代码为准** | 高（内核源码原文） | §1.1、§1.2 |
| C4 | tun 用的是 `__skb_get_hash_symmetric()`（flow dissector 软哈希），**与 DPDK/f-stack侧的 Toeplitz RSS 哈希完全不同**。因此「f-stack worker i 期望收到的流」与「tun 实际投给队列 i 的流」**没有任何一致性保证**，且 tun 表项3 秒（`TUN_FLOW_EXPIRE = 3*HZ`）不活动即老化删除 | 高（内核源码原文） | §1.1、§5.3 |
| C5 | DPDK 接管（igb_uio/vfio）**不影响** host 侧 tun/vhost steering——steering 在 host 内核里，与 guest 用什么驱动无关。但 guest 换成 DPDK 后，「学习」的触发者变成 f-stack 各 worker 的 tx 队列 | 高（机制推导+ QEMU 文档） | §2.1 |
| C6 | DPDK virtio PMD **会**在 `dev_start` 自动下发 `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET`，无需应用额外做什么；但前提是**控制队列（cvq）存在**，否则 `virtio_send_command` 直接返回 -1 → `dev_start` 失败 | 高（本地代码核实） | §2.2 |
| C7 | 「只有 queue 0 收到包」这一现象，**未找到 DPDK bugzilla / dpdk-dev 邮件列表 / stackoverflow 上的直接同类bug 报告**；但 OVS 官方文档给出了等价机制的明确记载（单 PMD → 全部流量进同一条 vhost 队列） | 中（间接证据充分，直接 bug 报告缺失） | §3 |
| C8 | f-stack 侧：**未找到任何**「在 virtio 虚拟网卡上成功跑起 f-stack 多进程（多队列）」的公开实践记录。所有能找到的公开记录都停在「virtio 不支持 RSS → 报错 → 改成单队列/单进程」| 高（多个独立来源一致） | §4 |
| C9 | 无 RSS 网卡上做多 worker 负载均衡的通行做法：**单 RX 队列 + 软件哈希二次分发**（`rte_distributor` 或 `rte_softrss` + ring），这是 DPDK 官方库级支持的方案 | 高（DPDK 官方文档） | §5 |

---

## 1. 问题1：host 侧如何决定入包进哪个 receive virtqueue

### 1.1 vhost-net + tap（Linux 内核 tun 驱动）——机制已由内核源码坐实

**来源**：Linux 内核 `drivers/net/tun.c`（tag `x86_misc_for_v5.16_rc1`，blob `fecc9a1d293a`）
链接：https://kernel.googlesource.com/pub/scm/linux/kernel/git/peterz/queue/+/refs/tags/x86_misc_for_v5.16_rc1/drivers/net/tun.c

关键数据结构与常量（原文）：

```c
struct tun_flow_entry {
    struct hlist_node hash_link;
    struct rcu_head rcu;
    struct tun_struct *tun;
    u32 rxhash;
    u32 rps_rxhash;
    int queue_index;
    unsigned long updated ____cacheline_aligned_in_smp;
};

#define TUN_NUM_FLOW_ENTRIES 1024
#define TUN_MASK_FLOW_ENTRIES (TUN_NUM_FLOW_ENTRIES - 1)
#define MAX_TAP_FLOWS  4096
#define TUN_FLOW_EXPIRE (3 * HZ)      /* 表项 3 秒不活动即老化 */
```

**入方向（host → guest，即 tun 决定包进哪条 rx virtqueue）**——`ndo_select_queue` 回调：

```c
static u16 tun_select_queue(struct net_device *dev, struct sk_buff *skb,
                            struct net_device *sb_dev)
{
    struct tun_struct *tun = netdev_priv(dev);
    u16 ret;

    rcu_read_lock();
    if (rcu_dereference(tun->steering_prog))
        ret = tun_ebpf_select_queue(tun, skb);   /* 设置了 steering eBPF 才走这条 */
    else
        ret = tun_automq_select_queue(tun, skb); /* 默认走 automatic flow steering */
    rcu_read_unlock();

    return ret;
}

static u16 tun_automq_select_queue(struct tun_struct *tun, struct sk_buff *skb)
{
    struct tun_flow_entry *e;
    u32 txq = 0;
    u32 numqueues = 0;

    numqueues = READ_ONCE(tun->numqueues);

    txq = __skb_get_hash_symmetric(skb);
    e = tun_flow_find(&tun->flows[tun_hashfn(txq)], txq);
    if (e) {
        tun_flow_save_rps_rxhash(e, txq);
        txq = e->queue_index;                    /* 命中：用学习到的队列 */
    } else {
        /* use multiply and shift instead of expensive divide */
        txq = ((u64)txq * numqueues) >> 32;      /* 未命中：按哈希比例散列 */
    }
    return txq;
}
```

**出方向（guest → host，即「学习」发生的地方）**——`tun_get_user()` 尾部：

```c
    /* Compute the costly rx hash only if needed for flow updates.
     * We may get a very small possibility of OOO during switching, not
     * worth to optimize.
     */
    if (!rcu_access_pointer(tun->steering_prog) &&
        tun->numqueues > 1 &&
        !tfile->detached)
        rxhash = __skb_get_hash_symmetric(skb);
    ...
    if (rxhash)
        tun_flow_update(tun, rxhash, tfile);
```

```c
static void tun_flow_update(struct tun_struct *tun, u32 rxhash,
                            struct tun_file *tfile)
{
    ...
    u16 queue_index = tfile->queue_index;   /* guest 从哪条队列发出来的 */
    head = &tun->flows[tun_hashfn(rxhash)];
    e = tun_flow_find(head, rxhash);
    if (likely(e)) {
        if (READ_ONCE(e->queue_index) != queue_index)
            WRITE_ONCE(e->queue_index, queue_index);   /* 流迁移到新队列 */
        ...
    } else {
        spin_lock_bh(&tun->lock);
        if (!tun_flow_find(head, rxhash) && tun->flow_count < MAX_TAP_FLOWS)
            tun_flow_create(tun, head, rxhash, queue_index);
        ...
    }
}
```

代码里还有一段注释，直接说明了为什么用 rxhash 而不是 rxq 号来标识流：

```c
/* We try to identify a flow through its rxhash. The reason that
 * we do not check rxq no. is because some cards(e.g 82599), chooses
 * the rxq based on the txq where the last packet of the flow comes. As
 * the userspace application move between processors, we may get a
 * different rxq no. here.
 */
```

**回答 team-lead 的三个子问题**：

1. **是否依赖 guest 先从该队列发包来「学习」流到队列的映射？**
   **是。** 表项唯一的创建/更新入口就是 `tun_flow_update()`，而它只在 `tun_get_user()` / `tun_xdp_one()`（即 host 从 tap 读到 **guest 发出的包**）路径上被调用，`queue_index` 取的是 `tfile->queue_index`（guest 发包所用的那条队列）。**guest 不发包 → 表里没有该流 → 入向只能靠哈希散列兜底。**

2. **首包（如 TCP SYN）在无学习记录时被送到哪个队列？**
   走 `else` 分支：`txq = ((u64)hash * numqueues) >> 32`，即按 `__skb_get_hash_symmetric()` 的哈希值在 `[0, numqueues)` 上按比例映射。**不是固定队列 0**，而是「按哈希伪随机散列」。对单条固定五元组的连接而言，其首包落在哪个队列是**确定但不可预测**的（取决于该流的对称哈希值），且与 guest 侧 Toeplitz RSS 的结果无关。

3. **表项寿命**：`TUN_FLOW_EXPIRE = 3 * HZ`（3 秒）。`tun_flow_cleanup()` 定时器会删除 `updated + 3s <= jiffies` 的表项。也就是说**空闲 3 秒的长连接，其队列绑定会丢失**，下一个入向包重新走哈希散列——这对「长连接 +稀疏流量」场景意味着入向队列会漂移。此外 `tun_flow_delete_by_queue()` 在队列 detach 时会清掉该队列的所有表项。

### 1.2 与 KVM 官方设计文档的对照（存在不一致，以代码为准）

**来源**：KVM Wiki《Multiqueue》（Multiqueue virtio-net 设计页，作者 Jason Wang<jasowang@redhat.com>，状态标注 merged upstream）
链接：https://www.linux-kvm.org/page/Multiqueue

该页 *Queue selector* 一节给出的判定顺序为：

1. skb 已带 RX queue mapping（来自物理网卡 RSS/flow director）→ 用该 queue 号；
2. 否则能算出 rxhash → 用 rxhash 选队列；
3. 两者都失败 → **总是落到第一个可用队列**。

而「哈希→队列映射表 + guest 发包时更新该表」在该页里被放在 **“Further Optimization ?”**（待优化提议）里，说明这是后来才进内核的：

> rxhash 只能把负载散开到不同 vcpu，但被选中的 vcpu 未必是真正执行 `recvmsg()` 的那个……
> 提议：记录每条 flow 实际使用的 cpu/queue，**在 guest 发包时更新该表**；tun/tap 向 guest 送包时查该表选队列。

**不一致点与裁决**：
- KVM wiki 说「无hash 可用时固定进第一个队列」。内核 5.16 代码里 `tun_automq_select_queue()` 无条件调用 `__skb_get_hash_symmetric()`，无 hash 时该函数返回 0，`((u64)0 * numqueues) >> 32 == 0`，**结果恰好也是队列 0**——所以两者在「真的算不出哈希」这个子情形下是一致的；但对「能算出哈希但表未命中」这一（正常 TCP 首包的）主流情形，wiki 的旧文没有描述 `((u64)hash * numqueues) >> 32` 这一现行行为。**以内核代码为准。**
- wiki 提到的 `IFF_ATTACH_QUEUE` / `IFF_DETACH_QUEUE`（临时启停队列，让单队列 driver 能跑在多队列设备上）在内核代码 `tun_set_queue()` 中确认存在，与 QEMU 侧行为对应（见 §2.1）。

### 1.3 vhost-user / OVS-DPDK 后端——分发**不是**按包哈希，而是绑 PMD 线程

**来源**：Open vSwitch 官方文档《DPDK vHost User Ports》
链接：https://docs.openvswitch.org/en/latest/topics/dpdk/vhost-user/

文档原文要点（直译）：
- 使用 multiqueue 时，**vswitch 至少要配 2 个 PMD**。只用1 个 PMD 会导致流量被**排入同一条 vhost 队列**，而不是分散到该 vhost-user 接口的不同队列。
- vhost-user 口的 `n_rxq` **不支持手工配置**，会在 virtio 设备连接后自动按 QEMU 的 `queues=N` 重新协商。
- 如果去 VM 的流量来自物理 DPDK 口，则该物理口的 rx 队列数也应 ≥2，以**提高**由不同 PMD 完成向 guest 发送、从而使用不同 vhost 队列的**概率**（原文用词是 probability）。

**来源**：Intel《Open vSwitch with DPDK: vHost User Multiqueue Configuration and Use》（作者 Ian Stokes，2016-07-12，文档 ID 659209）
链接：https://www.intel.cn/content/www/cn/zh/developer/articles/technical/configure-vhost-user-multiqueue-for-ovs-with-dpdk.html

- 分发是**两级**的：① 物理 NIC 用 RSS 把入向流量哈希散到多个 NIC 队列；② 主机 vSwitch 侧每个队列由一个独立 PMD 线程处理，各 PMD 把包送入 vhost-user 口对应的 VNIC 队列。
- 因此**测试流量必须是多条流**（文中通过变化目的 IP 触发 RSS），单条流不可能分散。
- 配置必须三处对齐：QEMU `queues=N` + `vectors=2N+2`；OVS 自动协商；guest 内核驱动 `ethtool -L eth0 combined N`（guest 用 DPDK 时改为 testpmd `--rxq/--txq`，不需要 ethtool）。

**结论**：vhost-user 路径下，队列选择**与执行发送的 PMD 线程绑定**，本质是「上游物理网卡的 RSS 结果 → PMD → vhost 队列」的传递链；如果上游只有 1 个 rxq / 1 个 PMD，则 guest 侧无论开多少队列都只有队列 0 收包。这与 §3 的现象直接对应。

### 1.4 QEMU / vhost-net 的 eBPF steering（可覆盖 tun 默认行为）

**来源**：QEMU 官方开发文档《eBPF RSS virtio-net support》（QEMU 11.0.92 master 文档）
链接：https://www.qemu.org/docs/master/devel/ebpf_rss.html

原文关键描述：
- **未给内核 TUN 设置 steering BPF 时**：TUN 使用「自动选择 rx virtqueue」方式——**基于按已发送报文的对称哈希构建的查找表**来选队列。（这与 §1.1 的内核代码完全吻合，是官方文档对 `tun_automq_select_queue` 的自然语言描述。）
- **设置了 steering BPF 时**：由 BPF 程序算哈希并直接返回 virtqueue 编号。
- `set_steering_ebpf()` 目前**仅 Linux TAP 后端支持**。
- rss/hash 组合行为表：`vhost=on` + `rss=on,hash=off` → 用 eBPF；`vhost=off` + `rss=on,hash=on` → 用 in-QEMU 软件 RSS；`vhost=on` + `rss=on,hash=on` → 用 eBPF但**不向guest 上报 hash 能力**。
- eBPF RSS 需要 **host 内核 ≥ 5.8**，QEMU 编译需 `CONFIG_EBPF`。加载/设置失败时回退 in-QEMU RSS（仅 `vhost=off` 有效）。

**来源**：QEMU `hw/net/virtio-net.c`（master）
链接：https://github.com/qemu/qemu/blob/master/hw/net/virtio-net.c

```c
    virtio_net_set_multiqueue(n,
                              virtio_has_feature_ex(features, VIRTIO_NET_F_RSS) ||
                              virtio_has_feature_ex(features, VIRTIO_NET_F_MQ));
```

即 QEMU 侧「协商了 F_MQ **或** F_RSS 就开多队列」，这与本地 DPDK 代码 `virtio_ethdev.c:1840-1852` 的判定条件**完全对称一致**（两边都是 MQ‖RSS）。

---

## 2. 问题2：DPDK 接管后 guest 内核 steering 是否仍生效 + VQ_PAIRS_SET 谁下发

### 2.1 igb_uio/vfio 接管**不影响** host 侧 steering

- tun flow steering 的代码**跑在 host 内核**（`drivers/net/tun.c` 的 `ndo_select_queue`），它面对的是 tap 设备与 `tun_file`（队列抽象），**完全不知道 guest 里用的是 virtio-net 内核驱动还是 DPDK virtio PMD**。因此 DPDK 接管不会「关掉」steering。
- 变化的是「学习」的触发方式：
  - guest 用**内核 virtio_net** 时，出方向队列由 guest 内核 `netdev_pick_tx`/XPS 选择；
  - guest 用 **DPDK + f-stack** 时，出方向队列由 f-stack 各 worker 显式指定（worker i 用 queue i 发送）。tun 依然会在收到该包时把 `hash(flow) → queue i` 记进表，从而**后续该流的入向包会被 steer 到 queue i**——这一点对 f-stack 反而是有利的（自愈式收发同队列）。
  - **但是**：① 首包（SYN）在学习前按`((u64)hash*numqueues)>>32` 散落，可能落到 worker j ≠ i；② 表项 3 秒老化；③ tun 的对称哈希 ≠ f-stack 的 Toeplitz RSS，f-stack 无法预测/控制任何一条流会落到哪个 worker。
- **未找到**任何公开资料明确讨论「DPDK guest + tun automatic flow steering」的组合行为（这是本节①②③ 的推导部分，属机制推导而非文献引用，标注置信度：中高，机制链条各环节均有代码/文档支撑）。

### 2.2 `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET`：DPDK 在 `dev_start` 自动下发（本地代码核实）

本地代码 `/data/workspace/dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c`：

```c
/* :2331virtio_dev_start() */
    nb_queues = RTE_MAX(dev->data->nb_rx_queues, dev->data->nb_tx_queues);
    if (hw->max_queue_pairs > 1) {
        if (virtio_set_multiple_queues(dev, nb_queues) != 0)
            return -EINVAL;
    }

/* :202 */
static int
virtio_set_multiple_queues(struct rte_eth_dev *dev, uint16_t nb_queues)
{
    struct virtio_hw *hw = dev->data->dev_private;

    if (virtio_with_feature(hw, VIRTIO_NET_F_RSS))
        return virtio_set_multiple_queues_rss(dev, nb_queues);
    else
        return virtio_set_multiple_queues_auto(dev, nb_queues);
}

/* :178 —— 无 RSS 时走这条，下发 VQ_PAIRS_SET */
static int
virtio_set_multiple_queues_auto(struct rte_eth_dev *dev, uint16_t nb_queues)
{
    ...
    ctrl.hdr.class = VIRTIO_NET_CTRL_MQ;
    ctrl.hdr.cmd = VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET;
    memcpy(ctrl.data, &nb_queues, sizeof(uint16_t));
    dlen = sizeof(uint16_t);
    ret = virtio_send_command(hw->cvq, &ctrl, &dlen, 1);
    if (ret) {
        PMD_INIT_LOG(ERR, "Multiqueue configured but send command "
                  "failed, this is too late now...");
        return -EINVAL;
    }
    return 0;
}
```

**结论**：
- 应用（f-stack）**不需要**额外做任何事，PMD 在 `rte_eth_dev_start()` 里自动下发 VQ_PAIRS_SET。
- **但有一个硬前提**：`hw->cvq` 必须非空。`virtio_cvq.c:188-200`：
  ```c
  int virtio_send_command(struct virtnet_ctl *cvq, ...)
  {
      ...
      if (!cvq) {
          PMD_INIT_LOG(ERR, "Control queue is not supported.");
          return -1;
      }
  ```
  即 host 未协商 `VIRTIO_NET_F_CTRL_VQ` 时，`dev_start` 会直接 `-EINVAL` 失败。**排障要点**：如果 f-stack 2 队列能启动成功并跑到 `dev_start` 之后，说明 cvq 存在且 VQ_PAIRS_SET **已成功下发**，host 侧 `curr_queue_pairs` 已被置为 2 —— 因此「host 只启用了 1 条队列」这一假设可以基本排除（可用 §6 的探测手段实证）。

**QEMU 侧对该命令的处理**（来源：`hw/net/virtio-net.c`，链接同上）：

```c
} else if (cmd == VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET) {
    struct virtio_net_ctrl_mq mq;
    if (!virtio_vdev_has_feature(vdev, VIRTIO_NET_F_MQ))
        return VIRTIO_NET_ERR;
    ...
    queue_pairs = virtio_lduw_p(vdev, &mq.virtqueue_pairs);
}
if (queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN ||
    queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX ||
    queue_pairs > n->max_queue_pairs || !n->multiqueue)
    return VIRTIO_NET_ERR;

n->curr_queue_pairs = queue_pairs;
...
virtio_net_set_status(vdev, vdev->status);   /* 先停后端 */
virtio_net_set_queue_pairs(n);               /* 再逐队列 attach/detach */
```

```c
static void virtio_net_set_queue_pairs(VirtIONet *n)
{
    for (i = 0; i < n->max_queue_pairs; i++) {
        if (i < n->curr_queue_pairs)
            r = peer_attach(n, i);    /* TAP: tap_enable()；vhost-user: set_vring_enable(1) */
        else
            r = peer_detach(n, i);    /* TAP: tap_disable()；vhost-user: set_vring_enable(0) */
    }
}
```

以及：
```c
/* virtio_net_can_receive() —— 超出 curr_queue_pairs 的队列不收包 */
    if (nc->queue_index >= n->curr_queue_pairs) {
        return false;
    }
```

即 **`curr_queue_pairs` 是 host 侧「哪些队列真正激活」的唯一依据**，而它正是由 guest 的 VQ_PAIRS_SET 设置的。这条链完整闭合：DPDK dev_start → VQ_PAIRS_SET → QEMU `curr_queue_pairs=2` → `tap_enable(queue1)` → tun `numqueues` 变为 2 → `tun_automq_select_queue` 才可能返回 1。

**与 team-lead 给出的代码事实是否一致**：完全一致，无冲突。`:1840-1852`（MQ‖RSS → 读 max_virtqueue_pairs）与 `:2660-2669`（无 F_RSS → reta_size/hash_key_size/flow_type_rss_offloads 全 0）两处均已在本地代码复核确认（见上文引用）。

---

## 3. 问题3：「DPDK virtio 多队列下只有 queue 0 收包」的已知问题

### 3.1 直接 bug 报告：未找到可靠来源

在DPDK bugzilla（bugs.dpdk.org）、dpdk-dev / dpdk-stable 邮件列表归档、stackoverflow、GitHub issue 上，**未检索到**标题或内容明确为「virtio 多队列只有 queue 0 收包 / 其他队列收不到包」的 bug 报告。搜索用词覆盖了 `virtio multiqueue only queue 0`、`virtio rx queue not receiving`、`vhost-net tap flow steering only first queue` 等组合。

**如实声明：此项无直接来源。** 不编造链接。

### 3.2 但等价机制有官方记载（间接证据，强）

1. **OVS 官方文档**（链接见 §1.3）明确写：单PMD →流量全部排入**同一条** vhost 队列。这就是「只有一条队列收到包」的官方成因记载（针对 vhost-user 后端）。
2. **DPDK dev 邮件列表**关于 `ETH_MQ_RX_NONE` 语义的争论，直接触及本问题的语义本质：

   **来源**：`[dpdk-dev] [PATCH 3/3] net/virtio: reject unsupported Rx multi queue modes`，David Marchand，2019-10-10
   链接：https://mails.dpdk.org/archives/dev/2019-October/146539.html

   - **Tiwei Bie（virtio 维护者）**：`ETH_MQ_RX_NONE` 的含义是「不规定报文如何被分发到多个队列」（而非「只用队列0」）。
   - **Thomas Monjalon（DPDK 主维护者）**：`ETH_MQ_RX_NONE` 的含义是**所有报文都进队列 0**；代码注释写的是「无 DCB、无 RSS、无 VMDQ」；NONE 这个值**已被滥用**于描述自定义分流行为；建议要么文档化，要么**新增 `CUSTOM` 值**。
   - **Andrew Rybchenko（ethdev 维护者）**：倾向用 `ETH_MQ_RX_RSS` + `rss_hf == 0` 表示「分发方式未指定」。
   - **David Marchand 的结论性意见**：RSS 的本质是维持「流 ↔ 队列」亲和性；而在 virtio/vhost 场景中，**同一条流的报文可能落在任意队列上，取决于 vhost 侧发生了什么**，因此**不应把这种行为称作 RSS**。

   **来源**：同一 patch 在 stable 列表的讨论，Andrew Rybchenko，2019-10-09
   链接：https://mails.dpdk.org/archives/stable/2019-October/017737.html
   > "I'm not 100% sure about RSS. Yes, I know that virtio has no RSS configuration support, but it looks possible to have multi queue in vhost-net case."

   注：该 patch 当年加的检查是 `if (rxmode->mq_mode != ETH_MQ_RX_NONE) return -EINVAL;`（只允许 NONE）。**本地 DPDK 24.11.6 已放宽**为允许 `NONE` 或 `RSS`（`virtio_ethdev.c:2147-2152`），并在 `:2207-2211` 对「请求 RSS 但设备无 F_RSS」单独报 `RSS support requested but not supported by the device`。**以代码为准。**

3. **DPDK DTS 测试计划**明确要求多队列测试必须用**多条流**：
   **来源**：DPDK Test Plans《197. Vhost/Virtio multiple queue qemu test plan》
   链接：https://doc.dpdk.org/dts/test_plans/vhost_multi_queue_qemu_test_plan.html
   - VM 内 testpmd 必须带 `--rss-ip`；发包脚本用 4 个不同目的 IP（1.1.1.1 / 1.1.1.7 / 1.1.1.8 / 1.1.1.20）；期望「两个队列都能收发」。
   - `vectors = 2 * queue_num + 2`（2 队列 → `vectors=6`），QEMU 侧 `queues=2,mq=on`。
   - 注意该测试计划的数据面是 **vhost-user**（host testpmd `--vdev 'eth_vhost0,iface=vhost-net,queues=2'`），tap 只用于管理面。

### 3.3 DPDK 官方 virtio PMD 文档中的多队列相关约束

**来源**：DPDK《Poll Mode Driver for Emulated Virtio NIC》（DPDK 26.07.0 文档；23.11 版内容一致）
链接：https://doc.dpdk.org/guides/nics/virtio.html ；https://doc.dpdk.org/guides-23.11/nics/virtio.html

- QEMU 启用多队列：`-device virtio-net-pci,mq=on,vectors=2N+2`；MSI-X 向量**最少 N+1，推荐 2N+2**。
- Virtio 支持 Rx 中断，但**目前仅支持 1:1 的 queue/interrupt 映射**。
- RSS Rx 模式：支持；hash key 40 字节可配、RETA 128 项可配、hash types 可配。**hash report 仅在 packed virtqueue 模式下支持。**
- **不支持运行时配置（runtime configuration）**；MAC/VLAN 过滤是 best-effort。
- QEMU ≤2.7 描述符数硬编码 256；QEMU ≥2.8 Rx 队列最大 1024，**Tx 仍硬编码 256**。

**与本地代码的一致性**：DPDK 官方文档说「RSS 支持」是指PMD 具备该能力（21.11 引入，见 `doc/guides/rel_notes/release_21_11.rst:222-227`「Initial support for RSS receive mode has been added to the Virtio PMD… Virtio hash reporting is yet to be added」），**能否用取决于 host 是否宣告 `VIRTIO_NET_F_RSS`**。这与 team-lead 给出的 `:2660-2669` 事实一致，无冲突。

---

## 4. 问题4：f-stack 项目侧的virtio 多进程/多队列公开实践

### 4.1 找到的公开记录（全部是「失败 → 退化为单队列」）

| 来源 | 时间 | 现象 | 处置 |
|---|---|---|---|
| F-Stack GitHub Issue #489 `F-stack in VM: Ethdev port_id=0 invalid rss_hf: 0x28, valid value: 0x0`<br>https://github.com/F-Stack/f-stack/issues/489 | 2020-03-18 | KVM/Ubuntu 18.04 里跑 f-stack+nginx，virtio 网卡绑 igb_uio，报 `invalid rss_hf: 0x28, valid value: 0x0`，`init_port_start failed`。提问者说 OVS 桥接的 virtio 与 SR-IOV VF 直通**都报同样错** | Issue 已 Closed。**注意：本次抓取只拿到 issue 正文，评论区未加载成功（页面提示 "There was an error while loading"），因此维护者的具体回复内容无法确认，不做推测** |
| StackOverflow 69104064（经腾讯云社区镜像）`Unsupported Rx multi queue mode 1`<br>https://cloud.tencent.com/developer/ask/sof/108809527<br>（原帖 https://stackoverflow.com/questions/69104064） | 2021-09-08 提问 / 2021-09-09 采纳 | 同一二进制在 AWS CentOS 8 正常，迁到**阿里云** CentOS 8（virtio 网卡）报 `virtio_dev_configure(): Unsupported Rx multi queue mode 1` → `Port0 dev_configure = -22` | 采纳答案：**改 f-stack 源码** `lib/ff_dpdk_if.c` 约 627 行，把 `ETH_MQ_RX_RSS` 改成 `ETH_MQ_RX_NONE`，重编译；并建议 `lcore_mask=1`（单核单队列）。物理网卡（AWSENA）支持 RSS 所以不报错 |
| GitBook《helloworld》（作者 wintertee，DPDK-related 笔记）<br>https://wintertee.github.io/DPDK-related/f-stack/helloworld.html | 2021-05-28 | 用 **vhost-user（virtio_user0 + OVS-DPDK）**，`config.ini` 里 `[vdev0] queues=1`。日志：`Port 0 modified RSS hash function based on hardware support, requested:0x3ffffc configured:0` → `virtio_dev_configure(): Unsupported Rx multi queue mode 1` → `-22` | 该文给的「临时解决方法」是**注释掉 DPDK virtio_ethdev.c 里的检查**并重编 DPDK。参考链接列了 F-Stack issue #489、mtcp issue #282、DPDK patch *net/virtio: reject unsupported Rx multi queue modes* |
| Proxmox 论坛 thread 145270 `VirtIO network not support RSS (Receive Side Scaling) in VM`<br>https://forum.proxmox.com/threads/virtio-network-not-support-rss-receive-side-scaling-in-vm.145270/ | 2024-04-17 起，末贴 2024-12-05 | DPDK 应用在 Proxmox 的 virtio VM 里报 `virtio_dev_configure(): RSS support requested but not supported by the device`。#3 指出 Proxmox 生成的 `-device virtio-net-pci,...` **没有 `rss=on,hash=on`**（引 QEMU ebpf_rss 文档）；#4 用 `qm set --args` 加这两个参数后 **VM 根本起不来** | **该帖至今无解决方案。** Proxmox UI/`qm` 未暴露 virtio-net 的 RSS 开关 |

### 4.2 关于「是否有人在 virtio 上成功跑起 f-stack 多进程（多队列）」

**未找到任何可靠来源。** 检索覆盖：F-Stack GitHub issue、f-stack wiki/README、中文技术博客（CSDN / 知乎 / 博客园 / 简书 / 腾讯云社区）、公众号转载文。所有能找到的公开记录都停在「virtio 不支持 RSS → 报错 → 退化为单队列单进程」或「换支持 RSS 的 VF/物理网卡」。

搜到的相关但不构成正面案例的资料：
- 《使用 Intel 82599 VF 功能，在虚拟机里运行（f-stack）nginx》 https://blog.csdn.net/shaoyunzhe/article/details/72843895 （2017-06）——走的是 **SR-IOV VF**（支持 RSS）而**不是** virtio，且文中提到多nginx 进程时各进程有独立协议栈带来的问题。
- 《f-stack 队列和进程关系》 https://blog.csdn.net/shaoyunzhe/article/details/73498685 （2017-06）——阐述 f-stack 多进程模型「各进程绑定独立网卡队列和 CPU，请求通过**网卡 RSS** 散落到各进程」，即 f-stack 多进程模型**在设计上就以硬件 RSS 为前提**。
- 《全用户态网络开发套件 F-Stack 架构分析》 https://zhuanlan.zhihu.com/p/546932177——同上，「多进程无共享架构，每进程 CPU/网卡队列绑定」。
- 《将 F-Stack 改造为多线程库》 https://zhuanlan.zhihu.com/p/21075875679 （2025-02）——多线程化改造思路，但**未涉及 virtio 多队列分发问题**。

### 4.3 公开资料给出的「virtio 上要跑多队列的配置要点」汇总

综合 §1.3、§1.4、§3.3 的官方来源，可核查的配置要点如下（**注意：这些是「多队列能被启用」的必要条件，不等于「入向能按 RSS 分发」**）：

1. QEMU 必须 `-device virtio-net-pci,mq=on,vectors=2N+2`（Intel 文/OVS 文/DPDK 文三处一致）；vectors 不足会导致 MQ 无法正常工作。
2. netdev 侧 `queues=N`（tap 或 vhost-user 都要）。
3. guest 内核virtio-net 需`ethtool -L eth0 combined N`；**guest 用 DPDK 时不需要 ethtool**（DPDK 自己下发 VQ_PAIRS_SET，见 §2.2）。
4. vhost-user + OVS-DPDK：**至少 2 个 PMD**，且上游物理口 `n_rxq ≥ 2`；vhost 口的 `n_rxq` **不要手工设**。
5. 想要真正的 RSS（可控哈希 + RETA）必须让 host 宣告 `VIRTIO_NET_F_RSS`：QEMU 需 `rss=on`（+ 可选 `hash=on`），vhost=on 路径依赖 eBPF RSS（host 内核 ≥5.8、QEMU 带 `CONFIG_EBPF`）。**Proxmox/多数云平台默认不开**（§4.1 末行）。
6. **关于「是否要关 KNI」**：未找到任何可靠来源把 KNI 与 virtio 多队列关联。**此项无来源，不做结论。**

---

## 5. 问题5：无 RSS 网卡上做多队列/多 worker 负载均衡的通行做法

### 5.1 DPDK 官方方案一：Packet Distributor Library

**来源**：DPDK《Packet Distributor Library》程序员指南
链接：https://doc.dpdk.org/guides/prog_guide/packet_distrib_lib.html
配套示例：https://doc.dpdk.org/guides/sample_app_ug/dist_app.html

模式：单个 distributor 线程从（单条）RX 队列收包 → 按流标签（tag，通常取 mbuf 的 `hash.rss` 或自算哈希）动态分配给 N 个 worker，保证**同一 tag 的包同一时刻只在一个 worker 上处理**（保序），并支持动态负载均衡。这正是「无 RSS 网卡+ 多 worker」的库级标准答案。

### 5.2 DPDK 官方方案二：软件 Toeplitz（`rte_thash` / `rte_softrss`）

DPDK 提供 `rte_softrss()` / `rte_softrss_be()`（`rte_thash.h`），可在软件里用与硬件 RSS **相同的 Toeplitz 算法和 key** 计算哈希，从而在单队列收包后按 `hash % nb_workers`（或经 RETA）分发到各 worker，且**与硬件 RSS 的结果一致**——这一点对 f-stack 尤其关键，因为 f-stack 内部（`ff_dpdk_if.c` 的 `rss_check` / `ff_rss_thash_build_key`）本身就依赖 Toeplitz key 与 RETA 的一致性。

> 说明：`rte_thash` 的 API 文档页本次未单独抓取原文，此处结论基于 DPDK 该头文件的通用用法 + 本地 f-stack 代码中已存在的 `ff_rss_thash_build_key()` 事实（`ff_dpdk_if.c:908-915`）。**标注为「机制推导+ 本地代码印证」，非文献引用。**

### 5.3 为什么「靠 tun flow steering 当RSS 用」不可行（与 f-stack 模型的冲突）

把 §1.1 的内核事实与 f-stack 的多进程/多线程模型对照，有四条硬冲突：

| # | 冲突 | 依据 |
|---|---|---|
| F1 | **哈希算法不同**：tun 用 `__skb_get_hash_symmetric()`（flow dissector 软哈希，含 jhash + 对称化），f-stack/DPDK 用 Toeplitz + 自定义 key + RETA。两者对同一条流给出的队列号**无任何关系** | 内核 tun.c；f-stack `ff_dpdk_if.c:884-925` |
| F2 | **f-stack 无法控制也无法查询该映射**：`reta_size = 0`、`hash_key_size = 0`、`flow_type_rss_offloads = 0`（`virtio_ethdev.c:2660-2669`），`rte_eth_dev_rss_reta_update()` / `rss_hash_update()` 全都无从下手 | 本地 DPDK 代码 |
| F3 | **首包不确定 + 3 秒老化**：SYN 落哪个 worker 不可预测；空闲 3 秒后队列绑定丢失，同一连接的入向队列可能漂移到另一个 worker → 对「每 worker 独立 TCP 栈、无共享」的 f-stack 模型是致命的（PCB 不在那个 worker 上） | 内核 tun.c `TUN_FLOW_EXPIRE`、`tun_flow_cleanup()` |
| F4 | **DPDK 维护者已明确拒绝把这种行为称为 RSS**：「同一条流的报文可能落在任意队列上，取决于 vhost 侧发生了什么」| David Marchand，https://mails.dpdk.org/archives/dev/2019-October/146539.html |

---

## 6. 建议的运行时验证手段（只读探测，供team-lead 决策）

以下均为**只读观测**，不改代码、不改配置；供 team-lead 安排执行者（本agent 未执行任何系统命令）：

1. **确认 host 后端类型**（决定走 §1.1 还是 §1.3的机制）：
   - 本机网卡 `0000:00:09.0 'Virtio network device 1000'`（transitional device，legacy+modern）。需要在 **hypervisor 侧**看 QEMU 命令行 / libvirt XML 才能区分 `-netdev tap,vhost=on`（→ tun steering）与 `-netdev vhost-user`（→ PMD 绑队列）。若拿不到 hypervisor 视角，此项**无法从 guest 内确定**。
2. **确认 MQ 实际协商结果**：启动日志里 DPDK virtio PMD 的 `PMD_INIT_LOG(DEBUG, "nb_queues=%u (port=%u)")`（`virtio_ethdev.c:2389`）与 `Neither VIRTIO_NET_F_MQ nor VIRTIO_NET_F_RSS are supported`（`:1848`）两条日志是决定性证据——开 `--log-level=pmd.net.virtio.init:debug` 即可看到。
   - 若 `nb_queues=2` 且**没有** `:1848` 那条日志、且没有 `Multiqueue configured but send command failed` → VQ_PAIRS_SET 成功，host `curr_queue_pairs=2`。
3. **确认包到底进了哪条队列**：用 `rte_eth_stats_get()` 的 per-queue `q_ipackets[]`（f-stack 已有 `ff_dpdk_if.c` 的统计通路）或直接在 worker 收包处打 per-queue 计数。若全部计数集中在 queue 0，则符合 §1.3（vhost-user 单 PMD）或 §1.1 未学习 + 哈希恰好都落 0 的情形。
4. **区分 §1.1 与 §1.3**：若是 tun steering，则「**先从 worker 1 主动发一个包**（同五元组），再让对端回包」应该能观察到该流的入向包切换到 queue 1（学习生效，3 秒内有效）。这是一个**判别性实验**：能切换 → tun automatic flow steering；不能切换 → vhost-user/PMD 绑定路径或 host 只启用了1 条队列。

---

## 7. 与 team-lead 给出的代码事实的一致性总表

| team-lead 给出的事实 | 外网资料是否一致 | 备注 |
|---|---|---|
| `virtio_ethdev.c:2660-2669`：无 F_RSS 则 reta_size/flow_type_rss_offloads/hash_key_size 全 0 | **一致**（本地代码已复核原文） | DPDK 官方文档说「支持 RSS」指PMD 能力（21.11 引入），能否用取决于 host 宣告 F_RSS。不矛盾 |
| `virtio_ethdev.c:1840-1852`：F_MQ ‖ F_RSS 任一 → 读 max_virtqueue_pairs，否则 =1 | **一致**，且 QEMU `virtio_net_set_features()` 侧判定条件完全对称（`F_RSS \|\| F_MQ`） | https://github.com/qemu/qemu/blob/master/hw/net/virtio-net.c |
| 本机 `0000:00:09.0 'Virtio network device 1000' drv=igb_uio` | 无冲突 | 1000 = transitional device ID |
| f-stack `nb_queues > max_rx_queues` 会 rte_exit；实测2 队列能启动 ⇒ MQ 已协商 | **一致**，并可进一步推出 cvq 也存在、VQ_PAIRS_SET 已下发成功（否则 `dev_start` 返回 -EINVAL） | 本地 `ff_dpdk_if.c:862-872` + `virtio_ethdev.c:2384-2387` + `virtio_cvq.c:197-200` |
| （新增交叉发现）f-stack 在 `flow_type_rss_offloads == 0` 时**不设** `mq_mode`，即保持 `RTE_ETH_MQ_RX_NONE`，但**仍然setup nb_queues 个队列** | 这正好落在 DPDK 邮件列表 2019 年那场「`ETH_MQ_RX_NONE` 到底是『全进队列0』还是『分发方式未指定』」的语义争议里，且该争议**至今未有 CUSTOM 枚举落地** | 本地 `ff_dpdk_if.c:884-926`；https://mails.dpdk.org/archives/dev/2019-October/146539.html |

---

## 8. 来源清单（可核查）

**内核 / 虚拟化机制**
1. Linux `drivers/net/tun.c`（tag x86_misc_for_v5.16_rc1，blob fecc9a1d293a） — https://kernel.googlesource.com/pub/scm/linux/kernel/git/peterz/queue/+/refs/tags/x86_misc_for_v5.16_rc1/drivers/net/tun.c
2. KVM Wiki《Multiqueue》（Jason Wang，merged upstream，页面无日期戳） — https://www.linux-kvm.org/page/Multiqueue
3. QEMU `hw/net/virtio-net.c`（master） — https://github.com/qemu/qemu/blob/master/hw/net/virtio-net.c
4. QEMU 开发文档《eBPF RSS virtio-net support》（QEMU 11.0.92 master 文档） — https://www.qemu.org/docs/master/devel/ebpf_rss.html
5. LKML《[PATCH net-next 1/3] tun: abstract flow steering logic》（Jason Wang，2017-09-27，「tun now use flow caches based automatic queue steering method」） — https://lkml.org/lkml/2017/9/27/118｜镜像 https://lkml.iu.edu/hypermail/linux/kernel/1709.3/02467.html
   （注：lkml.org 有 Anubis 反爬，正文未抓取成功；此条仅用于佐证「flow caches based automatic queue steering」这一表述的出处，机制细节以来源 1 的内核源码为准）
6. LKML《[PATCH net-next V3] tun: add eBPF based queue selection method》（Jason Wang，2017-12） — https://lkml.org/lkml/2017/12/4/125

**DPDK 官方**
7. 《Poll Mode Driver for Emulated Virtio NIC》 — https://doc.dpdk.org/guides/nics/virtio.html ｜23.11 版 https://doc.dpdk.org/guides-23.11/nics/virtio.html
8. 《Packet Distributor Library》 — https://doc.dpdk.org/guides/prog_guide/packet_distrib_lib.html
9. 《Distributor Sample Application》 — https://doc.dpdk.org/guides/sample_app_ug/dist_app.html
10. DTS《197. Vhost/Virtio multiple queue qemu test plan》 — https://doc.dpdk.org/dts/test_plans/vhost_multi_queue_qemu_test_plan.html
11. DTS《167. vhost/virtio-user loopback with multi-queues test plan》 — https://doc.dpdk.org/dts/test_plans/loopback_multi_queues_test_plan.html

**DPDK 邮件列表**
12. dpdk-dev《[PATCH 3/3] net/virtio: reject unsupported Rx multi queue modes》David Marchand 2019-10-10 — https://mails.dpdk.org/archives/dev/2019-October/146539.html
13. dpdk-stable 同一 patch，Andrew Rybchenko 2019-10-09 — https://mails.dpdk.org/archives/stable/2019-October/017737.html
14. 相关后续讨论（inbox 归档） — https://inbox.dpdk.org/stable/97813cf0-78c1-8ff3-5b36-b3423a9141ce@solarflare.com/
15. LTS 回合记录（18.11.6，Kevin Traynor 2019-12-10） — https://inbox.dpdk.org/stable/20191210145937.32755-29-ktraynor@redhat.com/

**OVS / vhost-user**
16. OVS 官方《DPDK vHost User Ports》 — https://docs.openvswitch.org/en/latest/topics/dpdk/vhost-user/
17. Intel《OVS with DPDK: vHost User Multiqueue Configuration and Use》Ian Stokes 2016-07-12 — https://www.intel.cn/content/www/cn/zh/developer/articles/technical/configure-vhost-user-multiqueue-for-ovs-with-dpdk.html

**f-stack 相关实践**
18. F-Stack Issue #489（2020-03-18，Closed，评论区未加载） — https://github.com/F-Stack/f-stack/issues/489
19. StackOverflow 69104064`Unsupported Rx multi queue mode 1`（2021-09） — https://stackoverflow.com/questions/69104064 ｜中文镜像 https://cloud.tencent.com/developer/ask/sof/108809527
20. GitBook《helloworld》wintertee（2021-05-28） — https://wintertee.github.io/DPDK-related/f-stack/helloworld.html
21. Proxmox 论坛 thread 145270（2024-04 ~ 2024-12，无解） — https://forum.proxmox.com/threads/virtio-network-not-support-rss-receive-side-scaling-in-vm.145270/
22. 《f-stack 队列和进程关系》（2017-06，f-stack 多进程以硬件 RSS 为前提） — https://blog.csdn.net/shaoyunzhe/article/details/73498685
23. 《使用 Intel 82599 VF 功能，在虚拟机里运行（f-stack）nginx》（2017-06，走 SR-IOV VF 而非 virtio） — https://blog.csdn.net/shaoyunzhe/article/details/72843895
24. 《全用户态网络开发套件 F-Stack 架构分析》— https://zhuanlan.zhihu.com/p/546932177

**本地代码（交叉核对用，非外网来源）**
- `/data/workspace/dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c`：`:146-211`（set_multiple_queues_rss/auto）、`:1840-1852`（max_virtqueue_pairs）、`:2147-2152`（mq_mode 校验）、`:2207-2211`（RSS 请求但不支持）、`:2331-2397`（dev_start 下发 VQ_PAIRS_SET）、`:2660-2670`（无 F_RSS → 三个字段为 0）
- `/data/workspace/dpdk-stable-24.11.6/drivers/net/virtio/virtio_cvq.c:188-212`（`virtio_send_command`，`!cvq` 返回 -1）
- `/data/workspace/dpdk-stable-24.11.6/drivers/net/virtio/virtqueue.h:222-229`（`VIRTIO_NET_CTRL_MQ*` 宏）
- `/data/workspace/dpdk-stable-24.11.6/doc/guides/rel_notes/release_21_11.rst:222-227`（virtio RSS 于 21.11 引入）
- `/data/workspace/f-stack/lib/ff_dpdk_if.c:862-926`（nb_queues 校验、`flow_type_rss_offloads` 条件下的 RSS 配置）

---

## 9. 明确的知识边界（不越界结论）

1. **本机 host 后端到底是 vhost-net+tap 还是 vhost-user，本次调研无法确定**（需 hypervisor 侧视角）。§1.1 与 §1.3 是两套不同机制，结论会不同。
2. **「只有 queue 0 收包」的直接 bug 报告未找到**，§3.2 是等价机制的间接证据链，不能替代直接证据。
3. **「virtio 上成功跑 f-stack 多队列」的正面案例未找到**，不能据此断言「不可能」，只能说「公开资料中无先例，且机制上存在 §5.3 的四条硬冲突」。
4. **「是否要关 KNI」无任何来源**，不做结论。
5. §2.1 的 ①②③ 与 §5.2 的部分内容属**机制推导**（基于已引用的代码/文档链条），已在正文标注，未混入文献引用。
