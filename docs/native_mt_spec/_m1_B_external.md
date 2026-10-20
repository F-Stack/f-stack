# M1-B External Research: Inbound Packet Distribution Mechanism of virtio-net under DPDK Multi-Queue

> Researcher: extern-researcher (external material research agent)
> Date: 2026-08-03
> Task source: team-lead (native-mt-fix team)
> Boundary declaration: this document only does material research and code cross-check, **modified no code files**. Every conclusion carries its source; wherever external material conflicts with local code, "**code wins**" is marked. Items with no reliable source are honestly written "no reliable source found".

---

## 0. TL;DR

| # | Conclusion | Confidence | Basis |
|---|---|---|---|
| C1 | With only `VIRTIO_NET_F_MQ` negotiated (no `VIRTIO_NET_F_RSS`), **the guest cannot control inbound distribution at all**; which rx virtqueue receives a packet is decided unilaterally by the host backend | High (code + official docs + DPDK maintainer mail) | §1, §2 |
| C2 | When the host is **vhost-net + tap**, distribution is decided by the kernel `tun` driver's automatic flow steering: **learn on egress (guest→host), look up on ingress (host→guest)** | High (kernel source original) | §1.1 |
| C3 | On a tun table miss, it is **not fixed to queue 0**, but `txq = ((u64)hash * numqueues) >> 32` proportional symmetric-hash spreading. The KVM wiki's "fallback to the first queue" is a 2012 design-draft old description; **the kernel code wins** | High (kernel source original) | §1.1, §1.2 |
| C4 | tun uses `__skb_get_hash_symmetric()` (flow dissector software hash), **completely different from the DPDK/f-stack-side Toeplitz RSS hash**. Therefore "the flow f-stack worker i expects" and "the flow tun actually delivers to queue i" have **no consistency guarantee whatsoever**; and tun table entries age out after 3 seconds of inactivity (`TUN_FLOW_EXPIRE = 3*HZ`) | High (kernel source original) | §1.1, §5.3 |
| C5 | DPDK takeover (igb_uio/vfio) **does not affect** host-side tun/vhost steering — steering lives in the host kernel, unrelated to what driver the guest uses. But after the guest switches to DPDK, the "learning" trigger becomes each f-stack worker's tx queue | High (mechanism derivation + QEMU docs) | §2.1 |
| C6 | The DPDK virtio PMD **does** issue `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` automatically at `dev_start`, requiring no extra app action; but the precondition is the **control queue (cvq) exists**, otherwise `virtio_send_command` returns -1 directly → `dev_start` fails | High (local code verified) | §2.2 |
| C7 | For the "only queue 0 receives packets" phenomenon, **no direct same-kind bug report found** on DPDK bugzilla / dpdk-dev mailing list / stackoverflow; but OVS official docs give an explicit record of the equivalent mechanism (single PMD → all traffic into the same vhost queue) | Medium (indirect evidence sufficient, direct bug report missing) | §3 |
| C8 | f-stack side: **no public record found** of successfully running f-stack multi-process (multi-queue) on a virtio virtual NIC. Every found public record stops at "virtio lacks RSS → error → degrade to single-queue/single-process" | High (multiple independent sources consistent) | §4 |
| C9 | The common approach for multi-worker load balancing on no-RSS NICs: **single RX queue + software-hash secondary distribution** (`rte_distributor` or `rte_softrss` + ring), a DPDK official library-level solution | High (DPDK official docs) | §5 |

---

## 1. Question 1: How the Host Side Decides Which Receive Virtqueue a Packet Enters

### 1.1 vhost-net + tap (Linux Kernel tun Driver) — Mechanism Confirmed by Kernel Source

**Source**: Linux kernel `drivers/net/tun.c` (tag `x86_misc_for_v5.16_rc1`, blob `fecc9a1d293a`)
Link: https://kernel.googlesource.com/pub/scm/linux/kernel/git/peterz/queue/+/refs/tags/x86_misc_for_v5.16_rc1/drivers/net/tun.c

Key data structures and constants (original):

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
#define TUN_FLOW_EXPIRE (3 * HZ)      /* table entries age out after 3s inactivity */
```

**Ingress (host → guest, i.e. tun decides which rx virtqueue a packet enters)** — the `ndo_select_queue` callback:

```c
static u16 tun_select_queue(struct net_device *dev, struct sk_buff *skb,
                            struct net_device *sb_dev)
{
    struct tun_struct *tun = netdev_priv(dev);
    u16 ret;

    rcu_read_lock();
    if (rcu_dereference(tun->steering_prog))
        ret = tun_ebpf_select_queue(tun, skb);   /* only with a steering eBPF set */
    else
        ret = tun_automq_select_queue(tun, skb); /* default automatic flow steering */
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
        txq = e->queue_index;                    /* hit: use the learned queue */
    } else {
        /* use multiply and shift instead of expensive divide */
        txq = ((u64)txq * numqueues) >> 32;      /* miss: proportional hash spreading */
    }
    return txq;
}
```

**Egress (guest → host, where "learning" happens)** — tail of `tun_get_user()`:

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
    u16 queue_index = tfile->queue_index;   /* the queue the guest sent from */
    head = &tun->flows[tun_hashfn(rxhash)];
    e = tun_flow_find(head, rxhash);
    if (likely(e)) {
        if (READ_ONCE(e->queue_index) != queue_index)
            WRITE_ONCE(e->queue_index, queue_index);   /* flow migrated to a new queue */
        ...
    } else {
        spin_lock_bh(&tun->lock);
        if (!tun_flow_find(head, rxhash) && tun->flow_count < MAX_TAP_FLOWS)
            tun_flow_create(tun, head, rxhash, queue_index);
        ...
    }
}
```

A comment in the code directly explains why flows are identified by rxhash rather than the rxq number:

```c
/* We try to identify a flow through its rxhash. The reason that
 * we do not check rxq no. is because some cards(e.g 82599), chooses
 * the rxq based on the txq where the last packet of the flow comes. As
 * the userspace application move between processors, we may get a
 * different rxq no. here.
 */
```

**Answers to team-lead's three sub-questions**:

1. **Does it depend on the guest first sending a packet from that queue to "learn" the flow-to-queue mapping?**
   **Yes.** The only create/update entry of a table entry is `tun_flow_update()`, which is only called on the `tun_get_user()` / `tun_xdp_one()` paths (i.e. the host reads from tap **a packet the guest sent**); `queue_index` takes `tfile->queue_index` (the queue the guest used to send). **If the guest sends nothing → the table has no such flow → ingress can only fall back to hash spreading.**

2. **Where does the first packet (e.g. TCP SYN) go when there is no learning record?**
   The `else` branch: `txq = ((u64)hash * numqueues) >> 32`, i.e. proportionally mapped into `[0, numqueues)` by `__skb_get_hash_symmetric()`. **Not fixed to queue 0** but "hash-pseudo-random spreading". For a single fixed five-tuple connection, which queue the first packet lands in is **deterministic but unpredictable** (depends on the flow's symmetric hash value), and is unrelated to the guest-side Toeplitz RSS result.

3. **Table entry lifetime**: `TUN_FLOW_EXPIRE = 3 * HZ` (3 seconds). `tun_flow_cleanup()`'s timer deletes entries with `updated + 3s <= jiffies`. That is, **a long connection idle for 3 seconds loses its queue binding**, and the next inbound packet goes through hash spreading again — for "long connection + sparse traffic" scenarios this means the inbound queue drifts. Additionally, `tun_flow_delete_by_queue()` clears all entries of a queue on detach.

### 1.2 Comparison with the KVM Official Design Document (Inconsistency Exists; Code Wins)

**Source**: KVM Wiki《Multiqueue》(Multiqueue virtio-net design page, author Jason Wang<jasowang@redhat.com>, status marked merged upstream)
Link: https://www.linux-kvm.org/page/Multiqueue

The *Queue selector* section gives the judgment order:

1. skb already carries an RX queue mapping (from physical NIC RSS/flow director) → use that queue number;
2. otherwise if rxhash can be computed → use rxhash to pick the queue;
3. both fail → **always falls to the first available queue**.

While "hash→queue mapping table + table updated when the guest sends" is placed under **"Further Optimization ?"** (pending optimization proposal) on that page, indicating it entered the kernel later:

> rxhash only spreads load to different vcpus, but the selected vcpu may not be the one actually executing `recvmsg()` …
> Proposal: record the actual cpu/queue each flow uses, **update the table when the guest sends**; look up the table when tun/tap delivers packets to the guest.

**Inconsistency and ruling**:
- The KVM wiki says "fixed to the first queue when no hash available". In the kernel 5.16 code, `tun_automq_select_queue()` unconditionally calls `__skb_get_hash_symmetric()`; with no hash it returns 0, and `((u64)0 * numqueues) >> 32 == 0` — the result is coincidentally queue 0 as well. So the two agree on the "truly cannot compute a hash" sub-case; but for the mainstream "hash computable but table miss" case (a normal TCP first packet), the wiki's old text does not describe the current `((u64)hash * numqueues) >> 32` behavior. **The kernel code wins.**
- The wiki mentions `IFF_ATTACH_QUEUE` / `IFF_DETACH_QUEUE` (temporarily enabling/disabling queues so single-queue drivers can run on multi-queue devices); confirmed to exist in the kernel code's `tun_set_queue()`, corresponding to QEMU-side behavior (see §2.1).

### 1.3 vhost-user / OVS-DPDK Backends — Distribution Is NOT by Packet Hash but Bound to PMD Threads

**Source**: Open vSwitch official docs《DPDK vHost User Ports》
Link: https://docs.openvswitch.org/en/latest/topics/dpdk/vhost-user/

Key points (translated):
- With multiqueue, the **vswitch must configure at least 2 PMDs**. With only 1 PMD, traffic is **enqueued to the same vhost queue**, not spread across the different queues of that vhost-user interface.
- The vhost-user port's `n_rxq` **does not support manual configuration**; it is re-negotiated automatically after the virtio device connects, based on QEMU's `queues=N`.
- If traffic to the VM comes from a physical DPDK port, that physical port should also have ≥2 rx queues, to **increase** the **probability** (the doc's own word) that different PMDs complete the send-to-guest and thus use different vhost queues.

**Source**: Intel《Open vSwitch with DPDK: vHost User Multiqueue Configuration and Use》(author Ian Stokes, 2016-07-12, doc ID 659209)
Link: https://www.intel.cn/content/www/cn/zh/developer/articles/technical/configure-vhost-user-multiqueue-for-ovs-with-dpdk.html

- Distribution is **two-level**: ① the physical NIC uses RSS to hash inbound traffic across multiple NIC queues; ② on the host vSwitch side each queue is handled by an independent PMD thread, and each PMD delivers packets into the VNIC queue corresponding to the vhost-user port.
- Therefore **test traffic must be multiple flows** (the article triggers RSS by varying destination IPs); a single flow cannot spread.
- Configuration must align in three places: QEMU `queues=N` + `vectors=2N+2`; OVS auto-negotiation; guest kernel driver `ethtool -L eth0 combined N` (when the guest uses DPDK, switch to testpmd `--rxq/--txq`, no ethtool needed).

**Conclusion**: on the vhost-user path, queue selection **is bound to the PMD thread performing the send**, essentially a "upstream physical NIC RSS result → PMD → vhost queue" chain; if upstream has only 1 rxq / 1 PMD, then no matter how many queues the guest enables, only queue 0 receives. This corresponds directly to the §3 phenomenon.

### 1.4 QEMU / vhost-net eBPF Steering (Can Override tun Default Behavior)

**Source**: QEMU official dev docs《eBPF RSS virtio-net support》(QEMU 11.0.92 master docs)
Link: https://www.qemu.org/docs/master/devel/ebpf_rss.html

Key descriptions:
- **When no steering BPF is set on the kernel TUN**: TUN uses the "automatic rx virtqueue selection" method — **selecting the queue based on a lookup table built from symmetric hashes of already-sent packets**. (This fully matches the §1.1 kernel code; it is the official natural-language description of `tun_automq_select_queue`.)
- **When a steering BPF is set**: the BPF program computes the hash and directly returns the virtqueue number.
- `set_steering_ebpf()` is currently **only supported by the Linux TAP backend**.
- rss/hash combination behavior table: `vhost=on` + `rss=on,hash=off` → use eBPF; `vhost=off` + `rss=on,hash=on` → use in-QEMU software RSS; `vhost=on` + `rss=on,hash=on` → use eBPF but **do not report hash capability to the guest**.
- eBPF RSS requires **host kernel ≥ 5.8** and QEMU compiled with `CONFIG_EBPF`. On load/set failure it falls back to in-QEMU RSS (only effective with `vhost=off`).

**Source**: QEMU `hw/net/virtio-net.c` (master)
Link: https://github.com/qemu/qemu/blob/master/hw/net/virtio-net.c

```c
    virtio_net_set_multiqueue(n,
                              virtio_has_feature_ex(features, VIRTIO_NET_F_RSS) ||
                              virtio_has_feature_ex(features, VIRTIO_NET_F_MQ));
```

That is, QEMU-side "negotiated F_MQ **or** F_RSS → enable multiqueue" is **fully symmetric** with the local DPDK code `virtio_ethdev.c:1840-1852`'s condition (both MQ‖RSS).

---

## 2. Question 2: Does Host Steering Still Work After DPDK Takeover + Who Issues VQ_PAIRS_SET

### 2.1 igb_uio/vfio Takeover Does NOT Affect Host-Side Steering

- tun flow steering code **runs in the host kernel** (`drivers/net/tun.c`'s `ndo_select_queue`); it faces the tap device and `tun_file` (queue abstraction) and **has no idea whether the guest uses the virtio-net kernel driver or the DPDK virtio PMD**. So DPDK takeover does not "turn off" steering.
- What changes is how "learning" is triggered:
  - with the guest on the **kernel virtio_net**, the egress queue is chosen by the guest kernel's `netdev_pick_tx`/XPS;
  - with the guest on **DPDK + f-stack**, the egress queue is explicitly chosen by each f-stack worker (worker i sends with queue i). tun still records `hash(flow) → queue i` into the table upon receiving that packet, so **later inbound packets of that flow get steered to queue i** — actually favorable for f-stack (self-healing same-queue send/receive).
  - **But**: ① the first packet (SYN), before learning, spreads by `((u64)hash*numqueues)>>32` and may land on worker j ≠ i; ② table entries age out in 3s; ③ tun's symmetric hash ≠ f-stack's Toeplitz RSS, so f-stack cannot predict/control which worker any flow lands on.
- **No public material found** explicitly discussing the "DPDK guest + tun automatic flow steering" combination (the §2.1 ①②③ part is mechanism derivation rather than literature citation; confidence marked medium-high, each link of the mechanism chain has code/doc support).

### 2.2 `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET`: Issued Automatically by DPDK at `dev_start` (Local Code Verified)

Local code `/data/workspace/dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c`:

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

/* :178 —— without RSS this path issues VQ_PAIRS_SET */
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

**Conclusion**:
- The application (f-stack) **needs to do nothing extra**; the PMD issues VQ_PAIRS_SET automatically inside `rte_eth_dev_start()`.
- **But there is a hard precondition**: `hw->cvq` must be non-NULL. `virtio_cvq.c:188-200`:
  ```c
  int virtio_send_command(struct virtnet_ctl *cvq, ...)
  {
      ...
      if (!cvq) {
          PMD_INIT_LOG(ERR, "Control queue is not supported.");
          return -1;
      }
  ```
  That is, when the host did not negotiate `VIRTIO_NET_F_CTRL_VQ`, `dev_start` directly fails with `-EINVAL`. **Troubleshooting key**: if f-stack's 2 queues start successfully and run past `dev_start`, then the cvq exists and VQ_PAIRS_SET **was successfully issued**, and the host-side `curr_queue_pairs` was set to 2 — therefore the "host only enabled 1 queue" hypothesis can basically be excluded (verifiable with the probing means in §6).

**QEMU-side handling of this command** (source: `hw/net/virtio-net.c`, link above):

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
virtio_net_set_status(vdev, vdev->status);   /* stop backend first */
virtio_net_set_queue_pairs(n);               /* then attach/detach per queue */
```

```c
static void virtio_net_set_queue_pairs(VirtIONet *n)
{
    for (i = 0; i < n->max_queue_pairs; i++) {
        if (i < n->curr_queue_pairs)
            r = peer_attach(n, i);    /* TAP: tap_enable(); vhost-user: set_vring_enable(1) */
        else
            r = peer_detach(n, i);    /* TAP: tap_disable(); vhost-user: set_vring_enable(0) */
    }
}
```

And:

```c
/* virtio_net_can_receive() —— queues beyond curr_queue_pairs do not receive */
    if (nc->queue_index >= n->curr_queue_pairs) {
        return false;
    }
```

That is, **`curr_queue_pairs` is the only basis for "which queues are genuinely active" on the host side**, and it is exactly what the guest's VQ_PAIRS_SET sets. This chain is fully closed: DPDK dev_start → VQ_PAIRS_SET → QEMU `curr_queue_pairs=2` → `tap_enable(queue1)` → tun `numqueues` becomes 2 → `tun_automq_select_queue` can return 1.

**Consistent with team-lead's code facts?** Fully consistent, no conflict. Both `:1840-1852` (MQ‖RSS → read max_virtqueue_pairs) and `:2660-2669` (no F_RSS → reta_size/hash_key_size/flow_type_rss_offloads all 0) were re-verified against local code (see citations above).

---

## 3. Question 3: Known Issues of "Only Queue 0 Receives under DPDK virtio Multi-Queue"

### 3.1 Direct Bug Report: No Reliable Source Found

On DPDK bugzilla (bugs.dpdk.org), the dpdk-dev / dpdk-stable mailing-list archives, stackoverflow, and GitHub issues, **no bug report** with title or content clearly "virtio multiqueue only queue 0 receives / other queues receive nothing" was found. Search terms covered combinations like `virtio multiqueue only queue 0`, `virtio rx queue not receiving`, `vhost-net tap flow steering only first queue`.

**Honest declaration: no direct source for this item.** No fabricated links.

### 3.2 But the Equivalent Mechanism Has Official Records (Indirect Evidence, Strong)

1. **OVS official docs** (link in §1.3) explicitly state: a single PMD → all traffic enqueued into **the same** vhost queue. This is the official recorded cause of "only one queue receives" (for the vhost-user backend).
2. The **DPDK dev mailing list** argument over the semantics of `ETH_MQ_RX_NONE` directly touches this problem's semantic essence:

   **Source**: `[dpdk-dev] [PATCH 3/3] net/virtio: reject unsupported Rx multi queue modes`, David Marchand, 2019-10-10
   Link: https://mails.dpdk.org/archives/dev/2019-October/146539.html

   - **Tiwei Bie (virtio maintainer)**: `ETH_MQ_RX_NONE` means "does not specify how packets are distributed across multiple queues" (rather than "use only queue 0").
   - **Thomas Monjalon (DPDK main maintainer)**: `ETH_MQ_RX_NONE` means **all packets go to queue 0**; the code comment says "no DCB, no RSS, no VMDQ"; the NONE value has been **abused** for describing custom distribution behaviors; suggests either documenting it or **adding a `CUSTOM` value**.
   - **Andrew Rybchenko (ethdev maintainer)**: prefers `ETH_MQ_RX_RSS` + `rss_hf == 0` to mean "distribution method unspecified".
   - **David Marchand's concluding opinion**: the essence of RSS is maintaining "flow ↔ queue" affinity; in the virtio/vhost scenario, **packets of the same flow may land on any queue depending on what happens on the vhost side**, so this behavior **should not be called RSS**.

   **Source**: the same patch's discussion on the stable list, Andrew Rybchenko, 2019-10-09
   Link: https://mails.dpdk.org/archives/stable/2019-October/017737.html
   > "I'm not 100% sure about RSS. Yes, I know that virtio has no RSS configuration support, but it looks possible to have multi queue in vhost-net case."

   Note: the check that patch added that year was `if (rxmode->mq_mode != ETH_MQ_RX_NONE) return -EINVAL;` (only NONE allowed). **Local DPDK 24.11.6 has relaxed** this to allow `NONE` or `RSS` (`virtio_ethdev.c:2147-2152`), and at `:2207-2211` reports `RSS support requested but not supported by the device` for "requested RSS but the device has no F_RSS". **Code wins.**

3. **The DPDK DTS test plan** explicitly requires multi-queue tests to use **multiple flows**:
   **Source**: DPDK Test Plans《197. Vhost/Virtio multiple queue qemu test plan》
   Link: https://doc.dpdk.org/dts/test_plans/vhost_multi_queue_qemu_test_plan.html
   - testpmd inside the VM must run with `--rss-ip`; the sending script uses 4 different destination IPs (1.1.1.1 / 1.1.1.7 / 1.1.1.8 / 1.1.1.20); expecting "both queues can send and receive".
   - `vectors = 2 * queue_num + 2` (2 queues → `vectors=6`), QEMU side `queues=2,mq=on`.
   - Note the test plan's data plane is **vhost-user** (host testpmd `--vdev 'eth_vhost0,iface=vhost-net,queues=2'`); tap is used only for the management plane.

### 3.3 Multi-Queue Related Constraints in the DPDK Official virtio PMD Docs

**Source**: DPDK《Poll Mode Driver for Emulated Virtio NIC》(DPDK 26.07.0 docs; 23.11 content identical)
Link: https://doc.dpdk.org/guides/nics/virtio.html ; https://doc.dpdk.org/guides-23.11/nics/virtio.html

- Enabling multiqueue in QEMU: `-device virtio-net-pci,mq=on,vectors=2N+2`; MSI-X vectors **minimum N+1, recommended 2N+2**.
- Virtio supports Rx interrupts, but **currently only 1:1 queue/interrupt mapping**.
- RSS Rx mode: supported; hash key 40 bytes configurable, RETA 128 entries configurable, hash types configurable. **Hash report only supported in packed virtqueue mode.**
- **No runtime configuration support**; MAC/VLAN filtering is best-effort.
- QEMU ≤2.7 hardcodes 256 descriptors; QEMU ≥2.8 Rx queues max 1024, **Tx still hardcoded 256**.

**Consistency with local code**: the DPDK official doc's "RSS supported" means the PMD has the capability (introduced in 21.11, see `doc/guides/rel_notes/release_21_11.rst:222-227` "Initial support for RSS receive mode has been added to the Virtio PMD… Virtio hash reporting is yet to be added"); whether it can be used depends on the host advertising `VIRTIO_NET_F_RSS`. Consistent with team-lead's `:2660-2669` fact, no conflict.

---

## 4. Question 4: Public Practice of f-stack virtio Multi-Process/Multi-Queue

### 4.1 Public Records Found (All "Failure → Degrade to Single-Queue")

| Source | Time | Symptom | Disposition |
|---|---|---|---|
| F-Stack GitHub Issue #489 `F-stack in VM: Ethdev port_id=0 invalid rss_hf: 0x28, valid value: 0x0`<br>https://github.com/F-Stack/f-stack/issues/489 | 2020-03-18 | f-stack+nginx in KVM/Ubuntu 18.04, virtio NIC bound to igb_uio, reports `invalid rss_hf: 0x28, valid value: 0x0`, `init_port_start failed`. The asker says OVS-bridged virtio and SR-IOV VF passthrough **both report the same error** | Issue Closed. **Note: this fetch only got the issue body; the comment section failed to load (page shows "There was an error while loading"), so the maintainer's exact reply cannot be confirmed; no speculation** |
| StackOverflow 69104064 (via Tencent Cloud community mirror) `Unsupported Rx multi queue mode 1`<br>https://cloud.tencent.com/developer/ask/sof/108809527<br>(original https://stackoverflow.com/questions/69104064) | asked 2021-09-08 / accepted 2021-09-09 | same binary works on AWS CentOS 8, moving to **Aliyun** CentOS 8 (virtio NIC) reports `virtio_dev_configure(): Unsupported Rx multi queue mode 1` → `Port0 dev_configure = -22` | accepted answer: **change f-stack source** at `lib/ff_dpdk_if.c` ~line 627, replace `ETH_MQ_RX_RSS` with `ETH_MQ_RX_NONE`, recompile; and suggest `lcore_mask=1` (single-core single-queue). Physical NICs (AWS ENA) support RSS so no error |
| GitBook《helloworld》(author wintertee, DPDK-related notes)<br>https://wintertee.github.io/DPDK-related/f-stack/helloworld.html | 2021-05-28 | uses **vhost-user (virtio_user0 + OVS-DPDK)**, `config.ini` has `[vdev0] queues=1`. Logs: `Port 0 modified RSS hash function based on hardware support, requested:0x3ffffc configured:0` → `virtio_dev_configure(): Unsupported Rx multi queue mode 1` → `-22` | the article's "temporary workaround" is **commenting out the check in DPDK virtio_ethdev.c** and recompiling DPDK. Reference links list F-Stack issue #489, mtcp issue #282, DPDK patch *net/virtio: reject unsupported Rx multi queue modes* |
| Proxmox forum thread 145270 `VirtIO network not support RSS (Receive Side Scaling) in VM`<br>https://forum.proxmox.com/threads/virtio-network-not-support-rss-receive-side-scaling-in-vm.145270/ | 2024-04-17 onward, last post 2024-12-05 | DPDK app in a Proxmox virtio VM reports `virtio_dev_configure(): RSS support requested but not supported by the device`. #3 points out Proxmox's generated `-device virtio-net-pci,...` **has no `rss=on,hash=on`** (citing QEMU ebpf_rss docs); #4 added these two params via `qm set --args` and the **VM would not start** | **This thread still has no solution.** The Proxmox UI/`qm` does not expose virtio-net's RSS switch |

### 4.2 Whether Anyone Successfully Ran f-stack Multi-Process (Multi-Queue) on virtio

**No reliable source found.** Search covered: F-Stack GitHub issues, f-stack wiki/README, Chinese tech blogs (CSDN / Zhihu / cnblogs / Jianshu / Tencent Cloud community), WeChat reposts. Every public record found stops at "virtio lacks RSS → error → degrade to single-queue single-process" or "switch to an RSS-capable VF/physical NIC".

Related-but-not-positive-case material found:
- 《使用 Intel 82599 VF 功能，在虚拟机里运行（f-stack）nginx》 https://blog.csdn.net/shaoyunzhe/article/details/72843895 (2017-06) — uses **SR-IOV VF** (RSS-capable) **not** virtio; and mentions the problems of each process having an independent stack when running multiple nginx processes.
- 《f-stack 队列和进程关系》 https://blog.csdn.net/shaoyunzhe/article/details/73498685 (2017-06) — explains f-stack's multi-process model "each process binds an independent NIC queue and CPU, requests spread across processes via **NIC RSS**", i.e. f-stack's multi-process model **is designed on the premise of hardware RSS**.
- 《全用户态网络开发套件 F-Stack 架构分析》 https://zhuanlan.zhihu.com/p/546932177 — same, "multi-process share-nothing architecture, per-process CPU/NIC-queue binding".
- 《将 F-Stack 改造为多线程库》 https://zhuanlan.zhihu.com/p/21075875679 (2025-02) — multithreading rework ideas, but **does not touch the virtio multi-queue distribution problem**.

### 4.3 Public-Material Summary of "Multi-Queue Config Points to Run on virtio"

Combining the official sources of §1.3, §1.4, §3.3, the verifiable config points are (**:note these are necessary conditions for multi-queue to be enabled, not equivalent to "inbound can distribute by RSS"**):

1. QEMU must use `-device virtio-net-pci,mq=on,vectors=2N+2` (Intel article / OVS article / DPDK article all agree); insufficient vectors break MQ.
2. netdev side `queues=N` (for both tap and vhost-user).
3. guest kernel virtio-net needs `ethtool -L eth0 combined N`; **guest on DPDK needs no ethtool** (DPDK issues VQ_PAIRS_SET itself, see §2.2).
4. vhost-user + OVS-DPDK: **at least 2 PMDs**, and the upstream physical port `n_rxq ≥ 2`; do **not manually set** the vhost port's `n_rxq`.
5. For real RSS (controllable hash + RETA), the host must advertise `VIRTIO_NET_F_RSS`: QEMU needs `rss=on` (+ optional `hash=on`); the vhost=on path depends on eBPF RSS (host kernel ≥5.8, QEMU with `CONFIG_EBPF`). **Proxmox/most cloud platforms do not enable it by default** (§4.1 last row).
6. **About "whether KNI must be disabled"**: no reliable source found correlating KNI with virtio multi-queue. **No source for this item; no conclusion drawn.**

---

## 5. Question 5: Common Approaches for Multi-Queue/Multi-Worker Load Balancing on No-RSS NICs

### 5.1 DPDK Official Solution 1: Packet Distributor Library

**Source**: DPDK《Packet Distributor Library》Programmer's Guide
Link: https://doc.dpdk.org/guides/prog_guide/packet_distrib_lib.html
Sample: https://doc.dpdk.org/guides/sample_app_ug/dist_app.html

Mode: a single distributor thread receives packets from a (single) RX queue → dynamically distributes them by flow tag (tag, usually the mbuf's `hash.rss` or a self-computed hash) to N workers, guaranteeing **packets of the same tag are processed by exactly one worker at a time** (ordering preserved), with dynamic load balancing. This is exactly the library-level standard answer for "no-RSS NIC + multi-worker".

### 5.2 DPDK Official Solution 2: Software Toeplitz (`rte_thash` / `rte_softrss`)

DPDK provides `rte_softrss()` / `rte_softrss_be()` (`rte_thash.h`), which can compute the hash in software using the **same Toeplitz algorithm and key** as hardware RSS, so after single-queue reception packets can be distributed to workers by `hash % nb_workers` (or via RETA), **consistent with hardware RSS results** — especially critical for f-stack, because f-stack internally (`ff_dpdk_if.c`'s `rss_check` / `ff_rss_thash_build_key`) already relies on Toeplitz-key/RETA consistency.

> Note: the `rte_thash` API doc page was not separately fetched this time; this conclusion is based on the header's general usage + the existing `ff_rss_thash_build_key()` fact in local f-stack code (`ff_dpdk_if.c:908-915`). **Marked "mechanism derivation + local code corroboration", not literature citation.**

### 5.3 Why "Using tun Flow Steering as RSS" Is Not Viable (Conflict with the f-stack Model)

Comparing the §1.1 kernel facts against f-stack's multi-process/multi-thread model, there are four hard conflicts:

| # | Conflict | Basis |
|---|---|---|
| F1 | **Different hash algorithms**: tun uses `__skb_get_hash_symmetric()` (flow dissector software hash, incl. jhash + symmetrization); f-stack/DPDK use Toeplitz + custom key + RETA. The queue numbers the two give for the same flow **have no relationship** | kernel tun.c; f-stack `ff_dpdk_if.c:884-925` |
| F2 | **f-stack can neither control nor query that mapping**: `reta_size = 0`, `hash_key_size = 0`, `flow_type_rss_offloads = 0` (`virtio_ethdev.c:2660-2669`); `rte_eth_dev_rss_reta_update()` / `rss_hash_update()` all have nothing to operate on | local DPDK code |
| F3 | **First packet uncertain + 3s aging**: which worker a SYN lands on is unpredictable; after 3s idle the queue binding is lost, and the same connection's inbound queue may drift to another worker → fatal for f-stack's "independent TCP stack per worker, no sharing" model (the PCB is not on that worker) | kernel tun.c `TUN_FLOW_EXPIRE`, `tun_flow_cleanup()` |
| F4 | **DPDK maintainers explicitly refused to call this behavior RSS**: "packets of the same flow may land on any queue, depending on what happens on the vhost side" | David Marchand, https://mails.dpdk.org/archives/dev/2019-October/146539.html |

---

## 6. Suggested Runtime Verification Means (Read-Only Probing, for team-lead to Decide)

All of the following are **read-only observations**; no code changes, no config changes; for team-lead to assign an executor (this agent ran no system commands):

1. **Confirm the host backend type** (decides whether §1.1 or §1.3 applies):
   - This machine's NIC `0000:00:09.0 'Virtio network device 1000'` (transitional device, legacy+modern). Distinguishing `-netdev tap,vhost=on` (→ tun steering) from `-netdev vhost-user` (→ PMD-bound queues) requires a **hypervisor-side** view of the QEMU command line / libvirt XML. Without hypervisor access, this item **cannot be determined from inside the guest**.
2. **Confirm the MQ negotiation result**: the DPDK virtio PMD's `PMD_INIT_LOG(DEBUG, "nb_queues=%u (port=%u)")` (`virtio_ethdev.c:2389`) and `Neither VIRTIO_NET_F_MQ nor VIRTIO_NET_F_RSS are supported` (`:1848`) are the decisive logs — visible with `--log-level=pmd.net.virtio.init:debug`.
   - If `nb_queues=2` and **no** `:1848` log, and **no** `Multiqueue configured but send command failed` → VQ_PAIRS_SET succeeded, host `curr_queue_pairs=2`.
3. **Confirm which queue packets actually enter**: use `rte_eth_stats_get()`'s per-queue `q_ipackets[]` (f-stack already has the stats path in `ff_dpdk_if.c`) or add per-queue counters at the worker receive point. If all counts concentrate on queue 0, it matches §1.3 (vhost-user single PMD) or §1.1 unlearned + hash coincidentally all 0.
4. **Distinguish §1.1 from §1.3**: with tun steering, "**first actively send one packet from worker 1** (same five-tuple), then let the peer reply" should observe that flow's inbound packets switching to queue 1 (learning takes effect within 3s). This is a **discriminative experiment**: switchable → tun automatic flow steering; not switchable → vhost-user/PMD-bound path or the host only enabled 1 queue.

---

## 7. Consistency Table with team-lead's Code Facts

| team-lead fact | External material consistent? | Note |
|---|---|---|
| `virtio_ethdev.c:2660-2669`: without F_RSS, reta_size/flow_type_rss_offloads/hash_key_size all 0 | **Consistent** (local code re-verified original) | DPDK official docs "supports RSS" means the PMD capability (introduced 21.11); whether usable depends on the host advertising F_RSS. Not contradictory |
| `virtio_ethdev.c:1840-1852`: either F_MQ ‖ F_RSS → read max_virtqueue_pairs, else =1 | **Consistent**, and QEMU `virtio_net_set_features()`'s condition is fully symmetric (`F_RSS \|\| F_MQ`) | https://github.com/qemu/qemu/blob/master/hw/net/virtio-net.c |
| This machine's `0000:00:09.0 'Virtio network device 1000' drv=igb_uio` | No conflict | 1000 = transitional device ID |
| f-stack `nb_queues > max_rx_queues` rte_exit; measured 2 queues start ⇒ MQ negotiated | **Consistent**, and can further infer the cvq exists and VQ_PAIRS_SET was successfully issued (otherwise `dev_start` returns -EINVAL) | local `ff_dpdk_if.c:862-872` + `virtio_ethdev.c:2384-2387` + `virtio_cvq.c:197-200` |
| (new cross-finding) f-stack, when `flow_type_rss_offloads == 0`, does **not** set `mq_mode` (keeps `RTE_ETH_MQ_RX_NONE`) but **still sets up nb_queues queues** | This exactly falls into the 2019 DPDK mailing-list semantic dispute over "is `ETH_MQ_RX_NONE` 'everything into queue 0' or 'distribution unspecified'", and **no `CUSTOM` enum has landed to date** | local `ff_dpdk_if.c:884-926`; https://mails.dpdk.org/archives/dev/2019-October/146539.html |

---

## 8. Source List (Verifiable)

**Kernel / virtualization mechanisms**
1. Linux `drivers/net/tun.c` (tag x86_misc_for_v5.16_rc1, blob fecc9a1d293a) — https://kernel.googlesource.com/pub/scm/linux/kernel/git/peterz/queue/+/refs/tags/x86_misc_for_v5.16_rc1/drivers/net/tun.c
2. KVM Wiki《Multiqueue》(Jason Wang, merged upstream, no date stamp) — https://www.linux-kvm.org/page/Multiqueue
3. QEMU `hw/net/virtio-net.c` (master) — https://github.com/qemu/qemu/blob/master/hw/net/virtio-net.c
4. QEMU dev docs《eBPF RSS virtio-net support》(QEMU 11.0.92 master) — https://www.qemu.org/docs/master/devel/ebpf_rss.html
5. LKML《[PATCH net-next 1/3] tun: abstract flow steering logic》(Jason Wang, 2017-09-27, "tun now use flow caches based automatic queue steering method") — https://lkml.org/lkml/2017/9/27/118｜mirror https://lkml.iu.edu/hypermail/linux/kernel/1709.3/02467.html
   (note: lkml.org has Anubis anti-crawling; body fetch failed; this item only corroborates the origin of the "flow caches based automatic queue steering" phrase; mechanism details follow the kernel source of source 1)
6. LKML《[PATCH net-next V3] tun: add eBPF based queue selection method》(Jason Wang, 2017-12) — https://lkml.org/lkml/2017/12/4/125

**DPDK official**
7. 《Poll Mode Driver for Emulated Virtio NIC》 — https://doc.dpdk.org/guides/nics/virtio.html ｜23.11 version https://doc.dpdk.org/guides-23.11/nics/virtio.html
8. 《Packet Distributor Library》 — https://doc.dpdk.org/guides/prog_guide/packet_distrib_lib.html
9. 《Distributor Sample Application》 — https://doc.dpdk.org/guides/sample_app_ug/dist_app.html
10. DTS《197. Vhost/Virtio multiple queue qemu test plan》 — https://doc.dpdk.org/dts/test_plans/vhost_multi_queue_qemu_test_plan.html
11. DTS《167. vhost/virtio-user loopback with multi-queues test plan》 — https://doc.dpdk.org/dts/test_plans/loopback_multi_queues_test_plan.html

**DPDK mailing lists**
12. dpdk-dev《[PATCH 3/3] net/virtio: reject unsupported Rx multi queue modes》David Marchand 2019-10-10 — https://mails.dpdk.org/archives/dev/2019-October/146539.html
13. dpdk-stable same patch, Andrew Rybchenko 2019-10-09 — https://mails.dpdk.org/archives/stable/2019-October/017737.html
14. Related follow-up discussion (inbox archive) — https://inbox.dpdk.org/stable/97813cf0-78c1-8ff3-5b36-b3423a9141ce@solarflare.com/
15. LTS backport record (18.11.6, Kevin Traynor 2019-12-10) — https://inbox.dpdk.org/stable/20191210145937.32755-29-ktraynor@redhat.com/

**OVS / vhost-user**
16. OVS official《DPDK vHost User Ports》 — https://docs.openvswitch.org/en/latest/topics/dpdk/vhost-user/
17. Intel《OVS with DPDK: vHost User Multiqueue Configuration and Use》Ian Stokes 2016-07-12 — https://www.intel.cn/content/www/cn/zh/developer/articles/technical/configure-vhost-user-multiqueue-for-ovs-with-dpdk.html

**f-stack related practice**
18. F-Stack Issue #489 (2020-03-18, Closed, comment section not loaded) — https://github.com/F-Stack/f-stack/issues/489
19. StackOverflow 69104064 `Unsupported Rx multi queue mode 1` (2021-09) — https://stackoverflow.com/questions/69104064 ｜Chinese mirror https://cloud.tencent.com/developer/ask/sof/108809527
20. GitBook《helloworld》wintertee (2021-05-28) — https://wintertee.github.io/DPDK-related/f-stack/helloworld.html
21. Proxmox forum thread 145270 (2024-04 ~ 2024-12, unsolved) — https://forum.proxmox.com/threads/virtio-network-not-support-rss-receive-side-scaling-in-vm.145270/
22. 《f-stack 队列和进程关系》(2017-06, f-stack multi-process premised on hardware RSS) — https://blog.csdn.net/shaoyunzhe/article/details/73498685
23. 《使用 Intel 82599 VF 功能，在虚拟机里运行（f-stack）nginx》(2017-06, uses SR-IOV VF not virtio) — https://blog.csdn.net/shaoyunzhe/article/details/72843895
24. 《全用户态网络开发套件 F-Stack 架构分析》 — https://zhuanlan.zhihu.com/p/546932177

**Local code (for cross-check, not external sources)**
- `/data/workspace/dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c`: `:146-211` (set_multiple_queues_rss/auto), `:1840-1852` (max_virtqueue_pairs), `:2147-2152` (mq_mode validation), `:2207-2211` (RSS requested but unsupported), `:2331-2397` (dev_start issues VQ_PAIRS_SET), `:2660-2670` (no F_RSS → three fields 0)
- `/data/workspace/dpdk-stable-24.11.6/drivers/net/virtio/virtio_cvq.c:188-212` (`virtio_send_command`, `!cvq` returns -1)
- `/data/workspace/dpdk-stable-24.11.6/drivers/net/virtio/virtqueue.h:222-229` (`VIRTIO_NET_CTRL_MQ*` macros)
- `/data/workspace/dpdk-stable-24.11.6/doc/guides/rel_notes/release_21_11.rst:222-227` (virtio RSS introduced in 21.11)
- `/data/workspace/f-stack/lib/ff_dpdk_if.c:862-926` (nb_queues validation, RSS config under `flow_type_rss_offloads`)

---

## 9. Explicit Knowledge Boundaries (No Out-of-Bounds Conclusions)

1. **Whether this machine's host backend is vhost-net+tap or vhost-user cannot be determined by this research** (needs a hypervisor-side view). §1.1 and §1.3 are two different mechanisms and yield different conclusions.
2. **The direct bug report for "only queue 0 receives" was not found**; §3.2 is an indirect-evidence chain of the equivalent mechanism, not a substitute for direct evidence.
3. **No positive case of running f-stack multi-queue on virtio was found**; one cannot assert "impossible" from this, only "no precedent in public material, and mechanism-wise there are the four hard conflicts of §5.3".
4. **"Whether KNI must be disabled" has no source at all**; no conclusion drawn.
5. §2.1's ①②③ and part of §5.2 are **mechanism derivations** (based on already-cited code/doc chains), marked in the body, not mixed into literature citations.
