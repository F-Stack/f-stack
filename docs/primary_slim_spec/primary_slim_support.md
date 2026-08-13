F-Stack primary_slim: turning the primary single point of failure from an emergency into planned maintenance

1. What problem this solves

Getting straight to the point: primary_slim is a runtime switch introduced in F-Stack v2.0 (expected official release 2026.10) that solves the problem of the primary process being a single point of failure in DPDK multi-process mode.

First some background. F-Stack's standard multi-process mode is 1 primary + N secondaries, each process occupying one lcore running an independent FreeBSD stack instance. A crashed secondary can be restarted independently without affecting other processes' queues or established connections. But if the primary exits abnormally, that's a bigger deal — by DPDK's design the primary is the sole IPC server, secondary heap growth must be proxied by the primary, and all interrupts only fire in the primary, so the conventional wisdom is "if the primary dies the whole process group must restart and all connections are affected".

The requirement comes from upstream issue #1078 (https://github.com/F-Stack/f-stack/issues/1078). The author's idea is straightforward: isolate the primary to do only control-plane work like NIC queue setup, binding and initialization, move packet reception and downstream processing entirely to the secondaries, so the primary is less likely to crash and the impact on connections is smaller.

That's exactly what primary_slim does. The core value in one sentence:

【Note 1】primary_slim turns "primary crash → must immediately restart the whole group + about 1/N connections interrupted right away" into "primary crash → zero data-plane loss, business keeps running, a crashed secondary can be restarted in place, the cluster enters a control-plane degraded state, and a full group restart happens at a planned maintenance window".

In other words, it turns an emergency into planned maintenance, making the restart timing controlled instead of reactive.

It must be stated upfront what it does NOT promise, to avoid over-expectation:

- Does not promise "no restart at all" — the control-plane degraded state cannot be fixed in place; a full group restart is eventually still needed at a planned window
- Does not promise "saving one CPU core" — the slimmed primary still spins and occupies a full core unless idle sleep is enabled
- Does not promise the primary is no longer a structural single point — it only lowers the failure probability and shrinks the blast radius
- Does not promise no connection loss on a secondary crash — each process has an independent FreeBSD stack, there is no connection migration

2. Main use cases

2.1 Production deployments sensitive to primary single-point stability

If your business runs in multi-process mode and a primary crash drags down the whole group, primary_slim lets the primary exit with zero data-plane loss. Measured data (detailed later): after killing the slimmed primary, 12/12 established connections had zero interruption (26 probe rounds with no failure), and 12/12 new connections succeeded.

2.2 Needing control/data plane decoupling and a smaller failure blast radius

In multi-process mode, if the primary holds rx/tx queues, a crash turns those queues into orphan queues that no one polls, and all traffic landing on them gets black-holed. primary_slim makes the primary hold no queues at all, leaving all data-plane capability in the secondaries, so a primary exit takes away no data-plane capability.

【Note】Because of the limitation of the virtio-created tap, KNI is still handled by the primary process, so KNI fails when the primary crashes.

2.3 Having external daemons/orchestration and wanting layered recovery

Combined with an external daemon, you get: a crashed secondary restarts in place → a crashed primary enters degraded-state alerting → a full group restart happens at a planned window. This is far more composed than "primary dies → emergency full group restart".

2.4 Cases where it does not fit

In single-process multi-thread mode (thread_mode=1) there is no independent primary process, so this feature's semantics do not exist, and primary_slim is mutually exclusive with thread_mode (the config validation rejects it). If there is only 1 process (nb_procs < 2), slimming is meaningless and is also rejected by validation.

3. Architectural characteristics

3.1 Before/after comparison

Before (standard multi-process):

```
┌─────────────────────────────────────────────┐
│ primary (lcore0)                             │
│  ├─ NIC queue setup/binding/init             │
│  ├─ holds rx/tx queue0  ← also does data plane│
│  ├─ IPC server / heap proxy / interrupt      │
│  └─ runs a FreeBSD stack instance            │
│                                              │
│ secondary1 (lcore1)    secondary2 (lcore2)   │
│  ├─ rx/tx queue1        ├─ rx/tx queue2     │
│  └─ FreeBSD stack 1     └─ FreeBSD stack 2   │
└─────────────────────────────────────────────┘
  primary crash → its queue0 orphaned + control plane down
```

After (primary_slim=1):

```
┌─────────────────────────────────────────────┐
│ primary (lcore0)  —— control plane only, no queue│
│  ├─ NIC queue setup/binding/init             │
│  ├─ IPC server / heap proxy / interrupt      │
│  ├─ KNI init (virtio_user vdev only primary) │
│  └─ main loop only timer + msg_ring, no mbuf │
│                                              │
│ secondary1 (lcore1)    secondary2 (lcore2)   │
│  ├─ rx/tx queue0        ├─ rx/tx queue1     │
│  └─ FreeBSD stack 1     └─ FreeBSD stack 2   │
└─────────────────────────────────────────────┘
  primary crash → zero data-plane loss, secondaries keep serving
```

3.2 Why queues shrink naturally without producing orphan queues

This is the key to the whole approach and the most counter-intuitive finding of the research phase. The initial worry was "removing the primary from lcore_list would reduce the queue count by 1, shift queueids, and misalign the RSS reta", but line-by-line verification showed it does not hold:

- nb_queues comes from the port's lcore_list length, not nb_procs (lib/ff_dpdk_if.c:836)
- queueid is the index of this process's lcore within lcore_list, fully decoupled from proc_id (lib/ff_dpdk_if.c:487-491)
- set_rss_table() recomputes reta from the same nb_queues

So after removing the primary from lcore_list, the queue count, queueids, RSS reta and dispatch_ring all shrink consistently, and orphan queues naturally disappear at the code level. This is exactly the fundamental basis of the "reuse lcore_list" approach conceived by the maintainer (myself) in the research prompt.

3.3 The KNI data path (the most complex case)

With primary_slim=1 and KNI enabled, the data path has three lines, involving a critical race fix (detailed in 4.4). The final stable form:

```
ICMP request inbound:
  client → physical NIC(Port0) → secondary rx_burst(q0)
    → ff_kni_enqueue → KNI ring
    → primary kni_process_tx → rte_eth_tx_burst(Port1=virtio_user0)
    → veth0(tap) → kernel stack → generates ICMP reply

ICMP reply outbound (inject ring path):
  kernel → veth0 → virtio_user0
    → primary kni_process_rx → enqueue to kni_inject_rp ring
    → owner secondary sends on its own tx_queue
    → physical NIC → client
```

The core division of labor: the secondary handles data-plane packet reception and enqueues into the KNI ring, the primary exclusively does the virtio_user vdev TX/RX (because only the primary can legally operate the vdev), and KNI's received reply packets are forwarded via the kni_inject_rp ring to the owner secondary, which sends them out on its own queue. This both works around the DPDK hard constraint that "the secondary cannot operate the virtio_user vdev" and eliminates the cross-process TX queue sharing race.

4. Refactoring work and problems encountered

The following is rather dry; readers who don't need to dig into the implementation can skip this section and jump straight to section 5.

4.1 PoC phase: 3 lines of code validate the core thesis

Before formal project approval a minimal PoC was done, changing only 3 lines of code (_poc_primary_slim.patch, 2 hunks):

- lib/ff_dpdk_if.c:508-510: append `&& rte_eal_process_type() != RTE_PROC_PRIMARY` to the `rte_exit` condition, removing blocker B1 ("lcore %u has nothing to do")
- lib/ff_dpdk_if.c:535: remove the mbuf pool RX item's dependence on this process's queue count, removing blocker B3 (pool size going to zero)

The config was `lcore_mask=3` + `[port0] lcore_list=1` (primary's lcore0 not in the list).

3 lines of code + 1 config item validated the core thesis: after the slimmed primary crashes, 12/12 established connections with zero interruption and 12/12 new connections, with no performance regression. This directly shows why the change is worth doing — tiny cost, qualitative gain.

【Note 2】The PoC used `rte_eal_process_type() != RTE_PROC_PRIMARY` to unconditionally relax, only to minimize the diff. The formal implementation changed it to `primary_slim && RTE_PROC_PRIMARY` conditional gating to avoid affecting the default path.

4.2 Formal implementation: from "auto-derived" to "explicit switch + validation chain"

The PoC worked but was not rigorous (relied on "auto-derivation" rather than an explicit switch). The formal implementation added a complete switch and validation chain. Core commits are `1c28aaa2d` (M1) + `f7961b083` (M2~M4).

What was delivered:

- `[dpdk] primary_slim=0/1` explicit switch, default 0, zero regression when off
- When on, the primary early-returns in init_lcore_conf, allocates no rx/tx queues, and does not enter the packet reception loop
- Companion `primary_slim_idle_sleep` (default 1000us) to solve CPU spinning
- Three validations: primary lcore must not be in lcore_list (V2), mutually exclusive with thread_mode (V4), nb_procs >= 2 (V5)
- `ff_is_slim_primary()` API

4.3 Pitfall: CPU spinning

This is the first negative finding from testing. The slimmed primary holds no queues and receives no packets, but `ps -o pid,pcpu` still shows 99.8% occupying a full core. The reason is main_loop is still spinning tightly (running timer and msg_ring processing), and config.ini's idle_sleep=0 means no idle sleep.

【Note 3】primary_slim's benefit is stability, not CPU savings. If a user expects "slim = save a core", that expectation must be corrected. The formal implementation introduced primary_slim_idle_sleep (default 1000us), otherwise it burns a whole core in core-constrained deployments.

4.4 Pitfall: cross-process TX queue race in the KNI scenario

This is the trickiest problem found in the post-implementation phase, fixed in two stages.

Stage 1 (f23f1a464): with primary_slim=1 + KNI enabled, KNI's runtime TX/RX should be done by the primary (because the virtio_user vdev can only be operated by the primary). But with this change, the primary's kni_process_rx calls `rte_eth_tx_burst(Port0, queue_id=0)` to inject kernel reply packets into the physical NIC, while under primary_slim=1 queue0 belongs to the first secondary worker0 — two processes concurrently operating the same TX queue will corrupt the desc ring and leak mbufs. In DPDK multi-process, each TX queue can only be exclusively used by one process, with no process-level lock.

Stage 2 (f250ad1ea): introduce the `kni_inject_rp` shared ring to fully eliminate the race. The primary no longer TXs Port0 directly after receiving a KNI reply packet; instead it enqueues to the inject ring, and the owner secondary dequeues and sends with its own tx_queue_id. Two other approaches were ruled out during selection:

- Reserved dedicated queue (nb_queues+1, KNI uses the last queue): local virtio does not support RSS, so RETA cannot isolate the extra rx queue; the vhost backend distributes to all enabled qps, and an extra rx queue no one polls would fill its desc ring and cause backpressure — not viable
- rx!=tx unequal queues: virtio PMD allocates vqs by max(rx,tx), and an un-setup rx queue would be written by the backend causing a crash — not viable

The inject ring is the only viable path.

4.5 Pitfall: primary_slim=0 + owner_proc_id wrongly breaks KNI

Implementation commit 1c28aaa2d changed the KNI call condition from ff_kni_is_owner_thread() to ff_kni_is_runtime_owner(), but did not account for the fact that with primary_slim=0, owner_proc_id taking effect would cause the primary to no longer handle KNI, wrongly breaking the default mode. The fix (e075e534f) changed it to a conditional branch: use runtime-owner judgment when primary_slim, otherwise owner-thread judgment.

4.6 A leftover issue: primary exit cleanup actually has limited effect

Document 14 analyzes this specifically. The intent of skipping rte_eal_cleanup() was to protect shared resources that secondaries depend on, but line-by-line verification shows the actual effect is almost zero — hugepages use MAP_SHARED, so when the primary exits the kernel only munmaps its own mapping without affecting secondaries; the config file is not deleted in cleanup; the mp_socket unlink does not affect secondaries (they have their own fd).

What is really missing is notifying the secondaries to exit; after the primary exits, the secondaries become orphan processes entering the control-plane degraded state. But by design philosophy the primary should not exit normally, and this path is the "just in case" fallback.

【Note 4】This corrects document 10's claim of "avoid rte_eal_cleanup() tearing down shared resources" — verified against source, rte_eal_cleanup() does not actually tear down the shared resources secondaries depend on, so that claim is not entirely accurate. The real value of skipping cleanup is a conservative strategy: avoiding undefined behavior from operations like pthread_cancel during cleanup.

4.7 The issue's two judgments corrected by testing

This deserves its own section because it's the most valuable part of the whole research — the two initial assumptions were both shown inaccurate by testing:

- "Once the primary exits abnormally, the whole process group must restart" → partially false. The remaining processes keep serving, a crashed secondary can restart in place (as long as some process still holds /dev/uioX, uio refcnt >= 1), no immediate full group restart is needed. But the primary itself cannot be pulled back in place (a new primary fails with EBUSY, which is EAL's design intent), so a full group restart is still eventually needed.
- "All connections will be affected" → false. In traditional mode only the traffic hashed to the primary's queue is affected (about 1/2 with 2 processes, about 1/3 with 3 processes), and zero impact after slimming.
- "A crashed secondary can be restarted without affecting other processes" → true, verified by E2d.

5. Usage, configuration and results

5.1 Configuration

Add primary_slim in the [dpdk] section and owner_proc_id in the [kni] section of config.ini:

```ini
[dpdk]
lcore_mask=3              # primary(lcore0) + 1 secondary(lcore1)
primary_slim=1            # 0(default)=off, 1=primary slim
primary_slim_idle_sleep=1000   # default 1000us, avoid primary spinning; can be tuned since KNI still needs primary processing

[port0]
lcore_list=1              # key: primary's lcore0 not in the list, all queues go to secondary

[kni]
enable=1
method=reject
owner_proc_id=1           # primary_slim=1 + KNI, runtime owner secondary
```

Config validation automatically rejects three illegal combinations: primary_slim mutually exclusive with thread_mode, nb_procs must be >= 2, and the primary lcore must not be in lcore_list.

5.2 Startup

The startup method is unchanged, still start.sh managing multiple processes:

```bash
./start.sh -c config.ini -b ./example/helloworld
```

5.3 Results

Functional correctness (document 05 measured):

- After killing the slimmed primary, 12/12 established connections with zero interruption, 26 probe rounds with no failure
- After killing the slimmed primary, 12/12 new connections succeeded
- QPS: slim primary alive 122.4k (vs single-process baseline 122.3k, +0.08%); slim primary crashed 127.7k (+4.5%), both with 0 failed requests

KNI scenario (document 13 measured):

- ping 5/5 with 0% loss, rtt 0.512~1.329ms
- HTTP 200

Closure verification (document 15):

- Physical machine functional test and performance stress test passed
- Default standard multi-process mode 10+ minutes high-traffic regression stress with zero regression
- Multi-thread mode (thread_mode=1) 10+ minutes high-traffic regression stress with zero regression

5.4 Known limitations

- All testing was done in a virtio + igb_uio virtualized environment; physical machine functional/performance stress was added and passed, but VFIO's refcnt semantics and device running-state preservation are still marked as not fully verified
- The primary cannot be pulled back in place; after control-plane degradation a full group restart is needed at a planned window
- Graceful exit is untested; a primary exit is recommended to go through a hard kill rather than rte_eal_cleanup()
- Long-term stability (hour-scale) is not fully observed; 10+ minute high-traffic regression passed

Related reading:

- Full research and implementation docs: docs/primary_slim_spec/zh_cn/ (00-15, 16 documents)
- Closure report: docs/primary_slim_spec/zh_cn/15-结项报告.md
- Three-layer architecture: docs/zh_cn/F-Stack_Architecture_Layer1_System_Overview.md
- Issue: https://github.com/F-Stack/f-stack/issues/1078
