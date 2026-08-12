# 13. primary_slim=1 + KNI Enabled Data Path Breakage Fix

## 1. Problem Symptom

With `primary_slim=1` + KNI `enable=1` + `owner_proc_id=1`:

- HTTP (TCP/80 data plane) normal, `http_code=200`, ~1.3ms latency
- ping (ICMP, via KNI to kernel) 100% packet loss
- `veth0` interface exists but RX stats don't grow (packets not reaching tap device)

Control group `primary_slim=1` + KNI disabled: ping 0% loss, HTTP 200; problem only with KNI enabled.

## 2. Root Cause Identification

### 2.1 Initial Hypothesis (Disproven)

Hypothesized `primary_slim=1` causes primary to early return in `init_lcore_conf()` (`ff_dpdk_if.c:541-546`), skipping `init_kni()`.

**Disproven by testing**: Primary's f-stack lib log contains `VDEV_BUS: vdev_probe virtio_user0` and `ff_kni_alloc` output; `veth0` interface exists. `init_kni()` executes normally in primary.

### 2.2 True Root Cause: virtio_user vdev Multi-process TX Limitation

Secondary calls `rte_eth_tx_burst(Port 1 = virtio_user0)` returning success (32 packets), but packets **never actually reach veth0 (tap device)**.

`init_port_start()`'s `total_nb_ports *= 2` (including virtio_user Port 1) **only effective for PRIMARY** (`ff_dpdk_if.c:865-868`); secondary's `total_nb_ports = nb_ports` (physical ports only), secondary skips `dev_configure`/`queue_setup`/`dev_start` in port loop (`:1106-1108`).

Therefore secondary's Port 1 (virtio_user0) TX queue is uninitialized; `rte_eth_tx_burst` returns success but writes to invalid virtqueue; packets silently dropped. This is DPDK virtio_user PMD's multi-process limitation — virtio_user virtqueues cannot be shared by secondary processes without queue configuration.

### 2.3 Why HTTP Works but ping Fails

- **HTTP (TCP)**: reject mode, TCP matches `tcp_port` list → not via KNI → f-stack handles directly → works
- **ping (ICMP)**: ICMP not in filter cases → reject mode sends to `ff_kni_enqueue` → KNI ring → secondary `kni_process_tx` → `rte_eth_tx_burst(Port 1)` → lost

## 3. Phase 1 Fix: Primary Executes KNI Process

### 3.1 Core Approach

KNI vdev (virtio_user0) is created by primary (`rte_eal_hotplug_add`, DPDK hard constraint primary-only). Therefore KNI runtime TX/RX (`ff_kni_process`) should also be executed by primary.

Modified `main_loop()` KNI process gate: `primary_slim=1` → primary executes `ff_kni_process`.

### 3.2 Introduced Race Condition

This fix resolved KNI connectivity but introduced **cross-process TX queue0 race**:

`ff_kni_process(pid, 0, ...)`'s `kni_process_rx` calls `rte_eth_tx_burst(Port0, queue_id=0)` to inject kernel reply packets to physical NIC. But with `primary_slim=1`, primary has no queue; queue0 belongs to first secondary worker (`lcore_list[0]`).

Two processes concurrently operating same TX queue causes desc ring corruption, mbuf leaks. DPDK multi-process model: each TX queue must be exclusively used by one process; no process-level lock protection.

## 4. Phase 2 Fix: Inject Ring Eliminates Race

### 4.1 Solution Selection

| Solution | Approach | Feasibility |
|----------|---------|-------------|
| A. ring forwarding | primary doesn't directly TX Port0; enqueues to dedicated ring; owner secondary dequeues and TX with own queue | ✓ Feasible |
| B. reserved dedicated queue | nb_queues+1, KNI uses last queue, RSS doesn't distribute to it | ✗ Local virtio doesn't support RSS; can't isolate extra rx queue |
| C. rx!=tx | rx=N, tx=N+1 | ✗ virtio PMD allocates vq by max(rx,tx); unconfigured rx queue gets written by backend → crash |

Solution B relies on RSS RETA to isolate extra rx queue. Local virtio_user (vhost-kernel backend) doesn't report `VIRTIO_NET_F_RSS`; `flow_type_rss_offloads=0`; f-stack skips RSS config. Without RSS, vhost backend distributes to all enabled qps; can't prevent traffic to extra rx queue → desc ring full → backpressure. Solution B infeasible.

Solution A is the only feasible race elimination approach.

### 4.2 Inject Ring Mechanism

Added `kni_inject_rp[port_id]` shared ring for primary→owner secondary KNI RX packet forwarding:

```
kni_process_rx (primary):
  rx from veth0 → enqueue to kni_inject_rp

ff_kni_inject_process (owner secondary):
  dequeue from kni_inject_rp → rte_eth_tx_burst(Port0, own_queue)
```

Primary no longer directly calls `rte_eth_tx_burst(Port0, q0)`, eliminating cross-process queue sharing.

### 4.3 Code Changes

**`lib/ff_dpdk_kni.c`**:
1. New global `kni_inject_rp` array, allocated in `ff_kni_init` (same pattern as `kni_rp`)
2. Create/lookup `kni_inject_rp[port_id]` ring in `ff_kni_alloc` (primary create, secondary lookup)
3. `kni_process_rx`: when `primary_slim && PRIMARY`, redirect to inject ring instead of direct `rte_eth_tx_burst`
4. New `ff_kni_inject_process`: owner secondary dequeues + tx_burst to Port0

**`lib/ff_dpdk_kni.h`**: Declare `ff_kni_inject_process`

**`lib/ff_dpdk_if.c`**: `main_loop()` KNI section adds owner secondary inject path

### 4.4 Zero Regression Guarantee

| Scenario | Behavior | Regression Risk |
|----------|----------|----------------|
| `primary_slim=0` | `kni_process_rx` takes original path (direct tx_burst); inject ring exists but unused | Zero |
| `primary_slim=1` + KNI disabled | `enable_kni=0`, entire KNI block skipped | Zero |
| `primary_slim=1` + KNI enabled | primary redirects to inject ring, owner secondary drains | Fix path |

## 5. Test Verification

### 5.1 KNI Enabled + primary_slim=1 (After inject ring fix)

Config: `primary_slim=1`, `[kni] enable=1 method=reject owner_proc_id=1`, `lcore_list=1`

From `<CLIENT_IP>`:
```
ping -c 5 <DPDK_NIC_IP>
5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/mdev = 0.512/0.895/1.329/0.268 ms

curl http://<DPDK_NIC_IP>/
http_code=200 time=0.000665s
```

ICMP (via KNI inject ring) and HTTP (f-stack direct) both normal.

### 5.2 KNI Disabled + primary_slim=1 (Regression test)

Config: `primary_slim=1`, `[kni] enable=0`, `lcore_list=1`

```
ping -c 3 <DPDK_NIC_IP>
3 packets transmitted, 3 received, 0% packet loss

curl http://<DPDK_NIC_IP>/
http_code=200 time=0.001347s
```

Zero regression confirmed.

### 5.3 Test Environment Note

Local `<KERNEL_NIC_IP>` (eth1) and veth0 are on same /21 subnet; routing conflict causes kernel `rp_filter` to drop ICMP replies. Test requires `rp_filter=0`:

```bash
sysctl -w net.ipv4.conf.veth0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
```

This is a test environment workaround, not part of the code fix. Production environments typically have veth0 and eth1 on different subnets, no such issue.

## 6. Post-Fix Data Path (primary_slim=1 + KNI Enabled)

```
ICMP request inbound:
  client → physical NIC (Port0) → secondary rx_burst(q0)
    → ff_kni_enqueue → KNI ring
    → primary kni_process_tx: ring dequeue
    → rte_eth_tx_burst(Port1=virtio_user0, q0)
    → veth0(tap) → kernel stack → generates ICMP reply

ICMP reply outbound (inject ring path):
  kernel → veth0(tap) → virtio_user0
    → primary kni_process_rx: rte_eth_rx_burst(Port1, q0)
    → rte_ring_enqueue_burst(kni_inject_rp)    [primary doesn't directly TX Port0]
    → owner secondary ff_kni_inject_process:
      rte_ring_dequeue_burst(kni_inject_rp)
      rte_eth_tx_burst(Port0, own_queue)       [secondary's own queue]
    → physical NIC → client
```

Key points:
- secondary handles `ff_kni_enqueue` (data plane receive → enqueue KNI ring)
- primary handles `ff_kni_process` (virtio_user0 TX/RX, as vdev can only be legally operated by primary)
- KNI RX packets forwarded via `kni_inject_rp` ring to owner secondary, which TX with its own queue
- Eliminates cross-process TX queue0 sharing race

## 7. Modified Files

| File | Change Type | Description |
|------|------------|-------------|
| `lib/ff_dpdk_kni.c` | MODIFY | New `kni_inject_rp` array/ring, `ff_kni_inject_process` function; `kni_process_rx` redirects to inject ring in primary_slim |
| `lib/ff_dpdk_kni.h` | MODIFY | Declare `ff_kni_inject_process` |
| `lib/ff_dpdk_if.c` | MODIFY | `main_loop()` KNI section: primary executes `ff_kni_process`; owner secondary executes `ff_kni_inject_process` |

## 8. Debugging Method

Key evidence for identifying virtio_user multi-process TX issue:

1. `veth0` RX stats don't grow → TX path (f-stack → veth0) broken
2. `kni_process_tx: tx_burst=32` but `veth0` RX unchanged → `rte_eth_tx_burst` "false success"
3. secondary's `total_nb_ports=1` (excludes Port 1) → secondary didn't configure virtio_user queue
4. primary's `total_nb_ports=2` (includes Port 1) → primary is legal virtio_user operator

Race identification:
5. `ff_kni_process(pid, 0, ...)` has queue_id hardcoded to 0
6. With `primary_slim=1`, queue0 belongs to secondary worker0, not primary
7. primary's `kni_process_rx` calls `rte_eth_tx_burst(Port0, q0)` → cross-process queue sharing
8. DPDK PMD `tx_burst` has no process-level lock → desc ring corruption risk
