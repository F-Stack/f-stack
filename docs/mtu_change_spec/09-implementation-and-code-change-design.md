# Full MTU Modification Support — Implementation and Code Change Design

## 1. Implementation Principles

1. Do not modify `freebsd/net/if_ethersubr.c`; break the traditional 1500 upper bound in the `lib/ff_veth.c` adaptation layer.
2. FreeBSD/veth layer must not directly depend on `rte_eth*`; all DPDK control encapsulated in `ff_dpdk_if.c`.
3. Startup config must complete in the correct order of `rte_eth_dev_configure()`/`rte_eth_dev_start()`.
4. Dynamic modification (primary) must have in-process control-plane serialization, dataplane quiesce, and failure rollback; no cross-process sync.
5. `large` and `scatter` are explicit policies; no implicit downgrade.

## 2. M1: Configuration and Data Structures

### 2.1 `lib/ff_config.h`

Anchors:
- `struct ff_port_cfg`: `ff_config.h:163-204`;
- `struct ff_config.dpdk`: anonymous embedded struct, `ff_config.h:258-313`.

Changes:
- Add `enum ff_mbuf_mode`;
- `dpdk` adds `mtu_enable/max_mtu/mbuf_mode`;
- `ff_port_cfg` adds `uint16_t mtu`.

For minimal diff, this task does not require extracting the anonymous `dpdk` struct into a named type; refactor separately later if multiple modules need to pass full config directly.

### 2.2 `lib/ff_config.c`

- `ff_default_config()` (L1366) sets `mtu_enable=0,max_mtu=9000,mbuf_mode=large`.
- `[dpdk]` keys parsed by `ini_parse_handler()`'s `MATCH` chain (from L976); no standalone `dpdk_cfg_handler()` exists — the implementation must not reference nonexistent functions.
- `port_cfg_handler()` (L542) sets `mtu=1500` for enabled ports after `calloc`.
- Add strict parsing helpers, no `atoi()`.
- `ff_check_config()` adds cross-field validation.

Pseudocode:

```c
if (MATCH("dpdk", "mtu_enable"))
    return parse_bool(value, &cfg->dpdk.mtu_enable);
else if (MATCH("dpdk", "max_mtu"))
    return parse_u16(value, ETHERMTU, UINT16_MAX, &cfg->dpdk.max_mtu);
else if (MATCH("dpdk", "mbuf_mode"))
    return parse_mbuf_mode(value, &cfg->dpdk.mbuf_mode);
```

`ff_check_config()` must perform mode-dependent cross-validation: large's `ff_mtu_data_room_size(max_mtu)` returning ERANGE due to uint16 pool API limit fails before startup; scatter does not allocate that room, but validates PMD frame capability at port probe. `mtu_enable=1` with KNI/kernel coexist enabled simultaneously returns EOPNOTSUPP semantics and advises disabling one.

Error messages must include section/key/value and valid range, but no unrelated config.

## 3. M2: mbuf Pool Dual Mode

### 3.1 Existing Order

`ff_dpdk_if.c` current order:
- `init_mem_pool()`: L385-452; pool creation L427-430;
- then `init_port_start()`: from L650;
- port capability `rte_eth_dev_info_get()`: L702;
- configure: L856; queue setup: L878/L886; start: L918.

Thus pool creation precedes per-port capability probe. Global `max_mtu/mbuf_mode` can determine pool size, but each PMD's capability must be strictly re-validated at port config stage.

### 3.2 large Mode data room

Unified helper:

```c
static int
ff_mtu_data_room_size(uint16_t max_mtu, uint16_t *out)
{
    size_t frame = (size_t)max_mtu + RTE_ETHER_HDR_LEN +
        2 * RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN;
    size_t room = RTE_PKTMBUF_HEADROOM + frame;
    room = RTE_ALIGN_CEIL(room, RTE_CACHE_LINE_SIZE);
    if (room > UINT16_MAX)
        return -ERANGE;
    *out = (uint16_t)room;
    return 0;
}
```

- `rte_pktmbuf_pool_create(..., data_room_size, ...)` uses this result. This param is uint16; large mode must call this helper at config validation; `max_mtu=65535` must deterministically fail, not truncate.
- Legacy pool API param `RTE_MBUF_DEFAULT_BUF_SIZE=2176` (128B headroom), usable `RTE_MBUF_DEFAULT_DATAROOM=2048`.
- Before large memory allocation, log estimate: `nb_mbuf * data_room_size`, check multiplication overflow.
- Do not confuse frame overhead with IP MTU; `max_mtu` is L3 MTU.

### 3.3 scatter Mode

- Pool retains `RTE_MBUF_DEFAULT_BUF_SIZE`.
- Port capability validation:

```c
if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) ||
    !(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS))
    return -ENOTSUP;
port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;
port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
```

- `rxq_conf.offloads` and `txq_conf.offloads` already inherit from port mode at L877/L885; no need to repeat bare assignments.
- Current RX already traverses `rte_mbuf->next` (`ff_dpdk_if.c:1557-1588`); TX already creates multi-segment rte_mbuf (L2209-2249, L2333-2364), but the implementation task must still verify item by item: `pkt_len/nb_segs/data_len/next` correct, partial allocation failure releases all, zero-copy ext mbuf lifecycle correct.

### 3.4 large TX Single-Segment and Zero-Copy

Existing copy/raw TX paths segment by fixed `RTE_MBUF_DEFAULT_DATAROOM`; large mode must change to fill by each new mbuf's actual `rte_pktmbuf_tailroom()`. For a 9000 MTU frame fitting in large room, normal copy/raw paths must produce `nb_segs==1`, or large mode loses design value and still depends on MULTI_SEGS.

page-array/zero-copy paths may naturally form multi-segment:
- When PMD supports `RTE_ETH_TX_OFFLOAD_MULTI_SEGS`, allow multi-segment and verify segment count/refcount lifecycle;
- When PMD does not support, large mode must fall back to a single large mbuf copy (not switch to scatter), or return EOPNOTSUPP on that zero-copy API; the implementation must select and unit-test, recommend copy fallback to keep functionality available.
- scatter mode always requires TX_MULTI_SEGS.

## 4. M2: Port Capability and Startup MTU

### 4.1 DPDK 24.11 Capability Fields

Current headers confirmed:
- `rte_eth_rxmode.mtu`: `dpdk/lib/ethdev/rte_ethdev.h:427-430`;
- `dev_info.min_mtu/max_mtu/max_rx_bufsize/max_rx_pktlen`: L1778-1790;
- scatter/multi-segs: L1562/L1612;
- get/set MTU: L3637/L3656.

`max_rx_bufsize` is single RX buffer capability excluding rte_mbuf headroom; not equivalent to port MTU; large compares `data_room_size - RTE_PKTMBUF_HEADROOM` with frame bytes/device buffer capability. `max_rx_pktlen` is L2 frame length upper bound; must compare with `L3 MTU + Ethernet/VLAN/FCS overhead`, not directly with L3 MTU; pool alignment/padding must not cause false rejection.

### 4.2 `init_port_start()` Insertion Point

After `rte_eth_dev_info_get()` succeeds, before `rte_eth_dev_configure()`:

```c
requested = pconf->mtu;
frame_bytes = ff_mtu_frame_bytes(requested, vlan_depth);
if (requested < dev_info.min_mtu || requested > dev_info.max_mtu)
    return -EINVAL;
if (requested > ff_global_cfg.dpdk.max_mtu ||
    frame_bytes > dev_info.max_rx_pktlen)
    return -EINVAL;
if (mbuf_mode == FF_MBUF_MODE_LARGE &&
    frame_bytes > ff_large_usable_room(data_room_size))
    return -EINVAL;
port_conf.rxmode.mtu = requested;
configure_mtu_offloads(&port_conf, &dev_info, mbuf_mode);
```

At startup prefer `port_conf.rxmode.mtu`; call `rte_eth_dev_set_mtu()` and readback while port is not yet started, to cover PMD differences in handling the configure field:

```c
ret = rte_eth_dev_configure(...);
if (ret == 0)
    ret = rte_eth_dev_set_mtu(port_id, requested);
if (ret == 0)
    ret = rte_eth_dev_get_mtu(port_id, &actual);
if (ret || actual != requested)
    fail_port_init();
```

Call order must be before `rte_eth_dev_start()` (L918); some PMDs return `-EBUSY` when started.

### 4.3 virtio Features

Current DPDK virtio PMD:
- `virtio_mtu_set()`: `drivers/net/virtio/virtio_ethdev.c:548`;
- `VIRTIO_NET_F_MTU` capability: `virtio_ethdev.h:30`;
- `dev_info.max_mtu`: `virtio_ethdev.c:2630`;
- scatter/multi-segs capability: L2635/L2648.

Subsequent tests must read actual `dev_info`; must not assert the current backend supports 9000 just because source has the capability.

## 5. M3: DPDK MTU Control Encapsulation

### 5.1 Public Interface

Add interfaces in `ff_dpdk_if.h` that do not expose DPDK types (see `08`). `ff_dpdk_if_set_mtu()` internally gets `port_id` from opaque context (context currently saves that field at `ff_memory.h:60-65`). Interface returns DPDK-style negative errno; `ff_veth_ioctl()` must convert to FreeBSD positive errno via unified `ff_dpdk_errno_to_bsd()`: `ENOTSUP→EOPNOTSUPP`, unknown→`EIO`; must not return negative values directly to ioctl.

### 5.2 Runtime Fast Path and EBUSY

First try direct `rte_eth_dev_set_mtu()` on primary:
- Success: readback verify, done;
- `-EBUSY`: enter explicit quiesce/stop/set/start state machine;
- `-ENOTSUP/-EINVAL/-EIO/-ENODEV`: convert as-is and keep old state.

DPDK docs explicitly state `set_mtu` may return `-EBUSY` (`rte_ethdev.h:3647-3655`); virtio/MLX5 may succeed at runtime, i40e/ice may require stopped. Must not assume all PMDs are the same.

### 5.3 stop/set/start State Machine

Add per-port control state and lock:

```c
enum ff_port_ctrl_state {
    FF_PORT_RUNNING,
    FF_PORT_QUIESCING,
    FF_PORT_RECONFIGURING,
    FF_PORT_FAILED,
};
```

Flow (primary process only; quiesce scope limited to this primary's lcores, not other procs):
1. CAS/lock port from RUNNING to QUIESCING; reject in-process concurrent MTU modification;
2. Notify all lcores of this primary to stop rx/tx on that port;
3. flush `tx_mbufs`; wait for in-flight burst completion with timeout;
4. primary executes `rte_eth_dev_stop()`;
5. `rte_eth_dev_set_mtu(new)` + `get_mtu` readback;
6. `rte_eth_dev_start()`; restore promiscuous/RSS etc. that PMD may not preserve;
7. Resume lcore dataplane; state RUNNING.

Failure rollback: if set/start fails, try stopped-state restore old MTU and start; if still fails, state `FF_PORT_FAILED`, interface stays down, return `EIO` with high-priority log. Must not recover dataplane in a broken state.

## 6. M3: ff_veth ioctl Transaction

`ff_veth_softc` (`ff_veth.c:69-93`) already has `host_ctx`; no need to copy `port_id`. At startup, `ff_veth_setup_interface()` must set config `if_mtu` after `ether_ifattach()` returns, before `ff_veth_setaddr()` and any route/VLAN creation, so address/MSS/routing use the correct value from first visibility. Add `SIOCSIFMTU` in `ff_veth_ioctl()` (L234-253):

```c
case SIOCSIFMTU:
    mtu = ((struct ifreq *)data)->ifr_mtu;
    if (!ff_global_cfg.dpdk.mtu_enable) {
        error = ether_ioctl(ifp, cmd, data);
        break;
    }
    error = ff_veth_validate_mtu(sc, mtu);
    if (error != 0)
        break;
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        dpdk_ret = ff_dpdk_if_set_mtu(sc->host_ctx, mtu);
        error = dpdk_ret < 0 ? ff_dpdk_errno_to_bsd(-dpdk_ret) : 0;
        if (error == 0)
            if_setmtu(ifp, mtu);      /* primary: hardware first, then commit software */
    } else {
        if_setmtu(ifp, mtu);          /* secondary: software only, no DPDK */
    }
    break;
```

Per-process-role distinction (`rte_eal_process_type()`):
- primary: first `ff_dpdk_if_set_mtu()` (hardware, including EBUSY→stop/set/start and rollback), then `if_setmtu()` (software) on success — **hardware first, then commit software**.
- secondary: only `if_setmtu()` (software); does not call `ff_dpdk_if_set_mtu`／does not touch DPDK port control. Hardware MTU is solely primary's responsibility.

Generic `if.c:2729-2755` executes `if_notifymtu()` after the driver ioctl returns success and MTU changed; the driver layer must not notify redundantly.

Only `mtu_enable==0` continues via `ether_ioctl()` legacy path. After feature enablement, all valid MTU for primary (including 1500, 1400, and fallback from 9000) must set hardware first then software, avoiding in-process software MTU fallback while hardware stays jumbo; no cross-process transactions. Multi-process consistency is achieved by each process setting independently (see Section 7).

## 7. M4: Multi-Process MTU Consistency (No IPC Coordination)

### 7.1 Static Consistency Model

This phase does not implement cross-process MTU IPC transaction coordination. Multi-process MTU consistency is achieved by "each f-stack process independently calling MTU set once at startup/runtime"; no inter-process communication, no transactions, no message rings/pools:

- Only DPDK primary can execute port stop/config/start and `rte_eth_dev_set_mtu`.
- primary receiving `SIOCSIFMTU`: set hardware MTU (including EBUSY state machine and rollback), then set in-process software MTU on success.
- secondary receiving `SIOCSIFMTU`: only set in-process software MTU; does not touch any DPDK port control interface.
- Current tool ioctl via `FF_IOCTL` only sends to the single proc specified by `-p` (`tools/compat/ioctl.c:101-146`); this phase takes this as-is: must execute once per proc.

### 7.2 Usage Convention and Known Constraints

- App/Ops must trigger `SIOCSIFMTU` once per f-stack process (e.g., run `tools/sbin/ifconfig` once per `-p` target).
- A proc not set keeps its software MTU view at the old value; not addressed by IPC this phase, a known constraint.
- Hardware MTU is shared state, solely primary's responsibility; only needs to be set once on primary.

### 7.3 Why No IPC Coordination This Phase

Scope convergence decision: cross-process request/prepare/commit/ack two-phase transactions, dedicated message rings/pools, coordinators and other IPC mechanisms have high complexity and risk; completely not done this phase, deferred to a separate milestone. The static "each process sets once" model satisfies consistency needs for now.

### 7.4 bond/vdev and KNI

- bond/vdev handled by primary in-process: first collect all member capabilities, upper bound takes the minimum; set_mtu for each member sequentially; reverse rollback on any failure (primary in-process operation, no cross-process transaction).
- vdev determined by its PMD `dev_info`/`set_mtu`; must not hardcode device name checks.
- This phase does not implement KNI/kernel-coexist interface linkage: `ff_check_config()` detects `mtu_enable=1` with KNI/kernel coexist enabled simultaneously and returns `EOPNOTSUPP` semantics with disable advice, preventing kernel interface and DPDK/ifnet MTU inconsistency.

## 8. M5: Logging and Observability

Startup log:

```text
port=0 mtu_enable=1 requested_mtu=9000 max_mtu=9000 mbuf_mode=large data_room=...
```

Runtime success:

```text
port=0 mtu change old=1500 new=9000 mode=large path=runtime
```

Failure:

```text
port=0 mtu change failed old=1500 new=9000 stage=set_mtu dpdk_errno=-16 rollback=success
```

Use `ff_log()`; no per-packet printing on hot path.

## 9. Unit Test Seams

- `test_ff_config.c`: defaults, valid config, invalid mode, non-numeric/negative/overflow, `port.mtu>max_mtu`, feature disabled but requesting jumbo.
- `test_ff_dpdk_if.c`: wrap `rte_eth_dev_set_mtu/get_mtu/stop/start`, cover primary set_mtu state machine success, `EBUSY`→stop/set/start, `ENOTSUP`, readback mismatch, rollback success/failure.
- veth ioctl tests: distinguish primary/secondary branches — primary mock `ff_dpdk_if_set_mtu`, prove failure does not change `if_mtu`, software committed only on success; secondary only changes `if_mtu` and does not call `ff_dpdk_if_set_mtu`.
- multi-seg tests: chain length, `pkt_len/nb_segs/data_len`, partial allocation failure, release counts.

## 10. Explicit Prohibitions

- Do not include `rte_ethdev.h` in `ff_veth.c`.
- Do not change `if_mtu` first then try hardware setting.
- Do not silently fall back to the other mode due to PMD not supporting large/scatter.
- Do not allow secondary to directly stop/start the shared port.
- Do not modify `freebsd/net/if_ethersubr.c` to lift the global upper bound.
