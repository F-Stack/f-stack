# Full MTU Modification Support — Interface and Config Design

## 1. Configuration Interface

### 1.1 `[dpdk]` Global Config

```ini
[dpdk]
# Existing configurations omit this key and retain legacy MTU behavior.
mtu_enable=1
# Upper bound for runtime MTU changes; defaults to 9000 when mtu_enable=1.
max_mtu=9000
# large: one jumbo-capable mbuf; scatter: standard mbufs chained together.
mbuf_mode=large
```

| Config Item | Type | Default | Valid Values | Description |
|---|---|---|---|---|
| `mtu_enable` | bool/int | `0` | `0`,`1` | MTU/jumbo feature master switch; old config zero regression |
| `max_mtu` | uint16 | `9000` when enabled | Mode-dependent: large must satisfy derived uint16 `data_room_size`; scatter up to 65535; both must satisfy PMD/frame capability | Runtime upper bound and pool capacity basis |
| `mbuf_mode` | enum/string | `large` when enabled | `large`,`scatter` | mbuf carrying approach; invalid string fails startup |

Design note: `max_mtu=9000` is only the default within the `mtu_enable=1` feature scope. When `mtu_enable=0`, `RTE_MBUF_DEFAULT_BUF_SIZE` is retained to avoid memory spikes for old deployments.

### 1.2 `[portN]` Config

```ini
[port0]
# Initial protocol-stack and DPDK-port MTU; defaults to 1500.
mtu=9000
```

| Config Item | Default | Constraint |
|---|---|---|
| `mtu` | `1500` | `IF_MINMTU <= mtu <= dpdk.max_mtu`; must also satisfy PMD `min_mtu..max_mtu` |

- `mtu_enable=0` and `mtu>1500` configured: config parse fails, prompt to enable MTU feature first.
- `mtu_enable=1` and `mtu` default: port starts at 1500, but pool has reserved capacity for runtime increase per selected mode.
- large mode computes `data_room_size = align(HEADROOM + max_mtu + L2_overhead)` at config validation; result exceeding `UINT16_MAX` must deterministically fail, so `max_mtu=65535` is unusable in large mode. scatter mode does not create large room and proceeds to PMD `max_mtu/max_rx_pktlen` validation.
- Unified frame formula: `frame_bytes = L3_MTU + Ethernet header + configured VLAN/QinQ overhead + FCS`. large compares `frame_bytes` with `data_room_size - RTE_PKTMBUF_HEADROOM`; `max_rx_pktlen` compared with frame_bytes; must not compare pool params including headroom/alignment directly against device frame capability.
- Multi-port allows different initial `mtu`, but shared pool large mode allocates by global `max_mtu`.

## 2. C Data Structures

### 2.1 `lib/ff_config.h`

Add to `struct ff_config.dpdk` (currently `ff_config.h:260-313`):

```c
enum ff_mbuf_mode {
    FF_MBUF_MODE_LARGE = 0,
    FF_MBUF_MODE_SCATTER,
};

int mtu_enable;
uint16_t max_mtu;
enum ff_mbuf_mode mbuf_mode;
```

Add to `struct ff_port_cfg` (currently `ff_config.h:163`):

```c
uint16_t mtu;
```

### 2.2 Effective Config and Capability Snapshot

Parsed values and PMD capability values should be separated. Suggest adding to `struct ff_dpdk_if_context` (`ff_memory.h:60-65`):

```c
uint16_t mtu;
uint16_t max_mtu;
enum ff_mbuf_mode mbuf_mode;
```

If the implementation needs to record device capability, build a read-only snapshot separately to avoid exposing `struct rte_eth_dev_info` to the FreeBSD adaptation layer:

```c
struct ff_mtu_capability {
    uint16_t min_mtu;
    uint16_t max_mtu;
    uint32_t max_rx_pktlen;
    uint32_t max_rx_bufsize;
    bool rx_scatter;
    bool tx_multi_segs;
};
```

## 3. Config Parsing API

### 3.1 Defaults

`ff_default_config()` (`ff_config.c:1366`) defines:

```c
cfg->dpdk.mtu_enable = 0;
cfg->dpdk.max_mtu = 9000;
cfg->dpdk.mbuf_mode = FF_MBUF_MODE_LARGE;
```

`struct ff_port_cfg` initializes `mtu=1500` after allocation. Note that `port_cfg_handler()` batch-`calloc`s on first `[portN]` (`ff_config.c:550-567`); set default MTU for each enabled port within that init loop.

### 3.2 Strict Parsing

Do not use `atoi()` for new numeric parsing. Add internal helpers:

```c
int ff_parse_u16(const char *value, uint16_t min, uint16_t max,
    uint16_t *out);
int ff_parse_mbuf_mode(const char *value, enum ff_mbuf_mode *out);
```

Requirements:
- Use `strtoul()` and check `errno`, `endptr`, range;
- Reject empty, negative, trailing chars, overflow;
- Config parse errors return 0 so `ini_parse()` fails, rather than silently using defaults.

`ini_parse_handler()` (`ff_config.c:976-1023`) adds `[dpdk]` branch; `port_cfg_handler()` (`ff_config.c:542`) adds `mtu` branch.

### 3.3 Cross-Field Validation

After fully parsing config, run a standalone `ff_validate_mtu_config()` to avoid config-order effects:

```c
if (!mtu_enable && any_port_mtu > ETHERMTU) error;
if (mtu_enable && max_mtu < ETHERMTU) error;
if (port.mtu < IF_MINMTU || port.mtu > max_mtu) error;
if (mtu_enable && mbuf_mode == LARGE &&
    ff_mtu_data_room_size(max_mtu, &room) != 0) error;
if (mtu_enable && kernel_coexist_or_kni_enabled) return EOPNOTSUPP;
```

PMD capability validation must be after `rte_eth_dev_info_get()`; do not speculate hardware capability during pure config parsing.

## 4. DPDK Layer Interface

### 4.1 Layering Principle

`ff_veth.c` already includes `ff_dpdk_if.h` but must not call `rte_eth_dev_*` directly. DPDK details are encapsulated in `ff_dpdk_if.c`, exposing a stable interface to `ff_veth`:

```c
int ff_dpdk_if_get_mtu(struct ff_dpdk_if_context *ctx, uint16_t *mtu);
int ff_dpdk_if_set_mtu(struct ff_dpdk_if_context *ctx, uint16_t mtu);
int ff_dpdk_if_get_mtu_capability(struct ff_dpdk_if_context *ctx,
    struct ff_mtu_capability *cap);
```

- Return values use negative errno style (consistent with DPDK); `ff_veth_ioctl()` must convert to FreeBSD positive errno via a unified helper: `ret < 0 ? ff_dpdk_errno_to_bsd(-ret) : 0`. Known errno preserves semantics, `ENOTSUP` maps to `EOPNOTSUPP`, unknown values normalize to `EIO`; must not return negative values to FreeBSD ioctl.
- `ff_dpdk_if_set_mtu()` is **primary-only**; secondary does not call this interface (does not touch any DPDK port control interface). The implementation handles in-primary dynamic stop/set/start, readback, and hardware rollback.
- `ff_veth_ioctl()` only handles ifnet semantics and software state transactions; not aware of PMD details.

### 4.2 Multi-Process MTU Setting Model (No IPC)

This phase does not implement cross-process MTU transaction coordination; no inter-process communication, no transactions, no IPC message rings/pools. Multi-process consistency is achieved by "each process sets once":

- primary: within `ff_veth_ioctl(SIOCSIFMTU)`, first `ff_dpdk_if_set_mtu()` to set hardware MTU (including EBUSY→stop/set/start and failure rollback), then `if_setmtu()` to set software MTU on success.
- secondary: within `ff_veth_ioctl(SIOCSIFMTU)`, only `if_setmtu()` to set software MTU; does not call `ff_dpdk_if_set_mtu()`／`rte_eth_dev_set_mtu`／stop/start.
- Each process triggers `SIOCSIFMTU` once independently (app/Ops usage convention); a proc not set keeps its software MTU view at the old value (known constraint).

Role determination uses `rte_eal_process_type() == RTE_PROC_PRIMARY`.

## 5. FreeBSD ifnet Interface

### 5.1 `ff_veth_ioctl()`

Add `case SIOCSIFMTU`:

```c
case SIOCSIFMTU:
    error = ff_veth_change_mtu(sc, ((struct ifreq *)data)->ifr_mtu);
    break;
```

`ff_veth_change_mtu()` handles: range validation → per-process-role processing (primary: `ff_dpdk_if_set_mtu()` set hardware, then `if_setmtu()` on success; secondary: `if_setmtu()` only, no DPDK) → no cross-process coordination. Runtime ioctl's `if_notifymtu()` is triggered uniformly by generic `freebsd/net/if.c:2729-2755` after the driver returns success; the driver must not notify redundantly. At startup, set initial `if_mtu` after `ether_ifattach()`, before `ff_veth_setaddr()` and any route/VLAN creation. Do not modify `freebsd/net/if_ethersubr.c`.

### 5.2 `SIOCGIFMTU`

Preserve existing `if.c` reading `ifp->if_mtu` semantics. In debug gates, additionally call `ff_dpdk_if_get_mtu()` to compare hardware value; normal queries should not access PMD every time to avoid hot-path control-plane calls.

## 6. ff_api Assessment

This feature does not add a `ff_set_mtu()` public API. Reasons:
- Linux/FreeBSD already have standard `ioctl(SIOCSIFMTU)` semantics;
- `tools/sbin/ifconfig` and existing apps need no special API;
- A new API widens the maintenance surface and bypasses the standard ioctl path.

If a socket-less management API is needed later, it should reuse the same per-process-role setting path (primary soft+hard, secondary soft only); must not create an inconsistent path.

## 7. Return Codes

| Scenario | External errno |
|---|---|
| MTU exceeds config/device upper bound | `EINVAL` |
| PMD does not support set_mtu or scatter/multi-segs | `EOPNOTSUPP` |
| Cannot modify while running and stop/start coordination fails | `EBUSY` |
| Device removed | `EIO`/`ENODEV` (preserve DPDK meaning) |
| Rollback failure, in-process soft/hard state may be inconsistent | `EIO`, with high-priority log |

## 8. Config Examples

### large mode

```ini
[dpdk]
mtu_enable=1
max_mtu=9000
mbuf_mode=large

[port0]
mtu=9000
```

### scatter mode

```ini
[dpdk]
mtu_enable=1
max_mtu=9000
mbuf_mode=scatter

[port0]
mtu=9000
```

### Backward Compatibility

Without the above new config, identical to current version: MTU 1500, pool API param `RTE_MBUF_DEFAULT_BUF_SIZE=2176` (128B headroom, usable `RTE_MBUF_DEFAULT_DATAROOM=2048`), no new offload, `>1500` ioctl still returns `EINVAL`.
