# Full MTU Modification Support — Risks and Compatibility

## 1. Risk Overview

| Risk | Level | Main Controls |
|---|---|---|
| large mode memory significant growth | High | Feature switch, startup estimate, cap, NUMA validation |
| scatter multi-seg lifecycle errors | High | Dual offload, chain consistency unit test, failure release audit |
| large TX still segments by fixed 2048 | High | Use actual tailroom; normal 9000 frame single-seg assertion; zero-copy capability/fallback |
| Runtime set_mtu returns EBUSY | High | In-primary quiesce/stop/set/start state machine |
| Multi-process requires per-proc setting; missed setting causes that proc's soft MTU view inconsistency | Medium | Document usage convention; not addressed by IPC this phase, known constraint |
| enabled primary MTU fallback erroneously takes legacy software-only path | High | primary all MTU set hardware first then software (in-process consistent) |
| PMD/vSwitch does not support jumbo | High | Capability probe, no implicit success, physical machine UAT |
| bond partial member modification success | High | prepare all members, reverse rollback |
| Default 1500 behavior/memory regression | Medium | `mtu_enable=0` retains legacy |
| TSO/GSO/checksum with multi-seg combinations | Medium | Offload combination matrix and packet capture |

## 2. large Mode Memory Risk

### 2.1 Estimation Method

Current pool count is determined by `nb_mbuf` calculation at `ff_dpdk_if.c:394-430`. Approximate added memory:

```text
pool_bytes ≈ nb_mbuf × aligned(data_room + rte_mbuf/object overhead)
data_room ≈ HEADROOM + max_mtu + Ethernet/VLAN/FCS overhead
```

Distinguish three-layer terminology: pool API's `data_room_size` **includes** `RTE_PKTMBUF_HEADROOM`; usable dataroom is the difference; `rte_mbuf` object/allocator overhead counted separately. Example:

| max_mtu/mode | Approx pool API data_room | Notes |
|---|---:|---|
| legacy | 2176B | 128B headroom; usable dataroom 2048B |
| large 1500 | helper aligned result | Must hold frame + headroom; actual per helper output |
| large 9000 | ~9.2KB aligned | ~4.2x vs 2176B, excluding object overhead |
| large 9216 | ~9.5KB aligned | ~4.4x vs 2176B |
| large 65535 | Not representable | Exceeds uint16 API limit after headroom/overhead; config deterministically rejected |
| scatter 65535 | 2176B/segment | No large room; availability determined by PMD max_mtu/max_rx_pktlen |

Actual values must use the implementation helper's alignment result and runtime `nb_mbuf`; this table is not a measurement.

### 2.2 Controls

- Old config `mtu_enable=0` does not enlarge pool at all.
- Log per-NUMA-socket estimated memory before startup and check overflow.
- `max_mtu` is a uint16 config field, but valid upper bound is mode-dependent: large's derived `data_room_size` must be ≤UINT16_MAX (65535 deterministically fails); scatter proceeds to PMD capability check. Production recommends 9000/9216.
- Pool creation failure must abort startup; must not downgrade to a smaller pool and continue claiming max_mtu support.

## 3. scatter Mode Risk

- RX scatter only solves large frame reception; TX still needs `RTE_ETH_TX_OFFLOAD_MULTI_SEGS`.
- PMD capability is necessary but not sufficient; existing FreeBSD mbuf/rte_mbuf bridging must maintain chain fields and lifecycle consistency.
- Multi-seg increases descriptor, cache miss, and reclaim overhead; high-PPS small-packet scenarios may be slower than large/legacy.
- TSO with multi-seg combination must be validated per PMD; must not assume `TX_TCP_TSO` and `TX_MULTI_SEGS` combine freely.

Controls: explicit large/scatter choice, direct failure on insufficient capability, independent performance matrix, no implicit switch.

## 4. PMD and Link Dependency

### 4.1 DPDK 24.11 Confirmed Semantics

- `rte_eth_rxmode.mtu` exists (`rte_ethdev.h:427-430`).
- `rte_eth_dev_set_mtu()` may return `ENOTSUP/ENODEV/EIO/EINVAL/EBUSY` (L3640-3656).
- i40e/ice may return `EBUSY` when started; virtio/MLX5 implementations may allow runtime modification. Must not assume the same across PMDs.
- DPDK requires stop before reconfigure; MTU usually preserved across stop/start; still must readback per PMD to confirm.

### 4.2 virtio

Current source has `VIRTIO_NET_F_MTU`, `virtio_mtu_set()`, and scatter/multi-segs capability, but whether the actual backend negotiates that feature and what `max_mtu` is can only be read at runtime. Source "has implementation" does not mean the current virtual link supports 9000.

### 4.3 End-to-End Consistency

NIC, vSwitch/bridge, host tap, switch, and f-stack-client must uniformly support the target MTU. Any intermediate node still at 1500 may cause drops or PMTU/fragmentation.

## 5. Dynamic Modification and Concurrency Risk

- Directly stopping while port RX/TX is polling on lcores causes races, drops, or PMD undefined behavior.
- Concurrent SIOCSIFMTU within primary may cause A's rollback to overwrite B's success.

Controls: in-primary per-port state machine, lock, in-process dataplane quiesce, TX drain, timeout. This phase introduces no cross-process IPC, so no ACK-late/message-pool-race risks; multi-process consistency is achieved by "each process sets once", at the cost of missed-setting proc view inconsistency (see Section 1 usage constraint risk).

## 6. Rollback Risk

Ideal transaction (in primary process): old hardware/software MTU → new hardware → new software. Failure handling:

1. New hardware set fails: software unchanged, return original errno directly.
2. New hardware succeeds, in-process software commit fails: restore old hardware.
3. Restart fails: try old MTU + restart.
4. Rollback still fails: port marked FAILED/interface down, forbid further send/receive and return EIO.

Must not return success with primary hardware 9000 and in-process software 1500 inconsistency.

## 7. IPv4/IPv6/VLAN/bond Compatibility

- IPv4/IPv6 share ifnet MTU, but ICMP PMTU, MSS, and fragmentation paths differ; must validate separately.
- VLAN/QinQ adds L2 overhead; large data room calculation must reserve double VLAN; device frame limit must also account for overhead.
- bond upper bound takes the minimum of all members' capabilities; primary modifies each member sequentially in-process; reverse rollback on any failure.
- The mutual exclusion between `mtu_enable=1` and `kni.enable=1` has been removed (physically verified; this entry prevails, overriding historical KNI-exclusion descriptions in 07/08/09/10/11 of this spec set): when KNI is enabled, if the KNI kernel interface `veth0` MTU stays at default 1500, the DPDK jumbo path works normally, with the KNI side handled by the kernel protocol stack for fragmentation send/receive; if `veth0` MTU is set to 9000 via `ifconfig veth0 mtu 9000`, the KNI path can also send/receive jumbo packets normally. The `FF_KERNEL_COEXIST` exclusion with `mtu_enable=1` is retained.

## 8. Default Compatibility Policy

`mtu_enable=0`:
- pool data room remains `RTE_MBUF_DEFAULT_BUF_SIZE`;
- no new scatter/multi-segs offload;
- `port_conf.rxmode.mtu` keeps existing default path;
- `ff_veth_ioctl` for >1500 still returns EINVAL via `ether_ioctl`;
- performance and memory must be equivalent to current version.

Only explicit `mtu_enable=1` bears the memory and control-plane cost of jumbo. After enablement, primary must set hardware first then software even when target reverts to 1500/1400 (in-process consistent); must not fall back to software-only legacy path.

## 9. Config and Commit Risk

- `config.ini` only commits feature-related comments/default examples; must not commit local `lcore_mask/idle_sleep/addr/addr6/gateway` values.
- For testing, use `/usr/local/nginx_fstack/conf/f-stack.conf` or an explicit test copy; must confirm the actual process restarted and loaded the correct config; must not assume effect just by editing the file.
- Stop processes with `kill_process.sh`; temp file cleanup with `rm_tmp_file.sh`; permission changes with `chmod_modify.sh`.

## 10. Release and Rollback

- First release `mtu_enable=0` compatible version; confirm default path no regression.
- Then gradually roll out large; scatter as explicit optional mode.
- On functional issues, set `mtu_enable=0` to return to legacy; if port already started with jumbo, must restart process to restore pool/port config; cannot just hot-toggle the switch.
- Each milestone independent commit; prefer forward-fix; do not rewrite shared history.
