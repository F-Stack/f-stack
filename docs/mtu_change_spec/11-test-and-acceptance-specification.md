# Full MTU Modification Support — Test and Acceptance Specification

## 1. Test Principles

- Every "pass" must come from actual execution with preserved output; plans are not results.
- First prove default 1500 zero regression, then validate jumbo.
- large and scatter must be validated separately; one mode must not substitute for the other.
- If the local link does not support jumbo, must distinguish "code path passes" from "link end-to-end fails".

## 2. Unit Tests

### 2.1 `test_ff_config.c`

| ID | Input | Expected |
|---|---|---|
| UT-CFG-01 | Old fixture without new items | enable=0, max=9000, mode=large, port mtu=1500 |
| UT-CFG-02 | enable=1,max=9000,mode=large,mtu=9000 | Success |
| UT-CFG-03 | mode=scatter | Success |
| UT-CFG-04 | Invalid mode/empty | Parse failure |
| UT-CFG-05 | max_mtu non-numeric/negative/overflow/trailing chars | Parse failure |
| UT-CFG-06 | port.mtu > max_mtu | Validation failure |
| UT-CFG-07 | enable=0 and port.mtu>1500 | Validation failure |
| UT-CFG-08 | port array calloc failure | No leak, returns failure |

### 2.2 `test_ff_dpdk_if.c`

Inject DPDK return values via linker wrap/stub:

- large data room: 1500, 9000, 65535 (must return ERANGE at config validation, not truncate), addition/multiplication overflow, alignment; assert legacy pool API param 2176, usable dataroom 2048 terminology and values.
- capability boundary table: compare `frame_bytes`, large `usable_room=data_room-headroom`, device `max_rx_bufsize`, `max_rx_pktlen` respectively; prove excess alignment/padding does not cause false rejection; scatter lacking RX or TX capability. scatter `max_mtu=65535` does not create large room, only enters PMD max_mtu/max_rx_pktlen validation.
- startup set/get: success, readback mismatch, `ENOTSUP/EINVAL/EIO`.
- dynamic: direct success; first `EBUSY` then stop/set/start success; set failure rollback; start failure recovery; rollback failure enters FAILED.
- opaque context: correct port_id; NULL context/invalid port.

### 2.3 veth/ioctl Tests

- `if_mtu` updated only after `ff_dpdk_if_set_mtu` succeeds.
- DPDK negative errno converted to FreeBSD positive errno via helper; upper ioctl returns `-1` with correct user-space `errno`, covering `EBUSY/EOPNOTSUPP/EINVAL` and unknown values normalized to `EIO`; on failure `if_mtu` keeps old value.
- legacy disabled: >1500 still goes through `ether_ioctl` and returns EINVAL.
- enabled: primary's 9000→1500, 9000→1400 must set hardware first then software (in-process soft/hardware sync fallback), must not take legacy shortcut.
- secondary branch: only updates in-process `if_mtu`, does not call `ff_dpdk_if_set_mtu`／does not touch any DPDK port control interface.
- success path triggers `if_notifymtu` once by generic `if.c`; must not duplicate.

### 2.4 multi-seg Lifecycle

For `ff_dpdk_if.c:1557-1588/2209-2249/2333-2364`:
- 1/2/N segment RX to FreeBSD mbuf;
- same 9000 frame in large normal copy/raw path uses actual `rte_pktmbuf_tailroom()`, assert `nb_segs==1`;
- scatter path computes N segments by actual tailroom, assert `pkt_len == sum(data_len)`, `nb_segs`, chain tail `next==NULL`;
- page-array/zero-copy: when PMD has TX_MULTI_SEGS verify expected segment count and capability; without that capability verify single large-mbuf copy fallback (if implementation chooses reject strategy, assert EOPNOTSUPP and record in spec change);
- Nth segment allocation failure, all allocated segments released;
- zero-copy ext mbuf refcount, send failure, NIC completion reclaim no double-free.

## 3. Build Gate

- `lib/` compiles fully under existing `-Werror`.
- `tools/sbin/ifconfig` and related tools rebuilt.
- All `tests/unit` pass; new code coverage no lower than project threshold.
- Search gate: `ff_veth.c` must not reference `rte_eth*`; `freebsd/` must have no feature diff.

## 4. Integration Test Matrix

### 4.1 Environment Preparation

- DPDK end: local `<f-stack-v4-address>`; client: ssh `f-stack-client`.
- First read PMD, `min_mtu/max_mtu/max_rx_bufsize/max_rx_pktlen`, scatter/multi-segs capability.
- Record original values before temporarily modifying f-stack-client/vSwitch MTU; must restore after. Any permission changes still go through `chmod_modify.sh`, process stops through `kill_process.sh`, temp file cleanup through `rm_tmp_file.sh`.

### 4.2 Static Startup Tests

| Mode | port MTU | Expected |
|---|---:|---|
| legacy | 1500 | Behavior matches baseline |
| large | 1500 | Startup succeeds, pool reserved per max_mtu |
| large | 9000 | Software/hardware readback 9000 |
| scatter | 9000 | RX_SCATTER/TX_MULTI_SEGS enabled, readback 9000 |
| any | >PMD max | Startup fails, error clear |
| scatter | PMD lacks offload | Startup fails EOPNOTSUPP |

### 4.3 Runtime Tests

Via `tools/sbin/ifconfig -p 0 f-stack-0 mtu N`:
- 1500→1400→1500;
- 1500→9000→1500;
- boundary `IF_MINMTU-1/max_mtu+1`;
- two concurrent different MTU requests in-process, verify primary serialization;
- multi-process consistency (no IPC): each proc executes `-p N` once, verify each proc's soft MTU view consistent;
- secondary setting: send request from secondary proc, verify only that proc's soft MTU changed, no DPDK touched (hardware MTU unchanged);
- known constraint: when only some procs set, unset procs keep old soft MTU (not a failure, must record);
- inject PMD EBUSY/stop failure/start failure (primary), verify in-process rollback.
- `mtu_enable=1` with KNI/kernel coexist configured simultaneously must be explicitly rejected before startup.

Assertions each time:
1. `SIOCGIFMTU` (each target proc);
2. `rte_eth_dev_get_mtu` (log or diagnostic interface, primary sets hardware only);
3. set procs' ifnet soft MTU matches expected, unset procs keep old value;
4. port still sends/receives.

### 4.4 IPv4/IPv6 Large Packets

When link supports:

```text
IPv4: ping -M do -s 8972 <f-stack-v4-address>
IPv6: ping -6 -M do -s 8952 <f-stack-v6-address>
```

Also validate:
- MTU=1500: above large packets fail as expected or trigger PMTU; must not erroneously send overlong frames;
- MTU=9000: no fragmentation success;
- TCP curl large file integrity (hash consistent), bidirectional multiple rounds;
- IPv4/IPv6 TCP MSS corresponds to MTU.

> ping payload must be calculated and recorded per actual tool/IP/ICMP headers; must not copy commands without confirming frame length.

### 4.5 VLAN, bond, vdev

- Single VLAN/double VLAN overhead; sub-interface MTU must not exceed parent capability.
- bond all members support/one member unsupported/mid-failure rollback.
- virtio, mlx5, i40e/ice (where conditions allow) cover runtime success and EBUSY PMD classes.

## 5. Performance Baseline

Test matrix:

| Mode | MTU | Metrics |
|---|---:|---|
| legacy | 1500 | Baseline |
| large | 1500/9000 | Throughput, P50/P99, CPU/packet, memory |
| scatter | 1500/9000 | Same + average nb_segs |

Requirements:
- Fixed CPU/lcore, file size, concurrency, test duration and warmup; at least 5 rounds, report median and dispersion.
- `mtu_enable=0` vs. old version throughput/latency/CPU regression within measurement noise; if exceeded must analyze.
- large memory must align with theoretical estimate; scatter must record segment distribution and offload overhead.
- Do not assume jumbo is necessarily faster; report actual results.

## 6. Stability and Fault Testing

- 24-hour continuous send/receive, one round each for large/scatter.
- 1500↔9000 switch every minute (in supported test environment, primary in-process stop/set/start), check deadlock/mbuf leak/port loss.
- primary rollback failure, repeated EBUSY, stop/start failure recovery paths.
- DPDK xstats/FreeBSD netstat: error frames, drops, retransmits no abnormal growth.

## 7. Honest Boundary and Tiered Acceptance

If the local virtio/vSwitch does not support jumbo:

- Can mark pass: config parsing, mbuf mode, DPDK capability rejection, software/hardware 1500 compatibility, unit tests.
- Cannot mark pass: 9000 end-to-end jumbo send/receive and performance.
- Report must note actual `dev_info`, backend MTU, failure errno/capture evidence.
- Should transfer to a jumbo-capable physical machine for final UAT; until then overall status is "code gate passed, end-to-end pending environment validation", not "all acceptance complete".

## 8. Final Acceptance Checklist

- [x] Unit tests and build gate pass
- [x] legacy 1500 zero regression
- [x] large 9000 bidirectional IPv4/IPv6 pass
- [ ] scatter 9000 bidirectional IPv4/IPv6 pass
- [ ] Dynamic MTU (primary soft+hard, secondary soft only) and "set once per process" consistency pass
- [ ] primary EBUSY stop/set/start and rollback pass
- [ ] VLAN/bond/vdev boundary pass or explicitly block unsupported config
- [ ] Performance/memory/stability data complete
- [x] config.ini commit contains no local test values
- [ ] Three-layer architecture and knowledge graph synced

> Physical machine acceptance record (2026-07-22): Under large 9000 mode, IPv4 `ping -M do -s 8972` bidirectional and IPv6 `ping6 -M do -s 8500` both verified passing (IPv6 no longer fragments after commit `0f25ac495` added `if_notifymtu`); KNI/MTU coexistence verified normal after commit `989f1d2da` removed mutual exclusion (`veth0` MTU=1500 fragmentation send/receive, `ifconfig veth0 mtu 9000` jumbo send/receive all normal). scatter/dynamic MTU/VLAN-bond/performance baseline/24h stability not included in this acceptance; test separately as needed.
