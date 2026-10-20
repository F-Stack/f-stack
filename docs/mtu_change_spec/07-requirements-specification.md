# Full MTU Modification Support — Requirements Specification

## 1. Document Purpose

This document converts the investigation conclusions of `00`–`06` into implementable requirements, aiming to let F-Stack support the following after DPDK NIC takeover:

- Setting standard or jumbo MTU from config at startup;
- Modifying MTU at runtime via `SIOCSIFMTU`, syncing FreeBSD `if_mtu` and DPDK port;
- Both `large` and `scatter` mbuf modes;
- Multi-process consistency between software stack and shared physical port;
- Zero regression for existing standard MTU 1500 config.

This task only generates the implementation spec; coding, unit tests, integration tests, and performance tests are executed in subsequent tasks.

## 2. Confirmed Decisions

| ID | Decision | Result |
|---|---|---|
| D-MTU-01 | mbuf approach | Implement both `large` and `scatter`, selected by config |
| D-MTU-02 | MTU upper bound | `max_mtu` configurable; defaults to 9000 when feature enabled |
| D-MTU-03 | Scope of this task | Spec only; coding and testing in separate tasks |
| D-MTU-04 | End-to-end validation | Best-effort; if link does not support jumbo, must record honestly, no faked pass |
| D-MTU-05 | FreeBSD source policy | Do not modify `freebsd/net/if_ethersubr.c`; intercept `SIOCSIFMTU` in `lib/ff_veth.c` |
| D-MTU-06 | Compatibility policy | When feature disabled, preserve current 1500 MTU, 2048B mbuf and existing ioctl behavior |

## 3. Terminology

- **Port MTU**: DPDK ethdev MTU, managed by `rte_eth_dev_set_mtu()`.
- **Protocol-stack MTU**: FreeBSD `ifnet.if_mtu`, affects MSS, fragmentation, and routing.
- **Config MTU**: `[portN] mtu`, the MTU requested at port startup.
- **Max MTU**: `[dpdk] max_mtu`, the process-wide config/runtime upper bound, also the large mbuf pre-allocation basis.
- **large mode**: Each mbuf's data room is large enough to hold a complete Ethernet frame for `max_mtu`.
- **scatter mode**: Standard mbuf data room retained; multi-segment mbufs used to receive/transmit jumbo frames.

## 4. Functional Requirements

### R-MTU-001 Config Switch and Default Compatibility

- Add `[dpdk] mtu_enable`, values `0|1`, default `0`.
- When `mtu_enable=0`, must not change existing mbuf pool, offload, port MTU, or ioctl behavior.
- When `mtu_enable=1`, enable this spec's MTU capabilities; `max_mtu` defaults to 9000, `mbuf_mode` defaults to `large`.

> `mtu_enable` is introduced to resolve the conflict between "default `max_mtu=9000`" and "zero memory regression for old configs": old configs without explicit enablement continue using `RTE_MBUF_DEFAULT_BUF_SIZE=2176` (128B headroom, usable dataroom 2048), not enlarged to jumbo size.

### R-MTU-002 Config Model

- `[dpdk] max_mtu=N`: config field is uint16, but valid upper bound is mode-dependent:
  - `large`: `max_mtu + L2_overhead + RTE_PKTMBUF_HEADROOM` aligned must be `<= UINT16_MAX`, and frame bytes/usable room must satisfy device capability; rejected at `ff_check_config()` if exceeded.
  - `scatter`: configurable up to 65535, but must still satisfy PMD `dev_info.max_mtu/max_rx_pktlen`.
- `[dpdk] mbuf_mode=large|scatter`: only effective when `mtu_enable=1`.
- `[portN] mtu=N`: default 1500; range `IF_MINMTU..max_mtu`.
- Unified frame formula: `frame_bytes = L3_MTU + Ethernet header + configured VLAN/QinQ overhead + FCS`; must also validate `frame_bytes <= dev_info.max_rx_pktlen`. large's usable RX room uses `data_room_size - RTE_PKTMBUF_HEADROOM`; must not compare pool params including headroom/alignment directly against `max_rx_bufsize`.
- Any invalid config must fail clearly at startup and abort init; no silent fallback to 1500.

### R-MTU-003 Startup Port MTU

- Set `port_conf.rxmode.mtu` before `rte_eth_dev_configure()`.
- Call and validate `rte_eth_dev_set_mtu()` in the port start flow; read back with `rte_eth_dev_get_mtu()` after.
- After `ff_veth_setup_interface()` completes `ether_ifattach()`, set FreeBSD `if_mtu` to the same `[portN] mtu`.
- Any inconsistency among software MTU, hardware MTU, or readback value fails port init.

### R-MTU-004 large mbuf Mode

- pool API `data_room_size` must be at least: `RTE_PKTMBUF_HEADROOM + max_mtu + L2_overhead`, aligned up to DPDK cache line.
- `L2_overhead` must cover worst-case Ethernet header, double VLAN, and FCS; specific constants defined uniformly, no bare numbers in multiple places.
- Pre-create pool: check multiplication/addition overflow and total memory limit.
- large mode compares `usable_room = data_room_size - RTE_PKTMBUF_HEADROOM` with `frame_bytes`, and checks device single-RX-buffer capability in the same headroom-free unit; pool alignment/padding must not cause false rejection. Must not auto-switch to scatter.

### R-MTU-005 scatter mbuf Mode

- Retain `RTE_MBUF_DEFAULT_BUF_SIZE`.
- Must validate and enable `RTE_ETH_RX_OFFLOAD_SCATTER` and `RTE_ETH_TX_OFFLOAD_MULTI_SEGS`.
- If PMD lacks either capability, init fails with `ENOTSUP` semantics; must not claim jumbo is enabled.
- Must verify existing FreeBSD mbuf ↔ rte_mbuf conversion, TX release, and failure reclaim paths support multi-segment mbuf; if not, the implementation task must complete them before passing the M2 gate.

### R-MTU-006 Runtime SIOCSIFMTU

- `ff_veth_ioctl()` adds a `SIOCSIFMTU` branch to avoid entering `ether_ioctl()`'s `ETHERMTU` upper bound.
- New MTU must satisfy `IF_MINMTU..configured max_mtu`, PMD `min_mtu..max_mtu`, and current mbuf mode capacity.
- This interface distinguishes by process role (`rte_eal_process_type()`):
  - primary: set protocol-stack software MTU (`if_setmtu`) and DPDK hardware MTU (`rte_eth_dev_set_mtu`); hardware change has in-process transaction semantics: save old soft/hard MTU → set hardware → readback confirm → commit software value; rollback hardware and software on any step failure.
  - secondary: only set protocol-stack software MTU (`if_setmtu`); never touch any DPDK port control interface.
- `rte_eth_dev_set_mtu()` may return `-EBUSY` on a running port. The implementation must not directly stop/start the port unsynchronized in `ff_veth_ioctl()`; primary must safely quiesce receive/transmit within the process (quiesce this primary process's lcores) then complete stop/set/start and resume, or return `EBUSY` explicitly if the PMD does not support dynamic change. Full acceptance requires implementing the in-primary stop/set/start path.

### R-MTU-007 Multi-Process Consistency

- DPDK physical port MTU is shared state; only primary may execute ethdev control operations; secondary only changes its own protocol-stack software MTU.
- Multi-process MTU consistency is achieved by "each f-stack process independently calling MTU set once at startup/runtime"; no inter-process communication, no transactions, no IPC coordination.
- Usage convention: app/Ops must trigger `SIOCSIFMTU` once per process; a proc not set keeps its software MTU view at the old value (known usage constraint, not addressed by IPC in this phase).
- `tools/sbin/ifconfig -p N ... mtu` updates both soft/hard MTU for primary, only that proc's soft MTU for secondary; hardware MTU is solely primary's responsibility.

### R-MTU-008 Query and Observability

- `SIOCGIFMTU` returns the protocol-stack effective MTU.
- Provide DPDK hardware MTU readback logging; success logs include `port_id/old_mtu/new_mtu/mbuf_mode`, failure logs include DPDK errno.
- No sensitive config printed; MTU logs use existing `ff_log()` facility.

### R-MTU-009 IPv4/IPv6/VLAN/bond/vdev

- IPv4 and IPv6 share the same ifnet MTU; both must cover PMTU, MSS, and non-fragmentation tests.
- VLAN scenarios validate against parent port MTU and VLAN overhead; VLAN sub-interfaces must not request MTU exceeding parent capability.
- bond/vdev must validate each member's minimum `max_mtu`; reject if any member unsupported, must not partially modify.
- This phase does not implement KNI/kernel-coexist MTU linkage: when `mtu_enable=1` is detected with KNI/kernel coexist enabled simultaneously, config phase must reject with `EOPNOTSUPP` semantics and advise disabling one; must not allow dual-stack MTU inconsistency.

## 5. Non-Functional Requirements

### NF-MTU-001 Performance

- `mtu_enable=0` must have no measurable regression vs. baseline throughput, P99 latency, and CPU.
- large/scatter modes each establish throughput, P99 latency, CPU/packet, mbuf memory baselines for MTU 1500 and 9000.

### NF-MTU-002 Reliability

- Config or runtime failure must not cause process exit, permanent port stop, mbuf leak, or in-process soft/hard MTU inconsistency (in-process transaction rollback guarantee).
- stop/set/start failure must have a recovery path; if unrecoverable, mark port unavailable and return error.

### NF-MTU-003 Security and Bounds

- All string config uses strict parsing; reject trailing garbage, negatives, integer overflow.
- `max_mtu` must not bypass PMD/device capability upper bounds.

## 6. Acceptance Criteria

- AC-01: Old config without new items behaves identically to current version.
- AC-02: `mtu_enable=1, mbuf_mode=large, mtu=9000` passes end-to-end on a jumbo-capable link.
- AC-03: `mbuf_mode=scatter` passes equivalently, with no multi-segment mbuf leak/double-free.
- AC-04: Runtime 1500→9000→1500 succeeds; software and hardware readback consistent.
- AC-05: PMD/link not supporting jumbo returns explainable error, no false success.
- AC-06: Each proc setting MTU independently yields consistent views; no cross-process auto-sync this phase (proc not set keeps old soft MTU, known constraint).
- AC-07: IPv4/IPv6, VLAN, bond/vdev boundary tests pass or are explicitly marked unsupported with config blocked.
- AC-08: Unit, integration, performance, and 24-hour stability gates all satisfy `11-test-and-acceptance-specification.md`.

## 7. Scope and Non-Goals

### 7.1 In Scope

- Multi-process independent MTU setting (no IPC transaction): each f-stack process triggers `SIOCSIFMTU` once; primary sets soft+hard, secondary sets soft only.

### 7.2 Out of Scope

- Multi-process runtime dynamic MTU cross-process IPC transaction coordination (request/prepare/commit/ack two-phase transactions, coordinators, dedicated message rings/pools) is deferred to a separate milestone; not done this phase.
- This spec task does not modify code or execute tests.
- Does not modify switch, virtio backend, or f-stack-client permanent MTU config; subsequent integration tests only temporarily adjust and restore in approved environments.
- Does not modify FreeBSD `ether_ioctl()` general semantics.
