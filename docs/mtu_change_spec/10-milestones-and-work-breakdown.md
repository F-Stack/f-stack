# Full MTU Modification Support — Milestones and Work Breakdown

## 1. Execution Principles

- Each milestone has an independent commit and gate; gate failure must bounce back to the previous step for repair.
- Max 3 bounces per step; if still failing, escalate to human decision.
- Code author and reviewer must be different agents.
- This document is the work breakdown for subsequent coding tasks; this spec task does not execute these steps.

## M0: Baseline Freeze and Environment Probe

### Work Items
- Record current HEAD, DPDK 24.11.6, PMD, NIC/vSwitch and f-stack-client link capabilities.
- Run build, unit tests, MTU=1500 connectivity and performance baseline under old config.
- Read each port's `dev_info.min_mtu/max_mtu/max_rx_bufsize/max_rx_pktlen` and offload capability.
- Confirm whether the local virtio backend advertises `VIRTIO_NET_F_MTU`.

### DoD
- Baseline report includes reproducible commands and actual output.
- config.ini local IP/lcore/idle_sleep test values not committed.

### Rollback Point
- No code changes; baseline recording only.

## M1: Configuration and Data Structures

### Work Items
- `ff_config.h` add enum/fields.
- `ff_config.c` add defaults, strict parser, mode-dependent data_room upper bound and cross-field validation.
- `mtu_enable=1` with KNI/kernel coexist combination explicitly rejected at config phase (EOPNOTSUPP semantics).
- config.ini add **comment-form** config docs and default examples.
- Extend `test_ff_config.c` and fixtures.

### DoD
- New and old fixtures all pass; no new `atoi()`; error messages clear.
- Old config parse results equivalent: `mtu_enable=0,port.mtu=1500`.
- large `max_mtu=65535` deterministically fails at config phase; scatter proceeds to PMD capability check.
- KNI/kernel coexist with MTU feature simultaneously enabled fixture deterministically fails.
- config.ini reviewed diff before commit; only feature comments/defaults, no local test values.

### Gate
- `-Werror` build; config unit tests; memory allocation failure paths.

### Rollback Point
- Revert M1 commit to restore original config structure.

## M2: DPDK Startup Path and Dual mbuf Mode

### Work Items
- large data room computation helper, overflow and memory estimation.
- scatter capability check and RX_SCATTER/TX_MULTI_SEGS config.
- Set `port_conf.rxmode.mtu`, validate `max_rx_pktlen` and large usable room by frame bytes, set/get MTU before start.
- Audit RX/TX multi-segment mbuf conversion and failure release paths.
- large normal copy/raw TX changed to fill by actual tailroom; 9000 frame in large room must be single-segment; page-array/zero-copy clarify TX_MULTI_SEGS capability or copy fallback.
- Extend `test_ff_dpdk_if.c` wrappers.

### DoD
- large/scatter both have deterministic unit tests.
- Insufficient PMD capability fails startup, no silent downgrade.
- large 9000 normal copy/raw TX `nb_segs==1`; scatter segment count by actual tailroom, `pkt_len/nb_segs/data_len` consistent.
- `mtu_enable=0` produces identical data room/offload/port config as old version.
- ASan/Valgrind (where runnable) no leak, no out-of-bounds, no double-free.

### Gate
- DPDK capability and config cross-validation; all error codes covered.
- Reviewer checks `pkt_len/nb_segs/data_len/next` item by item.

### Rollback Point
- Feature can be runtime-disabled via `mtu_enable=0`; revert M2 commit to restore old pool.

## M3: ff_veth Software MTU and DPDK Encapsulation

### Work Items
- `ff_dpdk_if.h/.c` add opaque MTU get/set/capability API and DPDK negative errno→FreeBSD positive errno helper.
- `ff_veth_ioctl` intercept `SIOCSIFMTU`; only legacy path when feature off; after enablement, all MTU including 1500/1400/fallback go through hardware transaction then software commit.
- `ff_veth_setup_interface` set config MTU after `ether_ifattach()`, before address/route/VLAN creation.
- Unit test success/failure/EBUSY/readback mismatch/unknown errno→EIO, verify software not split.

### DoD
- At startup `if_mtu == rte_eth_dev_get_mtu == port.mtu`.
- Runtime PMD natively supporting set_mtu: 1500↔9000 succeeds.
- `mtu_enable=0` with ≤1500 legacy path zero regression.

### Gate
- `ff_veth.c` has no `rte_eth*` symbols; FreeBSD tree unmodified.
- Reviewer verifies error returns and `if_notifymtu` not duplicated.

### Rollback Point
- Disable feature switch to restore legacy; revert M3 commit if needed.

## M4: Multi-Process MTU Consistency (No IPC) and EBUSY Control State Machine

### Work Items
- `ff_veth_ioctl(SIOCSIFMTU)` distinguish primary/secondary branches by `rte_eal_process_type()`: primary sets soft+hard, secondary sets soft only.
- Add per-port control state/lock and in-process dataplane quiesce to primary; implement stop/set/get/start and failure rollback (primary process only).
- bond member (within primary) sequential set and reverse rollback.
- Document "set once per process" usage convention and known constraint (proc not set keeps old soft MTU).
- This phase does not implement cross-process IPC transactions: no new MTU message rings, shared message pools, transaction/coordinator.
- Tests: primary EBUSY→stop/set/start and rollback, secondary only changes soft MTU, in-process concurrent ioctl serialization.

### DoD
- i40e/ice-class `EBUSY` PMD can modify via in-primary safe stop/set/start.
- Each proc setting independently yields consistent soft MTU views; hardware MTU set solely by primary; no cross-process transaction code.
- Secondary branch does not call any DPDK port control interface.
- Post-restart RSS/promiscuous/VLAN state matches baseline.

### Gate
- During stress test (single/primary process) continuous MTU round-trips, no deadlock, no hang, no half-recovered port.
- Primary state machine EBUSY/rollback cases pass; grep confirms no request/prepare/commit/ack transactions, rings, transaction, coordinator residue.

### Rollback Point
- Control state machine restores old MTU on failure; if unrecoverable, interface down and stop advancing.

## M5: Integration, Performance, Stability, and Documentation

### Work Items
- Execute IPv4/IPv6, large/scatter, VLAN, bond/vdev tests per `11`.
- Run performance matrix and 24-hour stability.
- Sync three-layer architecture docs, knowledge graph, config docs, and implementation report.
- English version has been generated and placed in this directory.

### DoD
- All functional acceptance passes, or link-limit items have actual evidence and no faked results.
- Default 1500 zero regression; jumbo performance and memory data complete.
- Document file:line consistent with final code.

## 2. Dependencies

```text
M0 → M1 → M2 → M3 → M4 → M5
```

- M2 depends on M1 config fields.
- M3 depends on M2 having reserved dataplane capacity for max_mtu.
- M4 depends on M3 in-process transaction correctness (M4 introduces no cross-process IPC transactions).
- Must not skip M2 to directly lift `ether_ioctl` upper bound, or software/hardware split occurs.

## 3. Commit Suggestions

1. `Add MTU configuration parsing and validation.`
2. `Configure jumbo-capable mbuf modes and DPDK port MTU.`
3. `Synchronize ff_veth MTU changes with DPDK ports.`
4. `Handle runtime MTU changes per process (primary sets hw+sw, secondary sw only).`
5. `Add MTU integration tests and update architecture docs.`

Keep each message 1–3 English sentences; do not mix test environment config into commits.
