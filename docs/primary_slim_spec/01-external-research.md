# 01 - External Research and Cross-Validation

> This document serves f-stack issue #1078 "primary stability control" feasibility investigation.
> Date: 2026-08-07. Evidence priority: local source code > local official docs (DPDK source tree rst) > external docs/community.

## Summary

Issue #1078's request is to "separate primary to only do initialization, move data plane to secondary." Conclusion: **"primary slimming to control plane" is feasible within DPDK model** (primary can hold no rx/tx queues, not receive packets). After primary exit, other processes continue serving and crashed secondary can restart in place (no full-group restart needed); but process group enters control-plane degraded state (no IPC server, no heap expansion, no interrupt handling), and if all processes exit, device runtime state is lost, must full-group restart.

## Key Conclusions

1. **DPDK never guarantees secondary works after primary exit**: Official definition says secondary "can only run alongside a primary process **or after a primary process has already configured the hugepage shared memory for them**" (`multi_proc_support.rst:19-24`). The "or after" gives textual space but no guarantee.

2. **Local testing consistent with official text**: After primary killed, running secondary survives, continues serving its RSS queue connections and accepts new ones (E2: 9/20 stable 24 rounds; E2b: 6/12 new connections succeeded).

3. **"Secondary silent failure with primary absent" root cause determined, unrelated to primary absence**: Root cause is **FP-1 + FP-2** combination:
   - **FP-1**: `igb_uio`'s `igbuio_pci_release()` only executes `pci_clear_master()` (stops device DMA) when **last** process closes `/dev/uioX` (`atomic_dec_and_test(&udev->refcnt)` true) — `igb_uio.c:352-366`
   - **FP-2**: virtio PMD secondary branch early-exits after setting rx/tx functions, doesn't reprogram device — `virtio_ethdev.c:1949-1954`
   - E2e proved: with refcnt ≥ 1, secondary restarts successfully with same EAL errors (which are just accompanying noise)

4. **Queue mapping not an obstacle**: Queue count is `pconf->nb_lcores` (port's `lcore_list` length, `ff_dpdk_if.c:836`), not `nb_procs`; `queueid` is lcore's index in `lcore_list` (`ff_dpdk_if.c:487-491`), fully decoupled from `proc_id`. Removing primary's lcore from `lcore_list` → queue count/queueid/reta/dispatch_ring consistently shrink, no orphan queues.

5. **Similar projects avoid multi-process**: VPP and DPVS both use single-process multi-thread; f-stack has native-mt direction. Issue #1078 is a mitigation within multi-process framework, not a root fix.

## Part I: DPDK Official Multi-Process Hard Constraints

### 1.1 Primary/Secondary Official Definitions

- Primary: initializes shared memory (hugepage, mempool, rings), configures NIC, starts secondary
- Secondary: attaches to pre-initialized shared memory, cannot initialize but can use
- Source: `dpdk/doc/guides/prog_guide/multi_proc_support.rst`

### 1.2 Three DPDK Hard Constraints (Primary Must Persist)

1. **IPC unique server**: Secondary's mp request destination hardcoded to primary's `mp_socket` (`eal_common_proc.c:750-751`)
2. **Dynamic heap expansion must be proxied by primary**: Secondary needs `request_to_primary()` for new hugepage (`malloc_heap.c:484`)
3. **All interrupts only trigger in primary**: Including link status/LSC (`multi_proc_support.rst:174-177`)

### 1.3 Primary Crash Recoverability Boundary (E10 Verified)

**Primary cannot be restarted in place** after crash: new primary fails at EAL stage with `Cannot allocate memzone list` — `fbarray_memzone` exclusive lock blocked by existing secondary's shared lock (`eal_common_fbarray.c:790-803`). Failed attempt doesn't damage existing secondary (fail-fast, no side effects).

**Conclusion**: Control-plane degraded state is **unidirectionally irreversible**. Restoring full capability requires stopping all processes + cleaning `/var/run/dpdk/<prefix>/` + full-group restart.

### 1.4 FP-1/FP-2: Device Runtime State Loss Mechanism

**FP-1** (`igb_uio.c:352-366`): `igbuio_pci_release()` — only last process closing `/dev/uioX` (`atomic_dec_and_test(&udev->refcnt)` true) executes `igbuio_pci_disable_interrupts()` + `pci_clear_master()` (stops device DMA). Symmetrically, `igbuio_pci_open()` only calls `pci_set_master()` when refcnt goes 0→1 (`:330-349`).

**FP-2** (`virtio_ethdev.c:1949-1954`): virtio PMD secondary branch early-exits after `set_rxtx_funcs()`, doesn't call `virtio_reinit_complete()` (which writes `VIRTIO_CONFIG_STATUS_DRIVER_OK`). Only primary probe path (`:1980`) and `virtio_dev_configure` path (`:2162`/`:2195`/`:2202`) call it — all unreachable in secondary.

**Combined effect**: Once `pci_clear_master()` stops device, any subsequently started secondary cannot restore it to running state.

**E2e correction**: Root cause is NOT "primary absent" but "all processes exited (refcnt → 0)". With refcnt ≥ 1, secondary restarts successfully.

## Part II: F-stack Code Primary/Secondary Responsibilities

### 2.1 Existing Multi-process Issues

- #804: F-Stack multi-process secondary segfault on startup (no official response)
- #860: FF primary exit → secondary segfault (closed, no fix)
- #863: FF multi-process mode ungraceful exit (no official response)

### 2.2 Similar Project Approaches

| Project | Architecture | Multi-process? | Primary dependency? |
|---------|-------------|----------------|-------------------|
| VPP | Single-process multi-thread (main/worker) | No | N/A |
| DPVS | Single-process multi-thread | No | N/A |
| f-stack native-mt | Single-process multi-thread | No | N/A |

All major userspace network stacks avoid multi-process primary/secondary dependency. Issue #1078 is a mitigation within multi-process, not a root fix.

## Part III: Independent Conclusion

**Feasible approach: "primary persists but doesn't receive packets"** — primary holds no rx/tx queues, only does device config/shared object creation/control-plane message processing. This aligns with DPDK hard constraints (primary must persist as IPC server/heap proxy/interrupt handler) while eliminating orphan queues (primary crash → zero data plane impact).

**NOT feasible: "primary exits after initialization"** — DPDK requires primary for IPC, heap expansion, interrupts. Primary can't be restarted after exit (E10). Control-plane degraded state is irreversible.
