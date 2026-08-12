# 10 - Feasibility Conclusion and Recommendations

> This document is the final verdict for issue #1078 "primary stability control" feasibility investigation, based on all documents 00-08 in this directory.
> Verdict date: 2026-08-07. Reviewer: investigation leader. Independent review see `09-审核门禁报告.md`.

## Summary

Issue #1078 proposes separating/"slimming" primary to only do NIC queue setup, binding, initialization, moving packet reception to secondary. Through code verification + 9 sets of hands-on experiments (E1/E2/E2b/E2c/E2d/E2e/E5/E10/E3) + minimal PoC patch testing, this round's verdict: **conditionally feasible, recommended for adoption**. PoC used **3 lines code change + 1 config item** to verify the core proposition: after slim primary crash, established connections **12/12 zero interruption**, new connections **12/12 normal**, no performance regression. The issue's two original judgments about "all connections affected" and "entire process group must restart" were both proven **inaccurate** by testing.

## Final Verdict

### Verdict: **Conditionally Feasible (Recommended for Adoption)**

| Sub-goal | Content | Verdict | Key Evidence |
|----------|---------|---------|--------------|
| **(a) Reduce primary anomaly probability** | primary doesn't run data plane, doesn't enter protocol stack receive path | **Achieved (statistical)** | PoC measured primary main loop shrunk to timer + msg_ring |
| **(b) Narrow primary anomaly impact** | primary crash doesn't take away data plane capability | **100% achieved (existing + new traffic)** | **E3b: after killing slim primary, 12/12 connections zero interruption (26 rounds)**; **E3c: new connections 12/12** |
| **(c) Post-failure recoverability** | Can recover in place after crash | **Partially achieved** | **E2e: if process holds `/dev/uioX` (refcnt ≥ 1), crashed secondary can restart in place**; but **E10: primary cannot be restarted in place** (EAL `Cannot allocate memzone list`) |

### Prerequisites (All Required)

1. `thread_mode=0` (single-process multi-thread mode has no separate primary process; this feature's semantics don't exist; must add mutual exclusion validation)
2. When `kni.enable=1`, must follow `04`'s **K4** (secondary as runtime KNI owner, E4a/E4b verified) or **K3-corrected** (KNI stays with primary, physical port send/recv via secondary, fallback)
3. Operations must ensure: **primary persists, doesn't exit gracefully** (avoid `rte_eal_cleanup()` tearing down shared resources), and **at least one data-plane process always alive** (maintain uio refcnt ≥ 1)
4. Must introduce **idle sleep** for slim primary — measured 99.8% CPU after slimming; slimming **≠ saving a core**
5. Recommend external daemon for layered recovery (in-place secondary restart → degraded state alert → opportunistic planned full group restart)

## I. Core Evidence (Ranked by Strength)

### 1.1 Strongest Evidence: PoC Hands-on Verification (E3 Series)

**Change volume** (`_poc_primary_slim.patch`, 2 hunks / 3 lines):

| # | Location | Change | Unblocked Point |
|---|----------|--------|-----------------|
| 1 | `lib/ff_dpdk_if.c:508-510` | `rte_exit` condition append `&& rte_eal_process_type() != RTE_PROC_PRIMARY` | **B1** |
| 2 | `lib/ff_dpdk_if.c:535` | mbuf pool RX term remove dependency on **this process's** queue count | **B3** |

**Results**:

| Verification Item | Result |
|-------------------|--------|
| Slim primary startup | Pass (no longer `rte_exit`) |
| primary + secondary full packet send/receive | **12/12** |
| **Kill slim primary, established connections** | **12/12 zero interruption, 26 probe rounds** |
| Kill slim primary, new connections | **12/12** |
| QPS (slim primary alive) | 122.4k (single-process baseline 122.3k, **+0.08%, no regression**) |
| QPS (slim primary crashed) | 127.7k (**+4.5%, no regression**) |
| Failed requests | All **0** |

### 1.2 Key Code Verification: B4 Assumption Invalid (Most Important "Good News")

Originally worried "primary exiting `lcore_list` would reduce queue count by 1, shift queueid, shift RSS reta" — proven **invalid** by line-by-line verification:

- `nb_queues` source is `pconf->nb_lcores` (`lib/ff_dpdk_if.c:836`), i.e., **that port's `lcore_list` length**, not `nb_procs`
- `queueid` is this process lcore's **index** in `lcore_list` (`lib/ff_dpdk_if.c:487-491`), completely **decoupled** from `proc_id`
- `set_rss_table()` recalculates reta by same `nb_queues` (`lib/ff_dpdk_if.c:801`, `1169-1174`)

⇒ After removing primary's lcore, queue count / queueid / reta / `dispatch_ring` **consistently shrink**, **orphan queues naturally disappear at code level**. This is the fundamental reason the issue author's "reuse `lcore_list`" approach is feasible.

### 1.3 Two Original Issue Judgments Corrected by Testing

| Issue Original Text | Test Verdict | Evidence |
|---------------------|-------------|----------|
| "primary exits, entire group must restart" | **Partially invalid**: other processes continue; crashed secondary can restart in place (refcnt ≥ 1); **no immediate full restart needed**, but primary can't be brought back (E10), need **opportunistic** full restart | E2, E2e, E10 |
| "all connections affected" | **Invalid**: only connections on primary's queue affected (2-proc ~1/2, 3-proc ~1/3); after slimming **zero impact** | E2, E2e, E3b |
| "secondary crashes can restart, not affecting others" | **Valid** | E2d |

### 1.4 DPDK Hard Constraints (Determine "primary must persist, cannot exit")

From `01` DPDK source/docs:

1. **IPC unique server**: secondary's mp request destination hardcoded to primary's `mp_socket`
2. **Dynamic heap expansion must be proxied by primary**: secondary needs `request_to_primary()` for new hugepage
3. **All interrupts only trigger in primary** — including link status/LSC

⇒ Solution can only be **"primary persists as control plane, doesn't participate in data plane"**, never **"primary exits after initialization"** (`03`'s S2 rejected).

## II. Accurate Value Statement (Avoid Over-promising)

> **primary-slim transforms "primary crash ⇒ must immediately full-group restart, ~1/N connections immediately interrupted" into "primary crash ⇒ zero data plane loss, business continues, crashed secondary can restart in place, cluster enters control-plane degraded state, can opportunistically full-group restart during planned maintenance window."**
>
> That is: **transforms emergency fault into planned maintenance, restart timing changes from passive to controllable.**

**Explicitly NOT promised**:
- Not "never need restart" (control-plane degraded state can't be fixed in place, E10)
- Not "save a CPU core" (slim primary still spins at full core, unless idle sleep implemented)
- Not "primary is no longer structural single point" (only probability reduced, impact narrowed)
- Not "connections don't fail on secondary crash" (each process has independent FreeBSD stack, no connection migration)

## III. Recommendations

### 3.1 Project Recommendations

| Priority | Recommendation | Basis |
|----------|---------------|-------|
| **P0** | Adopt S1 (primary-slim), proceed per `07` milestones; M1 minimal set delivers main benefit | PoC verified, minimal change |
| **P0** | Must implement `primary_slim` explicit switch (default 0): 0 regression when off | `07` C01~C12 |
| **P0** | Must implement slim primary idle sleep | P2 measured full core |
| **P0** | Must implement `thread_mode` / `primary_slim` mutual exclusion | B7 semantic exclusion |
| **P1** | Handle KNI per `04` K4 (secondary as runtime owner, E4a/E4b verified) | `04` K4 |
| **P2** | Provide "control-plane degraded state detection + alerting" | E10 ops implication |

### 3.2 Upstream Issue Reply Key Points

1. **Direction endorsed**: "reuse `lcore_list`" approach **technically valid**. Key reason: queue count and queueid determined by **port's `lcore_list` length and index** (`lib/ff_dpdk_if.c:836`, `487-491`), decoupled from `proc_id`
2. **Minimal changes needed**: mainly unlock `nb_rx_queue == 0` `rte_exit` + fix mbuf pool formula + handle primary simplified main loop + cleanup skip + ifp ownership + KNI ownership + msg_ring ownership
3. **Correct two issue judgments** (with test data): primary anomaly doesn't affect other processes; crashed secondary can restart in place
4. **Primary can only "persist slimmed", not "exit after init"**: DPDK constraints — primary is IPC server, heap proxy, interrupt handler; primary can't be brought back after exit
5. **Two pitfalls**: ① slimmed primary still spins at full core; ② KNI enabled has owner gate that never executes when primary doesn't receive
6. **Ask author's deployment**: KNI enabled? secondary count? uses `ff_*` tools? VFIO vs igb_uio?

## IV. Honest Boundaries

| No. | Boundary | Description | Closure Status (2026-08-11) |
|-----|----------|-------------|---------------------------|
| L1 | PMD/driver limitation | All tests on virtio + igb_uio. VFIO behavior unverified. Physical NIC may differ | **✓ Closed** — Physical machine tests passed |
| L2 | Single port, ≤3 processes | Multi-port heterogeneous `lcore_list`, more secondaries unverified | **✓ Closed** — Physical multi-process stress test passed |
| ~~L3~~ | KNI unverified | Closed (E4a/E4b) | ✓ Remains closed |
| L4 | PoC ≠ production | Production implementation per `07` needed | **✓ Closed** — Production impl passed all tests |
| L5 | Graceful exit untested | E2/E2e/E3b all killed primary. `rte_eal_cleanup()` impact untested | **Partially closed** — Doc 14 analyzed, limited effect |
| L6 | Long-term stability untested | ~90s observed. Hour-level, mbuf/message_pool levels unverified | **Partially closed** — 10+ min stress test passed |
| L7 | Performance absolute values not extrapolable | Client (8-core `ab`) is bottleneck | **Remains** |
| L8 | Upstream research incomplete | issue #804/#860/#863 not online-verified | **Remains** |

## V. One-Sentence Conclusion

> **Issue #1078's approach is correct, cost is minimal, benefit is significant: 3 lines code + 1 config PoC has proven "slim primary crash causes zero data plane impact"; recommend adoption and production implementation per `07` milestones; but must clarify boundaries — primary can only persist not exit, slimming doesn't save CPU, control-plane degraded state needs opportunistic full-group restart. KNI scenario verified via K4 (secondary as runtime owner, E4a/E4b); non-igb_uio drivers need further verification.**
