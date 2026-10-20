# 05 - Hands-on Experiment Report (E1/E2 Series)

## Summary

This document records the **most decisive** set of hands-on experiments for issue #1078 feasibility investigation. Core proposition: after primary abnormal exit, can secondary continue sending/receiving, are established connections alive, can in-place recovery happen. All experiments completed on **unmodified** current F-Stack mainline; data from real processes and real client traffic, not inference.

## Key Conclusions

1. **E2: After primary exit, secondary processes survive and continue serving** — 9 of 20 established connections continued 200 OK until experiment end (90s+, 24 probe rounds with zero degradation); 11 failed were those hashed to primary's queue. **Issue's "all connections affected" is invalid.**

2. **E2b: After primary exit, secondary can still accept new connections** — 6 of 12 new connections succeeded; 6 failures hashed to primary's queue.

3. **RSS queue affinity precisely proven**: Connections served by primary-only vs secondary-only sets are **strictly complementary**, proving each process only serves flows on its own queue, no mutual fallback. Primary exit leaves **unpolled orphan queues**, not "total paralysis."

4. **E2c: After primary exit AND process group had fully exited, new secondary silently fails** — process starts, completes FreeBSD stack init, but **receives zero packets (0/12)**. **⚠ But causation corrected by E2e: root cause is process group full exit (refcnt → 0 → kernel `pci_clear_master()` stops device DMA), not "primary absent" itself.**

5. **E2d: Issue's premise "secondary crash can restart without affecting others" is valid** — killing secondary only affects its own queue's 6 connections; primary's 6 completely unaffected; after restart, full recovery (12/12).

6. **E2e (most critical, corrects E2c): As long as at least one process holds `/dev/uioX` (refcnt ≥ 1), secondary can restart successfully with primary absent** — in 3-process experiment, after killing primary then killing/restarting secondary(2) (secondary(1) alive throughout), servable connections recovered from 5/18 to 10/18, **reproduced twice**.

7. **E3 (PoC decisive verification): primary-slim runs, and slim primary crash has zero data plane impact** — only 3 lines code change, with `[port0] lcore_list=1` so primary holds no queue: startup normal, 12/12 full send/receive; after killing slim primary **12/12 connections zero interruption (26 rounds)**, new connections also 12/12.

8. **E10 (residual boundary): Primary cannot be restarted in place after crash** — new primary fails at EAL stage with `Cannot allocate memzone list`; but this failed attempt **doesn't damage existing secondary** (service maintained 10/18). Control-plane degraded state cannot be fixed in place; needs opportunistic full-group restart.

> **Comprehensive judgment**: Issue #1078's value isn't "saving secondary" (secondary doesn't die with primary), but **eliminating orphan queues** — making primary hold no queue, so its crash has zero data plane impact. The feature's accurate value: **transforms "must immediately full-group restart" into "can opportunistically full-group restart."**

## I. Experiment Environment

| Item | Value |
|------|-------|
| Test program | `example/helloworld` (HTTP keep-alive, port 80) |
| Process model | DPDK multi-process: primary + secondary |
| `lcore_mask` | `3` (2 lcores → 2 processes) |
| DPDK port | 1, exclusive NIC (virtio, `igb_uio`) |
| Server address | `<DPDK_NIC_IP>:80` |
| Client | `f-stack-client`, Python3 probe script |
| Probe method | Bind fixed local ports, establish N keep-alive connections, send `GET /` every 2s, verify `HTTP/1.1 200` |
| Process termination | `/data/workspace/kill_process.sh <pid>` (per convention) |
| Environment cleanup | `/data/workspace/rm_tmp_file.sh` for `/var/run/dpdk/rte/` residue |

## II. E1 — Baseline (primary + secondary both online)

20/20 connections normal, 10 rounds zero jitter. Independent re-verification: 12/12.

## III. E2 — Decisive: Established Connection Survival After Primary Exit

With 20 long connections ongoing, kill primary, observe 90s+.

- Round 10 (before kill): ok=20 dead=0
- Round 11 (after kill): ok=9 dead=11 (dead = connections hashed to primary's queue)
- Rounds 12-34: ok=9 dead=11 (24 rounds completely stable)

**Conclusions**: Secondary doesn't fail with primary exit. 9/20 connections continuously served. Failure/survival split consistent with RSS hash.

> **Important boundary**: Force-kill only. Graceful exit (`rte_eal_cleanup()`) may differ.

## IV. E2b — New Connection Capability After Primary Exit

6/12 new connections succeeded (hashed to secondary's queue); 6/12 failed (hashed to primary's orphan queue).

## V. RSS Queue Affinity Cross-Proof

| State | Servable Ports | Unservable |
|-------|---------------|------------|
| Only primary | 20002,20003,20004,20005,20008,20010 | 20000,20001,20006,20007,20009,20011 |
| Only secondary | 20000,20001,20006,20007,20009,20011 | 20002,20003,20004,20005,20008,20010 |
| Both | All 12 | None |

Sets are **strictly complementary and reproducible**.

## VI. E2c — Key Limitation: Secondary Restart with Primary Absent

Primary killed → kill secondary → restart secondary with primary absent → 0/12 (silent failure).

**⚠ Corrected by E2e**: root cause is process group full exit (refcnt → 0 → device DMA stopped), not "primary absent."

## VII. E2d — Control: Kill and Restart Secondary with Primary Online

After kill secondary: 6/12 ok (primary's 6 unaffected). After restart: 12/12 ok.

**Conclusion**: Issue premise A valid. Secondary crash impact limited to own queue; can restart in place.

## VIII. E5 — Boundary: `nb_queues == 1` Skips `set_rss_table`

`lcore_mask=1` single process, `nb_queues == 1`, `set_rss_table()` skipped. Result: 12/12 — PMD default reta all points to queue 0.

## IX. E2e — [Most Critical] Correcting E2c

### Design (3 processes, maintain refcnt ≥ 1)

`lcore_mask=7` → 3 processes. Secondary(1) always alive throughout.

| Step | State | refcnt | Servable |
|------|-------|--------|----------|
| 1 | Baseline (primary+s1+s2) | 3 | 18/18 |
| 2 | Kill primary | 2 | 10/18 |
| 3 | Kill s2 | 1 | 5/18 |
| 4 | **Restart s2** (primary absent) | 2 | **10/18** |
| 5 | Kill s2 → restart again | 2 | **10/18** |

### Conclusion (Corrects E2c)

1. **With primary absent, secondary can restart successfully** — prerequisite: refcnt ≥ 1. Reproduced twice.
2. **E2c's 0/12 re-attributed**: root cause is process group full exit, not "primary absent."
3. **In primary-slim target state, after primary crash all secondaries remain (refcnt ≥ 1), any crashed secondary can restart in place, no full-group restart needed.**
4. **Remaining boundary**: If all processes exit, device runtime state lost, must full-group restart.

## X. E10 — Primary Cannot Be Restarted In Place

New primary fails: `EAL: Cannot allocate memzone list`. Doesn't damage existing secondary (10/18 maintained).

**Conclusion**: Control-plane degraded state cannot be fixed in place. Must full-group restart to restore full capability.

**Operational implication**: primary-slim transforms "must immediately full-group restart" from **emergency fault** to **planned maintenance**.

## XI. E3 — [PoC Decisive] primary-slim Runs, Primary Crash Zero Impact

### PoC Patch (3 lines)

| # | Location | Change |
|---|----------|--------|
| 1 | `ff_dpdk_if.c:508-510` | `rte_exit` adds `&& rte_eal_process_type() != RTE_PROC_PRIMARY` |
| 2 | `ff_dpdk_if.c:535` | mbuf pool RX term: `nb_rx_queue * nb_lcores` → `nb_ports * nb_lcores` |

### Config
```ini
lcore_mask=3
[port0]
lcore_list=1          # primary's lcore0 not in list
```

### E3 — Startup and Full Send/Receive

12/12 connections established and served. Both primary (slimmed) and secondary start normally.

### E3b — [Core] Slim Primary Crash Data Plane Impact

Kill slim primary at t≈10s:
```
ROUND=13 t=24.0 ok=12 dead=0
...
ROUND=26 t=50.1 ok=12 dead=0
```

**Result: 12/12 connections zero interruption, 26 rounds zero failures.**

Compare baseline: E2 killed primary → 11/20 failed; E2e 3-process → 8/18 failed. Improvement is **qualitative**.

### E3c — New Connections After Slim Primary Crash

12/12 success.

### E3 Conclusions

1. PoC runs, issue #1078's core proposition holds on real hardware
2. Sub-goal (b) "narrow impact" 100% achieved (established + new traffic)
3. B4 (queue count/queueid shrink with `lcore_list`) confirmed by testing
4. Residual: slim primary still occupies full CPU core (99.8%); production must introduce idle_sleep

## XII. Issue Requirement Mapping

| Issue Requirement | Test Verdict | Evidence |
|-------------------|-------------|----------|
| R3 "secondary crash can restart" | **Valid** | E2d |
| R4 "primary exit, entire group must restart" | **Partially invalid**: other processes continue; crashed secondary can restart in place (refcnt ≥ 1); primary can't be brought back (E10); **no immediate full restart needed** | E2+E2b+E2e+E10 |
| R4 "all connections affected" | **Invalid**: only primary's queue connections affected | E2 (9/20 stable 24 rounds) |
| R8 "smaller connection impact" | **Valid and stronger than expected**: zero impact after slimming | E3 PoC |

## XIII. Pending Experiments

| ID | Experiment | Status |
|----|-----------|--------|
| E4 | KNI scenario | Done (E4a/E4b) |
| E6 | ≥3 process impact ratio | Done (E2e: 8/18 ≈ 1/3) |
| E7 | E2c silent failure mechanism | Done (FP-1/FP-2) |
| E8 | Graceful exit (`rte_eal_cleanup()`) | Pending |
| E9 | Long-term stability (hour-level) | Pending |
| E11 | PoC + multi-secondary | Pending |
| E12 | slim primary idle_sleep CPU | Pending |

## E4b — K4 PoC: Secondary as Runtime KNI Owner

### Config
- PoC patch: 106 lines, 7 changes, 4 files
- `lcore_mask=3`, `[port0] lcore_list=0,1`, `[kni] enable=1 method=reject owner_proc_id=1`

### Results

| Verification Item | Result |
|-------------------|--------|
| K4 PoC compiles | ✅ |
| Primary as init owner starts | ✅ `Successed to register dpdk interface` |
| Primary creates virtio_user port | ✅ `ff_kni_alloc to rte_eal_hotplug_add` + veth0 exists |
| Secondary as runtime owner starts | ✅ `create kni ring success` |
| Both processes stable (2min+) | ✅ |
| Secondary accesses shared KNI ring | ✅ |

**K4 PoC verified**: secondary as runtime KNI owner, primary as init owner, both processes stable. virtio_user port created by primary, secondary probes via vdev scan.
