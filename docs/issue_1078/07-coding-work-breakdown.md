# 07 - Coding Work Breakdown

> Revised 2026-08-10 per K4 preferred / K3-corrected fallback + Q1/Q2/Q3 code verification + E4a experiment.

## Summary

This document is the coding work breakdown for issue #1078 "primary stability control" production implementation of S1 "primary-slim." The plan is defined by `03`, KNI/control-plane by `04`, PoC verified by `05`'s E3 series (3 lines + 1 config, kill slim primary → 12/12 zero interruption), no performance regression per `06`. This document breaks the plan into **4 milestones, 38 executable change points, 2 new config items**, with file:line, approach, dependencies, risks, and rollback for each.

## Key Conclusions

1. **PoC ≠ production**: PoC only did 2 changes (B1 relaxation + B3 pool formula approximation), using "primary not in lcore_list" auto-derivation instead of explicit switch. Production needs ~10x PoC's code volume.

2. **M1 (minimal runnable set) = 16 change points, 4 files** — the only "must complete in one batch" milestone. C09+C10 must commit together (C09 alone causes mbuf pool under-provisioning). M1 completion reproduces all PoC conclusions + solves P2 CPU spinning.

3. **Strongest rollback is config-level**: `primary_slim=0` (default) + restore `lcore_list` → behavior identical to pre-change. This is the direct benefit of explicit switch over auto-derivation.

4. **Two high-risk points requiring code comments + ops docs**:
   - (i) Never attach ifp to slim primary — `tx_queue_id[port]` = 0 would collide with secondary's tx queue 0 (non-MT-safe)
   - (ii) Slim primary is **persistent** control-plane process, graceful exit prohibited (`rte_eal_cleanup()` would tear down all secondary's shared memory)

5. **KNI (M3) is the largest milestone**: K4 preferred (9 points including N2 prerequisite); K3-corrected fallback (7-8 points). M1/M2 stages explicitly reject `primary_slim=1 && kni.enable=1` to isolate KNI.

## I. Prerequisites and Scope

| Item | Content |
|------|---------|
| Trigger | Execute only when user decides to productionize S1 |
| Input | 00 (requirements), 02 (blocking points), 03 (S1 design), 04 (KNI/control-plane), 05 (PoC), 06 (performance), 11 (Q1/Q2/Q3 + E4a) |
| Output | This document (work breakdown) + 08 (test spec); **this round: no lib/ code, no test code, no compilation, no commits** |

## II. Four Milestones

### M1: Minimal Runnable Set (16 change points, 4 files)

| Change ID | File | Description |
|-----------|------|-------------|
| C01 | `ff_config.h` | New `primary_slim` field |
| C02 | `ff_config.h` | New `primary_slim_idle_sleep` field (default 1000) |
| C03 | `ff_config.c` | V2: `thread_mode` + `primary_slim` mutual exclusion |
| C04 | `ff_config.c` | V4: `nb_procs >= 2` validation |
| C05 | `ff_config.c` | V5: primary lcore not in `lcore_list` validation |
| C06 | `ff_config.c` | `MATCH("dpdk", "primary_slim")` parsing |
| C07 | `ff_config.c` | `MATCH("dpdk", "primary_slim_idle_sleep")` parsing |
| C08 | `ff_config.c` | Default values |
| C09 | `ff_dpdk_if.c:508-510` | B1: `rte_exit` add `primary_slim && PRIMARY` condition |
| C10 | `ff_dpdk_if.c:535` | B3: mbuf pool RX formula `nb_ports * nb_lcores` |
| C11 | `ff_dpdk_if.c:836` | nb_queues unchanged (already correct) |
| C12 | `ff_dpdk_if.h` | New `ff_is_slim_primary()` API |
| C13 | `ff_dpdk_if.c` | `ff_is_slim_primary()` implementation |
| C14 | `ff_dpdk_if.c` | Slim primary main_loop: skip TX drain + rx loop |
| C15 | `ff_dpdk_if.c` | Slim primary idle_sleep floor |
| C16 | `ff_dpdk_if.c:2883-2884` | Skip `rte_eal_cleanup()` for primary_slim+PRIMARY |

**M1 acceptance**: Slim primary starts, 12/12 send/receive, kill slim primary → 12/12 zero interruption, `primary_slim=0` zero regression.

### M2: Control-Plane Integrity (8 change points)

| Change ID | File | Description |
|-----------|------|-------------|
| C17 | `ff_dpdk_if.c` | `nb_dev_ports` shared memzone (N1 fix) |
| C18 | `ff_dpdk_if.c:1196` | `init_flow`/`fdir` primary gate (N8) |
| C19 | `ff_dpdk_if.c:1707` | `init_clock` primary gate (N5) |
| C20 | `ff_config.h` | `kni.owner_proc_id` field |
| C21 | `ff_dpdk_kni.c` | `ff_kni_is_runtime_owner()` function |
| C22 | `ff_dpdk_kni.c:387,434` | Secondary `kni_stat` allocation |
| C23 | `ff_dpdk_if.c:297` | `nb_dev_ports` shared memzone publish |
| C24 | `ff_dpdk_if.c:821-825` | `total_nb_ports *= 2` condition → `enable_kni` only |

### M3: KNI (K4 preferred: 9 points; K3-corrected fallback: 7-8 points)

| Change ID | File | Description (K4) |
|-----------|------|-----------------|
| C25 | `ff_dpdk_kni.c` | `ff_kni_is_runtime_owner()` — `proc_id == owner_proc_id` |
| C26 | `ff_dpdk_kni.c:434` | Owner secondary allocates `kni_stat` |
| C27 | `ff_dpdk_if.c:2080` | Broadcast/multicast gate → `!pkts_from_ring` |
| C28 | `ff_dpdk_if.c:2765` | `ff_kni_process()` outside rx loop, owner gate |
| C29 | `ff_dpdk_kni.c` | Relax KNI mutex check for secondary |
| C30 | `ff_dpdk_if.c` | `ff_kni_process()` call: `ff_kni_is_runtime_owner()` |
| C31 | `ff_dpdk_kni.c:484` | Inject ring create/lookup |
| C32 | `ff_dpdk_kni.c` | `kni_process_rx` redirect to inject ring (primary_slim) |
| C33 | `ff_dpdk_kni.c` | `ff_kni_inject_process()` function |

### M4: Validation and Polish (6 change points)

| Change ID | File | Description |
|-----------|------|-------------|
| C34 | `ff_config.c` | `owner_proc_id` validation |
| C35 | `ff_config.c` | KNI + primary_slim compatibility check |
| C36 | `ff_dpdk_if.c` | `ff_dpdk_stop()` warning for slim primary |
| C37 | `config.ini` | New config item comments |
| C38 | `ff_api.h` | `primary_slim` struct field |

## III. Dependency Graph

```
M1 (C01-C16) → M2 (C17-C24) → M3 (C25-C33) → M4 (C34-C38)
```

- M1 is self-contained (can run independently)
- M2 depends on M1 (needs `primary_slim` switch)
- M3 depends on M2 (needs N2 fix for K4)
- M4 is validation/polish (depends on all previous)

## IV. Rollback

| Level | Method | Scope |
|-------|--------|-------|
| Config | `primary_slim=0` + restore `lcore_list` | Full (behavior identical to pre-change) |
| Code | Revert specific commit | Per-change |
| Emergency | `git revert` M1 commit | Full (if M1 causes issues) |

## V. Items Not Covered This Round

- No lib/ code changes
- No test code
- No compilation
- No commits
- KNI hands-on verification (E4c-E4f) pending
- Graceful exit (`rte_eal_cleanup()`) impact pending (E8)
- Long-term stability pending (E9)
