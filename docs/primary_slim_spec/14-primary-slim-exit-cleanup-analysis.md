# 14. primary_slim Exit Cleanup Analysis

> This document analyzes whether commit `1c28aaa2df`'s `ff_dpdk_run()` skipping `ff_unload_config()` + `rte_eal_cleanup()` for primary_slim+PRIMARY is correct, and the missing cleanup logic.
> Date: 2026-08-11. Basis: DPDK 24.11.6 source + issue #1078 docs `01`/`10` + external cross-validation.

## Summary

Skipping `rte_eal_cleanup()` was designed to protect shared resources secondary depends on, but DPDK source verification shows its actual effect is **limited** — `rte_eal_cleanup()` doesn't delete `/var/run/dpdk/rte/config`, mp_socket `unlink` is overwritten by `bind` on next primary startup, hugepage uses `MAP_SHARED` so primary exit only munmaps primary's own mapping without affecting secondary. The real gap is **no secondary exit notification**, causing orphan processes. Per issue #1078 design philosophy (doc `10` prerequisite 3: "primary persists, doesn't exit gracefully"), this exit path is a fallback, not normal flow.

## 1. `ff_dpdk_run()` Current Implementation

`lib/ff_dpdk_if.c:3004-3026`:

```c
void ff_dpdk_run(loop_func_t loop, void *arg) {
    ...
    rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);
    rte_eal_mp_wait_lcore();
    stop_clock();
    rte_free(lr);

    if (!(ff_global_cfg.dpdk.primary_slim &&
          rte_eal_process_type() == RTE_PROC_PRIMARY)) {
        ff_unload_config();
        rte_eal_cleanup();
    }
    ff_log_close();
}
```

primary_slim+PRIMARY skips `ff_unload_config()` + `rte_eal_cleanup()`, only calls `ff_log_close()`.

`ff_dpdk_stop()` (:3029-3035) only sets `stop_loop = 1` (`__thread` variable), prints warning.

## 2. `rte_eal_cleanup()` Function-by-Function Behavior

`dpdk/lib/eal/linux/eal.c:1300-1346`:

| # | Call | Line | Actual Behavior | Deletes Files? | Affects Secondary? |
|---|------|------|-----------------|----------------|-------------------|
| 1 | `rte_service_finalize()` | 1323 | Clean service core subsystem | No | No |
| 2 | `vfio_mp_sync_cleanup()` | 1332 | Clean VFIO mp sync thread | No | No (using igb_uio) |
| 3 | `rte_mp_channel_cleanup()` | 1334 | `close_socket_fd()` → `close(fd)` + `unlink(path)` | **Yes** (mp_socket file) | No (secondary has own fd) |
| 4 | `rte_eal_alarm_cleanup()` | 1335 | Clean alarm thread | No | No |
| 5 | `eal_mp_dev_hotplug_cleanup()` | 1338 | Clean hotplug mp thread | No | No |
| 6 | `rte_eal_memory_detach()` | 1340 | munmap primary's hugepage mapping; also `eal_memalloc_cleanup()` + `rte_fbarray_detach()` | No | **No** (MAP_SHARED; see B2) |
| 7 | `rte_eal_malloc_heap_cleanup()` | 1341 | Clean primary's malloc heap | No | No |
| 8 | `eal_cleanup_config()` | 1342 | `free()` 3 strings | **No** | No |
| 9 | `eal_lcore_var_cleanup()` | 1343 | Clean lcore variables | No | No |
| 10 | `rte_eal_log_cleanup()` | 1344 | Clean log | No | No |

### 2.1 `rte_mp_channel_cleanup()` Detail

`close_socket_fd()` does `unlink` mp_socket file. But:
- Primary exit: kernel already closed all fds
- mp_socket file residue doesn't affect next startup (`bind` overwrites)
- Secondary has own mp_socket fd, unaffected by primary unlink

### 2.2 `eal_cleanup_config()` Detail

**Only frees 3 strings, does NOT delete `/var/run/dpdk/rte/config` file.** Config file cleanup is in `eal_clean_runtime_dir()` (`linux/eal.c:84`), called at **primary startup** (cleaning previous residue), not in `rte_eal_cleanup()`.

### 2.3 Hugepage Uses MAP_SHARED

`dpdk/lib/eal/linux/eal_memory.c:556`:
```c
retval = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
```

`MAP_SHARED` semantics: mapping is only truly released when all referencing processes munmap. Primary exit: kernel munmaps primary's mapping, **secondary's mapping unaffected**, hugepage physical memory not released.

## 3. Actual Effect of Skipping Cleanup

| Resource | Skip Cleanup | Kernel Behavior on Exit | Actual Effect |
|----------|-------------|------------------------|---------------|
| mp_socket file | No unlink | fd closed, file residue | Next primary `bind` overwrites, harmless |
| `/var/run/dpdk/rte/config` | Not deleted (cleanup doesn't delete either) | File residue (tmpfs) | Next `eal_clean_runtime_dir()` cleans, harmless |
| hugepage mapping | No munmap | Kernel auto-munmaps primary's mapping | Secondary's MAP_SHARED unaffected |
| malloc heap | No cleanup | Kernel auto-reclaims | Harmless |
| ini config memory | No `ff_unload_config()` | Kernel auto-reclaims | Harmless |

**Conclusion**: Skipping `rte_eal_cleanup()` has **almost zero actual effect** — kernel auto-completes most cleanup on process exit (munmap, close fd, reclaim memory). DPDK's cleanup only adds `unlink` mp_socket file and `free` strings, none affecting next startup.

Doc `10` prerequisite 3's claim "avoid `rte_eal_cleanup()` tearing down shared resources" is **not entirely accurate**: `rte_eal_cleanup()` doesn't actually tear down secondary-dependent shared resources (hugepage uses MAP_SHARED, config file not deleted in cleanup).

## 4. Real Gap: No Secondary Exit Notification

`ff_dpdk_stop()` only sets `stop_loop = 1` (per-thread), only stops primary's own `main_loop`. **No cross-process secondary exit notification mechanism**:

- `ff_ipc_send` / `msg_ring.*stop` / `broadcast.*secondary` — no matches in `lib/`
- `rte_eal_mp_wait_lcore()` waits for lcore (thread) exit, not process exit — secondary is independent process, not lcore

### 4.1 Post-Primary-Exit Timeline

1. Primary receives signal or `ff_dpdk_stop()` called
2. `stop_loop = 1` (per-thread)
3. Primary's `main_loop` exits
4. `rte_eal_mp_wait_lcore()` returns (only waits primary's own lcore)
5. Skip cleanup
6. `ff_log_close()`
7. `ff_dpdk_run()` returns, primary process exits
8. **Secondary still running**, becomes orphan

### 4.2 Orphan Secondary State

After primary exit, secondary loses:
- IPC server (secondary's mp request destination hardcoded to primary)
- Dynamic heap expansion proxy (`request_to_primary()` fails)
- Interrupt handling (all interrupts only trigger in primary)

But secondary can still send/receive packets (data plane doesn't depend on primary online, doc `01` key conclusion 2), entering **control-plane degraded state** (doc `10` §1.4).

### 4.3 F-stack Has No Signal Handler

No `SIGINT`/`SIGTERM` handler in `example/`. helloworld with `SIGTERM` takes default behavior (direct exit), doesn't go through `ff_dpdk_stop()`.

## 5. Design Philosophy Analysis

### 5.1 Issue #1078 Positioning

Doc `10` prerequisite 3:
> "Operations must ensure: **primary persists, doesn't exit gracefully** (avoid `rte_eal_cleanup()` tearing down shared resources), and **at least one data-plane process always alive** (maintain uio refcnt ≥ 1)."

### 5.2 Real Value of Skipping Cleanup

The real value of skipping cleanup is **not protecting secondary** (hugepage uses MAP_SHARED, unaffected), but:
1. **Conservative strategy**: Avoid potential undefined behavior from `pthread_cancel` etc. during cleanup
2. **Fallback**: Primary shouldn't exit normally; this path is "just in case"

### 5.3 Difference from Doc `10`

Doc `10`'s claim "avoid `rte_eal_cleanup()` tearing down shared resources" is **inaccurate** per source verification:
- `rte_eal_cleanup()` doesn't delete config file (`eal_cleanup_config` only frees strings)
- hugepage uses MAP_SHARED, primary cleanup doesn't affect secondary
- mp_socket unlink doesn't affect secondary (secondary has own fd)

## 6. External Cross-Validation

### 6.1 DPDK Official Documentation

`dpdk/doc/guides/prog_guide/multi_proc_support.rst:19-24`:
> "secondary processes can only run alongside a primary process **or after a primary process has already configured the hugepage shared memory for them**"

The "or after" gives textual space for "primary absent but still runnable," but no guarantee semantics.

`dpdk/doc/guides/rel_notes/release_18_02.rst`:
> "It is expected that all DPDK applications call rte_eal_cleanup() before exiting. Not calling this function could result in leaking hugepages, leading to failure during initialization of secondary processes."

But source verification shows `rte_eal_cleanup()` doesn't actually release hugepage physical memory (MAP_SHARED reclaimed by kernel on process exit), only munmaps primary's own mapping. The official "leaking hugepages" claim may refer to earlier version behavior.

### 6.2 Community Practices

- VPP / DPVS both use single-process multi-thread, no primary/secondary exit issue
- f-stack native-mt (`thread_mode=1`) is also single-process multi-thread direction

## 7. Improvement Suggestions

### 7.1 Minimal Change (Recommended)

Add warning log in `ff_dpdk_run()`'s cleanup skip block:

```c
if (!(ff_global_cfg.dpdk.primary_slim &&
      rte_eal_process_type() == RTE_PROC_PRIMARY)) {
    ff_unload_config();
    rte_eal_cleanup();
} else {
    fprintf(stderr, "primary_slim: primary exiting without cleanup; "
        "secondary processes are orphaned and enter control-plane "
        "degraded state, need planned full restart\n");
}
```

### 7.2 Medium Change (Optional)

In `ff_dpdk_stop()`, broadcast stop to all secondaries via IPC, wait for them to exit before cleanup. But f-stack currently has no cross-process stop notification mechanism; needs new IPC message type.

### 7.3 Not Recommended

Don't call `rte_eal_cleanup()` on primary_slim exit — although analysis shows no actual impact on secondary, `pthread_cancel` of mp_handle_tid thread may have undefined behavior in multi-process environment; conservative skip is safer.

## 8. Honest Boundaries

| No. | Boundary | Description |
|-----|----------|-------------|
| B1 | **VFIO unverified** | Using igb_uio; `vfio_mp_sync_cleanup()` behavior unverified. VFIO primary cleanup may affect secondary's group fd |
| B2 | **`rte_eal_memory_detach` internals not deeply analyzed** | May not only munmap; may release fbarray shared files. Not line-by-line analyzed |
| B3 | **Graceful exit not tested** | Doc `10` L5's E8 experiment not executed; this analysis based on source code static analysis |
| B4 | **Long-term stability not tested** | Orphan secondary's long-term behavior (hour-level) unverified |

## 9. Conclusion

1. Skipping `rte_eal_cleanup()` and `ff_unload_config()` has **limited actual effect** — kernel auto-completes most cleanup on process exit
2. The real gap is **no secondary exit notification**, causing orphan processes entering control-plane degraded state
3. Per issue #1078 design philosophy, primary shouldn't exit normally; this path is a fallback
4. Recommend minimal change: add warning log alerting ops that secondary has become orphan
