# 07 Interface and Configuration Design

> Source `_material_C_lifecycle.md §1,§2`. Principles: opt-in, mutually exclusive with multi-process, zero regression, backward-compatible API.

## 1. Config-Layer Current State

- `struct ff_config.dpdk` (`ff_config.h:269-328`): `proc_type`(:272)/`lcore_mask`(:274)/`proc_mask`(:276)/`nb_procs`(:290)/`proc_id`(:291)/`proc_lcore`(:311). **No thread-mode field at all.**
- `parse_lcore_mask` (`ff_config.c:73-142`): number of set bits = `nb_procs` (:139), one process per bit on one lcore.
- proc_type validation only accepts primary/secondary/auto (`ff_config.c:1316-1321`).
- `--proc-type=` and `-c<proc_mask>` are concatenated into the EAL argv (`ff_config.c:1167-1170,1151-1154`); each process only passes its own lcore to EAL.

## 2. Thread-Mode Config Extension (Design)

### 2.1 New Fields
Add to `struct ff_config.dpdk` (`ff_config.h:269-328`):
- `int thread_mode`: run-mode switch, **default 0 (off, multi-process mode)**. Opt-in.
- `int nb_threads`: number of threads in thread mode (= number of set bits in lcore_mask). **New field; does not rewrite `nb_procs` semantics**, reducing regression surface.

config.ini example (new section/items):
```ini
[dpdk]
lcore_mask=0xf        ; 4 lcores
thread_mode=1         ; new: 1=single-process multi-thread multi-stack; 0(default)=multi-process
```

### 2.2 Semantic Fork (when thread_mode=1)
| Item | Multi-process mode (default) | Thread mode |
|---|---|---|
| lcore_mask M bits | M processes, 1 lcore each | **1 process, M threads** (`nb_threads=M`, `nb_procs=1`) |
| `proc_mask` (EAL `-c`) | Lights only this process's 1 core (`ff_config.c:1151-1154`) | **Lights all bits of lcore_mask** (let EAL build M lcores for `rte_eal_mp_remote_launch`) |
| `proc_type` | primary/secondary | **Forced primary** (no secondary) |
| Instance state | One global per process | One per thread (VNET + per-thread globals, see `03`/`05`) |

### 2.3 Config Code Points to Change
1. `parse_lcore_mask` (`ff_config.c:73-142`): in thread mode map the set bits to "N threads in the same process", fill `nb_threads`, light all bits in `proc_mask`.
2. proc_type validation (`ff_config.c:1316-1321`): thread mode rejects secondary/auto, forces primary.
3. `--proc-type=`/`-c` concatenation (`ff_config.c:1151-1170`): thread mode concatenates the full-bit coremask.
4. KNI validation (`ff_config.c:1392-1412`): change from "primary lcore" to "KNI owner thread's lcore" (see `08`).

## 3. Zero-Regression Strategy

- **Switch off by default**: with `thread_mode=0`, all the above paths take the existing primary/secondary branches, **byte-identical**.
- **Two modes mutually exclusive**: config-time validation that `thread_mode=1` requires proc_type=primary and no further multi-process fork; the `thread_mode=1` + `secondary` combination errors out directly.
- **Add rather than rewrite**: use `nb_threads` to carry the thread count, not polluting `nb_procs`'s multi-process semantics.

## 4. Lifecycle Interfaces

### 4.1 Current State
- `ff_init(int argc, char*const argv[])` (`ff_init.c:36`); `ff_run(loop_func_t loop, void *arg)` (`ff_init.c:59`) → `ff_dpdk_run` (`ff_dpdk_if.c:2763`).
- helloworld calls `ff_init` once (`example/main.c:128`) + `ff_run` once (`:217`) per process in `main()`.

### 4.2 API Compatibility (not breaking existing interfaces)
- `ff_init`/`ff_run` signatures **unchanged** (no process/thread identifier); thread mode is **transparent to the application**: the app still calls `ff_init`+`ff_run` once, and the library decides whether to launch one loop or N loops based on `thread_mode`. **API backward compatible** (`01` A4/G6).
- `rte_eal_init` (`ff_dpdk_if.c:1594`) is once per process, so `ff_init` is called only once (`04 §3`), no app calling-pattern change required.
- Positive signals: `pcurthread` is already `__thread` (`ff_api.h:55`); existing thread-context APIs `ff_switch/restore_curthread`, `ff_adapt_user_thread_add` (`ff_api.h:481-487`) are reusable.

### 4.3 Symbol Exports
If `ff_api.symlist` adds new external thread/instance-management APIs, they must be registered; this solution prefers thread mode being transparent to the app, **minimizing new external symbols** (config-driven only), maximizing compatibility.

## 5. Config Interface Contract Table

| Config item | Type | Default | Meaning | Constraint |
|---|---|---|---|---|
| `thread_mode` | int | 0 | 0=multi-process; 1=single-process multi-thread multi-stack | Mutually exclusive with secondary |
| `nb_threads` | int (derived) | — | Thread-mode thread count=lcore_mask bit count | Effective when thread_mode=1 |
| `lcore_mask` | hex | existing | Enabled lcore set | Thread mode=thread pinning set |
| `proc_type` | str | auto | Thread mode forces primary | — |
