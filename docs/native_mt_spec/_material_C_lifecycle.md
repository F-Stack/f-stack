# Research Material C: Lifecycle / Configuration / KNI-IPC Ownership / issue #430 Corroboration

> Dimension: current state and extension points of the **in-library native single-process multi-thread multi-stack-instance (share-nothing)** lifecycle and configuration side.
> Principle: read-only, no changes; every conclusion carries `file:line`; inconsistencies resolved in favor of code.
> Code baseline: `/data/workspace/f-stack/` (current tree after the FreeBSD 15.0 upgrade).

---

## 0. One-Line Current State (Objective Record, Not a Conclusion Anchor)

f-stack's current multi-instance model is "**one process = one lcore = one stack instance**"; multiple instances rely on **DPDK primary/secondary multi-process + fork** (one `config.ini`, each process with a different `-p proc_id`). In-library there is **no** native run model of "N pthreads in one process each running an independent stack instance". The adapter route (`adapter/syscall/`) is an **application-side** LD_PRELOAD adaptation, a different layer from "stack-side native multi-threaded run model" (see §4).

---

## 1. Configuration-Layer Current State and thread-Mode Extension Points

### 1.1 Data Structures (`lib/ff_config.h`)

`struct ff_config.dpdk` (`ff_config.h:269-328`) key fields:

| Field | Line | Meaning |
|---|---|---|
| `char *proc_type` | `ff_config.h:272` | DPDK process-type string (primary/secondary/auto) |
| `char *lcore_mask` | `ff_config.h:274` | globally enabled lcore mask (hex) |
| `char *proc_mask` | `ff_config.h:276` | this proc's mask over all lcores (derived from proc_id, see §1.2) |
| `int nb_procs` | `ff_config.h:290` | total process count (= set-bit count in lcore_mask, see §1.2) |
| `int proc_id` | `ff_config.h:291` | current process number (`0..nb_procs-1`) |
| `uint16_t *proc_lcore` | `ff_config.h:311` | proc_id → lcore_id mapping array (filled by `parse_lcore_mask`) |

**Key observation**: the whole struct has **no "thread count / thread mode" field**. `nb_procs`/`proc_id`/`proc_lcore[]` are entirely "process"-dimension semantics and are heavily reused in `ff_dpdk_if.c` as "instance count / instance number" directly (see §3.1). This is the first landing point for thread-mode extension.

### 1.2 lcore_mask → nb_procs Derivation (`lib/ff_config.c:73-142` `parse_lcore_mask`)

- `parse_lcore_mask()` (`ff_config.c:73`) scans `lcore_mask` hex-bit by hex-bit:
  - on each set bit (`ff_config.c:116-128`), records that bit's lcore idx into `proc_lcore[count]`, `count++`;
  - when `proc_id == count` (`ff_config.c:119-126`), derives this process's own `proc_mask` (the `-c` mask, lighting only its own one lcore) from that lcore idx;
  - at the end `cfg->dpdk.nb_procs = count` (`ff_config.c:139`), i.e. **nb_procs = set-bit count of lcore_mask**;
  - `proc_id >= count` directly errors (`ff_config.c:136-137`).
- **Semantics**: M set bits in lcore_mask ⇒ M processes, each process occupies 1 lcore, and `proc_mask` only lets this process see its own core. This is the core-splitting foundation of "multi-process share-nothing".

### 1.3 proc_type Validation (`lib/ff_config.c:1312-1321`)

- defaults to `"auto"` when unspecified (`ff_config.c:1312-1314`);
- only accepts `primary` / `secondary` / `auto`, otherwise reports `invalid proc-type` and returns -1 (`ff_config.c:1316-1321`).
- `proc_id` out of range (`> RTE_MAX_LCORE`) degrades to 0 (`ff_config.c:1323-1326`).

### 1.4 `--proc-type=` Concatenated into the EAL argv (`lib/ff_config.c:1167-1170`)

- when assembling the `dpdk_argv` passed to `rte_eal_init` (`dpdk_args()`), concatenates `cfg->dpdk.proc_type` into `--proc-type=xxx` (`ff_config.c:1167-1170`);
- at the same place `proc_mask` becomes `-c<proc_mask>` (`ff_config.c:1151-1154`), i.e. **each process passes only its own one lcore to EAL**. This is exactly the landing point of "one process one lcore".

### 1.5 KNI Primary-Only Config Validation (`lib/ff_config.c:1392-1412`)

- inside `ff_check_config()` (`ff_config.c:1332`), when `kni.enable && proc_type=="primary"` (`ff_config.c:1396-1397`), requires the primary's lcore (`proc_lcore[proc_id]`, `ff_config.c:1400`) to appear in every port's `lcore_list`, otherwise errors (`ff_config.c:1406-1411`).
- i.e. **KNI is bound only to the primary process / its lcore** (matching the runtime primary-only gating in §3).

### 1.6 thread-Mode Extension-Point Evaluation (New Switch, Zero-Regression Strategy)

> The following is an **extension-point analysis** based on the code above, not an existing implementation.

**Points needing change (if introducing single-process multi-thread N stack instances):**

1. **New switch (opt-in, default off)**: add e.g. `int thread_mode` to `struct ff_config.dpdk` (`ff_config.h:269-328`) (or extend proc_type with an enum value `"thread"`). Default 0/off, guaranteeing unchanged behavior.
2. **lcore_mask semantics fork**: `parse_lcore_mask` (`ff_config.c:73-142`) currently equates "set-bit count" with "process count". Under thread mode, the same `proc_lcore[]` should map to "N pthreads in the same process"; `nb_procs` (`ff_config.c:139`) semantics change to "thread count". For zero regression, **add a `nb_threads` field rather than rewriting `nb_procs` semantics**; under thread mode `nb_procs=1`.
3. **proc_type / proc_mask / `--proc-type=` concatenation**: under thread mode there is only **a single process** (primary, no secondary); `proc_mask` (`ff_config.c:1151-1154`) should light all bits of lcore_mask (let EAL see N cores so `rte_eal_mp_remote_launch` starts one thread per lcore), not the current "light only its own one". This is a **mutually exclusive fork** from the multi-process mode.
4. **proc_type validation** (`ff_config.c:1316-1321`): thread mode forces primary; `secondary`/`auto` combinations must be rejected here.
5. **KNI validation** (`ff_config.c:1392-1412`): under thread mode KNI ownership becomes "a designated thread" (see §3.4); the validation logic must adjust accordingly rather than by primary process.

**Zero-regression strategy**:
- The switch defaults off; when off, all the above paths are **byte-identical** (walk the existing primary/secondary branches).
- Thread mode and primary/secondary multi-process mode are **mutually exclusive** (config-time validation: thread_mode=1 requires proc_type=primary and no further multi-process fork).
- Suggest **adding nb_threads in parallel** alongside §1.2's `nb_procs`, avoiding polluting existing multi-process semantics and reducing the regression surface.

---

## 2. Lifecycle Entry Points ff_init / ff_run

### 2.1 `ff_init` (`lib/ff_init.c:35-56`)

Signature: `int ff_init(int argc, char * const argv[])` (`ff_init.c:36`). Order:
1. `ff_load_config(argc, argv)` (`ff_init.c:39`) — parses config.ini + command line, fills `ff_global_cfg`;
2. `ff_dpdk_init(dpdk_argc, dpdk_argv)` (`ff_init.c:43`) — internally `rte_eal_init` (`ff_dpdk_if.c:1594`) + `init_lcore_conf` / `init_mem_pool` / `init_dispatch_ring` / `init_msg_ring` / `init_kni` (`ff_dpdk_if.c:1609-1621`);
3. `ff_freebsd_init()` (`ff_init.c:47`, extern declared at `ff_init.c:33`) — initializes the FreeBSD stack;
4. `ff_dpdk_if_up()` (`ff_init.c:51`) — `ff_veth_attach` attaches ports (`ff_dpdk_if.c:2747-2761`).

### 2.2 `ff_run` (`lib/ff_init.c:58-62`)

Signature: `void ff_run(loop_func_t loop, void *arg)` (`ff_init.c:59`), only delegates to `ff_dpdk_run(loop, arg)` (`ff_init.c:61`).

`ff_dpdk_run` (`ff_dpdk_if.c:2763-2774`) core:
```
rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);   // ff_dpdk_if.c:2770
rte_eal_mp_wait_lcore();                                // ff_dpdk_if.c:2771
```
i.e. **the same `main_loop` is launched on all EAL-enabled lcores**. Under the current multi-process model each process passes only its own 1 lcore to EAL (§1.4), so `mp_remote_launch` actually runs only 1 loop.

### 2.3 Current Call Count and Location (`example/main.c`)

- helloworld calls `ff_init(argc, argv)` once in `main()` (`example/main.c:128`), and `ff_run(loop, NULL)` once (`example/main.c:217`).
- **Each process's own `main()` → calls ff_init/ff_run once each**; multiple instances are achieved by an external script launching N processes with `-p 0/1/2...`.

### 2.4 Feasibility and API-Compatibility Evaluation of per-Thread Calling ff_init/ff_run Once Each

> Extension-point analysis, not an existing implementation.

- **API signature compatibility**: `ff_init` (`ff_init.c:36`)/`ff_run` (`ff_init.c:59`) signatures carry no process/thread identifier, so no signature change is needed for multiple pthreads to call once each — **API-layer compatible**.
- **The main obstacle is the global singleton state** (located by this agent; dovetails with the explorer-globalstate dimension):
  - `rte_eal_init` (`ff_dpdk_if.c:1594`) **can only be called once per process** — per-thread calls would fail on second init. So EAL/lcore allocation must be reworked as "initialize only once + one lcore per thread" inside ff_init; simply having each thread run a whole ff_init is not possible.
  - `lcore_conf` (`ff_dpdk_if.c:123`) is a **global single instance** (not `__thread`); inside `main_loop`, `qconf = &lcore_conf` is shared by all launched lcores — under multi-thread it must become a **per-lcore/per-thread array or `RTE_PER_LCORE`**, otherwise the multi-stack instances trample each other.
  - `veth_ctx[RTE_MAX_ETHPORTS]` (`ff_dpdk_if.c:179`) global singleton, `ff_global_cfg` global singleton — likewise need per-instance-ization.
  - `pcurthread` (`ff_api.h:55`, `extern __thread struct thread *pcurthread`) **is already thread-local**, and thread-context APIs like `ff_switch_curthread`/`ff_restore_curthread`/`ff_adapt_user_thread_add` (`ff_api.h:481-487`) already exist — proving the FreeBSD-side curthread already has per-thread carrying capacity, a reusable positive signal.
- **Conclusion tendency**: `ff_run` running one `main_loop` per thread is **feasible at the interface layer** (`rte_eal_mp_remote_launch` is inherently the "one thread per lcore running main_loop" semantics, see `ff_dpdk_if.c:2770`); the real resistance is that the global singleton state listed in §3.1 must first be per-instance-ized. The suggested native shape is: **ff_init called only once (completing EAL + N per-lcore instance states), with `rte_eal_mp_remote_launch` naturally running one main_loop per lcore**, rather than "each pthread manually calling a full ff_init again".

---

## 3. KNI / IPC / Toolchain Ownership

### 3.1 Global Singleton State Inventory (KNI/IPC-related, located by this agent)

| Variable | Line | Singleton-ness | Multi-thread impact |
|---|---|---|---|
| `struct lcore_conf lcore_conf` | `ff_dpdk_if.c:123` | **global single, not __thread** | fatal shared point for multi-stack instances |
| `veth_ctx[RTE_MAX_ETHPORTS]` | `ff_dpdk_if.c:179` | global singleton | port→instance mapping needs per-instance |
| `msg_ring[]` (IPC) | `ff_dpdk_if.c:649-667` | ring array built by nb_procs | semantics follow nb_procs; thread mode must build by thread |

### 3.2 KNI Runtime Primary-Only Gating

- `ff_kni_init` (`ff_dpdk_kni.c:376-420`): the `kni_stat` global part is allocated only under `RTE_PROC_PRIMARY` (`ff_dpdk_kni.c:379-386`); `kni_rp`/`tcp_port_bitmap`/`udp_port_bitmap` are named by `rte_lcore_id()` (`ff_dpdk_kni.c:388-419`) — i.e. KNI rings already carry the lcore dimension.
- `ff_kni_alloc` (`ff_dpdk_kni.c:422-449+`): `kni_stat[port_id]` allocation likewise primary-only (`ff_dpdk_kni.c:426`).
- Main-loop KNI handling (`ff_dpdk_if.c:2660-2664`): under `#ifdef FF_KNI`, `ff_kni_process` is called only when `enable_kni && rte_eal_process_type()==RTE_PROC_PRIMARY`.
- Config validation (`ff_config.c:1392-1412`, see §1.5): KNI requires the primary lcore in every port's lcore_list.

### 3.3 IPC / Toolchain Dependency on secondary (`tools/`)

- `tools/compat/ff_ipc.c`: `ff_ipc_init` (`ff_ipc.c:54-80`) **hardcodes `--proc-type=secondary`** (`ff_ipc.c:67`) + `-c1` (`ff_ipc.c:66`), finds the message pool built by primary via `rte_mempool_lookup(FF_MSG_POOL)` (`ff_ipc.c:77`), selects the target process's ring with `ff_proc_id` (`ff_ipc.c:42`, set by `ff_set_proc_id`, `ff_ipc.c:44-52`).
- i.e. **sysctl/netstat/ifconfig/ipfw/ndp/route/arp/ngctl tools** (`tools/` subdirectories) all attach into primary's shared memory as **secondary processes**, communicating with the target stack instance via `msg_ring` (built `ff_dpdk_if.c:649-667`, consumed `process_msg_ring` `ff_dpdk_if.c:2278`/`2699`, handled `handle_msg` `ff_dpdk_if.c:2225`). The toolchain **strongly depends on the multi-process secondary model**.

### 3.4 KNI / Tool Ownership Conclusion (this agent's conclusion)

> Extension-point analysis.

- **KNI ownership**: under native multi-thread share-nothing, there is no more "primary process" concept; KNI should be **exclusively held by a single designated thread (e.g. thread 0 / instance 0)** with the KNI resources and `ff_kni_process`. The existing `kni_rp`/bitmaps are already named by `rte_lcore_id()` (`ff_dpdk_kni.c:388-419`), naturally per-lcore; but the `kni_stat` global + runtime `RTE_PROC_PRIMARY` gating (`ff_dpdk_if.c:2661`, `ff_dpdk_kni.c:379/426`) must change to "owner-thread determination" rather than `rte_eal_process_type()`. Config validation (`ff_config.c:1396-1411`) must change from "primary lcore" to "the KNI owner thread's lcore".
- **Toolchain/IPC ownership**: thread mode has **no secondary process**; the existing toolchain based on `--proc-type=secondary` (`ff_ipc.c:67`) **cannot be reused directly**. A new IPC channel is needed (e.g. exposing a compatibility layer in the primary process that external secondary processes can attach to, or changing tools to unix-socket / shared-memory direct connection to the designated thread's msg_ring). This is the biggest toolchain compatibility gap of thread mode; suggest the spec explicitly lists "thread mode needs a separate toolchain design".

---

## 4. issue #430 Application-Side Corroboration (Only Corroboration, Not a Conclusion Anchor)

Verify the combined-flag handling of SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC:

- Constant mapping: `LINUX_SOCK_CLOEXEC = LINUX_O_CLOEXEC` (`ff_syscall_wrapper.c:220`), `LINUX_SOCK_NONBLOCK = LINUX_O_NONBLOCK` (`ff_syscall_wrapper.c:221`).
- `linux2freebsd_socket_flags` (`ff_syscall_wrapper.c:672-684`): converts `LINUX_SOCK_NONBLOCK`→`SOCK_NONBLOCK` (`:675-678`) and `LINUX_SOCK_CLOEXEC`→`SOCK_CLOEXEC` (`:679-682`), returning the converted flags (`:683`). **Both high-bit flags convert correctly, handling complete.**
- `ff_socket` type conversion (`ff_syscall_wrapper.c:943`): `sa.type = linux2freebsd_socket_flags(type)`, after first stripping `SOCK_KERNEL|SOCK_FSTACK` (`:939`) — i.e. the NONBLOCK/CLOEXEC combined bits in type are handed to `sys_socket` after unified conversion (`:945`). **The SOCK_STREAM main type is unaffected; the additional flags are handled correctly.**
- `ff_accept4` (`ff_syscall_wrapper.c:1679`): `kern_accept4(curthread, s, pf, linux2freebsd_socket_flags(flags), &fp)` — accept4's flags likewise go through `linux2freebsd_socket_flags`; NONBLOCK/CLOEXEC combined-bit handling complete.

**Corroboration conclusion**: the conversion path for the application side passing `SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC` combined flags through `ff_socket`/`ff_accept4` is **complete**, proving "**application-side multi-threaded API calls are ready**" (the accept4+NONBLOCK+CLOEXEC pattern commonly used by multi-threaded servers works normally).

**Layer distinction (important)**: #430 corroborates **application-side API readiness** (an app can correctly call the socket layer from multiple threads), which is a **different layer** from this research's core "**stack-side native multi-threaded run model**" (N pthreads in one process each running an independent FreeBSD stack instance, share-nothing). The former being ready does not mean the latter is implemented — the latter's real resistance lies in the §2.4 / §3.1 global singleton state (`lcore_conf` `ff_dpdk_if.c:123` etc.) and the §3.4 KNI/toolchain ownership rework.

---

## 5. Key Findings Summary (for leader Convergence)

1. **thread-mode extension points**: the config struct (`ff_config.h:269-328`) has no thread field; `nb_procs`/`proc_id` are "process" semantics reused as "instance". Suggest **adding `nb_threads` (without changing `nb_procs` semantics) + a new opt-in switch defaulting off**; thread mode and primary/secondary multi-process are **mutually exclusive**; touch `parse_lcore_mask` (`ff_config.c:73-142`)/`proc_mask` concatenation (`ff_config.c:1151-1154`)/proc_type validation (`ff_config.c:1316-1321`)/KNI validation (`ff_config.c:1392-1412`). Zero regression via default-off switch + existing branches byte-unchanged.
2. **ff_run per-thread feasibility**: API signatures (`ff_init.c:36`/`:59`) compatible; `rte_eal_mp_remote_launch(main_loop,...)` (`ff_dpdk_if.c:2770`) is inherently "one thread per lcore running main_loop" semantics — the native shape should be **ff_init called only once (EAL + N per-lcore instances)**, not each pthread running a whole ff_init (`rte_eal_init` `ff_dpdk_if.c:1594` can only run once per process). The real resistance is the global singletons `lcore_conf` (`ff_dpdk_if.c:123`, not `__thread`), `veth_ctx` (`:179`), `ff_global_cfg` needing per-instance-ization. Positive signal: `pcurthread` already `__thread` (`ff_api.h:55`) with thread-context APIs (`ff_api.h:481-487`).
3. **KNI ownership conclusion**: under thread mode KNI should be **exclusively held by a single designated thread**; existing KNI rings already named by `rte_lcore_id()` (`ff_dpdk_kni.c:388-419`) can be per-lcore, but the `kni_stat` global + `RTE_PROC_PRIMARY` runtime gating (`ff_dpdk_if.c:2661`, `ff_dpdk_kni.c:379/426`) and config validation (`ff_config.c:1396-1411`) must change from "primary process" to "KNI owner thread".
4. **Toolchain/IPC gap**: `tools/` fully depends on `--proc-type=secondary` (`ff_ipc.c:67`) + `msg_ring` (`ff_dpdk_if.c:649-667`); thread mode has no secondary process, so the toolchain **cannot be reused directly** and needs a separately designed IPC channel — suggest the spec explicitly lists it as an independent sub-item.
5. **#430 positioning**: `linux2freebsd_socket_flags` (`ff_syscall_wrapper.c:672-684`) handles the NONBLOCK/CLOEXEC combined bits **completely**; `ff_socket` (`:943`)/`ff_accept4` (`:1679`) both go through this conversion; corroborates "**application-side multi-threaded API calls are ready**", a **different layer** from "stack-side native multi-threaded run model", not this round's conclusion anchor.
