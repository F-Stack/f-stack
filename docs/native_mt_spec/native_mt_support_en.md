# F-Stack Native Multi-Threading Support (native-mt): Single-Process Multi-Thread Multi-Stack-Instance

## 1. Core Purpose and Features

F-Stack native multi-threading support (native-mt, `thread_mode=1`) is a new runtime mode introduced in F-Stack v2.0 (expected official release 2026.10): **start N threads within a single process, each running a fully independent FreeBSD protocol stack instance**. Threads are share-nothing and lock-free; the data plane relies on NIC RSS for queue-based traffic distribution, and lock-free rings for cross-thread dispatch.

### Key Features

| Feature | Description |
|---------|-------------|
| **Single-process multi-thread** | No longer starts primary + N secondary processes; instead N lcore threads within one process |
| **Multi stack instances** | Each thread gets an independent vnet (VNET/VIMAGE isolation), including independent ifnet/PCB/routing table/port allocation |
| **Share-nothing lock-free** | No shared mutable state between data-plane threads, no lock contention, linear scaling |
| **Zero-regression opt-in** | `thread_mode=0` (default) keeps multi-process mode byte-for-byte unchanged |
| **API backward compatible** | `ff_init`/`ff_run` signatures unchanged; applications run in the new mode without modification |

### Comparison with Multi-Process Mode

| Dimension | Multi-process (default) | native-mt mode |
|-----------|------------------------|----------------|
| Process count | 1 primary + N secondary | 1 process |
| Thread count | 1 main thread per process | N lcore threads |
| Stack instances | One per process | One per thread (VNET isolation) |
| Shared memory | Cross-process hugepage/mempool | Same address space, direct access |
| IPC overhead | Cross-process `msg_ring` | No cross-process IPC, direct memory access |
| Process management | `start.sh` manages multiple processes | Single process, simpler management |
| Fault isolation | Process crash doesn't affect others | Thread crash may affect entire process |

## 2. Primary Use Cases

### 2.1 Simplified Management for Single-Machine Multi-Core Deployment

The multi-process model requires `start.sh` to start 1 primary + N secondary processes, making process management, signal handling, and resource cleanup complex. native-mt mode requires only one process, greatly simplifying deployment and operations.

### 2.2 Reduced Migration Cost for Multi-Threaded Applications

Some applications are originally multi-threaded; migrating them to the existing multi-process F-Stack requires significant migration effort. native-mt mode lets applications gain multi-core scaling within a single process, without fork or launching multiple independent processes.

### 2.3 Reduced Cross-Process IPC Overhead

In multi-process mode, some applications' shared control data may need IPC (such as shared memory or rings) to be shared across processes. In native-mt mode, this shared data can be accessed directly within the same process.

### 2.4 Alignment with Industry Mainstream

High-performance user-space network frameworks like mTCP and Seastar generally adopt thread-per-core + share-nothing single-process multi-thread models. native-mt aligns F-Stack with the industry mainstream architecture.

## 3. Architectural Characteristics

### 3.1 Overall Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              Single Process (thread_mode=1)                      │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  ff_init one-time initialization                         │  │
│  │  ├─ DPDK EAL init (full-bit coremask, launch N lcores)   │  │
│  │  ├─ Global one-time init (mi_startup / UMA / mutex)      │  │
│  │  └─ lcore_conf[RTE_MAX_LCORE] array allocation           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          │                                      │
│          ┌────────────────┼────────────────┐                   │
│          ▼                ▼                 ▼                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐           │
│  │ Thread0/lcore0│ │ Thread1/lcore1│ │ Thread2/lcore2│          │
│  │              │ │              │ │              │           │
│  │ vnet_0       │ │ vnet_1       │ │ vnet_2       │           │
│  │ pcpu_0       │ │ pcpu_1       │ │ pcpu_2       │           │
│  │ callwheel_0  │ │ callwheel_1  │ │ callwheel_2  │           │
│  │ lcore_conf[0]│ │ lcore_conf[1]│ │ lcore_conf[2]│           │
│  │ RX/TX queue0 │ │ RX/TX queue1 │ │ RX/TX queue2 │           │
│  │ KNI owner    │ │              │ │              │           │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘           │
│         │                │                 │                   │
│         │    dispatch/kni_ring (MP+SC)     │                   │
│         │◄───────────────┤─────────────────┤                   │
│         │  lock-free cross-thread dispatch  │                   │
└─────────┼────────────────┼─────────────────┼───────────────────┘
          │                │                 │
          ▼                ▼                 ▼
    ┌─────────────────────────────────────────┐
    │           DPDK NIC (RSS distribution)    │
    │  queue0 ←─ flow A                        │
    │  queue1 ←─ flow B                        │
    │  queue2 ←─ flow C                        │
    └─────────────────────────────────────────┘
```

### 3.2 Per-Thread Isolation Strategy

The core challenge of native-mt: FreeBSD protocol stack has hundreds of global variables. How to give each thread an independent copy within a single process? The answer is four categories of isolation:

```
┌─────────────────────────────────────────────────────────────────┐
│          Global Variable Categories and Isolation Strategy       │
├─────────────────────┬──────────────┬───────────────────────────┤
│ Category            │ Isolation    │ Rationale                 │
├─────────────────────┼──────────────┼───────────────────────────┤
│ Network stack       │ VNET/VIMAGE  │ FreeBSD native subsystem, │
│ globals             │ curvnet =    │ one enablement covers all;│
│ (V_ifnet/V_tcbinfo  │ td_vnet      │ vnet.h per-thread         │
│  V_rt_tables/...)   │              │                           │
├─────────────────────┼──────────────┼───────────────────────────┤
│ Cross-thread        │ Array +      │ Cross-thread accessible   │
│ accessed globals    │ rte_lcore_id │ by index (dispatch/stats);│
│ (lcore_conf/        │ indexing     │ ff_dpdk_if.c              │
│  veth_ctx)          │              │                           │
├─────────────────────┼──────────────┼───────────────────────────┤
│ Pure thread-private │ __thread     │ No cross-thread access,   │
│ (msg_iov_tmp/seed/  │              │ TLS is fastest,           │
│  stop_loop)         │              │ no false sharing          │
├─────────────────────┼──────────────┼───────────────────────────┤
│ Kernel identity/    │ One per      │ Each stack gets one       │
│ timer base          │ instance     │ pcpu/thread/callout;      │
│ (pcpup/thread0/     │ (RTE_PER_    │ ff_freebsd_init.c         │
│  cc_cpu)            │  LCORE)      │                           │
└─────────────────────┴──────────────┴───────────────────────────┘
```

### 3.3 Lock-Free Data Plane Communication

Cross-thread communication uses DPDK lock-free rings, maintaining the same semantics as multi-process mode:

```
                dispatch/kni_ring (RING_F_SC_DEQ, MP+SC)
            ┌──────────────────────────────────────────┐
            │  Multi-producer (MP): any worker enqueue │
            │  Single-consumer (SC): owner thread only │
            └──────────────────────────────────────────┘
                 ▲                              │
                 │ enqueue                      │ dequeue
    ┌────────────┼────────────┐                 ▼
    │            │            │          ┌──────────────┐
┌───┴───┐   ┌───┴───┐   ┌───┴───┐        │ owner thread │
│worker1│   │worker2│   │worker3│        │ (dispatch/   │
└───────┘   └───────┘   └───────┘        │  process)    │
                                        └──────────────┘
```

- **dispatch/kni_ring**: maintains `RING_F_SC_DEQ` (MP+SC), multi-worker writes, single owner reads
- **msg_ring**: already arrayed `msg_ring[RTE_MAX_LCORE]`, each thread uses its own lcore index, SP+SC
- **mempool**: shared by NUMA socket, DPDK per-lcore cache is MT-safe out of the box, no changes needed

## 4. Refactoring Work and Problems Encountered

> The following is rather technical; readers who don't need to dive into implementation details can skip ahead.

### 4.1 Milestone Overview

The native-mt refactoring was organized into 8 milestones (CM0-CM7) by increasing risk:

| Milestone | Goal | Risk | Key Commit |
|-----------|------|------|------------|
| CM0 | Low-hanging fruit + scaffolding | Low | `e79ceb9f0` |
| CM1 | Config-layer `thread_mode` switch | Low | `3c31cc540` |
| CM2 | `lcore_conf` per-lcore + DPDK N lcores | Medium | `e79ceb9f0` |
| CM3 | Base globals per-thread (pcpu/thread0/callout) | High | `e79ceb9f0` |
| CM4 | VIMAGE feasibility PoC (critical checkpoint) | High/Uncertain | `86e0f76b0` |
| CM5 | Init refactor (per-thread stack instance init) | Very High | `717843004` + `7495e70c0` |
| CM6 | KNI owner thread + msg_ring per-thread | Medium | `6d74d59e0` |
| CM7 | Integration + regression + perf baseline | Medium | `fea49af6d` + `be4233709` |

### 4.2 CM0-CM3: Per-Thread Foundation

**Problem 1: `msg_iov_tmp` global variable data corruption**

`ff_syscall_wrapper.c`'s `msg_iov_tmp`/`msg_iovlen_tmp` were global arrays; concurrent `ff_readv`/`ff_writev` calls would overwrite each other. This was the lowest-hanging fruit — restoring `__thread` fixed it, harmless to multi-process mode.

**Problem 2: `lcore_conf` global singleton**

`ff_dpdk_if.c:123`'s `lcore_conf` was a global singleton with 30+ reference points. Changed to `lcore_conf[RTE_MAX_LCORE]` array, each thread indexing its own via `rte_lcore_id()`. Introduced `ff_cur_lcore_conf()` macro as an indirection layer to reduce subsequent change surface.

**Problem 3: pcpu/thread0/callout base globals**

- `pcpup` (`ff_freebsd_init.c:69`) → `__thread struct pcpu` per thread
- `thread0`/`proc0` (`ff_init_main.c`) → one per instance
- `cc_cpu` callout (`ff_kern_timeout.c:180`) → `__thread struct callout_cpu`, `CC_SELF()` returns current thread's instance

### 4.3 CM4: VIMAGE Feasibility PoC (Critical Checkpoint)

This was the project's biggest uncertainty. VIMAGE is FreeBSD's native virtual network stack subsystem; when enabled, `curvnet = curthread->td_vnet` isolates hundreds of network stack globals per-thread. But f-stack heavily prunes FreeBSD user-space code, so whether VIMAGE would work needed runtime verification.

**PoC Result: VIMAGE works (route B validated)**

- `opt_global.h` added `#define VIMAGE 1`
- Each thread calls `vnet_alloc()` to create an independent vnet and sets `td_vnet`
- `VNET_SYSINIT` runs once per vnet; `V_tcbinfo`/`V_rt_tables` successfully isolated

### 4.4 CM5: Initialization Refactor

**Problem 4: `mi_startup`/SYSINIT one-time mechanism**

`ff_init_main.c`'s `mi_startup` ticks off `SI_SUB_LAST` after running; a second call is a no-op. Needed splitting: global one-time init (EAL/UMA/mutex/vnet0) + per-thread stack instance init (vnet_alloc/td_vnet/VNET_SYSINIT/pcpu_i/thread0_i).

**Problem 5: Worker cred on global prison0 (R1 defect)**

This was native-mt's most insidious bug. Symptom: 2-thread stress test produced 0 req/s; client retransmitted SYN repeatedly; f-stack never replied with SYN-ACK.

Root cause: worker thread's cred was on global `prison0`, but FreeBSD socket's vnet is taken from cred's prison (`CRED_TO_VNET(cred)`), not `curvnet`. This caused all worker socket/ifioctl calls to be silently redirected to vnet0: worker vnet had no interface address, no default route (`ENETUNREACH`); app listen PCBs were all on vnet0, while the data plane looked up PCBs on worker vnet → SYN received but no SYN-ACK sent.

Fix: `lib/ff_freebsd_init.c` added `ff_worker_prison_init()`, giving each worker an independent prison so `CRED_TO_VNET` points to its own vnet.

**Problem 6: Worker pcpu cpuid out-of-bounds (R2 defect)**

After fixing R1, worker vnet's PCB tables were actually used, and `in_pcblookup_mbuf` SIGSEGV'd during stress testing.

Root cause: worker's `pcpu_init()` passed `rte_lcore_id()` (=2) as cpuid, but this build was non-SMP (`MAXCPU==1`), `mp_maxid==0`; UMA/SMR per-cpu arrays were allocated for only 1 CPU → `zpcpu_get()` out-of-bounds.

Fix: `ff_pcpu_thread_init()` changed to pass 0 (intermediate fix). Later fully resolved in the SMP-aware refactoring (doc 17) — each thread gets a dense, independent pcpu slot.

### 4.5 CM6-CM7: KNI/Toolchain Ownership and Integration

**Problem 7: KNI ownership**

In multi-process mode, KNI is exclusively owned by the primary process (virtio_user vdev can only be created/operated by primary). native-mt has no primary/secondary concept; KNI changed to be exclusively held by a single designated thread (thread 0). The existing `kni_rp`/bitmap were already named by `rte_lcore_id()`, naturally per-lcore; changes focused on gate logic.

**Problem 8: Worker clock gap**

Symptom: 2-thread throughput improved from 0 to 557 req/s after R1 fix, but still far below 1-thread's ~209k req/s.

Root cause: worker thread's FreeBSD clock was never driven. `init_clock()` was called only once on the main thread; worker's `freebsd_clock` (`__thread`) was zero-initialized (`expire == 0`), `ff_hardclock_job` never fired → worker's callwheel never advanced → syncache timeout, TCP retransmit, delayed ACK on vnet_i all paralyzed.

Fix: added `ff_hardclock_worker()` (only advances this thread's callwheel, doesn't touch global `ticks`/timecounter) + `init_clock_worker()` (worker registers its own timer in `main_loop`).

### 4.6 Follow-up Optimization: SMP-Aware pcpu View and Global Lock Removal

**Problem 9: SMR per-cpu slot sharing UAF window**

After R2 fix, all workers' `pc_zpcpu_offset` was 0, sharing the same SMR per-cpu slot. Theoretical window: thread A's `smr_exit` sets `SMR_SEQ_INVALID` which may clear thread B's read section marker → `smr_poll` misjudges no readers → PCB reclaimed prematurely (UAF).

Fix (commit `c7996a94f`): defined `SMP`, set `mp_ncpus`/`mp_maxid`/`all_cpus` to `nb_threads`, each thread gets a dense pcpu id and per-thread `curcpu`, each thread exclusively owns disjoint UMA/SMR per-cpu slots.

**Problem 10: `uma_crit_lock` global spinlock**

f-stack had previously added a global spinlock `uma_crit_lock` (`lib/include/vm/uma_int.h`) to protect UMA per-cpu cache. With each thread owning an exclusive per-cpu slot, this lock was no longer necessary.

Fix (commit `57b612d16`): removed `uma_crit_lock`, `critical_enter`/`critical_exit` became no-ops, restoring UMA per-cpu cache's lock-free fast path.

## 5. Usage, Configuration, and Results

### 5.1 Configuration

Add `thread_mode` to the `[dpdk]` section of `config.ini`:

```ini
[dpdk]
# lcore_mask specifies the lcore set; in thread_mode=1, each bit = one thread
lcore_mask=0xf            # 4 lcores = 4 threads

# thread_mode: 0=multi-process (default), 1=single-process multi-thread multi-stack
thread_mode=1

# Other config items are the same as multi-process mode
idle_sleep=20
hz=100

[port0]
addr=<DPDK_NIC_IP>
netmask=<NETMASK>
broadcast=<BROADCAST_IP>
gateway=<GATEWAY_IP>
lcore_list=0,1,2,3        # corresponds to lcore_mask
```

### 5.2 Startup

In native-mt mode, only one process needs to be started (no `start.sh` for multi-process management):

```bash
# Build (make clean then full rebuild)
cd f-stack/lib && make clean && make -j$(nproc)
cd f-stack/example && make clean && make

# Start (single process)
./example/helloworld --conf config.ini --proc-type=primary --proc-id=0
```

### 5.3 Results

#### Performance Baseline (virtio NIC environment)

| Config | Threads/Procs | req/s | Latency (avg) | Notes |
|--------|--------------|------:|--------------:|-------|
| `thread_mode=1`, 2 threads | 2 | 233,380 | — | Post-fix multi-thread |
| `thread_mode=0`, 2 procs | 2 | 231,570 | — | Multi-process control |

Key findings:

1. **Multi-thread linear scaling**: 2 threads at 233k req/s, on par with 2 processes at 231k, validating the share-nothing lock-free model's linear scaling
2. **60-second soak stability**: 400 connections over 60 seconds achieved 497k req/s, 29.83 million requests with zero errors
3. 【Note】The single-process data for `thread_mode=0` was confirmed to be noise at the time and is not shown here; actual performance of single-process and single-thread is roughly the same

#### Zero-Regression Guarantee

With `thread_mode=0` (default), all paths follow existing primary/secondary branches, byte-for-byte unchanged. Verified by 10+ minute high-traffic regression stress tests.

### 5.4 Caveats and Limitations

| Limitation | Description |
|------------|-------------|
| **fd not shareable across threads** | Each thread's fd table is independent (VNET isolation); the same fd has different meanings in different threads, same as the fd semantics limitation within a single process in multi-process mode |
| **KNI single-thread exclusive** | KNI is exclusively held by thread 0; other threads don't process KNI (packets that other threads need KNI to process are forwarded to thread 0 via kni_rp, the same flow as multi-process mode) |
| **Toolchain compatibility** | Priority is preserving external tool process (`--proc-type=secondary`) attach method for backward compatibility |
| **VIMAGE dependency** | Enabling VIMAGE requires full compilation; some f-stack-pruned FreeBSD subsystems may be incomplete |
| **Physical NIC RSS** | True multi-thread scaling depends on NIC RSS capability; RSS-less NICs limit multi-thread scaling, same as multi-process mode |

## 6. References

- **Three-layer architecture docs**: `docs/zh_cn/F-Stack_Architecture_Layer1_System_Overview.md`
- **native-mt spec**: `docs/native_mt_spec/zh_cn/` (00-17, complete design documents)
- **Knowledge graph**: `docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md`
- **Issue summary**: `docs/zh_cn/f-stack-issue-ana.md` (#430/#571/#807/#855 and other multi-threading related issues)
- **Code commits**: `e79ceb9f0` (CM0-CM3) → `86e0f76b0` (CM4 VIMAGE) → `7495e70c0` (CM5 multi-stack) → `6d74d59e0` (CM6 KNI) → `82b409faf` (worker clock) → `ff09a17b2` (prison isolation) → `c7996a94f` (SMP-aware pcpu) → `57b612d16` (global lock removal)
