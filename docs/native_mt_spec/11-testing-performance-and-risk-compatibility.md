# 11 Testing, Performance Baseline and Risk Compatibility

## 1. Test Strategy

### 1.1 Unit Tests (mock points)
| Target | mock/verification point |
|---|---|
| Config fork | `parse_lcore_mask` (`ff_config.c:73-142`) thread mode: given lcore_mask, assert `nb_threads`/`proc_mask`/proc_type validation correct; with thread_mode=0 output byte-identical to old version |
| lcore_conf index | `lcore_conf[rte_lcore_id()]` (`ff_dpdk_if.c:123`) different instances per thread under multi-thread |
| msg_iov_tmp TLS | after restoring `__thread` (`ff_syscall_wrapper.c:225-226`), concurrent recvmsg/sendmsg with no trampling |
| Isolation macros | `__thread`/`RTE_PER_LCORE`/array three isolation methods each independent under N threads |

### 1.2 Integration Tests
- Thread mode starts N threads each with an independent stack instance; each socket/listen/accept works normally.
- Reuse the existing example (helloworld) to start a multi-threaded server under thread_mode=1.
- VNET isolation validation: different threads bind different IPs/routes, mutually invisible (`V_in_ifaddrhead`/`V_rt_tables` isolation).

### 1.3 End-to-End (this machine's dual-NIC constraint)
- **DPDK NIC** (exclusive, IP 9.134.214.176): requires `ssh f-stack-client` to originate traffic from the peer to test thread-mode N-thread send/receive and RSS flow splitting.
- **Kernel-stack comparison**: `127.0.0.1` lo goes through the kernel stack as the comparison baseline.

### 1.4 Multi-Process Zero Regression (one-vote veto)
- Under thread_mode=0 (default), all existing multi-process use cases (primary/secondary, KNI, toolchain) behave **byte-identically**. Any regression is a gate failure.

## 2. Performance Baseline Plan

### 2.1 Comparison Groups
| Group | Configuration |
|---|---|
| G0 baseline | Current multi-process (N processes, 1 lcore each) |
| G1 target | Thread mode (1 process, N threads, 1 lcore each) |

### 2.2 Metrics
- Throughput (pps/bps, short-connection QPS + long-connection bandwidth)
- Latency (p50/p99/p999)
- CPU utilization / cycles per core
- Cache misses (perf stat, validating share-nothing cache affinity)
- Memory footprint (thread mode shares one address space; mempool/hugepages shareable; expected memory better than multi-process)

### 2.3 Test Matrix
- lcore count: 1/2/4/8 (scalability curve, validating near-linearity)
- Packet sizes: 64/512/1500B
- Connection models: short connections (accept-heavy) + long connections (throughput-heavy)

### 2.4 Pass Criteria
- Thread-mode throughput/latency ≥ 95% of multi-process mode (share-nothing should have no fundamental degradation);
- Scalability near-linear with lcore count;
- If thread mode shows obvious lock points/degradation, re-check whether any global state was not per-thread-ized (degenerating into implicit sharing).

### 2.5 Measured Results (2026-07-29, see `13-performance-baseline-measurement-report.md`)

| Configuration | median req/s | Latency | Status |
|---|---:|---:|---|
| thread_mode=1, 1 thread (lcore_mask=10) | 189,044 | 497 us | ✅ PASS |
| thread_mode=0, multi-process (lcore_mask=10) | 114,629 | 411 us | ✅ baseline |
| thread_mode=1, 2 threads (lcore_mask=30) | — | — | ❌ crash (R1) |
| thread_mode=1, 4 threads (lcore_mask=f0) | — | — | ❌ crash (R1) |

- **PERF-1 PASS**: thread_mode=1 single-thread throughput = **165%** of thread_mode=0 (far above the 95% criterion).
- **PERF-2 BLOCKED**: 2/4-thread crashes due to incomplete VIMAGE isolation (R1 risk confirmed); scalability curve not measurable.

## 3. Risk List

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | **VIMAGE fails to run in f-stack userspace** | High | CM4 PoC as early as possible; on failure switch to Route A (manual per-thread-ization); escalate to human decision. **Confirmed by test (2026-07-29)**: VIMAGE compiles (`opt_global.h:6`), 1 thread works (189k req/s), 2 threads crash at `kqueue_kevent`→`memset` SIGSEGV (fd table/kqueue per-vnet isolation incomplete). CM4 must fully implement per-vnet isolation of kqueue/fd tables. |
| R2 | **A thread crash kills the whole process** (weaker than multi-process's process-level isolation) | High | Prominently marked in spec; key deployments recommended to keep the multi-process option; in-thread exception capture/watchdog |
| R3 | Init restructure (CM5) introduces initialization-order/duplicate-init defects | High | Strictly split one-shot vs per-thread; sufficient unit tests; rollback points |
| R4 | Global state missed per-thread-ization → implicit sharing trampling | Medium-high | Verify the `03` inventory item by item; tooling/static-scan assist; observe under load |
| R5 | callout per-instance interaction with tcp_hpts timer abnormal | Medium | Runtime validation (`ff_kern_timeout.c:1252-1274`); compare against multi-process behavior |
| R6 | mempool multi-thread shared-pool capacity insufficient | Medium | Capacity formula already scales with nb_lcores (`ff_dpdk_if.c:495`); observe `rte_mempool_avail_count` under load |
| R7 | Toolchain incompatible (no secondary) | Medium | C1 keeps external tool processes (`08`); thread-ization as separate sub-item |
| R8 | Multi-process zero regression broken | High | thread_mode off by default + two modes mutually exclusive + byte-level regression gate (one-vote veto) |

## 4. Compatibility

- **API compatibility**: `ff_init`/`ff_run` signatures unchanged (`ff_init.c:36,59`); thread mode transparent to the app (`07 §4.2`).
- **Config compatibility**: `thread_mode` defaults 0; old config.ini behavior unchanged.
- **Mode mutual exclusion**: thread mode and multi-process secondary are mutually exclusive, validated at config time.
- **Backward-compatibility strategy**: opt-in, rollback per milestone.

## 5. Honest-Boundary Layering (Requires Runtime Validation, No Speculation)

| Item | Static determination | Runtime validation |
|---|---|---|
| DPDK launch N lcores / ring / mempool semantics | ✅ Determinable (`06`) | capacity/NUMA/non-EAL-thread calls |
| `mi_startup`/SYSINIT cannot run N times | ✅ Hard conclusion (`04 §1.2`) | — |
| Global-state inventory file:line | ✅ Determinable (`03`) | — |
| VIMAGE availability in f-stack userspace | ❌ Cannot determine | **Must PoC (CM4)** |
| UMA N-thread concurrent MT-safe | ❌ Cannot determine | load test |
| callout per-instance tcp_hpts interaction | ❌ Cannot determine | runtime |
