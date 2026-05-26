# F-Stack LD_PRELOAD Lock-Free Ring Queue Transformation — Requirements Specification

> **Document ID**: SPEC-001  
> **Version**: v1.0 Draft  
> **Date**: 2026-03-27  
> **Status**: Reviewed by fengbojiang 2026-03-27, overall direction is fine, minor details adjusted  
> **Scope**: `/data/workspace/f-stack/adapter/syscall/`

---

## 1. Problem Domain Analysis

### 1.1 Current Architecture Overview

The F-Stack LD_PRELOAD module (`libff_syscall.so`) intercepts application socket system calls and forwards them to the fstack instance process for handling. IPC communication between the APP side and the fstack side is conducted through `ff_so_context` structures in **DPDK Hugepage shared memory**.

The current synchronization mechanism uses **three-layer synchronization**:

| Layer | Mechanism | Location |
|---|---|---|
| State Machine | `FF_SC_IDLE → FF_SC_REQ → FF_SC_REP → FF_SC_IDLE` | `ff_socket_ops.h:73-75` |
| Mutex Lock | `rte_spinlock_t lock` | `ff_socket_ops.h:103` |
| Semaphore | `sem_t wait_sem` (POSIX cross-process semaphore) | `ff_socket_ops.h:111` |

### 1.2 Semaphore Mechanism Performance Bottlenecks

#### 1.2.1 Kernel-Mode System Call Overhead

POSIX semaphores `sem_wait()`/`sem_post()` are implemented via `futex` system calls on Linux. Each invocation involves:
- **User-mode to kernel-mode switch**: approximately 100-200ns overhead
- **futex wakeup path**: `FUTEX_WAKE` needs to wake up threads in the wait queue, involving the kernel scheduler
- **Cross-process semaphores** (`sem_init(&sc->wait_sem, 1, 0)` with `pshared=1`) add additional shared memory futex lookup overhead

Under high-frequency syscall scenarios (e.g., Nginx's short epoll_wait timeout), these overheads are amplified.

#### 1.2.2 sem_timedwait Timeout Precision Issues

The current code uses `CLOCK_REALTIME` for timeout calculation (`ff_hook_syscall.c:2194-2207`):
```c
clock_gettime(CLOCK_REALTIME, &abs_timeout);
abs_timeout.tv_sec += timeout / 1000;
abs_timeout.tv_nsec += (timeout % 1000) * 1000 * 1000;
```
- `CLOCK_REALTIME` is affected by NTP time adjustments, potentially causing unexpected timeouts or delays
- The minimum wakeup granularity of `sem_timedwait` is affected by the kernel scheduler tick (typically 1-4ms)
- Race condition after timeout: comments explicitly state (lines 2224-2229) that after `sem_timedwait` times out, fstack may still `sem_post`, causing the next `sem_timedwait` to return immediately with stale results

#### 1.2.3 O(n) Request Traversal

`ff_handle_each_context()` (`ff_socket_ops.c:569-638`) traverses **all** `ff_so_context` entries in each polling cycle:
```c
for (i = 0; i < ff_so_zone->count; i++) {
    struct ff_so_context *sc = &ff_so_zone->sc[i];
    if (ff_so_zone->inuse[i] == 0) continue;
    if (sc->status == FF_SC_REQ) {
        ff_handle_socket_ops(sc);
    }
}
```
When `SOCKET_OPS_CONTEXT_MAX_NUM = 32`, each cycle performs dirty reads on the status field of all 32 sc entries, even though the vast majority are in IDLE state.

#### 1.2.4 Fragility of the alarm_event_sem Compensation Mechanism

`alarm_event_sem()` (`ff_hook_syscall.c:3235-3252`) is a compensation mechanism for handling the case where APP enters `sem_wait` but fstack hasn't called `sem_post` in time. However, this mechanism is only actually called in `main_stack.c:75`, while being commented out in the remaining 4 example programs, indicating it is unstable and difficult to use correctly.

#### 1.2.5 Mode Fragmentation

Two mutually exclusive epoll_wait implementation paths currently exist:
- **Semaphore mode** (default): uses `sem_wait`/`sem_post`, low CPU utilization but high latency
- **Polling mode** (`FF_PRELOAD_POLLING_MODE`): pure busy-poll, low latency but 100% CPU

The two modes are separated by compile-time macros, cannot be switched at runtime, and polling mode does not support `FF_KERNEL_EVENT`.

---

## 2. Functional Requirements

### FR-001: Lock-Free Request Queue

**Description**: Replace `sem_t wait_sem` with DPDK `rte_ring` (SPSC mode) for APP → fstack request notification.

**Detailed Requirements**:
- APP side enqueues the requested `ff_so_context` pointer into the request ring
- fstack side dequeues from the request ring to obtain pending requests (replacing O(n) traversal)
- Ring is allocated on DPDK Hugepage shared memory, supporting cross-process access

**Affected Files**: `ff_socket_ops.h`, `ff_so_zone.c`, `ff_hook_syscall.c`, `ff_socket_ops.c`

### FR-002: Lock-Free Response Queue

**Description**: Replace `sem_post`/`sem_wait` with DPDK `rte_ring` (SPSC mode) for fstack → APP response notification.

**Detailed Requirements**:
- fstack side enqueues the `ff_so_context` pointer into the response ring after processing a request
- APP side dequeues from the response ring to obtain processing results (replacing `sem_wait`/`sem_timedwait`)
- Supports timeout waiting (based on `rte_rdtsc()` high-precision timing)

**Affected Files**: `ff_hook_syscall.c`, `ff_socket_ops.c`

### FR-003: Configurable Wait Strategy

**Description**: Provide three configurable APP-side wait strategies, replacing the current binary choice between semaphore blocking and compile-time polling mode.

| Strategy | Description | Use Case |
|---|---|---|
| **busy-poll** | Continuously calls `rte_ring_dequeue` | Ultra-low latency, 100% CPU |
| **yield-poll** | Calls `rte_pause()` / `sched_yield()` after each dequeue failure | Low latency, moderate CPU usage |
| **eventfd** | Blocks via `eventfd` after dequeue failure | Low CPU usage, slightly higher latency |

**Detailed Requirements**:
- Wait strategy is configurable at runtime (via environment variable or configuration), not compile-time macros
- Default strategy is `yield-poll`, balancing latency and CPU usage

### FR-004: Replace alarm_event_sem

**Description**: Use ring mechanism to replace the current unstable `alarm_event_sem()` compensation mechanism.

**Detailed Requirements**:
- In ring mode, after fstack finishes processing blocking operations (kevent timeout=NULL, epoll_wait timeout=-1), it enqueues to the response ring regardless of whether events were returned
- Eliminate the `need_alarm_sem` global variable and its complex set/clear logic

**Affected Files**: `ff_hook_syscall.c`, `ff_socket_ops.c`, `ff_adapter.h`, `main_stack.c`

### FR-005: ff_handle_each_context Optimization

**Description**: Change fstack-side O(n) sc traversal to O(1) ring dequeue.

**Detailed Requirements**:
- `ff_handle_each_context()` changed to batch dequeue from request ring (`rte_ring_dequeue_burst`)
- Eliminate holding of the `ff_so_zone->lock` global spinlock (currently held throughout the entire loop)
- Maintain the behavior of multiple polling iterations within the `pkt_tx_delay` time window

**Affected Files**: `ff_socket_ops.c`

### FR-006: Backward Compatibility

**Description**: Control switching between old and new schemes via the compile macro `FF_USE_RING_IPC`.

**Detailed Requirements**:
- When macro `FF_USE_RING_IPC` is defined, use the lock-free ring scheme
- When not defined, maintain the current semaphore scheme unchanged
- The old scheme code can be removed after the new scheme is stabilized

---

## 3. Non-Functional Requirements

### NFR-001: Latency

| Metric | Current Baseline (sem) | Target (ring) |
|---|---|---|
| Single syscall RTT | 2-5 μs | < 1 μs |
| epoll_wait wakeup latency | 2-10 μs | < 2 μs |
| Timeout precision | Millisecond level | Microsecond level |

### NFR-002: Throughput

- In Nginx 600B body keep-alive benchmarks, ring scheme RPS must not be lower than sem scheme
- With the same number of CPU cores, ring scheme throughput improvement ≥ 10%

### NFR-003: CPU Usage

- In `yield-poll` mode, idle CPU usage must not exceed 2x that of sem scheme
- In `eventfd` mode, idle CPU usage must be on par with sem scheme
- In `busy-poll` mode, 100% CPU is allowed (consistent with existing `FF_PRELOAD_POLLING_MODE` behavior)

### NFR-004: Memory Overhead

- Per fstack instance additional memory overhead < 64KB (2 rings × 64 entries × cache line)
- Ring structures are allocated on Hugepage, not increasing regular memory usage

### NFR-005: Maintainability

- New code additions < 500 lines (excluding tests and documentation)
- Maintain existing code style (GNU C, 4-space indentation, BSD function naming)
- Critical paths have comments explaining ring operation semantics

---

## 4. Constraints

### C-001: Runtime Mode Compatibility

The new scheme must be compatible with the following 5 runtime modes:

| Mode | Compile Macro | Current State | Ring Scheme Requirement |
|---|---|---|---|
| PIPELINE (default) | None | Semaphore sync | Dual ring replacement |
| RTC (thread_socket) | `FF_THREAD_SOCKET` | Per-thread independent sc | Per-thread independent ring pair |
| FF_KERNEL_EVENT | `FF_KERNEL_EVENT` | Simultaneous fstack + kernel epoll | Ring dequeue + linux_epoll_wait |
| FF_MULTI_SC | `FF_MULTI_SC` | Similar to SO_REUSEPORT | Multiple ring zones |
| FF_PRELOAD_POLLING_MODE | `FF_PRELOAD_POLLING_MODE` | Pure polling | Unified as busy-poll strategy |

### C-002: Shared Memory Requirements

- Rings must be allocated on DPDK Hugepage (`rte_ring_create` uses `rte_memzone_reserve`)
- Ring names must be globally unique (format: `ff_sc_req_ring_%d` / `ff_sc_rsp_ring_%d`)
- APP side looks up already-created rings via `rte_ring_lookup`

### C-003: DPDK Version Compatibility

- Based on the DPDK version currently used by F-Stack (version in the `dpdk/` directory)
- Uses `rte_ring` SPSC mode (`RING_F_SP_ENQ | RING_F_SC_DEQ`)

### C-004: Build System

- New compile macro `FF_USE_RING_IPC` controlled in `Makefile`
- No new external dependencies introduced (only uses existing DPDK libraries)

### C-005: Error Handling

- Ring full (enqueue failure): log error, wait and retry
- Ring creation failure: fall back to semaphore scheme (if `FF_USE_RING_IPC` is enabled)
- Abnormal process exit: residual sc pointers in ring need cleanup during detach

---

## 5. Acceptance Criteria

### AC-001: Functional Acceptance

- [ ] All 5 helloworld example programs compile and run correctly
  - `helloworld_stack`
  - `helloworld_stack_thread_socket`
  - `helloworld_stack_epoll`
  - `helloworld_stack_epoll_thread_socket`
  - `helloworld_stack_epoll_kernel`
- [ ] After compiling with `FF_USE_RING_IPC`, all example echo servers correctly respond to client requests
- [ ] After compiling without `FF_USE_RING_IPC`, behavior is completely identical to before modification

### AC-002: Performance Acceptance

- [ ] Single syscall RTT ≤ 1μs under ring scheme (yield-poll mode)
- [ ] Nginx 600B body keep-alive RPS ≥ sem scheme performance
- [ ] All three wait strategies can be correctly switched, CPU usage meets NFR-003

### AC-003: Stability Acceptance

- [ ] 24-hour continuous operation with no memory leaks (verified via DPDK memzone statistics)
- [ ] No deadlocks or data corruption under high concurrency (32 APP threads)
- [ ] After APP process abnormal exit, fstack can correctly clean up residual requests in ring

### AC-004: Code Quality

- [ ] No new compilation warnings (`-Wall -Werror`)
- [ ] All new functions have comments describing parameters and return values
- [ ] Modified functions maintain original code style

---

## 6. Semaphore Code Location Index

> The following table lists all semaphore-related code points that need to be modified or removed in the ring scheme.

### 6.1 Semaphore API Calls

| Call | File | Line | Description |
|---|---|---|---|
| `sem_init` | `ff_so_zone.c` | 101 | Initialize cross-process semaphore |
| `sem_timedwait` | `ff_hook_syscall.c` | 2265 | epoll_wait timeout waiting |
| `sem_wait` | `ff_hook_syscall.c` | 2270 | epoll_wait infinite waiting |
| `sem_timedwait` | `ff_hook_syscall.c` | 2555 | kevent timeout waiting |
| `sem_wait` | `ff_hook_syscall.c` | 2558 | kevent infinite waiting |
| `sem_post` | `ff_hook_syscall.c` | 3244 | alarm compensation wakeup |
| `sem_post` | `ff_socket_ops.c` | 557 | fstack-side completion notification |

### 6.2 Semaphore Control Variables

| Variable | File | Line | Description |
|---|---|---|---|
| `sem_flag` | `ff_socket_ops.c` | 20 | Controls whether to sem_post |
| `sem_flag` assignment | `ff_socket_ops.c` | 313-364 | Set after epoll_wait/kevent returns |
| `sem_flag` read | `ff_socket_ops.c` | 551, 555 | Decides whether to wake up APP |
| `need_alarm_sem` | `ff_hook_syscall.c` | 248 | alarm compensation flag |
| `need_alarm_sem` set | `ff_hook_syscall.c` | 2234, 2534 | Set before entering sem_wait |
| `need_alarm_sem` clear | `ff_hook_syscall.c` | 2276, 2564, 3245 | Clear after sem_wait returns/alarm |

### 6.3 Structure Members

| Member | File | Line | Description |
|---|---|---|---|
| `sem_t wait_sem` | `ff_socket_ops.h` | 111 | Needs to be replaced with ring-related fields |
| `#include <semaphore.h>` | `ff_socket_ops.h` | 5 | Can be removed under ring scheme |

---

## Appendix A: Glossary

| Term | Description |
|---|---|
| **sc** | Abbreviation for `ff_so_context`, the communication context between APP and fstack |
| **SPSC** | Single Producer Single Consumer mode |
| **RTT** | Round-Trip Time, the complete round-trip time from request to response |
| **futex** | Fast userspace mutex primitive provided by the Linux kernel, underlying implementation of sem_wait |
| **Hugepage** | Large page memory used by DPDK, shared across processes |
| **rte_ring** | Lock-free ring queue implementation provided by DPDK |
| **drain_tsc** | Time window of fstack's polling loop, controlled by `pkt_tx_delay` parameter |

## Appendix B: Reference Documents

1. F-Stack adapter/syscall/README.md — Existing LD_PRELOAD module documentation
2. DPDK rte_ring API — https://doc.dpdk.org/api/rte__ring_8h.html
3. VPP memif — https://docs.fd.io/vpp/21.06/dc/dea/libmemif_doc.html
4. VPP svm_msg_q — FD.io VPP Session Layer shared memory message queue
5. F-Stack three-layer architecture documentation — `/data/workspace/f-stack/docs/`
