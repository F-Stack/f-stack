# F-Stack LD_PRELOAD Lock-Free Ring Queue Transformation — Test Specification

> **Document ID**: SPEC-004  
> **Version**: v1.0 Draft  
> **Date**: 2026-03-27  
> **Status**: Pending Review  
> **Prerequisite Documents**: SPEC-001 Requirements Specification, SPEC-002 Architecture Design Document, SPEC-003 Interface Specification

---

## 1. Overview

This document defines the complete test strategy for migrating from semaphore synchronization to the DPDK `rte_ring` lock-free ring queue scheme, covering:

- Functional testing: Verify correctness of all socket operations under ring mode
- Performance benchmarking: Quantify performance improvements of ring mode vs sem mode
- Regression testing: Ensure all 5 helloworld example programs pass
- Stress testing: High-concurrency, long-running stability verification
- Nginx integration validation: Real-world application scenario verification

---

## 2. Test Environment Requirements

### 2.1 Hardware Requirements

| Item | Minimum Configuration | Recommended Configuration |
|------|---------|---------|
| CPU | 4-core x86_64 | 8+ core x86_64 (SSE4.2 support) |
| Memory | 4GB + 2GB Hugepage | 16GB + 4GB Hugepage |
| NIC | DPDK-compatible (Intel 82599/X520/X710) | Dual-port 10GbE |
| Client | Separate physical machine/VM | Separate physical machine + wrk/ab tools |

### 2.2 Software Requirements

| Item | Version |
|------|------|
| OS | Linux 4.15+ (Ubuntu 18.04/20.04/22.04, CentOS 7/8) |
| GCC | 7.0+ |
| DPDK | Version matching F-Stack (detected via pkg-config) |
| F-Stack | Current development branch |
| wrk | 4.1.0+ |
| ab (Apache Bench) | 2.3+ |
| perf | Linux perf tools |
| Nginx | 1.25+ (with F-Stack adaptation patches) |

### 2.3 Compile Configuration Matrix

All tests must be executed under the following compile configuration combinations:

| Config # | `FF_USE_RING_IPC` | `FF_PRELOAD_POLLING_MODE` | `FF_THREAD_SOCKET` | `FF_KERNEL_EVENT` | `FF_MULTI_SC` |
|---------|-------------------|--------------------------|--------------------|--------------------|---------------|
| C1 | ✅ | ❌ | ❌ | ❌ | ❌ |
| C2 | ✅ | ❌ | ❌ | ❌ | ✅ |
| C3 | ✅ | ❌ | ✅ | ❌ | ❌ |
| C4 | ✅ | ❌ | ❌ | ✅ | ❌ |
| C5 (control) | ❌ | ❌ | ❌ | ❌ | ❌ |
| C6 (control) | ❌ | ✅ | ❌ | ❌ | ❌ |
| C7 (mutual exclusion) | ✅ | ✅ | — | — | — |

**C7** configuration is expected to fail compilation (mutual exclusion check in effect).

---

## 3. Functional Testing

### 3.1 Basic Socket Operation Tests

| Test ID | Test Name | Operation Sequence | Expected Result | Priority |
|---------|---------|---------|---------|--------|
| FT-001 | socket create | `socket(AF_INET, SOCK_STREAM, 0)` | Returns fd > 0 | P0 |
| FT-002 | socket create (UDP) | `socket(AF_INET, SOCK_DGRAM, 0)` | Returns fd > 0 | P0 |
| FT-003 | bind | `bind(fd, addr, len)` | Returns 0 | P0 |
| FT-004 | listen | `listen(fd, backlog)` | Returns 0 | P0 |
| FT-005 | connect | `connect(fd, addr, len)` | Returns 0 | P0 |
| FT-006 | accept | `accept(listen_fd, ...)` | Returns client_fd > 0 | P0 |
| FT-007 | accept4 | `accept4(listen_fd, ..., SOCK_NONBLOCK)` | Returns client_fd > 0 | P1 |
| FT-008 | read/write | `write(fd, buf, len)` + `read(fd, buf, len)` | Data consistent | P0 |
| FT-009 | send/recv | `send(fd, buf, len, 0)` + `recv(fd, buf, len, 0)` | Data consistent | P0 |
| FT-010 | sendto/recvfrom | UDP sendto + recvfrom | Data consistent | P1 |
| FT-011 | sendmsg/recvmsg | `sendmsg` + `recvmsg` (scatter-gather) | Data consistent | P1 |
| FT-012 | writev/readv | `writev` + `readv` (multi-iov) | Data consistent | P1 |
| FT-013 | close | `close(fd)` | Returns 0 | P0 |
| FT-014 | shutdown | `shutdown(fd, SHUT_WR)` | Returns 0 | P1 |
| FT-015 | getsockopt/setsockopt | SO_REUSEADDR, SO_REUSEPORT | Set/get consistent | P1 |
| FT-016 | getsockname/getpeername | Get after bind | Address info correct | P1 |
| FT-017 | ioctl (FIONBIO) | Set non-blocking | Returns 0 | P1 |
| FT-018 | fcntl (F_GETFL/F_SETFL) | Get/set flags | Returns correct flags | P1 |

### 3.2 Epoll Operation Tests

| Test ID | Test Name | Test Scenario | Expected Result | Priority |
|---------|---------|---------|---------|--------|
| FT-020 | epoll_create | `epoll_create(size)` | Returns epfd > 0 | P0 |
| FT-021 | epoll_ctl ADD | `EPOLL_CTL_ADD(epfd, fd, EPOLLIN)` | Returns 0 | P0 |
| FT-022 | epoll_ctl MOD | `EPOLL_CTL_MOD(epfd, fd, EPOLLOUT)` | Returns 0 | P1 |
| FT-023 | epoll_ctl DEL | `EPOLL_CTL_DEL(epfd, fd)` | Returns 0 | P1 |
| FT-024 | epoll_wait timeout=0 | No ready events, timeout=0 | Returns 0 immediately | P0 |
| FT-025 | epoll_wait timeout>0 | No ready events, timeout=1000 | Returns 0 after ~1s | P0 |
| FT-026 | epoll_wait timeout=-1 | Events ready, timeout=-1 | Returns when events arrive | P0 |
| FT-027 | epoll_wait event trigger | Peer sends data | Returns EPOLLIN event | P0 |
| FT-028 | epoll_wait multi-event | Multiple fds ready simultaneously | Returns all ready events | P1 |
| FT-029 | epoll_wait timeout precision | timeout=10ms | Actual return time 10±5ms | P1 |

### 3.3 Kevent Operation Tests

| Test ID | Test Name | Test Scenario | Expected Result | Priority |
|---------|---------|---------|---------|--------|
| FT-030 | kqueue create | `kqueue()` | Returns kq > 0 | P0 |
| FT-031 | kevent register | `EV_SET + kevent(kq, &kev, 1, NULL, 0, NULL)` | Returns 0 | P0 |
| FT-032 | kevent timeout=NULL | Events arrive | Returns when events arrive | P0 |
| FT-033 | kevent specified timeout | `timeout={0, 100000}` | Returns after ~100us | P0 |
| FT-034 | kevent EVFILT_READ | Peer sends data | Returns read event | P0 |
| FT-035 | kevent EV_EOF | Peer closes connection | Returns EV_EOF flag | P1 |

### 3.4 Special Scenario Tests

| Test ID | Test Name | Test Scenario | Expected Result | Priority |
|---------|---------|---------|---------|--------|
| FT-040 | alarm_event_sem replacement | Call alarm_event_sem in signal handler | APP wakes normally and exits | P0 |
| FT-041 | fork scenario | `FF_USE_THREAD_STRUCT_HANDLE` + fork | Parent/child run independently | P1 |
| FT-042 | multi-thread attach | `FF_THREAD_SOCKET` + multi-thread | Each thread has independent sc + ring | P1 |
| FT-043 | select operation | `FF_PRELOAD_SUPPORT_SELECT` + select | Correctly returns ready fds | P2 |
| FT-044 | kernel event mixed | `FF_KERNEL_EVENT` + ring mode | Both fstack + kernel events work | P1 |
| FT-045 | large buffer transfer | `write(fd, 1MB_buf, 1MB)` | Data received completely | P1 |
| FT-046 | zero-byte operation | `read(fd, buf, 0)` | Returns -1, errno=EINVAL | P2 |
| FT-047 | invalid fd operation | `read(invalid_fd, ...)` | Returns -1, errno=EBADF | P2 |
| FT-048 | ring full scenario | Continuously submit more requests than ring_size | Enqueue blocks/spin retries, no loss | P0 |

### 3.5 Wait Strategy Tests

| Test ID | Test Name | Wait Mode | Expected Result | Priority |
|---------|---------|---------|---------|--------|
| FT-050 | busy-poll mode | `wait_mode=0` | Ultra-low latency, 100% CPU | P0 |
| FT-051 | yield-poll mode | `wait_mode=1` | Low latency, CPU < 100% | P0 |
| FT-052 | eventfd mode | `wait_mode=2` | Medium latency, low CPU | P1 |
| FT-053 | mode switching | Runtime wait_mode switch | No request loss | P2 |

---

## 4. Performance Benchmarking

### 4.1 Test Metrics

| Metric | Definition | Target (ring vs sem) |
|------|------|-------------------|
| **Single syscall RTT** | Time from APP sending request to receiving response | ring ≤ 1μs, sem 2-5μs (2-5x improvement) |
| **Throughput (RPS)** | Requests processed per second | ring ≥ 1.5x sem |
| **epoll_wait latency** | Time from event arrival to epoll_wait return | ring ≤ 2μs |
| **CPU utilization** | CPU usage of fstack + APP | busy-poll: ≈200%, yield-poll: < 150% |
| **P99 latency** | 99th percentile latency | ring P99 < sem P50 |
| **Context switch rate** | Context switches per second | ring ≈ 0 (no futex), sem > 0 |

### 4.2 Micro-Benchmarks

#### PB-001: No-op RTT Test

```
Method:
  1. APP issues simplest syscall (e.g. getsockname)
  2. Measure TSC cycles from SYSCALL macro start to return
  3. Repeat 1,000,000 times, compute avg/P50/P99/P99.9

Expected:
  - ring busy-poll: avg < 500ns, P99 < 1μs
  - ring yield-poll: avg < 1μs, P99 < 2μs
  - sem (control): avg 2-5μs, P99 > 5μs
```

#### PB-002: epoll_wait Timeout Precision Test

```
Method:
  1. Call epoll_wait with timeout values: 1ms, 10ms, 100ms, 1000ms
  2. Measure deviation between actual return time and expected timeout
  3. 1000 repetitions per timeout value

Expected:
  - ring: deviation < 1ms (for timeout >= 10ms)
  - sem: deviation 1-10ms (CLOCK_REALTIME precision limitation)
```

#### PB-003: O(n) vs O(1) Dispatch Efficiency

```
Method:
  1. Set different numbers of active sc: 1, 4, 8, 16, 32
  2. Only 1 sc has a request, rest are idle
  3. Measure ff_handle_each_context processing time for that request

Expected:
  - ring: time independent of sc count (O(1))
  - sem: time grows linearly with sc count (O(n))
```

### 4.3 HTTP Throughput Benchmarks

#### PB-010: Short Connection HTTP 1.0

```
Method:
  - Server: fstack + main_stack_epoll example (return fixed HTML)
  - Client: wrk -t4 -c100 -d30s http://server:80/
  - Connection mode: short connection (Connection: close)

Metrics: RPS, avg/P50/P99 latency, Transfer/sec
Control group: sem mode + POLLING mode
```

#### PB-011: Keep-Alive HTTP 1.1

```
Method:
  - Client: wrk -t4 -c100 -d30s -H "Connection: keep-alive" http://server:80/
Metrics: same as PB-010
```

#### PB-012: High Concurrency

```
Method:
  - Client: wrk -t8 -c1000 -d60s http://server:80/
  - Concurrent connections: 100, 500, 1000, 5000, 10000

Metrics: RPS, latency distribution, error rate
```

### 4.4 CPU Utilization Comparison

```
Method:
  1. Run helloworld example, no client connections (idle state)
  2. top -p <pid> collect 5-minute CPU usage
  3. Compare modes: ring busy-poll, ring yield-poll, ring eventfd, sem (control), POLLING (control)

Expected:
  | Mode | Idle CPU | Full Load CPU |
  |------|---------|---------|
  | busy-poll | ~100% | ~100% |
  | yield-poll | < 50% | ~100% |
  | eventfd | < 5% | ~80% |
  | sem (control) | < 5% | ~80% |
  | POLLING (control) | ~100% | ~100% |
```

---

## 5. Regression Testing

### 5.1 Example Program Regression Matrix

All 5 helloworld examples must pass under Ring mode:

| Example | File | Event Model | Test Steps | Pass Criteria |
|---------|------|---------|---------|----------|
| helloworld_stack | `main_stack.c` | kevent | Start → wrk test 30s → signal exit | RPS > 0, no crash, clean exit |
| helloworld_stack_epoll | `main_stack_epoll.c` | epoll | Same as above | Same |
| helloworld_stack_epoll_kernel | `main_stack_epoll_kernel.c` | epoll + kernel | Same as above | Same |
| helloworld_stack_epoll_thread_socket | `main_stack_epoll_thread_socket.c` | epoll + multi-thread | Start(2 workers) → wrk 30s → exit | Same |
| helloworld_stack_thread_socket | `main_stack_thread_socket.c` | kevent + multi-thread | Start(2 workers) → wrk 30s → exit | Same |

### 5.2 Regression Test Flow

```bash
#!/bin/bash
# regression_test.sh

make clean && make FF_USE_RING_IPC=1

./fstack -c /etc/f-stack.conf &
FSTACK_PID=$!
sleep 2

for prog in helloworld_stack helloworld_stack_epoll \
            helloworld_stack_epoll_kernel \
            helloworld_stack_epoll_thread_socket \
            helloworld_stack_thread_socket; do
    echo "Testing $prog..."
    LD_PRELOAD=./libff_syscall.so ./$prog &
    APP_PID=$!; sleep 2
    wrk -t2 -c50 -d10s http://<server_ip>:80/ > ${prog}_result.txt 2>&1
    if grep -q "Requests/sec" ${prog}_result.txt; then
        echo "  PASS: $prog - RPS=$(grep 'Requests/sec' ${prog}_result.txt | awk '{print $2}')"
    else
        echo "  FAIL: $prog - no response"
    fi
    kill -SIGTERM $APP_PID; wait $APP_PID 2>/dev/null
done
kill $FSTACK_PID
```

### 5.3 Sem Mode Non-Degradation Verification

Ensure original sem mode is completely unaffected when `FF_USE_RING_IPC` is **not** enabled:

```bash
make clean && make
# Run same regression test flow — results must be identical to pre-modification
```

---

## 6. Stress Testing

### 6.1 Long-Running Stability

| Test ID | Test Name | Duration | Load Description | Pass Criteria |
|---------|---------|---------|---------|----------|
| ST-001 | 72-hour stability | 72h | wrk -t4 -c200 continuous | No crash, no memory leak, RPS fluctuation < 10% (Note: SPEC-001 AC-003 threshold is 24h, 72h is enhanced test) |
| ST-002 | Connection storm | 1h | 1000 new connections/sec | No fd leak, no ring overflow |
| ST-003 | Mass concurrency | 4h | wrk -t8 -c10000 | No hang, error rate < 0.1% |
| ST-004 | Idle stability | 24h | No client connections | CPU usage stable, no memory growth |

### 6.2 Memory Leak Detection

```
Method:
  1. Record startup rte_malloc stats: rte_malloc_dump_stats(stdout, NULL)
  2. Run stress test for 1 hour
  3. Record rte_malloc stats again
  4. Compare: alloc_count - free_count diff should be constant;
     heap_totalsz_bytes should not continuously grow
  5. Ring itself has no dynamic memory allocation (allocated once at creation)

Focus areas:
  - ff_so_context lifecycle (attach/detach balance)
  - share_mem_alloc / share_mem_free balance
  - ring zone created once, never destroyed (by design)
```

### 6.3 Ring Full/Empty Boundary Tests

| Test ID | Test Name | Scenario | Expected Behavior |
|---------|---------|------|---------|
| ST-010 | Ring full stress | fstack intentionally delays processing | APP enqueue spin waits, no request loss |
| ST-011 | Ring empty frequent | Very low frequency requests | fstack polls normally, no CPU waste (yield mode) |
| ST-012 | Ring single element | ring_size=2 (minimum) | Functionally correct but degraded performance |
| ST-013 | Ring large capacity | ring_size=4096 | Functionally correct, reasonable memory usage |

---

## 7. Nginx Integration Validation

### 7.1 Nginx Configuration

```nginx
# nginx.conf (LD_PRELOAD mode)
worker_processes 1;
events {
    worker_connections 1024;
    use epoll;
}
http {
    server {
        listen 80;
        server_name localhost;
        location / {
            return 200 "Hello from F-Stack + Ring IPC\n";
        }
    }
}
```

### 7.2 Nginx Test Scenarios

| Test ID | Test Name | Load | Pass Criteria |
|---------|---------|------|----------|
| NG-001 | Short connection benchmark | `wrk -t4 -c100 -d30s` | RPS >= 1.2x sem mode |
| NG-002 | Keep-alive benchmark | `wrk -t4 -c100 -d30s --latency` | P99 latency <= 0.8x sem mode |
| NG-003 | High concurrency | `wrk -t8 -c5000 -d60s` | Error rate < 0.01% |
| NG-004 | Static files | 1KB/10KB/100KB files | Transfer rate >= sem mode |
| NG-005 | Graceful reload | `nginx -s reload` during continuous requests | No request loss |
| NG-006 | Worker process exit | `kill -QUIT worker_pid` | Master re-forks worker |

### 7.3 Nginx Multi-Worker Test (FF_MULTI_SC)

```
Configuration:
  - worker_processes 4
  - FF_MULTI_SC=1 + FF_USE_RING_IPC=1
  - Each worker has independent sc and ring zone

Steps:
  1. Start 4 fstack instances
  2. Start Nginx (worker_processes 4)
  3. wrk -t8 -c1000 -d60s
  4. Verify load balanced across 4 workers
  5. Kill one worker, verify remaining workers continue serving
```

---

## 8. Build Testing

### 8.1 Build Correctness

| Test ID | Build Configuration | Expected Result |
|---------|---------|---------|
| CT-001 | `FF_USE_RING_IPC=1` | Build succeeds, no warnings |
| CT-002 | No extra macros (default sem mode) | Build succeeds, no warnings |
| CT-003 | `FF_USE_RING_IPC=1 FF_PRELOAD_POLLING_MODE=1` | Build fails (mutual exclusion check) |
| CT-004 | `FF_USE_RING_IPC=1 FF_THREAD_SOCKET=1` | Build succeeds |
| CT-005 | `FF_USE_RING_IPC=1 FF_KERNEL_EVENT=1` | Build succeeds |
| CT-006 | `FF_USE_RING_IPC=1 FF_MULTI_SC=1` | Build succeeds |
| CT-007 | `FF_USE_RING_IPC=1 FF_USE_THREAD_STRUCT_HANDLE=1` | Build succeeds |
| CT-008 | `FF_USE_RING_IPC=1 FF_PRELOAD_SUPPORT_SELECT=1` | Build succeeds |
| CT-009 | All targets: fstack, libff_syscall.so, examples | All build successfully |

### 8.2 Link Testing

```bash
# Verify libff_syscall.so exported symbols are complete
nm -D libff_syscall.so | grep -E "(socket|bind|listen|connect|accept|read|write|close|epoll|kevent|select|fork)" | sort

# Verify no undefined rte_ring symbol references
nm -D libff_syscall.so | grep "rte_ring" | head -20

# Verify fstack binary links correctly
ldd fstack | grep -E "(dpdk|fstack)"
```

---

## 9. Test Data Collection and Reporting

### 9.1 Test Report Template

```
=== F-Stack Ring IPC Performance Benchmark Report ===
Date: YYYY-MM-DD
Hardware: CPU model, Memory, NIC model
Software: OS version, GCC version, DPDK version, F-Stack version

1. Build Test Results: CT-001 ~ CT-009: PASS/FAIL
2. Functional Test Results: FT-001 ~ FT-053: PASS/FAIL summary
3. Regression Test Results: 5 helloworld programs: PASS/FAIL
4. Performance Comparison:
   | Mode | Connections | RPS | Avg Latency | P99 Latency | CPU% |
5. Stress Test Results: ST-001 ~ ST-013: PASS/FAIL
6. Nginx Integration Results: NG-001 ~ NG-006: PASS/FAIL
7. Conclusions and Recommendations
```

---

## 10. Test Priority and Execution Plan

### 10.1 Phase 1 — Smoke Testing (Day 1-2)

- [ ] CT-001 ~ CT-009 Build tests
- [ ] FT-001 ~ FT-018 Basic socket operations
- [ ] FT-020 ~ FT-027 Basic epoll operations
- [ ] 5 helloworld regression tests

### 10.2 Phase 2 — Functional Completeness (Day 3-5)

- [ ] FT-028 ~ FT-053 Complete functional tests
- [ ] FT-040 alarm_event_sem replacement verification
- [ ] FT-048 Ring full scenario
- [ ] FT-050 ~ FT-052 Three wait strategy verification

### 10.3 Phase 3 — Performance Benchmarks (Day 6-8)

- [ ] PB-001 ~ PB-003 Micro-benchmarks
- [ ] PB-010 ~ PB-012 HTTP throughput tests
- [ ] CPU utilization comparison

### 10.4 Phase 4 — Stability and Integration (Day 9-14)

- [ ] ST-001 72-hour stability test
- [ ] ST-002 ~ ST-003 Stress tests
- [ ] NG-001 ~ NG-006 Nginx integration validation
- [ ] Memory leak detection

### 10.5 Phase 5 — Report (Day 15)

- [ ] Aggregate all test data
- [ ] Generate performance comparison charts
- [ ] Write test report
- [ ] Provide optimization recommendations

---

## Appendix A: Troubleshooting Guide

### A.1 Ring-Related Issue Diagnosis

| Symptom | Possible Cause | Diagnosis Method |
|------|---------|---------|
| APP hang (no return) | Ring full, fstack not consuming | `rte_ring_dump()` to check ring state |
| fstack cannot receive requests | Ring zone not properly created/attached | Check `rte_memzone_lookup` return value |
| Response data incorrect | sc pointer overwritten | Check `sc->completion` atomic operation correctness |
| Performance below expectations | False sharing | `perf c2c` to check cache line contention |
| Timeout inaccuracy | TSC frequency incorrectly obtained | Check if `rte_get_tsc_hz()` value is reasonable |
| Build errors | DPDK version incompatibility | Check `rte_ring_create` parameter signature |

### A.2 Debug Logging

Ring mode debug logs output via `DEBUG_LOG` macro (requires not defining `NDEBUG` at compile time):

```c
#ifdef FF_USE_RING_IPC
DEBUG_LOG("ring enqueue: sc=%p, ops=%d, req_ring count=%u\n",
          sc, sc->ops, rte_ring_count(ring_zone->req_ring));
DEBUG_LOG("ring dequeue: sc=%p, result=%d, rsp_ring count=%u\n",
          sc, sc->result, rte_ring_count(ring_zone->rsp_ring));
#endif
```
