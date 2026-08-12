# 00 - Investigation Overview

## Issue Background

**Issue**: [#842 Extremely Bad Latency on TCP Connection for receiving Data](https://github.com/F-Stack/f-stack/issues/842)

**Status**: Open (submitted 2024-09-23 by winstonzhao, no comments)

**Problem Description**: F-Stack TCP client receiving large amounts of data has latency approximately 3.75x that of native Linux kernel (F-Stack ~7.5s vs Linux ~2s). Author already used optimized configuration (idle_sleep=0, pkt_tx_delay=0, delayed_ack=0, large buffers).

## Investigation Conclusions

### Core Conclusion: Issue #842 performance gap does not reproduce in this environment

On the local physical environment (F-Stack 1.26 + FreeBSD 15.0 + DPDK 24.11.6), using the same optimized configuration as the issue author:

| Test | Stack | Median Time | Conclusion |
|------|-------|-------------|------------|
| T1 | Linux Kernel | 9.286s | Baseline |
| T3 | F-Stack optimized config | 9.587s | 3.2% gap, F-Stack on par with kernel |

**F-Stack TCP receive performance matches the kernel with correct configuration**, far less than the 3.75x gap reported in issue #842.

### Key Finding: delayed_ack=1 is the critical configuration causing connection failure

| Test | delayed_ack | Result | Notes |
|------|-------------|--------|-------|
| T4 | 0 | ✅ Success (9.417s) | recvspace=8192 also works fine |
| T5 | 1 | ❌ Failure | Connection reset / GET request not sent |

With `delayed_ack=1`, ACKs are delayed 40ms, TCP window updates are blocked, and in large data receive scenarios the receive window exhausts causing connection reset.

### Incidental Finding: ff_epoll EPOLLOUT conversion analysis

During early investigation, observed ff_epoll sometimes returning EPOLLIN instead of EPOLLOUT after connect completion. After in-depth testing confirmed: ff_epoll's EPOLLOUT conversion logic is correct (`ff_event_to_epoll` correctly converts EVFILT_WRITE to EPOLLOUT); the initially observed problem originated from the test program registering both ff_epoll and kqueue on the same socket simultaneously (dual registration caused knote mechanism interference). This problem does not occur with normal ff_epoll usage.

## Test Environment

| Role | Machine | IP | NIC |
|------|---------|-----|-----|
| Python echo server | f-stack-client | <CLIENT_IP> | eth1 |
| F-Stack client | Local | <DPDK_NIC_IP> | DPDK NIC (igb_uio) |
| Kernel client | Local | <KERNEL_NIC_IP> | eth1 (virtio-pci) |

## Document Structure

- `01-测试方案与环境.md` — Test matrix, network topology, program list
- `02-测试结果与数据分析.md` — Test data for each configuration, comparison tables
- `03-根因分析与修复方案.md` — delayed_ack root cause analysis, ff_epoll defect analysis
- `04-spec审核门禁.md` — Gate checklist and conclusions
