# Issue #481 Investigation Overview

## 1. Issue Information

- **Title**: Padding bytes not removed from the ethernet frame
- **Number**: [#481](https://github.com/F-Stack/f-stack/issues/481)
- **Author**: freak82
- **Date**: 2020-02-20
- **Status**: Open (label: todo)
- **Comments**: 0

## 2. Problem Description

DPDK PMD driver does not strip padding bytes from Ethernet frames smaller than 64 bytes. F-Stack's `ff_mbuf_gethdr()` directly uses DPDK's `pkt_len/data_len` to set `m->m_pkthdr.len/m->m_len`, including padding bytes. When an Ethernet frame is < 60 bytes (excluding FCS), it must be padded to 60 bytes, which may cause the FreeBSD protocol stack to incorrectly treat padding bytes as valid data.

### Reproduction Conditions

1. Run an F-Stack epoll-based server
2. Client disables all TCP options (especially TCP timestamps) to make packets the smallest possible size
3. When client closes the connection, it sends a FIN+ACK packet (14 Ethernet + 20 IP + 20 TCP = 54 bytes < 60, requiring 6 bytes of padding)
4. After FreeBSD protocol stack strips all headers, `m->m_len` = 6 bytes (remaining padding bytes), which is reported to the application layer as received data

## 3. Investigation Conclusions

**Issue #481 does not reproduce in the F-Stack 1.26 + FreeBSD 15.0 + DPDK 24.11.6 LTS environment.**

### Test Results Summary

| Test | Protocol | Stack | Data Sent | Ethernet Frame Size | Padding Required | Server Received | Result |
|------|----------|-------|-----------|---------------------|------------------|-----------------|--------|
| T1 | TCP | F-Stack | 1 byte | 55 bytes | 5 bytes | 1 byte | ✅ PASS |
| T1 | TCP | F-Stack | 6 bytes | 60 bytes | 0 bytes | 6 bytes | ✅ PASS |
| T1 | TCP | F-Stack | 2 bytes | 56 bytes | 4 bytes | 2 bytes | ✅ PASS |
| T2 | UDP | F-Stack | 1 byte | 43 bytes | 17 bytes | 1 byte | ✅ PASS |
| T2 | UDP | F-Stack | 6 bytes | 48 bytes | 12 bytes | 6 bytes | ✅ PASS |
| T2 | UDP | F-Stack | 2 bytes | 44 bytes | 16 bytes | 2 bytes | ✅ PASS |
| T2 | UDP | F-Stack | 18 bytes | 60 bytes | 0 bytes | 18 bytes | ✅ PASS |

### Root Cause

FreeBSD 15.0's `ip_input.c:556-562` contains Ethernet padding trimming logic:

```c
if (m->m_pkthdr.len > ip_len) {
    if (m->m_len == m->m_pkthdr.len) {
        m->m_len = ip_len;
        m->m_pkthdr.len = ip_len;
    } else
        m_adj(m, ip_len - m->m_pkthdr.len);
}
```

This logic does execute under F-Stack's default configuration (`ipforwarding=0`, no firewall) (verified in depth by the code-explorer sub-agent). The `M_FASTFWD_OURS` fast path is not triggered under the default configuration and does not skip the trimming.

### Differences from Older F-Stack Versions

Issue #481 was reported in 2020, when F-Stack was based on FreeBSD 11.0. The older version's `ip_input` may not have had the trimming logic, or the logic may have been different. The current FreeBSD 15.0's trimming logic correctly handles Ethernet padding bytes.

## 4. Fix Plan

**No fix needed.** The current version already correctly handles Ethernet padding bytes.

## 5. Agent Team Division of Labor

| Role | Task | Status |
|------|------|--------|
| Lead agent (leader) | Coordination, plan.md, test program writing, test execution, documentation | Complete |
| Sub-agent (code-explorer) | Deep code tracing, verifying ip_input trimming logic | Complete |
| Sub-agent (code-explorer) | Documentation review gate | Pending |

## 6. Document List

| File | Content |
|------|---------|
| 00-调研总览.md | This document: Issue overview, investigation conclusions |
| 01-测试方案与环境.md | Test matrix, test environment, test programs |
| 02-测试结果与数据分析.md | T1/T2 test results, detailed data |
| 03-根因分析与修复方案.md | Code path analysis, ip_input trimming logic |
| 04-审核门禁.md | Review record |
