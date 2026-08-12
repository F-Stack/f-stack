# 00 - Issue #1076 Original Text and Requirements Analysis

> Issue: https://github.com/F-Stack/f-stack/issues/1076
> Title: F-STACK BEHAVIOR AT HIGH CPS
> Status: Open (as of 2026-08-10)
> Author: Sai-Raveendra-Kandregula
> Date Submitted: 2026-06-16
> F-Stack Version: 1.24

---

## 1. Issue Original Text Summary

### 1.1 Scenario Description

The user built a transparent proxy application using f-stack and conducted high CPS (Connections Per Second) stress testing on a single core (single lcore). The following chain of phenomena was observed:

1. **CPU reaches 100% at ~13k CPS on a single core**.
2. Beyond this CPS, **connection teardown is delayed** — new connections arrive faster than the TCP stack can process connection teardown.
3. **Active connections continuously accumulate** — each active connection holds send/receive buffer mbufs.
4. **mbuf pool exhaustion** — all available mbufs are consumed by accumulated active connections.
5. **Entire stack becomes unresponsive** — including `ff_ipc` tools (such as `ff_ipc netstat`), because these tools also depend on mbufs for inter-process communication.

### 1.2 User Request

> "If I did hit the maximum performance of my application, I would like to drop packets instead of my app getting unresponsive."

That is: when the application reaches its performance limit, the user **expects proactive packet dropping (graceful degradation / backpressure)** rather than the entire application becoming unresponsive.

### 1.3 User Configuration

Key configuration parameters given in the issue:

| Parameter | Value | Description |
|---|---|---|
| `dispatch_ring_size` | 16384 | dispatch ring size |
| `rx_queue_size` / `tx_queue_size` | 4096 | RX/TX queue size |
| `hz` | 1000000 | FreeBSD clock frequency (1MHz) |
| `kern.ipc.maxsockets` | 1048576 | Global socket limit (1M) |
| `net.inet.tcp.syncache.hashsize` | 32768 | syncache hash bucket count |
| `net.inet.tcp.tcbhashsize` | 262144 | TCB hash bucket count |
| `net.inet.tcp.sendspace` / `recvspace` | 65536 | TCP send/receive buffer initial size |
| `net.inet.tcp.sendbuf_max` / `recvbuf_max` | 16777216 | TCP send/receive buffer max (16MB) |

### 1.4 Official Response Summary

The issue remains open. The official response provided the following analysis and recommendations:

- **Root cause confirmed**: When single-core CPU reaches 100%, TCP stack connection teardown cannot keep up with new connection arrival rate. Active connections accumulate, each holding send/receive buffer mbufs. After mbuf pool exhaustion, the entire stack becomes unresponsive (including `ff_ipc` tools, which also need mbufs for communication).
- **F-Stack currently has no built-in backpressure mechanism** to automatically drop new connections when approaching mbuf exhaustion.
- **Recommendations**:
  1. Horizontal scaling (primary solution) — add lcores to distribute CPS load.
  2. Increase memory (hugepage) configuration to expand the mbuf pool.
  3. Reduce `hz` to 1000 in non-RACK/BBR scenarios (reduce timer overhead).
  4. Application-layer connection count limiting + RST rejection of new connections for graceful degradation.
  5. memif interface requires software RSS combined with multi-lcore scaling.

---

## 2. Requirements Breakdown

### 2.1 Core Requirement

The user requests investigation of **concurrent connection (CC, Concurrent Connections) limiting solutions** to enable f-stack to gracefully degrade under high CPS scenarios, rather than becoming entirely unresponsive.

### 2.2 Requirement Tiers

| Tier | Requirement | Priority |
|---|---|---|
| L1 | Verify whether the scenario described in the issue still exists in the current version | Required (prerequisite) |
| L2 | Investigate whether FreeBSD stack's built-in CC limiting mechanisms are usable | Required (user explicitly requested priority) |
| L3 | If native mechanisms are usable, provide usage methods and test results | Required |
| L4 | If native mechanisms are insufficient, design f-stack architecture-level CC limiting solutions | Alternative |
| L5 | Submit solution for user review | Required |

### 2.3 Scope Boundaries for This Round

- **This round is investigation and solution design only**, no production code changes will be implemented.
- Hands-on testing is only for verifying whether the issue scenario still exists and the actual effectiveness of native mechanisms.
- Documents are generated in Chinese only, placed in `docs/issue_1076/zh_cn/`.

---

## 3. Success Criteria

| No. | Criterion | Verification Method |
|---|---|---|
| SC-1 | Clearly determine whether the issue scenario still exists in the current version (mbuf exhaustion → stack unresponsive) | Hands-on stress test E1 |
| SC-2 | Code-level confirmation of the completeness of maxsockets / ipfw limit / somaxconn / syncache in the f-stack userspace stack | Code investigation report 02 |
| SC-3 | Hands-on testing of native mechanisms' actual effectiveness (whether connections are effectively limited, behavior at limit) | Hands-on tests E2~E5 |
| SC-4 | Provide recommended solution (zero-code / minor change / combined solution), including configuration examples and trade-off analysis | Solution design document 03 |
| SC-5 | Documents pass independent review agent gate | Review gate report 06 |
| SC-6 | Update Chinese and English issue-ana #1076 entries | issue-ana update |

---

## 4. Existing issue-ana Entry

issue-ana already has a preliminary entry for #1076 (Chinese `docs/zh_cn/f-stack-issue-ana.md:1444-1446`, English `docs/f-stack-issue-ana.md:1440-1442`), with conclusions:

- Root cause: mbuf exhaustion, no backpressure mechanism.
- Recommendation: horizontal scaling / increase mbuf pool / reduce hz / application-layer limiting.

This round of investigation will **deepen** on this basis: verify the usability of native CC limiting mechanisms, test hands-on effectiveness, and provide more specific solution designs.

---

## 5. Related Issue Cross-References

| Issue | Relationship |
|---|---|
| #93 | CPS testing bottleneck from single client port limit and kernel PCB lock contention |
| #410 | Multi-core non-persistent connection CPS improvement bottleneck on client-side ephemeral ports |
| #519 | CPS benchmark testing (nginx reuseport) |
| #649 | Low-latency real-time configuration (`pkt_tx_delay=0` / `idle_sleep=0` / `delayed_ack=0` / `hz=1000`) |
| #868 | Memory not released (DPDK hugepage pre-allocation + glibc ptmalloc2 deferred free) |
