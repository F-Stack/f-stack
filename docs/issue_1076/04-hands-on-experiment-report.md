# 04 - Hands-on Test Report

> This document records the execution of issue #1076 scenario reproduction and native mechanism hands-on testing.
> Test date: 2026-08-10
> Test environment: Local dual-NIC (DPDK exclusive NIC + eth1 kernel NIC), f-stack-client remote load generator

---

## 1. Test Environment Preparation

### 1.1 Hardware/Network Environment

| Item | Value |
|------|-------|
| DPDK NIC | 0000:00:09.0 'Virtio network device' drv=igb_uio |
| Kernel NIC | 0000:00:05.0 'Virtio network device' if=eth1 drv=virtio-pci |
| Hugepage | 4096 × 2MB = 8GB (4072 free) |
| f-stack-client | SSH accessible, has `/usr/bin/ab` (Apache Bench) |
| Local eth1 IP | `<KERNEL_NIC_IP>` |
| DPDK NIC IP | `<DPDK_NIC_IP>` |
| f-stack-client IP | `<CLIENT_IP>` |

### 1.2 config.ini Temporary Adjustments

Temporary adjustments for single-process testing (restored after testing, not committed):

| Config Item | Original | Temporary | Reason |
|-------------|----------|-----------|--------|
| `lcore_mask` | 3 | 1 | Single-core single-process test |
| `primary_slim` | 1 | (commented) | Single process doesn't need primary_slim |
| `[port0] lcore_list` | 1 | 0 | Match lcore_mask=1 |
| `[kni] owner_proc_id` | 1 | 0 | Match single process proc_id=0 |

### 1.3 helloworld Startup Verification

- **Startup command**: `./helloworld -c ../config.ini`
- **Startup result**: Success
  - DPDK EAL initialization success (PRIMARY process)
  - Port 0 Link Up
  - ipfw2 initialized
  - mbuf pool created successfully
  - f-stack-0 interface registered
  - CPU ~98.8% (DPDK polling mode normal behavior)

### 1.4 ff_ipc Tool Verification

ff_ipc tools (netstat/top/arp/ifconfig) all communicate normally with f-stack process, verifying report 02's conclusion that "ff_ipc uses independent message_pool, unaffected by pktmbuf_pool."

- `ff_ipc netstat -a`: Shows `tcp4 *.http LISTEN` and `tcp6 *.http LISTEN`
- `ff_ipc top`: Shows idle 67.5%, usr 32.5%, sys 0%
- `ff_ipc arp -a`: Shows f-stack-0 ARP entries
- `ff_ipc netstat -r`: Shows routing table

---

## 2. Network Connectivity Issue

### 2.1 Problem Description

TCP connections from f-stack-client to DPDK NIC IP (curl/ab) timeout.

### 2.2 Diagnosis Process

| Step | Test | Result | Analysis |
|------|------|--------|----------|
| 1 | f-stack-client curl DPDK NIC IP:80 | Timeout (132s) | TCP connection failed |
| 2 | f-stack-client ping DPDK NIC IP | 100% loss | Normal — DPDK NIC IP in userspace, doesn't respond to ICMP |
| 3 | `ff_ipc netstat -a` | tcp4/tcp6 LISTEN | helloworld listening on 80 |
| 4 | `ff_ipc netstat -i` | f-stack-0 Ipkts=0 | **DPDK NIC received no packets** |
| 5 | `ff_ipc top` | sys=0% | No packet processing |
| 6 | Local eth1 ping f-stack-client | Success (0.3ms) | eth1 and f-stack-client connected |
| 7 | `ff_ipc arp -a` | No f-stack-client entry | No client MAC in f-stack ARP table |
| 8 | Manual ARP entry | Success | `ff_arp -s <CLIENT_IP> <CLIENT_MAC>` |
| 9 | Retest after ARP | Still timeout | ARP not the only issue |
| 10 | `ff_ipc top` (after ARP) | sys=0%, Ipkts=0 | DPDK NIC still no packets |

### 2.3 Root Cause Analysis

**DPDK NIC (0000:00:09.0 virtio) received no network packets (Ipkts=0); root cause is DPDK NIC and f-stack-client are not on the same Layer 2 network.**

Evidence:
- Local eth1 (0000:00:05.0 virtio) can ping f-stack-client — eth1 and f-stack-client on same network
- DPDK NIC (0000:00:09.0 virtio) Ipkts=0 — DPDK NIC received no packets
- f-stack-client ARP requests did not reach DPDK NIC
- Two virtio NICs may connect to different virtual switches

### 2.4 Alternative Approach Evaluation

| Approach | Feasibility | Reason |
|----------|------------|--------|
| Fix virtual switch config | Not feasible (beyond investigation scope) | Needs virtualization admin access |
| Test via KNI interface | Not feasible | KNI interface not created in kernel |
| Test via f-stack lo0 | Not feasible | f-stack lo0 is userspace loopback; local curl goes through kernel stack |
| Test via kernel_coexist | Not attempted | config.ini has kernel_coexist=0; needs recompile |

---

## 3. Issue Scenario Reproduction Conclusion

### 3.1 Reproduction Status

**Not completed.** Due to DPDK NIC and f-stack-client not being on the same Layer 2 network, cannot generate high CPS traffic from f-stack-client to f-stack's DPDK NIC. Issue #1076's mbuf exhaustion scenario cannot be reproduced in this environment.

### 3.2 Verified Parts

Although high CPS stress test was not completed, the following were verified:

1. **helloworld starts normally**: DPDK init, ipfw engine, mbuf pool creation, interface registration, port 80 listening all successful.
2. **ff_ipc tools work normally**: netstat/top/arp/ifconfig all communicate via message_pool with f-stack process.
3. **f-stack protocol stack initialization complete**: ipfw2 initialized, tcp_bbr available, TCP Hpts created, syncache initialized.

### 3.3 Unverified Parts

1. **High CPS mbuf exhaustion scenario**: Cannot generate high CPS traffic externally.
2. **maxsockets limit-reached behavior**: Cannot generate enough connections.
3. **ipfw limit rule hands-on effect**: Cannot generate TCP connections.
4. **somaxconn/syncache limit-reached behavior**: Same as above.

### 3.4 Honest Boundaries

- Report 02 has code-level verified completeness of all 4 native mechanisms; code paths and enforcement chains unbroken.
- Report 01 has cross-validated FreeBSD official documentation confirming these mechanisms' behavior.
- Hands-on testing not completed due to environment limitation, but code-level conclusions are highly reliable.
- Future hands-on verification requires fixing DPDK NIC and f-stack-client Layer 2 connectivity (virtual switch configuration).

---

## 4. Native Mechanism Hands-on Test Conclusion

Due to network connectivity issues, native mechanism hands-on effect testing was not completed. Based on report 02's code-level verification and report 01's external documentation cross-validation:

| Mechanism | Code Completeness | Official Docs | Hands-on Verification | Overall Conclusion |
|-----------|------------------|---------------|----------------------|-------------------|
| maxsockets | ✅ Complete | ✅ | ❌ Not completed | Usable (code-level confirmed) |
| ipfw limit | ✅ Complete | ✅ | ❌ Not completed | Usable (code-level confirmed) |
| somaxconn | ✅ Complete | ✅ | ❌ Not completed | Usable (code-level confirmed) |
| syncache | ✅ Complete | ✅ | ❌ Not completed | Usable (code-level confirmed) |

**Note**: Hands-on verification marked "❌ Not completed" is due to environment limitation, not mechanism issues. Code-level verification has confirmed complete enforcement chains.
