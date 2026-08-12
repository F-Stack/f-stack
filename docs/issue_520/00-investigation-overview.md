# Issue #520 Investigation Overview

## Issue Information

| Item | Content |
|------|---------|
| Number | #520 |
| Title | Disable TX ip checksum offload in VMware ESXi 5.5.0 Update 2 |
| Author | vincentmli |
| Created | 2020-06-10 |
| Status | Open |

## Problem Description

Running F-Stack Nginx in VMware ESXi 5.5.0 Update 2 VM, TX IP checksum offload is enabled by default. The virtual NIC claims to support it but does not actually compute the IP checksum, causing outgoing IP packets to have checksum 0 (`bad cksum 0 (->95f6)!`). SYN+ACK packets are dropped by the client, and TCP connections cannot be established. ICMP ping is also affected.

## Investigation Conclusions

1. **Root cause**: In virtualization environments (VMware), the virtual NIC claims to support TX IP checksum offload but does not actually compute it — an environment-specific hardware/virtualization layer issue.
2. **Existing workaround**: `tx_csum_offoad_skip=1` disables all TX checksum offload (IP+L4), but with excessive performance loss.
3. **User suggestion**: Finer-grained control to disable only IP layer while keeping L4 offload.

## This Fix

### New Fine-Grained Control

| Config Item | Default | Effect |
|-------------|---------|--------|
| `tx_csum_ip_skip` | 0 | =1 disables only IP layer TX checksum offload |
| `tx_csum_l4_skip` | 0 | =1 disables only L4 layer TX checksum offload |

Backward compatible: `tx_csum_offoad_skip=1` still disables all; `=0` (default) still enables all.

### TX Path Guard Fix

Found that the TX path IP checksum offload was missing the `hw_features.tx_csum_ip` guard (L4 path had `tx_csum_l4` guard); fixed.

## Test Results

| Test | Config | TCP Connection | IP Checksum | Result |
|------|--------|---------------|-------------|--------|
| T1 | Default (skip=0) | Success | Correct | PASS |
| T2 | skip=1 | Success | Correct | PASS |
| T3 | ip_skip=1 | Success | Correct | PASS |

## Modified Files

| File | Change |
|------|--------|
| `lib/ff_config.h` | Added `tx_csum_ip_skip` / `tx_csum_l4_skip` fields |
| `lib/ff_config.c` | Added two config parsing branches |
| `lib/ff_dpdk_if.c` | Split IP/L4 enable conditions + TX path IP guard + TSO warning condition |
| `lib/ff_memory.c` | TX path IP guard |
| `config.ini` | Added new config item comments |
