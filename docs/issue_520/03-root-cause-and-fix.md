# Root Cause Analysis and Fix Plan

## Issue #520 Root Cause

### Problem Description

VMware ESXi 5.5.0 virtual NIC claims to support TX IP checksum offload (`RTE_ETH_TX_OFFLOAD_IPV4_CKSUM` capability is true), but does not actually compute the IP checksum. F-Stack's `ff_dpdk_if.c` enables offload based on the capability and sets `hw_features.tx_csum_ip=1`; FreeBSD stack therefore sets `CSUM_IP` hwassist and marks `CSUM_IP` in mbuf `csum_flags`, requesting hardware IP checksum computation. TX path sets `RTE_MBUF_F_TX_IP_CKSUM` ol_flag. But VMware virtual NIC does not perform the computation, resulting in IP checksum = 0.

### Packet Path

```
config.ini: tx_csum_offoad_skip=0
    ↓
ff_dpdk_if.c:983-988: detects RTE_ETH_TX_OFFLOAD_IPV4_CKSUM → hw_features.tx_csum_ip=1
    ↓
ff_veth.c:987-989: tx_csum_ip=1 → IFCAP_TXCSUM + CSUM_IP hwassist
    ↓
FreeBSD ip_output: CSUM_IP in hwassist → mbuf csum_flags |= CSUM_IP (requests hardware IP offload)
    ↓
ff_veth.c:289: ff_mbuf_tx_offload extracts offload.ip_csum=1
    ↓
ff_dpdk_if.c:2502: offload.ip_csum → sets RTE_MBUF_F_TX_IP_CKSUM
    ↓
DPDK PMD: VMware virtual NIC does not compute → IP checksum=0 ← Problem here
```

### Existing Workaround

`tx_csum_offoad_skip=1`: Disables all TX checksum offload (IP+L4); FreeBSD software-computes all checksums. Drawback: Also disables L4 offload, excessive performance loss.

## Fix Plan

### 1. Fine-Grained Control (New Config Items)

New `tx_csum_ip_skip` and `tx_csum_l4_skip` config items support independent control of IP layer and L4 layer TX checksum offload.

#### Backward Compatibility Matrix

| `tx_csum_offoad_skip` | `tx_csum_ip_skip` | `tx_csum_l4_skip` | IP offload | L4 offload |
|---|---|---|---|---|
| 0 (default) | 0 (default) | 0 (default) | Enabled | Enabled |
| 1 | * | * | Disabled | Disabled |
| 0 | 1 | 0 | **Disabled** | Enabled |
| 0 | 0 | 1 | Enabled | **Disabled** |

#### VMware Scenario Usage

```ini
# Disable only IP layer checksum offload (VMware virtual NIC does not compute IP checksum)
# Keep L4 checksum offload (VMware virtual NIC may correctly compute L4 checksum)
tx_csum_offoad_skip=0
tx_csum_ip_skip=1
```

### 2. TX Path Guard Fix

**Issue found**: TX path IP checksum offload only checked `offload.ip_csum` (from mbuf csum_flags), missing `ctx->hw_features.tx_csum_ip` guard. The L4 path correctly had `ctx->hw_features.tx_csum_l4` guard.

| File | Line | Before | After |
|------|------|--------|-------|
| `ff_dpdk_if.c` | 2502 | `if (offload.ip_csum)` | `if (ctx->hw_features.tx_csum_ip && offload.ip_csum)` |
| `ff_memory.c` | 319 | `if (offload.ip_csum)` | `if (ctx->hw_features.tx_csum_ip && offload.ip_csum)` |

**Impact Analysis**:
- Currently does not cause problems (`CSUM_IP` is only set in hwassist when it includes `CSUM_IP`, i.e., when `hw_features.tx_csum_ip=1`)
- But adding the guard is correct defensive programming, symmetric with L4 path
- After fine-grained control enabled, when `tx_csum_ip_skip=1`, `hw_features.tx_csum_ip=0`; guard ensures `RTE_MBUF_F_TX_IP_CKSUM` is not incorrectly set

### 3. TSO Warning Condition Update

TSO depends on L4 checksum offload. Updated TSO warning condition to also check `tx_csum_l4_skip`:

```c
// Before:
if (ff_global_cfg.dpdk.tx_csum_offoad_skip) { ... }

// After:
if (ff_global_cfg.dpdk.tx_csum_offoad_skip ||
    ff_global_cfg.dpdk.tx_csum_l4_skip) { ... }
```

## Modified Files

| File | Line | Change Type | Content |
|------|------|-------------|---------|
| `lib/ff_config.h` | 300 | ADD | Added `tx_csum_ip_skip` / `tx_csum_l4_skip` fields |
| `lib/ff_config.c` | 1061 | ADD | Added two MATCH parsing branches |
| `lib/ff_dpdk_if.c` | 983-998 | MODIFY | Split IP/L4 enable conditions into independent checks |
| `lib/ff_dpdk_if.c` | 1001 | MODIFY | TSO warning condition update |
| `lib/ff_dpdk_if.c` | 2502 | MODIFY | TX path IP guard |
| `lib/ff_memory.c` | 319 | MODIFY | TX path IP guard |
| `config.ini` | 29 | ADD | New config item comments |

## FreeBSD Software Checksum Mechanism

When `hw_features.tx_csum_ip=0` (IP offload disabled or unsupported):
- `if_sethwassistbits` does not set `CSUM_IP`
- FreeBSD `ip_output.c` detects `CSUM_IP` not set → software-computes IP checksum (`in_cksum`)
- mbuf `csum_flags` does not contain `CSUM_IP` → `offload.ip_csum=0` → does not set `RTE_MBUF_F_TX_IP_CKSUM`

When `hw_features.tx_csum_l4=0` (L4 offload disabled or unsupported):
- `if_sethwassistbits` does not set `CSUM_DELAY_DATA`
- FreeBSD `tcp_output.c`/`udp_output.c` software-computes L4 checksum
- mbuf `csum_flags` does not contain `CSUM_TCP`/`CSUM_UDP` → `offload.tcp_csum=0` → does not set `RTE_MBUF_F_TX_TCP_CKSUM`
