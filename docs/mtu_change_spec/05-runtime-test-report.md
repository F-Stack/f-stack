# Runtime Test Report

> Everything based on actual execution; no speculation without execution. This document records the complete evidence chain of testing MTU modification on a running f-stack NIC using f-stack's built-in `tools/sbin/ifconfig` (DPDK secondary process).

## 1. Test Environment

- **Process under test**: running nginx_fstack (primary, `lcore_mask=10`, DPDK device `0000:00:09.0`, bound to `igb_uio`).
- **DPDK NIC**: virtio, `f-stack-0`, IP `<DPDK_NIC_IP>`.
- **Test tool**: `tools/sbin/ifconfig`, attaching to primary as a DPDK secondary process.
- **Invocation**: `FF_CONFIG=/usr/local/nginx_fstack/conf/f-stack.conf tools/sbin/ifconfig -p 0 f-stack-0 [mtu <N>]`
  - The tool uses `-p <proc_id>` to select primary; `FF_CONFIG` specifies the same EAL config as primary.

> Note: The log message `Device 0000:00:05.0 is not driven by the primary process` is a default device probe notice (`0000:00:05.0` is kernel eth1); it does not affect attaching to `f-stack-0` on `0000:00:09.0`. All tests returned normally.

## 2. Baseline: Current MTU

```
$ ... ifconfig -p 0 f-stack-0
f-stack-0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
	inet <DPDK_NIC_IP> netmask 0xfffff800 broadcast <BROADCAST_IP>
	inet6 fe80::2290:6fff:fe7d:5d08 prefixlen 64 scopeid 0x2
	inet6 <DPDK_NIC_IPV6> prefixlen 128 autoconf
```
- Default **mtu 1500** (corroborates `ether_ifattach` initializing `if_mtu=ETHERMTU`).

## 3. Test Cases and Results

| Case | Command (MTU value) | Return | Result MTU | Conclusion |
|---|---|---|---|---|
| T1 decrease | `... f-stack-0 mtu 1400` | exit=0, no error | `mtu 1400` | ✅ **Success** |
| T2 jumbo | `... f-stack-0 mtu 9000` | `ifconfig: ioctl SIOCSIFMTU (set mtu): Invalid argument`, exit=1 | stays `mtu 1400` | ❌ **Fail (EINVAL)** |
| T3 slightly over standard | `... f-stack-0 mtu 2000` | `ifconfig: ioctl SIOCSIFMTU (set mtu): Invalid argument`, exit=1 | stays `mtu 1400` | ❌ **Fail (EINVAL)** |
| Restore | `... f-stack-0 mtu 1500` | exit=0 | `mtu 1500` | ✅ Restored |

### Key Raw Output

**T1 (decrease 1500→1400, success)**:
```
set1400_exit=0
mtu 1400
```

**T2 (increase →9000, fail)**:
```
ifconfig: ioctl SIOCSIFMTU (set mtu): Invalid argument
set9000_exit=1
mtu 1400          ← unchanged, request rejected
```

**T3 (increase →2000, fail)**:
```
ifconfig: ioctl SIOCSIFMTU (set mtu): Invalid argument
set2000_exit=1
mtu 1400          ← unchanged, request rejected
```

## 4. Correspondence Between Test Results and Code

| Observed Phenomenon | Corresponding Code |
|---|---|
| 1400 succeeds | `if_ethersubr.c:1181` `ifp->if_mtu = ifr->ifr_mtu` (≤ETHERMTU branch) |
| 9000 / 2000 return `SIOCSIFMTU ... Invalid argument` | `if_ethersubr.c:1178-1179` `if (ifr->ifr_mtu > ETHERMTU) error = EINVAL` (>1500 branch) |
| Upper bound exactly 1500 | `ETHERMTU = 1500` |

The runtime `EINVAL(22)` maps exactly to code `ether_ioctl`'s `> ETHERMTU → EINVAL`; the evidence chain is closed.

## 5. Uncovered Items and Honest Boundary

- **Not done**: jumbo end-to-end send/receive throughput test — since increasing MTU is rejected by `EINVAL` at the protocol-stack layer (`if_mtu` cannot be set >1500), the "send jumbo" path cannot be entered; thus jumbo end-to-end send/receive is untestable — which itself proves jumbo is unsupported.
- Connectivity after decreasing MTU: `f-stack-0` remains `UP,RUNNING`; IP/IPv6 addresses unchanged; decreasing MTU only tightens local fragmentation/MSS and does not break connectivity (consistent with `03` analysis).
- The local DPDK NIC is virtio; jumbo capability is also limited by PMD/vSwitch; even if f-stack code is completed in the future, jumbo usability still requires underlying link support.

## 6. Runtime Conclusion

- **Decrease MTU (≤1500)**: can be set successfully at runtime. ✅
- **Increase MTU (>1500)**: rejected by `EINVAL` at runtime; upper bound locked at 1500. ❌

Consistent across three sources: code analysis (`01`/`02`/`03`), external official issues (`04`).
