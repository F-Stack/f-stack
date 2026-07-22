# F-Stack MTU Modification After DPDK NIC Takeover — Investigation Overview

> Conclusion-first document. All conclusions are cross-validated against **actual code** (`lib/` + `freebsd/`) + **runtime testing** + **external authoritative sources**; conflicts resolved in favor of code and runtime results.
> Investigation target: `/data/workspace/f-stack/`, DPDK 24.11.6, runtime environment is the local DPDK-exclusive NIC (virtio, `0000:00:09.0`, IP `9.134.214.176`).

## One-Line Conclusion

**Partial support**: After f-stack's DPDK takes over the NIC, **decreasing MTU (≤1500) works**; **increasing MTU (>1500, i.e., jumbo frame) is unsupported** — `ff_ioctl(SIOCSIFMTU)` returns `EINVAL(22)` directly for >1500.

## Per-Scenario Conclusions

| Scenario | Supported | Direct Evidence |
|---|---|---|
| **Decrease MTU** (e.g., 1500→1400) | ✅ **Supported** | Runtime test `mtu 1400` succeeded (exit=0); code-wise `ether_ioctl` writes `ifp->if_mtu` directly for values ≤ETHERMTU (`if_ethersubr.c:1181`) |
| **Increase MTU to jumbo** (e.g., 9000) | ❌ **Unsupported** | Runtime test returns `ioctl SIOCSIFMTU (set mtu): Invalid argument`; code-wise `ether_ioctl` returns `EINVAL` for `ifr_mtu > ETHERMTU` (`if_ethersubr.c:1178-1179`) |
| **Increase MTU to 2000** (slightly over standard frame) | ❌ **Unsupported** | Same as above, same EINVAL; upper bound locked at `ETHERMTU=1500` |

## Root Cause (Software/Hardware Gap)

1. **Protocol-stack layer hardcodes 1500 upper bound**: f-stack's `ff_veth_ioctl` (`lib/ff_veth.c:235`) delegates `SIOCSIFMTU` to FreeBSD `ether_ioctl` (L248). `ether_ioctl` (`freebsd/net/if_ethersubr.c:1174-1181`) hardcodes `EINVAL` for `ifr_mtu > ETHERMTU(1500)`. Also `ether_ifattach` (`if_ethersubr.c:985`) statically sets `if_mtu` to `ETHERMTU=1500` on NIC attach.
2. **DPDK hardware layer has no MTU wiring at all**: `lib/ff_dpdk_if.c` port init/config flow has **no** `rte_eth_dev_set_mtu` call; `rxmode` has no `mtu`/`max_rx_pkt_len`/jumbo settings; mbuf pool created with `RTE_MBUF_DEFAULT_BUF_SIZE`(=2048), not enlarged by large MTU. Even bypassing the protocol-stack 1500 limit, DPDK hardware cannot send/receive jumbo frames.
3. **No software/hardware linkage**: Even if `if_mtu` (software value) is changed, it is never propagated to the DPDK hardware port. For ≤1500 this is harmless (hardware default 2048 buf suffices for standard frames); for jumbo it guarantees failure.

## Three-Source Evidence Consistency

| Evidence Source | Conclusion |
|---|---|
| **Code** (`ff_veth.c`/`if_ethersubr.c`/`ff_dpdk_if.c`) | ether_ioctl hardcodes 1500 upper bound; DPDK has no set_mtu/jumbo/large mbuf |
| **Runtime test** (`tools/sbin/ifconfig`) | 1400 succeeds; 9000/2000 both EINVAL; upper bound 1500 |
| **External** (F-Stack official issues #239 / #720) | Maintainer confirms "mtu cannot exceed 1500"; jumbo support issue remains OPEN (enhancement, unimplemented) |

## Modification Points for Full Jumbo Support (Increasing MTU)

See `06-solution-and-conclusion.md` for details. Core four points (all required):
1. `ff_dpdk_if.c`: port config calls `rte_eth_dev_set_mtu` + enables jumbo `rxmode` (`RTE_ETH_RX_OFFLOAD_SCATTER` or enlarged `mtu`).
2. `ff_dpdk_if.c`: mbuf pool `data_room_size` enlarged by max MTU (or multi-pool/scatter receive).
3. `ff_veth.c` / `ether_ifattach` path: make `if_mtu` upper bound configurable (bypass `ether_ioctl`'s ETHERMTU hard check, typically by intercepting `SIOCSIFMTU` in `ff_veth_ioctl` to handle it and propagate to DPDK).
4. `config.ini`: add `mtu` config item for `ff_veth_setup_interface` to read and initialize.

## Document Index

- `01-protocol-stack-analysis.md` — SIOCSIFMTU ioctl conversion and ether_ioctl 1500 upper-bound chain
- `02-dpdk-hardware-analysis.md` — port/mbuf/rxmode config gaps
- `03-software-hardware-gap-analysis.md` — different consequences of decreasing vs. increasing MTU
- `04-external-research.md` — F-Stack official issues, DPDK docs, tech blogs
- `05-runtime-test-report.md` — runtime evidence chain (tools/sbin/ifconfig)
- `06-solution-and-conclusion.md` — full jumbo modification plan + final conclusion
