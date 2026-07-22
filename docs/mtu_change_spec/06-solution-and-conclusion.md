# Solution and Conclusion

> This document provides the final conclusion and the complete modification plan for "supporting increased MTU (jumbo frame)" (design only; this investigation does not modify code).

## I. Final Conclusion

f-stack MTU modification after DPDK NIC takeover is **partially supported**:

- ✅ **Decrease MTU (≤1500)**: works out of the box. Modifiable via `ff_ioctl(SIOCSIFMTU)` or `tools/sbin/ifconfig ... mtu <N≤1500>`; the protocol-stack layer writes `if_mtu` software value and it takes effect; hardware capacity (default 1500 / mbuf 2048) ≥ new MTU, send/receive unaffected.
- ❌ **Increase MTU (>1500, jumbo frame)**: unsupported. Protocol-stack `ether_ioctl` hardcodes `> ETHERMTU(1500)` → `EINVAL`; DPDK hardware layer has no `rte_eth_dev_set_mtu`, fixed mbuf 2048, `rxmode` has no jumbo/scatter — dual block. F-Stack official issue #720 remains OPEN; jumbo is officially unimplemented.

Three-source evidence (code / runtime test / official issues) fully consistent; conclusion is reliable.

## II. Complete Modification Plan for Supporting Increased MTU (jumbo)

> Goal: enable f-stack to use >1500 MTU via config, and link the protocol stack with DPDK hardware. All points required.

### Modification Point 1: Add MTU Config Item to config.ini

- Add `mtu = <N>` (default 1500, absence preserves current behavior) to `[port0]` (and each `[portN]`).
- Add `int mtu;` to `struct ff_port_cfg` in `lib/ff_config.c` / `ff_config.h`; parse this item.

### Modification Point 2: ff_veth Init Sets if_mtu Per Config

- `lib/ff_veth.c` `ff_veth_setup_interface` (L910): after `ether_ifattach`, if `cfg->mtu > 0` then `if_setmtu(ifp, cfg->mtu)` (override `ether_ifattach`'s default 1500).
- Since `ether_ioctl` still hard-checks 1500 for `SIOCSIFMTU`, runtime dynamic increase also requires Modification Point 3.

### Modification Point 3: ff_veth_ioctl Intercepts SIOCSIFMTU (Break 1500 Hard Upper Bound + Hardware Propagation)

- Add an explicit `case` for `SIOCSIFMTU` in `lib/ff_veth.c` `ff_veth_ioctl` (L235), **no longer unconditionally delegating to `ether_ioctl`**:
  - Validate `ifr_mtu` ≤ config-allowed max (e.g., `cfg->max_mtu`).
  - Directly `if_setmtu(ifp, ifr_mtu)` to write the software value (bypass `ether_ioctl`'s ETHERMTU hard upper bound).
  - Call DPDK `rte_eth_dev_set_mtu(port_id, ifr_mtu)` to **propagate MTU to hardware**.
- Preserve current behavior for ≤1500 (may continue via `ether_ioctl`).

### Modification Point 4: DPDK Port/mbuf Support for Jumbo Frames

- `lib/ff_dpdk_if.c`:
  - Enlarge mbuf pool `data_room_size` from `RTE_MBUF_DEFAULT_BUF_SIZE(2048)` to `RTE_PKTMBUF_HEADROOM + max_mtu + Ethernet/CRC overhead` (e.g., 9000+ MTU needs ~9216B); or enable **multi-segment receive (scatter)** to assemble jumbo frames from multiple standard mbufs.
  - Set `port_conf.rxmode.mtu = max_mtu` in port config, enable `RTE_ETH_RX_OFFLOAD_SCATTER` per PMD capability (if using scatter); complete before `rte_eth_dev_configure`.
  - Call `rte_eth_dev_set_mtu(port_id, max_mtu)` in the init flow; check PMD/`dev_info` support for this `max_mtu`.

### Dependencies and Constraints

- **PMD/link dependency**: virtio and other PMDs have limited jumbo capability; underlying NIC/vSwitch/peer must uniformly support jumbo, or large frames are dropped/fragmented mid-path.
- **Memory overhead**: enlarging mbuf data area significantly increases memory; recommend scatter approach to balance.
- **Compatibility**: with default `mtu=1500` all behavior matches current; the modification should be "opt-in".

### Suggested Validation After Modification

- Unit/build: `lib/` rebuild (`-Werror`), `tools/` rebuild pass.
- Runtime: `tools/sbin/ifconfig ... mtu 9000` succeeds, `rte_eth_dev_get_mtu` returns 9000; verify jumbo send/receive via `ping -s 8972 -M do 9.134.214.176` from ssh f-stack-client (unfragmented large packets); `curl` large file throughput comparison.

## III. Effort and Priority Assessment (If Approved)

| Modification Point | Complexity | Risk |
|---|---|---|
| 1 config.ini + ff_config | Low | Low |
| 2 ff_veth init set mtu | Low | Low |
| 3 ff_veth_ioctl intercept + set_mtu propagation | Medium | Medium (ether_ioctl compatibility and error rollback) |
| 4 DPDK mbuf/rxmode/scatter | High | High (memory, PMD compatibility, performance regression) |

- If only **decreasing MTU** is needed: no modification; current state works.
- If **jumbo** is needed: all 4 points; focus on Point 4 (DPDK jumbo + PMD compat), and physical NIC/link support is required.

## IV. Delivery Notes

- This investigation is a conclusion-oriented study on "can it be supported", with the final verdict of **partial support** (decrease works, increase unsupported); thus this directory is delivered as conclusion documents without a full implementation spec.
- If jumbo support is later decided to be implemented, a separate implementation spec and milestones can be based on the "Modification Plan" here.
- The English version has been generated and placed in this directory (`mtu_change_spec/`).
