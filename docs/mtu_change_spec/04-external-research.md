# External Research

> Investigating F-Stack official issues, DPDK documentation, and technical resources regarding "MTU modification / jumbo frame after DPDK NIC takeover", cross-checked against this repo's code. Conflicts resolved in favor of code + runtime testing.

## 1. F-Stack Official GitHub Issues (Authoritative, Directly Relevant)

### 1.1 Issue #239 — [Question] set MTU in example (helloworld) (2018-06, closed)

- Link: https://github.com/F-Stack/f-stack/issues/239
- Question: Can jumbo frame (MTU=9000) be enabled in f-stack?
- **Maintainer response (search excerpt)**: "tools/ifconfig can set mtu. But there is a problem here, **the mtu value can not be more than 1500 for now**. We will fix it in the near future."
- Key points:
  - Official confirmation that `tools/ifconfig` **can set MTU** (corroborates this repo's `tools/sbin/ifconfig`).
  - Official confirmation that **MTU cannot exceed 1500** (corroborates `ether_ioctl`'s 1500 hard upper bound).
  - Promise to "fix in the near future", but as of #720 (2022) still unimplemented.

### 1.2 Issue #720 — Enabling jumbo frames in f-stack (2022-12, **still OPEN**, label `enhancement`)

- Link: https://github.com/F-Stack/f-stack/issues/720
- Reporter's original text (key):
  > "It seems like frame size later than 1500, because in function `ether_ifattach()` the `if_mtu` size is statically set to ETHERMTU"
  > "For now I am statically change the `if_mtu` value to `ETHER_MAX_LEN_JUMBO`, and call `rte_eth_dev_set_mtu()` afterwards. But this feels hacky ... having ether_ifattach read the configuration value somewhere maybe?"
  > "jumbo frame enables a 30% performance boost."
- Key points:
  - Directly identifies the root cause: `ether_ifattach()` statically sets `if_mtu` to `ETHERMTU` (exactly matches this repo's `if_ethersubr.c:985`).
  - Community workaround = **manually change `if_mtu` + call `rte_eth_dev_set_mtu()`** (exactly the two gaps in this repo: protocol-stack upper bound + DPDK propagation).
  - The issue is labeled `enhancement` and **remains open / no official merged PR** → jumbo frame is **officially still unsupported**.

> The reporter's claim that ETHERMTU "which is 1518" is a slip; `ETHERMTU=1500`, `ETHER_MAX_LEN=1518`; does not affect the conclusion.

## 2. DPDK Official Documentation / General Practice

### 2.1 DPDK Standard API for Setting MTU

- DPDK provides `rte_eth_dev_set_mtu(port_id, mtu)` to set port MTU; `rte_eth_dev_get_mtu` to read it.
- DPDK Test Plans "MTU Check Tests" (doc.dpdk.org) states PMD MTU support requires the PMD to implement the `mtu_set` callback and specify MTU via `rxmode.mtu` at `rte_eth_dev_configure` time.

### 2.2 General Requirements for Enabling Jumbo Frames (OVS-DPDK docs, etc.)

- OVS-DPDK docs "jumbo-frames.rst" (github.com/openvswitch/ovs): "By default, DPDK ports are configured with standard Ethernet MTU (1500B). To enable Jumbo Frames support for a DPDK port …" — i.e., **DPDK ports default to 1500**; enabling jumbo requires:
  1. Explicitly set a larger MTU (`rte_eth_dev_set_mtu` / `rxmode.mtu`).
  2. Enlarge mbuf data area to hold jumbo frames (or enable multi-segment/scatter receive).
  3. Underlying NIC / virtual switch / peer must also uniformly support jumbo.
- Tech blogs (CSDN/cnblogs on DPDK MTU, jumbo frame) consistently note: jumbo requires "physical switch + virtual switch + endpoint" MTU alignment, and the DPDK side must enlarge mbuf and enable scatter.

## 3. Cross-Check of External Conclusions Against This Repo's Code

| External Conclusion | This Repo Code Corroboration | Consistent? |
|---|---|---|
| tools/ifconfig can set MTU | `tools/sbin/ifconfig` + `ff_syscall_wrapper.c:520` ioctl conversion | ✅ Consistent |
| MTU cannot exceed 1500 | `ether_ioctl` (`if_ethersubr.c:1178-1179`) hard upper bound | ✅ Consistent |
| `ether_ifattach` statically sets `if_mtu=ETHERMTU` | `if_ethersubr.c:985` | ✅ Consistent |
| jumbo requires `rte_eth_dev_set_mtu` + enlarged mbuf | This repo's `ff_dpdk_if.c` has neither | ✅ Consistent (f-stack indeed lacks both) |
| jumbo officially still unsupported (#720 OPEN) | No jumbo/set_mtu implementation in code | ✅ Consistent |

## 4. Summary

External authoritative sources (especially F-Stack official issues #239 / #720) are **fully consistent** with this repo's code and runtime testing across all three sources:
- Decreasing MTU (≤1500) can be set via `tools/ifconfig`.
- Increasing MTU (jumbo) has never been officially implemented; requires the community workaround of manually raising the `if_mtu` upper bound and adding `rte_eth_dev_set_mtu` + enlarging mbuf.
