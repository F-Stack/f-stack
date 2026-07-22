# Software/Hardware Gap and Difference Analysis

> Synthesizing `01-protocol-stack-analysis.md` (software layer) and `02-dpdk-hardware-analysis.md` (hardware layer), this document analyzes the different consequences and the nature of the gap for "decreasing MTU" vs. "increasing MTU".

## 1. Nature of the Gap

f-stack's MTU handling has two independent stages, neither of which is wired through to hardware:

```
Application ff_ioctl(SIOCSIFMTU)
   │  ff_syscall_wrapper.c:520 (LINUX_SIOCSIFMTU→SIOCSIFMTU)
   ▼
if.c:2729 (priv_check + IF_MINMTU/IF_MAXMTU broad check)
   │
   ▼
ff_veth_ioctl (ff_veth.c:248 default branch)
   │
   ▼
ether_ioctl (if_ethersubr.c:1178)
   ├── ifr_mtu ≤ 1500 → write ifp->if_mtu (software value) ✅
   └── ifr_mtu > 1500 → EINVAL ❌ (hard upper bound)
   │
   ✗ Gap: no path calls rte_eth_dev_set_mtu
   ▼
DPDK port hardware MTU stays at PMD default (1500), mbuf buf=2048
```

**Gap point**: The `if_mtu` modified at the protocol-stack layer is a **pure software value**, never propagated to the DPDK hardware port. f-stack lacks the bridge from "software MTU change → `rte_eth_dev_set_mtu` hardware propagation".

## 2. Decreasing MTU (≤1500): Works

**Protocol-stack layer**: `ether_ioctl` accepts, writes `if_mtu` (`if_ethersubr.c:1181`). The protocol stack then uses the smaller `if_mtu` for TCP MSS negotiation and IP fragmentation decisions — i.e., outbound data is organized by the new smaller MTU.

**Hardware layer**: DPDK port MTU remains 1500, mbuf buf=2048. Since the new MTU (e.g., 1400) is **smaller** than hardware capacity, send/receive is unaffected:
- Send: protocol stack already organizes packets ≤1400; frames are smaller; hardware sends normally.
- Receive: hardware still receives ≤1500 frames; protocol stack processes per `if_mtu`.

**Conclusion**: Decreasing MTU **works**. The software/hardware gap is harmless in the "decrease" direction — because hardware capacity (1500/2048) is already ≥ the new software MTU. Runtime test confirmed 1400 succeeds with normal connectivity (see `05-runtime-test-report.md`).

> Note: Decreasing MTU only changes the local protocol stack's fragmentation/MSS behavior, not hardware; this is distinct from "physical link MTU". No side effects for the decrease scenario.

## 3. Increasing MTU (>1500, jumbo): Unsupported

**Protocol-stack layer**: `ether_ioctl` returns `EINVAL` for `ifr_mtu > ETHERMTU(1500)` (`if_ethersubr.c:1178-1179`). The request is **rejected at the protocol-stack layer**; `if_mtu` unchanged. Runtime test confirmed 9000 and 2000 both return `Invalid argument`.

**Even bypassing the protocol-stack upper bound** (e.g., directly changing `ether_ifattach`'s `if_mtu`, as in issue #720's hacky approach), the hardware layer still fails:
- mbuf `data_room_size` is fixed 2048, cannot hold a 9000B frame (`ff_dpdk_if.c:430`).
- Port `rxmode` has no jumbo/scatter config, no `rte_eth_dev_set_mtu` call; PMD initializes at 1500.
- RX: >1500 frames are dropped or truncated by the PMD; TX: single mbuf cannot hold jumbo and scatter is not enabled.

**Conclusion**: Increasing MTU is **unsupported**, and it is a dual block of "protocol-stack upper bound + hardware gap"; both must be modified to support it (see `06-solution-and-conclusion.md`).

## 4. Consistency Check with Three-Layer Architecture Docs / Knowledge Graph

- The three-layer architecture docs (`docs/03-LAYER3-FUNCTIONS.md` etc.) describe `ff_veth_ioctl`/`ff_syscall_wrapper`'s ioctl conversion responsibilities, consistent with this investigation; the docs do not list MTU capability separately — this investigation supplements the explicit conclusion "MTU modification is software-layer only, ≤1500".
- The knowledge graph (`KNOWLEDGE_GRAPH_WIKI.md`) does not record MTU/jumbo-related symbols; this investigation's conclusions can serve as incremental supplements (if needed later).
- **Consistency principle**: where docs and code differ, the actual code `file:line` referenced in this investigation prevails.

## 5. Difference Summary Table

| Dimension | Decrease MTU (≤1500) | Increase MTU (>1500 jumbo) |
|---|---|---|
| Protocol-stack `ether_ioctl` | Accepts, writes `if_mtu` | `EINVAL` rejection |
| Propagated to DPDK hardware | No (but harmless) | No (and harmful) |
| mbuf 2048 can hold | Yes (new MTU smaller) | No |
| PMD port default 1500 | Compatible | Incompatible |
| Runtime test | Success | Failure (EINVAL) |
| Overall conclusion | ✅ Supported | ❌ Unsupported |
