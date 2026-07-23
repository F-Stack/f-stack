# External Research: LRO / TSO DPDK and FreeBSD Mechanisms

> Researching authoritative conclusions from DPDK official documentation, FreeBSD mechanisms, and technical materials regarding LRO / TSO, cross-verified with this repository's code. Conflicts resolved per code + runtime testing.
> Research targets: DPDK 24.11.6 (this repository's `dpdk-stable-24.11.6/`), f-stack `lib/` + `freebsd/`.

## 1. LRO (Large Receive Offload)

### 1.1 Concept (TSO/LRO/GRO Relationship)

- **TSO (TCP Segmentation Offload)**: Transmit-side offload; NIC hardware-segments large TCP segments from upper layers per MSS, reducing CPU segmentation overhead.
- **LRO (Large Receive Offload)**: Receive-side offload; NIC **hardware-aggregates** multiple small packets from the same TCP flow into one large segment before delivering to the protocol stack, reducing interrupt and protocol stack processing count.
- **GRO (Generic Receive Offload)**: Software generic version of LRO (kernel software aggregation); DPDK also has the `rte_gro` library. This project's Q0 selected the **hardware LRO (DPDK offload) path**, so `RTE_ETH_RX_OFFLOAD_TCP_LRO` is primary.
- Sources: Linux kernel Segmentation Offloads documentation (kernel.org), multiple technical blogs (CSDN/Huawei Cloud/GitHub notes) consistently describe TSO improving transmit-side, LRO/GRO improving receive-side performance.

### 1.2 DPDK Hardware LRO Enablement Requirements (Official, Cross-Verified with Code)

DPDK `struct rte_eth_rxmode` (`doc.dpdk.org` API, `lib/ethdev/rte_ethdev.h`) key fields:

| Field | Description |
|------|------|
| `mtu` | Requested MTU |
| **`max_lro_pkt_size`** | **Maximum allowed size of LRO aggregated packet** |
| `offloads` | Uses `RTE_ETH_RX_OFFLOAD_*` flags; can only set bits already declared in `dev_info.rx_offload_capa` |

**Prerequisites for enabling hardware LRO**:
1. `dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO` is true (PMD/NIC supports).
2. `port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_LRO`.
3. **Must set `port_conf.rxmode.max_lro_pkt_size`** (otherwise some PMDs reject or behavior is undefined) — this is the upper limit for aggregated large segments; must match mbuf carrying capacity (data_room / scatter).
4. LRO-aggregated large segments may exceed a single mbuf; requires mbuf chain (scatter) or sufficiently large data_room.

> **Direct corroboration for this repository**: f-stack `ff_dpdk_if.c:890-897` `#if 0` LRO code **only sets the offloads bit and hw_features.rx_lro, without setting `max_lro_pkt_size`**, and uses the old macro `DEV_RX_OFFLOAD_TCP_LRO`. Even removing `#if 0` is incomplete — this is exactly the key point this spec's LRO full new development must address (M1 must verify 24.11.6 header macro name and max_lro_pkt_size field).

### 1.3 DPDK Macro Name Evolution (M1 Must Verify)

- Old version (≤19.x): `DEV_RX_OFFLOAD_TCP_LRO`.
- New version (20.11+ naming normalization): `RTE_ETH_RX_OFFLOAD_TCP_LRO`. DPDK 24.11 should use `RTE_ETH_*` as authoritative; old macro may have compat alias or be removed. This repository's `#if 0` still uses the old macro; M1 must verify against actual headers.

## 2. TSO (TCP Segmentation Offload)

### 2.1 DPDK Official TSO mbuf Metadata Requirements (Authoritative, doc.dpdk.org Mbuf Library)

When TSO is enabled, the transmit mbuf **must** correctly set the following fields and ol_flags (using inner TCP as example):

**Required mbuf fields**:
| Field | Value | Description |
|------|------|------|
| `mb->l2_len` | L2 header length (Ethernet header; to inner Ethernet header when encapsulated) | **Required** |
| `mb->l3_len` | IP header length | **Required** |
| `mb->l4_len` | TCP header length | **Required** |
| `mb->tso_segsz` | Segmentation MSS | **Required** (segment size) |

**Required ol_flags**:
```c
mb->ol_flags |= RTE_MBUF_F_TX_IPV4      /* or RTE_MBUF_F_TX_IPV6 */
             |  RTE_MBUF_F_TX_IP_CKSUM   /* for IPv4 */
             |  RTE_MBUF_F_TX_TCP_CKSUM
             |  RTE_MBUF_F_TX_TCP_SEG;   /* enable TCP segmentation */
```

**Pseudo-header checksum requirements (key difference between TSO and normal csum)**:
- IP header checksum set to **0**.
- TCP checksum filled with pseudo-header checksum **excluding IP payload length**, computed via `rte_ipv4_phdr_cksum()` (IPv6 uses `rte_ipv6_phdr_cksum()`).
- Constraint: outer L4 checksum must be 0 (encapsulation scenarios).
- Hardware capability: requires `RTE_ETH_TX_OFFLOAD_TCP_TSO`.

> **Verification points for this repository (M1 to confirm)**: f-stack `ff_dpdk_if.c:2448-2465` / `ff_memory.c:358-368` pre-read **only shows `l4_len`/`tso_segsz` populated**. Per DPDK official requirements, `l2_len`/`l3_len`/`RTE_MBUF_F_TX_TCP_SEG` flag/csum flag/pseudo-header checksum are also required. M1 must verify field-by-field whether any are missing — if l2_len/l3_len or TCP_SEG flag are missing, these are deterministic TSO enhancement points.

### 2.2 IPv4 vs IPv6 TSO

- IPv4 TSO: `RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_SEG`, pseudo-header via `rte_ipv4_phdr_cksum`.
- IPv6 TSO: `RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_TCP_SEG` (IPv6 has no IP header checksum), pseudo-header via `rte_ipv6_phdr_cksum`.
- FreeBSD side: `CSUM_TSO` (IPv4) and IPv6 TSO flag (`CSUM_IP6_TSO`) have different paths; M1 must verify whether f-stack `ff_veth.c:304-306` distinguishes v4/v6.

### 2.3 Virtualization virtio Environment TSO/LRO

- Zhihu article "qemu virtualization environment dpdk NIC tcp offloading": virtio backend requires `tso4/tso6/csum` etc. features in libvirt/qemu config, and host NIC checksum must be enabled; guest-side DPDK conf `txmode.offloads` sets corresponding TSO bits.
- Note: **virtio TSO/LRO capability is limited by backend negotiation (VIRTIO_NET_F_*)**; whether the local virtio supports `RTE_ETH_RX_OFFLOAD_TCP_LRO` / `RTE_ETH_TX_OFFLOAD_TCP_TSO` must be confirmed at runtime via `dev_info`, not statically assumed (honest boundary).

## 3. Cross-Verification of External Conclusions with This Repository's Code (Preliminary, M1 Re-verifies file:line)

| External Conclusion | This Repository Current Status (Pre-read) | Consistency |
|---|---|---|
| Hardware LRO requires offloads bit + `max_lro_pkt_size` + mbuf capacity | `#if 0` disabled, and max_lro_pkt_size not set | ⚠️ f-stack missing, needs full completion |
| LRO macro `RTE_ETH_RX_OFFLOAD_TCP_LRO` (24.11) | Code uses old macro `DEV_RX_OFFLOAD_TCP_LRO` | ⚠️ Macro name to be verified and corrected |
| TSO requires l2/l3/l4_len + tso_segsz + TCP_SEG/csum flag + pseudo-header | Pre-read only shows l4_len/tso_segsz | ⚠️ Suspected missing l2/l3_len/flags, M1 to confirm |
| TSO already enabled per capability | `ff_dpdk_if.c:931-942` already enabled | ✅ Consistent |
| virtio LRO/TSO capability must be confirmed at runtime dev_info | Local virtio | ✅ Consistent (marked pending runtime validation) |

## 4. Software Path External Research (Round 2 Supplement: Software LRO/TSO + rte_gso/gro + User-Space Stack Patterns)

> Researched by web-researcher sub-agent; all sources are public authoritative materials; conflicts with f-stack code resolved per code.

### 4.1 FreeBSD Software LRO (tcp_lro)

- **Authoritative sources**: FreeBSD Journal "Introduction to TCP Large Receive Offload" (Randall Stewart / Michael Tüxen, Chinese mirror github.com/FreeBSD-Ask/freebsd-journal-cn); FreeBSD commit e69573bc2bee (2025-08-12, Netflix, reviews.freebsd.org/D51772).
- **Software-dominant**: Most FreeBSD drivers use **single software TCP LRO** (tcp_lro.c); only a few NICs have hardware LRO. Software LRO is entirely in the protocol stack/interface layer, not NIC-dependent.
- **Two modes** (consistent with code verification): Classic `tcp_lro_init`+`tcp_lro_rx` (direct aggregation); Modern RSS sorted `tcp_lro_init_args`+`tcp_lro_queue_mbuf` (paired array full → `tcp_lro_flush_all` sorts first to make same-flow adjacent then enters `tcp_lro_rx_common` hash table for aggregation). Both use `tcp_lro_free` for release.
- **Evolution**: 2006 Gallatin(mxge)→2008 Vogel(generalization)→2012 Zeeb(IPv6)→2016 Selasky(sorted path, solving early "only 8 connections" limit).
- **iflib integration pattern (most standard reference for user-space stack software LRO integration)**: commit e69573bc2bee changed iflib to RSS-sorted `tcp_lro_queue_mbuf` — before the receive loop checks `lro_enabled`; if enabled, calls `tcp_lro_queue_mbuf(&rxq->ifr_lc, m)` per packet then continue; after a burst, `tcp_lro_flush_all(&lc)` uniformly sorts+aggregates+injects into stack; lifecycle `init_args→queue_mbuf→flush_all→free`. **f-stack can insert this set of calls after DPDK receive burst, before handing to FreeBSD stack — the most compatible approach for a ported stack**.
- **Software vs hardware LRO**: Software LRO has merge CPU overhead, but net benefit through reducing TCP stack call count and lowering cache miss; hardware LRO has zero CPU overhead but limited NIC support and less flexibility.
- **⚠ Side effects (spec must highlight)**: Merging loses per-segment receive timestamps and IP-layer ECN bits, negatively impacting congestion control/loss recovery. Modern stacks (RACK/BBR) use HPTS + mbuf-queueing + compressed ACK to preserve per-ACK info; basic FreeBSD TCP stack does not use HPTS, takes the "assemble large segments and inject at interface layer" path.
- **tunable**: `net.inet.tcp.lro.entries` (loader-tunable); driver-side `ifconfig lro/-lro`.

### 4.2 Software TSO / GSO (Essence = Protocol Stack Delayed Segmentation)

- **Authoritative source**: Linux kernel segmentation-offloads documentation (kernel.org).
- **Conclusion**: **"Software TSO" = protocol stack delayed segmentation** (GSO, pre-transmit MSS segmentation). When NIC lacks TSO, the protocol stack naturally splits into MTU-sized packets per MSS — an inherent protocol stack capability, **no extra development needed**. Linux calls it GSO; FreeBSD segments per `t_maxseg` in tcp_output. Linux explicitly states: "before enabling hardware segmentation offload, GSO must have a software offload fallback" — hardware TSO is an accelerated version of GSO; the software path always exists. **Completely consistent with f-stack code verification (5.2)**.

### 4.3 DPDK GRO / GSO Library

- **Authoritative sources**: DPDK official Generic Receive/Segmentation Offload Library documentation (doc.dpdk.org); Intel Hu Jiayu Chinese article (cloud.tencent.com).
- **rte_gro (receive software aggregation) = software replacement for hardware LRO** (DPDK 17.08): lightweight `rte_gro_reassemble_burst` (stack-based table, single call); heavyweight `rte_gro_ctx_create`+`rte_gro_reassemble` (per-packet) +`rte_gro_timeout_flush` (get results, **not rte_gro_get_pkt**). Supports TCP/IPv4, UDP/IPv4, VxLAN; **limitations**: no IPv4 Options/VLAN, single mbuf only, no checksum recompute, not thread-safe, must manually fill l2/l3/l4_len before calling.
- **rte_gso (transmit software segmentation) = software replacement for hardware TSO** (DPDK 17.11): `rte_gso_segment`, two-part mbuf (direct stores packet header copy + indirect points to original payload offset, zero-copy). **Limitations**: must explicitly call library, no automatic fallback, no checksum recompute, currently IPv4 only, egress driver must support multi-segment packets.
- **DPDK positioning**: Targeted at scenarios where NIC lacks hardware offload / VxLAN·GRE tunneling (hardware often unsupported) / software forwarding reducing per-packet overhead.

### 4.4 User-Space Protocol Stack Offload + virtio Negotiation

- User-space stacks (f-stack/mTCP/seastar) handle LRO/TSO via two paths: (a) rely on hardware offload (DPDK tx/rx offload bits); (b) software implementation (DPDK rte_gro/rte_gso or port FreeBSD software tcp_lro). f-stack ports the FreeBSD stack, **has the natural condition to port software tcp_lro** (4.1 iflib pattern); transmit segmentation is an inherent protocol stack capability (4.2).
- **virtio offload feature negotiation** (virtio-net spec): TSO=`VIRTIO_NET_F_HOST_TSO4/6` (host segments large segments for guest) / `VIRTIO_NET_F_GUEST_TSO4/6` (guest receives merged large segments = receive-side LRO); UFO=`HOST/GUEST_UFO`; csum=`VIRTIO_NET_F_CSUM/GUEST_CSUM`. Intersection negotiated at init; DPDK virtio PMD advertises offload capa based on result. **Local virtio tested as not supporting TSO/LRO (`guest_features=0x110ef8020`), consistent with this**.

### 4.5 f-stack Community (Honestly Stating Access Limitations)

- External search **did not find public issue/PR/wiki topics about software LRO integration/rte_gro integration in the F-Stack repository** (search results are mostly generic LRO/TSO/GRO/GSO concept articles, not f-stack-specific). As expected: f-stack's LRO/TSO handling is at the "FreeBSD stack + DPDK offload bits/ff_veth" level, not an independent community topic. **Conclusions are authoritative per in-repository code evidence**.

### 4.6 Software Path External ↔ Code Cross-Verification

| External Conclusion | Code Current Status | Consistency |
|---|---|---|
| FreeBSD software LRO uses tcp_lro.c, iflib pattern init_args/queue_mbuf/flush_all | tcp_lro.c compiled but 0 calls; iflib not compiled | ✅ Consistent (need to follow pattern to integrate) |
| Software TSO = protocol stack MSS segmentation, no development needed | NIC without TSO→TF_TSO not set→send per t_maxseg | ✅ Consistent |
| rte_gro/gso are standard software LRO/TSO replacements, require explicit calls | f-stack zero usage | ✅ Consistent (optional supplement path) |
| Software LRO merge loses ECN/timestamp, affects congestion control | Basic stack takes assemble-and-inject path | ⚠ Risk must be registered in 09 document |
| virtio offload subject to feature negotiation | Local virtio does not support TSO/LRO | ✅ Consistent |

---

## 5. Summary

- **LRO**: DPDK official explicitly requires hardware LRO to have `offloads` bit + `max_lro_pkt_size` + large-segment mbuf capacity all complete; f-stack's current `#if 0` code is incomplete on all three, needs full new development. Macro name must be corrected to `RTE_ETH_RX_OFFLOAD_TCP_LRO`.
- **TSO**: DPDK official requires l2/l3/l4_len + tso_segsz + `RTE_MBUF_F_TX_TCP_SEG` + csum flag + pseudo-header checksum all complete; f-stack suspected missing l2_len/l3_len or flags (M1 to confirm), and IPv6 TSO path must be verified — these are TSO enhancement points.
- All external conclusions must be cross-verified with M1 actual code; conflicts resolved per code.
