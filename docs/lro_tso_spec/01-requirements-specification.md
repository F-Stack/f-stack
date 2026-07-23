# F-Stack LRO/TSO Requirements Specification

> Document tier: Requirements specification (M1 phase deliverable 1)
> Applicable scope: /data/workspace/f-stack/ user-space protocol stack (DPDK 24.11.6 + FreeBSD 15.0 kernel stack port)
> Note: This round is a **pure spec documentation phase** — only design and current-status verification, no code writing, no lib changes, no commits. All assertions include precise `file:line`; inconsistencies with plan mode pre-read conclusions are resolved per actual code and noted with corrections.

---

## 1. Background

### 1.1 LRO (Large Receive Offload)

LRO is a NIC/driver-side receive offload technology: the NIC merges multiple consecutive small packets from the same TCP flow into one large mbuf segment before delivering to the protocol stack, thereby reducing per-packet processing overhead and significantly lowering CPU usage in high-throughput scenarios.

F-Stack current status (see 02-current-status-and-gap-analysis.md for details):

- **LRO is currently not enabled at all**. The DPDK-side LRO enablement code is wrapped in `#if 0` (`lib/ff_dpdk_if.c:891-898`), and the macro used therein `DEV_RX_OFFLOAD_TCP_LRO` **no longer exists** in DPDK 24.11.6 (only `RTE_ETH_RX_OFFLOAD_TCP_LRO` remains); even removing `#if 0` would cause compilation failure.
- `struct ff_hw_features` **already contains** the `uint8_t rx_lro;` field (`lib/ff_config.h:114`), but there is no assignment/consumer point anywhere in the flow (no config parsing item, no ifnet `IFCAP_LRO`, no LRO awareness in the receive path).
- Therefore LRO is a **completely disconnected null capability from config to protocol stack**; this round implements it as "full new development, using the hardware LRO / DPDK offload path".

**Motivation and value**: In high-throughput TCP receive scenarios (e.g., reverse proxy, download services), hardware LRO can multiplicatively reduce protocol stack CPU and improve single-core throughput; as a high-performance user-space stack, completing LRO capability is an important competitive enhancement for F-Stack to match kernel stacks/commercial stacks.

### 1.2 TSO (TCP Segmentation Offload)

TSO is a transmit-side offload: the protocol stack hands a large TCP segment exceeding MSS to the NIC, which splits it into multiple packets conforming to the link MTU and fills in IP/TCP headers and checksums for each, reducing per-segment protocol stack overhead on the transmit side.

F-Stack current status (see 02-current-status-and-gap-analysis.md for details):

- **TSO is basically supported**: config item `tso` (`config.ini:22`, `ff_config.c:1054-1055`), capability detection and rxmode/txmode enablement (`ff_dpdk_if.c:931-942`, macro `RTE_ETH_TX_OFFLOAD_TCP_TSO`), ifnet-side `IFCAP_TSO`+`CSUM_TSO` (`ff_veth.c:951-954`), offload field population (`ff_dpdk_if.c:2455-2465` and `ff_memory.c:358-368`) all exist.
- However, there are **several enhancement points** (see 02 gap table): IPv6 TSO path missing (downstream only processes via IPv4 `rte_ipv4_phdr_cksum`), `if_hw_tsomax` series limits never set on the lib side, two duplicate offload population logic blocks both predicated on IPv4, etc.

**Motivation and value**: Enhancing TSO to be correct and robust in IPv6, jumbo/MTU, multi-segment (scatter) and other combination scenarios, avoiding hidden risks such as IPv6 transmit anomalies once TSO is enabled beyond the default-off state.

### 1.3 Relationship between LRO/TSO and the Existing MTU Feature

LRO/TSO is strongly related to the previously completed MTU jumbo frame project (jumbo frame / offload context, including IPv6 fragmentation fix commit `0f25ac495`, KNI/MTU mutual exclusion removal `989f1d2da`): the large segments after LRO aggregation and the large segments before TSO both interleave with jumbo mbuf, `mtu_enable`, and multi-segment mbuf (`MULTI_SEGS`) processing paths; design must consider their interactions together.

---

## 2. Goals

### 2.1 LRO Goals (Full New Support)

Connect the **complete path** from config to protocol stack for LRO, with specific layered goals:

1. **Config layer**: Add `dpdk.lro` config option (`config.ini` + `ff_config.c` parsing), default off (`lro=0`), semantics symmetric with `tso`.
2. **Capability detection layer**: Fix the `#if 0` LRO code in `ff_dpdk_if.c`, use the DPDK 24.11.6 correct macro `RTE_ETH_RX_OFFLOAD_TCP_LRO`, detect via `dev_info.rx_offload_capa` and set `pconf->hw_features.rx_lro`.
3. **rxmode enablement layer**: When `dpdk.lro` is on and PMD supports it, set `RTE_ETH_RX_OFFLOAD_TCP_LRO` in `port_conf.rxmode.offloads`, and configure `max_lro_pkt_size` as needed.
4. **Receive path layer**: `ff_veth_input`/`ff_mbuf_gethdr`/`ff_veth_process_packet` correctly handle large aggregated mbuf segments from hardware LRO (`nb_segs`, `pkt_len`, csum flags, `RTE_MBUF_F_RX_LRO` flag passthrough).
5. **Protocol stack/ifnet layer**: Set `IFCAP_LRO` capability bit on the ifnet side so the FreeBSD protocol stack is aware and correctly receives LRO aggregated segments.
6. **Default-off zero regression**: When `lro=0` (default), behavior is completely identical to current status, introducing no regression.

### 2.2 TSO Goals (Enhancement)

Complete the enhancement points without breaking existing IPv4 TSO:

1. **IPv6 TSO support**: Downstream offload population distinguishes IPv4/IPv6; IPv6 uses `rte_ipv6_phdr_cksum` and correctly sets `l3_len`/`RTE_MBUF_F_TX_IPV6`/`RTE_MBUF_F_TX_TCP_SEG`.
2. **Offload field completeness**: Ensure TSO path fully populates `l2_len`+`l3_len`+`l4_len`+`tso_segsz` and `RTE_MBUF_F_TX_TCP_SEG` (and `RTE_MBUF_F_TX_IP_CKSUM` for IPv4).
3. **tsomax limit setting**: Evaluate and set `if_hw_tsomax`/`if_hw_tsomaxsegcount`/`if_hw_tsomaxsegsize` on the ifnet side as needed, so FreeBSD `tcp_output` segmentation decisions match PMD actual capability/jumbo limits.
4. **Duplicate logic convergence**: Evaluate whether the nearly-duplicate offload population logic in `ff_dpdk_if.c` and `ff_memory.c` can be converged to reduce maintenance divergence risk.
5. **Combination correctness**: Verify correctness of TSO combined with checksum offload, `tx_csum_offoad_skip`, scatter/`MULTI_SEGS`, `mtu_enable` (jumbo) scenarios.

---

## 3. Scope and Boundaries

### 3.1 In Scope

- LRO/TSO spec documents (requirements specification, current status/gap analysis, solution design, milestones, coding breakdown, test baseline, gate).
- Current-status verification and gap analysis based on **actual code file:line**.
- External source cross-verification (DPDK offload semantics, FreeBSD LRO/TSO semantics); inconsistencies resolved per code.

### 3.2 Out of Scope

- **No code writing, no lib changes, no commits** (pure documentation phase).
- **No runtime testing**: This round is design only; hardware LRO strongly depends on specific PMD capabilities (virtio / ixgbe / i40e / mlx5 etc., each different); all conclusions involving PMD actual behavior are marked "**pending runtime validation**".
- **No changes to FreeBSD general protocol stack semantics**: LRO/TSO protocol-stack-side receive/segmentation logic follows FreeBSD 15.0 native semantics; only F-Stack porting layer (lib/) adaptation is done.
- Software LRO (`tcp_lro.c` software merge path) is not the first choice this round; this round focuses on the **hardware LRO / DPDK offload path** (`tcp_lro.c` is already compiled in `lib/Makefile:513`, but currently has no F-Stack call site; whether to enable software LRO as a supplement is left for subsequent evaluation).

### 3.3 Dependencies and Assumptions

- DPDK version is **24.11.6** (`/data/workspace/dpdk-stable-24.11.6/`); offload macro names are authoritative per that version's `lib/ethdev/rte_ethdev.h`.
- FreeBSD kernel stack is the 15.0 version ported to `f-stack/freebsd/`.
- Network test environment: DPDK dedicated NIC IP `9.134.214.176` (testing must be initiated from the `ssh f-stack-client` side); kernel stack testing via `127.0.0.1` on `lo` (not tested this round; recorded for subsequent milestones).

---

## 4. Acceptance Criteria

### 4.1 Documentation Phase (This Round) Acceptance

1. Spec gate all PASS: multiple Chinese documents complete, structurally sound, no empty sections.
2. All key assertions include precise `file:line`, independently verifiable.
3. LRO path (config→capability detection→rxmode→receive→protocol stack→IFCAP) closed loop layer by layer, no logical gap omissions.
4. TSO enhancement points itemized clearly (current status/goal/gap/impact/file:line), no ambiguous statements.
5. Inconsistencies with pre-read conclusions are explicitly noted with corrections (e.g., LRO macro name, `rx_lro` field already exists, TSO missing fields).

### 4.2 Subsequent Implementation Phase (For Reference, Not This Round) Acceptance

1. Zero regression when `lro=0`, `tso=0` (default off): transmit/receive behavior byte-for-byte identical to current status.
2. When `lro=1` and PMD supports: LRO aggregated segments correctly received by protocol stack, throughput/CPU metrics improved (pending runtime validation).
3. When `tso=1`: IPv4 and **IPv6** TCP large segments both correctly segmented and transmitted, peer checksum correct (pending runtime validation).
4. Clean build passes (`make clean` then full compile).

---

## 5. Glossary

| Term | Full Name / Meaning |
| --- | --- |
| **LRO** | Large Receive Offload; NIC/driver-side merging of multiple TCP packets from the same flow into a large segment, reducing receive-side protocol stack overhead |
| **TSO** | TCP Segmentation Offload; protocol stack delivers a large TCP segment for the NIC to split per MSS, reducing transmit-side overhead |
| **GRO** | Generic Receive Offload; software-side generic receive merging (DPDK also has `rte_gro`); similar purpose to hardware LRO, different path |
| **offload** | Offloading protocol processing (checksum/segmentation/merging etc.) to NIC hardware |
| **rxmode.offloads / txmode.offloads** | DPDK `struct rte_eth_conf` receive/transmit direction offload enable bitmask fields |
| **rx_offload_capa / tx_offload_capa** | DPDK `dev_info` PMD-advertised receive/transmit offload capability bitmask |
| **RTE_ETH_RX_OFFLOAD_TCP_LRO** | DPDK 24.11.6 LRO receive offload capability macro (`= RTE_BIT64(4)`, `rte_ethdev.h:1556`); **old name `DEV_RX_OFFLOAD_TCP_LRO` removed in 24.11.6** |
| **RTE_ETH_TX_OFFLOAD_TCP_TSO** | DPDK 24.11.6 TSO transmit offload capability macro |
| **tso_segsz** | TSO segment size in mbuf (payload bytes per segment, typically equal to MSS) |
| **l2_len / l3_len / l4_len** | Layer header lengths in mbuf (Ethernet header / IP header / TCP header), required for TSO/csum offload |
| **RTE_MBUF_F_TX_TCP_SEG** | TSO request flag in mbuf `ol_flags` (old name `PKT_TX_TCP_SEG`), implies TCP checksum offload |
| **RTE_MBUF_F_TX_IPV4 / _IPV6** | IP version flags in mbuf `ol_flags`, used with offload |
| **RTE_MBUF_F_RX_LRO** | Receive-side flag in mbuf `ol_flags`, indicating this mbuf is a hardware LRO aggregated segment |
| **IFCAP_LRO / IFCAP_TSO** | FreeBSD ifnet capability bits, declaring the interface supports LRO / TSO |
| **CSUM_TSO / CSUM_IP6_TSO** | FreeBSD mbuf `csum_flags`, marking the mbuf needs TSO (IPv4 / IPv6) |
| **if_hw_tsomax / _tsomaxsegcount / _tsomaxsegsize** | FreeBSD ifnet-side TSO limits (total length/segment count/segment size); `tcp_output` constrains segmentation accordingly |
| **nb_segs** | Number of segments in a DPDK mbuf chain (relevant for LRO large segments, scatter, pre-TSO large segments) |
| **max_lro_pkt_size** | Maximum byte limit per LRO-aggregated packet in DPDK `rxmode` |
| **PMD** | Poll Mode Driver, DPDK poll-mode NIC driver (virtio/ixgbe/i40e/mlx5/ice/ena etc.) |

---

## 6. Key Correction Records (Pre-read vs Actual Code)

> This section summarizes inconsistencies between plan mode pre-read conclusions and actual code; all resolved per actual code.

1. **`rx_lro` field**: Pre-read question "does `uint8_t rx_lro;` exist" → **actually exists** (`ff_config.h:114`), but has no assignment/consumer point.
2. **LRO macro name**: Pre-read listed `DEV_RX_OFFLOAD_TCP_LRO` and `RTE_ETH_RX_OFFLOAD_TCP_LRO` as two candidates → **DPDK 24.11.6 actually only has `RTE_ETH_RX_OFFLOAD_TCP_LRO` (`rte_ethdev.h:1556`), no `DEV_` compat alias**. The existing `#if 0` code uses the defunct `DEV_RX_OFFLOAD_TCP_LRO` (`ff_dpdk_if.c:893/895`); enabling it would fail compilation.
3. **TSO offload fields**: Pre-read concern "only l4_len/tso_segsz seen" → **actually l2_len/l3_len are populated in the tcp_csum branch, TSO branch populates l4_len/tso_segsz/TCP_SEG flag**; the real gap is the **IPv6 path** (downstream always processes via IPv4 `rte_ipv4_phdr_cksum`, `ff_dpdk_if.c:2460`, `ff_memory.c:363`).
4. **stub**: `tcp_lro_hpts_init/uninit` are indeed empty stubs (`ff_stub_14_extra.c:629-639`); `tcp_lro.c` is compiled (`Makefile:513`), `tcp_hpts.c` is compiled (`Makefile:572`), but **`tcp_lro_hpts.c` is not in the Makefile compile list** (search 0 hits).
