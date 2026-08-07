# F-Stack Software TSO and Segmentation Solution

> Document tier: Software TSO / segmentation solution (software offload supplementary design 2)
> Design basis: `02-current-status-and-gap-analysis.md` (TSO current status), `04-solution-and-architecture-design.md` (hardware TSO enhancement). This document answers "whether software TSO is needed" and evaluates the DPDK `rte_gso` optional path.
> Authoritative version: DPDK `dpdk-stable-24.11.6`, FreeBSD 15.0 port (`f-stack/freebsd/`).
> Iron rule: This round **does not write code, does not change lib, does not commit**. All code references include precise `file:line`; all conclusions involving specific PMD/runtime behavior are marked "**pending runtime validation**".

---

## 0. Core Conclusion (Answer First)

> **Software TSO requires no development.** F-Stack's "software TSO" is essentially the protocol stack's normal MSS segmentation: when the NIC doesn't support hardware TSO, the FreeBSD TCP protocol stack sends segment by segment per `t_maxseg`, which is a protocol stack **inherent capability**, **already working**, **with no code gap whatsoever**. DPDK `rte_gso` (transmit software segmentation library) is an **optional optimization path** (protocol stack sends large segments + DPDK software segmentation), not required; this round does not include it in development scope, listed as a future optional optimization.

The complete verification logic chain is given below.

---

## 1. Verification: Software TSO = Protocol Stack MSS Segmentation (Complete file:line Logic Chain)

### 1.1 Whether TSO Is Enabled Depends on the `TF_TSO` Flag

- **TSO decision point**: `tcp_output.c:558-565`:
  ```c
  if ((tp->t_flags & TF_TSO) && V_tcp_do_tso && len > tp->t_maxseg &&
      (tp->t_port == 0) &&
      ((tp->t_flags & TF_SIGNATURE) == 0) &&
      (!sack_rxmit || V_tcp_sack_tso) &&
      (ipoptlen == 0 || ...) &&
      !(flags & TH_SYN))
      tso = 1;                          /* tcp_output.c:565 */
  ```
  → **Only when `tp->t_flags & TF_TSO` is set does `tso=1`**, handing the large segment to hardware/software segmentation; otherwise `tso=0`, protocol stack constructs and sends **segment by segment per `t_maxseg`**.

### 1.2 The Sole Set Point for `TF_TSO`

- **Sole set point**: `tcp_input.c:3973-3974`:
  ```c
  /* Check the interface for TSO capabilities. */
  if (cap.ifcap & CSUM_TSO) {           /* tcp_input.c:3973 */
      tp->t_flags |= TF_TSO;            /* tcp_input.c:3974 */
      tp->t_tsomax = cap.tsomax;
      tp->t_tsomaxsegcount = cap.tsomaxsegcount;
      tp->t_tsomaxsegsize = cap.tsomaxsegsize;
      ...
  }
  ```
  → `TF_TSO` **is set only when interface capability `cap.ifcap & CSUM_TSO` is true**.

### 1.3 Source of `cap.ifcap & CSUM_TSO`

- **IPv4**: `tcp_subr.c:3657-3660`:
  ```c
  if (ifp->if_capenable & IFCAP_TSO4 &&
      ifp->if_hwassist & CSUM_TSO) {    /* tcp_subr.c:3657-3658 */
      cap->ifcap |= CSUM_TSO;           /* tcp_subr.c:3659 */
      cap->tsomax = ifp->if_hw_tsomax;
      ...
  }
  ```
- **IPv6**: `tcp_subr.c:3699-3701` (`IFCAP_TSO6 && if_hwassist & CSUM_TSO`, structurally symmetric).
- → `cap.ifcap & CSUM_TSO` is true **⟺ interface has `IFCAP_TSO4/6` set and `if_hwassist & CSUM_TSO`**.

### 1.4 F-Stack Interface Capability Gated by `hw_features.tx_tso`

- **Capability setting**: `ff_veth.c:955-961`:
  ```c
  if (cfg->hw_features.tx_tso) {                 /* ff_veth.c:955 */
      if_setcapabilitiesbit(ifp, IFCAP_TSO, 0);  /* ff_veth.c:956 */
      if_sethwassistbits(ifp, CSUM_TSO, 0);      /* ff_veth.c:957 */
      if_sethwtsomax(ifp, IP_MAXPACKET);         /* ff_veth.c:958 */
      if_sethwtsomaxsegcount(ifp, 35);           /* ff_veth.c:959 */
      if_sethwtsomaxsegsize(ifp, 2048);          /* ff_veth.c:960 */
  }
  ```
  → **Only when `hw_features.tx_tso=1` are `IFCAP_TSO` + `CSUM_TSO` hwassist set**.
- **`tx_tso` source**: `ff_dpdk_if.c` TSO detection block (`04-solution-and-architecture-design.md` section 2 / `02-current-status-and-gap-analysis.md` 2.2): `hw_features.tx_tso = 1` only when `if (dpdk.tso)` and `dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO`.

### 1.5 Complete Logic Chain Closed Loop

```
NIC without hardware TSO
  → dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO == 0
  → ff_dpdk_if.c TSO detection block doesn't set hw_features.tx_tso (stays 0)
  → ff_veth.c:955 if(cfg->hw_features.tx_tso) not entered
  → doesn't set IFCAP_TSO, doesn't set if_hwassist & CSUM_TSO
  → tcp_subr.c:3657/3699 cap->ifcap doesn't include CSUM_TSO
  → tcp_input.c:3973 if(cap.ifcap & CSUM_TSO) not entered → TF_TSO not set
  → tcp_output.c:558 (tp->t_flags & TF_TSO) is false → tso=0
  → protocol stack sends segment by segment per t_maxseg (normal MSS segmentation)
```

**This chain is already working, with no breakpoints, no code development needed.** When NIC has no TSO, TCP data automatically goes through protocol stack segment-by-segment transmission; when NIC has TSO and `tso=1`, goes through hardware TSO (`04-solution-and-architecture-design.md` enhances its IPv6/tsomax correctness).

---

## 2. Why No Additional Software TSO Development Is Needed

### 2.1 "Software TSO" Is a Pseudo-Requirement

- Hardware TSO's value: protocol stack hands a large segment (far exceeding MSS) to NIC, which hardware-splits into multiple MSS-sized TCP segments for transmission, **saving CPU segmentation overhead**.
- So-called "software TSO" if meaning "use CPU to do the same segmentation" — that is exactly **the MSS segmentation the protocol stack is already doing** (`tcp_output.c` sends segment by segment when `tso=0`). There is no independent "software TSO module" to develop, because **segmentation itself is an inherent responsibility of the TCP protocol stack**.
- In other words: **TSO is the optimization of "outsourcing segmentation to hardware"; when not outsourced, segmentation falls back to the protocol stack itself**. The protocol stack's segmentation capability always exists and is the natural fallback for hardware TSO.

### 2.2 Transmit Side Has No Gap (Consistency with Hardware Path)

- `ff_mbuf_tx_offload` (`ff_veth.c:284-307`): only when `mb->m_pkthdr.csum_flags & CSUM_TSO` (`ff_veth.c:305`) does it take `tso_seg_size = mb->m_pkthdr.tso_segsz` (`ff_veth.c:306`).
- From 1.5's logic chain: NIC without TSO → protocol stack doesn't set `CSUM_TSO` → `ff_veth.c:305` branch not entered → `offload.tso_seg_size` stays 0 → downstream `ff_dpdk_if.c` / `ff_memory.c` TSO branch (`if (offload.tso_seg_size)`) not entered → transmit follows normal (already MSS-segmented) path.
- **Naturally consistent**: Transmit-side offload flag setting and consumption are completely gated by `CSUM_TSO`; when NIC has no TSO, the entire chain automatically skips TSO logic, producing no "protocol stack sends large segment but transmit side doesn't segment" mismatch.

### 2.3 Relationship with MTU/Jumbo Frames

- During segment-by-segment transmission, each segment doesn't exceed `t_maxseg` (from MSS negotiation, constrained by path MTU). In jumbo frame (`mtu_enable`) scenarios, `t_maxseg` is larger, single segment can carry more data, itself reducing segment count, no additional software TSO needed.
- During hardware TSO, `if_hw_tsomax` (`ff_veth.c:958`, currently `IP_MAXPACKET`) constrains large segment total length; during software segmentation there's no such constraint (each segment is ≤ MSS).

---

## 3. DPDK rte_gso Optional Path Evaluation

### 3.1 What Is rte_gso

- DPDK's **GSO (Generic Segmentation Offload) software library**: `dpdk-stable-24.11.6/lib/gso/`, core API `rte_gso_segment` (`rte_gso.h:120`).
- Mode: protocol stack/application hands a **large segment mbuf** to `rte_gso_segment`, DPDK **software-layer** splits it into multiple MSS-sized segments (output mbuf array), then sends.
- Uses **two-part mbuf (zero-copy)** technique: each segmented mbuf header is newly allocated (containing each segment's independent L2/L3/L4 headers), data area references original large segment data via `indirect mbuf`, avoiding data copy.

### 3.2 Difference Between rte_gso and Protocol Stack MSS Segmentation

| Dimension | Protocol Stack MSS Segmentation (current, `tso=0`) | rte_gso Software Segmentation |
| --- | --- | --- |
| Segmentation by | FreeBSD TCP protocol stack (`tcp_output.c`) | DPDK GSO library (`rte_gso_segment`) |
| Segmentation timing | Per-segment during protocol stack packet construction | After protocol stack sends large segment, DPDK cuts before transmission |
| Per-segment overhead | Protocol stack goes through full `tcp_output` path per segment | Protocol stack goes through large segment path once, DPDK batch cuts |
| Potential benefit | No additional benefit (baseline) | Reduces protocol stack per-segment processing, reduces tx descriptor generation overhead |
| F-Stack current status | **Already working** | **Zero usage** (`lib/*.c` search `rte_gso` hits 0) |

### 3.3 rte_gso Limitations and Costs (`03-external-research.md` / DPDK docs)

- **Requires explicit call**: Application/driver layer must explicitly call `rte_gso_segment`, no automatic fallback.
- **Doesn't recompute checksums**: GSO doesn't compute L3/L4 checksums for each segment; caller must handle or rely on hardware csum offload.
- **IPv4 only**: `rte_gso` currently mainly supports IPv4 TCP/UDP (VxLAN, GRE tunnel inner IPv4); IPv6 support limited.
- **Two-part mbuf complexity**: Output indirect mbufs need correct reference count management; egress driver must support multi-segment packets (`RTE_ETH_TX_OFFLOAD_MULTI_SEGS`).
- **Must manually fill `l2_len`/`l3_len`/`l4_len`/`tso_segsz`**: Similar to hardware TSO's mbuf field population requirements.

### 3.4 When rte_gso Might Be Valuable

- **NIC completely lacks hardware TSO and throughput bottleneck is protocol stack per-segment overhead**: Protocol stack sends large segment once, DPDK batch cuts, can reduce `tcp_output` per-segment call overhead.
- **Software forwarding/tunnel scenarios**: VxLAN etc. tunnel large segments need egress segmentation.
- **Need to reduce tx descriptor generation pressure**: Large segment injection + egress batch cutting.

But for F-Stack's typical scenarios (protocol stack termination type, with socket semantics), protocol stack MSS segmentation is sufficient; rte_gso's benefit needs actual testing to prove, and introduces explicit call/csum management/two-part mbuf complexity.

---

## 4. Conclusions and Recommendations

### 4.1 Software TSO: No Development Needed

1. **Software TSO = protocol stack MSS segmentation, is a protocol stack inherent capability, already working** (section 1 complete logic chain verified).
2. **Transmit side has no gap**: When NIC has no TSO, the entire chain automatically skips TSO offload logic; `ff_mbuf_tx_offload` (`ff_veth.c:305`) gating is naturally consistent (2.2).
3. **No software TSO development this round**.

### 4.2 rte_gso: Listed as Future Optional Optimization, Not in This Round's Scope

- rte_gso is a **performance optimization** path of "protocol stack sends large segment + DPDK software segmentation", **not functionally required**.
- Introduction cost (explicit call, no checksum recompute, IPv4 only, two-part mbuf complexity) is high; benefit needs runtime performance baseline to prove.
- **Recommendation**: **Don't introduce rte_gso this round**; if future performance baseline (`08-performance-baseline-plan.md`) shows protocol stack per-segment transmission CPU overhead is a bottleneck, then evaluate as an independent optimization item.

### 4.3 Relationship with Hardware TSO (This Round's Real TSO Work)

- **Hardware TSO is acceleration, software segmentation is the ever-present fallback**: The two are not a replacement relationship but "use hardware when available, fall back to protocol stack when not".
- This round's **real TSO work** is in hardware TSO path **correctness enhancement** (`04-solution-and-architecture-design.md` section 2), not "software TSO development":
  - IPv6 TSO pseudo-header/`l3_len` branching (`ff_dpdk_if.c:2467-2491`, `:2452-2466` are comments, real branch starts at `:2467`; `ff_memory.c:358-368`);
  - IPv4 TSO explicit `RTE_MBUF_F_TX_IP_CKSUM` self-consistency;
  - `if_hw_tsomax`/`tsomaxsegcount`/`tsomaxsegsize` value reasonableness verification (current `ff_veth.c:958-960`: `IP_MAXPACKET`/`35`/`2048`, **pending runtime validation** whether matches target PMD);
  - `ff_dpdk_if.c` and `ff_memory.c` duplicate logic convergence;
  - `ff_mbuf_tx_offload` compatible with `CSUM_IP6_TSO` (`ff_veth.c:305`).

---

## 5. Honest Boundary (Pending Runtime Validation Checklist)

1. Whether `ff_veth.c:958-960` current `if_hw_tsomax=IP_MAXPACKET` / `tsomaxsegcount=35` / `tsomaxsegsize=2048` matches target PMD (virtio/ixgbe/i40e vary) — **this is a hardware TSO enhancement item, not software TSO**.
2. If rte_gso is introduced in the future, its two-part mbuf and egress driver `MULTI_SEGS` compatibility in F-Stack transmit path.
3. Whether protocol stack per-segment transmission CPU overhead constitutes a throughput bottleneck (determines whether rte_gso is worth introducing).

> All the above are runtime/subsequent milestone validation items, not tested this round. Test environment: DPDK dedicated NIC IP `<DPDK_NIC_IP>` (`ssh f-stack-client` side initiates), kernel stack testing via `127.0.0.1` on `lo`.

---

## 6. This Document's Conclusion Summary

1. **Software TSO requires no development**: It is protocol stack MSS segmentation (`tcp_output.c:558` default path when `TF_TSO` not set), protocol stack inherent capability, already working, transmit side has no gap (complete logic chain in section 1 verified).
2. **rte_gso (`rte_gso.h:120`) is optional optimization, not required**: F-Stack zero usage, high introduction cost (explicit call/no csum recompute/IPv4 only/two-part mbuf), not included this round, listed as future performance optimization candidate.
3. **Hardware TSO is acceleration, software segmentation is fallback**: This round's real TSO work is in hardware TSO correctness enhancement (IPv6 pseudo-header, IP_CKSUM self-consistency, tsomax verification, duplicate convergence, CSUM_IP6_TSO compatibility), see `04-solution-and-architecture-design.md` section 2.
