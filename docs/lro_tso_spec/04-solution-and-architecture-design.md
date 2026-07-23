# F-Stack LRO/TSO Solution and Architecture Design

> Document tier: Solution and architecture design (M3 phase deliverable 1)
> Design basis: `01-requirements-specification.md`, `02-current-status-and-gap-analysis.md`, `03-external-research.md` (all M1 verified conclusions).
> Authoritative version: DPDK `dpdk-stable-24.11.6`, FreeBSD 15.0 port (`f-stack/freebsd/`).
> Iron rule: This round **does not write code, does not change lib, does not commit**; only produces an actionable solution. All code references include precise `file:line`; all conclusions involving specific PMD behavior are marked "**pending runtime validation**".

---

## 0. Design Overview

### 0.1 Two Main Lines

- **LRO (full new development)**: Adopt the **hardware LRO / DPDK offload path**, connecting all six layers (config → capability detection → rxmode enablement → receive path → ifnet/protocol stack → default-off zero regression). Software LRO (`tcp_lro.c`) is not the first choice this round.
- **TSO (enhancement)**: Without breaking existing IPv4 TSO, complete IPv6 TSO, `RTE_MBUF_F_TX_IP_CKSUM` self-consistency, `if_hw_tsomax` limits, duplicate logic convergence, and combination constraints.

### 0.2 Design Invariants (Throughout)

1. **Default-off zero regression**: When `dpdk.lro=0`, `dpdk.tso=0` (default values), code paths are byte-for-byte identical to current status, introducing no behavior changes. All new logic must hang under existing switches like `if (dpdk.lro)` / `if (offload.tso_seg_size)`.
2. **Capability detection gating**: Any offload bit is only set when `dev_info.rx_offload_capa` / `tx_offload_capa` declares support (following the existing pattern in `ff_dpdk_if.c:901-906`, `931-942`).
3. **Code as authority**: Macro names are authoritative per DPDK 24.11.6 `rte_ethdev.h` (LRO macro = `RTE_ETH_RX_OFFLOAD_TCP_LRO`, `rte_ethdev.h:1556`).
4. **lib minimal comments**: New code only adds concise comments at contracts/non-intuitive points.

---

## I. LRO Hardware Offload Complete Solution (Six-Layer Design)

### 1.1 Config Layer: Add `dpdk.lro` Config Option

**Design goal**: Give LRO a user-controllable switch, with semantics fully symmetric to `tso` (default off).

- **config.ini**: Add near `tso=0` (`config.ini:22`) in the `[dpdk]` section (comment form, committed with feature, local test values unchanged):
  ```ini
  # TCP large receive offload, default: disabled.
  lro=0
  ```
- **ff_config.h (struct)**: `struct ... dpdk` (`ff_config.h:288-300`) adds `int lro;` member after `int tso;` (L295). `struct ff_hw_features`'s `uint8_t rx_lro;` (L114) **already exists**, no need to add; this round activates it from "dead field" to real producer/consumer.
- **ff_config.c**:
  - Default value: `ff_default_config` (if a centralized default setting exists) or set `dpdk.lro = 0` in the init path (consistent with `tso` default off).
  - Parsing branch: `ini_parse_handler` (`ff_config.c:1054-1057` area, adjacent to `MATCH("dpdk","tso")`) adds
    ```c
    } else if (MATCH("dpdk", "lro")) {
        pconfig->dpdk.lro = atoi(value);
    }
    ```
- **Semantics**: `lro=0` (default) does not touch any LRO code path; `lro=1` enters capability detection.

**Risk**: Low. Pure new switch, default 0 no regression.

### 1.2 Capability Detection Layer: Remove `#if 0`, Correct Macro, Detect per Capability

**Current status**: `ff_dpdk_if.c:891-898` LRO block wrapped in `#if 0`, using **removed old macro** `DEV_RX_OFFLOAD_TCP_LRO` (24.11.6 search 0 hits, enabling fails compilation).

**Solution** (rewrite this block, remove `#if 0`, hang under `dpdk.lro` switch):

```c
if (ff_global_cfg.dpdk.lro) {
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO) {
        ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_LIB, "LRO is supported\n");
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_LRO;
        pconf->hw_features.rx_lro = 1;
        /* max_lro_pkt_size setting see 1.3 */
    } else {
        ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_LIB, "LRO is not supported\n");
    }
} else {
    ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_LIB, "LRO is disabled\n");
}
```

- **Macro correction**: `DEV_RX_OFFLOAD_TCP_LRO` → `RTE_ETH_RX_OFFLOAD_TCP_LRO` (`rte_ethdev.h:1556`, `= RTE_BIT64(4)`).
- **Pattern alignment**: Consistent with adjacent RX csum detection (L901-906) and TSO detection (L931-942) three segments (check capa first, then set offloads, then set hw_features, else log).
- **Producer activation**: `pconf->hw_features.rx_lro = 1` is the **sole production point** for the `rx_lro` field, consumed by the receive layer and ifnet layer.

**Risk**: Low (only effective when `lro=1` and PMD supports). **Pending runtime validation**: whether virtio advertises LRO bit in `rx_offload_capa` (03-external-research.md 2.3: virtio capability limited by backend `VIRTIO_NET_F_*` negotiation).

### 1.3 rxmode Enablement Layer: `max_lro_pkt_size` Setting and Relationship with mtu/data_room/scatter

**External conclusion (03-external-research.md 1.2)**: Hardware LRO must set `port_conf.rxmode.max_lro_pkt_size` (`rte_ethdev.h:432` "Maximum allowed size of LRO aggregated packet"), otherwise some PMDs reject or behavior is undefined.

**Solution**: Set `max_lro_pkt_size` alongside setting offloads bit in 1.2:

- **Upper limit source**: PMD advertises configurable limit in `dev_info.max_lro_pkt_size` (`rte_ethdev.h:1792` "Maximum configurable size of LRO aggregated packet"). Design value:
  ```c
  uint32_t lro_cap = dev_info.max_lro_pkt_size;
  port_conf.rxmode.max_lro_pkt_size =
      (lro_cap != 0) ? lro_cap : <conservative default, within 64KB and >= mbuf capacity>;
  ```
  i.e., prefer PMD-advertised limit; if PMD doesn't advertise (0), take a conservative default (not exceeding mbuf chain capacity).
- **Relationship with mtu (jumbo)**: LRO aggregated large segments far exceed single-frame MTU (this is LRO's purpose). `max_lro_pkt_size` is the post-aggregation limit, different dimension from single-frame `mtu`/`max_rx_pktlen` (`ff_dpdk_if.c:954+` MTU validation): MTU constrains single frame, `max_lro_pkt_size` constrains aggregated segment. They don't conflict, but must ensure `max_lro_pkt_size >= mtu`.
- **Relationship with data_room/scatter**: Aggregated large segments typically exceed single mbuf `data_room`; PMD uses **mbuf chain (scatter)** to carry. Therefore when enabling LRO, ensure mbuf pool `data_room` is sufficient or RX scatter is available (receive path already supports multi-segment chains, see 1.4). **Pending runtime validation**: matching relationship between local mbuf pool data_room and `max_lro_pkt_size`.
- **Relationship with RSS**: LRO only aggregates **same-flow** packets; RSS distributes different flows to different queues, inherently orthogonal and complementary to LRO (same-flow within same queue aggregates). No special handling needed.
- **Relationship with RX csum**: LRO large segment csum validation is done by PMD during aggregation and sets `RTE_MBUF_F_RX_L4_CKSUM_GOOD`/`BAD`; receive layer csum check logic (`ff_dpdk_if.c:1698-1703`) applies to large segments as well (see 1.4).
- **Relationship with timestamps**: LRO large segment timestamp takes one packet's timestamp within the aggregation; `ff_veth_input:1718-1722` logic unchanged.

**Risk**: Medium. Improper `max_lro_pkt_size` value may be rejected by PMD; must calibrate at runtime per `dev_info`.

### 1.4 Receive Path Layer: `ff_veth_input` Handling LRO Large Segments

**Current status**: `ff_veth_input` (`ff_dpdk_if.c:1694-1742`) can already move large segments into FreeBSD mbuf chain via `pkt->pkt_len` (total chain length, L1708) + multi-segment traversal (L1725-1739), but **has no `RTE_MBUF_F_RX_LRO` awareness**.

**Key insight (verified)**: The existing receive path **naturally supports LRO large segments** in the "**length搬运**" dimension — `ff_mbuf_gethdr(pkt, pkt->pkt_len, ...)` (L1708) builds mbuf header with total chain length, `while(pn)` loop (L1727-1738) attaches segments one by one. Therefore LRO large segment data movement needs no refactoring.

**Solution (minimal intrusion)**:

1. **csum flag passthrough**: LRO large segments have csum validated by PMD. The existing `rx_csum` check (L1698-1703) logic for dropping `RTE_MBUF_F_RX_L4_CKSUM_BAD` is still correct for LRO segments (PMD guarantees aggregated segment csum semantics). `ff_mbuf_gethdr` sets `CSUM_DATA_VALID|CSUM_PSEUDO_HDR` when `rx_csum` (`ff_veth.c:479-483`), which holds for LRO segments as well.
2. **LRO flag awareness (optional enhancement)**: If needed to convey "this is an LRO merged segment" info to the protocol stack, can detect `pkt->ol_flags & RTE_MBUF_F_RX_LRO` in `ff_veth_input` and set corresponding semantics on FreeBSD mbuf (via `ff_mbuf_gethdr` extended parameter or subsequent setting). **But FreeBSD-side LRO segment reception primarily depends on the `IFCAP_LRO` capability bit (see 1.5) and mbuf length**; `RTE_MBUF_F_RX_LRO` passthrough is not required for protocol stack reception — **FreeBSD `if_input` normally receives large segments per mbuf length and TCP header**. Therefore this design lists `RTE_MBUF_F_RX_LRO` awareness as **optional**; first version can rely solely on length movement + `IFCAP_LRO`.
3. **nb_segs/pkt_len**: No changes needed. `pkt->pkt_len` (whole chain) and `pkt->nb_segs` (PMD-filled) are correctly consumed by existing multi-segment traversal.
4. **Adaptation with `ff_mbuf_gethdr`**: No signature change needed; `total=pkt->pkt_len` is already the aggregation total length.

**Honest boundary (pending runtime validation)**: Whether LRO large segments can be seamlessly received by the FreeBSD protocol stack depends on (a) whether `IFCAP_LRO` is declared, (b) protocol stack receive handling of super-MTU TCP segments. 02-current-status-and-gap-analysis.md 1.5 has noted this as the main runtime risk point.

**Risk**: Medium. Data movement is ready; risk is on the protocol stack receive side (runtime validation).

### 1.5 ifnet/Protocol Stack Layer: Set `IFCAP_LRO`

**Current status**: `ff_veth.c:941-956` sets `IFCAP_RXCSUM/TXCSUM/TSO`, **no `IFCAP_LRO`** (searching all of lib yields 0 hits).

**Solution**: Add to `ff_veth.c` capability setting block (L941-954), hanging under `rx_lro`:

```c
if (cfg->hw_features.rx_lro) {
    if_setcapabilitiesbit(ifp, IFCAP_LRO, 0);
}
```

- Position: parallel to `IFCAP_TSO` (L951-953); `if_setcapenable(ifp, if_getcapabilities(ifp))` (L956) auto-enables.
- Effect: Declares to FreeBSD protocol stack that this interface supports LRO, so the stack receives large segments per LRO semantics (does not treat super-MTU segments as anomalies).
- LRO differs from TSO; receive direction has no `CSUM_*` hwassist requirement, only needs `IFCAP_LRO` capability bit.

**Risk**: Low. Only declared when `rx_lro=1`.

### 1.6 LRO Data Flow Diagram

```
[NIC hardware LRO aggregates same-flow multiple packets]
        │  (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO)
        ▼
[PMD] produces large rte_mbuf: large pkt_len, possibly nb_segs>1, ol_flags |= RTE_MBUF_F_RX_LRO
        │  rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_LRO; max_lro_pkt_size set
        ▼
[ff_veth_input  ff_dpdk_if.c:1694]
   ├─ rx_csum check (L1698-1703): PMD has validated aggregated segment csum
   ├─ ff_mbuf_gethdr(pkt, pkt->pkt_len, ...) (L1708): build mbuf header with aggregation total length
   └─ while(pn) traverse multi-segment attach chain (L1725-1739): scatter large segments attached one by one
        ▼
[FreeBSD mbuf chain]  m_pkthdr.len = aggregation total length, csum_flags mark VALID
        ▼
[ff_veth_process_packet → if_input  ff_veth.c:510-518]
        │  interface has declared IFCAP_LRO (ff_veth.c new addition)
        ▼
[FreeBSD TCP protocol stack]  receives large segments per LRO semantics, reducing per-packet overhead
```

### 1.7 LRO Interaction with Multi-Process (primary/secondary)

- Offload capability detection and `port_conf` configuration are done in the **primary process** port initialization path (`ff_dpdk_if.c` port setup); secondary processes share the configured port.
- `hw_features.rx_lro` is per-port config (`pconf->hw_features`); secondary reads via shared config; ifnet capability declaration is consistently set per `cfg->hw_features.rx_lro` in each process's `ff_veth_setup`.
- **Pending runtime validation**: whether LRO aggregation works correctly per-queue under multi-process (RSS distributes to each process queue, same-flow within same queue aggregates).

---

## II. TSO Enhancement Solution

### 2.1 IPv6 TSO: Offload Population Branch by IP Version

**Current status (verified)**: `ff_dpdk_if.c:2455-2465` and `ff_memory.c:358-368` TSO branches **unconditionally** use `rte_ipv4_phdr_cksum(iph, RTE_MBUF_F_TX_TCP_SEG)` (IPv4 pseudo-header only) + IPv4 header struct strong cast + `iph_len = (version_ihl & 0x0f)<<2` (IPv4 IHL); for IPv6 large-segment TSO, pseudo-header is wrong, `l3_len` is wrong. And upstream `ff_mbuf_tx_offload` (`ff_veth.c:304-306`) only fills `tso_seg_size` for `CSUM_TSO`, carrying no v4/v6 info; downstream can only judge via `iph->version` — but downstream恰恰 doesn't branch by version.

**Solution**: TSO branch branches by `iph->version` (synchronize both locations):

```c
if (offload.tso_seg_size) {
    struct rte_tcp_hdr *tcph;
    int tcph_len;

    if (iph->version == 4) {                 /* reuse L2415/L2426 iph_len calculation */
        tcph = (struct rte_tcp_hdr *)((char *)iph + iph_len);
        tcph_len = (tcph->data_off & 0xf0) >> 2;
        head->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;  /* see 2.2 */
        tcph->cksum = rte_ipv4_phdr_cksum(iph, RTE_MBUF_F_TX_TCP_SEG);
        head->l3_len = iph_len;              /* IPv4 IHL */
    } else {
        struct rte_ipv6_hdr *ip6h = (struct rte_ipv6_hdr *)iph;
        int ip6_len = sizeof(struct rte_ipv6_hdr);   /* fixed 40, extension headers see below */
        tcph = (struct rte_tcp_hdr *)((char *)ip6h + ip6_len);
        tcph_len = (tcph->data_off & 0xf0) >> 2;
        head->ol_flags |= RTE_MBUF_F_TX_IPV6;         /* IPv6 has no IP_CKSUM */
        tcph->cksum = rte_ipv6_phdr_cksum(ip6h, RTE_MBUF_F_TX_TCP_SEG);
        head->l3_len = ip6_len;
    }

    head->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
    head->l2_len = RTE_ETHER_HDR_LEN;        /* TSO branch self-consistent, no dependency on preceding branch */
    head->l4_len = tcph_len;
    head->tso_segsz = offload.tso_seg_size;
}
```

- **IPv6 pseudo-header**: `rte_ipv6_phdr_cksum` (DPDK `rte_ip.h`); 03-external-research.md 2.2 explicitly states IPv6 TSO uses it, no IP header checksum.
- **l3_len**: IPv6 base header fixed 40 (`sizeof(struct rte_ipv6_hdr)`).
- **Extension header handling (honest boundary)**: If IPv6 packet contains extension headers (Hop-by-Hop/Routing/Fragment etc.), `l3_len` should be "total IPv6 header length from Ethernet header to TCP header". First version can support no-extension-header scenario (`l3_len=40`); extension header scenario marked **pending runtime validation/subsequent enhancement** (requires parsing `next_header` chain). TSO is typically used for high-throughput TCP; extension headers are rare, risk controllable.
- **l2_len self-consistency**: Move `l2_len=RTE_ETHER_HDR_LEN` into TSO branch to avoid depending on whether preceding `tcp_csum` branch hits (current L2436 only fills l2_len in tcp_csum branch; if that branch doesn't hit, l2_len is missing).

**Risk**: Medium. IPv6 extension header scenario is a known boundary; core no-extension-header scenario is actionable.

### 2.2 IP_CKSUM Self-Consistency: IPv4 TSO Branch Explicitly Sets `RTE_MBUF_F_TX_IP_CKSUM`

**Current status**: TSO branch (L2455-2465) **does not explicitly** set `RTE_MBUF_F_TX_IP_CKSUM`, depending on `offload.ip_csum` (from `CSUM_IP`)恰好 hitting the `if (offload.ip_csum)` branch (L2410-2420) to set it. DPDK semantics (03-external-research.md 2.1/2.2) require IPv4 TSO to also request IP checksum offload and write IP header checksum to 0.

**Solution**: As shown in 2.1 code, IPv4 branch **explicitly** sets `RTE_MBUF_F_TX_IP_CKSUM`, making TSO self-consistent, not dependent on external branch hitting. IPv6 branch **does not set** (IPv6 has no IP header checksum).

**Risk**: Low. IPv4 TSO should carry IP_CKSUM; explicit setting better conforms to DPDK contract.

### 2.3 `if_hw_tsomax` Series Limit Setting

**Current status (verified)**: `ff_veth.c:951-953` only sets `IFCAP_TSO` + `CSUM_TSO`, **never sets** `if_hw_tsomax`/`tsomaxsegcount`/`tsomaxsegsize` (searching all of lib yields 0 hits). FreeBSD `tcp_output.c:905-931` only uses the limit to constrain `max_len` when `if_hw_tsomax != 0` (L927); `tcp_m_copym` (L1093-1095) constrains segmentation accordingly. When limit is 0, TSO segment length is not constrained by interface, may exceed PMD single-packet/segment-count capability.

**Solution**: Add limit setting near `IFCAP_TSO` in `ff_veth.c` (L951-953):

```c
if (cfg->hw_features.tx_tso) {
    if_setcapabilitiesbit(ifp, IFCAP_TSO, 0);
    if_sethwassistbits(ifp, CSUM_TSO, 0);
    if_sethwtsomax(ifp, <IP_MAXPACKET or derived from max_mtu>);       /* total length limit */
    if_sethwtsomaxsegcount(ifp, <PMD capability, e.g., nb_mbuf_segs>);    /* segment count limit */
    if_sethwtsomaxsegsize(ifp, <single segment limit, e.g., mbuf data_room>);   /* segment size limit */
}
```

- **Value principles**:
  - `if_hw_tsomax`: Total length limit of pre-TSO large segment. FreeBSD traditional default `IP_MAXPACKET` (65535 - headers); jumbo scenario relates to `max_mtu` (`ff_config.c:1070-1072`), but TSO segment total length limit is essentially determined by IP length field (≤65535); can take a conservative value near `IP_MAXPACKET - sizeof(Ethernet header)`.
  - `if_hw_tsomaxsegcount`: PMD single-send acceptable mbuf segment count limit (related to tx queue/PMD capability).
  - `if_hw_tsomaxsegsize`: Single segment byte limit (typically mbuf `data_room` or page size).
- **Honest boundary (pending runtime validation)**: Precise values of `tsomaxsegcount`/`tsomaxsegsize` depend on specific PMD (virtio/ixgbe/i40e vary); DPDK does not directly provide an equivalent "TSO segment count limit" field in `dev_info`. First version can take conservative defaults (e.g., segcount=a safe value, segsize=data_room), marked for runtime PMD calibration. Setting **non-0** limits is itself safer than current status (all 0, unconstrained).

**Risk**: Medium. Too-small values limit TSO efficiency, too-large may exceed PMD capability; conservative defaults + runtime calibration controllable. API names (`if_sethwtsomax` etc.) per FreeBSD 15.0 `if_var.h`/`if.h` actual exports (read_file verification during coding).

### 2.4 Duplicate Logic Convergence Solution

**Current status**: `ff_dpdk_if.c:2405-2472` (`ff_dpdk_if_send` main path) and `ff_memory.c:331-375` (another transmit path) offload population **logic nearly line-by-line identical**; fixing IPv6 requires changing both, easy to miss.

**Convergence solution (tiered)**:

- **Option A (preferred, low risk)**: Extract common function `ff_fill_tx_offload(struct rte_mbuf *head, void *data, const struct ff_tx_offload *offload, uint8_t tx_csum_l4)`, concentrating the 2.1/2.2 version branching logic in one place; both call sites change to call this function. After convergence, IPv6/IP_CKSUM fix only needs one change.
- **Option B (conservative, if time-tight this round)**: **Synchronize** identical logic in both locations, with cross-reference comments in both ("logic consistent with ff_memory.c:358, modifications must sync"). Risk is future divergence.

**Recommendation**: Coding milestone prefers Option A (convergence); if convergence involves complex header/compilation-unit dependencies, fall back to Option B with explicit sync constraint. **The convergence function should be placed in a common c/h that both can include** (e.g., common dependency of `ff_dpdk_if.c` and `ff_memory.c`), avoiding circular dependencies.

**Risk**: Medium (Option A has cross-compilation-unit refactoring risk, needs clean build verification); Low (Option B).

### 2.5 Combination Constraints with `tx_csum_offoad_skip` / scatter / jumbo

- **With `tx_csum_offoad_skip`**: Current TSO enablement (`ff_dpdk_if.c:931-942`) **is not constrained by** `tx_csum_offoad_skip`, while L4 csum offload enablement (L914-926) only sets `tx_csum_l4` when `skip=0`. TSO implicitly requires L4 csum offload (`RTE_MBUF_F_TX_TCP_SEG` implies TCP CKSUM). **Constraint design**:
  - If `tx_csum_offoad_skip=1` (skip L4 csum offload) simultaneously with `tso=1`, this is an **inconsistent combination**. Solution: Add consistency check at TSO enablement (L931) — when `tx_csum_offoad_skip` is true, log WARN "TSO depends on L4 csum offload, currently skipped, TSO may not take effect", or bring TSO enablement under `skip==0` prerequisite. **Prefer logging WARN without changing behavior** (avoid changing existing default path), document + log the mutual exclusion relationship.
- **With scatter / MULTI_SEGS**: Pre-TSO large segments are inherently multi-segment scenarios; transmit path (`ff_dpdk_if.c:2360-2403`) already supports multi-segment mbuf chains. `tso_segsz` + `nb_segs` combination PMD constraints are protected by 2.3's `tsomaxsegcount`/`tsomaxsegsize` limits.
- **With jumbo (`mtu_enable`)**: TSO segment total length limit (2.3 `if_hw_tsomax`) and jumbo MTU constrain each other. TSO segment total length is limited by IP length field (≤65535), different dimension from single-frame MTU (jumbo can reach 9000+); they don't conflict; `if_hw_tsomax` ensures total length doesn't exceed bounds.

**Risk**: Low (mainly logging + documentation constraints, not changing existing paths).

### 2.6 `ff_mbuf_tx_offload` Compatible with `CSUM_IP6_TSO`

**Current status**: `ff_veth.c:304-306` only recognizes `CSUM_TSO` (`if (csum_flags & CSUM_TSO)`); FreeBSD-side IPv6 TSO may set `CSUM_IP6_TSO` (02-current-status-and-gap-analysis.md 2.5: FreeBSD 15.0 natively supports IPv6 TSO, `CSUM_IP6_TSO|CSUM_TSO` hits 6 files in netinet).

**Solution**: Extend recognition to `CSUM_IP6_TSO`, so IPv6 TSO flag can also be mapped to `tso_seg_size`:

```c
if (mb->m_pkthdr.csum_flags & (CSUM_TSO | CSUM_IP6_TSO)) {
    offload->tso_seg_size = mb->m_pkthdr.tso_segsz;
}
```

- **Honest verification (read_file during coding)**: Must confirm the macro definition relationship between `CSUM_TSO` and `CSUM_IP6_TSO` in the FreeBSD 15.0 port — some FreeBSD versions define `CSUM_IP6_TSO` to include/be equivalent to the `CSUM_TSO` bit; if so, current `CSUM_TSO` single-check may already cover v6 (need to verify `sys/mbuf.h`/`freebsd/sys/... mbuf` macro values). **If `CSUM_IP6_TSO` and `CSUM_TSO` are different bits, this extension is required**; if equivalent, this step can be omitted. This is listed as the first verification item during coding.
- `ff_tx_offload` is protocol-agnostic (`ff_veth.c:290-291` comment), `tso_seg_size` carries no v4/v6; downstream branches by `iph->version` (2.1 already solved). Therefore this layer only needs to ensure IPv6 TSO requests can be recognized as "needs TSO"; version judgment is downstream.

**Risk**: Low. After verifying macro relationship, it's a one-line extension.

---

## III. Solution Interaction Matrix and Global Constraints

| Feature/Interaction | LRO | TSO |
| --- | --- | --- |
| Default-off zero regression | `lro=0` doesn't touch LRO path | `tso=0` doesn't touch TSO path |
| Capability detection gating | `rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO` | `tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO` (existing) |
| RX/TX csum | LRO segment csum validated by PMD, receive check logic reused | TSO implies L4 csum, constrained with `tx_csum_offoad_skip` (2.5) |
| RSS | Orthogonal (same-flow same-queue aggregation) | Unrelated |
| Timestamp | Large segment takes aggregation timestamp, logic unchanged | Unrelated |
| jumbo/MTU | `max_lro_pkt_size >= mtu`; aggregation exceeding MTU normal | `if_hw_tsomax` constrains total length (≤65535 dimension) |
| scatter/MULTI_SEGS | Large segments use mbuf chain (receive already supports multi-seg) | Pre-TSO large segments multi-seg (transmit already supports), constrained by tsomaxseg* |
| Multi-process | per-port capability, per-queue aggregation (pending runtime validation) | per-port enablement, consistent setting |

## IV. Honest Boundary Summary (Pending Runtime Validation Checklist)

1. Whether virtio (local) advertises `RTE_ETH_RX_OFFLOAD_TCP_LRO` in `dev_info.rx_offload_capa` (03-external-research.md 2.3).
2. Matching of `max_lro_pkt_size` value with mbuf pool `data_room`/scatter capacity.
3. Correctness of LRO large segments being seamlessly received by FreeBSD protocol stack after `IFCAP_LRO` (02-current-status-and-gap-analysis.md 1.5 main risk point).
4. Precise `l3_len` calculation for IPv6 with extension headers (2.1 first version only supports no extension headers).
5. Precise matching of `if_hw_tsomaxsegcount`/`tsomaxsegsize` with specific PMD capability (2.3).
6. Macro bit relationship between `CSUM_IP6_TSO` and `CSUM_TSO` in FreeBSD 15.0 port (2.6, verify during coding).
7. Per-queue behavior of LRO aggregation under multi-process primary/secondary (1.7).

> All the above are runtime/subsequent milestone validation items; no testing this round. Test environment: DPDK dedicated NIC IP `9.134.214.176` (`ssh f-stack-client` side initiates); kernel stack testing via `127.0.0.1` on `lo`.
