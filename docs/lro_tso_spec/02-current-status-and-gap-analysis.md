# F-Stack LRO/TSO Current Status and Gap Analysis

> Document tier: Current status and gap analysis (M1 phase deliverable 2)
> Method: Layer-by-layer verification of current status using **actual code file:line**, with gap/impact for each item. Inconsistencies with plan mode pre-read are noted as "pre-read was X, actual is Y", resolved per code.
> Authoritative version: DPDK `dpdk-stable-24.11.6`, FreeBSD 15.0 port (`f-stack/freebsd/`).

---

## I. LRO Current Status Layer-by-Layer Analysis (Currently Not Supported)

### 1.1 Config Layer (config.ini)

- **Current status**: `config.ini` has **no `lro` config option** (searching `config.ini` for `lro` yields 0 hits). Only adjacent `tx_csum_offoad_skip` (L19), `tso=0` (L22), `vlan_strip=1` (L25).
- **Gap**: Missing `dpdk.lro` switch; users cannot enable LRO.
- **Impact**: LRO has no entry point; the entire path is broken from the start.

### 1.2 Parsing Layer (ff_config.c)

- **Current status**: `ff_config.c:1054-1057` only parses `dpdk.tso`, `dpdk.tx_csum_offoad_skip`; searching the entire file for `tso` yields only L1054-1055, **no `lro` parsing branch**.
- **Gap**: No `MATCH("dpdk", "lro")` branch; even if config.ini has `lro`, it will not be read.
- **Impact**: `hw_features.rx_lro` never gets the user's config value.

### 1.3 Struct Layer (ff_config.h)

- **Current status**: `struct ff_hw_features` **already contains** `uint8_t rx_lro;` (`ff_config.h:114`), between `rx_csum` (L113) and `tx_csum_ip` (L115). `tx_tso` is at L117. The config struct has `int tso;` (`ff_config.h:295`), **no `int lro;`**.
- **Gap**: `rx_lro` field exists but has **no assignment point (producer) or consumer point (user)**; config struct missing `lro` member.
- **Impact**: Field is a "dead field"; needs producer/consumer on both ends.
- **Correction**: Pre-read question "does rx_lro exist" → actually exists.

### 1.4 DPDK Enablement Layer (ff_dpdk_if.c)

- **Current status**: `ff_dpdk_if.c:891-898` LRO enablement code is fully disabled by `#if 0 ... #endif`:
  ```
  891  /* FIXME: Enable TCP LRO ?*/
  892  #if 0
  893  if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_LRO) {
  894      ff_log(... "LRO is supported\n");
  895      port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TCP_LRO;
  896      pconf->hw_features.rx_lro = 1;
  897  }
  898  #endif
  ```
- **Macro name check**: The `DEV_RX_OFFLOAD_TCP_LRO` used **does not exist in DPDK 24.11.6** (searching `rte_ethdev.h` for `DEV_RX_OFFLOAD_TCP_LRO` yields 0 hits); the correct macro is `RTE_ETH_RX_OFFLOAD_TCP_LRO` (`dpdk-stable-24.11.6/lib/ethdev/rte_ethdev.h:1556`, `#define RTE_ETH_RX_OFFLOAD_TCP_LRO RTE_BIT64(4)`).
- **Gap**: (a) Code disabled by `#if 0`; (b) even removing `#if 0`, `DEV_RX_OFFLOAD_TCP_LRO` is undefined causing **compilation failure**; (c) not controlled by `dpdk.lro` config, and `max_lro_pkt_size` not set.
- **Impact**: `port_conf.rxmode.offloads` never contains the LRO bit; `hw_features.rx_lro` is always 0.
- **Correction**: Pre-read two candidate macros → actually only `RTE_ETH_RX_OFFLOAD_TCP_LRO`.

### 1.5 Receive Path Layer (ff_dpdk_if.c / ff_veth.c)

- **Current status (receive entry)**: `ff_dpdk_if.c:1694-1742 ff_veth_input`:
  - L1697-1703: If `rx_csum` is on, checks `RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD`; drops if bad. **No handling of `RTE_MBUF_F_RX_LRO`**.
  - L1708: `ff_mbuf_gethdr(pkt, pkt->pkt_len, data, len, rx_csum)` builds mbuf header using `pkt->pkt_len` (total chain length).
  - L1725-1739: Traverses `pkt->next` multi-segment chain, attaching each segment via `ff_mbuf_get` (already handles multi-segment/scatter).
  - L1741: `ff_veth_process_packet` → `if_input`.
- **Current status (mbuf header construction)**: `ff_veth.c:464-485 ff_mbuf_gethdr`: `m->m_pkthdr.len = total` (=pkt_len); when `rx_csum`, sets `CSUM_IP_CHECKED|CSUM_IP_VALID|CSUM_DATA_VALID|CSUM_PSEUDO_HDR` and `csum_data=0xffff`. **No LRO-related flags/fields (e.g., mbuf `csum_flags` LRO semantics, `tcp_lro` segment info)**.
- **Current status (delivery)**: `ff_veth.c:510-519 ff_veth_process_packet`: only sets `rcvif` then `if_input`; no LRO special handling.
- **Gap**: Receive path **completely unaware of hardware LRO**. Large segments from hardware LRO (`pkt_len` will be large, `nb_segs` may be >1, with `RTE_MBUF_F_RX_LRO` flag) can be moved into FreeBSD mbuf in terms of **length** via `pkt_len` + multi-segment traversal, but: (a) no `RTE_MBUF_F_RX_LRO` awareness; (b) protocol stack side has not declared support via `IFCAP_LRO`, FreeBSD may handle super-MTU aggregated segments unexpectedly; (c) whether csum semantics hold for LRO large segments needs runtime confirmation.
- **Impact**: Even if PMD LRO is forcibly enabled, whether delivered large segments can be correctly received by the protocol stack is **pending runtime validation**; the lack of explicit LRO path adaptation is the main gap.

### 1.6 Software LRO / stub Layer (ff_stub_14_extra.c / Makefile)

- **Current status**: `ff_stub_14_extra.c:629-639`: `tcp_lro_hpts_init()` returns 0, `tcp_lro_hpts_uninit()` empty body (both empty stubs); `tcp_hpts_softclock` set to NULL (L627).
- **Compile list**: `lib/Makefile:513` includes `tcp_lro.c` (software LRO core compiled); `lib/Makefile:572` includes `tcp_hpts.c`; **`tcp_lro_hpts.c` does not appear in Makefile** (search 0 hits).
- **F-Stack calls**: Searching `ff_veth.c` for `tcp_lro_init|tcp_lro_rx|tcp_lro_flush|tcp_lro` **yields 0 hits** → software LRO has code but **no F-Stack receive path call site**.
- **Gap**: Software LRO is in a "compiled but uncalled" state; HPTS LRO-related capabilities are stubbed out.
- **Impact**: This round focuses on hardware LRO; whether software LRO serves as a supplement/fallback path is left for subsequent evaluation.
- **Correction**: Pre-read question "are tcp_lro.c/tcp_lro_hpts.c compiled" → `tcp_lro.c` is compiled (L513), `tcp_lro_hpts.c` **is not compiled**.

### 1.7 ifnet Capability Layer (IFCAP_LRO)

- **Current status**: `ff_veth.c:941-956` sets interface capabilities: `IFCAP_RXCSUM`(rx_csum), `IFCAP_TXCSUM`+`CSUM_IP`(tx_csum_ip), `CSUM_DELAY_DATA`(tx_csum_l4), `IFCAP_TSO`+`CSUM_TSO`(tx_tso), finally `if_setcapenable(ifp, if_getcapabilities(ifp))`. Searching all of lib for `IFCAP_LRO` **yields 0 hits**.
- **Gap**: **`IFCAP_LRO` is never set**; FreeBSD protocol stack does not consider the interface LRO-capable.
- **Impact**: Protocol stack-level LRO path missing; even if hardware aggregates segments, the ifnet capability bit does not declare LRO.

### 1.8 LRO Gap Summary Table

| Layer | Current Status | Target | Gap | Impact | file:line |
| --- | --- | --- | --- | --- | --- |
| Config | No `lro` item | Add `dpdk.lro`, default 0 | Missing switch | No entry point | `config.ini` (none); cf. `config.ini:22` tso |
| Parsing | Only parses tso etc. | Add `MATCH("dpdk","lro")` | Missing parse branch | Config not read in | `ff_config.c:1054-1057` |
| Struct | `rx_lro` exists but idle; no `int lro` | Add producer/consumer + config member | Dead field | Field invalid | `ff_config.h:114,295` |
| DPDK enablement | `#if 0`+defunct macro `DEV_RX_OFFLOAD_TCP_LRO` | Use `RTE_ETH_RX_OFFLOAD_TCP_LRO`, detect per lro | Disabled+compile fail+no max_lro_pkt_size | offloads never include LRO | `ff_dpdk_if.c:891-898`; `rte_ethdev.h:1556` |
| Receive path | No LRO awareness, only moves chain per pkt_len | Aware of `RTE_MBUF_F_RX_LRO`, csum/length adaptation | No LRO branch | Large segment correct receipt pending runtime validation | `ff_dpdk_if.c:1694-1742`; `ff_veth.c:464-519` |
| Software LRO/stub | tcp_lro.c compiled but no calls; hpts stub | Hardware LRO primary, software LRO evaluated later | No call site | Software LRO not effective | `ff_stub_14_extra.c:629-639`; `Makefile:513,572` |
| IFCAP | No `IFCAP_LRO` | Set `IFCAP_LRO` | Capability not declared | Protocol stack doesn't recognize LRO | `ff_veth.c:941-956` |

---

## II. TSO Current Status Layer-by-Layer Analysis (Already Supported, Find Enhancement Points)

### 2.1 Config and Parsing Layer

- **Current status**: `config.ini:21-22` `# TCP segment offload, default: disabled.` + `tso=0`; `ff_config.c:1054-1055` `MATCH("dpdk","tso") → pconfig->dpdk.tso = atoi(value)`; struct `ff_config.h:295 int tso;`, `ff_config.h:117 uint8_t tx_tso;`.
- **Is it complete**: Complete. Default off, parsing normal, fields present.
- **Gap**: None.

### 2.2 DPDK Enablement Layer

- **Current status**: `ff_dpdk_if.c:931-942`: `if (dpdk.tso)` → if `dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO` then `port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_TSO` and set `hw_features.tx_tso = 1`, else log "TSO is not supported". Macro name `RTE_ETH_TX_OFFLOAD_TCP_TSO` is the correct 24.11.6 macro.
- **Is it complete**: Basically complete.
- **Gap**: Only probes single TCP TSO capability; does not cover IPv6/UFO etc.; acceptable.

### 2.3 Offload Field Population Layer (Field-by-Field Check)

There are **two nearly duplicate** population implementations:

**(A) `ff_dpdk_if.c:2405-2472` (`ff_dpdk_if_send` main transmit path)**:
- L2405-2406: `ff_tx_offload offload = {0}; ff_mbuf_tx_offload(m, &offload);`
- L2410-2420 `if (offload.ip_csum)`: comment "ipv6 not supported yet", takes `iph_len` per IPv4, sets `RTE_MBUF_F_TX_IP_CKSUM|RTE_MBUF_F_TX_IPV4`, `l2_len=RTE_ETHER_HDR_LEN`, `l3_len=iph_len`.
- L2422-2471 `if (ctx->hw_features.tx_csum_l4)`: sets `RTE_MBUF_F_TX_IPV4`/`_IPV6` per `iph->version` (L2428-2432);
  - L2434-2438 tcp_csum: sets `TCP_CKSUM`, `l2_len`, `l3_len`;
  - **L2455-2465 TSO**: `if (offload.tso_seg_size)` → `tcph = iph + iph_len` (**strong cast per IPv4 struct**), `tcph->cksum = rte_ipv4_phdr_cksum(iph, RTE_MBUF_F_TX_TCP_SEG)` (**IPv4 pseudo-header only**), `ol_flags |= RTE_MBUF_F_TX_TCP_SEG`, `l4_len = tcph_len`, `tso_segsz = offload.tso_seg_size`.
  - L2467-2471 udp_csum: sets `UDP_CKSUM`, `l2_len`, `l3_len`.

**(B) `ff_memory.c:331-375` (another transmit path, structure nearly identical to A)**:
- L358-368 TSO branch: same `rte_ipv4_phdr_cksum(iph, RTE_MBUF_F_TX_TCP_SEG)` (IPv4 only), sets `TCP_SEG`, `l4_len`, `tso_segsz`.

**Field-by-field conclusion** (TSO branch actual population):

| Field | IPv4 Populated? | Location | IPv6 Populated? |
| --- | --- | --- | --- |
| `RTE_MBUF_F_TX_TCP_SEG` | Yes | `ff_dpdk_if.c:2462` / `ff_memory.c:365` | Same branch but pseudo-header wrong |
| `l2_len` | Yes (in tcp_csum branch L2436; or ip_csum branch L2418) | — | Depends on preceding branch |
| `l3_len` | Yes (tcp_csum branch L2437) | — | Depends on preceding branch |
| `l4_len` | Yes | `ff_dpdk_if.c:2463` / `ff_memory.c:366` | Yes (but based on IPv4 offset) |
| `tso_segsz` | Yes | `ff_dpdk_if.c:2464` / `ff_memory.c:367` | Yes |
| `RTE_MBUF_F_TX_IPV4/_IPV6` | Yes (L2428-2432 per version) | — | Yes |
| `RTE_MBUF_F_TX_IP_CKSUM` (required for IPv4 TSO) | **No** (TSO branch does not explicitly set IP_CKSUM; depends on whether ip_csum branch L2417 hits) | — | N/A |
| Pseudo-header checksum | `rte_ipv4_phdr_cksum` | L2460 / L363 | **Wrong: IPv6 also uses IPv4 pseudo-header** |

- **Is it complete**: **IPv4 TSO basically complete** (l2/l3/l4/segsz/TCP_SEG all present).
- **Gap**:
  1. **IPv6 TSO missing/incorrect**: TSO branch unconditionally uses `rte_ipv4_phdr_cksum` and IPv4 header struct; for IPv6 large-segment TSO, pseudo-header checksum is wrong, and `l3_len` based on IPv4 IHL is inapplicable → IPv6 TSO unusable.
  2. **TSO branch does not explicitly set `RTE_MBUF_F_TX_IP_CKSUM`**: DPDK semantics require IPv4 TSO to also request IP checksum offload; currently depends on whether `offload.ip_csum` (from `CSUM_IP`) happens to be set, not self-consistent with TSO.
  3. **Two duplicates**: `ff_dpdk_if.c` and `ff_memory.c` logic diverges; fixing IPv6 requires changing both, easy to miss.
- **Impact**: Default `tso=0` no impact; once TSO is enabled and IPv6 is used, transmit anomalies/checksum errors.
- **Correction**: Pre-read concern "only l4_len/tso_segsz seen, are l2/l3/TCP_SEG populated" → actually l2_len/l3_len are populated in the adjacent tcp_csum branch, TCP_SEG flag is set; the real gap is **IPv6 and IP_CKSUM self-consistency**.

### 2.4 Offload Source Layer (ff_veth.c ff_mbuf_tx_offload)

- **Current status**: `ff_veth.c:282-307 ff_mbuf_tx_offload`: maps FreeBSD mbuf `csum_flags` to `ff_tx_offload`: `CSUM_IP→ip_csum`, `CSUM_TCP|CSUM_TCP_IPV6→tcp_csum`, `CSUM_UDP|CSUM_UDP_IPV6→udp_csum`, `CSUM_SCTP|CSUM_SCTP_IPV6→sctp_csum`, **`CSUM_TSO→tso_seg_size = mb->m_pkthdr.tso_segsz`** (L304-306).
- **Is it complete**: TCP/UDP csum already does v4/v6 merged mapping; **but TSO only recognizes `CSUM_TSO`**, does not distinguish IPv6 TSO semantics (FreeBSD has `CSUM_IP6_TSO`).
- **Gap**: `ff_tx_offload` is protocol-agnostic (comment L290-291), `tso_seg_size` carries no v4/v6 info; downstream can only judge via `iph->version`, and the downstream TSO branch恰恰 doesn't branch pseudo-header calculation by version → IPv6 broken.

### 2.5 IPv4 vs IPv6 TSO (FreeBSD Side Cross-Reference)

- **Current status**: In `freebsd/netinet`, `CSUM_IP6_TSO|CSUM_TSO` hits 6 files (`ip_output.c`×4, `tcp_subr.c`×4, `tcp_input.c`×1, `tcp_output.c`×1, `bbr.c`×2, `rack.c`×3) → FreeBSD 15.0 **natively supports IPv6 TSO semantics**.
- **`tcp_output.c:1404-1405`**: `m->m_pkthdr.csum_flags |= CSUM_TSO; m->m_pkthdr.tso_segsz = tp->t_maxseg - optlen - ipsec_optlen;` → protocol stack may set `CSUM_TSO` for both IPv4/IPv6 (no v6 distinction here).
- **Gap**: FreeBSD side will set TSO flag for IPv6 segments and hand to lib, but lib downstream only processes per IPv4 → **v6 gap is in the lib porting layer, not FreeBSD side**.

### 2.6 TSO Interaction with Other Features

- **With checksum offload / `tx_csum_offoad_skip`**: `ff_config.c:1056` parses `tx_csum_offoad_skip`; `ff_dpdk_if.c:914-929` enables IPv4/L4 csum offload only when skip=0. TSO implicitly requires L4 csum offload, but TSO enablement (L931-942) **is not constrained by `tx_csum_offoad_skip`**; the two may produce an inconsistent combination of "TSO on but L4 csum offload skipped".
- **With scatter / MULTI_SEGS**: `ff_dpdk_if.c:2360-2403` transmit already supports multi-segment mbuf chains (per-segment copy, `head->nb_segs++`); TSO large segments are inherently multi-segment scenarios; path exists but PMD constraints on `nb_segs`/`tso_segsz` combinations need confirmation.
- **With `mtu_enable` (jumbo)**: `ff_config.c:1068-1072` parses `mtu_enable`/`max_mtu`; `ff_dpdk_if.c:954+` validates MTU range. TSO segment length is constrained by jumbo MTU and `if_hw_tsomax` (see 2.7).
- **Gap/Impact**: The correctness of the above combinations needs explicit constraints in the solution design (e.g., "TSO depends on L4 csum offload, should not coexist with skip"), with runtime validation.

### 2.7 FreeBSD Side TSO Segmentation and tsomax

- **Current status**: `freebsd/netinet/tcp_output.c:905-931` TSO decision: `if_hw_tsomax = tp->t_tsomax`, `if_hw_tsomaxsegcount = tp->t_tsomaxsegcount`, `if_hw_tsomaxsegsize = tp->t_tsomaxsegsize`; L927 `if (if_hw_tsomax != 0)` then calculates `max_len` limit; L1093-1095 `tcp_m_copym(..., if_hw_tsomaxsegcount, if_hw_tsomaxsegsize, ...)` constrains segmentation accordingly.
- **lib side setting**: `ff_veth.c:951-953` only `if_setcapabilitiesbit(ifp, IFCAP_TSO, 0)` + `if_sethwassistbits(ifp, CSUM_TSO, 0)`; searching all of lib for `if_hw_tsomax` **yields 0 hits** → **lib never sets `if_hw_tsomax`/`tsomaxsegcount`/`tsomaxsegsize`**.
- **Gap**: If `t_tsomax` series is 0, `tcp_output.c:927` branch does not take effect; TSO segment length is not constrained by interface limit, may generate large segments exceeding PMD/jumbo capability.
- **Impact**: Default off no impact; after enabling TSO, large segments may exceed PMD single-packet/segment-count limits, causing transmit rejection or truncation by PMD (pending runtime validation).
- **Enhancement point**: Set `if_hw_tsomax` series limits on ifnet side per PMD capability/`max_mtu`.

### 2.8 TSO Enhancement Points Summary Table

| Enhancement Point | Current Status | Target | Gap | Impact | file:line |
| --- | --- | --- | --- | --- | --- |
| IPv6 TSO pseudo-header | Always `rte_ipv4_phdr_cksum` | Use `rte_ipv6_phdr_cksum` per version | IPv6 pseudo-header wrong | v6 TSO unusable | `ff_dpdk_if.c:2455-2465`; `ff_memory.c:358-368` |
| IPv6 TSO l3_len | Calculated per IPv4 IHL | IPv6 fixed 40 (+ extension headers) | v6 l3_len wrong | v6 segmentation wrong | `ff_dpdk_if.c:2415/2458` |
| IP_CKSUM self-consistency | TSO branch doesn't explicitly set `TX_IP_CKSUM` | IPv4 TSO explicitly set | Depends on ip_csum hitting | Potential checksum missing | `ff_dpdk_if.c:2455-2465` |
| tsomax limit | lib never sets `if_hw_tsomax` | Set limit per PMD/MTU | Limit missing | Segments may exceed PMD capability | `ff_veth.c:951-953`; `tcp_output.c:905-931` |
| Logic duplication | if.c and memory.c dual copies | Converge/share | Divergence easy to miss | Maintenance risk | `ff_dpdk_if.c:2405-2472`; `ff_memory.c:331-375` |
| Interaction with csum_skip | TSO enablement not constrained by skip | Constrain mutual exclusion/dependency | Inconsistent combination | Potential mismatch | `ff_dpdk_if.c:914-942` |
| Offload source v6 | Only recognizes `CSUM_TSO` | Compatible with `CSUM_IP6_TSO` semantics | v6 flag not distinguished | v6 broken | `ff_veth.c:304-306` |

---

## III. Macro Name Verification Conclusion (Authoritative: DPDK 24.11.6)

| Purpose | Current Code Name | DPDK 24.11.6 Actual Macro | Conclusion |
| --- | --- | --- | --- |
| LRO receive offload | `DEV_RX_OFFLOAD_TCP_LRO` (`ff_dpdk_if.c:893/895`, inside `#if 0`) | `RTE_ETH_RX_OFFLOAD_TCP_LRO` (`rte_ethdev.h:1556` `= RTE_BIT64(4)`) | **Must rename**; old macro `DEV_RX_OFFLOAD_TCP_LRO` removed in 24.11.6, search 0 hits, direct enablement fails compilation |
| TSO transmit offload | `RTE_ETH_TX_OFFLOAD_TCP_TSO` (`ff_dpdk_if.c:932/934`) | `RTE_ETH_TX_OFFLOAD_TCP_TSO` (correct) | No change needed |
| RX/TX csum | `RTE_ETH_RX_OFFLOAD_*` / `RTE_ETH_TX_OFFLOAD_*` (`ff_dpdk_if.c:901-924`) | Same | No change needed |
| mbuf TSO flag | `RTE_MBUF_F_TX_TCP_SEG` (`ff_dpdk_if.c:2462`) | Same (old `PKT_TX_TCP_SEG`) | No change needed |

**Core correction**: Plan mode pre-read listed `DEV_RX_OFFLOAD_TCP_LRO` and `RTE_ETH_RX_OFFLOAD_TCP_LRO` as two candidates; actually 24.11.6 **only has the latter**, with no compat alias for the former. This is the primary correction item for LRO implementation.

---

## IV. Overall Conclusion

1. **LRO**: From config to protocol stack, **all six layers broken** (no config item/no parsing/field idle/DPDK `#if 0`+defunct macro/receive no LRO awareness/no `IFCAP_LRO`); needs full new connection via hardware offload path; software LRO (`tcp_lro.c`) is compiled but has no call site, not the first choice this round.
2. **TSO**: IPv4 basically usable; main enhancement points focus on **IPv6 TSO broken link** (downstream always uses IPv4 pseudo-header), **`if_hw_tsomax` limit not set**, **duplicate dual logic**, **combination consistency with csum_skip**. FreeBSD side natively supports IPv6 TSO; gap is in the lib porting layer.
3. All conclusions involving specific PMD behavior (LRO large segment receive, TSO segment length limit, csum correctness) are marked **pending runtime validation**; no testing this round.

---

## V. Software LRO / Software TSO and Software/Hardware Integration Current Status (Round 2 Supplement)

> Background: Round 1 completed the hardware offload path (config lro switch, `RTE_ETH_RX_OFFLOAD_TCP_LRO` enablement, `IFCAP_LRO`, TSO IPv6 branching, `if_hw_tsomax`); runtime validation confirmed the local virtio does not support hardware TSO/LRO (`guest_features=0x110ef8020`) and gracefully degrades. This round focuses on **user-space protocol stack software LRO/software TSO** and **software path ↔ hardware offload integration**. All verified with actual file:line (working dir `f-stack/`, DPDK `dpdk-stable-24.11.6/`), three-way cross-consistent (leader verification + sw-path-explorer probing + web-researcher external).

### 5.1 Software LRO Current Status (tcp_lro.c compiled but completely not wired in)

- **Call sites = 0**: Searching all `lib/*.c` for `tcp_lro_(init|init_args|rx|flush_all|queue_mbuf|free)` **yields 0 hits**. Software LRO has code but no calls; in a "compiled but uncalled" state.
- **API complete** (`freebsd/netinet/tcp_lro.c` / `tcp_lro.h`):
  - `tcp_lro_init`(tcp_lro.c:167), `tcp_lro_init_args`(:173), `tcp_lro_free`(:491), `tcp_lro_rx`(:1426), `tcp_lro_flush_all`(:1199), `tcp_lro_queue_mbuf`(:1448); `tcp_lro_flush` is a static internal function(:86/:1109). Declarations tcp_lro.h:215-222.
  - `struct lro_ctrl` definition tcp_lro.h:161-181 (`ifp`/`lro_mbuf_data`/`lro_mbuf_count,max`/`lro_hash`/`lro_active,free`).
- **Two aggregation modes** (external FreeBSD Journal corroborates):
  - Classic: `tcp_lro_init` + `tcp_lro_rx` (direct entry into `tcp_lro_rx_common` for aggregation).
  - Modern RSS sorted: `tcp_lro_init_args` (allocates paired array) + `tcp_lro_queue_mbuf` (stores sequence numbers; when array full, `tcp_lro_flush_all` sorts first to make same-flow adjacent then aggregates).
- **iflib integration pattern (golden reference, f-stack does not use iflib)**: `iflib.c:462` one `struct lro_ctrl ifr_lc` per rxq; init `tcp_lro_init_args`(iflib.c:6035); per-packet `tcp_lro_queue_mbuf`(iflib.c:3000, `lro_enabled` gates L2999); batch end `tcp_lro_flush_all`(iflib.c:3029); free `tcp_lro_free`(iflib.c:6056/6079). **`iflib.c` is not compiled into f-stack** (Makefile search iflib=0); f-stack uses its own `ff_veth` receive, needs to follow this pattern to integrate.
- **⚠ hpts stub key risk**:
  - `tcp_lro.c:73` includes `tcp_hpts.h`; flush function pointer `tcp_lro_flush_tcphpts`(:92) when NULL safely falls back at L1114-1116 to `tcp_lro_condense` (core aggregation can work without hpts).
  - **But `tcp_lro_flush_all` ending at tcp_lro.c:1261 bare-calls `tcp_hpts_softclock()`**, and `ff_stub_14_extra.c:627` `tcp_hpts_softclock=NULL` → **if software LRO is wired in via `tcp_lro_flush_all`, it will dereference NULL and crash**. This is the #1 blocking risk for software LRO integration; must be handled in the solution (see 11-software-lro-solution.md).
  - `tcp_lro_hpts.c` not in Makefile (=0, as expected); `ff_stub_14_extra.c:629-639` `tcp_lro_hpts_init`/`uninit` are empty stubs, only affecting hpts-side LRO acceleration, not blocking basic software aggregation.

### 5.2 Software TSO Current Status (Essence = Protocol Stack MSS Segmentation, Naturally Working, No Development Needed)

- **Logic chain verified**:
  - `tcp_output.c:558-565`: `if ((tp->t_flags & TF_TSO) && V_tcp_do_tso && len > tp->t_maxseg ...) tso = 1;`, L993-994 `else tso = 0`.
  - `TF_TSO` sole set point: `tcp_input.c:3973-3974` `if (cap.ifcap & CSUM_TSO) tp->t_flags |= TF_TSO;`.
  - `cap.ifcap` source: `tcp_subr.c:3657-3660` (IPv4, requires `IFCAP_TSO4 && if_hwassist & CSUM_TSO`) / `:3699-3701` (IPv6, `IFCAP_TSO6`).
- **Conclusion**: NIC without TSO → `ff_veth.c:955` `tx_tso=0` → does not set `IFCAP_TSO/CSUM_TSO` → `cap.ifcap` lacks `CSUM_TSO` → `TF_TSO` not set → `tso=0` → `tcp_output` sends small packets segment by segment per `t_maxseg`(MSS) (normal `sendalot` loop). `CSUM_TSO` only set when `tso=1` (tcp_output.c:1401-1405). **"Software TSO" = inherent protocol stack MSS segmentation, already working, no gap, no development needed** (`tcp_var.h:789 TF_TSO=0x01000000`).

### 5.3 DPDK Software Offload Library Current Status (rte_gso/rte_gro exist but f-stack zero usage)

- `dpdk-stable-24.11.6/lib/gso/` (`rte_gso_segment` @rte_gso.h:120), `lib/gro/` (`rte_gro_reassemble_burst` @rte_gro.h:111, `rte_gro_reassemble` :142, `rte_gro_ctx_create` :78, get results `rte_gro_timeout_flush`) all exist.
- **f-stack `lib/*.c` search `rte_gso|rte_gro|gso_segment|gro_reassemble` yields 0 hits**, completely unused.
- Positioning (external DPDK official): `rte_gro` = software replacement for hardware LRO (receive aggregation), `rte_gso` = software replacement for hardware TSO (transmit segmentation); both require **explicit application calls**, are not thread-safe, do not recompute checksums, require manual `l2/l3/l4_len`; `rte_gso` currently IPv4 only. Optional software offload supplement paths.

### 5.4 Software/Hardware Offload Integration Current Status (Only Substantive Gap = Receive-Side Software LRO Not Integrated)

- **Receive `ff_veth_input`(ff_dpdk_if.c:1707-1748)**: `rx_csum` BAD drop(:1711)→`ff_mbuf_gethdr(pkt, pkt->pkt_len, ...)`(:1720) whole-segment delivery→multi-segment chain traversal(:1737-1751). **Software LRO integration gap is here, before `ff_mbuf_gethdr`** (natural integration point for `tcp_lro_rx/queue_mbuf` aggregation when hardware does not support LRO).
- **Transmit `ff_dpdk_if_send`(ff_dpdk_if.c:2360+) + tx assembly(:2434 tx_csum_l4)**: directly hands protocol stack mbuf to PMD, no software segmentation position. Since software TSO already does MSS segmentation in the protocol stack (5.2), the transmit side gets small packets; **transmit side has no gap** (rte_gso is optional optimization, not required).
- **`ff_mbuf_tx_offload`(ff_veth.c:283-308)**: L305-307 only takes `tso_segsz` when `csum_flags & CSUM_TSO`; NIC without TSO means protocol stack does not set `CSUM_TSO` → `tso_seg_size` not set → **protocol stack and hardware capability naturally consistent, no conflict**.
- **`struct ff_hw_features`(ff_config.h:112-118)**: `rx_csum`(113)/`rx_lro`(114)/`tx_csum_ip`(115)/`tx_csum_l4`(116)/`tx_tso`(117), all uint8_t. Populated ff_dpdk_if.c:895/914/926/933/947 (gated by dev_info offload_capa); consumed ff_veth.c:942-961 + ff_dpdk_if.c:1709/2434.
- **config.ini offload items**: `tx_csum_offoad_skip=0`(:19), `tso=0`(:22), `lro=0`(:24). No independent rx/tx csum switches (auto-enabled by NIC capability).

### 5.5 Software Path Gap Summary Table

| Layer | Current Status | Target | Gap | file:line |
| --- | --- | --- | --- | --- |
| Software LRO calls | tcp_lro.c compiled but 0 call sites | ff_veth_input integrates tcp_lro | No integration point | Makefile:513; ff_dpdk_if.c:1707 |
| Software LRO hpts | flush_all bare-calls NULL tcp_hpts_softclock | Avoid/safely handle :1261 | NULL dereference crash risk | tcp_lro.c:1261; ff_stub_14_extra.c:627 |
| Software TSO | Protocol stack MSS segmentation (naturally working) | No development needed | **No gap** | tcp_output.c:558; tcp_input.c:3973 |
| rte_gso/gro | Exists but zero usage | Optional, not this round | Optional supplement | dpdk lib/gso, lib/gro |
| Software/hardware integration switch | Only hardware lro switch | Software/hardware coordinated switch semantics | Missing software fallback semantics | config.ini:24; ff_config.h |
| Transmit-side integration | Protocol stack and hardware naturally consistent | No change needed | **No gap** | ff_veth.c:305-307 |

### 5.6 This Round Overall Conclusion

1. **Software LRO**: Completely not wired in (0 call sites); needs integration of `struct lro_ctrl` into `ff_veth_input` following the iflib pattern (init/rx/flush/free); **#1 blocking risk is the bare call to NULL `tcp_hpts_softclock` at tcp_lro.c:1261**, must be handled first.
2. **Software TSO**: Essence is protocol stack MSS segmentation, naturally working, **no development needed**; `rte_gso` is optional optimization, out of scope this round.
3. **Software/hardware integration**: The only substantive gap is receive-side software LRO integration; transmit-side TSO/csum protocol stack and hardware capability are naturally consistent, no gap. Need to design software/hardware coordinated switch semantics (hardware preferred + software fallback) and zero-regression guarantee.
4. All conclusions involving specific PMD/runtime behavior are marked **pending runtime validation** (software LRO aggregation correctness, CPU/latency benefits, interaction with congestion control, etc.).

---

## VI. Software LRO Implementation Results (2026-07-22, commit 8e320eeee)

### 6.1 Actual Changed Files List

| File | Change | Description |
| --- | --- | --- |
| `lib/ff_config.h` | +1 line | ff_hw_features added `uint8_t sw_lro` |
| `lib/ff_memory.h` | +1 line | ff_dpdk_if_context added `void *lro` (void* because ff_dpdk_if.c lacks FreeBSD include paths) |
| `lib/ff_veth.h` | +5 lines | Added ff_lro_init/ff_lro_free/ff_lro_rx/ff_lro_flush declarations |
| `lib/ff_veth.c` | +40 lines | include tcp_lro.h + implement 4 wrappers (malloc(M_DEVBUF)+tcp_lro_init/rx/flush_inactive/free) + IFCAP_LRO extension |
| `lib/ff_dpdk_if.c` | +30/-6 lines | Detection block sw_lro fallback + register/deregister/input/loop integration + ctx const removal |
| `lib/ff_api.symlist` | +4 lines | ff_lro_* symbols (due to Makefile localize/globalize mechanism) |

### 6.2 Architecture Adjustment (Difference from spec 11/13 Design)

Spec 11/13 originally designed ff_dpdk_if.c to directly include tcp_lro.h. During implementation, it was found that **ff_dpdk_if.c compilation command lacks `-I.../freebsd`** (DPDK layer CFLAGS, not FreeBSD layer), so it cannot include FreeBSD headers. Architecture adjustment: LRO logic is encapsulated in ff_veth.c (FreeBSD layer, with full include paths), and ff_dpdk_if.c calls ff_lro_* wrappers via ff_veth.h declarations. ff_memory.h uses `void *lro` (no need for complete lro_ctrl type). This is a cleaner layering (DPDK layer calls FreeBSD layer wrappers).

### 6.3 Integration Test Results (Local virtio)

| Scenario | IPv4 | IPv6 | f-stack log | Crash |
| --- | --- | --- | --- | --- |
| lro=1 (software fallback) | HTTP 200, 1.8ms | HTTP 200, 1.3ms | "LRO is not supported, fallback to software" | **None** (1261 avoidance effective) |
| lro=0 (zero regression) | HTTP 200, 1.8ms | HTTP 200, 1.4ms | "LRO is disabled" | None |

- **1261 avoidance verification**: lro=1 continuous operation without `tcp_hpts_softclock` NULL crash; classic mode (tcp_lro_rx+flush_inactive) avoidance effective.
- **Mutual exclusion verification**: virtio does not support hardware LRO → sw_lro=1, rx_lro=0 (software fallback); if hardware supports then rx_lro=1, sw_lro=0.
- **Zero regression**: lro=0 → ctx->lro=NULL (calloc zero-init), all new branches `if(ctx->lro!=NULL)` not entered, byte-for-byte identical to before changes.

### 6.4 Gate and Honest Boundary

- **Gate**: Leader bypass read-only verification of 12 key points all PASS (sw_lro field/mutual exclusion/lifecycle/integration point/1261 avoidance/IFCAP extension/symbol export/compilation/zero regression/style). Gatekeeper sub-agent did not respond due to team-mode environment delay (consistent with previous spec round); per fallback mechanism, submitted based on bypass verification + integration tests.
- **Pending items**: (1) Unit tests (sw_lro derivation/mutual exclusion/IFCAP) — logic is inside ff_dpdk_init_port/ff_veth_attach (not standalone functions), mock requires refactoring extraction, deferred; (2) Software LRO aggregation rate/CPU/latency benefits — requires high-throughput tools (iperf etc.), deferred; (3) Hardware LRO end-to-end aggregated receive path (`rx_lro=1` branch) — the physical machine test NIC also does not support hardware LRO (virtio class), so this path is not yet runtime-validated (see 6.5).

### 6.5 Physical Machine Test Results (2026-07-23)

Physical machine testing complete, no issues for now. The physical machine NIC used for testing **also does not support hardware LRO** (virtio class), so this physical machine test **only covers the software LRO fallback scenario**, same `sw_lro=1` path as the local virtio test.

| Scenario | IPv4 | IPv6 | f-stack log | Crash |
| --- | --- | --- | --- | --- |
| lro=1 (software fallback) | Normal | Normal | "LRO is not supported, fallback to software" | **None** (1261 avoidance effective) |
| lro=0 (zero regression) | Normal | Normal | "LRO is disabled" | None |

- **Verified**: Software LRO fallback path (`sw_lro=1`) works normally on the physical machine; 1261 NULL avoidance effective; `lro=0` zero regression; IPv4/IPv6 both normal.
- **Pending (end-to-end not verified)**: Hardware LRO aggregated receive path (`rx_lro=1`, `IT-LRO-10` aggregation observation, `HB-1` end-to-end, `IT-SWLRO-13` software/hardware mutual exclusion hardware branch) — because the physical machine NIC also does not support hardware LRO, this path has no runtime evidence to date. Requires a physical NIC that supports `RTE_ETH_RX_OFFLOAD_TCP_LRO` (e.g., ixgbe/i40e/mlx5/ice etc.) to verify.
