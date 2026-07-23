# F-Stack LRO/TSO Spec Review Gate

> Document tier: Spec review gate (M5 phase deliverable, issued by independent review agent)
> Review objects: `00`~`08` total 9 Chinese spec documents + `plan.md`.
> Review method: **Independent review agent (different from document-writing agent, strict write/review separation) item-by-item `read_file` actual code verification, code as authority, no speculation**. All `file:line`/macro names/structs referenced in documents are re-checked against workspace actual files during review.
> Authoritative version: DPDK `dpdk-stable-24.11.6`, FreeBSD 15.0 port (`f-stack/freebsd/`).
> Iron rule: This round is a **pure documentation phase** (no code written, no lib changed, no commits). This gate only reviews documents + issues conclusions, does not modify `00`~`08` content.

---

## I. Review Dimensions and Criteria

| Dimension | Criteria |
| --- | --- |
| M1 Code file:line consistency | Spot-check key references; review agent `read_file` actual code verification; consistent = PASS |
| M2 LRO six-layer closed loop | config→parsing→struct→DPDK enablement→rxmode→receive→IFCAP no gaps |
| M3 TSO enhancement closed loop | IPv6 branching/IP_CKSUM self-consistency/tsomax/duplicate convergence/CSUM_IP6_TSO/combination constraints all have solution + test |
| M4 Requirement coverage | Q0 (hardware LRO path)/Q1 (LRO full new + TSO enhancement) implemented |
| M5 Honest boundary | Pending runtime validation items truthfully annotated, no speculation masquerading |
| M6 Inter-document consistency | 01-08 cross-references/conclusions/file:line self-consistent no contradictions |
| M7 Hard constraints | Pure documentation didn't change code; config.ini local values not committed statement; lib minimal comments; macro names correct |

---

## II. Code file:line Consistency Check (Review Agent Actual Test)

> Each row's "actual test" column is the result of this review's `read_file`/`search_content` on workspace actual files.

| Reference Point | Document Claim | Review Actual Test | Conclusion |
| --- | --- | --- | --- |
| LRO capa macro `RTE_ETH_RX_OFFLOAD_TCP_LRO` | `rte_ethdev.h:1556` = `RTE_BIT64(4)` | `dpdk-stable-24.11.6/lib/ethdev/rte_ethdev.h:1556 #define RTE_ETH_RX_OFFLOAD_TCP_LRO RTE_BIT64(4)` | **PASS** |
| Old macro `DEV_RX_OFFLOAD_TCP_LRO` doesn't exist | 24.11.6 hits 0 | `rte_ethdev.h` search hits **0** | **PASS** |
| `max_lro_pkt_size` (rxmode / dev_info) | `rte_ethdev.h:432` / `:1792` | `:432` (rxmode)/`:1792` (dev_info), comment "Maximum allowed/configurable size of LRO aggregated packet" | **PASS** |
| LRO `#if 0` block | `ff_dpdk_if.c:891-898`, uses old macro | `:891` FIXME comment, `:892 #if 0`, `:893/895 DEV_RX_OFFLOAD_TCP_LRO`, `:896 rx_lro=1`, `:898 #endif` | **PASS** |
| TSO detection three-state | `ff_dpdk_if.c:931-942` | `:931 if (dpdk.tso)`, `:932 RTE_ETH_TX_OFFLOAD_TCP_TSO`, `:933/938/941` three-state log | **PASS** |
| TSO offload population/pseudo-header | `ff_dpdk_if.c:2455-2465`, `rte_ipv4_phdr_cksum` | `:2455 if(offload.tso_seg_size)`, `:2460 rte_ipv4_phdr_cksum(iph, RTE_MBUF_F_TX_TCP_SEG)`, `:2462 TCP_SEG`, `:2463 l4_len`, `:2464 tso_segsz` | **PASS** |
| ip_csum branch sets TX_IP_CKSUM | `ff_dpdk_if.c:2417` (TSO depends on this hit) | `:2417 head->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4` | **PASS** |
| `ff_config.h` rx_lro field | `:114` (between rx_csum:113 and tx_csum_ip:115) | `:113 rx_csum`, `:114 uint8_t rx_lro`, `:115 tx_csum_ip`, `:117 tx_tso` | **PASS** |
| `ff_config.h` dpdk struct tso, no lro | `:295 int tso;` | `:295 int tso;`, `:296 int tx_csum_offoad_skip;`, no `int lro` | **PASS** |
| `ff_config.c` tso parsing, no lro | `:1054-1057` | `:1054-1055 MATCH("dpdk","tso")`, `:1056-1057 tx_csum_offoad_skip`; `lro` hits **0** | **PASS** |
| `ff_veth.c` CSUM_TSO mapping | `:304-306` only recognizes `CSUM_TSO` | `:304 if(csum_flags & CSUM_TSO)`, `:305 tso_seg_size=tso_segsz`; `:292 CSUM_TCP\|CSUM_TCP_IPV6` | **PASS** |
| `ff_veth.c` capability block/no IFCAP_LRO | `:941-956`, TSO `:951-953` | `:941 rx_csum→IFCAP_RXCSUM`, `:951-953 tx_tso→IFCAP_TSO+CSUM_TSO`, `:956 setcapenable`; `IFCAP_LRO` all lib hits **0** | **PASS** |
| `ff_mbuf_gethdr` | `:464-485`, csum flags `:479-483` | `:464 ff_mbuf_gethdr`, `:474 m_pkthdr.len=total`, `:479-482 CSUM_*_VALID/PSEUDO_HDR+csum_data=0xffff` | **PASS** |
| `ff_memory.c` TSO population | `:358-368`, `:363 rte_ipv4_phdr_cksum` | `:358 if(offload.tso_seg_size)`, `:363 rte_ipv4_phdr_cksum`, `:365 TCP_SEG`, `:366 l4_len`, `:367 tso_segsz` | **PASS** |
| `ff_stub_14_extra.c` LRO/HPTS stub | `:629-639` empty stub | `:627 tcp_hpts_softclock=NULL`, `:630-633 tcp_lro_hpts_init returns 0`, `:636-639 tcp_lro_hpts_uninit empty body` | **PASS** |
| `ff_veth_input` receive path | `:1694-1742` | `:1694 ff_veth_input`, `:1698-1703 rx_csum BAD drop`, `:1708 ff_mbuf_gethdr(pkt,pkt->pkt_len,...)`, `:1725-1739 multi-segment traversal`, `:1741 ff_veth_process_packet` | **PASS** |
| `tcp_output.c` tsomax | `:905-931`, `:927 if(if_hw_tsomax!=0)` | `:905 if(tso)`, `:911-913 t_tsomax/segcount/segsize`, `:927 if(if_hw_tsomax!=0)`, `:929 max_len` | **PASS** |
| `config.ini` tso=0, no lro | `:22 tso=0` | `:21 comment`, `:22 tso=0`; `lro` hits **0** | **PASS** |
| Makefile compile list | `:513 tcp_lro.c`, `:572 tcp_hpts.c`, tcp_lro_hpts.c not compiled | `:513 tcp_lro.c`, `:572 tcp_hpts.c`; `tcp_lro_hpts.c` hits **0** | **PASS** |
| `rx_lro` dead field | Has field no consumer | All lib only 2 hits: `ff_config.h:114` (definition)+`ff_dpdk_if.c:896` (dead assignment inside `#if 0`), no effective consumer | **PASS** |
| `if_hw_tsomax` not set | All lib hits 0 | All lib hits **0** | **PASS** |

**Dimension M1 conclusion: PASS** (19/19 spot-check points completely consistent with actual code; document `00`'s `890-897`/`2448-2465` are M0 plan-mode pre-read values, already corrected in `01`/`02` with precise values `891-898`/`2455-2465` and explicitly noted, normal convergence, not contradiction.)

**Review additional verification (beyond documents, strengthening honest boundary)**: `freebsd/sys/mbuf.h:735 #define CSUM_TSO (CSUM_IP_TSO|CSUM_IP6_TSO)`, `:670 CSUM_IP6_TSO=0x1000`. Proves `CSUM_TSO` already includes `CSUM_IP6_TSO` bit → `ff_veth.c:304` current can already recognize IPv6 TSO segments. This point `04`/`05` documents both **honestly marked as "pending verification, if equivalent then can be omitted"** (not speculated as "required"), review considers honest boundary handling appropriate; this review has pre-resolved in `09` document R-TSO-05 and backfilled.

---

## III. Per-Dimension Assertion Checklist

### M2: LRO Six-Layer Closed Loop

| # | Assertion | Conclusion | Evidence |
| --- | --- | --- | --- |
| G-LRO-1 | Config layer has `dpdk.lro` new design (default 0) | PASS | `04` 1.1, `05` 1.1; aligned with `config.ini:22 tso=0` |
| G-LRO-2 | Parsing layer has `MATCH("dpdk","lro")` design | PASS | `05` 3.1, adjacent to `ff_config.c:1054` tso parsing |
| G-LRO-3 | Struct layer activates `rx_lro` (`ff_config.h:114`) + adds `int lro` | PASS | `05` 2.1/2.2; actual `:114` exists, `:295` no lro |
| G-LRO-4 | DPDK enablement layer removes `#if 0` + corrects macro + detects per capa | PASS | `04` 1.2, `05` 4.1; macro `:1556` verified |
| G-LRO-5 | rxmode layer sets `max_lro_pkt_size` (`>=mtu`, prefer dev_info) | PASS | `04` 1.3, `05` 4.2; `rte_ethdev.h:432/1792` verified |
| G-LRO-6 | Receive layer handles LRO large segments (length movement supported + LRO flag optional) | PASS | `04` 1.4; `ff_dpdk_if.c:1708/1725-1739` verified |
| G-LRO-7 | Protocol stack/ifnet layer sets `IFCAP_LRO` | PASS | `04` 1.5, `05` 5.1; `ff_veth.c:941-956` verified no LRO |
| G-LRO-8 | Default-off zero regression (all six layers hang under switches) | PASS | `05` VIII, `09` C-01 |

**M2 conclusion: PASS (six-layer closed loop no gaps).**

### M3: TSO Enhancement Closed Loop

| # | Assertion | Conclusion | Evidence |
| --- | --- | --- | --- |
| G-TSO-1 | IPv6 TSO branches by version (`rte_ipv6_phdr_cksum`+l3_len=40) | PASS | `04` 2.1, `05` 4.3; downstream `:2455-2465`/`:358-368` current IPv4-only verified |
| G-TSO-2 | IPv4 TSO explicitly sets `RTE_MBUF_F_TX_IP_CKSUM` self-consistency | PASS | `04` 2.2, `05` 4.3; current `:2417` depends on preceding branch verified |
| G-TSO-3 | `if_hw_tsomax` series sets non-0 limits | PASS | `04` 2.3, `05` 5.2; `tcp_output.c:927`/lib hits 0 verified |
| G-TSO-4 | Duplicate logic convergence (Option A/B) | PASS | `04` 2.4, `05` 4.4; `:2405-2472` vs `:331-375` duplication verified |
| G-TSO-5 | `CSUM_IP6_TSO` compatibility (decide modify/omit after verification) | PASS | `04` 2.6, `05` 5.3 honestly marked "pending verification"; review verified = can omit (mbuf.h:735) |
| G-TSO-6 | Combination constraint with `tx_csum_offoad_skip` (WARN) | PASS | `04` 2.5, `05` 7; `ff_dpdk_if.c:914-942` verified |
| G-TSO-7 | Each enhancement point has corresponding test case | PASS | `07` TC-TSO-FILL/MAP/CONV, IT-TSO-20..24 |

**M3 conclusion: PASS (TSO enhancement points all have solution + test; core IPv6 broken link accurately located, verified real broken link is in downstream pseudo-header calculation not `ff_veth.c:304`).**

### M4: Requirement Coverage (Q0/Q1)

| # | Assertion | Conclusion | Evidence |
| --- | --- | --- | --- |
| G-REQ-1 | Q0 hardware LRO / DPDK offload path (not software LRO first choice) | PASS | `01` 3.2, `04` 0.1; software LRO (tcp_lro.c compiled no calls) explicitly deferred |
| G-REQ-2 | Q1-LRO full new development complete support implemented | PASS | `04` I (six layers), `06` CM1-CM3 |
| G-REQ-3 | Q1-TSO enhancement points all implemented | PASS | `04` II, `06` CM4-CM5 |
| G-REQ-4 | Test/performance baseline covers LRO+TSO+IPv4/IPv6 | PASS | `07` IV matrix, `08` III matrix |

**M4 conclusion: PASS.**

### M5: Honest Boundary

| # | Assertion | Conclusion | Evidence |
| --- | --- | --- | --- |
| G-HB-1 | virtio LRO/TSO capability marked "pending runtime validation" | PASS | `03` 2.3, `04` IV.1, `07` HB-1, `08` VI |
| G-HB-2 | IPv6 extension header scenario marked "pending enhancement" | PASS | `04` 2.1, `07` HB-4, `09` R-TSO-02 |
| G-HB-3 | tsomax precise value / max_lro_pkt_size matching marked runtime calibration | PASS | `04` IV.2/.5, `07` HB-2/HB-5 |
| G-HB-4 | CSUM_IP6_TSO macro bit relationship marked "coding phase verification" (not speculated) | PASS | `04` 2.6, `05` 5.3; review verified and backfilled `09` R-TSO-05 |
| G-HB-5 | Multi-process per-queue aggregation marked runtime validation | PASS | `04` 1.7, `07` HB-7 |
| G-HB-6 | Test tiering: code path pass ≠ end-to-end pass | PASS | `07` I.3, section V template, `08` VI |

**M5 conclusion: PASS (honest boundary complete; especially macro bit relationship not speculated as "required", but marked for verification, review actual test proves this cautious handling correct).**

### M6: Inter-Document Consistency

| # | Assertion | Conclusion | Evidence |
| --- | --- | --- | --- |
| G-DOC-1 | LRO macro name unified across all documents as `RTE_ETH_RX_OFFLOAD_TCP_LRO` | PASS | `00`~`08` consistent; old macro only in "correction record" context |
| G-DOC-2 | Key file:line cross-document consistent (891-898/2455-2465/114/295 etc.) | PASS | `01`/`02`/`04`/`05`/`07`/`08` consistent; `00` pre-read values corrected in `01`/`02` |
| G-DOC-3 | Six-layer/enhancement points/CM/test/HB numbering cross-document traceable | PASS | `04`↔`05`↔`06`(CM)↔`07`(TC/IT/HB)↔`08`(PB) chain complete |
| G-DOC-4 | Zero regression conclusion consistent across all documents (lro=0/tso=0 byte-for-byte identical) | PASS | `01` 4.2, `04` 0.2, `05` VIII, `07` I.2, `08` I.1 |
| G-DOC-5 | Index (`00` document index) matches actual files complete | PASS | `00`~`08` + `plan.md` all exist; `09`/`10` supplemented this round |

**M6 conclusion: PASS (no substantive contradictions; `00` vs `01`/`02` line number differences are "M0 pre-read→M1 correction" explicit convergence, documents have explicitly noted correction records, not contradictions).**

### M7: Hard Constraints

| # | Assertion | Conclusion | Evidence |
| --- | --- | --- | --- |
| G-CON-1 | This round pure documentation, no lib code changed | PASS | Only generated `docs/lro_tso_spec/zh_cn/*.md`; lib actual test matches document-described current status (unchanged) |
| G-CON-2 | config.ini local test values not committed statement complete | PASS | `05` 1.1, `06` IV, `09` E-01; only `lro=0` feature changes allowed |
| G-CON-3 | lib minimal comment principle followed | PASS | `04` 0.2.4, `05` IX; no comments on self-explanatory code |
| G-CON-4 | Macro names correct (LRO uses RTE_ETH_*, no old macro) | PASS | `06` IV table, `02` III; review actual test `:1556` |
| G-CON-5 | rm/kill/chmod via scripts, clean build, commit English etc. conventions explicitly registered in coding milestones | PASS | `06` IV convention table, `07` I.6 |

**M7 conclusion: PASS.**

---

## IV. bounce Convention Notes

- This gate is a **documentation phase gate**: review agent only issues review conclusions, **does not rewrite** `00`~`08` (write/review separation). If non-passing items found, leader bounces back to corresponding document-writing agent for fix.
- Any dimension FAIL → bounce back to previous step for fix; same issue bounce **no more than 3 times**; over 3 times escalates to human decision, no shelving as "known issue" or carrying bugs forward.
- Coding phase (CM1-CM7) gate bounce convention see `06` document III, `07` document I.5: gate failure bounces back to corresponding CM, bounce≤3, over limit escalates to human.
- This round bounce count: **0** (first-round review all dimensions PASS, no bounces).

---

## V. Issues Found List

> Review actual test found no substantive defects causing rework. The following are **advisory/enhancement** observations (non-blocking, for coding milestone reference):

1. **[Advisory · already pre-resolved in 09] `CSUM_IP6_TSO` extension redundancy**: `04` 2.6 / `05` 5.3 suggested extending `ff_veth.c:304` to `& (CSUM_TSO | CSUM_IP6_TSO)`. Review actual test `freebsd/sys/mbuf.h:735 CSUM_TSO=(CSUM_IP_TSO|CSUM_IP6_TSO)` already includes this bit; this extension is redundant (equivalent result), can be omitted. Document marking it as "pending verification" is **correct cautious handling**; `09` document R-TSO-05 has backfilled verification conclusion. **Not a defect**.
2. **[Note · not a defect] `00` vs `01`/`02` line number differences**: `00` document is M0 plan-mode pre-read (`890-897`/`2448-2465`), `01`/`02` already corrected with precise values (`891-898`/`2455-2465`) and explicitly noted in "key correction records". Normal convergence, `00` document header already notes "M0 pre-read, M1 verify". Suggest (optional) adding a line at `00` top "line numbers per 01/02 as authoritative" to further reduce misreading. **Non-blocking**.
3. **[Note · not a defect] `ff_memory.c` vs `ff_dpdk_if.c` difference degree**: `02` 2.3 calls both "structure nearly line-by-line identical". Review actual test `ff_memory.c:331-375` **lacks** `ff_dpdk_if.c:2410-2420`'s `if (offload.ip_csum)` preceding block and `:2428-2432`'s version flag branch, i.e., `ff_memory.c` population is simpler (only tcp_csum/tso/udp_csum three branches). Document "nearly identical" slightly broad, but TSO branch (this project's focus) is indeed line-by-line identical, convergence solution (`04` 2.4) still holds. Suggest noting the IPv4/IPv6 flag setting difference during coding convergence. **Non-blocking**.

---

## VI. Overall Review Conclusion

**Review conclusion: CONDITIONAL PASS (deliverable, with 3 advisory/note observations, all non-blocking).**

Ruling basis:

- **Code file:line consistency (M1)**: 19/19 spot-check points verified by review agent actual `read_file`/`search_content`, completely consistent with workspace actual code (including DPDK macro `:1556`, old macro hits 0, `#if 0` block `:891-898`, TSO `:2455-2465`, `rx_lro:114`, `tso:295`, `IFCAP_LRO`/`if_hw_tsomax` hits 0, etc.).
- **LRO six-layer closed loop (M2) / TSO enhancement closed loop (M3) / requirement coverage (M4) / honest boundary (M5) / document consistency (M6) / hard constraints (M7)**: all PASS.
- **Honest boundary handling especially reliable**: Documents did not speculate on virtio capability, IPv6 extension headers, tsomax precise values, `CSUM_IP6_TSO` macro bit relationship, but marked "pending runtime/coding phase verification". Review's actual test of macro bit relationship (`CSUM_TSO` already includes `CSUM_IP6_TSO`) proves this cautious handling **correct** — if document had speculated "extension required", it would have introduced redundant code. This reflects "code as authority, no speculation" convention implementation.
- **No rework-level defects**: 3 observations are all advisory/notes (macro extension redundancy can be omitted, `00` pre-read line numbers already corrected, `ff_memory.c` difference degree slightly broad), do not affect solution actionability and document correctness, thus CONDITIONAL PASS not FAIL.

**Conditions for upgrade to full PASS (optional)**: Coding phase uses this gate §V three observations as authoritative (macro extension can be omitted, note `ff_memory.c` difference), and (optionally) add a line at `00` top that line numbers per `01`/`02` are authoritative. All the above are enhancement items, not delivery prerequisites.

**Pending runtime validation items (not document defects, closed in coding phase)**: virtio LRO/TSO capability (HB-1), `max_lro_pkt_size` matching (HB-2), LRO large segment protocol stack receive (HB-3), IPv6 extension header l3_len (HB-4), tsomax precise value (HB-5), multi-process per-queue aggregation (HB-7). All truthfully annotated in documents, must be verified at runtime in CM0/CM3/CM6.

---

## VII. Review Traceability Anchors

| Review Item | Actual Test File:Line |
| --- | --- |
| LRO capa macro | `dpdk-stable-24.11.6/lib/ethdev/rte_ethdev.h:1556` |
| max_lro_pkt_size | `rte_ethdev.h:432` (rxmode) / `:1792` (dev_info) |
| LRO #if 0 block | `f-stack/lib/ff_dpdk_if.c:891-898` |
| TSO detection | `ff_dpdk_if.c:931-942` |
| TSO offload population | `ff_dpdk_if.c:2405-2472` (TSO branch `:2455-2465`) |
| ff_memory TSO population | `ff_memory.c:331-375` (TSO branch `:358-368`) |
| rx_lro field/dpdk struct | `ff_config.h:114` / `:295` |
| config parsing | `ff_config.c:1054-1057` |
| ff_mbuf_tx_offload / CSUM_TSO | `ff_veth.c:282-307` (`:304-306`) |
| Capability block / IFCAP_LRO missing | `ff_veth.c:941-956` |
| ff_mbuf_gethdr | `ff_veth.c:464-485` |
| ff_veth_input | `ff_dpdk_if.c:1694-1742` |
| LRO/HPTS stub | `ff_stub_14_extra.c:627-639` |
| tcp_output tsomax | `freebsd/netinet/tcp_output.c:905-931` |
| CSUM_TSO macro bit relationship | `freebsd/sys/mbuf.h:670` (CSUM_IP6_TSO) / `:735` (CSUM_TSO composite) |
| config.ini | `f-stack/config.ini:22` |
| Compile list | `f-stack/lib/Makefile:513` (tcp_lro.c) / `:572` (tcp_hpts.c) |

---

## VIII. Software LRO / Software TSO / Software-Hardware Integration Gate Checklist (Round 2 Supplement)

> Review assertions for `11-software-lro-solution.md`, `12-software-tso-and-segmentation-solution.md`, `13-software-hardware-offload-integration.md` three new documents + 02/03/06/07/08/09 supplements. Item-by-item PASS/FAIL, with actual test file:line; this round is **document gate** (spec phase, no code implementation).

### 8.1 Software LRO Assertions

| # | Assertion | Verification Anchor |
| --- | --- | --- |
| S1 | Software LRO current 0 call sites (not connected) conclusion correct | lib/*.c search tcp_lro_* = 0 |
| S2 | tcp_lro API signatures/line numbers accurate | tcp_lro.c:167/173/491/1426/1199/1448; tcp_lro.h:161-181/215-222 |
| S3 | tcp_lro.c:1261 NULL bare-call risk verification accurate | tcp_lro.c:1261; ff_stub_14_extra.c:627 |
| S4 | Classic mode avoidance of 1261 path argument correct (tcp_lro_rx doesn't contain bare-call) | tcp_lro.c:1426/1108-1122 |
| S5 | Integration point ff_veth_input定位 accurate | ff_dpdk_if.c:1707/1720 |
| S6 | iflib pattern reference accurate (not compiled into f-stack) | iflib.c:462/3000/3029/6035; Makefile search iflib=0 |

### 8.2 Software TSO Assertions

| # | Assertion | Verification Anchor |
| --- | --- | --- |
| S7 | Software TSO = protocol stack MSS segmentation logic chain complete correct | tcp_output.c:558; tcp_input.c:3973; tcp_subr.c:3657/3699; ff_veth.c:955 |
| S8 | Software TSO no development needed conclusion correct (transmit side no gap) | ff_veth.c:305-307 (CSUM_TSO gating) |
| S9 | rte_gso positioning accurate (optional, not introduced this round) | dpdk lib/gso rte_gso.h:120 |

### 8.3 Software-Hardware Integration Assertions

| # | Assertion | Verification Anchor |
| --- | --- | --- |
| S10 | Only substantive gap = receive-side software LRO not connected conclusion correct | 13 document §0/§9 |
| S11 | Switch semantics Option A (single lro auto-select) argument reasonable | 13 document §2 |
| S12 | Software/hardware LRO mutual exclusion truth table correct (rx_lro & sw_lro==0 always holds) | 13 document §4.2 |
| S13 | IFCAP_LRO condition needs extension rx_lro\|\|sw_lro conclusion correct | ff_veth.c:945-947 |
| S14 | sw_lro included in ff_hw_features decision reasonable | ff_config.h:112-118; 13 document §3.3 |
| S15 | Zero regression argument correct (lro=0/tso=0 new branches unreachable) | 13 document §5 |

### 8.4 Cross-Verification and Code as Authority

| # | Assertion | Notes |
| --- | --- | --- |
| S16 | External conclusions consistent with code (software TSO=segmentation, rte_gro/gso positioning, iflib pattern) | 03 document §4.6 cross-table |
| S17 | Current code already ahead of old documents (IFCAP_LRO/if_hw_tsomax/lro=0 already exist) truthfully calibrated | design-writer found; 02/13 annotated per latest code |
| S18 | rte_gro get-results API corrected to rte_gro_timeout_flush (not get_pkt) | 03 document §4.3 |

### 8.5 Document Gate Summary Conclusion

- **Document completeness**: 11/12/13 new + 02/03/06/07/08/09/00/10 supplements, covering software LRO/software TSO/software-hardware integration three aspects.
- **Code as authority**: All assertions include file:line, cross-verified with code; where current code ahead of old documents has been calibrated.
- **Honest boundary**: Software LRO aggregation correctness/CPU benefit/1261 avoidance effectiveness/sw_lro field placement etc. all marked pending runtime/coding verification.
- **bounce≤3**: Document gate failure bounces back to corresponding document for fix, over 3 times escalates to human.
