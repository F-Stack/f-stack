# F-Stack LRO/TSO Test and Acceptance Specification

> Document tier: Test and acceptance specification (M4 phase deliverable 1)
> Design basis: `01-requirements-specification.md` (acceptance criteria), `02-current-status-and-gap-analysis.md` (current status/gaps), `04-solution-and-architecture-design.md` (design points and honest boundary checklist), `05-interface-and-config-design.md` (interface change points), `06-milestones-and-work-breakdown.md` (coding milestones CM0-CM7).
> Authoritative version: DPDK `dpdk-stable-24.11.6`, FreeBSD 15.0 port (`f-stack/freebsd/`).
> Iron rule: This round is a **pure documentation phase** (no code writing, no lib changes, no commits). This document defines how to test and accept in the "subsequent implementation phase (CM6)"; all test points include precise `file:line`; use latest code as authoritative during coding (read_file first).

---

## I. General Testing Principles (Red Lines)

1. **All "pass" from actual execution, no speculation**: Any case PASS must have actual runtime evidence (unit test binary exit code, compilation output, packet capture files, `netstat`/xstats counters, log lines). "Code looks correct" is not a pass basis.
2. **Prove default-off zero regression first, then validate enabled**: First prove `dpdk.lro=0` / `dpdk.tso=0` (default values) behavior is byte-for-byte identical to current status (04-solution-and-architecture-design.md 0.2 design invariants, 05-interface-and-config-design.md VIII), then validate `lro=1` / `tso=1` functionality. Zero regression is a hard red line; any enabled-state bug must not be fixed at the expense of the default path.
3. **Hardware-dependent items distinguish "code path pass" vs "end-to-end pass"**: Hardware LRO strongly depends on specific PMD capability (local virtio, see 04-solution-and-architecture-design.md honest boundary checklist). When local PMD doesn't advertise `RTE_ETH_RX_OFFLOAD_TCP_LRO`, items that **can be marked pass** (config parsing / capability detection graceful degradation / compilation / default zero regression) and items that **cannot be marked pass** (end-to-end LRO aggregated receive) must be explicitly tiered; code path pass must not masquerade as end-to-end pass.
4. **Code as authority, file:line verifiable**: Test assertion references to current status/change points all include `file:line`; inconsistencies with pre-read or external conclusions resolved per actual code.
5. **Gate failure must bounce back for fix (bounce≤3)**: Any gate failure bounces back to corresponding milestone (CM1-CM5) for fix; same step bounce no more than 3 times; over 3 times escalates to human; no shelving or carrying bugs forward (06-milestones-and-work-breakdown.md III).
6. **Compilation convention**: Before each lib change in unit/integration testing, `make clean` then full compile; no incremental compilation as pass basis.

---

## II. Unit Test Specification (CMocka Framework)

> Following existing `tests/unit/` framework: lib/*.c independently compiled into `lib_objs/` (`tests/unit/Makefile:166-167`), fixture-driven (`fixtures/*.ini`), `-Wl,--wrap=` interception, three-state gate. Refer to `c-unittest-expert` skill and existing `test_ff_config.c` (fixture-driven pattern, comments in its header §Strategy), `test_ff_dpdk_if.c` (stub + wrap pattern).

### 2.1 test_ff_config: LRO Config Parsing

**Test point**: `ff_config.c:1054-1057` area new `MATCH("dpdk","lro")` parsing branch (05-interface-and-config-design.md 3.1); `ff_config.h` dpdk struct new `int lro;` (05-interface-and-config-design.md 2.2). Test driven end-to-end via the sole non-static entry `ff_load_config()` (following `test_ff_config.c` header strategy).

| Case | Fixture/Input | Assertion | Basis |
| --- | --- | --- | --- |
| TC-LRO-CFG-01 default off | Existing `fixtures/valid_minimal.ini` (no `lro` option) | `ff_global_cfg.dpdk.lro == 0` (default, no MATCH hit stays zero) | 05-interface-and-config-design.md 3.2, 7 table "no lro option→default 0" |
| TC-LRO-CFG-02 explicit on | New fixture (`[dpdk]` with `lro=1`) | `ff_global_cfg.dpdk.lro == 1` | 05-interface-and-config-design.md 3.1 `atoi(value)` |
| TC-LRO-CFG-03 explicit off | New fixture (`lro=0`) | `ff_global_cfg.dpdk.lro == 0` | Symmetric with tso |
| TC-LRO-CFG-04 invalid value | New fixture (`lro=abc`) | `atoi("abc")==0` → `dpdk.lro == 0` (consistent with tso `atoi` semantics, no range validation, 05-interface-and-config-design.md 3.2 validation note) | 05-interface-and-config-design.md 3.2 "non-0 treated as enabled, no range validation" |
| TC-LRO-CFG-05 lro/tso combination | New fixture (`tso=1` + `lro=1`) | `dpdk.tso==1 && dpdk.lro==1`, two switches independent | 04-solution-and-architecture-design.md III interaction matrix |
| TC-LRO-CFG-06 old fixture zero regression | All 45 existing `fixtures/*.ini` (none have `lro` option) | After loading each, `dpdk.lro==0`, and existing assertions (tso/csum/mtu etc.) all unchanged | 05-interface-and-config-design.md 1.1 "old config.ini no lro option zero regression" |

**New fixture list** (in `tests/unit/fixtures/`, minimal changes, refer to `valid_minimal.ini` structure adding `[dpdk] lro=` line): `valid_lro_on.ini`, `valid_lro_off.ini`, `valid_lro_invalid.ini`, `valid_lro_tso_both.ini`. **Constraint**: fixture `port0.addr` etc. use existing test private network (e.g., `192.168.*`), must not use real local IP (config.ini local test value convention doesn't apply to fixtures, but still avoid real environment values).

**Zero regression verification method**: TC-LRO-CFG-06 loads each of 45 old fixtures via `ff_load_config` then diffs `ff_global_cfg` key fields against "pre-lro baseline" consistency; since new branch only takes effect when `lro` key is hit, non-hit path is byte-for-byte unchanged.

### 2.2 test_ff_dpdk_if: LRO Capability Detection and max_lro_pkt_size

**Test point**: `ff_dpdk_if.c:891-898` rewritten LRO enablement block (04-solution-and-architecture-design.md 1.2, 05-interface-and-config-design.md 4.1/4.2). This block is in the port init path, deeply depends on `dev_info`/`port_conf`; existing `test_ff_dpdk_if.c` only covers 7 trivial getter/setters (its header §NOT tested). Therefore this test group **prioritizes host-compilable pure logic extraction + stub `dev_info`** to cover detection decision branches; if detection logic is inlined in a large init function and cannot be called independently, degrades to "integration test static startup log assertion" (see section IV IT-LRO-01), marked in case table.

| Case | Construction | Assertion | Basis |
| --- | --- | --- | --- |
| TC-LRO-CAP-01 capa supported | stub `dev_info.rx_offload_capa` includes `RTE_ETH_RX_OFFLOAD_TCP_LRO` (`rte_ethdev.h:1556`), `dpdk.lro=1` | `port_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO` set; `hw_features.rx_lro==1` | 04-solution-and-architecture-design.md 1.2, 05-interface-and-config-design.md 4.1 contract |
| TC-LRO-CAP-02 capa unsupported | stub `rx_offload_capa` doesn't include LRO bit, `dpdk.lro=1` | offloads doesn't set LRO bit; `rx_lro==0`; logs "LRO is not supported" (graceful degradation not fatal) | 05-interface-and-config-design.md 7 "lro=1 but PMD unsupported", 04-solution-and-architecture-design.md 1.2 |
| TC-LRO-CAP-03 switch off | `dpdk.lro=0` (regardless of capa) | Doesn't enter detection block; offloads no LRO bit; `rx_lro==0`; logs "LRO is disabled" | 05-interface-and-config-design.md 4.1 three-state log, VIII zero regression |
| TC-LRO-CAP-04 max_lro_pkt_size from dev_info | capa supported and `dev_info.max_lro_pkt_size != 0` | `port_conf.rxmode.max_lro_pkt_size == dev_info.max_lro_pkt_size` | 05-interface-and-config-design.md 4.2 prefer dev_info |
| TC-LRO-CAP-05 max_lro_pkt_size conservative default | capa supported and `dev_info.max_lro_pkt_size == 0` | `max_lro_pkt_size` takes conservative default and `>= mtu` (`rte_ethdev.h:432` semantics) | 05-interface-and-config-design.md 4.2, 04-solution-and-architecture-design.md 1.3 `>=mtu` |

**Honest boundary (TC-LRO-CAP-* degradation note)**: The above assertions test "code path correctly sets bits per capa/switch",属于 **code path pass** layer; whether local virtio actually advertises LRO capa belongs to **end-to-end pass** layer, requires runtime `dev_info` testing (see section IV IT-LRO-* and 05-interface-and-config-design.md honest boundary).

### 2.3 test_ff_dpdk_if / standalone unit test: TSO Offload Population (IPv4/IPv6 Branching)

**Test point**: `ff_dpdk_if.c:2455-2465` TSO branch branches by `iph->version` (04-solution-and-architecture-design.md 2.1, 05-interface-and-config-design.md 4.3); if CM5 converges to common function `ff_fill_tx_offload` (05-interface-and-config-design.md 4.4), directly unit test that function (**recommended**: after convergence, the function has no DPDK runtime dependency, host-compilable, highest coverage).

| Case | Construction (mbuf data area forged IP/TCP header + `offload.tso_seg_size` non-0) | Assertion | Basis |
| --- | --- | --- | --- |
| TC-TSO-FILL-01 IPv4 TSO | `iph->version==4`, `offload.tso_seg_size=1448` | `ol_flags` includes `RTE_MBUF_F_TX_IPV4 \| RTE_MBUF_F_TX_IP_CKSUM \| RTE_MBUF_F_TX_TCP_SEG`; `l2_len==RTE_ETHER_HDR_LEN`; `l3_len==iph_len` (IHL<<2); `l4_len==tcph_len`; `tso_segsz==1448`; `tcph->cksum==rte_ipv4_phdr_cksum(...)` | 04-solution-and-architecture-design.md 2.1/2.2, 05-interface-and-config-design.md 4.3 |
| TC-TSO-FILL-02 IPv6 TSO | `iph->version==6`, no extension headers, `tso_seg_size=1448` | `ol_flags` includes `RTE_MBUF_F_TX_IPV6 \| RTE_MBUF_F_TX_TCP_SEG`, **excludes** `RTE_MBUF_F_TX_IP_CKSUM`; `l3_len==40` (`sizeof(struct rte_ipv6_hdr)`); `l4_len`/`tso_segsz` correct; `tcph->cksum==rte_ipv6_phdr_cksum(...)` | 04-solution-and-architecture-design.md 2.1 (IPv6 has no IP header checksum) |
| TC-TSO-FILL-03 l2_len self-consistency | TSO branch hits alone (without first hitting `ip_csum`/`tcp_csum` branch) | `l2_len==RTE_ETHER_HDR_LEN` still filled (04-solution-and-architecture-design.md 2.1 "l2_len moved into TSO branch self-consistent", fixes current L2436 dependency on preceding branch) | 04-solution-and-architecture-design.md 2.1, 02-current-status-and-gap-analysis.md 2.3 table l2_len row |
| TC-TSO-FILL-04 no TSO no trigger | `offload.tso_seg_size==0` (`tso=0` default state) | TSO branch not entered, `ol_flags` excludes `RTE_MBUF_F_TX_TCP_SEG`, behavior identical to current | 05-interface-and-config-design.md VIII zero regression, `ff_dpdk_if.c:2455 if(offload.tso_seg_size)` |

**IPv6 extension header boundary**: TC-TSO-FILL-02 only covers no extension headers (`l3_len=40`); extension header scenario marked **pending enhancement** (04-solution-and-architecture-design.md 2.1 honest boundary, 05-interface-and-config-design.md 7), not in this group's assertion scope.

### 2.4 Unit Test: ff_mbuf_tx_offload CSUM_TSO / CSUM_IP6_TSO Mapping

**Test point**: `ff_veth.c:282-307 ff_mbuf_tx_offload`, especially L304-306 `if (mb->m_pkthdr.csum_flags & CSUM_TSO)` (current only recognizes `CSUM_TSO`); CM4 per macro bit verification result decides whether to extend to `& (CSUM_TSO | CSUM_IP6_TSO)` (04-solution-and-architecture-design.md 2.6, 05-interface-and-config-design.md 5.3).

| Case | Construct mbuf `csum_flags` | Assertion | Basis |
| --- | --- | --- | --- |
| TC-TSO-MAP-01 CSUM_TSO | `csum_flags |= CSUM_TSO`, `tso_segsz=1448` | `offload.tso_seg_size==1448` | `ff_veth.c:304-306` |
| TC-TSO-MAP-02 CSUM_IP6_TSO | `csum_flags |= CSUM_IP6_TSO` (if independent bit) | `offload.tso_seg_size==1448` (should recognize after extension) | 04-solution-and-architecture-design.md 2.6, 05-interface-and-config-design.md 5.3 |
| TC-TSO-MAP-03 no TSO flag | `csum_flags` has no TSO bit | `offload.tso_seg_size==0` | Current default |
| TC-TSO-MAP-04 v4/v6 csum merge | `CSUM_TCP` / `CSUM_TCP_IPV6` | Both map to `tcp_csum==1` (regression guard, TSO changes don't break L292) | `ff_veth.c:290-294` |

**Verification prerequisite (CM4 first item)**: TC-TSO-MAP-02 validity depends on whether `CSUM_IP6_TSO` and `CSUM_TSO` are **independent bits** (coding phase `read_file` `freebsd/sys/.../mbuf.h` verify, 05-interface-and-config-design.md 5.3). If equivalent, TC-TSO-MAP-02 degrades to TC-TSO-MAP-01 coverage, extension code can be omitted; case table must note verification conclusion.

> **Note**: `ff_veth.c` depends on FreeBSD kernel headers, mostly cannot be host-compiled directly (see `test_ff_zc_send.c` header note on ff_veth.c non-host-compilable). Therefore TC-TSO-MAP-* prioritizes "self-contained mbuf shim + extract tested logic" algorithm consistency testing (same as `test_ff_zc_send.c` pattern), or indirectly verifies v6 TSO mapping via peer packet capture in integration testing (section IV).

### 2.5 Receive Path: LRO Large Segment Movement

**Test point**: `ff_veth_input` (`ff_dpdk_if.c:1694-1742`) builds mbuf header with `pkt->pkt_len` (L1708) + multi-segment traversal (L1725-1739); `ff_mbuf_gethdr` (`ff_veth.c:464-485`). Solution verified "length movement already naturally supports LRO large segments" (04-solution-and-architecture-design.md 1.4).

| Case | Construct large segment mbuf | Assertion | Basis |
| --- | --- | --- | --- |
| TC-LRO-RX-01 large pkt_len | Single mbuf, `pkt_len` far exceeds MTU (e.g., 60KB) | Built FreeBSD mbuf `m_pkthdr.len == pkt_len` | 04-solution-and-architecture-design.md 1.4, `ff_dpdk_if.c:1708` |
| TC-LRO-RX-02 nb_segs>1 | mbuf chain `nb_segs>1`, total `pkt_len` large | Multi-segment per-segment attach, final mbuf chain total length == pkt_len | `ff_dpdk_if.c:1725-1739` |
| TC-LRO-RX-03 RX_LRO flag passthrough (optional) | `ol_flags |= RTE_MBUF_F_RX_LRO` | Current status doesn't change movement due to this flag (first version LRO awareness optional enhancement, 04-solution-and-architecture-design.md 1.4 step 2); if passthrough implemented, assertion semantics correct | 04-solution-and-architecture-design.md 1.4 |
| TC-LRO-RX-04 csum flag | `rx_csum` on + LRO large segment csum good | `ff_mbuf_gethdr` sets `CSUM_DATA_VALID\|CSUM_PSEUDO_HDR` (`ff_veth.c:479-483`) holds for large segments | 04-solution-and-architecture-design.md 1.4 step 1 |

> **Note (host compilation limitation)**: `ff_veth_input`/`ff_mbuf_gethdr` depend on FreeBSD mbuf, host compilation difficult. TC-LRO-RX-* prioritizes "extract length/multi-segment movement algorithm + mbuf shim" consistency testing (same as zc_send pattern); real LRO large segment receive end-to-end correctness verified by section IV IT-LRO-* runtime,属于 **end-to-end pass** layer.

### 2.6 Offload Population Duplicate Convergence Consistency

**Test point**: `ff_dpdk_if.c:2405-2472` and `ff_memory.c:331-375` two population logic blocks (02-current-status-and-gap-analysis.md 2.3, 04-solution-and-architecture-design.md 2.4, 05-interface-and-config-design.md 4.4).

| Case | Construction | Assertion | Basis |
| --- | --- | --- | --- |
| TC-TSO-CONV-01 convergence equivalence (Option A) | Same offload input through converged `ff_fill_tx_offload` vs pre-convergence `ff_dpdk_if.c`/`ff_memory.c` field-by-field comparison | Pre/post convergence `ol_flags`/`l2_len`/`l3_len`/`l4_len`/`tso_segsz`/`cksum` completely identical (IPv4+IPv6 each set) | 04-solution-and-architecture-design.md 2.4 Option A |
| TC-TSO-CONV-02 dual sync (Option B fallback) | If fall back to Option B (both synchronized), call both with same input | Both outputs field-by-field identical | 04-solution-and-architecture-design.md 2.4 Option B |

**Note**: If CM5 uses Option A (extract common function), TC-TSO-CONV-02 doesn't apply; if Option B, use TC-TSO-CONV-02 to guard both don't diverge. One or the other, marked per CM5 actual implementation.

---

## III. Build Gate (Compilation Layer)

> Hard gate: Each lib change `make clean` then full compile (06-milestones-and-work-breakdown.md IV compilation convention); no incremental compilation as pass basis.

| Gate | Check Item | Pass Criteria | Basis |
| --- | --- | --- | --- |
| BG-01 lib clean build -Werror | `cd f-stack/lib && make clean && make` (project's existing build method, per its CFLAGS) | Zero errors zero new warnings; **key: verify LRO macro correction compiles** (old macro `DEV_RX_OFFLOAD_TCP_LRO` removed, using `RTE_ETH_RX_OFFLOAD_TCP_LRO`, `rte_ethdev.h:1556`; 02-current-status-and-gap-analysis.md 1.4 notes uncorrected macro direct enablement fails compilation) | 01-requirements-specification.md §6.2, 02-current-status-and-gap-analysis.md III |
| BG-02 example clean build | `f-stack/example/` clean build (helloworld etc.) | Pass | 06-milestones-and-work-breakdown.md CM0 |
| BG-03 unit clean build | `cd f-stack/tests/unit && make clean && make all` | All test binaries compile (including new LRO/TSO cases) | `tests/unit/Makefile:67` |
| BG-04 unit all pass | `cd f-stack/tests/unit && make test` | `ALL TESTS PASS` (including new cases, `Makefile:112-116`) | II unit test spec |
| BG-05 valgrind (optional bonus) | `make check` (`Makefile:132-154`) | No definite leak | Existing check target |
| BG-06 ff_veth.c reference constraint | If project convention `ff_veth.c` doesn't directly reference `rte_eth*` (convergence function placement must avoid breaking this constraint, 05-interface-and-config-design.md 4.4 "place in common position both can include") | No violating references after convergence | 05-interface-and-config-design.md 4.4 |

**BG-06 verification**: Coding phase first `search_content "rte_eth" f-stack/lib/ff_veth.c` to confirm whether this constraint exists; if so, convergence function must not introduce new `ff_veth.c` dependency on `rte_eth*` (place at `ff_dpdk_if.c`/`ff_memory.c` common dependency).

---

## IV. Integration Test Matrix (Runtime, CM6)

> Environment: DPDK dedicated NIC IP `<DPDK_NIC_IP>` (transmit/receive testing must `ssh f-stack-client` from peer); kernel stack control via `127.0.0.1` on `lo` (01-requirements-specification.md 3.3, 06-milestones-and-work-breakdown.md CM0). Tools: `iperf3`, `netstat -sp {ip,ip6,tcp}`, `tcpdump`/packet capture, DPDK `rte_eth_xstats`.

### 4.1 Static Startup Matrix (LRO×TSO Four Combinations)

| Case | config | Expected log/status | Basis |
| --- | --- | --- | --- |
| IT-START-01 | `lro=0,tso=0` (default) | No LRO/TSO enablement log or "LRO is disabled" / TSO not enabled; startup success; consistent with current | 05-interface-and-config-design.md VIII |
| IT-START-02 | `lro=1,tso=0` | virtio supports→"LRO is supported"+offloads includes LRO bit; unsupported→"LRO is not supported" and graceful startup | 04-solution-and-architecture-design.md 1.2, 05-interface-and-config-design.md 4.1 three-state |
| IT-START-03 | `lro=0,tso=1` | "TSO is supported" (`ff_dpdk_if.c:931-942`); startup success | 02-current-status-and-gap-analysis.md 2.2 |
| IT-START-04 | `lro=1,tso=1` | LRO/TSO two logs each per capa; two switches independently effective | 04-solution-and-architecture-design.md III interaction matrix |

**Evidence**: Save startup logs for each combination (grep "LRO is"/"TSO is"), CM0 phase `dev_info` capability table as control (06-milestones-and-work-breakdown.md CM0 step 4).

### 4.2 LRO Receive End-to-End

| Case | Steps | Expected | Basis |
| --- | --- | --- | --- |
| IT-LRO-10 high-throughput receive (lro=1) | `ssh f-stack-client` sends large TCP to `<DPDK_NIC_IP>` (`iperf3 -c <DPDK_NIC_IP>`, or large file download making f-stack the receiver) | Receive normal no drops/no anomalies; `netstat` received bytes correct; packet capture/xstats observe whether merged large segments appear (`RTE_MBUF_F_RX_LRO` or receive count < packet count) | 04-solution-and-architecture-design.md 1.6 data flow, 02-current-status-and-gap-analysis.md 1.5 |
| IT-LRO-11 lro=0 control | Same but `lro=0` | Receive correct; as throughput/CPU baseline control (performance see 08-performance-baseline-plan.md) | Zero regression control |
| IT-LRO-12 IPv6 receive | Send high-throughput TCP to f-stack IPv6 address (`iperf3 -6`) | Receive correct; LRO同样 effective for v6 or gracefully not effective | IPv4/IPv6 separately covered |

**LRO end-to-end honest boundary**: Whether IT-LRO-10/12 observes "aggregated large segments" depends on whether virtio advertises and actually executes LRO (04-solution-and-architecture-design.md honest boundary 1). If IT-START-02 shows "LRO is not supported", IT-LRO-10 **aggregation observation item cannot be marked pass** (end-to-end not passed), but "receive correct no regression" item can still be marked pass. Must record actual `dev_info.rx_offload_capa`, `errno`, packet capture/xstats evidence to support tiered conclusion.

### 4.3 TSO Transmit End-to-End

| Case | Steps | Expected | Basis |
| --- | --- | --- | --- |
| IT-TSO-20 IPv4 large segment transmit (tso=1) | f-stack sends large TCP segments (e.g., f-stack as server pulled by `f-stack-client` for large file), peer `tcpdump` capture | Peer receives correctly MSS-segmented packets; **IP/TCP checksum correct**; no retransmit storms | 04-solution-and-architecture-design.md 2.1/2.2, 02-current-status-and-gap-analysis.md 2.3 |
| IT-TSO-21 **IPv6 large segment transmit (key)** | f-stack IPv6 sends large TCP segments, peer capture | Peer receives correct segmentation; **IPv6 TCP pseudo-header checksum correct** (verifies `rte_ipv6_phdr_cksum` fix, 04-solution-and-architecture-design.md 2.1); `l3_len=40` no extension headers correct | 04-solution-and-architecture-design.md 2.1 (this project's TSO core enhancement point) |
| IT-TSO-22 tso=0 control | Same as IT-TSO-20 but `tso=0` | Software segmentation transmit correct (control baseline); proves `tso=0` zero regression | 05-interface-and-config-design.md VIII |
| IT-TSO-23 TSO + jumbo | `mtu_enable` + jumbo MTU + `tso=1` large segment transmit | Segment length constrained by `if_hw_tsomax` not exceeding bounds (04-solution-and-architecture-design.md 2.3); peer receives correctly | 04-solution-and-architecture-design.md 2.3/2.5 |
| IT-TSO-24 tso=1 + tx_csum_offoad_skip=1 | Inconsistent combination startup | Log WARN (04-solution-and-architecture-design.md 2.5 "TSO depends on L4 csum offload"); no crash | 04-solution-and-architecture-design.md 2.5, 05-interface-and-config-design.md 7 |

**IT-TSO-21 is this project's TSO enhancement key acceptance case**: Current IPv6 TSO uses IPv4 pseudo-header incorrectly (02-current-status-and-gap-analysis.md 2.3 table "pseudo-header checksum" row); after fix, peer capture TCP checksum must be correct. If local virtio doesn't support TX TSO (IT-START-03 shows "TSO is not supported"), TSO goes software segmentation; IT-TSO-21 verifies "lib offload population doesn't break software segmentation path + if hardware effective then pseudo-header correct", must distinguish in records.

### 4.4 IPv4/IPv6 Coverage Matrix

| Dimension | IPv4 | IPv6 |
| --- | --- | --- |
| LRO receive | IT-LRO-10/11 | IT-LRO-12 |
| TSO transmit | IT-TSO-20 | IT-TSO-21 (key) |
| Startup | IT-START-* all included | IT-START-* all included (config port includes vip6) |

---

## V. Honest Boundary and Tiered Acceptance

> Aligned with 04-solution-and-architecture-design.md "honest boundary summary (pending runtime validation checklist)" 7 items; clarifies each item's **can mark pass** (code path/compilation/zero regression layer) and **cannot mark pass** (end-to-end hardware-dependent layer) boundaries in CM6.

| ID (aligned with 04-solution-and-architecture-design.md IV) | Pending Validation | Can Mark Pass (with this evidence) | Cannot Mark Pass (without evidence) | Evidence Requirement |
| --- | --- | --- | --- | --- |
| HB-1 | Whether virtio advertises `RTE_ETH_RX_OFFLOAD_TCP_LRO` | Config parsing, detection code path (TC-LRO-CAP-*), graceful degradation log | End-to-end LRO aggregation (IT-LRO-10) | CM0 `dev_info` capability table + startup log |
| HB-2 | `max_lro_pkt_size` matching mbuf data_room/scatter | Value code path (TC-LRO-CAP-04/05) | Large segment actually accepted by PMD | `dev_configure`/`dev_start` return code |
| HB-3 | LRO large segment received by protocol stack via IFCAP_LRO | Length movement algorithm (TC-LRO-RX-*), `IFCAP_LRO` declared | Protocol stack seamless large segment receive (IT-LRO-10) | Packet capture/`netstat`/no anomaly log |
| HB-4 | IPv6 extension header l3_len | No extension header `l3_len=40` (TC-TSO-FILL-02) | Extension header scenario (not implemented this round) | Marked pending enhancement |
| HB-5 | `if_hw_tsomaxsegcount/segsize` matching PMD | Non-0 limits set (better than current all-0) | Precise values optimal (IT-TSO-23) | Packet capture segmentation within bounds |
| HB-6 | `CSUM_IP6_TSO` vs `CSUM_TSO` macro bit relationship | Verification conclusion + corresponding case (TC-TSO-MAP-02) | — | `read_file` mbuf.h record |
| HB-7 | Multi-process primary/secondary LRO aggregation | per-port capability consistent setting (code path) | per-queue aggregation behavior (IT multi-process) | Multi-process startup + packet capture |

**Tiered recording template** (CM6 each item must fill): `{HB-x} phenomenon=<actual observation> evidence=<log/capture/return code path> conclusion=<code path pass | end-to-end pass | end-to-end not passed (reason)>`. Prohibited writing "end-to-end not passed (virtio unsupported)" as "passed".

---

## VI. Final Acceptance Checklist

> Aligned with 01-requirements-specification.md §4.2 subsequent implementation phase acceptance + 04-solution-and-architecture-design.md honest boundary 7 items. Each item must include evidence path; PASS/tiered marking must not be left blank.

**A. Zero Regression (hard red line, must all PASS)**
- [ ] AC-01 `lro=0` transmit/receive behavior byte-for-byte identical to current (TC-LRO-CFG-06 + IT-START-01 + TC-LRO-RX/CAP off state)
- [ ] AC-02 `tso=0` TSO new logic all untouched (TC-TSO-FILL-04 + IT-TSO-22 + 05-interface-and-config-design.md VIII)
- [ ] AC-03 All 45 old fixtures zero regression (TC-LRO-CFG-06)

**B. Build Gate (must all PASS)**
- [ ] AC-04 lib clean build passes (BG-01, including LRO macro correction compiles)
- [ ] AC-05 example clean build passes (BG-02)
- [ ] AC-06 unit clean build + all pass (BG-03/04)

**C. LRO Functionality (code path layer must PASS; end-to-end layer per HB tiering)**
- [ ] AC-07 config parsing correct (TC-LRO-CFG-01..05)
- [ ] AC-08 capability detection + three-state log + graceful degradation (TC-LRO-CAP-01..03 + IT-START-02)
- [ ] AC-09 max_lro_pkt_size value (TC-LRO-CAP-04/05)
- [ ] AC-10 IFCAP_LRO declaration (code path + startup confirmation)
- [ ] AC-11 LRO large segment movement (TC-LRO-RX-*)
- [ ] AC-12 [end-to-end/tiered] LRO aggregated receive (IT-LRO-10/12, per HB-1/HB-3 tiering, with dev_info evidence)

**D. TSO Enhancement (code path layer must PASS; end-to-end layer per HB tiering)**
- [ ] AC-13 IPv4 TSO population correct and behavior unchanged (TC-TSO-FILL-01)
- [ ] AC-14 **IPv6 TSO pseudo-header/l3_len/flags correct** (TC-TSO-FILL-02 + IT-TSO-21, this project's TSO core)
- [ ] AC-15 IP_CKSUM self-consistency (TC-TSO-FILL-01 IPv4 explicit set)
- [ ] AC-16 CSUM_IP6_TSO mapping (TC-TSO-MAP-02, per HB-6 verification)
- [ ] AC-17 if_hw_tsomax non-0 limits set (HB-5)
- [ ] AC-18 Duplicate logic convergence equivalence (TC-TSO-CONV-01 or 02)
- [ ] AC-19 Combination constraint WARN (IT-TSO-24)
- [ ] AC-20 [end-to-end/tiered] IPv4+IPv6 TSO peer checksum correct (IT-TSO-20/21, per HB tiering)

**E. Honest Boundary (must record each item tiered)**
- [ ] AC-21 HB-1..HB-7 all recorded per section V template phenomenon/evidence/tiered conclusion, no "not passed masquerading as passed"

**Gate ruling**: A/B group any FAIL → bounce back to corresponding CM for fix (bounce≤3). C/D group code path layer FAIL → bounce back; end-to-end layer if "end-to-end not passed" due to hardware capability unsupported, must record per HB tiering honestly, doesn't block A/B and code path layer PASS milestone closure (but must explicitly note unverified items in spec review gate CM7).

---

## VII. Test Point file:line Index (Verifiable Anchors)

| Test Topic | Current Status/Change Point file:line |
| --- | --- |
| LRO config parsing | `ff_config.c:1054-1057` (adjacent to tso, new lro branch); `ff_config.h:295` (dpdk struct) |
| LRO capability detection | `ff_dpdk_if.c:891-898` (`#if 0` block rewrite); `rte_ethdev.h:1556` (`RTE_ETH_RX_OFFLOAD_TCP_LRO`) |
| max_lro_pkt_size | `rte_ethdev.h:432` (rxmode field); `rte_ethdev.h:1792` (dev_info limit) |
| LRO receive movement | `ff_dpdk_if.c:1694-1742` (ff_veth_input); `ff_veth.c:464-485` (ff_mbuf_gethdr) |
| IFCAP_LRO | `ff_veth.c:941-956` (capability setting block) |
| TSO offload population | `ff_dpdk_if.c:2455-2465`; `ff_memory.c:358-368` |
| ff_mbuf_tx_offload | `ff_veth.c:282-307` (L304-306 TSO mapping) |
| if_hw_tsomax | `ff_veth.c:951-953`; FreeBSD `tcp_output.c:905-931` |
| Duplicate convergence | `ff_dpdk_if.c:2405-2472`; `ff_memory.c:331-375` |
| Unit test framework | `tests/unit/Makefile`; `tests/unit/test_ff_config.c` (fixture pattern); `tests/unit/test_ff_dpdk_if.c` (stub/wrap pattern); `tests/unit/test_ff_zc_send.c` (mbuf shim pattern) |

---

## VIII. Software LRO / Software-Hardware Integration Test Specification (Round 2 Supplement)

> Per `11-software-lro-solution.md`, `13-software-hardware-offload-integration.md`. Software TSO has no development (`12-software-tso-and-segmentation-solution.md`); only need to confirm protocol stack MSS segmentation behavior unchanged in zero regression items.

### 8.1 Unit Tests

- **UT-SWLRO-01 sw_lro switch derivation**: mock `dev_info.rx_offload_capa` without LRO bit + `dpdk.lro=1`, assert detection block derives `hw_features.rx_lro=0 && sw_lro=1`; with LRO bit `rx_lro=1 && sw_lro=0`; `lro=0` both 0. (Corresponds to `13-software-hardware-offload-integration.md` 2.2 truth table)
- **UT-SWLRO-02 mutual exclusion invariant**: Traverse `(lro∈{0,1}) × (PMD support∈{yes,no})` four combinations, assert `rx_lro & sw_lro == 0` always holds (never both 1).
- **UT-SWLRO-03 IFCAP_LRO condition**: mock `rx_lro=0,sw_lro=1`, assert `ff_veth.c` capability setting block declares `IFCAP_LRO` (condition `rx_lro||sw_lro`).

### 8.2 Integration Tests (Runtime, Local virtio Testable Items)

- **IT-SWLRO-10 Software LRO fallback enablement** ✅ (local+physical machine 2026-07-23 tested): Local virtio / physical machine NIC both don't support hardware LRO, `lro=1` startup, assert log shows "LRO is not supported, fallback to software" (`13-software-hardware-offload-integration.md` 2.2), `IFCAP_LRO` declaration effective. PASS.
- **IT-SWLRO-11 Software LRO aggregated receive** ✅ (physical machine 2026-07-23 tested): `ssh f-stack-client` sends TCP high-throughput to `<DPDK_NIC_IP>`, software LRO fallback path receives normally, no crash (1261 NULL avoidance effective). Aggregation rate precise statistics (`lro_queued/lro_flushed`) pending iperf high-throughput tool supplement. PASS (no crash + receive correct).
- **IT-SWLRO-12 No-crash verification** ✅ (physical machine 2026-07-23 tested): Continuous high-throughput stress under software LRO enabled, confirm no `tcp_hpts_softclock` NULL dereference crash (verifies Option A classic mode avoidance effective). PASS.
- **IT-SWLRO-13 Software/hardware mutual exclusion** ❌ (pending, not verified): Requires hardware LRO-capable physical NIC. The physical machine NIC used for this test also doesn't support hardware LRO (virtio class); `rx_lro=1` hardware branch has no runtime evidence to date. **Pending replacement with a physical NIC supporting `RTE_ETH_RX_OFFLOAD_TCP_LRO` (ixgbe/i40e/mlx5/ice etc.) for verification**.

### 8.3 Zero Regression (Software Path)

- **RT-SWLRO-20**: When `lro=0` (default), `ff_veth_input` receive path has no software LRO branch (`if(sw_lro)` not entered), byte-for-byte identical to current.
- **RT-SWTSO-21**: When `tso=0` (default), protocol stack MSS segmentation behavior identical to before changes (software TSO has no code changes; this item confirms protocol stack segment-by-segment transmit normal).

### 8.4 Test Point file:line Index (Software Path)

| Test Topic | Current Status/Change Point file:line |
| --- | --- |
| Software LRO integration point | `ff_dpdk_if.c:1707` (ff_veth_input), `:1720` (after ff_mbuf_gethdr) |
| tcp_lro API | `tcp_lro.c:167/173/491/1426/1199/1448`; `tcp_lro.h:161-181/215-222` |
| 1261 NULL bare-call | `tcp_lro.c:1261`; `ff_stub_14_extra.c:627` |
| sw_lro derivation | `ff_dpdk_if.c` LRO detection block; `ff_config.h:112-118` (ff_hw_features) |
| IFCAP_LRO condition | `ff_veth.c:945-947` (extended to rx_lro\|\|sw_lro) |
| Software TSO=MSS segmentation | `tcp_output.c:558`; `tcp_input.c:3973`; `tcp_subr.c:3657/3699` |
