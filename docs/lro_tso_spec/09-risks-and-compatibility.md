# F-Stack LRO/TSO Risks and Compatibility Analysis

> Document tier: Risks and compatibility (M4/M5 phase deliverable)
> Design basis: `02-current-status-and-gap-analysis.md`, `04-solution-and-architecture-design.md`, `05-interface-and-config-design.md`, `06-milestones-and-work-breakdown.md`, `07-test-and-acceptance-specification.md`, `08-performance-baseline-plan.md`.
> Authoritative version: DPDK `dpdk-stable-24.11.6`, FreeBSD 15.0 port (`f-stack/freebsd/`).
> Iron rule: This round is **pure documentation phase**, no code writing, no lib changes, no commits. All risk items include precise `file:line` and control measures; all conclusions involving specific PMD behavior are marked "**pending runtime validation**".
> Risk level definitions: **High** = may cause transmit/receive failure/crash/silent packet drop/compilation failure; **Medium** = functional anomaly or performance below expectation under specific combinations; **Low** = small impact, easy to control, clear fallback.

---

## I. LRO Risk Register (Full New Development, Hardware Offload Path)

### R-LRO-01 Receive Semantic Change (Super-MTU Large Segment Delivered to Protocol Stack) [Medium]

- **Description**: After LRO is enabled, `ff_veth_input` (`ff_dpdk_if.c:1694-1742`) delivered mbuf `pkt_len` will far exceed single-frame MTU (this is LRO's purpose). Current receive path only moves via `pkt->pkt_len` (`ff_dpdk_if.c:1708`) + multi-segment traversal (`:1725-1739`) in the **length dimension**, with no special marking for "super-MTU segments"; whether FreeBSD protocol stack can seamlessly receive this large segment depends on whether the interface has declared `IFCAP_LRO` (current all lib hits 0, see `ff_veth.c:941-956`) and protocol stack receive logic for large segments.
- **Impact**: If `IFCAP_LRO` is not declared but PMD LRO is forcibly enabled, protocol stack may handle super-MTU TCP segments unexpectedly (drop/reassembly anomaly).
- **Level**: Medium.
- **Control measures**: (1) Solution requires setting `IFCAP_LRO` first (`04-solution-and-architecture-design.md` 1.5, `05-interface-and-config-design.md` 5.1) before enabling; (2) Default `lro=0` this path completely not triggered (zero regression); (3) End-to-end receive correctness listed in CM3/CM6 runtime validation (`07-test-and-acceptance-specification.md` IT-LRO-10/12, HB-3).

### R-LRO-02 Combination with jumbo (`mtu_enable`) / data_room / scatter [Medium]

- **Description**: LRO aggregated large segments typically exceed single mbuf `data_room`, requiring mbuf chain (scatter) or sufficiently large data_room; `max_lro_pkt_size` (`rte_ethdev.h:432`) must match carrying capacity. jumbo MTU and `max_lro_pkt_size` are different dimensions (single frame vs aggregated segment), must ensure `max_lro_pkt_size >= mtu` (`04-solution-and-architecture-design.md` 1.3).
- **Impact**: When `max_lro_pkt_size` value too large but mbuf carrying capacity insufficient, PMD may error at `dev_configure`/`dev_start` or drop segments at runtime.
- **Level**: Medium.
- **Control measures**: (1) Value preferentially uses `dev_info.max_lro_pkt_size` (`rte_ethdev.h:1792`) advertised limit; when PMD doesn't advertise, take conservative default (`05-interface-and-config-design.md` 4.2); (2) Receive path already supports multi-segment chains (`ff_dpdk_if.c:1725-1739`), carrying path exists; (3) Precise matching value listed for runtime calibration (HB-2).

### R-LRO-03 Combination with RX csum / RSS [Low]

- **Description**: LRO large segment L4 checksum is completed by PMD during aggregation; receive csum check (`ff_dpdk_if.c:1698-1703`, checks `RTE_MBUF_F_RX_L4_CKSUM_BAD` drop) still applies to large segments; `ff_mbuf_gethdr` sets `CSUM_DATA_VALID|CSUM_PSEUDO_HDR` when `rx_csum` (`ff_veth.c:479-483`) holds for large segments. RSS and LRO are orthogonal (RSS distributes different flows, LRO aggregates same-flow within same queue).
- **Impact**: No additional risk under normal conditions; only if PMD LRO segment csum semantics differ from expected, may falsely drop.
- **Level**: Low.
- **Control measures**: Reuse existing csum check logic, no new branches; LRO segment csum correctness listed for runtime validation (HB-3).

### R-LRO-04 virtio (Local) Capability Dependency [High (for "end-to-end verifiability")]

- **Description**: Hardware LRO strongly depends on PMD advertising `RTE_ETH_RX_OFFLOAD_TCP_LRO` in `dev_info.rx_offload_capa` (`rte_ethdev.h:1556`). virtio LRO/TSO capability is limited by backend negotiation (`VIRTIO_NET_F_*`) (`03-external-research.md` 2.3); whether local virtio advertises LRO **cannot be statically asserted**.
- **Impact**: If local virtio doesn't advertise LRO capa, when `lro=1` code takes graceful degradation (logs "LRO is not supported", `rx_lro` stays 0), LRO end-to-end aggregation **cannot be verified in this environment** (not "no gain", but "untestable").
- **Level**: High (for "whether end-to-end verifiable"); for stability **Low** (has graceful degradation, not fatal).
- **Control measures**: (1) Capability detection gating (only set bit when capa advertised, aligned with `ff_dpdk_if.c:901-906`/`931-942` pattern); (2) Graceful degradation when unsupported, not fatal (`05-interface-and-config-design.md` 7); (3) CM0 first reads `dev_info` (`06-milestones-and-work-breakdown.md` CM0 step 4); (4) End-to-end aggregation item tiered per HB-1, prohibited from masquerading "code path pass" as "end-to-end pass" (`07-test-and-acceptance-specification.md` section V).

### R-LRO-05 Protocol Stack Receiving LRO Large Segments (Behavior after IFCAP_LRO) [Medium]

- **Description**: Even after declaring `IFCAP_LRO` (solution `04-solution-and-architecture-design.md` 1.5 new addition), whether FreeBSD 15.0 protocol stack receive path for LRO merged segments (reassembly, sequence numbers, timestamp handling) can seamlessly integrate with f-stack user-space stack still needs runtime verification (`02-current-status-and-gap-analysis.md` 1.5 main risk point).
- **Impact**: Receive anomalies may manifest as throughput decreasing instead of increasing, reordering, or connection anomalies.
- **Level**: Medium.
- **Control measures**: CM3/CM6 end-to-end validation (IT-LRO-10/12), with `netstat`/packet capture/no anomaly log as evidence (HB-3); default-off zero regression fallback.

### R-LRO-06 Multi-Process (primary/secondary) LRO Aggregation Behavior [Medium]

- **Description**: Offload capability detection and `port_conf` done in primary process; secondary shares port config; per-queue LRO aggregation actual behavior under RSS multi-queue/multi-process needs runtime verification (`04-solution-and-architecture-design.md` 1.7).
- **Impact**: Under multi-process, if per-queue aggregation behavior inconsistent with single-process, some queues may not aggregate or aggregate abnormally.
- **Level**: Medium.
- **Control measures**: per-port capability consistent setting (each process's `ff_veth_setup` declares per `cfg->hw_features.rx_lro` consistently); per-queue behavior listed for runtime validation (HB-7).

### R-LRO-07 `rx_lro` Dead Field Activation Introducing Path Changes [Low]

- **Description**: `hw_features.rx_lro` (`ff_config.h:114`) is currently a dead field — all lib only two hits: definition (`ff_config.h:114`) and dead assignment inside `#if 0` (`ff_dpdk_if.c:896`), no effective consumer. Solution activates it to real production (`ff_dpdk_if.c` LRO detection block set 1) + consumption (`ff_veth.c` `IFCAP_LRO`).
- **Impact**: After activation, `rx_lro` will truly affect `IFCAP_LRO` declaration; if production/consumer not paired (e.g., set 1 but `ff_veth.c` doesn't consume), capability bit inconsistency.
- **Level**: Low.
- **Control measures**: Production point (`ff_dpdk_if.c` detection block) and consumer point (`ff_veth.c:941-956` new) must be implemented as a pair (CM2 + CM3); unit test covers detection set (TC-LRO-CAP-01..03).

---

## II. TSO Enhancement Risk Register (Already Supported, Completing Enhancement Points)

### R-TSO-01 IPv6 TSO Pseudo-header/l3_len Fix Correctness [High]

- **Description**: Current TSO branch (`ff_dpdk_if.c:2455-2465`, `ff_memory.c:358-368`) **unconditionally** uses `rte_ipv4_phdr_cksum` (`ff_dpdk_if.c:2460`, `ff_memory.c:363`) with IPv4 header struct strong cast; for IPv6 large-segment TSO, pseudo-header checksum is wrong, `l3_len` based on IPv4 IHL is also wrong. Solution changes to branch by `iph->version`, IPv6 uses `rte_ipv6_phdr_cksum` + `l3_len=40` (`04-solution-and-architecture-design.md` 2.1).
- **Impact**: If the fix itself has version judgment or offset calculation errors, may break originally correct IPv4 TSO (regression risk).
- **Level**: High (touches existing IPv4 transmit main path common code).
- **Control measures**: (1) IPv4 branch logic field-by-field equivalent to current (regression guard TC-TSO-FILL-01); (2) IPv6 branch unit test (TC-TSO-FILL-02) + peer packet capture checksum (IT-TSO-21, this project's TSO core acceptance); (3) `tso=0` default zero regression (TSO branch `if (offload.tso_seg_size)` not entered).

### R-TSO-02 IPv6 Extension Header Scenario `l3_len` Calculation [Medium]

- **Description**: IPv6 base header fixed 40, but with extension headers (Hop-by-Hop/Routing/Fragment) `l3_len` should be "total IPv6 header length from Ethernet header to TCP header". First version only supports no extension headers (`l3_len=40`, `04-solution-and-architecture-design.md` 2.1 honest boundary).
- **Impact**: IPv6 with extension headers and TSO enabled, `l3_len` too small causes TCP header定位 wrong, segmentation wrong.
- **Level**: Medium.
- **Control measures**: (1) First version explicitly marks only no-extension-header support; extension header scenario marked "pending enhancement" (requires parsing `next_header` chain, HB-4); (2) TSO typically used for high-throughput TCP, extension headers rare, narrow risk surface; (3) If extension headers hit, behavior degrades to comparable with current (no worse than current).

### R-TSO-03 `if_hw_tsomax` Series Values [Medium]

- **Description**: Current lib never sets `if_hw_tsomax`/`tsomaxsegcount`/`tsomaxsegsize` (all lib hits 0); FreeBSD `tcp_output.c:905-931` only uses limit to constrain segmentation when `if_hw_tsomax != 0` (`:927`). Solution sets three non-0 limits in `ff_veth.c:951-953` TSO block (`04-solution-and-architecture-design.md` 2.3).
- **Impact**: Too-small values limit TSO efficiency; too-large may generate segments exceeding PMD single-packet/segment-count capability, rejected/truncated by PMD. DPDK doesn't directly provide equivalent "TSO segment count limit" field in `dev_info`; precise values per PMD (virtio/ixgbe/i40e vary).
- **Level**: Medium.
- **Control measures**: (1) Conservative defaults (total length ≤ IP_MAXPACKET dimension, segcount/segsize conservative) + runtime calibration (HB-5); (2) Setting **non-0** limits is itself better than current (all 0, completely unconstrained); (3) `if_sethwtsomax*` exact API per FreeBSD 15.0 `if.h`/`if_var.h` actual exports (coding phase `read_file`, `05-interface-and-config-design.md` 5.2).

### R-TSO-04 Duplicate Logic Convergence (Refactoring) Risk [Medium]

- **Description**: `ff_dpdk_if.c:2405-2472` and `ff_memory.c:331-375` offload population logic highly duplicate (TSO branch `:2455-2465` vs `:358-368` nearly line-by-line identical). Solution A extracts common function for convergence; Solution B synchronizes both (`04-solution-and-architecture-design.md` 2.4). Convergence involves cross-compilation-unit (`ff_dpdk_if.c`/`ff_memory.c`) dependencies.
- **Impact**: Improper convergence function placement may introduce circular dependencies or break `ff_veth.c`'s existing constraint of not directly referencing `rte_eth*` (`07-test-and-acceptance-specification.md` BG-06); refactoring itself may introduce behavior differences.
- **Level**: Medium.
- **Control measures**: (1) Convergence function placed in common position both can include, avoiding circular dependencies (`04-solution-and-architecture-design.md` 2.4); (2) Pre/post convergence field-by-field comparison (TC-TSO-CONV-01); (3) Separate commit for easy rollback (`06-milestones-and-work-breakdown.md` CM5 rollback point); (4) Solution A failure falls back to Solution B (sync + cross-reference comments); (5) **`make clean` then full compile before code changes** to verify cross-compilation-unit consistency (avoid incremental compilation masking header dependency issues).

### R-TSO-05 `CSUM_IP6_TSO` Macro Bit Relationship (Verified) [Low]

- **Description**: Solution `04-solution-and-architecture-design.md` 2.6 / `05-interface-and-config-design.md` 5.3 once listed "whether `ff_veth.c:304` needs to extend recognition of `CSUM_IP6_TSO`" as coding phase first verification item. **Verified during this document's writing**: `freebsd/sys/mbuf.h:670` `CSUM_IP6_TSO = 0x00001000` (independent bit), `:735` `#define CSUM_TSO (CSUM_IP_TSO|CSUM_IP6_TSO)` — **`CSUM_TSO` is already a composite macro, already includes `CSUM_IP6_TSO` bit**.
- **Conclusion**: Current `ff_veth.c:304 if (csum_flags & CSUM_TSO)` **can already hit IPv6 TSO segments** (because `CSUM_TSO` includes `CSUM_IP6_TSO` bit). Therefore the extension `& (CSUM_TSO | CSUM_IP6_TSO)` proposed in `04`/`05` is **redundant** (equivalent result), this step can be omitted.
- **Impact**: Almost none. IPv6 TSO broken link **not in `ff_veth.c:304` layer** (this layer can already recognize), the real broken link is in downstream `ff_dpdk_if.c:2455-2465`/`ff_memory.c:358-368` pseudo-header calculation not branched by version (R-TSO-01 is the core).
- **Level**: Low.
- **Control measures**: Coding phase uses this verification conclusion as authoritative, `ff_veth.c:304` can remain unchanged; core fix focuses on R-TSO-01's downstream version branching.

### R-TSO-06 Combination Inconsistency with `tx_csum_offoad_skip` [Medium]

- **Description**: Current TSO enablement (`ff_dpdk_if.c:931-942`) **is not constrained by** `tx_csum_offoad_skip`, while L4 csum offload enablement (`:914-926`) only sets `tx_csum_l4` when `skip==0`. TSO implicitly requires L4 csum offload (`RTE_MBUF_F_TX_TCP_SEG` implies TCP CKSUM). When `tso=1 && tx_csum_offoad_skip=1`, this is an inconsistent combination.
- **Impact**: When `tx_csum_l4=0`, TSO population branch (`ff_dpdk_if.c:2422 if (ctx->hw_features.tx_csum_l4)`) **entirely not entered** → TSO actually doesn't take effect (large segment not marked TCP_SEG, may be rejected by PMD or fall back to software path).
- **Level**: Medium.
- **Control measures**: TSO enablement logs WARN prompting mutual exclusion relationship (`04-solution-and-architecture-design.md` 2.5, preferred not to change existing behavior); combination constraint documented + logged; integration case IT-TSO-24 verifies no crash.

### R-TSO-07 TSO with scatter / MULTI_SEGS Combination [Low]

- **Description**: Pre-TSO large segments are inherently multi-segment scenarios; transmit path (`ff_dpdk_if.c:2360-2403`) already supports multi-segment mbuf chains; `tso_segsz` + `nb_segs` combination PMD constraints protected by `if_hw_tsomaxsegcount`/`tsomaxsegsize` (R-TSO-03).
- **Impact**: When segment count/size exceeds PMD capability, rejected; protected by tsomax limits.
- **Level**: Low.
- **Control measures**: Reuse existing multi-segment transmit path; tsomax non-0 limit constraints (R-TSO-03).

---

## III. Default-Off Compatibility Policy (Zero Regression Red Line)

### C-01 LRO Default-Off Zero Regression [Mechanism Guarantee]

- `dpdk.lro` default 0 (`config.ini` committed value `lro=0`; when parsing doesn't hit, struct zeroed, `05-interface-and-config-design.md` 3.2) → `if (ff_global_cfg.dpdk.lro)` not entered → LRO detection block, `max_lro_pkt_size`, `rx_lro=1` all ineffective → `ff_veth.c` `if (rx_lro)` doesn't set `IFCAP_LRO` → receive path (`ff_dpdk_if.c:1694-1742`) no LRO branch changes.
- **Conclusion**: `lro=0` byte-for-byte identical to current. Verification: TC-LRO-CFG-06 (45 old fixtures) + IT-START-01.

### C-02 TSO Default-Off Zero Regression [Mechanism Guarantee]

- `dpdk.tso` default 0 (`config.ini:22` `tso=0`) → `if (dpdk.tso)` not entered → `tx_tso=0` → `ff_veth.c:951` `if (tx_tso)` doesn't set `IFCAP_TSO`/`tsomax`; transmit path `if (offload.tso_seg_size)` (`ff_dpdk_if.c:2455`) depends on `CSUM_TSO`, when `tso=0` protocol stack doesn't set `CSUM_TSO` → TSO branch (including new IPv6 branching) **entirely untouched**.
- **Conclusion**: `tso=0` IPv6 branching/IP_CKSUM self-consistency/tsomax etc. new logic all ineffective. Verification: TC-TSO-FILL-04 + IT-TSO-22.

### C-03 Old config.ini Compatibility [Mechanism Guarantee]

- When old config.ini has no `lro` option, `MATCH("dpdk","lro")` doesn't hit, `dpdk.lro` keeps default 0 (`05-interface-and-config-design.md` 1.1, 3.2) → behavior identical to current, no user config change needed.

---

## IV. Release and Rollback Strategy

### D-01 Per-Milestone Independent Rollback

- Each coding milestone (CM1-CM5) commits a commit anchor before submission (`06-milestones-and-work-breakdown.md` rollback point); gate failure can roll back to previous CM; LRO main line (CM1→CM2→CM3) and TSO main line (CM4→CM5) are decoupled, one main line's issue doesn't affect the other's rollback.

### D-02 Feature Switch as Runtime Rollback

- LRO/TSO both controlled by config switches and default off; even after release, on-site just set `lro`/`tso` to 0 to return to zero-regression behavior, no code rollback needed — this is the fastest runtime fallback.

### D-03 bounce Rollback Discipline

- Any gate failure must bounce back to corresponding milestone for fix (bounce≤3), no shelving as "known issue" or carrying bugs forward; same step bounce over 3 times escalates to human decision (`06-milestones-and-work-breakdown.md` III, `07-test-and-acceptance-specification.md` I.5).

---

## V. config.ini Commit Risk (Mandatory Convention)

### E-01 config.ini Local Test Values Not Committed [High (Compliance Risk)]

- **Description**: `config.ini` is a config file committed with features. Historically this file has twice mistakenly carried local test values (`lcore_mask`, `vlan_filter`, `portN` local real IP, etc.).
- **Impact**: Mistakenly committing local test values pollutes repository default config, affecting other environments.
- **Level**: High (compliance).
- **Control measures**: This LRO feature's `config.ini` changes **only allow** adding `lro=0` (`[dpdk]` section, adjacent to `tso=0`); committed default must be `lro=0`; if locally changed to `lro=1` for debugging, must roll back before commit. Before `git add config.ini`, must review `git diff`, item-by-item confirm no `lcore_mask`/`vlan_filter`/`idle_sleep`/`portN` IP etc. local residue (`06-milestones-and-work-breakdown.md` IV, `05-interface-and-config-design.md` 1.1).

### E-02 Unit Test Fixtures Don't Contain Real Environment Values [Low]

- New LRO fixtures (`valid_lro_on.ini` etc.) use test private network (e.g., `192.168.*`), must not use real local IP (`07-test-and-acceptance-specification.md` 2.1).

---

## VI. Risk Summary Table (Level × Control Measures × Owning Milestone)

| ID | Risk | Level | Control Measures Summary | Owning CM | Related |
| --- | --- | --- | --- | --- | --- |
| R-LRO-01 | Receive super-MTU large segment semantic change | Medium | Set IFCAP_LRO first + default-off fallback + runtime validation | CM3/CM6 | HB-3 |
| R-LRO-02 | With jumbo/data_room/scatter | Medium | Prefer dev_info limit + multi-segment carrying + runtime calibration | CM2 | HB-2 |
| R-LRO-03 | With RX csum/RSS | Low | Reuse existing csum check, RSS orthogonal | CM2/CM6 | HB-3 |
| R-LRO-04 | virtio capability dependency | High (verifiability) | Capability gating + graceful degradation + tiered recording | CM0/CM2 | HB-1 |
| R-LRO-05 | Protocol stack receiving large segments | Medium | End-to-end validation + default-off fallback | CM3/CM6 | HB-3 |
| R-LRO-06 | Multi-process per-queue aggregation | Medium | per-port consistent setting + runtime validation | CM2/CM6 | HB-7 |
| R-LRO-07 | rx_lro dead field activation | Low | Production/consumer paired + unit test | CM2/CM3 | — |
| R-TSO-01 | IPv6 pseudo-header/l3_len fix | High | IPv4 equivalence guard + v6 unit test + capture + default-off | CM4/CM6 | IT-TSO-21 |
| R-TSO-02 | IPv6 extension header l3_len | Medium | First version no extension headers + mark pending enhancement | CM4 | HB-4 |
| R-TSO-03 | if_hw_tsomax values | Medium | Conservative defaults + runtime calibration + non-0 better than current | CM5 | HB-5 |
| R-TSO-04 | Duplicate logic convergence refactoring | Medium | Equivalence comparison + separate commit + clean build + fall back to Option B | CM5 | TC-TSO-CONV |
| R-TSO-05 | CSUM_IP6_TSO macro bit (verified) | Low | CSUM_TSO already includes this bit, extension redundant can be omitted | CM4 | mbuf.h:735 |
| R-TSO-06 | With tx_csum_offoad_skip | Medium | WARN log + document mutual exclusion | CM5 | IT-TSO-24 |
| R-TSO-07 | With scatter/MULTI_SEGS | Low | Reuse multi-segment path + tsomax constraint | CM5 | — |
| C-01/02/03 | Default-off + old config compatibility | Mechanism guarantee | Switch gating + struct zeroing | All CM | Zero regression |
| D-01/02/03 | Release rollback + bounce | Mechanism | commit anchor + switch rollback + bounce≤3 | All CM | — |
| E-01 | config.ini local values committed | High (compliance) | Only commit lro=0 + git diff review | CM7 | Mandatory convention |
| E-02 | Fixture real values | Low | Private network | CM6 | — |

---

## VII. Honest Boundary (New Verification Items in This Document)

1. **R-TSO-05 verified during this document's writing**: `freebsd/sys/mbuf.h:735 CSUM_TSO=(CSUM_IP_TSO|CSUM_IP6_TSO)`, `:670 CSUM_IP6_TSO=0x1000`. Conclusion: `ff_veth.c:304` current can already recognize IPv6 TSO segments; the extension proposed in `04`/`05` is redundant. This is a prior resolution of a "pending verification item" in the spec, correcting direction to "this change can be omitted", and has been backfilled into the risk table.
2. Other LRO/virtio, `max_lro_pkt_size` matching, tsomax precise values, multi-process per-queue, IPv6 extension headers etc. are all **runtime/subsequent milestone validation items**, not tested this round (aligned with `04-solution-and-architecture-design.md` IV, `07-test-and-acceptance-specification.md` section V HB-1..HB-7, `08-performance-baseline-plan.md` VI).
3. Test environment: DPDK dedicated NIC IP `<DPDK_NIC_IP>` (`ssh f-stack-client` side initiates), kernel stack testing via `127.0.0.1` on `lo`.

---

## VIII. Software LRO / Software TSO / Software-Hardware Integration Risks (Round 2 Supplement)

> Per `11-software-lro-solution.md`, `12-software-tso-and-segmentation-solution.md`, `13-software-hardware-offload-integration.md`. Software TSO has no development (protocol stack inherent), no new risks; risks concentrate on software LRO integration and software-hardware integration.

### R-SWLRO-01 tcp_lro.c:1261 NULL Bare-Call Crash [High]

- **Description**: `tcp_lro_flush_all` (`tcp_lro.c:1199`) ending at `tcp_lro.c:1261` bare-calls `tcp_hpts_softclock()`, and this function pointer = NULL (`ff_stub_14_extra.c:627`). If software LRO takes **modern mode** (`tcp_lro_queue_mbuf`+`tcp_lro_flush_all`) it will dereference NULL → crash.
- **Impact**: If software LRO is connected and误用 modern mode → runtime crash.
- **Level**: High.
- **Control measures**: **Option A (classic mode) avoids from path** — use `tcp_lro_init`+`tcp_lro_rx`+`tcp_lro_flush_inactive` (none contain 1261 bare-call, `11-software-lro-solution.md` section 3); alternative Option B (set `tcp_hpts_softclock` to empty stub); Option C (modify `tcp_lro.c:1261` to add null check) only as last resort. Default `lro=0` software LRO completely not enabled (zero regression).

### R-SWLRO-02 Software/Hardware LRO Double Aggregation [Medium]

- **Description**: If hardware LRO and software LRO both effective, hardware already-aggregated large segments再走 software `tcp_lro_rx` would double-aggregate, may exceed `TCP_LRO_LENGTH_MAX` (`tcp_lro.h:200`) triggering anomaly.
- **Impact**: Semantic confusion, no gain, possible anomaly.
- **Level**: Medium.
- **Control measures**: `13-software-hardware-offload-integration.md` 2.2/4 **mutual exclusion derivation** — `hw_features.rx_lro` and `sw_lro` mutually exclusive assignment in detection block (hardware supports→rx_lro=1,sw_lro=0; unsupported and lro=1→sw_lro=1), only one enabled at any time (4.2 truth table).

### R-SWLRO-03 Congestion Control/RTT/ECN Precision Degradation [Medium]

- **Description**: Software LRO merging multiple segments loses per-segment arrival time and IP-layer ECN bits, affecting RTT sampling precision and congestion response (external FreeBSD Journal / `03-external-research.md` 4.1). Basic FreeBSD stack (non-RACK/BBR) takes "assemble large segments → inject `if_input`" path.
- **Impact**: May be negative for latency-sensitive/congestion-sensitive services.
- **Level**: Medium.
- **Control measures**: Default `lro=0` off; document that not recommended for latency-sensitive services; `tcp_lro_flush_inactive` timeout parameter controls max staging latency (`11-software-lro-solution.md` 5.2).

### R-SWLRO-04 IFCAP_LRO Condition Not Covering Software LRO [Medium]

- **Description**: Current `ff_veth.c:945-947` `IFCAP_LRO` only driven by `hw_features.rx_lro`; when software LRO enabled (`sw_lro=1, rx_lro=0`), `IFCAP_LRO` not declared, protocol stack may abnormally handle software-aggregated large segments.
- **Impact**: Software LRO large segment receive anomaly.
- **Level**: Medium.
- **Control measures**: `13-software-hardware-offload-integration.md` 3.3 — `IFCAP_LRO` condition extended to `rx_lro || sw_lro`; recommend `sw_lro` included in `ff_hw_features` (`ff_config.h:112-118`) for unified `ff_veth.c` consumer.

### R-SWLRO-05 tcp_lro_rx Ordering Correctness [Medium]

- **Description**: `tcp_lro_rx` (`tcp_lro.c:1426`) for non-aggregatable packets `tcp_lro_flush_active` (`:1441`) preserves order, but interleaving of aggregation and non-aggregation flows needs runtime confirmation.
- **Level**: Medium.
- **Control measures**: Classic mode flush_active ordering mechanism; **pending runtime validation** (`11-software-lro-solution.md` section 7).

### R-SW-06 Software TSO No Risk [Mechanism Guarantee]

- Software TSO = protocol stack MSS segmentation (`12-software-tso-and-segmentation-solution.md`), protocol stack inherent capability, **no new code, no new risk**. `rte_gso` not introduced this round, no related risk.

### Software Path Risk Summary Table

| ID | Risk | Level | Control Measures Summary | Related Doc |
| --- | --- | --- | --- | --- |
| R-SWLRO-01 | tcp_lro.c:1261 NULL bare-call crash | High | Classic mode avoidance + default off | 11 §3 |
| R-SWLRO-02 | Software/hardware LRO double aggregation | Medium | Mutual exclusion derivation (truth table) | 13 §4 |
| R-SWLRO-03 | Congestion control/RTT/ECN precision | Medium | Default off + documentation + flush timeout | 11 §5, 03 §4.1 |
| R-SWLRO-04 | IFCAP_LRO not covering software | Medium | Condition extension rx_lro\|\|sw_lro | 13 §3.3 |
| R-SWLRO-05 | tcp_lro_rx ordering | Medium | flush_active ordering + runtime validation | 11 §5.2 |
| R-SW-06 | Software TSO | Mechanism guarantee | Protocol stack inherent, no risk | 12 |

### Software Path Honest Boundary (Pending Runtime Validation)

1. Whether `tcp_lro_flush_tcphpts` (`tcp_lro.h:220`) is NULL in F-Stack (if so, classic flush goes through `tcp_lro_condense` completely safe, `11-software-lro-solution.md` 3.2).
2. Classic mode aggregation rate under F-Stack single-threaded per-lcore (whether need to upgrade to modern mode).
3. `sw_lro` field final placement (`ff_hw_features` vs `ff_dpdk_if_context`, verify during coding).
4. Software LRO aggregation CPU/latency benefit and side effects actual testing (`08-performance-baseline-plan.md` performance baseline).
