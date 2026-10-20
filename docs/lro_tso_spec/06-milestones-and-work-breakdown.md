# F-Stack LRO/TSO Milestones and Work Breakdown

> Document tier: Milestones and work breakdown (M3 phase deliverable 3)
> Design basis: `04-solution-and-architecture-design.md`, `05-interface-and-config-design.md`.
> Purpose: Break down the solution into **executable, gateable, rollbackable** coding milestones for direct reference by the subsequent implementation phase.
> Iron rule: This round is documentation phase; the following milestones are plans for the **subsequent implementation phase**, not executed this round. Coding phase strictly follows: `make clean` then full compile before any code change, lib minimal comments, commit message English 1-3 sentences, config.ini local test values not committed, rm/kill/chmod via scripts.

---

## I. Milestone Overview and Dependencies

```
CM0 (Baseline freeze/Environment)
  └─> CM1 (config/struct/parsing: lro switch)         [LRO main line]
        └─> CM2 (LRO DPDK enablement + max_lro_pkt_size + receive path)
              └─> CM3 (IFCAP_LRO + protocol stack receive verification)
CM1 independent of ──> CM4 (TSO IPv6 branching + IP_CKSUM self-consistency + CSUM_IP6_TSO)   [TSO main line]
                        └─> CM5 (if_hw_tsomax limits + duplicate logic convergence + combination constraints)
CM3 + CM5 ──> CM6 (unit/integration/performance baseline testing)
                └─> CM7 (spec review gate + commit)
```

- **LRO main line**: CM1 → CM2 → CM3 (layer-by-layer connection, strong sequential dependency).
- **TSO main line**: CM4 → CM5 (can parallel with LRO main line, only shares CM1's config infrastructure).
- **Convergence**: CM6 testing depends on both LRO+TSO complete; CM7 gate last.

---

## II. Milestone Details

### CM0: Baseline Freeze and Environment Preparation

- **Work items**:
  1. Record current lib/ related file git baseline commit as rollback anchor.
  2. Confirm clean build baseline passes (`make clean` → `make`), record build artifact baseline.
  3. Confirm test environment: DPDK dedicated NIC IP `<DPDK_NIC_IP>` (`ssh f-stack-client` side initiates testing), kernel stack test via `127.0.0.1` on `lo`.
  4. Runtime read `dev_info` to confirm local PMD (virtio) actual advertised values for `rx_offload_capa`/`tx_offload_capa`/`max_lro_pkt_size` (backfill 04-solution-and-architecture-design.md honest boundary checklist).
- **DoD**: Baseline commit recorded, clean build passes, `dev_info` offload capability table documented.
- **Gate**: clean build PASS.
- **Rollback point**: Baseline commit.

### CM1: config / struct / parsing (LRO switch infrastructure)

- **Work items** (corresponding to 05-interface-and-config-design.md I/II/III):
  1. `config.ini`: Add `lro=0` (comment form, committed default 0).
  2. `ff_config.h`: Add `int lro;` after dpdk struct `int tso;` (after L295). `rx_lro` (L114) already exists, unchanged.
  3. `ff_config.c`: Add `MATCH("dpdk","lro")` parsing branch after `MATCH("dpdk","tso")`; confirm/set default `lro=0` (align with tso default assignment location).
- **DoD**: clean build passes; `lro=0` behavior identical to current status; `lro=1` can be parsed into `dpdk.lro`.
- **Gate**: clean build PASS; unit test covers parsing (CM6 supplement); default-off zero regression static review.
- **Rollback point**: Pre-CM1 commit.
- **Commit suggestion (English)**: `Add dpdk.lro config option (default off) for LRO support.`

### CM2: LRO DPDK Enablement + max_lro_pkt_size + Receive Path

- **Work items** (corresponding to 04-solution-and-architecture-design.md 1.2/1.3/1.4, 05-interface-and-config-design.md IV):
  1. `ff_dpdk_if.c:891-898`: Delete `#if 0`, change macro to `RTE_ETH_RX_OFFLOAD_TCP_LRO`, hang under `if (dpdk.lro)` gating, detect per capa to set offloads + `rx_lro=1`, three-state log.
  2. Same block set `port_conf.rxmode.max_lro_pkt_size` (prefer `dev_info.max_lro_pkt_size`, `>= mtu`).
  3. `ff_veth_input` (`ff_dpdk_if.c:1694-1742`): Review LRO large segment movement correctness via `pkt_len` + multi-segment traversal; `RTE_MBUF_F_RX_LRO` awareness as optional enhancement (first version may not change, rely solely on length movement).
- **DoD**: clean build passes; when `lro=1` and PMD supports, offloads contains LRO bit, `max_lro_pkt_size` set; `lro=0` zero regression.
- **Gate**: clean build PASS; runtime (CM6) verify offloads bit actually takes effect, aggregated segments can enter receive path.
- **Rollback point**: Pre-CM2 commit.
- **Commit suggestion**: `Enable hardware LRO offload with max_lro_pkt_size on rx path.`

### CM3: IFCAP_LRO + Protocol Stack Receive

- **Work items** (corresponding to 04-solution-and-architecture-design.md 1.5, 05-interface-and-config-design.md 5.1):
  1. `ff_veth.c:941-956`: When `if (rx_lro)`, `if_setcapabilitiesbit(ifp, IFCAP_LRO, 0)`.
  2. Runtime verify LRO large segments correctly received by FreeBSD protocol stack after `IFCAP_LRO` (02-current-status-and-gap-analysis.md 1.5 main risk point).
- **DoD**: clean build passes; `lro=1` interface declares IFCAP_LRO; LRO segments received by protocol stack (runtime).
- **Gate**: clean build PASS; runtime LRO end-to-end receive correct (no drops/anomalies under TCP high throughput, CPU improvement as bonus).
- **Rollback point**: Pre-CM3 commit.
- **Commit suggestion**: `Declare IFCAP_LRO capability so stack accepts LRO segments.`

### CM4: TSO IPv6 Branching + IP_CKSUM Self-Consistency + CSUM_IP6_TSO

- **Work items** (corresponding to 04-solution-and-architecture-design.md 2.1/2.2/2.6, 05-interface-and-config-design.md 4.3/5.3):
  1. Verify `CSUM_IP6_TSO` and `CSUM_TSO` macro bit relationship (coding phase first item); based on result, decide whether to extend `ff_veth.c:304-306` to recognize `CSUM_IP6_TSO`.
  2. `ff_dpdk_if.c:2455-2465`: TSO branch branches by `iph->version` — IPv4 uses `rte_ipv4_phdr_cksum` + `RTE_MBUF_F_TX_IP_CKSUM` + `l3_len=iph_len`; IPv6 uses `rte_ipv6_phdr_cksum` + `RTE_MBUF_F_TX_IPV6` (no IP_CKSUM) + `l3_len=40`. Branch self-consistently fills l2_len/TCP_SEG/l4_len/tso_segsz.
  3. `ff_memory.c:358-368`: Synchronize same changes (or temporarily sync, converge in CM5).
- **DoD**: clean build passes; IPv4 TSO behavior unchanged; IPv6 TSO pseudo-header/l3_len/flags correct (static + runtime).
- **Gate**: clean build PASS; `tso=0` zero regression; IPv4/IPv6 TSO runtime peer checksum correct (CM6).
- **Rollback point**: Pre-CM4 commit.
- **Commit suggestion**: `Fix IPv6 TSO offload: split by IP version, use ipv6 pseudo-header cksum.`

### CM5: if_hw_tsomax Limits + Duplicate Logic Convergence + Combination Constraints

- **Work items** (corresponding to 04-solution-and-architecture-design.md 2.3/2.4/2.5, 05-interface-and-config-design.md 5.2/4.4):
  1. Verify `if_sethwtsomax*` exact API (FreeBSD 15.0 `if.h`/`if_var.h`), set three non-0 limits in `ff_veth.c:951-953` TSO block (conservative defaults, runtime calibration).
  2. Duplicate logic convergence: Prefer extracting `ff_fill_tx_offload` common function (Option A), both `ff_dpdk_if.c` and `ff_memory.c` call sites change to call it; if cross-compilation-unit complex, fall back to Option B (sync + cross-reference comments).
  3. Combination constraints: At TSO enablement (`ff_dpdk_if.c:931`), log WARN for `tso=1 && tx_csum_offoad_skip=1` (don't change behavior).
- **DoD**: clean build passes; tsomax three items non-0; single logic source after convergence; inconsistent combination has WARN.
- **Gate**: clean build PASS; IPv4/IPv6 TSO behavior equivalent before/after convergence (CM6 regression).
- **Rollback point**: Pre-CM5 commit (convergence refactoring high risk, separate commit for easy rollback).
- **Commit suggestion**: `Set if_hw_tsomax limits and consolidate duplicated tx offload logic.`

### CM6: Unit / Integration / Performance Baseline Testing

- **Work items**:
  1. **Unit tests** (Unity framework, refer to `c-unittest-expert` skill): config parsing (lro option), `ff_mbuf_tx_offload` v4/v6 TSO mapping, offload population function version branching.
  2. **Integration**: `lro=0/tso=0` zero regression control; `tso=1` IPv4/IPv6 TCP large segment segmented transmit (`ssh f-stack-client` packet capture verifies peer checksum); `lro=1` TCP high-throughput receive aggregation verification (prerequisite: `dev_info` supports).
  3. **Performance baseline**: LRO on/off receive CPU/throughput comparison; TSO on/off transmit CPU/throughput comparison (pending runtime environment).
- **DoD**: Unit tests all green; zero regression control byte-for-byte identical; v4/v6 TSO peer checksum correct; LRO end-to-end no anomalies.
- **Gate**: Unit tests PASS + integration key cases PASS; performance no degradation (improvement as bonus).
- **Rollback point**: Testing doesn't involve production code rollback (if bugs found, bounce back to corresponding CM).

### CM7: Spec Review Gate + Commit

- **Work items**:
  1. **Independent review agent** (not the coding agent) performs gate review on CM1-CM6 outputs (code vs spec consistency, file:line verifiable, zero regression verification, honest boundary closure).
  2. config.ini review: Confirm only `lro=0` feature changes, no local test value residue (`git diff` item-by-item).
  3. Commit per milestone (English commit message 1-3 sentences).
- **DoD**: Gate all PASS; config.ini no local residue; commits complete.
- **Gate**: Review agent signs PASS; bounce≤3 (failure bounces back to corresponding CM for fix, over 3 times escalates to human).

---

## III. Gate and Rollback Mechanism (Across All Milestones)

- **Per-milestone gate**: clean build PASS is hard gate (`make clean` then compile first, no incremental); functional gate per each CM's DoD.
- **Rollback point**: Each CM commits a commit anchor before submission; gate failure can roll back to previous CM.
- **bounce convention**: Any gate failure must bounce back to previous step for fix; same step bounce no more than 3 times; over 3 times escalates to human decision (no shelving, no carrying bugs forward).
- **Role separation**: Coding (CM1-CM5) and review (CM7) must be different agents.

---

## IV. Coding Conventions Checklist (Implementation Phase Mandatory)

| Convention | Requirement |
| --- | --- |
| Compilation | `make clean` then full compile before code changes; no incremental compilation as pass basis |
| Comments | lib minimal comments, only at contracts/non-intuitive points; no comments on self-explanatory code |
| config.ini | Only commit `lro=0` feature changes; local test values (lcore_mask/vlan_filter/portN IP etc.) rolled back before commit; review `git diff` before `git add` |
| commit message | English, 1-3 sentences, describing feature changes |
| rm/kill/chmod | Via `rm_tmp_file.sh` / `kill_process.sh` / `chmod_modify.sh`, no direct calls |
| Macro names | LRO macro uses `RTE_ETH_RX_OFFLOAD_TCP_LRO` (no old macro `DEV_RX_OFFLOAD_TCP_LRO`) |
| Default off | `lro=0`/`tso=0` zero regression is red line; no changes may break default path |

---

## V. Risk Register and Pending Runtime Validation Items (From 04-solution-and-architecture-design.md, for Milestone Tracking)

| ID | Risk/Pending Validation | CM | Mitigation |
| --- | --- | --- | --- |
| R1 | Whether virtio advertises `RTE_ETH_RX_OFFLOAD_TCP_LRO` | CM0/CM2 | CM0 read dev_info; if unsupported, LRO graceful degradation (log + not enabled) |
| R2 | `max_lro_pkt_size` matching mbuf data_room/scatter | CM2 | Prefer dev_info limit; runtime calibration |
| R3 | LRO large segment receive correctness via IFCAP_LRO | CM3 | CM3/CM6 runtime end-to-end validation |
| R4 | IPv6 extension header l3_len calculation | CM4 | First version no extension headers only; extension headers marked for enhancement |
| R5 | `if_hw_tsomaxsegcount/segsize` matching PMD | CM5 | Conservative defaults + runtime calibration; non-0 better than current |
| R6 | `CSUM_IP6_TSO` vs `CSUM_TSO` macro bit relationship | CM4 | Coding first item verification |
| R7 | Multi-process primary/secondary LRO aggregation behavior | CM2/CM6 | per-port capability consistent setting; runtime verify per-queue |
| R8 | Duplicate logic convergence cross-compilation-unit refactoring risk | CM5 | Separate commit; Option A failure falls back to Option B; clean build verification |

---

## VI. Software LRO Coding Milestones (Round 2 Supplement)

> Per `11-software-lro-solution.md`, `13-software-hardware-offload-integration.md`. Software TSO has no coding (`12-software-tso-and-segmentation-solution.md`: protocol stack MSS segmentation inherent). The following milestones are plans for the **subsequent implementation phase**; this round is documentation only. Previous hardware offload (CM0-CM7) is complete and committed; software LRO milestones continue numbering with SM.

### Dependencies

```
(Hardware offload CM1-CM7 complete)
  └─> SM1 (sw_lro field/derivation: ff_hw_features add sw_lro + detection block mutual exclusion derivation)
        └─> SM2 (Software LRO integration into ff_veth_input: per-lcore lro_ctrl + tcp_lro_init/rx/flush_inactive/free)
              └─> SM3 (IFCAP_LRO condition extension rx_lro||sw_lro + 1261 NULL bare-call avoidance verification)
                    └─> SM4 (unit/integration/performance + software/hardware mutual exclusion verification)
                          └─> SM5 (independent gate + commit)
```

### SM1: sw_lro Field and Derivation

- **Work items**:
  1. `ff_config.h:112-118`: `ff_hw_features` add `uint8_t sw_lro;` (parallel to `rx_lro`, `13-software-hardware-offload-integration.md` 3.3 decision).
  2. `ff_dpdk_if.c` LRO detection block: Derive per `13-software-hardware-offload-integration.md` 2.2 — `lro=1 && PMD supports`→`rx_lro=1,sw_lro=0`; `lro=1 && !supports`→`rx_lro=0,sw_lro=1`; `lro=0`→both 0. Three-state log (hardware/fallback software/disabled).
- **DoD**: clean build passes; mutual exclusion invariant `rx_lro & sw_lro == 0` always holds; `lro=0` zero regression.
- **Commit suggestion**: `Add sw_lro fallback flag with hardware-first LRO selection.`

### SM2: Software LRO Integration into ff_veth_input

- **Work items** (`11-software-lro-solution.md` section 2):
  1. per-lcore/per-port context add `struct lro_ctrl lro`; port/lcore init path `tcp_lro_init(&lro)` bind `lro.ifp=ctx->ifp` (classic mode), only when `sw_lro`.
  2. `ff_veth_input` (after `ff_dpdk_if.c:1720`): `if(ctx->hw_features.sw_lro) { if(tcp_lro_rx(&lro,hdr,0)==0) return; }` else original path delivery.
  3. Receive batch end: `tcp_lro_flush_inactive` (**not** `tcp_lro_flush_all`, avoids `tcp_lro.c:1261` NULL bare-call).
  4. Port/lcore cleanup: `tcp_lro_free(&lro)`.
- **DoD**: clean build passes; `sw_lro=1` software aggregation effective, no 1261 NULL crash; `sw_lro=0` receive path zero regression.
- **Commit suggestion**: `Wire software LRO into rx path using classic tcp_lro_rx mode.`

### SM3: IFCAP_LRO Condition Extension + 1261 Avoidance Verification

- **Work items**:
  1. `ff_veth.c:945-947`: `IFCAP_LRO` condition extended from `rx_lro` to `rx_lro || sw_lro` (`13-software-hardware-offload-integration.md` 3.3).
  2. Verify `tcp_lro_flush_tcphpts` (`tcp_lro.h:220`) is NULL in F-Stack (if so, classic flush goes through `tcp_lro_condense` completely safe, `11-software-lro-solution.md` 3.2); confirm classic mode path doesn't touch `tcp_lro.c:1261`.
- **DoD**: clean build passes; software LRO interface declares IFCAP_LRO; classic mode path statically confirmed not containing 1261 bare-call.
- **Commit suggestion**: `Extend IFCAP_LRO to cover software LRO fallback.`

### SM4: Testing (Unit/Integration/Performance)

- **Work items** (`07-test-and-acceptance-specification.md` VIII, `08-performance-baseline-plan.md` VIII): UT-SWLRO-01/02/03 (derivation/mutual exclusion/IFCAP); IT-SWLRO-10/11/12 (local virtio software fallback+aggregation+no crash); performance lro on/off comparison.
- **DoD**: Unit tests all green; local software LRO aggregation no crash; zero regression.

### SM5: Independent Gate + Commit

- **Work items**: Independent gatekeeper (not coding agent) reviews code vs `11`/`13` document consistency, 1261 avoidance correctness, mutual exclusion invariant, zero regression; commit per milestone (English 1-3 sentences).
- **DoD**: Gate PASS; bounce≤3.

### Software LRO Milestone Risk Register

| ID | Risk/Pending Validation | SM | Mitigation |
| --- | --- | --- | --- |
| SR1 | tcp_lro.c:1261 NULL bare-call crash | SM2/SM3 | Classic mode avoidance (Option A) |
| SR2 | Software/hardware LRO double aggregation | SM1 | Mutual exclusion derivation truth table |
| SR3 | Congestion control/RTT/ECN accuracy | SM4 | Default off + documentation |
| SR4 | Classic mode aggregation rate | SM4 | Runtime evaluation; if insufficient, upgrade to modern mode (Option B) |
| SR5 | sw_lro field placement | SM1 | Recommend ff_hw_features, verify during coding |
