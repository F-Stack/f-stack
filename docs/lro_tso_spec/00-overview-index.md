# F-Stack LRO/TSO Support and Enhancement — Research Findings Overview

> Conclusion-first document. All conclusions are cross-verified against **actual code** (`lib/` + `freebsd/` + DPDK 24.11.6 headers) + **external authoritative sources**; in case of conflict, code takes precedence.
> Scope of this round: **produce Chinese spec documents only; no code writing, no lib modifications, no English version**.
> Requirements: LRO is a full new development (hardware LRO / DPDK offload path); TSO is already supported, to be analyzed and enhanced.
> **Line number note**: The file:line references in the one-line conclusions of this document are M0 plan-mode pre-read values (e.g., `890-897`/`2448-2465`), corrected by M1 with precise values (`891-898`/`2455-2465`) in `01-requirements-specification.md`/`02-current-status-and-gap-analysis.md`. **Always refer to 01/02 for precise line numbers**.

## One-Line Conclusions (this round plan mode pre-read; M1 must verify with code evidence)

- **LRO: Currently not supported**. DPDK-layer LRO enablement code is fully commented out with `#if 0` (`ff_dpdk_if.c:890-897`), and uses the old macro `DEV_RX_OFFLOAD_TCP_LRO`; there is no `config.ini`/`ff_config.c` config option; the receive path `ff_veth_input→if_input` has no LRO semantics wired in. Full new development is needed to connect the complete path: "config option → dev_info capability detection → rxmode.offloads → receive path/IFCAP_LRO → protocol stack".
- **TSO: Already supported, with enhancement points**. DPDK tx offload is enabled (`ff_dpdk_if.c:931-942`) + offload info is populated (`ff_veth.c:304-306`, `ff_memory.c:358-368`, `ff_dpdk_if.c:2448-2465`); however, the pre-read only shows `l4_len`/`tso_segsz` being populated — whether `l2_len`/`l3_len` are populated, IPv6 TSO, and combinations with csum/scatter/jumbo are enhancement points to be verified with code evidence by M1.

## Current Status Quick Reference (file:line as authoritative, M1 verified)

| Dimension | LRO | TSO |
|------|-----|-----|
| Config option (config.ini) | ❌ None | ✅ `tso=0` (default off, `config.ini:21-22`) |
| Config parsing (ff_config.c) | ❌ None | ✅ `:1054-1055` parses dpdk.tso |
| Config struct field (ff_config.h) | ⚠️ Has `rx_lro` field (`:114`) but no parsing | ✅ `tx_tso` (`:117`) + dpdk.tso (`:295`) |
| DPDK-layer enablement | ❌ Disabled by `#if 0` (`:890-897`), old macro | ✅ `:931-942` enabled per capability |
| Data path | ❌ Receive `ff_veth_input→if_input` has no LRO | ✅ Transmit fills tso_segsz/l4_len (`:2448-2465`) |
| FreeBSD side | ⚠️ tcp_lro.c exists but hpts stub is empty (`ff_stub_14_extra.c:629-638`) | ✅ tcp_output TSO segmentation |

## LRO Full New Support Direction (hardware offload path, detailed in M3)

1. Add `config.ini` `[dpdk] lro` config option + `ff_config.c` parsing (aligned with the tso pattern).
2. Remove `ff_dpdk_if.c:890-897` `#if 0`, correct macro name to `RTE_ETH_RX_OFFLOAD_TCP_LRO` (M1 to verify against DPDK 24.11 headers), detect capability via `dev_info.rx_offload_capa`, set `rxmode.offloads` + `hw_features.rx_lro`.
3. Receive path `ff_veth_input`: deliver large aggregated mbuf segments from hardware LRO; evaluate csum/packet length handling in `ff_mbuf_gethdr`, ifnet `IFCAP_LRO` flag, and integration with protocol stack `if_input`.
4. Evaluate combinations and regression with RSS, csum offload, timestamps, `mtu_enable` (jumbo), scatter/multi-seg, multi-process primary/secondary.
5. Honest boundary: whether the local virtio supports `RTE_ETH_RX_OFFLOAD_TCP_LRO` must be confirmed at runtime via `dev_info`; spec phase marks "pending runtime validation".

## TSO Enhancement Direction (detailed in M3, M1 verifies first)

1. Verify whether offload population is missing `l2_len`/`l3_len` (DPDK TSO typically requires l2/l3/l4_len all populated + `RTE_MBUF_F_TX_TCP_SEG` flag).
2. IPv4/IPv6 TSO path differences (`CSUM_TSO` vs IPv6 equivalent, pseudo-header checksum).
3. Correctness of TSO combinations with checksum offload, `tx_csum_offoad_skip`, scatter/`MULTI_SEGS`, `mtu_enable` (jumbo).
4. PMD capability check completeness, multi-process consistency, error fallback.

## Document Index

- `plan.md` — Overall plan, milestone gates, agent team division, polling/timeout/fallback mechanisms, conventions checklist
- `01-requirements-specification.md` — LRO full new support + TSO enhancement requirements, goals, scope boundaries, acceptance criteria, glossary
- `02-current-status-and-gap-analysis.md` — LRO/TSO layer-by-layer current status (file:line) + gaps + impact
- `03-external-research.md` — DPDK LRO/TSO offload, FreeBSD tcp_lro, f-stack github issue/wiki/blog, cross-verified with code
- `04-solution-and-architecture-design.md` — LRO hardware offload complete design + TSO enhancement plan (including data path/protocol stack integration)
- `05-interface-and-config-design.md` — config.ini/ff_config/ff_api/hw_features change design
- `06-milestones-and-work-breakdown.md` — Subsequent coding work breakdown
- `07-test-and-acceptance-specification.md` — Unit/integration/real-machine tests (LRO aggregation, TSO segmentation, IPv4/IPv6, <DPDK_NIC_IP>)
- `08-performance-baseline-plan.md` — LRO/TSO on/off comparison throughput/CPU/latency baseline methodology
- `09-risks-and-compatibility.md` — LRO receive semantic changes, combinations with jumbo/scatter/RSS, TSO enhancement risks
- `10-spec-review-gate.md` — Item-by-item assertion checklist (consistent with code, LRO/TSO closed loop, no omissions)
- `11-software-lro-solution.md` — **(Round 2)** Software LRO special topic: tcp_lro API/lifecycle, ff_veth_input integration, tcp_lro.c:1261 NULL bare-call avoidance, classic vs modern mode, software/hardware switch coordination
- `12-software-tso-and-segmentation-solution.md` — **(Round 2)** Software TSO = protocol stack MSS segmentation (no development needed) verification + rte_gso optional path evaluation
- `13-software-hardware-offload-integration.md` — **(Round 2)** Software/hardware offload unification: capability detection priority, switch semantics (recommend single lro auto-select), mutual exclusion truth table, zero regression, change point summary

## Round 2 Supplementary Conclusions (Software LRO/TSO + Software/Hardware Integration)

> Round 1 completed hardware LRO/TSO offload (config lro switch, `RTE_ETH_RX_OFFLOAD_TCP_LRO`, `IFCAP_LRO`, TSO IPv6分流, `if_hw_tsomax`); runtime validation confirmed the local virtio does not support hardware offload and gracefully degrades. Round 2 focuses on software paths and integration (three-way cross-verification: code verification + explorer probing + external research).

- **Software LRO: Completely not wired in** (`tcp_lro.c` compiled into lib but lib call sites = 0). The only gap = not integrated into `ff_veth_input` (`ff_dpdk_if.c:1707`). Approach: following the iflib pattern, introduce per-lcore `struct lro_ctrl`; **recommend classic mode** (`tcp_lro_init`+`tcp_lro_rx`+`tcp_lro_flush_inactive`) to avoid the `tcp_lro.c:1261` bare call to NULL `tcp_hpts_softclock` (`ff_stub_14_extra.c:627`) crash risk.
- **Software TSO: No development needed**. Essence = protocol stack normal MSS segmentation (NIC without TSO → `TF_TSO` not set → `tcp_output.c:558` `tso=0` → send segment by segment), an inherent protocol stack capability, already working. `rte_gso` is an optional optimization, not introduced this round.
- **Software/hardware integration: The only substantive gap = receive-side software LRO integration**; transmit-side TSO/csum protocol stack and hardware capability are naturally consistent (`CSUM_TSO` gating). Switch semantics **recommend Option A (single `lro` switch auto-select: hardware preferred + software fallback)**, software fallback flag `sw_lro` included in `ff_hw_features` and **strictly mutually exclusive** with hardware `rx_lro` (eliminate double aggregation); `IFCAP_LRO` condition extended to `rx_lro||sw_lro`; `lro=0/tso=0` default zero regression.
- **Important calibration**: Probing found that the current code is already ahead of the pre-Round-1 old status docs (`IFCAP_LRO`/`if_hw_tsomax`/`lro=0` already exist, products of Round 1 hardware offload implementation); docs 02/13 have been updated to reflect the latest code as authoritative.

## Honest Boundary

- This overview is an M0-phase preliminary conclusion based on plan mode pre-read; all file:line and macro names must be verified item-by-item by the M1 sub-agent against actual code; inconsistencies are resolved per code and noted in 02.
- Hardware LRO local availability depends on the virtio PMD's `dev_info.rx_offload_capa`; must be validated at runtime, not statically assertable.

## Final Status (2026-07-23 closure)

Software LRO implementation is complete and passed gate review (commit `8e320eeee` implementation main body + `e6d64d266` NULL timeout fix). Physical machine testing complete, no issues for now.

- **Verified paths**: Software LRO fallback (`sw_lro=1`, auto-enabled when hardware unsupported) — both local virtio and physical machine (also virtio-class without hardware LRO) tested passing; 1261 NULL avoidance effective; `lro=0` zero regression; IPv4/IPv6 both normal.
- **Pending (end-to-end not verified)**: Hardware LRO aggregated receive path (`rx_lro=1` branch). Both local virtio and the physical machine NIC do not support `RTE_ETH_RX_OFFLOAD_TCP_LRO`, so hardware LRO end-to-end aggregation (`IT-LRO-10` aggregation observation / `HB-1` / `IT-SWLRO-13` hardware branch) has no runtime evidence to date; requires a physical NIC that supports hardware LRO to verify. Code path layer (config parsing / capability detection / graceful degradation / compilation / `IFCAP_LRO` declaration) all passed.
- **TSO**: Software TSO is inherent protocol stack MSS segmentation, no code changes, behavior unchanged; TSO offload population (IPv4/IPv6分流, pseudo-header checksum) code path implemented, end-to-end checksum correctness is similarly limited by the physical machine NIC offload capability.
