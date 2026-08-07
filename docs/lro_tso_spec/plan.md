# F-Stack Software LRO/TSO + Hardware Integration — Spec Enhancement Plan

> This round's task: Building on the completed **hardware LRO/TSO offload** (commit d7b194ed3 etc., runtime verified virtio unsupported with graceful degradation),
> complete the spec documents for **user-space protocol stack software LRO/software TSO** and **software path ↔ DPDK hardware offload integration coordination**.
> **This round only writes/modifies Chinese spec documents (docs/lro_tso_spec/zh_cn/), no code writing, no lib changes, no English version.**
> Method: harness engineering + spec-driven + agent team. All conclusions verified with actual code file:line, cross-verified with external sources, conflicts resolved per code.

---

## 0. Background and Scope Definition

### 0.1 Previous Round Completed (Hardware Offload Path, Don't Repeat)
- config `lro=0/tso=0` switches, `RTE_ETH_RX_OFFLOAD_TCP_LRO` hardware LRO enablement + `max_lro_pkt_size`
- `IFCAP_LRO` declaration, TSO IPv6 pseudo-header branching, `if_hw_tsomax/segcount/segsize` limits, tso+csum_skip WARN
- Runtime conclusion: local virtio doesn't advertise TSO/LRO capability (`guest_features=0x110ef8020`), hardware path graceful degradation, software fallback zero regression

### 0.2 This Round's Scope (Software Path + Integration)
- **Software LRO (receive-side software aggregation)**: FreeBSD `tcp_lro.c` compiled into lib (Makefile:513) but **no call sites whatsoever** — completely not connected. Need to evaluate integrating software LRO into `ff_veth_input` receive path (replicating iflib's init/queue/flush/free pattern).
- **Software TSO (transmit-side software segmentation)**: Verify "software TSO essence = protocol stack normal MSS segmentation" (when NIC has no TSO, TF_TSO not set, tcp_output naturally sends segment by segment) — need to evaluate whether additional software segmentation is needed (e.g., DPDK `rte_gso`).
- **Software ↔ Hardware integration**: Capability detection priority, switch semantics (hardware preferred/software fallback/force software), receive/transmit path offload flag passthrough and coordination, zero regression.

### 0.3 Verified Core Facts (leader plan-mode already read_file/search_content verified, file:line as authority)

**Software LRO:**
- `lib/Makefile:513` compiles `tcp_lro.c`; `lib/Makefile:572` compiles `tcp_hpts.c`; `tcp_lro_hpts.c` **not in Makefile** (search 0 hits)
- In lib/*.c, `tcp_lro_rx|tcp_lro_flush|tcp_lro_init|lro_ctrl` **hits 0** → software LRO has no integration point
- `ff_stub_14_extra.c:627` `tcp_hpts_softclock=NULL`; L629-633 `tcp_lro_hpts_init` returns 0; L635-639 `tcp_lro_hpts_uninit` empty body
- `tcp_lro.c:73` includes tcp_hpts.h; `:92` `tcp_lro_flush_tcphpts` default NULL; `:1114-1116` flush when tcp_lro_flush_tcphpts==NULL goes through `tcp_lro_condense` (non-hpts aggregation path) → **software LRO core aggregation can work without hpts**, hpts only flush acceleration
- **iflib software LRO golden reference template** (f-stack doesn't use iflib, but this is the integration pattern):
  - `iflib.c:462` one `struct lro_ctrl ifr_lc` per rxq
  - `iflib.c:6035` init: `tcp_lro_init_args(&ifr_lc, ifp, TCP_LRO_ENTRIES, nentries)`
  - `iflib.c:3000` per-packet enqueue: `tcp_lro_queue_mbuf(&ifr_lc, m)` (`lro_enabled` gating, L2999)
  - `iflib.c:3029` batch-end flush: `tcp_lro_flush_all(&ifr_lc)`
  - `iflib.c:6056/6079` free: `tcp_lro_free(&ifr_lc)`
- Core API: `tcp_lro_queue_mbuf` (tcp_lro.c:1449); `tcp_lro_init_args`/`tcp_lro_flush_all`/`tcp_lro_free` (within tcp_lro.c, line numbers M1 verify)

**Software TSO:**
- `tcp_input.c:3972-3977`: only when `cap.ifcap & CSUM_TSO` sets `tp->t_flags |= TF_TSO` + `t_tsomax/segcount/segsize`
- `tcp_subr.c:3657-3659` (IPv4) / `:3699-3701` (IPv6): only when `IFCAP_TSO4/6 && if_hwassist & CSUM_TSO` reports `cap->ifcap |= CSUM_TSO`
- `tcp_output.c:558` `if ((tp->t_flags & TF_TSO) && V_tcp_do_tso && len > tp->t_maxseg ...) tso = 1`; L994 else `tso = 0`
- **Conclusion**: NIC without IFCAP_TSO → TF_TSO not set → tcp_output doesn't enter TSO branch → protocol stack sends small packets segment by segment per `t_maxseg`. **"Software TSO" = protocol stack normal MSS segmentation, naturally working**. Additional software segmentation (`rte_gso`) is optional acceleration, not required.
- `tcp_var.h:789` `#define TF_TSO 0x01000000`

**DPDK software offload libraries:**
- `dpdk-stable-24.11.6/lib/gso/` (transmit-side software segmentation, `rte_gso_segment`, gso_types uses RTE_ETH_TX_OFFLOAD_*_TSO)
- `dpdk-stable-24.11.6/lib/gro/` (receive-side software aggregation, `rte_gro_reassemble`)
- In f-stack lib, `rte_gso|rte_gro` **hits 0** → unused

**Config/Capability:**
- `ff_config.h` `struct ff_hw_features`: rx_csum(L113)/rx_lro(L114)/tx_csum_ip/tx_csum_l4/tx_tso(L117) etc.
- Receive `ff_veth_input` (ff_dpdk_if.c:1694-1742); `ff_mbuf_gethdr` (ff_veth.c:464-485)
- Transmit `ff_dpdk_if_send` (ff_dpdk_if.c:2360+); `ff_mbuf_tx_offload` (ff_veth.c:282-307)

---

## 1. Documents to Enhance/Add

Under `docs/lro_tso_spec/zh_cn/`, **modify existing** + **add new**:

| Document | Action | Content |
|------|------|------|
| 02-现状与差距分析.md | Modify | Add sections III/IV: software LRO current status (tcp_lro.c not connected layer-by-layer), software TSO current status (protocol stack segmentation essence), software/hardware integration current status |
| 03-外网调研.md | Modify | Add software LRO/GRO, software TSO/GSO, rte_gso/rte_gro, iflib LRO pattern, software/hardware offload coordination external materials |
| 04-方案与架构设计.md | Modify | Add software LRO integration solution (ff_veth_input replicate iflib), software TSO conclusion, software/hardware integration switch semantics and priority |
| 05-接口与配置设计.md | Modify | Add software LRO switch config (e.g., lro=2 software/ or sw_lro), hw_features fields, interface design |
| 06-里程碑与工作清单.md | Modify | Add software LRO/integration coding milestones (subsequent implementation phase) |
| 07-测试与验收规格.md | Modify | Add software LRO/TSO unit/integration/end-to-end acceptance (lo + f-stack-client) |
| 08-性能基线方案.md | Modify | Add software LRO on/off, software/hardware comparison performance baseline |
| 09-风险与兼容性.md | Modify | Add software LRO memory/latency/reordering, hpts stub dependency, software/hardware switching risks |
| **11-软件LRO方案.md** | Add | Software LRO special topic: tcp_lro API, lro_ctrl lifecycle, ff_veth_input integration point, hpts stub impact, switch coordination with hardware LRO |
| **12-软件TSO与分段方案.md** | Add | Software TSO essence (protocol stack segmentation) verification + rte_gso optional path evaluation + conclusion (whether development needed) |
| **13-软硬offload对接方案.md** | Add | Unified design of capability detection/switch semantics/priority/fallback/receive-transmit path coordination/zero regression |
| 00-调研结论总览.md | Modify | Update overview: add software path + integration chapter index and conclusions |
| 10-spec评审门禁.md | Modify | Add software path + integration gate checklist |

---

## 2. Agent Team Division (team: lro-tso-spec2)

- **leader (main agent)**: Coordination + CM0 fact verification (mostly completed) + polling wait (bypass detection preferred, no timeout dead-wait) + timeout/exception fallback + pure summary. Can serve pure research/probe/summary **single-role** tasks.
- **sw-path-explorer (already spawned)**: Deep code probing of software LRO/TSO/integration (A/B/C/D four dimensions), already running.
- **web-researcher (sub-agent)**: External research (DPDK gso/gro docs, FreeBSD tcp_lro/iflib, f-stack github issues, software/hardware offload coordination blogs), produces 03 document supplement material.
- **design-writer (sub-agent)**: Write 04/05/11/12/13 solution design documents (based on explorer + researcher material).
- **doc-updater (sub-agent or leader as summary)**: Update 02/06/07/08/09/00/10.
- **spec-gatekeeper (sub-agent, independent review)**: Final spec gate — code vs document consistency, file:line verifiable, software/hardware integration closed loop, honest boundary.

**Write/review separation iron rule**: Document writers (design-writer/doc-updater) and reviewer (spec-gatekeeper) must be different agents. If leader personally writes a document, that document's review must spawn an independent sub-agent.

**Polling/timeout/fallback**: Leader sets minute-level timeout for each sub-agent + periodic polling (send_message inquiry + bypass read file落地/git status). Sub-agent exception: leader takes over (after takeover, review by another agent) or spawn new sub-agent (role doesn't overlap with downstream review) or per bounce≤3 escalate to human.

---

## 3. Execution Phases (Milestones)

- **SM0 Fact verification** (leader + sw-path-explorer): All software LRO/TSO/integration current status file:line verified → summary
- **SM1 External research** (web-researcher): Software offload external materials → 03 supplement
- **SM2 Solution design** (design-writer): 11/12/13 new + 04/05 supplement
- **SM3 Current status/milestones/test/risk docs** (doc-updater / leader summary): 02/06/07/08/09 supplement
- **SM4 Overview/gate update** (leader summary + spec-gatekeeper review): 00/10 update
- **SM5 Spec gate** (spec-gatekeeper independent review): Item-by-item checklist, bounce≤3
- **SM6 Commit**: Document commit local (English commit message 1-3 sentences, only commit docs/, don't touch config.ini local values)

**Gate convention**: Any gate failure bounces back to previous step for fix, same step bounce≤3, over 3 times escalate to human. No shelving, no carrying bugs forward.

---

## 4. Mandatory Conventions (All Continued, Zero Tolerance)
- Actual execution no speculation, code as authority, cross-verification inconsistencies resolved per code
- rm→rm_tmp_file.sh, kill→kill_process.sh, chmod→chmod_modify.sh (make install class executable)
- lib minimal comments (this round doesn't change lib); commit message English 1-3 sentences; config.ini local test values not committed
- Local dual NICs: DPDK dedicated NIC IP <DPDK_NIC_IP> (ssh f-stack-client test), kernel stack test 127.0.0.1 lo
- Leader strictly prohibited from exiting early before all sub-agents complete, must poll wait

---

## 5. Key Design Questions (For Solution Documents to Answer)

1. **Is software LRO worth integrating into f-stack?** iflib pattern is clear, but under f-stack's single-threaded run-to-completion model, how to place lro_ctrl lifecycle (per-port? per-lcore?); whether flush via condense path under hpts stub is sufficient.
2. **Software LRO switch semantics**: Add independent switch (e.g., `sw_lro`) or reuse `lro` (lro=1 hardware preferred, auto software fallback if unsupported, lro=2 force software)?
3. **Software TSO conclusion**: After verifying "protocol stack segmentation naturally works", is rte_gso still needed? (Most likely conclusion: not needed, unless reducing small packet tx descriptor pressure, optional optimization)
4. **Software/hardware integration priority**: Hardware preferred + software fallback detection/switch coordination, how to guarantee zero regression (byte-for-byte identical to current when all default off).
5. **Software LRO vs hardware LRO mutual exclusion/stacking**: Whether hardware already-aggregated large segments going through software LRO again is duplicate/conflict.
