# F-Stack LRO/TSO Performance Baseline Plan

> Document tier: Performance baseline plan (M4 phase deliverable 2)
> Design basis: `01-requirements-specification.md` (motivation and value: LRO reduces receive CPU, TSO reduces transmit CPU), `04-solution-and-architecture-design.md` (honest boundary checklist), `07-test-and-acceptance-specification.md` (zero regression red line, honest boundary tiering).
> Authoritative version: DPDK `dpdk-stable-24.11.6`, FreeBSD 15.0 port.
> Iron rule: This round is a **pure documentation phase** (no code writing, no lib changes, no commits, no actual testing). This document defines how the performance baseline for the "subsequent implementation phase (CM6)" is collected and interpreted; **does not presume offload is necessarily faster — report actual results**. All file:line include code verification locations; use latest code as authoritative during coding.

---

## I. Objectives and Interpretation Principles

1. **Zero regression first**: The primary objective is to prove that `lro=0` / `tso=0` (default off) has **no measurable performance regression** relative to "the status quo before the LRO/TSO feature was introduced" (throughput, CPU, latency, memory must not degrade). This is a hard red line, taking priority over any "enable for faster" request.
2. **No preset conclusions, report actual results**: Whether LRO/TSO enables faster performance depends on the local PMD (virtio) actual capabilities, traffic characteristics, CPU frequency, etc. **Do not assume offload necessarily improves performance**; report what is collected, allowing honest results such as "no significant improvement when enabled" or even "slight degradation," and analyze the cause.
3. **Testable vs untestable item tiering**: Hardware LRO end-to-end performance strongly depends on whether virtio advertises and executes LRO (04-solution-and-architecture-design.md honest boundary 1, 07-test-and-acceptance-specification.md section V HB-1). When local virtio doesn't support it, LRO end-to-end aggregation performance is an **untestable item** that must be explicitly annotated; "code path pass" must not masquerade as performance gain.
4. **Reproducible methodology**: Fix all variables (lcore, file/stream size, concurrency, duration, warmup), take median across multiple rounds and report dispersion, ensuring conclusions can be independently reproduced.

---

## II. Test Environment and Specifications

| Item | Specification | Basis |
| --- | --- | --- |
| f-stack side | DPDK dedicated NIC IP `<DPDK_NIC_IP>`, virtio PMD | 01-requirements-specification.md 3.3, 06-milestones-and-work-breakdown.md CM0 |
| Traffic initiator/peer | `ssh f-stack-client` initiated from peer machine (rx/tx direction per use case) | 01-requirements-specification.md 3.3 |
| Kernel stack baseline | `127.0.0.1` on `lo` (same-machine kernel stack baseline, for cross-reference, not primary criterion) | 01-requirements-specification.md 3.3 |
| lcore binding | Fixed `lcore_mask` (local test value, not committed to config.ini; consistent across rounds) | config.ini local value convention |
| PMD capability prerequisite | CM0 first records `dev_info` for `rx_offload_capa`/`tx_offload_capa`/`max_lro_pkt_size` (backfills 04-solution-and-architecture-design.md honest boundary) | 06-milestones-and-work-breakdown.md CM0 step 4 |

**Tools**:
- Throughput/latency: `iperf3` (`-c/-s`, `-t` duration, `-P` concurrency, `-J` JSON output for parsing; `--get-server-output`).
- Protocol stack counters: `netstat -sp tcp` / `-sp ip` / `-sp ip6` (receive/transmit packet counts, retransmits, reassembly, etc.).
- DPDK-side statistics: `rte_eth_stats`/`rte_eth_xstats` (rx/tx packet count, byte count, L4 csum good/bad, LRO counters if PMD provides).
- CPU: f-stack polling core CPU usage (`top -H`/`mpstat -P <core>`), converted to "per-packet/per-byte CPU".
- Interrupt/packet count: xstats rx_packets vs application-layer received bytes to derive "average segment size" (when LRO effective, segment size should be significantly > MTU).

---

## III. Test Matrix

> Complete matrix: `{lro∈{0,1}} × {tso∈{0,1}} × {IPv4,IPv6}`, each cell collecting 4 metric types. For focus, split by main line: LRO mainly observes receive direction, TSO mainly observes transmit direction.

### 3.1 Metric Definitions (per cell)

| Metric | Definition | Collection |
| --- | --- | --- |
| Throughput | Steady-state Gbps (or pps) | iperf3 `bits_per_second` / xstats pps |
| Latency P50/P99 | Request-response workload latency percentiles (e.g., `iperf3 --udp` or additional ping/req-resp probing) | Percentile statistics script |
| CPU per-packet/per-byte | f-stack polling core CPU% ÷ (pps or Bps) | mpstat + xstats |
| mbuf memory | mbuf pool in-use/peak (LRO large segments occupy multiple mbufs) | DPDK mempool statistics |

### 3.2 LRO Receive Performance Matrix

| Case | Config | Workload | Main Observations | Interpretation |
| --- | --- | --- | --- | --- |
| PB-LRO-01 | `lro=0` (baseline) | High-throughput TCP receive (`f-stack-client` → `<DPDK_NIC_IP>`, large file/long-flow iperf3) | Throughput, receive core CPU, rx pps, average segment size (=MTU) | Baseline |
| PB-LRO-02 | `lro=1` | Same | Same, compare CPU/pps/segment size | When LRO effective, rx pps should decrease, average segment size > MTU, per-byte CPU decrease; **if virtio unsupported, no difference from PB-LRO-01 (honest record)** |
| PB-LRO-03 | `lro=1` IPv6 | IPv6 high-throughput receive | Same | Same as PB-LRO-02, v6 listed separately |

**LRO performance core observation**: `average receive segment size = application-layer received bytes ÷ rx_packets`. When LRO truly effective, this value should be significantly larger than link MTU (multiple packets merged into one segment); rx_packets correspondingly decreases → protocol stack per-packet processing count decreases → receive core CPU (especially per-byte CPU) decreases. This is the quantitative basis for judging "whether LRO end-to-end is effective" (aligned with 07-test-and-acceptance-specification.md HB-1/HB-3).

### 3.3 TSO Transmit Performance Matrix

| Case | Config | Workload | Main Observations | Interpretation |
| --- | --- | --- | --- | --- |
| PB-TSO-01 | `tso=0` (baseline) | Large TCP segment transmit (f-stack as server pulled by `f-stack-client` for large file) | Throughput, transmit core CPU, tx pps, software segmentation count | Baseline |
| PB-TSO-02 | `tso=1` | Same (IPv4) | Same, compare CPU/segmentation path | When TSO effective, transmit-side per-segment protocol stack overhead decreases, transmit core CPU decreases; report actual |
| PB-TSO-03 | `tso=1` IPv6 | IPv6 large TCP segment transmit | Same + **peer checksum correctness** (linked to 07-test-and-acceptance-specification.md IT-TSO-21) | Verify v6 TSO performance and correctness after fix; this project's TSO core |

**TSO performance core observation**: Transmit-side `tcp_output` segmentation count and transmit core CPU. When TSO effective, protocol stack delivers large segments, PMD/NIC segments them, transmit core per-byte CPU should decrease. If local virtio doesn't advertise TX TSO (07-test-and-acceptance-specification.md IT-START-03 shows "TSO is not supported"), actual software segmentation; PB-TSO-02/03 mainly verifies "lib changes don't degrade software segmentation path", must annotate end-to-end hardware TSO as untestable item.

### 3.4 Combinations and Interactions

| Case | Config | Purpose |
| --- | --- | --- |
| PB-MIX-01 | `lro=1,tso=1` | Both receive/transmit simultaneously enabled, verify no mutual degradation, no resource (mbuf/CPU) anomalies |
| PB-JUMBO-01 | `tso=1 + mtu_enable` (jumbo) | TSO + jumbo combination throughput/segment length (linked to 04-solution-and-architecture-design.md 2.3 if_hw_tsomax, 07-test-and-acceptance-specification.md IT-TSO-23) |

---

## IV. Test Methodology (Reproducible Protocol)

> Each matrix cell executed per the following protocol, ensuring cross-round comparability.

1. **Fixed variables** (consistent per round, recorded in results table):
   - lcore binding and count (`lcore_mask`), queue count, RSS config;
   - Workload: file size / iperf3 stream size, concurrent connections `-P`, duration `-t` (recommend ≥30s steady state);
   - MTU / jumbo settings; warmup duration (discard first N seconds, take steady-state window).
2. **Warmup**: Warm up before formal collection (e.g., 10s), excluding cold start/cache/connection setup jitter.
3. **Multi-round median + dispersion**: Each cell **≥5 rounds**, report **median** as primary metric, also report min/max or standard deviation/CV; if CV too large (e.g., >10%), retest or explain cause.
4. **Zero regression determination**: `lro=0`/`tso=0` group vs "pre-feature baseline" (CM0 recorded baseline commit build artifact, same spec run once) difference must fall within measurement noise (recommended threshold: median difference ≤ measurement CV, and no systematic one-directional drift). Exceeding threshold = regression → bounce back to corresponding CM (07-test-and-acceptance-specification.md bounce≤3).
5. **Enabled-state interpretation**: Enabled group vs baseline group comparison, report actual difference (improve/flat/degrade) with causal analysis (combining dev_info capability, segment size, pps, CPU breakdown).
6. **Evidence retention**: Each cell saves iperf3 JSON, xstats dump, mpstat samples, netstat before/after diff, config snapshot (with local sensitive values removed), paths written to results table.

**Results table template** (one row per cell):
```
Case  Config  Rounds  Throughput(median/CV)  P50/P99  Per-byte CPU  Avg segment size  mbuf peak  Evidence path  Interpretation
```

---

## V. Baseline Requirements and Acceptance

| ID | Requirement | Criteria |
| --- | --- | --- |
| PBA-01 | `lro=0` no measurable regression vs current | PB-LRO-01 metrics vs baseline difference ≤ noise (section IV 4) |
| PBA-02 | `tso=0` no measurable regression vs current | PB-TSO-01 same |
| PBA-03 | `lro=1` results recorded as-is | PB-LRO-02/03 report actual difference + causal analysis (no preset improvement) |
| PBA-04 | `tso=1` results recorded as-is + v6 correct | PB-TSO-02/03 report actual + IT-TSO-21 checksum correct |
| PBA-05 | Combination/jumbo no resource anomalies | PB-MIX-01 / PB-JUMBO-01 no mbuf exhaustion/no throughput collapse |
| PBA-06 | Honest boundary tiering | Untestable items (virtio unsupported LRO/TSO hardware) explicitly annotated, with dev_info evidence |

**Key requirement (restated)**: **Do not preset offload as necessarily faster**. PBA-03/PBA-04 pass criteria is "recorded as-is + causal analysis", not "must improve". Zero regression (PBA-01/02) is the hard gate.

---

## VI. Honest Boundary (Local virtio Capability Limitations)

> Aligned with 04-solution-and-architecture-design.md honest boundary checklist and 07-test-and-acceptance-specification.md section V HB tiering, clarifies testable and untestable items under the local environment.

| Item | Testable (meaningful performance data) | Untestable/limited (must annotate) | Related |
| --- | --- | --- | --- |
| LRO end-to-end aggregation performance | Only when CM0 `dev_info` shows virtio advertises `RTE_ETH_RX_OFFLOAD_TCP_LRO` and actually aggregates (segment size > MTU) | When virtio doesn't advertise LRO, PB-LRO-02/03 no difference from baseline, **LRO performance gain untestable** (not "no gain", but "cannot verify in this environment") | 07 HB-1/HB-3 |
| TSO end-to-end hardware acceleration | Only when virtio advertises `RTE_ETH_TX_OFFLOAD_TCP_TSO` and hardware segments | When not advertised, software segmentation; hardware TSO acceleration **untestable**; can still test "lib changes don't degrade software path" | 07 HB-5, IT-START-03 |
| max_lro_pkt_size limit impact on memory | Can test mbuf peak varying with max_lro_pkt_size | Precise optimal value per PMD/data_room (runtime calibration) | 07 HB-2 |
| Multi-process per-queue aggregation performance | Single-process testable | Multi-process per-queue LRO aggregation behavior | 07 HB-7 |
| IPv6 extension header scenario | No extension header testable | With extension headers (not implemented this round) | 07 HB-4 |

**Recording template** (each untestable item must fill): `{item} local dev_info=<capa bit actual> conclusion=<testable with data | untestable (reason)> evidence=<path>`. Prohibited writing "untestable in this environment" as "no performance gain" or "performance pass".

---

## VII. file:line and Related Index

| Topic | Anchor |
| --- | --- |
| LRO enablement/max_lro_pkt_size | `ff_dpdk_if.c:891-898`; `rte_ethdev.h:432` (rxmode.max_lro_pkt_size), `:1556` (LRO capa), `:1792` (dev_info limit) |
| LRO receive path (segment size observation) | `ff_dpdk_if.c:1694-1742` (ff_veth_input, rx pps and segment size source) |
| TSO offload population (transmit segmentation) | `ff_dpdk_if.c:2455-2465`; `ff_memory.c:358-368` |
| if_hw_tsomax (jumbo combination limit) | `ff_veth.c:951-953`; FreeBSD `tcp_output.c:905-931` (segmentation decision) |
| Honest boundary checklist | 04-solution-and-architecture-design.md IV; 07-test-and-acceptance-specification.md section V HB-1..HB-7 |
| Environment/CM0 dev_info documentation | 06-milestones-and-work-breakdown.md CM0 steps 3/4 |

---

## VIII. Software LRO Performance Baseline (Round 2 Supplement)

> Per `11-software-lro-solution.md`. Software TSO has no development (`12-software-tso-and-segmentation-solution.md`), no independent performance baseline (protocol stack MSS segmentation is the current baseline itself).

### 8.1 Software LRO on/off Comparison (Local virtio Testable)

Local virtio doesn't support hardware LRO, so `lro=1` takes the **software LRO fallback**,正好 testable for software LRO performance impact:

| Metric | lro=0 (baseline) | lro=1 (software LRO) | Observation Method |
| --- | --- | --- | --- |
| Receive throughput (Gbps) | Baseline | Compare | `ssh f-stack-client` high-throughput TCP |
| Receive CPU usage | Baseline | Compare (software aggregation has CPU overhead) | per-lcore CPU sampling |
| Protocol stack per-packet call count | Baseline | Should decrease (aggregation reduces if_input count) | `lro_queued/lro_flushed` statistics |
| Latency (request-response) | Baseline | May increase (aggregation staging latency) | Short-connection RTT measurement |
| Aggregation rate | N/A | `lro_flushed/lro_queued` ratio | tcp_lro statistics |

- **Key observation**: Software LRO net benefit = reduced protocol stack calls/cache miss gain − CPU aggregation overhead − staging latency cost. Throughput-oriented large flows expect positive benefit; latency-sensitive short connections may be negative (`11-software-lro-solution.md` 5.2).

### 8.2 Software Path Performance Honest Boundary

| Item | Testability | Notes |
| --- | --- | --- |
| Software LRO throughput/CPU (virtio) | **Local testable** | virtio no hardware LRO, lro=1 is software fallback |
| Software LRO aggregation rate | Local testable | tcp_lro statistics counters |
| Classic vs modern mode aggregation rate comparison | Partially testable | Modern mode requires first resolving 1261 NULL bare-call (Option B) |
| Hardware vs software LRO comparison | **Physical machine test** | Requires hardware LRO-capable NIC |
| Software TSO | None (protocol stack segmentation = baseline) | `12-software-tso-and-segmentation-solution.md`, no independent baseline |
