# 08 Performance Baseline Plan — ff_rss_check Three Optimizations

> Scope: M4 performance baseline plan (comparison dimensions / measurement methods / baseline scope / real-machine steps / pass criteria). This phase **only writes the plan, does not run measurements**.
> Principle: measurement points correspond to **actual code (file:line number)**; external order-of-magnitude references are annotated with their source (wiki experience values), actual measurements are based on the real machine.
> Basis: 01 §3 requirements, 04 §3 thash design, 06 R-B milestone; test environment see 07 §3 / plan §Test Environment.
> Mandatory conventions: process cleanup via `kill_process.sh`, artifact deletion via `rm_tmp_file.sh`, permissions via `chmod_modify.sh`; local test values in config.ini must not be committed.

---

## 0. Performance Goals and Background

- 0.3 optimization goal (01 §3.2): while **retaining the static `ff_rss_tbl` fast path**, for **dynamic scenarios that miss the static table**, use `rte_thash_adjust_tuple` to reverse-compute the port instead of a per-port soft-compute scan, reducing port-selection overhead.
- Performance is not the primary goal of 0.1/0.2 (0.1 is a back-port, 0.2 is a new capability), but 0.1/0.2 must satisfy "no regression in the IPv4 path" (including no performance degradation).
- Order-of-magnitude references (wiki experience values, **to be calibrated by real-machine measurement**):
  - Per-port soft-compute scan: **300+ TSC cycles/connection** (dynamic worst-case path).
  - Static table hit (fast path): **100~250 TSC cycles/connection**.
  - Multi-process (8/16 processes) amplification effect: port-selection overhead amplifies by about **35%+** under high-concurrency connection establishment (per wiki report).
  > 【Source annotation: the above are wiki experience values cited in the plan brief, serving only as order-of-magnitude expectations; the pass criteria of this plan are based on **real-machine measurement on this machine**, not the wiki values as a hard gate.】

---

## 1. Comparison Dimensions (Three Port-selection Paths)

| Dimension | Path | Landing Point (file:line) | Expected Overhead |
|------|------|------------------|----------|
| **D1 Static-table Hit (fast path)** | `ff_rss_tbl_get_portrange` hit → port-set rotation | `ff_dpdk_if.c:2796`; 04 §1.2 hit branch | Lowest (table lookup + rotation, wiki 100~250-cycle range) |
| **D2 Miss Dynamic Soft-compute (current baseline)** | Per-port `++lastport` + `ff_rss_check` soft-compute scan | `ff_dpdk_if.c:2851` (`ff_rss_check`); 13.0 L896-911 form | Highest (O(port count) soft-compute, wiki 300+/connection, worst-case scanning until landing in the local queue) |
| **D3 Miss Dynamic Thash Reverse-computation (0.3 optimization)** | `ff_rss_adjust_sport` → `rte_thash_adjust_tuple` + 1 soft-compute re-verification | `rte_thash.h:456`; 05 §1.3; 04 §3.3 | Expected to be significantly lower than D2 (reverse computation + attempts count + 1 re-verification) |

- Core comparison: **D3 vs D2** (both are "miss dynamic" scenarios, the benefit of 0.3's optimization).
- Auxiliary comparison: D1 serves as the fast-path benchmark (must not degrade); D3 must not be slower than D2 (at least on par, expected to be better, 06 R-B.4 gate 4).
- Correlation: `ff_rss_tbl_init` (`ff_dpdk_if.c:2598`) pre-builds by calling `ff_rss_check` for each of the 65536 dports one at a time (L2690-2700), which is a one-time overhead during table construction, and can serve as a calibration reference for "soft-compute unit cost × port count" (not counted in the runtime connect path, but can corroborate the soft-compute unit price).

---

## 2. Measurement Methods

### 2.1 Micro-benchmark (Single-function TSC Instrumentation)

- Tool: `rte_rdtsc()` (already widely used in the lib, `ff_dpdk_if.c:1703/2350/...`) or `ff_get_tsc_ns()` (`ff_dpdk_if.c:2901`, rdtsc/tsc_hz).
- Instrumentation targets and methods:
  | Metric | Instrumentation Method | Unit |
  |------|----------|------|
  | M-1 Soft-compute Per-call Overhead | Take the `rte_rdtsc()` difference before and after the `ff_rss_check` (L2851) call | TSC cycles/call |
  | M-2 D2 Soft-compute Scan Total Overhead | In a miss scenario, take the rdtsc difference over the entire "per-port scan until landing in the local queue" segment | TSC cycles/connection |
  | M-3 D3 Thash Reverse-computation Overhead | Take the rdtsc difference over `ff_rss_adjust_sport` (including adjust_tuple + attempts + 1 soft-compute re-verification) | TSC cycles/connection |
  | M-4 D1 Static-table Hit Overhead | Take the rdtsc difference over `ff_rss_tbl_get_portrange`'s (L2796) hit branch | TSC cycles/connection |
  | M-5 `ff_rss_check` Call Count | Counter (D2 = number of ports scanned; D3 = 1 re-verification) | count/connection |
- Sampling: for each metric, take ≥1e4 samples and compute the mean + p50/p95/p99 (to avoid contamination by first-call cache misses/jitter); subtract rdtsc's own overhead (empty-measurement calibration).
- Implementation note: instrumentation code is gated by a **test/bench-dedicated build macro** (e.g., `FF_RSS_PERF_PROBE`), does not enter the production path, and is not included in the default lib build (to avoid instrumentation affecting production performance on the hot path). 【Pending confirmation: the macro naming and placement for instrumentation, to be finalized during coding.】

### 2.2 End-to-end (Macro-benchmark, Connection-establishment Rate / QPS)

- Tool: `f-stack-client`-side load testing (wrk / a self-built connect load-testing program).
- Metrics:
  | Metric | Meaning |
  |------|------|
  | E-1 Connect Establishment Rate | Number of successful connections established per second (short-connection QPS) |
  | E-2 Port-selection Path Proportion | The proportion of connections hitting the static table vs. missing and going dynamic (determines the weight of D3's benefit) |
  | E-3 Multi-process Amplification | The change in E-1 with process counts of 8/16 (verifying whether the wiki's 35%+ amplification effect is mitigated by 0.3) |
- Measure two types of load: (a) **static-table hit dominant** (configure rss_tbl to cover the target four-tuples); (b) **miss dominant** (connection four-tuples not in rss_tbl → go dynamic, highlighting the D2/D3 difference).

### 2.3 Joint Testing of Queue-landing Correctness and Performance

- Performance testing **simultaneously** verifies queue-landing correctness (07 §3 RT-RSS-03): D3's reverse-computed ports have 0 failures when re-verified by `ff_rss_check` (performance optimization must not sacrifice correctness, 01 §3.5).
- Packet capture / queue statistics verify that the actual packet-ingress queue distribution matches the port-selection expectation.

---

## 3. Baseline Scope (Reproducible Fixed Items)

> Performance comparison must be "apples-to-apples", otherwise the data is not comparable. Each round of baseline measurement must fix and record the following items.

| Scope Item | Fixing Method | Notes |
|--------|----------|------|
| lcore_mask / Queue Count | Fixed (e.g., one group each for 4 queues, 8 processes, 16 processes) | Multi-process amplification needs multiple groups |
| nb_queues / reta_size | Recorded (`lcore_conf.nb_queue_list`, `rss_reta_size` `ff_dpdk_if.c:123/133`) | Affects D(q) candidate count |
| RSS Key | Recorded symmetric/asymmetric (`default_rsskey_40bytes` L92 / `symmetric_rsskey` L110; `symmetric_rss` switch L699) | Affects D3 convergence rate |
| config.ini rss_tbl Rules | Fixed (hit / miss sets) | Determines whether the path goes D1 or D2/D3 |
| attempts | Fixed (04 §3.4 preferred initial value 16) | Affects D3 overhead and convergence |
| Peer / Load Tool | Same `f-stack-client`, same wrk parameters | Same load |
| DPDK / NIC | dpdk 24.11.6, NIC model, driver, `flow_type_rss_offloads` | Fixed environment |
| CPU Frequency / Core Binding | Fixed frequency (turbo off, fixed governor), consistent core binding | TSC must be comparable |

- **Per-protocol baseline**: IPv4 and IPv6 (0.2) baselines must be established **separately** (v6 tuples are 36B, hash paths differ, not directly comparable).
- **0.3 On/Off comparison**: under the same scope, measure "thash on (D3)" and "thash off/degraded to soft-compute (D2)" separately, obtaining the net benefit.

---

## 4. Real-machine Steps (`<DPDK_NIC_IP>` via `f-stack-client`)

> Environment: DPDK-dedicated NIC `<DPDK_NIC_IP>` (DPDK side); kernel stack `127.0.0.1` (functional regression only, not counted in RSS performance). dpdk 24.11.6.

### 4.1 Steps

1. **Environment Recording**: dpdk version (24.11.6), NIC model/driver, queue count, nb_queues, reta_size, key symmetry, CPU frequency/core binding, key config.ini items (per the §3 scope table, item by item).
2. **Build**: enable `FF_RSS_PERF_PROBE` (§2.1 instrumentation macro) + FSTACK's perf build; script permission adjustments go through `chmod_modify.sh`.
3. **Baseline B0 (Current State/D2 Soft-compute)**: disable 0.3 (or degrade via ctx init failure), miss-dominant load, measure M-1/M-2/M-5 + E-1/E-3.
4. **Baseline B1 (0.3/D3 Thash)**: enable 0.3, same load, measure M-3/M-5 + E-1/E-3, simultaneously test queue-landing correctness (RT-RSS-03, 0 re-verification failures).
5. **Fast-path B2 (D1 Static Table)**: hit-dominant load, measure M-4 + E-1, confirming the fast path does not degrade.
6. **Multi-process Amplification**: repeat steps 3~5 in groups of 8/16 processes to obtain E-3.
7. **IPv6 Baseline**: if the NIC supports v6 RSS offload (04 §2.4), repeat B0/B1 for v6 (per-protocol baseline).
8. **Data Aggregation**: comparison tables of D2 vs D3's TSC cycles/connection, `ff_rss_check` call counts, connection-establishment QPS, and multi-process amplification.

### 4.2 Cleanup and Commit Constraints

- Load-testing process cleanup: `/data/workspace/kill_process.sh <pid|pattern>` (direct kill is strictly forbidden).
- Packet capture/log/bench temp artifact deletion: `/data/workspace/rm_tmp_file.sh <path>` (direct rm is strictly forbidden).
- config.ini local values such as local IP (`9.134.x`), lcore_mask, idle_sleep **are for local use only; roll back to default values via `git diff` before committing** (existing convention).

---

## 5. Pass Criteria

| No. | Criterion | Measurement | Source |
|------|------|------|------|
| **P-1** | IPv4 path **does not regress**: static-table hit overhead (M-4) remains on par with before introducing 0.2/0.3 (within tolerance) | M-4 comparison | 01 §2.5; 06 R-C.4 |
| **P-2** | 0.3's dynamic path (D3) **is better than or at least on par with** pure soft-compute (D2): M-3 ≤ M-2 (same scope, miss-dominant load, M-3 expected to be significantly lower) | M-2 vs M-3 | 06 R-B.4 gate 4 |
| **P-3** | D3 selects the correct queue **100% of the time**: reverse-computed ports have **0 failures** when re-verified by `ff_rss_check` soft-compute (performance must not sacrifice correctness) | RT-RSS-03 + M-5 | 01 §3.5 (zero tolerance) |
| **P-4** | `ff_rss_check` call count: D3 (≈1 re-verification + within attempts) is significantly fewer than D2 (number of ports scanned) | M-5 | 04 §3.1 |
| **P-5** | Under multi-process (8/16), 0.3's benefit relative to soft-compute does not degrade (mitigating the wiki's 35%+ amplification) | E-3 comparison | §0 background |
| **P-6** | After ctx init failure/attempts exhaustion degrades to soft-compute, performance reverts to D2 level (not worse), functionality normal | B0 vs degraded state | 04 §3.6 |

- **Hard gates**: P-3 (never selecting the wrong queue, zero tolerance) + P-1 (IPv4 no regression). P-2/P-4/P-5 are performance-benefit items (expected to be achieved; if not achieved, record and analyze the tuning space for asymmetric key/attempts, does not block functional acceptance but must be noted in the 09 gate review).

---

## 5-bis. R-D (Requirement 0.4) Dedicated Benchmark: Recheck On/Off Comparison

> Purpose: quantify the performance benefit of disabling the reverse re-verification hard gate (corresponding to 0.4's acceptance AC-04-4 / 06 R-D.4 gate 4).
> **Orthogonal** to the existing §1-§5 baseline: the original D2/D3 (soft-compute vs. thash) comparison is about the overall benefit of "the reverse-computation path for static-table misses"; R-D further splits within D3 "whether soft-compute re-verification is performed after a successful reverse computation".

### 5-bis.1 Comparison Dimensions (Recheck On/Off)

| Dimension | Path | Trigger Switch | Landing Point (file:line) |
|------|------|----------|------------------|
| **D3-on** (recheck=1) | Reverse computation succeeds + mandatory `ff_rss_check[6]` soft-compute re-verification | `[rss_check] recheck=1` | `lib/ff_dpdk_if.c:3104` (v4) / L3436 (v6) re-verification if |
| **D3-off** (recheck=0, default) | Reverse computation succeeds, returns sport directly without calling `ff_rss_check[6]` | `[rss_check] recheck=0` or default | The same branch short-circuited by `!recheck` |

- Core comparison: **D3-off vs D3-on** (same scope, the reverse-computation path).
- Relationship to §1's existing D1/D2: D3-on is equivalent to D3 under the current R-B/R-C status quo; D3-off is R-D's performance increment.

### 5-bis.2 Measurement Fields (Recheck-dedicated Collection)

| Metric | Meaning | Collection Method |
|------|------|----------|
| RB-1 v4 Cumulative Time | N=10000 calls to `ff_rss_adjust_sport` cumulative ns | `clock_gettime(CLOCK_MONOTONIC)` start/end difference, unit-test microbench |
| RB-2 v6 Cumulative Time | N=10000 calls to `ff_rss_adjust_sport6` cumulative ns | Same as above |
| RB-3 Per-call Average | `RB-1/N` and `RB-2/N` | Computed field |
| RB-4 `ff_rss_check[6]` Call Count | Should be 0 for recheck=0, should be ≥N for recheck=1 (each candidate re-verified) | `__wrap_ff_rss_check[6]` accumulator |
| RB-5 Ratio (on/off) | `RB-1_on / RB-1_off` (v4); same for v6 | Reported value |
| RB-6 Real-machine Connection-establishment QPS | `example/rss_ct.c` real-machine load test comparing both states | rss_ct's own counter / external wrk |
| RB-7 Queue Distribution | The actual packet ingress-queue distribution when recheck=0 (verifying the correctness boundary in 04 §3-bis.4) | NIC RX queue counter |

### 5-bis.3 Collection Paths (Two Complementary Paths)

#### (a) Real-machine Path (`example/rss_ct.c` + multi-queue+thash-available environment)

- **Prerequisite**: NIC supports multi-queue + reta_size > 0 + thash ctx init succeeds.
- **Currently known limitation**: the `<DPDK_NIC_IP>` real-machine helloworld uses a virtio NIC, reta_size=0 → the reverse path is unreachable (thash ctx init guard directly returns -1) → **cannot directly run D3-off vs D3-on real-machine data**. spec 10's R-D section must clearly state this limitation and use microbench data as a fallback.
- Steps (executable if a NIC with reta>0 support becomes available in the future):
  1. Set config.ini `[rss_check] enable=1 + recheck=1`, start multi-process helloworld (or rss_ct).
  2. On the `f-stack-client` side, use wrk / a self-built connect load test, recording RB-6 + RB-7.
  3. Switch to `recheck=0`, restart the process; re-test with the same load, recording RB-6 + RB-7.
  4. Comparison table: QPS / queue-distribution skew / average connect time.
- **Joint correctness testing**: with D3-off, packet-capture statistics of "the proportion of connections whose first-packet sport hash lands in the local queue" (should be noticeably lower than D3-on's 100%), but "whether the connection is established successfully / whether the TCP three-way handshake completes" should be 100% (corresponding to 04 §3-bis.4).

#### (b) Unit-test Microbench Fallback Path (fallback for virtio reta=0)

- **Prerequisite**: the unit test can reach the reverse path (depends on R-B's already-landed hitrate-quantification context + reta_size injection; if injection fails, the microbench is skipped with a printed message).
- Steps: see 07 §1.4 TC-U-RSS-04-05.
- Output: `t_off_v4_ns` / `t_on_v4_ns` / `t_off_v6_ns` / `t_on_v6_ns` + RB-3 + RB-4 + RB-5.
- spec 10's R-D section backfills these fields; if constrained to microbench-only, clearly state "real-machine virtio reta=0 → microbench fallback".

### 5-bis.4 Pass Criteria (R-D Dedicated)

| No. | Criterion | Measurement | Source |
|------|------|------|------|
| **PD-1** | recheck=0's per-call average (RB-3) < recheck=1 (holds for both v4 and v6) | microbench / real machine | 01 AC-04-4; 06 R-D.4 gate 4 |
| **PD-2** | recheck=0's `ff_rss_check[6]` call count (RB-4) = 0 | wrap count mock | 06 R-D.4 gate 2 |
| **PD-3** | recheck=1 maintains the R-B/R-C status quo (D3-on performance consistent with existing R-B data; queue landing 100%) | microbench / hitrate cases | 06 R-D.4 gate 3 |
| **PD-4** | Switching recheck=0/recheck=1 requires no recompilation (ini takes effect at runtime) | spec 04 §3-bis.3 decision | 04 §3-bis.3 |
| **PD-5** | Connection correctness 100% when recheck=0 (even with uneven distribution, TCP handshake success rate remains 100%) | Real-machine packet capture/wrk failure rate | 04 §3-bis.4 |

- **Hard gates**: PD-2 (count mock) + PD-5 (connection correctness). PD-1/PD-3 are performance-acceptance items (expected to be achieved; if the microbench environment is constrained, mark as skipped and supplement with real-machine data, noted in spec 10).

### 5-bis.5 Data Backfill Location

- spec 10 "Implementation and Verification Report" R-D new section backfills:
  - Unit-test microbench measurements: `t_off_v4_ns` / `t_on_v4_ns` / ratio; same for v6.
  - Real-machine data (if obtainable): QPS / queue distribution / failure rate.
  - Real-machine limitation explanation (virtio reta=0): explicitly write "real-machine virtio environment thash ctx not ready → reverse path not reached → microbench fallback".
  - F-D-* pending item closure (e.g., wrap implementation details, microbench environment readiness strategy).

---

## 5-ter. R-E (Requirement 0.5) Dedicated: Correctness Baseline Primary, Small Performance Impact

> Purpose: 0.5 is a "correctness port" (making bind-then-connect no longer bypass RSS), **establish a correctness baseline as the primary focus** (return-packet queue-landing hit rate), performance is a secondary item.
> Relationship to the §1-§5 baseline: 0.5 introduces no new port-selection algorithm — once bind no longer grabs a port, connect still goes through the existing port-selection path of R-A/R-B/R-C/R-D (D1 static table / D2 soft-compute / D3 thash). Hence 0.5's port-selection overhead = the existing connect-path overhead, **no new hot path is introduced**.

### 5-ter.1 Correctness Baseline (Primary)

| Metric | Meaning | Collection Method |
|------|------|----------|
| RE-1 Bind-then-connect Return-packet Local-queue Hit Rate | The proportion of connections from bind(vip,0)+connect whose packets, after actual NIC RSS processing, land on the local worker queue | Real-machine packet capture / per-queue RX counters (RT-RSS-05/06) |
| RE-2 Before/After Port Comparison | RE-1 comparison between before the port (bind grabs a port early, bypassing RSS) and after the port (bind does not grab, goes through RSS) | Two groups under the same scope: without hunk1/hunk2 vs. with them applied |
| RE-3 Port Space Utilization | Port exhaustion situation for a large number of outbound connections on the same vip (before the port: bind occupies a port → exhausts easily; after the port: four-tuple uniqueness → reusable) | Connect success rate / port-allocation failure count |
| RE-4 v6 Hit Rate | The proportion of v6 bind(v6_vip,0)+connect6 return packets landing on the local queue | Same as RE-1 (v6, RT-RSS-06) |

- **Core comparison (RE-2)**: before the port, the bind-then-connect return-packet local-queue hit rate should be **noticeably lower** than direct connect (because RSS is bypassed, the hit rate ≈ 1/nb_queues at random); after the port, it should **align with** the direct-connect hit rate (near 100% when recheck=1, or the same softrss_be vs. toeplitz byte-order equivalence rate as direct connect when recheck=0, see 04 §3-bis.4).

### 5-ter.2 Performance Baseline (Secondary, Small Impact)

| Metric | Meaning | Expectation |
|------|------|------|
| RE-5 Connect Port-selection Overhead | The port-selection time cost during connect for bind-then-connect (= the existing D1/D2/D3 paths) | On par with direct connect under the same scope (no new logic) |
| RE-6 Bind Overhead Change | The time-cost change for FSTACK's bind(addr,0) skipping in_pcb_lport + in_pcbinshash | **May decrease slightly** (bind phase does less port allocation + hash insertion; port allocation overhead moves to connect) |

- Note: 0.5 moves "port selection + hash insertion" from the bind phase to the connect phase — the total overhead is essentially unchanged (just relocated), bind becomes slightly lighter, connect slightly heavier; the net performance impact is small. **Performance is not a hard acceptance gate for 0.5**.

### 5-ter.3 Pass Criteria (R-E Dedicated)

| No. | Criterion | Measurement | Source |
|------|------|------|------|
| **PE-1** | After porting, the bind-then-connect return-packet local-queue hit rate (RE-1) **aligns with** direct connect (RT-RSS-01); before porting it's noticeably lower (RE-2 comparison holds) | RE-1/RE-2 real machine | 01 §3-ter.7 AC-05-2 |
| **PE-2** | bind(addr,N) (N≠0) performance is on par with before the port (zero regression) | RE-5 comparison | AC-05-4 |
| **PE-3** | v6 bind-then-connect hit rate meets the target (if NIC supports v6 RSS offload) | RE-4 real machine | AC-05-3 |
| **PE-4** | bind does not prematurely occupy a port, port reuse works normally (RE-3, no abnormal exhaustion) | RE-3 real machine | 01 §3-ter.1 (port-exhaustion mitigation) |

- **Hard gate**: PE-1 (hit-rate alignment, correctness). PE-2/PE-3/PE-4 are auxiliary items.
- **Real-machine limitation**: same as R-B/R-D — if the `<DPDK_NIC_IP>` virtio NIC has reta=0 and cannot reach the thash path, bind-then-connect can still verify "connect enters the RSS branch + static-table/soft-compute path lands in the local queue" (not dependent on thash); the hit-rate baseline is collected via the static-table/soft-compute path, and thash-path data is handled per the §5-bis.3 limitation explanation.

### 5-ter.4 Data Backfill Location

- spec 10 "Implementation and Verification Report" R-E new section backfills: RE-1~RE-6 measurements; before/after port comparison table; v6 hit rate (if obtainable); real-machine limitation explanation; bind(addr,N) zero-regression confirmation.

---

## 6. Pending-confirmation Item List (Handed Off to Coding/Real-machine Phases for Verification, Not Speculated)

1. 【Pending confirmation】The naming and placement of the performance instrumentation macro (`FF_RSS_PERF_PROBE`) (§2.1), enabled only for perf builds, not on the production hot path.
2. 【Pending confirmation】The actual convergence rate of `rte_thash_adjust_tuple` under the asymmetric `default_rsskey_40bytes` (`ff_dpdk_if.c:92`) and a reasonable `attempts` value (04 §3.4), affecting D3's actual measured overhead (M-3); tune on real machine.
3. 【Pending confirmation】Calibrate the wiki order-of-magnitude values (soft-compute 300+/connection, static table 100~250, multi-process 35%+) against real-machine measurement on this machine, treating them as expectations rather than hard gates (§0).
4. 【Pending confirmation】Whether the real-machine NIC's `flow_type_rss_offloads` supports v6 RSS (04 §2.4), determining whether the IPv6 performance baseline (§4.1 step 7) can be done.
5. 【Pending confirmation】The load-testing client carrier (wrk / echo client / self-built connect load-test program) and connect load construction method (hit / miss sets, §2.2), same pending item as 07 §2.1.
6. 【Pending confirmation】The actual values of reta_size and nb_queues (determining the D(q) candidate count and thash reverse-computation difficulty, §3), record on real machine.
7. 【Pending confirmation】How to construct the "before the port" baseline for 0.5's before/after comparison (RE-2) — with/without hunk1/hunk2 recompiled vs. the same binary run-time without a switch — leaning toward using disable/enable FSTACK or applied/not-applied hunks as two separate builds for comparison (§5-ter.1).
8. 【Pending confirmation】When the 0.5 real-machine virtio has reta=0, the bind-then-connect hit-rate baseline is collected via the static-table/soft-compute path (not dependent on thash), with the thash-path data-limitation explanation (§5-ter.3).
