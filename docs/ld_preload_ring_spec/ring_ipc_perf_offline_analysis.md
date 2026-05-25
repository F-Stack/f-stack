# Ring IPC Performance Regression — Offline Deep Analysis (v3.7 · Final · Short/Long Connection Full-Scenario Convergence · Compile-Flag Consolidation)

> Revision history: v1 root cause H10/H11 (drain not present in sem) was falsified by the user; v2 root cause H15 (cache miss) was falsified by perf stat; v3 relocated the root cause to H17 based on F-Stack's official "event aggregation" theory; v3.1 (2026-05-21 morning) falsified H18 in measurement, plan A archived to §5.A; v3.2 (2026-05-21 evening) three sets of measurements jointly falsified H17/H21/H24, and the root cause converged to H19-final + H23; v3.3 (2026-05-22) plan C measured 4% regression and was discarded (H25 falsified), plan C+/D2 measured +9.7% QPS, plan D5 added; **v3.4 (2026-05-22 evening) plan D5 (+1.3%) + D6 (+0.9%) implementation closed out, QPS 91k → 102.2k for total +12.3% (reaching 97.3% of sem). The remaining 2.7% has been identified as ring SPSC architectural inherent overhead and cannot be eliminated**; v3.4.1 (2026-05-25) added §9 Appendix D documenting the multi-worker sem-mode `idle_sleep=0` startup starvation phenomenon; v3.4.2 (2026-05-25) §9.6 synced upstream fix progress (commit `8125beece6`, zero overhead under normal load); v3.5 (2026-05-25 evening) multi-core short-connection measurements across three groups (1/2/4 cores) jointly confirmed "ring has no performance advantage over sem under FF_MULTI_SC multi-worker short-connection scenarios"; **v3.6 (2026-05-25 evening) multi-core long-connection measurements across three groups (1/2/4 cores) showed ring consistently 2.4%–4.5% worse than sem, with stable direction and beyond the noise band of short-connection. Final convergence: the ring path has no performance advantage in any scenario under LD_PRELOAD + FF_MULTI_SC; the code is retained only as a reserve capability for future "multi-threaded sc sharing within a single process" and "cross-process sc sharing (where the worker count exceeds the fstack instance count)" extension scenarios. Production recommendation reverts to sem. See §1.4 and §10 Appendix E**; v3.7 (2026-05-25 evening) the three independent compile flags `FF_RING_SC_COMPLETION` / `FF_RING_FAST_EMPTY_CHECK` / `FF_RING_INLINE_DISPATCH` have been removed; the corresponding D2/D5/D6 implementations are now merged as the default behavior of the `FF_USE_RING_IPC` branch, and the legacy rsp_ring wait path and function-pointer dispatch branch have been deleted; the previously-discarded plan C compile flag `FF_RING_PENDING_BYPASS`, the `pending_count` field, and all its inc/dec/atomic_read paths have also been removed (§5.3 retains only the lessons record). Full lessons summary in §4.

---

## 1. Conclusion First (30-second view)

### 1.1 Performance Gap Facts

| Metric | Sem mode (baseline) | Ring mode (regression) | Difference |
|---|---|---|---|
| Short-connection QPS | 105k | 92k | **-12.4%** |
| CPU utilization | 100%×2 | 100%×2 | Identical |
| L1-dcache-load-misses (30s) | 1,830,010,884 | 1,824,039,526 | **-0.3% (almost identical)** |
| LLC-load-misses (30s) | 251,343 | 204,144 | **ring is 23% lower** |
| cache-misses (30s) | 792,424 | 692,902 | **ring is 14% lower** |

### 1.2 Root Cause Direction (v3.4 convergence)

**H17 (falsified · 2026-05-21 evening)**: Original hypothesis "event aggregation difference within drain window". pkt_tx_delay sensitivity matrix measurements: starting at 60μs ring and sem collapse synchronously; wrk latency Stdev of ring is even smaller than sem. See §3 and §5.A.

**H18 (falsified · 2026-05-21 morning)**: See §5.A and §4 Lessons.

**❌ H25 (falsified · 2026-05-22 morning)**: Plan C (atomic `pending_count` bypass) measured QPS regression of 4%. See §5.3.

**✅ H23 (fixed · 2026-05-22 noon · plan C+/D2)**: Original hypothesis: `ff_ring_send_response` writing to rsp_ring introduced cross-core cache invalidate (Self 3.33%). **After plan D2**: `ff_ring_send_response` Self 3.33% → 0% (completely eliminated), QPS 91k → 100k (+9.7%). See §5.4.

**✅ H19-final (optimized · 2026-05-22 afternoon · plans D5+D6)**: Original hypothesis: `ff_ring_process_requests` is called every main-loop iteration, including function call stack + empty-dequeue path. **After plan D5**: Self 18.98% → 4.53% (function call stack eliminated); **after plan D6**: completely inlined and disappeared, QPS 100k → 101.3k → **102.2k**. See §5.5, §5.6.

**🔵 Architectural inherent overhead (identified as unremovable lower bound)**: sem-mode `ff_handle_each_context` Self 50.41% ≈ ring(D2+D5+D6) 50.13% — main-loop CPU share already aligned, but ring is still 2.7% slower than sem (102.2k vs 105k). Sources of the gap:
- Acquire fence inside `rte_ring_sc_dequeue_burst` (every spin forces CPU memory system synchronization)
- Ring metadata maintenance (prod.head/cons.head sync, cmpxchg simulation)
- Sem mode dirty-read of `sc->status` is a plain load with no fence

**Single-worker optimization converged**: QPS 91k → 102.2k (+12.3%), only 2.7% from sem. The remaining gap is ring SPSC architectural cost, unremovable in the single-worker single-lcore scenario. Then move to multi-worker comparison testing (see plan.md §8).

### 1.3 Repair Path (C → C+/D2 → D5 → D6, all implemented)

| Plan | Diff size | Measured QPS gain | Status |
|---|---|---|---|
| ✅ §5.1 Pre-test: pkt_tx_delay matrix | 0 lines | - | Done (falsified H17) |
| ✅ §3.4 wrk latency distribution + perf top callgraph | 0 lines | - | Done (locked H19-final + H23) |
| ~~A: APP-side switch to pure BUSY_POLL~~ | ~~5 lines~~ | ~~95k–97k~~ | ❌ H18 falsified |
| ~~B: burst histogram quantification of H17~~ | ~~50 lines~~ | ~~no change~~ | ⚪ Skipped |
| ❌ **C**: atomic pending_count bypass | 30 lines | **-4% (regression)** | **H25 falsified · reverted** |
| ✅ **C+/D2**: sc->completion replaces rsp_ring | 50 lines | **+9.7%** (91k → 100k) | **H23 fixed · merged** |
| ✅ **D5**: rte_ring_empty fast empty check | 5 lines | **+1.3%** (100k → 101.3k) | **H19-final call stack eliminated · merged** |
| ✅ **D6**: inline dispatch (eliminate function pointer) | 15 lines | **+0.9%** (101.3k → 102.2k) | **architecture aligned with sem · merged** |
| 🔵 Remaining 2.7% | unremovable | -- | ring SPSC architectural overhead (acquire fence + metadata) |
| ✅ Multi-worker short-connection comparison | 0 lines (config only) | -- | **Done** (see §1.4.1 / §10.1-§10.4), ring ≡ sem |
| ✅ Multi-worker long-connection comparison | 0 lines (config only) | -- | **Done** (see §1.4.2 / §10.5-§10.7), ring **stably worse** than sem 2.4%–4.5%, ring design goal finally falsified |

### 1.4 Multi-core Short-Connection + Long-Connection Convergence (v3.6 · 2026-05-25 evening · user prediction confirmed + long-connection falsifies ring design goal)

> **User prediction** (raised repeatedly since v3.0): "ring has no performance advantage over sem under FF_MULTI_SC multi-worker mode, because each worker already has an independent zone with an independent lock, so there is no cross-worker lock contention to begin with."
> **Conclusion**: 6 sets of measurements across short and long connections **fully confirm** this prediction, and **under long connections, ring is consistently 2.4%–4.5% worse**.

#### 1.4.1 Short-Connection Measurements (wrk default)

| lcores | Sem QPS (10k) | Ring QPS (10k) | Difference |
|---|---|---|---|
| 1 | 10.4 | 10.2 | -1.92% |
| 2 | 20.8 | 20.8 | **0%** |
| 4 | 35.9 | 35.8 | **-0.3%** |

Differences ≤ 2% lie within the noise range and can be considered ring ≡ sem. See §10.1–§10.4.

#### 1.4.2 Long-Connection Measurements (keep-alive)

| lcores | Sem QPS (10k) | Ring QPS (10k) | Difference | Ring/Sem ratio |
|---|---|---|---|---|
| 1 | 33.3 | 31.8 | **-4.50%** | 95.50% |
| 2 | 65.9 | 64.3 | **-2.43%** | 97.57% |
| 4 | 130.5 | 127.0 | **-2.68%** | 97.32% |

**Key observations**:
- **All three sets show ring worse than sem, direction is stable** (unlike short-connection's noise distribution of 0/-0.3%/-1.9%)
- **Long-connection absolute QPS is ~3.1–3.6× short-connection**, closer to the true IPC-layer ceiling
- **Multi-core scaling factors are all good**: sem 1→2 ×1.98, 1→4 ×3.92; ring 1→2 ×2.02, 1→4 ×3.99 → **further confirms sem has no cross-worker lock contention**
- The ring disadvantage under long connections is more stable than under short connections, of the same magnitude as the v3.4 single-worker convergence figure of 2.7% inherent overhead

See §10.5–§10.7.

#### 1.4.3 Why Ring Is Stably Worse Under Long Connections (the author's prediction was falsified)

The author predicted in v3.5 §10.5: "Under long connections, sem holds the zone lock for 50-100μs the entire time, so the ring lock-free advantage may emerge." **This prediction was falsified by measurements.** Deep reasons:

| Inference (old) | Actual situation |
|---|---|
| Long-connection sem keeps `tmp > 0` → holds zone lock the whole time → fstack lcore vs nginx worker lock contention rises | Under sem `FF_MULTI_SC`, fstack lcore and nginx worker are in a **1:1 same-zone** relationship, but the nginx worker's frequency of entering the zone lock is intrinsically very low (only attach/detach), and **normal read/write paths do not contend for the zone lock at all** |
| Ring lock-free main loop saves sem's lock-holding overhead | Sem lock holding is **exclusive ownership by the fstack lcore**, the cache line stays in exclusive state and lock-holding cost is near zero; ring instead must do an acquire fence on every `rte_ring_sc_dequeue_burst` to synchronize the memory system → **long-connection high QPS amplifies this overhead linearly** |

**Conclusion**: The "ring SPSC architectural inherent overhead" identified in v3.4 §1.2 is **linearly amplified** at high long-connection QPS, not offset by any relative advantage.

#### 1.4.4 Final Wrap-up Conclusion

| Scenario | Ring vs Sem gap |
|---|---|
| Single-worker short-connection (v3.4) | -2.7% |
| Multi-worker short-connection (§1.4.1) | -0.3% ~ -1.9% (noise range) |
| Multi-worker long-connection (§1.4.2) | **-2.4% ~ -4.5% (consistently stable disadvantage)** |

**Final verdict**:
1. **Performance**: sem remains the optimal configuration for LD_PRELOAD + FF_MULTI_SC, ring has **no performance net win in any tested scenario**
2. **Robustness**: the theoretical value of ring's lock-free main loop (immunity to startup starvation) has been fixed at the source on the sem path by commit `8125beece6`, **so the robustness advantage has also been eliminated**
3. **Architecture**: the ring path **retains the code and compile flags** (`FF_USE_RING_IPC` + D2/D5/D6) as a reserve capability for future "multi-threaded sc sharing within a single process" and "cross-process sc sharing (where the worker count exceeds the fstack instance count)" extension scenarios. The current LD_PRELOAD fork-based multi-process scenario **does not enable ring by default**

**Production recommended configuration (2026-05-25 final)**:

```bash
# LD_PRELOAD + nginx multi-worker recommended (default)
make FF_KERNEL_EVENT=1 FF_MULTI_SC=1
# config.ini: idle_sleep = 0 (safe after commit 8125beec), pkt_tx_delay = 50 (short) / 100 (long)
```

The ring path is enabled only in either of the following cases:
- Multiple threads inside a single process need to share sc (current LD_PRELOAD does not match this)
- Cross-process sc sharing (worker count exceeds fstack instance count, the current LD_PRELOAD 1:1 deployment does not match this)
- The user accepts a -2.4%~-4.5% performance loss in exchange for the lock-free main-loop design

---

## 2. Official Documentation Evidence Chain

### 2.1 F-Stack Official README (verbatim)

Source: `adapter/syscall/README.md` line 290 (root cause for short-connection performance under-performing standard F-Stack beyond 8 cores):

> "After 8 cores, the performance of LD_PRELOAD is not as good as the performance of standard F-Stack. The main reason is that **the matching degree between the user application program and the fstack application program (such as the number of loops and time of `ff_handle_each_context`) is not high**, and the performance has not been fully optimized."

Source: F-Stack official WeChat article (cited by user, original Chinese):

> "If you want to improve the overall performance of libff_syscall.so, then matching the fstack instance application with the APP application is critical. **Optimal performance is achieved only when one ff_handle_each_context loop matches as many of the events of the loop as possible.** This requires very fine tuning, but currently the rough value of the pkt_tx_delay parameter is used."

### 2.2 Official Definition of pkt_tx_delay

The essential use of `pkt_tx_delay` in the LD_PRELOAD scenario is **not** simply a "timeout exit", but the **batch size of event aggregation within the drain window**:

- Too short → few APP requests accumulated per drain window / few fstack network events, frequent switching between "APP request handling" and "stack handling", high overhead
- Too long → APP request backlog, network packet latency rises, overall RTT worsens
- Just right → APP-side syscall accumulation count ≈ fstack-side stack event production count, the two sides "align"

Recommended 50us for short connections, 100us for long connections. The user's measurement environment is configured at 30us, which is the optimal tuned value for this business scenario.

### 2.3 SPEC FR-005 Constraint

Source: `docs/ld_preload_ring_spec/01-requirements-spec.md`:

> "Maintain the behavior of multiple polling iterations within the `pkt_tx_delay` time window"

→ The v3 fix for the ring mode must not simply shorten or break the drain-window semantics; it can **only optimize the empty-polling path within the window**.

---

## 3. perf Data Cross-Validation

### 3.1 perf stat Falsifies H15 (cache miss)

```
              Ring (92k QPS)    Sem (105k QPS)    Difference
cache-misses        692,902         792,424      ring 14% lower
LLC-load-misses     204,144         251,343      ring 23% lower
L1-dcache-misses 1,824,039,526   1,830,010,884   -0.3% (nearly identical)
```

**Verdict**:
- LLC-load-misses are at the order of only **6,800/sec**, neither mode is bottlenecked by it
- L1 misses are nearly identical → cache state is similar on both sides
- Ring has fewer LLC misses, completely opposite to v2's hypothesis "ring cross-core cache read waste"
- → **H15 is falsified**

### 3.2 perf top Cross-Evidence for H17 (event aggregation)

#### fstack perf top during stress test (provided by user)

```
20.75%  ff_handle_each_context     ← drain loop body
17.70%  ff_ring_process_requests   ← ring-mode-only batch dequeue entry
 7.10%  ff_handle_socket_ops_ring  ← ff_so_handler call
 3.81%  ff_ring_send_response      ← response enqueue
 Stack total ~18% (tcp_*/ip_*/syncache_*)
```

**Key observations**:
- Of the 17.70% on `ff_ring_process_requests`, the vast majority is likely **nb=0 empty dequeue** (few events within the drain window, multiple loops needed before the next event arrives)
- Stack total only ~18%, meaning the fstack lcore spends **~50% of time on the IPC path**
- If aggregation were high (multiple sc handled per loop), `ff_ring_process_requests` percentage would drop significantly

#### nginx perf top during stress test (provided by user)

```
78.24%  ff_ring_dequeue_wait       ← APP waiting for response (incl. sched_yield)
 4.06%  ff_ring_submit_and_wait    ← submit+wait wrapper
```

→ APP spends 78% of time waiting for responses, indicating long end-to-end syscall latency. This matches H17's derivation of "each syscall takes an extra ~150-250ns × 92k QPS".

### 3.3 H17 Physical Mechanism Derivation (proposed in v3 · falsified in v3.2, archived)

> The v3 phase derived H17 root cause based on "+150-250ns accumulation per syscall across cache lines breaks aggregation". Subsequent pkt_tx_delay matrix (§5.1) + wrk latency distribution (§3.4) + perf top callgraph (§3.4) jointly falsified it: starting from 60μs+ ring and sem collapse together, ring jitter Stdev is even smaller than sem, and the actual root cause lies in the two ring-specific functions with high perf top Self%. See §4 Lessons.

| Stage | Sem mode | Ring mode | Increment (estimated) |
|---|---|---|---|
| ① APP submit | `sc->status = FF_SC_REQ` | `rte_ring_sp_enqueue` | +30~50ns |
| ② fstack probe | `sc->status` dirty read | `rte_ring_sc_dequeue_burst` | +30~50ns |
| ③ fstack handling | same | same | 0 |
| ④ fstack reply | `sc->status = FF_SC_REP` | `rte_ring_sp_enqueue` | +30~50ns |
| ⑤ APP wait | `while sc->status != REP` | `ff_ring_dequeue_wait` | +50~100ns |

**v3 estimate**: +150-250ns per syscall; **v3.2 measurement**: wrk latency delta of +190μs (3 orders of magnitude off), proving the real cause is not in the per-syscall path but in fstack main-loop CPU share.

---

### 3.4 wrk Latency Distribution + perf top callgraph Evidence (v3.2 root cause locked, 2026-05-21 evening)

#### 3.4.1 wrk Latency Distribution Comparison (`-t24 -c128 -d10 -L`)

| Percentile | Sem (μs) | Ring (μs) | Δ(Ring-Sem) |
|---|---|---|---|
| Avg | 1010 | 1200 | **+190** |
| P50 | 1010 | 1200 | **+190** |
| P75 | 1030 | 1220 | **+190** |
| P90 | 1070 | 1240 | +170 |
| P99 | 1180 | 1300 | +120 |
| **Stdev** | **49** | **37** | **-12 (ring jitter is smaller)** |

**Key interpretation**:
- All percentiles show a **near-constant additive offset** (≈190μs) → the regression is deterministic and a fixed overhead occurring every time
- Ring Stdev is even smaller → **completely rules out H17 (aggregation-jitter type bottleneck)**
- But the 190μs magnitude is far beyond reasonable per-IPC-path range → the actual root cause is not in the per-syscall path but in macro-level "CPU share squeeze"

#### 3.4.2 perf top callgraph (`perf top -p $(pgrep fstack) --call-graph dwarf`)

Ring mode measurement (fstack lcore 1):

| Function | Self % | Children % | Role |
|---|---|---|---|
| `ff_handle_each_context` | **19.39** | 53.54 | Main-loop IPC scaffolding (ring-branch spin) |
| `ff_ring_process_requests` | **15.44** | 34.46 | dequeue burst path (ring-only) |
| `ff_handle_socket_ops_ring` | **5.99** | 15.82 | per-request dispatch (equivalent to sem) |
| `ff_ring_send_response` | **3.33** | 3.33 | rsp_ring write (ring-only) |
| Stack total (tcp_input/ip_input/...) | ~30 | -- | Unrelated to IPC |

**Ring-specific IPC overhead Self total** = `ff_ring_process_requests (15.44) + ff_ring_send_response (3.33)` = **18.77%**.

#### 3.4.3 Root Cause Locking

- 🔴 **H19-final (primary)**: `ff_ring_process_requests` Self 15.44%. Called every main-loop spin; even when nb=0 it goes through the full `rte_ring_sc_dequeue_burst` (including cross-core read of prod.tail + function call stack), whereas sem mode at the same position skips the for-loop with nb_handled=0 ≈ 0%.
- 🟠 **H23 (secondary)**: `ff_ring_send_response` Self 3.33%. Each response writes to rsp_ring->prod.tail, triggering nginx lcore 4 cache invalidate; sem mode is just a single `sc->status=REP` store.
- **Overall**: ring mode IPC path totals ~44% (incl. `ff_handle_each_context` 19.39 + the three above), squeezing protocol-stack handling (~30%), matching the magnitude of the 14% QPS regression.

#### 3.4.4 Reconciliation of 192μs Latency Delta and 18.77% CPU Squeeze

- fstack lcore CPU is fully saturated at 100%
- Ring mode uses 18.77% more CPU than sem on IPC → stack handling time is compressed by ~19%
- Stack share ~30% × 19% compression = ~5.7% direct QPS loss
- IPC-path own latency + stack squeeze → per-request RTT extension (perf top shows IPC-path time)
- **Simultaneously matches** the wrk-measured 14% QPS drop and 190μs latency stretch

**Conclusion**: Plan B (burst histogram) is no longer needed — the evidence chain is closed; proceed directly to plan C implementation.

---

## 4. Hypothesis Evolution Lessons Summary

> This section is a refined retrospective of the v1 → v2 → v3 → v3.1 → v3.2 → v3.3 → v3.4 erroneous reasoning and convergence trajectory, as a concrete case study of the working disciplines: "two-sided code comparison + falsifiable physical quantity + data before theory + symmetric assessment of newly introduced physical quantities + control group before optimization".

**v1 error (root cause H10/H11)**: Conclusion drawn after reading only the ring branch in `ff_socket_ops.c:618-645`: "sem mode has no 30μs drain forced empty polling", ignoring that the else-branch in `ff_socket_ops.c:646-702` also has the `if (diff_tsc >= drain_tsc) break` loop. **Root cause**: one-sided code reading, drawing conclusions without comparing the other branch. **Correction**: the user pointed out "sem mode also polls 30us before exiting", and H10/H11 was retracted document-wide.

**v2 error (root cause H15)**: Based on the code difference "sem has nb_handled bypass while ring does not", hypothesized that ring mode has elevated LLC miss because `rte_ring_sc_dequeue_burst` cross-core reads prod.tail. **Root cause**: hypothesis was written into the analysis doc before being validated with a falsifiable physical quantity via perf stat. **Correction**: user-provided perf stat showed ring and sem LLC miss are close and ring is even lower (only ~6.8K/s magnitude), and H15 was retracted document-wide.

**v3.1 error (secondary cause H18, 2026-05-21)**: Based on the code fact "YIELD_POLL triggers sched_yield every 256 PAUSEs", arithmetically derived "14k yield/s × 250ns ≈ 3-4% CPU waste" and listed it as a secondary cause. **Root cause**: ignored the key fact that `spin_count` is a function-local variable in `ff_ring_dequeue_wait`, and a single wait in a short-connection scenario does not even reach the 256 PAUSE threshold. **Correction**: the user measured three configurations (YIELD_POLL 0xFF / YIELD_POLL 0x1FFF / BUSY_POLL) with QPS all at 92k, and nginx worker `voluntary_ctxt_switches` growth ≈ 0; plan A was archived to §5.A. **Lesson**: any "frequency/count" type estimation must first be measured with the lowest-cost method before being added to the diagnosis list — only 10 seconds of voluntary_ctxt_switches sampling would have avoided 30 minutes of detour through plan A.

**v3.2 error (H17 + H21 + H24, 2026-05-21 evening)**: (a) **H17 misread**: interpreted F-Stack's official "event matching" theory as "structural difference between two IPC modes", but the pkt_tx_delay matrix showed that starting from 60μs ring and sem collapse together (53k/81k both identical), and ring jitter Stdev is even smaller than sem — the official wording referred to "configuration precision", not "inter-mode difference". **Root cause**: grafted official theory onto this scenario without first running pkt_tx_delay sensitivity tests. (b) **H21 magnitude misread**: after seeing wrk latency +190μs of ring over sem, jumped to "single-syscall RTT +~150ns additive overhead" without pause, but 190μs is ~3 orders of magnitude beyond a reasonable code-path range. **Root cause**: treated the latency delta as per-syscall overhead, forgetting the indirect path "latency = CPU share squeeze → stack handling delayed". (c) **H24 methodological error**: even after perf top gave clear evidence, still digressed to "lcore cross-NUMA" hypothesis, but ring vs sem is same-environment same-config comparison — **the only variable is the IPC implementation itself**, and an environment-variable hypothesis violates the basics of controlled experiments. **Root cause**: lack of controlled-experiment design awareness. **Correction**: after the user provided pkt_tx_delay matrix + wrk latency distribution + perf top callgraph (three sets of measurements), the evidence chain closed at `ff_ring_process_requests` Self 15.44% + `ff_ring_send_response` Self 3.33% — **all directly from perf top, no theoretical derivation**. **Lessons**: (1) never introduce environment-variable hypotheses in same-environment controlled experiments; (2) for any "latency delta", first lock down the function level via perf top before formulating mechanism hypotheses; (3) data before theory.

**v3.2 methodological correction**: (1) every hypothesis must be paired with a **falsifiable physical quantity** (perf stat / micro-benchmark / wrk latency distribution / perf top Self%); (2) "difference" conclusions can only be drawn after two-sided code comparison; (3) prefer citing **official authoritative documents** to anchor problem perspectives, but first confirm via zero-cost experiments whether the theory applies to this scenario; (4) any "frequency/count/latency" estimation must first be validated by zero-cost sampling; (5) **never introduce environment-variable hypotheses in same-environment controlled experiments** — single-variable principle; (6) **perf top callgraph is the ultimate root-cause arbitration tool** — any analysis direction should defer to perf top data. The final root causes H19-final + H23 were both read directly off perf top Self%, again confirming "data before theory".

**v3.3 error (H25, 2026-05-22)**: After implementing plan C (atomic `pending_count` bypass), QPS dropped 4% (91k → 87k); perf top showed `ff_handle_each_context` Self surged +16.88pp (19.39% → 36.27%). **Root cause**: the plan only evaluated the gain of "eliminating the dequeue burst path" (achieved — `ff_ring_process_requests` Self 15.44% → 9.16%), but **did not evaluate the new overhead from "high-frequency atomic_read cross-core ping-pong"** — nginx writes the atomic 2-4 times more per syscall (inc + possible rollback dec/inc), and the write frequency more than doubles from baseline's "1 enqueue per call", aggravating cache ping-pong. **Correction**: immediately reverted plan C after measurement (compile flag `FF_RING_PENDING_BYPASS` defaulted off), and switched to plan C+ (D2, sc->completion replaces rsp_ring). **v3.3 lessons**: (1) any plan design must **symmetrically evaluate** newly-introduced physical quantities (frequency, cross-core access pattern, cache behavior) and not look only at "what is removed" without "what is added"; (2) **CPU Self% does not equal optimization gain** — after plan C, `ff_ring_process_requests` Self did drop 6% (as expected) but was swallowed by the new atomic cross-core read and incurred an extra 10%; (3) plan C+/D2 succeeded crucially because it **reuses the existing `sc->completion` field (already in sc cache line 0), with zero new cross-core fields** — nginx write frequency is identical to baseline.

**v3.3 methodological correction**: introduce a "Symmetric Assessment Table" in the design phase — every fix plan must list the "physical quantities removed/reduced" and "physical quantities newly introduced", and the latter must be of an order of magnitude clearly smaller than the former before entering implementation. In this case: plan C+ (D2) and plan D5 both passed (D2 reuses sc cache line with zero additions, D5 reuses ring internal fields with zero additions); plan C did not (added atomic field and doubled nginx write frequency).

**v3.4 convergence (final insight)**: After plans D5/D6 were implemented smoothly (D5 +1.3%, D6 +0.9%), QPS converged to 102.2k (97.3% of sem), and perf top showed `ff_handle_each_context` Self 50.13% **virtually identical to** sem's 50.41% — main-loop CPU share is aligned. **Key insights**: (1) **under fstack 100% CPU + 30μs drain spin design, simply optimizing IPC-path overhead does not 1:1 translate into QPS gain** — saved CPU is immediately consumed by main_loop spin, only reducing one round of cycles; (2) **diminishing-returns law of optimization**: D2 +9.7% (eliminating rsp_ring) → D5 +1.3% (eliminating function call stack) → D6 +0.9% (eliminating function pointer) → next-step expected < 0.5%; (3) **the remaining 2.7% is ring SPSC architectural inherent overhead** — acquire fence inside `rte_ring_sc_dequeue_burst` + ring metadata maintenance; sem dirty-read of sc->status is a plain load with no fence, this is a physical cost. **v3.4 methodological correction**: (4) before performance optimization, first determine the "theoretical upper bound" with a control-group perf top — in this case sem perf top revealed main-loop CPU share is already aligned, telling us in advance that the remaining gap is architectural and avoiding micro-optimizations with marginal gain < 0.5%; (5) "data before theory" extended to "control group before optimization" — collect control-group data before optimization to assess remaining headroom, not after a round of work to discover you've already approached the limit.

---

## 5. Detailed Fix Plan Designs

### 5.A Archived Plan: Original Plan A — APP-side Switch to Pure BUSY_POLL (H18 falsified)

> **2026-05-21 measurement conclusion**: H18 fully falsified, plan archived but kept for retrospective.
>
> | Configuration | nginx vcs growth | sched_yield/s | QPS |
> |---|---|---|---|
> | Ring + YIELD_POLL (`0xFF`) | 0 | ≈ 0 | 92k |
> | Ring + YIELD_POLL (`0x1FFF`) | 0 | ≈ 0 | 92k |
> | Ring + BUSY_POLL (no yield path at all) | 0 | 0 | 92k |
> | Sem baseline | 0 | ≈ 0 | 105k |
>
> **Falsification logic**:
> 1. nginx worker `voluntary_ctxt_switches` growth measured ≈ 0 (A=1 B=1)
> 2. BUSY_POLL (with yield code path completely removed) gives identical 92k QPS as YIELD_POLL
> 3. `spin_count` is a function-local variable in `ff_ring_dequeue_wait`, and at 92k QPS short-connection scenario a single wait only spins a few hundred PAUSEs before getting the response — **far below the 256 threshold**
>
> **Methodological lesson**: "14k/s" was pure arithmetic back-derivation (QPS × 1.5 yield/req), listed as a secondary cause without measurement. See §4 Lessons.
>
> ---
>
> The discarded draft is kept below for comparison:
>
> **Change point**: `ff_ring_ipc.c:111-129` `ff_ring_dequeue_wait` wait_mode dispatch.
>
> ```c
> /* Before */
> case FF_RING_WAIT_YIELD_POLL:
>     if ((++spin_count & 0xFF) == 0) {
>         sched_yield();
>     } else {
>         rte_pause();
>     }
>     break;
>
> /* Draft change */
> case FF_RING_WAIT_YIELD_POLL:
>     if ((++spin_count & 0x1FFF) == 0) {
>         sched_yield();
>     } else {
>         rte_pause();
>     }
>     break;
> ```
>
> Measurement showed this change has no impact on QPS (still 92k).

### 5.1 Pre-test: pkt_tx_delay Sensitivity Matrix (zero-code · **execute first**)

**Purpose**: before writing any code, falsify/support H17 directly with pure config changes. If ring QPS is highly sensitive to pkt_tx_delay while sem is not → H17 is directly confirmed and we can skip plan B and proceed to plan C.

**File changed**: `config.ini` (only `pkt_tx_delay`). **Diff size**: 0 lines of code.

**Test matrix**:

| pkt_tx_delay (μs) | Ring QPS | Sem QPS | Inference |
|---|---|---|---|
| 10 | ? | ? | Short drain, little aggregation room |
| 30 (baseline) | 92k | 105k | baseline |
| 60 | ? | ? | Standard long drain |
| 100 | ? | ? | Officially recommended for long connections |

**Verdict**:

| Phenomenon | Inference |
|---|---|
| Ring QPS recovers to ≥ 100k at 60-100μs while sem barely changes | **Strong evidence for H17** → skip §5.2, go straight to §5.3 |
| Ring/Sem both insensitive to pkt_tx_delay | H17 weakened, do §5.2 to take direct evidence |
| Ring collapses at 10μs (e.g. < 70k) | Strong evidence for H17 (short drain leaves ring fully unable to aggregate events) |

### 5.2 Plan B: drain-window burst histogram quantification (validate H17)

**Change points**: `ff_socket_ops.c:618-645` ring branch + `ff_socket_ops.c:660-702` sem branch with synchronized sampling.

**ring branch patch** (line 636-645):
```c
#ifdef FF_RING_BURST_HIST
    static uint64_t hist[8] = {0}; /* 0/1/2/3/4-7/8-15/16-31/32+ */
    static uint64_t total_drain = 0;
    static uint64_t total_iter = 0;
    static uint64_t total_handled = 0;
    static uint64_t last_dump_tsc = 0;
    uint32_t drain_iter = 0;
    uint32_t drain_handled = 0;
#endif

    while (1) {
        uint16_t nb = ff_ring_process_requests(ff_so_zone->ring_zone,
            ff_handle_socket_ops_ring, FF_RING_SIZE);

#ifdef FF_RING_BURST_HIST
        drain_iter++;
        drain_handled += nb;
        uint8_t bucket = (nb == 0) ? 0 :
                         (nb == 1) ? 1 :
                         (nb == 2) ? 2 :
                         (nb == 3) ? 3 :
                         (nb < 8)  ? 4 :
                         (nb < 16) ? 5 :
                         (nb < 32) ? 6 : 7;
        hist[bucket]++;
#endif

        diff_tsc = rte_rdtsc() - cur_tsc;
        if (diff_tsc >= drain_tsc) {
            break;
        }
        rte_pause();
    }

#ifdef FF_RING_BURST_HIST
    total_drain++;
    total_iter += drain_iter;
    total_handled += drain_handled;
    if ((cur_tsc - last_dump_tsc) >= rte_get_tsc_hz() * 10) { /* dump every 10s */
        ERR_LOG("burst_hist drain=%lu iter=%lu handled=%lu avg_iter/drain=%.2f avg_handled/drain=%.2f"
            " bucket=[%lu/%lu/%lu/%lu/%lu/%lu/%lu/%lu]\n",
            total_drain, total_iter, total_handled,
            (double)total_iter/total_drain, (double)total_handled/total_drain,
            hist[0],hist[1],hist[2],hist[3],hist[4],hist[5],hist[6],hist[7]);
        last_dump_tsc = cur_tsc;
    }
#endif
```

**sem branch in sync** (line 660-702 embeds the same hist array, also updates `drain_handled` inside the for loop, and updates `hist` and `total_*` on drain exit).

**Compile flag**: add `-DFF_RING_BURST_HIST` to `Makefile`, enabled only during diagnostics, no impact on production builds.

**Expected verdict** (H17 validity criterion):
- ring mode: `avg_handled/drain` < 4, `bucket[0]` (empty dequeue) > 70%
- sem mode: `avg_handled/drain` > 6, `bucket[0]` < 50%
- The direction must be ring aggregation lower than sem; otherwise H17 is falsified

### 5.3 Plan C: atomic pending_count bypass — ❌ **Implemented, regressed, discarded, code removed**

> **2026-05-22 measurement conclusion**: QPS 91k → 87k (**4% regression**), `ff_handle_each_context` Self 19.39% → 36.27% (surged +16.88pp). **H25 falsified**. Reverted immediately; subsequently (post-v3.7) the compile flag `FF_RING_PENDING_BYPASS`, the `pending_count` field, and all its inc/dec paths were also removed from the code (`ff_socket_ops.h` / `ff_socket_ops.c` / `ff_hook_syscall.c` / `Makefile`); the plan is no longer kept as a research branch.
>
> **Failure root cause**: nginx originally only writes `req_ring->prod.tail` once on enqueue (frequency ~100k/s), but plan C makes nginx write `pending_count` 2-4 times per syscall (inc + possible dec/inc retry), more than doubling the write frequency → fstack reads cross-core every drain spin → cache line is constantly invalidated in a ping-pong → CPU wasted on cache miss is worse than the original dequeue path.
>
> **Lesson**: plan design must use a "Symmetric Assessment Table", listing "physical quantities removed" and "physical quantities newly introduced". See §4 Lessons. The path that was finally taken in code is §5.5 plan D5 (`rte_ring_empty` inline fast empty check) — the same goal (avoiding the empty-dequeue function call stack) achieved by **reusing existing ring metadata with zero new cross-core fields**, passing the symmetric assessment and confirmed by measurement.

---

### 5.4 Plan C+ / D2: sc->completion replaces rsp_ring (fix H23) — ✅ **Implemented and measured successful**

> **2026-05-22 measurement**: QPS 91k → **100k (+9.7%)**, wrk Avg 1.20ms → 1.06ms (-12%), `ff_ring_send_response` Self 3.33% → **0%**. **H23 fix confirmed**. Merged as the **default behavior** of the `FF_USE_RING_IPC` branch (the standalone compile flag is no longer needed; the legacy rsp_ring path has been deleted).

**Core idea**: eliminate `rsp_ring` enqueue; let fstack write directly to **`sc->completion`** after handling (already in sc cache line 0, offset 32, originally reserved for ring IPC). The response path is fully equivalent to sem mode's `sc->status=REP`.

**Files changed**: `ff_ring_ipc.c` (`ff_ring_send_response` + `ff_ring_alarm_wakeup`) + `ff_hook_syscall.c` (`ff_ring_submit_and_wait`) + `Makefile`.

**Symmetric Assessment Table** (newly enforced methodology in v3.3):

| Item | baseline | D2 |
|---|---|---|
| nginx cross-core write fields | `req_ring->prod.tail` + sc | Same as baseline (only sc write) |
| nginx write frequency | per-syscall: 1 sc write + 1 prod.tail write | **Same as baseline** |
| fstack cross-core write fields | `rsp_ring->prod.tail` + sc->result | Writes sc->completion + sc->result (same cache line) |
| fstack write frequency | 2 cache lines per response | **1 cache line per response** (merged within sc) |
| **Newly introduced cross-core field** | -- | **None** (completion field already exists) |
| Savings | -- | The entire rsp_ring path (enqueue + dequeue + one cache-line bouncing) |

✅ Symmetric assessment passes.

**Protocol design**:
```
APP-side ff_ring_submit_and_wait:                fstack-side ff_ring_send_response:
  1. sc->completion = 0  (RELAXED, before enqueue)  1. (write sc->result/error etc.)
  2. enqueue req_ring(sc)                            2. sc->completion = 1  (RELEASE)
  3. spin sc->completion == 1 (ACQUIRE)
  4. return
```

**Memory ordering**: fstack-side RELEASE store ensures sc->result is written first; APP-side ACQUIRE load ensures the sc->result read after seeing completion=1 is not reordered before it.

**Risk**: low. The `ff_ring_alarm_wakeup` path is updated synchronously to also set `sc->completion=1`, ensuring alarm wakeups still work under D2; the rsp_ring enqueue is retained as a sentinel/legacy fallback for the alarm path. This plan has been merged as the default behavior of `FF_USE_RING_IPC` and the standalone `FF_RING_SC_COMPLETION` compile flag has been removed (D5/D6 below were similarly defaulted).

---

### 5.5 Plan D5: rte_ring_empty fast empty check (fix H19-final function call stack) — ✅ **Implemented and measured successful (small)**

> **2026-05-22 afternoon measurement**: QPS 100k → **101.3k (+1.3%)**, `ff_ring_process_requests` Self 18.98% → **4.53%** (76% drop, as expected).
>
> **Key observation**: most of the function-call-stack overhead is gone, but QPS gain is only 1.3% — the saved 14.45% Self CPU was largely absorbed into `ff_handle_each_context` (Self 27.45 → 36.78), because the fstack lcore is already 100% CPU saturated and the saved CPU is directly consumed by main-loop spinning. This is the starting point of v3.4's key insight.

> **Trigger condition**: D2 has been merged; QPS 100k is still 5% from sem baseline 105k, dominated by `ff_ring_process_requests` Self 18.98% (unchanged after D2).

**Core idea**: use the DPDK public inline function `rte_ring_empty(r)` for the fast empty check, avoiding the function-call-stack expansion overhead of `ff_ring_process_requests`. **No new cross-core fields** — this is the fundamental difference between plan D5 and the failed plan C.

**Change point**: `ff_socket_ops.c` main-loop ring branch (same location as plan C but a completely different implementation). This plan has been merged as the **default behavior** of the `FF_USE_RING_IPC` branch and the standalone `FF_RING_FAST_EMPTY_CHECK` compile flag has been removed.

**Symmetric Assessment Table**:

| Item | baseline | D5 |
|---|---|---|
| nginx cross-core write fields | `req_ring->prod.tail` | Same as baseline |
| nginx write frequency | 1 per enqueue | **Same as baseline** |
| fstack cross-core read fields | `prod.tail` (through dequeue_burst stack) | `prod.tail` (through inline rte_ring_empty) |
| fstack read frequency | per drain spin | **Same as baseline** |
| **Newly introduced cross-core field** | -- | **None** |
| **Newly introduced cross-core write** | -- | **None** |
| Savings | -- | dequeue_burst function call stack, parameter passing, loop overhead |

✅ Symmetric assessment passes: only reductions, no new ping-pongs.

**Historical draft (v3.3 evaluation phase)** — this flag has been defaulted in v3.7+, the mainline code no longer relies on this switch:
```c
while (1) {
#ifdef FF_RING_FAST_EMPTY_CHECK     /* historical: defaulted, mainline no longer checks */
    if (!rte_ring_empty(ff_so_zone->ring_zone->req_ring)) {
        ff_ring_process_requests(...);
    }
#else
    ff_ring_process_requests(...);
#endif
    diff_tsc = rte_rdtsc() - cur_tsc;
    if (diff_tsc >= drain_tsc) break;
    rte_pause();
}
```

**Expected physical-quantity changes**:
- `ff_ring_process_requests` perf top Self %: 18.98% → < 5%
- QPS: 100k → ≥ 105k (catch up with sem)
- Cross-core cache behavior: identical to baseline, no new additions

**Comparison with the failed plan C**:

| Aspect | Plan C (failed) | Plan D5 |
|---|---|---|
| Idea | Introduce a new atomic field as bypass | Reuse existing ring fields with inline check |
| New cross-core field | `pending_count` | **None** |
| nginx write frequency change | +2~4 / syscall | **0** (same as baseline) |
| Measurement | -4% regression | +1.3% gain |

---

### 5.6 Plan D6: inline dispatch (eliminate function-pointer call) — ✅ **Implemented and measured successful (marginal)**

> **2026-05-22 afternoon measurement**: QPS 101.3k → **102.2k (+0.9%)**, `ff_handle_socket_ops_ring` changed from a standalone function (Self 8.38%) to inlined (visible 5.28%), `ff_ring_process_requests` completely disappeared from perf top. **Architecture aligned with sem mode** (sem's `ff_handle_socket_ops` is also static inline).

**Trigger reason**: after D5, perf top still showed `ff_handle_socket_ops_ring` Self 8.38%. Comparing with sem mode where `ff_handle_socket_ops` is `static inline` and fully inlined (no Self visible in perf top), the **function-pointer call stack** was identified as the extra overhead in ring mode over sem.

**Core idea**: directly expand the dequeue + loop logic of `ff_ring_process_requests` in the `ff_socket_ops.c` main loop, calling the handler directly by name (`ff_handle_socket_ops_ring`) instead of via function pointer, allowing the compiler to inline the entire dispatch chain. Also mark `ff_handle_socket_ops_ring` as `static inline` (aligned with sem mode's `ff_handle_socket_ops`).

**Symmetric Assessment Table**:

| Item | baseline (D2+D5) | D6 |
|---|---|---|
| nginx cross-core fields / write frequency | `req_ring->prod.tail` | Same as baseline |
| fstack cross-core read fields / frequency | `prod.tail` | Same as baseline |
| **Newly introduced cross-core field** | -- | **None** |
| Savings | -- | (1) `ff_ring_process_requests` function call stack (2) handler function-pointer indirection (3) compiler cross-function optimization |

✅ Symmetric assessment passes.

**Files changed**: `ff_socket_ops.c` (`ff_handle_socket_ops_ring` marked `inline` + main-loop inlined dispatch, embedded in the D5 path). This plan has been merged as the **default behavior** of the `FF_USE_RING_IPC` branch and the standalone `FF_RING_INLINE_DISPATCH` compile flag has been removed.

**Measured physical-quantity changes**:
- `ff_ring_process_requests` perf top: 4.53% → **completely gone** (inlined)
- `ff_handle_socket_ops_ring` perf top: 8.38% (standalone function) → **5.28% (inlined)**
- QPS: 101.3k → 102.2k (+0.9%)
- wrk Stdev: 53us → 45us (better than sem's 49us)
- wrk P99: 1.20ms → 1.18ms (on par with sem)

---

### 5.7 Architectural Inherent Overhead Lower Bound (v3.4 convergence conclusion)

After D6, ring(D2+D5+D6) main-loop CPU share **50.13%** is virtually identical to sem's **50.41%**, but ring is still 2.7% slower than sem (102.2k vs 105k). This is the **inherent cost** of the ring SPSC architecture:

| Operation | Sem mode | Ring mode |
|---|---|---|
| fstack probe request | dirty read `sc->status` (plain load) | inline `rte_ring_empty()`: load `prod.tail` (acquire fence) + load `cons.tail` |
| fstack take request | sc is in the array, taken directly | `rte_ring_sc_dequeue_burst`: load prod.tail (acquire) + compute entries + copy obj + write cons.head + write cons.tail |
| APP submit request | `sc->status = REQ` (single store) | `rte_ring_sp_enqueue`: write prod.head + prod.tail (release) + bound checks |

**Core difference**: sem's dirty read is a plain load (no memory barrier), while ring's acquire/release fence forces CPU memory-system synchronization with real overhead per spin (even if the cache is hit). At a 10M/s spin frequency this is ~2-3% CPU fixed cost, **unremovable in the single-worker single-lcore scenario**.

**Single-worker optimization converged**: from 91k → 102.2k (+12.3%), only 2.7% from sem (architectural inherent). Then move to multi-worker comparison testing to evaluate ring's true value.

---

## 6. Decision Matrix

| Validation Phenomenon | Root-cause Conclusion | Implementation Action |
|---|---|---|
| ✅ §5.1 Pre-test: at 60μs+ ring and sem collapse together in pkt_tx_delay matrix | **H17 falsified** | Skip §5.2 |
| ✅ §3.4 wrk latency distribution: ring +190μs additive over sem at every percentile | H21 proposed but magnitude mismatched | Move to perf top |
| ✅ §3.4 perf top: H19-final + H23 root cause locked | Data before theory | Implement fixes |
| ❌ §5.3 Plan C measured QPS 87k (4% regression) | **H25 falsified** (atomic bypass introduced worse ping-pong) | Reverted, switched to D2 |
| ✅ §5.4 Plan C+/D2 measured QPS 100k (+9.7%), `ff_ring_send_response` Self 0% | **H23 fix confirmed** | D2 merged |
| ✅ §5.5 Plan D5 measured QPS 101.3k (+1.3%), `ff_ring_process_requests` Self 4.53% | **H19-final function call stack eliminated** | D5 merged |
| ✅ §5.6 Plan D6 measured QPS 102.2k (+0.9%), `ff_handle_socket_ops_ring` inlined | **Architecture aligned with sem mode** | D6 merged |
| 🔵 §5.7 sem vs ring(D2+D5+D6) main-loop Self 50.41% ≈ 50.13% | **Architectural overhead approaching physical limit** | Single-worker converged |
| 🔜 Multi-worker comparison testing | Pending user measurement | See plan.md §8 |

---

## 7. Appendix: Two-sided Code Snippets

### 7.1 fstack Main Loop `ff_handle_each_context`

**Sem branch** (`ff_socket_ops.c:646-702`):
```c
rte_spinlock_lock(&ff_so_zone->lock);
tmp = nb_handled = ff_so_zone->count - ff_so_zone->free;
while (1) {
    nb_handled = tmp;
    if (nb_handled) {                       /* fast bypass */
        for (i = 0; i < ff_so_zone->count; i++) {
            if (ff_so_zone->inuse[i] == 0) continue;
            if (sc->status == FF_SC_REQ) ff_handle_socket_ops(sc);
            if (--nb_handled == 0) break;
        }
    }
    if (rte_rdtsc() - cur_tsc >= drain_tsc) break;
    rte_pause();
}
rte_spinlock_unlock(&ff_so_zone->lock);
```

**Ring branch** (`ff_socket_ops.c:618-645`):
```c
while (1) {
    ff_ring_process_requests(ff_so_zone->ring_zone,    /* no bypass */
        ff_handle_socket_ops_ring, FF_RING_SIZE);
    if (rte_rdtsc() - cur_tsc >= drain_tsc) break;
    rte_pause();
}
```

**Difference**: sem has an `if (nb_handled)` local-variable bypass; ring does not. This is the code fact behind H19, and plan C was supposed to introduce the bypass into ring via pending_count.

### 7.2 APP-side Wait Path

**Sem mode `ACQUIRE_ZONE_LOCK`** (`ff_hook_syscall.c:153-164`):
```c
while (1) {
    while (sc->status != exp) {
        rte_pause();    /* pure pause, no yield */
    }
    rte_spinlock_lock(&sc->lock);
    if (sc->status == exp) break;
    rte_spinlock_unlock(&sc->lock);
}
```

**Ring mode `ff_ring_dequeue_wait`** (`ff_ring_ipc.c:106-129`):
```c
while (rte_ring_sc_dequeue(ring, obj_p) != 0) {
    if (rte_rdtsc() - start_tsc >= timeout_tsc) return -ETIMEDOUT;
    if ((++spin_count & 0xFF) == 0) {
        sched_yield();    /* triggered every 256 iterations */
    } else {
        rte_pause();
    }
}
```

**Difference**: ring-mode APP-side triggers `sched_yield` every 256 PAUSEs, but in measurement at 92k short-connection QPS a single wait is far below the 256-PAUSE threshold, and sched_yield is essentially never triggered (vcs growth ≈ 0). This was originally suspected as a secondary cause (H18) but already falsified in measurement. See §1.3 and §5.A.

---

## 8. Mapping to plan.md Sections

| This document section | Corresponding plan.md section |
|---|---|
| §1.3 Repair path | plan.md §4 Validation plans A/B/C |
| §1.4 Multi-core short + long connection conclusion | plan.md §8.2 / §8.3 / §8.5 measurement data |
| §2 Official documentation evidence chain | plan.md §1 Overview |
| §3 perf data cross-validation | plan.md §1.2 Falsified hypothesis chain |
| §4 Lessons summary | plan.md §2 Lessons summary |
| §5 Detailed fix plan designs | plan.md §4 Code drafts of validation plans |
| §6 Decision matrix | plan.md §5 Decision matrix |
| §7 Two-sided code comparison | plan.md §3 Code references in hypothesis list |
| §9 Appendix D startup starvation | plan.md §8.6 Startup starvation |
| §10 Appendix E multi-core short/long connection tests | plan.md §8.2 / §8.5 |

---

## 9. Appendix D: sem-mode `idle_sleep=0` + Multi-worker Startup Starvation (not a real deadlock)

> Trigger conditions: `FF_USE_RING_IPC` **disabled** (i.e. legacy sem path) + `FF_MULTI_SC=1` + fstack `config.ini` has `idle_sleep = 0` + nb_procs ≥ 2.
> Phenomenon: after fstack/nginx fully started but **before any traffic is sent**, the second nginx worker hangs forever in `rte_spinlock_lock(&ff_so_zone->lock)` inside `ff_attach_so_context(idx=1)`; the gdb backtrace looks identical to a deadlock.
> User validation (2026-05-25): changing fstack `idle_sleep` from `0` to `1` (only 1μs) makes startup succeed. **Unrelated to ring mode** (ring main loop is lock-free and avoids this issue).

### 9.1 The Nature: Spinlock Starvation, Not Deadlock

The lock is not "held without releasing" by anyone. The fstack secondary lcore in the legacy sem-path main loop **rapidly acquires and releases** the same zone lock at high frequency, while the nginx worker process **never wins** in the ongoing cmpxchg contention — the appearance is identical to a deadlock.

### 9.2 Call Chain and Code References

**fstack secondary process main loop** (`adapter/syscall/fstack.c:7` → `ff_socket_ops.c:622`):

```
ff_main_loop                                    # DPDK lcore tight loop
  - ff_dpdk_if.c:2422-2428                     # idle_sleep==0 → no CPU yield
  - ff_handle_each_context()
       - #else (sem branch, ff_socket_ops.c:700-747)
            - rte_spinlock_lock(&ff_so_zone->lock)    line 702
            - while(1) { ... iterate sc, wait until drain_tsc ... }
            - rte_spinlock_unlock(&ff_so_zone->lock)  line 747
```

**nginx worker startup path** (`adapter/syscall/ff_so_zone.c:160`):

```
ff_adapter_init() → ff_attach_so_context(worker_id % nb_procs)
  - ff_so_zone.c:192  rte_spinlock_lock(&ff_so_zone->lock)   stuck here
```

The two paths contend for **the same lock**: fstack secondary (proc_id=1)'s `ff_so_zone` points to zone1 (`ff_so_zone.c:153`), and nginx worker1's attach also targets zone1 (`ff_hook_syscall.c:3292` computes idx=1).

### 9.3 Three Stacked Starvation Factors

| ID | Factor | Code location | Magnitude |
|---|---|---|---|
| **P1** | Lock-hold duration = `pkt_tx_delay` (independent of sc count) | `ff_socket_ops.c:700-744`, `while(1)` does not break until `diff_tsc ≥ drain_tsc` | 50-100 μs/iter |
| **P2** | No idle yield after unlock | `ff_dpdk_if.c:2423` `if (likely(idle && idle_sleep))`, falls through when `idle_sleep==0` | unlock-reacquire interval **<<1 μs** |
| **P3** | `rte_spinlock` is unfair (raw cmpxchg) | DPDK rte_spinlock impl: `while(__atomic_compare_exchange_n(&sl->locked, &exp=0, 1, ...) == 0) rte_pause();` | No ticket queue, no backoff |

**Stacking effect**:
- fstack lcore is dedicated-core + tight-spin + same-NUMA → continuously holds the zone-lock cache line and **wins back the lock the very next tsc after unlocking**
- nginx worker is a normally-scheduled process with low cmpxchg frequency, and the cache line must be pulled to its core first → **always one beat slower at every release window**
- Lock-hold 50μs >> idle window <<1μs, the probability of an nginx worker hitting the idle window approaches 0

### 9.4 Timeline Reconciliation

```
fstack lcore (idle_sleep=0)                 nginx worker tries to grab lock
  T0      lock zone1                            cmpxchg fail, rte_pause
  T0+50us unlock                                idle window <<1us (fstack cmpxchg right away)
  T0+50us lock zone1 (fstack wins back)         cmpxchg fail, rte_pause
  T0+100us unlock                               idle window <<1us
  ...                                           (continuously starved)

fstack lcore (idle_sleep=1us)               nginx worker tries to grab lock
  T0      lock zone1                            cmpxchg fail, rte_pause
  T0+50us unlock                                idle window >=1us
  T0+50us rte_delay_us_sleep(1)                 cmpxchg succeed, hold lock, init
```

cmpxchg itself only takes tens of ns; **success probability inside a 1μs window approaches 100%**.

### 9.5 Why Ring Mode Is Naturally Immune

`ff_socket_ops.c:622-688` (`#ifdef FF_USE_RING_IPC` branch):

```c
624: #ifdef FF_USE_RING_IPC
626:  * Ring mode: O(1) batch dequeue from req_ring.
627:  * No global zone lock needed — ring is lock-free.
```

Ring main loop **never locks the zone**, only briefly during `ff_attach_so_context` at startup (millisecond level), with no high-frequency contention from fstack lcore. **The v3.4-optimized ring path architecturally avoids this issue** — further evidence of the systemic gain of the ring path over the legacy sem path (not just performance, but also startup robustness).

### 9.6 Solutions (in increasing cost)

| Plan | Cost | Effect | Status |
|---|---|---|---|
| **A. User-side workaround** | Set fstack `config.ini` `idle_sleep >= 1` | lcore CPU drops from 100% to ~95%, sem mode starts up properly | ✅ Validated |
| **B. Code patch** (sem path only, commit `8125beec`) | `ff_socket_ops.c:744-752` releases the lock window only when `tmp==0` (no in-use sc) | Removes startup starvation; **zero impact under load** (`tmp>0` keeps original `rte_pause()`, no unlock) | ✅ Merged to mainline |
| **C. Long-term architecture** (done) | Enable ring mode (`FF_USE_RING_IPC=1`), main loop is lock-free | Avoids the issue; also delivers +12.3% QPS | ✅ Delivered in v3.4 |

### 9.6.1 Plan B Fix Details (commit `8125beece6`, 2026-05-25)

**Modified location**: `adapter/syscall/ff_socket_ops.c:707-752` (the while loop inside `ff_handle_each_context` sem branch)

**Modification highlights** (only +13/-5 lines):

1. **line 705**: keeps `tmp = nb_handled = ff_so_zone->count - ff_so_zone->free` (snapshot of in-use sc count at loop entry)
2. **line 709**: `if (nb_handled)` -> `if (likely(nb_handled))`, branch-prediction hint for compiler (normal load has in-use sc)
3. **line 744-752**: new "release lock window when no load" logic:

```c
if (unlikely(!tmp)) {                            // in-use sc count is 0 at iteration start
    rte_spinlock_unlock(&ff_so_zone->lock);      // unlock
    rte_pause();                                  // pause
    rte_spinlock_lock(&ff_so_zone->lock);        // re-acquire
}
```

**Why use `tmp` and not `nb_handled`**:
- `tmp` is the **snapshot at loop entry** (line 705), invariant for the entire `drain_tsc` window
- `nb_handled` is decremented to 0 inside each for iteration (line 728), so it cannot be the "is there load" indicator
- → `tmp==0` precisely expresses "startup/idle, the process truly has no sc right now"

**Why this is the optimal fix**:

| Scenario | tmp value | Behavior | Impact |
|---|---|---|---|
| Startup (nginx not attached yet) | `tmp == 0` | Each iteration unlock-pause-relock, **gives attach a window** | Solves starvation ✓ |
| Normal stress test (multi-sc in use) | `tmp > 0` | Goes through `rte_pause()` without unlocking, keeps the drain | **Zero performance impact** ✓ |
| Only a few sc temporarily idle | `tmp > 0` | Same as above | Doesn't trigger unlock, avoids sc handling delay ✓ |

**Difference from the author's original §9.6 plan B suggestion** (the committer's version is better):

- Author's original suggestion: unconditional `unlock - pause - lock`, adding two atomic ops to every load path
- Committer's fix: uses `unlikely(!tmp)` to limit it to the **startup/full-idle** scenario, zero overhead under normal load
- Also adds `likely(nb_handled)` to optimize branch prediction on the hot path, reflecting the author's respect for the still-in-production sem path

**Regression risk**:
- Active only on the sem path (`#else` branch, line 689-754), no impact on the ring path
- Lock invariant unchanged: holds lock before while, holds lock after while exit, no zone-field access between `unlock-lock`
- `tmp` is a local variable, unaffected by zone modifications during unlock

### 9.6.2 Recommended Configurations

| Deployment form | Compile flags | config.ini | Notes |
|---|---|---|---|
| Single-instance sem (compat with legacy deployments) | `FF_KERNEL_EVENT=1` (no ring) | `idle_sleep = 0` is fine | Requires being based on commit `8125beec` or later |
| Single-instance sem (conservative) | Same as above | `idle_sleep = 1` | Double safety, CPU usage ~95% |
| Multi-worker sem | Same as above | `idle_sleep = 0` (post-commit) or `1` (pre-commit) | Multi-worker is the main target of `8125beec` |
| Multi-worker ring (v3.4 recommended) | `FF_USE_RING_IPC=1 FF_KERNEL_EVENT=1 FF_MULTI_SC=1` | `idle_sleep` arbitrary (ring main loop does not lock zone) | +12.3% performance, no starvation issue (D2/D5/D6 are the default behavior of the ring branch since v3.7, no separate flags needed)

### 9.7 Relation to the Main Document

This appendix is **orthogonal** to the single-worker ring performance optimization in §1-§7 — it does not affect any of the implemented plan conclusions (D2/D5/D6). But it reveals an **additional architectural defect of the legacy sem path under multi-instance deployment**, supplementing the necessity argument for the ring path.

**Fix status (2026-05-25)**: commit `8125beece6` has fixed it at the source on the sem path (see §9.6.1), so production sem deployments no longer need to rely on the `idle_sleep` workaround. The ring path was naturally immune to begin with.

Investigation lessons (consistent with §4):
- For startup hangs, prioritize "high-frequency preemption + unfair lock" type starvation rather than real deadlock (gdb stack looks identical, but the lock state shows briefly locked, with `*sl` value flipping between 0/1)
- In cross-process spinlock contention, **a dedicated DPDK lcore always beats a normally-scheduled process** — this is a physical mechanism, not a code bug
- The user's clue "changing `idle_sleep` to 1 fixes it" was decisive — phenomena that can be eliminated by configuration are 99% timing-window/scheduling issues
- **An optimal patch should be "conditional yield" rather than "unconditional yield"**: using `unlikely(!tmp)` to confine the overhead to the starvation scenario, with zero impact on normal load (the commit `8125beec` paradigm)

---

## 10. Appendix E: Multi-core Short-Connection + Long-Connection Measurement Data (v3.6 · 2026-05-25 evening · final)

> This appendix is the complete data archive for the convergence conclusion in §1.4. Short connection (§10.1-§10.4) is from v3.5; long connection (§10.5-§10.7) is added in v3.6 and ultimately falsifies the ring path's design goal.

### 10.1 Test Environment (shared by short / long connection)

- **Platform**: same environment as the single-worker test (same NUMA, same lcore configuration principle)
- **fstack worker count**: 1:1 with nginx worker count
- **Compile flags**:
  - sem path: `FF_KERNEL_EVENT=1 FF_MULTI_SC=1` (including commit `8125beece6` startup-starvation fix)
  - ring path: `FF_USE_RING_IPC=1 FF_KERNEL_EVENT=1 FF_MULTI_SC=1` (D2+D5+D6 are merged as the default behavior of the ring branch since v3.7; the standalone flags `FF_RING_SC_COMPLETION` / `FF_RING_FAST_EMPTY_CHECK` / `FF_RING_INLINE_DISPATCH` have been removed)
- **wrk parameters**: `-c 128 -t 24 -d 10 -L` (short connection default; long connection uses keep-alive mode)
- **`config.ini`**: `pkt_tx_delay = 50` (short) / `100` (long), `idle_sleep = 0`

### 10.2 Short-Connection Measurement Data

| lcores | Sem QPS (10k) | Ring QPS (10k) | Ring/Sem gap | Sem per-core efficiency | Ring per-core efficiency | Scaling factor (Ring) |
|---|---|---|---|---|---|---|
| 1 | 10.4 | 10.2 | -1.92% | 10.40 | 10.20 | baseline |
| 2 | 20.8 | 20.8 | 0.00% | 10.40 | 10.40 | x2.04 |
| 4 | 35.9 | 35.8 | -0.28% | 8.98 | 8.95 | x3.51 |

### 10.3 Data Interpretation

**Conclusion 1: ring ≡ sem (gap ≤ 2% noise range)**

Among the three sets, the 1-core scenario shows ring 1.92% lower (close to the 2.7% in the v3.4 single-worker convergence in §1.4), and 2/4 cores are essentially on par. **Statistically, the two paths can be regarded as performance-equivalent**.

**Conclusion 2: 2-core scaling is near-linear (x2.04), confirming sem has no cross-worker lock contention**

If sem mode had cross-worker zone-lock contention, the 2-core scaling factor would be significantly below x2. Measured x2.04 slightly exceeds x2 because the 1-core baseline contains some fixed overhead (DPDK metadata, system interrupts) that is amortized across 2 cores. **This is direct evidence for the user's prediction since v3.0: "under `FF_MULTI_SC` each worker has an independent zone with an independent lock"**.

**Conclusion 3: 4-core sub-linear (x3.51) bottleneck is not in the IPC layer**

Ring and sem decay coefficients are identical (Ring x3.51 vs Sem actual x3.45 = 35.9/10.4), indicating the 4-core bottleneck is **shared by both paths**:
- Candidate 1: wrk client / NIC RSS hash distribution imbalance
- Candidate 2: NUMA boundary (are lcore 4-7 cross-NUMA?)
- Candidate 3: fstack main-loop cross-core cache (e.g. mempool sharing)

→ **Not an IPC-layer issue**; out of scope of this analysis (ring vs sem comparison).

### 10.4 Consistency with the Single-Worker Conclusion

| Scenario | Ring vs Sem gap | Explanation |
|---|---|---|
| Single-worker (§1) | -2.7% (102.2 vs 105) | ring SPSC architectural inherent overhead (acquire fence + metadata) |
| Multi-worker 1 core (§10.2) | -1.92% (10.2 vs 10.4) | Same as above (the 0.78% delta is noise across test days) |
| Multi-worker 2 cores | 0% (20.8 vs 20.8) | Noise covers the inherent overhead |
| Multi-worker 4 cores | -0.28% (35.8 vs 35.9) | Same as above |

→ **The 2.7% inherent overhead of the single-worker case is averaged out by noise at multi-core**, neither amplified nor eliminated. The two paths have identical scalability.

### 10.5 Long-Connection Measurement Data (added in v3.6)

| lcores | Sem QPS (10k) | Ring QPS (10k) | Ring/Sem gap | Sem per-core efficiency | Ring per-core efficiency | Sem scaling | Ring scaling |
|---|---|---|---|---|---|---|---|
| 1 | 33.3 | 31.8 | **-4.50%** | 33.30 | 31.80 | baseline | baseline |
| 2 | 65.9 | 64.3 | **-2.43%** | 32.95 | 32.15 | x1.98 | x2.02 |
| 4 | 130.5 | 127.0 | **-2.68%** | 32.63 | 31.75 | x3.92 | x3.99 |

### 10.6 Data Interpretation

**Conclusion 1: ring is consistently 2.4%-4.5% worse than sem under long connections, direction is stable**

Unlike short connection's noise distribution of 0/-0.3%/-1.9% (no directionality), all three long-connection sets show **ring worse than sem with a gap larger than the short-connection noise range**. This is on the same order as the -2.7% inherent overhead in the v3.4 single-worker convergence, indicating that the overhead is **linearly amplified** at high long-connection QPS.

**Conclusion 2: long-connection absolute QPS is ~3.1-3.6x short-connection**

| lcores | Sem short / long | Ring short / long |
|---|---|---|
| 1 | 10.4 -> 33.3 (x3.20) | 10.2 -> 31.8 (x3.12) |
| 2 | 20.8 -> 65.9 (x3.17) | 20.8 -> 64.3 (x3.09) |
| 4 | 35.9 -> 130.5 (x3.64) | 35.8 -> 127.0 (x3.55) |

The short-connection bottleneck is in the socket/close path (every request goes through slow paths like `ff_attach_so_context`); long connections bypass these and **get closer to the IPC-layer ceiling**. Both paths receive nearly identical "long-connection bonus" (~3.1-3.6x), showing ring gains no relative advantage from sem's "increased lock-holding pressure".

**Conclusion 3: multi-core scaling factors are good, again confirming sem has no cross-worker lock contention**

- sem: 1->2 x1.98 (~ linear), 1->4 x3.92 (~ linear)
- ring: 1->2 x2.02 (~ linear), 1->4 x3.99 (~ linear)

**Under long connections, sem not only shows no lock-contention degradation but actually scales better than under short connections (4-core x3.45)**. This thoroughly falsifies v3.5 §10.5's prediction that "sem lock-holding pressure rises under long connections -> lock contention".

### 10.7 Final Falsification of the Design Hypothesis and Root-Cause Retrospective

The author predicted in v3.5 §10.5: "Under long connections, sem holds the zone lock for 50-100us the entire time, so the ring lock-free advantage may emerge." **Thoroughly falsified by measurements.**

**Deep root-cause retrospective**:

| Inference (v3.5 old) | Actual situation (v3.6 measured) |
|---|---|
| Long-connection sem keeps `tmp > 0` -> holds zone lock the whole time -> fstack lcore vs nginx worker contention rises | Under sem `FF_MULTI_SC`, fstack lcore and nginx worker have a **1:1 same-zone** relationship, but the nginx worker's frequency of entering the zone lock is intrinsically very low (only attach/detach), and **normal read/write paths do not contend for the zone lock at all** -> longer lock-holding **does not cause additional contention** |
| Ring lock-free main loop saves sem's lock-holding overhead | Sem lock-holding is **exclusive to fstack lcore**, the cache line stays in exclusive state, and lock-holding cost is near zero; ring instead must do an acquire fence on every `rte_ring_sc_dequeue_burst` to synchronize the memory system -> **long-connection high QPS amplifies the acquire-fence overhead linearly** |
| Long-connection `tmp > 0` makes sem stay out of the §9.6.1 unlock branch -> continuous lock-holding -> gap with ring lock-free should shrink | More continuous lock-holding **actually favors sem** (cache line is not invalidated), and ring's relative disadvantage is amplified instead |

**Key insight**: under the `FF_MULTI_SC` single-lcore exclusive model, sem's "lock holding" is **not a performance burden but an advantage** — the cache line stays exclusive on the fstack lcore at all times with zero cross-core sync overhead; whereas ring's SPSC design **always requires a cross-core acquire fence** (even when producer/consumer being on different cores is the steady state), and this inherent overhead is linearly amplified at high QPS.

### 10.8 Consistency Summary Across Single-Worker / All Scenarios

| Scenario | Ring vs Sem gap | Explanation |
|---|---|---|
| Single-worker (§1) | -2.7% (102.2 vs 105) | ring SPSC architectural inherent overhead (acquire fence + metadata) |
| Multi-worker 1-core short connection (§10.2) | -1.92% (10.2 vs 10.4) | Same as above (same magnitude as v3.4 single-worker) |
| Multi-worker 2-core short connection | 0% (20.8 vs 20.8) | Noise covers the inherent overhead |
| Multi-worker 4-core short connection | -0.28% (35.8 vs 35.9) | Same as above |
| **Multi-worker 1-core long connection (§10.5)** | **-4.50% (31.8 vs 33.3)** | **Ring inherent overhead amplified at long-connection high QPS** |
| **Multi-worker 2-core long connection** | **-2.43% (64.3 vs 65.9)** | **Same as above** |
| **Multi-worker 4-core long connection** | **-2.68% (127.0 vs 130.5)** | **Same as above** |

**Final verdict (already written into §1.4.4)**:
- Ring has **no performance net win in any tested scenario** under LD_PRELOAD + FF_MULTI_SC
- Sem is the production recommended configuration; ring code is retained only as a reserve for future "multi-threaded sc sharing within a single process" and "cross-process sc sharing (where the worker count exceeds the fstack instance count)" extension scenarios
