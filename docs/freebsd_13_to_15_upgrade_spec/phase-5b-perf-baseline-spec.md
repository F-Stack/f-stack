# Phase-5b Perf Baseline Spec — F-Stack v1.26 / FreeBSD 15.0 (Phase-2 Feature Matrix)

> Chinese version: ./zh_cn/phase-5b-perf-baseline-spec.md (authoritative)

**Author**: Phase-5b Leader
**Date**: 2026-06-08
**Predecessor**: Phase-2 M6~M13 + M-Final (commit `99cc538cd`, ahead 22)
**Methodology base**: `06-test-and-acceptance-spec.md §5` NFR-1 framework + `cvm-bench-methodology.md`
**Status**: ACTIVE

---

## 1. Goal

Establish a **cross-config relative perf-delta matrix** for Phase-2's 8 enabled feature flags (M6~M13). Specifically close the two recorded follow-ups:

- **M9-F1**: PA+ZC combo 3.5× slower at 1000 short conns (vs. M8 ZC-only) — needs root-cause analysis or expected-behavior classification.
- **M10-F2**: IPIP tunnel heavy-traffic throughput baseline not done — substituted with a ping-RTT timing baseline due to client-tool limits.

**Non-goals**:
- Absolute QPS / throughput numbers (the client only has `curl`; no wrk/iperf3/ab; the canonical NFR-1 numbers were already PASSed in M5).
- Re-measuring the 13.0 baseline (already dual-baselined in M5).
- Physical-machine + CVM dual baseline (environment-limited).

---

## 2. Environmental Constraints (recorded as-is, never bypassed)

| Dimension | State |
|---|---|
| Server NIC | 1× virtio `0000:00:09.0` (also carries SSH transport) |
| Hugepages | configured (M6~M13 measured working) |
| DPDK binding | igb_uio loaded |
| Client OS | Linux (Ubuntu/Debian family per `uname -a`) |
| Client load tool | **`curl` only** (no iperf3/wrk/ab/httping) |
| Link | server-client same VPC, ping RTT < 1 ms |
| ssh round-trip | ≈ 6-7 ms (measured earlier; the bottleneck for 100/1000 serial curls) |

**No new tools installed**: respect OQ-1 (the client user is independently maintained).

---

## 3. Methodology

### 3.1 Trial unit (reusable harness)

`tools/sbin/p5b_perf_matrix.sh` implements **single trial = N serial curls from f-stack-client**:

```
T_total = $(ssh f-stack-client "time (for i in 1..N; do curl ... ; done)")
QPS_eff = N / T_total      # includes ssh round-trip; only meaningful as cross-config delta
fail_rate = (N - http_200_count) / N
```

Each config runs **3 trials**; we take **median(T_total)** + **max-min jitter** to dampen single-shot noise.

### 3.2 Matrix dimensions

| Config | lib/Makefile flags |
|---|---|
| **C0 BASELINE** | P0 only: FF_NETGRAPH+FF_IPFW (restore the minimal set with no P1/P2, but keep LOOPBACK=1 since the `ff_swi_net_excute` stub already landed) |
| **C7 M7** | C0 + FF_USE_PAGE_ARRAY=1 |
| **C8 M8** | C0 + FF_ZC_SEND=1 |
| **C9 M9** | C0 + FF_USE_PAGE_ARRAY=1 + FF_ZC_SEND=1 |
| **C10 M10** | C0 + FF_FLOW_IPIP=1 (used for tunnel ping-RTT timing + direct-path HTTP control) |

The P2 trio (M11/M12/M13) is smoke-only and **does not enter the perf matrix** (rte_flow has no effect on virtio).

### 3.3 Test cases (per config)

| TC | Description | Expected |
|---|---|---|
| **TC1** | 100 serial curls of `/` (short conn) | pass_rate = 100% / cross-config delta < 30% |
| **TC2** | 1000 serial curls of `/` (short conn) | pass_rate ≥ 99% / config-to-config ratio quantifies M9-F1 |
| **TC3 (C10 only)** | 100 pings of `10.10.10.1` inside the tunnel (IPIP inner IP) | 0% loss / median RTT ≤ 2 ms |

### 3.4 Acceptance downgrade (per master-plan OQ-2 + OQ-4)

- **observation-only**: every measurement is recorded but is not a PASS/FAIL gate.
- **Sole hard fail**: primary process SIGSEGV / panic / pass_rate < 90%.
- bounces ≤ 3 / milestone (same standard as Phase-2).

---

## 4. 5-Phase Pipeline

| Phase | Output |
|---|---|
| A. Spec | this document |
| B. Research | folded into §2 + §3 (env constraints + reusing the Phase-2 toolchain) |
| C. Code | `tools/sbin/p5b_perf_matrix.sh` |
| D. Run | 5 configs × 3 trials × 2 TCs + 1 IPIP-tunnel TC = 33 runs; total ETA ≤ 25 min |
| E. Gate | author `phase-5b-perf-baseline-report.md` (matrix CSV + delta table + 4 RCA items) |

---

## 5. Decision Points

After Phase-5b finishes, we must answer:

- **D1 M9-F1 disposition**: is 3.5× expected (PA mmap + ZC fast-path amplifies short-conn context-switch overhead) or a regression (need code fix)? Or is it only amplified by the small-traffic + ssh-round-trip-dominated regime?
- **D2 M10-F2 closure rationale**: a stable ping-RTT sequence counts as the IPIP software path baseline PASS.
- **D3 production default**: post M-Final, which flags should be on by default (P0 must-on + P1/P2 awaits user decision)?

---

## 6. Compliance

- `rm_tmp_file.sh` / `kill_process.sh` / `chmod_modify.sh` throughout
- liveness check via `[ -d /proc/$PID ]`, never `kill -0`
- Local commit only (no push, continuing the Phase-2 mandate)
- Commit message in English

---

> Entering Phase C: implement `p5b_perf_matrix.sh`.
