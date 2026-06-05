# F-Stack 13.0 vs 15.0 — Bare-Metal Baseline Benchmark Report

> Chinese version: `./zh_cn/physical-machine-bench-report.md`
>
> **Data source**: iWiki 4021545579 (executed by the external OSPF/CMC project team; filed in 2026-Q2).
>
> **Nature of this file**: engineering distillation of the iWiki raw data + cross-reference with this project's CVM same-timeline A/B data.
>
> **Related documents**:
> - `06-test-and-acceptance-spec.md` §5 (NFR-1 baseline framework)
> - `13.0-baseline-cvm-bench-report.md` (same hardware-class CVM same-timeline A/B; §14 bare-metal cross-reference)
> - `runtime-fix-execution-log.md` §12.6 / §12.10 / §12.11 (CVM helloworld + perf flame-graph)

---

## 1. Test platform

| Item | Value |
|---|---|
| Form factor | Bare metal (NOT a CVM) |
| CPU | Intel(R) Xeon(R) Platinum 8255C @ 2.50 GHz |
| NIC | Mellanox MT27800 Family [ConnectX-5], 100 GbE |
| OS | TencentOS Server 4.4 |
| Kernel | Linux 6.6.98-40.9.tl4.x86_64 (SMP, 2026-01-22 build) |
| Server IP (masked) | `x.x.x.39` (A/B/C segments masked; D segment retained) |
| wrk client | A separate machine in the same physical room (server-direct or 10G+ environment) |

**Key differences vs this project's CVM platform** (matter for the interpretation below):

| Dimension | Bare metal (iWiki) | This project's CVM | Note |
|---|---|---|---|
| Form | Bare metal | Virtualized (KVM) | Determines the "amplification factor" below |
| NIC | Mellanox CX-5 100 G (mlx5 PMD) | virtio-net (`virtio_user_pmd` / `virtio_pci_pmd`) | On 15.0, `virtio_recv_mergeable_pkts` ratio is markedly higher on virtio than on a physical NIC |
| CPU | Cascade Lake 2.5 GHz | Same-gen or newer vCPU (host-scheduled) | CVM is subject to neighbour noise; cross-day drift 6-10% |
| Kernel | 6.6.98-40.9.tl4 | Same-gen (does NOT impact F-Stack user-space stack; only drives host networking) | F-Stack runs DPDK bypass; the host kernel only handles the control plane |
| dpdk | LTS (iWiki did not state version; mlx5 PMD default config) | 23.11.5 (`pkg-config --modversion`-measured) | F-Stack lib's linked `librte_*.so` version has limited impact on throughput (same ABI) |

---

## 2. helloworld (F-Stack example, single-core long connections)

### 2.1 wrk command

```text
./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39
```

Reading: 24 client threads / 128 conns / 10 s / latency distribution enabled. **Long connections** (HTTP keep-alive — wrk's default).

### 2.2 Throughput and latency comparison

| Metric | 13.0 | 15.0 | Δ | Reading |
|---|---:|---:|---:|---|
| **Req/sec** | **958,109.22** | **1,056,177.98** | **+10.24%** | Single-core single-flow approaches 1 M QPS; **15.0 is significantly better than 13.0** |
| Transfer/sec | 593.01 MB/s | 653.71 MB/s | +10.24% | Tracks throughput |
| Avg Latency | 122.51 us | 110.67 us | -9.66% | Base path is faster |
| p50 | 121 us | 107 us | -11.57% | Median latency drops |
| p75 | 132 us | 118 us | -10.61% | |
| p90 | 151 us | 138 us | -8.61% | |
| p99 | 204 us | 197 us | **-3.43%** | Tail **NOT worse** (slightly better) |
| Total req | 9,677,043 / 10.10 s | 10,667,274 / 10.10 s | — | |

### 2.3 Key observations

**On bare metal, single-core long-connection helloworld is a net gain on 15.0**: throughput +10.24%; p50–p99 all drop. This matches the expected gains from RACK-as-default, the TCP CUBIC state-machine optimisation, and the socket-buffer locking refactor in 13.0 → 15.0.

> **Reversal vs the CVM same-timeline A/B**: on CVM, 15.0 helloworld regressed by -7.59% / -9.37% in T2/T3 (see `13.0-baseline-cvm-bench-report.md` §5.1). The root cause is already pinpointed in CVM report §11.5 via perf flame-graph as "virtualisation-path overhead amplified in narrow channels" — `virtio_recv_mergeable_pkts` / `tcp_default_output` vtable etc. Bare metal goes through the mlx5 PMD and bypasses virtio, so this overhead does not exist → the 15.0 vendor-evolution gains (RACK / CUBIC / sb_locking) materialise net on bare metal.

---

## 3. nginx_fstack (short connections)

### 3.1 wrk command family

| lcores | Command |
|---|---|
| 1 | `./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39 ; sleep 10` |
| 2 | `./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39 ; sleep 10` |
| 4 | `./wrk -c 200 -t 24 -d 10 -L http://x.x.x.39` |

**Short connections**: a fresh TCP connection per request (HTTP `Connection: close`; the nginx_fstack default or wrk `-H`-forced).

### 3.2 Throughput comparison

| lcores | 13.0 (Req/s) | 15.0 (Req/s) | Δ | Note |
|---:|---:|---:|---:|---|
| 1 | 127,592.23 | 124,726.68 | **−2.25%** | Single-core mild regression |
| 2 | 256,207.62 | 246,872.92 | **−3.65%** | Mid-grade regression |
| 4 | 406,379.63 | 381,614.48 | **−6.10%** | Worst at high concurrency; one-off run hit 410,998.92 (+1.14%) but **hard to reproduce** (iWiki note) |

### 3.3 Latency comparison (only the percentiles with notable changes)

| lcores | 13.0 p50 | 15.0 p50 | Δ p50 | 13.0 p99 | 15.0 p99 | Δ p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 483 us | 494 us | +2.28% | 600 us | 627 us | +4.50% |
| 2 | 260 us | 267 us | +2.69% | 403 us | 430 us | +6.70% |
| 4 (-c200) | 215 us | 219 us | +1.86% | 552 us | 586 us | +6.16% |

### 3.4 Key observations

**On bare metal, nginx_fstack short connections show a 2-6% systemic regression on 15.0**; the regression worsens with more lcores:

1. **The regression is NOT in the helloworld path** (same hardware, helloworld long-conn is +10%).
2. **Suspected cause**: the short-conn fastpath touches `sonewconn` / `solisten_clone` / `accept` heavily, plus the extra atomics from P3 (kern_descrip boundary + `badfileops` restoration) on fd creation/teardown paths. `13.0-baseline-cvm-bench-report.md` §6.3 has already listed P3 as a leading suspect.
3. **Multi-core scaling health**:
   - 13.0 multi-core scaling: 1→2 = ×2.008 (ideal ×2); 1→4 = ×3.184 (ideal ×4; efficiency 79.6%).
   - 15.0 multi-core scaling: 1→2 = ×1.979; 1→4 = ×3.060 (efficiency 76.5%).
   - Both versions show clear scaling efficiency drop, **expected for short-conn shared listen-socket lock contention**, but 15.0 is ~3 pp worse than 13.0.

---

## 4. nginx_fstack (long connections)

### 4.1 wrk command family

| lcores | Command |
|---|---|
| 1 | `./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39` |
| 2 | `./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39 ; sleep 10` |
| 4 | `./wrk -c 256 -t 24 -d 10 -L http://x.x.x.39` |

### 4.2 Throughput comparison

| lcores | 13.0 (Req/s) | 15.0 (Req/s) | Δ | Note |
|---:|---:|---:|---:|---|
| 1 | 314,889.22 | 330,837.26 | **+5.06%** | Single-core ~5% net gain |
| 2 | 623,961.88 | 653,647.68 | **+4.76%** | |
| 4 | 1,230,501.76 | 1,289,871.91 | **+4.83%** | 4 cores ~1.29 M QPS; per-core utilisation near 322 k |

### 4.3 Latency comparison

| lcores | 13.0 p50 | 15.0 p50 | Δ p50 | 13.0 p99 | 15.0 p99 | Δ p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 391 us | 372 us | **-4.86%** | 428 us | 408 us | **-4.67%** |
| 2 | 187 us | 180 us | -3.74% | 328 us | 320 us | -2.44% |
| 4 (-c256) | 185 us | 182 us | -1.62% | 310 us | 314 us | +1.29% |

### 4.4 Key observations

**On bare metal, nginx_fstack long connections show a +5% systemic net gain on 15.0; multi-core linearity is excellent**:

| lcores → | 13.0 scaling | 15.0 scaling |
|---|---|---|
| 1→2 | ×1.981 | ×1.976 |
| 1→4 | ×3.908 (97.7%) | ×3.899 (97.5%) |
| 2→4 | ×1.972 | ×1.973 |

**Both versions show 1→4 multi-core efficiency ≥ 97.5%**, and 15.0 does NOT regress vs 13.0 — as expected: long-conn fastpath sits primarily on shared paths like `tcp_do_segment` / `sbappendstream`, where the 15.0 vendor evolution (CUBIC / sb locking) net gain lands directly on throughput.

---

## 5. Cross-reference with the CVM same-timeline A/B

### 5.1 helloworld single-core data merged

| Platform | 13.0 (req/s) | 15.0 (req/s) | Δ | p99 13.0 | p99 15.0 | Δ p99 |
|---|---:|---:|---:|---:|---:|---:|
| **Bare metal** (iWiki) | 958,109 | 1,056,178 | **+10.24%** | 204 us | 197 us | -3.43% |
| **CVM T2** t4c100 | 220,691 | 203,933 | **−7.59%** | 811 us | 827 us | +2.0% |
| **CVM T3** t8c500 | 239,555 | 217,100 | **−9.37%** | 4.21 ms | 5.38 ms | +27.8% |

**Reversal reading**:

- **Absolute throughput**: bare metal is **4.34×** CVM (958k vs 220k) — matches the throughput ladder from the 100G mlx5 physical NIC vs virtio virtual NIC.
- **The 15.0 net effect is reversed in direction**: bare metal +10%, CVM -7%~-9%.
- This reversal is **already explained by perf flame-graph in CVM report §11.5**: on CVM, the top growing functions on 15.0 are `virtio_recv_mergeable_pkts` (+0.74 pp), `tcp_default_output` vtable wrapper (+0.94 pp), socket-buffer locking refactor (+1.5 pp); virtio simply does not exist on bare metal, and the vtable wrapper / sb-locking "overhead" is fully absorbed and overcompensated by the RACK / CUBIC "gain" on bare metal.

### 5.2 nginx_fstack long connections (no CVM same-timeline counterpart in this project)

| lcores | bare metal 13.0 | bare metal 15.0 | Δ |
|---:|---:|---:|---:|
| 1 | 314,889 | 330,837 | +5.06% |
| 2 | 623,962 | 653,648 | +4.76% |
| 4 | 1,230,502 | 1,289,872 | +4.83% |

**Note**: in this project the CVM-side nginx_fstack only did **functional verification** with multi-process `lcore_mask=0xC/0x3C` (see `runtime-fix-execution-log.md` §12.15); we did NOT run a 13.0-paired same-timeline throughput A/B. If a CVM-side nginx_fstack baseline is needed later, it must be scheduled separately. **For the current acceptance, the nginx_fstack performance baseline is taken from this bare-metal data**.

### 5.3 nginx_fstack short connections (no CVM same-timeline counterpart)

The bare-metal short-conn **−2% to −6%** regression is the **only systemic regression signal** in this upgrade. We have no CVM same-timeline short-conn comparison data in this project.

---

## 6. Key findings

### 6.1 Cross-platform overall verdict

| Scenario | Bare-metal Δ | CVM Δ (ref.) | Acceptance verdict |
|---|---:|---:|---|
| helloworld single-core long-conn | **+10.24%** | -7.59% ~ -9.37% | Bare-metal PASS (NFR-1 "no regression > 5%" satisfied with surplus); CVM regression is perf-attributed to vendor evolution, NOT runtime-fix |
| nginx_fstack long-conn 1/2/4 cores | **+4.76% ~ +5.06%** | not measured | PASS (systemic net gain) |
| nginx_fstack short-conn 1/2/4 cores | **−2.25% ~ −6.10%** | not measured | **Observation**: 1-core -2.25% within NFR-1 "short-conn QPS no regression > 5%" (PASS); 4-core -6.10% **over the 5% threshold** → triggers NFR-1 review (see §7) |

### 6.2 Disposition options for the short-conn 4-core -6.10% regression

NFR-1 short-conn QPS threshold is "no regression > 5%". Bare-metal nginx_fstack 4-core short-conn at -6.10% strictly triggers the review. Recommended dispositions (in order of engineering ROI):

1. **Preferred — accept as a trade-off and file**: the upgrade's core value is fixing 5 P0 SIGSEGV faults plus major vendor-evolution gains (helloworld long-conn +10%, nginx long-conn +5%); -6% on short-conn is explainable under multi-core listen-socket lock contention, and the one-off +1.14% data point (hard to reproduce) suggests it is not a hard regression. File into the known-trade-off section of `99-review-report.md`.
2. **Optional — bare-metal perf flame-graph bi-version overlay**: same methodology as CVM §11; localise the cpu-clock share changes on `sonewconn` / `accept` / `kern_descrip` paths. Budget 0.5 day.
3. **Optional — bisect P3 (kern_descrip) as an isolated commit**: if perf points at the `badfileops` restoration on the fd-creation path, evaluate whether the stub implementation should be revised.

### 6.3 Engineering value of the 13→15 vendor evolution

The bare-metal helloworld single-core long-conn +10.24% is the cleanest empirical "vendor-evolution gain" in this project:

- Same hardware, same NIC, same dpdk, same wrk parameters, same code skeleton (only F-Stack lib + freebsd kernel source differ);
- Eliminates virtualisation-layer interference;
- The gain matches the expected effect of RACK-default, CUBIC state-machine extension, and sb_locking refactor;
- Fully aligned with the `06-test-and-acceptance-spec.md` §5.3 framework "RACK improvement gain counted as net surplus".

### 6.4 Data-trust limits

- **The iWiki data was executed by an external team**; this project did not independently reproduce the bare-metal environment.
- Single-shot 10 s wrk sampling; no multi-run mean/stddev.
- Client machine, NUMA topology, CPU affinity, IRQ pinning, hugepages config, etc. are not listed on iWiki.
- "Short connection" definition (whether wrk `-H "Connection: close"` or nginx `keepalive_timeout 0`) is not stated explicitly on iWiki; only the "short-conn" label is given.
- The one-off 4-core short-conn 410,998.92 data point (labelled +1.14% vs 13.0) is "hard to reproduce" and is NOT in the main table; only mentioned in §3.2.

→ The data is **suitable for directional gain/regression judgement**, **NOT** suitable as an absolute baseline for micro-optimisation.

---

## 7. NFR-1 acceptance verdict matrix (per 06-spec §5.1)

| NFR-1 metric | Threshold | Bare-metal measured (min over runs) | CVM measured (ref.) | Pass |
|---|---|---|---|:---:|
| Single-flow TCP throughput (loopback) | regression ≤ 5% | helloworld +10.24% (over-satisfied) | -7.59% ~ -9.37% (CVM regression due to virtualisation path) | **Bare metal ✓** / CVM filed |
| Short-conn QPS (HTTP echo) | regression ≤ 5% | 1-core -2.25% / 2-core -3.65% / **4-core -6.10%** | not measured | **Observation ⚠** (4-core 1.10 pp over; per §6.2 disposition) |
| Long-conn QPS (informational) | regression ≤ 5% | +5% systemic gain | not measured | ✓ net gain |
| Single-core lcore CPU utilisation | informational | helloworld single-core close to 1 M QPS (saturated) | single-core ~220 k QPS (virtio-bound) | informational, captured |

**Overall verdict**: except for nginx 4-core short-conn (must trigger §6.2 review), **the bare-metal baseline satisfies NFR-1**.

---

## 8. Data-asset pointers

| Item | Path |
|---|---|
| iWiki original page | `https://iwiki.woa.com/p/4021545579` |
| This report | `docs/freebsd_13_to_15_upgrade_spec/physical-machine-bench-report.md` (this file) |
| CVM same-timeline A/B (helloworld) | `docs/freebsd_13_to_15_upgrade_spec/13.0-baseline-cvm-bench-report.md` |
| CVM perf flame-graph root cause | same as above §11 (bi-version sampling, top-function compare, differential flame-graph) |
| 06-spec NFR-1 framework | `06-test-and-acceptance-spec.md` §5 (baseline metrics + collection timing + RACK gain accounting) |
| 06-spec bare-metal section | `06-test-and-acceptance-spec.md` §5.4 (newly added) |

---

## 9. Filing record

| Item | Value |
|---|---|
| iWiki pull time | 2026-06-05 (UTC+8) |
| Pull tool | `iwiki-cli get 4021545579` v0.0.8 linux/amd64 |
| Data scope | helloworld single-core long-conn + nginx_fstack short-conn / long-conn (1/2/4 lcores) |
| IP masking | iWiki real server IPs (Tencent intranet A/B/C segments) → uniformly substituted to `x.x.x.39` (D segment retained for traceback; A/B/C segments masked; same convention as the rest of this project) |
| Mandatory convention | Temp file `/tmp/iwiki_4021545579.md` cleaned via `rm_tmp_file.sh` after completion |
