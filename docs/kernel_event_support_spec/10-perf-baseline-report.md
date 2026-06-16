# 10 Performance-Baseline Report (v3, SUPERSEDED)

> **⚠️ SUPERSEDED (v4, 2026-06-16)**: this report is based on the v3 **wrong
> implementation** — `ff_socket(SOCK_KERNEL)` → `ff_host_socket` → a raw host
> socket that **never ran the F-Stack user-space stack** (both A/B variants were
> pure kernel stack). That methodology did not measure "F-Stack + kernel-stack
> coexistence" at all; the conclusions are invalid and the whole report is
> superseded.
> The v4 performance baseline instead **proves that kernel-stack coexistence
> does not slow the F-Stack business fast path** (PERF-1/PERF-2, see
> `07-test-spec.md`), to be re-produced in R4 by comparing the F-Stack business
> under coexistence on/off; this document is kept for historical record only.

---

# 10 Performance-Baseline Report: Kernel-Access Path (ff_socket(SOCK_KERNEL)) wrk Self-Stress Baseline (v3 historical record)

> **Document ID**: SPEC-KE-10 (v3 historical record)
> **Date**: 2026-06-16
> **Status**: SUPERSEDED (see the notice above)
> **Scope**: On the **local host loopback**, use wrk to establish a performance baseline for the "local socket/fd/event access" feature (the `ff_socket(SOCK_KERNEL)` kernel-stack path), and use a same-source native `libc socket()` version for an A/B comparison to derive the overhead Δ%, with the existing CVM data in `freebsd_13_to_15_upgrade_spec/` as a background reference.
> **Evidence iron rule**: all numbers come from actual wrk runs (raw output `/tmp/keperf/{A,B}_T{1,2,3}_trial{1,2,3}.txt`); fabrication is forbidden.

---

## 1. Test Purpose

Quantify whether the "kernel-access feature" introduces throughput/latency overhead on the **data plane**. The core of this feature is selecting the stack by marker at socket creation (`ff_socket(...,SOCK_KERNEL)` → `ff_host_socket` → host `socket()`), after which `bind/listen/accept/recv/send/epoll` go through the same kernel-fd path. Therefore, theoretically the A/B difference is **only one `ff_socket→ff_host_socket` function jump per connection at connect time**, and should be zero extra overhead on the data plane of keep-alive long connections. This test empirically validates that judgment.

---

## 2. Environment

| Item | Value |
|---|---|
| Host | a single CVM, 16 vCPU, 31 GiB |
| Stress tool | wrk **4.2.0 [epoll]** (built locally from GitHub `wg/wrk` source, `/tmp/wrk-build/wrk`; no wrk package in the system repo) |
| Target | `example/helloworld_stacksel`, **single-thread epoll keep-alive HTTP server** (`bench <port>` mode) |
| Protocol | HTTP/1.1, `Connection: keep-alive`, fixed 15B response body (benchmarked against the freebsd-upgrade CVM helloworld scenario) |
| Link | **loopback 127.0.0.1** (server and wrk on the same host; server bound to CPU0, wrk bound to CPU2-15, `taskset` to reduce contention) |
| Build | A/B both `-O2 -g`, same-source `main.c`, both link `lib/libfstack.a` |

### 2.1 A/B Two Versions (same source, only `ksock()` differs)
| Version | Build | socket creation | Meaning |
|---|---|---|---|
| **A** `helloworld_stacksel_ffk` | `-DUSE_FF_KERNEL=1` | `ff_socket(AF_INET, SOCK_STREAM\|SOCK_KERNEL, 0)` | this feature's kernel-access path |
| **B** `helloworld_stacksel_libc` | `-DUSE_FF_KERNEL=0` | `socket(AF_INET, SOCK_STREAM, 0)` | pure kernel-stack reference |

---

## 3. Method (aligned with the existing CVM methodology tiers)

| Tier | wrk parameters | Duration | Purpose |
|---|---|---|---|
| T1 | `-t2 -c10  --latency` | 5s | light load + warmup discard |
| T2 | `-t4 -c100 --latency` | 30s | medium-load main regression |
| T3 | `-t8 -c500 --latency` | 30s | high-concurrency tail latency |

- Each tier **takes the median of 3 trials**; each version is preceded by one 3s warmup (discarded).
- Command template: `taskset -c 2-15 /tmp/wrk-build/wrk -t4 -c100 -d30s --latency http://127.0.0.1:<port>/`
- Server start/stop via `/data/workspace/kill_process.sh`; script `/tmp/keperf/runbench.sh`.

---

## 4. Measured Results (median of 3 trials; raw output see `/tmp/keperf/`)

### 4.1 Throughput req/s

| Tier | A `SOCK_KERNEL` | B `libc socket` | Δ (A vs B) | Three trials (A / B) |
|---|---:|---:|---:|---|
| T1 (-t2 -c10 5s)   | 120,949 | 136,199 | **−11.2%** | A 119822/132566/120949 · B 137667/136199/118075 |
| T2 (-t4 -c100 30s) | 125,169 | 119,498 | **+4.7%**  | A 125169/113753/135646 · B 119498/135067/118084 |
| T3 (-t8 -c500 30s) | 107,298 | 112,728 | **−4.8%**  | A 102829/115724/107298 · B 114646/105920/112728 |

### 4.2 Latency (median of 3 trials)

| Tier | A p50 | B p50 | A p99 | B p99 |
|---|---:|---:|---:|---:|
| T1 | 67us  | 60us  | 151us  | 133us  |
| T2 | 767us | 814us | 1.04ms | 1.15ms |
| T3 | 4.58ms| 4.37ms| 5.25ms | 5.11ms |

- **Socket errors: 0** (all 18 trials had no connect/read/write/timeout errors).

### 4.3 Conclusion (A/B)

**The throughput/latency difference between A and B is within the ±11% inter-trial noise range, with no systematic direction** (A is slightly faster at T2, slightly slower at T1/T3, and the trial intervals overlap heavily). This is consistent with theory: `ff_socket(SOCK_KERNEL)` only has one extra `ff_host_socket` function jump over `libc socket()` **at connect time**, with zero extra overhead on the keep-alive data plane.

→ **The kernel-access feature introduces no measurable data-plane performance regression** (corroborating NFR-1 zero-overhead / NFR-2 no regression on the business fast path). The main cause of fluctuation: under loopback self-stress, the server and wrk contend for the same host CPU/soft interrupts (the measured `sys` time ratio is extremely high), which is measurement noise rather than feature overhead.

---

## 5. Background Reference: the Existing freebsd_13_to_15 CVM Data (different methodology, reference only)

Source `docs/freebsd_13_to_15_upgrade_spec/zh_cn/13.0-baseline-cvm-bench-report.md` (**dual CVM, server runs DPDK + F-Stack user-space stack, the same wrk three tiers**):

| Tier | 13.0 baseline req/s | 15.0 rfix req/s | This report A (kernel stack loopback) |
|---|---:|---:|---:|
| T1 | 24,414 | 23,757 | 120,949 |
| T2 | 220,691 | 203,933 | 125,169 |
| T3 | 239,555 | 217,100 | 107,298 |

**Methodology differences (cannot be equated directly; please note)**:
1. **Different stacks**: the CVM data is the data-plane throughput of the **F-Stack user-space stack via the DPDK NIC**; this report is the throughput of the **Linux kernel stack + loopback** — the two measure different paths of different protocol stacks.
2. **Different topology**: CVM is **real send/receive between two hosts' NICs**; this report is **single-host loopback self-stress** (the server and wrk contend for the same set of CPUs).
3. **Different concurrency model**: CVM helloworld is F-Stack `lcore=4`; this report is **single-thread epoll** (the user has confirmed "the single-thread number only reflects the serial lower bound").
4. T1 fluctuates a lot on both sides (5s short window); it is used only for link liveness, not for the conclusion.

**Usage note**: this feature **adds** a "kernel-stack-accessible" channel outside F-Stack (for local ping/curl and a client connecting to local/external kernel services); it **does not replace** the F-Stack business data plane. The CVM data is used to indicate the throughput-magnitude background of the F-Stack business plane; this feature's overhead is given by the §4 same-environment A/B comparison (≈noise, no regression).

---

## 6. Limitations and Follow-ups

- This baseline is a **local-host loopback single-thread** self-stress, reflecting the "serial/single-loop lower bound", **not** the server's true limit, nor the dual-CVM DPDK data plane; absolute values are comparable only within the same methodology.
- The hook-mode end-to-end on a real physical machine/dual CVM and the coexistence throughput of the F-Stack business plane + the kernel management plane await an environment with a DPDK-bound physical NIC, to be supplemented per `cvm-bench-methodology.md` (following the `freebsd_13_to_15` F-A3/F-A4 path).
- For a higher single-host throughput baseline, multi-thread `SO_REUSEPORT` can be enabled (this round keeps single-thread per the user's request).

---

## 7. Reproduction Steps

```bash
# 1) Build wrk (build from source when the system has no package)
git clone --depth 1 https://github.com/wg/wrk.git /tmp/wrk-build && make -C /tmp/wrk-build -j4

# 2) Build the A/B target binaries
cd /data/workspace/f-stack/example/helloworld_stacksel && make bench
#   -> helloworld_stacksel_ffk (SOCK_KERNEL) / helloworld_stacksel_libc (libc)

# 3) Three-tier self-stress (server bound to CPU0, wrk bound to CPU2-15, 3 trials each)
bash /tmp/keperf/runbench.sh A helloworld_stacksel_ffk  18211
bash /tmp/keperf/runbench.sh B helloworld_stacksel_libc 18212
#   raw output: /tmp/keperf/{A,B}_T{1,2,3}_trial{1,2,3}.txt
```

> Compliance: wrk processes are stopped via `kill_process.sh`, temporary files are cleaned via `rm_tmp_file.sh`; no direct rm/kill/chmod.
