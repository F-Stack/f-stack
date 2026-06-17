# 10 Performance Baseline Report (v4, true-coexistence)

> Chinese version: `./zh_cn/10-perf-baseline-report.md`
>
> **Doc id**: SPEC-KE-10
> **Version**: v5 (compile-macro gating; retains the v4 true-coexistence methodology; supersedes the v3 pure-kernel-loopback methodology)
> **Date**: 2026-06-17
> **Status**: FINAL (R4 performance-gate measured output). **v5 note**: this baseline was measured with coexistence code **compiled in** (equivalent to `FF_KERNEL_COEXIST` on), toggling only the runtime `kernel_coexist` 0/1 — still valid. The macro-off (coexistence not compiled) zero-regression is verified by the `nm` symbol comparison MT-1 in `07 §1bis`; **no performance retest needed** (macro off = same binary as upstream F-Stack).
> **Scope**: empirically prove that "F-Stack user-space stack + host kernel-stack coexistence" causes **no regression on the F-Stack business fast path** (PERF-1/PERF-2), and give a **kernel-side bypass throughput** (PERF-3) management-plane data point.
> **Empirical rule**: every number comes from real wrk output (`/tmp/helloworld-coexist-bench/`, `/tmp/kbench-perf/`); no fabrication. Real server/client IPs are source-side `sed`-masked before landing on disk (`9.134.214.176→192.168.1.1`, `9.134.211.87→192.168.1.2`).

---

## 0. Why v3 is superseded

The v3 report measured `ff_socket(SOCK_KERNEL)→ff_host_socket→raw host socket` over local loopback — **F-Stack was never exercised** (both A/B were pure kernel). It did not measure "coexistence" at all. v4 reverted that wrong implementation and re-measured under the correct paradigm: **the app runs ON F-Stack for business; a per-fd `SOCK_KERNEL` additionally rides the host kernel stack; both coexist in the same process.** This report is the v4-correct measurement.

---

## 1. Goals

| Id | Metric | Method | Gate |
|---|---|---|---|
| PERF-1 | F-Stack fast-path regression | coexist off vs on, press F-Stack business only | throughput/latency delta ≤ noise (NFR-2) |
| PERF-2 | default-path zero overhead | effect of the coexist branch on default/`SOCK_FSTACK` | zero/negligible (NFR-1) |
| PERF-3 | kernel-side bypass throughput | local loopback wrk against the `SOCK_KERNEL` listener | meets management-plane expectation (not a fast path) |

---

## 2. Environment

| Item | Value |
|---|---|
| Host | Tencent CVM, 16 vCPU, DPDK 23.11.5 |
| Data-plane NIC | `0000:00:09.0` virtio_net, bound to `igb_uio` (DPDK PMD, F-Stack data plane) |
| Control NIC | `eth1` (kernel driver, ssh out-of-band; physically isolated from the data plane) |
| F-Stack model | single lcore (`lcore_mask=10`, CPU#4), single process, listen port 80, `idle_sleep=20us` |
| SUT (vector A) | `example/helloworld`: F-Stack keep-alive HTTP, returns preset 438B `html[]`; same binary for A/B, only config toggled |
| SUT (vector B) | `example/helloworld_stacksel bench`: `ff_socket(SOCK_KERNEL)` listener + `ff_host_epoll_*` non-blocking loop, preset 15B body (EAL-free) |
| Load gen | wrk 4.2.0 [epoll]; vector A from f-stack-client (`192.168.1.2`, same /21 as the data plane), vector B local loopback |
| Protocol | HTTP/1.1, `Connection: keep-alive` |

The sole A/B variable = `config.ini [stack] kernel_coexist` (`0` off / `1` on). helloworld source and binary are unchanged, eliminating link-artifact differences.

---

## 3. Method (aligned to freebsd_13_to_15 `cvm-bench-methodology.md`)

| Tier | wrk params | Duration | Purpose |
|---|---|---|---|
| T1 | `-t2 -c10 --latency` | 5s | light load + warm-up |
| T2 | `-t4 -c100 --latency` | 30s | **mid-load main verdict** |
| T3 | `-t8 -c500 --latency` | 30s | high-conc tail latency |

- Each tier: **median of 3 trials**.
- Vector A is **same-time-window A/B**: A0(`kernel_coexist=0`) and A1(`kernel_coexist=1`) switched within the same minute to suppress cross-time drift; each round stopped via `kill_process.sh`, rtemap hugepages cleared via `rm_tmp_file.sh`.
- Vector B is local loopback self-press: server pinned to CPU0, wrk to CPU2-15 (`taskset`).

---

## 4. Vector A: F-Stack fast-path A/B (PERF-1 / PERF-2)

### 4.1 Throughput req/s (median of 3)

| Tier | A0 coexist-off | A1 coexist-on | Δ (A1 vs A0) | trials (A0 / A1) |
|---|---:|---:|---:|---|
| T1 (-t2 -c10 5s)   | 27,386 | 27,204 | **−0.66%** | A0 28401/27386/26876 · A1 27204/27042/27618 |
| T2 (-t4 -c100 30s) | 207,723 | 210,811 | **+1.49%** | A0 206927/208099/207723 · A1 212296/208933/210811 |
| T3 (-t8 -c500 30s) | 128,422 | 134,354 | **+4.62%** | A0 127391/133667/128422 · A1 134354/139085/130335 |

### 4.2 p99 latency (median of 3)

| Tier | A0 p99 | A1 p99 |
|---|---:|---:|
| T2 | 695 us | 713 us |
| T3 | 281 ms | 210 ms |

### 4.3 Verdict (A/B)

All coexist-on (A1) vs coexist-off (A0) deltas fall within trial noise with no systematic negative trend: T1 −0.66%, T2 +1.49%, T3 +4.62% (A1 equal-or-slightly-faster); T2 p99 essentially equal (~700us). This matches the design: coexistence only adds one `ff_is_kernel_fd()` branch at each `ff_*` entry; the default/`SOCK_FSTACK` path is byte-for-byte unchanged, so an F-Stack business fd without `SOCK_KERNEL` incurs zero extra cost.

→ **PERF-1 / PERF-2 PASS: the coexistence switch introduces no measurable regression on the F-Stack business fast path (corroborates NFR-1 default-path zero overhead, NFR-2 fast-path no-regression, NFR-3 F-Stack always in place).**

---

## 5. Vector B: kernel-side bypass throughput (PERF-3, management plane)

Local loopback wrk against the `SOCK_KERNEL` kernel-stack HTTP keep-alive server (single-thread host-epoll, preset 15B body).

| Tier | req/s (median of 3) | p99 | socket errors | trials |
|---|---:|---:|---:|---|
| T1 (-t2 -c10 5s)   | 132,385 | — | 0 | 132385/130522/133348 |
| T2 (-t4 -c100 30s) | 127,501 | 1.43 ms | 0 | 128979/119463/127501 |
| T3 (-t8 -c500 30s) | 113,641 | 4.86 ms | 0 | 102595/113648/113641 |

- **Zero socket errors across all 9 trials** (no connect/read/write/timeout errors).
- **Caveat**: this is a **single-thread** kernel-stack server under **single-host loopback self-press** (server and wrk contend for the same CPUs); it reflects only the serial lower bound of the kernel-side management plane, **not** the F-Stack data plane, and is **not** directly comparable to vector A's absolute values. Its purpose is to show the `SOCK_KERNEL` channel serves high-concurrency keep-alive correctly, error-free, with throughput meeting management-plane expectations (local ping/curl/management connections).

→ **PERF-3 PASS: the kernel-side bypass serves all three tiers stably and error-free.**

---

## 6. Background cross-reference: existing freebsd_13_to_15 CVM data (different basis, reference only)

Source `docs/freebsd_13_to_15_upgrade_spec/13.0-baseline-cvm-bench-report.md` (also two-machine, server runs F-Stack, same wrk tiers, helloworld 438B):

| Tier | 15.0 existing ref req/s | this A0 coexist-off | this A1 coexist-on |
|---|---:|---:|---:|
| T1 | 23,757 | 27,386 | 27,204 |
| T2 | 203,933 | 207,723 | 210,811 |
| T3 | 217,100 | 128,422 | 134,354 |

- **T2 highly consistent**: this A0/A1 (207.7k/210.8k) matches the existing 15.0 (203.9k) within cross-time drift, cross-confirming "coexist-off equals pure F-Stack" (NFR-1).
- **T3 absolute below the existing cross-time ref**: in this run at c500, p50 is fast (1.26ms) but p99 tail is large (~200-300ms), consistent across all 3 trials — a characteristic of this host's c500 single-lcore accept scheduling + `idle_sleep=20us` on the day; A0/A1 show the same behavior, so it is **unrelated to coexistence** and does not affect the A/B verdict. The existing report §5.2 already noted large T3 cross-time drift (absolute values comparable only within the same basis); this report relies on the same-window A/B relative Δ.

---

## 7. Key process finding: header change requires a full lib rebuild (ABI skew)

The first helloworld relinked against the current lib **segfaulted at startup in `ff_log_close()→fclose(dangling)`**. Root cause (gdb + mtime cross-check): R3 added `int kernel_coexist` to the `stack` sub-struct of `struct ff_config`, shifting the offset of the following `log` sub-struct (incl. `log.f`); the lib Makefile **does not track header dependencies**, so an incremental build left **objects mixing the old and new `ff_config.h` layout** — `ff_log.o` (old offset) read `log.f` from a slot that holds another non-zero field in the new layout → `fclose` crash.

- **Discriminator**: the known-good 13.0-baseline helloworld ran fine in the same environment (entered `ff_run`, exit 124 timeout, no crash) → environment is healthy; the problem was the current tree's build state.
- **Fix**: `rm_tmp_file.sh` removed all 245 `.o` + `libfstack.a` → full rebuild (15s) → all objects share one header layout → helloworld starts normally (exit 124).
- **Conclusion**: **not a source regression**, purely a build-hygiene issue. The coexistence code itself is correct; NFR-1 (coexist-off equals baseline) holds on a clean build.
- **Action item**: changes to struct headers like `ff_config.h` require a `clean` full lib rebuild (lib/Makefile lacks header-dependency tracking — an existing F-Stack build characteristic); recommend noting this in the spec/README.

---

## 8. Compliance and final system state

| Item | Evidence |
|---|---|
| `rm_tmp_file.sh` | zero direct rm throughout; rtemap, `.o`/libfstack.a, stray log cleanup all via the script |
| `kill_process.sh` | zero direct kill throughout; A0/A1 helloworld and kernel bench server stopped via the script |
| `chmod_modify.sh` | no permission change this round |
| config.ini | `kernel_coexist` toggled 0↔1 during testing, **restored to 0 afterwards**; local runtime values (lcore_mask/port0 IP) are pre-existing uncommitted local state, **not committed** |
| IP masking | vector A client stdout source-side sed-masked before landing; vector B loopback has no real IPs |
| Final state | no leftover processes, hugepages clean (0 rtemap), config `kernel_coexist=0` |

## 9. Reproduction

```bash
# 0) full lib rebuild after header change (critical)
ls /data/workspace/f-stack/lib/*.o | xargs /data/workspace/rm_tmp_file.sh
/data/workspace/rm_tmp_file.sh /data/workspace/f-stack/lib/libfstack.a
make -C /data/workspace/f-stack/lib -j$(nproc)

# 1) relink helloworld (vector A SUT)
cd /data/workspace/f-stack/example && cc -O0 -g -gdwarf-2 $(pkg-config --cflags libdpdk) -DINET6 \
  -o helloworld main.c $(pkg-config --static --libs libdpdk) \
  -L../lib -Wl,--whole-archive,-lfstack,--no-whole-archive -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lz -pthread -lnuma

# 2) build kernel-side bench (vector B SUT)
cd /data/workspace/f-stack/example/helloworld_stacksel && make   # ./helloworld_stacksel bench <port>

# 3) vector A: same-window A0/A1 (only toggle config kernel_coexist 0/1), f-stack-client wrk T1/T2/T3 x3 (sed-masked)
# 4) vector B: local loopback wrk (server on CPU0, wrk on CPU2-15) T1/T2/T3 x3
# teardown: kill_process.sh stops servers; rm_tmp_file.sh clears rtemap; config restored to kernel_coexist=0
```

> Raw wrk output: vector A `/tmp/helloworld-coexist-bench/A{0,1}_T{1,2,3}_trial{1,2,3}.txt`; vector B `/tmp/kbench-perf/B_T{1,2,3}_trial{1,2,3}.txt`.
