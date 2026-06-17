# 10 Performance Baseline Report (true-coexistence)

> Chinese version: `./zh_cn/10-perf-baseline-report.md` (authoritative full text).
>
> **Doc id**: SPEC-KE-10
> **Version**: v6 (native automatic dual-stack paradigm; retains the v4/v5 true-coexistence methodology; supersedes the v3 pure-kernel-loopback methodology)
> **Date**: 2026-06-17
> **Status**: §4/§5 are v5 R4 real-machine FINAL (per-fd either/or methodology, toggling only runtime `kernel_coexist` 0/1). **v6 automatic dual-stack (commit 13b418191) functional correctness + macro-off zero regression + PERF-1/2/4 F-Stack fast-path A/B are all real-machine measured PASS (see §10).**
> **v6 note**: v5 measured per-fd either/or (default builds F-Stack only) → PERF-1/2 zero regression. v6 automatic dual-stack introduces **default dual-build/dual-drive**, so RE-MEASURE: (1) F-Stack business fast path still no regression under default dual-stack (PERF-1/2); (2) single-stack connection hot path does NOT consult `ff_native_fd_map` (PERF-4, see `07` UT-17). R6 macro-off (incl. v6 `ff_native_fd_map` not compiled) zero-regression is still verified by `07 §1bis` MT-1 `nm` symbol comparison; macro off = same binary as upstream, no perf retest.
> **Scope**: empirically prove coexistence causes **no regression on the F-Stack business fast path** (PERF-1/2/**4**), and give a **kernel-side bypass throughput** (PERF-3) management-plane data point.
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
| **PERF-4 (v6)** | **hot path does not consult the map** | single-stack connection recv/send throughput with auto dual-stack on/off (the single-stack connection accepted from a default dual-stack listen) | zero extra cost on the connection hot path (NFR-2, see `07` UT-17); **measured PASS** (recv/send do a single `ff_is_kernel_fd` check, no map lookup; §10.2 keep-alive throughput A1≈A0 corroborates) |

> **§4/§5 are the v5 per-fd either/or FINAL measurement**; under v6 automatic dual-stack (default dual-build/dual-drive), PERF-1/2/4 must be re-measured at R7 (see the v6 note above).

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

---

## 10. v6 R7 automatic dual-stack measured verdict (commit 13b418191)

> This section is the measured verdict for v6 native automatic dual-stack. The vector A A/B throughput in §10.2 is a **v6 default dual-build/dual-drive** real-machine measurement (helloworld, IPv4-only, linked against the macro-on lib, toggling only config `kernel_coexist` 0/1; client wrk 4.2.0 against the DPDK NIC 9.134.214.176:80). §4/§5 remain the v5 per-fd either/or FINAL, kept as a historical reference.

### 10.1 Measured / proven items

| Item | Evidence | Verdict |
|---|---|---|
| Macro-off zero regression (compile-time) | `nm libfstack.a` coexist symbols=0; size 6539682 byte-for-byte identical to baseline | PASS (same binary as upstream F-Stack) |
| Macro-on build | `make FF_KERNEL_COEXIST=1` rc=0; coexist symbols complete (incl. `ff_native_fd_map`) | PASS |
| Dual-mode unit tests | macro-off P1 50/50; macro-on P1 incl. `test_ff_native_fd_map`/`test_ff_kernel_fd_encode_roundtrip` | PASS |
| Real-machine dual-stack function (one listen, many uses) | single `listen(80)`: kernel `curl 127.0.0.1:80=200`; F-Stack `ssh→9.134.214.176:80=200` | PASS |
| PERF-1/2 F-Stack fast-path no regression | §10.2 vector A A/B real-machine measurement | PASS |
| PERF-4 hot path no map lookup | recv/send do a single `ff_is_kernel_fd` check, no map lookup (code) + §10.2 keep-alive throughput A1≈A0 (measured) | PASS |

### 10.2 Vector A: v6 default dual-build vs F-Stack business fast path A/B (PERF-1/2, real-machine)

> Same helloworld (IPv4-only, linked against the macro-on lib), toggling only `config.ini [stack] kernel_coexist`: A0=0 (pure F-Stack) / A1=1 (v6 default dual-build/dual-drive). Client (f-stack-client, masked 192.168.1.2) wrk 4.2.0 against the DPDK NIC 9.134.214.176:80 (masked 192.168.1.1); median of 3 trials per tier; environment/method per §2/§3 (single lcore `lcore_mask=10`, `idle_sleep=20`, keep-alive).

Throughput req/s (median of 3):

| Tier | A0 coexist-off | A1 v6 dual-stack | Δ (A1 vs A0) | trials (A0 / A1) |
|---|---:|---:|---:|---|
| T1 (-t2 -c10 5s)   | 28,216 | 27,729 | **−1.73%** | A0 28216/28213/28606 · A1 26873/27729/27911 |
| T2 (-t4 -c100 30s) | 202,805 | 206,219 | **+1.68%** | A0 206117/202805/202697 · A1 202045/206219/206744 |
| T3 (-t8 -c500 30s) | 120,702 | 127,784 | **+5.87%** | A0 120702/110394/125671 · A1 128306/117037/127784 |

p99 latency (median of 3):

| Tier | A0 p99 | A1 p99 |
|---|---:|---:|
| T1 | 526 us | 528 us |
| T2 | 726 us | 733 us |
| T3 | 206.22 ms | 208.25 ms |

- Zero socket errors across all 18 trials.

### 10.3 Verdict

All v6 default dual-build/dual-drive on (A1) vs off (A0) deltas fall within trial noise with no systematic negative trend: T1 −1.73%, T2 +1.68%, T3 +5.87% (A1 slightly faster at T2/T3); p99 essentially equal (T1 ~526us, T2 ~730us, T3 ~206-208ms same-basis c500 single-lcore tail, identical A0/A1 behavior). This matches the v5 §4 verdict: the dual-build cost is paid once on listen-socket setup, while a keep-alive connection's data hot path (recv/send) is single-stack and does not consult the map (PERF-4), so there is no measurable regression on the F-Stack business fast path.

→ **PERF-1/2/4 PASS (v6 real-machine): v6 native automatic dual-stack introduces no measurable regression on the F-Stack business fast path (NFR-1/NFR-2); F-Stack always carries the business (NFR-3).**

> Raw wrk output (IP-masked): `/tmp/perf/A{0,1}_T{1,2,3}_tr{1,2,3}.txt` (cleaned via `rm_tmp_file.sh` after the run).
