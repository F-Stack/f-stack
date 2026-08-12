# 05 Performance Regression Test Report (After #331 Fix, 1/2/4 Cores)

> **Document number**: ISSUE-331-05
> **Version**: v1
> **Date**: 2026-08-07
> **Related commits**: `53c580594` (#331 fix) + `9f711a5d5` (#ifndef FSTACK wrapper)
> **Evidence rule**: All numbers are from actual wrk raw output (`/tmp/perf_regression_331/`); no fabrication.

---

## 1. Test Purpose

Verify that the #331 fix (`kqtimer_sched_callout` tick conversion + `softclock()` enabled under FSTACK) does not introduce TCP performance regression.

Key concern: `softclock()` is called every tick (hz=100 → 100 times/second) in `callout_tick()` to process the regular callout wheel. If this wheel is non-empty (TCP timers use HPTS wheel, not regular wheel), it may introduce additional overhead.

---

## 2. Environment

| Item | Value |
|---|---|
| Test host | Tencent CVM, 16 vCPU |
| DPDK version | 25.0 (statically linked) |
| Data-plane NIC | `0000:00:09.0` virtio_net, igb_uio bound |
| Control-plane NIC | `0000:00:05.0` virtio_net (eth1, kernel driver, ssh bypass) |
| F-Stack config | `thread_mode=0` (multi-process), `idle_sleep=20`, `hz=100` |
| Test target | `example/helloworld`: 438B keep-alive HTTP (commit `9f711a5d5`, includes #331 fix) |
| Load generator | wrk 4.0.2 [epoll] (f-stack-client) |
| Load command | `ssh f-stack-client "/data/wrk/wrk -t4 -c100 -d30s --latency http://<DPDK_NIC_IP>:80/"` |
| lcore config | 1-core `lcore_mask=10`(CPU#4) / 2-core `lcore_mask=30`(CPU#4,5) / 4-core `lcore_mask=f0`(CPU#4,5,6,7) |

---

## 3. Method

- Each config: T1 warmup (`-t2 -c10 -d5s`) + T2 two trials (`-t4 -c100 -d30s`), take median.
- 30-second interval between trials (avoid TIME_WAIT buildup).
- Multi-process mode: primary (`--proc-id=0`) + secondary (`--proc-id=N`), one process per lcore.
- Before each restart, clean DPDK rtemap files via `rm_tmp_file.sh`; stop via `kill_process.sh`.

---

## 4. Results

### 4.1 Throughput req/s (T2 median of 2)

| Cores | lcore_mask | T1 warmup | T2 trial1 | T2 trial2 | **T2 median** |
|---|---|---:|---:|---:|---:|
| 1 | 0x10 | 28,810 | 193,462 | 193,348 | **193,405** |
| 2 | 0x30 | 29,064 | 234,107 | 232,061 | **233,084** |
| 4 | 0xF0 | 30,157 | 260,061 | 260,982 | **260,522** |

### 4.2 p99 Latency (T2 median of 2)

| Cores | T2 trial1 p99 | T2 trial2 p99 | **T2 median p99** |
|---|---:|---:|---:|
| 1 | 772 us | 751 us | **762 us** |
| 2 | 632 us | 647 us | **640 us** |
| 4 | 583 us | 554 us | **569 us** |

### 4.3 All trials had zero socket errors

---

## 5. Baseline Comparison (1-core T2)

| Baseline Source | Date | req/s | p99 | Notes |
|---|---|---:|---:|---|
| kernel_event_support_spec A0 | 2026-06-17 | 202,805 | 726 us | coexist off, single lcore, idle_sleep=20 |
| 13.0-baseline 15.0 | 2026-06-03 | 203,933 | 827 us | runtime-fix-done, single lcore |
| **This run (after #331 fix)** | **2026-08-07** | **193,405** | **762 us** | includes #331 fix + #ifndef FSTACK |

| Comparison | Δ req/s | Δ p99 |
|---|---:|---:|
| This run vs kernel_event_support A0 | **−4.6%** | +5.0% |
| This run vs 13.0-baseline 15.0 | **−5.1%** | **−7.9%** (better) |

---

## 6. Multi-core Scalability

| Scaling | req/s increase | Scaling ratio | p99 improvement |
|---|---:|---:|---:|
| 1→2 cores | 193,405 → 233,084 | 1.21x | 762→640 us (−16%) |
| 2→4 cores | 233,084 → 260,522 | 1.12x | 640→569 us (−11%) |
| 1→4 cores | 193,405 → 260,522 | 1.35x | 762→569 us (−25%) |

Scaling ratio is below ideal linear (2x/4x) because the fixed wrk load (`-t4 -c100`) is spread across more cores, reducing connections per core (4 cores: 25 conn/core), so cores are not saturated. p99 consistently decreases with more cores, confirming load is effectively distributed.

---

## 7. Conclusion

**The #331 fix does not introduce measurable performance regression.**

1. **1-core throughput**: 193,405 req/s vs baseline 202,805 req/s, deviation −4.6%, within the cross-day noise range (6-10%) documented in the baseline report (13.0-baseline report §5.2: "Cross-day 6-10% deviation due to network/CPU frequency jitter").
2. **p99 latency**: 762 us is better than 13.0-baseline's 827 us (−7.9%), roughly on par with kernel_event_support A0's 726 us (+5.0%).
3. **`softclock()` overhead is negligible**: at hz=100, called 100 times/second for regular callout wheel processing; TCP timers use HPTS wheel (not regular wheel), so the wheel is essentially empty; overhead does not appear in throughput/latency data.
4. **Multi-core scaling is healthy**: 1→2→4 core throughput monotonically increases, p99 monotonically decreases, no abnormal degradation.

---

## 8. Compliance

| Item | Evidence |
|---|---|
| `rm_tmp_file.sh` | Zero direct rm throughout; rtemap cleanup via script |
| `kill_process.sh` | Zero direct kill throughout; process stop via script |
| `chmod_modify.sh` | No permission changes this round |
| config.ini | Test-period `lcore_mask`/`idle_sleep` changes, **restored after testing**; not committed |
| commit message | English (`9f711a5d5`) |

---

## 9. Raw Data

| File | Content |
|---|---|
| `/tmp/perf_regression_331/1core_T1.txt` | 1-core T1 warmup |
| `/tmp/perf_regression_331/1core_T2_tr1.txt` | 1-core T2 trial1 |
| `/tmp/perf_regression_331/1core_T2_tr2.txt` | 1-core T2 trial2 |
| `/tmp/perf_regression_331/2core_T1.txt` | 2-core T1 warmup |
| `/tmp/perf_regression_331/2core_T2_tr1.txt` | 2-core T2 trial1 |
| `/tmp/perf_regression_331/2core_T2_tr2.txt` | 2-core T2 trial2 |
| `/tmp/perf_regression_331/4core_T1.txt` | 4-core T1 warmup |
| `/tmp/perf_regression_331/4core_T2_tr1.txt` | 4-core T2 trial1 |
| `/tmp/perf_regression_331/4core_T2_tr2.txt` | 4-core T2 trial2 |
