# 06 - Performance Baseline Comparison Report

## Summary

This document records performance baseline data for issue #1078 feasibility investigation. Purpose: provide **pre-change comparison baseline** for subsequent PoC (primary-slim: primary doesn't hold queues, data plane fully moved to secondary), confirm primary slimming doesn't introduce data plane performance regression. Pre-change baseline collection completed (no code changes), and post-PoC comparison collection also completed. Conclusion: PoC has no performance regression, but slim primary still occupies a full core (needs idle sleep).

## Key Conclusions

1. **2 data-plane process baseline**: ~**135.8k QPS** (3-round mean, range 132.9k~138.6k), 0 failed requests.
2. **1 data-plane process baseline**: ~**122.3k QPS** (3-round mean, range 115.8k~126.6k), 0 failed requests.
3. **Key methodology finding**: Increasing from 1 to 2 data-plane processes only improved QPS ~**11%** (122.3k → 135.8k), far below linear. This indicates **bottleneck is on client/link side, not server** (client 8-core `ab`); therefore absolute QPS in this environment **cannot be used to assess f-stack data plane throughput upper limit**, only for "pre-change vs post-change **same config** comparison."
4. **PoC no performance regression (measured)**: slim primary alive **122.4k QPS** (vs single-process baseline +0.08%), slim primary crashed **127.7k QPS** (+4.5%), both 0 failed requests, **far exceeding** acceptance threshold 111.5k.
5. **Negative finding: slim primary still occupies a full CPU core (99.8%)** — slimming only reduced its "responsibilities," not its "spinning." primary-slim benefit is stability, **does not include CPU savings**; production implementation must introduce idle sleep (`idle_sleep` currently 0).
6. **PoC comparison baseline selection (important)**: PoC target state is `lcore_mask=3` (primary slimmed + 1 secondary receiving), its **data-plane process count is 1**, so correct comparison baseline is **1 data-plane process baseline (~122.3k)**, not 2-process baseline. Using 2-process baseline would incorrectly conclude "10% performance drop."

## I. Test Environment and Method

| Item | Value |
|------|-------|
| Test program | `example/helloworld` (HTTP, port 80) |
| Server address | `<DPDK_NIC_IP>:80` |
| Load client | `f-stack-client` (8-core), tool `ab` (`wrk` unavailable) |
| Load command | `ab -k -c 50 -n 20000 http://<DPDK_NIC_IP>/` |
| Rounds | 3 consecutive rounds per config, take range and mean |
| DPDK NIC | `0000:00:09.0`, `Virtio network device 1000`, `drv=igb_uio` |
| Code status | **Unchanged** (`git status` shows no `lib/` modifications) |
| Env prep | Before each config switch: `kill_process.sh` + `rm_tmp_file.sh` to clean `/var/run/dpdk/rte/` |

## II. Baseline Data

### 2.1 Config A: `lcore_mask=3` (primary + secondary, 2 data-plane processes)

| Round | QPS (#/sec) | Failed requests | Time per request (mean) |
|-------|-------------|-----------------|------------------------|
| 1 | 135825.27 | 0 | 0.368 ms |
| 2 | 132931.88 | 0 | 0.376 ms |
| 3 | 138590.53 | 0 | 0.361 ms |
| **Mean** | **135782.56** | **0** | **0.368 ms** |

Noise range: ±2.1%.

### 2.2 Config B: `lcore_mask=1` (primary only, 1 data-plane process)

| Round | QPS (#/sec) | Failed requests |
|-------|-------------|-----------------|
| 1 | 124385.84 | 0 |
| 2 | 126619.94 | 0 |
| 3 | 115795.69 | 0 |
| **Mean** | **122267.16** | **0** |

Noise range: ±8.8%, significantly larger than Config A.

### 2.3 Horizontal Comparison

| Config | Data-plane processes | QPS mean | Relative to B |
|--------|---------------------|----------|---------------|
| B (`lcore_mask=1`) | 1 | 122267 | Baseline |
| A (`lcore_mask=3`) | 2 | 135783 | **+11.1%** |

**Interpretation**: Doubling data-plane processes only brings 11% improvement → server not saturated, bottleneck at client `ab` or virtualization network link. **Therefore absolute values in this report are only for same-config pre/post comparison, must not be used for capacity planning or claiming f-stack throughput.**

## III. PoC Comparison Design (Executed, results in Section IV)

| Item | Content |
|------|---------|
| PoC target | `lcore_mask=3`, primary slimmed (not in any port's `lcore_list`, no queues, no packet reception), secondary exclusively owns the only queue |
| Data-plane processes | **1** |
| **Correct baseline** | **Config B (122267 QPS)** |
| Acceptance criteria | PoC QPS ≥ Config B mean × (1 − noise upper bound 8.8%) ≈ **111.5k QPS**, and `Failed requests = 0` |

## IV. PoC Measured Data (primary-slim)

### 4.1 P1b: QPS with slim primary **alive**

| Round | QPS (#/sec) | Failed requests |
|-------|-------------|-----------------|
| 1 | 122952.84 | 0 |
| 2 | 123134.51 | 0 |
| 3 | 121008.24 | 0 |
| **Mean** | **122365.20** | **0** |

### 4.2 P1: QPS after slim primary **crashed** (only 1 secondary running)

| Round | QPS (#/sec) | Failed requests |
|-------|-------------|-----------------|
| 1 | 128812.03 | 0 |
| 2 | 130423.16 | 0 |
| 3 | 123999.48 | 0 |
| **Mean** | **127744.89** | **0** |

### 4.3 Comparison Conclusion (Key)

| Scenario | Data-plane processes | QPS mean | vs Baseline B (122267) | Verdict |
|----------|---------------------|----------|------------------------|---------|
| Baseline B: unchanged, single process | 1 | 122267 | Baseline | — |
| **P1b: PoC + slim primary alive** | 1 | **122365** | **+0.08%** | **No regression** (far below 8.8% noise) |
| **P1: PoC + slim primary crashed** | 1 | **127745** | **+4.5%** | **No regression**; slightly higher possibly because primary no longer competing, but within noise |

**Acceptance**: ≥ 111.5k QPS and `Failed requests = 0`. P1b and P1 both **far exceed** threshold with zero failures ⇒ **PoC passes performance acceptance, primary slimming introduces no data plane regression.**

### 4.4 P2: CPU Usage (Measured Issue)

`ps -o pid,pcpu -C helloworld` (idle, no load):

| Process | %CPU |
|---------|------|
| slim primary (no queues, no packets) | **99.8** |
| secondary (has queue, receiving) | 100 |

**Conclusion (important negative finding)**: **Slimmed primary still occupies an entire CPU core.** Reason: `main_loop` still tightly spinning (running timer + msg_ring processing), and `config.ini`'s `idle_sleep=0` means no idle sleep.

**Impact**:
- primary-slim benefit is stability, **does not include CPU savings**
- Production implementation **must** introduce idle sleep for slim primary
- Registered as pending experiment E12

## V. Methodology Notes (For Reproduction)

1. **Client is bottleneck**: Conclusions only for same-config comparison; for true throughput limit, need stronger load generator or multiple clients
2. **Cleanup between rounds**: `ab` leaves TIME_WAIT; 3 rounds run serially by `ab` itself, no port exhaustion observed
3. **Fixed-port probe script and `ab` cannot run simultaneously**: Four-tuple conflict
4. **Process startup wait**: primary needs ~25s for initialization (FreeBSD stack + port config); same for secondary
5. All cleanup via `/data/workspace/kill_process.sh` and `/data/workspace/rm_tmp_file.sh`
