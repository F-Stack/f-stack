# 38. Performance Baseline Specification

> Reference: 21-m2-test-report.md (ZC-recv single-core wrk A/B measurements) + docs/freebsd_13_to_15_upgrade_spec/zh_cn/cvm-bench-methodology.md
> Goal: after this phase's spec is implemented, the new scheme vs. the current hacked scheme should have Δ ≤ ±3% (within noise) under small-packet / large-packet / multi-concurrency scenarios

---

## §1 Test Topology

```
[client: f-stack-client (8-core CVM)]   ssh   [server: this machine (single-core lcore4 + DPDK NIC)]
   /tmp/wrk/wrk -t* -c* -d30s        ───▶   helloworld_zc (HTTP echo, port 80)
        9.134.214.176                       data-plane: vfio-pci 0000:00:09.0
                                            control-plane: eth1 SSH
```

Reference methodology: `docs/freebsd_13_to_15_upgrade_spec/zh_cn/cvm-bench-methodology.md` (the single-core baseline established during the 13.0→15.0 upgrade).

---

## §2 Test Matrix

### §2.1 Three-tier wrk Stress Tiers (consistent with 21-m2-test-report)

| Tier | command | purpose |
|---|---|---|
| T1 | `wrk -t2 -c10 -d5s --latency http://9.134.214.176/` | low-concurrency smoke, establish baseline |
| T2 | `wrk -t4 -c100 -d30s --latency http://9.134.214.176/` | medium concurrency, primary comparison tier |
| T3 | `wrk -t8 -c500 -d30s --latency http://9.134.214.176/` | high concurrency, saturated or oversaturated |

### §2.2 Three Comparison Groups

| Group | server-side build | meaning |
|---|---|---|
| **A** baseline | default compile (no ZC) | ordinary ff_read + ff_write, serves as baseline |
| **B-old** | current hacked ZC-send | `FF_ZC_SEND=1` old implementation (FSTACK_ZC_MAGIC + m_uiotombuf) |
| **B-new** | new native ZC-send | `FF_ZC_SEND=1` new implementation (kern_zc_sendit + sosend(top)) |

Note: B-old is the version currently landed on master (before commit de58b11e9); B-new is the version after this spec is implemented.

### §2.3 Large-payload Custom Client (issue #712 scenario)

| # | scenario | client | expected behavior |
|---|---|---|---|
| P1 | small packet (438 bytes, main_zc default HTML size) | wrk T1/T2/T3 | A ≈ B-old ≈ B-new (copy overhead negligible) |
| P2 | medium packet (4 KB) | custom client (write 4KB once) | A < B-new; B-old may crash/hang (issue #712) |
| P3 | large packet (64 KB) | custom client | A << B-new; B-old high crash/hang risk |
| P4 | huge packet (1 MB) | custom client | B-new should send fragmented (atomic + sb_max constraint, see 36 §4); A sequential copy; B-old highest crash probability |

---

## §3 Measured Command Templates (spec describes only, run during implementation phase)

> The spec does not provide executable "start / stop" commands, because these touch process management; during the implementation phase the agent must strictly comply with the `kill_process.sh` and `rm_tmp_file.sh` regulations (lessons already learned in the M2 phase).

Test flow pseudocode (non-executable):

```
1. compile server A: PKG_CONFIG_PATH=... make (default)
2. compile server B-new: PKG_CONFIG_PATH=... FF_ZC_SEND=1 make clean && make
3. start server A → wrk T1/T2/T3 → record r1/r2/r3
4. stop server A: /data/workspace/kill_process.sh <pid>
5. clean hugepage: /data/workspace/rm_tmp_file.sh /dev/hugepages/rtemap_*
6. start server B-new → wrk T1/T2/T3 → record r1/r2/r3
7. stop server B-new + clean up
8. compare A vs B-new → Δ target ≤ ±3%
9. (optional) start server B-old (git checkout old implementation + recompile) → wrk → record
10. compare B-old vs B-new → Δ target ≤ ±3%
```

---

## §4 Pass Conditions (AC3)

| Clause | Pass criterion |
|---|---|
| **PERF-1** | under all three tiers T1/T2/T3, B-new vs A Requests/sec Δ ≤ ±3% (within noise) |
| **PERF-2** | under all three tiers T1/T2/T3, B-new vs B-old Requests/sec Δ ≤ ±3% (within noise, proving no regression from replacement) |
| **PERF-3** | at the T2 tier, Latency p50 / p90 / p99 Δ across the three servers ≤ ±5% (noise includes tail-latency perturbation) |
| **PERF-4** | single-core server CPU usage at the T2 tier is 60-90% (unsaturated); the three servers are close to consistent |
| **PERF-5** | wrk Socket errors / Non-2xx responses are all = 0 across the three servers |
| **PERF-6** | (issue #712 scenario) P2 4KB single packet: B-new does not crash; B-old depends on environment (for reference, not forced PASS) |
| **PERF-7** | (issue #712 scenario) P3 64KB single packet: B-new does not crash and data is intact; B-old is a known risk |

---

## §5 Historical Baseline Reference (from the 13.0 upgrade baseline + the 21-m2 report)

| metric | 13.0 baseline | M2-A baseline (this machine, 21-m2) | M2-B ZC-recv (this machine, 21-m2) |
|---|---|---|---|
| T1 (-t2 -c10) | — | 22.4k | 22.1k |
| T2 (-t4 -c100) | ~220k est. | ~31.1k | ~32.1k |
| T3 (-t8 -c500) | ~239k est. | 28.6k | 28.3k |
| smoke RTT | 1.25ms | — | — |

> The 13.0 and M2 figures differ significantly (13.0 is a different fixture), due to the difference in main_zc's echo response size and the socket buffer default value; this phase's spec uses only M2-A/B as a reference baseline and does not align with the 13.0 absolute values.

---

## §6 Large-payload Custom Client Example (spec description, non-executable)

During the implementation phase one may write a custom TCP client in `tests/integration/zc_send_perf_client.c`:
- single connection, issue N requests, each sending a fixed-size payload (4KB / 64KB / 1MB);
- the server echoes back;
- the client records throughput / RTT / error rate.

Or reuse wrk's `-s` Lua script option to inject a custom body (recommended, no need to implement it yourself):

```lua
-- /tmp/perf_4k.lua (edited on the client side, during the implementation phase)
wrk.method = "POST"
wrk.body = string.rep("x", 4096)
wrk.headers["Content-Type"] = "application/octet-stream"
```

Start: `/tmp/wrk/wrk -t4 -c100 -d30s -s /tmp/perf_4k.lua --latency http://9.134.214.176/`

> The lua script snippet provided in the spec is not a "shell command"; editing this lua file during the implementation phase does not touch the rm/kill/chmod regulations.

---

## §7 Measurement Method

### §7.1 wrk Output Parsing

```
Running 30s test @ http://9.134.214.176/
  4 threads and 100 connections
  Latency Distribution
     50%   1.10ms
     90%   2.95ms
     99%   8.20ms
  Requests/sec:  31987.45      ← used by PERF-1/-2
  Transfer/sec:   12.34MB
```

### §7.2 Server-side CPU

```
ps -o pid,pcpu,comm <pid>      ← during the implementation phase the leader queries the PID via ssh + kill_process.sh companion
```

### §7.3 Error Rate

The `Socket errors: connect 0, read 0, write 0, timeout 0` at the end of the wrk output should all be 0.

### §7.4 Average of Three Runs

Run each tier 3 times, drop the highest/lowest outliers, take the average (during the 21-m2 phase a warmup outlier of 39k vs 31k was encountered; the regulation requires retesting).

---

## §8 Risks and Mitigations

| risk | mitigation |
|---|---|
| issue #712 large-data crash reproduced on B-old | do not require B-old to pass P2-P4; only used as a no-regression judgment for B-new |
| client wrk-side bottleneck (the client 9.134.213.x is also an 8-core VM) | enable -t4..-t8 to use the client's multiple cores; monitor client-side CPU |
| network jitter | take the average of 3 runs per tier; keep all raw logs |
| stale .o (M2 lesson) | `make clean` is mandatory each time the server is switched; emphasized in spec 39 §3 |

---

## §9 Gatekeeper-Verifiable Clauses (gatekeeper)

| Clause | Verification method | Pass criterion |
|---|---|---|
| P-G1 | spec lists ≥3 stress tiers (T1/T2/T3) | hit |
| P-G2 | spec lists ≥3 comparison groups (A/B-old/B-new) | hit |
| P-G3 | spec lists PERF-1..7 pass conditions | hit |
| P-G4 | spec references 21-m2-test-report historical data | hit |
| P-G5 | spec does not contain direct rm/kill/chmod commands | auto grep |

---

Next: **39-migration-guide.md** (migration guide for already-deployed projects).
