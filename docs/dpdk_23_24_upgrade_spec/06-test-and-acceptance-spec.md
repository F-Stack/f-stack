# 06 — Test & Acceptance Spec

> Document version: v0.1 (2026-06-09)
> Parent plan: `plan.md`
> Upstream documents: `00 / 01 / 02 / 04`
> Reused methodology: the phase-5b curl-bench pattern from `freebsd_13_to_15_upgrade_spec/zh_cn/phase-5b-perf-baseline-spec.md`

---

## 1. Test Matrix Overview

Per the plan q3=A decision, this single spec document covers all 7 test cases (TC-A ~ TC-G).

| TC | Content | Category | Owner |
|---|---|---|---|
| **TC-A** | helloworld single-process function | functional | gate-keeper |
| **TC-B** | helloworld single-process performance | perf | gate-keeper |
| **TC-C** | nginx single-process function | functional | gate-keeper |
| **TC-D** | nginx single-process performance | perf | gate-keeper |
| **TC-E** | nginx multi-process function (including reload + worker exit) | functional | gate-keeper |
| **TC-F** | nginx multi-process wrk functional (no horizontal-scaling evaluation) | functional | gate-keeper |
| **TC-G** | F-Stack phase-2 + vlan-test historical capability single-pass smoke | regression | gate-keeper |

---

## 2. Common Pre/Post Conditions

### 2.1 Pre-conditions (before each TC starts)

```bash
# 1. clean up DPDK runtime residue (prevent stale primary interference)
/data/workspace/rm_tmp_file.sh \
  /var/run/dpdk/rte/config \
  /var/run/dpdk/rte/fbarray_memseg-2048k-0-0 \
  /var/run/dpdk/rte/fbarray_memseg-2048k-0-1 \
  /var/run/dpdk/rte/fbarray_memseg-2048k-0-2 \
  /var/run/dpdk/rte/fbarray_memseg-2048k-0-3 \
  /var/run/dpdk/rte/fbarray_memzone \
  /var/run/dpdk/rte/hugepage_info

# 2. kill residual processes (if any)
PIDS=$(ps -ef | grep -E 'helloworld|nginx_fstack' | grep -v grep | awk '{print $2}')
[ -n "$PIDS" ] && /data/workspace/kill_process.sh $PIDS
```

### 2.2 Post-conditions (after each TC ends)

```bash
PID=$(ps -ef | grep -E 'helloworld|nginx_fstack' | grep -v grep | awk '{print $2}' | head -1)
[ -n "$PID" ] && /data/workspace/kill_process.sh $PID
sleep 2
```

### 2.3 Workspace Mandatory Rules

- **0 direct `rm/kill/chmod`** — every cleanup path in test scripts must go through the wrappers. Violation = G4 fail (gate-keeper review).
- Process liveness probing uses `[ -d /proc/$PID ]`, **forbidden**: `kill -0`.
- Failure screenshots / logs archived to `/tmp/dpdk24_test_<TC>_<timestamp>.log`, **forbidden**: polluting spec screenshots with stdout.

---

## 3. TC-A — helloworld Single-Process Function

### 3.1 Startup

```bash
cd /data/workspace/f-stack/example
setsid ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 \
    </dev/null > /tmp/dpdk24_TC-A_hw.log 2>&1 &
LAUNCHED_PID=$!

# Poll up to 18s for primary to finish DPDK init + BSD stack init
t=0
while [ $t -lt 18 ]; do
    sleep 1; t=$((t+1))
    PID=$(ps -ef | grep './helloworld -c' | grep -v grep | awk '{print $2}' | head -1)
    [ -n "$PID" ] && [ -d "/proc/$PID" ] && \
        grep -q 'Successed to register dpdk interface' /tmp/dpdk24_TC-A_hw.log 2>/dev/null && break
done
```

### 3.2 G2 Startup Acceptance

| AC | Check | PASS Condition |
|---|---|---|
| TC-A.G2.1 | primary alive | `[ -d /proc/$PID ]` true |
| TC-A.G2.2 | DPDK init keywords | log contains `EAL: Detected ...` + `Probe PCI driver ...` + `Port 0 Link Up` |
| TC-A.G2.3 | BSD stack init keywords | log contains `ipfw2 (+ipv6) initialized` + `tcp_bbr is now available` + `f-stack-0: Successed to register dpdk interface` |
| TC-A.G2.4 | 0 SIGSEGV / panic / abort | grep `-iE 'sigsegv\|panic\|fatal\|abort'` = 0 hits |
| TC-A.G2.5 | 0 stub-called keywords | grep `'stub called'` = 0 hits |
| TC-A.G2.6 | DPDK version banner | log contains `DPDK 24.11.6` or `RTE Version: ...24.11...` |

### 3.3 G3 Functional Acceptance

```bash
# on the server side (DPDK primary running)
ssh f-stack-client 'curl -sS -o /dev/null -w "%{http_code} %{size_download}\n" --connect-timeout 5 http://<DPDK_NIC_IP>/'
# Expected: 200 <body_size>

# 100x short connections
ssh f-stack-client 'OK=0; for i in $(seq 1 100); do
    CODE=$(curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 http://<DPDK_NIC_IP>/)
    [ "$CODE" = 200 ] && OK=$((OK+1))
done; echo $OK/100'
# Expected: 100/100
```

| AC | Check | PASS Condition |
|---|---|---|
| TC-A.G3.1 | single HTTP 200 + body | `200 <size>` and size > 0 |
| TC-A.G3.2 | 100x short connections | `100/100` |

---

## 4. TC-B — helloworld Single-Process Performance (curl-bench)

### 4.1 Methodology (reusing phase-5b)

- harness: `tools/sbin/p5b_perf_matrix.sh`
- client: `f-stack-client (<CLIENT_IP>)`
- single trial: N serial curls from f-stack-client
- run 3 trials per config, take median + max-min jitter
- ssh round-trip ~6 ms is the physical ceiling (consistent with phase-5b; this test does not pursue absolute throughput)

### 4.2 Test Cases

| Sub-TC | Command | Expectation |
|---|---|---|
| TC-B.1 (100 short connections) | `time { for i in $(seq 1 100); do curl ... ; done; }` × 3 | median ≤ 23.11.5 baseline + 5% (NFR-D-1) |
| TC-B.2 (1000 short connections) | `time { for i in $(seq 1 1000); do curl ... ; done; }` × 3 | same as above |

### 4.3 G4 Perf Acceptance

| AC | Check | PASS Condition |
|---|---|---|
| TC-B.G4.1 | 100 short-connection trade-off | median(24) / median(23) ≤ 1.05 |
| TC-B.G4.2 | 1000 short-connection trade-off | same as above |
| TC-B.G4.3 | pass_rate | 100/100 + 1000/1000 |
| TC-B.G4.4 | jitter | (max - min) / median ≤ 0.20 |

When trade-off > 5%, follow the phase-5b OQ-2 rule: downgrade to an observation label + spec-author threshold revision or user decision.

### 4.4 Archiving

CSV: `/tmp/dpdk24_TC-B_curl_bench.csv` + the 23 baseline reference `m1_23_perf.csv`.

---

## 5. TC-C — nginx Single-Process Function

### 5.1 nginx Single-Process Config

```nginx
# /data/workspace/f-stack/app/nginx-1.28.0/conf/nginx_dpdk24_single.conf
worker_processes 1;
fstack_conf ../../../config.ini;

events {
    worker_connections 1024;
    use kqueue;
}

http {
    server {
        listen 80;
        server_name _;
        location / {
            return 200 "Hello from nginx single-worker on DPDK 24.11.6\n";
        }
    }
}
```

### 5.2 Startup

```bash
cd /data/workspace/f-stack/app/nginx-1.28.0
setsid sudo ./objs/nginx -p . -c conf/nginx_dpdk24_single.conf </dev/null > /tmp/dpdk24_TC-C_nginx.log 2>&1 &
sleep 12
NGINX_PID=$(ps -ef | grep 'nginx_fstack\|nginx -p' | grep -v grep | grep -v worker | awk '{print $2}' | head -1)
```

### 5.3 G2 / G3 Acceptance

| AC | Check | PASS Condition |
|---|---|---|
| TC-C.G2.1 | nginx master alive | `[ -d /proc/$NGINX_PID ]` true |
| TC-C.G2.2 | DPDK + BSD init same as TC-A | log contains `Successed to register dpdk interface` |
| TC-C.G3.1 | single curl HTTP 200 | `Hello from nginx single-worker on DPDK 24.11.6` |
| TC-C.G3.2 | 100x short connections | 100/100 PASS |
| TC-C.G3.3 | 0 fatal in nginx internal error.log | nginx internal error.log has 0 fatal/segfault |

---

## 6. TC-D — nginx Single-Process Performance

### 6.1 Test Method

If the client has wrk:
```bash
ssh f-stack-client 'wrk -t1 -c10 -d30s http://<DPDK_NIC_IP>/ 2>&1' | tail -10
```
otherwise degrade to the 100/1000 short-connection curl loop (same as TC-B).

### 6.2 G4 Acceptance

| AC | Check | PASS Condition |
|---|---|---|
| TC-D.G4.1 | wrk req/sec (if available) | ≥ 23.11.5 baseline × 0.95 |
| TC-D.G4.2 | curl loop trade-off (degraded path) | same as TC-B.G4.1 / 4.2 |

---

## 7. TC-E — nginx Multi-Process Function (**key verification of 92718178b + 62f1c34df**)

### 7.1 nginx Multi-Process Config

```nginx
worker_processes 4;
fstack_conf ../../../config.ini;
# ... rest same as TC-C
```

### 7.2 Startup + Verification

```bash
cd /data/workspace/f-stack/app/nginx-1.28.0
setsid sudo ./objs/nginx -p . -c conf/nginx_dpdk24_multi.conf </dev/null > /tmp/dpdk24_TC-E_nginx.log 2>&1 &
sleep 18  # multi-worker init takes longer
ps -ef | grep nginx | grep -v grep
# Expected: 1 master + 4 workers (bound by lcore)
```

### 7.3 G3 Acceptance

| AC | Check | PASS Condition |
|---|---|---|
| TC-E.G3.1 | master + 4 workers all alive | ps grep shows 5 nginx processes |
| TC-E.G3.2 | single curl HTTP 200 | 200 |
| TC-E.G3.3 | 100x short connections | 100/100 |

### 7.4 92718178b Patch Effectiveness Verification

```bash
# Step 1: take one worker PID (secondary process)
WORKER_PID=$(ps -ef | grep 'nginx: worker' | grep -v grep | awk '{print $2}' | head -1)

# Step 2: SIGTERM this worker (simulate secondary exit)
/data/workspace/kill_process.sh $WORKER_PID

# Step 3: check whether the master is still alive and still responds to curl
sleep 5
[ -d /proc/$NGINX_MASTER_PID ] && echo "Master alive after worker exit ✓"
ssh f-stack-client 'curl -sS http://<DPDK_NIC_IP>/ -w "%{http_code}\n" -o /dev/null'
# Expected 200
```

| AC | Check | PASS Condition |
|---|---|---|
| TC-E.G3.4 | master alive after worker exit | `[ -d /proc/$NGINX_MASTER_PID ]` true |
| TC-E.G3.5 | still can curl HTTP 200 | 200 |
| TC-E.G3.6 | master log has 0 abort/SIGSEGV | grep 0 hits |

→ These ACs verify the `92718178b` patch is effective on 24.11.6 (secondary exit does not reset shared devices).

### 7.5 62f1c34df Patch Effectiveness Verification (reload test)

```bash
# nginx -s reload simulates a secondary restart
sudo ./objs/nginx -p . -c conf/nginx_dpdk24_multi.conf -s reload
sleep 12

# verify the new workers bring up the stack, no timer infinite loop
ps -ef | grep 'nginx: worker' | grep -v grep
# Expected: 4 workers all newly started
```

| AC | Check | PASS Condition |
|---|---|---|
| TC-E.G3.7 | 4 new workers all started after reload | ps shows 4 workers, PIDs differ from before reload |
| TC-E.G3.8 | 100x short connections after reload | 100/100 |
| TC-E.G3.9 | no timer infinite-loop keywords in log | grep `-iE 'timer.*infinite\|stuck\|hang'` = 0 hits |

→ These ACs verify the `rte_timer_meta_init()` of the `62f1c34df` patch is effective on 24.11.6 (secondary restart clears the priv_timer state).

---

## 8. TC-F — nginx Multi-Process wrk Functional (no horizontal-scaling evaluation)

### 8.1 Test Method

```bash
ssh f-stack-client 'wrk -t1 -c20 -d10s http://<DPDK_NIC_IP>/ 2>&1' | tail -10
```

### 8.2 G3 Acceptance (functional only)

| AC | Check | PASS Condition |
|---|---|---|
| TC-F.G3.1 | wrk completes with no connection errors | wrk output `Socket errors: connect 0, read 0, write 0, timeout 0` |
| TC-F.G3.2 | wrk has at least 1 HTTP 200 | wrk output `Non-2xx or 3xx responses: 0` |
| TC-F.G3.3 | nginx master + 4 workers all alive | ps grep shows 5 nginx processes |

> **Note**: this TC does **not** evaluate wrk's req/sec, rps-linear-scaling-with-worker-count, or other horizontal-scaling performance metrics. Those metrics are completed by the user later in a physical-machine environment. This TC only verifies that multiple workers serving concurrent requests **function correctly**.

---

## 9. TC-G — F-Stack Historical Capability Single-Pass Smoke

### 9.1 Scope

Per the plan §1.5 table, the 7 FF_* flags enabled in F-Stack phase-2 + the vlan-test config get a single-pass smoke on 24.11.6:

| Sub-TC | Test | Expectation |
|---|---|---|
| TC-G.1 | FF_NETGRAPH + FF_IPFW (M6 P0) | helloworld brings up the stack + `tools/sbin/ipfw show` lists default rules |
| TC-G.2 | FF_USE_PAGE_ARRAY (M7 P1a) + stable after the F-A1 fix | helloworld brings up the stack + 100x curl 100/100 |
| TC-G.3 | FF_ZC_SEND (M8 P1b) | helloworld_zc brings up the stack + 100x curl HTTP 200 |
| TC-G.4 | PA + ZC combo (M9 P1c) | same as above |
| TC-G.5 | FF_FLOW_IPIP (M10 P1d) | helloworld brings up the stack + GIF tunnel ping works (if configurable on the client side) |
| TC-G.6 | FF_LOOPBACK_SUPPORT (M13 P2c) | helloworld brings up the stack |
| TC-G.7 | VLAN + vip + ipfw_pr | reuse `vlan_test_validate.sh G2 + G3` (must PASS clone_ok=2 + 0 vip fail + ipfw show contains setfib rules) |

### 9.2 G3 Acceptance

Each sub-TC executes within 5 min; on any failure:

| Handling | Trigger Condition |
|---|---|
| **downgrade to observation** | ≤ 3 sub-TCs fail, with clear root causes (e.g. NIC hardware dependency) |
| **bounce → coder** | ≥ 4 sub-TCs fail, with root causes possibly in the DPDK 24 upgrade |
| **split into an independent phase** | a single sub-TC fails with a complex root cause (e.g. PA interaction with 24 mbuf field adjustments), not blocking the main upgrade |

### 9.3 Command Example (TC-G.7 vlan-test)

```bash
cd /data/workspace/f-stack
# reuse the vlan-test harness (already in place)
bash tools/sbin/vlan_test_validate.sh G2 2>&1 | tee /tmp/dpdk24_TC-G7_vlan.log
sleep 3
bash tools/sbin/vlan_test_validate.sh G3 2>&1 | tee -a /tmp/dpdk24_TC-G7_vlan.log
```

Expected G2 + G3 all PASS (consistent with the vlan-test project conclusion).

---

## 10. Acceptance Gates G1 / G5 / G6 / G7 (implementation-phase supplements)

| Gate | Acceptance | Failure Handling |
|---|---|---|
| **G1** build | see the 04 §M2 / M4 ACs | bounce → coder |
| **G5** doc | 04 §M6 ACs (top-level doc sync) | doc-updater |
| **G6** lint | `read_lints` 0 errors | doc-updater |
| **G7** commit | 04 §8.2 commit form (3-4 commits) | leader |

---

## 11. Performance Baseline 23 vs 24 Comparison Archiving (after M5 completes)

`/data/workspace/f-stack/docs/dpdk_23_24_upgrade_spec/baseline_data/perf_compare.md`:

| Test | 23.11.5 median (s) | 24.11.6 median (s) | Δ % | Threshold | PASS? |
|---|---|---|---|---|---|
| TC-B.1 (100 short connections) | (archived in M1) | (measured in M5) | calculated | ≤ +5% | Y/N |
| TC-B.2 (1000 short connections) | same as above | same as above | same | same | same |
| TC-D wrk req/sec | same as above | same as above | same | ≥ 0.95× | same |

---

## 12. Observation Label Management

Per the same phase-5b OQ-2 rule, when the performance trade-off is > 5% but < 10%:

- label `observation`, does **not block** the spec / implementation completion
- the spec-author adds a note in 04-port-and-impl.md §6.1: `Known perf observation: TC-X +N% vs baseline; reason: <hypothesis>`
- at Phase 2 completion the user decides: (a) accept (b) split an independent phase for optimization (c) revise the NFR-D-1/D-2 thresholds

---

## 13. Document Meta-Information

- **Status**: v0.1 DRAFT — pending gate-keeper review
- **Left for Phase 2 measurement**: performance baseline data and 24 comparison, whether wrk is available on the client, whether the specific binaries for each TC-G sub-TC are ready
- **Next**: the gate-keeper produces `99-review-report.md` reviewing this spec and the 4 upstream documents for consistency / completeness / risk coverage / executability
