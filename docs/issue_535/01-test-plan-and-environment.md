# 01 — Test Plan and Environment

## Test Environment

### Hardware

- **CPU**: 16 lcores (local machine)
- **NIC**: Dual NIC, DPDK exclusive NIC (IP: <DPDK_NIC_IP>), different from eth1
- **DPDK**: 24.11.6 LTS
- **FreeBSD**: 15.0 userspace protocol stack

### Software

- **f-stack**: dev branch, based on FreeBSD 15.0 + DPDK 24.11.6
- **FF_IPFW**: Enabled in `lib/Makefile` (`FF_IPFW=1`, `FF_NETGRAPH=1`)
- **ff_ipfw tool**: `tools/sbin/ipfw` (DPDK secondary process)
- **helloworld**: `example/helloworld` (DPDK primary process, FF_IPFW compiled in)

### Test Machines

- **Local**: f-stack server, DPDK NIC IP <DPDK_NIC_IP>
- **f-stack-client**: Load generator client, connected via ssh, wrk 4.0.2 at `/data/wrk/wrk`

### config.ini (During Testing)

| Parameter | IPFW Reproduction Test | Performance Regression Test |
|-----------|----------------------|---------------------------|
| lcore_mask | 1 (default) | 10 (aligned with baseline) |
| idle_sleep | 0 (default) | 20 (aligned with baseline) |
| port_list | 0 | 0 |

**Note**: config.ini local test values are not committed; restored to original values after testing.

## Reproduction Plan

### Goal

Verify the scenario described in issue #535: IPFW rule count >400 causes `ff_ipfw list` to fail.

### Steps

1. Start helloworld primary process (`example/helloworld -c config.ini`)
2. Wait for DPDK initialization (~18 seconds)
3. `tools/sbin/ipfw -P 0 flush` to clear existing rules
4. Add IPFW rules one by one: `tools/sbin/ipfw -P 0 add <num> allow tcp from any to any`
5. Execute `tools/sbin/ipfw -P 0 list` to retrieve all rules (triggers GET path)
6. Binary search to find the exact breaking point

### Pass/Fail Criteria

- `list` returns "ipfw: retrieving config failed: Invalid argument" = EINVAL failure (bug reproduced)
- `list` outputs all rules normally = success

## Fix Verification Plan

### Goal

Verify that after the fix, large IPFW rule sets (252/500/1000 rules) can be listed normally.

### Steps

1. `make clean && make` to rebuild ff_ipfw tool
2. Start helloworld primary process
3. Add specified number of rules
4. Execute `list` to verify all rules output normally
5. Compare with pre-fix breaking point (252 rules)

## Performance Regression Plan

### Goal

Verify the fix does not introduce TCP data-plane performance regression.

### Steps

1. Align config.ini with previous baseline test config (lcore_mask=10, idle_sleep=20)
2. Start helloworld primary process
3. T1 warmup: `wrk -t2 -c10 -d5s --latency http://<DPDK_NIC_IP>:80/`
4. T2 Trial 1: `wrk -t4 -c100 -d30s --latency http://<DPDK_NIC_IP>:80/`
5. 30-second interval for TIME_WAIT recycling
6. T2 Trial 2: `wrk -t4 -c100 -d30s --latency http://<DPDK_NIC_IP>:80/`
7. Compare with baseline: previous #331 fix 1-core T2 median = 193,405 req/s, p99 = 762us

### Pass/Fail Criteria

- Throughput deviation < 6% (cross-day noise range documented in baseline report)
- No significant p99 latency degradation
