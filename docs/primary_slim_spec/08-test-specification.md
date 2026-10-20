# 08 - Test Specification

> Revision: 2026-08-07 per gate report R1/R6/R8 corrected C28 line numbers; 2026-08-10 updated KNI test cases per K4 preferred / K3-corrected fallback.

## Summary

Complete test specification for issue #1078 "primary-slim (S1)" production implementation, covering 38 change points from `07`. Test infrastructure: CMocka 1.1.7+, 12 test binaries + 47 ini fixtures, 2 real-EAL integration binaries. Output: **22 new unit test cases + 11 new fixtures + 12 cmocka integration cases + 12 hands-on script cases + 5 performance cases + 14 regression items + 18 acceptance criteria**.

## Key Conclusions

1. **Framework is CMocka (≥1.1.7)**, not Unity; follow existing patterns
2. **C09 (B1 relaxation) unreachable at unit test level**: `init_lcore_conf()` is `static`; must use integration harness
3. **mbuf pool equivalence has two layers**: unit (arithmetic) + integration (real pool size)
4. **Most important regression**: `primary_slim=0` + primary not in `lcore_list` must preserve `rte_exit`
5. **Scripts must be real**: actual execution + exit code aggregation + no real IPs

## I. Test Infrastructure

### Unit Tests (`tests/unit/`)
- 12 binaries: test_hello, test_ff_ini_parser, test_ff_log, test_ff_host_interface, test_ff_epoll, test_ff_config, test_ff_thread, test_ff_init, test_ff_dpdk_pcap, test_ff_dpdk_if, test_ff_dpdk_kni, test_ff_zc_send
- CMocka with `--wrap=rte_exit --wrap=rte_panic`
- Clean uses `/data/workspace/rm_tmp_file.sh`

### Integration Tests (`tests/integration/`)
- 2 real-EAL binaries: `test_dpdk_init` (primary) + `test_dpdk_init_secondary`
- Use `--no-huge --no-pci --vdev=net_null0`

## II. New Unit Test Cases (22)

| ID | Description | Binary | Change Point |
|----|-------------|--------|-------------|
| UT-1078-01 | `primary_slim=0` default | test_ff_config | C01 |
| UT-1078-02 | `primary_slim=1` parsing | test_ff_config | C01 |
| UT-1078-03 | `primary_slim_idle_sleep` default 1000 | test_ff_config | C02 |
| UT-1078-04 | `primary_slim_idle_sleep` parsing | test_ff_config | C02 |
| UT-1078-05 | `thread_mode=1` + `primary_slim=1` mutex | test_ff_config | C03 |
| UT-1078-06 | `nb_procs < 2` + `primary_slim=1` reject | test_ff_config | C04 |
| UT-1078-07 | `primary_slim=0` + primary not in lcore_list → rte_exit | test_ff_config | C09 |
| UT-1078-08 | `primary_slim=1` + primary not in lcore_list → no rte_exit | test_ff_config | C09 |
| UT-1078-09 | mbuf pool formula equivalence L=2 | test_ff_config | C10 |
| UT-1078-10 | mbuf pool formula equivalence L=8 | test_ff_config | C10 |
| UT-1078-11 | `ff_is_slim_primary()` true for slim primary | test_ff_dpdk_if | C12 |
| UT-1078-12 | `ff_is_slim_primary()` false for secondary | test_ff_dpdk_if | C12 |
| UT-1078-13 | `ff_is_slim_primary()` false for non-slim | test_ff_dpdk_if | C12 |
| UT-1078-14 | `owner_proc_id` parsing | test_ff_config | C20 |
| UT-1078-15 | `ff_kni_is_runtime_owner()` proc_id match | test_ff_dpdk_kni | C21 |
| UT-1078-16 | `ff_kni_is_runtime_owner()` thread_mode | test_ff_dpdk_kni | C21 |
| UT-1078-17 | `ff_kni_is_runtime_owner()` primary_slim=0 fallback | test_ff_dpdk_kni | C21 |
| UT-1078-18 | secondary `kni_stat` allocation | test_ff_dpdk_kni | C22 |
| UT-1078-19 | `total_nb_ports *= 2` condition | test_ff_dpdk_if | C24 |
| UT-1078-20 | broadcast gate `!pkts_from_ring` | test_ff_dpdk_if | C27 |
| UT-1078-21 | `ff_kni_process()` outside rx loop | test_ff_dpdk_if | C28 |
| UT-1078-22 | `nb_dev_ports` shared memzone | test_ff_dpdk_if | C29 |

### Unreachable at Unit Level (Integration Coverage)

| Change Point | Reason | Coverage |
|-------------|--------|----------|
| C09 | `init_lcore_conf()` static | IT-1078-03 |
| C10 | `init_mem_pool()` static | IT-1078-04 |
| C11 | `init_port_start()` static | IT-1078-05 |

## III. Integration Test Cases (12)

| ID | Description |
|----|-------------|
| IT-1078-01 | Slim primary starts without rte_exit |
| IT-1078-02 | Slim primary + secondary full send/receive |
| IT-1078-03 | `primary_slim=0` + primary not in lcore_list → rte_exit |
| IT-1078-04 | mbuf pool real size assertion |
| IT-1078-05 | `init_port_start` with slim primary |
| IT-1078-06 | KNI virtio_user port creation by primary |
| IT-1078-07 | Secondary probes virtio_user via vdev scan |
| IT-1078-08 | Secondary accesses shared KNI ring |
| IT-1078-09 | `ff_kni_process()` called by owner secondary |
| IT-1078-10 | Broadcast gate `!pkts_from_ring` |
| IT-1078-11 | `nb_dev_ports` shared memzone lookup |
| IT-1078-12 | KNI inject ring create/lookup |

## IV. Hands-on Script Cases (12)

| ID | Description | Acceptance |
|----|-------------|------------|
| ST-1078-01 | Slim primary startup | Process alive, no error |
| ST-1078-02 | 12/12 full send/receive | All ok |
| ST-1078-03 | Kill slim primary, connections survive | 12/12 zero interruption |
| ST-1078-04 | Kill slim primary, new connections | 12/12 |
| ST-1078-05 | `primary_slim=0` zero regression | Ping+HTTP normal |
| ST-1078-06 | KNI + primary_slim=1 | veth0 exists, ping works |
| ST-1078-07 | KNI off + primary_slim=1 | Ping+HTTP normal |
| ST-1078-08 | KNI inject ring no race | Ping via veth0 reply |
| ST-1078-09 | `ff_kni_enqueue` stat consistency | Stats correct |
| ST-1078-10 | Multi-process 3+ stability | 10min+ stable |
| ST-1078-11 | `owner_proc_id` config | KNI owner correct |
| ST-1078-12 | `ff_is_slim_primary()` API | Returns correct |

## V. Performance Cases (5)

| ID | Description | Acceptance |
|----|-------------|------------|
| PT-1078-01 | Slim primary CPU | < 5% with idle_sleep |
| PT-1078-02 | QPS slim primary alive | ≥ baseline × (1-noise) |
| PT-1078-03 | QPS after slim primary crash | ≥ baseline × (1-noise) |
| PT-1078-04 | KNI enabled performance | No regression |
| PT-1078-05 | Multi-process scaling | Near-linear |

## VI. Regression Items (14)

RG-1078-01 through RG-1078-14 covering: `primary_slim=0` zero change, `thread_mode=1` unaffected, KNI disabled unaffected, `kni_process_rx` direct tx_burst preserved, `kni_inject_rp` unused but exists, `ff_kni_is_owner_thread()` preserved, `ff_kni_is_runtime_owner()` fallback, `ff_kni_enqueue` stat consistency, maxsockets/somaxconn/syncache unaffected, TCP/UDP echo normal, `ff_ipc` tools normal, `ff_dpdk_run()` cleanup skip, `ff_dpdk_stop()` stop_loop, config validation chain.

## VII. Acceptance Criteria (18)

AC-1078-01 through AC-1078-18 covering: all unit/integration/script/performance/regression tests pass, `primary_slim=0` zero regression, slim primary starts, 12/12 send/receive, kill slim primary zero interruption, KNI enabled works, KNI inject ring no race, `owner_proc_id` correct, `ff_is_slim_primary()` correct, multi-process stable, config validation, no real IPs in docs, commit message English, config.ini not committed, make clean before build.
