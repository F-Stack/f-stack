# 16 · CMocka Test Spec

> Methodology references c-unittest-expert (Unity ideas are general), API uses CMocka (assert_int_equal replaces TEST_ASSERT_EQUAL_INT etc.). Framework aligns with existing tests/unit + tests/integration paradigm.

## 1. Test Layering
| Layer | Location | Goal | Dependency |
|---|---|---|---|
| Unit | tests/unit/test_ff_zc_recv.c | pure logic of ff_zc_mbuf_read/segment/free (mock mbuf chain) | cmocka + rte_stub |
| Integration | tests/integration/test_ff_zc_recv_integration.c | ff_zc_recv full chain (real EAL + socketpair/loopback or net_ring injection) | cmocka + real DPDK EAL |

## 2. Test Framework Paradigm (aligned with existing)
- Headers: `#include <stdarg.h> <stddef.h> <setjmp.h> <cmocka.h>` + rte/ff headers (reference test_ff_dpdk_kni.c:20-37).
- Registration: `cmocka_unit_test_setup_teardown(tc, setup, teardown)` + `cmocka_run_group_tests`.
- Makefile: imitate `test_ff_dpdk_kni:` (Makefile:227) add per-target rule + into P3_TESTS; ZC cases need to build the unit-under-test with `-DFSTACK_ZC_RECV`.
- Naming convention: `test_<func>_<scenario>_<expected>` (following Stage-7/8).
- Cleanup: temporary files via rm_tmp_file.sh; valgrind 0 definite leak gate (make check).

## 3. Unit Cases (ff_zc_mbuf_read/segment/free, mock mbuf chain)
| Case | Scenario | Assertion |
|---|---|---|
| test_zc_segment_single_mbuf_returns_data | single mbuf chain | assert_int_equal(slen, m_len); seg points to mtod |
| test_zc_segment_multi_mbuf_walks_chain | multi-segment chain | multiple segment calls return each segment in order; finally returns 0 |
| test_zc_segment_after_free_returns_error | segment after free | assert_int_equal(rv, -1) (bsd_mbuf already zeroed) |
| test_zc_mbuf_read_copyout_correct | Plan 1 copy read out | out content matches source; off accumulates correctly |
| test_zc_recv_free_idempotent_on_null | bsd_mbuf==NULL | does not crash (no-op) |
| test_zc_recv_free_releases_all_segs | multi-segment release | mock ext_free call count == number of segments |
| test_zc_segment_off_overflow_guard | off+len>len | boundary returns 0/-1, no out-of-bounds |

## 4. Integration Cases (ff_zc_recv full chain, real EAL)
| Case | Scenario | Assertion |
|---|---|---|
| test_ff_zc_recv_basic_tcp | loopback/socketpair receive one segment of data | rv==sent bytes; zm.bsd_mbuf non-NULL; segment data matches sent |
| test_ff_zc_recv_multi_segment | data larger than a single mbuf | multi-segment segment concatenation == original data |
| test_ff_zc_recv_then_free_no_leak | recv+free loop N times | rte_mempool_in_use_count returns to baseline (no leak) |
| test_ff_zc_recv_peek_fallback | MSG_PEEK | degrades to copy path, data correct (no ZC benefit but correct) |
| test_ff_zc_recv_nonblock_eagain | non-blocking with no data | rv==-1 && errno==EAGAIN; zm has no chain |
| test_ff_zc_recv_conn_closed | peer closed | rv==0; zm has no chain |
| test_ff_zc_recv_split_mbuf_correct | requested length falls inside mbuf | m_copym fallback; data correct; free correct |
| test_ff_zc_recv_udp_fallback | UDP socket | equivalent to ordinary recv (correct) |

## 5. Mock / Isolation Strategy
- Unit layer: mock `m_freem`/`ext_free` count (cmocka `will_return`/`expect_*`/`mock()`), construct struct mbuf chain on the stack (imitate test_ff_dpdk_pcap's stack mbuf).
- Integration layer: real EAL (--no-huge --no-pci), inject data via socketpair or net_ring; if EAL init fails then skip() (imitate test_ff_dpdk_kni group_setup).
- Leak detection: `rte_mempool_in_use_count(pool)` before/after comparison + valgrind.

## 6. Coverage Goals
- ff_zc_mbuf_read/segment/free: line/branch ≥ 90%.
- ff_zc_recv: full-chain success + 5 categories of boundaries (peek/nonblock/closed/split/udp).
- Memory safety: valgrind 0 definite leak; mempool inuse count closed.
