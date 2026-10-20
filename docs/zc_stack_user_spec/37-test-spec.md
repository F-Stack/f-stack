# 37. CMocka Test Specification — ZC-send Nativization

> Style follows 16-test-spec (ZC-recv); methodology references c-unittest-expert (the Unity approach is general-purpose); API uses CMocka
> Framework aligns with the existing paradigm of tests/unit + tests/integration; when touching mbuf chain / sosend behavior, choose either mock or real EAL

---

## §1 Test Layering

| Layer | Location | Goal | Dependency |
|---|---|---|---|
| unit | `tests/unit/test_ff_zc_send.c` | pure logic of ff_zc_mbuf_get/write (M_PKTHDR / pkthdr.len / boundaries) + ff_zc_send input validation (mock kern_zc_sendit) | cmocka + rte_stub |
| integration | `tests/integration/test_ff_zc_send_integration.c` | full ff_zc_send chain (real EAL + loopback / net_ring injection) + kern_zc_sendit real run + sosend real path | cmocka + real DPDK EAL |
| E2E (end-to-end) | reuse example/main_zc.c | curl http=200 + wrk T1/T2/T3 | f-stack service process + ssh client |

---

## §2 Test Framework Paradigm (aligned with existing)

- Headers: `#include <stdarg.h> <stddef.h> <setjmp.h> <cmocka.h>` + ff/rte headers (reference `tests/unit/test_ff_dpdk_kni.c:20-37`).
- Registration: `cmocka_unit_test_setup_teardown(tc, setup, teardown)` + `cmocka_run_group_tests(...)`.
- Makefile: mirror `test_ff_dpdk_kni:` (Makefile:227) to add a per-target rule + add into `P3_TESTS`; ZC-send test cases need to compile the object under test with `-DFSTACK_ZC_SEND`.
- Naming convention: `test_<func>_<scenario>_<expected>` (following Stage-7/8).
- Cleanup: temporary files via `/data/workspace/rm_tmp_file.sh`; valgrind 0 definite leak gate (`make check`).
- Process cleanup: `/data/workspace/kill_process.sh`.

---

## §3 Unit Cases (mock kern_zc_sendit; pure logic)

| # | case | scenario | assertion |
|---|---|---|---|
| U1 | `test_ff_zc_mbuf_get_pkthdr_flag_set` | chain head has M_PKTHDR after get | `(mb->m_flags & M_PKTHDR) != 0` |
| U2 | `test_ff_zc_mbuf_get_initial_pkthdr_len_zero` | pkthdr.len=0 after get | `mb->m_pkthdr.len == 0` |
| U3 | `test_ff_zc_mbuf_get_negative_len_returns_error` | len < 0 | `assert_int_equal(rv, -1)` |
| U4 | `test_ff_zc_mbuf_get_zero_len_returns_minimal_chain` | len = 0 | rv=0; mb not NULL (max(len,1) protection) |
| U5 | `test_ff_zc_mbuf_write_accumulates_pkthdr_len` | multiple writes | `head->m_pkthdr.len == sum` |
| U6 | `test_ff_zc_mbuf_write_overflow_returns_error` | total > zm->len | `assert_int_equal(rv, -1)` |
| U7 | `test_ff_zc_mbuf_write_null_data_returns_error` | data == NULL | `rv == -1` |
| U8 | `test_ff_zc_mbuf_write_zero_len_noop` | len = 0 | rv=0; pkthdr.len unchanged |
| U9 | `test_ff_zc_send_mb_null_returns_einval` | mb==NULL | rv=-1 && errno=EINVAL (mock kern_zc_sendit not called) |
| U10 | `test_ff_zc_send_nbytes_overflow_returns_einval` | nbytes > INT_MAX | rv=-1 && errno=EINVAL |
| U11 | `test_ff_zc_send_calls_kern_zc_sendit_once` | normal call | mock kern_zc_sendit called once; arguments (fd, top, 0) correct |
| U12 | `test_ff_zc_send_propagates_kern_error` | kern_zc_sendit returns EPIPE | rv=-1 && errno=EPIPE |

---

## §4 Integration Cases (real EAL + loopback)

| # | case | scenario | assertion |
|---|---|---|---|
| I1 | `test_ff_zc_send_basic_tcp_loopback` | TCP socketpair / loopback; send 1KB | rv == 1024; peer recv content identical |
| I2 | `test_ff_zc_send_multi_segment` | data > single mbuf capacity (e.g. 16KB) | peer reassembles and receives 16KB identical |
| I3 | `test_ff_zc_send_then_no_leak` | send 1000-times loop | `rte_mempool_in_use_count` returns to baseline (no leak) |
| I4 | `test_ff_zc_send_eor_on_tcp_returns_einval` | TCP socket + MSG_EOR (requires ff_zc_send to expose flags to test; this phase fixes flags=0, so this case becomes: after kern_zc_sendit on the kernel side accepts a flags parameter, covered by a unit test) | rv=-1 && errno=EINVAL |
| I5 | `test_ff_zc_send_peer_closed_returns_epipe` | send after peer shutdown | rv=-1 && errno=EPIPE; SIGPIPE masked (SIG_IGN beforehand) |
| I6 | `test_ff_zc_send_nonblock_full_buf_returns_eagain` | non-blocking + sb filled up | rv=-1 && errno=EWOULDBLOCK |
| I7 | `test_ff_zc_send_udp_dgram` | UDP socket + < MTU | rv == n; peer recvfrom identical |
| I8 | `test_ff_zc_send_udp_emsgsize` | UDP + > MTU | rv=-1 && errno=EMSGSIZE |
| I9 | `test_ff_zc_send_after_unix_dgram` | UNIX-DGRAM | rv == n; peer identical |
| I10 | `test_ff_zc_send_zero_pkthdr_returns_zero` | top->m_pkthdr.len=0 (user sends directly after get without write) | rv == 0 (sosend takes resid=0) |

---

## §5 Memory Safety Test Matrix (INV-1 / INV-2 / INV-3)

| # | case | INV | method | assertion |
|---|---|---|---|---|
| L1 | `test_zc_send_no_pkthdr_returns_einval_kern` | INV-1 | unit + manually-built chain without M_PKTHDR → kern_zc_sendit | rv=-1 && errno=EINVAL; mock m_freem called once |
| L2 | `test_zc_send_negative_pkthdr_len_returns_einval` | INV-1 | manually build pkthdr.len = -1 | rv=-1 && errno=EINVAL; mock m_freem once |
| L3 | `test_zc_send_after_send_use_after_free_detected` | INV-2 | integration + valgrind | valgrind reports invalid read (in the spec-noted "access after send" scenario) |
| L4 | `test_zc_send_epipe_no_leak` | INV-3 | integration + valgrind --track-fds + 100 EPIPE | 0 definite leak; mempool count closed |
| L5 | `test_zc_send_dpdk_mempool_balanced` | INV-3 | `rte_mempool_in_use_count` before-after diff 0 | closed |

---

## §6 mock / Isolation Strategy

### §6.1 Unit layer

- **mock kern_zc_sendit**: at link time use `--wrap=kern_zc_sendit` + `__wrap_kern_zc_sendit` to replace with a cmocka mock (set `will_return` + `expect_value`).
- **mock m_freem**: at link time `--wrap=m_freem`; used in INV-3 to verify whether kern_zc_sendit calls it on input error.
- **stack mbuf chain**: mirror the stack mbuf construction helper of `tests/unit/test_ff_dpdk_pcap.c` (custom `make_test_mbuf_chain(payload_size)`).

### §6.2 Integration layer

- **real EAL**: `--no-huge --no-pci` (mirror `tests/integration/test_ff_zc_recv_integration.c`, commit 8a06862cd).
- **loopback / socketpair**: use `socketpair(AF_UNIX, SOCK_STREAM, 0, sv)`; TCP uses INADDR_LOOPBACK + ephemeral port.
- **EAL init failure**: call `skip()` (mirror `test_ff_dpdk_kni group_setup`).
- **mempool count**: record the baseline of `rte_mempool_in_use_count(pool)` in group_setup / group_teardown; closure check between cases.

---

## §7 Coverage Targets

| module | line coverage | branch coverage |
|---|---|---|
| `ff_zc_mbuf_get` | ≥ 95% | ≥ 90% (including len<0 / m_getm2 failure / normal) |
| `ff_zc_mbuf_write` | ≥ 95% | ≥ 90% (including NULL / 0 / overflow / multi-segment loop) |
| `ff_zc_send` | ≥ 95% | ≥ 90% (including mb=NULL / nbytes out of range / kern error propagation) |
| `kern_zc_sendit` | ≥ 90% | ≥ 80% (including input validation / getsock / MAC / sosend success / sosend error / SIGPIPE) |

Integration-layer cases **total ≥ 10**; unit-layer cases **total ≥ 12** (including INV safety cases).

---

## §8 Test Binary and Makefile Integration

### §8.1 unit additions

```
tests/unit/test_ff_zc_send.c            # new
tests/unit/Makefile                     # add test_ff_zc_send target + per-target -DFSTACK_ZC_SEND
                                        # add into the P3_TESTS list
                                        # add --wrap=kern_zc_sendit / --wrap=m_freem
```

### §8.2 integration additions

```
tests/integration/test_ff_zc_send_integration.c   # new
tests/integration/Makefile                        # add test_ff_zc_send_integration target + -DFSTACK_ZC_SEND
                                                  # EAL initialization + helloworld_zc_send mode
```

### §8.3 Reuse of existing ZC-recv integration

`tests/integration/test_ff_zc_recv_integration.c` (commit 8a06862cd) already established the EAL + loopback paradigm; the new ZC-send integration directly forks that template, replacing "receive→assert" with "send→peer recv assert".

---

## §9 Gatekeeper-Verifiable Clauses (gatekeeper)

| Clause | Verification method | Pass criterion |
|---|---|---|
| T-G1 | spec lists ≥12 unit cases | U1-U12+ |
| T-G2 | spec lists ≥10 integration cases | I1-I10+ |
| T-G3 | spec marks ≥3 INV safety cases | L1-L5 |
| T-G4 | spec marks the mock --wrap kern_zc_sendit pattern | §6.1 |
| T-G5 | spec marks valgrind 0 leak + mempool closure | §6.2 + L4-L5 |

---

Next: **38-perf-baseline-spec.md** (performance baseline specification).
