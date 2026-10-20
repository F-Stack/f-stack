# 16 · CMocka 测试规格

> 方法论参考 c-unittest-expert（Unity 思路通用），API 用 CMocka（assert_int_equal 替代 TEST_ASSERT_EQUAL_INT 等）。框架对齐现有 tests/unit + tests/integration 范式。

## 1. 测试分层
| 层 | 位置 | 目标 | 依赖 |
|---|---|---|---|
| 单元（unit）| tests/unit/test_ff_zc_recv.c | ff_zc_mbuf_read/segment/free 的纯逻辑（mock mbuf 链）| cmocka + rte_stub |
| 集成（integration）| tests/integration/test_ff_zc_recv_integration.c | ff_zc_recv 全链路（真 EAL + socketpair/loopback 或 net_ring 注入）| cmocka + 真 DPDK EAL |

## 2. 测试框架范式（对齐现有）
- 头：`#include <stdarg.h> <stddef.h> <setjmp.h> <cmocka.h>` + rte/ff 头（参考 test_ff_dpdk_kni.c:20-37）。
- 注册：`cmocka_unit_test_setup_teardown(tc, setup, teardown)` + `cmocka_run_group_tests`。
- Makefile：仿 `test_ff_dpdk_kni:`（Makefile:227）加 per-target 规则 + 入 P3_TESTS；ZC 用例需 `-DFSTACK_ZC_RECV` 构建被测对象。
- 命名规范：`test_<func>_<scenario>_<expected>`（沿用 Stage-7/8）。
- 清理：临时文件经 rm_tmp_file.sh；valgrind 0 definite leak 门禁（make check）。

## 3. 单元用例（ff_zc_mbuf_read/segment/free，mock mbuf 链）
| 用例 | 场景 | 断言 |
|---|---|---|
| test_zc_segment_single_mbuf_returns_data | 单 mbuf 链 | assert_int_equal(slen, m_len)；seg 指向 mtod |
| test_zc_segment_multi_mbuf_walks_chain | 多段链 | 多次 segment 依次返回各段；最后返回 0 |
| test_zc_segment_after_free_returns_error | free 后再 segment | assert_int_equal(rv, -1)（bsd_mbuf 已清零）|
| test_zc_mbuf_read_copyout_correct | 方案1 拷贝读出 | out 内容与源一致；off 累加正确 |
| test_zc_recv_free_idempotent_on_null | bsd_mbuf==NULL | 不崩溃（no-op）|
| test_zc_recv_free_releases_all_segs | 多段释放 | mock ext_free 被调用次数 == 段数 |
| test_zc_segment_off_overflow_guard | off+len>len | 边界返回 0/-1，不越界 |

## 4. 集成用例（ff_zc_recv 全链路，真 EAL）
| 用例 | 场景 | 断言 |
|---|---|---|
| test_ff_zc_recv_basic_tcp | loopback/socketpair 收一段数据 | rv==发送字节；zm.bsd_mbuf 非 NULL；segment 数据与发送一致 |
| test_ff_zc_recv_multi_segment | 大于单 mbuf 的数据 | 多段 segment 拼接 == 原数据 |
| test_ff_zc_recv_then_free_no_leak | recv+free 循环 N 次 | rte_mempool_in_use_count 回到基线（无泄漏）|
| test_ff_zc_recv_peek_fallback | MSG_PEEK | 退化为拷贝路径，数据正确（无 ZC 收益但正确）|
| test_ff_zc_recv_nonblock_eagain | 非阻塞无数据 | rv==-1 && errno==EAGAIN；zm 无链 |
| test_ff_zc_recv_conn_closed | 对端关闭 | rv==0；zm 无链 |
| test_ff_zc_recv_split_mbuf_correct | 请求长度落 mbuf 内部 | m_copym 回退；数据正确；free 正确 |
| test_ff_zc_recv_udp_fallback | UDP socket | 等价普通 recv（正确）|

## 5. mock / 隔离策略
- 单元层：mock `m_freem`/`ext_free` 计数（cmocka `will_return`/`expect_*`/`mock()`），用栈构造 struct mbuf 链（仿 test_ff_dpdk_pcap 的 stack mbuf）。
- 集成层：真 EAL（--no-huge --no-pci），用 socketpair 或 net_ring 注入数据；EAL init 失败则 skip()（仿 test_ff_dpdk_kni group_setup）。
- 泄漏检测：`rte_mempool_in_use_count(pool)` 前后对比 + valgrind。

## 6. 覆盖目标
- ff_zc_mbuf_read/segment/free：行/分支 ≥ 90%。
- ff_zc_recv：全链路成功 + 5 类边界（peek/nonblock/closed/split/udp）。
- 内存安全：valgrind 0 definite leak；mempool inuse 计数闭合。
