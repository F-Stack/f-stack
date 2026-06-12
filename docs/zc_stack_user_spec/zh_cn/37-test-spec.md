# 37. CMocka 测试规格 — ZC-send 原生化

> 风格沿用 16-test-spec（ZC-recv）；方法论参考 c-unittest-expert（Unity 思路通用）；API 用 CMocka
> 框架对齐 tests/unit + tests/integration 现有范式；触及 mbuf 链/sosend 行为时 mock vs 真 EAL 二选一

---

## §1 测试分层

| 层 | 位置 | 目标 | 依赖 |
|---|---|---|---|
| 单元（unit）| `tests/unit/test_ff_zc_send.c` | ff_zc_mbuf_get/write 的纯逻辑（M_PKTHDR / pkthdr.len / 边界）+ ff_zc_send 入参校验（mock kern_zc_sendit）| cmocka + rte_stub |
| 集成（integration）| `tests/integration/test_ff_zc_send_integration.c` | ff_zc_send 全链路（真 EAL + loopback / net_ring 注入）+ kern_zc_sendit 实跑 + sosend 真路径 | cmocka + 真 DPDK EAL |
| E2E（端到端）| 复用 example/main_zc.c | curl http=200 + wrk T1/T2/T3 | f-stack 服务进程 + ssh client |

---

## §2 测试框架范式（对齐现有）

- 头文件：`#include <stdarg.h> <stddef.h> <setjmp.h> <cmocka.h>` + ff/rte 头（参考 `tests/unit/test_ff_dpdk_kni.c:20-37`）。
- 注册：`cmocka_unit_test_setup_teardown(tc, setup, teardown)` + `cmocka_run_group_tests(...)`。
- Makefile：仿 `test_ff_dpdk_kni:`（Makefile:227）加 per-target 规则 + 入 `P3_TESTS`；ZC-send 用例需 `-DFSTACK_ZC_SEND` 编译被测对象。
- 命名规范：`test_<func>_<scenario>_<expected>`（沿用 Stage-7/8）。
- 清理：临时文件经 `/data/workspace/rm_tmp_file.sh`；valgrind 0 definite leak 门禁（`make check`）。
- 进程清理：`/data/workspace/kill_process.sh`。

---

## §3 单元用例（mock kern_zc_sendit；纯逻辑）

| # | 用例 | 场景 | 断言 |
|---|---|---|---|
| U1 | `test_ff_zc_mbuf_get_pkthdr_flag_set` | get 后 chain 头有 M_PKTHDR | `(mb->m_flags & M_PKTHDR) != 0` |
| U2 | `test_ff_zc_mbuf_get_initial_pkthdr_len_zero` | get 后 pkthdr.len=0 | `mb->m_pkthdr.len == 0` |
| U3 | `test_ff_zc_mbuf_get_negative_len_returns_error` | len < 0 | `assert_int_equal(rv, -1)` |
| U4 | `test_ff_zc_mbuf_get_zero_len_returns_minimal_chain` | len = 0 | rv=0；mb 不为 NULL（max(len,1) 保护）|
| U5 | `test_ff_zc_mbuf_write_accumulates_pkthdr_len` | 多次 write | `head->m_pkthdr.len == sum` |
| U6 | `test_ff_zc_mbuf_write_overflow_returns_error` | total > zm->len | `assert_int_equal(rv, -1)` |
| U7 | `test_ff_zc_mbuf_write_null_data_returns_error` | data == NULL | `rv == -1` |
| U8 | `test_ff_zc_mbuf_write_zero_len_noop` | len = 0 | rv=0；pkthdr.len 不变 |
| U9 | `test_ff_zc_send_mb_null_returns_einval` | mb==NULL | rv=-1 && errno=EINVAL（mock kern_zc_sendit 不被调）|
| U10 | `test_ff_zc_send_nbytes_overflow_returns_einval` | nbytes > INT_MAX | rv=-1 && errno=EINVAL |
| U11 | `test_ff_zc_send_calls_kern_zc_sendit_once` | 正常调用 | mock kern_zc_sendit 被调 1 次；参数 (fd, top, 0) 正确 |
| U12 | `test_ff_zc_send_propagates_kern_error` | kern_zc_sendit 返 EPIPE | rv=-1 && errno=EPIPE |

---

## §4 集成用例（真 EAL + loopback）

| # | 用例 | 场景 | 断言 |
|---|---|---|---|
| I1 | `test_ff_zc_send_basic_tcp_loopback` | TCP socketpair / loopback；send 1KB | rv == 1024；对端 recv 内容一致 |
| I2 | `test_ff_zc_send_multi_segment` | 数据 > 单 mbuf 容量（如 16KB）| 对端拼接接收 16KB 一致 |
| I3 | `test_ff_zc_send_then_no_leak` | send 1000 次循环 | `rte_mempool_in_use_count` 回到基线（无泄漏）|
| I4 | `test_ff_zc_send_eor_on_tcp_returns_einval` | TCP socket + MSG_EOR（需 ff_zc_send 暴露 flags 才能测；本期固定 flags=0，则该用例改为：内核侧 kern_zc_sendit 接 flags 参数后由 unit test 覆盖）| rv=-1 && errno=EINVAL |
| I5 | `test_ff_zc_send_peer_closed_returns_epipe` | 对端 shutdown 后 send | rv=-1 && errno=EPIPE；SIGPIPE 被屏蔽（先 SIG_IGN）|
| I6 | `test_ff_zc_send_nonblock_full_buf_returns_eagain` | 非阻塞 + 填满 sb | rv=-1 && errno=EWOULDBLOCK |
| I7 | `test_ff_zc_send_udp_dgram` | UDP socket + < MTU | rv == n；对端 recvfrom 一致 |
| I8 | `test_ff_zc_send_udp_emsgsize` | UDP + > MTU | rv=-1 && errno=EMSGSIZE |
| I9 | `test_ff_zc_send_after_unix_dgram` | UNIX-DGRAM | rv == n；对端一致 |
| I10 | `test_ff_zc_send_zero_pkthdr_returns_zero` | top->m_pkthdr.len=0（用户 get 后未 write 直接 send）| rv == 0（sosend 取 resid=0）|

---

## §5 内存安全测试矩阵（INV-1 / INV-2 / INV-3）

| # | 用例 | INV | 方法 | 断言 |
|---|---|---|---|---|
| L1 | `test_zc_send_no_pkthdr_returns_einval_kern` | INV-1 | unit + 手构无 M_PKTHDR 链 → kern_zc_sendit | rv=-1 && errno=EINVAL；mock m_freem 被调 1 次 |
| L2 | `test_zc_send_negative_pkthdr_len_returns_einval` | INV-1 | 手构 pkthdr.len = -1 | rv=-1 && errno=EINVAL；mock m_freem 1 次 |
| L3 | `test_zc_send_after_send_use_after_free_detected` | INV-2 | integration + valgrind | valgrind 报 invalid read（在 spec 标注的"send 后访问"场景）|
| L4 | `test_zc_send_epipe_no_leak` | INV-3 | integration + valgrind --track-fds + 100 次 EPIPE | 0 definite leak；mempool 计数闭合 |
| L5 | `test_zc_send_dpdk_mempool_balanced` | INV-3 | `rte_mempool_in_use_count` 前后差 0 | 闭合 |

---

## §6 mock / 隔离策略

### §6.1 单元层

- **mock kern_zc_sendit**：链接期用 `--wrap=kern_zc_sendit` + `__wrap_kern_zc_sendit` 替换为 cmocka mock（设 `will_return` + `expect_value`）。
- **mock m_freem**：链接期 `--wrap=m_freem`；用于 INV-3 验证 kern_zc_sendit 入参错误时是否调用。
- **栈 mbuf 链**：仿 `tests/unit/test_ff_dpdk_pcap.c` 的 stack mbuf 构造 helper（自定义 `make_test_mbuf_chain(payload_size)`）。

### §6.2 集成层

- **真 EAL**：`--no-huge --no-pci`（仿 `tests/integration/test_ff_zc_recv_integration.c`，commit 8a06862cd）。
- **loopback / socketpair**：用 `socketpair(AF_UNIX, SOCK_STREAM, 0, sv)`；TCP 用 INADDR_LOOPBACK + ephemeral port。
- **EAL init 失败**：调 `skip()`（仿 `test_ff_dpdk_kni group_setup`）。
- **mempool 计数**：`rte_mempool_in_use_count(pool)` 在 group_setup / group_teardown 记录基线；用例间闭合校验。

---

## §7 覆盖目标

| 模块 | 行覆盖 | 分支覆盖 |
|---|---|---|
| `ff_zc_mbuf_get` | ≥ 95% | ≥ 90%（含 len<0 / m_getm2 失败 / 正常）|
| `ff_zc_mbuf_write` | ≥ 95% | ≥ 90%（含 NULL / 0 / overflow / 多段循环）|
| `ff_zc_send` | ≥ 95% | ≥ 90%（含 mb=NULL / nbytes 越界 / kern 错误传递）|
| `kern_zc_sendit` | ≥ 90% | ≥ 80%（含入参校验 / getsock / MAC / sosend 成功 / sosend 错误 / SIGPIPE）|

集成层用例**总数 ≥ 10**；单元层用例**总数 ≥ 12**（含 INV 安全用例）。

---

## §8 测试 binary 与 Makefile 集成

### §8.1 unit 新增

```
tests/unit/test_ff_zc_send.c            # 新建
tests/unit/Makefile                     # 加 test_ff_zc_send 目标 + per-target -DFSTACK_ZC_SEND
                                        # 加入 P3_TESTS 列表
                                        # 加 --wrap=kern_zc_sendit / --wrap=m_freem
```

### §8.2 integration 新增

```
tests/integration/test_ff_zc_send_integration.c   # 新建
tests/integration/Makefile                        # 加 test_ff_zc_send_integration 目标 + -DFSTACK_ZC_SEND
                                                  # EAL 初始化 + helloworld_zc_send 模式
```

### §8.3 现有 ZC-recv integration 复用

`tests/integration/test_ff_zc_recv_integration.c`（commit 8a06862cd）已建立 EAL + loopback 范式；新 ZC-send integration 直接 fork 该模板，把"接收→断言"换为"发送→对端 recv 断言"。

---

## §9 可门禁验证条款（gatekeeper）

| 条款 | 验证方式 | 通过判据 |
|---|---|---|
| T-G1 | spec 列出 ≥12 单元用例 | U1-U12+ |
| T-G2 | spec 列出 ≥10 集成用例 | I1-I10+ |
| T-G3 | spec 标注 ≥3 个 INV 安全用例 | L1-L5 |
| T-G4 | spec 标注 mock --wrap kern_zc_sendit 模式 | §6.1 |
| T-G5 | spec 标注 valgrind 0 leak + mempool 闭合 | §6.2 + L4-L5 |

---

下一篇：**38-perf-baseline-spec.md**（性能基线规格）。
