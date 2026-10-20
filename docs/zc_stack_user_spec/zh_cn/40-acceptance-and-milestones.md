# 40. 验收条件与实施里程碑

> 本期 spec 阶段产出 = 30-39 + 49 文档集；实施期（M0-M5）独立 plan 启动
> AC 是实施期完工判据，里程碑是实施期任务分解

---

## §1 验收条件（AC）

### AC1 编译干净

| 编译组合 | 期望 |
|---|---|
| 默认（不带 FF_ZC_*）| `-Werror` clean，rc=0 |
| `FF_ZC_SEND=1` | `-Werror` clean，rc=0 |
| `FF_ZC_RECV=1` | `-Werror` clean，rc=0（与 ZC-recv 共存）|
| `FF_ZC_SEND=1 FF_ZC_RECV=1` | `-Werror` clean，rc=0 |

验证方法：
```
cd lib
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make clean
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig <FLAGS> make
```

### AC2 功能 PASS

| 测试 | 期望 |
|---|---|
| `ff_zc_mbuf_get` 后 chain 头有 M_PKTHDR | unit test U1 PASS |
| 多次 `ff_zc_mbuf_write` 累加 pkthdr.len | unit test U5 PASS |
| `ff_zc_send` 经 `kern_zc_sendit → sosend(top)` 链路成功 | integration I1/I2 PASS |
| example/main_zc.c **零修改** + curl http=200 | E2E PASS |
| 与 `FSTACK_ZC_RECV` 共存（main_zc 同时启 send+recv） | E2E PASS |

### AC3 性能持平（Δ ≤ ±3% 噪声内）

| 对比 | wrk 档 | 通过判据 |
|---|---|---|
| B-new vs A baseline | T1/T2/T3 | Requests/sec Δ ≤ ±3% |
| B-new vs B-old（魔改版） | T1/T2/T3 | Requests/sec Δ ≤ ±3% |
| Latency p50/p90/p99 | T2 | Δ ≤ ±5% |
| 错误率 | 全档 | Socket errors / Non-2xx = 0 |

详见 38-perf-baseline-spec.md。

### AC4 内核 diff 收缩

| diff base | 范围 | 期望差异 |
|---|---|---|
| vanilla FreeBSD 15.0 sys/kern/uipc_mbuf.c | m_uiotombuf 函数 | **0 行差异**（回归 vanilla）|
| vanilla FreeBSD 15.0 sys/sys/mbuf.h | FSTACK_ZC_MAGIC 区段 | **0 行差异**（已删除）|
| vanilla FreeBSD 15.0 sys/kern/sys_generic.c | dofilewrite uio_offset | **0 行差异** |
| vanilla FreeBSD 15.0 sys/kern/uipc_syscalls.c | recvit / sendit / sousrsend | 0 行差异 |
| vanilla FreeBSD 15.0 sys/kern/uipc_syscalls.c | 整体 | **+kern_zc_recvit + kern_zc_sendit 两个新函数**，无其他修改 |
| vanilla FreeBSD 15.0 sys/sys/syscallsubr.h | 整体 | +2 个声明（kern_zc_recvit 已落地 + kern_zc_sendit 新增），无其他修改 |

### AC5 内存安全

| 测试 | 期望 |
|---|---|
| valgrind 对 ff_zc_send + EPIPE 100 次 | 0 definite leak |
| `rte_mempool_in_use_count` 前后 | 闭合（差 0）|
| 入参错误（top NULL / 无 PKTHDR）下 mock m_freem 计数 | 与 spec INV-3 一致 |

### AC6 spec 文档完整

| 文档 | 状态 |
|---|---|
| 30-spec-overview ~ 40-acceptance-and-milestones | 全部落盘 |
| 49-spec-review | 含 gatekeeper 抽检表 + bounce counter |
| 全部交叉引用准确（行号容差 ±5）| gatekeeper PASS |
| spec 文档无直接 rm/kill/chmod 命令 | grep 0 命中 |

---

## §2 实施期里程碑（M0-M5，独立 plan 启动）

### M0 — 内核新增 + 删除清单（kern_zc_sendit + 5 处 DELETE）

| 子任务 | 文件 | 验证 |
|---|---|---|
| 0.1 加 kern_zc_sendit 声明 | freebsd/sys/syscallsubr.h | 编译通过 |
| 0.2 加 kern_zc_sendit 实现 | freebsd/kern/uipc_syscalls.c | 编译通过 |
| 0.3 删除 FSTACK_ZC_MAGIC 宏 | freebsd/sys/mbuf.h | 编译通过（旧 ff_zc_send 已删，无引用残留）|
| 0.4 回退 m_uiotombuf 至 vanilla | freebsd/kern/uipc_mbuf.c | 与 vanilla diff = 0（在 m_uiotombuf 区）|
| 0.5 删除 sys_generic.c uio_offset 守护 | freebsd/kern/sys_generic.c | 编译通过 |

里程碑出口：`PKG_CONFIG_PATH=... FF_ZC_SEND=1 make clean && make` 在 lib/ 通过；libfstack.a 含 `T kern_zc_sendit` 符号。

### M1 — 用户态 API 重写 + M_PKTHDR 修复

| 子任务 | 文件 | 验证 |
|---|---|---|
| 1.1 重写 ff_zc_send | lib/ff_syscall_wrapper.c | 编译；nm 含 ff_zc_send |
| 1.2 修复 ff_zc_mbuf_get（加 M_PKTHDR）| lib/ff_veth.c | 编译；unit U1 PASS |
| 1.3 修复 ff_zc_mbuf_write（维护 pkthdr.len）| lib/ff_veth.c | 编译；unit U5 PASS |
| 1.4 删除 ff_write/ff_writev opt-out | lib/ff_syscall_wrapper.c | 编译；grep 0 命中 |
| 1.5 更新 ff_api.h 文档块 | lib/ff_api.h | 文档级 |

里程碑出口：`example/helloworld_zc` 重编通过；smoke curl http=200。

### M2 — 单元测试

| 子任务 | 内容 | 验证 |
|---|---|---|
| 2.1 新建 tests/unit/test_ff_zc_send.c | U1-U12 全用例 | 12 PASS |
| 2.2 Makefile 加 test_ff_zc_send + per-target -DFSTACK_ZC_SEND + --wrap=kern_zc_sendit | tests/unit/Makefile | 编译 + 链接 PASS |
| 2.3 INV 安全用例 L1-L2（mock m_freem）| 同上 | PASS |
| 2.4 valgrind unit test | make check | 0 leak |
| 2.5 覆盖率 | gcov | ff_zc_mbuf_get/write/send ≥ 90% line |

### M3 — 集成测试

| 子任务 | 内容 | 验证 |
|---|---|---|
| 3.1 新建 tests/integration/test_ff_zc_send_integration.c | I1-I10 | PASS |
| 3.2 真 EAL + loopback 路径 | 仿 ZC-recv | PASS |
| 3.3 INV 安全用例 L3-L5（valgrind + mempool 计数）| 同 | 0 leak + 闭合 |
| 3.4 issue #712 场景大包测试 | 4KB / 64KB / 1MB | B-new 不 crash |

### M4 — E2E 性能基线

| 子任务 | 内容 | 验证 |
|---|---|---|
| 4.1 启动 server A baseline；wrk T1/T2/T3 x3 取均值 | helloworld | 数据归档 21-perf-... |
| 4.2 启动 server B-new；wrk T1/T2/T3 x3 | helloworld_zc | Δ vs A ≤ ±3% |
| 4.3（可选）启动 server B-old；同上 | git checkout 旧版 | Δ vs B-new ≤ ±3% |
| 4.4 大 payload P2-P4 自定义 client | wrk + lua / 自实现 | B-new 不 crash |

### M5 — 收尾 + 文档归档

| 子任务 | 内容 | 验证 |
|---|---|---|
| 5.1 ratchet G8 阈值 | tests/unit/coverage_threshold.sh | gcov 通过 |
| 5.2 写实施期 review 文档 | docs/zc_stack_user_spec/zh_cn/4x-impl-review.md | gatekeeper PASS |
| 5.3 整批 commit（英文 msg） | git | ahead +N |
| 5.4 ratchet AC1-6 全 PASS 标注 | 49-spec-review 升级 | 完工 |

---

## §3 时间预估（参考；实际由实施期 plan 决定）

| 阶段 | 预估 |
|---|---|
| M0 | 0.5 天 |
| M1 | 0.5 天 |
| M2 | 1 天 |
| M3 | 1 天 |
| M4 | 0.5-1 天 |
| M5 | 0.5 天 |
| **合计** | **4-4.5 天** |

含 1 次门禁打回的弹性。

---

## §4 准入条件（实施期 plan 启动前必须）

- [ ] 本期 spec（30-49）全部落盘并经 gatekeeper PASS
- [ ] 49-spec-review.md 显示 bounce counter < 3 / 步骤
- [ ] 用户已审计/确认本期 spec（人工 review）
- [ ] 实施期 plan 据本 40 §2 里程碑分解为可执行 plan_create

---

## §5 准出条件（实施期完工）

- [ ] AC1-AC6 全 PASS
- [ ] 整批 commit（英文 msg）已 push 至 feature 分支
- [ ] 21/22-style 性能 + 实施 review 文档归档至 docs/zc_stack_user_spec/zh_cn/4x-
- [ ] 41+ 系列实施 review 落盘

---

下一篇：**49-spec-review.md**（门禁审核记录 + bounce counter）。
