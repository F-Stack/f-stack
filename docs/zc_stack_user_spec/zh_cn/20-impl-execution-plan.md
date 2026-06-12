# 20 · 实现执行计划（FSTACK_ZC_RECV）

> 依据 spec 10-19。本阶段开始写实现代码。所有改动 `#ifdef FSTACK_ZC_RECV` 门控，默认不启用 → 现有构建零影响。
> 铁律：每步实际编译验证；改动以 spec 为蓝本但以实际代码/编译结果为准。

## 执行顺序（M0→M1→M2，M3-M5 后续）
| 步 | 里程碑 | 改动文件 | 退出条件 |
|---|---|---|---|
| 1 | 构建基线 | —— | 确认 lib 当前可编译（或记录现状）|
| 2 | M0-内核 | freebsd/kern/uipc_syscalls.c（+ 声明）| kern_zc_recvit 编译通过 |
| 3 | 开关 | lib/Makefile | FF_ZC_RECV→FSTACK_ZC_RECV |
| 4 | M1-API 声明 | lib/ff_api.h | ff_zc_recv/ff_zc_recv_free/ff_zc_mbuf_read 声明 |
| 5 | M1-用户态 | lib/ff_syscall_wrapper.c（ff_zc_recv）、lib/ff_veth.c（read 重写 + free）| 编译通过 |
| 6 | 构建验证 | —— | FSTACK_ZC_RECV=1 编译通过；默认编译不回归 |
| 7 | M2/测试 | tests/ | 后续 |

## 防回归
- 所有新增代码 `#ifdef FSTACK_ZC_RECV`；
- 不改 soreceive 核心、不改原 kern_recvit/soo_read；
- 默认（不定义 FF_ZC_RECV）构建与改动前一致。
