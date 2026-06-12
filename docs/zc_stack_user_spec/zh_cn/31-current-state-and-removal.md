# 31. 现状测绘与拆除清单 — `FSTACK_ZC_SEND` 旧路径全图

> 来源：probe-zcsend-current 子 agent 的实测报告（grep + read，全量 file:line:symbol 锚点）
> 范围：本 spec 规定**整体拆除**的全部内核与用户态触点（决策 A — 立即拆除）
> 用途：33-kernel-patch-spec / 34-userspace-api-spec 据此生成 c-precision-surgery 风格 patch

---

## §1 修改地图（17 处全量，按文件 + 行号 + 符号）

| # | 文件 | 行号 | 符号 / 上下文 | 类别 | 处置 |
|---|---|---|---|---|---|
| 1 | `freebsd/sys/mbuf.h` | 1856–1869 | `#ifdef FSTACK_ZC_SEND` 整段（含 `#define FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)`）| 哨兵宏 | **DELETE** |
| 2 | `freebsd/kern/uipc_mbuf.c` | 1955–2077 | `#ifndef FSTACK / #else` 13.0-era 简化版 `m_uiotombuf` 包 | 内核 fast-path | **DELETE**（连同 #3 一并）|
| 3 | `freebsd/kern/uipc_mbuf.c` | 2028–2049, 2070–2072 | `m_uiotombuf` 内部 `#ifdef FSTACK_ZC_SEND` 快路径分支 | 内核 fast-path 谓词 | **DELETE** |
| 4 | `freebsd/kern/sys_generic.c` | 57 | `#include <sys/mbuf.h>  /* M8: FSTACK_ZC_MAGIC for ZC fast-path */` | 头文件引入 | **DELETE**（如无其他依赖该 include）|
| 5 | `freebsd/kern/sys_generic.c` | 560–573 | `dofilewrite` 内 `#ifdef FSTACK_ZC_SEND` 哨兵保留 if/else | uio_offset 透传 | **DELETE** |
| 6 | `lib/ff_syscall_wrapper.c` | 32 | `#include <sys/mbuf.h>  /* M8: FSTACK_ZC_MAGIC for ff_zc_send */` | 头文件引入 | **保留**（仍需 `struct mbuf` 等类型）|
| 7 | `lib/ff_syscall_wrapper.c` | 1146–1151 | `ff_write` 内 `auio.uio_offset = 0;` opt-out + 5 行注释 | opt-out | **DELETE** |
| 8 | `lib/ff_syscall_wrapper.c` | 1175 | `ff_writev` 内 `auio.uio_offset = 0;` | opt-out | **DELETE** |
| 9 | `lib/ff_syscall_wrapper.c` | 1186–1226 | `#ifdef FSTACK_ZC_SEND ... ff_zc_send ... #endif` 整体（含 `auio.uio_offset = FSTACK_ZC_MAGIC` 注入）| ZC 公共入口 | **REWRITE**（详见 34）|
| 10 | `lib/ff_api.h` | 437–446 | `ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes);` 公开签名 + 文档块 | ABI | **保留签名，更新文档块**（详见 34）|
| 11 | `lib/ff_api.symlist` | 63 | `ff_zc_send` 导出符号 | so 导出 | **保留** |
| 12 | `lib/Makefile` | 211–213 | `ifdef FF_ZC_SEND / CFLAGS+= -DFSTACK_ZC_SEND / endif` | 编译开关 | **保留**（含义切换：从"魔改启用"→"原生路径启用"）|
| 13 | `lib/Makefile` | 47 | `#FF_ZC_SEND=1`（默认注释）| 顶层启用注释 | **保留** |
| 14 | `example/main_zc.c` | 132 | `extern ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes); /* M8 */` | 调用方原型 | **保留** |
| 15 | `example/main_zc.c` | 208–245 | `#ifdef FSTACK_ZC_SEND` 分支调用序列 `ff_zc_mbuf_get/write/ff_zc_send` | 调用序列 | **保留（零修改）** — 这是 ABI 不变性的合同验证点 |
| 16 | `example/Makefile` | 22, 26, 32, 34 | `FF_ZC_SEND=1` 探测 + `-DFSTACK_ZC_SEND` 编译目标 `${TARGET}_zc` | 示例编译 | **保留** |
| 17 | `lib/ff_veth.c` | 306–356 | `ff_zc_mbuf_get`（**无 `M_PKTHDR`** 的 `m_getm2(..., 0)`）+ `ff_zc_mbuf_write`（注释掉的 `m->m_pkthdr.len += length;` 在 L349-350）| mbuf 分配/写入 | **REWRITE**（M_PKTHDR 修复，详见 34）|

---

## §2 调用图：`FSTACK_ZC_MAGIC` 哨兵流转路径（旧方案）

```
APP (example/main_zc.c:209-244)
  ├── ff_zc_mbuf_get(&zc_buf, buf_len)          // ff_veth.c:306  m_getm2(..., MT_DATA, 0)  ← 无 M_PKTHDR
  ├── ff_zc_mbuf_write(&zc_buf, ...)            // ff_veth.c:326  bcopy 到 trailing space; pkthdr.len 累加被注释
  └── ff_zc_send(fd, zc_buf.bsd_mbuf, buf_len)  // ff_syscall_wrapper.c:1199
        │
        │  [ MAGIC 注入点 ]
        │  auio.uio_offset = FSTACK_ZC_MAGIC;   // L1216
        │  aiov.iov_base   = (void*)mb;         // L1210  ← mbuf 链伪装成 char*
        ▼
      kern_writev(curthread, fd, &auio)         // L1217
        │
        ▼
   freebsd/kern/sys_generic.c::sys_writev → kern_writev → dofilewrite
        │
        │  [ MAGIC 守护点 ]                     // L560-573
        │  if (auio->uio_offset != FSTACK_ZC_MAGIC)
        │      auio->uio_offset = offset;       ← 仅当非 MAGIC 才覆写为 -1
        ▼
      fo_write(fp, auio, ...)                  // L579
        │  → soo_write → sosend_generic
        │     (uio 仍带 uio_offset == FSTACK_ZC_MAGIC)
        ▼
   freebsd/kern/uipc_mbuf.c::m_uiotombuf       // L2000-2076
        │
        │  [ MAGIC 消费点 ]                    // L2040-2046
        │  if (uio_segflg==UIO_SYSSPACE && uio_rw==UIO_WRITE
        │      && uio->uio_offset == FSTACK_ZC_MAGIC) {
        │      m = (struct mbuf *)uio->uio_iov->iov_base;   ← iov_base 重新解释为 mbuf
        │      uio->uio_offset = total;        ← MAGIC 在此销毁
        │      progress = total;
        │  } else {
        │      ... 慢路径 m_getm2 + uiomove
```

**对外影响**（即 G2 拆除后必须保证不变）：
- 调用方序列（example/main_zc.c L208-245 不修改）；
- ff_zc_send / ff_zc_mbuf_get / ff_zc_mbuf_write 签名不变；
- `FF_ZC_SEND=1` 编译开关名不变；

新方案（详见 32 / 33 / 34）将整个 MAGIC 注入/守护/消费链替换为：
- `ff_zc_send` → `kern_zc_sendit(td, s, top, flags)` → `sosend(so, NULL, NULL, top, NULL, flags, td)`
- 不再修改 `kern_writev` / `m_uiotombuf` / `mbuf.h` 任一行。

---

## §3 待删除区段精确引用（c-precision-surgery 锚点格式）

> 锚点格式：每段含"前 5 行 + 待删除段 + 后 5 行"，便于实施期 agent 一次精确替换。
> 实施期 patch 工具：`replace_in_file`（旧字符串/新字符串），由 spec → 实施 plan 的 patch script 生成。

### §3.1 anchor: `freebsd/sys/mbuf.h:1856-1869`（删除 FSTACK_ZC_MAGIC 宏）

```c
// 锚点（前 5 行）— 1851-1855：
#endif

#define MBUF_PROBE3(probe, arg0, arg1, arg2)                 \
        SDT_PROBE3(sdt, , , probe, arg0, arg1, arg2)
#define MBUF_PROBE4(probe, arg0, arg1, arg2, arg3)           \
        SDT_PROBE3(sdt, , , probe, arg0, arg1, arg2, arg3)

// 待删除段 — 1856-1869：
#ifdef FSTACK_ZC_SEND
/*
 * M8 zero-copy send fast-path sentinel.
 * ff_zc_send stamps uio->uio_offset with this magic value to tell
 * m_uiotombuf (uipc_mbuf.c) that uio->uio_iov->iov_base is actually
 * a pre-built mbuf chain (NOT a char buffer), so it can be adopted
 * verbatim and the regular uiomove copy loop should be skipped.
 *
 * Plain ff_write / ff_writev paths must explicitly clear uio_offset
 * (see lib/ff_syscall_wrapper.c) so they never collide.
 */
#define FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)
#endif

// 锚点（后 5 行）— 1870-1874：
#endif /* _KERNEL */

#endif /* !_SYS_MBUF_H_ */
```

新方案下整段（含 `#ifdef FSTACK_ZC_SEND ... #endif` + 注释 + #define）**整体删除**。

### §3.2 anchor: `freebsd/kern/uipc_mbuf.c:2028-2072`（删除 m_uiotombuf 的 ZC 分支）

> 子 agent 报告显示 `freebsd/kern/uipc_mbuf.c:1955-2077` 是 13.0-era 简化版 m_uiotombuf 整段（非 vanilla 15.0），其中 L2028-2049 + L2070-2072 是 `#ifdef FSTACK_ZC_SEND` 分支。本期建议**回退到 vanilla FreeBSD 15.0 m_uiotombuf**（即整段 1955-2077 全部删除并恢复上游版本）。详细恢复方案见 33-kernel-patch-spec.md §3。

### §3.3 anchor: `freebsd/kern/sys_generic.c:560-573`（删除 dofilewrite uio_offset 守护）

```c
// 锚点（前 5 行）— 555-559（实测，已修正）：
#endif

	AUDIT_ARG_FD(fd);
	auio->uio_rw = UIO_WRITE;
	auio->uio_td = td;

// 待删除段 — 560-573（实测）：
#ifdef FSTACK_ZC_SEND
	/*
	 * M8: preserve FSTACK_ZC_MAGIC sentinel set by ff_zc_send so it
	 * survives down to m_uiotombuf where the ZC fast path tests for
	 * it. Plain ff_write callers pass uio_offset = 0, which is
	 * indistinguishable from default offset = -1 here, so we still
	 * overwrite for them (the fast-path predicate also checks
	 * UIO_SYSSPACE/UIO_WRITE which everyone has).
	 */
	if (auio->uio_offset != FSTACK_ZC_MAGIC)
		auio->uio_offset = offset;
#else
	auio->uio_offset = offset;
#endif

// 锚点（后 5 行）— 574-578（实测，已修正）：
#ifdef KTRACE
	if (KTRPOINT(td, KTR_GENIO))
		ktruio = cloneuio(auio);
#endif
	cnt = auio->uio_resid;
```

新方案删除上面 `#ifdef FSTACK_ZC_SEND ... #else ... #endif` 整段，仅保留 `auio->uio_offset = offset;` 单行。同时若 L57 `#include <sys/mbuf.h>` 仅为 MAGIC 而引入则一并删除（实施期需 grep 验证 sys_generic.c 是否别处用到 mbuf 类型）。

### §3.4 anchor: `lib/ff_syscall_wrapper.c:1146-1151`（删除 ff_write opt-out）

```c
// 锚点（前 5 行）— 1141-1145：
    auio.uio_iovcnt = 1;
    auio.uio_resid = nbytes;
    auio.uio_segflg = UIO_USERSPACE;

    /* M8: explicitly clear uio_offset so the FSTACK_ZC_SEND fast path

// 待删除段 — 1146-1151：
     * (uipc_mbuf.c:2028) sees a normal write and not a chance match
     * with FSTACK_ZC_MAGIC (0xF8AC2C00F8AC2C00LL). All non-ZC ff_write
     * callers carry plain char buffers; this is a safety opt-out.
     */
    auio.uio_offset = 0;
    /* Note: kern_writev consults uio_offset only via dofilewrite;

// 锚点（后 5 行）— 1152-1156：
     * the lseek-style use here is harmless. */
    if ((rc = kern_writev(curthread, fd, &auio)))
        ...
```

### §3.5 anchor: `lib/ff_syscall_wrapper.c:1175`（删除 ff_writev opt-out）

```c
// 锚点（前 5 行）— 1170-1174：
    auio.uio_iovcnt = iovcnt;
    auio.uio_resid = total;
    auio.uio_segflg = UIO_USERSPACE;

    auio.uio_offset = 0; /* M8: see ff_write comment */

// 待删除段 — 1175：
    auio.uio_offset = 0; /* M8: see ff_write comment */

// 锚点（后 5 行）— 1176-1180：
    if ((rc = kern_writev(curthread, fd, &auio)))
        ...
```

### §3.6 anchor: `lib/ff_syscall_wrapper.c:1186-1226`（重写 ff_zc_send，详见 34）

整段（含 `#ifdef FSTACK_ZC_SEND ... ff_zc_send ... #endif`）替换为新版（基于 `kern_zc_sendit`），详见 34-userspace-api-spec.md §3。

### §3.7 anchor: `lib/ff_veth.c:306-356`（修复 ff_zc_mbuf_get/write 的 M_PKTHDR）

详见 34-userspace-api-spec.md §4。**关键变化**：
- L313 `m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, 0)` → `m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, M_PKTHDR)`
- L349-350 注释掉的 `pkthdr.len += length` 改为有效代码（仅在链首累加，O(1) 维护总量）

---

## §4 ABI 不变性证据

### §4.1 公开签名（lib/ff_api.h:437-446）

```c
ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes);
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);
```

→ 新方案三者签名**完全保留**；只改实现。

### §4.2 调用方序列（example/main_zc.c:208-245）

新方案下该序列**零修改**通过；这是 G4 ABI 不变性的合同验证点（也是 AC2 验收条件之一）。

### §4.3 导出符号（lib/ff_api.symlist:63）

`ff_zc_send` 单符号；新方案不增不减不改。

### §4.4 编译开关（lib/Makefile:211-213）

```makefile
ifdef FF_ZC_SEND
CFLAGS+= -DFSTACK_ZC_SEND
endif
```

新方案保留宏名 `FSTACK_ZC_SEND`，但**含义切换**：
- 旧：启用魔改 `m_uiotombuf` 分支 + uio_offset 哨兵
- 新：启用 `kern_zc_sendit` 入口 + ff_zc_mbuf_get/write 走 M_PKTHDR 路径

迁移者唯一要求：**`make clean` 后重新编译**（与 M2 阶段教训一致，详见 39 迁移指南）。

---

## §5 可门禁验证条款（gatekeeper 抽检用）

| 条款 | 验证方式 | 通过判据 |
|---|---|---|
| C1 | `grep -rn "FSTACK_ZC_MAGIC" freebsd/ lib/` | 实施后应只剩 spec/docs 中的历史引用，源码 0 命中 |
| C2 | `grep -rn "FSTACK_ZC_SEND" freebsd/kern/uipc_mbuf.c freebsd/kern/sys_generic.c freebsd/sys/mbuf.h` | 0 命中 |
| C3 | `grep -n "auio.uio_offset = 0" lib/ff_syscall_wrapper.c` | 0 命中 |
| C4 | `nm libfstack.a \| grep ff_zc_send` | 仅 1 个符号定义（与旧方案一致）|
| C5 | `diff example/main_zc.c (HEAD) example/main_zc.c (post-impl)` | 0 行变化 |
| C6 | `diff freebsd/kern/uipc_mbuf.c (vanilla 15.0) freebsd/kern/uipc_mbuf.c (post-impl)` | 0 行变化（回归 vanilla）|

---

下一篇：**32-native-arch-design.md**（新对称架构图）。
