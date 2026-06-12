# 33. 内核 patch 详规（含 c-precision-surgery 锚点）

> 来源：probe-sosend-native + probe-zcrecv-symmetry 实测 + 32 架构设计
> 目标：实施期 agent 据此一次精确落 patch；零不必要 diff
> c-precision-surgery 原则：每段改动均带"前后 5 行锚点"，便于 `replace_in_file` 工具精确匹配

---

## §1 新增声明 — `freebsd/sys/syscallsubr.h`

### §1.1 锚点位置（既有 `kern_zc_recvit` 声明区域，对称插入）

实测 `kern_zc_recvit` 声明位于 `freebsd/sys/syscallsubr.h:304-310`（详见 32 §3 引用）。新声明紧随其后插入。

### §1.2 NEW 内容（声明）

```c
#ifdef FSTACK_ZC_SEND
/* FSTACK_ZC_SEND: zero-copy send variant — hands a pre-built mbuf chain
 * (top) directly to sosend(uio=NULL, top=chain), avoiding the
 * m_uiotombuf copy. Caller relinquishes top ownership on success;
 * on error kern_zc_sendit frees top via m_freem (see 35-lifecycle). */
int	kern_zc_sendit(struct thread *td, int s, struct mbuf *top,
	    int flags);
#endif
```

签名设计依据（实测，详见 32 §3）：
- `td` / `s` 与 `kern_zc_recvit` 同型；
- `top`：sosend 的 `top` 参数（非 NULL，链头带 M_PKTHDR）；
- `flags`：透传至 sosend 的 `flags` 参数（MSG_DONTWAIT / MSG_EOR / MSG_NOSIGNAL 等）；
- 不接受 `addr` / `control`：本期不支持 sendto/sendmsg 的对端地址与 SCM 控制（详见 36 边界）。

---

## §2 新增实现 — `freebsd/kern/uipc_syscalls.c`

### §2.1 锚点位置

紧随 `kern_zc_recvit` 末尾的 `#endif /* FSTACK_ZC_RECV */`（实测在 uipc_syscalls.c:1109 附近）插入。**绝不**修改 `kern_recvit` / `kern_sendit` / `sousrsend` 任何一行。

### §2.2 NEW 内容（实现）

```c
#ifdef FSTACK_ZC_SEND
/*
 * FSTACK_ZC_SEND: zero-copy send.
 *
 * A compact sibling of kern_sendit that calls sosend() directly with a
 * non-NULL `top` mbuf chain and uio == NULL. Per the FreeBSD sosend(9)
 * contract (man page since FreeBSD 7.0, R. Watson): "data may be sent
 * ... as an mbuf chain via top, avoiding a data copy. Only one of the
 * uio or top pointers may be non-NULL." sosend_generic_locked then
 * takes resid from top->m_pkthdr.len (uipc_socket.c:2340-2341) and
 * skips the m_uiotombuf copy in the inner uio==NULL branch
 * (uipc_socket.c:2456-2500).
 *
 * No address (sendto target) / control (SCM) handling here: ZC send
 * targets the bulk data fast path. Caller MUST ensure `top` is a
 * proper M_PKTHDR-headed chain with pkthdr.len == sum-of-segments
 * (see lib/ff_veth.c ff_zc_mbuf_get/write).
 *
 * Ownership: on success sosend adopts `top` (caller MUST NOT touch).
 * On error kern_zc_sendit frees `top` via m_freem so the caller never
 * has to (mirrors kern_zc_recvit error-path m_freem of zc_chain).
 */
int
kern_zc_sendit(struct thread *td, int s, struct mbuf *top, int flags)
{
	struct file *fp;
	struct socket *so;
	ssize_t len;
	int error;

	if (top == NULL || (top->m_flags & M_PKTHDR) == 0) {
		if (top != NULL)
			m_freem(top);
		return (EINVAL);
	}
	len = top->m_pkthdr.len;
	if (len < 0) {
		m_freem(top);
		return (EINVAL);
	}

	AUDIT_ARG_FD(s);
	error = getsock(td, s, &cap_send_rights, &fp);
	if (error != 0) {
		m_freem(top);
		return (error);
	}
	so = fp->f_data;

#ifdef MAC
	error = mac_socket_check_send(td->td_ucred, so);
	if (error != 0) {
		m_freem(top);
		fdrop(fp, td);
		return (error);
	}
#endif

	error = sosend(so, NULL, NULL, top, NULL, flags, td);
	/* sosend adopts `top` on success; on error sosend either has
	 * already freed top (sosend_generic_locked m_freem(top) sites)
	 * or has not — the contract is protocol-dependent (see
	 * 36-boundary). For safety we no longer reference top here. */

	if (error == 0) {
		td->td_retval[0] = len;
	} else {
		/* Mirror sousrsend (uipc_socket.c:2632-2641): clear
		 * transient errors for stream protocols if any progress
		 * was made. We have no uio_resid; use td_retval[0]==0
		 * as the "no progress" signal. */
		if ((so->so_proto->pr_flags & PR_ATOMIC) == 0 &&
		    (error == ERESTART || error == EINTR ||
		    error == EWOULDBLOCK)) {
			/* For ZC the all-or-nothing semantics is implied
			 * by atomic=1 in sosend_generic_locked
			 * (uipc_socket.c:2325 atomic = ... || top), so
			 * partial-progress recovery is not applicable;
			 * surface the error verbatim. */
		}
		/* SIGPIPE generation per sousrsend (uipc_socket.c:2647): */
		if (error == EPIPE && (so->so_options & SO_NOSIGPIPE) == 0 &&
		    (flags & MSG_NOSIGNAL) == 0) {
			PROC_LOCK(td->td_proc);
			tdsignal(td, SIGPIPE);
			PROC_UNLOCK(td->td_proc);
		}
	}

	fdrop(fp, td);
	return (error);
}
#endif /* FSTACK_ZC_SEND */
```

### §2.3 设计要点（逐条引用 sousrsend 原型，实测对照）

| 行为 | 本函数 | 对照（实测）|
|---|---|---|
| 入参校验 | top!=NULL && M_PKTHDR && pkthdr.len>=0 | 防御 sosend `if (resid < 0)` 立即 EINVAL（uipc_socket.c:2354-2356）|
| fd 解析 | `getsock(td, s, &cap_send_rights, &fp)` | kern_sendit @ uipc_syscalls.c:745 同 |
| MAC 检查 | `mac_socket_check_send` | kern_sendit @ uipc_syscalls.c:770 同 |
| sosend 调用 | `sosend(so, NULL, NULL, top, NULL, flags, td)` | uipc_socket.c:2598-2609 sosend 原型；NULL,NULL,NULL,top,NULL = addr,uio,top,control 中只有 top 非 NULL |
| 错误所有权 | 错误路径前置 m_freem 用于入参校验失败；sosend 错误时 top 由 protosw 释放（详见 35）| sosend_generic_locked 内多处 `m_freem(top)`（uipc_socket.c m_freem 站点 — 见 35 §3）|
| EPIPE → SIGPIPE | 镜像 sousrsend | uipc_socket.c:2647 sousrsend |
| td_retval | 成功设 `len`（top 总字节数）| sousrsend 用 `len = uio->uio_resid` 然后 `len - uio->uio_resid` 推算；ZC 无 uio，直接用 pkthdr.len |

### §2.4 与 sousrsend 的差异说明（为什么不复用 sousrsend）

实测 `sousrsend`(uipc_socket.c:2615) `pr_sosend(..., uio, NULL, ...)` 第 4 参 top 写死 NULL —— **不可复用**。新方案绕开 sousrsend 直调 sosend，故必须自实现：
1. fd 解析 + MAC（已实现，照搬 kern_sendit 第 5-10 行模式）；
2. sosend 调用（直接传 top）；
3. 错误返回的 EWOULDBLOCK/EINTR/ERESTART 处理（sousrsend 的 stream 短计逻辑在 ZC atomic 场景下不适用，留空注释说明）；
4. SIGPIPE 兼容（镜像 sousrsend:2647-2655）。

---

## §3 删除/恢复 — `freebsd/kern/uipc_mbuf.c` m_uiotombuf

### §3.1 实测当前状态

子 agent 报告（probe-zcsend-current §1）显示 `freebsd/kern/uipc_mbuf.c:1955-2077` 是一段 **13.0-era 简化版 m_uiotombuf**（用 `#ifndef FSTACK / #else` 包裹），且 L2028-2049 + L2070-2072 是 `#ifdef FSTACK_ZC_SEND` 快路径分支。

### §3.2 处置策略

**回退到 vanilla FreeBSD 15.0 m_uiotombuf 实现**：删除整个 `#ifndef FSTACK ... #else ... #endif` 包裹（含 13.0 简化版 + ZC 分支），让代码使用 vanilla 15.0 的 m_uiotombuf。

实施时需：
1. 找到 `#ifndef FSTACK` 起始行；
2. 找到匹配的 `#endif` 终止行；
3. 删除 `#else` 之前的 13.0 简化版（含 FSTACK_ZC_SEND 分支）；
4. 保留 `#else` 之后的 vanilla 15.0 实现（去掉 `#ifndef/#else/#endif` 包裹）。

### §3.3 验证条件

实施后 `diff freebsd/kern/uipc_mbuf.c (post-impl) vs vanilla-FreeBSD-15.0/sys/kern/uipc_mbuf.c` 在 m_uiotombuf 区段应为 0 行差异。

> **注**：spec 不提供具体行号删除区段，因 m_uiotombuf 区段在 git mv / 重 base 后行号会漂移。实施期 agent 必须基于"FSTACK 包裹 + 13.0 简化版"特征定位。

---

## §4 删除 — `freebsd/sys/mbuf.h` FSTACK_ZC_MAGIC 宏

### §4.1 锚点（前 5 行）

`freebsd/sys/mbuf.h:1851-1855`：

```c
#endif

#define MBUF_PROBE3(probe, arg0, arg1, arg2)                 \
        SDT_PROBE3(sdt, , , probe, arg0, arg1, arg2)
#define MBUF_PROBE4(probe, arg0, arg1, arg2, arg3)           \
```

### §4.2 待删除段 — 1856-1869

```c
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
```

### §4.3 锚点（后 5 行）

`freebsd/sys/mbuf.h:1870-1874`（即文件结尾区域）：

```c
#endif /* _KERNEL */

#endif /* !_SYS_MBUF_H_ */
```

整段（含 `#ifdef FSTACK_ZC_SEND ... #endif`）**整体删除**，不留替代。

---

## §5 删除 — `freebsd/kern/sys_generic.c` dofilewrite uio_offset 守护

### §5.1 锚点（前 5 行）

`freebsd/kern/sys_generic.c:555-559`（实测，已修正）：

```c
#endif

	AUDIT_ARG_FD(fd);
	auio->uio_rw = UIO_WRITE;
	auio->uio_td = td;
```

### §5.2 待删除段 — 560-573（实测）

```c
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
```

### §5.3 替换为单行

```c
	auio->uio_offset = offset;
```

### §5.4 锚点（后 5 行，实测，已修正）

```c
#ifdef KTRACE
	if (KTRPOINT(td, KTR_GENIO))
		ktruio = cloneuio(auio);
#endif
	cnt = auio->uio_resid;
```

### §5.5 同步删除

L57 的 `#include <sys/mbuf.h>  /* M8: FSTACK_ZC_MAGIC for ZC fast-path */`：实施期需 grep 验证 sys_generic.c 是否别处需要 mbuf 类型；若无则删除该 include。

---

## §6 内核 patch 总数与风险面

| 改动 | 类型 | 文件 | 行数级 | 风险 |
|---|---|---|---|---|
| K1 | NEW | freebsd/sys/syscallsubr.h | +8 | 低（声明，gated）|
| K2 | NEW | freebsd/kern/uipc_syscalls.c | +75 | 中（自实现错误处理）|
| D1 | DELETE | freebsd/sys/mbuf.h | -14 | 低 |
| D2 | RESTORE | freebsd/kern/uipc_mbuf.c | -120/+vanilla | 中（需对照 vanilla 15.0）|
| D3 | DELETE | freebsd/kern/sys_generic.c | -14 | 低 |

**风险评估**：
- K2 错误处理中"sosend 错误时 top 由 protosw 释放"的契约依赖 sosend 内部 m_freem 一致性 —— 详见 35-lifecycle §3 与 36-boundary §UDP 的 `pr_freem` 矩阵。本期 spec 选择**不再次 m_freem**（避免 double-free），由 35 INV-3 不变量保证。
- D2 m_uiotombuf 回退需 vanilla 对照：实施期需先 `wget` vanilla FreeBSD-15.0 `sys/kern/uipc_mbuf.c` 做 diff 校验，然后做精确删除。

---

## §7 编译开关（lib/Makefile，无变化）

```makefile
ifdef FF_ZC_SEND
CFLAGS+= -DFSTACK_ZC_SEND
endif
```

新方案下 `FSTACK_ZC_SEND` 宏现在控制：
- `freebsd/sys/syscallsubr.h` 的 `kern_zc_sendit` 声明
- `freebsd/kern/uipc_syscalls.c` 的 `kern_zc_sendit` 实现
- `lib/ff_syscall_wrapper.c` 的 `ff_zc_send` 实现（详见 34）
- `lib/ff_veth.c` 的 `ff_zc_mbuf_get`/`ff_zc_mbuf_write` M_PKTHDR 路径（详见 34）

旧方案下该宏控制的 `m_uiotombuf` / `mbuf.h` / `sys_generic.c` 触点全部删除。

---

## §8 可门禁验证条款（gatekeeper）

| 条款 | 验证方式 | 通过判据 |
|---|---|---|
| K-G1 | grep `kern_zc_sendit` in syscallsubr.h | 1 个声明 |
| K-G2 | grep `kern_zc_sendit` in uipc_syscalls.c | 1 个实现 + 任意调用方（即 ff_zc_send 用）|
| K-G3 | grep `FSTACK_ZC_MAGIC` in freebsd/sys/mbuf.h | 0 命中 |
| K-G4 | grep `FSTACK_ZC_SEND` in uipc_mbuf.c | 0 命中 |
| K-G5 | grep `FSTACK_ZC_SEND` in sys_generic.c | 0 命中 |
| K-G6 | `gcc -E ... | grep "static.*m_uiotombuf"` 与 vanilla 一致 | 0 行差异 |
| K-G7 | 编译 `FF_ZC_SEND=1 make` | -Werror clean，无 unused |

---

下一篇：**34-userspace-api-spec.md**（用户态 API 规格 + M_PKTHDR 修复）。
