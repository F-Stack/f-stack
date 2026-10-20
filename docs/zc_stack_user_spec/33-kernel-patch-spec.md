# 33. Detailed Kernel Patch Spec (including c-precision-surgery anchors)

> Source: probe-sosend-native + probe-zcrecv-symmetry measurements + 32 architecture design
> Goal: during implementation an agent can land the patch precisely in one pass; zero unnecessary diff
> c-precision-surgery principle: each change carries "5-line anchors before and after" to enable the `replace_in_file` tool to match precisely

---

## §1 New Declaration — `freebsd/sys/syscallsubr.h`

### §1.1 Anchor Location (existing `kern_zc_recvit` declaration region, symmetric insertion)

Measured: the `kern_zc_recvit` declaration is located at `freebsd/sys/syscallsubr.h:304-310` (see the reference in 32 §3). The new declaration is inserted immediately after it.

### §1.2 NEW Content (declaration)

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

Rationale for the signature design (measured, see 32 §3 for details):
- `td` / `s` are the same type as in `kern_zc_recvit`;
- `top`: the `top` argument of sosend (non-NULL, chain head carries M_PKTHDR);
- `flags`: passed through to the `flags` argument of sosend (MSG_DONTWAIT / MSG_EOR / MSG_NOSIGNAL etc.);
- does not accept `addr` / `control`: this round does not support the peer address of sendto/sendmsg or SCM control (see 36 boundary for details).

---

## §2 New Implementation — `freebsd/kern/uipc_syscalls.c`

### §2.1 Anchor Location

Insert immediately after the `#endif /* FSTACK_ZC_RECV */` at the end of `kern_zc_recvit` (measured around uipc_syscalls.c:1109). **Never** modify a single line of `kern_recvit` / `kern_sendit` / `sousrsend`.

### §2.2 NEW Content (implementation)

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

### §2.3 Design Points (citing the sousrsend prototype item by item, measured comparison)

| Behavior | This function | Reference (measured) |
|---|---|---|
| Argument validation | top!=NULL && M_PKTHDR && pkthdr.len>=0 | guards against sosend's `if (resid < 0)` immediate EINVAL (uipc_socket.c:2354-2356) |
| fd resolution | `getsock(td, s, &cap_send_rights, &fp)` | same as kern_sendit @ uipc_syscalls.c:745 |
| MAC check | `mac_socket_check_send` | same as kern_sendit @ uipc_syscalls.c:770 |
| sosend call | `sosend(so, NULL, NULL, top, NULL, flags, td)` | uipc_socket.c:2598-2609 sosend prototype; NULL,NULL,NULL,top,NULL = of addr,uio,top,control only top is non-NULL |
| Error ownership | error path uses m_freem upfront for argument-validation failure; on sosend error top is freed by protosw (see 35) | multiple `m_freem(top)` inside sosend_generic_locked (uipc_socket.c m_freem sites — see 35 §3) |
| EPIPE → SIGPIPE | mirrors sousrsend | uipc_socket.c:2647 sousrsend |
| td_retval | on success sets `len` (total bytes of top) | sousrsend uses `len = uio->uio_resid` then derives `len - uio->uio_resid`; ZC has no uio and directly uses pkthdr.len |

### §2.4 Explanation of the Difference from sousrsend (why sousrsend is not reused)

Measured: `sousrsend`(uipc_socket.c:2615) `pr_sosend(..., uio, NULL, ...)` hardcodes the 4th argument top to NULL —— **not reusable**. The new scheme bypasses sousrsend and calls sosend directly, so it must be self-implemented:
1. fd resolution + MAC (implemented, copying the lines 5-10 pattern of kern_sendit);
2. sosend call (passing top directly);
3. handling of EWOULDBLOCK/EINTR/ERESTART on error return (sousrsend's stream short-count logic does not apply in the ZC atomic scenario, left as an empty comment for explanation);
4. SIGPIPE compatibility (mirroring sousrsend:2647-2655).

---

## §3 Delete/Restore — `freebsd/kern/uipc_mbuf.c` m_uiotombuf

### §3.1 Measured Current State

The sub-agent report (probe-zcsend-current §1) shows that `freebsd/kern/uipc_mbuf.c:1955-2077` is a **13.0-era simplified m_uiotombuf** (wrapped in `#ifndef FSTACK / #else`), and L2028-2049 + L2070-2072 are the `#ifdef FSTACK_ZC_SEND` fast-path branch.

### §3.2 Handling Strategy

**Roll back to the vanilla FreeBSD 15.0 m_uiotombuf implementation**: delete the entire `#ifndef FSTACK ... #else ... #endif` wrapper (including the 13.0 simplified version + the ZC branch), letting the code use vanilla 15.0's m_uiotombuf.

At implementation time:
1. find the `#ifndef FSTACK` start line;
2. find the matching `#endif` end line;
3. delete the 13.0 simplified version before `#else` (including the FSTACK_ZC_SEND branch);
4. keep the vanilla 15.0 implementation after `#else` (removing the `#ifndef/#else/#endif` wrapper).

### §3.3 Verification Condition

After implementation, `diff freebsd/kern/uipc_mbuf.c (post-impl) vs vanilla-FreeBSD-15.0/sys/kern/uipc_mbuf.c` should show 0 lines of difference in the m_uiotombuf section.

> **Note**: the spec does not provide specific line numbers for the deletion section, because the m_uiotombuf section's line numbers will drift after git mv / re-base. The implementation-phase agent must locate it based on the "FSTACK wrapper + 13.0 simplified version" characteristics.

---

## §4 Delete — `freebsd/sys/mbuf.h` FSTACK_ZC_MAGIC macro

### §4.1 Anchor (5 lines before)

`freebsd/sys/mbuf.h:1851-1855`:

```c
#endif

#define MBUF_PROBE3(probe, arg0, arg1, arg2)                 \
        SDT_PROBE3(sdt, , , probe, arg0, arg1, arg2)
#define MBUF_PROBE4(probe, arg0, arg1, arg2, arg3)           \
```

### §4.2 Section to Delete — 1856-1869

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

### §4.3 Anchor (5 lines after)

`freebsd/sys/mbuf.h:1870-1874` (i.e. the end-of-file region):

```c
#endif /* _KERNEL */

#endif /* !_SYS_MBUF_H_ */
```

The whole section (including `#ifdef FSTACK_ZC_SEND ... #endif`) is **deleted entirely**, with no replacement left.

---

## §5 Delete — `freebsd/kern/sys_generic.c` dofilewrite uio_offset guard

### §5.1 Anchor (5 lines before)

`freebsd/kern/sys_generic.c:555-559` (measured, corrected):

```c
#endif

	AUDIT_ARG_FD(fd);
	auio->uio_rw = UIO_WRITE;
	auio->uio_td = td;
```

### §5.2 Section to Delete — 560-573 (measured)

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

### §5.3 Replace with a Single Line

```c
	auio->uio_offset = offset;
```

### §5.4 Anchor (5 lines after, measured, corrected)

```c
#ifdef KTRACE
	if (KTRPOINT(td, KTR_GENIO))
		ktruio = cloneuio(auio);
#endif
	cnt = auio->uio_resid;
```

### §5.5 Synchronized Deletion

L57's `#include <sys/mbuf.h>  /* M8: FSTACK_ZC_MAGIC for ZC fast-path */`: at implementation time grep-verify whether sys_generic.c needs the mbuf type elsewhere; if not, delete this include.

---

## §6 Total Number of Kernel Patches and Risk Surface

| Change | Type | File | Line scale | Risk |
|---|---|---|---|---|
| K1 | NEW | freebsd/sys/syscallsubr.h | +8 | low (declaration, gated) |
| K2 | NEW | freebsd/kern/uipc_syscalls.c | +75 | medium (self-implemented error handling) |
| D1 | DELETE | freebsd/sys/mbuf.h | -14 | low |
| D2 | RESTORE | freebsd/kern/uipc_mbuf.c | -120/+vanilla | medium (needs comparison with vanilla 15.0) |
| D3 | DELETE | freebsd/kern/sys_generic.c | -14 | low |

**Risk assessment**:
- The contract in K2 error handling that "on sosend error top is freed by protosw" depends on the consistency of m_freem inside sosend —— see 35-lifecycle §3 and the `pr_freem` matrix in 36-boundary §UDP. This spec round chooses to **not m_freem again** (to avoid double-free), guaranteed by the 35 INV-3 invariant.
- The D2 m_uiotombuf rollback needs comparison with vanilla: at implementation time first `wget` the vanilla FreeBSD-15.0 `sys/kern/uipc_mbuf.c` to do a diff check, then perform the precise deletion.

---

## §7 Compilation Switch (lib/Makefile, unchanged)

```makefile
ifdef FF_ZC_SEND
CFLAGS+= -DFSTACK_ZC_SEND
endif
```

Under the new scheme the `FSTACK_ZC_SEND` macro now controls:
- the `kern_zc_sendit` declaration in `freebsd/sys/syscallsubr.h`
- the `kern_zc_sendit` implementation in `freebsd/kern/uipc_syscalls.c`
- the `ff_zc_send` implementation in `lib/ff_syscall_wrapper.c` (see 34)
- the `ff_zc_mbuf_get`/`ff_zc_mbuf_write` M_PKTHDR path in `lib/ff_veth.c` (see 34)

The `m_uiotombuf` / `mbuf.h` / `sys_generic.c` touch points controlled by this macro under the old scheme are all deleted.

---

## §8 Gateable Verification Clauses (gatekeeper)

| Clause | Verification method | Pass criterion |
|---|---|---|
| K-G1 | grep `kern_zc_sendit` in syscallsubr.h | 1 declaration |
| K-G2 | grep `kern_zc_sendit` in uipc_syscalls.c | 1 implementation + any caller (i.e. used by ff_zc_send) |
| K-G3 | grep `FSTACK_ZC_MAGIC` in freebsd/sys/mbuf.h | 0 hits |
| K-G4 | grep `FSTACK_ZC_SEND` in uipc_mbuf.c | 0 hits |
| K-G5 | grep `FSTACK_ZC_SEND` in sys_generic.c | 0 hits |
| K-G6 | `gcc -E ... | grep "static.*m_uiotombuf"` consistent with vanilla | 0 lines of difference |
| K-G7 | compile `FF_ZC_SEND=1 make` | -Werror clean, no unused |

---

Next: **34-userspace-api-spec.md** (userspace API spec + M_PKTHDR fix).
