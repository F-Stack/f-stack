# 12 · Kernel Patch Detailed Spec

> All anchors are measured. Changes are wrapped in `#ifdef FSTACK_ZC_RECV`, disabled by default, not affecting existing paths.

## 1. Change Summary Table
| # | File | Anchor | Change | Risk |
|---|---|---|---|---|
| K1 | freebsd/kern/uipc_syscalls.c | kern_recvit:895 / soreceive:948 | Add `kern_zc_recvit` variant, change soreceive 4th arg from NULL to `&mp` passthrough | Low (new function, original kern_recvit unchanged) |
| K2 | freebsd/kern/sys_socket.c | soo_read:121 / soreceive:133 | read() path ZC support (optional, see §4): pass mp through fp flag or new fileop | Medium |
| K3 | lib/Makefile | 210-212 | Add `ifdef FF_ZC_RECV → -DFSTACK_ZC_RECV` | None |
| K4 | lib/ff_syscall_wrapper.c | ff_recvfrom:1319 / ff_recvmsg:1359 | Add `ff_zc_recv` entry, calling kern_zc_recvit; ordinary recv unchanged | Low |

## 2. K1 — kern_zc_recvit (recommended core change)
Current state (uipc_syscalls.c:948, **kept unchanged**):
```c
error = soreceive(so, &fromsa, &auio, NULL,
    (mp->msg_control || controlp) ? &control : NULL, &mp->msg_flags);
```
New variant (pseudocode, `#ifdef FSTACK_ZC_RECV`):
```c
int
kern_zc_recvit(struct thread *td, int s, struct msghdr *mp,
    enum uio_seg fromseg, struct mbuf **controlp, struct mbuf **mp0 /* new out-param */)
{
    /* build auio the same way as kern_recvit (uio_segflg/uio_rw/uio_resid, :928-941) */
    struct mbuf *zc_chain = NULL;
    error = soreceive(so, &fromsa, &auio, &zc_chain /* mp0 non-NULL */,
        (mp->msg_control || controlp) ? &control : NULL, &mp->msg_flags);
    /* returned bytes same as kern_recvit:967: td_retval[0] = len - auio.uio_resid */
    if (mp0 != NULL) *mp0 = zc_chain;   /* hand out the zero-copy chain */
    /* address/control-message backfill logic reuses kern_recvit's existing code */
}
```
**Constraints**:
- Must reuse kern_recvit's existing auio construction (:928-941), return value computation (:967), and fromsa/control backfill, keeping semantics consistent.
- When mp0!=NULL, soreceive only uses uio_resid (FreeBSD manual, 04 §1), so auio still needs uio_resid correctly set.
- The caller (ff_zc_recv) is responsible for storing zc_chain into struct ff_zc_mbuf and ultimately m_freem.

## 3. soreceive Side (**unchanged**)
The mp0 branch of soreceive(uipc_socket.c:3661) is FreeBSD native, **no change needed**:
- mp!=NULL hands out the whole segment directly (sbfree + *mp=m + sb_mb advance);
- split → m_copym fallback;
- mp==NULL → uiomove (existing recv unaffected).
The TCP default pr_soreceive=soreceive_generic (supports mp0); enabling soreceive_stream also supports it.

## 4. K2 — read() path (optional, phased)
read→soo_read→`soreceive(so,0,uio,0,0,0)` (sys_socket.c:133) hard-codes mp0=0. The read() interface itself has no mbuf output parameter semantics; ZC-recv is **preferentially implemented via ff_zc_recv (recv family)**; read() path ZC is listed as optional/subsequent (requires passing mp via file flag or new fileop, larger change surface, evaluated at M4).

## 5. Argumentation of Not Breaking Existing recv
- Original kern_recvit / soo_read have **zero change**, mp0 still NULL → existing recv/read behavior completely unchanged.
- New kern_zc_recvit takes effect only when FSTACK_ZC_RECV is compiled + the APP explicitly calls ff_zc_recv.
- soreceive core unchanged → protocol layer/accounting/lock semantics unchanged (02 §4 already verified the mp0 branch accounting is self-consistent).

## 6. FSTACK_ZC_RECV Macro Gating Scope
- lib/ff_api.h: ff_zc_recv/ff_zc_mbuf_read/ff_zc_recv_free declarations
- lib/ff_veth.c: ff_zc_mbuf_read rewrite + ff_zc_recv_free
- lib/ff_syscall_wrapper.c: ff_zc_recv
- freebsd/kern/uipc_syscalls.c: kern_zc_recvit
