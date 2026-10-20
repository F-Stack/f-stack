# 22 · Research on FreeBSD 15.0 Native Send-side Zero-copy Interface (Benchmarked against kern_zc_recvit)

> Research question: Does FreeBSD 15.0 natively support a **send-side zero-copy interface** that is "symmetric to the receive-side mp0 (reused by kern_zc_recvit)", thereby able to replace f-stack's current self-implemented `FSTACK_ZC_MAGIC` + `m_uiotombuf` hack?
> Method: actually measure the freebsd/ source code bundled with f-stack (already re-applied to 15.0), code is authoritative.

## 0. Conclusion (First)
**Yes. FreeBSD 15.0 natively supports send-side zero-copy** — via the `top` (pre-built mbuf chain) parameter of `sosend`: when `uio == NULL && top != NULL`, `sosend` **directly sends that mbuf chain, skipping the `m_uiotombuf` copy**. This is exactly the send-side counterpart of `soreceive`'s `mp0` native mechanism.

⇒ f-stack's current ZC-send (`ff_zc_send` uses `uio_offset=FSTACK_ZC_MAGIC` + modifies `m_uiotombuf` to treat `iov_base` as mbuf) **is a self-implemented hack, and is not necessary**; it can switch to the native `sosend(top)` path (adding `kern_zc_sendit`, fully symmetric with `kern_zc_recvit`), **eliminating the kernel patch to `m_uiotombuf`**.

## 1. Native Interface Evidence (Measured)
### 1.1 sosend prototype carries top (mbuf chain) parameter
`freebsd/kern/uipc_socket.c:2599 sosend(struct socket *so, struct sockaddr *addr, struct uio *uio, struct mbuf *top, struct mbuf *control, int flags, struct thread *td)`
- Dispatched via `pr_sosend` to `sosend_generic`(2577) / `sosend_dgram`(2156).
- Symmetry: `soreceive(..., struct mbuf **mp0, ...)` receive-side out-param vs `sosend(..., struct mbuf *top, ...)` send-side in-param.

### 1.2 When uio==NULL, use top as data and skip the copy
`sosend_generic_locked`:
- `uipc_socket.c:2338-2341`: `if (uio != NULL) resid = uio->uio_resid; else resid = top->m_pkthdr.len;` —— when uio==NULL the data length is taken from **top's pkthdr.len**.
- `uipc_socket.c:2457 if (uio == NULL) { ... }`: **directly use the already-built top, skip the copy**; its `else` branch (2479/2490 `top = m_uiotombuf(uio, ...)`) is the regular uio→mbuf copy.
- `sosend_dgram` is isomorphic: 2167/2170 take resid, 2238 `if (uio == NULL)` skips the `m_uiotombuf` at 2248.

### 1.3 The sosend region is native, without f-stack hacks
- `awk '2320..2560' | grep FSTACK` → **empty**: the entire sosend section has no `FSTACK_*` macro.
- git blame: the file's most recent change was `2a9114132 ... Phase 5b: re-apply 10 kern/ F-Stack deltas on FreeBSD 15.0` (fengbojiang), but sosend's top/uio logic is upstream native (f-stack's delta is not here).
- ⇒ **top zero-copy send is a native capability of FreeBSD 15.0, usable without any hack.**

## 2. Review of Current f-stack ZC-send (Self-implemented Hack)
- `ff_zc_send`(ff_syscall_wrapper.c:1199): `iov_base = mbuf chain`, `uio_offset = FSTACK_ZC_MAGIC`(0xF8AC2C00F8AC2C00, mbuf.h:1868) → `kern_writev` → sosend (**uio non-null, top=NULL**).
- Modifies `m_uiotombuf`(uipc_mbuf.c:2028 `#ifdef FSTACK_ZC_SEND`): detects the magic → mounts `iov_base` as an mbuf chain, skips the regular copy.
- **Essence**: because it goes through the uio path (top=NULL), it has to "hijack" uio inside `m_uiotombuf` to stuff in the mbuf —— this is a workaround that **bypasses sosend's native top entry**, at the cost of one kernel patch + easy accidental triggering (plain ff_write needs an explicit `uio_offset=0` opt-out).

## 3. Why the Native Path is Currently Unreachable
- The userspace send entry ultimately all goes through `sousrsend`(uipc_socket.c:2615) → `pr_sosend(so, addr, uio, NULL /*top*/, control, flags, td)`: **top is hard-coded NULL** (kern_sendit uipc_syscalls.c:797 / soo_write sys_socket.c:`sousrsend(so,NULL,uio,NULL,0,NULL)` all do so).
- That is: **fully isomorphic** to the receive-side `mp0` being hard-coded NULL by kern_recvit —— the native capability is ready in the kernel, all that's missing is the entry to "thread top through from userspace into sosend".

## 4. Proposed Solution: kern_zc_sendit (Symmetric with kern_zc_recvit)
New addition (same `#ifdef FSTACK_ZC_RECV` style gating, or a new `FSTACK_ZC_SEND_NATIVE`):
```c
/* Pseudocode: send-side native zero-copy, symmetric with kern_zc_recvit */
int
kern_zc_sendit(struct thread *td, int s, struct mbuf *top, int flags)
{
    /* getsock ... so */
    /* uio = NULL, top = the chain built by APP via ff_zc_mbuf_get/write */
    error = sosend(so, /*addr*/NULL, /*uio*/NULL, top, /*control*/NULL, flags, td);
    /* sosend directly sends top in the uio==NULL branch, skipping the m_uiotombuf copy;
       td_retval[0] = bytes sent (resid difference); on failure handle top ownership per sosend semantics */
}
```
Userspace `ff_zc_send` changes to call `kern_zc_sendit` (passing top), no longer setting `FSTACK_ZC_MAGIC`.

### 4.1 Benefits (vs current hack)
| Dimension | Current FSTACK_ZC_MAGIC hack | Native sosend(top) solution |
|---|---|---|
| Kernel patch | Must modify m_uiotombuf (uipc_mbuf.c) | **No need to modify m_uiotombuf** (only add the kern_zc_sendit entry, analogous to recvit) |
| Accidental-trigger risk | Plain ff_write must explicitly opt out with uio_offset=0 (once caused a GPF, see ff_syscall_wrapper.c:1146 RCA) | None (the top path and uio path are naturally separated) |
| Upstream consistency | Low (self-invented magic) | **High** (uses native sosend top semantics) |
| Symmetry | Asymmetric with the receive side | **Fully symmetric with kern_zc_recvit** |
| Upgrade maintenance | Each FreeBSD merge requires re-aligning the m_uiotombuf hack | Only maintain one independent entry |

### 4.2 Caveats (to verify during implementation)
- **top must carry a correct pkthdr.len**: the sosend uio==NULL branch uses `top->m_pkthdr.len` as resid. Currently `ff_zc_mbuf_get`(ff_veth.c:306) uses `m_getm2(..., flags=0)` **without M_PKTHDR**, and `ff_zc_mbuf_write` does not update pkthdr.len (01 §1.3 measured). The native solution must make the top chain head carry M_PKTHDR and pkthdr.len = total bytes written (otherwise resid is wrong).
- **mbuf ownership**: after a successful sosend it takes over/frees top (consistent with the current hack); the top-release semantics of the failure path must be verified against the sosend contract (to avoid leaks/double free).
- **PRUS_MORETOCOME / segmentation**: sosend internally does multiple pr_send by sbspace; when top spans multiple mbufs sosend handles it, the APP need not care.
- **Protocol**: both TCP (sosend_generic) / UDP (sosend_dgram) support the top (uio==NULL) branch.

## 5. Summary
- FreeBSD 15.0 **natively** provides send-side zero-copy (`sosend`'s `top` mbuf entry, uio==NULL skips the copy), **fully symmetric** with the receive-side `mp0`, and the entire sosend section is hack-free.
- f-stack's current ZC-send is a `FSTACK_ZC_MAGIC`+`m_uiotombuf` workaround that **bypasses that native entry**.
- **Recommendation**: a subsequent step can add a symmetric `kern_zc_sendit` (sosend top path) to replace the hack, **eliminating the m_uiotombuf kernel patch, reducing accidental-trigger and upgrade-maintenance cost**; this requires first solving top's pkthdr.len construction (modify ff_zc_mbuf_get/write to carry M_PKTHDR). This research only evaluates and is not implemented within the scope of this ZC-recv cycle.
