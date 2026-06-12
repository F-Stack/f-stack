# 10 · Spec Overview (FSTACK_ZC_RECV Zero-Copy Receive)

> Implementation-level specification. Bridges from the feasibility conclusion (00-09, conclusion "feasible", recommends Plan A reusing soreceive mp0).

## 1. Scope
Add zero-copy receive capability FSTACK_ZC_RECV to f-stack: let the APP directly obtain the BSD mbuf chain in the socket receive buffer (whose data zero-copy points to the DPDK mbuf), eliminating the `soreceive→uiomove` mbuf→user buffer copy. This specification guides subsequent coding; **no implementation code is written in this phase**.

## 2. Terminology
| Term | Meaning |
|---|---|
| ZC-RECV | Zero-copy receive (this feature) |
| mp0 | The 4th formal parameter of soreceive `struct mbuf **mp0`; when non-NULL, returns as an mbuf chain to avoid copying (FreeBSD native) |
| ext-mbuf | external mbuf: BSD mbuf header + external storage pointing to DPDK mbuf data (EXT_DISPOSABLE) |
| release contract | After the APP finishes reading, it must return the mbuf chain (m_freem), otherwise the mempool leaks |

## 3. Goals and Non-Goals
- **Goals**: zero-copy receive of large data over TCP (including stream); correct ownership handover and release; do not break existing recv/read semantics.
- **Non-Goals (this feature)**: MSG_OOB / MSG_PEEK / KERN_TLS zero-copy (fall back to copy); UDP falls back to dgram; small-packet optimization.

## 4. Compile Switch (symmetric with SEND)
- Existing: `lib/Makefile:210-212  ifdef FF_ZC_SEND → CFLAGS+=-DFSTACK_ZC_SEND`
- New: `ifdef FF_ZC_RECV → CFLAGS+=-DFSTACK_ZC_RECV`
- The sentinel macro FSTACK_ZC_MAGIC (used by send) is **not reused for recv** (opposite direction, see 01 §5 / 11).

## 5. Document Navigation
11 architecture / 12 kernel patch / 13 userspace API / 14 lifecycle / 15 boundary & fallback / 16 testing / 17 acceptance & milestones / 19 review.

## 6. Key Measured Evidence (traceability)
- soreceive prototype and mp0 dispatch: uipc_socket.c:3661-3671
- recv chain: sys_recvfrom/sys_recvmsg → recvit(uipc_syscalls.c:1049) → kern_recvit(:895) → soreceive(...,NULL,...)(:948)
- read chain: read → dofileread(sys_generic.c:345) → fo_read → soo_read(sys_socket.c:121) → soreceive(so,0,uio,0,0,0)(:133)
- returned bytes: kern_recvit:967 `td_retval[0]=len-auio.uio_resid`
- ext-mbuf: ff_veth.c:374 m_extadd(...EXT_DISPOSABLE); release chain ff_veth.c:300/1106 → rte_pktmbuf_free_seg
