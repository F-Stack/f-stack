# 02 · READ Path Analysis (soreceive / mp0 / sockbuf accounting)

> Probe: probe-recvpath (read-only measurement, f-stack's own reworked source). Every assertion carries file:line:symbol. Code takes priority over comments/docs.

## 0. Conclusion at a Glance (TL;DR)
- The kernel `soreceive_generic_locked` **inherently supports the mp (soreceive's mp0 out-parameter) zero-copy mbuf hand-out** branch: `uipc_socket.c:3022 if(mp==NULL)` (copy) vs. `uipc_socket.c:3061 *mp=m` (zero-copy direct hand-out). When `mp!=NULL` it **does not call uiomove**, only moving the pointer + `uio_resid-=len` (L3050).
- **But this path is currently completely unreachable from f-stack user space**: the 5 read/recv entries go through `kern_readv`/`kern_recvit`, both of which **hardcode soreceive's 4th formal parameter mp0 to NULL** (`uipc_syscalls.c:948`; read goes through `sys_generic.c`→`soo_read`→`soreceive(...,NULL,...)`).
- f-stack **made no ZC-related changes to the receive path**; the rework is concentrated on the send side (FSTACK_ZC_SEND).
- The **minimal change** on the kernel side to implement ZC-read: add a channel that lets `kern_recvit`/`dofileread` expose the mbuf out-parameter mp to the upper layer (§7).

## 1. User-Space Entries (ff_syscall_wrapper.c)
| Entry | Line | Kernel call | mp passing |
|---|---|---|---|
| ff_read | 1077 | kern_readv (1094), uio_segflg=UIO_SYSSPACE | no (readv has no mp parameter) |
| ff_readv | 1105 | kern_readv (1118) | no |
| ff_recv | 1313 | forwards to ff_recvfrom (1315) | no |
| ff_recvfrom | 1319 | kern_recvit (1339), msg_control=0 | controlp passes NULL |
| ff_recvmsg | 1359 | kern_recvit (1371) | NULL |
- All use UIO_SYSSPACE (same address space, uiomove degenerates to memcpy, **still one full copy**).
- The user API layer has no concept of a "data mbuf out-parameter"; kern_recvit's last parameter is controlp (control messages), not the data mp0.

## 2. soreceive Call Chain and Copy Points
Dispatch: `soreceive` (uipc_socket.c:3661) → `pr_soreceive`. Measured values:
- default `DEFAULT(pr_soreceive, soreceive_generic)` (uipc_domain.c:196);
- **TCP**: tcp_protosw does not set it explicitly (tcp_usrreq.c:1403) → default = soreceive_generic; only when sysctl `net.inet.tcp.soreceive_stream` is enabled does it change to soreceive_stream (tcp_subr.c:1492);
- **UDP**: soreceive_dgram (udp_usrreq.c:1794); **SCTP**: sctp_soreceive.

| Copy point | File:Line | Condition |
|---|---|---|
| OOB | uipc_socket.c:2682 | MSG_OOB |
| **generic main copy** | uipc_socket.c:3031 uiomove | mp==NULL and not M_EXTPG |
| EXTPG | uipc_socket.c:3028 m_unmapped_uiomove | mp==NULL and M_EXTPG |
| stream main copy | uipc_socket.c:3382 m_mbuftouio | stream and mp0==NULL |
| dgram main copy | uipc_socket.c:3640 uiomove | soreceive_dgram |

## 3. mp0 Out-Parameter Mechanism (core)
`soreceive_generic_locked` (uipc_socket.c:3015-3105), comment makes clear "If mp is set, just pass back the mbufs":
- **mp==NULL**: `uiomove(mtod(m,char*)+moff,len,uio)` (L3031) ← the real copy;
- **mp!=NULL and whole mbuf (len==m_len-moff)**: `sbfree(&so->so_rcv,m)` (L3060) → `*mp=m` (L3063) → `mp=&m->m_next` (L3064) → `sb_mb=m->m_next` (L3065) → **zero-copy direct hand-out**; `m_free` (L3068) only when mp==NULL;
- **mp!=NULL and partial mbuf (split)**: still `m_copym` (L3081/L3098) one copy —— **the boundary where zero-copy is not possible**.
- The mp0!=NULL path of soreceive_stream_locked is the same (L3337-3359 m_cat hands out the whole segment; trailing remainder m_copym L3365).

**Does f-stack modify this path?** Measured: the soreceive-series logic is consistent with upstream FreeBSD, **no FSTACK_* macro, no ZC customization**.

## 4. sockbuf Accounting and Locking (uipc_sockbuf.c)
- `sballoc`(254): on enqueue sb_ccc/sb_acc/sb_mbcnt +=; `sbfree`(282): on dequeue -=; `sbavail()`(sockbuf.h:267)=sb_acc.
- Zero-copy whole hand-out: `sbfree`(uipc_socket.c:3060)+`*mp=m` are completed **within the same SOCKBUF lock**; **the lock is not released** (no uiomove), so the critical section is shorter.
- Copy-path taking a whole mbuf: `sbfree`+`m_free`(L3068); partial: `sbcut_locked`(L3103).
- Locks: top-level `sblock`/`SOCK_IO_RECV_LOCK`(L3239) guards against multiple readers; `SOCKBUF_LOCK`(L2767) protects pointers/accounting, released before uiomove(L3026) then re-acquired(L3033) (uiomove may sleep).

## 5. Do kern_recvit / kern_readv Expose mp? — Neither, copy is hardcoded
- `kern_recvit` (uipc_syscalls.c:895): `soreceive(so,&fromsa,&auio, NULL, (control message?&control:NULL), &msg_flags)` (L948) → the 4th formal parameter mp0 is **hardcoded NULL**; control only carries MT_CONTROL.
- `kern_readv` (sys_generic.c:283) → `dofileread`(345) → `fo_read` → `soo_read` → `soreceive(...,mp0=NULL,...)`.
**Therefore there is no existing path from user space into the kernel that passes mp0!=NULL into soreceive; the zero-copy branch exists but is currently unreachable.**

## 6. Boundary Path Locating
| Boundary | Location | Impact on ZC-read |
|---|---|---|
| MSG_PEEK | uipc_socket.c:2872/3055/3076 | does not detach the chain; whole hand-out is inapplicable; only m_copym |
| MSG_WAITALL | uipc_socket.c:3129-3165 | needs to loop until full; can do per-segment zero-copy over multiple rounds |
| non-blocking DONTWAIT/SS_NBIO | uipc_socket.c:2828/3081 | partial mbuf goes m_copym(M_NOWAIT) |
| controlp | uipc_socket.c:2888-2955 / entry 949 | control messages are an independent channel; already mbuf direct hand-out |
| MSG_OOB | uipc_socket.c:2668-2690 | independent uiomove(2682), does not go through mp0, cannot be zero-copy |
| KERN_TLS | uipc_socket.c:3456/3470 | forced fallback to soreceive_generic |

## 7. Minimal Kernel-Side Change Points (measured conclusion)
The kernel zero-copy engine is **already in place** (mp0 branch L3061-3066 / stream L3337-3359); what is missing is wiring mp0 through from user space to soreceive. By change volume:
1. **Add a receive-side ZC entry (recommended, minimal change)**: following ff_zc_send's isolation approach, add `ff_zc_recv`; add a variant beside kern_recvit that changes soreceive's 4th formal parameter from hardcoded NULL (L948) to accepting a pass-through `struct mbuf **mp`. Constraint: after the user obtains the mbuf chain, it is responsible for `m_freem` to return it.
2. **TCP needs no protocol-layer change**: the default soreceive_generic already supports mp0; soreceive_stream also supports it.
3. **Non-zero-copy boundaries fall back to copy** (reuse existing): split→m_copym; PEEK/OOB/TLS→status quo; UDP soreceive_dgram falls back to generic when mp0!=NULL (L3508), naturally usable.
4. **No accounting/locking change needed**: the zero-copy branch already does sbfree accounting within the lock, sb_mb is already advanced, semantics are self-consistent.

> In one sentence: **the ZC-read kernel engine is ready (mp0 branch); the only engineering work is to add the mbuf out-parameter pass-through channel between kern_recvit/dofileread and the f-stack user-space API + design the mbuf return interface.**
