# 32. Symmetric Architecture Design — `kern_zc_sendit` ↔ `kern_zc_recvit`

> Source: probe-sosend-native + probe-zcrecv-symmetry + research-ext-zcsend
> Purpose: master diagram for 33 kernel patch / 34 API / 35 lifecycle / 36 boundary

---

## §1 Design Principles

| Principle | Description |
|---|---|
| P1 Symmetry | ZC-send fully mirrors the already-landed ZC-recv across five dimensions: kernel entry, userspace entry, lifecycle, error path, ABI delta |
| P2 Native | Directly reuse the FreeBSD 15.0 upstream `sosend(top)` path (uipc_socket.c:2599); do not modify a single line of `m_uiotombuf` / `mbuf.h` / `kern_writev` |
| P3 Minimal | Only add 1 kernel function (`kern_zc_sendit`) + 1 declaration + rewrite 1 userspace function (`ff_zc_send`) + fix 2 userspace functions (`ff_zc_mbuf_get/write`) |
| P4 ABI Stable | Zero changes to userspace function signatures; zero changes to the example/main_zc.c call sequence; the `FF_ZC_SEND` macro name is retained |
| P5 Gated | All newly added code is gated by `#ifdef FSTACK_ZC_SEND`; independent of `FSTACK_ZC_RECV`, can be toggled separately |

---

## §2 High-Level Architecture Diagram

### §2.1 Old Scheme (Hacky Modification)

```
┌────────────────────────────────────────────────────────────────────┐
│ APP                                                                 │
│   ff_zc_mbuf_get → ff_zc_mbuf_write → ff_zc_send(fd, mb, n)         │
│                                            │                        │
│                                            │ uio.iov_base=mb (char*) │
│                                            │ uio.uio_offset=MAGIC   │
└────────────────────────────────────────────┼────────────────────────┘
                                             ▼
┌────────────────────────────────────────────────────────────────────┐
│ KERNEL — 5 hacky modifications                                     │
│   ff_zc_send → kern_writev → dofilewrite [#ifdef FSTACK_ZC_SEND]   │
│              → soo_write → sousrsend → sosend → sosend_generic     │
│              → m_uiotombuf [#ifdef FSTACK_ZC_SEND magic consume]   │
│  ↑ uio_offset threaded through 5 files; ff_write/writev must opt-out│
└────────────────────────────────────────────────────────────────────┘
```

### §2.2 New Scheme (Native)

```
┌────────────────────────────────────────────────────────────────────┐
│ APP                                                                 │
│   ff_zc_mbuf_get(M_PKTHDR) → ff_zc_mbuf_write(maintain pkthdr.len)  │
│   → ff_zc_send(fd, mb, n)                                           │
│                │                                                    │
│                │ top = (struct mbuf *)mb                            │
│                │ flags = 0                                          │
└────────────────┼────────────────────────────────────────────────────┘
                 ▼
┌────────────────────────────────────────────────────────────────────┐
│ KERNEL — only add kern_zc_sendit                                   │
│   ff_zc_send → kern_zc_sendit(td, s, top, flags)                   │
│              → sosend(so, NULL, NULL, top, NULL, flags, td)        │
│              → pr_sosend → sosend_generic / sosend_dgram           │
│                ↑ takes the native if (uio == NULL) branch          │
│                  resid = top->m_pkthdr.len                          │
│                  m_uiotombuf fully skipped                          │
│  no magic, no uio_offset threading, ff_write/writev need no opt-out │
└────────────────────────────────────────────────────────────────────┘
```

---

## §3 Symmetry Table (Five-Dimension Mirror with ZC-recv)

| Dimension | ZC-recv (landed, commit b87f5f0d2) | ZC-send (specified in this spec) |
|---|---|---|
| **Kernel entry function** | `kern_zc_recvit(td, s, uio, mp0)` (uipc_syscalls.c:1065) | `kern_zc_sendit(td, s, top, flags)` new |
| **Declaration location** | `freebsd/sys/syscallsubr.h:304-310` `#ifdef FSTACK_ZC_RECV` | similar location in `freebsd/sys/syscallsubr.h` `#ifdef FSTACK_ZC_SEND` |
| **Core BSD call** | `soreceive(so, NULL, uio, &chain, NULL, &flags)` | `sosend(so, NULL, NULL, top, NULL, flags, td)` |
| **Zero-copy native branch** | the `mp0!=NULL` branch of soreceive (uipc_socket.c:~3055-3070) | the `uio==NULL` branch of sosend_generic_locked (uipc_socket.c:2456-2500) |
| **resid source** | `uio->uio_resid` (input budget) | `top->m_pkthdr.len` (uipc_socket.c:2340-2341) |
| **Bypass point** | `uiomove(mtod, ..., uio)` (@~3022-3031) | `m_uiotombuf(uio, ..., flags)` (@2490) |
| **MAC check** | `mac_socket_check_receive` (uipc_syscalls.c:1083) | `mac_socket_check_send` (introduced at implementation time) |
| **fd resolution** | `getsock(td, s, &cap_recv_rights, &fp)` | `getsock(td, s, &cap_send_rights, &fp)` |
| **Error path** | error and chain already populated → `m_freem(chain)` (uipc_syscalls.c:1107-1108) | error → `m_freem(top)` (see 33 §3 at implementation time) |
| **Success semantics** | `*mp0 = chain; td->td_retval[0] = len - resid` | `td->td_retval[0] = len - uio_resid_simulated` (no uio; derived from the sosend return value) |
| **Userspace entry function** | `ssize_t ff_zc_recv(int fd, struct ff_zc_mbuf *zm, size_t nbytes)` | `ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes)` (signature retained) |
| **lib implementation location** | `ff_syscall_wrapper.c` ZC-recv block (commit b87f5f0d2) | `ff_syscall_wrapper.c:1186-1226` rewrite |
| **mbuf manipulation API** | `ff_zc_mbuf_read` / `ff_zc_mbuf_segment` / `ff_zc_recv_free` | `ff_zc_mbuf_get` / `ff_zc_mbuf_write` (retained + M_PKTHDR fix) |
| **ABI delta** | +3 symbols (recv/segment/free) | 0 symbols (only ff_zc_send implementation changes) |
| **ff_api.symlist delta** | 3 lines | 0 lines |
| **Makefile switch** | `FF_ZC_RECV → -DFSTACK_ZC_RECV` | `FF_ZC_SEND → -DFSTACK_ZC_SEND` (retained, meaning switched) |

---

## §4 Key Kernel Path Anchors (Measured)

### §4.1 sosend dispatch — accepts non-NULL top (kernel-thread entry)

`uipc_socket.c:2598-2609`:

```c
int
sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
    struct mbuf *top, struct mbuf *control, int flags, struct thread *td)
{
    int error;
    CURVNET_SET(so->so_vnet);
    error = so->so_proto->pr_sosend(so, addr, uio, top, control, flags, td);
    CURVNET_RESTORE();
    return (error);
}
```

Comment (uipc_socket.c:2590-2597) verbatim: "Send to a socket from a kernel thread. … in almost all cases uio is NULL and the mbuf is supplied."—— i.e. `sosend()` is the kernel-thread entry that **accepts a non-NULL `top`**.

### §4.2 sousrsend forces top=NULL — not reusable

`uipc_socket.c:2624-2626`:

```c
CURVNET_SET(so->so_vnet);
    error = so->so_proto->pr_sosend(so, addr, uio, NULL, control, flags, td);
                                                ^^^^ hardcoded
    CURVNET_RESTORE();
```

→ The syscall layer (kern_sendit / soo_write / aio) all goes through sousrsend with `top=NULL`; **the new scheme bypasses sousrsend and calls sosend directly**.

### §4.3 sosend_generic_locked top!=NULL Path

#### resid derivation — uipc_socket.c:2338-2343

```c
if (uio != NULL)
    resid = uio->uio_resid;
else if ((top->m_flags & M_PKTHDR) != 0)
    resid = top->m_pkthdr.len;     ← key: M_PKTHDR is required
else
    resid = m_length(top, NULL);   ← O(chain-length) fallback
```

#### inner loop skips m_uiotombuf — uipc_socket.c:2456-2500

```c
do {
    if (uio == NULL) {
        resid = 0;                 ← one-shot delivery (atomic)
        if (flags & MSG_EOR)
            top->m_flags |= M_EOR;
#ifdef KERN_TLS
        if (tls != NULL) {
            ktls_frame(top, tls, &tls_enq_cnt, tls_rtype);
            tls_rtype = TLS_RLTYPE_APP;
        }
#endif
    } else {
        ...
        top = m_uiotombuf(uio, M_WAITOK, space, ...);   ← copy path
        ...
    }
```

→ When `top!=NULL && uio==NULL`, **m_uiotombuf is never called**; it merely sets `resid=0` + EOR/KTLS as needed.

#### atomic determined by top — uipc_socket.c:2325

```c
int atomic = sosendallatonce(so) || top;
```

→ `top!=NULL` is automatically atomic (i.e. one-shot delivery, no fragmentation). This is consistent with the `PR_ATOMIC` protocol; TCP (non-PR_ATOMIC) must consider the sb_max limit under atomic=1 (see 36 for details).

### §4.4 sosend_dgram top Path

`uipc_socket.c:2160-2270` is isomorphic (DGRAM, UDP/UNIX-DGRAM):
- `if (uio == NULL)` takes `top->m_pkthdr.len` as resid (L2170 etc.)
- error path `m_freem(top)` as fallback (DGRAM internally self-frees failed mbufs)

→ Under the new scheme UDP/UNIX-DGRAM is automatically supported, no special handling needed. See the 36 boundary matrix for details.

---

## §5 Data Structure Comparison

### §5.1 struct ff_zc_mbuf (lib/ff_api.h:347, unchanged)

```c
struct ff_zc_mbuf {
    void *bsd_mbuf;       /* points to the BSD mbuf chain head */
    void *bsd_mbuf_off;   /* SEND: current write node / RECV: current read node */
    int   off;            /* in-chain offset */
    int   len;            /* SEND: total requested length / RECV: actual received length */
};
```

Under the new scheme the field semantics are completely identical to the old scheme; the only change is that **the chain head node must carry `M_PKTHDR`**, and `pkthdr.len` equals the accumulated bytes written (see 34 for details).

### §5.2 mbuf Chain Structure (Chain Head vs Chain Tail)

```
zc_buf.bsd_mbuf (chain head)
  ├─ M_PKTHDR ✓     (old scheme: ✗ none — this is the gap)
  ├─ pkthdr.len = N  (old scheme: always 0 — this is the sosend failure root cause)
  ├─ m_data, m_len
  └─ m_next ─→ mb1 (mid-chain)
                ├─ m_data, m_len
                └─ m_next ─→ mb2 (chain tail)
                              ├─ m_data, m_len
                              └─ m_next = NULL
```

`zc_buf.bsd_mbuf_off` (SEND): records the current write position across multiple `ff_zc_mbuf_write` calls, resuming across calls; symmetric with ZC-recv's "current read node" semantics.

---

## §6 List of New/Rewritten Components

| # | Component | Type | File:approx. line | Detailed spec |
|---|---|---|---|---|
| K1 | `kern_zc_sendit` implementation | NEW | freebsd/kern/uipc_syscalls.c (beside kern_sendit) | 33 §2 |
| K2 | `kern_zc_sendit` declaration | NEW | freebsd/sys/syscallsubr.h (beside kern_sendit, #ifdef gated) | 33 §1 |
| U1 | `ff_zc_send` rewrite | REWRITE | lib/ff_syscall_wrapper.c:1186-1226 | 34 §3 |
| U2 | `ff_zc_mbuf_get` add M_PKTHDR | MODIFY | lib/ff_veth.c:306-323 | 34 §4.1 |
| U3 | `ff_zc_mbuf_write` maintain pkthdr.len | MODIFY | lib/ff_veth.c:325-356 | 34 §4.2 |
| D1 | mbuf.h FSTACK_ZC_MAGIC macro | DELETE | freebsd/sys/mbuf.h:1856-1869 | 31 §3.1 |
| D2 | uipc_mbuf.c m_uiotombuf whole block | DELETE/RESTORE-VANILLA | freebsd/kern/uipc_mbuf.c:1955-2077 | 33 §3 |
| D3 | sys_generic.c uio_offset guard | DELETE | freebsd/kern/sys_generic.c:560-573 | 31 §3.3 |
| D4 | ff_syscall_wrapper.c ff_write opt-out | DELETE | lib/ff_syscall_wrapper.c:1146-1151 | 31 §3.4 |
| D5 | ff_syscall_wrapper.c ff_writev opt-out | DELETE | lib/ff_syscall_wrapper.c:1175 | 31 §3.5 |

Total: 2 NEW + 3 MODIFY + 5 DELETE = 10 changes.

Compared to the ZC-recv landing (commit b87f5f0d2, 2 NEW + 1 MODIFY + 1 SYMBOL = 4 changes) —— this round is slightly more but **all are reversible operations** (DELETE rolls back to vanilla, with no new intrusive points).

---

## §7 sequence diagram — userspace success path

```
APP                ff_zc_send       kern_zc_sendit       sosend           pr_sosend
  │                     │                  │                 │                 │
  │ ff_zc_mbuf_get      │                  │                 │                 │
  │  (M_PKTHDR)         │                  │                 │                 │
  ├────────────────────▶│                  │                 │                 │
  │ ff_zc_mbuf_write    │                  │                 │                 │
  │  (pkthdr.len += n)  │                  │                 │                 │
  ├────────────────────▶│                  │                 │                 │
  │ ff_zc_send(fd,top,n)│                  │                 │                 │
  ├────────────────────▶│                  │                 │                 │
  │                     │ kern_zc_sendit   │                 │                 │
  │                     │  (td, s, top, 0) │                 │                 │
  │                     ├─────────────────▶│                 │                 │
  │                     │                  │ getsock + MAC   │                 │
  │                     │                  │ sosend(uio=NULL)│                 │
  │                     │                  ├────────────────▶│                 │
  │                     │                  │                 │ pr_sosend(top)  │
  │                     │                  │                 ├────────────────▶│
  │                     │                  │                 │  uio==NULL branch│
  │                     │                  │                 │  resid=pkthdr.len
  │                     │                  │                 │  enqueue sb_mb  │
  │                     │                  │                 │◀────────────────│
  │                     │                  │  td_retval[0]=n │                 │
  │                     │                  │◀────────────────│                 │
  │                     │  rc = n          │                 │                 │
  │                     │◀─────────────────│                 │                 │
  │  rc = n             │                  │                 │                 │
  │◀────────────────────│                  │                 │                 │
```

Error path (sosend inside kern_zc_sendit returns error and has not taken over top): see 35 lifecycle for details.

---

## §8 Co-stack Relationship with ZC-recv

`FF_ZC_SEND` and `FF_ZC_RECV` are completely independent:
- either one can be enabled alone (each has its own `ifdef` in lib/Makefile);
- both can be enabled at the same time (verified in the M2 phase, commit 8a06862cd / de58b11e9);
- they share the same `struct ff_zc_mbuf` data structure (reusing different field semantics, see §5.1);
- they share the same comment system and spec numbering (30+ ZC-send / 11-19 ZC-recv).

→ After this spec is implemented, `zc_stack_user` forms a **truly symmetric userspace zero-copy stack**:
```
APP ↔ ff_zc_recv / ff_zc_mbuf_segment / ff_zc_recv_free      (RECV, mp0)
APP ↔ ff_zc_send / ff_zc_mbuf_get / ff_zc_mbuf_write         (SEND, top)
```

---

Next: **33-kernel-patch-spec.md** (detailed kernel patch spec, including c-precision-surgery anchors).
