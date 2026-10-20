# 35. mbuf Chain Ownership State Machine and Invariants

> Source: probe-sosend-native (sosend error-path m_freem sites) + probe-zcrecv-symmetry (ZC-recv error-handling pattern) + FreeBSD sosend(9) upstream manual
> Goal: precisely define the ownership contract of the ff_zc_mbuf chain in user space / kernel space, avoiding use-after-free / double-free / leaks

---

## §1 State Machine

```
                            ┌───────────────────────────────────────────────────┐
                            │                                                   │
                            ▼                                                   │
   ┌───────────┐  get   ┌──────────┐  write   ┌──────────┐  send err ┌──────────┴──┐
─▶│  S0 NONE   │──────▶│  S1 EMPTY │────────▶│  S2 FILL  │─────────▶│  S4 ERROR    │
   └───────────┘        │  M_PKTHDR │          │ pkthdr.len│           │ kern frees  │
                        │ pkthdr.len│          │  > 0      │           │ via m_freem │
                        │  = 0      │          └─────┬────┘           └─────────────┘
                        └──────────┘                 │ send ok
                                                     ▼
                                              ┌──────────────┐
                                              │  S3 ADOPTED  │
                                              │ kernel owns  │
                                              │ (via sosend) │
                                              └──────────────┘
```

### §1.1 State Definitions

| State | Identifier | Description |
|---|---|---|
| S0 NONE | `zc_buf.bsd_mbuf == NULL` | ff_zc_mbuf_get not yet called |
| S1 EMPTY | M_PKTHDR + pkthdr.len=0 | after get; no data written yet |
| S2 FILL | M_PKTHDR + pkthdr.len>0 | after write; may continue writing or send |
| S3 ADOPTED | kernel has taken over, user space must not access | after ff_zc_send succeeds |
| S4 ERROR | kernel has freed via m_freem (KERN_OWNED) | after ff_zc_send fails |

### §1.2 State Transition Rules

| from | event | to | Note |
|---|---|---|---|
| S0 | ff_zc_mbuf_get(len) | S1 | kernel m_getm2(M_PKTHDR) allocation |
| S1 | ff_zc_mbuf_write(d, n) | S2 | progress=n; pkthdr.len accumulated |
| S2 | ff_zc_mbuf_write(d, n) | S2 | multiple writes accumulate; progress<=zc_buf.len |
| S2 | ff_zc_send(...) success | S3 | kernel sosend takes over, user-space pointer is **invalidated** |
| S2 | ff_zc_send(...) failure | S4 | kern_zc_sendit has done m_freem(top), user-space pointer is **invalidated** |
| S3 / S4 | any user-space access | **UAF error** | triggers use-after-free |
| S3 / S4 | ff_zc_mbuf_get(zc_buf, len) | S1 | reuse zc_buf struct; re-get the chain |

---

## §2 Invariants (INV)

### INV-1: M_PKTHDR + pkthdr.len consistency

> In states S1 / S2, the chain head pointed to by `zc_buf.bsd_mbuf` **must** satisfy `(m->m_flags & M_PKTHDR) != 0`, and `m->m_pkthdr.len == sum(mb->m_len for mb in chain)` (but may be < zc_buf.len, i.e. trailing space not fully written).

**Consequence of violation**: sosend takes resid incorrectly in the `uio==NULL` branch (uipc_socket.c:2340-2341):
- missing M_PKTHDR → falls back to `m_length()` O(N) scan; not a crash, but slow;
- pkthdr.len=0 → resid=0 → immediately returns 0 bytes sent, user perceives "send not working" (hit during the M2 phase).

**Guarantee mechanism**: ff_zc_mbuf_get forces the `M_PKTHDR` flag; ff_zc_mbuf_write accumulates `pkthdr.len += progress` on the chain head (see 34 §4.2).

### INV-2: single ownership point (no double ownership)

> At any moment, ownership of the chain head `top` belongs to **and only to** one of user space or kernel space.
> - **Before** user space calls ff_zc_send: user space owns it exclusively.
> - After ff_zc_send returns (regardless of success/failure): kernel owns it exclusively (on success it is taken over by sosend/sb_mb; on failure it has already been freed by kern_zc_sendit/m_freem).

**Consequence of violation**:
- double m_freem → kernel panic / memory corruption;
- user space accessing it again after send → UAF.

**Guarantee mechanism**:
- user space: after ff_zc_send returns, it is **forbidden** to use `zc_buf.bsd_mbuf` for read/write again (spec requirement; the code cannot enforce it, relies on the spec);
- kernel space: the kern_zc_sendit error path **uniformly does m_freem**; on the sosend error path, if protosw has already freed internally then kern_zc_sendit does **not** m_freem again (relies on the sosend interface contract, see §3).

### INV-3: no leak on error

> Any failed ff_zc_send call leaves **no** leaked mbuf chain — either kern_zc_sendit does m_freem immediately, or sosend does m_freem internally.

**Guarantee mechanism**:
- input validation failure (top NULL / no M_PKTHDR / pkthdr.len < 0): kern_zc_sendit immediately `m_freem(top)` (33 §2.2 lines 16-19, 22-25);
- getsock / MAC failure: kern_zc_sendit immediately `m_freem(top)` (33 §2.2 lines 32-35, 41-43);
- sosend failure: handled per the sosend internal spec, see §3.

---

## §3 sosend Error-Path Ownership Matrix (measured, probe-sosend-native)

> The disposition of top on a sosend error varies by protosw implementation. The matrix below is based on the m_freem(top) sites of sosend_generic_locked (uipc_socket.c:2390-2580) + sosend_dgram (uipc_socket.c:2160-2270) measured by probe-sosend-native:

| sosend internal site | line range | top disposition | subsequent kern_zc_sendit action |
|---|---|---|---|
| sosend_dgram input check failure | ~2200 | m_freem(top) inside sosend_dgram | does **not** m_freem again (INV-2 guard) |
| sosend_dgram pr_send returns error | ~2260 | top already handed to pr_send, freed by protocol layer m_freem | does **not** m_freem again |
| sosend_generic atomic delivery failure (sb_max insufficient) | ~2400 | m_freem(top) by sosend itself | does **not** m_freem again |
| sosend_generic SOCK_STREAM + MSG_EOR (EINVAL @ 2354) | 2354-2360 | top handled by the branch above sosend goto out; usually freed | does **not** m_freem again |
| sosend_generic pr_send returns EWOULDBLOCK (atomic one-shot, no fragmentation) | ~2540 | top handled by pr_send; sosend no longer holds it | does **not** m_freem again |

**Conclusion (INV-3 implementation rules)**:
1. **After kern_zc_sendit calls sosend, it does not m_freem(top) again, regardless of success/failure**;
2. this relies on FreeBSD sosend's "caller lets go" contract (implied by the sosend(9) manual; measured evidence: multiple m_freem(top) sites inside sosend);
3. exception: when kern_zc_sendit's own input validation / getsock / MAC fails (before calling sosend), kern_zc_sendit explicitly m_freem.

> **Risk note**: if some protosw implementation of sosend violates this contract (returns error but does not free top), it leaks. This spec assumes by default that vanilla FreeBSD 15.0's inet/unix/raw and other protosw are all compliant; if valgrind testing during the implementation phase finds a leak, it must bounce back to 33 §2.3 to adjust the kern_zc_sendit error fallback.

---

## §4 Symmetry with ZC-recv (measured comparison)

### §4.1 ZC-recv error path (already landed)

`uipc_syscalls.c:1100-1108` (kern_zc_recvit):

```c
if (error == 0) {
    td->td_retval[0] = len - uio->uio_resid;
    *mp0 = zc_chain;
} else if (zc_chain != NULL) {
    /* error after some mbufs were detached: free them */
    m_freem(zc_chain);
}
```

### §4.2 ZC-send error path (specified by this spec)

`kern_zc_sendit` (33 §2.2):

```c
if (top == NULL || (top->m_flags & M_PKTHDR) == 0) {
    if (top != NULL) m_freem(top);
    return (EINVAL);
}
... // getsock/MAC failure also m_freem(top)

error = sosend(so, NULL, NULL, top, NULL, flags, td);
/* no further m_freem(top): sosend manages it itself */
```

### §4.3 Symmetry difference notes

| Dimension | ZC-recv | ZC-send |
|---|---|---|
| chain ownership direction | kernel → user space | user space → kernel |
| who frees on error | kern_zc_recvit (when chain != NULL) | kern_zc_sendit during the input validation phase; during the sosend phase, by sosend internally |
| user-space free API | `ff_zc_recv_free` explicitly calls m_freem | **none** — user space does not hold it after send, no free needed |

---

## §5 sequence diagram — error path

### §5.1 input validation failure (top missing M_PKTHDR)

```
APP                ff_zc_send       kern_zc_sendit
  │                     │                  │
  │ ff_zc_send(fd,top,n)│                  │
  ├────────────────────▶│                  │
  │                     │ kern_zc_sendit   │
  │                     ├─────────────────▶│
  │                     │                  │ if (!(top->m_flags & M_PKTHDR))
  │                     │                  │     m_freem(top);   ← free immediately
  │                     │                  │     return EINVAL;
  │                     │  rc=-1, EINVAL   │
  │                     │◀─────────────────│
  │  rc=-1, errno=EINVAL│                  │
  │◀────────────────────│                  │
```

### §5.2 sosend failure (EPIPE)

```
APP                ff_zc_send       kern_zc_sendit       sosend           pr_sosend
  │ ...                │                  │                 │                 │
  │                     │ kern_zc_sendit   │                 │                 │
  │                     ├─────────────────▶│                 │                 │
  │                     │                  │ getsock OK      │                 │
  │                     │                  │ MAC OK          │                 │
  │                     │                  │ sosend(NULL,top)│                 │
  │                     │                  ├────────────────▶│                 │
  │                     │                  │                 │ pr_sosend       │
  │                     │                  │                 ├────────────────▶│
  │                     │                  │                 │     EPIPE       │
  │                     │                  │                 │ m_freem(top)    │
  │                     │                  │                 │◀────────────────│
  │                     │                  │  EPIPE          │                 │
  │                     │                  │◀────────────────│                 │
  │                     │                  │ tdsignal(SIGPIPE) (unless SO_NOSIGPIPE/MSG_NOSIGNAL)
  │                     │                  │ fdrop, return EPIPE
  │                     │  rc=-1, EPIPE    │                 │
  │                     │◀─────────────────│                 │
  │  rc=-1, errno=EPIPE │                  │                 │
  │  + SIGPIPE          │                  │                 │
  │◀────────────────────│                  │                 │
```

Note: after user space receives -1 in §5.2, `zc_buf.bsd_mbuf` is already a dangling pointer (the KERN_OWNED state is converted to KERN_FREED by sosend's internal m_freem); ff_zc_send no longer returns the chain for user-space access.

---

## §6 Multiple ff_zc_mbuf_write (partial write) states

```
ff_zc_mbuf_get(zc, 4096)        // S1 EMPTY: pkthdr.len=0, off=0, len=4096
ff_zc_mbuf_write(zc, "ab", 2)   // S2 FILL: pkthdr.len=2, off=2
ff_zc_mbuf_write(zc, "cd", 2)   // S2 FILL: pkthdr.len=4, off=4
... user decides not to write more ...
ff_zc_send(fd, zc.bsd_mbuf, 4096)
                                // ⚠ warning: pkthdr.len=4 but nbytes=4096
                                // sosend takes resid=top->m_pkthdr.len=4
                                // → actually only sends 4 bytes, returns 4
```

→ Under the new scheme, ff_zc_send's `nbytes` parameter **only does a bounds check** (preventing overflow of INT_MAX), and is **not** used as resid (resid is derived by sosend from top->m_pkthdr.len). This differs semantically from the old scheme (in which nbytes determined uio_resid), but **has zero impact on the caller**: the user expects "send as much as has been written", which the new scheme satisfies exactly.

> **Implicit spec clause**: the caller should ensure `nbytes >= sum(len of write calls)` (to prevent passing the INT_MAX overflow check while misjudging pkthdr.len); see 36 §UDP / §sb_max.

---

## §7 Memory Safety Test Matrix (elaborated in 37)

| Test point | INV | Test method | Trigger |
|---|---|---|---|
| L1 | INV-1 | unit: construct a chain without M_PKTHDR → ff_zc_send should return EINVAL | mock kern_zc_sendit |
| L2 | INV-1 | unit: pkthdr.len < 0 → EINVAL | direct construction |
| L3 | INV-2 | integration: access zc_buf.bsd_mbuf again after a successful send → valgrind reports invalid read | example refit |
| L4 | INV-3 | integration: valgrind --track-fds running ff_zc_send EPIPE 100 times → 0 leak | close the peer to trigger EPIPE |
| L5 | INV-3 | integration: DPDK rte_mempool count check (before-after diff 0) | ff_dpdk_pktmbuf_pool count API |
| L6 | INV-1 | integration: after running wrk for real, dump struct mbuf → pkthdr.len == bytes written | gdb attach |

See 37-test-spec.md.

---

## §8 Gatekeeper-Verifiable Clauses (gatekeeper)

| Clause | Verification method | Pass criterion |
|---|---|---|
| L-G1 | check that the spec state machine covers S0-S4 | all 5 states described |
| L-G2 | check the three invariants INV-1 / INV-2 / INV-3 | all carry "consequence of violation" + "guarantee mechanism" |
| L-G3 | check the sosend error-site matrix | ≥3 protosw paths |
| L-G4 | check the symmetry comparison with ZC-recv | references the actual code of uipc_syscalls.c:1100-1108 |

---

Next: **36-boundary-and-fallback-spec.md** (boundary matrix).
