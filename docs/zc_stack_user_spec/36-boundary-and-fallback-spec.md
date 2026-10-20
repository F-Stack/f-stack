# 36. Boundary and Fallback Matrix

> Source: probe-sosend-native (all branches of sosend_generic_locked / sosend_dgram) + FreeBSD protocol-family protosw definitions
> Goal: exhaustively cover ff_zc_send's behavior under each socket type / flag / protocol feature, and specify fallback or rejection strategies

---

## §1 socket type × protocol matrix

| socket type | protocol | PR_ATOMIC | sosend path | ZC support | fallback strategy |
|---|---|---|---|---|---|
| SOCK_STREAM | TCP | NO | sosend_generic_locked | **supported** | — |
| SOCK_DGRAM | UDP | YES | sosend_dgram | **supported** (atomic one-shot delivery, subject to sb_max constraint) | EMSGSIZE |
| SOCK_DGRAM | UNIX-DGRAM | YES | sosend_dgram | **supported** | EMSGSIZE |
| SOCK_STREAM | UNIX-STREAM | NO | sosend_generic_locked | **supported** | — |
| SOCK_SEQPACKET | SCTP | YES | protosw custom | **not supported** (this phase) | degenerates to EOPNOTSUPP (decided by the implementation-phase spec; SCTP not exposed this phase) |
| SOCK_RAW | IPv4/IPv6 raw | varies | sosend_generic | **supported but cautiously** (user space must build its own IP header) | — |

---

## §2 flag matrix (kern_zc_sendit passes through to sosend)

| flag | description | behavior on the ZC path | Note |
|---|---|---|---|
| `MSG_DONTWAIT` | non-blocking | sosend will not block, returns EWOULDBLOCK when sb is full | the sosend(9) manual warns: "MSG_DONTWAIT flag is not implemented for sosend()" — measured to go through the SS_NBIO check on the atomic path (uipc_socket.c sosend_generic_locked), works but mind the BUGS section |
| `MSG_EOR` | end-of-record | top->m_flags \|= M_EOR (uipc_socket.c:2459-2460) | **immediate EINVAL on TCP** (uipc_socket.c:2354) |
| `MSG_NOSIGNAL` | suppress SIGPIPE | checked by kern_zc_sendit (33 §2.2 SIGPIPE block) | recommended to always set |
| `MSG_OOB` | out-of-band | accepted by sosend | TCP only; rarely used; passed through this phase |
| `MSG_EOF` | shutdown after send | protocol-specific | passed through; not a key test focus this phase |
| 0 (default) | — | — | recommended |

Under the new scheme, `ff_zc_send` currently always passes `flags=0`; later one may expose `ff_zc_sendmsg(fd, mb, flags)` or extend `ff_zc_send` with a 4th parameter (API increment, not in scope of this phase's spec).

---

## §3 socket option matrix

| option | impact | behavior |
|---|---|---|
| `SO_NOSIGPIPE` | suppress SIGPIPE | checked by kern_zc_sendit (33 §2.2) |
| `SS_NBIO` (i.e. `O_NONBLOCK`) | non-blocking | atomic + insufficient buffer → EWOULDBLOCK returned immediately; caller may retry or shrink mb |
| `SO_LINGER` | residual data handling on close | no direct relation to ZC; after sosend returns normally it is handled by close() |
| `SO_SNDBUF` | sb_max upper limit | on atomic delivery, `top->m_pkthdr.len > sb_max` → ENOBUFS |
| `SO_SNDTIMEO` | blocking timeout | effective under atomic blocking |

---

## §4 atomic Delivery and the sb_max Constraint

Measured `uipc_socket.c:2325`:

```c
int atomic = sosendallatonce(so) || top;
```

→ `top != NULL` forces atomic = 1. Its consequences:
1. **must deliver in one shot**: insufficient sb space → block (default) / EWOULDBLOCK (non-blocking) / ENOBUFS (buffer exhausted);
2. `top->m_pkthdr.len > sb_max` → ENOBUFS / EMSGSIZE (DGRAM path);
3. no "partial send" occurs — on success all is enqueued, on failure 0 bytes.

Caller inferences:
- TCP large data (> SO_SNDBUF) should **self-fragment**: ff_zc_mbuf_get(MIN(SNDBUF, total)) each time, send multiple times;
- UDP must be ≤ MTU - IP header (typically 1472 bytes); exceeding → EMSGSIZE;
- do not expect "send 8MB → kernel helps you split into N writes" (that is the semantics of ordinary ff_writev, not applicable to ZC).

→ **This is the root cause of F-Stack issue #712** (the original scheme crash/hang on large data): the original scheme did not respect atomic semantics on the m_uiotombuf hacked path, and an oversized mbuf would cause an abnormality on the sosend path. The new scheme explicitly follows the atomic contract, the caller is responsible for fragmentation, and instead of crashing it returns a clear error code (ENOBUFS / EMSGSIZE).

---

## §5 Compatibility with LD_PRELOAD ring mode / FF_USE_PAGE_ARRAY

| feature | relation to ZC-send | Note |
|---|---|---|
| LD_PRELOAD ring | no impact (ZC-send is a lib-internal path, no conflict with ld_preload ring's ipc delivery) | see docs/ld_preload_ring_spec |
| FF_USE_PAGE_ARRAY | orthogonal relation (FF_USE_PAGE_ARRAY manages "protocol stack→DPDK" zero-copy; ZC-send manages "application→protocol stack" zero-copy; can be enabled simultaneously) | measured that commit ca83653c1 + M2 phase passed with both coexisting |
| ZC-recv | fully independent (shares struct ff_zc_mbuf but the switch is independent) | 32 §8 |

---

## §6 Peer Address and Control Message (addr / control)

Under the new scheme, `ff_zc_send` does not support:
- specifying the peer address (sendto semantics) → the new version is **only valid for connected sockets**; UDP must connect first;
- control message SCM (cmsghdr) → not supported (kern_zc_sendit passes control=NULL).

Rationale: spec simplification, alignment with the ZC-recv design (kern_zc_recvit also has no address/control).

Future extension: one may define `ff_zc_sendto(fd, mb, n, addr, addrlen)` / `ff_zc_sendmsg(fd, msghdr)` APIs (not in scope of this phase).

---

## §7 Boundary Checklist (implementation phase + testing)

| # | boundary | spec clause | verification method |
|---|---|---|---|
| B1 | top == NULL | kern_zc_sendit returns EINVAL | unit test |
| B2 | top missing M_PKTHDR | kern_zc_sendit returns EINVAL (also m_freem) | unit test |
| B3 | top->m_pkthdr.len < 0 | kern_zc_sendit returns EINVAL | unit test |
| B4 | top->m_pkthdr.len = 0 | kern_zc_sendit calls sosend, sosend takes resid=0 and immediately returns 0 bytes | integration |
| B5 | top->m_pkthdr.len > SO_SNDBUF (TCP) | sosend blocks / non-blocking EWOULDBLOCK | integration |
| B6 | top->m_pkthdr.len > MTU (UDP) | sosend_dgram returns EMSGSIZE | integration |
| B7 | TCP + MSG_EOR | sosend returns EINVAL (uipc_socket.c:2354) | unit test |
| B8 | peer closed + no SO_NOSIGPIPE/MSG_NOSIGNAL | EPIPE + SIGPIPE | integration |
| B9 | peer closed + MSG_NOSIGNAL | EPIPE but **no** SIGPIPE | integration |
| B10 | fd is not a socket | getsock returns ENOTSOCK | unit test |
| B11 | fd already closed | getsock returns EBADF | unit test |
| B12 | UNIX-DGRAM cross-process | sosend_dgram accepts; behavior consistent with sendto | integration |
| B13 | RAW socket + self-built IP header | passed through to sosend_generic | integration (optional) |

---

## §8 Unsupported Matrix (explicitly rejected this phase)

| scenario | rejection reason | expected error code |
|---|---|---|
| sendto semantics (with addr) | API not supported (the top path does not expose addr) | caller should use connect+ff_zc_send |
| sendmsg semantics (with control) | API not supported | caller falls back to ordinary ff_sendmsg |
| SCTP socket | sosend path untested | EOPNOTSUPP |
| Datagram fragmentation > MTU | atomic one-shot | EMSGSIZE |
| Send `>` SO_SNDBUF on TCP non-blocking | atomic one-shot | EWOULDBLOCK |

---

## §9 Gatekeeper-Verifiable Clauses (gatekeeper)

| Clause | Verification method | Pass criterion |
|---|---|---|
| B-G1 | spec lists ≥10 boundaries | B1-B11+ |
| B-G2 | each boundary marks spec clause + verification method | whole table |
| B-G3 | atomic meaning references uipc_socket.c:2325 | hit |
| B-G4 | TCP+EOR references uipc_socket.c:2354 | hit |

---

Next: **37-test-spec.md** (CMocka test specification).
