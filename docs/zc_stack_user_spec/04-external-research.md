# 04 · External Material Research and Cross-Verification

> Probe: research-ext. External material is inspiration only; every citation is annotated for whether it is consistent with the f-stack measured code; where inconsistent, code prevails.

## 1. FreeBSD Official Manual —— soreceive mp0 (authoritative corroboration, fully consistent with code)
Source: FreeBSD `SOCKET(9)` / `soreceive_generic(9)` manual (authors Robert Watson & Benjamin Kaduk, 2014-05-26).
Prototype: `int soreceive(struct socket *so, struct sockaddr **psa, struct uio *uio, struct mbuf **mp0, struct mbuf **controlp, int *flagsp);`
**Original text**:
> "Data may be retrieved directly to kernel or user memory via the `uio` argument, **or as an mbuf chain returned to the caller via `mp0`, avoiding a data copy**. The `uio` must always be non-NULL. **If `mp0` is non-NULL, only the `uio_resid` of `uio` is used**."

**Cross-verification**: fully matches the 02 §3 measurement —— when `mp0!=NULL`, soreceive returns an mbuf chain, avoiding the copy (uipc_socket.c:3061-3066), and only uses uio_resid (L3050 `uio_resid-=len`). **The ZC-read kernel mechanism is a FreeBSD-native official capability, not a hack.**

BUGS note (manual):
> "The MSG_DONTWAIT flag ... may not always work with `soreceive()` when **zero copy sockets** are enabled."
→ Consistent with the 02 §6 non-blocking boundary: ZC + DONTWAIT still needs m_copym(M_NOWAIT) for partial mbufs; a boundary limitation exists.

## 2. F-Stack Official (Tencent Cloud Developer Community) —— the receive direction was not implemented at the time
Source: "F-Stack Send Zero-Copy Introduction" (2022-04-25, Tencent Cloud Developer Community).
Key points (consistent with code):
- Send zero-copy has two copy stages: ① protocol stack→DPDK rte_mbuf; ② at application-layer socket send, application layer→protocol-stack mbuf. f-stack ZC-send targets stage ② (consistent with 01 §0/§2: ff_zc_mbuf_write still bcopy, what is saved is the user→kernel socket copy).
- **Original text**: "Because our own business scenario involves very little received-packet data, the receive direction will be introduced separately later" → **confirms ZC-recv was not landed officially at the time**, consistent with this repository's `ff_zc_mbuf_read` being an empty stub (03/01 measurement).

## 3. DPDK mbuf Zero-Copy / refcount (Zhihu technical article)
Source: "DPDK Memory Management Core: the Zero-Copy Implementation of mbuf and mempool" (2025-07).
Key points: DPDK achieves mbuf zero-copy through **shared data buffers + incrementing the reference count**, avoiding the actual data copy; smart reclaim is triggered when refcount drops to zero.
**Cross-verification**: consistent in approach with the 03 §2/§3 measured EXT_FLAG_EMBREF / ext_count + rte_pktmbuf_free_seg return mechanism —— f-stack uses the BSD mbuf's m_ext refcnt to drive the DPDK seg return.

## 4. Reference to Similar Mechanisms
- FreeBSD `sosplice`/`soreceive_stream`: the mp0 path has been used by in-kernel splice (e.g. so_splice) for mbuf direct relay (corroborated by 02 §3 soreceive_stream_locked L3337-3359 m_cat handing out the whole segment).
- Conclusion: handing the mbuf chain to a consumer without copying is an existing mature kernel pattern; ZC-read extends the "consumer" from in-kernel splice to the f-stack user-space APP.

## 5. Cross-Verification Conclusion Summary
| External view | f-stack measurement | Consistency |
|---|---|---|
| soreceive mp0 can return the mbuf chain zero-copy | uipc_socket.c:3061-3066 indeed has this branch | ✅ fully consistent |
| mp0!=NULL only uses uio_resid | L3050 uio_resid-=len | ✅ consistent |
| ZC + MSG_DONTWAIT has boundary limitations | L3081 partial mbuf goes m_copym(M_NOWAIT) | ✅ consistent |
| F-Stack receive zero-copy not officially implemented | ff_zc_mbuf_read empty stub | ✅ consistent |
| DPDK refcount drives zero-copy reclaim | EXT_FLAG_EMBREF + rte_pktmbuf_free_seg | ✅ consistent |

**No conflicting items.** The external material comprehensively supports the technical route of "reusing soreceive mp0 to implement ZC-read".
