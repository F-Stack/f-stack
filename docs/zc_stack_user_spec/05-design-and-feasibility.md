# 05 · Design and Feasibility Conclusion (FSTACK_ZC_RECV)

> Based on the synthesis of 01-04 measurements + cross-verification. Conclusions are traceable to code; unverified design-level items are explicitly annotated "pending implementation verification".

## 0. Feasibility Conclusion (conclusion first)
**Conclusion: feasible (high confidence).** Core rationale:
1. The kernel zero-copy engine is **already natively in place** —— the `mp0!=NULL` branch of `soreceive_generic_locked` (uipc_socket.c:3061-3066) returns the mbuf chain, avoiding the copy, and is confirmed by the FreeBSD official manual (04 §1).
2. RX-side **data is already zero-copy** —— the DPDK mbuf is attached as a BSD ext-mbuf via m_extadd(EXT_DISPOSABLE) (03 §1); the sole residual copy point is soreceive→uiomove (02 §2).
3. Ownership transfer **has ready-made refcount support** —— if the BSD mbuf is not released, the DPDK seg is not reclaimed (03 §2/§4).
**The sole gap**: the mp0 pass-through channel from user space to soreceive + the APP-side release contract. **This is controllable engineering work, not an architectural obstacle.**

## 1. Kernel Mechanism Selection Comparison

| Dimension | Option A: reuse soreceive mp0 (recommended) | Option B: mimic send's FSTACK_ZC_RECV sentinel hook |
|---|---|---|
| Principle | kern_recvit changes soreceive's 4th argument from NULL to a pass-through mp out-parameter | add a magic determination at soreceive/uiomove; a special path returns the mbuf |
| Kernel change surface | minimal: only kern_recvit(uipc_syscalls.c:948) + one new entry | large: must change the soreceive copy loop logic, intruding the core path |
| Consistency with upstream | high (mp0 is a FreeBSD-native official capability) | low (a homemade hack, prone to conflicts when upgrading FreeBSD) |
| Risk | low (reuses a mature branch + existing accounting/locking, self-consistent per 02 §4) | high (changing soreceive easily introduces regressions) |
| Protocol-layer change | none (TCP default soreceive_generic already supports it; UDP dgram falls back to generic when mp0!=NULL, L3508) | may need multi-protocol adaptation |
| Symmetry | asymmetric with send but cleaner | superficially symmetric with send, but forcing symmetry while the direction is actually opposite |

**Option A recommended**. Reasons: mp0 is FreeBSD's official zero-copy API (corroborated by the 04 §1 manual), with the smallest change, lowest risk, and upgrade-friendliness; send's magic mechanism, because the direction is opposite (user→kernel vs kernel→user), should not be forcibly mirrored (01 §5).

## 2. API Design (proposed)
Symmetric to send's get/write/send, the read side needs three stages recv→consume→release:

```c
/* 1) Zero-copy receive the mbuf chain from the socket; on success zm->bsd_mbuf points to the chain handed out by the kernel, returns the byte count */
ssize_t ff_zc_recv(int fd, struct ff_zc_mbuf *zm, size_t nbytes);

/* 2) Sequentially read out/traverse the mbuf chain data (redesign the existing empty stub ff_zc_mbuf_read)
 *    The current signature const char*data contradicts read-out semantics; it should be changed to an out-parameter or return a segment pointer/length */
int ff_zc_mbuf_read(struct ff_zc_mbuf *zm, char *out, int len);   /* drop const from data, make it OUT */
/* Or zero-copy traversal: */
int ff_zc_mbuf_segment(struct ff_zc_mbuf *zm, void **seg_data, int *seg_len);

/* 3) After the APP finishes reading, return the whole chain (triggers per-segment ff_mbuf_ext_free → rte_pktmbuf_free_seg) */
void ff_zc_recv_free(struct ff_zc_mbuf *zm);   /* internally m_freem(zm->bsd_mbuf) */
```
- `struct ff_zc_mbuf` is reusable (01 §1.1): bsd_mbuf=chain head, bsd_mbuf_off=traversal cursor, off=read offset, len=total length.
- Kernel side: add `ff_zc_recv` → a new kern_recvit variant (passing through `struct mbuf **mp`) → soreceive(..., mp, ...).

## 3. mbuf Lifecycle / Ownership Scheme (closed-loop argument)
- Take out: the mp0!=NULL branch `sbfree`(L3060)+`*mp=m`(L3063); the kernel **does not m_free** (L3068 only goes when mp==NULL), sb_mb is advanced(L3065) → the kernel side no longer holds it, no double free (verified in 03 §6).
- Hold: the BSD ext-mbuf is in the APP's hands, m_ext refcnt>0 → the DPDK seg is not reclaimed (03 §2 the return chain is driven by BSD free) → **no use-after-free**.
- Return: `ff_zc_recv_free`→`m_freem(chain)`→ each segment's refcnt drops to zero → ff_mbuf_ext_free → ff_rte_frm_extcl(takes ext_arg1) → rte_pktmbuf_free_seg → DPDK seg returned.
- **Mandatory contract**: the APP must release, otherwise the mempool leaks (03 §6). Recommend documentation + a debug-phase mbuf-count warning.

## 4. Boundary-Handling Matrix
| Scenario | Design handling | Rationale |
|---|---|---|
| whole mbuf (len==m_len-moff) | zero-copy direct hand-out | uipc_socket.c:3061-3066 |
| partial mbuf (split) | fall back to m_copym (non-zero-copy, but correct) | L3081/3098 |
| MSG_PEEK | ZC not supported, fall back to copy | does not detach the chain L3055/3076 |
| MSG_WAITALL | per-segment zero-copy multi-round delivery | L3129-3165 |
| non-blocking DONTWAIT | partial mbuf m_copym(M_NOWAIT); official manual warns of ZC+DONTWAIT limitation | L3081 + 04 §1 BUGS |
| MSG_OOB | ZC not supported (independent uiomove) | L2682 |
| control message SCM | goes the controlp independent channel (already mbuf direct hand-out) | L2888-2955 |
| KERN_TLS | fall back to soreceive_generic | L3456/3470 |
| UDP | soreceive_dgram falls back to generic when mp0!=NULL, naturally usable | L3508 |

## 5. Risk and Effort Assessment
| Risk | Level | Mitigation |
|---|---|---|
| mempool leak (APP does not release) | medium | mandatory release API + debug-phase count warning |
| split/PEEK/OOB non-zero-copy boundaries | low | explicit fall-back-to-copy, document that ZC only takes effect for large whole mbufs |
| page-array timing (FF_USE_PAGE_ARRAY) | medium | dedicated implementation-phase verification (03 §5) |
| kern_recvit variant coexisting with existing recv | low | follow ff_zc_send isolation (01 §2 mis-trigger-guard experience) |

**Effort estimate (implementation phase, not this round)**:
- Kernel: kern_recvit variant + soreceive mp pass-through (~50-100 lines);
- User space: ff_zc_recv + ff_zc_mbuf_read rewrite + ff_zc_recv_free (~100-150 lines);
- Compile switch FSTACK_ZC_RECV (lib/Makefile, mimic L212);
- Example + tests + performance baseline.
- Rough estimate **8-15 person-days** (excluding large-scale performance tuning).

## 6. Implementation Milestone Recommendations
- **M0** Kernel mp wiring: kern_recvit variant + soreceive mp pass-through, unit-verify the mbuf is handed out correctly
- **M1** User-space API: ff_zc_recv / ff_zc_mbuf_read rewrite / ff_zc_recv_free
- **M2** Lifecycle closed-loop: refcnt + release contract + leak detection; valgrind/mempool count
- **M3** Boundary completeness: split/PEEK/WAITALL/DONTWAIT/UDP fall-back correctness tests
- **M4** Example + performance baseline (compared against the copy path, large-packet receiving/proxy forwarding scenarios)
- **M5** FF_USE_PAGE_ARRAY compatibility verification

## 7. Applicable / Non-Applicable Scenarios
- **Applicable**: large-block data receiving, proxy/forwarding (forward upon receipt, copy-free), zero-copy splice-like.
- **Non-applicable/low-benefit**: small packets, MSG_PEEK, OOB, TLS, scenarios requiring immediate processing of the data content (still need to access it, immediately triggering a cache miss).

## 8. Conclusion Restated
**ZC-read is feasible**: the three foundations of the kernel engine (mp0) + RX zero-copy (ext-mbuf) + ownership (refcnt) **all already exist and are confirmed by measurement**, comprehensively corroborated by external official material (04). What remains is the engineering implementation of "the mp pass-through channel between user space↔soreceive + the release contract"; **Option A (reuse soreceive mp0)** is recommended, with controllable risk, estimated at 8-15 person-days.
