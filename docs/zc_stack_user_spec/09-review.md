# 09 · Document Review Gate Record

> gatekeeper (independent spot-check). Review across 4 dimensions: ① reference authenticity ② line-number/symbol match ③ conclusion has rationale ④ no speculation.

## Key Reference Spot-Check Results (measured grep/sed verification)
| Check item | Doc assertion | Measured verification | Result |
|---|---|---|---|
| G1 | ff_zc_mbuf_read empty stub @ ff_veth.c:359 | `ff_zc_mbuf_read(...){ // DOTO...; return 0; }` indeed at 358-363 | ✅ |
| G2 | ff_zc_send sets uio_offset=MAGIC | `auio.uio_offset = FSTACK_ZC_MAGIC` @ ff_syscall_wrapper.c:1216 | ✅ |
| G3 | FSTACK_ZC_MAGIC definition | `#define FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)` @ mbuf.h:1868 | ✅ |
| G4 | RX m_extadd EXT_DISPOSABLE | `m_extadd(m,data,len,ff_mbuf_ext_free,pkt,NULL,0,EXT_DISPOSABLE)` @ ff_veth.c:374 (multi-segment 399) | ✅ |
| G5 | kern_recvit soreceive mp0 hardcoded NULL | `soreceive(so, &fromsa, &auio, NULL,` @ uipc_syscalls.c:948 | ✅ |
| G6 | soreceive mp!=NULL zero-copy direct hand-out branch | `sbfree(...); if(mp!=NULL){ *mp=m; mp=&m->m_next; sb_mb=m=m->m_next; }` @ uipc_socket.c:~3060-3066 | ✅ |
| G7 | mp==NULL uiomove copy point | `if(mp==NULL){ ... uiomove(mtod(m,char*)+moff,len,uio) }` @ uipc_socket.c:~3022-3031 | ✅ |

Spot-check hit rate **7/7 = 100%**. All line numbers match within tolerance (mp branch is actually sbfree@3060 / *mp=m@3063, doc annotates 3061-3066, matches).

## 4-Dimension Adjudication
| Doc | Reference authenticity | Line-number match | Conclusion has rationale | No speculation | Verdict |
|---|---|---|---|---|---|
| 00-plan | N/A | N/A | ✓ | ✓ | PASS |
| 01-zcsend-baseline | ✓ | ✓ | ✓ | ✓ | PASS |
| 02-recv-path-analysis | ✓ | ✓ | ✓ | ✓ | PASS |
| 03-extmbuf-lifecycle | ✓ | ✓ | ✓ | ✓ (§4/§5 design-level items annotated "design verification needed") | PASS |
| 04-external-research | ✓ (external+code cross) | ✓ | ✓ | ✓ | PASS |
| 05-design-and-feasibility | ✓ | ✓ | ✓ | ✓ (effort/milestones annotated "implementation phase") | PASS |

## Acceptance Gates G-ZCR-1..7
| Gate | Result |
|---|---|
| G-ZCR-1 reference authenticity 100% hit | ✅ 7/7 |
| G-ZCR-2 ≥2 kernel mechanism comparison + recommendation | ✅ 05 §1 (A reuse mp0 / B mimic magic, A recommended) |
| G-ZCR-3 lifecycle closed-loop argument | ✅ 05 §3 + 03 §2/§4/§6 |
| G-ZCR-4 boundary matrix coverage | ✅ 05 §4 (whole/split/PEEK/WAITALL/DONTWAIT/OOB/SCM/TLS/UDP) |
| G-ZCR-5 explicit feasibility conclusion + effort + milestones | ✅ 05 §0/§5/§6 (feasible, 8-15 person-days) |
| G-ZCR-6 where external and code inconsistent, code prevails | ✅ 04 §5 all consistent, no conflict |
| G-ZCR-7 Chinese-only + no speculation | ✅ all Chinese, design-level items all annotated |

## Bounce-Back/Correction Record
- No bounce-back. One doc-wording correction: 01 §5 clarifies "ZC-send/read are opposite in direction, the magic should not be forcibly replicated symmetrically", consistent with the 02/05 selection.

## Final Verdict: **All PASS, the feasibility study passes.**
