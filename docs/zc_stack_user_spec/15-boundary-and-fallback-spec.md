# 15 · Boundary and Fallback Spec

> Anchors see 02 §3/§6 (measured). Principle: scenarios where zero-copy is not possible all fall back to the existing copy path, guaranteeing semantics consistent with the current state.

## 1. Boundary Matrix
| Scenario | ZC? | Handling | Anchor | Note |
|---|---|---|---|---|
| Whole mbuf (len==m_len-moff) | ✅ ZC | sbfree+*mp=m direct handover | uipc_socket.c:~3061-3066 | Main path |
| Partial mbuf (split, len<m_len) | ❌ fallback | m_copym (M_WAITOK/M_NOWAIT) | uipc_socket.c:~3081/3098 | Copies out a new mbuf, APP can still m_freem |
| MSG_PEEK | ❌ fallback | does not unlink the chain; goes copy | uipc_socket.c:~3055/3076 | ZC and PEEK are mutually exclusive, ff_zc_recv does not pass PEEK |
| MSG_WAITALL | ⚠ multi-round ZC | accumulate zero-copy segment by segment until full | uipc_socket.c:~3129-3165 | Feasible but multiple deliveries |
| Non-blocking MSG_DONTWAIT/SS_NBIO | ⚠ partial ZC | no data returns EAGAIN; partial mbuf m_copym(M_NOWAIT) | uipc_socket.c:~3081 + 04§1 BUGS | Official manual warns of ZC+DONTWAIT limitation |
| MSG_OOB | ❌ fallback | independent soreceive_rcvoob→uiomove | uipc_socket.c:2682 | OOB does not go through mp0 |
| Control message (SCM) | ✅ independent channel | controlp already mbuf direct handover | uipc_socket.c:~2888-2955 | Orthogonal to data mp0 |
| KERN_TLS | ❌ fallback | force soreceive_generic | uipc_socket.c:~3456/3470 | TLS decryption needs copy |
| UDP (soreceive_dgram) | ❌ fallback | when mp0!=NULL fall back to soreceive_generic | uipc_socket.c:~3508 | Naturally compatible, this feature focuses on TCP |
| SCTP | ❌ unsupported | goes sctp_soreceive | udp/sctp_usrreq.c | Not supported this period |

## 2. Fallback Decision and APP Visibility
- The kernel soreceive automatically chooses ZC/copy when mp!=NULL (whole segment vs split), transparent to ff_zc_recv.
- The zm->bsd_mbuf chain the APP obtains may mix ext-mbuf (ZC segments) and m_copym ordinary mbuf (split segments); **m_freem is correct for both** (14 §4).
- ff_zc_recv **should not** pass MSG_OOB; if MSG_PEEK is passed, it degrades to copy (no error, but no zero-copy benefit).

## 3. Protocol Applicability
- **TCP**: default soreceive_generic supports mp0; soreceive_stream (sysctl net.inet.tcp.soreceive_stream) also supports → ZC main scenario.
- **UDP/SCTP**: fallback/unsupported, ff_zc_recv behavior equivalent to ordinary recv (correct but no benefit).

## 4. Errors and Partial Packets
- Partial packet (data has not reached nbytes): return actual bytes, APP handles by len; subsequent ff_zc_recv again.
- Connection closed: return 0, zm has no chain.
- Error: return -1 + errno, zm has no chain, no need to free.
