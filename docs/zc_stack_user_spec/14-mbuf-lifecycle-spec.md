# 14 · mbuf Lifecycle and Ownership State Machine

> Closed-loop argumentation: no use-after-free / no leak / no double free. Anchors see 03 (measured).

## 1. Ownership State Machine
```
[DPDK mbuf pool]
   │ NIC receive
   ▼
(S1) ext-mbuf enters sockbuf  ── owner: kernel sockbuf; refcnt=1 (EXT_FLAG_EMBREF, kern_mbuf.c:1604)
   │ ff_zc_recv → soreceive mp!=NULL
   ▼
(S2) sbfree + *mp=m handout    ── owner: APP; sockbuf has done sbfree(uipc_socket.c:~3060) and sb_mb advanced, kernel no longer references it
   │ APP holds/traverses (ff_zc_mbuf_segment read-only, does not change refcnt)
   ▼
(S3) APP processing           ── owner: APP; refcnt still=1; DPDK seg not reclaimed (no m_free)
   │ ff_zc_recv_free → m_freem
   ▼
(S4) segment-by-segment refcnt→0 ── mb_free_ext(kern_mbuf.c:1217) → ff_mbuf_ext_free(ff_veth.c:300)
   │
   ▼
(S5) rte_pktmbuf_free_seg      ── DPDK seg returned to pool (ff_dpdk_if.c:2533)
```

## 2. Key Invariants
| Invariant | Guarantee Mechanism | Anchor |
|---|---|---|
| INV1: after S2 the kernel no longer references this mbuf | soreceive does sbfree + sb_mb=m->m_next within the lock | uipc_socket.c:~3060-3065 |
| INV2: during APP holding, the DPDK seg is not reclaimed | refcnt>0 (not m_free'd), return is driven only by m_freem | 03 §2 |
| INV3: no double free | the mp!=NULL branch does not go through m_free (only mp==NULL goes to L3068) | uipc_socket.c |
| INV4: complete release | m_freem releases the whole chain along m_next, each segment its own ext_arg1→its own DPDK seg | 03 §1 multi-segment |

## 3. Sequence Diagram (success)
```
APP            ff_zc_recv     kern_zc_recvit   soreceive       sockbuf      DPDK
 │  recv(n)  ───►│             │               │              │            │
 │              │ kern_zc_recvit(&mp) ─►│       │              │            │
 │              │             │ soreceive(&mp) ─►│              │            │
 │              │             │               │ sbfree(m) ────►│(account-)  │
 │              │             │               │ *mp=m         │            │
 │              │             │◄── mp=chain head ─│              │            │
 │◄── zm.bsd_mbuf=chain head, n ─│             │               │              │
 │ segment()*(read-only mtod) │             │               │              │
 │ free() ──► m_freem ─────────────────────────────────────────────────►│ refcnt→0
 │              │             │               │              │ ff_mbuf_ext_free→rte_pktmbuf_free_seg
```

## 4. Exceptions and Protection
| Exception | Consequence | Protection |
|---|---|---|
| APP does not call free | DPDK mempool leak | strong API doc constraint + debug-time mbuf inuse count warning (rte_mempool_in_use_count) |
| APP segment after free | use-after-free | after free zero out zm->bsd_mbuf, segment sees NULL and returns -1 |
| split segment (m_copym) | that segment is non-ext / new ext | m_freem still releases correctly (ordinary mbuf goes m_free, ext goes ext_free) |
| peer reset during receive | soreceive returns error | ff_zc_recv returns -1, zm contains no chain, no need to free |

## 5. Relationship with page-array (item verified at implementation time)
Under FF_USE_PAGE_ARRAY (ff_memory.c), the impact of the DPDK mbuf→BSD page mapping on the validity of data pointers during S3 must be specifically verified at M5 (this spec annotates "verified at implementation time", no speculation).
