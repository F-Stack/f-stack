# 03 · RX ext-mbuf Lifecycle and Ownership

> Probe: probe-extmbuf (read-only measurement). Every conclusion gives file:line:symbol; inferences not verified by code are explicitly annotated "design verification needed".

## 1. RX Path: DPDK rte_mbuf → external BSD mbuf (zero-copy)
- The packet-receiving main loop calls `ff_veth_input` for each rtem (ff_dpdk_if.c:1788/1795/1803/1806/1810).
- `ff_veth_input` (ff_dpdk_if.c:1494):
  - `data = rte_pktmbuf_mtod(pkt, void*)` (L1504) gets the DPDK data pointer (**no copy**);
  - `len = rte_pktmbuf_data_len(pkt)` (L1505);
  - `hdr = ff_mbuf_gethdr(pkt, pkt->pkt_len, data, len, rx_csum)` (L1507).
- `ff_mbuf_gethdr` (ff_veth.c:366):
  - `m = m_gethdr(M_NOWAIT, MT_DATA)` (L369) allocates only the mbuf header shell;
  - **`m_extadd(m, data, len, ff_mbuf_ext_free, pkt, NULL, 0, EXT_DISPOSABLE)` (L374)**.

`m_extadd` actual arguments (key evidence):
| Formal | Actual | Meaning |
|---|---|---|
| buf | `data` | **directly points to the DPDK mbuf data area (zero-copy core)** |
| freef | `ff_mbuf_ext_free` | release callback |
| arg1 | `pkt` | **the referenced original `struct rte_mbuf*` (used at reclaim)** |
| type | `EXT_DISPOSABLE` | external storage type |

`m_extadd` internals (kern_mbuf.c:1586-1607): `ext_buf=buf; m_data=ext_buf` (L1594-1595); `ext_arg1=arg1` (L1598); because type≠EXT_EXTREF → `ext_count=1`, `ext_flags=EXT_FLAG_EMBREF` (embedded reference count, initial value 1) (L1602-1604).

**Multi-segment chain**: when `pkt->next!=NULL`, each segment goes `ff_mbuf_get(prev, pn, data, len)` (ff_dpdk_if.c:1524-1538), internally `m_extadd(mb,data,len,ff_mbuf_ext_free, pn, ...)` (ff_veth.c:399) —— **each BSD segment's ext_arg1 points to its own DPDK seg**. Finally `ff_veth_process_packet(ctx->ifp, hdr)` (L1540) → `if_input` (ff_veth.c:420) enters the stack.

## 2. ff_mbuf_ext_free: Signature / Trigger / Reclaim
- Signature (ff_veth.c:300-304): `ff_mbuf_ext_free(struct mbuf *m){ ff_dpdk_pktmbuf_free(ff_rte_frm_extcl(m)); }`
- `ff_rte_frm_extcl` (ff_veth.c:1106-1116): checks `M_EXT && ext_type==EXT_DISPOSABLE && ext_free==ff_mbuf_ext_free`; on hit returns `m_ext.ext_arg1` (i.e. §1's pkt/pn), otherwise NULL.
- `ff_dpdk_pktmbuf_free` (ff_dpdk_if.c:2533-2536): `rte_pktmbuf_free_seg` (**frees only a single seg**, consistent with "each segment records one DPDK seg").
- Trigger timing: FreeBSD `mb_free_ext` (kern_mbuf.c) is called when the external reference count drops to zero: `if(*refcnt==1 || atomic_fetchadd_int(refcnt,-1)==1)` (L1217) → `case EXT_DISPOSABLE` (L1245-1250) → `ext_free(mref)` (L1248, i.e. ff_mbuf_ext_free) → `m_free_raw(mref)` (L1249). Entry `m_free`: `M_EXT → mb_free_ext` (mbuf.h:1527-1528).

**Return chain**: `m_free/m_freem(BSD mbuf)` → (refcnt drops to zero) `mb_free_ext` → `ff_mbuf_ext_free` → `ff_rte_frm_extcl(takes ext_arg1)` → `ff_dpdk_pktmbuf_free` → `rte_pktmbuf_free_seg(DPDK seg)`.
**That is: the return of the DPDK mbuf is driven by the release of the BSD mbuf; the two are bound via EXT_DISPOSABLE + embedded refcnt.**

## 3. m_ext Reference-Count Semantics
- EXT_FLAG_EMBREF (L1604): the reference count is embedded in the first mbuf, initial value 1.
- m_copym and similar clones sharing the external storage increment the count +1; each m_free on an mbuf holding the external decrements the count -1; only at zero is ext_free truly called back.
- EXT_DISPOSABLE: the external buffer is disposed by ext_free along with the last reference being released.

## 4. ZC-READ Ownership Challenge (core, partly design-level analysis)
- **Favorable (verified)**: under the current mechanism, as long as the BSD mbuf is not freed, the DPDK mbuf it references will not be reclaimed (refcnt>0). Therefore **handing the ext-mbuf chain to the APP to hold automatically extends the DPDK mbuf's lifetime, naturally supporting ownership transfer** —— this is the key support for ZC-read feasibility.
- **Challenges/constraints (design verification needed)**:
  1. In the conventional recv path, after soreceive takes the mbuf, the kernel's `m_free` (mp==NULL branch uipc_socket.c:3068) triggers the return. ZC-read goes the mp!=NULL branch (L3063 `*mp=m`, **no m_free**) → the mbuf is handed to the upper layer, **the return responsibility transfers to the APP**.
  2. A release contract must be added: after reading, the APP must call the symmetric `m_freem` (or the wrapped ff_zc_recv_free), otherwise the DPDK mbuf leaks (mempool exhaustion).
  3. When spanning multiple mbufs/multiple DPDK segs, release must m_freem the whole chain (each segment calls back ff_mbuf_ext_free to free its corresponding seg).
  4. split (partial mbuf) goes m_copym (02 §3) → the copied-out mbuf is no longer an ext (or a new ext reference), so release semantics need to distinguish.

## 5. Relationship with FF_USE_PAGE_ARRAY
- The `#ifdef FF_USE_PAGE_ARRAY` blocks of ff_memory.c / ff_memory.h (lib/ff_memory.c / ff_memory.h:101) establish a mapping from DPDK mbuf memory to the BSD page model.
- "design verification needed": when ZC-read hands the ext-mbuf to the APP, whether the page-array mapping affects the validity of the mbuf data pointer / refcnt needs dedicated verification during implementation (this round did not go deep to page-level timing).

## 6. Potential Risk List
| Risk | Rationale | Status |
|---|---|---|
| use-after-free: APP holds the mbuf but the DPDK mbuf is reclaimed prematurely | depends on correctness of the release contract | pending design verification (the refcnt mechanism itself already provides protection) |
| mempool leak: APP does not return the mbuf | the mp!=NULL branch does not m_free (L3063) | requires a mandatory release API |
| double free: sockbuf and APP free simultaneously | sbfree already advances sb_mb within the lock (L3060/3065) | verified the kernel side no longer holds it |
| split copy semantics confusion | m_copym (L3081/3098) | the API needs to distinguish ZC segments from copied segments |
| page-array timing | ff_memory.c FF_USE_PAGE_ARRAY | pending implementation-phase verification |
