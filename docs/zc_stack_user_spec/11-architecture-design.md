# 11 · Architecture Design

> Implementation-level architecture. All kernel/code anchors are measured (see 10 §6).

## 1. Layered Overview
```
┌─────────────────────────────────────────────────────────────┐
│ APP (user business)                                           │
│   ff_zc_recv(fd, &zm, n) → traverse ff_zc_mbuf_read/segment → ff_zc_recv_free │
├─────────────────────────────────────────────────────────────┤
│ Userspace API layer (lib/ff_api.h, lib/ff_veth.c, lib/ff_syscall_wrapper.c)│
│   - ff_zc_recv: build msghdr/uio, pass mbuf out-param mp via new kernel entry │
│   - ff_zc_mbuf_read (rewrite): sequentially read out/traverse zm->bsd_mbuf chain │
│   - ff_zc_recv_free: m_freem(zm->bsd_mbuf) returns the whole chain │
├─────────────────────────────────────────────────────────────┤
│ Kernel bridge layer (freebsd/kern/uipc_syscalls.c / sys_socket.c) │
│   - kern_zc_recvit variant / soo_read passthrough: change soreceive mp0 from NULL to &mp │
├─────────────────────────────────────────────────────────────┤
│ soreceive mp0 engine (freebsd/kern/uipc_socket.c, FreeBSD native) │
│   - mp!=NULL: sbfree + *mp=m direct handover (zero-copy)         │
│   - split: m_copym fallback                                     │
├─────────────────────────────────────────────────────────────┤
│ ext-mbuf (ff_veth.c m_extadd EXT_DISPOSABLE) → DPDK rte_mbuf     │
│   - data zero-copy points to DPDK mbuf; m_ext refcnt drives rte_pktmbuf_free_seg │
└─────────────────────────────────────────────────────────────┘
```

## 2. Data Flow (ZC-RECV success path)
1. NIC→DPDK mbuf→`ff_veth_input`→`ff_mbuf_gethdr` (m_extadd EXT_DISPOSABLE)→ ext-mbuf enters sockbuf (already zero-copy, current state).
2. APP `ff_zc_recv`: construct uio (uio_resid=n) + pass mbuf output parameter mp.
3. Kernel bridge: `soreceive(so, psa, uio, &mp, ...)` (mp non-NULL).
4. `soreceive` mp!=NULL branch: `sbfree` (accounting) + `*mp=m` + `sb_mb` advance → **no uiomove**, the whole mbuf segment is handed out.
5. Return: `td_retval[0]=len-uio_resid`; zm->bsd_mbuf = the head of the handed-out chain.
6. APP traverses and reads data (directly accessing mbuf data, zero-copy); when done `ff_zc_recv_free`→`m_freem`→segment-by-segment ff_mbuf_ext_free→rte_pktmbuf_free_seg returns the DPDK seg.

## 3. Architectural Differences from ZC-SEND (key)
| Dimension | SEND | RECV |
|---|---|---|
| Direction | user constructs mbuf→kernel takes over | kernel hands out mbuf→user consumes |
| Trigger | uio_offset=FSTACK_ZC_MAGIC (m_uiotombuf) | mp0 output parameter (soreceive native) |
| Release | kernel manages itself after takeover | **APP responsible for release (new contract)** |
| Change | m_uiotombuf adds magic branch | kern_recvit/soo_read passthrough mp0 (soreceive core unchanged) |

## 4. Design Principles
- **Do not change soreceive core logic**: only open the mp0 channel (minimal risk, upgrade-friendly).
- **Do not break existing recv/read**: add an independent entry (kern_zc_recvit); existing kern_recvit keeps mp0=NULL unchanged.
- **Fallback prioritizes correctness**: scenarios where zero-copy is not possible (split/PEEK/OOB/TLS/UDP) fall back to the copy path, semantics consistent with current state.
