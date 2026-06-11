# 11 · 架构设计

> 实现级架构。所有内核/代码锚点经实测（见 10 §6）。

## 1. 分层总览
```
┌─────────────────────────────────────────────────────────────┐
│ APP（用户业务）                                               │
│   ff_zc_recv(fd, &zm, n) → 遍历 ff_zc_mbuf_read/segment → ff_zc_recv_free │
├─────────────────────────────────────────────────────────────┤
│ 用户态 API 层（lib/ff_api.h, lib/ff_veth.c, lib/ff_syscall_wrapper.c）│
│   - ff_zc_recv：构造 msghdr/uio，经新内核入口透传 mbuf 出参 mp     │
│   - ff_zc_mbuf_read（重写）：从 zm->bsd_mbuf 链顺序读出/遍历      │
│   - ff_zc_recv_free：m_freem(zm->bsd_mbuf) 归还整链              │
├─────────────────────────────────────────────────────────────┤
│ 内核桥接层（freebsd/kern/uipc_syscalls.c / sys_socket.c）         │
│   - kern_zc_recvit 变体 / soo_read 透传：把 soreceive mp0 由 NULL 改为 &mp │
├─────────────────────────────────────────────────────────────┤
│ soreceive mp0 引擎（freebsd/kern/uipc_socket.c，FreeBSD 原生）      │
│   - mp!=NULL：sbfree + *mp=m 直交（零拷贝）                       │
│   - split：m_copym 回退                                          │
├─────────────────────────────────────────────────────────────┤
│ ext-mbuf（ff_veth.c m_extadd EXT_DISPOSABLE）→ DPDK rte_mbuf      │
│   - 数据零拷贝指向 DPDK mbuf；m_ext refcnt 驱动 rte_pktmbuf_free_seg │
└─────────────────────────────────────────────────────────────┘
```

## 2. 数据流（ZC-RECV 成功路径）
1. NIC→DPDK mbuf→`ff_veth_input`→`ff_mbuf_gethdr`（m_extadd EXT_DISPOSABLE）→ ext-mbuf 入 sockbuf（已零拷贝，现状）。
2. APP `ff_zc_recv`：构造 uio（uio_resid=n）+ 传 mbuf 出参 mp。
3. 内核桥接：`soreceive(so, psa, uio, &mp, ...)`（mp 非 NULL）。
4. `soreceive` mp!=NULL 分支：`sbfree`（记账）+ `*mp=m` + `sb_mb` 前移 → **不 uiomove**，整段 mbuf 交出。
5. 返回：`td_retval[0]=len-uio_resid`；zm->bsd_mbuf = 交出的链首。
6. APP 遍历读数据（直接访问 mbuf 数据，零拷贝），用完 `ff_zc_recv_free`→`m_freem`→逐段 ff_mbuf_ext_free→rte_pktmbuf_free_seg 归还 DPDK seg。

## 3. 与 ZC-SEND 的架构差异（关键）
| 维度 | SEND | RECV |
|---|---|---|
| 方向 | 用户构造 mbuf→内核接管 | 内核交出 mbuf→用户消费 |
| 触发 | uio_offset=FSTACK_ZC_MAGIC（m_uiotombuf）| mp0 出参（soreceive 原生）|
| 释放 | 内核接管后自行管理 | **APP 负责 release（新增契约）** |
| 改动 | m_uiotombuf 加 magic 分支 | kern_recvit/soo_read 透传 mp0（不改 soreceive 核心）|

## 4. 设计原则
- **不改 soreceive 核心逻辑**：仅打通 mp0 通道（风险最小，升级友好）。
- **不破坏现有 recv/read**：新增独立入口（kern_zc_recvit），现有 kern_recvit 保持 mp0=NULL 不变。
- **回退优先正确性**：不可零拷贝场景（split/PEEK/OOB/TLS/UDP）回退拷贝路径，语义与现状一致。
