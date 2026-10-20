# 22 · FreeBSD 15.0 原生发送端零拷贝接口调研（对标 kern_zc_recvit）

> 调研问题：FreeBSD 15.0 是否原生支持「与接收端 mp0（kern_zc_recvit 所复用）对称」的**发送端零拷贝接口**，从而可替代 f-stack 当前自实现的 `FSTACK_ZC_MAGIC` + `m_uiotombuf` 魔改方案？
> 方法：实测 f-stack 自带 freebsd/ 源码（已 re-apply 到 15.0），代码为准。

## 0. 结论（先说）
**是。FreeBSD 15.0 原生支持发送端零拷贝**——通过 `sosend` 的 `top`（预构造 mbuf 链）参数：当 `uio == NULL && top != NULL` 时，`sosend` **直接发送该 mbuf 链、跳过 `m_uiotombuf` 拷贝**。这正是发送侧对应 `soreceive` 的 `mp0` 的原生机制。

⇒ f-stack 当前的 ZC-send（`ff_zc_send` 用 `uio_offset=FSTACK_ZC_MAGIC` + 改 `m_uiotombuf` 把 `iov_base` 当 mbuf）**属自实现魔改，并非必要**；可改用原生 `sosend(top)` 路径（新增 `kern_zc_sendit`，与 `kern_zc_recvit` 完全对称），**消除对 `m_uiotombuf` 的内核 patch**。

## 1. 原生接口证据（实测）
### 1.1 sosend 原型带 top（mbuf 链）参数
`freebsd/kern/uipc_socket.c:2599 sosend(struct socket *so, struct sockaddr *addr, struct uio *uio, struct mbuf *top, struct mbuf *control, int flags, struct thread *td)`
- 经 `pr_sosend` 分派到 `sosend_generic`(2577) / `sosend_dgram`(2156)。
- 对称性：`soreceive(..., struct mbuf **mp0, ...)` 收侧出参 vs `sosend(..., struct mbuf *top, ...)` 发侧入参。

### 1.2 uio==NULL 时以 top 为数据、跳过拷贝
`sosend_generic_locked`：
- `uipc_socket.c:2338-2341`：`if (uio != NULL) resid = uio->uio_resid; else resid = top->m_pkthdr.len;` —— uio==NULL 时数据长度取自 **top 的 pkthdr.len**。
- `uipc_socket.c:2457 if (uio == NULL) { ... }`：**直接使用已构造的 top，跳过拷贝**；其 `else` 分支（2479/2490 `top = m_uiotombuf(uio, ...)`）才是常规 uio→mbuf 拷贝。
- `sosend_dgram` 同构：2167/2170 取 resid、2238 `if (uio == NULL)` 跳过 2248 的 `m_uiotombuf`。

### 1.3 sosend 区为原生、无 f-stack 魔改
- `awk '2320..2560' | grep FSTACK` → **空**：sosend 全段无任何 `FSTACK_*` 宏。
- git blame：该文件最近改动为 `2a9114132 ... Phase 5b: re-apply 10 kern/ F-Stack deltas on FreeBSD 15.0`（fengbojiang），但 sosend 的 top/uio 逻辑是上游原生（f-stack 的 delta 不在此处）。
- ⇒ **top 零拷贝发送是 FreeBSD 15.0 原生能力，未经魔改即可用。**

## 2. 当前 f-stack ZC-send（自实现魔改）回顾
- `ff_zc_send`(ff_syscall_wrapper.c:1199)：`iov_base = mbuf链`、`uio_offset = FSTACK_ZC_MAGIC`(0xF8AC2C00F8AC2C00, mbuf.h:1868) → `kern_writev` → sosend（**uio 非空、top=NULL**）。
- 改 `m_uiotombuf`(uipc_mbuf.c:2028 `#ifdef FSTACK_ZC_SEND`)：检测 magic → 把 `iov_base` 当 mbuf 链挂载、跳过常规拷贝。
- **本质**：因为走的是 uio 路径（top=NULL），不得不在 `m_uiotombuf` 里"劫持"uio 来塞 mbuf —— 这是**绕过 sosend 原生 top 入口**的 workaround，代价是一处内核 patch + 易误触（普通 ff_write 需显式 `uio_offset=0` opt-out）。

## 3. 原生路径为何当前不可达
- 用户态 send 入口最终都经 `sousrsend`(uipc_socket.c:2615) → `pr_sosend(so, addr, uio, NULL /*top*/, control, flags, td)`：**top 被写死 NULL**（kern_sendit uipc_syscalls.c:797 / soo_write sys_socket.c:`sousrsend(so,NULL,uio,NULL,0,NULL)` 均如此）。
- 即：与收侧 `mp0` 被 kern_recvit 写死 NULL **完全同构** —— 原生能力在内核就绪，缺的只是"把 top 从用户态贯通进 sosend"的入口。

## 4. 建议方案：kern_zc_sendit（与 kern_zc_recvit 对称）
新增（`#ifdef FSTACK_ZC_RECV` 同款门控，或新 `FSTACK_ZC_SEND_NATIVE`）：
```c
/* 伪代码：发送侧原生零拷贝，对称于 kern_zc_recvit */
int
kern_zc_sendit(struct thread *td, int s, struct mbuf *top, int flags)
{
    /* getsock ... so */
    /* uio = NULL，top = APP 经 ff_zc_mbuf_get/write 构造的链 */
    error = sosend(so, /*addr*/NULL, /*uio*/NULL, top, /*control*/NULL, flags, td);
    /* sosend 在 uio==NULL 分支直发 top，跳过 m_uiotombuf 拷贝；
       td_retval[0] = 已发送字节（resid 差）；失败时按 sosend 语义处理 top 归属 */
}
```
用户态 `ff_zc_send` 改为调用 `kern_zc_sendit`（传 top），不再设 `FSTACK_ZC_MAGIC`。

### 4.1 收益（对比现魔改）
| 维度 | 现 FSTACK_ZC_MAGIC 魔改 | 原生 sosend(top) 方案 |
|---|---|---|
| 内核 patch | 需改 m_uiotombuf（uipc_mbuf.c）| **无需改 m_uiotombuf**（仅新增 kern_zc_sendit 入口，类比 recvit）|
| 误触风险 | 普通 ff_write 须显式 uio_offset=0 opt-out（曾致 GPF，见 ff_syscall_wrapper.c:1146 RCA）| 无（top 路径与 uio 路径天然分流）|
| 与上游一致性 | 低（自造 magic）| **高**（用原生 sosend top 语义）|
| 对称性 | 与收侧不对称 | **与 kern_zc_recvit 完全对称** |
| 升级维护 | 每次 merge FreeBSD 需重对齐 m_uiotombuf hack | 仅维护一个独立入口 |

### 4.2 注意事项（实现期验证）
- **top 必须带正确 pkthdr.len**：sosend uio==NULL 分支用 `top->m_pkthdr.len` 作 resid。现 `ff_zc_mbuf_get`(ff_veth.c:306) 用 `m_getm2(..., flags=0)` **不带 M_PKTHDR**、且 `ff_zc_mbuf_write` 未更新 pkthdr.len（01 §1.3 实测）。改原生方案须让 top 链首带 M_PKTHDR 且 pkthdr.len = 总写入字节（否则 resid 错）。
- **mbuf 归属**：sosend 成功后接管/释放 top（与现魔改一致）；失败路径的 top 释放语义需按 sosend 约定核对（避免泄漏/双重 free）。
- **PRUS_MORETOCOME / 分段**：sosend 内部按 sbspace 分多次 pr_send，top 跨多 mbuf 时由 sosend 处理，无需 APP 关心。
- **协议**：TCP（sosend_generic）/ UDP（sosend_dgram）均支持 top（uio==NULL）分支。

## 5. 总结
- FreeBSD 15.0 **原生**提供发送端零拷贝（`sosend` 的 `top` mbuf 入口，uio==NULL 跳过拷贝），与接收端 `mp0` **完全对称**，且 sosend 全段无魔改。
- f-stack 现 ZC-send 是**绕开该原生入口**的 `FSTACK_ZC_MAGIC`+`m_uiotombuf` workaround。
- **建议**：后续可新增对称的 `kern_zc_sendit`（sosend top 路径）替换魔改，**消除 m_uiotombuf 内核 patch、降低误触与升级维护成本**；需先解决 top 的 pkthdr.len 构造（改 ff_zc_mbuf_get/write 带 M_PKTHDR）。本调研仅评估，不在本期 ZC-recv 范围内实施。
