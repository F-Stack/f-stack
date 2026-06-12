# 03 · RX ext-mbuf 生命周期与所有权

> 探针：probe-extmbuf（只读实测）。每条结论给出 file:line:symbol；未经代码验证的推断显式标注「需设计验证」。

## 1. RX 路径：DPDK rte_mbuf → external BSD mbuf（零拷贝）
- 收包主循环对每个 rtem 调 `ff_veth_input`（ff_dpdk_if.c:1788/1795/1803/1806/1810）。
- `ff_veth_input`（ff_dpdk_if.c:1494）：
  - `data = rte_pktmbuf_mtod(pkt, void*)`（L1504）取 DPDK 数据指针（**不复制**）；
  - `len = rte_pktmbuf_data_len(pkt)`（L1505）；
  - `hdr = ff_mbuf_gethdr(pkt, pkt->pkt_len, data, len, rx_csum)`（L1507）。
- `ff_mbuf_gethdr`（ff_veth.c:366）：
  - `m = m_gethdr(M_NOWAIT, MT_DATA)`（L369）仅分配 mbuf 头壳；
  - **`m_extadd(m, data, len, ff_mbuf_ext_free, pkt, NULL, 0, EXT_DISPOSABLE)`（L374）**。

`m_extadd` 实参（关键证据）：
| 形参 | 实参 | 含义 |
|---|---|---|
| buf | `data` | **直接指向 DPDK mbuf 数据区（零拷贝核心）** |
| freef | `ff_mbuf_ext_free` | 释放回调 |
| arg1 | `pkt` | **被引用的原始 `struct rte_mbuf*`（回收时用）** |
| type | `EXT_DISPOSABLE` | external 存储类型 |

`m_extadd` 内部（kern_mbuf.c:1586-1607）：`ext_buf=buf; m_data=ext_buf`（L1594-1595）；`ext_arg1=arg1`（L1598）；因 type≠EXT_EXTREF → `ext_count=1`、`ext_flags=EXT_FLAG_EMBREF`（嵌入式引用计数，初值 1）（L1602-1604）。

**多段链**：`pkt->next!=NULL` 时逐段 `ff_mbuf_get(prev, pn, data, len)`（ff_dpdk_if.c:1524-1538），内部 `m_extadd(mb,data,len,ff_mbuf_ext_free, pn, ...)`（ff_veth.c:399）—— **每个 BSD 段的 ext_arg1 指向各自的 DPDK seg**。最终 `ff_veth_process_packet(ctx->ifp, hdr)`（L1540）→ `if_input`（ff_veth.c:420）入栈。

## 2. ff_mbuf_ext_free：签名 / 触发 / 回收
- 签名（ff_veth.c:300-304）：`ff_mbuf_ext_free(struct mbuf *m){ ff_dpdk_pktmbuf_free(ff_rte_frm_extcl(m)); }`
- `ff_rte_frm_extcl`（ff_veth.c:1106-1116）：校验 `M_EXT && ext_type==EXT_DISPOSABLE && ext_free==ff_mbuf_ext_free`，命中返回 `m_ext.ext_arg1`（即 §1 的 pkt/pn），否则 NULL。
- `ff_dpdk_pktmbuf_free`（ff_dpdk_if.c:2533-2536）：`rte_pktmbuf_free_seg`（**仅释放单 seg**，与"每段各记一个 DPDK seg"一致）。
- 触发时机：FreeBSD `mb_free_ext`（kern_mbuf.c）在 external 引用计数归零时调用：`if(*refcnt==1 || atomic_fetchadd_int(refcnt,-1)==1)`（L1217）→ `case EXT_DISPOSABLE`（L1245-1250）→ `ext_free(mref)`（L1248，即 ff_mbuf_ext_free）→ `m_free_raw(mref)`（L1249）。入口 `m_free`：`M_EXT → mb_free_ext`（mbuf.h:1527-1528）。

**归还链**：`m_free/m_freem(BSD mbuf)` →（refcnt 归零）`mb_free_ext` → `ff_mbuf_ext_free` → `ff_rte_frm_extcl(取 ext_arg1)` → `ff_dpdk_pktmbuf_free` → `rte_pktmbuf_free_seg(DPDK seg)`。
**即：DPDK mbuf 的归还由 BSD mbuf 的释放驱动，二者经 EXT_DISPOSABLE + 嵌入式 refcnt 绑定。**

## 3. m_ext 引用计数语义
- EXT_FLAG_EMBREF（L1604）：引用计数嵌入首个 mbuf，初值 1。
- m_copym 等克隆共享 external 存储时计数 +1；每次 m_free 对持有 external 的 mbuf 计数 -1；归零才真正回调 ext_free。
- EXT_DISPOSABLE：external buffer 随最后引用释放而由 ext_free 处置。

## 4. ZC-READ 所有权难题（核心，部分为设计级分析）
- **利好（已验证）**：现机制下，只要 BSD mbuf 未被 free，其引用的 DPDK mbuf 就不会被回收（refcnt>0）。因此**把 ext-mbuf 链交给 APP 持有，DPDK mbuf 自动延寿，天然支持所有权移交** —— 这是 ZC-read 可行性的关键支撑。
- **难题/约束（需设计验证）**：
  1. 常规 recv 路径中，soreceive 取走 mbuf 后由内核 `m_free`（mp==NULL 分支 uipc_socket.c:3068）触发归还。ZC-read 走 mp!=NULL 分支（L3063 `*mp=m`，**不 m_free**）→ mbuf 交到上层，**归还责任转移给 APP**。
  2. 需新增 release 契约：APP 读完必须调用对称的 `m_freem`（或封装的 ff_zc_recv_free），否则 DPDK mbuf 泄漏（mempool 耗尽）。
  3. 跨多 mbuf/多 DPDK seg 时，release 须整链 m_freem（每段各自回调 ff_mbuf_ext_free 释放对应 seg）。
  4. split（部分 mbuf）走 m_copym（02 §3）→ 该拷贝出的 mbuf 不再是 ext（或新 ext 引用），release 语义需区分。

## 5. 与 FF_USE_PAGE_ARRAY 的关系
- ff_memory.c / ff_memory.h 的 `#ifdef FF_USE_PAGE_ARRAY` 块（lib/ff_memory.c / ff_memory.h:101）建立 DPDK mbuf 内存到 BSD page 模型的映射。
- 「需设计验证」：ZC-read 把 ext-mbuf 交 APP 时，page-array 映射是否影响 mbuf 数据指针有效性 / refcnt，需在实现期专项验证（本期未深入到 page 级时序）。

## 6. 潜在风险清单
| 风险 | 依据 | 状态 |
|---|---|---|
| use-after-free：APP 持有 mbuf 但 DPDK mbuf 被提前回收 | 取决于 release 契约正确性 | 待设计验证（refcnt 机制本身已具备防护）|
| mempool 泄漏：APP 不归还 mbuf | mp!=NULL 分支不 m_free（L3063） | 需强制 release API |
| 双重 free：sockbuf 与 APP 同时 free | sbfree 已在锁内前移 sb_mb（L3060/3065）| 已验证内核侧不再持有 |
| split 拷贝语义混淆 | m_copym（L3081/3098）| 需 API 区分 ZC 段与拷贝段 |
| page-array 时序 | ff_memory.c FF_USE_PAGE_ARRAY | 待实现期验证 |
