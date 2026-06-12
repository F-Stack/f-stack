# 14 · mbuf 生命周期与所有权状态机

> 闭环论证：无 use-after-free / 无泄漏 / 无双重 free。锚点见 03（实测）。

## 1. 所有权状态机
```
[DPDK mbuf 池]
   │ NIC 收包
   ▼
(S1) ext-mbuf 入 sockbuf      ── 所有者：内核 sockbuf；refcnt=1（EXT_FLAG_EMBREF, kern_mbuf.c:1604）
   │ ff_zc_recv → soreceive mp!=NULL
   ▼
(S2) sbfree + *mp=m 交出       ── 所有者：APP；sockbuf 已 sbfree(uipc_socket.c:~3060) 且 sb_mb 前移，内核不再引用
   │ APP 持有/遍历（ff_zc_mbuf_segment 只读，不改 refcnt）
   ▼
(S3) APP 处理中                ── 所有者：APP；refcnt 仍=1；DPDK seg 不回收（无 m_free）
   │ ff_zc_recv_free → m_freem
   ▼
(S4) 逐段 refcnt→0             ── mb_free_ext(kern_mbuf.c:1217) → ff_mbuf_ext_free(ff_veth.c:300)
   │
   ▼
(S5) rte_pktmbuf_free_seg      ── DPDK seg 归还池（ff_dpdk_if.c:2533）
```

## 2. 关键不变量（invariants）
| 不变量 | 保障机制 | 锚点 |
|---|---|---|
| INV1：S2 后内核不再引用该 mbuf | soreceive 在锁内 sbfree + sb_mb=m->m_next | uipc_socket.c:~3060-3065 |
| INV2：APP 持有期 DPDK seg 不回收 | refcnt>0（未 m_free），归还仅由 m_freem 驱动 | 03 §2 |
| INV3：无双重 free | mp!=NULL 分支不走 m_free（仅 mp==NULL 走 L3068）| uipc_socket.c |
| INV4：释放完整 | m_freem 沿 m_next 整链释放，每段各自 ext_arg1→各自 DPDK seg | 03 §1 多段 |

## 3. 时序图（成功）
```
APP            ff_zc_recv     kern_zc_recvit   soreceive       sockbuf      DPDK
 │  recv(n)  ───►│             │               │              │            │
 │              │ kern_zc_recvit(&mp) ─►│       │              │            │
 │              │             │ soreceive(&mp) ─►│              │            │
 │              │             │               │ sbfree(m) ────►│(记账-)     │
 │              │             │               │ *mp=m         │            │
 │              │             │◄── mp=链首 ────│              │            │
 │◄── zm.bsd_mbuf=链首, n ────│             │               │              │
 │ segment()*（只读 mtod）    │             │               │              │
 │ free() ──► m_freem ─────────────────────────────────────────────────►│ refcnt→0
 │              │             │               │              │ ff_mbuf_ext_free→rte_pktmbuf_free_seg
```

## 4. 异常与防护
| 异常 | 后果 | 防护 |
|---|---|---|
| APP 不调 free | DPDK mempool 泄漏 | API 文档强约束 + 调试期 mbuf inuse 计数告警（rte_mempool_in_use_count）|
| APP free 后再 segment | use-after-free | free 后清零 zm->bsd_mbuf，segment 见 NULL 返回 -1 |
| split 段（m_copym）| 该段非 ext / 新 ext | m_freem 仍正确释放（普通 mbuf 走 m_free，ext 走 ext_free）|
| 收取中对端 reset | soreceive 返回错误 | ff_zc_recv 返回 -1，zm 不含链，无需 free |

## 5. 与 page-array 关系（实现期验证项）
FF_USE_PAGE_ARRAY（ff_memory.c）下 DPDK mbuf→BSD page 映射对 S3 期间数据指针有效性的影响，须在 M5 专项验证（本规格标注"实现期验证"，不臆测）。
