# 15 · 边界与回退规格

> 锚点见 02 §3/§6（实测）。原则：不可零拷贝场景一律回退到现有拷贝路径，保证语义与现状一致。

## 1. 边界矩阵
| 场景 | 是否 ZC | 处理 | 锚点 | 备注 |
|---|---|---|---|---|
| 整 mbuf（len==m_len-moff）| ✅ ZC | sbfree+*mp=m 直交 | uipc_socket.c:~3061-3066 | 主路径 |
| 部分 mbuf（split，len<m_len）| ❌ 回退 | m_copym（M_WAITOK/M_NOWAIT）| uipc_socket.c:~3081/3098 | 拷贝出新 mbuf，APP 仍可 m_freem |
| MSG_PEEK | ❌ 回退 | 不摘链；走拷贝 | uipc_socket.c:~3055/3076 | ZC 与 PEEK 互斥，ff_zc_recv 不传 PEEK |
| MSG_WAITALL | ⚠ 多轮 ZC | 逐段零拷贝累积到满 | uipc_socket.c:~3129-3165 | 可行但多次交付 |
| 非阻塞 MSG_DONTWAIT/SS_NBIO | ⚠ 部分 ZC | 无数据返回 EAGAIN；部分 mbuf m_copym(M_NOWAIT) | uipc_socket.c:~3081 + 04§1 BUGS | 官方手册警示 ZC+DONTWAIT 限制 |
| MSG_OOB | ❌ 回退 | 独立 soreceive_rcvoob→uiomove | uipc_socket.c:2682 | OOB 不经 mp0 |
| 控制消息（SCM）| ✅ 独立通道 | controlp 已 mbuf 直交 | uipc_socket.c:~2888-2955 | 与数据 mp0 正交 |
| KERN_TLS | ❌ 回退 | 强制 soreceive_generic | uipc_socket.c:~3456/3470 | TLS 解密需拷贝 |
| UDP（soreceive_dgram）| ❌ 回退 | mp0!=NULL 时回退 soreceive_generic | uipc_socket.c:~3508 | 天然兼容，本特性聚焦 TCP |
| SCTP | ❌ 未支持 | 走 sctp_soreceive | udp/sctp_usrreq.c | 本期不支持 |

## 2. 回退判定与 APP 可见性
- 内核 soreceive 在 mp!=NULL 时自动选择 ZC/拷贝（整段 vs split），对 ff_zc_recv 透明。
- APP 拿到的 zm->bsd_mbuf 链可能混合 ext-mbuf（ZC 段）与 m_copym 普通 mbuf（split 段）；**m_freem 对两者均正确**（14 §4）。
- ff_zc_recv **不应**传 MSG_OOB；若传 MSG_PEEK 则退化为拷贝（不报错，但无零拷贝收益）。

## 3. 协议适用性
- **TCP**：默认 soreceive_generic 支持 mp0；soreceive_stream（sysctl net.inet.tcp.soreceive_stream）亦支持 → ZC 主场景。
- **UDP/SCTP**：回退/不支持，ff_zc_recv 行为等价普通 recv（正确但无收益）。

## 4. 错误与半包
- 半包（数据未达 nbytes）：返回实际字节，APP 按 len 处理；后续再 ff_zc_recv。
- 连接关闭：返回 0，zm 无链。
- 错误：返回 -1 + errno，zm 无链，无需 free。
