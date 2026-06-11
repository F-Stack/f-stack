# 02 · READ 路径分析（soreceive / mp0 / sockbuf 记账）

> 探针：probe-recvpath（只读实测，f-stack 自带魔改源码）。所有论断带 file:line:symbol。代码优先于注释/文档。

## 0. 结论速览（TL;DR）
- 内核 `soreceive_generic_locked` **天生支持 mp（soreceive 的 mp0 出参）零拷贝交出 mbuf** 的分支：`uipc_socket.c:3022 if(mp==NULL)`（拷贝）vs `uipc_socket.c:3061 *mp=m`（零拷贝直交）。`mp!=NULL` 时**不调 uiomove**，仅指针移交 + `uio_resid-=len`（L3050）。
- **但该通路当前对 f-stack 用户态完全不可达**：5 个 read/recv 入口经 `kern_readv`/`kern_recvit`，二者**把 soreceive 第 4 形参 mp0 写死为 NULL**（`uipc_syscalls.c:948`；read 经 `sys_generic.c`→`soo_read`→`soreceive(...,NULL,...)`）。
- f-stack 对接收路径**未做 ZC 相关改动**；魔改集中在发送侧（FSTACK_ZC_SEND）。
- 实现 ZC-read 内核侧**最小改动**：新增让 `kern_recvit`/`dofileread` 把 mbuf 出参 mp 暴露给上层的通道（§7）。

## 1. 用户态入口（ff_syscall_wrapper.c）
| 入口 | 行 | 进内核调用 | mp 传递 |
|---|---|---|---|
| ff_read | 1077 | kern_readv（1094），uio_segflg=UIO_SYSSPACE | 否（readv 无 mp 形参）|
| ff_readv | 1105 | kern_readv（1118）| 否 |
| ff_recv | 1313 | 转 ff_recvfrom（1315）| 否 |
| ff_recvfrom | 1319 | kern_recvit（1339），msg_control=0 | controlp 传 NULL |
| ff_recvmsg | 1359 | kern_recvit（1371）| NULL |
- 全部用 UIO_SYSSPACE（同地址空间，uiomove 退化为 memcpy，**仍是一次完整拷贝**）。
- 用户 API 层无"数据 mbuf 出参"概念；kern_recvit 末参是 controlp（控制消息），非数据 mp0。

## 2. soreceive 调用链与拷贝点
分发：`soreceive`（uipc_socket.c:3661）→ `pr_soreceive`。取值实测：
- 默认 `DEFAULT(pr_soreceive, soreceive_generic)`（uipc_domain.c:196）；
- **TCP**：tcp_protosw 未显式设（tcp_usrreq.c:1403）→ 默认 = soreceive_generic；仅 sysctl `net.inet.tcp.soreceive_stream` 开启时改为 soreceive_stream（tcp_subr.c:1492）；
- **UDP**：soreceive_dgram（udp_usrreq.c:1794）；**SCTP**：sctp_soreceive。

| 拷贝点 | 文件:行 | 条件 |
|---|---|---|
| OOB | uipc_socket.c:2682 | MSG_OOB |
| **generic 主拷贝** | uipc_socket.c:3031 uiomove | mp==NULL 且非 M_EXTPG |
| EXTPG | uipc_socket.c:3028 m_unmapped_uiomove | mp==NULL 且 M_EXTPG |
| stream 主拷贝 | uipc_socket.c:3382 m_mbuftouio | stream 且 mp0==NULL |
| dgram 主拷贝 | uipc_socket.c:3640 uiomove | soreceive_dgram |

## 3. mp0 出参机制（核心）
`soreceive_generic_locked`（uipc_socket.c:3015-3105），注释明示 "If mp is set, just pass back the mbufs"：
- **mp==NULL**：`uiomove(mtod(m,char*)+moff,len,uio)`（L3031）← 真正拷贝；
- **mp!=NULL 且整 mbuf（len==m_len-moff）**：`sbfree(&so->so_rcv,m)`（L3060）→ `*mp=m`（L3063）→ `mp=&m->m_next`（L3064）→ `sb_mb=m->m_next`（L3065）→ **零拷贝直交**；mp==NULL 时才 `m_free`（L3068）；
- **mp!=NULL 且部分 mbuf（split）**：仍 `m_copym`（L3081/L3098）一次拷贝 —— **无法零拷贝的边界**。
- soreceive_stream_locked 的 mp0!=NULL 路径同理（L3337-3359 m_cat 整段移交；尾部余量 m_copym L3365）。

**f-stack 是否改动该路径？** 实测：soreceive 系列逻辑与上游 FreeBSD 一致，**无 FSTACK_* 宏、无 ZC 定制**。

## 4. sockbuf 记账与锁（uipc_sockbuf.c）
- `sballoc`(254)：入队 sb_ccc/sb_acc/sb_mbcnt += ；`sbfree`(282)：出队 -=；`sbavail()`(sockbuf.h:267)=sb_acc。
- 零拷贝整交：`sbfree`(uipc_socket.c:3060)+`*mp=m` 在**同一把 SOCKBUF 锁内**完成；**不释放锁**（不 uiomove），临界区更短。
- 拷贝路径取整 mbuf：`sbfree`+`m_free`(L3068)；部分：`sbcut_locked`(L3103)。
- 锁：顶层 `sblock`/`SOCK_IO_RECV_LOCK`(L3239) 防多读者；`SOCKBUF_LOCK`(L2767) 保护指针/记账，uiomove 前释放(L3026)后重取(L3033)（uiomove 可能睡眠）。

## 5. kern_recvit / kern_readv 是否暴露 mp？——均未，写死拷贝
- `kern_recvit`（uipc_syscalls.c:895）：`soreceive(so,&fromsa,&auio, NULL, (控制消息?&control:NULL), &msg_flags)`（L948）→ 第 4 形参 mp0 **硬编码 NULL**；control 仅承载 MT_CONTROL。
- `kern_readv`（sys_generic.c:283）→ `dofileread`(345)→ `fo_read`→ `soo_read`→ `soreceive(...,mp0=NULL,...)`。
**故从用户态到内核无任何现成通路把 mp0!=NULL 传进 soreceive；零拷贝分支虽存在但当前不可达。**

## 6. 边界路径定位
| 边界 | 位置 | 对 ZC-read 影响 |
|---|---|---|
| MSG_PEEK | uipc_socket.c:2872/3055/3076 | 不摘链，整交不适用，只能 m_copym |
| MSG_WAITALL | uipc_socket.c:3129-3165 | 需循环等满，可逐段零拷贝多轮 |
| 非阻塞 DONTWAIT/SS_NBIO | uipc_socket.c:2828/3081 | 部分 mbuf 走 m_copym(M_NOWAIT) |
| controlp | uipc_socket.c:2888-2955 / 入口 949 | 控制消息独立通道，已 mbuf 直交 |
| MSG_OOB | uipc_socket.c:2668-2690 | 独立 uiomove(2682)，不经 mp0，无法零拷贝 |
| KERN_TLS | uipc_socket.c:3456/3470 | 强制回退 soreceive_generic |

## 7. 内核侧最小改动点（实测结论）
内核零拷贝引擎**已现成**（mp0 分支 L3061-3066 / stream L3337-3359），缺的是把 mp0 从用户态贯通到 soreceive。按改动量：
1. **新增接收侧 ZC 入口（推荐，改动最小）**：仿 ff_zc_send 隔离做法新增 `ff_zc_recv`；在 kern_recvit 旁新增变体，把 soreceive 第 4 形参由写死 NULL（L948）改为接收 `struct mbuf **mp` 透传。约束：用户拿到 mbuf 链后负责 `m_freem` 归还。
2. **TCP 无需改协议层**：默认 soreceive_generic 已支持 mp0；soreceive_stream 同样支持。
3. **不可零拷贝边界回退拷贝**（复用现有）：split→m_copym；PEEK/OOB/TLS→现状；UDP soreceive_dgram 在 mp0!=NULL 时回退 generic（L3508）天然可用。
4. **记账与锁无需改**：零拷贝分支已在锁内 sbfree 记账，sb_mb 已前移，语义自洽。

> 一句话：**ZC-read 内核引擎已就绪（mp0 分支），唯一工程量是在 kern_recvit/dofileread 与 f-stack 用户态 API 间新增 mbuf 出参贯通通道 + 设计 mbuf 归还接口。**
