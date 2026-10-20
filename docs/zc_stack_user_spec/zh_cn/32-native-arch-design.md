# 32. 对称架构设计 — `kern_zc_sendit` ↔ `kern_zc_recvit`

> 来源：probe-sosend-native + probe-zcrecv-symmetry + research-ext-zcsend
> 用途：33 内核 patch / 34 API / 35 lifecycle / 36 boundary 的总图

---

## §1 设计原则

| 原则 | 说明 |
|---|---|
| P1 对称 | ZC-send 与已落地的 ZC-recv 在内核入口、用户态入口、生命周期、错误路径、ABI 增量五个维度全镜像 |
| P2 原生 | 直接复用 FreeBSD 15.0 上游 `sosend(top)` 路径（uipc_socket.c:2599），不修改 `m_uiotombuf` / `mbuf.h` / `kern_writev` 任一行 |
| P3 最小 | 只新增 1 个内核函数（`kern_zc_sendit`）+ 1 个声明 + 改写 1 个用户态函数（`ff_zc_send`）+ 修复 2 个用户态函数（`ff_zc_mbuf_get/write`） |
| P4 ABI 稳 | 用户态函数签名零修改；example/main_zc.c 调用序列零修改；`FF_ZC_SEND` 宏名保留 |
| P5 门控 | 全部新增代码 `#ifdef FSTACK_ZC_SEND` 门控；与 `FSTACK_ZC_RECV` 互不依赖、可独立开关 |

---

## §2 高层架构图

### §2.1 旧方案（魔改）

```
┌────────────────────────────────────────────────────────────────────┐
│ APP                                                                 │
│   ff_zc_mbuf_get → ff_zc_mbuf_write → ff_zc_send(fd, mb, n)         │
│                                            │                        │
│                                            │ uio.iov_base=mb (char*) │
│                                            │ uio.uio_offset=MAGIC   │
└────────────────────────────────────────────┼────────────────────────┘
                                             ▼
┌────────────────────────────────────────────────────────────────────┐
│ KERNEL — 5 处魔改                                                  │
│   ff_zc_send → kern_writev → dofilewrite [#ifdef FSTACK_ZC_SEND]   │
│              → soo_write → sousrsend → sosend → sosend_generic     │
│              → m_uiotombuf [#ifdef FSTACK_ZC_SEND magic 消费]      │
│  ↑ uio_offset 在 5 个文件中透传；ff_write/writev 须显式 opt-out     │
└────────────────────────────────────────────────────────────────────┘
```

### §2.2 新方案（原生）

```
┌────────────────────────────────────────────────────────────────────┐
│ APP                                                                 │
│   ff_zc_mbuf_get(M_PKTHDR) → ff_zc_mbuf_write(maintain pkthdr.len)  │
│   → ff_zc_send(fd, mb, n)                                           │
│                │                                                    │
│                │ top = (struct mbuf *)mb                            │
│                │ flags = 0                                          │
└────────────────┼────────────────────────────────────────────────────┘
                 ▼
┌────────────────────────────────────────────────────────────────────┐
│ KERNEL — 仅新增 kern_zc_sendit                                      │
│   ff_zc_send → kern_zc_sendit(td, s, top, flags)                   │
│              → sosend(so, NULL, NULL, top, NULL, flags, td)        │
│              → pr_sosend → sosend_generic / sosend_dgram           │
│                ↑ 走 if (uio == NULL) 原生分支                       │
│                  resid = top->m_pkthdr.len                          │
│                  完全跳过 m_uiotombuf                               │
│  没有 magic、没有 uio_offset 透传、ff_write/writev 不需 opt-out     │
└────────────────────────────────────────────────────────────────────┘
```

---

## §3 对称表（与 ZC-recv 五维镜像）

| 维度 | ZC-recv（已落地，commit b87f5f0d2）| ZC-send（本 spec 规定）|
|---|---|---|
| **内核入口函数** | `kern_zc_recvit(td, s, uio, mp0)`（uipc_syscalls.c:1065）| `kern_zc_sendit(td, s, top, flags)` 新增 |
| **声明位置** | `freebsd/sys/syscallsubr.h:304-310` `#ifdef FSTACK_ZC_RECV` | `freebsd/sys/syscallsubr.h` 类似位置 `#ifdef FSTACK_ZC_SEND` |
| **核心 BSD 调用** | `soreceive(so, NULL, uio, &chain, NULL, &flags)` | `sosend(so, NULL, NULL, top, NULL, flags, td)` |
| **零拷贝原生分支** | soreceive 的 `mp0!=NULL` 分支（uipc_socket.c:~3055-3070）| sosend_generic_locked 的 `uio==NULL` 分支（uipc_socket.c:2456-2500）|
| **resid 来源** | `uio->uio_resid`（输入预算）| `top->m_pkthdr.len`（uipc_socket.c:2340-2341）|
| **绕过点** | `uiomove(mtod, ..., uio)`（@~3022-3031）| `m_uiotombuf(uio, ..., flags)`（@2490）|
| **MAC 检查** | `mac_socket_check_receive`（uipc_syscalls.c:1083）| `mac_socket_check_send`（实施时引入）|
| **fd 解析** | `getsock(td, s, &cap_recv_rights, &fp)` | `getsock(td, s, &cap_send_rights, &fp)` |
| **错误路径** | 错误且 chain 已有 → `m_freem(chain)`（uipc_syscalls.c:1107-1108）| 错误 → `m_freem(top)`（实施时见 33 §3）|
| **成功语义** | `*mp0 = chain; td->td_retval[0] = len - resid` | `td->td_retval[0] = len - uio_resid_simulated`（无 uio，从 sosend 返回值推算）|
| **用户态入口函数** | `ssize_t ff_zc_recv(int fd, struct ff_zc_mbuf *zm, size_t nbytes)` | `ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes)`（签名保留）|
| **lib 实现位置** | `ff_syscall_wrapper.c` ZC-recv 块（commit b87f5f0d2）| `ff_syscall_wrapper.c:1186-1226` 重写 |
| **mbuf 操作 API** | `ff_zc_mbuf_read` / `ff_zc_mbuf_segment` / `ff_zc_recv_free` | `ff_zc_mbuf_get` / `ff_zc_mbuf_write`（保留+修复 M_PKTHDR）|
| **ABI 增量** | +3 符号（recv/segment/free）| 0 符号（仅改 ff_zc_send 实现）|
| **ff_api.symlist 增量** | 3 行 | 0 行 |
| **Makefile 开关** | `FF_ZC_RECV → -DFSTACK_ZC_RECV` | `FF_ZC_SEND → -DFSTACK_ZC_SEND`（保留，含义切换）|

---

## §4 关键内核路径锚点（实测）

### §4.1 sosend dispatch — 接受非 NULL top（kernel-thread 入口）

`uipc_socket.c:2598-2609`：

```c
int
sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
    struct mbuf *top, struct mbuf *control, int flags, struct thread *td)
{
    int error;
    CURVNET_SET(so->so_vnet);
    error = so->so_proto->pr_sosend(so, addr, uio, top, control, flags, td);
    CURVNET_RESTORE();
    return (error);
}
```

注释（uipc_socket.c:2590-2597）原文："Send to a socket from a kernel thread. … in almost all cases uio is NULL and the mbuf is supplied."—— 即 `sosend()` 是内核线程入口，**接受非 NULL `top`**。

### §4.2 sousrsend 强制 top=NULL — 不可复用

`uipc_socket.c:2624-2626`：

```c
CURVNET_SET(so->so_vnet);
error = so->so_proto->pr_sosend(so, addr, uio, NULL, control, flags, td);
                                                ^^^^ 写死
CURVNET_RESTORE();
```

→ 系统调用层（kern_sendit / soo_write / aio）走 sousrsend 都是 `top=NULL`；**新方案绕开 sousrsend，直调 sosend**。

### §4.3 sosend_generic_locked top!=NULL 路径

#### resid 推导 — uipc_socket.c:2338-2343

```c
if (uio != NULL)
    resid = uio->uio_resid;
else if ((top->m_flags & M_PKTHDR) != 0)
    resid = top->m_pkthdr.len;     ← 关键：必须有 M_PKTHDR
else
    resid = m_length(top, NULL);   ← O(链长) fallback
```

#### 内层循环跳过 m_uiotombuf — uipc_socket.c:2456-2500

```c
do {
    if (uio == NULL) {
        resid = 0;                 ← 一次性投递（atomic）
        if (flags & MSG_EOR)
            top->m_flags |= M_EOR;
#ifdef KERN_TLS
        if (tls != NULL) {
            ktls_frame(top, tls, &tls_enq_cnt, tls_rtype);
            tls_rtype = TLS_RLTYPE_APP;
        }
#endif
    } else {
        ...
        top = m_uiotombuf(uio, M_WAITOK, space, ...);   ← 拷贝路径
        ...
    }
```

→ `top!=NULL && uio==NULL` 时**完全不调 m_uiotombuf**；仅设 `resid=0` + 按需 EOR/KTLS。

#### atomic 由 top 决定 — uipc_socket.c:2325

```c
int atomic = sosendallatonce(so) || top;
```

→ `top!=NULL` 自动 atomic（即一次性投递、不分片）。这与 `PR_ATOMIC` 协议一致；TCP（非 PR_ATOMIC）在 atomic=1 下需考虑 sb_max 限制（详见 36）。

### §4.4 sosend_dgram top 路径

`uipc_socket.c:2160-2270` 同构（DGRAM，UDP/UNIX-DGRAM）：
- `if (uio == NULL)` 取 `top->m_pkthdr.len` 作 resid（L2170 等）
- 错误路径 `m_freem(top)` 兜底（DGRAM 内部对失败 mbuf 自释放）

→ 新方案下 UDP/UNIX-DGRAM 自动支持，无需特殊处理。详见 36 边界矩阵。

---

## §5 数据结构对照

### §5.1 struct ff_zc_mbuf（lib/ff_api.h:347，无变化）

```c
struct ff_zc_mbuf {
    void *bsd_mbuf;       /* 指向 BSD mbuf 链头 */
    void *bsd_mbuf_off;   /* SEND: 当前写入节点 / RECV: 当前读取节点 */
    int   off;            /* 链内偏移 */
    int   len;            /* SEND: 申请总长 / RECV: 实际接收长 */
};
```

新方案下字段语义与旧方案完全一致；唯一变化是**链头节点必须带 `M_PKTHDR`**，且 `pkthdr.len` 等于已写入字节累计（详见 34）。

### §5.2 mbuf 链结构（链头 vs 链尾）

```
zc_buf.bsd_mbuf (链头)
  ├─ M_PKTHDR ✓     (旧方案：✗ 无 — 这是缺口)
  ├─ pkthdr.len = N  (旧方案：始终 0 — 这是 sosend 失败根因)
  ├─ m_data, m_len
  └─ m_next ─→ mb1 (链中)
                ├─ m_data, m_len
                └─ m_next ─→ mb2 (链尾)
                              ├─ m_data, m_len
                              └─ m_next = NULL
```

`zc_buf.bsd_mbuf_off`（SEND）：在 `ff_zc_mbuf_write` 多次调用之间记录当前写入位置，跨调用 resume；与 ZC-recv 的"当前读取节点"语义对称。

---

## §6 新增/改写组件清单

| # | 组件 | 类型 | 文件:大致行 | 详规 |
|---|---|---|---|---|
| K1 | `kern_zc_sendit` 实现 | NEW | freebsd/kern/uipc_syscalls.c（kern_sendit 旁）| 33 §2 |
| K2 | `kern_zc_sendit` 声明 | NEW | freebsd/sys/syscallsubr.h（kern_sendit 旁，#ifdef 门控）| 33 §1 |
| U1 | `ff_zc_send` 重写 | REWRITE | lib/ff_syscall_wrapper.c:1186-1226 | 34 §3 |
| U2 | `ff_zc_mbuf_get` 加 M_PKTHDR | MODIFY | lib/ff_veth.c:306-323 | 34 §4.1 |
| U3 | `ff_zc_mbuf_write` 维护 pkthdr.len | MODIFY | lib/ff_veth.c:325-356 | 34 §4.2 |
| D1 | mbuf.h FSTACK_ZC_MAGIC 宏 | DELETE | freebsd/sys/mbuf.h:1856-1869 | 31 §3.1 |
| D2 | uipc_mbuf.c m_uiotombuf 整段 | DELETE/RESTORE-VANILLA | freebsd/kern/uipc_mbuf.c:1955-2077 | 33 §3 |
| D3 | sys_generic.c uio_offset 守护 | DELETE | freebsd/kern/sys_generic.c:560-573 | 31 §3.3 |
| D4 | ff_syscall_wrapper.c ff_write opt-out | DELETE | lib/ff_syscall_wrapper.c:1146-1151 | 31 §3.4 |
| D5 | ff_syscall_wrapper.c ff_writev opt-out | DELETE | lib/ff_syscall_wrapper.c:1175 | 31 §3.5 |

合计：2 NEW + 3 MODIFY + 5 DELETE = 10 处改动。

对比 ZC-recv 落地（commit b87f5f0d2，2 NEW + 1 MODIFY + 1 SYMBOL = 4 处）—— 本期略多但**全部为可逆操作**（DELETE 是回退到 vanilla，没有新增侵入点）。

---

## §7 sequence diagram — 用户态成功路径

```
APP                ff_zc_send       kern_zc_sendit       sosend           pr_sosend
  │                     │                  │                 │                 │
  │ ff_zc_mbuf_get      │                  │                 │                 │
  │  (M_PKTHDR)         │                  │                 │                 │
  ├────────────────────▶│                  │                 │                 │
  │ ff_zc_mbuf_write    │                  │                 │                 │
  │  (pkthdr.len += n)  │                  │                 │                 │
  ├────────────────────▶│                  │                 │                 │
  │ ff_zc_send(fd,top,n)│                  │                 │                 │
  ├────────────────────▶│                  │                 │                 │
  │                     │ kern_zc_sendit   │                 │                 │
  │                     │  (td, s, top, 0) │                 │                 │
  │                     ├─────────────────▶│                 │                 │
  │                     │                  │ getsock + MAC   │                 │
  │                     │                  │ sosend(uio=NULL)│                 │
  │                     │                  ├────────────────▶│                 │
  │                     │                  │                 │ pr_sosend(top)  │
  │                     │                  │                 ├────────────────▶│
  │                     │                  │                 │  uio==NULL 分支 │
  │                     │                  │                 │  resid=pkthdr.len
  │                     │                  │                 │  入队 sb_mb     │
  │                     │                  │                 │◀────────────────│
  │                     │                  │  td_retval[0]=n │                 │
  │                     │                  │◀────────────────│                 │
  │                     │  rc = n          │                 │                 │
  │                     │◀─────────────────│                 │                 │
  │  rc = n             │                  │                 │                 │
  │◀────────────────────│                  │                 │                 │
```

错误路径（kern_zc_sendit 内 sosend 返错误且未接管 top）：详见 35 lifecycle。

---

## §8 与 ZC-recv 共栈关系

`FF_ZC_SEND` 与 `FF_ZC_RECV` 完全独立：
- 可单独启用任一（lib/Makefile 各自 `ifdef`）；
- 可同时启用（M2 阶段已验证，commit 8a06862cd / de58b11e9）；
- 共享同一 `struct ff_zc_mbuf` 数据结构（不同字段语义复用，已见 §5.1）；
- 共享同一注释体系与 spec 编号（30+ ZC-send / 11-19 ZC-recv）。

→ 本 spec 实施后，`zc_stack_user` 形成**真正的对称用户态零拷贝栈**：
```
APP ↔ ff_zc_recv / ff_zc_mbuf_segment / ff_zc_recv_free      (RECV, mp0)
APP ↔ ff_zc_send / ff_zc_mbuf_get / ff_zc_mbuf_write         (SEND, top)
```

---

下一篇：**33-kernel-patch-spec.md**（内核 patch 详规，含 c-precision-surgery 锚点）。
