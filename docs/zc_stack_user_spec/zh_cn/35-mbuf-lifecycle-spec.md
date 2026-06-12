# 35. mbuf 链所有权状态机与不变量

> 来源：probe-sosend-native（sosend 错误路径 m_freem 站点）+ probe-zcrecv-symmetry（ZC-recv 错误处理模式）+ FreeBSD sosend(9) 上游手册
> 目标：精确定义 ff_zc_mbuf 链在用户态/内核态的所有权契约，避免 use-after-free / double-free / 泄漏

---

## §1 状态机

```
                            ┌───────────────────────────────────────────────────┐
                            │                                                   │
                            ▼                                                   │
   ┌───────────┐  get   ┌──────────┐  write   ┌──────────┐  send err ┌──────────┴──┐
─▶│  S0 NONE   │──────▶│  S1 EMPTY │────────▶│  S2 FILL  │─────────▶│  S4 ERROR    │
   └───────────┘        │  M_PKTHDR │          │ pkthdr.len│           │ kern frees  │
                        │ pkthdr.len│          │  > 0      │           │ via m_freem │
                        │  = 0      │          └─────┬────┘           └─────────────┘
                        └──────────┘                 │ send ok
                                                     ▼
                                              ┌──────────────┐
                                              │  S3 ADOPTED  │
                                              │ kernel owns  │
                                              │ (via sosend) │
                                              └──────────────┘
```

### §1.1 状态定义

| 状态 | 标识 | 说明 |
|---|---|---|
| S0 NONE | `zc_buf.bsd_mbuf == NULL` | 尚未调用 ff_zc_mbuf_get |
| S1 EMPTY | M_PKTHDR + pkthdr.len=0 | get 后；尚未写入数据 |
| S2 FILL | M_PKTHDR + pkthdr.len>0 | write 后；可继续 write 或 send |
| S3 ADOPTED | 内核已接管，用户态不得访问 | ff_zc_send 成功后 |
| S4 ERROR | 内核已 m_freem 释放（KERN_OWNED）| ff_zc_send 失败后 |

### §1.2 状态迁移规则

| from | event | to | 备注 |
|---|---|---|---|
| S0 | ff_zc_mbuf_get(len) | S1 | 内核 m_getm2(M_PKTHDR) 分配 |
| S1 | ff_zc_mbuf_write(d, n) | S2 | progress=n; pkthdr.len 累加 |
| S2 | ff_zc_mbuf_write(d, n) | S2 | 多次写入累加；progress<=zc_buf.len |
| S2 | ff_zc_send(...) 成功 | S3 | 内核 sosend 接管，用户态指针**作废** |
| S2 | ff_zc_send(...) 失败 | S4 | kern_zc_sendit 已 m_freem(top)，用户态指针**作废** |
| S3 / S4 | 任何用户态访问 | **UAF 错误** | 触发 use-after-free |
| S3 / S4 | ff_zc_mbuf_get(zc_buf, len) | S1 | 重用 zc_buf 结构体；重新 get 链 |

---

## §2 不变量（INV）

### INV-1：M_PKTHDR + pkthdr.len 一致性

> 在状态 S1 / S2 下，`zc_buf.bsd_mbuf` 指向的链头**必须**满足 `(m->m_flags & M_PKTHDR) != 0`，且 `m->m_pkthdr.len == sum(mb->m_len for mb in chain)`（但允许 < zc_buf.len，即 trailing space 未写满）。

**违反后果**：sosend 在 `uio==NULL` 分支取 resid 错误（uipc_socket.c:2340-2341）：
- 缺 M_PKTHDR → 走 `m_length()` O(N) 扫描 fallback；不算崩溃，但慢；
- pkthdr.len=0 → resid=0 → 立即返回 0 字节发送，用户感知 "send 不工作"（M2 阶段曾命中）。

**保证机制**：ff_zc_mbuf_get 强制 `M_PKTHDR` flag；ff_zc_mbuf_write 在链头累加 `pkthdr.len += progress`（详见 34 §4.2）。

### INV-2：所有权单点（no double ownership）

> 任意时刻，链头 `top` 的所有权属于**且仅属于**用户态或内核态之一。
> - 用户态调用 ff_zc_send **之前**：用户态独占。
> - ff_zc_send 返回后（无论成功/失败）：内核独占（成功则被 sosend/sb_mb 接管；失败则已被 kern_zc_sendit/m_freem 释放）。

**违反后果**：
- 双 m_freem → kernel panic / 内存损坏；
- 用户态在 send 后再访问 → UAF。

**保证机制**：
- 用户态：ff_zc_send 返回后**禁止**再用 `zc_buf.bsd_mbuf` 进行 read/write（spec 要求；但代码无法强制，靠规范）；
- 内核态：kern_zc_sendit 错误路径**统一 m_freem**，sosend 错误路径若 protosw 内部已 free 则 kern_zc_sendit **不再 m_freem**（依赖 sosend 接口契约，详见 §3）。

### INV-3：错误路径无泄漏（no leak on error）

> 任何失败的 ff_zc_send 调用都**不**留下泄漏的 mbuf 链 — 要么由 kern_zc_sendit 立即 m_freem，要么由 sosend 内部 m_freem。

**保证机制**：
- 入参校验失败（top NULL / 无 M_PKTHDR / pkthdr.len < 0）：kern_zc_sendit 立即 `m_freem(top)`（33 §2.2 第 16-19, 22-25 行）；
- getsock / MAC 失败：kern_zc_sendit 立即 `m_freem(top)`（33 §2.2 第 32-35, 41-43 行）；
- sosend 失败：依据 sosend 内部规范处理，详见 §3。

---

## §3 sosend 错误路径所有权矩阵（实测，probe-sosend-native）

> sosend 错误时 top 的处置因 protosw 实现而异。以下矩阵基于 probe-sosend-native 实测的 sosend_generic_locked（uipc_socket.c:2390-2580）+ sosend_dgram（uipc_socket.c:2160-2270）的 m_freem(top) 站点：

| sosend 内部站点 | 行号区域 | top 处置 | 后续 kern_zc_sendit 动作 |
|---|---|---|---|
| sosend_dgram 入参检查失败 | 2200 区 | sosend_dgram 内 m_freem(top) | **不**再 m_freem（INV-2 守护）|
| sosend_dgram pr_send 返错 | 2260 区 | top 已交 pr_send 由协议层 m_freem | **不**再 m_freem |
| sosend_generic atomic 投递失败（sb_max 不够） | 2400 区 | m_freem(top) 由 sosend 自身 | **不**再 m_freem |
| sosend_generic SOCK_STREAM + MSG_EOR (EINVAL @ 2354) | 2354-2360 | top 由 sosend goto out 上面分支处置；通常 free | **不**再 m_freem |
| sosend_generic pr_send 返 EWOULDBLOCK（atomic 一次性，不分片）| 2540 区 | top 由 pr_send 处置；sosend 不再持有 | **不**再 m_freem |

**结论（INV-3 实施细则）**：
1. **kern_zc_sendit 在调用 sosend 后，无论成功/失败，都不再 m_freem(top)**；
2. 这依赖 FreeBSD sosend 的"调用者放手"契约（sosend(9) 手册暗含；实测证据：sosend 内部多个 m_freem(top) 站点）；
3. 例外：kern_zc_sendit 自身入参校验 / getsock / MAC 失败时（在调 sosend 之前），由 kern_zc_sendit 显式 m_freem。

> **风险标注**：若 sosend 某个 protosw 实现违反此契约（错误返回但未 free top），会泄漏。本期 spec 默认 vanilla FreeBSD 15.0 的 inet/unix/raw 等 protosw 均合规；若实施期 valgrind 测试发现泄漏，需打回 33 §2.3 调整 kern_zc_sendit 错误兜底。

---

## §4 与 ZC-recv 的对称（实测对照）

### §4.1 ZC-recv 错误路径（已落地）

`uipc_syscalls.c:1100-1108`（kern_zc_recvit）：

```c
if (error == 0) {
    td->td_retval[0] = len - uio->uio_resid;
    *mp0 = zc_chain;
} else if (zc_chain != NULL) {
    /* error after some mbufs were detached: free them */
    m_freem(zc_chain);
}
```

### §4.2 ZC-send 错误路径（本 spec 规定）

`kern_zc_sendit`（33 §2.2）：

```c
if (top == NULL || (top->m_flags & M_PKTHDR) == 0) {
    if (top != NULL) m_freem(top);
    return (EINVAL);
}
... // getsock/MAC 失败也 m_freem(top)

error = sosend(so, NULL, NULL, top, NULL, flags, td);
/* 不再 m_freem(top): sosend 自管 */
```

### §4.3 对称差异说明

| 维度 | ZC-recv | ZC-send |
|---|---|---|
| 链所有权方向 | 内核 → 用户态 | 用户态 → 内核 |
| 错误时由谁 free | kern_zc_recvit（chain != NULL 时）| 入参校验阶段 kern_zc_sendit；sosend 阶段由 sosend 内部 |
| 用户态释放 API | `ff_zc_recv_free` 显式调用 m_freem | **无** — 用户态 send 后不持有，无需 free |

---

## §5 sequence diagram — 错误路径

### §5.1 入参校验失败（top 缺 M_PKTHDR）

```
APP                ff_zc_send       kern_zc_sendit
  │                     │                  │
  │ ff_zc_send(fd,top,n)│                  │
  ├────────────────────▶│                  │
  │                     │ kern_zc_sendit   │
  │                     ├─────────────────▶│
  │                     │                  │ if (!(top->m_flags & M_PKTHDR))
  │                     │                  │     m_freem(top);   ← 立即释放
  │                     │                  │     return EINVAL;
  │                     │  rc=-1, EINVAL   │
  │                     │◀─────────────────│
  │  rc=-1, errno=EINVAL│                  │
  │◀────────────────────│                  │
```

### §5.2 sosend 失败（EPIPE）

```
APP                ff_zc_send       kern_zc_sendit       sosend           pr_sosend
  │ ...                │                  │                 │                 │
  │                     │ kern_zc_sendit   │                 │                 │
  │                     ├─────────────────▶│                 │                 │
  │                     │                  │ getsock OK      │                 │
  │                     │                  │ MAC OK          │                 │
  │                     │                  │ sosend(NULL,top)│                 │
  │                     │                  ├────────────────▶│                 │
  │                     │                  │                 │ pr_sosend       │
  │                     │                  │                 ├────────────────▶│
  │                     │                  │                 │     EPIPE       │
  │                     │                  │                 │ m_freem(top)    │
  │                     │                  │                 │◀────────────────│
  │                     │                  │  EPIPE          │                 │
  │                     │                  │◀────────────────│                 │
  │                     │                  │ tdsignal(SIGPIPE) (除非 SO_NOSIGPIPE/MSG_NOSIGNAL)
  │                     │                  │ fdrop, return EPIPE
  │                     │  rc=-1, EPIPE    │                 │
  │                     │◀─────────────────│                 │
  │  rc=-1, errno=EPIPE │                  │                 │
  │  + SIGPIPE          │                  │                 │
  │◀────────────────────│                  │                 │
```

注意：用户态在 §5.2 收到 -1 后，`zc_buf.bsd_mbuf` 已是悬空指针（KERN_OWNED 状态由 sosend 内部 m_freem 转为 KERN_FREED）；ff_zc_send 不再返回链给用户态访问。

---

## §6 多次 ff_zc_mbuf_write（部分写）状态

```
ff_zc_mbuf_get(zc, 4096)        // S1 EMPTY: pkthdr.len=0, off=0, len=4096
ff_zc_mbuf_write(zc, "ab", 2)   // S2 FILL: pkthdr.len=2, off=2
ff_zc_mbuf_write(zc, "cd", 2)   // S2 FILL: pkthdr.len=4, off=4
... 用户决定不再写 ...
ff_zc_send(fd, zc.bsd_mbuf, 4096)
                                // ⚠ 警告：pkthdr.len=4 但 nbytes=4096
                                // sosend 取 resid=top->m_pkthdr.len=4
                                // → 实际只发送 4 字节，返回 4
```

→ ff_zc_send 的 `nbytes` 参数在新方案下**仅做边界检查**（防止溢出 INT_MAX），**不**作 resid（resid 由 sosend 从 top->m_pkthdr.len 推导）。这与旧方案语义不同（旧方案 nbytes 决定 uio_resid），但**对调用方影响为零**：用户期望"已 write 多少就 send 多少"，新方案恰好满足。

> **隐含 spec 条款**：调用方应保证 `nbytes >= sum(write 调用的 len)`（防止 INT_MAX 溢出检查通过但 pkthdr.len 误判）；详见 36 §UDP / §sb_max。

---

## §7 内存安全测试矩阵（37 详化）

| 测试点 | INV | 测试方法 | 触发 |
|---|---|---|---|
| L1 | INV-1 | unit：构造无 M_PKTHDR 链 → ff_zc_send 应返回 EINVAL | mock kern_zc_sendit |
| L2 | INV-1 | unit：pkthdr.len < 0 → EINVAL | 直接构造 |
| L3 | INV-2 | integration：成功 send 后再访问 zc_buf.bsd_mbuf → valgrind 报 invalid read | example 改造 |
| L4 | INV-3 | integration：valgrind --track-fds 跑 ff_zc_send EPIPE 100 次 → 0 leak | 关闭对端触发 EPIPE |
| L5 | INV-3 | integration：DPDK rte_mempool 计数检查（前后差 0）| ff_dpdk_pktmbuf_pool 计数 API |
| L6 | INV-1 | integration：实跑 wrk 后 dump struct mbuf → pkthdr.len == 已写入字节 | gdb attach |

详见 37-test-spec.md。

---

## §8 可门禁验证条款（gatekeeper）

| 条款 | 验证方式 | 通过判据 |
|---|---|---|
| L-G1 | 检查 spec 状态机覆盖 S0-S4 | 5 个状态全描述 |
| L-G2 | 检查 INV-1 / INV-2 / INV-3 三个不变量 | 全部带"违反后果"+"保证机制" |
| L-G3 | 检查 sosend 错误站点矩阵 | ≥3 个 protosw 路径 |
| L-G4 | 检查与 ZC-recv 对称对照 | 引用 uipc_syscalls.c:1100-1108 实代码 |

---

下一篇：**36-boundary-and-fallback-spec.md**（边界矩阵）。
