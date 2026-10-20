# 36. 边界与回退矩阵

> 来源：probe-sosend-native（sosend_generic_locked / sosend_dgram 全分支）+ FreeBSD 协议族 protosw 定义
> 目标：穷尽 ff_zc_send 在各 socket 类型 / flag / 协议特性下的行为，规定回退或拒绝策略

---

## §1 socket 类型 × 协议矩阵

| socket type | 协议 | PR_ATOMIC | sosend 路径 | ZC 支持 | 回退策略 |
|---|---|---|---|---|---|
| SOCK_STREAM | TCP | NO | sosend_generic_locked | **支持** | — |
| SOCK_DGRAM | UDP | YES | sosend_dgram | **支持**（atomic 一次性投递，受 sb_max 约束）| EMSGSIZE |
| SOCK_DGRAM | UNIX-DGRAM | YES | sosend_dgram | **支持** | EMSGSIZE |
| SOCK_STREAM | UNIX-STREAM | NO | sosend_generic_locked | **支持** | — |
| SOCK_SEQPACKET | SCTP | YES | protosw 自定义 | **不支持**（本期）| 退化为 EOPNOTSUPP（实施期 spec 决定，本期不暴露 SCTP）|
| SOCK_RAW | IPv4/IPv6 raw | varies | sosend_generic | **支持但谨慎**（用户态需自构 IP 头）| — |

---

## §2 flag 矩阵（kern_zc_sendit 透传至 sosend）

| flag | 说明 | 在 ZC 路径下行为 | 备注 |
|---|---|---|---|
| `MSG_DONTWAIT` | 非阻塞 | sosend 不会阻塞，sb 满返回 EWOULDBLOCK | sosend(9) 手册警告："MSG_DONTWAIT flag is not implemented for sosend()" — 实测在 atomic 路径下走 SS_NBIO 检查（uipc_socket.c sosend_generic_locked），可工作但注意 BUG 节 |
| `MSG_EOR` | end-of-record | top->m_flags \|= M_EOR（uipc_socket.c:2459-2460）| **TCP 下立即 EINVAL**（uipc_socket.c:2354）|
| `MSG_NOSIGNAL` | 抑制 SIGPIPE | kern_zc_sendit 检查（33 §2.2 SIGPIPE 块）| 推荐总是设置 |
| `MSG_OOB` | out-of-band | sosend 接受 | TCP only；少用；本期允许透传 |
| `MSG_EOF` | shutdown after send | 协议特定 | 透传；不在本期重点测试 |
| 0（默认）| — | — | 推荐 |

新方案下 `ff_zc_send` 当前固定传 `flags=0`；后续可暴露 `ff_zc_sendmsg(fd, mb, flags)` 或扩展 `ff_zc_send` 第 4 参（API 增量，非本期 spec 范围）。

---

## §3 socket 选项矩阵

| 选项 | 影响 | 行为 |
|---|---|---|
| `SO_NOSIGPIPE` | 抑制 SIGPIPE | kern_zc_sendit 检查（33 §2.2）|
| `SS_NBIO`（即 `O_NONBLOCK`）| 非阻塞 | atomic + 缓冲不足 → EWOULDBLOCK 立即返回；caller 可重试或减小 mb |
| `SO_LINGER` | 关闭时残留数据处理 | 与 ZC 无直接关系；sosend 正常返回后由 close() 处理 |
| `SO_SNDBUF` | sb_max 上限 | atomic 投递时 `top->m_pkthdr.len > sb_max` → ENOBUFS |
| `SO_SNDTIMEO` | 阻塞超时 | atomic 阻塞下生效 |

---

## §4 atomic 投递与 sb_max 约束

实测 `uipc_socket.c:2325`：

```c
int atomic = sosendallatonce(so) || top;
```

→ `top != NULL` 强制 atomic = 1。其后果：
1. **必须一次性投递**：sb 空间不足 → 阻塞（默认）/ EWOULDBLOCK（非阻塞）/ ENOBUFS（缓冲耗尽）；
2. `top->m_pkthdr.len > sb_max` → ENOBUFS / EMSGSIZE（DGRAM 路径）；
3. 不会发生"部分发送"——成功则全部入队，失败则 0 字节。

调用方推论：
- TCP 大数据（> SO_SNDBUF）应**自分片**：每次 ff_zc_mbuf_get(MIN(SNDBUF, total))，多次发送；
- UDP 必须 ≤ MTU - IP header（典型 1472 字节）；超过 → EMSGSIZE；
- 不要预期"send 8MB → 内核帮你分 N 次写入"（这是普通 ff_writev 的语义，ZC 不适用）。

→ **此即 F-Stack issue #712 的根因**（原方案大数据 crash/hang）：原方案在 m_uiotombuf 魔改路径下未尊重 atomic 语义，超大 mbuf 会导致 sosend 路径异常。新方案明确遵循 atomic 契约，调用方需负责分片，不再 crash 而是返回明确错误码（ENOBUFS / EMSGSIZE）。

---

## §5 与 LD_PRELOAD ring 模式 / FF_USE_PAGE_ARRAY 兼容性

| 特性 | 与 ZC-send 关系 | 备注 |
|---|---|---|
| LD_PRELOAD ring | 不影响（ZC-send 是 lib-internal 路径，与 ld_preload ring 用 ipc 投递无冲突）| 详见 docs/ld_preload_ring_spec |
| FF_USE_PAGE_ARRAY | 正交关系（FF_USE_PAGE_ARRAY 管"协议栈→DPDK"零拷贝；ZC-send 管"应用→协议栈"零拷贝；可同时启用）| 实测 commit ca83653c1+M2 阶段两者共存通过 |
| ZC-recv | 完全独立（共享 struct ff_zc_mbuf 但开关独立）| 32 §8 |

---

## §6 对端地址与控制消息（addr / control）

新方案下 `ff_zc_send` 不支持：
- 指定对端地址（sendto 语义） → 新版**只对 connected socket 有效**；UDP 必须先 connect；
- 控制消息 SCM（cmsghdr） → 不支持（kern_zc_sendit 传 control=NULL）。

理由：spec 简化、对齐 ZC-recv 设计（kern_zc_recvit 也无地址/控制）。

后续扩展：可定义 `ff_zc_sendto(fd, mb, n, addr, addrlen)` / `ff_zc_sendmsg(fd, msghdr)` API（非本期范围）。

---

## §7 边界检查清单（实施期 + 测试用）

| # | 边界 | spec 条款 | 验证方法 |
|---|---|---|---|
| B1 | top == NULL | kern_zc_sendit 返 EINVAL | unit test |
| B2 | top 缺 M_PKTHDR | kern_zc_sendit 返 EINVAL（同时 m_freem）| unit test |
| B3 | top->m_pkthdr.len < 0 | kern_zc_sendit 返 EINVAL | unit test |
| B4 | top->m_pkthdr.len = 0 | kern_zc_sendit 调 sosend，sosend 取 resid=0 立即返 0 字节 | integration |
| B5 | top->m_pkthdr.len > SO_SNDBUF (TCP) | sosend 阻塞 / 非阻塞 EWOULDBLOCK | integration |
| B6 | top->m_pkthdr.len > MTU (UDP) | sosend_dgram 返 EMSGSIZE | integration |
| B7 | TCP + MSG_EOR | sosend 返 EINVAL（uipc_socket.c:2354）| unit test |
| B8 | 对端关闭 + 无 SO_NOSIGPIPE/MSG_NOSIGNAL | EPIPE + SIGPIPE | integration |
| B9 | 对端关闭 + MSG_NOSIGNAL | EPIPE 但**不**SIGPIPE | integration |
| B10 | fd 非 socket | getsock 返 ENOTSOCK | unit test |
| B11 | fd 已关闭 | getsock 返 EBADF | unit test |
| B12 | UNIX-DGRAM 跨进程 | sosend_dgram 接受；行为与 sendto 一致 | integration |
| B13 | RAW socket + 自构 IP 头 | 透传 sosend_generic | integration（可选）|

---

## §8 不支持矩阵（本期明确拒绝）

| 场景 | 拒绝原因 | 期望错误码 |
|---|---|---|
| sendto 语义（带 addr） | API 不支持（top 路径不暴露 addr） | 调用方应用 connect+ff_zc_send |
| sendmsg 语义（带 control） | API 不支持 | 调用方退化为普通 ff_sendmsg |
| SCTP socket | sosend 路径未测 | EOPNOTSUPP |
| Datagram fragmentation > MTU | atomic 一次性 | EMSGSIZE |
| Send `>` SO_SNDBUF on TCP non-blocking | atomic 一次性 | EWOULDBLOCK |

---

## §9 可门禁验证条款（gatekeeper）

| 条款 | 验证方式 | 通过判据 |
|---|---|---|
| B-G1 | spec 列出 ≥10 个边界 | B1-B11+ |
| B-G2 | 每个边界标 spec 条款 + 验证方法 | 全表 |
| B-G3 | atomic 含义引用 uipc_socket.c:2325 | 命中 |
| B-G4 | TCP+EOR 引用 uipc_socket.c:2354 | 命中 |

---

下一篇：**37-test-spec.md**（CMocka 测试规格）。
