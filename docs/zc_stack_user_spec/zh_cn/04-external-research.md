# 04 · 外网资料调研与交叉验证

> 探针：research-ext。外网仅作启发；凡引用标注与 f-stack 实测代码是否一致，不一致以代码为准。

## 1. FreeBSD 官方手册 —— soreceive mp0（权威佐证，与代码完全一致）
来源：FreeBSD `SOCKET(9)` / `soreceive_generic(9)` 手册（作者 Robert Watson & Benjamin Kaduk，2014-05-26）。
原型：`int soreceive(struct socket *so, struct sockaddr **psa, struct uio *uio, struct mbuf **mp0, struct mbuf **controlp, int *flagsp);`
**原文**：
> "Data may be retrieved directly to kernel or user memory via the `uio` argument, **or as an mbuf chain returned to the caller via `mp0`, avoiding a data copy**. The `uio` must always be non-NULL. **If `mp0` is non-NULL, only the `uio_resid` of `uio` is used**."

**交叉验证**：与 02 §3 实测完全吻合 —— `mp0!=NULL` 时 soreceive 以 mbuf 链返回、避免拷贝（uipc_socket.c:3061-3066），且仅用 uio_resid（L3050 `uio_resid-=len`）。**ZC-read 内核机制是 FreeBSD 原生官方能力，非 hack。**

BUGS 提示（手册）：
> "The MSG_DONTWAIT flag ... may not always work with `soreceive()` when **zero copy sockets** are enabled."
→ 与 02 §6 非阻塞边界一致：ZC + DONTWAIT 部分 mbuf 仍需 m_copym(M_NOWAIT)，存在边界限制。

## 2. F-Stack 官方（腾讯云开发者社区）—— 收包方向当时未实现
来源：《F-Stack 发送零拷贝介绍》（2022-04-25，腾讯云开发者社区）。
要点（与代码一致）：
- 发包零拷贝分两阶段拷贝：①协议栈→DPDK rte_mbuf；②应用层 socket 发送时 应用层→协议栈 mbuf。f-stack ZC-send 针对的是阶段②（与 01 §0/§2 一致：ff_zc_mbuf_write 仍 bcopy，省的是用户→内核 socket 拷贝）。
- **原文**："收包方向因为我们自己本身的业务场景涉及收包数据很少，后续另行介绍" → **印证 ZC-recv 在官方当时未落地**，与本仓库 `ff_zc_mbuf_read` 为空 stub（03/01 实测）一致。

## 3. DPDK mbuf 零拷贝 / refcount（知乎技术文）
来源：《DPDK 内存管理核心：mbuf 和 mempool 的零拷贝实现》（2025-07）。
要点：DPDK 通过 **共享数据缓冲 + 增加引用计数** 实现 mbuf 零拷贝，避免实际数据拷贝；智能回收按 refcount 归零触发。
**交叉验证**：与 03 §2/§3 实测的 EXT_FLAG_EMBREF / ext_count + rte_pktmbuf_free_seg 归还机制思路一致 —— f-stack 用 BSD mbuf 的 m_ext refcnt 驱动 DPDK seg 归还。

## 4. 同类机制参考
- FreeBSD `sosplice`/`soreceive_stream`：mp0 路径已被内核 splice（如 so_splice）用于 mbuf 直递（02 §3 soreceive_stream_locked L3337-3359 m_cat 整段移交印证）。
- 结论：把 mbuf 链交给消费者而不拷贝，是内核既有成熟模式；ZC-read 是把"消费者"从内核 splice 扩展到 f-stack 用户态 APP。

## 5. 交叉验证结论汇总
| 外网观点 | f-stack 实测 | 一致性 |
|---|---|---|
| soreceive mp0 可零拷贝返回 mbuf 链 | uipc_socket.c:3061-3066 确有该分支 | ✅ 完全一致 |
| mp0!=NULL 仅用 uio_resid | L3050 uio_resid-=len | ✅ 一致 |
| ZC + MSG_DONTWAIT 有边界限制 | L3081 部分 mbuf 走 m_copym(M_NOWAIT) | ✅ 一致 |
| F-Stack 收包零拷贝官方未实现 | ff_zc_mbuf_read 空 stub | ✅ 一致 |
| DPDK refcount 驱动零拷贝回收 | EXT_FLAG_EMBREF + rte_pktmbuf_free_seg | ✅ 一致 |

**无冲突项**。外网资料全面支持"复用 soreceive mp0 实现 ZC-read"的技术路线。
