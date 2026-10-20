# 10 · Spec 总览（FSTACK_ZC_RECV 零拷贝收包）

> 实现级规格。衔接可行性结论（00-09，结论"可行"，推荐方案A 复用 soreceive mp0）。

## 1. 范围
为 f-stack 增加零拷贝收包能力 FSTACK_ZC_RECV：让 APP 直接获得 socket 接收缓冲区中的 BSD mbuf 链（其数据已零拷贝指向 DPDK mbuf），消除 `soreceive→uiomove` 的 mbuf→用户 buffer 拷贝。本规格指导后续编码，**本阶段不写实现代码**。

## 2. 术语
| 术语 | 含义 |
|---|---|
| ZC-RECV | 零拷贝收包（本特性）|
| mp0 | soreceive 第 4 形参 `struct mbuf **mp0`，非 NULL 时以 mbuf 链返回、避免拷贝（FreeBSD 原生）|
| ext-mbuf | external mbuf：BSD mbuf 头 + 指向 DPDK mbuf 数据的外部存储（EXT_DISPOSABLE）|
| release 契约 | APP 读完后必须归还 mbuf 链（m_freem），否则 mempool 泄漏 |

## 3. 目标与非目标
- **目标**：TCP（含 stream）大块数据零拷贝收取；正确的所有权移交与释放；不破坏现有 recv/read 语义。
- **非目标（本特性）**：MSG_OOB / MSG_PEEK / KERN_TLS 零拷贝（回退拷贝）；UDP 走 dgram 回退；小包优化。

## 4. 编译开关（与 SEND 对称）
- 现有：`lib/Makefile:210-212  ifdef FF_ZC_SEND → CFLAGS+=-DFSTACK_ZC_SEND`
- 新增：`ifdef FF_ZC_RECV → CFLAGS+=-DFSTACK_ZC_RECV`
- 哨兵宏 FSTACK_ZC_MAGIC（send 用）**不复用于 recv**（方向相反，见 01 §5 / 11）。

## 5. 文档导航
11 架构 / 12 内核 patch / 13 用户态 API / 14 生命周期 / 15 边界回退 / 16 测试 / 17 验收里程碑 / 19 审核。

## 6. 关键实测依据（溯源）
- soreceive 原型与 mp0 分派：uipc_socket.c:3661-3671
- recv 链：sys_recvfrom/sys_recvmsg → recvit(uipc_syscalls.c:1049) → kern_recvit(:895) → soreceive(...,NULL,...)(:948)
- read 链：read → dofileread(sys_generic.c:345) → fo_read → soo_read(sys_socket.c:121) → soreceive(so,0,uio,0,0,0)(:133)
- 返回字节：kern_recvit:967 `td_retval[0]=len-auio.uio_resid`
- ext-mbuf：ff_veth.c:374 m_extadd(...EXT_DISPOSABLE)；释放链 ff_veth.c:300/1106 → rte_pktmbuf_free_seg
