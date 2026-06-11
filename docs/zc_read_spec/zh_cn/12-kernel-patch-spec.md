# 12 · 内核 Patch 详规

> 所有锚点经实测。改动包裹于 `#ifdef FSTACK_ZC_RECV`，默认不启用，不影响现有路径。

## 1. 改动总表
| # | 文件 | 锚点 | 改动 | 风险 |
|---|---|---|---|---|
| K1 | freebsd/kern/uipc_syscalls.c | kern_recvit:895 / soreceive:948 | 新增 `kern_zc_recvit` 变体，把 soreceive 第4参由 NULL 改为 `&mp` 透传 | 低（新增函数，不改原 kern_recvit）|
| K2 | freebsd/kern/sys_socket.c | soo_read:121 / soreceive:133 | read() 路径 ZC 支持（可选，见 §4）：经 fp 标志或新 fileop 透传 mp | 中 |
| K3 | lib/Makefile | 210-212 | 新增 `ifdef FF_ZC_RECV → -DFSTACK_ZC_RECV` | 无 |
| K4 | lib/ff_syscall_wrapper.c | ff_recvfrom:1319 / ff_recvmsg:1359 | 新增 `ff_zc_recv` 入口，调 kern_zc_recvit；普通 recv 不变 | 低 |

## 2. K1 — kern_zc_recvit（推荐核心改动）
现状（uipc_syscalls.c:948，**保持不变**）：
```c
error = soreceive(so, &fromsa, &auio, NULL,
    (mp->msg_control || controlp) ? &control : NULL, &mp->msg_flags);
```
新增变体（伪代码，`#ifdef FSTACK_ZC_RECV`）：
```c
int
kern_zc_recvit(struct thread *td, int s, struct msghdr *mp,
    enum uio_seg fromseg, struct mbuf **controlp, struct mbuf **mp0 /* 新增出参 */)
{
    /* 与 kern_recvit 同样构造 auio（uio_segflg/uio_rw/uio_resid，:928-941）*/
    struct mbuf *zc_chain = NULL;
    error = soreceive(so, &fromsa, &auio, &zc_chain /* mp0 非 NULL */,
        (mp->msg_control || controlp) ? &control : NULL, &mp->msg_flags);
    /* 返回字节同 kern_recvit:967: td_retval[0] = len - auio.uio_resid */
    if (mp0 != NULL) *mp0 = zc_chain;   /* 把零拷贝链交出 */
    /* 地址/控制消息回填逻辑复用 kern_recvit 现有代码 */
}
```
**约束**：
- 必须复用 kern_recvit 现有的 auio 构造（:928-941）、返回值计算（:967）、fromsa/control 回填，保持语义一致。
- mp0!=NULL 时 soreceive 仅用 uio_resid（FreeBSD 手册，04 §1），故 auio 仍需正确设置 uio_resid。
- 调用方（ff_zc_recv）负责把 zc_chain 存入 struct ff_zc_mbuf 并最终 m_freem。

## 3. soreceive 侧（**不改**）
soreceive(uipc_socket.c:3661) 的 mp0 分支为 FreeBSD 原生，**无需改动**：
- mp!=NULL 整段直交（sbfree + *mp=m + sb_mb 前移）；
- split → m_copym 回退；
- mp==NULL → uiomove（现有 recv 不受影响）。
TCP 默认 pr_soreceive=soreceive_generic（支持 mp0）；开启 soreceive_stream 亦支持。

## 4. K2 — read() 路径（可选，分期）
read→soo_read→`soreceive(so,0,uio,0,0,0)`（sys_socket.c:133）写死 mp0=0。read() 接口本身无 mbuf 出参语义，ZC-recv **优先经 ff_zc_recv（recv 系）实现**；read() 路径 ZC 列为可选/后续（需经 file 标志或新 fileop 传 mp，改动面更大，M4 评估）。

## 5. 不破坏现有 recv 的论证
- 原 kern_recvit / soo_read **零改动**，mp0 仍 NULL → 现有 recv/read 行为完全不变。
- 新增 kern_zc_recvit 仅在 FSTACK_ZC_RECV 编译 + APP 显式调 ff_zc_recv 时生效。
- soreceive 核心未改 → 协议层/记账/锁语义不变（02 §4 已验证 mp0 分支记账自洽）。

## 6. FSTACK_ZC_RECV 宏门控范围
- lib/ff_api.h：ff_zc_recv/ff_zc_mbuf_read/ff_zc_recv_free 声明
- lib/ff_veth.c：ff_zc_mbuf_read 重写 + ff_zc_recv_free
- lib/ff_syscall_wrapper.c：ff_zc_recv
- freebsd/kern/uipc_syscalls.c：kern_zc_recvit
