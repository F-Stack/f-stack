# 34. 用户态 API 规格 — `ff_zc_send` / `ff_zc_mbuf_get` / `ff_zc_mbuf_write`

> 来源：probe-zcsend-current（实测当前缺口）+ 32 架构设计 + 33 内核 patch
> 目标：保持 ABI 不变（G4），同时修复 M_PKTHDR/pkthdr.len 缺口（G3），切换到 `kern_zc_sendit` 入口（G1）

---

## §1 ABI 不变性宣言

| 函数 | 当前签名 | 新方案签名 | ABI 影响 |
|---|---|---|---|
| `ff_zc_send` | `ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes)` | **不变** | 0 |
| `ff_zc_mbuf_get` | `int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len)` | **不变** | 0 |
| `ff_zc_mbuf_write` | `int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len)` | **不变** | 0 |
| `struct ff_zc_mbuf` | `{ void *bsd_mbuf; void *bsd_mbuf_off; int off; int len; }` | **不变** | 0 |
| `lib/ff_api.symlist` | `ff_zc_send` 单符号 | **不变** | 0 |

调用方代码（example/main_zc.c L208-245）**零修改**通过；这是 G4 的合同验证点（也是 AC2 验收条件）。

---

## §2 ff_api.h 文档块更新（仅注释）

### §2.1 锚点（前 5 行）— `lib/ff_api.h:432-436`

```c
/*
 * Get/alloc a mbuf chain into 'struct ff_zc_mbuf' as the buffer of
 * subsequent zero copy write.
 */
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
```

### §2.2 待替换段 — 437-446（旧文档块）

```c
/*
 * Write data to the mbuf chain in 'sturct ff_zc_mbuf'.
 * The caller of ff_zc_mbuf_write must guarantees the total amount of
 * data written into the mbuf chain in multiple calls is no larger than
 * len of the previous ff_zc_mbuf_get call. (FIXME: refine this with
 * implementation)
 */
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);

ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes);
```

### §2.3 NEW 文档块（语义未变；澄清 M_PKTHDR + pkthdr.len 维护契约）

```c
/*
 * Write data to the mbuf chain in 'struct ff_zc_mbuf'.
 *
 * The caller MUST guarantee the total amount of data written across
 * multiple calls does not exceed the `len` passed to ff_zc_mbuf_get.
 *
 * Internally maintains the chain head's m_pkthdr.len so that the
 * subsequent ff_zc_send -> kern_zc_sendit -> sosend(top) takes
 * top->m_pkthdr.len as resid (FreeBSD sosend(9) contract;
 * uipc_socket.c:2340-2341).
 */
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);

/*
 * Zero-copy send: the `mb` argument MUST be a struct mbuf * obtained
 * from ff_zc_mbuf_get + ff_zc_mbuf_write (cast through `const void *`
 * for ABI compatibility). On success the chain is adopted by the
 * kernel; on error kern_zc_sendit frees it. After a successful
 * ff_zc_send the ff_zc_mbuf is consumed; reuse requires another
 * ff_zc_mbuf_get.
 */
ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes);
```

仅文档注释变化；签名 100% 一致。

---

## §3 ff_zc_send 重写 — `lib/ff_syscall_wrapper.c:1186-1226`

### §3.1 锚点（前 5 行）— 1181-1185

```c
    if ((rc = kern_writev(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
```

（即 `ff_writev` 末尾、`#ifdef FSTACK_ZC_SEND` 区段之前）

### §3.2 待替换段 — 1186-1226（旧 ff_zc_send 整段）

详见 31 §3.6（旧实现：构造 uio + `auio.uio_offset = FSTACK_ZC_MAGIC` + `kern_writev`）。

### §3.3 NEW 实现

```c
#ifdef FSTACK_ZC_SEND
/*
 * Zero-copy send fast-path. Caller passes a pre-built mbuf chain head
 * (obtained from ff_zc_mbuf_get + ff_zc_mbuf_write; cast through
 * const void* for ABI compatibility) as `mb`. We re-cast to
 * struct mbuf* and hand it to kern_zc_sendit, which calls sosend
 * with top != NULL and uio == NULL — the FreeBSD-native zero-copy
 * path (see sosend(9), uipc_socket.c:2598-2609).
 *
 * Compared to the previous FSTACK_ZC_MAGIC magic-stamping scheme
 * (deleted in this revision), no kernel m_uiotombuf modification
 * is needed; ff_write/ff_writev no longer need uio_offset opt-out.
 */
ssize_t
ff_zc_send(int fd, const void *mb, size_t nbytes)
{
    struct mbuf *top;
    int rc;

    if (mb == NULL || nbytes == 0 || nbytes > INT_MAX) {
        rc = EINVAL;
        goto kern_fail;
    }

    /* The chain MUST already be M_PKTHDR-headed with pkthdr.len
     * == nbytes; ff_zc_mbuf_get/write maintain this invariant.
     * kern_zc_sendit re-validates and returns EINVAL otherwise. */
    top = (struct mbuf *)(uintptr_t)mb;

    if ((rc = kern_zc_sendit(curthread, fd, top, /*flags*/0)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}
#endif /* FSTACK_ZC_SEND */
```

### §3.4 关键变化

| 旧实现 | 新实现 |
|---|---|
| 构造 `struct uio auio` + `struct iovec aiov` | 直接 cast `mb` 为 `struct mbuf *` |
| `auio.uio_segflg = UIO_SYSSPACE; auio.uio_offset = FSTACK_ZC_MAGIC;` | 无哨兵 |
| `kern_writev(curthread, fd, &auio)` | `kern_zc_sendit(curthread, fd, top, 0)` |
| 依赖 m_uiotombuf 内 `uio_offset == FSTACK_ZC_MAGIC` 分支 | 依赖 sosend 原生 `uio == NULL` 分支 |
| `flags` 不可控 | `flags` 由 kern_zc_sendit 透传至 sosend（本期固定 0；后续可暴露 `ff_zc_sendto/zc_sendmsg`）|

### §3.5 错误码语义

| 错误 | 来源 | 调用方语义 |
|---|---|---|
| `EINVAL` | mb==NULL / nbytes 越界 / kern_zc_sendit 入参校验 | 调用方编程错误 |
| `EBADF` / `ENOTSOCK` | getsock 失败 | fd 非法 |
| `EACCES` | MAC 拒绝 | 安全策略 |
| `EPIPE` | sosend 对端关闭（同时 SIGPIPE 由 kern_zc_sendit 投递）| 链路断开 |
| `ENOBUFS` | sosend 缓冲不足（atomic + sb_max 不够）| 重试 / 减小 mb |
| `EWOULDBLOCK` | 非阻塞 socket 满 | 重试（atomic 一次性投递语义下不会有部分进度）|
| `EMSGSIZE` | DGRAM 消息过大 | 减小 mb |

ff_zc_send **始终返回 ssize_t**（成功为发送字节数=top->m_pkthdr.len，错误返回 -1 + errno）—— 与旧实现一致。

---

## §4 ff_zc_mbuf_get / ff_zc_mbuf_write 修复 — `lib/ff_veth.c`

### §4.1 ff_zc_mbuf_get — 加 M_PKTHDR

#### 锚点（前 5 行）— L300-305

```c
static void
ff_mbuf_ext_free(struct mbuf *m)
{
    ff_dpdk_pktmbuf_free(ff_rte_frm_extcl(m));
}

```

#### 待替换段 — L306-323（旧实现）

```c
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len) {
    struct mbuf *mb;

    if (m == NULL) {
        return -1;
    }

    mb = m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, 0);
    if (mb == NULL) {
        return -1;
    }

    m->bsd_mbuf = m->bsd_mbuf_off = mb;
    m->off = 0;
    m->len = len;

    return 0;
}
```

#### NEW 实现

```c
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len) {
    struct mbuf *mb;

    if (m == NULL || len < 0) {
        return -1;
    }

    /* M_PKTHDR is REQUIRED so the chain head carries an m_pkthdr.
     * sosend (uipc_socket.c:2340-2341) takes resid from
     * top->m_pkthdr.len when uio==NULL; without M_PKTHDR sosend
     * would fall through to m_length() (O(N)) or, worse, mis-route
     * resid. ff_zc_mbuf_write maintains pkthdr.len incrementally. */
    mb = m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, M_PKTHDR);
    if (mb == NULL) {
        return -1;
    }
    /* m_getm2 with M_PKTHDR initializes pkthdr.len to 0 already
     * (verified upstream); ff_zc_mbuf_write will accumulate. */

    m->bsd_mbuf = m->bsd_mbuf_off = mb;
    m->off = 0;
    m->len = len;

    return 0;
}
```

#### 唯一变更

第 9 行 `m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, 0)` → `m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, M_PKTHDR)`，加入参 `len < 0` 校验，加注释说明意图。

### §4.2 ff_zc_mbuf_write — 维护 pkthdr.len

#### 锚点（前 5 行）— L322-326

```c
    m->len = len;

    return 0;
}

```

#### 待替换段 — L325-356（旧实现）

```c
int
ff_zc_mbuf_write(struct ff_zc_mbuf *zm, const char *data, int len)
{
    int ret, length, progress = 0;
    struct mbuf *m, *mb;

    if (zm == NULL) {
        return -1;
    }
    m = (struct mbuf *)zm->bsd_mbuf_off;

    if (zm->off + len > zm->len) {
        return -1;
    }

    for (mb = m; mb != NULL; mb = mb->m_next) {
        length = min(M_TRAILINGSPACE(mb), len - progress);
        bcopy(data + progress, mtod(mb, char *) + mb->m_len, length);

        mb->m_len += length;
        progress += length;
        if (len == progress) {
            break;
        }
        //if (flags & M_PKTHDR)
        //    m->m_pkthdr.len += length;
    }
    zm->off += len;
    zm->bsd_mbuf_off = mb;

    return len;
}
```

#### NEW 实现

```c
int
ff_zc_mbuf_write(struct ff_zc_mbuf *zm, const char *data, int len)
{
    int length, progress = 0;
    struct mbuf *m, *mb, *head;

    if (zm == NULL || data == NULL || len < 0) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    head = (struct mbuf *)zm->bsd_mbuf;
    m = (struct mbuf *)zm->bsd_mbuf_off;

    if (zm->off + len > zm->len) {
        return -1;
    }

    for (mb = m; mb != NULL; mb = mb->m_next) {
        length = min(M_TRAILINGSPACE(mb), len - progress);
        if (length > 0) {
            bcopy(data + progress, mtod(mb, char *) + mb->m_len, length);
            mb->m_len += length;
            progress += length;
        }
        if (len == progress) {
            break;
        }
    }

    /* Maintain pkthdr.len on the chain HEAD only (per FreeBSD mbuf(9)
     * convention: only the leading mbuf of a packet carries pkthdr).
     * sosend (uipc_socket.c:2340-2341) reads exactly this field as
     * resid when uio==NULL. */
    head->m_pkthdr.len += progress;

    zm->off += progress;
    zm->bsd_mbuf_off = mb;

    return progress;
}
```

#### 关键变化

1. 入参校验加 `data != NULL` 与 `len < 0` 拒绝；
2. 把链头指针 `head = zm->bsd_mbuf` 提取出来，循环外**一次性**累加 `head->m_pkthdr.len += progress`（O(1) 维护）；
3. 删除内层注释掉的 `m->m_pkthdr.len += length`（旧设计错把累加放在每段循环内，且未生效）；
4. 删除未使用的 `int ret`；
5. 返回 `progress`（实际写入字节数）而非 `len`（行为兼容：成功时两者相等；空 trailing space 边界更稳健）。

---

## §5 删除 — ff_write/ff_writev 的 uio_offset opt-out

详见 31 §3.4 / §3.5。删除 `lib/ff_syscall_wrapper.c:1146-1151` 与 `:1175` 两处 `auio.uio_offset = 0` 行（含相关注释）。新方案下不再需要任何 opt-out（kern_writev 路径不感知 ZC，kern_zc_sendit 走独立路径）。

---

## §6 调用序列对照（example/main_zc.c，零修改通过）

```c
struct ff_zc_mbuf zc_buf;
size_t buf_len = strlen(html_buf);

if (ff_zc_mbuf_get(&zc_buf, buf_len) < 0) {
    /* error */
}
if (ff_zc_mbuf_write(&zc_buf, html_buf, buf_len) < 0) {
    /* error */
}
ssize_t n = ff_zc_send(clientfd, zc_buf.bsd_mbuf, buf_len);
if (n < 0) {
    /* error */
}
```

新方案下：
- ff_zc_mbuf_get 内部走 M_PKTHDR；
- ff_zc_mbuf_write 累加 pkthdr.len = buf_len；
- ff_zc_send 把 zc_buf.bsd_mbuf 当 struct mbuf* 投给 kern_zc_sendit；
- kern_zc_sendit 调 sosend(uio=NULL, top=链)；
- sosend 读取 top->m_pkthdr.len = buf_len 作 resid，跳过 m_uiotombuf。

完整流程**零拷贝**（应用 buf → mbuf 单次 bcopy 在 ff_zc_mbuf_write 内；mbuf → 协议栈 0 拷贝；协议栈 → DPDK 视 FF_USE_PAGE_ARRAY 而定）。

---

## §7 可门禁验证条款（gatekeeper）

| 条款 | 验证方式 | 通过判据 |
|---|---|---|
| U-G1 | grep `kern_writev` in ff_zc_send body | 0 命中（已不再用）|
| U-G2 | grep `FSTACK_ZC_MAGIC` in lib/ | 0 命中（仅 spec 文档可保留历史引用）|
| U-G3 | grep `M_PKTHDR` in ff_zc_mbuf_get | 1 命中（m_getm2 调用处）|
| U-G4 | grep `m_pkthdr.len` in ff_zc_mbuf_write | 1 命中（链头累加处，未注释）|
| U-G5 | grep `auio.uio_offset` in ff_write/ff_writev | 0 命中 |
| U-G6 | `nm libfstack.a \| grep "T ff_zc_send"` | 1 个符号 |
| U-G7 | example/main_zc.c diff (HEAD vs post-impl) | 0 行变化 |

---

下一篇：**35-mbuf-lifecycle-spec.md**（mbuf 链所有权状态机 + 不变量）。
