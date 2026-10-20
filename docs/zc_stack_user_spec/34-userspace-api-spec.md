# 34. Userspace API Spec — `ff_zc_send` / `ff_zc_mbuf_get` / `ff_zc_mbuf_write`

> Source: probe-zcsend-current (measured current gap) + 32 architecture design + 33 kernel patch
> Goal: keep the ABI unchanged (G4), while fixing the M_PKTHDR/pkthdr.len gap (G3), and switching to the `kern_zc_sendit` entry (G1)

---

## §1 ABI Invariance Declaration

| Function | Current signature | New-scheme signature | ABI impact |
|---|---|---|---|
| `ff_zc_send` | `ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes)` | **unchanged** | 0 |
| `ff_zc_mbuf_get` | `int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len)` | **unchanged** | 0 |
| `ff_zc_mbuf_write` | `int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len)` | **unchanged** | 0 |
| `struct ff_zc_mbuf` | `{ void *bsd_mbuf; void *bsd_mbuf_off; int off; int len; }` | **unchanged** | 0 |
| `lib/ff_api.symlist` | single symbol `ff_zc_send` | **unchanged** | 0 |

The caller code (example/main_zc.c L208-245) passes with **zero modification**; this is the contract verification point of G4 (and also the AC2 acceptance condition).

---

## §2 ff_api.h Documentation Block Update (comment only)

### §2.1 Anchor (5 lines before) — `lib/ff_api.h:432-436`

```c
/*
 * Get/alloc a mbuf chain into 'struct ff_zc_mbuf' as the buffer of
 * subsequent zero copy write.
 */
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
```

### §2.2 Section to Replace — 437-446 (old documentation block)

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

### §2.3 NEW Documentation Block (semantics unchanged; clarifies the M_PKTHDR + pkthdr.len maintenance contract)

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

Only the documentation comments change; the signatures are 100% identical.

---

## §3 ff_zc_send Rewrite — `lib/ff_syscall_wrapper.c:1186-1226`

### §3.1 Anchor (5 lines before) — 1181-1185

```c
    if ((rc = kern_writev(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
```

(i.e. the end of `ff_writev`, before the `#ifdef FSTACK_ZC_SEND` section)

### §3.2 Section to Replace — 1186-1226 (the whole old ff_zc_send)

See 31 §3.6 (old implementation: construct uio + `auio.uio_offset = FSTACK_ZC_MAGIC` + `kern_writev`).

### §3.3 NEW Implementation

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

### §3.4 Key Changes

| Old implementation | New implementation |
|---|---|
| construct `struct uio auio` + `struct iovec aiov` | directly cast `mb` to `struct mbuf *` |
| `auio.uio_segflg = UIO_SYSSPACE; auio.uio_offset = FSTACK_ZC_MAGIC;` | no sentinel |
| `kern_writev(curthread, fd, &auio)` | `kern_zc_sendit(curthread, fd, top, 0)` |
| relies on the `uio_offset == FSTACK_ZC_MAGIC` branch inside m_uiotombuf | relies on sosend's native `uio == NULL` branch |
| `flags` not controllable | `flags` passed through by kern_zc_sendit to sosend (fixed at 0 this round; can later expose `ff_zc_sendto/zc_sendmsg`) |

### §3.5 Error Code Semantics

| Error | Source | Caller semantics |
|---|---|---|
| `EINVAL` | mb==NULL / nbytes out of range / kern_zc_sendit argument validation | caller programming error |
| `EBADF` / `ENOTSOCK` | getsock failure | illegal fd |
| `EACCES` | MAC denial | security policy |
| `EPIPE` | sosend peer closed (SIGPIPE delivered simultaneously by kern_zc_sendit) | link broken |
| `ENOBUFS` | sosend buffer insufficient (atomic + sb_max not enough) | retry / reduce mb |
| `EWOULDBLOCK` | non-blocking socket full | retry (no partial progress under atomic one-shot delivery semantics) |
| `EMSGSIZE` | DGRAM message too large | reduce mb |

ff_zc_send **always returns ssize_t** (on success the number of bytes sent = top->m_pkthdr.len, on error returns -1 + errno) —— consistent with the old implementation.

---

## §4 ff_zc_mbuf_get / ff_zc_mbuf_write Fix — `lib/ff_veth.c`

### §4.1 ff_zc_mbuf_get — add M_PKTHDR

#### Anchor (5 lines before) — L300-305

```c
static void
ff_mbuf_ext_free(struct mbuf *m)
{
    ff_dpdk_pktmbuf_free(ff_rte_frm_extcl(m));
}

```

#### Section to Replace — L306-323 (old implementation)

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

#### NEW Implementation

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

#### The Only Change

Line 9 `m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, 0)` → `m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, M_PKTHDR)`, adding the argument `len < 0` validation, plus a comment explaining the intent.

### §4.2 ff_zc_mbuf_write — maintain pkthdr.len

#### Anchor (5 lines before) — L322-326

```c
    m->len = len;

    return 0;
}

```

#### Section to Replace — L325-356 (old implementation)

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

#### NEW Implementation

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

#### Key Changes

1. argument validation adds `data != NULL` and `len < 0` rejection;
2. extract the chain-head pointer `head = zm->bsd_mbuf` and accumulate `head->m_pkthdr.len += progress` **once** outside the loop (O(1) maintenance);
3. remove the inner commented-out `m->m_pkthdr.len += length` (the old design wrongly placed accumulation inside each segment of the loop, and it had no effect);
4. remove the unused `int ret`;
5. return `progress` (actual bytes written) instead of `len` (behavior-compatible: the two are equal on success; the empty-trailing-space boundary is more robust).

---

## §5 Delete — the uio_offset opt-out of ff_write/ff_writev

See 31 §3.4 / §3.5. Delete the two `auio.uio_offset = 0` lines (including the related comments) at `lib/ff_syscall_wrapper.c:1146-1151` and `:1175`. Under the new scheme no opt-out is needed anymore (the kern_writev path is unaware of ZC, kern_zc_sendit takes an independent path).

---

## §6 Call Sequence Comparison (example/main_zc.c, passes with zero modification)

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

Under the new scheme:
- ff_zc_mbuf_get internally goes through M_PKTHDR;
- ff_zc_mbuf_write accumulates pkthdr.len = buf_len;
- ff_zc_send treats zc_buf.bsd_mbuf as a struct mbuf* and hands it to kern_zc_sendit;
- kern_zc_sendit calls sosend(uio=NULL, top=chain);
- sosend reads top->m_pkthdr.len = buf_len as resid, skipping m_uiotombuf.

The full flow is **zero-copy** (app buf → mbuf is a single bcopy inside ff_zc_mbuf_write; mbuf → protocol stack is 0-copy; protocol stack → DPDK depends on FF_USE_PAGE_ARRAY).

---

## §7 Gateable Verification Clauses (gatekeeper)

| Clause | Verification method | Pass criterion |
|---|---|---|
| U-G1 | grep `kern_writev` in ff_zc_send body | 0 hits (no longer used) |
| U-G2 | grep `FSTACK_ZC_MAGIC` in lib/ | 0 hits (only the spec doc may retain a historical reference) |
| U-G3 | grep `M_PKTHDR` in ff_zc_mbuf_get | 1 hit (at the m_getm2 call site) |
| U-G4 | grep `m_pkthdr.len` in ff_zc_mbuf_write | 1 hit (at the chain-head accumulation site, not commented out) |
| U-G5 | grep `auio.uio_offset` in ff_write/ff_writev | 0 hits |
| U-G6 | `nm libfstack.a \| grep "T ff_zc_send"` | 1 symbol |
| U-G7 | example/main_zc.c diff (HEAD vs post-impl) | 0 lines changed |

---

Next: **35-mbuf-lifecycle-spec.md** (mbuf chain ownership state machine + invariants).
