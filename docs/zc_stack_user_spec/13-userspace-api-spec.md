# 13 · Userspace API Spec

> Everything wrapped in `#ifdef FSTACK_ZC_RECV`. Symmetric to SEND's get/write/send, RECV is the three stages recv→read/segment→free.

## 1. struct ff_zc_mbuf (reused, ff_api.h:347)
```c
struct ff_zc_mbuf {
    void *bsd_mbuf;       /* ZC-RECV: head of mbuf chain handed out by kernel (the object of m_freem) */
    void *bsd_mbuf_off;   /* ZC-RECV: traversal cursor (the mbuf currently being read) */
    int   off;            /* ZC-RECV: cumulative read offset, APP should not modify */
    int   len;            /* ZC-RECV: total valid bytes of the chain (= bytes returned by this recv) */
};
```
Semantics reuse: in SEND, off/len are "written/capacity"; in RECV, they are "read/total valid".

## 2. ff_zc_recv —— Zero-Copy Receive
```c
ssize_t ff_zc_recv(int fd, struct ff_zc_mbuf *zm, size_t nbytes);
```
| Item | Spec |
|---|---|
| Input | fd: socket; zm: output container (non-NULL); nbytes: expected maximum bytes (maps to uio_resid) |
| Behavior | passes mp0 through via kern_zc_recvit, retrieves the zero-copy mbuf chain; fills zm->bsd_mbuf=chain head, bsd_mbuf_off=chain head, off=0, len=returned bytes |
| Return | >0: actual received bytes (=len); 0: peer closed; -1: error (errno) |
| Error codes | EINVAL (zm==NULL/nbytes>INT_MAX), EAGAIN (non-blocking with no data), ECONNRESET etc. inherited from soreceive |
| Misuse protection | After returning >0, the APP **must** eventually call ff_zc_recv_free (otherwise mempool leaks) |

## 3. ff_zc_mbuf_read —— Read Out/Traverse (rewrite empty stub)
Currently an empty stub (ff_veth.c:359, signature `const char *data` contradicts reading out). Redesign:
```c
/* Plan 1: copy read out into user buf (drop const on data, use as OUT) */
int ff_zc_mbuf_read(struct ff_zc_mbuf *zm, char *out, int len);
/* Plan 2 (recommended, true zero-copy traversal): return current segment pointer+length, advance cursor */
int ff_zc_mbuf_segment(struct ff_zc_mbuf *zm, void **seg_data, int *seg_len);
```
| Item | Spec (Plan 2) |
|---|---|
| Behavior | take the current mbuf's mtod(m)/m_len from bsd_mbuf_off, return *seg_data/*seg_len, advance the cursor m_next, off+=seg_len |
| Return | >0: bytes of this segment; 0: chain fully read; -1: error |
| Zero-copy | seg_data directly points to mbuf data (pointing to DPDK mbuf); the APP can safely access it before free |

## 4. ff_zc_recv_free —— Return the Whole Chain
```c
void ff_zc_recv_free(struct ff_zc_mbuf *zm);
```
| Item | Spec |
|---|---|
| Behavior | `m_freem((struct mbuf*)zm->bsd_mbuf)`; segment-by-segment triggers ff_mbuf_ext_free→rte_pktmbuf_free_seg to return DPDK seg; zeroes zm |
| Idempotent | when bsd_mbuf==NULL, no-op |
| Constraint | after the call, zm can no longer be used for read/segment (need a fresh ff_zc_recv) |

## 5. Call Sequence (symmetric to main_zc.c SEND)
```c
struct ff_zc_mbuf zm;
ssize_t n = ff_zc_recv(clientfd, &zm, sizeof_expect);
if (n > 0) {
    void *seg; int slen;
    while (ff_zc_mbuf_segment(&zm, &seg, &slen) > 0) {
        /* zero-copy process seg[0..slen) (e.g. forward/parse) */
    }
    ff_zc_recv_free(&zm);   /* mandatory! */
}
```

## 6. Relationship with Existing APIs
- Ordinary ff_read/ff_recv/ff_recvfrom/ff_recvmsg are **completely unchanged** (mp0 still NULL, copy path).
- ff_zc_recv and ordinary recv are mutually exclusive for the same read; mixing them does not break correctness (each is an independent soreceive call).
