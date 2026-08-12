# 00 — Investigation Overview

## Issue #535 Details

- **Title**: Crash on multiple IPFW rules
- **Status**: Open
- **Created**: 2020-07-28
- **Reporter**: chinosat
- **Repository**: F-Stack/f-stack

### Problem Description

Using f-stack dev branch 1.21, with IPFW support enabled, 32 worker_processes on a 32-core host, 13968 huge pages. Works normally when the IPFW rule list is short; when adding more than 400 IPFW rules per nginx process, ipfw hangs, EAL allocation errors occur, and traffic cannot be processed.

### Environment

- f-stack version: dev branch 1.21
- IPFW support: Enabled
- nginx worker_processes: 32
- CPU: 32 cores
- Huge Pages: 13968 (2048 kB/page)

## Code Path Analysis

### IPC Message Buffer Limit

**`lib/ff_msg.h:131`**:
```c
#define MAX_MSG_BUF_SIZE 10240
```
IPC message buffer upper limit 10KB.

**`lib/ff_dpdk_if.c:704-709`** — mempool creation:
```c
message_pool = rte_mempool_create(FF_MSG_POOL,
   MSG_RING_SIZE * 2 * nb_rings,
   MAX_MSG_BUF_SIZE,   // elt_size = 10240
   MSG_RING_SIZE / 2,  // cache_size = 16
   0,
   NULL, NULL, ff_msg_init, NULL,
   socketid, 0);
```

**`lib/ff_dpdk_if.c:688-689`** — `ff_msg_init` sets available buffer:
```c
msg->buf_addr = (char *)msg + sizeof(struct ff_msg);
msg->buf_len = mp->elt_size - sizeof(struct ff_msg);
```
Actual available buffer ≈ 10240 - sizeof(struct ff_msg) ≈ 10112 bytes.

### Silent EINVAL Failure in IPFW Tool

**`tools/ipfw/compat.c:59-64`** (before fix):
```c
len = sizeof(struct ff_ipfw_args) + *optlen + sizeof(socklen_t);
if (len > msg->buf_len) {
    errno = EINVAL;
    ff_ipc_msg_free(msg);
    return -1;
}
```
When total IPFW rule data exceeds ~10KB, `getsockopt(IP_FW3)` retrieving all rule data exceeds the buffer limit, returning EINVAL and failing silently.

### Existing Dynamic Buffer Template

**`tools/compat/sysctl.c:57-69`** — the sysctl tool already implements a dynamic buffer scheme:
```c
if (total_len > msg->buf_len) {
    extra_buf = rte_malloc(NULL, total_len, 0);
    if (extra_buf == NULL) { errno = ENOMEM; ... return -1; }
    msg->original_buf = msg->buf_addr;
    msg->original_buf_len = msg->buf_len;
    msg->buf_addr = extra_buf;
    msg->buf_len = total_len;
}
```

### Infrastructure Completeness

| Component | Location | Status |
|-----------|----------|--------|
| `original_buf`/`original_buf_len` fields | `lib/ff_msg.h:142-143` | Existing |
| `ff_ipc_msg_free` dynamic buffer recovery | `tools/compat/ff_ipc.c:121-126` | Supported |
| Primary process enqueue failure cleanup | `lib/ff_dpdk_if.c:2338-2344` | Supported |
| `ff_msg_init` initializes `original_buf=NULL` | `lib/ff_dpdk_if.c:690` | Existing |

## 13.0 Baseline Comparison

**`f-stack-13.0-baseline/lib/ff_msg.h:131`**: `#define MAX_MSG_BUF_SIZE 10240` — same as 15.0.

**`f-stack-13.0-baseline/tools/ipfw/compat.c:59-63`**: Same `len > msg->buf_len` → EINVAL pattern.

**Conclusion**: This issue is a **long-standing problem**, not a regression introduced by the 13.0→15.0 upgrade.

## External Resource Search

Searched GitHub issues/wiki, Tencent Cloud developer community, technical blogs, etc. No official fix PR or patch for issue #535 was found. The issue remains in OPEN status with no maintainer response or fix plan.

## All tools/compat Buffer Handling Comparison

| Tool File | Buffer Overflow Handling | Dynamic Allocation? |
|-----------|------------------------|---------------------|
| `tools/compat/sysctl.c` | `rte_malloc` + `original_buf` | Yes |
| `tools/compat/ioctl.c` | Static EINVAL/ENOMEM | No |
| `tools/compat/rtioctl.c` | Static EINVAL | No |
| `tools/libnetgraph/compat.c` | Static EINVAL | No |
| `tools/ipfw/compat.c` (before fix) | Static EINVAL | No |
| `tools/ipfw/compat.c` (after fix) | `rte_malloc` + `original_buf` | Yes |

The fix aligns `ipfw/compat.c` with the `sysctl.c` pattern. Other tools' static limitations are pre-existing and outside the scope of this fix.
