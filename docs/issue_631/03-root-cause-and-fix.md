# Issue #631 Root Cause Analysis and Conclusion

## 1. Complete Call Chain Tracing

### 1.1 ff_shutdown Entry

**File**: `lib/ff_syscall_wrapper.c:1862-1891`

```c
int ff_shutdown(int s, int how) {
    struct shutdown_args sa = { .s = s, .how = how };
    if ((rc = sys_shutdown(curthread, &sa)))
        goto kern_fail;
    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}
```

`ff_shutdown` directly calls FreeBSD's `sys_shutdown`; `curthread` is the F-Stack userspace thread.

### 1.2 kern_shutdown

**File**: `freebsd/kern/uipc_syscalls.c:1328-1355`

```c
int kern_shutdown(struct thread *td, int s, int how) {
    error = getsock(td, s, &cap_shutdown_rights, &fp);
    if (error == 0) {
        so = fp->f_data;
        error = soshutdown(so, how);
        if (error == ENOTCONN &&
            td->td_proc->p_osrel < P_OSREL_SHUTDOWN_ENOTCONN)
            error = 0;                    // ← ENOTCONN converted to 0
        fdrop(fp, td);
    }
    return (error);
}
```

**Key**: `p_osrel` is 0 in F-Stack userspace (in `lib/ff_init_main.c`'s `proc0_init()`, `p->p_osrel = osreldate` is disabled by `#if 0`, leaving `proc0.p_osrel` at zero-initialized value 0), and `P_OSREL_SHUTDOWN_ENOTCONN = 1100077` (`freebsd/sys/param.h:100`). Therefore `0 < 1100077` is true, and `ENOTCONN` is always converted to 0.

### 1.3 soshutdown

**File**: `freebsd/kern/uipc_socket.c:3673-3683`

```c
int soshutdown(struct socket *so, enum shutdown_how how) {
    error = so->so_proto->pr_shutdown(so, how);  // dispatch to udp_shutdown
    return (error);
}
```

FreeBSD 15.0's `soshutdown` fully delegates to the protocol's `pr_shutdown` callback, no longer handling sorflush/socantsendmore itself.

### 1.4 udp_shutdown (Core Function)

**File**: `freebsd/netinet/udp_usrreq.c:1741-1778`

```c
int udp_shutdown(struct socket *so, enum shutdown_how how) {
    SOCK_LOCK(so);
    if (!(so->so_state & SS_ISCONNECTED))
        error = ENOTCONN;        // ← unconnected UDP returns ENOTCONN
    else
        error = 0;
    SOCK_UNLOCK(so);

    switch (how) {
    case SHUT_RD:
        sorflush(so);            // ← sorflush executed regardless of connection state
        break;
    case SHUT_RDWR:
        sorflush(so);
        /* FALLTHROUGH */
    case SHUT_WR:
        socantsendmore(so);
    }
    return (error);              // ← returns ENOTCONN (but sorflush already executed)
}
```

**Key**: `sorflush(so)` is inside the `switch` statement, **unaffected by the ENOTCONN error**. Even when ENOTCONN is returned, `sorflush` is still executed.

### 1.5 sorflush

**File**: `freebsd/kern/uipc_socket.c:3688-3718`

```c
void sorflush(struct socket *so) {
    socantrcvmore(so);                          // ← sets SBS_CANTRCVMORE
    error = SOCK_IO_RECV_LOCK(so, SBL_WAIT | SBL_NOINTR);
    sbrelease(so, SO_RCV);                      // ← releases receive buffer
    SOCK_IO_RECV_UNLOCK(so);
}
```

### 1.6 socantrcvmore

**File**: `freebsd/kern/uipc_sockbuf.c:393-414`

```c
void socantrcvmore_locked(struct socket *so) {
    so->so_rcv.sb_state |= SBS_CANTRCVMORE;    // ← sets flag
    sorwakeup_locked(so);                       // ← wakes blocked recv
}
```

### 1.7 soreceive_dgram (Receive Path Check)

**File**: `freebsd/kern/uipc_socket.c:3486-3545`

```c
int soreceive_dgram(struct socket *so, ...) {
    SOCKBUF_LOCK(&so->so_rcv);
    while ((m = so->so_rcv.sb_mb) == NULL) {
        if (so->so_error) { ... }
        if (so->so_rcv.sb_state & SBS_CANTRCVMORE ||  // ← checks flag
            uio->uio_resid == 0) {
            SOCKBUF_UNLOCK(&so->so_rcv);
            return (0);                                // ← returns 0 (EOF)
        }
        if ((so->so_state & SS_NBIO) ||
            (flags & (MSG_DONTWAIT|MSG_NBIO))) {
            SOCKBUF_UNLOCK(&so->so_rcv);
            return (EWOULDBLOCK);
        }
        // ... block waiting for data ...
    }
}
```

**Key**: When `SBS_CANTRCVMORE` is set and the receive buffer is empty, `soreceive_dgram` returns 0 (EOF).

## 2. Root Cause Conclusion

### 2.1 Why Issue #631 Does Not Reproduce in Current Version

1. `ff_shutdown(SHUT_RD)` → `udp_shutdown` returns `ENOTCONN`, but **still calls `sorflush`**
2. `sorflush` → `socantrcvmore` sets `SBS_CANTRCVMORE` + `sbrelease` releases buffer
3. `kern_shutdown` converts `ENOTCONN` to 0 (because `p_osrel=0 < P_OSREL_SHUTDOWN_ENOTCONN`)
4. Subsequent `ff_recvfrom` → `soreceive_dgram` checks `SBS_CANTRCVMORE` → returns 0 (EOF)

### 2.2 Difference from Linux Kernel

| Behavior | F-Stack (FreeBSD 15.0) | Linux Kernel |
|---------|----------------------|-------------|
| shutdown(SHUT_RD) return value | 0 (ENOTCONN swallowed) | -1 (ENOTCONN) |
| sorflush executed? | Yes | No equivalent |
| SBS_CANTRCVMORE set? | Yes | No |
| Subsequent recvfrom behavior | Returns 0 (EOF) | Continues receiving data |

Linux kernel returns `ENOTCONN` for unconnected UDP `shutdown(SHUT_RD)` without modifying socket state, so it continues receiving data. F-Stack (FreeBSD)'s `udp_shutdown` executes `sorflush` even when returning `ENOTCONN`, causing subsequent receives to return EOF.

### 2.3 Possible Differences from Older F-Stack

Issue #631 was submitted in 2021, when F-Stack likely used FreeBSD 11.0 (speculated, no version info provided). Possible causes:
1. Older `soreceive_dgram` check for `SBS_CANTRCVMORE` was incomplete
2. Older `soshutdown` logic differed from 15.0 (15.0 fully delegates to `pr_shutdown`)
3. Older F-Stack's `p_osrel` handling may have been different

## 3. Fix Plan

**No fix needed.** In the current F-Stack 1.26 + FreeBSD 15.0 codebase, `ff_shutdown(SHUT_RD)` works correctly on UDP sockets.

## 4. Code Evidence List

| Step | File:Line | Verified Content |
|------|-----------|-----------------|
| ff_shutdown | lib/ff_syscall_wrapper.c:1862 | Calls sys_shutdown |
| kern_shutdown | freebsd/kern/uipc_syscalls.c:1349 | ENOTCONN→0 conversion |
| soshutdown | freebsd/kern/uipc_socket.c:3679 | Delegates to pr_shutdown |
| udp_shutdown | freebsd/netinet/udp_usrreq.c:1768 | sorflush executed regardless of ENOTCONN |
| sorflush | freebsd/kern/uipc_socket.c:3707 | Calls socantrcvmore |
| socantrcvmore_locked | freebsd/kern/uipc_sockbuf.c:398 | Sets SBS_CANTRCVMORE (called by socantrcvmore) |
| soreceive_dgram | freebsd/kern/uipc_socket.c:3537 | Checks SBS_CANTRCVMORE, returns 0 |
| P_OSREL | freebsd/sys/param.h:100 | P_OSREL_SHUTDOWN_ENOTCONN=1100077 |
