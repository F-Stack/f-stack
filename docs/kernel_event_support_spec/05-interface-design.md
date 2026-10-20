# 05 Interface Design: Automatic Dual-Stack Contracts + marker semantics + config + connect draft + exception matrix

> **Document ID**: SPEC-KE-05
> **Version**: v6 (native automatic dual-stack coexistence paradigm)
> **Date**: 2026-06-17
> **Status**: Drafting (v6 design)
> **Authoritative full text**: `zh_cn/05-interface-design.md`. On conflict, code is authoritative.

> **v6 sync (key points; see `zh_cn/05-interface-design.md` for full detail)**:
> - **Marker semantics (v6 = single-stack override of default dual-stack)**: no marker → dual-stack (build F-Stack + kernel, return F-Stack raw fd, `map[fstack]=host`); `SOCK_KERNEL` (and not `SOCK_FSTACK`) → kernel only (encode, no map); `SOCK_FSTACK` → F-Stack only (no map). `SOCK_FSTACK` wins (`ff_socket:929`). Priority: marker > auto dual-stack (kernel_coexist on) > F-Stack.
> - **Per-`ff_*` dual-drive contracts (v6)**: `ff_socket:915-947` (default dual-build), `ff_bind:1607-1627` (`kern_bindat` then `ff_host_bind(map[s], raw linux addr)`), `ff_listen:1584-1605` (`sys_listen` then `ff_host_listen(map[s],backlog)`), `ff_close:1095-1112` (`kern_close` then `ff_host_close(map[fd])`+`ff_native_map_clear`), `ff_setsockopt:999`/`ff_fcntl:1495` (sync both stacks). recv/send/read/write/recvfrom/sendto are single-stack-only by `ff_is_kernel_fd` (hot path, NOT consulting the map, NFR-2).
> - **`ff_native_fd_map` accessors (v6 to-be-implemented)**: `ff_native_map_get/set/clear`; `static int ff_native_fd_map[FF_MAX_FREEBSD_FILES]`(=65536) in `ff_host_interface.c`, lock-free.
> - **§accept (Q3=A)**: dual-stack listen `ff_accept` → `kern_accept` first; on success return F-Stack raw conn fd; EAGAIN → `ff_host_accept(map[s])` → encode; both EAGAIN → EAGAIN. Listen socket must be non-blocking.
> - **§connect (Q2=B, DRAFT, PENDING USER CONFIRMATION)**: dual-stack `ff_connect` connects on both stacks (`kern_connectat` + `ff_host_connect(map[s])`), returns F-Stack-primary (EINPROGRESS); data path F-Stack-primary, kernel concurrent for dual-network reachability; close tears down both. Exception matrix in `zh_cn/05 §6bis`. Use `SOCK_KERNEL` for pure-kernel client; kernel-primary/failover future.
> - **Partial-build failure**: F-Stack ok but `ff_host_socket` fails → contract (degrade to F-Stack-only / rollback, no leak) to be finalized at R7.
> - **D2-D6** retained from v5 (config parse `ff_config.c:1027-1031`/`:1363`; no `default_stack`; bridge `unsigned int` vs `socklen_t`; stats NOT implemented; `FF_KERNEL_FD_BASE` offset + `ff_epoll_pairs[64]`).
>
> **R9 sync (key points; see `zh_cn/05-interface-design.md §3ter` for full detail)**:
> - **`ff_kqueue/ff_kevent` coexistence contract**: `ff_kqueue` (coexist on) returns the F-Stack kqueue fd; first `ff_kevent` lazily pairs a host epoll (reuse `ff_epoll_host_ep`). `ff_kevent` changelist — ident being kernel/dual-stack fd, EV_ADD/EV_DELETE → `ff_host_epoll_ctl` (`EVFILT_READ↔EPOLLIN`/`EVFILT_WRITE↔EPOLLOUT`, `data`=app-side fd); kernel-only changes not sent to F-Stack kqueue. eventlist — first `ff_host_epoll_wait(timeout=0)` → synthesize `struct kevent` (`ident` restored from app fd, `filter`=READ/WRITE, `EV_EOF`↔`EPOLLHUP|ERR`), then `ff_kevent_do_each`, merge counts. kqueue-fd `ff_close` clears `ff_epoll_pairs` + closes host_ep.
> - **IPv6 V6ONLY contract**: host IPv6 socket `setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 1)` → IPv6-only, coexists with host IPv4 on the same port. best-effort; host bind failures stay diagnosable; only affects the host socket (not `SOCK_KERNEL` IPv6 / F-Stack path).
> - **Known limits (R9)**: `ff_kevent` kernel fd supports only `EVFILT_READ/WRITE` (kernel side via host epoll = `EPOLLIN/EPOLLOUT`); non-READ/WRITE filters on kernel fds do NOT coexist via host epoll (stay F-Stack kqueue). `ff_readv/writev/ioctl` keep the D8 known limitation in R9 (collected by R10 below).
>
> **R10 sync (key points; see `zh_cn/05-interface-design.md §3quater` for full detail)**:
> - **Per-`ff_*` R10 contracts (impl landed, compiles, macro-off zero regression verified; actual line numbers)**: `ff_readv:1189`/`ff_writev:1251` kernel fd → `ff_host_readv/writev(real, iov, iovcnt)` (single-stack, NOT dual-driven, mimic read/write); `ff_ioctl:1067` kernel fd → `ff_host_ioctl(real, raw-Linux-request, argp)` (NOT via `linux2freebsd_ioctl`; **dual-stack fd same-driver added in R10.1** — `FIONBIO`/`FIOASYNC` synced to the paired host fd; query ioctls like `FIONREAD` not forwarded); `ff_dup:2130` kernel fd → `ff_host_dup(real)`+encode; `ff_dup2:2156` both-kernel → `ff_host_dup2`+encode, **cross-stack rejected errno=EINVAL**.
> - **select/poll (D15)**: `ff_select:1879` & `ff_poll:1903` both **NOT implemented (comment only)** — `select` hard limit (encode kernel fd ≫ `FD_SETSIZE`=1024); `poll` conservative downgrade (merge complexity/regression risk). Use `ff_epoll_*`/`ff_kqueue` (R9) for kernel-fd multiplexing.
> - **ioctl request contract**: kernel host fd MUST use the raw Linux request (`_IO/_IOR/_IOW(type,nr,size)` differs Linux vs FreeBSD); `va_arg` for `argp` unchanged. **dup2 cross-stack errno=EINVAL** (both fds valid but semantics ill-defined, not EBADF). New host bridges `ff_host_readv/writev/ioctl/dup/dup2` at `ff_host_interface.h:178-184`.
>
> **Scope**: marker semantics, per-`ff_*` dual-stack/dual-drive contracts, `ff_native_fd_map` accessors, config switch, connect draft, exception matrix.
> **Core principle**: **do not create a side API**; reuse the single native `ff_*` API, default dual-stack + marker single-stack override + runtime config switch, F-Stack always present.
> **Basis**: `02` (code), `04` (architecture). Line numbers subject to the code; v6 new contracts are to-be-implemented (D9).

---

## 1. Interface Baseline (all reused, not rebuilt)

| Category | Reused interface | Source |
|---|---|---|
| hook mode (LD_PRELOAD + FF_KERNEL_EVENT) | POSIX `socket/bind/listen/accept/connect/close/epoll_*` (taken over by `ff_hook_*`) | `adapter/syscall/ff_hook_syscall.c` |
| native mode | `ff_socket/ff_bind/ff_listen/ff_accept/ff_connect/ff_close/ff_kqueue/ff_kevent`, `ff_epoll_*` | `lib/ff_api.h`, `lib/ff_epoll.c` |
| kernel-side wrappers | hook: `ff_linux_*` (`ff_linux_syscall.c`); native: via the `ff_host_interface` managed bridge (added this round) | `ff_linux_syscall.c` / `ff_host_interface.c` |

> This feature **adds no new socket/epoll API**; it only standardizes the two conventions "selection marker" and "config coexistence switch", and completes the native-mode managed kernel fd + unified events.

---

## 2. Stack-Selection Marker Convention (per-fd, default F-Stack)

```c
/* From adapter/syscall/ff_adapter.h:7-8, standardized into an external coexistence convention */
#define SOCK_FSTACK 0x01000000   /* this socket uses the F-Stack user-space stack (default) */
#define SOCK_KERNEL 0x02000000   /* this socket uses the host Linux kernel stack (requires coexistence enabled) */
```
- Superimposed on the high bits of `type`, not conflicting with glibc `SOCK_*`.
- Semantics/priority (measured `ff_hook_socket:387`): `(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)` → kernel; otherwise → F-Stack. **`SOCK_FSTACK` takes priority.**

### Usage (same-process dual-stack coexistence)
```c
/* Business listener on F-Stack (default, no marker needed) */
int biz = socket(AF_INET, SOCK_STREAM, 0);          /* or |SOCK_FSTACK */
bind(biz, ...); listen(biz, backlog);                /* serve business via the DPDK NIC */

/* Same process: kernel-stack listener (local curl/ssh reachable) */
int mgmt = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
bind(mgmt, ...); listen(mgmt, backlog);              /* lands on the kernel stack */

/* Kernel-stack client connect to local/external kernel services (FR-4/FR-5) */
int c = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
connect(c, (struct sockaddr*)&srv, sizeof(srv));     /* by fd ownership → kernel */

/* A single epoll receives biz / mgmt / c events together (unified events) */
```

---

## 3. config.ini Coexistence-Capability Switch (weakened, does not change default semantics)

### 3.1 Config item (design draft)
```ini
[stack]
# Whether to enable kernel-stack coexistence: 0=disabled (pure F-Stack),
# 1=enabled (allow per-fd SOCK_KERNEL to use the kernel stack).
# Note: when enabled, the default per-fd semantics is still F-Stack; only a
# socket explicitly carrying SOCK_KERNEL uses the kernel stack.
# There is NO "whole-process default-to-kernel" option (that would bypass F-Stack).
kernel_coexist = 0
```
- Parsing landing point: `lib/ff_config.c ini_parse_handler:956` adds `MATCH("stack","kernel_coexist")` (mimicking `MATCH("kni","enable") :1011`).
- Struct landing point: `struct ff_config` (`ff_config.h:253`) nested section:
```c
struct {
    int kernel_coexist;   /* 0=disabled(default), 1=enable kernel-stack coexistence */
} stack;
```
- Default value: `kernel_coexist = 0` (default section in `ff_config.c`).
- **Difference from v3**: the `default_stack`(fstack/kernel) and `default_to_kernel` "whole-process default-to-kernel" semantics are removed.

### 3.2 Relationship with hook mode
- Hook-mode coexistence is decided by the compile macro `FF_KERNEL_EVENT` (README). `[stack] kernel_coexist` mainly serves the **native mode**'s runtime enablement and provides a unified capability-switch semantics; the hook-layer `ff_global_cfg` is a stub (`ff_hook_syscall.c:31` "Just for so, no used"), so the hook mode is still governed by the compile macro (faithfully recorded).

### 3.3 Multi-process differentiation
- Each process sets `kernel_coexist` independently via its own config.ini (`ff_config.filename:254`) — multi-process relies on different config files, no thread-level needed (NFR-6).

---

## 4. Dual-Mode Adaptation Contract

| Mode | Current coexistence state | v4 contract |
|---|---|---|
| **hook (LD_PRELOAD + FF_KERNEL_EVENT)** | **Already supported** (`ff_hook_socket:387-390`, `ff_hook_connect:858`, epoll merge `:2324+`) | **Solidify as the primary baseline**, re-verify + a correct same-process dual-stack demo; behavior unchanged |
| **native `ff_api`** | **Not supported**: `ff_socket` always creates an F-Stack socket, `ff_epoll.c` is pure kqueue (`02 §4`/D3) | **New unified-event coexistence design**: `ff_socket(SOCK_KERNEL)` creates a managed kernel fd (via `ff_host_interface`, registered for ownership); `ff_bind/listen/accept/connect/close/epoll_ctl` route by ownership; `ff_epoll_wait` merges kqueue⊕kernel epoll; default/`SOCK_FSTACK` zero regression |

> The implementation must guarantee: under both modes, "coexistence not enabled / default / `SOCK_FSTACK`" is **byte-for-byte identical** to before the change (NFR-1), and the F-Stack business plane is always present (NFR-3).

---

## 5. Key Data Structures (design draft)

```c
/* config section (added to struct ff_config) */
struct { int kernel_coexist; } stack;

/* native-mode fd ownership (new; mimics hook fstack_kernel_fd_map / nginx ngx_max_sockets offset) */
enum ff_stack_owner { FF_OWNER_FSTACK = 0, FF_OWNER_KERNEL = 1 };
/* Managed kernel fd scheme: a kernel fd is returned as host_fd + FF_KERNEL_FD_BASE
   (0x40000000), above the FreeBSD fd range, so no collision. Raw kernel fds are
   never exposed to the application for bypass. */
```

---

## 6. Observability (NFR-5)

```c
/* design draft: per-stack fd-count/event-count statistics (no new external socket API) */
struct ff_stack_stats { uint64_t fstack_fds, kernel_fds, fstack_events, kernel_events; };
int ff_stack_get_stats(struct ff_stack_stats *out);   /* naming fixed in the implementation phase */
```

---

## 7. Compatibility Matrix

| Dimension | Value | Notes |
|---|---|---|
| DPDK | 23.11.5 / 24.11.6 | Does not depend on the removed `rte_kni` |
| Mode | hook (FF_KERNEL_EVENT solidified) / native (unified-event coexistence added) | See §4 |
| Direction | server + client | FR-2~FR-5 |
| Default state | coexistence not enabled / no marker | equivalent to pure F-Stack (NFR-1) |
| Business plane | always F-Stack | NFR-3 |
| `kern.maxfiles` | ≤ 65536 | hook fd-mapping prerequisite (README note 1) |

---

## 8. Error-Handling Conventions

| Scenario | Behavior |
|---|---|
| `type` has both `SOCK_KERNEL`+`SOCK_FSTACK` | Goes to F-Stack per priority (`ff_hook_socket:387` not satisfied); documented |
| coexistence off but `SOCK_KERNEL` set (native) | Return an error (e.g., `-EINVAL`/`-EOPNOTSUPP`) or degrade to F-Stack per documentation, pick one and state it; **must not** silently bypass |
| hook `maxevents < 2` | Return `-EINVAL` (`:2212-2218`) |
| Kernel-side socket/connect failure | Return the native `errno`, no silent fallback |
| Kernel/F-Stack address-port conflict | Return `-EADDRINUSE` |
| Closing an fd | Linked release of the corresponding stack's resources (hook `:1874-1883`; native added this round), no leak (FR-8) |

---

## 9. Open Questions
- The config switch naming (`kernel_coexist` vs other) and default value (default off).
- The fd-space distinction between native managed kernel fds and F-Stack fds (encoded offset / ownership table).
- The kernel-event throttling strategy of the `ff_epoll_wait` merge (mimic hook `:2324+` timeout=0+throttle).
- The statistics interface naming and export location.

> This document is a v4 design-contract draft; naming/signatures are confirmed in the `06` milestones; referenced line numbers are subject to the code.
