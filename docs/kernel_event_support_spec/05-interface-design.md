# 05 Interface Design: Single API + Marker-Based Selection + config default switch Contracts

> **Document ID**: SPEC-KE-05
> **Version**: v3 (paradigm-correction rework)
> **Date**: 2026-06-15
> **Status**: Drafting
> **Scope**: Stack-selection marker convention, the config.ini switch, client/server usage contracts, dual-mode adaptation, data structures, and error handling.
> **Core principle**: **do not add a new `ff_local_*` dual API**; reuse F-Stack's existing single API (the hook POSIX suite + the native `ff_*` suite), selecting the stack by **markers + config**, with the glue layer auto-adapting.
> **Basis**: `02` (code current state), `04` (architecture). Line numbers are subject to the code; in the implementation phase, the gatekeeper's re-verification is authoritative.

---

## 1. Interface Baseline (all reused, not rebuilt)

| Category | Reused interface | Source |
|---|---|---|
| hook mode (LD_PRELOAD) | standard POSIX `socket/bind/listen/accept/connect/close/epoll_*` (taken over by `ff_hook_*`) | `adapter/syscall/ff_hook_syscall.c` |
| native mode | `ff_socket/ff_bind/ff_listen/ff_accept/ff_connect/ff_close/ff_kqueue/ff_kevent` | `lib/ff_api.h:81,89,90,91,93,94,138,139` |
| kernel-side wrappers | `ff_linux_socket/bind/listen/accept/connect/close/epoll_*` | `ff_linux_syscall.c:81,88,96,131,144,217,233,239,247` |

> This feature **adds no new socket/epoll API**; it only standardizes the two conventions "stack-selection marker" and "config default switch" + adds marker recognition in native mode.

---

## 2. Stack-Selection Marker Convention (the only selection method in v3, standardizing existing markers)

### 2.1 Marker definitions (reused, promoted to an external convention)
```c
/* From adapter/syscall/ff_adapter.h:7-8; v3 standardizes them into an externally-reliable convention */
#define SOCK_FSTACK 0x01000000   /* this socket goes to the F-Stack user-space stack */
#define SOCK_KERNEL 0x02000000   /* this socket goes to the host Linux kernel stack (locally direct-accessible / can connect to local or external kernel services) */
```
- The markers are superimposed on the high bits of the standard `type` and do not conflict with glibc's `SOCK_STREAM/DGRAM/NONBLOCK/CLOEXEC`.
- **Semantics and priority (measured `ff_hook_socket:387`)**: `(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)` → kernel stack; otherwise → F-Stack (default). That is, **`SOCK_FSTACK` takes priority over `SOCK_KERNEL`** (when both are set, it goes to F-Stack).

### 2.2 Usage (the application uses only the single API + markers)
```c
/* server goes to the kernel stack (local curl/ssh can directly access) */
int s = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);   /* hook mode */
bind(s, ...); listen(s, backlog);                         /* the glue auto-lands on the kernel stack by fd ownership */

/* business goes to F-Stack (default, no marker needed, or explicit SOCK_FSTACK) */
int f = socket(AF_INET, SOCK_STREAM, 0);

/* client connects to local/external kernel services via the kernel stack (FR-3/FR-4) */
int c = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
connect(c, (struct sockaddr*)&srv, sizeof(srv));          /* ff_hook_connect:858 goes to ff_linux_connect by ownership */
```

---

## 3. config.ini Global Default Switch (newly added, mimicking the `[kni]` paradigm)

### 3.1 Config item (design draft)
```ini
[stack]
# this process's default protocol stack: fstack (default) | kernel
default_stack = fstack
```
- Parsing landing point: `lib/ff_config.c` `ini_parse_handler` (:956) adds a branch `MATCH("stack","default_stack")` (mimicking `MATCH("kni","enable")` :1011).
- Struct landing point: `struct ff_config` (`ff_config.h:253`) adds a nested section:
```c
struct {
    int default_to_kernel;   /* 0=F-Stack (default), 1=kernel stack */
} stack;
```
- Default value: `default_to_kernel = 0` (default-section setting at `ff_config.c:1358+`).

### 3.2 Priority and override
- `stack = app_marker(SOCK_KERNEL/SOCK_FSTACK) ?? config.default_stack ?? F-Stack`.
- **The app marker always overrides the config default**; when no marker is set, the config default applies; when config is also unset, the built-in F-Stack applies.

### 3.3 Multi-process differentiation
- Each process sets the default stack independently via its own config.ini (`ff_config.filename:254`, `ff_load_config` `ff_config.h:347`) — **process-level differentiation via different config files, no thread-level selection needed** (`02 §4`/NFR-6).

---

## 4. Dual-Mode Adaptation Contract

| Mode | Current marker-selection state | v3 contract |
|---|---|---|
| **hook mode (LD_PRELOAD)** | **Already supported** (`ff_hook_socket:387-390`, `ff_hook_connect:858`, `ff_hook_epoll_create:1981`) | Directly reuse; add the config default injection (when no marker is set, inject the equivalent `SOCK_KERNEL` per `default_to_kernel`) |
| **native `ff_api` mode** | **Not supported**: `ff_socket:913` via `linux2freebsd_socket_flags:668` (handles only NONBLOCK/CLOEXEC) always creates an F-Stack socket (`02 §5`/D4) | Add a `SOCK_KERNEL` recognition branch at the `ff_socket` entry, mimicking hook → route to the equivalent kernel-socket path; keep a single API, add no API |

> The implementation phase must guarantee: under both modes, when "no marker set + default F-Stack", the behavior is **byte-for-byte identical** to before the change (NFR-1).

---

## 5. Key Data Structures (design draft)

```c
/* config section (newly added to struct ff_config) */
struct { int default_to_kernel; } stack;

/* fd ownership enum (aligned with the existing is_fstack_fd, just documenting the semantics) */
enum ff_stack_owner { FF_OWNER_FSTACK = 0, FF_OWNER_KERNEL = 1 };

/* unified epoll fd → kernel epoll fd mapping: reuse fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES=65536]
   (ff_hook_syscall.c:257-258), no new container */
```

---

## 6. Observability (NFR-4)

```c
/* design draft: reuse/extend the adaptation-layer statistics (no new external socket API) */
struct ff_stack_stats { uint64_t kernel_fds, fstack_fds, kernel_events, fstack_events; };
int ff_stack_get_stats(struct ff_stack_stats *out);   /* naming fixed in the implementation phase */
```

---

## 7. Compatibility Matrix

| Dimension | Value | Notes |
|---|---|---|
| DPDK | 23.11.5 / 24.11.6 | Does not depend on the removed `rte_kni` |
| Mode | hook (full) / native (add marker recognition) | See §4 |
| Direction | server (listener accessed) / client (connect to local/external kernel service) | FR-1~FR-4 |
| Events | external epoll / F-Stack internal kqueue | smoothed at the interface layer |
| Default state | no marker set + `default_stack=fstack` | equivalent to pure F-Stack (NFR-1) |
| Protocols | TCP/UDP/ICMP (the kernel side handled by the kernel stack) | ping via the kernel stack |

---

## 8. Error-Handling Conventions

| Scenario | Behavior |
|---|---|
| `type` has both `SOCK_KERNEL` and `SOCK_FSTACK` set | Goes to F-Stack per the measured priority (`ff_hook_socket:387` condition not satisfied); documented explicitly |
| `maxevents < 2` | Return `-EINVAL` (per `:2212-2218`) |
| Kernel-side socket/connect failure | Return the native `errno`, no silent fallback to F-Stack |
| Client fd ownership does not match the destination address's stack | The corresponding stack returns a standard error (e.g., a kernel fd connecting to an address only reachable via F-Stack → kernel-stack `connect` failure errno), no cross-stack redirection |
| Kernel/F-Stack address-port conflict | Return `-EADDRINUSE`, raise an explicit error |
| Closing an fd | Linked release of both stacks' resources (`:1874-1883`), avoiding leaks (FR-8) |
| Before the native-mode marker recognition enhancement | `ff_socket` ignores `SOCK_KERNEL` and is always F-Stack (`02 §5`); a documentation warning is needed until the enhancement |

---

## 9. Open Questions
- The config section naming (`[stack] default_stack` vs merging into `[dpdk]`) and the value table (`fstack`/`kernel`).
- The native-mode marker recognition enhancement landing point (`ff_socket` entry branch vs a separate wrapper), which must guarantee zero overhead on the default path.
- Whether to provide an "explicit kernel-stack convenience wrapper" externally (e.g., a macro `FF_SOCK_KERNEL(type)`) to improve readability, still within the single-API scope.
- The statistics interface naming and export location.

> This document is a v3 design-contract draft; naming/signatures are confirmed in the implementation milestones (`06`); referenced line numbers are subject to the code.
