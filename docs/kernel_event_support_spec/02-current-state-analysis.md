# 02 Current-State Analysis: F-Stack's Existing "Single API + Marker-Based Stack Selection" Mechanism (code is authoritative)

> **Document ID**: SPEC-KE-02
> **Version**: v3 (paradigm-correction rework)
> **Date**: 2026-06-15
> **Status**: Drafting
> **Scope**: Empirically measure the existing mechanism in F-Stack for "using markers/config to route a certain fd to the host kernel stack", to serve as the **direct reuse baseline** for the v3 lib (rather than building another dual API). Covers: stack-selection markers, hook-mode single-API selection, the client connect path, config.ini parsing, native ff_api mode differences, and dual-stack event merging.
> **Iron rule**: every assertion carries `relative-path:line` (relative to `/data/workspace/f-stack/`); on conflict with docs/README/comments, **code is authoritative** and explicitly noted.

---

## 0. v3 Current-State Positioning

| Existing capability | Location | Form | Role in v3 |
|---|---|---|---|
| **Single API + `SOCK_KERNEL`/`SOCK_FSTACK` marker-based selection** | `adapter/syscall/` (hook mode) | POSIX single API + type marker + glue auto-adaptation | **Directly reuse and standardize** (the v3 core paradigm) |
| **Dual-stack fd/event merging** | `adapter/syscall/` (`FF_KERNEL_EVENT`) | `fstack_kernel_fd_map` + dual-stack epoll | **Reuse** (unified events) |
| Connection-level selection (nginx) | `app/nginx-1.28.0/` | `belong_to_host` 1-bit + dual event backend | **Isomorphic corroboration** (proves the paradigm is feasible) |
| Native `ff_socket` selection | `lib/` (native mode) | Does not recognize stack-selection markers, always creates an F-Stack socket | **Difference**: native mode needs standardization enhancement (see §5) |

> KNI (`lib/ff_dpdk_kni.c` + `config.ini [kni]`) is **another independent "packet reinjection into the kernel" mechanism** and **is not part of this feature** (see `00`/`03`); not elaborated here.

---

## 1. Stack-Selection Markers (v3 core, measured)

`adapter/syscall/ff_adapter.h:5-8`:
```c
//#define SOCK_CLOEXEC  0x10000000
//#define SOCK_NONBLOCK 0x20000000
#define SOCK_FSTACK 0x01000000
#define SOCK_KERNEL 0x02000000
```
- `SOCK_FSTACK`/`SOCK_KERNEL` are **stack-selection markers** that the F-Stack adaptation layer attaches to the high bits of the `type` argument of the standard `socket()` (they do not conflict with glibc's real `SOCK_*` values).
- **This is exactly the "specific marker" that v3 wants to standardize**: the application does not need to call multiple API sets; it just sets the marker on `type` as needed to select the stack; if no marker is set, the default applies (hook mode defaults to F-Stack, see §2).

---

## 2. Hook Mode: Single API + Marker-Based Selection (the primary reuse baseline for v3)

### 2.1 Domain determination
`adapter/syscall/ff_hook_syscall.c:360` `fstack_territory(domain, type, protocol)`: first strips `SOCK_CLOEXEC/SOCK_NONBLOCK/SOCK_FSTACK/SOCK_KERNEL` (:363-366); only when `domain∈{AF_INET,AF_INET6}` and `type∈{SOCK_STREAM,SOCK_DGRAM}` does it belong to the F-Stack domain (:368-373), otherwise it returns 0 (→ kernel stack).

### 2.2 Selection core (`ff_hook_socket`)
`ff_hook_syscall.c:380` `ff_hook_socket(domain, type, protocol)`:
```c
if (unlikely(fstack_territory(domain, type, protocol) == 0))     /* :383 not the fstack domain → kernel */
    return ff_linux_socket(domain, type, protocol);
if (unlikely(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)) {     /* :387 explicitly select kernel */
    type &= ~SOCK_KERNEL;                                        /* :388 clear marker */
    return ff_linux_socket(domain, type, protocol);             /* :389 → kernel stack */
}
...
type &= ~SOCK_FSTACK;                                            /* :406 clear marker then create F-Stack socket */
```
- Comment `:376-378`: "APP need set type |= SOCK_FSTACK".
- **Conclusion**: defaults to F-Stack; with `SOCK_KERNEL` (and no `SOCK_FSTACK`) → goes to the kernel stack. **A single `socket()` entry + a marker** completes stack selection, with the glue layer auto-adapting — v3 directly reuses this paradigm.

### 2.3 epoll uses the same paradigm
`ff_hook_syscall.c:1981` `ff_hook_epoll_create`: `(fdsize & SOCK_KERNEL) && !(fdsize & SOCK_FSTACK)` → `ff_linux_epoll_create` (:1982-1983), likewise selecting the kernel-side epoll by marker.

### 2.4 Subsequent operations auto-route by fd ownership
- fd ownership macro: `ff_hook_syscall.c:57-61` `CHECK_FD_OWNERSHIP(name, args)`: `if (!is_fstack_fd(fd)) return ff_linux_##name args;` — **a non-F-Stack fd directly falls through to the kernel `ff_linux_*`**.
- Ownership determination: `ff_hook_syscall.c:309` `is_fstack_fd(int sockfd)` (F-Stack fds are distinguished by an encoded offset; with companion `convert_fstack_fd`/`restore_fstack_fd`).
- The hook functions `bind/listen/accept/connect/recv/send/close`, etc., all split by ownership at their entry via `CHECK_FD_OWNERSHIP`: the marker at socket creation time **decides once** which stack all subsequent operations of that fd go to.

---

## 3. Client connect Stack-Selection Path (v3 newly added capability, measured)

`adapter/syscall/ff_hook_syscall.c:847-886` `ff_hook_connect(fd, addr, addrlen)`:
```c
CHECK_FD_OWNERSHIP(connect, (fd, addr, addrlen));   /* :858 non-fstack fd → ff_linux_connect */
...
SYSCALL(FF_SO_CONNECT, args);                        /* :881 otherwise go to F-Stack connect */
```
- **Key fact**: `connect` is **routed purely by fd ownership**, not by the destination address. That is:
  - If the socket was created with `SOCK_KERNEL` (or under a "default kernel stack" config) → it is a kernel fd → `connect` goes to `ff_linux_connect` (`ff_linux_syscall.c:144`) → **can connect to local `127.0.0.1`/host kernel-stack IP and any external kernel-stack service**.
  - If it is an F-Stack fd → `connect` goes to the F-Stack stack (via the DPDK NIC).
- **v3 client usage (derived from the code, feasible)**: for an F-Stack application acting as a client to connect to a kernel-stack service (local or external), it only needs to route that socket to the kernel stack (hook mode: `socket(AF_INET, SOCK_STREAM|SOCK_KERNEL, 0)`; or in a config.ini default-kernel-stack process, directly `socket(...)`), after which `connect()` automatically goes to the kernel stack. **This is two directions of the same marker mechanism as server-side selection.**

---

## 4. config.ini Parsing Layer (the landing point of the v3 global default switch, measured)

- Parsing entry: `lib/ff_config.c:956` `ini_parse_handler(user, section, name, value)`; matching macro `:963` `#define MATCH(s,n) strcmp(section,s)==0 && strcmp(name,n)==0`.
- Existing section paradigm (to mimic): the `[dpdk]` section `:964-1010`, **the `[kni]` section `:1011-1026`** (e.g., `MATCH("kni","enable") → pconfig->kni.enable=atoi(value)` :1011-1012).
- Config validation: `:1261+` (e.g., kni.method validity :1266-1281); default value setting: `:1358+`; string field freeing: `:1647+`.
- Config struct: `lib/ff_config.h:253` `struct ff_config`, containing anonymous nested sections `dpdk` (:255-308), **`kni` (:310-319)**, `log` (:321-325), `freebsd` (:327-334), `pcap` (:336-342); `extern struct ff_config ff_global_cfg;` (:345).
- **v3 landing point**: the new "global default-stack switch" should mimic the `[kni]` paradigm — add a nested section (e.g., `stack`, containing `int default_to_kernel;`) to `struct ff_config` + add a `MATCH("stack","default_stack")` branch in `ini_parse_handler` + a default value.
- **Multi-process model corroboration**: F-Stack has one instance per process, each holding its own config.ini (`struct ff_config.filename` :254; `ff_load_config` declared `ff_config.h:347`). Therefore "different processes use different default stacks" is realized by **different config files**, **without thread-level stack selection**.

---

## 5. The Marker Difference of the Native ff_api Mode (Important, measured, code is authoritative)

- Native entry: `lib/ff_syscall_wrapper.c:912-926` `ff_socket(domain, type, protocol)`:
```c
sa.type = linux2freebsd_socket_flags(type);   /* :918 */
... sys_socket(curthread, &sa);                /* :920 directly enter the FreeBSD stack */
```
- `linux2freebsd_socket_flags` (`:668-`) **only handles `LINUX_SOCK_NONBLOCK`/`LINUX_SOCK_CLOEXEC`** (:671-677), and **does not recognize `SOCK_FSTACK`/`SOCK_KERNEL`**.
- **Conclusion (code is authoritative)**: **native `ff_socket` always creates an F-Stack socket and does no marker-based selection**. That is, "single API + marker-based selection + glue auto-adaptation" **currently only holds in hook mode**; in native mode, selecting the kernel stack currently requires the application to call libc `socket()` itself.
- **v3 design implication**: to also give native mode "single API + marker-based selection", a **standardization enhancement** is needed in the native glue layer (mimicking `ff_hook_socket:387-390`, recognizing `SOCK_KERNEL` at the `ff_socket` entry → routing to the equivalent libc `socket`/`ff_linux_socket` path); this is implementation-phase work (see `05`/`06`). This phase faithfully records this difference as a v3 design point rather than an established fact.

---

## 6. Dual-Stack Event Merging (carried over and re-verified, measured)

`adapter/syscall/ff_hook_syscall.c`:
- Mapping table: `:257-258` `int fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES];` (`FF_MAX_FREEBSD_FILES=65536`).
- create mirrors the kernel epoll: `:1996-1998` (`fstack_kernel_fd_map[ret]`).
- ctl routes non-fstack fds: `:2016-2023`.
- wait merging (first take kernel events with `timeout=0` + throttle, then merge F-Stack events): `:2324+`; the `maxevents>=2` constraint `:2212-2218`.
- close linkage: `:1874-1883`.
- Kernel-side wrappers: `adapter/syscall/ff_linux_syscall.c` socket:81/bind:88/listen:96/accept:131/connect:144/close:217/epoll_create:233/epoll_ctl:239/epoll_wait:247.

---

## 7. Cross-Validation Difference List (docs/README/comments vs code)

| ID | Source | Code source | Actual conclusion |
|---|---|---|---|
| D1 | User statement "both existing modes support local socket access" | `ff_hook_socket:387-390`, `ff_hook_connect:858` | True (hook mode relies on marker-based selection, including client connect) |
| D2 | v2 spec mistakenly treated "creating a new `ff_local_*` dual API" as the solution | The hook layer is already single API + markers | The v2 direction is wrong; v3 changes to reusing the existing single API + markers |
| D3 | A comment in `ff_hook_syscall.c` says "the first version does not support `ff_linux_epoll_wait`" | `:2324+` actually already calls it | Code is authoritative: already called (with throttling) |
| D4 | The intuition that "native `ff_socket` also recognizes `SOCK_KERNEL`" | `ff_socket:918` + `linux2freebsd_socket_flags:668-677` | **Does not recognize**: native mode always creates an F-Stack socket; selecting the kernel stack needs the standardization enhancement (§5) |

---

## 8. Key Points for Writing 04/05/06

- **Marker standardization**: use `SOCK_KERNEL`/`SOCK_FSTACK` (`ff_adapter.h:7-8`) as the only stack-selection markers; hook mode reuses directly (`ff_hook_socket:387-390`), and native mode adds a recognition branch.
- **config.ini global default switch**: mimic `[kni]` (`ff_config.c:1011`/`ff_config.h:310-319`) to add `[stack] default_stack` + a `struct ff_config.stack` field; priority **app marker > config default**.
- **Client-side selection**: the marker/config at socket creation fixes the stack; `connect` (`ff_hook_connect:858`) auto-routes to kernel/F-Stack by fd ownership, covering connecting to local loopback / host IP / external kernel services.
- **fd ownership and events**: `is_fstack_fd:309` + `CHECK_FD_OWNERSHIP:57-61` auto-split; dual-stack events are merged via `fstack_kernel_fd_map` (§6).
- **Dual-mode coverage**: hook mode (fully holds) + native mode (needs the §5 standardization enhancement).
