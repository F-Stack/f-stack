# 02 Current-State Analysis: Existing Coexistence Mechanisms + v5 Landed Code + v6 Map Gap (code is authoritative)

> **Document ID**: SPEC-KE-02
> **Version**: v6 (native automatic dual-stack coexistence paradigm)
> **Date**: 2026-06-17
> **Status**: Drafting (v6 design)
> **Authoritative full text**: `zh_cn/02-current-state-analysis.md`. On conflict, code is authoritative.
> **Iron rule**: every assertion carries `relative-path:line` (relative to `/data/workspace/f-stack/`).

> **v6 sync (key points; see `zh_cn/02-current-state-analysis.md` for full detail with measured line numbers)**:
> - **v5 state (landed + macro-wrapped)**: `lib/` implements per-fd either/or coexistence, all wrapped by `#ifdef FF_KERNEL_COEXIST` (R6, ba148589d). managed kernel fd = host fd + `FF_KERNEL_FD_BASE` 0x40000000 (`ff_host_interface.h:113-128`); 18 `ff_host_*` bridges (`.h:137-159`); `ff_socket` kernel branch (`ff_syscall_wrapper.c:921-935`, default builds F-Stack only — NOT dual-built); 13 `ff_*` entry routes; `ff_epoll_pairs[64]` merge (`ff_epoll.c:37-39`, ctl `:99-115`, wait `:214-252`); config `kernel_coexist` (`ff_config.h:321-323` / `ff_config.c:1027-1031`,`:1363`); Makefile `:57-60`/`:174-177`.
> - **hook cross-reference**: `fstack_kernel_fd_map[65536]` (`ff_hook_syscall.c:258`, bare array, lock-free, single-threaded poll); epoll dual-build merge (create `:1990-2000`, wait `:2324+`, close linkage `:1871-1884`); **socket/listen are NOT dual-built**.
> - **native vs hook**: isomorphic (map / epoll merge / close linkage); divergent (socket/bind/listen/connect auto dual-build is v6-only).
> - **v6 map gap (D9, grep verified)**: `grep ff_native_fd_map / ff_native_map_get/set/clear lib/` → 0 hits; `FF_MAX_FREEBSD_FILES` only in `ff_hook_syscall.c:257` and these docs. The v6 native map and default dual-build/dual-drive are NOT yet landed — to-be-implemented at R7. v6 adds (HOST_CFLAGS, `#ifdef FF_KERNEL_COEXIST`): `static int ff_native_fd_map[FF_MAX_FREEBSD_FILES]` + `ff_native_map_get/set/clear` in `ff_host_interface.{c,h}`, lock-free (modeled on hook).
> - **D1-D8** code-doc inconsistencies fixed in §6 (D2 config parse line `:1027-1031` not `:956`; D3 no `default_stack`, `ff_api.h:91` comment stale; D4 header `unsigned int` vs impl `socklen_t`; D5 `ff_stack_get_stats` NOT implemented; D6 encode-offset + `ff_epoll_pairs`, not enum/ownership-table; D8 R8 adds kernel routing for `sendmsg/recvmsg/getpeername/getsockname/shutdown` (first four single-stack hot-route, shutdown kernel-route + dual-stack dual-drive); `ff_readv/writev/ioctl` were left unrouted (known limitation) — **now collected by R10 (kernel-fd routed), see the R10 sync block and D12-D15**).

> **R9 sync (key points; see `zh_cn/02-current-state-analysis.md §7` for full detail with measured evidence)**:
> - **R7 dual-stack events cover ONLY `ff_epoll_*`**. `ff_kqueue`/`ff_kevent`/`ff_kevent_do_each` have **NO FF_KERNEL_COEXIST routing/dual-register** (grep: only `ff_epoll.c` hits the macro; `ff_syscall_wrapper.c` `ff_kqueue/ff_kevent` have no coexistence branch — D10). An app using `ff_kqueue`+`ff_kevent` directly (e.g. `example/main.c`) **cannot perceive kernel-side connections**: measured kernel-side `curl 127.0.0.1:80` = http_code **000** (TCP handshake done, GET buffered and TCP-ACKed `ack 73`, but the app is never woken to `ff_accept`); same-process F-Stack side `9.134.214.176:80` = **200 size=438**. R9 to-be-implemented.
> - **IPv6 dual-build port conflict (D11)**: under `-DINET6`, default `ff_socket(AF_INET6)` dual-build → host IPv6 socket `ff_bind([::]:80)` with host `net.ipv6.bindv6only=0` (measured) also occupies IPv4 → conflicts with the same-process host IPv4 `0.0.0.0:80`. Measured **`ff_bind failed, sockfd6:1026, errno:98 EADDRINUSE`**, process exits / cannot start. host IPv6 socket lacks `IPV6_V6ONLY=1`. R9 to-be-implemented.
> - **R9 fix**: (P2) `ff_kqueue/ff_kevent` symmetrically mimic `ff_epoll` — reuse `ff_epoll_pairs[kq→host_ep]` lazy pairing + dual-register (changelist→`ff_host_epoll_ctl`, `EVFILT_READ↔EPOLLIN`/`EVFILT_WRITE↔EPOLLOUT`) + synthesize `struct kevent` from `ff_host_epoll_wait(timeout=0)` (`ident`=app-fd via `epoll_event.data`, `EV_EOF`↔`EPOLLHUP|ERR`) merged with `ff_kevent_do_each`; (P1) set `IPV6_V6ONLY=1` on the host IPv6 socket. Cross-validation: with bindv6only=0, `::` wildcard also binds IPv4; the standard fix is `IPV6_V6ONLY=1` (consistent across multiple references); F-Stack upstream epoll is a kqueue wrapper.

> **R10 sync (key points; see `zh_cn/02-current-state-analysis.md §7bis` for full detail with measured line numbers)**:
> - **Residual unrouted entries (R10 targets)**: of the 42 `ff_*` entries in `ff_syscall_wrapper.c`, `ff_readv`/`ff_writev`/`ff_ioctl` had **NO `FF_KERNEL_COEXIST` kernel-fd routing** (read/write do; `readv/writev/ioctl` were the `D8` known limitation). Additionally `ff_dup`/`ff_dup2`/`ff_select`/`ff_poll` also lacked coexistence routing. New diff IDs **D12** (readv/writev), **D13** (ioctl), **D14** (dup/dup2), **D15** (select/poll).
> - **R10 done (impl landed, compiles, macro-off byte-for-byte zero regression verified)**. Actual post-change line numbers: `ff_ioctl:1067`, `ff_readv:1189`, `ff_writev:1251`, `ff_select:1879` (comment only), `ff_poll:1903` (comment only), `ff_dup:2130`, `ff_dup2:2156`.
> - **D12 readv/writev**: kernel fd → `ff_host_readv/writev(ff_kernel_fd_real(fd), iov, iovcnt)` (mimic `ff_read`/`ff_write`); connection fds single-stack, hot path one `ff_is_kernel_fd` check, no map lookup (NFR-2).
> - **D13 ioctl**: kernel fd uses the **raw Linux request** passed straight to `ff_host_ioctl` (NOT via `linux2freebsd_ioctl`; `_IO/_IOR/_IOW(type,nr,size)` encodings differ between Linux and FreeBSD — cross-validated). Branch placed after `va_arg` for `argp`, before translation. **Dual-stack fd same-driver added in R10.1** (`FIONBIO`/`FIOASYNC` synced to the paired host fd after F-Stack success, mirroring `ff_fcntl`; query ioctls like `FIONREAD` not forwarded to avoid clobbering argp).
> - **D14 dup/dup2**: `ff_dup` kernel fd → `ff_host_dup(real)` returning a new encode fd (−1 if <0); `ff_dup2` both-kernel → `ff_host_dup2`+encode, **cross-stack (one kernel, one F-Stack) explicitly rejected errno=EINVAL** (both fds valid but semantics ill-defined), both-F-Stack keeps `sys_dup2`.
> - **D15 select/poll**: **both NOT implemented, downgraded to a documented limitation (comment only, logic unchanged)**. `ff_select`: encode kernel fd (≥0x40000000) ≫ `FD_SETSIZE`(1024), cannot fit in `fd_set` (hard limit). `ff_poll`: `pollfd.fd` can hold an encode fd but mixing a pure-kernel subset needs array split/index mapping/merged revents/timeout merge — high complexity & regression risk, conservatively downgraded. Use `ff_epoll_*`/`ff_kqueue` (R9 host-epoll bridge) for kernel-fd multiplexing.
> - **New host bridges (R10, `ff_host_interface.h:178-184`)**: `ff_host_readv/writev` (`ssize_t (int, const void*, int)`), `ff_host_ioctl` (`int (int, unsigned long, void*)`, raw Linux request), `ff_host_dup`/`ff_host_dup2`; `iov` passed as `void*` then cast `const struct iovec*` (same-ABI, mimic sendmsg/recvmsg); `.c` coexist-include block adds `sys/uio.h`, `sys/ioctl.h`.

---

## 0. v5 Current-State Positioning

| Existing capability | Location | Form | Role in v4 |
|---|---|---|---|
| **Hook-mode FF_KERNEL_EVENT dual-stack coexistence** | `adapter/syscall/` (LD_PRELOAD) | marker selection + `fstack_kernel_fd_map` dual-stack epoll merge | **Directly reuse and solidify as the primary baseline** |
| **nginx kernel_network_stack dual-stack coexistence** | `app/nginx-1.28.0/` | per-listen `belong_to_host` + dual event backends (kqueue+epoll) | **Reference (isomorphic proof that coexistence is feasible)** |
| Native `ff_api` event layer | `lib/ff_epoll.c` | pure kqueue wrapper, no kernel-fd awareness | **Gap**: native coexistence needs a new design (see §4) |
| Stack-selection markers | `adapter/syscall/ff_adapter.h:7-8` | `SOCK_FSTACK`/`SOCK_KERNEL` on `type` high bits | **Reused as per-fd coexistence markers** |

> KNI (`lib/ff_dpdk_kni.c` + `config.ini [kni]`) is another independent "packet reinjection" mechanism and **is not part of this feature** (see `00`/`03`).

---

## 1. Stack-Selection Markers (measured)

`adapter/syscall/ff_adapter.h:5-8`:
```c
//#define SOCK_CLOEXEC  0x10000000
//#define SOCK_NONBLOCK 0x20000000
#define SOCK_FSTACK 0x01000000
#define SOCK_KERNEL 0x02000000
```
- Superimposed on the high bits of `type` of the standard `socket()`, not conflicting with glibc's `SOCK_*` values.
- Default (no marker) → F-Stack; with `SOCK_KERNEL` (and no `SOCK_FSTACK`) → kernel stack. `lib/ff_api.h` already `#ifndef`-exposes these two macros (a correct v3 leftover, kept).

---

## 2. Hook Mode FF_KERNEL_EVENT: Dual-Stack Coexistence Primary Baseline (measured)

> The README (`adapter/syscall/README.md:169-186`) states: "This mode can support both F-Stack and the system kernel's socket interface at the same time." Enable: `Makefile` or `export FF_KERNEL_EVENT=1`. demo = `main_stack_epoll_kernel.c`.

### 2.1 Marker selection (app on F-Stack, business defaults to F-Stack)
`adapter/syscall/ff_hook_syscall.c`:
- `fstack_territory(domain,type,protocol)` `:360`: strips `SOCK_CLOEXEC/NONBLOCK/FSTACK/KERNEL` (:363-366); only `AF_INET/INET6`+`SOCK_STREAM/DGRAM` belong to the F-Stack domain.
- `ff_hook_socket` `:380`:
  ```c
  if (fstack_territory(...)==0) return ff_linux_socket(...);        /* :383-385 not the domain → kernel */
  if ((type & SOCK_KERNEL) && !(type & SOCK_FSTACK)) {             /* :387 explicit kernel */
      type &= ~SOCK_KERNEL; return ff_linux_socket(...);          /* :388-390 → kernel stack */
  }
  ... type &= ~SOCK_FSTACK;                                        /* :406 default → F-Stack business stack */
  ```
  Comment `:376-378`: "APP need set type |= SOCK_FSTACK". **Business defaults to F-Stack, per-fd `SOCK_KERNEL` goes to the kernel — the two coexist in the same process.**

### 2.2 fd ownership and subsequent routing
- `CHECK_FD_OWNERSHIP(name,args)` `:57-61`: `if(!is_fstack_fd(fd)) return ff_linux_##name args;` — a non-F-Stack fd falls through to the kernel.
- `is_fstack_fd(sockfd)` `:309`: F-Stack fds distinguished by an encoded offset (with `convert_fstack_fd`/`restore_fstack_fd`).
- The entries of `bind/listen/accept/connect/recv/send/close` all split by ownership via `CHECK_FD_OWNERSHIP`; the client `ff_hook_connect` `:847-886` (`:858` CHECK_FD_OWNERSHIP, `:881` `SYSCALL(FF_SO_CONNECT)`) routes purely by fd ownership.

### 2.3 Dual-stack unified events (the FF_KERNEL_EVENT core)
- Mapping table `:257-258` `int fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES];` (`=65536`).
- `ff_hook_epoll_create` `:1981`: selects the kernel epoll by `SOCK_KERNEL` (`:1982-1983`) and mirrors the kernel epoll fd (`:1996-1998` `fstack_kernel_fd_map[ret]`).
- ctl routes non-fstack fds `:2016-2023`; wait merges (first take kernel events with `timeout=0` + throttle, then merge F-Stack events) `:2324+` (`:2333-2336`); `maxevents>=2` `:2212-2218`.
- close linkage releases both stacks' fds `:1874-1883`.
- Kernel-side wrappers `adapter/syscall/ff_linux_syscall.c` (dlsym host libc): socket:81/bind:88/listen:96/accept:131/connect:144/close:217/epoll_create:233/epoll_ctl:239/epoll_wait:247.

> **Conclusion**: hook mode is already a complete coexistence implementation of "app on F-Stack + per-fd marker selection + dual-stack epoll merge"; v4 **solidifies it as the primary baseline** and adds a correct same-process dual-stack demo (the v3 demo was pure-kernel and wrong).

---

## 3. nginx kernel_network_stack: Dual-Stack Coexistence Reference (measured)

- Directive `src/http/ngx_http_core_module.c:298-303` (`NGX_HAVE_FSTACK`, `ngx_conf_set_flag_slot` → `offsetof(ngx_http_core_srv_conf_t, kernel_network_stack)`); field `ngx_http_core_module.h:206` `ngx_flag_t kernel_network_stack;`; merge default `0` (`:3540-3541`, comment `:3539` "By default, we set up a server on fstack"). stream/mail have the same implementation.
- Ownership landing: `src/http/ngx_http.c:1890` `ls->belong_to_host = cscf->kernel_network_stack;` (stream `ngx_stream.c:1049`).
- socket adds/skips `SOCK_FSTACK` by ownership: `ngx_ff_skip_listening_socket()` `src/core/ngx_connection.c:22-49` (worker non-kernel listen `*type |= SOCK_FSTACK` `:46`).
- **Dual event backends coexist**: F-Stack = kqueue primary backend `ngx_event_actions`; kernel = an independent Linux epoll backend `ngx_ff_host_event_actions` (`src/event/modules/ngx_ff_host_event_module.c:441`); `ngx_add_event/ngx_del_event` split by `ev->belong_to_host` (`src/event/ngx_event.h:408-424`); the event loop runs both stacks (`src/event/ngx_event.c:258-280`: first `ngx_process_events`(kqueue) then `ngx_ff_process_host_events`(epoll)).
- fd distinction: `convert/restore_fstack_fd` + `is_fstack_fd` (fd≥`ngx_max_sockets`, `src/event/modules/ngx_ff_module.c:147-167`).
- Ownership propagation: listen→event `ngx_event.c:889`; accept inherits `ngx_event_accept.c:236`; connect determines by fd `ngx_connection.c:1310` `is_fstack_fd(s)?0:1`.

> **Conclusion**: the nginx process as a whole runs on F-Stack (workers run DPDK+FreeBSD stack), a per-server `kernel_network_stack on` routes that server to the kernel stack, and dual event backends coexist in the same worker — fully isomorphic to the v4 "coexistence" paradigm, used as a reference.

---

## 4. The Native ff_api Mode's Event-Layer Gap (the v4 new-design landing point, measured)

- `lib/ff_epoll.c`: `ff_epoll_create(size)` `:25-28` = `return ff_kqueue();`; `ff_epoll_ctl` `:31-104` → `ff_kevent`; `ff_epoll_wait` `:148-158` → `ff_kevent_do_each`. **A pure F-Stack kqueue wrapper, no kernel-fd awareness.**
- Native entry `lib/ff_syscall_wrapper.c:912 ff_socket` → `linux2freebsd_socket_flags(type)` `:668-677` (only NONBLOCK/CLOEXEC, **does not recognize SOCK_KERNEL/SOCK_FSTACK**) → `sys_socket` always enters the FreeBSD stack.
- Native applications run the `ff_run(loop,arg)` (`ff_api.h:59`) DPDK main loop; events use `ff_kqueue/ff_kevent` (`ff_api.h:158-159`) or `ff_epoll_*`.
- **Gap conclusion**: native mode currently **cannot coexist** — there is no fd-ownership table, kernel-epoll mirror, or event merging; `ff_socket` always creates an F-Stack socket. To let native applications coexist over both stacks in one process, v4 must **add, inside lib, mimicking hook/nginx**: (a) fd-ownership registration; (b) `ff_socket(SOCK_KERNEL)` creating a **managed kernel fd** via `ff_host_interface` (registered for ownership, **not the v3 raw bypass**); (c) `ff_bind/ff_listen/ff_accept/ff_connect/ff_close/ff_epoll_ctl` routing by ownership to host syscalls; (d) `ff_epoll_wait` merging kqueue⊕kernel epoll. The default/`SOCK_FSTACK` path stays byte-for-byte unchanged. See `04`/`05`/`06`.

---

## 5. v3 Mistake Revert Check (reverted, commit 0748eff94)

| Item | v3 mistake | v4 handling |
|---|---|---|
| `lib/ff_syscall_wrapper.c` ff_socket | `SOCK_KERNEL→ff_host_socket` raw host socket (bypassing F-Stack) | **Reverted** to the clean F-Stack path |
| `lib/ff_host_interface.{c,h}` | `ff_host_socket`=raw `socket()`, `ff_default_stack_is_kernel` decl | **Reverted** |
| `example/helloworld_stacksel/` | pure kernel socket throughout, no F-Stack business | Rewritten in R2/R3 as a **same-process dual-stack** coexistence demo |
| `lib/ff_config.{c,h}` `[stack] default_stack` | whole-process default-to-kernel (anti-F-Stack) | Changed in R3 to a **coexistence-capability switch** (does not change the default per-fd F-Stack) |
| `10-perf-baseline-report` | based on a pure-kernel bench | Superseded / rewritten to "coexistence has no regression on the F-Stack fast path" |

---

## 6. Cross-Validation Difference List (docs/comments vs code)

| ID | Source | Code source | Actual conclusion |
|---|---|---|---|
| D1 | v3 mistakenly treated "ff_socket → raw kernel socket" as the solution | hook/nginx are both "app on F-Stack + kernel-fd coexistence" | The v3 direction is wrong; v4 changes to coexistence, F-Stack always present |
| D2 | The comment "the first version does not support ff_linux_epoll_wait" | `:2324+` actually already calls it (with throttling) | Code is authoritative: already called |
| D3 | Does native `ff_socket` recognize SOCK_KERNEL? | `:918`+`linux2freebsd_socket_flags:668-677` | Does not recognize, always creates an F-Stack socket; native coexistence needs the §4 new design |

---

## 7. Key Points for Writing 04/05/06

- **Primary baseline = hook FF_KERNEL_EVENT**: reuse marker selection (`ff_hook_socket:387-390`) + dual-stack epoll merge (`fstack_kernel_fd_map:257-258`/`:2324+`) + close linkage (`:1874-1883`); solidify and add a correct demo.
- **Reference = nginx kernel_network_stack**: per-listen switch + dual event backends (kqueue+epoll) coexisting in the same worker.
- **New design = native unified-event coexistence**: inside lib, fd ownership + managed kernel fd (`ff_host_interface` host socket, not a raw bypass) + `ff_epoll_wait` merging kqueue⊕epoll; default/`SOCK_FSTACK` zero regression.
- **config**: mimic `[kni]` to add a **coexistence-capability switch** (enable/disable kernel-stack coexistence), removing the whole-process default-to-kernel semantics.
- **Coexistence iron rule**: the F-Stack user-space stack always carries the business; the kernel stack is only an additional side path (NFR-3).
