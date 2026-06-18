# 06 Milestones and Coding Work List

> **Document ID**: SPEC-KE-06
> **Version**: v6 (native automatic dual-stack coexistence paradigm)
> **Date**: 2026-06-17
> **Status**: Drafting (R0-R6 done; R7 v6 auto dual-stack to-be-implemented)
> **Authoritative full text**: `zh_cn/06-milestones.md`.

> **v6 sync (key points; see `zh_cn/06-milestones.md` for full detail)**: R0-R6 done (revert / spec / hook solidify / native per-fd coexistence / tests+perf / compile-macro gating, ba148589d). New milestone **R7 native automatic dual-stack (v6)**: (a) add `ff_native_fd_map` + `ff_native_map_get/set/clear` (lock-free, modeled on adapter); (b) refactor `ff_socket` to default dual-build (marker single-stack override); (c) dual-drive `ff_bind/listen/close/connect/accept/setsockopt/fcntl`; (d) `ff_epoll_ctl/wait` register a dual-stack listen once on each stack + merge; (e) dual-mode cmocka (map / dual-build / accept ownership / event merge / connect dual-stack / zero-regression) + real-machine dual-stack (F-Stack 9.134.214.176:80 + kernel 127.0.0.1:80); (f) gate. All v6 code under `#ifdef FF_KERNEL_COEXIST`, macro-off zero regression (incl. no `ff_native_fd_map` symbols). **R7 done (gate PASS)**; **R8 done** (kernel routing for `sendmsg/recvmsg/getpeername/getsockname/shutdown`, D8).

> **R9 sync (key points; see `zh_cn/06-milestones.md §6bis` for full detail)**: New milestone **R9 kqueue coexistence + IPv6 V6ONLY** (this round's design; to-be-implemented). R7 dual-stack events cover only `ff_epoll_*`; the kqueue model (`example/main.c`) cannot perceive kernel-side connections (measured kernel-side `curl=000`). **6bis.1 (P2)**: `ff_syscall_wrapper.c` `ff_kqueue/ff_kevent/ff_kevent_do_each` mimic `ff_epoll` — reuse `ff_epoll_pairs`/`ff_epoll_host_ep`; changelist → `ff_host_epoll_ctl` (READ↔IN/WRITE↔OUT, `data`=app fd); eventlist → synthesize `struct kevent` from `ff_host_epoll_wait(timeout=0)` (EOF↔HUP|ERR) merged with `ff_kevent_do_each`; kqueue-fd close clears `ff_epoll_pairs`. **6bis.2 (P1)**: host IPv6 socket `setsockopt(IPV6_V6ONLY,1)` (placement decided by code measurement). **6bis.3**: all under `#ifdef FF_KERNEL_COEXIST`, macro-off byte-for-byte zero regression. **6bis.4 acceptance**: kqueue helloworld (coexist=1) kernel `curl 127.0.0.1:80=200 size=438` + F-Stack `9.134.214.176:80=200`; `-DINET6` helloworld starts (v4+v6 listen, no errno=98). Risk: kqueue/epoll share `ff_epoll_pairs` (independent kq per `ff_epoll_create`, low risk, still review); V6ONLY placement measured.

> **R10 sync (key points; see `zh_cn/06-milestones.md §6ter` for full detail)**: New milestone **R10 residual-entry coexistence completion** (impl landed, compiles, macro-off zero regression verified; real-machine/UT pending). **6ter.1** new host bridges `ff_host_readv/writev/ioctl/dup/dup2` (`ff_host_interface.c`, decl `.h:178-184`; `iov` as `void*`, `.c` adds `sys/uio.h`/`sys/ioctl.h`). **6ter.2 (D12)**: `ff_readv:1189`/`ff_writev:1251` kernel fd → `ff_host_readv/writev(real,...)` (mimic read/write, single-stack hot path). **6ter.3 (D13)**: `ff_ioctl:1067` kernel fd → `ff_host_ioctl(real, raw-Linux-request, argp)` (after `va_arg`, before `linux2freebsd_ioctl`); dual-stack fd same-driver added in R10.1 (`FIONBIO`/`FIOASYNC` synced to paired host fd). **6ter.4 (D14)**: `ff_dup:2130` → `ff_host_dup`+encode; `ff_dup2:2156` both-kernel → encode, cross-stack rejected errno=EINVAL. **6ter.5 (D15)**: `ff_select:1879`/`ff_poll:1903` both NOT implemented, downgraded to documented limitation (select = `FD_SETSIZE` hard limit; poll = merge complexity), comment only. **6ter.6**: all under `#ifdef FF_KERNEL_COEXIST`, macro-off byte-for-byte zero regression, host-bridge count 18→23. **6ter.7 acceptance**: UT host-bridge + route + zero-regression; real-machine kernel-fd readv/writev/ioctl correct + kernel 200 + F-Stack 200 no regression.

---

## 0. Milestone Overview

| Milestone | Name | Goal | Dependency | Main acceptance |
|---|---|---|---|---|
| **R0** | revert wrong code | revert the v3 F-Stack-bypassing `ff_host_socket`/`ff_socket` side path | — | compile + unit tests no regression (done, commit 0748eff94) |
| **R1** | full spec rewrite (**this phase**) | rewrite the Chinese & English spec to the "coexistence" paradigm | R0 | `08-review-gate.md` PASS |
| **R2** | hook-mode coexistence solidification + correct demo | build with FF_KERNEL_EVENT; a same-process F-Stack business + SOCK_KERNEL kernel coexistence demo | R1 | FR-1/FR-2/FR-6 (hook) |
| **R3** | native ff_api unified-event coexistence | lib-internal fd ownership + managed kernel fd + `ff_epoll_wait` merge; config coexistence switch | R1 | FR-7/FR-9/NFR-1/NFR-3 |
| **R4** | tests and performance baseline | unit / integration (same-process dual-stack) / performance (no regression on the F-Stack fast path) | R2,R3 | `07-test-spec.md` gate |
| **R5** | gate + commit | gatekeeper verification + English spec sync + short English commit | R1-R4 | all gates PASS |

> **Coexistence iron rule**: every milestone must ensure the F-Stack user-space stack always carries the business and is never bypassed (NFR-3).

---

## 1. R0 Revert Wrong Code (done)
- `lib/ff_syscall_wrapper.c` `ff_socket`: revert the `SOCK_KERNEL→ff_host_socket` side-path branch → clean F-Stack path.
- `lib/ff_host_interface.{c,h}`: remove `ff_host_socket`, the `ff_default_stack_is_kernel` declaration, and the extra include.
- Acceptance: lib compiles (`-Werror`), `test_ff_config` 54/54 no regression. commit `0748eff94`.

## 2. R2 Hook-Mode Coexistence Solidification + Correct Demo
**Coding work list**:
1. Build `adapter/syscall/libff_syscall.so` with `FF_KERNEL_EVENT=1` (requires `FF_PATH`/`PKG_CONFIG_PATH`).
2. Re-verify and solidify the coexistence chain: `ff_hook_socket:387-390` (SOCK_KERNEL→kernel), `ff_hook_connect:858`, epoll merge `:2324+`, close linkage `:1874-1883` (read-only verification, the existing correct implementation is not changed).
3. Provide a **correct same-process dual-stack demo** (modeled after `main_stack_epoll_kernel.c`): within one process, both an F-Stack business listen (default socket) and a `SOCK_KERNEL` kernel listen, with one epoll receiving both stacks' events; replace/deprecate the v3 pure-kernel `helloworld_stacksel`.
**Acceptance**: the demo runs through — local `curl` reaches the kernel listen, the F-Stack business listen works via the NIC; both stacks' events delivered in one epoll (FR-1/FR-2/FR-6). Requires the DPDK runtime; when a real NIC is unavailable, the business plane is skipped with measured evidence while the kernel side is still measured on loopback.

## 3. R3 Native ff_api Unified-Event Coexistence (new design, core change)
**Coding work list**:
1. `lib/ff_config.{c,h}`: change the v3 `stack.default_to_kernel`/`default_stack` to `stack.kernel_coexist` (`MATCH("stack","kernel_coexist")`, default 0); sync the `test_ff_config` cases and fixtures, the `config.ini` example section; callers read `ff_global_cfg.stack.kernel_coexist` directly (no accessor).
2. `lib/ff_host_interface.{c,h}`: add a **managed kernel-side bridge** (host `socket/bind/listen/accept/connect/close/epoll_create1/epoll_ctl/epoll_wait`) for lib to create managed kernel fds (**not a raw bypass**; lib registers ownership).
3. lib-internal fd-ownership mechanism: an ownership table / encoded offset distinguishes managed kernel fds from F-Stack fds; `ff_socket(SOCK_KERNEL)` (when coexistence enabled) creates a managed kernel fd and registers it; default/`SOCK_FSTACK` go the original `sys_socket` (byte-for-byte zero regression).
4. `ff_bind/ff_listen/ff_accept/ff_connect/ff_close`: route by ownership at the entry (kernel fd → managed host bridge; F-Stack fd → original path).
5. `lib/ff_epoll.c`: `ff_epoll_create` also creates a kernel epoll; `ff_epoll_ctl` splits by ownership; `ff_epoll_wait` merges kernel epoll events (`timeout=0`+throttle) + `ff_kevent_do_each` F-Stack events; `ff_close` linkage.
6. Observability: `ff_stack_get_stats` draft.
**Acceptance**: native applications coexist over both stacks in one process; default/`SOCK_FSTACK` byte-for-byte zero regression (NFR-1); the F-Stack business plane is always present (NFR-3); the config coexistence switch takes effect (FR-9).

## 4. R4 Tests and Performance Baseline
See `07-test-spec.md`. Key points: cmocka unit tests (coexistence-switch parsing, fd ownership, managed kernel fd, event-merge boundaries, zero regression); integration (**same-process dual-stack**: F-Stack business + local curl/ping kernel listen + client connect); performance (coexistence on/off has no regression on the F-Stack fast path); coverage met.

## 5. R5 Gate + Commit
- gatekeeper read-only verification of all assertions/gate items; sync the English spec (00-10) to v4; short English commit; no push.

---

## 6. Risks and Rollback
- The native unified-event coexistence touches the `ff_socket`/`ff_epoll.c` hot paths: the default/`SOCK_FSTACK` path goes the original path, the coexistence branch is front-placed, with unit-test coverage for zero regression.
- **Coexistence iron rule**: if any phase finds the kernel stack replacing/bypassing the F-Stack business plane → bounce immediately (violates NFR-3).
- Strictly forbid introducing KNI/`rte_kni`.
- Changes are concentrated in the markers/`ff_config` switch/`ff_socket` entry/`ff_epoll.c` merge/managed bridge/demo, avoiding the packet fast-path hotspots.

## 7. Workspace Script Conventions
Clean temporary files via `/data/workspace/rm_tmp_file.sh`, stop processes via `/data/workspace/kill_process.sh`, change permissions via `/data/workspace/chmod_modify.sh`; `make install`-type (non-direct chmod) commands may be executed.

## 8. Gate Rollback
Any phase failing bounces back to the previous step; ≤3 bounces for the same step, escalate to manual when exceeded; bounces recorded in `08`.
