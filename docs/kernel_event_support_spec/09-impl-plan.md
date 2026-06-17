# 09 Implementation Plan: F-Stack + Kernel Stack Automatic Dual-Stack Coexistence (R0-R7)

> **Document ID**: SPEC-KE-09 (implementation-phase plan)
> **Version**: v6 (native automatic dual-stack coexistence paradigm)
> **Date**: 2026-06-17
> **Status**: In progress (R0-R6 done; **R7 v6 auto dual-stack to-be-implemented**)
> **Basis**: the v6 spec in this directory (00-08); line numbers are subject to the actual code, gatekeeper re-verified. v6 changes are to-be-implemented design.
> **Authoritative full text**: `zh_cn/09-impl-plan.md`.

> **v6 sync (key points; see `zh_cn/09-impl-plan.md` for full detail)**: **R7 per-file rework** (under `#ifdef FF_KERNEL_COEXIST`, runtime `kernel_coexist=0` short-circuit, `SOCK_FSTACK`/macro-off byte-for-byte zero regression):
> - (1) `ff_host_interface.h`: declare `ff_native_map_get/set/clear` (NO struct-header change).
> - (2) `ff_host_interface.c`: `static int ff_native_fd_map[FF_MAX_FREEBSD_FILES]`(=65536, lock-free) + accessors (bounds-checked).
> - (3) `ff_syscall_wrapper.c`: `ff_socket:915-947` default dual-build (`sys_socket`(s)+`ff_host_socket`(h)+`ff_native_map_set(s,h)`, return s; markers single-stack); `ff_bind:1607-1627` (`kern_bindat` then `ff_host_bind(map[s], raw linux addr)`); `ff_listen:1584-1605` (`sys_listen` then `ff_host_listen(map[s])`); `ff_close:1095-1112` (`kern_close` then `ff_host_close(map[fd])`+`ff_native_map_clear`); `ff_accept/accept4:1514-1582` single-stack ownership; `ff_setsockopt:999`/`ff_fcntl:1495` sync both; `ff_connect:1629-1649` §connect draft (pending user confirmation). recv/send/read/write/recvfrom/sendto unchanged (single-stack by `ff_is_kernel_fd`, NO map lookup).
> - (4) `ff_epoll.c`: `ff_epoll_ctl:99-115` dual-register a dual-stack listen (kqueue + `ff_host_epoll_ctl(host_ep, op, map[fd], event)`, pass `event.data`); `ff_epoll_wait:214-252` merge (existing skeleton); `ff_close` clear `ff_epoll_pairs` for kqueue fd.
> - (5) `lib/Makefile`: already in place (`:174-177` dual CFLAGS); no change.
> - (6) demo: default dual-stack `listen(80)` demo for real-machine IT-1/2/3.
> Then R7 tests (cmocka dual-mode + real-machine dual-stack + perf) and gate (`08 §4` V1-V12; MT-1/3 incl. `ff_native_fd_map`); English spec sync; English short commit; config local values NOT committed; clean full rebuild after any header change (ABI skew).

---

## 0. Scope and Gate

- **Do all of R0-R5**: revert wrong code → spec rewrite → hook coexistence solidification + demo → native unified-event coexistence → tests/performance → gate + commit.
- **Hard gate (unconditionally all green)**: compilation passes + cmocka unit tests all green + coverage met + **F-Stack business fast-path zero regression (NFR-1/NFR-2)**.
- **Coexistence iron rule (NFR-3)**: at every phase the F-Stack user-space stack always carries the business and is never bypassed by the kernel stack; violating it bounces.
- **Target gate**: best-effort to actually set up the DPDK runtime and run the same-process dual-stack integration; when a real NIC is unavailable, the business plane is skipped with measured evidence and the kernel side is still measured on loopback.

---

## 1. Agent Team Topology (harness + spec-driven)

| Agent | Role | Responsibility |
|---|---|---|
| **Leader** | orchestration+authoring+arbitration | orchestration, coding, gate arbitration, commit, bounce counting |
| **arch-probe** | architecture probe (read-only) | measure hook FF_KERNEL_EVENT / nginx / native event layer |
| **spec-writer** | spec rewrite | v4 Chinese & English docs |
| **build** | compilation (actual build) | lib / libff_syscall.so / tests |
| **unit-test** | unit tests | cmocka coexistence cases |
| **review** | review (read-only) | minimal diff/zero regression/coexistence iron rule/conventions |
| **test** | integration/performance | same-process dual-stack end-to-end + no regression on the F-Stack fast path |
| **gatekeeper** | gate (read-only) | per-assertion + gate-item verification |

**Gate rollback**: any phase failing bounces back to the previous step; ≤3 bounces for the same step, escalate to manual when exceeded; bounces recorded in `08`.

---

## 2. Change Points (measured anchors, code is authoritative)

| Milestone | File | Change |
|---|---|---|
| R0 | `lib/ff_syscall_wrapper.c`, `lib/ff_host_interface.{c,h}` | revert the ff_host_socket side path (**done 0748eff94**) |
| R2 | `adapter/syscall/` (Makefile FF_KERNEL_EVENT), new demo | build libff_syscall.so; a correct same-process dual-stack demo (modeled after `main_stack_epoll_kernel.c`), replacing the v3 pure-kernel helloworld_stacksel |
| R3 | `lib/ff_config.{c,h}` | change the v3 `stack.default_to_kernel`/`default_stack` to `stack.kernel_coexist` (`MATCH("stack","kernel_coexist")`, default 0) + accessor |
| R3 | `lib/ff_host_interface.{c,h}` | add the managed kernel-side bridge (host socket/bind/listen/accept/connect/close/epoll_*) for lib to create managed kernel fds |
| R3 | `lib/ff_syscall_wrapper.c` `ff_socket` and ff_bind/listen/accept/connect/close | when coexistence enabled, SOCK_KERNEL→managed kernel fd+register ownership; route by ownership; default/`SOCK_FSTACK` zero regression |
| R3 | `lib/ff_epoll.c` | `ff_epoll_create` also creates a kernel epoll; `ff_epoll_ctl` splits; `ff_epoll_wait` merges kqueue⊕epoll; close linkage |
| R3 | `config.ini` | `[stack] kernel_coexist=0` example section (replacing the v3 default_stack) |
| R4 | `tests/unit/`, `tests/integration/` | cmocka coexistence cases + same-process dual-stack integration |
| docs | `docs/kernel_event_support_spec/` (Chinese & English 00-10) | v4 coexistence paradigm |

---

## 3. Key Design Decisions
- **Reuse first**: hook coexistence is implemented; R2 mainly re-verifies/solidifies + a correct demo.
- **Native coexistence core**: managed kernel fd (**not a raw bypass**; lib registers ownership and integrates it into unified events) + `ff_epoll_wait` merge; the default path is byte-for-byte zero regression.
- **fd-space distinction**: mimic the nginx `ngx_max_sockets` offset or the hook encoded offset; fixed in the implementation phase.
- **Reachability layering**: config/fd-ownership/event-merge go through cmocka unit tests (host compilation, no DPDK runtime); same-process dual-stack end-to-end goes through integration (DPDK runtime, prefer vdev+--no-huge to avoid a physical NIC).

---

## 4. Execution Steps
1. R0 revert (done).
2. R1 spec rewrite (Chinese & English done).
3. R2 hook coexistence solidification + demo + build.
4. R3 native unified-event coexistence + config change + build.
5. R4 unit/integration/performance.
6. R5 gate + English spec + commit.

## 5. Workspace Script Conventions
Delete files via `/data/workspace/rm_tmp_file.sh`; stop processes via `/data/workspace/kill_process.sh`; change permissions via `/data/workspace/chmod_modify.sh`; `make install`-type (non-direct chmod) commands may be executed.
