# 06 Milestones and Coding Work List

> **Document ID**: SPEC-KE-06
> **Version**: v4 (coexistence-paradigm rework)
> **Date**: 2026-06-16
> **Status**: Drafting
> **Scope**: The rework implementation roadmap of this feature.

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
1. `lib/ff_config.{c,h}`: change the v3 `stack.default_to_kernel`/`default_stack` to `stack.kernel_coexist` (`MATCH("stack","kernel_coexist")`, default 0); sync the `test_ff_config` cases and fixtures, the `config.ini` example section, and the accessor (e.g., `ff_kernel_coexist_enabled()`).
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
