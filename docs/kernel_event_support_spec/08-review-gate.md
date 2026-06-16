# 08 Review Gate Report

> **Document ID**: SPEC-KE-08
> **Version**: v4 (coexistence-paradigm rework)
> **Date**: 2026-06-16
> **Status**: In progress (R1 spec gate; R2-R5 implementation gate done)
> **Scope**: Gate verification of the v4 spec and implementation for "consistency with the actual code / coexistence-paradigm correctness / zero regression".

---

## 1. Gate Method
- gatekeeper (code-explorer, read-only) async verification + the Leader synchronously measuring each key `file:line` assertion; on conflict, **the actual code is authoritative**.
- bounce convention: any item FAIL → bounce back to the previous step, ≤3 times for the same step, escalate to manual when exceeded.

## 2. Coexistence-Paradigm Correctness Assertions (R1 spec gate)

| ID | Assertion | Evidence |
|---|---|---|
| P1 | The spec no longer has "ff_socket→raw kernel bypass" / "whole-process default-to-kernel" wording | 00/01/02/04/05/06 removed `ff_host_socket`/`default_stack=kernel` |
| P2 | Paradigm = app on F-Stack + per-fd `SOCK_KERNEL` additional kernel side path + unified-event coexistence | 00 §1/01 §1/04 §1 |
| P3 | Hook FF_KERNEL_EVENT is the primary baseline (coexistence implemented) | 02 §2, `README.md:169-186`, `ff_hook_socket:387-390`/`fstack_kernel_fd_map:257-258` |
| P4 | nginx kernel_network_stack is an isomorphic reference | 02 §3, `ngx_http_core_module.c:298-303`/dual backend `ngx_ff_host_event_module.c:441` |
| P5 | Native-mode coexistence is a new design (event-layer gap faithfully recorded) | 02 §4, `ff_epoll.c:25-28/103/157` (pure kqueue wrapper) |
| P6 | config changed to a coexistence-capability switch (whole-process default-to-kernel removed) | 05 §3, 06 R3 |
| P7 | The coexistence iron rule NFR-3 (F-Stack always present) runs throughout | 01 §4, 04 §1, 06 §6 |

## 3. R0 Revert Verification (done)

| ID | Assertion | Result | Evidence |
|---|---|---|---|
| RV1 | `ff_socket` side-path branch reverted | PASS | `lib/ff_syscall_wrapper.c` ff_socket restored to the sa.domain/linux2freebsd_socket_flags/sys_socket path |
| RV2 | `ff_host_socket` removed | PASS | `lib/ff_host_interface.c`/`.h` has no `ff_host_socket` (then re-added as the managed bridge in R3) |
| RV3 | compile/unit tests no regression | PASS | lib `-Werror` re-link passes; `test_ff_config` 54/54 |
| RV4 | commit | PASS | `0748eff94 revert(stack-select): drop ff_host_socket bypass...` |

## 4. R2-R5 Implementation Gate (measured)

> Conclusions come from actual compilation/execution; the evidence is reproducible. Commit chain: 0748eff94(R0)→32d6f8837(R1)→7b6bcca2f(R3.1)→74f365a62(R3.2/3.3)→7b38bca62(R3.4)→4b29dd8dc(R4)→c806af9bf(test fix).

### I.1 Code-Change Verification (all PASS)
| ID | Assertion | Result | Evidence |
|---|---|---|---|
| I1 | config coexistence switch (R3.1) | PASS | `ff_config.h` `struct{int kernel_coexist;}stack;`; `ff_config.c` `MATCH("stack","kernel_coexist")`(1/on/true/yes→1), default 0, `ff_kernel_coexist_enabled()` |
| I2 | FD-space scheme (no collision) | PASS | `ff_host_interface.h` `FF_KERNEL_FD_BASE 0x40000000`, `ff_is_kernel_fd/encode/real` (above FreeBSD fd ≤65536, host fds bounded by RLIMIT) |
| I3 | host bridge (managed kernel fd, not a raw bypass) | PASS | `ff_host_interface.c` `ff_host_socket/bind/listen/accept/accept4/connect/close/read/write/recv/send/sendto/recvfrom/setsockopt/getsockopt/fcntl/epoll_create1/ctl/wait`; `_GNU_SOURCE` for accept4/epoll_create1 |
| I4 | socket-side ownership routing (R3.2/3.3) | PASS | `ff_syscall_wrapper.c` `ff_socket`(SOCK_KERNEL+coexist→managed kernel fd) and close/read/write/sendto/recvfrom/accept/accept4/listen/bind/connect/setsockopt/getsockopt/fcntl entries route by `ff_is_kernel_fd` |
| I5 | unified-event merge (R3.4) | PASS | `ff_epoll.c` epfd↔host-epoll pair table, `ff_epoll_ctl` kernel-fd routing, `ff_epoll_wait` merge kqueue⊕host epoll; degrades to original behavior when no kernel fd |
| I6 | NFR-1 zero regression | PASS | The default/`SOCK_FSTACK` path is byte-for-byte unchanged (only an `ff_is_kernel_fd` branch is front-placed in each function) |
| I7 | NFR-3 F-Stack present | PASS | Kernel fd is an additional side path; business still defaults to F-Stack; no whole-process default-to-kernel semantics |

### I.2 Compilation and Unit Tests (hard gate PASS)
- **lib compilation**: `cd lib && make` re-links `libfstack.a` under `-Werror` (changes to ff_config/ff_host_interface/ff_syscall_wrapper/ff_epoll).
- **cmocka all green**: test_ff_config 54/54, test_ff_host_interface 24/24, test_ff_epoll 21/21, test_ff_init 6, test_ff_log 13, test_ff_ini_parser 25 — **0 failures**.
- Pre-existing baseline `test_ff_dpdk_if` is missing `ff_tcp_hpts_softclock` (unrelated to this feature); the hard gate does not depend on it.

### I.3 Integration Measurement (coexistence selftest, EAL-free)
| Case | Command | Result |
|---|---|---|
| native managed kernel-fd loopback server+client | `example/helloworld_stacksel` selftest | `COEXIST SELFTEST PASS: native ff_socket(SOCK_KERNEL) kernel-stack server+client over loopback` |

> Through `ff_socket(SOCK_KERNEL)`→managed kernel fd→bind/listen/accept + client connect/send/recv/close, the full chain runs through, validating socket-side coexistence and fd-ownership routing.

### I.4 Skip (no physical NIC in the environment)
- The full "F-Stack business plane + SOCK_KERNEL kernel listen + ff_epoll merge" end-to-end coexistence requires `ff_init`/`ff_run` + a DPDK data plane (NIC/hugepages); this sandbox has no physical NIC → skipped per Q1, to be supplemented on real hardware per `07`'s integration plan. The socket side, config, unit tests, and zero regression are all green under the hard gate.

### I.5 Bounce Record
| # | Trigger | Handling | Re-verification |
|---|---|---|---|
| self-fix | ff_host_interface.c missing `<unistd.h>`/`_GNU_SOURCE` | added includes in the same step | compiles |
| self-fix | socklen_t undefined across namespaces | header declarations use `unsigned int` (same type, compatible) | compiles |
| self-fix | test_ff_epoll missing ff_host_epoll_* at link | added no-op stubs in the test | 21/21 PASS |
- bounce: 0 cross-step bounces (all same-step immediate self-fixes, < 3 limit).

### I.6 Implementation-Phase Conclusion
**PASS (hard gate)**: compilation + cmocka unit tests all green + socket-side coexistence selftest actually run + zero regression. Native ff_api dual-stack coexistence (socket side + ff_epoll merge) is implemented; the F-Stack business-plane end-to-end coexistence awaits real hardware (skip + note).

---

## 5. Bounce Record (R1)
| # | Trigger | Handling | Re-verification |
|---|---|---|---|
| — | The R1 spec rewrite is consistent with the coexistence paradigm; no FAIL triggered | — | — |
- bounce: 0 (< 3 limit).

## 6. Current Conclusion
**R1 spec gate PASS** (coexistence paradigm correct, v3 bypass/default-to-kernel wording removed, code anchors consistent). The R2-R5 implementation gate is PASS (hard gate) with the F-Stack-business-plane end-to-end coexistence pending real hardware.
