# 08 Review Gate Report

> **Document ID**: SPEC-KE-08
> **Version**: v6 (native automatic dual-stack coexistence paradigm)
> **Date**: 2026-06-17
> **Status**: R0-R6 (v5, ba148589d) gate PASS; **v6 R7 auto dual-stack gate: pending measurement**
> **Authoritative full text**: `zh_cn/08-review-gate.md`.

> **v6 sync (key points; see `zh_cn/08-review-gate.md` for full detail)**:
> - **R0-R6 PASS (v5)**: coexistence paradigm correct, compile-macro gating complete, macro-off `nm` coexistence symbols=0, macro-on=39, real-machine perf PERF-1/2/3 PASS, D1-D8 consistent. M1-M7 PASS.
> - **R7 spec gate (v6)**: spec upgraded to native automatic dual-stack (default dual-build/dual-drive + `ff_native_fd_map` + dual-stack unified events + accept single-stack ownership + connect draft); line numbers code-authoritative; explicitly distinguishes "v5 measured" vs "v6 to-be-implemented" (D9).
> - **R7 implementation gate V1-V12 PENDING MEASUREMENT**: V1 map landed, V2 socket dual-build, V3 bind/listen dual-drive, V4 accept ownership, V5 close dual-drive+clear, V6 epoll dual-register+merge, V7 one-listen-many-uses real-machine (F-Stack 9.134.214.176:80 + kernel 127.0.0.1:80, `ff_netstat`+`ss` each see 80), V8 hot path no map lookup, V9 macro-off no `ff_native_fd_map` symbols / macro-on present, V10 **connect contract PENDING USER CONFIRMATION**, V11 partial-build-failure contract, V12 NFR-1/3 zero regression + F-Stack always present.
>
> **R9 sync (kqueue coexistence + IPv6 V6ONLY; spec gate PASS, implementation pending impl; see `zh_cn/08-review-gate.md §4bis`)**:
> - **Gap (measured, R9-P1/P2)**: `ff_kqueue/ff_kevent/ff_kevent_do_each` have NO coexistence routing (only `ff_epoll.c` hits the macro) — kqueue-model kernel-side `curl 127.0.0.1:80=000` (handshake done, GET TCP-ACKed `ack 73`, app never woken), F-Stack side 200 (D10). `-DINET6` dual-build `ff_bind errno=98 EADDRINUSE` (host IPv6 lacks `IPV6_V6ONLY=1`, bindv6only=0) → start failure (D11).
> - **Solution (R9-P3/P4)**: (P2) `ff_kqueue/ff_kevent` symmetrically mimic `ff_epoll` (reuse `ff_epoll_pairs`/`ff_epoll_host_ep`, changelist→`ff_host_epoll_ctl`, eventlist synthesize `struct kevent`, close clears pairing); (P1) host IPv6 `setsockopt(IPV6_V6ONLY,1)`, placement measured.
> - **Contracts/limits (R9-P5/P6)**: app-fd restore (`epoll_event.data`↔`kevent.ident`), filter map (READ↔IN/WRITE↔OUT/EOF↔HUP|ERR); `ff_kevent` kernel fd `EVFILT_READ/WRITE`-only; `readv/writev/ioctl` keep D8 limit in R9 (collected by R10).
> - **Gating/status (R9-P7/P8/P9)**: all `#ifdef FF_KERNEL_COEXIST`, macro-off zero regression; implementation status faithfully marked **to-be-implemented**; tests UT-19~23 + IT-11 (kernel 200) / IT-12 (INET6-on start). Implementation gate (real-machine kernel 200 / INET6-on start / macro-off nm zero regression) to be filled by gatekeeper after impl lands.

> **R10 sync (residual-entry coexistence completion — readv/writev/ioctl + dup/dup2 + select/poll; spec gate PASS, impl landed/compiles, real-machine pending; see `zh_cn/08-review-gate.md §4ter`)**:
> - **Gap (measured, R10-P1/P2)**: `ff_readv:1189`/`ff_writev:1251`/`ff_ioctl:1067` had NO `FF_KERNEL_COEXIST` kernel-fd routing (read/write do; were D8 limit, D12-D13); `ff_dup:2130`/`ff_dup2:2156`/`ff_select:1879`/`ff_poll:1903` also lacked it (D14-D15).
> - **Solution (R10-P3/P4/P5)**: readv/writev → `ff_host_readv/writev(real,...)` (mimic read/write, single-stack); ioctl → `ff_host_ioctl(real, raw Linux request)` (not via `linux2freebsd_ioctl`; **dual-stack fd same-driver added in R10.1** — `FIONBIO`/`FIOASYNC` synced to the paired host fd; query ioctls like `FIONREAD` not forwarded); `ff_dup`→`ff_host_dup`+encode, `ff_dup2` both-kernel→encode / **cross-stack rejected errno=EINVAL**.
> - **Limits (R10-P6)**: `ff_select`/`ff_poll` both NOT implemented, downgraded to documented limits (select = `FD_SETSIZE` hard limit; poll = merge complexity), comment only — use `ff_epoll_*`/`ff_kqueue` (R9).
> - **Bridges/gating/status (R10-P7/P8/P9)**: 5 new host bridges `ff_host_readv/writev/ioctl/dup/dup2` (`ff_host_interface.h:178-184`, 18→23); all `#ifdef FF_KERNEL_COEXIST`, macro-off byte-for-byte zero regression verified by impl; tests UT-24~28 + IT-13/IT-14. Implementation gate (real-machine kernel-fd readv/writev/ioctl correct + kernel 200 / F-Stack 200 no regression / macro-off nm zero regression) to be filled by gatekeeper.

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
| I1 | config coexistence switch (R3.1) | PASS | `ff_config.h` `struct{int kernel_coexist;}stack;`; `ff_config.c` `MATCH("stack","kernel_coexist")`(1/on/true/yes→1), default 0; callers read `ff_global_cfg.stack.kernel_coexist` directly |
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

### I.4 Performance Baseline (PERF-1/2/3, real-hardware DPDK NIC)
The environment now has a DPDK NIC (`00:09.0`→igb_uio) + a two-machine f-stack-client, measured per `10-perf-baseline-report.md`:
- **PERF-1/2 (vector A, F-Stack fast-path A/B; helloworld 438B keep-alive, same binary, same window toggling only config `kernel_coexist` 0 vs 1)**: T1 **−0.66%** / T2 **+1.49%** / T3 **+4.62%**, all within trial noise (coexist-on equal-or-slightly-faster); T2 p99 ~700us equal → **the coexistence switch causes no regression on the F-Stack business fast path (NFR-1/2/3)**.
- **PERF-3 (vector B, local loopback against the `SOCK_KERNEL` kernel listener bench; single-thread host-epoll, 15B body)**: T1 132,385 / T2 127,501 / T3 113,641 req/s, **zero socket errors across 9 trials** → kernel-side bypass management plane works correctly and error-free (basis: single-host serial lower bound, not comparable to vector A absolutes).
- Background cross-reference: existing 15.0 CVM T2 203,933 matches this A0 207,723 closely (cross-confirms NFR-1).

### I.5 Bounce Record
| # | Trigger | Handling | Re-verification |
|---|---|---|---|
| self-fix | ff_host_interface.c missing `<unistd.h>`/`_GNU_SOURCE` | added includes in the same step | compiles |
| self-fix | socklen_t undefined across namespaces | header declarations use `unsigned int` (same type, compatible) | compiles |
| self-fix | test_ff_epoll missing ff_host_epoll_* at link | added no-op stubs in the test | 21/21 PASS |
| **bounce-1 (R4 perf cross-step)** | helloworld relinked against the current lib segfaulted at startup in `ff_log_close→fclose(dangling)` | root cause = `ff_config.h` adding `kernel_coexist` shifted the `log` offset + lib Makefile lacks header-dep tracking → leftover objects mixing old/new layout (ABI skew); not a source bug. `rm_tmp_file.sh` cleared all 245 .o + libfstack.a, full rebuild | helloworld retest enters ff_run normally (exit 124); 13.0-baseline cross-check in the same env does not crash → env healthy; the full PERF A/B then ran through |
- bounce: **1 cross-step bounce (R4 perf, root-caused and fixed, < 3 limit, no manual escalation)**; the rest are same-step immediate self-fixes.

### I.6 Implementation-Phase Conclusion
**PASS (hard gate)**: compilation + cmocka unit tests all green + socket-side coexistence selftest actually run + zero regression + **R4 real-hardware performance baseline (PERF-1/2/3) measured PASS** (coexistence has no fast-path regression; kernel-side bypass is error-free). Native ff_api dual-stack coexistence (socket side + ff_epoll merge) is implemented and validated on a real NIC.
> **Build note**: after changing struct headers like `ff_config.h`, a clean full lib rebuild is mandatory (lib/Makefile lacks header-dependency tracking — an existing F-Stack trait); otherwise an incremental build yields an ABI-skew runtime crash.

---

## 5. Bounce Record (R1)
| # | Trigger | Handling | Re-verification |
|---|---|---|---|
| — | The R1 spec rewrite is consistent with the coexistence paradigm; no FAIL triggered | — | — |
- bounce: 0 (< 3 limit).

## 6. Current Conclusion
**R1 spec gate PASS** (coexistence paradigm correct, v3 bypass/default-to-kernel wording removed, code anchors consistent). **R2-R4 implementation gate PASS**: compilation/cmocka all green, socket-side coexistence selftest run, zero regression, and the real-hardware performance baseline PERF-1/2/3 measured PASS (coexistence has no fast-path regression; kernel-side bypass is error-free — see `10-perf-baseline-report.md`). One cross-step bounce in R4 (ABI skew, root-caused and fixed, < 3 limit). R5 commit wrap-up remains.
