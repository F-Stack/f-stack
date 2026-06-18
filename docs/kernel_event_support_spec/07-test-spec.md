# 07 Test and Performance-Baseline Spec

> **Document ID**: SPEC-KE-07
> **Version**: v6 (native automatic dual-stack coexistence paradigm)
> **Date**: 2026-06-17
> **Status**: Drafting (R0-R6 measured; R7 v6 cases pending)
> **Authoritative full text**: `zh_cn/07-test-spec.md`.
> **Scope**: compile-macro zero-regression + automatic dual-stack (default dual-build/dual-drive + `ff_native_fd_map` + accept ownership + event merge + connect dual-stack + real-machine dual-stack) unit/integration/perf test plan and gate.

> **v6 sync (key points; see `zh_cn/07-test-spec.md` for full detail)**:
> - **MT-1~MT-5 (compile-macro zero-regression)**: macro off `nm`/`objdump` shows NO coexistence symbols incl. v6 `ff_native_fd_map`/`ff_native_map_*`; macro on → symbols appear; `symlist` unchanged.
> - **New v6 cmocka cases (macro-on)**: UT-4 `ff_native_map_set/get/clear`; UT-5 `ff_socket` default dual-build (returns F-Stack fd, `map[fd]==host`); UT-8 `ff_bind/ff_listen` dual-drive (mock counts); UT-9 accept single-stack ownership; UT-10 `ff_close` dual-drive + `ff_native_map_clear`; UT-12 dual-stack listen dual-register; UT-14 connect dual-stack (pending contract); UT-17 hot path does NOT consult the map (mock count=0); UT-18 partial-build-failure.
> - **Real-machine dual-stack (Q4=B)**: DPDK-exclusive NIC (≠eth1); one default `listen(80)` demo. IT-1 `ff_netstat`+`ss` each see 80; IT-2 remote `curl 9.134.214.176:80` (F-Stack side, via DPDK NIC); IT-3 local `curl 127.0.0.1:80` (kernel side); IT-5 unified events both stacks. config local test values not committed.
> - **PERF-4 (v6)**: single-stack connection recv/send hot path no extra cost (no map lookup, NFR-2).
> - **Gate**: connect (UT-14/IT-9) finalized only after **user confirms the §6 contract**.
>
> **R9 sync (key points; see `zh_cn/07-test-spec.md` for full detail)**:
> - **New v6/R9 cmocka cases (macro-on)**: UT-19 `ff_kevent` changelist registers kernel/dual-stack fd → `ff_host_epoll_ctl(ADD, map[fd], EPOLLIN)` (mock count, `data`=app fd); UT-20 `ff_kevent` eventlist synthesizes a kernel-ready `struct kevent` (`ident` restored, `filter=EVFILT_READ`, `EPOLLHUP`→`EV_EOF`) merged with `ff_kevent_do_each`, no loss; UT-21 kqueue-fd close clears `ff_epoll_pairs`+host_ep (no leak); UT-22 `ff_socket(AF_INET6)` dual-build → host IPv6 `IPV6_V6ONLY==1`, host `[::]:80`+`0.0.0.0:80` both bind OK (real loopback); UT-23 macro-off `ff_kqueue/ff_kevent` zero regression (no `ff_host_epoll_*`).
> - **Real-machine (R9)**: IT-11 kqueue-model helloworld (coexist=1) kernel `curl 127.0.0.1:80=200 size=438` (was 000) + F-Stack `9.134.214.176:80=200` no regression; IT-12 `-DINET6` helloworld (coexist=1) starts successfully (v4+v6 listen, no errno=98), packet capture confirms kernel-side 200.
> - **Gate (R9)**: UT-19~23 pass + IT-11 + IT-12 measured; macro-off nm zero regression for `ff_kqueue/ff_kevent`; `ff_kevent` kernel fd `EVFILT_READ/WRITE`-only is a documented known limit.
>
> **R10 sync (key points; see `zh_cn/07-test-spec.md` for full detail)**:
> - **New R10 cmocka cases (macro-on)**: UT-24 `ff_host_readv/writev` (real socketpair/pipe iov, bytes/content correct); UT-25 `ff_readv/writev` kernel-fd route → `ff_host_readv/writev(real)` (mock count or real host fd); UT-26 `ff_host_ioctl`+`ff_ioctl` kernel-fd route with **raw Linux request** (not via `linux2freebsd_ioctl`), `FIONBIO/FIONREAD` effective; UT-27 `ff_dup` kernel fd → encode, `ff_dup2` both-kernel → encode / **cross-stack rejected errno=EINVAL**; UT-28 macro-off `ff_readv/writev/ioctl/dup/dup2/select/poll` zero regression (no `ff_host_readv/writev/ioctl/dup/dup2`, no new symbols, host-bridge count 18→23).
> - **Real-machine (R10)**: IT-13 kernel-fd readv/writev/ioctl correct on managed kernel fd (127.0.0.1), kernel `curl 127.0.0.1:80=200`; IT-14 F-Stack side `9.134.214.176:80=200` no regression.
> - **Confirmed (impl measured)**: `ff_select` `FD_SETSIZE` hard limit + `ff_poll` conservative non-implementation → both documented limits (no UT, comment only); `ff_dup2` cross-stack errno=EINVAL; `ioctl` dual-stack fd same-driver added in R10.1 (`FIONBIO`/`FIOASYNC` synced to paired host fd). impl verified macro-off byte-for-byte zero regression.
> - **Gate (R10)**: UT-24~28 pass + IT-13 + IT-14 measured; macro-off nm zero regression for the residual entries; select/poll documented limits and the ioctl/dup2 decisions documented.
>
> **Alignment**: `tests/unit` (**cmocka**, *.c + *.ini), `tests/integration`, coverage `tests/run_full_coverage.sh` (lcov).

---

## 1. Test Layering

| Level | Directory | Framework/method | Coverage target |
|---|---|---|---|
| Unit test | `tests/unit/` | cmocka | config coexistence-switch parsing, fd ownership, native managed kernel fd, event-merge boundaries, zero regression |
| Integration test | `tests/integration/` or demo | end-to-end process + local tools | **same-process dual-stack coexistence**: F-Stack business + kernel listen reached locally + client connecting to local/external |
| Performance baseline | `tests/` | stress test + comparison | coexistence on/off has no regression on the **F-Stack business fast path** |

---

## 2. Unit-Test Cases (cmocka)

| ID | Case | Assertion | Mapped requirement |
|---|---|---|---|
| UT-1 | `ini_parse_handler` parses `[stack] kernel_coexist=1/0` | Correctly fills `ff_config.stack.kernel_coexist` | FR-9 |
| UT-2 | `[stack]` absent | Coexistence disabled (0) by default (pure F-Stack) | FR-9/NFR-1 |
| UT-3 | native `ff_socket` default/`SOCK_FSTACK` | Goes to F-Stack (byte-for-byte zero regression, path unchanged) | FR-1/NFR-1 |
| UT-4 | native `ff_socket(SOCK_KERNEL)` (coexistence enabled) | Creates a managed kernel fd and registers ownership (`is_kernel_fd==true`) | FR-7 |
| UT-5 | native `ff_socket(SOCK_KERNEL)` (coexistence disabled) | Errors or degrades per convention (no silent bypass of F-Stack) | boundary/`05 §8` |
| UT-6 | fd ownership determination | Managed kernel fds and F-Stack fds correctly distinguished | FR-8 |
| UT-7 | native `ff_epoll_ctl` split | kernel fd→host epoll; F-Stack fd→kqueue | FR-6 |
| UT-8 | native `ff_epoll_wait` merge | Both stacks' events returned, not lost | FR-6 |
| UT-9 | `type` both `SOCK_KERNEL\|SOCK_FSTACK` | Goes to F-Stack per priority | boundary |
| UT-10 | `ff_close` a managed kernel fd | Linked release, ownership entry cleared, no leak | FR-8 |
| UT-11 | hook-mode `maxevents=1` | Return `-EINVAL` (`:2212-2218`) | boundary |
| UT-12 | coexistence off / default | Behavior equivalent to pure F-Stack | NFR-1/NFR-3 |

> Cases land by following the existing `*.c`+`*.ini` (cmocka) organization in `tests/unit/`.

---

## 3. Integration-Test Cases (same-process dual-stack coexistence is the core)

| ID | Scenario | Steps | Pass criteria | Mapped requirement |
|---|---|---|---|---|
| IT-1 | **Same-process dual-stack** | Start the demo: within one process, an F-Stack business listen (default) + a `SOCK_KERNEL` kernel listen | Both listeners established; F-Stack business via the NIC, kernel listen via the kernel | FR-1/FR-2/FR-6 |
| IT-2 | Server-side local direct access to the kernel listen | local `curl 127.0.0.1:<kport>` / `curl <host_ip:kport>` | HTTP 200 (while the business listen is also present) | FR-2 |
| IT-3 | Local ping | `ping <host_ip>` | Has replies | FR-3 |
| IT-4 | Client connects to a local service | the demo's `SOCK_KERNEL` client `connect 127.0.0.1`/host IP | Connection established, send/recv normal; the business client still uses F-Stack | FR-4 |
| IT-5 | Client connects to an external kernel service | `SOCK_KERNEL` client `connect <external kernel service>` | Connection established, send/recv normal | FR-5 |
| IT-6 | config coexistence switch | `kernel_coexist=0` and restart → `SOCK_KERNEL` does not bypass per convention | When off, pure F-Stack | FR-9/NFR-1 |
| IT-7 | Multi-process differentiation | Two processes with different configs (coexistence on/off) | Each takes effect independently | NFR-6 |
| IT-8 | Long-run/leak | A large number of short connections repeatedly opened/closed (both stacks) | fd count stable, no leak | FR-8 |

> Process cleanup uses `/data/workspace/kill_process.sh`, temporary files use `/data/workspace/rm_tmp_file.sh`, permission changes use `/data/workspace/chmod_modify.sh`.

---

## 4. Performance Baseline

| ID | Metric | Method | Gate |
|---|---|---|---|
| PERF-1 | **F-Stack business fast-path regression** | coexistence off vs coexistence on but stressing only the F-Stack business | throughput/latency deviation ≤ noise threshold (NFR-2) |
| PERF-2 | default-path zero overhead | the impact of the coexistence branch on the default/`SOCK_FSTACK` path | zero/negligible (NFR-1) |
| PERF-3 | kernel-side side-path throughput | local curl concurrency on the kernel listen / client connect | meets management-plane expectations (not the fast path) |
| PERF-4 | event-merge latency | the latency impact of throttled kernel-event fetching | acceptable range |

> **Note**: the v3 "pure-kernel loopback bench" methodology is deprecated (it never ran F-Stack at all). The v4 performance core is **proving coexistence does not slow the F-Stack business fast path**.

---

## 5. Coverage and Gate Standard

- Reuse `tests/unit/run_coverage.sh`/`tests/run_full_coverage.sh` (lcov) to measure the coverage of this feature's changes.
- **Gate standard**:
  1. All UTs pass; the line coverage of new code reaches the existing standard.
  2. IT-1 (same-process dual-stack) + IT-2~IT-5 (direct access/ping/client) measured successfully (when a real NIC is unavailable, the F-Stack business plane is skipped with measured evidence; the kernel side must be measured on loopback).
  3. PERF-1/PERF-2 show no regression on the F-Stack business fast path and the default path.
  4. When coexistence is off/default, behavior/performance is consistent with pure F-Stack (NFR-1/NFR-3).
- Any item failing → bounce back to the previous milestone (≤3 times for the same step, escalate to manual when exceeded).

---

## 6. Cross-Validation Requirements
- All tests must actually be executed for evidence (logs/captures/coverage); speculation is forbidden.
- It must be measured that the **F-Stack business plane stays present and is not bypassed under coexistence** (NFR-3).
- Client cases must measure that `connect` reaches via the kernel stack (confirm by packet capture that it goes through the kernel rather than the DPDK NIC).
