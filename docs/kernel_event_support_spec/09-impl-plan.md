# 09 Implementation Plan: Local socket/fd/event Support (M1-M6)

> **Document ID**: SPEC-KE-09 (implementation-phase plan)
> **Date**: 2026-06-15
> **Status**: In progress
> **Basis**: the v3 spec in this directory (00-08); line numbers are subject to the actual code, gatekeeper re-verified.

---

## 0. Scope and Gate (user-confirmed)

- **Do all of M1-M6**: marker standardization / server-side kernel-stack listen / client connect selection / config.ini global default switch / native `ff_socket` marker recognition / dual-stack events + observability / tests and performance baseline.
- **Hard gate (unconditionally all green)**: compilation passes + cmocka unit tests all green + coverage G8 met.
- **Target gate**: best-effort to actually set up the DPDK runtime and run integration (curl/ping/client connect) and the performance baseline; when a real NIC/hugepages are truly unavailable, skip with **measured failure evidence (command + output)**.
- **NFR-1 zero regression**: the default/`SOCK_FSTACK` path is byte-for-byte identical to before the change.

---

## 1. Agent Team Topology (harness + spec-driven)

| Agent | Role | Responsibility |
|---|---|---|
| **Leader** | orchestration+authoring+arbitration | global orchestration, coding, gate arbitration, commit, bounce counting |
| **build** | compilation (read-only evidence + actual build) | compile lib / libff_syscall.so / tests, report errors |
| **unit-test** | unit-test authoring | cmocka cases (`test_ff_config` extension + native `ff_socket` marker cases) |
| **review** | code review (read-only) | minimal diff/zero regression/style/convention verification |
| **test** | integration/performance | example + end-to-end + performance baseline actual run or skip+evidence |
| **gatekeeper** | gate (read-only) | per-assertion + gate-item verification, FAIL bounce |

**Gate rollback**: any phase failing bounces back to the previous step; **≤3 bounces for the same step**, escalate to **manual when exceeded**; bounces are recorded in `08`.

---

## 2. Change Points (measured anchors, code is authoritative)

| Milestone | File | Change |
|---|---|---|
| M3 | `lib/ff_config.h:253` | `struct ff_config` adds `struct { int default_to_kernel; } stack;` (mimicking the kni section :310-319) |
| M3 | `lib/ff_config.c:956` `ini_parse_handler` | add `MATCH("stack","default_stack")` parsing `fstack`/`kernel`; `ff_default_config:1346` memset 0→default fstack holds automatically; add validation if necessary |
| M3 | `config.ini` (project root) | add a `[stack] default_stack=fstack` example section |
| M1 | external header (`lib/ff_api.h:63+` or new `ff_stack_select.h`) | expose the `SOCK_KERNEL`/`SOCK_FSTACK` selection convention + semantics/priority comments |
| M4 | `lib/ff_syscall_wrapper.c:912` `ff_socket` | add a `SOCK_KERNEL && !SOCK_FSTACK` recognition branch at the entry (equivalent kernel-socket path); default/`SOCK_FSTACK` goes the original `linux2freebsd_socket_flags:668`→`sys_socket` byte-for-byte zero-overhead |
| M5/M1/M2 | `adapter/syscall/ff_hook_syscall.c` | re-verify and solidify selection (`:387-390`)/connect (`:858`)/dual-stack events (`:2324+`); the glue layer injects the default per `ff_global_cfg.stack.default_to_kernel`; observability `ff_stack_get_stats` |
| M6 | `tests/unit/test_ff_config.c` + `Makefile` | `[stack]` parse/default/priority cmocka cases; add native `ff_socket` marker cases into the P group |
| M6 | `example/`, `tests/integration/` | dual-stack example + end-to-end (curl/ping/client-connect/config default/multi-process) |
| docs | `07-test-spec.md` | Unity→cmocka correction |

---

## 3. Key Design Decisions

- **Reuse first**: hook-mode selection is already implemented; this round mainly does "re-verify and solidify + standardize + complete".
- **Marker priority**: `stack = app_marker ?? config_default ?? F-Stack`, consistent with `ff_hook_socket:387` (`SOCK_KERNEL && !SOCK_FSTACK`).
- **M4 boundary (faithfully recorded)**: this round implements the `SOCK_KERNEL` recognition branch at the `ff_socket` entry; in native mode, the full-chain ownership routing of subsequent `ff_bind/ff_listen/...` for the kernel fd is a larger change, explicitly marked per the spec as a boundary/follow-up item to avoid misleading.
- **Reachability layering**: M3/M4 go through cmocka unit tests (host compilation, no DPDK runtime needed); M1/M2/M5 end-to-end go through integration (DPDK runtime, prefer `vdev`+`--no-huge` to avoid a physical NIC/hugepages).

---

## 4. Execution Steps (corresponding to the plan to-dos)
1. prep-plan-team (this document + team creation).
2. impl-config-marker: M3+M1 (config/marker/header) + compile.
3. impl-native-hook: M4 + M5/M1/M2 hook solidification + compile lib and libff_syscall.so.
4. unit-tests: cmocka unit tests all green + G8.
5. integration-perf: example + integration/performance actual run or skip+evidence.
6. gate-review: gate verification, FAIL bounce (≤3 escalate to manual), update 07/08.
7. commit-cleanup: short English commit + cleanup.

## 5. Workspace Script Conventions
Delete files via `/data/workspace/rm_tmp_file.sh`; stop processes via `/data/workspace/kill_process.sh`; change permissions via `/data/workspace/chmod_modify.sh`; `make install`-type (non-direct chmod) commands may be executed.
