# 06 Milestones and Coding Work List

> **Document ID**: SPEC-KE-06
> **Version**: v3 (paradigm-correction rework)
> **Date**: 2026-06-15
> **Status**: Drafting
> **Scope**: The implementation roadmap of this feature (the subsequent implementation phase, not this phase's deliverable). This phase delivers only the spec.

---

## 0. Milestone Overview

| Milestone | Name | Goal | Dependency | Main acceptance |
|---|---|---|---|---|
| **M0** | spec documents (**this phase**) | The full Chinese spec passes the gate | — | `08-review-gate.md` all PASS |
| **M1** | marker standardization + server-side kernel-stack listen | Standardize `SOCK_KERNEL`/`SOCK_FSTACK`; in hook mode, a marked listen lets local `curl`/`ping` succeed | M0 | FR-1/FR-2 |
| **M2** | client-side stack-selection connect | In hook mode, `connect` to local/external kernel services via the kernel stack | M1 | FR-3/FR-4 |
| **M3** | config.ini global default switch | Add `[stack] default_stack`, process default stack + marker override | M1 | FR-5/NFR-6 |
| **M4** | native `ff_api` mode marker recognition | `ff_socket` recognizes `SOCK_KERNEL`, dual-mode alignment | M1-M3 | FR-6 |
| **M5** | dual-stack unified events + resource linkage | A single loop serves both stacks, close linkage, observability | M1-M4 | FR-7/FR-8/NFR-4 |
| **M6** | tests and performance baseline | Unit/integration/performance baselines pass | M1-M5 | `07-test-spec.md` gate |

> Note: M1+M2 alone satisfy the two core requirements "local direct access to F-Stack host services" and "an F-Stack application as a client connecting to local/external kernel services", **without involving KNI and without adding APIs**.

---

## 1. M1 Marker Standardization + Server-Side Kernel-Stack Listen

**Coding work list**:
1. Promote `SOCK_KERNEL`/`SOCK_FSTACK` (`adapter/syscall/ff_adapter.h:7-8`) to an **externally-reliable convention** (expose in an external header + document the semantics/priority, per `ff_hook_socket:387-390`).
2. Re-verify/solidify hook-mode selection: `socket(type|SOCK_KERNEL)` → `ff_linux_socket`; `bind/listen/accept` auto-land on the kernel stack via `CHECK_FD_OWNERSHIP:57-61`.
3. Verify ICMP: `ping` succeeds to the kernel-stack-side address (the kernel handles it natively).

**Acceptance**: `curl <kernel-stack listen IP:port>` succeeds, `ping <kernel-stack IP>` succeeds; no regression for default/F-Stack business.

## 2. M2 Client-Side Stack-Selection connect (newly added core)

**Coding work list**:
1. Re-verify/solidify `ff_hook_connect:858` routing by fd ownership: kernel fd → `ff_linux_connect:144`.
2. Document and verify client usage: `socket(SOCK_KERNEL) + connect(127.0.0.1 / host kernel-stack IP)` and `connect(<external kernel-stack service>)`.
3. Cover TCP/UDP clients; confirm `send/recv/close` auto-split by ownership.

**Acceptance**: start a server locally (kernel stack), F-Stack client `connect` succeeds (FR-3); `connect` to an external kernel-stack service succeeds (FR-4).

## 3. M3 config.ini Global Default Switch

**Coding work list**:
1. `lib/ff_config.h:253` `struct ff_config` adds `struct { int default_to_kernel; } stack;`.
2. `lib/ff_config.c:956` `ini_parse_handler` adds a `MATCH("stack","default_stack")` branch (mimicking `MATCH("kni","enable")` :1011), parsing `fstack|kernel`.
3. Default value (`:1358+`) `default_to_kernel=0`; if there are string fields, free at `:1647+` (this item is an int, not needed).
4. Glue layer: when the app carries no marker, inject the equivalent `SOCK_KERNEL` per `ff_global_cfg.stack.default_to_kernel` (ensuring the app marker takes priority).
5. Add a `[stack] default_stack=fstack` example section to config.ini.

**Acceptance**: changing the config default stack takes effect; the app marker override takes effect; multiple processes use different config files to get different default stacks (NFR-6).

## 4. M4 Native `ff_api` Mode Marker Recognition

**Coding work list**:
1. At the `ff_socket` entry in `lib/ff_syscall_wrapper.c:912`, add a `SOCK_KERNEL` recognition branch mimicking `ff_hook_socket:387-390` (`02 §5`/D4: currently always creates an F-Stack socket).
2. Ensure the `linux2freebsd_socket_flags:668` path's behavior for default/`SOCK_FSTACK` is unchanged (zero-overhead).
3. Align native-mode client/server selection semantics with hook mode.

**Acceptance**: native mode can do marker-based selection; the default path has byte-for-byte no regression (FR-6/NFR-1).

## 5. M5 Dual-Stack Unified Events + Resource Linkage

**Coding work list**:
1. Reuse `fstack_kernel_fd_map:257-258` + dual-stack epoll: create mirror (`:1996-1998`), ctl routing (`:2016-2023`), wait merging (`:2324+`, `timeout=0`+throttle), `maxevents>=2` (`:2212-2218`).
2. `close` links the release of both stacks' fds (`:1874-1883`); `is_fstack_fd:309` ownership determination.
3. Observability: per-stack fd-count/event-count statistics (`ff_stack_get_stats` draft, `05 §6`).

**Acceptance**: a single event loop correctly sends/receives both stacks' events; no fd leak (FR-7/FR-8/NFR-4).

## 6. M6 Tests and Performance Baseline
See `07-test-spec.md`.

---

## 7. Risks and Rollback
- The native-mode marker recognition change touches the `ff_socket` hot path: use a front-placed conditional branch + a default zero-overhead branch, with unit-test coverage (M4).
- Confusion between config default injection and app marker priority: explicitly covered by UT cases (`07`).
- Event-merging latency: control it with mechanism B's "throttled kernel event fetching" (`:2324+`).
- **Strictly forbid introducing KNI/`rte_kni`** (removed in DPDK 23.11) as a rollback path.
- Changes are concentrated in the marker convention/`ff_config`/`ff_socket` entry/client documentation, avoiding touching the packet fast-path hotspots.

## 8. With Workspace Script Conventions
In the implementation phase, clean temporary files via `/data/workspace/rm_tmp_file.sh`, stop processes via `/data/workspace/kill_process.sh`, change permissions via `/data/workspace/chmod_modify.sh`; `make install`-type (non-direct chmod) commands may be executed.
