# 01 Requirements Spec: F-Stack User-Space Stack + Local Kernel Stack AUTOMATIC DUAL-STACK COEXISTENCE

> **Document ID**: SPEC-KE-01
> **Version**: v6 (native automatic dual-stack coexistence paradigm)
> **Date**: 2026-06-17
> **Status**: Drafting (v6 design)
> **Scope**: Define the problem domain, goals/non-goals, functional and non-functional requirements, and success criteria of this feature.
> **Authoritative full text**: `zh_cn/01-requirements-spec.md` (Chinese is the maintained source of truth; this English file carries the v6 key points). On conflict, code is authoritative.

> **v6 sync (key points; see `zh_cn/01-requirements-spec.md` for full detail)**:
> - **Paradigm upgrade**: from v5 per-fd either/or to v6 **automatic dual-stack**. When `FF_KERNEL_COEXIST` is compiled in AND `kernel_coexist=1`, a default (no-marker) `ff_socket` builds BOTH an F-Stack fd and a kernel host fd, registers `ff_native_fd_map[fstack_fd]=host_fd`, returns the F-Stack raw fd; `ff_bind/ff_listen/ff_close/ff_connect` dual-drive both stacks. One `listen(80)` listens on both F-Stack (DPDK) and the Linux kernel stack.
> - **FR-2/FR-3/FR-4 (auto dual-stack, v6 to-be-implemented)**: `ff_socket` dual-build; `ff_bind/ff_listen` dual-drive; one-listen-many-uses (remote `9.134.214.176:80` via DPDK NIC + local `curl 127.0.0.1:80` via kernel).
> - **FR-6 (accept single-stack ownership, Q3=A)**: a dual-stack listen fd's accept returns a single-stack connection fd (F-Stack raw / kernel encode); subsequent recv/send/close route by `ff_is_kernel_fd`, NOT consulting the map (hot path, NFR-2).
> - **FR-8/FR-9 (marker single-stack override)**: `SOCK_KERNEL` = kernel only (encode, no map); `SOCK_FSTACK` = F-Stack only (no map, zero regression). `SOCK_FSTACK` wins.
> - **FR-10 / N7 (connect dual-stack, DRAFT, PENDING USER CONFIRMATION)**: a single client logical flow cannot truly duplex over both stacks; v6 contract = "F-Stack primary + kernel concurrent connect for dual-network reachability". Use `SOCK_KERNEL` for a pure-kernel client; kernel-primary/failover is future work. See `zh_cn/05 §6`.
> - **FR-12 (compile-macro gating, opt-in)**: all `lib/` coexistence code (incl. the v6 `ff_native_fd_map`) is wrapped by `FF_KERNEL_COEXIST`, off by default (`lib/Makefile:57-60`/`:174-177`); macro off → byte-for-byte zero regression (`nm`/`objdump` shows no `ff_host_*`/`ff_epoll_pairs`/`ff_native_fd_map`).
> - **NFR-1/NFR-2/NFR-3**: triple zero-regression guarantee (macro off / `kernel_coexist=0` / `SOCK_FSTACK`); hot path no regression (single-stack connection recv/send do not consult the map); F-Stack always present.
> - **Implementation status (D9, anti-speculation)**: `ff_native_fd_map` and default dual-build/dual-drive are NOT yet landed (`zh_cn/02 §5.2` grep=0). v6 FR/NFR new items are to-be-implemented; acceptance pending R7.

---

## 1. Problem Domain

After F-Stack takes over the NIC via DPDK, that NIC's traffic bypasses the Linux kernel protocol stack. An F-Stack application wants, **while continuing to run its business on the F-Stack user-space stack**, to also:

1. **Server direction**: route some listening sockets to the host kernel stack so that local `ping`/`curl`/`ssh` can reach them (e.g., management plane / health checks / local debugging).
2. **Client direction**: as a client, `connect` via the kernel stack to local services (`127.0.0.1`/host kernel-stack IP) or external kernel-stack services.
3. **Unified events**: handle business (F-Stack) and kernel-stack fds in the **same event loop**, without splitting into two processes / two loops.

**Key**: this must be **coexistence** — the F-Stack user-space stack always carries the business fast path, and the kernel stack is merely an **additional** side channel selected per fd; it is **never** a replacement/bypass of F-Stack (the v3 mistake).

F-Stack already has two coexistence implementations to reuse/reference (see `02`):
- **hook mode `FF_KERNEL_EVENT`** (`adapter/syscall`): `socket(type|SOCK_KERNEL)` uses the kernel stack, the rest use F-Stack, epoll handles both stacks and maintains an F-Stack-fd↔kernel-fd mapping — **coexistence is fully implemented**.
- **nginx `kernel_network_stack`** (`app/nginx-1.28.0`): a per-server switch sets `belong_to_host`, and dual event backends (kqueue + Linux epoll) coexist in the same worker.

But:
- the hook mode's coexistence capability is **not documented/solidified**, and there is no correct "same-process dual-stack" demo (the v3 demo was pure-kernel and wrong);
- the **native `ff_api` mode**'s `ff_epoll_*` is a pure kqueue wrapper (`ff_epoll.c`) with **no kernel-fd awareness**, so natively-linked applications cannot coexist;
- config.ini lacks a **coexistence-capability switch** (and the v3 `default_stack=kernel` is an anti-F-Stack mistake that must be dropped).

This feature is: **solidify hook-mode coexistence as the primary baseline + add native-mode unified-event coexistence + add a config coexistence-capability switch + provide a correct same-process dual-stack demo and tests**.

---

## 2. Goals and Non-Goals

### 2.1 Goals (In Scope)
- **G1 (Coexistence semantics standardization)**: use `SOCK_KERNEL`/`SOCK_FSTACK` (`ff_adapter.h:7-8`) as the per-fd selection markers (default F-Stack); standardize them into a coexistence convention usable by any F-Stack application. **Do not create a side API, do not create a `belong_to_host` parameter-style interface**.
- **G2 (Hook-mode solidification)**: use `FF_KERNEL_EVENT` as the coexistence primary baseline; re-verify and solidify `ff_hook_socket` marker selection + `fstack_kernel_fd_map` dual-stack epoll merge + close linkage, and provide a correct "same-process F-Stack business + SOCK_KERNEL kernel" coexistence demo.
- **G3 (Native-mode unified-event coexistence, new design)**: inside lib, add an fd-ownership table + a kernel-epoll mirror + an `ff_epoll_wait` merge of kqueue⊕epoll, so native `ff_*` applications can also coexist over both stacks in one process; `ff_socket(SOCK_KERNEL)` creates a **managed kernel fd** (via `ff_host_interface` host socket, but registered for ownership and integrated into unified events), and subsequent `ff_bind/ff_listen/ff_accept/ff_connect/ff_close/ff_epoll_ctl` route by ownership.
- **G4 (config coexistence-capability switch)**: add **one switch** in config.ini controlling whether kernel-stack coexistence is enabled (runtime equivalent of `FF_KERNEL_EVENT`'s enable semantics), **keeping the default per-fd F-Stack unchanged**; **no "whole-process default-to-kernel" option**.
- **G5 (Server-side coexistence)**: F-Stack business listeners keep using the user-space stack; listeners with `SOCK_KERNEL` use the kernel stack, locally reachable by `ping`/`curl`.
- **G6 (Client-side coexistence)**: business clients use F-Stack; clients with `SOCK_KERNEL` `connect` via the kernel stack to local/external kernel services.
- **G7 (Default zero-overhead / zero regression)**: when coexistence is not enabled or no marker is set, the behavior is **byte-for-byte identical** to the original F-Stack; the F-Stack business fast path is unaffected.

### 2.2 Non-Goals (Out of Scope)
- **N1**: Do **not** create a side socket that bypasses F-Stack (v3 `ff_host_socket` deprecated); a kernel fd must be "managed + integrated into unified events".
- **N2**: Do **not** add a "whole-process default-to-kernel" switch (v3 `default_stack=kernel` deprecated, anti-F-Stack).
- **N3**: Do **not** create a new `ff_local_*` dual API / mTCP-like dual namespace.
- **N4**: Do **not** do gazelle-style thread-level selection (multi-process relies on different config files).
- **N5**: Do **not** adopt KNI/`rte_kni`/virtio-user packet reinjection.
- **N6**: Do not implement automatic socket migration / transparent proxying between the kernel stack and F-Stack (ownership is fixed at creation).

---

## 3. Functional Requirements (FR)

| ID | Requirement | Acceptance points | Code basis/reference |
|---|---|---|---|
| FR-1 | **F-Stack business unaffected**: default/`SOCK_FSTACK` sockets still use the F-Stack user-space stack | Business listen/connect sends/receives normally via the DPDK NIC | `ff_hook_socket:406`/`ff_socket` default path |
| FR-2 | **Server-side kernel coexistence**: a listener with `SOCK_KERNEL` uses the kernel stack, locally reachable by `curl`/`ssh` | Within one process, F-Stack business listen + kernel listen coexist; local access to the kernel listen succeeds | `ff_hook_socket:387-390` |
| FR-3 | Local `ping` (ICMP) can reach the kernel-stack-side address | ping succeeds | Kernel stack natively handles ICMP |
| FR-4 | **Client-side kernel coexistence**: the F-Stack app `connect`s via the kernel stack to local loopback / host IP services | local server + this app's client connect succeeds (while its business connections still use F-Stack) | `ff_hook_connect:858` + `is_fstack_fd:309` |
| FR-5 | **Client connects to external kernel services**: `connect` via the kernel stack to an external kernel-stack service | connect succeeds | `ff_hook_connect:858`→`ff_linux_connect:144` |
| FR-6 | **Unified event loop**: a single epoll receives both F-Stack and kernel-stack events | Both stacks' events are delivered, not lost | hook: `fstack_kernel_fd_map:257-258`+merge `:2324+`; native: new design this round |
| FR-7 | **Dual-mode coverage**: hook mode (FF_KERNEL_EVENT solidified) + native `ff_api` mode (unified-event coexistence added) | Both modes can do same-process dual-stack coexistence | `02 §2` (hook) / `02 §4` (native new design) |
| FR-8 | **fd ownership + resource linkage**: split by ownership; on close/exception both stacks' fds are released consistently, no leak | Correct behavior, no fd leak | hook `is_fstack_fd:309`+close linkage `:1874-1883`; native added this round |
| FR-9 | **config coexistence-capability switch**: kernel-stack coexistence can be enabled/disabled, default per-fd F-Stack unchanged | Switch takes effect; when off, equivalent to pure F-Stack | mimic `[kni]`: `ff_config.c:1011`/`ff_config.h:310-319` |

---

## 4. Non-Functional Requirements (NFR)

| ID | Requirement |
|---|---|
| NFR-1 | **Default zero-overhead / zero regression**: when coexistence is not enabled or on the default/`SOCK_FSTACK` path, behavior is byte-for-byte identical to the original F-Stack |
| NFR-2 | **No regression on the business fast path**: the F-Stack user-space stack's fast-path performance is unaffected by coexistence (baseline in `07`) |
| NFR-3 | **F-Stack always present**: the kernel stack is only an additional side path; under no circumstances may it replace/bypass the F-Stack business plane |
| NFR-4 | **Portable**: compatible with DPDK 23.11.5 / 24.11.6 and the ported FreeBSD stack |
| NFR-5 | **Observable**: provide basic statistics such as per-stack fd and event counts |
| NFR-6 | **Multi-process consistency**: each process sets the coexistence switch independently via its own config.ini, without affecting others (`ff_config.filename:254`) |

---

## 5. Boundary and Exception Scenarios

- The priority when both `SOCK_KERNEL` and `SOCK_FSTACK` are set (it is measured that `ff_hook_socket:387` requires `SOCK_KERNEL && !SOCK_FSTACK` to go to the kernel, otherwise F-Stack); the interface contract must state "`SOCK_FSTACK` takes priority".
- The behavior convention for a request carrying `SOCK_KERNEL` when the coexistence switch is off (degrade to F-Stack or raise an explicit error; must be made clear).
- When the kernel-stack-side address/port conflicts with the F-Stack side, raise an error instead of silently failing.
- Hook-mode `maxevents` too small (the mechanism requires `>=2`, `:2212-2218`).
- The behavior convention when, on client `connect`, the fd ownership does not match the destination address's stack.
- Compatibility before and after the native-mode unified-event coexistence enhancement (`02 §4`).
- The prerequisite that F-Stack `kern.maxfiles` ≤ 65536 (hook-mode fd mapping constraint, README note 1).

---

## 6. Success Criteria

1. Within **one F-Stack application process**: F-Stack business listen/connect works normally via the DPDK NIC (FR-1), **while** a kernel listener with `SOCK_KERNEL` is reached by local `curl`/`ping` successfully (FR-2/FR-3) — proving F-Stack is not bypassed and the two stacks truly coexist.
2. As a client, the app `connect`s via the kernel stack to local/external kernel services successfully (FR-4/FR-5), while its business clients still use F-Stack.
3. A single epoll correctly sends/receives both stacks' events (FR-6/FR-8); both hook and native modes coexist (FR-7).
4. The config coexistence switch takes effect; when off/default, business functionality and performance have **zero regression** (FR-9/NFR-1/NFR-2/NFR-3).
5. The full spec passes the `08-review-gate.md` gate.
