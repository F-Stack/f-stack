# 01 Requirements Spec: F-Stack Connection-Level Stack Selection Enhancement (Single API + Markers + config default switch)

> **Document ID**: SPEC-KE-01
> **Version**: v3 (paradigm-correction rework)
> **Date**: 2026-06-15
> **Status**: Drafting
> **Scope**: Define the problem domain, goals/non-goals, functional and non-functional requirements, and success criteria of this feature.

---

## 1. Problem Domain

After F-Stack takes over the NIC via DPDK, the NIC traffic bypasses the Linux kernel protocol stack, resulting in:

1. **Server direction**: Local tools (`ping`/`curl`/`ssh`) cannot access services running on the F-Stack user-space stack.
2. **Client direction**: When an F-Stack application acts as a client, it cannot use the kernel stack to `connect` to local services (`127.0.0.1`/the host kernel-stack IP) or external kernel-stack services.

F-Stack's `adapter/syscall` (hook/LD_PRELOAD mode) **has already implemented "single POSIX API + `SOCK_KERNEL`/`SOCK_FSTACK` markers + glue auto-adaptation"** stack selection (see `02`), but:
- The marker semantics are **embedded** in the syscall adaptation layer and have not been standardized into "a stack-selection convention that any F-Stack application can rely on";
- There is **no config.ini-level "global default-stack switch"** (one can only set the marker per socket in the application);
- **Client connecting to local/external kernel-stack services** has not been systematically documented;
- The `ff_socket` of the **native `ff_api` mode** currently **does not recognize** the stack-selection markers (`02 §5`, always creates an F-Stack socket).

This feature is: **standardize the existing "single API + marker-based stack selection" convention + add the config.ini global default switch + cover the client direction + add marker recognition in native mode**, so any F-Stack application can select the stack on demand without switching to multiple API sets.

---

## 2. Goals and Non-Goals

### 2.1 Goals (In Scope)
- **G1 (Marker standardization)**: Use the existing `SOCK_KERNEL`/`SOCK_FSTACK` (`ff_adapter.h:7-8`) as the **only stack-selection markers**, standardized into a convention usable by any F-Stack application; **do not create a new `ff_local_*` dual API, do not create a new `belong_to_host` parameter**.
- **G2 (config.ini global default switch)**: Add **one global default-stack switch** in config.ini (modeled after the `[kni]` paradigm) that decides whether this process defaults to F-Stack or the kernel stack; **priority: app marker > config default**.
- **G3 (Server-side stack selection)**: The application can route a listening socket to the kernel stack, and local `ping`/`curl`/`ssh` can directly access its service.
- **G4 (Client-side stack selection, newly added)**: As a client, the application can `connect` via the kernel stack to local loopback / host kernel-stack IP services **and external kernel-stack services** (carrier point `ff_hook_connect:858`).
- **G5 (Dual-mode coverage)**: The stack-selection markers and client capability cover both **hook mode** (full reuse) and **native `ff_api` mode** (add `ff_socket` marker recognition, `02 §5`).
- **G6 (Unified events)**: A single event loop serves both kernel-stack fds and F-Stack fds (reuse the `fstack_kernel_fd_map` dual-stack merge).
- **G7 (Low-intrusion / default zero-overhead)**: The compile switch is off by default; when no marker is set / default F-Stack, the behavior is identical to the original F-Stack.

### 2.2 Non-Goals (Out of Scope)
- **N1**: Do **not** create a new `ff_local_*` dual API / mTCP-like dual namespace (the v2 approach is deprecated).
- **N2**: Do **not** do gazelle-style **thread-level stack selection** (the F-Stack multi-process model distinguishes by different config files, see `02 §4`).
- **N3**: Do **not** do config.ini port/address rule lists (only "one global default switch").
- **N4**: Do **not** adopt KNI/`rte_kni`/virtio-user/TAP/AF_XDP packet reinjection.
- **N5**: This phase does **not** write implementation code, does **not** modify f-stack source; only produce the Chinese spec; **do not generate English documents**.
- **N6**: Do not implement automatic socket migration / transparent proxying between the kernel stack and F-Stack (ownership is determined at creation time).

---

## 3. Functional Requirements (FR)

| ID | Requirement | Acceptance points | Code basis |
|---|---|---|---|
| FR-1 | **Marker stack selection (server)**: a listening socket with `SOCK_KERNEL` goes to the kernel stack, and local `curl`/`ssh` can access it | Local access to the kernel-stack listener succeeds | `ff_hook_socket:387-390` |
| FR-2 | Local `ping` (ICMP) can reach the kernel-stack-side address | ping succeeds | Kernel stack natively handles ICMP |
| FR-3 | **Marker stack selection (client, newly added)**: an F-Stack application `connect`s to local loopback / host IP services via the kernel stack | Local server + F-Stack client connect succeeds | `ff_hook_connect:858` + `is_fstack_fd:309` |
| FR-4 | **Client connects to external kernel-stack services (newly added)**: an F-Stack application as a client selects the stack to access external kernel-stack services | Connect to external kernel service succeeds | `ff_hook_connect:858` → `ff_linux_connect:144` |
| FR-5 | **config.ini global default switch**: the default stack of this process (F-Stack/kernel) is configurable, and the app marker can override it | Default stack takes effect; marker override takes effect | `ff_config.c:1011`/`ff_config.h:310-319` paradigm |
| FR-6 | **Dual-mode coverage**: hook mode directly reuses markers; native `ff_api` mode adds `ff_socket` marker recognition | Both modes can do marker-based stack selection | `02 §2` (hook) / `02 §5` (native difference) |
| FR-7 | Unified event loop: a single loop receives both F-Stack and kernel-stack events | Both stacks' events are delivered correctly | `ff_hook_syscall.c:2324+` |
| FR-8 | fd ownership determination + resource linkage: split by ownership; on close/exception both stacks' fds are released consistently | Correct behavior, no fd leak | `is_fstack_fd:309`, close linkage `:1874-1883` |
| FR-9 | Compile switch: this capability can be enabled/disabled at compile time, zero-overhead when off by default | When off, behavior is identical to the original F-Stack | `Makefile -DFF_KERNEL_EVENT` paradigm |

---

## 4. Non-Functional Requirements (NFR)

| ID | Requirement |
|---|---|
| NFR-1 | **Default zero-overhead**: when not enabled / default F-Stack, no extra branches/memory overhead is introduced |
| NFR-2 | **No regression on the business fast path**: F-Stack fast-path performance is unaffected (baseline in `07`) |
| NFR-3 | **Portable**: compatible with this workspace's DPDK 23.11.5 / 24.11.6 and the ported FreeBSD stack |
| NFR-4 | **Observable**: provide basic statistics such as the number of fds and events per stack |
| NFR-5 | **Stable/low-intrusion interface**: reuse the existing single API + markers, no multiple API sets introduced; semantics align with POSIX/`ff_api.h` |
| NFR-6 | **Multi-process consistency**: each process sets the default stack independently via its own config.ini, without affecting others (`ff_config.filename:254`) |

---

## 5. Boundary and Exception Scenarios

- The priority when both `SOCK_KERNEL` and `SOCK_FSTACK` are set (it is measured that `ff_hook_socket:387` requires `SOCK_KERNEL && !SOCK_FSTACK` to go to the kernel; this must be explicit in the interface contract).
- When the app marker conflicts with the config default: **the app marker takes priority**.
- When the kernel-stack-side address/port conflicts with the F-Stack side, raise an error instead of silently failing.
- Handling when `maxevents` is too small (the mechanism requires `>=2`, `:2212-2218`).
- The behavior convention when, on client `connect`, the fd ownership does not match the destination address's stack (e.g., a kernel fd connecting to an address only reachable via F-Stack).
- The compatibility before and after the native-mode `ff_socket` marker recognition enhancement (`02 §5`).
- When this capability is disabled (compile time), all paths degrade to pure F-Stack behavior.
- Detection and prompting when system prerequisites are missing (referring to gazelle's `rp_filter`, etc.).

---

## 6. Success Criteria

1. After DPDK takes over the NIC, with a kernel-stack listener carrying `SOCK_KERNEL`: local `ping <kernel-stack IP>` succeeds and `curl <kernel-stack service>` succeeds (FR-1/FR-2).
2. As a client, an F-Stack application can `connect` via the kernel stack to local services (127.0.0.1/host IP) and external kernel-stack services, both successfully (FR-3/FR-4).
3. The config.ini global default-stack switch takes effect, and the app marker can override it (FR-5); multiple processes use different config files to get different default stacks (NFR-6).
4. Both the hook and native modes can do marker-based stack selection (FR-6); a single event loop serves both stacks correctly (FR-7/FR-8).
5. When this capability is disabled / default F-Stack, business performance and functionality have **zero regression** (NFR-1/NFR-2).
6. The full spec passes the `08-review-gate.md` gate.
