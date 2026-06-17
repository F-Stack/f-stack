# 00 Overview: F-Stack User-Space Stack + Local Kernel Stack COEXISTENCE (compile-macro gated + per-fd marker selection + unified events)

> **Document ID**: SPEC-KE-00
> **Version**: v5 (compile-macro gating: `FF_KERNEL_COEXIST` off by default + runtime `kernel_coexist` dual-layer switch)
> **Date**: 2026-06-17
> **Status**: Drafting
> **Scope**: Navigation, terminology, and scope statement for the spec in this directory

---

## 0. v5 Compile-Macro Gating Background (must read)

v4 already landed coexistence (app ON F-Stack + per-fd `SOCK_KERNEL` to the kernel stack + unified events). But all v4 coexistence code in `lib/` is **compiled unconditionally**, so even deployments not using coexistence link it in and cannot guarantee byte-for-byte zero regression vs. upstream F-Stack.

**v5 new requirement**: gate ALL `lib/` coexistence code under a single compile macro `FF_KERNEL_COEXIST`, **commented off by default in `lib/Makefile`**, forming a **compile-time + runtime dual-layer switch**:

- **Compile-time (`FF_KERNEL_COEXIST`)**: undefined → all coexistence code (managed kernel-fd bridge, fd discrimination, `ff_epoll` merge, `ff_socket` kernel branch, per-`ff_*` routing, config `kernel_coexist`, `SOCK_FSTACK/SOCK_KERNEL` macros) is **not compiled**; `libfstack.a` is **byte-for-byte zero regression** vs. upstream. Defined (`make FF_KERNEL_COEXIST=1` or uncomment) → compiled in.
- **Runtime (config `kernel_coexist`)**: **only when the macro is enabled**, `config.ini [stack] kernel_coexist=1` actually enables per-fd `SOCK_KERNEL` to use the kernel stack; default `=0` stays per-fd F-Stack.
- **Opt-in impact**: `ff_api.h` `SOCK_FSTACK`/`SOCK_KERNEL` macros are also wrapped by `FF_KERNEL_COEXIST`, so a consumer (APP) must likewise define the macro to see these markers — the reasonable semantics of "off by default, explicitly enabled".

**The correct paradigm**: within **one F-Stack application process**, business connections use the **F-Stack user-space stack (DPDK + FreeBSD)**, while fds carrying the `SOCK_KERNEL` marker use the **host Linux kernel stack**, and the two **coexist in a single event loop**, gated by the compile macro `FF_KERNEL_COEXIST` (off by default). This is exactly what F-Stack's two existing implementations do:
- the `FF_KERNEL_EVENT` compile mode of `adapter/syscall` (hook/LD_PRELOAD);
- nginx's `kernel_network_stack` config switch.

This feature = **solidify that coexistence capability as the primary baseline (hook mode)** + **add unified-event coexistence to the native `ff_api` mode**, gated by the `FF_KERNEL_COEXIST` compile macro, rather than building a side path that bypasses F-Stack.

> **v3 history**: v3 routed `ff_socket(SOCK_KERNEL)` to `ff_host_socket()` → a raw host `socket()`, completely bypassing the F-Stack user-space stack (a fundamental mistake), reverted in v4 and rewritten to the paradigm above.

## 1. One-Sentence Goal

Let an F-Stack application, **while running its business fast path on the F-Stack user-space stack**, route some sockets/listens/connects to the host kernel stack on a per-fd basis (so local `ping`/`curl`/`ssh` can directly reach its kernel-stack services, and the app as a client can `connect` via the kernel stack to local/external kernel services), with both stacks' fds sent/received in the **same epoll/event loop** — **F-Stack is always present and is never replaced by a side path**.

## 2. Scope Statement (Important)

- **This feature = dual-stack coexistence**: F-Stack user-space stack (business, default) + host kernel stack (per-fd `SOCK_KERNEL`), in the same process and event loop.
- **Selection method**: per-fd `SOCK_KERNEL`/`SOCK_FSTACK` markers (default F-Stack); one **coexistence-capability switch** in config.ini (whether to enable kernel-stack coexistence, without changing the default per-fd F-Stack semantics).
- **Hook mode (primary baseline, already supported)**: directly reuse `FF_KERNEL_EVENT` — `ff_hook_socket` marker-based selection + `fstack_kernel_fd_map` dual-stack epoll merge; this round solidifies it and provides a correct coexistence demo.
- **Native `ff_api` mode (new design)**: `ff_epoll_*` is currently a pure kqueue wrapper with no kernel-fd awareness; this round adds, inside lib, an fd-ownership table + a kernel-epoll mirror + an `ff_epoll_wait` merge of kqueue⊕epoll, so natively-linked applications can also coexist over both stacks in one process.
- **Explicitly excluded**:
  - Do **not** create a side socket that bypasses F-Stack (the v3 `ff_host_socket` approach is deprecated).
  - Do **not** add an anti-F-Stack "whole-process default-to-kernel" global switch (the v3 `default_stack=kernel` is deprecated).
  - Do **not** create a new `ff_local_*` dual API / mTCP-like dual namespace.
  - Do **not** do gazelle-style thread-level selection (the F-Stack multi-process model relies on different config files).
  - Do **not** adopt KNI/`rte_kni`/virtio-user packet reinjection (boundary clarification only).

## 3. Reading Path

| Order | Document | Purpose |
|---|---|---|
| 1 | `plan.md` | Plan, team, gate, rework paradigm |
| 2 | `01-requirements-spec.md` | Requirements and goals/non-goals (coexistence) |
| 3 | `02-current-state-analysis.md` | Current state of hook FF_KERNEL_EVENT / nginx kernel_network_stack / native event layer (code is authoritative) |
| 4 | `03-external-research.md` | External solution research (with URLs) |
| 5 | `04-architecture-design.md` | Coexistence architecture, dual-stack unified events, bidirectional data flow |
| 6 | `05-interface-design.md` | Marker/config contracts, hook and native dual-mode adaptation |
| 7 | `06-milestones.md` | Milestones and coding work list |
| 8 | `07-test-spec.md` | Test and performance-baseline plan |
| 9 | `08-review-gate.md` | Review gate conclusion |

## 4. Glossary

| Term | Meaning |
|---|---|
| F-Stack stack | DPDK PMD + user-space FreeBSD protocol stack (business fast path, **default stack**) |
| Kernel stack | Host Linux kernel network protocol stack (local/management/client connecting to local or external kernel services) |
| Coexistence | F-Stack fds and kernel fds present **in the same process and the same event loop**, each using its own stack |
| Stack-selection marker | `SOCK_KERNEL`(0x02000000)/`SOCK_FSTACK`(0x01000000) on socket `type`, per-fd |
| Coexistence-capability switch | A config.ini switch for whether to enable kernel-stack coexistence (does not change the default per-fd F-Stack semantics) |
| fd ownership | The marker at creation fixes whether the fd belongs to F-Stack or the kernel; subsequent syscalls/events route by ownership (`is_fstack_fd`/`CHECK_FD_OWNERSHIP`) |
| Unified events | External epoll style, internally merging F-Stack kqueue events + kernel epoll events |
| Hook mode | LD_PRELOAD takes over the POSIX API (`ff_hook_*`) + `FF_KERNEL_EVENT`; coexistence already supported |
| Native mode | The app directly calls `ff_*` (`ff_api.h`) + the `ff_run` main loop; this round adds unified-event coexistence |

## 5. Sources

- F-Stack actual code (`adapter/syscall/`, `app/nginx-1.28.0/`, `lib/`) — **highest priority; on conflict, code is authoritative**.
- F-Stack three-tier architecture docs and knowledge graph (`docs/`), `adapter/syscall/README.md`.
- Public external materials (GitHub/technical blogs, etc.), all with accessible URLs in `03`.
