# 00 Overview: F-Stack User-Space Stack + Local Kernel Stack AUTOMATIC DUAL-STACK COEXISTENCE (compile-macro gated + default dual-stack + marker single-stack override + unified events)

> **Document ID**: SPEC-KE-00
> **Version**: v6 (**native automatic dual-stack coexistence** paradigm: with no marker, one `ff_socket` builds BOTH the F-Stack and kernel stacks, dual-drives both, unified events; markers override to single-stack, compatible with v5; still gated by the `FF_KERNEL_COEXIST` compile macro + runtime `kernel_coexist` dual-layer switch)
> **Date**: 2026-06-17
> **Status**: Drafting (v6 design)
> **Scope**: Navigation, terminology, and scope statement for the spec in this directory

---

## 0. v6 Background: from "per-fd either/or" to "automatic dual-stack" (must read)

v5 (commit ba148589d) already gated all `lib/` coexistence code under the compile macro `FF_KERNEL_COEXIST` (`lib/Makefile` off by default), forming a **compile-time + runtime dual-layer switch**, and measured byte-for-byte zero regression when off and per-fd coexistence usable when on (real-machine perf in `10`). The v5 semantics are **per-fd either/or**:

- `ff_socket(type|SOCK_KERNEL)` → builds **only** a kernel fd, returns `ff_kernel_fd_encode(host_fd)` (≥`FF_KERNEL_FD_BASE`);
- otherwise → builds **only** an F-Stack fd (raw fd).

**v6 upgrades the default semantics to "automatic dual-stack"**: when `FF_KERNEL_COEXIST` is compiled in **and** `config.ini [stack] kernel_coexist=1` —

- **Default (no marker) = dual-stack**: one `ff_socket` builds BOTH an F-Stack fd and a kernel host fd, registers `ff_native_fd_map[fstack_fd]=host_fd`, and **returns the F-Stack raw fd**; `ff_bind/ff_listen/ff_close/ff_connect` etc. **dual-drive both stacks** on that dual-stack fd — **one `listen(80)` listens on both the F-Stack (DPDK) and Linux kernel stacks simultaneously**. Local `curl 127.0.0.1:80` and remote access to `:80` via the DPDK NIC are both reachable, with no marker required.
- **Marker single-stack override (compatible with v5)**: `type|SOCK_KERNEL` = kernel only; `type|SOCK_FSTACK` = F-Stack only.
- **Zero regression**: macro off **or** `kernel_coexist=0` **or** `SOCK_FSTACK` → byte-for-byte zero regression (the original F-Stack path).

> **Implementation-status note (anti-speculation)**: v6's native map `ff_native_fd_map` and the default dual-build/dual-drive logic are **NOT yet landed in `lib/`** (grep confirms `lib/` has no `ff_native_fd_map`). This directory's v6 docs are the **upgraded design**; they explicitly distinguish "v5 already measured/landed" from "v6 to-be-implemented design" and must not present any v6 behavior as a fait accompli.

> **v3 historical mistake (reverted)**: v3 routed `ff_socket(SOCK_KERNEL)` to `ff_host_socket()` → raw host `socket()`, completely bypassing F-Stack — a fundamental mistake, reverted (commit 0748eff94). v6's "dual-stack" is never a bypass: F-Stack is always built and always present; the kernel stack is a **parallel additional** second stack.

---

## 1. One-Sentence Goal

Let an F-Stack application be **dual-stack by default**: the same socket/listen works on BOTH the F-Stack user-space stack (DPDK+FreeBSD, business fast path) and the host Linux kernel stack — local `ping`/`curl`/`ssh` reach the kernel-stack side, remote peers reach the F-Stack side via the DPDK NIC, and both stacks' events are sent/received in the **same epoll/event loop** — **F-Stack is always present, never replaced by a side path**; use `SOCK_KERNEL`/`SOCK_FSTACK` markers to override to single-stack when needed.

## 2. Scope Statement (Important)

- **This feature = automatic dual-stack coexistence**: with no marker, F-Stack + kernel dual-stack, dual-drive, unified events; markers override to single-stack.
- **Compile-macro gating (outermost)**: all coexistence code is gated by `FF_KERNEL_COEXIST`, **commented off by default** in `lib/Makefile`; when off, coexistence code is not compiled and is byte-for-byte zero regression vs. upstream.
- **Runtime switch**: `config.ini [stack] kernel_coexist` (effective only when the macro is on), `=1` enables automatic dual-stack, `=0` degrades to pure F-Stack (zero regression).
- **Selection markers**: `SOCK_KERNEL` (kernel only) / `SOCK_FSTACK` (F-Stack only) override the default dual-stack.
- **Hook mode (cross-reference baseline)**: `adapter/syscall`'s `FF_KERNEL_EVENT` already supports "app ON F-Stack + epoll dual-build merge + close linkage", **but socket/listen are NOT dual-built** (kernel listen requires explicit `SOCK_KERNEL`). The native v6 divergence = socket/bind/listen/connect **are also auto dual-built / dual-driven**.
- **Explicitly excluded**:
  - Do **not** create a side socket that bypasses F-Stack (v3 `ff_host_socket` raw bypass deprecated).
  - Do **not** add an anti-F-Stack "whole-process default-to-kernel" switch (v3 `default_stack=kernel` deprecated).
  - Do **not** create an `ff_local_*` dual API / mTCP-like dual namespace.
  - Do **not** do gazelle-style thread-level selection (F-Stack multi-process relies on different config files).
  - Do **not** adopt KNI/`rte_kni`/virtio-user packet reinjection (boundary clarification only).

## 3. Reading Path

| Order | Document | Purpose |
|---|---|---|
| 1 | `01-requirements-spec.md` | Requirements and goals/non-goals (auto dual-stack + marker single-stack override) |
| 2 | `02-current-state-analysis.md` | v5 measured state + native vs hook isomorphism/divergence table + v6 map gap |
| 3 | `03-external-research.md` | External research (with URLs, low-trust corroboration) |
| 4 | `04-architecture-design.md` | Dual-drive data flow + fd tri-state routing + dual-stack events + map |
| 5 | `05-interface-design.md` | socket/bind/listen/connect/accept/close/epoll_* dual-stack contracts + marker semantics + connect draft + exception matrix |
| 6 | `06-milestones.md` | R6→R7 automatic dual-stack milestones |
| 7 | `07-test-spec.md` | cmocka dual-mode cases + real-machine dual-stack plan |
| 8 | `08-review-gate.md` | Gate conclusion (v6 R7 "pending measurement") |
| 9 | `09-impl-plan.md` | Per-file rework steps |
| 10 | `10-perf-baseline-report.md` | No-regression criteria of dual-stack on the F-Stack fast path |

## 4. Glossary

| Term | Meaning |
|---|---|
| F-Stack stack | DPDK PMD + user-space FreeBSD protocol stack (business fast path, **always present**) |
| Kernel stack | Host Linux kernel network protocol stack (local/management/client to local or external kernel services) |
| **Automatic dual-stack (v6)** | With no marker, one `ff_socket` builds both an F-Stack fd and a kernel host fd; each `ff_*` dual-drives both stacks |
| **Dual-stack fd (v6)** | The F-Stack raw fd returned to the app, mapped to one kernel host fd in `ff_native_fd_map` |
| **native map (v6, to-be-implemented)** | `ff_native_fd_map[fstack_fd]=host_fd` (`ff_host_interface.c`, 65536 entries), modeled on adapter `fstack_kernel_fd_map` |
| Managed kernel fd (kernel-only) | `ff_kernel_fd_encode(host_fd)` (≥`FF_KERNEL_FD_BASE`=0x40000000), returned by `SOCK_KERNEL` or a kernel-side accepted connection; no map entry |
| `FF_KERNEL_COEXIST` | **Compile macro** gating whether all coexistence code is compiled; off by default (commented) in `lib/Makefile` (compile-time switch) |
| Selection marker | `SOCK_KERNEL`(0x02000000)/`SOCK_FSTACK`(0x01000000) on socket `type`, single-stack override of the default dual-stack (wrapped by `FF_KERNEL_COEXIST`, opt-in) |
| Coexistence-capability switch | `config.ini [stack] kernel_coexist`, **runtime** enabling of automatic dual-stack (effective only when the macro is on) |
| fd tri-state routing | `ff_is_kernel_fd(fd)`(≥BASE)=kernel only; else the F-Stack path, and if `ff_native_map_get(fd)>0` also dual-drive host_fd |
| Unified events | External epoll style; internally merges F-Stack kqueue events + kernel epoll events (a dual-stack listen is registered once on each stack) |
| Hook mode | LD_PRELOAD takes over the POSIX API (`ff_hook_*`) + `FF_KERNEL_EVENT`; epoll dual-build merge, socket/listen NOT dual-built |
| Native mode | The app directly calls `ff_*` (`ff_api.h`) + the `ff_run` main loop; v6 implements automatic dual-stack |

## 5. Sources

- F-Stack actual code (`lib/`, `adapter/syscall/`, `app/nginx-1.28.0/`) — **highest priority; on conflict, code is authoritative**.
- F-Stack three-tier architecture docs and knowledge graph (`docs/`), `adapter/syscall/README.md`.
- Public external materials (GitHub/technical blogs, etc.), all with accessible URLs in `03`, **low-trust corroboration only**.
