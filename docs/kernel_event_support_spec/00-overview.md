# 00 Overview: F-Stack Connection-Level Stack Selection Enhancement (Single API + Markers + config default switch)

> **Document ID**: SPEC-KE-00
> **Version**: v3 (paradigm-correction rework)
> **Date**: 2026-06-15
> **Status**: Drafting
> **Scope**: Navigation, terminology, and scope statement for the Chinese spec in this directory

---

## 1. One-Sentence Goal

**Standardize F-Stack's existing "single API + `SOCK_KERNEL`/`SOCK_FSTACK` marker-based stack selection + glue-layer auto-adaptation" capability**, and add **one global default-stack switch** in config.ini; so that any F-Stack application can, **without switching to multiple API sets**, route certain fds to the host kernel stack (local `ping`/`curl` can directly reach their services, and the application as a client can also `connect` to local/external kernel-stack services via the kernel stack), while the remaining fds go to the F-Stack fast path.

## 2. Scope Statement (Important)

- **This feature = connection-level stack-selection enhancement**, where stack selection = **app marker (per-fd) + config.ini global default switch (per-process)**, with the glue layer adapting automatically.
- **Directly reuse the baseline**: the `SOCK_KERNEL`/`SOCK_FSTACK` marker-based stack selection of the `adapter/syscall` hook mode (`ff_hook_socket`/`ff_hook_connect`) + `FF_KERNEL_EVENT` dual-stack events.
- **Bidirectional coverage**: server side (kernel-stack listener directly accessible from local host) + **client side (`connect` to local/external kernel-stack services via the kernel stack, newly added)**.
- **Dual-mode coverage**: hook mode (already supported, directly reused) + native `ff_api` mode (add `ff_socket` marker recognition).
- **Explicitly excluded**:
  - Do **not** create a new `ff_local_*` dual API / mTCP-like dual namespace (the v2 approach is deprecated).
  - Do **not** do gazelle-style thread-level stack selection (the multi-process model relies on different config files).
  - Do **not** do config port/address lists (only one global default switch).
  - Do **not** adopt KNI/`rte_kni`/virtio-user/TAP/AF_XDP packet reinjection (boundary clarification only).

## 3. Reading Path

| Order | Document | Purpose |
|---|---|---|
| 1 | `plan.md` | Plan, team, gate, paradigm correction |
| 2 | `01-requirements-spec.md` | Requirements and goals/non-goals |
| 3 | `02-current-state-analysis.md` | Code current state of single API+markers / client / config / native mode (code is authoritative) |
| 4 | `03-external-research.md` | External solution research (with URLs) |
| 5 | `04-architecture-design.md` | Marker+config stack-selection architecture and bidirectional data flow |
| 6 | `05-interface-design.md` | Marker/config contracts and dual-mode adaptation |
| 7 | `06-milestones.md` | Milestones and coding work list |
| 8 | `07-test-spec.md` | Test and performance-baseline plan |
| 9 | `08-review-gate.md` | Review gate conclusion |

## 4. Glossary

| Term | Meaning |
|---|---|
| F-Stack stack | DPDK PMD + user-space FreeBSD protocol stack (business fast path) |
| Kernel stack | Host Linux kernel network protocol stack (local/management/client connecting to local or external kernel-stack services) |
| Stack-selection marker | `SOCK_KERNEL`(0x02000000)/`SOCK_FSTACK`(0x01000000) on socket `type`, per-fd stack selection |
| Global default-stack switch | A switch in config.ini that decides the default stack of this process (`[stack] default_stack`) |
| Glue auto-adaptation | The marker/config at creation time determines fd ownership, and subsequent syscalls are automatically routed via `is_fstack_fd`/`CHECK_FD_OWNERSHIP` |
| Hook mode | LD_PRELOAD takes over the POSIX API (`ff_hook_*`); marker-based stack selection already supported |
| Native mode | The application directly calls `ff_*` (`ff_api.h`); currently `ff_socket` does not recognize the markers (needs enhancement) |

## 5. Sources

- F-Stack actual code (`adapter/syscall/`, `lib/`, `app/nginx-1.28.0/`) — **highest priority; on conflict, code is authoritative**.
- F-Stack three-tier architecture docs and knowledge graph (`docs/`).
- Public external materials (GitHub/technical blogs, etc.), all with accessible URLs in `03`.
