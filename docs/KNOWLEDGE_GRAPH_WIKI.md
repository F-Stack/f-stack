# F-Stack Knowledge Graph Wiki

> Auto-extracted from the GitNexus knowledge graph (schema v1) plus manual cross-checking against current source. **Indexed: 2026-06-08T03:37:02Z, commit `208b0c4`** (`dev` branch, post FreeBSD 13.0 → 15.0 first-stage upgrade including M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS).

---

## 1. Project Overview

| Metric | Data |
|--------|------|
| Indexed files | 2,656 |
| Symbol nodes | 64,855 |
| Relation edges | 113,858 |
| Function clusters | 981 (communities) |
| Execution flows | 300 (processes) |
| Embedding nodes | 0 (semantic search not enabled this round) |
| Effective scope | F-Stack source surface only (DPDK / FreeBSD vendored trees excluded by gitnexus 1.6.5 schema) |
| Indexer | gitnexus 1.6.5 (ladybugdb provider; FTS available, vector search disabled) |

> **Schema migration note**: prior wiki snapshots (commit `a695757`, indexed 2026-04-09) reported 25,723 files / 710,596 nodes under gitnexus 1.5.x, which counted vendored FreeBSD/DPDK trees in some node categories. Schema v1 now correctly restricts the graph to the F-Stack-authored surface; the dramatic count drop is **a measurement-scope correction, not a code regression**.

> **Detailed node-type / named-cluster breakdown unavailable**: schema v1 `meta.json` only exposes top-level totals. Earlier per-type tables (Macro / Function / Property / …) and named-cluster tables (Net / Netinet / Tcp_stacks / …) were schema-v0 outputs produced via LLM enrichment. Regenerating them requires running `npx gitnexus wiki` with an LLM API key (not configured this round). To re-derive the equivalent taxonomy without LLM, query the underlying ladybugdb directly under `.gitnexus/lbug` or refer to the authoritative subsystem grouping in `docs/freebsd_13_to_15_upgrade_spec/02-architecture-analysis.md`.

---

## 2. F-Stack 13.0 → 15.0 Upgrade Delta Map

This index has been rebuilt **after** the first-stage 13.0 → 15.0 upgrade. The graph therefore reflects:

| Area | Where reflected in the graph |
|------|------------------------------|
| 33 `lib/*.c` files (17 newly authored / re-platformed since 13.0) | `lib/` folder & file nodes; new bank `lib/ff_stub_14_extra.c` (799 LoC, M5 + runtime-fix landing point) |
| 14.0+ KBI/KPI deltas (`pr_usrreqs` merged into `protosw`; `if_t` opaquification; `rt_alloc` 3rd-arg signature; `rt_ifmsg` rtbridge dispatch; 8-category 14.0+ ABI deltas) | Edges between `lib/ff_glue.c`, `lib/ff_route.c`, `lib/ff_veth.c`, `lib/ff_kern_timeout.c`, `lib/ff_lock.c`, `lib/ff_syscall_wrapper.c` and the new central stub bank |
| 5 P0 SIGSEGV runtime-fix landing points (UMA `UMA_USE_DMAP`, `smr_create %gs` barrier, `rt_ifmsg` NULL, `ff_veth_setaddr` ENOBUFS, `kern_accept` `badfileops`) plus 1 defensive `vm_page_alloc_noobj` panic | Files `freebsd/{amd64,arm64}/include/vmparam.h`, `freebsd/amd64/include/atomic.h`, `freebsd/kern/kern_descrip.c`, `lib/Makefile`, `lib/ff_stub_14_extra.c` |
| Architecture removal: `freebsd/mips/` (synced to FreeBSD 14.0 upstream removal) | mips arch nodes are absent from the F-Stack graph; remaining `mips` strings live only in `freebsd/contrib/device-tree/` (DTS, not compiled) |
| New header-only subsystem port: `freebsd/netlink/` (18 `.h`, 0 `.c`, 0 `SRCS`) — DP-2 "no NETLINK protocol port" | netlink folder node has zero outbound CALL edges into F-Stack libraries |
| Routing FIB rework subdir: `freebsd/net/route/` (22 files: `nhop`, `fib_algo`, `route_ctl`) | New cluster of route_ctl nodes connected from `lib/ff_route.c` and `lib/ff_stub_14_extra.c` |
| TCP stacks modularization (`-DMODNAME=tcp_rack -DSTACKNAME=rack`); F-Stack H-5 module rename `tcp_rack_fstack` re-applied | `freebsd/netinet/tcp_stacks/` (11 files including `rack.c` ~759 KB, `bbr.c` ~444 KB) |

For evidence-level traceability of each delta, see the upgrade spec series: `docs/freebsd_13_to_15_upgrade_spec/{00-overview-and-glossary, 01-requirements-spec, 02-architecture-analysis, 03-freebsd-15-changes, 04-diff-and-port-strategy, 05-implementation-plan, 06-test-and-acceptance-spec}.md`, the milestone logs `M1~M5-execution-log.md`, the `runtime-fix-execution-log.md`, the `rib-fix-plan.md`, and the dual baselines (`13.0-baseline-cvm-bench-report.md` + `physical-machine-bench-report.md`).

---

## 2A. Post-index code delta: `FF_KERNEL_COEXIST` kernel-stack coexistence

> **Manual addendum (not yet re-indexed)**: the graph above was indexed at commit `208b0c4` (2026-06-08). The `feature/1.26` branch has since landed the **`FF_KERNEL_COEXIST` automatic dual-stack coexistence** feature (commits `ba148589d` → `55a84f313`), the **R9** increment (kqueue/kevent coexistence + IPv6 `IPV6_V6ONLY`), and the **R10** increment (`ff_readv`/`ff_writev`/`ff_ioctl` kernel-fd routing + `ff_dup`/`ff_dup2`). The surface below is documented manually against current source until the next `npx gitnexus analyze`.

The feature lets a single process serve a listener over both the F-Stack user-space stack (via the DPDK NIC) and the host Linux kernel stack (via loopback / the management NIC) from one event loop — either `ff_epoll_wait` or, since R9, `ff_kqueue`/`ff_kevent`. It is **off by default** (compile-time macro + runtime `kernel_coexist` switch), and when off the default / `SOCK_FSTACK` path is byte-for-byte unchanged.

| Area | Where in source |
|------|-----------------|
| Build & runtime gating (default OFF) | `lib/Makefile` L174-177 injects `-DFF_KERNEL_COEXIST` into both `CFLAGS` and `HOST_CFLAGS`; runtime `config.ini [stack] kernel_coexist=0` default (`ff_config.c` L1027-1033 parse / L1366 default; `ff_config.h` L321-325 `stack` struct) |
| Managed kernel-fd space | `lib/ff_host_interface.h` L113-128: `FF_KERNEL_FD_BASE 0x40000000` + inline `ff_is_kernel_fd / ff_kernel_fd_encode / ff_kernel_fd_real`; a managed kernel fd = `host_fd + 0x40000000`, which never collides with FreeBSD fds (`kern.maxfiles <= 65536`) |
| Dual-stack fd map | `lib/ff_host_interface.c` L257-278: `ff_native_fd_map[65536]` + `ff_native_map_get/set/clear` (single-threaded per F-Stack instance) |
| 32 host-stack bridges | `lib/ff_host_interface.c` (`ff_host_socket` … `ff_host_getsockname`), declared `lib/ff_host_interface.h` — each a thin passthrough to host libc. **R9 added 3**: `ff_host_set_v6only` (`setsockopt IPV6_V6ONLY`), `ff_host_kqueue_ctl`, `ff_host_kqueue_poll` (the latter two service the kqueue↔host-epoll coexistence path). **R10 added 5**: `ff_host_readv`, `ff_host_writev`, `ff_host_ioctl` (raw Linux request passed straight to host libc), `ff_host_dup`, `ff_host_dup2` |
| Per-socket stack markers | `lib/ff_api.h` L95-100: `SOCK_FSTACK 0x01000000`, `SOCK_KERNEL 0x02000000`; priority: per-socket marker > config `kernel_coexist` > F-Stack |
| Entry routing | `lib/ff_syscall_wrapper.c`: `ff_socket` dual-create (L916-958; on `AF_INET6` dual-build calls `ff_host_set_v6only(hfd)` at L952 so the host IPv6 socket is `IPV6_V6ONLY` and coexists with the same-port host IPv4 socket — R9/P1); kernel-fd hot-routes + dual-stack map dual-drive across `socket/bind/listen/connect/accept[4]/close/read/write/recv*/send*/sendmsg/recvmsg/getpeername/getsockname/shutdown/setsockopt/getsockopt/fcntl`. `LINUX_IPV6_V6ONLY 26`→`IPV6_V6ONLY` translation at L620-621. **R10 added kernel-fd routing: `ff_readv` / `ff_writev` / `ff_ioctl` / `ff_dup` / `ff_dup2`** (see the R10 row below) |
| Unified epoll | `lib/ff_epoll.c` (289 L): `ff_epoll_pairs[64]{kq, host_ep}` lazily pairs one host epoll fd per kqueue; `ff_epoll_ctl` routes kernel fds to the host epoll / dual-registers dual-stack fds; `ff_epoll_wait` polls the host epoll (non-blocking) then merges kqueue events. `ff_epoll_pairs_lock` removed — single-threaded model (commit `3e71f4699`). `ff_epoll_host_ep` promoted from `static` to a shared symbol (declared `ff_host_interface.h` L139) so the kqueue path reuses the same pairing table |
| Unified kqueue/kevent (R9/P2) | `lib/ff_syscall_wrapper.c`: `ff_kqueue` (L1895) + `ff_kevent` (L2050) now coexist symmetrically with epoll. `ff_kevent` changelist → `ff_kevent_host_change` (L2006) registers kernel/dual-stack-fd `EVFILT_READ/WRITE` into the kqueue-paired host epoll via `ff_host_kqueue_ctl` (kernel-only changes are NOT forwarded to the F-Stack kqueue; dual-stack fds are still forwarded); eventlist → `ff_kevent_host_wait` (L2034) polls the host epoll via `ff_host_kqueue_poll` (`timeout=0`), synthesizes `struct kevent` (`ident`=app-side fd, `EV_EOF`↔`EPOLLHUP|ERR`), then merges `ff_kevent_do_each` F-Stack events. Fixes the `example/main.c` kqueue model: kernel-side `curl 127.0.0.1:80` measured **200 size=438** (was 000). Known limit: kernel fds via kqueue support `EVFILT_READ/WRITE` only |
| Residual-entry coexistence (R10) | `lib/ff_syscall_wrapper.c`: `ff_ioctl` (L1067) kernel fd uses the **raw Linux request** passed straight to `ff_host_ioctl` (NOT via `linux2freebsd_ioctl`, because `_IO/_IOR/_IOW(type,nr,size)` encodings differ between Linux and FreeBSD; dual-stack fd same-driver since R10.1 syncs `FIONBIO`/`FIOASYNC` to the paired host fd (query ioctls like `FIONREAD` not forwarded, to avoid clobbering argp)); `ff_readv` (L1189)/`ff_writev` (L1251) kernel fd via `ff_host_readv/writev` (mimic `ff_read/write`, connection fds single-stack hot path); `ff_dup` (L2130) kernel fd → `ff_host_dup`+encode; `ff_dup2` (L2156) both-kernel → `ff_host_dup2`+encode, **cross-stack (one kernel, one F-Stack) rejected `errno=EINVAL`**. **Known limits**: `ff_select` (encode kernel fd ≥ `0x40000000` ≫ `FD_SETSIZE`(1024), cannot fit in `fd_set` — hard limit) and `ff_poll` (merge complexity/regression risk, conservatively not implemented) — use `ff_epoll_*`/`ff_kqueue` (R9) for kernel-fd multiplexing |

Traceability: `docs/kernel_event_support_spec/` and `docs/kernel_event_support_spec/zh_cn/` (00-10), including the R8 review-gate logs, the R9 plan `plan-r9-kqueue-coexist-ipv6.md` and the R10 plan `plan-r10-readv-writev-ioctl-coexist.md`.

---

## 3. Directory Structure

```
f-stack/
├── lib/            # F-Stack core library (33 .c files; ff_stub_14_extra.c is the central 14.0+ stub bank)
├── adapter/        # LD_PRELOAD adaptation layer (syscall hook, micro_thread bridge)
├── app/            # Integrated applications (nginx-1.28.0/, redis-6.2.6/)
├── example/        # Example programs (helloworld, helloworld_epoll, main_zc.c zero-copy)
├── tools/          # User-space ports of ifconfig / netstat / arp / route
├── mk/             # Build system (Makefile include files)
├── doc/            # Original upstream documentation
├── docs/           # 3-tier architecture knowledge base + LD_PRELOAD Ring IPC spec + 13.0→15.0 upgrade spec
├── dpdk/           # DPDK 24.11.6 LTS submodule (upgraded from 23.11.5 on 2026-06-09; excluded from gitnexus indexing)
└── freebsd/        # FreeBSD 15.0 kernel source port (excluded from gitnexus indexing)
```

### 3.1 Core Library Files (`lib/`)

The 33 `.c` files in `lib/` (verified by direct read) group into six roles. Selected anchors below; full inventory and verified line counts in `docs/F-Stack_Architecture_Layer3_Function_Index.md` §"lib/ file index" and `docs/freebsd_13_to_15_upgrade_spec/docs-sync-2026-06-08-update-matrix.md` §1.2.

| Role | Representative files |
|------|----------------------|
| Public API & init | `ff_api.h`, `ff_init.c` (70 L), `ff_init_main.c` (~660+ L), `ff_freebsd_init.c` (~154 L) |
| Configuration | `ff_config.c` (1,694 L; incl. `[stack] kernel_coexist` parse), `ff_ini_parser.c` (3rd-party inih) |
| DPDK adapter | `ff_dpdk_if.c` (2,907 L; `main_loop` lives here), `ff_dpdk_kni.c` (~441 L), `ff_dpdk_pcap.c` (~118 L) |
| Linux→FreeBSD glue | `ff_glue.c` (1,467 L), `ff_syscall_wrapper.c` (2,265 L; incl. `FF_KERNEL_COEXIST` entry routing + R9 `ff_kqueue/ff_kevent` coexistence + `IPV6_V6ONLY` + R10 `ff_readv/writev/ioctl/dup/dup2` kernel-fd routing), `ff_host_interface.c` (617 L; 32 `ff_host_*` host-stack bridges incl. R9 `ff_host_kqueue_ctl/poll` + `ff_host_set_v6only`, R10 `ff_host_readv/writev/ioctl/dup/dup2`, + `ff_native_fd_map`), `ff_host_interface.h` (187 L), `ff_epoll.c` (289 L; unified F-Stack + kernel epoll, `ff_epoll_host_ep` shared with the kqueue path), `ff_compat.c` (~360 L) |
| Kernel emulation (libplebnet/libuinet derived) | `ff_kern_condvar.c`, `ff_kern_environment.c` (509 L), `ff_kern_intr.c` (108 L), `ff_kern_subr.c` (271 L), `ff_kern_synch.c` (132 L), `ff_kern_timeout.c` (1,266 L; callout subsystem), `ff_lock.c` (448 L; sx/mutex/lockmgr), `ff_log.c` (111 L), `ff_memory.c` (481 L), `ff_subr_epoch.c` (83 L; verify-only), `ff_subr_prf.c` (604 L), `ff_thread.c` (51 L), `ff_vfs_ops.c` (117 L) |
| Networking & netgraph | `ff_route.c` (1,604 L; rtsock partial port + ff_rtioctl), `ff_veth.c` (1,132 L; if_t accessors rewrite at M4), `ff_ng_base.c` (3,887 L; full netgraph framework port), `ff_ngctl.c` (131 L) |
| **14.0+ stub bank (NEW)** | `ff_stub_14_extra.c` (799 L) — central bank for 14.0+ ABI gaps + landing point for 5 runtime-fix patches + defensive `vm_page_alloc_noobj` `panic()` |

### 3.2 Adapter Layer (`adapter/`)

The `adapter/syscall/` directory builds two binaries — `libff_syscall.so` (preloaded into the user application) and a standalone `fstack` instance — that together implement the LD_PRELOAD path. Key files:

| File | Responsibility |
|------|---------------|
| `syscall/ff_hook_syscall.c` / `.h` | LD_PRELOAD POSIX hooks (`socket / bind / connect / accept[4] / listen / close / read / write / send* / recv* / __read_chk / __recv_chk / __recvfrom_chk / ioctl / epoll_* / fork`), dispatched to `ff_*` via shared memory |
| `syscall/ff_linux_syscall.c` / `ff_declare_syscalls.h` | Linux-flag → FreeBSD-flag translation (e.g. `LINUX_SOCK_CLOEXEC`, `LINUX_SOCK_NONBLOCK`) and hook declarations |
| `syscall/ff_socket_ops.h` / `.c` | Per-socket operation context (`sc`) and producer/consumer dispatch logic |
| `syscall/ff_sysproto.h` | Cross-boundary syscall argument struct definitions |
| `syscall/ff_so_zone.c` | Hugepage shared-memory zone management (semaphore IPC path) |
| `syscall/ff_event.c` / `ff_epoll.c` | Epoll adaptation (incl. polling mode) and event delivery |
| `syscall/ff_ring_ops.c` / `.h` *(FF_USE_RING_IPC)* | Lock-free DPDK SPSC `rte_ring` IPC path; replaces the `ff_so_zone` global lock |
| `syscall/Makefile` | Builds both `libff_syscall.so` and the `fstack` instance binary |

LD_PRELOAD-mode applications run as **two separate processes**: the `fstack` instance (links `libfstack.a` + DPDK) plus the user app preloaded with `libff_syscall.so`. The two communicate over Hugepage shared memory — sem-based by default, or a lock-free DPDK SPSC ring when `FF_USE_RING_IPC=1` is set. Compile / runtime switches `FF_KERNEL_EVENT`, `FF_MULTI_SC` and `FF_USE_RING_IPC` further tune behavior; full details in `adapter/syscall/README.md` and `docs/ld_preload_ring_spec/`.

---

## 4. Dependency Overview

```
                    ┌──────────────┐
                    │ Applications │
                    │ (Nginx 1.28, │
                    │  Redis 6.2.6)│
                    └──────┬───────┘
                           │ ff_* API
                    ┌──────▼───────┐
                    │   lib/       │
                    │  F-Stack Core│
                    └──┬───────┬───┘
                       │       │
              ┌────────▼──┐ ┌──▼────────┐
              │  FreeBSD  │ │   DPDK    │
              │  15.0 TCP/│ │ 24.11.6   │
              │  IP Stack │ │ (PMD/EAL) │
              └────────────┘ └──────────┘

  adapter/                    tools/
  LD_PRELOAD Hook ─────────►  ifconfig/netstat/arp/route
  (syscall redirect)          (user-space network tools)
```

### Relation Types

All relationships in the knowledge graph are of `CodeRelation` type (113,858 total in current index), covering:
- Function calls (CALL)
- Type references (USES_TYPE)
- Macro expansions (EXPANDS)
- File includes (INCLUDES)
- Struct member access (HAS_MEMBER)
- Community membership (BELONGS_TO)

---

## 5. Knowledge Graph Usage Guide

### Query Tools (via the GitNexus MCP server)

| Tool | Purpose | Example |
|------|---------|---------|
| `gitnexus_query` | Search execution flows by concept | "packet receive" |
| `gitnexus_context` | View 360° relationships of a symbol | All callers/callees of `ff_init` |
| `gitnexus_impact` | Pre-modification impact analysis | Impact radius of changing `lib/ff_dpdk_if.c` |
| `gitnexus_detect_changes` | Pre-commit change scope check | Verify impact of staged files |
| `gitnexus_rename` | Safe renaming | Batch rename across multiple files |
| `gitnexus_cypher` | Custom graph queries | Advanced analysis |

### Updating the Index

```bash
# Run from the repository root
cd /data/workspace/f-stack

# Check status
npx gitnexus status

# Re-index (incremental)
npx gitnexus analyze

# Force full rebuild
npx gitnexus analyze --force

# Regenerate the human-readable wiki (requires LLM API key in ~/.gitnexus/config.json)
npx gitnexus wiki --force
```

> **Auto-update**: a `post-commit` hook can re-run `npx gitnexus analyze` in the background after each commit; configure once in `.git/hooks/post-commit`.

> **Re-indexing duration**: full rebuild on the current 2,656-file F-Stack surface takes ~11 minutes on this workspace (verified 2026-06-08).

---

## 6. References

- **Upgrade evidence**: `docs/freebsd_13_to_15_upgrade_spec/` — full Markdown record of M0~M5, runtime-fix, Phase-5b, rib-fix, plus dual baselines.
- **3-tier architecture (this knowledge base)**: `docs/01-LAYER1-ARCHITECTURE.md` + `docs/F-Stack_Architecture_Layer1_System_Overview.md`; same for Layer 2 / Layer 3.
- **LD_PRELOAD Ring IPC spec**: `docs/ld_preload_ring_spec/`.

---

*Generated from GitNexus knowledge graph (64,855 nodes, 113,858 edges) — 2026-06-08, commit `208b0c4`. Schema v1 / ladybugdb provider.*
