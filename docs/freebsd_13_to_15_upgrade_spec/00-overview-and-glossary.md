# 00 — Project Overview and Glossary

> Chinese version: ./zh_cn/00-overview-and-glossary.md
>
> Document language: English (translated from zh_cn v0.1)
> Series root directory: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-26)

---

## 1. One-line Project Definition

Upgrade the **FreeBSD 13.0-RELEASE** kernel network stack and the matching user-space tool set that the **F-Stack** project currently depends on, all the way to **FreeBSD 15.0-RELEASE**, and produce an English Spec document set that engineering teams and downstream AI agents can execute directly.

> This Spec phase only produces documents and does not modify code; the actual code migration is executed by the subsequent phases defined in `05-implementation-plan.md`.

---

## 2. Project Background

F-Stack is the project that detaches the FreeBSD kernel network stack and runs it in DPDK user-space:

- **Idea**: extract a subset of FreeBSD `sys/` (kern / net / netinet / netinet6 / netipsec / netgraph / vm / libkern / opencrypto / ...), use a set of glue files (`ff_*.c`) to replace the parts that are tightly coupled to the host kernel (VFS / process / signal / kvm / AIO / RACCT / kpilite / unmapped mbuf / extpg / SWI taskqueue, etc.), and then use DPDK to provide NIC I/O and lcore multi-threading, so that the network stack runs as a single-process library (`libff`).
- **Status quo**: the current FreeBSD upstream version that F-Stack aligns with is **13.0-RELEASE-p2** (verified via `/data/workspace/freebsd-src-releng-13.0/sys/conf/newvers.sh`).
- **Driving force**: FreeBSD 15.0-RELEASE was officially released in 2025 (`REVISION=15.0 BRANCH=RELEASE-p9`), spanning 6 versions in between (14.0/14.1/14.2/14.3/14.4). Many P0-grade KBI/KPI breakages happened between the two versions (pr_usrreqs merge / inpcb migrated to SMR / if_t opaque-ization / mbuf field adjustments / netlink added / mips removed / RACK as default), and at the same time the clang/llvm toolchain was upgraded from 11.x to 19.x. Staying on 13.0 will increasingly diverge from upstream security/performance/driver support.

---

## 3. Scope Boundary

### 3.1 IN-SCOPE (covered by this Spec series)

| Scope | Measured size |
|---|---|
| `f-stack/freebsd/` (kernel-stack carved subset) | 25 top-level subdirectories; **102 file diffs** vs the 13.0 baseline backup, with ~50 files actually adapted |
| `f-stack/tools/` (user-space tools, F-Stack-ized) | 22 top-level subdirectories; **163 file diffs** vs the 13.0 baseline backup |
| `ff_*.c` and `ff_*.h` inside `f-stack/lib/` (glue files) | **30 `.c` + 14 `.h` = 44 files** (delineated by `FF_SRCS+FF_HOST_SRCS` in `f-stack/lib/Makefile`) |

### 3.2 OUT-OF-SCOPE (NOT covered by this Spec series)

| Scope | Reason for exclusion |
|---|---|
| Actual code migration and build verification | Spec phase only; later phases are tracked separately |
| Performance benchmarks / stress tests | No binary is built; no tests are run |
| Git commit / push | Only working-tree files are written |
| English Spec | (Note: this is now satisfied by the English-translation pass; original v0.1 only delivered the Chinese version) |
| "Capability extension" ports for FreeBSD 15.0 new capabilities (e.g. netlink port, ML-KEM post-quantum crypto, inotify, post-quantum TLS) | This pass only does "alignment", not "capability extension"; new capabilities are listed in "Future Enhancement Suggestions" only |
| F-Stack `adapter/syscall/` (LD_PRELOAD ring IPC part) | Has no direct dependency on the FreeBSD kernel upgrade; covered by an independent spec series `docs/ld_preload_ring_spec/` |

---

## 4. Three Source Roots (verified)

| Path | Role | Version |
|---|---|---|
| `/data/workspace/freebsd-src-releng-13.0/` | Community FreeBSD 13.0 full source | `REVISION=13.0 BRANCH=RELEASE-p2` |
| `/data/workspace/freebsd-src-releng-15.0/` | Community FreeBSD 15.0 full source | `REVISION=15.0 BRANCH=RELEASE-p9` |
| `/data/workspace/f-stack/` | F-Stack project root | Adapted from freebsd-13.0 |

### 4.1 13.0 original backup (already exists, read-only baseline)

`/data/workspace/freebsd-src-releng-13.0/f-stack-lib/`
- `f-stack-lib/freebsd/` — 25 subdirectories, mirroring F-Stack `freebsd/` top-level
- `f-stack-lib/tools/` — 22 subdirectories, mirroring F-Stack `tools/` top-level

### 4.2 15.0 original backup (created in Phase 1.4)

`/data/workspace/freebsd-src-releng-15.0/f-stack-lib/`
- `f-stack-lib/freebsd/` — 24 subdirectories + Makefile (23 freebsd-native + new netlink, missing mips)
- `f-stack-lib/tools/` — 22 subdirectories (12 freebsd-native + 3 f-stack-shipped tool placeholders + 2 f-stack-lib helper directories + 5 helper files)
- `f-stack-lib/INVENTORY.md` — full inventory

---

## 5. Glossary

| Term | Chinese | Explanation |
|---|---|---|
| **F-Stack** | F-Stack | Tencent open-source high-performance networking framework that runs the FreeBSD network stack in DPDK user-space |
| **`f-stack-lib/`** | 13.0/15.0 original backup | Unmodified subset of freebsd-src copied at F-Stack initialization; serves as the baseline for diff and upgrade |
| **`ff_*.c` / `ff_*.h`** | F-Stack glue files | F-Stack-implemented wrappers that replace host kernel facilities (44 files in total) |
| **`FSTACK-stub`** | F-Stack short-circuit stub | Adaptation pattern: wrap the function body with `#ifndef FSTACK` to short-circuit to an empty implementation |
| **`FSTACK-altimpl`** | F-Stack alternate implementation | Adaptation pattern: `#ifdef FSTACK ... #else` switches to a different implementation |
| **`IPC-replace`** | IPC takeover | tools-side adaptation pattern: replace raw socket / sysctl with `ff_ipc_*` to talk to the f-stack instance |
| **`FSTACK_ZC_SEND`** | F-Stack zero-copy send | A zero-copy send-path macro added by F-Stack in `uipc_mbuf.c` |
| **DPDK** | Data Plane Development Kit | Intel open-source user-space network driver framework, F-Stack's runtime base |
| **KPI** | Kernel Programming Interface | Source-level kernel API (function signatures, macros) |
| **KBI** | Kernel Binary Interface | Binary-level kernel API (struct layout, syscall table) |
| **VNET** | Virtualized Network Stack | FreeBSD's network-stack virtualization mechanism |
| **SMR** | Safe Memory Reclamation | Mechanism used by FreeBSD 14/15 to replace some epoch scenarios |
| **`pr_usrreqs`** | Protocol user-request vector table | 13.0-era socket protocol interface; 15.0 has merged it into `struct protosw` |
| **`if_t`** | ifnet opaque access handle | 13.0 already has `typedef struct ifnet * if_t;` in `sys/net/if_var.h` but kernel APIs still expose `struct ifnet *`; 15.0 lifts the typedef up to `sys/net/if.h` (still `typedef struct ifnet *if_t`, **not** `void *`), changes kernel APIs such as `if_alloc()` to use `if_t`, and provides `if_get*/if_set*` accessors. "Opaque-ization" is API-contract semantics: external code should operate via accessors and should not depend on field layout. See `03-freebsd-15-changes.md §3.3`. |
| **inpcbgroup** | inpcb group hash | 13.0 protected by epoch; 15.0 switched to SMR |
| **netlink (FreeBSD)** | netlink-compatible subsystem | New in 15.0 (actually introduced in 14.0); a Linux netlink compatibility layer at sys/netlink/ |
| **RACK** | Recent ACKnowledgment | TCP retransmission stack default-enabled in FreeBSD 14/15 |
| **mips** | MIPS architecture | Removed from base in 14.0; affects F-Stack `freebsd/mips/` subdirectory |
| **`__FreeBSD_version`** | FreeBSD version macro | 13.0 = `1300139`; 15.0 = `1500068` |
| **`SYS_MAXSYSCALL`** | Highest syscall number | 13.0 = 580; 15.0 = 599 (13→15 net additions: 22 + deletions: 3; representative additions: `fspacectl`, `kqueuex`, `membarrier`, `timerfd_create/gettime/settime`, `inotify_add_watch_at`, `inotify_rm_watch`, `jail_remove_jd`, etc.; deletions: `gssd_syscall`, `sbrk`, `sstk`. Full list in `03-freebsd-15-changes.md` §2.4) |
| **pkgbase** | base-system packaging | An optional 15.0 release form, unrelated to F-Stack |
| **`m_pkthdr` / `m_ext`** | mbuf header / external storage pointer | Field adjustments between 14→15 |
| **`mb_unmapped_*` / `pcpu_page_alloc`** | unmapped mbuf path | Host VM dependencies that F-Stack masks out |
| **`kpilite.h`** | KPI lite header | Masked by F-Stack to avoid dependency on host module subsystem |
| **`libff`** | F-Stack user-space library | Static library compiled from `ff_*.c` plus the linked-in freebsd `*_SRCS` |
| **`KERN_SRCS` / `NET_SRCS` / `NETINET_SRCS` ...** | F-Stack Makefile link lists | Source-file lists in `f-stack/lib/Makefile` deciding "which freebsd source files actually participate in libff compilation" |
| **Milestones M1-M5** | M1=infrastructure / M2=kern / M3=network stack / M4=edge subsystems / M5=tools+ff_* | See `05-implementation-plan.md` |
| **P0 / P1 / P2 / P3** | Risk / priority tags | P0 must-fix blocking compile/run; P1 compiles but semantics need verification; P2 non-critical path; P3 informational |

---

## 6. Relationship with Existing F-Stack Documents

| Existing doc | How this Spec series reuses it |
|---|---|
| `docs/01-LAYER1-ARCHITECTURE.md` | Reused for source-tree panorama (in `02-architecture-analysis.md`) |
| `docs/F-Stack_Architecture_Layer1_System_Overview.md` | Reused for system-layer architecture diagram (same as above) |
| `docs/F-Stack_Architecture_Layer2_Interface_Specification.md` | Reused for interface inventory (same as above) |
| `docs/KNOWLEDGE_GRAPH_WIKI.md` | Reused for dependency graph (same as above) |
| `docs/ld_preload_ring_spec/` | **Not reused**: the LD_PRELOAD ring IPC is an independent workstream |
| `adapter/syscall/README.md` | **Not directly reused**: but `ff_syscall_wrapper.c` is the intersection point and is referenced in `02-architecture-analysis.md` §3 |

---

## 7. 8 Core Decisions (locked, confirmed via multi-round q&a in `plan.md`)

| # | Decision | Outcome | Locked-in document |
|---|---|---|---|
| 1 | Spec output directory | `f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/` (English version added later, flat under parent) | plan.md §0 |
| 2 | Coverage scope | Full f-stack/freebsd + full f-stack/tools + 30 .c + 14 .h under f-stack/lib | plan.md §1.5 |
| 3 | Risk-record granularity | Full-set major changes for 13→14 plus 14→15 | plan.md §4 |
| 4 | Execution mode | Hybrid Agent Team: Leader in main dialogue + 3 code-explorer subagents in parallel | plan.md §2 |
| 5 | Disposition of mips/ | Skipped; not pulled into the 15.0 backup; the 04-diff phase plans to delete `f-stack/freebsd/mips/` | INVENTORY.md / plan.md Step 1.4 |
| 6 | Disposition of netlink/ | Pulled into the 15.0 backup; spec DP-2 decides **not to introduce it into** `f-stack/freebsd/` for now (alignment only, no capability extension) | INVENTORY.md / plan.md §4.2 DP-2 |
| 7 | Disposition of f-stack-shipped tools (knictl/traffic/top) | Placeholder-copied from the 13.0 backup; their upgrade is tracked under the dedicated milestone M5 | INVENTORY.md |
| 8 | Copy strategy | `cp -a` preserves mtime / permissions / symlinks | INVENTORY.md |

---

## 8. Reading-Order Suggestions

| Role | Order |
|---|---|
| Project manager / architecture reviewer | 00 → 01 → 05 → 06 → 99 |
| Implementation engineer | 00 → 03 → 04 → 05 → 02 |
| Downstream AI agents (task pickup) | 04 → 05 → 02 → 06 |
| Risk auditor | 01 → 03 → 99 |

---

## 9. Document Metadata

- **Author**: Agent Team Leader (executed inside the main dialogue)
- **Collaboration**: Sub-Agents A/B/C (completed via code-explorer subagents)
- **Review**: Reviewer (issued `99-review-report.md` on 2026-05-26; supplemented independent audit v0.2 `98-independent-audit-report.md` and 6 must-fix revisions on 2026-05-28)
- **Verification**: all numeric figures come from measured command output; non-measured inferences are tagged with their source in the "7. 8 Core Decisions" table at the end
- **Next step**: read `01-requirements-spec.md` to learn what specific problems this upgrade solves / does not solve
