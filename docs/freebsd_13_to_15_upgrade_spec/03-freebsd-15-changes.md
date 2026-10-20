# 03 — FreeBSD 13.0 → 14.x → 15.0 Key Changes Inventory

> Chinese version: ./zh_cn/03-freebsd-15-changes.md
>
> Series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-26)
> Data source: artifact from **Sub-Agent B (Analyzer-15)** + measured local dual-version source comparison
> Verification: every P0/P1 conclusion can be reviewed against local `/data/workspace/freebsd-src-releng-{13.0,15.0}/sys/`

---

## 0. One-line Conclusion

FreeBSD 13.0 → 15.0 spans 4 years and 6 releases (13.0 → 14.0 → 14.1 → 14.2 → 14.3 → 14.4 → 15.0). Multiple **core network-stack KBI/KPI breakages** sit between the two endpoints. F-Stack's `freebsd/` subtree **cannot be upgraded by simply patching**; it has to redo its "subset + adaptation" baseline on top of 15.0 `sys/` (i.e. re-apply the 9 adaptation patterns from `02-architecture-analysis.md` on the 15.0 baseline).

### 0.1 Two-axis priority convention (added 2026-05-28; addresses audit §6.2-1)

All `P0` / `P1` / `P2` / `P3` tags in this Spec series are used along **two independent axes**; when cross-referencing across documents, the reader must be clear about which axis is meant:

| Axis | Meaning | Determining factor |
|---|---|---|
| **Risk level** | How severely the upstream change breaks F-Stack | Whether KBI/KPI is broken; scope and recoverability; the *fact* axis |
| **Task priority** | How urgent the task is in the implementation schedule | Whether it blocks other milestones; whether it is mandatory cleanup; the *schedule* axis |

The two **can be independent** — typical contrasts:

- **mips removal (R-001)**: risk level = P2 (an upstream fact, not strongly coupled to F-Stack); task priority = **P0** (the cleanup of `f-stack/freebsd/mips/` must happen in M1 to unblock the build chain)
- **netlink introduction (R-002)**: risk level = P1 (a major new 15.0 subsystem); task priority = P3 (DP-2 decided "do not introduce", this upgrade does not touch it)
- **Most P0 risks coincide with P0 tasks**: `pr_usrreqs` merge / inpcb SMR / `if_t` / mbuf / routing rewrite, etc.

To avoid ambiguity, in §2/§3 of this document the bracket `[Pn]` next to each heading **always means task priority**; in `§4.1`, `§7` and other "risk tables", the "Priority" column **always means risk level**; where the two diverge, the table will spell out two columns explicitly (see §3.7 / §3.8). `plan.md §4.1` has been updated to use two columns following this convention.

---

## 1. Version Facts

| Item | 13.0 | 15.0 |
|---|---|---|
| `REVISION` | 13.0 | 15.0 |
| `BRANCH` | RELEASE-p2 | RELEASE-p9 |
| `__FreeBSD_version` | **1300139** | **1500068** |
| Measured path | `sys/sys/param.h:63` | `sys/sys/param.h:77` |
| Highest syscall number | `SYS_aio_readv=579` | `SYS_jail_remove_jd=598` |
| `SYS_MAXSYSCALL` | 580 | 599 |

---

## 2. Architecture-Level Changes (affecting the overall build boundary)

### 2.1 [P0] mips architecture fully removed

| Aspect | Detail |
|---|---|
| **Fact** | Removed in 14.0; the local `freebsd-src-releng-15.0/sys/` tree contains no `mips/` subdirectory |
| **Source** | FreeBSD 14.0R Release Notes — "Removal of the mips architecture from the tree as Tier 2 platform" |
| **F-Stack impact** | `f-stack/freebsd/mips/` (carried over from the 13.0 copy) must be deleted; mips conditional branches in all Makefile / mk must be cleaned |
| **Action** | FR-4 / DP-1 → delete |
| **Priority** | **Task priority P0** (without removal a flood of compile errors will appear, M1 mandatory cleanup); **risk level P2** (an upstream fact, unrelated to F-Stack functional capability). See `§0.1` two-axis convention and `plan.md §4.1` R-001. |

### 2.2 [P1] clang/llvm toolchain version requirement

| Aspect | Detail |
|---|---|
| **Fact** | 13.0R defaults to clang/lld 11.0.1, requires GCC ≥ 6; 14.0R uses clang 16, requires GCC ≥ 9; 15.0R uses clang/llvm 19.x |
| **F-Stack impact** | F-Stack headers use GCC extensions (`__attribute__((packed))` etc., backward-compatible); but the 15.0 kernel uses C11 `_Atomic(T)` / `atomic_load_explicit` heavily, the host compiler must be ≥ clang 11 / GCC 9 |
| **Action** | Pinned in `05-implementation-plan.md` §Prerequisites |
| **Priority** | P1 |

### 2.3 [P3] pkgbase / EXPERIMENTAL knob

| Aspect | Detail |
|---|---|
| **Fact** | 14.0R/15.0R introduce pkgbase as an optional release form; 15.0 default is still installworld + installkernel |
| **F-Stack impact** | None (F-Stack does not depend on the base install) |
| **Priority** | P3 (out of scope) |

### 2.4 [P3] 13→15 syscall table delta (measured)

13.0 has `SYS_MAXSYSCALL=580` (420 `SYS_*` names total); 15.0 has `SYS_MAXSYSCALL=599` (439 names). **Net 22 additions and 3 deletions between 13→15** (measured by comparing the `SYS_*` name set).

#### 2.4.1 13→15 additions (22, by 15.0 number)

| Item | 15.0 syscall # | Type | Priority | Note |
|---|---:|---|---|---|
| `fspacectl` | 580 | New feature | P3 | File-hole allocation |
| `sched_getcpu` | 581 | New feature | P3 | — |
| `freebsd13_swapoff` | (compat) | compat shim | P3 | In 13.0 `swapoff=424`; 15.0 renumbered to 582 with the old number kept as a compat entry |
| `kqueuex` | 583 | New feature | P3 | kqueue extension |
| `membarrier` | 584 | New feature | P3 | — |
| `timerfd_create` | 585 | New feature | P3 | Linux compat |
| `timerfd_gettime` | 586 | New feature | P3 | Linux compat |
| `timerfd_settime` | 587 | New feature | P3 | Linux compat |
| `kcmp` | 588 | New feature | P3 | — |
| `getrlimitusage` | 589 | New feature | P3 | — |
| `fchroot` | 590 | New feature | P3 | — |
| `setcred` | 591 | New feature | P3 | — |
| `exterrctl` | 592 | New feature | P3 | — |
| **`inotify_add_watch_at`** | 593 | New feature | P3 (OOS) | C-1 forbids introduction |
| **`inotify_rm_watch`** | 594 | New feature | P3 (OOS) | C-1 forbids introduction |
| `freebsd14_getgroups` | (compat) | compat shim | P3 | In 13.0 `getgroups=79`; 15.0 renumbered to 595 with the old number kept as compat |
| `freebsd14_setgroups` | (compat) | compat shim | P3 | In 13.0 `setgroups=80`; 15.0 renumbered to 596 with the old number kept as compat |
| `jail_attach_jd` | 597 | New feature | P3 | — |
| `jail_remove_jd` | 598 | New feature | P3 | — |
| `_exit` | (compat) | compat shim | P3 | Compat alias for old number 1 |
| `freebsd10__umtx_lock` | (compat) | compat shim | P3 | freebsd10 compat |
| `freebsd10__umtx_unlock` | (compat) | compat shim | P3 | freebsd10 compat |

#### 2.4.2 13→15 deletions (3)

| Item | 13.0 syscall # | Reason for removal | Priority |
|---|---:|---|---|
| `gssd_syscall` | 505 | gssd user-space daemon interface deprecated | P3 |
| `sbrk` | 69 | brk/sbrk user-space interface had its syscall implementation removed in 14.0 (only the libc emulation remains) | P3 |
| `sstk` | 70 | Removed together with `sbrk` | P3 |

#### 2.4.3 syscalls already present in 13.0 (**NOT 13→15 additions**)

The following syscalls were already defined in 13.0 `sys/sys/syscall.h`; **the document previously listed them as 15.0 additions by mistake**: `SYS___realpathat=574`, `SYS_close_range=575`, `SYS_rpctls_syscall=576`, `SYS___specialfd=577`, `SYS_aio_writev=578`, `SYS_aio_readv=579`.

> **Source command**: `grep '^#define[[:space:]]\+SYS_' /data/workspace/freebsd-src-releng-{13.0,15.0}/sys/sys/syscall.h | awk '{print $2}' | sort | comm` (measured 2026-05-28).
>
> F-Stack does not go through the host syscall layer (it has an in-house user-space dispatch); the above does not directly affect F-Stack. Action is only needed when `ff_syscall_wrapper.c` needs to expose them. This upgrade does not introduce new syscalls (constraint C-1).

### 2.5 [P2] Overall impact of syscall-table expansion

Although individual syscalls are out of scope, changes to the `init_sysent.c` system affect the static-link size and compilation of F-Stack. **P2**: monitor compile warnings is enough.

---

## 3. Network-Stack-Level Changes (the core battlefield)

### 3.1 [P0 ★] `pr_usrreqs` fully retired and merged into `protosw`

| Aspect | Detail |
|---|---|
| **Fact** | 13.0: `struct protosw` contains the field `struct pr_usrreqs *pr_usrreqs;` and exposes the protocol user-request vector through this struct. 15.0: `pr_usrreqs` is removed entirely; all methods are merged directly into top-level fields of `protosw` (the `pru_*` family hangs directly off `struct protosw`) |
| **Affected files** | All protocol registration sites (tcp_usrreq.c / udp_usrreq.c / raw_ip.c, etc.) + every site calling `pr->pr_usrreqs->pru_*()` |
| **F-Stack impact** | All `pru_*` function-pointer references in `ff_glue.c` + `kern_event.c` + `uipc_socket.c` must be rewritten |
| **Risk ID** | R-011 |
| **Priority** | **P0** (build-breaking) |

### 3.2 [P0 ★] `struct inpcb` migrates from epoch to SMR

| Aspect | Detail |
|---|---|
| **Fact** | 13.0: `inpcb` hash lookup is protected by NET_EPOCH. 15.0: SMR (Safe Memory Reclamation) is used, and the `inpcbgroup` hash is rewritten |
| **Affected files** | `in_pcb.c` / `in_pcb.h` / `tcp_input.c` / `udp_usrreq.c` / `raw_ip.c` |
| **F-Stack impact** | F-Stack today stubs out epoch via `ff_subr_epoch.c` (FSTACK-stub); after SMR appears, evaluate: stub it out (simpler) or introduce a new SMR wrapper |
| **Risk ID** | R-012 |
| **Priority** | **P0** |

### 3.3 [P0 ★] `struct ifnet` opaque-ized as `if_t`

| Aspect | Detail |
|---|---|
| **Fact** | 13.0: `sys/net/if_var.h:127` already contains `typedef struct ifnet * if_t;`, but kernel APIs still expose `struct ifnet *` (e.g. `if_alloc()` returns `struct ifnet *`); driver/bridge code generally accesses fields directly (`ifp->if_flags`, `ifp->if_xname`, etc.). 15.0: that typedef is lifted up to `sys/net/if.h:667` (`typedef struct ifnet *if_t;`) and kernel APIs such as `if_alloc()` are uniformly switched to use `if_t`; concurrently, a large number of accessors are provided (`if_getflags(ifp)`, `if_name(ifp)`, `if_setname(ifp, ...)` in `sys/net/if_var.h`). **The underlying type has NOT become `void *`; "opaque-ization" refers to the API contract: external code should operate on `if_t` via `if_get*/if_set*` accessors and should not depend on `struct ifnet` field layout.** |
| **Affected files** | `net/if.c` / `if_var.h` / all drivers / `ff_veth.c` |
| **F-Stack impact** | `ff_veth.c` is F-Stack's own DPDK bridge; it must switch to `if_t` accessors. F-Stack `freebsd/net/if.c` adaptation points need re-evaluation (whether the H-1 / H-9 stubs still hold) |
| **Risk ID** | R-013 |
| **Priority** | **P0** |

### 3.4 [P0] mbuf field adjustments (13→14→15)

| Aspect | Detail |
|---|---|
| **Fact** | 14.0 adjusts `m_pkthdr` (adds `numa_domain` etc.); 15.0 further adjusts `m_ext` (refcnt / ext_type / ext_free reorganized) |
| **Affected files** | `uipc_mbuf.c` / `kern_mbuf.c` / `mbuf.h` / all `m_*` operation macros |
| **F-Stack impact** | F-Stack already has `FSTACK-stub` + `FSTACK_ZC_SEND` adaptations in `uipc_mbuf.c`; they need to be re-applied on top of the 15.0 new fields. The `FSTACK_ZC_SEND` path's iov_base mounting in `m_uiotombuf` must adapt to the new `m_ext` layout |
| **Risk ID** | R-003 |
| **Priority** | **P0** |

### 3.5 [P1] netlink subsystem (added in 15.0)

| Aspect | Detail |
|---|---|
| **Fact** | 14.0 introduces the `sys/netlink/` subdirectory (10 .c: netlink_domain.c / netlink_io.c / netlink_message_parser.c / netlink_message_writer.c / netlink_module.c / netlink_route.c, etc.); a Linux netlink compatibility layer |
| **F-Stack impact** | Constraint C-1 decides **not to introduce** (DP-2), but it must be explicitly recorded in this spec |
| **Knock-on impact** | The internal APIs of `route.c` / `if.c` in 15.0 are tightly coupled with netlink; after removing netlink, some `#include` and symbol references must be stubbed |
| **Risk ID** | R-002 |
| **Priority** | P1 (DP-2 not introducing for now, but dependency severance still needed at implementation time) |

### 3.6 [P1] TCP RACK as default

| Aspect | Detail |
|---|---|
| **Fact** | From 14.0 `tcp_stacks/rack` enters base; in 15.0 the default TCP stack is still freebsd default, but RACK has matured further with many added symbols, statistics and `sysctl` knobs |
| **Affected files** | `tcp_stacks/rack.c` and the companion `rack_bbr_common.c` |
| **F-Stack impact** | F-Stack's existing `tcp_stacks/rack.c` has the module name renamed (H-5); this rename must be re-applied on the 15.0 baseline |
| **Risk ID** | R-004 |
| **Priority** | P1 |

### 3.7 [P2] Kernel TLS API changes

| Aspect | Detail |
|---|---|
| **Fact** | 14.0 introduces the full KTLS API; 15.0 refactors it further |
| **F-Stack impact** | F-Stack does not currently enable KTLS, so no direct breakage; but `sys_socket.c` / `uipc_socket.c` contain KTLS-related `#ifdef` branches whose stub-out strategy needs evaluation |
| **Risk ID** | R-006 |
| **Priority** | **Task priority P2 / risk level P2** (see `§0.1` two-axis convention) |

### 3.8 [P0] Routing table structure change (rib / nexthop)

| Aspect | Detail |
|---|---|
| **Fact** | 14.0 refactors the routing table from the old `rtentry` to `rib` + `nexthop`; 15.0 stabilizes the new structures |
| **Affected files** | `net/route.c` / `net/route.h` / `net/route_var.h` / all `rtinit / rtalloc` call sites |
| **F-Stack impact** | `ff_route.c` must be rewritten to the rib/nexthop API |
| **Priority** | **Task priority P0 / risk level P0** (parallel to R-013, KPI breakage; see `§0.1` two-axis convention) |

### 3.9 [P1] VNET API evolution

| Aspect | Detail |
|---|---|
| **Fact** | VNET has been refactored internally several times in 14.0 / 15.0 (vnet_data_*, CURVNET_SET optimizations) |
| **F-Stack impact** | F-Stack does not enable VNET (single instance), but every source file referencing `VNET(*)` follows upstream upgrades |
| **Priority** | P2 |

### 3.10 [P1] epoch / rmlock synchronization-primitive adjustments

| Aspect | Detail |
|---|---|
| **Fact** | 14.0 replaces several NET_EPOCH scenes with SMR / rmlock; the `epoch_call` semantics is fine-tuned in 15.0 |
| **F-Stack impact** | The coverage of `ff_subr_epoch.c`'s stub needs re-evaluation |
| **Priority** | P1 |

### 3.11 [P2] wifi stack / pf / dummynet / netgraph changes

| Subitem | Priority | F-Stack impact |
|---|---|---|
| wifi stack refactor | P3 | F-Stack does not use wifi |
| pf upgrade (13.x → 15.x) | P2 | F-Stack does not use pf directly |
| dummynet | P3 | F-Stack does not use directly |
| netgraph | P1 | `ng_socket.c` change is small; F-Stack already has H-2 adaptation |

---

## 4. ABI / KPI / KBI Changes (affecting user-space libff)

### 4.1 Key struct layout changes (all incompatible)

| struct | 13→15 change | Priority |
|---|---|---|
| `struct protosw` | merges `pr_usrreqs` into top level | **P0** |
| `struct inpcb` | epoch → SMR; field rearrangement | **P0** |
| `struct tcpcb` | RACK-related fields added | **P0** |
| `struct sockbuf` | KTLS / mbuf fields added | **P0** |
| `struct ifnet` → `if_t` | opaque-ization | **P0** |
| `struct mbuf::m_pkthdr` | adds numa_domain etc. | **P0** |
| `struct mbuf::m_ext` | field rearrangement | **P0** |
| `struct rtentry` → `rib`+`nexthop` | full table rewrite | **P0** |

### 4.2 User-space libc interface

Only the libc parts referenced by F-Stack are involved; this upgrade does not switch libc, so P3.

### 4.3 ABI break overall

13→15 spans 2 major versions; per FreeBSD policy, ABI is not guaranteed to stay backward compatible. F-Stack's user-space libff ABI must be reviewed, especially:
- `struct ff_ev` (in `ff_event.h`)
- `ff_msg` (in `ff_msg.h`, IPC command channel)
- `ff_veth_softc` (in `ff_veth.h`)

→ R-007 in `01-requirements-spec.md`.

---

## 5. Build-Level Changes

### 5.1 src.conf / src.opts.mk KNOB changes

13→15 sees about 60 KNOBs added or removed (e.g. `WITHOUT_GOOGLETEST` → `WITH_GOOGLETEST`, plus new `WITH_LLVM_AWK`, etc.). F-Stack does not use the freebsd base build system, impact P3.

### 5.2 Makefile.inc evolution

`bsd.prog.mk / bsd.lib.mk` had minor adjustments in 15.0 (e.g. PIE support added). The F-Stack tools build uses its own Makefile; verify the `include` path is `<bsd.prog.mk>` — measurement shows F-Stack tools' Makefile uses `lib.mk / prog.mk` (in `f-stack-lib/tools/`), decoupled from base, **P3**.

### 5.3 CTF / DTrace and other optionals

F-Stack does not enable, P3.

---

## 6. crypto/ Subdirectory Changes

| Item | 13.0 | 15.0 | Priority |
|---|---|---|---|
| `chacha20_poly1305.c/.h` | absent | added | P2 (F-Stack does not directly use) |
| `curve25519.c/.h` | absent | added | P3 |
| `blowfish/` | present | **removed** | P3 |
| `sha1.c` content tweaks | 8.64 KB | 8.6 KB | P3 |

---

## 7. Upgrade Risk Panorama (sorted by priority)

| ID | Risk | Priority | Source | Disposition |
|---|---|---|---|---|
| **R-011** | `pr_usrreqs` merged into `protosw` | **P0** | §3.1 | Rewrite all pru_* references in `ff_glue.c` and beyond |
| **R-012** | `inpcb` epoch → SMR | **P0** | §3.2 | Evaluate stub vs rewrite of `ff_subr_epoch.c` |
| **R-013** | `ifnet` → `if_t` opaque-ization | **P0** | §3.3 | Rewrite `ff_veth.c` |
| R-003 | mbuf field adjustments | **P0** | §3.4 | Adapt to new `m_pkthdr`/`m_ext` layout |
| **new** | rib/nexthop routing table rewrite | **P0** | §3.8 | Rewrite `ff_route.c` |
| R-001 / FR-4 | mips fully removed | **P0** | §2.1 | Delete `f-stack/freebsd/mips/` |
| R-002 | netlink added | P1 (DP-2) | §3.5 | Do not introduce; sever dependencies |
| R-004 | RACK as default / tcp_stacks changes | P1 | §3.6 | Re-apply H-5 rename |
| R-007 | ABI break | P1 | §4 | User-space libff ABI review |
| R-009 | clang/llvm 14→15 bump | P1 | §2.2 | Build-environment prerequisite |
| R-006 | KTLS / wlan API change | P2 | §3.7 | Stub-out strategy evaluation |
| R-008 | f-stack-lib drift vs f-stack | P2 | §1.4 of 01 | diff -rq cleanup of SKIP noise |
| R-005 | pkgbase | P3 | §2.3 | Information record |
| R-010 | inotify / post-quantum crypto | P3 (OOS) | §2.4 | Information record |

> Total **6 P0 items**; 4 P1 items; 3 P2 items; 2 P3 items. This is the basis for milestone planning in 04 / 05.

---

## 8. Selected Milestone Events Between 14.0 → 14.4

| Version | Date | Key event |
|---|---|---|
| 14.0R | 2023-11 | mips removed; clang 16; KTLS complete; rib/nexthop stable; netlink introduced; RACK enters base |
| 14.1R | 2024-05 | OpenSSH 9.7; ZFS 2.2.4 |
| 14.2R | 2024-12 | ZFS 2.2.6; vnet routing tweaks |
| 14.3R | 2025-06 | clang 18; netlink hardening |
| 14.4R | 2025-12 | Enters ESR; the last 14.x |
| 15.0R | end of 2025 | clang/llvm 19; pr_usrreqs merge; inpcb SMR; if_t opaque; mbuf m_ext field rearrangement; syscall table expanded to 599 |
| 15.1R | first half of 2026 | Subsequent maintenance |

---

## 9. Hand-off to Other Documents in the Series

| Artifact from this section | Hand-off target |
|---|---|
| 6 P0 risks (§7) | "Mandatory tasks" in `04-diff-and-port-strategy.md` |
| Adaptation file matrix (§3) | "File-locating by P0 risk" in `04-diff-and-port-strategy.md` |
| ABI break (§4.3) | FR-3 + R-007 in `01-requirements-spec.md` |
| Upgrade timeline (§8) | Referenced as a baseline timeline by `05-implementation-plan.md` |

> Next: `04-diff-and-port-strategy.md` cross-cuts this section's risks with the §02 adaptation points to produce the final port task list.

## 10. External Citations and To-Be-Verified Inventory (added 2026-05-28)

> This section addresses independent audit §P1-005: this document cites a large number of upstream facts (mips removal, clang/llvm 19, pkgbase, `pr_usrreqs` merge, inpcb SMR, `if_t` opaque-ization, netlink, RACK as default, KTLS, routing/rib/nexthop, 14.4/15.1 timeline, etc.), but in v0.1 did not give per-line URL / quote / capture date. This section is split into "§10.1 Local authoritative source (verifiable now)" and "§10.2 External URLs to be verified", filling in the source for each fact; §10.3 gives the upgrade conditions for to-be-verified entries.
> All citations are measured 2026-05-28; local paths sit under `/data/workspace/freebsd-src-releng-15.0/` (unless otherwise noted).

### 10.1 Local authoritative source (verifiable now)

Each citation in the table below is in the form "file path + line number + short quote"; the reader can `sed -n '<line>p' <path>` to verify directly.

| 03 section | Fact | Local authoritative source (path:line + quote) |
|---|---|---|
| §1 / §2.1 | 13.0 = `RELEASE-p2`, 15.0 = `RELEASE-p9` | `freebsd-src-releng-13.0/sys/conf/newvers.sh`: `REVISION="13.0" / BRANCH="RELEASE-p2"`; `freebsd-src-releng-15.0/sys/conf/newvers.sh`: `REVISION="15.0" / BRANCH="RELEASE-p9"` |
| §1 / §6 | `__FreeBSD_version`: 13.0=`1300139`, 15.0=`1500068` | `freebsd-src-releng-13.0/sys/sys/param.h`: `#define __FreeBSD_version 1300139`; `freebsd-src-releng-15.0/sys/sys/param.h:#define __FreeBSD_version 1500068` |
| §2.1 | mips fully removed (started in 14.0, commit 2021-12-09) | `freebsd-src-releng-15.0/UPDATING:929-932`: `20211209: Remove mips as a recognized target. This starts the decommissioning of mips support in FreeBSD. mips related items will be removed wholesale in the coming days and weeks.`; line 971: `Mips has been removed from universe builds`; line 1463: `mips, powerpc, and sparc64 are no longer built as part of universe`; line 1643: `mips GXEMUL support has been removed`; line 751: `Following the general removal of MIPS support, the ath(4) AHB bus-…` |
| §2.2 | clang/llvm 18 ladder upgrade (→ 19 pending 14.x→15 RELNOTES verification) | `freebsd-src-releng-15.0/UPDATING:621-628`: `20240406: Clang, llvm, lld, lldb, compiler-rt, libc++, libunwind and openmp have been upgraded to 18.1.6.`; the clang 19 upgrade entry stays "to verify" in §10.2 (the UPDATING text in this repository version did not surface a 19.x upgrade line) |
| §2.3 | pkgbase landed densely in the 15.0 phase | `freebsd-src-releng-15.0/UPDATING` lines 80/90/157/159/166/184/188/211/227/243/265/358/373/381/386/458/463/527/556/613/618/622/712/716/717/718 (40+ in total); representative quote line 157: `release engineering builds on pkgbase.freebsd.org`; line 527: `different transport - netlink(4) socket instead of unix(4). Users of …` (also touches netlink) |
| §2.4 | 13→15 syscall-table measurement (22 additions + 3 deletions) | `grep '^#define[[:space:]]\+SYS_' freebsd-src-releng-{13.0,15.0}/sys/sys/syscall.h \| awk '{print $2}' \| sort \| comm` (see 99 §12.1) |
| §3.1 | `pr_usrreqs` merged into `protosw` in 15.0 | `freebsd-src-releng-13.0/sys/sys/protosw.h:95`: `struct pr_usrreqs *pr_usrreqs;`; `freebsd-src-releng-13.0/sys/sys/protosw.h:188`: `struct pr_usrreqs {`; in 15.0 the same header has no `pr_usrreqs` field (grep returns 0 lines) |
| §3.2 | `inpcb` migrates to SMR | `freebsd-src-releng-15.0/sys/netinet/in_pcb.h:141-142`: `are be performed inside SMR section. Once desired PCB is found its own lock is to be obtained and SMR section exited.`; line 192: `smr_seq_t inp_smr; /* (i) sequence number at disconnect */`; line 342: `The pcbs are protected with SMR section…` |
| §3.3 | `if_t` typedef (see 99 §12.2) | `freebsd-src-releng-13.0/sys/net/if_var.h:127`: `typedef struct ifnet * if_t;`; `freebsd-src-releng-15.0/sys/net/if.h:667`: `typedef struct ifnet *if_t;` |
| §3.5 | netlink subsystem introduced in 15.0 | `freebsd-src-releng-15.0/sys/netlink/` (directory exists, 3907 lines of `.c`; this directory is absent in 13.0); `freebsd-src-releng-15.0/UPDATING:851-853`: `As of commit 7c40e2d5f685, the dependency on netlink(4) has been added … to compile netlink(4) module if it is not present in their kernel.` |
| §3.6 | RACK / BBR / extra TCP stacks modularized | `freebsd-src-releng-15.0/sys/conf/files:4451-4456`: `netinet/tcp_stacks/rack.c optional inet tcphpts tcp_rack \| inet6 tcphpts tcp_rack \\` and `compile-with "${NORMAL_C} -DMODNAME=tcp_rack -DSTACKNAME=rack"`; `rack_bbr_common.c` / `sack_filter.c` / `tailq_hash.c` / `rack_pcm.c` are also declared there |
| §3.7 | KTLS enabled by default in GENERIC | `freebsd-src-releng-15.0/RELNOTES:227-228`: `Kernel TLS is now enabled by default in kernels including KTLS support. KTLS is included in GENERIC kernels for aarch64, …` |
| §3.8 | Routing / rib / nexthop security-related | `freebsd-src-releng-15.0/UPDATING:107-109`: `15.0-RELEASE-p4 SA-26:05.route … Local DoS and possible privilege escalation via routing sockets.` (side evidence that the routing subsystem is still actively maintained in 15.0) |

### 10.2 External URL to-be-verified inventory

The facts in the table below need external network access to fill in the URL / capture date. For this audit cycle's scope, these entries are kept "to verify" and shall be filled by manual review before M1 starts.

| 03 section | Fact | Candidate URL (to verify) | Promotion condition |
|---|---|---|---|
| §2.2 | clang/llvm 19 upgrade timing (v0.1 says "clang/llvm 19") | `https://www.freebsd.org/releases/15.0R/relnotes/` (FreeBSD 15.0 official release notes); `https://lists.freebsd.org/archives/freebsd-current/` (search "Clang 19 import") | Open online → capture key sentence → record into this section + 99 §12.6 |
| §2.3 | pkgbase status in 15.0 (v0.1 says "P3 / EXPERIMENTAL knob") | `https://wiki.freebsd.org/PkgBase`; `https://docs.freebsd.org/en/articles/explaining-bsd/` (pkgbase chapter) | same as above |
| §3.5 | Netlink introduction year (v0.1 says "actually introduced in 14.0") official statement | `https://www.freebsd.org/releases/14.0R/relnotes/`; `man.freebsd.org/cgi/man.cgi?netlink(4)` | same as above |
| §3.6 | RACK default-knob status in 15.0 base | `https://www.freebsd.org/releases/15.0R/relnotes/`; `https://lists.freebsd.org/archives/freebsd-net/` (search "RACK default") | same as above |
| §3.7 | Concrete commit / phabricator review for KTLS API 14→15 changes | `https://reviews.freebsd.org/`; `https://cgit.freebsd.org/src/log/sys/sys/ktls.h` | same as above |
| §3.8 | routing/rib/nexthop rewrite design doc | `https://reviews.freebsd.org/D26577` (route_ctl introduction); FreeBSD wiki "FIB / NHOP" entry | same as above |
| §6 | 14.0R to 14.4R timeline table | `https://www.freebsd.org/releases/` (each 14.x version main page) | same as above |
| §6 | 15.1R timeline placeholder | `https://www.freebsd.org/releases/15.1R/` (not yet released) | back-fill once released |

### 10.3 Promotion condition and process for to-be-verified items

1. **Trigger time**: the to-be-verified items in this batch should have URLs filled by manual review before the M1 implementation phase starts; this **does NOT block** Spec-phase delivery (in §7 Go/No-Go judgment "as a Spec draft = GO")
2. **Verification method**: visit the candidate URL listed in §10.2 → capture no more than 3 sentences of original text related to the document fact → append "URL + capture date + quote" in this section → change "Candidate URL (to verify)" of the corresponding line to "Verified URL"
3. **Fallback**: if a URL is dead or inconsistent with the document fact, record "verification attempted; conclusion conflicts with v0.1 / inaccessible" here and amend the main chapter accordingly
4. **Phase 4 reviewer responsibility**: when this document is reviewed again in the future, if §10.2 list is empty (i.e. all verified), add a "100% externally-reproducible facts" quality metric to 99 §3 / §7
