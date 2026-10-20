# 01 — Upgrade Requirements Spec

> Chinese version: ./zh_cn/01-requirements-spec.md
>
> Series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-26)
> Predecessor: `00-overview-and-glossary.md`

---

## 1. Document Purpose

State the **problems to solve, problems NOT to solve, acceptance criteria, and constraints** for the project "F-Stack upgrade from FreeBSD 13.0 to 15.0", as the contractual input for all subsequent Spec docs and implementation work.

---

## 2. Top-Level User Story

> **As** a code maintainer of the F-Stack project,
> **I want** F-Stack to follow upstream FreeBSD up to 15.0-RELEASE,
> **so that** F-Stack continuously inherits upstream stack security fixes, performance improvements (such as RACK-as-default), and new hardware support, instead of staying on 13.0 and drifting away from upstream.
>
> **Acceptance**: after the upgrade, `libff.a` builds normally, the `fstack` main program can run + passes the existing functional test cases; all F-Stack-specific adaptations are preserved (DPDK integration, IPC tools, ff_* glue, zero-copy mbuf extension).

---

## 3. Functional Requirements (FR)

### FR-1 Kernel network stack aligned to 15.0 upstream
**ID**: FR-1
**Description**: All freebsd-src files in the `f-stack/freebsd/` subtree (excluding F-Stack adaptation files and metadata) must be **byte-identical** to the corresponding files in `freebsd-src-releng-15.0/sys/` (or, where F-Stack has its own adaptations, "baseline = 15.0 upstream" instead of "baseline = 13.0 upstream").
**Acceptance**:
- `diff -rq f-stack/freebsd/<subdir> freebsd-src-releng-15.0/sys/<subdir>` differences must **only** be F-Stack's own adaptation points (each diff must map to an adaptation type tag in `02-architecture-analysis.md` §1.2/§1.3/§1.4)
- "Phantom diffs" — neither F-Stack adaptation nor 15.0 upstream — are not allowed

### FR-2 User-space tools aligned to 15.0 upstream
**ID**: FR-2
**Description**: The 12 freebsd-native tool subdirectories under `f-stack/tools/` (arp / ifconfig / ipfw / libmemstat / libnetgraph / libutil / libxo / ndp / netstat / ngctl / route / sysctl) must have their upstream baseline switched to 15.0; F-Stack's `IPC-replace` and `Makefile-fstack` adaptation patterns must be re-applied on top of the new baseline.
**Acceptance**: same as FR-1, but scoped to tools/.

### FR-3 ff_* glue files: synchronized API upgrade
**ID**: FR-3
**Description**: All code in the 30 `ff_*.c` + 14 `ff_*.h` files under `f-stack/lib/` that **references FreeBSD kernel symbols or headers** must be updated to the 15.0 equivalent APIs.
**Typical mapping points**:
- `ff_kern_intr.c` aligned with `kern_intr.c`
- `ff_subr_epoch.c` aligned with `subr_epoch.c`
- `ff_syscall_wrapper.c` aligned with `sendit/recvit` external declarations in `kern/sys_generic.c` + `uipc_syscalls.c`
- `ff_veth.c` aligned with the `if_t` opaque-ization (FR-1 §P0 KBI break #3) accessor APIs
- `ff_route.c` aligned with the new rib/nexthop structures
- `ff_glue.c` aligned with the new signatures after `protosw` merged `pr_usrreqs`
**Acceptance**:
- `f-stack/lib/Makefile` links cleanly on the 15.0 baseline (covered by FR-5)
- All `#include <sys/...>` directives resolve under 15.0 headers without missing-path / undefined-symbol errors

### FR-4 mips architecture cleanup
**ID**: FR-4
**Description**: Since 15.0 has fully removed the mips architecture, the entire `f-stack/freebsd/mips/` subdirectory must be removed from the F-Stack project; all `mips`-related conditional branches in `Makefile / mk` must be cleaned up.
**Acceptance**:
- `find f-stack/freebsd/mips -type f` returns empty
- `grep -rE '\bmips\b' f-stack/freebsd/conf f-stack/lib/Makefile` only matches comments or returns no hits

### FR-5 Build acceptance
**ID**: FR-5
**Description**: On the upgraded code, `make` and `make install` (per F-Stack's existing build flow) must show **0 errors and 0 new warnings** (relative to the 13.0 baseline warning set).
**Acceptance**:
- `libff.a` produced successfully
- All 12 tools binaries produced (ff_arp / ff_ifconfig / ff_ipfw / ff_ndp / ff_netstat / ff_ngctl / ff_route / ff_sysctl, etc.)
- The 3 f-stack-shipped tools (knictl / traffic / top) keep their pre-upgrade state (not part of this freebsd-side upgrade, but must not be broken by it)
- Any warning increment must be explicitly explained in `99-review-report.md` and tagged P2/P3

### FR-6 Runtime acceptance
**ID**: FR-6
**Description**: After upgrade, the `fstack` main program + matching tools must complete F-Stack's existing baseline networking cases (see `06-test-and-acceptance-spec.md`):
- Single-lcore startup, NIC binding, IP configuration
- TCP echo service round-trip
- UDP echo service round-trip
- ifconfig / netstat / ipfw / route subcommand query and configuration
**Acceptance**: see the 9 cases in `06-test-and-acceptance-spec.md` §3.

### FR-7 Preserve F-Stack-specific extensions
**ID**: FR-7
**Description**: The following F-Stack-specific "non-standard" extensions must be **preserved fully** after the upgrade and must not be deleted by mistake under the banner of "align with upstream":
- `FSTACK_ZC_SEND` zero-copy mbuf send path (in `uipc_mbuf.c` `m_uiotombuf`)
- RSS port-range extension (in `in_pcb.c`)
- TCP RACK/BBR module-name renames (to avoid clashing with upstream)
- ff_ipc.c/ff_ipc.h user-space tool IPC bridge
**Acceptance**: those code segments still exist post-upgrade; `grep -rE 'FSTACK_ZC_SEND|ff_ipc'` hit count is no less than pre-upgrade.

---

## 4. Non-Functional Requirements (NFR)

### NFR-1 No performance regression
**Description**: After the upgrade, F-Stack throughput / latency under identical hardware / identical workload must **not regress by more than 5%** versus pre-upgrade (the measurement baseline is decided by existing benchmarks, see `06-test-and-acceptance-spec.md` §5).
**Note**: performance **gains** brought by the upgrade (e.g. throughput uplift from RACK-as-default) are recorded as bonus benefits.

### NFR-2 Document executability
**Description**: The 7 documents produced by this Spec series must be directly consumable by downstream AI agents picking up implementation tasks.
**Acceptance**:
- Each spec section provides "path", "verification command", and "expected artifact"
- The port task list in `04-diff-and-port-strategy.md` can be directly consumed by the c-precision-surgery skill
- The milestone task list in `05-implementation-plan.md` can be directly picked up by the spec-driven skill

### NFR-3 Full risk coverage
**Description**: All major changes between 13→14 + 14→15 (architecture-level / network-stack-level / ABI-level / build-level) must each have at least one entry in `03-freebsd-15-changes.md`.
**Acceptance**: the reviewer enumerates them by P0-P3 in `99-review-report.md` → cross-checked with this spec's FR/NFR; 0 missing entries.

### NFR-4 Rollback-capable
**Description**: The upgrade implementation must preserve the ability to roll back to the 13.0 baseline (a git branch or a workspace-level dual backup).
**Acceptance**: the implementation plan contains a "rollback command list" (see `05-implementation-plan.md` §6).

### NFR-5 Backward incompatibility (no longer support 13.0)
**Description**: After F-Stack is upgraded to 15.0, **no** further commitment is made to support the 13.0 baseline. From milestone M5 completion onward, the 13.0-baseline-related code is regarded as "historical code".
**Note**: this is an explicit incompatibility statement, intended to avoid the maintenance cost of a dual-version setup.

---

## 5. Constraints

### C-1 Do not introduce 15.0 new capabilities ("alignment" ≠ "capability extension")
**Description**: Even though the following 15.0 new capabilities **have source files** in the sys/ subtree, this upgrade **does NOT** pull them into `f-stack/freebsd/`:
- `sys/netlink/` (Linux netlink compatibility subsystem, 10 .c files)
- Post-quantum cryptography (ML-KEM, etc.)
- inotify (syscall 593/594)
- timerfd (syscall 585/586/587)
- kqueuex (syscall 583)
- membarrier (syscall 584)
**Note**: kept as "future enhancement suggestions"; not touched by this implementation.
**Corresponding decision**: DP-2 (see `plan.md` §4.2 and `05-implementation-plan.md` §Decision Points table).

### C-2 Do not touch the LD_PRELOAD ring IPC part
**Description**: `f-stack/adapter/syscall/` is covered by the independent workstream `docs/ld_preload_ring_spec/`; this upgrade does not touch it.
**Exception**: `f-stack/lib/ff_syscall_wrapper.c` is the intersection (affected by both freebsd upgrade and ld_preload), covered by FR-3.

### C-3 Do not change DPDK dependency
**Description**: Keep the existing DPDK LTS unchanged; if FreeBSD 15.0 upgrade requires DPDK update, that is recorded as a P2 risk but is not in scope.

### C-4 Do not touch Git
**Description**: Neither this Spec series nor the subsequent implementation will run `git add / commit / push`. All artifacts are written to the working tree only.

### C-5 Document language: Chinese
**Description**: The first version of this series is Chinese only; an English version is to be considered after the Chinese version is human-audited.
**(Update: this English version is the result of that consideration.)**

### C-6 Compiler floor
**Description**: The host compiler must be ≥ **GCC 9 / clang 12** (per Analyzer-15 research: FreeBSD 14.0 already requires GCC 9; the 15.0 kernel uses C11 `_Atomic`/`atomic_load_explicit`).

---

## 6. Acceptance Criteria Matrix

| Category | Criterion | Quantitative measure | Document |
|---|---|---|---|
| Code | FR-1 freebsd/ alignment | diff -rq contains adaptation points only | `04-diff-and-port-strategy.md` |
| Code | FR-2 tools/ alignment | diff -rq contains adaptation points only | `04-diff-and-port-strategy.md` |
| Code | FR-3 ff_* API sync | 0 build errors | `02-architecture-analysis.md` §3 + `04` §3 |
| Code | FR-4 mips cleanup | find returns empty | `05-implementation-plan.md` M1 |
| Build | FR-5 build acceptance | 0 errors, 0 new warnings | `06-test-and-acceptance-spec.md` §2 |
| Run | FR-6 runtime acceptance | All 9 cases pass | `06-test-and-acceptance-spec.md` §3 |
| Code | FR-7 extensions preserved | grep hits ≥ pre-upgrade | `04-diff-and-port-strategy.md` §5 |
| Performance | NFR-1 regression ≤ 5% | benchmark comparison | `06-test-and-acceptance-spec.md` §5 |
| Doc | NFR-2 executability | spec contains path/command/artifact | `99-review-report.md` |
| Doc | NFR-3 full risk coverage | 0 missing | `99-review-report.md` |
| Implementation | NFR-4 rollback-capable | rollback list exists | `05-implementation-plan.md` §6 |

---

## 7. Key Decision Points (summary; the formal version is in 05)

| DP | Decision | Default tendency | Scope |
|---|---|---|---|
| DP-1 | Whether to delete `f-stack/freebsd/mips/` | **Delete** | FR-4 |
| DP-2 | Whether to pull 15.0 sys/netlink/ into f-stack/freebsd/ | **Not pull in for now** | C-1 |
| DP-3 | Big-bang full sync vs progressive | **Progressive M1-M5** | `05-implementation-plan.md` |
| DP-4 | Whether f-stack/lib/ff_*.c is upgraded in lockstep with f-stack/freebsd | **Must be in lockstep** | FR-3 |
| DP-5 | Whether the f-stack/tools/ upgrade is its own milestone | **Independent M5** | `05-implementation-plan.md` |

---

## 8. Assumptions

| ID | Assumption | Consequence on failure |
|---|---|---|
| A-1 | `freebsd-src-releng-15.0/` is already a stable 15.0-RELEASE-p9 baseline | Re-copy of the 15.0 backup is required (Phase 1.4 redo) |
| A-2 | F-Stack's existing build flow is 0-error on the 13.0 baseline | "Errors introduced by upgrade" cannot be distinguished from "pre-existing errors" |
| A-3 | The DPDK LTS version is compatible with FreeBSD 15.0 | A DPDK upgrade evaluation is required |
| A-4 | F-Stack will not introduce new SMP / VNET call boundaries | FR-3 must be widened |

---

## 9. Risk Inventory (full justification in `03-freebsd-15-changes.md`)

> Only IDs and one-liners are listed here; the full reasoning is in 03.

| ID | Risk | Priority |
|---|---|---|
| R-001 | 15.0 removes mips architecture | P2 |
| R-002 | 15.0 adds netlink subsystem | P1 (DP-2 not introducing now, still recorded as risk) |
| R-003 | 14→15 mbuf struct adjustments | **P0** |
| R-004 | 14→15 TCP RACK as default + tcp_stacks changes | P1 |
| R-005 | 15.0 base switches to pkgbase | P3 |
| R-006 | 15.0 wlan / kernel TLS API changes | P2 |
| R-007 | 14→15 ABI break | P1 |
| R-008 | Drift between 13.0/f-stack-lib and current f-stack (102 sites containing noise) | P2 |
| R-009 | clang/llvm 14→15 bump | P2 |
| R-010 | 15.0 inotify / post-quantum crypto | P3 (out of scope) |
| **R-011** | **15.0 `pr_usrreqs` merged into `protosw`** | **P0** |
| **R-012** | **15.0 `inpcb` epoch → SMR refactor** | **P0** |
| **R-013** | **15.0 `ifnet` opaque-ized as `if_t`** | **P0** |

> R-011/R-012/R-013 are P0 risks discovered by Analyzer-15 measurement that were not listed in plan.md §4.1; this spec adds them.

---

## 10. Inputs (already in place)

| Material | Path | Status |
|---|---|---|
| 13.0 upstream source | `/data/workspace/freebsd-src-releng-13.0/` | Exists |
| 15.0 upstream source | `/data/workspace/freebsd-src-releng-15.0/` | Exists |
| 13.0 backup | `/data/workspace/freebsd-src-releng-13.0/f-stack-lib/` | Exists |
| 15.0 backup | `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/` | Created in Phase 1.4 |
| F-Stack current state | `/data/workspace/f-stack/` | Exists |
| Existing architecture docs | `/data/workspace/f-stack/docs/01-LAYER1-ARCHITECTURE.md` etc. | Exist |

---

## 11. Outputs (final deliverables of this Spec phase, all 9 delivered)

> Status as of 2026-05-28: all 9 deliverables landed (Phases 1-5 finished on 2026-05-26); on 2026-05-28 an additional independent audit v0.2 (98-independent-audit-report.md) and 6 must-fix revisions were appended. See `99-review-report.md` §1 (volume table) and §12 (revision log).

| # | File | Status |
|---|---|---|
| 1 | `plan.md` | Delivered (2026-05-26; §1.3/§8 status corrected on 2026-05-28) |
| 2 | `00-overview-and-glossary.md` | Delivered (2026-05-26; §5 syscall/if_t corrected on 2026-05-28) |
| 3 | **`01-requirements-spec.md`** | **This document** (delivered 2026-05-26; §11 status corrected on 2026-05-28) |
| 4 | `02-architecture-analysis.md` | Delivered (2026-05-26) |
| 5 | `03-freebsd-15-changes.md` | Delivered (2026-05-26; §1/§2.4/§3.3 corrected on 2026-05-28) |
| 6 | `04-diff-and-port-strategy.md` | Delivered (2026-05-26; §1/§2 rewritten on 2026-05-28 to a measured version) |
| 7 | `05-implementation-plan.md` | Delivered (2026-05-26) |
| 8 | `06-test-and-acceptance-spec.md` | Delivered (2026-05-26; §4.2 if_t corrected on 2026-05-28) |
| 9 | `99-review-report.md` | Delivered (2026-05-26; §7/§10/§12 expanded on 2026-05-28) |
| 10 | `98-independent-audit-report.md` | Independent audit v0.2 (report issued at 2026-05-26 19:45; 6 must-fix revisions completed on 2026-05-28) |
