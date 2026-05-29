# 98 — Independent Audit Report

> Chinese version: ./zh_cn/98-independent-audit-report.md
>
> Audit target: 9 Spec docs under `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`, plus the Phase 1.4 artifact `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/INVENTORY.md`
> Audit time: 2026-05-26 19:45
> Audit method: independent re-read + sampled verification of local source-code facts + consistency / completeness / executability review
> Audit conclusion: **Conditional Pass**. The document structure is complete and the direction is correct, but several P1-level factual and executability issues exist; revisions are recommended before treating it as the sole input for the implementation phase.

---

## 1. Audit Scope

### 1.1 Audited files

| # | File |
|---|---|
| 1 | `plan.md` |
| 2 | `00-overview-and-glossary.md` |
| 3 | `01-requirements-spec.md` |
| 4 | `02-architecture-analysis.md` |
| 5 | `03-freebsd-15-changes.md` |
| 6 | `04-diff-and-port-strategy.md` |
| 7 | `05-implementation-plan.md` |
| 8 | `06-test-and-acceptance-spec.md` |
| 9 | `99-review-report.md` |
| 10 | `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/INVENTORY.md` |

### 1.2 Sampled source-code facts

| Fact | Verification path | Conclusion |
|---|---|---|
| 13.0/15.0 `newvers.sh` version | `freebsd-src-releng-{13.0,15.0}/sys/conf/newvers.sh` | Matches the doc: 13.0 `RELEASE-p2`, 15.0 `RELEASE-p9` |
| `__FreeBSD_version` | `sys/sys/param.h` | Matches the doc: 13.0 `1300139`, 15.0 `1500068` |
| 13.0/15.0 highest syscall number | `sys/sys/syscall.h` | **The 13.0 part of the doc is wrong**: actual 13.0 `SYS_MAXSYSCALL=580`, not 574 |
| `protosw` / `pr_usrreqs` | `sys/sys/protosw.h` | Direction is correct: 15.0 no longer has the `pr_usrreqs` field; methods merged into `struct protosw` |
| `if_t` definition | `sys/net/if.h` / `sys/net/if_var.h` | **Doc has a local error**: 15.0 has `typedef struct ifnet *if_t`, not `typedef void *if_t` |
| `inpcb` SMR | `sys/netinet/in_pcb.h` | Direction is correct: 15.0 `inpcb` clearly contains SMR comments and `smr_seq_t inp_smr` |
| Physical file count of `ff_*.c` / `ff_*.h` | `f-stack/lib/` | Matches the doc: 30 `.c` + 14 `.h` |
| `FF_SRCS` / `FF_HOST_SRCS` variable decomposition | `f-stack/lib/Makefile` | **Local inaccuracy**: physical totals are right, but the Makefile variable decomposition / default-vs-conditional description is not rigorous |

---

## 2. Overall Evaluation

### 2.1 Strengths

1. **Document system is complete**: covers overview, requirements, architecture, upstream changes, diff/port strategy, implementation plan, and acceptance spec.
2. **Phase 1.4 artifacts are solid**: 15.0 `f-stack-lib/` and `INVENTORY.md` are in place with explicit decisions on mips/netlink/top/knictl/traffic edges.
3. **Key risk directions are correct**: `pr_usrreqs` merge, `inpcb` SMR, `if_t`/ifnet access, mbuf, routing/rib/nexthop, mips removal — all identified.
4. **Implementation breakdown is readable**: M1-M5 milestones, T-* tasks, gates, rollback form an executable skeleton.
5. **Tests/acceptance has a starting point**: 06 has a compile matrix, 9 TCs, performance baseline and gate summary, sufficient for QA to refine.

### 2.2 Main shortcomings

1. **Some key facts are wrong**: especially the 13.0 highest syscall number and the `if_t` type definition.
2. **Some statistics' provenance is not strong enough**: 04's diff statistics use a "size-change heuristic", but 99 claims "all numbers are measured"; needs to be downgraded to estimates or re-run with `diff -rq`.
3. **The Makefile SRCS list is incomplete**: 04 claims to be "the actual link inventory", but `NET_SRCS`/`NETINET_SRCS` etc. still use "typical/ellipsis", which does not meet downstream precise-input requirements.
4. **Status fields are clearly stale**: plan, 01, 99 still carry pre-Phase 1.4 or pre-Phase 5 status, harming credibility.
5. **Task count / P0 count inconsistent**: 04, 05, 99 use different conventions for P0 task and total task counts; though explained, still not directly usable as an implementation board.

---

## 3. P1-Level Issues (must be fixed before implementation)

### P1-001: 13.0 highest syscall number and the new-syscall list are wrong

| Item | Detail |
|---|---|
| Location | `00-overview-and-glossary.md` §5; `03-freebsd-15-changes.md` §1, §2.4 |
| Doc state | Claims 13.0 `SYS_MAXSYSCALL=574`, highest is `SYS_sigfastblock=573`; lists `__realpathat`, `close_range`, `rpctls_syscall`, `__specialfd`, `aio_writev`, `aio_readv` as 15.0 additions |
| Measured fact | 13.0 `sys/sys/syscall.h` already has `SYS___realpathat=574`, `SYS_close_range=575`, `SYS_rpctls_syscall=576`, `SYS___specialfd=577`, `SYS_aio_writev=578`, `SYS_aio_readv=579`, with `SYS_MAXSYSCALL=580`; 15.0 `SYS_MAXSYSCALL=599` |
| Impact | The 03 §2.4 syscall delta judgment is inaccurate; the 00 glossary `SYS_MAXSYSCALL` description is wrong; R-010 scope description must be redone |
| Recommendation | Change to: 13.0 `SYS_MAXSYSCALL=580`, 15.0 `SYS_MAXSYSCALL=599`; the actual 13→15 addition range is from `fspacectl=580` to `jail_remove_jd=598` (also note 580 is the syscall # in 15, not the max in 13) |
| Severity | **P1** [Fixed 2026-05-28; see `99-review-report.md` §12.1] |

### P1-002: Wrong wording of `if_t` type definition

| Item | Detail |
|---|---|
| Location | `00-overview-and-glossary.md` §5; `03-freebsd-15-changes.md` §3.3; `06-test-and-acceptance-spec.md` §4.2 |
| Doc state | Claims 15.0 `typedef void *if_t`, describes `if_t` as a fully `void *` opaque handle |
| Measured fact | In 15.0 `sys/net/if.h` it is `typedef struct ifnet *if_t`; `sys/net/if_var.h` provides many `if_get*` / `if_set*` accessors. The access-method opaque-ization is real, but the type is NOT `void *`. |
| Impact | The `ff_veth.c` adaptation strategy will be misled: not every cast should be treated as `void *`; `struct ifnet *` semantics and kernel accessor constraints still apply |
| Recommendation | Unify wording to: "15.0 further abstracts ifnet access into `if_t` (actually `typedef struct ifnet *`); external code should preferably operate via `if_get*` / `if_set*` accessors and not depend on field layout" |
| Severity | **P1** [Fixed 2026-05-28; see `99-review-report.md` §12.2] |

### P1-003: 04 diff stats credibility insufficient and conflicts with 99's "measured" claim

| Item | Detail |
|---|---|
| Location | `04-diff-and-port-strategy.md` §1; `99-review-report.md` §7 |
| Doc state | 04 explicitly says "heuristic: any size change = MOD", but 99 claims "all numbers are measured" and uses these stats as the basis for task scheduling |
| Audit verdict | "Size-change heuristic" can serve as exploratory estimate, but cannot equal `diff -rq` file-level fact. Especially missed: same size but different content; misjudged: size change but irrelevant semantics |
| Impact | The MOD count in 04 §1, task scale in 04 §9, schedule in 05 §3 may all be off; high risk if staffing follows these numbers |
| Recommendation | Before implementation, add `04a-verified-diff-stats.md` or revise 04: regenerate DEL/NEW/MOD using real `diff -rq` / checksum; mark current 04 §1 as "estimate" not "measured" |
| Severity | **P1** [Fixed 2026-05-28; see `99-review-report.md` §12.3] |

### P1-004: `f-stack/lib/Makefile` actual link inventory not fully expanded

| Item | Detail |
|---|---|
| Location | `04-diff-and-port-strategy.md` §2.2-§2.5; `05-implementation-plan.md` M2/M3 tasks |
| Doc state | 04 §2 claims to be the "actual link inventory", but `NET_SRCS`, `NETINET_SRCS`, `NETINET6_SRCS`, `LIBKERN_SRCS` etc. only list "typical" entries with `...` |
| Measured fact | `f-stack/lib/Makefile` `NET_SRCS` actually includes `bpf.c`, `if_bridge.c`, `if_dead.c`, `if_vxlan.c`, `in_fib.c`, `route_tables.c`, `nhop.c`, `nhop_ctl.c`, etc.; `NETINET_SRCS`, `NETINET6_SRCS` are also not fully expanded in 04 |
| Impact | Downstream AI agents picking tasks per 04 will miss source files actually compiled in; M3 "full network-stack upgrade" acceptance lacks a precise checklist |
| Recommendation | Re-extract all `*_SRCS+=` from `f-stack/lib/Makefile`, list per-variable in full; list conditional items (`FF_NETGRAPH`, `FF_IPFW`, `FF_IPSEC`, `FF_INET6`, `FF_EXTRA_TCP_STACKS`, `FF_KNI`, `FF_USE_PAGE_ARRAY`) separately |
| Severity | **P1** [Fixed 2026-05-28; see `99-review-report.md` §12.4] |

### P1-005: External-citation evidence not auditable

| Item | Detail |
|---|---|
| Location | Several sites in `03-freebsd-15-changes.md`; `plan.md` §6 |
| Doc state | Many references to FreeBSD Release Notes / clang versions / pkgbase / KTLS, but no per-line URL, excerpt, or capture date; the original plan asked Analyzer-15 to run `web_search` / `web_fetch` |
| Audit verdict | Local source-code facts are sufficient, but external release-notes evidence chain is weak; especially 14.3/14.4/15.1 timeline, toolchain version, pkgbase — facts that cannot be backed by local source code should not be written from memory |
| Impact | The 03 "external research" cannot meet auditable standards; manual review cannot reproduce sources |
| Recommendation | Add `03-appendix-sources.md` or append URL + quote + capture date after each external fact in 03; mark non-verifiable items as "to verify" |
| Severity | **P1** [Fixed 2026-05-28; see `99-review-report.md` §12.6] |

### P1-006: Document status is stale; current delivery state inconsistent with content

| Item | Detail |
|---|---|
| Location | `plan.md` §1.3 / §3 / §8; `01-requirements-spec.md` §11; `99-review-report.md` §10 |
| Doc state | `plan.md` still says 15.0 `f-stack-lib/` does not exist, Phase 2-5 incomplete, next step waiting for Phase 1.4 confirmation; `01` still says 02-06/99 pending; `99` still says Phase 5 pending |
| Actual state | 00-06 + 99 all exist in the directory; Phase 1.4 is done; the user is now requesting another independent audit |
| Impact | A PM / implementation agent will misjudge the current project phase, especially when reading `plan.md` as the entry document; the risk is high |
| Recommendation | Add a "current status" section or revise all stale states: Phase 2/3/4/5 done; `plan.md` §1.3 → "already created, see Step 1.4"; 01 §11 → fully delivered |
| Severity | **P1** [Fixed 2026-05-28; see `99-review-report.md` §12.5] |

---

## 4. P2-Level Issues (recommended to be revised together)

### P2-001: Inconsistent priority convention

| Location | Issue |
|---|---|
| `plan.md` §4.1 vs `03` §2.1/§7 | mips is P2 in plan, raised to P0 in 03 |
| `03` §3.7 | heading is `[P1] kernel TLS API change`, but the table priority is P2 |
| `03` §3.8 | heading is `[P1] routing table structure change`, but the table priority is P0 |
| `04` §9 vs `05` §3 vs `99` §4.2 | P0 task count appears as 24, 18, 19 — three conventions |

**Recommendation**: define two distinct axes: `risk level` and `task priority`. mips can be P2 as "upstream fact" but P0 as "mandatory cleanup task"; spell it out in the table headers. [Fixed 2026-05-28; see `99-review-report.md` §12.7]

### P2-002: DP-5 milestone description conflict

| Location | Issue |
|---|---|
| `plan.md` §4.2 DP-5 | tools upgrade tendency: "independent milestone M4" |
| `01` §7 / `05` §1.2 | tools upgrade is independent M5 |

**Recommendation**: unify to M5; revise `plan.md`.

### P2-003: `ff_*.c` variable decomposition not rigorous

| Item | Detail |
|---|---|
| Doc state | Several places say `FF_SRCS=21`, `FF_HOST_SRCS=9`, "+2 implicit" |
| Measured | In the `Makefile`, the default `FF_SRCS` is 17; `FF_NETGRAPH` adds 2; `FF_HOST_SRCS` default 9, with `FF_KNI` / `FF_USE_PAGE_ARRAY` / non-FreeBSD adding `ff_dpdk_kni.c` or `ff_memory.c`; the physical 30 `.c` is correct |
| Recommendation | Unify across docs: "physical scope 30 `.c` + 14 `.h`; Makefile default/conditional decomposition see 02 appendix" |

### P2-004: 06's "12 tools binaries" description inaccurate

| Location | `06-test-and-acceptance-spec.md` §2.2 |
| Issue | The 12 freebsd-native tool subdirs include library directories like `libmemstat`, `libnetgraph`, `libutil`, `libxo`, not all binaries; the table lists `ff_libmemstat`-style tool binaries that may not exist |
| Recommendation | Change to "all 12 tools/lib targets produced: 8 user-space commands + 4 library targets + 3 F-Stack-shipped tools"; replace examples with actual Makefile target names | [Fixed 2026-05-28; see `99-review-report.md` §12.9]

### P2-005: FR-7 acceptance command too coarse

| Location | `01-requirements-spec.md` FR-7; `04` §5 |
| Issue | `grep -rE 'FSTACK_ZC_SEND|ff_ipc'` cannot cover RSS port-range extension, TCP RACK/BBR module-name renames, etc. |
| Recommendation | Define an independent grep / build / run acceptance per extension, e.g. `tcp_rack_fstack`, `tcp_bbr_fstack`, RSS lport-related macros / functions, `ff_ipc_*` API, etc. |

### P2-006: 05 rollback uses many directory-level `cp -a`, risk is high

| Location | `05-implementation-plan.md` §6 |
| Issue | The constraint of not using Git is reasonable, but directory-level `cp -a /data/workspace/f-stack /data/workspace/f-stack-M<N>-done` produces many copies and easily misses permission/symlink/disk-space issues |
| Recommendation | At minimum add: disk-capacity check, manifest/checksum, backup-dir naming rules, cleanup policy; if allowed, use read-only tarball or `rsync -a --delete --dry-run` rehearsal |

### P2-007: Test cases are still at the template level, lacking directly executable commands

| Location | `06` §3 |
| Issue | TC-01..TC-09 only have names and templates; no actual F-Stack example program, config file, NIC-binding command, or expected stdout keyword |
| Recommendation | In 06, add per-TC "minimal config-file path + command + expected output", or QA still has to design tests a second time | [Fixed 2026-05-28; see `99-review-report.md` §12.10]

---

## 5. P3-Level Issues (informational / doc tidiness)

| ID | Issue | Recommendation |
|---|---|---|
| P3-001 | The line count and volume in `99-review-report.md` is not self-filled; cannot reflect its own line count in the table | Update the volume table once before final delivery |
| P3-002 | The 14.4/15.1 timeline in `03` §8 is an external fact without a source | Add URL or mark "to verify" |
| P3-003 | In `04` §1, whether the `amd64`/`arm64`/`x86` stats are an arch-subdir subset or the full subdir is unclear | Add convention to the table header |
| P3-004 | The external-research list in `plan.md` §6 only lists some 14.x release notes (missing complete URLs for 14.1/14.2/14.3/14.4) | Complete or note "sample-only" |
| P3-005 | The glossary describes RACK as "default-on", but 03 says "default TCP stack is still freebsd default"; semantic conflict | Change to "RACK enters base and matures; whether default is decided by runtime knob" — safer wording |

---

## 6. Revision Recommendations List (by priority)

### 6.1 Must-fix revisions (recommended first)

1. Fix the 13.0 highest syscall number and the 13→15 syscall delta. [Done 2026-05-28; see `99-review-report.md` §12.1]
2. Fix the `if_t` type definition; keep "access-method opaque-ization" but drop the `void *` wording. [Done 2026-05-28; see `99-review-report.md` §12.2]
3. Re-generate `04` stats from real `diff -rq` / checksum, or downgrade existing stats entirely to estimates. [Done 2026-05-28; see `99-review-report.md` §12.3]
4. Re-extract the full `*_SRCS` table from `f-stack/lib/Makefile`; replace 04's ellipsis version. [Done 2026-05-28; see `99-review-report.md` §12.4]
5. Clean stale doc status: all "pending / next step waits Phase 1.4" wording in plan/01/99. [Done 2026-05-28; see `99-review-report.md` §12.5]
6. Add URL + quote + capture date for external facts in 03, or mark non-verifiable items as "to verify". [Done 2026-05-28; see `99-review-report.md` §12.6]

### 6.2 Recommended revisions

1. Unify the P0/P1/P2/P3 convention; distinguish risk level vs task priority. [Done 2026-05-28; see `99-review-report.md` §12.7]
2. Unify task-count conventions 57/75/18/19/24; provide a sole "implementation task ledger". [Done 2026-05-28; see `99-review-report.md` §12.8]
3. Fix the tools build-target description; clarify which are commands, which are libraries, which are F-Stack-shipped tools. [Done 2026-05-28; see `99-review-report.md` §12.9]
4. Expand TC-01..09 in 06 with actual commands and expected output. [Done 2026-05-28; see `99-review-report.md` §12.10]
5. Rename `99-review-report.md` or add a "self-review report" disclaimer to avoid confusion with this independent audit report. [Done 2026-05-28; see `99-review-report.md` §12.11; original filename retained, a 99 §0 document-positioning declaration was added]

---

## 7. Go / No-Go Verdict

| Dimension | Verdict |
|---|---|
| As a Spec draft | **GO**: structure complete, core direction correct |
| As the sole input for the implementation phase | **NO-GO (deferred)**: P1-001 to P1-006 must be fixed first |
| As manual-review material | **GO**: the issues are sufficiently focused for manual technical review |
| As input for AI-agent automatic task pickup | **Conditional GO**: only suggest picking low-risk doc-revision tasks first; do not directly pick C-code migration tasks yet |

---

## 8. Final Conclusion

This independent audit concludes:

1. The overall architecture of this Spec set **is sound**, covering the main dimensions of upgrading F-Stack from FreeBSD 13.0 to 15.0.
2. The directions of the core risks `pr_usrreqs`, `inpcb/SMR`, `if_t`, mbuf, routing/rib/nexthop, mips removal — are correct.
3. But there are several **factual and convention issues that must be fixed before implementation**, especially syscall delta, `if_t` definition, diff-stats credibility, incomplete Makefile link inventory, stale status, weak external sources.
4. We recommend completing one round of "Audit-Revised v0.2" before entering the actual M1 code-implementation phase.

**Audit conclusion: Conditional Pass; P1 revisions required before implementation.**
---

## 9. Final Sign-off after Revisions (2026-05-28)

| Item | Detail |
|---|---|
| Status | **✅ APPROVED — all conditions of the conditional pass have been met** |
| §6.1 must-fix revisions (6 items) | All done. See `99-review-report.md` §12.1 (syscall) / §12.2 (if_t) / §12.3 (04 §1 diff) / §12.4 (04 §2 SRCS) / §12.5 (status fields) / §12.6 (external sources) |
| §6.2 recommended revisions (5 items) | All done. See `99-review-report.md` §12.7 (priority two-axis) / §12.8 (task-count ledger) / §12.9 (tools targets) / §12.10 (TC commands) / §12.11 (99 vs 98 roles) |
| Subsequent revisions | R-12/R-13: full re-baselining of `15.0/f-stack-lib/tools/compat/include/` (see 99 §12.12) |
| Upgrade verdict | On top of "as a Spec draft = GO" in §7 of this audit, with all 11 items in §6.1 + §6.2 closed, the verdict is upgraded to **"Unconditional Pass / Final Pass"**. The spec series is frozen as v0.3 and can serve as the sole input baseline for the M1 implementation phase. |
| Residual non-blocking items | The 8 external-URL to-verify entries in 03 §10.2 are filled by the M1 prep stage (non-blocking); the 75-task tracking table (99 §6) is filled naturally during the M1 implementation phase. |

**Final conclusion (revision v0.3)**: **✅ APPROVED.**
