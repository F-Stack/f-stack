# F-Stack FreeBSD 13.0 → 15.0 Upgrade Spec Work Plan

> Chinese version: ./zh_cn/plan.md (full prose detail)
>
> Doc series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-26; §1.3 / §8 status updated 2026-05-28)
> Author: Leader (in main dialogue)
>
> NOTE: This English version is a structural condensation. All section headings, sub-section IDs, deliverable list, agent-team role definitions, phase order, decision-point IDs (DP-1..5), and the 5 external-research items are preserved verbatim from the Chinese master.

---

## 0. Plan Goals

### Deliverables (must end up under `freebsd_13_to_15_upgrade_spec/zh_cn/`)

The 9-doc spec set: `plan.md`, `00-overview-and-glossary.md`, `01-requirements-spec.md`, `02-architecture-analysis.md`, `03-freebsd-15-changes.md`, `04-diff-and-port-strategy.md`, `05-implementation-plan.md`, `06-test-and-acceptance-spec.md`, `99-review-report.md` (later supplemented with `98-independent-audit-report.md` v0.2 on 2026-05-28; and English-version translations under the parent directory).

---

## 1. Workspace State and Boundaries (measured, not guessed)

### 1.1 Three source-tree roots

| Path | Role | Version |
|---|---|---|
| `/data/workspace/freebsd-src-releng-13.0/` | Community FreeBSD 13.0 | RELEASE-p2 |
| `/data/workspace/freebsd-src-releng-15.0/` | Community FreeBSD 15.0 | RELEASE-p9 |
| `/data/workspace/f-stack/` | F-Stack project root | adapted from 13.0 |

### 1.2 13.0 original backup (exists)

`/data/workspace/freebsd-src-releng-13.0/f-stack-lib/` — 25 freebsd + 22 tools subdirectories.

### 1.3 15.0 original backup (**created in Phase 1.4, 2026-05-26**)

`/data/workspace/freebsd-src-releng-15.0/f-stack-lib/` — 25,044 files (`freebsd/` 24,593 + `tools/` 451 + INVENTORY.md). Status status corrected 2026-05-28: this directory exists.

### 1.4 F-Stack already-adapted directories (core upgrade subject)

f-stack/freebsd/ (102 diffs vs 13.0 backup) + f-stack/tools/ (163 diffs).

### 1.5 `f-stack/lib/` scope to include in upgrade (**q2-corrected precise boundary**)

30 `.c` + 14 `.h` = 44 ff_* glue files; precise inventory in 02 §4.

### 1.6 13.0 ↔ 15.0 sys-top-level diff (measured)

(Full table in Chinese master; see 04 §1 for the per-subdir authoritative diff -rq stats added 2026-05-28.)

---

## 2. Agent Team Composition (hybrid mode)

### 2.1 Leader (executed in main dialogue)

| Item | Detail |
|---|---|
| Role | Leader |
| Responsibility | Owns the whole plan; orchestrates 3 subagents; writes the 7 specs and 99 report; handles user q&a; final sign-off |
| Implementation | Main dialogue only (no `Task` spawn) |

### 2.2 Sub-Agent A: Analyzer-13 (code-explorer subagent)

| Item | Detail |
|---|---|
| Role | Analyzer-13 |
| Responsibility | Measure F-Stack adaptation footprint vs the 13.0 baseline; produce the 9-pattern adaptation inventory (H-1..H-9) |
| Implementation | `Task` tool → `code-explorer` subagent (read-only) |

### 2.3 Sub-Agent B: Analyzer-15 (code-explorer + web research)

| Item | Detail |
|---|---|
| Role | Analyzer-15 |
| Responsibility | Measure 13→15 upstream changes in `sys/` + external research (FreeBSD release notes / mailing lists / commit logs / blogs) for 14.0+ ABI/KPI breakage |
| Implementation | `Task` tool → `code-explorer` subagent + `web_search` / `web_fetch` |

### 2.4 Sub-Agent C: Diff-Comparator (code-explorer subagent)

| Item | Detail |
|---|---|
| Role | Diff-Comparator |
| Responsibility | Cross-cut Sub-Agent A + B outputs; produce the `04-diff-and-port-strategy.md` per-file port-task table |
| Implementation | `Task` tool → `code-explorer` subagent (read-only) |

### 2.5 Spec-Writer & Reviewer (Leader concurrent in main dialogue)

| Item | Detail |
|---|---|
| Role | Spec-Writer + Reviewer |
| Responsibility | Spec-Writer drafts 00-06 + 99 + 98 from Sub-Agent A/B/C inputs; Reviewer reviews internally |
| Implementation | Leader in main dialogue executes both |

---

## 3. Execution Steps (chronological)

### Phase 1: Material readiness (Leader in main dialogue)

1.1 Probe workspace
1.2 Create output directory `f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
1.3 Produce `plan.md` (this document)
1.4 **Create 15.0 backup** `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/` (cp -a + INVENTORY.md generation)

### Phase 2: Parallel research (spawn 3 code-explorer subagents)

2.A Sub-Agent A executes Analyzer-13
2.B Sub-Agent B executes Analyzer-15
2.C Sub-Agent C executes Diff-Comparator

### Phase 3: Produce 7 spec docs (Leader+Spec-Writer in main dialogue)

3.1 00-overview-and-glossary.md
3.2 01-requirements-spec.md
3.3 02-architecture-analysis.md
3.4 03-freebsd-15-changes.md
3.5 04-diff-and-port-strategy.md
3.6 05-implementation-plan.md
3.7 06-test-and-acceptance-spec.md

### Phase 4: Reviewer audit (Leader+Reviewer)

Audit the 7 specs along 4 dimensions (consistency / completeness / risk coverage / executability) and produce 99-review-report.md.

### Phase 5: Delivery report

Aggregate the 9 deliverables; explicit "no git / no source change" declaration; pointer to M1 implementation entry.

---

## 4. Risks and Key Decision Points

### 4.1 Identified risks (each elaborated by the spec docs)

(See 03 §7 for the full panorama: R-001 mips / R-002 netlink / R-003 mbuf / R-004 RACK / R-005 pkgbase / R-006 KTLS / R-007 ABI break / R-008 baseline drift / R-009 clang/llvm / R-010 inotify-OOS / R-011 pr_usrreqs / R-012 inpcb SMR / R-013 if_t opaque.)

### 4.2 Key decision points (must be answered explicitly when writing specs in Phase 3)

| DP | Decision | Default tendency |
|---|---|---|
| DP-1 | Whether to delete `f-stack/freebsd/mips/` | **Delete** |
| DP-2 | Whether to pull sys/netlink/ into f-stack/freebsd/ | **Do NOT introduce** |
| DP-3 | Sync strategy: big-bang full sync vs progressive | **Progressive (M1→M5)** |
| DP-4 | Whether ff_*.c is upgraded in lockstep with f-stack/freebsd | **Must be in lockstep** |
| DP-5 | Whether tools/ upgrade is its own milestone | **Independent M5** |

---

## 5. Relationship with Existing F-Stack Docs

(See 00 §6 / 02 §5 for the full mapping. Summary: reuse the 3-layer architecture docs + knowledge-graph; do NOT reuse ld_preload_ring_spec/ workstream.)

---

## 6. External Research Inventory (for Analyzer-15)

5 items (see Chinese master for the full URL inventory): (1) FreeBSD 14.0R/14.1R/14.2R/14.3R/14.4R/15.0R release notes; (2) `pr_usrreqs` merge phabricator review; (3) `inpcb` SMR migration commits + design; (4) `if_t` opaque-ization design; (5) `routing/rib/nexthop` rewrite (D26577).

---

## 7. Things Out of Scope of This Plan

| Item | Note |
|---|---|
| Actual code migration and build verification | Spec phase only; later phases handle |
| Performance benchmarks / stress tests | No binary built |
| Git commit / push | Only working-tree files written |
| English Spec | (Later satisfied by the English translation pass — see 99 §1 final-review entry) |
| 15.0 new-capability ports (netlink port / ML-KEM / inotify / timerfd / kqueuex / membarrier) | "Alignment only, no capability extension" |
| F-Stack `adapter/syscall/` | Independent workstream `docs/ld_preload_ring_spec/` |

---

## 8. Pacing Control (harness-engineering-orchestrator style)

(Plan finished entirely on 2026-05-26; on 2026-05-28 entered audit-revision phase + v0.2 independent audit; on 2026-05-29 M1-M5 implementation closed and project final delivery PASS.)

**Current status (2026-05-29 / project closure)**: Phase 1-5 + v0.2 audit all delivered; M1-M5 implementation all done; G-Acceptance PASS. The plan has been fully executed.
