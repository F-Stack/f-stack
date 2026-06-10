# 01 — Requirements Specification

> Document version: v0.1 (2026-06-09 17:50 UTC+8)
> Author: spec-author
> Scope: CMocka unit-test framework for the 11 FF_HOST_SRCS files of F-Stack `lib/`

---

## 1. Document Purpose

This spec lists, for the current task (spec phase only): (1) functional
requirements FR-U-x; (2) non-functional requirements NFR-U-x; (3) risks
R-U-x; (4) decisions DP-U-x; (5) acceptance gates G1-G4; (6) entry
conditions. All IDs are referenced by the remaining spec documents
(02 / 04 / 06 / 99).

---

## 2. Functional Requirements (FR-U-x)

### 2.1 Spec-document level (FR-U-1..3)

| ID | Description | Acceptance |
|---|---|---|
| **FR-U-1** | All 7 Chinese spec documents land under `docs/unit_test_spec/zh_cn/` | `ls docs/unit_test_spec/zh_cn/*.md \| wc -l` ≥ 7 (plan + 6 specs) |
| **FR-U-2** | Every line citation in the 6 tracked specs is verified against actual code | gate-keeper samples ≥10 cross-checks; hit rate = 100% |
| **FR-U-3** | spec 04 contains a Unity → CMocka API mapping table with ≥15 rows | grep `assert_int_equal\\|assert_string_equal` ≥15 rows |

### 2.2 Test-scope level (FR-U-4..6)

| ID | Description | Acceptance |
|---|---|---|
| **FR-U-4** | spec 02 contains the full FF_HOST_SRCS 11-file list + P0/P1/P2/P3 tiering | spec 02 §2 / §3 tables have 11 rows; tier total = 11 |
| **FR-U-5** | spec 04 contains the mock-strategy matrix: 11 files × 4 dependency classes (rte/pthread/sys/printf) | spec 04 §7 table has ≥11 × 4 = 44 cells filled with measured data |
| **FR-U-6** | spec 06 contains a TC-U-* draft for the P0/P1 files | spec 06 §3 + §4 total ≥25 cases; ≥10 per P0 file; ≥6 per P1 file |

### 2.3 Methodology level (FR-U-7..9)

| ID | Description | Acceptance |
|---|---|---|
| **FR-U-7** | Test-case naming follows the `test_<func>_<scenario>` convention (c-unittest-expert.mdc methodology) | spec 06 sampling of 5 names — all conformant |
| **FR-U-8** | Boundary coverage includes at least: empty input / extreme length / illegal characters / NULL pointer / duplicate key — 5 categories | spec 06 §5 boundary-coverage table has ≥5 rows |
| **FR-U-9** | Fatal-function handling (rte_exit / rte_panic / exit / abort) has an explicit wrap strategy | spec 04 §8 contains code snippets using `__wrap_*` + `longjmp` / `mock_assert` |

---

## 3. Non-Functional Requirements (NFR-U-x)

### 3.1 Quality attributes (NFR-U-1..3)

| ID | Description | Threshold |
|---|---|---|
| **NFR-U-1** | Spec grounded-ness | Each spec ≥80% of statements carry a line citation or code snippet; gate-keeper sampling hit rate = 100% |
| **NFR-U-2** | Cross-spec consistency | Across all 5 specs, line numbers, terminology, decision IDs, risk IDs, and TC-IDs are 100% consistent |
| **NFR-U-3** | Line-budget compliance | Each spec's actual line count is within ±20% of its budget (plan §0.2) |

### 3.2 Test-system quality (NFR-U-4..6 — these are the NFRs of Phase 2+, but described in this spec)

| ID | Description | Threshold |
|---|---|---|
| **NFR-U-4** | Unit-test portability | Depends only on `pkg-config cmocka`; 0 private patches; ≥98% test pass rate on TencentOS 4.4 + Ubuntu 22.04 + RHEL 9 |
| **NFR-U-5** | Unit-test runtime | Full P0 + P1 suite < 30s (rough estimate; spec 04 §10 lists the concrete budget) |
| **NFR-U-6** | Decoupling from lib/ build | `tests/unit/` has its own Makefile, **does not modify a single line of `lib/Makefile`**, and **does not link the entire libfstack.a** (avoiding pulling in the FreeBSD kernel-subset) |

### 3.3 Engineering compliance (NFR-U-7..8)

| ID | Description | Threshold |
|---|---|---|
| **NFR-U-7** | 0 direct rm/kill/chmod calls | Throughout the spec phase, grepping `rm[^_t]\\|^kill\\b\\|^chmod\\b` in commits/logs returns 0 hits |
| **NFR-U-8** | Local commit only | 1 commit during the spec phase; no push; plan.md kept out of the repo per .gitignore |

---

## 4. Risk Register (R-U-x, synced with plan §5)

> Severity: High = project-blocking / Mid = phase-blocking / Low = minor adjustment risk

| ID | Risk | Severity | Mitigation | Detection |
|---|---|---|---|---|
| **R-U-1** | DPDK rte_* mock effort explodes (ff_dpdk_if.c has 173 rte_ calls) | **High** | P2 follow-up; spec 04 §7 only plans mocks for the "pure-function subset" | mock-strategist Phase 2 ✓ |
| **R-U-2** | FreeBSD vs host compilation differences | Mid | spec 04 §6 lists a host-only compilation matrix; the test Makefile uses `uname -s` guards | spec 04 drafting |
| **R-U-3** | CMocka 1.1.7 vs 1.1.5/1.1.0 API differences | Low | spec 04 §2 pins ≥1.1.7; `pkg-config --modversion cmocka` validation | Phase 2 landing |
| **R-U-4** | Function signatures change after the DPDK 24.11.6 upgrade | Mid | Each row of the spec 04 §7 mock matrix is annotated "DPDK 24.11.6 verified" | gate-keeper review |
| **R-U-5** | All 11 ff_config.c handlers are static and not directly testable | **High (closed)** | spec 06 §3.4 provides a dual strategy: end-to-end .ini fixture + `#include "ff_config.c"`; end-to-end is preferred | target-prioritizer Phase 2 ✓ closed |
| **R-U-6** | ff_ini_parser.c is BSD-licensed third-party inih, with limited unit-test value | Mid | spec 06 §3 explicitly states "test the F-Stack integration wrapper + inih state-machine coverage"; do not retest inih internals | spec 06 drafting |
| **R-U-7** | mock-strategist and target-prioritizer outputs conflict | Low | Phase 3 spec-author unifies them; gate-keeper Phase 4 cross-checks | Phase 3-4 |
| **R-U-8** | Linking libfstack.a into a test binary triggers FreeBSD kernel-subset compilation explosion | **High** | spec 04 §5 mandates "link only the .o under test + minimum stubs"; do not link the whole libfstack.a | spec 04 drafting |
| **R-U-9** | gate-keeper bounce ≥4 triggers escalation | Low | Bounce cap = 3; ≥4 writes ESCALATION-INFO.md | Phase 4 |
| **R-U-10** | iwiki / external F-Stack-CMocka material is scarce | Low | Explicitly mark "no match"; reference CMocka official docs + Samba / libssh / DPDK app/test/ CMocka usage | reviewer/spec-author |
| **R-U-11** | Coverage tooling conflicts with CMocka flags | Low | spec 04 §6 provides `-fprofile-arcs -ftest-coverage` + CMocka-compatible compile flags | Phase 2 landing |
| **R-U-12** | Workspace mandatory-rule violations (direct rm/kill/chmod) | **Zero tolerance** | All wrapper calls in the specs are explicitly annotated; reviewer compliance gate | Whole process |
| **R-U-13** | rte_exit / rte_panic without wrap kill the unit-test process (**new**) | **High** | spec 04 §8 mandates `__wrap_rte_exit` + `__wrap_rte_panic` + `mock_assert(false)` replacement | mock-strategist Phase 2 ✓ |
| **R-U-14** | ff_log_open_set / ff_log_close depend on the `ff_global_cfg` global (**new**) | Mid | spec 06 §3.2 provides an ff_global_cfg fixture template | spec 06 drafting |

---

## 5. Decision Points (DP-U-x, synced with plan §4)

### 5.1 Decided (no further discussion in the spec phase)

| ID | Decision | Value | Source |
|---|---|---|---|
| **DP-U-1** | Directory naming | `docs/unit_test_spec/zh_cn/` | User conversation |
| **DP-U-2** | Document language | Chinese (English deferred) | User original requirement |
| **DP-U-3** | Number of specs | Lean 7 | plan_create |
| **DP-U-4** | Test framework | CMocka 1.1.7 (already installed) | User decision |
| **DP-U-5** | Methodology reference | `c-unittest-expert.mdc` (Unity-based) but APIs mapped to CMocka | User original requirement §6 |
| **DP-U-6** | Test directory | `f-stack/tests/unit/` | GNU project convention |
| **DP-U-7** | Build system | Standalone GNU Makefile + pkg-config | Consistent with lib/Makefile style |
| **DP-U-8** | Bounce cap | 3 | Same as vlan-test / dpdk-23-24 |
| **DP-U-9** | KG handling | Reviewer queries the MCP directly; no reindex | spec phase does not modify code |
| **DP-U-10** | Backup directory | `f-stack/.spec-backup/unit-test-spec/` | In-repo local backup (see plan §6) |
| **DP-U-11** | Scope | FF_HOST_SRCS 11 files; KERN_SRCS out-of-scope | §1.2 measurement |

### 5.2 Closed after Phase 2 research (DP-U-Bx)

| ID | Decision | Value | Closure source |
|---|---|---|---|
| **DP-U-B1** | P1 scope | `ff_host_interface.c` + `ff_epoll.c` + `ff_config.c` (end-to-end) | target-prioritizer Phase 2 |
| **DP-U-B2** | `ff_dpdk_kni.c` priority | **P2** (extremely high mock complexity; only pure-function subset can be tested) | mock-strategist + target-prioritizer Phase 2 |
| **DP-U-B3** | DPDK rte_* mock boundary | CMocka `__wrap_*` linker substitution; fatal functions (rte_exit/panic) replaced with mock_assert; non-fatal pure functions (rte_eal_process_type, etc.) use will_return | mock-strategist Phase 2 |
| **DP-U-B4** | Coverage tooling integration in P0 phase | **Not integrated** (only NFR metrics are listed in the spec; the actual hookup is in Phase 3) | Simplifies the P0 start |
| **DP-U-B5** | tests/unit/ subdirectory layout | By source-file name (`tests/unit/test_ff_ini_parser.c` / `test_ff_log.c`, etc.) | Simplifies tracking |
| **DP-U-B6** | Standard `make test` / `make check` targets | spec 04 §6 provides `make test` (default) + `make check` (with valgrind) | GNU style |
| **DP-U-B7** | TC-U-* lower bound | ≥10 per P0 file; ≥6 per P1 file (FR-U-6) | spec 06 |
| **DP-U-B8 (new)** | Re-selection of P0 | **`ff_ini_parser.c` + `ff_log.c`** | target-prioritizer adjustment: original plan §1.1 listed "ff_config.c parser handlers subset", but since they are all static, they were moved to P1 (end-to-end) |

### 5.3 Decisions deferred to Phase 2/3 (not closed in the spec phase)

| ID | Decision | Time |
|---|---|---|
| **DP-U-C1** | CI integration (GitHub Actions / internal CI) | Phase 5 |
| **DP-U-C2** | Mutation testing (mutpy / mull) | Phase 5 |
| **DP-U-C3** | Extending nginx_fstack / helloworld integration tests | Phase 5 |
| **DP-U-C4** | Pure-function subset tests for ff_dpdk_if.c (4 candidates: `ff_rss_check` / `ff_rss_tbl_get_portrange` / `ff_in_pcbladdr` / `ff_get_tsc_ns`) | Phase 5 |

---

## 6. Acceptance Gates (Gx, synced with plan §3.4)

| Gate | Check | PASS condition |
|---|---|---|
| **G1 spec landing** | `ls docs/unit_test_spec/zh_cn/` ≥ 7 markdown files | All 7 docs exist + line count within budget ±20% |
| **G2 cross-check** | gate-keeper samples ≥10 line citations against actual code | Hit rate = 100% |
| **G3 4-dim score** | Consistency / Completeness / Risk-coverage / Executability | All ≥A (4-grade scale) |
| **G4 compliance** | grep `^rm \\|^kill \\|^chmod ` direct calls | 0 hits across the entire spec-phase commit/log |

---

## 7. Entry Conditions (already satisfied for the spec phase)

| Condition | Status |
|---|---|
| ✅ CMocka 1.1.7 installed via dnf | confirmed in earlier dialog |
| ✅ All workspace skills installed (c-unittest-expert.mdc / spec-driven / harness-engineering-orchestrator) | greps confirmed |
| ✅ KG ready (`.gitnexus/`) | ls confirmed |
| ✅ docs three-layer architecture + existing spec templates ready | ls confirmed |
| ✅ git working tree clean | git status confirmed |
| ✅ Workspace wrapper scripts available | ls -l confirmed |

---

**End of document (v0.1)**
