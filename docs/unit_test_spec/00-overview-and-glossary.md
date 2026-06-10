# 00 — Project Overview and Glossary

> Document version: v0.1 (2026-06-09 17:45 UTC+8)
> Author: spec-author (drafted from Phase 2 three-track research material)
> Scope: CMocka unit-test framework for the glue code (FF_HOST_SRCS) under
> the `lib/` directory of F-Stack v1.26 (FreeBSD 15.0 port + DPDK 24.11.6 LTS)

---

## 1. Project Background

F-Stack is a user-space TCP/IP stack that ports the FreeBSD network stack into
user space and delivers a high-performance data plane on top of DPDK. As of
2026-06-09, F-Stack has completed two large-scale upgrades (FreeBSD 13.0 → 15.0
and DPDK 23.11.5 → 24.11.6 LTS), yet **has never had a unit-test framework**:

- The `f-stack/` repository root contains no `tests/` / `test/` directory.
- No `#ifdef TEST` / `#ifdef UNITTEST` guards exist in `lib/*.c`.
- Existing runtime validation relies on (a) the helloworld primary stack
  bring-up + curl smoke test, (b) nginx_fstack multi-worker smoke runs, and
  (c) the phase-5b performance matrix.
- Those are **integration tests**; covering pure functions, string handling,
  and protocol parsing in the lib glue layer through them is prohibitively
  expensive.

→ This project introduces, for the first time, **real unit testing** for the
F-Stack lib layer (based on CMocka 1.1.7), starting from the easiest-to-reach
glue code and building a sustainable, evolvable testing system step by step.

## 2. Project Goals

| ID | Goal | Phase |
|---|---|---|
| **G-A** | Establish a **CMocka unit-test framework spec** for the host-side glue code under F-Stack `lib/` (FF_HOST_SRCS, 11 files) | **Current task (spec phase)** |
| **G-B** | Phase 2: scaffold the `tests/unit/` project + first hello-world test | Future |
| **G-C** | Phase 3: land the P0 cases (`ff_ini_parser.c` + `ff_log.c`) | Future |
| **G-D** | Phase 4: extend with P1 (`ff_host_interface.c` + `ff_epoll.c` + `ff_config.c` end-to-end) | Future |
| **G-E** | Phase 5: P2 follow-up (DPDK-heavy files) + CI integration + coverage gating | Future |

**This task scope = G-A only**, producing 7 Chinese spec documents (plan +
6 specs); no test code is written, `lib/*.c` is not modified, and
`lib/Makefile` is left untouched.

## 3. Scope (In-Scope / Out-of-Scope)

### 3.1 In-Scope

- ✅ The **11 glue-code files** listed in FF_HOST_SRCS (see 02 §2)
- ✅ Spec for the CMocka 1.1.7 framework integration approach
- ✅ Spec for the `tests/unit/` directory structure + draft Makefile
- ✅ Mock-strategy matrix for four classes of external dependencies
  (DPDK rte_* / pthread / epoll / printf)
- ✅ First-batch P0 test-case draft (TC-U-*)
- ✅ Unity → CMocka API mapping table (referencing the `c-unittest-expert.mdc`
  methodology)

### 3.2 Out-of-Scope

- ❌ Unit tests for KERN_SRCS (the kernel-subset port) — about 20 files
  (`ff_veth.c` / `ff_glue.c` / `ff_route.c` / `ff_kern_*.c` / `ff_subr_*.c` /
  `ff_syscall_wrapper.c`, etc.) which are essentially a FreeBSD-kernel
  subset. They are not directly host-compiled, the unit-test value is low,
  and the mocking effort would explode.
- ❌ Integration tests (already covered by helloworld + nginx + vlan-test)
- ❌ Performance tests (already covered by the phase-5b matrix)
- ❌ Bare-metal environment tests (handled by the user)
- ❌ CI integration (DP-U-C1, deferred to Phase 5)
- ❌ Mutation testing (DP-U-C2, deferred to Phase 5)
- ❌ English version of the spec (DP-U-2 decision: deferred until human audit
  of the Chinese version is complete)
- ❌ Actual test code / Makefile delivery (belongs to Phase 2+ G-B)

## 4. Relationship to the Existing System

### 4.1 Relationship to the docs/ three-layer architecture

| Three-layer doc | Relationship to this task |
|---|---|
| `docs/01-LAYER1-ARCHITECTURE.md` | All 11 files of this task fall under the L1-listed `lib/ff_dpdk_*.c` + `lib/ff_config.c` + `lib/ff_*.c` glue layer; spec 02 uses L1 file paths as anchors |
| `docs/02-LAYER2-INTERFACES.md` | The "non-static public API" list of this task maps 1:1 to the L2 interface contracts; specs 02 / 06 cite L2 function signatures |
| `docs/03-LAYER3-FUNCTIONS.md` | The static-helper / inih-handler list of this task is cross-validated against the L3 function index |

**After the spec is complete, the commit phase appends minimal anchor lines**
to L1 (the same pattern as dpdk-23-24 / vlan-test), but `docs/01-LAYER*.md`
is **not** touched during this spec phase.

### 4.2 Relationship to existing spec projects

| Project | Time | Style | Reused |
|---|---|---|---|
| `freebsd_13_to_15_upgrade_spec/` | 2025-2026 | Full 9-doc style | Backup-directory naming style / commit template |
| `dpdk_23_24_upgrade_spec/` | 2026-06-09 | **Lean 7-doc style** | **Reused by this task** |
| `unit_test_spec/` (this task) | 2026-06-09 17:35 | Lean 7-doc style | — |

### 4.3 Relationship to the c-unittest-expert.mdc rule

`workspace/.codebuddy/rules/c-unittest-expert.mdc` is a **Unity-based** Chinese
methodology rule. This task **reuses its methodology** (test naming /
setup-teardown / assertion granularity / boundary coverage), but **maps every
API to its CMocka form**. spec 04 §3 provides the **Unity → CMocka API
mapping table** (≥15 rows).

## 5. Glossary

| Term | Definition |
|---|---|
| **CMocka** | A lightweight unit-test framework for C (v1.1.7 already installed via `dnf install libcmocka libcmocka-devel`); home page https://cmocka.org/. Features: built-in mock + setjmp subprocess isolation + group fixture. |
| **FF_HOST_SRCS** | The host-side source-file list defined in `lib/Makefile` (lines 272-291 + 568-572), totaling 11 `.c` files compiled directly on the host — distinct from KERN_SRCS (the FreeBSD kernel-subset port). |
| **glue code** | Code that sits between the user-space TCP/IP stack and the DPDK PMD in F-Stack — primarily the `lib/ff_dpdk_*.c` / `lib/ff_config.c` files — and is the test target of this task. |
| **mock** | Replacing an external function called by the code-under-test with a CMocka `__wrap_*` (linker flag) or `mock()` macro to control its return value and verify its arguments. |
| **fixture** | The setup/teardown closure of `cmocka_unit_test_setup_teardown`, used to prepare/clean per-test resources (e.g., temporary `.ini` files, fake `ff_global_cfg`, etc.). |
| **assertion** | CMocka-provided macros such as `assert_int_equal` / `assert_string_equal` / `assert_non_null`, used to verify the output of code-under-test. |
| **inih** | The BSD-licensed third-party INI parser (https://github.com/benhoyt/inih) embedded into `ff_ini_parser.c`; the foundation for F-Stack's configuration parsing. |
| **handler** | The 11 `*_cfg_handler` functions (all static) in `ff_config.c`, callbacks under the inih `ini_handler` protocol used to parse each `[section] key=value`. |
| **P0/P1/P2/P3** | Test-priority tiers: P0 = land immediately (highest ROI) / P1 = second batch (high ROI) / P2 = follow-up (medium ROI) / P3 = not yet tested (low ROI). |
| **TC-U-x** | Unit-test-case ID, numbered in spec 06. |
| **FR-U-x** | Functional-requirement ID (functional requirement, unit-test), numbered in spec 01. |
| **NFR-U-x** | Non-functional-requirement ID, numbered in spec 01. |
| **R-U-x** | Risk ID, numbered in spec 01. |
| **DP-U-x** | Decision-point ID, numbered in spec 01 + plan §4. |
| **G1-G4** | Acceptance gates, defined in spec 01 §8. |
| **bounce** | Gate-keeper review-rejection mechanism, capped at 3 (DP-U-8); ≥4 writes ESCALATION-INFO.md. |

## 6. Key-Decision Summary (full detail in spec 01 §7)

| ID | Decision | Value |
|---|---|---|
| DP-U-1 | Directory naming | `docs/unit_test_spec/zh_cn/` |
| DP-U-2 | Document language | Chinese (English deferred) |
| DP-U-3 | Number of specs | 7 (lean, reused from dpdk_23_24 mode) |
| DP-U-4 | Test framework | CMocka 1.1.7 |
| DP-U-6 | Test directory | `f-stack/tests/unit/` |
| DP-U-7 | Build system | Standalone GNU Makefile + pkg-config |
| DP-U-11 | Scope | FF_HOST_SRCS 11 files; KERN_SRCS out-of-scope |
| DP-U-12 (revised) | P0 | **`ff_ini_parser.c` + `ff_log.c`** (after target-prioritizer Phase 2 adjustment; the original plan listed ff_config.c, but its handlers are all static, so it was moved to P1) |

## 7. Deliverables (spec phase)

| # | File | Line budget | Status |
|---|---|---|---|
| 1 | `plan.md` | 354 ✓ | local-only ✓ |
| 2 | `00-overview-and-glossary.md` (this file) | ≤200 | drafting |
| 3 | `01-requirements-spec.md` | ≤250 | pending |
| 4 | `02-current-architecture-and-targets.md` | ≤450 | pending |
| 5 | `04-cmocka-framework-and-impl.md` | ≤500 | pending |
| 6 | `06-test-cases-and-acceptance.md` | ≤450 | pending |
| 7 | `99-review-report.md` | ≤350 | pending |

## 8. Workspace Mandatory Conventions (re-stated)

- Direct `rm/kill/chmod` is forbidden; everything must go through
  `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`.
- No guessing; every line citation must be measured against actual code, with
  the reviewer cross-checking ≥10 places.
- Chinese spec; English version deferred until human audit completes.
- Local commit only; no push.

---

**End of document (v0.1)**
