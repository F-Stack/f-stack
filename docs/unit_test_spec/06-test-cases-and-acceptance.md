# 06 — Test Cases and Acceptance Criteria

> Document version: v0.1 (2026-06-09 18:05 UTC+8)
> Author: spec-author
> Scope: P0 / P1 test-case drafts + acceptance criteria + coverage targets for F-Stack lib/ FF_HOST_SRCS

---

## 1. Document Purpose and Naming Convention

This spec lists, for the current task (spec phase): (1) the **TC-U-\*** test
cases for the P0 files (ff_ini_parser.c + ff_log.c), ≥20 total; (2) an
overview of the P1 files (ff_host_interface.c + ff_epoll.c + ff_config.c),
≥18 total; (3) the boundary-coverage matrix; (4) coverage targets;
(5) acceptance criteria.

### 1.1 TC-U-* case-ID numbering rule

```
TC-U-<P0|P1|P2>-<file_short>-<seq>
            Examples:
            TC-U-P0-INI-01    ← ff_ini_parser.c case #1
            TC-U-P0-LOG-03    ← ff_log.c case #3
            TC-U-P1-HIF-02    ← ff_host_interface.c case #2
```

| Abbrev | File |
|---|---|
| INI | ff_ini_parser.c |
| LOG | ff_log.c |
| HIF | ff_host_interface.c |
| EPL | ff_epoll.c |
| CFG | ff_config.c |

### 1.2 Test-function naming (FR-U-7)

`test_<function-under-test>_<scenario>(void **state)` — must start with `test_`;
the function-name segment drops the `ff_` prefix for brevity.

Examples:
- `test_ini_parse_stream_valid_basic` — the "basic valid input" scenario for
  `ini_parse_stream` in ff_ini_parser.c
- `test_ff_log_open_set_dir_not_exist` — the scenario for `ff_log_open_set` in
  ff_log.c when the dir does not exist
- `test_ff_load_config_minimal_valid_ini` — the end-to-end "minimum valid ini"
  scenario for `ff_load_config` in ff_config.c

---

## 2. P0 ff_ini_parser.c Test Cases (≥10)

### 2.1 APIs under test (see spec 02 §3.3)

| API | Main logic |
|---|---|
| `ini_parse_stream(ini_reader reader, void* stream, ini_handler handler, void* user)` | Core state machine |
| `ini_parse_file(FILE* file, ini_handler handler, void* user)` | Wraps standard fgets |
| `ini_parse(const char* filename, ini_handler handler, void* user)` | Wraps fopen + ini_parse_file |

### 2.2 Case list

| TC-ID | Case name | API tested | Input | Expected output | Coverage |
|---|---|---|---|---|---|
| **TC-U-P0-INI-01** | `test_ini_parse_stream_valid_basic` | ini_parse_stream | `[s1]\\nkey=value\\n` | Returns 0; handler called once with section="s1", name="key", value="value" | Basic valid path |
| **TC-U-P0-INI-02** | `test_ini_parse_stream_multiple_sections` | ini_parse_stream | 2 sections × 2 keys | Returns 0; handler called 4 times with accurate section/name/value each time | Multi-section switching |
| **TC-U-P0-INI-03** | `test_ini_parse_stream_comment_lines` | ini_parse_stream | `; comment\\n# comment\\n[s1]\\nk=v` | Returns 0; handler called only once (comments skipped) | Comment skipping |
| **TC-U-P0-INI-04** | `test_ini_parse_stream_inline_comment` | ini_parse_stream | `[s1]\\nk=v ; inline` | Returns 0; handler value="v" (inline comment stripped) | Inline-comment handling |
| **TC-U-P0-INI-05** | `test_ini_parse_stream_whitespace_strip` | ini_parse_stream | `[s1]\\n  k  =  v  \\n` | name="k", value="v" (leading/trailing whitespace stripped) | rstrip / lskip |
| **TC-U-P0-INI-06** | `test_ini_parse_stream_empty_value` | ini_parse_stream | `[s1]\\nk=\\n` | name="k", value="" (empty value is legal) | Empty-value boundary |
| **TC-U-P0-INI-07** | `test_ini_parse_stream_no_section` | ini_parse_stream | `k=v` | Returns 1 (first-line error: not in a section) | Error recovery (missing section) |
| **TC-U-P0-INI-08** | `test_ini_parse_stream_invalid_syntax` | ini_parse_stream | `[s1]\\ninvalid_no_eq` | Returns 2 (line-2 error) | Error recovery (no `=`) |
| **TC-U-P0-INI-09** | `test_ini_parse_stream_handler_returns_zero` | ini_parse_stream | Any valid input + handler returns 0 | ini_parse_stream returns non-zero (handler reports error) | Handler abort |
| **TC-U-P0-INI-10** | `test_ini_parse_stream_bom_utf8` | ini_parse_stream | `\\xEF\\xBB\\xBF[s1]\\nk=v` | Returns 0 (BOM skipped) | BOM handling |
| **TC-U-P0-INI-11** | `test_ini_parse_file_normal` | ini_parse_file | Temp FILE\* with 2 lines | Returns 0; handler invoked the expected number of times | FILE\* entry |
| **TC-U-P0-INI-12** | `test_ini_parse_file_null` | ini_parse_file | NULL FILE\* | Returns -1 or SIGSEGV (behavior decided in the spec; recommendation: wrap fgets to capture) | NULL defense |
| **TC-U-P0-INI-13** | `test_ini_parse_filename_not_exist` | ini_parse | `/nonexistent.ini` | Returns -1 | fopen-failure path |
| **TC-U-P0-INI-14** | `test_ini_parse_filename_normal` | ini_parse | Temporary file path | Returns 0; handler invoked the expected number of times | filename entry |
| **TC-U-P0-INI-15** | `test_ini_parse_stream_long_section_name` | ini_parse_stream | section name 60 chars (> MAX_SECTION 50) | section name truncated to 50 | MAX_SECTION boundary |
| **TC-U-P0-INI-16** | `test_ini_parse_stream_long_key_name` | ini_parse_stream | key name 60 chars (> MAX_NAME 50) | key name truncated to 50 | MAX_NAME boundary |
| **TC-U-P0-INI-17** | `test_ini_parse_stream_user_data_passed` | ini_parse_stream | user = pointer to a custom struct | handler receives the same user pointer | user passthrough |
| **TC-U-P0-INI-18** | `test_ini_parse_stream_zero_byte_input` | ini_parse_stream | empty stream | Returns 0; handler not invoked | Empty input |

**Total P0-INI cases: 18** (FR-U-6 threshold ≥10 ✓)

### 2.3 Key fixture design

```c
/* test_ff_ini_parser.c */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include "ff_ini_parser.h"

/* Capture handler invocations via cmocka mock() */
static int capture_handler(void *user, const char *section,
                           const char *name, const char *value) {
    check_expected_ptr(section);   /* expect_string verification */
    check_expected_ptr(name);
    check_expected_ptr(value);
    return mock_type(int);          /* will_return pushes 1 to indicate success */
}

/* Helper: parse a string buffer */
static int parse_buf(const char *buf, ini_handler h, void *user) {
    FILE *f = fmemopen((void *)buf, strlen(buf), "r");
    int rv = ini_parse_file(f, h, user);
    fclose(f);
    return rv;
}
```

---

## 3. P0 ff_log.c Test Cases (≥10)

### 3.1 APIs under test (see spec 02 §3.4)

7 public APIs + the global ff_global_cfg.log.* dependency.

### 3.2 Required common stubs (see spec 04 §9)

`common/ff_log_stub.{c,h}` provides `struct ff_config_stub ff_global_cfg`.

### 3.3 Case list

| TC-ID | Case name | API tested | Input | Expected | Coverage |
|---|---|---|---|---|---|
| **TC-U-P0-LOG-01** | `test_ff_log_open_set_normal` | ff_log_open_set | dir="/tmp/", proc_id=0 | Returns 0; ff_global_cfg.log.f non-NULL; rte_openlog_stream invoked once | Normal path |
| **TC-U-P0-LOG-02** | `test_ff_log_open_set_dir_invalid` | ff_log_open_set | dir="/nonexistent/xyz/" | Returns ≠ 0; ff_global_cfg.log.f == NULL | fopen failure |
| **TC-U-P0-LOG-03** | `test_ff_log_open_set_long_filename` | ff_log_open_set | dir 200 chars long | Filename built correctly (no truncation in the filename field) | String concatenation |
| **TC-U-P0-LOG-04** | `test_ff_log_close_when_open` | ff_log_close | log.f non-NULL (precondition: fopen tmpfile) | log.f set to NULL; fclose invoked | Resource reclamation |
| **TC-U-P0-LOG-05** | `test_ff_log_close_when_null` | ff_log_close | log.f == NULL | No crash; log.f still NULL | NULL defense |
| **TC-U-P0-LOG-06** | `test_ff_log_reset_stream_normal` | ff_log_reset_stream | f=tmpfile() | Returns 0; __wrap_rte_openlog_stream invoked once with arg == f | rte_ wrap |
| **TC-U-P0-LOG-07** | `test_ff_log_set_global_level` | ff_log_set_global_level | level=7 | __wrap_rte_log_set_global_level invoked with arg == 7 | rte_ wrap |
| **TC-U-P0-LOG-08** | `test_ff_log_set_level_normal` | ff_log_set_level | logtype=1, level=7 | __wrap_rte_log_set_level invoked with (logtype, level) | rte_ wrap |
| **TC-U-P0-LOG-09** | `test_ff_log_set_level_returns_value` | ff_log_set_level | rte_log_set_level wrap returns -1 | ff_log_set_level returns -1 (passthrough) | Return-value passthrough |
| **TC-U-P0-LOG-10** | `test_ff_log_variadic_basic` | ff_log | level=7, logtype=1, fmt="x=%d", args=42 | __wrap_rte_vlog invoked once; args correctly assembled by va_start | Variadic + va_start/end |
| **TC-U-P0-LOG-11** | `test_ff_log_variadic_zero_args` | ff_log | fmt="static msg" | __wrap_rte_vlog invoked once; fmt passed through accurately | 0-arg boundary |
| **TC-U-P0-LOG-12** | `test_ff_vlog_normal` | ff_vlog | level, logtype, fmt, va_list ap | __wrap_rte_vlog invoked once with all args passed through | va_list direct passthrough |
| **TC-U-P0-LOG-13** | `test_ff_log_returns_rte_vlog_value` | ff_log | __wrap_rte_vlog returns 5 | ff_log returns 5 | Return-value passthrough |

**Total P0-LOG cases: 13** (FR-U-6 threshold ≥10 ✓)

### 3.4 Key wrap implementations

```c
/* In test_ff_log.c */
int __wrap_rte_openlog_stream(FILE *f) {
    check_expected_ptr(f);
    return mock_type(int);
}

void __wrap_rte_log_set_global_level(uint32_t level) {
    check_expected(level);
}

int __wrap_rte_log_set_level(uint32_t logtype, uint32_t level) {
    check_expected(logtype);
    check_expected(level);
    return mock_type(int);
}

int __wrap_rte_vlog(uint32_t level, uint32_t logtype, const char *fmt, va_list ap) {
    (void)ap;   /* don't dereference, only verify level/logtype/fmt fingerprint */
    check_expected(level);
    check_expected(logtype);
    check_expected_ptr(fmt);
    return mock_type(int);
}
```

---

## 4. P1 Case Draft Overview (≥18)

### 4.1 ff_host_interface.c TC draft (≥6)

| TC-ID | Case name | API covered | Key point |
|---|---|---|---|
| **TC-U-P1-HIF-01** | `test_ff_malloc_normal` | ff_malloc | __wrap_rte_malloc invoked |
| **TC-U-P1-HIF-02** | `test_ff_calloc_zeros_memory` | ff_calloc | Return value zero-filled |
| **TC-U-P1-HIF-03** | `test_ff_realloc_grow` | ff_realloc | __wrap_rte_realloc invoked |
| **TC-U-P1-HIF-04** | `test_ff_free_null` | ff_free | NULL does not crash |
| **TC-U-P1-HIF-05** | `test_ff_clock_gettime_monotonic` | ff_clock_gettime | Return value ≥ previous |
| **TC-U-P1-HIF-06** | `test_ff_arc4rand_buf_filled` | ff_arc4rand | Buf filled with non-all-zero |
| **TC-U-P1-HIF-07** | `test_ff_get_current_time_advances` | ff_get_current_time | Multiple calls return increasing values |
| **TC-U-P1-HIF-08** | `test_ff_os_errno_mapping` | ff_os_errno | errno mapping is accurate |

**TC-U-P1-HIF total: 8** ✓

### 4.2 ff_epoll.c TC draft (≥6)

| TC-ID | Case name | API covered | Key point |
|---|---|---|---|
| **TC-U-P1-EPL-01** | `test_ff_epoll_create_returns_fd` | ff_epoll_create | size argument ignored; returns fd |
| **TC-U-P1-EPL-02** | `test_ff_epoll_ctl_add_event` | ff_epoll_ctl | EPOLL_CTL_ADD → ff_kevent EV_ADD |
| **TC-U-P1-EPL-03** | `test_ff_epoll_ctl_del_event` | ff_epoll_ctl | EPOLL_CTL_DEL → ff_kevent EV_DELETE |
| **TC-U-P1-EPL-04** | `test_ff_epoll_ctl_mod_event` | ff_epoll_ctl | EPOLL_CTL_MOD → accurate logic mapping |
| **TC-U-P1-EPL-05** | `test_ff_epoll_wait_event_translation` | ff_epoll_wait | EVFILT_READ → EPOLLIN |
| **TC-U-P1-EPL-06** | `test_ff_epoll_wait_zero_timeout` | ff_epoll_wait | timeout=0 path |
| **TC-U-P1-EPL-07** | `test_ff_epoll_wait_invalid_args` | ff_epoll_wait | maxevents ≤ 0 → -1 / EINVAL |

**TC-U-P1-EPL total: 7** ✓

### 4.3 ff_config.c TC draft (≥10, mainly end-to-end)

| TC-ID | Case name | API covered | Key point |
|---|---|---|---|
| **TC-U-P1-CFG-01** | `test_ff_load_config_valid_minimal_ini` | ff_load_config | fixtures/valid_minimal.ini → ff_global_cfg.dpdk.lcore_mask et al. accurate |
| **TC-U-P1-CFG-02** | `test_ff_load_config_no_dpdk_section` | ff_load_config | fixtures/invalid_no_dpdk.ini → returns error |
| **TC-U-P1-CFG-03** | `test_ff_load_config_invalid_lcore_mask` | ff_load_config | fixtures/invalid_bad_lcore.ini → returns error / message |
| **TC-U-P1-CFG-04** | `test_ff_load_config_dual_vlan` | ff_load_config | fixtures/valid_dual_vlan.ini → ff_global_cfg.vlan[0/1] fields accurate |
| **TC-U-P1-CFG-05** | `test_ff_load_config_with_vip_addr` | ff_load_config | vip_addr=192.169.0.10,11 → parsed correctly |
| **TC-U-P1-CFG-06** | `test_ff_load_config_argv_override` | ff_load_config | argv "-c /tmp/x.ini --proc-type=primary" → parsed accurately |
| **TC-U-P1-CFG-07** | `test_ff_load_config_unknown_section` | ff_load_config | ini contains [unknown] → warns but does not crash |
| **TC-U-P1-CFG-08** | `test_ff_load_config_empty_ini` | ff_load_config | empty ini → returns error |
| **TC-U-P1-CFG-09** | `test_vlan_cfg_handler_isolated` (white-box) | `#include "ff_config.c"` | Directly calls vlan_cfg_handler, verifies ff_vlan_cfg fields |
| **TC-U-P1-CFG-10** | `test_ipfw_pr_cfg_handler_isolated` (white-box) | same as above | ipfw_pr_cfg_handler parses fib + cidr |
| **TC-U-P1-CFG-11** | `test_port_cfg_handler_addr_parse` | same as above | port_cfg_handler parses addr=9.134.214.176/21 |

**TC-U-P1-CFG total: 11** ✓

---

## 5. Boundary Coverage Matrix (FR-U-8)

| Boundary type | P0 file coverage | P1 file coverage |
|---|---|---|
| **Empty input** | TC-U-P0-INI-18 (empty stream) / TC-U-P0-LOG-11 (0 args) | TC-U-P1-CFG-08 (empty ini) |
| **Extreme length** | TC-U-P0-INI-15/16 (long section/key) / TC-U-P0-LOG-03 (long dir) | TC-U-P1-HIF-03 (large alloc) |
| **Illegal characters** | TC-U-P0-INI-08 (no `=`) / TC-U-P0-INI-07 (no section) | TC-U-P1-CFG-03 (illegal lcore_mask) |
| **NULL pointer** | TC-U-P0-INI-12 (NULL FILE\*) / TC-U-P0-LOG-05 (NULL log.f close) | TC-U-P1-HIF-04 (NULL free) |
| **Duplicate key** | (deferred; filled in Phase 3) | TC-U-P1-CFG-07 (unknown section) |
| **Resource-failure path** | TC-U-P0-INI-13 (fopen fail) / TC-U-P0-LOG-02 (dir does not exist) | — |

**5 boundary classes ≥ 5 rows ✓** (FR-U-8 threshold)

---

## 6. Coverage Targets (NFR-U-2 + DP-U-B4)

### 6.1 Thresholds (listed in the spec phase; tooling integrated in Phase 3)

| Priority | File | Line cov | Branch cov | Phase |
|---|---|---|---|---|
| **P0** | ff_ini_parser.c | ≥80% | ≥70% | Required by Phase 3 |
| **P0** | ff_log.c | ≥80% | ≥70% | Required by Phase 3 |
| **P1** | ff_host_interface.c | ≥60% | ≥50% | Required by Phase 4 |
| **P1** | ff_epoll.c | ≥60% | ≥50% | Required by Phase 4 |
| **P1** | ff_config.c | ≥50% (end-to-end coverage is naturally limited) | ≥40% | Required by Phase 4 |
| **P2/P3** | Other 6 files | not enforced | not enforced | Follow-up |

### 6.2 Toolchain (introduced in Phase 3; not integrated in this spec phase)

- `gcov` — compile-time instrumentation (spec 04 §6.2 lists the flags)
- `lcov` — collects .gcda and produces an HTML report
- `gcovr` — XML report (CI-friendly)

---

## 7. Acceptance Criteria (synced with spec 01 §6)

### 7.1 Spec-phase acceptance (current task scope)

| Gate | Check | PASS condition |
|---|---|---|
| **G1 spec landing** | `ls docs/unit_test_spec/zh_cn/` ≥ 7 markdown | All 7 docs exist |
| **G2 cross-check** | gate-keeper samples ≥10 line citations | 100% hit |
| **G3 4-dim score** | Consistency / Completeness / Risk-coverage / Executability | All ≥A |
| **G4 compliance** | grep direct rm/kill/chmod | 0 hits |
| **G5 case-count lower bound** | P0 ≥ 20 + P1 ≥ 18 | Actual P0=31 / P1=26 (G5 PASS) |

### 7.2 Phase 2/3 acceptance (listed in the spec only, not executed here)

| Gate | Check | PASS condition |
|---|---|---|
| **G6 Phase-2 build** | `cd tests/unit && make` | exit=0 / 0 errors |
| **G7 Phase-3 P0 all PASS** | `make test` runs ≥31 P0 TC | 100% PASS / total runtime < 3s |
| **G8 Phase-3 coverage** | `make coverage` produces .gcov | P0 line coverage ≥80% / branch ≥70% |
| **G9 Phase-4 P1 all PASS** | `make test` runs ≥26 P1 TC | 100% PASS / total runtime < 30s |
| **G10 Phase-5 CI** | GitHub Actions / internal CI integration | Each PR auto-runs full P0+P1 |

---

## 8. Test-Run Commands (described in the spec; landed in Phase 2)

```bash
# Switch to the test directory
cd /data/workspace/f-stack/tests/unit

# Default (build + run only; no valgrind / coverage)
make test

# With valgrind
make check

# With coverage
make coverage

# Build only, no run
make all

# Cleanup (uses the wrapper, per NFR-U-7)
make clean
```

---

## 9. Case Count Summary

| Priority | File | # cases | Phase |
|---|---|---|---|
| **P0** | ff_ini_parser.c | 18 | Phase 3 |
| **P0** | ff_log.c | 13 | Phase 3 |
| **P1** | ff_host_interface.c | 8 | Phase 4 |
| **P1** | ff_epoll.c | 7 | Phase 4 |
| **P1** | ff_config.c | 11 | Phase 4 |
| **P0+P1 subtotal** | 5 files | **57** | — |
| **P2 follow-up** | 5 files | TBD | Phase 5 |
| **P3 not tested** | 1 file (ff_memory.c) | 0 | — |

→ **FR-U-6 threshold ≥25**: P0+P1 totals **57** ✓

---

## 10. Cross-reference to the c-unittest-expert.mdc Methodology

| Methodology principle | Realization |
|---|---|
| Test naming `test_<func>_<scenario>` | §1.2 + §2.2 / §3.3 / §4.x — every case |
| 5 boundary classes (empty / extreme / illegal / NULL / failure path) | §5 matrix |
| Setup/teardown isolation | §2.3 + §3.4 fixture templates |
| Each test verifies one behavior | Each TC has only one expected outcome |
| Assertion-granularity refinement | Distinguish via `assert_int_equal` / `assert_string_equal` / `assert_non_null` |
| Clear mock boundaries | spec 04 §7 matrix + this file §3.4 wrap implementations |

---

## 11. Phase 3 Landing Checklist (not executed in the spec phase, listed only)

- [ ] Land `tests/unit/test_ff_ini_parser.c` (18 TCs)
- [ ] Land `tests/unit/test_ff_log.c` (13 TCs)
- [ ] Land `tests/unit/fixtures/valid_minimal.ini` and 4-6 other ini fixtures (for P1)
- [ ] `make test` passes 31/31 P0
- [ ] `make coverage` reaches P0 line coverage ≥80%

---

**End of document (v0.1, within the 450-line budget)**
