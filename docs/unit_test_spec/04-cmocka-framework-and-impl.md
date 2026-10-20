# 04 — CMocka Framework and Implementation Strategy

> Document version: v0.1 (2026-06-09 18:00 UTC+8)
> Author: spec-author (based on Phase 2 research from mock-strategist + arch-explorer)
> Scope: Integration approach / directory layout / Makefile design / mock-strategy matrix for the CMocka unit-test framework over F-Stack lib/ FF_HOST_SRCS 11 files

---

## 1. CMocka Framework Overview and Selection

### 1.1 Selection rationale (vs Unity / Check / Criterion)

| Feature | Unity | **CMocka** | Check | Criterion |
|---|---|---|---|---|
| Built-in mock | ❌ (needs CMock companion) | ✅ `expect_*` / `will_return` / `mock()` | partial | ✅ |
| Subprocess crash isolation | ❌ | ✅ setjmp/longjmp | ✅ fork | ✅ fork |
| Group fixture | manual | ✅ `cmocka_run_group_tests` | ✅ | ✅ |
| Memory-leak detection | ❌ | ✅ `test_malloc/test_free` | ✅ | ❌ |
| Exception assertions | partial | ✅ `expect_assert_failure` | ❌ | ✅ |
| C99/C11/C17 | ✅ | ✅ | ✅ | ✅ |
| Embedded-friendliness | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| Chinese-community resources | many | medium (CMocka official + Samba/libssh practice) | few | few |

→ **Decision (DP-U-4 already set)**: CMocka 1.1.7. **Rationale**: (a) strong
  built-in mock (suits F-Stack's heavy use of DPDK API replacement); (b) the
  setjmp subprocess isolation is friendly to fatal paths like
  `rte_exit/rte_panic`; (c) already installed via `dnf install` — no source
  build required.

### 1.2 Version requirement (R-U-3 mitigation)

- **CMocka ≥ 1.1.7** (validated via `pkg-config --modversion cmocka`).
- For environments below 1.1.7, the spec 04 §6 Makefile provides a fallback:
  build from source at https://gitlab.com/cmocka/cmocka.

---

## 2. Installation and Readiness

### 2.1 Current CVM measurement

```bash
$ rpm -qa | grep cmocka
libcmocka-1.1.7-4.tl4.x86_64
libcmocka-devel-1.1.7-4.tl4.x86_64

$ pkg-config --modversion cmocka
1.1.7

$ pkg-config --cflags --libs cmocka
-lcmocka

$ ls /usr/include/cmocka.h /usr/lib64/libcmocka.so.0.8.0
/usr/include/cmocka.h
/usr/lib64/libcmocka.so.0.8.0
```

### 2.2 CMocka demo (validated in earlier dialog)

A simple `add` demo: 2/2 PASS (test_add_positive + test_add_negative). This
confirms `cmocka_unit_test` + `cmocka_run_group_tests` + `assert_int_equal`
are all working.

---

## 3. Unity → CMocka API Mapping Table (FR-U-3)

References the `c-unittest-expert.mdc` methodology while mapping each API to
its CMocka form:

| Methodology concept | Unity API | **CMocka API** | Note |
|---|---|---|---|
| Test function definition | `void test_xxx(void)` | `static void test_xxx(void **state)` | CMocka takes a `state` parameter (fixture context) |
| Group setup/teardown | `setUp()` / `tearDown()` | `static int test_setup(void **state)` / `static int test_teardown(void **state)` | CMocka returns int |
| Main test runner | `RUN_TEST(test_xxx)` | `cmocka_unit_test(test_xxx)` or `cmocka_unit_test_setup_teardown(test_xxx, setup, teardown)` | — |
| Group runner | `UNITY_BEGIN()` + multiple `RUN_TEST` + `UNITY_END()` | `cmocka_run_group_tests(tests, group_setup, group_teardown)` | — |
| **assert int equal** | `TEST_ASSERT_EQUAL_INT(a, b)` | `assert_int_equal(a, b)` | — |
| assert int not equal | `TEST_ASSERT_NOT_EQUAL_INT(a, b)` | `assert_int_not_equal(a, b)` | — |
| assert string equal | `TEST_ASSERT_EQUAL_STRING(a, b)` | `assert_string_equal(a, b)` | — |
| assert pointer non-null | `TEST_ASSERT_NOT_NULL(p)` | `assert_non_null(p)` | — |
| assert pointer null | `TEST_ASSERT_NULL(p)` | `assert_null(p)` | — |
| assert true | `TEST_ASSERT_TRUE(cond)` | `assert_true(cond)` | — |
| assert false | `TEST_ASSERT_FALSE(cond)` | `assert_false(cond)` | — |
| Memory equal | `TEST_ASSERT_EQUAL_MEMORY(a, b, n)` | `assert_memory_equal(a, b, n)` | — |
| Range assert | `TEST_ASSERT_INT_WITHIN(d, ex, ac)` | `assert_in_range(value, min, max)` | — |
| Force fail | `TEST_FAIL()` | `fail()` or `fail_msg("reason")` | — |
| Skip test | `TEST_IGNORE()` | `skip()` | — |
| **Mock function return value** | `Mock_xxx_ExpectAnyArgsAndReturn(v)` (CMock) | `will_return(__wrap_xxx, v)` | CMocka pairs with `--wrap` linker flag |
| **Mock argument validation** | `Mock_xxx_Expect(arg)` (CMock) | `expect_value(__wrap_xxx, param, val)` / `expect_string(__wrap_xxx, param, "str")` | — |
| Read parameter | — | `mock_type(int)` / `mock_ptr_type(void *)` | Inside the wrap body, fetches the value pushed by will_return |
| **Assert that an assert fires** | — | `expect_assert_failure(call(...))` | Verifies fatal paths |

→ **18 rows of API mapping** (FR-U-3 threshold ≥15 ✓).

---

## 4. tests/unit/ Directory Layout (DP-U-B5)

```
f-stack/
└── tests/
    ├── README.md                                # Test-system entry + usage docs
    └── unit/
        ├── Makefile                             # Standalone GNU Makefile (see §5)
        ├── common/
        │   ├── ff_log_stub.c                    # Common stub: mock ff_log/ff_global_cfg
        │   ├── ff_log_stub.h                    # ff_global_cfg static-instance declarator
        │   ├── rte_stub.c                       # Common mock: rte_exit/rte_panic fatal substitution
        │   └── rte_stub.h
        ├── fixtures/
        │   ├── valid_minimal.ini                # P1 ff_config.c end-to-end fixture
        │   ├── invalid_no_dpdk.ini              # missing [dpdk] section
        │   ├── invalid_bad_lcore.ini            # illegal lcore_mask
        │   └── (other .ini fixtures by need)
        ├── test_ff_ini_parser.c                 # P0 #1
        ├── test_ff_log.c                        # P0 #2
        ├── test_ff_host_interface.c             # P1 #3
        ├── test_ff_epoll.c                      # P1 #4
        ├── test_ff_config.c                     # P1 #5
        └── (P2 / P3 left as follow-up)
```

### 4.1 Naming conventions

- Test file: `test_<source-without-.c>.c` (e.g., `test_ff_log.c` tests `lib/ff_log.c`)
- Test function: `test_<func>_<scenario>(void **state)` (FR-U-7)
- Group fixture: `<test_file>_setup` / `<test_file>_teardown`
- Mock wrap: `__wrap_<api_name>` (paired with `--wrap=<api_name>` linker flag)

---

## 5. Makefile Design Draft (NFR-U-6 — must not pollute lib/Makefile)

### 5.1 Top-level `tests/unit/Makefile`

```makefile
# F-Stack lib/ unit test Makefile (CMocka 1.1.7+)
# Independent of lib/Makefile; compiles only target .c + stubs + tests.

TOPDIR        := $(abspath ../..)
LIB_DIR       := $(TOPDIR)/lib
COMMON_DIR    := common
FIXTURE_DIR   := fixtures

# Tooling
CC            ?= gcc
PKG_CFG       ?= pkg-config
CMOCKA_CFLAGS := $(shell $(PKG_CFG) --cflags cmocka)
CMOCKA_LIBS   := $(shell $(PKG_CFG) --libs cmocka)

# Versions guard (R-U-3)
CMOCKA_VER    := $(shell $(PKG_CFG) --modversion cmocka)
CMOCKA_OK     := $(shell echo "$(CMOCKA_VER)" | awk -F. '{ if ($$1 > 1 || ($$1 == 1 && $$2 > 1) || ($$1 == 1 && $$2 == 1 && $$3 >= 7)) print "ok" }')
ifneq ($(CMOCKA_OK),ok)
$(error CMocka >= 1.1.7 required, found $(CMOCKA_VER))
endif

# Host-only build flags (R-U-2 / NFR-U-4)
CFLAGS        := -O0 -g3 -Wall -Wextra -Wno-unused-parameter \
                 -I$(LIB_DIR) -I$(COMMON_DIR) \
                 $(CMOCKA_CFLAGS) \
                 -DFF_UNIT_TEST=1
LDFLAGS       := $(CMOCKA_LIBS)

# Tests list
P0_TESTS      := test_ff_ini_parser test_ff_log
P1_TESTS      := test_ff_host_interface test_ff_epoll test_ff_config
ALL_TESTS     := $(P0_TESTS) $(P1_TESTS)

# Per-test wrap flags (decide --wrap=<sym> per test file; see §7)
WRAP_FF_LOG   := -Wl,--wrap=rte_openlog_stream \
                 -Wl,--wrap=rte_log_set_global_level \
                 -Wl,--wrap=rte_log_set_level \
                 -Wl,--wrap=rte_vlog
WRAP_FF_HOST  := -Wl,--wrap=rte_malloc -Wl,--wrap=rte_free
WRAP_FF_INI   := # zero wrap

# Common stubs (link into every test by default)
COMMON_OBJS   := $(COMMON_DIR)/ff_log_stub.o $(COMMON_DIR)/rte_stub.o

# Default goal
.PHONY: all test check clean coverage
all: $(ALL_TESTS)

test: all
	@for t in $(ALL_TESTS); do \
	  echo "==> running $$t"; ./$$t || exit 1; \
	done
	@echo "ALL TESTS PASS"

check: test
	@echo "TODO: integrate valgrind --tool=memcheck per test"

# Pattern rule (each test links target .o + stubs)
test_ff_ini_parser: test_ff_ini_parser.o $(LIB_DIR)/ff_ini_parser.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(WRAP_FF_INI)

test_ff_log: test_ff_log.o $(LIB_DIR)/ff_log.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(WRAP_FF_LOG)

test_ff_host_interface: test_ff_host_interface.o $(LIB_DIR)/ff_host_interface.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(WRAP_FF_HOST)

test_ff_epoll: test_ff_epoll.o $(LIB_DIR)/ff_epoll.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

test_ff_config: test_ff_config.o $(LIB_DIR)/ff_config.o $(LIB_DIR)/ff_ini_parser.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@find . -name '*.o' -print | xargs -r /data/workspace/rm_tmp_file.sh
	@for t in $(ALL_TESTS); do \
	  [ -f $$t ] && /data/workspace/rm_tmp_file.sh $(CURDIR)/$$t; \
	done

coverage: CFLAGS += -fprofile-arcs -ftest-coverage
coverage: LDFLAGS += -lgcov --coverage
coverage: clean test
	gcov *.c > /dev/null
	@echo "TODO: lcov / genhtml integration (Phase 3)"
```

### 5.2 Key Makefile design points

| Design | Rationale |
|---|---|
| **Does not include `lib/Makefile`** | NFR-U-6: fully decoupled from the lib build |
| **Does not link `libfstack.a`** | R-U-8: avoids triggering FreeBSD-kernel-subset compilation explosion |
| **Links only the .o under test + stubs** | Minimal dependencies; quick compilation (< 5s/test) |
| **`pkg-config cmocka`** | NFR-U-4 portability |
| **CMocka version guard** | R-U-3 mitigation |
| **`-DFF_UNIT_TEST=1`** | The code-under-test can use `#ifdef FF_UNIT_TEST` to expose static handlers (used by spec 06 §3.4 Approach B) |
| **`make clean` uses the wrapper** | NFR-U-7 workspace compliance |

---

## 6. Compilation Matrix (host-only / coverage / valgrind)

### 6.1 Host-only compile matrix (R-U-2)

| Platform | gcc version | CMocka version | Expectation | Measurement timing |
|---|---|---|---|---|
| TencentOS 4.4 (current CVM) | ≥11 | 1.1.7 | ≥98% TC PASS | Phase 2 |
| Ubuntu 22.04 | ≥11 | ≥1.1.5 | ≥98% TC PASS | Phase 2 |
| RHEL 9 | ≥11 | ≥1.1.5 | ≥98% TC PASS | Phase 2 |
| FreeBSD 13/15 | clang ≥14 | ≥1.1.5 | Some TC skip (host-only TC fully PASS) | Phase 3 |

### 6.2 Coverage matrix (R-U-11)

| Flags combination | Compatibility | Note |
|---|---|---|
| `-fprofile-arcs -ftest-coverage` + CMocka | ✅ | Phase 3 introduction |
| `-fsanitize=address` + CMocka | ✅ | Phase 3, optional |
| `-fsanitize=memory` + CMocka | ❌ | clang only; not adopted |
| `-fsanitize=thread` + CMocka | ⚠ | May produce false positives on pthread tests; use cautiously |

---

## 7. Mock Strategy Matrix (11×4, FR-U-5)

### 7.1 Overview (dependency stats + mock recommendation)

| File | rte_* | pthread | sys | printf | Recommended strategy | Fixture complexity |
|---|---:|---:|---:|---:|---|---|
| **ff_ini_parser.c** | 0 | 0 | 0 | 0 | **Link real directly** (no external deps) | Trivial |
| **ff_log.c** | 5 | 0 | 0 | 0 | **wrap + will_return** (wrap all 4 rte) | Easy |
| **ff_host_interface.c** | 6 | 0 | 1 | 0 | wrap rte_malloc/free + sys/mman | Medium |
| **ff_epoll.c** | 0 | 0 | 0 | 0 | Link real + only stub ff_kqueue/ff_kevent | Easy |
| **ff_config.c** | 7 | 0 | 0 | 56 | Link real + prepare .ini fixtures + ff_log_stub | Medium |
| **ff_thread.c** | 0 | 2 | 0 | 0 | wrap pthread + ff_malloc/free | Medium |
| **ff_dpdk_pcap.c** | 3 | 0 | 0 | 0 | Mock rte_mbuf data structure | Hard |
| **ff_dpdk_kni.c** | 34 | 0 | 0 | 3 | Pure-function subset only; mostly stub | Hard |
| **ff_init.c** | 0 | 0 | 0 | 0 | Stub ff_load_config/ff_dpdk_*/ff_freebsd_init | Hard (many stubs) |
| **ff_dpdk_if.c** | 173 | 0 | 0 | 5 | **Pure-function subset only** (4 candidates) | Very Hard |
| **ff_memory.c** | 24 | 0 | 1 | 1 | Off by default; P3 not invested | N/A |

**Total cells = 11 × 4 = 44 cells** ✓ (FR-U-5 threshold)

### 7.2 P0 file mock detailed plan

#### P0 #1 ff_ini_parser.c

- **# mocks = 0**: depends only on stdio (FILE\* / fopen / fgets / ungetc), ctype, string.
- **Fixture design**: build an in-memory stream with `tmpfile()` or
  `fmemopen()`; a custom `ini_handler` callback verifies parameters via the
  cmocka `mock()` family.
- **Coverage target**: every branch of the ini_parse_stream state machine
  (comment / section / multiline / BOM / inline-comment / error recovery).

#### P0 #2 ff_log.c

- **# mocks = 4**: `__wrap_rte_openlog_stream`,
  `__wrap_rte_log_set_global_level`, `__wrap_rte_log_set_level`,
  `__wrap_rte_vlog`.
- **Fixture design**: a static `ff_global_cfg` instance (from
  `common/ff_log_stub.h`) + a temporary log path.
- **Coverage target**: all 7 public APIs + va_start/va_end pairing.

---

## 8. Fatal-Function Handling (R-U-13, **mandatory rule**)

### 8.1 Functions that must be wrapped

| Function | Caller | Behavior after wrap |
|---|---|---|
| `rte_exit(code, fmt, ...)` | ff_dpdk_if.c × 25+, ff_dpdk_kni.c × 5 | `mock_assert(false, "rte_exit", __FILE__, __LINE__)` |
| `rte_panic(fmt, ...)` | ff_dpdk_kni.c × 4 | `mock_assert(false, "rte_panic", __FILE__, __LINE__)` |
| `exit(int)` | scattered | `mock_assert(false, "exit", __FILE__, __LINE__)` |
| `abort()` | scattered | `mock_assert(false, "abort", __FILE__, __LINE__)` |

### 8.2 Common stub template (`common/rte_stub.c`)

```c
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_rte_exit(int code, const char *fmt, ...) {
    (void)code; (void)fmt;
    mock_assert(0, "rte_exit", __FILE__, __LINE__);
    /* unreachable */
}

void __wrap_rte_panic(const char *fmt, ...) {
    (void)fmt;
    mock_assert(0, "rte_panic", __FILE__, __LINE__);
    /* unreachable */
}
```

Linker flag: `-Wl,--wrap=rte_exit -Wl,--wrap=rte_panic`

### 8.3 Tests that verify fatal paths (used in spec 06 §3)

```c
static void test_xxx_invalid_input_calls_rte_exit(void **state) {
    expect_assert_failure(some_func(NULL));   /* expect internal rte_exit */
}
```

---

## 9. Fixture Templates (Common Stubs)

### 9.1 ff_global_cfg stub (`common/ff_log_stub.h`)

```c
#ifndef FF_LOG_STUB_H
#define FF_LOG_STUB_H

#include <stdio.h>
#include <stdint.h>

/* Minimal shim of ff_global_cfg required by ff_log.c / ff_config.c.
 * Only the .log sub-struct is populated; other fields are zero-init.
 * Declared `extern` here, defined as a static instance in ff_log_stub.c. */
struct ff_log_cfg_stub {
    char        dir[256];
    int         proc_id;
    FILE       *f;
    uint32_t    level;
};
struct ff_config_stub {
    struct ff_log_cfg_stub log;
};
extern struct ff_config_stub ff_global_cfg;

#endif
```

### 9.2 Generic group setup/teardown template

```c
static int test_xxx_setup(void **state) {
    /* prepare ff_global_cfg.log fields, tmp dir, etc. */
    ff_global_cfg.log.proc_id = 0;
    snprintf(ff_global_cfg.log.dir, sizeof(ff_global_cfg.log.dir), "/tmp/");
    ff_global_cfg.log.level = 7;
    ff_global_cfg.log.f = NULL;
    *state = NULL;
    return 0;
}

static int test_xxx_teardown(void **state) {
    if (ff_global_cfg.log.f) fclose(ff_global_cfg.log.f);
    return 0;
}
```

---

## 10. Performance Budget (NFR-U-5)

| Phase | TC count | Expected runtime | Note |
|---|---|---|---|
| Full P0 (ff_ini_parser + ff_log) | ~30 | < 3s | Mostly string/format logic |
| Full P1 (host_interface + epoll + config) | ~50 | < 15s | config end-to-end .ini fixture is slightly slower |
| **P0 + P1** | **~80** | **< 30s (NFR-U-5 threshold)** | — |
| P2 follow-up | TBD | not estimated | Phase 5 |

---

## 11. Mapping to the c-unittest-expert.mdc Methodology

| Methodology principle | Where it is realized in this spec |
|---|---|
| Test naming `test_<func>_<scenario>` | 04 §4.1 + 06 §1 |
| Boundary coverage (empty / extreme / illegal) | 04 §3 + 06 §5 |
| Setup/teardown isolation | 04 §9 |
| Assertion-granularity refinement | 04 §3 mapping table |
| Clear mock boundaries | 04 §7 matrix + §8 fatal-function handling |
| Each test verifies only one behavior | 06 §3 case organization |

---

## 12. Phase 2 Landing Checklist (not executed in the spec phase, listed for reference)

- [ ] Create `tests/unit/` directory (with `common/` + `fixtures/`)
- [ ] Land `tests/unit/Makefile` (based on §5.1 draft)
- [ ] Land `common/ff_log_stub.{c,h}` + `common/rte_stub.{c,h}`
- [ ] Write the first hello-world test to validate the project plumbing
      (just `cmocka_unit_test` + `assert_int_equal(2+3, 5)`)
- [ ] CMocka version guard takes effect in the Makefile (verified empirically)

---

**End of document (v0.1, within the 500-line budget)**
