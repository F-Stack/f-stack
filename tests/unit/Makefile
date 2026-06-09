# F-Stack lib/ unit test Makefile (CMocka 1.1.7+)
# Independent of lib/Makefile; compiles lib/*.c into lib_objs/ with our own CFLAGS.
# Per docs/unit_test_spec/zh_cn/04-cmocka-framework-and-impl.md §5.1.

TOPDIR        := $(abspath ../..)
LIB_DIR       := $(TOPDIR)/lib
COMMON_DIR    := common
FIXTURE_DIR   := fixtures
LIB_OBJS_DIR  := lib_objs

# Tooling
CC            ?= gcc
PKG_CFG       ?= pkg-config
CMOCKA_CFLAGS := $(shell $(PKG_CFG) --cflags cmocka)
CMOCKA_LIBS   := $(shell $(PKG_CFG) --libs cmocka)

# Versions guard (R-U-3 mitigation)
CMOCKA_VER    := $(shell $(PKG_CFG) --modversion cmocka 2>/dev/null)
CMOCKA_OK     := $(shell echo "$(CMOCKA_VER)" | awk -F. '{ if ($$1 > 1 || ($$1 == 1 && $$2 > 1) || ($$1 == 1 && $$2 == 1 && $$3 >= 7)) print "ok" }')
ifneq ($(CMOCKA_OK),ok)
$(error CMocka >= 1.1.7 required, found '$(CMOCKA_VER)')
endif

# Host-only build flags (R-U-2 / NFR-U-4)
CFLAGS        := -O0 -g3 -Wall -Wextra -Wno-unused-parameter \
                 -I$(LIB_DIR) -I$(COMMON_DIR) \
                 $(CMOCKA_CFLAGS) \
                 -DFF_UNIT_TEST=1

# Fatal-function wraps applied globally (spec 04 §8.1):
# rte_exit / rte_panic redirect to mock_assert via common/rte_stub.c.
BASE_WRAPS    := -Wl,--wrap=rte_exit -Wl,--wrap=rte_panic

LDFLAGS_BASE  := $(CMOCKA_LIBS)

# Per-test wrap flags (test_ff_log needs 4 rte_log API wraps)
WRAP_FF_LOG   := -Wl,--wrap=rte_openlog_stream \
                 -Wl,--wrap=rte_log_set_global_level \
                 -Wl,--wrap=rte_log_set_level \
                 -Wl,--wrap=rte_vlog

# Tests list
SANITY_TESTS  := test_hello
P0_TESTS      := test_ff_ini_parser test_ff_log
P1_TESTS      := test_ff_host_interface test_ff_epoll test_ff_config
ALL_TESTS     := $(SANITY_TESTS) $(P0_TESTS) $(P1_TESTS)

# Common stub objects
COMMON_OBJS   := $(COMMON_DIR)/ff_log_stub.o $(COMMON_DIR)/rte_stub.o

# Default goal
.PHONY: all test test_p0 test_p1 test_sanity check clean coverage coverage_clean help
all: $(ALL_TESTS)

help:
	@echo "F-Stack lib/ unit-test build targets:"
	@echo "  make all          - build all test binaries"
	@echo "  make test         - run all tests"
	@echo "  make test_sanity  - run hello-world sanity test"
	@echo "  make test_p0      - run P0 tests only"
	@echo "  make test_p1      - run P1 tests only"
	@echo "  make clean        - clean build artifacts (uses rm_tmp_file.sh wrapper)"
	@echo "  make coverage     - build with gcov + run tests + emit lcov HTML report"
	@echo "  make coverage_clean - remove gcov/.gcda/.gcno + coverage_report/"

test_sanity: $(SANITY_TESTS)
	@for t in $(SANITY_TESTS); do \
	  echo "==> running $$t"; ./$$t || exit 1; \
	done

test_p0: $(P0_TESTS)
	@for t in $(P0_TESTS); do \
	  echo "==> running $$t"; ./$$t || exit 1; \
	done

test_p1: $(P1_TESTS)
	@for t in $(P1_TESTS); do \
	  echo "==> running $$t"; ./$$t || exit 1; \
	done

test: all
	@for t in $(ALL_TESTS); do \
	  echo "==> running $$t"; ./$$t || exit 1; \
	done
	@echo "ALL TESTS PASS ($(words $(ALL_TESTS)) binaries)"

check: test
	@echo "TODO: integrate valgrind --tool=memcheck per test (FU-S2-1)"

# ----- lib/*.c → lib_objs/*.o (independent of lib/Makefile, NFR-U-6) -----
$(LIB_OBJS_DIR):
	@mkdir -p $@

$(LIB_OBJS_DIR)/%.o: $(LIB_DIR)/%.c | $(LIB_OBJS_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# ----- common stubs -----
$(COMMON_DIR)/%.o: $(COMMON_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# ----- top-level test source -----
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ----- test binaries (per-test linking rules) -----
# Sanity: no lib deps, no stubs
test_hello: test_hello.o
	$(CC) -o $@ $^ $(LDFLAGS_BASE)

# P0 #1 ff_ini_parser: zero rte deps, no wraps needed
test_ff_ini_parser: test_ff_ini_parser.o $(LIB_OBJS_DIR)/ff_ini_parser.o
	$(CC) -o $@ $^ $(LDFLAGS_BASE)

# P0 #2 ff_log: 4 rte_log API wraps
test_ff_log: test_ff_log.o $(LIB_OBJS_DIR)/ff_log.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) $(WRAP_FF_LOG)

# P1 #1 ff_host_interface (uses RAND_bytes from libcrypto; ff_log linked locally
# via stub in the test file since we don't pull in lib/ff_log.c here)
test_ff_host_interface: test_ff_host_interface.o $(LIB_OBJS_DIR)/ff_host_interface.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) -lcrypto

# P1 #2 ff_epoll
test_ff_epoll: test_ff_epoll.o $(LIB_OBJS_DIR)/ff_epoll.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS)

# P1 #3 ff_config (links ff_ini_parser too; ff_config.o defines its own
# ff_global_cfg so we DO NOT link common/ff_log_stub.o here, only rte_stub.o)
test_ff_config: test_ff_config.o $(LIB_OBJS_DIR)/ff_config.o $(LIB_OBJS_DIR)/ff_ini_parser.o $(COMMON_DIR)/rte_stub.o
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS)

# ----- clean (NFR-U-7: must use workspace wrapper, no direct rm) -----
clean:
	@find . -name '*.o' -type f -print 2>/dev/null | while read f; do \
	  /data/workspace/rm_tmp_file.sh "$$(realpath "$$f")" >/dev/null; \
	done
	@for t in $(ALL_TESTS); do \
	  if [ -x "./$$t" ]; then \
	    /data/workspace/rm_tmp_file.sh "$$(realpath ./$$t)" >/dev/null; \
	  fi; \
	done
	@if [ -d $(LIB_OBJS_DIR) ]; then \
	  /data/workspace/rm_tmp_file.sh "$$(realpath $(LIB_OBJS_DIR))" >/dev/null; \
	fi
	@$(MAKE) -s coverage_clean
	@echo "clean done"

# ----- coverage (Stage-3, FU-U-6 / G8 line>=80% branch>=70% for P0) -----
COVERAGE_INFO := coverage.info
COVERAGE_DIR  := coverage_report

coverage: CFLAGS    += -fprofile-arcs -ftest-coverage
coverage: LDFLAGS_BASE += -lgcov --coverage
coverage: clean test
	@echo "==> Collecting coverage data via lcov..."
	@lcov --capture --directory $(LIB_OBJS_DIR) --directory . \
		--output-file $(COVERAGE_INFO) \
		--rc branch_coverage=1 \
		--ignore-errors mismatch,negative,inconsistent,empty,unused,source 2>&1 \
		| tail -8
	@echo "==> Stripping system / cmocka / test-harness paths from report..."
	@lcov --remove $(COVERAGE_INFO) \
		'/usr/*' '*/cmocka.h' \
		'*/tests/unit/test_*.c' '*/tests/unit/common/*' \
		--output-file $(COVERAGE_INFO).clean \
		--rc branch_coverage=1 \
		--ignore-errors unused,inconsistent,empty 2>&1 | tail -5
	@mv $(COVERAGE_INFO).clean $(COVERAGE_INFO)
	@echo "==> Generating HTML report at $(COVERAGE_DIR)/..."
	@genhtml $(COVERAGE_INFO) --output-directory $(COVERAGE_DIR) \
		--branch-coverage \
		--title "F-Stack lib/ unit-test coverage" \
		--ignore-errors source,inconsistent,corrupt 2>&1 | tail -6
	@bash coverage_threshold.sh $(COVERAGE_INFO)

coverage_clean:
	@find . \( -name '*.gcda' -o -name '*.gcno' \) -type f -print 2>/dev/null \
	  | while read f; do \
	      /data/workspace/rm_tmp_file.sh "$$(realpath "$$f")" >/dev/null; \
	    done
	@if [ -f $(COVERAGE_INFO) ]; then \
	  /data/workspace/rm_tmp_file.sh "$$(realpath $(COVERAGE_INFO))" >/dev/null; \
	fi
	@if [ -d $(COVERAGE_DIR) ]; then \
	  /data/workspace/rm_tmp_file.sh "$$(realpath $(COVERAGE_DIR))" >/dev/null; \
	fi
