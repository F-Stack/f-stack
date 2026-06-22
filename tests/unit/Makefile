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
DPDK_CFLAGS   := $(shell $(PKG_CFG) --cflags libdpdk 2>/dev/null)
DPDK_LIBS     := $(shell $(PKG_CFG) --libs libdpdk 2>/dev/null)

# Versions guard (R-U-3 mitigation)
CMOCKA_VER    := $(shell $(PKG_CFG) --modversion cmocka 2>/dev/null)
CMOCKA_OK     := $(shell echo "$(CMOCKA_VER)" | awk -F. '{ if ($$1 > 1 || ($$1 == 1 && $$2 > 1) || ($$1 == 1 && $$2 == 1 && $$3 >= 7)) print "ok" }')
ifneq ($(CMOCKA_OK),ok)
$(error CMocka >= 1.1.7 required, found '$(CMOCKA_VER)')
endif

# Host-only build flags (R-U-2 / NFR-U-4)
# DPDK_CFLAGS includes -march=native -mssse3 etc. needed because rte_memcpy
# and other inline DPDK helpers expand into ISA-specific intrinsics.
CFLAGS        := -O0 -g3 -Wall -Wextra -Wno-unused-parameter \
                 -I$(LIB_DIR) -I$(COMMON_DIR) \
                 $(CMOCKA_CFLAGS) \
                 $(DPDK_CFLAGS) \
                 -DFF_UNIT_TEST=1

# Kernel-stack coexistence is compile-gated in lib/ by FF_KERNEL_COEXIST
# (default off). Build the suite with FF_KERNEL_COEXIST=1 to compile and run
# the coexistence test cases against the macro-enabled lib objects.
ifdef FF_KERNEL_COEXIST
CFLAGS        += -DFF_KERNEL_COEXIST
endif

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
P2_TESTS      := test_ff_thread test_ff_init test_ff_dpdk_pcap test_ff_dpdk_if
P3_TESTS      := test_ff_dpdk_kni test_ff_zc_send
ALL_TESTS     := $(SANITY_TESTS) $(P0_TESTS) $(P1_TESTS) $(P2_TESTS) $(P3_TESTS)

# Common stub objects
COMMON_OBJS   := $(COMMON_DIR)/ff_log_stub.o $(COMMON_DIR)/rte_stub.o

# Default goal
.PHONY: all test test_p0 test_p1 test_p2 test_p3 test_sanity check clean coverage coverage_clean help
all: $(ALL_TESTS)

help:
	@echo "F-Stack lib/ unit-test build targets:"
	@echo "  make all          - build all test binaries"
	@echo "  make test         - run all tests"
	@echo "  make test_sanity  - run hello-world sanity test"
	@echo "  make test_p0      - run P0 tests only"
	@echo "  make test_p1      - run P1 tests only"
	@echo "  make test_p2      - run P2 tests only"
	@echo "  make test_p3      - run P3 tests only"
	@echo "  make check        - run all tests under valgrind memcheck (FU-S2-1)"
	@echo "  make clean        - clean build artifacts (uses rm_tmp_file.sh wrapper)"
	@echo "  make coverage     - build with gcov + run tests + emit lcov HTML report"
	@echo "  make coverage_clean - remove gcov/.gcda/.gcno + coverage_report/"

# Runtime LD path for DPDK shared libs (test_ff_dpdk_if depends on them)
DPDK_RUNPATH  := /usr/local/lib64
RUN_ENV       := LD_LIBRARY_PATH=$(DPDK_RUNPATH):$$LD_LIBRARY_PATH

test_sanity: $(SANITY_TESTS)
	@for t in $(SANITY_TESTS); do \
	  echo "==> running $$t"; $(RUN_ENV) ./$$t || exit 1; \
	done

test_p0: $(P0_TESTS)
	@for t in $(P0_TESTS); do \
	  echo "==> running $$t"; $(RUN_ENV) ./$$t || exit 1; \
	done

test_p1: $(P1_TESTS)
	@for t in $(P1_TESTS); do \
	  echo "==> running $$t"; $(RUN_ENV) ./$$t || exit 1; \
	done

test_p2: $(P2_TESTS)
	@for t in $(P2_TESTS); do \
	  echo "==> running $$t"; $(RUN_ENV) ./$$t || exit 1; \
	done

test_p3: $(P3_TESTS)
	@for t in $(P3_TESTS); do \
	  echo "==> running $$t"; $(RUN_ENV) ./$$t || exit 1; \
	done

test: all
	@for t in $(ALL_TESTS); do \
	  echo "==> running $$t"; $(RUN_ENV) ./$$t || exit 1; \
	done
	@echo "ALL TESTS PASS ($(words $(ALL_TESTS)) binaries)"

# ----- check (FU-S2-1: valgrind memcheck per binary) ---------------------
# Runs every test binary under valgrind --tool=memcheck. Definite leaks
# fail the build (--errors-for-leak-kinds=definite + --error-exitcode=99).
# Long-lived F-Stack config-cache leaks (lib/ff_config.c) are filtered
# via valgrind.supp; see that file for the FU-S2-2-CFG-UNLOAD follow-up.
VALGRIND      ?= valgrind
VALGRIND_SUPP := valgrind.supp
VALGRIND_OPTS := --tool=memcheck \
                 --leak-check=full \
                 --errors-for-leak-kinds=definite \
                 --error-exitcode=99 \
                 --suppressions=$(VALGRIND_SUPP) \
                 --quiet

check: all
	@if ! command -v $(VALGRIND) >/dev/null 2>&1; then \
	  echo "ERROR: $(VALGRIND) not installed; please 'dnf install -y valgrind'"; \
	  exit 1; \
	fi
	@pass=0; fail=0; failed=""; \
	for t in $(ALL_TESTS); do \
	  printf "==> valgrind %-30s ... " "$$t"; \
	  if $(RUN_ENV) $(VALGRIND) $(VALGRIND_OPTS) ./$$t >/dev/null 2>/tmp/vg_$$t.$$$$.log; then \
	    echo "OK"; pass=$$((pass+1)); \
	    /data/workspace/rm_tmp_file.sh /tmp/vg_$$t.$$$$.log >/dev/null 2>&1; \
	  else \
	    echo "FAIL (see /tmp/vg_$$t.$$$$.log)"; \
	    fail=$$((fail+1)); failed="$$failed $$t"; \
	  fi; \
	done; \
	echo ""; \
	echo "=== valgrind summary: $$pass pass / $$fail fail ($(words $(ALL_TESTS)) total) ==="; \
	if [ $$fail -gt 0 ]; then \
	  echo "Failed binaries:$$failed"; \
	  exit 1; \
	fi
	@echo "ALL VALGRIND CHECKS PASS"

# ----- lib/*.c → lib_objs/*.o (independent of lib/Makefile, NFR-U-6) -----
$(LIB_OBJS_DIR):
	@mkdir -p $@

# Per-target extra CFLAGS for selected lib objects.
# FU-S7-KNI-ENABLE (Stage-7 follow-up): build ff_dpdk_kni.o with -DFF_KNI so
# that the test suite can exercise the OSPF case and the (!enable_kni)
# protocol_filter guard branches (otherwise dead code in the unit build).
$(LIB_OBJS_DIR)/ff_dpdk_kni.o: KNI_EXTRA_CFLAGS := -DFF_KNI

$(LIB_OBJS_DIR)/%.o: $(LIB_DIR)/%.c | $(LIB_OBJS_DIR)
	$(CC) $(CFLAGS) $(DPDK_CFLAGS) $(KNI_EXTRA_CFLAGS) -c $< -o $@

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
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) -Wl,--wrap=exit -Wl,--wrap=abort -Wl,--wrap=clock_gettime -Wl,--wrap=__assert_fail -lcrypto

# P1 #2 ff_epoll (ff_epoll.c references the kernel-coexistence host bridge
# symbols ff_host_epoll_*; this unit test exercises only the kqueue path and
# provides no-op stubs for them in test_ff_epoll.c)
test_ff_epoll: test_ff_epoll.o $(LIB_OBJS_DIR)/ff_epoll.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS)

# P1 #3 ff_config (links ff_ini_parser too; ff_config.o defines its own
# ff_global_cfg so we DO NOT link common/ff_log_stub.o here, only rte_stub.o)
# FU-S8-CFG-OOM: --wrap=calloc lets TCs force allocation failures to cover
# the `if (X == NULL)` OOM error legs in parse_lcore_mask / port / vlan.
test_ff_config: test_ff_config.o $(LIB_OBJS_DIR)/ff_config.o $(LIB_OBJS_DIR)/ff_ini_parser.o $(COMMON_DIR)/rte_stub.o
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) -Wl,--wrap=calloc

# P2 #1 ff_thread (links real pthread + ff_host_interface for ff_malloc/free;
# the test file ships its own `__thread struct thread *pcurthread` storage)
test_ff_thread: test_ff_thread.o $(LIB_OBJS_DIR)/ff_thread.o $(LIB_OBJS_DIR)/ff_host_interface.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) -Wl,--wrap=ff_malloc -lpthread -lcrypto

# P2 #2 ff_init (4 init step stubs in test file; exit() wrapped so failure
# paths surface as cmocka assertion failures rather than process death)
WRAP_FF_INIT  := -Wl,--wrap=exit
test_ff_init: test_ff_init.o $(LIB_OBJS_DIR)/ff_init.o
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(WRAP_FF_INIT)

# P2 #3 ff_dpdk_pcap (rte_lcore_id is inline, intercepted via TLS variable
# definition in the test file; rte_exit covered by BASE_WRAPS)
test_ff_dpdk_pcap: test_ff_dpdk_pcap.o $(LIB_OBJS_DIR)/ff_dpdk_pcap.o $(COMMON_DIR)/rte_stub.o
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) -lpthread

# P2 #4 ff_dpdk_if (trivial 7-function subset; rte_get_tsc_hz wrapped;
# many dpdk/ff_* refs stubbed in the test file. We DO link the real DPDK
# shared libraries to resolve the bulk of rte_eth_*/rte_timer_*/etc. that
# ff_dpdk_if.o references but our 7 tests never invoke. -lrte_net_bond
# pulls in the bond PMD which is not in the default libdpdk umbrella.)
WRAP_FF_DPDKIF := -Wl,--wrap=rte_get_tsc_hz \
                  -Wl,--wrap=ff_rss_check \
                  -Wl,--wrap=ff_rss_check6
test_ff_dpdk_if: test_ff_dpdk_if.o $(LIB_OBJS_DIR)/ff_dpdk_if.o $(COMMON_DIR)/rte_stub.o
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) $(WRAP_FF_DPDKIF) $(DPDK_LIBS) -lrte_net_bond -Wl,-rpath=/usr/local/lib64 -lpthread -lcrypto -ldl -lm

# P3 #1 ff_dpdk_kni (FU-S4-KNI subset: ff_kni_enqueue ratelimit branches;
# requires real DPDK EAL --no-huge for mempool + ring; if EAL init fails
# at runtime, all 4 TC are marked skip().)
test_ff_dpdk_kni: test_ff_dpdk_kni.o $(LIB_OBJS_DIR)/ff_dpdk_kni.o $(COMMON_DIR)/rte_stub.o
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) $(DPDK_LIBS) -lrte_net_bond -Wl,-rpath=/usr/local/lib64 -lpthread -lcrypto -ldl -lm

# P3 #2 ff_zc_send (FSTACK_ZC_SEND user-space logic; algorithm-conformance
# test with a self-contained mbuf shim, no lib/rte deps — the real TUs
# (ff_veth.c/ff_syscall_wrapper.c) cannot be host-compiled, see test header).
test_ff_zc_send: test_ff_zc_send.o
	$(CC) -o $@ $^ $(LDFLAGS_BASE)

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

# ----- coverage (Stage-3 + Stage-5, FU-U-6 / G8 thresholds for 10 files) -----
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
