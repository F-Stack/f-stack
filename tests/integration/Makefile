# F-Stack lib/ integration test Makefile (CMocka 1.1.7+)
# Per docs/unit_test_spec/zh_cn/99-stage6-coverage-boost-review.md
#   FU-CB-DPDKIF-INTEGRATION
#
# Unlike tests/unit/, this harness boots a real DPDK EAL (no-huge, no-pci,
# --vdev=net_null0) so ff_dpdk_init() can run end-to-end and exercise the
# init_lcore_conf / init_mem_pool / init_dispatch_ring / init_msg_ring /
# init_port_start / init_clock paths that are unreachable in pure-mock unit
# tests.

TOPDIR        := $(abspath ../..)
LIB_DIR       := $(TOPDIR)/lib
COMMON_DIR    := common
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

# Host build flags (no FF_KNI / FF_FLOW_ISOLATE / FF_FDIR / FF_USE_PAGE_ARRAY)
CFLAGS        := -O0 -g3 -Wall -Wextra -Wno-unused-parameter \
                 -I$(LIB_DIR) -I$(COMMON_DIR) \
                 $(CMOCKA_CFLAGS) \
                 $(DPDK_CFLAGS) \
                 -DFF_INTEGRATION_TEST=1

# Fatal-function wraps (mirror unit/Makefile).
# Note: unlike unit tests we do NOT wrap rte_get_tsc_hz here since the real
# EAL is initialized and rte_get_tsc_hz returns a sane value post-init.
BASE_WRAPS    := -Wl,--wrap=rte_exit -Wl,--wrap=rte_panic

LDFLAGS_BASE  := $(CMOCKA_LIBS)

# Tests list
ALL_TESTS     := test_ff_dpdk_if_integration test_ff_kni_integration \
                 test_ff_reload_integration test_ff_gendir_mp_integration

# Common stub objects
COMMON_OBJS   := $(COMMON_DIR)/rte_stub.o

# Runtime LD path for DPDK shared libs
DPDK_RUNPATH  := /usr/local/lib64
RUN_ENV       := LD_LIBRARY_PATH=$(DPDK_RUNPATH):$$LD_LIBRARY_PATH

.PHONY: all test check clean coverage coverage_clean help reload-harness reload-harness-dry
all: $(ALL_TESTS)

help:
	@echo "F-Stack lib/ integration-test build targets:"
	@echo "  make all          - build all integration test binaries"
	@echo "  make test         - run all integration tests"
	@echo "  make check        - run integration tests under valgrind"
	@echo "  make coverage     - build with gcov + run + emit lcov HTML report"
	@echo "  make clean        - clean build artifacts (uses rm_tmp_file.sh wrapper)"
	@echo "  make coverage_clean - remove gcov/.gcda/.gcno + coverage_report/"
	@echo "  make reload-harness - real-machine graceful-reload harness (needs TARGET_IP)"

# ----- graceful-reload real-machine harness (C-NR-601) ---------------------
# Deliberately NOT part of ALL_TESTS / `make test`: this one boots nginx on
# the DPDK-owned NIC, needs TARGET_IP plus a client machine and runs for
# minutes, none of which a CI box has. Keeping the default target C-only also
# guarantees `make test` never fails just because TARGET_IP is unset.
#   make reload-harness TARGET_IP=<DPDK_NIC_IP> HARNESS_ARGS="--rounds 100"
#   make reload-harness-dry TARGET_IP=<DPDK_NIC_IP>          (2-round smoke)
RELOAD_HARNESS := test_graceful_reload.sh
HARNESS_ARGS   ?=

reload-harness:
	@if [ -z "$(TARGET_IP)" ]; then \
	  echo "ERROR: TARGET_IP is mandatory (make reload-harness TARGET_IP=<DPDK_NIC_IP>)"; \
	  exit 2; \
	fi
	@/data/workspace/chmod_modify.sh +x $(RELOAD_HARNESS) >/dev/null
	@./$(RELOAD_HARNESS) -t "$(TARGET_IP)" $(HARNESS_ARGS)

reload-harness-dry:
	@$(MAKE) --no-print-directory reload-harness \
	  HARNESS_ARGS="--cases precheck,rt01,rv9 --rounds 2 --interval 6 $(HARNESS_ARGS)"

test: all
	@# The hugepage cleanup below must run even when a test FAILS (review
	@# P2-1): a failed run leaks 256 pages (512 MB) and ~7 failures would
	@# exhaust the 2048-page pool, so record the failure, clean, then exit.
	@fail=0; for t in $(ALL_TESTS); do \
	  echo "==> running $$t"; $(RUN_ENV) ./$$t || { fail=1; break; }; \
	done; \
	if ls /dev/hugepages/ff_gendir_mpmap_* >/dev/null 2>&1; then \
	  echo "==> cleaning ff_gendir_mp hugepage files"; \
	  ls /dev/hugepages/ff_gendir_mpmap_* | while read f; do \
	    /data/workspace/rm_tmp_file.sh "$$f" >/dev/null; \
	  done; \
	fi; \
	if [ -d /var/run/dpdk/ff_gendir_mp ]; then \
	  /data/workspace/rm_tmp_file.sh /var/run/dpdk/ff_gendir_mp >/dev/null; \
	fi; \
	if [ $$fail -ne 0 ]; then \
	  echo "INTEGRATION TESTS FAILED"; exit 1; \
	fi; \
	echo "ALL INTEGRATION TESTS PASS ($(words $(ALL_TESTS)) binaries)"

# ----- check (valgrind memcheck on integration tests) -------------------
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
	  printf "==> valgrind %-40s ... " "$$t"; \
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

# ----- lib/*.c → lib_objs/*.o -----
$(LIB_OBJS_DIR):
	@mkdir -p $@

$(LIB_OBJS_DIR)/%.o: $(LIB_DIR)/%.c | $(LIB_OBJS_DIR)
	$(CC) $(CFLAGS) $(DPDK_CFLAGS) $(KNI_EXTRA_CFLAGS) -c $< -o $@

# FU-S9-KNI-PROCESS-INTEG: ff_dpdk_kni.o built -DFF_KNI to match tests/unit
# (keeps the gcov branch layout consistent when run_full_coverage merges).
$(LIB_OBJS_DIR)/ff_dpdk_kni.o: KNI_EXTRA_CFLAGS := -DFF_KNI

# ----- common stubs -----
$(COMMON_DIR)/%.o: $(COMMON_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# ----- top-level test source -----
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ----- integration test binary -----
# Links full DPDK shared libs + ff_dpdk_if.o + ff_config.o + ff_ini_parser.o
# + ff_log.o (real, since logging happens during ff_dpdk_init) + ff_host_interface.o
# (for ff_clock_gettime in ff_get_tsc_ns).
# ff_reload.o + ff_drain_ring.o: M2/M3 graceful-reload objects referenced by
# ff_dpdk_if.c (ff_no_hw_mode / drain rings / heartbeat hooks).
INT_LIB_OBJS := \
    $(LIB_OBJS_DIR)/ff_dpdk_if.o \
    $(LIB_OBJS_DIR)/ff_config.o \
    $(LIB_OBJS_DIR)/ff_ini_parser.o \
    $(LIB_OBJS_DIR)/ff_log.o \
    $(LIB_OBJS_DIR)/ff_host_interface.o \
    $(LIB_OBJS_DIR)/ff_reload.o \
    $(LIB_OBJS_DIR)/ff_reload_gendir.o \
    $(LIB_OBJS_DIR)/ff_drain_ring.o \
    $(LIB_OBJS_DIR)/ff_flow_map.o

test_ff_dpdk_if_integration: test_ff_dpdk_if_integration.o $(INT_LIB_OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) \
	    $(DPDK_LIBS) -lrte_net_bond -Wl,-rpath=$(DPDK_RUNPATH) \
	    -lpthread -lcrypto -ldl -lm

# FU-S9-KNI-PROCESS-INTEG: drives kni_process_tx/rx via a net_ring port whose
# rx/tx rings we own (inject packets into rx, fill tx to force drop legs).
KNI_LIB_OBJS := \
    $(LIB_OBJS_DIR)/ff_dpdk_kni.o \
    $(LIB_OBJS_DIR)/ff_config.o \
    $(LIB_OBJS_DIR)/ff_ini_parser.o \
    $(LIB_OBJS_DIR)/ff_log.o \
    $(LIB_OBJS_DIR)/ff_host_interface.o \
    $(LIB_OBJS_DIR)/ff_reload.o

test_ff_kni_integration: test_ff_kni_integration.o $(KNI_LIB_OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) \
	    $(DPDK_LIBS) -lrte_net_ring -lrte_net_bond -Wl,-rpath=$(DPDK_RUNPATH) \
	    -lpthread -lcrypto -ldl -lm

# ----- graceful-reload integration test (IT-NR-A09/A10, nginx_reload_spec 08) -----
# Full graceful-reload lib surface: ff_reload.o (shared state + handover
# primitives), ff_drain_ring.o (bidirectional drain rings), ff_flow_map.o
# (flow table). Note rte_eth_tx_burst is a static inline in this DPDK, so
# the RV11 tx counting is done via rte_eth_fp_ops[] pointer swap inside the
# test source (no --wrap possible).
RELOAD_LIB_OBJS := \
    $(LIB_OBJS_DIR)/ff_dpdk_if.o \
    $(LIB_OBJS_DIR)/ff_config.o \
    $(LIB_OBJS_DIR)/ff_ini_parser.o \
    $(LIB_OBJS_DIR)/ff_log.o \
    $(LIB_OBJS_DIR)/ff_host_interface.o \
    $(LIB_OBJS_DIR)/ff_reload.o \
    $(LIB_OBJS_DIR)/ff_reload_gendir.o \
    $(LIB_OBJS_DIR)/ff_drain_ring.o \
    $(LIB_OBJS_DIR)/ff_flow_map.o

test_ff_reload_integration: test_ff_reload_integration.o $(RELOAD_LIB_OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) \
	    $(DPDK_LIBS) -lrte_net_bond -Wl,-rpath=$(DPDK_RUNPATH) \
	    -lpthread -lcrypto -ldl -lm

# ----- M5 Batch C: cross-master generation directory, real two-process EAL --
# (IT-NR-A14, nginx_reload_spec 08). Unlike the harnesses above this one
# boots a real PRIMARY (huge mode, no --no-huge: a DPDK 24.11 secondary
# needs the runtime-dir hugepage_data the primary only writes in that mode)
# and forks master->worker chains that attach as real secondaries with the
# same --file-prefix. NIC exclusivity is kept via --no-pci + net_null0.
MP_LIB_OBJS := $(RELOAD_LIB_OBJS)

test_ff_gendir_mp_integration: test_ff_gendir_mp_integration.o $(MP_LIB_OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) \
	    $(DPDK_LIBS) -lrte_net_bond -Wl,-rpath=$(DPDK_RUNPATH) \
	    -lpthread -lcrypto -ldl -lm

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

# ----- coverage (FU-CB-DPDKIF-INTEGRATION: ff_dpdk_if.c init/port path) -----
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
		'*/tests/integration/test_*.c' '*/tests/integration/common/*' \
		--output-file $(COVERAGE_INFO).clean \
		--rc branch_coverage=1 \
		--ignore-errors unused,inconsistent,empty 2>&1 | tail -5
	@mv $(COVERAGE_INFO).clean $(COVERAGE_INFO)
	@echo "==> Generating HTML report at $(COVERAGE_DIR)/..."
	@genhtml $(COVERAGE_INFO) --output-directory $(COVERAGE_DIR) \
		--branch-coverage \
		--title "F-Stack lib/ integration-test coverage" \
		--ignore-errors source,inconsistent,corrupt 2>&1 | tail -6

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
