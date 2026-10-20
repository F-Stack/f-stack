# F-Stack `tests/`

Test harness for the F-Stack `lib/` glue layer. It contains two suites:

| Suite | Path | Boots DPDK EAL? | Purpose |
|-------|------|-----------------|---------|
| **Unit**        | `tests/unit/`        | No (rte_* stubbed/wrapped) | Fast, isolated per-file branch/line coverage |
| **Integration** | `tests/integration/` | Yes (`--no-huge --no-pci`) | `ff_dpdk_if.c` paths that need a live EAL |

Total: **189 unit test cases** across 11 binaries + **8 integration test cases**.

---

## 1. Prerequisites

- `gcc` + GNU `make`
- `pkg-config` reporting `cmocka >= 1.1.7`
  - TencentOS 4.x: `dnf install -y libcmocka libcmocka-devel`
  - Verify: `pkg-config --modversion cmocka`
- DPDK 23.11 / 24.11 headers + runtime libs under `/usr/local` (`rte_config.h`, `librte_*.so`)
- `lcov` / `genhtml` (for coverage reports)
- `valgrind` (for `make check` memcheck)

Coverage and integration binaries are linked against the DPDK shared libs, so they
need the runtime path at execution time:

```bash
export LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH
```

The Makefiles already inject this via `RUN_ENV` for `make test` / `make check` /
`make coverage`; you only need it when launching a binary by hand (e.g.
`./test_ff_dpdk_kni`).

---

## 2. Quick start

```bash
cd /data/workspace/f-stack/tests/unit

make help            # list all targets
make test            # build + run every unit binary (189 TC)
make check           # re-run everything under valgrind memcheck (0 leak gate)
./run_coverage.sh    # build with gcov + run + lcov HTML + G8 threshold gate
```

Whole-project (unit + integration merged) coverage:

```bash
cd /data/workspace/f-stack/tests
./run_full_coverage.sh   # merges unit + integration into one report
```

---

## 3. Unit suite — `make` targets

| Target | Action |
|--------|--------|
| `make all`           | Build all test binaries |
| `make test`          | Build + run all suites (sanity + P0 + P1 + P2 + P3) |
| `make test_sanity`   | hello-world cmocka/pkg-config sanity (2 TC) |
| `make test_p0`       | P0: `ff_ini_parser` + `ff_log` |
| `make test_p1`       | P1: `ff_host_interface` + `ff_epoll` + `ff_config` |
| `make test_p2`       | P2: `ff_thread` + `ff_init` + `ff_dpdk_pcap` + `ff_dpdk_if` |
| `make test_p3`       | P3: `ff_dpdk_kni` |
| `make check`         | Run every binary under `valgrind --tool=memcheck` (definite leak => fail) |
| `make coverage`      | gcov build + run + emit `coverage_report/index.html` |
| `make clean`         | Remove build artifacts (via `rm_tmp_file.sh` wrapper) |
| `make coverage_clean`| Remove `.gcda/.gcno` + `coverage_report/` |

You can also build/run a single binary:

```bash
make test_ff_config
LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH ./test_ff_config
```

### Test-binary → lib-file map

| Binary | Group | lib file under test | TC | Notes |
|--------|-------|---------------------|----|-------|
| `test_hello`             | sanity | — | 2 | toolchain smoke test |
| `test_ff_ini_parser`     | P0 | `ff_ini_parser.c` | 25 | inih-style parser |
| `test_ff_log`            | P0 | `ff_log.c` | 13 | 4 `rte_log` API wraps |
| `test_ff_host_interface` | P1 | `ff_host_interface.c` | 22 | links libcrypto (RAND_bytes) |
| `test_ff_epoll`          | P1 | `ff_epoll.c` | 21 | kqueue/kevent synth stubs |
| `test_ff_config`         | P1 | `ff_config.c` | 50 | end-to-end via `ff_load_config`; `--wrap=calloc` for OOM |
| `test_ff_thread`         | P2 | `ff_thread.c` | 4 | links real pthread |
| `test_ff_init`           | P2 | `ff_init.c` | 6 | `--wrap=ff_malloc` |
| `test_ff_dpdk_pcap`      | P2 | `ff_dpdk_pcap.c` | 9 | stack mbuf + pcap rotation |
| `test_ff_dpdk_if`        | P2 | `ff_dpdk_if.c` | 19 | unit-mockable subset only |
| `test_ff_dpdk_kni`       | P3 | `ff_dpdk_kni.c` | 18 | boots EAL `--no-huge`; built `-DFF_KNI` |

---

## 4. Coverage scripts

### 4.1 `unit/run_coverage.sh` — unit coverage + G8 gate

```bash
./run_coverage.sh              # full: clean + gcov build + run + report + G8 summary
./run_coverage.sh --quick      # reuse existing .gcda (skip rebuild)
./run_coverage.sh --file ff_config.c   # per-line gcov detail for one file
./run_coverage.sh --serve      # also serve HTML report on :8080
./run_coverage.sh --clean      # remove all coverage artifacts and exit
./run_coverage.sh -h           # help
```

Exit codes: `0` success & all G8 thresholds met · `1` build/test failure or G8
violation · `2` bad CLI args.

HTML report: `unit/coverage_report/index.html`.

### 4.2 `unit/coverage_threshold.sh` — the "G8" per-file gate

Invoked automatically at the end of `run_coverage.sh`. It parses `coverage.info`
and enforces a per-file minimum **line** and **branch** percentage. Thresholds are
maintained as `tline["<file>"]` / `tbr["<file>"]` entries and are ratcheted upward
after each coverage-boost stage (kept at `actual − ~5pp` as a regression guard).

### 4.3 `run_full_coverage.sh` — merged unit + integration

```bash
cd tests
./run_full_coverage.sh         # build + run both suites, merge, report
./run_full_coverage.sh --quick # reuse existing .info traces
./run_full_coverage.sh --clean # remove all coverage artifacts
```

Merged HTML report: `tests/full_coverage_report/index.html`.

---

## 5. Integration suite — `tests/integration/`

Unlike the unit suite, this harness boots a **real DPDK EAL** (`--no-huge`,
`--no-pci`) so it can exercise `ff_dpdk_if.c` paths that depend on live mempools,
rings and ethdev. If EAL init fails (e.g. insufficient permissions), the affected
TCs `skip()` rather than fail.

```bash
cd tests/integration
make help
make test            # run integration tests (8 TC)
make check           # under valgrind
make coverage        # gcov build + report -> coverage_report/index.html
make clean
```

---

## 6. Current coverage snapshot (merged unit + integration)

| File | line | branch | Note |
|------|------|--------|------|
| `ff_log.c`            | 100%  | 100%  | capped |
| `ff_thread.c`         | 100%  | 100%  | capped |
| `ff_init.c`           | 100%  | 100%  | capped |
| `ff_dpdk_pcap.c`      | 100%  | 100%  | L118 dead leg `LCOV_EXCL_BR_LINE` |
| `ff_epoll.c`          | 100%  | 100%  | |
| `ff_host_interface.c` | 100%  | 98.1% | 2 clock-assert legs need `--wrap=__assert_fail` |
| `ff_ini_parser.c`     | 98.7% | 91.2% | 6 `&&!error` legs dead via `INI_STOP_ON_FIRST_ERROR` |
| `ff_config.c`         | 89.9% | 85.4% | remaining = OOM/dataflow single legs |
| `ff_dpdk_kni.c`       | 59.9% | 51.6% | tx/rx/alloc need integration (`rte_eth_*_burst` are `static inline`, not wrappable) |
| `ff_dpdk_if.c`        | 30.8% | 22.6% | mostly integration-only |
| **Project (merged)**  | 62.9% | 63.7% | |

> Numbers are produced by `run_coverage.sh` / `run_full_coverage.sh`; re-run them
> to refresh. The authoritative source is always the freshly generated
> `coverage.info`, not this table.

---

## 7. Adding a test for an existing lib file

1. Add a per-target rule in `unit/Makefile` listing the `lib_objs/*.o` + stubs to
   link, and any `-Wl,--wrap=<sym>` flags the file needs (see `WRAP_FF_LOG`,
   `WRAP_FF_DPDKIF`, the `test_ff_config` `--wrap=calloc`, and the
   `ff_dpdk_kni.o: KNI_EXTRA_CFLAGS := -DFF_KNI` per-object override for examples).
2. Add the binary name to the right `P{0,1,2,3}_TESTS` group.
3. Create `test_<file>.c` following the cmocka template (`group_setup` /
   `test_setup` / `cmocka_unit_test_setup_teardown`).
4. Naming convention: `test_<function>_<scenario>_<expected>`.
5. `make test_<file>` to build, run, then `./run_coverage.sh --file <file>.c` to
   confirm the targeted branches are now covered.

### Mock / wrap infrastructure

- `common/rte_stub.c` — `__wrap_rte_exit` / `__wrap_rte_panic` redirect to
  cmocka `mock_assert`, so a regression can never `SIGABRT` the harness.
- `common/ff_log_stub.{c,h}` — provides `struct ff_config ff_global_cfg` and a
  no-op `ff_log` for binaries that do not link `lib/ff_log.c`.
- OOM testing: `--wrap=calloc` with an armed counter (`g_calloc_fail_after`)
  passes through to `__real_calloc` unless armed, letting a TC force the Nth
  allocation to fail without disturbing cmocka's own allocations.
- Inline DPDK helpers (`rte_eth_tx_burst`, `rte_eth_rx_burst`,
  `rte_ring_dequeue_burst`) are `static inline` and **cannot** be `--wrap`-ed;
  testing those paths requires the integration suite with a real PMD.

---

## 8. Workspace mandates honored

- All transient file deletions go through `/data/workspace/rm_tmp_file.sh`
  (the Makefile `clean` target uses it; no direct `rm`).
- No direct `rm` / `kill` / `pkill` / `killall` / `chmod` anywhere in the tree.
- Test processes never call real `rte_exit` / `rte_panic` (intercepted via
  `__wrap_*` → `mock_assert`).

---

## 9. Design references

- Specs: `docs/unit_test_spec/zh_cn/` (`04-cmocka-framework-and-impl.md`,
  `06-test-cases-and-acceptance.md`, Stage-7 `7x-*.md`, Stage-8 `8x-*.md`)
- Methodology: `c-unittest-expert` skill (Unity-based, mapped to CMocka API)
- Stage reviews: `docs/unit_test_spec/zh_cn/{99-*,79-stage7-review,89-stage8-review}.md`
