# F-Stack tests/

Unit-test framework for F-Stack `lib/` glue code, scoped to the host-side
files declared in `lib/Makefile` `FF_HOST_SRCS`.

## Quick start

```bash
cd /data/workspace/f-stack/tests/unit

make help            # list available targets
make test            # build + run sanity + P0 + P1 (~0.4s, 59 TC)
make test_p0         # P0 only (ff_ini_parser + ff_log, 31 TC)
make test_p1         # P1 only (ff_host_interface + ff_epoll + ff_config, 26 TC)
make test_sanity     # hello-world sanity check (2 TC)
make clean           # remove build artifacts (uses workspace rm_tmp_file.sh)
```

## Prerequisites

- `gcc` + GNU `make`
- `pkg-config` reporting `cmocka >= 1.1.7`
  - On TencentOS 4.4: `dnf install -y libcmocka libcmocka-devel`
  - Verify: `pkg-config --modversion cmocka`
- DPDK headers (`/usr/local/include/rte_config.h` etc.) — used when compiling
  `lib/ff_log.c` and `lib/ff_config.c` host-side

## Layout

```
tests/
└── unit/
    ├── Makefile                  GNU make, no cmake/meson, no lib/Makefile pollution
    ├── common/
    │   ├── ff_log_stub.{c,h}     defines `struct ff_config ff_global_cfg`
    │   └── rte_stub.{c,h}        __wrap_rte_exit / __wrap_rte_panic via mock_assert
    ├── fixtures/                 .ini files for P1 ff_config end-to-end tests
    ├── lib_objs/                 (build cache) lib/*.c built with our CFLAGS
    ├── test_hello.c              sanity (CMocka + pkg-config)
    ├── test_ff_ini_parser.c      P0 #1 — 18 TC (1 SKIP: FU-S2-NULLFILE)
    ├── test_ff_log.c             P0 #2 — 13 TC, 4 rte_log API wraps
    ├── test_ff_host_interface.c  P1 #1 — 8 TC, links libcrypto for RAND_bytes
    ├── test_ff_epoll.c           P1 #2 — 7 TC, ff_kqueue/ff_kevent stubs in test
    └── test_ff_config.c          P1 #3 — 11 TC, end-to-end via ff_load_config
```

## Adding a new test for an existing lib file

1. Add a target rule in `Makefile` listing the lib_objs/*.o + stubs to link
2. Add `__wrap_<sym>` linker flags if the file needs to mock additional rte_*
   APIs (see `WRAP_FF_LOG` for an example)
3. Create `test_<file>.c` following the cmocka template
4. `make <target>` to build, `./<target>` to run

## Test design references

- Spec docs: `docs/unit_test_spec/zh_cn/{04-cmocka-framework-and-impl.md, 06-test-cases-and-acceptance.md}`
- Methodology: `.codebuddy/rules/c-unittest-expert.mdc` (Unity-based; mapped to CMocka API)
- Stage-1 review: `docs/unit_test_spec/zh_cn/99-review-report.md`
- Stage-2 implementation review: `docs/unit_test_spec/zh_cn/99-stage2-review.md`

## Workspace mandates honored

- All transient file deletions go through `/data/workspace/rm_tmp_file.sh`
- No direct `rm`, `kill`, `pkill`, `killall`, `chmod` invocations anywhere in
  the tree (zero-tolerance per workspace memory rules)
- Test process never calls real `rte_exit` / `rte_panic` (intercepted via
  `__wrap_*` to `mock_assert`, so a regression cannot SIGABRT the harness)
