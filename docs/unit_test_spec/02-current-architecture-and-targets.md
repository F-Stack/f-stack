# 02 — Current Architecture and Test-Target Tiering

> Document version: v0.1 (2026-06-09 17:55 UTC+8)
> Author: spec-author (based on parallel research from arch-explorer + mock-strategist + target-prioritizer)
> Scope: Measured F-Stack lib/ FF_HOST_SRCS 11-file inventory + P0/P1/P2/P3 test-target tiering

---

## 1. Document Purpose

Take a precise inventory of the 11 glue-code files listed by
`lib/Makefile FF_HOST_SRCS` in F-Stack lib/, covering:
1. File-level current state (line count / load condition / business complexity)
2. Function-level inventory (public API + static helpers + inih handlers)
3. Cross-file dependency matrix (11×11)
4. External-dependency statistics (rte / pthread / sys / printf, 4 classes)
5. **P0/P1/P2/P3 test-target tiering and ROI decision table**

Used as the direct reference when drafting specs 04 / 06, and the basis for
gate-keeper cross-checks.

---

## 2. FF_HOST_SRCS Measured Inventory (lib/Makefile lines 272-291 + 568-572)

### 2.1 File-level overview

| # | File | Lines | Load condition | Complexity (1–5) | Main logic |
|---|---|---|---|---|---|
| 1 | `ff_host_interface.c` | 332 | always | 3 | Per-process mmap/clock/arc4rand/errno conversion utilities |
| 2 | `ff_thread.c` | 51 | always | 1 | Thin pthread wrapper + thread-local injection |
| 3 | `ff_config.c` | 1381 | always | 4 | 11 inih handlers + argv parsing + dpdk_argv construction + string validation |
| 4 | `ff_ini_parser.c` | 195 | always | 3 | INI state machine (comment / section / multiline / BOM / inline-comment) |
| 5 | `ff_dpdk_if.c` | 2887 | always | 5 | Whole DPDK start/stop + port/RSS/bond/timer/burst rx/tx main loop |
| 6 | `ff_dpdk_pcap.c` | 137 | always | 2 | pcap file header / record write + timestamp |
| 7 | `ff_epoll.c` | 159 | always | 3 | Mapping translation between epoll API and ff_kqueue events |
| 8 | `ff_log.c` | 111 | always | 2 | `fopen` + rte_log wrapper + log-level setting |
| 9 | `ff_init.c` | 69 | always | 1 | 4-step serial initialization sequence (no branching logic) |
| 10 | `ff_dpdk_kni.c` | 536 | `FF_KNI=1` | 4 | KNI initialization + per-port/socket protocol filtering + multi-ring |
| 11 | `ff_memory.c` | 509 | `FF_USE_PAGE_ARRAY=1` | 4 | mbuf reference pool + virt2phy + tx ring + offload bridging |

**Total**: 11 files / 6377 lines, of which 9 are always loaded and 2 are conditional.

### 2.2 Relationship to the lib/ landscape

- lib/ contains **31 ff_*.c files / 22400 lines** in total.
- **This task covers** the HOST_SRCS 11 files / 6377 lines (28% of the lines).
- **Out-of-scope** = KERN_SRCS, ~20 files / ~16000 lines (72% of the lines) —
  the FreeBSD-kernel-subset port; not directly host-compiled.

### 2.3 Existing test traces (measured)

```bash
$ for f in <11 files>; do
    grep -cE "(^#ifdef.*TEST|UNITTEST|UNIT_TEST|assert\\()" lib/$f
  done
```

| File | `assert()` count | Is this a "test trace"? |
|---|---|---|
| ff_dpdk_if.c | 1 (line 784, hardware reta_size validation) | No — runtime assertion |
| ff_host_interface.c | 3 (lines 68, 176, 209) | No — runtime assertions |
| Other 9 files | 0 | — |
| `f-stack/tests/` or `test/` directory | does not exist | — |

→ **Conclusion**: All 11 files are "greenfield testing"; no existing unit-test
  code or remnants whatsoever.

---

## 3. Function-Level Inventory (measured)

### 3.1 Public APIs (non-static)

| File | # public APIs | API list (line numbers) |
|---|---|---|
| **ff_ini_parser.c** | **3** | `ini_parse` (L184), `ini_parse_file` (L178), `ini_parse_stream` (L73) |
| **ff_log.c** | **7** | `ff_log` (L95), `ff_log_close` (L68), `ff_log_open_set` (L48), `ff_log_reset_stream` (L77), `ff_log_set_global_level` (L83), `ff_log_set_level` (L89), `ff_vlog` (L108) |
| **ff_host_interface.c** | **11** | `ff_arc4rand` (L213), `ff_arc4random` (L221), `ff_calloc` (L111), `ff_clock_gettime` (L154), `ff_clock_gettime_ns` (L183), `ff_free` (L131), `ff_get_current_time` (L194), `ff_getenv` (L233), `ff_malloc` (L103), `ff_mmap` (L54), `ff_munmap` (L89), `ff_os_errno` (L238), `ff_realloc` (L119), `ff_setenv` (L228), `ff_update_current_ts` (L206), `panic` (L142, `__noreturn__`) |
| **ff_thread.c** | 2 | `ff_pthread_create` (L33), `ff_pthread_join` (L49) |
| **ff_config.c** | **1** | `ff_load_config` (L1347) |
| **ff_dpdk_if.c** | 17+ | `ff_dpdk_init`, `ff_dpdk_run`, `ff_dpdk_stop`, `ff_dpdk_register_if`, `ff_dpdk_deregister_if`, `ff_dpdk_if_send`, `ff_dpdk_if_up`, `ff_dpdk_pktmbuf_free`, `ff_dpdk_raw_packet_send`, `ff_get_traffic`, `ff_get_tsc_ns`, `ff_in_pcbladdr`, `ff_regist_packet_dispatcher`, `ff_regist_packet_dispatcher_context`, `ff_regist_pcblddr_fun`, `ff_rss_check`, `ff_rss_tbl_get_portrange`, `ff_rss_tbl_init`, `ff_rss_tbl_set_portrange` |
| **ff_dpdk_pcap.c** | 1 | `ff_enable_pcap` (L59) |
| **ff_epoll.c** | 3 | `ff_epoll_create` (L25), `ff_epoll_ctl` (L31), `ff_epoll_wait` (L148) |
| **ff_init.c** | 3 | `ff_init` (L36), `ff_run` (L59), `ff_stop_run` (L65) |
| **ff_dpdk_kni.c** | 5 | `ff_kni_alloc` (L423), `ff_kni_enqueue` (L503), `ff_kni_init` (L377), `ff_kni_process` (L494), `ff_kni_proto_filter` (L371) |
| **ff_memory.c** | 6 | `ff_enq_tx_bsdmbuf` (L505), `ff_if_send_onepkt` (L440), `ff_init_ref_pool` (L213), `ff_mem_free_addr` (L305), `ff_mem_get_page` (L300), `ff_mmap_init` (L228) |
| **Total** | **~75 public APIs** | — |

### 3.2 The 11 inih handlers in ff_config.c (**all static**, key constraint)

| # | Handler | Line | static? | Directly testable? |
|---|---|---|---|---|
| 1 | `freebsd_conf_handler` | L156 | static | No |
| 2 | `vip_cfg_handler` | L380 | static | No |
| 3 | `vip6_cfg_handler` | L429 | static | No |
| 4 | `ipfw_pr_cfg_handler` | L480 | static | No |
| 5 | `port_cfg_handler` | L541 | static | No |
| 6 | `vlan_cfg_handler` | L641 | static | No |
| 7 | `vdev_cfg_handler` | L746 | static | No |
| 8 | `bond_cfg_handler` | L800 | static | No |
| 9 | `rss_tbl_cfg_handler` | L860 | static | No |
| 10 | `rss_check_cfg_handler` | L903 | static | No |
| 11 | `ini_parse_handler` | L935 | static | No (top-level dispatcher invoked by ini_parser) |

**Only non-static API**: `ff_load_config(int argc, char *const argv[])` (L1347).

→ **Key constraint (recorded as R-U-5)**: ff_config.c handlers **cannot** be
  directly unit-tested; they must be reached through:
- **Approach A (recommended for P0/P1)**: build a temporary `.ini` file +
  `argv[]` → call `ff_load_config()` → check the global `ff_global_cfg`
  structure (end-to-end black box).
- **Approach B (white-box hack)**: tests `#include "ff_config.c"` directly
  (hack-style; acceptable as a P1 augmentation).
- **Approach C (intrusive, not recommended)**: change handlers to non-static
  (violates the black-box principle).

### 3.3 ff_ini_parser.c public API (**P0 test target**)

From `ff_ini_parser.h` L21–48, the inih standard trio:

```c
typedef int (*ini_handler)(void* user, const char* section,
                           const char* name, const char* value);
typedef char* (*ini_reader)(char* str, int num, void* stream);

int ini_parse(const char* filename, ini_handler handler, void* user);     // L184
int ini_parse_file(FILE* file, ini_handler handler, void* user);          // L178
int ini_parse_stream(ini_reader reader, void* stream,
                     ini_handler handler, void* user);                    // L73
```

Return-value contract: `0` success; `>0` line number of the first error; `-1`
file-open failure; `-2` memory-allocation failure (only when `INI_USE_STACK=0`).

**Internal helpers** (all static, indirectly covered through `ini_parse_stream`
+ a custom reader):
- `rstrip` (L28), `lskip` (L37), `find_chars_or_comment` (L47), `strncpy0` (L65)

### 3.4 ff_log.c public API (**P0 test target**)

Measured directly from `ff_log.c` (**arch-explorer Q5 lists 7**;
target-prioritizer counted 6 — slight off; arch-explorer prevails):

```c
extern char FF_LOG_FILENAME_PREFIX[];   // global constant

int  ff_log_open_set(void);                                 // L48; fopen + ff_log_reset_stream + 2× ff_log_set_level
void ff_log_close(void);                                    // L68; fclose and clear ff_global_cfg.log.f
int  ff_log_reset_stream(void *f);                          // L77; rte_openlog_stream(f) wrapper
void ff_log_set_global_level(uint32_t level);               // L83; rte_log_set_global_level wrapper
int  ff_log_set_level(uint32_t logtype, uint32_t level);    // L89; rte_log_set_level wrapper
int  ff_log(uint32_t level, uint32_t logtype,
            const char *format, ...);                        // L95; va_start + rte_vlog + va_end
int  ff_vlog(uint32_t level, uint32_t logtype,
             const char *format, va_list ap);                // L108; rte_vlog passthrough
```

**Test points**:
- **All 5 rte_ calls are 1:1 forwarders** → unit tests must mock:
  `rte_openlog_stream` / `rte_log_set_global_level` / `rte_log_set_level` /
  `rte_vlog` (4 in total).
- `ff_log_open_set` / `ff_log_close` depend on the global `ff_global_cfg`
  (an external global from ff_config.c); fixtures must build a stub for it.
- `ff_log` is variadic → verify `va_start/va_end` pairing and return-value passthrough.

---

## 4. External-Dependency Statistics (11×4 matrix)

Measured `grep -cE "..."` hits (mock-strategist Q1):

| File (lines) | rte_* | pthread_* | sys class | printf class |
|---|---:|---:|---:|---:|
| ff_host_interface.c (332) | 6 | 0 | 1 (mmap) | 0 |
| ff_thread.c (51) | 0 | 2 | 0 | 0 |
| ff_config.c (1381) | 7 | 0 | 0 | **56** |
| **ff_ini_parser.c (195)** | **0** | **0** | **0** | **0** |
| ff_dpdk_if.c (2887) | **173** | 0 | 0 | 5 |
| ff_dpdk_pcap.c (137) | 3 | 0 | 0 | 0 |
| ff_epoll.c (159) | 0 | 0 | 0 | 0 |
| ff_log.c (111) | 5 | 0 | 0 | 0 |
| ff_init.c (69) | 0 | 0 | 0 | 0 |
| ff_dpdk_kni.c (536) | 34 | 0 | 0 | 3 |
| ff_memory.c (509) | 24 | 0 | 1 (open) | 1 |

### 4.1 Key observations

1. **Files with zero external dependencies (easiest to test, P0 candidates)**:
   `ff_ini_parser.c` (**0/0/0/0**), `ff_epoll.c` (**0/0/0/0**), `ff_init.c`
   (0/0/0/0) — but epoll/init still indirectly depend on `ff_kqueue/ff_kevent`
   and other ff_api stubs.
2. **rte_ heavy hitters**: `ff_dpdk_if.c` 173 + `ff_dpdk_kni.c` 34 +
   `ff_memory.c` 24 — P2/P3.
3. **printf-heavy**: `ff_config.c` has 56 (mostly error prints; can stay real).

### 4.2 ff_dpdk_if.c top-5 most frequent rte_ APIs (mock-strategist Q2)

| Rank | rte_ API | Hits | Main use |
|---|---|---:|---|
| 1 | `rte_exit()` | ~25+ | Error exit (fatal path; **must mock**) |
| 2 | `rte_pktmbuf_free()` | ~15 | mbuf release |
| 3 | `rte_eal_process_type()` | 8 | Primary/secondary check (control branch; **must mock**) |
| 4 | `rte_eth_*` family | ~20 | NIC management |
| 5 | `rte_panic()` / `rte_zmalloc()` / `rte_memcpy()` / `rte_ring_*` | 5–8 each | Fatal / memory / ring |

---

## 5. Cross-File Dependency Matrix (11×11, only callers shown)

Rows = caller, columns = callee (based on arch-explorer Q6 measurement):

| from \\ to | host_if | thread | config | ini_parse | dpdk_if | dpdk_pcap | epoll | log | init | kni | memory |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **ff_host_interface.c** | — | | | | | | | 1 | | | 2 |
| **ff_thread.c** | 2 | — | | | | | | | | | |
| **ff_config.c** | | | — | 1 | | | | many | | | |
| **ff_ini_parser.c** | | | | — | | | | | | | |
| **ff_dpdk_if.c** | 1+extern | | many | | — | 1 | | dozens | | 2+ | 1 |
| **ff_dpdk_pcap.c** | | | | | | — | | | | | |
| **ff_epoll.c** | | | | | | | — | | | | |
| **ff_log.c** | | | many | | | | | — (self-call) | | | |
| **ff_init.c** | | | 1 | | 4 | | | | — | | |
| **ff_dpdk_kni.c** | | | many | | | | | | | — | |
| **ff_memory.c** | | | 1 | | header ref | | | | | | — |

### 5.1 Key observations (used to prioritize mocks)

1. **`ff_log` / `ff_global_cfg` are common dependencies**: 6 files
   (ff_dpdk_if / ff_config / ff_log / ff_dpdk_kni / ff_memory /
   ff_host_interface) all need them → spec 04 §9 must first build a shared
   `ff_log_stub.c` + `ff_global_cfg` static instance.
2. **Files with zero external dependencies**: `ff_ini_parser.c` (referenced by
   ff_config.c but with zero reverse dependencies) → the best P0 starting
   point.
3. **`ff_init.c` is a high-level glue**: its 3 public functions all forward to
   ff_dpdk_*/ff_load_config/ff_freebsd_init → unit-test strategy is "mock all
   downstream + verify call ordering".
4. **`ff_dpdk_if.c` is the dependency hub**: it calls 6 other modules + 173
   rte_ calls → highest unit-test cost; only the pure-function subset can be
   broken out (4 candidates: `ff_rss_check` / `ff_rss_tbl_get_portrange` /
   `ff_in_pcbladdr` / `ff_get_tsc_ns`).

---

## 6. Test-Target P0/P1/P2/P3 Tiering (**core ROI decision table**)

> Effort unit (turns) = estimated number of "spec → impl → tests pass" iterations.

| # | File | **Priority** | Lines | Estimated TC | Effort (turns) | Mock complexity | ROI rationale |
|---|---|---|---|---|---|---|---|
| 1 | **ff_ini_parser.c** | **P0** | 195 | 18–22 | 2–3 | **Zero** (pure stdlib + FILE\*) | Zero DPDK deps, 3 public APIs, many state-machine branches, full coverage achievable with temp files; highest ROI |
| 2 | **ff_log.c** | **P0** | 111 | 10–14 | 2 | Low (mock 4 symbols: `rte_log/rte_vlog/rte_openlog_stream`) | All 7 public APIs are directly callable, `fopen/fclose` are trivial to test; only 4 rte symbols need mocking |
| 3 | **ff_host_interface.c** | **P1** | 332 | 14–18 | 3–4 | Medium (mock `rte_malloc/rte_free`, rest libc) | 11 public APIs, pure per-process utilities (pagesize/clock/arc4rand), no main-loop dependency |
| 4 | **ff_epoll.c** | **P1** | 159 | 8–12 | 3 | Medium-high (need to stub `ff_kqueue/ff_kevent` and other ff_api functions) | 3 public APIs + epoll↔kqueue event translation is the core business; the translation table is fully testable, but the ff_api dependency must be stubbed |
| 5 | **ff_config.c** (end-to-end + handler include hack) | **P1** | 1381 | 20–28 | 5–7 | Medium (need to prepare real .ini temp files + partial stub of `rte_strsplit`) | Business complexity 4 but only 1 public API; an .ini fixture end-to-end can cover ~70%; the rest of the handlers can be reached white-box via `#include "ff_config.c"` |
| 6 | **ff_thread.c** | **P2** | 51 | 4–6 | 1 | Medium (`__thread pcurthread` injection + `ff_malloc/ff_free` stubs) | Tiny file but ROI is mediocre: business is "pass the parent thread to the child"; 4 symbols must be stubbed before it runs; pure-wrapper value is low |
| 7 | **ff_dpdk_pcap.c** | **P2** | 137 | 6–8 | 3 | Medium-high (mock rte_mbuf data structures + timestamp) | The pcap-file-header output is testable; need a fake mbuf; medium value |
| 8 | **ff_init.c** | **P2** | 69 | 3–4 | 2 | High (need to stub `ff_load_config/ff_dpdk_init/ff_freebsd_init/ff_dpdk_if_up` etc.) | Business is just "4 sequential steps + exit(1)"; once all dependencies are stubbed, error propagation can be verified; ROI is low but the stubs are reusable |
| 9 | **ff_dpdk_if.c** | **P2** | 2887 | 30–50 (pure-function subset only) | 8–12 | **Very high** (27 rte_ headers + main loop + hardware state) | Only pure functions (`ff_rss_check`/`ff_rss_tbl_get_portrange`/`ff_in_pcbladdr`/`ff_get_tsc_ns`) can be unit-tested; main init/run path is not unit-testable → leave as follow-up |
| 10 | **ff_dpdk_kni.c** | **P2** | 536 | 8–12 | 5–7 | **Very high** (KNI kernel module + ring + ethdev) | Port-string parsing + filter dispatch can be split into pure-function tests; the rest depends on the kernel module and needs integration tests |
| 11 | **ff_memory.c** | **P3** | 509 | — | — | Very high (mmap + virt2phy + ethdev) | **Load condition `FF_USE_PAGE_ARRAY=1` is off by default**; core is mbuf / physical-memory mapping black magic; not invested unless explicitly enabled |

### 6.1 Tier summary

- **P0 = 2 files** (ff_ini_parser.c + ff_log.c) — land immediately, ~4–5 turns,
  covering 3+7 = **10 public APIs**
- **P1 = 3 files** (ff_host_interface.c + ff_epoll.c + ff_config.c) — second
  batch, ~11–14 turns, covering 11+3+1 = **15 public APIs** (config has 11
  handlers covered end-to-end)
- **P2 = 5 files** (ff_thread.c + ff_dpdk_pcap.c + ff_init.c + ff_dpdk_if.c +
  ff_dpdk_kni.c) — follow-up
- **P3 = 1 file** (ff_memory.c) — off by default, not invested
- **Total = 11** ✓

### 6.2 Differences vs the plan §1.1 preliminary classification (important revisions)

| File | plan §1.1 preliminary | spec 02 §6 (research-based) | Adjustment rationale |
|---|---|---|---|
| **ff_log.c** | P1 | **P0 ↑** | All 7 public APIs are directly callable; only 4 rte symbols to mock; ROI higher than ff_host_interface.c |
| **ff_config.c** | P0 (parser-handlers subset) | **P1 end-to-end** (no longer "handlers subset") | All 11 handlers are static and not directly testable; must use the .ini fixture end-to-end via ff_load_config() |
| **ff_thread.c** | (not listed) | **P2** | 51 lines, but 4 symbols need stubbing before it runs; low ROI |

---

## 7. Anchors to the Three-Layer Architecture Docs

| 11 files | Position in docs/01-LAYER1-ARCHITECTURE.md | In docs/02-LAYER2-INTERFACES.md | In docs/03-LAYER3-FUNCTIONS.md |
|---|---|---|---|
| ff_ini_parser.c | L1 lib/ tree node | inih API contract | 4 public functions |
| ff_log.c | L1 lib/ tree node | log API contract | 7 public functions |
| ff_config.c | L1 lib/ tree node | config API contract | 1 public + 11 static handlers |
| ff_dpdk_if.c | L1 lib/ tree node (core) | dpdk_if API contract | ~17 public + many static |
| Other 7 files | L1 lib/ tree node | Their respective interface contracts | Their respective function lists |

→ **This task does not modify the three-layer architecture docs**; the commit
  phase appends 1 anchor line to L1 (the same minimal-footprint pattern as
  dpdk-23-24 / vlan-test).

---

## 8. Key Findings Summary (referenced by specs 04 / 06)

| # | Key finding | Impact |
|---|---|---|
| F1 | ff_config.c has 11 static handlers | Strategy = end-to-end `.ini` fixture (recommended) + `#include "ff_config.c"` hack (alternate) |
| F2 | All 5 rte calls in ff_log.c are 1:1 forwarders | Mock template is reusable; fixtures are simple |
| F3 | rte_exit / rte_panic must be wrapped or the unit-test process gets killed | spec 04 §8 mandatory rule |
| F4 | ff_ini_parser.c is BSD-licensed third-party inih code | spec 06 §3.1 explicitly says "test the F-Stack integration layer + state-machine coverage" |
| F5 | ff_global_cfg is a cross-file shared dependency | spec 04 §9 fixture template must include a static `ff_global_cfg` instance |
| F6 | ff_dpdk_if.c has 173 rte_ calls | spec 04 §7 only plans P2 pure-function subset mocks; full coverage is not pursued |
| F7 | The host build does not directly compile KERN_SRCS | NFR-U-6 — the test Makefile does not link `lib/libfstack.a` as a whole; only the .o under test + stubs |
| F8 | The f-stack repo has zero pre-existing test traces | Greenfield throughout; no historical compatibility to consider |

---

**End of document (v0.1, within the 450-line budget)**
