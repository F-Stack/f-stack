# M7 Spec — FF_USE_PAGE_ARRAY (P1a)

> Chinese version: ./zh_cn/phase2-M7-spec.md (authoritative)

> Spec version: v0.1 (2026-06-08)
> Parent plan: `phase2-feature-enable-plan.md` v0.1
> Predecessor milestone: M6 committed at `4139198f6` (feature/1.26 ahead 14)
> M5 baseline: libfstack.a 5.4 MB / 0 errors / 55 warnings
> M6 baseline: libfstack.a 6.5 MB / 0 errors / 57 warnings (M7 G1.3 threshold = 57+5 = 62)

---

## 1. Scope

### 1.1 In scope

| Item | Note |
|---|---|
| Enable `FF_USE_PAGE_ARRAY=1` | uncomment `lib/Makefile:46` |
| **Keep `FF_ZC_SEND` off** | validate the page-array path on its own; FF_ZC_SEND belongs to M8 |
| Build clean | `lib && make all` exit=0; warnings ≤ 62 (M6+5) |
| Primary smoke | `helloworld` alive ≥10 s without crash; log shows `ff_init_ref_pool` / `ff_mmap_init` success traces |
| Simple curl smoke | `helloworld_epoll` listens on port 80; local-host curl over the page-array path doesn't crash |
| Perf baseline (G4 mandatory) | nginx_fstack 4-core short/long conn, trade-off vs. M6 baseline ≤ 5%; over budget → observation (non-blocking, same as Phase-5b OQ) |
| Doc sync (partial) | docs/01-LAYER1 + Summary add an M7 footnote |
| Local commit | English message; no push |

### 1.2 Out of scope

| Item | Reason |
|---|---|
| FF_ZC_SEND combo | M8/M9 task |
| ff_memory.c internal refactor | enable only, no implementation change |
| KG re-index | M-Final |

---

## 2. Background and State (measured)

### 2.1 lib/Makefile control points

```
:46   #FF_USE_PAGE_ARRAY=1                ← uncomment
:113  ifdef FF_USE_PAGE_ARRAY (host CFLAGS)
:114    HOST_CFLAGS+= -DFF_USE_PAGE_ARRAY
:288  ifdef FF_USE_PAGE_ARRAY
:290    FF_HOST_SRCS += ff_memory.c
```

### 2.2 Source files (measured)

| File | Lines | Role |
|---|---|---|
| `lib/ff_memory.c` | 481 | mmap-based page array + mbuf reference pool implementation |
| `lib/ff_memory.h` | ~115 | 4 API declarations (FF_USE_PAGE_ARRAY guarded) |
| `lib/ff_dpdk_if.c` | — | 5 `#ifdef FF_USE_PAGE_ARRAY` branches (init/TX/error path) |
| `lib/ff_host_interface.c` | — | 2 branches (ff_mmap/ff_munmap special path for 4 KB pages routes through page array) |

### 2.3 Public API (declared in `ff_memory.h` under FF_USE_PAGE_ARRAY)

| API | Purpose |
|---|---|
| `ff_init_ref_pool(int nb_mbuf, int socketid)` | initialize the mbuf reference pool (called at init) |
| `ff_mmap_init()` | initialize the mmap page array (called at init) |
| `ff_if_send_onepkt(ctx, m, total)` | TX one packet (replaces `ff_dpdk_if_send` under FF_USE_PAGE_ARRAY) |
| `ff_enq_tx_bsdmbuf(portid, p_mbuf, nb_segs)` | enqueue a BSD mbuf (async free after TX completion) |
| `ff_mem_get_page()` / `ff_mem_free_addr(addr)` | fast 4 KB page alloc/free (internal to ff_memory.c, not exposed in ff_memory.h) |

### 2.4 Performance motivation (inferred from README + history; cross-checked during research)

Reduces mbuf alloc/free and 4 KB mmap/munmap syscall overhead; the TX path uses the reference pool to enable a zero-copy idea (ZC_SEND is the more thorough version, addressed in M8).

---

## 3. Interface and Code Changes

### 3.1 lib/Makefile change (1 line)

```diff
-#FF_USE_PAGE_ARRAY=1
+FF_USE_PAGE_ARRAY=1
```

### 3.2 Other source-file changes

**Default: none**. If G1 fails (undefined ref), follow R-M7-1/R-M7-2.

---

## 4. Acceptance Criteria (G1-G7)

### G1 — build

| AC | Threshold | Test |
|---|---|---|
| G1.1 | exit=0 | `cd lib && make clean && make all` |
| G1.2 | errors=0 | `grep -ic 'error:'` |
| G1.3 | warnings ≤ 62 | `grep -ic 'warning'` (M6=57, allow +5) |
| G1.4 | libfstack.a size | within ±5% of M6 (6.5 MB) — page array adds only ~30 KB ff_memory.o |
| G1.5 | helloworld linkage | `cd example && make` exit=0 |

### G2 — primary smoke

| AC | Test | Pass |
|---|---|---|
| G2.1 | helloworld alive ≥10 s in background | `[ -d /proc/$PID ]` |
| G2.2 | log: 0 SIGSEGV/panic/stub-called | `grep -iE 'sigsegv\|panic\|stub called'` |
| G2.3 | log shows page-array init traces | `grep -iE 'ref_pool\|mmap_init\|page'` or simply no panic |

### G3 — simple functional (curl)

| AC | Test | Pass |
|---|---|---|
| G3.1 | helloworld_epoll builds + listens on 80 | helloworld_epoll PID alive |
| G3.2 | local curl `localhost` (or configured IP) | HTTP 200 OR at least no crash; the focus is "page-array TX path doesn't crash" |
| G3.3 downgrade | if helloworld_epoll/curl path fails due to environment (no port-80 binding), downgrade to: helloworld primary polls 30 s without crash → G3 PASS+observation | OQ-4 default-allowed |

### G4 — perf baseline

| AC | Test | Criterion |
|---|---|---|
| G4.1 | perf script available | `tools/sbin/m5_perf.sh` already in place (Phase-5b reuses) |
| G4.2 | M6 vs M7 short-conn rps trade-off | ≤ 5% (else → observation) |
| G4.3 | M6 vs M7 long-conn goodput trade-off | ≤ 5% |
| G4.4 downgrade | if env can't run perf (CVM/network limits), downgrade to: only record a 1-min stability observation under synthetic traffic from M6→M7 | OQ-2 default-allowed |

### G5 — doc sync (partial)

| AC | File |
|---|---|
| G5.1 | docs/01-LAYER1 + zh_cn mirror: M7 footnote |
| G5.2 | docs/Summary + zh_cn: scope tag + M7 |
| G5.3 | phase2-M7-execution-log.md (this milestone artifact) |

### G6 — lint
`read_lints docs/ + lib/` 0 errors.

### G7 — commit
Local English commit; no push.

---

## 5. Risks

| ID | Risk | Mitigation |
|---|---|---|
| **R-M7-1** | ff_memory.c may reference removed/renamed mbuf fields under 14.0+ ABI (e.g. old m_ext, m_extadd usage) | on G1 fail, add stub or minimal patch; reviewer cross-checks `freebsd-src-releng-15.0/sys/sys/mbuf.h` |
| **R-M7-2** | DPDK 23.11.5 mbuf API incompatible with ff_memory.c older usage (pktmbuf_init / mempool) | grep `rte_mbuf_init\|rte_mempool_create` inside ff_memory.c |
| **R-M7-3** | helloworld_epoll binary stale (linked against old libfstack.a) | example/make forces relink |
| **R-M7-4** | perf trade-off > 5% | observation tag, user decides (plan §8 OQ-2 default-allowed) |
| **R-M7-5** | DPDK runtime residue prevents helloworld startup | before launch, `rm_tmp_file.sh` cleans `/var/run/dpdk/rte/*` |

---

## 6. Phase Progress

| Phase | Status |
|---|---|
| A. Spec (this doc) | ✅ DRAFT |
| B. Research | skipped (folded into §2) |
| C. Code | ⏭ |
| D. Review | ⏭ |
| E. Gate | ⏭ |

---

> Next: Phase C — coder applies the 1-line `lib/Makefile:46` diff and triggers G1-G7.
