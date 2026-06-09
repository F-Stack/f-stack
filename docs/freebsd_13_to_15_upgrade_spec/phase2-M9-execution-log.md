# Phase-2 M9 Execution Log — PA + ZC combo (P1c)

> Chinese version: ./zh_cn/phase2-M9-execution-log.md (authoritative)

> Status: ✅ PASS (G1-G3 + G6/G7 all green; G4 perf observation shows occasional 1000-conn timeout under combo, recorded as follow-up F1)
> Date: 2026-06-08
> Upstream basis: M8 commit `add33a04a`

---

## 1. Summary

Enable `FF_USE_PAGE_ARRAY=1` + `FF_ZC_SEND=1` together in `lib/Makefile` to validate that the M7 and M8 features coexist in a single build. **0 source-code changes**, 0 bounces, 1 line of Makefile diff.

---

## 2. Change List

| File | Change |
|---|---|
| `lib/Makefile` | line 46 `#FF_USE_PAGE_ARRAY=1` → `FF_USE_PAGE_ARRAY=1` (M8 already enabled ZC; this milestone only flips PA) |

**Total: 1 file +1/-1**

---

## 3. Gate Results (measured)

### G1 — build

| Item | Result |
|---|---|
| `lib/ make clean && make` | exit=0 / 0 errors / 57 warnings (= baseline) |
| `libfstack.a` | 6.55 MB (≈ M7/M8; new code lives in shared .o files) |
| `example/ make` | all 3 binaries produced |

### G2 — primary smoke

| Item | Result |
|---|---|
| primary alive ≥12 s | ✓ |
| `ff_mmap_init mmap 65536 pages, 256 MB.` | ✓ (PA active) |
| `tcp_bbr is now available` + `ipfw2 (+ipv6) initialized` | ✓ (ZC stack) |
| 0 SIGSEGV / panic / stub-called | ✓ |

### G3 — functional

| Item | Result |
|---|---|
| G3.2 single curl | HTTP 200 / Content-Length 438 / body = real HTML |
| G3.3 100× short-conn | ok=100/100 ✓ |
| primary clean exit after 1000+ conns | ✓ (SIGTERM within 5 s) |

### G4 — simple perf observation (OQ-2 default-allowed downgrade)

| build | 1000 short-conn time | Implied conn/s |
|---|---|---|
| M8 (ZC only) | 6.768s | ~148 |
| M9 (PA + ZC combo) | 23.65s | ~42 (incl. 1 timeout) |

**Observation**: under M9 combo, the 1000-conn time grows + occasional timeouts. Likely reasons:
1. The PA 256 MB mmap pool sharing mbufs with the ZC fast-path may delay cluster refcnt release under heavy short-conn load.
2. The test client is ssh-round-trip-dominated, but the same client measured M8 at only 6.7 s — the gap can't all be ssh.

Recorded as **F1 follow-up**: M9-followup-issue. Functionality PASS; the perf note sits inside OQ-2's allowed envelope.

### G5 — docs

`phase2-M9-spec.md` + `phase2-M9-execution-log.md`; docs anchor + Summary scope follow the M6/M7/M8 pattern.

### G6 — lint

0 errors.

### G7 — commit

Local English commit, no push.

---

## 4. Bounce Ledger

| # | Stage | Trigger | Fix |
|---|---|---|---|
| – | – | – | – |

**0 bounces**.

---

## 5. Known Leftovers / Follow-up

| ID | Description | Plan |
|---|---|---|
| **F1** (perf observation) | M9 combo 1000 short-conn 23.6 s vs M8 ZC-only 6.7 s (3.5× slowdown, occasional timeout) | Deferred to the Phase-5b methodology stage with wrk/iperf at high concurrency; this milestone only needs functional PASS |

---

## 6. Phase Progress

| Phase | Status |
|---|---|
| A. Spec | ✅ |
| B. Research | ✅ (folded into §1) |
| C. Code | ✅ (1-line Makefile) |
| D. Review | ✅ (self review, 0 lint) |
| E. Gate | ✅ G1-G3 + G6/G7 PASS; G4 observation only |

**M9 overall: ✅ PASS**
