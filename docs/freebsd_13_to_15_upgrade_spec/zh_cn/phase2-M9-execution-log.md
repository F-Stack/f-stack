# Phase-2 M9 Execution Log — PA + ZC combo (P1c)

> 状态：✅ PASS（所有 G1-G3 + G6/G7 全过；G4 性能 observation 显示 combo 下 1000 短连存在 timeout 偶发，记为 follow-up F1）
> 日期：2026-06-08
> 上游基础：M8 commit `add33a04a`

---

## 1. 摘要

`lib/Makefile` 同时启用 `FF_USE_PAGE_ARRAY=1` + `FF_ZC_SEND=1`，验证 M7+M8 两个独立功能在同一 build 下共存能力。**0 源码改动**，0 bounce，1 行 Makefile diff。

---

## 2. 改动清单

| 文件 | 改动 |
|---|---|
| `lib/Makefile` | line 46 `#FF_USE_PAGE_ARRAY=1` → `FF_USE_PAGE_ARRAY=1`（M8 已启用 ZC，本次仅启用 PA） |

**总计 1 文件 +1/-1**

---

## 3. Gate 实测结果

### G1 — 编译

| 子项 | 结果 |
|---|---|
| `lib/ make clean && make` | exit=0 / 0 errors / 57 warnings (= baseline) |
| `libfstack.a` | 6.55 MB（与 M7/M8 大致相同；增加的代码量在共享 .o 内） |
| `example/ make` | 3 binaries 全产出 |

### G2 — 主程序冒烟

| 子项 | 结果 |
|---|---|
| primary 起栈 12s ALIVE | ✓ |
| `ff_mmap_init mmap 65536 pages, 256 MB.` | ✓（PA active） |
| `tcp_bbr is now available` + `ipfw2 (+ipv6) initialized` | ✓（ZC stack）|
| 0 SIGSEGV / panic / stub-called | ✓ |

### G3 — 功能验收

| 子项 | 结果 |
|---|---|
| G3.2 单次 curl | HTTP 200 / Content-Length 438 / body = 真实 HTML |
| G3.3 100x 短连 | ok=100/100 ✓ |
| primary 1000+ 连接后干净退出 | ✓（SIGTERM 5s 内退出） |

### G4 — 简易性能 observation（OQ-2 默认许可降级）

| build | 1000 短连耗时 | 推算 conn/s |
|---|---|---|
| M8 (ZC only) | 6.768s | ~148 |
| M9 (PA + ZC combo) | 23.65s | ~42（含 1 次 timeout） |

**观察**：M9 combo 下 1000 短连耗时增大 + 偶发 timeout。可能原因：
1. PA 256 MB mmap 池与 ZC fast-path 共用 mbuf 时，cluster refcnt 释放路径在密集短连下偶发延迟
2. 测试客户端 ssh round-trip 主导 — 但同一客户端测 M8 仅 6.7s，差异不能完全归因 ssh

记为 **F1 follow-up**：M9-followup-issue。功能已 PASS，性能在 OQ-2 许可范围内。

### G5 — 文档

`phase2-M9-spec.md` + `phase2-M9-execution-log.md`；docs anchor + Summary scope 同 M6/M7/M8 模式。

### G6 — Lint

0 errors。

### G7 — Commit

本地英文 commit，不 push。

---

## 4. Bounce 计数

| # | 阶段 | 触发原因 | 修复 |
|---|---|---|---|
| – | – | – | – |

**0 bounces**。

---

## 5. 已知遗留 / Follow-up

| ID | 描述 | 计划 |
|---|---|---|
| **F1**（性能观察） | M9 combo 下 1000 短连 23.6s vs M8 ZC-only 6.7s（3.5x slowdown，偶发 timeout） | 推迟到 phase-5b 方法学复用阶段做 wrk/iperf 大并发剖析；本里程碑功能 PASS 即可 |

---

## 6. Phase 进度

| Phase | 状态 |
|---|---|
| A. Spec | ✅ |
| B. Research | ✅（合并入 §1） |
| C. Code | ✅（1 行 Makefile） |
| D. Review | ✅（self review，0 lint） |
| E. Gate | ✅ G1-G3 + G6/G7 PASS；G4 observation only |

**M9 整体：✅ PASS**
