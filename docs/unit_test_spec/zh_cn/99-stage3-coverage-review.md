# 99 — Stage-3 覆盖率集成评审报告

> 文档版本：v0.1（2026-06-09 20:25 UTC+8）
> Stage：Stage-3 覆盖率集成（FU-U-6 / G8 验收）
> 评审者：reviewer + gate-keeper（Stage-3 sub-agent team）
> 上游：Stage-2 实施评审（HEAD `8a3f0e8f6`，BOUNCE 0/3，PASS）

---

## 0. 总评结论：**PASS**（BOUNCE 累计 1/4）

| Gate | 检查项 | 结果 | 备注 |
|---|---|---|---|
| **G6c build** | `make coverage` 编译 + 运行 + 收 .gcda exit=0 | ✅ PASS | 13 个 .gcda（5 lib + 6 test + 2 common）|
| **G8 thresholds** | 5 文件 line/branch 全 ≥ spec 06 §6.1 阈值 | ✅ PASS | **5/5 PASS**，详 §3 |
| **G_REP report** | `coverage_report/index.html` 可读 + 含 5 文件 | ✅ PASS | genhtml 2.0 输出，含 branch 列 |
| **G_REGRESS** | 非 coverage 模式 `make test` 仍全 PASS | ✅ PASS | 64 TC = 63 PASS + 1 SKIP（同 Stage-2 SKIP）|

**BOUNCE = 1/4**：G8 第一次实测时 ff_host_interface.c (27%) 和 ff_config.c (47.6%) 未达阈值，回 Phase 4 加 5 个 TC + 1 个 fixture 后第二次实测全过。

---

## 1. 实施流程合规性

| Phase | 状态 | 关键产物 |
|---|---|---|
| Phase 1 plan-stage3-coverage.md | ✅ DONE | 140 行（local-only via .gitignore plan-*.md 新规则）|
| Phase 2 Makefile 扩展 + threshold script | ✅ DONE | +60 行 Makefile / 110 行 awk threshold |
| Phase 3 跑 make coverage 实测 | ✅ DONE | 第一次 G8 FAIL → BOUNCE+1 |
| Phase 4 加 TC + fixture（修复 BOUNCE）| ✅ DONE | +4 TC HIF / +1 TC CFG / +1 fixture |
| Phase 5 重跑 G8 + review + commit | ✅ DONE（本报告）| — |

---

## 2. 实测覆盖率结果（spec 06 §6.1 表格 vs 实测）

| 文件 | 优先级 | line 阈 | line 实测 | line ✓ | branch 阈 | branch 实测 | branch ✓ |
|---|---|---|---|---|---|---|---|
| **ff_log.c** | P0 | ≥80% | **100.0%** (30/30) | ✅ +20pp | ≥70% | **100.0%** (4/4) | ✅ +30pp |
| **ff_ini_parser.c** | P0 | ≥80% | **94.5%** (69/73) | ✅ +14.5pp | ≥70% | 80.3% (53/66) | ✅ +10.3pp |
| **ff_host_interface.c** | P1 | ≥60% | **92.8%** (141/152) | ✅ +32.8pp | ≥50% | 88.7% (94/106) | ✅ +38.7pp |
| **ff_epoll.c** | P1 | ≥60% | 75.4% (46/61) | ✅ +15.4pp | ≥50% | 54.3% (25/46) | ✅ +4.3pp |
| **ff_config.c** | P1 | ≥50% | 59.5% (434/729) | ✅ +9.5pp | ≥40% | 60.3% (326/541) | ✅ +20.3pp |

**Project 总体**：lines 68.9% (720/1045) / branches 65.8% (502/763) / functions 91.7% (55/60)。

---

## 3. BOUNCE 修复明细

### 3.1 第一次 G8 实测（FAIL → BOUNCE+1）

| 文件 | line | 阈值 | 差距 | 根因 |
|---|---|---|---|---|
| ff_host_interface.c | 27.0% | 60% | -33.0pp | `ff_os_errno` switch 60+ case 仅测 5 个；多个其他 API（mmap/munmap/clock_gettime_ns/setenv/getenv/arc4random）未测 |
| ff_config.c | 47.6% | 50% | -2.4pp | 多个 ini section（[freebsd.*] / [pcap] / [vdev] / [bond] / [kni] 等）未测 |

P0 全部一次过（94.5% 和 100%），P1 ff_epoll 也一次过（75.4%）。

### 3.2 修复改动

**`test_ff_host_interface.c`**（+4 TC，从 8 → 12 TC）：
- `test_ff_os_errno_mapping`：5 cases → 完整 60+ cases 表驱动测试
- `test_ff_clock_gettime_ns_advances`（new）
- `test_ff_arc4random_distribution`（new）
- `test_ff_setenv_getenv_roundtrip`（new）
- `test_ff_mmap_munmap_roundtrip`（new）
- 注：`ff_get_tsc_ns` 未实测（impl 在 ff_dpdk_if.c，超 host scope；FU-S3-TSC 标记）

**`test_ff_config.c`**（+1 TC，从 11 → 12 TC）：
- `test_ff_load_config_all_sections`（new）：含 `valid_all_sections.ini` fixture，覆盖 [freebsd.boot] / [freebsd.sysctl] / [vdev0] / [pcap] / 完整 [kni] / [vlan0] 等多 section

**新增 fixture**：`fixtures/valid_all_sections.ini`（55 行，覆盖全部支持的 section）

### 3.3 第二次 G8 实测（PASS）

| 文件 | line（修后）| 提升 | branch（修后）| 提升 |
|---|---|---|---|---|
| ff_host_interface.c | 27% → **92.8%** | **+65.8pp** | 10.4% → 88.7% | +78.3pp |
| ff_config.c | 47.6% → **59.5%** | **+11.9pp** | 48.8% → 60.3% | +11.5pp |
| 总 lines | 51% → **68.9%** | +17.9pp | 46.8% → 65.8% | +19pp |

---

## 4. lcov 2.0 集成关键技术决策

| 项 | 决策 | 理由 |
|---|---|---|
| 工具版本 | lcov 2.0-2.oc9（dnf install）| EPOL 仓库就位；branch coverage 需 `--rc branch_coverage=1` |
| `lcov --capture` | `--directory lib_objs --directory .` | 收集 lib/*.o + test*/*.o 全部 .gcda |
| Strip 排除路径 | `/usr/* */cmocka.h */tests/unit/test_*.c */tests/unit/common/*` | 排除 system / cmocka / 测试代码自身（only lib/ measured）|
| Branch coverage 开启 | `--rc branch_coverage=1` 三处（capture / remove / genhtml --branch-coverage）| lcov 2.0 默认关 branch |
| Threshold 解析 | 自实现 awk（解析 SF/LF/LH/BRF/BRH） | lcov 2.0 `--list` 输出格式与 1.x 不同；自己解析最稳 |
| Make clean | 内置走 `coverage_clean` + `rm_tmp_file.sh` 三层调用 | NFR-U-7 zero-tolerance |

---

## 5. 12 处 cross-check（reviewer）

| # | 检查项 | 实测命令 | 期望 | 实测 | 结果 |
|---|---|---|---|---|---|
| 1 | lcov 工具版本 | `lcov --version` | ≥ 2.0 | 2.0-1 | ✅ |
| 2 | gcov 工具版本 | `gcov --version` | ≥ 12 | 12.3.1 | ✅ |
| 3 | .gcda 产出文件数 | `find . -name '*.gcda'` | ≥ 12 | 13 | ✅ |
| 4 | .gcno 产出文件数 | `find . -name '*.gcno'` | ≥ 12 | 13 | ✅ |
| 5 | coverage.info 大小 | `wc -l coverage.info` | ≥ 1000 行 | ~1900 | ✅ |
| 6 | HTML report `index.html` | `ls coverage_report/index.html` | exists | exists | ✅ |
| 7 | P0 ff_log.c line 100% 不退化 | threshold output | 100% | 100% | ✅ |
| 8 | P0 ff_ini_parser.c line ≥80% | threshold output | ≥80% | 94.5% | ✅ |
| 9 | P1 全 3 文件 line ≥阈值 | threshold output | 3/3 | 3/3（92.8 / 75.4 / 59.5）| ✅ |
| 10 | branch coverage data 实存在 | `lcov --summary` | "branches" 行非空 | 65.8% (502/763) | ✅ |
| 11 | non-coverage `make test` 不退化 | `make clean && make test` | exit=0 | 63 PASS + 1 SKIP | ✅ |
| 12 | 0 直接 rm/kill/chmod in Stage-3 改动 | grep 新增脚本 + Makefile | 0 | 0 | ✅ |

**Cross-check 12/12 = 100%**。

---

## 6. 4 维评分

| 维度 | 评分 | 依据 |
|---|---|---|
| **一致性** | **A** | 5 个 P0/P1 全文件按 spec 06 §6.1 阈值实测 + 文档化；threshold 脚本与 spec 表 1:1 对应 |
| **完整性** | **A** | 工具链（gcov + lcov 2.0 + genhtml）全接 + threshold 自动校验 + clean 链路；Makefile help 更新；HTML 报告可读 |
| **风险覆盖度** | **A** | R-S3-1..5 全 mitigation 落地（lcov 版本 / branch 默认关 / `--ignore-errors` / coverage_clean wrapper）|
| **可执行性** | **A** | `make coverage` 一键；G8 自动校验；CI 接入仅需复用此 target |

**4 维全 A**，PASS，无 Must-Fix。

---

## 7. 工作区合规

- ✅ 0 直接 rm/kill/chmod（chmod_modify.sh 用于 coverage_threshold.sh +x；rm_tmp_file.sh 用于 coverage_clean）
- ✅ make clean 链路新增 coverage_clean，仍 100% 走 wrapper（13 .gcda + 13 .gcno + coverage.info + coverage_report/ 全 trash）
- ✅ chmod 用 wrapper：`/data/workspace/chmod_modify.sh +x ...sh` 实测 `644 → 755`，snapshot 落 .trash

---

## 8. 已知未达 100% 项 + Follow-up

| ID | 项 | 当前 | 目标 | 优先级 | 备注 |
|---|---|---|---|---|---|
| **FU-S3-TSC** | ff_get_tsc_ns 未测（impl 在 ff_dpdk_if.c）| skip | 测试 | P3 | 等 P2 stage（FU-U-4）顺带实施 |
| **FU-S3-EPOLL-BR** | ff_epoll branch 54.3% / 阈 50% 离 P0 阈值 70% 还远 | 54.3% | 70%（如升 P0）| P3 | 当前满足 P1 阈值 |
| **FU-S3-CFG-BR** | ff_config.c 还有 40.5% line 未覆盖（DPDK arg 拼接 / port port-list 多 port 路径）| 59.5% | 80%（升 P0 时）| P3 | 端到端 fixture 难触达 dpdk_args_setup 内部 |
| **FU-S2-NULLFILE** | (Stage-2 旧) NULL FILE\* SKIP TC | skip | passing | P2 | 需 lib/ patch |

---

## 9. 最终交付物（Stage-3 commit 范围）

| 文件 | 行数 | tracked |
|---|---|---|
| `tests/unit/Makefile` (modified) | +60 | ✅（已 tracked，git diff）|
| `tests/unit/coverage_threshold.sh` | 110 | ✅（new, +x via chmod_modify.sh）|
| `tests/unit/test_ff_host_interface.c` (modified) | +130 | ✅（+4 TC + errno 完整表）|
| `tests/unit/test_ff_config.c` (modified) | +30 | ✅（+1 TC）|
| `tests/unit/fixtures/valid_all_sections.ini` | 55 | ✅（new）|
| `.gitignore` (modified) | +10 | ✅（新增 path-scoped plan-*.md + coverage 产物）|
| `docs/unit_test_spec/zh_cn/99-stage3-coverage-review.md` | ~250 | ✅（本文件）|

**~6 跟踪文件 modified/new + ~+545 lines staged**。

---

## 10. 评审签名

| 角色 | 名称 | 签名时间 |
|---|---|---|
| reviewer | Stage-3 审查角色 | 2026-06-09 20:25 UTC+8 |
| gate-keeper | Stage-3 终审 | 2026-06-09 20:25 UTC+8 |

**Stage-3 覆盖率集成 PASS（BOUNCE 1/4），进入 commit 阶段**。

---

**文档结束（v0.1，220 行）**
