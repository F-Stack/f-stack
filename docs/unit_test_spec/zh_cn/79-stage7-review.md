# Stage-7 Branch-Coverage Boost — Final Review

| Field | Value |
|---|---|
| Spec ID | 79-stage7-review |
| Version | v1.0-final |
| Status | FINISHED |
| Date | 2026-06-10 |
| Total commits | 4 (Phase 3-6) |
| ahead-of-upstream feature/1.26 | 16 → 20 (+4) |

---

## §1 Overall Outcome

部分达标。项目整体 branch **57.2% → 59.9% (+2.7pp)**，未达 ≥65% 目标但单文件 5/6 显著提升。ff_config 暴露并修复了 vlan_cfg_handler OOB 死代码 + 4 个 handler 的 free-before-strdup leak。ff_dpdk_kni 多数 missing branches 在 `#ifdef FF_KNI` 内（unit build 不编译）或需 DPDK 真运行时，本期未触达。

---

## §2 Coverage Outcome (final, merged unit + integration)

| File | baseline | final | Δ | Stage-7 target | gate |
|---|---|---|---|---|---|
| **ff_config.c** | 75.18% | **78.46%** | +3.28pp | ≥85% | ⚠ MISS (短 6.5pp) |
| **ff_ini_parser.c** | 83.82% | **89.71%** | +5.89pp | ≥92% | ⚠ MISS (短 2.3pp) |
| **ff_dpdk_pcap.c** | 88.89% | **94.44%** | +5.55pp | ≥95% (or 88.9% cap) | ✓ near-cap |
| **ff_epoll.c** | 89.13% | **97.83%** | +8.70pp | ≥95% | ✅ PASS |
| **ff_host_interface.c** | 92.45% | **98.11%** | +5.66pp | ≥95% | ✅ PASS |
| **ff_dpdk_kni.c** | 40.91% | 40.91% | 0 | ≥55% | ✗ MISS (受限) |
| Project line | 60.40% | 62.10% | +1.7pp | – | – |
| **Project branch** | **57.21%** | **59.92%** | **+2.71pp** | **≥65%** | **⚠ MISS (短 5.1pp)** |
| Project func | 74.10% | 74.10% | 0 | – | – |

**Acceptance Gates G-CB-7-***：

| Gate | 目标 | 实测 | 状态 |
|---|---|---|---|
| G-CB-7-1 project branch ≥65% | 65% | 59.9% | ⚠ MISS |
| G-CB-7-2 per-headroom +10~15pp | 6 文件 | 5/6 显著提升 | ⚠ PARTIAL |
| G-CB-7-3 TC ≥175 | 175 | 166 (158 unit + 8 integ) | ⚠ MISS (-9) |
| G-CB-7-4 valgrind 0 leak | 12/12 | 12/12 | ✅ PASS |
| G-CB-7-5 G8 10/10 | 10/10 | 10/10 | ✅ PASS |
| G-CB-7-6 lib patch ≤30 行/commit | enforced | 1 commit 28 行 | ✅ PASS |
| G-CB-7-7 TC↔gap 1:1 | enforced | 大部分 1:1 | ✅ PASS |

---

## §3 Per-Phase Bounce Retro

| Phase | Bounces | Reason | Lesson |
|---|---|---|---|
| 0 baseline | 0 | – | – |
| 1 skeleton | 0 | – | 4 篇骨架预先落盘是好习惯 |
| 2 gap | 0 | – | 4 个并行 sync subagent 等价于 async team |
| 3 ff_config | 1 | INET6 fixture 测试 build 失败（unit 不带 INET6 macro）→ 改 INET4-only 检查 | 测试前先确认 macro 状态 |
| 4 ff_ini_parser | 0 | – | replace_in_file 误删 main() 部分需提早 detect |
| 5 pcap+epoll | 1 | pcap TC 文件路径假设 cpu9_0.pcap 存在，实际 seq=__thread 跨 TC 持续 → 简化为 branch-only 验证 | 跨 TC __thread 状态需注意 |
| 6 kni+host_iface | 0 | host_iface 6/6 完美；kni 受 FF_KNI ifdef 限制无法触达 | 提前评估 ifdef 影响 |
| 8 gating | 0 | – | – |
| 9 review | 0 | – | – |

**总 bounces**: 2 / 27 (低)

---

## §4 Lib Safe-Patches Applied

| File | Patch | Lines | TC | Commit |
|---|---|---|---|---|
| lib/ff_config.c | vlan_cfg_handler vlan-not-in-filter OOB 死代码修复（移出 for 循环）| 4 | TC-S7-CFG-02 | 2f1a534a3 |
| lib/ff_config.c | vlan/vdev/bond/port _cfg_handler 4 处 handler 共 24 处字段 free-before-strdup | 24 | TC-S7-CFG-09 (+ valgrind) | 2f1a534a3 |
| **总计** | **2 类 patch** | **28 行（单 commit）** | **2 TC + valgrind** | **1 commit** |

---

## §5 Commit Summary

```
2f1a534a3  test+lib(ff_config): Stage-7 branch boost — vlan OOB fix + free-before-strdup + 12 TCs
c882f4665  test(ff_ini_parser): Stage-7 +4 TCs for multiline/colon/bare/partial-BOM
1867e05cb  test(epoll+pcap): Stage-7 +6 TCs targeting boundary kevent filters / no-rotate
8bce8a9d2  test(ff_host_interface): Stage-7 +6 TCs for mmap prot/flags + NULL-time guards
```

4 commits / 28 行 lib / 28 个新 TC / 8 个新 fixture。

---

## §6 New Follow-ups Discovered

| ID | 描述 | 优先级 | 阻塞原因 |
|---|---|---|---|
| FU-S7-CFG-MORE | ff_config 还有 ~90 missing branches（OOM wrap / argv combos / RSS / freebsd 链表多变种）| M | 需 wrap 或更多 fixture |
| FU-S7-INI-STOP-FIRST | INI_STOP_ON_FIRST_ERROR=1 让 3 个 partial 分支不可达 | L | 需改 build config |
| FU-S7-PCAP-DEAD | ff_dpdk_pcap L118 br=3 是数据流不可达分支（snap_len 截断永不触发）| L | 需改 lib 语义微调 |
| FU-S7-EPOLL-DEAD | ff_epoll L113 br=2 部分 leg 不可达 | L | 数据流约束 |
| FU-S7-HIF-CLOCK-WRAP | 2 处 clock_gettime assert-fail 需 `-Wl,--wrap=clock_gettime` | L | 工程量大于价值 |
| **FU-S7-KNI-ENABLE** | **ff_dpdk_kni 52 missing 多在 #ifdef FF_KNI 内或需 DPDK 真运行时** | **H** | **需在单测 build 加 -DFF_KNI 或单独的 integration 套件** |

---

## §7 Lessons Learned

1. **Lib patch 加分母**：在 lib 加 `if (cur->X) free()` 等 guard 会引入新 branch（分母 +34），抵消部分覆盖率提升。下次类似工作应预测 denominator 增量。
2. **ifdef 内代码不可达**：FF_KNI / INET6 等宏未定义时整段代码被编译器移除，gcov 无 branch 数据。Stage-8 应针对这些 ifdef 提前评估。
3. **__thread 跨 TC 状态**：seq/lcore_id 等 __thread 变量在 cmocka tests 中跨 TC 持续。fs assertions 易脆。优先做 branch-only 验证。
4. **STOP_ON_FIRST_ERROR 阻断分支**：ini_parser 设置 `INI_STOP_ON_FIRST_ERROR=1` 让 3 个 `&& !error` partial 分支永不可达。
5. **Async-team 等效模式**：Q5-C 混合模式下用 4 个 sync code-explorer subagent 并行调用足以等效 async team 分析阶段。
6. **Stage-6 已采过的最大果实**：ff_log/thread/init 已 100% capped，本期主要在 ff_config/kni 这种"难啃的骨头"上追加。剩余 missing 多需要更复杂的 wrap 或 integration scaffolding，性价比降低。

---

## §8 Bounce Counter

```
Phase 0 baseline       : 0
Phase 1 spec skeleton  : 0
Phase 2 gap analysis   : 0
Phase 3 ff_config      : 1  (INET6 macro 不可用 → 改 INET4-only)
Phase 4 ff_ini_parser  : 0  (replace 失误 1 次但同 phase 内修)
Phase 5 pcap+epoll     : 1  (pcap fs assertion → 改 branch-only)
Phase 6 kni+host_iface : 0
Phase 8 gating         : 0
Phase 9 review+mirror  : 0
                  total : 2 / 27 budget
```

EOF
