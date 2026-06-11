# Stage-8 Test Cases & Acceptance（执行时填充）

> TC 命名：`test_<func>_<scenario>_<expected>`（CMocka，参考 c-unittest-expert 方法论）
> 本文随各 Phase 落 TC 实测结果

## Phase 2 — FU-S8-CFG-ARGV-FIXTURES（待填）
## Phase 3 — FU-S8-CFG-OOM + KNI-OOM（待填）
## Phase 4 — FU-S8-KNI-PROCESS（待填）
## Phase 5 — FU-S8-DEAD-AUDIT（待填）
## Phase 6 — FU-S8-HIF-CLOCK-WRAP（待填）
## Phase 7 — FU-S8-KNI-ALLOC（待填/降级）

## Acceptance（执行后填实测）
| Gate | 目标 | actual | 状态 |
|---|---|---|---|
| G-S8-1 ff_config branch | ≥88% | 85.4% | ⚠ MISS（剩余 1br/TC OOM/dataflow）|
| G-S8-2 ff_dpdk_kni branch | ≥70% | 51.6% | ✗ MISS（inline-wrap 不可行→S9）|
| G-S8-3 project merged branch | ≥68% | 63.7% | ✗ MISS（ff_dpdk_if 结构性受限）|
| G-S8-4 pcap/epoll 收尾 | 100% | 100%/100% | ✅ PASS |
| G-S8-5 valgrind | 0 leak | 12/12 0 leak | ✅ PASS |

详见 89-stage8-review.md。
