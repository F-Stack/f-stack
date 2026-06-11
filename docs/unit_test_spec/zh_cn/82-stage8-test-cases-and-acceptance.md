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
| G-S8-1 ff_config branch | ≥88% | - | - |
| G-S8-2 ff_dpdk_kni branch | ≥70% | - | - |
| G-S8-3 project merged branch | ≥68% | - | - |
| G-S8-5 valgrind | 0 leak | - | - |
