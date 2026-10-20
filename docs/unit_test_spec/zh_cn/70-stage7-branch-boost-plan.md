# Stage-7 Branch-Coverage Boost — Master Plan

| Field | Value |
|---|---|
| Plan ID | stage7-branch-coverage-boost |
| Version | v1.0-draft (Phase 1 skeleton) |
| Status | BUILDING |
| Author | unit-test-impl-leader (主 agent) |
| Bounce Counter | 0 / 3 (max-allowed per phase) |
| Last Updated | 2026-06-10 (Phase 1) |
| Local-only | YES (匹配 .gitignore `plan-*.md` 规则；最终若提交需重命名为 `plan-stage7-branch-boost.md`) |

---

## §1 Goals & Acceptance Gates

### 1.1 Top-level Goal

在 Stage-6 已闭环（merged branch 57.2%）的基础上，对 10 个已纳入 unit 测试集的 lib 文件**深挖异常与边界 case 的 branch 覆盖率**，配套必要的 lib safe-patch（含小重构），项目整体 branch ≥ 65%。

### 1.2 Acceptance Gates

| Gate | 描述 | 起点 | 目标 | 度量来源 |
|---|---|---|---|---|
| **G-CB-7-1** | merged project branch | 57.2% | **≥ 65%** | `tests/run_full_coverage.sh` |
| **G-CB-7-2** | per-headroom-file branch +10~15pp | 见 §3 | 见 §3 | `tests/unit/coverage_threshold.sh` |
| **G-CB-7-3** | 全部 unit + integration TC PASS | 142+8=150 | ≥ 175 | `make test` |
| **G-CB-7-4** | valgrind 0 definite leak（不依赖 supp）| 12/12 PASS | 12/12 PASS | `make check` (unit + integ) |
| **G-CB-7-5** | G8 阈值表 10/10 PASS（按 Stage-7 actual ratchet up）| 10/10 PASS | 10/10 PASS | `coverage_threshold.sh` |
| **G-CB-7-6** | lib safe-patch 单 commit ≤ 30 行 | n/a | enforced | `git diff --stat` |
| **G-CB-7-7** | 每个新 TC 可追溯到 71 gap 条目 | n/a | 1:1 | 71/72 cross-ref |

---

## §2 Per-File Targets

| 文件 | baseline branch | missing | Stage-7 目标 | Δbranches | 优先级 |
|---|---|---|---|---|---|
| **ff_config.c** | 75.18% (512/681) | **169** | **≥85% (~580/681)** | **+68** | **P0** |
| **ff_dpdk_kni.c** | 40.91% (36/88) | **52** | **≥55% (~49/88)** | **+13** | **P0** |
| ff_ini_parser.c | 83.82% (57/68) | 11 | ≥92% (63/68) | +6 | P1 |
| ff_epoll.c | 89.13% (41/46) | 5 | ≥95% (44/46) | +3 | P1 |
| ff_dpdk_pcap.c | 88.89% (16/18) | 2 | ≥95% (17/18) | +1 | P2 |
| ff_host_interface.c | 92.45% (98/106) | 8 | ≥95% (101/106) | +3 | P2 |
| ff_init.c | 100% | 0 | unchanged | 0 | capped |
| ff_log.c | 100% | 0 | unchanged | 0 | capped |
| ff_thread.c | 100% | 0 | unchanged | 0 | capped |
| ff_dpdk_if.c | 22.64% | 427 | unchanged (受 unit mock 限) | 0 | out-of-scope |
| **Σ headroom** | – | **247** | – | **+94 (min)** | – |

**+94 branches → 项目整体 +6.0pp → 57.2% + 6.0 = 63.2%**（仍未达 65% G-CB-7-1）

**ratchet-up plan**：ff_config 实际可冲到 90% (+102) + ff_dpdk_kni 冲到 65% (+21) → 总 +146 → 66.5% ≥ 65% ✓

---

## §3 Phase Schedule

| Phase | 内容 | 模式 | Owner | 验收 |
|---|---|---|---|---|
| **0** | baseline 实测 | sync | leader | merged branch=57.2% / valgrind 12/12 / git ahead=16 (✅ DONE) |
| **1** | spec 骨架落盘（本文档 + 71/72/79）| sync | leader | 4 篇 .md 创建 (← 当前) |
| **2** | async-team gap analysis | **async** | 4 analysts | 71 文档完整 / ≥40 gap 条目 |
| **3** | ff_config.c 实施 | sync | test-author + c-precision-surgery | branch 75→85%+ / +8~12 TC / commit |
| **4** | ff_ini_parser.c 实施 | sync | test-author + c-precision-surgery | branch 84→92%+ / +5~8 TC / commit |
| **5** | ff_dpdk_pcap + ff_epoll 双文件 | sync | test-author + c-precision-surgery | 各 branch ≥95% / +6~10 TC / commit |
| **6** | ff_dpdk_kni + ff_host_iface | sync | test-author + c-precision-surgery | kni 41→55%+ / host ≥95% / +6~10 TC / commit |
| **8** | 全套门禁 | sync | gatekeeper | G-CB-7-1..G-CB-7-7 全 PASS |
| **9** | review + EN mirror + commit | sync | leader | 79 review v1.0-final / 4 篇 EN 落 docs/unit_test_spec/ 根 |

（Phase 7 在原计划合并入 Phase 6，故无 Phase 7）

---

## §4 Agent Team Topology

```
                     ┌──────────────────────────┐
                     │   Stage-7 Leader (主)    │
                     │ 统筹 / 仲裁 / 失败回滚   │
                     └──────────┬───────────────┘
                                │
                ┌───────────────┼───────────────┐
                │ Phase 2 async │  Phase 3-7    │  Phase 8-9
                │   (并行)      │   (串行)      │   (串行)
                ▼               ▼               ▼
        ┌────────────┐    ┌────────────┐  ┌────────────┐
        │ analyst-   │    │ test-author│  │ gatekeeper │
        │ config     │    │ (leader)   │  │ (leader)   │
        ├────────────┤    ├────────────┤  ├────────────┤
        │ analyst-   │    │ c-precision│  │ EN mirror  │
        │ pcap-epoll │    │ -surgery   │  │            │
        ├────────────┤    ├────────────┤  └────────────┘
        │ analyst-   │    │ build-     │
        │ iniparser- │    │ runner     │
        │ kni        │    ├────────────┤
        ├────────────┤    │ coverage-  │
        │ analyst-   │    │ runner     │
        │ host-iface │    ├────────────┤
        └────────────┘    │ reviewer   │
                          └────────────┘
```

### 4.1 职责矩阵

| Agent | 阶段 | 模式 | 职责 |
|---|---|---|---|
| Leader (主) | 全局 | – | spec 骨架 / 调度 / 失败仲裁 / commit / EN mirror |
| analyst-config | P2 | async | ff_config.c branch gap → 71 文档 §A |
| analyst-pcap-epoll | P2 | async | ff_dpdk_pcap + ff_epoll → 71 §B+C |
| analyst-iniparser-kni | P2 | async | ff_ini_parser + ff_dpdk_kni → 71 §D+E |
| analyst-host-iface | P2 | async | ff_host_interface → 71 §F |
| code-explorer | P2-7 | sync subagent | gap 验证 / 函数实现深挖 |
| c-precision-surgery | P3-6 | sync skill | lib safe-patch 最小 diff 修改 |
| test-author (leader 自任) | P3-6 | sync inline | 写 TC + fixture + 注册 main runner |
| build-runner (leader 自任) | P3-6, P8 | sync inline | make clean && make test |
| coverage-runner (leader 自任) | P3-6, P8 | sync inline | run_coverage.sh + lcov 实测对照 71 |
| reviewer (leader 自任) | P3-6, P8 | sync inline | 4 维 review (assertions / boundary / mock / determinism) |
| gatekeeper (leader 自任) | P8 | sync inline | G-CB-7-1..G-CB-7-7 |

### 4.2 失败回滚 SOP

| 失败点 | 立即操作 | bounce 计数 |
|---|---|---|
| Build fail | reviewer 重审 TC + 修 → 重 build | +1 |
| Test fail | 检查断言粒度 / mock 缺失 → 修 → 重跑 | +1 |
| Coverage 未达 G-CB-7-2 | analyst 重出 gap 或扩展 lib safe-patch → 重做 | +1 |
| Valgrind fail | 优先排查新 lib patch → c-precision-surgery 二次修 | +1 |
| 同 phase bounce ≥ 3 | leader 升级到用户介入 | – |

---

## §5 Lib Safe-Patch Plan (Q4 扩展授权 ≤30 行 / commit)

### 5.1 候选 patch 清单（Phase 2 分析后细化）

| 文件 | 候选 patch | 行数预估 | 配套 TC |
|---|---|---|---|
| ff_config.c | vlan_cfg_handler / bond_cfg_handler / vdev_cfg_handler 的 free-before-strdup（Stage-6 仅修了 log.dir/filename/proc_type）| ~24 行（×4 处 ×6 行）| TC-S7-CFG-* |
| ff_config.c | port_cfg_handler 的 OOM 路径 / NULL guard | ~10 行 | TC-S7-CFG-* |
| ff_ini_parser.c | BOM (0xEF 0xBB 0xBF) 处理 / 全空白 line 跳过 | ~8 行 | TC-S7-INI-* |
| ff_dpdk_pcap.c | write 失败 fd 关闭 / save_path 长度上限 | ~6 行 | TC-S7-PCAP-* |
| ff_epoll.c | EBADF 早期返回 / fd 表满 | ~10 行 | TC-S7-EPOLL-* |
| ff_dpdk_kni.c | proto_filter NULL 入参 / 无效 port_id 边界 | ~12 行 | TC-S7-KNI-* |

**总计预估：~70 行 lib 改动，分 5~6 个 commit（每个 ≤30 行）**

### 5.2 重构候选（Q4 扩展授权）

仅当无法通过 ≤30 行 safe-patch 触达边界时启用。当前预估**不需要**进入扩展模式。

---

## §6 New Test Cases List

详见 `72-stage7-test-cases-and-acceptance.md`（Phase 1 同步落盘）。

预估总量：**+30~50 TC**，按 6 大边界分类（NULL / 0 / 最大值 / 越界 / 重复调用 / 错误返回路径）。命名规范：`test_<func>_<scenario>_<expected>`。

---

## §7 Risk & Rollback

| Risk | Likelihood | Mitigation |
|---|---|---|
| ff_config 复杂 INI corner case 难以模拟 | M | 复用 fixtures/ 现有 INI 模板 + 新增 minimal corner fixture |
| lib safe-patch 引入新 leak | L | 每 patch 配 valgrind 即时验证；G-CB-7-4 守护 |
| 跨文件改动相互影响 | L | sync 模式串行；每 phase 独立 commit |
| ff_dpdk_kni 41% → 55% 实际不可达 | M | 71 gap 分析阶段提前评估，必要时调降至 50% |
| async team 协调失败 | L | 4 个 analyst 互相隔离（不同文件），无依赖 |

---

## §8 Reproducibility Commands

```bash
# unit-only
cd /data/workspace/f-stack/tests/unit
make clean && make test
make clean && make check
make clean && ./run_coverage.sh

# integration-only
cd /data/workspace/f-stack/tests/integration
make clean && make test
make clean && make check

# merged
cd /data/workspace/f-stack/tests
./run_full_coverage.sh
```

---

## §9 Stage-6 Diff & Stage-8 Future Work

### 9.1 Stage-6 已完成（不重复）

- 10 文件 line/branch baseline 建立
- ff_dpdk_if integration（FU-CB-DPDKIF-INTEGRATION）
- ff_unload_config 引入（FU-S2-2-CFG-UNLOAD）
- ff_dpdk_if_send NULL guard（FU-CB-DPDKIF-NULLGUARD）

### 9.2 Stage-8 Out-of-Scope

- 新增未覆盖 lib 文件 unit 测试（ff_kern_* / ff_route / ff_lock 等）
- ff_dpdk_if integration 扩容
- CI 接入（GitHub/GitLab Actions）
- libFuzzer 接入

---

## §10 Bounce Counter

```
Phase 0 baseline       : 0 bounces
Phase 1 spec skeleton  : 0 bounces
Phase 2 gap analysis   : (pending)
Phase 3 ff_config      : (pending)
Phase 4 ff_ini_parser  : (pending)
Phase 5 pcap+epoll     : (pending)
Phase 6 kni+host_iface : (pending)
Phase 8 gating         : (pending)
Phase 9 review+mirror  : (pending)
```

EOF
