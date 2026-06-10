# 99 — Stage-5 P3 Follow-ups Review

> 文档版本：v0.1（2026-06-10 11:15 UTC+8）
> Stage：Stage-5（P3 follow-up：FU-S4-KNI / FU-S4-DPDK-IF-FULL / FU-S4-PKTMBUF）
> 上一阶段：Stage-4 P2（HEAD `46227a0e0`，PASS）

---

## 0. 总评：**PASS**（BOUNCE 0/4）

| Gate | 检查 | 结果 |
|---|---|---|
| **G6d** | test_ff_dpdk_kni build & run（含 EAL `--no-huge` init） | ✅ 4/4 PASS |
| **G6e** | test_ff_dpdk_if 增 3 TC（ff_in_pcbladdr） | ✅ 10/10 PASS（含 1 处 spec-vs-code 修正：EADDRNOTAVAIL=99 非 49）|
| **G_FINAL** | 全套 `make test` 不退化 | ✅ **11 binaries / 90 TC / 5.19s 全 PASS** |

---

## 1. 三个 P3 Follow-up 处理结果

| Follow-up | 决策 | 实施 |
|---|---|---|
| **FU-S4-PKTMBUF** | DEFER to integration tests | ff_dpdk_pktmbuf_free 调 inline rte_pktmbuf_free_seg → 必须真 mempool；mempool 必须 EAL init + hugepages → 不适合 unit test。改建议在 helloworld/nginx 集成测试覆盖 |
| **FU-S4-KNI** | 实施（部分） | ff_kni_enqueue 限速逻辑 4 TC（ff_kni_init/alloc/process 仍 deferred 因需 KNI subsystem + virtio_user hotplug） |
| **FU-S4-DPDK-IF-FULL** | 实施（小子集） | ff_in_pcbladdr 3 TC（4 分支：no callback / AF_INET / AF_INET6_FREEBSD remap / unknown family） |

---

## 2. Phase 落地

### Phase 1 plan
- `plan-stage5-p3-followups.md`（local-only via .gitignore plan-*.md）

### Phase 2 — FU-S4-KNI（test_ff_dpdk_kni.c, 4 TC）
- TC-01 `test_ff_kni_enqueue_no_ratelimit`：限速=0 → enqueue 通过，ring 含 1 entry
- TC-02 `test_ff_kni_enqueue_console_ratelimit_over`：console_ratelimit=2 → 第 3 次 over → -1 + rx_dropped++
- TC-03 `test_ff_kni_enqueue_general_ratelimit_over`：general 路径同
- TC-04 `test_ff_kni_enqueue_filter_classification`：FILTER_ARP→console / FILTER_KNI→general 计数器分流

**关键技术**：`rte_eal_init(--no-huge --no-pci --no-shconf -m 32 --file-prefix=ff_kni_test)` 一次性 init EAL；创建真实 mempool 64 buf + ring 16 slot；wire kni_rp[0] / kni_stat[0]。EAL init 失败兜底（`SKIP_IF_NO_EAL` 宏全 4 TC skip）。

### Phase 3 — FU-S4-DPDK-IF-FULL（test_ff_dpdk_if.c +3 TC）
- TC-08 `test_ff_in_pcbladdr_no_callback`：pcblddr_fun=NULL → 0
- TC-09 `test_ff_in_pcbladdr_af_inet_dispatches`：family=AF_INET → callback 收到 (AF_INET, faddr, fport, laddr) 完全透传 + 返回值透传
- TC-10 `test_ff_in_pcbladdr_af_inet6_freebsd_to_linux_remap`：AF_INET6_FREEBSD(28) remap 到 AF_INET6_LINUX(10) + unknown family → 返回 EADDRNOTAVAIL

### Phase 4 — Review + commit（本阶段）

---

## 3. spec-vs-code 修正（DP-U-12）

| # | 位置 | 期望（plan）| 实际（代码）| 修正 |
|---|---|---|---|---|
| 1 | TC-10 unknown family 返回值 | `ff_EADDRNOTAVAIL` (49) | POSIX `EADDRNOTAVAIL` (99 on Linux glibc) | TC 改用 `EADDRNOTAVAIL` 宏 |

---

## 4. 工作区合规

- ✅ 0 直接 rm/kill/chmod
- ✅ make clean / coverage_clean 走 `rm_tmp_file.sh`
- ✅ 新 binary `test_ff_dpdk_kni` 已加 `.gitignore`

---

## 5. 累计 TC 数

| Stage | TC 数 |
|---|---|
| Stage-2（spec 基线 + P0/P1） | 59 |
| Stage-3（覆盖率 + 扩 5 TC） | 64 |
| Stage-4（P2 +19） | 83 |
| **Stage-5（P3 +7）** | **90** |

11 个 binaries / 总耗时 5.19s（< NFR-U-5 30s 阈值）。

---

## 6. 剩余 follow-up

| ID | 内容 | 优先级 | 建议 |
|---|---|---|---|
| **FU-S4-PKTMBUF** | ff_dpdk_pktmbuf_free（已 defer） | P4 | 集成测试覆盖 |
| **FU-S4-KNI-INIT-ALLOC-PROCESS** | ff_kni_init / ff_kni_alloc / ff_kni_process 测试（需 virtio_user hotplug） | P4 | 集成测试覆盖 |
| **FU-S4-DPDK-IF-OTHER** | ff_dpdk_if.c 其余 ~136 个 ff_* 函数（lcore_conf / rss_reta_size 全局依赖）| P4 | 集成测试覆盖 |
| **FU-U-5** | CI 集成 | P2 | 下一 stage 候选 |
| **FU-S2-1** | valgrind into make check | P3 | 下一 stage 候选 |
| **FU-U-7** | 4 篇 spec 英文翻译 | P3 | 人工审计后 |

---

## 7. 交付物

| 文件 | 行 | tracked |
|---|---|---|
| `tests/unit/test_ff_dpdk_kni.c` | 270 | ✅ new |
| `tests/unit/test_ff_dpdk_if.c` (modified) | +95 | ✅ |
| `tests/unit/Makefile` (modified) | +12 | ✅ |
| `.gitignore` (modified) | +1 | ✅ |
| `99-stage5-p3-review.md` (本文件) | ~120 | ✅ new |

---

**Stage-5 P3 follow-up PASS** — 进入 commit。
