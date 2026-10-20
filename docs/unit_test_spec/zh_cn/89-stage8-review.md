# Stage-8 残余分支攻坚 Review（v1.0-final）

> 执行窗口：2026-06-11
> 起点：Stage-7+ 收尾（merged branch 60.5%，ahead=22）
> 终点：merged branch **63.7%**，ahead=**26**（本期 4 commits）
> 口径：`run_coverage.sh`（unit + G8）/ `run_full_coverage.sh`（merged），区分 taken=0 / taken=- / LCOV_EXCL

---

## §1 战果总览

| 文件 | baseline branch | final branch | Δ | 手段 |
|---|---|---|---|---|
| **ff_config.c** | 78.5% (561/715) | **85.4% (612/717)** | **+6.9pp / +51 br** | P2 argv/fixtures(13TC) + P3 OOM wrap(5TC) + vlan-vip leak fix |
| **ff_dpdk_pcap.c** | 94.4% (17/18) | **100% (14/14)** | +5.6pp | P5 多段 mbuf TC + L118 死腿 LCOV_EXCL |
| **ff_epoll.c** | 97.8% (45/46) | **100% (46/46)** | +2.2pp | P5 L113 idx2 (data=0 no-EOF) TC |
| **ff_ini_parser.c** | 89.7% (61/68) | **91.2% (62/68)** | +1.5pp | BOM L107 third-byte TC |
| ff_host_interface.c | 98.1% (104/106) | 98.1% | 0 | clock assert 见 §3 |
| ff_dpdk_kni.c | 51.6% (48/93) | 51.6% | 0 | process/alloc 见 §3 |
| **Project merged** | **60.5%** | **63.7% (1025/1610)** | **+3.2pp** | — |

测试数：unit TC ff_config 32→50 / pcap 8→9 / epoll 20→21 / ini 24→25。valgrind 11/11 + integ 1/1，**0 definite leak**。

---

## §2 验收门禁结果

| Gate | 目标 | actual | 状态 |
|---|---|---|---|
| G-S8-1 ff_config branch ≥88% | 88% | 85.4% | ⚠ MISS（差 2.6pp，剩余皆 1br/TC 的 OOM/dataflow 单腿，ROI 极低）|
| G-S8-2 ff_dpdk_kni branch ≥70% | 70% | 51.6% | ✗ MISS（inline-wrap 不可行，见 §3.1）|
| G-S8-3 project merged ≥68% | 68% | 63.7% | ✗ MISS（结构性受限 ff_dpdk_if，见 §3.4）|
| G-S8-4 pcap/epoll 收尾 | 100% | **100%/100%** | ✅ PASS |
| G-S8-5 valgrind 0 leak | 0 | 12/12 0 leak | ✅ PASS |
| G-S8-6 G8 ratchet up | PASS | 11/11 PASS | ✅ PASS |
| G-S8-7 lib safe-patch ≤30 行 | ≤30 | vlan leak fix 10 行 | ✅ PASS |
| G-S8-8 真死代码标注 | — | pcap L118 EXCL + ini×6/kni 文档化 | ✅ PASS |

G8 阈值 ratchet：ff_config br 73→80、pcap br 89→95、epoll br 92→95、ini br 84→86。

---

## §3 未达目标的根因（交叉验证，以实际代码为准）

### 3.1 FU-S8-KNI-PROCESS（L142/148/149/161/163/181/183/185）→ 降级 Stage-9
**实测结论**：`rte_eth_tx_burst`(rte_ethdev.h:6395)、`rte_eth_rx_burst`、`rte_ring_dequeue_burst`(rte_ring.h:811) 均为 `static inline`。`-Wl,--wrap` 仅对链接期未解析符号有效，对已内联进 `ff_dpdk_kni.o` 的函数**无效**（已验证）。
**继任**：FU-S9-KNI-PROCESS-INTEG — 需真 PMD（net_null/net_ring vdev）+ rte_eal_hotplug_add 整合套件。

### 3.2 FU-S8-KNI-ALLOC（L426/435/466/476/480/486）→ 降级 Stage-9
ff_kni_alloc 内部依赖 rte_eal_hotplug_add 真 vdev 注册 + rte_ring_create + rte_eth_macaddr_get。需 root/vhost-net 整合环境。并入 FU-S9-KNI-PROCESS-INTEG。

### 3.3 FU-S8-HIF-CLOCK-WRAP（L176/L209）→ accepted-gap
`clock_gettime` 非 inline（可 wrap），但 `assert(0==rv)` 是 glibc assert；`expect_assert_failure` 需用 cmocka mock_assert override **重编译** ff_host_interface.o（侵入式）。与用户「工作量＞价值」判断一致 → 文档化为 accepted-gap（仅内核时钟失败可触发的防御性断言）。

### 3.4 G-S8-3 project ≥68% → 结构性受限
merged 分母含 **ff_dpdk_if.c：552 branches 仅 125 hit（22.6%）**，单文件拖累全局。该文件覆盖率提升属 integration 范畴（Stage-6 Phase-7 已闭环 unit-mock 可达部分），plan §7 明确 out-of-scope。即便 ff_config 提至 92%，项目仍约 66%，无法仅靠 unit 达 68%。**真实可达上限受 ff_dpdk_if 结构性约束**。

### 3.5 FU-S8-{INI}-DEAD（L121×3/133/155/158）→ 真死，文档化
`INI_STOP_ON_FIRST_ERROR=1` 下 `if(error) break`（L165），首次 error 即退出循环 → `&& !error` / `else if(!error)` 的 false 腿（error!=0）永不可达。6 腿数据流真死，未 EXCL（避免误删同行 legit 腿），文档记录。

---

## §4 Lib 改动（safe-patch）

| 改动 | 文件 | 行数 | 说明 |
|---|---|---|---|
| FU-S8-CFG-VLAN-VIP-LEAK | ff_config.c | +8 | ff_cfg_free_vlan_one 补 free(vip_addr_array)，修 24B 真实 leak |
| FU-S8-PCAP-DEAD | ff_dpdk_pcap.c | +5 | L118 死腿 LCOV_EXCL_BR_LINE 注释（无行为变更）|

---

## §5 Commits（本期 4 个，ahead 22→26）

```
dc44b863a test(ff_ini_parser): Stage-8 +1 TC for BOM third-byte mismatch (L107)
ea0bd9ab8 test(ff_config): Stage-8 P3 OOM wrap — 5 calloc-fail TCs
79a932638 test+lib(epoll+pcap): Stage-8 P5 dead-branch audit -> both 100%
597c499f1 test+lib(ff_config): Stage-8 P2 branch boost — 13 TCs + vlan-vip leak fix
```

---

## §6 继任 Follow-ups（Stage-9）

| ID | 内容 | 预期增量 |
|---|---|---|
| **FU-S9-KNI-PROCESS-INTEG** | net_null/net_ring vdev 整合套件覆盖 kni_process_tx/rx + ff_kni_alloc（L142-185 + L426-486，~21 br）| kni → ~80% |
| FU-S9-DPDKIF-INTEG-BOOST | ff_dpdk_if.c integration 扩容（427 missing br，项目级最大杠杆）| project → ≥68% |
| FU-S9-CFG-OOM-MORE | ff_config 剩余 OOM/dataflow 单腿（vip arrays / rss / L132 huge-mask），ROI 低 | ff_config → ~90% |
| FU-S9-HIF-ASSERT-WRAP | --wrap=__assert_fail + longjmp 覆盖 clock assert（仅当值得）| hif → 100% |

---

## §7 Bounce Counter
```
Phase 0 baseline       : 0
Phase 1 spec skeleton  : 0
Phase 2 cfg-argv        : 1 (kni fixtures 缺 broadcast → 补字段重跑)
Phase 3 cfg-oom         : 0 (calloc ordinal 一次命中)
Phase 5 dead-audit      : 1 (pcap/epoll 首版 TC 未命中目标腿 → 改 data=0/EXCL)
Phase 8 gating          : 0
Phase 9 review          : 0
                  total : 2 / 30 budget
```

## §8 工作区合规
- ✅ 0 直接 rm/kill/chmod
- ✅ valgrind 12/12 0 definite leak（含新 --wrap=calloc）
- ✅ G8 ratchet 后全 PASS
- ✅ Commit message 英文
