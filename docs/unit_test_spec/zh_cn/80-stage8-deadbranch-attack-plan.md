# Stage-8 残余分支攻坚计划（FU-S7/S8 遗留事项）

> 状态：PLAN-READY
> 前置基线：Stage-7+ 收尾（ahead-of-upstream feature/1.26 = 22，merged branch 60.5%）
> 口径：单一权威 = `tests/unit/run_coverage.sh` → coverage.info（区分 taken=0 reachable vs taken=- dead）
> 防漂移：本文所有 missing 行号/数量均为 plan 阶段 lcov 实测（非估计）；执行后用同口径复测落 89-review

---

## §1 实测基线（本计划制定时 lcov 实测，纠正 Stage-7 review 的估计值）

各文件 missing 分为两类：
- **taken=0**（reached-not-taken）：代码块已执行但某分支方向未取 → **可补**（造数据/wrap）
- **taken=-**（dead）：整块从未执行 → 需 wrap/integration，或确认为真死代码

| 文件 | total br | hit | **taken=0（可补）** | **dead（需 wrap/integ）** | missing 合计 |
|---|---|---|---|---|---|
| **ff_config.c** | 715 | 561 | **130** | 24 | **154** |
| ff_dpdk_kni.c | 93 | 48 | **14** | **31** | 45 |
| ff_ini_parser.c | 68 | 61 | 7 | 0 | 7 |
| ff_host_interface.c | 106 | 104 | 2 | 0 | 2 |
| ff_dpdk_pcap.c | 18 | 17 | 1 | 0 | 1 |
| ff_epoll.c | 46 | 45 | 1 | 0 | 1 |

> ⚠ 纠偏：Stage-7 review 估 ff_config「~90 missing」，实测 **154**（130 reachable + 24 dead），headroom 比预估更大。

### 1.1 ff_config taken=0 行号热点（无需 wrap，造数据即可）

```
L64/82/86/96/99/103×2/106-121×N  → parse_lcore_mask 各位/进制/边界
L131/133/146×2/148×2/151/155/158/162  → lcore mask 解析分支
L175-215  → dpdk args / channel / promiscuous 等
L356  if(!res) return res          → 子 handler 失败回传
L360  if(portid_list==NULL)         → lcore_list 空
L390/417  else if(cur_vlan_cfg)     → vlan ctx 分流
L702  if(portid > max_portid)       → port id 上界
L724  if(cur->vip_addr_str)         → vip 已设
L1113 while(strtok_r ...)           → slave_port_list 多 token
L1271 strcasecmp(kni.method,"reject")→ kni method 校验三分支
L1331/1332/1336  lcore_list 去重     → for/if/!found
```

### 1.2 ff_config dead（24，多需 OOM wrap）
- strdup / calloc / malloc 返回 NULL 的 `if (X == NULL)` 错误分支（OOM 路径）

### 1.3 ff_dpdk_kni taken=0（14，部分需 OOM wrap）
```
L121  protocol_filter_ip 某 case
L334  switch(proto) default 流
L379  ff_kni_init process_type==PRIMARY
L383/394/402/410  rte_zmalloc==NULL → rte_exit（OOM，需 --wrap=rte_zmalloc）
L513  ff_kni_enqueue filter>=FILTER_ARP
L521×4/L522  rte_ring_enqueue ret<0（满环）
L529  error: process_type==PRIMARY
```

### 1.4 ff_dpdk_kni dead（31，需 wrap/integration）
```
[process_tx/rx — 需 --wrap=rte_eth_tx_burst/rx_burst + rte_ring_dequeue_burst]
L142×5  kni_process_tx rte_ring_dequeue_burst
L148×2/L149×2  kernel_packets_ratelimit 分支
L161×2/L163×2  nb_kni_tx<nb_tx tx_dropped
L181×2/L183×2/L185×2  kni_process_rx

[alloc — 需 rte_eal_hotplug_add 真 vdev / rte_ring_create]
L426×2/L435×2/L466×2/L476×2/L480×2/L486×2  ff_kni_alloc 内部
```

### 1.5 其余小文件 taken=0
```
ff_ini_parser  L107(BOM 第3字节) L121×3/L133/L155/L158(&&!error，STOP_ON_FIRST_ERROR 数据流约束)
ff_dpdk_pcap   L118  while(pkt!=NULL && out_len<=snap_len) 某腿（多段 mbuf）
ff_epoll       L113  if(kev->data || !(flags&EV_EOF)) 组合腿
ff_host_iface  L176/L209  assert(0==rv) clock_gettime 失败腿（需 --wrap=clock_gettime）
```

---

## §2 目标与验收门禁

| Gate | 内容 | 目标 |
|---|---|---|
| **G-S8-1** | ff_config.c branch | 78.5% → **≥88%**（补 ≥70 reachable）|
| **G-S8-2** | ff_dpdk_kni.c branch | 51.6% → **≥70%**（补 process_tx/rx + OOM，≥20 br）|
| **G-S8-3** | project merged branch | 60.5% → **≥68%** |
| **G-S8-4** | 小文件收尾 | ini ≥92% / pcap=100% / epoll=100% / hif≥99%（能补则补，dead 标注 LCOV_EXCL）|
| **G-S8-5** | valgrind | 全 binary 0 definite leak（含新 wrap）|
| **G-S8-6** | G8 ratchet | 各文件阈值 = actual − 5pp，仍 PASS |
| **G-S8-7** | lib safe-patch | 单 commit ≤30 行（如需）|
| **G-S8-8** | 真死代码 | 确认后用 `LCOV_EXCL_BR_LINE` 标注 + 文档记录原因 |

---

## §3 Phase Schedule（按 ROI 从高到低，逐步攻坚）

### Phase 0 — baseline 实测落盘（✅ 本 plan §1 已完成）

### Phase 1 — spec 骨架
落盘 `80-plan`（本文）/ `81-stage8-gap-detail.md` / `82-stage8-tc-list.md` / `89-stage8-review.md`

### Phase 2 — 【Tier-1 高 ROI】FU-S8-CFG-ARGV-FIXTURES（无 wrap）
- 目标：ff_config 130 reachable 中补 ~60-80（argv 组合 / fixture 变种 / lcore-RSS-kni 解析）
- 手段：纯 fixtures + argv 数组，零 wrap，零 lib 改动
- 子簇：
  - C1 parse_lcore_mask 全进制/全位（L64-162）
  - C2 dpdk args/channel/promiscuous/numa（L175-215）
  - C3 port/vlan handler 分流（L356/360/390/417/702/724）
  - C4 kni.method 三分支（L1271：accept/reject/默认）
  - C5 lcore_list 去重 + slave_port_list 多 token（L1113/1331/1332/1336）
- 验收：ff_config branch ≥85%；commit

### Phase 3 — 【Tier-2 OOM wrap】FU-S8-CFG-OOM + FU-S8-KNI-OOM
- 目标：ff_config 24 dead 中 OOM 分支 + KNI L383/394/402/410
- 手段：`--wrap=strdup` / `--wrap=calloc` / `--wrap=rte_zmalloc`（计数器控制第 N 次返回 NULL）
- 注意：rte_exit 已 wrap → mock_assert；OOM 后用 expect_assert / longjmp 验证
- 验收：ff_config branch ≥88%；KNI init OOM 覆盖；commit

### Phase 4 — 【Tier-3 burst wrap】FU-S8-KNI-PROCESS（用户点名）
- 目标：KNI dead L142/148/149/161/163（tx）+ L181/183/185（rx）= 13 dead → reachable
- 手段：`--wrap=rte_eth_tx_burst` / `--wrap=rte_eth_rx_burst` / `--wrap=rte_ring_dequeue_burst`
  - tx wrap 可返回 < 请求量 → 触发 `nb_kni_tx<nb_tx` tx_dropped 分支
  - 配 ff_global_cfg.kni.kernel_packets_ratelimit 触发 ratelimit 分支
- 测 ff_kni_process（含 enqueue L521 满环 ret<0）
- 验收：KNI branch ≥65%；commit

### Phase 5 — 【Tier-4 dead 审计】FU-S8-DEAD-AUDIT
- 逐个验证「假定 dead」是否真死：
  - **ini L121/133/155/158**：尝试 handler 返回 0 + 多行 → 确认 STOP_ON_FIRST_ERROR 是否真阻断；真死则 `LCOV_EXCL_BR_LINE`
  - **pcap L118**：构造 **多段 mbuf**（pkt->next 链）→ 大概率可补（非死）
  - **epoll L113**：构造 `kev->data=0 && !(flags&EV_EOF)` 组合 → 大概率可补
- 验收：pcap/epoll 能补则补到 100%；真死代码标注 + 89-review 记录

### Phase 6 — 【Tier-5 低 ROI 可选】FU-S8-HIF-CLOCK-WRAP
- 目标：HIF L176/L209 `assert(0==rv)` 失败腿
- 手段：`--wrap=clock_gettime` 返回 -1 + cmocka `expect_assert_failure`
- 风险：assert abort 流程 / mock_assert 集成；若 >2h 未通过则降级为 `LCOV_EXCL_BR_LINE` + 文档说明（用户已标「工作量＞价值」）
- 验收：HIF ≥99% 或 EXCL 标注；commit

### Phase 7 — 【Tier-6 最高成本，评估后决定本期/Stage-9】FU-S8-KNI-ALLOC
- 目标：KNI L426/435/466/476/480/486（ff_kni_alloc 内部）
- 手段两选一：
  - A. unit + `--wrap=rte_eal_hotplug_add` / `--wrap=rte_ring_create` / `--wrap=rte_eth_macaddr_get`（mock 全套，工作量大）
  - B. `tests/integration/test_ff_kni_integration.c`：真 DPDK + virtio_user vdev（需 root/vhost-net 权限，CI 不友好）
- 决策点：若 Phase 2-4 已达 G-S8-3（project ≥68%），本 Phase 可**降级为 Stage-9 follow-up**，避免低 ROI 投入
- 验收：达成则 KNI branch ≥80%；否则文档化为 FU-S9-KNI-ALLOC

### Phase 8 — 门禁全套
- make test + make check（valgrind）+ run_coverage + run_full_coverage + G8 ratchet + ahead 计数

### Phase 9 — review + commit + 阈值 ratchet
- 刷新 coverage_threshold.sh 旁注；写 89-review（actual 同口径复测 + bounce counter + 真死代码清单）

---

## §4 Agent Team 拓扑（混合模式，沿用 Stage-7 Q5-C）

- **分析阶段（并行）**：spawn code-explorer 扫 ff_config 130 reachable 聚类 + KNI wrap 可行性
- **实施阶段（串行）**：leader 逐 Phase 调 c-precision-surgery（lib safe-patch）+ c-unittest-expert 方法论（CMocka TC）
- **门禁**：build-runner → coverage-runner → reviewer → gatekeeper，任一失败打回上一 Phase

---

## §5 Wrap 基础设施扩展清单（Makefile）

现有：`BASE_WRAPS`（rte_exit/rte_panic）、`WRAP_FF_LOG`、`--wrap=exit/abort/ff_malloc`

本期新增（per-target，仅对应 test binary 生效）：
```makefile
WRAP_CFG_OOM   := -Wl,--wrap=strdup -Wl,--wrap=calloc
WRAP_KNI_OOM   := -Wl,--wrap=rte_zmalloc
WRAP_KNI_PROC  := -Wl,--wrap=rte_eth_tx_burst -Wl,--wrap=rte_eth_rx_burst \
                  -Wl,--wrap=rte_ring_dequeue_burst
WRAP_HIF_CLOCK := -Wl,--wrap=clock_gettime
```
> 注：rte_eth_*_burst / rte_ring_dequeue_burst 多为 **inline**，--wrap 可能失效；Phase 4 入场先验证可 wrap 性，若 inline 不可 wrap 则改 `-D` 测试钩子或 stub 重定义。

---

## §6 风险 & 回滚

| 风险 | 缓解 |
|---|---|
| inline 函数 --wrap 失效（rte_eth_*_burst）| Phase 4 入场先验证；失败则 fallback stub 重定义或降级 Stage-9 |
| OOM wrap 触发 rte_exit → 进程 abort | 用 cmocka expect_assert_failure + 已有 rte_exit→mock_assert wrap |
| clock_gettime wrap ROI 低 | Phase 6 设 2h 上限，超时降级 EXCL 标注 |
| lib safe-patch 引入新分母 | 每 patch 预估 denom 增量，控制单 commit ≤30 行 |
| KNI alloc 整合需 root | Phase 7 评估后可降级 Stage-9 |

---

## §7 Out-of-Scope（明确不做）
- ff_dpdk_if.c integration 扩容（Stage-6 已闭环）
- CI 接入 / libFuzzer（Stage-9+）
- 已 100% capped 文件（ff_log/thread/init）重写

---

## §8 Reproducibility
```bash
cd /data/workspace/f-stack/tests/unit && make clean && ./run_coverage.sh      # unit + G8
cd /data/workspace/f-stack/tests/unit && make check                            # valgrind
cd /data/workspace/f-stack/tests && ./run_full_coverage.sh                     # merged
```

---

## §9 Bounce Counter（执行时维护）
```
Phase 0 baseline       : 0
Phase 1 spec skeleton  : -
Phase 2 cfg-argv        : -
Phase 3 cfg/kni-oom     : -
Phase 4 kni-process     : -
Phase 5 dead-audit      : -
Phase 6 hif-clock       : -
Phase 7 kni-alloc       : -
Phase 8 gating          : -
Phase 9 review          : -
                  budget : 30
```
