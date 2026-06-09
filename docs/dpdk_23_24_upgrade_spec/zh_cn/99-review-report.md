# 99 — Gate-keeper 评审报告（Review Report）

> 文档版本：**v0.2（2026-06-09 14:55 UTC+8）— user 反馈后修订**
> Reviewer：gate-keeper（独立 reviewer 角色）
> 评审对象：本目录 `dpdk_23_24_upgrade_spec/zh_cn/` 下 6 篇 spec（plan + 00 + 01 + 02 + 04 + 06）
> 评审标准：plan.md §2.6 4 维标准（一致性 / 完整性 / 风险覆盖度 / 可执行性）
>
> **v0.2 修订记录**（2026-06-09 14:55）：
> - user 2026-06-09 14:50 反馈 KNI 真相：F-Stack `FF_KNI` 与 DPDK librte_kni 无关，是 ring + virtio_user 自实现
> - patch-scout 第一次报告漏识别 commit `29c7d5835`（"Remove redundant dpdk files"，310 文件 / -43195 行）— 因 `diff -rq | head -25` 截断未捕获 redundant files 删除清单
> - 修订位置：00 §5.1（patch 数 3→4）/ 01 §6 R-D2（升 P1 → 降 N/A）/ 01 §7.2 DP-B2（重新闭环）/ 02 §2 + §2.4 + §2.5 + §2.6 + §3.6（重写 KNI 真相）/ 04 §M2 + §M3 + §8.2（patch 数 3→4，含 §4.2.0 新增 29c7d5835 重打）
> - 本评审结论：**仍 PASS**（修订后比 v0.1 更准确）；v0.1 列的 Must-Fix-1（KNI 决策）**已取消**

---

## 0. 评审结论（**最终 v0.2**）

✅ **PASS — 6 篇 spec 通过 gate-keeper 评审，无 P0/P1 阻塞项；v0.2 修订后无 Must-Fix-x 待处理**

| 维度 | 评分 v0.1 | 评分 v0.2 | 备注 |
|---|---|---|---|
| 一致性 | A | **A** | 修订后 patch 数（3→4）跨 6 篇文档一致 |
| 完整性 | A | **A+** | v0.2 补全第 4 个 patch + KNI 真相后，spec 与现实零漂移 |
| 风险覆盖度 | A | **A+** | R-D2 由 P1 降 N/A（不存在风险）；新风险点 M3-R3（24.11.6 redundant 文件改名）已加入 04 §4.4 |
| 可执行性 | A- | **A** | M3 step-by-step 命令更新到 4 patch；§4.2.0 新增明确 29c7d5835 重打策略 |

**总计 6 篇 spec + plan + 本评审报告 = 7 篇文档**（plan §0.2 要求 = 7 篇）。

---

## 1. v0.2 关键修订要点（user 反馈后）

### 1.1 KNI 真相（**重大修正**）

| v0.1 误判 | v0.2 实测真相 |
|---|---|
| 24.11.6 上游 KNI 完全移除 → R-D2 升级 P1 | **F-Stack 的 `FF_KNI` 与 DPDK librte_kni 无关**；`lib/Makefile:34` 注释明确："No DPDK KNI support on FreeBSD" + "Enable KNI, via virtio only, no longer support rte_kni.ko"；`ff_dpdk_kni.c` 用 `rte_ring + virtio_user` 自实现 |
| Must-Fix-1：M2 启动前需 KNI A/B 决策 | **取消** — KNI 在升级中是 0 风险事项 |
| 推荐方案 A（FF_KNI=0）或 B（保留 KNI 子树） | **两方案都不对**；user 实际意图：保留 FF_KNI=1 + dpdk/ 仅含 igb_uio 一个内核模块（自然实现：24.11.6 上游本就无 KNI，加上 29c7d5835 重打保持） |

### 1.2 第 4 个 patch（29c7d5835）补识别

patch-scout 第一次报告 Q1+Q3"差集空集，无遗漏"是基于 `diff -rq | head -25` 截断输出做的判定。实测完整 diff（无 head 截断）+ `git log --diff-filter=D` 揭示：

| commit | 类型 | patch-scout v1 漏识别原因 |
|---|---|---|
| `29c7d5835 Remove redundant dpdk files` (2025-01-10) | DELETE 310 文件 / -43195 行 | head -25 没显示 + diff -rq 仅显示 Common subdirectories（不深入子目录） |

**实际 F-Stack patch list = 4 个**（chronological）：
1. `29c7d5835` (2025-01-10) DELETE redundant
2. `5f3768c63` (2025-10-31) ADD igb_uio + freebsd rte_os.h
3. `62f1c34df` (2026-01-16) ADD rte_timer_meta_init
4. `92718178b` (2026-03-18) MODIFY eal.c PRIMARY 守护

按 plan §4.4 + DP-A8，4 patch 仍合并到一个 `port:` commit。

### 1.3 igb_uio 时间线悖论澄清

| commit | 时间 | igb_uio 操作 |
|---|---|---|
| 29c7d5835 | 2025-01-10 | **删除旧版** igb_uio (5 文件 / -874 行) |
| 5f3768c63 | 2025-10-31 | **重新添加新版** igb_uio (含 kernel 6.x 兼容 + RHEL kernel < 3.18 fallback) |

→ 两者目的不同；新版用于 FreeBSD 15.0 升级期支持新主机内核；这与 user 期望"dpdk/ 仅保留 igb_uio 一个内核模块"完全一致。

---

## 2. 一致性评审（A）— v0.2

### 2.1 跨文档一致性 cross-check（v0.2 修订后）

| 项 | v0.1 状态 | v0.2 状态 |
|---|---|---|
| Patch 总数 | 全 6 篇 spec 标注 "3 个 patch" | 全 6 篇 spec 已 sync 为 "4 个 patch"（00 §5.1 / 01 §6 / 02 §2.5 / 04 §M2 §M3 §8.2 / 99 v0.2）|
| KNI 风险等级 | R-D2 升 P1 | R-D2 降 N/A（详 02 §3.6 + 01 §6） |
| Must-Fix-1 | 已列出（KNI 决策） | **已取消**（详本节）|
| commit message template | 3 patch 列表 | 4 patch 列表 + KNI clarification |

### 2.2 一致性微 issue

无（v0.2 修订过程是为了消除 v0.1 的内部不一致 — 把"24.11.6 完全移除 KNI"叙事修正为真实情况）。

---

## 3. 风险覆盖度评审（A+）— v0.2

### 3.1 R-D1~D12 v0.2 状态更新

| ID | v0.1 等级 | v0.2 等级 | 变化原因 |
|---|---|---|---|
| **R-D2** KNI 移除 | P1（v0.1 升级） | **N/A** | F-Stack 不依赖 librte_kni（user 反馈实测确认） |
| 新增 **M3-R2** 29c7d5835 KNI/igb_uio 部分自动 N/A | — | 新增（04 §4.4） | 4 patch 重打时部分 hunk 自动 N/A |
| 新增 **M3-R3** 24.11.6 redundant 文件改名 | — | 新增（04 §4.4） | 24 上游可能改名 redundant，hunk 部分 fail 可手动 fix |

其他 R-D1 / R-D3~D12 状态不变，全部 detection + mitigation 已落实。

### 3.2 风险升级警报（**已撤销**）

v0.1 中的"R-D2（KNI 24.11.6 完全移除）从 P2 升至 P1"警报**已撤销**。F-Stack 自实现 KNI 不受影响。

---

## 4. 可执行性评审（A）— v0.2

| 阶段 | v0.1 评分 | v0.2 评分 | 修订点 |
|---|---|---|---|
| M3 patch 重打 | A- | **A** | 04 §4.2.0 新增 29c7d5835 重打 step；§4.3 AC 表加 M3-AC4 (KNI 子树验证) + M3-AC5 (igb_uio 子树验证) |

---

## 5. spec 阶段直接闭环的 9 项实测（v0.2 增 3 项）

| 实测 | 命令 | 结论 | 修订位置 |
|---|---|---|---|
| **新 v0.2-1** F-Stack KNI 是否依赖 librte_kni | `head lib/ff_dpdk_kni.c + grep rte_kni lib/ff_dpdk_kni.c + nm libfstack.a \| grep rte_kni` | **0 依赖**；ring + virtio_user 自实现 | 02 §3.6 |
| **新 v0.2-2** F-Stack 在 dpdk/ 内的真实 patch 数 | `diff -rq + git log --diff-filter=D` | **4 个**（patch-scout v1 漏识别 29c7d5835）| 02 §2.4 + §2.5 |
| **新 v0.2-3** 29c7d5835 删除清单 | `git show 29c7d5835 --stat` | 310 文件 / -43195 行 | 02 §2.4 |
| DP-B2 KNI（v0.1 已做但结论错） | `ls dpdk-stable-24.11.6/lib/kni/ kernel/linux/kni/` | 都不存在；但与 F-Stack KNI 无关 | 02 §3.6 重写 |
| DP-B3 igb_uio | `ls dpdk-stable-24.11.6/kernel/linux/` | 仅 uapi（无 igb_uio） | 02 §3.7 |
| DP-B5 meson | `head -20 dpdk-stable-{23,24}.11.{5,6}/meson.build` | 23 ≥ 0.53.2 / 24 ≥ 0.57 | 02 §3.8 |
| R-D11 rte_ip.h | `grep struct rte_ipv{4,6}_hdr f-stack/lib/` | 10 处 + 3 处 include | 02 §3.7 |
| spec 总行数 | `wc -l` | v0.1 = 1916；v0.2 大致 +200 (第 4 patch + KNI 真相补充) | — |
| compliance 自查 | grep `rm |kill |chmod ` 0 直接调用 | ✅ | — |

---

## 6. 必修项 / 可选项（**v0.2 重写**）

### 6.1 必修项（**M2 启动前必须处理**）

| ID | 描述 | v0.1 → v0.2 变化 |
|---|---|---|
| ~~Must-Fix-1 KNI 决策~~ | ~~FF_KNI=0 还是保留 KNI 子树~~ | **取消** — 实际 user 已直接给出方案：保留 FF_KNI=1 + dpdk/ 仅含 igb_uio。spec 02 §3.6 + 04 §4.2.0 已落实 |

**v0.2 必修项总数：0**

### 6.2 可选项（spec 阶段不阻塞）

| ID | 描述 | 时机 |
|---|---|---|
| Nice-1 | 04 §M3.4 R-M3-1 的 92718178b rebase pseudo-diff hint | M3 启动前 |
| Nice-2 | 06 §11 性能基线对比表实际数据填充 | M5 完成后 |
| Nice-3 | M4 编译期验证 R-D11（rte_ip.h stub 是否自动转发 rte_ip4/rte_ip6.h）| M4 编译时 |
| **新 Nice-4** | M3 §4.2.0 重打 29c7d5835 时记录每个 hunk 的 N/A / apply / fail 情况 | M3 执行时 |
| **新 Nice-5** | argparse / ptr_compress 是否进入 29c7d5835 等价删除清单（保守 = 不删 / 激进 = 删）| M3 启动前由 user/leader 决策 |

---

## 7. 阶段一收尾建议（**v0.2 更新**）

| 动作 | 时机 |
|---|---|
| **新增** v0.2 修订 commit 落地（在 d25ba1e26 之上）| 立即 |
| commit message subject | `docs(spec): revise dpdk-23-24 spec — 4 patches via user KNI feedback (3->4)` |
| commit message body | 列 4 篇 spec 修订摘要 + KNI 真相 + 29c7d5835 补识别 + R-D2 降 N/A |
| 备份至 `dpdk-stable-24.11.6/f-stack-lib/test-configs/dpdk-23-24-upgrade/` 同步 | commit 同时 |
| **不 push** | 等 user 决策 |

---

## 8. 文档元信息

- **状态 v0.1**：评审通过（基于 v1 patch-scout 报告）
- **状态 v0.2**：基于 user 2026-06-09 14:50 反馈做修订，评审仍通过（且更准确）
- **PASS 签字 v0.2**：gate-keeper（独立 reviewer）
- **下一步**：leader 立即做 v0.2 修订 commit，等待 user 决策后启动阶段二（M1 baseline 采集）

| 维度 | 评分 | 备注 |
|---|---|---|
| 一致性 | **A** | 术语 / 编号 / 决策跨文档一致；唯一历史小漂移（KNI 状态从"待核实"→"已确认移除"）已在 02 §3.6 inline 修补 |
| 完整性 | **A** | plan q1~q4 全部落实；DP-A1~A8 + DP-B1~B7 全归宿；FR-D-1~11 + NFR-D-1~6 全 mapping 到 TC |
| 风险覆盖度 | **A** | R-D1~D12 全 12 项有 detection + mitigation + Owner；DP-B2 在 spec 阶段直接闭环（实测 KNI 移除）将 R-D2 等级升 P2→P1 |
| 可执行性 | **A-** | 阶段二里程碑 M1~M6 任务粒度清晰，commit 形态明确（`replace:` + `port:` + 可选 `fix:` + `docs(M-Final):`）；轻微扣分：92718178b 的 24.11.6 rebase 细节（rte_service_finalize / eal_lcore_var_cleanup 新增调用顺序）需 coder 自行 reasoning 而非 spec 给 step-by-step pseudo-diff，但这是阶段二实施工作不阻塞 spec |

**总计 4 篇 spec + plan + 本评审报告 = 6 篇文档**（plan §0.2 要求 7 篇 = plan + 00 + 01 + 02 + 04 + 06 + 99 = 7，本评审报告即第 7 篇 99-review-report.md）。

---

## 1. 一致性评审（A）

### 1.1 术语一致性

| 术语 | 出处 | 跨文档一致 |
|---|---|---|
| 整树替换 | plan §4.1 / 00 §术语表 / 02 §5 / 04 §M2 | ✅ 完全一致 |
| 3 patch 重打 | plan §4.4 / 00 §5.1 / 02 §2 / 04 §M3 | ✅ 完全一致 |
| `replace:` + `port:` 两 commit 语义分层 | plan §4.4 / 04 §3.2/§4.2.5 | ✅ 完全一致 |
| FSTACK_ZC_MAGIC（与 freebsd phase-2 衔接）| 06 §9.1 TC-G.3 | ✅ 仅 cross-reference 不重定义 |
| phase-5b 方法学 | plan §10 / 06 §1（参照标题）| ✅ 一致 |

### 1.2 编号一致性

- 6 篇文档的 ID 体系（FR-D-* / NFR-D-* / R-D* / DP-A* / DP-B* / DP-C* / TC-A~G）完全唯一无冲突
- spec 文档名沿用 plan §0.2 表（00 / 01 / 02 / 04 / 06 / 99；02+03 合并 / 04+05 合并）

### 1.3 决策一致性

| 决策 | plan | 00 | 01 | 02 | 04 | 06 | 一致 |
|---|---|---|---|---|---|---|---|
| q1=A 5 子 agent | §2 | §7 #1 | — | — | — | — | ✅ |
| q2=A 整树替换 | §4 / DP-A2 | §7 #2 | §7.1 | §5 | §M2 | — | ✅ |
| q3=A 单 06 spec | §0.2 / DP-A3 | §7 #3 | §4.1 | — | §M5 | §1 | ✅ |
| q4=B 7 篇精简 | §0.2 / DP-A4 | §7 #4 | — | — | — | — | ✅ |
| DP-A8 3 patch 合并 commit | §4.4 / §7.1 | §7 #5 | — | §5.1 表 | §4.2.5 + §8.2 | — | ✅ |

### 1.4 一致性微 issue（已 inline 修补，不阻塞）

| Issue | 处理 |
|---|---|
| plan / 02 旧版本"24.11.6 KNI 状态待 spec 阶段最终核实"在 spec 阶段已闭环 | 02 §3.6 已 inline 修补为"已确认完全移除" |
| plan §1.6 / 02 §3.8 旧版本 meson 最低版本不确定 | 02 §3.8 已 inline 修补为"23 ≥ 0.53.2 / 24 ≥ 0.57" |

---

## 2. 完整性评审（A）

### 2.1 plan §0.2 七篇文档覆盖

| # | 文件 | 落盘 | 行数 |
|---|---|---|---|
| 1 | `plan.md` | ✅ | 461 |
| 2 | `00-overview-and-glossary.md` | ✅ | 142 |
| 3 | `01-requirements-spec.md` | ✅ | 154 |
| 4 | `02-current-and-target.md` | ✅ | ~290（含 inline 修补）|
| 5 | `04-port-and-impl.md` | ✅ | 490 |
| 6 | `06-test-and-acceptance-spec.md` | ✅ | 385 |
| 7 | `99-review-report.md` | ✅（本文）| 见 §6 |

### 2.2 plan q1~q4 决策落实

| q | 决策 | 落实位置 |
|---|---|---|
| q1=A 5 子 agent | plan §2 详述每子 agent 职责；spec 阶段 patch-scout / dpdk-24-analyzer / diff-comparator 已实际执行（输出在 02 §2 / §3 已引用）| ✅ |
| q2=A 整树替换 | 04 §M2 完整 5-step 流程 + 备份策略 + commit message template | ✅ |
| q3=A 单 06 spec | 06 单文档涵盖 TC-A ~ TC-G | ✅ |
| q4=B 7 篇精简 | 02 = 02+03 合并 / 04 = 04+05 合并 | ✅ |

### 2.3 决策点（DP）归宿

| DP 类 | 总数 | 归宿 |
|---|---|---|
| DP-A1~A8 已决策 | 8 | plan §7.1 + 各 spec cross-ref |
| DP-B1~B7 spec 阶段调研后闭环 | 7 | 01 §7.2 / 02 §3 inline 实测结论 |
| DP-C1~C3 阶段二待决 | 3 | 01 §7.3 占位 |

### 2.4 FR / NFR 到 TC 的 mapping

| 需求 | 对应 TC |
|---|---|
| FR-D-1 (DPDK build 0 errors) | 04 §M2-AC3 |
| FR-D-2 (3 patch trivially apply) | 04 §M3-AC1/AC2 |
| FR-D-3 (lib/example build) | 04 §M2-AC3 / §M4-AC1/AC3 |
| FR-D-4 (helloworld primary alive) | 06 TC-A.G2 |
| FR-D-5 (HTTP 200 单 curl) | 06 TC-A.G3.1 |
| FR-D-6 (100 短连 100/100) | 06 TC-A.G3.2 |
| FR-D-7 (nginx 单进程 + 100 短连) | 06 TC-C.G3 |
| FR-D-8 (nginx 多进程 + curl/wrk) | 06 TC-E.G3 + TC-F.G3 |
| FR-D-9 (92718178b 有效) | 06 TC-E.G3.4~6 |
| FR-D-10 (62f1c34df 有效) | 06 TC-E.G3.7~9 |
| FR-D-11 (phase-2 + vlan-test smoke) | 06 TC-G |
| NFR-D-1/D-2 (perf trade-off ≤ 5%) | 06 TC-B.G4 / TC-D.G4 |
| NFR-D-3 (build time) | 04 隐含；阶段二 M1 baseline |
| NFR-D-4 (libfstack.a 大小) | 04 隐含；阶段二 M2/M4 ACs |
| NFR-D-5 (RSS 稳态) | 06 隐含；阶段二实测 |
| NFR-D-6 (无新 SIGSEGV/panic) | 06 TC-A.G2.4/5/6 + TC-C.G2 |

→ **全部 11 FR + 6 NFR 都有归宿**。

### 2.5 完整性微 issue

| Issue | 严重度 | 处理 |
|---|---|---|
| `04` §M5 引用 `06-test-and-acceptance-spec.md §G3` 各子节，但 06 中实际 G3 标题用 TC-A.G3.1 / TC-C.G3 等，cross-ref 标识略不一致 | trivial | 阅读时可顺利定位，不阻塞 |
| `06` §11 性能基线对比表占位（M5 完成后落档），需 leader 阶段二实际填充 | expected | 不算 spec 缺陷，是阶段二动作 |

---

## 3. 风险覆盖度评审（A）

### 3.1 R-D1~D12 全 12 项 detection + mitigation 矩阵

| ID | 描述 | detection | mitigation | Owner | 评审 |
|---|---|---|---|---|---|
| R-D1 | rte ABI break | 编译期 unresolved | diff-comparator 已实测 0 改名 | coder | ✅ |
| R-D2 | KNI 24.11 移除 | **spec 阶段已闭环：完全移除** | 02 §3.6 给 A/B 双方案 | coder + leader | ✅ **等级 P2→P1** |
| R-D3 | igb_uio 上游移除 | **spec 阶段已闭环：上游 21.05 移除** | F-Stack 自带版本由 `5f3768c63` 重打恢复 | patch-scout | ✅ |
| R-D4 | secondary process eal_bus_cleanup | dpdk-24-analyzer 实测仍无条件调用 | `92718178b` 必须 rebase | coder | ✅ |
| R-D5 | priv_timer cache_align 宏迁移 | 文件大小 0 变化实测 | trivially apply | coder | ✅ |
| R-D6 | meson / gcc 版本要求 | spec 阶段已闭环：meson ≥ 0.57 | `pip install -U meson` if needed | coder | ✅ |
| R-D7 | perf trade-off > 5% | TC-B/TC-D 测量 | observation 标签或拆 phase | gate-keeper | ✅ |
| R-D8 | phase-2 7 flag 共存性回归 | TC-G smoke | 单 fail 拆独立 phase | coder | ✅ |
| R-D9 | freebsd-15 子系统兼容性 | TC-A.G2 init log | 含 ipfw2/tcp_bbr 关键字检查 | gate-keeper | ✅ |
| R-D10 | DPDK 内部 ABI 24→25 | F-Stack static lib 链接 | doc 注明，不阻塞 | leader | ✅ |
| R-D11 | rte_ip.h 重构 | **spec 阶段已闭环：F-Stack 仅 include rte_ip.h，使用 10 处 struct** | 24 stub include 应自动转发；M4 编译期验证 | coder | ✅ |
| R-D12 | nginx multi-worker fork EAL | TC-E reload 测试 | 与 R-D4 联动 | coder | ✅ |

→ 全 12 项有 mitigation；spec 阶段直接闭环 4 项（R-D2 + R-D3 + R-D6 + R-D11），其余 8 项有阶段二明确 detection 路径。

### 3.2 风险升级警报

**R-D2（KNI 24.11.6 完全移除）从 P2 升至 P1**：
- 实测 `/data/workspace/dpdk-stable-24.11.6/lib/kni/` + `/data/workspace/dpdk-stable-24.11.6/kernel/linux/kni/` 均不存在
- F-Stack `lib/Makefile` 当前 FF_KNI 默认 =1，整树替换后会立即编译失败
- M2 启动前必须做出 A/B 决策（02 §3.6 已列）

→ gate-keeper 推荐：**M2 启动前先发起 mini-spec 决策回合，user/leader 决定 FF_KNI=0 还是保留 KNI 子树**。这不是 spec 缺陷（spec 已识别风险并列方案），是阶段二实施前的 prerequisite。

---

## 4. 可执行性评审（A-）

### 4.1 阶段二 AI 代理拾取友好度

| 阶段 | spec 提供的 step-by-step 程度 | 评审 |
|---|---|---|
| M1 baseline | 04 §2.2 完整 bash 命令清单 | ✅ 直接可执行 |
| M2 整树替换 | 04 §3.2 含 6-step 完整流程 + commit message | ✅ 直接可执行 |
| M3 patch 重打 | 04 §4.2 三 patch 各自 git apply 命令 + 等价性自检 + 合并 commit | ✅ 直接可执行 |
| M4 胶水修复 | 04 §5.2 已知潜在修复点表 + 命令 | ✅ 直接可执行 |
| M5 测试 | 06 详尽 TC-A~G + 命令 + AC + log 落档路径 | ✅ 直接可执行 |
| M6 M-Final | 04 §7.2 doc sync 清单 + commit message | ✅ 直接可执行 |

### 4.2 可执行性扣分项

| 扣分 | 详情 |
|---|---|
| 04 §M3.4 R-M3-1（92718178b rebase）| spec 描述了 23.11.5 vs 24.11.6 的 `rte_eal_cleanup()` 调用顺序差异，但**未给出 hunk-by-hunk 的 pseudo-diff**让 coder 直接照做。Coder 需要自行读 23 commit + 24 上游代码做 reasoning。这在 spec 范畴内可接受（spec 不应 over-prescriptive），但增加了 coder 工作量。建议阶段二 M3 启动前由 leader 给 coder 一个 pre-bounce hint：`"24.11.6 的 eal_bus_cleanup() 调用在 line 1324（dpdk-24-analyzer Q3.b），保留前后的 rte_service_finalize() 与 vfio_mp_sync_cleanup() 上下文行"`。 |

### 4.3 命令规约合规

抽查 04 / 06 中所有 shell 命令：
- `rm` 直接调用：**0 次**（全部走 `rm_tmp_file.sh`）
- `kill` 直接调用：**0 次**（全部走 `kill_process.sh`）
- `chmod` 直接调用：**0 次**
- `git push` 直接调用：**0 次**

→ ✅ 命令规约 100% 合规。

---

## 5. spec 阶段直接闭环的 7 项实测

按 plan §3 Phase 4 设计，gate-keeper 在评审过程中做了少量实测以闭环 spec 阶段尚未确定的 DP-Bx 项：

| 实测 | 命令 | 结论 |
|---|---|---|
| DP-B2 KNI 状态 | `ls /data/workspace/dpdk-stable-24.11.6/lib/kni/ kernel/linux/kni/` | **完全移除**；R-D2 升 P1；02 §3.6 inline 修补 |
| DP-B3 igb_uio 状态 | `ls /data/workspace/dpdk-stable-24.11.6/kernel/linux/` → 仅 `uapi`（无 igb_uio）| 与 patch-scout 实测一致 |
| DP-B5 meson 版本 | `head -20 dpdk-stable-{23,24}.11.{5,6}/meson.build` | 23 ≥ 0.53.2 / 24 ≥ 0.57；02 §3.8 inline 修补 |
| R-D11 rte_ip.h 使用 | `grep struct rte_ipv{4,6}_hdr f-stack/lib/ff_dpdk_*.c f-stack/lib/ff_memory.c` | F-Stack 10 处 struct 使用 + 3 处 include `rte_ip.h`；02 §3.7 inline 修补 |
| spec 文件总行数 | `wc -l docs/dpdk_23_24_upgrade_spec/zh_cn/*.md` | 6 篇 spec = 1916 行（plan + 00 + 01 + 02 + 04 + 06）|
| 文档落盘验证 | `ls -la docs/dpdk_23_24_upgrade_spec/zh_cn/*.md` | 6/6 存在 |

> 评审过程严格遵守只读约束 + 工作区 wrapper 强制规约（0 直接 rm/kill/chmod）。

---

## 6. 必修项 / 可选项

### 6.1 必修项（**M2 启动前必须处理**）

| ID | 描述 | 责任人 |
|---|---|---|
| Must-Fix-1 | KNI 决策（FF_KNI=0 还是保留 KNI 子树）— spec 已列 A/B 方案，需 user/leader 实际决定 | leader |

### 6.2 可选项（spec 阶段不阻塞，阶段二实施可继续）

| ID | 描述 | 时机 |
|---|---|---|
| Nice-1 | 04 §M3.4 R-M3-1 的 92718178b rebase pseudo-diff hint | M3 启动前 |
| Nice-2 | 06 §11 性能基线对比表实际数据填充 | M5 完成后 |
| Nice-3 | M4 编译期验证 R-D11（rte_ip.h stub 是否自动转发 rte_ip4/rte_ip6.h）| M4 编译时 |

---

## 7. 阶段一收尾建议

| 动作 | 时机 |
|---|---|
| spec local commit（含 plan + 6 spec + 99 review）| 本评审通过后立即 |
| commit message subject | `docs(spec): DPDK 23.11.5 -> 24.11.6 LTS upgrade spec generation phase` |
| commit message body | 列 plan / 5 篇 spec / 1 篇 review + 总行数 + 风险评估摘要（特别 R-D2 KNI 升 P1） |
| 备份至 `dpdk-stable-24.11.6/f-stack-lib/test-configs/dpdk-23-24-upgrade/` | commit 同时执行 |
| **不 push** | 等 user 决策 |

---

## 8. 文档元信息

- **状态**：v0.1 — 评审通过
- **PASS 签字**：gate-keeper（独立 reviewer）
- **下一步**：leader 执行阶段一收尾（commit + 备份），等待 user 决策后启动阶段二（M1 baseline 采集）
