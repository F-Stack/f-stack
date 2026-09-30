# Nginx 无损 reload：spec 文档 × 代码实现 交叉审核 + 运行时回归（plan_audit.md）

> 状态：已人工确认（2026-09-17），执行中
> 本文件 local-only，不入库（与 plan.md / plan_m3~m6.md 同规约）
> 审核报告落盘 work/，不新增 zh_cn 正式篇目；受影响正文按代码事实最小订正

## 1. 目标与范围

### 1.1 目标

1. 对 `docs/nginx_reload_spec/zh_cn/`（00~09 共 10 篇）与被测代码（`lib/`、`app/nginx-1.28.0/src/event/modules/`、`tests/`、`tools/`、`doc/`）做一轮独立交叉审核：锚点级（file:line/符号/配置项/commit/issue-PR）、语义级（机制描述 vs 实现）、完整性（C-NR 编码点与 UT/IT/RT/PT/A-NR 对照）、方案级（并发/资源/契约/新风险）。
2. 结合三层架构文档与知识图谱（`docs/01-LAYER1-ARCHITECTURE.md` 等）与外网资料（GitHub issue/wiki、官方文档、技术博客、公众号）三方交叉；不一致处以实际代码为准。
3. 修复发现的不一致与缺陷（写审分离、bounce ≤ 3），`make clean` 全量重建，跑真机全量 harness（rv9 20 轮）确认运行正常。
4. 结论与证据落盘并按里程碑英文短提交。

### 1.2 不在本轮范围

- 中文 spec 转英文翻译；新增 zh_cn 正式篇目；编号体系变更
- 已定案的方案级形态变更（如 DR11 M-A/M-B 重新裁决）；超范围设计问题只登记上报

## 2. 团队结构与写审分离矩阵

| 角色 | 属性 | 职责与产物 | 约束 |
|---|---|---|---|
| leader（主 agent） | 编排/裁决 | 全局统筹、定时轮询、门禁裁决、按里程碑提交、兼任非写非审串行任务 | 不撰写/修改被审文档与代码正文、不自审；子 agent 全部完成前不退出 |
| audit-anchor | 审 | 00/03/04/07 锚点级与完整性核对 → `work/audit-E-doc-code.md` | 与全部写者不同实例 |
| audit-solution | 审 | 06/08/09 语义/方案级 + 01/02/05 外部回查 → `work/audit-F-solution.md` | 与全部写者不同实例 |
| doc-writer | 写 | 按清单订正 zh_cn 正文 | 由 auditor 复核，不得自审 |
| code-fixer（按需） | 写 | lib/nginx/tools 缺陷修复 + 单测补充 | 由独立 auditor 复核 |
| build-runner | 执行 | clean 重建 + 安装 + 单测/集成测试 | 只执行不裁决 |
| rt-runner | 执行 | 真机 harness 全量运行 | 只执行不裁决 |
| rt-auditor | 审 | 独立复核 harness 原始产物并重算 verdict | 与 rt-runner、harness 作者不同实例 |
| gate-reviewer | 审 | 终门禁独立裁决 | 与全部写者不同实例 |

## 3. 阶段与门禁

```
P0 准备与基线 → P1 并行交叉审核 → P2 修复(bounce≤3) → P3 clean 重建+单测/集成
  → P4 真机全量测试(rv9 20 轮)+独立复核 → P5 文档同步+里程碑提交 → P6 终门禁
```

| 阶段 | 门禁判据 | 失败回退 |
|---|---|---|
| P1 | 两报告落盘，发现均有证据（文件:行/命令/URL），无臆断 | 超时/异常 → leader 接管或 spawn 新 auditor |
| P2 | 每条发现处置闭环且复核通过 | 同一单点 bounce ≤ 3，超限停止转人工并登记 |
| P3 | lib error 0、无新增 warning、单测/集成全过 | 打回 P2 |
| P4 | harness 退出码 0（全用例 PASS）且 rt-auditor 复核通过 | 打回 P2 修复后重跑（≤3） |
| P5 | IP 合规扫描 0 违规、提交规范 | 打回重做 |
| P6 | 发现全闭环、证据链完整、无遗留 | 打回 P5 |

## 4. leader 轮询与超时机制

- 每 3~5 分钟旁路探测：`work/` 落盘文件 mtime、git status、harness.log/err 日志 tail、进程表与产物
- 单任务超时：审核 40min、修复 30min、构建 60min、harness 120min；超时先旁路确认存活性
- 回退：非写非审任务 leader 接管；写/审任务 spawn 新 agent 重做（写审分离不破）；保留部分产物续做

## 5. 发现分级与处置

| 分级 | 处置 |
|---|---|
| DOC-BUG | 以代码为准改文档（doc-writer） |
| CODE-BUG | 修代码 + 补单测（code-fixer），clean 重建后重跑相关回归；复现方式与修复 diff 一并落盘 |
| DESIGN-ISSUE | 评审裁决；超范围登记上报人工决策 |
| UNVERIFIED | 显式标注未坐实，给出运行时/后续验证方法，不臆断 PASS |

## 6. 环境基线（P0 实测，2026-09-17）

| 项 | 实测 |
|---|---|
| HEAD | `28e751259`（2026-09-09，仅文档提交；最后一次触碰代码/测试的提交为 `410276188`，仅 harness 脚本） |
| 工作区 | 仅 `config.ini` 本地修改（不入库）；其余为 untracked |
| 已安装 nginx | `/usr/local/nginx_fstack/sbin/nginx`，构建于 Sep 8 18:13 |
| lib 产物 | `lib/libfstack.a`，构建于 Sep 9 12:44 ⇒ **晚于安装二进制，RT 前必须 clean 重建+安装** |
| DPDK 网卡 | `0000:00:09.0` 已绑 `igb_uio`（内核网卡 eth1 为另一张卡，`<KERNEL_NIC_IP>`） |
| hugepage | Total=2048 / Free=2048 |
| KNI 前置 | `/dev/vhost-net` 存在（rt12 可全跑） |
| 残留 | 无 nginx/ff_slim 进程；`/dev/hugepages` rtemap=0；`/var/run/dpdk/rte` 不存在（仅 ff_* 私有前缀目录） |
| 客户端 | ssh 别名 `f-stack-client` 可达（`<CLIENT_IP>`） |
| harness | `tests/integration/test_graceful_reload.sh`（可执行，Sep 9 13:51）；探针目录 `work/m4-poc/` 齐备 |
| 上次运行 | `/tmp/gr_harness_20260909_135528_1162234`（rv9 2 轮 PASS）；本轮用新 OUT 目录 |

## 7. 产物清单

```
docs/nginx_reload_spec/
├── plan_audit.md                 # 本文件（local-only）
├── work/audit-E-doc-code.md      # [NEW] 锚点级/完整性交叉审核报告
├── work/audit-F-solution.md      # [NEW] 方案级评审 + 外部资料交叉
├── work/audit-G-fix-review.md    # [NEW] 逐条修复独立复核记录（含 bounce 计数）
├── work/audit-G-escalation.md    # [NEW] 仅 bounce 超限时登记
└── work/rt-round2-report.md      # [NEW] 真机运行报告 + 独立复核结论
zh_cn/                            # [MODIFY 按需] 00/04/06/07/08/09 最小订正
lib/ app/nginx-1.28.0/ tests/     # [MODIFY 仅当发现 CODE-BUG]
/tmp/gr_harness_<ts>/             # 运行原始产物（不入库；报告定稿前不清理）
```

## 8. 运行时测试方案（本轮）

```
tests/integration/test_graceful_reload.sh -t <DPDK_NIC_IP> -c all -r 20 --shutdown-timeout 15 \
    --client f-stack-client
```

- 用例集合：precheck / baseline / rt01 / rt02 / rv9(20 轮) / gr0 / rt12 / rt13
- 形态沿用 M6 终门禁可执行配置（无 keepalive 纯 fresh + 显式 shutdown timeout）
- 逐用例判据由 rt-auditor 从原始日志独立重算，拒绝只信 runner 摘要

## 9. 硬性约束（零容忍）

1. Shell：删除走 `/data/workspace/rm_tmp_file.sh`；停进程走 `/data/workspace/kill_process.sh`；改权限走 `/data/workspace/chmod_modify.sh`（命令串与注释内均不得出现直接 rm/kill/chmod）
2. 改 .c/.h 必须 `make clean` 全量编译（规避 safe-delete hook：`PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin" make clean`；先 `make machine_includes` 再 `make -j16`）；lib error 0 且不得新增 warning
3. config.ini 本地测试值（lcore_mask、port 真实地址、idle_sleep 等）绝不 `git add`
4. 任何文档/报告/commit 禁止真实 IP，统一占位符（允许 `127.0.0.1`、`fe80::`）
5. commit message 英文 1~3 句；按里程碑多次提交；不改写历史
6. 代码注释一律简短英文；lib 只写必须注释
7. 实事求是：所有结论实际执行取证；未坐实标「未坐实」，不臆断 PASS

## 10. 执行追踪

| 阶段 | 状态 | 备注 |
|---|---|---|
| P0 准备与基线 | 完成 | 环境三查通过（2026-09-17 16:32） |
| P1 并行交叉审核 | 完成 | E：DOC-BUG 29 / CODE-BUG 0 / UNVERIFIED 3；F：DOC-BUG 8 / UNVERIFIED 1 / 风险 6；报告 `work/audit-E-doc-code.md`、`work/audit-F-solution.md` |
| P2 修复 | 完成 | bounce-1（writer-a 5 FAIL + writer-b 3 FAIL）→ 复验通过；bounce-2（09 版本 token、O-1/O-2）→ 复验通过；**PH-1（新）：harness kni=0 泄漏缺陷**已由 code-fixer 修复并复核（rt-auditor §8 PASS） |
| P3 clean 重建 + 单测/集成 | 完成 | lib error 0 / warning 51（基线）；单测 87/87 + 48 PASS（1 显式 SKIP）；集成 7/7 + 7/7；nginx/lib md5 与 HEAD 一致 |
| P4 真机全量测试 | 完成 | RT-2a（修复前形态，KNI 全开）与 **RT-2b（修复后设计形态，权威）** 各一轮全量：退出码 0、failed=0、rv9 各 20/20；rt-auditor 独立复核（§0~§9） |
| P5 文档同步 + 提交 | 完成 | P5 → P5b → bounce-3（终门禁 N1/N3/O-3）全部落盘并由 audit-solution / gate-reviewer 复核；提交：`3d2b60750`（harness KNI 修复）、`e00a0c9c6`（8 篇 zh_cn 订正 + RT 记录）；config.ini / work/ / plan*.md 未入库 |
| P6 终门禁 | 完成 | gate-reviewer 最终裁决 **PASS（无条件）**（`work/audit-H-final-gate.md`，418 行）；55 条发现 + N1/N2/N3/O-3 全部闭环；受限项 L1/L2/L3/L4/L6 与残留 UNVERIFIED（心跳校准、DPDK 硬禁令例外缺 IT-NR-A13）如实登记 |

### 收尾结论（2026-09-17）

- 交付达成 `plan_audit` §1 四项目标；对外口径：本轮运行时测试为「0 FAIL + 未执行项登记」，**不得表述为「全用例 PASS」**（rt13 zc 形态未执行、rt12 管理面未判）。
- 关键产出：`work/audit-E-doc-code.md`、`work/audit-F-solution.md`、`work/audit-G1-fix-review-anchor.md`、`work/audit-G2-fix-review-solution.md`、`work/rt-round2-report.md`、`work/audit-H-final-gate.md`。
