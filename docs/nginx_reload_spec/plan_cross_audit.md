# Nginx 无损 reload：spec × 代码交叉审核 + 第三轮运行时回归（plan_cross_audit.md）

> 状态：已人工确认（2026-09-17），执行中
> 性质：交叉审核（文档×代码）+ 分级修复 + 实机回归。代码改动按 P0/P1 修复；文档按实际代码订正。
> 本文件 local-only，不入库。
> 中文 spec 目录：`docs/nginx_reload_spec/zh_cn/`（本阶段不产出英文版）。
> 本轮产物目录：`docs/nginx_reload_spec/work/cross-audit/`、`docs/nginx_reload_spec/work/rt-round3/`（不覆盖历史 work 文件）。

## 1. 任务目标

1. **交叉审核**：`zh_cn/` 10 篇 spec 的每条事实性声明（行号锚点、配置项键名、函数/符号名、状态机语义、编码点数、用例数、判据）与实际代码核对，检出「文档≠代码」；并结合三层架构文档/知识图谱与外网资料（GitHub issue/wiki、技术博客、公众号）对方案本身提出质疑。
2. **分级修复**：P0/P1 代码缺陷修复（最小 diff）+ `make clean` 完整编译 + 单测；文档类问题按代码订正（含版本头与修订记录）；P2/P3 如实登记。
3. **运行时回归**：实机 harness 全量用例 + rv9 **50 轮**，与 RT-2b 基线横向对比；结果由独立复核员从原始产物重算。
4. **范围外（如实登记，不尝试）**：rt13 的 zc 构建运行时复跑（不重建 lib/nginx）；rt12 管理面（不传 `--kernel-nic-ip`）；rt12 的 `ok` 分支（云环境不可构造）。

## 2. 团队结构（ff-reload-cross-audit）

| 角色 | 职责 | 产物落盘 |
|---|---|---|
| Leader（主 agent） | 统筹、轮询（旁路探测优先）、证据汇总、异常回退裁决；**不写正式 findings/文档/代码，不自审** | 本 plan.md + 收尾报告 |
| auditor-docs（A） | 交叉审核 00/01/02/03/05 + 外网佐证 | `work/cross-audit/A-docs-findings.md` |
| auditor-lib（B） | 交叉审核 04/06 × lib 层（锚点/符号/配置项/方案质疑） | `work/cross-audit/B-lib-findings.md` |
| auditor-app（C） | 交叉审核 07/08/09 × nginx 适配层 + tests 资产与用例数 | `work/cross-audit/C-app-test-findings.md` |
| external-researcher（E） | 三层架构文档/知识图谱 + 外网资料检索（f-stack-info-search） | `work/cross-audit/external-research.md` |
| audit-reviewer（R1） | **独立复核**三份 findings：合并去重 + 逐条以代码复审 + 分级裁决 | `work/cross-audit/consolidated-findings.md` |
| doc-fixer（F1） | 按裁决订正 `zh_cn/*.md`（含版本头与修订记录） | `zh_cn/00/04/06/07/08/09` 等 |
| code-fixer（F2） | P0/P1 代码缺陷最小 diff 修复（c-precision-surgery 风格） | lib/ + app/nginx-1.28.0/src/ |
| builder（B1） | `make clean` 全量编译 + 单测执行 | 编译/单测日志 |
| build-reviewer（R2） | 编译与单测门禁（无新增 warning、无回归） | 复核记录 |
| rt-runner（T1） | 实机 harness 全量用例 + rv9 50 轮 | `work/rt-round3/rt3-runner-report.md` + 原始日志 |
| rt-auditor（T2） | 从原始产物重算判定，对比 RT-2b 基线 | `work/rt-round3/rt3-auditor-report.md` |
| gate-reviewer（G） | 终门禁裁决 | 裁决记录 |
| committer（C1） | 分层提交（英文 1-3 句；config.ini 不入库） | git log |

**写审分离矩阵（铁律）**

| 写者 | 审核者（必须不同 agent） |
|---|---|
| auditor-A/B/C（findings） | audit-reviewer |
| doc-fixer（文档订正） | gate-reviewer / audit-reviewer |
| code-fixer（代码修复） | build-reviewer + gate-reviewer |
| rt-runner（测试执行） | rt-auditor |
| leader | 不写不审同一产物；仅兼任纯探测/轮询/汇总/裁决 |

**轮询与超时（leader 必做）**

- 旁路探测优先于消息探测：每轮唤醒先查 `work/cross-audit/*.md`、`work/rt-round3/*` 的 mtime/size、`git status --short`、`app/nginx-1.28.0/objs/nginx` 与 `lib/*.o` 的 md5/mtime、harness 日志尾部行数。
- 分阶段超时阈值：审核 60min / 复核 30min / 编译 30min / 运行时 240min。
- 超时先旁路判活（产物是否在增长）；仍无进展：纯探测类 leader 接管，写/审类 spawn 新 agent 重做（**不得由 leader 自写自审**）。
- bounce≤3：任一门禁失败打回上一步修复，同一单点打回超 3 次立即停止，转人工决策。

## 3. 执行阶段

1. **Phase 0**：建团 + 落盘本 plan + 记录基线（HEAD commit、构建产物 md5、三查）。
2. **Phase 1（并行）**：A/B/C 三名审核员 + E 外部检索，落盘 4 份产物。
3. **Phase 2（串行）**：audit-reviewer 合并去重 + 逐条以代码复审 + 分级裁决（G-A 门禁）。
4. **Phase 3（串行，依赖 G-A）**：doc-fixer 订正文档 + code-fixer 修 P0/P1 → builder `make clean` 全量编译 + 单测 → build-reviewer 门禁（G-B）。
5. **Phase 4（串行，依赖 G-B）**：rt-runner 实机全量用例 + rv9 50 轮 → rt-auditor 独立重算（G-C）。
6. **Phase 5**：gate-reviewer 终门禁 → committer 分层提交。
7. **Phase 6**：leader 收尾报告（交叉审核结论、修复清单、运行时对比、残留登记）。

## 4. 审核方法论

- **以实际代码为唯一准绳**：spec 每条事实声明必须附 `grep -n` / `nm` / 文件实际输出；文档与代码冲突一律改文档（除非代码本身是缺陷）。
- **高价值靶点（种子）**：
  1. 07 §2.7(2) 与 (5) 仍登记「F2 脏 EAL respawn」，与同节 §(3)「机理证伪、表述作废」自相矛盾；
  2. `lib/ff_reload_gendir.c`（M5 世代目录）在 zh_cn 全库 0 命中；
  3. F-M6-5：`config.ini` 的 `[port0] addr` 在 HEAD 被提交为本机测试地址（违反「本地测试值不入库」）；
  4. 08 声明的 UT-NR/IT-NR 用例数与实际 `tests/unit`（16 个 .c）/ `tests/integration` 资产对齐性；
  5. 全库行号锚点漂移（M1~M6 在 `ngx_process_cycle.c`、`ff_dpdk_if.c` 插入大量代码）。
- **finding 条目契约**（多 agent 依赖，必需字段）：`id / severity(P0-P3) / type(DOC|CODE|DESIGN|EXTERNAL) / spec_ref / code_ref(附取证命令与输出) / claim / reality / verdict / action`。

## 5. 运行时测试口径

- 命令形态：全量用例 + rv9 50 轮，其余参数沿用 RT-2b（`-i 6 -p 5 --shutdown-timeout 15`），TARGET_IP 执行用真实值、**报告与文档一律占位符 `<DPDK_NIC_IP>`**。
- 执行前三查（hugepage、rte 文件新鲜度、客户端连通）；执行后停净进程（kill_process.sh）并回收临时文件（rm_tmp_file.sh）。
- 与 RT-2b 基线的逐指标对比：complete 轮数、drain 分布、deadline forced 数、防重入拒绝数、rtemap 斜率、HugePages 终态、fresh_n/fresh_fail。
- 不臆断 PASS：未执行/环境不满足的判据一律标注「未执行/未坐实」并登记。

## 6. 硬性约束（全程零容忍）

- 删除走 `/data/workspace/rm_tmp_file.sh`；停进程走 `/data/workspace/kill_process.sh`；加执行位走 `/data/workspace/chmod_modify.sh`。
- 改代码必须 `make clean` 后完整编译（已知坑：`PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin" make clean` 规避 safe-delete hook；先 `make machine_includes` 再 `make -j16`）；编译基线 lib error 0 / warning 51，不得新增 warning。
- `config.ini` 本地测试值不入库；文档与报告严禁真实 IP，统一占位符；commit message 英文 1-3 句；F-Stack 代码注释一律英文；lib 最小注释。
- 所有结论必须实际执行取证，严禁猜测；交叉验证不一致以实际代码为准。

## 7. 执行追踪

| 阶段 | 状态 | 备注 |
|---|---|---|
| Phase 0 建团 + plan | 进行中 | 2026-09-17 启动 |
| Phase 1 A/B/C/E 并行审核 | 待开始 | |
| Phase 2 G-A 复核裁决 | 待开始 | |
| Phase 3 修复 + G-B 编译门禁 | 待开始 | |
| Phase 4 运行时 + G-C | 待开始 | |
| Phase 5 终门禁 + 提交 | 待开始 | |
| Phase 6 收尾报告 | 待开始 | |
