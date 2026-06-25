# R-F 多智能体 Team Runtime 故障复盘（postmortem）

> 角色：leader 自我复盘。本文是对"R-F 里程碑前半段（诊断 + 设计 + 审核）期间多智能体并行运行时未真正生效"事实的如实记录，用户明确要求落盘以保证可追溯。
> 时间窗：2026-06-23 ~ 2026-06-24。
> 目的：避免后续 spec / 实施报告误以为真正"并行多 agent 协作"完成了 R-F 前半段，实际是**串行 + 半失效 team 通信**。
> 此文不否定根因诊断结论的正确性（key 不一致根因与 v4/v6 串行构造方案有源码位级证据 + 独立 reviewer 复核，结论可靠）；仅澄清"协作方式"未达 claw-multi-agent 设计预期。

---

## 1. 事实证据（按时间序）

### 1.1 团队创建（2026-06-23 10:53）

`team_create(team_name=rf-rss-thash)` 成功，磁盘留下：

- `/data/workspace/.codebuddy/teams/rf-rss-thash/config.json`：`leadAgentId=20d481cfab0944a483780d03620f2da7`，初始 members 仅 `team-lead`。
- `inboxes/team-lead.json`。

### 1.2 诊断阶段（diag-code / diag-dpdk）— 表面像并行，实际是串行 subagent

并发 spawn 两个 `task` 子 agent（`name=diag-code`、`name=diag-dpdk`，均 `team_name=rf-rss-thash`）。两者最终都成功落盘：

- `_rf_work/diag_code_findings.md`、`_rf_work/diag_dpdk_findings.md`。
- 团队 `config.json` members 后续被运行时追加为 `team-lead / diag-code / diag-dpdk / arbiter`。

但**没有任何证据表明二者是真并发执行**：

- `task` 工具返回是同步阻塞式的 `Execution Summary: ... credits: ...`，每次返回一个子 agent 的最终消息。
- 我（leader）作为主 agent 在两个 `task` 之间收到的 `<teammate-message>` 是**汇总注入**形式，不是异步 push。
- 后续 `send_message(recipient=diag-code/diag-dpdk)` 调用没有任何"消息已投递、对方下一轮处理"的实证（子 agent 一旦返回就视为终止，再发消息也无人接收）。

→ 结论：诊断阶段的"并行多 agent"实际是 **leader 同步派两次任务、每次一个 subagent 跑、跑完返回**。最多是"轮转"，不是"并行"。

### 1.3 仲裁（arbiter）— 同上，单个串行 subagent

仲裁结论 `_rf_work/arbiter_rootcause.md` 由独立 `task` 子 agent（`name=arbiter`）跑完后返回。同样无并发证据。但：

- ✅ **写/审分离逻辑达成**：诊断（diag-code/diag-dpdk）与仲裁（arbiter）是**不同的 subagent 实例**完成的，且 leader 没有自写自审。
- ✅ **仲裁纠正了诊断的错误共识**：诊断双方一致认为根因是字节序 → 仲裁用位级推导推翻、确认根因为 key 不一致。这是写/审分离设计价值的真实兑现，不受"串行 vs 并行"影响。

### 1.4 设计阶段（designer）— team runtime 第一次破裂

leader spawn `name=designer, team_name=rf-rss-thash` 设计子 agent。返回：

```
Execution Summary: 24 tool uses, cost: 326.98s, credits: 126.52
（子 agent 抱怨没有写文件工具）"由于工具集中没有写文件工具..."
（子 agent 在返回里直接输出了完整 design 文档内容，但被截断）
```

故障迹象：

1. **能力错配**：spawn 时未指定 subagent 类型为有写权限的 agent（实际上目前可用 subagent 仅 `code-explorer`，纯只读），子 agent 想写文件时发现工具集没有 write 工具，只能在返回里把内容贴出来，被截断丢失。
2. **team 注册不一致**：随后我尝试 `send_message(recipient=designer, ...)` 给设计子 agent 发轮询消息，运行时返回 **"Not in a team. SendMessage is only available when in a team."**
3. **config.json 成员丢失**：检查磁盘 `/data/workspace/.codebuddy/teams/rf-rss-thash/config.json`，members 列表里**根本没有 designer**，只有 `team-lead / diag-code / diag-dpdk / arbiter`——说明 designer 子 agent 退出时未被运行时注册到团队成员表，team_name 参数未生效。

### 1.5 审核阶段（reviewer）— team runtime 第二次破裂

吸取 designer 没写权限的教训后，由 leader 自己写 `design_rf.md`（满足"写"角色），然后再 spawn `name=reviewer, team_name=rf-rss-thash` 做独立审核。运行时直接报：

```
Failed to create team "rf-rss-thash": Error: Team "rf-rss-thash" already exists. Use different name or delete existing team.
```

**矛盾点**：

- 团队**确实已存在**（config.json 在磁盘上），但运行时却把"加入已存在团队"当成"新建团队冲突"——即 `team_create` 与 `task(team_name=...)` 之间的语义在当前 runtime 状态下混乱了。
- 同时 `send_message` 报"Not in a team"——也就是 leader 主 agent 自己根本没绑定进该团队。

最终 reviewer 不带 `team_name` / `name` 参数（普通同步 subagent 模式）跑通，写/审分离仍达成，但**没用上 team 异步通信通道**。

### 1.6 网状故障汇总

| 故障表现 | 证据 | 推断原因 |
|---|---|---|
| `send_message` 失效 | 工具返回 "Not in a team" | leader 主 agent 没绑定到 team runtime |
| `team_create` 重建报已存在 | 工具返回 "already exists" | 磁盘 team 残留 + runtime 未自愈 |
| 子 agent 不在 members 列表 | config.json 仅 4 个成员 | spawn 时 team_name 注册未生效 |
| designer 子 agent 没写权限 | 子 agent 自述无 write tool | subagent_name=code-explorer 是只读 |
| "并行" 实际是串行 | task 工具返回同步阻塞 | spawn 模式不是真异步 push |

---

## 2. 后果 / 影响范围

| 阶段 | 受影响 | 实际质量 |
|---|---|---|
| 诊断（diag-code / diag-dpdk） | 仅"并行"声明不实，结论本身正确 | ✅ 合格（产出文件 OK，结论有证据） |
| 仲裁（arbiter） | 仅协作通道未用上，仲裁结论是独立 subagent 完成 | ✅ 合格（位级推导独立复核 OK） |
| 设计（designer → leader 接管） | 子 agent 没写权限被截断丢内容；leader 接管后写出 design_rf.md | ⚠ 协作模式偏离，但 design 文档质量 OK（含核心 v4/v6 串行构造难点） |
| 审核（reviewer） | team 通信失效，改为普通同步 subagent，写/审分离仍达成 | ✅ 审核结论 PASS，独立位级复核 OK |
| **整体根因 / 修复方案** | — | ✅ **结论可靠，不受 runtime 故障影响** |

→ R-F 前半段的**技术结论可信**，但"多智能体并行协作"这个**方法论标签名不副实**。

---

## 3. 用户裁决（2026-06-24）

leader 复盘后向用户暴露此事实，用户明确要求：

1. **修复 team 并行 runtime**：team_delete 清理不一致状态 → 重建 → 验证 `send_message` / 并行 `task` spawn 真能用 → 再继续 R-F 剩余工作（实施 / 编译单测 / SOP / 门禁）。耗时但还原"真并行"。
2. **如实记录**：把"多智能体并行未真正生效"事实落盘 `_rf_work/`（即本文）保证可追溯。

---

## 4. 修复 / 重建计划（执行中）

### 4.1 清理（按规约用脚本，不直接 rm）

- 等所有 idle teammate 走 `shutdown_request` 协议（按规约 leader 不可对未 idle 子 agent 强行 shutdown）。
- `team_delete` 清理 runtime + 磁盘目录。
- 若 team_delete 失败导致 `/data/workspace/.codebuddy/teams/rf-rss-thash/` 仍残留：用 `find` 收集所有文件绝对路径 → `/data/workspace/rm_tmp_file.sh` 多文件清理（不用 `rm -rf`）。

### 4.2 重建 + 自检

- `team_create(team_name=rf-rss-thash-v2)`（避开旧名，规避运行时残留）。
- **并行 spawn 自检**：在同一回合内同时派出 2 个轻量只读 subagent（如各自 list_dir + 摘要），观察 `task` 是否真能并发返回（同步等待两个 Execution Summary）。
- **send_message 自检**：spawn 一个长寿命 subagent，leader 给它 send_message，观察是否报 "Not in a team"。
- 若任一自检失败 → 走 bounce 计数（≤3）：再清理重建一次；连续 3 次失败 → 转人工决策（向用户报障，按规约不私自降级）。

### 4.3 自检通过后才继续剩余 todos

- implement-fix（leader 写代码 + 独立 subagent 审）
- build-and-unittest
- realmachine-sop
- gate-and-commit（本次不 git，仅准备改动）

---

## 6. 修复执行结果（2026-06-24 10:47 实测）

按 §4 执行，全部 PASS（带证据）：

### 6.1 清理

- `team_delete` 报 "Not in a team. Nothing to delete."（leader 上下文丢失，runtime 自身无法清）。
- 改用 `find` + `/data/workspace/rm_tmp_file.sh` 一次性 trash 7 个路径（5 文件 + 2 目录）至 `/data/workspace/.trash/20260624-024701-2035926/`，按规约不直接 `rm -rf`。

### 6.2 重建 + 自检（rf-rss-thash-v2）

| 自检项 | 实测证据 | 结论 |
|---|---|---|
| 真异步并行 spawn | `task` 返回 **"Spawned team member... async execution in the background"**，与旧 runtime 同步阻塞返回 `Execution Summary: ... credits: ...` 完全不同的签名 | ✅ 真 async |
| team_name 注册生效 | `config.json` members = `[team-lead, probe-a@rf-rss-thash-v2, probe-b@rf-rss-thash-v2]`（旧 runtime designer/reviewer 不在 members） | ✅ |
| leader→子 agent send_message | 工具返回 "Message sent to ...'s inbox"（旧 runtime 报 "Not in a team"）；inboxes/probe-{a,b}.json 真有 leader 投递记录 | ✅ |
| 子 agent→leader send_message | inboxes/team-lead.json 共 4 条 probe 发来消息（每个 probe 2 条：自主上报 + 收到 leader 后回报） | ✅ |
| 真并发 | probe-a 02:47:36.424Z + probe-b 02:47:39.909Z 在同一 leader 回合后短时间内分别异步返回 | ✅ |
| 子 agent 持久 daemon | probe 在收到 leader 第二条 send_message 后 02:47:51 / 02:47:54 第二轮回复，证明不是 spawn 完就死 | ✅ |
| shutdown 协议 | shutdown_request 工具返回 "Shutdown request sent... Wait for their shutdown_response. ... force-terminated... timeout" | ✅ 协议齐全 |

→ **结论：rf-rss-thash-v2 multi-agent runtime 可用、真并行、真异步通信。**

### 6.3 影响

后续 R-F 剩余工作（implement-fix / build-and-unittest / realmachine-sop / gate-and-commit）将在此可用 runtime 上以"真并行 + 真协作"方式执行，"多智能体"标签自此名实相符。本 postmortem 与 §6 实测证据共同保证 R-F 全过程可追溯。

---

## 7. plan 类文档修订落点澄清（gatekeeper N3 采纳）

R-F 推进过程中"字节序假设 → key 不一致根因"的修订**实际落在以下两个文档**，而非 `docs/ff_rss_check_opt_spec/zh_cn/plan.md`（plan.md / plan-impl.md 范围限于 R-A/R-B/R-C 既有里程碑）：

- `_rf_work/arbiter_rootcause.md`：仲裁裁决以位级源码推导推翻字节序假设、确立 key 不一致为根因。
- `_rf_work/design_rf.md` 顶部声明 + §1：明确"字节序假设已被位级推翻、作废"，禁止后续 designer/coder 误回头。

`plan.md` 类用户级 plan 文档**本期未改动**。

---

## 8. 真机 OK 后 git 提交注意事项（gatekeeper N1 采纳）

本期 gate 阶段**不 git commit**，等真机验证 OK 后由用户手动通知 leader 提交。提交前**必须** review `git status`/`git diff`，按 AI memory 44404940 规约**只 stage 与 R-F 特性相关**的改动，**剔除本机调试残留**：

- **必 stage（R-F 特性相关）**：
  - `lib/ff_dpdk_if.c`、`lib/ff_config.c`、`lib/ff_config.h`（核心修复）
  - `tests/unit/test_ff_dpdk_if.c`、`tests/unit/test_ff_config.c`（R-F 单测 + 预存 ff_arc4random 链接 stub）
  - `tests/unit/fixtures/valid_rss_check_key_sync_off.ini`（R-F 单测 fixture，新增）
  - `docs/ff_rss_check_opt_spec/zh_cn/_rf_work/*`（R-F 工作日志：design_rf.md、team_runtime_postmortem.md、realmachine_sop.md、arbiter_rootcause.md、diag_*.md）
  - 视用户决策：`docs/ff_rss_check_opt_spec/zh_cn/02/03/04/05/07/09` R-F 章节增补（本期未做，可在 commit 前增补；不增补则单留 _rf_work/）。
- **必排除（本机调试残留，绝对不 stage）**：
  - `config.ini`：本机改动（lcore_mask 1→10、vlan_filter 注释、idle_sleep 0→20、port0 IP→9.134.x 等）—— 与 R-F 无关，**直接命中 AI memory 44404940 强约束**。
  - `lib/Makefile`：`#DEBUG=...` 调试开关取消注释（-O0/-gdwarf-2/-g3）—— 调试构建残留，**与 R-F 无关**。
- **commit message**：英文（按 AI memory 73362122），简短描述路线③ + key_sync 开关 + 多 port 残余风险（design §6.6）。建议 subject ≈ `fix(rss): align rte_thash adjust/check/NIC keys with route③ (key_sync switch)`。

---

## 5. 经验教训

1. **subagent 能力先行确认**：spawn 写任务前必须确认 subagent 类型有写工具，否则交付物会丢（designer 教训）。当前可用 subagent 只有 `code-explorer`（只读），写任务**必须由 leader 主 agent 自己写**或等待平台提供有写权限的 subagent。
2. **team runtime 故障要早暴露**：第一次 `send_message` 报 "Not in a team" 时就该停下来检查 + 暴露给用户，而不是默默改用其他通道继续推进，导致"多智能体并行"标签变虚。
3. **"并行"必须有可观测证据**：`task` 同步返回不等于并行，要看是否有真正"两个 task 同时跑、回合内同时返回 Execution Summary"或异步 send_message 跨回合通信。下次 spawn 后必须做并发证据自检。
4. **写/审分离 vs 并行是两件事**：本次写/审分离逻辑达成（不同 subagent 实例分别写 / 审），这是结论质量的保障；但"并行"是协作效率属性，二者不可混为一谈。
