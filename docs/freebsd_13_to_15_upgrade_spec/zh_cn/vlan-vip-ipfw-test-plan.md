# VLAN + VIP + IPFW_PR 功能测试计划（Plan）

> 本文件：VLAN 双 vlan 配置 + vip_addr/vip_addr6 + ipfw_pr 功能测试 Plan v0.1（2026-06-09）
> 与既有 `plan.md`（Phase-2 功能启用计划）并存，作 follow-up 任务的独立交付文档。
> 工作方式：**Harness 工程化 + Spec 驱动 + 多 Agent Team（1 Leader + 4 子 agent）**
> 输出根目录：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 当前 HEAD：`cb1fe9950`（feature/1.26 ahead 25 vs upstream/feature/1.26，user 已 push 至 ahead 0 状态后再产出本任务）
> 文档语言：中文优先，英文 anchor 在执行收尾时镜像同步

---

## 0. 目标与范围

### 0.1 总目标

在 F-Stack v1.26（FreeBSD 15.0 移植版，phase-2 + phase-5b + F-A1 fix 全部 PASS 之后）上，验证 **VLAN multi-tenant 配置链路**：

1. 配置 `config.test-vlan.ini`（独立测试 config，**不污染 production `config.ini`**）启用 `dpdk.vlan_filter=1,2` + `[vlan1]` + `[vlan2]` 双 vlan section，每段含主 IP、`vip_addr`（≥1 个 VIP）、`ipfw_pr`（1 条简单策略路由）
2. helloworld primary 启动时，能：
    - 正确 parse 双 vlan section（`vlan_cfg_handler`）
    - 为每 vlan `if_clone_create` 出 `f-stack-0.<vlanid>` iface（stdout 含 `Successed to if_clone_create vlan interface`）
    - 把 `vip_addr` 列表全部加到 vlan iface（`ff_veth_setvaddr` 调用成功）
    - 把 `ipfw_pr` 翻译成 `IP_FW_XADD` 装入 ipfw 规则集（`ff_ipfw show` 看到）
3. 上述任一步失败：进入 RCA + 修复循环（最多 3 次跨阶段打回）
4. 第 4 次打回：写 ESCALATION 文档暂停，人工决策

### 0.2 范围边界（用户 q1=D 决定）

| 项 | 本期是否在 scope |
|---|---|
| 配置 parse OK | ✅ in |
| `if_clone_create` vlanN iface | ✅ in |
| `ifconfig`/stdout 看到 vlan iface 上挂主 IP + VIP | ✅ in |
| `ff_ipfw show` 看到 setfib 规则 | ✅ in |
| 本机 loopback ping vip 验证 fib 真生效 | ❌ **F-V1（follow-up）** |
| client → server 802.1Q tagged HTTP 200 + ipfw counter 增长 | ❌ **F-V2（follow-up）** |
| `rte_eth_dev_set_vlan_filter()` HW filter 调用补全 | ❌ **F-V3（follow-up，与 F-V2 联动）** |
| `vlan_strip=1` 与 `nb_vlan!=0` 路径的潜在交互 | ❌ **F-V4（follow-up，risk 已记录）** |

---

## 1. 团队拓扑（4 子 agent + 1 leader）

| 角色 | 主要 skill / subagent | 职责 |
|---|---|---|
| **agent-leader** | `harness-engineering-orchestrator` + `claw-multi-agent` | 总编排；调度 4 子 agent；维护 `BOUNCE_COUNT`；写 plan/execution-log；触发 commit / escalation |
| **spec-writer** | `spec-driven` + `code-explorer` + `RAG_search`（外网+内部 KB）| 产出 `vlan-vip-ipfw-test-spec.md`：配置矩阵 / TC-V1~TC-V5 / 三源 cross-check / risk register |
| **coder** | `c-precision-surgery` | 创建 `config.test-vlan.ini`、`tools/sbin/vlan_test_orchestrator.sh`、`tools/sbin/vlan_test_validate.sh`；如需源码修复，最小 diff 改 `lib/ff_config.c` / `lib/ff_veth.c` 并备份至 `freebsd-src-releng-15.0/f-stack-lib/` |
| **reviewer** | `gitnexus-impact-analysis` + `gitnexus-exploring` + `iwiki-doc` + `RAG_search` | KG 影响面分析 / 调用链 / 三源 cross-check（实际代码 vs spec vs 13.0 baseline）；发现问题打回 coder |
| **gate-keeper** | `gitnexus-debugging`（仅 RCA 时）| 执行 G1~G4：build / start primary / 关键字 grep / `ff_ipfw show` / compliance；任一失败按规则打回 |

### 1.1 状态机 + 打回规则

```
phases:    spec_writing → coding → reviewing → gating → done
escalate:                                              ↓
                                              BOUNCE_COUNT >= 4

bounce 路径：
  reviewer → coder           （bounce#1，artifact 缺陷）
  gate-keeper → coder        （bounce#2，build / G2 / G3 失败）
  gate-keeper → spec-writer  （bounce#3，规格本身有缺陷）
```

`BOUNCE_COUNT >= 4` 即停：leader 写 `vlan-test-ESCALATION-INFO.md`，整理失败 step + stderr + 已试 hypothesis + 待人工决策项。

---

## 2. G1~G4 验收门

| Gate | 命令 / 检查 | 通过判据 | 失败处理 |
|---|---|---|---|
| **G1 Build** | `cd lib && make clean && make` + `cd example && make` | exit=0；`grep -ic 'error:'`=0；warnings 与 baseline（57）持平 | bounce → coder |
| **G2 Startup** | `sudo ./helloworld -c ../config.test-vlan.ini --proc-type=primary --proc-id=0`，`sleep 12 && [ -d /proc/$PID ]` | PID alive=yes | bounce → coder |
| **G3 Functional** | grep helloworld stdout：`Successed to if_clone_create vlan interface` ×2；`ff_veth_setvaddr` 无 ERROR；`ff_ipfw_add_simple_v4` 调用 OK；`ff_ipfw -P 0 show` 列出 vlan1/vlan2 各自的 setfib 规则 | 4 个证据全部命中 | bounce → coder（小 bug）或 spec-writer（规格错） |
| **G4 Compliance** | `grep -E '^[+ ]*(rm |kill |chmod )' commit-diff` + `grep -E '\\brm |\\bkill |\\bchmod ' tools/sbin/*.sh` | 0 hits（除 wrapper 调用）；commit 仅本地 / 未 push | bounce → coder |

每次 G1~G4 全部 PASS：状态 → done，触发 `local-commit` step。

---

## 3. 输入与依赖（已在 plan_create 阶段 verified）

### 3.1 关键代码位置（实际代码 = 唯一事实源）

| 路径 | 行 | 角色 |
|---|---|---|
| `lib/ff_config.h:38` | `DPDK_MAX_VLAN_FILTER 128` | vlan filter 容量上限 |
| `lib/ff_config.h:58` | `VIP_MAX_NUM 64` | vip 上限 |
| `lib/ff_config.h:125` | `struct ff_vlan_cfg` | vlan 配置结构 |
| `lib/ff_config.c:373-377` | `parse_vlan_filter_list` | parse `dpdk.vlan_filter=` |
| `lib/ff_config.c:381-477` | `vip_cfg_handler` / `vip6_cfg_handler` | parse `vip_addr` / `vip_addr6` |
| `lib/ff_config.c:479-538` | `ipfw_pr_cfg_handler`（`#ifdef FF_IPFW`）| parse `ipfw_pr=` |
| `lib/ff_config.c:641-744` | `vlan_cfg_handler` | `[vlanN]` section 总入口 |
| `lib/ff_veth.c:152-200` | `ff_veth_vlan_config` | vlan vip inet_pton |
| `lib/ff_veth.c:551-...` | `ff_ipfw_add_simple_v4` | ipfw 规则装入（v4 only）|
| `lib/ff_veth.c:916-991` | **`nb_vlan!=0` 分支** | vlan iface create + addr/gw/vip/ipfw_pr 一站式（**本任务核心路径**）|

### 3.2 已知约束 / 风险

| ID | 风险 | 影响 | 处置 |
|---|---|---|---|
| R-V1 | `nb_vlan!=0` 时 [portN] 段全跳过 → port0 9.134.214.176 SSH 中断 | server 失联 | 用 **独立 config 文件** + 显式 `-c` 参数；测试期间 host kernel eth1 仍承担 SSH，DPDK 接管期间提示已知影响 |
| R-V2 | `lib/ff_dpdk_if.c` 未调 `rte_eth_dev_set_vlan_filter()` | HW vlan filter 不工作；端到端流量需此函数 | 本期范围 D 不依赖 HW filter；记 F-V3 follow-up |
| R-V3 | virtio-net vlan offload 能力受限 | 端到端时可能需 promisc 加 soft filter | 本期不验证；记 F-V2 follow-up |
| R-V4 | `vlan_strip=1` 与 `nb_vlan!=0` 收包逻辑潜在冲突 | tag 被剥离后 vlan iface 收不到包 | 本期不验证；记 F-V4 follow-up |
| R-V5 | `vlan_cfg_handler` line 668-677 循环结构对 `vlan_index >= nb_vlan_filter` 的判断在循环内部，写法奇怪 | 可能命中错误 vlan_index 路径 | reviewer 阶段 KG 调用链 + 静态读 cross-check |

### 3.3 已有 spec 文档参考

`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/` 38 个文件，新 spec 延续命名（`vlan-vip-ipfw-test-*.md`）与章节风格（参考 `phase2-M*-spec.md`、`Phase-5b-execution-log.md`、`F-A1-fix-execution-log.md`）。

### 3.4 工作区强制规约（每个子 agent 必须遵守，违反即 G4 fail）

- 删除：`/data/workspace/rm_tmp_file.sh <path...>`（**禁** `rm`）
- kill：`/data/workspace/kill_process.sh <pid>`（**禁** `kill/pkill/killall`）
- 加权限：`/data/workspace/chmod_modify.sh +x <file>`（**禁** `chmod`）
- 仅本地 commit，不 push（用户掌控 push 时点）

---

## 4. 阶段产物

| 阶段 | 产物 | Owner |
|---|---|---|
| T1 leader bootstrap | `vlan-vip-ipfw-test-plan.md`（本文件）| leader |
| T2 spec | `vlan-vip-ipfw-test-spec.md` | spec-writer |
| T3 coder | `config.test-vlan.ini` + `tools/sbin/vlan_test_orchestrator.sh` + `tools/sbin/vlan_test_validate.sh` + `freebsd-src-releng-15.0/f-stack-lib/` 备份（如改源码）| coder |
| T4 reviewer | review brief（写入 execution-log §reviewer 段）| reviewer |
| T5 gate | G1~G4 实测证据（写入 execution-log §gate-keeper 段）| gate-keeper |
| T6 终结 | `vlan-vip-ipfw-test-execution-log.md`（成功）OR `vlan-test-ESCALATION-INFO.md`（停止）| leader |
| T7 anchor sync | 4 docs 镜像更新（en/zh L1 架构 + KB summary）| leader |
| T8 commit | local commit | leader |

---

## 5. Follow-up 占位（不在本期 scope）

| ID | 描述 | 优先级 |
|---|---|---|
| **F-V1** | 本机 loopback：在 vlan iface 上 ping/curl vip → 验证 ipfw_pr setfib 真生效 | Medium |
| **F-V2** | 端到端：client 配 802.1Q vlan iface 同段 → curl server vlan vip HTTP 200 + ipfw counter 增长 | Medium |
| **F-V3** | `lib/ff_dpdk_if.c` 补 `rte_eth_dev_set_vlan_filter()` 调用（与 F-V2 联动）| Medium |
| **F-V4** | `vlan_strip=1` × `nb_vlan!=0` 交互验证（HW strip 后 vlan iface 还能收包吗）| Low |
| **F-V5** | `vlan_cfg_handler:668-677` 奇怪循环结构静态/动态确认（可能潜伏 bug）| Low |

---

## 6. 执行启动信号

- 本 plan v0.1 完成 → 进入 T2 spec-writer 阶段
- 任一阶段 BOUNCE_COUNT >= 4 → ESCALATION 暂停
- T1~T8 全 PASS → leader 触发 local commit + 通知用户
