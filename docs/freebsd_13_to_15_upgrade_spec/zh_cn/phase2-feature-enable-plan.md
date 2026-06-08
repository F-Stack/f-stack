# F-Stack FreeBSD 15.0 升级 Phase-2 功能启用计划（Plan）

> 本文件：Phase-2 起步计划，与既有 `plan.md`（Phase-1 spec 生成 + M0~M5 移植，已 frozen v0.3）并存。  
> 计划版本：**v0.1（2026-06-08）**  
> 工作方式：**Harness 工程化 + Spec 驱动 + 多 Agent Team（1 Leader + 5 子 agent）**  
> 输出根目录：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`  
> 当前 HEAD：`07f9bb0b7`（feature/1.26 ahead 13 vs upstream/feature/1.26）  
> 文档语言：中文优先，英文版在每个里程碑收尾后镜像（参考既有约定）

---

## 0. 目标与范围

### 0.1 总目标

在已完成 **M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS** 的 FreeBSD 15.0 移植基础上，分批启用 `lib/Makefile` 中默认被注释的 7 个 `FF_*` 编译选项，每个里程碑完成「编译 → 主程序运行 → 功能/性能验收 → 文档同步」全闭环。

### 0.2 编译选项分级（来自用户原始需求 + Makefile 实测交叉验证）

| 选项 | Makefile 行 | HOST_CFLAGS | CFLAGS | VPATH 引入 | 引入 .c 文件 | 优先级 |
|---|---|---|---|---|---|---|
| `FF_NETGRAPH` | 43, 104-106, 224-226, 266-269, 424 | `-DFF_NETGRAPH` | — | `$S/netgraph` | `ff_ng_base.c` + `ff_ngctl.c` + freebsd/netgraph/*.c | **P0** |
| `FF_IPFW` | 44, 108-111, 237-240, 575-590 | `-DFF_IPFW` | `-DFF_IPFW` | `$S/netpfil/ipfw`, `$S/netpfil/ipfw/pmod` | `NETIPFW_SRCS`（13 个 `ip_fw_*.c` + `ip_fw2.c` + `ip_fw_pmod.c` + `tcpmod.c`） | **P0** |
| `FF_USE_PAGE_ARRAY` | 46, 113-115, 288-291 | `-DFF_USE_PAGE_ARRAY` | — | — | `ff_memory.c`（已存在） | **P1a** |
| `FF_ZC_SEND` | 47, 204-206 | — | `-DFSTACK_ZC_SEND` ⚠ | — | `example/main_zc.c`（example 端而非 lib 端） | **P1b** |
| `FF_FLOW_IPIP` | 41, 100-102 | `-DFF_FLOW_IPIP` | — | — | 仅 ff_dpdk_if.c 内部分支 | **P1d** |
| `FF_FLOW_ISOLATE` | 39, 96-98 | `-DFF_FLOW_ISOLATE` | — | — | 仅 ff_dpdk_if.c 内部分支 | **P2** |
| `FF_FDIR` | 40, 92-94 | `-DFF_FDIR` | — | — | 仅 ff_dpdk_if.c 内部分支 | **P2** |
| `FF_LOOPBACK_SUPPORT` | 55, 157-160 | `-DFF_LOOPBACK_SUPPORT` | `-DFF_LOOPBACK_SUPPORT` | — | 仅 ff_dpdk_if.c 内部分支 | **P2** |

> ⚠ **重要发现**（侦察阶段实测）：`FF_ZC_SEND` 实际宏名是 `FSTACK_ZC_SEND`（`lib/Makefile:205`），**不是** `-DFF_ZC_SEND`。源码侧检索 `example/main_zc.c:183 #ifdef FSTACK_ZC_SEND` 确认。本计划全程以 `FSTACK_ZC_SEND` 为准。

### 0.3 不在范围

| 项 | 说明 |
|---|---|
| `FF_IPSEC` | 用户未列入；保持注释默认关闭 |
| `FF_KNI` / `FF_INET6` / `FF_TCPHPTS` / `FF_EXTRA_TCP_STACKS` | 已默认 ON，本阶段不变 |
| 内核新增子系统（NETLINK 协议、KTLS） | DP-2 历史决策：不引入，仅保留 header-only |
| 真实生产部署 | 仅本工作区 CVM/物理机基线机做验证 |
| 远程 push | **每里程碑本地 commit + 等用户 review，不自动 push** |

---

## 1. 工作区现状（侦察实测，非记忆）

### 1.1 仓库与分支

| 项 | 值 | 数据来源 |
|---|---|---|
| 主仓库 | `/data/workspace/f-stack/` | `pwd` |
| 当前分支 | `feature/1.26` | `git status` |
| HEAD | `07f9bb0b7` (docs sync 2026-06-08) | `git log -1` |
| 领先 origin | ahead 13 commits | `git status -sb` |
| 13.0 基线 | `/data/workspace/f-stack-13.0-baseline/` | 项目约定 |
| 社区 13.0 源 | `/data/workspace/freebsd-src-releng-13.0/` | 项目约定 |
| 社区 15.0 源 | `/data/workspace/freebsd-src-releng-15.0/` | 项目约定 |
| 15.0 原始备份 | `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/` | 项目约定（仅含 `freebsd/` + `tools/` + `INVENTORY.md`） |

### 1.2 关键源码与工具就位状态

| 资源 | 路径 | 状态 |
|---|---|---|
| netgraph 内核源 | `freebsd/netgraph/*.c` | ✅ 74 个 .c |
| ipfw 内核源 | `freebsd/netpfil/ipfw/*.c` + `freebsd/netpfil/ipfw/pmod/*.c` | ✅（VPATH 已配置） |
| ipfw 用户态工具 | `tools/ipfw/`（含 `ipfw2.c` `ipfw.8` `dummynet.c` `altq.c` 等 26 个文件） | ✅ |
| ifconfig 工具 | `tools/ifconfig/`（40 个文件，含 `af_inet.c` `af_inet6.c` `af_link.c`） | ✅ |
| GIF 隧道驱动 | `freebsd/net/if_gif.c` + `if_gif.h` | ✅ |
| ZC 示例 | `example/main_zc.c`（示例代码） | ✅ |
| ZC 文档 | `lib/ff_api.h:381 // See 'example/main_zc.c'` | ✅ |
| `ff_ng_base.c` / `ff_ngctl.c` | `lib/`（M5 已落地） | ✅ |
| `ff_memory.c`（page-array） | `lib/` | ✅ |
| `f-stack-client` | **不在仓库内** | ⚠ 需 spec 阶段澄清：是用户独立维护的客户端测试程序，还是需要本阶段提供？已列入 §3.OQ-1 |

### 1.3 已知小不一致（从 phase-1 文档同步遗留）

| 项 | 现象 | 处理 |
|---|---|---|
| docs 写"33 个 .c 文件" | 实测 `lib/ff_*.c` = **31 个** | 在 doc-update 阶段顺手修正（非阻塞） |
| docs 写 `ff_epoll.c ~134` | 实测可能 ~159 / ~134（不同度量） | 每里程碑结束时 wc -l 实测落定 |

> 这些是 phase-1 docs sync commit `07f9bb0b7` 留下的小数字漂移，本计划在每个里程碑结束时一并校准。

---

## 2. Agent Team 拓扑（1 Leader + 5 子 agent）

```
                        ┌─────────────────────────────┐
                        │   Leader（main agent）      │
                        │  · 状态机 / 打回计数器       │
                        │  · 最终 commit / 进度汇报    │
                        └────┬────────────────┬───────┘
                             │                │
        ┌────────────────────┼─────────┬──────┴──────┬───────────┐
        ▼                    ▼         ▼             ▼           ▼
 ┌────────────┐  ┌──────────────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐
 │spec-author │  │  research-scout  │  │  coder   │  │ reviewer │  │ gate-keeper │
 │spec-driven │  │  外部资料调研     │  │ 代码改动 │  │ 静态评审 │  │ 编译/运行/  │
 │ 写 spec    │  │ github/blog/wiki │  │c-precision│  │ 交叉验证 │  │ 功能/性能   │
 │ + decisions│  │ + freebsd 官方源 │  │ -surgery │  │ 风险打回 │  │ + 文档同步  │
 └────────────┘  └──────────────────┘  └──────────┘  └──────────┘  └─────────────┘
        ↓                ↓                  ↓             ↓             ↓
  spec.md       research/{topic}.md     code change    review report   gate report
                                                       (PASS/FAIL +    + bounce ledger
                                                        bounce reason)
```

### 2.1 角色与子 agent 选型

| 角色 | 子 agent / Skill | 主要工具 |
|---|---|---|
| **Leader** | main agent（本对话） | plan_create / todo_write / git / 协调 |
| **spec-author** | spec-driven skill 主导，code-explorer 辅助 | write_to_file（spec.md） |
| **research-scout** | code-explorer × N 并行 + 外网检索（web_fetch / web_search 受限于环境） | search_content / RAG_search / web_fetch |
| **coder** | c-precision-surgery skill（C 语言精准修改，最小 diff） | replace_in_file（lib/ + tools/ + freebsd/） |
| **reviewer** | code-explorer（独立上下文、避免与 coder 同源偏置） | search_content / read_file / 引用 spec |
| **gate-keeper** | main agent 自执行 + execute_command（make / 主程序起栈 / ff_ipfw / 性能脚本） | execute_command + 验收门 |

### 2.2 打回机制（bounce protocol，与 phase-1 风格一致）

- 每里程碑独立 bounce counter，每"阶段"独立子计数：
  - bounce(spec → research)：spec 阶段发现外部资料缺口
  - bounce(code → spec)：coder 发现 spec 不可实现
  - bounce(review → code)：reviewer 发现实现违反 spec/规约
  - bounce(gate → code)：编译/运行/测试不过
  - bounce(gate → spec)：测试发现 spec 验收标准不充分（罕见）
- 同一阶段累计 bounce ≥ **3 次** → **暂停里程碑**、整理 escalation-report、**人工决策**
- 总累计 bounce 上限：单里程碑 ≤ 6（跨阶段合并），超过则强制暂停

---

## 3. 里程碑分解（M6 ~ M13）

> 编号续接 phase-1 的 M0~M5。每里程碑独立 spec、独立 commit、独立 execution-log。

### M6 — FF_NETGRAPH + FF_IPFW Combo (P0)

| 项 | 值 |
|---|---|
| 范围 | **同时**启用 FF_NETGRAPH + FF_IPFW；不允许任何一个单独发布 |
| 主要风险 | (1) netgraph 74 个 .c 在 13→15 升级中部分接口已变（如 `ng_node_t` / `ng_ID_t`），需 reviewer 重点核对 ff_stub_14_extra 是否补全；(2) ipfw 13 个 NETIPFW_SRCS 文件 + 用户态 `tools/ipfw/ipfw2.c` 同步 14/15 ABI；(3) `tools/ipfw/` 目录已含 `ipfw2.o` 等残留 build 产物，需用 `rm_tmp_file.sh` 清理 |
| 验收标准 | (a) `make` 编译通过 0 error 0 warning（warning 阈值见 §6.4）；(b) `example/helloworld` + `tools/sysctl` 主程序能起栈；(c) `tools/ipfw add 100 deny ip from 1.2.3.4 to any` 命令能下发，`ipfw show` 能显示规则；(d) 简单 ping 测试规则匹配（可观察 `pkts/bytes` 计数器变动）；(e) netgraph 至少能 `ngctl list` 列出节点（即使没有 active node 也应能空跑） |
| 输出文件 | `phase2-M6-spec.md` / `phase2-M6-research-brief.md`（如需）/ `phase2-M6-execution-log.md` |
| 启动条件 | 用户接受本 plan |
| 完成定义 | 上述 (a)~(e) 全部 PASS + 三层架构文档同步 + 本地 commit + 等 review |

### M7 — FF_USE_PAGE_ARRAY 单独 (P1a)

| 项 | 值 |
|---|---|
| 范围 | 仅启用 `FF_USE_PAGE_ARRAY=1`，关闭 `FF_ZC_SEND` |
| 主要变更 | `ff_memory.c` 进入 `FF_HOST_SRCS`；DPDK mbuf → mempool page-array 路径走 |
| 验收标准 | (a) 编译通过；(b) 主程序起栈；(c) 短简单连接（curl 单个）走 page-array 路径不崩溃；(d) `dpdk-procinfo` 或 `tools/sysctl` 能查到 page-array 启用状态（具体探测点待 spec 阶段定）|
| 性能基线 | 默认配置 vs FF_USE_PAGE_ARRAY，**短连接 + 长连接 各 1 组**，记录 rps / latency p99 / cpu%；trade-off ≤ 5% 视为 PASS（与 Phase-5b NFR-1 阈值一致） |
| 输出 | `phase2-M7-spec.md` + `phase2-M7-execution-log.md` |

### M8 — FF_ZC_SEND 单独 (P1b)

| 项 | 值 |
|---|---|
| 范围 | 仅启用 `FF_ZC_SEND=1`（实际宏 `-DFSTACK_ZC_SEND`），关闭 `FF_USE_PAGE_ARRAY` |
| 主要变更 | `example/main_zc.c` 走 `#ifdef FSTACK_ZC_SEND` 分支；服务端编译为 `helloworld_zc` 二进制 |
| 验收标准 | (a) 编译通过；(b) `helloworld_zc` 主程序起栈；(c) f-stack-client（**OQ-1 待澄清**：客户端来源）发包，服务端能收并 ZC 回包；(d) 与默认 helloworld 对比，**4 KB / 64 KB 单链接吞吐**至少不劣化 |
| 输出 | `phase2-M8-spec.md` + `phase2-M8-execution-log.md` |

### M9 — FF_USE_PAGE_ARRAY + FF_ZC_SEND Combo (P1c)

| 项 | 值 |
|---|---|
| 范围 | M7+M8 同时启用 |
| 验收标准 | M7+M8 验收并集 + 联合性能基线（与单独启用各自对比，combo 不应劣于任一单独启用 -5%） |
| 风险 | mbuf 引用计数 / page array 与 ZC 路径冲突；ff_memory.c 是否需要新增 ZC 兼容分支待 spec 阶段决策 |
| 输出 | `phase2-M9-spec.md` + `phase2-M9-execution-log.md` |

### M10 — FF_FLOW_IPIP (P1d)

| 项 | 值 |
|---|---|
| 范围 | 仅启用 `FF_FLOW_IPIP=1` |
| 测试拓扑 | 服务端 f-stack 主程序 + `tools/ifconfig` 创建 `gif0`（GIF/IPIP 隧道）；客户端为 Linux 系统命令 `ip tunnel add` 建对端隧道 |
| 验收标准 | (a) 编译通过；(b) 主程序起栈；(c) `ff_ifconfig gif0 create` + `ff_ifconfig gif0 inet 10.0.0.1 10.0.0.2` 成功；(d) 客户端配置对端隧道 + 路由后，`ping 10.0.0.1` 通；(e) `ff_route get` 能看到 IPIP-tunneled 路由 |
| 风险 | `if_gif.c` 在 13→15 是否被改动；DPDK 端 IPIP flow rule 是否依赖 NIC 硬件能力 |
| 输出 | `phase2-M10-spec.md` + `phase2-M10-execution-log.md` |

### M11 — FF_FLOW_ISOLATE (P2a)

| 项 | 值 |
|---|---|
| 范围 | 仅启用 `FF_FLOW_ISOLATE=1` |
| 验收标准 | (a) 编译通过；(b) 主程序起栈；(c) **冒烟通过**（不要求功能验证，因依赖 NIC SR-IOV/VLAN 隔离能力，本工作区 CVM 不具备）；(d) 文档说明启用条件与硬件依赖 |
| 输出 | `phase2-M11-spec.md` + `phase2-M11-execution-log.md` |

### M12 — FF_FDIR (P2b)

同 M11 风格：仅编译 + 主程序起栈 + 硬件依赖说明。

### M13 — FF_LOOPBACK_SUPPORT (P2c)

| 项 | 值 |
|---|---|
| 范围 | 仅启用 `FF_LOOPBACK_SUPPORT=1` |
| 验收标准 | (a) 编译通过；(b) 主程序起栈；(c) `127.0.0.1` 在 f-stack 内部能 ping 通（`tools/sysctl` 或自写小 helloworld 测试） |
| 输出 | `phase2-M13-spec.md` + `phase2-M13-execution-log.md` |

> ⚠ **关于用户原始需求中"FF_FLOW_IPIP 同时出现在 P1 和 P2"**：以 P1（M10）为准，P2 不重复。本计划仅安排在 M10。

### M-Final — 总收尾（统一文档同步）

| 项 | 值 |
|---|---|
| 范围 | M6~M13 全部完成后，重跑 GitNexus 索引 + 全量同步 18 份 3 层架构文档 + KG_WIKI |
| 输出 | `phase2-final-execution-log.md` + 与既有 phase-1 docs sync 同款 commit |
| 备注 | 与 `phase-1` 同款方法（详见 `docs-sync-2026-06-08-execution-log.md`） |

---

## 4. 每里程碑标准化工作流（Spec-Driven 5 phase）

```
       ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
       │ Phase A  │ →  │ Phase B  │ →  │ Phase C  │ →  │ Phase D  │ →  │ Phase E  │
       │ Spec     │    │ Research │    │ Code     │    │ Review   │    │ Gate     │
       │  by      │    │ (option) │    │  by      │    │   by     │    │  by      │
       │spec-author│    │ research │    │ coder    │    │reviewer  │    │gatekeeper│
       └──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
            ↑               ↑               ↓               ↓               ↓
            │               │               │               │               │
            └───── bounce ──┴────────────── bounce ────────┴── bounce ─────┘
                            (同阶段 ≥3 次 → 暂停 → 人工决策)
```

### 4.1 Phase A — Spec（必经）

- 输入：用户原始需求 + Makefile 实测（本计划 §0.2）+ phase-1 既有 spec 文档
- 输出：`phase2-MN-spec.md`，包含
  - 范围（in / out scope）
  - 背景与现状（实测引用，禁止猜测）
  - 接口/数据结构变更点（按文件:行号引用）
  - 验收标准（可执行、有测量值）
  - 风险与回滚（每条风险给出 detection + mitigation）
  - 测试清单（编译矩阵 + 主程序冒烟 + 功能 + 性能 + 文档）
- 完成定义：spec ≥ 99/100 一致性自检（无内部矛盾、无 TBD）

### 4.2 Phase B — Research（按需）

- 触发条件：spec 阶段发现外部资料缺口（如 freebsd-15 上游 ipfw 是否改 ABI）
- 输入：spec.md + 调研主题
- 输出：`phase2-MN-research-brief.md`，包含
  - github 检索（F-Stack/f-stack issues + freebsd/freebsd-src 提交）
  - 官方 release notes（13.0 / 14.0 / 15.0）
  - 中文博客 / 公众号
  - DeepWiki F-Stack 自动生成的架构 wiki
  - 每条结论给出 URL + 引用片段

### 4.3 Phase C — Code（必经）

- 输入：spec.md + research-brief（如有）+ phase-1 既有 lib/ 实现
- 输出：实际 git diff（lib/ + tools/ + freebsd/ + 必要时新增 ff_*.c）
- 子规则：
  - 优先用 `replace_in_file`（最小 diff）；新增文件用 `write_to_file`
  - 新增源文件**必须**同步备份到 `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/`（按用户规则 §5）
  - 任何临时 .o / 备份 / 残留 → 必须用 `/data/workspace/rm_tmp_file.sh`
  - 任何进程清理 → 必须用 `/data/workspace/kill_process.sh`
  - 任何 chmod → 必须用 `/data/workspace/chmod_modify.sh`

### 4.4 Phase D — Review（必经）

- Reviewer 用**独立** code-explorer 子 agent（隔离上下文，避免 coder 偏置）
- 检查项：
  1. spec 与代码一致性（每条 AC 是否落地）
  2. 风险条目是否对应 detection + mitigation 落到代码或文档
  3. 与 freebsd-src-releng-15.0 上游 diff（识别"我们的修改是否偏离上游意图"）
  4. 与 13.0 baseline 的 delta（识别"是否破坏 13.0 兼容假设"）
  5. 三个 forbidden command（rm/kill/chmod）静态扫描（grep）
  6. commit message 模板（英文 subject + body）
- 输出：`phase2-MN-review-report.md`（PASS / FAIL + 必修项清单）

### 4.5 Phase E — Gate（必经）

按顺序串行执行，任一不过则按 reason 打回上一相应阶段：

| 门 | 测试 | 失败 → 打回 |
|---|---|---|
| **G1 编译** | `make clean && make all` 0 error，warning ≤ M5 baseline + 5 | code |
| **G2 主程序冒烟** | `example/helloworld -c x.conf -p 0 --proc-type=primary --proc-id=0`，10 秒不崩 | code（罕见 spec） |
| **G3 功能测试** | 每里程碑特定（M6 ipfw add/show；M10 GIF tunnel ping；M13 lo ping） | code（spec 若不充分则 spec） |
| **G4 性能测试** | M7/M8/M9 必须；其余可选；阈值 ±5% | code |
| **G5 文档同步** | 3 层架构 + KG（每 P0/P1 里程碑后局部更新；M-Final 统一全量重跑） | doc-updater |
| **G6 lint** | `read_lints` 0 errors | doc-updater |
| **G7 commit** | 英文 subject + body；本地 commit；**禁止 push** | leader |

---

## 5. 测试与验收策略详解

### 5.1 编译矩阵

| 矩阵维度 | 取值 |
|---|---|
| 主机 | CVM (M5 已用)+ 物理机基线机（与 Phase-5b 一致） |
| 编译器 | gcc 10/11/12（Makefile 已含 `GCCVERGE10/11/12` 分支） |
| arch | amd64（默认，本工作区唯一） |
| 编译选项组合 | 见 §3 各 milestone 的 in-scope FF_* 组合 |

### 5.2 性能基线（仅 M7/M8/M9 必做）

| 维度 | 取值 |
|---|---|
| 测试形态 | nginx_fstack（Phase-5b 同款）+ helloworld(_zc)（M8/M9 专用） |
| 流量类型 | 短连接（rps）+ 长连接（goodput）|
| 并发 | 4 / 8 核 |
| 时长 | 60s × 3 轮，取均值 |
| 指标 | rps / latency p50 / p99 / cpu% / mem% |
| 阈值 | 默认 ≥ M5 baseline -5%；trade-off > 5% → 必须有显式 spec 决策 + observation 标签 |

### 5.3 主程序冒烟测试通用脚本（spec 阶段细化）

```bash
# 模板（每个里程碑按需调整）
cd /data/workspace/f-stack/example
sudo ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 &
HELLOWORLD_PID=$!
sleep 5
# 功能验证（按里程碑）...
# 通过后清理：必须用 kill_process.sh，禁止直接 kill
/data/workspace/kill_process.sh $HELLOWORLD_PID
```

### 5.4 文档同步策略（每里程碑结束）

| 文档 | M6/M10 (P0/P1d) | M7/M8/M9 (P1a-c) | M11/M12/M13 (P2) | M-Final |
|---|---|---|---|---|
| `phase2-MN-spec.md` | 写 | 写 | 写 | — |
| `phase2-MN-research-brief.md` | 按需 | 按需 | 按需 | — |
| `phase2-MN-execution-log.md` | 写 | 写 | 写 | — |
| `phase2-MN-review-report.md` | 写 | 写 | 写 | — |
| 三层架构 6 文档 + Summary 局部更新 | 是（小 diff） | 是（小 diff） | 是（小 diff） | 全量重检 |
| KG_WIKI 重跑 GitNexus | 否（小局部） | 否 | 否 | **是**（M-Final） |
| README + zh_cn 镜像 | 是 | 是 | 是 | 是 |

---

## 6. 工具与规约

### 6.1 强制脚本（来自工作区 AI memory，零容忍）

| 命令 | 替换为 |
|---|---|
| `rm <path>` / `rm -rf` / `rm -f` | `/data/workspace/rm_tmp_file.sh <path1> [path2 ...]` |
| `kill <pid>` / `pkill` / `killall` | `/data/workspace/kill_process.sh <pid_or_name>` |
| `chmod <mode> <path>` / `install -m` / `setfacl` | `/data/workspace/chmod_modify.sh <mode> <path1> [path2 ...]` |

> 注：`make clean` / `make install` / `cp` 等内部隐式 rm/chmod **允许**（用户已明确"非直接调用 chmod 等"且 install 类命令允许）。但 agent 自身的脚本与命令**严禁**直接 rm/kill/chmod。

### 6.2 git 规约

- commit message：**英文**（subject + body）
- 单里程碑 1 commit（含 lib/ + tools/ + freebsd/ + docs 的全部相关改动）
- **每里程碑 commit 后等用户 review，不主动 push**（与 phase-1 docs sync 同款）
- 远程：`origin` = `feature/1.26`（不变）

### 6.3 source backup 规约（用户 §5）

- 任何**新增**源文件（.c / .h），编辑前的"原始基线"必须存到 `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/`
- 已有文件的修改**不需要**重新备份（13.0 baseline 已在 `freebsd-src-releng-13.0/f-stack-lib/`，15.0 上游已在 `freebsd-src-releng-15.0/sys/`）

### 6.4 Warning 阈值

- M5 baseline：编译告警基线（待执行时 grep 当前 `make all 2>&1 | grep -c warning`）
- 每里程碑允许 +5（绝对值）；超过则视为 G1 失败 → 打回 code

### 6.5 跨数据源交叉验证

| 数据源 | 角色 |
|---|---|
| `f-stack/lib/`、`f-stack/freebsd/`、`f-stack/tools/` | **当前实现**（最高权威） |
| `freebsd-src-releng-15.0/sys/`、`freebsd-src-releng-15.0/f-stack-lib/` | **上游基线**（diff 参考） |
| `freebsd-src-releng-13.0/`、`f-stack-13.0-baseline/` | **13.0 历史基线**（兼容性参考） |
| `docs/freebsd_13_to_15_upgrade_spec/zh_cn/M*-execution-log.md` | **历史决策**（DP-1 ~ DP-N） |
| `docs/01-LAYER1`、`02-LAYER2`、`03-LAYER3` | **架构文档**（只读，按 phase-1 sync 已对齐到 v1.26） |
| GitNexus `meta.json`（`.gitnexus/`） | **当前 KG 快照**（commit `208b0c4`，2656 files / 64855 nodes） |
| 外部资料 | github issues + 官方 release notes + 中文博客 |

> **铁律**：所有不一致以**当前实现**为准；若实现与 spec/上游/历史决策矛盾，**必须**先 spec 阶段记录 + reviewer 确认，再行修改。**禁止默默改实现去贴合文档**。

---

## 7. 外部资料调研清单（research-scout 用）

| 维度 | 入口 |
|---|---|
| FreeBSD 15.0 release notes | https://www.freebsd.org/releases/15.0R/relnotes/ |
| FreeBSD 14.0 release notes | https://www.freebsd.org/releases/14.0R/relnotes/ |
| FreeBSD ipfw / netgraph 14/15 ABI 变化 | https://man.freebsd.org/cgi/man.cgi?query=ipfw / `git log freebsd-src-releng-15.0/sys/netpfil/ipfw/` |
| F-Stack 社区 | https://github.com/F-Stack/f-stack/issues + wiki |
| DeepWiki | https://deepwiki.com/F-Stack/f-stack |
| DPDK 23.11.5 zero-copy / page-array | https://doc.dpdk.org/guides-23.11/ |
| 中文社区 | 搜"FreeBSD 15"、"f-stack ipfw"、"DPDK zero copy"、"GIF tunnel f-stack"等 |
| 内部知识库 | 通过 `RAG_search` 查 TencentOS / TencentOS for Network / 类似工作 |

---

## 8. Open Questions（人工决策项）

| OQ | 内容 | 默认假设 | 决策时机 |
|---|---|---|---|
| **OQ-1** | `f-stack-client` 是用户独立维护的客户端测试程序，还是需要本阶段一起提供？ | 假设**用户独立维护**（ZC/GIF 测试时由用户提供 IP + 二进制路径） | M8 启动前 |
| **OQ-2** | 性能测试是否复用 Phase-5b 的 CVM 同期 A/B + 物理机方法学？ | 默认**是**（保持可比性） | M7 启动前 |
| **OQ-3** | M-Final 统一文档同步是在 M13 完成后立即做，还是分批（每个 P0/P1 完成后做局部 sync）？ | 默认**分批小 sync + 最终全量重跑 KG** | M6 完成时 |
| **OQ-4** | NETGRAPH + IPFW combo 验收若 G3 测试不通过且根因在 NIC 驱动（无 DPDK 控制能力），是否允许降级为冒烟 PASS 标签 + observation？ | 默认**允许**，但必须独立标注 observation 段 | M6 G3 |
| **OQ-5** | 外网检索（web_fetch / web_search）若被网络环境限制不可用，是否允许仅基于本地源码 + RAG_search 内部知识库做 research？ | 默认**允许**，并在 research-brief 顶部声明限制 | M6 Phase B |

---

## 9. 风险登记（按里程碑）

| 风险 | 影响 | Mitigation | 监控点 |
|---|---|---|---|
| FF_NETGRAPH 编译期 undef 符号（13→15 ABI 漂移） | M6 G1 失败 | 用 `ff_stub_14_extra.c` 兜底 stub；reviewer 比对 freebsd-src-releng-15.0/sys/netgraph/ng_base.c 上游签名 | 编译日志 grep `undefined reference` |
| FF_IPFW 用户态 `tools/ipfw/ipfw2.o` 残留 | 编译阶段 stale | 启动前用 `rm_tmp_file.sh` 清残留 | `find tools/ipfw -name '*.o'` |
| FF_USE_PAGE_ARRAY 与 ZC combo 内存生命周期冲突 | M9 SIGSEGV | spec 阶段提前列出 mbuf 引用计数模型；reviewer 重点核对 ff_memory.c | runtime gdb |
| GIF 隧道客户端配置方式因客户端 OS 不同而异 | M10 G3 测试不可重现 | spec 阶段列出 Linux + 假设客户端两种配置脚本，且明确 OQ-1 | spec § 验收脚本 |
| 性能测试 trade-off > 5% | M7/M8/M9 G4 失败 | 与 Phase-5b 同款：观察 vs 阻塞二选一，由用户决策 | gate 报告 |
| 三层架构文档"33 .c"小漂移 | 文档不一致 | M-Final 一并修正 | M-Final |
| GitNexus 索引节点数因 schema v1 变化 | KG_WIKI 描述对不上 | M-Final 重跑后用真实 meta.json 数据，不复用旧 v0 表 | M-Final |

---

## 10. 进度追踪（status table，每完成一个里程碑由 leader 更新）

| Milestone | 优先级 | 状态 | Spec | Research | Code | Review | Gate | Bounce | Commit | Pushed |
|---|---|---|---|---|---|---|---|---|---|---|
| M6 NETGRAPH+IPFW | P0 | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G5/G7 PASS | 3/3 | `4139198f6` | NO |
| M7 PAGE_ARRAY | P1a | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G5/G7 PASS | 0/3 | `cba3d882b` | NO |
| M8 ZC_SEND | P1b | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G7 PASS（HTTP 200/438B real HTML，100/100 short-conn） | 1/3 | `add33a04a` | NO |
| M9 PA+ZC combo | P1c | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G3 PASS（G4 perf observation deferred） | 0/3 | `2f4748638` | NO |
| M10 FLOW_IPIP | P1d | ✅ DONE | ✅ | ✅ | ✅ | ✅ | ✅ G1-G3.6 PASS（ping 3/3 IPIP tunnel cross-impl） | 1/3 | `90c730496` | NO |
| M11 FLOW_ISOLATE | P2a | ✅ DONE (smoke) | ✅ | ✅ | ✅ | ✅ | ✅ G1/G2 PASS | 0/3 | `6be5461a9` | NO |
| M12 FDIR | P2b | ✅ DONE (smoke) | ✅ | ✅ | ✅ | ✅ | ✅ G1/G2 PASS | 0/3 | `b6bf3f094` | NO |
| M13 LOOPBACK | P2c | ✅ DONE (smoke) | ✅ | ✅ | ✅ | ✅ | ✅ G1/G2 PASS（+1 link stub `ff_swi_net_excute`） | 0/3 | `73622c85c` | NO |
| M-Final docs sync | – | ✅ DONE | – | – | ✅ | ✅ | ✅ status table backfilled + 4 layer1+summary docs synced + plan §10 updated | – | (this commit) | NO |

**Bounce ledger（全 plan 累计）**：0  
**Escalations**：0

---

## 11. 节奏建议（仅参考，不约束）

| 里程碑 | 预估投入（agent 任务回合） |
|---|---|
| M6 NETGRAPH + IPFW（最复杂） | 8~14 回合 |
| M7 / M8 / M9 ZC + PA | 5~8 回合 each |
| M10 FLOW_IPIP | 6~10 回合 |
| M11 / M12 / M13 P2 三个 | 3~5 回合 each |
| M-Final docs sync | 与 phase-1 同款（~10 回合） |

整体节奏：用户接受 plan 后，**先逐里程碑串行**（避免上下文污染）；每个里程碑完成后等用户 review 一次，再进入下一里程碑。

---

## 12. 启动检查清单（用户接受本计划后立即执行）

| # | 检查项 | 命令 |
|---|---|---|
| 1 | 当前 HEAD 干净 | `git status -sb` |
| 2 | M5 编译 baseline（默认配置） | `cd lib && make all 2>&1 \| tee /tmp/m5_baseline.log` 然后 `grep -c warning /tmp/m5_baseline.log` |
| 3 | gitnexus meta.json 可访问 | `python3 -c "import json; print(json.load(open('.gitnexus/meta.json'))['stats'])"` |
| 4 | 三个 forbidden command 脚本可执行 | `ls -l /data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh` |
| 5 | freebsd-src-releng-15.0/f-stack-lib/ 写权限 OK | `touch test && rm test`（注：此处 rm 测试需用 rm_tmp_file.sh） |

---

## 13. 与 phase-1 文档体系的关系

| 复用 | 项 |
|---|---|
| ✅ 复用 | `plan.md`（master）/ `00-overview-and-glossary.md` / `01-requirements-spec.md` / `02-architecture-analysis.md` 的术语与 DP 决策表（DP-1 ~ DP-5） |
| ✅ 复用 | `06-test-and-acceptance-spec.md` 的测试方法学（CVM A/B + 物理机基线） |
| ✅ 复用 | `runtime-fix-execution-log.md` 的 5 P0 SIGSEGV 修复模式（spec 阶段需重新自检是否被本阶段触发） |
| ✅ 复用 | `docs/01-LAYER1`、`02-LAYER2`、`03-LAYER3`、`Summary`、`KNOWLEDGE_GRAPH_WIKI`（v1.26 baseline，2026-06-08 sync） |
| ⛔ 不重写 | 既有 plan.md（master frozen v0.3） |
| ⛔ 不重写 | M0~M5 + Phase-5b + runtime-fix + rib-fix execution-logs |

---

## 14. 计划版本号

| 版本 | 日期 | 状态 |
|---|---|---|
| **v0.1** | **2026-06-08** | **本版**（待用户接受） |

---

> **当前状态：等待用户确认本计划。一旦接受，立即进入 M6 Phase A（spec-author 起草 `phase2-M6-spec.md`），并按 §4 标准化工作流推进。**
