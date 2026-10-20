# F-Stack 软件 LRO/TSO + 硬件对接 —— Spec 完善 Plan（中文）

> 本轮任务：在已完成的**硬件 LRO/TSO offload**（commit d7b194ed3 等，已运行时验证 virtio 不支持而优雅降级）基础上，
> 补齐 **用户态协议栈软件 LRO/软件 TSO** 与 **软件路径 ↔ DPDK 硬件 offload 的对接协同** 的 spec 文档。
> **本轮只写/改中文 spec 文档（docs/lro_tso_spec/zh_cn/），不写代码、不改 lib、不出英文版。**
> 方法：harness 工程 + spec 驱动 + agent team。所有结论以实际代码 file:line 坐实，交叉验证外网，冲突以代码为准。

---

## 0. 背景与范围界定

### 0.1 上一轮已完成（硬件 offload 路径，勿重复）
- config `lro=0/tso=0` 开关、`RTE_ETH_RX_OFFLOAD_TCP_LRO` 硬件 LRO 使能 + `max_lro_pkt_size`
- `IFCAP_LRO` 声明、TSO IPv6 伪头分流、`if_hw_tsomax/segcount/segsize` 上限、tso+csum_skip WARN
- 运行时结论：本机 virtio 不宣告 TSO/LRO 能力（`guest_features=0x110ef8020`），硬件路径优雅降级，软件回退零回归

### 0.2 本轮范围（软件路径 + 对接）
- **软件 LRO（接收端软件聚合）**：FreeBSD `tcp_lro.c` 已编译进 lib（Makefile:513）但**无任何调用点**——完全未接通。需评估在 `ff_veth_input` 收包路径接入软件 LRO（复刻 iflib 的 init/queue/flush/free 模式）。
- **软件 TSO（发送端软件分段）**：坐实"软件 TSO 本质 = 协议栈按 MSS 正常分段"（NIC 无 TSO 时 TF_TSO 不设，tcp_output 自然逐段发）——需评估是否有额外软件分段需求（如 DPDK `rte_gso`）。
- **软件 ↔ 硬件对接**：能力探测优先级、开关语义（硬件优先/软件回退/强制软件）、收发路径的 offload 标记透传与协同、零回归。

### 0.3 已坐实的核心事实（leader plan-mode 已 read_file/search_content 坐实，file:line 为准）

**软件 LRO：**
- `lib/Makefile:513` 编译 `tcp_lro.c`；`lib/Makefile:572` 编译 `tcp_hpts.c`；`tcp_lro_hpts.c` **未在 Makefile**（搜索 0 命中）
- lib/*.c 中 `tcp_lro_rx|tcp_lro_flush|tcp_lro_init|lro_ctrl` **命中 0** → 软件 LRO 无接入点
- `ff_stub_14_extra.c:627` `tcp_hpts_softclock=NULL`；L629-633 `tcp_lro_hpts_init` 返回 0；L635-639 `tcp_lro_hpts_uninit` 空体
- `tcp_lro.c:73` include tcp_hpts.h；`:92` `tcp_lro_flush_tcphpts` 默认 NULL；`:1114-1116` flush 时若 tcp_lro_flush_tcphpts==NULL 走 `tcp_lro_condense`（非 hpts 聚合路径）→ **软件 LRO 核心聚合可脱离 hpts 工作**，hpts 仅 flush 加速
- **iflib 软件 LRO 黄金参考模板**（f-stack 不用 iflib，但这是对接范式）：
  - `iflib.c:462` 每 rxq 一个 `struct lro_ctrl ifr_lc`
  - `iflib.c:6035` init：`tcp_lro_init_args(&ifr_lc, ifp, TCP_LRO_ENTRIES, nentries)`
  - `iflib.c:3000` 每包入队：`tcp_lro_queue_mbuf(&ifr_lc, m)`（`lro_enabled` 门控，L2999）
  - `iflib.c:3029` 批次末 flush：`tcp_lro_flush_all(&ifr_lc)`
  - `iflib.c:6056/6079` free：`tcp_lro_free(&ifr_lc)`
- 核心 API：`tcp_lro_queue_mbuf`（tcp_lro.c:1449）；`tcp_lro_init_args`/`tcp_lro_flush_all`/`tcp_lro_free`（tcp_lro.c 内，行号 M1 复核）

**软件 TSO：**
- `tcp_input.c:3972-3977`：仅当 `cap.ifcap & CSUM_TSO` 时设 `tp->t_flags |= TF_TSO` + `t_tsomax/segcount/segsize`
- `tcp_subr.c:3657-3659`（IPv4）/ `:3699-3701`（IPv6）：仅当 `IFCAP_TSO4/6 && if_hwassist & CSUM_TSO` 才上报 `cap->ifcap |= CSUM_TSO`
- `tcp_output.c:558` `if ((tp->t_flags & TF_TSO) && V_tcp_do_tso && len > tp->t_maxseg ...) tso = 1`；L994 else `tso = 0`
- **结论**：NIC 无 IFCAP_TSO → TF_TSO 不设 → tcp_output 不进 TSO 分支 → 协议栈按 `t_maxseg` 逐段发小包。**"软件 TSO" = 协议栈正常 MSS 分段，天然工作**。额外软件分段（`rte_gso`）为可选加速，非必需。
- `tcp_var.h:789` `#define TF_TSO 0x01000000`

**DPDK 软件 offload 库：**
- `dpdk-stable-24.11.6/lib/gso/`（发送端软件分段，`rte_gso_segment`，gso_types 用 RTE_ETH_TX_OFFLOAD_*_TSO）
- `dpdk-stable-24.11.6/lib/gro/`（接收端软件聚合，`rte_gro_reassemble`）
- f-stack lib 中 `rte_gso|rte_gro` **命中 0** → 未使用

**配置/能力：**
- `ff_config.h` `struct ff_hw_features`：rx_csum(L113)/rx_lro(L114)/tx_csum_ip/tx_csum_l4/tx_tso(L117) 等
- 收包 `ff_veth_input`（ff_dpdk_if.c:1694-1742）；`ff_mbuf_gethdr`（ff_veth.c:464-485）
- 发包 `ff_dpdk_if_send`（ff_dpdk_if.c:2360+）；`ff_mbuf_tx_offload`（ff_veth.c:282-307）

---

## 1. 待完善/新增的文档清单

在 `docs/lro_tso_spec/zh_cn/` 下**修改已有** + **新增**：

| 文档 | 动作 | 内容 |
|------|------|------|
| 02-现状与差距分析.md | 修改 | 补第三/四节：软件 LRO 现状（tcp_lro.c 未接通逐层）、软件 TSO 现状（协议栈分段本质）、软硬对接现状 |
| 03-外网调研.md | 修改 | 补软件 LRO/GRO、软件 TSO/GSO、rte_gso/rte_gro、iflib LRO 范式、软硬 offload 协同的外网资料 |
| 04-方案与架构设计.md | 修改 | 补软件 LRO 接入方案（ff_veth_input 复刻 iflib）、软件 TSO 结论、软硬对接开关语义与优先级 |
| 05-接口与配置设计.md | 修改 | 补软件 LRO 开关配置（如 lro=2 软件/或 sw_lro）、hw_features 字段、接口设计 |
| 06-里程碑与工作清单.md | 修改 | 补软件 LRO/对接的编码里程碑（后续实现阶段） |
| 07-测试与验收规格.md | 修改 | 补软件 LRO/TSO 的单测/集成/端到端验收（lo + f-stack-client） |
| 08-性能基线方案.md | 修改 | 补软件 LRO on/off、软硬对比的性能基线 |
| 09-风险与兼容性.md | 修改 | 补软件 LRO 内存/时延/乱序、hpts stub 依赖、软硬切换风险 |
| **11-软件LRO方案.md** | 新增 | 软件 LRO 专项：tcp_lro API、lro_ctrl 生命周期、ff_veth_input 接入点、hpts stub 影响、与硬件 LRO 的开关协同 |
| **12-软件TSO与分段方案.md** | 新增 | 软件 TSO 本质（协议栈分段）坐实 + rte_gso 可选路径评估 + 结论（是否需开发） |
| **13-软硬offload对接方案.md** | 新增 | 能力探测/开关语义/优先级/回退/收发路径协同/零回归的统一设计 |
| 00-调研结论总览.md | 修改 | 更新总览：新增软件路径 + 对接章节索引与结论 |
| 10-spec评审门禁.md | 修改 | 补软件路径 + 对接的门禁 checklist |

---

## 2. agent team 分工（team: lro-tso-spec2）

- **leader（主 agent）**：统筹 + CM0 事实坐实（已完成大部分）+ 轮询等待（旁路探测优先，禁无超时死等）+ 超时/异常回退 + 纯汇总。可兼任纯调研/探测/汇总等**单一角色**任务。
- **sw-path-explorer（已 spawn）**：软件 LRO/TSO/对接的深度代码探测（A/B/C/D 四维度），已运行。
- **web-researcher（子 agent）**：外网调研（DPDK gso/gro 文档、FreeBSD tcp_lro/iflib、f-stack github issue、软硬 offload 协同博客），产出 03 文档增补素材。
- **design-writer（子 agent）**：写 04/05/11/12/13 方案设计文档（基于 explorer + researcher 素材）。
- **doc-updater（子 agent 或 leader 兼任汇总）**：更新 02/06/07/08/09/00/10。
- **spec-gatekeeper（子 agent，独立审核）**：最终 spec 门禁——代码 vs 文档一致性、file:line 可复核、软硬对接闭环、诚实边界。

**写审分离铁律**：写文档（design-writer/doc-updater）与审核（spec-gatekeeper）必须不同 agent。leader 若亲自写某文档，则该文档审核必须 spawn 独立子 agent。

**轮询/超时/回退**：leader 对每个子 agent 设分钟级超时 + 定时轮询（send_message 询问 + 旁路读文件落盘/git 状态）。子 agent 异常时：leader 接管（接管后审核另派 agent）或 spawn 新子 agent（角色不与下游审核重叠）或按 bounce≤3 转人工。

---

## 3. 执行阶段（里程碑）

- **SM0 事实坐实**（leader + sw-path-explorer）：软件 LRO/TSO/对接现状全部 file:line 坐实 → 汇总
- **SM1 外网调研**（web-researcher）：软件 offload 外网资料 → 03 增补
- **SM2 方案设计**（design-writer）：11/12/13 新增 + 04/05 增补
- **SM3 现状/里程碑/测试/风险文档**（doc-updater / leader 汇总）：02/06/07/08/09 增补
- **SM4 总览/门禁更新**（leader 汇总 + spec-gatekeeper 审核）：00/10 更新
- **SM5 spec 门禁**（spec-gatekeeper 独立审核）：逐项 checklist，bounce≤3
- **SM6 提交**：文档提交本地（英文 commit message 1-3 句，只提交 docs/，不动 config.ini 本地值）

**门禁规约**：任一门禁失败打回上一步修复，同一步骤 bounce≤3，超 3 次转人工。不搁置、不带病放行。

---

## 4. 强制规约（全部沿用，零容忍）
- 实际执行不臆测、代码为准、交叉验证不一致以代码为准
- rm→rm_tmp_file.sh、kill→kill_process.sh、chmod→chmod_modify.sh（make install 类可执行）
- lib 最小注释（本轮不改 lib）；commit message 英文 1-3 句；config.ini 本地测试值不入库
- 本机双网卡：DPDK 独占网卡 IP <DPDK_NIC_IP>（ssh f-stack-client 测），内核栈测 127.0.0.1 的 lo
- 子 agent 全部完成前 leader 严禁提前退出，必须轮询等待

---

## 5. 关键设计问题（待方案文档回答）

1. **软件 LRO 是否值得在 f-stack 接入？** iflib 范式清晰，但 f-stack 单线程 run-to-completion 模型下 lro_ctrl 生命周期如何放置（per-port? per-lcore?）；hpts stub 下 flush 走 condense 路径是否够用。
2. **软件 LRO 开关语义**：新增独立开关（如 `sw_lro`）还是复用 `lro`（lro=1 硬件优先、硬件不支持自动软件回退、lro=2 强制软件）？
3. **软件 TSO 结论**：坐实"协议栈分段天然工作"后，是否还需 rte_gso？（大概率结论：不需要，除非要减少小包 tx 描述符压力，属可选优化）
4. **软硬对接优先级**：硬件优先 + 软件回退的探测/开关协同，如何保证零回归（默认全关时与现状逐字节一致）。
5. **软件 LRO 与硬件 LRO 互斥/叠加**：硬件已聚合的大段再走软件 LRO 是否重复/冲突。
