# 07 里程碑规划：M0~M7 里程碑与编码工作清单

| 项 | 值 |
|---|---|
| 文档编号 | 07 |
| 标题 | Nginx 无损 reload（S3 方案）里程碑规划与后续编码工作清单（C-NR-100~604） |
| 版本 | v1.9（M3 实现批注） |
| 日期 | 2026-09-02 |
| 状态 | 待人工审计（v1.4 人工决策落盘） |
| 对齐基线 | [06-方案设计](06-solution-design.md) **v1.9.1**（v1.6：同队列 + 同期接管 + flow_map；**v1.9.1 人工决策：D-A 反转为两代同 lcore_id ⇒ 取消四链解耦/代际 lcore 池（C-NR-311、DR5），自驱 hardclock 与代际 mempool 恢复为必需项（C-NR-307/308/314/315），新增心跳与 rx 交还（C-NR-316）**；M1′ 单硬件所有者 + G_old 软件寄生 + 双向 drain_ring 维持不变） |
| 来源产物 | work/milestones-testing.md（规划师 milestone-planner，2026-08-18 落盘）。本篇为其里程碑与编码工作清单部分的正式化改写；测试计划部分拆分至 [08-测试计划](08-testing.md)。输入：[06-方案设计](06-solution-design.md)（推荐方案 S3，含四层所有权模型、T0-T5 时序、接口面清单 5.4、RV1-10、DR1-7——**v1.9 已扩展为 RV1-14 / DR1-10**）、[04-现状分析](04-fstack-current-analysis.md)（8 项障碍清单）、[01-VPP/VCL 调研](01-vpp-vcl-research.md)（§6.3-7 VPP 验证模式）、[03-旧方案考证](03-fstack-legacy-solution.md)（旧方案失败教训）；对齐 docs/primary_slim_spec/zh_cn/ 里程碑切分粒度 |
| 修订记录 | v1.1（2026-08-21）：据 [06] v1.6 贯通——删除乒乓双队列段与 reta 切流，M3 改为同期移交+flow_map。v1.2（2026-08-31）：据 [06] v1.7 贯通——M2 新增 C-NR-307 自驱 hardclock / C-NR-308 应用 mempool 分代际，编码点总数 35→37；删除已废弃的 RV2/DR3，新增 RV10；修正 M0 一票否决项、8 项障碍消解机制、DAG 与全部残留的「乒乓/reta/原子切流」表述。**v1.3（2026-09-01）：据 [06] v1.9 交叉审核贯通**——新增 5 个编码点（C-NR-309~313）承载 M1′ 形态与 6 项缺陷修复，编码点总数 37→42；C-NR-307/308 由必需降为**加固项**；M3 改为「同期接管 + TX 独占 + 双向 drain_ring」；新增 RV11~14 与 DR8~10；DR6 新增「T3 后 G_new 崩溃」必答项；统一 lcore_id 口径为「两代不同 lcore_id」。**v1.4（2026-09-01）：人工决策反转 D-A = 两代使用相同 lcore_id** ⇒ 取消 C-NR-311 与 DR5（代际 lcore 池/四链解耦），P0-3 随之消解；C-NR-307 自驱 hardclock 与 C-NR-308 代际 mempool **恢复为 M2 必需项**，308 细化拆分为 C-NR-314（应用侧）+ C-NR-315（共享 RX 池）；新增 C-NR-316（心跳检测 + rx 交还，DR6 定案①）；新增 DR11（RX 池 M-A/M-B）与 RV15；编码点 42 → **43**（M2 12→13：+314/315/316，−311，308 转索引不计数）。**v1.4 门禁修正（据独立门禁审核 G1）**：修正 7 项 D-A 反转口径残留（摘要计数、障碍 8、C-NR-201/307 表述、M2 风险表、DAG）、修正「45」为「43」的算术错误。**v1.5（2026-09-02）：DR11 定案 M-A 为主**（M-B 备选，[09] §24.1），DR11 相关表述全篇同步；mbuf 池归属问题调研结论落盘（[09] §24.2/24.3）；**DR1 定案候选 b**（[09] §24.6），M0 DoD 与前置评审表同步。**v1.6（2026-09-02）：M0 实测结论回写**——五项一票否决全 PASS（RV12 为「问题坐实+修法预算充足」，端到端留 M1）；E-NR-03 同 lcore 必崩实测坐实，C-NR-307 扩为 5 处改动点 + 新增 N-1/N-2/N-3 配套修复；C-NR-315 落点精确化（无独立 RX 池）+ 扩展 message_pool；C-NR-201 新增 ENV-1 约束（移交期禁重协商 RSS/MQ）；DR4 定案确认；M2 风险表 ④⑤ 修正 v1.3 过时口径并登记大页泄漏风险（证据：work/impl/m0-poc-runner-veto2.md、m0-lcore-shared-state-audit.md、m0-dr2-dr4-review.md）。**v1.7（2026-09-02）：M1 CR 补注**——C-NR-104 的 attach 确认超时 15s→60s（数据出处与理由见该行补注）；C-NR-102 实现引入 proc_id 移位（worker i → proc_id i+1，slim primary 占 0），配置约束 worker_processes = nb_procs−1（master 侧双向校验拦截错配）。**v1.8（2026-09-03）：M2 实现补注**——DR4 行内回写「master↔worker 方向控制事件走 nginx channel + 匿名共享块（worker/primary 方向仍走 msg_ring）」；M5 前置表登记跨 master 世代 gen/ring 撞号硬前置。**v1.9（2026-09-03）：M3 实现批注**——① C-NR-310 行内回写：D-6（命名含队列维度 `(port,queue,gen)`）、D-1（每进程附全代 4 ring）、flags 修正（drain_rx 改 MP/SC——miss 转发 + ARP/NDP clone fan-out 双生产者；drain_tx 保持 SP/SC）、R-310-1（仅注销不销毁）；② C-NR-306 实现新增 **T2 park barrier**（共享块扩展 handover_epoch + rx_parked，master 收齐全部存活 G_old worker 的 epoch ack 才翻转 rx owner——结构性封死 RV3；cache manager/loader 无 ff 主循环被排除）；③ C-NR-303 实现选**方案 b**（新返回值 `FF_DISPATCH_PEER`，lib 内兜底 enqueue——mbuf 所有权全程不跨 API，R-303-1 double-free 结构性消除）；④ C-NR-309 五路径覆盖 + `send_burst` 防御性短路（RV11 成结构性保证）；⑤ FF_RELOAD 消息面新增只读 `FF_RELOAD_CMD_QUERY`（tools `-g` 观测用），非 QUERY 一律 ENOTSUP；⑥ `ff_no_hw_mode()` 读序为**先 stopped 后 owner**（撕裂读不可达证明见 lib/ff_reload.c 注释） |

相关篇章：[00-总览](00-overview.md) | [06-方案设计](06-solution-design.md) | [08-测试计划](08-testing.md)

---

## 摘要

本文把 [06-方案设计](06-solution-design.md) 的推荐方案 S3（**M1′ 同队列 + ready 后同期接管 rx+tx+listen + G_new 独占硬件 + G_old 软件寄生 + 双向 drain_ring** + flow_map 软件分发表 + rx 互斥 + ARP/NDP clone + **两代同 lcore_id 及其两项资源隔离（自驱 hardclock + 代际 mempool，均为必需项）** + **心跳与 rx 交还**，承接 primary_slim；M2 大阶段：可选 dispatcher 中心化）拆解为 **M0 预研 → M1 常驻 primary 化 → M2 新旧并存 → M3 同期接管+TX 独占+flow_map → M4 drain 收尾 → M5 USR2 → M6 门禁收尾 → M7（可选，DR7 触发）** 共 8 个里程碑、**43 个编码改动点（C-NR-100~604；v1.7 新增 307/308；v1.9 新增 309~313；v1.4 新增 314/315/316，取消 311，308 拆分为索引）**。逐项给出文件:行号锚点、依赖、DoD、测试门禁与回退方案；并把 **RV1-15** 逐项分配到里程碑、**DR1-11** 标注为对应里程碑开工前置评审。测试计划（单测 UT-NR-01~22 + 真 EAL 集成用例 IT-NR-A01~A13 + 实机用例 RT-00~15 + 性能基线 PT-NR-01~10 + 验收标准 A-NR-01~28 + 循环 reload 门禁）见 [08-测试计划](08-testing.md)。

> 【数字口径说明】本文规模数字以实际清点为准（**v1.4 重新清点，修正 v1.4 初稿的算术错误**）：**43 个编码改动点** = M1 7（100~106）+ M2 **13**（201~208 八个 + **307 自驱 hardclock** + **313** msg_ring/KNI 代际隔离 + **314** 代际 mempool 应用侧 + **315** 共享 RX 池跨代 free + **316** 心跳与 rx 交还）+ M3 **8**（301~306 + **309** TX 独占 + **310** drain_ring 双向通道）+ M4 **7**（401~406 + **312** 半开连接窗口）+ M5 4（501~504）+ M6 4（601~604）。
>
> **计数规则（人工裁定）**：**C-NR-308 已于 v1.4 拆分为 C-NR-314 + C-NR-315，其条目仅作索引保留、不重复计数**；**C-NR-311 已取消、不计数**。用例数见 [08](08-testing.md)。
>
> **自动清点对照（供审核员核对）**：全文  得 **45 个唯一编号**（C-NR-100~106、201~208、301~316、401~406、501~504、601~604）。**45 − 308（索引条目）− 311（已取消）= 43 个有效编码点**。若后续再增删编码点，请同步本对照式。
>
> **v1.4 变更说明**：D-A 反转为「两代同 lcore_id」后，C-NR-307/308 **由加固项恢复为必需项**，代际 mempool 细化为 314/315；代际 lcore 池（311）取消。净变化：42 −311 −308（转索引）+314 +315 +316 = **43**。
>
> **勘误**：v1.4 初稿曾写「45」（误把 308 与 314/315 重复计数、且 M2 误记为 15），经独立门禁审核发现并修正为 **43**。00/06/09 三篇的同源数字已同步。
>
> **v1.2 修正**：v1.0/v1.1 正文残留的「35」未计入 v1.7 新增的 C-NR-307/308，与摘要自相矛盾，已统一为 37（v1.3 再增至 42）。C-NR-307/308/311/313 虽编号为 3xx，但语义上属「新旧代际共存的前提改造」，故归属 M2 而非 M3。来源产物 work/milestones-testing.md 中的同源旧数字（41/6/13）系中间产物原文，不回改；如与本文冲突以本文为准。
>
> **v1.3 新增编码点速览**（全部来自 [06] v1.9 交叉审核的 6 项 P0 缺陷）：

| 编号 | 归属 | 对应缺陷 | 一句话 |
|---|---|---|---|
| C-NR-309 | M3 | **P0-1** TX 并发 | G_new 独占 tx；G_old 出包经 `drain_ring_tx` 由 G_new 代发 |
| C-NR-310 | M3 | **P0-2** ring 双消费者 | per-generation `drain_ring_rx` 替代 `dispatch_ring` 转发旧连接包 |
| ~~C-NR-311~~ | ~~M2~~ | ~~P0-3/P0-4~~ | **已取消**（D-A = 同 lcore_id，无需代际 lcore 池；P0-3 消解） |
| C-NR-312 | M4 | **P0-5** 半开连接窗口 | G_old 停 accept 但延迟 close listening 至 syncache 排空 |
| C-NR-313 | M2（+M4 收尾） | **P0-6** msg_ring/KNI owner | msg_ring 按 (proc_id, 代际) 索引；KNI runtime owner 跟随活跃代际 |
| **C-NR-314**（v1.4） | M2 | **同 lcore_id 的 mempool 同槽（应用侧）** | 代际 mempool `gen0/gen1` init 期预建 + 乒乓复用；应用侧 alloc 改用本代际 pool |
| **C-NR-315**（v1.4；**v1.6 扩展**） | M2 | **同 lcore_id 的 mempool 同槽（共享池）** | DR11：**M-A 为主**（`cache_size=0`）；M-B（`free_ring` 由 G_new 代 free）为备选。**v1.6 两个扩展**：① 落点精确化——F-Stack **无独立「RX 池」**，RX 队列绑定（`:1128`→`:1140-1141`）与应用侧 alloc（`:2563/:2705/:2172/:2187`）用的是**同一个** `pktmbuf_pool[socketid]`（cache=256，`ff_memory.h:34`），该池**不参与代际乒乓、保持固定名**；② **`message_pool`（`ff_dpdk_if.c:750-754`，cache=16）与 `ff_ref_pool`（`lib/ff_memory.c:222`，cache=256，`FF_USE_PAGE_ARRAY=1` 条件编译）双池必须一并改 `cache_size=0`**——前者承载 reload 握手消息（READY/DRAIN_DONE/REJECT/HANDOVER_ACK，reload 期间恰是其高频期），后者在 PA 启用时同为两代共用（终审 P3-4 补入；PA 默认关闭，启用时须校验拦截或直接置 0）（lcore 清查 N-4，work/impl/m0-lcore-shared-state-audit.md §6.4） |
| **C-NR-316**（v1.4） | M2 + M4 | **DR6 定案①** | 共享内存全局切换标记每 loop 递增作心跳；G_old 检测失活后由 primary 将 rx 交还 G_old；超时默认 1s 可配 |

> **v1.4 编码点总数**：M1 7 + M2 **15**（201~208 + 307/308/313/314/315/316，~~311~~ 取消）+ M3 8 + M4 7 + M5 4 + M6 4 = **45**。

## 关键结论

1. **最强回滚点仍是配置级**：`graceful_reload=0`（默认）⇒ reload 行为与现状逐字一致（[06](06-solution-design.md) 5.4-3 的 0 回归原则）。所有里程碑的代码都以该开关门控，与 primary_slim 的 `primary_slim=0` 同构。
2. **M0 必须先行解决三个一票否决预研项（v1.2 据 [06] v1.6/v1.7 重列）**：
   - **RV7**（双代际栈隔离 listen 同 IP:port 是否真不冲突——[04](04-fstack-current-analysis.md) §3.5 仅为静态推断）：失败则方案需重新评审。
   - **RV3**（同期移交的跨进程互斥正确性——G_old 停 poll 与 G_new 起 poll 的串行化是否可靠，残余风险为 virtqueue 数据结构并发损坏，**静态无法定论**）：失败则 S3 主路径不成立。
   - **RV10**（v1.6 新增：新旧进程同核处理时切换瞬间的流量/丢包/CPU 抢占）：失败则需回退到「新旧进程各占独立物理核」形态（代价是稳态预留一倍核）。
   - **RV11（v1.9 新增）**：**TX 独占的正确性**——能否确保 drain 期 G_old 无任何 `rte_eth_tx_burst` 路径。这是 M1′ 的核心不变量，失败则 M1′ 不成立（须退 DR9 的 (b) tx queue 分离或 (c) 自旋锁形态）。
   - **RV12（v1.9 新增）**：**半开连接窗口**——移交前 G_old 已收 SYN、ACK 在接管后到达的连接能否完成握手（语义 14 两种修法至少一种生效）。失败则「新连接零丢失」目标不成立。

   五者**在 M1 开工前必须出结论**（RV11/RV12 可与 RV3 合并到同一 PoC 环境，降低搭建成本）。~~RV2（reta 运行时更新）~~ 已随 v1.6「reta 不改」决策**取消**——S3 不再依赖任何 NIC RSS 能力，virtio 与物理网卡均可用。
3. **本文 M 编号与 [06](06-solution-design.md) 的 M1/M2 不同名不同义**：本文 M1+M2+M3+M4 合起来 = 方案设计的 S3-M1；本文 M7 = S3-M2。映射表见第 0.2 节，后续文档引用本文编号时以此为准。
4. **M2（新旧并存）是风险最集中的里程碑**：它一次性引入多 secondary 双代际并存（RV1）、**queue_id 代际无关映射（两代同 lcore_id）**、FF_RELOAD 控制消息（DR4）、**msg_ring 与 KNI owner 代际隔离（C-NR-313）**、**同 lcore_id 的两项资源隔离改造——自驱 hardclock（C-NR-307）与代际 mempool（C-NR-314/315）**、以及心跳与 rx 交还（C-NR-316），且删除了现状两段串行 reload 的「安全」行为——该里程碑必须独立成提交串、独立验收，不得与 M3 混批。
   **v1.4 风险重估**：D-A 反转为「同 lcore_id」后，C-NR-307/314/315 **恢复为必需项、无退路**，M2 的风险面相对 v1.9 是**上升**的（v1.9 曾把它们降为可选）。其中 **C-NR-307 改动全局 timer 心跳，须按最高回归风险对待**（独立提交 + PT-NR-08 门槛）。**v1.4 的补偿**：取消了 C-NR-311（代际 lcore 池），不再改动 `lcore_mask → nb_procs → 队列数` 这条全局配置链，配置面风险归零。
5. **测试环境的三个如实约束**（引自 primary_slim 08 §7 实测）：
   - 本机仅 virtio 系 PMD。**v1.6 起 S3 不再依赖 reta（不调用 `set_rss_table`），故「物理网卡上 reta 结论不可外推」这一约束对本方案主路径已不适用**；但保留两条 virtio 特有限制：① virtio PMD stats **无 `imissed`**（只有 `ierrors`/`rx_nombuf`），无主队列/移交窗口的丢包发生在 host 侧，**guest 侧不可观测**；② 本机 virtio 未协商 `VIRTIO_NET_F_RSS`（`reta_size==0`），需留意 `ff_rss_check` 在 virtio 多队列下本就与硬件落点无关（既有失效项，独立于 reload，建议单独记 issue）。
   - `wrk` 在本环境不可用，压测用 `ab` + python 探测脚本（`_e2_probe_client.py` 模式）。
   - primary/secondary 初始化各需约 25s，脚本必须轮询就绪标志不得裸 sleep。
6. **实机脚本硬性规约**：进程终止一律 `/data/workspace/kill_process.sh`、临时文件清理一律 `/data/workspace/rm_tmp_file.sh`、加执行位一律 `/data/workspace/chmod_modify.sh`；目标地址为必填参数，严禁硬编码（不得重蹈 `test_mtu.sh` 曾硬编码真实内网地址的覆辙）。

## 0. 编号体系与总分配表

### 0.1 编号前缀

| 前缀 | 含义 | 前缀 | 含义 |
|---|---|---|---|
| M0~M7 | 里程碑 | UT-NR-xx | 单元测试用例（[08](08-testing.md)） |
| C-NR-xxx | 编码改动点 | IT-NR-Axx | cmocka 真 EAL 集成用例（[08](08-testing.md)） |
| E-NR-xx | M0 预研实验项 | IT-NR-RT-xx（RT-xx） | 实机用例（[08](08-testing.md)） |
| F-NR-x | 单测 fixture（[08](08-testing.md)） | PT-NR-xx | 性能基线用例（[08](08-testing.md)） |
| RV1-14 | [06](06-solution-design.md) §6.1 运行时验证项（v1.9 新增 RV11~14） | A-NR-xx | 验收标准（[08](08-testing.md)） |
| DR1-10 | [06](06-solution-design.md) §6.2 设计评审项（v1.9 新增 DR8~10） | RG-NR-xx | 回归项（[08](08-testing.md)） |

### 0.2 本文里程碑与方案设计阶段的映射

| 方案设计（06 篇） | 本文里程碑 | 内容 |
|---|---|---|
| （前置，S3 依赖） | M0 | 预研定案 + 基线采集 |
| S3-M1′ | M1 → M2 → M3 → M4 | 常驻 primary 化 → 新旧并存（**两代同 lcore_id** + 同 lcore_id 资源隔离 + msg_ring/KNI 代际隔离 + 心跳） → 同期接管 rx/tx+TX 独占+flow_map 转发兜底 → drain 收尾+半开连接窗口+状态机完备 |
| S3-M1 收尾 | M5、M6 | USR2 升级路径；循环 reload 终门禁 + 特殊场景回归 + 文档 |
| S3-M2 | M7（可选） | dispatcher 中心化（DR7 触发才立项） |

### 0.3 RV1-14 分配总表

> v1.2 据 [06] v1.6/v1.7 重列。~~RV2（reta 运行时更新）~~ 已取消（reta 不改）；RV3 由「降级变体」升为**主路径**；RV6 因 v1.7 自驱 hardclock 而性质改变。
> **v1.3 据 [06] v1.9 重列**：RV3 改为「rx 接管互斥」（tx 已独占）；RV4 改为「双向 `drain_ring` 的吞吐与满环行为」；**新增 RV11（TX 独占）、RV12（半开连接窗口）、RV13（msg_ring/KNI 代际隔离）、RV14（keepalive 下 drain 时长与门禁节拍）**。
> **v1.4 再重列**：D-A 反转为「同 lcore_id」后，~~「不同 lcore 的 timer 隔离」~~ 不再成立，RV6 改为**验证自驱 hardclock 本身的精度等价性**（C-NR-307 恢复必需，PT-NR-08 为门槛）；并新增 **RV15（同 lcore_id 下的 mempool 隔离：代际池乒乓复用 + 共享 RX 池跨代 free）**。

| RV | 项目（[06](06-solution-design.md) §6.1） | 首验里程碑 | 复验/关闭里程碑 |
|---|---|---|---|
| RV1 | **N+N 双代际** worker + 1 slim primary 多 secondary 并存稳定性（同队列，不配 2N 队列） | M2 | M6（长稳） |
| ~~RV2~~ | ~~reta 运行时更新在目标 PMD 的支持度与生效时延~~ | **已取消**（v1.6：reta 不改，不依赖 NIC RSS） | — |
| RV3 | **同期接管 rx 的互斥正确性**（v1.9：互斥只覆盖 rx，tx 已独占）：跨进程互斥标记（SEQ_CST 原子）保证 G_old 停 rx 后 G_new 才起 rx；接管窗口靠 NIC rx ring（RX_QUEUE_SIZE 4096）兜底；残余风险为 virtqueue 数据结构并发损坏（静态无法定论）；**virtio 无 `imissed`，guest 侧不可观测** | **M0**（PoC，一票否决项） | M3（集成后复测）、M6（长循环） |
| RV4 | **双向 `drain_ring` 的吞吐/时延与满环行为**（v1.9 改写：drain 期存量连接**双向各一跳**、100% 走 ring；满环不得静默丢已建连接包） | M3 | M6（循环 reload 期间） |
| RV5 | flow_map 查表开销【仅 reload 窗口，稳态零开销】 | M3 | M6（PT-NR-06 关闭） |
| RV6 | **自驱 hardclock 的 timer 精度等价性**（v1.4 再改：D-A = 同 lcore_id ⇒ `priv_timer` 必然同槽，**C-NR-307 是唯一解法、无退路**；本项验证其精度与 `rte_timer` 挂槽基线等价） | M0（双进程共存初验） | **M2（PT-NR-08 为合入门槛）**、M6（长稳） |
| RV7 | 多代际栈隔离 listen 同 IP:port 实际行为 | **M0**（PoC，一票否决项） | M2（正式链路） |
| RV8 | KNI 启用场景与双代际 worker 交互（**v1.9：owner 须跟随活跃代际，C-NR-313**） | M6 | M6 |
| RV9 | 端到端循环 reload 门禁（≥100 次）；**v1.9 补充：须先由 RV14 确定 keepalive 与强退阈值，否则机时不可控** | M4（20 次小规模） | **M6（终门禁，≥100 次）** |
| **RV10**（v1.6 新增） | **同核处理新旧进程的切换瞬间性能**（v1.9 补充：M1′ 下 G_old 不 poll 硬件，算力占用低于 v1.6 形态，预期改善但仍需实测） | **M0**（PoC，一票否决项） | M3/M6（高负载压测） |
| **RV11**（v1.9 新增） | **TX 独占正确性**：drain 期 G_old 零 `rte_eth_tx_burst` 路径；`drain_ring_tx` 代发在高出包量下不成为瓶颈 | **M0**（PoC，一票否决项；可与 E-NR-02b 合并环境） | M3（IT-NR-A09）、M6 |
| **RV12**（v1.9 新增） | **半开连接窗口**：移交前 G_old 收 SYN、ACK 在接管后到达的连接能否完成握手（语义 14 两种修法实测对比） | **M0**（PoC，一票否决项） | M4（IT-NR-A10）、M6 |
| **RV13**（v1.9 新增） | **msg_ring 代际隔离与 KNI owner 跟随**：两代并存期间控制消息不错收；多轮交替后 KNI 仍可用 | M2（IT-NR-A11） | M6（长循环） |
| **RV14**（v1.9 新增） | **keepalive 场景下 drain 时长与门禁节拍可行性**：实测 `keepalive_timeout`（默认 75s）下的 drain 时长，确定 shutdown timer 强退阈值与 RV9 总机时 | M4（RT 实测） | M6（确定门禁配置） |
| **RV15**（v1.4 新增） | **同 lcore_id 下的 mempool 隔离**：代际池 `gen0/gen1` 乒乓复用后资源总量恒定、跨代 alloc/free 无泄漏与双重释放、**共享 RX 池的跨代 free 路径正确**（DR11 选型的实测依据） | M2（PT-NR-09 + IT-NR-A13） | M6（长稳） |

### 0.4 DR1-10 前置评审分配总表

| DR | 项目 | 评审时点（对应里程碑开工前） |
|---|---|---|
| DR1 | reload 编排者：master vs slim primary | **已定案（v1.9.3）= 候选 b：master 编排 + primary 原语**（决定 M1 的 primary 拉起方式与 M2 状态机归属，见 [09] §24.5/24.6） |
| DR2 | 旧连接归属判定：实时查询 vs 快照表（两形态均须遵守流表窗口化：READY 后生效、排空确认后关表，[06] 第 2 节语义 6） | M0（接口初评）→ **M3 开工前定案**（RV5 数据支撑） |
| ~~DR3~~ | ~~reta 切流 vs 末期一次性队列移交~~ | **已取消**（v1.6：reta 不改，同期移交为唯一主路径，见 [06] §6.2 DR3） |
| DR4 | reload 控制通道载体（v1.6 已定）：移交互斥用**共享内存标记**（非 msg ring），READY/DRAIN_DONE/REJECT 用 msg ring。**【M2 v1.8 实现补注（CR 裁定：接受偏离但限定条件）】master↔worker 方向的控制事件（READY 现状、M4 的 DRAIN_DONE/REJECT）实际走 nginx channel + 匿名 MAP_SHARED 共享块**——master 非 DPDK 进程无法 dequeue msg_ring（EAL attach 会破坏 M1 fork 安全定案）；FF_RELOAD 消息族仍在 (proc_id,gen) 隔离的 msg_ring 上承载（lib 侧查询/验证面）。**worker↔primary 方向（M3 的 HANDOVER_REQ/ACK）必须走 msg_ring**（全 EAL 进程） | **已定案确认**（M0 评审 + M2 CR） |
| ~~DR5~~ | ~~四链解耦与代际 lcore 池的配置表达~~ | **已取消（2026-09-01 人工决策）**：D-A = 同 lcore_id，无 2N lcore_id 需求，`lcore_mask`/`nb_procs`/队列数保持 N。C-NR-311 随之取消 |
| DR6 | 异常回退完备性（每阶段回退目标态） | **M4 开工前**。**T3 之后 G_new 崩溃已于 2026-09-01 定案：方案① 由 primary 将 rx 交还 G_old**；检测手段 = 共享内存全局切换标记每 loop 递增作心跳（G_old 采样，G_old 排空后标记随 flow_map 消亡不再递增）；超时 **默认 1s 可配置**（M4 实测校准）。落地编码点 **C-NR-316**，附则见 [06] §6.2 DR6 附则 |
| DR7 | M7（dispatcher 中心化）启动判据与阈值 | **M7 立项评审**（M6 数据齐后；暂定阈值：reload 窗口内转发开销致吞吐下降 >5%、或 drain 期 P99 劣化 >10%、或高存量连接场景 drain 时长超 SLO——流表窗口化后稳态损耗恒 0，原稳态阈值失效）。**v1.9 决策 D-C：M2 不提前，维持可选演进** |
| **DR8**（v1.9 新增·**2026-09-01 终版定案**） | **lcore_id 策略** | **已定案：两代使用相同 lcore_id**（推翻本轮前一版「不同 lcore_id」）。理由：拆 lcore 链引发的各类池冲突远严重于同槽问题；DPDK 硬禁令（`multi_proc_support.rst:169-172`）的理由即 mempool cache 损坏，由代际 mempool 消除 ⇒ 例外适用。**推论：C-NR-307/308/314/315 恢复为必需项** |
| **DR9**（v1.9 新增） | **TX 处理形态**：(a) G_new 代发（M1′ 主路径）/ (b) init 期多配 `nb_tx_queues=2N` 代际各一组 / (c) 共享内存自旋锁保护 tx queue | **M3 开工前**（倾向 a；RV11 数据支撑，不达标则评 b） |
| **DR10**（v1.9 新增） | **防重入可否放松**：G_old 退化为纯软件进程后可支持多代并存，是否允许「上一代未排空即接受新 reload」 | **M6 后**（默认保持防重入；属可选增强） |
| **DR11**（v1.4 新增） | **共享 RX 池的跨代 free**：M-A（RX 池 `cache_size=0`，简单但稳态有损耗）/ M-B（`free_ring` 由 G_new 代 free，稳态零损耗） | **已定案（v1.9.3 人工决策）：M-A 为主，M-B 备选**；M-B 仅在 PT-NR-09 显示 M-A 稳态损耗不可接受时启用 |

### 0.5 8 项障碍（[04](04-fstack-current-analysis.md) §4）→ 里程碑消解映射

| 障碍 | 内容 | 消解里程碑 | 机制（v1.6/v1.7） |
|---|---|---|---|
| 1 | 两段串行空窗 | M2 + M3 | 并存 + **同期接管 rx/tx**（跨进程互斥标记保证队列始终有主；~~reta 切流~~ 已废弃） |
| 2 | listening fd 无法跨进程 | M2 | 回避式：栈隔离多代际 listen（RV7 验证） |
| 3 | TCP 连接无迁移 | M3 + M4 | **flow_map miss → `drain_ring_rx` 转发兜底** + 出包经 `drain_ring_tx` 代发 + drain（v1.9） |
| 4 | primary 单点/硬编码 | M1 | 全 secondary + 常驻 slim primary |
| 5 | respawn/时序脆弱（500ms/15s） | M2 | 显式 READY 协议取代 |
| 6 | master 不在数据面 | M2 + M3 | master 编排 + primary 原语（**DR1 已定案候选 b**） |
| 7 | RSS 静态映射窗口 | M3 | **同期接管 rx + 互斥**（reta 不改 → `ff_rss_check`/`adjust_sport`/`tbl`/`thash` 四件套不变；~~reta 原子切流（DR3）~~ 已取消）；**v1.9 追加：tx 由 G_new 独占（C-NR-309），互斥只需覆盖 rx** |
| 8 | 定时器随进程消亡 | M2（**必需项**） | **v1.9.1 终版定案 D-A：两代 lcore_id 相同 ⇒ `priv_timer[L]` 必然同槽**（`rte_timer.c:216-228` 的 memset 会清零 G_old 的 skiplist）⇒ 由 **C-NR-307 自驱 hardclock（必需，无退路）** 解决：main_loop 按 TSC 间隔直调 `ff_hardclock()`，每进程 timer 完全独立。合入门槛 = PT-NR-08。~~v1.9 曾定「两代 lcore_id 不同 ⇒ 天然隔离」~~ 已被推翻。**M0 实测（E-NR-03）：同 lcore_id 双实例 2/2 必崩**——旧实例 `rte_timer_manage` 段错误（死者持锁）、新实例永久自旋（指令级坐实：崩溃点落在 `list_lock` 临界区内 `rte_timer.c:701-702`）。**v1.6 改动点扩为 5 处**（lcore 清查 + 复核定案，缺一无效）：`ff_dpdk_if.c:2804-2805`（main_loop manage）、`:1242-1256`（init_clock：meta_init 清槽 + 注册，两件都要去）、`:1275-1277`+`:3011`（stop_clock/stop_sync）、`:1263-1274`+`:2776-2777`（thread_mode 路径）、`:1244`（subsystem_init 持共享 tlock，须改 attach 旁路）。**另须配套修 N-1/N-2/N-3**：`rte_timer_meta_init` 幂等保护（每进程 memset 共享槽是崩溃扳机）、G_old 退出不走 `rte_timer_stop_sync`（无界自旋）、G_new 不调 `rte_timer_subsystem_init` |
| 补充 | worker QUIT 缺 ngx_set_shutdown_timer | M4 | 补回（修 bug 性质，独立可先做） |
| 补充 | **移交瞬间半开连接无归属**（v1.9 P0-5） | M4 | C-NR-312：G_old 停 accept 但延迟 close listening 至 syncache 排空 |
| 补充 | **msg_ring / KNI owner 落在已退代际**（v1.9 P0-6） | M2 + M4 | C-NR-313：按 (proc_id, 代际) 索引；owner 跟随活跃代际（T5 更新） |

## 1. 里程碑总览

| 里程碑 | 目标 | 编码点数 | 主要文件 | 前置 | 独立验收 | 回退点 |
|---|---|---|---|---|---|---|
| **M0** 预研定案 | **RV7/RV3/RV10** 一票否决项出结论；DR4 定案 + DR2 初评；基线数据（~~DR1 已定案候选 b~~；~~DR5 已取消~~） | 0（PoC 脚本/报告） | 无正式编码 | 无 | ✅ | — |
| **M1** 常驻 primary 化 | nginx worker 全 secondary，slim primary 常驻不随 reload 退出；`graceful_reload` 开关落地 | 7（C-NR-100~106） | `ngx_ff_module.c`/`ngx_process_cycle.c`/`ff_config.{h,c}`/`config.ini` | M0（DR1 定案）；primary_slim 已合入 | ✅ | `graceful_reload=0` + revert 提交串 |
| **M2** 新旧并存 | **queue_id 代际无关映射**（v1.6 取代乒乓段）+ **两代同 lcore_id（D-A v1.4）** + **msg_ring/KNI 代际隔离（C-NR-313）** + **同 lcore_id 资源隔离：自驱 hardclock（C-NR-307）+ 代际 mempool（C-NR-314/315）** + **心跳与 rx 交还（C-NR-316）** + FF_RELOAD 消息族 + READY 协议 + 双代际 worker 并存；删除两段串行 reload（条件化） | **13（C-NR-201~208 + 307/313/314/315/316；308 拆分为索引不计数、~~311~~ 已取消）** | `ff_config.{h,c}`/`ff_msg.h`/`ff_dpdk_if.c`/`ff_dpdk_kni.c`/`ngx_process_cycle.c`/新增 `ngx_ff_reload.c` | M1；DR4 评审（DR5 已取消；DR8 已定案；**DR11 已定案 M-A 为主**） | ✅ | `graceful_reload=0` 走旧路径；各 C-NR 独立提交串 |
| **M3** 同期接管+TX 独占+flow_map | **flow_map 软件分发表** + **rx 跨进程互斥原语** + **TX 独占与 `drain_ring_tx` 代发（C-NR-309）** + **per-generation `drain_ring_rx`（C-NR-310）** + ARP/NDP clone + RX_QUEUE_SIZE 放大；旧连接包经 flow_map miss → `drain_ring_rx` 转发（**reta 不改**） | **8（C-NR-301~306 + 309/310）** | `ff_api.h`/新增 `ff_flow_map.c`/`ff_handover.c`/`ff_drain_ring.c`/`ff_dpdk_if.c`/`ngx_ff_module.c` | M2；DR2/DR4/**DR9** 定案 | ✅ | 接管消息不触发即回退（状态机停 T2） |
| **M4** drain 收尾 | 补 shutdown timer、drain 上报与强退、**半开连接窗口处理（C-NR-312：延迟 close listening）**、T0-T5 状态机完备与异常分支（含 **T3 后 G_new 崩溃回退**）、HUP 全链路打通 | **7（C-NR-401~406 + 312）** | `ngx_process_cycle.c`/`ngx_ff_reload.c`/`ff_msg.h`/`freebsd/netinet/tcp_syncache.{c,h}` | M3；DR6 评审 | ✅ | 各点独立 revert |
| **M5** USR2 升级 | master exec 换代 + 新 master 对接常驻 primary；WINCH/QUIT 语义 | 4（C-NR-501~504） | `ngx_process_cycle.c`/`nginx.c` | M4 | ✅ | 不用 USR2 即无影响 |
| **M6** 门禁收尾 | RV9 终门禁、RV8/zc/KNI 回归、文档 | 4（C-NR-601~604） | `tests/`/`doc/` | M4（M5 可并行） | ✅ | — |
| **M7**（可选） | dispatcher 中心化（S3-M2） | 另立 spec | — | DR7 触发 | — | 独立演进线 |

**通用规约提醒（适用于全部里程碑，写进每个实现阶段的工作约定）**：
- 改代码后必须 `make clean && make`（lib/ 与 example/ 均 exit 0），增量编译通过不算通过。
- lib/ 代码最小注释，F-Stack 代码注释一律英文（ftdns 相关可中文）；commit message 英文 1~3 句。
- 遵循 F-Stack 惯例：**每个里程碑一次或多次独立可 revert 的 git 提交**（建议每个 C-NR 功能簇一个 commit），示例：`nginx: spawn all workers as DPDK secondary under graceful_reload` / `lib: add FF_RELOAD message family for reload control plane`。
- `config.ini` 只提交特性相关注释块与注释掉的示例项，本地测试值（lcore_mask/地址等）不入库。
- 文档与测试脚本严禁真实 IP；Shell 清理/终止/加执行位只走 `rm_tmp_file.sh` / `kill_process.sh` / `chmod_modify.sh`。
- 每个里程碑 DoD = 单测全绿（含既有零回归）+ clean build + 实机运行时回归门禁（[08](08-testing.md) 对应用例）。

## 2. 各里程碑详述

### 2.1 M0：预研与设计定案（无正式编码）

| 项 | 内容 |
|---|---|
| **目标** | 用最小 PoC 消除 S3-M1 的**三个一票否决不确定性（RV7、RV3、RV10）**，完成 DR1/DR4/DR5 设计定案，采集性能基线，为 M1~M6 提供决策数据。（~~RV2 reta 运行时更新~~ 已随 v1.6「reta 不改」决策取消） |
| **范围** | 不改任何 lib/app 正式代码；PoC 可用临时补丁/脚本（产物入库为报告，补丁仅留档不进主线，参照 primary_slim `_poc_*.patch` 的做法） |

**实验与评审清单**：

| 编号 | 内容 | 方法 | 通过判据 | 失败时的换档 |
|---|---|---|---|---|
| E-NR-01（RV7） | 双代际栈隔离 listen 同 `<IP>:80` 是否冲突 | 常驻 slim primary（primary_slim=1）+ 两个 secondary helloworld/nginx 实例各自 bind/listen 同 `<DPDK_NIC_IP>:80`，从 f-stack-client 并发 SYN 压测，两实例各自 accept | 两实例均正常 accept、无 bind 报错、无 RST；两栈各自独立维护 pcb/syncache 表（v1.6 起 reta 不改，连接分布由网卡既有分发决定，**不校验 reta 映射**） | S3 需重新评审（listen 层加协调） |
| ~~E-NR-02（RV2）~~ | ~~virtio PMD 上 `rte_eth_dev_rss_reta_update`/`set_rss_table` 运行时更新是否生效、时延~~ | **已取消**（v1.6：reta 不改，本项不再是一票否决项）。保留此行仅供审计追溯 | — | — |
| **E-NR-02b（RV3，一票否决）** | **同期移交的跨进程互斥是否可靠**——G_old 停 poll → G_new 起 poll 的串行化；残余风险为两进程并发操作同一 virtqueue/rxq 造成**数据结构损坏**（非业务语义、无软件兜底） | 双进程 PoC：A poll 同队列 N 秒 → 停（共享内存标记 + ACK）→ B 接管 → 校验 `rx_packets` 连续、无 crash、无 mbuf 双重释放/校验错误；virtio 与物理网卡各测；扫 `RX_QUEUE_SIZE` 512/4096 两档 | 移交全程无任何一瞬间两进程并发 `rx_burst`；无 crash；**virtio 上丢包 guest 侧不可观测**（virtio PMD stats 只有 `ierrors`/`rx_nombuf`，**无 `imissed`**），故判据以**端到端业务指标**（客户端错误数/重传率）+ 宿主机侧 tap/vhost 统计为准 | S3 主路径不成立，须回炉（或退 [06] §4.2 的 S4 蓝绿多实例） |
| E-NR-03（RV6 初验） | 双进程共存期的 TCP 定时器行为（**v1.4 再改**：两代**同 lcore_id**，采集 `rte_timer` 挂槽模式的基线，供 C-NR-307 自驱 hardclock 做**精度等价性**对比） | E-NR-01 的双实例运行（**两实例须用相同 lcore_id**，复现生产形态）期间观测 RTO/keepalive 精度与 `rte_timer` 状态（ff_top/sysctl 采样）；**先采集改造前（挂槽）基线，再采集改造后（自驱）数据** | 无 timer 重复触发/停摆迹象；TCP 定时器精度正常；两组基线数值落盘 | 自驱 hardclock 精度不等价 → **升级为 blocker**（同 lcore_id 下无替代方案） |
| E-NR-04 | 现状串行 reload 基线数据（[04](04-fstack-current-analysis.md) §5-3） | 现状代码跑一轮 HUP reload：实测空窗时长（服务不可用窗口）、reload 总时长、期间丢包/失败数 | 产出基线数值（用于 A-NR-14 的 reload 耗时上限与 PT-NR-03 对照） | — |
| E-NR-05 | 性能基线采集（PT-NR-01 前置） | 按 primary_slim 06 方法：`ab -k -c 50 -n 20000 http://<DPDK_NIC_IP>/`，3 轮取区间 | 产出改造前稳态 QPS/延迟基线 | — |
| **E-NR-06（RV10，一票否决，v1.6 新增）** | **同核处理新旧进程的切换瞬间性能**：两代进程**同 lcore_id ⇒ 必然同核**（v1.4：不再是「可经 `--lcores` 亲和」的可选项，而是 D-A 定案的必然后果），切换瞬间的流量/丢包/CPU 抢占，以及 drain 期算力分配造成的「drain 变慢 → 抢核更久」正反馈 | 双代际同核共存压测：稳态基线 → 触发接管 → 观测切换瞬间 pps/丢包/两侧 CPU 占用 → 持续至 drain 完成，记录 drain 时长 | 产出量化数据：切换瞬间丢包数、两侧有效算力占比、drain 时长。**v1.4 补充预期**：M1′ 下 G_old 不 poll 硬件，算力占用低于 v1.6 形态，预期改善 | 若 drain 时长或切换丢包不可接受 → 需重新评估（**v1.4 注意：同 lcore_id 下已无法改用独立核，此路已封**，可选方向只剩优化 G_old 的循环开销或缩短 drain） |
| **E-NR-07（RV11，一票否决，v1.9 新增）** | **TX 独占可行性**：能否让 G_old 在 drain 期完全不调用 `rte_eth_tx_burst`，所有出包经 ring 由 G_new 代发；代发路径在高出包量（大量 RTO 重传）下是否成为瓶颈 | 双进程 PoC：G_old 置「无硬件模式」标志后，审计其所有出包路径（`ff_dpdk_if_send`/`send_single_packet`/`send_burst`/main_loop tx drain/`ff_dpdk_raw_packet_send`）均无 tx_burst 调用；构造 RTO 重传高峰观测代发时延与 `drain_ring_tx` 水位 | ① G_old 零 tx_burst（代码路径审计 + 运行时计数器断言）；② 代发路径在高出包量下无成为瓶颈的迹象（给出水位与 pps 数据） | M1′ 不成立，按 DR9 切 (b) tx queue 分离或 (c) 自旋锁形态 |
| **E-NR-08（RV12，一票否决，v1.9 新增）** | **半开连接窗口**：移交前 G_old 已收 SYN、第 3 个 ACK 在接管后到达的连接能否完成握手 | 构造确定时序：向 G_old 发 SYN（不回 ACK）→ 触发接管 → 再发 ACK；分别验证语义 14 的 (a) 延迟 close listening 与 (b) syncache 导出两种修法 | 握手成功率 100%（无 RST、无连接失败）；(a)/(b) 至少一种可行并给出取舍 | 「新连接零丢失」目标不成立，需重新设计移交时序（如延后接管至 syncache 排空） |
| 评审 | ~~DR1（编排者）~~ **已定案候选 b（v1.9.3）**；DR4（控制通道载体）、DR2 初评（flow_map 形态）评审。~~DR5（四链解耦与代际 lcore 池）~~ **已取消**；**DR8（lcore_id 策略）已于 2026-09-01 定案「两代同 lcore_id」**；**DR11 已定案 M-A 为主，M-B 备选** | 评审会，结论更新回 [06](06-solution-design.md) 或本文附录 | 定案记录在案 | — |

> **E-NR-02b / 06 / 07 / 08 的不可分割性**：RV3（rx 接管互斥）、RV10（同核性能）、RV11（TX 独占）、RV12（半开连接窗口）四项**都依赖「双代际共存」这一前提**，建议合并为同一个 PoC 环境的四次实验，避免重复搭建环境（v1.9：四项中 RV3/RV11/RV12 为一票否决项）。

**slim primary 拉起方式（U-NR-1，DR1 已定案候选 b，M1 编码按此执行）**：
- 候选 a（独立常驻进程）：部署形态新增一个 systemd unit 拉起的 slim primary 守护进程；nginx master 启动时探测其存活（EAL attach 失败即报错退出）。运维形态变化明确，primary 生命周期与 nginx 完全解耦。
- 候选 b（master 代管 + double-fork 脱离）：nginx master 首次启动时检测 primary 缺席则 spawn 专职 slim primary 子进程并 double-fork/setsid 脱离 master 生命周期，reload/USR2 均不对其发信号。nginx 语义内聚，但需处理老 master 退出不波及 primary 的细节。
- **DR1 已于 v1.9.3 定案候选 b（运维零新增）**；两候选在 M1 的差异仅在 C-NR-100/101 两点。

| 项 | 内容 |
|---|---|
| **DoD** | E-NR-01（RV7）/**E-NR-02b（RV3）**/**E-NR-06（RV10）**/**E-NR-07（RV11）**/**E-NR-08（RV12）** 五项一票否决项出明确结论；**DR1 已定案候选 b**；DR4/DR8/DR2 初评有书面定案（DR5 已取消）；基线数据落盘 `work/m0-poc-report.md` |
| **测试门禁** | 本身即测试产出；无代码门禁 |
| **风险与回退** | RV7/RV3/RV10/RV11/RV12 任一失败 → 按「失败换档」列处理，M3 范围调整或方案回炉（RV3 或 RV11 失败则退 [06] §4.2 的 S4 蓝绿多实例，或按 DR9 换 TX 形态）；不产生主线代码风险 |
| **提交** | 仅文档（m0-poc-report.md）；英文 commit 1~3 句 |

### 2.2 M1：常驻 primary 化（worker 全 secondary + graceful_reload 开关）

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 4：nginx worker 0 不再硬编码 DPDK primary；slim primary 常驻（承接 primary_slim #1078），nginx 全部 worker 以 secondary attach。reload 时 primary 不退出 |
| **范围** | [06](06-solution-design.md) 接口面 5.4-3（config.ini）+ 5.4-4 第 2 条（secondary 化）；不改 reload 顺序本身（仍两段串行，M2 才动） |

**编码工作清单**：

| 编号 | 文件:行号锚点（引自 [04](04-fstack-current-analysis.md)，以实际代码为准） | 类型 | 要点 |
|---|---|---|---|
| C-NR-100 | 新增：slim primary 拉起（候选 a：`tools/` 或 `example/` 下小工具；候选 b：`ngx_process_cycle.c` master 启动分支） | 新增 | 按 DR1 定案二选一；primary 进程以 `--proc-type=primary --proc-id=0` + `primary_slim=1` 常驻 |
| C-NR-101 | `lib/ff_config.h:295-316` 旁 + `lib/ff_config.c:1035-1036` 旁 + `ff_default_config()` | 新增 | `[dpdk] graceful_reload`（int，默认 0）；校验链：`graceful_reload=1` 要求 `primary_slim=1`、`nb_procs>=2`、与 `thread_mode=1` 互斥（沿用 primary_slim V4 风格，新增 V-NR 系列） |
| C-NR-102 | `app/nginx-1.28.0/src/event/modules/ngx_ff_module.c:169-187` | 修改 | `ff_mod_init` 拼参：`graceful_reload=1` 时 proc_type 一律 secondary（去掉 worker==0 → primary 硬编码分支） |
| C-NR-103 | `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:1117-1121` + `ngx_process_cycle.h:40-44` | 修改 | `ngx_ff_process` 赋值：全 worker → `NGX_FF_PROCESS_SECONDARY`；枚举按需扩展 slim primary 角色（候选 b） |
| C-NR-104 | `ngx_process_cycle.c:443-510`（sem 同步块） | 修改 | `graceful_reload=1` 时跳过 master 的 15s sem 等待（primary 常驻已就绪），改为 attach 确认（worker 0 ff_mod_init 成功即上报，超时语义保留）；`=0` 时逐字保留现状。**【v1.7 实现补注（M1 CR 裁定）】`=1` 的 attach 确认超时取 60s 而非 15s**：15s 是「primary worker 首次初始化」的历史经验值，而 attach 场景的实测参考是 secondary 初始化 ~25s（primary_slim 06 §6-4 基线报告，经 milestones-testing.md 转引；M0 自测 worker 就绪 0.8s 是无 primary_slim 场景，不可比）；60s 保留「超时失败 exit(2)」语义不变 |
| C-NR-105 | `ngx_process_cycle.c:1251-1256`（primary 退前 500ms） | 修改 | `graceful_reload=1` 时无 primary worker，该分支自然不触发；条件化保留供 `=0` |
| C-NR-106 | `config.ini` 注释块 + `doc/F-Stack_Nginx_APP_Guide.md` | 文档 | `graceful_reload` 注释掉的示例项 + 与 primary_slim 的配合说明；本地测试值不入库 |

| 项 | 内容 |
|---|---|
| **前置** | M0（DR1 定案）；primary_slim 已合入主线 |
| **DoD** | ① clean build 全绿；② 单测 UT-NR-01~03/07~09 全绿 + 既有 TC 零回归；③ 实机 RT-00（启动基线）：`graceful_reload=1` 下 nginx 正常启动收发（此阶段 reload 仍串行，行为不劣化）；④ `graceful_reload=0` 时与现状逐字一致 |
| **测试门禁** | UT（[08](08-testing.md) §1）+ RT-00 + RG-NR-01 |
| **风险与回退** | 风险：常驻 primary 与 nginx 生命周期的拉起/探测细节（候选 b 的 double-fork）；回退：`graceful_reload=0` 或整体 revert C-NR-100~106（一个自洽提交串） |
| **提交建议** | 2~3 个 commit：lib 配置项 / nginx secondary 化 / primary 拉起 |

### 2.3 M2：新旧 worker 并存与 FF_RELOAD 协议（v1.9.1：queue_id 代际无关映射 + **两代同 lcore_id** + 同 lcore_id 资源隔离 + 代际隔离）

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 1（前半）/2/5/8：reload 改回原生「先起新再退旧」顺序；G_new 与 G_old 并存（同队列：queue_id 代际无关映射，**两代取相同 lcore_id**，D-A v1.9.1；~~C-NR-311 代际 lcore 池~~ 已取消）；**同 lcore_id 的两项资源隔离**：自驱 hardclock（C-NR-307，绕开共享 `priv_timer` 槽）+ 代际 mempool（C-NR-314 应用侧 / C-NR-315 共享 RX 池）；**心跳与 rx 交还**（C-NR-316）；msg_ring 与 KNI owner 代际隔离（C-NR-313）；READY 显式协议取代 500ms/15s 时序 |
| **范围** | [06](06-solution-design.md) 5.4-2（FF_RELOAD 消息族）、5.4-3（proc_id 代际无关配置）、5.4-4 第 1 条（两段式条件化）；时序 T0-T2 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-201 | `lib/ff_config.h`（dpdk 段，字段区 `:274/:293/:297/:320` 附近）+ `ff_config.c` 解析/校验（`:1414-1519` 区域） | 修改 | ~~`reload_lcore_policy=pingpong`~~ → v1.6 改为：**queue_id 代际无关固定映射**配置（G_new 直接用 G_old 的 queue 映射，`rx_queue_list/tx_queue_id/reta/rss_check` 四件套不变）；**v1.9 拆分**：本点只保留 queue 映射语义；**v1.9.1 终版：D-A 定案「两代同 lcore_id」后，lcore_id 的代际分配问题不存在**（`lcore_mask`/`nb_procs`/队列数保持 N，proc_lcore 映射不变，~~C-NR-311 代际 lcore 池~~ 已取消，P0-3 消解）。V-NR 校验链：worker 数与 queue 数一致、primary lcore 排除、`graceful_reload=0` 时全部新校验不生效。**【M0 v1.6 新增约束 ENV-1】移交期与整个 reload 窗口严禁重协商 RSS/MQ/`dev_configure`**——M0 实测坐实：单 poll 队列不协商 RSS 时，vhost 多队列分流存在「逐轮随机整流静默丢弃」（四态全复现，`imissed=0` guest 侧不可观测）；F-Stack 靠 `ff_dpdk_if.c:938-970` 显式 RSS+RETA 编程规避，重协商 = 重掷骰子（证据 work/impl/m0-poc-runner-veto2.md §2） |
| C-NR-202 | `lib/ff_msg.h:37-53` 旁 | 新增 | FF_RELOAD 消息族（v1.6 修订）：`FF_RELOAD_READY` / `FF_RELOAD_HANDOVER_REQ`（移交请求，[06] 第 2 节语义 7）/ `FF_RELOAD_HANDOVER_ACK` / `FF_RELOAD_DRAIN_PROGRESS` / `FF_RELOAD_DRAIN_DONE`（G_old 排空确认→G_new 关 flow_map 回稳态）/ `FF_RELOAD_REJECT`（防重入）；~~SWITCH_REQ/SWITCH_ACK~~ → 改为 HANDOVER 语义（v1.6 不切流，同期移交） |
| C-NR-203 | `lib/ff_dpdk_if.c:2404-2454`（handle_msg） | 修改 | FF_RELOAD 处理器注册与分派；容量/实时性按 DR4 结论 |
| C-NR-204 | `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:223-270` | 修改 | **两段式 reload 块整体条件化**：`graceful_reload=1` 走原生顺序（fork G_new JUST_RESPAWN → 等 READY → 同期移交[M3] → G_old QUIT）；T1~T5 期间再次收到 HUP → **拒绝并记日志（reload 防重入，[06] 第 2 节语义 6）**；`=0` 逐字保留旧两段式 |
| C-NR-205 | 新增 `app/nginx-1.28.0/src/event/modules/ngx_ff_reload.c` + `auto/sources` 挂载 | 新增 | **reload 编排状态机**：T0-T5 状态枚举 + 纯转移函数 + 每阶段打点（状态日志 + ff_top 可见计数）；master 侧驱动 |
| C-NR-206 | `lib/ff_config.c` proc_lcore 分配（`ff_dpdk_if.c:508-538` 消费侧，`:508` proc_id→proc_lcore、`:518-524` lcore→queueid）+ `ngx_process_cycle.c:1123` | 修改 | ~~代际号→段号取模~~ → v1.6 改为 proc_id 代际无关固定映射（消除审核 B-1 乒乓代际重合）。**v1.9 重要修正**：proc_id 同值会连带撞上**按 proc_id 索引的 msg_ring**（`ff_dpdk_if.c:2903`/`:2457-2470`，`RING_F_SP_ENQ\|RING_F_SC_DEQ`）→ 控制消息错收（P0-6）。故本点**必须与 C-NR-313 成套实现**：proc_id 同值只用于 queue 映射，msg_ring 与 KNI owner 一律按 (proc_id, 代际) 或活跃代际判定。**不得单独合入本点** |
| C-NR-207 | `ngx_process_cycle.c:762-764`（respawn 条件） | 修改 | `graceful_reload=1` 时恢复原生 respawn 语义（reload 期间 worker 挂了允许重生或按状态机决策，DR6 定） |
| C-NR-208 | worker 侧 READY 上报 | 新增 | worker 完成 `ff_freebsd_init` + `ngx_open_listening_sockets` 后经 FF_RELOAD_READY 上报 master |
| C-NR-307 | `lib/ff_dpdk_if.c` init_clock(:1244-1257)/init_clock_worker(:1262-1272)/main_loop(:2804-2805) | 修改 | **自驱 hardclock**（[06] 第 2 节语义 11）。**【v1.9.1 终版：M2 必需项，无退路】**——D-A 定案「两代同 lcore_id」后 `priv_timer[L]` **必然同槽**（`rte_timer.c:51` 的 `priv_timer[RTE_MAX_LCORE]` 位于共享 memzone、`:216-228` `rte_timer_meta_init` 的 memset 会清零 G_old 的 `pending_head`/skiplist；叠加 `rte_timer_manage` 跨进程解引用对方私有地址，**不可修补**），本项为唯一解法。~~v1.9 曾以「两代 lcore_id 不同 ⇒ 天然不同槽」为由降为加固项~~ 已随 D-A 反转推翻。**做法**：init_clock 删除 `rte_timer_subsystem_init/rte_timer_meta_init/rte_timer_init/reset` 四连，改为计算 `hardclock_interval_tsc = hz_tsc / freebsd.hz`；main_loop 的 `if (freebsd_clock.expire < cur_tsc) rte_timer_manage()` 改为 `if (next_hardclock_tsc < cur_tsc) { ff_hardclock(); ff_update_current_ts(); next_hardclock_tsc += interval; }`。**合入门槛**：PT-NR-08 精度回归（偏差 ≤5%、无漏/重复触发、`graceful_reload=0` 行为等价）**不可省略**。**须独立提交**——改动全局 timer 心跳，是本项目回归风险最高的单点之一 |
| C-NR-308 | （**v1.9.1 拆分为 C-NR-314 + C-NR-315**，本编号保留为索引） | 修改 | **代际 mempool（应用侧 + 共享 RX 池）**，[06] 语义 12 / §6.6。**【v1.9.1 变更：恢复为 M2 必需项，并细化拆分】**：① **C-NR-314** = 应用侧分代际 pool（独立 cache ⇒ 应用侧竞态归零）；② **C-NR-315** = 共享 RX 池的跨代 free（DR11：**M-A 为主**（`cache_size=0`）/ M-B 备选（代 free，v1.9.3 人工定案）。**v1.9.1 新坐实**：`local_cache` 为 per-mempool 成员（`rte_mempool.h:258`）⇒ v1.7 所称「即使不同 pool 仍会同号 cache 槽竞态」不成立，**分代际即消除应用侧竞态**，全局 `cache_size=0` 不再是必选项 |
| ~~**C-NR-311**~~ | ~~代际 lcore 池与四链解耦（原属 M2）~~ | **已取消** | **【2026-09-01 人工决策】D-A 定案「两代使用相同 lcore_id」后本点不再需要**：不需要 2N 个 lcore_id，`lcore_mask`/`nb_procs`/队列数保持 N 不变，无新增配置面。取而代之的是**同 lcore_id 下的两处资源隔离**（C-NR-307 自驱 hardclock、C-NR-308 代际 mempool），二者**恢复为 M2 必需项**。保留本行仅供审计追溯 |
| **C-NR-314**（v1.4 新增；锚点已由独立审核员坐实，见 [09](09-review-report.md) §22） | `lib/ff_dpdk_if.c:616/632-638`（`init_mem_pool` 内的 `rte_pktmbuf_pool_create` `:632-635`、secondary `rte_mempool_lookup` `:636-638`）+ 应用侧 alloc/clone 点 **`:2564`/`:2706`/`:2173`** + `lib/ff_memory.{h,c}`（`ff_ref_pool`：`ff_memory.c:76` 声明、`:213` `ff_init_ref_pool()`、`:222` 创建、`:224` lookup、alloc `:424`，对外声明 `ff_memory.h:122`）+ `lib/ff_config.{h,c}`（代际池配置） | 新增+修改 | **【代际 mempool 细化实现·应用侧】**（[06] 语义 12 / §6.6.3，D-A 反转后的必需项）。① `graceful_reload=1` 时 **init 期预建** `mbuf_pool_%d_gen0/gen1`（含对应的 `ff_ref_pool`），G_new secondary `rte_mempool_lookup`；② 代际号按 reload 轮次**乒乓复用**（资源上界恒定）；③ 应用侧 alloc/clone 点改用本代际 pool；跨进程 free 靠 `m->pool` 指针自动回正确池，**无需额外记账**。依据：`local_cache` 是 per-mempool 成员（`dpdk/lib/mempool/rte_mempool.h:258`，访问见 `:1340-1341`）⇒ 分代际后两代 cache 互不重叠，应用侧竞态归零。**坐实附注**：(a) `:2564` 在 `FF_USE_PAGE_ARRAY` 打开时因 `:2561` 提前 return 而不执行，该构建下应用侧 alloc 只剩 `:2706`；**(b) `:2173`（ARP/NDP dispatch clone）与 `:2188`（`#ifdef FF_KNI` 内的 KNI clone）两处 `pktmbuf_deep_clone` 均纳入应用侧代际池**（M2 Batch A 实现按 lcore 清查合并版 §6.3 的权威口径执行，CR 已核对：alloc 出自本代池、free 经 `m->pool` 回本代池，功能安全且性能更优；KNI 无独立池，mbuf 全出于此点）；(c) `ff_ref_pool` 是 `ff_memory.c` 内的 `static`，代际化需先新增 accessor |
| **C-NR-315**（v1.4 新增；锚点已坐实） | M-A → **`lib/ff_dpdk_if.c:634`**（`rte_pktmbuf_pool_create` 的 `cache_size` 实参精确行）；M-B → 新增 `free_ring` + **主循环 drain 点 `:2861`**（tx drain `:2841-2860` 之后、rx_burst `:2865` 之前，本轮回收即可复用）+ G_old 侧 free 改 enqueue；常量 `FREE_RING_SIZE` 加在 **`lib/ff_memory.h:37`**（`DISPATCH_RING_SIZE :36` 与 `MSG_RING_SIZE :38` 之间）。RX 池绑定事实：**`rte_eth_rx_queue_setup` 在 `:1140-1141`**，pool 实参来自 `:1128` | 新增+修改 | **【共享 RX 池的跨代 free】**（[06] DR11，**v1.9.3 定案 M-A 为主**）。**M-A（主）**：RX 池 `cache_size=0`，简单但有**稳态持续损耗**（由 PT-NR-09 量化并下调 [06] §4.1 D5）；**M-B（备选）**：RX 池**保留 cache**，G_old 用完的 RX mbuf 批量 enqueue 到 `free_ring` 由 G_new 统一 free ⇒ 稳态零损耗；M-B 仅在 PT-NR-09 显示 M-A 稳态损耗不可接受时启用。**实现建议**：与 C-NR-310 的 `drain_ring_tx`（同为 G_old→G_new 方向）合并为一条通道，用 mbuf 私有标记区分「待发送」与「待释放」。**M-A 机理已坐实**：`cache_size=0` 时 `rte_mempool_default_cache` 返回 NULL（`rte_mempool.h:1333-1334`），get/put 直接走 `rte_mempool_ops_{dequeue,enqueue}_bulk`（`:1594-1597` / `:1416-1425`），全程无 per-lcore 私有缓存 ⇒ 多进程安全。取舍由 PT-NR-09 数据定案 |
| **C-NR-316**（v1.4 新增；锚点已坐实并补齐） | 心跳递增点 **`lib/ff_dpdk_if.c:2802`**（`main_loop` `:2747-2978`，`while(1)` `:2797-2975`；插在 `stop_loop` 检查 `:2799-2801` 之后、`cur_tsc = rte_rdtsc()` `:2803` 之前，保证每轮必执行且不受 sleep 影响）+ G_old 采样点 **`:2959`**（idle sleep `:2952-2953` 之前，保证空闲轮次也采样）+ 配置项：**`ff_config.h:317`**（dpdk 段字段区 `:271-338`，插在 `pkt_tx_delay` 后）、**`ff_config.c:1089` 后**（dpdk 段解析 `:1021-1089`，kni 段起 `:1091`）、**`ff_config.c:1579` 后**（`ff_default_config()` `:1566-1603`，dpdk 默认值区 `:1574-1584` 设默认值 1000） | 新增+修改 | **【G_new 崩溃检测与 rx 交还】**（[06] DR6 附则 / U-NR-8 定案）。① 共享内存**全局切换标记**由 G_new 每 loop 递增；② G_old 每 loop 采样比对，连续未递增超过阈值即判定失活；③ **标记随 G_old 排空退出、flow_map 消亡而停止递增**（避免 G_old 退出后无人递增导致误报）；④ 超时默认 **1s 可配置**（`reload_heartbeat_timeout_ms`，M4 实测校准）；⑤ 回退动作 = **primary 将 rx 交还 G_old**：置 `rx_owner_gen` 回退、G_old 退出无硬件模式恢复 rx/tx、关闭 flow_map。**实现约束（落到 C-NR-309）**：无硬件模式标志必须**可逆**，且恢复 rx 前须确认 G_new 确已不再 poll（否则回到并发 poll）。**坐实附注**：代码里**没有现成的运行时可切换标志**可复用——现有的 `primary_slim`（`ff_config.h:297`）是静态只读配置，main_loop 内直接判 `dpdk.primary_slim` 的位置为 `:2916`（KNI inject）与 `:2948-2950`（idle sleep），可作为「运行时标志门禁」的写法参照；另有 `:541-547`（`nb_rx_queue==0` 豁免）、`:2984-2987`（`ff_dpdk_if_up`）可参考。`rx_owner`/`no_hw`/`gen_id` 全库 0 命中，须新建 |
| **C-NR-313** | `lib/ff_dpdk_if.c:739-782`（`init_msg_ring`，含 `:763-778` 的 ring 创建循环）/`:764-777`（ring 命名与 `RING_F_SP_ENQ\|RING_F_SC_DEQ`）/`:2444`（`handle_msg` enqueue）/`:2456-2474`（`process_msg_ring`）/`:2903`（主循环按 proc_id 调用）；`lib/ff_dpdk_kni.c:101-109`（`ff_kni_is_runtime_owner`，`:108` 比较 `proc_id == kni.owner_proc_id`）；`lib/ff_config.h:345`（`owner_proc_id` 字段）+ `lib/ff_config.c:1093-1094`（解析）+ `:1440-1453`（owner lcore 必须在 lcore_list 的校验） | 修改 | **【v1.9 新增·P0-6】msg_ring 与 KNI runtime owner 的代际隔离**。① msg_ring 索引由 `proc_id` 改为 `(proc_id, 代际号)`（或代际各建一套 ring），保证 READY/DRAIN_DONE/REJECT/HANDOVER_ACK 只被本代际收到；② KNI runtime owner 改为跟随「当前活跃代际」，由 master/primary 在 T5（接管完成）更新，避免 owner 落到已退代际；③ `ff_config.c:1440-1453` 的 owner-lcore 校验须同步适配（两代同 lcore_id 下 owner 靠代际标记区分，不靠 lcore 区分）。**必须与 C-NR-206 成套实现** |

| 项 | 内容 |
|---|---|
| **前置** | M1 合入；**DR4 定案确认**（M0 评审：互斥=共享内存标记已运行时验证，消息=msg ring 维持；DR5 已取消；DR8 已定案；DR11 已定案 M-A 为主）。**v1.6 新增前置：lcore_id 共享态清查已闭环**（work/impl/m0-lcore-shared-state-audit.md：Class A 仅 timer 与 mempool 两项需处置，分别由 C-NR-307 五处与 C-NR-314/315+message_pool 覆盖；N-1/N-2/N-3 纳入 M2 编码） |
| **DoD** | ① clean build + 单测（UT-NR-04~06/10/12/15~16/**17/18/20** + 零回归；**v1.4：C-NR-307/308 恢复必需，UT-NR-17/18 一并恢复为必过**）；② 实机 RT-01（空载 reload：双代际并存、各自 listen、G_old 退出后 G_new 独自服务——此阶段尚未做同期接管，判据放宽为：reload 完成、服务最终恢复、无 crash）；③ RV1 初验（双代际共存 ≥30min 无异常，含 mbuf 水位平稳无泄漏趋势）；④ ~~C-NR-311 四链解耦~~ **已取消（D-A = 同 lcore_id）**——改为断言「两代 lcore_id 相同、`nb_procs`/队列数保持 N 未被撑到 2N」（承载用例 UT-NR-20，**v1.4 改为反向断言**）；⑤ **C-NR-313 代际隔离：双代际并存期间控制消息不错收（IT-NR-A11、UT-NR-12），KNI owner 交替后仍正确（RV13）**；⑥ **C-NR-307 自驱 hardclock：PT-NR-08 精度回归通过（偏差 ≤5%、无漏/重复触发、`graceful_reload=0` 行为等价）——合入门槛，不可省略**；⑦ **C-NR-314/315 代际 mempool：跨代 alloc/free 无泄漏、无 pool 错配、无双重释放；两个代际池乒乓复用，池数量不随 reload 轮次增长（PT-NR-09 + RV1）**；⑧ **C-NR-316 心跳：注入 G_new 失活（杀进程）→ G_old 在超时内检出并由 primary 交还 rx，服务恢复（新增 IT-NR-A12 / RT 用例）**。v1.4 复审修正：UT-NR-19 属 C-NR-310（M3 才实现），**不属 M2** |
| **测试门禁** | UT-NR-17/18/**20** + IT-NR-A11/A12 + RT-01 + RV1/RV6/RV13 观测记录 + **PT-NR-08（门槛）/PT-NR-09**。**不属 M2**：UT-NR-19、IT-NR-A09/A10（属 M3/M4） |
| **风险与回退** | 风险：① 多 secondary 并存的 mempool/EAL/msg_ring 并发（RV1 主体风险）；② **C-NR-311 四链解耦是新引入的配置语义变更**——`lcore_mask` 不再唯一决定 lcore 分配，配置错误可能让两代落到同一 lcore_id（违反 DPDK 硬禁令）或撑大 nb_procs，须靠校验链拦截并加启动期自检；③ **C-NR-313 若不与 C-NR-206 成套合入，控制消息会被错收**（P0-6，属必现缺陷）；④ **C-NR-307 改动全局 timer 心跳，且 v1.6 扩为 5 处改动点 + N-1/N-2/N-3 配套**（v1.3 曾降为加固项已被 v1.4 推翻；M0 实测同 lcore 必崩，此项是 M2 可运行的前提），须按最高回归风险对待（独立提交 + PT-NR-08 门槛）；⑤ **C-NR-315 `cache_size=0` 稳态损耗**（v1.4 恢复必需；v1.6 扩展到 message_pool）。**M0 新增风险登记**：ENV-1（vhost 分流骰子，约束见 C-NR-201）与 SIGTERM 大页泄漏（每进程组 ~23 页/次，M6 循环 reload 门禁须加大页余量断言，三次独立复现）。回退：`graceful_reload=0`（FF_RELOAD 不注册、reload 走旧路径）；C-NR-201~208、C-NR-311、C-NR-313、C-NR-307/308 各自独立提交串可分别 revert |
| **提交建议** | 7~8 个 commit：**自驱 hardclock（C-NR-307，最先独立合入 + PT-NR-08 回归）** / **代际 mempool 应用侧（C-NR-314）** / **共享 RX 池跨代 free（C-NR-315，DR11 已定案 M-A）** / **心跳与 rx 交还（C-NR-316）** / 配置与校验 / **msg_ring 与 KNI 代际隔离（C-NR-313，与 C-NR-206 同批）** / FF_RELOAD 消息族 / 状态机与 reload 顺序 / READY 协议 |

### 2.4 M3：同期接管 rx+tx+listen、TX 独占与 flow_map 软件分发表（v1.9：reta 不改，主路径）

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 3/6/7：G_new READY 后**同期接管 rx poll + tx + listen**（跨进程互斥标记保证不并发 rx poll；tx 由 G_new 独占）；**G_old 自此完全脱离硬件**（C-NR-309/310）；G_new 注册 flow_map 软件分发表（只记新流，miss 经 `drain_ring_rx` 转 G_old）；ARP/NDP clone 给 G_old；reta 不改（rss_check 四件套不变）；RX_QUEUE_SIZE 4096 增大接管窗口缓冲 |
| **范围** | [06](06-solution-design.md) 5.4-1（flow_map 三函数+互斥原语+drain_ring+ARP clone）、5.2 时序 T3 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-301 | `lib/ff_api.h` + 新增 `lib/ff_flow_map.c` | 新增 | **flow_map 三函数**：`ff_flow_map_lookup(four_tuple)` / `ff_flow_map_insert(four_tuple)` / `ff_flow_map_close()`（排空确认后关闭回稳态，[06] 第 2 节语义 6）——软件分发表替代 ~~ff_conn_owner_query~~ inpcb 查询，避免 syncache/inpcb 语义漏洞（审核 B-3/Q3b）。**【v1.2 修正·入表时机】**：插入点必须是**本栈收到 SYN 并发出 SYN-ACK 的时刻**（即 `syncache_insert` 完成、连接进入 syncache 半开态时），**不得**推迟到 `accept()` 返回时——三次握手的第 3 个 ACK 到达时连接仍在 syncache、尚无 inpcb，`accept()` 尚未发生；若按「accept 时入表」，该 ACK 会 flow_map miss → 被转给 G_old → G_old 无对应 syncache 条目 → 回 RST → **reload 窗口内新建连接全失败**（这正是 B-3/Q3b 的原始病根，仅换了一层形式）。实现须在 `tcp_input` 的 listen 分支（syncache 插入成功后）挂钩入表，并同步覆盖 SYN 重传（重传 SYN 命中已有表项，不重复插入） |
| C-NR-302 | 新增 `lib/ff_handover.c` 或扩展 `lib/ff_dpdk_if.c` | 新增 | **跨进程互斥原语** `ff_queue_handover_mutex(port, queue, from_gen, to_gen)`：共享内存标记（非 msg ring）——G_old 设停 rx 标记 + 确认已停 → G_new 确认后起 rx poll；保证不同时 poll 同一 queue（[06] 第 2 节语义 7）。~~set_rss_table 切流原语改造~~ v1.6 删除（reta 不改）。**【v1.9 补全规格，原仅给函数名】**：① 载体 = hugepage 共享内存 `struct ff_handover_state{ magic; rx_owner_gen; rx_stopped; }`，由 primary 创建；② 读写一律 `__atomic_*_n(..., __ATOMIC_SEQ_CST)`，禁止裸 volatile 轮询；③ **「G_old 停 poll」的精确定义 = 跳过 `rte_eth_rx_burst`（`ff_dpdk_if.c:2872`）与 tx drain（`:2844-2856`），但不退出主循环**——退出循环会导致 G_old 收不到 `drain_ring_rx` 的转发包（P1-4）；④ 超时（初值 100ms，RV3 校准）→ HANDOVER_TIMEOUT，由 master 决定放弃本轮或强制接管；⑤ G_old 异常退出时须清理脏标记 |
| C-NR-303 | `app/nginx-1.28.0/src/event/modules/ngx_ff_module.c`（worker init） | 修改 | G_new worker **READY 后自动注册** flow_map 查表回调（[06] 第 2 节语义 6，稳态零开销）：**① 先做协议过滤——仅 TCP/UDP 四元组参与归属判定，ARP/NDP/ICMP/非 IP/分片一律返回 `queue_id`（本栈处理），保留原生克隆路径**（否则 G_new 邻居表建不起来，见 C-NR-304）；② 解析四元组 → `ff_flow_map_lookup` → 命中（本代际新流，含 syncache 中的半连接）本栈处理 / **miss 一律**经 **`drain_ring_rx`** 转 G_old（**v1.9：不复用 `dispatch_ring`**——同队列下两代会成为同一 SC ring 的两个消费者，见 C-NR-310）；③ **目标 G_old 须按代际精确反算**并校验存活——G_old 已退出则本栈处理并按 TCP 规范回 RST，禁止 enqueue 到无主 ring；④ **排空确认后注销回调**（C-NR-403 通知驱动，含「`drain_ring_rx` 已排空」条件，见 U-NR-5） |
| C-NR-304 | `lib/ff_dpdk_if.c:2153-2195`（`protocol_filter` 起的 ARP/NDP 克隆分支；v1.9 复审修正：原写 `:2105-2183`，`:2105` 实际是 dispatcher 回调门禁而非 ARP/NDP 分支起点） | 修改 | **ARP/NDP clone 给 G_old**（[06] 第 2 节语义 9；审核 B Q3a）：ARP/NDP 等协议包在转给 G_new 协议栈处理的同时，额外 clone 一份转发给所有 G_old 进程——原有 clone 给其他 G_new 和 KNI 的逻辑不变（`:2161-2183`），新增 clone 给 G_old 分支。**v1.9 补充**：M1′ 下 G_old 已无硬件出口，此路径是其邻居表的唯一来源，从「优化项」升为**必需项** |
| C-NR-305 | `lib/ff_memory.h:43`（RX_QUEUE_SIZE）+ `lib/ff_config.{h,c}` | 修改 | RX_QUEUE_SIZE 默认 512→**4096**（[06] 第 2 节语义 7：接管窗口缓冲放大 8 倍）；**v1.9 追加**：新增 `drain_ring_size` 配置项（默认 2048，见 C-NR-310），并同步计入 mbuf 池预留 |
| C-NR-306 | `ngx_ff_reload.c` 状态机 | 修改 | T3 状态（v1.9 时序）：master 触发同期接管→**建立双向 drain_ring**→G_old 停 rx（互斥标记）→**G_old 进入无硬件模式**→G_new 起 rx poll+接管 listen+**独占 tx**→G_new 注册 flow_map→ARP/NDP clone 生效；~~SWITCH_REQ reta 切流~~ 改为 HANDOVER 消息族；超时/失败分支（DR6 前半） |
| **C-NR-310** | 新建 `lib/ff_drain_ring.c`（参照 `lib/ff_dpdk_if.c:660-680` `create_ring` 封装与 `:682-724` `init_dispatch_ring`）+ `lib/ff_memory.h`（容量常量）+ `ff_dpdk_if.c:2142-2150`（回调转发 enqueue 点，改为写 `drain_ring_rx`）+ `:2222-2236`（`process_dispatch_ring`，**仅作语义参照，不复用**）+ `:2865-2870`（主循环 dequeue 点） | 新增+修改 | **【v1.9 新增·P0-2】per-generation 双向 drain_ring**（**本点须先于 C-NR-309 实现**，309 依赖本点提供的 `drain_ring_tx`）。① 两个 ring 按 `(port, queue, 代际号)` 命名（**M3 实现 D-6 偏离**：多一个队列维度——F-Stack 每队列一个独立 FreeBSD 栈实例，包必须交回对端**同队列**实例，否则该栈无 PCB 会回 RST；N worker 共享一 ring 也会破坏单消费者语义），primary 创建、secondary lookup，且**每进程须创建/附着全部代际的 ring**（M3 实现 D-1：drain_ring 双向，任一代际都要本代 rx/tx + 对端 rx/tx 全部 4 个）；**flags 两侧不同（M3 CR 修正）**：`drain_ring_rx` 仅 `RING_F_SC_DEQ`（MP/SC——生产者有两类：owner 代 queue-q worker 的 flow_map miss 转发 + owner 代任意 worker 的 ARP/NDP clone fan-out，`RING_F_SP_ENQ` 会因多生产者损坏 prod head），`drain_ring_tx` 取 `RING_F_SP_ENQ | RING_F_SC_DEQ`（唯一生产者 ff_divert_tx_mbuf，保留零 CAS 快路径）；② `drain_ring_rx`：生产者 = G_new（flow_map miss），消费者 = G_old（**替代 `dispatch_ring` 转发，避免同队列下两代 dequeue 同一 SC ring**）；③ `drain_ring_tx`：生产者 = G_old，消费者 = G_new（出向代发）；④ **不可复用 `process_dispatch_ring`**，其语义是 dequeue 后以 `pkts_from_ring=1` 进 `process_packets → ff_veth_input`（入向进协议栈），与出向代发相反；⑤ 排空确认后**注销**（C-NR-403 驱动）；**M3 实现仅注销不销毁**（R-310-1：`rte_ring_free` 跨进程只能一个进程 free，且 `_g<gen>` 乒乓复用下销毁后下轮还要重建；注销后 ring 驻留 hugepage，创建者 re-init 经 EEXIST 回退 lookup 复用）。**承载用例**：UT-NR-19、IT-NR-A03 |
| **C-NR-309** | `lib/ff_dpdk_if.c:2540-2700`（`ff_dpdk_if_send`，协议栈出包统一入口，末尾 `:2699 send_single_packet`）/`:2519-2538`（`send_single_packet`）/`:2477-2495`（`send_burst`，全文件唯一 `rte_eth_tx_burst`）/`:2840-2860`（main_loop tx drain）/`:2702-2745`（`ff_dpdk_raw_packet_send`） | 新增+修改 | **【v1.9 新增·P0-1】TX 独占与 `drain_ring_tx` 代发**（**依赖 C-NR-310**）。**【v1.9.1 追加约束】无硬件模式标志必须「可逆」**——C-NR-316 的 rx 交还依赖本点：G_old 判定 G_new 失活后须能退出无硬件模式、恢复 `rte_eth_rx_burst` 与 tx；且恢复前必须确认 G_new 确已不再 poll（否则回到并发 poll 的老问题）。故本点实现时**不得**把该标志设计为一次性/不可回退。依据：`tx_queue_id` 与 rx 同号（`:486/:534`）、唯一 tx 出口在 `send_burst`（`:2495`）、`dpdk/lib/ethdev/rte_ethdev.h:6575-6577` 限定仅 `MT_LOCKFREE` PMD 允许同一 tx queue 无锁并发（virtio 未声明）。**做法**：① 新增「无硬件模式」标志（G_old 在 T3 后置位）；② `ff_dpdk_if_send` 在该标志下不调 `send_single_packet`，改为 `rte_ring_enqueue(drain_ring_tx[port][gen], m)`；③ `send_burst` 与**全部三处 flush 入口**在无硬件模式下不执行——`:2532`（`send_single_packet` 满 burst）、`:2557`（`FF_USE_PAGE_ARRAY` 分支内，**易漏**）、`:2853`（main_loop tx drain），保证 G_old 零 `rte_eth_tx_burst`；④ G_new 主循环每轮 dequeue `drain_ring_tx` 并直接 `rte_eth_tx_burst`（唯一消费者）；⑤ 满环须计数+告警，禁止沿用 `:2144-2147` 的静默 `rx_dropped++`。**判据（RV11）**：drain 期 G_old 无任何 tx_burst 路径（含异常/超时分支、含 `FF_USE_PAGE_ARRAY` 构建）。**承载用例**：IT-NR-A09 |

| 项 | 内容 |
|---|---|
| **前置** | M2 合入；**DR2/DR4/DR9 定案**（flow_map 形态 + 控制通道载体 + TX 处理形态） |
| **DoD** | ① clean build + 单测（UT-NR-11/13/14/**19** + 零回归）；② 实机 RT-02（带长连接流量 HUP：新连接全走 G_new、旧连接包 flow_map miss → `drain_ring_rx` 转发回 G_old 零 RST、G_old 出包经 `drain_ring_tx` 代发成功、ARP/NDP 正常）；③ RT-03（持续 CPS 压力下 reload，客户端错误 0）；④ **RV11：TX 独占断言通过（IT-NR-A09）——G_old 在 drain 期零 `rte_eth_tx_burst`**；⑤ RV3 互斥正确性 + RV4/RV5 实测数据落盘（DR7/DR9 输入） |
| **测试门禁** | UT（含 UT-NR-19）+ **IT-NR-A09/A10** + IT-NR-A02/A03/A07/A08 + RT-02/RT-03 |
| **风险与回退** | 风险：RV3 互斥标记实现缺陷导致并发 rx poll（virtqueue 数据结构损坏，静态无法定论需实测）；RV4 ring 容量与满环行为；RV5 flow_map 查表开销；**RV11 代发路径在出包高峰成为瓶颈（则按 DR9 切 tx queue 分离）**。**v1.9 新增风险**：T3 后 **G_new 崩溃时 G_old 已脱离硬件、无法续服**（v1.6 形态下 G_old 仍持 rx），回退依赖 primary/master 检测与恢复，须与 DR6 一并定案。回退：接管消息不触发（状态机停在 T2，G_old 继续服务，本轮 reload 放弃）；互斥标记保证不会并发 rx poll；`graceful_reload=0` 兜底 |
| **提交建议** | 6 个 commit：flow_map 三函数 / 互斥原语（含规格⑤点） / **drain_ring 双向通道（C-NR-310）** / **TX 独占与代发（C-NR-309，依赖 C-NR-310）** / ARP clone+RX_QUEUE_SIZE+drain_ring_size / 回调注册与状态机 T3 |

### 2.5 M4：drain 收尾、异常回退与状态机完备（HUP 全链路）

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 3（drain 保障）与 [04](04-fstack-current-analysis.md) §4 补充事实：T4/T5 落地——**G_old 停 accept 并延迟 close listen（C-NR-312，v1.9 修正）**、drain 存量连接至自然关闭（出包经 `drain_ring_tx` 代发）、drain 挂起强退兜底、flow_map 关表 + drain_ring 注销回稳态；T0-T5 全链路 + 全部异常分支打通（**含 T3 后 G_new 崩溃**） |
| **范围** | [06](06-solution-design.md) 5.4-4 第 3/4 条、DR6 全部回退目标态、5.2 异常分支 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-401 | `ngx_process_cycle.c:894-898`（对照原生 :951-957） | 修改 | **补回 `ngx_set_shutdown_timer`**（F-Stack 版 worker QUIT 分支缺失，[04](04-fstack-current-analysis.md) §4 补充事实）；此项是修 bug 性质，可提前独立提交（不依赖 M1~M3，`graceful_reload=0` 也受益） |
| C-NR-402 | `ngx_ff_reload.c` + `ff_msg.h` | 新增 | drain 进度上报（FF_RELOAD_DRAIN_PROGRESS：剩余连接数/最后活动时间）+ **G_old 排空确认上报（FF_RELOAD_DRAIN_DONE：连接数=0 且全部 G_old 进程退出）** + drain 强退阈值（shutdown timer 时长，默认建议对齐 nginx `worker_shutdown_timeout` 语义，值经 RT-06 校准） |
| C-NR-403 | `ngx_ff_reload.c` | 修改 | 状态机 T4/T5：收 G_old 全退 SIGCHLD/DRAIN_DONE → **通知 G_new 关闭 flow_map 并注销双向 drain_ring，G_new 进入稳态成为下轮 G_old（防性能退化，[06] 第 2 节语义 6；防重入拦截随排空确认解除）** → **【v1.9 追加】更新 KNI runtime owner 至当前活跃代际（C-NR-313 的收尾动作）** → ~~释放段 A → 乒乓翻转记账~~（v1.6 删除：不再乒乓，同队列）→ reload 完成打点 |
| C-NR-404 | `ngx_ff_reload.c` 异常分支 | 修改 | ① T2 前 G_new 任一 worker 起不来/READY 超时 → 放弃本轮（G_old 未动，对齐内核 HUP 配置失败回滚语义）；② T3 接管失败（G_old 未确认停 rx / G_new 起 rx 超时）→ 放弃本轮（互斥标记保证不会并发 rx poll）；③ primary 被 kill → 本轮 reload 安全放弃 + 告警（primary_slim E10：primary 不可复活）；**④ 【v1.9 新增·DR6 必答项】T3 之后 G_new 崩溃**——M1′ 下 G_old 已脱离硬件、无法自行恢复 rx（这是相对 v1.6 形态**新增的风险**），须定案回退目标态：由 primary 将 rx 交还 G_old（若仍在）/ 触发新代际重生 / 整体降级为有损 reload，并给出检测手段（心跳/SIGCHLD）与超时 |
| C-NR-405 | `ngx_process_cycle.c` G_old graceful 分支（F-Stack 版 `:888-899`，对照原生 `:945-954`） | 修改 | G_old 收 QUIT：**【v1.9 修正】先停 accept，延迟 close listening 至自身 syncache 半开条目排空或超时**（C-NR-312，不立即 close）+ 进入无硬件模式继续跑 ff_run drain；**存量连接后续包经 flow_map miss → `drain_ring_rx` 转发回来，出包经 `drain_ring_tx` 由 G_new 代发**（M3 已铺）。注：drain 期存量连接流量**100%** 走 ring 转发且**双向各一跳**（v1.6 为出向零跳；M1′ 出向也走 ring），RV4 的 ring 容量与背压压力按此量级评估 |
| C-NR-406 | 打点与可观测收尾 | 新增 | 每阶段耗时/计数落 ff_top 或日志（reload 总时长、接管时延、drain 时长、**上行/下行转发包量**、`drain_ring` 满环次数、水位峰值），供 PT-NR-03/10 与 A-NR-14 度量 |
| **C-NR-312** | `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:888-899`（F-Stack 版 QUIT 分支，`:896 ngx_close_listening_sockets`；对照原生 `:945-954`，`:953 ngx_set_shutdown_timer`）+ `freebsd/netinet/tcp_syncache.h:36-48`（导出接口清单）+ `tcp_syncache.c`（`syncache_lookup` 为 static，`:1052`） | 新增+修改 | **【v1.9 新增·P0-5】半开连接窗口处理**。问题：移交前 G_old 收到的 SYN 停留在自身 syncache；T4 若立即 close listening，第 3 个 ACK 到 G_new → flow_map miss → 转回 G_old → 虽有 syncache 条目但 `syncache_expand`（`tcp_syncache.c:1033-1055`）需 `*lsop` 建 socket 而 listening 已 `in_pcbdrop`（`tcp_close` 对 LISTEN 只做 `in_pcbdrop`，`tcp_subr.c:2517-2553`，**不清 syncache**）→ 连接失败。**做法（择一，倾向 a）**：(a) **延迟 close listening**：G_old 只停 accept，保留 listening socket，轮询自身 syncache 半开条目计数至 0 或超时后 close（超时由 C-NR-401 的 shutdown timer 兜底）；**注意 `tcp_syncache.h:36-48` 未导出任何半开条目计数接口**（只有 `syncache_init/destroy/unreach/expand/add/chkrst/pcblist`），需新增一个轻量导出函数或复用 `syncache_pcblist` 的统计路径；(b) T3 时导出 G_old syncache 中的半开四元组给 G_new，登记进 flow_map 并标记「转 G_old」（需把 `syncache_lookup` 从 static 改为导出或新增遍历钩子，改动更大）。**判据（RV12）**：构造「SYN 在 T3 前、ACK 在 T3 后」的注入用例，握手成功率 100% |

| 项 | 内容 |
|---|---|
| **前置** | M3 合入；**DR6 评审完成**（含 T3 后 G_new 崩溃的回退定案） |
| **DoD** | ① clean build + 单测（UT-NR-10 状态机全转移 + 零回归）；② 实机 HUP 全链路：RT-01~RT-03 复跑全绿 + RT-05/06/07/09 异常注入全绿 + RT-10（连续 20 轮 reload：**每轮 queue/lcore 映射一致、无资源泄漏、抢先 HUP 被正确拒绝**）；③ RT-14（同核高负载切换，RV10 集成复验）；④ **RV12：半开连接窗口用例通过（IT-NR-A10）**；⑤ RV9 小规模预演：带流量连续 reload 50 次零错误 |
| **测试门禁** | UT + **IT-NR-A10** + RT-01~RT-10 + 50 次循环 reload |
| **风险与回退** | 风险：drain 强退阈值过短误杀长连接（RT-06 校准）；异常分支状态机死锁（用例覆盖每分支）；**C-NR-312 若选 (a)，延迟关闭的超时值需要权衡「半开连接完成握手」与「drain 及时收尾」**。回退：C-NR-401 独立；402~406 与 C-NR-312 各自独立提交串 revert 后 M3 行为保留（drain 依赖 nginx 原生 no_timers_left，无强退兜底） |
| **提交建议** | 4 个 commit：shutdown timer（可提前）/ drain 上报与强退 / **半开连接窗口（C-NR-312）** / 状态机 T4-T5 与异常分支 |

### 2.6 M5：USR2 二进制升级

| 项 | 内容 |
|---|---|
| **目标** | [06](06-solution-design.md) 5.2 USR2 段：master 无 ff 状态可安全 exec；新 master 对接常驻 primary，fork 全 secondary worker，复用 M2~M4 全套 T1-T5 机制；老 master 保留回退能力 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-501 | `src/core/nginx.c`（USR2/exec 路径） | 验证+微调 | 确认 master 侧无任何 ff 状态残留（[04](04-fstack-current-analysis.md) §2.2 已证 master 不 ff_init、socket 未劫持）；处理 exec 后 pid 文件/channel 与常驻 primary 的共存（候选 a/b 差异点） |
| C-NR-502 | 新 master 启动分支（`ngx_master_process_cycle`） | 修改 | 探测常驻 primary → 全 secondary fork（复用 C-NR-100~104）→ READY → 切流（复用 M3）；老 master 的 worker 即「G_old 代际」，复用 drain |
| C-NR-503 | WINCH/QUIT 语义 | 修改 | 老 master 收 WINCH → 对老 worker 走 M4 drain；QUIT 收尾不波及常驻 primary（候选 b 需显式豁免） |
| C-NR-504 | 回退路径 | 验定 | USR2 后新二进制异常 → 对老 master 发 HUP 回退（老 worker 未 drain 完时语义验证，RT-04b） |

| 项 | 内容 |
|---|---|
| **前置** | M4 合入。**【M2 CR 移交的硬前置】跨 master 世代 gen/ring 撞号问题必须解决**：USR2 新 master 重建匿名块 active_gen=0 起步，老 worker（偶数次 reload 后 gen=0）与新 worker 撞号 ⇒ 共享 gen0 msg_ring 双消费者 + KNI 双主（块独立但 DPDK ring/mempool 名字空间跨 master 共享、常驻 primary 不换代）——ring 名掺入 master epoch 或改命名 shm + 世代握手（C-NR-502 承载） |
| **DoD** | ① RT-04（USR2 带流量升级零错误）；② RT-04b（升级失败回退可用）；③ HUP 回归复跑不劣化 |
| **测试门禁** | RT-04/04b + RG-NR-01 |
| **风险与回退** | 风险：exec 后环境/fd 细节（channel 继承）；候选 b 下 primary 归属交接。回退：不使用 USR2 即无影响（HUP 路径不依赖本章） |
| **提交建议** | 1~2 个 commit |

### 2.7 M6：终门禁、特殊场景回归与文档收尾

| 项 | 内容 |
|---|---|
| **目标** | 关闭全部 RV：RV9 终门禁（v1.6 修订：循环 reload ≥100 次，每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次，对齐 [01](01-vpp-vcl-research.md) §6.3-7 VPP 模式并适配防重入语义）、RV8（KNI）、zc 场景回归、文档入库 |

**编码工作清单**：

| 编号 | 文件 | 类型 | 要点 |
|---|---|---|---|
| C-NR-601 | 新增 `tests/integration/test_graceful_reload.sh`（实机 B 组 harness） | 新增 | 真实执行 + 逐用例判定 + 退出码汇总；TARGET_IP 必填参数；进程终止走 `kill_process.sh`、清理走 `rm_tmp_file.sh`（硬性规约见本文「关键结论 6」）；内嵌循环 reload 驱动（可配次数/间隔） |
| C-NR-602 | 无正式编码（RV8 用例执行） | 测试 | `enable_kni=1` 的 reload 回归（RT-12），问题修复按需另立 C 项 |
| C-NR-603 | 无正式编码（zc 回归用例） | 测试 | zc 收包路径下 reload 回归（RT-13，[06](06-solution-design.md) 5.5 正交性验证） |
| C-NR-604 | `doc/F-Stack_Nginx_APP_Guide.md`、`doc/F-Stack_Release_Note.md`、`config.ini` 注释 | 文档 | 部署形态（常驻 primary + **queue_id 代际无关映射 + 两代同 lcore_id** + **代际 mempool（乒乓复用）** + graceful_reload 开关矩阵）、运维手册（reload 状态打点解读、**`drain_ring` 水位与满环告警**、primary 死亡降级处置、**T3 后 G_new 崩溃的处置流程（含心跳超时调优）**、drain 强退阈值调优）、**DPDK 硬禁令例外适用的说明**、语义变更声明 |

| 项 | 内容 |
|---|---|
| **前置** | M4（M5 可并行推进）；**RV14 已确定门禁节拍配置** |
| **DoD** | ① RV9：持续流量 + 每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次，≥100 次零错误、无死锁无 crash、mbuf/内存无泄漏趋势（v1.6 修订：原「每 2~5s reload、≥1000 次」与防重入语义+25s 初始化不可同时成立；**v1.9 补充：须先由 RV14 给出 keepalive 配置与强退阈值，否则 100 轮的机时不可控**）；② RT-12/13 通过（或出明确结论与限制声明）；③ 全部 RV1-14 关闭记录在案；④ 文档入库 |
| **测试门禁** | PT-NR-05 终门禁 + 全量 RT 矩阵复跑 |
| **风险与回退** | 风险：长循环暴露的低概率状态错位（VPP #3547/#3645 前车之鉴，[01](01-vpp-vcl-research.md) §4.3/§6.4）——这正是门禁价值所在，暴露即回 M4 状态机修。回退：无代码回退需求 |
| **提交建议** | 2 个 commit：测试脚本 / 文档 |

### 2.8 M7（可选）：dispatcher 中心化（S3-M2）

仅当 DR7 触发（M6 数据，v1.3 修订判据——流表窗口化后稳态损耗恒 0，原稳态判据失效：改为 **reload 窗口内**转发开销致吞吐下降 >5%、或 drain 期 P99 劣化 >10%、或高存量连接场景 drain 时长超 SLO）才立项。方向：slim primary 统一收包 + 流表分发，worker 变纯 ring 消费者（VPP app_listener workers bitmap 同构 + 旧 iWiki dispatch 思想现代化，避开同核共存）。**若触发须另立 spec 重新走本流程**，本文不展开。

## 3. 后续编码工作清单汇总（按提交批次）

**43 个编码点**已按里程碑列于第 2 节各表（计数规则见 §0 数字口径说明：308 已拆为 314/315 作索引不计数、311 已取消）。此处仅给跨里程碑的总依赖序（DAG 摘要）与并行度建议（**v1.4 更新**）：

```
M0(E-NR-01   RV7   栈隔离 listen        ── 一票否决
  +E-NR-02b  RV3   rx 接管互斥          ── 一票否决
  +E-NR-06   RV10  同核切换             ── 一票否决
  +E-NR-07   RV11  TX 独占（v1.9 新增）  ── 一票否决
  +E-NR-08   RV12  半开连接窗口（v1.9）  ── 一票否决
  + E-NR-03/04/05 基线与初验 + DR1/DR4/DR8 定案 + DR2 初评（~~DR5 已取消~~）)
        │
        ▼
  C-NR-100/101 ──> 102/103 ──> 104/105 ──> 106                              [M1  7]
        │
        ▼ (DR4/DR8；~~DR5 已取消~~)
  C-NR-307（自驱 hardclock，**M2 最先做**，独改全局 timer 心跳，独立回归 PT-NR-08）
  C-NR-314（代际 mempool 应用侧，init 期预建 + 乒乓复用）──┐
  C-NR-315（共享 RX 池跨代 free，**DR11 已定案 M-A**）────────┤ 三者构成
  C-NR-307 + 314 + 315 = 同 lcore_id 下的资源隔离三件套 ──┘「同 lcore_id 前提」
        │
        ▼
  C-NR-201/206 + C-NR-313（msg_ring/KNI 代际隔离，**必须与 206 同批**）
        ──> 202/203 ──> 205 ──> 204/207 ──> 208                              [M2 13]
  C-NR-316（心跳 + rx 交还，依赖 307/309 的「无硬件模式可逆」）── M2 铺检测、M4 验收
        │
        ▼ (DR2/DR4/DR9 终案)
  C-NR-301 ──> 310（drain_ring 双向通道）──> 309（TX 独占与代发，依赖 310）
        ──> 302 ──> 303 ──> 304/305 ──> 306                                  [M3  8]
C-NR-401（shutdown timer，可提前至任意时点独立提交）
        │
        ▼ (DR6，含「T3 后 G_new 崩溃」必答项)
  C-NR-402/403 ──> 312（半开连接窗口）──> 404 ──> 405/406                     [M4  7]
        │
        ├──> 501~504 [M5  4]
        └──> 601~604 [M6  4]（M5/M6 可并行；RV14 确定门禁节拍后执行）
```

- **可提前独立项**：
  - C-NR-401：补 shutdown timer（修 bug 性质，不依赖 M1~M3，`graceful_reload=0` 也受益）。
  - **C-NR-307 自驱 hardclock**：**v1.4 恢复为必需项**，且因改动全局 timer 心跳，建议**最先独立合入 + 独立回归（PT-NR-08）**后再做 M2 其余部分。
- **v1.4 最高风险单点（重排，D-A 反转后）**：
  1. **C-NR-307 自驱 hardclock**：改动 timer 心跳这一全局基础机制，精度劣化会**静默**影响 RTO/keepalive。同 lcore_id 定案后本项为唯一解法，无退路；门槛是 PT-NR-08。
  2. **C-NR-314/315 代际 mempool**：同 lcore_id 下唯一的资源冲突点。风险在于「池乒乓复用的时序」与「跨代 free 的正确性」——表现为 mbuf 泄漏、双重释放或 pool 错配，需 PT-NR-09 + RV1 长稳双重覆盖。**M-B 的 `free_ring` 若与 `drain_ring_tx` 合并通道，需防止「待发送」与「待释放」标记混淆**。
  3. **C-NR-309 TX 独占**：若 G_old 残留任何 tx 路径（含 `FF_USE_PAGE_ARRAY` 分支），即为 DPDK 契约违反；须有 IT-NR-A09 断言兜底。
  4. **C-NR-316 心跳与 rx 交还**：依赖 C-NR-309 的「无硬件模式」必须**可逆**；且交还 rx 前须确认 G_new 确已不再 poll，否则回到并发 poll 的老问题。
- **并行度**：M1 单人串行；C-NR-401 可与任意里程碑并行；C-NR-307/308（若启用）独立串行回归；M5 与 M6 前半可双线并行；M7 条件触发（D-C：不提前）。
- 每个提交串保持独立可 revert；revert 顺序遵守依赖反向。
