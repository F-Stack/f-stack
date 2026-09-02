# 06 方案设计：候选方案对比与推荐方案 S3 关键设计

| 项 | 值 |
|---|---|
| 文档编号 | 06 |
| 标题 | F-Stack Nginx 无损 reload 候选方案对比（S1~S4）+ 推荐方案 S3 设计 |
| 版本 | v1.9.3（v1.9 基础上：**人工决策反转 D-A = 两代使用相同 lcore_id**，并据此细化代际 mempool 方案、取消四链解耦、定案 DR6 与心跳机制） |
| 日期 | 2026-09-02 |
| 状态 | 待人工审计（v1.9 交叉审核修订 + 人工决策落盘） |
| 修订来源 | 2026-09-01 独立交叉审核（只读，无代码改动、无 git 写操作），全部结论带 `文件:行号` 证据，区分「代码坐实」与「推断」 |
| 决策定案 | **D-A=两代使用相同 lcore_id**（2026-09-01 人工决策，推翻本轮前一版「不同 lcore_id」；DPDK 硬禁令理由由代际 mempool 消除 ⇒ 例外适用）；D-B=**采用 M1′ 形态**；D-C=**M2 维持可选演进**（DR7 触发，不提前）；**DR5 取消**；**DR6=方案① primary 将 rx 交还 G_old**（心跳=共享内存全局切换标记每 loop 递增，G_old 排空后随 flow_map 消亡，超时默认 1s 可配）；**语义 11/12 恢复为必需项** |
| v1.9.1 变更 | 语义 8/11/12/15、§6.2（DR5 取消 / DR6 定案+附则 / DR8 反转 / 新增 DR11）、§6.3（重写）、§6.6（重写为代际 mempool 细化设计）、§4.1 D5、§5.4-3、§7、§9 |
| 来源产物 | work/solution-design.md（方案设计师 solution-designer，2026-08-18 落盘）。本篇为正式化改写：输入为 [01](01-vpp-vcl-research.md)/[02](02-other-projects-research.md)/[03](03-fstack-legacy-solution.md)/[04](04-fstack-current-analysis.md)/[05](05-ld-preload-alternative.md) 五篇的前身产物（均已全文阅读）+ 关键机制回查实际代码交叉验证（只读）；保留全部事实证据、单来源声明与未坐实标注 |

相关篇章：[00-总览](00-overview.md) | [04-现状分析](04-fstack-current-analysis.md) | [07-里程碑](07-milestones.md) | [08-测试计划](08-testing.md)

### v1.9 修订摘要（2026-09-01 交叉审核）

审核范围：v1.6/v1.7/v1.8 三版新增语义的代码实证复核（对照 2026-08-21 四份历史审核报告所针对的 v1.3，本轮为增量审核）。

| # | 缺陷（v1.8 现文） | 关键证据 | v1.9 处理 |
|---|---|---|---|
| P0-1 | **TX 队列并发独占违反 DPDK 契约**：T3 后 G_old drain 发包与 G_new 服务发包使用同一 `tx_queue_id`，06 只对 rx 做互斥、tx 零保护 | `ff_dpdk_if.c:486/:534`（tx 与 rx 同号）、`:2478-2495`（唯一 `rte_eth_tx_burst` 点）、`:2532`/`:2557`（`FF_USE_PAGE_ARRAY` 分支内）/`2844-2856`（三处 flush 入口，v1.9 复审修正：原写「两个」漏了 `:2557`）；`dpdk/lib/ethdev/rte_ethdev.h:6575-6577`（仅 `RTE_ETH_TX_OFFLOAD_MT_LOCKFREE` PMD 允许无锁并发，virtio 未声明） | 语义 13：G_new 独占 tx，G_old 出包经 `drain_ring_tx` 代发 |
| P0-2 | **dispatch_ring 双消费者违反 `RING_F_SC_DEQ`**：同队列下两代 dequeue 同一个 ring | `ff_dpdk_if.c:710-713`（`RING_F_SC_DEQ`）、`:2865-2870`（同循环同 queue_id dequeue）、`:2144-2147`（满环静默丢包） | 语义 13：改用 per-generation `drain_ring_rx`/`drain_ring_tx`，各自 SP/SC 明确 |
| P0-3 | **「同队列 + 不同 lcore_id」与 nb_procs/lcore_mask 语义死锁** | `ff_config.c:118/:127/:139`（lcore_mask 置位数 = nb_procs）、`ff_dpdk_if.c:508`/`:518-524`（proc_id→lcore_id→queueid 一条链）、`ff_config.c:555-574`（nb_lcores = nb_procs） | ~~语义 15：四链解耦规则 + 新增配置面~~ → **v1.9.1 随 D-A 反转为「同 lcore_id」而消解**：不需要 2N 个 lcore_id，`lcore_mask`/`nb_procs`/队列数保持 N，无新增配置面 |
| P0-4 | **lcore_id 口径自相矛盾**：§6.3 说「不同 lcore_id」、语义 11/§6.6 按「同 lcore_id」设计 | 06 §6.3:388、§3.3:176 vs §2 语义 11:73、§6.6:413-426 | **v1.9.1 终版：统一为「同 lcore_id」**（D-A 人工决策），§6.3 重写、**语义 11/12 恢复为必需项**（v1.9 曾定「不同 lcore_id + 两条改造降为加固项」，已被推翻） |
| P0-5 | **移交瞬间半开连接无归属**：G_old close listening 后其 syncache 半开条目无法完成握手 | `tcp_syncache.c:1033-1055`（expand 需 lsop）、`tcp_subr.c:2517-2553`（`tcp_close` 对 LISTEN 不清 syncache，仅 `in_pcbdrop`） | 语义 14：listening 延迟关闭至 syncache 排空（或 T3 导出半开四元组） |
| P0-6 | **msg_ring 按 proc_id 冲突**：两代 dequeue 同一 msg ring，控制消息错收 | `ff_dpdk_if.c:2903`/`:2457-2470`、`:764-777`（`RING_F_SP_ENQ\|RING_F_SC_DEQ`）；`ff_dpdk_kni.c:101-109`（KNI runtime owner 同类问题） | 语义 15：msg_ring 与 KNI owner 代际隔离 |

另修 P1-3（D5 评级与 `cache_size=0` 口径）、P1-4（G_old 停 poll 精确定义）、P1-5（移交互斥原语规格）、P1-7（kernel_coexist 未评估声明）与 P2 残留（§5.3 reta 表述、§0 行号、§8 单来源口径）。

**方案形态升级**：v1.6 的「两代共享同一批硬件队列（rx 互斥移交 + tx 无保护）」改为 v1.9 的 **M1′「单硬件所有者 + drain 代际软件寄生」**——T3 后 G_new 独占 rx+tx，G_old 完全脱离硬件只跑协议栈，双向经两个新 ring 转发（详见 §3.3 与 §5.2）。

---

## 0. 输入清单与交叉验证声明

本设计基于以下 5 份产物（均已全文阅读）：

| 代号 | 文档 | 性质 |
|---|---|---|
| R-A | [01-VPP/VCL 调研](01-vpp-vcl-research.md) | VPP VCL 机制 + 工程问题 + 队列归属结论 |
| R-B | [02-其他项目调研](02-other-projects-research.md) | 内核基线/其他用户态栈/通用模式 |
| E-C | [03-旧社区方案考证](03-fstack-legacy-solution.md) | issue #547/#12、iWiki 旧方案、timer 演变 git 链 |
| P-D | [04-F-Stack 现状分析](04-fstack-current-analysis.md) | F-Stack 现状 + 8 项障碍清单 |
| P-E | [05-ld_preload 备选路线](05-ld-preload-alternative.md) | ld_preload 路线优势/缺口 |

设计关键机制时另行回查的代码（与上述产物行号一致，以实际代码为准）：

- `lib/ff_dpdk_if.c:2105-2150`：packet_dispatcher 回调 + dispatch_ring 跨进程转发（**关键确认：回调仅对 `!pkts_from_ring` 的包触发，门禁在 `:2105`——`:2100-2103` 是收包计数门禁（`ff_traffic.rx_packets/rx_bytes`）与回调无关，v1.8 引用 `:2100` 有误，v1.9 修正**；ring 转发来的包以 `pkts_from_ring=1` 短路，不会二次进回调——转发兜底机制天然无循环风险）。
- `lib/ff_dpdk_if.c:2222-2236`：process_dispatch_ring 从 per-(port,queue) ring dequeue（`:2228`）后以 `pkts_from_ring=1` 进 process_packets（`:2232`）→ ff_veth_input。**语义是「入向进协议栈」，出向代发不可复用本路径**（v1.9 语义 13 依据）。
- `lib/ff_dpdk_if.c:2478-2495`：`send_burst()` 是全文件唯一 `rte_eth_tx_burst` 调用点，`queueid = qconf->tx_queue_id[port]`；`ff_dpdk_if.c:486/:534` 显示 `tx_queue_id` 与 rx `queue_id` 同号（同源于 `:518-524` 的 lcore_list 下标）。**构成 v1.9 P0-1 的证据**。
- `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:223-270`：`#if (NGX_HAVE_FSTACK)` 两段串行 reload（先全退再起新）。
- `app/nginx-1.28.0/src/event/modules/ngx_ff_module.c:169-187`：ff_mod_init 按 proc_type 硬编码拼 `--proc-type=primary/secondary`。

另粗读 `docs/primary_slim_spec/03-solution-design.md`、`10-feasibility-conclusion.md` 作为 S3 依据。

### 0.1 两条外部调研线的共同结论基线（第 1 判据，方案评估的锚）

R-A §6.2 与 R-B §5.2 增补段独立得出同构结论，本设计将其作为第一判据：

1. **业界无 TCP 已建连接迁移先例**（R-B §4 P4：Envoy 原句 "existing connections are not transferred"；R-A §4.2 第 5 点 VCL 旧 worker 连接随 drain 关闭互证）。目标语义必须对齐「**新连接无缝切换 + 旧进程 drain**」，不追连接状态迁移。
2. **网卡队列/收包所有权与业务进程生命周期解耦，是用户态栈无损 reload 的结构性前提**（R-A §6.2：VPP 队列归独立进程、无主窗口结构性不存在；#1078 primary_slim PoC 杀 primary 后 12/12 连接零中断；adapter/syscall 中心化设计，三方独立指向同一结论）。**监听 fd 归属是第二位的控制面问题**（P-D 障碍 2 的前提性弱化）。
3. FB "ready 前不切流"（R-B §2.4(a)）与 VCL app_listener workers bitmap（R-A §2.2/§4.2）同构：新 worker 注册进 bitmap / 应用 ready 之前，accept 不分发给它、流量持续给旧实例。

### 0.2 v1.9 新增回查代码（本轮交叉审核实读，均为本分支 release/2.0 当前内容）

| 文件 | 区段 | 用于坐实 |
|---|---|---|
| `lib/ff_dpdk_if.c` | `:486/:534`、`:518-524`、`:2478-2495`、`:2532`/`:2557`/`:2853`（三处 flush 入口）、`:2840-2901`、`:710-713`、`:764-777`、`:2457-2470` | TX 与 rx 同号、唯一 tx 出口、main_loop 中 dequeue 与 rx_burst 的同循环耦合、两个 ring 的 flags |
| `lib/ff_config.c` | `:118/:127/:139`、`:555-574` | lcore_mask 置位数 = nb_procs、nb_lcores = nb_procs（四链死锁） |
| `lib/ff_dpdk_kni.c` | `:101-109`（`:108` 比较 `proc_id == kni.owner_proc_id`） | KNI runtime owner 绑定 proc_id，代际交替后会落到已退代际 |
| `freebsd/netinet/tcp_syncache.c` | `:1033-1055`（`syncache_lookup` 的 `static` 声明在 `:586`） | `syncache_expand` 靠 VNET 私有全局 hash，需 lsop 建 socket |
| `freebsd/netinet/tcp_syncache.h` | `:36-48` | 导出接口仅七项，**无半开条目计数接口**（C-NR-312 需新增） |
| `freebsd/netinet/tcp_subr.c` | `:2517-2553`（`syncache_destroy` 唯一调用点在 `:1583` 的 `tcp_destroy`） | `tcp_close` 对 `TCPS_LISTEN` 只 `in_pcbdrop`，不清 syncache |
| `dpdk/lib/ethdev/rte_ethdev.h` | `:6575-6577` | 仅 `RTE_ETH_TX_OFFLOAD_MT_LOCKFREE` PMD 允许同一 tx queue 无锁并发 |
| `dpdk/doc/guides/prog_guide/multi_proc_support.rst` | `:169-172` | primary/secondary 禁止共用同一 logical core（DPDK 硬禁令） |

> 上表行号已由**独立复审员**（写审分离）逐条回查坐实，复核结论见 [09](09-review-report.md) §20。

## 1. 评估维度与判据

| # | 维度 | 高分标准（打分依据） |
|---|---|---|
| D1 | 无损性/丢包窗口 | 结构性无损：reload 全程收包队列始终有主、新连接切换原子（对照 R-A §6.2 VPP 模式）。中等：工程无损——切换窗口依赖缓冲兜底（NIC rx ring/dispatch ring），窗口微小但需实测。低：存在无缓冲的服务空窗 |
| D2 | 连接保持语义 | 对齐基线 1：新连接无缝 + 存量连接完整 drain（旧进程活着跑完 RTO/keepalive 至自然关闭）。加分：drain 期间旧连接收包路径有显式保障；减分：需要「TCP 状态迁移」这种无业界先例的机制（风险转嫁） |
| D3 | 改动面与风险 | 代码量、涉及层（nginx 适配层 / lib / DPDK 补丁 / 网卡驱动）、对现有稳态路径的侵入度、是否有已验证的 PoC 基础 |
| D4 | 与主线演进兼容性 | 与 primary_slim（#1078，已有生产实现）、native_mt（单进程多线程线）、zc_stack、DPDK 23→24 升级线的关系：是承接还是制造长期分叉 |
| D5 | 性能影响 | 稳态（非 reload 期）每包路径开销；reload 窗口资源开销（是否双倍核/双倍实例） |
| D6 | 运维复杂度 | 部署形态变化（新增常驻进程？）、配置项数量、监控/降级/回退手段是否明确 |
| D7 | 可测试性 | 能否套用 VPP 社区验证模式（R-A §6.3-7：带流量循环 reload + 不死锁不 crash + 错误数 0 作门禁；v1.6 适配防重入语义：节拍以排空确认+READY 为准、≥100 次）；能否增量交付、异常场景可注入 |

补充一条否决性判据（来自 E-C §9-1 与 R-A §6.4 教训）：reload 逻辑必须是**显式的、可观测的状态机**（每阶段可打点/可回退），不能散落在 fork/signal hook 里的隐式逻辑——VPP #3547/#3645 三年未修即前车之鉴（R-A §4.3/§6.4）。

## 2. 目标语义定义（"无损"的确切含义）

依据基线 1/2 与 R-B §2.2（内核 HUP 语义）、§2.1（USR2 语义），本设计的目标语义定义为：

1. **新连接零丢失**：reload 全程任意时刻到达的 SYN 都有进程收下并 accept（窗口内允许短暂排队于 NIC rx ring / 栈 backlog，不允许 RST/丢弃）。
2. **存量连接优雅 drain**：reload 前建立的连接由旧 worker 继续服务至自然关闭（客户端主动断开或 keepalive 超时），drain 期间旧 worker 的 TCP 定时器（RTO/keepalive/延迟 ACK）持续驱动。**不做**跨进程 TCP 状态迁移（业界无先例，R-B §4 P4）。
3. **配置失败可回滚**：对齐内核 HUP（R-B §2.2：配置解析失败回滚旧配置继续跑）。
4. **HUP 与 USR2 均可支持**：HUP 换配置、USR2 换二进制（exec），两者数据面机制同源。
5. **工程意义无损**：接受 R-B §2.2 引 HAProxy 文档的边界——边界条件上 backlog 中的连接仍可能极小概率损失，验收以压测错误数为 0 为门禁而非绝对论断。
6. **流表仅 reload 窗口生效 + reload 防重入**（v1.3 增补语义，v1.6 据 2026-08-21 方案修订改写）：稳态所有数据包**不经过流表**（零额外每包开销）；流表仅在新 worker 初始化完成（READY）并同期接管队列+listen 后自动生效，至老 worker 排空确认后关闭。流表（**flow_map**，软件分发表）**只记录本代际新建连接的四元组**；**入表时机 = 本栈收到 SYN 并发出 SYN-ACK 的时刻**（此时连接进入 syncache 半开态、尚无 inpcb，非协议栈 inpcb 表）——**不得推迟到 `accept()` 返回时**，否则三次握手的第 3 个 ACK 到达时会因连接尚在 syncache 而 miss，被转给 G_old（其无对应 syncache 条目 → 回 RST）导致 reload 窗口内新建连接全失败（v1.8 修正，见 §5.2 T3）；表项 miss（旧连接的包）**一律经 `drain_ring_rx` 转老 worker**（v1.9：不再复用 `dispatch_ring`，原因见语义 13）。**flow_map 只解决「G_new 收到 SYN」的一半**——「G_old 收到 SYN、第 3 个 ACK 在移交后才到」的另一半由语义 14 处理。老 worker 排空后新 worker 感知并关闭 flow_map、进入稳态成为新的「老 worker」（防止性能退化）。**不支持老 worker 排空前的快速连续 reload**：上一批老 worker 排空前，新的 reload 请求被拦截（拒绝并记日志）。
7. **ready 后同期接管 rx+tx+listen，G_old 退化为软件寄生进程**（v1.9 改写，替代 v1.6 的「两代共享同一批硬件队列」；保留 v1.6「ready 后即接管、非末期移交」的决策）：G_new ready 后**同期接管 rx poll + tx + listen**（新配置立即生效），并自此成为**唯一触碰硬件队列的进程**；G_old **完全脱离硬件**——不再 `rte_eth_rx_burst`、不再 `rte_eth_tx_burst`，只跑协议栈 + 定时器，把存量连接 drain 完。移交靠**跨进程互斥原语**（共享内存标记，非 msg ring）保证 G_old 停 rx poll 后 G_new 才起 rx poll，规避并发 poll 同一 queue；移交窗口靠 NIC rx ring 缓冲兜底（RX_QUEUE_SIZE 512→4096 放大 8 倍）。**v1.6 的缺陷**：只对 rx 做互斥，tx 侧 G_old 仍在与 G_new 并发 `rte_eth_tx_burst` 同一 queue（P0-1）。
8. **lcore_id 策略：两代使用相同 lcore_id（同核同 lcore_id）**（**v1.9 终版定案 D-A**，2026-09-01 人工决策；推翻本轮前一版「不同 lcore_id」的定案）：
   - **决策理由（人工决策原文要点）**：改用不同 lcore_id 会牵动 `lcore_mask → nb_procs → lcore_id → queue_id` 这条全局资源分配链，由此产生的**各类池（mempool / msg_ring / dispatch_ring / timer 槽 / 队列池）的冲突与重分配，其严重程度远超 `priv_timer` 与 `mempool.local_cache` 同槽这一处问题**。正确做法是**接受同 lcore_id，把 mempool 的代际隔离方案做细**（见语义 12 与 §6.6），而不是为避免一处同槽去拆整条链。
   - **随之消解的问题**：P0-3（四链死锁）**不再成立**——不需要 2N 个 lcore_id，`lcore_mask` / `nb_procs` / 队列数三者保持 N 不变，语义 15 中的「代际 lcore 池」配置项**取消**。
   - **同 lcore_id 的两处真实冲突（必须由语义 11/12 解决，二者因此恢复为必需项）**：
     1. `priv_timer[lcore_id]` 共享槽 → 由**语义 11 自驱 hardclock** 解决（必需）。
     2. mempool `local_cache[lcore_id]` 共享槽 → 由**语义 12 代际 mempool 细化方案**解决（必需）。
   - **与 DPDK 硬禁令的关系（例外论证，须写进评审记录）**：`dpdk/doc/guides/prog_guide/multi_proc_support.rst:169-172` 禁止 primary/secondary 共用同一 logical core，**其给出的理由正是「mempool per-lcore cache 会被破坏」**。本方案通过「代际 mempool 分离 + 共享 RX 池的无 cache/代 free 化」（语义 12）**直接消除了该禁令所指的失效机理**，因此属于**理由不成立后的例外适用**，而非无视禁令。该论证须在 M2 评审时明确记录，并在 RV1/RV6/PT-NR-09 中实测佐证（观测 mbuf 水位、无双重释放、无 pool 错配）。
   - **物理核**：两代同 lcore_id ⇒ 天然同物理核，无需 `--lcores` 亲和；X3 决策（2N 物理核非必需）自动满足。drain 期算力竞争由 RV10 实测。
9. **ARP/NDP 等协议包 clone 给 G_old**（v1.6 增补）：reload 窗口内，ARP/NDP 等协议包在转给 G_new 协议栈处理的同时，**额外 clone 一份转发给所有 G_old 进程**（原有 clone 给其他 G_new 和 KNI 的逻辑不变）——确保 G_old drain 期间邻居表正常、能发 RTO/FIN/ACK。
10. **reta 不改、不依赖 NIC RSS 能力**（v1.6 增补，同时解决审核致命 1/2/3）：S3-M1′ 不再依赖 reta 切流原语——同队列 + **queue_id 代际无关固定映射**使 reta 不变、ff_rss_check 四件套不变、不配 2N 队列（不丢半流量）。**virtio 与物理网卡均可用**（无需 guest 侧 RSS 能力）。
11. **自驱 hardclock，绕开 DPDK 共享 timer 槽**（**v1.9 终版定案：必需项**，因 D-A 定案「同 lcore_id」而恢复；v1.7 据 2026-08-24 定时器调研+人工决策）：新旧进程**同 lcore_id** 共存时，DPDK `priv_timer[lcore_id]` 共享槽不可用（`rte_timer_meta_init` 的 memset 会踩掉 G_old 挂着的 timer 链表 → 其 hardclock 永不再触发 → 存量连接 RTO/keepalive 静默停摆；且共享链表上挂对方进程私有地址指针，`rte_timer_manage` 遍历会跨进程解引用私有虚拟地址 → 崩溃/数据损坏，不可修补）。**方案**：放弃 rte_timer 挂槽方式，main_loop 按 TSC 间隔直接调用 `ff_hardclock()`（`if (next_hardclock_tsc < cur_tsc) { ff_hardclock(); ff_update_current_ts(); next_hardclock_tsc += interval; }`）；`init_clock` 删除 `rte_timer_subsystem_init/rte_timer_meta_init/rte_timer_init/reset` 四连，改为计算 `interval = hz_tsc / freebsd.hz`（默认 100 → 10ms）；每进程 hardclock 完全独立、零共享状态，同 lcore_id 无冲突。依据：F-Stack 全树 `freebsd_clock` 是唯一 rte_timer 用户（lib/app 仅 ff_dpdk_if.c 两处），不依赖 rte_timer 任何跨核/同步特性。改动点：`ff_dpdk_if.c` init_clock/init_clock_worker/main_loop 三处。对 `graceful_reload=0` 等价生效（自驱与挂槽行为等价），需回归 timer 精度（RTO/keepalive）。
   **v1.9 终版定案（D-A = 同 lcore_id）**：`priv_timer` 必然同槽，故本项**恢复为 M1′ 必需项**，不再是可选项。附加收益有二——(a) 无需依赖 `--lcores` 映射的正确性；(b) M1′ 下 G_old 不再 poll 硬件、main_loop 语义变「纯软件循环」，自驱 hardclock 免去了对 `rte_timer_manage` lcore 语义的依赖，实现更简单。**回归要求**：PT-NR-08 精度回归为**合入门槛，不可省略**；RTO/keepalive/延迟 ACK 精度与 `graceful_reload=0` 基线偏差 ≤5%（阈值 M0 校准），且无漏触发/重复触发。
12. **代际 mempool 与共享 RX 池的细化方案**（**v1.9 终版定案：必需项**，因 D-A 定案「同 lcore_id」而恢复并细化；v1.7 据 2026-08-24 人工决策提出，v1.9 按人工决策「细化不同代际 mempool 的具体实现方案」展开）：

   **(1) 关键事实：cache 是 per-mempool 的，不是全局的**
   `struct rte_mempool` 有成员 `struct rte_mempool_cache *local_cache`（`dpdk/lib/mempool/rte_mempool.h:258`），访问形如 `&mp->local_cache[lcore_id]`（同文件 `:1340-1341`）。**即每个 mempool 拥有自己独立的 local_cache 数组**。推论：**两个不同 mempool 的同号 `local_cache[L]` 是两块不同内存，两代进程各用各的 pool 时不存在 cache 竞态**。v1.7 原文称「同 lcore_id 两代进程即使在不同 pool 内仍会在同号 cache 槽竞态」——该表述**不准确**，v1.9 予以更正。

   **(2) 因此竞态面收敛为唯一一处：共享的 RX 池**
   - **RX 池不能分代际**：`pktmbuf_pool[socketid]`（`ff_dpdk_if.c:149`）在 init 期由 `rte_eth_rx_queue_setup(..., mbuf_pool)` 绑定（`:1141`），**运行时不可更换**（virtio 无 queue stop/setup）。
   - M1′ 下的访问矩阵（决定性事实）：

     | 路径 | 谁在做 | 是否跨代共享 |
     |---|---|---|
     | RX refill（`rx_burst` 内部 `mempool_get`） | **仅 G_new**（G_old 不 poll rx） | 否 |
     | 应用侧 alloc（TX/clone/构造出包、`ff_ref_pool`） | 两代各自 | 可分离（见 (3)） |
     | RX mbuf 的 free | **G_new + G_old 两者**（G_old 从 `drain_ring_rx` 收到的包用完要 free 回 RX 池） | **是 ← 唯一竞态** |

   **(3) 应用侧：分代际 mempool（消除该侧全部竞态）**
   - G_old 用 `mbuf_pool_%d_gen0`（即现 `pktmbuf_pool[socketid]` 的应用侧语义）、G_new 用 `mbuf_pool_%d_gen1`；**init 期预建**（`graceful_reload=1` 时），避免 reload 触发路径上的创建时序问题；G_new 以 secondary 身份 `rte_mempool_lookup`。
   - 代际号按 reload 轮次在 gen0/gen1 间**乒乓复用**，G_old 退出后其代际池清空并可被下一代复用，避免池数量随 reload 次数增长。
   - **跨代 free 天然正确**：mbuf 自带 `m->pool` 指针，`rte_pktmbuf_free` 自动回正确的 pool，无需额外记账。
   - 两个 pool 的 `local_cache[L]` 彼此独立 ⇒ 应用侧 alloc/free 的 cache 竞态**归零**。

   **(4) RX 池：两个候选方案（DR11 已定案 M-A 为主，M-B 备选）**
   - **M-A（简单，有稳态损耗）**：RX 池创建时 `cache_size=0`（`ff_dpdk_if.c:633-634` 的 `MEMPOOL_CACHE_SIZE→0`），alloc/free 全走 common pool 的无锁 MP/MC ring。代价是**稳态持续生效**——RX 路径每包多两次 ring 操作。**v1.9.3 DR11 定案 M-A 为主** ⇒ 该损耗为已接受项，须由 PT-NR-09 量化并下调 §4.1 D5 评级（见 §6.6.4）。
   - **M-B（备选，稳态零损耗）**：RX 池**保留 cache**；G_old 用完的 RX mbuf **不直接 free**，改为批量 enqueue 到 `free_ring`（G_old → G_new），由 G_new 统一 `rte_pktmbuf_free`。于是 RX 池的 alloc 与 free **都只有 G_new 一个进程**，cache 竞态消失且 cache 性能保留。**v1.9.3：改判为备选**——其 free_ring 与 drain_ring_tx 合并存在「待发送/待释放」标记混淆风险，且比 M-A 多一道 inbound 滞留（见 §24.2）。
     - 稳态零额外开销：`free_ring` 仅在 drain 期有流量，G_old 不存在时该路径完全不触发。
     - 实现上可与已有的 `drain_ring_tx`（同为 G_old → G_new 方向）**合并为一条通道**，用 mbuf 上的私有标记（如 `mbuf->udata64` 或复用 `ol_flags` 空闲位）区分「待发送」与「待释放」，避免多开一个 ring。
     - 代价：drain 期每个用完的 mbuf 多一次批量 ring 往返；drain 流量随时间衰减，且可 burst 批量处理。
   - **定案（v1.9.3 DR11）**：默认取 **M-A**（`cache_size=0`，实现简单，稳态有损耗由 PT-NR-09 量化并须下调 §4.1 D5 评级）；若 PT-NR-09 实测 M-A 稳态损耗不可接受，升级 **M-B**（须接受 `free_ring` 实现量与 inbound 滞留代价）。

   **(5) 回归与观测**：跨代 alloc/free 无泄漏（`rte_mempool_avail_count` 无单调下降）、无 pool 错配（无 mbuf 校验错误/crash）、无双重释放——由 PT-NR-09 + RV1 长稳观测覆盖；M-A/M-B 已由 DR11 定案（**M-A 为主**），PT-NR-09 负责量化 M-A 的稳态损耗并给出是否切 M-B 的依据。

### 2.1 v1.9 新增目标语义（13~15）

13. **TX 独占与 `drain_ring` 双向转发**（v1.9 新增，消解 P0-1/P0-2）：
    - **TX 独占**：G_new 是唯一调用 `rte_eth_tx_burst` 的进程。G_old drain 期间的出包（RTO 重传 / keepalive / FIN / 数据 ACK / SYN-ACK 重传）**不再自己发**，改为 enqueue 到 `drain_ring_tx`，由 G_new 取出后代发。**依据（代码坐实）**：`ff_dpdk_if.c:2478-2495` 是全文件唯一 `rte_eth_tx_burst` 调用点且 `queueid = qconf->tx_queue_id[port]`，而 `tx_queue_id` 与 rx `queue_id` 同号（`:486/:534`）；`dpdk/lib/ethdev/rte_ethdev.h:6575-6577` 限定仅 `RTE_ETH_TX_OFFLOAD_MT_LOCKFREE` PMD 允许同一 tx queue 无锁并发（virtio 未声明该能力，F-Stack 亦无能力探测）。故「两代共享硬件队列」形态下 tx 并发属**契约违反**，必须在**机制层面消除**而非加锁掩盖。
    - **双向 ring 均按代际建立、各自 SP/SC 明确**：
      - `drain_ring_rx`（G_new → G_old）：G_new flow_map miss 的包 enqueue，G_old 为唯一消费者。
      - `drain_ring_tx`（G_old → G_new）：G_old 的出包 enqueue，G_new 为唯一消费者，取出后直接 `rte_eth_tx_burst`。
    - **为什么不能复用 `dispatch_ring`**：其一，`dispatch_ring` 是 per-(port,queue) 且 `RING_F_SC_DEQ`（`ff_dpdk_if.c:710-713`），同队列下两代会成为**同一 ring 的两个消费者**（P0-2）；其二，`process_dispatch_ring`（`:2222-2236`）的语义是 dequeue 后以 `pkts_from_ring=1` 进 `process_packets → ff_veth_input`，即**入向进协议栈**，与「出向代发」语义相反，不可复用。
    - **满环行为**：`drain_ring_rx` 满时的丢弃是**已建连接的数据包**，须显式计数与告警（现有 `dispatch_ring` 满环是静默 `rx_dropped++`，`:2144-2147`），不得静默（见 RV4 修订）。
    - **备选形态**（DR9 待评审，非当前主路径）：(a) init 期多配 `nb_tx_queues = 2N`，代际各用一组 tx queue（零跳、无锁，但需改 `:486/:534` 的 tx/rx 同号分配且依赖硬件多队列）；(b) G_old 直接 tx + 共享内存自旋锁保护 tx queue（`rte_ethdev.h:6575-6577` 允许应用自加 SW lock；改动最小但有锁开销与优先级反转风险）。
14. **半开连接窗口处理**（v1.9 新增，消解 P0-5）：移交前由 G_old 收到 SYN、尚未完成握手的连接，其第 3 个 ACK 在移交后会落到 G_new → flow_map miss（SYN 不是 G_new 收的）→ 转回 G_old → 若此时 G_old 已 close listening，则 `syncache_expand` 无法建 socket → 连接失败。**依据（代码坐实）**：`freebsd/netinet/tcp_syncache.c:1033-1055` 的 `syncache_expand` 经 VNET 私有全局 hash 查到条目后需 `*lsop`（listening socket）创建子 socket；`freebsd/netinet/tcp_subr.c:2517-2553` 的 `tcp_close` 对 `TCPS_LISTEN` 只做 `tcp_offload_listen_stop` + `in_pcbdrop`，**不清 syncache**（`syncache_destroy()` 仅在 `tcp_subr.c:1583` 全局销毁时调用）。
    **处理（择一，倾向 (a)）**：
    - (a) **listening 延迟关闭**：T4 时 G_old 仅**停止 accept**，保留 listening socket 直至自身 syncache 半开条目排空或超时（`syncache` 自有超时与 SYN-ACK 重传机制），由 shutdown timer 兜底强退。此时新 SYN 已全归 G_new（队列归 G_new），保留 listen 不抢新连接。
    - (b) **T3 导出半开四元组**：移交时把 G_old syncache 中的半开四元组导出给 G_new，在 G_new 的 flow_map 中登记为「转 G_old」，使第 3 个 ACK 能被正确转回。
15. **queue_id 代际无关映射 + msg_ring / KNI 代际隔离规则**（v1.9 新增；**v1.9 终版按 D-A = 同 lcore_id 简化**）：
    - **背景（代码事实，保留备查）**：现有代码 `lcore_mask 置位数 = nb_procs`（`ff_config.c:118/:127/:139`）→ `proc_lcore[proc_id]` 定 lcore_id（`ff_dpdk_if.c:508`）→ `queueid = lcore_id 在 lcore_list[] 中的下标`（`:518-524`）→ 队列数 `nb_lcores = nb_procs`（`ff_config.c:555-574`），四者绑成一条链。**v1.9 前一版曾试图新增「代际 lcore 池」让两代取不同 lcore_id，该方案已被人工决策否决并取消**——理由见语义 8（拆链的冲突面远大于同槽问题）。因此：
    - **queue_id**：代际无关固定映射（沿用 v1.6），两代用同一批 queue，`rx_queue_list / tx_queue_id / reta / rss_check 四件套`全部不变。
    - **lcore_id**：两代**取相同的 lcore_id**（D-A 定案）。`lcore_mask` / `nb_procs` / 队列数**全部保持 N 不变，无需任何配置面新增项**。同 lcore_id 引发的 `priv_timer` 与 mempool 同槽问题由语义 11 / 语义 12 解决。
    - **proc_id**：两代同值（沿用 v1.6 的代际无关映射，消除审核 B-1 的乒乓代际重合），仅保留其既有的 `msg_ring[proc_id]` 索引与 `ff_kni_is_runtime_owner`（`ff_dpdk_kni.c:101-109`）语义——**且这两处必须做代际隔离**：
      - `msg_ring`：`ff_dpdk_if.c:2903` 的 `process_msg_ring(qconf->proc_id, ...)` 与 `:2457-2470` 的 dequeue 均按 proc_id 索引，ring flags 为 `RING_F_SP_ENQ | RING_F_SC_DEQ`（`:764-777`）。两代同 proc_id 则会 dequeue 同一 ring，导致 READY / DRAIN_DONE / REJECT / HANDOVER_ACK 错收。**处理**：msg ring 按 `(proc_id, 代际号)` 二维索引，或代际各建一套 ring。
      - **KNI runtime owner**：`ff_dpdk_kni.c:101-109` 的 `ff_kni_is_runtime_owner` 固定比较 `proc_id == kni.owner_proc_id`，代际交替后 owner 会落到已退代际。**处理**：owner 标记改为跟随「当前活跃代际」，由 master/primary 在移交成功时更新（原列为 RV8，v1.9 升为设计约束）。

## 3. 候选方案集

### 3.1 S1：旧 iWiki 方案复活（dispatch 中间层在 DPDK 24.11.6 下的现代化改造）

**机制描述**（依据 E-C §3.3 图 1-4、§6.1）：

- 数据流：dispatch 进程作为中间层持有全局 connection 表，收包后按五元组决定去向；worker 进程经无锁 ring 与 dispatch 通信。DPDK primary 身份从首个 worker 调整为 dispatch 进程（E-C 图 4 第 4 点）。
- 新旧 worker 并存于**同一批 CPU core**：靠 (a) 新旧进程不同 mempool + 网卡驱动 mempool 关 cache/CAS 缩小冲突域（E-C 图 2）；(b) nice 值动态调整 CPU 权重（CFS 公式 `1024/(1.25^nice)`，新 worker 初始 nice=19 占 1.7% CPU，流量切换时绑预留核 1 秒再绑回，E-C 图 5/6）。
- 反向代理回包路由：网卡配双内网 IP，新旧 worker 各用一 IP 与后端通信 + 协议栈支持 `IP_BIND_ADDRESS_NO_PORT`（E-C 图 3/4）。
- worker 退出条件改为「全局 connection 表中无本进程连接」（E-C 图 4）。

**对 8 项障碍的覆盖**（障碍编号沿用 P-D §4，见 [04](04-fstack-current-analysis.md) §4）：

| 障碍 | 覆盖 | 说明 |
|---|---|---|
| 1 两段串行空窗 | 解决 | 新旧 worker 并存，dispatch 常握全局表 |
| 2 listening fd 跨进程 | 回避 | listen 归各 worker 栈（栈隔离），切流由 dispatch 表控制新连接去向 |
| 3 TCP 连接无迁移 | 不迁移/可 drain | 全局表 + 退出条件改造，旧 worker drain 至表清空 |
| 4 primary 单点 | 解决 | primary=dispatch 进程，常驻 |
| 5 respawn/时序脆弱 | 解决 | 编排归 dispatch |
| 6 master 不在数据面 | 解决 | dispatch 即协调者（取代 master 数据面角色） |
| 7 RSS 静态映射窗口 | 解决 | dispatch 持全部队列 |
| 8 定时器随进程消亡 | 部分 | 旧 worker drain 期间活着跑 timer；但**新旧进程同 core 共存时共享 memzone timer 的同 lcore 槽问题未闭环**（见风险） |

**依据的证据**：E-C §3（iWiki 4015929276 全文 + 7 张截图解析）、§5（timer git 链）、§6（失效性）；R-B §3.7（#547 社区先例）。

**风险与未坐实项**：

1. **原代码从未开源**（E-C §8-U5：仅有截图与微信联系），「复活」等于全部重新开发。
2. **timer 失效根因在 24.11.6 未闭环**：19.11 起 `priv_timer` 数组入共享 memzone（E-C §5.3），多进程**同 lcore** 驱动同一槽会互踩；F-Stack 本地补丁 `rte_timer_meta_init`（commit 62f1c34df，2026-01-16）只修「secondary 重启死循环」，未解决「新旧进程同核共存期间 timer 状态隔离」（E-C §6.2 表第 2/3 行原文："至今未通过上游修复彻底闭环"）。
3. mempool 隔离需改网卡驱动层（关 cache + 冲突域 numa→workerid 粒度，E-C 图 2），24.11 PMD 下需重做，无代码基础。
4. ~~`IP_BIND_ADDRESS_NO_PORT` 在 FreeBSD 15.0 是否已支持：**未坐实**（E-C §8-U1）~~ **→ 已坐实（2026-08-18）：F-Stack 15.0 栈已支持**（E-C U1，系 F-Stack 本地扩展：cb9b4d462 → ff9e3c449 port 到 15.0 → a2537e143 `lib/ff_syscall_wrapper.c:100/979/1041-1046` setsockopt 接线；上游原生 FreeBSD 无此选项，升级 freebsd 树须保留补丁）。**该风险项从 S1 风险清单中消除**。
5. 旧方案实测数据（58 万 QPS、10 小时 200 次 reload 112 timeout）均为 DPDK 18.11 + F-Stack 1.20 时代且**单来源**（见第 8 节），不可外推到 24.11.6。
6. 同核双 DPDK 进程靠 CFS nice 分时，性能确定性与 fairness 依赖内核调度，对 run-to-completion 的用户态栈是持续干扰。

**结论要素**：S1 是历史上唯一被实测证明「能做成」的 F-Stack 原生路线（虽未开源），但其三大支柱（同核共存、mempool 隔离、nice 调度）在新 DPDK 上全部要重做且 timer 风险未闭环；其 dispatch 中间层的**思想**应被现代化承接（见 S3-M2），而非原样复活。

### 3.2 S2：ld_preload（adapter/syscall）路线——stack 进程持有连接，nginx 作为 client

**机制描述**（依据 P-E §3/§4/§5）：

- 数据面：独立 fstack 实例进程（标准 F-Stack 应用，`fstack.c:15-36`：ff_init → ff_run(loop=ff_handle_each_context)）持有 FreeBSD 协议栈、fd 表、listening socket、全部 TCP 连接状态；nginx master+worker 经 libff_syscall.so（LD_PRELOAD hook socket 族，P-E §3.1）以 sc 上下文 + rte_ring IPC 调用栈（`ff_hook_syscall.c:3384-3443`）。
- 控制面：FF_KERNEL_EVENT 模式下 nginx channel/timer 等控制 fd 走真实内核 epoll（P-E §3.7），nginx 的 master-worker 信号协议原样保留。
- HUP reload：master 存活即 listening 稳定（listening 本体在 stack 进程，P-E §4.2）；新 worker fork 走已验证的 FF_MULTI_SC + FF_USE_THREAD_STRUCT_HANDLE fork 路径（P-E §3.2，README 文档化的 nginx 工作路径）；旧 worker 按原生 nginx 语义优雅 close 存量连接（close hook → FF_SO_CLOSE → stack 侧真关闭）。行为**对齐内核 nginx HUP**：listening 无缝 + 存量连接优雅退役。
- USR2：exec 未 hook 是硬缺口（P-E §3.2/§4.3）；但 stack 侧 `ff_bound_fds` + `ff_dup2`（`ff_socket_ops.c:131-147`）提供「新 master bind 同地址挂回旧 listening socket」的代码级复用潜力（P-E §4.3，时序前提未坐实）。

**对 8 项障碍的覆盖**：

| 障碍 | 覆盖 | 说明 |
|---|---|---|
| 1 两段串行空窗 | 解决 | nginx 用原生进程模型（无需 F-Stack 版 ngx_process_cycle.c 改造），HUP 天然先起新再退旧 |
| 2 listening fd 跨进程 | 解决 | listening 本体在 stack 进程（P-E §5.1-1/4）；fd 数字经 fork 天然继承 |
| 3 TCP 连接无迁移 | 语义对齐内核 | 不迁移，旧 worker graceful close；「连接保活跨 worker」仅有理论潜力（fd 无 sc 归属校验，P-E §3.6），无代码路径 |
| 4 primary 单点 | 解决 | fstack 实例是常驻 DPDK 进程，nginx 全是 client，无 primary 身份竞争 |
| 5 respawn/时序脆弱 | 解决 | 原生 nginx respawn 语义保留 |
| 6 master 不在数据面 | 解决 | master 是纯协调者，数据面归 stack 进程——结构上正是基线 2 的解耦形态 |
| 7 RSS 静态映射窗口 | 解决 | 队列归 fstack 实例，nginx 代际更替不影响收包 |
| 8 定时器随进程消亡 | 解决 | timer 在 fstack 实例内常驻 |

**依据的证据**：P-E 全文（代码行号在案）；R-A §6.1 对照表第 4 列（adapter/syscall 与 VPP 结构同构性）。

**风险与未坐实项**（P-E §5.2 十项缺口 + §6）：

1. exec 未 hook：USR2 需补 exec 恢复逻辑（scs[]/current_worker_id/fd 映射表全丢），或 nginx 侧规避（老 master 显式传递 fd 清单）——需设计开发。
2. client 异常退出无回收：sc 槽泄漏（32 上限）、stack 侧连接 fd 泄漏，无心跳/孤儿回收（P-E §3.5）。
3. **多 fstack 实例不能作 client**（P-E §4.4 引 README L25-29）：nginx 作反向代理（主动 connect upstream）在多实例部署下不可用——**纯 web/正向服务可用，proxy 场景判死**。
4. 性能：每实例组占近两核、8 核后短连接性能低于标准 F-Stack app 模式（README L15-16/L307/L319）；ring 模式官方仍定位「储备」，生产推荐 sem（README L37-39）。
5. FF_KERNEL_EVENT 内核 epoll 1/256 轮询：reload 期间 channel 事件延迟放大，需实测（P-E §3.7）。
6. 多轮 reload 的 sc 容量耗尽风险未量化（P-E §6-5）；spec C-005 ring 残留清理未实现（P-E §2.3）。

### 3.3 S3：原生多进程演进（primary_slim 式解耦 + worker 独立重生）【推荐，详见第 5 节】

**机制描述**（概要，设计细节见第 5 节）：

在 app/nginx 源码集成路线内演进，核心是把「数据面资源所有权」从 nginx worker 生命周期中剥离，分两个里程碑：

- **S3-M1′（同队列 + ready 后同期接管 + 单硬件所有者 + drain 代际软件寄生）**【v1.9 方案形态升级；v1.6 为「同队列 + ready 后同期移交 + flow_map」，其缺陷是两代共享同一批硬件队列而 tx 无保护】：
  - 常驻 slim primary（dispatcher 角色，#1078 已验证：primary 持 EAL/设备/队列 setup 不持数据面，杀掉后 12/12 连接零中断，`docs/primary_slim_spec/10-feasibility-conclusion.md` §1.1）。
  - nginx worker 全部改为 secondary；**queue_id 代际无关固定映射**（G_new 直接用 G_old 的队列号，不需运行时重算 lcore_conf → `rx_queue_list / tx_queue_id / reta / rss_check 四件套`全部不变）；**两代取相同的 lcore_id**（D-A 终版定案），`lcore_mask`/`nb_procs`/队列数保持 N 不变、无需新增配置面；同 lcore_id 的 timer 与 mempool 同槽由语义 11/12 解决。
  - 新 worker ready（栈 init + listen 完成）后**同期接管 rx poll + tx + listen**：G_new 立即接管新连接（**新配置立即生效**），并自此成为**唯一触碰硬件队列的进程**。
  - **跨进程互斥原语**（共享内存标记，非 msg ring）保证 G_old 停 rx poll 后 G_new 才起 rx poll；移交窗口靠 NIC rx ring 缓冲兜底（RX_QUEUE_SIZE 512→4096 放大 8 倍）。**互斥只需保护 rx 一侧**——tx 由 G_new 独占，不存在并发。
  - **G_old 退化为软件寄生进程**：不再 `rte_eth_rx_burst` / `rte_eth_tx_burst`，只跑协议栈 + 定时器，经两个 per-generation ring 与 G_new 双向通信（语义 13）：
    - 下行 `drain_ring_rx`：G_new flow_map miss 的旧连接包 → enqueue → G_old dequeue 后进本栈（唯一消费者，SP/SC 明确）。
    - 上行 `drain_ring_tx`：G_old 的出包（RTO/FIN/ACK/SYN-ACK 重传）→ enqueue → G_new dequeue 后代发 `rte_eth_tx_burst`（唯一消费者）。
  - **G_new 软件分发表 flow_map**（reload 窗口生效，稳态零开销）：flow_map 存 G_new 本代际新建连接的四元组，**在收到 SYN 并发出 SYN-ACK 时入表**（非 `accept()` 时，非协议栈 inpcb 表——第 2 节语义 6 的 v1.8 修正）；drain 期间增量更新；miss（旧连接包）→ 一律经 `drain_ring_rx` 转 G_old；排空确认后关闭 flow_map 回稳态。**移交瞬间的半开连接**由语义 14 单独处理（G_old 延迟关闭 listening 或 T3 导出半开四元组）。
  - **ARP/NDP 等协议包处理**：reload 窗口内，ARP/NDP 等协议包在转给 G_new 协议栈处理的同时，**额外 clone 一份转发给所有 G_old 进程**（原有 clone 给其他 G_new 和 KNI 的逻辑不变）——G_old 已无硬件出口，其邻居表全靠此路径维持，否则发不出任何包。
  - G_old drain 完成（连接数=0 + DRAIN_DONE）后退出；G_new 感知排空（共享内存标记 + SIGCHLD 确认）后关闭 flow_map、进入稳态成为下一轮的「老 worker」。
  - reload 防重入：上一批老 worker 排空前，master **拦截（拒绝）新的 reload 请求**并记日志。**后续演进**：G_old 退化为纯软件进程后多代并存在结构上成为可能，可作为放松防重入（支持快速连续 reload）的候选，需独立评审（DR10）。
  - **reta 不改、不依赖 NIC RSS 能力**：virtio 与物理网卡均可用（无需 guest 侧 RSS 能力、无需 set_rss_table 运行时改造、不破坏 ff_rss_check 不变量、不配 2N 队列不丢半流量）。
- **S3-M2（可选演进，dispatcher 中心化）**：把「每 worker 独占队列」改为 slim primary 统一收包 + 流表分发（worker 变纯 ring 消费者）——即 VPP/VCL app_listener workers bitmap 同构（R-A §2.2）+ 旧 iWiki dispatch 思想的现代化（避开同核共存，因 dispatcher 与 worker 分核）。是否演进取决于 M1 转发路径的实测开销。

**对 8 项障碍的覆盖**（按 S3-M1′）：

| 障碍 | 覆盖 | 说明 |
|---|---|---|
| 1 两段串行空窗 | 解决 | 回退为原生顺序：新 worker 起（secondary attach 常驻 primary，无 primary 竞争）→ 同期接管 rx+tx+listen → 旧 drain |
| 2 listening fd 跨进程 | 回避 | 每 worker 栈内自建 listen（栈隔离天然允许多代际 listen 同 IP:port，P-D §3.5）；新连接归属由同期接管+flow_map 控制，无需 fd 传递 |
| 3 TCP 连接无迁移 | 不迁移 + drain 保障 | 旧连接包经 flow_map miss → `drain_ring_rx` 显式送达 G_old；G_old 出包经 `drain_ring_tx` 代发；drain 期 timer 正常（G_old 活着跑 ff_run） |
| 4 primary 单点 | 解决 | primary=slim dispatcher 常驻；worker0 不再硬编码 primary（改 ngx_ff_module.c:183-187 与 ngx_process_cycle.c:1117-1121）；queue_id 代际无关映射消除乒乓代际重合（审核 B-1） |
| 5 respawn/时序脆弱 | 解决 | 原 500ms sleep/15s sem 时序被显式 ready 协议取代 |
| 6 master 不在数据面 | 重新分工 | master 编排（nginx 语义层）+ primary 提供原子原语（互斥标记/队列状态），master 仍不碰 ff fd |
| 7 RSS 静态映射窗口 | 解决（同期接管+rx 互斥+tx 独占） | 互斥标记保证 G_old 停 rx poll 后 G_new 才起 rx poll（队列始终有主，无空窗）；tx 由 G_new 独占，无并发；reta 不改 → ff_rss_check 不变量不破坏（审核 B-2 消解） |
| 8 定时器随进程消亡 | 解决（需实测） | **v1.9.1 终版**：两代 **lcore_id 相同** ⇒ `priv_timer[L]` **必然同槽**（`rte_timer.c:216-228` 的 memset 会清零 G_old 的 skiplist）⇒ 由**语义 11 自驱 hardclock（必需项）**解决：main_loop 按 TSC 间隔直调 `ff_hardclock()`，每进程 timer 完全独立、零共享状态；drain 期 G_old timer 持续驱动。合入门槛 = PT-NR-08 精度回归。~~v1.9 曾称「两代 lcore_id 不同 → 天然隔离、自驱 hardclock 降为加固项」~~ 已被 D-A 反转推翻 |

**依据的证据**：P-D 全文（现状与障碍，行号在案）；`docs/primary_slim_spec/03/10`（slim primary 可行性 PoC 与生产实现）；R-A §6.2/§6.3（队列归属结论 + 可借鉴机制 1/2/5/7）；R-B §5.3 方向 A；E-C §5（timer 结构与 62f1c34df 补丁）；本设计回查代码（第 0 节）。

**风险与未坐实项**：见第 6 节（集中列出）。

### 3.4 S4：双进程热备 + 流量切换（FB ready-前-不切流的用户态移植）

**机制描述**（依据 R-B §2.4(a)、§4 P3/P4）：

- 新老 nginx 实例（两组完整进程）并行运行；新实例启动初始化期间，分发层（dispatcher/流表）持续把全部流量导给老实例。
- 新实例完成初始化/健康检查后，**显式动作触发切换**（更新流表：VIP:Port → 实例映射），新连接开始导向新实例；老实例后台 drain。
- 用户态移植形态：在 F-Stack 的 RSS/分发层引入「可编程 socket 查找」等价物——dispatcher 进程内 map（VIP:Port → nginx 实例），即 FB sk_reuseport+map 模式（R-B §2.4(a)）或 Cloudflare tubular sk_lookup 思想的用户态版（R-B §2.4(b)）；UDP 场景需 flow 一致性表（FB 经验）。

**对 8 项障碍的覆盖**：

| 障碍 | 覆盖 | 说明 |
|---|---|---|
| 1 两段串行空窗 | 解决 | 双实例并存，切流原子 |
| 2 listening fd 跨进程 | 回避 | 分发层决定新连接去向 |
| 3 TCP 连接无迁移 | 对齐基线 | 老实例 drain（FB：老进程继续服务已接受连接 1~N） |
| 4 primary 单点 | 取决于实现 | 分发层本身须常驻（否则又造一个新单点） |
| 5 respawn/时序脆弱 | 解决 | 切流显式化 |
| 6 master 不在数据面 | 解决 | 分发层即协调点 |
| 7 RSS 静态映射窗口 | 解决 | 前提是分发层持有队列（否则无从导流） |
| 8 定时器随进程消亡 | 解决 | 老实例常活直至 drain |

**依据的证据**：R-B §2.4(a)（FB LPC 2021 译文：sk_reuseport+map、30x 流量不丢、UDP flow map）、§2.4(b)（tubular/sk_lookup）、§4 P3；R-A §6.2（VPP 侧同构印证）。

**关键问题**：S4 的「分发层持有队列 + 流表导流 + 旧连接一致性路由」**在机制上与 S3-M2（dispatcher 中心化）完全同构**，且额外要求双实例常驻（双倍内存/双倍栈实例/双倍核，直到 drain 完成）。切流要安全，同样绕不开「旧连接的包必须继续到老实例」——FB 用 flow→socket map 解决 UDP，TCP 靠内核 socket 归属天然不变；F-Stack 用户态栈没有内核 socket 归属，最终仍需 dispatch 层按四元组把旧连接钉给老实例——**这就是 S3 的转发兜底机制**。换言之：S4 做到底 = S3-M2 + 双倍资源，独立实施无增量收益。

**结论要素**：不作为进程内 reload 的独立方案推荐；其「**ready 前不切流 + 显式切流动作 + 切流可观测**」三原则作为时序设计原则并入 S3（第 5.2 节时序图即按此设计）。

**v1.4 据 X2 增补——virtio/云主机场景的推荐定位**（**v1.9 更新理由**）：S4 形态（多实例蓝绿轮换）在 **virtio/云主机场景**下恰好完全没有 S3 的队列共享/syncache/ARP 等障碍（两实例各自 N 队列、各自 file_prefix、不共享任何 state、不需要跨代 ring、无不可观测门禁），且复用 F-Stack 已有能力（`file_prefix` 已坐实：ff_config.c:1044/1193/1236、Release Note:299）。**在 virtio/云主机场景推荐作为首选方案**。
**v1.9 更正**：v1.4 给出的理由是「S3 在该场景依赖的 reta/queue 切流原语不可用」——该理由自 v1.6 起已失效（S3 不再依赖 reta，virtio 亦可用，见 §6.4）。**X2 决策维持不变，但理由改为投入产出**：S4 为**零代码**，而 S3-M1′ 需改动 nginx 适配层 + lib，且 v1.9 后改动面进一步上升（双向 drain_ring + 代际隔离，见 D3；~~四链解耦随 DR5 取消~~）。故在有上游撤流能力的 virtio/云主机场景仍优先推荐 S4。硬前提：上游撤流能力（LB/consul/etcd/手动摘节点）+ 独立网卡或 VF（或同机双 VIP + 路由）+ 双倍资源 + 业务无单机粘性状态；不适用：单机无 LB/单网卡场景（该场景走 S3-M1′）。

### 3.5 组合关系说明（S2+S3、S1→S3-M2）

- **S2 与 S3 不冲突、可并行**：两者是两条接入产品线（ld_preload 零改动接入 vs app/nginx 源码集成）。S3 的 dispatcher 控制面协议（ready/切流/队列状态消息）设计可为 S2 的 fstack 实例管理（sc 动态注册、实例重生）复用经验；R-A §6.3-3 已指出 FF_MULTI_SC 静态 scs 数组向「动态注册/注销 worker」演进的方向。
- **S1 → S3-M2**：S1 的 dispatch 中间层思想由 S3-M2 现代化承接——dispatcher 仍持有分发权，但 (a) dispatcher=slim primary 分核常驻（不再与 worker 同 lcore_id 共存）；(b) 流表只管「新连接去向 + 旧连接钉住」，不维护全量 TCP 状态镜像；(c) **M2 形态下 worker 退化为纯 ring 消费者，S1 的 mempool/nice/timer 三大难题因 worker 不再触碰硬件而弱化**（注意：M1′ 形态下两代 **同 lcore_id**，这三个难题依然存在，由语义 11/12 解决——见语义 8/§6.3）。
- 不引入额外新组合方案：S2+S3 深度耦合（如 nginx 经 ld_preload 接入 S3 dispatcher）会使两条线的问题空间叠加（exec hook 缺口 + 切流协议），无证据支持其收益，不如各自演进。

## 4. 对比矩阵与分档结论

### 4.1 对比矩阵（定性评级 + 一句话依据）

| 维度 | S1 旧方案复活 | S2 ld_preload | S3 原生演进（M1/M2） | S4 双实例热备 |
|---|---|---|---|---|
| D1 无损性 | 中高：dispatch 表切流，但依赖同核共存稳定性（未闭环） | 高：stack 常驻，HUP 对齐内核语义 | v1.9 高（同队列+rx 互斥移交+tx 独占+flow_map 转发兜底，reta 不改不破不变量）；M2 高（结构性） | 高（ready 前不切流） |
| D2 连接语义 | 高：全局表+drain 退出条件 | 中：原生 graceful close（存量连接被关闭而非服务到自然结束——与内核 nginx 一致，但对齐基线 1 的弱化形态） | 高：drain 期旧连接双向路径显式保障（入向 flow_map miss → `drain_ring_rx`；出向 `drain_ring_tx` 代发）+ ARP/NDP clone + timer 持续；半开连接窗口由语义 14 兜底 | 高 |
| D3 改动面 | 极大：全量重写（原码未开源）+ 驱动层改造 | 小：nginx 零改动；缺口集中在 adapter 侧（exec hook/回收） | v1.9 **中-大**（由 v1.6 的「中」上调）：nginx 适配层回退原生顺序 + lib 新增 flow_map/互斥原语/ARP clone/**两个 drain_ring 与 G_new 代发路径**/**proc_id-lcore-queue-msg_ring 四链解耦**（语义 15，v1.6 完全未计入）；有 primary_slim PoC 基础；不依赖 reta 改造 | 大：双实例管理 + 分发层全新 |
| D4 主线兼容 | 低：孤儿路线，同核共存与主线（native_mt 分核演进）方向相反 | 中：独立产品线，与主线无耦合也无承接 | v1.9 高：直接承接 primary_slim；timer 隔离受益于 native-mt `__thread` 改造；与 zc_stack 正交；不依赖 reta 能力（virtio 也可用）；**新增与 stack-coexist 的未评估声明（§6.4）** | 低：双倍栈实例与 share-nothing 主线相悖 |
| D5 性能 | 中：稳态每包经 dispatch 一跳（旧实测 58 万 QPS 为 18.11 单来源数据） | 低-中：每 socket 调用走 IPC，近双核占用，8 核后短连接劣于 app 模式 | v1.9.1 **中-高**：稳态零新增**每包**开销（flow_map 仅 reload 窗口、drain_ring 仅 drain 期）；drain 期旧连接出包多一跳（v1.6 为出向零跳，M1′ 双向各一跳，PT-NR-10 量化）。**v1.9.3 人工定案：DR11 取 M-A 为主（RX 池 `cache_size=0`）⇒ 引入稳态持续损耗，本项评级须下调，损耗幅度由 PT-NR-09 量化确认**（见 §6.6.4）；M-B 备选可消除该损耗但有 inbound 滞留代价；M2 中：稳态每包一跳 | 中低：reload 窗口双倍核/内存 |
| D6 运维 | 高复杂：nice/双 IP/驱动参数 | 中：独立 fstack 实例进程 + 环境变量矩阵 | v1.9.1 中：新增常驻 slim primary + 互斥标记 + flow_map + 两个 drain_ring + **代际 mempool（乒乓复用）** + 心跳与 rx 交还 + RX_QUEUE_SIZE 调优 + reload 状态可观测（**无代际 lcore 池配置项**） | 高：双实例生命周期管理 |
| D7 可测试性 | 差：无法增量验证（须一次性做成） | 好：可先在非 nginx 应用验证 adapter，再套 nginx | v1.9 好：M1′ 可分里程碑增量交付；reload 状态机显式可打点；**virtio 与物理网卡均可验证**（不依赖 reta 能力）；**TX 独占、ring SP/SC、半开连接窗口均有可注入用例**（见 08 v1.3 新增；~~四链解耦随 DR5 取消~~） | 中：切流逻辑可测，但双实例编排复杂 |

### 4.2 分档结论

| 分档 | 方案 | 理由 |
|---|---|---|
| **推荐** | **S3（M1′ 先行，M2 视数据演进）**【v1.9 修订：同队列 + ready 后同期接管 rx+tx+listen + **G_new 独占硬件、G_old 软件寄生** + flow_map + 双向 drain_ring，virtio 与物理网卡均可用】 | 唯一同时满足：结构性前提（队列所有权与 worker 解耦，基线 2）、连接语义对齐（基线 1）、稳态**零额外**开销（~~D5 中-高，DR11 M-A 定案后须下调，幅度由 PT-NR-09 量化~~ → 见 §4.1 D5）、有已验证 PoC 基础（primary_slim）、与主线演进同向（D4 高）、可增量交付（D7 高）、**不依赖 NIC RSS 能力**（reta 不改，virtio 也可用）。**v1.9 相对 v1.6 的关键改进**：把「两代共享同一批硬件队列」改为「单硬件所有者」，从机制层面消除 TX 并发（P0-1）与 ring 双消费者（P0-2）两类**契约级正确性风险**，而非靠互斥与缓冲掩盖。代价：drain 期旧连接出包多一跳 + 改动面由「中」升为「中-大」（四链解耦）。前置依赖：primary_slim 合入 |
| **备选** | **S2（限定场景）** | 适用于「存量应用零改动接入 + 非 proxy 场景 + 可接受 IPC 性能折损」的独立产品线；HUP 语义天然对齐内核 nginx，缺口（exec/回收）收敛在 adapter 侧。**不建议作为 F-Stack nginx（app 源码集成主线）的 reload 解法**，但建议与 S3 并行推进其缺口修复 |
| **virtio/云主机场景推荐**【v1.4 据 X2 增补；v1.9 更新理由】 | **S4 多实例蓝绿轮换** | **v1.9 更正**：v1.4 的理由是「virtio 下 S3 的 reta 切流原语不可用」，该理由已在 v1.6 失效（S3 不再依赖 reta，virtio 亦可用）。**X2 决策仍然维持**的原因是投入产出而非可行性：S4 为**零代码**（复用已坐实的 `file_prefix`，ff_config.c:1044/1193/1236），而 S3 需改动 nginx 适配层 + lib（v1.9 后改动面进一步上升，见 D3）。故在有上游撤流能力的 virtio/云主机场景仍优先推荐 S4。硬前提：上游撤流（LB/consul/etcd/手动摘节点）+ 独立网卡或 VF（或同机双 VIP + 路由）+ 双倍资源 + 业务无单机粘性状态。**不适用**：单机无 LB/单网卡场景——该场景若必须 `nginx -s reload` 无损，则走 S3-M1′（v1.9：不再有「形态 V」这一说法，软件切流已并为主路径） |
| **不推荐（独立实施）** | **S1** | 同核共存三支柱（mempool 隔离/nice 调度/timer 隔离）在 24.11.6 全部需重做且 timer 未闭环（E-C §6.2）；原码未开源。其 dispatch 思想由 S3-M2 承接 |

## 5. 推荐方案 S3 关键设计

### 5.1 进程/队列/listening fd/连接 四层所有权模型

| 层 | 所有者 | reload 时行为 | 依据 |
|---|---|---|---|
| L1 EAL/设备/mempool/ring/队列 setup | **slim primary（dispatcher），常驻** | 不动（杀 primary 数据面零影响已实测：`docs/primary_slim_spec/10` §1.1 E3b/E3c；但 primary 只能常驻不能复活，E10） | P-D §3.2；primary_slim_spec 03 §III |
| L2a 收包消费权（rx poll） | **G_new 独占**（reload 窗口内） | G_new ready 前：G_old 持续 poll（队列始终有主，无空窗）；ready 后**同期接管**（跨进程互斥标记保证 G_old 停 rx 后 G_new 才起 rx）。G_old 自此**不再调用 `rte_eth_rx_burst`** | ff_dpdk_if.c:508-538（lcore↔queue 映射）、:2865-2872（rx_burst 调用点）；基线 2/3；queue_id 代际无关固定映射 |
| L2b 发包权（tx burst） | **G_new 独占**（全程） | G_old 出包一律经 `drain_ring_tx` 由 G_new 代发；G_old **不再调用 `rte_eth_tx_burst`**。**依据**：`ff_dpdk_if.c:2478-2495` 唯一 tx 出口 + `tx_queue_id` 与 rx 同号（:486/:534）+ `rte_ethdev.h:6575-6577` 并发契约 | 语义 13；P0-1 消解 |
| L2c 代际通信 ring | per-generation，`drain_ring_rx` / `drain_ring_tx` 各一 | 下行：G_new flow_map miss → enqueue → G_old 唯一消费者；上行：G_old 出包 → enqueue → G_new 唯一消费者后代发。两 ring 均 SP/SC 明确，**不复用 per-(port,queue) 的 `dispatch_ring`**（后者在同队列下会产生双消费者，且其语义为入向进协议栈） | 语义 13；ff_dpdk_if.c:710-713（`RING_F_SC_DEQ`）、:2222-2236（入向语义） |
| L3 listening socket | **各 worker 栈内自建**（保持现状） | 不跨进程传递：栈隔离天然允许多代际 worker 并存 listen 同 IP:port（每进程独立 FreeBSD 栈实例各自 bind/listen 互不冲突，P-D §3.5）；新连接归属由 L2a 同期接管决定（G_new 接管 listen）。**G_old 的 listening 延迟关闭**至自身 syncache 半开条目排空（语义 14） | P-D 障碍 2 的回避式解法；R-A §6.3-2 的对照（VPP 用 app_listener 单点，F-Stack 用栈隔离多 listen——路线差异点，功能等价） |
| L4 TCP 连接 | worker 私有，**不迁移** | G_old drain：其 RTO/keepalive 持续驱动（自身 lcore_id 上的 timer）；到达 G_new 的旧连接包经 **flow_map miss** → `drain_ring_rx` 转发回 G_old，G_old 的响应经 `drain_ring_tx` 回 G_new 代发。**flow_map 窗口限定**：G_new 接管后注册、排空确认后关闭——稳态零开销；flow_map 只记本代际新流（**SYN-ACK 时入表**，第 2 节语义 6 v1.8 修正），miss 一律转 G_old；ARP/NDP 等协议包额外 clone 给所有 G_old（第 2 节语义 9）；**移交瞬间的半开连接**由语义 14 处理 | 基线 1；ff_dpdk_if.c:2105-2150；语义 13/14；P-D §3.5（dispatch 回调 nginx 未用——本方案启用） |

设计取舍说明（与 VPP 的有意差异）：VPP 把 listen 收敛到栈侧单点（app_listener + workers bitmap，R-A §2.2），F-Stack 不照搬——fd 是进程内索引（P-D §2.4），跨进程传递无意义；「多代际栈隔离 listen + 数据面切流」在功能上等价于 workers bitmap（决定「谁收新连接」的是 reta/分发层而非 listen 对象本身），改动面小得多。

### 5.2 reload 时序（文字版时序图，HUP）【v1.9 改写：同队列+同期接管+G_new 独占硬件+双向 drain_ring】

前置状态：slim primary 常驻（PID_P）；旧 worker 代际 G_old（N 个 secondary）；G_new 使用**同批 queue**（queue_id 代际无关固定映射）与**相同的 lcore_id**（D-A 终版定案，`lcore_mask`/`nb_procs`/队列数保持 N 不变）；两代各有自己的代际 mempool（gen0/gen1 乒乓复用）。

```
T0  master 收 HUP
    ├─ 【防重入】若上一轮 reload 未完成（存在未排空的 G_old）→ 拒绝本次
    │   HUP 并记日志（不支持快速连续 reload，第 2 节语义 6）
    ├─ ngx_init_cycle 重读配置（语法错→回滚，对齐内核 HUP，R-B §2.2）
T1  master fork 新 worker 代际 G_new（NGX_PROCESS_JUST_RESPAWN）
    ├─ 每个 G_new worker: ff_mod_init(--proc-id, secondary)
    │   secondary attach 到常驻 primary——无 primary 竞争（对比现状障碍 4）
    ├─ G_new worker 使用 G_old 同批 queue（queue_id 代际无关固定映射，
    │   rx_queue_list/tx_queue_id/reta/rss_check 四件套全部不变）
    ├─ G_new worker 取**与 G_old 相同的 lcore_id**（D-A 终版定案，第 2 节
    │   语义 8）；随之需启用：自驱 hardclock（语义 11，绕开共享
    │   priv_timer 槽）+ 代际 mempool（语义 12，各自独立 cache）
    ├─ G_new lookup 本代际 mempool（gen1）；G_old 继续使用 gen0（§6.6.3）
    ├─ master 不再需要 15s sem 等 primary 就绪（primary 一直在）；保留 ready 上报等待
T2  G_new worker 各自完成：ff_freebsd_init 栈实例 → ngx_open_listening_sockets
    │   （各自栈内 listen 同 IP:port，与 G_old 并存，栈隔离保证不冲突）
    └─ 经控制通道向 master 上报 READY
T3  master 确认全部 G_new READY → 触发同期接管（rx poll + tx + listen）
    ├─ ③-1【建立双向 drain_ring】（per-generation，SP/SC 明确，语义 13）：
    │      drain_ring_rx（G_new enqueue → G_old 唯一 dequeue）
    │      drain_ring_tx（G_old enqueue → G_new 唯一 dequeue 后代发）
    ├─ ③-2【跨进程互斥原语】移交 rx（共享内存标记，非 msg ring，语义 7/§5.4-1）：
    │      ① G_old 设置「停 rx 标记」并**确认本轮 rx_burst 已返回、不再调用**
    │      ② G_new 确认 G_old 已停 rx 后才起 rx poll
    │      ③ 移交窗口靠 NIC rx ring 缓冲兜底（RX_QUEUE_SIZE 512→4096 放大 8 倍）
    │      ④ 互斥只需覆盖 rx；tx 自此刻起由 G_new 独占，无并发
    ├─ ③-3【G_old 脱离硬件】：G_old 主循环进入「无硬件模式」——
    │      不再 rte_eth_rx_burst、不再 rte_eth_tx_burst、不再 send_burst
    │      （ff_dpdk_if.c:2865-2901 的 rx 循环与 :2844-2856 的 tx drain 均跳过）
    ├─ ③-4【G_new 同期接管 listen】（新连接归 G_new，新配置立即生效）
    ├─ ③-5【G_new 注册 flow_map】（软件分发表，第 2 节语义 6）：
        收到包 → ①先协议过滤（仅 TCP/UDP 四元组参与判定，
                  ARP/NDP/ICMP/非 IP/分片一律返回 queue_id 走原生路径）
                → ②解析四元组 → 查 flow_map
        ├─ SYN（新连接）→ 本栈处理并发 SYN-ACK →
        │   ★此时立即入 flow_map（v1.8：不等 accept）✓
        ├─ flow_map 命中（本代际已建连接后续包，**含第 3 个握手 ACK
        │   ——此刻连接尚在 syncache、accept 未发生，命中靠 SYN-ACK 时入表保证**）
        │   → 本栈处理 ✓
        └─ flow_map miss（旧连接的包）→ 经 drain_ring_rx 转 G_old ✓
           （校验 G_old 存活；G_old 已退则本栈按 TCP 规范回 RST，
            禁止 enqueue 到无主 ring。满环须计数+告警，不得静默丢弃）
    ├─ ③-6【G_new 代发路径】：主循环每轮 drain drain_ring_tx，
    │      dequeue 出的 mbuf 直接 rte_eth_tx_burst（唯一 tx 出口）
    └─ ③-7【ARP/NDP 等协议包处理】（第 2 节语义 9）：
        ARP/NDP 等协议包在转给 G_new 协议栈处理的同时，
        额外 clone 一份转发给所有 G_old 进程（原有 clone 给其他 G_new
        和 KNI 的逻辑不变）——G_old 已无硬件出口，邻居表全靠此路径维持
T4  G_old worker 收到 master 的 graceful shutdown（原生语义）
    ├─ 【语义 14】**停止 accept 但延迟 close listening**：保留 listening socket
    │   直至自身 syncache 半开条目排空或超时（tcp_close 对 LISTEN 不清 syncache，
    │   tcp_subr.c:2517-2553；syncache_expand 需 lsop，tcp_syncache.c:1033-1055）
    │   ——避免「移交前 G_old 收的 SYN」在移交后因无 listening 而握手失败
    ├─ 继续跑 ff_run（无硬件模式）：drain 存量连接
    │   （存量连接后续包经 G_new flow_map miss → drain_ring_rx 转发回来）
    │   （G_old 的出包 → drain_ring_tx → G_new 代发）
    │   timer 持续驱动（G_old 活着，自身 lcore_id 上的 timer，或启用自驱 hardclock）
    │   ARP/NDP 邻居表正常（③-7 clone 保证）
    └─ drain 完成（连接数=0 或 no_timers_left）→ 进程退出
T5  master 收 G_old SIGCHLD（且确认排空：连接数=0 + DRAIN_DONE）→ reload 完成
    ├─ 通知 G_new：关闭 flow_map、注销 drain_ring → G_new 进入稳态，成为
    │   下一轮 reload 的「老 worker」（防止性能退化；稳态无 flow_map、无 drain_ring）
    ├─ 更新 KNI runtime owner 至当前活跃代际（语义 15，ff_dpdk_kni.c:101-109）
    └─ G_new 已可再次接受 reload（防重入拦截随排空确认解除）
异常分支：
- T2 前 G_new 任一 worker 起不来/ready 超时 → master 放弃本轮（G_old 未受任何
  影响，服务继续）——对齐内核 HUP 配置失败回滚语义
- T3 移交失败（G_old 未确认停 rx / G_new 起 rx 超时）→ 放弃本轮（G_old
  恢复 rx poll 继续服务，G_new 退出）——互斥标记保证不会并发 poll
- T3 后 G_new 崩溃 → G_old 已脱离硬件，无法自行恢复 rx（v1.6 下 G_old 仍持 rx
  可继续服务，此处为 M1′ 相对 v1.6 的**新增风险**）→ 必须由 primary 或 master
  检测到后将 rx 交还给 G_old（若其仍在）或触发 worker 重生；该项须在 DR6 中
  定义明确的回退目标态与超时（见 §6.2 DR6 修订）
- drain_ring 满环 → 显式计数 + 告警（RV4），不静默丢弃已建连接包
- drain 挂起（长连接不退）→ 增补 shutdown timer（P-D §4 补充事实：F-Stack 版
  恰好缺失 ngx_set_shutdown_timer，需补回）兜底强退
```

USR2 时序：与 HUP 共用 T1-T5 机制，差异仅在 master 自身也经 exec 换代——master 本就无任何 ff 状态（P-D §2.2：master 不 ff_init、socket() 未劫持走内核），exec 是纯内核操作；新 master fork 的 worker 全是 secondary（T1 机制），常驻 primary 不受影响。**这使 #12 结论 "exec() is not supported"（R-B §3.7：DPDK 资源不能跨 exec 存活）在 S3 下不再阻塞 nginx USR2**——该限制约束的是 DPDK 进程自身的 exec，而 nginx master 不是 DPDK 进程。

### 5.3 与 nginx HUP/USR2 语义的映射

| nginx 原生语义（R-B §2.1/§2.2） | S3 映射 |
|---|---|
| HUP：新 worker 先起 → 旧 worker 关监听继续服务存量 → 排空退出 | 完全对齐（T1→T4）；「关监听」= 各自栈内 close，无跨进程影响；**v1.9 修正为「先停 accept、延迟 close listening」（语义 14），否则移交瞬间 G_old 的半开连接会全部失败** |
| HUP：配置失败回滚 | T2 前失败即回滚（G_old 未动） |
| USR2：旧 master 不关监听、保留回退能力 | 数据面等价物 = G_old drain 期间 drain_ring 双向路径持续可用；回退 = T3 前可随时放弃 G_new |
| USR2：新旧 worker 并行 accept | **v1.9 修正（原文残留 v1.0-v1.5 的 reta 表述）**：v1.6 起已不切流，本行为表现为「有序接管」——接管前 G_old 收新连接，接管后 G_new 收（更优：避免双代际同时 accept 的连接分布碎片化） |
| WINCH/QUIT：worker 优雅/强制退出 | drain 语义保留；补回 ngx_set_shutdown_timer |

### 5.4 需要新增的 ff_api / config.ini / ff_msg 接口面（设计清单，非实现承诺）

1. **ff_api 新增**（lib 侧）【v1.9 改写】：
   - `ff_flow_map_lookup(four_tuple)` / `ff_flow_map_insert(four_tuple)` / `ff_flow_map_close()`：**软件分发表 flow_map**（替代 v1.0-v1.5 的 `ff_conn_owner_query`）——存 G_new 本代际新建连接的四元组，**插入点在 `tcp_input` 的 listen 分支、syncache 插入成功并发 SYN-ACK 之后**（v1.8 修正：非 `accept()` 时，否则第 3 个握手 ACK 会 miss 被误转 G_old → RST）；须覆盖 SYN 重传（命中已有表项不重复插入）；drain 期间增量更新；miss → 经 **`drain_ring_rx`** 转 G_old；排空确认后 close 回稳态。窗口语义（第 2 节语义 6）：仅 reload 窗口被调用，稳态零调用。
   - **【v1.9 新增】`ff_drain_ring_create(port, gen)` / `ff_drain_ring_rx_enqueue(m)` / `ff_drain_ring_tx_enqueue(m)` / `ff_drain_ring_drain(dir, burst)` / `ff_drain_ring_destroy(port, gen)`**：per-generation 双向 ring（语义 13）。**约束**：
     - 两个 ring 均按 `(port, 代际号)` 命名，创建于 primary（secondary lookup），flags 分别取 `RING_F_SP_ENQ | RING_F_SC_DEQ`（单生产者单消费者，比 `dispatch_ring` 的多生产者语义更严，可在单测中直接断言）。
     - `drain_ring_rx`：生产者恒为持有队列的 G_new（每个 queue 一个生产者），消费者恒为对应的 G_old 进程。
     - `drain_ring_tx`：生产者为 G_old 进程，消费者恒为 G_new；G_new 侧 dequeue 后**直接 `rte_eth_tx_burst`**，不进协议栈（与 `process_dispatch_ring` 的入向语义区分，ff_dpdk_if.c:2222-2236）。
     - 满环行为：必须 `__atomic` 计数 + 日志告警，**禁止沿用 `:2144-2147` 的静默 `rx_dropped++`**（丢的是已建连接的数据包）。
   - **【v1.9 规格补全】`ff_queue_handover_mutex(port, queue, from_gen, to_gen)`**：**跨进程互斥原语**（共享内存标记，非 msg ring，语义 7）——G_old 设停 rx 标记 + 确认已停 → G_new 确认后起 rx poll。v1.6 只给了函数名，v1.9 补全规格：
     - **载体**：hugepage 共享内存中的 `struct ff_handover_state { uint32_t magic; volatile uint32_t rx_owner_gen; volatile uint32_t rx_stopped; ... }`，由 primary 创建。
     - **可见性**：所有读写用 `__atomic_load_n/__atomic_store_n(..., __ATOMIC_SEQ_CST)`，禁止裸 volatile 轮询（跨进程且可能跨物理核，需全序）。
     - **时序**：G_old 置 `rx_stopped=1` → 自旋等待自身本轮 `rte_eth_rx_burst` 返回并**不再调用**（P1-4：必须明确是「跳过 rx_burst」而非「退出主循环」，否则 G_old 收不到 `drain_ring_rx`）；G_new 自旋等待 `rx_stopped==1` 后起 rx poll，再置 `rx_owner_gen = 新代际`。
     - **超时与强制接管**：等待超时（建议 ≤ 移交窗口预算，初值 100ms，以 RV3 实测调整）→ 上报 HANDOVER_TIMEOUT，由 master 决定「放弃本轮（G_old 恢复 rx）」或「强制接管（仅当能确认 G_old 已停止触碰硬件）」；**强制接管的判据与兜底须在 DR6 中定案**。
     - **崩溃清理**：G_old 异常退出时标记残留 → 由 primary 或 master 依 SIGCHLD/心跳清理，避免下一轮 reload 读到脏标记。
   - `ff_arp_ndp_clone_to_old(m, port)`：ARP/NDP 等协议包 clone 给所有 G_old（第 2 节语义 9）——原有 clone 给其他 G_new 和 KNI 的逻辑不变（ff_dpdk_if.c:2161-2183），新增 clone 给 G_old 分支。**v1.9 说明**：M1′ 下 G_old 已无硬件出口，此路径是其邻居表的唯一来源，从「优化项」升为「必需项」。
   - **【v1.9 新增】半开连接窗口处理**（语义 14，择一）：
     - (a) `ff_listen_defer_close(so)`：G_old 进入 drain 时只停 accept、保留 listening socket，轮询自身 syncache 半开条目计数至 0 或超时后 close（推荐，改动小）。
     - (b) `ff_syncache_export_pending(...)`：T3 时导出 G_old syncache 中的半开四元组给 G_new，登记进 flow_map 并标记「转 G_old」（需新增 syncache 导出钩子，`syncache_lookup` 现为 static，见 tcp_syncache.c:1052）。
   - **【v1.9 新增】代际隔离相关**：`msg_ring` 索引由 `proc_id` 改为 `(proc_id, gen)`（`ff_dpdk_if.c:2903`/`:2457-2470`）；KNI runtime owner 改为跟随当前活跃代际（`ff_dpdk_kni.c:101-109`），由 T5 更新（语义 15）。
2. **ff_msg 扩展**（控制通道）：新增 FF_RELOAD 消息族——READY 上报、接管请求/应答、drain 进度上报、**DRAIN_DONE（触发 G_new 关 flow_map、注销 drain_ring 回稳态）**、**REJECT（防重入）**、**HANDOVER_TIMEOUT**（v1.9 新增，见上）。**v1.9 约束**：msg ring 必须做代际隔离（语义 15），否则两代 dequeue 同一 ring（`RING_F_SP_ENQ|RING_F_SC_DEQ`，`ff_dpdk_if.c:764-777`）导致控制消息错收。移交互斥仍用共享内存标记轮询而非 msg ring。
3. **config.ini 新增**（[dpdk] 段）：
   - `primary_slim = 1`（primary_slim_spec 已设计，V2/V4/V5 校验链沿用）。
   - `graceful_reload = 1`（总开关，默认 0 时行为完全回退现状——0 回归原则）。
   - `rx_queue_size = 4096`（从默认 512 放大 8 倍，增大接管窗口缓冲深度，ff_memory.h:43）。
   - **【v1.9 新增】`drain_ring_size`**：默认建议 2048（与 `DISPATCH_RING_SIZE` 对齐，ff_memory.h:36），可按 drain 期旧连接流量调整；须同步计入 mbuf 池预留。
   - ~~**【v1.9 新增】代际 lcore 池配置**~~ **已取消（2026-09-01 人工决策）**：D-A 定案两代同 lcore_id 后，`lcore_mask`/`nb_procs`/队列数保持 N 不变，**无需任何新增配置面**。原 C-NR-311 一并取消。
   - **【v1.9.1 新增】代际 mempool 配置**：`graceful_reload=1` 时 init 期预建 `mbuf_pool_%d_gen0/gen1`（乒乓复用），G_new secondary lookup（语义 12 / §6.6.3）。可选项：`reload_free_ring_size`（仅 M-B 需要，与 `drain_ring_size` 同族）。
   - **【v1.9.1 新增】心跳超时配置**：`reload_heartbeat_timeout_ms`，默认 **1000**（1s，可配置），用于 G_old 检测 G_new 失活（DR6 附则 / U-NR-8）。
   - **【v1.9 新增（加固项，默认关）】`self_driven_hardclock = 0` / `mempool_cache_size`**：对应语义 11/12 的加固项；D-A 定案后默认不需要开启，开启条件见语义 11/12 与 §6.6。
4. **nginx 适配层改造**（app/nginx-1.28.0）：
   - `ngx_process_cycle.c:223-237` 两段式 reload 块整体移除/条件化（graceful_reload=1 时走原生顺序：fork G_new → 等 READY → 同期接管 → G_old QUIT）。
   - `ngx_ff_module.c:169-187` + `ngx_process_cycle.c:1117-1121`：worker0 不再 primary，全部 secondary；queue_id 代际无关固定映射、lcore_id 两代相同（语义 15，DR8 定案；~~代际 lcore 池随 DR5 取消~~）。
   - 补回 worker QUIT 分支缺失的 `ngx_set_shutdown_timer`（P-D §4 补充事实）。
   - **【v1.9 新增】G_old 的 drain 分支改为「先停 accept、延迟 close listening」**（语义 14），不得在进入 drain 时立即 close。
   - reload 编排状态机（T0-T5 显式状态 + 打点），满足第 1 节否决性判据；**v1.9 新增 T3 后 G_new 崩溃的回退分支**（见 §5.2 异常分支与 DR6）。

### 5.5 与既有演进线的关系

| 演进线 | 关系 |
|---|---|
| primary_slim（#1078） | **直接依赖**：slim primary 是 S3 的 L1 常驻基础；其生产实现已过全部测试（`docs/primary_slim_spec/10` L4 闭环）。S3 是 primary_slim 的自然延伸（从"primary 稳定性"到"worker 可独立重生"） |
| native_mt（单进程多线程） | **受益+互斥沿用**：native-mt 已把 freebsd_clock 改 `__thread`（E-C §5.5），per-lcore timer 槽结构为多进程分核并存提供隔离基础；S3 沿用 thread_mode=0 与 primary_slim 的互斥校验（primary_slim_spec V4） |
| zc_stack（零拷贝） | **正交**：零拷贝收包路径不影响队列所有权模型；回调判定发生在包分发层，与 mbuf 来源无关（需在 M1 测试中纳入 zc 场景回归） |
| DPDK 23→24 升级线 | **依赖其补丁**：`rte_timer_meta_init`（62f1c34df）已 re-apply 到 24.11.6（commit 14355bf7b，E-C §5.1 表）；S3 的分核布局进一步降低对该补丁场景（同 lcore 槽残留）的暴露 |
| ld_preload ring（S2） | **并行独立**：S3 的 reload 控制消息协议设计（5.4-2）可复用于 fstack 实例的动态 sc 管理（R-A §6.3-3 方向）；无代码耦合 |
| 旧 iWiki 方案（S1） | **思想承接**：dispatch 层 → S3-M2；mempool/nice/timer 三难题 → **M1′ 下（两代同 lcore_id）依然存在**，由语义 11（自驱 hardclock）与语义 12（代际 mempool）分别解决；M2 形态下因 worker 不触碰硬件而弱化 |
| **stack-coexist（内核栈共存）**【v1.9 新增】 | **未评估，存在未知交互**：主线已有 `FF_KERNEL_COEXIST` 特性（`13b418191` 一个 listen 同时服务 F-Stack 与内核栈、`ba148589d` 默认关闭、`0f9e7f6ef` 配对 host socket 设 `SO_REUSEPORT`），每个 F-Stack socket 在内核侧有配对 socket。多代际 worker 并存 bind 同端口时的内核侧行为、reload 期间内核 fd ↔ F-Stack fd 映射的代际隔离均**未做代码考证**，§6.4 标为未评估；M0 需补专项调研或明确不支持 |

## 6. 风险清单与未坐实项

### 6.1 需运行时验证（RV，静态分析无法定论）

| # | 项目 | 验证方法建议 |
|---|---|---|
| RV1 | N worker + 1 slim primary 多 secondary 并存（24.11.6）稳定性：mempool 跨进程并发（不同 lcore cache）、EAL 资源、msg_ring 广播 | 双代际进程组长时间共存压测 + ff_top/ff_traffic 观测 |
| RV2 | ~~reta 运行时更新~~ v1.6 删除（reta 不改、不依赖 NIC RSS） | — |
| RV3 | **同期接管 rx 的互斥正确性**（v1.9 改写：互斥只覆盖 rx，tx 已由 G_new 独占）：跨进程互斥标记（共享内存 + SEQ_CST 原子）保证 G_old 停 rx 后 G_new 才起 rx；接管窗口靠 NIC rx ring（RX_QUEUE_SIZE 4096）缓冲兜底；残余风险为 virtqueue 数据结构并发损坏（非业务语义、静态无法定论）；virtio 无 imissed 不可观测 | 高速率注入 + 接管瞬间丢包计数（物理网卡 imissed / virtio 端到端业务指标）+ 互斥超时分支注入 |
| RV4 | **`drain_ring` 双向路径的吞吐/时延与满环行为**（v1.9 改写）：`drain_ring_rx`（旧连接入向）与 `drain_ring_tx`（旧连接出向）容量（默认 2048）在 drain 高峰是否成为瓶颈；**满环不得静默丢已建连接包**（现有 `dispatch_ring` 满环是静默 `rx_dropped++`，ff_dpdk_if.c:2144-2147） | 构造 80% 流量在旧连接的 reload 压测 + 满环计数/告警断言 |
| RV5 | flow_map 查表开销【仅 reload 窗口】：稳态零开销（flow_map 已关闭）；reload 窗口内四元组解析 + flow_map 查找在 10G 线速小包下的 CPU 占比 | reload 窗口内/外 pps 对比；验证排空确认后 flow_map 查表计数停止增长 |
| RV6 | **自驱 hardclock 精度等价性实测**（**v1.9.1 改写**：D-A 定案「两代同 lcore_id」⇒ `priv_timer` **必然同槽**，C-NR-307 是唯一解法、**无退路**；本项验证自驱模式与 `rte_timer` 挂槽基线的精度等价性，而非验证"隔离") | 先采集挂槽基线（E-NR-03，两实例须用**相同** lcore_id），再采集自驱数据；双代际共存期间观测 RTO/keepalive/延迟 ACK 精度与漏/重复触发。**不等价即为 blocker**（PT-NR-08 为 M2 合入门槛） |
| RV7 | 多代际栈隔离 listen 同 IP:port 的实际行为 | 双代际并存期并发 SYN 压测 |
| RV8 | KNI 启用场景：runtime owner 与双代际 worker 的交互（审核 Q13）。**v1.9 升为设计约束**：owner 必须跟随当前活跃代际（`ff_dpdk_kni.c:101-109` 的 `proc_id == kni.owner_proc_id` 固定比较需改造，见语义 15） | enable_kni=1 的 reload 回归 + 交替多轮后 KNI 仍可用 |
| RV9 | 端到端门禁：带流量循环 reload + 无死锁无 crash + 新连接错误数 0 + 存量连接全部 drain 成功 | ab 持续流量 + 循环 reload（v1.6 修订节拍：每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次，≥100 次）。**v1.9 补充约束**：单轮耗时 = 25s 初始化 + drain 时长 + 5s，而 nginx 默认 `keepalive_timeout` 75s 会显著拉长 drain → 门禁须声明客户端是否带 keepalive 与 drain 强退阈值，否则 100 轮不可在合理机时内完成（见 RV14） |
| RV10 | **同核处理新旧进程切换瞬间性能**（X3 关注点）：两代亲和同一物理核时高负载切换瞬间的流量/丢包/CPU 抢占；drain 期算力分配与 cache 抖动 | 高负载 reload 压测 + 切换瞬间 pps/CPU 观测。**v1.9 补充**：M1′ 下 G_old 不再 poll 硬件，算力占用显著低于 v1.6 形态，本项预期改善，但仍需实测 |
| **RV11** | **【v1.9 新增】TX 独占正确性回归**：确认 drain 期 G_old 无任何 `rte_eth_tx_burst` 调用路径（含异常/超时分支），G_new 代发路径在高速率下不成为瓶颈 | 代码路径审计 + 注入 G_old 出包高峰（大量 RTO 重传）验证无 tx 描述符环异常、无 mbuf 双重释放 |
| **RV12** | **【v1.9 新增】半开连接窗口**：移交前 G_old 已收 SYN、第 3 个 ACK 在接管后到达的连接能否完成握手（语义 14 两种修法的实测对比） | 构造「SYN 在 T3 前、ACK 在 T3 后」的时序注入 + 握手成功率断言 |
| **RV13** | **【v1.9 新增】msg_ring 代际隔离与 KNI owner 跟随**：两代并存期间 READY/DRAIN_DONE/REJECT/HANDOVER 消息不被错收；KNI owner 交替后仍正确 | 双代际并存期注入控制消息 + 校验各代际只收到本代际消息；多轮 reload 后 KNI 功能回归 |
| **RV14** | **【v1.9 新增】keepalive 场景下 drain 时长与门禁节拍可行性**：实测 `keepalive_timeout`（默认 75s）下 drain 完成时长，据此确定 RV9 的 `shutdown timer` 强退阈值与门禁总机时 | 长连接 + 循环 reload 实测单轮耗时；给出「客户端关闭 keepalive」与「保留 keepalive + 强退阈值 Xs」两种门禁配置的数据支撑 |

### 6.2 需设计评审（DR，机制选择需评审定案）

| # | 项目 | 备选与倾向 |
|---|---|---|
| DR1 | reload 编排者：nginx master（语义层自然）vs slim primary（全局视图） | **已定案（v1.9.3 人工决策）= 候选 b**：nginx master 编排（发 FF_RELOAD 消息 + double-fork 拉起 G_new + 等 READY 后发 QUIT 给 G_old）为主，slim primary 仅提供原子原语（队列互斥标记/msg_ring），保持数据面组件无业务语义 |
| DR2 | 旧连接归属判定：flow_map 查表（v1.6 主路径）vs reload 握手时导出四元组快照表 | 已定：flow_map 查表（**SYN-ACK 时入表**，miss 转 G_old，窗口化；v1.8 修正入表时机）；性能不足再退化快照（RV5 数据支撑） |
| DR3 | ~~reta 切流 vs 队列移交~~ v1.6 删除（reta 不改，同期接管+flow_map 为主路径） | — |
| DR4 | reload 控制通道载体（v1.6 已定）：移交互斥用共享内存标记（非 msg ring），READY/DRAIN_DONE/REJECT 用 msg ring | 已定：分两类通道。**v1.9 补充约束**：msg ring 必须做代际隔离（语义 15），否则两代 dequeue 同一 SP/SC ring |
| ~~DR5~~ | ~~代际 lcore 池与四链解耦的配置表达~~ | **已取消（2026-09-01 人工决策）**：D-A 定案「两代同 lcore_id」后，不需要 2N 个 lcore_id，`lcore_mask`/`nb_procs`/队列数保持 N 不变，**无新增配置面**。原 C-NR-311 随之取消。保留本行仅供审计追溯 |
| DR6 | 异常回退完备性：新 worker 部分失败、primary 被 kill、drain 挂起强退、T3 接管失败回退 | 状态机每阶段定义回退目标态。**v1.9 新增必答项已于 2026-09-01 定案**：**T3 之后 G_new 崩溃** → **采用方案① 由 primary 将 rx 交还 G_old**（M1′ 下 G_old 已脱离硬件、无法自行恢复 rx，v1.6 形态下 G_old 仍持 rx 可续服）。检测与超时见 DR6 附则 |
| DR7 | M2（dispatcher 中心化）启动判据：reload 窗口内 flow_map 开销 + drain 期 P99 劣化超阈值时立项 | 评审定阈值。**v1.9 决策 D-C**：M2 维持可选演进，不提前为主路径 |
| **DR8** | **【v1.9·2026-09-01 终版定案 D-A】lcore_id 策略** | **已定案：两代使用相同 lcore_id**（同核同 lcore_id）。理由：改用不同 lcore_id 会牵动 `lcore_mask → nb_procs → lcore_id → queue_id` 整条链，由此产生的各类池冲突**远严重于** `priv_timer` 与 mempool 同槽这一处问题。DPDK 硬禁令（`multi_proc_support.rst:169-172`）的理由正是 mempool cache 损坏，本方案以代际 mempool 分离消除该机理，属**理由不成立后的例外适用**（论证见语义 8）。**推论：语义 11（自驱 hardclock）与语义 12（代际 mempool）恢复为必需项** |
| **DR11**（v1.9 新增） | **共享 RX 池的跨代 free 方案**：M-A（RX 池 `cache_size=0`，简单但有稳态损耗）vs M-B（RX 池保留 cache，`free_ring` 由 G_new 代 free，稳态零损耗但有多一道 inbound 滞留） | **已定案（v1.9.3 人工决策）：先按 M-A 进行，M-B 作为 M-A 性能不达标的备选**。依据：M-A 实现简单、无 free_ring 标记混淆、触发占用饥饿更晚（§24.2）；M-B 仅在 PT-NR-09 显示 M-A 稳态损耗不可接受时启用 |

**DR6 附则：G_new 崩溃的检测与 rx 交还（2026-09-01 定案，对应 U-NR-8）**

- **心跳载体**：共享内存中的**全局切换标记（generation heartbeat counter）**，由 **G_new 在其 main_loop 每轮递增**。
- **G_old 侧检测**：G_old 在自己的 main_loop 中每轮（或每 N 轮）读取该标记，与上一轮采样值比较；**连续未递增超过阈值**即判定 G_new 失活。
- **标记的生命周期（关键，避免误判）**：标记持续递增，**直到 G_old 排空退出为止**；G_old 排空退出后，全局切换标记**随 flow_map 一并消亡、不再递增**。因此 G_old 只在「自己还存在」的窗口内检测心跳，**不存在「G_old 已退出后无人递增导致误报」的问题**。
- **超时值**：**默认 1s，可配置**（配置项沿用 §5.4-3 的开关族，建议 `reload_heartbeat_timeout_ms`，默认 1000）。1s 的依据：main_loop 为忙轮询、无阻塞，正常轮次间隔为微秒级；1s 对「进程崩溃/被 kill」这类硬失效有充分余量，同时将服务中断窗口控制在秒级。**该值须由 RV11/RT 实测校准**（M4 阶段）。
- **回退动作（方案①）**：G_old 判定 G_new 失活后，**由 primary 将 rx 交还 G_old**——即置 `rx_owner_gen` 回退为 G_old 代际、G_old 退出「无硬件模式」恢复 `rte_eth_rx_burst` 与 tx，并**关闭 flow_map**（此时无新代际，flow_map 无意义）。同时上报告警打点。
- **前置条件**：该回退要求 G_old 具备「可逆转回硬件模式」的能力，须在 C-NR-309 的实现中一并设计（无硬件模式标志必须可逆，且恢复 rx 前须确认 G_new 确已不再 poll——否则回到并发 poll 的老问题）。**该点已列入 C-NR-309 的实现约束与 M3 风险。**
- **未覆盖**：G_new 与 G_old **同时**崩溃（此时仅剩 primary，无法恢复数据面）→ 依赖外部运维重启，须写进运维手册。
| **DR9** | **【v1.9 新增】TX 处理形态**：(a) G_new 代发（M1′ 主路径，推荐）/ (b) init 期多配 `nb_tx_queues = 2N` 代际各一组（零跳，依赖硬件多队列）/ (c) 共享内存自旋锁保护 tx queue（改动最小，有锁开销与优先级反转） | 倾向 (a)；若 RV11 实测代发路径成为 drain 期瓶颈，评审切 (b)（需先确认目标网卡支持 2N tx queue） |
| **DR10** | **【v1.9 新增】防重入可否放松**：G_old 退化为纯软件进程后，多代并存在结构上成为可能——是否允许「上一代未排空即接受新 reload」 | 默认保持防重入（语义 6）；本项为可选增强，需独立评审多代并存下的 ring 链、flow_map 归属判定（miss 时转哪一代）与资源上界 |

### 6.3 lcore_id 策略与同核处理的性能考量（v1.9 定案，替代 v1.4 DISC-1）

**v1.9 终版定案（D-A，2026-09-01 人工决策）：两代使用相同 lcore_id（同核同 lcore_id）。**

> **本节前一版曾定案「不同 lcore_id」，已被 2026-09-01 人工决策推翻。保留下文作为决策留痕，避免后续重复论证。**

**推翻的理由（人工决策要点）**：改用不同 lcore_id 必须解开 `lcore_mask → nb_procs → lcore_id → queue_id` 这条链（需新增「代际 lcore 池」配置面与配套校验链），由此牵动的**各类池的冲突与重分配（mempool、msg_ring、dispatch_ring、timer 槽、队列池）远严重于 `priv_timer` 与 `mempool.local_cache` 同槽这一处问题**。正确做法是接受同 lcore_id，把代际 mempool 方案做细。

- **同 lcore_id 的两处真实冲突，及各自的解法（均为 M1′ 必需项）**：

  | 冲突 | 后果（代码坐实） | 解法 |
  |---|---|---|
  | `priv_timer[lcore_id]` 共享槽 | `rte_timer_meta_init` 的 memset 踩掉 G_old 挂着的 timer 链表 → 其 hardclock 永不再触发，存量连接 RTO/keepalive 静默停摆；共享链表上挂对方进程私有地址指针，`rte_timer_manage` 遍历会跨进程解引用私有虚拟地址 → 崩溃/数据损坏，**不可修补** | **语义 11 自驱 hardclock**（必需）：main_loop 按 TSC 间隔直调 `ff_hardclock()`，每进程 timer 完全独立、零共享状态 |
  | mempool `local_cache[lcore_id]` 共享槽 | 仅存在于**共享的 RX 池**（G_old 从 `drain_ring_rx` 收的包用完要 free 回 RX 池，与 G_new 的 free 并发） | **语义 12 代际 mempool + RX 池方案**（必需）：应用侧分代际 pool（各自独立 cache，竞态归零）；RX 池按 DR11 定案取 **M-A**（`cache_size=0`），M-B 备选 |

- **DPDK 硬禁令的例外论证（须写进 M2 评审记录）**：`dpdk/doc/guides/prog_guide/multi_proc_support.rst:169-172` 禁止 primary/secondary 共用同一 logical core，**其给出的理由正是「mempool per-lcore cache 会被破坏」**。本方案以「代际 mempool 分离 + 共享 RX 池的跨代 free 处理」**直接消除该失效机理**，属**理由不成立后的例外适用**，而非无视禁令。该论证须由 RV1（长稳）、RV6（timer）、PT-NR-09（mempool）三项实测佐证：观测 mbuf 水位平稳、无双重释放、无 pool 错配、无 cache 计数异常。
- **由此消解的问题**：**P0-3（四链死锁）不再成立**——不需要 2N 个 lcore_id，`lcore_mask` / `nb_procs` / 队列数全部保持 N，语义 15 的「代际 lcore 池」与 DR5 / C-NR-311 一并取消。
- **物理核**：两代同 lcore_id ⇒ 天然同物理核，无需 `--lcores` 亲和；X3 决策（2N 物理核非必需）自动满足。
- **同核算力竞争**（X3 关注点，RV10 专项验证）：轮询线程 100% 忙等，同核会算力分配与 cache 抖动。**v1.9 补充**：M1′ 下 G_old 已不 poll 硬件（只跑协议栈 + 定时器 + ring），算力占用显著低于 v1.6 形态，预期改善，但仍需实测。

### 6.4 适用范围（v1.6 修订：reta 不改，virtio 与物理网卡均可用；v1.9 增补 kernel_coexist 声明）

v1.6 方案不依赖 reta 切流原语，故不再有 v1.4/v1.5 的 NIC 能力矩阵限制：

| 部署环境 | S3 v1.9 可行性 | 说明 |
|---|---|---|
| 物理网卡（ixgbe/i40e/mlx5/ice 等） | ✅ | reta 不改，rss_check 不变；无 NIC RSS 能力依赖 |
| virtio/云主机 | ✅ | 同上——virtio 也可用（reta_size==0 不影响，因不调用 set_rss_table） |
| 启用 FF_FLOW_ISOLATE/FF_FDIR 的部署 | ✅ | 不调用 set_rss_table，无编译期互斥 |
| **启用 stack-coexist（`kernel_coexist=1`）的部署**【v1.9 新增】 | ⚠️ **未评估** | 主线自 2026-06 起有内核栈与 F-Stack 双栈共存特性（`13b418191`「one listen serves F-Stack and kernel」、`ba148589d` 门控 `FF_KERNEL_COEXIST` 默认关闭、`0f9e7f6ef` 对配对 host socket 设 `SO_REUSEPORT`）。**该特性下每个 F-Stack socket 在内核侧有配对 socket**，多代际 worker 并存 bind 同端口时内核侧行为、以及 reload 期间「内核 fd ↔ F-Stack fd」映射是否需要代际隔离，**本设计未做代码考证**。M1′ 在该场景的行为**未坐实**，须先补做专项调研再决定是否支持（建议：M0 增补一项 E-NR，或明确列为不支持并在 `graceful_reload=1` 时校验拒绝） |

**M1′ 准入前置依赖**：primary_slim 合入。v1.5 的「取得支持 reta 的物理网卡环境」前置依赖已取消（不依赖 reta）。`graceful_reload=1` 的降级语义保留（当环境不支持多队列时退化为有损 reload）。

**v1.9.1 追加的准入条件**（由 P0-6 与同 lcore_id 引入，v1.6 未计入）：

1. ~~代际 lcore 池可配置且校验通过（DR5）~~ **已取消**（D-A = 同 lcore_id，无此依赖）。
2. **msg_ring 与 KNI runtime owner 完成代际隔离**（语义 15 / RV13）——同 lcore_id 下 proc_id 也同值，该项**依然必需**。
3. **`drain_ring` 两个 ring 可创建且容量纳入 mbuf 池预留**（§5.4-3 / RV4）。
4. **【v1.9.1 新增】自驱 hardclock 合入并通过 PT-NR-08 精度回归**（语义 11，同 lcore_id 下必需）。
5. **【v1.9.1 新增】代际 mempool 就绪**（语义 12）。**DR11 已于 v1.9.3 定案取 M-A**，故须接受 RX 池 `cache_size=0` 的稳态损耗并下调 D5（幅度由 PT-NR-09 量化）；若损耗超阈值则启用 M-B 备选。
6. **【v1.9.1 新增】DPDK 硬禁令例外论证经评审记录**（语义 8 / §6.3），并由 RV1/RV6/PT-NR-09 实测佐证。

### 6.5 v1.6 对 v1.4/v1.5 旧内容的废弃说明

以下 v1.4/v1.5 增补的内容在 v1.6 方案修订后已**废弃**（保留本节供审计追溯，不再作为设计依据）：

- ~~§6.3 DISC-1（乒乓 lcore_id 亲和物理核）~~：v1.6 不再乒乓双队列段，DISC-1 的前提（2N 队列段浪费 50% 物理核）不存在。同核处理的性能考量见新版 §6.3。
- ~~§6.4 适用范围与网卡能力矩阵（reta 依赖）~~：v1.6 不依赖 reta，virtio 与物理网卡均可用。新版 §6.4 简化为环境能力说明。
- ~~§6.4.1 无 RSS 有损 reload 兜底~~：v1.6 不依赖 reta，无「reta 静默成功伪装」黑洞。`graceful_reload=1` 的降级语义保留（不支持多队列时退化为有损），但触发条件从「reta_size==0」改为「不支持多队列」。
- ~~§6.5 形态 V（软件切流，未来工作）~~：v1.6 主路径本身就是「同队列+软件切流（flow_map）」，形态 V 的机制已并为主路径。不再作为单独的未来工作。

#### 6.5.1 v1.9 对 v1.6 形态的废弃说明（新增）

v1.6 的「两代共享同一批硬件队列（rx 互斥移交 + tx 无保护）」在 v1.9 被 **M1′「单硬件所有者」** 取代，原因与差异：

| 维度 | v1.6 形态 | v1.9 M1′ |
|---|---|---|
| rx | 互斥移交，两代先后持有 | 互斥接管，此后仅 G_new 持有 |
| tx | **两代并发同一 `tx_queue_id`（违反 `rte_ethdev.h:6575-6577` 契约）** | G_new 独占；G_old 出包经 `drain_ring_tx` 代发 |
| 旧连接入向 | 复用 `dispatch_ring`（同队列下产生双消费者，违反 `RING_F_SC_DEQ`） | per-generation `drain_ring_rx`（SP/SC 明确） |
| 旧连接出向 | 零跳（但并发不安全） | 一跳（安全） |
| 硬件状态共享面 | rx + tx 双份 | 仅 rx，且互斥保护 |
| G_old 崩溃影响 | 无（G_new 独占后） | 同上 |
| **G_new 崩溃影响** | G_old 仍可续服（若未退） | **G_old 已脱离硬件，须靠 primary/master 回退（DR6 新增必答项）** |

保留 v1.6 中仍然有效的部分：同队列 + queue_id 代际无关映射（reta/rss_check 不变）、flow_map 软件分发表与 SYN-ACK 入表时机、ARP/NDP clone、防重入、reta 不依赖。

### 6.6 代际 mempool 与共享 RX 池的细化设计（v1.9 终版：D-A = 同 lcore_id，本项为必需项）

> 本节是 D-A 反转后**唯一需要正面解决的资源冲突**。设计目标：在两代进程同 lcore_id 的前提下，做到「应用侧零竞态」+「共享 RX 池可控」+「稳态零每包开销（仅选 M-B 时；**已定案 M-A 为主故有稳态损耗，D5 须下调**）」。

#### 6.6.1 现状与关键事实

**代码事实**：`pktmbuf_pool[socketid]`（`ff_dpdk_if.c:149`，per-NUMA 一个）由 primary 创建（`:616-635`，`rte_pktmbuf_pool_create(..., MEMPOOL_CACHE_SIZE, ...)`）、secondary lookup 共享（`:638`）。**RX queue 在 init 期绑定该 pool**（`rte_eth_rx_queue_setup(..., mbuf_pool)` `:1141`）且**运行时不可更换**（virtio 无 queue stop/setup）。应用侧 alloc 点：TX 发包 `:2564`/`:2706`、dispatch clone `:2173`/`:2188`（v1.9 复审修正：原引 :2563/:2705/:2172 是「取池」行）。

**关键事实（决定了方案形态）**：`local_cache` 是 **`struct rte_mempool` 的成员**（`dpdk/lib/mempool/rte_mempool.h:258`），访问为 `&mp->local_cache[lcore_id]`（`:1340-1341`）。

> ⇒ **每个 mempool 拥有独立的 local_cache 数组。两个不同 mempool 的同号 `local_cache[L]` 是两块不同内存。**
> ⇒ **代际 mempool 一旦分开，两代的 cache 便互不重叠，同 lcore_id 也不冲突。**
> 本项更正了 v1.7 语义 12 中「即使在不同 pool 内仍会在同号 cache 槽竞态」的表述（该表述不成立）。

#### 6.6.2 竞态面全表（同 lcore_id + M1′ 形态下重新评估）

| # | 路径 | 谁在做 | 是否竞态 | 处置 |
|---|---|---|---|---|
| 1 | RX refill（`rx_burst` 内 `mempool_get`） | **仅 G_new**（G_old 不 poll rx） | 否 | 无需处理 |
| 2 | 应用侧 alloc（TX/clone/构造出包/`ff_ref_pool`） | 两代各自 | 是 | **分代际 mempool**（各自独立 cache）→ 归零 |
| 3 | **RX mbuf 的 free** | **G_new + G_old 两者**（G_old 从 `drain_ring_rx` 收到的包用完要 free 回 RX 池） | **是（唯一残留）** | **DR11 已定案：M-A**（`cache_size=0`）；M-B 备选 |
| 4 | 跨代 free（对端消费后释放） | 两代各自 | 否 | 靠 `m->pool` 指针自动回正确 pool（分代际后 pool 不同，cache 也不同） |

#### 6.6.3 应用侧：代际 mempool（必需项）

- **池的划分**：`mbuf_pool_%d_gen0`（G_old）/ `mbuf_pool_%d_gen1`（G_new），以及对应的 `ff_ref_pool` 等一并分代际。
- **创建时机**：**init 期预建**（`graceful_reload=1` 时），由 primary 创建、G_new 以 secondary 身份 `rte_mempool_lookup`。**不选「reload 触发时创建」**——后者会在 reload 关键路径上引入创建失败与时序风险。
- **代际号复用**：按 reload 轮次在 gen0/gen1 间**乒乓复用**；G_old 排空退出后其代际池清空，可被下一代复用。**避免池数量随 reload 轮次无限增长**（这是分代际方案必须回答的资源上界问题）。
- **不用改 DPDK**：仅需 F-Stack 侧替换 alloc 点使用的 pool 指针。跨进程 free 正确性由 `m->pool` 指针天然保证，**无需额外记账**。

#### 6.6.4 共享 RX 池：M-A / M-B（**DR11 已定案：M-A 为主，M-B 备选**，2026-09-02 人工决策）

| | **M-A（主）** | **M-B（备选）** |
|---|---|---|
| 做法 | RX 池 `cache_size=0`（`:633-634` 的 `MEMPOOL_CACHE_SIZE→0`） | RX 池**保留 cache**；G_old 用完的 RX mbuf 批量 enqueue 到 `free_ring`，由 G_new 统一 free |
| 机理 | alloc/free 全走 common pool 的无锁 MP/MC ring | RX 池的 alloc **与** free 都只剩 G_new 一个进程 |
| 稳态开销 | **有**（每包多两次 ring 操作），应 D5「稳态零每包开销」须下调（v1.9.3 DR11 已定案 M-A 为主并接受此损耗，PT-NR-09 量化） | **零**（G_old 不存在时该路径完全不触发） |
| drain 期开销 | 无额外 | 每个用完的 mbuf 多一次**批量** ring 往返（可 burst） |
| 实现量 | 小（改一个创建参数） | 中（多一个 ring + G_new 侧 drain 逻辑；可与 `drain_ring_tx` 合并为同一条 G_old→G_new 通道，用 mbuf 私有标记区分「待发送」与「待释放」） |
| 风险 | 稳态性能损失（PT-NR-09 量化） | 若 G_new 崩溃而 G_old 仍在 enqueue，free_ring 会堆积（由 DR6 附则的回退一并处理：交还 rx 后 G_old 可自行 free 或丢弃） |

- **定案（v1.9.3 DR11）**：默认取 **M-A**（`cache_size=0`，稳态有损耗由 PT-NR-09 量化）；PT-NR-09 实测 M-A 稳态损耗不可接受时，启用 **M-B** 备选（须接受 `free_ring` 实现量与 drain 期 inbound 滞留代价）。
- **对照 iWiki 旧方案**：E-C §6.1 记录 iWiki 4015929276 采用「关闭 cache + 缩小冲突域 + CAS，实测性能损失很小」——即 M-A 路线（且作用于驱动层 mempool）。本设计**不照搬**：M-B 在保留 cache 的前提下用「跨代代 free」消除竞态，稳态无损耗。iWiki 的「实测损失很小」属**单来源且为 DPDK 18.11 环境**（[06] §8），不可直接外推到 24.11.6。

#### 6.6.5 否决项

- ~~**方案 C（双 pool 运行时切换）**~~：TX/clone 侧可行但 **RX 侧不可行**（queue 绑定不可换），不能独立成立 —— 否决。
- ~~**改 `local_cache[]` 索引为 workerid/代际 id**~~（v1.7 的方案 B）：需改 DPDK `rte_mempool.c`（F-Stack 本地补丁，升级 DPDK 需重做）。**既然 per-mempool cache 天然隔离，此项已无必要** —— 否决。

#### 6.6.6 回归要求

跨代 alloc/free 无泄漏（`rte_mempool_avail_count` 无单调下降）、无 pool 错配（无 mbuf 校验错误/crash）、无双重释放 —— 由 **PT-NR-09**（量化 + 正确性）与 **RV1**（≥30min 长稳，mbuf 水位平稳）覆盖；DR11 已定案取 **M-A**；PT-NR-09 负责量化其稳态损耗，并在超阈值时提供切 M-B 的依据。

## 7. 与目标语义的对照验收（推荐方案自检）

| 目标（第 2 节） | S3-M1′ 达成方式（v1.9） | 残余风险 |
|---|---|---|
| 1 新连接零丢失 | G_new 接管 rx+tx+listen 后 flow_map 记录新 SYN（SYN-ACK 时入表）；互斥标记保证 rx 队列始终有主；**移交瞬间的半开连接由语义 14 兜底** | RV3（接管互斥正确性/缓冲）、RV12（半开连接窗口） |
| 2 存量连接完整 drain | G_old 活着跑 ff_run（无硬件模式）+ flow_map miss → `drain_ring_rx` 送达 + 出包经 `drain_ring_tx` 代发 + ARP/NDP clone + **timer 持续（同 lcore_id ⇒ 由自驱 hardclock 保证，语义 11 必需项）** | RV4（ring 容量与满环行为）、RV6（自驱精度等价性，PT-NR-08 为门槛）、RV11（TX 独占回归） |
| 3 配置失败回滚 | T2 前失败 G_old 未动；T3 接管失败回退（互斥标记保证不并发 rx）；**T3 后 G_new 崩溃的回退由 DR6 定案** | 设计保证（DR6，v1.9 新增必答项） |
| 4 HUP+USR2 均支持 | 机制同源；master 无 ff 状态可安全 exec | USR2 路径需专项测试 |
| 5 工程意义无损 | 门禁 = RV9 错误数 0（≥100 次，排空确认后 reload）；**v1.9 补充 RV14：须实测 keepalive 下 drain 时长并确定强退阈值，否则门禁机时不可控** | 接受 HAProxy 文档级边界（R-B §2.2） |
| 6（语义 6 防重入） | 排空前拒绝新 reload（REJECT）；多代并存放松属 DR10 可选增强 | DR10 未定案 |
| **13（TX 独占，v1.9 新增行）** | G_new 独占 tx：G_old 置「无硬件模式」后**三处 flush 入口全部短路**（`:2532`/`:2557`/`:2853`），出包一律 enqueue `drain_ring_tx` 由 G_new 代发；`drain_ring_rx`/`drain_ring_tx` 各自 SP/SC，不再有 `dispatch_ring` 双消费者问题 | RV11（TX 独占回归，IT-NR-A09 断言 G_old 侧 tx_burst 计数恒 0）；PT-NR-10（代发开销）；**T3 后 G_new 崩溃 → 无进程收发包**（DR6） |
| **14（半开连接窗口，v1.9 新增行）** | G_old 停 accept 但**延迟 close listening** 至自身 syncache 半开条目排空或超时（shutdown timer 兜底），使移交前收到的 SYN 仍能完成三次握手 | RV12（IT-NR-A10）；`tcp_syncache.h:36-48` 无计数接口 → 需新增导出（C-NR-312）；修法 (a)/(b) 待 U-NR-9 定案 |
| **15（代际隔离，v1.9 新增行）** | **两代同 lcore_id**（D-A 终版），queue_id 代际无关映射；`lcore_mask`/`nb_procs`/队列数保持 N 不变，**无新增配置面**（DR5 取消）；msg_ring 按 (proc_id, 代际) 索引 + KNI runtime owner 跟随活跃代际（T5 更新） | RV13（IT-NR-A11、UT-NR-12）；同 lcore_id 的 timer/mempool 同槽由语义 11/12 解决 |
| **同 lcore_id 的 timer 同槽（语义 11，必需）** | 自驱 hardclock：main_loop 按 TSC 间隔直调 `ff_hardclock()`，每进程 timer 完全独立 | PT-NR-08 精度回归为**合入门槛**（偏差 ≤5%，无漏/重复触发）；RV6 长稳 |
| **同 lcore_id 的 mempool 同槽（语义 12，必需）** | 应用侧分代际 pool（独立 cache ⇒ 竞态归零）+ 共享 RX 池按 DR11 处理（**M-A 为主**：`cache_size=0`；M-B 备选） | PT-NR-09 量化与正确性；RV1 长稳（mbuf 水位平稳、无双重释放/错配）；DPDK 硬禁令例外论证须由三项实测佐证 |
| 稳态零每包开销 | flow_map 与 drain_ring 均窗口化，排空后注销；**代际 mempool 选 M-B 时 RX 池保留 cache、稳态零损耗**（选 M-A 则有稳态损耗，须下调 D5，见 §6.6.4） | PT-NR-01/09/10 量化 |

## 8. 单来源声明

本设计引用的证据中，以下为**单来源**（未经第二独立来源交叉坐实，使用时须注意强度）：

1. **iWiki 4015929276 全部内容**（旧方案四大改造、58 万 QPS、10h/200 次 reload/112 timeout 数据）：仅此来源（E-C 考证员经 iwiki-cli 获取）；orange30 原始代码从未开源（E-C §8-U5）。
2. **Facebook LPC 2021 细节**（socket takeover/sk_reuseport/30x 不丢）：中文译文单来源（R-B §6-3：原 slides 未取到）。
3. **VPP issue #3547 的根因分析**（vcl/vls worker index 错位连环 crash）：报告者个人分析，维护者未确认（R-A §4.3）。
4. **primary_slim PoC/生产数据**（12/12 零中断、E2e/E10 等）：docs/primary_slim_spec 本地实测一手文档，但**非本团队成员复测**（R-A §6.2 对其的引用是转述）。
5. **VSAP 补丁内容**：仅 README 描述级，补丁正文未读（R-A §7-2）。
6. **AsterNOS-VPP**：营销内容，本设计未采用为证据（R-A §7-8）。
7. **6WIND 本地应用路径**：introduction 页推断（R-B §3.3，标注推断）。
8. P-D/P-E 的全部代码行号事实：本团队一手探测（可回查复核，本设计第 0 节已抽查四处一致）；v1.9 新增的 §0.2 回查表亦为一手实读。
9. ~~R-A/R-B 对 DPDK 24.11.6 中 reta 动态更新、多 secondary 并存行为的推论~~ **v1.9 更新**：v1.6 起已不依赖 reta，该项失效；替代为「多 secondary 并存（24.11.6）行为」的静态结构推断，本团队未运行时验证（对应 RV1）。
10. **【v1.9 新增】TX 并发后果的定性**：「两代并发同一 tx queue 违反 DPDK 契约」属**代码坐实**（`rte_ethdev.h:6575-6577` 原文 + F-Stack 单 tx 出口）；但其**具体故障形态**（描述符环竞争导致 mbuf 双重释放 / 描述符覆盖 / 网卡挂死）为**推断，未实测**，不得当作已验证结论。
11. **【v1.9 新增】stack-coexist 特性信息**：来自本地 git 提交（`13b418191`/`ba148589d`/`0f9e7f6ef`）与代码实读，非外部来源；但该特性与 reload 的**交互未做代码考证**（§6.4 标为未评估）。

---

## 9. v1.9 定案汇总（决策记录）

| 决策 | 结论 | 依据 |
|---|---|---|
| **D-A** lcore_id 策略 | **两代使用相同 lcore_id（同核同 lcore_id）**【2026-09-01 人工决策，推翻本轮前一版「不同 lcore_id」】 | 拆 `lcore_mask→nb_procs→lcore_id→queue_id` 链引发的各类池冲突，远严重于 `priv_timer` 与 mempool 同槽一处问题。DPDK 硬禁令的理由（mempool cache 损坏）由代际 mempool 消除 ⇒ 例外适用（语义 8 / §6.3） |
| **D-B** 方案形态 | **M1′ 单硬件所有者 + drain 代际软件寄生**（G_new 独占 rx+tx，G_old 软件寄生，双向 `drain_ring`） | 一次性消除 P0-1（TX 并发）与 P0-2（ring 双消费者）两类契约级风险；代价为 drain 期出包多一跳（PT-NR-10 量化） |
| **D-C** M2 定位 | 维持可选演进（DR7 触发），**不提前**为主路径 | M2 稳态每包一跳，收益需以 M1′ 实测数据为前提 |
| **DR5** 代际 lcore 池 / 四链解耦 | **取消**（D-A 定案的推论） | 同 lcore_id 不需要 2N 个 lcore_id；`lcore_mask`/`nb_procs`/队列数保持 N；C-NR-311 一并取消；**P0-3 随之消解** |
| **DR6** T3 后 G_new 崩溃 | **方案① 由 primary 将 rx 交还 G_old** | 见 DR6 附则：共享内存全局切换标记每 loop 递增作心跳，G_old 检测；G_old 排空退出后标记随 flow_map 消亡不再递增；超时默认 1s 可配置 |
| **语义 11 自驱 hardclock** | **恢复为必需项** | D-A = 同 lcore_id ⇒ `priv_timer` 必然同槽；PT-NR-08 为合入门槛 |
| **语义 12 代际 mempool** | **恢复为必需项并细化** | 应用侧分代际 pool（独立 cache，竞态归零）；共享 RX 池按 DR11 选 M-A/M-B（**M-A 为主，M-B 备选**） |
| 半开连接窗口（语义 14） | 倾向 (a) listening 延迟关闭；(b) syncache 导出的前提是新增 static 函数导出钩子，改动更大 | `tcp_subr.c:2517-2553`、`tcp_syncache.c:1033-1055` |
| msg_ring / KNI owner | **必须做代际隔离**（由 RV8 升级为设计约束） | `ff_dpdk_if.c:2903`/`:764-777`、`ff_dpdk_kni.c:101-109` |
| ~~加固项默认态~~ | ~~自驱 hardclock、`cache_size=0`、mempool 分代际默认全部关闭~~ **已废止** | D-A 反转后前两条为必需项；`cache_size=0` 不再是全局默认，仅作为 DR11 的 M-A 选项、作用域限于共享 RX 池 |

**核心结论**：推荐 S3（**v1.9 M1′：同队列 + ready 后同期接管 rx+tx+listen + G_new 独占硬件 + G_old 软件寄生 + 双向 `drain_ring` + flow_map 软件分发表 + rx 互斥 + ARP/NDP clone**，承接 primary_slim），S2 为并行备选产品线，S1/S4 不独立实施（思想/原则分别并入 S3-M2 与 S3 时序）。落地拆解见 [07-里程碑](07-milestones.md)，测试与验收见 [08-测试计划](08-testing.md)。

**开工前置**：
- **已定案（无需再评审）**：D-A（同 lcore_id）、D-B（M1′）、D-C（M2 不提前）、DR6（rx 交还 G_old + 心跳）、DR8（lcore_id 策略）。
- **DR 定案汇总（v1.9.3）**：DR1 **已定案 = 候选 b**（nginx master 编排 + primary 原子原语，详见 [09] §24.5）；DR5 已取消；DR6/DR8/DR11 已定案（见 §6.2 DR 表）。**M2 开工前无待评审 DR 项。**
- **待评审（M4 开工前）**：DR6 附则的超时值实测校准（默认 1s）。
- P0-1~P0-6 对应的编码点见 07 v1.4 的 C-NR-309~313（**C-NR-311 已取消，C-NR-307/308 恢复为必需**）。
