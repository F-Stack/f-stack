# 06 方案设计：候选方案对比与推荐方案 S3 关键设计

| 项 | 值 |
|---|---|
| 文档编号 | 06 |
| 标题 | F-Stack Nginx 无损 reload 候选方案对比（S1~S4）+ 推荐方案 S3 设计 |
| 版本 | v1.7（v1.6 基础上据 2026-08-24 定时器/mempool 调研+人工决策：新增语义 11 自驱 hardclock 绕开共享 timer 槽、语义 12 应用 mempool 分代际；§6.6 网卡 RX mempool 已定方案 A cache_size=0 主 + 方案 B cache 槽位改造备选） |
| 日期 | 2026-08-24 |
| 状态 | 待人工审计（v1.7 增量修订） |
| 来源产物 | work/solution-design.md（方案设计师 solution-designer，2026-08-18 落盘）。本篇为正式化改写：输入为 [01](01-vpp-vcl-research.md)/[02](02-other-projects-research.md)/[03](03-fstack-legacy-solution.md)/[04](04-fstack-current-analysis.md)/[05](05-ld-preload-alternative.md) 五篇的前身产物（均已全文阅读）+ 关键机制回查实际代码交叉验证（只读）；保留全部事实证据、单来源声明与未坐实标注 |

相关篇章：[00-总览](00-overview.md) | [04-现状分析](04-fstack-current-analysis.md) | [07-里程碑](07-milestones.md) | [08-测试计划](08-testing.md)

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

- `lib/ff_dpdk_if.c:2100-2150`：packet_dispatcher 回调 + dispatch_ring 跨进程转发（**关键确认：回调仅对 `!pkts_from_ring` 的包触发（:2100/:2105），ring 转发来的包不会二次进回调——转发兜底机制天然无循环风险**）。
- `lib/ff_dpdk_if.c:2223-2236`：process_dispatch_ring 从 per-(port,queue) ring dequeue 后以 `pkts_from_ring=1` 进 process_packets → ff_veth_input。
- `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:223-270`：`#if (NGX_HAVE_FSTACK)` 两段串行 reload（先全退再起新）。
- `app/nginx-1.28.0/src/event/modules/ngx_ff_module.c:169-187`：ff_mod_init 按 proc_type 硬编码拼 `--proc-type=primary/secondary`。

另粗读 `docs/primary_slim_spec/03-solution-design.md`、`10-feasibility-conclusion.md` 作为 S3 依据。

### 0.1 两条外部调研线的共同结论基线（第 1 判据，方案评估的锚）

R-A §6.2 与 R-B §5.2 增补段独立得出同构结论，本设计将其作为第一判据：

1. **业界无 TCP 已建连接迁移先例**（R-B §4 P4：Envoy 原句 "existing connections are not transferred"；R-A §4.2 第 5 点 VCL 旧 worker 连接随 drain 关闭互证）。目标语义必须对齐「**新连接无缝切换 + 旧进程 drain**」，不追连接状态迁移。
2. **网卡队列/收包所有权与业务进程生命周期解耦，是用户态栈无损 reload 的结构性前提**（R-A §6.2：VPP 队列归独立进程、无主窗口结构性不存在；#1078 primary_slim PoC 杀 primary 后 12/12 连接零中断；adapter/syscall 中心化设计，三方独立指向同一结论）。**监听 fd 归属是第二位的控制面问题**（P-D 障碍 2 的前提性弱化）。
3. FB "ready 前不切流"（R-B §2.4(a)）与 VCL app_listener workers bitmap（R-A §2.2/§4.2）同构：新 worker 注册进 bitmap / 应用 ready 之前，accept 不分发给它、流量持续给旧实例。

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
6. **流表仅 reload 窗口生效 + reload 防重入**（v1.3 增补语义，v1.6 据 2026-08-21 方案修订改写）：稳态所有数据包**不经过流表**（零额外每包开销）；流表仅在新 worker 初始化完成（READY）并同期接管队列+listen 后自动生效，至老 worker 排空确认后关闭。流表（**flow_map**，软件分发表）**只记录本代际新建连接的四元组**（SYN accept 时入表，非协议栈 inpcb 表）；表项 miss（旧连接的包）**一律经 dispatch_ring 转老 worker**。老 worker 排空后新 worker 感知并关闭 flow_map、进入稳态成为新的「老 worker」（防止性能退化）。**不支持老 worker 排空前的快速连续 reload**：上一批老 worker 排空前，新的 reload 请求被拦截（拒绝并记日志）。
7. **ready 后同期移交队列+listen**（v1.6 据 2026-08-21 决策修订，替代 v1.4 的「末期一次性移交」）：G_new ready 后**同期移交队列消费权 + listen**给 G_new（不是末期才移交），G_new 立即接管新连接（**新配置立即生效**），旧连接包经 flow_map miss → ring 转 G_old drain。移交靠**跨进程互斥原语**（共享内存标记，非 msg ring）保证 G_old 停 poll 后 G_new 才起 poll，规避并发 poll 同一 queue；移交窗口靠 NIC rx ring 缓冲兜底（RX_QUEUE_SIZE 512→4096 放大 8 倍）。
8. **同核处理新旧进程**（v1.6 据 X3 决策，替代 v1.4 的「2N 逻辑 lcore_id」）：新旧进程可**同核处理**（不占 2N 物理核、不乒乓双队列段），proc_id 分配改为**代际无关固定映射**到同一批 queue（G_new 启动时直接用 G_old 的队列号，`tx_queue_id / rx_queue_list / dispatch_ring` 全部对齐，不需运行时重算 lcore_conf → rss_check/adjust/tbl/thash 四件套不变）。**但新旧进程高负载时切换瞬间的流量/丢包情况需关注**：两代进程同核时各得约 50% 有效算力 + 上下文切换/cache 抖动，可能延长 drain（需运行时观测，列入 RV）。
9. **ARP/NDP 等协议包 clone 给 G_old**（v1.6 增补）：reload 窗口内，ARP/NDP 等协议包在转给 G_new 协议栈处理的同时，**额外 clone 一份转发给所有 G_old 进程**（原有 clone 给其他 G_new 和 KNI 的逻辑不变）——确保 G_old drain 期间邻居表正常、能发 RTO/FIN/ACK。
10. **reta 不改、不依赖 NIC RSS 能力**（v1.6 增补，同时解决审核致命 1/2/3）：S3-M1 不再依赖 reta 切流原语——同队列 + proc_id 代际无关固定映射使 reta 不变、ff_rss_check 四件套不变、不配 2N 队列（不丢半流量）。**virtio 与物理网卡均可用**（无需 guest 侧 RSS 能力）。
11. **自驱 hardclock，绕开 DPDK 共享 timer 槽**（v1.7 据 2026-08-24 定时器调研+人工决策）：新旧进程**同 lcore_id** 共存时，DPDK `priv_timer[lcore_id]` 共享槽不可用（`rte_timer_meta_init` 的 memset 会踩掉 G_old 挂着的 timer 链表 → 其 hardclock 永不再触发 → 存量连接 RTO/keepalive 静默停摆；且共享链表上挂对方进程私有地址指针，`rte_timer_manage` 遍历会跨进程解引用私有虚拟地址 → 崩溃/数据损坏，不可修补）。**方案**：放弃 rte_timer 挂槽方式，main_loop 按 TSC 间隔直接调用 `ff_hardclock()`（`if (next_hardclock_tsc < cur_tsc) { ff_hardclock(); ff_update_current_ts(); next_hardclock_tsc += interval; }`）；`init_clock` 删除 `rte_timer_subsystem_init/rte_timer_meta_init/rte_timer_init/reset` 四连，改为计算 `interval = hz_tsc / freebsd.hz`（默认 100 → 10ms）；每进程 hardclock 完全独立、零共享状态，同 lcore_id 无冲突。依据：F-Stack 全树 `freebsd_clock` 是唯一 rte_timer 用户（lib/app 仅 ff_dpdk_if.c 两处），不依赖 rte_timer 任何跨核/同步特性。改动点：`ff_dpdk_if.c` init_clock/init_clock_worker/main_loop 三处。对 `graceful_reload=0` 等价生效（自驱与挂槽行为等价），需回归 timer 精度（RTO/keepalive）。
12. **应用 mempool 分代际**（v1.7 据 2026-08-24 人工决策）：新旧进程**同 lcore_id** 时 mempool per-lcore cache 竞态——应用侧分配（TX 发包 `ff_mbuf_get` 的 `rte_pktmbuf_alloc(pktmbuf_pool)`、dispatch clone `pktmbuf_deep_clone`、ff_ref_pool 等）改为**分代际 mempool**：G_old 用第一代（现 `pktmbuf_pool[socketid]`），G_new 用第二代（primary 在 reload 触发时创建 `mbuf_pool_%d_gen2` 或 init 期预建，G_new secondary lookup）；mbuf 自带 `m->pool` 指针，跨进程流转后 `rte_pktmbuf_free` 自动回正确 pool。**cache 竞态处理（v1.7 已定）**：mempool 的 `local_cache[lcore_id]` 以 lcore_id 索引，同 lcore_id 两代进程即使在不同 pool 内仍会在同号 cache 槽竞态（RX 共享 pool 的 free + dispatch 跨代 free）→ **叠加方案 A：`graceful_reload` 部署形态下 `pktmbuf_pool` 创建时 `cache_size=0`**（ff_dpdk_if.c:633-634 的 MEMPOOL_CACHE_SIZE→0），alloc/free 全走 common pool 无锁 ring（多进程安全）；性能损失以 PT-NR-01 基线对比量化，若实测不可接受则切备选方案 B（`local_cache[]` 索引改 workerid/代际 id，见 §6.6）。

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

- **S3-M1（同队列 + ready 后同期移交 + flow_map 软件分发表）**【v1.6 据 2026-08-21 方案修订：从乒乓双队列段+reta 切流改为同队列+软件切流，同时解决审核致命 1/2/3/4/5/6】：
  - 常驻 slim primary（dispatcher 角色，#1078 已验证：primary 持 EAL/设备/队列 setup 不持数据面，杀掉后 12/12 连接零中断，`docs/primary_slim_spec/10-feasibility-conclusion.md` §1.1）。
  - nginx worker 全部改为 secondary；**proc_id 代际无关固定映射**到同一批 queue（G_new 启动时直接用 G_old 的队列号，不需运行时重算 lcore_conf → `tx_queue_id / rx_queue_list / dispatch_ring` 全部对齐，rss_check/adjust/tbl/thash 四件套不变）。
  - **新旧进程可同核处理**（不占 2N 物理核、不乒乓双队列段）；新旧进程高负载切换瞬间性能需关注（见 RV10）。
  - 新 worker ready（栈 init + listen 完成）后**同期移交队列消费权 + listen**给 G_new（修改 X1：不是末期才移交）：G_new 立即接管新连接（**新配置立即生效**），旧连接 drain 给 G_old。
  - **跨进程互斥原语**（共享内存标记，非 msg ring）保证 G_old 停 poll 后 G_new 才起 poll，规避并发 poll 同一 queue；移交窗口靠 NIC rx ring 缓冲兜底（RX_QUEUE_SIZE 512→4096 放大 8 倍）。
  - **G_new 软件分发表 flow_map**（reload 窗口生效，稳态零开销）：flow_map 存 G_new accept 过的连接四元组（SYN accept 时入表，非协议栈 inpcb 表）；drain 期间增量更新；miss（旧连接的包）→ 一律经 dispatch_ring 转 G_old（回调返回目标 queue id → `rte_ring_enqueue(dispatch_ring[port][ret])`，ff_dpdk_if.c:2142-2150；G_old 侧 process_dispatch_ring dequeue 后进本栈，:2223-2233；ring 来的包不再进回调，:2100，无循环）；排空确认后关闭 flow_map 回稳态。
  - **ARP/NDP 等协议包处理**：reload 窗口内，ARP/NDP 等协议包在转给 G_new 协议栈处理的同时，**额外 clone 一份转发给所有 G_old 进程**（原有 clone 给其他 G_new 和 KNI 的逻辑不变）——确保 G_old drain 期间邻居表正常。
  - G_old 继续跑 ff_run drain 存量连接，完成后退出；G_new 感知排空（共享内存标记 + SIGCHLD 确认）后关闭 flow_map、进入稳态成为下一轮的「老 worker」。
  - reload 防重入：上一批老 worker 排空前，master **拦截（拒绝）新的 reload 请求**并记日志。
  - **reta 不改、不依赖 NIC RSS 能力**：virtio 与物理网卡均可用（无需 guest 侧 RSS 能力、无需 set_rss_table 运行时改造、不破坏 ff_rss_check 不变量、不配 2N 队列不丢半流量）。
- **S3-M2（可选演进，dispatcher 中心化）**：把「每 worker 独占队列」改为 slim primary 统一收包 + 流表分发（worker 变纯 ring 消费者）——即 VPP/VCL app_listener workers bitmap 同构（R-A §2.2）+ 旧 iWiki dispatch 思想的现代化（避开同核共存，因 dispatcher 与 worker 分核）。是否演进取决于 M1 转发路径的实测开销。

**对 8 项障碍的覆盖**（按 S3-M1）：

| 障碍 | 覆盖 | 说明 |
|---|---|---|
| 1 两段串行空窗 | 解决 | 回退为原生顺序：新 worker 起（secondary attach 常驻 primary，无 primary 竞争）→ 同期移交队列+listen → 旧 drain |
| 2 listening fd 跨进程 | 回避 | 每 worker 栈内自建 listen（栈隔离天然允许多代际 listen 同 IP:port，P-D §3.5）；新连接归属由同期移交+flow_map 控制，无需 fd 传递 |
| 3 TCP 连接无迁移 | 不迁移 + drain 保障 | 旧连接包经 flow_map miss → dispatch_ring 显式送达 G_old，drain 期 timer 正常（G_old 活着跑 ff_run） |
| 4 primary 单点 | 解决 | primary=slim dispatcher 常驻；worker0 不再硬编码 primary（改 ngx_ff_module.c:183-187 与 ngx_process_cycle.c:1117-1121）；proc_id 代际无关固定映射消除乒乓代际 proc_id 重合（审核 B-1） |
| 5 respawn/时序脆弱 | 解决 | 原 500ms sleep/15s sem 时序被显式 ready 协议取代 |
| 6 master 不在数据面 | 重新分工 | master 编排（nginx 语义层）+ primary 提供原子原语（互斥标记/队列状态），master 仍不碰 ff fd |
| 7 RSS 静态映射窗口 | 解决（同期移交+互斥） | 互斥标记保证 G_old 停 poll 后 G_new 才起 poll（队列始终有主，无空窗）；reta 不改 → ff_rss_check 不变量不破坏（审核 B-2 消解） |
| 8 定时器随进程消亡 | 解决（需实测） | 新旧进程同核但不同 lcore_id（proc_id 代际无关但 lcore_id 仍需不同，DPDK 硬禁令）→ `priv_timer` 不同槽天然隔离；drain 期 G_old timer 持续驱动 |

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

**v1.4 据 X2 增补——virtio/云主机场景的推荐定位**：S4 形态（多实例蓝绿轮换）在 **virtio/云主机场景**下恰好完全没有 S3 的 reta/queue 共享/syncache/ARP 等障碍（两实例各自 N 队列、各自 file_prefix、不共享任何 state、不需要 reta/queue start-stop/跨代 ring、无不可观测门禁），且复用 F-Stack 已有能力（`file_prefix` 已坐实：ff_config.c:1044/1193/1236、Release Note:299）。**在 virtio/云主机场景推荐作为首选方案**（S3 进程内 reload 在该场景依赖的 reta/queue 切流原语不可用，详见 §6.4 适用范围与网卡能力矩阵）。硬前提：上游撤流能力（LB/consul/etcd/手动摘节点）+ 独立网卡或 VF（或同机双 VIP + 路由）+ 双倍资源 + 业务无单机粘性状态；不适用：单机无 LB/单网卡场景。

### 3.5 组合关系说明（S2+S3、S1→S3-M2）

- **S2 与 S3 不冲突、可并行**：两者是两条接入产品线（ld_preload 零改动接入 vs app/nginx 源码集成）。S3 的 dispatcher 控制面协议（ready/切流/队列状态消息）设计可为 S2 的 fstack 实例管理（sc 动态注册、实例重生）复用经验；R-A §6.3-3 已指出 FF_MULTI_SC 静态 scs 数组向「动态注册/注销 worker」演进的方向。
- **S1 → S3-M2**：S1 的 dispatch 中间层思想由 S3-M2 现代化承接——dispatcher 仍持有分发权，但 (a) dispatcher=slim primary 分核常驻（不再同核共存）；(b) 流表只管「新连接去向 + 旧连接钉住」，不维护全量 TCP 状态镜像；(c) mempool/nice/timer 三大同核难题因分核而消失。
- 不引入额外新组合方案：S2+S3 深度耦合（如 nginx 经 ld_preload 接入 S3 dispatcher）会使两条线的问题空间叠加（exec hook 缺口 + 切流协议），无证据支持其收益，不如各自演进。

## 4. 对比矩阵与分档结论

### 4.1 对比矩阵（定性评级 + 一句话依据）

| 维度 | S1 旧方案复活 | S2 ld_preload | S3 原生演进（M1/M2） | S4 双实例热备 |
|---|---|---|---|---|
| D1 无损性 | 中高：dispatch 表切流，但依赖同核共存稳定性（未闭环） | 高：stack 常驻，HUP 对齐内核语义 | v1.6 高（同队列+互斥移交+flow_map 转发兜底，reta 不改不破不变量）；M2 高（结构性） | 高（ready 前不切流） |
| D2 连接语义 | 高：全局表+drain 退出条件 | 中：原生 graceful close（存量连接被关闭而非服务到自然结束——与内核 nginx 一致，但对齐基线 1 的弱化形态） | 高：drain 期旧连接收包路径显式保障（flow_map miss → ring 转 G_old）+ ARP/NDP clone + timer 持续 | 高 |
| D3 改动面 | 极大：全量重写（原码未开源）+ 驱动层改造 | 小：nginx 零改动；缺口集中在 adapter 侧（exec hook/回收） | v1.6 中：nginx 适配层回退原生顺序 + lib 新增 flow_map/互斥原语/ARP clone；有 primary_slim PoC 基础；不再依赖 reta 改造（消除 rss_check 四件套改造） | 大：双实例管理 + 分发层全新 |
| D4 主线兼容 | 低：孤儿路线，同核共存与主线（native_mt 分核演进）方向相反 | 中：独立产品线，与主线无耦合也无承接 | v1.6 高：直接承接 primary_slim；timer 隔离受益于 native-mt `__thread` 改造；与 zc_stack 正交；不再依赖 reta 能力（virtio 也可用） | 低：双倍栈实例与 share-nothing 主线相悖 |
| D5 性能 | 中：稳态每包经 dispatch 一跳（旧实测 58 万 QPS 为 18.11 单来源数据） | 低-中：每 socket 调用走 IPC，近双核占用，8 核后短连接劣于 app 模式 | v1.6 高：稳态零新增开销（flow_map 仅 reload 窗口）；reload 窗口 flow_map 查表开销 + 同核切换瞬间性能需关注（RV10）；M2 中：稳态每包一跳 | 中低：reload 窗口双倍核/内存 |
| D6 运维 | 高复杂：nice/双 IP/驱动参数 | 中：独立 fstack 实例进程 + 环境变量矩阵 | v1.6 中：新增常驻 slim primary + 互斥标记 + flow_map + RX_QUEUE_SIZE 调优 + reload 状态可观测 | 高：双实例生命周期管理 |
| D7 可测试性 | 差：无法增量验证（须一次性做成） | 好：可先在非 nginx 应用验证 adapter，再套 nginx | v1.6 好：M1 可分里程碑增量交付；reload 状态机显式可打点；**virtio 与物理网卡均可验证**（不依赖 reta 能力） | 中：切流逻辑可测，但双实例编排复杂 |

### 4.2 分档结论

| 分档 | 方案 | 理由 |
|---|---|---|
| **推荐** | **S3（M1 先行，M2 视数据演进）**【v1.6 修订：同队列+ready 后同期移交+flow_map，virtio 与物理网卡均可用，不再限于物理网卡】 | 唯一同时满足：结构性前提（队列所有权与 worker 解耦，基线 2）、连接语义对齐（基线 1）、稳态零性能损耗（D5-M1 高）、有已验证 PoC 基础（primary_slim，改动面可控）、与主线演进同向（D4 高）、可增量交付（D7 高）、**不依赖 NIC RSS 能力**（reta 不改，virtio 也可用）。前置依赖：primary_slim 合入 |
| **备选** | **S2（限定场景）** | 适用于「存量应用零改动接入 + 非 proxy 场景 + 可接受 IPC 性能折损」的独立产品线；HUP 语义天然对齐内核 nginx，缺口（exec/回收）收敛在 adapter 侧。**不建议作为 F-Stack nginx（app 源码集成主线）的 reload 解法**，但建议与 S3 并行推进其缺口修复 |
| **virtio/云主机场景推荐**【v1.4 据 X2 增补】 | **S4 多实例蓝绿轮换** | virtio 场景下 S3 的 reta/queue 切流原语不可用（§6.4）；S4 在该场景完全没有上述障碍、复用 file_prefix 已有能力、零代码。硬前提：上游撤流 + 独立网卡/VF + 双倍资源 + 业务无单机粘性。不适用：单机无 LB/单网卡场景，该场景如必须 `nginx -s reload` 无损，见 §6.5 形态 V 降级路径（未来工作） |
| **不推荐（独立实施）** | **S1** | 同核共存三支柱（mempool 隔离/nice 调度/timer 隔离）在 24.11.6 全部需重做且 timer 未闭环（E-C §6.2）；原码未开源。其 dispatch 思想由 S3-M2 承接 |

## 5. 推荐方案 S3 关键设计

### 5.1 进程/队列/listening fd/连接 四层所有权模型

| 层 | 所有者 | reload 时行为 | 依据 |
|---|---|---|---|
| L1 EAL/设备/mempool/ring/队列 setup | **slim primary（dispatcher），常驻** | 不动（杀 primary 数据面零影响已实测：`docs/primary_slim_spec/10` §1.1 E3b/E3c；但 primary 只能常驻不能复活，E10） | P-D §3.2；primary_slim_spec 03 §III |
| L2 队列消费权（rx poll） | worker 级，可移交 | 新 worker ready 前：旧 worker 持续 poll（队列始终有主，无空窗）；ready 后**同期移交**（跨进程互斥标记保证 G_old 停后 G_new 才起），旧连接包经 L4 flow_map miss → dispatch_ring 转发兜底 | ff_dpdk_if.c:508-538（lcore↔queue 映射）；基线 2/3；proc_id 代际无关固定映射 |
| L3 listening socket | **各 worker 栈内自建**（保持现状） | 不跨进程传递：栈隔离天然允许多代际 worker 并存 listen 同 IP:port（每进程独立 FreeBSD 栈实例各自 bind/listen 互不冲突，P-D §3.5）；新连接归属由 L2 同期移交决定（G_new 接管 listen） | P-D 障碍 2 的回避式解法；R-A §6.3-2 的对照（VPP 用 app_listener 单点，F-Stack 用栈隔离多 listen——路线差异点，功能等价） |
| L4 TCP 连接 | worker 私有，**不迁移** | G_old drain：其队列/RTO/keepalive 持续驱动；ready 后同期移交队列后，到达 G_new 的旧连接包经 **flow_map miss** → dispatch_ring 转发回 G_old（现成机制）。**flow_map 窗口限定**：G_new ready 同期移交后注册 flow_map、排空确认后关闭——稳态零开销；flow_map 只记本代际新流（SYN accept 入表），miss 一律转 G_old（第 2 节语义 6）；ARP/NDP 等协议包额外 clone 给所有 G_old（第 2 节语义 9） | 基线 1；ff_dpdk_if.c:2105-2150/:2223-2233；P-D §3.5（dispatch 回调 nginx 未用——本方案启用） |

设计取舍说明（与 VPP 的有意差异）：VPP 把 listen 收敛到栈侧单点（app_listener + workers bitmap，R-A §2.2），F-Stack 不照搬——fd 是进程内索引（P-D §2.4），跨进程传递无意义；「多代际栈隔离 listen + 数据面切流」在功能上等价于 workers bitmap（决定「谁收新连接」的是 reta/分发层而非 listen 对象本身），改动面小得多。

### 5.2 reload 时序（文字版时序图，HUP）【v1.6 改写：同队列+同期移交+互斥+flow_map】

前置状态：slim primary 常驻（PID_P）；旧 worker 代际 G_old（N 个 secondary，占 lcore 段 A）；G_new 使用**同批 queue**（proc_id 代际无关固定映射）。

```
T0  master 收 HUP
    ├─ 【防重入】若上一轮 reload 未完成（存在未排空的 G_old）→ 拒绝本次
    │   HUP 并记日志（不支持快速连续 reload，第 2 节语义 6）
    ├─ ngx_init_cycle 重读配置（语法错→回滚，对齐内核 HUP，R-B §2.2）
T1  master fork 新 worker 代际 G_new（NGX_PROCESS_JUST_RESPAWN）
    ├─ 每个 G_new worker: ff_mod_init(--proc-id, secondary)
    │   secondary attach 到常驻 primary——无 primary 竞争（对比现状障碍 4）
    ├─ G_new worker 使用 G_old 同批 queue（proc_id 代际无关固定映射，
    │   tx_queue_id/rx_queue_list/dispatch_ring 全部对齐，rss_check 不变）
    ├─ G_new worker 与 G_old 同核处理（不占 2N 物理核，第 2 节语义 8）
    ├─ master 不再需要 15s sem 等 primary 就绪（primary 一直在）；保留 ready 上报等待
T2  G_new worker 各自完成：ff_freebsd_init 栈实例 → ngx_open_listening_sockets
    │   （各自栈内 listen 同 IP:port，与 G_old 并存，栈隔离保证不冲突）
    └─ 经控制通道向 master 上报 READY
T3  master 确认全部 G_new READY → 触发同期移交（队列消费权 + listen）
    ├─ 【跨进程互斥原语】（共享内存标记，非 msg ring，第 2 节语义 7）：
    │   ① G_old 停止 poll（设置停 poll 标记 + 确认已停）
    │   ② G_new 确认 G_old 已停 poll 后起 poll（互斥保证不同时 poll 同一 queue）
    │   ③ 移交窗口靠 NIC rx ring 缓冲兜底（RX_QUEUE_SIZE 512→4096 放大 8 倍）
    ├─ G_new 同期接管 listen（新连接归 G_new，新配置立即生效，第 2 节语义 7）
    └─ G_new 注册 flow_map（软件分发表，第 2 节语义 6）：
        收到包 → 解析四元组 → 查 flow_map
        ├─ SYN（新连接）→ 本栈 accept → 四元组入 flow_map ✓
        ├─ flow_map 命中（本代际已建连接后续包）→ 本栈处理 ✓
        └─ flow_map miss（旧连接的包）→ 经 dispatch_ring 转 G_old ✓
    ├─ 【ARP/NDP 等协议包处理】（第 2 节语义 9）：
        ARP/NDP 等协议包在转给 G_new 协议栈处理的同时，
        额外 clone 一份转发给所有 G_old 进程（原有 clone 给其他 G_new
        和 KNI 的逻辑不变）
T4  G_old worker 收到 master 的 graceful shutdown（原生语义）
    ├─ 各自栈内 close listening（只影响自己栈，G_new 的 listening 不受影响）
    ├─ 停止 accept，继续跑 ff_run：drain 存量连接
    │   （存量连接后续包经 G_new flow_map miss → dispatch_ring 转发回来）
    │   timer 持续驱动（G_old 活着，freebsd_clock 在自己 lcore 槽）
    │   ARP/NDP 邻居表正常（T3 clone 保证）
    └─ drain 完成（连接数=0 或 no_timers_left）→ 进程退出
T5  master 收 G_old SIGCHLD（且确认排空：连接数=0 + DRAIN_DONE）→ reload 完成
    ├─ 通知 G_new：关闭 flow_map → G_new 进入稳态，成为下一轮 reload 的
    │   「老 worker」（防止性能退化；此后稳态所有包不过 flow表，第 2 节语义 6）
    └─ G_new 已可再次接受 reload（防重入拦截随排空确认解除）
异常分支：
- T2 前 G_new 任一 worker 起不来/ready 超时 → master 放弃本轮（G_old 未受任何
  影响，服务继续）——对齐内核 HUP 配置失败回滚语义
- T3 移交失败（G_old 未确认停 poll / G_new 起 poll 超时）→ 放弃本轮（G_old
  继续服务，G_new 退出）——互斥标记保证不会并发 poll
- drain 挂起（长连接不退）→ 增补 shutdown timer（P-D §4 补充事实：F-Stack 版
  恰好缺失 ngx_set_shutdown_timer，需补回）兜底强退
```

USR2 时序：与 HUP 共用 T1-T5 机制，差异仅在 master 自身也经 exec 换代——master 本就无任何 ff 状态（P-D §2.2：master 不 ff_init、socket() 未劫持走内核），exec 是纯内核操作；新 master fork 的 worker 全是 secondary（T1 机制），常驻 primary 不受影响。**这使 #12 结论 "exec() is not supported"（R-B §3.7：DPDK 资源不能跨 exec 存活）在 S3 下不再阻塞 nginx USR2**——该限制约束的是 DPDK 进程自身的 exec，而 nginx master 不是 DPDK 进程。

### 5.3 与 nginx HUP/USR2 语义的映射

| nginx 原生语义（R-B §2.1/§2.2） | S3 映射 |
|---|---|
| HUP：新 worker 先起 → 旧 worker 关监听继续服务存量 → 排空退出 | 完全对齐（T1→T4）；「关监听」= 各自栈内 close，无跨进程影响 |
| HUP：配置失败回滚 | T2 前失败即回滚（G_old 未动） |
| USR2：旧 master 不关监听、保留回退能力 | 数据面等价物 = G_old drain 期间 QA/转发路径持续可用；回退 = T3 前可随时放弃 G_new |
| USR2：新旧 worker 并行 accept | reta 切流后 G_new 收新连接；切流前 G_old 收——「并行 accept」退化为「有序接管」（更优：避免双代际同时 accept 的连接分布碎片化） |
| WINCH/QUIT：worker 优雅/强制退出 | drain 语义保留；补回 ngx_set_shutdown_timer |

### 5.4 需要新增的 ff_api / config.ini / ff_msg 接口面（设计清单，非实现承诺）

1. **ff_api 新增**（lib 侧，最小集）【v1.6 改写】：
   - `ff_flow_map_lookup(four_tuple)` / `ff_flow_map_insert(four_tuple)` / `ff_flow_map_close()`：**软件分发表 flow_map**（替代 v1.0-v1.5 的 `ff_conn_owner_query`）——存 G_new accept 过的连接四元组（SYN accept 时 insert，非协议栈 inpcb 表）；drain 期间增量更新；miss → 经 dispatch_ring 转 G_old；排空确认后 close 回稳态。窗口语义（第 2 节语义 6）：仅 reload 窗口被调用，稳态零调用。
   - `ff_queue_handover_mutex(port, queue, from_gen, to_gen)`：**跨进程互斥原语**（共享内存标记，非 msg ring）——G_old 设停 poll 标记 + 确认已停 → G_new 确认后起 poll；保证不同时 poll 同一 queue（第 2 节语义 7）。
   - `ff_arp_ndp_clone_to_old(m, port)`：ARP/NDP 等协议包 clone 给所有 G_old（第 2 节语义 9）——原有 clone 给其他 G_new 和 KNI 的逻辑不变（ff_dpdk_if.c:2161-2183），新增 clone 给 G_old 分支。
2. **ff_msg 扩展**（控制通道，复用现有 msg ring 机制，P-D §3.3）：新增 FF_RELOAD 消息族——READY 上报、移交请求/应答、drain 进度上报、**drain 完成确认（DRAIN_DONE：触发 G_new 关 flow_map 回稳态）**、**reload 拒绝（REJECT：防重入）**。注意：移交互斥用共享内存标记轮询而非 msg ring（第 2 节语义 7），msg ring 仅用于 READY/DRAIN_DONE/REJECT 等非实时关键路径。
3. **config.ini 新增**（[dpdk] 段）：
   - `primary_slim = 1`（primary_slim_spec 已设计，V2/V4/V5 校验链沿用）。
   - `graceful_reload = 1`（总开关，默认 0 时行为完全回退现状——0 回归原则）。
   - `rx_queue_size = 4096`（从默认 512 放大 8 倍，增大移交窗口缓冲深度，ff_memory.h:43）。
   - proc_id 代际无关固定映射配置（替代 v1.0-v1.5 的乒乓 lcore 段约定）。
4. **nginx 适配层改造**（app/nginx-1.28.0）：
   - `ngx_process_cycle.c:223-237` 两段式 reload 块整体移除/条件化（graceful_reload=1 时走原生顺序：fork G_new → 等 READY → 同期移交 → G_old QUIT）。
   - `ngx_ff_module.c:169-187` + `ngx_process_cycle.c:1117-1121`：worker0 不再 primary，全部 secondary；proc_id 改为代际无关固定映射（消除乒乓代际 proc_id 重合，审核 B-1）。
   - 补回 worker QUIT 分支缺失的 `ngx_set_shutdown_timer`（P-D §4 补充事实）。
   - reload 编排状态机（T0-T5 显式状态 + 打点），满足第 1 节否决性判据。

### 5.5 与既有演进线的关系

| 演进线 | 关系 |
|---|---|
| primary_slim（#1078） | **直接依赖**：slim primary 是 S3 的 L1 常驻基础；其生产实现已过全部测试（`docs/primary_slim_spec/10` L4 闭环）。S3 是 primary_slim 的自然延伸（从"primary 稳定性"到"worker 可独立重生"） |
| native_mt（单进程多线程） | **受益+互斥沿用**：native-mt 已把 freebsd_clock 改 `__thread`（E-C §5.5），per-lcore timer 槽结构为多进程分核并存提供隔离基础；S3 沿用 thread_mode=0 与 primary_slim 的互斥校验（primary_slim_spec V4） |
| zc_stack（零拷贝） | **正交**：零拷贝收包路径不影响队列所有权模型；回调判定发生在包分发层，与 mbuf 来源无关（需在 M1 测试中纳入 zc 场景回归） |
| DPDK 23→24 升级线 | **依赖其补丁**：`rte_timer_meta_init`（62f1c34df）已 re-apply 到 24.11.6（commit 14355bf7b，E-C §5.1 表）；S3 的分核布局进一步降低对该补丁场景（同 lcore 槽残留）的暴露 |
| ld_preload ring（S2） | **并行独立**：S3 的 reload 控制消息协议设计（5.4-2）可复用于 fstack 实例的动态 sc 管理（R-A §6.3-3 方向）；无代码耦合 |
| 旧 iWiki 方案（S1） | **思想承接**：dispatch 层 → S3-M2；mempool/nice/同核三难题 → 分核布局后消失 |

## 6. 风险清单与未坐实项

### 6.1 需运行时验证（RV，静态分析无法定论）

| # | 项目 | 验证方法建议 |
|---|---|---|
| RV1 | N worker + 1 slim primary 多 secondary 并存（24.11.6）稳定性：mempool 跨进程并发（不同 lcore cache）、EAL 资源、msg_ring 广播 | 双代际进程组长时间共存压测 + ff_top/ff_traffic 观测 |
| RV2 | ~~reta 运行时更新~~ v1.6 删除（reta 不改、不依赖 NIC RSS） | — |
| RV3 | **同期移交互斥正确性**（v1.6 改写）：跨进程互斥标记（共享内存）保证 G_old 停 poll 后 G_new 才起 poll；移交窗口靠 NIC rx ring（RX_QUEUE_SIZE 4096）缓冲兜底；残余风险为 virtqueue 数据结构并发损坏（非业务语义、静态无法定论）；virtio 无 imissed 不可观测 | 高速率注入 + 移交瞬间丢包计数（物理网卡 imissed / virtio 端到端业务指标） |
| RV4 | dispatch_ring 转发旧连接包的吞吐/时延：ring 容量（DISPATCH_RING_SIZE 2048）在 drain 高峰是否成为瓶颈 | 构造 80% 流量在旧连接的 reload 压测 |
| RV5 | flow_map 查表开销【仅 reload 窗口】：稳态零开销（flow_map 已关闭）；reload 窗口内四元组解析 + flow_map 查找在 10G 线速小包下的 CPU 占比 | reload 窗口内/外 pps 对比；验证排空确认后 flow_map 查表计数停止增长 |
| RV6 | 不同 lcore 的多进程 timer 槽隔离实测 | 双代际共存期间观测 RTO/keepalive 精度 |
| RV7 | 多代际栈隔离 listen 同 IP:port 的实际行为 | 双代际并存期并发 SYN 压测 |
| RV8 | KNI 启用场景：runtime owner 与双代际 worker 的交互（审核 Q13：KNI owner 固定 proc_id，代际交替后 owner 落已退代际，需解决） | enable_kni=1 的 reload 回归 |
| RV9 | 端到端门禁：带流量循环 reload + 无死锁无 crash + 新连接错误数 0 + 存量连接全部 drain 成功 | ab 持续流量 + 循环 reload（v1.6 修订节拍：每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次，≥100 次；原「每 2~5s reload、≥1000 次」与防重入语义+25s 初始化不可同时成立） |
| RV10 | **同核处理新旧进程切换瞬间性能**（v1.6 新增，X3 关注点）：新旧进程同核时高负载切换瞬间的流量/丢包/CPU 抢占情况；drain 期各得约 50% 有效算力 + 上下文切换/cache 抖动的影响 | 高负载 reload 压测 + 切换瞬间 pps/CPU 观测 |

### 6.2 需设计评审（DR，机制选择需评审定案）

| # | 项目 | 备选与倾向 |
|---|---|---|
| DR1 | reload 编排者：nginx master（语义层自然）vs slim primary（全局视图） | 倾向 master 编排 + primary 提供原子原语（互斥标记/队列状态），保持数据面组件无业务语义 |
| DR2 | 旧连接归属判定：flow_map 查表（v1.6 主路径）vs reload 握手时导出四元组快照表 | 已定：flow_map 查表（SYN accept 入表，miss 转 G_old，窗口化）；性能不足再退化快照（RV5 数据支撑） |
| DR3 | ~~reta 切流 vs 队列移交~~ v1.6 删除（reta 不改，同期移交+flow_map 为主路径） | — |
| DR4 | reload 控制通道载体（v1.6 已定）：移交互斥用共享内存标记（非 msg ring），READY/DRAIN_DONE/REJECT 用 msg ring | 已定：分两类通道 |
| DR5 | ~~乒乓 lcore 配置~~ v1.6 删除（不再乒乓，同核处理+proc_id 代际无关固定映射） | — |
| DR6 | 异常回退完备性：新 worker 部分失败、primary 被 kill、drain 挂起强退、T3 移交失败回退 | 状态机每阶段定义回退目标态 |
| DR7 | M2（dispatcher 中心化）启动判据：reload 窗口内 flow_map 开销 + drain 期 P99 劣化超阈值时立项 | 评审定阈值 |

### 6.3 同核处理新旧进程的性能考量（v1.6 替代 v1.4 DISC-1，因不再乒乓双队列段）

v1.6 方案不再使用乒乓 2N 队列段，新旧进程同核处理（proc_id 代际无关固定映射到同一批 queue）。性能关注点：

- **DPDK 硬禁令仍生效**：primary/secondary 禁止共用同一 logical core（multi_proc_support.rst:169-172，理由 mempool per-lcore cache 损坏），故新旧进程仍需不同 lcore_id（可经 `--lcores` 亲和到同一物理核）。
- **同物理核的代价**（X3 关注点，RV10 专项验证）：DPDK 轮询线程 100% 忙等，两代际 lcore 亲和同一物理核时 drain 期各得约 50% 有效算力 + 上下文切换/cache 抖动 + 正反馈延长 drain。**新旧进程高负载时切换瞬间的流量/丢包情况**是核心关注点。
- **定位**：默认形态（v1.6 主路径）；如物理核充足可给新旧进程分配不同物理核以消除切换开销，但非必需。

### 6.4 适用范围（v1.6 修订：reta 不改，virtio 与物理网卡均可用）

v1.6 方案不依赖 reta 切流原语，故不再有 v1.4/v1.5 的 NIC 能力矩阵限制：

| 部署环境 | S3 v1.6 可行性 | 说明 |
|---|---|---|
| 物理网卡（ixgbe/i40e/mlx5/ice 等） | ✅ | reta 不改，rss_check 不变；无 NIC RSS 能力依赖 |
| virtio/云主机 | ✅ | 同上——**v1.6 关键优势**：virtio 也可用（reta_size==0 不影响，因不调用 set_rss_table） |
| 启用 FF_FLOW_ISOLATE/FF_FDIR 的部署 | ✅ | 不调用 set_rss_table，无编译期互斥 |

**M1 准入前置依赖**：primary_slim 合入。v1.5 的「取得支持 reta 的物理网卡环境」前置依赖已取消（v1.6 不依赖 reta）。`graceful_reload=1` 的降级语义保留（当环境不支持多队列时退化为有损 reload），但 v1.6 方案在支持多队列的 virtio/物理网卡上均可做无损 reload。

### 6.5 v1.6 对 v1.4/v1.5 旧内容的废弃说明

以下 v1.4/v1.5 增补的内容在 v1.6 方案修订后已**废弃**（保留本节供审计追溯，不再作为设计依据）：

- ~~§6.3 DISC-1（乒乓 lcore_id 亲和物理核）~~：v1.6 不再乒乓双队列段，DISC-1 的前提（2N 队列段浪费 50% 物理核）不存在。同核处理的性能考量见新版 §6.3。
- ~~§6.4 适用范围与网卡能力矩阵（reta 依赖）~~：v1.6 不依赖 reta，virtio 与物理网卡均可用。新版 §6.4 简化为环境能力说明。
- ~~§6.4.1 无 RSS 有损 reload 兜底~~：v1.6 不依赖 reta，无「reta 静默成功伪装」黑洞。`graceful_reload=1` 的降级语义保留（不支持多队列时退化为有损），但触发条件从「reta_size==0」改为「不支持多队列」。
- ~~§6.5 形态 V（软件切流，未来工作）~~：v1.6 主路径本身就是「同队列+软件切流（flow_map）」，形态 V 的机制已并为主路径。不再作为单独的未来工作。

### 6.6 网卡 RX mempool 同 lcore_id 共存（v1.7 2026-08-24 已定：方案 A 主 + 方案 B 备选）

**现状**（代码事实）：`pktmbuf_pool[socketid]`（ff_dpdk_if.c:149，per-NUMA 一个）由 primary 创建（:616-635，`rte_pktmbuf_pool_create(..., MEMPOOL_CACHE_SIZE, ...)`）、secondary lookup 共享（:638）；**RX queue 在 init 期绑定该 pool**（`rte_eth_rx_queue_setup(..., mbuf_pool)` :1141）且**运行时不可更换**（virtio 无 queue stop/setup）。RX 收包 refill、TX 发包 alloc（:2563/:2705）、dispatch clone（:2172/:2188）全部走同一 pool。

**同 lcore_id 竞态面**（v1.7 调研）：
1. RX refill：两代进程的 `rx_burst` 内部 `mempool_get` → `local_cache[L]` 同槽竞态
2. TX/clone alloc：`rte_pktmbuf_alloc` → `local_cache[L]` 同槽竞态
3. 跨代 free：dispatch 转发的 mbuf 被 G_old 消费后 `rte_pktmbuf_free` → 对端 pool 的 `local_cache[L]` 同槽竞态
4. **应用 mempool 分代际（语义 12）不能独立消除**：RX mbuf（共享第一代 pool）的 free 与 dispatch 转发 mbuf 的跨代 free 仍落入同号 cache 槽

**候选方案与决策**（v1.7 2026-08-24 人工拍板，对照 iWiki 4015929276/E-C §6.1「网卡驱动 mempool：关闭 cache + 缩小冲突域 + CAS，实测性能损失很小」）：
- **方案 A（已选定，iWiki 同路）**：RX pool 共享第一代 + 创建时 `cache_size=0`（:633-634 的 MEMPOOL_CACHE_SIZE→0）→ 所有 alloc/free 走 common pool 无锁 ring（多进程安全）；代价：稳态也失去 per-lcore cache 加速，性能损失以 PT-NR-01 基线对比量化（iWiki 18.11 实测「很小」，24.11 virtio 待复测）
- **方案 B（备选，仅当 A 实测不可接受时启用）**：保持 cache 但把 `local_cache[]` 索引从 lcore_id 改为 workerid/代际 id（改 DPDK `rte_mempool.c` 或 F-Stack 侧 wrapper）→ 稳态保留 cache 性能，reload 期天然分槽；改动面在 DPDK 层（F-Stack 本地补丁，升级 DPDK 需重做）
- ~~方案 C（双 pool 运行时切换）~~：TX/clone 侧可行但 **RX 侧不可行**（queue 绑定不可换）→ 不能独立成立，否决

## 7. 与目标语义的对照验收（推荐方案自检）

| 目标（第 2 节） | S3-M1 达成方式（v1.6） | 残余风险 |
|---|---|---|
| 1 新连接零丢失 | 同期移交后 G_new 接管 listen + flow_map 记录新 SYN；互斥标记保证队列始终有主 | RV3（移交互斥正确性/缓冲） |
| 2 存量连接完整 drain | G_old 活着跑 ff_run + flow_map miss → ring 转发兜底 + ARP/NDP clone + timer 持续 | RV4/RV6 |
| 3 配置失败回滚 | T2 前失败 G_old 未动；T3 移交失败回退（互斥标记保证不并发 poll） | 设计保证（DR6） |
| 4 HUP+USR2 均支持 | 机制同源；master 无 ff 状态可安全 exec | USR2 路径需专项测试 |
| 5 工程意义无损 | 门禁 = RV9 错误数 0（v1.6 修订：≥100 次，每 5s 检测排空后 reload） | 接受 HAProxy 文档级边界（R-B §2.2） |

## 8. 单来源声明

本设计引用的证据中，以下为**单来源**（未经第二独立来源交叉坐实，使用时须注意强度）：

1. **iWiki 4015929276 全部内容**（旧方案四大改造、58 万 QPS、10h/200 次 reload/112 timeout 数据）：仅此来源（E-C 考证员经 iwiki-cli 获取）；orange30 原始代码从未开源（E-C §8-U5）。
2. **Facebook LPC 2021 细节**（socket takeover/sk_reuseport/30x 不丢）：中文译文单来源（R-B §6-3：原 slides 未取到）。
3. **VPP issue #3547 的根因分析**（vcl/vls worker index 错位连环 crash）：报告者个人分析，维护者未确认（R-A §4.3）。
4. **primary_slim PoC/生产数据**（12/12 零中断、E2e/E10 等）：docs/primary_slim_spec 本地实测一手文档，但**非本团队成员复测**（R-A §6.2 对其的引用是转述）。
5. **VSAP 补丁内容**：仅 README 描述级，补丁正文未读（R-A §7-2）。
6. **AsterNOS-VPP**：营销内容，本设计未采用为证据（R-A §7-8）。
7. **6WIND 本地应用路径**：introduction 页推断（R-B §3.3，标注推断）。
8. P-D/P-E 的全部代码行号事实：本团队一手探测（可回查复核，本设计第 0 节已抽查四处一致）。
9. R-A/R-B 对 DPDK 24.11.6 中 reta 动态更新、多 secondary 并存行为的推论：静态结构推断，本团队未运行时验证（对应 RV1/RV2）。

---

**核心结论**：推荐 S3（v1.6：同队列 + ready 后同期移交队列+listen + flow_map 软件分发表 + 跨进程互斥 + ARP/NDP clone，承接 primary_slim），S2 为并行备选产品线，S1/S4 不独立实施（思想/原则分别并入 S3-M2 与 S3 时序）。落地拆解见 [07-里程碑](07-milestones.md)，测试与验收见 [08-测试计划](08-testing.md)。
