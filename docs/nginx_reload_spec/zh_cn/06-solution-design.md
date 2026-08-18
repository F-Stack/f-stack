# 06 方案设计：候选方案对比与推荐方案 S3 关键设计

| 项 | 值 |
|---|---|
| 文档编号 | 06 |
| 标题 | F-Stack Nginx 无损 reload 候选方案对比（S1~S4）+ 推荐方案 S3 设计 |
| 版本 | v1.0 |
| 日期 | 2026-08-18 |
| 状态 | 待人工审计 |
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
| D7 | 可测试性 | 能否套用 VPP 社区验证模式（R-A §6.3-7：带流量循环 reload 数千次 + 不死锁不 crash + 错误数 0 作门禁）；能否增量交付、异常场景可注入 |

补充一条否决性判据（来自 E-C §9-1 与 R-A §6.4 教训）：reload 逻辑必须是**显式的、可观测的状态机**（每阶段可打点/可回退），不能散落在 fork/signal hook 里的隐式逻辑——VPP #3547/#3645 三年未修即前车之鉴（R-A §4.3/§6.4）。

## 2. 目标语义定义（"无损"的确切含义）

依据基线 1/2 与 R-B §2.2（内核 HUP 语义）、§2.1（USR2 语义），本设计的目标语义定义为：

1. **新连接零丢失**：reload 全程任意时刻到达的 SYN 都有进程收下并 accept（窗口内允许短暂排队于 NIC rx ring / 栈 backlog，不允许 RST/丢弃）。
2. **存量连接优雅 drain**：reload 前建立的连接由旧 worker 继续服务至自然关闭（客户端主动断开或 keepalive 超时），drain 期间旧 worker 的 TCP 定时器（RTO/keepalive/延迟 ACK）持续驱动。**不做**跨进程 TCP 状态迁移（业界无先例，R-B §4 P4）。
3. **配置失败可回滚**：对齐内核 HUP（R-B §2.2：配置解析失败回滚旧配置继续跑）。
4. **HUP 与 USR2 均可支持**：HUP 换配置、USR2 换二进制（exec），两者数据面机制同源。
5. **工程意义无损**：接受 R-B §2.2 引 HAProxy 文档的边界——边界条件上 backlog 中的连接仍可能极小概率损失，验收以压测错误数为 0 为门禁而非绝对论断。
6. **流表仅 reload 窗口生效 + reload 防重入**（v1.3 增补语义）：稳态所有数据包**不经过流表**（零额外每包开销）；流表仅在新 worker 初始化完成（READY）后自动生效，至老 worker 排空确认后关闭。流表**只记录新流**的状态；表项 miss（不在流表中）**一律转老 worker**。老 worker 排空后新 worker 感知并关闭流表、进入稳态成为新的「老 worker」（防止性能退化）。**不支持老 worker 排空前的快速连续 reload**：上一批老 worker 排空前，新的 reload 请求被拦截（拒绝并记日志）。

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

- **S3-M1（乒乓核 + 队列切换 + 转发兜底）**：
  - 常驻 slim primary（dispatcher 角色，#1078 已验证：primary 持 EAL/设备/队列 setup 不持数据面，杀掉后 12/12 连接零中断，`docs/primary_slim_spec/10-feasibility-conclusion.md` §1.1）。
  - nginx worker 全部改为 secondary；reload 时新 worker 绑「乒乓」lcore 段（lcore_mask 配 2N 段，稳态用一半、reload 窗口用另一半，新旧 worker **不同核并存**）。
  - 新 worker ready（栈 init + listen 完成）后切换流量：修改 RSS reta（`set_rss_table`，ff_dpdk_if.c:832（定义，内部 :850 调 rte_eth_dev_rss_reta_update）/:1218（既有调用点）已有）把新 flow 导向新队列段（FB "ready 前不切流"原则）。
  - 旧连接兜底（reload 窗口流表）：新 worker READY 后**自动注册** packet_dispatcher 回调（`ff_regist_packet_dispatcher`，ff_api.h:299-303）——流表仅 reload 窗口生效，稳态不注册、零每包开销。流表即本栈连接表的实时查询（`ff_conn_owner_query`）：只有本代际**新建的流**在表中（新 SYN 匹配本栈 listen → 本栈 accept 即隐式入表）；表项 miss（旧连接的包因 reta 重哈希落入新队列）**一律转老 worker**（回调返回目标 queue id → `rte_ring_enqueue(dispatch_ring[port][ret])`，ff_dpdk_if.c:2142-2150；旧 worker 侧 process_dispatch_ring dequeue 后进本栈，:2223-2233；ring 来的包不再进回调，:2100，无循环）。
  - 旧 worker 继续跑 ff_run drain 存量连接，完成后退出；新 worker **感知排空**（控制消息 + SIGCHLD 确认）后**注销回调/关闭流表，进入稳态成为下一轮的「老 worker」**（防止每包判定的性能退化），释放原 lcore 段供下轮 reload 乒乓使用。
  - reload 防重入：上一批老 worker 排空前，master **拦截（拒绝）新的 reload 请求**并记日志——不支持快速连续 reload（属明确不支持项，非未定义行为）。
- **S3-M2（可选演进，dispatcher 中心化）**：把「每 worker 独占队列」改为 slim primary 统一收包 + 流表分发（worker 变纯 ring 消费者）——即 VPP/VCL app_listener workers bitmap 同构（R-A §2.2）+ 旧 iWiki dispatch 思想的现代化（避开同核共存，因 dispatcher 与 worker 分核）。是否演进取决于 M1 转发路径的实测开销。

**对 8 项障碍的覆盖**（按 S3-M1）：

| 障碍 | 覆盖 | 说明 |
|---|---|---|
| 1 两段串行空窗 | 解决 | 回退为原生顺序：新 worker 起（secondary attach 常驻 primary，无 primary 竞争）→ 切流 → 旧 drain |
| 2 listening fd 跨进程 | 回避 | 每 worker 栈内自建 listen（栈隔离天然允许多代际 listen 同 IP:port，P-D §3.5）；新连接去向由 reta/回调控制，无需 fd 传递 |
| 3 TCP 连接无迁移 | 不迁移 + drain 保障 | 旧连接包经 dispatch_ring 显式送达旧 worker，drain 期 timer 正常（旧 worker 活着跑 ff_run） |
| 4 primary 单点 | 解决 | primary=slim dispatcher 常驻；worker0 不再硬编码 primary（改 ngx_ff_module.c:183-187 与 ngx_process_cycle.c:1117-1121） |
| 5 respawn/时序脆弱 | 解决 | 原 500ms sleep/15s sem 时序被显式 ready 协议取代 |
| 6 master 不在数据面 | 重新分工 | master 编排（nginx 语义层）+ primary 提供原子原语（reta 更新/队列状态），master 仍不碰 ff fd |
| 7 RSS 静态映射窗口 | 解决（原子切流） | reta 切换前旧队列始终有主；切换后新队列已 ready；旧连接经转发兜底 |
| 8 定时器随进程消亡 | 解决（需实测） | 新旧 worker **不同 lcore** → `priv_timer` 不同槽天然隔离（共享 memzone 按 lcore 分槽，E-C §5.3 结构 + native-mt 已把 freebsd_clock 改 `__thread`，E-C §5.5）；drain 期旧 worker timer 持续驱动 |

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

**结论要素**：不作为独立方案推荐；其「**ready 前不切流 + 显式切流动作 + 切流可观测**」三原则作为时序设计原则并入 S3（第 5.2 节时序图即按此设计）。

### 3.5 组合关系说明（S2+S3、S1→S3-M2）

- **S2 与 S3 不冲突、可并行**：两者是两条接入产品线（ld_preload 零改动接入 vs app/nginx 源码集成）。S3 的 dispatcher 控制面协议（ready/切流/队列状态消息）设计可为 S2 的 fstack 实例管理（sc 动态注册、实例重生）复用经验；R-A §6.3-3 已指出 FF_MULTI_SC 静态 scs 数组向「动态注册/注销 worker」演进的方向。
- **S1 → S3-M2**：S1 的 dispatch 中间层思想由 S3-M2 现代化承接——dispatcher 仍持有分发权，但 (a) dispatcher=slim primary 分核常驻（不再同核共存）；(b) 流表只管「新连接去向 + 旧连接钉住」，不维护全量 TCP 状态镜像；(c) mempool/nice/timer 三大同核难题因分核而消失。
- 不引入额外新组合方案：S2+S3 深度耦合（如 nginx 经 ld_preload 接入 S3 dispatcher）会使两条线的问题空间叠加（exec hook 缺口 + 切流协议），无证据支持其收益，不如各自演进。

## 4. 对比矩阵与分档结论

### 4.1 对比矩阵（定性评级 + 一句话依据）

| 维度 | S1 旧方案复活 | S2 ld_preload | S3 原生演进（M1/M2） | S4 双实例热备 |
|---|---|---|---|---|
| D1 无损性 | 中高：dispatch 表切流，但依赖同核共存稳定性（未闭环） | 高：stack 常驻，HUP 对齐内核语义 | M1 中高（缓冲+转发兜底，需实测）；M2 高（结构性） | 高（ready 前不切流） |
| D2 连接语义 | 高：全局表+drain 退出条件 | 中：原生 graceful close（存量连接被关闭而非服务到自然结束——与内核 nginx 一致，但对齐基线 1 的弱化形态） | 高：drain 期旧连接收包路径显式保障（转发兜底）+ timer 持续 | 高 |
| D3 改动面 | 极大：全量重写（原码未开源）+ 驱动层改造 | 小：nginx 零改动；缺口集中在 adapter 侧（exec hook/回收） | 中：nginx 适配层回退原生顺序 + lib 协议新增；有 primary_slim PoC 基础 | 大：双实例管理 + 分发层全新 |
| D4 主线兼容 | 低：孤儿路线，同核共存与主线（native_mt 分核演进）方向相反 | 中：独立产品线，与主线无耦合也无承接 | 高：直接承接 primary_slim（生产实现已过测试）；timer 隔离受益于 native-mt `__thread` 改造；与 zc_stack 正交 | 低：双倍栈实例与 share-nothing 主线相悖 |
| D5 性能 | 中：稳态每包经 dispatch 一跳（旧实测 58 万 QPS 为 18.11 单来源数据） | 低-中：每 socket 调用走 IPC，近双核占用，8 核后短连接劣于 app 模式 | M1 高：稳态零新增开销（转发仅 reload 窗口启用）；M2 中：稳态每包一跳 | 中低：reload 窗口双倍核/内存 |
| D6 运维 | 高复杂：nice/双 IP/驱动参数 | 中：独立 fstack 实例进程 + 环境变量矩阵 | 中：新增常驻 slim primary + 乒乓 lcore 约定 + reload 状态可观测 | 高：双实例生命周期管理 |
| D7 可测试性 | 差：无法增量验证（须一次性做成） | 好：可先在非 nginx 应用验证 adapter，再套 nginx | 好：M1 可分里程碑增量交付；reload 状态机显式可打点 | 中：切流逻辑可测，但双实例编排复杂 |

### 4.2 分档结论

| 分档 | 方案 | 理由 |
|---|---|---|
| **推荐** | **S3（M1 先行，M2 视数据演进）** | 唯一同时满足：结构性前提（队列所有权与 worker 解耦，基线 2）、连接语义对齐（基线 1）、稳态零性能损耗（D5-M1 高）、有已验证 PoC 基础（primary_slim，改动面可控）、与主线演进同向（D4 高）、可增量交付（D7 高） |
| **备选** | **S2（限定场景）** | 适用于「存量应用零改动接入 + 非 proxy 场景 + 可接受 IPC 性能折损」的独立产品线；HUP 语义天然对齐内核 nginx，缺口（exec/回收）收敛在 adapter 侧。**不建议作为 F-Stack nginx（app 源码集成主线）的 reload 解法**，但建议与 S3 并行推进其缺口修复 |
| **不推荐（独立实施）** | **S1** | 同核共存三支柱（mempool 隔离/nice 调度/timer 隔离）在 24.11.6 全部需重做且 timer 未闭环（E-C §6.2）；原码未开源。其 dispatch 思想由 S3-M2 承接 |
| **不推荐（独立实施）** | **S4** | 机制上收敛为 S3-M2 + 双倍资源，无增量收益；其切流时序三原则并入 S3 |

## 5. 推荐方案 S3 关键设计

### 5.1 进程/队列/listening fd/连接 四层所有权模型

| 层 | 所有者 | reload 时行为 | 依据 |
|---|---|---|---|
| L1 EAL/设备/mempool/ring/队列 setup | **slim primary（dispatcher），常驻** | 不动（杀 primary 数据面零影响已实测：`docs/primary_slim_spec/10` §1.1 E3b/E3c；但 primary 只能常驻不能复活，E10） | P-D §3.2；primary_slim_spec 03 §III |
| L2 队列消费权（rx poll）+ RSS reta | worker 级，可切换 | 新 worker ready 前：旧 worker 持续 poll（队列始终有主，无空窗）；ready 后 reta 切流（或队列移交），旧连接包经 L4 兜底 | ff_dpdk_if.c:508-538（lcore↔queue 映射）、:832/:850/:1218（reta）；基线 2/3 |
| L3 listening socket | **各 worker 栈内自建**（保持现状） | 不跨进程传递：栈隔离天然允许多代际 worker 并存 listen 同 IP:port（每进程独立 FreeBSD 栈实例各自 bind/listen 互不冲突，P-D §3.5）；新连接归属由 L2 切流决定 | P-D 障碍 2 的回避式解法；R-A §6.3-2 的对照（VPP 用 app_listener 单点，F-Stack 用栈隔离多 listen——路线差异点，功能等价） |
| L4 TCP 连接 | worker 私有，**不迁移** | 旧 worker drain：其队列/RTO/keepalive 持续驱动；切换后到达新 worker 队列的旧连接包，经 packet_dispatcher 回调 → dispatch_ring 转发回旧 worker（现成机制）。**流表窗口限定**：回调在新 worker READY 后注册、排空确认后注销——稳态零开销；流表只记新流，miss 一律转旧 worker（第 2 节语义 6） | 基线 1；ff_dpdk_if.c:2105-2150/:2223-2233；P-D §3.5（dispatch 回调 nginx 未用——本方案启用） |

设计取舍说明（与 VPP 的有意差异）：VPP 把 listen 收敛到栈侧单点（app_listener + workers bitmap，R-A §2.2），F-Stack 不照搬——fd 是进程内索引（P-D §2.4），跨进程传递无意义；「多代际栈隔离 listen + 数据面切流」在功能上等价于 workers bitmap（决定「谁收新连接」的是 reta/分发层而非 listen 对象本身），改动面小得多。

### 5.2 reload 时序（文字版时序图，HUP）

前置状态：slim primary 常驻（PID_P）；旧 worker 代际 G_old（N 个 secondary，占 lcore 段 A / queue 集 QA）；lcore_mask 配有乒乓段 B（稳态空闲）。

```
T0  master 收 HUP
    ├─ 【防重入】若上一轮 reload 未完成（存在未排空的 G_old）→ 拒绝本次
    │   HUP 并记日志（不支持快速连续 reload，第 2 节语义 6）
    ├─ ngx_init_cycle 重读配置（语法错→回滚，对齐内核 HUP，R-B §2.2）
T1  master fork 新 worker 代际 G_new（NGX_PROCESS_JUST_RESPAWN）
    ├─ 每个 G_new worker: ff_mod_init(--proc-id, secondary)
    │   secondary attach 到常驻 primary——无 primary 竞争（对比现状障碍 4）
    ├─ G_new worker 绑 lcore 段 B / 对应 queue 集 QB（段 B 与段 A 不同核）
    ├─ master 不再需要 15s sem 等 primary 就绪（primary 一直在）；保留 ready 上报等待
T2  G_new worker 各自完成：ff_freebsd_init 栈实例 → ngx_open_listening_sockets
    │   （各自栈内 listen 同 IP:port，与 G_old 并存，栈隔离保证不冲突）
    ├─ G_new worker 注册 packet_dispatcher 回调——流表随初始化完成自动生效
    │   （稳态不注册：所有包不过流表零开销，第 2 节语义 6）
    └─ 经控制通道（ff_msg ring 扩展，见 5.4）向 master 上报 READY
T3  master 确认全部 G_new READY → 向 primary 请求切流（显式动作，S4 原则）
    ├─ primary 执行 set_rss_table 重算：reta 将新 flow 哈希导向 QB
    │   （切换原子性：reta 更新前 QA 始终有 G_old poll——队列无主窗口不存在）
    └─ G_new 回调流表判定（仅 reload 窗口生效）：
        收到包 → 解析四元组 → ff 连接归属查询（新 ff_api，见 5.4）
        ├─ 新流（SYN 匹配本栈 listen → accept 隐式入表）或流表命中
        │   （本代际已建连接）→ 本栈处理 ✓
        └─ 流表 miss（旧连接包因 reta 重哈希落入 QB）→ 一律回调返回 G_old 的
           queue id → rte_ring_enqueue(dispatch_ring) → G_old dequeue →
           ff_veth_input → 旧栈正常处理（RTO/keepalive/数据）✓
T4  G_old worker 收到 master 的 graceful shutdown（原生语义）
    ├─ 各自栈内 close listening（只影响自己栈，G_new 的 listening 不受影响）
    ├─ 停止 accept，继续跑 ff_run：drain 存量连接
    │   （存量连接后续包即使被 reta 导入 QB 也经 T3 回调转发回来）
    │   timer 持续驱动（G_old 活着，freebsd_clock 在自己 lcore 槽）
    └─ drain 完成（连接数=0 或 no_timers_left）→ 进程退出
T5  master 收 G_old SIGCHLD（且确认排空：连接数=0 + DRAIN_DONE）→ reload 完成
    ├─ 通知 G_new：注销回调/关闭流表 → G_new 进入稳态，成为下一轮 reload 的
    │   「老 worker」（防止性能退化；此后稳态所有包不过流表，第 2 节语义 6）
    ├─ lcore 段 A 释放，成为下一轮 reload 的乒乓段
    └─ 下一轮 reload 时 G_new' 绑段 A（乒乓交替；G_new 已可再次接受 reload——
        防重入拦截随排空确认解除）
异常分支：
- T2 前 G_new 任一 worker 起不来/ready 超时 → master 放弃本轮（G_old 未受任何
  影响，服务继续）——对齐内核 HUP 配置失败回滚语义
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

1. **ff_api 新增**（lib 侧，最小集）：
   - `ff_conn_owner_query(...)`：四元组 → 是否本栈已知连接（封装 in_pcblookup 语义），供 dispatcher 回调判定归属。**窗口语义（第 2 节语义 6）**：仅在 reload 窗口被调用——回调随 G_new READY 注册、随排空确认注销；本栈连接表即「只含本代际新流的流表」，表项 miss 一律转 G_old；稳态零调用。
   - 可选：`ff_pcb_export(...)` / reload 连接表同步辅助（若回调实时查询性能不足，退化 reload 握手时一次性导出旧连接四元组集，drain 期间增量更新）。
   - 队列移交模式变体（若 reta 动态更新在某些 PMD 不可用，见 RV2）：`ff_queue_handover(q, from_proc, to_proc)` 原语（旧停 poll → 新起 poll，NIC rx ring 缓冲兜底窗口）。
2. **ff_msg 扩展**（控制通道，复用现有 msg ring 机制，P-D §3.3）：新增 FF_RELOAD 消息族——READY 上报、切流请求/应答、队列状态查询、drain 进度上报、**drain 完成确认（DRAIN_DONE：触发 G_new 关流表回稳态，第 2 节语义 6）**、**reload 拒绝（REJECT：防重入，上一代 G_old 未排空时 master 拒绝新 HUP）**。注意：现有 msg ring 是工具进程↔ff 进程的控制面（P-D §3.3），扩展为 master↔primary↔worker 的 reload 控制面需评估容量与实时性（或经 nginx channel + primary 轮询组合）。
3. **config.ini 新增**（[dpdk] 段）：
   - `primary_slim = 1`（primary_slim_spec 已设计，V2/V4/V5 校验链沿用：需 nb_procs>=2、与 thread_mode=1 互斥、primary lcore 不入 lcore_list）。
   - `graceful_reload = 1`（总开关，默认 0 时行为完全回退现状——0 回归原则）。
   - 乒乓 lcore 段约定：lcore_mask 含 2N 段 + `reload_lcore_policy = pingpong`。
4. **nginx 适配层改造**（app/nginx-1.28.0）：
   - `ngx_process_cycle.c:223-237` 两段式 reload 块整体移除/条件化（graceful_reload=1 时走原生顺序）。
   - `ngx_ff_module.c:183-187` + `ngx_process_cycle.c:1117-1121`：worker0 不再 primary，全部 secondary；sem 就绪同步改为对常驻 primary 的 attach 确认。
   - 补回 worker QUIT 分支缺失的 `ngx_set_shutdown_timer`（P-D §4 补充事实）。
   - reload 编排状态机（T0-T5 显式状态 + 打点），满足第 1 节否决性判据（显式可观测，对齐 R-A §6.4 教训）。

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
| RV1 | 2N worker + 1 slim primary 多 secondary 并存（24.11.6）稳定性：mempool 跨进程并发（不同 lcore cache）、EAL 资源、msg_ring 广播 | 双代际进程组长时间共存压测 + ff_top/ff_traffic 观测 |
| RV2 | **reta 运行时更新**（rte_eth_dev_rss_reta_update / set_rss_table 路径）在目标 PMD（virtio 已知 + 物理网卡待测）的支持度与生效时延；若不支持 → 退化到队列移交变体（RV3） | reload 窗口抓包验证新 flow 导向；dpdk-devbind 确认 PMD 能力 |
| RV3 | 队列移交变体：旧 worker 停 poll → 新 worker 起 poll 的移交窗口内，NIC rx ring（默认描述符深度）缓冲是否足以零丢包（窗口预估微秒~毫秒级） | 高速率注入 + 移交瞬间丢包计数 |
| RV4 | dispatch_ring 转发旧连接包的吞吐/时延：ring 容量（create_ring 默认）在 drain 高峰（大流量长连接集中转发）是否成为瓶颈 | 构造 80% 流量在旧连接的 reload 压测 |
| RV5 | dispatcher 回调每包判定开销【仅 reload 窗口，第 2 节语义 6】：稳态流表不生效（回调已注销，零开销为设计属性，非待验证项）；度量对象为 reload 窗口内（切流至排空确认期间）四元组解析 + 归属查询（ff_conn_owner_query）在 10G 线速小包下的 CPU 占比（usr_cb_tsc 已有统计钩子，ff_dpdk_if.c:2111） | reload 窗口内/外 pps 对比；并验证排空确认后回调计数停止增长（关表生效） |
| RV6 | 不同 lcore 的多进程 timer 槽隔离实测（共享 memzone 结构上分槽，E-C §5.3；native-mt `__thread` 化后未在多进程 reload 场景验证过） | 双代际共存期间观测 RTO/keepalive 精度、rte_timer 状态 |
| RV7 | 多代际栈隔离 listen 同 IP:port 的实际行为（P-D §3.5 推断栈隔离不冲突，未运行时验证） | 双代际并存期并发 SYN 压测 |
| RV8 | KNI 启用场景：runtime owner（primary_slim_spec 04 K4 已验证 secondary 为 owner）与双代际 worker 的交互 | enable_kni=1 的 reload 回归 |
| RV9 | 端到端门禁（对齐 R-A §6.3-7 VPP 验证模式）：带流量循环 reload 数千次 + 无死锁无 crash + 新连接错误数 0 + 存量连接全部 drain 成功 | wrk/JMeter 持续流量 + 每 2s reload 循环（#3547/#3645 复现模式） |

### 6.2 需设计评审（DR，机制选择需评审定案）

| # | 项目 | 备选与倾向 |
|---|---|---|
| DR1 | reload 编排者：nginx master（语义层自然）vs slim primary（全局视图） | 倾向 master 编排 + primary 提供原子原语（reta 更新/队列状态），保持数据面组件无业务语义 |
| DR2 | 旧连接归属判定：回调实时查询（ff_conn_owner_query）vs reload 握手时导出四元组快照表 | 倾向实时查询：本栈连接表天然「只含本代际新流」（miss=旧连接→一律转 G_old），与流表窗口化原则（第 2 节语义 6）严格契合，且避免快照一致性协议；性能不足再退化快照（RV5 数据支撑决策；**快照形态同样必须遵守窗口语义**——READY 后生效、排空确认后关表） |
| DR3 | reta 切流 vs 队列移交：两变体的选择依据（RV2/RV3 数据）与兼容降级链 | 设计上并列支持，运行时按 PMD 能力选择 |
| DR4 | ff_msg ring 作为 reload 控制通道的容量/实时性 vs 新增专用 ring | msg ring 现为工具控制面（P-D §3.3），reload 是数据面近路径控制，评审是否需要专用低延迟通道 |
| DR5 | 乒乓 lcore 的配置表达与校验链（lcore_mask 2N 约定、worker 数一致性、单代际模式向后兼容） | 仿 primary_slim V2/V4/V5 校验链风格 |
| DR6 | 异常回退完备性：新 worker 部分失败、primary 被 kill（数据面不受影响但控制面降级，primary_slim E10：不可复活）、drain 挂起强退阈值 | 状态机每阶段定义回退目标态 |
| DR7 | M2（dispatcher 中心化）启动判据（v1.3 修订：流表窗口化后稳态转发路径不启用、损耗恒 0，原「稳态损耗 >5%」判据失效）：改为 **reload 窗口开销**判据——RV5 实测窗口内回调开销致吞吐下降 >5%，或 drain 期 P99 时延劣化 >10%，或高连接存量场景 drain 时长超 SLO（流表在 drain 全程生效的代价）时才立项 | 评审定阈值 |

## 7. 与目标语义的对照验收（推荐方案自检）

| 目标（第 2 节） | S3-M1 达成方式 | 残余风险 |
|---|---|---|
| 1 新连接零丢失 | reta 切流前 QA 始终有主；切流后 QB 已 ready 且 listening 已建 | RV2/RV3（切流原子性/缓冲） |
| 2 存量连接完整 drain | G_old 活着跑 ff_run + 转发兜底送达 + timer 持续 | RV4/RV6 |
| 3 配置失败回滚 | T2 前失败 G_old 未动 | 设计保证（DR6） |
| 4 HUP+USR2 均支持 | 机制同源；master 无 ff 状态可安全 exec | USR2 路径需专项测试 |
| 5 工程意义无损 | 门禁 = RV9 错误数 0 | 接受 HAProxy 文档级边界（R-B §2.2） |

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

**核心结论**：推荐 S3（M1 乒乓核队列切换 + dispatch_ring 转发兜底，承接 primary_slim），S2 为并行备选产品线，S1/S4 不独立实施（思想/原则分别并入 S3-M2 与 S3 时序）。落地拆解见 [07-里程碑](07-milestones.md)，测试与验收见 [08-测试计划](08-testing.md)。
