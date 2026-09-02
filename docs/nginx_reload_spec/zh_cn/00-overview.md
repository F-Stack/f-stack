# 00 总览：F-Stack Nginx 无损 reload 方案 spec 文档集

| 项 | 值 |
|---|---|
| 文档编号 | 00 |
| 标题 | 总览（任务背景 / 调研方法 / 核心结论 / 文档集导读 / 未坐实事项总览） |
| 版本 | v1.9.3 |
| 日期 | 2026-09-01 |
| 修订说明 | v1.9（2026-09-01）：本篇此前停留在 v1.0，仍在描述 v1.6 已废弃的「乒乓 lcore 段 + reta 原子切流」方案，与 06/07/08 严重脱节。本轮按 [06] v1.9（交叉审核后的 M1′ 形态）全量同步：§3.2 一句话结论、§3.3 落地路径、§4 导读、§5 未坐实清单、§6 编号体系。**v1.9.1（2026-09-01）：人工决策反转 D-A = 两代同 lcore_id**，同步 §3.3 落地路径表（lcore_id 行、新增代际 mempool 与心跳两行）与 §5 未坐实清单。**v1.9.2（2026-09-02）：据 G1 门禁重确认整改**——§2.1/§4 导读/§5/§6 同步为 43 编码点、07=v1.4、08=v1.4（22 单测/13 集成/10 性能/28 验收）、RV1-15、DR1-11；§5 G 类未坐实项由 4 项扩为 7 项。**v1.9.3（2026-09-02）：DR11 定案 M-A 为主**（M-B 备选，[09] §24.1）；mbuf 池归属机理代码坐实（[09] §24.2/24.3）；DR1 已定案候选 b（[09] §24.5/24.6） |
| 状态 | 待人工审计 |
| 来源产物 | 汇总本目录 01~08 各篇（其各自来源产物见文头声明）；本篇由 spec 撰写者基于 work/ 下 6 份中间产物正式化改写 |

---

## 1. 任务背景

F-Stack 的 nginx 适配（`app/nginx-1.28.0/`，源码集成路线）自 2017 年起即支持基于 fork 协议的 master-worker reload（commit `406002113b143fda1fa444f0af42b97b41951882`，close issue #12），但该实现是"旧 worker 全部退出后新 worker 才启动"的两段串行模式，reload 期间数据面完全空窗，存在丢包与服务中断。issue #1036 已坐实根因：多进程模型下每个 worker 独占绑定 NIC 硬件队列（RSS），reload 时旧 worker 退出而新 worker 尚未完成 DPDK/F-Stack 栈初始化，存在「队列无主窗口」导致丢包——问题在数据面（网卡队列归属），不在监听 fd 本身。

社区历史上唯一被实测证明可零丢包 reload 的方案（issue #547，orange30，DPDK 18.11 + F-Stack 1.20）因 DPDK 19.11 timer 库改为共享 memzone 实现而失效，且原始代码从未开源（详见 [03-旧社区方案考证](03-fstack-legacy-solution.md)）。

本任务目标：以多 agent 调研 + 本地代码考证为证据基础，设计并规划 F-Stack 当前主线（DPDK 24.11.6 + FreeBSD 15.0 + nginx 1.28.0）上可落地的 nginx 无损 reload 方案，产出本中文 spec 文档集供人工审计。按工作区规约，本阶段仅产出中文文档（`docs/nginx_reload_spec/zh_cn/`），功能验收完成后再翻译英文版。

## 2. 调研范围与方法

### 2.1 团队分工（多 agent 并行）

| 线 | 内容 | 产物 → 对应正式文档 |
|---|---|---|
| 外部调研 A（researcher-vpp-vcl） | VPP/VCL 如何支持 nginx reload：架构、fork/session 所有权、已知 issue、对 F-Stack 的启示 | work/research-vpp-vcl.md → [01](01-vpp-vcl-research.md) |
| 外部调研 B（researcher-others） | 内核基线三机制（USR2/HUP/reuseport）、eBPF 线（Facebook/Cloudflare/Cilium）、其他用户态栈（Seastar/mTCP/6WIND/dpdk-nginx/OpenOnload/lwIP）、通用模式归纳 | work/research-other-projects.md → [02](02-other-projects-research.md) |
| 考证 C（evidence-hunter） | issue #547/#12 全部原始评论、iWiki 4015929276 旧方案全文与 7 张截图解析、PR#559、DPDK 18.11→19.11→24.11.6 定时器实现演变 git 证据链 | work/evidence-legacy.md → [03](03-fstack-legacy-solution.md) |
| 探测 D（probe-fstack） | F-Stack nginx 适配层与 lib 层现状代码事实 + 无损 reload 的 8 项代码级障碍清单 | work/probe-fstack-current.md → [04](04-fstack-current-analysis.md) |
| 探测 E（probe-ldpreload） | adapter/syscall（LD_PRELOAD ring IPC）路线架构事实 + nginx 无损 reload 可行性与缺口 | work/probe-ld-preload.md → [05](05-ld-preload-alternative.md) |
| 设计 F（solution-designer） | 候选方案集 S1~S4 对比、推荐方案 S3 关键设计、RV/DR 清单 | work/solution-design.md → [06](06-solution-design.md) |
| 规划 G（milestone-planner） | 里程碑 M0~M7、**43 个编码改动点**（v1.7 新增 307/308；v1.9 新增 309~313；**v1.9.1 新增 314/315/316，取消 311，308 转索引**）、单测/集成/性能/验收测试计划 | work/milestones-testing.md → [07](07-milestones.md) + [08](08-testing.md) |

### 2.2 证据策略

1. 一手来源优先：官方文档（nginx/Envoy/HAProxy/FDio wiki/内核文档）、源码原文（VPP raw.githubusercontent、本地 f-stack 仓库）、git log/show/blame、gh CLI issue/PR 全文、iwiki-cli 抓取。
2. 以实际代码为准：文档/外部资料/代码不一致时以代码为准；关键机制在方案设计阶段另行回查代码交叉验证。
3. 诚实标注：单一来源标「仅此来源，未二次坐实」；查不到的如实标「未查到」；静态分析无法定论的进「未坐实清单」并给出运行时验证方法；不臆断 PASS。
4. 证据可追溯：各调研/探测篇保留「实际执行的操作清单」一节（搜索关键词、抓取 URL、执行的只读命令）。
5. 全部调研/考证均为只读操作，未执行任何 git 写操作，未修改任何代码。

## 3. 核心结论摘要

### 3.1 三条基线结论（两条外部调研线独立收敛，作为方案评估的锚）

1. **业界无 TCP 已建连接迁移先例**。Envoy 官方原句 "existing connections are not transferred to the new Envoy process"；VCL 模式下旧 worker 的连接同样随 drain 关闭而非迁移，互相印证。因此目标语义必须对齐「**新连接无缝切换 + 旧进程 drain**」，不追求跨进程 TCP 状态迁移（依据：[02](02-other-projects-research.md) §4 P4、[01](01-vpp-vcl-research.md) §4.2）。
2. **网卡队列/收包所有权与业务进程生命周期解耦，是用户态栈无损 reload 的结构性前提；监听 fd 归属是第二位的控制面问题**。三个独立来源指向同一结论：VPP 队列归独立进程（无主窗口结构性不存在）、#1078 primary_slim PoC（杀 primary 后 12/12 存量连接零中断）、adapter/syscall 中心化设计（依据：[01](01-vpp-vcl-research.md) §6.2、[02](02-other-projects-research.md) §5）。
3. **"ready 前不切流"模式在两种架构里同构存在**。Facebook LPC 2021「新实例 ready 前流量持续导给旧实例」与 VCL app_listener workers bitmap（新 worker 注册进 bitmap 前 accept 不分发给它）同构（依据：[02](02-other-projects-research.md) §2.4(a)、[01](01-vpp-vcl-research.md) §2.2/§4.2）。

### 3.2 一句话结论

- **S3 推荐理由**：S3（原生多进程演进，**v1.9 形态 M1′：常驻 slim primary + 同队列（queue_id 代际无关映射）+ ready 后同期接管 rx+tx+listen + G_new 独占硬件、G_old 软件寄生 + 双向 per-generation `drain_ring` + flow_map 软件分发表 + rx 互斥 + **两代同 lcore_id** + **同 lcore_id 资源隔离（自驱 hardclock + 代际 mempool）** + msg_ring/KNI 代际隔离 + 心跳与 rx 交还 + ARP/NDP clone**，直接承接 primary_slim #1078）是唯一同时满足结构性前提（基线 2）、连接语义对齐（基线 1）、稳态零额外开销（~~DR11 定案 M-A 为主后须由 PT-NR-09 量化，见 [06] §4.1 D5~~）、有已验证 PoC 基础、与主线演进同向、可增量交付的方案（[06](06-solution-design.md) §4.2）。
  > **注意（v1.9）**：v1.0-v1.5 的「乒乓 lcore 段 + reta 原子切流」已在 v1.6 废弃（reta 不改、不依赖 NIC RSS 能力）；v1.6 的「两代共享同一批硬件队列」又因 **TX 并发违反 DPDK 契约**（`dpdk/lib/ethdev/rte_ethdev.h:6575-6577`）与 **dispatch_ring 双消费者违反 `RING_F_SC_DEQ`** 而在 v1.9 被 M1′ 取代。历次形态变更的废弃说明见 [06](06-solution-design.md) §6.5/§6.5.1。
- **旧方案失效原因**：orange30/iWiki 旧方案的「新旧进程同核共存」依赖 DPDK 18.11 timer 库「每进程独立静态数据」实现，DPDK 19.11 起 timer 状态迁入共享 memzone 而失效，原代码从未开源且主线至今未彻底闭环（[03](03-fstack-legacy-solution.md) §5/§6）。
- **ld_preload 定位**：S2（adapter/syscall LD_PRELOAD 路线）是并行备选产品线——适用于「存量应用零改动接入 + 非 proxy 场景 + 可接受 IPC 性能折损」，不建议作为 F-Stack nginx（app 源码集成主线）的 reload 解法（[06](06-solution-design.md) §4.2、[05](05-ld-preload-alternative.md)）。

### 3.3 落地路径概要

推荐方案 S3 拆解为 M0 预研 → M1 常驻 primary 化 → M2 新旧并存（**两代同 lcore_id** + 自驱 hardclock + 代际 mempool + 心跳与 rx 交还 + msg_ring/KNI 代际隔离）→ M3 同期接管 rx+tx+listen + TX 独占 + flow_map 软件分发表 + 双向 drain_ring（同队列、reta 不改、virtio 与物理网卡均可用）→ M4 drain 收尾、半开连接窗口与关表回稳态 → M5 USR2 → M6 终门禁（循环 reload ≥100 次，每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次）→ M7（可选，DR7 触发）共 8 个里程碑、**43 个编码改动点**（[07](07-milestones.md) v1.4；计数规则见其 §0 数字口径说明——308 已拆为 314/315 作索引不计数、311 已取消）；全程以 `graceful_reload=0`（默认）为配置级总回退点。

**v1.9 方案核心 M1′**（[06](06-solution-design.md) §2 语义 13~15、§3.3、§5）：

| 要素 | 内容 |
|---|---|
| 队列 | 同队列（queue_id 代际无关映射），reta 不改 → `ff_rss_check`/`adjust_sport`/`tbl`/`thash` 四件套不变，不配 2N 队列 |
| 硬件所有权 | **G_new 独占 rx poll + tx**；G_old 接管后完全脱离硬件（无硬件模式，只跑协议栈 + 定时器） |
| 双向通道 | `drain_ring_rx`（G_new → G_old，旧连接入向）+ `drain_ring_tx`（G_old → G_new，出向由 G_new 代发），均 per-generation、SP/SC 明确，**不复用 `dispatch_ring`** |
| 新连接判定 | flow_map 软件分发表，**收到 SYN 并发出 SYN-ACK 时入表**（非 `accept()` 时），miss 一律转 G_old；排空确认后关表回稳态 |
| 半开连接窗口 | G_old 停 accept 但**延迟 close listening** 至自身 syncache 排空（语义 14） |
| **lcore_id / 代际隔离**（v1.9.1 人工决策） | **两代使用相同 lcore_id**（同核同 lcore_id）；`lcore_mask`/`nb_procs`/队列数**保持 N 不变、无新增配置面**；DPDK 硬禁令（`multi_proc_support.rst:169-172`）的理由即 mempool cache 损坏，由代际 mempool 消除 ⇒ **例外适用**。msg_ring 按 (proc_id, 代际) 索引、KNI runtime owner 跟随活跃代际（语义 15） |
| **代际 mempool**（v1.9.1，必需项） | 应用侧分代际 `gen0/gen1` 池（init 期预建、乒乓复用）⇒ **各自独立 cache，应用侧竞态归零**；**共享 RX 池**的跨代 free 按 DR11 处理——**DR11 已定案 M-A**（`cache_size=0`，稳态有损耗由 PT-NR-09 量化）；M-B（free_ring 代 free，稳态零损耗）为备选（见 [09] §24.1） |
| **自驱 hardclock**（v1.9.1，必需项） | 同 lcore_id 下 `priv_timer[L]` 必然同槽 ⇒ main_loop 按 TSC 间隔直调 `ff_hardclock()`，每进程 timer 完全独立；PT-NR-08 精度回归为 M2 **合入门槛** |
| **G_new 崩溃回退**（v1.9.1，DR6 定案①） | 共享内存全局切换标记**每 loop 递增**作心跳供 G_old 检测；G_old 排空退出后标记随 flow_map 消亡不再递增（避免误报）；超时**默认 1s 可配置**；判定失活后**由 primary 将 rx 交还 G_old** |
| 缓冲 | RX_QUEUE_SIZE 512→4096（接管窗口缓冲） |

## 4. 文档集导读

- **[01 VPP/VCL 调研](01-vpp-vcl-research.md)**：VCL 三层架构（LDP/VLS/VCL）、application/app_worker/app_listener 模型、fork 三阶段与 SIGCHLD 延迟清理、session/listen 所有权迁移 API、VCL 模式 nginx HUP reload 的机制性支持与 #3547/#3645 两个未修复 bug、对 F-Stack 的启示（队列归属中心化为第一优先级）与教训（reload 必须做成显式可观测状态机）。
- **[02 其他项目调研](02-other-projects-research.md)**：内核基线三种机制（USR2 双 master、HUP、SO_REUSEPORT）、eBPF 三条线的任务前提修正（Facebook sk_reuseport / Cloudflare sk_lookup / Cilium 澄清）、Seastar/mTCP/6WIND/dpdk-nginx/OpenOnload/lwIP 逐个结论、业界做法六类通用模式（P1~P6）与对 F-Stack 的适用性初判（方向 A/B/C）。
- **[03 旧社区方案考证](03-fstack-legacy-solution.md)**：issue #547/#12 全部评论原文与关键事实、iWiki 4015929276《F-Stack Nginx reload方案》全文与 7 张截图解析（dispatch 中间层、不同 mempool、nice 动态调整、双内网 IP + IP_BIND_ADDRESS_NO_PORT 四大改造点）、PR#559、DPDK timer 库 18.11→19.11→24.11.6 演变 git 证据链（失效分水岭 commit 37a7c72f0/4418919fe、本地补丁 rte_timer_meta_init 62f1c34df）。
- **[04 F-Stack 现状分析](04-fstack-current-analysis.md)**：nginx 适配层全部改动文件清单与进程模型/事件循环/fd 生命周期/HUP 两段串行 reload 路径的代码事实；lib 层 ff_init/ff_dpdk_if/IPC/timer/多进程现状；无损 reload 的 8 项代码级障碍清单（每项带文件:行号证据）。
- **[05 ld_preload 备选路线](05-ld-preload-alternative.md)**：adapter/syscall 架构（hook 面、ring IPC、fork 语义、stack 进程侧、异常退出回收）、与既有 ld_preload_ring_spec 的三处偏差、nginx HUP/USR2 结合可行性、7 项天然优势与 10 项缺口。
- **[06 方案设计](06-solution-design.md)**（v1.9）：7 个评估维度与否决性判据、目标语义定义（12 条 + v1.9 新增 13~15）、候选方案 S1~S4 逐一机制描述/障碍覆盖/风险、对比矩阵与分档结论（推荐 S3-M1′、备选 S2、virtio 场景推荐 S4、S1 不独立实施）、S3 四层所有权模型（L2 拆 rx/tx/ring 三行）与 T0~T5 reload 时序、需新增的 ff_api/ff_msg/config.ini 接口面、**RV1~14 运行时验证与 DR1~10 设计评审清单**、单来源声明、**v1.9 定案汇总（D-A/D-B/D-C）**。
- **[07 里程碑规划](07-milestones.md)**（v1.4）：编号体系与映射表、M0~M7 里程碑总览与逐个详述（目标/范围/编码工作清单 C-NR-100~604 带文件:行号锚点/DoD/测试门禁/风险与回退/提交建议）、**43 个编码点**（v1.9 新增 C-NR-309~313 承载 M1′ 与 6 项 P0 修复；**v1.9.1 新增 314/315/316 承载同 lcore_id 的资源隔离与心跳，取消 311**）的跨里程碑依赖 DAG。
- **[08 测试计划](08-testing.md)**（v1.4）：**22 条单测用例（UT-NR-01~22）** + 9 个 fixture + mock 三层策略、**13 条 cmocka 真 EAL 集成用例（IT-NR-A01~13，v1.9 新增 A09 TX 独占/A10 半开连接窗口/A11 msg_ring 代际隔离；v1.9.1 新增 A12 G_new 失活与 rx 交还/A13 同 lcore_id 的 timer 与 mempool 隔离）**、**17 行实机用例（RT-00~15，含 RT-04b）** 与测试环境拓扑/硬性规约、**10 条性能基线用例（PT-NR-01~10）**、**28 项验收标准（A-NR-01~28）** 与 6 项回归（RG-NR）、未覆盖风险声明与未决问题。

（09-review-report.md 由后续独立审核 agent 产出，不属于本撰写批次。）

## 5. 未坐实事项总览

各篇未坐实/单来源事项按类别汇总如下，人工审计时应重点关注其证据强度：

| 类别 | 内容 | 数量 | 详见 |
|---|---|---|---|
| A. 外部机制未坐实 | VPP-HostStack-nginx wiki 正文未获取到、VSAP 补丁正文未读、SIGUSR2/exec 无证据（「未查到」）、4d9df5cb3d 与 #3547 对应关系、VPP 侧 session worker_update handler 未定位、#3490/#3463/#3189 细节、25.10 后是否修复 #3645、AsterNOS 营销内容不采用、session-pinning 补丁与 25.x 关系；nginx reuseport 模式 reload 官方描述无、reuseport 分布不均无一手定量来源、FB LPC 2021 为译文单来源、sk_lookup 内核版本推断、tubular 是否用于业务重启未明说、6WIND 本地应用路径推断、mTCP fork 官方声明无、ScyllaDB 滚动重启文档未取到、lwIP/PicoTCP 非穷尽、Cilium 1.6 博客抓取不完整 | 9 + 11 | [01](01-vpp-vcl-research.md) §7、[02](02-other-projects-research.md) §6 |
| B. 历史方案未坐实 | v1.20→v1.21 timer 使用层完整 diff（U2）、旧方案验收数据（U3/U4）、orange30 原始代码不可恢复（U5）、24.11.6+native-mt 多进程 reload 实测（U6）、#528/#1036/#673 评论细节（U7）| 6 | [03](03-fstack-legacy-solution.md) §8（U1 已于 2026-08-18 坐实为「F-Stack 15.0 栈已支持 IP_BIND_ADDRESS_NO_PORT」，系本地扩展，见该篇 §6.2/§8）|
| C. 本地代码运行时行为未坐实 | secondary 在 primary 退出后存活行为、worker 退出不经 rte_eal_cleanup 的脏状态、reload 空窗实测时长、SO_REUSEPORT 实际设置路径、kernel_network_stack 混跑 fd 冲突、KNI 归属影响（04）；child_process_init 固定 attach zone 0 的交互、USR2 时序、fd 映射表 fork 继承、FF_PROC_ID 使用方式、sc 容量曲线、03/04 spec 未读、ff_adapt_user_thread_add 语义、epoll 多 accept 边缘行为（05） | 6 + 8 | [04](04-fstack-current-analysis.md) §5、[05](05-ld-preload-alternative.md) §6 |
| D. 新方案需运行时验证/评审 | **RV1~RV15**：多 secondary 并存、~~reta 运行时更新~~（v1.6 取消）、**rx 接管互斥**、**双向 drain_ring 吞吐与满环行为**、flow_map 查表开销、**自驱 hardclock 精度等价性**（v1.9.1 改写：同 lcore_id ⇒ priv_timer 必然同槽，C-NR-307 无退路）、多代际 listen、KNI owner 跟随、循环 reload 终门禁、同核切换性能、**TX 独占**、**半开连接窗口**、**msg_ring/KNI 代际隔离**、**keepalive 下 drain 时长与门禁节拍**、**同 lcore_id 下的 mempool 隔离（v1.9.1 新增 RV15）**；**DR1~DR11**：~~编排者（DR1 已定案候选 b：master 编排+primary 原语）~~、归属判定、~~切流变体~~、~~四链解耦与代际 lcore 池（v1.9.1 取消）~~、控制通道、异常回退（**T3 后 G_new 崩溃已定案：primary 将 rx 交还 G_old**）、M7 启动判据、**lcore_id 策略（已定案：两代相同）**、**TX 处理形态**、**防重入可否放松**、**共享 RX 池 M-A/M-B（DR11 已定案 M-A 为主）** | 15 + 11（DR1/DR5/DR8/DR11 已定案）| [06](06-solution-design.md) §6、[07](07-milestones.md) §0 |
| E. 单来源声明 | iWiki 旧方案全部内容与数据、FB LPC 2021 译文细节、#3547 根因分析（报告者个人分析）、primary_slim PoC 数据（非本团队复测）、VSAP 补丁内容、AsterNOS（不采用）、6WIND 本地路径推断、~~reta/多 secondary 推论~~（v1.9：reta 项已随方案取消） | 9 条 | [06](06-solution-design.md) §8 |
| F. 测试环境局限 | 本机仅 virtio 系 PMD（**virtio stats 无 `imissed`，host 侧丢包 guest 不可观测**；物理网卡上的 rx 接管互斥 RV3 未验证）、wrk 不可用（ab + python 探测替代）、本机 IPv6 存在独立 13→15 回归问题（IPv6 reload 回归暂不覆盖）、单机客户端瓶颈、多 port 异构未决 | — | [08](08-testing.md) §1/§5/§6 |
| **G. v1.9 交叉审核新增未坐实项**（2026-09-01） | ① **TX 并发的具体故障形态未实测**（「两代并发同一 tx queue 违反 `rte_ethdev.h:6575-6577` 契约」属代码坐实，但「描述符环竞争 → mbuf 双重释放/描述符覆盖」为推断）；② **stack-coexist（`kernel_coexist=1`）与本方案的交互未做代码考证**（多代际并存时内核侧配对 socket 行为、fd 映射是否需代际隔离）；③ **「T3 后 G_new 崩溃」的回退已定案**（DR6 方案① primary 将 rx 交还 G_old + 心跳检测，v1.9.1）——**残留：G_new 与 G_old 同时崩溃无解**，依赖外部运维重启；④ **`drain_ring_tx` 代发路径的开销量化未实测**（PT-NR-10，DR9 决策输入）；⑤ **DPDK 硬禁令例外论证未经实测佐证**（v1.9.1，须 RV1/RV6/RV15 + PT-NR-08/09 + IT-NR-A13）；⑥ **心跳超时默认 1s 未实测校准**；~~⑦ DR11（M-A/M-B）未定案~~ **已定案（v1.9.3）M-A 为主** | 6 项未坐实 | [06](06-solution-design.md) §6.4/§8/§9、[08](08-testing.md) §5-10~12 |

## 6. 编号体系

| 前缀 | 含义 | 前缀 | 含义 |
|---|---|---|---|
| M0~M7 | 里程碑 | UT-NR-xx | 单元测试用例 |
| C-NR-xxx | 编码改动点 | IT-NR-Axx | cmocka 真 EAL 集成用例 |
| E-NR-xx | M0 预研实验项 | IT-NR-RT-xx（RT-xx） | 实机用例 |
| F-NR-x | 单测 fixture | PT-NR-xx | 性能基线用例 |
| RV1-15 | 运行时验证项（v1.9 新增 11~14；v1.9.1 新增 15） | A-NR-xx | 验收标准（v1.9.1 增至 28 项） |
| DR1-11 | 设计评审项（v1.9 新增 8~10；v1.9.1 新增 11，取消 5） | RG-NR-xx | 回归项 |
| S1~S4 | 候选方案 | U-NR-x | 测试计划未决问题 |

【注】07 篇的里程碑编号 M1~M4 合起来等于 06 篇方案设计的 S3-M1 大阶段；07 的 M7 等于 S3-M2。映射表见 [07](07-milestones.md) §0.2，跨文档引用以该表为准。
