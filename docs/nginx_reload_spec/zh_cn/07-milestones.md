# 07 里程碑规划：M0~M7 里程碑与编码工作清单

| 项 | 值 |
|---|---|
| 文档编号 | 07 |
| 标题 | Nginx 无损 reload（S3 方案）里程碑规划与后续编码工作清单（C-NR-100~604） |
| 版本 | v1.2 |
| 日期 | 2026-08-31 |
| 状态 | 待人工审计（v1.2 增量修订） |
| 对齐基线 | [06-方案设计](06-solution-design.md) **v1.7**（v1.6：同队列 + 同期移交 + flow_map，去乒乓双队列段、去 reta 切流；v1.7：自驱 hardclock + 应用 mempool 分代际） |
| 来源产物 | work/milestones-testing.md（规划师 milestone-planner，2026-08-18 落盘）。本篇为其里程碑与编码工作清单部分的正式化改写；测试计划部分拆分至 [08-测试计划](08-testing.md)。输入：[06-方案设计](06-solution-design.md)（推荐方案 S3，含四层所有权模型、T0-T5 时序、接口面清单 5.4、RV1-10、DR1-7）、[04-现状分析](04-fstack-current-analysis.md)（8 项障碍清单）、[01-VPP/VCL 调研](01-vpp-vcl-research.md)（§6.3-7 VPP 验证模式）、[03-旧方案考证](03-fstack-legacy-solution.md)（旧方案失败教训）；对齐 docs/primary_slim_spec/zh_cn/ 里程碑切分粒度 |
| 修订记录 | v1.1（2026-08-21）：据 [06] v1.6 贯通——删除乒乓双队列段与 reta 切流，M3 改为同期移交+flow_map。v1.2（2026-08-31）：据 [06] v1.7 贯通——M2 新增 C-NR-307 自驱 hardclock / C-NR-308 应用 mempool 分代际，编码点总数 35→37；删除已废弃的 RV2/DR3，新增 RV10；修正 M0 一票否决项、8 项障碍消解机制、DAG 与全部残留的「乒乓/reta/原子切流」表述 |

相关篇章：[00-总览](00-overview.md) | [06-方案设计](06-solution-design.md) | [08-测试计划](08-testing.md)

---

## 摘要

本文把 [06-方案设计](06-solution-design.md) 的推荐方案 S3（v1.6：同队列 + ready 后同期移交队列+listen + flow_map 软件分发表 + 跨进程互斥 + ARP/NDP clone，承接 primary_slim；v1.7：自驱 hardclock + 应用 mempool 分代际；M2 大阶段：可选 dispatcher 中心化）拆解为 **M0 预研 → M1 常驻 primary 化 → M2 新旧并存 → M3 同期移交+flow_map → M4 drain 收尾 → M5 USR2 → M6 门禁收尾 → M7（可选，DR7 触发）** 共 8 个里程碑、**37 个编码改动点（C-NR-100~604，v1.7 新增 C-NR-307 自驱 hardclock / C-NR-308 应用 mempool 分代际）**。逐项给出文件:行号锚点、依赖、DoD、测试门禁与回退方案；并把 RV1-10 逐项分配到里程碑、DR1-7 标注为对应里程碑开工前置评审。测试计划（16 条单测 UT-NR-01~16 + 8 条真 EAL 集成用例 IT-NR-A（v1.6 新增 A06/A07/A08）+ 15 行实机用例 IT-NR-RT + 6 条性能基线 PT-NR + 20 项验收标准 A-NR + 循环 reload 门禁）见 [08-测试计划](08-testing.md)。

> 【数字口径说明】本文规模数字以实际清点为准：**37 个编码改动点**（C-NR-100~604）= M1 7 个（100~106）+ M2 **10 个**（201~208 **+ 307 自驱 hardclock + 308 应用 mempool 分代际**）+ M3 6 个（301~306）+ M4 6 个（401~406）+ M5 4 个（501~504）+ M6 4 个（601~604）。集成用例 8 条、实机用例 16 行（RT-00~14，含 RT-04b）见 [08](08-testing.md)。
>
> **v1.2 修正**：v1.0/v1.1 正文残留的「35」未计入 v1.7 新增的 C-NR-307/308，与摘要的 37 自相矛盾，此处统一为 37。C-NR-307/308 虽编号为 3xx，但语义上属「新旧代际共存的前提改造」（绕开共享 timer 槽与 mempool cache 竞态），故归属 M2 而非 M3。来源产物 work/milestones-testing.md 中的同源旧数字（41/6/13）系中间产物原文，不回改；如与本文冲突以本文为准。

## 关键结论

1. **最强回滚点仍是配置级**：`graceful_reload=0`（默认）⇒ reload 行为与现状逐字一致（[06](06-solution-design.md) 5.4-3 的 0 回归原则）。所有里程碑的代码都以该开关门控，与 primary_slim 的 `primary_slim=0` 同构。
2. **M0 必须先行解决三个一票否决预研项（v1.2 据 [06] v1.6/v1.7 重列）**：
   - **RV7**（双代际栈隔离 listen 同 IP:port 是否真不冲突——[04](04-fstack-current-analysis.md) §3.5 仅为静态推断）：失败则方案需重新评审。
   - **RV3**（同期移交的跨进程互斥正确性——G_old 停 poll 与 G_new 起 poll 的串行化是否可靠，残余风险为 virtqueue 数据结构并发损坏，**静态无法定论**）：失败则 S3 主路径不成立。
   - **RV10**（v1.6 新增：新旧进程同核处理时切换瞬间的流量/丢包/CPU 抢占）：失败则需回退到「新旧进程各占独立物理核」形态（代价是稳态预留一倍核）。

   三者**在 M1 开工前必须出结论**。~~RV2（reta 运行时更新）~~ 已随 v1.6「reta 不改」决策**取消**——S3 不再依赖任何 NIC RSS 能力，virtio 与物理网卡均可用。
3. **本文 M 编号与 [06](06-solution-design.md) 的 M1/M2 不同名不同义**：本文 M1+M2+M3+M4 合起来 = 方案设计的 S3-M1；本文 M7 = S3-M2。映射表见第 0.2 节，后续文档引用本文编号时以此为准。
4. **M2（新旧并存）是风险最集中的里程碑**：它一次性引入多 secondary 双代际并存（RV1）、**proc_id 代际无关固定映射**校验（DR5，v1.6 取代原乒乓段）、FF_RELOAD 控制消息（DR4）、以及 v1.7 的**自驱 hardclock（C-NR-307）与应用 mempool 分代际（C-NR-308）**两项底层改造，且删除了现状两段串行 reload 的「安全」行为——该里程碑必须独立成提交串、独立验收，不得与 M3 混批。**C-NR-307 改动的是 timer 心跳这一全局基础机制，须按最高回归风险对待**。
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
| RV1-10 | [06](06-solution-design.md) §6.1 运行时验证项 | A-NR-xx | 验收标准（[08](08-testing.md)） |
| DR1-7 | [06](06-solution-design.md) §6.2 设计评审项 | RG-NR-xx | 回归项（[08](08-testing.md)） |

### 0.2 本文里程碑与方案设计阶段的映射

| 方案设计（06 篇） | 本文里程碑 | 内容 |
|---|---|---|
| （前置，S3 依赖） | M0 | 预研定案 + 基线采集 |
| S3-M1 | M1 → M2 → M3 → M4 | 常驻 primary 化 → 新旧并存 → 同期移交+flow_map 转发兜底 → drain 收尾+状态机完备 |
| S3-M1 收尾 | M5、M6 | USR2 升级路径；循环 reload 终门禁 + 特殊场景回归 + 文档 |
| S3-M2 | M7（可选） | dispatcher 中心化（DR7 触发才立项） |

### 0.3 RV1-10 分配总表

> v1.2 据 [06] v1.6/v1.7 重列。~~RV2（reta 运行时更新）~~ 已取消（reta 不改）；RV3 由「降级变体」升为**主路径**；RV6 因 v1.7 自驱 hardclock 而性质改变（不再是「槽隔离」而是「自驱精度回归」）；新增 RV10。

| RV | 项目（[06](06-solution-design.md) §6.1） | 首验里程碑 | 复验/关闭里程碑 |
|---|---|---|---|
| RV1 | **N+N 双代际** worker + 1 slim primary 多 secondary 并存稳定性（同队列，不配 2N 队列） | M2 | M6（长稳） |
| ~~RV2~~ | ~~reta 运行时更新在目标 PMD 的支持度与生效时延~~ | **已取消**（v1.6：reta 不改，不依赖 NIC RSS） | — |
| RV3 | **同期移交互斥正确性**（v1.6 主路径，不再是可选变体）：跨进程互斥标记保证 G_old 停 poll 后 G_new 才起 poll；移交窗口靠 NIC rx ring（RX_QUEUE_SIZE 4096）兜底；残余风险为 virtqueue 数据结构并发损坏（静态无法定论）；**virtio 无 `imissed`，guest 侧不可观测** | **M0**（PoC，一票否决项） | M3（集成后复测）、M6（长循环） |
| RV4 | dispatch_ring 转发吞吐/时延（drain 高峰；v1.6 下 drain 期**存量连接 100% 流量**走 ring） | M3 | M6（循环 reload 期间） |
| RV5 | flow_map 查表开销【仅 reload 窗口，稳态零开销】 | M3 | M6（PT-NR-06 关闭） |
| RV6 | **自驱 hardclock 的 timer 精度回归**（v1.7 改写：不再是「不同 lcore 的 `priv_timer` 槽隔离实测」——同 lcore_id 共存下共享槽已被自驱方案绕开；此处改为验证 TSC 自驱 `ff_hardclock()` 的 RTO/keepalive/延迟 ACK 精度与 `graceful_reload=0` 行为等价性） | M0（双进程共存初验） | M2（自驱 hardclock 合入后专项回归） |
| RV7 | 多代际栈隔离 listen 同 IP:port 实际行为 | **M0**（PoC，一票否决项） | M2（正式链路） |
| RV8 | KNI 启用场景与双代际 worker 交互 | M6 | M6 |
| RV9 | 端到端循环 reload 门禁（v1.6 修订：≥100 次） | M4（20 次小规模） | **M6（终门禁，≥100 次）** |
| **RV10**（v1.6 新增） | **同核处理新旧进程的切换瞬间性能**：两代进程同核时各得约 50% 有效算力 + 上下文切换/cache 抖动，切换瞬间的流量/丢包/CPU 抢占；以及「drain 变慢 → 抢核更久」的正反馈 | **M0**（PoC，一票否决项） | M3/M6（高负载压测） |

### 0.4 DR1-7 前置评审分配总表

| DR | 项目 | 评审时点（对应里程碑开工前） |
|---|---|---|
| DR1 | reload 编排者：master vs slim primary（倾向 master 编排 + primary 原语） | **M0**（决定 M1 的 primary 拉起方式与 M2 状态机归属） |
| DR2 | 旧连接归属判定：实时查询 vs 快照表（两形态均须遵守流表窗口化：READY 后生效、排空确认后关表，[06] 第 2 节语义 6） | M0（接口初评）→ **M3 开工前定案**（RV5 数据支撑） |
| ~~DR3~~ | ~~reta 切流 vs 末期一次性队列移交~~ | **已取消**（v1.6：reta 不改，同期移交为唯一主路径，见 [06] §6.2 DR3） |
| DR4 | reload 控制通道载体（v1.6 已定）：移交互斥用**共享内存标记**（非 msg ring），READY/DRAIN_DONE/REJECT 用 msg ring | **M2 开工前** |
| DR5 | **proc_id 代际无关固定映射**的配置表达与校验链（v1.6 取代原「乒乓 lcore 段」）：worker 数与 queue 数一致、primary lcore 排除、代际映射唯一性；同核 vs 独立物理核的部署形态选择（[06] §6.3，X3 决策：同核为默认） | **M2 开工前** |
| DR6 | 异常回退完备性（每阶段回退目标态） | **M4 开工前** |
| DR7 | M7（dispatcher 中心化）启动判据与阈值 | **M7 立项评审**（M6 数据齐后；v1.3 修订暂定阈值：reload 窗口内转发开销致吞吐下降 >5%、或 drain 期 P99 劣化 >10%、或高存量连接场景 drain 时长超 SLO——流表窗口化后稳态损耗恒 0，原稳态阈值失效，见 [06] §6.2 DR7） |

### 0.5 8 项障碍（[04](04-fstack-current-analysis.md) §4）→ 里程碑消解映射

| 障碍 | 内容 | 消解里程碑 | 机制（v1.6/v1.7） |
|---|---|---|---|
| 1 | 两段串行空窗 | M2 + M3 | 并存 + **同期移交**（跨进程互斥标记保证队列始终有主；~~reta 切流~~ 已废弃） |
| 2 | listening fd 无法跨进程 | M2 | 回避式：栈隔离多代际 listen（RV7 验证） |
| 3 | TCP 连接无迁移 | M3 + M4 | **flow_map miss → dispatch_ring 转发兜底** + drain |
| 4 | primary 单点/硬编码 | M1 | 全 secondary + 常驻 slim primary |
| 5 | respawn/时序脆弱（500ms/15s） | M2 | 显式 READY 协议取代 |
| 6 | master 不在数据面 | M2 + M3 | master 编排 + primary 原语（DR1） |
| 7 | RSS 静态映射窗口 | M3 | **同期移交 + 互斥**（reta 不改 → `ff_rss_check`/`adjust_sport`/`tbl`/`thash` 四件套不变；~~reta 原子切流（DR3）~~ 已取消） |
| 8 | 定时器随进程消亡 | M2 | **自驱 hardclock（C-NR-307，v1.7）**：main_loop 按 TSC 间隔直调 `ff_hardclock()`，绕开同 lcore_id 下的共享 `priv_timer[]` 槽（~~乒乓分核 → timer 槽天然隔离~~ 已随同核方案失效） |
| 补充 | worker QUIT 缺 ngx_set_shutdown_timer | M4 | 补回（修 bug 性质，独立可先做） |

## 1. 里程碑总览

| 里程碑 | 目标 | 编码点数 | 主要文件 | 前置 | 独立验收 | 回退点 |
|---|---|---|---|---|---|---|
| **M0** 预研定案 | **RV7/RV3/RV10** 一票否决项出结论；DR1/DR4/DR5 定案；基线数据 | 0（PoC 脚本/报告） | 无正式编码 | 无 | ✅ | — |
| **M1** 常驻 primary 化 | nginx worker 全 secondary，slim primary 常驻不随 reload 退出；`graceful_reload` 开关落地 | 7（C-NR-100~106） | `ngx_ff_module.c`/`ngx_process_cycle.c`/`ff_config.{h,c}`/`config.ini` | M0（DR1 定案）；primary_slim 已合入 | ✅ | `graceful_reload=0` + revert 提交串 |
| **M2** 新旧并存 | **proc_id 代际无关固定映射**（v1.6 取代乒乓段）+ FF_RELOAD 消息族 + READY 协议 + **自驱 hardclock（C-NR-307）/ 应用 mempool 分代际（C-NR-308）**（v1.7）；双代际 worker 并存；删除两段串行 reload（条件化） | **10（C-NR-201~208 + 307/308）** | `ff_config.{h,c}`/`ff_msg.h`/`ff_dpdk_if.c`/`ngx_process_cycle.c`/新增 `ngx_ff_reload.c` | M1；DR4/DR5 评审 | ✅ | `graceful_reload=0` 走旧路径 |
| **M3** 同期移交+flow_map | **flow_map 软件分发表** + **跨进程互斥原语** + ARP/NDP clone + RX_QUEUE_SIZE 放大；旧连接包经 flow_map miss → dispatch_ring 转发（**reta 不改**） | 6（C-NR-301~306） | `ff_api.h`/新增 `ff_flow_map.c`/`ff_handover.c`/`ff_dpdk_if.c`/`ngx_ff_module.c` | M2；DR2/DR4 定案 | ✅ | 移交消息不触发即回退（状态机停 T2） |
| **M4** drain 收尾 | 补 shutdown timer、drain 上报与强退、T0-T5 状态机完备、异常分支；HUP 全链路打通 | 6（C-NR-401~406） | `ngx_process_cycle.c`/`ngx_ff_reload.c`/`ff_msg.h` | M3；DR6 评审 | ✅ | 各点独立 revert |
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
| E-NR-03（RV6 初验） | 双进程共存期的 TCP 定时器行为（v1.7 起改为**自驱 hardclock 精度**的基线采集） | E-NR-01 的双实例运行期间观测 RTO/keepalive 精度与 `rte_timer` 状态（ff_top/sysctl 采样）；**并采集改造前的 `rte_timer` 挂槽基线**，供 C-NR-307 合入后做等价性对比 | 无 timer 重复触发/停摆迹象；TCP 定时器精度正常；基线数值落盘 | 升级为 blocker，评审 timer 机制补强 |
| E-NR-04 | 现状串行 reload 基线数据（[04](04-fstack-current-analysis.md) §5-3） | 现状代码跑一轮 HUP reload：实测空窗时长（服务不可用窗口）、reload 总时长、期间丢包/失败数 | 产出基线数值（用于 A-NR-14 的 reload 耗时上限与 PT-NR-03 对照） | — |
| E-NR-05 | 性能基线采集（PT-NR-01 前置） | 按 primary_slim 06 方法：`ab -k -c 50 -n 20000 http://<DPDK_NIC_IP>/`，3 轮取区间 | 产出改造前稳态 QPS/延迟基线 | — |
| **E-NR-06（RV10，一票否决，v1.6 新增）** | **同核处理新旧进程的切换瞬间性能**：两代进程同核（同物理核、不同 lcore_id）时，切换瞬间的流量/丢包/CPU 抢占，以及 drain 期各得约 50% 算力造成的「drain 变慢 → 抢核更久」正反馈 | 双代际同核共存压测：稳态基线 → 触发移交 → 观测切换瞬间 pps/丢包/两侧 CPU 占用 → 持续至 drain 完成，记录 drain 时长相对独立核形态的延长幅度 | 产出量化数据：切换瞬间丢包数、两侧有效算力占比、drain 时长延长倍数 | 回退到「新旧进程各占独立物理核」形态（[06] §6.3：稳态需预留一倍核，但 drain 期性能可预测） |
| 评审 | DR1（编排者 + slim primary 拉起方式）、DR5（proc_id 代际无关映射 + 同核/独立核部署形态）、DR4（控制通道载体）、DR2 初评（flow_map 形态） | 评审会，结论更新回 [06](06-solution-design.md) 或本文附录 | 定案记录在案 | — |

> **E-NR-06 与 E-NR-02b 的不可分割性**：RV10（同核性能）与 RV3（移交互斥）都依赖「双代际共存」这一前提，建议合并为同一个 PoC 脚本的两次实验，避免重复搭建环境。

**slim primary 拉起方式（DR1 评审的两个候选，M1 编码按定案执行）**：
- 候选 a（独立常驻进程）：部署形态新增一个 systemd unit 拉起的 slim primary 守护进程；nginx master 启动时探测其存活（EAL attach 失败即报错退出）。运维形态变化明确，primary 生命周期与 nginx 完全解耦。
- 候选 b（master 代管 + double-fork 脱离）：nginx master 首次启动时检测 primary 缺席则 spawn 专职 slim primary 子进程并 double-fork/setsid 脱离 master 生命周期，reload/USR2 均不对其发信号。nginx 语义内聚，但需处理老 master 退出不波及 primary 的细节。
- 本规划倾向候选 b（运维零新增），最终以 DR1 评审为准；两候选在 M1 的差异仅在 C-NR-100/101 两点。

| 项 | 内容 |
|---|---|
| **DoD** | E-NR-01（RV7）/**E-NR-02b（RV3）**/**E-NR-06（RV10）** 三项一票否决项出明确结论；DR1/DR4/DR5/DR2 初评有书面定案；基线数据落盘 `work/m0-poc-report.md` |
| **测试门禁** | 本身即测试产出；无代码门禁 |
| **风险与回退** | RV7/RV3/RV10 任一失败 → 按「失败换档」列处理，M3 范围调整或方案回炉（RV3 失败则退 [06] §4.2 的 S4 蓝绿多实例）；不产生主线代码风险 |
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
| C-NR-104 | `ngx_process_cycle.c:443-510`（sem 同步块） | 修改 | `graceful_reload=1` 时跳过 master 的 15s sem 等待（primary 常驻已就绪），改为 attach 确认（worker 0 ff_mod_init 成功即上报，超时语义保留）；`=0` 时逐字保留现状 |
| C-NR-105 | `ngx_process_cycle.c:1251-1256`（primary 退前 500ms） | 修改 | `graceful_reload=1` 时无 primary worker，该分支自然不触发；条件化保留供 `=0` |
| C-NR-106 | `config.ini` 注释块 + `doc/F-Stack_Nginx_APP_Guide.md` | 文档 | `graceful_reload` 注释掉的示例项 + 与 primary_slim 的配合说明；本地测试值不入库 |

| 项 | 内容 |
|---|---|
| **前置** | M0（DR1 定案）；primary_slim 已合入主线 |
| **DoD** | ① clean build 全绿；② 单测 UT-NR-01~03/07~09 全绿 + 既有 TC 零回归；③ 实机 RT-00（启动基线）：`graceful_reload=1` 下 nginx 正常启动收发（此阶段 reload 仍串行，行为不劣化）；④ `graceful_reload=0` 时与现状逐字一致 |
| **测试门禁** | UT（[08](08-testing.md) §1）+ RT-00 + RG-NR-01 |
| **风险与回退** | 风险：常驻 primary 与 nginx 生命周期的拉起/探测细节（候选 b 的 double-fork）；回退：`graceful_reload=0` 或整体 revert C-NR-100~106（一个自洽提交串） |
| **提交建议** | 2~3 个 commit：lib 配置项 / nginx secondary 化 / primary 拉起 |

### 2.3 M2：新旧 worker 并存与 FF_RELOAD 协议（v1.6：proc_id 代际无关固定映射，不再乒乓）

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 1（前半）/2/5/8：reload 改回原生「先起新再退旧」顺序；G_new 与 G_old 并存（v1.6：同队列，proc_id 代际无关固定映射）；READY 显式协议取代 500ms/15s 时序 |
| **范围** | [06](06-solution-design.md) 5.4-2（FF_RELOAD 消息族）、5.4-3（proc_id 代际无关配置）、5.4-4 第 1 条（两段式条件化）；时序 T0-T2 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-201 | `lib/ff_config.h`（dpdk 段）+ `ff_config.c` 解析/校验（`:1414-1519` 区域） | 修改 | ~~`reload_lcore_policy=pingpong`~~ → v1.6 改为：**proc_id 代际无关固定映射**配置项（G_new 启动时直接用 G_old 的 proc_id/queue 映射，[06] 第 2 节语义 8）；V-NR 校验链：worker 数与 queue 数一致、primary lcore 排除、`graceful_reload=0` 时全部新校验不生效 |
| C-NR-202 | `lib/ff_msg.h:37-53` 旁 | 新增 | FF_RELOAD 消息族（v1.6 修订）：`FF_RELOAD_READY` / `FF_RELOAD_HANDOVER_REQ`（移交请求，[06] 第 2 节语义 7）/ `FF_RELOAD_HANDOVER_ACK` / `FF_RELOAD_DRAIN_PROGRESS` / `FF_RELOAD_DRAIN_DONE`（G_old 排空确认→G_new 关 flow_map 回稳态）/ `FF_RELOAD_REJECT`（防重入）；~~SWITCH_REQ/SWITCH_ACK~~ → 改为 HANDOVER 语义（v1.6 不切流，同期移交） |
| C-NR-203 | `lib/ff_dpdk_if.c:2404-2454`（handle_msg） | 修改 | FF_RELOAD 处理器注册与分派；容量/实时性按 DR4 结论 |
| C-NR-204 | `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:223-270` | 修改 | **两段式 reload 块整体条件化**：`graceful_reload=1` 走原生顺序（fork G_new JUST_RESPAWN → 等 READY → 同期移交[M3] → G_old QUIT）；T1~T5 期间再次收到 HUP → **拒绝并记日志（reload 防重入，[06] 第 2 节语义 6）**；`=0` 逐字保留旧两段式 |
| C-NR-205 | 新增 `app/nginx-1.28.0/src/event/modules/ngx_ff_reload.c` + `auto/sources` 挂载 | 新增 | **reload 编排状态机**：T0-T5 状态枚举 + 纯转移函数 + 每阶段打点（状态日志 + ff_top 可见计数）；master 侧驱动 |
| C-NR-206 | `lib/ff_config.c` proc_lcore 分配（`ff_dpdk_if.c:508-538` 消费侧）+ `ngx_process_cycle.c:1123` | 修改 | ~~代际号→段号取模~~ → v1.6 改为：**proc_id 代际无关固定映射**——G_new worker 的 proc_id 直接使用与 G_old worker 相同的值（消除审核 B-1 乒乓代际 proc_id 重合导致 lcore/queue/msg_ring 全重合的静默内存损坏问题） |
| C-NR-207 | `ngx_process_cycle.c:762-764`（respawn 条件） | 修改 | `graceful_reload=1` 时恢复原生 respawn 语义（reload 期间 worker 挂了允许重生或按状态机决策，DR6 定） |
| C-NR-208 | worker 侧 READY 上报 | 新增 | worker 完成 `ff_freebsd_init` + `ngx_open_listening_sockets` 后经 FF_RELOAD_READY 上报 master |
| C-NR-307 | `lib/ff_dpdk_if.c` init_clock(:1244-1257)/init_clock_worker(:1262-1272)/main_loop(:2804-2805) | 修改 | **自驱 hardclock**（[06] 第 2 节语义 11，v1.7）：init_clock 删除 `rte_timer_subsystem_init/rte_timer_meta_init/rte_timer_init/reset` 四连，改为计算 `hardclock_interval_tsc = hz_tsc / freebsd.hz`；main_loop 的 `if (freebsd_clock.expire < cur_tsc) rte_timer_manage()` 改为 `if (next_hardclock_tsc < cur_tsc) { ff_hardclock(); ff_update_current_ts(); next_hardclock_tsc += interval; }`——绕开同 lcore_id 下的共享 `priv_timer[L]` 槽（meta_init memset 踩链 + manage 跨进程私有地址解引用双重致命）。**可提前独立提交**（同 C-NR-401 性质：`graceful_reload=0` 也生效且行为等价，需回归 timer 精度） |
| C-NR-308 | `lib/ff_dpdk_if.c` mempool 创建(:616-638) + ff_mbuf_get/clone alloc 点(:2563/:2705/:2172/:2188) | 修改 | **应用 mempool 分代际 + 方案 A cache_size=0**（[06] 第 2 节语义 12 / §6.6，v1.7 已定）：① primary reload 触发时创建第二代 `mbuf_pool_%d_gen2`（或 init 期预建），G_new secondary lookup 并在 TX/clone/ref 的 alloc 点使用本代际 pool；跨代 free 自动回正确 pool（`m->pool`）；② **方案 A**：`graceful_reload` 部署形态下 `pktmbuf_pool` 创建参数 `MEMPOOL_CACHE_SIZE`→0（:633-634），alloc/free 走 common pool 无锁 ring（多进程安全，iWiki 验证路线）；性能损失以 PT-NR-01 基线对比量化；③ 备选方案 B（仅当 A 实测不可接受）：`local_cache[]` 索引从 lcore_id 改 workerid/代际 id（DPDK `rte_mempool.c` 本地补丁） |

| 项 | 内容 |
|---|---|
| **前置** | M1 合入；**DR4/DR5 评审完成** |
| **DoD** | ① clean build + 单测（UT-NR-04~06/10/12/**17/18**/15~16 + 零回归）；② 实机 RT-01（空载 reload：双代际并存、各自 listen、G_old 退出后 G_new 独自服务——此阶段尚未做同期移交，判据放宽为：reload 完成、服务最终恢复、无 crash）；③ RV1 初验（双代际共存 ≥30min 无异常，含 mbuf 水位平稳无泄漏趋势）；④ **RV6 复验（C-NR-307 自驱 hardclock 专项回归：RTO/keepalive/延迟 ACK 精度与 E-NR-03 改造前基线等价，且 `graceful_reload=0` 行为不变——PT-NR-08）**；⑤ **C-NR-308 mempool 分代际：跨代 alloc/free 无泄漏、无 pool 错配（PT-NR-09 观测 mbuf 水位与 `rte_mempool_avail_count`）** |
| **测试门禁** | UT（含 UT-NR-17/18）+ RT-01 + RV1/RV6 观测记录 + PT-NR-08/09 |
| **风险与回退** | 风险：① 多 secondary 并存的 mempool/EAL/msg_ring 并发（RV1 主体风险，primary_slim 已有 2 secondary 先例但未到双代际）；② **C-NR-307 自驱 hardclock 改动 timer 心跳这一全局基础机制，精度劣化或漏触发会静默影响 RTO/keepalive，是本项目回归风险最高的单点**；③ C-NR-308 方案 A `cache_size=0` 的稳态性能损失可能超预期（备选方案 B 待命）；④ proc_id 代际无关固定映射配置错误导致 msg_ring 冲突（C-NR-206 校验拦截）。回退：`graceful_reload=0`（FF_RELOAD 不注册、reload 走旧路径）；C-NR-201~208 与 C-NR-307/308 各自独立提交串可分别 revert |
| **提交建议** | 5~6 个 commit：配置与校验 / FF_RELOAD 消息族 / 状态机与 reload 顺序 / READY 协议 / **自驱 hardclock（独立，先于其余合入以便单独回归）** / **应用 mempool 分代际** |

### 2.4 M3：同期移交队列+listen 与 flow_map 软件分发表（v1.6：reta 不改，主路径）

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 3/6/7：G_new READY 后同期移交队列消费权 + listen（跨进程互斥标记保证不并发 poll）；G_new 注册 flow_map 软件分发表（只记新流，miss 转 G_old）；ARP/NDP clone 给 G_old；reta 不改（rss_check 四件套不变）；RX_QUEUE_SIZE 4096 增大移交窗口缓冲 |
| **范围** | [06](06-solution-design.md) 5.4-1（flow_map 三函数+互斥原语+ARP clone）、5.2 时序 T3 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-301 | `lib/ff_api.h` + 新增 `lib/ff_flow_map.c` | 新增 | **flow_map 三函数**：`ff_flow_map_lookup(four_tuple)` / `ff_flow_map_insert(four_tuple)` / `ff_flow_map_close()`（排空确认后关闭回稳态，[06] 第 2 节语义 6）——软件分发表替代 ~~ff_conn_owner_query~~ inpcb 查询，避免 syncache/inpcb 语义漏洞（审核 B-3/Q3b）。**【v1.2 修正·入表时机】**：插入点必须是**本栈收到 SYN 并发出 SYN-ACK 的时刻**（即 `syncache_insert` 完成、连接进入 syncache 半开态时），**不得**推迟到 `accept()` 返回时——三次握手的第 3 个 ACK 到达时连接仍在 syncache、尚无 inpcb，`accept()` 尚未发生；若按「accept 时入表」，该 ACK 会 flow_map miss → 被转给 G_old → G_old 无对应 syncache 条目 → 回 RST → **reload 窗口内新建连接全失败**（这正是 B-3/Q3b 的原始病根，仅换了一层形式）。实现须在 `tcp_input` 的 listen 分支（syncache 插入成功后）挂钩入表，并同步覆盖 SYN 重传（重传 SYN 命中已有表项，不重复插入） |
| C-NR-302 | 新增 `lib/ff_handover.c` 或扩展 `lib/ff_dpdk_if.c` | 新增 | **跨进程互斥原语** `ff_queue_handover_mutex(port, queue, from_gen, to_gen)`：共享内存标记（非 msg ring）——G_old 设停 poll 标记 + 确认已停 → G_new 确认后起 poll；保证不同时 poll 同一 queue（[06] 第 2 节语义 7）。~~set_rss_table 切流原语改造~~ v1.6 删除（reta 不改） |
| C-NR-303 | `app/nginx-1.28.0/src/event/modules/ngx_ff_module.c`（worker init） | 修改 | G_new worker **READY 后自动注册** flow_map 查表回调（[06] 第 2 节语义 6，稳态零开销）：**① 先做协议过滤——仅 TCP/UDP 四元组参与归属判定，ARP/NDP/ICMP/非 IP/分片一律返回 `queue_id`（本栈处理），保留原生克隆路径**（否则 G_new 邻居表建不起来，见 C-NR-304）；② 解析四元组 → `ff_flow_map_lookup` → 命中（本代际新流，含 syncache 中的半连接）本栈处理 / **miss 一律**经 dispatch_ring 转 G_old（ff_dpdk_if.c:2142-2150 现成 enqueue 路径）；③ **目标 G_old 队列须精确反算**（同队列方案下即 G_old 的 queue_id，须按 proc_id 代际无关映射表查得，不得凭空假设），并校验目标存活——G_old 已退出则本栈处理并按 TCP 规范回 RST，禁止 enqueue 到无主 ring；④ **排空确认后注销回调**（C-NR-403 通知驱动，含「dispatch_ring 已排空」条件，见 U-NR-5） |
| C-NR-304 | `lib/ff_dpdk_if.c:2105-2183`（process_packets ARP/NDP 分支） | 修改 | **ARP/NDP clone 给 G_old**（[06] 第 2 节语义 9；审核 B Q3a）：ARP/NDP 等协议包在转给 G_new 协议栈处理的同时，额外 clone 一份转发给所有 G_old 进程——原有 clone 给其他 G_new 和 KNI 的逻辑不变（:2161-2183），新增 clone 给 G_old 分支 |
| C-NR-305 | `lib/ff_memory.h:43`（RX_QUEUE_SIZE）+ `lib/ff_config.{h,c}` | 修改 | RX_QUEUE_SIZE 默认 512→**4096**（[06] 第 2 节语义 7：移交窗口缓冲放大 8 倍）；~~dispatch_ring 容量配置项~~ 保留为 RV4 观测后按需（默认保持现值） |
| C-NR-306 | `ngx_ff_reload.c` 状态机 | 修改 | T3 状态（v1.6 时序）：master 触发同期移交→G_old 停 poll（互斥标记）→G_new 起 poll+接管 listen→G_new 注册 flow_map→ARP/NDP clone 生效；~~SWITCH_REQ reta 切流~~ 改为 HANDOVER 消息族；超时/失败分支（DR6 前半） |

| 项 | 内容 |
|---|---|
| **前置** | M2 合入；**DR2/DR4 定案**（flow_map 形态 + 控制通道载体） |
| **DoD** | ① clean build + 单测（UT-NR-11/13/14 + 零回归）；② 实机 RT-02（带长连接流量 HUP：新连接全走 G_new、旧连接包 flow_map miss → ring 转发回 G_old 零 RST、ARP/NDP 正常）；③ RT-03（持续 CPS 压力下 reload，客户端错误 0）；④ RV3 互斥正确性 + RV4/RV5 实测数据落盘（DR7 输入） |
| **测试门禁** | UT + IT-NR-A02/A03/A07/A08 + RT-02/RT-03 |
| **风险与回退** | 风险：RV3 互斥标记实现缺陷导致并发 poll（virtqueue 数据结构损坏，静态无法定论需实测）；RV4 ring 容量；RV5 flow_map 查表开销。回退：移交消息不触发（状态机停在 T2，G_old 继续服务，本轮 reload 放弃）；互斥标记保证不会并发 poll；`graceful_reload=0` 兜底 |
| **提交建议** | 4 个 commit：flow_map 三函数 / 互斥原语 / ARP clone+RX_QUEUE_SIZE / 回调注册与状态机 T3 |

### 2.5 M4：drain 收尾、异常回退与状态机完备（HUP 全链路）

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 3（drain 保障）与 [04](04-fstack-current-analysis.md) §4 补充事实：T4/T5 落地——G_old 关自身 listen、drain 存量连接至自然关闭、drain 挂起强退兜底、flow_map 关表回稳态（v1.6：~~lcore 段乒乓翻转~~ 已取消，同队列方案无段翻转）；T0-T5 全链路 + 全部异常分支打通 |
| **范围** | [06](06-solution-design.md) 5.4-4 第 3/4 条、DR6 全部回退目标态、5.2 异常分支 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-401 | `ngx_process_cycle.c:894-898`（对照原生 :951-957） | 修改 | **补回 `ngx_set_shutdown_timer`**（F-Stack 版 worker QUIT 分支缺失，[04](04-fstack-current-analysis.md) §4 补充事实）；此项是修 bug 性质，可提前独立提交（不依赖 M1~M3，`graceful_reload=0` 也受益） |
| C-NR-402 | `ngx_ff_reload.c` + `ff_msg.h` | 新增 | drain 进度上报（FF_RELOAD_DRAIN_PROGRESS：剩余连接数/最后活动时间）+ **G_old 排空确认上报（FF_RELOAD_DRAIN_DONE：连接数=0 且全部 G_old 进程退出）** + drain 强退阈值（shutdown timer 时长，默认建议对齐 nginx `worker_shutdown_timeout` 语义，值经 RT-06 校准） |
| C-NR-403 | `ngx_ff_reload.c` | 修改 | 状态机 T4/T5：收 G_old 全退 SIGCHLD/DRAIN_DONE → **通知 G_new 关闭 flow_map，G_new 进入稳态成为下轮 G_old（防性能退化，[06] 第 2 节语义 6；防重入拦截随排空确认解除）** → ~~释放段 A → 乒乓翻转记账~~（v1.6 删除：不再乒乓，同队列）→ reload 完成打点 |
| C-NR-404 | `ngx_ff_reload.c` 异常分支 | 修改 | ① T2 前 G_new 任一 worker 起不来/READY 超时 → 放弃本轮（G_old 未动，对齐内核 HUP 配置失败回滚语义）；② T3 移交失败（G_old 未确认停 poll / G_new 起 poll 超时）→ 放弃本轮（互斥标记保证不会并发 poll，[06] 5.2 异常分支）；③ primary 被 kill（数据面不受影响但互斥原语不可用）→ 本轮 reload 安全放弃 + 告警（primary_slim E10：primary 不可复活，运维择机全组重启） |
| C-NR-405 | `ngx_process_cycle.c` G_old graceful 分支 | 修改 | G_old 收 QUIT：各自栈内 close listening（只影响自己栈）+ 停 accept + 继续跑 ff_run drain；**存量连接后续包落到 G_new 队列后，经 flow_map miss → dispatch_ring 转发回来（M3 已铺；v1.6 同队列方案下 reta 不变，落点不变，只是消费者换成 G_new）**。注：v1.6 下 drain 期存量连接流量**100%** 走 ring 转发（非 v1.0 假设的「部分桶重哈希」），RV4 的 ring 容量与背压压力按此量级评估 |
| C-NR-406 | 打点与可观测收尾 | 新增 | 每阶段耗时/计数落 ff_top 或日志（reload 总时长、切流时延、drain 时长、转发包量），供 PT-NR-03 与 A-NR-14 度量 |

| 项 | 内容 |
|---|---|
| **前置** | M3 合入；**DR6 评审完成** |
| **DoD** | ① clean build + 单测（UT-NR-10 状态机全转移 + 零回归）；② 实机 HUP 全链路：RT-01~RT-03 复跑全绿 + RT-05/06/07/09 异常注入全绿 + RT-10（连续 20 轮 reload：**每轮 proc_id 映射一致、无资源泄漏、抢先 HUP 被正确拒绝**）；③ RT-14（同核高负载切换，RV10 集成复验）；④ RV9 小规模预演：带流量连续 reload 50 次零错误 |
| **测试门禁** | UT + RT-01~RT-10 + 50 次循环 reload |
| **风险与回退** | 风险：drain 强退阈值过短误杀长连接（RT-06 校准）；异常分支状态机死锁（用例覆盖每分支）。回退：C-NR-401 独立；402~406 独立提交串 revert 后 M3 行为保留（drain 依赖 nginx 原生 no_timers_left，无强退兜底） |
| **提交建议** | 3 个 commit：shutdown timer（可提前）/ drain 上报与强退 / 状态机 T4-T5 与异常分支 |

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
| **前置** | M4 合入 |
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
| C-NR-604 | `doc/F-Stack_Nginx_APP_Guide.md`、`doc/F-Stack_Release_Note.md`、`config.ini` 注释 | 文档 | 部署形态（常驻 primary + proc_id 代际无关固定映射 + graceful_reload 开关矩阵）、运维手册（reload 状态打点解读、primary 死亡降级处置、drain 强退阈值调优）、语义变更声明 |

| 项 | 内容 |
|---|---|
| **前置** | M4（M5 可并行推进） |
| **DoD** | ① RV9：持续流量 + 每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次，≥100 次零错误、无死锁无 crash、mbuf/内存无泄漏趋势（v1.6 修订：原「每 2~5s reload、≥1000 次」与防重入语义+25s 初始化不可同时成立）；② RT-12/13 通过（或出明确结论与限制声明）；③ 全部 RV1-10 关闭记录在案；④ 文档入库 |
| **测试门禁** | PT-NR-05 终门禁 + 全量 RT 矩阵复跑 |
| **风险与回退** | 风险：长循环暴露的低概率状态错位（VPP #3547/#3645 前车之鉴，[01](01-vpp-vcl-research.md) §4.3/§6.4）——这正是门禁价值所在，暴露即回 M4 状态机修。回退：无代码回退需求 |
| **提交建议** | 2 个 commit：测试脚本 / 文档 |

### 2.8 M7（可选）：dispatcher 中心化（S3-M2）

仅当 DR7 触发（M6 数据，v1.3 修订判据——流表窗口化后稳态损耗恒 0，原稳态判据失效：改为 **reload 窗口内**转发开销致吞吐下降 >5%、或 drain 期 P99 劣化 >10%、或高存量连接场景 drain 时长超 SLO）才立项。方向：slim primary 统一收包 + 流表分发，worker 变纯 ring 消费者（VPP app_listener workers bitmap 同构 + 旧 iWiki dispatch 思想现代化，避开同核共存）。**若触发须另立 spec 重新走本流程**，本文不展开。

## 3. 后续编码工作清单汇总（按提交批次）

**37 个编码点**已按里程碑列于第 2 节各表。此处仅给跨里程碑的总依赖序（DAG 摘要）与并行度建议：

```
M0(E-NR-01  RV7
  +E-NR-02b RV3  移交互斥   ── 一票否决
  +E-NR-06  RV10 同核切换)  ── 一票否决
  + E-NR-03/04/05 基线与初验 + DR1/DR4/DR5/DR2 定案
        │
        ▼
  C-NR-100/101 ──> 102/103 ──> 104/105 ──> 106                              [M1  7]
        │
        ▼ (DR4/DR5)
  C-NR-201/206 ──> 202/203 ──> 205 ──> 204/207 ──> 208                       [M2 10]
  C-NR-307（自驱 hardclock，**建议最先合入**，独立回归 RV6/PT-NR-08）
  C-NR-308（应用 mempool 分代际，依赖 307 之后的共存验证，PT-NR-09）
        │
        ▼ (DR2/DR4 终案)
  C-NR-301 ──> 302 ──> 303 ──> 304/305 ──> 306                               [M3  6]
C-NR-401（shutdown timer，可提前至任意时点独立提交）
        │
        ▼ (DR6)
  C-NR-402/403 ──> 404 ──> 405/406                                           [M4  6]
        │
        ├──> 501~504 [M5  4]
        └──> 601~604 [M6  4]（M5/M6 可并行）
```

- **可提前独立项（两项，均不依赖 M1~M3，`graceful_reload=0` 也受益）**：
  - C-NR-401：补 shutdown timer（修 bug 性质）。
  - C-NR-307：自驱 hardclock（v1.7，绕开共享 timer 槽；行为等价改造，独立回归）。
- **最高回归风险单点**：C-NR-307。它改动 timer 心跳这一全局基础机制，精度劣化会静默影响 RTO/keepalive，建议**独立 commit + 独立回归（PT-NR-08）后再合入 M2 其余部分**。
- **并行度**：M1 单人串行；C-NR-401/307 可与任意里程碑并行推进；M5 与 M6 前半可双线并行；M7 条件触发。
- 每个提交串保持独立可 revert；revert 顺序遵守依赖反向。
