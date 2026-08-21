# 07 里程碑规划：M0~M7 里程碑与编码工作清单

| 项 | 值 |
|---|---|
| 文档编号 | 07 |
| 标题 | Nginx 无损 reload（S3 方案）里程碑规划与后续编码工作清单（C-NR-100~604） |
| 版本 | v1.0 |
| 日期 | 2026-08-18 |
| 状态 | 待人工审计 |
| 来源产物 | work/milestones-testing.md（规划师 milestone-planner，2026-08-18 落盘）。本篇为其里程碑与编码工作清单部分的正式化改写；测试计划部分拆分至 [08-测试计划](08-testing.md)。输入：[06-方案设计](06-solution-design.md)（推荐方案 S3，含四层所有权模型、T0-T5 时序、接口面清单 5.4、RV1-9、DR1-7）、[04-现状分析](04-fstack-current-analysis.md)（8 项障碍清单）、[01-VPP/VCL 调研](01-vpp-vcl-research.md)（§6.3-7 VPP 验证模式）、[03-旧方案考证](03-fstack-legacy-solution.md)（旧方案失败教训）；对齐 docs/primary_slim_spec/zh_cn/ 里程碑切分粒度 |

相关篇章：[00-总览](00-overview.md) | [06-方案设计](06-solution-design.md) | [08-测试计划](08-testing.md)

---

## 摘要

本文把 [06-方案设计](06-solution-design.md) 的推荐方案 S3（v1.6：同队列 + ready 后同期移交队列+listen + flow_map 软件分发表 + 跨进程互斥 + ARP/NDP clone，承接 primary_slim；M2 大阶段：可选 dispatcher 中心化）拆解为 **M0 预研 → M1 常驻 primary 化 → M2 新旧并存 → M3 同期移交+flow_map → M4 drain 收尾 → M5 USR2 → M6 门禁收尾 → M7（可选，DR7 触发）** 共 8 个里程碑、**35 个编码改动点（C-NR-100~604）**（v1.6 待配合调整：删 reta/乒乓相关、增 flow_map/互斥/ARP clone/proc_id 代际无关相关）。逐项给出文件:行号锚点、依赖、DoD、测试门禁与回退方案；并把 RV1-10 逐项分配到里程碑、DR1-7 标注为对应里程碑开工前置评审。测试计划（16 条单测 UT-NR-01~16 + 5 条真 EAL 集成用例 IT-NR-A + 15 行实机用例 IT-NR-RT + 6 条性能基线 PT-NR + 20 项验收标准 A-NR + 循环 reload 门禁）见 [08-测试计划](08-testing.md)。

> 【数字口径说明】本文规模数字以实际清点为准：35 个编码改动点（C-NR-100~604）、5 条集成用例、15 行实机用例（RT-00~13，含 RT-04b）。来源产物 work/milestones-testing.md 中的同源旧数字（41/6/13）系中间产物原文，不回改；如与本文冲突以本文为准。

## 关键结论

1. **最强回滚点仍是配置级**：`graceful_reload=0`（默认）⇒ reload 行为与现状逐字一致（[06](06-solution-design.md) 5.4-3 的 0 回归原则）。所有里程碑的代码都以该开关门控，与 primary_slim 的 `primary_slim=0` 同构。
2. **M0 必须先行解决两个「一票否决」预研项**：RV7（双代际栈隔离 listen 同 IP:port 是否真不冲突——[04](04-fstack-current-analysis.md) §3.5 仅为静态推断）与 RV2（virtio PMD 上 reta 运行时更新是否生效）。任一失败则 S3-M1 主路径需换档（RV2 失败 → 队列移交变体 RV3/DR3；RV7 失败 → 方案需重新评审），**在 M1 开工前必须出结论**。
3. **本文 M 编号与 [06](06-solution-design.md) 的 M1/M2 不同名不同义**：本文 M1+M2+M3+M4 合起来 = 方案设计的 S3-M1；本文 M7 = S3-M2。映射表见第 0.2 节，后续文档引用本文编号时以此为准。
4. **M2（新旧并存）是风险最集中的里程碑**：它一次性引入多 secondary 双代际并存（RV1）、乒乓 lcore 配置校验（DR5）、FF_RELOAD 控制消息（DR4），且删除了现状两段串行 reload 的「安全」行为——该里程碑必须独立成提交串、独立验收，不得与 M3 混批。
5. **测试环境的三个如实约束**（引自 primary_slim 08 §7 实测）：本机仅 virtio 系 PMD（物理网卡上 reta 结论不可外推）；`wrk` 在本环境不可用，压测用 `ab` + python 探测脚本（`_e2_probe_client.py` 模式）；primary/secondary 初始化各需约 25s，脚本必须轮询就绪标志不得裸 sleep。
6. **实机脚本硬性规约**：进程终止一律 `/data/workspace/kill_process.sh`、临时文件清理一律 `/data/workspace/rm_tmp_file.sh`、加执行位一律 `/data/workspace/chmod_modify.sh`；目标地址为必填参数，严禁硬编码（不得重蹈 `test_mtu.sh` 曾硬编码真实内网地址的覆辙）。

## 0. 编号体系与总分配表

### 0.1 编号前缀

| 前缀 | 含义 | 前缀 | 含义 |
|---|---|---|---|
| M0~M7 | 里程碑 | UT-NR-xx | 单元测试用例（[08](08-testing.md)） |
| C-NR-xxx | 编码改动点 | IT-NR-Axx | cmocka 真 EAL 集成用例（[08](08-testing.md)） |
| E-NR-xx | M0 预研实验项 | IT-NR-RT-xx（RT-xx） | 实机用例（[08](08-testing.md)） |
| F-NR-x | 单测 fixture（[08](08-testing.md)） | PT-NR-xx | 性能基线用例（[08](08-testing.md)） |
| RV1-9 | [06](06-solution-design.md) §6.1 运行时验证项 | A-NR-xx | 验收标准（[08](08-testing.md)） |
| DR1-7 | [06](06-solution-design.md) §6.2 设计评审项 | RG-NR-xx | 回归项（[08](08-testing.md)） |

### 0.2 本文里程碑与方案设计阶段的映射

| 方案设计（06 篇） | 本文里程碑 | 内容 |
|---|---|---|
| （前置，S3 依赖） | M0 | 预研定案 + 基线采集 |
| S3-M1 | M1 → M2 → M3 → M4 | 常驻 primary 化 → 新旧并存 → 原子切流+转发兜底 → drain 收尾+状态机完备 |
| S3-M1 收尾 | M5、M6 | USR2 升级路径；循环 reload 终门禁 + 特殊场景回归 + 文档 |
| S3-M2 | M7（可选） | dispatcher 中心化（DR7 触发才立项） |

### 0.3 RV1-9 分配总表

| RV | 项目（[06](06-solution-design.md) §6.1） | 首验里程碑 | 复验/关闭里程碑 |
|---|---|---|---|
| RV1 | 2N worker + 1 slim primary 多 secondary 并存稳定性 | M2 | M6（长稳） |
| RV2 | reta 运行时更新在目标 PMD 的支持度与生效时延 | **M0**（PoC，一票否决项） | M3（集成后复测） |
| RV3 | 队列移交变体的 NIC rx ring 缓冲窗口 | M0（仅当 RV2 存疑才开展） | M3（若走该变体） |
| RV4 | dispatch_ring 转发吞吐/时延（drain 高峰） | M3 | M6（循环 reload 期间） |
| RV5 | dispatcher 回调每包判定开销 | M3 | M6（PT-NR-06 关闭） |
| RV6 | 不同 lcore 多进程 timer 槽隔离实测 | M0（双进程共存初验） | M2（乒乓并存期） |
| RV7 | 多代际栈隔离 listen 同 IP:port 实际行为 | **M0**（PoC，一票否决项） | M2（正式链路） |
| RV8 | KNI 启用场景与双代际 worker 交互 | M6 | M6 |
| RV9 | 端到端循环 reload 门禁（v1.6 修订：≥100 次） | M4（20 次小规模） | **M6（终门禁，≥100 次）** |

### 0.4 DR1-7 前置评审分配总表

| DR | 项目 | 评审时点（对应里程碑开工前） |
|---|---|---|
| DR1 | reload 编排者：master vs slim primary（倾向 master 编排 + primary 原语） | **M0**（决定 M1 的 primary 拉起方式与 M2 状态机归属） |
| DR2 | 旧连接归属判定：实时查询 vs 快照表（两形态均须遵守流表窗口化：READY 后生效、排空确认后关表，[06] 第 2 节语义 6） | M0（接口初评）→ **M3 开工前定案**（RV5 数据支撑） |
| DR3 | reta 切流 vs **末期一次性队列移交**（X1 已决策可接受，[06] 语义 7）：两变体选择依据与降级链；virtio 下 reta 不可用→降级到队列移交（[06] §6.4） | **M0**（RV2/RV3 数据定案） |
| DR4 | ff_msg ring 作 reload 控制通道的容量/实时性 | **M2 开工前** |
| DR5 | 乒乓 lcore 配置表达与校验链（2N 逻辑 lcore_id 必需、2N 物理核非必需——DISC-1 `[--lcores]` 亲和可选，[06] §6.3 X3 决策） | **M2 开工前** |
| DR6 | 异常回退完备性（每阶段回退目标态） | **M4 开工前** |
| DR7 | M7（dispatcher 中心化）启动判据与阈值 | **M7 立项评审**（M6 数据齐后；v1.3 修订暂定阈值：reload 窗口内转发开销致吞吐下降 >5%、或 drain 期 P99 劣化 >10%、或高存量连接场景 drain 时长超 SLO——流表窗口化后稳态损耗恒 0，原稳态阈值失效，见 [06] §6.2 DR7） |

### 0.5 8 项障碍（[04](04-fstack-current-analysis.md) §4）→ 里程碑消解映射

| 障碍 | 内容 | 消解里程碑 | 机制 |
|---|---|---|---|
| 1 | 两段串行空窗 | M2 + M3 | 并存 + reta 切流 |
| 2 | listening fd 无法跨进程 | M2 | 回避式：栈隔离多代际 listen（RV7 验证） |
| 3 | TCP 连接无迁移 | M3 + M4 | 转发兜底 + drain |
| 4 | primary 单点/硬编码 | M1 | 全 secondary + 常驻 slim primary |
| 5 | respawn/时序脆弱（500ms/15s） | M2 | 显式 READY 协议取代 |
| 6 | master 不在数据面 | M2 + M3 | master 编排 + primary 原语（DR1） |
| 7 | RSS 静态映射窗口 | M3 | reta 原子切流（DR3） |
| 8 | 定时器随进程消亡 | M2 | 乒乓分核 → timer 槽天然隔离（RV6） |
| 补充 | worker QUIT 缺 ngx_set_shutdown_timer | M4 | 补回（修 bug 性质，独立可先做） |

## 1. 里程碑总览

| 里程碑 | 目标 | 编码点数 | 主要文件 | 前置 | 独立验收 | 回退点 |
|---|---|---|---|---|---|---|
| **M0** 预研定案 | RV2/RV7 一票否决项出结论；DR1/DR3 定案；基线数据 | 0（PoC 脚本/报告） | 无正式编码 | 无 | ✅ | — |
| **M1** 常驻 primary 化 | nginx worker 全 secondary，slim primary 常驻不随 reload 退出；`graceful_reload` 开关落地 | 7（C-NR-100~106） | `ngx_ff_module.c`/`ngx_process_cycle.c`/`ff_config.{h,c}`/`config.ini` | M0（DR1 定案）；primary_slim 已合入 | ✅ | `graceful_reload=0` + revert 提交串 |
| **M2** 新旧并存 | 乒乓 lcore 段 + FF_RELOAD 消息族 + READY 协议；双代际 worker 并存；删除两段串行 reload（条件化） | 8（C-NR-201~208） | `ff_config.{h,c}`/`ff_msg.h`/`ff_dpdk_if.c`/`ngx_process_cycle.c`/新增 `ngx_ff_reload.c` | M1；DR4/DR5 评审 | ✅ | `graceful_reload=0` 走旧路径 |
| **M3** 原子切流+兜底 | `ff_conn_owner_query` + dispatcher 回调 + reta 切流原语；旧连接包经 dispatch_ring 转发 | 6（C-NR-301~306） | `ff_api.h`/`ff_dpdk_if.c`/`ngx_ff_module.c` | M2；DR2/DR3 定案 | ✅ | 切流消息不触发即回退 |
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
| **目标** | 用最小 PoC 消除 S3-M1 的两个一票否决不确定性（RV7、RV2），完成 DR1/DR3 设计定案，采集性能基线，为 M1~M6 提供决策数据 |
| **范围** | 不改任何 lib/app 正式代码；PoC 可用临时补丁/脚本（产物入库为报告，补丁仅留档不进主线，参照 primary_slim `_poc_*.patch` 的做法） |

**实验与评审清单**：

| 编号 | 内容 | 方法 | 通过判据 | 失败时的换档 |
|---|---|---|---|---|
| E-NR-01（RV7） | 双代际栈隔离 listen 同 `<IP>:80` 是否冲突 | 常驻 slim primary（primary_slim=1）+ 两个 secondary helloworld/nginx 实例各自 bind/listen 同 `<DPDK_NIC_IP>:80`，从 f-stack-client 并发 SYN 压测，两实例各自 accept | 两实例均正常 accept、无 bind 报错、无 RST；连接分布符合 reta 映射 | S3 需重新评审（listen 层加协调） |
| E-NR-02（RV2） | virtio PMD 上 `rte_eth_dev_rss_reta_update`/`set_rss_table` 运行时更新是否生效、时延 | 进程组运行中，经临时工具（扩展 `ff_top` 或 msg 通道）触发 reta 重算，客户端抓包观察新 flow 导向变化 | reta 更新后新 flow 立即（亚秒级）导向新队列段；旧连接 flow 不受影响（hash 不变） | 走队列移交变体（RV3/DR3-B），M3 改实现 C-NR-304 |
| E-NR-03（RV6 初验） | 双进程不同 lcore 的 timer 槽隔离 | E-NR-01 的双实例运行期间观测 RTO/keepalive 精度与 `rte_timer` 状态（ff_top/sysctl 采样） | 无 timer 重复触发/停摆迹象；TCP 定时器精度正常 | 升级为 blocker，评审 timer 槽初始化补强 |
| E-NR-04 | 现状串行 reload 基线数据（[04](04-fstack-current-analysis.md) §5-3） | 现状代码跑一轮 HUP reload：实测空窗时长（服务不可用窗口）、reload 总时长、期间丢包/失败数 | 产出基线数值（用于 A-NR-14 的 reload 耗时上限与 PT-NR-03 对照） | — |
| E-NR-05 | 性能基线采集（PT-NR-01 前置） | 按 primary_slim 06 方法：`ab -k -c 50 -n 20000 http://<DPDK_NIC_IP>/`，3 轮取区间 | 产出改造前稳态 QPS/延迟基线 | — |
| 评审 | DR1（编排者 + slim primary 拉起方式）、DR3（reta vs 队列移交）、DR2 初评 | 评审会，结论更新回 [06](06-solution-design.md) 或本文附录 | 定案记录在案 | — |

**slim primary 拉起方式（DR1 评审的两个候选，M1 编码按定案执行）**：
- 候选 a（独立常驻进程）：部署形态新增一个 systemd unit 拉起的 slim primary 守护进程；nginx master 启动时探测其存活（EAL attach 失败即报错退出）。运维形态变化明确，primary 生命周期与 nginx 完全解耦。
- 候选 b（master 代管 + double-fork 脱离）：nginx master 首次启动时检测 primary 缺席则 spawn 专职 slim primary 子进程并 double-fork/setsid 脱离 master 生命周期，reload/USR2 均不对其发信号。nginx 语义内聚，但需处理老 master 退出不波及 primary 的细节。
- 本规划倾向候选 b（运维零新增），最终以 DR1 评审为准；两候选在 M1 的差异仅在 C-NR-100/101 两点。

| 项 | 内容 |
|---|---|
| **DoD** | E-NR-01/02 出明确结论；DR1/DR3/DR2 初评有书面定案；基线数据落盘 `work/m0-poc-report.md` |
| **测试门禁** | 本身即测试产出；无代码门禁 |
| **风险与回退** | RV2/RV7 失败 → 按「失败换档」列处理，M3 范围调整或方案回炉；不产生主线代码风险 |
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

### 2.3 M2：乒乓 lcore 与新旧 worker 并存（风险最集中）

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 1（前半）/2/5/8：reload 改回原生「先起新再退旧」顺序；新 worker 绑乒乓 lcore 段 B，与旧 worker（段 A）不同核并存；READY 显式协议取代 500ms/15s 时序 |
| **范围** | [06](06-solution-design.md) 5.4-2（FF_RELOAD 消息族）、5.4-3（乒乓段配置）、5.4-4 第 1 条（两段式条件化）；时序 T0-T2 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-201 | `lib/ff_config.h`（dpdk 段）+ `ff_config.c` 解析/校验（`:1414-1519` 区域） | 新增 | `reload_lcore_policy=pingpong`；V-NR 校验链（DR5 定案）：lcore_mask 含 2N 段、worker 数 N 与段容量一致、乒乓两段等价、primary lcore 排除（沿用 primary_slim V2）、`graceful_reload=0` 时全部新校验不生效 |
| C-NR-202 | `lib/ff_msg.h:37-53` 旁 | 新增 | FF_RELOAD 消息族：`FF_RELOAD_READY` / `FF_RELOAD_SWITCH_REQ` / `FF_RELOAD_SWITCH_ACK` / `FF_RELOAD_QUEUE_STATE` / `FF_RELOAD_DRAIN_PROGRESS` / `FF_RELOAD_DRAIN_DONE`（G_old 排空确认→触发 G_new 关流表回稳态，[06] 第 2 节语义 6）/ `FF_RELOAD_REJECT`（防重入：上一代 G_old 未排空时拒绝新 reload）；消息体含 proc_id、代际号、lcore 段标识、时间戳（打点用） |
| C-NR-203 | `lib/ff_dpdk_if.c:2404-2454`（handle_msg） | 修改 | FF_RELOAD 处理器注册与分派；容量/实时性按 DR4 结论（必要时专用 ring） |
| C-NR-204 | `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:223-270` | 修改 | **两段式 reload 块整体条件化**：`graceful_reload=1` 走原生顺序（fork G_new JUST_RESPAWN → 等 READY → 切流[M3] → G_old QUIT）；T1~T5 期间再次收到 HUP → **拒绝并记日志（reload 防重入，[06] 第 2 节语义 6：不支持 G_old 排空前的快速连续 reload）**；`=0` 逐字保留旧两段式 |
| C-NR-205 | 新增 `app/nginx-1.28.0/src/event/modules/ngx_ff_reload.c` + `auto/sources` 挂载 | 新增 | **reload 编排状态机**（满足 [06](06-solution-design.md) 第 1 节否决性判据：显式、可观测、可回退）：T0-T5 状态枚举 + 纯转移函数 + 每阶段打点（状态日志 + ff_top 可见计数）；master 侧驱动 |
| C-NR-206 | `lib/ff_config.c` proc_lcore 分配（`ff_dpdk_if.c:508-538` 消费侧） | 修改 | 新 worker 代际 → 乒乓段 B 的 lcore/queue 分配映射（代际号 → 段号取模） |
| C-NR-207 | `ngx_process_cycle.c:762-764`（respawn 条件） | 修改 | `graceful_reload=1` 时恢复原生 respawn 语义（reload 期间 worker 挂了允许重生或按状态机决策，DR6 定） |
| C-NR-208 | worker 侧 READY 上报 | 新增 | worker 完成 `ff_freebsd_init` + `ngx_open_listening_sockets` 后经 FF_RELOAD_READY 上报 master（经 channel 或 msg ring，DR4 定案） |

| 项 | 内容 |
|---|---|
| **前置** | M1 合入；**DR4/DR5 评审完成** |
| **DoD** | ① clean build + 单测（UT-NR-04~06/10/12/15~16 + 零回归）；② 实机 RT-01（空载 reload：双代际并存、各自 listen、G_old 退出后 G_new 独自服务——此阶段切流靠「旧 worker 停 accept 后 reta 尚未切」的窗口可能仍有短暂不确定性，故 RT-01 判据放宽为：reload 完成、服务最终恢复、无 crash）；③ RV1 初验（双代际共存 ≥30min 无异常）；④ RV6 复验（并存期 TCP 定时器正常） |
| **测试门禁** | UT + RT-01 + RV1/RV6 观测记录 |
| **风险与回退** | 风险：多 secondary 并存的 mempool/EAL/msg_ring 并发（RV1 主体风险，primary_slim 已有 2 secondary 先例但未到 2N 双代际）；乒乓段配置错误导致队列无主。回退：`graceful_reload=0`（FF_RELOAD 不注册、reload 走旧路径）；C-NR-201~208 独立提交串可整体 revert |
| **提交建议** | 3~4 个 commit：配置与校验 / FF_RELOAD 消息族 / 状态机与 reload 顺序 / READY 协议 |

### 2.4 M3：原子切流与 dispatch_ring 转发兜底

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 3/6/7：T3 时序落地——G_new READY 后 reta 原子切流；旧连接包经 packet_dispatcher 回调 + dispatch_ring 转发回 G_old；master 编排 + primary 原语分工（DR1/DR3 定案形态） |
| **范围** | [06](06-solution-design.md) 5.4-1（ff_conn_owner_query 等）、5.4-2（切流请求/应答）、T3 时序 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-301 | `lib/ff_api.h` + 实现（封装 in_pcblookup 语义） | 新增 | `ff_conn_owner_query(...)`：四元组 → 本栈已知连接 / SYN(新连接) / 非本栈；供回调判定（DR2 定案的实时查询形态；若 M0/M3 实测性能不足，退化快照表形态在此点扩展） |
| C-NR-302 | `lib/ff_dpdk_if.c`（`set_rss_table` 定义 :832、rte_eth_dev_rss_reta_update :850、既有调用点 :1218，新增触发入口） | 修改 | 切流原语：primary 收 FF_RELOAD_SWITCH_REQ → 重算 reta 将新 flow 导向 QB → ACK；失败路径回 ACK(error)（RT-07 注入用） |
| C-NR-303 | `app/nginx-1.28.0/src/event/modules/ngx_ff_module.c`（worker init） | 修改 | G_new worker **READY 后自动注册** `ff_regist_packet_dispatcher` 回调（ff_api.h:299-303，流表仅 reload 窗口生效、稳态零开销，[06] 第 2 节语义 6）：解析四元组 → `ff_conn_owner_query` → 本栈已知连接（=流表命中，本代际新流）本栈处理 / **miss 一律**返回 G_old queue id（经 ff_dpdk_if.c:2142-2150 现成 enqueue 路径转发） |
| C-NR-304 | （条件项，DR3-B）`lib/ff_api.h` + `ff_dpdk_if.c` | 新增 | `ff_queue_handover(q, from, to)` 队列移交变体：仅当 M0 E-NR-02 判 reta 不可用时启用；旧停 poll → 新起 poll，NIC rx ring 缓冲兜底（RV3） |
| C-NR-305 | `lib/ff_config.{h,c}` | 新增 | dispatch_ring 容量配置项（若 RV4 实测默认容量在 drain 高峰不足；默认保持现值） |
| C-NR-306 | `ngx_ff_reload.c` 状态机 | 修改 | T3 状态：master 确认全部 G_new READY → 发 SWITCH_REQ → 收 ACK → 状态推进；超时/失败分支（DR6 前半） |

| 项 | 内容 |
|---|---|
| **前置** | M2 合入；**DR2/DR3 定案**（M0 数据 + M2 补充） |
| **DoD** | ① clean build + 单测（UT-NR-11/13/14 + 零回归）；② 实机 RT-02（带长连接流量 HUP：新连接全走 G_new、旧连接包转发回 G_old 零 RST）；③ RT-03（持续 CPS 压力下 reload，客户端错误 0）；④ RV4/RV5 实测数据落盘（DR7 输入） |
| **测试门禁** | UT + IT-NR-A02/A03 + RT-02/RT-03 |
| **风险与回退** | 风险：RV2 残余（reta 生效时延导致切流瞬间少量新 flow 仍入 QA——QA 此刻仍有 G_old poll，且 SYN 会经回调转发判定，属设计内兜底）；RV4 ring 容量；RV5 回调开销。回退：切流消息不触发（状态机停在 T2，G_old 继续服务，本轮 reload 放弃）；`graceful_reload=0` 兜底 |
| **提交建议** | 3 个 commit：ff_conn_owner_query / 切流原语与消息 / 回调注册与状态机 T3 |

### 2.5 M4：drain 收尾、异常回退与状态机完备（HUP 全链路）

| 项 | 内容 |
|---|---|
| **目标** | 消解障碍 3（drain 保障）与 [04](04-fstack-current-analysis.md) §4 补充事实：T4/T5 落地——G_old 关自身 listen、drain 存量连接至自然关闭、drain 挂起强退兜底、lcore 段乒乓翻转；T0-T5 全链路 + 全部异常分支打通 |
| **范围** | [06](06-solution-design.md) 5.4-4 第 3/4 条、DR6 全部回退目标态、5.2 异常分支 |

**编码工作清单**：

| 编号 | 文件:行号锚点 | 类型 | 要点 |
|---|---|---|---|
| C-NR-401 | `ngx_process_cycle.c:894-898`（对照原生 :951-957） | 修改 | **补回 `ngx_set_shutdown_timer`**（F-Stack 版 worker QUIT 分支缺失，[04](04-fstack-current-analysis.md) §4 补充事实）；此项是修 bug 性质，可提前独立提交（不依赖 M1~M3，`graceful_reload=0` 也受益） |
| C-NR-402 | `ngx_ff_reload.c` + `ff_msg.h` | 新增 | drain 进度上报（FF_RELOAD_DRAIN_PROGRESS：剩余连接数/最后活动时间）+ **G_old 排空确认上报（FF_RELOAD_DRAIN_DONE：连接数=0 且全部 G_old 进程退出）** + drain 强退阈值（shutdown timer 时长，默认建议对齐 nginx `worker_shutdown_timeout` 语义，值经 RT-06 校准） |
| C-NR-403 | `ngx_ff_reload.c` | 修改 | 状态机 T4/T5：收 G_old 全退 SIGCHLD/DRAIN_DONE → **通知 G_new 注销回调/关闭流表，G_new 进入稳态成为下轮 G_old（防性能退化，[06] 第 2 节语义 6；防重入拦截随排空确认解除）** → 释放段 A → 乒乓翻转记账（下轮 reload 用段 A）→ reload 完成打点 |
| C-NR-404 | `ngx_ff_reload.c` 异常分支 | 修改 | ① T2 前 G_new 任一 worker 起不来/READY 超时 → 放弃本轮（G_old 未动，对齐内核 HUP 配置失败回滚语义）；② T3 切流失败 → 停在 T2 状态放弃；③ primary 被 kill（数据面不受影响但原语不可用）→ 本轮 reload 安全放弃 + 告警（primary_slim E10：primary 不可复活，运维择机全组重启） |
| C-NR-405 | `ngx_process_cycle.c` G_old graceful 分支 | 修改 | G_old 收 QUIT：各自栈内 close listening（只影响自己栈）+ 停 accept + 继续跑 ff_run drain；存量连接后续包即使被 reta 导入 QB 也经 T3 回调转发回来（M3 已铺） |
| C-NR-406 | 打点与可观测收尾 | 新增 | 每阶段耗时/计数落 ff_top 或日志（reload 总时长、切流时延、drain 时长、转发包量），供 PT-NR-03 与 A-NR-14 度量 |

| 项 | 内容 |
|---|---|
| **前置** | M3 合入；**DR6 评审完成** |
| **DoD** | ① clean build + 单测（UT-NR-10 状态机全转移 + 零回归）；② 实机 HUP 全链路：RT-01~RT-03 复跑全绿 + RT-05/06/07/09 异常注入全绿 + RT-10（连续 20 轮 reload 乒乓翻转正确）；③ RV9 小规模预演：带流量连续 reload 50 次零错误 |
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
| C-NR-604 | `doc/F-Stack_Nginx_APP_Guide.md`、`doc/F-Stack_Release_Note.md`、`config.ini` 注释 | 文档 | 部署形态（常驻 primary + 乒乓 lcore 约定 + graceful_reload 开关矩阵）、运维手册（reload 状态打点解读、primary 死亡降级处置、drain 强退阈值调优）、语义变更声明 |

| 项 | 内容 |
|---|---|
| **前置** | M4（M5 可并行推进） |
| **DoD** | ① RV9：持续流量 + 每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次，≥100 次零错误、无死锁无 crash、mbuf/内存无泄漏趋势（v1.6 修订：原「每 2~5s reload、≥1000 次」与防重入语义+25s 初始化不可同时成立）；② RT-12/13 通过（或出明确结论与限制声明）；③ 全部 RV1-9 关闭记录在案；④ 文档入库 |
| **测试门禁** | PT-NR-05 终门禁 + 全量 RT 矩阵复跑 |
| **风险与回退** | 风险：长循环暴露的低概率状态错位（VPP #3547/#3645 前车之鉴，[01](01-vpp-vcl-research.md) §4.3/§6.4）——这正是门禁价值所在，暴露即回 M4 状态机修。回退：无代码回退需求 |
| **提交建议** | 2 个 commit：测试脚本 / 文档 |

### 2.8 M7（可选）：dispatcher 中心化（S3-M2）

仅当 DR7 触发（M6 数据，v1.3 修订判据——流表窗口化后稳态损耗恒 0，原稳态判据失效：改为 **reload 窗口内**转发开销致吞吐下降 >5%、或 drain 期 P99 劣化 >10%、或高存量连接场景 drain 时长超 SLO）才立项。方向：slim primary 统一收包 + 流表分发，worker 变纯 ring 消费者（VPP app_listener workers bitmap 同构 + 旧 iWiki dispatch 思想现代化，避开同核共存）。**若触发须另立 spec 重新走本流程**，本文不展开。

## 3. 后续编码工作清单汇总（按提交批次）

35 个编码点已按里程碑列于第 2 节各表。此处仅给跨里程碑的总依赖序（DAG 摘要）与并行度建议：

```
M0(E-NR-01/02 + DR1/DR3) ══> C-NR-100/101 ──> 102/103 ──> 104/105 ──> 106   [M1]
M1 ──> (DR4/DR5) ──> 201/202 ──> 203/205 ──> 204/207 ──> 208                 [M2]
M2 ──> (DR2/DR3 终案) ──> 301 ──> 302 ──> 303 ──> 306   (304/305 条件项)     [M3]
C-NR-401（shutdown timer，可提前至任意时点独立提交）
M3 ──> (DR6) ──> 402/403 ──> 404 ──> 405/406                                  [M4]
M4 ──> 501~504 [M5]；M4 ──> 601~604 [M6]（M5/M6 可并行）
```

- **可提前独立项**：C-NR-401（补 shutdown timer，修 bug 性质，`graceful_reload=0` 也受益）。
- **并行度**：M1 单人串行；M5 与 M6 前半可双线并行；M7 条件触发。
- 每个提交串保持独立可 revert；revert 顺序遵守依赖反向。
