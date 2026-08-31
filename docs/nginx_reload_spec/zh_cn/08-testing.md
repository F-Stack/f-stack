# 08 测试计划：单元测试、集成测试、性能基线与验收标准

| 项 | 值 |
|---|---|
| 文档编号 | 08 |
| 标题 | Nginx 无损 reload（S3 方案）测试计划（UT/IT/PT/A/RG 编号体系） |
| 版本 | v1.2 |
| 日期 | 2026-08-31 |
| 状态 | 待人工审计（v1.2 增量修订） |
| 对齐基线 | [06-方案设计](06-solution-design.md) **v1.7** / [07-里程碑](07-milestones.md) **v1.2** |
| 来源产物 | work/milestones-testing.md（规划师 milestone-planner，2026-08-18 落盘）。本篇为其测试计划部分的正式化改写；里程碑与编码工作清单部分拆分至 [07-里程碑](07-milestones.md)。对齐 docs/primary_slim_spec/zh_cn/08-测试规格.md 的测试篇风格 |
| 修订记录 | v1.1（2026-08-21）：据 [06] v1.6 贯通——UT-NR-04/05/12 去掉乒乓改 proc_id 映射、UT-NR-11 去 reta 改移交互斥、新增 IT-NR-A06/A07/A08。v1.2（2026-08-31）：据 [06] v1.7 与 [07] v1.2 贯通——**补齐此前被完全遗漏的三类测试：自驱 hardclock 精度回归（UT-NR-17/PT-NR-08/A-NR-21）、应用 mempool 分代际（UT-NR-18/PT-NR-09/A-NR-23）、同核切换性能（RT-14/PT-NR-07/A-NR-22）**；修正 flow_map 入表时机（SYN-ACK 而非 accept）；补充 virtio 无 `imissed` 的判据替代方案；同步用例总数 16→18、PT 6→9、A-NR 20→23、RT 15→16 行 |

相关篇章：[00-总览](00-overview.md) | [06-方案设计](06-solution-design.md) | [07-里程碑](07-milestones.md)

---

## 摘要

本测试计划覆盖 [07-里程碑](07-milestones.md) M0~M7 全周期：**18 条单测用例（UT-NR-01~18）+ 9 个 fixture + 8 条真 EAL 集成用例（IT-NR-A01~08）+ 16 行实机用例（RT-00~14，含 RT-04b）+ 9 条性能基线用例（PT-NR-01~09）+ 23 项验收标准（A-NR-01~23）+ 6 项回归（RG-NR）**，含循环 reload 门禁（v1.6 修订：每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次，≥100 次零错误，依据 [01-VPP/VCL 调研](01-vpp-vcl-research.md) §6.3-7 验证模式并适配防重入语义）与未覆盖风险声明。

> 【数字口径说明】本篇规模数字以实际清点为准（v1.2 更新）：单测 16→**18**（新增 UT-NR-17 自驱 hardclock 间隔计算、UT-NR-18 mempool 代际/cache_size 配置校验）；性能基线 6→**9**（新增 PT-NR-07 同核切换性能、PT-NR-08 hardclock 精度回归、PT-NR-09 mempool 分代际）；实机 15→**16 行**（新增 RT-14 同核高负载切换）；验收标准 20→**23**（新增 A-NR-21/22/23）。集成用例 8 条（A06 DRAIN_DONE/REJECT、A07 ARP/NDP clone、A08 flow_map 三态判定）。来源产物 work/milestones-testing.md 中的同源旧数字（6/13）系中间产物原文，不回改；如与本篇冲突以本篇为准。
>
> 【v1.2 补齐说明】v1.1 之前本篇对 [06] v1.7 的两项核心底层改造（自驱 hardclock、应用 mempool 分代际）**零测试覆盖**——这是本篇此前最严重的缺口（timer 心跳改动无回归、mempool cache 关闭无性能基线）。v1.2 一次性补齐，并新增 RV10（同核切换）的承载用例。

## 1. 单元测试计划

### 1.1 框架与现状（对应仓库 tests/unit）

沿用 `tests/unit/` 既有 CMocka（≥1.1.7，Makefile 有 `$(error)` 版本门禁）体系：`load_with_fixture()` / `load_with_proc()` 加载 fixture + `cmocka_unit_test_setup_teardown(fn, test_setup, NULL)` 注册 + `cmocka_run_group_tests()`；**不另建框架、不新增测试二进制**（状态机纯函数用例落在 `test_ff_config.c`/`test_ff_dpdk_if.c` 既有二进制内；若膨胀再评估拆文件，同 primary_slim 08 T8 的权衡）。fixture 地址一律 `192.168.1.x` 文档地址，文件头写意图注释。

### 1.2 用例清单（UT-NR-01~16）

| 编号 | 用例名 | 目的 | 输入 | 预期 | 对应编码点 |
|---|---|---|---|---|---|
| UT-NR-01 | `test_graceful_reload_default_off` | 默认 0，零回归 | `valid_dpdk_full.ini`（既有，无新键） | `graceful_reload==0`；既有语义不变 | C-NR-101 |
| UT-NR-02 | `test_graceful_reload_parse` | `=1` 解析合法 | `valid_graceful_reload.ini`（含 `primary_slim=1`）+ `load_with_proc(...,"secondary","0")` | `rv==0`；`graceful_reload==1` | C-NR-101 |
| UT-NR-03 | `test_graceful_reload_requires_slim` | `graceful_reload=1 && primary_slim=0` 拒绝 | `invalid_greload_no_slim.ini` | `rv==-1`，stderr 含明确原因 | C-NR-101 |
| UT-NR-04 | `test_procid_fixed_mapping_valid`（v1.1 重命名，原 `test_pingpong_lcore_valid`） | **proc_id 代际无关固定映射**配置合法（v1.6 取代 2N 乒乓段） | `valid_procid_mapping.ini`（N=2 worker，lcore_mask 含 N 个 worker 核 + 1 primary 核，代际映射唯一） | `rv==0`；映射字段正确；两代际 proc_id 集合完全重合且合法 | C-NR-201/206 |
| UT-NR-05 | `test_procid_fixed_mapping_insufficient`（v1.1 重命名，原 `test_pingpong_lcore_insufficient`） | worker 数与 queue 数不一致 / 核数不足 → 拒绝 | `invalid_procid_short.ini` | `rv==-1`，stderr 含明确原因 | C-NR-201/206 |
| UT-NR-06 | `test_greload_thread_mode_mutex` | 与 thread_mode=1 互斥 | `invalid_greload_thread_mode.ini` | `rv==-1`；既有 TC-CM1-01..03 不受影响 | C-NR-101/201 |
| UT-NR-07 | `test_greload_off_no_new_checks` | `=0` 时全部新校验不生效（含 proc_id 映射段不配也不报错） | `valid_dpdk_full.ini` 变体（无 proc_id 映射段） | `rv==0` | C-NR-201 零回归 |
| UT-NR-08 | `test_greload_bad_value_atoi` | 非数字退化为 0（记录既有 atoi 语义） | `graceful_reload=abc` | `graceful_reload==0`、`rv==0` | C-NR-101 |
| UT-NR-09 | `test_dispatch_ring_capacity_parse` | ring 容量项解析与默认值 | 显式值/缺省两 fixture | 显式生效；缺省=现默认值 | C-NR-305 |
| UT-NR-10 | `test_reload_fsm_transitions` | 状态机转移表：合法转移（T0→T1→T2→T3→T4→T5）通过；非法转移（如 T0 直接 T4、T3 回 T1）拒绝且打点 | 直接调 `ngx_ff_reload.c` 纯转移函数（需设计为无副作用可测） | 合法路径状态推进正确；非法路径返回错误不转移 | C-NR-205/403/404 |
| UT-NR-11 | `test_handover_mutex_pure_fn`（v1.1 重命名改写，原 `test_reta_recalc_pure_fn`） | **跨进程移交互斥纯函数**（v1.6：reta 重算已废弃）：`ff_queue_handover_mutex` 的状态机——G_old 未确认停 poll 时 G_new 不得起 poll；G_old 已确认后方可；超时路径返回错误且不改变共享标记 | 本地构造共享内存标记状态，驱动状态转移 | ① 未确认 → 拒绝起 poll；② 已确认 → 放行；③ 超时 → 错误返回且标记不变；④ **并发展开：任何路径下都不存在「双方同时持有」的中间态** | C-NR-302 |
| UT-NR-12 | `test_procid_generation_independent`（v1.1 重命名改写，原 `test_pingpong_generation_flip`） | **proc_id 代际无关性**：连续两轮 reload，G_new/G_new' 的 proc_id、queue_id、msg_ring 索引与 G_old **完全一致**（v1.6 不再乒乓交替） | 模拟多轮状态机 T5 推进，断言每轮映射 | 任意轮次映射一致；两代际不存在 lcore/queue/msg_ring 重合冲突（审核 B-1 回归） | C-NR-206/403 |
| UT-NR-13 | `test_flow_map_ops` | **flow_map 三函数**（v1.6 替代 ff_conn_owner_query）：lookup/insert/close 参数校验与错误路径（NULL 四元组/非法 family/重复 insert/close 后 lookup）；**入表时机语义（v1.2 修正）**：SYN 到达→发出 SYN-ACK 时入表，**而非 `accept()` 时**——须能覆盖「SYN 已入表、第三次握手 ACK 到达、连接尚在 syncache、尚未 accept」这一窗口 | 直接调用（本地 hash 表，无 FreeBSD 栈依赖）；构造 SYN→SYN-ACK→ACK 三段序列 | 返回码正确；insert→lookup 命中；未 insert→lookup miss；close 后 lookup miss；**SYN-ACK 后、ACK 到达时查表必命中（此断言是握手不被误转 G_old 的判据）**；SYN 重传不重复插入 | C-NR-301 |
| UT-NR-14 | `test_ff_reload_msg_serdes` | FF_RELOAD 消息构造/序列化/解析/坏消息丢弃 | 本地构造消息体 | round-trip 一致；截断/魔数错丢弃 | C-NR-202 |
| UT-NR-15 | `test_fsm_ready_timeout_gives_up` | T2 READY 超时 → 放弃本轮，状态回 T0 且 G_old 未动（状态机层） | 注入超时事件序列 | 状态回退正确 + 打点含放弃原因 | C-NR-404 |
| UT-NR-16 | `test_fsm_handover_fail_rollback`（v1.1 重命名，原 `test_fsm_switch_fail_rollback`） | T3 **移交** HANDOVER_ACK(error) 或互斥标记超时 → 停在 T2 放弃，不推进 T4；共享内存互斥标记保持「G_old 持有」不变（保证不会并发 poll） | 注入失败 ACK / 超时事件 | 状态回 T0 且 G_old 未动 + 打点含放弃原因；**互斥标记断言：失败后 G_new 不得处于 poll 态** | C-NR-306/404 |
| **UT-NR-17**（v1.2 新增） | `test_hardclock_interval_calc` | **自驱 hardclock 间隔计算纯函数**（C-NR-307）：`interval = hz_tsc / freebsd.hz` 的正确性与边界 | 构造 `freebsd.hz` = 100/1000/1 与不同 `rte_get_timer_hz()` 组合 | 间隔值精确；`hz==0` 或超大值不除零/不溢出（有兜底或拒绝）；默认 100 → 10ms | C-NR-307 |
| **UT-NR-18**（v1.2 新增） | `test_mempool_generation_config` | **应用 mempool 分代际配置校验**（C-NR-308）：`graceful_reload=1` 时第二代 pool 名解析/`cache_size=0` 参数生效；`=0` 时全部不生效（零回归） | fixture 两态 + 直接断言 pool 创建参数 | `=1` 时 gen2 pool 可 lookup 且 cache_size==0；`=0` 时与现状逐字一致（`MEMPOOL_CACHE_SIZE` 保持原值） | C-NR-308 |

> 诚实标注（v1.6 修订）：~~`ff_conn_owner_query` 的真实归属判定依赖 FreeBSD 栈状态~~ → v1.6 改为 flow_map 软件分发表（本地 hash 表，无 FreeBSD 栈依赖），UT-NR-13 可完整测 lookup/insert/close 语义；flow_map 窗口语义（READY 后生效/miss 一律转 G_old/排空确认后关表）属状态机与回调注册逻辑，由 UT-NR-10 状态机转移 + RT-02/RT-10 判据覆盖；跨进程互斥标记正确性由 RV3 实测覆盖。

### 1.3 新增 fixture 清单（F-NR-1~9，置于 tests/unit/fixtures/）

| # | 文件名 | 要点 |
|---|---|---|
| F-NR-1 | `valid_graceful_reload.ini` | `primary_slim=1` + `graceful_reload=1` + **proc_id 代际无关固定映射** + `lcore_list` 排除 primary 核（v1.6：不再含 2N 乒乓段） |
| F-NR-2 | `invalid_greload_no_slim.ini` | 同上但 `primary_slim=0` |
| F-NR-3 | `valid_procid_mapping.ini`（v1.1 重命名，原 `valid_pingpong_2n.ini`） | N=2、2 数据核 + 1 primary 核的合法布局（v1.6：核数=worker 数，不再需要 2N 余量） |
| F-NR-4 | `invalid_procid_short.ini`（v1.1 重命名，原 `invalid_pingpong_short.ini`） | worker 数与 queue 数不一致 / 核数不足 |
| F-NR-5 | `invalid_greload_thread_mode.ini` | + `thread_mode=1` |
| F-NR-6 | `valid_greload_bad_value.ini` | `graceful_reload=abc` |
| F-NR-7 | `valid_dispatch_ring_cap.ini` | 显式 ring 容量（保留供 RV4 观测后按需启用） |
| F-NR-8 | `valid_greload_off_no_mapping.ini`（v1.1 重命名，原 `valid_greload_no_pingpong_off.ini`） | `graceful_reload=0` 且无 proc_id 映射段（零回归用） |
| F-NR-9 | `valid_greload_2port.ini` | 多 port 布局（若 DR5 定案支持；v1.6 后不再称「乒乓段」） |

### 1.4 mock 策略

| 被测依赖 | 单测层 | 集成层（真 EAL） | 实机层 |
|---|---|---|---|
| ~~reta 更新（`rte_eth_dev_rss_reta_update`/`set_rss_table`）~~ | **已删除**（v1.6：reta 不改，无此依赖） | — | — |
| **跨进程移交互斥**（共享内存标记） | **mock**：驱动 `ff_queue_handover_mutex` 状态机，断言无「双方同时持有」中间态（UT-NR-11） | 真共享内存（net_null + 两线程模拟两代际） | RT-02/RT-07 |
| rte_ring（dispatch ring） | 不 mock（纯逻辑不触 ring） | 真 ring（net_null + 回调路径） | RT-02/RT-03 |
| **自驱 hardclock**（TSC 间隔直调 `ff_hardclock()`） | 纯函数测间隔计算（UT-NR-17） | 真 EAL 下测 TSC 推进与触发次数 | **PT-NR-08 精度回归（不可省略）** |
| **mempool 代际选择 / cache_size=0** | 配置校验（UT-NR-18） | 真 pool 创建与跨代 alloc/free | PT-NR-09 |
| ff_msg 通道 | 消息 serdes 纯函数 | 真 msg ring 环回（IT-NR-A01） | — |
| EAL/进程模型 | 不可达（沿用既有边界结论） | `--no-huge --no-pci --no-shconf -l 0 -m 64 --vdev=net_null0 --file-prefix=ff_reload_test`（**新前缀避免冲突**） | 全真 |

> **关于 `net_null` PMD**：v1.6 后不再需要其 reta 能力（原 §1.4 的「rss_reta 支持待确认」已消除）。`net_null` 在本计划中仅作为 ring/回调/消息通道的真 EAL 载体。

### 1.5 执行与判定

```bash
cd /data/workspace/f-stack/tests/unit
make clean && make all && make test   # 末行 "ALL TESTS PASS (12 binaries)"
make check                            # valgrind memcheck，definite leak 即失败
```

判定：新增 16 条全绿；**既有 TC 一条不许变红**（尤其 TC-S8-CFG-10/11、TC-CM1-01..03、UT-1078 系列）。

## 2. 集成测试计划

### 2.1 环境拓扑

```
f-stack-client（客户端机，8 核，ssh 可达）
   │ ssh 后从客户端发起压测/探测
   ▼
本机 DPDK 接管网卡 <DPDK_NIC_IP>
   ├─ 常驻 slim primary（proc_id=0，primary_slim=1，控制面）
   ├─ nginx master（无 ff 状态，编排者）
   ├─ G_old worker ×N（secondary，queue 集 Q）
   └─ G_new worker ×N（reload 时 secondary attach，**同一批 queue 集 Q**，
                       proc_id 代际无关固定映射；与 G_old 同核或独立核按 DR5 定案）
内核栈对照：127.0.0.1（lo）跑原生路径 nginx（RG-NR-05）

【v1.6 拓扑变更】不再有「lcore 段 A/B」与「queue 集 QA/QB」之分——新旧代际共用
同一批队列，reload 时移交的是「队列消费权」而非「队列归属」，reta 全程不改。
【v1.7 补充】G_old/G_new 各自使用本代际的应用 mempool（gen1/gen2），RX 侧共享
第一代 pool 且 cache_size=0。
```

- 客户端工具：`ab`（`-k -c 50 -n 20000`，wrk 本环境不可用——primary_slim 08 §7.1 实测）；python 探测脚本（`_e2_probe_client.py` 模式：固定本地端口 20000+i 建 N 条 keep-alive 长连接每 2s 逐条 GET 校验 200，扩展逐请求计时供 P50/P99）。
- 时序约束（沿用 primary_slim 08 §7.3）：worker 初始化约 25s，脚本轮询日志就绪标志（FreeBSD 栈初始化完成；持队列进程另有 `Successed to register dpdk interface`；**slim primary 无后者**，勿误判）；固定端口探测与 ab 串行；启动用绝对路径；切配置前 `kill_process.sh` + `rm_tmp_file.sh` 清 `/var/run/dpdk/rte/`。
- 已知无害噪声（不得据此判失败）：内核态网卡被 EAL 扫描的三条 VIRTIO/PCI 报错；secondary 的 `Connection refused`/`vdev_scan` 类伴随噪声（primary_slim 08 §7.2 原文经验）。

### 2.2 A 组：cmocka 真 EAL 集成用例（tests/integration，进 CI）

新增独立二进制 `test_ff_reload_integration`（独立 `--file-prefix`，理由同 primary_slim 08 §3.1：单进程内 EAL 只能 init/cleanup 一次）。

| 编号 | 用例 | 步骤 | 判据 | 对应 |
|---|---|---|---|---|
| IT-NR-A01 | FF_RELOAD 消息环回（含 v1.6 全部消息） | net_null0 init 后经 msg ring 发 **READY / HANDOVER_REQ / HANDOVER_ACK / DRAIN_PROGRESS / DRAIN_DONE / REJECT**（~~SWITCH_REQ/ACK~~ 已改 HANDOVER 语义） | 各消息 round-trip 类型/字段一致；未知子类型丢弃不崩 | C-NR-202/203 |
| IT-NR-A02 | flow_map 查表回调触发与归属判定（v1.6：软件分发表） | 注入构造包（本代际新流四元组 insert 后 / 未知四元组=flow_map miss）驱动 process_packets 路径 | 本代际新流→本栈处理（flow_map 命中语义）；miss→一律经 dispatch_ring enqueue 转发（目标 queue id 正确） | C-NR-301/303 |
| IT-NR-A03 | dispatch_ring 转发路径 | A02 的 enqueue 后驱动 process_dispatch_ring dequeue | 包进入 ff_veth_input；ring 来的包不二次进回调（ff_dpdk_if.c:2100 语义回归） | C-NR-303 |
| IT-NR-A04 | 状态机消息驱动 | 注入 READY 序列 → 断言 HANDOVER_REQ 发出（v1.6：~~SWITCH_REQ~~ 改为移交请求）；注入部分 READY 缺失 → 不发 | 转移与 UT-NR-10 一致 | C-NR-205/306 |
| IT-NR-A06 | **DRAIN_DONE/REJECT 消息集成**（v1.6 新增） | 注入 DRAIN_DONE → 断言 G_new flow_map close 生效；注入双 reload 场景 → 断言 REJECT 返回 | DRAIN_DONE 后 flow_map 查表停止；REJECT 场景 master 拒绝并记日志 | C-NR-202/403 |
| IT-NR-A07 | **ARP/NDP clone 给 G_old**（v1.6 新增） | 注入 ARP/NDP 包驱动 process_packets；观察 clone 行为 | 包被 clone 一份转发给所有 G_old（原有 clone 给 G_new/KNI 不受影响） | C-NR-304 |
| IT-NR-A08 | **flow_map 三态判定完整性**（v1.6 新增，v1.2 修正入表时机） | 注入**完整三次握手 + 数据**序列：SYN →（本栈发 SYN-ACK，此时断言已入表）→ 第 3 个 ACK → 数据包；再注入未入表的旧连接包 | ① SYN 到达并在发出 SYN-ACK 时入表；② **第 3 个 ACK 到达时（连接尚在 syncache、尚未 `accept()`）查表必命中、本栈处理、不转 G_old**；③ 数据包命中本栈；④ 未入表的旧连接包 miss→转 G_old；⑤ **协议过滤：ARP/NDP/ICMP 包不参与 flow_map 判定，直接返回 `queue_id` 走原生克隆路径** | C-NR-301/303 |
| IT-NR-A05 | `graceful_reload=0` 零回归 | 同 init 不注册消息族/回调 | handle_msg 对 FF_RELOAD 类型返回未支持（不崩）；回调未注册 | C-NR-101 门控 |

### 2.3 B 组：实机用例矩阵（RT-00~13，C-NR-601 harness 承载）

**脚本硬性规约**：真实执行 + 逐用例判定 + pass/fail 汇总退出码；TARGET_IP 必填（缺省 usage+exit 2）；严禁硬编码 IP；进程终止/清理/加执行位只走三个规约脚本（`kill_process.sh` / `rm_tmp_file.sh` / `chmod_modify.sh`）。

| 编号 | 场景 | 步骤要点 | 通过判据 | 阶段 |
|---|---|---|---|---|
| RT-00 | 启动基线 | `graceful_reload=1` 全 secondary 启动 + ab 3 轮 | 启动全成功；QPS 落在 PT-NR-01 基线噪声区间；Failed=0 | M1 |
| RT-01 | 空载 HUP | 无流量 reload | T0→T5 状态打点完整；G_old 退出/G_new 接管；服务恢复可访问；无 crash | M2（放宽版）/M4（全判据） |
| RT-02 | 带长连接流量 HUP | 12+ 条 keep-alive 探测持续，中途 reload | **探测 0 失败**；旧连接全部由 G_old drain 完成后自然关闭（或继续服务至客户端断开）；新连接由 G_new accept（日志/计数证实）；无 RST；**排空确认后 G_new 关闭 flow_map 回稳态：查表计数停止增长、稳态 pps/时延与 reload 前基线一致（flow_map 窗口化验证，[06] 第 2 节语义 6）；ARP/NDP 正常（G_old drain 期邻居表有效，[06] 第 2 节语义 9）** | M3/M4 |
| RT-03 | 持续 CPS 压力下 HUP | ab 短连接持续打满，中途 reload | **connect/read/write error = 0**；ab 两段（reload 前后）均 Failed=0 | M3 |
| RT-04 | USR2 带流量升级 | 同 RT-02 流量下 USR2 换二进制 | 错误 0；新 master+G_new 接管；老 worker drain；pid 双文件共存期正确 | M5 |
| RT-04b | 升级失败回退 | USR2 后新二进制配置错 → 对老 master HUP | 老代际继续服务；回退后 HUP/QUIT 链路正常 | M5 |
| RT-05 | 异常：新 worker 起不来 | 注入（配置错/READY 超时，测试构建含 `FF_RELOAD_FAULT_INJECTION` 开关） | G_old 全程服务零影响；master 放弃本轮有明确日志；状态机回 T0 | M4 |
| RT-06 | 异常：旧 worker 不退 | 构造 drain 挂起（长连接不关 + 压低超时） | shutdown timer 强退生效；reload 不永久挂起；强退前连接得到 graceful 尝试 | M4 |
| RT-07 | 异常：移交失败（v1.6：~~reta 更新失败~~ → 同期移交失败） | 故障注入使 HANDOVER_REQ 返回 error 或互斥标记超时 | 回退停留 T2；G_old 继续服务（互斥标记保证不会并发 poll）；告警打点；无半移交状态 | M4 |
| RT-08 | 异常：双 primary 误启 | 人为再拉一个 primary 进程 | DPDK EAL 拒绝（现有机制）；既有进程组不受影响；报错明确 | M1 |
| RT-09 | reload 中杀 slim primary | T2~T3 窗口 kill_process.sh 杀 primary | 数据面零中断（primary_slim E3b 已验语义回归）；本轮 reload 安全放弃 + 降级告警 | M4 |
| RT-10 | 连续多轮 reload | 空载+轻流量连续 20 轮；每轮 drain 完成前注入一次抢先 HUP | **每轮 proc_id/queue 映射一致（v1.6 不再乒乓交替）**；无资源泄漏（mbuf 水位平稳、`rte_mempool_avail_count` 无单调下降趋势）；20/20 成功；**抢先 HUP 均被拒绝且记日志（reload 防重入），排空确认后下一轮 HUP 正常放行（[06] 第 2 节语义 6）**；**跨代 mbuf 无泄漏、无 pool 错配（C-NR-308 回归）** | M4 |
| RT-11 | （可选）内核栈混跑对照 | `kernel_network_stack` 指令部分 server 走内核栈（127.0.0.1）+ reload | 内核栈 server 全程不受影响 | M6 |
| RT-12 | KNI 启用 reload | `enable_kni=1` 下 RT-02 复跑（RV8） | 同 RT-02 判据 + KNI 管理面（ping/ssh 旁路）reload 后仍可用 | M6 |
| RT-13 | zc 收包路径 reload | zc 场景配置下 RT-02 复跑 | 同 RT-02 判据（回调判定与 mbuf 来源无关的验证） | M6 |
| **RT-14**（v1.2 新增） | **同核高负载切换（RV10 集成复验）** | 新旧进程同物理核（不同 lcore_id）配置下，在**高负载**（ab 打满 + 长连接探测）触发 reload，观测切换瞬间与整个 drain 期 | ① 切换瞬间客户端错误数 0；② 记录两侧有效算力占比（预期各约 50%）与切换瞬间 pps 下凹；③ **drain 时长相对独立物理核形态的延长倍数**（量化「drain 变慢→抢核更久」正反馈）；④ 无死锁无 crash | M4/M6 |

**通用通过判据定义**：
- **丢包=0**：客户端侧 connect error=0、read error=0、timeout=0（探测脚本与 ab 汇总）；服务端侧 NIC 计数 reload 窗口前后 `imissed/ierrors` 无异常增长（ff_top 采样对比）。
  > **【v1.2 补充·virtio 判据陷阱】** virtio PMD 的 stats **无 `imissed`**（源码仅上报 `ierrors` 与 `rx_nombuf`），而无主队列/移交窗口的丢包发生在 **host 侧**（vring 无可用 buffer → 后端 drop），**guest 侧完全不可观测**。故在 virtio 环境上本判据**必须以端到端业务指标为准**：客户端错误数/重传率/时延 + 宿主机侧 tap/vhost 队列统计（`ip -s link` 等，需宿主机权限）。`ierrors`/`rx_nombuf` 无增长**不得**作为「无丢包」的证据。物理网卡环境可正常使用 `imissed`。
- **存量连接 drain 完成**：reload 前建立的连接全部服务至自然关闭（客户端主动断或 keepalive 超时），drain 期间探测 0 失败；drain 时长有打点。
- **新连接零失败**：切流后到达的 SYN 全部被 accept（不允许 RST/超时）。
- **reload 耗时上限**：T0→T3（新配置生效）≤ M0 基线（E-NR-04 实测旧串行空窗 + 新 worker 初始化时长）× 1.5；T0→T5 ≤ drain 强退阈值。具体数值以 M0 报告为准写入 A-NR-14。

## 3. 性能基线测试计划（PT-NR-01~06）

### 3.1 指标与工具

| 指标 | 采集方式 |
|---|---|
| 吞吐（QPS） | `ab -k -c 50 -n 20000 http://<DPDK_NIC_IP>/`，每配置 3 轮取区间与均值（沿用 primary_slim 06 方法保证可比） |
| CPS | ab 短连接（去 -k）轮次折算 + 探测脚本建连计数 |
| 延迟 avg/P50/P99 | ab 的 percentage 输出 + python 探测脚本逐请求计时分布（reload 瞬态以探测脚本为主，采样粒度 2s） |
| reload 瞬态 | 切流时延（T3 打点）、drain 时长（T5 打点）、reload 窗口时延毛刺 P99 劣化幅度、吞吐下凹深度/时长、错误数 |
| 资源 | mbuf 池可用数、dispatch_ring 水位、进程 CPU（ff_top/ps 采样） |

> 工具如实声明：本环境 `wrk` 不可用（primary_slim 08 §7.1）；恒定速率压测（wrk2 型）以 ab 开环 + python 恒速客户端近似替代；JMeter（VPP 社区 #3547/#3645 复现模式用的 100 线程）在客户端机 Java 可用时作为循环门禁的备选客户端。boost-nginx 类工具链本环境未部署，不作为依赖。

### 3.2 对照配置

| 编号 | 用例 | 对照 | 判据 |
|---|---|---|---|
| PT-NR-01 | 稳态基线（改造前 + `graceful_reload=0` 改造后各测一次） | 自身 | 两次基线差在噪声区间内（证明代码合入零回归）；绝对值沿用「仅同配置对照」原则（客户端是瓶颈，primary_slim 06 §4.4 已证） |
| PT-NR-02 | reload 后新代际稳态 vs reload 前稳态 | PT-NR-01 | QPS 差在噪声区间内；Failed=0 |
| PT-NR-03 | reload 瞬态 | PT-NR-01 稳态 | 窗口内错误数 0；P99 劣化幅度与时长有记录（形成瞬态画像，供 DR7 判据） |
| PT-NR-04 | drain 期开销：G_old drain 高峰（80% 流量在旧连接——RV4 场景构造）期间 G_new 吞吐 | PT-NR-01 | 有量化数据；若 reload 窗口内吞吐下降 >5%、P99 劣化 >10% 或 drain 时长超 SLO 触发 DR7 评审（v1.3 修订判据，流表窗口化后稳态损耗恒 0） |
| PT-NR-05 | **循环 reload 门禁**（[01](01-vpp-vcl-research.md) §6.3-7 适配 v1.6 防重入语义） | — | 分档：M4 20 次 → M6 **≥100 次**；持续流量 + **每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次**（reload 成功计算一次）；判据：错误数 0、无死锁无 crash、无内存泄漏趋势。VPP 前车之鉴（#3547 连环 crash、#3645 卡死，[01](01-vpp-vcl-research.md) §4.3）正是此门禁要拦的。v1.6 修订原因：v1.3 防重入语义（排空前拒绝新 reload）+ 25s 初始化时延使「每 2~5s reload、≥1000 次」不可同时成立——防重入下 999 次会被拒 |
| PT-NR-06 | 稳态零开销验证：`graceful_reload=1` 不 reload 稳态 vs `=0` 稳态 | PT-NR-01 | 差在噪声区间内（验证 T5 后回调注销路径生效——**C-NR-303 须含回调注销**：G_old 全退后 G_new 注销 dispatcher 回调，回到零开销稳态） |
| **PT-NR-07**（v1.2 新增，RV10） | **同核处理切换瞬间性能**：高负载下触发 reload，采集切换瞬间的 pps/丢包/两侧 CPU 占用，与独立物理核形态对照 | 自身（同核 vs 独立核两形态对照） | 产出量化数据：切换瞬间丢包数、两侧有效算力占比、drain 时长延长倍数。判据：客户端错误数 0；若 drain 时长延长 >2× 或切换丢包不可接受 → 触发 DR5 重新评估部署形态（改独立物理核） |
| **PT-NR-08**（v1.2 新增，RV6，**阻塞发布**） | **自驱 hardclock 精度回归**（C-NR-307）：RTO/keepalive/延迟 ACK 的触发精度与 `graceful_reload=0`（`rte_timer` 挂槽）基线对比 | E-NR-03 采集的改造前基线 | ① RTO/keepalive/延迟 ACK 实测精度与基线偏差在可接受范围（建议 ≤5%，阈值待 M0 校准）；② 无漏触发/重复触发；③ `graceful_reload=0` 与改造前**行为等价**（QPS/时延在噪声区间内）。**此项是 C-NR-307 的合入门槛，不可省略** |
| **PT-NR-09**（v1.2 新增，C-NR-308） | **应用 mempool 分代际 + `cache_size=0` 的稳态性能损失量化** | PT-NR-01（cache_size 原值基线） | ① 稳态 QPS/时延损失量化（iWiki 18.11 实测「很小」，24.11 virtio 待复测）；② 跨代 alloc/free 无泄漏（`rte_mempool_avail_count` 无单调下降）；③ 无 pool 错配（无 mbuf 校验错误/crash）。**若损失超阈值（建议 >5%）→ 启用备选方案 B（`local_cache[]` 索引改 workerid/代际 id）** |

### 3.3 噪声与限定（随数据一并给出）

- 噪声区间沿用 primary_slim 06 实测：2 数据面进程配置约 ±2.1%、1 数据面进程约 ±8.8%；区间内差异判「无回归」，不得宣称为收益。
- 绝对值仅用于同配置前后对照，严禁用于容量规划或吞吐宣称（客户端单机瓶颈）。
- ab TIME_WAIT 假象：轮间串行执行即可。

## 4. 测试通过判据汇总表（A-NR-01~20）

| 编号 | 验收内容 | 判据 | 对应用例 | 阻塞发布 | 阶段 |
|---|---|---|---|---|---|
| A-NR-01 | `graceful_reload` 默认 0 零回归 | 默认值 0；`=0` 时新校验全不生效 | UT-NR-01/07/08；IT-NR-A05；RG-NR-01 | ✅ | M1 |
| A-NR-02 | 配置校验链完备（互斥/依赖/段容量） | 4 类误配组合均配置期拒绝 | UT-NR-03/05/06 | ✅ | M1/M2 |
| A-NR-03 | worker 全 secondary + 常驻 primary | 启动成功；无 worker0 primary 竞争；RT-08 双 primary 被拒 | RT-00/RT-08 | ✅ | M1 |
| A-NR-04 | 双代际并存稳定（RV1） | 并存 ≥30min + RT-10 全绿 | RT-10；RV1 记录 | ✅ | M2 |
| A-NR-05 | READY 显式协议取代旧时序 | 无 500ms/15s 经验等待依赖；打点可证 | RT-01 状态日志 | ✅ | M2 |
| A-NR-06 | 多代际 listen 并存（RV7 终验） | E-NR-01 + RT-01/02 | E-NR-01；RT-02 | ✅ | M2/M3 |
| A-NR-07 | **同期移交正确性**（v1.6 改名，原「reta 原子切流（RV2 终验）」；~~RV2~~ 已取消） | 移交全程队列始终有主（互斥标记保证不并发 poll）；移交后 G_new 接管 listen；无半移交状态 | E-NR-02b；RT-02/RT-07 | ✅ | M3 |
| A-NR-08 | 转发兜底正确（v1.6：flow_map miss → ring 转 G_old；ARP/NDP clone） | 旧连接包达 G_old；drain 期探测 0 失败；G_old 邻居表有效 | IT-NR-A02/A03/A07/A08；RT-02 | ✅ | M3 |
| A-NR-09 | 带流量 reload 零错误（核心） | RT-02/RT-03 判据全满足 | RT-02/RT-03 | ✅ | M3/M4 |
| A-NR-10 | timer 隔离（RV6 终验） | 并存期 RTO/keepalive 正常 | RV6 记录 | ✅ | M2 |
| A-NR-11 | drain 语义完整 | 存量连接自然关闭；进度可观测 | RT-02 | ✅ | M4 |
| A-NR-12 | drain 强退生效 | RT-06 判据 | RT-06 | ✅ | M4 |
| A-NR-13 | 异常回退完备（DR6） | RT-05/07/09 判据 | RT-05/07/09 | ✅ | M4 |
| A-NR-14 | reload 耗时上限 | T0→T3 ≤ 基线×1.5；T0→T5 ≤ 强退阈值（数值随 M0 报告定） | PT-NR-03；打点 | ✅ | M4 |
| A-NR-15 | USR2 升级 + 回退 | RT-04/04b 判据 | RT-04/04b | ✅ | M5 |
| A-NR-16 | 循环 reload 终门禁（RV9，v1.6 修订） | ≥100 次零错误无死锁无泄漏（每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次） | PT-NR-05 | ✅ | M6 |
| A-NR-17 | 稳态零性能损耗 | PT-NR-01/02/06 判据 | PT-NR-01/02/06 | ✅ | M6 |
| A-NR-18 | KNI/zc 回归（RV8 + 正交验证） | RT-12/13 通过或有明确限制结论 | RT-12/13 | ❌（须有结论） | M6 |
| A-NR-19 | 全编译组合 clean build + 无泄漏 | 矩阵 exit 0；make check exit 0 | RG-NR-02 | ✅ | 各里程碑 |
| A-NR-20 | 文档与运维手册入库 | 部署/降级/阈值文档齐 | C-NR-604 | ✅ | M6 |
| **A-NR-21**（v1.2 新增，RV6） | **自驱 hardclock timer 精度**（C-NR-307） | RTO/keepalive/延迟 ACK 精度与改造前基线偏差可接受；无漏/重复触发；`graceful_reload=0` 行为等价 | PT-NR-08；UT-NR-17 | ✅ | M2 |
| **A-NR-22**（v1.2 新增，RV10） | **同核处理切换无损**（[06] §6.3 X3 决策项） | RT-14/PT-NR-07 判据：切换瞬间错误数 0；drain 时长延长倍数在可接受范围（阈值 RT-14 校准） | RT-14；PT-NR-07 | ✅ | M4/M6 |
| **A-NR-23**（v1.2 新增，C-NR-308） | **应用 mempool 分代际正确性** | 跨代 alloc/free 无泄漏、无 pool 错配、无 crash；`cache_size=0` 的稳态性能损失量化在阈值内 | PT-NR-09；UT-NR-18；RT-10 | ✅ | M2/M6 |

**回归项（RG-NR）**：
- RG-NR-01：`graceful_reload=0` 全量回归（每里程碑必跑：旧两段式 reload 行为不变、既有单测零变红）。
- RG-NR-02：编译组合矩阵 clean build（默认/FF_KNI/FF_FLOW_ISOLATE/FF_FDIR/FF_USE_PAGE_ARRAY/FF_RSS_DIAG/FF_KERNEL_COEXIST/FF_LOOPBACK_SUPPORT + 本特性开关两态）。
- RG-NR-03：primary_slim 既有能力回归（IT-1078/IT-RT 系列抽测：杀 primary 数据面零中断、CPU ≤5%、工具链不挂起）。
- RG-NR-04：单进程模式（`ngx_single_process_cycle` 路径，[04](04-fstack-current-analysis.md) §2.3）不受影响。
- RG-NR-05：内核栈对照（127.0.0.1 原生路径 + kernel_network_stack 混跑，RT-11）。
- RG-NR-06：MTU/pcap/vlan/bond 等特性单测零回归（不新增用例，跑既有）。

## 5. 未覆盖风险声明（诚实边界）

1. **PMD 局限与 virtio 观测盲区**（v1.2 改写）：本机仅 virtio 系设备 + igb_uio。
   - ~~reta 运行时更新（RV2）在物理网卡上的支持度未验证~~：v1.6 起 S3 **不再调用 `set_rss_table`、不依赖任何 NIC RSS 能力**，该项已不适用；`net_null` 的 reta 支持确认亦随之取消。
   - **virtio 观测盲区（新增，关键）**：virtio PMD stats **无 `imissed`**，移交窗口/无主队列的丢包发生在 host 侧，**guest 侧不可观测**。因此「丢包=0」这一核心判据在 virtio 上只能靠端到端业务指标 + 宿主机侧 tap/vhost 统计（后者需宿主机权限，多数云环境拿不到）。**这意味着本机环境无法为「移交窗口零丢包」提供强证据**，该结论的强度须如实标注为「端到端无业务错误」而非「实测零丢包」。
   - 物理网卡（ixgbe/i40e/mlx5/ice）上的同期移交互斥（RV3）行为**未验证**，结论不可外推；上线物理网卡前须补 RV3 终验（可直接用 `imissed` 判据）。
2. **IPv6 场景未覆盖**：本机 f-stack IPv6 存在独立的 13→15 回归问题（另行跟踪中），本文全部实机用例以 IPv4 为主；IPv6 reload 回归列为环境受限项，待 IPv6 问题闭环后补。
3. **HTTPS/TLS 长连接 drain 未专项**：openssl 握手连接在 drain 期的行为（session 恢复、握手中途切流）未设专项用例，列为 M6 可选补充。
4. **UDP/stream/mail 模块未专项**：nginx stream（L4 proxy）与 mail 模块的 reload 语义依赖 TCP 同机制，理论同源但未实测。
5. **单机客户端瓶颈**：全部性能绝对值仅用于同配置对照；CPS 上限类指标受 ab/探测脚本能力限制，不能反映 10G 线速（RV5 的 10G 小包回调开销只能以 CPU 占比间接度量）。
6. **多 NUMA/多 port 异构**：proc_id 代际无关映射校验链按单 port 同构设计（DR5 默认），多 port 异构 lcore_list 下的映射布局列为未决（第 6 节 U-NR-3）。
9. **同核形态的调度依赖**（v1.2 新增）：[06] §6.3 X3 决策以「新旧进程同核」为默认形态，其 drain 期性能依赖内核调度行为与 `idle_sleep` 配置。RT-14/PT-NR-07 只能给出本环境的量化数据，**不同核数/不同负载模型下不可外推**。
7. **M7（dispatcher 中心化）不在本计划覆盖内**：若 DR7 触发须另立 spec 与测试计划。
8. **单来源证据沿用声明**：本计划继承 [06-方案设计](06-solution-design.md) §8 的单来源清单（iWiki 旧方案数据、FB LPC 译文细节、primary_slim 实测数据未经本团队复测等），相关推论强度以该节为准。

## 6. 未决问题

| 编号 | 未决问题 | 影响 | 处置建议 |
|---|---|---|---|
| U-NR-1 | slim primary 拉起方式（DR1 候选 a/b）最终定案 | M1 编码形态、M5 USR2 细节 | M0 评审定案；倾向候选 b（master 代管 + double-fork），运维零新增 |
| U-NR-2 | FF_RELOAD 走 ff_msg ring 还是专用 ring（DR4） | M2 容量与实时性 | M0/M2 前评审；先按复用 msg ring 设计，压测不满足再加专用 ring |
| U-NR-3 | 多 port 异构 lcore_list 下的 **proc_id 代际无关映射**布局（v1.6 后不再称「乒乓布局」） | 校验链复杂度 | DR5 定案；首版可显式仅支持单 port 同构，多 port 拒绝并文档声明 |
| U-NR-4 | drain 强退阈值默认值 | A-NR-12 | 对齐 nginx worker_shutdown_timeout 语义，RT-06 校准后写默认值 |
| U-NR-5 | 回调注销的精确时点（最后一个 G_old 退出即注销 vs 延迟注销防乱序包） | PT-NR-06 稳态零开销 | M3 实现时以「dispatch_ring 排空 + G_old 全退」双条件注销，RT 用例验证无乱序丢包 |
| U-NR-6 | 故障注入开关（RT-05/07 依赖）的形态 | 测试构建 | 建议 `FF_RELOAD_FAULT_INJECTION` 编译宏，仅测试构建启用，禁入生产默认编译 |
| U-NR-7 | 状态机打点的落点（日志 vs ff_top 计数） | 可观测性 | M2 实现时两者兼有：关键转移打 NOTICE 日志 + ff_top 增加 reload 状态字段 |

---

**配套文档**：方案设计见 [06-方案设计](06-solution-design.md)；里程碑与编码清单见 [07-里程碑](07-milestones.md)；本计划为 M0~M7 全周期测试规划，M0 报告（`work/m0-poc-report.md`）产出后据实修订耗时上限（A-NR-14）与 DR 定案引用。
