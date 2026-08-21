# 08 测试计划：单元测试、集成测试、性能基线与验收标准

| 项 | 值 |
|---|---|
| 文档编号 | 08 |
| 标题 | Nginx 无损 reload（S3 方案）测试计划（UT/IT/PT/A/RG 编号体系） |
| 版本 | v1.0 |
| 日期 | 2026-08-18 |
| 状态 | 待人工审计 |
| 来源产物 | work/milestones-testing.md（规划师 milestone-planner，2026-08-18 落盘）。本篇为其测试计划部分的正式化改写；里程碑与编码工作清单部分拆分至 [07-里程碑](07-milestones.md)。对齐 docs/primary_slim_spec/zh_cn/08-测试规格.md 的测试篇风格 |

相关篇章：[00-总览](00-overview.md) | [06-方案设计](06-solution-design.md) | [07-里程碑](07-milestones.md)

---

## 摘要

本测试计划覆盖 [07-里程碑](07-milestones.md) M0~M7 全周期：**16 条单测用例（UT-NR-01~16）+ 9 个 fixture + 5 条真 EAL 集成用例（IT-NR-A01~05）+ 15 行实机用例（RT-00~13，含 RT-04b）+ 6 条性能基线用例（PT-NR-01~06）+ 20 项验收标准（A-NR-01~20）+ 6 项回归（RG-NR）**，含循环 reload 门禁（v1.6 修订：每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次，≥100 次零错误，依据 [01-VPP/VCL 调研](01-vpp-vcl-research.md) §6.3-7 验证模式并适配防重入语义）与未覆盖风险声明。

> 【数字口径说明】本篇规模数字以实际清点为准：5 条真 EAL 集成用例（IT-NR-A01~05）、15 行实机用例（RT-00~13，含 RT-04b）。来源产物 work/milestones-testing.md 中的同源旧数字（6/13）系中间产物原文，不回改；如与本篇冲突以本篇为准。

## 1. 单元测试计划

### 1.1 框架与现状（对应仓库 tests/unit）

沿用 `tests/unit/` 既有 CMocka（≥1.1.7，Makefile 有 `$(error)` 版本门禁）体系：`load_with_fixture()` / `load_with_proc()` 加载 fixture + `cmocka_unit_test_setup_teardown(fn, test_setup, NULL)` 注册 + `cmocka_run_group_tests()`；**不另建框架、不新增测试二进制**（状态机纯函数用例落在 `test_ff_config.c`/`test_ff_dpdk_if.c` 既有二进制内；若膨胀再评估拆文件，同 primary_slim 08 T8 的权衡）。fixture 地址一律 `192.168.1.x` 文档地址，文件头写意图注释。

### 1.2 用例清单（UT-NR-01~16）

| 编号 | 用例名 | 目的 | 输入 | 预期 | 对应编码点 |
|---|---|---|---|---|---|
| UT-NR-01 | `test_graceful_reload_default_off` | 默认 0，零回归 | `valid_dpdk_full.ini`（既有，无新键） | `graceful_reload==0`；既有语义不变 | C-NR-101 |
| UT-NR-02 | `test_graceful_reload_parse` | `=1` 解析合法 | `valid_graceful_reload.ini`（含 `primary_slim=1`）+ `load_with_proc(...,"secondary","0")` | `rv==0`；`graceful_reload==1` | C-NR-101 |
| UT-NR-03 | `test_graceful_reload_requires_slim` | `graceful_reload=1 && primary_slim=0` 拒绝 | `invalid_greload_no_slim.ini` | `rv==-1`，stderr 含明确原因 | C-NR-101 |
| UT-NR-04 | `test_pingpong_lcore_valid` | 2N 段配置合法 | `valid_pingpong_2n.ini`（N=2 worker，lcore_mask 含 4 段核 + primary 核） | `rv==0`；段划分字段正确 | C-NR-201 |
| UT-NR-05 | `test_pingpong_lcore_insufficient` | 段容量不足拒绝 | `invalid_pingpong_short.ini`（仅 N 核） | `rv==-1` | C-NR-201 |
| UT-NR-06 | `test_greload_thread_mode_mutex` | 与 thread_mode=1 互斥 | `invalid_greload_thread_mode.ini` | `rv==-1`；既有 TC-CM1-01..03 不受影响 | C-NR-101/201 |
| UT-NR-07 | `test_greload_off_no_new_checks` | `=0` 时全部新校验不生效（含乒乓段不配也不报错） | `valid_dpdk_full.ini` 变体（无乒乓段） | `rv==0` | C-NR-201 零回归 |
| UT-NR-08 | `test_greload_bad_value_atoi` | 非数字退化为 0（记录既有 atoi 语义） | `graceful_reload=abc` | `graceful_reload==0`、`rv==0` | C-NR-101 |
| UT-NR-09 | `test_dispatch_ring_capacity_parse` | ring 容量项解析与默认值 | 显式值/缺省两 fixture | 显式生效；缺省=现默认值 | C-NR-305 |
| UT-NR-10 | `test_reload_fsm_transitions` | 状态机转移表：合法转移（T0→T1→T2→T3→T4→T5）通过；非法转移（如 T0 直接 T4、T3 回 T1）拒绝且打点 | 直接调 `ngx_ff_reload.c` 纯转移函数（需设计为无副作用可测） | 合法路径状态推进正确；非法路径返回错误不转移 | C-NR-205/403/404 |
| UT-NR-11 | `test_reta_recalc_pure_fn` | reta 重算纯函数：给定 QB 段 → 全部表项指向 QB；QB 为空时拒绝 | 本地构造队列集参数 | 表项覆盖断言；边界（reta 表大小非 2 的幂） | C-NR-302 |
| UT-NR-12 | `test_pingpong_generation_flip` | 乒乓翻转记账：连续两轮 reload 的段分配交替 | 模拟两轮状态机 T5 推进 | 第二轮 G_new' 绑段 A | C-NR-206/403 |
| UT-NR-13 | `test_conn_owner_query_args` | `ff_conn_owner_query` 参数校验与错误路径（NULL 四元组/非法 family） | 直接调用 | 返回错误码不崩溃 | C-NR-301 |
| UT-NR-14 | `test_ff_reload_msg_serdes` | FF_RELOAD 消息构造/序列化/解析/坏消息丢弃 | 本地构造消息体 | round-trip 一致；截断/魔数错丢弃 | C-NR-202 |
| UT-NR-15 | `test_fsm_ready_timeout_gives_up` | T2 READY 超时 → 放弃本轮，状态回 T0 且 G_old 未动（状态机层） | 注入超时事件序列 | 状态回退正确 + 打点含放弃原因 | C-NR-404 |
| UT-NR-16 | `test_fsm_switch_fail_rollback` | T3 切流 ACK(error) → 停在 T2 放弃，不推进 T4 | 注入失败 ACK | 同上 | C-NR-306/404 |

> 诚实标注：`ff_conn_owner_query` 的真实归属判定（栈内已有连接）依赖 FreeBSD 栈状态，单测层不可达——由 IT-NR-A02 与 RT-02 覆盖；单测仅覆盖参数/错误路径（同 primary_slim 08 §1.1.4 的可达性标注法）。流表窗口语义（READY 后生效/miss 一律转 G_old/排空确认后关表）属状态机与回调注册逻辑，由 UT-NR-10 状态机转移 + RT-02/RT-10 判据覆盖。

### 1.3 新增 fixture 清单（F-NR-1~9，置于 tests/unit/fixtures/）

| # | 文件名 | 要点 |
|---|---|---|
| F-NR-1 | `valid_graceful_reload.ini` | `primary_slim=1` + `graceful_reload=1` + 2N 乒乓段 + `lcore_list` 排除 primary 核 |
| F-NR-2 | `invalid_greload_no_slim.ini` | 同上但 `primary_slim=0` |
| F-NR-3 | `valid_pingpong_2n.ini` | N=2、4 数据核 + 1 primary 核的合法布局 |
| F-NR-4 | `invalid_pingpong_short.ini` | 仅 N 核（无乒乓余量） |
| F-NR-5 | `invalid_greload_thread_mode.ini` | + `thread_mode=1` |
| F-NR-6 | `valid_greload_bad_value.ini` | `graceful_reload=abc` |
| F-NR-7 | `valid_dispatch_ring_cap.ini` | 显式 ring 容量 |
| F-NR-8 | `valid_greload_no_pingpong_off.ini` | `graceful_reload=0` 且无乒乓段（零回归用） |
| F-NR-9 | `valid_greload_2port.ini` | 多 port 乒乓段（若 DR5 定案支持） |

### 1.4 mock 策略

| 被测依赖 | 单测层 | 集成层（真 EAL） | 实机层 |
|---|---|---|---|
| reta 更新（`rte_eth_dev_rss_reta_update`/`set_rss_table`） | **mock**：记录调用参数，断言重算后的 reta 表内容（UT-NR-11 配套）；`rte_stub.c` 扩展 | `net_null0` 上真调用——**注意**：net_null PMD 对 rss_reta 的支持需在用例编写时实测确认；不支持则该断言降级 mock-only，真验证移实机（RT-02 抓包） | 抓包验证新 flow 导向（RV2 终验） |
| rte_ring（dispatch ring） | 不 mock（纯逻辑不触 ring） | 真 ring（net_null + 回调路径） | RT-02/RT-03 |
| ff_msg 通道 | 消息 serdes 纯函数 | 真 msg ring 环回（IT-NR-A01） | — |
| EAL/进程模型 | 不可达（沿用既有边界结论） | `--no-huge --no-pci --no-shconf -l 0 -m 64 --vdev=net_null0 --file-prefix=ff_reload_test`（**新前缀避免冲突**） | 全真 |

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
   ├─ G_old worker ×N（secondary，lcore 段 A / queue 集 QA）
   └─ G_new worker ×N（reload 时 secondary attach，lcore 段 B / queue 集 QB）
内核栈对照：127.0.0.1（lo）跑原生路径 nginx（RG-NR-05）
```

- 客户端工具：`ab`（`-k -c 50 -n 20000`，wrk 本环境不可用——primary_slim 08 §7.1 实测）；python 探测脚本（`_e2_probe_client.py` 模式：固定本地端口 20000+i 建 N 条 keep-alive 长连接每 2s 逐条 GET 校验 200，扩展逐请求计时供 P50/P99）。
- 时序约束（沿用 primary_slim 08 §7.3）：worker 初始化约 25s，脚本轮询日志就绪标志（FreeBSD 栈初始化完成；持队列进程另有 `Successed to register dpdk interface`；**slim primary 无后者**，勿误判）；固定端口探测与 ab 串行；启动用绝对路径；切配置前 `kill_process.sh` + `rm_tmp_file.sh` 清 `/var/run/dpdk/rte/`。
- 已知无害噪声（不得据此判失败）：内核态网卡被 EAL 扫描的三条 VIRTIO/PCI 报错；secondary 的 `Connection refused`/`vdev_scan` 类伴随噪声（primary_slim 08 §7.2 原文经验）。

### 2.2 A 组：cmocka 真 EAL 集成用例（tests/integration，进 CI）

新增独立二进制 `test_ff_reload_integration`（独立 `--file-prefix`，理由同 primary_slim 08 §3.1：单进程内 EAL 只能 init/cleanup 一次）。

| 编号 | 用例 | 步骤 | 判据 | 对应 |
|---|---|---|---|---|
| IT-NR-A01 | FF_RELOAD 消息环回 | net_null0 init 后经 msg ring 发 READY/SWITCH_REQ/ACK/DRAIN_PROGRESS | 各消息 round-trip 类型/字段一致；未知子类型丢弃不崩 | C-NR-202/203 |
| IT-NR-A02 | dispatcher 回调触发与归属判定 | 注入构造包（本代际新流四元组 / 未知四元组=流表 miss）驱动 process_packets 路径 | 本栈新流→本栈处理（流表命中语义）；miss→一律回调返回目标 queue id 且 enqueue 发生 | C-NR-301/303 |
| IT-NR-A03 | dispatch_ring 转发路径 | A02 的 enqueue 后驱动 process_dispatch_ring dequeue | 包进入 ff_veth_input；ring 来的包不二次进回调（ff_dpdk_if.c:2100 语义回归） | C-NR-303 |
| IT-NR-A04 | 状态机消息驱动 | 注入 READY 序列 → 断言 SWITCH_REQ 发出；注入部分 READY 缺失 → 不发 | 转移与 UT-NR-10 一致 | C-NR-205/306 |
| IT-NR-A05 | `graceful_reload=0` 零回归 | 同 init 不注册消息族/回调 | handle_msg 对 FF_RELOAD 类型返回未支持（不崩）；回调未注册 | C-NR-101 门控 |

### 2.3 B 组：实机用例矩阵（RT-00~13，C-NR-601 harness 承载）

**脚本硬性规约**：真实执行 + 逐用例判定 + pass/fail 汇总退出码；TARGET_IP 必填（缺省 usage+exit 2）；严禁硬编码 IP；进程终止/清理/加执行位只走三个规约脚本（`kill_process.sh` / `rm_tmp_file.sh` / `chmod_modify.sh`）。

| 编号 | 场景 | 步骤要点 | 通过判据 | 阶段 |
|---|---|---|---|---|
| RT-00 | 启动基线 | `graceful_reload=1` 全 secondary 启动 + ab 3 轮 | 启动全成功；QPS 落在 PT-NR-01 基线噪声区间；Failed=0 | M1 |
| RT-01 | 空载 HUP | 无流量 reload | T0→T5 状态打点完整；G_old 退出/G_new 接管；服务恢复可访问；无 crash | M2（放宽版）/M4（全判据） |
| RT-02 | 带长连接流量 HUP | 12+ 条 keep-alive 探测持续，中途 reload | **探测 0 失败**；旧连接全部由 G_old drain 完成后自然关闭（或继续服务至客户端断开）；新连接由 G_new accept（日志/计数证实）；无 RST；**排空确认后 G_new 关闭流表回稳态：回调打点计数停止增长、稳态 pps/时延与 reload 前基线一致（流表窗口化验证，[06] 第 2 节语义 6）** | M3/M4 |
| RT-03 | 持续 CPS 压力下 HUP | ab 短连接持续打满，中途 reload | **connect/read/write error = 0**；ab 两段（reload 前后）均 Failed=0 | M3 |
| RT-04 | USR2 带流量升级 | 同 RT-02 流量下 USR2 换二进制 | 错误 0；新 master+G_new 接管；老 worker drain；pid 双文件共存期正确 | M5 |
| RT-04b | 升级失败回退 | USR2 后新二进制配置错 → 对老 master HUP | 老代际继续服务；回退后 HUP/QUIT 链路正常 | M5 |
| RT-05 | 异常：新 worker 起不来 | 注入（配置错/READY 超时，测试构建含 `FF_RELOAD_FAULT_INJECTION` 开关） | G_old 全程服务零影响；master 放弃本轮有明确日志；状态机回 T0 | M4 |
| RT-06 | 异常：旧 worker 不退 | 构造 drain 挂起（长连接不关 + 压低超时） | shutdown timer 强退生效；reload 不永久挂起；强退前连接得到 graceful 尝试 | M4 |
| RT-07 | 异常：reta 更新失败 | 故障注入使 SWITCH_REQ 返回 error | 回退停留 T2；G_old 继续服务；告警打点；无半切流状态（QA/QB 均有主或全归 G_old） | M4 |
| RT-08 | 异常：双 primary 误启 | 人为再拉一个 primary 进程 | DPDK EAL 拒绝（现有机制）；既有进程组不受影响；报错明确 | M1 |
| RT-09 | reload 中杀 slim primary | T2~T3 窗口 kill_process.sh 杀 primary | 数据面零中断（primary_slim E3b 已验语义回归）；本轮 reload 安全放弃 + 降级告警 | M4 |
| RT-10 | 连续多轮 reload | 空载+轻流量连续 20 轮；每轮 drain 完成前注入一次抢先 HUP | 每轮乒乓段交替正确；无资源泄漏（mbuf 水位平稳）；20/20 成功；**抢先 HUP 均被拒绝且记日志（reload 防重入），排空确认后下一轮 HUP 正常放行（[06] 第 2 节语义 6）** | M4 |
| RT-11 | （可选）内核栈混跑对照 | `kernel_network_stack` 指令部分 server 走内核栈（127.0.0.1）+ reload | 内核栈 server 全程不受影响 | M6 |
| RT-12 | KNI 启用 reload | `enable_kni=1` 下 RT-02 复跑（RV8） | 同 RT-02 判据 + KNI 管理面（ping/ssh 旁路）reload 后仍可用 | M6 |
| RT-13 | zc 收包路径 reload | zc 场景配置下 RT-02 复跑 | 同 RT-02 判据（回调判定与 mbuf 来源无关的验证） | M6 |

**通用通过判据定义**：
- **丢包=0**：客户端侧 connect error=0、read error=0、timeout=0（探测脚本与 ab 汇总）；服务端侧 NIC 计数 reload 窗口前后 `imissed/ierrors` 无异常增长（ff_top 采样对比）。
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
| A-NR-07 | reta 原子切流（RV2 终验） | 切流前后 flow 导向正确；切换窗口 QA 始终有主 | E-NR-02；RT-02 抓包 | ✅ | M3 |
| A-NR-08 | 转发兜底正确 | 旧连接包达 G_old；drain 期探测 0 失败 | IT-NR-A02/A03；RT-02 | ✅ | M3 |
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

**回归项（RG-NR）**：
- RG-NR-01：`graceful_reload=0` 全量回归（每里程碑必跑：旧两段式 reload 行为不变、既有单测零变红）。
- RG-NR-02：编译组合矩阵 clean build（默认/FF_KNI/FF_FLOW_ISOLATE/FF_FDIR/FF_USE_PAGE_ARRAY/FF_RSS_DIAG/FF_KERNEL_COEXIST/FF_LOOPBACK_SUPPORT + 本特性开关两态）。
- RG-NR-03：primary_slim 既有能力回归（IT-1078/IT-RT 系列抽测：杀 primary 数据面零中断、CPU ≤5%、工具链不挂起）。
- RG-NR-04：单进程模式（`ngx_single_process_cycle` 路径，[04](04-fstack-current-analysis.md) §2.3）不受影响。
- RG-NR-05：内核栈对照（127.0.0.1 原生路径 + kernel_network_stack 混跑，RT-11）。
- RG-NR-06：MTU/pcap/vlan/bond 等特性单测零回归（不新增用例，跑既有）。

## 5. 未覆盖风险声明（诚实边界）

1. **PMD 局限**：本机仅 virtio 系设备 + igb_uio。reta 运行时更新（RV2）在物理网卡（ixgbe/i40e/mlx5/ice）上的支持度与行为**未验证**，结论不可外推；上线物理网卡前须补 RV2 终验。net_null PMD 对 rss_reta_update 的支持亦需在集成用例编写时确认（§1.4 已列降级路径）。
2. **IPv6 场景未覆盖**：本机 f-stack IPv6 存在独立的 13→15 回归问题（另行跟踪中），本文全部实机用例以 IPv4 为主；IPv6 reload 回归列为环境受限项，待 IPv6 问题闭环后补。
3. **HTTPS/TLS 长连接 drain 未专项**：openssl 握手连接在 drain 期的行为（session 恢复、握手中途切流）未设专项用例，列为 M6 可选补充。
4. **UDP/stream/mail 模块未专项**：nginx stream（L4 proxy）与 mail 模块的 reload 语义依赖 TCP 同机制，理论同源但未实测。
5. **单机客户端瓶颈**：全部性能绝对值仅用于同配置对照；CPS 上限类指标受 ab/探测脚本能力限制，不能反映 10G 线速（RV5 的 10G 小包回调开销只能以 CPU 占比间接度量）。
6. **多 NUMA/多 port 异构**：乒乓段校验链按单 port 同构设计（DR5 默认），多 port 异构 lcore_list 下的乒乓布局列为未决（第 6 节 U-NR-3）。
7. **M7（dispatcher 中心化）不在本计划覆盖内**：若 DR7 触发须另立 spec 与测试计划。
8. **单来源证据沿用声明**：本计划继承 [06-方案设计](06-solution-design.md) §8 的单来源清单（iWiki 旧方案数据、FB LPC 译文细节、primary_slim 实测数据未经本团队复测等），相关推论强度以该节为准。

## 6. 未决问题

| 编号 | 未决问题 | 影响 | 处置建议 |
|---|---|---|---|
| U-NR-1 | slim primary 拉起方式（DR1 候选 a/b）最终定案 | M1 编码形态、M5 USR2 细节 | M0 评审定案；倾向候选 b（master 代管 + double-fork），运维零新增 |
| U-NR-2 | FF_RELOAD 走 ff_msg ring 还是专用 ring（DR4） | M2 容量与实时性 | M0/M2 前评审；先按复用 msg ring 设计，压测不满足再加专用 ring |
| U-NR-3 | 多 port 异构 lcore_list 的乒乓布局 | 校验链复杂度 | DR5 定案；首版可显式仅支持单 port 同构，多 port 拒绝并文档声明 |
| U-NR-4 | drain 强退阈值默认值 | A-NR-12 | 对齐 nginx worker_shutdown_timeout 语义，RT-06 校准后写默认值 |
| U-NR-5 | 回调注销的精确时点（最后一个 G_old 退出即注销 vs 延迟注销防乱序包） | PT-NR-06 稳态零开销 | M3 实现时以「dispatch_ring 排空 + G_old 全退」双条件注销，RT 用例验证无乱序丢包 |
| U-NR-6 | 故障注入开关（RT-05/07 依赖）的形态 | 测试构建 | 建议 `FF_RELOAD_FAULT_INJECTION` 编译宏，仅测试构建启用，禁入生产默认编译 |
| U-NR-7 | 状态机打点的落点（日志 vs ff_top 计数） | 可观测性 | M2 实现时两者兼有：关键转移打 NOTICE 日志 + ff_top 增加 reload 状态字段 |

---

**配套文档**：方案设计见 [06-方案设计](06-solution-design.md)；里程碑与编码清单见 [07-里程碑](07-milestones.md)；本计划为 M0~M7 全周期测试规划，M0 报告（`work/m0-poc-report.md`）产出后据实修订耗时上限（A-NR-14）与 DR 定案引用。
