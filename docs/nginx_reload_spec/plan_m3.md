# Nginx 无损 reload 实现计划 · M3（plan_m3.md）

> **性质**：功能实现与验收阶段 · M3 里程碑（M0/M1/M2 已提交并通过门禁）
> **spec 基线**：`docs/nginx_reload_spec/zh_cn/07-milestones.md` v1.8
> **代码基线**：分支 `release/2.0`，base commit `7e4d4409a`
> **方式**：harness 工程 + spec 驱动 + 多 agent team（leader 轮询、写审分离、bounce≤3、门禁失败转人工）

---

## 1. 范围与决策

**M3「同期接管 rx+tx+listen + TX 独占 + flow_map」共 8 个编码点**（C-NR-301~306 + 309/310）——这是方案中**真正让 reload 变无损**的阶段。

用户已确认的三项决策：

| 决策 | 结论 |
|---|---|
| **范围** | M3 八点 **+ M2 顺延的移交补缺项**：① IT-NR-A09/A10 真 EAL harness ② `tools -g <gen>` 观测支持 ③ F5（out-ring 陈旧应答跨代错收） |
| **DR9（TX 形态）** | **(a) G_new 代发**（spec 倾向 + M0 的 RV11 一票否决已 PASS）；代价：drain 期出向也走 ring（双向各一跳） |
| **集成测试** | 新建真 EAL harness + 实机双轨（`tests/integration/` 建 IT-NR-A09/A10，同时保留 M2 的实机验证法 RT-02/RT-03） |

## 2. 已完成基线（M0/M1/M2，10 个 commit）

| commit | 内容 |
|---|---|
| `4aec26875` / `4321b873f` / `8abec9b47` | P0 修复（TCP 定时器从未挂载）+ issue #331 档案更正 + spec 回写 |
| `5a084bcb8` / `13d1b4ec7` / `850b4ba8e` | M1：`graceful_reload` 配置、常驻 slim primary、worker 全 secondary（RT-00 PASS，reload 空窗 0.718→0.102s） |
| `982a5793a` | M2 Batch A：自驱 hardclock 五处 + 三池 cache=0 + gen 池（同 lcore 双实例不再崩） |
| `b96a22dd1` / `0e511b0fa` / `7e4d4409a` | M2 Batch B：FF_RELOAD 控制面 + 代际隔离 + 心跳；T0-T5 状态机 + 看门狗；spec v1.8 |

M2 门禁裁决 **PASS**（`work/impl/m2-gate-ruling.md`）：PT-NR-08 合入门槛达标、12 轮 reload 干净（144~179ms）、FSM 打点 72/72。

## 3. 关键技术决策

### 3.1 先做锚点复核（Phase0，必做）
spec 锚点在 M1/M2 改动后**整体漂移 +275~+300 行**（`rte_eth_tx_burst` `:2495`→实际 `:2770`；`rte_eth_rx_burst` `:2872`→实际 `:3173`；`RX_QUEUE_SIZE` `ff_memory.h:43`→实际 `:54`）。任何按 spec 锚点落笔都会错位点。Phase0 产出新基线 `work/impl/m3-anchor-verifier.md`，是全部编码的落笔依据。

### 3.2 分批按「依赖层」：A 建基础设施并留 seam，B 消费 seam（严格串行）
锚点复核（`work/impl/m3-anchor-verifier.md` §6）给出比原计划更优的划分——按依赖而非文件数量：

- **Batch A（lib 基础设施）**：**C-NR-301 + C-NR-302 + C-NR-310 + C-NR-305**
  新建 `ff_flow_map.{h,c}`、`ff_drain_ring.c`；改 `ff_api.h`、`ff_memory.h`、`ff_config.{h,c}`、`ff_reload.{h,c}`、`tcp_syncache.c`、`lib/Makefile`、`tests/unit/Makefile`。
  **A 必须预留 5 个 seam 给 B**：① `ff_no_hw_mode()`（可逆）② `ff_drain_ring_rx_enqueue`/`ff_drain_ring_tx_enqueue` ③ `ff_drain_ring_rx_dequeue`（返回本轮 deque 包数，保持 `process_dispatch_ring` 返回约定供 `idle &=` 用）④ `ff_drain_ring_tx_drain`（唯一消费者，内部直接 tx_burst）⑤ `ff_handover_*` 原子读写
- **Batch B（拦截 / 主循环 / 回调 / 状态机）**：**C-NR-309 + C-NR-303 + C-NR-304 + C-NR-306**
  集中改 `ff_dpdk_if.c`（出包改道、send_burst 防御短路、tx drain 与 rx_burst 跳过区间、`:3171` dequeue **替换**、ARP/NDP clone 新分支、G_new 侧 tx drain）+ `ngx_ff_module.c` + `ngx_ff_reload.c` + `ngx_process_cycle.c`
- **Batch C（补缺）**：IT-NR-A09/A10 harness + `tools -g` + F5。其中 **`tools -g` 与 F5 只依赖 M2 已提交代码，可与 Batch A 并行**；**IT harness 依赖 Batch B**（A09 需 C-NR-309、A10 需 C-NR-301/312），须在 B 之后

### 3.2.1 Phase0 推翻的 spec 描述（必须按实际代码落笔）

| # | 项 | spec 说 | 实际（复核坐实） |
|---|---|---|---|
| **S-1** | C-NR-304 锚点 | `:2153-2195` 是 ARP/NDP 克隆分支 | `protocol_filter`（`:2122-2172`）**函数体内无 clone**；clone 在 `process_packets:2388-2412`，KNI clone `:2414-2423`。spec 该区段**失效** |
| **S-2** | C-NR-301 入表点 | 「`tcp_input` listen 分支 syncache 插入成功后」 | `tcp_input.c:1347` 的 `syncache_add` **成功与失败都返回 NULL** 无法区分；唯一点是 **`tcp_syncache.c:1749`**（SYN-ACK 已发出且条目已入 syncache） |
| **S-3** | C-NR-302 载体 | 新建 hugepage memzone | `lib/ff_reload.h:82-84` **已按 DR4 决议预留** `rx_owner_gen`/`rx_stopped` 在 master 建的匿名 MAP_SHARED 块中 —— **复用，不新建**（分设会推翻已落地决议并引入 primary 启动顺序依赖） |
| **S-4** | C-NR-309 可达路径 | 3 条 flush | **5 条**：`:2807`/`:2832`/`:3154` + spec 未列的 `process_packets:2361`（FF_DISPATCH_RESPONSE）+ `ff_dpdk_raw_packet_send:3019` |

### 3.2.2 隐藏硬约束（编码最易踩）

- **H-1**：`freebsd/` 侧 TU 不可 `#include "ff_api.h"`（全树 0 先例）→ 用零 include 的 `lib/ff_flow_map.h`
- **H-2**：新建 lib 源文件必须加入 `lib/Makefile` 的 `FF_HOST_SRCS`（`:298-308`），否则链接失败；`ff_api.symlist` 可选
- **H-3/H-4**：syncache 挂钩点已释放 inp/sch 锁、处于 `NET_EPOCH` ⇒ insert 必须非阻塞不睡眠；syncookies-only 模式（`sc == &scs`）跳过 `syncache_insert`，须保留该条件
- **H-6**：新 clone 必须用 `ff_app_mbuf_pool()`（M2 的 C-NR-314 已改动），误用 `pktmbuf_pool[]` 会破坏代际池隔离
- **H-7**：PA 分支 `ff_dpdk_if.c:2826-2837` 提前 return ⇒ 无硬件模式拦截必须在 `:2826` **之前**
- **H-8**：`RX_QUEUE_SIZE` 4096 会被 `rte_eth_dev_adjust_nb_rx_tx_desc`（`:1298`）夹取 ⇒ 必须按返回值验证，不能假设
- **H-9**：`unsigned` 配置项必须负值重映射（`atoi("-1")`→巨大正值会穿透校验）
- **H-12**：互斥标记必须**可逆**（C-NR-316 的 rx 交还依赖）
- **R-303-1（最易 crash）**：dispatcher 回调把 mbuf enqueue 进 `drain_ring_rx` 后若返回 `FF_DISPATCH_ERROR`，框架会再 `rte_pktmbuf_free` ⇒ **double free**。正确做法：enqueue 成功后返回 ERROR（框架不重复处理），enqueue 失败（满环）时**自己 free 后**再返回 ERROR。**必须写进单测**
- **R-310-1**：`rte_ring_free` 技术可行，但跨进程只能一个进程 free + ring 按 `_g<gen>` 乒乓复用 ⇒ **M3 只注销不销毁**，销毁推迟 M4/M6

### 3.3 C-NR-310 是 C-NR-309 的硬前置（同批完成）
TX 代发依赖 drain_ring 通道存在。

### 3.4 C-NR-309 拦截点必须在 `send_burst`，不得在 `ff_dpdk_if_send`
依据 M0 静态审计 **F-1**：`ff_dpdk_if_send` 处 `m` 仍是 bsd mbuf（G_old 进程私有堆/UMA，PA 下更是私有 mmap VMA），G_new 无法解引用；`send_burst` 的 `m_table` 已是 rte_mbuf。PA 分支内有提前 return，逐个 flush 点拦截必漏其一。附加约束：
- 拦截点须在 **pcap dump 之后、`rte_eth_tx_burst` 之前**（否则丢捕获）
- 自行累加 `ff_traffic` 出向统计（early-return 会全丢）
- 满环需打点告警并与 C-NR-316 联动

### 3.5 `FF_USE_PAGE_ARRAY` 首版限定 0 并显式声明
依据 **F-3**：PA=1 下 bsd mbuf 跨进程回收不可行（`ff_enq_tx_bsdmbuf` 收回 G_old 私有 static `nic_tx_ring`）。

### 3.6 F-2 须先核实闭合状态
M2 的 C-NR-313 已为 `ff_kni_is_runtime_owner` 增加 `gen==active_gen` 判定，M3 需核实是否完整闭合 F-2（KNI inject 是独立物理口 tx 出口），并明确登记「G_old 的 KNI 出向报文丢弃还是代发」。

### 3.7 `graceful_reload=0` 逐字等价是 G-M3 硬判据
全部新逻辑条件化包裹，**含 RX_QUEUE_SIZE 默认值变更也须条件化**（避免改变既有内存占用）。

## 4. 编码点清单

| 编号 | 落点 | 要点 |
|---|---|---|
| **C-NR-301** | 新增 `lib/ff_flow_map.c` + `lib/ff_api.h` | flow_map 三函数（lookup/insert/close）。**入表时机硬约束：收到 SYN 并发出 SYN-ACK 时（syncache 插入成功后），不得推迟到 `accept()`**——否则三次握手第三个 ACK 会 miss 转 G_old → 无 syncache 条目 → RST → reload 窗口内新建连接全失败。须覆盖 SYN 重传不重复插入 |
| **C-NR-302** | 新增 `lib/ff_handover.c` | 跨进程互斥 `ff_queue_handover_mutex`。hugepage 共享 `struct ff_handover_state{magic;rx_owner_gen;rx_stopped;in_handover;}`，primary 创建，**读写一律 `__atomic_*_n(SEQ_CST)`**，禁裸 volatile 轮询。**「G_old 停 poll」= 跳过 rx_burst 与 tx drain，但不退出主循环**（退出会收不到 drain_ring_rx 转发包）。超时初值 100ms → HANDOVER_TIMEOUT。G_old 异常退出须清脏标记 |
| **C-NR-303** | `ngx_ff_module.c` | G_new READY 后注册 flow_map 查表回调：① **协议过滤**——仅 TCP/UDP 四元组参与判定，ARP/NDP/ICMP/非 IP/分片一律本栈处理（否则 G_new 邻居表建不起来）② miss 一律经 `drain_ring_rx` 转 G_old（**不复用 dispatch_ring**）③ **目标 G_old 须按代际精确反算并校验存活**，已退出则本栈处理并按 TCP 规范回 RST ④ 排空确认后注销回调 |
| **C-NR-304** | `ff_dpdk_if.c`（protocol_filter 起的 ARP/NDP 克隆分支） | ARP/NDP clone 给 G_old：转 G_new 处理的同时额外 clone 一份转发给所有 G_old |
| **C-NR-305** | `lib/ff_memory.h`（RX_QUEUE_SIZE）+ `ff_config.{h,c}` | RX_QUEUE_SIZE 512→4096（条件化）+ 新增 `drain_ring_size` 配置（默认 2048）+ 同步计入 mbuf 池预留 |
| **C-NR-306** | `ngx_ff_reload.c` 状态机 | T3：master 触发同期接管 → 建立双向 drain_ring → G_old 停 rx → G_old 无硬件模式 → G_new 起 rx poll + 接管 listen + 独占 tx → 注册 flow_map → ARP/NDP clone 生效；HANDOVER 消息族；超时/失败分支 |
| **C-NR-309** | `ff_dpdk_if.c`（send_burst / send_single_packet / ff_dpdk_if_send / raw_packet_send / main_loop tx drain） | TX 独占与 `drain_ring_tx` 代发（DR9=a） |
| **C-NR-310** | 新增 `lib/ff_drain_ring.c` + `ff_memory.h` 常量 + `ff_dpdk_if.c` enqueue/dequeue 点 | per-generation `drain_ring_rx`（G_new→G_old）与 `drain_ring_tx`（G_old→G_new） |

## 5. 门禁判据

| 门禁 | 判据 | 失败处理 |
|---|---|---|
| **G-A**（Batch A） | clean build 零 error / warning 51 零新增 + `make install` + nginx 重链 + 单测（含 UT-NR-19）全绿零回归 + =0 等价静态自证 + CR 通过 | 打回 m3-coder-io，bounce+1 |
| **G-B**（Batch B） | 同上 + 单测 UT-NR-11/13/14 + 互斥内存序与入表时机 CR 通过 | 打回 m3-coder-dp，bounce+1 |
| **G-C**（补缺） | IT-NR-A09/A10 可执行 + `tools -g` 在 graceful=1 下可用 + F5 不再错收 + 独立复核 | 打回 m3-coder-it，bounce+1 |
| **G-M3** | 前三门禁全过 + **RT-02**（长连接 HUP：新连接走 G_new、旧包 miss 转发零 RST、代发成功、ARP/NDP 正常）+ **RT-03**（CPS 压力下客户端错误 0）+ **IT-NR-A09 TX 独占断言 PASS** + gARP 对照 baseline 零丢失 + =0 运行时等价 | 打回对应批次，bounce+1 |

## 6. 两个判据污染防护（M3 尤其致命）

1. **gARP 假阴性**：gARP 一次性 + `garp_rexmit_count` 默认 0 ⇒ 上游 L2 表老化丢包与 ring 满环丢包**在 guest 侧观测不可区分**（virtio PMD 无 `imissed`）。长跑压测前必须设 `net.link.ether.inet.garp_rexmit_count > 0`（sysctl，上限 16），并**先跑无接管长跑对照 baseline 确认零丢失**，否则 RT-02/RT-03/IT-NR-A09 会假阴性。
2. **IT-NR-A09 断言口径**：`tx_burst` 次数断言必须**过滤 `port_id ∈ dpdk.portid_list`**，否则 KNI vdev 口会误判。

## 7. 执行规约（全员强制）

1. **Shell**：删文件 `rm_tmp_file.sh`、停进程 `kill_process.sh`、加权限 `chmod_modify.sh`；严禁直接 rm/kill/chmod
2. **编译**：lib 三步法（`make clean` → `make machine_includes` → `make -j16` → `make libfstack.a`）；`make clean` 用 `PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin" make clean` 规避 IDE hook；**warning 基线 51 零新增**；lib 改动后 `make install` 再重链 nginx（nginx `make clean` 会删 Makefile 需重跑 configure）
3. **注释**：`lib/` 最小注释、一律英文；仅 `ff_api.h` 新接口、config.ini 新配置项、复杂逻辑（入表时机/互斥内存序/满环处置）可加
4. **提交**：英文 1-3 句；**config.ini 本地测试值不入库**；按 spec 建议拆 6 个可独立 revert 的 commit
5. **网卡串行**（M0 曾发生双 primary 互踩事故）：起进程前三查（`ps` 空 + `ls /dev/hugepages | wc -l`=0 + `/var/run/dpdk/rte` 无近期 mtime）；`--proc-type` 显式禁 auto；各 agent 私有目录；SIGTERM 后 rtemap 泄漏走 `rm_tmp_file.sh` 清理并记录数
6. **写审分离**：`m3-coder-*` 写、`m3-reviewer-*` 审，同一产物写与审必须不同 agent；leader 只做运营性任务与汇总
7. **leader 轮询**：子 agent 落盘到 `work/impl/<stage>-<role>.md`，leader 旁路探测（读文件/git status/产物路径）每 10 分钟一次，硬超时 60 分钟；超时发状态探测，仍无响应则 spawn 替补
8. **文档 IP**：严禁真实 IP，用 `<DPDK_NIC_IP>` / `<CLIENT_IP>` / `<GATEWAY_IP>` 等占位符

## 8. 已知风险

- RV3：互斥标记缺陷导致并发 rx poll（virtqueue 数据结构损坏，**静态无法定论需实测**）
- RV4：ring 容量与满环行为
- RV5：flow_map 查表开销
- RV11：代发路径在出包高峰成为瓶颈（则按 DR9 切 b）
- T3 后 G_new 崩溃时 G_old 已脱离硬件、无法续服（回退由 M4/C-NR-404 与 C-NR-316 心跳处理）
- M2 登记移交：F2（脏 EAL respawn，M4/M6）、F7（单 worker 看门狗 arm 缺口，M4 C-NR-402）、SIGTERM 大页泄漏（M6 断言已入 RT-10，M3 每轮须记录增量）
