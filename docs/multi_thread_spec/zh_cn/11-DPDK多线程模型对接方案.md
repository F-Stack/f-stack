# 11 — DPDK 多线程模型对接方案

> 本文由方案设计子 agent（design-writer）撰写。所有技术论断以 `_material_code.md` 的 `file:line` 代码证据为准，外网素材（DPDK 博客摘要）仅作方向性参考；冲突以代码为准。
> 关联素材：`_material_code.md` §1.3/§5、`_material_web.md` §3。关键 ring flag 已由 design-writer 二次 `read_file` 核验（`ff_dpdk_if.c:619,671`）。

---

## 0. 结论先行

1. **f-stack 当前 DPDK 对接是「每 lcore / 每进程恰好一个消费者」的 share-nothing 模型**：`rte_eal_mp_remote_launch(main_loop, ...)`（`ff_dpdk_if.c:2770`）虽向所有 EAL lcore 分发 `main_loop`，但每个 f-stack 进程的 EAL coremask 是**单 bit**（`proc_mask`，`ff_config.c:123-125,1151-1153`），所以每进程实际只有一个 lcore 跑 `main_loop`（`_material_code.md` §1.3 结论）。
2. **dispatch_ring / msg_ring 的 SC/SP flag 是「反多线程」前提**：dispatch_ring 用 `RING_F_SC_DEQ`（**单消费者**，`ff_dpdk_if.c:619`，design-writer 核验一致），msg_ring 用 `RING_F_SP_ENQ | RING_F_SC_DEQ`（**单生产单消费**，`ff_dpdk_if.c:671`，核验一致）。这些 flag 的正确性**依赖「一队列一消费者」**；若一进程多线程消费同一 ring，SC 前提被破坏，会导致数据竞争/损坏。
3. **要支持「一进程多线程跑协议栈」（选项 a），DPDK 侧必须二选一**：(i) 把 ring flag 改为 MC/MP（引入 ring 内部锁/CAS，损失免锁性能）；或 (ii) **每线程独立 ring**（保持 SC/SP，推荐，符合 share-nothing）。**推荐 (ii)**。
4. **mempool 本身 MT-safe（有 per-lcore cache）**，是多线程下少数无需改造的 DPDK 资源（`_material_code.md` §5）。

---

## 1. 现状：DPDK 启动与 lcore 模型（file:line）

### 1.1 启动原语
- `ff_dpdk_run()`（`ff_dpdk_if.c:2764-2771`）：`rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)`（`:2770`）+ `rte_eal_mp_wait_lcore()`（`:2771`）。
- **关键**：用 `mp_remote_launch`（向所有 EAL lcore 分发），但每进程 coremask 单 bit（`proc_mask`，`ff_config.c:1151-1153` `-c<proc_mask>`），故实际每进程只 1 个 lcore 执行 `main_loop`。**这是「多进程各一 lcore」，不是「单进程多 lcore 多线程」**（`_material_code.md` §1.3 明示）。
- 全库**未使用**单 lcore 版 `rte_eal_remote_launch`，仅 `:2770` 一处 mp 版本（`_material_code.md` §5）。
- 外网佐证（`_material_web.md` 3）：DPDK lcore 即 pthread 封装，`rte_eal_remote_launch` 经管道通知 worker lcore 执行回调（`eal_thread_loop`）。**诚实边界**：DPDK 官方 Programmers Guide 原文本轮未直抓，为博客摘要，精确 API 语义以本仓库 dpdk-stable-23.11.5 / 24.11.6 源码为准。

### 1.2 lcore ↔ queue 绑定
- `init_lcore_conf()`（`ff_dpdk_if.c:400-464`）：`lcore_conf.proc_id = proc_id`（`:415`）；`lcore_id = proc_lcore[proc_id]`（`:424`）；按 proc_id 在 `lcore_list` 找 index 作 `queueid`（`:434-448`）→ **RSS 队列 = proc_id**；`nb_queue_list[port_id] = nb_lcores`（`:459`，总队列数=进程数）；无 rx queue 则 `rte_exit`（`:462-463`）。
- `rte_lcore_to_socket_id(rte_lcore_id())`（`:419`）取 NUMA socket；`rte_lcore_is_enabled(lcore_id)`（`:425`）校验。
- `lcore_conf` 是**全局单例**（`ff_dpdk_if.c:123`）—— 一进程一份，`main_loop` 里 `qconf = &lcore_conf`（`:2585`）。这是 share-nothing 单例的直接证据。

---

## 2. DPDK 资源的线程安全前提（逐项，file:line）

| 资源 | 创建/flag | file:line | 现状线程安全性 | 一进程多线程隐患 |
|---|---|---|---|---|
| `lcore_conf` | 全局单例 | `ff_dpdk_if.c:123`；`main_loop` `qconf=&lcore_conf` `:2585` | 单进程单例，RTC 下安全 | **高危**：多线程共享同一 queue 配置会乱，必须 per-thread 化 |
| `pktmbuf_pool[NB_SOCKETS]` | per-NUMA，PRIMARY 建/SECONDARY lookup | `ff_dpdk_if.c:125`；`init_mem_pool:522-523` | **MT-safe**（DPDK mempool 有 per-lcore cache） | 低：可多线程共享，是少数免改资源 |
| `dispatch_ring[port][queue]` | `RING_F_SC_DEQ`（单消费者） | `ff_dpdk_if.c:606-619`（核验：`:619` `create_ring(..., RING_F_SC_DEQ)`） | 依赖「一队列一消费者」才安全 | **高危**：多线程消费同一 ring 破坏 SC 前提 |
| `msg_ring[i].ring[0]` | `RING_F_SP_ENQ \| RING_F_SC_DEQ`（单生产单消费） | `ff_dpdk_if.c:667-671`（核验：`:671`） | 依赖单生产单消费 | **高危**：多线程并发 enq/deq 破坏 SP/SC |
| `message_pool` | PRIMARY `rte_mempool_create` / SECONDARY lookup | `ff_dpdk_if.c:653-660` | mempool MT-safe | 低 |
| rx/tx 队列数 | `nb_queues = pconf->nb_lcores` | `ff_dpdk_if.c:785`；越界 `rte_exit:819-828` | 队列数=进程数 | 需重定义为「线程数」（选项 a） |
| RSS reta 表 | `reta[j]=hash++%nb_queues`，仅 `nb_queues>1` | `ff_dpdk_if.c:736-751`（`:750`）；`:1110-1114` | 只 PRIMARY 设 | 需 queue→线程亲和映射 |

> **核验说明**：dispatch_ring 与 msg_ring 的 flag 由 design-writer 二次 `read_file`（`ff_dpdk_if.c:593-672`）确认与素材 §5 一致：dispatch_ring `RING_F_SC_DEQ`@`:619`；msg_ring `RING_F_SP_ENQ | RING_F_SC_DEQ`@`:671`。

---

## 3. 若支持「一进程多线程跑协议栈」（选项 a）的 DPDK 改造方案

> 对齐 `04-多线程架构方案与选型.md` 选项 (a) thread-per-core share-nothing；选项 (c)（推荐首选）不改 lib DPDK 层，故本节仅针对选项 (a)。

### 3.1 lcore/线程模型改造
- 现状 `rte_eal_mp_remote_launch(main_loop, ...)`（`:2770`）在单 bit coremask 下只跑一个 lcore。选项 (a) 需让**本进程 coremask 含多个 bit**（`proc_mask` 从单 bit 扩为多 bit），`mp_remote_launch` 即会在每个 lcore 上各起一个 `main_loop` 线程（DPDK lcore = pthread，`_material_web.md` 3）。
- **关键约束**：每个 `main_loop` 线程必须持有**自己的 `lcore_conf`**（当前是全局单例 `:123`），否则 `qconf=&lcore_conf`（`:2585`）会让所有线程指向同一份配置 → 必须把 `lcore_conf` per-thread 化（`__thread` 或数组 `lcore_conf[lcore_id]`）。

### 3.2 ring 方案：每线程独立 ring（推荐，保持 SC/SP 免锁）
- **推荐 (ii)**：维持 `RING_F_SC_DEQ`（dispatch，`:619`）/`RING_F_SP_ENQ|RING_F_SC_DEQ`（msg，`:671`）不变，但**每线程/每 queue 独立一份 ring**（现有 `dispatch_ring[port][queue]` 二维结构已按 queue 分离，`:615-618`，天然支持「一 queue 一线程」，只需保证 queue↔线程一一映射，不共享）。
- **不推荐 (i)**：改 MC/MP flag（`RING_F_MC_...`/`RING_F_MP_...`），会引入 ring 内部锁/CAS，损失 share-nothing 免锁性能，违背 f-stack 与业界（mTCP/Seastar，`_material_web.md` 4）的免锁基因。
- msg_ring 同理：每线程独立 msg_ring（现已 `msg_ring[i]` 按 proc_id/线程 index 分离，`:667-671`），保持 SP/SC。

### 3.3 mempool：可共享，无需改造
- `pktmbuf_pool[NB_SOCKETS]` per-NUMA（`:125`）+ DPDK mempool per-lcore cache → MT-safe，多线程可直接共享，是选项 (a) 下**唯一无需改造**的核心 DPDK 资源（`_material_code.md` §5）。
- **诚实边界**：mempool/ring 的 MP/MC vs SP/SC 精确语义，`_material_web.md` §3 标注为博客摘要级，建议实现时以 dpdk-stable-23.11.5 / 24.11.6 源码核实 `RING_F_SC_DEQ`/`RING_F_SP_ENQ` 语义。

### 3.4 RSS 队列 → 线程亲和
- 现状 RSS queue = proc_id（`init_lcore_conf:434-448`），reta 表 `reta[j]=hash++%nb_queues`（`:750`）。
- 选项 (a) 下改为 queue = 线程 index，`nb_queues = 本进程线程数`（现 `nb_queues=pconf->nb_lcores`@`:785` 需重定义），每线程绑定自己的 rx/tx queue（延续 share-nothing 流亲和，类比 mTCP flow-level core affinity，`_material_web.md` 4.1）。

---

## 4. DPDK 对接改造清单（选项 a，按危险度）

| 改造点 | 现状 file:line | 目标 | 危险度 |
|---|---|---|---|
| `lcore_conf` per-thread 化 | `ff_dpdk_if.c:123` 单例；`:2585` `qconf=&lcore_conf` | `__thread` 或 `lcore_conf[]` 数组，每线程独立 | 高 |
| coremask 单 bit → 多 bit | `ff_config.c:123-125,1151-1153` proc_mask 单 bit | 本进程 coremask 含多个 lcore | 中 |
| dispatch_ring 每线程独立 | `ff_dpdk_if.c:615-619` `RING_F_SC_DEQ` | 保持 SC，queue↔线程一一映射不共享 | 中 |
| msg_ring 每线程独立 | `ff_dpdk_if.c:667-671` `RING_F_SP_ENQ\|SC_DEQ` | 保持 SP/SC，按线程 index 分离 | 中 |
| rx/tx 队列数语义 | `ff_dpdk_if.c:785` `nb_queues=nb_lcores` | 重定义为「本进程线程数」 | 中 |
| RSS reta → 线程亲和 | `ff_dpdk_if.c:736-751` | queue=线程 index | 中 |
| mempool | `ff_dpdk_if.c:125,522-523` | 无需改（MT-safe） | 低 |

> **对齐结论**：选项 (c)（本轮首选）**完全不触碰**上述 DPDK 层，多进程 RTC 路径零回归；上述改造仅在决定实现选项 (a) 时执行，且需以 opt-in（`thread_mode`，见 `06-配置与接口设计.md` §2.4）隔离。

---

## 5. 诚实边界

- 「coremask 多 bit → mp_remote_launch 在每 lcore 起线程」的行为为**基于 DPDK 语义的推断**（`_material_web.md` 3 博客摘要 + 代码 `:2770`），精确行为需以 dpdk-stable 源码核实。
- 改造危险度为**基于代码结构的定性评估**，精确工作量待编码里程碑（`07`）细化。
- 本轮不改 lib、不编译，所有改造方案为设计建议，未做运行时验证。
