# 调研材料 B：DPDK 侧原生多线程对接能力深探

> 子 agent B（explorer-dpdk）产出。方向：**库内原生支持单进程内 N 个 pthread（每线程绑一个 lcore）各跑一份独立 FreeBSD 协议栈实例、share-nothing**（非 adapter 路线）。
> 所有结论以代码为准，逐条给 `file:line`。诚实标注「静态可判定」vs「需运行时验证」。
> 代码基线：`/data/workspace/f-stack/lib/`；DPDK 交叉参考：`/data/workspace/dpdk-stable-24.11.6/`。

---

## 一、DPDK 多 lcore 线程拉起机制

### 1.1 当前 f-stack 拉起路径（单进程只跑一个 lcore 的根因）

`ff_dpdk_run()` → `rte_eal_mp_remote_launch`：

```
lib/ff_dpdk_if.c:2763  void ff_dpdk_run(loop_func_t loop, void *arg) {
lib/ff_dpdk_if.c:2765      struct loop_routine *lr = rte_malloc(...);
lib/ff_dpdk_if.c:2768      lr->loop = loop;
lib/ff_dpdk_if.c:2769      lr->arg  = arg;
lib/ff_dpdk_if.c:2770      rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);
lib/ff_dpdk_if.c:2771      rte_eal_mp_wait_lcore();
lib/ff_dpdk_if.c:2772      stop_clock();
```

关键点：**`rte_eal_mp_remote_launch` 本身就会在「所有 EAL 注册的 lcore」上各拉起一份 `main_loop`。**
当前单进程只跑一个 lcore，**不是** launch API 的限制，而是 **coremask（EAL `-c`/`-l` 参数）单 bit** 导致本进程只注册了 1 个 lcore。

DPDK 侧语义（交叉验证）：
- `rte_eal_mp_remote_launch(f, arg, call_main)`：`dpdk-stable-24.11.6/lib/eal/include/rte_launch.h:99`
  文档 `:78-82`：*"Launch a function on all lcores. Check that each WORKER lcore is in a WAIT state, then call rte_eal_remote_launch() for each lcore."*
- `rte_eal_remote_launch(f, arg, worker_id)`：`rte_launch.h:67`
  文档 `:37-51`：向指定 worker lcore（处于 WAIT 状态）发消息，**该 remote lcore = 一个已由 EAL 创建并绑核的 pthread**，收到消息后切 RUNNING 调用 `f(arg)`，执行完回 WAIT。
- `rte_eal_wait_lcore(worker_id)`：`rte_launch.h:130`；`rte_eal_mp_wait_lcore()`：`rte_launch.h`（`:133` 文档段）等所有 lcore 回到 WAIT。

**结论（静态可判定）**：`lcore = pthread + 核绑定`，由 EAL 在 `rte_eal_init` 阶段按 coremask 一次性创建。要在单进程内拉起 N 个 lcore 线程，**几乎不需要改动 launch 代码**，只需：
1. EAL 启动参数给 N-bit coremask（如 `-l 0-3`）→ EAL 自动创建 N 个 worker pthread；
2. `rte_eal_mp_remote_launch(main_loop, ...)` 会自动在这 N 个 lcore 上各跑一份 `main_loop`（`ff_dpdk_if.c:2770`）。

⇒ **单进程拉多 lcore 的「线程创建」这一层，DPDK 已原生提供，f-stack 现成代码已具备**。真正的改动点在「每个 `main_loop` 里访问的全局状态是否 per-lcore 隔离」（见第二、四节）。

### 1.2 lcore id 的 TLS 本质（per-thread 隔离的天然基础）

- `rte_lcore_id()` 定义：`dpdk-stable-24.11.6/lib/eal/include/rte_lcore.h:77-81`
  ```c
  static inline unsigned rte_lcore_id(void) { return RTE_PER_LCORE(_lcore_id); }
  ```
  即 lcore id 本身就是 **TLS（`__thread`）变量**，每个 EAL 线程天然知道自己是哪个 lcore，**无需传参**。
- `RTE_LCORE_FOREACH(i)`：`rte_lcore.h:217-220`；`RTE_LCORE_FOREACH_WORKER(i)`：`rte_lcore.h:225-228`（遍历所有/除 main 外的运行中 lcore）。
- `rte_get_next_lcore(i, skip_main, wrap)`：`rte_lcore.h:212`。

**意义**：f-stack 全局状态 per-thread 化后，各线程可用 `rte_lcore_id()` 或 `lcore_conf.proc_id` 作为**数组下标**索引自己那一份实例，无需锁、无需传参。这是「原生多线程 share-nothing」的核心可行性支点（静态可判定）。

`ff_dpdk_if.c:419` / `:1148` 已在用 `rte_lcore_id()`（取 socket、注册 timer）。

---

## 二、每线程独立 RX/TX 队列与独立 ring（核心）

### 2.1 `lcore_conf` —— 当前是「全局单例」，是多线程化的头号障碍

结构定义：`lib/ff_memory.h:82-95`
```
lib/ff_memory.h:82   struct lcore_conf {
lib/ff_memory.h:83       uint16_t proc_id;
lib/ff_memory.h:84       uint16_t socket_id;
lib/ff_memory.h:85       uint16_t nb_queue_list[RTE_MAX_ETHPORTS];
lib/ff_memory.h:86       struct ff_port_cfg *port_cfgs;
lib/ff_memory.h:88       uint16_t nb_rx_queue;
lib/ff_memory.h:89       struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
lib/ff_memory.h:90       uint16_t nb_tx_port;
lib/ff_memory.h:91       uint16_t tx_port_id[RTE_MAX_ETHPORTS];
lib/ff_memory.h:92       uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
lib/ff_memory.h:93       struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];   // 每 port 的 TX 缓冲
lib/ff_memory.h:95   } __rte_cache_aligned;
```
`struct lcore_rx_queue { port_id; queue_id; }`：`ff_memory.h:77-80`。

**全局单例声明**：`lib/ff_dpdk_if.c:123  struct lcore_conf lcore_conf;`（**不是数组**）。

所有热路径都直接引用这一份单例：
- `main_loop`：`ff_dpdk_if.c:2585  qconf = &lcore_conf;`
- `ff_dpdk_if_up`：`ff_dpdk_if.c:2749  struct lcore_conf *qconf = &lcore_conf;`
- `process_packets`：`ff_dpdk_if.c:1905  struct lcore_conf *qconf = &lcore_conf;`
- `send_burst`/`send_single_packet` 通过 `qconf->tx_queue_id` / `tx_mbufs`（`:2305-2306`）。

**结论（静态可判定，头号改动点）**：
> `lcore_conf` 是**进程级全局单例**。当前 `main_loop` 里 N 个 lcore 若同时跑，会**共享同一份 `lcore_conf`**（尤其 `tx_mbufs` TX 缓冲区、`tx_queue_id`），造成数据竞争。
> **原生多线程改造必须把 `lcore_conf` 改为 per-lcore：`struct lcore_conf lcore_conf[RTE_MAX_LCORE]`（或用 `RTE_DEFINE_PER_LCORE`），各 `main_loop` 用 `&lcore_conf[rte_lcore_id()]`（或 proc_id）索引自己那份。**
> 好在结构内**队列 id、TX 缓冲已是天然 per-lcore 语义**（每 lcore 对应一个 NIC 队列），拆成数组即可 share-nothing，无需锁。

`init_lcore_conf()`（`ff_dpdk_if.c:400-467`）目前只按**本进程单一 lcore_id**（`:424 lcore_id = proc_lcore[proc_id]`）填一份；多线程下需按每个 lcore 各填一份（循环/或每线程各自 init 自己那份）。

### 2.2 RX/TX 队列按 lcore 分配语义

- 队列数 = `pconf->nb_lcores`（每 port 的 lcore 数）：`ff_dpdk_if.c:602 int nb_queues = pconf->nb_lcores;`
- `rte_eth_dev_configure(port, nb_queues, nb_queues, ...)`：`ff_dpdk_if.c:1006`（RX/TX 队列数 = lcore 数）。
- 每队列 setup：`ff_dpdk_if.c:1019-1037`，`q` 从 0..nb_queues-1，`rte_eth_tx_queue_setup(port,q,...)` / `rte_eth_rx_queue_setup(port,q,...,mbuf_pool)`。
- 当前进程认领的 queue：`init_lcore_conf` 中按 `lcore_list[i]==lcore_id` 找到自己的 `queueid=i`（`ff_dpdk_if.c:436-440`），记入 `rx_queue_list`/`tx_queue_id`（`:446-450`）。

**结论（静态可判定）**：DPDK **每 NIC 队列天生独立**（RSS 把不同流散列到不同队列），一个 lcore 独占一个 RX 队列 + 一个 TX 队列。这套「N 队列 ↔ N lcore」映射**本身就是 share-nothing 数据面的理想模型**。当前多进程模型下每进程认领一个 queue；转成单进程多线程后，只需每个线程在自己的 `lcore_conf[i]` 里认领对应 `queueid=i` 即可，**队列层面天然无共享，无需改 NIC 配置逻辑**。

### 2.3 dispatch_ring —— `RING_F_SC_DEQ`（单消费者）是否可保？

创建：`init_dispatch_ring()`
```
lib/ff_dpdk_if.c:129   static struct rte_ring **dispatch_ring[RTE_MAX_ETHPORTS];
lib/ff_dpdk_if.c:603   dispatch_ring[portid] = rte_zmalloc(... nb_queues 个指针 ...);
lib/ff_dpdk_if.c:615   for (queueid = 0; queueid < nb_queues; ++queueid) {
lib/ff_dpdk_if.c:618       dispatch_ring[portid][queueid] = create_ring(name_buf,
lib/ff_dpdk_if.c:619           DISPATCH_RING_SIZE, socketid, RING_F_SC_DEQ);
```
- 结构：`dispatch_ring[port][queue]`，**每 (port,queue) 一个 ring**，`nb_queues = nb_lcores`（`:602`）。
- Flag：仅 `RING_F_SC_DEQ`（**单消费者**出队），**未加 `RING_F_SP_ENQ`**（即入队默认 **MP 多生产者**）。

**消费者（单）**：`process_dispatch_ring(port,queue,...)` `ff_dpdk_if.c:2044`，`rte_ring_dequeue_burst(dispatch_ring[port][queue],...)` `:2049`。每个 ring 只被「拥有该 queue 的那个 lcore」出队 ⇒ **单消费者成立**。

**生产者（多）**：`process_packets` 中把不属于本队列的包 enqueue 到目标队列的 ring：
- 用户 dispatcher 重定向：`ff_dpdk_if.c:1964 rte_ring_enqueue(dispatch_ring[port_id][ret], rtem);`（`ret != queue_id`，即写入**别的 lcore** 的 ring）
- ARP/NDP 广播克隆到所有其他队列：`ff_dpdk_if.c:1996 rte_ring_enqueue(dispatch_ring[port_id][j], mbuf_clone);`（`j != queue_id`）

即：**每个 dispatch_ring 会被多个 lcore（源 lcore）写入、被单个 lcore（owner）读出** ⇒ 天然是 **MP + SC** 模型。当前 flag `RING_F_SC_DEQ`（SC 出队 + 默认 MP 入队）**正好匹配**。

**结论（静态可判定，关键裁决）**：
> - **dispatch_ring 在原生多线程下不能改成 SP**（入队），因为它本就是「多个源 lcore → 单个 owner lcore」的跨线程分发管道，多生产者是**本质需求**，当前的 **MP（默认）+ SC（`RING_F_SC_DEQ`）配置在多线程下仍然正确且必需**，无需修改。
> - 多进程模型下这些 ring 通过共享大页内存跨进程可见；转成单进程多线程后，这些 ring 变成**进程内跨线程共享**，`rte_ring` 的无锁 MP/SC 语义**同样适用于线程**（DPDK ring 对进程/线程无差别，都是共享内存上的无锁环）。⇒ **dispatch_ring 平滑迁移，flag 不变**。

### 2.4 msg_ring —— `RING_F_SP_ENQ | RING_F_SC_DEQ`（单生产单消费）语义

创建：`init_msg_ring()`
```
lib/ff_dpdk_if.c:170   struct ff_msg_ring { char ring_name[FF_MSG_NUM][...]; struct rte_ring *ring[FF_MSG_NUM]; } __rte_cache_aligned;
lib/ff_dpdk_if.c:177   static struct ff_msg_ring msg_ring[RTE_MAX_LCORE];   // 已经是「按 proc_id/lcore 索引」的数组！
lib/ff_dpdk_if.c:667   for (i = 0; i < nb_procs; ++i) {
lib/ff_dpdk_if.c:670       msg_ring[i].ring[0] = create_ring(..., RING_F_SP_ENQ | RING_F_SC_DEQ);   // in ring
lib/ff_dpdk_if.c:678       msg_ring[i].ring[j] = create_ring(..., RING_F_SP_ENQ | RING_F_SC_DEQ);   // out rings
```
- `ring[0]` = 外部工具进程 → 本栈线程（sysctl/ioctl 请求入）；`ring[1..]` = 本栈线程 → 外部工具（响应出）。
- **`msg_ring` 已经是 `[RTE_MAX_LCORE]` 数组**（`:177`），**每 proc_id/lcore 一套独立 in/out ring**。
- 消费：`process_msg_ring(proc_id, ...)` `ff_dpdk_if.c:2278`，`rte_ring_dequeue_burst(msg_ring[proc_id].ring[0],...)` `:2284`；`main_loop` 里 `process_msg_ring(qconf->proc_id, ...)` `:2699`。
- 生产/响应：`handle_msg(msg, proc_id)` `:2225`，回包 `rte_ring_enqueue(msg_ring[proc_id].ring[msg->msg_type], msg)` `:2265`。

**结论（静态可判定）**：
> `msg_ring` 是 **控制面 IPC**（f-stack 栈进程 ↔ 外部 `ff_ipc`/sysctl 客户端工具），**不是数据面**。它**已经按 proc_id 数组化**（`:177`），SP/SC 成立的前提是「单个外部客户端 ↔ 单个栈线程」一对一。
> 转成单进程多线程后：每个栈线程用自己的 `proc_id`（=lcore 序号）索引 `msg_ring[proc_id]`，**数组天然 per-thread 隔离，SP/SC 语义可原样保留**，无需改 flag。外部工具仍按 proc_id 找到对应线程的 ring。

---

## 三、mempool / mbuf pool MT-safe 性

### 3.1 f-stack 侧创建

```
lib/ff_dpdk_if.c:125   struct rte_mempool *pktmbuf_pool[NB_SOCKETS];   // 按 NUMA socket 一个池（非 per-lcore）
lib/ff_dpdk_if.c:538   pktmbuf_pool[socketid] = rte_pktmbuf_pool_create(s, nb_mbuf,
lib/ff_dpdk_if.c:540       MEMPOOL_CACHE_SIZE, 0, data_room, socketid);
```
- 池按 **NUMA socket** 共享（`pktmbuf_pool[socketid]`），**同一 socket 上的所有 lcore 共用一个池**。
- `cache_size = MEMPOOL_CACHE_SIZE`（`:540`，非 0）——**关键**：带 per-lcore cache。
- 每 socket 只建一次：`:518-520 if (pktmbuf_pool[socketid] != NULL) continue;`

### 3.2 DPDK mempool MT-safe 语义（交叉验证，决定性）

`dpdk-stable-24.11.6/lib/mempool/rte_mempool.h:28-32`：
> *"...usual mempool functions like `rte_mempool_get()` or `rte_mempool_put()` are designed to be called from an **EAL thread** due to the internal **per-lcore cache**. Due to the lack of caching, ... performance will suffer when called by **unregistered non-EAL threads**."*

- per-lcore cache 结构：`rte_mempool.h:113` `void *objs[RTE_MEMPOOL_CACHE_MAX_SIZE * 2];`
- 默认 get/put 为 **MP/MC（多生产多消费，无锁）**；仅当置 `RTE_MEMPOOL_F_SP_PUT`(`:289`)/`RTE_MEMPOOL_F_SC_GET`(`:296`) 才变单端。f-stack 建池 flag 传 `0`（`ff_dpdk_if.c` 无 SP/SC flag），即 **MP/MC 默认**。
- `cache_size` 语义：`rte_mempool.h:1031-1035`，per-lcore 对象缓存，减少对公共无锁池的访问。

**结论（静态可判定 + 部分需运行时验证）**：
> - ✅ **多个 lcore 线程共享同一 `pktmbuf_pool[socketid]` 是 MT-safe 的**——前提是：(a) 从 **EAL 线程**（即 `rte_eal_remote_launch` 拉起的 lcore pthread）调用；(b) 建池时 `cache_size > 0`（f-stack 已满足，`MEMPOOL_CACHE_SIZE`，`:540`）；(c) 默认 MP/MC flag（f-stack 已满足，flag=0）。
> - ✅ **无需为多线程改造 mempool 的正确性**：DPDK per-lcore cache 用 `rte_lcore_id()`（TLS）索引，每个 EAL 线程自动有独立 cache 分片，天然无锁隔离。原生多线程模型下这套机制**开箱即用**。
> - ✅ **无需显式 `RTE_MEMPOOL_CACHE`（per-lcore cache 已由 `cache_size` 参数内建）**；`nb_mbuf` 计算已按 `nb_lcores * MEMPOOL_CACHE_SIZE` 预留每 lcore cache 量（`ff_dpdk_if.c:495`）。
> - ⚠️ **需运行时验证**：(1) 若未来引入**非 EAL 线程**（如用户回调里自建 pthread）调用 `rte_pktmbuf_alloc`，则会走公共池慢路径且需确认线程已 `rte_thread_register`。(2) N 个线程共池时 `nb_mbuf` 总量是否够（`init_mem_pool` `:491-501` 的容量公式随 `nb_lcores` 线性放大，静态看已考虑，但高并发实测需观测 `rte_mempool_avail_count`）。(3) 跨 NUMA 时每线程应绑到本 socket 的池以避免远程访问（`numa_on` 分支 `:509-511` 已处理，但多线程绑核策略需运行时确认）。

---

## 四、`RTE_PER_LCORE` 机制（f-stack 全局状态 per-thread 化的隔离手段）

DPDK 提供 per-lcore 变量宏（本质 TLS）：`dpdk-stable-24.11.6/lib/eal/include/rte_per_lcore.h`
```
rte_per_lcore.h:33   #define RTE_DEFINE_PER_LCORE(type, name)   __thread type per_lcore_##name
rte_per_lcore.h:39   #define RTE_DECLARE_PER_LCORE(type, name)  extern __thread type per_lcore_##name
rte_per_lcore.h:46   #define RTE_PER_LCORE(name)  (per_lcore_##name)
```
（MSVC 分支 `:22-26` 用 `__declspec(thread)`，语义同。）

**结论（静态可判定，重要隔离手段）**：
> - `RTE_DEFINE_PER_LCORE` **底层就是编译器 TLS（`__thread`）**，每个线程一份独立副本，零锁、零传参。
> - `rte_lcore_id()` 本身就是靠它实现（`rte_lcore.h:80 return RTE_PER_LCORE(_lcore_id)`）。
> - **可作为 f-stack 全局状态 per-thread 化的两条候选路径之一**：
>   - **路径 A（数组 + rte_lcore_id 索引）**：`struct X x_arr[RTE_MAX_LCORE]`，访问 `x_arr[rte_lcore_id()]`。优点：可被别的线程/初始化代码按下标访问（如 dispatch/msg 跨线程场景）、内存布局集中、便于统计遍历（`RTE_LCORE_FOREACH`）。缺点：需手动加 `__rte_cache_aligned` 防伪共享。**适合像 `lcore_conf`、`msg_ring` 这类「有时需被其他线程按 id 索引」的状态。**
>   - **路径 B（`RTE_DEFINE_PER_LCORE` / `__thread`）**：`RTE_DEFINE_PER_LCORE(struct X, x)`，访问 `RTE_PER_LCORE(x)`。优点：真正 TLS，天然隔离、无伪共享、访问最快。缺点：**其他线程无法按 id 直接访问**（TLS 只对本线程可见）。**适合「纯本线程私有、无需被别的线程读取」的 FreeBSD 全局状态**（如各协议栈实例内部大量 `V_xxx`/全局变量的 per-thread 化——需与子 agent A 的 FreeBSD 全局状态清单联动裁决）。
> - **两者可混用**：跨线程可见的用数组（lcore_conf/dispatch_ring/msg_ring），纯线程私有的用 `__thread`。

---

## 五、`process_msg_ring` / IPC —— 单进程多线程下的简化空间

### 5.1 当前 IPC 路径（多进程）

- `main_loop` 每轮调用 `process_msg_ring(qconf->proc_id, pkts_burst)`：`ff_dpdk_if.c:2699`。
- `process_msg_ring`：`ff_dpdk_if.c:2278-2295`，从 `msg_ring[proc_id].ring[0]` 出队请求，逐条 `handle_msg`（`:2291`）。
- `handle_msg(msg, proc_id)`：`ff_dpdk_if.c:2225`，处理 sysctl/ioctl/route 等控制请求，回包 enqueue 到 out ring（`:2265`）。
- 对端：外部工具进程（`tools/` 下的 `ff_ipc`，SECONDARY 进程）通过 `rte_ring_lookup`（`create_ring` 的 `else` 分支 `ff_dpdk_if.c:578`）拿到共享大页上的同名 ring，跨进程投递请求 / 收响应。

### 5.2 单进程多线程下的简化结论

**结论（静态可判定 + 设计建议）**：
> - **数据面（dispatch_ring）与控制面（msg_ring）在单进程多线程下都退化为「进程内跨线程共享内存」**，`rte_ring` 无锁语义对线程同样成立，**功能上可直接复用现有 ring 路径，无需改写**。
> - **但存在简化空间**：外部 `ff_ipc` 工具若也并入同一进程（作为管理线程），则「管理线程 → 栈线程」的控制消息**可用进程内共享内存 + 直接函数调用/无锁 ring 替代跨进程 IPC**，省去 SECONDARY 进程 attach、`rte_ring_lookup` 按名查找、跨进程序列化等开销。
> - **最小改动方案**：保持 `msg_ring[proc_id]` 数组结构不变（已 per-lcore，`:177`），单进程多线程下每个栈线程仍用自己的 `proc_id` 消费自己的 msg_ring，SP/SC 不变。外部工具仍可作为独立进程通过共享大页访问（**兼容性最好，改动最小**）。
> - ⚠️ **需与团队裁决**：是否把管理面也线程化（更激进、更省 IPC）还是保留外部进程（改动小、兼容旧工具），取决于 spec 对「share-nothing 纯度」与「向后兼容」的权衡。

---

## 六、给 leader 的关键裁决摘要（DPDK 侧原生多线程可行性）

| 维度 | 当前状态 (file:line) | 原生多线程改动结论 |
|---|---|---|
| **拉起 N 个 lcore 线程** | `rte_eal_mp_remote_launch(main_loop,...)` `ff_dpdk_if.c:2770`；单 lcore 因 coremask 单 bit | ✅ **launch 层几乎零改动**：给 N-bit coremask，EAL 自动建 N 个绑核 pthread，`main_loop` 自动各跑一份。真正工作量在全局状态隔离。 |
| **lcore_conf** | **全局单例** `ff_dpdk_if.c:123`；`main_loop` `:2585` 共享 | ⛔ **头号障碍**：必须改 per-lcore 数组 `lcore_conf[RTE_MAX_LCORE]`（或 `__thread`），各线程按 `rte_lcore_id()`/proc_id 索引。结构内队列 id/tx 缓冲天然 per-lcore，拆数组即 share-nothing。 |
| **dispatch_ring（数据面）** | `RING_F_SC_DEQ`（MP+SC）`ff_dpdk_if.c:619`；多源 lcore 写、单 owner 读 | ✅ **保持 MP+SC 不变**：多生产者是本质需求（跨 lcore 分发），当前 flag 正确，多线程下 ring 无锁语义原样适用，平滑迁移。 |
| **msg_ring（控制面 IPC）** | `RING_F_SP_ENQ\|RING_F_SC_DEQ`，**已 `[RTE_MAX_LCORE]` 数组** `ff_dpdk_if.c:177` | ✅ **保持 SP+SC 不变**：已 per-proc_id 数组化，每线程用自己 proc_id 索引，天然隔离；可选进一步简化为进程内共享内存替代跨进程 IPC。 |
| **mempool MT-safe** | 按 socket 共享 `pktmbuf_pool[NB_SOCKETS]` `:125`，`cache_size=MEMPOOL_CACHE_SIZE` `:540`，flag=0(MP/MC) | ✅ **开箱 MT-safe**：DPDK per-lcore cache（`rte_mempool.h:28-32`）+ MP/MC 默认，从 EAL 线程调用天然无锁隔离，无需改造。⚠️ 容量与非-EAL 线程调用需运行时验证。 |
| **per-thread 隔离手段** | — | ✅ `RTE_DEFINE_PER_LCORE=__thread`（`rte_per_lcore.h:33`）+ `rte_lcore_id()`（TLS，`rte_lcore.h:80`）；跨线程可见状态用数组、纯私有状态用 `__thread`，与子 agent A 的 FreeBSD 全局状态清单联动。 |

**一句话总纲**：DPDK 侧「拉起 N 线程 + 每线程独立队列/ring/mempool」的能力**原生齐备且现成代码大部分可复用**（launch/queue/ring/mempool 均无需重写或仅改 flag=保持），**唯一硬骨头是把 `lcore_conf` 及其它进程级全局单例改为 per-lcore（数组或 `__thread`）**——这与 FreeBSD 协议栈全局状态 per-thread 化（子 agent A）是同一类工作，共用 `rte_lcore_id()`/`__thread` 隔离机制。

> 诚实边界：本材料所有「结论（静态可判定）」均基于代码与 DPDK 头文件确证；标注「⚠️ 需运行时验证」的为 mempool 容量、非-EAL 线程调用、NUMA 绑核策略、以及 N 线程实跑时 NIC 多队列 RSS 分流均衡性——这些须在编码后实测。
