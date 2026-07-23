# 06 DPDK 多线程对接方案

> 来源 `_material_B_dpdk.md`（含 file:line）+ DPDK 24.11.6 源码交叉。结论：DPDK 侧原生能力齐备，改动集中在 `lcore_conf` per-lcore 化。

## 1. 单进程拉起 N 个 lcore 线程

- `ff_dpdk_run()` → `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)`（`ff_dpdk_if.c:2770`）+ `rte_eal_mp_wait_lcore()`（`:2771`）。
- `rte_eal_mp_remote_launch`（`dpdk-stable-24.11.6/lib/eal/include/rte_launch.h:99`）本就在**所有 EAL 注册的 lcore** 上各拉一份 `main_loop`。当前单 lcore 是因**每进程 coremask 单 bit**（`ff_config.c:1151-1154`），非 API 限制。
- `lcore = pthread + 核绑定`（`rte_launch.h:37-51`），由 `rte_eal_init` 按 coremask 一次性创建。

**改动结论（静态可判定）**：thread 模式下给 EAL N-bit coremask（如 `-l 0-3`），EAL 自动创建 N 个绑核 pthread，`rte_eal_mp_remote_launch` 自动在 N 个 lcore 各跑 `main_loop`。**launch 层几乎零改动**，真正工作在全局状态隔离。

## 2. lcore id 的 TLS 本质（隔离基础）

- `rte_lcore_id() ≡ RTE_PER_LCORE(_lcore_id)`（`rte_lcore.h:77-81`）——lcore id 本身是 `__thread` 变量，每线程天然知道自己是哪个 lcore，无需传参。
- `RTE_LCORE_FOREACH(i)`（`rte_lcore.h:217-220`）遍历运行中 lcore。
- `ff_dpdk_if.c:419/1148` 已在用 `rte_lcore_id()`。

**意义**：各线程用 `rte_lcore_id()` 作为数组下标索引自己那份实例状态，无锁无传参。

## 3. lcore_conf per-lcore 化（唯一硬骨头）

- 结构定义 `ff_memory.h:82-95`（`proc_id`/`socket_id`/`nb_rx_queue`/`rx_queue_list`/`tx_queue_id`/`tx_mbufs`）。
- **全局单例** `struct lcore_conf lcore_conf;`（`ff_dpdk_if.c:123`，非数组）。热路径全引用它：`main_loop`(`:2585`)、`ff_dpdk_if_up`(`:2749`)、`process_packets`(`:1905`)、send 路径(`:2305-2306`)。
- `init_lcore_conf()`（`:400-467`）目前只按本进程单 lcore 填一份（`:424 lcore_id=proc_lcore[proc_id]`）。

**改造**：改为 `struct lcore_conf lcore_conf[RTE_MAX_LCORE]`（或 `RTE_DEFINE_PER_LCORE`），各线程 `&lcore_conf[rte_lcore_id()]`（或 proc_id）索引。结构内队列 id/TX 缓冲天然 per-lcore，拆数组即 share-nothing。init 时每线程各填自己那份。

## 4. RX/TX 队列分配（天然 share-nothing）

- 队列数 = `pconf->nb_lcores`（`ff_dpdk_if.c:602`），`rte_eth_dev_configure(port, nb_queues, nb_queues,...)`（`:1006`）。
- 每队列 setup（`:1019-1037`），当前进程按 `lcore_list[i]==lcore_id` 认领 `queueid=i`（`:436-440`）。
- **结论**：一 lcore 独占一 RX+一 TX 队列，「N 队列↔N lcore」本就是 share-nothing 理想模型。转单进程多线程只需每线程在自己 `lcore_conf[i]` 认领 `queueid=i`，**NIC 配置逻辑无需改**。

## 5. ring 语义（保持不变）

| ring | 现状 flag | 结论 |
|---|---|---|
| `dispatch_ring[port][queue]`（数据面） | `RING_F_SC_DEQ`（MP+SC）`ff_dpdk_if.c:619` | 多源 lcore 写(`:1964,1996`)、单 owner 读(`:2049`)是本质需求，**保持 MP+SC**，多线程下 `rte_ring` 无锁语义原样适用 |
| `msg_ring[RTE_MAX_LCORE]`（控制面） | `RING_F_SP_ENQ\|RING_F_SC_DEQ` `:670`，已数组化 `:177` | 每线程用自己 proc_id 索引，**保持 SP+SC** |

## 6. mempool MT-safe（开箱可用）

- `pktmbuf_pool[socketid]`（`ff_dpdk_if.c:125`）按 NUMA socket 共享，`cache_size=MEMPOOL_CACHE_SIZE`（`:540`，非 0），flag=0（MP/MC 默认）。
- DPDK 语义（`rte_mempool.h:28-32`）：get/put 靠 per-lcore cache（`rte_lcore_id()` 索引），从 **EAL 线程**调用天然无锁隔离。
- **结论**：多 lcore 共享同一 socket 的池 **MT-safe，无需改造**。⚠️ 需运行时验证：容量随 `nb_lcores` 放大（`:495`）是否够、非-EAL 线程调用、NUMA 绑核（`:509-511`）。

## 7. RTE_PER_LCORE 隔离手段

- `RTE_DEFINE_PER_LCORE(t,n) ≡ __thread t per_lcore_##n`（`rte_per_lcore.h:33`）。
- 两条隔离路径：**数组+`rte_lcore_id()`索引**（跨线程可见，用于 `lcore_conf`/`dispatch_ring`/`msg_ring`）；**`RTE_DEFINE_PER_LCORE`/`__thread`**（纯私有，用于本线程独占的 FreeBSD 全局，与 `03` 联动）。

## 8. IPC 简化空间

- 单进程多线程下数据面/控制面 ring 都退化为进程内跨线程共享，`rte_ring` 无锁语义对线程同样成立，**功能上可直接复用**。
- 可选简化：把外部 `ff_ipc` 工具并入同进程作管理线程，用进程内共享内存/直接调用替代跨进程 IPC（更省开销但改动大）；或保留外部工具进程走共享大页（兼容性最好）。详见 `08`。

## 9. DPDK 侧改动清单小结

| 项 | 改动 | 成本 |
|---|---|---|
| 拉 N lcore | N-bit coremask（配置层，`07`） | 极低 |
| `lcore_conf` | 单例→数组 per-lcore | 中-大 |
| RX/TX 队列 | 每线程认领 queueid | 低 |
| dispatch_ring/msg_ring | 保持 flag 不变 | 无 |
| mempool | 无需改 | 无（⚠️容量运行时验证） |
