# 08 KNI / IPC / 工具链归属

> 来源 `_material_C_lifecycle.md §3`。thread 模式无 secondary 进程，KNI 与工具链归属需重设计。

## 1. KNI 现状（primary-only）

- `ff_kni_init`（`ff_dpdk_kni.c:376-420`）：`kni_stat` 仅 `RTE_PROC_PRIMARY` 分配（`:379-386`）；`kni_rp`/`tcp_port_bitmap`/`udp_port_bitmap` 按 `rte_lcore_id()` 命名（`:388-419`）——KNI ring 已带 lcore 维度。
- `ff_kni_alloc`（`ff_dpdk_kni.c:422-449`）：`kni_stat[port_id]` 分配同样 primary-only（`:426`）。
- 主循环 KNI 处理（`ff_dpdk_if.c:2660-2664`）：仅 `enable_kni && rte_eal_process_type()==RTE_PROC_PRIMARY` 才调 `ff_kni_process`。
- 配置校验（`ff_config.c:1392-1412`）：要求 primary lcore 在每端口 lcore_list。

## 2. KNI 归属设计（thread 模式）

- thread 模式无 primary/secondary 进程概念，KNI 应**由单一指定线程（如线程 0 / instance 0）独占持有** KNI 资源与 `ff_kni_process`。
- 现有 `kni_rp`/bitmap 已按 `rte_lcore_id()` 命名（`ff_dpdk_kni.c:388-419`），天然可 per-lcore；
- 需改动：`kni_stat` 全局 + 运行时 `RTE_PROC_PRIMARY` 门控（`ff_dpdk_if.c:2661`、`ff_dpdk_kni.c:379/426`）改为**按 owner-thread 判定**（如 `rte_lcore_id()==kni_owner_lcore`）；
- 配置校验（`ff_config.c:1396-1411`）从「primary lcore」改判「KNI owner 线程的 lcore」。

## 3. IPC / 工具链现状（强依赖 secondary）

- `tools/compat/ff_ipc.c`：`ff_ipc_init`（`:54-80`）**硬编码 `--proc-type=secondary`**（`:67`）+ `-c1`（`:66`），经 `rte_mempool_lookup(FF_MSG_POOL)`（`:77`）找 primary 建好的消息池，用 `ff_proc_id`（`:42`）选目标进程 ring。
- sysctl/netstat/ifconfig/ipfw/ndp/route/arp/ngctl 等工具（`tools/` 各子目录）都以 **secondary 进程** attach 进 primary 共享内存，经 `msg_ring`（`ff_dpdk_if.c:649-667` 建、`process_msg_ring` `:2278/2699` 消费、`handle_msg` `:2225` 处理）与栈通信。
- **工具链强依赖多进程 secondary 模型。**

## 4. IPC / 工具链归属设计（thread 模式）

thread 模式无 secondary 进程，现有基于 `--proc-type=secondary`（`ff_ipc.c:67`）的工具链**不可直接复用**。三个候选（供后续编码阶段裁决，本轮列出权衡）：

| 候选 | 描述 | 优点 | 缺点 |
|---|---|---|---|
| C1 保留外部工具进程 | thread 模式的进程仍作 primary，暴露与旧 secondary 兼容的共享大页 + msg_ring，外部 `ff_ipc` 工具照旧 attach | 工具链改动最小、向后兼容 | 需保证 thread 模式进程仍建可被外部 attach 的 `FF_MSG_POOL`/`msg_ring` |
| C2 管理线程内置 | 把管理面并入同进程一个管理线程，走进程内共享内存/直接调用 | 省跨进程 IPC 开销、更 share-nothing | 工具需重写为线程内接口，改动大 |
| C3 unix socket 直连 | 工具经 unix socket 连到目标线程的 msg_ring | 解耦 DPDK secondary 依赖 | 新增通道实现 |

- **建议**：保持 `msg_ring[proc_id]` 数组结构不变（已 per-lcore，`:177`），thread 模式下每栈线程用自己的 lcore/proc_id 消费自己的 msg_ring；**优先 C1**（兼容旧工具、改动最小），把「工具链完整线程化」（C2/C3）列为独立后续子项。

## 5. tools/ 归属小结

| 组件 | 现状依赖 | thread 模式归属 |
|---|---|---|
| KNI | primary 进程 | owner 线程独占 |
| `msg_ring` | 按 proc_id 数组（已 per-lcore） | 每线程用自己 lcore 索引，保持 |
| `ff_ipc`/sysctl/netstat 等 | `--proc-type=secondary` | C1 保留外部进程（首选）/ C2/C3 后续 |

> 结论：**KNI 可较平滑改为 owner 线程门控**（ring 已 per-lcore 命名）；**工具链是 thread 模式最大兼容缺口**，建议 spec 明确列为独立子项，编码阶段优先 C1 保兼容。
