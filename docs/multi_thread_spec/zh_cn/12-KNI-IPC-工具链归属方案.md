# 12 — KNI / IPC / 工具链归属方案

> 本文由方案设计子 agent（design-writer）撰写。所有技术论断以 `_material_code.md` 的 `file:line` 代码证据为准，外网素材仅作交叉参考；冲突以代码为准。
> 关联素材：`_material_code.md` §1.2/§6。`SOCKET_OPS_CONTEXT_MAX_NUM=32` 已由 design-writer 二次 `read_file` 核验（`ff_socket_ops.h:45`）。

---

## 0. 结论先行

1. **KNI 严格 primary-only**：`ff_kni_init`（`ff_dpdk_kni.c:379`）、`ff_kni_alloc`（`:426`）、主循环 KNI 处理（`ff_dpdk_if.c:2661-2663`）、配置校验（`ff_config.c:1392-1410`）全部用 `rte_eal_process_type()==RTE_PROC_PRIMARY` 门控。**多进程模式下只有 proc_id=0（primary）跑 KNI**。
2. **多线程模式下 KNI 归属结论**：
   - **选项 (c)（推荐）**：底层仍多进程，KNI 归属**不变**（仍 primary 进程处理），adapter 多 worker 不涉及 KNI，零改动。
   - **选项 (a)（单进程多线程）**：单进程内只应有**一个线程**承担 KNI（相当于「KNI 线程」，取代原 primary 进程角色），其余栈线程不碰 KNI，需把 primary 门控从「进程级」改为「指定线程级」。
3. **IPC**：进程间 `msg_ring`（`ff_dpdk_if.c:649-668`）在选项 (c) 下保持不变；选项 (a) 单进程内多线程若不再跨进程，则 `msg_ring` 的进程间控制语义可简化，但工具链（tools/）仍依赖它连接目标实例。
4. **adapter 层 IPC（ff_ring_ipc / so_zone）**：单实例最多挂 **32** 个 worker（`SOCKET_OPS_CONTEXT_MAX_NUM=(1<<5)=32`，`ff_socket_ops.h:45`，核验一致），这是选项 (c) 多 worker 的硬上限。

---

## 1. KNI 现状：严格 primary-only（file:line）

### 1.1 全局与初始化门控（`lib/ff_dpdk_kni.c`）
- 全局：`struct rte_ring **kni_rp;`（`:89`）、`struct kni_interface_stats **kni_stat;`（`:90`）、`struct kni_ratelimit kni_rate_limt`（`:92`）。
- `ff_kni_init()`（`:377-420`）：`if (rte_eal_process_type()==RTE_PROC_PRIMARY)` 才 `rte_zmalloc kni_stat`（`:379-382`）。
- `ff_kni_alloc()`（`:423-471`）：同样 `if PRIMARY`（`:426`）才建 virtio_user 异常路径 port（`:451-467`）。
- ratelimit 常量：`ff_config.h:47-50`（`KNI_RATELIMT_PROCESS=10000` 等）。

### 1.2 主循环调用门控（`lib/ff_dpdk_if.c`）
- `if (enable_kni && rte_eal_process_type()==RTE_PROC_PRIMARY) ff_kni_process(...)`（`:2661-2663`）。
- `int enable_kni`（`:74`）全局开关。

### 1.3 配置校验（`lib/ff_config.c`）
- `:1392-1410` 注释明确 “only primary process process KNI”：若 KNI 开启且 `proc_type=="primary"`，则 **primary lcore 必须在每个 port 的 `lcore_list` 中**（保证 primary 有队列跑 KNI）。

> **结论**：KNI 与「primary 进程」强绑定。多进程模式下 secondary 进程完全不碰 KNI（不 alloc、不 process）。

---

## 2. KNI 在多线程模式下的归属方案

### 2.1 选项 (c)（推荐首选）：KNI 归属不变
- 底层维持多进程，KNI 仍由 primary 进程（proc_id=0）独占处理（`ff_dpdk_if.c:2661-2663`）。
- adapter 层多 worker（用户线程）不参与 KNI 收发，**零改动、零回归**。
- 配置约束（`ff_config.c:1392-1410`）不变。

### 2.2 选项 (a)（单进程多线程独立栈）：KNI 归「KNI 线程」
- 单进程内起 N 个栈线程后，`rte_eal_process_type()==RTE_PROC_PRIMARY` 对**整个进程**恒为 true，无法再用它区分「哪个线程跑 KNI」。
- **改造方向**：把 KNI 门控从「进程级 primary 判断」改为「指定线程级判断」——例如指定 `queueid==0` 或 `lcore index==0` 的那个栈线程承担 KNI，其余线程 `main_loop` 跳过 KNI 段（`ff_dpdk_if.c:2661-2663` 的条件改为 `enable_kni && is_kni_thread`）。
- `kni_rp`/`kni_stat`（`ff_dpdk_kni.c:89-90`）作为进程级全局，仅由该 KNI 线程访问，避免多线程竞态。
- **危险度**：中（需重定义门控条件 + 保证仅一个线程访问 KNI 全局）。

### 2.3 归属决策表

| 模式 | KNI 承担者 | 门控条件 | 改动 |
|---|---|---|---|
| 多进程（现状） | primary 进程（proc_id=0） | `rte_eal_process_type()==RTE_PROC_PRIMARY`（`ff_dpdk_if.c:2661`） | — |
| 选项 (c) 多 worker | primary 进程（不变） | 同上 | 零改动 |
| 选项 (a) 单进程多线程 | 指定「KNI 线程」（如 index 0） | `enable_kni && is_kni_thread`（需新增线程级判定） | 中 |

---

## 3. IPC 归属方案

### 3.1 进程间 msg_ring（`lib/ff_dpdk_if.c`）
- `init_msg_ring()`（`:649-668`）：`nb_procs` 个 `msg_ring[i]`，PRIMARY 建 `message_pool`（`:653-655`，核验），ring flag `RING_F_SP_ENQ | RING_F_SC_DEQ`（`:671`，核验）。
- 主循环 `process_msg_ring(qconf->proc_id, ...)`（`:2699`，定义 `:2278`）—— 每进程按自己 proc_id 收控制消息。
- **选项 (c)**：msg_ring 语义不变（进程间控制），tools/ 仍通过它连接目标 proc_id。
- **选项 (a)**：若单进程内多线程不再跨进程通信，进程间 msg_ring 的必要性下降；但只要 tools/ 仍需从外部进程控制栈，就仍需保留 msg_ring（此时按「线程 index」而非「proc_id」路由，需保持 SP/SC 每线程独立，见 `11-DPDK多线程模型对接方案.md` §3.2）。

### 3.2 adapter 层 IPC（`adapter/syscall/`）
- `ff_ring_ipc.c`：LD_PRELOAD 模式用户 APP ↔ f-stack 后端的 ring IPC；`ff_socket_ops.c` 生产/消费（`:653-655` req_ring dequeue）。
- `SOCKET_OPS_CONTEXT_MAX_NUM = (1<<5) = 32`（`ff_socket_ops.h:45`，**design-writer 核验一致**）—— sc 上下文槽位上限，**单实例最多挂 32 个 worker**。
- so_zone 共享内存（`ff_so_zone.c`）：`ff_so_zone`（`:27`，`__FF_THREAD`）；`ff_attach_so_context(idx)`（`:160+`）用 `rte_spinlock_lock(&ff_so_zone->lock)`（`:192`）+ `inuse[]` 位图（`:200-210`）分配 sc；`FF_MULTI_SC` 下 `ff_so_zones[]` 数组（`ff_socket_ops.h:208-210`）。
- **选项 (c) 归属**：每 worker 通过 `ff_attach_so_context(worker_id % nb_procs)`（`ff_hook_syscall.c:3297`）绑定后端进程实例，worker→后端映射清晰，**32 是硬上限**。

### 3.3 IPC 归属决策表

| IPC 通道 | 作用 | 选项 (c) | 选项 (a) |
|---|---|---|---|
| 进程间 msg_ring（`ff_dpdk_if.c:649-668`） | tools/APP 控制栈 | 不变（按 proc_id 路由） | 保留，按线程 index 路由，SP/SC 每线程独立 |
| adapter ff_ring_ipc / so_zone（`ff_socket_ops.h:45`） | 用户 worker ↔ 后端实例 | 每 worker attach 后端进程，≤32 | N/A（选项 a 不走 adapter 多进程映射） |

---

## 4. 工具链（tools/）归属方案

### 4.1 现状（`_material_code.md` §6.3）
- `tools/` 各工具（`netstat/ifconfig/ipfw/route/ngctl/arp/ndp/...`）通过 `ff_ioctl_freebsd`/`ff_setsockopt_freebsd`/`ff_rtioctl`/`ff_ngctl`（`ff_api.h:343-368`）与 f-stack 交互。
- 多进程下工具通常连 primary 或指定 proc_id（经 msg_ring）。
- `ff_route.c` 路由控制；`ff_ngctl.c`/`ff_ng_base.c` netgraph（`VNET_DEFINE_STATIC`，`ff_ng_base.c:183-189,385`；f-stack 通常不启用 VIMAGE，VNET 退化单实例）。

### 4.2 归属方案
- **选项 (c)**：tools/ 归属**不变**——通过 msg_ring 连接指定 proc_id 的后端进程查询/控制，与现状一致（每个后端进程有独立栈状态）。
- **选项 (a)**：单进程内多线程各有独立栈实例（share-nothing），tools/ 需能指定「连接哪个线程实例」查询——即把现有「按 proc_id 路由」扩展为「按线程 index 路由」（复用 msg_ring 每线程独立，§3.1）。**诚实边界**：tools/ 的具体路由改造未在素材中细化 file:line，属选项 (a) 实现时的工作项。

### 4.3 工具链归属决策表

| 模式 | tools/ 连接对象 | 路由键 | 改动 |
|---|---|---|---|
| 多进程（现状） | 指定 proc_id 的后端进程 | proc_id（msg_ring） | — |
| 选项 (c) | 同上 | proc_id | 零改动 |
| 选项 (a) | 指定线程实例 | 线程 index（msg_ring 每线程独立） | 中（需扩展路由） |

---

## 5. 归属总表（跨 KNI/IPC/工具链）

| 组件 | 现状归属 | 选项 (c) 首选 | 选项 (a) 进阶 | 关键 file:line |
|---|---|---|---|---|
| KNI | primary 进程独占 | 不变 | 指定「KNI 线程」（index 0） | `ff_dpdk_if.c:2661-2663`、`ff_dpdk_kni.c:379,426`、`ff_config.c:1392-1410` |
| 进程间 msg_ring | 按 proc_id 路由 | 不变 | 按线程 index，SP/SC 每线程独立 | `ff_dpdk_if.c:649-671` |
| adapter so_zone/IPC | worker→后端进程，≤32 | 不变 | 不适用 | `ff_socket_ops.h:45`、`ff_hook_syscall.c:3297` |
| tools/ | 连指定 proc_id | 不变 | 连指定线程 index | `ff_api.h:343-368` |

---

## 6. 诚实边界

- 选项 (a) 下「KNI 线程」门控改造、msg_ring 按线程路由、tools/ 按线程 index 路由，均为**基于现状代码的设计建议**，当前代码库不存在这些机制，需实现时新增。
- `ff_route.c`/`ff_ngctl.c` 的多线程细节未在素材中逐行核验，选项 (a) 实现时需专项审计。
- 选项 (c) 的所有归属结论均为「保持现状不变」，无新增代码，多进程零回归。
