# M1-A 代码路径核验：thread_mode=0 vs 1 双队列差异 + 根因定位

> 探测人：leader（纯只读探测/汇总角色）+ code-explorer 子 agent A
> 日期：2026-08-03
> 实证铁律：所有结论附`file:line`；无法静态判定者标注「需运行时验证」，并在下文给出实际运行输出。

---

## 0. 先决事实（后续结论的基础，全部代码坐实）

| 事实 | 证据 |
|---|---|
| `parse_lcore_mask` 把 bit-count 写入 `nb_procs`，填 `proc_lcore[]`（mask=6 → `{1,2}`） | `lib/ff_config.c:110-141` |
| `port_cfgs[].nb_lcores` 在 ini 解析期固化为 `nb_procs`(=2) 并复制 `proc_lcore` | `lib/ff_config.c:566-572` |
| `thread_mode=1` 的塌缩在所有 per-port 校验之后：`nb_threads=nb_procs; nb_procs=1; proc_id=0; proc_mask=lcore_mask` | `lib/ff_config.c:1465-1484` |
| 故 `nb_lcores==2`（队列数）与 `nb_threads==2` 一致，`nb_procs==1` | 上两条组合 |
| DPDK main lcore = 第一个enabled lcore（未传 `--main-lcore`）→ mask=6 时为 lcore 1 | `dpdk-stable-24.11.6/lib/eal/common/eal_common_options.c` |
| 所有 lcore（含 main）都跑 `main_loop` | `lib/ff_dpdk_if.c:2855` `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` |
| `ff_lcore_conf_idx()`：mode0 恒 0；mode1 用 `rte_lcore_id()` | `lib/ff_memory.h:104-111` |

---

## 1. H6：dispatch_ring / msg_ring 按 nb_procs(=1) 分配 → worker 访问 NULL ring

**结论：否证（不成立）。**

- `init_dispatch_ring()` 队列上界取 `pconf->nb_lcores`（=2），非 `nb_procs`：`lib/ff_dpdk_if.c:643-660`
- `init_msg_ring()` 显式按 thread_mode 选 `nb_threads`：`lib/ff_dpdk_if.c:692-694`
- 消费侧索引合法：`process_dispatch_ring` 用 `dispatch_ring[port_id][queue_id]`（`:2106`），`queue_id` 来自 `init_lcore_conf` thread_mode 分支的 0/1（`:441-448`）；`process_msg_ring(qconf->proc_id)`（`:2784`），`lc->proc_id = ti`（`:433`）

**运行时印证**：ff_log 实测 `dispatch_ring_p0_q0` / `dispatch_ring_p0_q1` 均创建成功。

### 1.1 附带发现的条件性缺陷（本轮未触发，建议后续修）

`init_mem_pool()` 的 mempool 创建循环上界仍是 `nb_procs`：`lib/ff_dpdk_if.c:548`

```c
for (i = 0; i < ff_global_cfg.dpdk.nb_procs; i++) {   /* thread_mode=1 → 只循环 1 次 */
```

而 `nb_mbuf` 规模计算已正确使用 `nb_threads`（`:526-527`）。后果：worker lcore 若与 `proc_lcore[0]` 不同 NUMA socket，`pktmbuf_pool[worker_socket]` 保持 NULL，`init_port_start` 按每队列 lcore 的 socket 取池（`:1062-1080`）会拿到 NULL。
**本机 lcore 1/2 同 socket（实测 ff_log 仅 `create mbuf pool on socket 0`），故未触发。**

---

## 2. H7：veth_ctx 主线程条目与 worker 条目错位/NULL/重复创建

**结论：否证。**

- `veth_ctx[RTE_MAX_LCORE][RTE_MAX_ETHPORTS]` 二维按 lcore 维度隔离，容量足够
- worker 在 `main_loop` 按 `rte_lcore_id()` 索引创建（`lib/ff_dpdk_if.c:2649-2664`），`veth_ctx[lcore][port] == NULL` 才创建，无重复
- **运行时印证**：`DBGVNET ... unit_eq=1` 表明 `ifunit_ref(if_name)` 返回的 ifp 与 `sc->ifp` 相同，无错位

---

## 3. H8：KNI 归属吞掉 80 端口 SYN

**结论：对本场景否证。**

- `ff_kni_is_owner_thread()`：thread_mode=1 时 `rte_lcore_id() == proc_lcore[0]`（`lib/ff_dpdk_kni.c:92-98`），即只有 lcore 1 是 owner
- `config.ini` 为 `kni.enable=1, method=reject, tcp_port=80,443` → `kni_accept=0`
- `process_packets` 的 KNI 分支（`lib/ff_dpdk_if.c:2081-2089`）：`FILTER_KNI && kni_accept` 或 `(FILTER_UNKNOWN || >=FILTER_OSPF) && !kni_accept` 才入 KNI。80 端口 TCP 属`FILTER_KNI`，而 `kni_accept=0` → **走 `ff_veth_input`**，不进 KNI

---

## 4. H9：worker vnet 无 listen socket

**结论：否证（app 侧每线程都 listen）。**

`example/main.c`：
- `kq`/`sockfd`/`sockfd6` 均为 `__thread`（`:22-28`）
- `init_thread()` 每线程各自 `ff_socket` + `SO_REUSEPORT` + `ff_bind` + `ff_listen`（`:62-140`）
- `loop()` 首行调`init_thread()`（`:144`），故每个 worker 线程都建了 listen socket
- **运行时印证**：`helloworld.log` 有 `thread init success on lcore 1.` 与 `thread init success on lcore 2.`，两线程 listen 均成功

>但见第 6 节：这些 socket **实际建在 vnet0**，这是真正的问题所在。

---

## 5. thread_mode=0 vs 1 双队列路径差异对照

| 维度 | thread_mode=0（2 进程） | thread_mode=1（2 线程） | 是否差异源 |
|---|---|---|---|
| `nb_procs` / `nb_threads` | 2 / 0 | 1 / 2 | 否（各处已正确适配） |
| `lcore_conf` 索引 | 恒 0（`ff_lcore_conf_idx`） | `rte_lcore_id()` | 否 |
| queue 分配 | 每进程 1 队列（实测 p0→q0, p1→q1） | 每线程 1 队列（q0/q1） | 否 |
| RSS 配置路径 | `if (dev_info.flow_type_rss_offloads)` 整段跳过（virtio） | **完全相同** | **否（关键：两模式共享同一"无 RSS"路径）** |
| `dispatch_ring` | 按 `nb_lcores`=2 | 按 `nb_lcores`=2 | 否 |
| `msg_ring` | 按 `nb_procs`=2 | 按 `nb_threads`=2 | 否 |
| mempool 循环 | `nb_procs`=2（覆盖两lcore socket） | `nb_procs`=1（只覆盖 lcore[0] socket） | 条件性（跨 NUMA 才触发） |
| KNI owner | primary 进程 | `lcore==proc_lcore[0]` | 否 |
| **协议栈实例** | 每进程独立地址空间 → 独立 vnet0，cred/prison0各自一份 | 同进程内 vnet0 + vnet_i，**共享唯一 prison0** | **是（根因）** |

---

## 6. 根因（代码 + 运行时双坐实）

### 6.1 运行时证据

在 `lib/ff_veth.c` `ff_veth_setup_interface` / `ff_veth_setaddr` 加临时探针实测：

```
主线程 (f-stack-0.log):
DBGSOCK cret=0 so=0x7f9526f94400 so_vnet=0x37754ef0 curvnet=0x37754ef0 ioctl_ret=0
DBGVNET curvnet=0x37754ef0 ifp_vnet=0x37754ef0 ifp_fib=0 gw_ifa=0x37d1f240 self_ifa=0x37d1f240 unit_eq=1 flags=0x8803

worker   (helloworld.log):
DBGSOCK cret=0 so=0x7f9526f95c00 so_vnet=0x37754ef0 curvnet=0x7f952000eb10 ioctl_ret=0
DBGVNET curvnet=0x7f952000eb10 ifp_vnet=0x7f952000eb10 ifp_fib=0 gw_ifa=0 self_ifa=0 unit_eq=1 flags=0x8802
f-stack-0: ff_veth_set_gateway failed DBGERR=51
```

判读：
- worker 的 `so_vnet=0x37754ef0` **等于主线程的 vnet0**，而 `curvnet=0x7f952000eb10` 是 worker 自己的 vnet_2 → **不一致**
- `ioctl_ret=0`（"成功"），但 worker vnet 中 `self_ifa=0`（`ifa_ifwithaddr(本机IP)` 找不到）、`gw_ifa=0`（`ifa_ifwithnet(网关)` 找不到）
- `flags`：主线程 `0x8803` 含 `IFF_UP`(0x1)，worker `0x8802` **缺 IFF_UP**（`if_up` 未被调用的连带现象）
- `DBGERR=51` = **ENETUNREACH**（`freebsd-src-releng-15.0/sys/sys/errno.h:114`），来自 `net/route.c:507` `rt_getifa_fib()` 中 `info->rti_ifa == NULL`

### 6.2 代码链（全部坐实）

| 步 | 位置 | 事实 |
|---|---|---|
| 1 | `freebsd/net/vnet.c:336` | `curvnet = prison0.pr_vnet = vnet0 = vnet_alloc();` — prison0 永久绑定 vnet0 |
| 2 | `lib/ff_init_main.c:586-590` | worker cred：`p->p_ucred = crget(); ... cr_prison = &prison0;` |
| 3 | `freebsd/net/vnet.h:247` | `#define CRED_TO_VNET(cr) (cr)->cr_prison->pr_vnet` → **vnet0** |
| 4 | `freebsd/kern/uipc_socket.c:948` | `so = soalloc(CRED_TO_VNET(cred));` → worker 所有 socket 的 `so_vnet` = vnet0 |
| 5 | `freebsd/kern/uipc_socket.c:829-833` | `so->so_vnet = vnet;`（来自 soalloc 参数） |
| 6 | `freebsd/net/if.c:2908` | `ifioctl` 开头 `CURVNET_SET(so->so_vnet);` → **切到 vnet0** |
| 7 | `lib/ff_veth.c:599-601` | `ff_veth_setaddr` 用 `socreate()` + `ifioctl(so, SIOCAIFADDR, ...)` |
| 8 | 后果 | worker 的 IP 被加到 **vnet0** 的 `f-stack-0` 上（故`ioctl_ret=0`），worker 自己的 vnet_2 里的 ifp 从未获得地址 |
| 9 | `lib/ff_veth.c:1028` → `lib/ff_veth.c:638` → `freebsd/net/route/route_ctl.c:756-757` → `freebsd/net/route.c:497,507` | `ff_veth_set_gateway` 的 `rib_action(RTM_ADD)` 在 vnet_2 执行（不经 socket，直接用 `curvnet`）→ `ifa_ifwithroute` 找不到 on-link ifa → `ENETUNREACH` |

### 6.3 为何 thread_mode=0 没有此问题

多进程模式每个进程是独立地址空间，各自有一份 `prison0` 且各自 `prison0.pr_vnet = 自己的 vnet0`，故 `CRED_TO_VNET(cred) == curvnet` 恒成立。**单进程多线程共享唯一 `prison0`（全局变量 `ff_init_main.c:97`）才暴露该错配。**

### 6.4 影响范围（不止路由）

凡「经 socket 进入协议栈」的 worker 操作都被静默重定向到 vnet0：
- `ff_veth_setaddr` / `ff_veth_setaddr6` / `ff_veth_setvaddr`（`ifioctl` 路径）
- `lo_set_defaultaddr()`（定义 `lib/ff_freebsd_init.c:219-263`，`socreate` 在 `:255`、`ifioctl` 在 `:259`）
- **app 侧 `ff_socket`/`ff_bind`/`ff_listen`**：worker 的 listen PCB 全部建在 vnet0 的 PCB 哈希表中，而 worker 数据面 `ff_veth_input` 用 `ifp->if_vnet`(=vnet_2) 作 curvnet 查 PCB → 永远查不到 listen socket → 不回 SYN-ACK

这与实测「listen 成功、client 反复重传 SYN 无响应」完全吻合。

---

## 7. 最可能根因排序

| 排名 | 根因 | 性质 |
|---|---|---|
| **1** | worker cred 挂 `prison0` → `CRED_TO_VNET` 恒为 vnet0 → 所有 socket/ifioctl 操作被 `CURVNET_SET(so->so_vnet)` 重定向到 vnet0 | **代码 + 运行时双坐实** |
| 2 | `init_mem_pool` 循环上界 `nb_procs`（跨 NUMA 才触发） | 代码坐实，本机未触发 |
| 3 | virtio 无 RSS | **已由 E2 实测否证**（thread_mode=0 双队列 231,570 req/s 正常） |
