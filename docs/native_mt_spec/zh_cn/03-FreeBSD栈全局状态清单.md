# 03 FreeBSD 栈全局状态清单

> 本清单是原生多栈实例改造的核心工作面。来源 `_material_A_globalstate.md`（含 file:line）。
> 等级：P0=多线程必崩/数据错乱核心靶点；P1=高频读写踩踏；P2=初始化期一次性/每实例一份；P3=低频/统计；P4=只读或天然安全。
> 隔离方式：`__thread`（纯线程私有）/ `RTE_PER_LCORE`（=`__thread`，DPDK 语义）/ 按 lcore_id 索引数组（需被其他线程按 id 访问时）/ VNET（网络栈虚拟化，见 §5）。

## 1. 线程/进程上下文核心（f-stack 自造全局）

| 变量 | file:line | 类型 | 已 per-thread | 建议隔离 | 改造量 | 等级 |
|---|---|---|---|---|---|---|
| `pcpup` | `ff_freebsd_init.c:69` | `struct pcpu *` 单例 | 否 | `RTE_PER_LCORE`/`__thread`，每线程一份 pcpu | 中（PCPU 宏底座） | **P0** |
| `pcurthread` | `ff_compat.c:59` | `__thread struct thread *` | **是** | 保持 | 无 | P4 |
| `thread0`/`thread0_st` | `ff_init_main.c:98` | 单例 struct | 否 | 每实例一份 | 中 | **P0** |
| `proc0` | `ff_init_main.c:96` | `struct proc` 单例 | 否 | 每实例一份 | 中 | **P0** |
| `prison0`/`vmspace0`/`initproc` | `ff_init_main.c:97,99,100` | 单例 | 否 | 每实例一份（prison0 或共享只读需评估） | 低-中 | P1 |
| `msg_iov_tmp[UIO_MAXIOV]` | `ff_syscall_wrapper.c:225` | `static struct iovec[1024]`（`__thread` 被注释掉） | **否** | **恢复 `__thread`** | **极低** | **P0** |
| `msg_iovlen_tmp` | `ff_syscall_wrapper.c:226` | `static size_t`（同上） | 否 | 恢复 `__thread` | 极低 | **P0** |

> `msg_iov_tmp/msg_iovlen_tmp` 用于 `recvmsg/sendmsg`（`ff_syscall_wrapper.c:864,893-897`），是每次 syscall 临时暂存，`__thread` 被故意注释掉（历史单线程假设）。多线程下确定性数据错乱，**恢复注释掉的 `__thread` 即可**，是头号低垂果实。

## 2. DPDK 转发层全局（f-stack 自造）

| 变量 | file:line | 类型 | 已 per-thread | 建议隔离 | 改造量 | 等级 |
|---|---|---|---|---|---|---|
| `lcore_conf` | `ff_dpdk_if.c:123` | `struct lcore_conf` 单例（结构定义 `ff_memory.h:82-95`） | 否 | 数组 `lcore_conf[RTE_MAX_LCORE]` 或 `RTE_PER_LCORE`，按 `rte_lcore_id()` 索引 | 中（**30+ 引用** + `ff_memory.c:71,395,414,459,510`） | **P0** |
| `stop_loop` | `ff_dpdk_if.c:87` | `static int` | 否 | 每线程停止标志/`__thread` | 低 | P1 |
| `freebsd_clock` | `ff_dpdk_if.c:89` | `static struct rte_timer` | 否 | 每线程一份（各栈自己的 hardclock） | 低-中 | **P1** |
| `pktmbuf_pool[NB_SOCKETS]` | `ff_dpdk_if.c:125` | 数组（按 socket） | 部分 | 多线程共 socket 可共享（mempool MT-safe） | 低 | P2 |
| `msg_ring[RTE_MAX_LCORE]` | `ff_dpdk_if.c:177` | 数组（按 lcore） | 是 | 保持 | 无 | P4 |
| `veth_ctx[RTE_MAX_ETHPORTS]` | `ff_dpdk_if.c:179` | 数组（按 port） | 否（按 port 非线程） | 多线程共 port 需评估共享读 | 中 | P2 |
| `ff_top_status`/`ff_traffic` | `ff_dpdk_if.c:181,182` | `static struct` 统计 | 否 | 每线程一份后聚合 | 低 | P3 |
| `ff_rss_tbl[]`/`ff_rss_tbl6[]` | `ff_dpdk_if.c:203,223` | `static[]` RSS 反算表 | 否 | 每线程一份或只读共享 | 中 | P1 |
| `numa_on`/`idle_sleep`/`rsskey` 等 | `ff_dpdk_if.c:80,82,120` | init 期赋值、运行期只读 | 否 | 只读共享 | 无 | P4 |

> `lcore_conf` 结构内 `nb_rx_queue`/`rx_queue_list`/`tx_queue_id`/`tx_mbufs`（`ff_memory.h:88-93`）本就是天然 per-lcore 语义（每 lcore 一个 NIC 队列），拆成数组即 share-nothing，无需锁。

## 3. callout/timer 子系统（`ff_kern_timeout.c`）

| 变量 | file:line | 类型 | 已 per-thread | 建议隔离 | 改造量 | 等级 |
|---|---|---|---|---|---|---|
| `cc_cpu` | `ff_kern_timeout.c:180` | `struct callout_cpu` 单例（`CC_CPU()/CC_SELF()` 全返回它 `:181,182`，无视传入 cpu） | 否 | 每线程一份 callout_cpu（每实例独立 callwheel） | **高**（TCP/IP 所有定时器挂此） | **P0** |
| `callwheelsize`/`callwheelmask` | `ff_kern_timeout.c:135` | `u_int` 全局 | 否 | 每实例一份 callwheel | 中 | **P1** |
| `timeout_cpu` | `ff_kern_timeout.c:187` | `static int` | 否 | 每实例一份 | 低 | P1 |

> `CC_CPU(cpu)`/`CC_SELF()` 硬编码为 `&cc_cpu`（`:181-182`），必须改「按 lcore_id/线程索引取各自 callout_cpu」，否则 N 个栈的定时器串到同一 callwheel，锁竞争+逻辑错乱。仅次于 `lcore_conf`/`pcpup` 的第二大硬骨头。

## 4. init/进程全局（`ff_init_main.c` / `ff_freebsd_init.c` / `ff_compat.c`）

| 变量 | file:line | 类型 | 等级 | 建议 |
|---|---|---|---|---|
| `sysinit/sysinit_end`/`newsysinit` | `ff_init_main.c:123,124` | SYSINIT 排序表 | **P0** | 一次性表，N 次执行有问题，见 `04` |
| `uma_page_slab_hash`/`uma_page_mask` | `ff_freebsd_init.c:70,71` | UMA 分配器 hash | **P0(存疑)** | UMA 底座极难 per-thread，建议共享+加锁，MT-safe 性**需运行时验证** |
| `proctree_lock` | `ff_freebsd_init.c:68` | 全局 sx 锁 | P2 | 每实例一份 |
| `allproc`/`allproc_lock` | `ff_compat.c:64,65` | 进程链表+锁 | P1 | 每实例一份 |
| `rootvnode` | `ff_compat.c:62` | `struct vnode *` | P3 | 每实例一份或共享 NULL（f-stack 不做真实 VFS） |
| `seed` | `ff_compat.c:80` | arc4random 种子 | P2 | `__thread`（避免 rand_r 竞争） |

## 5. VNET 退化全局（网络栈主战场，数百个）— 原生解法

无 VIMAGE 时，FreeBSD 所有 `VNET_DEFINE(...)` 全局退化为进程级普通全局（`vnet.h:429`），f-stack 现状即此。类别：
- `V_ifnet`（ifnet 链表，`ff_freebsd_init.c:87` 已引用）
- `V_in_ifaddrhead`/`V_in6_ifaddr`（地址表）
- `V_tcbinfo`/`V_udbinfo`（TCP/UDP PCB hash 表 + 锁）
- `V_rt_tables`（路由/FIB，`ff_route.c:643,1411` 已引用）
- `V_ipport_*`（端口分配）
- 数百个协议计数器（`V_tcpstat`/`V_ipstat`/`V_ip6stat`...）

**原生隔离方式 = 启用 VIMAGE**：`curvnet=curthread->td_vnet`（`vnet.h:176`），每线程 `vnet_alloc()`（`vnet.c:239`）一份 vnet，这批全局自动按 vnet 数据段隔离（`vnet.h:279-306`）。详见 `04`/`05`。**这是不必手工把数百个全局逐个 `__thread` 化的关键**——但 VIMAGE 在 f-stack 阉割用户态能否跑通须运行时验证（`09`/`11`）。

## 6. 已正确 per-thread 的范式参考

| 变量 | file:line | 说明 |
|---|---|---|
| `g_pcap_fp/seq/g_flen` | `ff_dpdk_pcap.c:55-57` | `static __thread`，证明 f-stack 已有 `__thread` per-thread 惯例，可复用 |
| `pcurthread` | `ff_compat.c:59` | `__thread`，与 VNET `curvnet=td_vnet` 契合 |

## 7. 改造规模小结

- **P0 头号**：`msg_iov_tmp`（极低）、`mi_startup`/SYSINIT（极大，见 `04`）、`lcore_conf`（中-大）、`pcpup/thread0/proc0`（中）、`cc_cpu`（高）、VNET 退化全局（极大，VNET 原生覆盖）、UMA（高/需运行时验证）。
- **总策略**：网络栈全局走 VNET（一次性启 VIMAGE 覆盖数百个）；f-stack 自造 DPDK/pcpu/callout 全局走「数组按 lcore_id 索引 或 `__thread`」；纯临时缓冲走 `__thread`。
