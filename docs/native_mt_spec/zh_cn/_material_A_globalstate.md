# 素材 A：FreeBSD 栈全局状态清单 + 每线程独立栈实例初始化可行性

> 子 agent A（代码深探）产出。目标：库内原生支持「单进程内 N 个 pthread（每线程绑一个 lcore）各跑一份独立 FreeBSD 协议栈实例、靠全局状态 per-thread 化实现 share-nothing」。
> 铁律：所有结论带 file:line；交叉验证不一致以代码为准；只读不改 lib。
> 代码基线：`/data/workspace/f-stack/lib/`（FreeBSD 15.0 移植）。

---

## 0. 全局背景结论（必读，决定整体路线）

### 0.1 当前 f-stack 是「多进程」模型，不是「多线程多栈」
- `ff_init()`（`ff_init.c:35-56`）串行调用 `ff_load_config → ff_dpdk_init → ff_freebsd_init → ff_dpdk_if_up`，**整个进程只跑一次**。
- 多核靠 **DPDK 多进程**（primary/secondary）实现：每个实例一个 `proc_id`，配置项 `proc_lcore[]` / `nb_procs`（`ff_config.c:79-139`），每进程绑一个 lcore。
- `ff_dpdk_run()`（`ff_dpdk_if.c:2764-2773`）：`rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` + `rte_eal_mp_wait_lcore()`。**注意**：虽然用了 mp_remote_launch，但单个进程里通常只有一个 lcore 在跑 `main_loop`（其余 lcore 属于别的 secondary 进程）；`main_loop`（`ff_dpdk_if.c:2585`）里 `qconf = &lcore_conf` 直接取**全局单例**。
- 正因为进程隔离，`pcpup` / `lcore_conf` / `cc_cpu` / 所有 `VNET_*` 全局各进程一份，天然 share-nothing，**从不冲突**。

### 0.2 未编译 VIMAGE / VNET —— 这是最大的隐性改造面
- `lib/opt/opt_global.h` 全文仅 5 行（`MUTEX_NOINLINE / RWLOCK_NOINLINE / SX_NOINLINE / DEV_RANDOM / NO_EVENTTIMERS`），**无 `VIMAGE`**。
- 全 lib 中 `VNET_DEFINE / curvnet / rootvnet` 仅 `ff_ng_base.c` 一处命中（netgraph），协议栈主路径无 VNET。
- **后果**：FreeBSD 源码里所有 `VNET_DEFINE(...)` 定义的全局——`V_ifnet`、`V_in_ifaddrhead`/`V_in6_ifaddr`、`V_tcbinfo`/`V_udbinfo`（PCB hash 表）、`V_rt_tables`（路由/FIB）、`V_ipport_*`（端口分配）、海量协议计数器与定时器——在 f-stack 编译时**全部退化为普通进程级全局单例**。多线程多栈下这些会被 N 个线程同时读写踩踏，是本方案**规模最大的一类全局状态**（数量级：数百个）。
- 证据：`ff_freebsd_init.c:87` 直接用 `V_ifnet`（无 curvnet 上下文）；`ff_route.c:643,1411` 用 `rt_tables_get_rnh(fibnum, saf)`（FIB 表在非 VNET 下是全局）。

### 0.3 两条可选的 per-thread 隔离宏路线
- **`__thread`（GCC TLS）**：已在 f-stack 使用（见 §3）。适合「每线程一个指针/小结构」。
- **`RTE_PER_LCORE` / `RTE_DEFINE_PER_LCORE`**：DPDK 提供、按 lcore 索引，语义上与「每线程绑一个 lcore」高度契合。**当前 lib 中 0 处使用**（grep 确认）。
- **按 lcore_id 索引的结构体数组**：`pktmbuf_pool[NB_SOCKETS]`（`ff_dpdk_if.c:125`）、`msg_ring[RTE_MAX_LCORE]`（`ff_dpdk_if.c:177`）已是这种模式，可作范式。

---

## 1. 维度1：FreeBSD 栈全局状态完整清单

�forcast等级：P0=多线程必崩/数据错乱核心靶点；P1=高频读写踩踏；P2=初始化期一次性、需保证仅一次或每实例一份；P3=低频/统计类；P4=只读或天然安全。

### 1.1 线程/进程上下文核心（f-stack 自己的全局）

| 变量名 | file:line | 类型 | 当前是否 per-thread | 建议隔离方式 | 改造量 | 等级 |
|---|---|---|---|---|---|---|
| `pcpup` | `ff_freebsd_init.c:69` | `struct pcpu *`（全局单例） | 否 | `RTE_PER_LCORE` 或 `__thread`；每线程一份 pcpu，PCPU_GET/SET 走它 | 中（PCPU 宏底层依赖它，牵连广） | **P0** |
| `pcurthread` | `ff_compat.c:59` | `__thread struct thread *` | **是（已 TLS）** | 已 OK，保持 | 无 | P4 |
| `thread0` / `thread0_st` | `ff_init_main.c:98`（`thread0_storage thread0_st`） | 全局单例 struct | 否 | 每实例一份 thread0（随 pcpu/proc0 一起 per-thread 化） | 中 | **P0** |
| `proc0` | `ff_init_main.c:96` | `struct proc` 全局单例 | 否 | 每实例一份 | 中 | **P0** |
| `prison0` / `vmspace0` / `initproc` | `ff_init_main.c:97,99,100` | 全局单例 | 否 | 每实例一份（或共享 prison0 只读，需评估） | 低-中 | P1 |
| `msg_iov_tmp[UIO_MAXIOV]` | `ff_syscall_wrapper.c:225` | `static struct iovec[1024]` | **否（`/*__thread*/` 被故意注释掉）** | 恢复 `__thread`（本就是 per-call 临时缓冲，TLS 天然正确） | **极低（去注释即可）** | **P0** |
| `msg_iovlen_tmp` | `ff_syscall_wrapper.c:226` | `static size_t`（同上被注释） | 否 | 恢复 `__thread` | 极低 | **P0** |

> **注**：`msg_iov_tmp/msg_iovlen_tmp` 使用点在 `ff_syscall_wrapper.c:864,893-897`（`recvmsg/sendmsg` 路径），是每次 syscall 的临时暂存。当前注释掉 `__thread` 说明历史上是单进程单线程假设。**多线程下这是确定性数据错乱靶点，且修复成本几乎为零，是头号"低垂果实"P0。**

### 1.2 DPDK 转发层全局（f-stack 自己的全局）

| 变量名 | file:line | 类型 | per-thread | 建议隔离 | 改造量 | 等级 |
|---|---|---|---|---|---|---|
| `lcore_conf` | `ff_dpdk_if.c:123` | `struct lcore_conf`（全局单例） | 否 | `RTE_PER_LCORE` 或按 lcore_id 索引数组 `lcore_conf[RTE_MAX_LCORE]` | 中（**被引用 30+ 处**，见下） | **P0** |
| `lcore_conf`（外部引用） | `ff_memory.c:71,395,414,459,510` | `extern` 引用 | — | 随上改造 | — | P0 |
| `pktmbuf_pool[NB_SOCKETS]` | `ff_dpdk_if.c:125` | 数组（按 socket 索引） | 部分（按 socket 非按线程） | 多线程共 socket 时可共享 mempool，但需 mempool 本身 MT-safe（DPDK mempool 是 MT-safe） | 低 | P2 |
| `stop_loop` | `ff_dpdk_if.c:87` | `static int` | 否 | 每线程一个停止标志 / `__thread` | 低 | P1 |
| `freebsd_clock` | `ff_dpdk_if.c:89` | `static struct rte_timer` | 否 | 每线程一份定时器（每栈实例自己的 hardclock） | 低-中 | **P1** |
| `msg_ring[RTE_MAX_LCORE]` | `ff_dpdk_if.c:177` | 数组（按 lcore 索引） | 是（已按 lcore） | 保持 | 无 | P4 |
| `veth_ctx[RTE_MAX_ETHPORTS]` | `ff_dpdk_if.c:179` | 数组（按 port） | 否（按 port 非线程） | 若多线程共 port（RSS 分队列）需评估共享读 | 中 | P2 |
| `ff_top_status` / `ff_traffic` | `ff_dpdk_if.c:181,182` | `static struct` 统计 | 否 | 每线程一份统计后聚合 | 低 | P3 |
| `ff_rss_tbl[]` / `ff_rss_tbl6[]` | `ff_dpdk_if.c:203,223` | `static struct[]` RSS 反算表 | 否 | 每线程一份（或只读共享，取决于是否运行时写） | 中 | P1 |
| `rss_thash_ctx/ready[RTE_MAX_ETHPORTS]` 等 | `ff_dpdk_if.c:137-139,158-160` | `static[]` 按 port | 否 | init 期一次性构建、运行期只读 → 可共享 | 低 | P3 |
| `dispatch_ring / packet_dispatcher(_with_context)` | `ff_dpdk_if.c:129-131` | `static` 全局回调/环 | 否 | 每线程一份或只读共享 | 低 | P2 |
| `enable_kni / kni_accept / knictl_action` | `ff_dpdk_if.c:74-76` | 全局 | 否 | 每线程一份或只读 | 低 | P2 |
| `numa_on / idle_sleep / pkt_tx_delay` | `ff_dpdk_if.c:80,82,83` | `static`（init 期赋值、运行期只读） | 否 | init 后只读 → 可共享 | 低 | P4 |
| `rsskey / rsskey_len` | `ff_dpdk_if.c:120,121` | `static`（只读） | 否 | 只读共享 | 无 | P4 |

### 1.3 callout / timer 子系统（`ff_kern_timeout.c`，FreeBSD 移植）

| 变量名 | file:line | 类型 | per-thread | 建议隔离 | 改造量 | 等级 |
|---|---|---|---|---|---|---|
| `cc_cpu` | `ff_kern_timeout.c:180` | `struct callout_cpu`（全局单例，`CC_CPU()/CC_SELF()` 全返回它，见 `:181,182`） | 否 | 每线程一份 callout_cpu（每栈实例独立 callwheel/定时轮） | **高**（callout 子系统核心，TCP/IP 所有定时器都挂这） | **P0** |
| `callwheelsize` / `callwheelmask` | `ff_kern_timeout.c:135` | `u_int` 全局 | 否 | 每实例一份（或全局相同值只读，但 callwheel 本身要每实例一份） | 中 | **P1** |
| `timeout_cpu` | `ff_kern_timeout.c:187` | `static int` | 否 | 每实例一份 | 低 | P1 |
| `ncallout` | `ff_kern_timeout.c:107` | `static int`（sysctl RDTUN） | 否 | init 期定值、只读 | 低 | P3 |
| `avg_depth/gcalls/lockcalls/mpcalls` | `ff_kern_timeout.c:93-104` | `static int`（仅 CALLOUT_PROFILING） | 否 | 统计类，profiling 时才有 | 低 | P4 |

> **关键**：`CC_CPU(cpu)` / `CC_SELF()` 被硬编码为 `&cc_cpu`（`:181-182`），完全无视传入的 cpu 参数。多线程多栈必须改成「按 lcore_id/线程索引取各自的 callout_cpu」，否则 N 个栈的定时器（TCP 重传、keepalive、TIME_WAIT 等）全部串到同一个 callwheel 上，锁竞争 + 逻辑错乱。**这是仅次于 lcore_conf/pcpup 的第二大改造硬骨头。**

### 1.4 FreeBSD 内核移植的进程/init 全局（`ff_init_main.c`）

| 变量名 | file:line | 类型 | per-thread | 建议隔离 | 改造量 | 等级 |
|---|---|---|---|---|---|---|
| `sysinit / sysinit_end` | `ff_init_main.c:123` | `struct sysinit **` 全局 | 否 | 见 §2（一次性排序表，N 次执行有问题） | 高 | **P0** |
| `newsysinit / newsysinit_end` | `ff_init_main.c:124` | 同上 | 否 | 同上 | 高 | P0 |
| `null_sysvec` | `ff_init_main.c:301` | 全局 struct（只读常量式） | 否 | 只读共享 | 无 | P4 |
| `proctree_lock`(sx) | `ff_freebsd_init.c:68` | 全局锁 | 否 | 每实例一份锁 | 低 | P2 |
| `uma_page_slab_hash / uma_page_mask` | `ff_freebsd_init.c:70,71` | UMA 分配器全局 hash | 否 | UMA 是内存分配器底座，**极难 per-thread**，建议整个 UMA 层共享 + 加锁（现状是否 MT-safe 需运行时验证） | 高/存疑 | **P0(存疑)** |
| `physmem` | `ff_freebsd_init.c:74` | `long` | 否 | init 期定值只读 | 无 | P4 |
| `all_cpus`(cpuset) | `ff_freebsd_init.c:72`(extern) | 全局 | 否 | 每实例设自己的 cpu | 低 | P2 |

### 1.5 `ff_compat.c` 的 FreeBSD 全局

| 变量名 | file:line | 类型 | per-thread | 建议隔离 | 改造量 | 等级 |
|---|---|---|---|---|---|---|
| `rootvnode` | `ff_compat.c:62` | `struct vnode *` | 否 | f-stack 不做真实 VFS，多为占位；每实例一份或共享 NULL | 低 | P3 |
| `allproc` / `allproc_lock` | `ff_compat.c:64,65` | 进程链表+锁 | 否 | 每实例一份（各栈自己的 proc0 链） | 中 | P1 |
| `allprison / allprison_lock` | `ff_compat.c:66,67` | jail 链表+锁 | 否 | 每实例一份或共享只读 | 低 | P2 |
| `namei_zone` | `ff_compat.c:76` | `uma_zone_t`（链接期符号，运行期不达） | 否 | 共享（不达路径） | 无 | P4 |
| `async_io_version` | `ff_compat.c:70` | `int` | 否 | 只读 | 无 | P4 |
| `seed` | `ff_compat.c:80` | `unsigned int`（arc4random 种子） | 否 | `__thread`（避免多线程 rand_r 竞争） | 极低 | P2 |
| `vttoif_tab[10]` | `ff_compat.c:84` | 只读表 | 否 | 只读共享 | 无 | P4 |

### 1.6 pcap（对照：已正确 per-thread 的范式）

| 变量名 | file:line | 类型 | per-thread | 说明 |
|---|---|---|---|---|
| `g_pcap_fp / seq / g_flen` | `ff_dpdk_pcap.c:55-57` | `static __thread` | **是** | 证明 f-stack 已有 `__thread` per-thread 惯例，可复用此模式 |

### 1.7 VNET 退化全局（§0.2，规模最大、需 B/C agent 交叉核对 FreeBSD 源码树）
- 未列具体行号（在 `freebsd-src-releng-15.0/sys/` 内，非 f-stack/lib）。类别：
  - `V_ifnet`（ifnet 链表）、`V_in_ifaddrhead` / `V_in6_ifaddr`（地址表）
  - `V_tcbinfo` / `V_udbinfo`（TCP/UDP PCB hash 表 + 锁）
  - `V_rt_tables`（路由/FIB，`ff_route.c:643,1411` 已引用）
  - `V_ipport_lowfirstauto` 等端口分配全局
  - 数百个协议计数器（`V_tcpstat` / `V_ipstat` / `V_ip6stat` ...）
- 统一等级 **P0-P1**：这是 share-nothing 多栈的**主战场**。若走 per-thread：要么开启 VIMAGE 让每线程 `curvnet` 指向独立 vnet（工程量巨大、且 f-stack 阉割了 VNET 基建），要么手工把这批全局逐个 per-thread 化（数量惊人）。**建议 leader 让 B/C agent 专门盘点 VNET 全局清单并评估「开 VIMAGE vs 手工 per-thread」两条路线成本。**

---

## 2. 维度2：每线程独立栈实例初始化可行性（核心难点）

### 2.1 一次性初始化序列（`ff_freebsd_init.c:124-192`）
`ff_freebsd_init()` 现状是**进程级一次性**：
1. `kern_setenv`（`:134-148`）— 全局环境变量，N 次会互相覆盖。
2. `pcpup = malloc(...)` + `pcpu_init` + `PCPU_SET(prvspace, pcpup)` + `CPU_SET(0, &all_cpus)`（`:152-155`）— **写全局单例 `pcpup`**，N 次执行后一个 pcpu ，其余泄漏/覆盖。
3. `ff_init_thread0()`（`:157` → `ff_compat.c:157-160`：`pcurthread = &thread0`）— 把 TLS 指向**全局单例 thread0**。多实例需各指向各自的 thread0。
4. `uma_startup1/2` + `uma_page_slab_hash`（`:162-167`）— **UMA 分配器全局初始化，天生一次性**。N 次会重复初始化 UMA、破坏 slab hash。
5. `mutex_init()` + **`mi_startup()`**（`:169-170`）— 见 §2.2，最硬核。
6. `sx_init(&proctree_lock)`（`:171`）— 全局锁，N 次重复 init。
7. `lo_set_defaultaddr()`（`:187`）— 给 loopback 配 127.0.0.1，操作 `V_ifnet` 全局。

### 2.2 `mi_startup()` / SYSINIT —— 静态可判定「不可安全 N 次执行」【硬结论】
- `mi_startup()`（`ff_init_main.c:173-285`）遍历 `sysinit_set` linker set，**逐个执行 SYSINIT 并把 `(*sipp)->subsystem = SI_SUB_LAST` 打勾**（`:271`），跑完后所有条目被标记为已执行。
- 二次调用时：`if (sysinit == NULL)`（`:188`）已不成立（第一次已赋值），进入排序循环时**所有条目 subsystem 已是 SI_SUB_LAST**，`:235-236` 全部 `continue` 跳过 → **第二次 `mi_startup()` 实际什么都不做**。
- **后果**：N 个线程各调一次 `ff_freebsd_init()` 时，**只有第一次真正跑了协议栈子系统初始化**（`domaininit`、`tcp_init`、`ip_init`、hash 表分配、UMA zone 创建……全走 SYSINIT），后续线程拿到的是**第一次初始化出来的那一份全局栈状态**，根本得不到独立实例。
- SYSINIT 表本身是**进程级 linker set，全线程共享一张**（`ff_init_main.c:122` `SET_DECLARE(sysinit_set, ...)`），无法「每线程一张 sysinit 表」而不魔改 mi_startup。
- 其中 `SYSINIT(p0init, SI_SUB_INTRINSIC, ...)`（`ff_init_main.c:523`）初始化**全局单例 proc0/thread0**；`SYSINIT(callwheel_init, SI_SUB_CPU, ...)`（`ff_kern_timeout.c:279`）初始化**全局单例 cc_cpu**。这些 SYSINIT 语义上就是"给唯一的全局对象初始化一次"。

> **【硬结论·静态可判定】**：现有 `ff_freebsd_init()` + `mi_startup()` + SYSINIT 机制**无法通过「per-thread 各调用一次」得到 N 份独立协议栈实例**。第一次调用做全部真初始化并把 SYSINIT 打勾，后续调用是空转。要实现多栈，必须**魔改初始化架构**，二选一：
> - **路线甲（每线程一套栈全局 + 重构 init）**：把所有栈全局 per-thread 化（含 §1 + §0.2 的 VNET 退化全局），并把 `mi_startup` 改成「每线程独立跑一遍、每线程自己的 sysinit 完成标记」（例如每线程一份 sysinit 打勾位图，或 init 函数直接接受 per-thread 上下文指针）。工程量：极大。
> - **路线乙（开 VIMAGE）**：启用 FreeBSD VNET/VIMAGE，每线程 `curvnet` 指向独立 vnet 实例，复用内核成熟的多网络栈基建。但 f-stack 当前**完全没编 VIMAGE**（§0.2），且 f-stack 对 FreeBSD 做了大量阉割（`ff_init_main.c` 里大段 `#if 0`），VNET 基建能否在 f-stack 用户态跑通**静态无法定论、需运行时验证**。

### 2.3 `ff_init` / `ff_run` 调用现状
- `ff_init()`（`ff_init.c:35`）：全 lib 内无 per-thread 调用设计，example 里进程启动时调一次。
- `ff_run()`（`ff_init.c:58-62`）→ `ff_dpdk_run()`（`ff_dpdk_if.c:2764`）→ `rte_eal_mp_remote_launch(main_loop,...)`。虽然 mp_remote_launch 会在所有 lcore 上启动 main_loop，**但 main_loop 里 `qconf=&lcore_conf`（全局单例）**——所以即便物理上多 lcore 跑起来，逻辑上共用同一份 lcore_conf/栈全局，**不是多栈，是多线程踩同一栈（会崩）**。
- 结论：`ff_init/ff_run` **现在不是 per-thread 多栈设计**；改造需引入「每线程：绑 lcore → 建独立 thread 上下文 → 跑独立 ff_freebsd_init（重构后）→ 进入 main_loop 用各自 lcore_conf」的新流程。

### 2.4 诚实边界标注
- 【静态可判定不可 N 次执行】：`mi_startup`/SYSINIT 打勾机制（§2.2）、`pcpup`/`thread0`/`proc0` 全局单例覆盖、UMA 一次性 init。
- 【静态无法定论、需运行时验证】：(a) UMA 分配器在多线程并发下是否 MT-safe（`uma_page_slab_hash` 无 per-thread）；(b) 若走 VIMAGE 路线，f-stack 阉割版 VNET 基建能否跑通；(c) DPDK mempool/mbuf 在多线程共 socket 下的实际行为；(d) callout 改多实例后 hpts/tcp 定时器交互（`ff_kern_timeout.c:1252-1274` 的 tcp_hpts_softclock 特殊处理）。

---

## 3. 维度3：线程基础设施现状

### 3.1 已具备的 per-thread 能力
| 能力 | file:line | 说明 |
|---|---|---|
| `pcurthread` TLS | `ff_compat.c:59` `__thread struct thread *pcurthread` | 每线程独立的 current thread 指针，**已 TLS**。`ff_api.h:55` 对外 extern 声明。 |
| `ff_pthread_create` | `ff_thread.c:32-46` | 封装 pthread_create，把**父线程的 pcurthread 传播给子线程**（`data->parent = pcurthread`，子线程 `ff_set_thread(parent)`）。`ff_api.h:182`。 |
| `ff_init_thread0` | `ff_compat.c:157-160` | 把 pcurthread 设为全局 thread0。 |
| `ff_adapt_user_thread_add/exit` | `ff_compat.c:96-128` | 为「用户线程」建一份独立 proc/thread 上下文（`ff_adapt_user_proc_add` in `ff_init_main.c:541-639`，含独立 fd 表 `fdcopy`、独立 cred、独立 limit）。`ff_api.h:481,483`。**注释标注 "Only used by LD_PRELOAD mode"**（`ff_compat.c:90`）。 |
| `ff_switch/restore_curthread` | `ff_compat.c:131-148` | 临时切换 pcurthread（LD_PRELOAD 场景）。`ff_api.h:485,487`。 |
| pcap per-thread | `ff_dpdk_pcap.c:55-57` | `static __thread` 范式参考。 |

### 3.2 缺口（要实现原生多栈还差什么）
1. **每线程只有独立 thread/proc 上下文，没有独立"栈实例"**：`ff_adapt_user_thread_add` 建的是 thread+proc（fd 表、cred、limit），**共享同一份协议栈全局**（PCB 表、路由、ifnet、callout）。这只解决了"每线程有身份"，没解决"每线程有独立协议栈"。
2. **`ff_pthread_create` 只传播父 thread 指针**（`ff_thread.c:44`），**不做**：绑 lcore、建独立栈实例、独立 ff_freebsd_init。
3. **无 per-thread 的 pcpup / lcore_conf / cc_cpu 访问器**：所有代码直接引用全局符号（`&lcore_conf`、`&cc_cpu`、`pcpup`），没有「按当前线程/lcore 取各自实例」的间接层。需引入统一访问宏/函数（如 `ff_current_stack()`）。
4. **无多栈生命周期管理**：没有「N 份栈实例的创建/销毁/注册表」。
5. **VNET 退化全局无隔离层**（§0.2）：主战场缺口。

---

## 4. 头号靶点排序（供 leader 决策）

| 排名 | 靶点 | file:line | 为何是 P0 头号 | 改造成本 |
|---|---|---|---|---|
| 0（低垂果实） | `msg_iov_tmp/msg_iovlen_tmp` | `ff_syscall_wrapper.c:225-226` | 确定性数据错乱，且**恢复被注释掉的 `__thread` 即可** | 极低 |
| 1 | `mi_startup`/SYSINIT 一次性机制 | `ff_init_main.c:173-285`, `:271` | **决定多栈能否成立的架构级卡点**（静态判定不可 N 次执行） | 极大 |
| 2 | `lcore_conf` 全局单例 | `ff_dpdk_if.c:123`（30+ 引用 + `ff_memory.c`） | 转发层核心，多线程共用即崩 | 中-大 |
| 3 | `pcpup` / `thread0` / `proc0` 单例 | `ff_freebsd_init.c:69`, `ff_init_main.c:96,98` | PCPU 宏底座 + 内核身份对象 | 中 |
| 4 | `cc_cpu` callout 单例 | `ff_kern_timeout.c:180-182` | 所有 TCP/IP 定时器共轮，锁竞争+逻辑错乱 | 高 |
| 5 | VNET 退化全局（数百个） | freebsd-src 树（`V_ifnet/V_tcbinfo/V_rt_tables/...`） | share-nothing 主战场 | 极大（建议专项 agent） |
| 6 | UMA 分配器全局 | `ff_freebsd_init.c:70-71,162-167` | 分配器底座，per-thread 极难；MT-safe 性存疑 | 高/需运行时验证 |

---

## 5. 交叉验证提示（给 B/C agent）
- §0.2 VNET 退化全局的**具体行号**在 `freebsd-src-releng-15.0/sys/` 内，本 agent 只盘了 f-stack/lib 侧的引用点，需 B/C agent 深入 freebsd 源码树补全 `VNET_DEFINE` 清单并评估 VIMAGE 路线。
- §2.4 的四项【需运行时验证】结论，本 agent 无法静态定论，须留待运行时或专项验证，**不得臆测**。
