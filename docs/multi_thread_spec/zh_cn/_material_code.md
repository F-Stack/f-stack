# f-stack 多线程模式支持 —— 代码事实素材（带 file:line 证据）

> 本文由代码深探子 agent (arch-code-explorer) 产出。所有结论均基于 `/data/workspace/f-stack` 实际代码，逐条标注 `file:line`。仅只读代码，未修改 lib。交叉验证不一致以代码为准。
> 探测时间基准：2026-07-23。

---

## 0. 核心结论摘要（TL;DR）

1. **f-stack 原生并发模型是「多进程 run-to-completion（RTC）」，不是「单进程多线程」**：每个 f-stack 进程绑定**恰好一个** DPDK lcore，`lcore_conf` 是**全局单例**（`ff_dpdk_if.c:123`），多进程间通过 DPDK 共享大页内存（mempool/ring）+ 网卡 RSS 分流协作。并发扩展靠 `lcore_mask` 里多个 bit → 拉起多个进程（proc_id 0..N-1），而非在一个进程里开多线程跑协议栈。
2. **协议栈本身不是线程安全的（未按多线程设计）**：`curthread`（=TLS `pcurthread`）已 per-thread 化（`ff_compat.c:59`、`pcpu.h:41-64`），但 `pcpup`（PCPU 全局指针，`ff_freebsd_init.c:69`）、`thread0`、以及 `ff_syscall_wrapper.c:225-226` 的 `msg_iov_tmp/msg_iovlen_tmp`（**故意注释掉 `__thread`**）等仍是**进程级单例/全局**，一个进程内多线程同时进协议栈会产生竞态。
3. **已有的“多线程”能力集中在 LD_PRELOAD syscall adapter 层**（`adapter/syscall/`），通过 `FF_THREAD_SOCKET`（RTC per-thread `sc`）与 `FF_MULTI_SC`（类 `SO_REUSEPORT`）两个编译宏支持“用户 APP 多线程/多进程 + 每线程/进程各连一个 f-stack 后端实例”。**底层协议栈仍是多进程**，adapter 只是把 N 个用户线程映射到 N 个后端 f-stack 进程实例。
4. **issue #430（socket type 组合标志位）在当前代码下已完备处理**：`SOCK_NONBLOCK/SOCK_CLOEXEC` 经 `linux2freebsd_socket_flags`（`ff_syscall_wrapper.c:672-684`）统一转换，`ff_socket`（:943）与 `ff_accept4`（:1679）都走这条路径；hook 层 `fstack_territory`（`ff_hook_syscall.c:359-374`）先剥离所有 4 类标志位再判 STREAM/DGRAM。结论：**pthread 多线程 + `SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC` 组合已被正确处理**，隐患不在 type 转换，而在“同一 fd 跨线程/协议栈全局状态共享”。
5. **KNI 严格 primary-only**：`ff_kni_init`/`ff_kni_alloc`/主循环 KNI 处理都用 `rte_eal_process_type()==RTE_PROC_PRIMARY` 门控（`ff_dpdk_kni.c:379,426`、`ff_dpdk_if.c:2661`、`ff_config.c:1396-1410`），多进程下只有 proc_id=0（primary）跑 KNI。

---

## 1. 多进程模型完整机制

### 1.1 配置结构定义（lib/ff_config.h）

- `struct ff_config.dpdk` 关键字段（`ff_config.h:269-328`）：
  - `char *proc_type;`（`:272`）—— "primary"/"secondary"/"auto"
  - `char *lcore_mask;`（`:274`）—— 全部启用的 lcore 掩码
  - `char *proc_mask;`（`:276`）—— **当前进程**在所有 lcore 上的掩码（单 bit）
  - `int nb_procs;`（`:290`）—— 进程总数（由 lcore_mask bit 数推导）
  - `int proc_id;`（`:291`）—— 当前进程序号（0-based）
  - `uint16_t *proc_lcore;`（`:311`）—— proc_id → lcore_id 映射表
  - `int numa_on;`（`:295`）
- `struct ff_port_cfg`（`:173-215`）：`int nb_lcores;`（`:207`，= nb_procs）、`uint16_t lcore_list[DPDK_MAX_LCORE];`（`:209`）—— 每端口参与的 lcore 列表（用于 RSS 队列分配）。
- 常量：`DPDK_MAX_LCORE 128`（`:37`）。

### 1.2 proc_type / lcore_mask 解析与校验（lib/ff_config.c）

- **`parse_lcore_mask()`**（`ff_config.c:73-142`）：把 `lcore_mask` 十六进制掩码逐 bit 解析：
  - `proc_lcore[count] = idx;`（`:118`）逐个记录启用的 lcore；
  - 当 `proc_id == count`（`:119`）时，为**本进程**生成单 bit 的 `proc_mask`（`:123-125`，`cfg->dpdk.proc_mask = strdup(buf)`）；
  - `cfg->dpdk.nb_procs = count;`（`:139`）—— 进程数 = 掩码里 bit 总数；
  - `if (cfg->dpdk.proc_id >= count) return 0;`（`:136-137`）—— proc_id 越界校验。
- **proc_type 解析**（`ff_config.c:1300-1326`）：
  - `-p` → `proc_id = atoi(optarg)`（`:1300-1301`）；
  - `-t` → `proc_type = strdup(optarg)`（`:1303-1305`）；
  - 默认 `proc_type = "auto"`（`:1312-1314`）；
  - 合法性校验：只允许 primary/secondary/auto（`:1316-1321`）；
  - `proc_id > RTE_MAX_LCORE` 兜底为 0（`:1323-1326`）。
- **DPDK argv 拼接**（`ff_config.c:1150-1170`）：
  - `-c<proc_mask>`（`:1151-1153`）—— 传给 EAL 的 coremask 是**本进程单 bit** proc_mask；
  - `--proc-type=<proc_type>`（`:1167-1169`）。
- **端口 lcore_list 初始化**（`ff_config.c:567-571`）：`pconf->nb_lcores = ff_global_cfg.dpdk.nb_procs; memcpy(pconf->lcore_list, proc_lcore, ...)`。
- **KNI primary-only 校验**（`ff_config.c:1392-1410`）：注释明确 “only primary process process KNI”，若 KNI 开启且 proc_type=="primary"，则 primary lcore 必须在每个端口的 lcore_list 中。

### 1.3 EAL init / PRIMARY-SECONDARY / 共享资源（lib/ff_dpdk_if.c）

- **全局单例 `lcore_conf`**：`struct lcore_conf lcore_conf;`（`ff_dpdk_if.c:123`）—— 整个进程一份，`main_loop` 里 `qconf = &lcore_conf;`（`:2585`）。这是“一进程一 lcore”模型的直接证据。
- **`init_lcore_conf()`**（`:400-464`）：
  - `lcore_conf.proc_id = ff_global_cfg.dpdk.proc_id;`（`:415`）；
  - `uint16_t lcore_id = proc_lcore[lcore_conf.proc_id];`（`:424`）—— 本进程只认自己那颗 lcore；
  - 按 `proc_id` 在 `pconf->lcore_list` 中找到自己的 index 作为 `queueid`（`:434-448`）—— **RSS 队列 = proc_id**；
  - `lcore_conf.nb_queue_list[port_id] = pconf->nb_lcores;`（`:459`）—— 总队列数=进程数；
  - 若本 lcore 无 rx queue 则 `rte_exit`（`:462-463`）。
- **rte_eal_init**：`ff_dpdk_init()` 里 `rte_eal_init(argc, argv)`（`:1594`），入口前校验 `nb_procs/proc_id` 合法性（`:1584-1592`）。
- **mempool 共享（PRIMARY 建，SECONDARY attach）**：
  - `init_mem_pool()`（`:480+`）遍历 `nb_procs` 个 lcore，`if (rte_eal_process_type()==RTE_PROC_PRIMARY)` 则 `rte_pktmbuf_pool_create`（`:522-523`），否则 lookup。
- **ring 共享**：`create_ring()`（`:575-576`）—— `if PRIMARY rte_ring_create` 否则 lookup。
- **dispatch ring**：`init_dispatch_ring()`（`:593-626`）—— 每 port 每 queue 一个 `dispatch_ring[portid][queueid]`（`:618`），`nb_queues = pconf->nb_lcores`（`:602`）。
- **msg ring（进程间控制消息）**：`init_msg_ring()`（`:649-668`）—— `nb_procs` 个 `msg_ring[i]`，PRIMARY 建 `message_pool`（`:653-655`）。
- **网卡配置只 PRIMARY 做**：`rte_eth_dev_configure` 前 `if (rte_eal_process_type()!=RTE_PROC_PRIMARY) continue;`（`:1002-1006`）；`nb_queues = pconf->nb_lcores`（`:785`）作为 rx/tx 队列数；`nb_queues>max_rx/tx_queues` 时 `rte_exit`（`:819-828`）。
- **RSS reta 表**：`set_rss_table(port_id, reta_size, nb_queues)`（`:736-751`），`reta_conf[i].reta[j] = hash++ % nb_queues`（`:750`），仅 `nb_queues>1` 时设置（`:1110-1114`）。
- **link status 检查只 PRIMARY**：`:1130-1131`。
- **主 polling 循环 `main_loop()`**（`:2566-2760+`）：
  - `while (1)`（`:2587`），`stop_loop` 退出（`:2589`）；
  - TX drain（`:2634-2650`）；
  - 逐 rx queue：`process_dispatch_ring`（`:2666`）→ `rte_eth_rx_burst`（`:2668`）→ `process_packets`（`:2688,2693`）；
  - KNI 处理 `if (enable_kni && PRIMARY) ff_kni_process`（`:2661-2663`）；
  - `process_msg_ring(qconf->proc_id, ...)`（`:2699`）；
  - LRO flush（`:2671-2672,2695-2696`）。
- **`ff_dpdk_run()`**（`:2764-2771`）：`rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)`（`:2770`）+ `rte_eal_mp_wait_lcore()`（`:2771`）。
  - **重要**：虽然用 `mp_remote_launch`（会向所有 EAL lcore 分发），但每个 f-stack 进程的 EAL coremask 只含**一颗** lcore（proc_mask 单 bit），所以实际每进程只有一个 lcore 跑 `main_loop`。这不是“单进程多 lcore 多线程”，而是“多进程各一 lcore”。

### 1.4 关键全局变量清单（ff_dpdk_if.c 文件级 static/global）

| 变量 | file:line | 说明 | 多线程隐患 |
|---|---|---|---|
| `struct lcore_conf lcore_conf` | :123 | 每进程一份 rx/tx queue 配置 | 单例，一进程多线程共享会乱 |
| `struct rte_mempool *pktmbuf_pool[NB_SOCKETS]` | :125 | per-NUMA mbuf 池 | DPDK mempool 本身 MT-safe |
| `dispatch_ring[RTE_MAX_ETHPORTS]` | :129 | 派发 ring | rte_ring MT-safe（按 flag） |
| `packet_dispatcher / _with_context` | :130-131 | 用户派发回调 | 全局函数指针 |
| `int enable_kni` | :74 | KNI 开关 | |
| `static int numa_on` | :80 | | |
| `static unsigned idle_sleep / pkt_tx_delay` | :82-83 | | |
| `static int stop_loop` | :87 | 停止标志 | |
| `static struct rte_timer freebsd_clock` | :89 | | |
| `rsskey / rsskey_len` | :120-121 | RSS key | |
| `int nb_dev_ports` | :78 | 注释注明 secondary 不准确 | |

---

## 2. 已有线程基础设施

### 2.1 TLS 当前线程指针（curthread per-thread 化）

- **`ff_compat.c:59`**：`__thread struct thread *pcurthread = NULL;` —— **TLS**，每线程独立。
- **`pcpu.h`（amd64/i386）**：
  - `amd64/include/pcpu.h:41`：`extern __thread struct thread *pcurthread;`
  - `:52-64`：`__curthread_ff()` 返回 `pcurthread`，`#define curthread __curthread_ff()`（`:63`）。
  - 即 FreeBSD 内核代码里所有 `curthread` 引用，在 f-stack 里都解析为 TLS `pcurthread`。**这是唯一已被 per-thread 化的核心内核状态。**
- symbol 导出：`ff_api.symlist:76 pcurthread`（`:79-82` 导出 4 个 thread 适配函数）。

### 2.2 ff_thread.c 全文（lib/ff_thread.c，仅 52 行）

- `extern __thread struct thread *pcurthread;`（`:7`）
- `struct thread_data { start_routine; arg; struct thread *parent; }`（`:9-13`）
- `ff_set_thread(other)` → `pcurthread = other`（`:15-18`）
- `ff_start_routine()`（`:20-30`）：在新 pthread 里 `ff_set_thread(p_data->parent)`（`:26`）—— **把父线程的 thread 指针直接赋给子线程的 TLS**（继承父的 struct thread，并非新建独立 thread）。
- `ff_pthread_create()`（`:32-46`）：`data->parent = pcurthread;`（`:44`）后 `pthread_create(thread, attr, ff_start_routine, data)`（`:45`）。
- `ff_pthread_join()`（`:48-51`）：直接透传 `pthread_join`。
- **隐患**：子线程 `pcurthread` = 父的 `struct thread`（共享同一 struct thread），并非独立 thread 上下文，多个子线程同时进协议栈会共享同一 `td`。

### 2.3 LD_PRELOAD 模式的用户线程上下文（lib/ff_compat.c）

- `ff_adapt_user_thread_add(parent)`（`:96-120`）：parent==NULL 时用 `&thread0`（`:102-103`），`malloc(sizeof(struct proc))`（`:106`）+ `ff_adapt_user_proc_add`（`:111`）—— 为用户线程**新建独立 struct thread**。
- `ff_adapt_user_thread_exit(td)`（`:122-128`）。
- `ff_switch_curthread(new)`（`:131-140`）：保存旧 `pcurthread`，切到 new，返回旧值。
- `ff_restore_curthread(old)`（`:142-148`）：恢复。
- `ff_init_thread0()`（`:156-160`）：`pcurthread = &thread0;`。
- **对比 ff_thread.c**：`ff_adapt_user_thread_add` 才是“每线程独立 thread 上下文”的正确姿势（LD_PRELOAD 用）；`ff_thread.c` 的 `ff_pthread_create` 只是共享父 thread（老式，隐患大）。

### 2.4 API 声明（lib/ff_api.h）

- `extern __thread struct thread *pcurthread;`（`ff_api.h:55`）
- `ff_pthread_create/join`（`:180-185`，`#ifndef _KERNEL` + `#include <pthread.h>`）
- `ff_adapt_user_thread_add/exit`、`ff_switch_curthread`、`ff_restore_curthread`（`:481-487`）
- `ff_rss_self_queue_info(proc_id, queueid, nb_queues, reta_size)`（`:124-126`）—— 只读本进程 RSS 队列信息（自检工具用）。
- 栈选择标志位（`#ifdef FF_KERNEL_COEXIST`，`:81-101`）：`SOCK_FSTACK 0x01000000`（`:96`）、`SOCK_KERNEL 0x02000000`（`:99`）。注释说明 per-socket 选栈优先级：per-socket marker > config.ini kernel_coexist > F-Stack。

### 2.5 adapter 多 worker 结构（adapter/syscall/）

**main_stack_thread_socket.c（kqueue 版，全文 262 行）**：
- `#define MAX_WORKERS 128`（`:25`），`pthread_t hworker[MAX_WORKERS];`（`:26`），`pthread_spinlock_t worker_lock;`（`:27`）。
- `loop()`（`:75-212`）：每 worker 独立 `socket()`（`:90`）→ `bind`（:110）→ `listen`（:117）→ `kqueue`（:125）→ 事件循环（:144-206）。**每线程各自一套 fd/kq**。
- `main()`（`:214-262`）：`worker_num = atoi(argv[1])`（:224）；`pthread_spin_lock` 串行化 worker 启动（:229,252）；`pthread_create(&hworker[i], NULL, loop, &i)`（:232）；**绑核**：`lcore_id = 2+i`，`pthread_setaffinity_np`（:239-250）。
- 关键注释：`/* socket will init adapter, so unlock after socket */`（:98）—— socket() 里会 `ff_adapter_init`，spinlock 保证初始化串行。

**main_stack_epoll_thread_socket.c（epoll 版）**：
- 结构同上（`:19-27`）。`loop()`（`:68+`）：`socket(AF_INET, SOCK_STREAM | SOCK_FSTACK, 0)`（`:79`）—— **显式 OR SOCK_FSTACK 标志**；`setsockopt(..., SO_REUSEPORT, ...)`（`:92`）；`epoll_create(512|SOCK_FSTACK)`（`:117`）。每 worker 独立 epfd/sockfd + SO_REUSEPORT 多线程 accept。

### 2.6 ff_hook_syscall.c 的 sc/type 处理（adapter/syscall/ff_hook_syscall.c）

- **per-thread 编译开关**：`static __FF_THREAD int inited = 0;`（`:226`）、`static __FF_THREAD struct ff_so_context *sc;`（`:227`）。`__FF_THREAD` 定义见 `ff_socket_ops.h:27-31`：`#ifdef FF_THREAD_SOCKET → __thread`，否则空。
- **总是 TLS 的**：`shutdown_args/getsockname_args`（`:75-77`，注释 “Always use __thread, but no __FF_THREAD”）。
- **FF_MULTI_SC**（`:234-251`）：`ff_multi_sc_type scs[SOCKET_OPS_CONTEXT_MAX_NUM]`（`:241`），`current_worker_id`（`:250`）。
- **worker_id 分配**：`int worker_id`（`:272`）、`rte_spinlock_t worker_id_lock`（`:273`）；`ff_adapter_init()`（`:3163+`）里 `getenv("FF_PROC_ID")`（`:3248`）设 worker_id，`sc = ff_attach_so_context(worker_id % nb_procs)`（`:3297`）—— **worker → 后端 f-stack 进程实例的映射**。
- **socket type 处理链**：
  - `fstack_territory(domain, type, protocol)`（`:359-374`）：先 `type &= ~SOCK_CLOEXEC/~SOCK_NONBLOCK/~SOCK_FSTACK/~SOCK_KERNEL`（`:363-366`）再判 `AF_INET/AF_INET6` + `SOCK_STREAM/SOCK_DGRAM`（`:368-369`）。
  - `ff_hook_socket(domain, type, protocol)`（`:379-427`）：非 f-stack 领地 → `ff_linux_socket`（:384）；`SOCK_KERNEL && !SOCK_FSTACK` → kernel 栈（:387-390）；`type &= ~SOCK_FSTACK`（:406）后转发 `FF_SO_SOCKET`（:414）。

---

## 3. FreeBSD 栈全局状态 per-thread 化清单（多线程共享隐患）

> 判定原则：一进程内若开多线程同时进协议栈，以下**非 TLS 的进程级单例**会产生竞态/数据损坏。

| 全局状态 | file:line | 类型 | 是否已 per-thread | 多线程隐患评估 |
|---|---|---|---|---|
| `pcurthread` | `ff_compat.c:59` | `__thread struct thread*` | ✅ 是（TLS） | 安全。唯一被 per-thread 化的核心状态 |
| `pcpup`（PCPU 指针） | `ff_freebsd_init.c:69` | `struct pcpu *`（全局单例） | ❌ 否 | **高危**。`PCPU_GET/SET`（pcpu.h:44-50）全走这个单例指针；per-CPU 统计/状态在多线程下共享，非原子 |
| `thread0` / `thread0_st` | `ff_init_main.c:98` | 单例 struct | ❌ 否（初始模板） | 中危。多个用户线程若都退回 thread0（如 ff_thread.c 共享父 td）会冲突 |
| `vmspace0` | `ff_init_main.c:99` | 单例 | ❌ 否 | 低（f-stack 不做真实 VM） |
| `msg_iov_tmp[UIO_MAXIOV]` | `ff_syscall_wrapper.c:225` | **static 全局（注释掉 __thread）** | ❌ 否（**故意**） | **高危**。`recvmsg`（:864 memcpy from）/`sendmsg`（:893-897 memcpy to）路径共用这块 iovec 暂存区，多线程并发 sendmsg/recvmsg 会互相踩踏 |
| `msg_iovlen_tmp` | `ff_syscall_wrapper.c:226` | 同上 | ❌ 否 | **高危**，同上 |
| `rootvnode / allproc / allproc_lock / allprison / allprison_lock` | `ff_compat.c:62-67` | 单例 | ❌ 否 | 进程级全局；多线程改动需加锁（FreeBSD 原生有 sx 锁 allproc_lock:65） |
| `seed`（rand_r） | `ff_compat.c:80` | 单例 | ❌ 否 | 低危（随机数质量） |
| VNET（`V_*`） | `ff_ng_base.c:183-189,385` | `VNET_DEFINE_STATIC` | N/A | f-stack 通常**不启用 VIMAGE**，VNET() 退化为单实例全局；仅 netgraph 用到。若未来多线程需网络栈隔离，VNET 是天然隔离点但当前未开 |
| `g_pcap_fp / seq / g_flen` | `ff_dpdk_pcap.c:55-57` | `__thread` | ✅ 是 | 安全（pcap 抓包已 per-thread） |

**关键结论**：协议栈的 socket table（`in_pcbinfo`/tcbinfo）、route table、callout wheel 等在 FreeBSD 原生实现里靠自己的锁（mtx/rwlock/epoch）保护，f-stack 保留了这些锁但**运行时是单线程 RTC**（一进程一 lcore），锁基本不产生竞争。若强行改成一进程多线程跑 `main_loop`/协议栈，除上述全局单例外，还需重新审视 `pcpup`、`lcore_conf`、`msg_iov_tmp` 三处最直接的破坏点。

---

## 4. issue #430 落点核验（socket type 组合标志位）

### 4.1 lib 层（ff_syscall_wrapper.c）

- **标志位定义**（`:220-221`）：`LINUX_SOCK_CLOEXEC = LINUX_O_CLOEXEC`、`LINUX_SOCK_NONBLOCK = LINUX_O_NONBLOCK`。
- **`linux2freebsd_socket_flags(flags)`**（`:672-684`）：
  - `LINUX_SOCK_NONBLOCK` → 清掉再 `|= SOCK_NONBLOCK`（`:675-678`）；
  - `LINUX_SOCK_CLOEXEC` → 清掉再 `|= SOCK_CLOEXEC`（`:679-682`）。
- **`ff_socket()`**（`:916-946+`）：`sa.type = linux2freebsd_socket_flags(type);`（`:943`）→ `sys_socket(curthread, &sa)`（`:945`）。
  - FF_KERNEL_COEXIST 段（`:922-940`）：`SOCK_KERNEL && !SOCK_FSTACK` → 走 host kernel（:932-936）；`type &= ~(SOCK_KERNEL|SOCK_FSTACK)`（:939）后再转换。
- **`ff_accept4()`**（`:1664-1679+`）：`kern_accept4(curthread, s, pf, linux2freebsd_socket_flags(flags), &fp)`（`:1679`）—— accept4 的 flags 走**同一转换函数**。

### 4.2 hook 层（ff_hook_syscall.c）

- `fstack_territory`（`:363-366`）：判领地前统一剥离 `SOCK_CLOEXEC/SOCK_NONBLOCK/SOCK_FSTACK/SOCK_KERNEL` 四类标志位。
- `ff_hook_socket`（:406）：`type &= ~SOCK_FSTACK` 后转发。

### 4.3 结论

- **`SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC` 组合已被完整、正确处理**：
  - hook 层剥离标志位判领地（不会因标志位误判 STREAM/DGRAM）；
  - lib 层 `linux2freebsd_socket_flags` 完整转换 NONBLOCK/CLOEXEC 到 FreeBSD 语义；
  - `ff_socket` 与 `ff_accept4` 均走此路径，标志位处理一致。
- **pthread 多线程场景下**：type 转换本身与线程数无关（纯参数变换，无共享状态），**不是多线程隐患点**。真正的多线程隐患在第 3 节列出的全局单例（`msg_iov_tmp`、`pcpup`、`lcore_conf` 等），与 socket type 无关。

---

## 5. DPDK 多线程模型对接点

- **`rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)`**（`ff_dpdk_if.c:2770`）+ `rte_eal_mp_wait_lcore()`（`:2771`）：语义上向所有 EAL lcore 分发 `main_loop`，但因每进程 coremask 单 bit（见 1.2 proc_mask），实际每进程只 1 个 lcore 执行。
- **`rte_lcore_id()`** 用法：`init_lcore_conf` 里 `rte_lcore_to_socket_id(rte_lcore_id())`（`:419`）取 NUMA socket；`rte_timer_reset(..., rte_lcore_id(), ...)`（`:1148`）。
- **`rte_lcore_is_enabled(lcore_id)`**（`:425`）校验本进程 lcore 已启用。
- **未使用 `rte_eal_remote_launch`（单 lcore 版）**：全库只用 mp 版本（grep 结果仅 `:2770`）。
- **mempool/ring 线程安全前提**：
  - mempool per-NUMA（`pktmbuf_pool[NB_SOCKETS]`，`:125`），DPDK mempool 默认 MT-safe（有 per-lcore cache）；
  - dispatch_ring 用 `RING_F_SC_DEQ`（`:618-619`）—— **单消费者** ring，正因为一队列只对应一个进程/lcore 消费，才安全；若一进程多线程消费同一 ring 会破坏 SC 前提。
  - msg_ring 用 `RING_F_SP_ENQ | RING_F_SC_DEQ`（见 init_msg_ring 附近）—— 单生产单消费，同样依赖“一 proc 一消费者”。
- **结论**：DPDK 层的对接点已按“每 lcore/进程一个消费者”优化（SC/SP ring flag），这是**反多线程**的设计前提；要支持一进程多线程需改 ring flag 为 MC/MP 或每线程独立 ring。

---

## 6. KNI / IPC / 工具链

### 6.1 KNI primary-only（lib/ff_dpdk_kni.c）

- 全局：`struct rte_ring **kni_rp;`（`:89`）、`struct kni_interface_stats **kni_stat;`（`:90`）、`struct kni_ratelimit kni_rate_limt`（`:92`）。
- `ff_kni_init()`（`:377-420`）：`if (rte_eal_process_type()==RTE_PROC_PRIMARY)` 才 `rte_zmalloc kni_stat`（`:379-382`）。
- `ff_kni_alloc()`（`:423-471`）：同样 `if PRIMARY`（`:426`）才建 virtio_user 异常路径 port（`:451-467`）。
- 主循环调用：`if (enable_kni && rte_eal_process_type()==RTE_PROC_PRIMARY) ff_kni_process(...)`（`ff_dpdk_if.c:2661-2663`）。
- 配置校验：`ff_config.c:1392-1410` 注释 “only primary process process KNI”。
- ratelimit 常量：`ff_config.h:47-50`（KNI_RATELIMT_PROCESS=10000 等）。
- **结论**：KNI 仅 primary（proc_id=0）进程处理，多进程模型下 secondary 进程不碰 KNI。这是 KNI 与多线程/多进程的关键归属约束。

### 6.2 IPC ring

- **进程间控制消息 msg_ring**：`init_msg_ring()`（`ff_dpdk_if.c:649-668`），`nb_procs` 个 ring，`message_pool`（`:653-655`），主循环 `process_msg_ring(qconf->proc_id, ...)`（`:2699`、定义 `:2278`）—— 每进程按自己 proc_id 收消息。
- **adapter 层 IPC**：`adapter/syscall/ff_ring_ipc.c`（LD_PRELOAD 模式用户 APP ↔ f-stack 后端的 ring IPC），`ff_socket_ops.c` 生产/消费（`:653-655` req_ring dequeue）。`SOCKET_OPS_CONTEXT_MAX_NUM = (1<<5) = 32`（`ff_socket_ops.h:44-45`）—— sc 上下文槽位上限，即单实例最多挂 32 个 worker。
- **so_zone 共享内存**（`ff_so_zone.c`）：`ff_so_zone`（`:27`，`__FF_THREAD`）；`ff_attach_so_context(idx)`（`:160+`）用 `rte_spinlock_lock(&ff_so_zone->lock)`（`:192`）+ `inuse[]` 位图（`:200-210`）分配 sc；FF_MULTI_SC 下 `ff_so_zones[]` 数组（`:29`）。

### 6.3 工具链（tools/）

- `tools/` 下各工具（`netstat/ifconfig/ipfw/route/ngctl/arp/ndp/...`）通过 `ff_ioctl_freebsd/ff_setsockopt_freebsd/ff_rtioctl/ff_ngctl`（`ff_api.h:343-368`）与 f-stack 交互；多进程下工具通常连 primary/指定 proc_id。
- `ff_route.c` 路由控制、`ff_ngctl.c`/`ff_ng_base.c` netgraph（VNET_DEFINE 出现处，见 3 节）。

---

## 7. 对多线程 spec 的直接输入（供方案设计参考）

1. **现状定性**：f-stack 是「多进程 shared-nothing（RSS 分流）」，**不是**「多线程共享协议栈」。“多线程支持”在 f-stack 语境里目前=①LD_PRELOAD adapter 的多 worker（FF_THREAD_SOCKET RTC / FF_MULTI_SC SO_REUSEPORT）②`ff_pthread_create` 共享父 thread（隐患大，慎用）。
2. **若要真正“一进程多线程跑协议栈”**，最小改造清单（按危险度）：
   - `msg_iov_tmp/msg_iovlen_tmp`（`ff_syscall_wrapper.c:225-226`）→ 恢复 `__thread`（注释已预留）；
   - `pcpup`（`ff_freebsd_init.c:69`）→ per-thread 或每线程绑定独立 pcpu；
   - `lcore_conf`（`ff_dpdk_if.c:123`）→ per-thread queue 配置 + 每线程独立 rx/tx queue；
   - dispatch_ring / msg_ring 的 SC/SP flag（`ff_dpdk_if.c:618`）→ 每线程独立 ring 或改 MC/MP；
   - `ff_pthread_create`（`ff_thread.c:44`）→ 改为每子线程 `ff_adapt_user_thread_add` 建独立 `struct thread`（参照 ff_compat.c:96）。
3. **推荐路线**：优先沿用/完善 adapter 层多 worker（FF_THREAD_SOCKET + FF_MULTI_SC + SO_REUSEPORT）+ 底层维持多进程 RSS 模型，而非改造协议栈为多线程共享（后者要动 FreeBSD 全局状态，风险极高）。README.md（`adapter/syscall/README.md:122-209,342-410`）已系统描述这四种模式，是 spec 的权威参考。
4. **issue #430 已闭环**：socket type 组合标志位处理完备，spec 中列为“已支持/无需改动”。

---

（素材完，所有 file:line 均基于实际代码核验；如与外网资料冲突，以本文代码证据为准。）
