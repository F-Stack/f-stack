# 04 F-Stack 现状分析：nginx 适配层与 lib 层代码事实及无损 reload 障碍清单

| 项 | 值 |
|---|---|
| 文档编号 | 04 |
| 标题 | F-Stack nginx 适配层与 lib 层现状代码探测（无损 reload 前置事实 + 8 项代码级障碍） |
| 版本 | v1.0 |
| 日期 | 2026-08-18 |
| 状态 | 待人工审计 |
| 来源产物 | work/probe-fstack-current.md（探测员 probe-fstack，2026-08-18 落盘，只读探测，未改任何代码）。本篇为正式化改写：保留全部事实证据（文件:行号）、未坐实标注；「探测方法与读过文件清单」保留为第 1 节以体现证据可追溯 |

探测范围：/data/workspace/f-stack（DPDK 24.11.6 + FreeBSD 15.0），nginx 适配 `app/nginx-1.28.0/`，核心库 `lib/`。

相关篇章：[00-总览](00-overview.md) | [03-旧方案考证](03-fstack-legacy-solution.md) | [05-ld_preload 备选路线](05-ld-preload-alternative.md) | [06-方案设计](06-solution-design.md)

---

## 1. 探测方法

实际读过的文件（全文或关键区段）：

- app/nginx-1.28.0/src/event/modules/ngx_ff_module.c（全文，syscall 劫持层）
- app/nginx-1.28.0/src/event/modules/ngx_ff_host_event_module.c（全文，host epoll 模块）
- app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c（L28-520、L755-1278 关键区段）
- app/nginx-1.28.0/src/event/ngx_event.c（L655-774）、src/event/ngx_event.h（L395-454）
- app/nginx-1.28.0/src/core/ngx_connection.c（L14-73、L460-570）
- app/nginx-1.28.0/src/os/unix/ngx_channel.c（L195-255）
- app/nginx-1.28.0/src/http/ngx_http_core_module.c、src/http/ngx_http.c（搜索定位）
- lib/ff_api.h（全文）、lib/ff_init.c（全文）、lib/ff_msg.h（全文）
- lib/ff_dpdk_if.c（L440-730、L1230-1330、L1690-1840、L2095-2235、L2404-2475、L2740-3060 关键区段）
- lib/ff_syscall_wrapper.c（L900-960 ff_socket）
- lib/ff_freebsd_init.c（L260-370 ff_freebsd_init）
- lib/ff_kern_timeout.c（L1235-1303 ff_hardclock 族）
- lib/ff_config.c（L1150-1270 dpdk_args_setup；L1335-1552 proc_type 解析）
- tools/compat/ff_ipc.c、tools/compat/ff_ipc.h（全文）

搜索过的关键词（grep 实证）：`ff_mod_init|ff_run`、`NGX_HAVE_FSTACK|ngx_ff`、`fstack_conf|belong_to_host|SOCK_FSTACK`、`rte_eal_init|RTE_PROC_PRIMARY|proc_type`、`reuseport`、`dispatch_ring|ff_inpkt`、`ff_hardclock|rte_timer_manage`、`ff_socket|ff_getmaxfd`、`kernel_network_stack`、`ff_freebsd_init`。

全程只读，未运行任何写操作、未跑任何 git 写命令。

## 2. nginx 适配层事实清单

### 2.1 F-Stack 对 nginx 打的适配改动（文件清单）

新增文件（F-Stack 专属）：

- `src/event/modules/ngx_ff_module.c`：libc 符号劫持层 + ff_mod_init。
- `src/event/modules/ngx_ff_host_event_module.c`：host 侧（Linux 内核 epoll）事件模块。

修改文件（相对官方 nginx 1.28.0，通过 `#if (NGX_HAVE_FSTACK)` / `NGX_HAVE_KQUEUE || NGX_HAVE_FSTACK` 插入）：

- `src/os/unix/ngx_process_cycle.c`（进程模型/reload 路径核心改动，见 2.2/2.5）
- `src/os/unix/ngx_process_cycle.h:40-44`（`NGX_FF_PROCESS_NONE/PRIMARY/SECONDARY` 枚举 + `ngx_ff_process` 全局变量）
- `src/os/unix/ngx_channel.c:216-218, 230-234`（channel 事件 `belong_to_host=1`）
- `src/event/ngx_event.c:673-677, 742-747`（额外初始化 host 事件模块）
- `src/event/ngx_event.h:140, 406-446`（`belong_to_host` 位 + 双轨 `ngx_add_event/ngx_del_event` 内联分派 + `ngx_ff_process_host_events`）
- `src/core/ngx_connection.c:14-52`（`ngx_ff_skip_listening_socket()`）、`src/core/ngx_connection.c:1310`（新建连接按 `is_fstack_fd(s)` 判定 belong_to_host）
- `src/core/ngx_connection.h:93`（`belong_to_host:1`）
- `src/core/nginx.c:35, 161-165, 1708` + `src/core/ngx_cycle.h:124`（`fstack_conf` 指令，存 f-stack config.ini 路径）
- `src/http/ngx_http_core_module.c:298-302` + `ngx_http_core_module.h:206` + `src/http/ngx_http.c:1890`（`kernel_network_stack` 指令：server 级选择内核栈/F-Stack 栈）
- `src/event/ngx_event_connect.c:46-47`（upstream 连接按 `pc->belong_to_host` 决定是否带 `SOCK_FSTACK` 创建）
- `src/stream/*`、`src/mail/*` 同款 `kernel_network_stack`（ngx_stream.c:1049、ngx_mail.c:351 等）
- `src/os/unix/ngx_recv.c/ngx_send.c/ngx_readv_chain.c/ngx_writev_chain.c` 等：`#if (NGX_HAVE_KQUEUE) || (NGX_HAVE_FSTACK)`（复用 kqueue 分支的 ready 语义）
- 构建系统：`auto/options:182,219,457`（`--with-ff_module`）、`auto/modules:58-61`（定义 `NGX_HAVE_FSTACK`、`SOCK_FSTACK=0x1000`）、`auto/sources:112-113`（KQUEUE_MODULE/SRCS 追加 ff 两文件）、`auto/make:22-43`（链接 `$FF_PATH/lib/libfstack` whole-archive）

### 2.2 进程模型（master / worker / ff_init 时机）

- master 进程【不做】ff_init / DPDK 初始化：`ngx_master_process_cycle` 里无任何 ff_mod_init 调用，主循环为纯信号驱动 `sigsuspend`（src/os/unix/ngx_process_cycle.c:150-174）。master 的 `ngx_ff_process == NGX_FF_PROCESS_NONE`（默认 0）。
- master 跳过所有 F-Stack 领域 listening socket 的创建：`ngx_ff_skip_listening_socket()` 在 master（NGX_FF_PROCESS_NONE）分支直接返回 1 跳过 AF_INET/INET6+STREAM/DGRAM 的 socket（src/core/ngx_connection.c:25-34；调用点 ngx_connection.c:481、788）。
- worker 创建方式：标准 fork。`ngx_start_worker_processes` → `ngx_spawn_process(cycle, ngx_worker_process_cycle, i, ...)`（ngx_process_cycle.c:480-483），fork 发生在 worker 做 ff_init 之前。
- 【fork 后每个 worker 独立 ff_init】：`ngx_worker_process_init` 内调用 `ff_mod_init(fstack_conf, worker, worker==0)`（ngx_process_cycle.c:1109-1128）。worker 0 → `--proc-type=primary`，worker i>0 → `--proc-type=secondary`（ngx_ff_module.c:169-187 ff_mod_init 拼参数，硬编码）。
- master 用 POSIX shm + 命名信号量同步 worker 0 初始化：`shm_open("ff_shm") + sem_init(pshared=1)`，master `sem_timedwait` 最多等 15s，超时则 master exit(2)（ngx_process_cycle.c:443-475, 487-510）；worker 0 在 ff_mod_init 成功后 `sem_post`（:1130-1132）。
- listening socket 在每个 worker 内创建：ff_mod_init 成功后 worker 调 `ngx_open_listening_sockets(cycle)`（ngx_process_cycle.c:1134-1138）。此时 `ngx_socket(...)` 走 libc 劫持的 `socket()` → `ff_socket()`（见 2.4 fd 机制）。
- nginx worker 数与 config.ini 的 nb_procs 一一对应（worker i ↔ --proc-id=i），流量靠 NIC RSS queue ↔ proc 映射分流（见 3.2/3.5）。
- worker 退出顺序保护：primary worker（worker 0）退出前 `ngx_msleep(500)` 等 secondary 先退（ngx_process_cycle.c:1251-1256）。

### 2.3 事件循环（epoll/kqueue 如何被替换）

- 主事件模块是 ngx_kqueue_module：F-Stack 把 ff 两个文件挂进 KQUEUE_MODULE/KQUEUE_SRCS（auto/sources:112-113）。nginx 调 `kqueue()/kevent()` 时被 ngx_ff_module.c 的同名 libc 符号覆盖劫持到 `ff_kqueue()/ff_kevent()`（ngx_ff_module.c:515-546，kevent 内对 EVFILT_READ/WRITE/VNODE 的 ident 做 restore_fstack_fd 还原）。
- 辅助 host 事件模块 ngx_ff_host_event_module：真实 Linux 内核 `epoll_create/epoll_ctl/epoll_wait`（ngx_ff_host_event_module.c:102-127, 340），专管内核 fd（master-worker channel 等）。
- 双轨分派：`ev->belong_to_host==1` → `ngx_ff_host_event_actions.*`，否则 → `ngx_event_actions.*`（= kqueue 模块 actions → ff 栈）（src/event/ngx_event.h:406-424）。channel 事件固定 belong_to_host=1（ngx_channel.c:216-218）。
- 每个事件模块 init 均在 `ngx_event_process_init` 里执行：先主模块（kqueue→ff），再 `ngx_ff_host_event_actions.init`（ngx_event.c:723-747）。
- worker 事件循环：`ff_run(ngx_worker_process_cycle_loop, cycle)`（ngx_process_cycle.c:924）→ `ff_dpdk_run` → `rte_eal_mp_remote_launch(main_loop, ..., CALL_MAIN)`（lib/ff_dpdk_if.c:3009）。main_loop 每轮：rte_timer_manage 驱动（:2803-2805）→ 收包/发包/IPC msg → 调 `lr->loop()` 即 `ngx_worker_process_cycle_loop` → `ngx_process_events_and_timers(cycle)`（ngx_process_cycle.c:868-907）。
- master 没有事件循环，纯 sigsuspend 等信号（ngx_process_cycle.c:174）。
- single process 模式同样支持：`ngx_single_process_cycle` 里 ff_mod_init(0, primary) + ff_run(ngx_single_process_cycle_loop)（ngx_process_cycle.c:358-397）。

### 2.4 fd 生命周期（fd 是进程内索引还是跨进程实体）

- ff socket fd 是【本进程 FreeBSD 用户态栈内的 fd】，非 Linux 内核 fd：`ff_socket()` 直接 `sys_socket(curthread,...)` 返回 `curthread->td_retval[0]`（lib/ff_syscall_wrapper.c:916-958），fd 属于本进程的 FreeBSD kern_descrip fd 表（ff_freebsd_init 内 `ff_fdused_range(fd_reserve)`，lib/ff_freebsd_init.c:355）。跨进程无意义。
- nginx 侧 fd 命名空间区分：libc 劫持层把 ff fd 加偏移 `convert_fstack_fd = sockfd + ngx_max_sockets`（ngx_ff_module.c:147-149），`is_fstack_fd` 判断 `sockfd >= ngx_max_sockets`（:161-167），restore 时减回去（:152-158）。init 时校验 `ngx_max_sockets + ff_getmaxfd() <= INT_MAX`（:194-197）。
- master fork worker 时：master 未 ff_init（其 socket() 因 `inited==0` 全走 SYSCALL 真系统调用，ngx_ff_module.c:129, 233-234），fork 只继承内核 fd（channel 管道等）。worker 的 ff fd 全部是 fork 后自己创建，【不存在 master→worker 的 ff listening fd 传递】。
- close 同样劫持：`close()` 判断 is_fstack_fd 后走 `ff_close`（ngx_ff_module.c:439-447）。

### 2.5 reload（HUP）路径：F-Stack 版下发生了什么

信号链：SIGCHLD→ngx_reap、SIGHUP(HUP=NGX_RECONFIGURE_SIGNAL)→ngx_reconfigure、QUIT→ngx_quit（ngx_process_cycle.c:98-108 + src/os/unix/ngx_process.c 信号处理，未改）。

F-Stack 对 `ngx_master_process_cycle` 的 ngx_reconfigure 分支改成了【两段式串行 reload】（ngx_process_cycle.c:223-270）：

1. 第一拍收到 HUP（ngx_reconfigure=1 且 !sig_worker_quit）：置 sig_worker_quit=1，向所有子进程发 QUIT（`ngx_signal_worker_processes(NGX_SHUTDOWN_SIGNAL)`），continue（:224-230）。
2. 后续循环若仍有活 worker（live=1）则 continue 干等（:232-234）。
3. 全部 worker 退出（live=0，经 ngx_reap_children 确认）后：sig_worker_quit 复位，`ngx_init_cycle`（重建配置、重新解析 nginx.conf）→ `ngx_start_worker_processes(NGX_PROCESS_JUST_RESPAWN)` → `ngx_start_cache_manager_processes` → sleep 100ms → 再向旧 worker 发 QUIT（此时已无旧 worker）（:236-269）。

即：旧 worker（含 ff primary=worker 0）全部退出后，新 worker 才 fork 并各自 ff_init（新 worker 0 以 DPDK primary 身份重新 rte_eal_init 接管网卡）。期间数据面完全空窗。

配套改动：

- worker 收 QUIT：graceful shutdown——`ngx_close_listening_sockets(cycle)`（ff fd 在本进程栈内 close）+ `ngx_close_idle_connections`，等 `ngx_event_no_timers_left()` 后 `ngx_worker_process_exit`（ngx_process_cycle.c:888-899, 872-877）。注意 F-Stack worker 分支【没有】 `ngx_set_shutdown_timer`（:894-898 对比原生 :951-957）。
- reload 期间禁止自动重生：`ngx_reap_children` 的 respawn 条件追加 `&& !ngx_reconfigure`（ngx_process_cycle.c:762-764）。
- master 的 ngx_quit 分支：非 F-Stack 才 `ngx_close_listening_sockets`；F-Stack 版跳过（master 本来就没有 ff listening fd）（:217-219）。
- 未改动点：ngx_signal_worker_processes、ngx_init_cycle 本体、channel 消息（NGX_CMD_*）逻辑与原生一致（除 belong_to_host）。

## 3. lib 层事实清单

### 3.1 ff_api.h 接口面 / ff_init 参数

- `ff_init(int argc, char * const argv[])`（lib/ff_api.h:57；实现在 lib/ff_init.c:36-56）：顺序 = `ff_load_config` → `ff_dpdk_init(dpdk_argc, dpdk_argv)` → `ff_freebsd_init()` → `ff_dpdk_if_up()`。argv 是 f-stack 自己的参数（--conf/--proc-id/--proc-type 等），ff_load_config 内解析后重新组装 dpdk_argv 给 EAL（lib/ff_config.c:1159-1270 dpdk_args_setup）。
- `ff_run(loop_func_t loop, void *arg)`（ff_api.h:59；ff_init.c:59-62）→ `ff_dpdk_run`；`ff_stop_run()`（ff_api.h:61）置 stop_loop=1（ff_dpdk_if.c:3026-3033）。
- socket 族：ff_socket/setsockopt/getsockopt/listen/bind/accept/accept4/connect/close/shutdown/getpeername/getsockname/read/readv/write/writev/send/sendto/sendmsg/recv/recvfrom/recvmsg/select/poll（ff_api.h:63-181）；ff_kqueue/ff_kevent/ff_kevent_do_each（:168-173）；ff_gettimeofday（:175-179）；ff_dup/ff_dup2（:181-182）。
- 辅助：`ff_fdisused/ff_getmaxfd`（:201-204）、`ff_regist_packet_dispatcher(_context)`（:299-303）、`ff_dpdk_raw_packet_send`（:319）、`ff_zc_*` 零拷贝族（:383-500）。
- EAL 参数透传：config.ini `[dpdk]` 的 no_huge/proc_mask(-c)/nb_channel(-n)/memory/log_level/proc_type/base_virtaddr/file_prefix/allow(--allow PCI)/vdev 全部拼进 dpdk_argv（ff_config.c:1166-1240），其中 `--proc-type` 来自 cfg->dpdk.proc_type（:1185-1188；默认 "auto"，:1343-1344；只允许 primary/secondary/auto，:1347-1350）。nginx 场景下 proc_type 由 ff_mod_init 硬编码覆盖为 primary/secondary（ngx_ff_module.c:183-187）。

### 3.2 ff_dpdk_if.c：EAL 初始化、PCI 接管、primary/secondary

- `rte_eal_init` 在 `ff_dpdk_init()`（lib/ff_dpdk_if.c:1699-1836）内调用：ff_dpdk_if.c:1712。前置校验 `nb_procs∈[1,RTE_MAX_LCORE]`、`proc_id∈[0,nb_procs)`（:1702-1710）。之后 init_lcore_conf（:1727）→ init_mem_pool（:1729）→ init_dispatch_ring（:1731）→ init_msg_ring（:1733）→ init_port_start（:1763，内部 dev_configure/rx/tx queue setup/start）。
- 网卡 PCI 接管：EAL `--allow=<PCI>`（或 -c + 默认 probe），primary 进程执行 rte_eth_dev_configure/queue setup/start；secondary 通过 DPDK multi-process 共享 hugepage 中的设备状态直接操作同一网卡的 RX/TX queue。
- primary 独占创建、secondary 只 lookup 的资源（代码级证据，RTE_PROC_PRIMARY 判断）：
  - mempool：primary `rte_pktmbuf_pool_create`，secondary `rte_mempool_lookup`（ff_dpdk_if.c:616-639）
  - rte_ring（dispatch/msg ring）：primary `rte_ring_create`，secondary `rte_ring_lookup`（:660-680 create_ring）
  - 链路状态检查、flow isolate、rte_flow 规则、FDIR、KNI vdev（:1234, :1752, :1790, :1807, :1824；ff_dpdk_kni.c:98-202）
- 【两个进程不能同时以 primary 初始化】：同 file_prefix 下 DPDK EAL 只允许一个 primary（secondary attach 到 primary 的 hugepage 配置）。nginx 侧通过 worker 编号硬编码决定身份（worker0=primary），并且 master 用 semaphore 保证 worker0 就绪后才 fork 后续 secondary（ngx_process_cycle.c:487-510）。
- 收发模型：多进程模式（thread_mode=0）每个进程绑一个 lcore（`proc_lcore[proc_id]`，ff_dpdk_if.c:508-511），该 lcore 在网卡 lcore_list 中的下标即其 RX queue id（:513-538），main_loop 中各进程直接 `rte_eth_rx_burst` 自己的 queue（:2865+）。跨进程包转发经 dispatch_ring（primary/任意进程 enqueue :2142-2150、目标进程 dequeue :2223-2233）。
- timer 现状见 3.4；timer 库共享 memzone 结构与本地补丁背景见 [03-旧方案考证](03-fstack-legacy-solution.md) §5。

### 3.3 ff_ipc / ff_msg：现有 IPC 能力

- lib 主库【没有】ff_ipc.c；IPC 实现在 tools/compat/ff_ipc.c（工具侧客户端）+ ff_dpdk_if.c（数据面服务端）。
- 通信模型：工具进程（ff_top/ff_sysctl/ff_route/ff_ipc_msg 等）以 `--proc-type=secondary` 跑 rte_eal_init attach（tools/compat/ff_ipc.c:65-75），从共享 mempool `ff_msg_pool` 取消息（:77-80, 94-111），enqueue 到目标 ff 进程的 `ff_msg_ring_in_<proc_id>`（:133-159），阻塞等 `ff_msg_ring_out_<proc_id>_<msg_type>`（:161-192，最多 1000ms*1000 次 usleep 轮询）。
- 数据面服务端：每个 ff 进程 main_loop 里 `process_msg_ring(proc_id, ...)`（ff_dpdk_if.c:2903；实现 :2456-2474）→ `handle_msg()`（:2404-2454）按 msg_type 分发 sysctl/ioctl/route/top/ngctl/ipfw/traffic/knictl 处理器。
- 消息类型全集（lib/ff_msg.h:37-53）：FF_SYSCTL、FF_IOCTL、FF_IOCTL6、FF_ROUTE、FF_TOP、FF_NGCTL、FF_IPFW_CTL、FF_TRAFFIC、FF_KNICTL。
- 【结论：现有 IPC 仅覆盖控制面工具类消息；没有任何跨进程 fd/socket/listening/TCP session 传递的机制或消息类型】（ff_msg.h:134-155 结构体里也无对应字段）。

### 3.4 定时器现状

- 初始化：`init_clock()`（ff_dpdk_if.c:1241-1257，ff_dpdk_init 末尾调用 :1783）= `rte_timer_subsystem_init` + `rte_timer_meta_init` + 创建周期 rte_timer `freebsd_clock`（周期 = 1/config freebsd.hz，PERIODICAL，绑定当前 lcore，回调 `ff_hardclock_job`）。
- 回调实现：`ff_hardclock_job → ff_hardclock()`（ff_dpdk_if.c:254-258；lib/ff_kern_timeout.c:1242-1253）：`ticks++`、`callout_tick()`、`tc_ticktock()`、`cpu_tick_calibration()`。thread_mode=1 时 worker 用 `ff_hardclock_worker()`（只 `callout_tick()`，ff_kern_timeout.c:1261-1265；注册于 init_clock_worker ff_dpdk_if.c:1262-1272）。
- 驱动点：main_loop 每轮 `cur_tsc=rte_rdtsc()`，若 `freebsd_clock.expire < cur_tsc` 则 `rte_timer_manage()`（ff_dpdk_if.c:2803-2805）。
- 其他时钟点：每轮 `ff_tcp_hpts_softclock()` 驱动 HPTS pacing wheel（:2934；实现 ff_kern_timeout.c:1290-1295）；`ff_get_tsc_ns()`（:4227-4229）为 timecounter 源（ff_kern_timeout.c:1297-1303）。
- 【没有内核信号/独立定时器线程】：所有定时都由 ff_run 的 run-to-completion 主循环驱动（ff_kern_timeout.c:1268-1286 注释明说 swi/userret 路径在 f-stack 是 no-op）。

### 3.5 多进程 / reuseport 支持现状

- SO_REUSEPORT：仅作为 setsockopt 的 Linux→FreeBSD 常量透传（lib/ff_syscall_wrapper.c:82, 561-562）。F-Stack nginx 多 worker 不是内核 reuseport 语义，而是【每 worker 一个完全隔离的 FreeBSD 协议栈实例，各自 socket/bind/listen 同一 IP:port 互不冲突（栈隔离），流量由 NIC RSS queue↔proc 静态映射分流，每条 TCP 连接只存在于一个进程的栈内】。
- 每进程独立协议栈实例：`ff_freebsd_init()`（lib/ff_freebsd_init.c:269-370）在每进程内跑完整 FreeBSD 内核初始化（kern_setenv、mp_ncpus、UMA、mi_startup、fd_reserve），thread_mode=0 时 nb_cpus=1（:298-301）。
- thread_mode=1（进程内多线程 native-mt）与 proc_type=secondary 显式互斥（lib/ff_config.c:1547-1548 报错；:1551-1552 强制 primary）。nginx 多进程模式用的是 thread_mode=0。
- dispatch 回调：`ff_regist_packet_dispatcher(_context)` 允许 app 重定向包到指定 queue/进程（ff_api.h:235-303；ff_dpdk_if.c:2105-2150），nginx 未使用。

## 4. 无损 reload 的代码级障碍清单

按「为什么当前架构做不到 nginx 原生无损 reload（新旧 worker 并存、listening fd 继承、旧 worker 处理完存量连接再退）」整理，每项带证据位置。本清单是 [06-方案设计](06-solution-design.md) 候选方案评估与 [07-里程碑](07-milestones.md) 障碍消解映射的输入。

- **障碍 1【reload 被改成两段串行：旧 worker 全退→新 worker 才起，存在服务空窗】**
  证据：app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:223-237（sig_worker_quit 先发 QUIT、live==0 才继续 init_cycle/start workers）。
  原因：新 worker 0 必须以 DPDK primary 身份 rte_eal_init，而旧 worker 0 仍是 primary（网卡/mempool/ring 归属），二者不能并存（见障碍 4）。

- **障碍 2【listening socket fd 无法跨进程继承/传递】**
  证据：ff fd 是进程私有 FreeBSD 栈 fd（lib/ff_syscall_wrapper.c:945-958 返回 td_retval[0]；lib/ff_freebsd_init.c:355 每进程独立 fd 表）；master 不创建 ff listening（ngx_connection.c:25-34）；worker fork 后各自 ff_socket/bind/listen（ngx_process_cycle.c:1134 + ngx_connection.c:543-547）；IPC 无 fd 传递消息类型（lib/ff_msg.h:37-53）。
  原因：新 worker 无法「接手」旧 worker 的 listening socket，只能整套重建；过渡期端口在新栈里短暂无人 listen（SYN 到达 RSS queue 却无人 accept）。

- **障碍 3【TCP 连接状态（PCB/sockbuf）在 worker 私有栈内，无迁移机制】**
  证据：每进程独立 ff_freebsd_init 实例（lib/ff_freebsd_init.c:269-370）；进程间仅共享 mempool/ring/dispatch ring 等数据面资源（ff_dpdk_if.c:616-639, 683-724），无任何 TCP 状态导出/导入接口（ff_api.h 全文无此能力）。
  原因：旧 worker 退出=其上全部 TCP 连接销毁；无损 reload 需要连接迁移或旧 worker 继续服务存量连接直至自然结束，而当前 reload 把旧 worker 全部 QUIT（含正在服务的 primary），且 QUIT 后 worker 因 ngx_close_listening_sockets + no_timers_left 较快退出（长连接会被 ngx_event_no_timers_left 之外的逻辑尽快排空，但 ff 栈随进程消亡）。

- **障碍 4【DPDK primary 单点：worker0 硬编码 primary，新旧 primary 无法并存】**
  证据：ngx_process_cycle.c:1117-1121（worker==0 → NGX_FF_PROCESS_PRIMARY）；ngx_ff_module.c:183-187（proc_type==1 → --proc-type=primary）；primary 独占创建 mempool/ring/port（ff_dpdk_if.c:616-639, 669-673, 1763）；master 用 sem 同步 worker0 就绪后才能 fork secondary（ngx_process_cycle.c:487-510）。
  原因：nginx 原生 reload 顺序（先起新 worker 再退旧 worker）要求新 primary 在旧 primary 存活时完成 rte_eal_init——DPDK 同 file_prefix 下不可能；这是 F-Stack 版把 reload 改成串行的根本约束。

- **障碍 5【reload 期间 worker 挂掉不重生 + primary 退出前 sleep 500ms 的脆弱时序】**
  证据：ngx_process_cycle.c:762-764（respawn 条件加 !ngx_reconfigure）；ngx_process_cycle.c:1251-1256（primary 退出 sleep 500ms 等 secondary）。
  原因：过渡期容错差；500ms 是经验值非同步原语，慢机器上 secondary 可能先于 primary 完全退出前失去 primary 共享资源（未实测，见未坐实清单）。

- **障碍 6【master 不在数据面，无法充当「配置切换协调者+listening 持有者」】**
  证据：master 不 ff_init（ngx_process_cycle.c:82-174 无 ff 调用）；master 的 socket() 未劫持（ngx_ff_module.c:129, 233-234 inited==0 走内核）。
  原因：任何「master 统一持有 ff listening 并分发给 worker」的方案在现状下无基础设施（fd 无跨进程语义、IPC 无传递通道）。

- **障碍 7【流量分流是 NIC RSS queue↔proc 静态映射，过渡期队列无人消费】**
  证据：init_lcore_conf 每进程绑一个 lcore=一个 RX queue（ff_dpdk_if.c:508-538）；main_loop 各自 rx_burst（:2865+）；跨进程仅 dispatch ring（:2142-2150, 2223-2233）。
  原因：旧 worker 停止循环后其 queue 的包积压直至 ring/描述符满后丢包；新 worker 起来前没有任何进程替它收包（除非 RSS 重定向，现状无此动态机制）。该障碍即 issue #1036 坐实的「队列无主窗口」根因（见 [01](01-vpp-vcl-research.md) §6.2、[03](03-fstack-legacy-solution.md) §7）。

- **障碍 8【定时器/时钟随进程消亡】**
  证据：freebsd_clock 是进程内 rte_timer，由该进程 main_loop 的 rte_timer_manage 驱动（ff_dpdk_if.c:1242-1257, 2803-2805）；ff_hardclock 推进 ticks/callout/timecounter（ff_kern_timeout.c:1242-1253）。
  原因：旧 worker 退出期间其栈内所有 TCP 定时器（RTO/keepalive/延迟 ACK）停止，存量连接的拥塞控制状态冻结；若做「旧 worker 拖到连接结束」方案则旧进程必须一直活着跑 ff_run，与当前 reload 全退语义冲突（当前实现其实是允许 worker 拖到 no_timers_left，但 master 会因 live=1 一直等，期间新配置不生效——语义与无损目标错位）。

- **补充事实（非障碍但影响方案设计）**：F-Stack 版 worker QUIT 分支没有 ngx_set_shutdown_timer（ngx_process_cycle.c:894-898 对比原生 951-957），存量长连接可能拖住 worker 不退，master 一直 live=1 等待，reload 挂起（只能再发 TERM/INT 强杀）。

## 5. 未坐实清单

以下问题静态读码无法定论，需运行时实验或更深入追踪：

1. DPDK 24.11 下 secondary 进程在 primary 退出后的存活行为：mempool/ring 由 primary 创建于共享 hugepage，primary 死后 secondary 继续收发是否稳定、多久后出问题——未实测。（ngx_process_cycle.c:1251-1256 的 500ms sleep 暗示上游已知此窗口敏感。）
2. nginx worker 退出是否走 ff_dpdk_run 的收尾路径：worker 实际是 ngx_worker_process_exit → exit(0)（ngx_process_cycle.c:1258），不经 ff_run 返回，因此 rte_eal_cleanup（ff_dpdk_if.c:3014-3022）不被调用；hugepage 资源释放完全依赖进程死亡——是否留下脏状态（如 primary 异常退出后 secondary 或新 primary attach 失败）未验证。
3. reload 空窗时长实测值：sem 等待上限 15s（ngx_process_cycle.c:494）、master ngx_msleep(100)（:265）、primary 退前 500ms（:1254）都是静态值；真实空窗=旧 worker 退出时间 + 新 worker EAL+栈初始化时间，未测（对应 [08-测试计划](08-testing.md) E-NR-04 基线采集）。
4. ff 栈内 SO_REUSEPORT（ff_syscall_wrapper.c:561-562 透传）在多进程各自 listen 同端口场景是否被 F-Stack nginx 实际设置（ngx_connection.c 的 SO_REUSEADDR 设置路径 :556-570 见到的是 SO_REUSEADDR；SOCK_FSTACK 分支下是否额外设 REUSEPORT 未逐行追）。
5. ngx_http_core_module.c:298 的 kernel_network_stack 指令与 listening 归属（ngx_http.c:1890）在「同端口部分 server 走内核栈、部分走 F-Stack」时的 fd 分配冲突行为，未深挖（对本 spec 主线影响小）。
6. KNI 启用时（enable_kni）reload 空窗期 KNI vdev 归属 primary（ff_dpdk_if.c:2905-2925）对控制面的影响，未展开。
