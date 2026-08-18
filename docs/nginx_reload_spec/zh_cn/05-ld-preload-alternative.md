# 05 备选路线分析：adapter/syscall（LD_PRELOAD）架构与 Nginx 无损 reload 可行性

| 项 | 值 |
|---|---|
| 文档编号 | 05 |
| 标题 | F-Stack adapter/syscall（LD_PRELOAD ring IPC）架构探测 + nginx 无损 reload 可行性与缺口清单 |
| 版本 | v1.0 |
| 日期 | 2026-08-18 |
| 状态 | 待人工审计 |
| 来源产物 | work/probe-ld-preload.md（探测员 probe-ldpreload，2026-08-18 落盘，只读探测，未改任何代码，未执行 git 写操作）。本篇为正式化改写：保留全部事实证据（文件:行号）、与既有 spec 的偏差标注、未坐实清单；「探测方法」保留为第 1 节以体现证据可追溯 |

探测范围：`/data/workspace/f-stack/adapter/syscall/` + `docs/ld_preload_ring_spec/zh_cn/` 01/02 两篇。所有行号以当前工作区代码为准（探测时点 2026-08-18）。

相关篇章：[00-总览](00-overview.md) | [04-现状分析](04-fstack-current-analysis.md) | [06-方案设计](06-solution-design.md)

---

## 1. 探测方法

- 通读 `docs/ld_preload_ring_spec/zh_cn/01-requirements-spec.md`、`02-architecture-design-spec.md` 全文（各约 300/640 行），提炼功能定位。
- 逐行通读代码（全文非抽样）：
  - `adapter/syscall/ff_hook_syscall.c`（3445 行，全文分 4 段读完）
  - `adapter/syscall/ff_ring_ipc.c`（164 行）、`ff_socket_ops.c`（753 行）、`ff_so_zone.c`（372 行）、`fstack.c`（37 行）
  - `ff_declare_syscalls.h`、`ff_hook_syscall.h`、`ff_socket_ops.h`、`ff_adapter.h`、`ff_linux_syscall.c`（268 行）、`Makefile`
  - `adapter/syscall/README.md`（439 行，英文版）
- 分析方法：从 hook 面（syscall 覆盖）、IPC 面（ring/sem 双路径）、生命周期面（attach/detach/fork/exit）、nginx 映射面（master/worker、HUP/USR2、连接所有权）四个维度交叉核对代码事实。
- 未做：编译、运行、git log 考古（本轮时间盒内以现行代码为准）。

## 2. 既有 spec 文档要点提炼

### 2.1 功能定位（01-requirements-spec.md）

- 该改造的目标是把 LD_PRELOAD 模块（libff_syscall.so）与 fstack 实例进程之间的 IPC，从「三层同步」（状态机 IDLE/REQ/REP + spinlock + POSIX 跨进程信号量，01 文档 §1.1，引用 `ff_socket_ops.h:73-75/103/111`）替换为 DPDK `rte_ring` SPSC 双环（FR-001/FR-002，§2）。
- 动机是纯性能：sem/futex 内核态开销 100-200ns（§1.2.1）、sem_timedwait 毫秒级超时精度（§1.2.2）、fstack 侧 O(n) 遍历 32 个 sc（§1.2.3）、alarm_event_sem 补偿脆弱（§1.2.4）、轮询/信号量模式编译期分裂（§1.2.5）。
- 支持 5 种运行模式兼容（C-001 表）：PIPELINE（默认）、RTC/FF_THREAD_SOCKET、FF_KERNEL_EVENT、FF_MULTI_SC、FF_PRELOAD_POLLING_MODE（ring 下统一为 busy-poll 策略）。
- 注意：01/02 两篇是「ring IPC 改造」的 spec，不是 LD_PRELOAD 功能本身的 spec。LD_PRELOAD 功能定位在 README.md：让存量应用（nginx 为典型）不改代码接入 F-Stack（README L7-L16）。

### 2.2 架构设计（02-architecture-design-spec.md）

- 双 Ring SPSC 模型：请求环 APP→fstack、响应环 fstack→APP，均在 Hugepage（§2.1/2.2）。
- 新状态机取消 IDLE/REQ/REP，sc 生命周期由 ring 入队/出队隐式管理（§2.3）。**注意其隐含假设：一个 sc 同一时刻只属于一个发起者**（§2.3 注："在 req_ring 中 = 请求已提交"）。
- 三种等待策略 busy/yield/eventfd，运行时可配置（§6.2 承诺环境变量 `FF_RING_WAIT_MODE`，默认 yield-poll）。
- 业界对比：VPP memif / svm_msg_q（§4），选 rte_ring 理由是 F-Stack 已重度使用 rte_ring（dispatch_ring/msg_ring）。
- 错误处理（§8）：ring 满自旋重试；C-005 要求「进程异常退出时 ring 中残留 sc 指针需在 detach 时清理」。

### 2.3 spec 与代码的偏差（重要）

- **wait_mode 运行时配置未实现**：spec 02 §6.2 承诺 `FF_RING_WAIT_MODE` 环境变量；代码中无任何 `getenv` 读取该变量，`ff_create_so_memzone` 调 `ff_create_sc_ring_zone(proc_id, FF_RING_SIZE, FF_RING_DEFAULT_WAIT_MODE)`（`ff_so_zone.c:124-125`），`FF_RING_DEFAULT_WAIT_MODE` 是编译期常量（`ff_socket_ops.h:155-157`）。
- **响应路径已偏离 spec v1.0**：spec 设计响应走 rsp_ring；实现演进为 v3.3 D2 修复——fstack 侧不再向 rsp_ring 入队，而是直接置 `sc->completion=1`（与 result 同 cache line），rsp_ring 仅在 `ff_ring_alarm_wakeup` 里作 legacy 兜底入队（`ff_ring_ipc.c:49-75`、`ff_hook_syscall.c:3411-3440` 注释）。
- **detach 清理 ring 未实现**：spec C-005 要求 detach 时排空 ring 残留；`ff_detach_so_context`（`ff_so_zone.c:229-264`）无任何 ring 操作。
- 03/04（interface/test）与 `ld_preload_ring_support.md`、`ring_ipc_perf_offline_analysis.md` 本轮未读（任务只要求 01/02），可能含补充约束（见 §6-6）。

## 3. 代码事实清单

### 3.1 hook 的系统调用（全列）

声明面（`ff_declare_syscalls.h:1-31` + `ff_hook_syscall.h:6-14`），通过 strong_alias 把 `ff_hook_##fn` 别名为 `fn` 符号（`ff_hook_syscall.c:43-52`）实现 LD_PRELOAD 劫持：

| 类别 | 接口 | 证据 |
|---|---|---|
| socket 建立 | socket / bind / listen / connect / shutdown | ff_declare_syscalls.h:1-11 |
| 接受连接 | accept / accept4 | ff_declare_syscalls.h:9-10 |
| 收发 | recv / recvfrom / recvmsg / read / readv / send / sendto / sendmsg / write / writev | ff_declare_syscalls.h:12-23 |
| 元数据 | getsockname / getpeername / getsockopt / setsockopt | ff_declare_syscalls.h:5-8 |
| 控制 | close / fcntl / ioctl（变长参数独立实现）/ select | ff_declare_syscalls.h:24-30；ioctl 变长版 ff_hook_syscall.c:1939-1950 |
| 事件 | epoll_create / epoll_ctl / epoll_wait；kqueue / kevent 直接导出 | ff_declare_syscalls.h:26-28；ff_hook_syscall.h:12-14 |
| 进程 | **fork**（已 hook）；**exec 系列完全未 hook** | ff_declare_syscalls.h:29；全目录无 exec 符号 |
| glibc 加固 | __recv_chk / __read_chk / __recvfrom_chk | ff_hook_syscall.h:6-9 |

路由规则：`is_fstack_fd(fd)`（fd >= ff_kernel_max_fd，即 RLIMIT_NOFILE，`ff_hook_syscall.c:309-316`、`3192-3202`）为真走 fstack（`CHECK_FD_OWNERSHIP` 宏 L57-63），否则走 dlsym libc 的真系统调用（`ff_linux_syscall.c:80-267`）。fstack fd = 真实 fd + ff_kernel_max_fd（`convert_fstack_fd` L296-298，逆变换 L301-307）。

### 3.2 fork 的 hook 语义（ff_hook_syscall.c:2426-2496）

- 真正的 fork 经 `ff_linux_fork` → dlsym libc fork（`ff_linux_syscall.c:254-259`）。
- FF_MULTI_SC：fork 前切 `sc = scs[current_worker_id].sc; ff_so_zone = ff_so_zones[current_worker_id]`（L2434-2435），让子进程继承该 worker 的 sc 与 zone；父进程 `current_worker_id++`（L2451）。
- 整个 fork 窗口持有 `sc->lock`（L2438-2440），父进程 `sc->refcount++`（L2447）。
- FF_USE_THREAD_STRUCT_HANDLE：父进程置 `sc->forking=1` 并自旋等子进程完成（L2455-2457）；子进程先 `ff_adapter_child_process_init()` attach 新 sc（L2470，实现见 L3335-3347，内部 `ff_attach_so_context(0)` 固定 attach zone 0），再发 `FF_SO_FORK` 请求，stack 侧 `ff_sys_fork` 调 `ff_adapt_user_thread_add(parent)` 在 FreeBSD 栈内复制线程与 fd 表（`ff_socket_ops.c:381-395`），子进程拿新 thread handle（L2482）。
- 注释明确支持的拓扑限制：master→child→workers 扁平/一层嵌套，不支持 worker→worker→worker 链式（L244-247）。
- **exec 未 hook**：USR2 升级二进制后 so 重载，进程内 sc/scs/current_worker_id/inited/fstack_kernel_fd_map 全部清零重置。

### 3.3 ring IPC 机制（ff_ring_ipc.c + ff_socket_ops.c + ff_so_zone.c）

- 命名：`ff_sc_req_ring_%d` / `ff_sc_rsp_ring_%d` / `ff_sc_ring_zone_%d`（`ff_so_zone.c:18-20`），按 proc_id（fstack 实例号）区分。
- 创建（primary=fstack 进程）：`ff_create_sc_ring_zone`（`ff_so_zone.c:273-337`），SPSC 标志 `RING_F_SP_ENQ|RING_F_SC_DEQ`（L280），ring_size 默认 64（`ff_socket_ops.h:147-149`）；eventfd 仅 wait_mode==2 时创建（L321-330）。APP 侧 `ff_attach_sc_ring_zone` 按名 lookup（L344-370）。
- **消息格式即 sc 指针**（void* 入环，无消息头）：APP 侧 `ff_ring_submit_and_wait`（`ff_hook_syscall.c:3384-3443`）：先 `completion=0`（v3.3 H23 修复，防先完成后清零，L3395-3398 注释）→ `rte_ring_sp_enqueue` 满则自旋 → 按 wait_mode 自旋等 `sc->completion==1`（acquire 语义 L3419）。超时基于 `rte_rdtsc`（L3414-3421）。
- fstack 侧消费：`ff_handle_each_context` ring 分支（`ff_socket_ops.c:621-668`）：`rte_ring_empty` 快速空判（D5，L653）+ inline dequeue burst（D6，L654-660）+ `ff_handle_socket_ops_ring`（L524-549）无锁执行 `ff_so_handler` → `ff_ring_send_response` 置 `completion=1`（release 语义，`ff_ring_ipc.c:61`）。主循环无任何 zone 级锁。
- stack 进程与 client 配对：fstack 进程按 `nb_procs` 为每个 proc_id 建 zone+ring（`ff_so_zone.c:74-139`）；APP 是 DPDK secondary 进程（`--proc-type=secondary`，`ff_hook_syscall.c:3267-3272`），按 `ff_attach_so_context(worker_id % nb_procs)` 绑定到某实例（L3297）。
- 多 client：每个 zone 有 `SOCKET_OPS_CONTEXT_MAX_NUM=32` 个 sc 槽（`ff_socket_ops.h:45`），attach 置 inuse=1、refcount=1（`ff_so_zone.c:200-212`）；同一 sc 可被 fork 出的进程共享（refcount 机制）。FF_MULTI_SC 下 APP 内维护 `scs[32]` 数组顺序占用（`ff_hook_syscall.c:234-251`、`3305-3310`）。

### 3.4 stack 进程侧（fstack.c + ff_socket_ops.c）

- `fstack` 二进制 = 标准 F-Stack 应用（`fstack.c:15-36`）：`ff_init` → `ff_set_max_so_context(32)` → `ff_create_so_memzone` → `ff_run(loop)`，loop 只调 `ff_handle_each_context`（L7-12）。
- 多进程：即标准 F-Stack config.ini 多进程实例（README L263-273 用 `start.sh -b adapter/syscall/fstack` + lcore_mask 启多实例）；每实例一个 zone/ring，每 zone 32 sc。
- 所有 socket 真实动作（ff_socket/ff_bind/ff_accept/ff_read...）在 stack 进程内执行（`ff_socket_ops.c:124-267` 各 ff_sys_* wrapper）——**连接状态、fd 表（FreeBSD）、协议栈全在 stack 进程**。
- 驻留状态：`ff_bound_fds[8]`（static，stack 进程内存，L42）记录已 bind 的地址→fd，重复 bind 同地址触发 `ff_dup2(bound_fd, fd)` 复用旧 listening socket（`ff_sys_bind` L131-147）。

### 3.5 client 退出/崩溃时的资源回收

- 正常退出：so 的 destructor `ff_adapter_exit`（`ff_hook_syscall.c:3131-3160`）：FF_MULTI_SC 且当前是 master（`current_worker_id == worker_id`）时循环对每个 scs[i] 执行 `ff_application_exit`（FF_SO_EXIT_APPLICATION → stack 侧 `ff_adapt_user_thread_exit`，`ff_socket_ops.c:410-419`）+ `ff_detach_so_context`；否则单 sc detach。detach 语义：refcount>1 减一，=1 才释放 inuse 槽（`ff_so_zone.c:241-263`）。
- 线程退出：pthread_key destructor（L3045-3052）仅 FF_THREAD_SOCKET 下 detach sc。
- **异常退出（kill -9 / crash）**：destructor 不执行 → sc inuse 永久占用 → zone 满 32 后新 APP attach 失败（`ff_so_zone.c:194-198`）。**无心跳、无进程监控、无 stack 侧孤儿回收机制**。req_ring 残留项会被 stack 照常处理（结果无人读，无害）；completion 无人清（下次复用该 sc 前 submit 会清，但该 sc 已泄漏不复用）。
- **client 退出不关闭 stack 侧 socket fd**：detach 只释放 sc 槽位，`ff_sys_close` 只在 APP 显式调 close 时执行（L269-275）。进程死亡 = Linux fd 表销毁，但 stack 进程的 FreeBSD fd 表不受影响 → 连接 fd 泄漏。README L22 明示「进程结束时仍有潜在内存泄漏与死锁风险」。

### 3.6 fd 传递 / fork 后 socket 共享

- Linux fd 表由 fork 天然复制（fd 数字不变）；APP 侧「fd」只是 `数字 + ff_kernel_max_fd 偏移`，socket 本体在 stack 进程。
- stack 侧 FreeBSD fd 表复制仅发生在 FF_USE_THREAD_STRUCT_HANDLE 开启时的 FF_SO_FORK 路径（`ff_adapt_user_thread_add`，`ff_socket_ops.c:390-392`）；未开该宏时 ff_sys_fork 直接返回 0 不做 stack 侧动作（L383-394）。
- **fd 与 sc 无强绑定**：所有 ff_sys_* handler 直接拿 `args->fd` 执行，不校验 fd 归属于哪个 sc/线程（如 `ff_sys_read` L224-229）。同 zone 内任意 sc 携带任意 fd 数字均可操作（PIPELINE 模式基础假设）。
- FF_KERNEL_EVENT 的 fstack↔kernel epoll fd 映射表 `fstack_kernel_fd_map[65536]`（`ff_hook_syscall.c:255-259`）是进程内数组：fork 继承有效；exec 后丢失。

### 3.7 epoll_wait 语义（nginx 关键路径）

- ring 模式（L2267-2299）：`ff_ring_submit_and_wait(timeout_us)`，timeout<0 永久阻塞、超时映射为 0 事件（L2291-2292）；`timeout<=0 && ret==0` 时 goto RETRY 自旋（L2406-2410）。
- FF_KERNEL_EVENT：同时调内核 epoll，但**每 256 次才轮询一次内核 fd**（`if ((count & 0xff) == 0)`，L2333-2345）——控制面（nginx channel/timer fd）事件延迟可达数百次循环。maxevents 必须 >=2（L2213-2217）。
- fstack epoll 是 kqueue 封装，触发方式与多 accept 与标准 epoll 有差异，nginx 需 `multi_accept on`（README L232、L138）。

## 4. nginx 结合可行性分析（代码级）

前提配置（README L203-288）：`FF_KERNEL_EVENT=1 + FF_MULTI_SC=1` 编译，nginx `listen ... reuseport` + `worker_processes=N` + `FF_NB_FSTACK_INSTANCE=N`，fstack 实例先行启动。

### 4.1 master + worker 全 LD_PRELOAD 的基本成立性

- master 启动即带 LD_PRELOAD；signal / pid 文件 / open / write / kill 等**非 socket 系统调用均未 hook**，走内核，pid 文件与信号机制语义不变（hook 清单见 §3.1）。
- reuseport 模式：master 为每个 worker 调 socket/bind/listen——每次 socket 触发 `ff_adapter_init` 顺序 attach sc 并记入 `scs[]`（`ff_hook_syscall.c:392-404`、`3297-3310`）；fork 时按 `current_worker_id` 切换 sc/zone 给子进程（L2434-2435）。该流程是 README 明确文档化的 nginx 工作路径（L188-201）。
- worker fork 时 socket fd 继承：Linux fd 数字自然继承；stack 侧连接本体不动。**成立**。
- master 的 epoll：nginx master 主要用信号 + channel（内核 fd），走 FF_KERNEL_EVENT 内核路径；worker 的 epoll 混挂控制 fd（channel/timer）与数据 fd，正是 FF_KERNEL_EVENT 设计场景（README L180-186）。**成立，但受 §3.7 的 1/256 轮询延迟影响**。

### 4.2 HUP reload（master 不退出，换 worker）

- master 存活 → listening fd 持有不断，stack 侧 listening socket 稳定。**listening 无损成立**。
- 新 worker fork：走已验证的 fork hook 路径，可再生成 worker（每次 HUP 会令 master 再 fork 一批 worker；FF_MULTI_SC 的 scs[]/current_worker_id 继续递增，zone 内 32 sc 是容量上限——多轮 reload 的过渡期「老 worker 未退 + 新 worker 已起」会同时占用 sc，多次 reload 有耗尽风险，需压测）。
- 老 worker 退出：nginx graceful 逻辑会显式 close 连接（close hook → FF_SO_CLOSE → stack 关 socket）——**连接处理语义与内核 nginx 相同：优雅退役、非无损**。若 worker 异常死亡（未 close），stack 侧 fd 泄漏（§3.5）。sc 槽靠 refcount/detach 回收（正常退出路径有；异常退出无）。
- 结论：HUP 在该架构下行为对齐内核 nginx（listening 无损、存量连接优雅关闭），没有天然增益也没有额外损失（除 sc 容量与泄漏风险）。

### 4.3 USR2 升级二进制（新 master exec 新文件）

- **exec 未 hook 是硬缺口**（§3.2）：新 master 中 so 重新加载，`sc / scs[] / current_worker_id / worker_id / inited / fstack_kernel_fd_map` 全部归零。旧 listening fd 的数字经 exec 保留（Linux 语义），且新进程首次 socket 调用会重新 `ff_adapter_init`（RLIMIT 相同则 fd 判定一致），但 FF_MULTI_SC 的 worker→sc 映射体系完全丢失，新 master 的 fork 流程从 `current_worker_id=0` 重来。
- 有利事实：stack 进程完全不动，`ff_bound_fds` 驻留（stack 进程内存，`ff_socket_ops.c:42`）；新 master 对同地址 bind 时 `sockaddr_is_bound` 命中 → `ff_dup2(旧listening_fd, 新fd)`（L131-147）——**listening socket 在 stack 侧可被新进程代际复用**，前提是老 master 退出时不要把旧 listening fd close 掉（nginx USR2 老 master 会保留 listening 直到 QUIT；老 master QUIT 时 close → ff_sys_close 会 `sockaddr_unbind` 清表，L273——则新代际需重新真 bind，FreeBSD 栈内该端口已无 socket，时序上若新 master 已 dup 完成则无碍）。
- 已建立连接：连接 fd 本体在 stack 进程全局 FreeBSD fd 表，fd 数字跨进程有效且无 sc 归属校验（§3.6）。**理论上**新 worker 只需知道 fd 数字即可通过自己的 sc 继续读写该连接——这是该架构独有的「连接迁移潜力」。但：nginx 自身没有连接移交机制（原生 USR2 也不迁移连接，只共享 listening）；fd→connection 的 nginx 运行时状态（读缓冲、状态机）在老 worker 进程内，无法跨 exec 重建。故「连接级无损 reload」超出 nginx 原生能力，需改造 nginx（如反解 fd 表重建 connection），属于大改。
- 结论：USR2 路线在该架构下「listening 无损」有代码级支撑（ff_dup2 复用），但 exec 状态丢失使 FF_MULTI_SC/FF_KERNEL_EVENT 映射重建路径未被现有代码覆盖，需补 exec 后的恢复逻辑（或在 nginx 侧规避：USR2 前由老 master 显式传递 fd 清单）。

### 4.4 性能 / 成熟度限制（README + 代码）

- CPU 近两倍（每实例组占两核，README L15-16、L307）；8 核后短连接性能低于标准 F-Stack（L319）。
- 多 fstack 实例时不能作 client——nginx 反向代理/proxy 场景不可用（L25-29，含铁皮大爷的 RSS 改造提案）。
- ring vs sem：性能差 2-4%，官方仍推荐 sem 为生产配置、ring 留作未来多线程共享 sc / 跨进程共享 sc 场景储备（L37-39、L379）。
- pkt_tx_delay 复用作 sc 处理窗口，粗调参数（L88-92）。
- epoll_wait `timeout<=0 && ret==0` 自旋 RETRY（L2406-2410）+ yield-poll 默认策略：空闲 CPU 高（01 spec NFR-003 目标即承认此点）。
- **ring 模式下同 sc 并发无序列化**：sem 模式 `ACQUIRE_ZONE_LOCK(FF_SC_IDLE)` 自旋天然串行化同一 sc；ring 模式 submit 前清 `completion=0` 无锁（L3398），两个线程共用一个 sc 会互踩 completion——与 spec 02 §2.3 「sc 生命周期由 ring 隐式管理」的单持有者假设一致，但意味着 PIPELINE 默认模式（sc 为进程级全局、非 thread-local，`ff_hook_syscall.c:227` + `ff_socket_ops.h:27-31`）下，多线程 APP 在 ring 模式存在数据竞争风险（nginx worker 是进程不受影响；带线程池的 APP 有风险）。

## 5. 优势 / 缺口清单

### 5.1 ld_preload 路线实现 nginx 无损 reload 的「天然优势」

1. **连接与 listening socket 的所有权在 stack 进程**：所有 ff_socket/ff_accept/ff_close 在 stack 进程执行（`ff_socket_ops.c:124-275`），nginx（client）重启不触碰网络协议栈状态——client 生命周期与连接生命周期解耦，是该路线最核心的结构优势（即 [01](01-vpp-vcl-research.md) §6.2 基线 2「队列/收包所有权与业务进程解耦」的同构形态）。
2. **fd 无进程归属**：fd 数字在 stack 实例的 FreeBSD fd 表内全局有效，ff_sys_* 直接以 args->fd 执行、无 sc 归属校验（§3.6）——连接跨进程迁移只需传递 fd 数字，无需 SCM_RIGHTS 类内核 fd 传递。
3. **stack 进程对 nginx 重启零感知**：fstack 独立进程 + 全部 IPC 状态（zone/sc/ring）在 Hugepage 共享内存（`ff_so_zone.c:66-157`），nginx 整体重启不影响 stack 侧数据结构。
4. **listening socket 跨代际复用有现成机制**：stack 侧 `ff_bound_fds` + `ff_dup2`（`ff_socket_ops.c:131-147`），新 master bind 同地址可挂回旧 listening socket。
5. **fork 已完整支持且经 nginx 验证**：FF_MULTI_SC + FF_USE_THREAD_STRUCT_HANDLE 的 fork 路径（`ff_hook_syscall.c:2426-2496`）即按 nginx reuseport 工作流设计（README L188-201）。
6. **控制面自动落内核**：FF_KERNEL_EVENT 让 nginx channel/timer 等控制 fd 保持内核语义（L2324-2345），reload 控制行为与内核 nginx 一致，无需适配。
7. **sc refcount 支持父子共享**（L2447 + `ff_so_zone.c:244-256`）：master fork worker 不额外消耗新 sc（共享计数），过渡期容量压力小于每 worker 独占。

### 5.2 「缺口清单」

1. **exec 未 hook**（§3.2/§4.3）：USR2 升级后 so 内全部状态丢失，FF_MULTI_SC scs[]/current_worker_id、FF_KERNEL_EVENT fd 映射表无法重建——无损升级二进制的最大硬缺口。
2. **client 异常退出无回收**（§3.5）：kill -9 后 sc 槽永久泄漏（32 上限）、stack 侧连接 fd 永不关闭；无心跳/监控/孤儿回收机制。
3. **client 退出 ≠ 连接关闭**：detach 只还 sc 槽（`ff_so_zone.c:229-264`）；存量连接要求 APP 退出前显式 close，否则泄漏——「连接保活等新 worker 接手」目前没有任何代码路径支撑，只有理论潜力（优势 2 的反面）。
4. **ring wait_mode 不可运行时配置**（§2.3 偏差一）：spec 承诺的 FF_RING_WAIT_MODE 未实现，eventfd 低 CPU 模式无法在线启用。
5. **ring 模式同 sc 多线程竞争**（§4.4 末条）：PIPELINE 默认模式 sc 为进程级共享，ring 路径无串行化，多线程 APP 有正确性风险（nginx 多进程模型不受影响）。
6. **FF_KERNEL_EVENT 内核 epoll 1/256 轮询**（L2333-2345）：控制面事件延迟放大，reload 期间 channel 事件（如 worker 退出通知）响应变慢，需实测量化。
7. **sc 容量 32/实例**（`ff_socket_ops.h:45`）：reload 过渡期双代 worker 并存 + FF_MULTI_SC 顺序占用 scs[]，频繁 reload 的 sc 耗尽风险未评估。
8. **多实例不能作 client**（README L25-29）：nginx 若做 proxy（含健康检查主动连接 upstream）在多实例部署下不可用。
9. **成熟度**：进程退出内存泄漏/死锁风险官方在案（README L22）；sendmsg/readv 族未重度验证（L23）；ring 路线官方定位仍是「储备」而非推荐生产配置（L379）。
10. **spec C-005 的 ring 残留清理未实现**（§2.3 偏差三）：v3.3 D2 后实际影响小，但与设计文档不一致。

## 6. 未坐实清单（静态分析无法定论，需运行时验证或补读）

1. **ff_adapter_child_process_init 固定 attach zone 0**（`ff_hook_syscall.c:3338`：`ff_attach_so_context(0)`，而该函数在 FF_MULTI_SC 下会 `ff_so_zone = ff_so_zones[0]`，`ff_so_zone.c:165-167`）与 FF_MULTI_SC fork 前切到 `current_worker_id` zone（L2434-2435）的交互：子进程 sc 变量被 zone-0 新 sc 覆盖后，`scs[current_worker_id].sc` 继承值与实际使用值是否一致，静态读码存疑，需运行时打日志核实（对 nginx fork 流程正确性有直接影响）。
2. USR2 场景新 master 重新 bind 同地址时，老 master 是否已 close 旧 listening fd（决定 `ff_bound_fds`/ff_dup2 复用是否成立）——取决于 nginx USR2 时序与 stack 侧 unbind 时序，需实测。
3. FF_KERNEL_EVENT 下 fd 映射表在 fork 继承后的行为（master 的 map 被所有 worker 继承，各自 close 时 L1875-1883 的 map 清理跨进程是否互踩）。
4. `FF_PROC_ID` 环境变量在 nginx 场景的实际使用方式（README L421-429 提到但 nginx 部署章节只用 FF_NB_FSTACK_INSTANCE，L280-282）；exec 后该环境变量是否仍在。
5. 多轮 HUP reload 下 scs[]/zone 占用的实测曲线（缺口 7 的量化）。
6. 03-interface-spec.md / 04-test-spec.md / ld_preload_ring_support.md / ring_ipc_perf_offline_analysis.md 未读，可能含 sc 共享与容量设计的补充约束。
7. `ff_adapt_user_thread_add/exit`（lib 侧）的 fd 表复制完整语义（本轮只看了 adapter 层调用点，未深入 ff_adapt_user_proc/thread 实现）。
8. epoll_wait 的 kevent 封装在多 accept/multi_accept 下的边缘行为（README L138 提到有差异，未逐条核实 ff_epoll 实现）。
