# 调研材料 C：生命周期 / 配置 / KNI-IPC 归属 / issue #430 佐证

> 维度：**库内原生单进程多线程多栈实例（share-nothing）** 的生命周期与配置侧现状与扩展点。
> 原则：只读不改，所有结论给 `file:line`，不一致以代码为准。
> 代码基线：`/data/workspace/f-stack/`（FreeBSD 15.0 升级后当前树）。

---

## 0. 一句话现状（客观记录，非结论落点）

当前 f-stack 的多实例模型是「**一进程 = 一 lcore = 一栈实例**」，多实例靠 **DPDK primary/secondary 多进程 + fork** 实现（`config.ini` 一份、每进程 `-p proc_id` 不同）。库内**尚无**「一个进程内 N 个 pthread 各跑独立栈实例」的原生运行模式。adapter 路线（`adapter/syscall/`）是**应用侧** LD_PRELOAD 适配，与「栈侧原生多线程运行模型」是两个层面（见 §4）。

---

## 1. 配置层现状与 thread 模式扩展点

### 1.1 数据结构（`lib/ff_config.h`）

`struct ff_config.dpdk`（`ff_config.h:269-328`）关键字段：

| 字段 | 行号 | 含义 |
|---|---|---|
| `char *proc_type` | `ff_config.h:272` | DPDK 进程类型字符串（primary/secondary/auto） |
| `char *lcore_mask` | `ff_config.h:274` | 全局启用的 lcore 掩码（hex） |
| `char *proc_mask` | `ff_config.h:276` | 当前 proc 在所有 lcore 上的掩码（由 proc_id 推导，见 §1.2） |
| `int nb_procs` | `ff_config.h:290` | 进程总数（= lcore_mask 中置位 bit 数，见 §1.2） |
| `int proc_id` | `ff_config.h:291` | 当前进程序号（`0..nb_procs-1`） |
| `uint16_t *proc_lcore` | `ff_config.h:311` | proc_id → lcore_id 映射数组（`parse_lcore_mask` 填充） |

**关键观察**：整个结构里没有任何「线程数 / thread 模式」字段。`nb_procs`/`proc_id`/`proc_lcore[]` 语义完全是「进程」维度，且被 `ff_dpdk_if.c` 大量当作「实例数 / 实例序号」直接复用（见 §3.1）。这是 thread 模式扩展的第一落点。

### 1.2 lcore_mask → nb_procs 推导（`lib/ff_config.c:73-142` `parse_lcore_mask`）

- `parse_lcore_mask()`（`ff_config.c:73`）逐 hex 位扫描 `lcore_mask`：
  - 每遇到一个置位 bit（`ff_config.c:116-128`），把该 bit 对应的 lcore idx 记入 `proc_lcore[count]`，`count++`；
  - 当 `proc_id == count` 时（`ff_config.c:119-126`），据该 lcore idx 生成本进程专属 `proc_mask`（`-c` 掩码，只点亮自己那一个 lcore）；
  - 结束时 `cfg->dpdk.nb_procs = count`（`ff_config.c:139`），即 **nb_procs = lcore_mask 中置位 bit 数**；
  - `proc_id >= count` 直接判错返回（`ff_config.c:136-137`）。
- **语义**：lcore_mask 里点亮 M 个 bit ⇒ M 个进程，每进程占 1 个 lcore，`proc_mask` 只让本进程看见自己那颗核。这是「多进程 share-nothing」的分核基石。

### 1.3 proc_type 校验（`lib/ff_config.c:1312-1321`）

- 未指定时默认 `"auto"`（`ff_config.c:1312-1314`）；
- 只接受 `primary` / `secondary` / `auto`，否则报 `invalid proc-type` 返回 -1（`ff_config.c:1316-1321`）。
- `proc_id` 越界（`> RTE_MAX_LCORE`）时降级为 0（`ff_config.c:1323-1326`）。

### 1.4 `--proc-type=` 拼接进 EAL argv（`lib/ff_config.c:1167-1170`）

- 在组装传给 `rte_eal_init` 的 `dpdk_argv` 时（`dpdk_args()`），把 `cfg->dpdk.proc_type` 拼成 `--proc-type=xxx`（`ff_config.c:1167-1170`）；
- 同处 `proc_mask` 拼成 `-c<proc_mask>`（`ff_config.c:1151-1154`），即**每进程只把自己那颗 lcore 传给 EAL**。这正是「一进程一 lcore」的落地点。

### 1.5 KNI primary-only 配置校验（`lib/ff_config.c:1392-1412`）

- 在 `ff_check_config()` 里（`ff_config.c:1332`），当 `kni.enable && proc_type=="primary"`（`ff_config.c:1396-1397`）时，要求 primary 的 lcore（`proc_lcore[proc_id]`，`ff_config.c:1400`）必须出现在每个端口的 `lcore_list` 中，否则报错（`ff_config.c:1406-1411`）。
- 即 **KNI 只绑定在 primary 进程/其 lcore 上**（配合 §3 运行时 primary-only 门控）。

### 1.6 thread 模式扩展点评估（新增开关、零回归策略）

> 以下为基于上述代码的**扩展点分析**，非既有实现。

**需要动的点（若引入单进程多线程 N 栈实例）：**

1. **新增开关（opt-in、默认关）**：在 `struct ff_config.dpdk`（`ff_config.h:269-328`）新增例如 `int thread_mode`（或复用 proc_type 扩一个枚举值 `"thread"`）。默认 0/关，保证不改行为。
2. **lcore_mask 语义分叉**：`parse_lcore_mask`（`ff_config.c:73-142`）当前把「置位 bit 数」等价为「进程数」。thread 模式下需让同一份 `proc_lcore[]` 映射到「同进程内 N 个 pthread」，`nb_procs`（`ff_config.c:139`）语义改为「线程数」。为零回归，建议**新增 `nb_threads` 字段**而非改写 `nb_procs` 语义，thread 模式下 `nb_procs=1`。
3. **proc_type / proc_mask / `--proc-type=` 拼接**：thread 模式下只有**单个进程**（primary，无 secondary），`proc_mask`（`ff_config.c:1151-1154`）应点亮 lcore_mask 全部 bit（让 EAL 看见 N 颗核以便 `rte_eal_mp_remote_launch` 在 N 个 lcore 各起一线程），而非当前「只点亮自己一颗」。这是与多进程模式**互斥的分叉**。
4. **proc_type 校验**（`ff_config.c:1316-1321`）：thread 模式强制 primary，需在此拒绝 `secondary`/`auto` 组合。
5. **KNI 校验**（`ff_config.c:1392-1412`）：thread 模式下 KNI 归属改为「某一个指定线程」（见 §3.4），校验逻辑需相应调整而非按 primary 进程。

**零回归策略**：
- 开关默认关；关时所有上述路径**字节级不变**（walk 现有 primary/secondary 分支）。
- thread 模式与 primary/secondary 多进程模式**互斥**（配置期校验：thread_mode=1 时 proc_type 必须 primary 且不得再 fork 多进程）。
- 建议在 §1.2 的 `nb_procs` 之外**并行新增 nb_threads**，避免污染既有多进程语义，降低回归面。

---

## 2. 生命周期入口 ff_init / ff_run

### 2.1 `ff_init`（`lib/ff_init.c:35-56`）

签名：`int ff_init(int argc, char * const argv[])`（`ff_init.c:36`）。顺序：
1. `ff_load_config(argc, argv)`（`ff_init.c:39`）—— 解析 config.ini + 命令行，填 `ff_global_cfg`；
2. `ff_dpdk_init(dpdk_argc, dpdk_argv)`（`ff_init.c:43`）—— 内部 `rte_eal_init`（`ff_dpdk_if.c:1594`）+ `init_lcore_conf` / `init_mem_pool` / `init_dispatch_ring` / `init_msg_ring` / `init_kni`（`ff_dpdk_if.c:1609-1621`）；
3. `ff_freebsd_init()`（`ff_init.c:47`，extern 声明于 `ff_init.c:33`）—— 初始化 FreeBSD 栈；
4. `ff_dpdk_if_up()`（`ff_init.c:51`）—— `ff_veth_attach` 挂端口（`ff_dpdk_if.c:2747-2761`）。

### 2.2 `ff_run`（`lib/ff_init.c:58-62`）

签名：`void ff_run(loop_func_t loop, void *arg)`（`ff_init.c:59`），仅转调 `ff_dpdk_run(loop, arg)`（`ff_init.c:61`）。

`ff_dpdk_run`（`ff_dpdk_if.c:2763-2774`）核心：
```
rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);   // ff_dpdk_if.c:2770
rte_eal_mp_wait_lcore();                                // ff_dpdk_if.c:2771
```
即 **在所有 EAL enabled lcore 上启动同一个 `main_loop`**。当前多进程模式下每进程只把自己那 1 颗 lcore 传给 EAL（§1.4），所以 `mp_remote_launch` 实际只跑 1 个 loop。

### 2.3 当前调用次数与位置（`example/main.c`）

- helloworld 在 `main()` 里调用一次 `ff_init(argc, argv)`（`example/main.c:128`），一次 `ff_run(loop, NULL)`（`example/main.c:217`）。
- **每个进程各自 `main()` → 各调一次 ff_init/ff_run**，靠外部脚本按 `-p 0/1/2...` 拉起 N 个进程实现多实例。

### 2.4 per-thread 各调一次 ff_init/ff_run 的可行性与 API 兼容性评估

> 扩展点分析，非既有实现。

- **API 签名兼容**：`ff_init`（`ff_init.c:36`）/`ff_run`（`ff_init.c:59`）签名本身不含进程/线程标识，无需改签名即可被多个 pthread 各调一次 —— **API 层面兼容**。
- **主要障碍是全局单例状态**（本 agent 定位，与 explorer-globalstate 维度衔接）：
  - `rte_eal_init`（`ff_dpdk_if.c:1594`）**全进程只能调用一次**——per-thread 各调一次会二次 init 失败。故 EAL/lcore 分配必须在 ff_init 里做「只初始化一次 + 每线程绑一 lcore」的改造，不能简单地每线程整份 ff_init。
  - `lcore_conf`（`ff_dpdk_if.c:123`）是**全局单一实例**（非 `__thread`），`main_loop` 里 `qconf = &lcore_conf` 被所有 launch 的 lcore 共享——多线程下必须改为 **per-lcore/per-thread 数组或 `RTE_PER_LCORE`**，否则多栈实例互踩。
  - `veth_ctx[RTE_MAX_ETHPORTS]`（`ff_dpdk_if.c:179`）全局单例、`ff_global_cfg` 全局单例——同理需要 per-instance 化。
  - `pcurthread`（`ff_api.h:55`，`extern __thread struct thread *pcurthread`）**已是线程局部**，且已存在 `ff_switch_curthread`/`ff_restore_curthread`/`ff_adapt_user_thread_add`（`ff_api.h:481-487`）这类线程上下文 API —— 说明 FreeBSD 侧 curthread 已具备 per-thread 承载能力，是可复用的正向信号。
- **结论倾向**：`ff_run` per-thread 各跑一个 `main_loop` 在**接口层可行**（`rte_eal_mp_remote_launch` 本就是「每 lcore 一线程跑 main_loop」的语义，见 `ff_dpdk_if.c:2770`），真正阻力在于 §3.1 罗列的全局单例状态必须先 per-instance 化。建议的原生形态是：**ff_init 只调一次（完成 EAL + N 份 per-lcore 实例状态），由 `rte_eal_mp_remote_launch` 天然在 N 个 lcore 各跑一份 main_loop**，而非「每 pthread 手动再调一次完整 ff_init」。

---

## 3. KNI / IPC / 工具链归属

### 3.1 全局单例状态清单（KNI/IPC 相关，本 agent 定位）

| 变量 | 行号 | 单例性 | 多线程影响 |
|---|---|---|---|
| `struct lcore_conf lcore_conf` | `ff_dpdk_if.c:123` | **全局单一，非 __thread** | 多栈实例致命共享点 |
| `veth_ctx[RTE_MAX_ETHPORTS]` | `ff_dpdk_if.c:179` | 全局单例 | 端口→实例映射需 per-instance |
| `msg_ring[]`（IPC） | `ff_dpdk_if.c:649-667` | 按 nb_procs 建 ring 数组 | 语义随 nb_procs，thread 模式需按线程建 |

### 3.2 KNI 运行时 primary-only 门控

- `ff_kni_init`（`ff_dpdk_kni.c:376-420`）：`kni_stat` 全局部分仅 `RTE_PROC_PRIMARY` 分配（`ff_dpdk_kni.c:379-386`）；`kni_rp`/`tcp_port_bitmap`/`udp_port_bitmap` 按 `rte_lcore_id()` 命名（`ff_dpdk_kni.c:388-419`）——即 KNI ring 已带 lcore 维度。
- `ff_kni_alloc`（`ff_dpdk_kni.c:422-449+`）：`kni_stat[port_id]` 分配同样 primary-only（`ff_dpdk_kni.c:426`）。
- 主循环 KNI 处理（`ff_dpdk_if.c:2660-2664`）：`#ifdef FF_KNI` 下仅当 `enable_kni && rte_eal_process_type()==RTE_PROC_PRIMARY` 才调 `ff_kni_process`。
- 配置校验（`ff_config.c:1392-1412`，见 §1.5）：KNI 要求 primary lcore 在每端口 lcore_list。

### 3.3 IPC / 工具链对 secondary 的依赖（`tools/`）

- `tools/compat/ff_ipc.c`：`ff_ipc_init`（`ff_ipc.c:54-80`）**硬编码 `--proc-type=secondary`**（`ff_ipc.c:67`）+ `-c1`（`ff_ipc.c:66`），通过 `rte_mempool_lookup(FF_MSG_POOL)`（`ff_ipc.c:77`）找到 primary 建好的消息池，用 `ff_proc_id`（`ff_ipc.c:42`，由 `ff_set_proc_id` 设，`ff_ipc.c:44-52`）选择目标进程的 ring。
- 即 **sysctl/netstat/ifconfig/ipfw/ndp/route/arp/ngctl 等工具**（`tools/` 各子目录）都以 **secondary 进程** attach 进 primary 的共享内存、经 `msg_ring`（`ff_dpdk_if.c:649-667` 建、`process_msg_ring` `ff_dpdk_if.c:2278`/`2699` 消费、`handle_msg` `ff_dpdk_if.c:2225` 处理）与目标栈实例通信。工具链**强依赖多进程 secondary 模型**。

### 3.4 KNI / 工具归属结论（本 agent 结论）

> 扩展点分析。

- **KNI 归属**：原生多线程 share-nothing 下，KNI 不再有「primary 进程」概念，应**由单一指定线程（例如线程 0 / instance 0）独占持有** KNI 资源与 `ff_kni_process`。现有 `kni_rp`/bitmap 已按 `rte_lcore_id()` 命名（`ff_dpdk_kni.c:388-419`），天然可 per-lcore；但 `kni_stat` 全局 + 运行时 `RTE_PROC_PRIMARY` 门控（`ff_dpdk_if.c:2661`、`ff_dpdk_kni.c:379/426`）需改为「按 owner-thread 判定」而非 `rte_eal_process_type()`。配置校验（`ff_config.c:1396-1411`）需从「primary lcore」改判「KNI owner 线程的 lcore」。
- **工具链/IPC 归属**：thread 模式下**没有 secondary 进程**，现有基于 `--proc-type=secondary`（`ff_ipc.c:67`）的工具链**不可直接复用**。需要新的 IPC 通道（例如 primary 进程内暴露一个可被外部 secondary attach 的兼容层，或改工具走 unix socket / 共享内存直连指定线程的 msg_ring）。这是 thread 模式最大的工具链兼容缺口，建议 spec 明确列为「thread 模式下工具链需单独设计」。

---

## 4. issue #430 应用侧佐证核验（仅佐证，非结论落点）

核验 SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC 组合标志位处理：

- 常量映射：`LINUX_SOCK_CLOEXEC = LINUX_O_CLOEXEC`（`ff_syscall_wrapper.c:220`）、`LINUX_SOCK_NONBLOCK = LINUX_O_NONBLOCK`（`ff_syscall_wrapper.c:221`）。
- `linux2freebsd_socket_flags`（`ff_syscall_wrapper.c:672-684`）：分别把 `LINUX_SOCK_NONBLOCK`→`SOCK_NONBLOCK`（`:675-678`）、`LINUX_SOCK_CLOEXEC`→`SOCK_CLOEXEC`（`:679-682`），返回转换后 flags（`:683`）。**两个高位标志都正确转换，处理完备。**
- `ff_socket` type 转换（`ff_syscall_wrapper.c:943`）：`sa.type = linux2freebsd_socket_flags(type)`，在此之前已剥离 `SOCK_KERNEL|SOCK_FSTACK`（`:939`）——即 type 里的 NONBLOCK/CLOEXEC 组合位经统一转换后交给 `sys_socket`（`:945`）。**SOCK_STREAM 主类型不受影响，附加标志正确处理。**
- `ff_accept4`（`ff_syscall_wrapper.c:1679`）：`kern_accept4(curthread, s, pf, linux2freebsd_socket_flags(flags), &fp)`——accept4 的 flags 同样经 `linux2freebsd_socket_flags` 转换，NONBLOCK/CLOEXEC 组合位处理完备。

**佐证结论**：应用侧通过 `ff_socket`/`ff_accept4` 传入 `SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC` 组合标志的转换路径**完备**，说明「**应用侧多线程调 API 已就绪**」（多线程 server 常用 accept4+NONBLOCK+CLOEXEC 模式可正常工作）。

**层面区分（重要）**：#430 佐证的是**应用侧 API 就绪度**（app 多线程能正确调用 socket 层），与本调研的核心「**栈侧原生多线程运行模型**」（一进程内 N 个 pthread 各跑独立 FreeBSD 栈实例、share-nothing）是**两个不同层面**。前者已就绪不等于后者已实现——后者的真正阻力在 §2.4 / §3.1 的全局单例状态（`lcore_conf` `ff_dpdk_if.c:123` 等）与 §3.4 的 KNI/工具链归属重构。

---

## 5. 关键发现汇总（供 leader 收敛）

1. **thread 模式扩展点**：配置结构（`ff_config.h:269-328`）无任何线程字段；`nb_procs`/`proc_id` 是「进程」语义且被当「实例」复用。建议**新增 `nb_threads`（不改 `nb_procs` 语义）+ 新增 opt-in 开关默认关**，thread 模式与 primary/secondary 多进程**互斥**，动 `parse_lcore_mask`（`ff_config.c:73-142`）/`proc_mask` 拼接（`ff_config.c:1151-1154`）/proc_type 校验（`ff_config.c:1316-1321`）/KNI 校验（`ff_config.c:1392-1412`）。零回归靠开关默认关 + 现有分支字节不变。
2. **ff_run per-thread 可行性**：API 签名（`ff_init.c:36`/`:59`）兼容，`rte_eal_mp_remote_launch(main_loop,...)`（`ff_dpdk_if.c:2770`）本就是「每 lcore 一线程跑 main_loop」语义 —— 原生形态应是 **ff_init 只调一次（EAL+N 份 per-lcore 实例）**，而非每 pthread 各调整份 ff_init（`rte_eal_init` `ff_dpdk_if.c:1594` 全进程只能一次）。真正阻力是全局单例 `lcore_conf`（`ff_dpdk_if.c:123`，非 __thread）、`veth_ctx`（`:179`）、`ff_global_cfg` 需 per-instance 化。正向信号：`pcurthread` 已是 `__thread`（`ff_api.h:55`）且有线程上下文 API（`ff_api.h:481-487`）。
3. **KNI 归属结论**：thread 模式下 KNI 应**由单一指定线程独占持有**；现有 KNI ring 已按 `rte_lcore_id()` 命名（`ff_dpdk_kni.c:388-419`）可 per-lcore，但 `kni_stat` 全局 + `RTE_PROC_PRIMARY` 运行时门控（`ff_dpdk_if.c:2661`、`ff_dpdk_kni.c:379/426`）与配置校验（`ff_config.c:1396-1411`）需从「primary 进程」改判「KNI owner 线程」。
4. **工具链/IPC 缺口**：`tools/` 全链路强依赖 `--proc-type=secondary`（`ff_ipc.c:67`）+ `msg_ring`（`ff_dpdk_if.c:649-667`）；thread 模式无 secondary 进程，工具链**不可直接复用**，需单独设计 IPC 通道 —— 建议 spec 明确列为独立子项。
5. **#430 定位**：`linux2freebsd_socket_flags`（`ff_syscall_wrapper.c:672-684`）对 NONBLOCK/CLOEXEC 组合位处理**完备**，`ff_socket`（`:943`）/`ff_accept4`（`:1679`）均经此转换；佐证「**应用侧多线程调 API 已就绪**」，与「栈侧原生多线程运行模型」是**两个层面**，不作本轮结论落点。
