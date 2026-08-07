# 15 worker 时钟缺口修复与 virtio RSS 限制

> **文档编号**：SPEC-NMT-15
> **版本**：v1
> **日期**：2026-08-03
> **状态**：H1（worker 时钟缺口）已定位并修复，实测生效。
> **⚠️ 结论已被纠偏（2026-08-03）**：本文第 5 节「2 线程吞吐受限的最终瓶颈是 virtio PMD 不支持 RSS/RETA（环境限制，非代码缺陷）」**已被实测推翻**，请以 `16-多队列对照实验与根因纠偏.md` 为准。
> **实证铁律**：本文所有计数、req/s、backtrace 均来自实际运行输出，禁止臆造。

---

## 0. 纠偏声明（2026-08-03 追加）

本文第 5 节与第 9 节关于「virtio 无 RSS 导致多队列失效」的结论**不成立**，原因是本文的对照实验缺失了关键一组：**`thread_mode=0` + 2 进程 2 队列**。

16 号文档补做该实验后实测：

| 配置 | 队列数 | req/s |
|---|---|---|
| `thread_mode=0`，1 进程 | 1 | 206,963 |
| **`thread_mode=0`，2 进程** | **2** | **231,570**（正常） |
| `thread_mode=1`，2 线程 | 2 | 0（不通） |

即 virtio 双队列在**完全相同的"无 RSS"代码路径**下工作正常且吞吐更高。本文错误地把「1 队列 vs 2 队列」的差异归因为「进程模式 vs 线程模式」。

真实根因是两个代码缺陷（详见 16 号文档）：
1. **R1**：worker cred 挂全局 `prison0`，而 socket 的 vnet 取自 `CRED_TO_VNET(cred)` 而非 `curvnet`（`freebsd/kern/uipc_socket.c:948`）→ worker 所有 socket / `ifioctl` 被静默重定向到 vnet0。
2. **R2**：worker `pcpu_init()` 传 `rte_lcore_id()` 作 cpuid，但本build 非 SMP（`MAXCPU==1`）→ `zpcpu_get()` 越界。

修复后 `thread_mode=1` 双线程达~233k req/s（与 2 进程 ~234k 持平），60 秒 400 连接 soak 达 497k req/s。

**因此本文第 9 节「这是环境约束，代码侧已无可修之处」的表述亦属错误。**

---

## 1. 本轮起点

14 号文档结论：per-vnet 隔离（每 worker 独立 `vnet_alloc()` + 独立 ifp）已消除 `in_pcblookup_mbuf` crash，但 2 线程吞吐塌陷至 91.39 req/s，而 1 线程为 209,388 req/s。本轮定位该性能塌陷的根因。

---

## 2. 根因 H1：worker 线程的 FreeBSD 时钟从未被驱动

### 2.1 代码证据链

| 环节 | 位置 | 事实 |
|---|---|---|
| 定时器是线程私有 | `lib/ff_dpdk_if.c:92` | `static __thread struct rte_timer freebsd_clock;` |
| 注册函数 | `lib/ff_dpdk_if.c:1181-1196` | `init_clock()` 内 `rte_timer_init(&freebsd_clock)` + `rte_timer_reset(..., rte_lcore_id(), &ff_hardclock_job, NULL)` |
| 唯一注册调用点 | `lib/ff_dpdk_if.c:1722` | `init_clock()` 仅在 `ff_dpdk_init()`（主线程）中调用一次 |
| worker 初始化路径 | `lib/ff_freebsd_init.c:110-149` | `ff_stack_thread_init()` 只做 pcpu/thread/callwheel/vnet，**无任何 `rte_timer_*` 注册** |
| 数据面判定 | `lib/ff_dpdk_if.c:2679-2680` | `if (freebsd_clock.expire < cur_tsc) rte_timer_manage();` |
| callwheel 是线程私有 | `lib/ff_kern_timeout.c:183-185` | `__thread struct callout_cpu cc_cpu;`，`CC_SELF()` 返回本线程实例 |
| tick 推进 | `lib/ff_kern_timeout.c:339-349` | `callout_tick()` 用 `cc = CC_SELF()` 推进本线程 `cc_softticks` |

DPDK 侧关键语义：`rte_timer_manage()` 只处理**注册在当前 lcore 上**的定时器（`dpdk/lib/timer/rte_timer.c:674-686`，per-lcore `pending_head` 为空时直接返回）。

**推论**：worker 的 `freebsd_clock` 是零初始化 TLS（`expire == 0`），`0 < cur_tsc` 恒真使 `rte_timer_manage()` 每轮被调用，但该 lcore 上没有注册任何定时器 → `ff_hardclock_job` 永不触发 → worker 的 `cc_cpu` callwheel 永不推进 → vnet_i 上 syncache 超时、TCP 重传、delayed ACK、keepalive、TIME_WAIT 回收全部瘫痪。

### 2.2 实测验证（修复前）

探针统计 `ff_hardclock_job` 每 lcore 触发次数，每 5 秒打印：

```
DBG CLK lcore=1 hardclock=501  expire=7142589130052176
DBG CLK lcore=2 hardclock=0    expire=0
DBG CLK lcore=1 hardclock=1001 expire=7142602110052176
DBG CLK lcore=2 hardclock=0    expire=0
DBG CLK lcore=1 hardclock=1501 expire=7142615090052176
DBG CLK lcore=2 hardclock=0    expire=0
DBG CLK lcore=1 hardclock=2001 expire=7142628070052176
DBG CLK lcore=2 hardclock=0    expire=0
```

- lcore=1（DPDK master lcore，主线程，vnet0）：每 5 秒 +500，即 100Hz，正常
- lcore=2（worker，vnet_2）：**hardclock 恒为 0，expire 恒为 0**

H1 由实测坐实。

---

## 3. 修复方案（数据面零锁）

### 3.1 核心约束

修复必须满足：worker 推进自己的 callwheel，但**不得**触碰全局共享时间基准，否则 N 个线程同时推进会使时间前进 N 倍。

需要保护的全局状态：

| 全局状态 | 位置 | 若被多线程 tick 的后果 |
|---|---|---|
| `volatile int ticks` | `lib/ff_glue.c:132` | `atomic_add_int(&ticks,1)` 被 N 线程执行 → ticks 前进 N 倍 → 所有基于 ticks 的超时提前 N 倍触发 |
| `static long count` + `tc_windup()` | `freebsd/kern/kern_tc.c:1923-1935` | timecounter 推进倍速，系统时间失真 |
| `static struct timespec current_ts` | `lib/ff_host_interface.c:64` | 多线程并发写同一 timespec |

### 3.2 实施内容

**`lib/ff_kern_timeout.c`** — 新增 worker 专用时钟入口：

```c
/*
 * Worker-thread clock: only advances this thread's own callwheel (cc_cpu is
 * __thread). Global `ticks` and the timecounter stay owned by the main thread,
 * otherwise N threads ticking them would make the shared time base run N times
 * too fast and break every ticks-based timeout.
 */
void
ff_hardclock_worker(void)
{
    callout_tick();
}
```

对比主线程版 `ff_hardclock()`（保持不变，此处省略末尾未启用的 `#ifdef DEVICE_POLLING` 块）：

```c
void
ff_hardclock(void)
{
    atomic_add_int(&ticks, 1);
    callout_tick();
    tc_ticktock((hz + 999)/1000);
    cpu_tick_calibration();
}
```

**`lib/ff_dpdk_if.c`** — 新增 worker 定时器回调与注册函数：

```c
static void
ff_hardclock_worker_job(__rte_unused struct rte_timer *timer,
    __rte_unused void *arg) {
    ff_hardclock_worker();
}

/* Register this worker's own freebsd_clock (a __thread rte_timer) on its own
 * lcore, so main_loop's rte_timer_manage() can drive its per-thread callwheel.
 * The DPDK timer subsystem is already initialized by the main thread. */
static void
init_clock_worker(void)
{
    uint64_t hz = rte_get_timer_hz();
    uint64_t intrs = US_PER_S / ff_global_cfg.freebsd.hz;
    uint64_t tsc = (hz + US_PER_S - 1) / US_PER_S * intrs;

    rte_timer_init(&freebsd_clock);
    rte_timer_reset(&freebsd_clock, tsc, PERIODICAL,
        rte_lcore_id(), &ff_hardclock_worker_job, NULL);
}
```

`main_loop()` 中的调用点（`ff_stack_thread_init()` 之后、`while(1)` 之前）：

```c
    if (ff_global_cfg.dpdk.thread_mode) {
        unsigned lcore = rte_lcore_id();
        if (freebsd_clock.expire == 0)
            init_clock_worker();
        ...
    }
```

`freebsd_clock.expire == 0` 精确区分主线程与 worker：主线程已在 `init_clock()` 中 reset 过（expire 非零）故跳过，worker 的 TLS 为零故注册。

**`lib/ff_api.symlist`** — 新增 `ff_hardclock_worker`，避免被 objcopy localize 导致链接失败。

### 3.3 数据面零锁论证

- `while(1)` 循环体位于 `lib/ff_dpdk_if.c:2672-2826`，全文件仅 3 处锁操作（`:191` 定义、`:2657` lock、`:2659` unlock），**全部在循环体之外**
- `init_clock_worker()` 调用点在 `:2651-2652`，属初始化路径
- `freebsd_clock` 是 `__thread`、绑定本 lcore，`rte_timer_reset` 无跨线程竞争，无需加锁
- `callout_tick()` 内的 `mtx_lock(&cc->cc_lock)` 在 f-stack 中是 no-op（`lib/include/sys/mutex.h:57-67` 全部 `DO_NOTHING`），且 `cc_cpu` 线程私有
- `callout_tick()` 是「只读全局 `ticks` + 只写线程私有 `cc_softticks`」的安全模式（`lib/ff_kern_timeout.c:342`）

### 3.4 实测验证（修复后）

```
DBG CLK lcore=1 hardclock=1001 expire=7143639270566176
DBG CLK lcore=2 hardclock=999  expire=7143639298714294
DBG CLK lcore=1 hardclock=1501 expire=7143652250566176
DBG CLK lcore=2 hardclock=1499 expire=7143652278714294
DBG CLK lcore=1 hardclock=2001 expire=7143665230566176
DBG CLK lcore=2 hardclock=1999 expire=7143665258714294
```

worker（lcore=2）hardclock 从 **0 变为与主线程同步推进**（1999 vs 2001），`expire` 已注册为非零。修复生效。

---

## 4. 其他假设的排查结论

| 假设 | 结论 | 实测依据 |
|---|---|---|
| H2：per-vnet ARP 表隔离导致网关 MAC 无法解析 | **排除** | client 清空 ARP 缓存后，探针显示 `arp=1` 在**两个 lcore 都收到**，`lib/ff_dpdk_if.c:2031-2061` 的 ARP/NDP 跨 queue 克隆机制正常工作 |
| H3：`ff_veth_set_gateway` 在 worker vnet 失败 | **排除** | 探针 `setaddr_count=2`（两个 vnet 都配置了 IP），`ifaddr[0]=0x21f4c4a0`（vnet0）、`ifaddr[1]=0x7fe2204836f0`（vnet_2）均非 NULL，日志无 `setaddr failed`/`set_gateway failed` |
| H4：worker 时间基准停滞 | **与 H1 同源**，已随 H1 修复 | 见 3.4 |

---

## 5. ~~最终瓶颈：virtio PMD 不支持 RSS/RETA（环境限制）~~【本节结论已被推翻，见第 0 节与 16 号文档】

### 5.1 现象

时钟修复后 2 线程吞吐从 91.39 req/s 提升至 557.34 req/s（6 倍），但仍远低于 1 线程的 ~209k req/s。

### 5.2 实测定位

client 侧 tcpdump（wrk 期间）：

```
13:42:15.912247 IP <CLIENT_IP>.33858 > <DPDK_NIC_IP>.80: Flags [S], seq 3566723268, ...
13:42:16.929338 IP <CLIENT_IP>.33858 > <DPDK_NIC_IP>.80: Flags [S], seq 3566723268, ...
13:42:17.953339 IP <CLIENT_IP>.33858 > <DPDK_NIC_IP>.80: Flags [S], seq 3566723268, ...
13:42:18.977337 IP <CLIENT_IP>.33858 > <DPDK_NIC_IP>.80: Flags [S], seq 3566723268, ...
13:42:20.001348 IP <CLIENT_IP>.33858 > <DPDK_NIC_IP>.80: Flags [S], seq 3566723268, ...
13:42:21.025330 IP <CLIENT_IP>.33858 > <DPDK_NIC_IP>.80: Flags [S], seq 3566723268, ...
6 packets captured
```

client 反复重传同一个 SYN，f-stack 从未回 SYN-ACK。

RX 层探针（区分「到网卡」与「进协议栈」）：

```
=== before wrk ===
DBG CLK lcore=1 hardclock=2001 arp=0 rxburst=3  vethin=3
DBG CLK lcore=2 hardclock=1999 arp=0 rxburst=12 vethin=12
=== after wrk (t1 -c4 -d5s) ===
DBG CLK lcore=1 hardclock=3500 arp=0 rxburst=9  vethin=9
DBG CLK lcore=2 hardclock=3498 arp=0 rxburst=23 vethin=23
```

wrk 期间 `rxburst` 仅增加 6+11=17 个包，且 `rxburst == vethin`（到达的包全部进了协议栈，协议栈未丢包）。**SYN 根本没到达 DPDK 网卡**。

### 5.3 根因

网卡为 virtio：

```
0000:00:09.0 'Virtio network device 1000' drv=igb_uio unused=
```

`lib/ff_dpdk_if.c:1009-1016` 仅在 `dev_info.reta_size` 非零时打印 `port[%d]: rss table size: %d` 并记录 `rss_reta_size[port_id]`。实测 ff_log 中**完全没有该输出**，据此判定 `dev_info.reta_size == 0`，即 **virtio PMD 不提供 RSS/RETA 能力**。

多队列配置下（2 队列，`dispatch_ring_p0_q0` / `dispatch_ring_p0_q1` 均创建成功），virtio 无法按流哈希把包分发到正确队列，TCP 连接无法建立。单队列（1 线程）不受影响。

**这是虚拟网卡环境限制，非 f-stack 代码缺陷**。ICMP 单包偶尔能通（ping 0% 丢包）但 TCP 连接建立需要稳定的双向队列一致性，故 wrk 失败。

---

## 6. 性能基线实测数据

压测命令：`ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://<DPDK_NIC_IP>:80/"`，trial 间隔 30 秒。

### 6.1 thread_mode=1（native-mt）

| 线程数 | lcore_mask | Trial 1 | Trial 2 | Trial 3 | 均值 | Latency avg | 说明 |
|---|---|---|---|---|---|---|---|
| 1 | 2 | 208,092 | 212,124 | 209,155 | **209,790** | 451-461us | 单队列，正常 |
| 2 | 6 | 557 | 0 | — | — | 519us | virtio 无 RSS，多队列失效 |

1 线程 3 次 trial 波动 <2%，数据稳定。

### 6.2 thread_mode=0（多进程）零回归对照

| 配置 | req/s | Latency avg | 结论 |
|---|---|---|---|
| thread_mode=0, lcore_mask=2 | **216,812** | 442.56us | 与历史基线一致，本轮修复未破坏多进程模式 |

---

## 7. 本轮修改清单

| 文件 | 修改 | 性质 |
|---|---|---|
| `lib/ff_kern_timeout.c` | 新增 `ff_hardclock_worker()`（只推进本线程 callwheel） | H1 修复 |
| `lib/ff_dpdk_if.c` | 新增 `ff_hardclock_worker_job()` / `init_clock_worker()`；`main_loop` 中 worker 注册时钟 | H1 修复 |
| `lib/ff_api.symlist` | 新增 `ff_hardclock_worker` 符号导出 | H1 修复（链接需要） |
| `lib/ff_freebsd_init.c` | 清理上一轮调试 printf | 清理 |
| `lib/ff_veth.c` | 清理上一轮调试探针 | 清理 |
| `example/main.c` | 清理调试 fprintf | 清理 |

所有调试探针已彻底移除（grep `DBG `/`dbg_*` 零命中），清理后独立复测 1 线程为 208,092 req/s，与清理前同量级（208,514 req/s），确认清理未引入回归。该复测即 6.1 表中 1 线程 Trial 1。

---

## 8. 独立审核结论

由独立 reviewer（写审分离）审核，全部 PASS：

| 审核项 | 结论 | 关键证据 |
|---|---|---|
| A. 核心数据面零锁 | PASS | `while(1)` 在 `:2672-2826`，3 处锁操作（`:191`/`:2657`/`:2659`）全在循环外；mutex.h 全为 `DO_NOTHING` |
| B. 全局时间基准未被破坏 | PASS | `ff_hardclock_worker()` 不含 `atomic_add_int(&ticks)`/`tc_ticktock`/`cpu_tick_calibration`；`ff_hardclock()` 本轮未被改动（`git diff` 中 `ff_kern_timeout.c` 仅新增 worker 函数） |
| C. thread_mode=0 零回归 | PASS | `init_clock_worker()` 严格在 `thread_mode` 分支内；`init_clock()` 主线程路径未改动 |
| D. 定时器注册正确性 | PASS | tsc 算法与 `init_clock()` 逐字符相同；未重复调用 `rte_timer_subsystem_init`/`rte_timer_meta_init` |
| E. 调试代码清理彻底 | PASS | 所有 `dbg_*`/`DBG ` pattern 零命中 |
| F. vnet 隔离完整性 | PASS | `vnet_alloc` + `td_vnet` + `lo_set_defaultaddr` 完整；`veth_ctx[lcore][port]` 2D 访问完整 |

---

## 9. 遗留事项与后续方向

1. **virtio RSS 限制**：本机 virtio 网卡无 RSS 能力，无法在本环境验证 2/4 线程的真实扩展性。需在支持 RSS 的物理网卡（ixgbe/i40e/mlx5 等）上复测 2/4 线程基线。这是环境约束，代码侧已无可修之处。
2. **软件分发兜底（可选增强）**：若需在无 RSS 的虚拟网卡上支持多线程，可考虑单队列 RX + 软件按五元组哈希分发到各 worker 的 `dispatch_ring`（`lib/ff_dpdk_if.c:2100-2114` 已有消费侧机制），但这会引入跨线程 mbuf 传递，需评估对「数据面零锁」的影响，本轮未实施。
3. **per-vnet 时钟语义已自洽**：worker 独立 callwheel + 主线程独占全局 ticks 的分工在当前架构下正确。若未来主线程也变为纯 worker（无 master lcore 特殊角色），需重新设计全局 ticks 的归属。
