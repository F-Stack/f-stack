# F-Stack 原生多线程支持（native-mt）：单进程多线程多协议栈实例

## 1. 本功能主要作用和特点

F-Stack 原生多线程支持（native-mt，`thread_mode=1`）是 F-Stack v2.0（预计2026.10正式release） 引入的一种新运行模式：**在单进程内启动 N 个线程，每线程运行一份完全独立的 FreeBSD 协议栈实例**，线程间 share-nothing、无锁，靠网卡 RSS 分队列做数据面分流，靠无锁 ring 做跨线程分发。

### 核心特点

| 特点 | 说明 |
|------|------|
| **单进程多线程** | 不再启动 primary + N 个 secondary 进程，改为一个进程内 N 个 lcore 线程 |
| **多协议栈实例** | 每线程一份独立 vnet（VNET/VIMAGE 隔离），含独立 ifnet/PCB/路由表/端口分配 |
| **share-nothing 无锁** | 数据面线程间无共享可变状态，无锁竞争，线性扩展 |
| **零回归 opt-in** | `thread_mode=0`（默认）时多进程模式逐字节不变 |
| **API 向后兼容** | `ff_init`/`ff_run` 签名不变，应用无需改动即可在新模式运行 |

### 与多进程模式的对比

| 维度 | 多进程模式（默认） | native-mt 模式 |
|------|-------------------|----------------|
| 进程数 | 1 primary + N secondary | 1 个进程 |
| 线程数 | 每进程 1 个主线程 | N 个 lcore 线程 |
| 协议栈实例 | 每进程一份 | 每线程一份（VNET 隔离） |
| 共享内存 | 跨进程共享 hugepage/mempool | 同地址空间，直接访问 |
| IPC 开销 | 跨进程 `msg_ring` 通信 | 无跨进程 IPC，直接内存访问 |
| 进程管理 | 需 start.sh 管理多进程 | 单进程管理简单 |
| 容错隔离 | 进程崩溃互不影响 | 线程崩溃可能影响整个进程 |

## 2. 本功能的主要适用场景

### 2.1 单机多核部署的简化管理

多进程模型需要 `start.sh` 脚本启动 1 个 primary + N 个 secondary 进程，进程管理、信号处理、资源清理都较复杂。native-mt 模式只需启动一个进程，大幅简化部署运维。

### 2.2 减少多线程应用迁移成本

某些应用原本是多线程模式，迁移到原有的多进程 F-Stack 需要较大的迁移成本，native-mt 模式让应用在单进程内获得多核扩展能力，而不再需要 fork 或启动多个独立进程等迁移改造。

### 2.3 减少跨进程 IPC 开销

多进程模式下，某些应用的共享控制数据可能需要 IPC （如共享内存或ring等方式）才能在进行跨进程共享，native-mt 模式下这部分共享数据可直接在同进程内访问。

### 2.4 业界主流模型对齐

mTCP、Seastar 等高性能用户态网络框架普遍采用 thread-per-core + share-nothing 的单进程多线程模型。native-mt 让 F-Stack 与业界主流架构对齐。

## 3. 本功能的架构特征

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│              单进程 (thread_mode=1)                              │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  ff_init 一次初始化                                        │   │
│  │  ├─ DPDK EAL 初始化（全 bit coremask，拉 N 个 lcore）       │   │
│  │  ├─ 全局一次性 init（mi_startup / UMA / mutex）             │  │
│  │  └─ lcore_conf[RTE_MAX_LCORE] 数组分配                     │  │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                     │
│          ┌────────────────┼────────────────┐                   │
│          ▼                ▼                 ▼                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │ 线程0/lcore0  │ │ 线程1/lcore1 │ │ 线程2/lcore2  │            │
│  │              │ │              │ │              │            │
│  │ vnet_0       │ │ vnet_1       │ │ vnet_2       │            │
│  │ pcpu_0       │ │ pcpu_1       │ │ pcpu_2       │            │
│  │ callwheel_0  │ │ callwheel_1  │ │ callwheel_2  │            │
│  │ lcore_conf[0]│ │ lcore_conf[1]│ │ lcore_conf[2]│            │
│  │ RX/TX queue0 │ │ RX/TX queue1 │ │ RX/TX queue2 │            │
│  │ KNI owner    │ │              │ │              │            │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘            │
│         │                │                 │                   │
│         │    dispatch/kni_ring (MP+SC)     │                   │
│         │◄───────────────┤─────────────────┤                   │
│         │  无锁跨线程分发                    │                   │
└─────────┼────────────────┼─────────────────┼───────────────────┘
          │                │                 │
          ▼                ▼                 ▼
    ┌─────────────────────────────────────────┐
    │           DPDK NIC (RSS 分发)            │
    │  queue0 ←─ flow A                        │
    │  queue1 ←─ flow B                        │
    │  queue2 ←─ flow C                        │
    └─────────────────────────────────────────┘
```

### 3.2 per-thread 隔离策略

native-mt 的核心挑战是：FreeBSD 协议栈有数百个全局变量，如何在单进程内让每线程拥有独立副本？答案是分四类隔离：

```
┌─────────────────────────────────────────────────────────────────┐
│                    全局变量分类与隔离策略                          │
├─────────────────────┬──────────────┬───────────────────────────┤
│ 类别                │ 隔离手段      │ 理由                      │
├─────────────────────┼──────────────┼───────────────────────────┤
│ 网络栈全局           │ VNET/VIMAGE  │ FreeBSD 原生子系统，       │
│ (V_ifnet/V_tcbinfo  │ curvnet =    │ 一次启用覆盖全部；         │
│  V_rt_tables/...)   │ td_vnet      │ vnet.h per-thread         │
├─────────────────────┼──────────────┼───────────────────────────┤
│ 跨线程访问的全局      │ 数组 +       │ 跨线程可按下标访问         │
│ (lcore_conf/        │ rte_lcore_id │ （分发/统计）；            │
│  veth_ctx)          │ 索引         │ ff_dpdk_if.c              │
├─────────────────────┼──────────────┼───────────────────────────┤
│ 纯线程私有           │ __thread     │ 无跨线程访问，TLS 最快     │
│ (msg_iov_tmp/seed/  │              │ 无伪共享                  │
│  stop_loop)         │              │                           │
├─────────────────────┼──────────────┼───────────────────────────┤
│ 内核身份/定时器底座   │ 每实例一份    │ 每栈一份 pcpu/thread/     │
│ (pcpup/thread0/     │ (RTE_PER_    │ callout；                 │
│  cc_cpu)            │  LCORE)      │ ff_freebsd_init.c         │
└─────────────────────┴──────────────┴───────────────────────────┘
```

### 3.3 数据面无锁通信

跨线程通信使用 DPDK 的无锁 ring，保持多进程模式已有的语义：

```
                dispatch/kni_ring (RING_F_SC_DEQ, MP+SC)
            ┌──────────────────────────────────────────┐
            │  多生产者（MP）：任意 worker 可 enqueue     │
            │  单消费者（SC）：owner 线程 dequeue         │
            └──────────────────────────────────────────┘
                 ▲                              │
                 │ enqueue                      │ dequeue
    ┌────────────┼────────────┐                 ▼
    │            │            │          ┌──────────────┐
┌───┴───┐   ┌───┴───┐   ┌───┴───┐        │ owner thread │
│worker1│   │worker2│   │worker3│        │ (分发/处理)   │
└───────┘   └───────┘   └───────┘        └──────────────┘
```

- **dispatch/kni_ring**：保持 `RING_F_SC_DEQ`（MP+SC），多 worker 写、单 owner 读
- **msg_ring**：已数组化 `msg_ring[RTE_MAX_LCORE]`，每线程用自己 lcore 索引，SP+SC
- **mempool**：按 NUMA socket 共享，DPDK per-lcore cache 开箱 MT-safe，无需改造

## 4. 改造工作与遇到的问题

> 后续比较枯燥，不需要深入研究实现过程的可以跳过本节。

### 4.1 改造里程碑总览

native-mt 的改造按危险度递增分 8 个里程碑（CM0-CM7）：

| 里程碑 | 目标 | 危险度 | 关键 commit |
|--------|------|--------|-------------|
| CM0 | 低垂果实 + 脚手架 | 低 | `e79ceb9f0` |
| CM1 | 配置层 `thread_mode` 开关 | 低 | `3c31cc540` |
| CM2 | `lcore_conf` per-lcore 化 + DPDK 拉 N lcore | 中 | `e79ceb9f0` |
| CM3 | 底座全局 per-thread（pcpu/thread0/callout） | 高 | `e79ceb9f0` |
| CM4 | VIMAGE 可行性 PoC（关键卡点） | 高/存疑 | `86e0f76b0` |
| CM5 | 初始化重构（per-thread 栈实例 init） | 极高 | `717843004` + `7495e70c0` |
| CM6 | KNI owner 线程 + msg_ring per-thread | 中 | `6d74d59e0` |
| CM7 | 联调 + 回归 + 性能基线 | 中 | `fea49af6d` + `be4233709` |

### 4.2 CM0-CM3：per-thread 化基础

**问题1：`msg_iov_tmp` 全局变量数据错乱**

`ff_syscall_wrapper.c` 的 `msg_iov_tmp`/`msg_iovlen_tmp` 是全局数组，多线程并发调用 `ff_readv`/`ff_writev` 会互相覆盖。这是最低垂的果实——恢复 `__thread` 即可修复，多进程模式亦无害。

**问题2：`lcore_conf` 全局单例**

`ff_dpdk_if.c:123` 的 `lcore_conf` 是全局单例，30+ 引用点。改为 `lcore_conf[RTE_MAX_LCORE]` 数组，每线程用 `rte_lcore_id()` 索引自己的那份。同时引入 `ff_cur_lcore_conf()` 宏作为间接层，降低后续改动面。

**问题3：pcpu/thread0/callout 底座全局**

- `pcpup`（`ff_freebsd_init.c:69`）→ 每线程一份 `__thread struct pcpu`
- `thread0`/`proc0`（`ff_init_main.c`）→ 每实例一份
- `cc_cpu` callout（`ff_kern_timeout.c:180`）→ `__thread struct callout_cpu`，`CC_SELF()` 返回本线程实例

### 4.3 CM4：VIMAGE 可行性 PoC（关键卡点）

这是整个项目最大的不确定项。VIMAGE 是 FreeBSD 原生的虚拟网络栈子系统，启用后 `curvnet = curthread->td_vnet` 按 per-thread 隔离数百个网络栈全局。但 f-stack 大量阉割了 FreeBSD 用户态代码，VIMAGE 能否跑通需实测验证。

**PoC 结果：VIMAGE 可用（route B 验证通过）**

- `opt_global.h` 加 `#define VIMAGE 1`
- 每线程 `vnet_alloc()` 创建独立 vnet 并设 `td_vnet`
- `VNET_SYSINIT` 每 vnet 各跑一份，`V_tcbinfo`/`V_rt_tables` 成功隔离

### 4.4 CM5：初始化重构

**问题4：`mi_startup`/SYSINIT 一次性机制**

`ff_init_main.c` 的 `mi_startup` 跑完会打勾 `SI_SUB_LAST`，二次调用空转。需拆分：全局一次性 init（EAL/UMA/mutex/vnet0）+ per-thread 栈实例 init（vnet_alloc/td_vnet/VNET_SYSINIT/pcpu_i/thread0_i）。

**问题5：worker cred 挂全局 prison0（R1 缺陷）**

这是 native-mt 最隐蔽的 bug。症状：2 线程压测 0 req/s，client 反复重传 SYN，f-stack 从不回 SYN-ACK。

根因：worker 线程的 cred 挂在全局 `prison0` 上，而 FreeBSD socket 的 vnet 取自 cred 的 prison（`CRED_TO_VNET(cred)`），不是 `curvnet`。导致 worker 所有 socket/ifioctl 被静默重定向到 vnet0，worker vnet 无接口地址、无默认路由（`ENETUNREACH`），app listen 的 PCB 全建在 vnet0，而数据面在 worker vnet 查 PCB → 收到 SYN 不回 SYN-ACK。

修复：`lib/ff_freebsd_init.c` 新增 `ff_worker_prison_init()`，给每个 worker 分配独立 prison，使其 `CRED_TO_VNET` 指向自己的 vnet。

**问题6：worker pcpu cpuid 越界（R2 缺陷）**

修复 R1 后，worker vnet 的 PCB 表被真正使用，压测时 `in_pcblookup_mbuf` SIGSEGV。

根因：worker 的 `pcpu_init()` 传 `rte_lcore_id()`（=2）作 cpuid，但本 build 非 SMP（`MAXCPU==1`）、`mp_maxid==0`，UMA/SMR per-cpu 数组只按 1 CPU 分配 → `zpcpu_get()` 越界。

修复：`ff_pcpu_thread_init()` 改传 0（当时方案）。后续在文档 17 的 SMP-aware 改造中彻底修复——每线程拥有稠密、独立的 pcpu 槽位。

### 4.5 CM6-CM7：KNI/工具链归属与联调

**问题7：KNI 归属**

多进程模式下 KNI 由 primary 进程独占（virtio_user vdev 只能由 primary 创建）。native-mt 无 primary/secondary 概念，KNI 改由单一指定线程（线程 0）独占持有。现有 `kni_rp`/bitmap 已按 `rte_lcore_id()` 命名，天然可 per-lcore，改动集中在门控判定。

**问题8：worker 时钟缺口**

症状：2 线程吞吐从修复前的 0 提升到 557 req/s，但仍远低于 1 线程的 ~209k req/s。

根因：worker 线程的 FreeBSD 时钟从未被驱动。`init_clock()` 仅在主线程调用一次，worker 的 `freebsd_clock`（`__thread`）是零初始化（`expire == 0`），`ff_hardclock_job` 永不触发 → worker 的 callwheel 永不推进 → vnet_i 上 syncache 超时、TCP 重传、delayed ACK 全部瘫痪。

修复：新增 `ff_hardclock_worker()`（只推进本线程 callwheel，不触碰全局 `ticks`/timecounter）+ `init_clock_worker()`（worker 在 `main_loop` 中注册自己的定时器）。

### 4.6 后续优化：SMP-aware pcpu 视图与去全局锁

**问题9：SMR per-cpu 槽位共享的 UAF 窗口**

R2 修复后所有 worker 的 `pc_zpcpu_offset` 均为 0，共享同一份 SMR per-cpu 槽位。理论窗口：A 线程 `smr_exit` 置 `SMR_SEQ_INVALID` 可能清掉 B 线程的 read section 标记 → `smr_poll` 误判无读者 → PCB 提前回收（UAF）。

修复（commit `c7996a94f`）：定义 `SMP`，设置 `mp_ncpus`/`mp_maxid`/`all_cpus` 为 `nb_threads`，每线程拥有稠密 pcpu id 和 per-thread `curcpu`，每线程独占不相交的 UMA/SMR per-cpu 槽位。

**问题10：`uma_crit_lock` 全局自旋锁**

f-stack 曾为保护 UMA per-cpu cache 加了全局自旋锁 `uma_crit_lock`（`lib/include/vm/uma_int.h`）。在每线程独占 per-cpu 槽位后，该锁已无必要。

修复（commit `57b612d16`）：移除 `uma_crit_lock`，`critical_enter`/`critical_exit` 变为 no-op，恢复 UMA per-cpu cache 的无锁快路径。

## 5. 如何使用、配置与效果

### 5.1 配置方法

在 `config.ini` 的 `[dpdk]` 段新增 `thread_mode` 配置项：

```ini
[dpdk]
# lcore_mask 指定使用的 lcore 集合，thread_mode=1 时每个 bit 对应一个线程
lcore_mask=0xf            # 4 个 lcore = 4 个线程

# thread_mode: 0=多进程模式（默认），1=单进程多线程多栈实例
thread_mode=1

# 其他配置项与多进程模式相同
idle_sleep=20
hz=100

[port0]
addr=<DPDK_NIC_IP>
netmask=<NETMASK>
broadcast=<BROADCAST_IP>
gateway=<GATEWAY_IP>
lcore_list=0,1,2,3        # 与 lcore_mask 对应
```

### 5.2 启动方式

native-mt 模式下只需启动一个进程（不再需要 `start.sh` 脚本管理多进程）：

```bash
# 编译（make clean 后全量重编）
cd f-stack/lib && make clean && make -j$(nproc)
cd f-stack/example && make clean && make

# 启动（单进程）
./example/helloworld --conf config.ini --proc-type=primary --proc-id=0
```

### 5.3 使用效果

#### 性能基线实测（virtio 网卡环境）

| 配置 | 线程/进程数 | req/s | 延迟 (avg) | 说明 |
|------|------------|------:|----------:|------|
| `thread_mode=1`, 2 线程 | 2 | 233,380 | — | 修复后多线程 |
| `thread_mode=0`, 2 进程 | 2 | 231,570 | — | 多进程对照 |

关键发现：

1. **多线程线性扩展**：2 线程 233k req/s，与 2 进程 231k 持平，验证 share-nothing 无锁模型的线性扩展能力
2. **60 秒 soak 稳定**：400 连接持续 60 秒达 497k req/s、2983 万请求零错误
3. 【注意】thread_mode=0时单进程程数据确认为当时噪声，不在本文展示，实际性能单进程和单线程都差不多

#### 零回归保证

`thread_mode=0`（默认）时所有路径走既有 primary/secondary 分支，字节级不变。已通过 10 分钟以上大流量回归压测验证。

### 5.4 注意事项与限制

| 限制 | 说明 |
|------|------|
| **fd 不可跨线程共享** | 每个线程的 fd 表独立（VNET 隔离），同 fd 在不同线程含义不同，与多进程模式时单进程内的fd语义限制相同 |
| **KNI 单线程独占** | KNI 由线程 0 独占持有，其他线程不处理 KNI（其他线程需要kni处理的包通过kni_rp转发至线程0，流程与多进程模式相同） |
| **工具链兼容** | 优先保留外部工具进程（`--proc-type=secondary`）attach 方式，向后兼容 |
| **VIMAGE 依赖** | 启用 VIMAGE 需完整编译，部分 f-stack 阉割的 FreeBSD 子系统可能不完整 |
| **物理网卡 RSS** | 多线程真实扩展性依赖网卡 RSS 能力，无 RSS 网卡多线程扩展受限，与多进程模式相同 |

## 6. 参考资料

- **三层架构文档**：`docs/zh_cn/F-Stack_Architecture_Layer1_System_Overview.md`
- **native-mt spec**：`docs/native_mt_spec/zh_cn/`（00-17 共 18 篇完整设计文档）
- **知识图谱**：`docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md`
- **issue 汇总**：`docs/zh_cn/f-stack-issue-ana.md`（#430/#571/#807/#855 等多线程相关 issue）
- **代码提交**：`e79ceb9f0`（CM0-CM3）→ `86e0f76b0`（CM4 VIMAGE）→ `7495e70c0`（CM5 多栈实例）→ `6d74d59e0`（CM6 KNI）→ `82b409faf`（worker 时钟）→ `ff09a17b2`（prison 隔离）→ `c7996a94f`（SMP-aware pcpu）→ `57b612d16`（去全局锁）
