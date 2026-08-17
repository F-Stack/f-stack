F-Stack 2.0 前瞻6：LD_PRELOAD 无锁 Ring IPC 改造纪实，从信号量三层同步到 SPSC 双环的三年演进

1. 本功能主要作用和特点

直接说目的：F-Stack 的 LD_PRELOAD 模块（libff_syscall.so）从 2023-05 初版提交到现在已经演进三年，本文要讲的是 2026 年上半年给它做的无锁环形队列改造（FF_USE_RING_IPC），以及这三年里从初版到现在的全部优化和修改。

先交代背景。F-Stack 的标准接入方式是改代码：应用调 ff_* 前缀 API + ff_run() 主循环，代码侵入大。为了降低存量应用的迁移门槛，2023 年社区在 dev 分支提交了 adapter/syscall 目录（commit 8f5f1dfbb，2023-05-03），提供 libff_syscall.so 动态库，通过 LD_PRELOAD 劫持 Linux socket 系统调用转发给 fstack 实例进程处理，应用零代码修改即可接入。初版发布时官方定位很克制：「目前功能尚不完善，仅供测试使用」。

三年后的今天，这个模块已经支持 fork、accept4、_FORTIFY_SOURCE 包装函数、epoll polling 模式，并且把 APP 与 fstack 之间的 IPC 从信号量三层同步演进到了 DPDK 无锁 rte_ring 双环 SPSC。本文的三个关键词：

- **免改代码接入**：socket/bind/connect/read/write/epoll/kevent/select 全部劫持，存量应用（Nginx、netperf 等）零代码修改直接跑在 F-Stack 上
- **双环 SPSC**：FF_USE_RING_IPC 用 rte_ring 单生产者单消费者模式替换 sem_wait/sem_post，消灭全局锁和 O(n) 遍历
- **诚实收敛**：ring 改造经过 v1~v3.7 共七轮实测迭代，最终结论不是"ring 全面胜利"，而是"ring 在 LD_PRELOAD + FF_MULTI_SC 场景下没有性能优势，生产推荐 sem"——这是本文最想传达的：优化要有对照、有证伪、敢于否定自己

规模数据：adapter/syscall 目录从初版到现在 40 余个 commit；ring 专项产出 4 篇 spec 文档（docs/ld_preload_ring_spec/）、1 份 v3.7 终版性能分析（ring_ipc_perf_offline_analysis.md）；性能攻坚期间 9.1w → 10.22w QPS（+12.3%）。

2. 本功能的主要适用场景

2.1 存量应用免改代码接入 F-Stack

这是 LD_PRELOAD 模块的根本定位。历史 issue 档案里，官方对"现有多线程/多进程/Go/netperf 类应用怎么移植"的回答，推荐方案第一条几乎都是它：不用改源码，先起 fstack 实例进程，再 LD_PRELOAD 拉起应用。适配的接口面包括 socket 全家桶、epoll 全家桶、kqueue/kevent、select、fork，以及 glibc _FORTIFY_SOURCE 编译的 __recv_chk/__read_chk/__recvfrom_chk 包装函数。

2.2 Nginx 免改代码集成

Nginx 官方默认携带 1.16.1，经 LD_PRELOAD 接入无需改任何代码，需要同时开 FF_KERNEL_EVENT + FF_MULTI_SC 两个编译开关，配置上 multi_accept on、listen reuseport。不适用场景明确：多实例做客户端（反向代理）暂不支持，需要像社区 @铁皮大爷 那样在 hook 层加 RSS 对称 hash 选实例。

2.3 fork 多进程模型应用

2025-05 的 fork 支持（commit 4891fabf5，PR #887）之后，每个 fork 出来的进程都拥有独立的 FreeBSD struct thread，行为对标 Linux 内核 fork。配合 FF_MULTI_SC，Nginx master fork worker 的经典模型可以跑通。

2.4 不太适合的场景

- 追求极致性能：每组应用实例要 2 个 CPU 核（1 个 fstack + 1 个 APP），CPU 几乎翻倍，官方原话"性价比不高"。要极致性能还是直接改代码用标准 F-Stack
- 8 核以上的短连接场景：LD_PRELOAD 性能不如标准 F-Stack，受 APP 与 fstack 匹配度影响

3. 本功能的架构特征

3.1 整体拓扑

```
┌───────────────────────────────────────────────────┐
│           用户应用程序（Nginx / netperf / ...）      │
│   socket()/bind()/listen()/connect()/accept()/     │
│   read()/write()/epoll_wait()/kevent()/fork()      │
└──────────────────────┬────────────────────────────┘
                       │ LD_PRELOAD 劫持
                       ▼
┌───────────────────────────────────────────────────┐
│   libff_syscall.so（APP 侧 hook 层）                │
│   ff_hook_syscall.c：                              │
│   按 fd 判断走 F-Stack 还是系统内核；               │
│   填充 sc->ops/sc->args 请求 fstack 实例处理         │
└──────────────────────┬────────────────────────────┘
                       │ Hugepage 共享内存（rte_malloc）
                       │   ff_so_context（sc，每上下文一个）
                       ▼
┌───────────────────────────────────────────────────┐
│   fstack 实例进程（1 实例 = 1 个完整 F-Stack 栈）    │
│   ff_handle_each_context() 主循环：                 │
│   处理 sc 请求 → ff_so_handler → F-Stack API        │
│   时间窗口复用 config.ini 的 pkt_tx_delay 参数       │
└───────────────────────────────────────────────────┘
```

核心通信载体是 DPDK 大页共享内存上的 ff_so_context（简称 sc）。APP 把要执行的 socket 操作填进 sc，fstack 实例主循环处理并把结果写回。fstack 实例和 APP 建议跑在同 NUMA 节点的不同物理核上。

3.2 初版同步机制：信号量三层同步

初版（2023-05 ~ 2026-04 默认路径）sc 的同步靠三层机制：

| 层 | 机制 | 位置 |
|---|---|---|
| 状态机 | FF_SC_IDLE → FF_SC_REQ → FF_SC_REP → FF_SC_IDLE | ff_socket_ops.h |
| 互斥锁 | rte_spinlock_t lock（sc 级 + zone 级全局锁） | ff_socket_ops.h |
| 信号量 | sem_t wait_sem（POSIX 跨进程信号量，futex 实现） | ff_socket_ops.h |

一次 socket 调用的往返流程：

```
APP 侧                          fstack 侧
──────                          ──────────
FF_SC_IDLE ──填 ops/args──► FF_SC_REQ
                                  │ 主循环 O(n) 遍历全部 sc，
                                  │ 脏读 status==REQ
                                  ▼
                              trylock → ff_so_handler(sc)
                                → F-Stack API 处理
                                  │
                                  ▼
                            sc->result 写回 + sem_post 唤醒
                                  │
FF_SC_REP ◄───────────────────────┘
  │ 读 result/error
  ▼
FF_SC_IDLE
```

3.3 新同步机制：双 Ring SPSC

2026-04-09 的 commit d2b71ac89 引入 FF_USE_RING_IPC：用 DPDK rte_ring（SPSC 模式）替代 sem。请求环 APP 生产 fstack 消费，响应环 fstack 生产 APP 消费：

```
APP 侧                          fstack 侧
──────                          ──────────
① 填充 sc->ops/sc->args
② rte_ring_sp_enqueue(req_ring, sc)
        ┌─────────────┐
        │  请求 Ring    │────► ③ rte_ring_sc_dequeue_burst()
        │  (SPSC)      │       批量出队，O(1) 替代 O(n) 遍历
        └─────────────┘       ④ ff_handle_socket_ops_ring(sc)
                                  → sc->result = ...; sc->error = errno
        ┌─────────────┐       ⑤ rte_ring_sp_enqueue(rsp_ring, sc)
        │  响应 Ring    │◄───（D2 优化后改为直接写 sc->completion）
        │  (SPSC)      │
        └─────────────┘
⑥ rte_ring_sc_dequeue(rsp_ring) → 读 result/error
```

状态语义的等价迁移：sc 在 req_ring 中 = 旧 FF_SC_REQ；在 rsp_ring 中 = 旧 FF_SC_REP；两个 ring 都不在 = 空闲。spinlock 和状态机转换不再参与同步逻辑。

3.4 为什么选 rte_ring

spec 文档（SPEC-002）里给了四条理由：F-Stack 本身大量使用 rte_ring（dispatch_ring、msg_ring），零学习成本；DPDK 原生 SPSC 无需自研无锁算法；Hugepage + rte_memzone 已验证跨进程可见；比 VPP 的 svm_msg_q 更简单。APP 与 fstack 实例 1:1 绑定，天然满足 SPSC 约束。

4. 具体做了哪些改造、遇到了哪些问题、怎么解决的

后续比较枯燥，不需要深入研究实现过程的可以跳过本节，直接看第 5 节怎么用。

4.1 初版遗留问题清单（ring 改造的动机）

初版的信号量机制在 spec 文档（SPEC-001）里被列了 5 条性能瓶颈：

1. **内核态切换**：sem_wait/sem_post 走 futex 系统调用，每次 100-200ns，epoll_wait 短超时场景被放大
2. **超时精度差**：sem_timedwait 用 CLOCK_REALTIME，受 NTP 调时影响，唤醒粒度受调度器 tick（1-4ms）限制；还有个竞态：超时返回后 fstack 才 sem_post，导致下次 sem_timedwait 立即返回读到过期结果
3. **O(n) 遍历**：ff_handle_each_context 每轮遍历全部 32 个 sc 的 status 字段，绝大多数处于 IDLE 也要脏读
4. **alarm_event_sem 补偿机制脆弱**：5 个示例程序里只有 1 个真正调用它，其余全注释掉了
5. **模式分裂**：信号量模式（低 CPU 高延迟）和轮询模式 FF_PRELOAD_POLLING_MODE（低延迟 100% CPU）通过编译宏二选一，运行时不可切换

4.2 三年中间演进（2023-08 ~ 2026-03，ring 之前的沉淀）

ring 不是凭空出现的，中间这三年社区补了不少坑，按时间排：

| 时间 | commit | 内容 |
|---|---|---|
| 2023-08 | 0ee517ed0 | 修 Ubuntu 22.04 / kernel 5.19 / gcc 11.4 编译错误（#777），pre-C99 声明问题 |
| 2025-03 | 5de6ec6d2 | 新增 epoll polling 模式，改善 RTT 敏感场景延迟 |
| 2025-03 | 3c21f2253 | 修 ff_hook_recvfrom sh_fromlen 未初始化导致返回 -1（PR #872） |
| 2025-03 | e3766b423 | accept4 支持 + ff_socket 支持 LINUX_SOCK_CLOEXEC/NONBLOCK |
| 2025-05 | 111816e29 | hook __recv_chk/__read_chk/__recvfrom_chk，_FORTIFY_SOURCE 编译的应用可用 |
| 2025-05 | 4891fabf5 | 完整 fork 支持（PR #887），每个进程独立 FreeBSD struct thread |
| 2026-03 | b36ce995d | 修 ioctl 可变参数签名冲突编译错误（#942，PR #1048） |

其中 ioctl 那个坑值得展开一句：glibc 里 ioctl(2) 是可变参数签名 int ioctl(int, unsigned long, ...)，而 ff_declare_syscalls.h 按定参注册，新工具链一编就炸。这类"glibc 签名 vs hook 声明"的不一致，是 LD_PRELOAD 这类方案的天生雷区，只能靠社区逐一踩坑修复。

4.3 ring 初版落地（2026-04）

2026-03-27 先产出了 4 篇 spec（需求/架构/接口/测试），审核通过后 2026-04-09 一次性提交 d2b71ac89：双 rte_ring SPSC、FF_USE_RING_IPC 编译开关、三种等待策略（busy-poll/yield-poll/eventfd，默认 yield-poll）、rte_rdtsc 替代 sem_timedwait 做微秒级超时、alarm_event_sem 改为 sentinel 入队。设计上严格走"编译宏切换 + 旧路径不动"，可渐进迁移。

4.4 ring 性能优化攻坚战（2026-05，七轮迭代的教训全集）

初版 ring 一上实测就出问题：短连接 QPS 9.1w，比 sem 基线 10.5w 低 12.4%。于是有了 v1~v3.7 的七轮迭代，这段过程是本文最有价值的部分——不是"怎么修好的"，而是"怎么一步步证伪自己的错误假设"。

**第一轮假设（H10/H11，v1）**：只读了 ff_socket_ops.c 的 ring 分支，下结论"sem 模式没有 30us drain 强制空轮询"。被证伪——对照 else 分支发现 sem 同样有 if (diff_tsc >= drain_tsc) break 循环。教训：单边代码分析，不对照另一分支就下结论。

**第二轮假设（H15，v2）**：基于"sem 有 nb_handled 旁路而 ring 没有"，假设 ring 的 dequeue burst 跨核读 prod.tail 导致 LLC miss 暴增。perf stat 实测证伪：ring 的 LLC miss 反而比 sem 少 23%（6.8K/s 量级，不构成瓶颈）。教训：没先验证可证伪的物理量就把假设写进文档。

**第三轮（v3.1）**：把"每 256 次 PAUSE 触发 sched_yield"按纯算术推成次因（H18），实测三组配置（yield 阈值 0xFF/0x1FFF/busy-poll）QPS 全部 9.2w，voluntary_ctxt_switches 增长约等于 0——spin_count 是局部变量，短连接场景单次 wait 根本到不了 256 次。教训：频率类估算先做 10 秒采样，别做 30 分钟的弯路。

**第四轮（v3.2）**：perf top callgraph 锁定真因——ff_ring_process_requests Self 15.44%（每次主循环 spin 都走完整 dequeue burst 函数调用栈，即使 nb=0）+ ff_ring_send_response Self 3.33%（每次响应写 rsp_ring->prod.tail，触发 APP 核 cache invalidate）。同期还证伪了自己两条假设：H21 把 wrk 延迟差 +190us 当成单 syscall 开销（差 3 个数量级，真因是 CPU 占用挤压）；H24 在 perf 已给明确证据后还发散"跨 NUMA"环境假设（同环境对照实验的唯一变量是 IPC 实现本身）。

**方案 C 的失败（v3.3，H25）**：想用 atomic pending_count 旁路复刻 sem 的 nb_handled 快速跳过，结果 QPS 反劣化 4%（9.1w → 8.7w）。根因：APP 每次 syscall 多写 atomic 2-4 次，跨核 cache 乒乓比省掉的 dequeue 路径更贵。这个方案当天实施当天回退，代码随后彻底删除（f344d945f）。教训写进了文档的"对称评估表"方法论：任何优化必须同时列出"消除的物理量"和"新引入的物理量"，后者数量级必须明显小于前者才允许实施。

**D2 的成功（v3.4，+9.7%）**：放弃响应 ring，fstack 处理完直接写 sc->completion（sc cache line 0 上本来就预留的字段），APP 端 spin completion 标志。写频率与 sem 基线完全一致，零新跨核字段。QPS 9.1w → 10.0w，ff_ring_send_response 从 perf top 消失。

**D5（+1.3%）**：ff_ring_process_requests 改为先 rte_ring_empty() 内联快速空判断，空时不展开函数调用栈。Self 18.98% → 4.53%，但 QPS 只涨 1.3%——省下的 CPU 立刻被 main loop spin 填满。这是关键的洞察起点：fstack lcore 100% CPU + 30us drain 设计下，IPC 省下的 CPU 不会 1:1 变 QPS。

**D6（+0.9%）**：ff_handle_socket_ops_ring 标 static inline，主循环直接函数名调用（去函数指针），与 sem 模式的 ff_handle_socket_ops 对齐。10.13w → 10.22w。

最终收敛：ring 单 worker QPS 10.22w，距 sem 的 10.5w 还差 2.7%。perf top 显示两边 main loop CPU 占比已完全一致（50.13% vs 50.41%），剩余差距来自 rte_ring_sc_dequeue_burst 的 acquire fence 和 ring 元数据维护——sem 的 dirty read 是 plain load 无 fence。**这是 SPSC 架构的物理代价，单 worker 单 lcore 场景不可消除**。

4.5 意外收获：sem 路径的启动饥饿修复

ring 攻坚过程中顺带修了一个老问题（8125beece，2026-05-25）。现象：sem 模式 + FF_MULTI_SC + config.ini 里 idle_sleep=0 时，多 worker 启动、还没任何流量，nginx 第二个 worker 卡死在 ff_attach_so_context 的 rte_spinlock_lock，gdb 堆栈和死锁一模一样。

但它是饥饿不是死锁：fstack secondary lcore 专核紧自旋，每 50-100us 释锁一次但释锁窗口 <<1us（idle_sleep=0 不让 CPU），nginx worker 是普通调度进程，cmpxchg 永远慢一拍，命中窗口概率趋近 0。修复只改了 13+/5- 行：进入 while 前快照 tmp（in-use sc 数），unlikely(!tmp) 时 unlock → pause → lock 让出窗口，有负载时零影响。最优补丁是"条件性让出"不是"无条件让出"。

【注1】这条饥饿现象同时说明：跨进程自旋锁竞争里，专核 DPDK lcore 永远胜过普通调度进程，这是物理机制不是代码 bug。能用配置（idle_sleep 改 1）消除的现象，根因 99% 是时间窗/调度类问题。

4.6 多核长连接实测：最终证伪 ring 的设计目标（v3.5~v3.7）

单 worker 收敛后转向多核对照。结果比预想残酷：

| 场景 | 结论 |
|---|---|
| 多核短连接（1/2/4 核） | ring ≡ sem（差距 -1.9%/0%/-0.3%，噪声范围） |
| 多核长连接（1/2/4 核） | ring **稳定劣于** sem 2.4%~4.5%，方向一致且大于噪声 |

长连接把 ring 的劣势放大而不是抵消：FF_MULTI_SC 下每个 fstack lcore 与 nginx worker 是 1:1 同 zone，sem 的 zone 锁是 fstack lcore 独占持有（cache line 一直 exclusive，近乎零成本），而 ring 每次 dequeue 都要 acquire fence 同步内存系统，高 QPS 下线性放大。当初"长连接下 sem 全程持锁压力升高、ring lock-free 优势将显现"的预测被彻底证伪。

v3.7 终版结论（2026-05-25 晚）：

1. **性能层面**：ring 在任何已测场景下均无 net win，sem 仍是 LD_PRELOAD + FF_MULTI_SC 的最优配置
2. **鲁棒性层面**：ring 主循环 lock-free 的理论价值（启动饥饿免疫）已被 8125beece 在 sem 源头修复
3. **架构层面**：ring 代码保留（FF_USE_RING_IPC + D2/D5/D6 作为默认行为，c62d56a3b），作为"多线程同进程共享 sc"和"多进程间共享 sc（worker 数 > fstack 实例数）"的未来预留能力，当前 fork 多进程场景默认不启用

【注2】这个收敛结论值得反复看：一个设计良好、实现了完整 spec、优化了七轮的方案，最终被对照实验判定"不如老方案"。如果只有实现没有对照基线，这个结论永远不会出现。性能优化工作里，"对照组先于优化"比"数据先于理论"更值钱。

4.7 ring 之后还在继续（2026-05 ~ 08）

收敛之后模块没有停：README 全面刷新（bc7c380b2，2026-05-26）；ff_hook_bind 增加 addrlen 边界检查（8762e05c1，2026-06-08，#1068）；新增 UDP echo server 示例（2215dc4f2，2026-08-07，#1063）。

5. 如何使用、如何配置、使用效果

5.1 编译

```bash
export FF_PATH=/data/f-stack
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig

cd /data/f-stack/adapter/syscall
# Nginx 无缝接入：同时开 FF_KERNEL_EVENT + FF_MULTI_SC
export FF_KERNEL_EVENT=1
export FF_MULTI_SC=1
# 可选：启用无锁 ring IPC（默认关闭，见 5.4 推荐配置）
#export FF_USE_RING_IPC=1
make clean; make all
```

编译产物：fstack（实例程序）、libff_syscall.so（劫持库）、5 个 helloworld 示例 + main_stack_udp 示例。FF_USE_RING_IPC 与 FF_PRELOAD_POLLING_MODE 互斥，Makefile 有编译期检查，同时定义直接报错。

5.2 运行

```bash
# 1. 先起 fstack 实例（lcore_mask 等配置同标准 F-Stack）
bash ./start.sh -b adapter/syscall/fstack

# 2. 再以 LD_PRELOAD 方式拉起应用
export LD_PRELOAD=/data/f-stack/adapter/syscall/libff_syscall.so
export FF_NB_FSTACK_INSTANCE=4        # 与 nginx worker 数 1:1
/usr/local/nginx/sbin/nginx
```

运行时环境变量：FF_NB_FSTACK_INSTANCE（实例数，默认 1）、FF_INITIAL_LCORE_ID（起始核，默认 0x4）、FF_PROC_ID（进程号，配合 CPU 绑定）。应用能自己绑核的（如 nginx worker_cpu_affinity）优先自己绑。

5.3 Nginx 配置要点（免改代码，但要调配置）

```nginx
worker_processes  4;
worker_cpu_affinity 10000 100000 1000000 10000000;

events {
    worker_connections  1024;
    multi_accept on;      # F-Stack epoll 是 kqueue 封装，必须开
    use epoll;
}

http {
    access_log  off;
    sendfile    off;      # 用 F-Stack 必须关
    keepalive_timeout  0;

    server {
        listen       80 reuseport;   # 每个 fd 对接不同 fstack 实例的 sc
        location / {
            return 200 "0123456789abcdefghijklmnopqrstuvwxyz";
        }
    }
}
```

注意 kern.maxfiles 不应大于 65536（保证 epoll fd 到内核 fd 的正确映射）。

5.4 使用效果与推荐配置

性能数据（E5-2670 v3 双路 / 10G X540，v3.7 终版实测）：

| 场景 | Sem | Ring | 差距 |
|---|---|---|---|
| 多核短连接 1/2/4 核（万 QPS） | 10.4 / 20.8 / 35.9 | 10.2 / 20.8 / 35.8 | ≤2%（噪声） |
| 多核长连接 1/2/4 核（万 QPS） | 33.3 / 65.9 / 130.5 | 31.8 / 64.3 / 127.0 | -2.4%~-4.5% |
| 单 worker 优化轨迹 | — | 9.1w → 10.22w（+12.3%） | 距 sem 10.5w 差 2.7% |

生产推荐配置（2026-05-25 终版）：

```bash
# LD_PRELOAD + nginx 多 worker 推荐（默认，不开 ring）
make FF_KERNEL_EVENT=1 FF_MULTI_SC=1
# config.ini: idle_sleep = 0（8125beece 之后安全），pkt_tx_delay = 50（短连接）/ 100（长连接）
```

ring 路径仅在以下任一情况启用：单进程内多线程需共享 sc；多进程间共享 sc（worker 数 > fstack 实例数）；或者接受 -2.4%~-4.5% 的性能损失换取主循环 lock-free 设计。

对 F-Stack 使用者的整体建议：LD_PRELOAD 是"少改代码"的折中，不是"性能最优"的路径。要追求极致还是标准 F-Stack 改代码接入；只想快速迁移存量应用，LD_PRELOAD + sem 默认配置就够用，ring 等未来多对多共享场景再启。

延伸阅读：

- ring 需求/架构/接口/测试 spec：docs/ld_preload_ring_spec/zh_cn/01~04
- v3.7 终版性能分析（七轮迭代完整复盘）：docs/ld_preload_ring_spec/zh_cn/ring_ipc_perf_offline_analysis.md
- 模块官方文档（含 2023-05 ~ 2026-05 全部 feature updates）：adapter/syscall/README.md
- 初版公众号介绍（2023-05）：https://mp.weixin.qq.com/s/hmxCEu0kOzp5X5TEB7r3OQ
- 三层架构文档：docs/zh_cn/01-LAYER1-ARCHITECTURE.md
- 知识图谱：docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md
- 历史 issue 档案：docs/zh_cn/f-stack-issue-ana.md
