F-Stack 主进程瘦身 primary_slim：把 primary 单点故障从紧急事故降级为计划内维护

1. 这功能解决什么问题

primary_slim 是 F-Stack v2.0（预计 2026.10 正式 release）引入的一个运行开关，解决 DPDK 多进程模式下 primary 进程是单点的问题。

F-Stack 的标准多进程模式是 1 个 primary + N 个 secondary，每个进程独占一个 lcore 跑一份独立 FreeBSD 栈实例。secondary 崩了可以单独重启，不影响其他进程的队列和已建连接；但 primary 一旦异常退出，问题就大了——按照 DPDK 的设计，primary 是 IPC 唯一服务端、secondary 扩堆必须由 primary 代理、所有中断只在 primary 触发，所以传统认知是"primary 挂了整个进程组都得重启，所有连接受影响"。

这个诉求来自上游 issue #1078（https://github.com/F-Stack/f-stack/issues/1078），作者提的想法很直接：把 primary 独立出来，只做网卡队列设置、绑定、初始化这类控制面工作，收包和后续处理全部下移 secondary，这样 primary 就不那么容易异常，对连接的影响范围也小。

primary_slim 干的就是这件事：

【注1】primary_slim 把"primary 崩溃 → 必须立刻全组重启 + 约 1/N 连接立即中断"变成"primary 崩溃 → 数据面零损失、业务继续跑、崩掉的 secondary 可原地重启、集群进入控制面降级态、在计划内维护窗口择机全组重启"。

说白了，是把紧急故障转化为计划内维护，重启时机从被动变成可控。

这里先说清楚它不做什么，免得期待过高：

- 不承诺"完全无需重启"——控制面降级态无法就地修复，最终还是要择机全组重启
- 不承诺"省一个 CPU 核"——瘦身后的 primary 仍会空转占满一核，除非开空闲休眠
- 不承诺 primary 不再是结构性单点——只是降低异常概率、缩小影响面
- 不承诺 secondary 崩溃时连接不丢——每进程独立 FreeBSD 栈，没有连接迁移这回事

2. 主要适用场景

2.1 对 primary 单点稳定性敏感的生产部署

如果你的业务在多进程模式下跑，primary 一旦挂了要拖累全组，primary_slim 能让 primary 退出时数据面零损失。实测数据（后文详述）：杀掉瘦身 primary 后，已建连接 12/12 零中断（26 轮探测无一次失败），新建连接 12/12 正常。

2.2 需要控制面与数据面解耦、缩小故障爆炸半径

多进程模式里，primary 名下如果持有 rx/tx 队列，它崩了这些队列就变成没人 poll 的孤儿队列，落到上面的流量全部黑洞化。primary_slim 让 primary 不持任何队列，数据面能力全部留在 secondary，primary 退出不带走任何数据面能力。

【注意】因为使用virtio创建的tap的限制，kni依然由主进程处理，primary挂了后kni会失效。

2.3 已经有外部守护/编排，想要分层恢复能力的场景

配合外部守护，可以做到：secondary 崩了原地重启 → primary 崩了进入降级态告警 → 择机计划内全组重启。这比"primary 一挂就紧急全组重启"从容得多。

2.4 不太适合的场景

单进程多线程模式（thread_mode=1）下没有独立 primary 进程，这个特性语义不存在，所以 primary_slim 与 thread_mode 是互斥的，配置校验会拦掉。如果只有 1 个进程（nb_procs < 2），也没有瘦身的意义，同样会被校验拦截。

3. 架构特征

3.1 改造前后对比

改之前（标准多进程）：

```
┌─────────────────────────────────────────────┐
│ primary (lcore0)                             │
│  ├─ 网卡队列配置/绑定/初始化                 │
│  ├─ 持有 rx/tx queue0  ← 也参与数据面收包    │
│  ├─ IPC 服务端 / 扩堆代理 / 中断处理         │
│  └─ 跑一份 FreeBSD 栈实例                    │
│                                              │
│ secondary1 (lcore1)    secondary2 (lcore2)   │
│  ├─ rx/tx queue1        ├─ rx/tx queue2     │
│  └─ FreeBSD 栈实例1     └─ FreeBSD 栈实例2   │
└─────────────────────────────────────────────┘
  primary 崩了 → 它的 queue0 孤儿化 + 控制面全挂
```

改之后（primary_slim=1）：

```
┌─────────────────────────────────────────────┐
│ primary (lcore0)  —— 纯控制面，不持队列      │
│  ├─ 网卡队列配置/绑定/初始化                 │
│  ├─ IPC 服务端 / 扩堆代理 / 中断处理         │
│  ├─ KNI 初始化（virtio_user vdev 只能 primary 建）│
│  └─ 主循环只剩 timer + msg_ring，不碰 mbuf    │
│                                              │
│ secondary1 (lcore1)    secondary2 (lcore2)   │
│  ├─ rx/tx queue0        ├─ rx/tx queue1     │
│  └─ FreeBSD 栈实例1     └─ FreeBSD 栈实例2   │
└─────────────────────────────────────────────┘
  primary 崩了 → 数据面零损失，secondary 继续服务
```

3.2 为什么队列能自然收缩、不产生孤儿队列

这是整个方案成立的关键，也是调研阶段最反直觉的发现。一开始担心"把 primary 摘出 lcore_list 会导致队列数减 1、queueid 错位、RSS reta 错位"，逐行坐实后发现根本不成立：

- nb_queues 来源是该 port 的 lcore_list 长度，不是 nb_procs（lib/ff_dpdk_if.c:836）
- queueid 是本进程 lcore 在 lcore_list 里的下标，与 proc_id 完全解耦（lib/ff_dpdk_if.c:487-491）
- set_rss_table() 按同一个 nb_queues 重算 reta

所以把 primary 摘出 lcore_list 后，队列数、queueid、RSS reta、dispatch_ring 一致收缩，孤儿队列在代码层面自然消失。这正好是维护者（本人）提示词设想的"复用 lcore_list"路线的根本依据。

3.3 KNI 场景下的数据通路（最复杂的情况）

primary_slim=1 且 KNI 开启时，数据通路是三条线，涉及一个关键竞态修复（后文 4.3 详述）。最终稳定形态：

```
ICMP 请求入站：
  client → 物理网卡(Port0) → secondary rx_burst(q0)
    → ff_kni_enqueue → KNI ring
    → primary kni_process_tx → rte_eth_tx_burst(Port1=virtio_user0)
    → veth0(tap) → kernel 协议栈 → 生成 ICMP reply

ICMP 回复出站（inject ring 路径）：
  kernel → veth0 → virtio_user0
    → primary kni_process_rx → enqueue 到 kni_inject_rp ring
    → owner secondary 用自己的 tx_queue 发出
    → 物理网卡 → client
```

核心分工：secondary 负责数据面收包入队 KNI ring，primary 独占 virtio_user vdev 的 TX/RX（因为 vdev 只有 primary 能合法操作），KNI 收到的回复包经 kni_inject_rp ring 转发给 owner secondary 用自己的队列发出。这样既绕开了"secondary 不能操作 virtio_user vdev"的 DPDK 硬约束，又消除了跨进程共享 TX queue 的竞态。

4. 改造工作与遇到的问题

后续比较枯燥，不需要深入研究实现过程的可以跳过本节，直接看第 5 节怎么用。

4.1 PoC 阶段：3 行代码验证核心命题

正式立项前先做了个最小 PoC，只改 3 行代码（`_poc_primary_slim.patch`，2 hunk）：

- lib/ff_dpdk_if.c:508-510：`rte_exit` 条件追加 `&& rte_eal_process_type() != RTE_PROC_PRIMARY`，解除 B1 阻塞点（"lcore %u has nothing to do"）
- lib/ff_dpdk_if.c:535：mbuf 池 RX 项去掉对本进程队列数的依赖，解除 B3 阻塞点（池规模归零）

配置是 `lcore_mask=3` + `[port0] lcore_list=1`（primary 的 lcore0 不在列表内）。

3 行代码 + 1 项配置就验证了核心命题：瘦身 primary 崩溃后已建连接 12/12 零中断、新建连接 12/12、性能无回归。这也直接说明了为什么这个改动值得做——代价极小，收益是质变。

【注2】PoC 用 `rte_eal_process_type() != RTE_PROC_PRIMARY` 无条件放宽只是为了最小化 diff，正式实现改成了 `primary_slim && RTE_PROC_PRIMARY` 有条件门控，避免影响默认路径。

4.2 正式实现：从"自动推导"到"显式开关 + 校验链"

PoC 能用但不严谨（靠"自动推导"而非显式开关），正式实现补了完整的开关和校验链。核心提交是 `1c28aaa2d`（M1）+ `f7961b083`（M2~M4）。

交付的东西：

- `[dpdk] primary_slim=0/1` 显式开关，默认 0，关闭时零回归
- 开启后 primary 在 init_lcore_conf 里 early return，不分配 rx/tx 队列，不进收发包主循环
- 配套 `primary_slim_idle_sleep`（默认 1000us）解决 CPU 空转
- 三道校验：primary lcore 不得在 lcore_list（V2）、与 thread_mode 互斥（V4）、nb_procs >= 2（V5）
- `ff_is_slim_primary()` API

4.3 踩到的坑：CPU 空转

这是实测发现的第一个负面问题。瘦身后的 primary 不持队列、不收包，但 `ps -o pid,pcpu` 一看还是 99.8% 占满一核。原因是 main_loop 仍在紧密空转（跑 timer 和 msg_ring 处理），而 config.ini 的 idle_sleep=0 意味着无空闲休眠。

【注3】primary_slim 的收益是稳定性，不包含 CPU 节省。如果用户期望"瘦身 = 省一个核"，这个预期必须纠正。正式实现引入了 primary_slim_idle_sleep（默认 1000us），否则在核数紧张的部署里就是白烧一个核。

4.4 踩到的坑：KNI 场景下的跨进程 TX 队列竞态

这是 post-implementation 阶段发现的最棘手的问题，分两阶段修复。

第一阶段（f23f1a464）：primary_slim=1 + KNI 开启时，KNI 的 runtime TX/RX 应该由 primary 执行（因为 virtio_user vdev 只能 primary 操作）。但这样一改，primary 的 kni_process_rx 里调 `rte_eth_tx_burst(Port0, queue_id=0)` 把 kernel 回复包注入物理网卡，而 primary_slim=1 时 queue0 归属第一个 secondary worker0——两个进程并发操作同一个 TX queue，desc ring 会损坏、mbuf 会泄漏。DPDK 多进程模型里每个 TX queue 只能一个进程独占，没有进程级锁。

第二阶段（f250ad1ea）：引入 `kni_inject_rp` 共享 ring 彻底消除竞态。primary 收到 KNI 回复包后不直接 TX Port0，而是 enqueue 到 inject ring，由 owner secondary dequeue 后用自己的 tx_queue_id 发出。方案选型时排除了另外两个：

- 预留专用 queue（nb_queues+1，KNI 用最后一个 queue）：本地 virtio 不支持 RSS，无法用 RETA 隔离额外 rx queue，vhost backend 会向所有启用的 qp 分发，额外 rx queue 无人 poll 会 desc ring 满导致 backpressure，不可行
- rx!=tx 不等队列：virtio PMD 按 max(rx,tx) 分配 vq，未 setup 的 rx queue 会被后端写入导致 crash，不可行

inject ring 是唯一可行的路径。

4.5 踩到的坑：primary_slim=0 + owner_proc_id 误伤 KNI

实现 commit 1c28aaa2d 把 KNI 调用条件从 ff_kni_is_owner_thread() 改成了 ff_kni_is_runtime_owner()，但没考虑到 primary_slim=0 时 owner_proc_id 生效会导致 primary 不再处理 KNI，反而误伤了默认模式。修复（e075e534f）改成条件分支：primary_slim 时用 runtime owner 判定，否则用 owner thread 判定。

4.6 一个遗留问题：primary 退出清理其实效果有限

文档 14 专门分析了这个。跳过 rte_eal_cleanup() 的设计意图是保护 secondary 依赖的共享资源，但逐函数坐实后结论是实际效果几乎为零——hugepage 用 MAP_SHARED，primary 退出内核只 munmap 自己的映射不影响 secondary；config 文件不在 cleanup 里删除；mp_socket unlink 不影响 secondary（有自己的 fd）。

真正缺失的是没有通知 secondary 退出，primary 退出后 secondary 变成孤儿进程进入控制面降级态。但按设计哲学 primary 本来就不该正常退出，这个路径是"万一"的兜底。

【注4】这里对文档 10 里"避免 rte_eal_cleanup() 拆除共享资源"的说法做了修正——经源码坐实，rte_eal_cleanup() 实际上不拆除 secondary 依赖的共享资源，这个说法不完全准确。skip cleanup 的真正价值是保守策略：避免 cleanup 过程中 pthread_cancel 等操作的未定义行为。

4.7 issue 原文两处判断被实测修正

这个值得单独说，因为它是整个调研最有价值的部分——初始回复的两个前提假设，实测后都不准确：

- "primary 一旦异常退出，整个进程组都得重启" → 部分不成立。其余进程继续服务，崩掉的 secondary 可原地重启（只要还有进程持有 /dev/uioX，uio refcnt >= 1），无需立即全组重启。但 primary 本身不能原地拉回（新 primary 会 EBUSY 失败，这是 EAL 的设计意图），所以还是要择机全组重启。
- "所有连接都会受到影响" → 不成立。传统模式下只有哈希到 primary 队列的那部分流量受影响（2 进程约 1/2，3 进程约 1/3），瘦身后零影响。
- "secondary 异常了可以重启，不影响其他进程" → 成立，E2d 实测验证。

5. 如何使用、配置与效果

5.1 配置

在 config.ini 的 [dpdk] 段加 primary_slim，在 [kni] 段加 owner_proc_id：

```ini
[dpdk]
lcore_mask=3              # primary(lcore0) + 1 个 secondary(lcore1)
primary_slim=1            # 0(默认)=关闭，1=primary 瘦身
primary_slim_idle_sleep=1000   # 默认 1000us，避免 primary 空转占满一核，后续因为kni还需要主进程处理，可以根据需要适当调整该值

[port0]
lcore_list=1              # 关键：primary 的 lcore0 不在列表内，队列全归 secondary

[kni]
enable=1
method=reject
owner_proc_id=1           # primary_slim=1 + KNI 时指定 runtime owner secondary
```

配置校验会自动拦截三种非法组合：primary_slim 与 thread_mode 互斥、nb_procs 必须 >= 2、primary lcore 不得在 lcore_list 里。

5.2 启动

启动方式不变，还是 start.sh 管多进程：

```bash
./start.sh -c config.ini -b ./example/helloworld
```

5.3 效果

功能正确性（文档 05 实测）：

- 杀瘦身 primary 后已建连接 12/12 零中断，26 个探测轮次无一次失败
- 杀瘦身 primary 后新建连接 12/12 正常
- QPS：slim primary 存活时 122.4k（相对单进程基线 122.3k，+0.08%）；slim primary 崩溃后 127.7k（+4.5%），均 0 失败请求

KNI 场景（文档 13 实测）：

- ping 5/5 0% 丢包，rtt 0.512~1.329ms
- HTTP 200

结项验证（文档 15）：

- 物理机功能测试、性能压测通过
- 默认标准多进程模式 10 分钟以上大流量回归压测零回归
- 多线程模式（thread_mode=1）10 分钟以上大流量回归压测零回归

5.4 已知边界

- 全部实测在 virtio 设备 + igb_uio 的虚拟化环境完成，物理机功能/性能压测已补做通过，但 VFIO 下的 refcnt 语义与设备运行态保持行为仍标注为未充分验证
- primary 不可原地拉回，控制面降级后需择机计划内全组重启
- 优雅退出未实测，primary 退出建议走强杀而非 rte_eal_cleanup()
- 长期稳定性（小时级）未充分观测，10 分钟以上大流量回归通过

延伸阅读：

- 完整调研与实现文档：docs/primary_slim_spec/zh_cn/（00-15）
- 结项报告：docs/primary_slim_spec/zh_cn/15-结项报告.md
- 三层架构：docs/zh_cn/F-Stack_Architecture_Layer1_System_Overview.md
- issue 原文：https://github.com/F-Stack/f-stack/issues/1078
