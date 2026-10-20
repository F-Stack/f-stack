F-Stack 2.0 前瞻：FreeBSD 13.0 → 15.0 协议栈升级纪实，跨 6 个版本的裁剪与重做

1. 本功能主要作用和特点

F-Stack 把 FreeBSD 内核协议栈剥离出来跑在 DPDK 用户态。协议栈不是自己写的，是从 FreeBSD 上游裁剪出来的——F-Stack v1.25 对齐的是 FreeBSD 13.0-RELEASE-p2，而 FreeBSD 15.0-RELEASE 已于 2025 年正式发布，中间跨过 14.0/14.1/14.2/14.3/14.4 共 6 个版本、约 4 年演进。F-Stack 2.0 要做的就是把这份"裁剪子集"从 13.0 基线整体升级到 15.0 基线。

为什么必须升？继续停在 13.0，就吃不到上游的安全修复、性能改进（TCP 栈演进）和新驱动支持，而且会越来越远离社区。但这个升级的难点在于：13→15 之间网络栈核心发生了多处 P0 级 KBI/KPI 破坏性变更，**不是打 patch 能搞定的，必须基于 15.0 源码把 F-Stack 的裁剪+改造手法重新做一遍**。

主要特点：

- **裁剪重做**：F-Stack 的 freebsd/ 子树是从上游 sys/ 精选的子集（25 个顶层子目录、18000+ 文件），升级=在 15.0 源码上重做一遍"裁剪 + FSTACK 化改造"，而不是 diff 搬运
- **分层里程碑**：M1 基础设施 → M2 kern → M3 网络栈 → M4 胶水层 ABI → M5 全验收，每个里程碑都有编译门禁和打回链，滚雪球式推进
- **功能等价对齐**：本次只做"对齐"不做"扩能"——15.0 的新能力（netlink、ML-KEM 抗量子等）明确不引入，保证升级后的行为与 13.0 基线等价可比

2. 本功能的主要适用场景

2.1 想跟进上游安全修复和生产演进的生产部署

这是最主要的场景。FreeBSD 13.0 的安全支持周期有限，协议栈里的安全修复、性能补丁持续在 14.x/15.0 合入。生产环境要长期维护，就必须跟上。升级后 F-Stack 2.0 对齐 15.0-RELEASE-p9，`__FreeBSD_version` 从 1300139 到 1500068。

2.2 需要新硬件/新驱动支持的环境

15.0 的驱动栈和 DPDK 适配面比 13.0 时代宽得多。虽然 F-Stack 的 DPDK 侧驱动来自 DPDK 本身，但协议栈对 NIC offload、TSO/LRO、RACK 等能力的支撑在 15.0 都有演进。

2.3 多进程/多队列生产部署（升级后重点验证面）

升级项目在 1 primary + N secondary 经典部署上做了全套验收：编译矩阵（默认/FF_IPFW/FF_NETGRAPH/FF_USE_PAGE_ARRAY/FF_KNI）、9 项运行时功能验收、13.0 vs 15.0 双基线性能对照，全部有数据可查。

2.4 不太适合的场景

- 只是想体验 15.0 新特性（netlink、抗量子加密等）——本次升级明确"只对齐不扩能"，这些新能力不在范围内
- 依赖 mips 架构的场景——mips 在 FreeBSD 14.0 已整体移除，升级必须接受
- 期望升级后性能大涨——实测 13.0 vs 15.0 是持平略降（详见 4.6/5.2），升级的收益是安全性和演进可持续性，不是性能

3. 本功能的架构特征

3.1 F-Stack 的"裁剪+改造"模型

理解这次升级，先看 F-Stack 的源码组织。F-Stack 不是把 FreeBSD 整个搬进用户态，而是：

```
FreeBSD sys/ 全集（13.0: 含 mips；15.0: 含 netlink）
   │
   │ 裁剪：只保留协议栈相关子集
   │   kern / net / netinet / netinet6 / netipsec / netgraph / vm /
   │   libkern / opencrypto / amd64 / x86 / arm64 / ...
   ▼
f-stack/freebsd/（25 顶层子目录，18000+ 文件）
   │
   │ FSTACK 化改造（9 大手法）
   │   FSTACK-stub：用 #ifndef FSTACK 短路 host 耦合函数
   │   FSTACK-altimpl：#ifdef FSTACK 走备选实现
   │   IPC-replace：ff_ipc_* 替换 raw socket/sysctl
   │   胶水文件：ff_*.c/.h（44 个）替换 VFS/进程/信号等
   ▼
libfstack.a（用户态协议栈库）+ DPDK NIC I/O
```

升级的本质：13.0 基线上做的这层"裁剪+改造"，要在 15.0 基线上**重新做一遍**——因为 13→15 网络栈核心 KBI/KPI 已经多处不兼容，13.0 的 patch 直接打到 15.0 上根本不可能。

3.2 13→15 的核心 KBI/KPI 破坏清单

这是升级的"地雷图"，全项目风险清单的骨架：

| 变更 | 13.0 | 15.0 | 对 F-Stack 的冲击 |
|------|------|------|-------------------|
| pr_usrreqs 合并 | 独立 `struct pr_usrreqs` 向量表 | 合并进 `struct protosw` | P0：所有协议注册代码重写 |
| inpcb 并发保护 | epoch | SMR | P0：inpcb 生命周期改造 |
| if_t 不透明化 | 内核 API 暴露 `struct ifnet *` | `if_t` + `if_get*/if_set*` 访问函数 | P0：所有直接字段访问要改 |
| mbuf 布局 | m_pkthdr/m_ext 旧布局 | 字段调整 | P0：偏移依赖全部失效 |
| 路由子系统 | 传统 route | fib_algo/rib 重写 + netlink 新增 | P0：rib/nexthop 重写是最大单点 |
| mips 架构 | 存在（586 文件） | 14.0 整体移除 | P0 任务：清理子树和 Makefile 分支 |
| TCP 栈 | 单一 tcp_output | stacks 框架 vtable + RACK/BBR 可选栈（15.0 默认栈仍为 freebsd default，RACK 更成熟但未默认启用） | P0：TCP 路径适配 |
| 工具链 | clang/llvm 11 | clang/llvm 19（要求 GCC ≥ 9） | P1：C11 _Atomic 依赖 |
| syscall 表 | SYS_MAXSYSCALL=580 | 599（+22/-3） | P3：compat shim 处理 |

3.3 里程碑分层推进模型

升级不是一把梭，按依赖关系切成 5 个里程碑，每个里程碑末有编译门禁，失败打回：

```
M1 基础设施：mips 清理 + 头文件基线 + libkern/opencrypto 等 cp -a
   │  G-M1: 编译矩阵默认格通过
   ▼
M2 kern：10 个 kern 文件 5 步法应用（subr_*.c、kern_*.c）
   │  G-M2: KERN_SRCS 编译通过
   ▼
M3 网络栈：netinet/netinet6 4 梯度并行
   │  G-M3: libff.a 完整编译 + TCP/UDP echo 拉起
   ▼
M4 胶水层：lib/ff_*.c 对 15.0 ABI 适配（R-013/R-004）
   │  G-M4: 编译矩阵全格 + 4 TC
   ▼
M5 全验收：9 TC 功能 + 性能基线 + reviewer 签字
   │  G-M5/G-Acceptance
   ▼
Phase-2 扩能（M6-M13）：FF_NETGRAPH/FF_IPFW/PA/ZC 等配置开关
```

4. 具体做了哪些改造、遇到了哪些问题

后续比较枯燥，不需要深入研究实现过程的可以跳过本节，直接看第 5 节怎么用。

4.1 起点：双版本源码基线与 diff 计划

升级的第一步不是写代码，是把三个源码根摆齐（实测版本号：13.0 = RELEASE-p2、15.0 = RELEASE-p9）：社区 13.0 全集、社区 15.0 全集、F-Stack 工程（基于 13.0 改造）。然后建立 15.0 的 f-stack-lib 原始备份，逐文件 diff 出"13.0 FSTACK 定制在 15.0 基线上对应位置要重做什么"。这个 diff 计划直接决定了整个项目的改造面。

4.2 M1~M3：裁剪重做的滚雪球

M1 先把最基础的事干了：mips 子树 586 个文件清理（15.0 已移除该架构，不清理 build 链直接断）、libkern/opencrypto/vm 等子目录按 15.0 基线 cp -a、头文件基线对齐。

M2 用"5 步法"把 10 个 kern 文件逐文件应用到 15.0 基线：读 13.0 的 FSTACK 改造 → 在 15.0 对应文件重做 → 编译验证 → 打回修复 → 门禁。M3 是重头戏：netinet/netinet6 按 4 个梯度并行推进（in_pcb/in_pcbgroup 的 SMR 化、pr_usrreqs→protosw 合并、tcp stacks 框架、路由子系统 rib/nexthop 重写）。

【注1】路由子系统的 fib_algo/rib 重写是整个升级里最大的单点风险——FreeBSD 14/15 把传统路由表实现整个换掉了。M5 验收里 TC-08（ff_route add + ff_route get）专门盯这个点，最终确认 fib4_lookup 符号在 libfstack.a 里正常 defined 才算过。

4.3 问题一：helloworld 启动 hang（runtime-fix 阶段）

M5 验收通过后，真机拉起 helloworld 直接 hang 在 "Port 0 Link Up" 之后，4 线程 R+ 状态 busy-loop。gdb attach 拿全栈：死循环在 `uma_small_alloc → zone_import → zone_alloc_item → zone_ctor → uma_startup1`。

根因挖出来是一个"改名没跟上"的经典坑：FreeBSD 14.0 把 UMA_MD_SMALL_ALLOC 宏重命名为 UMA_USE_DMAP，F-Stack 在 13.0 基线里对这个宏有 `#ifndef FSTACK` 包裹（用户态不用 DMAP 直映射），但升级时这个包裹丢了。后果：uma keg 选了 uma_small_alloc 路径 → vm_page_alloc_noobj_domain 是个 stub 返回 NULL → keg_fetch_slab 在 M_WAITOK 下死等内存永远等不到。

同阶段还揪出两个同源问题：smr_create 里 atomic 屏障走内核 %gs 路径在用户态 SEGV、rtbridge 的 rtsock/netlink callback stub 是 NULL 被 rt_ifmsg 解引用。修复原则是"一根因一 commit"，3 个根因 3 个 commit，加一个 panic 防御性硬化。

【注2】这个坑值得单独记一笔：它告诉我们"宏改名"这种看似无害的上游演进，对裁剪式派生工程就是致命的——派生代码对上游符号的每个 #ifdef 包裹，升级时都要逐一点名核对。

4.4 问题二：ff_config.h 头改动未 clean 重编的 ABI 偏斜

这是 M3 阶段踩的构建卫生坑，跟内核栈共存功能（FF_KERNEL_COEXIST）的 kernel_coexist 字段同源：给结构体加字段改变了后续成员的偏移，而 Makefile 不跟踪头依赖，增量编译混用了新旧布局的 .o，运行时 fclose 直接段错误。教训写进了强制规约：改结构头必须 make clean 全量重编。升级项目从 M3 末开始就把"每修一处必跑 make clean && make"固化成流水线铁律。

4.5 问题三：性能 9% gap 的归因（13.0 vs 15.0 双基线）

性能基线对照出来一个必须交代的数字：helloworld 场景 15.0 比 13.0 吞吐低 7.59%（T2 t4c100）~9.37%（T3 t8c500），p99 尾部恶化 27.8%（T3）。这不是能糊弄过去的，项目做了根因分析：

| 真凶（13→15 vendor 演进） | 占比 |
|--------------------------|------|
| TCP stacks 框架 vtable 派发（tcp_output → tcp_default_output） | 主因 ~+1% |
| TCP CUBIC 拥塞控制状态机扩展 | ~+0.6% |
| socket buffer locking 重构 | ~+1.5% |

结论：9% gap 不是升级改造引入的回归，是 FreeBSD 15.0 上游本身的演进成本（换来了 RACK/BBR 栈框架等能力）。nginx/redis 等真实工作负载下差异收窄到基本持平。

4.6 Phase-2：把 15.0 的能力重新点亮

升级主体完成后，Phase-2 把 F-Stack 的编译期配置开关在 15.0 基线上重新验证/点亮：FF_NETGRAPH（41 个 netgraph 节点）+ FF_IPFW（14 个内核对象，25MB 的 ipfw 用户态二进制）、FF_USE_PAGE_ARRAY（256MB 一次性 mmap）、FF_ZC_SEND（零拷贝发送）、PA+ZC 组合、FF_FLOW_IPIP（GIF 隧道软退化）、FF_FLOW_ISOLATE/FF_FDIR/FF_LOOPBACK_SUPPORT 冒烟三件套。每个开关一个里程碑、一次编译+运行验证。

其中 FF_USE_PAGE_ARRAY 单独启用时还触发了一个 panic（F-A1），修复为 soft drop 后，C0/C7/C8/C9 四个生产配置全部 production-ready。

4.7 遗留的 follow-up

项目收尾时归档了 13 项 follow-up，全部不阻塞交付：vlan 测试系列 5 项（vlan_filter_id 硬件下推等）、FDIR 容量上限物理机验证、spec 系列英译等。英文版 spec 按计划"待人工审计后再考虑"。

5. 如何使用、如何配置、使用效果

5.1 使用方式（对 F-Stack 用户）

升级是"协议栈底座"的更换，**使用方式完全不变**：还是 `cd f-stack/lib && make clean && make` 编译 libfstack.a，config.ini 配置不变，ff_* API 不变。这就是"功能等价对齐"的交付承诺——上层应用无感知。

编译期配置开关在 15.0 基线上的验证矩阵（5 格全 PASS）：

| 配置 | 说明 | libfstack.a |
|------|------|-------------|
| 默认 | x86_64 默认 KNOB | 5.2M / 193 .o |
| FF_IPFW=1 | ipfw 防火墙 | 5.5M / 206 .o |
| FF_NETGRAPH=1 | netgraph 框架 | 5.9M / 250 .o |
| FF_USE_PAGE_ARRAY=1 | page array 内存 | 5.2M / 207 .o |
| FF_KNI=1 | KNI 接口 | 5.2M / 207 .o |

5.2 使用效果

功能验收（9 TC 全 PASS）：TCP/UDP echo（v4/v6）、ff_ifconfig、ff_netstat、ff_ipfw、ff_route add/get（rib 重写回归）、ff_ngctl 全部编译拉起通过。真机双基线（同硬件同分钟 A/B 对照）：

| 场景 | 13.0 req/s | 15.0 req/s | Δ 吞吐 | Δ p99 |
|------|-----------:|-----------:|-------:|------:|
| T1 t2c10 | 24,414 | 23,757 | −2.69% | +39.7% |
| T2 t4c100 | 220,691 | 203,933 | −7.59% | +2.0% |
| T3 t8c500 | 239,555 | 217,100 | −9.37% | +27.8% |

helloworld 微基准下 15.0 有 7~9% 的吞吐差（根因见 4.5，属上游演进成本非回归）；nginx/redis 真实负载下基本持平。Phase-5b 矩阵结论：C0/C7/C8/C9 四个生产配置全部 production-ready，推荐 C8（ZC-only）为生产首选。

5.3 对升级者/二次开发者的价值

如果你也想做类似的大版本跳跃升级，这套 spec 值得看的地方：里程碑分层 + 编译门禁 + 打回链的组织方式（累计打回 0~3 次、从未触发暂停）、"裁剪+改造"手法清单（FSTACK-stub/altimpl/IPC-replace 等 9 大手法）、P0 风险清单与两维度优先级约定（风险等级 vs 任务优先级分开标）、以及三个实打实的坑（宏改名丢包裹、结构头 ABI 偏斜、性能 gap 归因）。

延伸阅读：

- 项目收尾全景：docs/freebsd_13_to_15_upgrade_spec/zh_cn/00-project-closure.md
- 变更清单：docs/freebsd_13_to_15_upgrade_spec/zh_cn/03-freebsd-15-changes.md
- 启动 hang 调试：docs/freebsd_13_to_15_upgrade_spec/zh_cn/runtime-fix-execution-log.md
- 双基线性能：docs/freebsd_13_to_15_upgrade_spec/zh_cn/13.0-baseline-cvm-bench-report.md
- 三层架构文档：docs/zh_cn/01-LAYER1-ARCHITECTURE.md
- 知识图谱：docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md
