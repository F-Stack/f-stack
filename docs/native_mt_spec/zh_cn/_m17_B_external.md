# M17-B 外网调研：SMP-aware per-cpu 视图 / SMR 独占性 / 用户态 per-CPU 仿真 / 去全局锁

> 调研人：`res-web`（外网资料交叉调研 agent，team `ff-smp-aware`）
> 时间：2026-08-04
> 任务来源：team-lead（plan-17M1-B）
> 上一轮外网调研（`_m1_B_external.md`）主题为 **virtio-net多队列入向分发**，与本轮无重叠，本文不重复其内容。
>
> **边界声明**：
> 1. 本 agent **未修改任何源码**，只写本文件。
> 2. 每条结论后紧跟 `来源：<URL>`。凡属**机制推导**（非文献直述）一律显式标注。
> 3. 与f-stack 实际代码可能冲突的说法，标注「**需与代码交叉验证（以代码为准）**」。
> 4. 搜不到可靠来源的条目如实写「**未找到可靠来源**」，不编造 URL 或内容。
>
> **进度**：本文分批落盘。当前状态见文末「落盘进度」一节。
> **节次顺序说明**：小节编号 `§1~§5` 对应 team-lead 给的 5 个调研方向编号（编号不变以便对照）。因分两批落盘，文中物理顺序为 **§1 → §2 → §5 → §3 → §4 → §6（知识边界）→ §7（来源清单）**。

---

## 0. 结论速览（TL;DR，按 plan-17 的 U 编号对应）

| # | 结论 | 置信度 | 对应节|
|---|---|---|---|
| E1 | **SMR 的 per-CPU `c_seq` 槽位独占性是硬假设**，且上游用 `critical_enter()`（禁抢占 + 禁迁移）+ `KASSERT(c_seq == 0)`（禁递归）双重保障。两个线程共享同一 `c_seq` 槽位时，**非 INVARIANTS 构建下断言被编译掉**，A 线程 `smr_exit()` 会把仍在读区间的 B 线程的 `c_seq` 清成 `SMR_SEQ_INVALID` → `smr_poll_scan()` 判该CPU inactive → 提前推进 `s_rd_seq` → **UMA 提前复用内存 → UAF**。这与 plan-17 §0.1「理论 UAF 窗口」的判断**完全吻合，且可由上游源码逐行坐实** | 高（上游源码原文 + man页） | §2.1、§2.2 |
| E2 | `smr_enter()`/`smr_exit()` **本身就包含** `critical_enter()`/`critical_exit()`，调用者**不需要**额外关抢占；man 页明确「读区间内上下文切换被禁用、线程被 pin 在当前 CPU」 | 高（smr.h 源码 + smr(9)） | §2.2 |
| E3 | `UMA_ZONE_PCPU` 的语义是「一次分配产生 `mp_ncpus` 份影子副本」；uma(9) **明确要求 `zpcpu_get()` 必须在 `critical_enter()/critical_exit()` 之间访问**。这意味着 G2（移除 `uma_crit_lock`）不能简单等同于「上游也没锁」——上游有关抢占，f-stack 用户态没有，必须另行论证等价性 | 高（uma(9) 原文示例代码） | §2.3 |
| E4 | `smr_create()` 的 `for (i = 0; i <= mp_maxid; i++)` 与 `smr_poll_scan()` 的 `CPU_FOREACH(i)` 是 `mp_maxid` 与 `UMA_ZONE_PCPU` **必须成对修改**的上游依据；`counter(9)` 的 `counter_u64_fetch()` 也「遍历所有 per-CPU 字段」 | 高（上游源码 + counter(9)） | §2.4、§2.5 |
| E5 | **用户态 `MAXCPU` 恒为 1 是 FreeBSD 上游的有意设计**，官方 commit message 直陈：「用户态 `MAXCPU` 通常为 1，因为把它设为更大的 MD 值的前提是定义了 `SMP`，而用户态一般不定义 `SMP`」。这正是 f-stack 现状（`#else → MAXCPU 1`）的成因 | 高（FreeBSD 官方 commit message 原文） | §5.1 |
| E6 | `cpuset_t` 宽度由 `CPU_SETSIZE` 决定，**内核侧 `CPU_SETSIZE == MAXCPU`**；改 `MAXCPU` 会改变 `cpuset_t` 结构大小 → 改变所有含 `cpuset_t` 的结构体布局 → **KBI 破裂**，必须全树重编。FreeBSD 官方把 amd64 MAXCPU 从 256 提到 1024 时，正是因为 ABI/KBI 稳定性约束而必须在 14.0 发布前一次做完 | 高（cpuset(9) + commit + 官方季度报告） | §5.2、§5.3 |
| E7 | f-stack 官方仓库：**未找到任何**关于 SMR / UMA per-cpu 槽位 / `pcpu_init` cpuid / MAXCPU /定义 SMP 的 issue 或 PR 讨论。已找到的唯一相关 issue（#27，2017）是 7 年前基于 FreeBSD 11 的「单进程多线程跑协议栈 → `curthread` 为 NULL → segfault」，**时代与代码基础都与本轮不同**，且评论区抓取失败 | 中高（多次检索无果+ 单一旧 issue） | §1|
| E8 | 「其他用户态 FreeBSD/NetBSD 栈如何伪造 per-CPU 视图」——**部分方向未找到可靠来源**，详见 §3 各小节的逐条标注 | — | §3 |

---

## 1. 方向1：f-stack 官方/社区关于「单进程多线程」「per-cpu」「UMA/SMR」的讨论

### 1.1 唯一找到的直接相关 issue：#27（2017-06-05，Closed）

**来源**：https://github.com/F-Stack/f-stack/issues/27

抓取到的 issue **正文**要点（原文要点转述）：

- 提问者（`taoswords`）依据 `start.sh` 判断 f-stack 是「单进程绑单核」模型，尝试改为「1 进程 + 多核 + 多线程」：
  `sudo ./demo ./config.ini -c 0x3 --proc-type=primary --num-procs=1 --proc-id=0`
- 结果协议栈 **segment fault**。
- GDB 结论：传给 `ff_syscall_wrapper` 的 **`curthread` 为 0（NULL）**；slave core 上调用 `ff_epoll_create` → `ff_kqueue` 即崩。
- 诉求：为什么 slave core 上 `curthread` 是 0、代码中何处赋值。

**重要限制（如实声明）**：本次抓取**只拿到 issue 正文，评论区未加载成功**（页面反复出现 "There was an error while loading. Please reload this page."）。因此 **f-stack 维护者对该问题的具体回复内容无法确认，本文不做任何推测**。

> 与本轮的关系：#27 的现象（`curthread == NULL`）是 **per-thread `pcpup`/`curthread` 未初始化**的问题，f-stack 现状（`__thread struct pcpu *pcpup` + `ff_pcpu_thread_init()`）已经解决了这一层；本轮要解决的是**更深一层的「pcpu 槽位共享」**。#27 **不能**作为本轮方案的参考。

### 1.2 f-stack 官方文档中对 pcpu/curthread 的移植描述

**来源**：F-Stack Development Guide（社区转载版）
- https://rtoax.blog.csdn.net/article/details/107987976
- https://www.codeleading.com/article/50794435172/

该 Development Guide 在「FreeBSD 协议栈移植改造点」清单中明确列出了以下条目（原文英文条目）：

```
pcpu
curthread
proc0
thread0, initialization
```

以及（中文社区转述，来源见下）改造范围：

> 1) 调度：对 FreeBSD Network Stack 的内核线程、中断线程、定时器线程、sched、sleep 等进行了去除。
> 2) 锁：对 FreeBSD Network Stack 的 mtx、rw、rm、sx、cond 等各种锁操作进行了裁剪。
> 3) 内存管理：重构 phymem、uma_page_slab_hash 等内存管理模块。
> 4) 全局变量：优化 pcpu、curthread 等全局变量。

**来源**：
- https://blog.csdn.net/21cnbao/article/details/105803864（2020-04-27）
- https://blog.csdn.net/gitblog_01019/article/details/148549951 （2025-06-10）
- https://zhuanlan.zhihu.com/p/376144528 （2021-05-28）

**交叉验证意义**：这些资料**佐证了「f-stack 有意把 UMA / pcpu / 锁做了裁剪和单实例化」是其原始设计取向**（而非偶发缺陷），因此 plan-17 §1.4 中 `uma_int.h` 把 `critical_enter/exit` 换成全局自旋锁、`#undef UMA_MD_SMALL_ALLOC`、自造 `uma_page` hash 等做法，与该设计取向一致。
**需与代码交叉验证（以代码为准）**：上述均为二手中文博客的概括性描述，未给出 `file:line`；「重构 uma_page_slab_hash」「裁剪各种锁」的**具体范围**必须由 `res-code` 在本地代码中坐实，不得以博客描述为准。

### 1.3 f-stack 多线程化的第三方实践

- 知乎《将 F-Stack 改造为多线程库》（2025-02） — https://zhuanlan.zhihu.com/p/21075875679
  **本次抓取失败（HTTP 403 Forbidden，知乎反爬）**。搜索结果摘要只显示「F-Stack 提供 posix-api……但现存应用大多是多线程」等背景性文字，**未见任何关于 per-cpu / UMA / SMR / MAXCPU 的内容**。
  **如实声明：该文正文内容本次未能获取，不做任何引用性结论。**
- 《使用 Photon 协程库与 F-Stack 简化 DPDK 应用开发》 — https://developer.aliyun.com/article/1208390 （2023-05-10）
  该文走的是**协程 / 多执行单元**方向，与「多线程共享一个协议栈实例的 per-cpu 视图」不是同一问题层次。**不构成本轮参考。**

### 1.4 检索「SMR / UMA per-cpu 槽位 / pcpu_init cpuid / MAXCPU / -DSMP」在 f-stack 社区的讨论

**未找到可靠来源。** 检索覆盖：
- GitHub F-Stack/f-stack 的 issue 与 PR（关键词组合：`multi-thread` / `single process multiple cores` / `per-cpu` / `UMA` / `SMR` / `pcpu` / `MAXCPU` / `SMP` / `curthread`）；
- f-stack.org 官网与Development Guide；
- 中文技术社区（CSDN / 知乎 / 博客园 / 简书 / 腾讯云社区 / 阿里云开发者社区）。

**结论：公开资料中没有任何人讨论过「f-stack 让内核视图 SMP-aware /给每个 worker 分配独立 pcpu 槽位 / 移除 UMA 全局自旋锁」这一具体问题。** 本轮属无先例改造，**不能指望外网提供现成方案，必须以本地代码实证为唯一依据**。

另需注意一个**时代性事实**：f-stack 官网与 README 描述其移植的是 **FreeBSD 11.0 stable**（来源：http://f-stack.org/ ；https://github.com/F-Stack/f-stack）。而本仓库已升级到 **FreeBSD 15.0**。**SMR（GUS）子系统是 FreeBSD 12/13 时代（2019–2020，Jeffrey Roberson）才引入的**（版权年份见 §2 源码原文），因此**所有基于 FreeBSD 11 的 f-stack 公开经验都不涉及 SMR**——这解释了为什么社区无先例可循。
来源：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c （文件头 `Copyright (c) 2019,2020 Jeffrey Roberson`）；http://f-stack.org/

---

## 2. 方向2：FreeBSD 上游语义（SMR / UMA_ZONE_PCPU / mp_maxid / MAXCPU）

> 本节所有源码引用均取自 GitHub 官方镜像 `freebsd/freebsd-src` 的 `main` 分支 raw 文本（`cgit.freebsd.org` 有 Anubis 反爬，抓取失败，已改用镜像）。
> **需与代码交叉验证（以代码为准）**：本仓库参照树是 `releng/15.0`，而下述引用来自 `main`。SMR 核心逻辑在 13→15→main 之间未见结构性改动（本文引用的 `critical_enter`/`c_seq`/`mp_maxid` 循环等关键点），但**具体行号与细节须由 `res-code` 在 `/data/workspace/freebsd-src-releng-15.0` 中复核**。

### 2.1 SMR 对 per-CPU `c_seq` 槽位的独占性假设——上游源码坐实

**来源**：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/sys/smr.h

`struct smr`（per-CPU 状态，用 `zpcpu` 分配）：

```c
struct smr {
    smr_seq_t    c_seq;      /* 本 CPU 当前观测到的写序号；0 (SMR_SEQ_INVALID) = 不在读区间 */
    smr_shared_t c_shared;
    int c_deferred, c_limit, c_flags;
};
```

`smr_enter()` 原文（关键三行）：

```c
static inline void
smr_enter(smr_t smr)
{
    critical_enter();/* ① 关抢占，把线程钉在当前 CPU */
    smr = zpcpu_get(smr);                /* ② 取本 CPU 的 struct smr */

    KASSERT((smr->c_flags & SMR_LAZY) == 0, ...);
    KASSERT(smr->c_seq == 0, ("smr_enter(%s) does not support recursion.", ...));

#if defined(__amd64__) || defined(__i386__)
    atomic_add_acq_int(&smr->c_seq, smr_shared_current(smr->c_shared));
#else
    atomic_store_int(&smr->c_seq, smr_shared_current(smr->c_shared));
    atomic_thread_fence_seq_cst();
#endif
}
```

`smr_exit()` 原文：

```c
static inline void
smr_exit(smr_t smr)
{
    smr = zpcpu_get(smr);
    CRITICAL_ASSERT(curthread);
    KASSERT((smr->c_flags & SMR_LAZY) == 0, ...);
    KASSERT(smr->c_seq != SMR_SEQ_INVALID, ("smr_exit(%s) not in a smr section.", ...));

    atomic_store_rel_int(&smr->c_seq, SMR_SEQ_INVALID);   /* 无条件清成 INVALID */
    critical_exit();
}
```

**独占性假设的三条硬证据**：

1. **x86 快路径依赖「进入时 `c_seq` 必为 0」**。源码注释说明：因为 `SMR_SEQ_INVALID == 0`，进入读区间时 `c_seq` 必然为 0，所以可以用一条 `atomic_add_acq_int`（locked add）同时完成「写入序号」和「提供全序屏障」。
   → **若槽位被共享**：线程 B 进入时 `c_seq` 已被线程 A 置为非0，`atomic_add`会把 **A 的序号 + B 的序号相加**，得到一个**完全无意义的序号值**（不是 B 想观测的值，也不是 A 的值）。这是比「覆盖」更糟的破坏形式：得到的值可能远大于 `s_wr_seq`。
   > 标注为「源码语义推导」：源码注释明确了「进入时必为 0」这一前提与 `atomic_add` 优化的因果关系；「共享槽位下 add 会累加成垃圾值」是该前提被违反时的直接算术后果，**属推导，非文献直述**。**需与代码交叉验证（以代码为准）**：f-stack 编译目标是 amd64，故走的正是 `atomic_add_acq_int` 这条分支，须由 `res-code` 确认 `__amd64__` 分支确实被编译进来。

2. **不支持递归的断言**：`KASSERT(smr->c_seq == 0, "does not support recursion")`。`c_seq` 只有「0 / 非 0」两态，**无嵌套计数**。两个线程共享槽位，在语义上等价于「递归进入」——而这被上游明文禁止。
   → **致命点**：`KASSERT` 在**未定义 `INVARIANTS`** 的构建中被编译为空（plan-17 §1.2 已核实 f-stack 未定义 `INVARIANTS`），因此这个本该拦住问题的断言在 f-stack 中**完全不存在**，破坏只会以静默的内存损坏形式出现。

3. **`smr_exit()` 无条件清 `SMR_SEQ_INVALID`**，不做任何「是不是我自己进入的」检查。
   → **UAF 链条（推导，但每一环都有源码支撑）**：
   `worker A: smr_enter()` → `c_seq = S1`
   `worker B: smr_enter()` → `c_seq = S1 + S2`（或在非 x86 路径下被覆盖为 `S2`）
   `worker A: smr_exit()` → `c_seq = SMR_SEQ_INVALID`（**B 仍在读区间**）
   写者 `smr_poll()` → `smr_poll_cpu()` 见 `c_seq == SMR_SEQ_INVALID` → `break`，该 CPU 被判为**inactive**（等价于「已观测到 wr_seq」）→ `smr_poll_scan()` 把 `s_rd_seq` 推进到 `s_wr_seq` → `uma_zfree_smr()` 判定 grace period 结束 → **内存被复用，而 B 仍持有指向它的指针 → UAF**。

**`smr_poll_cpu()` 原文（坐实「INVALID ⇒ 该 CPU 无活跃读者」）**：

```c
static smr_seq_t
smr_poll_cpu(smr_t c, smr_seq_t s_rd_seq, smr_seq_t goal, bool wait)
{
    smr_seq_t c_seq;

    c_seq = SMR_SEQ_INVALID;
    for (;;) {
        c_seq = atomic_load_int(&c->c_seq);
        if (c_seq == SMR_SEQ_INVALID)
            break;                       /* ← 判定该 cpu 不在读区间 */
        ...
    }
    return (c_seq);
}
```

以及 `smr_poll_scan()` 中：

```c
        if (c_seq != SMR_SEQ_INVALID)
            rd_seq = SMR_SEQ_MIN(rd_seq, c_seq);   /* INVALID 的 cpu 不参与拉低 rd_seq */
```

来源（以上三段均出自）：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c

**与 plan-17 §0.1 的一致性**：plan-17 写的是「SMR 的 per-CPU 序号被多线程互相覆盖，可能过早判定 grace period 结束而回收仍被引用的 PCB」——**方向完全正确**。本节补充的是：在 amd64 上机制不是简单「覆盖」而是 `atomic_add` **累加**，且真正触发提前回收的更直接路径是 **`smr_exit()` 把仍在读区间的另一线程的槽位清成 INVALID**。建议 spec 17 采用后一描述（更精确、且可由源码逐行坐实）。

### 2.2 `smr_enter/smr_exit` 是否要求关抢占、为什么

**答：要求，且 `smr_enter()` 自己就做了 `critical_enter()`，调用者不需额外加。**

smr(9) man 页（FreeBSD 15.0，2023-01-17，作者 Mark Johnston；算法作者 Jeff Roberson）在Readers 一节明确：

- 读临界区内**上下文切换被禁用（context switching is disabled）**；
- 因此读者**不能获取可阻塞的互斥体**（如 `mutex(9)`）；
- 直接后果是 **线程在整个读临界区期间被 pin 在当前 CPU 上**（不会发生线程迁移）；
- `smr_enter()` **永不阻塞**；具acquire 语义，`smr_exit()` 具 release 语义；
- `smr_enter()`/`smr_exit()` **仅操作 per-CPU 数据**，这是其性能优势的来源；写者则**必须扫描所有 CPU 的 per-CPU 状态**以检测活跃读者。
- **不允许嵌套**。

来源：https://man.freebsd.org/cgi/man.cgi?query=smr&sektion=9&manpath=FreeBSD+15.0-RELEASE

**为什么需要**（`smr.h` 源码注释侧重内存序，未逐字论述临界区必要性；以下三条为**基于源码的归纳**，标注为推导）：

1. **保证 `smr_enter()` 与 `smr_exit()` 操作同一份 per-CPU 状态**。若线程在两者之间被抢占并迁移到另一个 CPU，`zpcpu_get()` 会返回**不同**的 `struct smr`：一边残留非零 `c_seq`（永久卡住 `rd_seq`，内存无限膨胀），另一边被误清零（提前回收 → UAF）。
2. **保证读区间短而有界**。`smr_poll_scan()` 取各 CPU `c_seq` 的最小值决定可回收序号；读者若能被长时间调度出去，`rd_seq` 会被卡住。
3. **约束使用方式**：临界区内不可睡眠、不可取可睡眠锁，使 `c_seq` 的「0/非 0」两态简化设计成为安全的。

写侧同样依赖临界区，且上游给出了**明确的理由注释**：

```c
    /*
     * Use a critical section so that we can avoid ABA races
     * caused by long preemption sleeps.
     */
    success = true;
    critical_enter();
```
（`smr_poll()`）

以及 `smr_advance()`：

```c
    SMR_ASSERT_NOT_ENTERED(smr);
    atomic_thread_fence_rel();
    critical_enter();
    self = zpcpu_get(smr);
    ...
    critical_exit();
```

而 `smr_lazy_advance()`、`smr_default_advance()`、`smr_poll_scan()` 三处均以 **`CRITICAL_ASSERT(curthread)`** 开头——即上游把「必须在临界区内」写成了断言。
来源：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c

> **对 G2 的直接含义（重要）**：plan-17 §1.4 记录 f-stack 在 `lib/include/vm/uma_int.h`把 `critical_enter/exit` 宏替换成了全局自旋锁。若该覆盖是**全局可见**的（而非仅限UMA 编译单元），那么 `smr.h` 里的 `critical_enter()` 也会被替换成抢全局锁 —— 这会让 **SMR 读区间也串行化**。**需与代码交叉验证（以代码为准）**：该宏覆盖的**实际作用域**（是否被 `subr_smr.c`/`smr.h` 的编译单元看到）必须由 `res-code` 用 `gcc -E` 预处理坐实，这直接决定 G2 移除全局锁后 SMR 读区间是否失去任何保护。

### 2.3 `UMA_ZONE_PCPU` 的语义与 `zpcpu_get` 的前置条件

uma(9) man 页（FreeBSD 15.0，2023-01-16）原文要点：

- **`UMA_ZONE_PCPU` 语义**：从此类 zone 的**一次分配**会产生 **`mp_ncpu` 个影子副本（shadow copies）**，分别私有归属各CPU。
- **访问方式**：以分配返回的基地址加上「当前 CPU ID × `sizeof(struct pcpu)`」得到本 CPU 副本；实际代码用 `zpcpu_get()` 宏，且**必须在临界区内访问**。man 页给出的示例代码就是：

  ```c
  foo_zone = uma_zcreate(..., UMA_ZONE_PCPU);
  foo_base = uma_zalloc(foo_zone, ...);
  ...
  critical_enter();
  foo_pcpu = (foo_t *)zpcpu_get(foo_base);
  /* do something with foo_pcpu */
  critical_exit();
  ```

- **限制**：`M_ZERO` **不能**用于 PCPU zone 的 `uma_zalloc()`；需要零初始化的 per-CPU 内存必须用 `uma_zalloc_pcpu()` 系列并传 `M_ZERO`。
- `uma_zalloc_pcpu()` / `uma_zfree_pcpu()` 按上述语义**分配/释放 `mp_ncpu` 份影子副本**。
- **`UMA_ZONE_SMR`**：zone 中 item 用 smr(9) 同步；创建时自动关联一个 `smr_t`，可用 `uma_zone_get_smr()` 取回。`uma_zone_set_smr()` 可关联既有 SMR 结构，**必须在该 zone 发生任何分配之前调用**。
- `uma_zfree_smr()` **会等待所有可能正在访问该 item 的活跃读者退出读临界区后才回收内存**。
- 每个 zone 维护 **per-CPU 缓存**，在 SMP 系统上具备线性可扩展性；per-CPU 缓存中缓存的 item 数量有上界；另有一个无界缓存用于快速满足 per-CPU 缓存未命中。
- 回收语义：`UMA_RECLAIM_DRAIN` 清空无界缓存但**per-CPU 缓存中的空闲项保持不动**；`UMA_RECLAIM_DRAIN_CPU` 才回收 per-CPU 缓存。

来源：https://man.freebsd.org/cgi/man.cgi?query=uma&sektion=9&manpath=FreeBSD+15.0-RELEASE

**对本轮的三条关键含义**：

1. **`mp_ncpus` 与 `mp_maxid` 是 per-cpu 分配尺寸的唯一依据**，plan-17 §1.3「`mp_maxid` 与 `UMA_ZONE_PCPU` 必须成对修改」这一约束**得到上游文档正面支撑**。
2. **官方文档层面明确要求 `zpcpu_get()` 在临界区内使用**。因此 G2「移除 `uma_crit_lock`」在文档语义上等价于「移除上游要求的保护」，**必须以「每线程独占槽位 + 线程不迁移」作为等价性论证**（见 §4），而不能以「上游 UMA 快路径无锁」为理由——上游快路径不是无保护，而是靠禁抢占。
3. `UMA_ZONE_SMR` + `uma_zfree_smr()` 的「等待活跃读者」正是 §2.1 UAF 链条的最后一环，**PCB 回收路径的语义由此闭合**。

### 2.4 `mp_maxid` / `mp_ncpus` / `cpuid_to_pcpu[]` 的上游约束

**（a）`smr_create()` 明确按 `mp_maxid` 初始化「所有 CPU，不只是运行中的」**：

```c
smr_t
smr_create(const char *name, int limit, int flags)
{
    ...
    s   = uma_zalloc(smr_shared_zone, M_WAITOK);
    smr = uma_zalloc_pcpu(smr_zone, M_WAITOK);

    s->s_name = name;
    s->s_rd_seq = s->s_wr.seq = SMR_SEQ_INIT;
    s->s_wr.ticks = ticks;

    /* Initialize all CPUS, not just those running. */
    for (i = 0; i <= mp_maxid; i++) {
        c = zpcpu_get_cpu(smr, i);
        c->c_seq = SMR_SEQ_INVALID;
        c->c_shared = s;
        c->c_deferred = 0;
        c->c_limit = limit;
        c->c_flags = flags;
    }
    atomic_thread_fence_seq_cst();
    return (smr);
}
```

`smr_init()`：

```c
void
smr_init(void)
{
    smr_shared_zone = uma_zcreate("SMR SHARED", sizeof(struct smr_shared),
        NULL, NULL, NULL, NULL, (CACHE_LINE_SIZE * 2) - 1, 0);
    smr_zone = uma_zcreate("SMR CPU", sizeof(struct smr),
        NULL, NULL, NULL, NULL, (CACHE_LINE_SIZE * 2) - 1, UMA_ZONE_PCPU);
}
```

来源：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c
**与 plan-17 §1.3 记录的 `releng/15.0` 事实一致**（plan-17 记`:583-609`、`:625-632`），无冲突。

**（b）`smr_poll_scan()` 用 `CPU_FOREACH(i)` + `zpcpu_get_cpu(smr, i)` 扫描所有 CPU**：

```c
    rd_seq = s_wr_seq;
    CPU_FOREACH(i) {
        c_seq = smr_poll_cpu(zpcpu_get_cpu(smr, i), s_rd_seq, goal, wait);
        if (c_seq != SMR_SEQ_INVALID)
            rd_seq = SMR_SEQ_MIN(rd_seq, c_seq);
    }
```

来源：同上。

> **对本轮的关键含义（需与代码交叉验证，以代码为准）**：`CPU_FOREACH` 在上游依赖 `all_cpus` cpuset 与 `CPU_ABSENT`。plan-17 §1.2 记录 f-stack 在 `lib/ff_glue.c:143-147` 附近定义了 `cpuset_t all_cpus;`（BSS 零值）。**若 `all_cpus` 为全 0，则 `CPU_FOREACH` 可能一个 CPU 都不遍历**（取决于其非 SMP 展开形式）——那么 `smr_poll_scan()` 会把 `rd_seq` 直接推进到 `s_wr_seq`，**等价于「SMR 完全失效、立即回收」**，这比「槽位共享」严重得多。`res-code` **必须**用 `gcc -E`坐实 `CPU_FOREACH` 在 f-stack 非 SMP 构建下的实际展开，并核实 `all_cpus` 是否被初始化。这是本轮**优先级最高的待验证项**（本文标注为推导，不下结论）。
> 上游 `CPU_FOREACH` 定义在 `sys/sys/smp.h`（而非 `sys/cpuset.h`）—— cpuset(9) man 页的宏清单中**不包含** `CPU_FOREACH`，可佐证这一点。
> 来源：https://man.freebsd.org/cgi/man.cgi?query=cpuset&sektion=9&manpath=FreeBSD+15.0-RELEASE

**（c）`zpcpu_offset_cpu` / `pcpu(9)`**：
**`pcpu(9)` man 页未找到**（man.freebsd.org 上无该 section 9 手册页；smr(9)/uma(9)/counter(9)/cpuset(9) 均存在）。`zpcpu_get`/`zpcpu_get_cpu`/`zpcpu_offset_cpu` 的语义**只有源码是权威来源**（`sys/sys/pcpu.h`），plan-17 §1.1 已用 `file:line` 记录，本文不重复。**如实声明：pcpu(9) 无手册页可引。**

### 2.5 `counter(9)`：另一个 per-cpu 消费者的语义（对应 plan-17 §1.4 末尾）

counter(9) man 页（FreeBSD 15.0，2025-06-19，作者 Gleb Smirnoff / Konstantin Belousov）原文要点：

- counter 由 **per-CPU 数据字段**实现，特殊对齐以避免 false sharing；**分配使用 `UMA_ZONE_PCPU` uma(9) zone**。
-更新**只触碰当前 CPU 私有字段**，因此并发更新**无损（lossless）**，不用 atomic(9)，可用于任何非中断上下文。
- `counter_u64_add()` 的架构差异：
  - **amd64**：更新是**单条指令、无 lock 语义**，作用于当前 CPU 私有数据，因此对**抢占与中断天然安全**；
  - i386：有 `cmpxchg8` 时用之，提供同等保证；
  - **某些其他架构**：更新计数器**需要 critical(9) 临界区**。
- 批量更新用 `counter_enter()` / `counter_u64_add_protected()` / `counter_exit()`；`counter_enter()` **在部分机器上展开为 critical(9) 区，其他机器上是 nop**。
- `counter_u64_fetch()`：**遍历所有 per-CPU 字段**求和取快照，不保证反映某一时刻真值。
- `counter_u64_zero()`：清零（sysctl 写入即清零）。

来源：https://man.freebsd.org/cgi/man.cgi?query=counter&sektion=9&manpath=FreeBSD+15.0-RELEASE

**对本轮的含义**：
1. amd64 上 `counter_u64_add()` 是**单条非 lock 指令**，因此**即使多线程共享同一 per-cpu 槽位，最坏后果只是「统计计数丢失/不准」，不会内存损坏**。这解释了为什么 plan-17 §1.4 把 counter 列为「须核验不越界、不漏统计」而非崩溃风险。
2. `counter_u64_fetch()` 遍历所有 per-CPU 字段 → **`mp_maxid` 提高后，若 counter 的 per-cpu 分配未同步扩大，fetch 会越界读**。这与 §2.4 的「成对修改」约束是同一类问题，须列入 U4 核验清单。
3. `subr_smr.c` 自身也大量使用 counter（`COUNTER_U64_DEFINE_EARLY(advance)` / `poll` / `poll_scan` / `poll_fail` 等，并在 `smr_poll_scan()` 内用 `counter_u64_add_protected()`）——即 **SMR 与 counter 在 f-stack 中是同一条链上的两个 per-cpu 消费者**，必须一起改。
来源：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c

### 2.6 SMR（GUS）设计文档级说明——`subr_smr.c`顶部算法注释（原文摘录）

上游把 SMR 的设计文档直接写在源码注释里（**没有独立的设计文档或wiki 页**；本文已尝试检索 FreeBSD wiki / 邮件列表，未找到独立设计文档，**如实声明：SMR 的独立设计文档未找到可靠来源，源码注释即为权威设计说明**）。

关键原文摘录：

> **Global Unbounded Sequences (GUS)**
> This is a novel safe memory reclamation technique inspired by epoch based reclamation from Samy Al Bahra's concurrency kit which in turn was based on work described in: Fraser, K. 2004. Practical Lock-Freedom. PhD Thesis, University of Cambridge Computing Laboratory. And shares some similarities with: Wang, Stamler, Parmer. 2016 Parallel Sections: Scaling System-Level Data-Structures
>
> The basic approach is to maintain a monotonic write sequence number that is updated on some application defined granularity. **Readers record the most recent write sequence number they have observed.** A shared read sequence number records the lowest sequence number observed by any reader as of the last poll. **Any write older than this value has been observed by all readers and memory can be reclaimed.** Like Epoch we also **detect idle readers by storing an invalid sequence number in the per-cpu state when the read section exits.** Like Parsec we establish a global write clock that is used to mark memory on free.
>
> ... **Readers never advance any sequence number, they only observe them.**
>
> This mechanism is primarily intended to be used in coordination with UMA. By integrating with the allocator we avoid all of the callout queue machinery and are provided with an efficient way to batch sequence advancement and waiting. **The allocator accumulates a full per-cpu cache of memory before advancing the sequence.**

以及那张说明图的原文：

>```
>0                          UINT_MAX
>  | -------------------- sequence number space -------------------- |
>              ^ rd seq                            ^ wr seq
>              | ----- valid sequence numbers ---- |
>                ^cpuA  ^cpuC
>  | -- free -- | --------- deferred frees -------- | ---- free ---- |
> ```
> In this example cpuA has the lowest sequence number and poll can advance rd seq. **cpuB is not running and is considered to observe wr seq.**
> **Freed memory that is tagged with a sequence number between rd seq and wr seq can not be safely reclaimed because cpuA may hold a reference to it.** Any other memory is guaranteed to be unreferenced.

来源：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c

**「cpuB is not running and is considered to observe wr seq」是本轮最关键的一句上游原文**：它明确了 GUS 的核心假设——**「一个 CPU 的槽位为 INVALID ⟺ 该 CPU 上没有活跃读者」**。f-stack 现状下多个 worker 共享一个槽位，使这个「⟺」的右半边不再成立（槽位 INVALID 但仍有活跃读者），**这就是 UAF 的根本原因，且属于对 GUS 算法基本不变式的违反，不是实现细节问题**。

另外注意`subr_smr.c` 中 SMR_LAZY 的 grace period 说明依赖 **hardclock / 每 CPU 定期时钟中断**：

> Hardclock is responsible for advancing ticks on a single CPU while **every CPU receives a regular clock interrupt.** The clock interrupts are flushing the store buffers and any speculative loads that may violate our invariants. Because these interrupts are not synchronized we must wait one additional tick in the future to be certain that all processors have had their state synchronized by an interrupt.

**需与代码交叉验证（以代码为准）**：f-stack 用户态**没有「每 CPU 定期时钟中断」**（plan-17 提到的 15号文档「worker 时钟缺口修复」正是这一类问题）。若 f-stack 中有任何 zone 使用 `SMR_LAZY`，其 grace period 假设在用户态**不成立**。`res-code` 应核查f-stack 实际用到的 SMR 是否为 `SMR_LAZY`（`in_pcb.c` 的 `ipi_smr` 走`uma_zone_get_smr`，默认 flags 须坐实）。

---

## 5. 方向5：`cpuset_t` / `CPU_SETSIZE` 随 `MAXCPU` 变化的 ABI 影响；为何 `#else` 把 MAXCPU 硬定为 1

> 编号沿用 team-lead 给的方向号（方向 3、4 见后续批次）。

### 5.1 为何用户态 / 非 SMP 下 `MAXCPU` 恒为 1 —— FreeBSD 官方 commit message 直接回答

**来源**：FreeBSD commit `87767249233f`（stable/13，cherry-pick 自 main `8232a1eddadd`），作者 Brooks Davis，Author Date 2022-09-23，Reviewed by cem/jhb，Differential D36679
链接：https://lists.freebsd.org/archives/dev-commits-src-all/2022-September/017116.html

commit message 原文要点：

> `cpuset_t` 能表示的最大 CPU 编号由 **`CPU_SETSIZE`** 决定。在内核中它等于 **`MAXCPU`**；而在用户态它等于 **`CPU_MAXSIZE`**，除非在包含 `sys/_cpuset.h` 之前先自行定义 `CPU_SETSIZE`。`CPU_MAXSIZE` 为 **256**；而**在用户态 `MAXCPU` 通常为 1，因为将它设为更大的机器相关（MD）值的前提是定义了 `SMP`（用户态一般不会定义）**。

**这就是 plan-17 §1.2 所记 `freebsd/amd64/include/param.h:60-66`「`#ifdef SMP → MAXCPU 1024`；`#else → MAXCPU 1`」的官方解释**：`MAXCPU` 的大值是**以 `SMP` 为条件**的MD 常量；`#else` 分支的 `MAXCPU 1` 本来是给**用户态编译**（以及历史上的 non-SMP 内核）准备的退化值，目的是让那些以`MAXCPU` 为维度的静态数组在用户态不至于膨胀。

该 commit 同时说明了一个**陷阱**（原文归纳）：用户态代码若按 `MAXCPU` 理解 cpuset 宽度，会得到 **1 而不是 256**，导致遍历、掩码操作或断言出错。**f-stack 正是「用户态编译内核代码」这一混合场景，天然踩在这个陷阱上**——这与 plan-17 §0.1 记录的「本 build 非 SMP（`MAXCPU==1`、`mp_maxid==0`），UMA/SMR per-cpu 数组只按 1 CPU 分配 → `zpcpu_get()` 必然越界」**完全对应**。

`sys/sys/_cpuset.h` 的典型结构（该 commit 分析中给出，**标注：属对头文件结构的说明性重述，须以本地`freebsd-src-releng-15.0/sys/sys/_cpuset.h` 原文为准**）：

```c
#ifdef _KERNEL
#define CPU_SETSIZE   MAXCPU        /* 内核：跟随平台 MAXCPU */
#endif
#define CPU_MAXSIZE   256           /* ABI 上的最大可能宽度 */
#ifndef CPU_SETSIZE                 /* 用户态未自定义时的默认值 */
#define CPU_SETSIZE   CPU_MAXSIZE   /* = 256 */
#endif
```

**对候选 B（覆盖 `MAXCPU`）的直接提示**：由于 `CPU_SETSIZE` 有 `#ifndef` 守卫，**用户态可以在包含 `sys/_cpuset.h` 之前先 `#define CPU_SETSIZE <值>` 来覆盖**（该 commit message 明文提到这一机制）。但同时警告：一旦改变宽度，`cpuset_t` 的大小随之改变，与内核交互时须使用配套的 `setsize` 参数保持一致，否则 ABI 不匹配。
> **需与代码交叉验证（以代码为准）**：f-stack 全在用户态、不与真实 FreeBSD 内核交互，所以「与内核 ABI 不匹配」这一顾虑**不适用**；但**「f-stack 自己的 lib/ 与 example/ 必须用同一个 `CPU_SETSIZE`/`MAXCPU` 全树重编」这一要求依然成立**（否则 f-stack 内部结构体布局不一致）。这正是 plan-17 强制规约 2「改代码必须 `make clean` 再完整编译」在本轮的技术必要性——**不是流程洁癖，而是 KBI 级别的硬要求**。

### 5.2 `cpuset_t` 宽度由 `CPU_SETSIZE` 决定（cpuset(9) 官方定性）

cpuset(9)（FreeBSD 15.0，页脚 2025-08-07，宏作者 Jeff Roberson，手册页作者 Conrad Meyer）原文要点：

- cpuset(9) 宏族基于 **bitset(9)** 实现，**每个 CPU 一个 bit**。
- **`cpuset_t` 可表示的最大 CPU 数量就是 `CPU_SETSIZE`**；单个 CPU 通过索引 **0 ～ `CPU_SETSIZE - 1`** 引用。
- `CPUSET_FSET` 配合 `CPUSET_T_INITIALIZER()` 表示「全满集合」：
  ```c
  cpuset_t myset;
  myset = CPUSET_T_INITIALIZER(CPUSET_FSET);  /* 全部 CPU */
  ```
- CAVEATS：`CPU_FFS()` 返回 **1-索引** 结果（空集返回 0），当作 `cpu_idx` 传给其它宏时**必须先减 1**。
- 该手册页**通篇未出现 `MAXCPU`**（已由 §5.1 的 commit 修正为 `CPU_SETSIZE`），**也不包含 `CPU_FOREACH`**（后者在 `sys/sys/smp.h`）。

来源：https://man.freebsd.org/cgi/man.cgi?query=cpuset&sektion=9&manpath=FreeBSD+15.0-RELEASE

**对本轮的含义**：
- `MAXCPU: 1 → N` ⇒ `CPU_SETSIZE: 1 → N` ⇒ **`cpuset_t` 从 1 个 bit（1 字节/1 long）变成 N bit** ⇒ 所有内嵌 `cpuset_t` 的结构体（如 `struct pcpu`、`struct thread` 的亲和性字段、`all_cpus` 全局变量等）**布局改变**。
- 因此候选 B「覆盖 `MAXCPU`」**不是一个局部改动**，它是全树 KBI 改动。
- `CPUSET_T_INITIALIZER(CPUSET_FSET)` 是**初始化 `all_cpus` 的上游惯用法**，可作为 f-stack 补齐 `all_cpus`（plan-17 U4）的参考写法。**需与代码交叉验证（以代码为准）**：f-stack 当前 `all_cpus` 是 BSS 零值（plan-17 §1.2），是否需要、以及在何处初始化为 `0..N-1`，须由 `res-code` 依`CPU_FOREACH` 的实际展开确定。

### 5.3 FreeBSD 官方提升 MAXCPU 的经验：为什么「大 MAXCPU」有代价、ABI/KBI 如何约束

**来源**：FreeBSD 季度状态报告 2023Q2《Increasing MAXCPU》，作者 Ed Maste（FreeBSD Foundation 赞助），最后修改 2023-07-18；关联评审 https://reviews.freebsd.org/D36838（*amd64: Bump MAXCPU to 1024 (from 256)*）
链接：https://www.freebsd.org/status/report-2023-04-2023-06/maxcpu/

原文（英文）关键段落：

> The default amd64 and arm64 FreeBSD kernel configurations currently support a maximum of 256 CPUs. A custom kernel can be built with support for larger core counts by setting the MAXCPU kernel option. ...
> **A number of changes have been made to support a larger default MAXCPU, including fixing the userland maximum for cpuset_t at 1024. Changes have also been made to avoid static MAXCPU-sized arrays, replacing them with on-demand memory allocation.**
> Additional work is required to continue reducing static allocations sized by MAXCPU and addressing scalability bottlenecks on very high core count systems, but the goal is to release FreeBSD 14 with a **stable ABI and KBI** with support for large CPU counts.

**可核查的四条事实**：
1. amd64/arm64 **默认 `MAXCPU` 为 256**（不是 1024）；1024 是 14.x 才推动的目标值。
   > **需与代码交叉验证（以代码为准）**：plan-17 §1.2 记 f-stack 参照树 `freebsd/amd64/include/param.h`的 `#ifdef SMP` 分支是 `MAXCPU 1024`。这与「默认 256」的表述不矛盾（256 是 2023 年报告时的状态，1024 是该项目的目标，`releng/15.0` 已落地为 1024），但**具体数值以本地 `freebsd-src-releng-15.0` 为准**。
2. **用户态 `cpuset_t` 上限被固定为 1024**（已完成项）——即上游选择了「用户态与内核 `MAXCPU` 解耦」的路线，而不是让用户态跟随`MAXCPU`。
3. **上游正在系统性消除「按 `MAXCPU` 定长的静态数组」，改为按需分配**——这条对本轮**直接有参考价值**：候选 B若只把 `MAXCPU` 从 1 改成 N（N = worker 数，通常 ≤ 16），**静态数组膨胀的代价可忽略**，这是 f-stack 场景相对上游的一个天然优势（上游要考虑 1024 核，f-stack 只需考虑个位数 worker）。
4. **ABI/KBI 稳定性是上游做这件事的最大约束**，必须在 major release 前一次做完。

**对本轮方案选择的启示（推导，标注为分析而非文献结论）**：
- 上游的经验表明 `MAXCPU` 是**编译期常量、且是 KBI 的一部分**。因此候选 B（覆盖 `MAXCPU`）在 f-stack 里必须做到：`lib/`、`example/`、以及任何 include了 f-stack 头文件的用户代码，**全部用同一份 `MAXCPU` 定义重新完整编译**。
- 上游「大 MAXCPU 的代价主要是静态数组与缓存局部性」这一点说明：把 `MAXCPU` 定成一个**刚好够用的小值**（如 8/16/32）比定成 1024 更符合 f-stack 场景，既拿到稠密槽位，又避免结构膨胀。**但这不构成对候选 B 优于候选 A 的判定依据**——候选 A（`-DSMP`）会连带激活 `smp_rendezvous`/`ipi_*`/`sched_pin` 等路径，其成本只能由 `res-build` 用实际编译错误清单来量化（plan-17 U3）。

---

## 3. 方向 3：其他用户态内核/协议栈移植如何处理「多线程下的 per-CPU 视图」

>本节是本轮**最有直接参考价值**的一节：找到了两个**与候选 B 高度同构的既有实现**（libuinet、rump kernel），且都能拿到源码原文。

### 3.1 libuinet（FreeBSD 9.1 用户态栈）——**与候选 B 几乎完全同构的既有实现**

**项目定位**（来源：https://github.com/pkelsey/libuinet ）：
- FreeBSD **9.1-RELEASE** TCP/IP 栈的用户态库化移植，大量借用Kip Macy 更早的 **libplebnet**；
- 数据包 I/O 走 netmap 或 libpcap；
- README **未描述**内核环境仿真方式、线程模型、SMP/per-CPU 处理（**如实声明：README 层面无相关内容**），因此以下结论全部取自**源码原文**。

#### （a）`lib/libuinet/uinet_subr_smp.c`：用户态「伪 SMP」的完整实现

**来源**：https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_smp.c
（版权：Kip Macy 2010 / Patrick Kelsey 2013；注释注明 `Derived in part from libplebnet's pn_glue.c.`）

关键事实（源码原文归纳）：

| 项| libuinet 的做法 |
|---|---|
| `mp_ncpus` | **普通变量、由外部初始化代码赋值**（本文件不赋 1，BSS 默认 0）——即**参数化的多「CPU」，不是硬编码 1 CPU** |
| `mp_maxcpus` | `= MAXCPU`（编译期常量），注释 `/* export this for libkvm consumers. */` |
| `mp_maxid` | 仅声明并导出 sysctl，**本文件不赋值**，由外部设置 |
| `all_cpus` | 在 `mp_start()` 里用 `CPU_SET(i, &all_cpus)` 循环逐个置位（`i = 0 … mp_ncpus-1`）；注释 `/* This is used in modules that need to work in both SMP and UP. */` |
| `smp_started` | 声明为 `volatile int`，**从未置 1** → 依赖 `if (smp_started)` 的内核代码全走 UP 路径 |
| per-cpu 存储 | `pcpup = malloc(sizeof(struct pcpu) * mp_ncpus, M_DEVBUF, M_ZERO)`；失败 `panic("Failed to allocate PCPU space for %d cpus\n")` |
| 稠密索引初始化 | 循环 `i`：`CPU_SET(i, &all_cpus)` → **`pcpu_init(&pcpup[i], i, sizeof(struct pcpu))`** → `malloc(DPCPU_SIZE, ...)` → `dpcpu_init(dpcpu, i)` → `mtx_init(&uinet_pcpu_locks[i], ...)` |
| 注册时机 | `SYSINIT(cpu_mp, SI_SUB_CPU, SI_ORDER_THIRD, mp_start, NULL);`；启动打印 `"UINET multiprocessor subsystem configured with %d CPUs\n"` |
| 缺失的 SMP 设施 | 无 `smp_rendezvous*`、无 `stop_cpus/restart_cpus`、无 `forward_signal`、无 IPI、无 `smp_topology`、无 `kern.smp.active/cpus/disabled/topology` sysctl |
| 一条关键 XXX 注释 | `uinet_pcpu_locks[MAXCPU]`（每CPU 一把 `MTX_DEF｜MTX_RECURSE` 互斥锁）前面写着 **`/* XXX temporary until final pcpu approach is determined */`** |

**对本轮的直接价值（四条）**：

1. **候选 B 的做法已被libuinet 实践过且是其正式实现**：不定义 `SMP`（`smp_started` 永为 0、无 rendezvous/IPI），但**per-cpu 存储按 `mp_ncpus` 分槽 + `pcpu_init()` 传稠密索引 `0..N-1` + `all_cpus` 逐位置位**。这与 plan-17 §0.3 候选 B 的四步手段（覆盖 `MAXCPU` / 放开 `UMA_ZONE_PCPU` 剥离 / 设 `mp_ncpus`/`mp_maxid` / `pcpu_init` 传稠密索引）**逐项对应**。
2. **`all_cpus` 必须显式置位**，这正面回答了 plan-17 U4 与本文 §2.4 提出的疑虑：libuinet 明确写了 `CPU_SET(i, &all_cpus)` 循环。**需与代码交叉验证（以代码为准）**：f-stack 当前 `all_cpus` 是 BSS 零值（plan-17 §1.2），必须补齐，否则 `CPU_FOREACH` 语义不明。
3. **`mp_maxcpus = MAXCPU` 与 `mp_ncpus` 是两个不同量**，libuinet 严格区分：`MAXCPU` 是编译期上限（决定 `cpuset_t` 宽度与静态数组尺寸），`mp_ncpus`/`mp_maxid` 是运行期实际数量。候选 B 需要**同时**处理两者。
4. **那条 `XXX temporary until final pcpu approach is determined` 注释**说明：即使 libuinet 作者也把「用户态 pcpu 方案」视为未定稿的难点，并且**保留了一把 per-cpu 互斥锁作为兜底**。
   > ⚠️ **本条已被 §3.1(d) 部分修正（2026-08-04 第 2 批补充核实）**：`uinet_pcpu_locks[MAXCPU]` **与 UMA 无关**——libuinet 的 UMA 用的是**另外两把全局锁**（`bucket_lock`、`page_slab_hash_lock`，见 §3.1(d)）。因此**「libuinet 用 per-cpu 一把锁保护 UMA」这一推断是错的，本文原先提出的「G2 可退化为 per-worker 一把锁」回退路径并无 libuinet 背书**。`uinet_pcpu_locks[]` 的真实用途本轮仍未核实（未在 UMA 相关文件中出现）。

#### （b）`lib/libuinet/uinet_subr_pcpu.c`：cpuid 从何而来 + DPCPU 的用户态处理

**来源**：https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_pcpu.c （版权 Patrick Kelsey 2013）

**（i）cpuid 的取法（本轮 U6 的直接参考）**：

```c
struct pcpu *
uinet_pcpu_get(void)
{
	KASSERT(curthread->td_oncpu < mp_ncpus,
		("curthread->td_oncpu >= mp_ncpus"));
	return (&pcpup[curthread->td_oncpu]);
}
```

要点：
- CPU 号取自 **`curthread->td_oncpu`**，即一个**软件维护的「虚拟 CPU 号」**，**不用** `sched_getcpu()`/APIC ID/`rte_lcore_id()` 之类的真实硬件 CPU 号；
- `pcpup` 是**数组**（`&pcpup[...]`），因此结构上支持 `mp_ncpus > 1`；
- **带`KASSERT(td_oncpu < mp_ncpus)` 边界断言**——这正是 team-lead 问的「在用户态把 `curcpu`/pcpu 绑到 TLS 时如何保证 per-cpu 数组不越界」的**具体做法**：**在取槽位的唯一入口处做上界断言，且上界用运行期 `mp_ncpus`（而非编译期 `MAXCPU`）**。
- 该文件中**完全没有 TLS**（无 `__thread`、无 `pthread_getspecific`）；定位路径是「线程 → `curthread` → `td_oncpu` → 数组下标」。`curthread` 自身是否 TLS 属线程层，本文件不含。

> **与 f-stack 的差异（重要，需`res-code` 裁决）**：f-stack 用的是 `__thread struct pcpu *pcpup;`（plan-17 §1.1，`ff_freebsd_init.c:85`），即**直接把 pcpu 指针放TLS**，而 libuinet 用「`td_oncpu` 下标 + 全局数组」。
> - f-stack 方案的**优点**：`PCPU_GET` 少一次间接、不依赖 `curthread` 已初始化；
> - f-stack 方案的**风险**：`pcpup` 是**独立 malloc 的**（plan-17 §1.1：`malloc(sizeof(struct pcpu),...)`），**不是同一个连续数组的成员**。而 `zpcpu_get()` 用的是 `pc_zpcpu_offset`（由 `pcpu_init` 里 `zpcpu_offset_cpu(cpuid)` 算出），**其正确性只依赖 cpuid 的稠密性与 per-cpu zone 的分配尺寸，与 `pcpup` 本身是否连续无关**。因此 f-stack 的 TLS 方案与稠密索引**并不冲突**。
> - **但**：`subr_pcpu.c` 里的 `cpuid_to_pcpu[cpuid] = pcpu` 与 `STAILQ_INSERT_TAIL(&cpuhead,...)`（plan-17 §1.1 已记录 `file:line`）会把这些**分散 malloc 的 pcpu** 串进全局表；`pcpu_find()` 与遍历 `cpuhead` 的读者是否存在，仍须按 plan-17 U5 穷尽核验。**本文不越界下结论。**
> - **「不越界」的可移植做法建议（分析，非文献结论）**：照 libuinet 的样子，在 f-stack 的 `PCPU_*`/`zpcpu_*` 覆盖宏或 `ff_pcpu_thread_init()` 里加一条**运行期上界检查**（`cpuid < mp_ncpus` 且 `cpuid <= mp_maxid`），失败即 `panic`/`rte_exit`。这比依赖被编译掉的 `KASSERT(cpuid < MAXCPU)`（plan-17 §1.1 记`subr_pcpu.c:88`，因 `INVARIANTS` 未定义而失效）可靠。

**（ii）DPCPU 的用户态难点（f-stack 可能同样踩到）**：

libuinet 用**运行时注册 + 手动拼接连续区**替代内核的 linker set：

```c
struct dpcpu_definition dpcpu_definitions[DPCPU_MAX_DEFINITIONS];
unsigned int dpcpu_num_definitions;
unsigned int dpcpu_total_size;
unsigned char *dpcpu_init_area;
```

`uinet_dpcpu_init()`：`malloc(dpcpu_total_size, M_DEVBUF, M_ZERO|M_WAITOK)`（失败 `panic("Could not allocate DPCPU init area\n")`）→ 遍历注册项 `memcpy(&dpcpu_init_area[def->copyoffset], def->addr, def->copysize)`。

文件里唯一的实质性注释解释了动机：

> "Copy all of the registered data structures to a contiguous area, as the implementation in subr_pcpu.c expects."

**对本轮的含义**：内核 `DPCPU_DEFINE()` 依赖链接器把变量放进连续的 `set_pcpu` 段（`DPCPU_START`/`DPCPU_STOP`），**用户态共享库里不能可靠依赖这种section 布局**。plan-17 §1.1 已注意到 `subr_pcpu.c:252` 的 `dpcpu_copy()` 有 `#ifdef SMP` 分支、`:269-287` 的 `pcpu_destroy()` 会清 `dpcpu_off[]`。
**需与代码交叉验证（以代码为准）**：f-stack 是否使用 DPCPU（`DPCPU_DEFINE`/`DPCPU_GET`/`dpcpu_init`）、以及若使用则其 linker set 在 f-stack 静态库里是否有效，属 `res-code` 的核验项。若 f-stack 实际有DPCPU 消费者且走`dpcpu_init(dpcpu, i)`，则**候选 B 除 UMA/SMR 外还多一处按 CPU 数分配的路径**。本文只提示风险，不下结论。

#### （c）libuinet 的其他移植层文件（用于定位同类问题）

目录 `lib/libuinet/` 中与本轮同类的 glue 文件（来源：https://github.com/pkelsey/libuinet/tree/master/lib/libuinet ）：
`uinet_subr_pcpu.c`、`uinet_subr_smp.c`、`uinet_sched.c`、`uinet_kern_kthread.c`、`uinet_kern_proc.c`、`uinet_kern_synch.c`、`uinet_kern_intr.c`、`uinet_host_interface.c`、`uinet_uma_int.c`（UMA）、`uinet_kern_mutex.c`/`rwlock`/`rmlock`/`sx`/`condvar`、以及**`override_include/`**（覆盖 FreeBSD 头文件的目录，与 f-stack 的 `lib/include/`覆盖机制同构）。

**注意**：libuinet 有独立的 `uinet_uma_int.c`，即它**也**对 UMA 做了用户态改造。**本次未抓取该文件内容**，**如实声明：libuinet 的 UMA per-cpu cache 是否也被加锁/去锁，本轮未核实**。若 leader 认为该点关键，可追加抓取 `https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_uma_int.c`。

> **重大时代差异提醒**：libuinet 基于 **FreeBSD 9.1**，**没有 SMR**（SMR 是 2019–2020 引入）。所以 libuinet 只解决了 pcpu/UMA 层，**没有 SMR 这一层的先例**。f-stack 15.0 的 SMR 问题**在 libuinet 中不存在**，无法从 libuinet 得到验证。

#### （d）`lib/libuinet/uinet_uma_int.c`：libuinet 究竟如何保护 UMA —— **已核实（补充批次，对 G2 形态裁决直接有用）**

**来源**：https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_uma_int.c （版权 Patrick Kelsey 2013，BSD 2-clause）
> 本条原在 §3.1(c) 被标为「本轮未核实」，现已抓取到源码原文并核实完毕。

**（i）是否覆盖 `critical_enter`/`critical_exit`？——否。**
该文件中**完全不出现** `critical_enter` / `critical_exit` / `critical_nesting` 及相关宏。libuinet 没有走 f-stack 那条「把 `critical_enter/exit` 重定义成抢锁」的路（f-stack 见 plan-17 §1.4 `lib/include/vm/uma_int.h:45-52`），而是**直接在 UMA 移植层引入显式锁原语**。

**（ii）UMA per-cpu cache/bucket 的保护方式：一把「全局」互斥锁，不是 per-cpu 锁。**

```c
struct mtx bucket_lock;

static void thread_bucket_lock_init(void) {
        mtx_init(&bucket_lock, "bucket lock", NULL, MTX_DEF);
}
void thread_bucket_lock(void)   { mtx_lock(&bucket_lock);   }
void thread_bucket_unlock(void) { mtx_unlock(&bucket_lock); }
```

要点：
- **只有单个** `struct mtx bucket_lock`（全局变量，锁名 `"bucket lock"`，`MTX_DEF`）；**文件中没有任何锁数组**（不存在 `mtx bucket_lock[MAXCPU]` 之类）。
- 命名是 **`thread_bucket_lock`** 而非 `cpu_bucket_lock` —— 提示 libuinet 的心智模型是「**每线程 bucket**」而非「每 CPU cache」，并用一把全局锁把bucket 访问整体串行化。
- **`uinet_pcpu_locks[]` 在本文件中完全未出现**。⇒ §3.1(a) 第 4 条原先的推断（「libuinet 用 per-cpu 一把锁保护 UMA」）**被证伪**，已在该处修正。

**（iii）`uma_page` / slab 反查哈希：由「另一把独立的全局锁」保护。**

```c
struct mtx page_slab_hash_lock;
int uma_page_mask;
struct uma_page_head *uma_page_slab_hash;

static void uma_page_slab_hash_lock_init(void) {
        mtx_init(&page_slab_hash_lock, "uma page slab hash lock", NULL, MTX_DEF);
}
void uma_page_slab_hash_lock(void)   { mtx_lock(&page_slab_hash_lock);   }
void uma_page_slab_hash_unlock(void) { mtx_unlock(&page_slab_hash_lock); }
```

这与 f-stack 的做法**结构上同源**：plan-17 §1.4 已记录 f-stack 的 `lib/include/vm/uma_int.h` 同样 `#undef UMA_MD_SMALL_ALLOC`、定义 `UMA_PAGE_HASH` 与 `struct uma_page` —— 即**两个项目都因为用户态拿不到 `vm_page` 上的 slab 反向指针，而改用「页地址 → slab」的全局哈希表**。

**（iv）唯一的注释（初始化顺序的 XXX）**：

```c
/*
 * XXX this should really be handled by SYSINIT I think.  Although it works
 * out with the current port, calling mtx_init() before mutex_init() is
 * called is technically wrong.
 */
```
两个 init 函数都用 `__attribute__((constructor))` 在 `main` 之前跑，以便早于子系统 `mutex_init()` 完成 `mtx_init()`；作者明确承认这在技术上不正确。

**（v）本文件不含 `uma_zalloc`/`uma_zfree` 快路径代码**，只提供上述两组锁原语给 UMA 核心调用。**如实声明：这两组锁的实际调用点（在 libuinet 版 `uma_core.c` 或 `uinet_uma_int.h` 中）本轮未抓取核实，因此「libuinet 是否在每次 `uma_zalloc` 快路径上都抢 `bucket_lock`」无法确证，不做推测。**

##### 对 G2 形态裁决的四条直接含义

| # | 结论 | 强度 |
|---|---|---|
| **L1** | **libuinet 不是「per-cpu 锁」先例，而是「全局锁」先例**。它与 f-stack 现状（单一全局 `uma_crit_lock`）在**保守程度上同级**，只是 f-stack 通过重定义 `critical_enter` 实现、libuinet 通过显式锁函数实现。⇒ **G2「libuinet 式 per-cpu 一把锁」这个候选形态没有文献依据，建议从候选集中移除**（除非另有依据） | 高（源码原文） |
| **L2** | **libuinet 把「bucket 保护」与「uma_page slab 哈希保护」拆成两把独立锁**，理由清晰：`uma_page_slab_hash` 是**真正跨线程共享的全局数据结构**（页地址 → slab 反查表），它**不是 per-cpu 数据**，因此「每线程独占 per-cpu 槽位」这一不变式**对它完全无保护作用**。⇒ **强烈支持 G2-a（去`critical_enter` 锁 + 为真正的共享结构补真锁）而非 G2-b（仅去锁）**：f-stack 的 `uma_crit_lock` 很可能同时在替两件事挡枪，其中 `UMA_PAGE_HASH` 那一半**无论G1 做得多干净都必须保留某种真锁** | 高（源码原文 + f-stack 侧同源结构已由 plan-17 §1.4 记录） |
| **L3** | 与 X3（`git show b90ddcba5` 原始动机）**直接呼应**：plan-17 §1.4 已把「f-stack 自造的 `uma_page` hash 表并发」列为 `uma_crit_lock` 可能的真实动机之一。libuinet 的实现表明**这个可能性有很高的先验概率**（同类项目独立地为该哈希表专门配了一把锁）。⇒ 建议 `res-code` 在做 X3 时**特别核查`uma_crit_lock` 是否覆盖了 `UMA_PAGE_HASH` 的查找/插入路径** | 中高（同源结构类比，属推导） |
| **L4** | libuinet 用 `__attribute__((constructor))` 解决「锁必须在 `mutex_init()` 之前可用」的初始化顺序问题，并自评technically wrong。若 G2-a 需要新增 per-zone/哈希锁，f-stack 会遇到**同一个初始化顺序难题**（锁要在 UMA 首次分配前就绪，而 UMA 早于大多数 SYSINIT）。⇒ 建议 `designer` 在 G2-a 设计中显式处理该顺序，可用静态初始化的 `pthread_mutex`/`rte_spinlock`（**无需**动态 init）绕开，而不是照抄 constructor 技巧 | 中（工程类比，属建议） |

> **总评（供 leader 在 G2-a/b/c 之间裁决）**：本条核实结果**把天平推向 G2-a**。核心理由是 L2 —— 「per-cpu 槽位独占」这个不变式**只能保护 per-cpu 数据（`uma_cache`/`uc_*bucket`）**，对 f-stack 自造的 `UMA_PAGE_HASH` 全局哈希表**零保护**；而当前这两者恰好被同一把 `uma_crit_lock` 一起挡住了。因此「仅去锁」（G2-b）在**尚未确认 `uma_crit_lock` 是否也在保护 `UMA_PAGE_HASH`** 之前是不安全的。**这是代码级必须先回答 X3 的又一个独立理由。**（标注：L2/L3/L4 含推导与建议成分，已逐条标注强度；L1 与源码事实为原文直述。）



**来源**：NetBSD `sys/rump/librump/rumpkern/scheduler.c`（`$NetBSD: scheduler.c,v 1.55 2023/10/05 19:41:07 ad Exp $`，版权 Antti Kantee 2010, 2011）
链接：https://raw.githubusercontent.com/NetBSD/src/trunk/sys/rump/librump/rumpkern/scheduler.c

**（a）机制：rump kernel 有 N 个「虚拟 CPU」，host 线程必须先「抢到」一个虚拟 CPU 才能跑内核代码**

```c
static struct rumpcpu {
	/* needed in fastpath */
	struct cpu_info *rcpu_ci;
	void *rcpu_prevlwp;
	/* needed in slowpath */
	struct rumpuser_mtx *rcpu_mtx;
	struct rumpuser_cv *rcpu_cv;
	int rcpu_wanted;
	...
	int rcpu_align[0] __aligned(CACHE_LINE_SIZE);
} rcpu_storage[MAXCPUS];

static inline struct rumpcpu *
cpuinfo_to_rumpcpu(struct cpu_info *ci)
{
	return &rcpu_storage[cpu_index(ci)];
}
```

即 **`rcpu_storage[MAXCPUS]` 就是一个「按虚拟 CPU 号索引的稠密数组」，每项 cache line 对齐**；虚拟 CPU 数由 `rump_scheduler_init(int numcpu)` 决定，`rump_cpus_bootstrap()` 里还做了 **`if (num > MAXCPUS) num = MAXCPUS;`** 的上界钳制，并打印
`"CPU limit: %d wanted, %d (MAXCPUS) available (adjusted)"`，`cpu_setmodel("rumpcore (virtual)")`。

`rump_schedule()` 的函数注释直接点明设计目标：

> `rump_schedule: ensure that the calling host thread has a valid lwp context. ie. ensure that curlwp != NULL. Also, ensure that there **a 1:1 mapping between the lwp and rump kernel cpu**.`

`rump_schedule_cpu_interlock()` 的注释与实现：

> `Schedule a CPU. This optimizes for the case where we schedule the same thread often, and we have nCPU >= nFrequently-Running-Thread (where CPU is virtual rump cpu, not host CPU).`

```c
	rcpu = cpuinfo_to_rumpcpu(l->l_target_cpu);
	if (atomic_cas_ptr(&rcpu->rcpu_prevlwp, l, RCPULWP_BUSY) == l) {
		...
		goto fastlane;         /* 上次就是我用的这个虚拟 CPU：直接复用 */
	}
	...
	for (;;) {
		old = atomic_swap_ptr(&rcpu->rcpu_prevlwp, RCPULWP_WANTED);
		if (old != RCPULWP_BUSY && old != RCPULWP_WANTED) {
			if (atomic_cas_ptr(&rcpu->rcpu_prevlwp,
			    RCPULWP_WANTED, RCPULWP_BUSY) == RCPULWP_WANTED)
				break;      /* 抢到空闲虚拟 CPU */
		}
		if (domigrate && !bound) {... rcpu = getnextcpu(); continue; }
		rcpu->rcpu_wanted++;
		rumpuser_cv_wait_nowrap(rcpu->rcpu_cv, rcpu->rcpu_mtx);
		rcpu->rcpu_wanted--;
	}
```

释放（`rump_unschedule_cpu1()`）：`old = atomic_swap_ptr(&rcpu->rcpu_prevlwp, l);`，有等待者则`rumpuser_cv_broadcast()`。

**核心语义**：虚拟 CPU 槽位由 **`rcpu_prevlwp` 的 BUSY/WANTED 状态机 + atomic CAS** 做**互斥独占**——**任一时刻一个虚拟 CPU 槽位只被一个 lwp（host 线程）持有**。这与「靠禁止 host 抢占来保护 per-cpu 数据」是**完全不同的两条路线**：rump **不禁止 host 线程被抢占**，而是**保证槽位在语义上被独占**，因此 host 内核把线程调度出去**无害**（别的线程拿不到这个槽位）。

**（b）rump 对「关抢占」的处理：直接把内核抢占语义常量化为「永远关着」**

```c
bool
kpreempt(uintptr_t where)
{
	return false;
}

/*
 * There is no kernel thread preemption in rump currently.  But call
 * the implementing macros anyway in case they grow some side-effects
 * down the road.
 */
void kpreempt_disable(void) { KPREEMPT_DISABLE(curlwp); }
void kpreempt_enable(void)  { KPREEMPT_ENABLE(curlwp);  }

bool
kpreempt_disabled(void)
{
#if 0
	const lwp_t *l = curlwp;
	return l->l_nopreempt != 0 || l->l_stat == LSZOMB ||
	    (l->l_flag & LW_IDLE) != 0 || cpu_kpreempt_disabled();
#endif
	/* XXX: emulate cpu_kpreempt_disabled() */
	return true;
}

void preempt(void) { yield(); }
bool preempt_needed(void) { return false; }
void preempt_point(void) { }
```

**这是本轮最有分量的外部先例**：一个成熟的、上游NetBSD 树内维护十余年的用户态内核移植，其做法是
**「内核代码视角下抢占永久关闭（`kpreempt_disabled()` 恒返回 `true`、`kpreempt()` 恒 `false`、`preempt_needed()` 恒 `false`），真正的互斥由『虚拟 CPU 槽位被线程独占持有』提供」**。

**（c）与 f-stack native-mt 的对照（分析，标注为推导）**

| 维度 | rump kernel | f-stack native-mt 目标态（候选 B） |
|---|---|---|
| 槽位数组 | `rcpu_storage[MAXCPUS]`，cache line 对齐 | UMA/SMR per-cpu zone 按 `mp_maxid+1` 分槽 |
| 槽位归属 | **动态独占**：线程运行时 CAS 抢占某个虚拟 CPU，可迁移（`domigrate`/`getnextcpu()`），但同一时刻独占 | **静态 1:1 永久绑定**：worker i ↔ 槽位 i，不迁移 |
| 保护手段 | atomic CAS 状态机 + mutex/cv（**不禁 host 抢占**） | 拟依赖「1:1 绑定 + 不迁移」（**也不禁 host 抢占**） |
| 上界保护 | `if (num > MAXCPUS) num = MAXCPUS;` | 建议照 libuinet 加运行期 `cpuid < mp_ncpus` 断言 |
| 严格性 | 较弱（允许迁移，故必须用 CAS 互斥） | **更强**（永久绑定 ⇒ 天然互斥，理论上无需 CAS） |

**结论（推导）**：f-stack 拟采用的「每 worker 独占一个稠密槽位、永不迁移」比 rump 的「动态独占 + 可迁移」**约束更强**。既然更弱的 rump 模型在不禁 host 抢占的前提下已被证明可用（NetBSD 树内长期维护），**更强的 f-stack 模型在同一维度上不会更差**。
**但这不构成对 G2 的充分性证明**——因为：
- rump 的虚拟 CPU 是**内核代码执行权本身**（拿不到虚拟 CPU 就不能跑内核代码），而 f-stack 的 pcpu 槽位**只是数据槽位**，f-stack 的 worker 之间**并没有**「必须先抢到槽位才能进协议栈」这层门；
- 因此 f-stack 必须额外证明：**所有会触碰 per-cpu 槽位的执行流都与某个固定槽位一一对应**。这正是 plan-17 U7 列出的「主线程 / KNI / callout / `ff_veth` 等辅助路径」问题——**外部先例无法替代这项本地核验**。

### 3.3 Seastar / ScyllaDB —— 「shared-nothing + 线程绑核+ per-core 分配器」

**来源**：Seastar 官方 tutorial（作者 Nadav Har'El、Avi Kivity；ScyllaDB 官方仓库 master分支 `doc/tutorial.md`）
链接：https://raw.githubusercontent.com/scylladb/seastar/master/doc/tutorial.md

原文要点：
- **动机**：跨核共享数据的代价（原子指令、cache line bouncing、内存屏障）远高于核本地访问；文中明确指出**「不可扩展的编程实践（如加锁）会在多核上严重摧毁性能」**。
- **Share-nothing SMP 架构**：SMP 系统中**每个核完全独立运行**；**内存、数据结构、CPU 时间均不共享**；核间通信用**显式消息传递**；一个 Seastar core 常称为一个 **shard**。
- **线程绑核**：每 CPU 一个线程（engine），**每个 engine 线程被 pin（类似 `taskset(1)`）到不同的硬件线程**；`-c` 可指定线程数；只请求 2 线程时会保证 pin 到**不同物理核**（避开同核超线程竞争）；**不允许**启动多于硬件线程数的线程。
- **per-core 内存分配器**：每个线程**预先分配一大块内存**（位于其所在 NUMA 节点），并**只用这块内存做分配**。
- **推论级原文**：由于 Seastar 对象**始终只被单个 CPU 使用**，`seastar::shared_ptr`/`lw_shared_ptr` 的引用计数增减**不需要原子操作**，只是普通核本地整数操作；标准 `std::shared_ptr` **在分片式 Seastar 应用中不应使用**。

**来源（补充，ScyllaDB 官方产品页）**：https://www.scylladb.com/product/technology/shard-per-core-architecture/
> each shard-per-core has dedicated resources and its own custom schedulers for CPU and I/O processing. Using the Seastar framework, ScyllaDB runs **one application thread per core** and relies on **explicit message passing**.

**对本轮的价值**：Seastar 提供的是**「线程与核1:1 绑定 ⇒ 数据结构可以完全无锁、连引用计数都不用原子」这一论断的工业级背书**。这与 G2 的目标（去掉 `uma_crit_lock`）在**推理形式上同构**：`独占 + 不迁移 ⇒ 无需互斥原语`。
**局限（如实声明）**：Seastar 是**自研**的 shared-nothing 运行时，**不是移植既有内核代码**，因此它**没有**「内核代码内部隐含要求 `critical_enter` 语义」这一约束。**它能支撑「1:1 绑定可以去锁」这一一般性论断，但不能证明「FreeBSD UMA/SMR 的具体实现在去掉 `critical_enter` 后仍正确」**——后者只能靠 §4 的上游代码语义 + 本地核验。

### 3.4 DPDK ANS（`ansyun/dpdk-ans`）—— per-lcore 独立 TCP 栈、lock-free，但分层共享

**来源**：https://github.com/ansyun/dpdk-ans

README 明确的架构（原文要点）：
- **TCP 层per-lcore 独立实例**（"Support multicore tcp stack, per tcp stack per lcore"）；**IP / ARP / ICMP 层跨 lcore 共享**。
- **"Each lcore has own TCP stack, free lock"** —— per-lcore TCP 路径**无锁**。
- 流亲和性**依赖网卡 RSS**："same TCP flow are handled in the same lcore"；**无 RSS 时**建议改`ans_main.c`，**预留一个 lcore 专门收包 + 软件 RSS 分发**。
- 参考 FreeBSD 实现，但**用 DPDK 原语替换内核原语**：`ANS use dpdk mbuf, ring, memzone, mempool, timer, spinlock` —— 即 **DPDK `rte_mempool` 取代 UMA/zone、`rte_timer` 取代 callout、`rte_spinlock` 取代 mutex/rwlock**。
- 性能：1 lcore → 2 lcore 的 CPS 从 105,860 → 204,512 req/s（近线性）。

**对本轮的价值与局限**：
- **价值**：证明「per-lcore 独立栈 + 无锁」在生产级 DPDK 栈里是主流选择；且它给出了「无 RSS 时用软件二次分发」的通行做法（与上一轮 `_m1_B_external.md` §5 的结论一致）。
- **局限（如实声明）**：ANS **不是移植 FreeBSD 代码，而是「参考 FreeBSD 重新实现」并把 UMA 整个换成了 `rte_mempool`**。因此**它完全绕开了本轮的问题**（没有 UMA per-cpu cache、没有 SMR、没有 `struct pcpu`）。**ANS 对「如何让 FreeBSD 的 per-cpu 视图 SMP-aware」没有任何直接参考价值。**
- README **未说明** FreeBSD per-CPU 结构（`curcpu`、per-CPU 缓存、pcbinfo 哈希分区）具体如何改写，**如实声明：该点未核实**。

### 3.5 未找到可靠来源的条目（如实声明）

| 检索目标 | 结果 |
|---|---|
| **rump kernel 官方书籍**《Flexible Operating System Internals: The Design and Implementation of the Anykernel and Rump Kernels》(Kantee, 2012) 中关于虚拟 CPU / per-CPU 的章节 | **抓取失败**（`http://www.fixup.fi/misc/rumpkernel-book/rumpkernel-bookv2-web.pdf` 请求被中止/超时）。已改用**上游源码原文**（§3.2）作为权威依据，源码可核查性更强，故不再重试。 |
| **mTCP** 论文（NSDI 2014）中「per-core 栈 + 线程绑核 + 无共享数据结构」的原文表述 | **未找到可靠来源**。多次检索只返回二手 CSDN 博客（提到 `struct mtcp_context` / `struct mtcp_thread_context` 做「多线程资源隔离」，来源 https://blog.csdn.net/gitblog_01026/article/details/156748380 ），**未取得论文原文或官方文档页**。且 mTCP 是自研栈、非 FreeBSD 移植，与本轮相关性低，**不作为依据**。 |
| **OpenFastPath / ODP** 的 per-core 与锁模型 | **未找到可靠来源**。检索只返回一篇 CSDN 的「常见问题解决方案」（编译依赖类内容，https://blog.csdn.net/gitblog_00880/article/details/143679925 ），**未取得官方设计文档**。**不作为依据。** |
| **glue（f-stack 之外的其他 FreeBSD 用户态 glue 项目）** 对 per-cpu 的处理 | **未找到可靠来源**。除libuinet / libplebnet（后者已被 libuinet 吸收，见 §3.1 注释 `Derived in part from libplebnet's pn_glue.c`）外，未检索到其他可核查的同类项目。 |
| **libuinet 的 UMA 改造细节**（`uinet_uma_int.c` 是否也加了锁 / 如何处理 per-cpu cache） | **已核实（第2 批补充完成）**，见 §3.1(d)：**不覆盖 `critical_enter`，改用一把全局 `bucket_lock` + 一把独立的 `page_slab_hash_lock`**。**仍未核实**的只剩这两把锁在 libuinet 版 `uma_core.c`/`uinet_uma_int.h` 中的**实际调用点**（即是否每次 `uma_zalloc` 快路径都抢 `bucket_lock`），**不做推测**。 |
| 「用户态多线程共享 SMR 槽位导致 UAF」的**已公开 bug 报告/事故记录** | **未找到可靠来源**。检索 FreeBSD bugzilla / 邮件列表 / GitHub 均无同类报告——合理解释是：**几乎没有其他项目把 FreeBSD 13+ 的 SMR搬到用户态多线程环境**（libuinet 停在 9.1、ANS 不用 UMA、rump 是 NetBSD 无 SMR）。本轮的 UAF 论证**只能靠 §2 的上游源码语义推导**，无外部事故案例可引。 |

---

## 4. 方向 4：用户态无「关抢占」语义时，UMA per-cpu cache 快路径的正确性

### 4.1 上游对「per-CPU cache 为何无需锁」的权威表述——`uma_int.h` 原文

**来源**：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/vm/uma_int.h
（版权：Jeffrey Roberson 2002–2019；Bosko Milekic 2004, 2005）

文件顶部总览注释的**决定性一句**：

> "The **PCPU caches are protected by critical sections**, and **may be accessed safely only from their associated CPU**, while the Zones backed by the same Keg all share a common Keg lock (to coalesce contention on the backing slabs)."

`struct uma_cache` 前的注释：

> "The uma_cache structure is allocated for each cpu for every zone type. **This optimizes synchronization out of the allocator fast path.**"

分配层次（注释中的 allocation order）：

```
1) Per-CPU cache
2) Per-domain cache of buckets
3) Slab from any of N kegs
4) Backend page provider
```

结构定义：

```c
struct uma_cache {
	struct uma_cache_bucket uc_freebucket;   /* Bucket we're freeing to */
	struct uma_cache_bucket uc_allocbucket;  /* Bucket to allocate from */
	struct uma_cache_bucket uc_crossbucket;  /* cross domain bucket */
	uint64_t uc_allocs;
	uint64_t uc_frees;
} UMA_ALIGN;
```

并有一条注释说明其cache line 布局意图：

> "The cache structure **pads perfectly into 64 bytes** so we use spare bits from the embedded cache buckets to store information from the zone and **keep all fast-path allocations accessing a single per-cpu line**."

**另一条重要事实**：`uma_int.h` 定义的锁宏**只有** keg / zone-domain / cross-domain 三类（`KEG_LOCK`、`ZDOM_LOCK`/`ZONE_LOCK`、`ZONE_CROSS_LOCK`），**完全没有针对 per-CPU cache 的锁宏**。这从反面坐实：上游对 per-cpu cache 的保护**唯一手段就是 critical section**。

**跨 CPU 释放的上游语义（对应plan-17 U8）**：`uma_int.h` 注释写

> "…frees may happen on any CPU and these are returned to the **CPU-local cache regardless of the originating domain**."

即**「在哪个 CPU 上free 就进哪个 CPU 的本地 cache」**——上游**允许**「A 分配、B 释放」，并且**不需要**把 item 送回原CPU。
**对本轮的含义**：plan-17 U8 担心的「mbuf 在 worker A 分配、B 释放」**在上游语义下本身是合法的**，因为释放只碰**释放者自己**的 per-cpu cache。**前提仍然是「每个执行流有自己独占的cache 槽位」**——这正是 G1 要建立的前提。
**需与代码交叉验证（以代码为准）**：f-stack 是否把 `uz_lock`/`ZDOM_LOCK`/`ZONE_CROSS_LOCK` 也 stub 掉了（plan-17 U8 的原问题）必须由 `res-code` 坐实；若zone 级锁被 stub 成空，则 bucket 交换路径（per-cpu cache 与 zone bucket list 之间）会失去保护，**那是与 per-cpu 槽位无关的另一个独立缺陷**。

**辅助来源（二手，仅作佐证）**：DeepWiki 对 FreeBSD UMA 的整理：
> "**Per-CPU Cache**: The allocator first checks the local CPU's cache (`uma_cache`) to satisfy the request **without locking**." / "Objects freed to an SMR zone are not immediately reused. They are placed in a deferred state until the SMR subsystem confirms that no threads hold references to the memory. This is critical for networking structures like pcb (Protocol Control Blocks) where high-performance lookups occur without global locks."
来源：https://deepwiki.com/freebsd/freebsd-src/4.3-uma-(universal-memory-allocator)
（**标注：DeepWiki 为 AI 生成的第三方整理，非官方文档**；此处仅用于佐证 §2/§4 已由官方源码/man页坐实的结论，**不作为独立依据**。它同时印证了「PCB 查找是 SMR 的关键消费者」，与 plan-17 §1.3 的 `in_pcb.c:583,615-617` 事实一致。）

### 4.2 核心论断的交叉验证：「上游 `critical_enter` 防的是同 CPU 上的抢占后另一线程访问同一 per-cpu 槽位；若用户态每线程独占槽位则被抢占无害」

**裁决：该论断在「per-cpu 数据槽位的互斥」这一维度上，得到上游文档与源码的正面支撑；但作为「可以移除 `uma_crit_lock`」的充分条件，它是不完整的——还缺三块，必须本地核验。**

#### （a）支撑该论断的证据（三条，均可核查）

1. **`uma_int.h` 原文把两件事并列**：「protected by critical sections」**且**「may be accessed safely **only from their associated CPU**」。第二个从句给出的是**归属性不变式**（一个 cache 只被它所属的 CPU 访问），而 critical section 是在「线程可迁移 + 可被抢占」的内核环境中**维持这个不变式的手段**，不是不变式本身。
   → **若用户态用「线程 ↔ 槽位 1:1 永久绑定、绝不迁移」直接建立该不变式，则维持它的手段就不再必需。**
   来源：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/vm/uma_int.h
   *（标注：这一步是**语义推导**——上游没有一句话直说「若能用别的手段建立该不变式则临界区可省」。推导链条清晰且每一环有原文，但**属推导，不是文献直述**。）*

2. **`counter(9)` 提供了同构的官方先例**：counter 也是 `UMA_ZONE_PCPU` 分配的 per-cpu 数据，而 man 页明确 **amd64 上 `counter_u64_add()` 是单条非 lock 指令、对抢占与中断天然安全**，因此 **amd64 上 `counter_enter()` 展开为 nop 而非 critical section**（"在部分机器上展开为 critical(9) 区，其他机器上是 nop"）。
   → **说明上游本身就承认：当访问在架构上是原子/单指令的，per-cpu 数据不需要临界区。** 换言之临界区**不是**per-cpu 数据的形而上要求，而是针对「多指令序列 + 可迁移」这一具体威胁模型。
   来源：https://man.freebsd.org/cgi/man.cgi?query=counter&sektion=9&manpath=FreeBSD+15.0-RELEASE

3. **rump kernel 是工程先例**（§3.2）：`kpreempt_disabled()` **恒返回 true**、`kpreempt()` 恒 false，靠「虚拟 CPU 槽位被线程独占持有」而**不是**靠禁止 host 抢占，来保护 per-CPU 结构；且这是 NetBSD 上游树内长期维护的实现。
   来源：https://raw.githubusercontent.com/NetBSD/src/trunk/sys/rump/librump/rumpkern/scheduler.c

#### （b）该论断**不足以**支撑 G2 的三块缺口（必须本地核验，本文不下结论）

| # | 缺口 | 为什么外部资料无法解决 | 交给谁 |
|---|---|---|---|
| **X1** | **「所有触碰 per-cpu 槽位的执行流」是否都与某个固定槽位 1:1 对应**。plan-17 U7 已列出主线程 / KNI / callout / `ff_veth` 等辅助路径。若存在**任何一个**没有独占槽位、或会漂移槽位的执行流（例如某个 pthread 未调用 `ff_pcpu_thread_init()`、或多个逻辑任务复用同一线程但期望不同槽位），不变式即破裂 | 这是 f-stack 特有的代码结构问题，外部无先例 | `res-code`（U7 逐路径核验）+ `tester`（压测） |
| **X2** | **`critical_enter/exit` 宏覆盖的实际作用域**。若 `lib/include/vm/uma_int.h` 的宏覆盖也被 `smr.h`/`subr_smr.c`/`counter.h` 等编译单元看到，则移除它会**同时**移除 SMR 写侧（`smr_advance`/`smr_poll`）与 counter 的保护；而 SMR 写侧的临界区上游有**明确的独立理由**——`smr_poll()` 注释：**"Use a critical section so that we can avoid ABA races caused by long preemption sleeps."**这条理由**与 per-cpu 槽位归属无关**，是关于「序号ABA」的，**不能**被「线程独占槽位」论证覆盖 | 上游只说了「防 long preemption sleep 导致的 ABA」，是否在 f-stack 用户态成立取决于 f-stack 的线程被 OS 调度出去的时长与 `SMR_SEQ_MAX_DELTA`（`UINT_MAX/4`）的关系，**必须实测/代码分析** | `res-code`（`gcc -E` 坐实作用域）+ `designer`（决定 SMR 写侧是否需要替代保护） |
| **X3** | **`uma_crit_lock` 的原始引入动机**。plan-17 §1.4 已要求 `git show b90ddcba5` 坐实。**若它当初解决的不是「共享 pcpu 槽位」而是别的问题**（例如 f-stack 自造的 `uma_page` hash 表并发、或 `#undef UMA_MD_SMALL_ALLOC` 后`page_alloc` 路径的并发），那么即使 G1 完成，该锁**仍不能移除** | 该commit 是 f-stack 私有历史，外部完全无资料 | `res-code`（M1-A 必做项） |

#### （b-2）X2 结论回填（`res-code` 已用代码坐实，2026-08-04 leader 轮询时同步）

`res-code`坐实的代码事实：**`freebsd/sys/systm.h:186` 的 `#ifndef FSTACK` 使 f-stack 全树的 `critical_enter()/critical_exit()` 本身就是空操作（nop）**；只有 **UMA 编译单元**被 `lib/include/vm/uma_int.h:46/50` 的全局自旋锁覆盖。**以代码为准**，本文 X2 原先「宏覆盖作用域未知」的假设被推翻，据此修正三条结论：

1. **SMR 读侧（`smr_enter`/`smr_exit`）与写侧（`smr_advance`/`smr_poll`/`smr_poll_scan`）在 f-stack 中当前已经完全没有临界区保护**（`critical_enter` 是 nop，`CRITICAL_ASSERT` 亦随`INVARIANTS` 未定义而失效）。因此 §4.2(b) 原 X2 所担心的「移除 `uma_crit_lock` 会连带削弱 SMR 写侧保护」**不成立**——G2 对 SMR **零影响**，SMR 侧的风险是**既存**的、与 G2 无关的独立问题。
2. 由此，**T5（SMR 序号 ABA）不是 G2 的门禁项**，而是 **G1 之外需独立评估的既存风险**：上游用 `critical_enter` 防的「long preemption sleep 导致 ABA」在 f-stack 里本来就没有防护。所幸 `smr_poll_cpu()` 自带一层软兜底（原文注释："There is a race described in smr.h:smr_enter that can lead to a stale seq value but not stale data access. If we find a value out of range here we pin it to the current min…"，并有 `if (SMR_SEQ_LT(c_seq, s_rd_seq)) c_seq = s_rd_seq;`），且注释指出该race "is only likely to happen on hypervisor or with a system management interrupt"。**用户态线程被 OS 调度出去在性质上与 hypervisor vm-exit 同类**，故该软兜底恰好覆盖本场景；但它只保证「不访问 stale 数据」，不消除 §2.1 的「共享槽位 → `smr_exit` 误清INVALID」这条**根本破坏**。
   来源：https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c
3. **G2 的真实语义被澄清**：`uma_crit_lock` 不是「上游临界区的用户态替身」，而是**f-stack 在 `critical_enter` 已被 nop 化之后、为UMA per-cpu cache 单独补上的一把全局串行锁**。因此 G2 = 「撤掉这把补丁锁，回到与全树其余部分一致的 nop 语义」——其正确性**完全依赖 G1 建立的『每线程独占槽位』不变式**，与 SMR 无关。这使 G1→G2 的依赖关系比plan-17 原先的表述**更干净**（推导，标注为分析）。

**遗留待验证（仅剩两项）**：X1（执行流与槽位 1:1 的路径穷尽）、X3（`b90ddcba5` 的原始动机）。



| 威胁 | 在「每线程独占槽位、永不迁移」下是否成立 | 依据 |
|---|---|---|
| **T1：抢占后另一线程访问同一 per-cpu 槽位** | **不成立**（这是该论断的核心，槽位独占即消除） | `uma_int.h` "only from their associated CPU"；rump 先例 |
| **T2：抢占后同一线程在另一 CPU 上继续，导致 `zpcpu_get()` 返回不同槽位** | **不成立**。f-stack 的槽位索引来自**软件量**（`__thread pcpup` /稠密worker 序号），**不是**真实硬件 CPU 号，所以线程被迁移到别的物理核也仍然访问自己那份槽位 | libuinet `uinet_pcpu_get()` 用 `curthread->td_oncpu`（软件虚拟 CPU 号）而非硬件 CPU 号；f-stack 用 TLS 指针（plan-17 §1.1） |
| **T3：抢占导致临界区变长，per-cpu cache 数据处于中间不一致状态时被别人看到** | **不成立**（无人看得到——槽位独占）；但**`uma_reclaim(UMA_RECLAIM_DRAIN_CPU)` 类路径会遍历所有 CPU 的 cache**，那是**跨槽位访问**，须单独核验 | uma(9)：`UMA_RECLAIM_DRAIN_CPU` "回收所有缓存项（含 per-CPU）"；`UMA_RECLAIM_DRAIN` 则 "per-CPU 缓存中的空闲项保持不动" |
| **T4：抢占导致 SMR 读区间被拉长，`rd_seq` 卡住 → 内存膨胀** | **成立且无法用槽位独占消除**。这是**性能/内存**问题不是正确性问题，但极端情况会触发 `smr_advance()` 里 `SMR_SEQ_DELTA(goal, s_rd_seq) >= SMR_SEQ_MAX_DELTA` 的强制 `smr_wait()`（busy loop） | `subr_smr.c` 的 `smr_default_advance()` 原文 |
| **T5：抢占导致 SMR 序号 ABA** | **可能成立**，见上表 X2。上游明确以此为 `critical_enter` 的独立理由 | `smr_poll()` 注释 "avoid ABA races caused by long preemption sleeps" |
| **T6：`SMR_LAZY` 的 grace period 依赖「每 CPU 定期时钟中断」** | **用户态不成立**（无 per-CPU 时钟中断）。**须核查 f-stack 是否用到 `SMR_LAZY`** | `subr_smr.c` `SMR_LAZY_GRACE` 注释原文（见 §2.6） |

> **总结（供leader 裁决用，已按 X2 代码坐实结果修正）**：team-lead 提出的论断——「上游 `critical_enter` 防的是同 CPU 上的抢占后另一线程访问同一 per-cpu 槽位；若用户态每线程独占槽位则被抢占无害」——**对 T1/T2/T3 正确，且有上游原文（`uma_int.h` "may be accessed safely only from their associated CPU"）+ counter(9) 架构级先例 + rump/Seastar 工程先例三重支撑**。因此：
> - **G1（每线程独占稠密槽位）是 G2 的必要前提**，且该论断已被完整证成；
> - **G2（移除 `uma_crit_lock`）在「与 SMR 的耦合」这一维度上已被排除风险**（X2 已坐实 `critical_enter` 全树为 nop，G2 对 SMR 零影响）；
> - **G2 剩余门禁只有两项**：X1（所有触碰 per-cpu 槽位的执行流是否都 1:1 独占某个固定槽位——含主线程/KNI/callout/`ff_veth`）与 X3（`b90ddcba5` 的原始引入动机是否确为「共享 pcpu 槽位」而非 `uma_page` hash / `page_alloc` 并发）。二者均为 f-stack 私有代码问题，**外部资料无法替代本地核验**。
> - **T4（`rd_seq` 卡住→内存膨胀）/ T5（SMR 序号 ABA）/ T6（`SMR_LAZY` 时钟假设）属既存的SMR 侧风险，与 G2 无因果关系**，应在 spec 17 中作为独立风险项记录（T6 须核查 f-stack 实际是否用到 `SMR_LAZY`）。

### 4.3 「线程与槽位 1:1 绑定 + 不迁移」替代 critical section 的先例汇总

| 项目 | 是否有此先例 | 具体形态 | 来源 |
|---|---|---|---|
| **rump kernel (NetBSD)** | **有，且最贴近** | 虚拟 CPU 槽位 `rcpu_storage[MAXCPUS]` 由 lwp 通过 atomic CAS **独占持有**；`kpreempt_disabled()` 恒 true | https://raw.githubusercontent.com/NetBSD/src/trunk/sys/rump/librump/rumpkern/scheduler.c |
| **Seastar / ScyllaDB** | **有（更强形式）** | 线程 pin 到核，shared-nothing，per-core 分配器；**连引用计数都不用原子** | https://raw.githubusercontent.com/scylladb/seastar/master/doc/tutorial.md ；https://www.scylladb.com/product/technology/shard-per-core-architecture/ |
| **DPDK ANS** | **有（但绕过了问题）** | per-lcore独立 TCP 栈 "free lock"；**但 UMA 被整体换成 `rte_mempool`** | https://github.com/ansyun/dpdk-ans |
| **libuinet** | **否——反例侧的弱信号**：建立了稠密槽位与运行期边界断言，但 UMA 仍靠**一把全局 `bucket_lock`** 串行化（另有独立的 `page_slab_hash_lock`），**未**用「槽位独占」替代锁；且 `uinet_pcpu_locks[MAXCPU]` 标注 `XXX temporary until final pcpu approach is determined`（用途与 UMA 无关，本轮未核实） | 见 §3.1(a)(d) | https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_smp.c ；https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_uma_int.c |
| **FreeBSD 上游 counter(9)** | **有（架构级）** | amd64 上 `counter_enter()` 是 **nop**，因为单指令更新对抢占天然安全 | https://man.freebsd.org/cgi/man.cgi?query=counter&sektion=9&manpath=FreeBSD+15.0-RELEASE |
| **反驳该论断的资料** | **未找到**。检索未发现任何资料主张「即使每线程独占 per-cpu 槽位、仍必须禁抢占才能保证 UMA per-cpu cache 正确」 | — | 如实声明：无反例来源 |

**注意 libuinet 这一行是一个「弱信号」**：一个同类项目在建立了稠密槽位之后**仍然保留了 per-cpu 锁**，并把pcpu 方案标为「未定稿」。这**不能证明**去锁不可行（那把锁的用途未核实，可能与 UMA 无关），但**足以要求 G2 必须有实测数据支撑，不可仅凭推理放行**（与 plan-17 §0.4「G2 是主目标，须有性能数据支撑」的要求一致）。

---

## 6. 明确的知识边界（不越界结论）

1. **f-stack 社区对本轮问题零讨论**：没有任何公开资料涉及「f-stack + SMR / SMP-aware pcpu / 去 UMA 全局锁」。issue #27（2017、FreeBSD 11时代、评论区未加载）**不构成参考**。本轮无先例。
2. **SMR 层面无任何用户态先例**：libuinet 停在 FreeBSD 9.1（无 SMR）、ANS 不用 UMA/SMR、rump 是 NetBSD（无 SMR）。**f-stack 是（据公开资料）第一个把 FreeBSD 13+ SMR 搬进用户态多线程环境的项目**，SMR 相关结论只能靠上游源码语义推导 + 本地实证，**没有外部事故案例可引**。
3. **本文所有源码引用来自 `freebsd/freebsd-src` 的 `main` 分支**（因 `cgit.freebsd.org` 有 Anubis 反爬无法抓取）。本仓库参照树是 `releng/15.0`，**行号与细节须由 `res-code` 在 `/data/workspace/freebsd-src-releng-15.0` 复核**；本文引用的关键点（`critical_enter` 位置、`c_seq` 语义、`mp_maxid` 循环、`CPU_FOREACH` 扫描、`uma_int.h` 注释）在 13→15→main 之间未见结构性改动，但**这一判断本身也需代码复核**。
4. **`pcpu(9)` man页不存在**（man.freebsd.org 无此 section 9 页面）。`zpcpu_get`/`zpcpu_offset_cpu`/`UMA_PCPU_ALLOC_SIZE` 的语义**只有源码是权威**（`sys/sys/pcpu.h`、`sys/vm/uma.h`）。本文 §4.1 引用的 `uma_int.h` 分析提到 `UMA_PCPU_ALLOC_SIZE` 定义在 `sys/vm/uma.h` 且等于 `PAGE_SIZE`——**该点已由 `res-code` 在本地代码坐实为 `UMA_PCPU_ALLOC_SIZE = PAGE_SIZE = 4096`、`zpcpu_offset_cpu(cpu) = 4096 * cpu`（plan-17 U1 关闭）**，与本文所引外部资料一致，无冲突；**若后续任何外部资料与此不一致，一律以代码为准**。
5. **`CPU_FOREACH` 在 f-stack 非 SMP 构建下的实际展开、以及 `all_cpus` 是否为全0，本文未能确定**（§2.4 已标注为本轮优先级最高的待验证项）。若 `CPU_FOREACH` 遍历为空，`smr_poll_scan()` 会把 `rd_seq` 直推到 `s_wr_seq` ⇒ **SMR 等价于完全失效**——这比槽位共享严重得多。**本文只提示，不下结论。**
6. **属机制/语义推导（非文献直述）的部分**已在正文逐处标注，主要是：§2.1 的 `atomic_add` 累加后果与 UAF 链条、§2.4 的 `CPU_FOREACH` 风险、§3.1 的 f-stack/libuinet 方案差异分析与「per-worker 一把锁」回退建议、§3.2 的 rump 对照表与结论、§4.2(a)1 的「不变式 vs 维持手段」推导、§4.2 总结中的「宏改nop 而非删除」建议。
7. **未找到可靠来源的条目**已集中列于 §3.5，另有 §1.3（知乎文403）、§1.4（f-stack 社区无讨论）、§2.6（SMR 无独立设计文档）、§4.3 末行（无反驳该论断的资料）。**均未编造替代内容。**
8. **未执行任何 shell 命令、未修改任何源码文件**；本 agent 只写了本文件。

---

## 7. 统一来源清单（可核查）

**FreeBSD 官方 man 页**
1. `smr(9)`（FreeBSD 15.0，2023-01-17；算法 Jeff Roberson，man 页 Mark Johnston） — https://man.freebsd.org/cgi/man.cgi?query=smr&sektion=9&manpath=FreeBSD+15.0-RELEASE
2. `uma(9)`（FreeBSD 15.0，2023-01-16） — https://man.freebsd.org/cgi/man.cgi?query=uma&sektion=9&manpath=FreeBSD+15.0-RELEASE
3. `counter(9)`（FreeBSD 15.0，2025-06-19；Gleb Smirnoff / Konstantin Belousov） — https://man.freebsd.org/cgi/man.cgi?query=counter&sektion=9&manpath=FreeBSD+15.0-RELEASE
4. `cpuset(9)`（FreeBSD 15.0，2025-08-07；宏 Jeff Roberson，man 页 Conrad Meyer） — https://man.freebsd.org/cgi/man.cgi?query=cpuset&sektion=9&manpath=FreeBSD+15.0-RELEASE
5. **`pcpu(9)`：不存在**（如实声明）

**FreeBSD 上游源码（`freebsd/freebsd-src` main 分支 raw）**
6. `sys/kern/subr_smr.c`（GUS 算法注释、`smr_create`/`smr_poll`/`smr_poll_scan`/`smr_advance`、`SMR_LAZY_GRACE`） — https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/kern/subr_smr.c
7. `sys/sys/smr.h`（`struct smr`、`smr_enter`/`smr_exit` 实现与 `critical_enter`） — https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/sys/smr.h
8. `sys/vm/uma_int.h`（"PCPU caches are protected by critical sections… only from their associated CPU"、`struct uma_cache`、锁宏清单） — https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/vm/uma_int.h
9. （抓取失败，已改道）`cgit.freebsd.org/src/plain/sys/kern/subr_smr.c` — Anubis 反爬拦截，未取得内容

**FreeBSD 官方 commit / 项目报告**
10. commit `87767249233f`（stable/13，MFC `8232a1eddadd`）*cpuset(9): Refer to CPU_SETSIZE not MAXCPU*，Brooks Davis，2022-09-23，D36679 — https://lists.freebsd.org/archives/dev-commits-src-all/2022-September/017116.html
11. FreeBSD 季度状态报告 2023Q2《Increasing MAXCPU》，Ed Maste，2023-07-18 — https://www.freebsd.org/status/report-2023-04-2023-06/maxcpu/
12. Phabricator D36838*amd64: Bump MAXCPU to 1024 (from 256)*（仅引用，未抓取正文） — https://reviews.freebsd.org/D36838

**其他用户态内核/协议栈移植（源码原文）**
13. libuinet `lib/libuinet/uinet_subr_smp.c`（Kip Macy 2010 / Patrick Kelsey 2013） — https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_smp.c
14. libuinet `lib/libuinet/uinet_subr_pcpu.c`（Patrick Kelsey 2013） — https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_subr_pcpu.c
14a. libuinet `lib/libuinet/uinet_uma_int.c`（Patrick Kelsey 2013；全局 `bucket_lock` + 独立 `page_slab_hash_lock`，**不**覆盖 `critical_enter`） — https://raw.githubusercontent.com/pkelsey/libuinet/master/lib/libuinet/uinet_uma_int.c
15. libuinet 仓库 README（FreeBSD 9.1 基线、netmap/libpcap、libplebnet 渊源） — https://github.com/pkelsey/libuinet
16. libuinet `lib/libuinet/` 目录清单 — https://github.com/pkelsey/libuinet/tree/master/lib/libuinet
17. NetBSD `sys/rump/librump/rumpkern/scheduler.c`（rev1.55，2023-10-05；Antti Kantee 2010, 2011） — https://raw.githubusercontent.com/NetBSD/src/trunk/sys/rump/librump/rumpkern/scheduler.c
18. rump kernel 官网 — https://rumpkernel.github.io/
19. Antti Kantee《Rump File Systems: Kernel Code Reborn》USENIX ATC 2009（仅列为背景，未用于本文任何结论） — https://www.usenix.org/legacy/event/usenix09/tech/full_papers/kantee/kantee.pdf
20. rump kernel 书籍 PDF（**抓取失败/超时**，未使用） — http://www.fixup.fi/misc/rumpkernel-book/rumpkernel-bookv2-web.pdf

**Seastar / ScyllaDB**
21. Seastar tutorial（Nadav Har'El、Avi Kivity；官方仓库 master） — https://raw.githubusercontent.com/scylladb/seastar/master/doc/tutorial.md
22. ScyllaDB《Shard-per-Core Architecture》 — https://www.scylladb.com/product/technology/shard-per-core-architecture/

**DPDK ANS**
23. `ansyun/dpdk-ans` README（per-lcore TCP 栈、free lock、DPDK 原语替换） — https://github.com/ansyun/dpdk-ans

**f-stack 相关**
24. F-Stack Issue #27（2017-06-05，Closed，**评论区未加载**） — https://github.com/F-Stack/f-stack/issues/27
25. F-Stack 官网（移植 FreeBSD 11.0 stable） — http://f-stack.org/
26. F-Stack 仓库 — https://github.com/F-Stack/f-stack
27. F-Stack Development Guide 社区转载（列出 `pcpu` / `curthread` / `proc0` / `thread0` 改造项） — https://rtoax.blog.csdn.net/article/details/107987976｜https://www.codeleading.com/article/50794435172/
28. 《基于dpdk 的用户态协议栈 f-stack 实现分析》（2020-04-27，四类改造点概括） — https://blog.csdn.net/21cnbao/article/details/105803864
29. 《F-Stack 高性能网络框架开发指南》（2025-06-10，同上概括） — https://blog.csdn.net/gitblog_01019/article/details/148549951
30. 《用户态 TCP 协议栈及 dpdk 用户态协议栈 f-stack》（2021-05-28） — https://zhuanlan.zhihu.com/p/376144528
31. 《将 F-Stack 改造为多线程库》（2025-02，**抓取失败 HTTP 403，未使用其内容**） — https://zhuanlan.zhihu.com/p/21075875679
32. 《使用 Photon 协程库与 F-Stack 简化 DPDK 应用开发》（2023-05-10，协程方向，不同层次问题） — https://developer.aliyun.com/article/1208390

**第三方整理（仅佐证，非独立依据）**
33. DeepWiki《UMA (Universal Memory Allocator)》（**AI 生成的第三方整理**） — https://deepwiki.com/freebsd/freebsd-src/4.3-uma-(universal-memory-allocator)

**未取得可靠来源的检索目标**（详见 §3.5、§1.3、§1.4、§2.6、§4.3）
- mTCP 论文原文中的 per-core/无共享表述
- OpenFastPath / ODP 官方设计文档
- libuinet 版 `uma_core.c` / `uinet_uma_int.h` 中 `bucket_lock`/`page_slab_hash_lock` 的**实际调用点**（`uinet_uma_int.c` 本体已核实，见 §3.1(d)）
- libuinet `uinet_pcpu_locks[MAXCPU]` 的真实用途（已确认与 UMA 无关）
- 「用户态多线程共享 SMR槽位导致 UAF」的公开 bug 报告
- 反驳「1:1 绑定可替代 critical section」的资料
- SMR 的独立设计文档（源码注释即权威）

---

## 落盘进度

- [x] 方向 1（f-stack 官方/社区）— §1，**已完成**
- [x] 方向 2（FreeBSD 上游 SMR/UMA/mp_maxid/MAXCPU 语义）— §2，**已完成**
- [x] 方向 3（其他用户态 FreeBSD/NetBSD 栈移植经验）— §3，**已完成**（含§3.5 未找到来源清单）
- [x] 方向 4（用户态无关抢占语义下 UMA per-cpu 快路径正确性）— §4，**已完成**
- [x] 方向 5（`cpuset_t`/`CPU_SETSIZE`/MAXCPU ABI）— §5，**已完成**
- [x] 知识边界（§6）与统一来源清单（§7）— **已完成**

> 第1 批落盘：2026-08-04（§1/§2/§5）；第 2 批（终版）落盘：2026-08-04（§3/§4/§6/§7）；
> 第 3 批补充：2026-08-04 —— 回填 leader 第 1 次轮询给的代码坐实结果（§4.2(b-2) X2 结论回填、§6 边界第 4 条`UMA_PCPU_ALLOC_SIZE`）；
> 第 4 批补充：2026-08-04 —— 完成 leader 第 2 次轮询的可选项，新增 **§3.1(d) libuinet `uinet_uma_int.c` 核实**（并据此**修正** §3.1(a) 第 4 条的错误推断、§4.3 libuinet 行、§3.5 未核实清单、§7 来源清单）。
> **本 agent 全部调研工作完成，无未完成项。** 后续若leader 需要追加特定方向（如 libuinet 版 `uma_core.c` 中两把锁的实际调用点、`smr_types.h` 宏语义），可再指派。

---

## 8. 终局回填与本文时效性声明（2026-08-04，任务收尾时由 `res-web` 补记）

本轮已收尾：裁决为**候选 A（全树 `-DSMP`）**，落地提交 `c7996a94f`（G1）、`57b612d16`（G2）、`06396b501`（spec 17 及全部调研/门禁材料）。为避免后人误读本文的前提假设，把三条**由队内代码实证得出、与本文部分推理前提相冲突**的终局事实回填于此。**一律以代码/实测为准，本文对应段落的推理视为已被取代。**

| # | 终局事实（来源：队内 `res-code`/`designer`/`res-build`/`tester` 的代码与实测） | 影响本文哪一段 |
|---|---|---|
| **F1** | **`curcpu` 在 f-stack 中被硬编码为 0，UMA per-cpu cache 并不走 `zpcpu_get()`**（由 `designer` 发现，是决定 G1 成败的关键点）。 | **取代本文 §4 的隐含前提**。本文 §4.1/§4.2 论证时假设「UMA per-cpu cache 经 `zpcpu_get()` 按槽位索引」，据此推导 T1/T2/T3。该前提在 f-stack 实际代码中**不成立**：UMA cache 的索引路径与 SMR 的 `zpcpu_get()` 路径**是两条不同的路**。故§4 关于「槽位独占 ⇒ UMA 快路径安全」的推理**须以 `designer` 在 spec 17 中的代码级论证为准**，本文该段只保留「上游语义是什么」的引用价值（§4.1 的 `uma_int.h` 原文引用仍然有效且被采纳）。 |
| **F2** | **f-stack 中 UMA 的全部 `mtx` 都是 no-op**，且 **`mp_maxid` 从来没有赋值点**（由 `res-code` 坐实）。 | **强化并部分取代 §4.1 末段与 §3.1(d) L2/L3**。本文曾提示「若 f-stack 把 `uz_lock`/`ZDOM_LOCK`/`ZONE_CROSS_LOCK` stub 空则是独立缺陷」——现已确证**确实全为 no-op**。另`mp_maxid` 无赋值点这一事实，使本文 §2.4「`mp_maxid` 与 `UMA_ZONE_PCPU` 必须成对修改」的告警在f-stack 场景下由「潜在风险」变为「确定缺口」。最终 G2 采用 **G2-b** 形态，本文 §3.1(d) 推荐的 G2-a 未被采纳——**以 `designer` 的 G2-b 裁决与 `reviewer` 的双重放行依据为准**；本文 L2 提出的「`UMA_PAGE_HASH` 是真共享结构、槽位独占对它零保护」这一点仍成立，其处置方式见 spec 17。 |
| **F3** | **候选 A 的成本被 `res-build` 实测证伪为「仅需补 1 个 `smp_topo` stub」**；另 `tester` 抓到静态分析完全未预见的 **3/4 线程 `uma_startup1()` 确定性崩溃**。 | **取代本文 §5.3 末段的「候选 A 成本只能由实际编译错误清单量化」这一保留意见**（该保留意见方向正确，实测结论是成本远低于预期）。同时印证本文 §6 边界第1、2 条的自我限制是必要的——**外网资料无法预见 f-stack 私有代码中的运行期缺陷，`uma_startup1()` 崩溃即为例证。** |

**本文的定位（终局）**：本文的**外部事实与上游语义引用**（§2SMR/UMA/counter/cpuset 语义、§3 libuinet/rump/Seastar/ANS 先例、§5 MAXCPU/cpuset ABI）经门禁采纳，其中 §2.1（SMR per-CPU 槽位独占性）被引为 G1 必要性论证的核心依据，§3.1/§3.2（libuinet 稠密索引实证、rump 线程独占虚拟 CPU）写入设计约束 D6与 G2 回退形态讨论。本文的**推理与建议部分**（已在正文逐处标注为「推导」「分析建议」）凡与上表 F1~F3 冲突者，**一律以代码/实测为准，不再作为依据**。§3.5/§6/§7 中「未找到可靠来源」的条目保持原样，未事后补写。

> `res-web` 交付完毕，无未落盘材料。
