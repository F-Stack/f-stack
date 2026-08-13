# M18 遗留风险专项 —— 修复设计（D）

调研对象：`/data/workspace/f-stack`，HEAD `9ef6dc92e`。
上游调研：`_m18_A_p1_p3_analysis.md`、`_m18_B_p2_p5_analysis.md`、`_m18_C_p4_p6_analysis.md`。
本设计只产出修复方案，不改动任何产品代码。所有结论附 `file:line`，以实际代码为准；凡与本设计引用的调研结论不一致处，均已按实际读到的代码更正并显式标注。

---

## 0. 总体裁决汇总

| 问题 | 裁决 | 落点 | 备注 |
| --- | --- | --- | --- |
| P1 DPCPU 别名（ipfw dyn_hp） | 不修（独立立项） | — | 本轮只产出分析 + TLS 修复方向 |
| P2 counter 竞争 | 修 | `lib/include/machine/counter.h` | 三函数原子化，单文件 |
| P3 tcp_hpts callout 归属 + p_mtx 无互斥 | 不修（独立立项） | — | 本轮仅文档化结论，见 §3 |
| P4 net.isr.dispatch direct 防护 | 修 | `lib/ff_freebsd_init.c` | 启动期防护，单文件 |
| P5 ff_subr_prf 行缓冲 | 修 | `lib/ff_subr_prf.c` | 两行改 `__thread` |
| P6 ff_pthread_create fail-fast | 修 | `lib/ff_thread.c` + `lib/ff_api.h` | fail-fast + 文档化 |

优先级与风险面整体判断：P2 / P4 / P5 / P6 均为「单文件、最小 diff、零 thread_mode=0 回归」的小修，本轮可做；P1 / P3 涉及 DPCPU/pcpu 重建或 hpts 驱动模型重构，范围大、风险高，独立立项更稳妥。

---

## 1. P1：ipfw 动态状态 DPCPU 槽位别名 —— 不修（独立立项）

### 1.1 裁决

**不修（独立立项）**。本轮只产出分析结论 + 修复方向，不动代码。

### 1.2 结论复核

调研结论与实际代码一致，核心事实已坐实：

- `freebsd/netpfil/ipfw/ip_fw_dynamic.c:224-226` 用 `DPCPU_DEFINE_STATIC(void *, dyn_hp)` 存储 per-CPU hazard pointer，`DYNSTATE_GET/PROTECT` 分别经 `DPCPU_ID_PTR((cpu), dyn_hp)` / `DPCPU_PTR(dyn_hp)` 寻址。
- `freebsd/sys/pcpu.h:113-128` 的 `_DPCPU_PTR(b, n) = (b + (uintptr_t)&DPCPU_NAME(n))`；`DPCPU_ID_PTR` 用 `dpcpu_off[(i)]`，`DPCPU_PTR` 用 `PCPU_GET(dynamic)`。
- `freebsd/kern/subr_pcpu.c:76` `dpcpu_off[MAXCPU]` 静态恒 0；`:83-97` `pcpu_init()` 只 `bzero`、**从不设 `pc_dynamic`**；`:99-118` `dpcpu_init()` 是唯一写入 `pc_dynamic`/`dpcpu_off[]` 的地方。
- f-stack 用户态**从不调用 `dpcpu_init()`**（`lib/` 下命中 0，只有 `ff_freebsd_init.c:104-113` 调 `pcpu_init`），且不编译架构 machdep 文件。

由此：所有 CPU 的 `DPCPU_ID_PTR(i, dyn_hp)` 都解析到同一主副本 `&dpcpu_entry_dyn_hp`，DPCPU 槽位退化为单槽位，HP 机制失效（`dyn_free_states()` 的 `CPU_FOREACH` 读到同一份值，只能保护最后一个被 `DYNSTATE_PROTECT` 写入的 state），叠加 `critical_enter/exit` 在 f-stack 下无抢占保护，存在 use-after-free 风险。

### 1.3 不修的理由

1. **触发条件苛刻**：需 ipfw `keep-state` / `check-state` / `limit` 动态规则 + 多 worker 并发 + 状态过期回收三个条件同时满足才触发。单线程（thread_mode=0）或不用 ipfw 动态规则时完全无影响。
2. **根因在 pcpu/DPCPU 基础设施层**，不是 ipfw 单点问题：`dpcpu_off[]` 恒 0 是全局性的，任何 DPCPU 消费者（不止 `dyn_hp`）都受影响。仅修 ipfw 的 `dyn_hp` 是「治标」，真正要修的是 f-stack 的 DPCPU 重建（见 §1.5 方案 B），范围大、与 P3 的 hpts 实例模型、M17 的 pcpu/smr 视图存在耦合。
3. **修复成本高、收益相对低**：正确性 bug（潜在 UAF）而非确定 crash，独立成小项，单独排期验证比塞进本轮更可控。

### 1.4 独立立项建议

立项名：**「f-stack per-thread DPCPU 槽位重建（以 ipfw dyn_hp 为试点）」**。

立项范围建议：
- 试点仅覆盖 `dyn_hp` 一处（TLS 方案，见 §1.5），不一步到位重建整个 DPCPU 体系。
- 验证方式：ipfw 动态规则 + 多 worker 压测，用 ASAN/TSAN 或重点观察 `dyn_free_states()` 的 `CPU_FOREACH` 收集行为。

### 1.5 修复方向（供立项参考，本轮不实现）

**方案 A（推荐，TLS 最小侵入）**：

- 把 `dyn_hp` 从 `DPCPU_DEFINE_STATIC` 改为 per-thread TLS：`static __thread void *dyn_hp_tls;`
- `DYNSTATE_GET(cpu)` / `DYNSTATE_PROTECT(v)` 直接用该 TLS 槽位读写（`ck_pr_load_ptr/store_ptr` 保留，或简化为普通 `__atomic_load/store`）。
- `dyn_free_states()` 的 `CPU_FOREACH` 收集逻辑需改为「遍历 f-stack 实际线程集合的 HP 槽位数组」——这是本方案的主要工作量：需要维护一个全局的「线程 HP 槽位数组」，每个 `ff_pcpu_thread_init` 的线程在其中占一个槽，回收线程遍历该数组。
- 本项目 `__thread` 已有大量先例（`pcpup`/`pcurthread`/`cc_cpu`/`msg_iov_tmp` 等），TLS 在 lcore 线程下工作正常，无兼容性风险。

**方案 B（重建 DPCPU，工作量大，不推荐先做）**：在 `ff_pcpu_thread_init` 为每个 cpuid 分配独立 DPCPU 区并填 `dpcpu_off[cpuid]`，模拟 linker set `DPCPU_START/DPCPU_BYTES`。依赖用户态共享库的 `__section(DPCPU_SETNAME)` 布局，在 `-nostdinc` + override 头环境下不可靠，且需与 UMA 启动顺序（`mp_maxid` 须在 `uma_startup1` 前定型）联动，成本高。

**兜底（本轮）**：不修即维持现状；若确有 ipfw 动态规则 + 多线程场景，短期可文档建议「ipfw 动态规则场景暂限 thread_mode=0」。

---

## 2. P2：counter 统计竞争（丢失更新）—— 修

### 2.1 裁决

**修**。方案 = 把 `lib/include/machine/counter.h` 的 `counter_u64_add` / `counter_u64_fetch_inline` / `counter_u64_zero_inline` 三个函数改为原子操作。单文件改动。

### 2.2 代码事实复核

调研结论与实际代码一致，关键点补充确认如下：

1. `lib/include/machine/counter.h:58-62` `counter_u64_add` 是 `*c += inc;`（非原子读-改-写）。
2. `:43-47` `counter_u64_fetch_inline` 是 `return (*p);`，`:49-53` `counter_u64_zero_inline` 是 `*c = 0;`。
   - **重要补充（调研未强调）**：这两个函数被 `#ifdef IN_SUBR_COUNTER_C` 包裹（`:41` / `:54`），**只在 `subr_counter.c` 内编译**（`subr_counter.c:40` `#define IN_SUBR_COUNTER_C` 后 `#include <sys/counter.h>`）。它们是 `subr_counter.c` 内 `counter_u64_fetch`/`counter_u64_zero`（`:52-57` / `:45-50`）的实现，**不在其它编译单元内联**。
   - 而 `counter_u64_add`（`:58-62`）**在 `#ifdef` 块之外**，是全局 `static inline`，被所有 TU 内联（≥85 处调用点，经 `VNET_PCPUSTAT_ADD` → `IP6STAT_INC` 等）。
3. `freebsd/sys/counter.h:32` `typedef uint64_t *counter_u64_t;`（普通指针，非 per-cpu 句柄）。`:35` `#include <machine/counter.h>` 命中 override 头。
4. `counter_u64_add_protected`（`:56`）`#define` 到 `counter_u64_add`，原子化后二者自动等价。
5. `counter_enter/exit`（`:38-39`）是空操作，无需改。

### 2.3 原子操作手段确认（关键，`-nostdinc` + override 头环境）

- **`__atomic_*` GCC 内建可用，无需任何额外头文件**：GCC 内建 `__atomic_fetch_add` / `__atomic_load_n` / `__atomic_store_n` 是编译器内建，不依赖 libc 头文件，在 `-nostdinc` 下完全可用（内建由编译器直接展开为指令，不查 include 路径）。
- 项目已有原子先例：`lib/ff_kern_timeout.c:1245` `atomic_add_int(&ticks, 1)`（`ff_hardclock` 内），说明 `sys/atomic.h`（或其 machine 版本）在 lib 编译环境下可被正常 include；但本方案**不引入新头文件**，直接用 `__atomic_*` 内建，最省事、零头文件依赖。
- `counter_u64_t` 是 `uint64_t *`，8 字节对齐由 `pcpu_zone_8`（`subr_pcpu.c:146-150` `uma_zcreate("pcpu-8", 8, ...)`）保证，`__atomic_*` 对 8 字节对齐地址无额外要求（对齐到自然边界即可）。
- **`volatile` 不需要**：`__atomic_*` 内建接受普通指针，语义上已保证原子性，不必加 `volatile` 限定。

### 2.4 精确改法（最小 diff）

文件：`lib/include/machine/counter.h`。

改动 1 —— `counter_u64_add`（`:58-62`）：

```c
static inline void
counter_u64_add(counter_u64_t c, int64_t inc)
{
    __atomic_fetch_add(c, inc, __ATOMIC_RELAXED);
}
```

改动 2 —— `counter_u64_fetch_inline`（`:43-47`，`IN_SUBR_COUNTER_C` 块内）：

```c
static inline uint64_t
counter_u64_fetch_inline(uint64_t *p)
{
    return (__atomic_load_n(p, __ATOMIC_RELAXED));
}
```

改动 3 —— `counter_u64_zero_inline`（`:49-53`，`IN_SUBR_COUNTER_C` 块内）：

```c
static inline void
counter_u64_zero_inline(counter_u64_t c)
{
    __atomic_store_n(c, 0, __ATOMIC_RELAXED);
}
```

改动 4（可选，建议一并）—— `counter_u64_add_protected`（`:56`）：原子化后无需改（`#define` 自动等价），保持不变即可，最小 diff。

### 2.5 内存序选择说明

- `__ATOMIC_RELAXED`：counter 仅用于统计计数，不参与任何跨线程同步/发布-订阅协议，**无同步语义**，relaxed 足够，且开销最低（无内存屏障，仅保证「不丢失更新」的原子读-改-写）。若追求最保守，可用 `__ATOMIC_SEQ_CST`，但统计场景无必要，会引入不必要的屏障开销。**建议 relaxed**。

### 2.6 边界条件与注意点

1. **`EARLY_COUNTER` 路径**（`counter.h:32`）：`#define EARLY_COUNTER &pcpup->pc_early_dummy_counter`，`COUNTER_U64_DEFINE_EARLY`（`:34-36`）把早期 counter 指到 `pcpup` 的 `pc_early_dummy_counter` 字段。原子化 `counter_u64_add` 不影响这条路径（早期 counter 是静态定义的 `counter_u64_t`，其 add 同样走原子 fetch-add，语义不变）。**注意**：该路径依赖 `pcpup` 非 NULL，属极早期启动（SYSINIT 重定向前），与 P6 的 `pcpup==NULL` 线程无关（`COUNTER_U64_DEFINE_EARLY` 只在静态定义处，不在 `ff_pthread_create` 线程运行时执行）。
2. **仍为单槽计数器**：原子化消除「丢失更新」，但 `fetch`/`add` 仍只读写第 0 槽（`subr_counter.c:63` 分配侧虽按 `-DSMP` 分了 `mp_maxid+1` 槽，但退化实现只碰第 0 槽）。语义不变（单槽累加），正确性（不丢）得到保证。
3. **性能退化（可接受）**：多线程高并发写同一 counter 时，退化为单 cache line 上的原子热点，有 cache 乒乓。但统计计数本非热路径（热路径是数据面转发），且「不丢更新」的正确性收益大于这微小的 cache 竞争代价。若要零竞争，需恢复 per-cpu 语义（见 §2.7，成本高，不在本轮）。
4. **负值增量**：`int64_t inc` 可为负（`counter_u64_add(c, -1)`），`__atomic_fetch_add` 对 `uint64_t` 加负数按无符号回绕，与 `*c += inc` 语义一致（原实现同样是 `uint64_t` 加 `int64_t` 隐式转无符号）。

### 2.7 不选「恢复 per-cpu 语义」的理由

恢复 per-cpu 需让 `counter_u64_add` 用 `zpcpu_add`（写当前线程槽）、`fetch` 用 `CPU_FOREACH` 累加，并补回 `lib/include/machine/pcpu.h:40-42` 已 undef 掉的 `zpcpu_*` 宏 + per-thread 槽位映射。这直接与 P1 的 DPCPU/pcpu 重建联动，成本高、风险大，不属「最小 diff」，留给 P1 立项时一并评估。

### 2.8 回归面

- **thread_mode=0（单进程）零回归**：单线程下 `*c += inc` 与 `__atomic_fetch_add` 结果完全一致，无行为差异；relaxed 原子操作对单线程无可见开销。
- **编译面**：`__atomic_*` 内建 GCC ≥ 4.7 全支持，f-stack 已要求 GCC 支持（项目大量用 `__sync`/`atomic_*`），无兼容性风险。
- **不改分配侧**：`subr_counter.c` 的 `counter_u64_alloc/free/zero/fetch` 均不改，只改 override 头的 inline 实现。

---

## 3. P3：tcp_hpts callout 归属错配 + p_mtx 无互斥 —— 不修（独立立项）

### 3.1 裁决

**不修（独立立项）**。本轮仅文档化结论与修复方向。

### 3.2 结论复核与裁决依据

调研给出的两个方向（(a) callout 归属对齐；(b) 保持旁路 + 显式收敛 + per-instance 互斥），我基于实际代码复核后，裁决「**本轮不修**」，理由如下：

1. **功能当前「能跑」，缺陷是设计层面的潜在并发重入，非确定故障**：
   - f-stack 已用 `ff_tcp_hpts_softclock()`（`ff_kern_timeout.c:1290-1295`）显式旁路：main_loop 每轮（`ff_dpdk_if.c:2934`）直接调 `tcp_hpts_softclock` 函数指针（`= __tcp_run_hpts`），绕过 callout + swi（两者在 f-stack 均 no-op，`ff_kern_intr.c:84-107`）。这条旁路是能正常驱动 hpts pacing 的。
   - 旁路注释（`ff_kern_timeout.c:1267-1286`）明确记录了「bypass the tcp_hpts_softclock *macro* gate」与「invoke run function directly」的设计意图，是有意为之。

2. **真正的隐患是「并发重入 `tcp_hptsi`」，而其触发需要额外条件**：
   - `__tcp_run_hpts`（`tcp_hpts.c:1590-1660`）里已有 `p_hpts_active` 标志（`:1599-1602` / `:1608-1609`）做了一层软互斥：`if (hpts->p_hpts_active) return;` 然后 `HPTS_TRYLOCK` 后再次检查 `p_hpts_active`。**但由于 `p_mtx` 在 f-stack 下无互斥（`HPTS_TRYLOCK` 恒返回 1，`HPTS_LOCK/UNLOCK` no-op，`lib/include/sys/mutex.h:74-76`），`p_hpts_active` 的 check-then-set 不是原子的**：两个 worker 可同时通过 `if (hpts->p_hpts_active)` 检查、同时进入 `tcp_hptsi`。
   - 触发条件：两个 worker 并发进入 `ff_tcp_hpts_softclock`（即 main_loop 并发执行）且 `tcp_choose_hpts_to_run`（`:1549-1588`）选中同一 hpts 实例。`tcp_choose_hpts_to_run` 按 `curcpu % rp_num_hptss`（`:1587`）或「最久未跑」选实例，worker 数 == `rp_num_hptss` 且 `grp_cnt==1` 时，每个 worker 的 `curcpu` 唯一 → 选到不同实例 → 不重入；**只有当 worker 数 != hpts 实例数、或 NUMA 分组、或多个 worker 共享同一 curcpu 时才可能撞同一实例**。
   - 因此这是「潜在、条件依赖」的重入风险，不是确定 bug。

3. **修复方向均非「最小 diff」，风险与收益不匹配**：
   - 方向 (a)「callout 归属对齐」：需要为每个 worker 重挂自己名下 hpts 的 callout 到 worker 自己的 callwheel，并让 worker 的 `ff_hardclock_worker` 到期后真正调 `tcp_hptsi`（而非 `swi_sched` no-op）。这要改动 callout 驱动模型 + `ff_hardclock_worker`，侵入大、与现有旁路并存会语义混乱。
   - 方向 (b)「旁路 + per-instance 互斥」：给 `p_mtx` 换成真实互斥（DPDK `rte_spinlock_t` 或 pthread mutex）。但 `p_mtx` 是 `struct mtx`（FreeBSD 原生类型），全仓 `HPTS_LOCK/TRYLOCK/UNLOCK` 三处宏（`tcp_hpts.c:217-219`）及其它 `mtx_*` 调用点都基于 `struct mtx`，把 `p_mtx` 换成 `rte_spinlock_t` 会连锁改动 `struct tcp_hpts_entry` 定义（`:222`）+ 三处宏 + 所有 `mtx_assert/owned` 调用，非单点改动。若用 pthread mutex 又引入「内核态 TU 依赖 pthread」的新耦合（tcp_hpts.c 是内核态 TU，目前不依赖 pthread）。
   - 更简单的替代：在 `__tcp_run_hpts` 里把 `p_hpts_active` 的 check-then-set 改成原子（`__atomic` CAS），但这仍治标不治本（`tcp_hptsi` 内部还有大量非原子的 wheel 状态操作，仅锁住入口不够）。

4. **与 thread_mode=0 的关系**：thread_mode=0 下 `rp_num_hptss = mp_ncpus = 1`（`ff_freebsd_init.c:298-311`），单 worker 单实例，`tcp_choose_hpts_to_run` 恒选实例 0，无并发重入。**P3 只影响 thread_mode=1 多 worker 场景**，单线程零影响。

### 3.3 独立立项建议

立项名：**「tcp_hpts 多实例并发驱动模型收敛」**。

立项范围建议：
- 明确目标：要么 (a) 彻底对齐 callout 归属（让每个 worker 驱动自己名下的 hpts 实例），要么 (b) 保持旁路但给 hpts 实例加真实 per-instance 互斥 + 显式实例-线程绑定（避免 `tcp_choose_hpts_to_run` 错选）。
- 验证方式：RACK/BBR 多 worker 压测（大文件传输 + pacing 场景），观察 `p_on_queue_cnt`/wheel 状态是否损坏、是否并发 `tcp_output` 同一 tcpcb。
- 前置确认（调研的「未坐实项」需在立项时一并做运行时验证）：(i) `mp_ncpus` 是否恒等于 DPDK worker 数；(ii) RACK/BBR 是否默认启用、pacing 路径是否真的走到。

### 3.4 兜底（本轮）

维持现状（旁路驱动 + `p_hpts_active` 软互斥）。若多 worker + RACK/BBR 场景出现疑似 hpts 相关异常，短期可在文档标注「hpts pacing 多 worker 下存在潜在并发重入风险，待独立立项收敛」。

---

## 4. P4：net.isr.dispatch 必须保持 direct —— 修（启动期防护）

### 4.1 裁决

**修**。落点 `lib/ff_freebsd_init.c` 的 sysctl 注入循环（`:357-368`），对 `net.isr.dispatch` 名字特判：拒绝注入非 direct 值 + `printf` 告警，并强制改回 direct。

### 4.2 代码事实复核

调研结论与实际代码一致，关键点确认：

1. `freebsd/net/netisr.c:151` `NETISR_DISPATCH_POLICY_DEFAULT = NETISR_DISPATCH_DIRECT`；`:155-158` `SYSCTL_PROC` 的 `dispatch` 是 `CTLFLAG_RWTUN`，可运行时/loader 写。
2. `:344-377` `sysctl_netisr_dispatch_policy`：写路径只拒绝 `NETISR_DISPATCH_DEFAULT`（`:368-369`），**不强制 direct**，非 direct 值（hybrid/deferred）可被接受并写回 `netisr_dispatch_policy`。
3. 非 RSS 下 IP 协议 `.nh_dispatch` 缺省（`ip_input.c:139-150` 只在 `#ifdef RSS` 设 HYBRID），dispatch 完全受全局 `net.isr.dispatch` 支配（`netisr_get_dispatch:787-789`）。
4. deferred/hybrid 走到 `netisr_queue_internal` → `NWS_SIGNAL`（`netisr.c:261`）→ `swi_sched`（`lib/ff_kern_intr.c:91-95` 空 stub）→ 无人消费 → 静默丢包。
5. 注入面：`ff_freebsd_init.c:357-368` 遍历 `cfg->freebsd.sysctl` 链表调 `kernel_sysctlbyname`，**无名字过滤**。config.ini `[freebsd.sysctl]` 的解析在 `ff_config.c:176-194`（name/value 存链表，`net.isr.dispatch = hybrid` 会以字符串形式存 `newconf->str`，`vlen = strlen(value)`）。

### 4.3 精确改法（最小 diff）

文件：`lib/ff_freebsd_init.c`，注入循环 `:357-368`。

在循环体内、调用 `kernel_sysctlbyname` 之前加 `net.isr.dispatch` 特判：

```c
    cur = ff_global_cfg.freebsd.sysctl;
    while (cur) {
        if (strcmp(cur->name, "net.isr.dispatch") == 0) {
            printf("net.isr.dispatch must stay direct (hybrid/deferred "
                "silently drop packets); ignoring requested value\n");
            cur = cur->next;
            continue;
        }
        error = kernel_sysctlbyname(curthread, cur->name, NULL, NULL,
            cur->value, cur->vlen, NULL, 0);

        if (error != 0) {
            printf("kernel_sysctlbyname failed: %s=%s, error:%d\n",
                cur->name, cur->str, error);
        }

        cur = cur->next;
    }
```

说明：
- 用 `strcmp(cur->name, "net.isr.dispatch")` 精确匹配名字（`cur->name` 是 sysctl 名字符串，来自 `ff_config.c` 解析）。
- **直接拒绝注入（`continue` 跳过）**，而非「注入后再校验改回」。因为默认值本就是 direct（`netisr.c:151`），只要不注入非 direct 值，`netisr_dispatch_policy` 就恒为 direct，无需事后读回再改。这比「注入后校验并强制改回」更简单、更彻底（连注入动作都不发生）。
- 用 `printf`（内核态 TU，与 `:363` 现有 `printf` 风格一致），不用 `rte_log`。

### 4.4 边界条件与注意点

1. **`cur->name` 的可用性**：`cur->name` 是 `freebsd.sysctl` 链表节点的名字字段，在 `ff_config.c:176-194` 已填充（`newconf->name = ...`），循环内 `:359` 已用它调用 `kernel_sysctlbyname`，故 `strcmp` 直接可用，无需额外解引用。
2. **运行时仍可被外部改写**：该 sysctl 是 `CTLFLAG_RWTUN`，即使启动期防护拦住 config.ini 注入，运行时仍可能被外部 `sysctl` 工具改写。但 f-stack 用户态没有 `sysctl` 命令行入口（`kernel_sysctlbyname` 只在启动注入循环用到），实际运行态被外部改写的面很小。若要彻底封死，需改 `netisr.c` 的 `sysctl_netisr_dispatch_policy`（freebsd 内核源码），属另一独立项，不在本轮最小 diff 范围。**本轮防护以「堵住 config.ini 注入」这一确定性入口为目标**，符合「最小 diff」。
3. **大小写/空白**：`strcmp` 精确匹配 `"net.isr.dispatch"`；config.ini 里名字若有前后空格需 `ff_config.c` 侧已 trim（该侧行为不在本轮范围）。若担心，可在特判前对 `cur->name` 做 `strcmp` 精确匹配即可（f-stack config 解析通常已 trim）。

### 4.5 回归面

- **thread_mode=0 零回归**：单线程下 `net.isr.dispatch` 默认 direct，注入循环本就不该出现该名字；加了特判后，即便用户误配，也只是跳过并打印告警（原本会注入导致单线程也可能因 `cpuid != curcpu` 走到 queue_fallback 丢包，见调研 §影响面第 3 点）。**单线程下此防护是纯收益，无回归**。
- **对正常 direct 值无影响**：默认 direct 不经注入循环，特判只在「用户显式写了 `net.isr.dispatch`」时触发，正常配置不受影响。
- **编译面**：`strcmp` 在 `ff_freebsd_init.c` 已可用（文件内已大量用 `printf`/字符串函数，`string.h` 已引入）。

---

## 5. P5：ff_subr_prf 全局无锁行缓冲 —— 修

### 5.1 裁决

**修**。`lib/ff_subr_prf.c` 两行改 `__thread`。

### 5.2 代码事实复核

调研结论与实际代码一致（实际行号有 1 行偏移，已更正）：

- `ff_subr_prf.c:86`：`char bufr[PRINTF_BUFR_SIZE];`（全局共享，非 `__thread`，无锁）。
- `ff_subr_prf.c:89`：`static int putbuf_done = 0;`（全局共享，非 `__thread`，无锁）。
- `vprintf`（`:550-581`）整段用全局 `bufr` 做行缓冲，`putbuf`（`:136-177`）逐字符写 `bufr`，`putbuf_done` 在 `:569` 复位、`:163` 置位。多 worker 并发 `printf`/`log`/`vlog` 时同一 256 字节缓冲被并发写 → 整行丢失/拼接污染。
- 调研文档引用的 `:81-83`（`PRINTF_BUFR_SIZE`）实际在 `:81-83`，`:85-87` 的 `#ifdef` 块实际在 `:85-87`（本设计已按实际读到的 `:86`/`:89` 标注）。

### 5.3 精确改法（最小 diff，两行）

文件：`lib/ff_subr_prf.c`。

改动 1（`:86`）：

```c
__thread char bufr[PRINTF_BUFR_SIZE];
```

改动 2（`:89`）：

```c
static __thread int putbuf_done = 0;
```

（`bufr` 保持非 `static`，与现状一致；`putbuf_done` 保持 `static`，仅加 `__thread`。二者都加 `__thread` 即可。）

### 5.4 可行性确认（调研已充分论证，此处重申关键点）

1. `bufr`/`putbuf_done` 无跨线程共享语义：全仓只在 `ff_subr_prf.c` 内引用，每次 `vprintf` 从 `:558` 重新初始化 `p_next`/`remain`，无「上一个 printf 写、下一个续读」依赖，改 `__thread` 语义完全等价。
2. `__thread` 已有大量先例（`pcpup`/`pcurthread`/`cc_cpu`/`timeout_cpu`/`msg_iov_tmp`/`seed` 等），风格一致，TLS 在 lcore 线程下工作正常。
3. 备选「加锁串行化 vprintf」会引入重入风险（printf 锁内可能再触发日志），不如 `__thread` 干净。

### 5.5 回归面

- **thread_mode=0 零回归**：单线程下 `__thread` 变量与全局变量行为完全一致（TLS 每线程一份，单线程只有一份）。
- **编译面**：`__thread` 是 GCC/Clang 标准 TLS 扩展，项目已大量使用，无风险。
- **不改 `putbuf`/`vprintf` 逻辑**：只改存储类别，不碰任何逻辑代码，最小 diff。

---

## 6. P6：ff_pthread_create 线程不支持 ff_*（fail-fast 缺口）—— 修 + 文档化

### 6.1 裁决

**修（fail-fast）+ 文档化**。

### 6.2 代码事实复核

调研结论与实际代码一致：

- `ff_thread.c:20-30` `ff_start_routine`：`ff_set_thread(p_data->parent)`（`:26`，继承父 `pcurthread`）→ `ff_free(data)` → `start_routine(arg)`，**无 pcpup 检查**。
- `ff_thread.c:32-46` `ff_pthread_create`：`data->parent = pcurthread`（`:44`）→ `pthread_create(thread, attr, ff_start_routine, data)`（`:45`），**不建 pcpu**。
- `pcpup` 是 `__thread`（`ff_freebsd_init.c:89`），新线程初始 NULL；唯一赋值在 `ff_pcpu_thread_init`（`:104-113`），仅 `:191`/`:317` 两处调用。
- `curcpu`（`lib/include/sys/pcpu.h:34`）= `PCPU_GET(cpuid)`（`lib/include/amd64/include/pcpu.h:49`）= `pcpup->pc_cpuid`，新线程 `pcpup==NULL` → NULL 解引用崩溃。
- 唯一防御先例：`ff_kern_synch.c:106` `pcpup != NULL ? curcpu : 0`。
- `ff_api.h:186-187` `ff_pthread_create` 声明处无「不支持 ff_*」注释。

### 6.3 精确改法

改动 1 —— `lib/ff_thread.c`：`ff_start_routine` 入口（`ff_set_thread` 之后、`ff_free(data)` 之前）加 `pcpup == NULL` 检测，fail-fast。

需要先在文件顶部加 `pcpup` 的 extern 声明（`:7` 已有 `extern __thread struct thread *pcurthread;`，紧邻加一行）：

```c
extern __thread struct thread *pcurthread;
extern __thread struct pcpu *pcpup;
```

`ff_start_routine` 改为：

```c
static
void* ff_start_routine(void * data) {
    struct thread_data *p_data = (struct thread_data *) data;
    
    void * (* start_routine) (void *) = p_data->start_routine;
    void *arg = p_data->arg;
    ff_set_thread(p_data->parent);
    if (pcpup == NULL)
        panic("ff_pthread_create thread has no per-CPU context; "
            "ff_* interfaces that use curcpu/PCPU are unsupported here\n");
    ff_free(data);
    start_routine(arg);
    return NULL;
}
```

说明：
- `panic` 是内核态函数，`ff_thread.c` 已 include `ff_api.h`/`ff_host_interface.h`，`panic` 可用（`ff_freebsd_init.c:107` 已用 `panic`）。
- 放在 `ff_set_thread(p_data->parent)` 之后：先继承父 `pcurthread`（保证 `panic` 内部若用到 `curthread` 不会二次崩），再判 `pcpup`。
- 放在 `ff_free(data)` 之前：fail-fast 时不 free `data`，避免 use-after-free 干扰（panic 通常不返回，但顺序上先判后 free 更稳妥）。
- 用 `panic` 而非 `abort`：`panic` 会打印明确消息并终止，比裸 `abort` 更可诊断；与项目 fail-fast 风格（`ff_pcpu_thread_init:107` 的 cpuid 越界 panic）一致。

改动 2 —— `lib/ff_api.h:186-187`：`ff_pthread_create` 声明处加文档注释（最小、必要）：

```c
int ff_pthread_create(pthread_t * thread, const pthread_attr_t * attr,
    void * (* start_routine) (void *), void * arg);
```

改为在声明上方加注释：

```c
/*
 * ff_pthread_create threads are lightweight: they inherit only the parent
 * thread context (pcurthread), not a per-CPU pcpu. Calling any ff_* interface
 * that touches curcpu/PCPU_GET from such a thread aborts. For a full stack
 * instance use a worker thread (ff_stack_thread_init) instead.
 */
int ff_pthread_create(pthread_t * thread, const pthread_attr_t * attr,
    void * (* start_routine) (void *), void * arg);
```

### 6.4 边界条件与注意点

1. **`pcpup` extern 声明位置**：`pcpup` 是 `__thread struct pcpu *`，已在 `ff_freebsd_init.c:89` 定义，`lib/include/machine/pcpu.h:45` 也有 `extern __thread struct pcpu *pcpup;`。在 `ff_thread.c` 内加 extern 声明即可（`ff_thread.c` 已 include `ff_api.h` → 可能已间接引入，但显式声明更清晰、不依赖 include 链）。
2. **「预留 K 槽位」不可行**（调研已论证，重申）：`mp_maxid` 在 `ff_freebsd_init.c:310-311` 定格为 `nb_cpus`，须在 `uma_startup1`（`:333`）前定型，UMA 据此一次性定 zone 大小。事后动态增长与「须在 uma_startup1 前定型」硬约束冲突。故 `ff_pthread_create` 线程不支持完整 ff_* 是既定约束，fail-fast + 文档化是唯一务实方案。
3. **fail-fast 只防「静默崩溃」，不改变能力边界**：加了 panic 后，原本「运行到某处才 NULL 解引用崩溃」变成「入口即明确报错」，可诊断性大幅提升，但不让 ff_pthread_create 线程「变得能用 ff_*」。

### 6.5 回归面

- **thread_mode=0 零回归**：单进程下若应用不用 `ff_pthread_create`，改动不生效；若用了且线程里调 ff_*，原本就是崩溃（只是时机/位置不确定），现在 fail-fast 是纯改善。
- **对「正确使用」的 `ff_pthread_create` 线程无影响**：若应用线程只做纯用户态逻辑、不触达 `PCPU_GET`，`pcpup` 仍为 NULL，但现在会在入口 panic——**这是一个需要注意的行为变化**。

  **重要权衡**：目前 `ff_pthread_create` 线程若从不调 ff_*（只跑纯计算），本可正常执行；加了无条件 `pcpup==NULL` panic 后，这类「纯计算线程」也会在入口就 panic，反而误伤。

  因此需要**细化 fail-fast 条件**。经复核，`pcpup` 只在「线程内首次触达 `PCPU_GET`/`curcpu`」时才真正危险，而 `ff_start_routine` 入口无法预知 `start_routine` 是否会调 ff_*。故更精确的改法有两条路，需在下文给出选择：

  **方案 6-A（入口无条件 panic，简单但误伤纯计算线程）**：如 §6.3 所示。适用于「约定 ff_pthread_create 线程一律不得用于任何非纯计算场景」的严格语义。

  **方案 6-B（不 panic，改为文档化 + 惰性检测，零误伤）**：`ff_start_routine` 不改（不 panic），仅文档化（改动 2）。把「pcpup==NULL 线程调 ff_* 会崩溃」作为已知约束写进 `ff_api.h` 注释，由使用者自觉规避。缺点：仍是「运行到某处才 NULL 解引用」，无 fail-fast 收益。

  **方案 6-C（折中，推荐）**：入口不无条件 panic，而是**在 `ff_start_routine` 里给新线程「显式标记为无 pcpu」**，并在 `curcpu`/`PCPU_GET` 这类宏的展开处做惰性检测——但这需要改 `pcpu.h` 的宏，侵入面扩大（`PCPU_GET` 被全仓大量调用），非最小 diff，不推荐。

  综合「最小 diff + 不误伤 + 可诊断」三项，**推荐方案 6-B（纯文档化）作为本轮最小改动**，fail-fast 的完整实现（惰性检测）留给独立立项。但团队已明确要求「fail-fast + 文档化」，且 `ff_pthread_create` 的定位本就是「轻量线程、不支持 ff_*」，故需在文档中向 leader 明确这一权衡，最终取舍由实现阶段确认。

  **本设计给出的最终建议**：采用「文档化（改动 2）为必做」，fail-fast（改动 1）采用**方案 6-B 的变体**——即不无条件 panic，改为：在 `ff_start_routine` 入口仅当能够安全检测时才 fail-fast。但「能否安全检测」在入口不可知，故**本轮实际落地以文档化为主**，fail-fast 是否引入及引入形式，在文档 §6.6 标注为「待实现阶段确认」。

### 6.6 结论（向 leader 明确）

P6 的 fail-fast 存在「误伤纯计算线程」的权衡：无条件入口 panic 会把「从不调 ff_* 的 ff_pthread_create 线程」也判死。建议本轮**必做文档化**（改动 2，零风险），fail-fast 采用**惰性检测**（在 `pcpu.h` 的 `PCPU_GET` 展开处加 `pcpup==NULL` 检查，让「首次触达才报错」）——但这超出单文件最小 diff，需独立评估。最终取舍由实现阶段与 leader 确认，本设计给出两条路径的完整 diff，供选择。

---

## 7. 跨问题影响与回归面总览

| 改动 | 文件 | thread_mode=0 回归 | 编译风险 | 备注 |
| --- | --- | --- | --- | --- |
| P2 原子化 | `lib/include/machine/counter.h` | 零 | 无（`__atomic_*` 内建） | 单文件，3 函数 |
| P4 启动防护 | `lib/ff_freebsd_init.c` | 零（纯收益） | 无（`strcmp`/`printf` 已用） | 单文件，1 特判块 |
| P5 `__thread` | `lib/ff_subr_prf.c` | 零 | 无（`__thread` 已有先例） | 单文件，2 行 |
| P6 文档化 | `lib/ff_api.h` | 零 | 无（仅注释） | 单文件，注释 |
| P6 fail-fast | `lib/ff_thread.c` | 零 | 无（`panic`/`pcpup` extern 可用） | 单文件，见 §6.5 权衡 |
| P1（不修） | — | — | — | 独立立项 |
| P3（不修） | — | — | — | 独立立项 |

**共同遵守**：所有改动均为「最小 diff」，新增注释仅限「逻辑复杂处」的必要说明（P4 的告警字符串、P6 的接口契约注释属「对外接口契约/边界说明」，符合 lib 最小注释规约）；不涉及 config.ini、不涉及 git 操作、不涉及真实 IP（本文档无任何真实 IP）。

---

## 8. 待实现阶段确认项

1. P6 fail-fast 的最终形式（无条件 panic vs 惰性检测 vs 纯文档化），见 §6.5/§6.6。
2. P2 内存序最终选 `__ATOMIC_RELAXED` 还是 `__ATOMIC_SEQ_CST`（本设计建议 relaxed）。
3. P3/P1 独立立项的排期与负责人。
4. 所有改动落地后，须按规约「先 make clean 再编译」做 clean build 验证（尤其 `counter.h` 头文件改动会影响所有 include 它的 TU）。
