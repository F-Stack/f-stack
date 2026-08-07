# plan-17：让 f-stack 内核视图 SMP-aware —— 消除 worker 共享 SMR/UMA per-cpu 槽位 + 移除数据面全局锁

> 本文为本轮任务的执行计划（用户要求「先生成完整 plan.md，再执行」）。
> 所有「已核实事实」均为实际打开文件确认，标注 `file:line`；所有「待验证」项禁止推测，必须由子 agent 实测后回填。

---

## 0. 任务定义

### 0.1 问题陈述

上一轮（commit `ff09a17b2`）为修复 native-mt 多线程崩溃，把 `ff_pcpu_thread_init()` 内的 `pcpu_init()` 的 cpuid 恒定为 0：

-修复前：worker 把 `rte_lcore_id()`（如 2）当 cpuid，而本 build 非 SMP（`MAXCPU==1`、`mp_maxid==0`），UMA/SMR per-cpu 数组只按 1 CPU 分配 → `zpcpu_get()` **必然越界** → 实测 SIGSEGV 于 `in_pcblookup_mbuf`。
- 修复后：所有 worker 的 `pc_zpcpu_offset` 都是 0 → 多 worker **合法但共享**同一份 UMA per-cpu cache 槽位与同一个 SMR `c_seq` 槽位→ 存在理论 UAF 窗口（SMR 的 per-CPU 序号被多线程互相覆盖，可能过早判定 grace period 结束而回收仍被引用的 PCB）。

已在 `16-多队列对照实验与根因纠偏.md` 第 8.1 节如实记录该遗留风险。本轮即为其独立立项。

### 0.2 本轮两个并列主目标（用户已确认 `uma_crit_lock` 移除为主目标之一，非可选）

- **G1**：让 f-stack 内核视图 SMP-aware —— 每个 worker 拥有稠密、独立的 pcpu 槽位；UMA/SMR per-cpu 存储按线程数分槽；彻底消除共享 SMR 槽位的 UAF 理论窗口。
- **G2**：在 per-cpu 槽位真正隔离后，移除数据面全局自旋锁 `uma_crit_lock`（`lib/include/vm/uma_int.h:45-52` 把 `critical_enter/exit` 替换成单一全局自旋锁；**实际作用域仅 include `vm/uma_int.h` 的编译单元，详见 §1.4**），恢复 UMA per-cpu cache 的无锁快路径。

### 0.3 方案取向（用户裁决：先调研后由 leader 裁决）

不预设路线，必须以**编译/代码实证**在下列两条候选中选定，并在 spec 中写明决策依据与回退路径：

- **候选 B（最小侵入）**：不定义 `SMP`，仅让 per-cpu 分配按 worker 数分槽 + 每 worker 稠密索引。手段：覆盖 `MAXCPU` + 放开 `freebsd/vm/uma_core.c:2546` 的 `UMA_ZONE_PCPU` 剥离 + 在 UMA/SMR 初始化前设 `mp_ncpus`/`mp_maxid` + `pcpu_init` 传稠密索引 `0..N-1`。
- **候选 A（彻底）**：全树 `-DSMP`。最贴近上游语义，但会激活 `smp_rendezvous`/`CPU_FOREACH`/`ipi_*`/`sched_pin` 等路径，可能需补大量 stub。

### 0.4 验证强度（用户裁决：标准档）

`thread_mode=1` 的 1/2/4 线程矩阵 × 多轮 wrk（`-t5 -c100 -d10s`）+ 60s/400 连接 soak（`-t8 -c400 -d60s`）+ `thread_mode=0` 单进程/双进程零回归对照；并额外做 `uma_crit_lock` 移除前后的吞吐对比（G2 是主目标，须有性能数据支撑）。不做 ASAN/valgrind 特殊构建。

---

## 1. 已核实的代码事实（本轮起点，禁止推翻除非有新实证）

仓库根 `/data/workspace/f-stack`，HEAD = `ff09a17b2`；参照树 `/data/workspace/freebsd-src-releng-15.0`、`/data/workspace/dpdk-stable-24.11.6`。

### 1.1 pcpu / zpcpu 视图

| 位置 | 事实 |
|---|---|
| `lib/ff_freebsd_init.c:85` | `__thread struct pcpu *pcpup;` |
| `lib/ff_freebsd_init.c` `ff_pcpu_thread_init()` | `malloc(sizeof(struct pcpu),...)` → `pcpu_init(pcpup, 0, sizeof(struct pcpu))` → `PCPU_SET(prvspace, pcpup)`；形参 `cpuid` 当前被刻意忽略 |
| `lib/ff_freebsd_init.c:~187` | worker 调用点在 `ff_stack_thread_init`，位于 `init_lock` 自旋锁临界区内 |
| `lib/ff_freebsd_init.c:~293` | 主线程调用点 `ff_pcpu_thread_init(0)` |
| `lib/include/amd64/include/pcpu.h:33-42`（undef）、`:47-53`（`PCPU_*` 重定义）、`:55-67`（`__curthread_ff`/`curthread` 重定义） | `#include_next` 后 `#undef`了 `__curthread`/`get_pcpu`/`PCPU_GET`/`PCPU_ADD`/`PCPU_INC`/`PCPU_PTR`/`PCPU_SET`/`zpcpu_offset_cpu`/`zpcpu_base_to_offset`/`zpcpu_offset_to_base`（10 项），并把 `PCPU_*` 重定义为经 `__thread pcpup` 访问。**`zpcpu_offset_cpu` 被 undef 后未重新定义** |
| `freebsd/sys/pcpu.h:234-236` | `#ifndef zpcpu_offset_cpu` / `#define zpcpu_offset_cpu(cpu) (UMA_PCPU_ALLOC_SIZE * cpu)` / `#endif` |
| `freebsd/sys/pcpu.h:237-239,249-252,254-257` | `zpcpu_offset()` = `PCPU_GET(zpcpu_offset)`；`zpcpu_get(base)` = `base + zpcpu_offset()`；`zpcpu_get_cpu(base,cpu)` = `base + zpcpu_offset_cpu(cpu)` |
| `freebsd/kern/subr_pcpu.c:88-89,91-92,96` | `KASSERT(cpuid >= 0 && cpuid < MAXCPU, ...)`（INVARIANTS 未定义故编译掉）；`cpuid_to_pcpu[cpuid]=pcpu`；`STAILQ_INSERT_TAIL(&cpuhead,...)`；`pc_zpcpu_offset = zpcpu_offset_cpu(cpuid)` |
| `freebsd/kern/subr_pcpu.c:252,270-277,282-287` | `dpcpu_copy()` 有 `#ifdef SMP` 分支；`pcpu_destroy()` 会 `STAILQ_REMOVE`(:274) 并清 `cpuid_to_pcpu[]`(:275)/`dpcpu_off[]`(:276)；`pcpu_find(cpuid)` 返回 `cpuid_to_pcpu[cpuid]` |
| `lib/ff_dpdk_if.c:2649` | `ff_stack_thread_init(rte_lcore_id());` —— **当前 cpuid 的实际来源就是 `rte_lcore_id()`**，G1 的稠密索引改造必须落在此调用点 |
| `lib/ff_freebsd_init.c:294` | 主线程 `ff_pcpu_thread_init(0)` 之后紧跟 `CPU_SET(0, &all_cpus);` —— `all_cpus` 目前只含 CPU 0，`mp_maxid>0` 后须同步 |
| `freebsd/amd64/include/pcpu_aux.h:47`（经 `freebsd/sys/pcpu.h:223` 引入） | `_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE, ...)` —— `struct pcpu` 必须恰为 4096 字节，改动 pcpu 相关定义时该断言是硬约束 |

### 1.2 MAXCPU / mp_ncpus / mp_maxid

- `freebsd/amd64/include/param.h:60-66`：`#ifdef SMP` → `MAXCPU 1024`；`#else` → **无条件** `#define MAXCPU 1`。故单纯 `-DMAXCPU=N` 不生效，必须定义 `SMP` 或用 override 头文件改写。
- `lib/ff_glue.c:138-146`：`cpuset_t all_cpus;`(:138)、`int mp_ncpus = 1;`(:140)、`int mp_maxcpus = MAXCPU;`(:142)、`volatile int smp_started;`(:144)、`u_int mp_maxid;`(:145，BSS 零值)、`volatile int uma_crit_lock;`(:146)。
- `lib/Makefile` 未定义 `-DSMP`（已grep CFLAGS/HOST_CFLAGS 段确认）；`INVARIANTS` 亦未定义。**待 M1-C 对 `mk/` 与 `lib/opt/opt_global.h` 做穷尽复核。**

### 1.3 UMA / SMR 的 per-cpu 依赖

- `freebsd/vm/uma_core.c:2546-2548`：`#ifndef SMP` → `keg->uk_flags &= ~UMA_ZONE_PCPU;`（非 SMP 下 per-cpu zone 退化为单份）。
- `freebsd/vm/uma_core.c:3494-3516` `uma_zalloc_pcpu_arg()`：`#ifdef SMP` 时 `MPASS(uz_flags & UMA_ZONE_PCPU)` 且 `for (i=0;i<=mp_maxid;i++) bzero(zpcpu_get_cpu(item,i), uz_size)`；`#else` 只 bzero 一份。`:3521-3536` `uma_zfree_pcpu_arg` 同构（`MPASS` 在 `:3527`）。
- `freebsd/vm/uma_core.c:1957` `#ifndef FSTACK` → 逐 CPU `vm_page_alloc_noobj` 版 `pcpu_page_alloc`（`:1970 MPASS(bytes == (mp_maxid+1)*PAGE_SIZE)`、`:1975 for (cpu=0; cpu<=mp_maxid; cpu++)`）；`:2082 #else` → 回退版 `:2083-2089`（`*pflag=UMA_SLAB_KERNEL; return page_alloc(zone,bytes,domain,pflag,wait)`）；`:2114 #endif`。因 `lib/Makefile:219 CFLAGS+= -DFSTACK`，**本 build 必然编译回退版（已静态坐实，非待验证）**。`lib/include/vm/uma_int.h:43 #undef UMA_MD_SMALL_ALLOC` 影响的是 `uma_core.c:2116`/`:2208` 的 `UMA_USE_DMAP && !UMA_MD_SMALL_ALLOC` 块，与本选择无关。
- `freebsd/sys/pcpu.h:221 #define UMA_PCPU_ALLOC_SIZE PAGE_SIZE`，`freebsd/amd64/include/param.h:92-93 PAGE_SHIFT 12 / PAGE_SIZE (1<<12)` → **4096**。因 `sys/pcpu.h:48` 先 include f-stack 覆盖的 `machine/pcpu.h`（其 `:40 #undef zpcpu_offset_cpu`），`sys/pcpu.h:234 #ifndef` 成立 → `zpcpu_offset_cpu(cpu) == 4096*cpu`（非 `freebsd/amd64/include/pcpu.h:270` 的 `&__pcpu[0]+...` 版）。
- `freebsd/vm/uma_core.c:2351-2356` 是 `KASSERT((uk_flags & UMA_ZONE_PCPU)==0 || (uk_size <= UMA_PCPU_ALLOC_SIZE && ...))`，**未定义 `INVARIANTS` 时整条编译掉，本 build 无此运行期保护**。`keg_layout` 中真正生效的 PCPU 逻辑是 `:2472-2478`：`pages = atop(kl.slabsize); if (UMA_ZONE_PCPU) pages *= mp_maxid+1; keg->uk_ppera = pages;`。
- **`mp_maxid` 的时序硬约束**：`freebsd/vm/uma_core.c:3179-3182` zone 结构大小 `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + ...` 在 uma_startup 期一次性算定；`:2472-2478` keg 的 `uk_ppera` 亦按 `mp_maxid+1` 放大；`:2873 zone_update_caches`、`:5589/:5620/:5674` 统计路径均按 `mp_maxid` 遍历 `uz_cpu[]`。→ **`mp_maxid` 必须在 `uma_startup1/2` 之前设定且此后不得再变**，否则 `uz_cpu[i>0]` 越界（堆溢出）。
- `freebsd/kern/subr_smr.c:583-609` `smr_create()`：`uma_zalloc_pcpu(smr_zone, M_WAITOK)`(:591) 后 `for (i=0;i<=mp_maxid;i++){ c=zpcpu_get_cpu(smr,i); c->c_seq=SMR_SEQ_INVALID; c->c_shared=s; }`(:598-605)。`:623-631` `smr_init()`：`uma_zcreate("SMR CPU", sizeof(struct smr), ..., UMA_ZONE_PCPU)`。
  > **关键约束**：`mp_maxid` 与 `UMA_ZONE_PCPU` 必须**成对**修改。只提高 `mp_maxid` 而 zone 仍单槽 → 该循环写越界。
- `freebsd/sys/smr.h:105-143` `smr_enter()` 走 `zpcpu_get(smr)`(:110)，其内的 `critical_enter()` 在非 UMA 编译单元里是**空操作**（见 §1.4）。
- `freebsd/netinet/in_pcb.c:583,615-617` `ipi_smr = uma_zone_get_smr(...)`、`uma_zcreate(..., UMA_ALIGN_CACHE, UMA_ZONE_SMR)` —— PCB 查找路径确实走 SMR，即上一轮 SIGSEGV 现场。

### 1.4 数据面全局锁（G2 目标）

- `lib/include/vm/uma_int.h:45-52`：
  ```c
  extern volatile int uma_crit_lock;
  #define critical_enter() do { while (__sync_lock_test_and_set(&uma_crit_lock, 1)) ; } while(0)
  #define critical_exit()  do { __sync_lock_release(&uma_crit_lock); } while(0)
  ```
  同文件还 stub 了 `sleepq_*`(:54-57)/`_vm_map_unlock`(:59)、`#undef UMA_MD_SMALL_ALLOC`(:43)、定义 `UMA_PAGE_HASH`(:65)/`struct uma_page`(:67-74)。
- **该锁的真实作用域（G2 论证核心）**：`freebsd/sys/systm.h:179-193` 非 KLD 分支的 inline `critical_enter()` 函数体被 `#ifndef FSTACK`(:186) 整体排除 → **f-stack 下 `critical_enter/exit` 本身是空操作**；全树 `critical_enter` 的宏级覆盖仅 `lib/include/vm/uma_int.h:46/50` 一处。include `vm/uma_int.h` 且在 `lib/Makefile` SRCS 内的 `.c` 只有 `freebsd/vm/uma_core.c`(:650) 与 `lib/ff_freebsd_init.c`（`kern_malloc.c`/`subr_vmem.c`/`vm_page.c`/`uma_dbg.c`/`memguard.c`/`kern_switch.c` 均未编译）。
  → 推论：`uma_crit_lock` 实际只串行化 `uma_core.c` 的分配快路径；`smr_enter()`(smr.h:109) 的 `critical_enter()` 是空操作，**SMR 读侧当前毫无抢占/并发保护**，共享 `c_seq`槽位是唯一实质风险。G2 的等价性论证落点应是「每线程独占 per-cpu 槽位」，**而非「关抢占」**；去锁后 UMA 只是回到与其它子系统相同的「空 critical section」语义。
- 相关提交 `b90ddcba5` "Fix UMA per-CPU cache race and sizeof mismatch for native-mt multi-thread startup" —— 该全局锁很可能是为规避「共享 pcpu 槽位」引入的权宜之计。**M1-A 必须 `git show b90ddcba5` 坐实引入动机，禁止猜测。**
- `lib/include/amd64/include/counter.h:38-62` 把 counter(9) 完全去 per-cpu 化（`counter_u64_add`(:58-62) 为 `*c += inc`、`counter_u64_fetch_inline`(:43-47) 为 `*p`、`counter_enter/exit`(:38-39) 空操作），`freebsd/kern/subr_counter.c` 内无任何 `mp_maxid`/`CPU_FOREACH`/`zpcpu` 遍历（仅 `:63uma_zalloc_pcpu(pcpu_zone_8,...)`）。→ `mp_maxid` 提高后 counter **不会越界**；实际影响是多线程写同一 slot 造成统计竞争、fetch 仅读 slot 0，须在 spec 中记录为**已知偏差**而非内存安全项。

---

## 2. 必须实测的关键未知量（M1 产出；禁止推测）

| # | 未知量 | 验证手段 |
|---|---|---|
| U1 | （**已静态坐实**，`gcc -E` 仅作交叉确认）`zpcpu_offset_cpu(cpu) = 4096*cpu`、`UMA_PCPU_ALLOC_SIZE = PAGE_SIZE = 4096` | `gcc -E` 预处理输出交叉确认 |
| U2 | （**编译分支已静态坐实为 `uma_core.c:2083-2089` 回退版**，依据 `-DFSTACK`）待验的是：f-stack `page_alloc` 能否稳定分配 `(mp_maxid+1)*PAGE_SIZE` 且满足 `keg_layout:2472-2478` 放大后的 `uk_ppera` 假设 | 代码审 + 运行期探针 |
| U3 | 全树 `#ifdef SMP`/`#ifndef SMP`/`defined(SMP)` 在 **`lib/Makefile` 实际 SRCS 列表内**的分布与数量；`-DSMP` 后新激活并缺失的符号清单 | 以实际 `make` 的编译/链接错误为准 |
| U4 | `mp_maxid` 所有读者（`CPU_FOREACH`、counter(9)、`uma_core.c`、`subr_smr.c`、`subr_pcpu.c`、sysctl/netstat 统计）在 `mp_maxid>0` 后是否全部安全；`all_cpus`/`CPU_ABSENT`/`cpuset_t`（`CPU_SETSIZE` 随 MAXCPU 变化影响结构大小与 ABI）是否需同步初始化与全树重编 | grep 穷尽 + 逐点代码审|
| U5 | 稠密索引后 `cpuid_to_pcpu[]`/`cpuhead` 写入是否仍需 `init_lock` 保护；`pcpu_find()`/遍历 `cpuhead` 的运行期读者是否存在（语义已变，须重新穷尽核验） | grep + 调用链分析 |
| U6 | 稠密索引来源：应取自 `ff_global_cfg.dpdk.proc_lcore[]` 下标（`lib/ff_config.c` ~110-141、~1465-1490 `parse_lcore_mask` 与 thread_mode塌缩逻辑），而非 `rte_lcore_id()`；须确认主线程（现用 0）与 worker 序号**不撞车**，给出明确映射方案 | 代码审 + 运行期打印实证 |
| U7 | 移除 `uma_crit_lock` 的前提是否成立：上游靠关抢占保证同CPU 内无并发，用户态需论证等价性（worker 1:1 绑核轮询无迁移，但主线程/KNI/callout/`ff_veth` 等辅助路径是否也满足） | 逐路径核验 + 压测 |
| U8 | 是否存在跨线程分配/释放同一 zone 的路径（mbuf 在 worker A 分配、B 释放）；去锁后是否安全（上游靠 zone 级 `uz_lock` 做 bucket 交换，须确认 f-stack 未把 zone 锁stub 掉） | 代码审 + 压测 |
| **U9**（高） | `MAXCPU` 尺寸数组的**跨编译单元一致性**：候选 B 用覆盖头改写 `MAXCPU` 时是否所有 TU 都见到同一值？任一 TU 漏改即产生新越界源。依据：`freebsd/kern/subr_pcpu.c:76-77` `uintptr_t dpcpu_off[MAXCPU]; struct pcpu *cpuid_to_pcpu[MAXCPU];`、`lib/ff_kern_synch.c:59` `static uint8_t pause_wchan[MAXCPU];`（`:105` 以 `curcpu` 索引）、`lib/ff_glue.c:142` `mp_maxcpus = MAXCPU`、`lib/ff_kern_timeout.c:730` `cpu >= MAXCPU` panic | 预处理逐 TU 核对 + 编译 |
| **U10**（高） | `mp_maxid` 的**设置时序**必须早于 `uma_startup1/2`（所有 zone `uz_cpu[]` 尺寸在此定型）且此后不可变；须确认 f-stack 启动序列中 `mp_maxid` 赋值点与 `uma_startup*`/`smr_init`/各 `uma_zcreate` 的先后 | 代码审 + 运行期打印 |
| **U11**（高） | callout 的 cpuid 语义在稠密索引下失真：`lib/ff_kern_timeout.c:183-185` `__thread struct callout_cpu cc_cpu; #define CC_CPU(cpu) &cc_cpu`（注释明写"cpuid is always 0, MAXCPU=1"）、`:190 static int timeout_cpu;`（**非 `__thread` 全局却被每线程写**）、`:254 timeout_cpu = PCPU_GET(cpuid);`、`:662/:1181 CC_CPU(timeout_cpu)`、`:1061/:1077 c->c_cpu = timeout_cpu;`、`:730-733 panic("Invalid CPU in callout %d")` | 代码审 + 运行时 |
| **U12**（中） | 稠密 pcpu id 与 `rte_lcore_id()` 是**两个索引空间**，须逐点确认无混用；DPDK `rte_mempool` per-lcore cache 仍按 `rte_lcore_id`，与 UMA per-cpu 槽位无关（须在 spec 写清边界）。依据：`lib/ff_dpdk_if.c:2649`、`:2745/:2841 veth_ctx[rte_lcore_id()][port_id]`、`:582-583`；`lib/Makefile:346,372-373` 表明 `kern_mbuf.c`/`uipc_mbuf.c` 仍被编译（UMA mbuf zone 与 DPDK 池并存） | 代码审 |
| **U13**（中） | **无 `pcpup` 的线程**是否可能进入 UMA/SMR 快路径：`lib/ff_thread.c:20-30/33-46` `ff_pthread_create` 只继承 `pcurthread`、不调 `ff_pcpu_thread_init` → 该类线程 `pcpup == NULL`。KNI（`lib/ff_dpdk_kni.c`，`lib/Makefile:36,90-91` 已开 `FF_KNI=1`）/`ff_veth`/DPDK service 线程的线程模型须穷尽核实 | 代码审 |
| **U14**（中） | `mp_ncpus` 的其它读者：`lib/ff_ng_base.c:3249 numthreads = mp_ncpus;`（netgraph）、`lib/ff_kern_timeout.c:1212-1216`（仅打印） | 代码审 |
| **U15**（低） | DPCPU 路径：`dpcpu_init()` 仅在 `freebsd/kern/subr_pcpu.c:100` 定义，`lib/` 与 `freebsd/kern/` 内无调用者（其余目录未穷尽）；但 `pcpu_destroy():276` 仍写 `dpcpu_off[pc_cpuid]`，故仍受 U9 的 `MAXCPU` 一致性约束 | 代码审 |

---

## 3. 里程碑与门禁

>门禁规则：任一阶段失败 → **打回上一步修复**；同一步骤打回上限 **3 次**，超限即停止转人工决策；不允许留「遗留事项」带病放行。leader 维护 bounce counter。

| 里程碑 | 内容 | 承担者 | 交付物 | 门禁（须不同 agent） |
|---|---|---|---|---|
| **M0** | 本 plan.md 落盘 | leader（写） | 本文件 | `gate-plan`（子 agent 审 plan 完整性与规约覆盖） |
| **M1** | 三路并行调研：<br>A代码路径穷尽探测（U1/U2/U4~U8 + U9~U15 + `git show b90ddcba5`）<br>B 外网资料交叉调研<br>C 双候选路线编译可行性实证（U3，并单独登记 HEAD 基线 warning 数）| 子 agent `res-code`、`res-web`、`res-build` | `_m17_A_codepath.md`（**须对 U1~U15 逐项回填，缺项即门禁不通过**）、`_m17_B_external.md`、`_m17_C_buildprobe.md` | leader 汇总 + `gate-design` 复核证据链 |
| **M2** | 方案裁决（B vs A）+ 详细设计 → spec 17号文档 | 子 agent `designer`（写） | `17-SMP-aware-pcpu视图与去全局锁.md` | 子 agent `gate-design`（审：证据链、file:line、边界措辞） |
| **M3** | 编码里程碑 1（G1）：SMP-aware per-cpu 视图 + 稠密索引；`make clean` 后完整编译 | 子 agent `coder`（写） | `lib/` 代码改动 + clean build 通过记录 | 子 agent `reviewer`（并发/内存/回归/注释规约） |
| **M4** | 编码里程碑 2（G2）：移除 `uma_crit_lock`；`make clean` 后完整编译 | 子 agent `coder` | `lib/` 代码改动 + clean build 记录 | 子 agent `reviewer` |
| **M5** | 运行时验证矩阵实测（含去锁前后吞吐对比） | 子 agent `tester`（与 coder 不同） | `_m17_E_runtime.md` 实测原始数据 | 子 agent `reviewer` 复核数据可信度（若 leader 接管测试执行，数据复核必须新起子 agent） |
| **M6** | 文档收尾（把裁决/实测/残留风险回填 spec 17） | 子 agent `designer` | 更新后的 17 号文档 | 子 agent `gate-doc`（逐条核验 `file:line` 与措辞不越实证边界） |
| **M7** | 本地 commit（G1/G2 分两次提交；英文 1-3 句；`config.ini` 本地测试值不入库） | leader | git commit | 门禁 = `gate-doc`（复核 commit 范围与 `git diff`）；leader 自身 diff review 仅作提交前自检，不计为门禁 |

### 3.1 角色分离铁律落实

- **写 vs 审必须不同 agent**：`designer`↔`gate-design`/`gate-doc`；`coder`↔`reviewer`；`tester` 与 `coder` 不同。
- leader 只兼任**纯调研/探测/汇总/执行**（如 git操作、进程启停、数据汇总）；**若 leader 接管了任何「写」，其审核必须新起子 agent**。
- M0 由 leader 写 plan → 必须由子 agent `gate-plan` 审（不得leader 自审）。

### 3.2 超时与旁路探测机制

- 每个子 agent 设分钟级超时；leader 定时轮询 `send_message` 询问进度。
- **旁路探测优先**：消息无回应时，直接读子 agent 应落盘的文件（`docs/native_mt_spec/zh_cn/_m17_*.md`）、`git status`、编译产物 `lib/libfstack.a` mtime、日志文件行数，判断其真在跑还是已异常。
- 异常回退：① leader 接管（则后续审核必须新起子 agent）；② 新起子 agent 重跑（新 agent 角色不得与下游审核 agent 重合）；③ 按 bounce≤3 转人工。

---

## 4. 强制规约（各阶段门禁逐条核查）

1. 删文件必须 `/data/workspace/rm_tmp_file.sh`；终止进程必须 `/data/workspace/kill_process.sh`；改权限必须 `/data/workspace/chmod_modify.sh`。**严禁任何 shell 命令字符串（含注释、ssh 远端命令）内出现 `rm`/`kill`/`pkill`/`killall`/`chmod`**。`make install` 类允许。
2. 每次改代码必须先 `make clean` 再完整编译（`lib/` 与 `example/` 均如此），严禁依赖增量编译；编译验证以 clean build 通过为准。
3. `lib/` 只写非常必要的注释，严禁长篇大论、严禁给一看就懂的代码加注释。
4. commit message 英文、1-3 句；`config.ini` 的本地测试改动（`thread_mode`/`lcore_mask`/IP 等）**不入库**，`git add` 前必须 review `git diff`。
5. 所有行动实际执行，禁止未执行就给结果；代码与文档/外网资料交叉验证，**不一致以实际代码为准**。
6. agent team：leader 在所有子 agent 完成前严禁提前退出；必须超时 + 定时轮询 + 旁路探测；异常须回退补救；写/审必须不同 agent；门禁失败打回上一步，同步骤上限 3 次。
7. 外网调研须给可核查链接；搜不到须如实写「未找到可靠来源」，**禁止编造**。

---

## 5. 运行时验证环境（已验证可用）

- 本机双网卡；DPDK 独占网卡 IP `<DPDK_NIC_IP>`，压测须 `ssh f-stack-client` 后用 `/data/wrk/wrk` 打该 IP；内核栈测试用 `127.0.0.1`。
- 被测程序 `/data/workspace/f-stack/example/helloworld`，配置 `/data/workspace/f-stack/config.ini`。
- 上一轮踩过的坑（沿用）：
  - `(nohup ... &)` 子 shell 启动的进程会被回收，必须 `setsid nohup ... < /dev/null &` 完全脱离；
  - 启动 secondary 进程必须用绝对路径（`setsid` 改变 cwd 语义）；
  - 日志追加写入 `example/helloworld.log`、`example/f-stack-0.log`，读新增内容须先记旧行数再 `tail -n +N`；
  - core dump 被禁用（`/proc/sys/kernel/core_pattern`），抓崩溃须`setsid gdb -q -x <cmdfile>` 在负载下捕获。

### 5.1 性能回归对照基线（上一轮实测，同机同客户端）

| 场景 | req/s |
|---|---|
| `thread_mode=1` 2 线程 | 233,380 / 234,084 / 230,510 |
| `thread_mode=1` 1 线程 | 209,483 / 209,739 |
| `thread_mode=0` 1 进程 | 209,946 / 209,367 |
| `thread_mode=0` 2 进程 | 234,613 / 233,982 |
| 60s/400 连接 soak | 497,043 req/s、2983万请求、零 socket error、进程存活 |

---

## 6. 验收标准（Definition of Done）

- **DoD-1**：per-cpu 槽位真正隔离，**判定手段与判定式**：在 `ff_pcpu_thread_init()` 内加临时探针打印 `tid / dense_idx / pcpup->pc_cpuid / pcpup->pc_zpcpu_offset / mp_maxid`，并在 SMR 使用点打印各 worker `&zpcpu_get(ipi_smr)->c_seq`；判定：① 各 worker `pc_zpcpu_offset == 4096 * dense_idx` 且 `dense_idx <= mp_maxid`；② 两两 `c_seq` 地址差 `== 4096 * Δidx` 且全部落在 `[base, base + (mp_maxid+1)*4096)` 内；③ 日志从 `example/helloworld.log` 取证并落盘到 `_m17_E_runtime.md`；探针在 M5 后移除或转为 `ff_log`。
- **DoD-2**：`uma_crit_lock` 从 `lib/` 中移除（或论证其不可移除并给出代码级依据 + 由 `reviewer` 门禁确认）。
- **DoD-3**：`lib/` 与 `example/` clean build 零错误；**warning 基线 = 未改动 HEAD `ff09a17b2` 的 `lib/`+`example/` clean build warning 条数**（M1-C 已实测 `lib/` 为 51 条，须与候选路线实验产生的 warning 分开登记），改动后不得增加。
- **DoD-4**：1/2/4 线程矩阵 + 60s soak 全部零崩溃、零 socket error；`thread_mode=0` 零回归（吞吐相对基线波动≤5%）。
- **DoD-5**：去锁前后吞吐对比数据落盘；**阈值**：去锁后吞吐不得低于去锁前（同机同客户端、≥3 轮取中位数，允许 ±2% 噪声）；若无提升，仍须给出代码级结论说明 G2 的正确性收益，并由 `reviewer` 门禁确认是否保留该改动。
- **DoD-6**：spec 17 号文档所有结论有 `file:line` 或实测数据支撑，残留风险如实记录。
- **DoD-7**：两次 commit 落地，`config.ini` 本地测试值未入库（`git status` 当前为 `M config.ini`，提交前必须逐项 review 并回滚本地测试值）。
- **DoD-8**：仓库内本轮临时产物（`lib/_m17_probe_u1.c`、根目录 `_m17_*.log`/`_m17_*.txt`/`_m17_uma_core.i` 等）在 M7 前一律通过 `/data/workspace/rm_tmp_file.sh` 清理或确认不入库。
