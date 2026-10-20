# 17 SMP-aware pcpu 视图与去全局锁

> **文档编号**：SPEC-NMT-17
> **版本**：v1（M2 设计稿）
> **日期**：2026-08-04
> **性质**：设计规格（spec，非补丁）。本文只定义「改什么、为什么、怎么验」，不给完整补丁全文。
> **代码事实基线**：`git HEAD = ff09a17b2`（`/data/workspace/f-stack`）。参照树`/data/workspace/freebsd-src-releng-15.0`、`/data/workspace/dpdk-stable-24.11.6`、对照树 `/data/workspace/f-stack-13.0-baseline`。
> **上游出处**：`16-多队列对照实验与根因纠偏.md` §8.1（遗留风险登记）。
> **输入文档**：`plan-17-SMP-aware-pcpu-smr.md`（任务定义/U1~U15/DoD）、`_m17_A_codepath.md`（M1-A 代码路径穷尽）、`_m17_B_external.md`（M1-B 外网交叉）、`_m17_C_buildprobe.md`（M1-C 编译实证）、`_m17_gate_plan.md`（plan 门禁 + §8 候选 A 语义风险独立核验）、`_m17_D_verdict.md`（leader 路线裁决 + D1~D9）。

---

## 0. 阅读约定与撰写边界

### 0.1 证据强度标记

本文每条事实都必须落到下列三档之一，**不允许无标记的断言**：

| 标记 | 含义 |
|---|---|
| **【代码坐实】** | 已实际打开 `file:line` 确认，或由预处理/编译/链接输出直接证明 |
| **【实测】** | 有命令输出/编译数字/运行日志 |
| **【未坐实】** | 静态推断或依赖运行期数据，**禁止当作已验证事实使用**，须注明验证手段与承担里程碑 |

### 0.2 撰写期工作区状态声明（重要，供 `gate-design` 核对行号用）

- 本文所有 `file:line` **一律以 HEAD `ff09a17b2` 为准**。
- 撰写期间（2026-08-04）工作区中`lib/` 存在**他人（M3 `coder`）in-progress 的 G1 改动**：`git diff --stat -- lib/` 实测为 `lib/Makefile |4 ++++`、`lib/ff_dpdk_if.c | 8 +++++++-`、`lib/ff_dpdk_if.h | 1 +`、`lib/ff_freebsd_init.c | 48 ++++++++++---------`、`lib/ff_glue.c | 7 +++++++`、`lib/ff_kern_timeout.c | 2 +-`。**【实测】**
- 因此 `lib/ff_dpdk_if.c` 的工作区行号比 HEAD **偏移 +6**（工作区在 `:409` 后插入了 6 行 `ff_cur_proc_id()`）。本文引用 `ff_dpdk_if.c:2649`/`:2644`/`:2794`/`:2857` 等均为 **HEAD 行号**。
- 本文作者（`designer`）**未修改任何源码**，唯一写入文件即本文档；所有验证均为只读（`read_file` / `grep` / 只输出到 stdout 的 `cc -E`），**未执行 `make`、未创建任何临时文件**。

### 0.3 本文对 M1 文档的纠正（C1~C3 详见 §2.3 / §4.3.4 / §6.5；C4 = 4 处 `file:line` 校正，详见 §6.21-2）

| # | M1 文档原表述 | 本文纠正（以实际代码为准） |
|---|---|---|
| **C1** | `_m17_A_codepath.md` §7.3：「`curcpu = PCPU_GET(cpuid) = pcpup->pc_cpuid` 是**线程私有常量**」 | **错误。** `lib/include/sys/pcpu.h:32-34` `#undef curcpu` + `#define curcpu 0` 把 `curcpu` 硬编码为字面量 `0`，覆盖了 `freebsd/sys/pcpu.h:218#define curcpu PCPU_GET(cpuid)`。→ **UMA per-cpu cache 不走 `zpcpu`偏移，而走 `uz_cpu[curcpu]`，因此 G1 单靠稠密 `pc_cpuid` 无法隔离 UMA cache。** 见 §2.3 |
| **C2** | `_m17_A_codepath.md` §6.2 / `_m17_D_verdict.md` D4：建议「主线程也走 `proc_id` 取号」 | **需加`thread_mode` 门控。** `lib/ff_dpdk_if.c:460ff_cur_lcore_conf()->proc_id = ff_global_cfg.dpdk.proc_id;`【代码坐实】→ `thread_mode=0` 的 secondary 进程 `proc_id` 为 **1、2、…**（不是 0）。无门控直接用 `proc_id` 会让多进程模式的 secondary 拿到 `cpuid=1` 而其 `mp_maxid=0` → 越界，**破坏 D7 零回归**。见 §4.3.4 |
| **C3** | `_m17_A_codepath.md` U9 #4：`lib/ff_kern_synch.c:59 pause_wchan[MAXCPU]` 被 `curcpu` 索引「取址越界（UB）」 | **表述需修正为条件式。** 因 C1，`pause_wchan[curcpu]`（`:105`）**今天恒为 `pause_wchan[0]`，不存在越界**；越界只会在本轮把 `curcpu` 改为 per-thread **之后**才可能出现，而候选 A 的 `MAXCPU=1024` 已同时消除它。定级不变（仍须 `MAXCPU ≥ N`），但因果链要写对 |

### 0.4 本文关闭的一项 M1 未坐实项

**U16-a（`tcp_hpts` 在 f-stack 里是否真活跃）= 活跃，已关闭。**【代码坐实】证据链：

1. `lib/ff_dpdk_if.c:2794`在 `main_loop` 内**无条件**调用 `ff_tcp_hpts_softclock();`（注释 `:2789-2793` 明写「f-stack has no userret to call it, and the hpts swi thread is a no-op」）。
2. `lib/ff_kern_timeout.c:1291-1296` `ff_tcp_hpts_softclock()` = `if (tcp_hpts_softclock != NULL) tcp_hpts_softclock();`。
3. `freebsd/netinet/tcp_hpts.c:2061 tcp_hpts_softclock = __tcp_run_hpts;`（在 `tcp_hpts_mod_load()` 内，`:1853`）。
4. `freebsd/netinet/tcp_hpts.c:2142 DECLARE_MODULE(tcphpts, tcp_hpts_module, SI_SUB_SOFTINTR, SI_ORDER_ANY);` + `:2117-2118 case MOD_LOAD: tcp_hpts_mod_load();`；`freebsd/kern/kern_module.c:106-107 module_register_init()`（`:106` 为返回类型 `void`、`:107` 为函数名行）参与编译（`lib/Makefile` HEAD **`:347`**列 `kern_module.c`；**含 M3 改动后的工作区为 `:351`** —— gate-design报的 `:351` 是工作区行号，与本文 HEAD 基线并不矛盾），`lib/kern_module.o` 存在 → 在 `mi_startup()`（`lib/ff_freebsd_init.c:309`）内执行。

→ **每个 worker 的 `main_loop` 都在驱动 hpts**，故「N 个 worker 争同一个 hpts 实例」不是纸面风险。这直接支持 §4.3.2 的裁决：**`mp_ncpus` 必须与 `mp_maxid` 同步抬到 N**。

---

## 1. 背景与问题陈述

### 1.1 上游出处

`16-多队列对照实验与根因纠偏.md` §8.1 在修复 native-mt 多队列崩溃时登记了一条遗留风险，原文（`:270-275`）要点：

> 修复 R2 后所有 worker 的 `pc_zpcpu_offset` 均为 0，故多 worker **共享同一份** SMR per-cpu 槽位。理论窗口：A 线程 `smr_exit` 置 `SMR_SEQ_INVALID` 可能清掉 B 线程的 read section 标记 → `smr_poll` 误判无读者 → PCB 提前回收（UAF）。……彻底消除需让 f-stack 内核视图 SMP-aware（`mp_maxid > 0` + 真正按线程数分配 per-cpu 数组），**建议独立立项**。

本文档即该独立立项的设计规格。

### 1.2 三态演进（必须理解「修复前必然越界 / 修复后合法但共享 / 目标态独占」）

|阶段 | commit | `pcpu_init()` 的 cpuid | `MAXCPU`/`mp_maxid` | per-cpu 槽位状态 | 观测到的症状 |
|---|---|---|---|---|---|
| **T0 修复前** | `b90ddcba5` | `rte_lcore_id()`（稀疏，可为 2） | 1 / 0 | **必然越界**：`cpuid_to_pcpu[2]` 越过 `cpuid_to_pcpu[MAXCPU=1]`（`freebsd/kern/subr_pcpu.c:77,91`）；`pc_zpcpu_offset = 4096*2` 越过只按1 CPU 分配的 zone | **【实测，doc-16 §1.2 R2】** 压测时 `in_pcblookup_mbuf` SIGSEGV |
| **T1 当前 HEAD** | `ff09a17b2` |恒 `0`（`lib/ff_freebsd_init.c:107`） | 1 / 0 | **合法但共享**：所有线程 `pc_zpcpu_offset == 0` → 共用同一个 SMR `c_seq` 槽位与同一份 `uz_cpu[0]` | 不崩（60s/400连接 soak 497k req/s 零错误，doc-16 §8.1-3），但**静态 UAF 窗口客观存在** |
| **T2 本轮目标** | 本设计 | 稠密 `0..N-1` | ≥N / N-1 | **每线程独占**：`pc_zpcpu_offset == 4096*i`，`uz_cpu[i]` 线程私有 | 待 M5 验证（DoD-1） |

**T1 相对 T0 是严格改善**（合法访问 vs 越界访问），这一点不得在文中弱化；但 T1 仍违反 SMR 的核心不变式（§2.2），因此必须推进到 T2。

### 1.3 本轮目标

| 目标 | 内容 | 里程碑/提交 |
|---|---|---|
| **G1** | 让 f-stack 内核视图 SMP-aware：每个栈线程拥有稠密、独立的 pcpu 槽位；UMA/SMR per-cpu 存储按线程数分槽；**并让 `curcpu` 解析到本线程**（§2.3 新增的必要条件）。彻底消除共享 SMR 槽位的 UAF 理论窗口与共享 `uz_cpu[0]` 的竞态 | M3 / commit-1 |
| **G2** | 在槽位真正隔离后，移除数据面全局自旋锁 `uma_crit_lock`（`lib/include/vm/uma_int.h:45-52`），恢复 UMA per-cpu cache 的无锁快路径 | M4 / commit-2（**独立提交，可单独回退**） |

**G1 → G2 是硬依赖且不可交换顺序**：G2 的正确性完全建立在 G1 建立的「每线程独占 `uz_cpu[i]`」不变式上（§2.4、§4.7）。

---

## 2. 问题的代码级机理

### 2.1 pcpu 槽位定位链

**【代码坐实】** 全链条（HEAD 行号）：

```
lib/ff_freebsd_init.c:106   pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);   /* __thread，:85 */
lib/ff_freebsd_init.c:107   pcpu_init(pcpup, 0, sizeof(struct pcpu));               /* ★ 形参 cpuid 被刻意忽略 */
freebsd/kern/subr_pcpu.c:90   pcpu->pc_cpuid = cpuid;
freebsd/kern/subr_pcpu.c:91   cpuid_to_pcpu[cpuid] = pcpu;                          /* 数组尺寸 MAXCPU，:77 */
freebsd/kern/subr_pcpu.c:92   STAILQ_INSERT_TAIL(&cpuhead, pcpu, pc_allcpu);        /* 共享链表，:78 */
freebsd/kern/subr_pcpu.c:96   pcpu->pc_zpcpu_offset = zpcpu_offset_cpu(cpuid);
```

关键宏的**最终展开值**（M1-A U1 用 `gcc -E` 实测，本文交叉确认定义链）：

| 宏 | 展开 | 值 |
|---|---|---|
| `MAXCPU` | `freebsd/amd64/include/param.h:65`（`#else` 分支**无条件** `#define MAXCPU 1`） | **1** |
| `UMA_PCPU_ALLOC_SIZE` | `freebsd/sys/pcpu.h:221` = `PAGE_SIZE` = `freebsd/amd64/include/param.h:92-93` `(1<<12)` | **4096** |
| `zpcpu_offset_cpu(cpu)` | `freebsd/sys/pcpu.h:235`（`:234 #ifndef` 成立，因 `lib/include/amd64/include/pcpu.h:40 #undef zpcpu_offset_cpu`） | **`4096 * cpu`** |
| `zpcpu_get(base)` | `freebsd/sys/pcpu.h:249-252` → `base + pcpup->pc_zpcpu_offset` | — |
| `PCPU_GET(m)` | `lib/include/amd64/include/pcpu.h:49` | `pcpup->pc_## m` |
| **`curcpu`** | **`lib/include/sys/pcpu.h:34`** | **字面量 `0`（见 §2.3）** |

→ 因 `lib/ff_freebsd_init.c:107` 恒传 0，**所有线程的 `pc_zpcpu_offset` 都是 0**，`zpcpu_get(x)` 对每个线程都返回同一地址。

### 2.2 为什么共享 SMR 槽位构成 UAF

**上游语义（`_m17_B_external.md` §2.1 / §2.6，源码原文可核查）**：

- `struct smr` 的 `c_seq` 只有「0(`SMR_SEQ_INVALID`) / 非 0」两态，**无嵌套计数**；`smr_enter()` 带 `KASSERT(smr->c_seq == 0, "does not support recursion")`。f-stack **未定义 `INVARIANTS`**（M1-A U1【实测】），该断言**已编译掉**，破坏只会静默发生。
- `smr_exit()` **无条件** `atomic_store_rel_int(&smr->c_seq, SMR_SEQ_INVALID)`，不检查「是不是我自己进入的」。
- `smr_poll_cpu()`：`if (c_seq == SMR_SEQ_INVALID) break;` → 该 CPU 被判为**无活跃读者**；`smr_poll_scan()` 里 `if (c_seq != SMR_SEQ_INVALID) rd_seq = SMR_SEQ_MIN(rd_seq, c_seq);` → INVALID 的槽位不参与拉低 `rd_seq`。
- GUS 算法注释原文（`subr_smr.c` 顶部，上游把设计文档直接写在源码里）：**“cpuB is not running and is considered to observe wr seq.”** 即 GUS 的核心不变式是「槽位为 INVALID ⟺ 该 CPU 上无活跃读者」。

**共享槽位下的破坏链**（每一环都有源码支撑；`_m17_B_external.md` §2.1 标注为「源码语义推导」）：

```
worker A: smr_enter()  -> c_seq = S1
worker B: smr_enter()  -> c_seq = S1 + S2（amd64 走 atomic_add_acq_int 快路径，是"累加"不是"覆盖"）
worker A: smr_exit()   -> c_seq = SMR_SEQ_INVALID   （B 仍在读区间！）
写者:     smr_poll()   -> 该槽位 INVALID -> 判定无读者 -> s_rd_seq 推进到 s_wr_seq
          uma_zfree_smr() 判定 grace period 结束 -> PCB 内存被复用
worker B: 仍持有指向该PCB 的指针  ==>  UAF
```

f-stack 侧的落点【代码坐实】：`freebsd/netinet/in_pcb.c:583 ipi_smr = uma_zone_get_smr(pcbinfo->ipi_zone);`、`:615-617 uma_zcreate(..., UMA_ZONE_SMR)`；`freebsd/sys/smr.h:110 smr = zpcpu_get(smr);`。这正是 T0 阶段 SIGSEGV 的现场函数 `in_pcblookup_mbuf` 所在的查找路径。

**另一条关键既存事实**（M1-A U7 §7.1【实测】，`cc -E freebsd/kern/subr_smr.c` 后 `grep -c uma_crit_lock == 0`）：`subr_smr.c` 不include `vm/uma_int.h`，其 `critical_enter()` 取自 `freebsd/sys/systm.h`，而 `:186 #ifndef FSTACK` 把函数体整体排除 → **f-stack 下 `critical_enter/exit` 本身是空操作**。→ **SMR 读侧今天完全没有任何串行化保护，`uma_crit_lock` 从未保护过 SMR**。这同时说明：G1 是修UAF 的唯一手段，G2 对 SMR 零影响。

### 2.3 【本轮新发现】UMA per-cpu cache 走的是另一条路：`curcpu`，而不是 `zpcpu` 偏移

这是 M1 三份文档全部遗漏、但**决定 G1 成败**的一条事实。

**（a）f-stack 把 `curcpu` 硬编码为 0**【代码坐实】：

```c
/* lib/include/sys/pcpu.h:31-34 */
#include_next <sys/pcpu.h>
#undef curcpu

#define curcpu    0
```

它覆盖的是上游 `freebsd/sys/pcpu.h:218 #define curcpu PCPU_GET(cpuid)`。`lib/include/sys/pcpu.h` 确实在真实编译中被预处理器读入（`_m17_C_buildprobe.md` §0.2 用 248 个 TU 的 `gcc -M` 依赖并集实测的 15 个 override 文件清单里就有它）。

**（b）UMA 的 per-cpu cache 全部按 `uz_cpu[curcpu]` 定位**【代码坐实，11 处】：
`freebsd/vm/uma_core.c:1452`（`cache_drain_safe_cpu`）、`:3738`、`:3776`、`:3818`、`:3901`、`:4534`、`:4543`、`:4595`、`:4628`、`:4803`、`:4853` 均为 `cache = &zone->uz_cpu[curcpu];`。

**（c）预处理交叉确认最终展开**【代码坐实】：撰写期用 `_m17_A_codepath.md` §0 抄录的真实编译参数对 `freebsd/vm/uma_core.c` 做过一次**只读** `cc -E`（仅输出到 stdout、未跑 `make`），**输出中对应行为**：

```
cache = &zone->uz_cpu[0];
```

（**预处理输出的行号随编译参数、include 展开而变化，不作为可复核证据，故此处不列**。可复核的是：任何人以 `_m17_A_codepath.md` §0 的参数重跑 `cc -E` 都应看到 `uz_cpu[0]` 而非 `uz_cpu[curcpu]`。）

同一份输出还坐实了 `ZDOM_GET` 展开为 `(&((uma_zone_domain_t)&(zone)->uz_cpu[mp_maxid + 1])[domain])`（对应 `freebsd/vm/uma_int.h:529`），与 M1-A U4.1 的「硬约束 H1」一致。

> **证据强度说明（E6）**：该预处理产物 `_m17_uma_core.i` 已按 DP-10 清理、**未落盘**，因此**不可事后复核**，故本条降级标注为**【代码坐实】**而非【实测】—— 其结论不依赖该产物即可独立成立（`lib/include/sys/pcpu.h:34` 的 `#define curcpu 0` + `uma_core.c` 11 处 `uz_cpu[curcpu]` 两项均为可直接打开复核的静态事实），且已由 `gate-design`独立坐实。

**（d）结论（G1 的必要条件被扩容）**：

- SMR 侧靠 `zpcpu_get()`（`pc_zpcpu_offset`）定位 → **稠密 `pc_cpuid` 即可修好**。
- UMA per-cpu cache 侧靠 `curcpu` 定位 → **即使 `pc_cpuid` 稠密，所有线程仍然共用 `uz_cpu[0]`**。
- 因此：**若 G1 不同时把 `curcpu` 改为 per-thread，则**
  1. DoD-1 中 UMA 侧的隔离性判定不可能通过（各线程 `&zone->uz_cpu[curcpu]` 地址完全相同）；
  2. **G2 会直接把 `b90ddcba5` 修掉的那个竞态原样放回来** —— 因为 `uma_crit_lock` 今天是 load-bearing 的：它正是在「所有线程共享`uz_cpu[0]`」的前提下用全局串行化掩盖竞态（`b90ddcba5` commit message 原文：「Serialize UMA per-CPU cache access via spinlock in critical_enter/exit … to fix kqueue_kevent memset SIGSEGV at 0 on 2-thread startup」，M1-A U7 第1 部分【实测】）。

→ 设计上把「`curcpu` per-thread 化」列为 **G1 的第三个必做项**（§4.5），与「稠密 `pc_cpuid`」「`mp_*` 三元组」并列。

### 2.4 `uma_crit_lock` 的真实语义与作用域（G2 论证的落点）

**【代码坐实】**

```c
/* lib/include/vm/uma_int.h:45-52 */
extern volatile int uma_crit_lock;
#define critical_enter() do { while (__sync_lock_test_and_set(&uma_crit_lock, 1)) ; } while(0)
#define critical_exit()  do { __sync_lock_release(&uma_crit_lock); } while(0)
```

| 事实 | 依据 |
|---|---|
| 该宏只对 include `vm/uma_int.h` 的 TU 生效；编译集合（248 TU）内只有 **2个**文件 include它：`freebsd/vm/uma_core.c`（`lib/Makefile:650`）与 `lib/ff_freebsd_init.c`；而后者内 `grep -c 'critical_enter\|critical_exit'` = **0** | M1-A U10 §10.3【实测】+ `_m17_gate_plan.md` §三-4 独立核验 |
| → **`uma_crit_lock` 事实上只作用于 `freebsd/vm/uma_core.c`** |同上 |
| `uma_core.c` 内 `critical_enter/exit` 共 21 处：`:1451,1464,3727,3744,3775,3817,3859,3891,3900,3916,3918,4541,4554,4558,4626,4649,4653,4827,4850,4872,4874` | 本文【代码坐实】 |
| **慢路径本来就在临界区之外**：`:3859 critical_exit();` → `:3880 cache_fetch_bucket()` / `:3882 zone_alloc_bucket()`；`:3916 critical_exit();` → `:3917 zone_put_bucket()` → `:3918 critical_enter();`。`:3867-3874` 的上游注释明写「This requires the zdom lock, so we must drop the critical section」| 本文【代码坐实】，与 M1-A U7§7.3 末段一致 |
| **f-stack 把 UMA 的全部 `mtx` 锁 stub 成空操作**：`lib/include/sys/mutex.h:57 #define DO_NOTHING ((void)0)`、`:59-72` 把 `__mtx_lock/__mtx_unlock/__mtx_lock_spin/__mtx_unlock_spin/_mtx_lock_flags/_mtx_unlock_flags/_mtx_lock_spin_flags/_mtx_unlock_spin_flags/thread_lock*/thread_unlock` 全部定义为 `DO_NOTHING`，`:74-76` 把 trylock 系定义为常量 `1`，`:85mtx_owned(m) (1)`；`freebsd/kern/kern_mutex.c`不在 `lib/Makefile` SRCS。→ `ZONE_LOCK`/`ZDOM_LOCK`/`KEG_LOCK` 预处理后为 `((void)0)` | M1-A U8 §8.2【实测】+ 本文核对 `lib/include/sys/mutex.h:55-90` |

**由此得到 G2 的等价性论证落点（与 plan §1.4 一致）**：

- 上游 `critical_enter()` 的作用是「同一 CPU 上禁抢占⇒ `uz_cpu[curcpu]` 槽位在临界区内无第二个执行流」。f-stack 的 `uma_crit_lock` **不是**上游临界区的用户态替身，而是在 `critical_enter` 已被 nop 化之后、**为共享 `uz_cpu[0]` 单独补上的一把全局串行锁**。
- 所以 G2 的正确性条件是「**每线程独占 `uz_cpu[i]`**」，**不是**「关抢占」。这一不变式由 G1（稠密 `pc_cpuid` + per-thread `curcpu` + 线程与槽位 1:1 且永不迁移）建立，且**比上游条件更强**（上游按物理 CPU 分槽、线程可迁移；f-stack 按线程分槽、迁移无害）。
- 外部先例支撑（`_m17_B_external.md` §4.2/§4.3）：上游 `uma_int.h` 原文「PCPU caches are protected by critical sections, and **may be accessed safely only from their associated CPU**」把「不变式」与「维持手段」并列；counter(9) 在 amd64 上 `counter_enter()` 就是 nop（架构级先例）；rump kernel `kpreempt_disabled()` 恒 true、靠「虚拟 CPU 槽位被线程独占」保护 per-CPU 结构（NetBSD 树内长期维护）；Seastar/ANS 为 shared-nothing 工业先例。**但外部先例只支撑一般性论断，不能替代本地核验**（同文档 §4.2(b) 明列缺口）。

### 2.5 现状总表：per-cpu 消费者分别靠哪条路定位

| 消费者 | 定位方式 | T1（HEAD）实际行为 | G1 后（稠密 `pc_cpuid` + per-thread `curcpu`） |
|---|---|---|---|
| SMR `c_seq`（`freebsd/sys/smr.h:110`） | `zpcpu_get()` → `pc_zpcpu_offset` | 全线程共享一槽 → **UAF 窗口** | 每线程 `4096*i` 独立槽 →窗口消除 |
| SMR 创建/扫描（`subr_smr.c:598-605`、`smr_poll_scan`的 `CPU_FOREACH`） | `zpcpu_get_cpu(smr,i)` + `mp_maxid` / `all_cpus` | 只初始化/只扫 1 槽 | 初始化并扫描 N槽（要求 `mp_maxid`+`all_cpus` 成对，D2/H4） |
| **UMA per-cpu cache**（`uma_core.c` 11 处 `uz_cpu[curcpu]`） | **`curcpu`（字面量 0）** | **全线程共享 `uz_cpu[0]`**，靠 `uma_crit_lock` 串行化 | 每线程 `uz_cpu[i]` → 可去锁 |
| UMA zone/keg 慢路径（`zdom`/keg/bucket zones） | zone 级共享结构 | **无锁**（`mtx` 全stub），且不在临界区内 | 不变（本轮不改，见 §6.1） |
| f-stack 自有 `uma_page` 反查哈希（`lib/include/vm/uma_int.h:105-126vsetzoneslab`） | 全局哈希表 + `LIST_INSERT_HEAD`，**无锁** | 无锁 | 不变（本轮不改，G2 降级台阶 L1 才动，见 §4.7.4） |
| counter(9)（`lib/include/amd64/include/counter.h:38-62`） | **完全去 per-cpu 化**（`*c += inc`，只碰第 0 槽） | 统计竞争（非内存安全） | 不变（§5-2） |
| callout（`lib/ff_kern_timeout.c:183-185`） | `__thread struct callout_cpu cc_cpu` + `CC_CPU(cpu)` 忽略参数 | 已按线程隔离；但 `timeout_cpu`（`:190`）漏了 `__thread` | 补 `__thread`（D5，§4.6） |
| ipfw DPCPU hazard pointer（`ip_fw_dynamic.c:224-226`） | `DPCPU_PTR` → `dpcpu_off[]` 恒 0 | **所有 cpu 槽位互相别名**（`dpcpu_init()` 无调用者） | **本轮修不了**（§6.3） |
| DPDK `rte_mempool` per-lcore cache | `rte_lcore_id()`（**另一个索引空间**） | 正常 | 不受影响（§5-5） |

---

## 3. 方案选型与裁决依据

### 3.1 候选A vs 候选 B 实测对照

路线已由 leader 在 `_m17_D_verdict.md` §1 裁决为**候选 A（全树 `-DSMP`）**。本文不重新论证，仅转述决定性依据并如实转述边界。

| 维度 | 候选 A（全树 `-DSMP`） | 候选 B（不定义 SMP，覆盖 `MAXCPU` + 放开上游 `#ifdef SMP`） | 来源 |
|---|---|---|---|
| 编译代价 | **【实测】** 仅需 1 个 stub（`smp_topo`）；`error 0`、`warning 51`（= HEAD 基线 51，**零新增**）；`lib` + `example` 双 clean build 通过，`example/helloworld` 二进制产出成功（30,392,616 字节） | **无任何编译数字**（探测被还原授权门禁阻断，如实记录） | `_m17_C_buildprobe.md` §2.2/§2.3/§3.1 |
| 改动面 | `lib/` 2 文件 2 处，**上游 `freebsd/` 树 0 处** | `lib/` 2 文件（含新增 `lib/include/amd64/include/param.h`）+ **上游 `freebsd/vm/uma_core.c` 4 处**（`:2546`/`:3498`/`:3508`/`:3526`），四处强耦合、漏改无编译报错 | 同上 §3.2/§3.3 |
| 逐槽路径一致性 | `uma_core.c:2546/3498/3508/3526`、`subr_pcpu.c:252` 的 SMP 分支**自动一致** | 需人工逐处放开，漏一处即脏内存/越界 | 同上 |
| spin 锁语义风险 | **已证伪，语义中性**：`lib/include/sys/mutex.h:31-48` 在 `#include_next` 后 `#undef` 全部 spin 锁宏、`:59-76` 重定义为 `DO_NOTHING`/常量 1；`spinlock_enter/exit` 的定义与调用者所在 `.c` 全不在 SRCS | 同样中性 | `_m17_gate_plan.md` §8.2（独立核验） |
| `smp_topo` stub 安全性 | **已坐实安全**：`tcp_hpts.c:1867-1871` 本就有 `#else cpu_top = NULL`，`:1890 if (cpu_top == NULL) grp_cnt = 1`；`:1565 if (grp_cnt > 1)` 才解引用 `grps[]`；`:2095` 的 `free(grps)` 仅模块卸载路径 | — | `_m17_D_verdict.md` §1.1（leader 实测） |
| 附带正确性收益 | `ck_md.h:95 CK_MD_UMP` 失效 → CK **RMW** 原语恢复 `lock` 前缀。唯一实质受影响 TU 是 `ip_fw_dynamic.c`（`ck_pr_inc_32/dec_32/or_32/xor_32`）；`ck_queue.h`/`net/if.c` 全为 load/store，`ck_epoch` 已被 `ff_glue.c:1358-1396`（`:1358 ck_epoch_synchronize_wait` … `:1392 ck_epoch_init`）stub，`contrib/ck/src/*.c` 未编译 | 无 | `_m17_gate_plan.md` §8.3（其引用的 `:1366-1404` 经本文以 HEAD 复核后校正为 `:1358-1396`） |
| 主要开销 | `sizeof(cpuset_t)` 8→**128** 字节、`cpuid_to_pcpu[]`/`dpcpu_off[]` 由 1→1024 槽（各 8KB，**纯 BSS 增长**）、`netisr.c` 若干 `malloc(...*MAXCPU)`；CK `lock` 前缀有性能成本，待 M5 量化 | 槽数可控（64） | `_m17_C_buildprobe.md` §0.3/§2.7 |
| 上游 diff 维护成本 | 低（13.0→15.0 升级语境下权重高） | 高 | leader 判断 |

### 3.2 裁决与理由（转述 `_m17_D_verdict.md` §1.2）

**路线 = 候选 A。** 理由四条：

1. 候选 A 的代价被**实测**否证了 plan §0.3 的悲观预判（预判「需补大量 stub」，实测仅 **1 个**，且该 stub 返回 `NULL` 与上游 `#else` 分支逐字等价）。
2. 被 plan 标为「最小侵入」的候选 B **实际更侵入**：要改上游 `uma_core.c` 4 处且强耦合；在 FreeBSD 13.0→15.0 升级项目语境下上游树零补丁权重很高。
3. 候选 A 让所有 `#ifdef SMP` 逐槽路径一次性自洽，规避候选 B「漏改一处即静默内存破坏」的高风险。
4. 附带修掉 CK RMW 缺 `lock` 前缀这一潜在原子性缺陷（成本为零、方向正确）。

**补充（本文新增的第5 条理由）**：`-DSMP` 把 `MAXCPU` 抬到 1024，**顺带**为 §4.5 的「`curcpu` per-thread 化」提供了必要前提 —— `lib/ff_kern_synch.c:59 static uint8_t pause_wchan[MAXCPU];` 被 `:105 pause_wchan[curcpu]` 索引，`curcpu` 一旦变成 `0..N-1` 就需要 `MAXCPU ≥ N`。候选 B 若把 `MAXCPU` 覆盖为 64 也能满足，但候选 A 无需额外动作。【代码坐实】

### 3.3 诚实边界（必须一并转述，`_m17_D_verdict.md` §1.3）

- **候选 B 无任何编译数字**，其全部结论仅为代码审级别；若将来需回退到 B，**必须先补做编译实证**。
- 候选 A 的**运行时**行为（槽位是否真隔离、`uma_crit_lock` 能否移除、吞吐变化）**均未验证**，须 M3/M5 实测。**【未坐实】**
- M1-C 的探针代码**不得**直接沉淀为产品代码：M3 由 `coder` 正式实现并经 `reviewer` 门禁（`_m17_gate_plan.md` §8.6-3）。
- `-DSMP` 是否还改变**非** spin 锁/非 CK 的其它运行时语义（例如 `cpuset_t` 8→128 对按值传参/结构体嵌入的影响）：`_m17_gate_plan.md` §8.7 记为**未核验**。本文按「`SRCS`（238 内核态 TU）全部 clean 重编、口径一致；`HOST_SRCS`（10 个）不含 FreeBSD 内核头（`_m17_C_buildprobe.md` §0.1）」判断无跨 `.o` ABI 撕裂面，但该判断只覆盖**编译期**，运行期仍由 M5 兜底。**【未坐实】**

### 3.4 回退路径（三级，按优先级）

| # | 台阶 | 触发条件 | 内容 | 依据 |
|---|---|---|---|---|
| **R-1** | 候选 A 内部降级（**仍不动上游树**） | M5 显示 `MAXCPU=1024` 的内存开销或 CK `lock` 前缀开销不可接受 | `-DSMP` 的同时在 `lib/opt/opt_global.h` 内 `#define MAXCPU 64` | `freebsd/amd64/include/param.h:61-63` 的 SMP 分支带 `#ifndef MAXCPU` 保护、可被外部覆盖（而 `#else` 分支是无条件 define，这正是非 SMP 下 `-DMAXCPU=N` 失效的原因）【代码坐实】 |
| **R-2** | 退候选 B | 候选 A 在运行时暴露不可控问题 | 按 `_m17_C_buildprobe.md` §3.2 的 B-1…B-6 实施，**必须同时**完成 B-2/B-4/B-6 的成对改动，并补做编译实证 + 额外论证 `subr_pcpu.c:252` dpcpu 拷贝语义不一致的残留面 | 同上 |
| **R-3** | 转人工决策 | A 与 B 均在运行时失败，或同一步骤打回已达 3 次 | 按 bounce ≤ 3 规约停止并转人工 | plan §3 门禁规则 |

---

## 4. 详细设计

> 本节逐文件、逐函数给出改动点与改法，并在 §4.9 与 D1~D9 逐条对齐。
> **注释规约**：本节要求的所有代码注释都必须是「非常必要」的（对外接口契约、不直观的时序/边界约束）。**严禁**为一看就懂的代码加注释，**严禁**长篇注释。下文凡标注「须注释」的地方，均给出**建议不超过 3 行**的注释要点。

### 4.1 `lib/Makefile`：定义 `SMP`

**改动**：在 `:219 CFLAGS+= -DFSTACK` 之后新增

```make
CFLAGS+= -DSMP
```

**理由与依据**：
- `freebsd/amd64/include/param.h:60-66` 的 `#else`（非 SMP）分支是**无条件** `#define MAXCPU 1`，故**单纯 `-DMAXCPU=N` 不生效**（会触发 macro redefined，`-Werror` 下失败）；必须定义 `SMP` 或用override 头改写。【代码坐实】
- 生效性已【实测】：`-DSMP` 后 `MAXCPU` 由 1 变1024（`-dM -E`，`_m17_C_buildprobe.md` §0.3）。
- 两条等价入口（`lib/opt/opt_global.h` 或 `lib/Makefile` 的 `CFLAGS+=`）中选`Makefile`：与既有 `-DFSTACK`/`-DFF_IPFW`/`-DINET6` 等开关同处一地，便于检索。【依据】`_m17_C_buildprobe.md` §0.1
- **作用域说明**：内核 option 只影响 `SRCS`（238 个内核态 TU），不影响 `HOST_SRCS`（10 个走 `HOST_C`、不带 `KERNEL_CFLAGS`、不含FreeBSD 内核头）。【代码坐实】`lib/Makefile:179`、`_m17_C_buildprobe.md` §0.1

**须注释（≤2 行）**：说明「`SMP` 使 `MAXCPU` 变为 1024，从而 UMA/SMR 的 per-cpu 存储按栈线程数分槽；不定义时 `MAXCPU==1`，所有线程共享0 号槽位」。这属于「不直观的编译期约束」，是必要注释。

### 4.2 `lib/ff_glue.c`：`smp_topo()` stub

**改动**：新增唯一一个 stub（落点建议紧随 `:168-170 smp_topology` 的定义之后，与 `mp_ncpus`/`mp_maxid`/`all_cpus`/`smp_started`/`smp_disabled` 同处一地）：

```c
struct cpu_group *
smp_topo(void)
{
    return (NULL);
}
```

**为什么只需这1 个**【实测】：`_m17_C_buildprobe.md` §2.2/§2.4 —— `-DSMP` 后`lib` clean build `error 0`、`warning 51`（= 基线，零新增）；符号差分「新增未解析符号 = 1 个」；真实链接实测 `undefined reference` 去重后仅 `smp_topo` 一个，链接器原文：

```
../lib/libfstack.a(libfstack.ro): in function `tcp_hpts_modevent':
tcp_hpts.c:(.text+0x28ecc4): undefined reference to `smp_topo'
```

**返回 `NULL` 的安全性论证**【代码坐实】（唯一调用者是 `tcp_hpts.c`）：

| 位置 | 代码 | 结论 |
|---|---|---|
| `freebsd/netinet/tcp_hpts.c:1867-1871` | `#ifdef SMP cpu_top = smp_topo(); #else cpu_top = NULL; #endif` | 上游**本就有** `NULL` 分支，stub 与非 SMP 行为**逐字等价** |
| `freebsd/netinet/tcp_hpts.c:1890` | `if (cpu_top == NULL) { tcp_pace.grp_cnt = 1; }` | 对 `NULL` 显式处理，不解引用 |
| `freebsd/netinet/tcp_hpts.c:1564-1572` | `if (tcp_pace.grp_cnt > 1) { ... CPU_ISSET(curcpu, &tcp_pace.grps[i]->cg_mask) ... }` | `grp_cnt == 1` → `grps[]` **不被解引用**；`:1559 end = tcp_pace.rp_num_hptss` 不越界 |
| `freebsd/netinet/tcp_hpts.c:2095` | `#ifdef SMP free(tcp_pace.grps, M_TCPHPTS); #endif` | 仅模块卸载路径；`grps` 为 NULL/未分配时 `free(NULL)` 无害 |

**须注释（≤2 行）**：说明「用户态无 CPU 拓扑；调用者必须能处理 NULL，见 `tcp_hpts.c:1890`」。属对外契约，必要。

### 4.3 `lib/ff_freebsd_init.c`：三元组、时序、槽位取号、上界检查

#### 4.3.1 时序硬约束（D2/ H1 / H2）

**`mp_ncpus` / `mp_maxid` / `all_cpus` 必须作为三元组同步设置，且全部早于 `lib/ff_freebsd_init.c:301 uma_startup1()`。**【代码坐实】

理由（三条，均为「设晚了就错」）：

| # | 依据 | 后果 |
|---|---|---|
| H1 | `freebsd/vm/uma_core.c:3179-3182`：`zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + sizeof(struct uma_zone_domain)*vm_ndomains`，在 `uma_startup1()` **一次性算定**；`freebsd/vm/uma_int.h:529ZDOM_GET(z,n) = &((uma_zone_domain_t)&(z)->uz_cpu[mp_maxid+1])[n]`（本文预处理【实测】确认展开）；`uma_core.c:2472-2478 pages *= mp_maxid+1; uk_ppera = pages;` | 此后再抬 `mp_maxid` → `uz_cpu[i>0]` 与 `zdom` 全部越界（堆溢出） |
| H2 | `freebsd/kern/subr_smr.c:598-605 for (i=0;i<=mp_maxid;i++){ c = zpcpu_get_cpu(smr,i); c->c_seq = SMR_SEQ_INVALID; ... }`（**不带 `#ifdef SMP`**），由 `mi_startup()`（`:309`）里 `in_pcbinfo_init` → `uma_zcreate(UMA_ZONE_SMR)` → `zone_ctor` → `smr_create()` 触发 | `mp_maxid` 与 `UMA_ZONE_PCPU` 必须成对；候选 A 由 `-DSMP` 自动放开 `uma_core.c:2546` 的 PCPU 剥离，二者自洽 |
| D2/§8.4 | `freebsd/netpfil/ipfw/ip_fw_dynamic.c:3236 malloc(mp_ncpus * sizeof(void *), ...)` 按 **`mp_ncpus`** 定尺寸，而 `:2086-2091 CPU_FOREACH(i) { dyn_hp_cache[cached_count++] = DYNSTATE_GET(i); }` 按 **`mp_maxid` + `all_cpus`** 遍历（`freebsd/sys/smp.h:197-199`）；`FF_IPFW=1` 已编译（`lib/Makefile:44`，`ip_fw_dynamic.c` 在 `NETIPFW_SRCS` 的 `:601`） | 只抬 `mp_maxid`+`all_cpus` 而不抬 `mp_ncpus` → **堆溢出** |
| **H3** | **`uma_page_slab_hash`/`uma_page_mask` 也必须早于 `uma_startup1()`** —— 一旦 `mp_maxid > 0`，zone-of-zones 变大→ slab 升多页 → 置 `UMA_ZFLAG_VTOSLAB` → `uma_startup1()` 期间就会调用 f-stack 自有的 `vsetzoneslab()` | **【实测】** `mp_maxid ≥ 2` 时启动即 SIGSEGV（100% 复现）。**完整机理、改法与诚实边界见 §4.10**；本条与 H1/H2 共同构成「G1 的启动时序契约」 |

**落点**：`ff_freebsd_init()` 内、`:293` 之前（即 `:291 physmem = ...` 与 `:293 ff_pcpu_thread_init(0)` 之间）。此时 `ff_global_cfg.dpdk.nb_threads` 已由 `ff_load_config()`（`lib/ff_init.c:39`，早两级）确定，`ff_dpdk_init()`（`:43`）也已跑完 `init_lcore_conf()`，**信息完全可用**。【代码坐实】

**改法（示意，≤10 行）**：

```c
nb_cpus = ff_global_cfg.dpdk.thread_mode ? ff_global_cfg.dpdk.nb_threads : 1;
if (nb_cpus < 1)
    nb_cpus = 1;
if (nb_cpus > MAXCPU)
    panic("nb_threads %d exceeds MAXCPU %d\n", nb_cpus, MAXCPU);
mp_ncpus = nb_cpus;
mp_maxid = nb_cpus - 1;
for (i = 0; i < nb_cpus; i++)
    CPU_SET(i, &all_cpus);
```

- 需`#include <sys/smp.h>`（`mp_ncpus`/`mp_maxid` 声明；`all_cpus` 已在 `:88` extern）。
- 原 `:294 CPU_SET(0, &all_cpus);` 被上面的循环取代（**不是保留后再补**，避免两处写同一位图）。
- **须注释（≤3 行）**：说明「三者必须在 `uma_startup1()` 之前定型且此后不得再变（UMA 在那里按 `mp_maxid` 定死 zone 尺寸），`mp_ncpus`亦不可落后于 `all_cpus`（`ip_fw_dynamic.c` 按 `mp_ncpus` 定尺寸、按 `CPU_FOREACH` 遍历）」。这是典型的「不加注释无法理解」的时序约束，属必要注释。
- `panic` 而非静默钳制：因`freebsd/kern/subr_pcpu.c:88`的 `KASSERT(cpuid >= 0 && cpuid < MAXCPU, ...)` 在无 `INVARIANTS` 时**已编译掉**（M1-A U1【实测】），必须有运行期兜底（D6）。

#### 4.3.2 `mp_ncpus` 是否随 `mp_maxid` 抬高—— 裁决：**抬到 N**

**「两种取法都不越界」的结论成立，但理由必须是「写侧有界」，不是「读侧取模」**（本文按 `gate-design` 必改 F1 整段替换原论证；原文误称「`rp_ent[]` 的每个索引都独立对 `mp_ncpus`/`rp_num_hptss` 取模」，**该表述已被实测证伪**）。

**证伪的事实**【代码坐实】：`freebsd/netinet/tcp_hpts.c:569-579tcp_hpts_lock()` 内`:575 hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];` —— **没有任何取模**。故 `rp_ent[]` 的越界安全性**完全取决于写入 `t_hpts_cpu` 的值是否有界**。

**改用「写侧有界」论证**（`t_hpts_cpu` 全树仅 3 个写入点，已穷举）：

| # | 写入点 | 值域 | 依据 |
|---|---|---|---|
| 1 | `tcp_hpts.c:606 tp->t_hpts_cpu = hpts_random_cpu();`（`tcp_hpts_init()` 内，`:605 if (t_hpts_cpu == HPTS_CPU_NONE)`） | `hpts_random_cpu()`（`:466-475`）为 **双重取模** `(((ran & 0xffff) % mp_ncpus) % tcp_pace.rp_num_hptss)`（`:473`）→ `< min(mp_ncpus, rp_num_hptss)` | 【代码坐实】 |
| 2 | `tcp_hpts.c:1542 tp->t_hpts_cpu = hpts_cpuid(tp, &failed);`（`tcp_set_hpts()` 内） | `hpts_cpuid()`（`:1040-1099`）的**全部**返回路径都有界：`:1050` 返回已置位的旧值（归纳有界）；`:1067`/`:1078` 返回 `hpts_random_cpu()`（同上）；`:1089 cpuid = inp->inp_flowid % mp_ncpus`；`:1059 return (0)`。**`#ifdef RSS`（`:1064-1070`）与 `#ifdef NUMA`（`:1085-1096`）两段均未编译**（`RSS` 未定义、`NUMA` 未定义见§5-9） | 【代码坐实】 |
| 3 | `tcp_subr.c:2298 tp->t_hpts_cpu = HPTS_CPU_NONE;`（tcpcb 初始化） | `HPTS_CPU_NONE == (uint16_t)-1 == 65535`（`freebsd/netinet/tcp_var.h:330`）→ **这是哨兵值、不是合法索引**，见下方「⚠ 既存不变式」 | 【代码坐实】 |

**关于 `t_lro_cpu` 分支（`:1056-1062`）**：即使 `tcp_use_irq_cpu` 被打开（默认 **0**，`:286`，可由 tunable `net.inet.tcp.use_irq` 改），也**不产生越界值** —— `tp->t_lro_cpu` 的唯一非哨兵赋值在 `freebsd/netinet/tcp_lro_hpts.c:577`，而**该文件未参与编译**（HEAD `lib/Makefile:515` 的 `NETINET_SRCS` 只列 `tcp_lro.c`；`lib/tcp_lro_hpts.o` 不存在）⇒ `t_lro_cpu` 恒为 `HPTS_CPU_NONE` ⇒ 必走 `:1057-1060 { *failed = 1; return (0); }`这条**有界**分支，`:1061 return (tp->t_lro_cpu)` 不可达。【代码坐实】

**`rp_num_hptss == mp_ncpus` 与时序**【代码坐实】：`tcp_hpts.c:1864 ncpus = mp_ncpus ? mp_ncpus : MAXCPU;` → `:1872 tcp_pace.rp_num_hptss = ncpus;`；而 `tcp_hpts_init`（模块 SYSINIT）由 `mi_startup()`（`lib/ff_freebsd_init.c:309`）驱动，**晚于**三元组设置（§4.3.1，在 `:301 uma_startup1()` 之前）⇒ 二者恒一致，写侧的两重取模上界与读侧的数组尺寸**恒相等**。

> **⚠ 一条既存不变式（须如实登记，但与本裁决无关）**：写入点 3 的 `HPTS_CPU_NONE`（65535）本身是越界索引，安全性依赖「`tcp_hpts_init()` 必在任何 `tcp_hpts_lock()` 之前把它替换掉」。而 `tcp_set_hpts()`恰恰是**先** `:1540 tcp_hpts_lock(tp)`（内含 `:575` 的取用）**再** `:1542` 赋值。该不变式由 `rack.c:14368` / `bbr.c:9946` 调用 `tcp_hpts_init()` 来维持（两者**均已编译**：HEAD `lib/Makefile:584-586`，`lib/rack.o`/`lib/bbr.o` 存在），上游注释 `:596-600`亦明示该路径的病态情形（syzkaller）。**关键点：此风险与 `mp_ncpus` 取值无关** —— 65535 在 `mp_ncpus=1`（1 个 entry）时同样越界，故 **G1 既未引入也未加重它**，本轮不处理。【代码坐实】

在「不越界」已由上述写侧论证确立后，剩下的是并发权衡，**本文裁决为 `mp_ncpus = N`**，理由两条：

1. **D2 的ipfw 堆溢出使其成为强制项**：`mp_ncpus` 若保持 1 而 `all_cpus` 有 N 位，`ip_fw_dynamic.c:2086-2091` 会往只有 1 槽的`dyn_hp_cache` 连续写 N 项。虽然触发还需「共享 `dyn_hp` 槽位非 NULL」（即 ipfw 动态规则被实际使用，`_m17_gate_plan.md` §8.7 记为未核验其是否启用），但这是**不该留的条件性越界**。
2. **U16-a 已由本文关闭为「hpts 活跃」**（§0.4）：`mp_ncpus=1` 会让 `tcp_pace.rp_num_hptss == 1`，N 个 worker 的 `main_loop` 都去驱动同一个 hpts 实例；而 `HPTS_TRYLOCK` = `mtx_trylock` 在 f-stack 里被 `lib/include/sys/mutex.h:74-76` 定义为**常量 1（永远"成功"）**，即**毫无互斥**【代码坐实】。`mp_ncpus=N` 让 `hpts_cpuid()` 按 `inp_flowid % mp_ncpus`（`tcp_hpts.c:1089`）把连接分流到 N 个实例，显著降低该热点。

**残留（必须如实记录，非本轮修复）**：即使 `mp_ncpus=N`，`tcp_choose_hpts_to_run()`（`tcp_hpts.c:1574-1587`）仍是「在 `0..rp_num_hptss-1` 里挑最久未运行的那个」，因此两个 worker **仍可能选中同一个 hpts**；配合 `HPTS_TRYLOCK` 恒真与 `:1599/:1608 if (hpts->p_hpts_active)` 的非原子守卫，存在并发进入同一 hpts 的窗口。**这是既存缺陷（T1 下更严重：N 个 worker 必然挤在唯一实例上），G1 使其变轻而非变重**；本轮不修，登记于 §6.4。**【未坐实】**其实际发生率须 M5 观测（建议打印 `tcp_pace.rp_num_hptss` 与各 `hpts->p_on_queue_cnt`）。

**⚠ 本裁决的代价（前向引用）**：`mp_ncpus = N` 会使 `tcp_hpts` 实例数由 1 变N（`tcp_hpts.c:1864/1872`），带来**约 +2.34 MiB × (N−1)** 的内存增量、以及「N 个实例的 callout 全挂在主线程 callwheel、却由各 worker 驱动」的语义错配与 `p_mtx` 无实际互斥问题。**这三点已完整登记为 §6.19（记为 native-mt 并发风险清单的 R6），并要求 M5 量化内存增量（§7.4）。** 本文仍维持 `mp_ncpus = N` 的裁决，因为其收益（消除 D2 的 ipfw 堆溢出这一**内存安全**问题 + 分散 hpts 热点）优先于上述**资源与既存并发**代价；若 M5 显示内存增量不可接受，降级手段是 §3.4 的 R-1（缩小 `MAXCPU`）**不适用**（本增量由运行期 `mp_ncpus` 驱动而非 `MAXCPU`），须另行评估「`mp_ncpus` 保持 1 + 单独修复 ipfw `dyn_hp_cache` 尺寸」的组合方案 —— 该组合**本轮未设计、未验证**【未坐实】。

#### 4.3.3 `ff_pcpu_thread_init()`：真正使用形参 + 运行期上界检查（D3 / D6）

**当前**（HEAD `:103-109`）：形参 `cpuid`被刻意忽略，恒传 0给 `pcpu_init()`；`:94-101` 的注释明确解释了「cpuid must stay 0」的原因（非 SMP、`MAXCPU==1`）。

**改法**：

```c
void
ff_pcpu_thread_init(int cpuid)
{
    if (cpuid < 0 || (u_int)cpuid > mp_maxid)
        panic("ff_pcpu_thread_init: cpuid %d out of range [0, %u]\n", cpuid, mp_maxid);

    pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);
    pcpu_init(pcpup, cpuid, sizeof(struct pcpu));
    PCPU_SET(prvspace, pcpup);
}
```

- **上界用运行期 `mp_maxid`**（而非编译期 `MAXCPU`），与 libuinet 的 `uinet_pcpu_get()` 在取槽位唯一入口做 `KASSERT(td_oncpu < mp_ncpus)` 同构（`_m17_B_external.md` §3.1(b)(i)）。D6 要求。
- `malloc(sizeof(struct pcpu))` 尺寸**不需改**：`sizeof(struct pcpu)` 在 `-DSMP` 前后实测**均为 4096**（`_m17_C_buildprobe.md` §0.3），且 `freebsd/amd64/include/pcpu_aux.h:47_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE)` 是编译期硬约束。【实测 + 代码坐实】
- **`:94-101` 的原注释必须重写**（它现在陈述的是被本轮推翻的约束）。**须注释（≤3 行）**：说明「每线程一份 pcpu +稠密 cpuid ∈ [0, mp_maxid] 是 UMA_ZONE_PCPU/SMR 槽位互不重叠的前提」与「上界检查是刻意保留的，因为 `subr_pcpu.c:88` 的 KASSERT 已被编译掉」。
- `pcpu_init()` 仍在`init_lock` 临界区内（`:185-186` 自旋、`:216` 释放），**不缩小该锁范围**：稠密索引后 `cpuid_to_pcpu[cpuid]=pcpu`（`subr_pcpu.c:91`）各线程写不同下标，但 `STAILQ_INSERT_TAIL(&cpuhead, ...)`（`:92`）操作共享链表尾指针，必须串行；且 `init_lock` 还覆盖 `ff_init_thread0()`/`ff_adapt_user_thread_add()`/`vnet_alloc()`/`lo_set_defaultaddr()` 等全局操作（AI memory 记录的 R1~R5）。【依据】M1-A U5.1

#### 4.3.4 主线程槽位取号（D4）——含 C2纠正

**要求（D4）**：主线程槽位不得与 worker 撞车，且**不得依赖「EAL main lcore == `proc_lcore[0]`」这一未坐实推断**（U6-a；传 `--main-lcore` 可打破）。

**改法**：把 `:293 ff_pcpu_thread_init(0);` 改为

```c
ff_pcpu_thread_init(ff_global_cfg.dpdk.thread_mode ? ff_cur_proc_id() : 0);
```

其中 `ff_cur_proc_id()` 是新增的跨 TU 取号辅助函数（见 §4.4）。

**为什么必须有 `thread_mode` 门控（本文纠正 C2，M1 文档未指出）**【代码坐实】：

- `lib/ff_dpdk_if.c:460`（`init_lcore_conf()` 的**非** thread_mode 分支）：`ff_cur_lcore_conf()->proc_id = ff_global_cfg.dpdk.proc_id;`
- 即 **`thread_mode=0` 时 `proc_id` 是「进程序号」**：secondary 进程为 1、2、…（`:1645-1646` 校验 `proc_id < nb_procs`）。而 `thread_mode=0` 的每个进程都是独立地址空间、各自 `mp_maxid=0`。
- 若无门控直接用 `proc_id`：doc-16 §2.1 E2 的「2 进程」场景下 secondary 会得到 `cpuid=1`，触发 §4.3.3 的 `panic`（幸运）或（若无上界检查）越界写 `cpuid_to_pcpu[1]`（灾难）。→ **直接违反 D7 零回归**。
- 门控后：`thread_mode=0` 恒取 0，`nb_cpus=1`、`mp_maxid=0`、`all_cpus` 仅 bit 0 → 与 HEAD **逐语义等价**。

**`thread_mode=1` 下的正确性**【代码坐实】：`lib/ff_dpdk_if.c:429-433` 对 `ti in [0, nb_threads)` 设 `lcore_conf[proc_lcore[ti]].proc_id = ti`；主线程是 EAL main lcore（必属coremask，thread_mode 下 `proc_mask == lcore_mask`，`lib/ff_config.c:1477-1481`），故 `ff_cur_lcore_conf()->proc_id` 必落在 `[0, N)` 且与各 worker 互不相同。**这一取法对 `--main-lcore` 免疫**，因此 U6-a 从「方案依赖项」降为「仅需 M5 打印核对的观测项」。

**时点可用性**【代码坐实】：`rte_eal_init()` 在 `ff_dpdk_init()`（`lib/ff_init.c:43`）内已完成，故主线程在 `ff_freebsd_init()`（`:47`）内调用 `rte_lcore_id()` 有效；`lcore_conf[]` 也已在 `init_lcore_conf()` 中填好。

#### 4.3.5 与 `ff_stack_thread_init()` 的关系（不改动）

`ff_stack_thread_init()`（`:170-217`）本身**无需改动**：它把形参 `cpuid` 直接转给 `ff_pcpu_thread_init()`（`:187`）；主线程因 `:82 static __thread int ff_stack_inited` 在 `:348` 被置1，进入 `main_loop` 后于 `:177-178` 直接 return，**不会重复建 pcpu**。【代码坐实】

### 4.4 `lib/ff_dpdk_if.c`：稠密序号取用（D3）

**改动 1**：`:2649ff_stack_thread_init(rte_lcore_id());` → **必须带 `thread_mode` 门控**：

```c
ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0);
```

（**以代码为准**：实际落地的 M3 代码即为此形态；本文早先只写 `qconf->proc_id` 是漏了门控，已按 gate-design E2 修正。）

**为什么这里也必须门控（与 §4.3.4 的 C2 同源，但这是第二个落点，不可只改一处）**【代码坐实】：`lib/ff_dpdk_if.c:460`（`init_lcore_conf()` 的非 thread_mode 分支）把 `lcore_conf[].proc_id` 设为**进程序号**（`ff_global_cfg.dpdk.proc_id`，secondary 进程为 1、2、…，`:1643-1651` 校验 `< nb_procs`），而 `thread_mode=0` 的每个进程都是独立地址空间、各自 `mp_maxid == 0`。若此处无门控：secondary 进程一旦真的走到 `ff_stack_thread_init()`，会以 `cpuid=1` 触发 §4.3.3 的上界`panic`（`ff_pcpu_thread_init: cpuid 1 out of range [0, 0]`），或（若上界检查被去掉）越界写 `cpuid_to_pcpu[1]` —— **直接破坏 D7 零回归**。

**⚠ 脆弱耦合（必须显式登记，gate-design E2）**：即使有了门控，`thread_mode=0` 下的安全性仍**双重依赖**「`main_loop` 内的 `ff_stack_thread_init()` 会提前返回」这一既存机制 —— `lib/ff_freebsd_init.c:82 static __thread int ff_stack_inited;` 在主线程于 `:348` 被置 1，`ff_stack_thread_init()` 于 `:177-178` 检查后直接 `return`【代码坐实】。也就是说：`thread_mode=0` 时 `main_loop`（`ff_dpdk_if.c:2649`）传进去的实参**根本不会被使用**。这是「门控」与「早返回」两道机制同时兜底的**冗余但脆弱**的结构：任何一方将来被改动（例如把 `ff_stack_inited` 改成全局、或让 `main_loop` 在`thread_mode=0` 下也重新初始化）都会立刻暴露该实参。**因此本文在 DoD-4（§7.4）里显式要求 `thread_mode=0` 的1 进程与 2 进程都必须实测，并在日志中确认无 `ff_pcpu_thread_init: cpuid ... out of range`**，而不是仅靠静态推断。

- `qconf` 已在 `:2644 qconf = ff_cur_lcore_conf();` 取好，**零额外开销**。
- `rte_lcore_id()` 是**稀疏**的物理 lcore 号（例如 `lcore_mask=6` → lcore 1、2），与 pcpu 槽位所需的稠密 `0..N-1` 是**两个索引空间**；混用即 T0 的越界根因。【代码坐实】M1-A U6.1

**改动 2**：新增供内核态 TU 调用的取号辅助函数（落点建议在 `init_lcore_conf()` 之前）：

```c
int
ff_cur_proc_id(void)
{
    return ff_cur_lcore_conf()->proc_id;
}
```

并在 `lib/ff_dpdk_if.h` 声明。

**为什么需要这个函数**：`lib/ff_freebsd_init.c` 是内核态 TU（带 `KERNEL_CFLAGS` + `-nostdinc`），**不能** include DPDK 头（`rte_lcore_id()`）也拿不到 `lcore_conf[]`（`static`，`lib/ff_dpdk_if.c:126`）；而 `ff_dpdk_if.c` 属 `FF_HOST_SRCS`（走 `HOST_C`，`lib/Makefile:179`）。函数签名 `int (void)` 不涉及任何跨编译口径不一致的类型，是安全的跨 TU 边界。【代码坐实】`_m17_C_buildprobe.md` §0.1

- **须注释（≤1 行）**：在声明处说明「返回调用线程的稠密栈实例序号（`lcore_conf[].proc_id`）」。属对外接口契约。
- **不要**改 `ff_lcore_conf_idx()`/`ff_cur_lcore_conf()`（`lib/ff_memory.h:104-111`）的语义：它们按 `rte_lcore_id()` 索引 `lcore_conf[]` 是正确的（`lcore_conf` 就是按 lcore id 索引的数组，`lib/ff_dpdk_if.c:126 lcore_conf[RTE_MAX_LCORE]`）。**两个索引空间的边界必须保持清晰**：`lcore_conf[]`/`veth_ctx[][]`/`rte_mempool` 用 lcore id；pcpu/UMA/SMR 槽位用 `proc_id`。

### 4.5 `lib/include/sys/pcpu.h`：`curcpu` per-thread 化（G1 的第三个必做项）

这是本文相对 D1~D9 的**唯一实质性增补**，依据见 §2.3。

**改动**：把 `:34 #define curcpu 0` 改为解析到本线程：

```c
#define curcpu    PCPU_GET(cpuid)
```

（`PCPU_GET` 已由 `lib/include/amd64/include/pcpu.h:49` 重定义为 `pcpup->pc_ ## member`，故等价于 `pcpup->pc_cpuid`；这也正是上游 `freebsd/sys/pcpu.h:218` 的原始定义。`:32 #undef curcpu` 必须保留，用于抹掉上游定义后再给出 f-stack 版本，避免 redefined 告警在 `-Werror` 下失败。）

**必须同时评估的全部使用点** —— 穷举范围严格限定为「**`curcpu` 这个标识符**在**实际参与编译的集合**内的出现」（编译集合以 `lib/*.o` 反推；实测只在 7 个文件中出现）。**范围外但必须显式排除的两类**见本表末尾的「排除项」两行：

| # | 位置 | 用法 | `curcpu` 变为 `0..N-1` 后 | 判定依据 |
|---|---|---|---|---|
| 1 | `freebsd/vm/uma_core.c` × 11（`:1452,3738,3776,3818,3901,4534,4543,4595,4628,4803,4853`） | `cache = &zone->uz_cpu[curcpu];` | **这就是改动目的**：每线程独占cache 槽位；尺寸由 `uma_startup1` 按 `mp_maxid+1` 分配（H1）→ 不越界 | 【代码坐实】+本文预处理【实测】 |
| 2 | `lib/ff_kern_synch.c:105` | `_sleep(&pause_wchan[curcpu], ...)`，`:59 static uint8_t pause_wchan[MAXCPU];` | 需 `MAXCPU≥ N`：候选 A 的 1024 已满足。（**注**：今天 `curcpu==0` 故**不存在**越界，这纠正了 M1-A U9 #4 的因果表述 → C3） | 【代码坐实】 |
| 3 | `freebsd/netinet/tcp_timer.c:237,249` | `inp_to_cpuid()` 的两条fallback `return (curcpu);` | 返回值只作 `callout_reset_sbt_on()` 的 `cpu` 实参（`:896`/`:932`），经`lib/ff_kern_timeout.c:730cpu >= MAXCPU` 判定；`MAXCPU=1024 ≥ N` → **不 panic**；`CC_CPU(cpu)` 忽略参数（`:184`）→ 仍取本线程 `cc_cpu` | 【代码坐实】M1-A U11.3 |
| 4 | `freebsd/netinet/tcp_hpts.c:1587` | `return rp_ent[(curcpu % tcp_pace.rp_num_hptss)];` | **取模** → 不越界 | 【代码坐实】 |
| 5 | `freebsd/netinet/tcp_hpts.c:1566` | `CPU_ISSET(curcpu, &tcp_pace.grps[i]->cg_mask)` | 位于 `:1564 if (tcp_pace.grp_cnt > 1)` 内；`smp_topo()` 返回 NULL → `:1890 grp_cnt = 1` → **不可达** | 【代码坐实】§4.2 |
| 6 | `freebsd/netinet/tcp_lro.c:1210,1216` | `if (lc->lro_last_cpu == curcpu) ... lc->lro_last_cpu = curcpu;` | 纯启发式比较，无索引；变为 per-thread 后**语义更正确**（原来所有线程都认为在同一 CPU） | 【代码坐实】 |
| 7 | `freebsd/net/netisr.c:839` | `*cpuidp = netisr_get_cpuid(curcpu);` | `netisr_get_cpuid()`（`:275-279`）= `nws_array[cpunumber % nws_count]` → **取模**，不越界。且该行位于 `NETISR_POLICY_CPU` + `NETISR_DISPATCH_HYBRID` 分支，f-stack 下不可达（见下） | 【代码坐实】 |
| 8 | `freebsd/net/netisr.c:1172` | `if (cpuid != curcpu) goto queue_fallback;` | **不可达**：`:151 #define NETISR_DISPATCH_POLICY_DEFAULT NETISR_DISPATCH_DIRECT`、`:153 netisr_dispatch_policy = NETISR_DISPATCH_POLICY_DEFAULT`，而 `ip_nh`/`ip6_nh` 未设 `nh_dispatch`（`RSS` 未定义，`ip_input.c:139-149`、`ip6_input.c:138-148`）→ `netisr_get_dispatch()`（`:781-790`）返回 DIRECT → `:1146-1153` 分支直接 `np_handler(m)` 并 `goto out_unlock`，**在 `:1164` 之前就返回** | 【代码坐实】 |

**穷举范围外、但必须显式排除的两类（gate-design E7）**：

| # | 位置 | 为何不受影响 | 判定依据 |
|---|---|---|---|
| **排除 X1** | `freebsd/libkern/arc4random.c:212 chacha20 = &chacha20inst[curcpu];` | **该文件未参与编译**，故不受影响 | `lib/Makefile` HEAD `:582` 的 `LIBKERN_SRCS` 只列 `arc4random_uniform.c`，**不含 `arc4random.c`**；`lib/arc4random.o` 不存在（`ls` 实测 `No such file`）。（gate-design 报的 `:586` 是含 M3 改动后的工作区行号） |
| **排除 X2** | `freebsd/sys/callout.h:100-102/108-109/115-116/119-120` 的 `callout_reset_sbt_curcpu` / `callout_reset_curcpu` / `callout_schedule_sbt_curcpu` / `callout_schedule_curcpu` 宏族 | **宏名里带 `curcpu` 但宏体不经 `curcpu`**，而是直接用 `PCPU_GET(cpuid)`【代码坐实】→ 它们本来就是 per-thread 的，**不因本轮改动而改变**。其唯一已编译使用者 `freebsd/kern/subr_taskqueue.c:368 callout_reset_sbt_curcpu(...)`（在 `:366-367 tq_spin && tq_tcount == 1 && tq_threads[0] == curthread` 分支内）在 G1 后会传入稠密 cpuid（`0..N-1`），经 `lib/ff_kern_timeout.c:730` 的 `cpu >= MAXCPU` 判定，`MAXCPU=1024 ≥ N` → **安全**（另见 §6.20 的 U12-ish） | 本文实测 grep |

> **补充**（消除「改 `curcpu` 会打断 netisr 直接派发」的疑虑）：`netisr_queue*` 路径（`if_loop.c:357`、`ip_output.c:158/192`、`ip6_output.c:1045/1077`、`rtsock.c:2233`、`ip_divert.c:543/550`）走 `netisr_queue_src()` → `netisr_select_cpuid()`，而 `:810 if (nws_count == 1) { *cpuidp = nws_array[0]; return (m); }` 在触达 `:839` 之前就返回（`netisr_maxthreads` 默认 1，`:169`）。→ **`curcpu` 改动对 netisr 的选核行为无影响。**【代码坐实】（但 netisr 另有一条与 `curcpu` **无关**的 DPCPU 别名问题，见 §6.15。）

**新引入的一类风险 + 一处必须的例外（本文按实际代码修正原立场）**：`curcpu` 从字面量 0 变成 `pcpup->pc_cpuid` 之后，**在 `pcpup == NULL` 的执行点求值 `curcpu` 会解引用 NULL**。必须区分两类，**处置方式不同**：

**（i）「引导窗口」类—— 必须加定点兜底（不是可选）**【代码坐实】

`lib/ff_kern_synch.c:105 pause_sbt()` 里的 `pause_wchan[curcpu]` **在本线程建立 pcpu 之前就可达**：

```
lib/ff_freebsd_init.c:106  pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);   /* pcpup仍为 NULL */
lib/ff_glue.c:1067-1078malloc() 的 M_WAITOK 重试循环 → :1070 pause("malloc", hz/100)
freebsd/sys/systm.h:485pause() → pause_sbt()
lib/ff_kern_synch.c:105pause_wchan[curcpu] → pcpup->pc_cpuid  ==> NULL 解引用
lib/ff_freebsd_init.c:107  pcpu_init(pcpup, cpuid, ...)                /* 才建立 */
```

即 **`:106` 的 `malloc` 一旦走到 OOM 重试，就会在 `pcpup` 尚为 NULL 时求值 `curcpu`**。改动前 `curcpu ≡ 0` 故无害；改动后必崩。因此 M3 实际代码在此处加了定点兜底：

```c
/* Reachable from malloc()'s OOM retry before this thread has a pcpu. */
return (_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], NULL, 0, wmesg, sbt, pr, flags));
```

**本文采纳该改动**（以代码为准），并把它列入 §8.2 commit-1 的文件清单。它**不违背**下面(ii) 的 fail-fast 原则：这是**受支持线程**在**引导窗口内**的正确性修复，不是为不受支持的用法兜底；退化到槽位 0 在该窗口内是安全的（此时本线程尚未拥有任何 per-cpu 状态，且 `pause_wchan[]` 只用作 `_sleep` 的等待通道地址、不承载数据）。其注释是 1 行、说明「为何可达」，符合最小注释规约。

> **另需注意**：`freebsd/vm/uma_core.c:5440 pause("umarclslp", hz)` 也会走到同一路径，但它在 `uma_reclaim` 系路径上、远晚于 pcpu 建立，不属引导窗口。

**（ii）「不受支持的线程」类 —— 刻意不兜底（fail-fast）**

- 主线程：`ff_pcpu_thread_init()` 是 `ff_freebsd_init()` 里最早的动作之一（`:293`，早于 `:299 kmem_malloc` / `:301 uma_startup1`）→ **安全**。【代码坐实】
- worker：`ff_pcpu_thread_init()` 是 `ff_stack_thread_init()` 的第一个动作（`:187`）→ **安全**。
- `ff_pthread_create()` 创建的应用线程（`lib/ff_thread.c:33-45`）：`ff_start_routine`（`:21-30`）只做 `ff_set_thread(p_data->parent)`（`:16-19`），**不调用 `ff_pcpu_thread_init`** → `pcpup == NULL`。这类线程**今天调用任何走 SMR/`PCPU_GET` 的 `ff_*` API 就已经崩**（`zpcpu_get()` 解引用 `pcpup->pc_zpcpu_offset`），本轮把失败面扩大到「凡进 UMA 即崩」。**设计裁决：不加通用 NULL 兜底**（通用兜底会把不支持的用法伪装成能跑，且必然导致多线程共享槽位——正是 T1 的问题），改为按 D9 明确文档化为**不支持的用法**（§5-1）。**fail-fast 是刻意选择。**
- DPDK 内部线程（`eal-intr-thread`/telemetry）：不调用 `ff_*`/UMA（M1-A U13.2【代码坐实】：f-stack 未注册任何 `rte_service`）→ 不受影响。

**为什么这项改动必须与 §4.1/§4.3同属 G1 一个提交**：`curcpu` 变为 `0..N-1` 的前提是 `uz_cpu[]` 已按 `mp_maxid+1` 分配、`MAXCPU ≥ N`。三者拆开提交会产生「中间态即崩」的提交，违反「每个提交都应可独立编译且不引入已知崩溃」的基本要求。

### 4.6 `lib/ff_kern_timeout.c`：`timeout_cpu` 改 `__thread`（D5）

**改动**：`:190 static int timeout_cpu;` → `static __thread int timeout_cpu;`

**依据**【代码坐实】：

- 它与 `:183 __thread struct callout_cpu cc_cpu;` 是配套的一对（同一注释块 `:180-182` 描述），语义是「本线程 callwheel 对应的 cpuid」，却漏了 `__thread`。
- 唯一写入点 `lib/ff_kern_timeout.c:254 timeout_cpu = PCPU_GET(cpuid);` 在 `ff_callout_thread_init()` 内，**被每个线程执行**（主线程经 `lib/ff_kern_timeout.c:285 ff_callout_thread_init();`，该函数由 `:287 SYSINIT(callwheel_init, SI_SUB_CPU, SI_ORDER_ANY, callout_callwheel_init, NULL);` 在 `mi_startup()` 中驱动；worker 经 `lib/ff_freebsd_init.c:207`）。稠密 cpuid 后它会被覆盖成「最后一个完成初始化的线程的 cpuid」（写在 `init_lock` 内故不撕裂，但**最终值与任何单个线程都不对应**）。
- 不改的后果：`:1061 c->c_cpu = timeout_cpu;`（`callout_init`）与 `:1077`（`_callout_init_lock`）会把**别的线程的 cpuid** 写进 `c->c_cpu`；随后 `:815 return callout_reset_on(c, to_ticks, c->c_func, c->c_arg, c->c_cpu);` 把它当 `cpu` 传回 `:720 callout_reset_tick_on()` → `:730-733` 的合法性判断。即使 `MAXCPU=1024` 不 panic，语义上仍是「A 线程的 callout 记着 B 线程的 cpuid」的隐性错误。
- 改动代价**近乎为零**：`timeout_cpu` 无任何跨线程语义需求；`:662`（`timeout(9)`）与 `:1181`（`sysctl kern.callout_stat`）读它后传给 `CC_CPU()`，而 `CC_CPU(cpu)`（`:184`）**忽略参数**恒返回本线程 `cc_cpu`。

**不做的可选项（明确排除）**：M1-A U11.4「可选 C」提议把 `:730` 的`cpu >= MAXCPU` 改成 `cpu > (int)mp_maxid`。**本文裁决：不做。** 理由：① `MAXCPU=1024 ≥ N` 后该判断已不会误panic；② 它是 f-stack 既有语义，改动会扩大 G1 的 diff 面与回归面，收益仅为「更贴近真实语义」；③ 若 M5 出现该panic，说明有路径传入了非稠密 cpuid，**此时 panic 正是我们想要的信号**，不应放宽。

### 4.7 `lib/include/vm/uma_int.h`：G2 的实现形态（D8 裁决）

> **G2 的前置条件（硬）**：`curcpu` 必须已 per-thread 化（§4.5）。否则移除 `uma_crit_lock` 会使所有线程在共享 `uz_cpu[0]` 上无保护并发，**等于原样放回 `b90ddcba5` 修掉的竞态**（§2.3(d)2）。M4 开工前须由 `reviewer` 核对该前置已满足（判据：`lib/include/sys/pcpu.h` 中 `curcpu` 已为 `PCPU_GET(cpuid)`，且 DoD-1 判定式 ⑤「各线程 UMA cache 槽位互不相同」已实测通过）。

#### 4.7.1 裁决

**采用 G2-b：把 `critical_enter/exit` 改回空操作，慢路径不动，以压测验证并如实记录残留风险。**

具体改法：删除 `:45` 的 `extern volatile int uma_crit_lock;` 与 `:46-52` 的两个宏，改为

```c
#define critical_enter() do {} while(0)
#define critical_exit()  do {} while(0)
```

并删除 `lib/ff_glue.c:146 volatile int uma_crit_lock;`。

-这正是 `b90ddcba5` **之前**的状态（M1-A U7 第1 部分【实测】diff 原文：`-#define critical_enter() do {} while(0)`）。
- **保留宏而不是彻底删掉**：`lib/include/vm/uma_int.h` 在 `#include_next <vm/uma_int.h>`（`:38`）之后仍需覆盖 `freebsd/sys/systm.h` 的 inline 版本；虽然后者在 f-stack 下本就是空函数体（`systm.h:186 #ifndef FSTACK`），但保留显式空宏可避免依赖「上游某天不再有 `#ifndef FSTACK`」这一脆弱假设。**须注释（≤2行）**：说明「f-stack 无抢占语义；UMA per-cpu cache 的互斥由『每线程独占稠密 pcpu 槽位』保证，见 spec 17 §2.4」。

#### 4.7.2 为什么不选 G2-a（去锁 + 给 zone/keg/`vsetzoneslab` 补真锁）

三条代码级否决理由：

1. **UMA 的锁是可睡眠语义（`MTX_DEF`），补自旋锁会自死锁。**【代码坐实】`freebsd/vm/uma_core.c:1725 msleep(zone, ZONE_LOCKPTR(zone), PVM, "zonedrain", 1);` —— 在**持有 zdom 锁的情况下睡眠**（`ZONE_LOCKPTR(z)` 见 `freebsd/vm/uma_int.h:584`）；`freebsd/vm/uma_int.h:540-548 KEG_LOCK_INIT` 与 `:566-574 ZDOM_LOCK_INIT` 的两条分支全部用 `MTX_DEF | MTX_DUPOK`（`:544`/`:547`/`:570`/`:573`），`:586-587 ZONE_CROSS_LOCK_INIT` 用 `MTX_DEF`；`uma_core.c:5433 sx_sleep(uma_reclaim, &uma_reclaim_lock, ...)`。→ G2-a 真正需要的是**可睡眠互斥体+ 条件变量**，等于把 f-stack 整个 `mtx` 层去 stub 化（`lib/include/sys/mutex.h:59-85` 把 `__mtx_lock`/`_mtx_lock_flags`/`mtx_init`/`mtx_destroy`/`mtx_owned`/trylock 系全部 stub，`kern_mutex.c` 不在 SRCS，`lib/ff_lock.c` 只提供初始化/销毁壳子）。这是项目级改造，远超本轮范围。
2. **嵌套持锁 → 单把全局锁必自死锁，逐锁真化又依赖 `mtx_init` 真正工作。**【代码坐实】`freebsd/vm/uma_int.h:582 ZONE_LOCK(z) = ZDOM_LOCK(ZDOM_GET((z), 0))`、`:551-552 KEG_LOCK(k,d) = ({ mtx_lock(KEG_LOCKPTR(k,d)); KEG_LOCKPTR(k,d); })`；`zone_alloc_bucket` → `keg_alloc_slab` 路径与 `zone_put_bucket` 路径分别持 keg / zdom 锁且存在嵌套。用一把非递归全局自旋锁替换两者即自死锁。
3. **与 DoD-5 直接冲突**：在**今天没有锁**的路径上新增锁，几乎必然让吞吐下降，而 DoD-5 要求「去锁后吞吐不得低于去锁前（±2% 噪声内）」。把 G2 做成「净增锁」会使该门禁自相矛盾。

#### 4.7.3 为什么不选 G2-c（保留锁但缩小到只包 bucket 交换）与 libuinet 的「per-cpu 一把锁」

- **G2-c 名不副实**：bucket 交换**本来就在临界区之外**（§2.4 表：`uma_core.c:3859 critical_exit()` → `:3880 cache_fetch_bucket()`/`:3882 zone_alloc_bucket()`；`:3916 critical_exit()` → `:3917 zone_put_bucket()`）。因此「把锁缩小到只包 bucket 交换」实质是**把锁搬到一个今天没有锁的地方 = 新增锁**，落回 G2-a 的否决理由 1、2、3（尤其嵌套与 `msleep`）。
- **libuinet 的 `uinet_pcpu_locks[MAXCPU]`（per-cpu 一把锁）在 f-stack 里等价于无锁**：G1 之后线程与槽位 1:1 且永不迁移，per-cpu 锁**零争用**，只剩一次 `lock xchg` 的固定开销而无任何互斥收益。libuinet 那把锁有意义是因为它允许线程在虚拟 CPU 间迁移（`_m17_B_external.md` §3.1(a)：注释 `XXX temporary until final pcpu approach is determined`；§3.2 rump 亦允许迁移故必须 CAS 互斥）；f-stack 的模型**更强**，不需要它。**故明确排除。**

#### 4.7.4 G2 的降级台阶（若 M5 压测失败）

`_m17_A_codepath.md` 附录 A.2 已把「移除 `uma_crit_lock` 后 zone/keg 慢路径 + `vsetzoneslab` 的无锁竞争窗口放大到什么程度」列为 **U8-perf：静态分析无法定论，必须运行期数据**。本文接受该边界，并**预先设计**三级台阶，使 M5 失败时不需要重新设计：

| 台阶 | 触发条件（可观测） | 动作 | 依据 / 风险 |
|---|---|---|---|
| **L0** | — | G2-b，**独立提交**（commit-2），可单独 `git revert` 而不影响 G1 | §4.7.1 |
| **L1** | **触发判据（已按 `reviewer` M4 门禁「必改-2」整体重写；原判据 (a) 指向死代码，作废）**：**(c) 升为首选 —— 哈希结构异常的直接证据**：桶内自环 / 重复 `up_va` / **节点数与登记次数不符**（见 §4.7.5 的早期检测式，**不必等崩溃**）。**(a′) 次选 —— 崩点必须落在下列之一**：① `vtoslab()`（`uma_int.h:77-88`，`:87return (NULL)`）返回 NULL 后被解引用，具体为 `freebsd/vm/uma_core.c:4930 slab = vtoslab((vm_offset_t)item);` → `:4938 if (lock != KEG_LOCKPTR(keg, slab->us_domain))` 处的 `slab->us_domain`；或 ② `uma_core.c:5819 return (vtoslab((vm_offset_t)mem));` 的调用者对返回值解引用。**(b) 佐证 —— 并发性**：只在 `thread_mode=1 && nb_threads ≥ 2` 出现，1 线程与 `thread_mode=0` 同负载不复现。**⛔ 不得再用「崩在 `uma_int.h:101/102`」作判据**：该两行属`vtozoneslab()`，其**唯一调用者是 `freebsd/kern/kern_malloc.c:943/1039/1136`，而该文件不在 `lib/Makefile` SRCS（HEAD内 `grep kern_malloc` 零命中、`lib/kern_malloc.o` 不存在）→ `vtozoneslab()` 在本 build 中是死代码、该行永不执行**【代码坐实】。故 `gate-design` E9 所指的「歧义」实为「**不可达**」，原判据恒不可触发 | 只给 **f-stack 自有的写侧** `vsetzoneslab()`（`:105-126`）加一把**专用**全局自旋锁（新变量，例如 `uma_page_hash_lock`），**不触碰任何上游锁宏** | 闭包最小、**无嵌套、无睡眠**（函数体只有遍历 + `malloc` + 字段写 + `LIST_INSERT_HEAD`）。**但不可「只加锁了事」——实施注意事项见 §4.7.6**（`reviewer` G2-S2：编译器屏障 / release store，以及 `:115-118`「命中即改」分支的撕裂读） |
| **L2** | L1 仍失败，或 L1 使吞吐跌破 DoD-5 阈值 | `git revert` commit-2，**保留 G1**；把 `uma_crit_lock` 的必要性作为**结论**写回 spec（DoD-2 允许「论证其不可移除并给出代码级依据 + 由 `reviewer` 门禁确认」） | plan §6 DoD-2 原文 |

**bounce 纪律**：L0→L1→L2 每次失败都算 M4 的一次打回，累计 3 次即按规约转人工决策，**不允许带病放行**。

#### 4.7.5 L1 的早期检测式（哈希节点数比对，**不必等崩溃**）

`reviewer` M4 门禁指出：仅靠「崩在某行」来判定并发插入竞态既滞后又易误判。因此把「**哈希节点数比对**」定为 L1 判据(c) 的首选形式 —— 它能在**任何崩溃发生之前**直接判定「是否发生了插入丢失」。

**检测原理**（依据见 §6.2：该哈希**只增不删**，故「登记次数」与「实际节点数」应恒等）：

1. 在 `vsetzoneslab()`（`lib/include/vm/uma_int.h:105-126`）的**插入分支**（`:120-125`）加一个诊断计数器：`uma_page_inserts++`（评估期用 `__sync_fetch_and_add` 以免自身竞态掩盖问题）。
2. 在一个可控时点（例如 soak 结束前的探针里）遍历全部 `num_hash_buckets`（8192）个桶，累加实际节点数得 `n_actual`。
3. **判定式**：`n_actual == uma_page_inserts`。
   - `n_actual < uma_page_inserts` ⇒ **发生了插入丢失** ⇒ L1 触发条件 (c) 成立（并发竞态被直接坐实，不需要等崩溃）。
   - 二者相等 ⇒ 未发生插入丢失（在该次运行的负载下）。
4. 辅助判据（同一次遍历里顺带做，成本极低）：每个桶内 **`up_va` 是否有重复**、遍历是否出现**自环**（节点数超过 `uma_page_inserts` 即可判定异常）。

**性质**：这是**纯诊断代码**，仅在评估是否需要 L1 时临时加入，**不进入任何正式提交**（与 §8.3 的探针同等对待）。**【未坐实】** 本轮未实施（G2 尚未进入需要 L1 的状态）。

#### 4.7.6 L1 的实施注意事项（`reviewer` G2-S2；**若采纳 L1 必须一并处理**）

**加锁本身不足以修正内存可见性与撕裂读**，采纳 L1 时必须同时处理以下两点，否则「加了锁仍然可能错」：

1. **写侧发布需要屏障 / release store**：`:122-124` 先填 `up_va`/`up_slab`/`up_zone`、`:125` 再 `LIST_INSERT_HEAD` 发布。x86-TSO 下**硬件**存储保序，但**编译器**仍可能重排这几条普通存储（它们之间无依赖）。因此必须至少加编译器屏障（`__compiler_membar()` / `atomic_thread_fence_rel()`），或把 `list_entry.le_next` 的发布写成 release store。**本文原先只论证了硬件序而未提编译器序，此处修正。**
2. **「命中即改」分支存在撕裂读**：`:115-118` 的 `up->up_slab = slab; up->up_zone = zone;` 是**对已发布节点的原地覆盖**。读侧 `vtoslab()`（`:83-86`）可能在这两条存储之间读到 `up_slab` 与 `up_zone` **不属于同一次更新**的组合。**只给写侧加锁并不能消除这一撕裂**（读侧不持锁）。若采纳 L1，须一并决定：**(i)** 读侧也进入同一把锁；**(ii)** 或改为「写新节点 + 原子替换指针」的发布式更新；**(iii)** 或论证在本build 中该分支实际不被触发（**需先坐实**：`vsetzoneslab()` 对同一 `va` 的重复登记是否真会发生 —— 本文**未坐实**）。
   - 补充事实：`vtoslab()` 只返回 `up_slab`、**不读 `up_zone`**（`:85`），而唯一读 `up_zone` 的`vtozoneslab()` 在本 build 中是死代码（§4.7.4 的⛔ 说明）⇒ **该撕裂读在当前编译集合内实际无消费者**。这使 (iii) 成为最省的选项，但**必须在实施时重新核实`kern_malloc.c` 仍未被加入 SRCS**。**【代码坐实】+【未坐实（前瞻性）】**

#### 4.7.7 G2 独立性要求（硬性）

- G2 **必须**是独立提交（commit-2），且 `git revert` 该提交后代码回到「G1 已生效 + 全局锁仍在」的**可运行**状态。
- 因此 G2 的 diff 面被限定为**2 个文件**：`lib/include/vm/uma_int.h`（`:45-52`）与 `lib/ff_glue.c`（`:146`）。**任何其它改动都不得混入 commit-2。**
- G1 提交（commit-1）**不得**顺手改 `uma_crit_lock`：否则 G2 失败时无法单独回退，会把 G1 的收益一起丢掉。

### 4.8 `thread_mode=0` 零回归保证（D7）

| 保证点 | 机制 | 验证 |
|---|---|---|
| `mp_ncpus`/`mp_maxid`/`all_cpus` | §4.3.1 的 `nb_cpus = thread_mode ? nb_threads : 1` → `mp_ncpus=1`、`mp_maxid=0`、`all_cpus` 仅 bit 0，与 HEAD（`:294 CPU_SET(0,&all_cpus)`、`ff_glue.c:140 mp_ncpus = 1`、`:145 mp_maxid` BSS 0）**逐值相同** | DoD-4 的 `thread_mode=0` 1 进程 / 2 进程对照 |
| pcpu cpuid（**主线程路径**，`ff_freebsd_init`） | §4.3.4 的 `thread_mode ? ff_cur_proc_id() : 0` → 恒 0（**这正是 C2 纠正的关键**） | DoD-1 探针在 `thread_mode=0` 下须打印 `dense_idx=0`、`pc_zpcpu_offset=0` |
| pcpu cpuid（**`main_loop` 路径**，`ff_dpdk_if.c:2649`，gate-design E2 要求补齐） | §4.4 改动 1 的 `thread_mode ? qconf->proc_id : 0` → 恒 0。**双重保险**：即使门控失效，`main_loop` 内的 `ff_stack_thread_init()` 也会因 `__thread ff_stack_inited`（`ff_freebsd_init.c:82`，主线程在 `:348` 置1）在 `:177-178` 直接 `return`，**实参根本不被使用**。**但这是脆弱耦合**：`thread_mode=0` 时 `lcore_conf[].proc_id` 是**进程序号**（`ff_dpdk_if.c:460`，secondary=1/2/…），一旦门控被去掉**且**早返回机制被改动（例如 `ff_stack_inited` 改为全局、或 `main_loop` 在 `thread_mode=0` 下也重新初始化），secondary 进程立刻会以 `cpuid=1` 撞上 `mp_maxid==0` 的上界检查 | **不接受静态推断**：DoD-4（§7.4）显式要求 `thread_mode=0` 的 **1 进程与 2 进程都实测**，并在日志中确认无`ff_pcpu_thread_init: cpuid ... out of range`；DoD-1 判定式 ⑧ 要求 secondary 进程也打印 `dense_idx=0` |
| `curcpu` | `PCPU_GET(cpuid)` = `pcpup->pc_cpuid` = 0 → 与原字面量 0 **同值** | 同上 |
| `timeout_cpu` | 单栈线程，`__thread` 与全局同值 | — |
| `MAXCPU` 1→1024 | 只影响静态数组尺寸与 `sizeof(cpuset_t)`（8→128），**不改变任何单进程语义**；`SRCS` 全量 clean 重编保证口径一致 | DoD-3（warning 不增）+ DoD-4（吞吐波动 ≤5%） |
| `-DSMP` 的 CK `lock` 前缀 | 单进程无并发 → 仅微小指令开销 | DoD-4 吞吐对照 |

**⚠唯一需要 M5 确认的点**【未坐实】：`-DSMP` 使 `cpuset_t` 8→128 字节、`MAXCPU` 相关静态数组 1→1024 槽，理论上有 cache 局部性影响。plan §5.1 的 `thread_mode=0` 基线为 209,946 / 209,367 req/s（1 进程）、234,613 / 233,982（2 进程），DoD-4 允许≤5% 波动。

### 4.9 与 D1~D9 的逐条对齐核对表

| # | 约束 | 本文落点 | 状态 |
|---|---|---|---|
| **D1** | `MAXCPU ≥ N` 是 G1 硬前置（`cpuid_to_pcpu[MAXCPU]` 越界写会覆盖紧邻的 `cpuhead`；`ff_kern_timeout.c:730` panic；`pause_wchan[MAXCPU]`） | §4.1（`-DSMP` → 1024）+ §4.3.1 的 `nb_cpus > MAXCPU` panic | ✅ 满足。**并纠正 C3**：`pause_wchan` 的 UB 今天不存在，是 `curcpu` 改动后才需要 `MAXCPU ≥ N` |
| **D2** | `mp_ncpus`/`mp_maxid`/`all_cpus` 三元组同步设置且全部早于 `uma_startup1()`；`mp_ncpus` 不同步会导致 ipfw 堆溢出 | §4.3.1（落点在 `:291`~`:293` 之间）+ §4.3.2（裁决 `mp_ncpus = N`） | ✅ 满足 |
| **D3** | 稠密序号用现成 `lcore_conf[].proc_id`；`ff_dpdk_if.c:2649` 改用 `qconf->proc_id`；`ff_pcpu_thread_init()` 真正使用形参 | §4.4 改动 1 + §4.3.3 | ✅ 满足 |
| **D4** | 主线程槽位不撞车，且不依赖「main lcore == `proc_lcore[0]`」 | §4.3.4（用 `ff_cur_proc_id()`，对 `--main-lcore` 免疫）+ §4.4 改动 2 | ✅ 满足，**并增补 C2 的 `thread_mode` 门控** |
| **D5** | `timeout_cpu` 必须改 `static __thread` | §4.6 | ✅ 满足 |
| **D6** | `ff_pcpu_thread_init()` 增加运行期上界检查（因 `subr_pcpu.c:88` KASSERT 已编译掉） | §4.3.3（`cpuid < 0 \|\| cpuid > mp_maxid` → `panic`） | ✅ 满足（上界用运行期 `mp_maxid`，与 libuinet 同构） |
| **D7** | `thread_mode=0` 零回归：`mp_maxid=0`、`mp_ncpus=1`、`all_cpus` 仅 bit 0 | §4.8 | ✅ 满足|
| **D8** | designer 必须在 G2-a/b/c 中裁决并给理由 + 降级台阶 + 独立提交 | §4.7（裁决 G2-b；§4.7.2/§4.7.3 逐条否决 a/c与 libuinet 形态；§4.7.4 三级台阶；§4.7.5 独立提交要求） | ✅ 满足 |
| **D9** | `ff_pthread_create()` 线程 `pcpup == NULL`，须明确为「不支持的用法」或另立项 | §5-1（明确为不支持，并说明为何**不加** NULL 兜底）+ §4.5 的风险说明 | ✅ 满足（选择「文档化为不支持」，不做「预留 K 槽位」方案，理由见 §5-1） |
| **（增补 1）** | **`curcpu` 硬编码为 0 → UMA per-cpu cache 不随 `pc_cpuid` 隔离** | §2.3（机理）+ §4.5（改法 + 7 处影响点穷举） | 🆕 本文新增，**不在D1~D9 内，但属 G1 必做项** |
| **（增补 2）** | **`uma_page_slab_hash` 必须早于 `uma_startup1()` 初始化**（G1 打破了「hash 可以晚于 UMA 启动」这一既有隐含假设） | §4.10（机理 + 改法）+ §6.22（记为 G1 暴露的既有缺陷） | 🆕 **运行时实测发现**（`mp_maxid ≥ 2` 启动即 SIGSEGV），属 G1 必做项 |

### 4.10 `uma_page_slab_hash` 初始化时序（时序硬约束 H3；**运行时实测发现，已修复**）

> **来源与证据强度**：这是 M3 阶段**运行时实测**发现的 G1 回归（`thread_mode=1` 的 3/4 线程档 **100% 复现**启动即 SIGSEGV），**比本文其余静态分析结论的证据强度更高**。现场特征：崩在 `uma_startup1() → zone_alloc_item() → zone_import()`，**主线程内、worker 尚未启动**，与 virtio/RSS 无关；1/2 线程档正常。**【实测】**

#### 4.10.1 性质定性（措辞必须准确）

**这不是 G1 的逻辑错误，而是 f-stack 既有的一个隐含假设被 G1 打破** —— 该假设是：「`uma_page_slab_hash` 可以在 `uma_startup1()` **之后**才初始化」。它**仅在 `mp_maxid == 0` 时成立**：那时 zone-of-zones 的 item 足够小 → slab 恒为单页 → `UMA_ZFLAG_VTOSLAB` 永不被置 → `uma_startup1()` 期间根本不会调用 f-stack 自有的 `vsetzoneslab()`，于是 hash 未就绪也无妨。G1 把 `mp_maxid` 抬到 N−1 后，该前提消失。

#### 4.10.2 根因链（逐点坐实）

| # | 环节 | 依据 |
|---|---|---|
| 1 | zone-of-zones 的 item尺寸随 `mp_maxid` 线性增长：`zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache) * (mp_maxid + 1) + sizeof(struct uma_zone_domain) * vm_ndomains` | `freebsd/vm/uma_core.c:3179-3182`【代码坐实】。每多一个 CPU **+128 字节**（`sizeof(struct uma_cache) == 128`，由 §7.1 探针实测的 `uma_cache` 槽距 `0x80` 坐实【实测】；注意上游 `uma_int.h:280-281` 的注释说「pads perfectly into 64 bytes」**与本地实测不符**，以实测为准） |
| 2 | `keg_layout()` 的升级循环在效率不达标时把 slab 由 1 页升到 2 页：`:2440for ( ; ; i++)` → `:2441-2442 slabsize = ptoa(i)`；`:2466-2469` 的退出条件是「`kl.eff >= UMA_MIN_EFF`（`:2262`）**或** `!multipage_slabs` **或** `slabsize >= SLAB_MAX_SETSIZE*rsize` **或** 带 `UMA_ZONE_PCPU\|UMA_ZONE_CONTIG` 标志」→ zone-of-zones **不带** PCPU/CONTIG 标志，故会真的升到多页 | `freebsd/vm/uma_core.c:2436-2472`【代码坐实】 |
| 3 | slab 变2 页后置上 `UMA_ZFLAG_VTOSLAB`：`:2486-2491 if ((uk_flags & UMA_ZFLAG_OFFPAGE) != 0 \|\| (keg->uk_ipers - 1) * rsize >= PAGE_SIZE) { ... keg->uk_flags \|= UMA_ZFLAG_VTOSLAB; }` —— 该条件**单页时恒不成立、两页时成立** | `freebsd/vm/uma_core.c:2486-2491`【代码坐实】 |
| 4 | `VTOSLAB` 使 `keg_alloc_slab()` 在 `uma_startup1()` 期间就逐页调用 f-stack 自有的 `vsetzoneslab()` | `freebsd/vm/uma_core.c:1822-1825`（对 `i < uk_ppera` 逐页登记）【代码坐实】 |
| 5 | 而 `vsetzoneslab()` 直接使用 `uma_page_slab_hash` / `uma_page_mask`，**无判空** | `lib/include/vm/uma_int.h:107-126`（`:112 &uma_page_slab_hash[(va >> PAGE_SHIFT) & uma_page_mask]`）【代码坐实】 |
| 6 | 但这两个全局量原先在 `lib/ff_freebsd_init.c` 中**晚于** `uma_startup1()` 才被 `kmem_malloc` 分配 → **NULL 解引用** | HEAD `lib/ff_freebsd_init.c:304-306`（在 `:301 uma_startup1()` **之后**）【代码坐实】 |

**⚠ 诚实边界（沿用 `coder` 的措辞强度，不得越界）**：本文**只断言机制成立 + 实测阈值（`mp_maxid ≥ 2` 必崩、`mp_maxid ≤ 1` 不崩）**，**不给出「恰好 N=3 越界」的算术推导**。原因：`keg_layout_one()` 对 `UMA_ZFLAG_INTERNAL` 格式会 `slabsize += PAGE_SIZE` 并经 `slab_ipers_hdr()` 把内联 slab 头计入，手工推导极易出错。**任何未经运行时验证的算术阈值都不得写入本文。**【未坐实】

#### 4.10.3 改法（已落地）

把 `uma_page_slab_hash` / `uma_page_mask` 的初始化**整体提前到 `uma_startup1()` 之前**。落地后的顺序（当前工作区实测）：

```
lib/ff_freebsd_init.c:380-382   num_hash_buckets = 8192; uma_page_slab_hash = kmem_malloc(...); uma_page_mask = ...;
lib/ff_freebsd_init.c:385       bootmem = kmem_malloc(boot_pages * PAGE_SIZE, M_ZERO);
lib/ff_freebsd_init.c:387       uma_startup1((vm_offset_t)bootmem);
```

**可行性依据**：`boot_pages` 那次 `kmem_malloc()` 本来就在 `uma_startup1()` **之前**（HEAD `lib/ff_freebsd_init.c:299`），这直接证明 **`kmem_malloc` 在 UMA 启动前可用**，故把另一次 `kmem_malloc` 提到同一位置之前不引入新的依赖。【代码坐实】

**注释要求**：此处**必须**有注释（属「不加注释无法理解的时序约束」），但应控制在 **≤3 行**，只说明「必须早于 `uma_startup1()`：一旦 `mp_maxid > 0`，zone-of-zones 变大 → slab 升多页 → 置 `VTOSLAB` → `uma_startup1()` 期间就会调用 `vsetzoneslab()`」。当前落地版本的 `:376-378` 三行注释符合该要求。

**同时并入 §4.3.1 的时序硬约束族**：H1（`uma_startup1` 前定死 zone 尺寸）、H2（`mp_maxid` 与 `UMA_ZONE_PCPU` 成对）、**H3（本节：`uma_page_slab_hash` 必须早于 `uma_startup1()`）**。三者共同构成「G1 的启动时序契约」。

**一处既存的良性瑕疵（本轮不改，仅登记）**：`:381` 的分配尺寸写作 `sizeof(struct uma_page) * num_hash_buckets`，而数组元素类型是 `struct uma_page_head`（`lib/include/vm/uma_int.h:74-76`，仅 1 个指针 = 8 字节）而非 `struct uma_page`（`:67-72`，4 个字段 = 32 字节）→ **超额分配约 4 倍**（8192 桶多占约 192 KB）。这是**既存写法**（HEAD `:305` 即如此）、只多占内存不引发错误，**本轮不改**（改它与G1 无关，会扩大 diff 面）。【代码坐实】

---

## 5. 明确不做的事与理由

| # | 排除项 | 理由（代码级） |
|---|---|---|
| **1** | **不支持 `ff_pthread_create()` 创建的应用线程调用 f-stack API**（D9）。**不**为其补 `ff_pcpu_thread_init()`，**不**加通用的 `pcpup == NULL` 兜底（**唯一例外**：`pause_sbt()` 的引导窗口定点兜底，见 §4.5(i)，那是受支持线程在 pcpu 建立前的正确性修复，不属此列） | `lib/ff_thread.c:33-45 ff_pthread_create()` → `:21-30 ff_start_routine()` 只做 `:16-19 ff_set_thread(p_data->parent)`（即 `pcurthread = other`），**不调用 `ff_pcpu_thread_init()`** → `__thread pcpup == NULL`【代码坐实】。补槽位方案需要「`mp_maxid` ≥ 栈线程数 + 预留 K 个应用线程槽位」，而应用线程数在启动时未知，与 §4.3.1 的 H1「`mp_maxid` 必须在 `uma_startup1()` 前定型且此后不得再变」**直接冲突**，需要新增配置项 → 另立项。加通用 NULL 兜底会把不支持的用法伪装成能跑，且必然导致多线程共享同一槽位（回到 T1 的问题）。**故选择 fail-fast + 文档化** |
| **2** | **不修 counter(9) 的统计竞争** | `lib/include/amd64/include/counter.h:38-62` 已把 counter(9) 完全去 per-cpu 化（`counter_u64_add` = `*c += inc`、`counter_u64_fetch_inline` = `*p`、`counter_enter/exit` 空操作），`freebsd/kern/subr_counter.c` 内无任何 `mp_maxid`/`CPU_FOREACH`/`zpcpu` 遍历（仅 `:63 uma_zalloc_pcpu(pcpu_zone_8, ...)`）【代码坐实】。→ `mp_maxid` 抬高**不会越界**；实际影响是多线程写同一 slot 造成统计丢失、fetch 只读 slot 0。**是统计准确性问题，不是内存安全问题**，与G1/G2 无因果，独立立项 |
| **3** | **不修 ipfw DPCPU hazard pointer 别名** | `freebsd/netpfil/ipfw/ip_fw_dynamic.c:224-226` 的 `DPCPU_DEFINE_STATIC(void *, dyn_hp)` / `DPCPU_ID_PTR` / `DPCPU_PTR`，因`dpcpu_init()`（`freebsd/kern/subr_pcpu.c:100`）在编译集合内**零调用者**（M1-A U15【实测】）、`dpcpu_off[]` 恒 0 → 所有 cpu 的 DPCPU 槽位**互相别名**。**候选 A 修不了这一条**（`-DSMP` 只放开 `subr_pcpu.c:252` 的 `dpcpu_copy` 分支，不产生 `dpcpu_init` 调用者）。见 §6.3 |
| **4** | **不给 `ZDOM_LOCK`/`KEG_LOCK`/`vsetzoneslab` 补真锁**（即不做 G2-a/G2-c） | §4.7.2/§4.7.3 的三条代码级否决理由（`msleep` 持锁睡眠、嵌套持锁、与 DoD-5 冲突）。仅在 G2 降级台阶 L1 才对 f-stack 自有的 `vsetzoneslab()` 写侧加一把专用锁 |
| **5** | **不动 DPDK 侧的 `rte_lcore_id()` 索引空间** | `lcore_conf[RTE_MAX_LCORE]`（`lib/ff_dpdk_if.c:126`）、`veth_ctx[RTE_MAX_LCORE][RTE_MAX_ETHPORTS]`（`:182`）、`rte_mempool` per-lcore cache **都应当**继续按 `rte_lcore_id()` 索引，与 UMA/SMR 的 pcpu 槽位（按 `proc_id`）是**两个独立索引空间**【代码坐实】。本轮只在 `:2649` 这一个「跨越两个空间」的点做转换 |
| **6** | **不缩小 `init_lock`（`lib/ff_freebsd_init.c:175`）的范围** | 稠密索引后 `cpuid_to_pcpu[cpuid]=pcpu`（`subr_pcpu.c:91`）各线程写不同下标，但 `STAILQ_INSERT_TAIL(&cpuhead,...)`（`:92`）操作共享链表尾指针必须串行；且该锁还覆盖 `ff_init_thread0()`/`ff_adapt_user_thread_add()`（`uifind(0)`/`crget`/`EVENTHANDLER_INVOKE` 等全局操作）/`vnet_alloc()`/`lo_set_defaultaddr()`。**收益在数据面而非启动路径**【依据】M1-A U5.1 |
| **7** | **不放宽 `ff_kern_timeout.c:730` 的 `cpu >= MAXCPU` 判断** | §4.6 末段三条理由（`MAXCPU=1024` 后不会误panic；改动扩大回归面；若真触发，panic 正是我们要的信号） |
| **8** | **不修 hpts 的并发进入窗口** | §4.3.2 残留段：`HPTS_TRYLOCK` = `mtx_trylock` 被 `lib/include/sys/mutex.h:74-76` 定义为常量 1，`tcp_choose_hpts_to_run()` 可让两个 worker 选中同一实例。**这是既存缺陷，G1 使其变轻而非变重**，本轮不修，见 §6.4 |
| **9** | **不做 NUMA 相关工作** | `lib/ff_glue.c:83 int __read_mostly vm_ndomains = 1;` 且 `NUMA` 未定义（编译命令与 `lib/opt/opt_global.h` 均无）→ `uma_core.c` 全部 `#ifdef NUMA` 跨 domain bucket 路径未编译、`itemdomain` 恒 0、`uc_crossbucket` 永不装载【代码坐实】M1-A U8.4-4。→ 只需处理「跨线程」，不需处理「跨 domain」（前向约束见 §6.16） |
| **10** | **不支持 `net.isr.dispatch` 设为非 `direct`**（即 `config.ini` 的 `[freebsd.sysctl]` 段**不得**出现 `net.isr.dispatch`，保持默认 `direct`） | `curcpu` per-thread 化后，`hybrid`/`deferred` 会让 worker 在 `netisr.c:1172 cpuid != curcpu` 处成立而 `goto queue_fallback`，入队后因`lib/ff_kern_intr.c:91-95 swi_sched()` 是空 stub 而**静默丢包**【代码坐实】。改动前 `curcpu ≡ 0 == nws_array[0]`（`netisr.c:810-812`）恒相等故永不命中。完整论证与可选校验建议见 §6.18 |

---

## 6. 风险清单与残留风险

> 格式：`风险 → 依据 → 本轮是否修复 → 若不修则由谁/何时兜底`。
> 前 6 条来自 `_m17_D_verdict.md` §3（须如实记录的已知偏差），后续为本文新增或收敛。

**覆盖对照表（供 `gate-design` 快速核验，verdict §3 的 6 条 + 门禁新增 4 条）**：

| 来源 | 风险 | 本文落点 |
|---|---|---|
| verdict §3-1 | counter(9) 统计竞争 | §6.7 + §5-2 |
| verdict §3-2 | `cache_drain_safe()` 重复排空 | §6.6 |
| verdict §3-3 | ipfw DPCPU hazard pointer 别名 | §6.3 + §5-3 |
| verdict §3-4 | NUMA 未编译（简化因素 + 前向约束） | §6.16 + §5-9 |
| verdict §3-5 | 各类 stub 线程不存在（1:1 不变式的前提） | §6.17 |
| verdict §3-6 | U6-a 未坐实 | §6.12（已降为观测项） |
| gate-design E8 | **netisr DPCPU 别名** | §6.15 |
| gate-design E9 | **`vtozoneslab()` 无判空**（既存） | §6.2 |
| gate-code §2.14-A | **`net.isr.dispatch` 必须保持 `direct`**（`curcpu` per-thread 化新引入的条件性风险） | §6.18 + §5-10 |
| gate-code §2.14-B | **`tcp_hpts` 实例数 1→N（记为 R6）** | §6.19 |
| **M3 运行时实测** | **`uma_page_slab_hash` 初始化时序（G1 打破既有隐含假设，`mp_maxid ≥ 2` 启动即SIGSEGV）** | §4.10 + **§6.22**（本轮**已修复**，是本表中唯一「已修复」项） |
| **物理机人工校验（2026-08-06）** | **wrk 压测下进程偶发 crash（非必现，需多次复现）** | **§6.23**（本轮不修，后续排查） |

### 6.1 慢路径无锁窗口放大（G2 的**主要**残留风险；**定级已按 `reviewer` G2-S1 下调**）

- **依据**【代码坐实】：f-stack 把 UMA 全部 `mtx` stub 成 `((void)0)`（§2.4），故 `zdom`/keg/bucket zones 的慢路径**今天就是无锁的**；且慢路径本来就在 `critical_enter/exit` **之外**（`uma_core.c:3859/3880/3882`、`:3916/3917`）。→ **G2 不移除慢路径的任何现有保护。**
- **但**：`uma_crit_lock` 事实上把快路径全局串行化，客观上**压缩了**两个 worker 同时进入慢路径的概率窗口。G2 之后该窗口会放大。
- **⬇ 定级下调（`reviewer` G2-S1 提供的两项减风险事实，本文原先未记录）**【代码坐实】：
  1. **f-stack 的 `uma_page` 哈希只增不删** —— 全树对该链表**无任何 `LIST_REMOVE`**（`lib/include/vm/uma_int.h` 内只有 `LIST_INSERT_HEAD`（`:125`）与 `LIST_FOREACH`（`:84`/`:97`/`:111`）；`grep LIST_REMOVE` 在 `lib/` 内的命中全部属`ff_kern_timeout.c` 的 callout 链，与本哈希无关）⟹ **节点一经发布永不释放** ⟹ **不存在 UAF**。
  2. **`le_prev` 无消费者** —— 既无 `LIST_REMOVE` 也无反向遍历 ⟹ `LIST_INSERT_HEAD` 写入的 `le_prev` 从不被读取 ⟹ 并发插入的**最坏故障收敛为「插入丢失」**（两个插入同时改 `lh_first`，后者覆盖前者 ⟹ 前一个节点从未进入链表），**而不是「破链后任意内存破坏」**。
  → 因此本条风险由原先的「**可能内存破坏**」**下调为「可能插入丢失 → 后续 `vtoslab()` 对该 va 返回 `NULL` → 调用者解引用 NULL 崩溃」**。仍然是崩溃级故障（fail-fast、可定位），但**不是**堆破坏/UAF 这类难以定位、可能静默扩散的故障。
- **⬇ 影响半径收敛（`reviewer` G2-S4）**【代码坐实】：G2 的行为改变**严格局限于 `freebsd/vm/uma_core.c` 这一个 TU** —— `critical_enter/exit` 宏只对 include `vm/uma_int.h` 的 TU 生效，而编译集合（248 TU）内仅 2 个文件 include 它，其中 `lib/ff_freebsd_init.c` 内 `critical_enter\|critical_exit` 命中数为 **0**（§2.4）。故 G2 的风险面**远小于「改了一个全局宏」给人的直觉**，也不存在跨 TU 的语义撕裂面。
- **本轮是否修复**：**否**（这是 G2 的代价，不是 G2 引入的缺陷）。
- **兜底**：M5 的 60s/400连接 soak（DoD-4）+ §4.7.5 的早期检测式（节点数比对，不必等崩溃）+ §4.7.4 的 L1/L2 台阶。**【未坐实】** 放大到什么程度，`_m17_A_codepath.md` 附录 A.2 已明确「静态分析无法定论，必须运行期数据」（U8-perf）。

### 6.2 `vsetzoneslab()` 的无锁哈希插入

- **依据**【代码坐实】：`lib/include/vm/uma_int.h:105-126` 每次新 slab 上线时 `malloc(sizeof(*up))` + `LIST_INSERT_HEAD(hash_list, up, list_entry)`（`:120-125`），**无任何锁**。哈希表 8192 桶（HEAD `lib/ff_freebsd_init.c:304-306`，修复后为 `:380-382`，见 §4.10）。
- **最坏故障已收敛为「插入丢失」，不是 UAF/堆破坏** —— 依据同 §6.1 的两项减风险事实（只增不删 + `le_prev` 无消费者）。后果链：插入丢失 → `vtoslab()`（`:77-88`）对该 va 走到 `:87 return (NULL)` → 调用者 `uma_core.c:4930` → `:4938 slab->us_domain` 解引用 NULL 而崩（**这正是 §4.7.4 判据 (a′) 的落点**）。
- **另有一个独立的既存缺陷（gate-design E9 指出，但须按 `reviewer` 必改-2 修正其可达性）**：`vtozoneslab()`（`:90-103`）未命中时 `up == NULL` 而 `:101-102` **无判空即解引用**（对比 `vtoslab()` `:87` 有 `return (NULL)`）。**但该函数在本build 中是死代码** —— 唯一调用者 `freebsd/kern/kern_malloc.c:943/1039/1136`，而 `kern_malloc.c` 不在 `lib/Makefile` SRCS（HEAD 内零命中、`lib/kern_malloc.o` 不存在）【代码坐实】。→ 该缺陷**当前不可触发**，仅在将来把 `kern_malloc.c` 纳入编译时才需处理。
- **本轮是否修复**：**否**（均为既存缺陷，与 G1 无关；G2 会放大插入竞态的窗口）。**不给 `vtozoneslab()` 补判空**：它当前不可达，补判空是纯噪声改动。
- **兜底**：§4.7.5 的早期检测式（首选）+ §4.7.4 台阶 L1（含 §4.7.6 的实施注意事项）。

### 6.3 ipfw DPCPU hazard pointer 已失效（U15 由「低」提为「中」）

- **依据**【代码坐实】：`ip_fw_dynamic.c:224-226` 使用 DPCPU，但 `dpcpu_init()` 全程无调用者、`dpcpu_off[]` 恒 0（`freebsd/sys/pcpu.h:113-114/121/128`）→ 所有 cpu 的 DPCPU 槽位**互相别名**，多 worker 共用一个 HP 槽位；叠加 `:228 DYNSTATE_CRITICAL_ENTER() = critical_enter()` 在该 TU 中是空操作（`systm.h:186#ifndef FSTACK`）→ HP 读侧毫无保护。
- **本轮是否修复**：**否**，候选 A 修不了。§4.3.2 的 `mp_ncpus = N` 只消除了 `dyn_hp_cache` 的**堆溢出**，不消除**别名**。
- **诚实边界**【未坐实】：`_m17_gate_plan.md` §8.7 记「ipfw 动态规则在本项目运行时是否真被启用」**未核验**。若未启用，`DYNSTATE_GET` 恒 NULL、该路径不活跃。
- **兜底**：登记为独立立项；M5 若启用 ipfw 动态规则须单独设计验证。

### 6.4 hpts 并发进入窗口（本文新增）

- **依据**【代码坐实】：`HPTS_TRYLOCK` = `mtx_trylock` → `lib/include/sys/mutex.h:74-76` 常量 1（永远"成功"）；`tcp_hpts.c:1599/:1608 if (hpts->p_hpts_active)` 是非原子守卫；`tcp_choose_hpts_to_run()`（`:1574-1587`）在 `0..rp_num_hptss-1` 里挑「最久未运行」的实例，两个 worker 可选中同一个。hpts 由每个 worker 的 `main_loop` 驱动（§0.4）。
- **本轮是否修复**：**否**。`mp_ncpus = N` 把「N 个 worker 必然挤在唯一实例」改善为「N 实例 + 概率性重合」，**方向是变好**。
- **兜底**【未坐实】：M5 建议打印 `tcp_pace.rp_num_hptss` 与各 `hpts->p_on_queue_cnt`；若观测到重合导致的异常，独立立项。

### 6.5 `curcpu` 改动新引入的 fail-fast 面（本文新增）

- **依据**：§4.5末段。`curcpu` 由字面量 0 变为 `pcpup->pc_cpuid` 后，`pcpup == NULL` 的线程求值 `curcpu` 即解引用 NULL。
- **本轮是否修复**：**刻意不兜底**（§5-1）。已核实所有栈线程都在最早期建立 `pcpup`（主线程 `ff_freebsd_init.c:293`，早于 `:299/:301`；worker `ff_stack_thread_init` 的第一个动作 `:187`）。
- **兜底**：文档化为不支持用法；M5 的 `helloworld` 不使用 `ff_pthread_create`（标准用法）。

### 6.6 `cache_drain_safe()` 只排空调用线程自己的 cache

- **依据**【代码坐实】：`uma_core.c:1497-1509 CPU_FOREACH(cpu) { sched_bind(curthread, cpu); cache_drain_safe_cpu(...); }`，而 `lib/ff_glue.c:1178sched_bind()` 是 stub，`cache_drain_safe_cpu()` 用 `&zone->uz_cpu[curcpu]`（`:1452`）。→ `mp_maxid > 0` 后该循环把**调用线程自己的 cache 重复排空 N 次**，其它线程 cache 不回收。
- **本轮是否修复**：**否**。**仅回收效率问题，无越界、无内存不安全。**
- **注**：`curcpu` per-thread 化**不改变**这一结论（仍然是「自己的 cache」）。

### 6.7 counter(9) 统计竞争 / 内存放大

- **统计竞争**：见 §5-2，本轮不修。
- **内存放大**【代码坐实】：`-DSMP` 使 `keg_ctor`（`uma_core.c:2546#ifndef SMP`）不再剥离 `UMA_ZONE_PCPU`，`keg_layout`（`:2472-2478`）`pages *= mp_maxid + 1` → 每个 PCPU zone 的 slab 变为 **N 页**。放大倍数由**运行期 N**（栈线程数）决定，**不是** `MAXCPU`（1024）。f-stack 内 counter 数量众多（每 zone 2 个 + 各协议栈统计），N=2~4 时放大 2~4 倍。
- **兜底**【未坐实】：M5 建议记录 RSS，与基线对比。

### 6.8 `MAXCPU = 1024` 的静态开销

- **依据**【实测】`_m17_C_buildprobe.md` §0.3/§2.7：`sizeof(cpuset_t)` 8 → **128** 字节；`freebsd/kern/subr_pcpu.c:76-77` 的 `dpcpu_off[MAXCPU]`/`cpuid_to_pcpu[MAXCPU]` 由 1 槽扩到 1024 槽（各 8 KB，**纯 BSS**）；`freebsd/net/netisr.c:243nws_array[MAXCPU]`、`:1432/1457/1486/1516 malloc(... * MAXCPU ...)`（sysctl 统计路径）。`sizeof(struct pcpu)` **不变**（4096）。
- **本轮是否修复**：不需要（非正确性问题）。
- **兜底**：§3.4 台阶 R-1（`lib/opt/opt_global.h` 内 `#define MAXCPU 64`），仅在 M5 显示不可接受时启用。

### 6.9 CK `lock` 前缀恢复的性能开销

- **依据**【代码坐实】`_m17_gate_plan.md` §8.3：`-DSMP` 使 `ck_md.h:95 #ifndef SMP → #define CK_MD_UMP` 失效，`gcc/x86_64/ck_pr.h:54-58` 的 `CK_PR_LOCK_PREFIX` 由空变回 `"lock "`。**唯一实质受影响的 TU 是 `ip_fw_dynamic.c`**（`ck_pr_inc_32/dec_32/or_32/xor_32`，`:155/157/290/376/378/982/984/1001`）；`ck_queue.h` 34 处、`net/if.c` 5 处全是 `ck_pr_load_ptr`/`ck_pr_store_ptr`/`ck_pr_fence_store`（**不受 `lock` 前缀影响**）；`ck_epoch` 已被 `lib/ff_glue.c:1358-1396` 整体 stub；`contrib/ck/src/*.c` 全未编译。
- **措辞纪律（必须遵守）**：应表述为「**消除潜在原子性缺陷**的正确性收益（成本为零、方向正确）」，**不得声称修复了某个已复现的 bug**（无实测复现证据）。同时记录：若将来放弃 per-worker vnet 隔离或引入共享 vnet 的 ipfw 使用，该缺陷会立即变成真实 bug。
- **兜底**【未坐实】开销未量化 → M5 吞吐对照兜底。

### 6.10 `-DSMP` 的非 spin 锁 / 非 CK 运行时语义

- `_m17_gate_plan.md` §8.7 记为**未核验**（例如 `cpuset_t` 8→128 对按值传参/结构体嵌入的影响）。本文按「`SRCS` 全量clean 重编、口径一致；`HOST_SRCS` 不含内核头」判断无跨 `.o` ABI 撕裂面，但该判断只覆盖编译期。**【未坐实】** → M5 兜底。
- 已收敛的两条：`smp_started` 无语义风险（编译集合内只有 `lib/ff_glue.c:210 active = smp_started;` 一个读者，sysctl handler；M1 引用的 `:219` 经本文以 HEAD 复核后校正为 `:210`）；spin锁层面语义中性（§3.1）。

### 6.11 SMR侧的既存风险（与 G2 无因果，须独立记录）

`_m17_B_external.md` §4.2 的威胁模型 T4/T5/T6，按本地代码逐条收敛：

| 威胁 | 结论 | 依据 |
|---|---|---|
| **T4** 读区间被拉长 → `rd_seq` 卡住 → 内存膨胀 | **成立且无法用槽位独占消除**，但是**性能/内存**问题非正确性问题 | 上游 `smr_default_advance()` 的 `SMR_SEQ_MAX_DELTA` 强制 `smr_wait()` |
| **T5** 长时间被调度出去导致序号 ABA | **既存风险，与 G2 无因果**：f-stack 全树 `critical_enter` 本就是 nop（`systm.h:186`），SMR 读/写侧从来没有临界区保护【代码坐实】。上游 `smr_poll_cpu()` 自带软兜底（`if (SMR_SEQ_LT(c_seq, s_rd_seq)) c_seq = s_rd_seq;`，注释说明该 race「only likely to happen on hypervisor or with a system management interrupt」，与用户态线程被 OS 调度出去同类）；该兜底只保证「不访问 stale 数据」，不消除 §2.2 的根本破坏 —— 而后者正由 G1 修复 | `_m17_B_external.md` §4.2(b-2) |
| **T6** `SMR_LAZY` 的 grace period 依赖「每 CPU 定期时钟中断」，用户态不成立 | **不适用，本文关闭**：f-stack 编译集合内唯一的 `smr_create()` 调用点是 `freebsd/vm/uma_core.c:3024 zone->uz_smr = smr_create(zone->uz_name, 0, 0);` —— **flags = 0，非 `SMR_LAZY`**【代码坐实】 | 本文实测 grep |

### 6.12 U6-a（EAL main lcore 是否为 `proc_lcore[0]`）

- **状态变更**：由「方案依赖项」降为**纯观测项**。因 §4.3.4 的取号方式（主线程用 `ff_cur_proc_id()`，即直接取 `lcore_conf[rte_lcore_id()].proc_id`）**不依赖**「EAL main lcore == `proc_lcore[0]`」这一推断，即使 `--main-lcore` 打破它也仍然正确。
- **本轮处置（leader 裁决，`gate-design` 必改 N1 方案 (b)）：本轮不核对 U6-a。** 实际落地的 `[M17-PROBE]` 探针只打印 7 个字段（§7.1），**不含 `rte_lcore_id()`/`rte_get_main_lcore()`**，故原先承诺的「四元组核对」**当前无法执行**；且 M5 已结束、探针即将摘除，不值得为此再改代码重测。**因 §4.3.4 的取号方式不依赖该推断，故不核对不影响正确性。**
- **仅作旁证的间接实测**【实测】：`lcore_mask=6` 时 `proc_lcore[0]=1`、`proc_lcore[1]=2`，实测**主线程取到 `dense_idx=0`**、worker 取到 `dense_idx=1`，日志中 `thread init success on lcore 1.` 与 `on lcore 2.` 均出现（`_m17_F_runtime.md` §1.2）。**这只是由 `dense_idx` 反推的旁证，不构成对 U6-a 的核对**，且只覆盖未使用 `--main-lcore` 的默认情形。**【未坐实】**
- **将来若要彻底闭合**：在探针增打 `rte_get_main_lcore()` 并跑一次 `--main-lcore` 取非默认值的用例即可；但这属于「加强验证」而非「修正缺陷」。

### 6.15 【本文新增，gate-design E8】netisr 的 DPCPU 别名

- **依据**【代码坐实】：`freebsd/net/netisr.c:236 DPCPU_DEFINE(struct netisr_workstream, nws);`，而 `dpcpu_init()`（`freebsd/kern/subr_pcpu.c:100`）在编译集合内**零调用者**、`dpcpu_off[]` 恒 0（同 §6.3的机理）→ **`DPCPU_PTR(nws)` 对每个线程都解析到同一份 `nws`**，N 个 worker 共享。
- **两个落点，严重性不同（须区分，不可一概而论）**：
  1. **`netisr.c:1147 nwsp = DPCPU_PTR(nws);`** —— 位于 `:1146 if (dispatch_policy == NETISR_DISPATCH_DIRECT)` 分支内，而 DIRECT **正是 f-stack 的实际生效路径**（§4.5 表第8 行已坐实）。该分支只做 `:1149 npwp->nw_dispatched++; :1150 npwp->nw_handled++;` 再 `:1151 np_handler(m)`。→ **纯统计计数竞争（非原子递增丢计数），非内存安全问题**，与 counter(9)（§6.7）同级。
  2. **`netisr.c:1174 nwsp = DPCPU_PTR(nws);`（`netisr_queue_src`）与 `:1044 DPCPU_ID_PTR(cpuid, nws)`（`netisr_queue_internal`）** —— 这条路径会操作**共享的 mbuf 队列**（`nws_work[proto]` 的 `nw_head`/`nw_tail`、`nws_pendingbits`），且 f-stack 的 `NWS_LOCK` 系亦为 stub（`lib/include/sys/mutex.h`）→ **不止统计，是共享链表的无锁并发操作**。**但**：该路径末端依赖 `swi_sched()`，而 `lib/ff_kern_intr.c:91-95 swi_sched()` 是**空 stub**（`:84-89 swi_add()`亦返回 0）→ 入队的包**从来不会被处理**。也就是说这条路径在 f-stack 下**本来就是功能死路**（既存缺陷，与本轮无关）。
- **候选 A 是否能修**：**不能**。`-DSMP` 只放开 `subr_pcpu.c:252` 的 `dpcpu_copy` 分支，**不会产生 `dpcpu_init()` 的调用者**，`dpcpu_off[]` 仍恒 0。与 §6.3 的 ipfw DPCPU 同因同源。
- **本轮是否修复**：**否**。落点 1 仅统计竞争，落点 2 是既存功能死路。二者都**不因 G1/G2 而变差**（`dpcpu_off[]` 在改动前后都恒 0）。
- **兜底**：与 §6.3 合并为「DPCPU 机制在 f-stack 下整体失效」独立立项；M5 若发现 netisr 统计异常或 `netisr_queue*` 路径被依赖，须单独设计。**【未坐实】** netisr_queue 路径在本项目运行时是否真被走到（`if_loop.c:357`、`ip_output.c:158/192`、`ip6_output.c:1045/1077` 等）未观测。

### 6.16 NUMA 未编译（verdict §3 已知偏差之一）

- **依据**【代码坐实】：`lib/ff_glue.c:83 int __read_mostly vm_ndomains = 1;`，且 `NUMA` 未定义（编译命令与 `lib/opt/opt_global.h` 均无）→ `uma_core.c` 全部 `#ifdef NUMA` 跨 domain bucket 路径未编译、`itemdomain` 恒 0、`uc_crossbucket` 永不装载（M1-A U8.4-4）。
- **本轮是否修复**：**不需要修，这是简化因素而非风险** —— 它使本轮只需处理「跨线程」、无需处理「跨 NUMA domain」，`ZDOM_GET(z,0)` 恒为唯一 domain。
- **残留**：若将来引入 NUMA，`uc_crossbucket` / `ZONE_CROSS_LOCK`（`uma_int.h:586-590`）会成为新的共享点，届时 G2 的无锁结论**须重新论证**。登记为前置条件而非缺陷。

### 6.17 各类 stub 线程不存在（verdict §3 已知偏差之一）

- **依据**【代码坐实】：`lib/ff_kern_intr.c:84-89 swi_add()` 返回 0、`:91-95 swi_sched()` 空、`:97-101 swi_remove()` 返回 0、`:103-107 intr_event_bind()` 返回 `EOPNOTSUPP`；`lib/ff_compat.c:162-177`（kproc/kthread 类 stub）；`lib/ff_dpdk_kni.c:93-97`；`lib/ff_glue.c:1178 sched_bind()` stub；f-stack 未注册任何 `rte_service`（M1-A U13.2）。
- **本轮是否修复**：**不需要修，这是 G1「线程↔槽位 1:1 且永不迁移」不变式成立的前提**（没有内核线程/软中断线程会在栈线程之外碰 per-cpu 结构）。
- **残留风险（须显式登记）**：该不变式是**当前**代码形态的产物，不是被强制的约束。若将来引入真实的 taskqueue/swi 线程而不为其建立 pcpu 槽位，它们会以 `pcpup == NULL` 崩溃（同 §6.5）或复用别人的槽位。**建议在 §5-1 的「不支持用法」文档化之外，M6 时考虑在 `ff_pcpu_thread_init()` 附近加一句注释说明该不变式**（≤2 行，属必要注释）。

### 6.18 【`curcpu` per-thread 化新引入】`net.isr.dispatch` 必须保持 `direct`

来源：`reviewer` 的 G1 代码门禁 `_m17_gate_code_g1.md` §2.14-A。**这不是越界问题，是语义变化**，与 §4.5 表格第 7/8 行「不越界、默认不可达」的结论**不矛盾**：那两行论证的是**默认配置下**不可达，本条论证的是**改配置后**可达且行为变坏。

- **默认路径不受影响**【代码坐实】：`freebsd/net/netisr.c:151 #define NETISR_DISPATCH_POLICY_DEFAULT NETISR_DISPATCH_DIRECT`、`:153 static u_int netisr_dispatch_policy = NETISR_DISPATCH_POLICY_DEFAULT;`、`netisr_get_dispatch()`（`:781-790`）、`:1146-1153` 的 DIRECT 分支无条件直发并 `goto out_unlock` → `:839` 与 `:1172` 的 `curcpu` **不可达**。
- **但该策略是可调 sysctl**【代码坐实】：`netisr.c:155-158 SYSCTL_PROC(_net_isr, OID_AUTO, dispatch, CTLTYPE_STRING | CTLFLAG_RWTUN | CTLFLAG_NEEDGIANT, 0, 0, sysctl_netisr_dispatch_policy, "A", ...)` —— `RWTUN` 意味着**运行期可写、也可由 tunable 预置**，f-stack 可经 `config.ini` 的 `[freebsd.sysctl]` 设置。
- **改为 `hybrid`（或 `deferred`）后的行为变化**【代码坐实】：`netisr_select_cpuid()`在 `nws_count == 1` 时走 `:810-812 *cpuidp = nws_array[0]; return (m);`，而 `nws_array[0]` 是 `netisr_start_swi()` 启动 workstream 时那个线程（主线程/boot）的 cpuid，**通常为 0**；随后 `:1172 if (cpuid != curcpu) goto queue_fallback;`：
  - **改动前**：`curcpu ≡ 0 == nws_array[0]` → 恒相等 → 仍然直发，**永不入队**。
  - **改动后**：worker 的 `curcpu = i ≠ 0` → 条件成立 → `goto queue_fallback` → `netisr_queue_internal()` 入队 + `swi_sched()`，而 `lib/ff_kern_intr.c:91-95 swi_sched()` 是**空 stub**（`:84-89 swi_add()` 返回 0）→ **报文进队后无人处理 = 静默丢包**。
- **本轮是否修复**：**否（列为不支持的配置）**，见 §5-10。**可选增强（本轮不做，登记为建议）**：在 `lib/ff_config.c` 的 sysctl 处理处加一条校验，若 `[freebsd.sysctl]` 中把 `net.isr.dispatch` 设为非 `direct` 且 `thread_mode=1 && nb_threads>1` 则拒绝启动或告警。是否实施由 leader 裁决；**若不实施，则必须依赖文档约束**。
- **兜底**：§7.4 的 DoD-4 要求 `config.ini` 的 `[freebsd.sysctl]` 段**不得**出现 `net.isr.dispatch`（默认即`direct`）；M5 建议顺手 `sysctl net.isr.dispatch` 打印确认为 `direct`。**【未坐实】** 未实测`hybrid` 下的丢包（不必实测：这是被排除的配置）。

### 6.19 【`mp_ncpus = N` 的代价，记为 R6】`tcp_hpts` 实例数 1 → N

来源：`_m17_gate_code_g1.md` §2.14-B。这是 §4.3.2 裁决（`mp_ncpus` 抬到 N）的**直接代价**，须与收益一并记录。建议与 native-mt 已有的并发风险清单 **R1~R5 并列记为 R6**，供 CM6/CM7 缩小 Giant 范围时逐条评估。

- **实例数与内存**【代码坐实】：`freebsd/netinet/tcp_hpts.c:1864 uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;` → `:1872 tcp_pace.rp_num_hptss = ncpus;`；`:1920 asz = sizeof(struct hptsh) * NUM_OF_HPTSI_SLOTS;`（`:169 #define NUM_OF_HPTSI_SLOTS 102400`，`:243-247 struct hptsh { TAILQ_HEAD(, tcpcb) head; uint32_t count; uint32_t gencnt; }`）；`:1921-1924` 对每个 `i` 各 `malloc(sizeof(struct tcp_hpts_entry))` + `malloc(asz)`。`FF_TCPHPTS=1` 是**默认开**（`lib/Makefile` HEAD `:51`，`:161 CFLAGS+= -DTCPHPTS -DRATELIMIT`）。
  → **单实例 `asz` 约 `24 B × 102400 ≈ 2.34 MiB`**（`sizeof(struct hptsh)` = 16(TAILQ_HEAD) + 4 + 4 = 24 字节，**此字节数为结构布局推导，须 M5 以 RSS 实测确认**【未坐实（推导）】）。`mp_ncpus` 由 1 抬到 N ⇒ **约 +2.34 MiB × (N−1)**（N=4 时约 +7 MiB）。
- **语义错配（本条的核心，非内存）**【代码坐实】：`tcp_hpts_init()` 在 `mi_startup()` 期由**主线程**执行 → `:1999 callout_init(&hpts->co, 1)` 与 `:2047-2049 callout_reset_sbt_on(&hpts->co, sb, 0, hpts_timeout_swi, hpts, hpts->p_cpu, ...)`（`:2010 hpts->p_cpu = i`）对**全部 N 个实例**都在主线程上执行，而 `lib/ff_kern_timeout.c:184 CC_CPU(cpu)` **忽略实参**恒取本线程的 `__thread cc_cpu` → **N 个实例的 callout 全部挂在主线程的 callwheel 上**；而 `__tcp_run_hpts()` 经 `:1587 rp_ent[curcpu % rp_num_hptss]` 由**各 worker** 选取**不同** entry（`curcpu` per-thread 化后才真正分散）→ 形成「**worker 驱动的 hpts entry，其超时 callout 归主线程 callwheel**」的错配。
- **互斥缺失**【代码坐实】：`:1931-1932 mtx_init(&hpts->p_mtx, "tcp_hpts_lck", "hpts", MTX_DEF | MTX_DUPOK)`，而 f-stack 全部 `mtx` 已塌缩为 `((void)0)`、`HPTS_TRYLOCK`（`:218`）= `mtx_trylock` 被 `lib/include/sys/mutex.h:74-76` 定义为**常量 1** → **无实际互斥**；当前 CM5-B靠 `mtx_lock(&Giant)` 把 worker proc 建立串行化来掩盖。**若 CM6/CM7 缩小/移除 Giant 范围，此处必须先加真锁或改设计。**
- **与 §6.4 的关系**：§6.4 记的是「两个 worker 可能选中同一 hpts 实例」（`tcp_choose_hpts_to_run()` 挑最久未运行）；本条记的是「实例数变多带来的内存 + callout 归属错配 + 无互斥」。二者同源不同面，**都不在本轮修复范围**。
- **本轮是否修复**：**否**。`mp_ncpus = N` 相对 `mp_ncpus = 1` 在正确性上是**改善**（消除 §4.3.1-D2 的 ipfw 堆溢出、把 N 个 worker 从「必然挤在唯一实例」变为「分散到 N 个实例」），代价是本条列出的内存与错配。
- **兜底**：§7 要求 M5 **量化 N 个 hpts 的内存增量**（`thread_mode=1` 下 1/2/4 线程的 RSS 对照）；并作为 R6 登记进 native-mt 并发风险清单，CM6/CM7 缩锁时强制复查。

### 6.20 其余未坐实项（原样继承，不得当作已证事实）

| 编号 | 内容 | 兜底 |
|---|---|---|
| **U5-a** | `netisr_start`（`SYSINIT... SI_SUB_SMP`，`netisr.c:1365`）确实在 worker 建 pcpu 之前跑完，属静态时序推断 | M5 打印 `nws_count` 与 `cpuhead` 长度。**注**：因 `swi_add()` 是空 stub（`lib/ff_kern_intr.c:84-89`），即使推断有误影响也趋近 0 |
| **U12-ish** | `freebsd/kern/subr_taskqueue.c:368 callout_reset_sbt_curcpu()` 在 f-stack 下是否真被走到（其`cpu` = `PCPU_GET(cpuid)`，稠密后为 `0..N-1`） | `MAXCPU=1024 ≥ N` 后即使走到也不 panic；M5 观察是否触发 `ff_kern_timeout.c:730` |
| **U2（已关闭）** | 「`UMA_ZONE_PCPU` zone 是否真按 `(mp_maxid+1)` 页分配」原为**未坐实**（只能由「SMR槽距 4096」间接推断，无法排除越界访问相邻内存）| **已由 M3 第三轮 `[M17-PROBE-ZONE]` 探针运行时坐实**：4 线程档实测 `pcpu_zone_8`/`pcpu_zone_64` 均 `uk_ppera=4 == mp_maxid+1`【实测】。见 §7.1 判定式 ⑨。**残留仅为并发问题（= §6.2），非尺寸问题** |
| **候选 B 无编译数字** | §3.3 | 若走 R-2 台阶须先补编译实证 |

### 6.21 流程风险（撰写期实际观测到，需 leader 处置）

**【实测】** 本文撰写期间`lib/` 已被 M3 `coder` 改动（§0.2）。风险两条：

1. **M2 未过门禁即已开始 M3 编码**，若本文的设计（尤其 §4.5 的 `curcpu`）与在写代码不一致，会产生返工。本文撰写期实际比对了该 in-progress diff：其方向与 D1~D7 基本一致，**但未包含 §4.5 的 `curcpu` 改动** → 若照其现状落地，DoD-1 的 UMA 侧判定必然失败，且 G2 会重新引入 `b90ddcba5` 修掉的崩溃。已即时向 leader 报告。**（后续已闭环：`coder` 第二轮落地了 `curcpu`；第三轮又在运行时发现并修复了 §4.10 的时序缺陷 —— 这说明「M3 与 M2 并行」既带来返工风险，也确实提前暴露了静态分析看不见的问题。本文对此如实两面记录，不作单向结论。）**
2. **事实基线漂移**：`lib/ff_dpdk_if.c` 工作区行号已比 HEAD 偏移 +6。`gate-design` 复核本文 `file:line` 时**必须以 HEAD `ff09a17b2` 为准**（例如 `git show HEAD:lib/ff_dpdk_if.c | grep -n ...`），否则会误判为事实错误。**同类问题已在 M1 文档中实际发生（记为纠正 C4）**：M1撰写时工作区带着 res-build 的探针改动，导致 4 处引用与 HEAD 不符—— `lib/ff_glue.c` 的 `active = smp_started;` 实为 **`:210`**（M1 记 `:219`）、`sched_bind()` 实为 **`:1178`**（M1 记 `:1187`）、`ck_epoch` stub 块实为 **`:1358-1396`**（M1/gate 记 `:1366-1404`）、`ip_fw_dynamic.c` 在 `lib/Makefile` 实为 **`:601`**（gate 记 `:604`）；本文已全部按 HEAD 校正。其余经逐条抽查的引用（`freebsd/vm/uma_core.c` `:1452/1497/1725/1822/2472/2474/2546/3024/3179/3181`、`uma_int.h` `:280-281/529/540/566/582/584`、`subr_smr.c` `:583/591/598/605/623`、`smr.h:110`、`smp.h:197/199`、`tcp_hpts.c:217-218/1089`、`ip_fw_dynamic.c:224/228/3236`、`pcpu_aux.h:47`、`in_pcb.c:583/615`、`lib/ff_freebsd_init.c`、`lib/ff_kern_timeout.c`、`lib/include/sys/mutex.h:57/85`、`lib/ff_glue.c:83`、`lib/Makefile:44/346/347/650`）**核对无误**。

### 6.22 【G1 暴露的既有缺陷，本轮已修复】`uma_page_slab_hash` 的初始化时序假设

这是 **§6 中唯一「本轮已修复」的条目**，其余条目均为「不修复 + 兜底」。**证据强度是运行时实测**（本文最硬的一条），机理与改法见 §4.10。

- **缺陷本身**：f-stack 原先隐含假设「`uma_page_slab_hash` 可以晚于 `uma_startup1()`初始化」（HEAD `lib/ff_freebsd_init.c:304-306` 在 `:301` 之后）。该假设**只在 `mp_maxid == 0` 时成立**，属**既有缺陷**而非 G1 引入的错误 —— G1 只是把它从「不可触发」变成「必然触发」。
- **症状**【实测】：`thread_mode=1` 的 **3/4 线程档 100% 启动即SIGSEGV**，崩在 `uma_startup1() → zone_alloc_item() → zone_import()`；**主线程内、worker 尚未启动**，与 virtio/RSS 无关；**1/2 线程档不复现**。
- **修复**：初始化整体提前到 `uma_startup1()` 之前（§4.10.3），已并入 commit-1（§8.2）。
- **残留**【未坐实】：
  1. 「`mp_maxid ≥ 2` 必崩、`≤ 1` 不崩」是**实测阈值**，本文**刻意不给算术推导**（§4.10.2 的诚实边界）。若将来 `struct uma_cache`/`struct uma_zone` 尺寸或`UMA_MIN_EFF` 变化，阈值会漂移，但**修复后与阈值无关**（hash 恒早于 UMA 启动）。
  2. 同类隐含假设是否还有第三处（即「还有哪些 f-stack 自有全局量被上游代码在 `uma_startup1()` 期间使用、却在其后才初始化」）**未做穷举**。建议 M6 补一次针对性排查：以 `lib/ff_freebsd_init.c` 中 `uma_startup1()` **之后**的全局量初始化为清单，逐个反查是否被 `uma_core.c`/`subr_smr.c` 在启动期引用。
  3. `:381` 的分配尺寸误用 `sizeof(struct uma_page)`（应为 `struct uma_page_head`）导致约 4 倍超额分配 —— **既存、良性、本轮不改**（§4.10.3 末段）。

### 6.23 【物理机人工校验新增】wrk 压测下进程偶发 crash

- **来源**：物理机人工校验（2026-08-06），功能验证与性能测试整体通过后，多次 wrk 压测中**偶发**进程异常 crash 退出。
- **现象**：**非必现**——需多次压测才可能复现一次；复现时进程直接 crash 退出（非 hang、非 socket error 退化为 0 吞吐）。
- **本轮处置**：**不修**。功能验证正常、性能测试正常（见 §7 各表），偶发 crash 不影响上述结论；根因未定位，需后续专项排查（多次复现 → 抓崩溃栈 → 定位）。
- **已排除**（物理机校验范围内）：非 G1/G2 改动引入的确定性回归（1/2/3/4 线程 + `thread_mode=0` 各档功能与吞吐均通过，见 §7.4/§7.5）。
- **待排查方向**（后续）：与 §6.1（慢路径无锁窗口放大）、§6.3（ipfw DPCPU 别名）、§6.19（tcp_hpts 实例数 1→N callout 归属错配 R6）等既存残留风险是否存在因果关联，需运行时崩溃栈坐实；亦不排除客户端侧或宿主虚拟化层瞬时干扰（本机校验曾观测到 1 小时内 2.6%~3.2% 的环境漂移，见 `_m17_F_runtime.md` Z7.2）。
- **定级**：中（非阻断产品发布，但生产部署前应排查收敛）。

---

## 7. 验证方案（对齐 DoD-1 ~ DoD-8）

> 本节写到「M5 `tester` 可直接执行」的粒度。运行环境沿用 plan §5：本机双网卡，DPDK 独占网卡 IP `<DPDK_NIC_IP>`（压测须 `ssh f-stack-client` 后用 `/data/wrk/wrk` 打该 IP），内核栈用 `127.0.0.1`；被测程序 `example/helloworld`，配置 `config.ini`。
> 沿用踩坑经验：必须 `setsid nohup ... < /dev/null &` 完全脱离；secondary 进程用绝对路径；读日志先记旧行数再 `tail -n +N`；core dump 被禁用，抓崩溃用 `setsid gdb -q -x <cmdfile>` 在负载下捕获。

### 7.1 DoD-1：per-cpu 槽位真正隔离（**最重要，判定式必须可机械执行**）

> **实测进度快照（数据源 `_m17_F_runtime.md`「第二部分：崩溃修复后的复测」，被测二进制 md5 `751a8153d3b200229cff99b3fa7650b0` = **G2 去锁前**）**
>
> | 档位 | 判定式 ①②③④⑦ | ⑤ UMA cache 槽距 | ⑥ SMR 槽距 | ⑨ `uk_ppera` | 结论 |
> |---|---|---|---|---|---|
> | `thread_mode=1` **2 线程** | **已实测 PASS**：`dense_idx=0/1`、`pc_cpuid=0/1`、`curcpu=0/1`、`pc_zpcpu_offset=0/4096`、`mp_ncpus=2`、`mp_maxid=1` | **已实测 = 128** | **已实测 = 4096** | 待补（应 == 2） | **PASS** |
> | `thread_mode=1` **3 线程** | **已实测 PASS**（**原崩溃档**，§4.10 修复后回归通过） | **已实测 = 128** | **已实测 = 4096** | **已实测 = 3（== mp_maxid+1）** | **PASS** |
> | `thread_mode=1` **4 线程** | **已实测 PASS** | **已实测 = 128** | **已实测 = 4096** | **已实测 = 4（== mp_maxid+1）** | **PASS** |
> | `thread_mode=0` 1 进程 | **已实测 PASS**（判定式 ⑧：`dense_idx=0`、`pc_cpuid=0`、`pc_zpcpu_offset=0`、`curcpu=0`、`mp_ncpus=1`、`mp_maxid=0`） | — | — | — | **PASS**（吞吐见§7.4） |
> | `thread_mode=0` 2 进程 | **已实测 PASS**（判定式 ⑧；**secondary 进程亦为 `dense_idx=0`**，C2 的门控由此实证生效） | — | — | — | **PASS**（吞吐见 §7.4） |
>
> ⇒ **DoD-1 已在 `thread_mode=1` 的 2/3/4 线程全档 + `thread_mode=0` 两档 PASS**；SMR侧（`zpcpu_get()` → 公差 4096）与 UMA cache 侧（`uz_cpu[curcpu]` → 公差 128）**双路径同时实证隔离**。**【实测】**
>
> **⚠ 两条限定，不得省略**：
> **(1) 本快照数据均为「G2 去锁前」**（`uma_crit_lock` 仍在）。**去锁后的槽位隔离复验已于 M5 第三部分完成（`_m17_F_runtime.md` X1：2/3/4 线程三档 + `thread_mode=0` 退化档全部 PASS）** —— 去锁后「每线程独占槽位」是**唯一**保护，其有效性已实测。**【实测】**（复验无需重编：`helloworld_g2_nolock` 的三条探针格式串完好，见 `_m17_F_runtime.md` X1。）
> **(2) ⑤/⑥ 仍是跨线程绝对地址相减的结果**，证明力依赖下文 ⚠ 块的「基址一致性」前提。**不过**：公差在 **2/3/4 三个线程档**上同时成立、每档 2~4 个数据点构成**精确等差数列**（4096 / 128）；若各线程实际取自**不同**的 `ipi_smr`/`ipi_zone` 对象，如此整齐的等差序列在多档位同时出现的概率可忽略 ⇒ **「同一对象」的推断强度已显著提高，但仍非直接证明**。> 故建议在去锁后复测时**顺手增打基址**（成本 1 行，见下 ⚠ 方案 (a)），一次性闭合该缺口。**本轮未做该增打**，故该缺口**保留为未闭合项**。**【未坐实】**

> **与 `coder` 已实现探针的对齐说明（M3 第三轮，`_m17_E_coder_g1.md` §6）**：本节的字段/判定式是**规范形式**；实际落地的探针共 **4 处**（P1 = `ff_pcpu_thread_init()` 末尾打印 `[M17-PROBE]` 标量行；P2 = 新增 `static void ff_probe_slots(int dense_idx)` 打印 `[M17-PROBE-SLOT]` 槽位行；P3 = `ff_stack_thread_init()` 末尾 worker 调 `ff_probe_slots(cpuid)`；P4 = `ff_freebsd_init()` 末尾主线程调 `ff_probe_slots(PCPU_GET(cpuid))`），输出格式为：
>
> ```
> [M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
> [M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
> [M17-PROBE-ZONE] name=%s uk_ppera=%u uk_rsize=%u mp_maxid=%u
> ```
>
> 第三类 `[M17-PROBE-ZONE]`（**P5**，`lib/ff_freebsd_init.c:160`）是 M3 第三轮新增的，用于坐实 U2（见判定式 ⑨）。
>
> **日志落点（实测，两个文件都要看）**：主线程的 P1+P4 在 **`example/f-stack-0.log`**；worker 的 P1+P3 在 **`example/helloworld.log`**。两者都是追加写入，读新增内容须先记旧行数再 `tail -n +N`。
> **`tid` 取的是 `pthread_self()` 句柄，不是 OS tid**，仅用于区分线程，勿与 `ps -T` 的 LWP 对照。

**探针位置（规范形式为两类：标量 + 槽位地址；实际实现为上述 4 处）**：

- **P1** —— `lib/ff_freebsd_init.c`的 `ff_pcpu_thread_init()` 末尾（`PCPU_SET(prvspace, pcpup)` 之后）。
- **P2** —— `lib/ff_stack_thread_init()` 的 `lo_set_defaultaddr()` 之后、`__sync_lock_release(&init_lock)` 之前（此时 `curthread->td_vnet` 已由 `:210` 设好，`V_*` 可解析）；主线程对应位置为 `ff_freebsd_init()` 内`:342lo_set_defaultaddr()` 之后。

**P1 实际打印的字段（**7 个**，与落地探针格式串逐字一致；本文按 `gate-design` 必改 N1 修正 —— 原先写「9 个」并含 `rte_lcore_id()`/`rte_get_main_lcore()`，**实际探针并未打印这两项**）**：

| 字段 | 取法 |
|---|---|
| `tid` | `pthread_self()` 返回值（**pthread 句柄，不是 OS tid**，仅用于区分线程） |
| `dense_idx` | `ff_pcpu_thread_init()` 的形参 `cpuid` |
| `pcpup->pc_cpuid` | 直接读 |
| `pcpup->pc_zpcpu_offset` | 直接读 |
| `curcpu` | 直接求值（**验证 §4.5**） |
| `mp_maxid` / `mp_ncpus` | 直接读（**共 7 字段**：`tid`/`dense_idx`/`pc_cpuid`/`pc_zpcpu_offset`/`mp_ncpus`/`mp_maxid`/`curcpu`） |
| ~~`MAXCPU`~~ | **实际探针未打印**。`MAXCPU` 为编译期常量，改由 §7.3 的 clean build 与 `-dM -E` 实测核对（`_m17_C_buildprobe.md` §0.3），不依赖运行期探针 |

**P2 必须打印的字段（3 个）**：

| 字段 | 取法 | 用途 |
|---|---|---|
| **UMA cache 槽位地址** | 规范形式建议用**全局（非 VNET）** zone，例如 `&((uma_zone_t)zone_mbuf)->uz_cpu[curcpu]`（`freebsd/kern/kern_mbuf.c`，`lib/Makefile` HEAD `:346` 已编译）→ 跨线程地址**必定**可直接比较。**实际实现用的是 `&V_tcbinfo.ipi_zone->uz_cpu[curcpu]`**，见下方 ⚠ | UMA cache 隔离性 |
| **SMR 槽位地址+ 其基址** | 实际实现打印 `zpcpu_get(V_tcbinfo.ipi_smr)`。**必须additionally 打印基址 `V_tcbinfo.ipi_smr` 与 `V_tcbinfo.ipi_zone` 本身**，见下方 ⚠ | SMR 槽位隔离性 |
| `sizeof(struct uma_cache)` | 打印实际值。`coder` 已用 `nm --print-size` 实测为 **128 字节（0x80）**（`freebsd/vm/uma_int.h:280-281` 的注释说「pads perfectly into 64 bytes」是**上游注释，与本地实测不符**，以实测 128 为准） | 判定式 ⑤ 的乘数 |

> **⚠ 判定式可靠性修正（本文新增，M5 必须照做，否则 ⑤/⑥ 的证明力不成立）**
>
> 实际探针用 `V_tcbinfo.ipi_smr` / `V_tcbinfo.ipi_zone` 取槽位，而 **`V_tcbinfo` 是 per-vnet 的**：`freebsd/netinet/tcp_var.h:1308 VNET_DECLARE(struct inpcbinfo, tcbinfo);` + `:1315 #define V_tcbinfo VNET(tcbinfo)`，且 **`VIMAGE` 确实已定义**（`lib/opt/opt_global.h:6 #define VIMAGE 1`）→ `freebsd/net/vnet.h:305 #define VNET(n) VNET_VNET(curvnet, n)`【代码坐实】。而 native-mt 下**主线程用 vnet0、每个 worker 用自己的 `vnet_i`**。
>
> ⇒ **主线程与 worker 打印的 `smr_c_seq`/`uma_cache` 可能来自不同的 `ipi_smr`/`ipi_zone` 对象**，此时「两线程地址之差 == 4096×Δidx / 128×Δidx」这种**跨线程绝对地址相减**的判定式**在数学上不成立**（差值里混入了两个不同对象的基址差）。`coder` 冒烟运行中 `0x1000` 与 `0x80` 两个差值都恰好精确，**强烈提示两次读到的其实是同一个 `V_tcbinfo`**（否则两个精确值同时出现的概率极低），但这**只是推断，未坐实**【未坐实】。
>
> **因此 M5 必须（二者取一，推荐 a）**：
> **(a)** 让探针**增打基址**：`[M17-PROBE-SLOT] ... smr_base=%p zone_base=%p`（2 个`%p`，1 行改动）。然后：
> - 若各线程 `smr_base`/`zone_base` **完全相同** → 说明确为同一对象，原判定式 ⑤/⑥（绝对地址相减）**有效**，直接沿用；
> - 若**不同** → 原判定式作废，改用**偏移形式**（对每个线程独立成立，不跨对象）：`(char *)smr_c_seq - (char *)smr_base == 4096 * dense_idx`，且 `(char *)uma_cache - (char *)&zone_base->uz_cpu[0] == 128 * dense_idx`。
>
> **(b)** 或把探针改成规范形式（用全局 zone `zone_mbuf` +偏移形式的 SMR 判定），代价是要改探针取值路径。
>
> 无论 (a) 还是 (b)，**都不得在未确认基址一致性的前提下，把 `coder` 冒烟运行的 `0x1000`/`0x80` 当作 DoD-1 已通过的证据**。

**判定式（全部必须成立，逐条可机械核对）**：

| # | 判定式 | 失败含义 |
|---|---|---|
| ① |每线程 `pcpup->pc_cpuid == dense_idx` 且 `dense_idx <= mp_maxid` 且 `dense_idx >= 0` | 稠密取号未生效 |
| ② | 每线程 `pcpup->pc_zpcpu_offset == 4096 * dense_idx` | `zpcpu_offset_cpu()` 展开异常 |
| ③ | 各线程 `dense_idx` **两两不同**，且集合 == `{0, 1, …, N-1}`（N = `nb_threads`） | 撞车或漏号 |
| ④ |每线程 `curcpu == dense_idx` | **§4.5 未落地**（这是最容易被漏掉的一条） |
| ⑤ | 各线程 UMA cache 槽位地址**两两不同**；且在**基址一致**（见上 ⚠）时地址差 == `128 * Δdense_idx`，基址不一致时改判 `uma_cache - &zone_base->uz_cpu[0] == 128 * dense_idx` | UMA cache 仍共享（**此条不通过则 G2 绝不可放行**，§4.7 硬前置） |
| ⑥ | 各线程 SMR 槽位地址**两两不同**；且在**基址一致**时地址差 == `4096 * Δdense_idx`，基址不一致时改判 `smr_c_seq - smr_base == 4096 * dense_idx`；无论哪种，该偏移必须 < `(mp_maxid + 1) * 4096` | SMR 槽位仍共享或越界 |
| ⑦ | `mp_ncpus == N` 且 `mp_maxid == N - 1`（**由探针实测**）；`MAXCPU == 1024`（或 R-1 台阶下 64）**由编译期 `-dM -E` 核对，不经探针** | 三元组设置错误 |
| ⑧ | `thread_mode=0` 下：`N==1`、`dense_idx==0`、`pc_zpcpu_offset==0`、`curcpu==0`、`mp_ncpus==1`、`mp_maxid==0`（**1 进程与 2 进程都要跑，secondary 进程也必须打印 `dense_idx==0`**） | D7 零回归被破坏（**C2 就是这里暴露**） |

**⑨ 补充判定式（U2）—— 已由 M3 第三轮探针首次坐实【实测】**：判定式 ⑥ 只证明「相邻线程 SMR槽距 4096」，**并不能**证明该 `UMA_ZONE_PCPU` zone 真的分配了 `(mp_maxid+1) × 4096` 字节—— 若 zone 只分配 1 页，`dense_idx ≥ 1` 的槽位就是**越界访问到相邻内存**，短时冒烟不一定立刻崩。为此新增第三类探针 `[M17-PROBE-ZONE]`（`lib/ff_freebsd_init.c:160`），直接打印 keg 的 `uk_ppera`/`uk_rsize`：

```
[M17-PROBE-ZONE] name=pcpu_zone_8  uk_ppera=4 uk_rsize=8  mp_maxid=3
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=4 uk_rsize=64 mp_maxid=3
```

**判定式**：对每个 `UMA_ZONE_PCPU` zone，`uk_ppera == mp_maxid + 1`。**已在 3 线程档（`uk_ppera=3, mp_maxid=2`）与 4 线程档（`uk_ppera=4, mp_maxid=3`）双档实测通过 → U2 已坐实：`UMA_ZONE_PCPU` zone 确实按 `(mp_maxid+1)` 页分配，`dense_idx ≥ 1` 的槽位是合法内存而非越界。**【实测】此前该结论只能由「SMR 槽距 4096」间接推断、无法排除越界访问相邻内存，现已由运行时实证闭合。

**仍需覆盖的档位**：上述实测取自 4 线程档；2 线程档应同样满足 `uk_ppera == 2`，**待复测确认**。

**取证**：日志从 **`example/f-stack-0.log`（主线程）**与 **`example/helloworld.log`（worker）** 两个文件同时提取（缺一会漏掉主线程的探针行），原始输出**逐字**落盘到 `_m17_F_runtime.md`；同时 `grep -iE "panic|segmentation|out of range"` 必须无命中。

### 7.2 DoD-2：`uma_crit_lock` 移除 —— **已完成，PASS**

- 判定：`grep -rn "uma_crit_lock" lib/ freebsd/` 零命中；且 `lib/include/vm/uma_int.h` 的 `critical_enter/exit` 为 `do {} while(0)`。
- **实测：`grep -rn "uma_crit_lock" lib/ freebsd/` 零命中，`critical_enter/exit` 已为 `do {} while(0)`（`reviewer2` 复核时全树0 命中）→ DoD-2 PASS。**【实测】
- **运行时侧确认（`_m17_F_runtime.md` X4.2）**：去锁后二进制 `helloworld_g2_nolock` 中 `uma_crit_lock` 符号 `grep -c` = **0**，而去锁前副本 = **1** → 该锁**确已从二进制中移除**，不是「代码改了但没编进去」；去锁后在 **1/2/3/4 线程 + `thread_mode=0` 1/2 进程共 6 档 + 2 个 60s soak（合计约 6,000 万请求）**下零崩溃、零 socket error、日志零新增字节。**【实测】**
- 若最终走 §4.7.4 的 L2 台阶（不可移除），则必须给出**代码级依据**并由 `reviewer` 门禁确认（DoD-2 原文允许）。**→ 本轮未触发 L2，G2 已按 L0（G2-b）落地。**

### 7.3 DoD-3：clean build —— **已完成，PASS**

- **实测结论：`error 0` / `warning 51`（= HEAD `ff09a17b2` 基线，零新增），由 `reviewer` 独立复现。**【实测】提交后再次 `make clean && make`（`lib` + `example`）rc **0/0**，`example/helloworld` md5 `df05d2cd078d631ad2d8ee7caba8d387`（30,392,632 B）与提交前审过的二进制**逐字节一致**。**【他人实测（leader/reviewer），designer 未旁证】**
- `lib/` 与 `example/` 均**先 `make clean` 再完整编译**（强制规约），零 error。
- **warning 基线 = 未改动 HEAD `ff09a17b2` 的 `lib/`+`example/` clean build warning 条数**。M1-C 已【实测】`lib/` 基线为 **51 条**（且该数字是在**未带 `-DSMP` 探针**的 pristine 配置下测得，`_m17_C_buildprobe.md` §1）。改动后 `grep -c "warning:"` **不得增加**。
- 参考数据【实测】：M1-C 的候选 A 实验（`-DSMP` + `smp_topo` stub）同样是 `error 0` / `warning 51`。本轮 G1 相对该实验多出 `curcpu`、`mp_*` 三元组、`timeout_cpu`、`ff_cur_proc_id()` 四组改动，**其 warning 影响已由 M3/M6 复测确认仍为 51条**（见本节首条）。

### 7.4 DoD-4：运行矩阵零崩溃 + 零回归

| 场景 | 命令 | 判定 | 基线 / 本轮结果（**均为 G2 去锁前；去锁后数据统一见 §7.5**） |
|---|---|---|---|
| `thread_mode=1` 1 线程 | `wrk -t5 -c100 -d10s`，≥3 轮 | 零崩溃、零 socket error | 209,483 / 209,739 |
| `thread_mode=1` 2 线程 | 同上 | 同上 | 233,380 / 234,084 / 230,510 |
| `thread_mode=1` **3 线程** | 同上（**须加轮次，见下方稳定性提醒**） | 同上（**该档位曾 100% 崩溃，是 §4.10 时序缺陷的发现档位**） | **已实测 PASS**（修复后回归；**去锁前** 6 轮中位 **240,802.74** req/s，含 2 个离群值）。**去锁后数据见 §7.5** |
| `thread_mode=1` **4 线程** | 同上 | 同上（**本轮首次跑 4 线程，无历史基线**） | **已实测 PASS**（`[M17-PROBE-ZONE]` 在此档实测 `uk_ppera=4`）。**去锁后数据见 §7.5** |
| 60s/400 连接 soak | `wrk -t8 -c400 -d60s` | 零崩溃、零 socket error、进程存活 | 497,043 req/s、2983 万请求 |
| `thread_mode=0` 1 进程 | 同上 | 吞吐相对基线波动 **≤5%**；**且日志中 `grep "out of range"` 无命中**（见下方 D7 专项） | **已实测 PASS**：修复前二进制 **+0.03%**、修复后二进制 **+0.05%** |
| `thread_mode=0` **2 进程（primary + secondary，不可省）** | 同上 | 同上；**secondary 进程的 DoD-1 探针必须打印 `dense_idx=0`** | **已实测 PASS**：修复前 **−1.25%**、修复后 **+2.38%**（均 ≤5%）；**secondary 的 `dense_idx=0` 已实测确认** |
| **RSS 内存对照（新增，量化 §6.19 的 R6）** | `thread_mode=1` 下 1 / 2 / 4 线程各取稳定期 RSS（如 `grep VmRSS /proc/<pid>/status`），并与 HEAD 基线同档位对照 | 记录实测增量；核对是否接近「`+2.34 MiB × (N−1)`」的推导值 | **仍待采集**（`_m17_F_runtime.md` 未含 RSS 项） |

**⚠ DoD-4 整体状态**：`_m17_F_runtime.md`「第二部分」判定 **DoD-4 PASS** —— `thread_mode=1` 的 1/2/3/4 线程 + `thread_mode=0` 的 1/2 进程共 **六档零崩溃、零 socket error、日志零新增**，2 线程与 4 线程 soak 均通过。**【实测】**唯一未采集项是上表最后一行的 RSS 对照。

**⚠ 3 线程档吞吐稳定性提醒（`_m17_F_runtime.md` R2.3）**：该档 6 轮中出现 2 个明显离群值（143,232 / 204,857，其余 4 轮在 240k~247k），**零崩溃零 socket error**，故不构成功能失败，但**用它做 G2 去锁前后对比时必须加轮次，或优先改用 2 线程与 4 线程档**。离群根因**未坐实**（可排除崩溃/socket error/栈内报错；是否为 virtio 3 队列 RSS 分布不均需每队列收包计数探针，本轮无此探针）。**【未坐实】**

**D7 专项（gate-design E2 要求，不可省）**：`thread_mode=0` 的 **1 进程与 2 进程都必须实测**，且在两个日志文件中都确认**无** `ff_pcpu_thread_init: cpuid ... out of range`。理由见 §4.8：`thread_mode=0` 下 `lcore_conf[].proc_id` 是**进程序号**（secondary=1/2/…），安全性同时依赖「§4.4 的 `thread_mode` 门控」与「`__thread ff_stack_inited` 的早返回」两道机制，属**脆弱耦合**，**不接受仅静态推断**。

**§6.19（R6）专项**：M5 建议同时打印 `tcp_pace.rp_num_hptss`（应 == `mp_ncpus` == N）与各 `hpts->p_on_queue_cnt`，用于观测 §6.4 的「两worker 撞同一实例」发生率。

- **soak 是 §6.1/§6.2 的主要检测器**：若慢路径无锁窗口放大导致 `uma_page` 哈希破链，症状为崩在 `lib/include/vm/uma_int.h:101`（`up == NULL` 解引用）。**但判定必须用 §4.7.4 台阶 L1 的复合判据**（该行也会因「查表本就未命中」而崩，见 §6.2），不可仅凭崩溃行号断定并发破链。
- `config.ini` 的本地测试值（`thread_mode`/`lcore_mask`/IP 等）**不入库**；且 `[freebsd.sysctl]` 段**不得**出现 `net.isr.dispatch`（§6.18 / §5-10）。

### 7.5 DoD-5：G2 去锁前后吞吐对比 —— **已完成，PASS**

**实测结论（M5 第三部分 A/B 交叉复测，`_m17_F_runtime.md` X4.1）：DoD-5 PASS。**【实测】

| 档位 | 方法 | 去锁前中位 (req/s) | 去锁后中位 (req/s) | 差值 | 判定 |
|---|---|---|---|---|---|
| **2 线程** | **A/B 交叉各 6 轮** | 234,867.29 | 236,032.94 | **+0.50%** | **PASS** |
| **4 线程** | **A/B 交叉各 6 轮** | 250,734.43 | 254,913.26 | **+1.67%** | **PASS** |
| 2 线程 soak（60s/400连接） | 顺序 | 499,223.54 | 503,590.01 | +0.87% | PASS |
| 4 线程 soak（60s/400连接） | 顺序 | 487,968.74 | 496,646.19 | +1.78% | PASS |
| 1 线程 | 顺序 | 209,730.76 | 213,938.31 | +2.01% | PASS |
| `thread_mode=0` 1 进程 | 顺序 | 209,825.01 | 214,151.94 | +2.06% | PASS |
| `thread_mode=0` 2 进程 | 顺序 | 236,871.31 | 236,484.61 | −0.16% | PASS（在 ±2% 噪声内） |
| 3 线程 | 顺序，**不作判定依据** | 240,802.74 | 252,683.63 | +4.93% | 仅参考（去锁前含离群值） |

- **诚实边界（不得删减）**：+0.50% / +1.67% **接近噪声下限**，**不宣称 G2 带来确定的性能提升**；可支撑的结论仅为「去锁后吞吐不低于去锁前，DoD-5 阈值满足」。4 线程差值大于 2 线程，方向上与「线程数越多、全局锁争用越重」一致，但**样本量不足以坐实该因果**。
- **3 线程 +4.93% 不可直接采信**：去锁前该档 6 轮含两个离群值（143k / 205k）拉低了中位数，而去锁后 3 轮极差仅 0.25%；该差值很可能主要来自离群值而非 G2 收益，且该档**未做 A/B 交叉**。
- **A/B 交叉法的必要性**：±2% 判据对机器状态漂移极敏感；A 侧与 R5 既有中位互校偏差 −0.41% / +0.71%，证明本轮无漂移。
- **最终产品二进制冒烟（摘除探针后，leader 实测）**：`example/helloworld` md5 **`df05d2cd078d631ad2d8ee7caba8d387`**（30,392,632 B）在 2 线程档`wrk -t5 -c100 -d10s` = **236,273.85 req/s**、2,365,694 requests、**零 error**，日志无 `M17`/`panic`/`Segmentation`/`assert`；与本表去锁后 2 线程中位 236,032.94 相差 **+0.10%**。这是**唯一一次用「即将入库的那份二进制」跑出的运行时数据**，据此闭合「摘探针后未做运行时冒烟」这一残余风险。**【他人实测（leader），designer 未旁证】**

**以下为原计划口径，保留备查：**

- 对比对象：commit-1（G1 已生效、锁仍在） vs commit-2（G2 去锁）。**同机同客户端、≥3 轮取中位数。**
- **去锁前基线：已完整就绪**（`_m17_F_runtime.md` R5表，8 个场景，被测二进制 md5 `751a8153d3b200229cff99b3fa7650b0`，含**首次取得的 4 线程数据**）。**【实测】**
- **阈值**：去锁后吞吐**不得低于**去锁前，允许 ±2% 噪声。
- **对比档位选择（依据 R2.3 的实测稳定性）**：**优先用 2 线程与 4 线程档**；3 线程档因存在离群值必须加轮次（≥6 轮取中位）。
- **去锁后必须重做的不只是吞吐**：还须用 §7.1 全套探针**重新验证槽位隔离**（R1 全套判定式），**不可沿用去锁前的数据** —— 去锁后「每线程独占槽位」是唯一保护。**→ 该项已于 M5 第三部分完成（`_m17_F_runtime.md` X1：2/3/4 线程三档 + `thread_mode=0` 退化档全部 PASS），见 §7.1 限定 (1)。**【实测】
- 若无提升：仍须给出代码级结论说明 G2 的正确性收益（§2.4 / §4.7.1），并由 `reviewer` 门禁确认是否保留该改动。
- 若低于阈值或出现崩溃：先用 §4.7.5 的**早期检测式**判断是否为插入丢失，再进入 §4.7.4 的 L1 → L2 台阶（L1 须同时落实 §4.7.6），每次算一次 M4 打回（bounce ≤ 3）。

### 7.6 DoD-6：文档可追溯 —— **已完成**

本文所有结论已在 §9 建立「结论 → `file:line` / M1 文档章节」的对应表；残留风险集中于 §6。M6 须把 M5 实测数据回填 §7 各表并把 §6 中「【未坐实】」项按实测结果改写或保留。

**回填完成情况（M6，本节即DoD-6 的自检清单）**：DoD-1 → §7.1快照表（去锁前 2/3/4 线程 + `thread_mode=0` 两档）与 §7.1(1)（**去锁后复验已完成**）；DoD-2 → §7.2（含二进制符号级与6 档运行时确认）；DoD-3 → §7.3；DoD-4 → §7.4（六档 + soak，含 3 线程稳定性提醒）；**DoD-5 → §7.5（A/B 交叉全表 + 两条诚实边界 + 最终产品二进制冒烟）**；U2 → §7.1 判定式 ⑨ 与 §6.20（**已坐实**）；U6-a → §6.12（**本轮不核对，降为观测项**）；§4.10/§6.22 → 运行时发现的时序缺陷（**已修复**）。**仍未闭合的三项已如实保留**：§7.1 ⚠ 的基址一致性（未增打基址）、§7.4 的 RSS 对照（未采集）、§6.19 的 hpts 内存增量量化（未采集）。

### 7.7 DoD-7 / DoD-8：提交与清理

- **DoD-7—— 已完成**：两次 commit 落地（§8.2）—— **`c7996a94f`**（G1，8 文件）、**`57b612d16`**（G2，2 文件）；提交后 `git status --short lib/ freebsd/` 为**空**，`config.ini` 保持 ` M` **未入库**。`git add` 前必须逐项 review `git diff config.ini`，把 `lcore_mask`/`thread_mode`/`vlan_filter`/`idle_sleep`/`[portN]` 本机 IP 等回滚到仓库默认值。**【他人实测（leader），designer 未旁证】**
- **DoD-8**：M7 前必须 **① 摘掉全部 6 处 `#if 1 /* M17temporary probe */` 探针并重跑 clean build**（`grep -rn "M17 temporary probe" lib/` 零命中；摘除后已实测 rc 0/0、md5 `df05d2cd078d631ad2d8ee7caba8d387`、2 线程冒烟 236,273.85 req/s，见§7.5）；**② 清理临时产物**（`example/helloworld_g1_prelock`、`example/helloworld_g2_nolock`、`config.m17_g2_2t.ini`、`config.m17_g2_4t.ini`、`/tmp/m17*`、根目录 `_m17_*.log`/`_m17_*.txt`/`_m17_*.i`/`_m17_dep/`、`example/*.log` 等），**一律通过 `/data/workspace/rm_tmp_file.sh` 执行**。**建议把 `helloworld_g1_prelock` / `helloworld_g2_nolock` 两个二进制副本保留到 M7 最后一步再删**，以便随时复核 DoD-5的 A/B 数据。DoD-1 的探针属**源码内改动**，须通过**正向修改删除代码**（不适用 `rm_tmp_file.sh`）。
- **文档入库建议**：提交本spec 时**建议把 `_m17_F_runtime.md` 一并入库** —— 它是 §7.1/§7.4/§7.5 全部实测数据的唯一出处；若只提交 spec 而不提交它，文中「见 `_m17_F_runtime.md` X4.1 / X1」等引用在库内将**悬空**。

---

## 8. 里程碑与工作分解

### 8.1 里程碑

| 里程碑 | 内容 | 承担者 | 门禁（须不同 agent） |
|---|---|---|---|
| **M2** | 本文档 | `designer` | `gate-design` |
| **M3** | **G1**：SMP-aware per-cpu 视图 + 稠密索引 + `curcpu` per-thread（§4.1~§4.6、§4.8）；`make clean` 后 `lib/`+`example/` 完整编译 | `coder` | `reviewer` |
| **M4** | **G2**：移除 `uma_crit_lock`（§4.7）；`make clean` 后完整编译 | `coder` | `reviewer` |
| **M5** | 运行时验证矩阵（§7），含去锁前后吞吐对比 | `tester`（≠ `coder`） | `reviewer` 复核数据可信度 |
| **M6** | 实测数据/残留风险回填本文档 | `designer` | `gate-doc` |
| **M7** | 本地 commit（两次） | leader | `gate-doc`（复核 commit 范围与 `git diff`） |

**M3 前置动作（阻断性）**：M1-C 的探针改动若仍在工作区，必须先还原到HEAD 干净态，再由 `coder` **正式重写**（探针代码不得直接沉淀为产品代码，`_m17_gate_plan.md` §8.6-3）。**撰写期实测工作区已含 in-progress 改动（§0.2/§6.21），leader 须先裁定其归属：纳入 M3 正式产出并补 `curcpu`，或还原后重写。**（**已裁定**：`coder` 的 M3 产出已在第二轮落地 `curcpu`，见`_m17_E_coder_g1.md`；本文 §4.5 立场不变。）

### 8.2 两次提交的文件清单

**commit-1（G1）**

| 文件 | 改动 | 本文小节 |
|---|---|---|
| `lib/Makefile` | `+CFLAGS+= -DSMP`（`:219` 之后） | §4.1 |
| `lib/ff_glue.c` | `+smp_topo()` stub；（**不动** `:146 uma_crit_lock`） | §4.2 |
| `lib/ff_freebsd_init.c` | `+#include <sys/smp.h>`；`+extern int ff_cur_proc_id(void);`；`mp_ncpus`/`mp_maxid`/`all_cpus` 三元组（替换 `:294`）；`ff_pcpu_thread_init()` 用形参 + 上界panic + 重写 `:94-101` 注释；`:293` 改为 `thread_mode ? ff_cur_proc_id() : 0`；**`uma_page_slab_hash`/`uma_page_mask` 初始化由 `:304-306` 提前到 `uma_startup1()` 之前（§4.10，H3）** | §4.3 + **§4.10** |
| `lib/ff_dpdk_if.c` | `:2649` → `qconf->proc_id`；`+ff_cur_proc_id()` | §4.4 |
| `lib/ff_dpdk_if.h` | `+int ff_cur_proc_id(void);` | §4.4 |
| **`lib/include/sys/pcpu.h`** | `:34 #define curcpu 0` → `#define curcpu PCPU_GET(cpuid)` | §4.5 |
| `lib/ff_kern_timeout.c` | `:190` → `static __thread int timeout_cpu;` | §4.6 |
| **`lib/ff_kern_synch.c`** | `:105` 的 `pause_wchan[curcpu]` → `pause_wchan[pcpup != NULL ? curcpu : 0]`（引导窗口定点兜底 + 1 行必要注释） | §4.5(i) |

→ 共 **8 个文件，`freebsd/` 上游树 0 处改动**。（`lib/ff_host_interface.c/.h` 的 `ff_probe_tid()` 属**探针临时代码**，不计入本清单，见 §8.3。）

> **`lib/ff_glue.c` 同时出现在两个 commit 中**（commit-1 加 `smp_topo()` stub、commit-2 删 `uma_crit_lock` 定义），两处改动在文件的**不同位置**、可干净拆分 —— **实际采用的拆分手法（非 `git add -p`）见 §8.3.1**。
>
> **实际提交（已完成）**：**`c7996a94f`**（G1，8 文件）、**`57b612d16`**（G2，2 文件）。提交后 `git status --short lib/ freebsd/` 为**空**，`config.ini` 保持 ` M` **未入库**；重新 `make clean && make`（`lib` + `example`）rc 0/0，`example/helloworld` md5 **`df05d2cd078d631ad2d8ee7caba8d387`**（30,392,632 B）与提交前审过的二进制**逐字节一致**。**【他人实测（leader），designer 未旁证】**

**commit-2（G2）**

| 文件 | 改动 | 本文小节 |
|---|---|---|
| `lib/include/vm/uma_int.h` | `:45-52` → `critical_enter/exit` 为 `do {} while(0)`（删`extern volatile int uma_crit_lock;`） | §4.7.1 |
| `lib/ff_glue.c` | 删 `:146 volatile int uma_crit_lock;` | §4.7.1 |

→ 共 **2 个文件**。**不得混入任何其它改动**（§4.7.7）。**commit-2 可单独 `git revert` 而不影响 G1** —— 这是 §4.7.4 台阶 L2 的操作保障，也是把 G2 拆成独立提交的根本原因。

### 8.3 探针的生命周期与提交拆分操作方法

DoD-1 探针（§7.1 的 P1~P5）**不进入 commit-1/commit-2**：M3 加入 → M5 取证 → M6 之前由 `coder` 通过正向修改删除。实际落地的探针涉及 **`lib/ff_freebsd_init.c`（P1~P4 + P5 `[M17-PROBE-ZONE]`，`:115`/`:134`/`:160`）+ `lib/ff_host_interface.c`/`.h`（`ff_probe_tid()`）**，全部用 `#if 1 /* M17 temporary probe */ … #endif` 包裹，`grep -rn "M17 temporary probe" lib/` 可一次列全。M7 提交前必须 `git diff` 确认探针不在 diff 中；若为便于复现而必须提交，则应作为**独立的临时提交**并在 M5 后revert（由 leader 裁决）。**若 §7.1 的 ⚠ 采用方案 (a)，探针还需增打 `smr_base`/`zone_base` 两个 `%p`，该增改同属临时代码。**

> **注意区分**：§4.10 的 `uma_page_slab_hash` 提前**不是探针**，而是**必须入库的正式修复**，已计入 §8.2 的 commit-1 清单。清理探针时**不得**把它一并删掉。

#### 8.3.1 两类拆分场景，方法**不同**（`gate-design` 必改 N2）

探针 P1~P4 与 G1 的真实改动**同处`lib/ff_freebsd_init.c` 一个文件**，直接 `git add` 会把探针一起提交。两种情形必须用不同手法：

| 场景 | 方法 | 理由 |
|---|---|---|
| **同一 commit 内的探针vs 正式改动**（`lib/ff_freebsd_init.c` 的 P1~P4、`lib/ff_host_interface.c/.h` 的 `ff_probe_tid()`） | **必须先通过正向修改删除全部探针块，再整文件 `git add`。** 用 `grep -rn "M17 temporary probe" lib/` 一次列全全部 6 处`#if 1 /* M17 temporary probe */ … #endif`；删除后**必须 `make clean` 重跑完整编译 + 冒烟**，确认摘除未破坏编译与启动 | **不建议**用 `git add -p` 拆同一文件内的探针：探针块与正式改动交错，易漏改，且会在索引中留下**不可编译的中间态**（例如探针调用了已被 stage 的辅助函数却未 stage 其定义） |
| **跨 commit 的同一文件**（`lib/ff_glue.c`：commit-1 的 `smp_topo()` stub vs commit-2 的删 `uma_crit_lock`） | **须按 hunk 拆分**：commit-1 只提交 `smp_topo()` 那处、commit-2 再提交删 `uma_crit_lock` 那处。**实际采用的手法见下方 ⚠（不是 `git add -p`）** | 两处改动在文件的**不同位置**、互不依赖，`reviewer` 已确认拆分后两个 commit **各自都可独立编译**；拆分是满足 §4.7.7「G2 独立可回退」的**必要**手段 |

> **⚠ 拆分手法的实际执行（`reviewer2` S3 校正）**：**`git add -p` 只能交互运行，自动化/agent 环境会卡住，不要照抄。** 本轮**实际采用「临时保留 → 提交 → 再删除」的正向编辑法**：① commit-1 之前把 G2 已删掉的 `volatile int uma_crit_lock;` **临时加回** `lib/ff_glue.c`，使该文件只含 G1 的 `smp_topo()` stub，然后**整文件 `git add`**，与其余 7 个文件一起提交为 **`c7996a94f`**（G1，8 文件）；② commit-2 再删掉该行，`git add lib/ff_glue.c lib/include/vm/uma_int.h` 提交为 **`57b612d16`**（G2，2 文件）。非交互场景的等价手法有两种：**① 本轮采用的正向编辑法**；**② `git diff <file>` 导出补丁后只保留目标 hunk，再 `git apply --cached`**（见 `_m17_gate_final.md` §8 R2-S1）。

**M7 提交前的检查清单**：① `grep -rn "M17 temporary probe" lib/` **零命中**；② `make clean` 后 `lib/` + `example/` 完整编译 error 0 / warning 51；③ `git diff --cached` 逐文件复核无探针残留；④ `git diff config.ini` 确认本地测试值未入库（§7.7）。

### 8.4 commit message 英文草案（1~3 句）

> **以下为草案；实际提交见 `c7996a94f`（G1）/ `57b612d16`（G2）**，措辞与草案已有出入，以库内历史为准。

**commit-1（G1）**

```
Make the f-stack kernel view SMP-aware so each stack thread owns a dense pcpu slot.

Define SMP so MAXCPU is large enough, set mp_ncpus/mp_maxid/all_cpus from
nb_threads before uma_startup1(), pass the dense lcore_conf proc_id to
pcpu_init(), and resolve curcpu per thread, so UMA per-CPU caches and SMR
c_seq slots no longer all alias slot 0.  Also move the uma_page_slab_hash
setup ahead of uma_startup1(), because a larger zone-of-zones makes UMA
allocate multi-page slabs and call vsetzoneslab() during UMA startup.
```

**commit-2（G2）**

```
Remove the global uma_crit_lock now that each stack thread owns its own UMA per-CPU cache slot.

This restores the lock-free per-CPU fast path; the zone/keg slow path is
unaffected because it already runs outside the critical section.
```

---

## 9. 证据索引

> **行号基线声明（重申，避免复核误报）**：本文**全部** `file:line` 均相对 **`HEAD = ff09a17b2`**（§0.2）。G1 提交 `c7996a94f` 之后，因`-DSMP` 在 `lib/Makefile:218` 附近插入 4 行，**该文件此后的行号一律 +4**（例如 `tcp_lro.c` 由 `:515` 变为 `:519`、`kern_mbuf.c` 由 `:346` 变为 `:350`）；`lib/ff_freebsd_init.c`/`lib/ff_dpdk_if.c`/`lib/include/vm/uma_int.h` 等亦有相应偏移。**这不是缺陷** —— 用新 HEAD 复核时请先按此换算，或直接 `git show ff09a17b2:<file> | grep -n`。

### 9.1 本文关键结论 → 证据

| # | 结论 | 证据 |
|---|---|---|
| 1 | `MAXCPU == 1`（非 SMP 下无条件） | `freebsd/amd64/include/param.h:60-66`；M1-A U1【实测】 |
| 2 | `zpcpu_offset_cpu(cpu) == 4096 * cpu`；`UMA_PCPU_ALLOC_SIZE == PAGE_SIZE == 4096` | `freebsd/sys/pcpu.h:221/234-236`；`freebsd/amd64/include/param.h:92-93`；`lib/include/amd64/include/pcpu.h:40`；M1-A U1【实测】 |
| 3 | `pcpu_init()` 写 `pc_cpuid`/`cpuid_to_pcpu[]`/`cpuhead`/`pc_zpcpu_offset` | `freebsd/kern/subr_pcpu.c:84-97`（`:88-89` KASSERT、`:90/91/92/96`）；`:76-77` 数组尺寸 `MAXCPU` |
| 4 | HEAD 恒传 cpuid 0 | `lib/ff_freebsd_init.c:103-109`（`:107`），注释 `:94-101` |
| 5 |稠密序号现成来源 | `lib/ff_dpdk_if.c:429-433`（`lc->proc_id = ti`）、`:126 lcore_conf[RTE_MAX_LCORE]`、`:460`（thread_mode=0 分支为进程序号）；`lib/ff_memory.h:104-111`；`lib/ff_config.c:116-118/139/1466-1481` |
| 6 | cpuid 当前来源是 `rte_lcore_id()` | `lib/ff_dpdk_if.c:2649`（HEAD） |
| 7 | 启动时序（`uma_startup1` 的位置） | `lib/ff_init.c:36/39/43/47/51`；`lib/ff_freebsd_init.c:291/293/294/296/301/302/304-306/308/309/317/342/348` |
| 8 | zone 尺寸在 `uma_startup1` 定死/ `ZDOM_GET` | `freebsd/vm/uma_core.c:3179-3182`、`:2472-2478`、`:2873`；`freebsd/vm/uma_int.h:529`；本文预处理【实测】 |
| 9 | `smr_create()` 按 `mp_maxid` 逐槽写 | `freebsd/kern/subr_smr.c:583-609`（`:591`、`:598-605`）；`:623-631smr_init()` |
| 10 | PCB 走 SMR | `freebsd/netinet/in_pcb.c:583`、`:615-617`；`freebsd/sys/smr.h:105-143`（`:110`） |
| 11 | SMR 独占性是上游硬假设（UAF 机理） | `_m17_B_external.md` §2.1/§2.2/§2.6（上游 `smr.h`/`subr_smr.c` 原文 + smr(9)） |
| 12 | **`curcpu` 硬编码为 0** | **`lib/include/sys/pcpu.h:31-34`**；上游 `freebsd/sys/pcpu.h:218`；本文对 `uma_core.c` 的只读 `cc -E`【实测】输出 `cache = &zone->uz_cpu[0];` |
| 13 | UMA cache 按 `uz_cpu[curcpu]` 定位（11 处） | `freebsd/vm/uma_core.c:1452/3738/3776/3818/3901/4534/4543/4595/4628/4803/4853` |
| 14 | `curcpu` 的全部其它使用点及安全性 | `lib/ff_kern_synch.c:59/105`；`freebsd/netinet/tcp_timer.c:237/249`；`freebsd/netinet/tcp_hpts.c:1566/1587`；`freebsd/netinet/tcp_lro.c:1210/1216`；`freebsd/net/netisr.c:275-279/810/839/1146-1153/1172`、`:151/153/781-790/169`；`freebsd/netinet/ip_input.c:139-149`、`freebsd/netinet6/ip6_input.c:138-148` |
| 15 | `uma_crit_lock` 定义与作用域 | `lib/include/vm/uma_int.h:45-52`；作用域仅 `uma_core.c`（M1-A U10§10.3【实测】、`_m17_gate_plan.md` §三-4） |
| 16 | `critical_enter` 在非 UMA TU 本就是空操作 | `freebsd/sys/systm.h:179-193`（`:186 #ifndef FSTACK`）；M1-A U7 §7.1【实测】 |
| 17 | 慢路径在临界区之外 | `freebsd/vm/uma_core.c:3855-3893`（`:3859` `critical_exit` → `:3880/3882`）、`:3916-3918`；上游注释 `:3867-3874` |
| 18 | UMA 全部 `mtx` 被 stub | `lib/include/sys/mutex.h:31-48`（undef）、`:57 DO_NOTHING`、`:59-72`、`:74-76`（trylock → 1）、`:85 mtx_owned → 1`；`freebsd/vm/uma_int.h:540/551-552/566/578/582/584/588`（锁宏全部建立在 `mtx_lock` 上）；M1-A U8 §8.2【实测】 |
| 19 | UMA 锁是可睡眠语义（否决 G2-a 的依据 1） | `freebsd/vm/uma_core.c:1725 msleep(zone, ZONE_LOCKPTR(zone), PVM, "zonedrain", 1)`、`:5433 sx_sleep`；`freebsd/vm/uma_int.h:540 KEG_LOCK_INIT` / `:566 ZDOM_LOCK_INIT` 用 `MTX_DEF|MTX_DUPOK` |
| 20 | `vsetzoneslab` 无锁 + `vtozoneslab` 对 NULL 解引用 | `lib/include/vm/uma_int.h:90-103`（`:101`）、`:105-126`（`:121-125`）；哈希表 `lib/ff_freebsd_init.c:304-306` |
| 21 | `timeout_cpu` 漏 `__thread` | `lib/ff_kern_timeout.c:183/184/185/190/247-259（:252/254/255/258）/662/730-733/815/1061/1077/1181` |
| 22 | `MAXCPU` 边界判断/尺寸数组 | `freebsd/kern/subr_pcpu.c:76-77`；`lib/ff_kern_synch.c:59`；`lib/ff_kern_timeout.c:730`；`lib/ff_glue.c:142`；`freebsd/net/netisr.c:243/1432/1457/1486/1516`；`freebsd/amd64/include/pcpu_aux.h:47` |
| 23 | 三元组的 ipfw 堆溢出依据 | `freebsd/netpfil/ipfw/ip_fw_dynamic.c:3236`、`:2086-2091`、`:224-226`、`:228`；`freebsd/sys/smp.h:197-199/187`；`_m17_gate_plan.md` §8.4 |
| 24 | hpts 活跃（U16-a 关闭） | `lib/ff_dpdk_if.c:2794`（HEAD）；`lib/ff_kern_timeout.c:1291-1296`；`freebsd/netinet/tcp_hpts.c:2061/2142/2117-2118/1853`；`freebsd/kern/kern_module.c:107`；`lib/Makefile:347` |
| 25 | hpts 索引与锁语义 | `freebsd/netinet/tcp_hpts.c:217-219`（`HPTS_TRYLOCK` = `mtx_trylock`）、`:1549-1588`、`:1599/1608`、`:1864/1872/1885-1888/1921-1925`、`:1089`；`freebsd/netinet/tcp_timer.c:229-253`；M1-A U16 |
| 26 | 候选 A 编译代价 | `_m17_C_buildprobe.md` §1/§2.2/§2.3/§2.4【实测】 |
| 27 | 候选 A 语义风险已证伪/限定 | `_m17_gate_plan.md` §8.2（spin 锁）、§8.3（CK）、§8.7（未核验边界） |
| 28 | 候选 B 改动面（无编译数字） | `_m17_C_buildprobe.md` §3.1/§3.2/§3.3 |
| 29 | `MAXCPU` 降级台阶可行性 | `freebsd/amd64/include/param.h:61-63`（SMP 分支带 `#ifndef MAXCPU`）；`_m17_C_buildprobe.md` §2.7 |
| 30 | 无真线程的辅助路径（1:1 前提成立） | `lib/ff_kern_intr.c:84-107`；`lib/ff_compat.c:162-177`；`lib/ff_dpdk_kni.c:93-97`；`lib/ff_kern_timeout.c:183-185`；M1-A U13.2 |
| 31 | `ff_pthread_create` 线程无 pcpup | `lib/ff_thread.c:16-19/21-30/33-45` |
| 32 | NUMA 未编译 | `lib/ff_glue.c:83`；M1-A U8.4-4 |
| 33 | counter(9) 去 per-cpu 化 | `lib/include/amd64/include/counter.h:38-39/43-47/49-53/56/58-62`；`freebsd/kern/subr_counter.c:46-57/63` |
| 34 | `SMR_LAZY` 未被使用（T6 关闭） | `freebsd/vm/uma_core.c:3024 smr_create(zone->uz_name, 0, 0)`（flags = 0）；本文实测grep |
| 35 | 上游出处（遗留风险登记） | `16-多队列对照实验与根因纠偏.md:266-279`（§8.1/§8.2） |
| 36 | `uma_crit_lock` 的引入动机 | `git show b90ddcba5`【实测】（M1-A U7 第1 部分，commit message 与 diff 原文） |

### 9.2 输入文档索引

| 文档 | 本文引用处|
|---|---|
| `_m17_D_verdict.md` | §3.1/§3.2/§3.3/§3.4（路线裁决与边界）、§4.9（D1~D9）、§6（残留风险六条） |
| `plan-17-SMP-aware-pcpu-smr.md` | §1.3（G1/G2 定义）、§7（DoD-1~8）、§8.1（里程碑）、§7.4（性能基线 §5.1） |
| `_m17_A_codepath.md` | U1（宏展开）、U2（`pcpu_page_alloc`/逐页登记）、U4（`mp_*` 读者与 H1~H4）、U5（`init_lock`）、U6（稠密序号与时序）、U7（`uma_crit_lock` 动机与语义）、U8（跨线程 zone / 锁 stub）、U9（`MAXCPU` 边界）、U10（时序）、U11（callout）、U13（线程模型）、U14/U15、U16（`mp_ncpus` 自由度）、附录 A（未坐实项） |
| `_m17_C_buildprobe.md` | §0.1/§0.2/§0.3（编译机制与宏实测）、§1（基线）、§2（候选 A 实测）、§3（候选 B 代码审）、§4（`#ifdef SMP` 分布）、§5.2（工作区状态） |
| `_m17_gate_plan.md` | §三-4（`critical_enter` 作用域）、§8.2（spin 锁证伪）、§8.3（CK 措辞限定）、§8.4（ipfw 堆溢出）、§8.6（探针不得沉淀）、§8.7（未核验边界） |
| `_m17_B_external.md` | §2.1/§2.2/§2.6（SMR 语义与 UAF）、§2.3（`UMA_ZONE_PCPU`/`zpcpu_get` 前置条件）、§3.1（libuinet）、§3.2（rump）、§3.3/§3.4（Seastar/ANS）、§4.1/§4.2/§4.3（去锁论证与缺口）、§5（`cpuset_t`/`MAXCPU` ABI）、§6（知识边界） |
| `16-多队列对照实验与根因纠偏.md` | §1.1（上游出处 §8.1）、§1.2（T0/T1 三态） |

### 9.3 本文档新增的证据（非来自 M1）

| # | 内容 | 取证方式 |
|---|---|---|
| N1 | `curcpu` 硬编码为 0 及其 11 处 UMA 影响点 | `read_file lib/include/sys/pcpu.h`；`grep -n curcpu freebsd/vm/uma_core.c`；对 `uma_core.c` 的只读 `cc -E`（未写文件、未跑 `make`） |
| N2 | `curcpu` 在编译集合内的全部 7 个使用文件及逐点安全性 | 以 `lib/*.o` 反推编译集合后逐文件 `grep -n '\bcurcpu\b'` |
| N3 | netisr 默认 DIRECT 策略使 `:1172` 不可达 | `read_file freebsd/net/netisr.c:1128-1236`；`grep NETISR_DISPATCH_POLICY_DEFAULT`；`netisr_get_dispatch:781-790`；`ip_nh`/`ip6_nh` 定义 |
| N4 | `thread_mode=0` 的 `proc_id` 为进程序号（C2） | `grep -n proc_id lib/ff_dpdk_if.c`（`:460`）+ `:1643-1651` 校验 |
| N5 | U16-a 关闭（hpts 由 `main_loop` 驱动） | `grep -rn ff_tcp_hpts_softclock`；`grep DECLARE_MODULE freebsd/netinet/tcp_hpts.c`；`grep module_register_init freebsd/kern/kern_module.c`；`ls lib/kern_module.o` |
| N6 | `HPTS_TRYLOCK` 恒真 | `grep -n 'define HPTS_TRYLOCK' freebsd/netinet/tcp_hpts.c` + `lib/include/sys/mutex.h:74-76` |
| N7 | UMA 锁可睡眠（否决 G2-a） | `grep -n 'msleep\|_sleep(' freebsd/vm/uma_core.c`；`sed -n '520,600p' freebsd/vm/uma_int.h` |
| N8 | `SMR_LAZY` 未被使用（T6 关闭） | 在编译集合内 `grep 'SMR_LAZY\|smr_create('` |
| N9 | 慢路径在临界区外（G2 的核心事实） | `read_file freebsd/vm/uma_core.c:3855-3921` + `grep -n 'critical_enter\|critical_exit' freebsd/vm/uma_core.c`（21 处） |
| N10 | 撰写期工作区含他人 in-progress 改动 | `git status --short -- lib/`、`git diff --stat -- lib/`、`git show HEAD:lib/ff_dpdk_if.c \| grep -n ...` |
| N11 | **`VIMAGE` 已定义 → `V_tcbinfo` 是 per-vnet → DoD-1 判定式 ⑤/⑥ 须先确认基址一致性**（§7.1 的 ⚠） | `grep -rn VIMAGE lib/opt/opt_global.h`（`:6 #define VIMAGE 1`）；`freebsd/netinet/tcp_var.h:1308/1315`；`freebsd/net/vnet.h:305 #define VNET(n) VNET_VNET(curvnet, n)`（`:427/440` 是非 VIMAGE 的退化定义，本项目不走） |
| N12 | **netisr DPCPU 别名**（E8，§6.15） | `grep -n "DPCPU_DEFINE\|DPCPU_PTR\|DPCPU_ID_PTR" freebsd/net/netisr.c`（`:236` 定义；`:1147` DIRECT 分支；`:1174`/`:1044` 队列路径）；`awk` 读 `:1143-1152`；`lib/ff_kern_intr.c:84-101`（swi 全stub） |
| N13 | **`net.isr.dispatch` 可调且改后丢包**（§6.18） | `awk` 读 `freebsd/net/netisr.c:149-158`（`:151` 默认 DIRECT、`:153` 初值、`:155-158 SYSCTL_PROC ... CTLFLAG_RWTUN`）与 `:806-813`（`nws_count==1` 短路） |
| N14 | **`tcp_hpts` 实例数 1→N 及其代价（R6，§6.19）** | `awk` 读 `freebsd/netinet/tcp_hpts.c:1862-1876`（`:1864ncpus = mp_ncpus ? ... : MAXCPU`、`:1872`）、`:1918-1932`（`:1920 asz`、`:1921-1924` per-i malloc、`:1931-1932 MTX_DEF`）、`:2040-2052`（`:2047-2049 callout_reset_sbt_on(..., hpts->p_cpu, ...)`）；`:169 NUM_OF_HPTSI_SLOTS 102400`；`:243-247 struct hptsh`；`:1999 callout_init`、`:2010 p_cpu = i`；`git show HEAD:lib/Makefile \| grep TCPHPTS`（`:51 FF_TCPHPTS=1`、`:161`） |
| N15 | **`callout_*_curcpu` 宏族不经 `curcpu`**（E7-X2） | `awk` 读 `freebsd/sys/callout.h:96-122`（`:101/109/116/120` 均为 `PCPU_GET(cpuid)`）；`awk` 读 `freebsd/kern/subr_taskqueue.c:366-370` |
| N16 | **`arc4random.c` 未参与编译**（E7-X1） | `git show HEAD:lib/Makefile \| grep -n arc4random`（`:582` 只有 `arc4random_uniform.c`）；`ls lib/arc4random.o` → `No such file` |
| N17 | **`vtozoneslab()` 缺判空 vs `vtoslab()` 有判空**（E9） | `awk` 读 `lib/include/vm/uma_int.h:82-104`（`:87return (NULL)` vs `:101-102` 无判空解引用） |
| N18 | **UMA 锁宏的精确行范围**（E4） | `awk` 读 `freebsd/vm/uma_int.h:538-590`（`:540-548 KEG_LOCK_INIT`、`:566-574ZDOM_LOCK_INIT`、`:578-584`、`:586-590 ZONE_CROSS_*`） |
| N19 | **`lib/Makefile` / `kern_module.c` 行号的HEAD vs 工作区差异**（E5） | `git show HEAD:lib/Makefile \| grep -n kern_module.c`（`:347`）vs `grep -n kern_module.c lib/Makefile`（`:351`）；`awk` 读 `freebsd/kern/kern_module.c:104-110`（`:106-107`） |
| N20 | **U2 已坐实：`UMA_ZONE_PCPU` zone 真按 `(mp_maxid+1)` 页分配** | M3 第三轮 `[M17-PROBE-ZONE]` 探针（`lib/ff_freebsd_init.c:160`）运行时实测：`pcpu_zone_8`/`pcpu_zone_64` 均 `uk_ppera=4 uk_rsize=8/64 mp_maxid=3`【实测】。见 §7.1 判定式 ⑨、§6.20 |
| N21 | **§4.10 的 `uma_page_slab_hash` 时序缺陷**（`mp_maxid ≥ 2` 启动即 SIGSEGV，已修复） | 运行时实测 100% 复现（`thread_mode=1` 3/4 线程，崩在 `uma_startup1()→zone_alloc_item()→zone_import()`，worker 未启动）【实测】；机理逐点：`freebsd/vm/uma_core.c:3179-3182`（zsize 随 `mp_maxid` 每 CPU +128）、`:2436-2472`（`keg_layout` 升级循环，`:2466-2469` 的退出条件不含非-PCPU zone）、`:2486-2491`（两页时置 `UMA_ZFLAG_VTOSLAB`）、`:1822-1825`（逐页 `vsetzoneslab`）、`lib/include/vm/uma_int.h:107-126`（`:112` 直接用 hash，无判空）、HEAD `lib/ff_freebsd_init.c:299/301/304-306`（原顺序）vs 当前 `:380-382/385/387`（修复后顺序）；`sizeof(struct uma_cache)==128` 由 `[M17-PROBE-SLOT]` 槽距 `0x80` 实测 |
| N22 | **DoD-1 2/3/4 线程全档 PASS + `thread_mode=0` 零回归 + DoD-4 六档 PASS** | `_m17_F_runtime.md`「第二部分」R1.2~R1.4（`pc_zpcpu_offset==4096×idx`、`smr_c_seq` 公差 4096、`uma_cache` 公差 128、`dense_idx==pc_cpuid==curcpu`、三元组正确）、R2.3（3 线程 6 轮，中位 240,802.74，2 个离群）、R5（去锁前基线 8 场景）、R6 判定表（DoD-1/DoD-4 PASS、`thread_mode=0` +0.05%/+2.38%）【实测】；被测二进制 md5 `751a8153d3b200229cff99b3fa7650b0`（**去锁前**） |
| N23 | **`vtozoneslab()` 在本 build 中是死代码**（`reviewer` 必改-2 的依据，推翻原L1 判据 (a)） | `grep -rn vtozoneslab --include=*.c freebsd/ lib/` → 仅 `freebsd/kern/kern_malloc.c:943/1039/1136`；`git show HEAD:lib/Makefile \| grep kern_malloc` → **零命中**；`ls lib/kern_malloc.o` → `No such file` |
| N24 | **`vtoslab()` 的两个调用点 = L1 判据 (a′) 的崩点** | `grep -rn "vtoslab(" --include=*.c` → `freebsd/vm/uma_core.c:4930`、`:5819`；`awk` 读 `:4924-4940`（`:4930` 取 slab → `:4938 slab->us_domain` 解引用）与 `:5812-5828`（`:5819return vtoslab(...)`） |
| N25 | **`uma_page` 哈希只增不删⟹ 无 UAF；`le_prev` 无消费者 ⟹ 最坏为插入丢失**（`reviewer` G2-S1，据此下调 §6.1 定级） | `grep -rn "LIST_REMOVE\|uma_page_slab_hash" lib/include/vm/uma_int.h lib/ff_freebsd_init.c lib/*.c` → 该哈希只有 `LIST_INSERT_HEAD`（HEAD `:125`）与 `LIST_FOREACH`（`:84`/`:97`/`:111`），`LIST_REMOVE` 命中全部属 `ff_kern_timeout.c:617` 的 callout 链 |
| N26 | **HEAD vs worktree 的 `uma_int.h` 行号校准**（worktree 已带 G2 改动） | `git --no-pager diff --stat -- lib/include/vm/uma_int.h`（+14/−9）；`git show HEAD:lib/include/vm/uma_int.h \| grep -n ...` → `critical_enter/exit` `:45-52`、`vtoslab` `:77-88`（`:87 return NULL`）、`vtozoneslab` `:90-103`（`:101-102` 无判空）、`vsetzoneslab` `:105-126`（`:115-118` 命中即改、`:120-125` 插入）。**本文所有引用均为 HEAD 值** |
| N27 | **`rp_ent[]` 索引无取模 ⇒ `mp_ncpus=N` 的安全性须由「写侧有界」论证**（`gate-design` 必改 F1，本文整段替换原论证） | `awk` 读 `freebsd/netinet/tcp_hpts.c:570-580`（`:575 hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];` **无取模**）；`grep -rn "t_hpts_cpu = " freebsd/netinet/` → 全树仅 3 个写点（`tcp_hpts.c:606`、`:1542`、`tcp_subr.c:2298`）；`awk` 读 `:462-478`（`:473` 双重取模）、`:1040-1099`（`:1050`/`:1059`/`:1067`/`:1078`/`:1089` 全部返回路径有界；`:1064-1070` RSS 与 `:1085-1096` NUMA 未编译）；`grep -rn t_lro_cpu` → 唯一非哨兵赋值在 `tcp_lro_hpts.c:577`，而 `git show HEAD:lib/Makefile \| grep tcp_lro` →只有 `:515 tcp_lro.c`、`lib/tcp_lro_hpts.o` 不存在；`tcp_var.h:330 HPTS_CPU_NONE == (uint16_t)-1`；`tcp_hpts.c:601-609 tcp_hpts_init()` 的调用者 `rack.c:14368`/`bbr.c:9946`，二者已编译（`lib/Makefile:584-586`，`lib/rack.o`/`lib/bbr.o` 存在）；`:1864/:1872` 保证 `rp_num_hptss == mp_ncpus`；时序由 `lib/ff_freebsd_init.c:309 mi_startup()` 晚于三元组设置保证 |

---

**文档状态**：M2 设计稿完成，待 `gate-design` 门禁。M5 实测数据与 §6 中【未坐实】项的收敛由 M6 回填。

