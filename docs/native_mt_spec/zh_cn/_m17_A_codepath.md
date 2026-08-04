# M17-A：代码路径穷尽探测（res-code 调研产出）

> 本文为 plan-17 的 M1-A 交付物。所有结论均为**实际执行**命令 / 实际打开文件所得，标注 `file:line` 或命令输出摘录。
> 未坐实的项明确标注「未坐实」+ 原因 + 建议后续手段，**不做任何推测性断言**。
>
> 仓库：`/data/workspace/f-stack`，`git log --oneline -1` = `ff09a17b2 Fix native-mt multi-thread multi-queue: give each worker its own prison ...`（实测输出）。
>
> **本文档作者不修改任何源码**。为完成预处理实证创建的临时文件（`lib/_m17_probe_u1.c`、`_m17_probe_u1.i`、`_m17_uma_core.i`、`_m17_srcset.txt`、`_m17_allc.txt`、`_m17_srcpaths.txt`）在调研结束后已通过 `/data/workspace/rm_tmp_file.sh` 清理。

---

## 0. 实证基线：真实编译命令行

用 `make -n -B uma_core.o`（只打印不执行，未跑 `make`）抓到 `lib/` 内 FreeBSD 源文件的真实编译命令：

```
cc -c -O2 -fno-strict-aliasing -frename-registers -pipe -Wno-maybe-uninitialized \
  -std=c99 -Wall ... -fno-common -finline-limit=8000 --param inline-unit-growth=100 \
  --param large-function-growth=1000 -DFF_IPFW -DINET -Wno-error=stringop-overflow \
  -Wno-error=stringop-overread -Wno-error=array-bounds -Wno-error=format \
  -Wno-error=format-extra-args -Wno-error=cast-qual -DINET6 -DTCPHPTS -DRATELIMIT \
  -DFF_LOOPBACK_SUPPORT -DFSTACK -fstack-protector -D__FreeBSD__ -D_KERNEL \
  -DHAVE_KERNEL_OPTION_HEADERS -include opt_global.h -fno-builtin \
  -I/data/workspace/f-stack/lib/include -undef -imacros filtered_predefined_macros.h \
  -nostdinc -I. -I/data/workspace/f-stack/lib/../freebsd -I. \
  -I/data/workspace/f-stack/lib/../freebsd/contrib/ck/include -I./machine_include -I./opt \
  -Werror -Wno-unused-variable .../freebsd/vm/uma_core.c -o uma_core.o
```

对应`mk/kern.pre.mk:75` `NORMAL_C`。要点（对后续方案有约束）：

- **没有 `-DSMP`**，**没有 `-DINVARIANTS`**（下文 U1 预处理实测确认）。
- `-DFSTACK` 存在 —— 这是 f-stack 在 FreeBSD 源码里做条件裁剪的开关，**比 `lib/include/` 的 override 头更关键**（见 U1）。
- `-nostdinc` + `-undef` + `-imacros filtered_predefined_macros.h`，`-I${lib}/include` 排在 `-I${freebsd}` 之前→ override 头生效靠 `#include_next`。
- `-DFF_IPFW -DINET -DINET6 -DTCPHPTS -DRATELIMIT -DFF_LOOPBACK_SUPPORT` 均已开启；**`FF_KERNEL_COEXIST` 未开启**（`lib/Makefile:60` 被注释）。

> **⚠ 可复现性提示（重要）**：本文档所有 `cc -E` 预处理都是**显式手写上述参数列表**执行的（未经由 `make`），基线是 **pristine HEAD `ff09a17b2` 的编译配置**。
> 本文档写作期间，另一个 agent（`res-build`，负责 M1-C 编译可行性）已在工作树里加入**临时编译探针**：`lib/Makefile:221-223 # _M17_PROBE_A ... CFLAGS+= -DSMP` 与 `lib/ff_glue.c:161-169 #ifdef SMP struct cpu_group *smp_topo(void) { return (NULL); } #endif`（实测 `git diff --stat` = `lib/Makefile |3 +++`、`lib/ff_glue.c | 9 +++++++++`，两处注释均自带 "temporary build probe, to be reverted"）。
> 因此**若现在直接跑 `make -n` 会看到多出的 `-DSMP`**，与本文档第 0 节抄录的命令行不一致。**本文档的所有结论（尤其 U1 的 `SMP = not_defined`）描述的是 pristine 配置**，这也正是 M2 裁决所需要的「改动前基线」。`res-build` 的探针改动不属于本 agent，本 agent 未修改任何源码、亦不清理他人的探针文件。

---

## C-更正（重要）：`curcpu` 在 f-stack 里被硬编码为 `0`，UMA per-cpu cache **不走 `zpcpu_get()`**

> **本条由 `designer` 发现、`leader` 复核，本 agent 已亲自用 `git show` + `grep` 独立坐实。**
> **它推翻了本文档 U7.3 的一处关键推断、并修正了 U9 #4 的一处判断。原始错误论断保留在下文并逐条标注更正，以免后续读者误用。**

### C.1 事实（实测）

`lib/include/sys/pcpu.h`（f-stack 的 override头，**HEAD `ff09a17b2` 版**，`git show HEAD:lib/include/sys/pcpu.h` 实测）：
```
31:#include_next <sys/pcpu.h>
32:#undef curcpu
34:#define curcpu    0          ← ★ 硬编码为字面量 0
```
覆盖的是上游 `freebsd/sys/pcpu.h:218 #define curcpu PCPU_GET(cpuid)`（实测同文件`:216-222`）。

而 **UMA 的 per-cpu cache 全部按 `zone->uz_cpu[curcpu]` 定位，共 11 处**（实测 `grep -c 'uz_cpu\[curcpu\]' freebsd/vm/uma_core.c` = **11**）：
```
freebsd/vm/uma_core.c:1452, 3738, 3776, 3818, 3901, 4534, 4543, 4595, 4628, 4803, 4853
        cache = &zone->uz_cpu[curcpu];
```
**它们完全不经过 `zpcpu_get()` / `pc_zpcpu_offset`。**

### C.2 由此得到的正确因果链（替换U7.3 的错误推断）

f-stack 的 per-cpu 定位其实有**两套彼此独立**的机制：

| 机制 | 定位方式 | 由谁使用 | HEAD 基线下的行为 |
|---|---|---|---|
| **A. `zpcpu_get()` 系** | `base + pcpup->pc_zpcpu_offset`，`pc_zpcpu_offset = 4096*cpuid`（`subr_pcpu.c:96` + U1） | **SMR**（`freebsd/sys/smr.h`的 `smr_enter/exit`、`subr_smr.c:439 zpcpu_get_cpu`）、counter zone 的分配侧 | 所有 worker 的 `pc_cpuid==0` → offset 都是 0 → **共享同一个 `c_seq` 槽位**（doc-16 §8.1 的 UAF 窗口） |
| **B. `curcpu` 系** | `zone->uz_cpu[curcpu]`，而 `curcpu` **是字面量 0** | **UMA per-cpu cache 的全部 11 处快/慢路径入口** | **无论 `pc_cpuid` 是多少，所有线程恒用 `uz_cpu[0]`** |

**因此**：
1. **`b90ddcba5` 引入 `uma_crit_lock` 的真正根因是机制 B** —— 多线程共享 `uz_cpu[0]`，与 `pc_zpcpu_offset` **毫无关系**。这也解释了为什么 `ff09a17b2` 把 cpuid 改回 0 之后**仍必须保留那把全局锁**：改cpuid 对机制 B 一点作用都没有。
2. **只让 `pcpu_init()` 用稠密 cpuid（机制 A）并不能隔离 UMA per-cpu cache**。**G1 必须同时把 `curcpu` 改回上游语义**，即 `lib/include/sys/pcpu.h:34` 从 `#define curcpu 0` 改为 `#define curcpu PCPU_GET(cpuid)`。
   —— 实测 `coder` 已在工作树实施该改动（当前 `lib/include/sys/pcpu.h:34` = `#define curcpu    PCPU_GET(cpuid)`），**与本节结论一致**。
3. **G2（移除 `uma_crit_lock`）的前置条件因此要改写为「机制 A 与机制 B 都做到每线程独占」**，二者缺一不可。本文档 U7 §7.2 的「线程上下文穷尽」与 U13 的结论（只有主线程 + N-1 个 worker 会进 UMA，且都有 `pcpup`）**不受影响，仍然成立**；受影响的只有 U7.3 关于「稠密槽位即足够」的推断。

### C.3 `curcpu` 由 `0` 改为 `PCPU_GET(cpuid)` 的**影响面穷尽**（编译集合 254 文件内，实测 `grep -n -H -w curcpu`）

| # | 位置 | 用法 | 改动后是否安全 |
|---|---|---|---|
| 1 | `freebsd/vm/uma_core.c` 11 处 | `&zone->uz_cpu[curcpu]` | **安全且是本次改动的目的**。前提：`uz_cpu[]` 已按 `mp_maxid+1` 分配（`uma_core.c:3180`）、`zone_update_caches()` 已逐槽初始化（`:2873-2875`）→即 **H1 必须成立**（`mp_maxid` 在 `uma_startup1` 前定型） |
| 2 | `lib/ff_kern_synch.c:105` | `_sleep(&pause_wchan[curcpu], ...)`，`:59 static uint8_t pause_wchan[MAXCPU];` | 改动后索引变成 `0..N-1` → **必须 `MAXCPU ≥ N`**（否则取到数组外地址；只取地址不解引用故不崩，但会与相邻静态变量地址混淆）。**这修正了本文档 U9 #4 的判断依据**：在 HEAD 基线上`curcpu==0`，该处**本来并不越界**；越界风险是 `curcpu` 改动**引入**的 |
| 3 | `freebsd/netinet/tcp_timer.c:237` 与 `:249` | `inp_to_cpuid()` 的两条兜底 `return (curcpu);` | 改动后返回 `0..N-1`，随后作为 `callout_reset_sbt_on()` 的 cpu 实参（`tcp_timer.c:896,932`）→ 落入 `lib/ff_kern_timeout.c:730 cpu >= MAXCPU` 判断 → **必须 `MAXCPU ≥ N`**。**这是 U11 结论的一条新增触发路径**（U11 原先只列了 `% (mp_maxid+1)` 那条，`curcpu` 兜底这两条同样会产出非 0 值） |
| 4 | `freebsd/netinet/tcp_hpts.c:1587` | `rp_ent[(curcpu % tcp_pace.rp_num_hptss)]` | **安全**（取模）。与 U16 结论一致 |
| 5 | `freebsd/netinet/tcp_hpts.c:1566` | `CPU_ISSET(curcpu, &tcp_pace.grps[i]->cg_mask)` | 仅 `grp_cnt > 1` 分支可达，而 `cpu_top == NULL → grp_cnt = 1`（`:1890`，U16 §16.5）→ **不可达** |
| 6 | `freebsd/netinet/tcp_lro.c:1210,1216` | `if (lc->lro_last_cpu == curcpu) ... lc->lro_last_cpu = curcpu;` | **安全**。`lro_last_cpu` 只经`tcp_lro_hpts.c:576-577` 流向 `t_lro_cpu`，而该文件**不参与编译**（U16 §16.4已实测 `ls lib/tcp_lro_hpts.o` = No such file）→ 不进入任何数组索引 |
| 7 | `freebsd/net/netisr.c:839` | `*cpuidp = netisr_get_cpuid(curcpu);`，而 `netisr.c:277-279netisr_get_cpuid(u_int cpunumber) { return (nws_array[cpunumber % nws_count]); }` | **安全**（取模）。另注：`nws_count` 为 0 时会除零，但这与 `curcpu` 无关、是既有行为（且 `swi_add()` 为空 stub、netisr 路径实际不运行，U7-b） |
| 8 | `freebsd/net/netisr.c:1172` | `if (cpuid != curcpu)` |仅比较，安全 |
| — | `freebsd/netinet/tcp_timer.c:243`、`freebsd/netinet/tcp_hpts.c:1073` | 注释 | 不适用 |

**C.3 小结**：`curcpu` 改回`PCPU_GET(cpuid)` 后，新增的硬约束仍然只是 **`MAXCPU ≥ N`**（由 #2 与 #3 两处引入，与 U9/U11 已有的结论合并同一条），**没有引入任何新的数组越界风险**；其余 6 处都是取模或纯比较。

### C.4 本文档中受本条更正影响的具体论断（逐条标注）

| 位置 | 原论断 | 更正后 |
|---|---|---|
| U7 §7.3 第2 个bullet | 「在稠密索引 + 每线程 1:1 独占槽位下，`curcpu = PCPU_GET(cpuid) = pcpup->pc_cpuid`…`&zone->uz_cpu[curcpu]` 因此是线程私有的 → **成立**」 | **前提不成立**：HEAD 基线 `curcpu` 是字面量 `0`。该结论只有在**同时**把 `lib/include/sys/pcpu.h:34` 改为 `#define curcpu PCPU_GET(cpuid)` 之后才成立。已在 §7.3 原文处就地加了更正标注 |
| U9 #4（`pause_wchan[MAXCPU]`） | 「`&pause_wchan[i]`（i≤N-1）越出数组…」 | HEAD 基线**不越界**（`curcpu==0`）；越界风险由 `curcpu` 改动引入。**要求 `MAXCPU ≥ N` 的结论不变**，但归因需改。已在 U9 表内就地标注 |
| U8 §8.4 第 2 点 | 「`uma_crit_lock` 目前事实上起到了缩小慢路径并发窗口的副作用…这解释了为什么 `b90ddcba5` 加上这把锁就修好了 SIGSEGV」 | **补强而非推翻**：真正被这把锁保护的是「所有线程共享 `uz_cpu[0]`」这一**必然**冲突（机制 B），而非概率性的慢路径竞态。已在 §8.4 就地补注 |
| U1 / U2 / U4 / U5 / U6 / U10 / U11 / U13 / U14 / U15 / U16 | — | **不受影响**（U1 关于 `zpcpu_offset_cpu`/`zpcpu_get` 的结论对**机制 A（SMR）**依然完全正确） |

---

## U1 `zpcpu_offset_cpu` 最终展开值与 `UMA_PCPU_ALLOC_SIZE` 实际数值

> 本节结论适用于 **C-更正 §C.2 的「机制 A（`zpcpu_get()` 系，SMR 使用）」**，不受 `curcpu` 更正影响。

### 结论（全部由 `gcc -E` 预处理实证，非推测）

| 宏 | 最终展开 | 数值 |
|---|---|---|
| `MAXCPU` | `1` | **1** |
| `PAGE_SIZE` | `(1<<12)` | **4096** |
| `CACHE_LINE_SIZE` | `(1 << 6)` | 64 |
| `UMA_PCPU_ALLOC_SIZE` | `(1<<12)` | **4096（== PAGE_SIZE，确认）** |
| `zpcpu_offset_cpu(cpu)` | `((1<<12) * cpu)` | **4096 * cpu** |
| `zpcpu_offset()` | `((pcpup->pc_zpcpu_offset))` | f-stack `__thread pcpup` 版|
| `zpcpu_get(base)` | `({ __typeof(base) _ptr = (void *)((char *)(base) + ((pcpup->pc_zpcpu_offset))); _ptr; })` | — |
| `zpcpu_get_cpu(base,3)` | `({... (char *)(base) + ((1<<12) * 3) ... })` | base + 12288 |
| `PCPU_GET(cpuid)` | `(pcpup->pc_cpuid)` | f-stack override |
| `PCPU_SET(zpcpu_offset,7)` | `(pcpup->pc_zpcpu_offset = (7))` | f-stack override |
| `curthread` | `__curthread_ff()` | f-stack override |
| `CPU_SETSIZE` | `1` | **1** |
| `zpcpu_base_to_offset(base)` | `(base)`（恒等） | `freebsd/sys/pcpu.h:242` 默认版生效 |
| `SMP` | **not_defined** | — |
| `INVARIANTS` | **not_defined** | — |
| `UMA_MD_SMALL_ALLOC` | **not_defined** | 被 `lib/include/vm/uma_int.h:43` `#undef` |

### 证据

1. 预处理探针（临时文件 `lib/_m17_probe_u1.c`，照抄上面第0 节的真实参数，仅把 `-c` 换成 `-E`）实测输出：

```
PROBE_MAXCPU = 1;
PROBE_PAGE_SIZE = (1<<12);
PROBE_CACHE_LINE_SIZE = (1 << 6);
PROBE_UMA_PCPU_ALLOC_SIZE = (1<<12);
PROBE_ZPCPU_OFFSET_CPU_0 = ((1<<12) * 0);
PROBE_ZPCPU_OFFSET_CPU_1 = ((1<<12) * 1);
PROBE_ZPCPU_OFFSET_CPU_N = ((1<<12) * nnn);
PROBE_ZPCPU_OFFSET = ((pcpup->pc_zpcpu_offset));
PROBE_ZPCPU_GET = ({ __typeof(basep) _ptr = (void *)((char *)(basep) + ((pcpup->pc_zpcpu_offset))); _ptr; });
PROBE_ZPCPU_GET_CPU = ({ __typeof(basep) _ptr = (void *)((char *)(basep) + ((1<<12) * 3)); _ptr; });
PROBE_PCPU_GET_CPUID = (pcpup->pc_cpuid);
PROBE_PCPU_SET_ZOFF = (pcpup->pc_zpcpu_offset = (7));
PROBE_CURTHREAD = __curthread_ff();
PROBE_CPU_SETSIZE = 1;
PROBE_SMP_IS = not_defined;
PROBE_INVARIANTS_IS = not_defined;
PROBE_UMA_MD_SMALL_ALLOC_IS = not_defined;
PROBE_ZPCPU_BASE_TO_OFFSET_DEFINED = yes;
PROBE_ZPCPU_BASE_TO_OFFSET = (basep);
```

2. 定义链（实际打开文件确认）：
   - `freebsd/sys/pcpu.h:221` `#define UMA_PCPU_ALLOC_SIZE PAGE_SIZE`
   - `freebsd/sys/pcpu.h:234-236` `#ifndef zpcpu_offset_cpu` / `#define zpcpu_offset_cpu(cpu) (UMA_PCPU_ALLOC_SIZE * cpu)` → **实测生效的就是这个默认定义**。
   - `freebsd/amd64/include/param.h`的 `PAGE_SIZE` = `(1<<PAGE_SHIFT)`，`PAGE_SHIFT=12` → 4096（预处理输出 `(1<<12)` 佐证）。

###对 plan 假设的一处纠偏（重要）

plan-17 §1.1 写「`lib/include/amd64/include/pcpu.h:28-46` `#undef zpcpu_offset_cpu` 后未重定义，需确认最终生效的是 `freebsd/sys/pcpu.h:236`」——结论**成立**，但真正的原因不是那个 `#undef`：

- `freebsd/amd64/include/pcpu.h:269-273`：
  ```c
  #ifndef FSTACK
  #define zpcpu_offset_cpu(cpu)	((uintptr_t)&__pcpu[0] + UMA_PCPU_ALLOC_SIZE * cpu)
  #define zpcpu_base_to_offset(base) (void *)((uintptr_t)(base) - (uintptr_t)&__pcpu[0])
  #define zpcpu_offset_to_base(base) (void *)((uintptr_t)(base) + (uintptr_t)&__pcpu[0])
  #endif
  ```
  因为编译命令带 `-DFSTACK`，**这三个宏在 amd64 机器头里根本没被定义过**。故 `lib/include/amd64/include/pcpu.h:40-42` 的三个 `#undef`（由 `b90ddcba5` 引入，见 U7）在当前配置下是**冗余**的，真正的守门人是 `#ifndef FSTACK`。

### 对方案的影响

- `zpcpu_offset_cpu(cpu) = 4096*cpu`、`zpcpu_get(base) = base + pcpup->pc_zpcpu_offset`：只要 `pcpu_init(pcpup, i, ...)` 传稠密`i`，`pc_zpcpu_offset` 自然变成 `4096*i`（`freebsd/kern/subr_pcpu.c:96`），**无需改动任何宏**。这是候选 B 的关键便利条件。
- **per-cpu 分配粒度被硬编码为 4096 字节/CPU**（不是 `roundup(uz_size, cacheline)`）。故 N 线程的 pcpu zone 每个 item 必须至少 `N*4096` 字节；这与 `keg_layout` 的 `pages *= mp_maxid + 1`（`uma_core.c:2474`）一致。
- `MAXCPU == 1` 是 `freebsd/amd64/include/param.h`在 `#else`（非 SMP）分支**无条件**给出的；`CPU_SETSIZE == 1`。见 U4 的 ABI 讨论。
- `INVARIANTS` 未定义 → `subr_pcpu.c:88` 的 `KASSERT(cpuid < MAXCPU)`、`uma_core.c:2351` `keg_layout` 的 PCPU KASSERT、`uma_core.c:1970/2183` 的 `MPASS` **全部编译掉**，所以「越界」不会被断言拦住，只会静默踩内存（上一轮 SIGSEGV 正是如此）。**这意味着方案正确性不能依赖断言，必须靠代码结构保证。**

---

## U2 实际编译进来的 `pcpu_page_alloc` 是哪一版+ `page_alloc` 能力

### 结论

1. **编译进来的是 `freebsd/vm/uma_core.c:2083-2089` 的回退版**（`*pflag = UMA_SLAB_KERNEL; return page_alloc(...)`），`:1959` 的逐 CPU `vm_page_alloc_noobj` 版**未编译**。
   - 分界不是 `UMA_MD_SMALL_ALLOC`，而是 `freebsd/vm/uma_core.c:1957` 的 **`#ifndef FSTACK`**（`:2082` 是它的 `#else`）。
2. **但当前这条路径实际上是死代码**：`keg_ctor()` 在 `freebsd/vm/uma_core.c:2546-2548` `#ifndef SMP` → `keg->uk_flags &= ~UMA_ZONE_PCPU;`，把 PCPU 标记剥离，于是 `:2577` 的 `else if (keg->uk_flags & UMA_ZONE_PCPU) keg->uk_allocf = pcpu_page_alloc;` 永不命中，所有 keg 都落到 `:2582` `page_alloc`。
3. f-stack 的 `page_alloc` 底座是 **匿名 `mmap`**，能稳定分配任意 `bytes`（含 `(mp_maxid+1)*PAGE_SIZE`），且返回**页对齐、虚拟地址连续**的区域—— 这恰好满足 `zpcpu_offset_cpu(cpu)=4096*cpu` 的连续性假设（上游 `pcpu_page_alloc` 也是把各 CPU 的物理页 `pmap_qenter` 到**连续 KVA**）。

### 证据

1. 预处理实测（`cc -E` 整个 `uma_core.c`，输出 `_m17_uma_core.i`），`grep -n pcpu_page_alloc`：
   ```
   10578:static void *pcpu_page_alloc(uma_zone_t, vm_size_t, int, uint8_t *, int);
   11869:pcpu_page_alloc(uma_zone_t zone, vm_size_t bytes, int domain, uint8_t *pflag,
   12170:  keg->uk_allocf = pcpu_page_alloc;
   12238:  keg->uk_allocf = pcpu_page_alloc;
   ```
   `sed -n '11860,11880p'` 实测函数体：
   ```
   # 2083 "/data/workspace/f-stack/lib/../freebsd/vm/uma_core.c"
   static void *
   pcpu_page_alloc(uma_zone_t zone, vm_size_t bytes, int domain, uint8_t *pflag,
       int wait)
   {
    *pflag = 0x04;
    return page_alloc(zone, bytes, domain, pflag, wait);
   }
   ```
   `# 2083` 的行号标记直接坐实是 `:2084` 那一版。
2. 编译产物符号（`nm lib/uma_core.o`）实测：
   ```
                    U kmem_malloc_domainset
   0000000000000330 t page_alloc
   0000000000001210 t pcpu_page_alloc
   ```
   两者都是本地符号，`pcpu_page_alloc` 体积小（紧跟 `page_alloc` 之后），与回退版一致。
3. 分配链：`freebsd/vm/uma_core.c:1946-1955` `page_alloc()` → `kmem_malloc_domainset(DOMAINSET_FIXED(domain), bytes, wait)`（预处理为 `kmem_malloc_domainset((&domainset_fixed[(domain)]), bytes, wait)`）→ `lib/ff_glue.c:1250-1253`：
   ```c
   kmem_malloc_domainset(struct domainset *ds, vm_size_t size, int flags)
   { return (kmem_malloc(size, flags)); }
   ```
   → `lib/ff_glue.c:1025-1032`：
   ```c
   void * kmem_malloc(vm_size_t bytes, int flags)
   {
       void *alloc = ff_mmap(NULL, bytes, ff_PROT_READ|ff_PROT_WRITE,
                             ff_MAP_ANON|ff_MAP_PRIVATE, -1, 0);
       if ((flags & M_ZERO) && alloc != NULL) bzero(alloc, bytes);
       return (alloc);
   }
   ```
4. `keg_layout` 对 PCPU keg 的布局（`freebsd/vm/uma_core.c:2472-2479`）：
   ```c
   pages = atop(kl.slabsize);
   if ((keg->uk_flags & UMA_ZONE_PCPU) != 0)
           pages *= mp_maxid + 1;
   keg->uk_rsize = rsize; keg->uk_ipers = kl.ipers; keg->uk_ppera = pages;
   ```
   以及 `:2406-2407`（PCPU keg 不允许 inline slab头）、`:2466-2469`（PCPU keg 不做multipage 迭代）、`:2486-2492`（OFFPAGE 时按 `UMA_ZONE_NOTPAGE` 选`UMA_ZFLAG_HASH` 或 `UMA_ZFLAG_VTOSLAB`）。

### 对方案的影响 / 风险（含未坐实项）

- **候选 B 若保留 `UMA_ZONE_PCPU`（放开 `:2546`），slab 大小会变成 `N*PAGE_SIZE`，走 `pcpu_page_alloc` → `page_alloc` → `mmap(N*4096)`。功能上可行**（mmap 天然连续、页对齐）；**代价**：失去 NUMA 亲和（上游是逐 CPU 就近分配物理页），本项目单机单NUMA 场景可接受。
- **⚠ 未坐实项 U2-a（须交给 M1-C/M3 编译+运行验证）**：`uk_ppera > 1` 的 slab 在 f-stack 的 **`UMA_PAGE_HASH` 反查表**（`lib/include/vm/uma_int.h:65-126`：`vtoslab/vtozoneslab/vsetzoneslab`，按 `va >> PAGE_SHIFT & uma_page_mask` 逐页哈希）下是否每一页都被登记。`vtoslab()` 用 `up_va == (va & ~(PAGE_SIZE-1))` 精确匹配**单页**，所以多页 slab 必须对每一页调用一次 `vsetzoneslab`。我未能在静态阅读中把 `uma_core.c` 里 `vsetzoneslab` 的调用点与「多页 slab 逐页登记」对应关系完全坐实（`UMA_ZFLAG_VTOSLAB` 路径 vs `UMA_ZFLAG_HASH` 路径分叉较多）。**建议手段**：M3 阶段在 `smr_create()`/`counter_u64_alloc()` 之后加临时探针，对 `item` 的每一页调 `vtoslab()` 断言非 NULL；或直接在 `uma_zfree_pcpu` 上跑压测看是否 `vtozoneslab` 拿到 NULL `up` 而崩（`uma_int.h:101` 的 `*slab = up->up_slab` 对 NULL `up` 会直接段错）。
- **⚠ 未坐实项 U2-b**：`uma_page_slab_hash` 的桶数由 `lib/ff_freebsd_init.c:305` `kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO)` 决定，`num_hash_buckets` 的取值与 `uma_page_mask` 的设置我未逐行核到（须读 `ff_freebsd_init.c` 290-320 完整段）。若 pcpu zone 让 slab 页数暴增，哈希链会变长（性能）而非正确性问题。
- **`vsetzoneslab()`（`lib/include/vm/uma_int.h:105-126`）内部 `malloc` + `LIST_INSERT_HEAD` 无任何锁**。这是一个 f-stack 自有的全局可变结构，见 U8 的并发讨论。

---

## U7（第 1 部分）`uma_crit_lock` 的引入动机 —— `git show b90ddcba5` 实测

### 结论

`uma_crit_lock` 是为修复 **2 线程启动时 `kqueue_kevent` 里 memset 到地址 0 的 SIGSEGV** 而引入的**权宜串行化**；同一提交里 worker 的 `pcpu_init` 用的是 `rte_lcore_id()`（**稀疏且可能 ≥ MAXCPU=1**）。也就是说：**这个全局锁与「worker 用了非法/共享 pcpu 槽位」是同一次修复的两面**，锁本身是为了掩盖 per-cpu 槽位不隔离带来的竞态。

### 证据（`git --no-pager show b90ddcba5` 实际输出摘录）

commit message：
```
Fix UMA per-CPU cache race and sizeof mismatch for native-mt multi-thread startup

- Serialize UMA per-CPU cache access via spinlock in critical_enter/exit
  (uma_int.h + uma_crit_lock in ff_glue.c) to fix kqueue_kevent memset
  SIGSEGV at 0 on 2-thread startup.
- Fix malloc(sizeof(struct proc)) -> sizeof(struct thread) in ff_compat.c.
- Pass rte_lcore_id() as cpuid to ff_pcpu_thread_init/ff_stack_thread_init
  for per-thread pcpu init.
- Worker temporarily shares vnet0 (skips vnet_alloc) ...
- Reverted rmlock global lock attempt ...
```

改动文件（`--stat`）：`lib/ff_compat.c` (2)、`lib/ff_dpdk_if.c` (4)、`lib/ff_freebsd_init.c` (18)、`lib/ff_glue.c` (1)、`lib/include/amd64/include/pcpu.h` (3)、`lib/include/vm/uma_int.h` (10) + 1 篇文档。

关键 diff：
```diff
--- a/lib/include/vm/uma_int.h
-#define critical_enter() do {} while(0)
-#define critical_exit()  do {} while(0)
+extern volatile int uma_crit_lock;
+#define critical_enter() do { \
+    while (__sync_lock_test_and_set(&uma_crit_lock, 1)) \
+        ; \
+} while(0)
+#define critical_exit()  do { \
+    __sync_lock_release(&uma_crit_lock); \
+} while(0)
```
```diff
--- a/lib/ff_glue.c
 u_int mp_maxid;
+volatile int uma_crit_lock;
```
```diff
--- a/lib/ff_freebsd_init.c
-ff_pcpu_thread_init(void) {pcpu_init(pcpup, 0, sizeof(struct pcpu)); }
+ff_pcpu_thread_init(int cpuid) { pcpu_init(pcpup, cpuid, sizeof(struct pcpu)); }
...
-    ff_pcpu_thread_init();
+    ff_pcpu_thread_init(0);
     CPU_SET(0, &all_cpus);
```
```diff
--- a/lib/ff_dpdk_if.c
-    ff_stack_thread_init();
+    ff_stack_thread_init(rte_lcore_id());
```
```diff
--- a/lib/include/amd64/include/pcpu.h
 #undef PCPU_SET
+#undef zpcpu_offset_cpu
+#undef zpcpu_base_to_offset
+#undef zpcpu_offset_to_base
```

### 三个可核查的事实（对G2 决策直接相关）

1. **`b90ddcba5` 之前 `critical_enter/exit` 就已经是 no-op**（`do {} while(0)`）。即 f-stack 单线程时代根本没有关抢占语义；全局锁是**新增**的串行化，不是「恢复上游语义」。
2. **该锁的粒度是「整个 UMA 快路径全局串行」**：`critical_enter/exit` 在 `uma_core.c` 中被 `cache_alloc*`/`cache_free*`/`uma_zalloc_smr`/`uma_zfree_smr` 等大量调用，且 `uma_int.h` 的宏是**编译单元级替换**，凡 include `vm/uma_int.h` 的 .c 都受影响。
3. **`ff09a17b2`（当前 HEAD）把 cpuid 又改回 0**，但**没有**回退这个全局锁。所以现在是「共享槽位 + 全局锁」的组合：锁保护了 UMA cache 的互斥，但**并不能**修复 SMR `c_seq` 槽位被多线程互相覆盖（`smr_enter/smr_exit` 在 `freebsd/sys/smr.h` 里走 `zpcpu_get(smr)`，其读写并不都在 `critical_enter/exit` 的 UMA 宏覆盖范围内 —— 该点见 U7 第 2 部分）。

---

## U4 `mp_maxid`/`mp_ncpus`/`mp_maxcpus`/`all_cpus` 读者穷尽清单

### 方法（限定在实际参与编译的源文件集合内）

`lib/Makefile` 的 `SRCS` 是多段拼接的 make 变量，不便静态解析，故采用**更强的实证**：直接以 `lib/` 目录里**已存在的 `.o` 反推**（上一次完整 build 的真实产物）：

```
cd /data/workspace/f-stack/lib && ls *.o | wc -l     ->  248
```
把 248 个 `.o` 映射回 `.c` 后在 `lib/` + `freebsd/` 内解析出**254 条路径**（>248 是因少数基名在多个目录同时存在，如 `in_cksum.c`；属**过近似**，只会多报不会漏报），形成 `_m17_srcpaths.txt`，后续所有 grep 都限定在该清单内。

> 说明：`lib/Makefile` 里 `subr_counter.c`（第 357行）、`subr_pcpu.c`（363）、`subr_smr.c`（367）、`uma_core.c`（`VM_SRCS`，650）**均在 `KERN_SRCS`/`VM_SRCS` 中**，`.o` 也确实存在，故 counter(9)/pcpu/SMR/UMA 全部参与编译。

### 4.1 `mp_maxid` 全部读者（实测 grep 输出，共 24 处）

| 位置 | 用法 | `mp_maxid>0` 后是否安全 |
|---|---|---|
| `lib/ff_glue.c:145` | 定义 `u_int mp_maxid;`（BSS=0） | 写入点，需改|
| `lib/ff_glue.c:151` | `SYSCTL_INT(_kern_smp, maxid, ...)` | 安全（只读导出） |
| `freebsd/vm/uma_int.h:529` | **`#define ZDOM_GET(z,n) (&((uma_zone_domain_t)&(z)->uz_cpu[mp_maxid + 1])[n])`** | **⚠ 最高危：见下方「硬约束 H1」** |
| `freebsd/vm/uma_core.c:3180` | `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + sizeof(struct uma_zone_domain)*vm_ndomains`（`uma_startup1`） | 安全**前提**是 H1 |
| `freebsd/vm/uma_core.c:2873` | `zone_update_caches()`：`for (i=0;i<=mp_maxid;i++) cache_set_uz_size(&zone->uz_cpu[i],...)` | 安全**前提**是 H1 |
| `freebsd/vm/uma_core.c:562,583,674` | UMA 统计/`uz_cpu` 遍历 | 同上 |
| `freebsd/vm/uma_core.c:2474` | `keg_layout`：`pages *= mp_maxid + 1`（仅 PCPU keg） | 安全（与 U2 配套） |
| `freebsd/vm/uma_core.c:1970,2183` | `MPASS(bytes == (mp_maxid+1)*PAGE_SIZE)` | 已编译掉（`INVARIANTS` 未定义），且 1970 在未编译的 `#ifndef FSTACK` 段 |
| `freebsd/vm/uma_core.c:1975` |未编译的 `#ifndef FSTACK` 段 | 不适用 |
| `freebsd/vm/uma_core.c:3509` | `uma_zalloc_pcpu_arg` 的 `#ifdef SMP` 分支 `for (i=0;i<=mp_maxid;i++) bzero(zpcpu_get_cpu(...))` | **未编译**（`SMP` 未定义）→ 目前只`bzero(item, uz_size)` 一份。**⚠ 见「硬约束 H2」** |
| `freebsd/vm/uma_core.c:5589,5620,5637,5674,5684,5787` | `sysctl vm.zone*` 统计（`malloc((mp_maxid+1)*...)`、`ush_maxcpus`） | 安全（按`mp_maxid` 自适应） |
| `freebsd/kern/subr_smr.c:598` | `smr_create()`：`for (i=0;i<=mp_maxid;i++){c=zpcpu_get_cpu(smr,i); c->c_seq=...;}` | **⚠ 见「硬约束 H2」** |
| `freebsd/kern/uipc_socket.c:449,1636` | `so_splice` 的 `mallocarray(mp_maxid+1,...)` 与 `wq_index % (mp_maxid+1)` | 安全，且 `splice_init()` 是**懒初始化**（`uipc_socket.c:435-450`，仅 `SO_SPLICE` 首次使用时触发），f-stack 场景不触发 |
| `freebsd/net/netisr.c:1038-1039` | `KASSERT(cpuid <= mp_maxid)` | 已编译掉 |
| `freebsd/netinet/tcp_timer.c:246-248` | `inp_to_cpuid()`：`cpuid = inp->inp_flowid % (mp_maxid+1); if (!CPU_ABSENT(cpuid)) return cpuid;` | **需注意**：返回值最终传给 `callout_reset_*_on(..., cpu, ...)`。f-stack 的 `lib/ff_kern_timeout.c:184-185` `#define CC_CPU(cpu) &cc_cpu` / `CC_SELF() &cc_cpu` **忽略 cpu 参数**，返回本线程 `__thread cc_cpu`，所以行为不变；但 `lib/ff_kern_timeout.c:730` 有 `else if ((cpu >= MAXCPU) || ((CC_CPU(cpu))->cc_inited == 0)) panic("Invalid CPU in callout %d", cpu);` —— **若 `MAXCPU` 仍为 1 而 `mp_maxid` 被抬到 N-1，`inp_to_cpuid()` 会返回 1..N-1，触发 `cpu >= MAXCPU` 的 `panic`**。⚠ 见「硬约束 H3」 |

### 4.2 `mp_ncpus` 全部读者（实测，共 16 处）

| 位置 | 用法 | 抬到 N 后 |
|---|---|---|
| `lib/ff_glue.c:140` | `int mp_ncpus = 1;` | 写入点 |
| `lib/ff_kern_timeout.c:1212,1215,1216` | 仅 `printf` 里做除数 | 安全（非 0 即可） |
| `lib/ff_ng_base.c:3249` | `numthreads = mp_ncpus;`（netgraph worker 数） | **需评估**：会让 netgraph 起 N 个 worker；`FF_NETGRAPH=1` 已开启 |
| `freebsd/net/netisr.c:1308,1309,1312` | `netisr_maxthreads` 上限钳位；**`netisr.c:169` `static int netisr_maxthreads = 1;` 默认 1** | 安全（默认值不变，只是允许上限变大） |
| `freebsd/netinet/tcp_hpts.c:473,1089,1864` | `cpuid = ... % mp_ncpus`选 hpts 槽 | **需评估**：`TCPHPTS` 已开启（`-DTCPHPTS`）。`tcp_hpts.c:1864 uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;` 决定 `rp_num_hptss`，抬高后会创建 N 个 hpts 实例|
| `freebsd/netpfil/ipfw/ip_fw_dynamic.c:3236` | `malloc(mp_ncpus * sizeof(void*))` | 安全（按值分配） |
| `freebsd/vm/uma_core.c:5042` | `nb = bpcpu * mp_ncpus + bpdom * vm_ndomains;`（bucket 预热数） | 安全（只影响预分配量） |
| `freebsd/kern/subr_lock.c:149` | `lc->max = min(lock_roundup_2(mp_ncpus)*256, SHRT_MAX)` | 安全 |

> **结论**：`mp_ncpus` 与 `mp_maxid` **可以解耦**（这一点已由 **U16 §16.2~16.4 从「是否越界」角度彻底坐实：解耦不会造成 `tcp_pace.rp_ent[]` 越界**，因为 `hpts_cpuid()` 用的是 `% mp_ncpus`（`tcp_hpts.c:1089`）而 `inp_to_cpuid()` 用的是 `% (mp_maxid+1)`（`tcp_timer.c:246`），两者是**两套独立编号**）。若只需per-cpu 槽位隔离，**只抬 `mp_maxid`（+`all_cpus`）而把 `mp_ncpus` 保持 1** 可以规避 `ff_ng_base.c:3249`（实测无影响，见 U14）与 `tcp_hpts.c:1864` 的连带影响；**但会让 N 个 worker 共享同一个无锁 hpts 队列**。取舍见 **U16 §16.6**，**须由 designer 显式裁决**。

### 4.3 `mp_maxcpus` / `all_cpus`

- `mp_maxcpus`：仅 `lib/ff_glue.c:142`（`= MAXCPU`）与 `:154`（sysctl 导出）。**无功能读者**，安全。
- `all_cpus`：仅 3 处 —— `lib/ff_glue.c:138` 定义、`lib/ff_freebsd_init.c:88` extern、**`lib/ff_freebsd_init.c:294` `CPU_SET(0, &all_cpus);`**。
  - **⚠ 硬约束 H4**：`CPU_FOREACH(i)` 预处理实测展开为
    ```c
    for((i) = 0; (i) <= mp_maxid; (i)++) if (!(!(CPU_ISSET(i, &all_cpus))))
    ```
    即 **`mp_maxid` 与 `all_cpus` 位图必须成对设置**。只抬 `mp_maxid` 而不 `CPU_SET(i,&all_cpus)`，所有 `CPU_FOREACH` 会静默跳过 1..N-1（统计漏算、`cache_drain` 漏回收、`smr_poll_scan` **漏扫其它线程的 `c_seq` → 直接导致 SMR 提前判定 grace period 结束 → UAF**，比现状更糟）。

### 4.4 `cpuset_t` / `CPU_SETSIZE` 的 ABI 一致性

- 预处理实测 `CPU_SETSIZE == 1`（= `MAXCPU`）。`cpuset_t` = `struct { unsigned long __bits[howmany(CPU_SETSIZE, _NCPUBITS)]; }`，`howmany(1,64)=1` → **8 字节**。
- **`MAXCPU` 从 1 抬到任意 `2..64` 时`sizeof(cpuset_t)` 仍是 8 字节**（`howmany(64,64)=1`），ABI 不变；**抬到 65 及以上才会变成 16 字节**。本轮线程数远小于 64。
- `cpuset_t` 出现在跨编译单元接口的位置（实测 grep，编译集合内仅 4 处）：`lib/ff_glue.c:138` / `lib/ff_freebsd_init.c:88`（同一个全局变量）、`freebsd/kern/subr_taskqueue.c:705,808`（`taskqueue_start_threads_cpuset()`/`_in_proc()` 的 `cpuset_t *mask` 形参）。
- **结论**：只要 `MAXCPU≤ 64`，`cpuset_t` 尺寸不变，**无跨 .o 的 ABI 风险**；但 `struct pcpu`/`struct uma_zone` 等**确实**随 `mp_maxid` 改变运行期布局（不是编译期），故必须**全树 `make clean` 重编**（这也与既有强制规约一致）。另外 `freebsd/kern/subr_pcpu.c:76-77`的 `uintptr_t dpcpu_off[MAXCPU]; struct pcpu *cpuid_to_pcpu[MAXCPU];` 是**编译期**按 `MAXCPU` 定尺寸的数组 → **`MAXCPU` 必须 ≥ 线程数**，否则 `pcpu_init()` 里 `cpuid_to_pcpu[cpuid]=pcpu`（`subr_pcpu.c:91`）直接越界写（且 `KASSERT` 已编译掉，不会报错）。这正是上一轮 SIGSEGV 的机制之一。

### 4.5 counter(9)：`mp_maxid` 抬高后是否越界/漏统计

**结论：counter(9) 在 f-stack 里已被彻底「去 per-cpu 化」，`mp_maxid` 抬高对其无越界风险，但会引入一处「分配变大、访问仍只用第0 槽」的浪费与已存在的数据竞争。**

证据（`lib/include/amd64/include/counter.h`，f-stack override）：
```c
:38-39#define counter_enter() do {} while (0)     /* 上游是 critical_enter() */
        #define counter_exit()  do {} while (0)
:43-47  static inline uint64_t counter_u64_fetch_inline(uint64_t *p) { return (*p); }
:49-53  static inline void counter_u64_zero_inline(counter_u64_t c) { *c = 0; }
:56#define counter_u64_add_protected(c, i)  counter_u64_add(c, i)
:58-62  static inline void counter_u64_add(counter_u64_t c, int64_t inc) { *c += inc; }
```
即 **`counter_u64_add/fetch/zero` 完全不走 `zpcpu_get()`，只读写基指针指向的第 0 个槽**（对比 `freebsd/i386/include/counter.h:101,123,157,169` 的上游实现，那里是 `+ UMA_PCPU_ALLOC_SIZE * cpu`）。`freebsd/kern/subr_counter.c:46-57` 的 `counter_u64_zero/fetch` 只是转调这些 inline，因此**没有 `CPU_FOREACH` 聚合**。

- 越界风险：**无**（永远只碰第 0 槽）。
- 分配侧：`subr_counter.c:63` `counter_u64_alloc()` = `uma_zalloc_pcpu(pcpu_zone_8, flags|M_ZERO)`；`pcpu_zone_8` 由 `freebsd/kern/subr_pcpu.c:148-149` 以 `UMA_ZONE_PCPU` 创建。若放开 `uma_core.c:2546` 的 PCPU 剥离，每个 counter 会占`N*4096` 字节（**每个** counter！）——f-stack 里 counter 数量众多（每个 zone 2 个 +各协议栈统计），**内存放大需评估**。
- 竞争：`*c += inc` 非原子、多线程共享同一 u64 → **今天就已存在**统计计数丢失（非内存安全问题）。本轮不改变这一现状。

### 4.6 三条硬约束（对方案的强制要求）

- **H1（`mp_maxid` 必须在第一个 zone 创建之前定型且此后永不变）**：`ZDOM_GET`（`freebsd/vm/uma_int.h:529`）用 `uz_cpu[mp_maxid+1]` 定位 zone-domain 数组，而 zone 的实际字节数在 `uma_startup1()`（`uma_core.c:3179-3181`）就按当时的 `mp_maxid` 算定。调用序实测为 `lib/ff_freebsd_init.c:301 uma_startup1()` → `:302 uma_startup2()`（内含 `uma_core.c:3233 smr_init()`）→ `:309 mi_startup()`（跑 `SYSINIT(pcpu_zones, SI_SUB_COUNTER,...)`、`SYSINIT(netisr_*)`、各 `counter_u64_sysinit`、`in_pcbinfo_init`→`smr_create`）。**故 `mp_maxid`/`all_cpus` 必须在 `ff_freebsd_init.c:301` 之前设好**（详见 U6 时序）。
- **H2（`mp_maxid` 与 `UMA_ZONE_PCPU` 必须成对）**：`smr_create()`（`subr_smr.c:598-605`）无条件 `for (i=0;i<=mp_maxid;i++) zpcpu_get_cpu(smr,i)->c_seq=...`，**不带 `#ifdef SMP`**。若只抬 `mp_maxid` 而 `keg_ctor`（`uma_core.c:2546-2548`）仍剥离 `UMA_ZONE_PCPU`，则"SMR CPU" zone 每个 item 只有 `sizeof(struct smr)` 大小，这个循环会**越界写 `N*4096` 字节范围** —— 比现状更危险。同理 `uma_zalloc_pcpu_arg` 的 `M_ZERO` 只`bzero` 一份（`:3512`，因 `SMP` 未定义），若zone 变成 N 槽，则 1..N-1 槽**未清零**（`uma_zalloc`拿到的是回收内存，`c_seq` 会是脏值）→ 必须同时放开 `:3508` 的 `#ifdef SMP` 分支或改为按 `uz_flags & UMA_ZONE_PCPU` 判断。
- **H3（`MAXCPU` 必须 ≥ 线程数，且 `ff_kern_timeout.c:730` 的 `cpu >= MAXCPU` panic 要复核）**：`subr_pcpu.c:76-77` 的 `dpcpu_off[MAXCPU]`/`cpuid_to_pcpu[MAXCPU]` 是编译期定长；`tcp_timer.c:246` 会产出 `1..mp_maxid` 的cpuid 传给 callout。**若采用「抬 `mp_maxid` 但不动 `MAXCPU`」的方案，这两处会立即崩**。
- **H4（`all_cpus` 位图必须与 `mp_maxid` 同步）**：见 4.3。

---

## U5 稠密索引后 `cpuid_to_pcpu[]`/`cpuhead`/`dpcpu_off[]` 的写入保护与运行期读者

### 5.1 写入点与现有保护

`pcpu_init()`（`freebsd/kern/subr_pcpu.c:83-97`）会写三个全局：
```c
:90  pcpu->pc_cpuid = cpuid;
:91  cpuid_to_pcpu[cpuid] = pcpu;             /* 稠密索引后各线程写不同下标 */
:92  STAILQ_INSERT_TAIL(&cpuhead, pcpu, pc_allcpu);   /* 共享链表头/尾指针 */
:96  pcpu->pc_zpcpu_offset = zpcpu_offset_cpu(cpuid);
```
现有保护：`lib/ff_freebsd_init.c:175` `static volatile int init_lock = 0;` + `:185-186` `while (__sync_lock_test_and_set(&init_lock,1));` … `:216 __sync_lock_release(&init_lock);`，把 `ff_pcpu_thread_init` 一直到 `lo_set_defaultaddr()` 全部串行化（注释见 `:181-184`）。

**结论：`init_lock` 仍然必须保留。** 理由（代码级）：
- `cpuid_to_pcpu[cpuid]=pcpu` 在稠密索引后各线程写**不同**下标，单看这一行确实不再需要锁；
- 但 **`STAILQ_INSERT_TAIL(&cpuhead, ...)`（`:92`）操作共享的 `cpuhead.stqh_last`，是典型的链表并发插入，必须串行**；
- 且 `init_lock` 覆盖的范围远大于 `pcpu_init`：`ff_init_thread0()`、`ff_adapt_user_thread_add()`（GIANT_REQUIRED、`uifind(0)`/`crget`/`EVENTHANDLER_INVOKE` 等全局操作，已在 AI memory 84914768 记录为 R1~R5）、`vnet_alloc()`（跑 VNET_SYSINIT）、`lo_set_defaultaddr()`（`socreate`+`ifioctl`）。**这些与本轮 U5 无关但同样依赖该锁**。
- 因此建议：**不缩小 `init_lock` 范围**（本轮不动它），G1/G2 的收益来自数据面而非启动路径。

### 5.2 `pcpu_find()` / `cpuhead` / `dpcpu_off[]` 的运行期读者穷尽（编译集合内）

| 读者 | 位置 | 是否真编译/运行 | 是否数据面 |
|---|---|---|---|
| `pcpu_find()` | `freebsd/vm/uma_core.c:1982` | **未编译**（在 `#ifndef FSTACK` 的 `pcpu_page_alloc` 内、且还套 `#else NUMA` 分支） | — |
| `pcpu_find()` | `freebsd/netinet/tcp_hpts.c:2032` | **未编译**（实测该行位于 `#ifndef FSTACK` 段内，见 `tcp_hpts.c:2025 #ifndef FSTACK`） | — |
| `pcpu_find()` | `freebsd/kern/subr_pcpu.c:105`（`dpcpu_init`） | 函数编译进来但 **无任何调用者**（在254 文件清单内 grep `dpcpu_init` 只命中定义本身） | 否 |
| `pcpu_find()` | `freebsd/kern/subr_pcpu.c:402,417` | `#ifdef DDB` 内（`:340`/`:393` 段）；`lib/opt/opt_ddb.h` **为空文件** → `DDB` 未定义 → 未编译 | — |
| `STAILQ_FOREACH(&cpuhead)` | `freebsd/net/netisr.c:1334` | 在 `#ifdef EARLY_AP_STARTUP` 内（`:1333`），`EARLY_AP_STARTUP` 未定义（不在编译命令、不在 `lib/opt/opt_global.h`）→ **未编译**；实际走`:1341pc = get_pcpu();` | — |
| `STAILQ_FOREACH(&cpuhead)` | `freebsd/net/netisr.c:1356`（`netisr_start`） | 编译，`SYSINIT(netisr_start, SI_SUB_SMP, SI_ORDER_MIDDLE)`（`:1365`）→在 `mi_startup()` 内、**worker 尚未创建 pcpu 之前**执行，此时 `cpuhead` 只有主线程一项；且 `netisr_maxthreads` 默认 1（`netisr.c:169`）→ 只起 1 个 | 否（启动期） |
| `dpcpu_off[]` 读 | `subr_pcpu.c:257`（`dpcpu_copy`的 `#ifdef SMP` 分支） | **未编译**；走 `:263 memcpy((void *)(dpcpu_off[0] + ...))` | 否|
| `dpcpu_off[]` 读 | `subr_pcpu.c:298,315,332`（`sysctl_dpcpu_*`） | 编译，仅 sysctl | 否 |
| `pcpu_destroy()` 写 | `subr_pcpu.c:269-277` | 编译，**无调用者**（f-stack 线程不退出） | 否 |

**结论**：**`pcpu_find()` 与 `cpuhead` 在f-stack 当前配置下没有任何数据面（报文/连接处理）读者**；启动期读者（`netisr_start`）在 worker 创建 pcpu 之前就跑完了。故稠密索引不会让任何运行期读者读到「半初始化」的 `cpuid_to_pcpu[]`。**唯一必须保留的同步就是 `cpuhead` 插入（由 `init_lock`覆盖）。**

⚠ **未坐实项U5-a**：`netisr_start` 在 SYSINIT 时只看到主线程 pcpu，这是**静态推断的时序**（`mi_startup()` 在 `ff_freebsd_init.c:309`，worker 的 `ff_stack_thread_init` 在 `ff_dpdk_run`→`main_loop` 之后）。**建议**在 M5 运行期打印 `nws_count` 与 `cpuhead` 长度确认。

---

## U6 稠密索引的来源方案与调用时序

### 6.1 现成的稠密序号：`lcore_conf[].proc_id`（**已存在，无需新增字段**）

实测代码链：

1. `lib/ff_config.c:116-118`（`parse_lcore_mask`）：
   ```c
   for (j = 0; j < BITS_PER_HEX && idx < RTE_MAX_LCORE; j++, idx++) {
       if ((1 << j) & val) {
           proc_lcore[count] = idx;      /* count 是稠密下标，idx 是稀疏 lcore id */
   ```
   `:139 cfg->dpdk.nb_procs = count;` → **`proc_lcore[0..count-1]` 是「稠密序号 → lcore id」的映射表**。
2. `lib/ff_config.c:1465-1484`（thread_mode 塌缩）：
   ```c
   if (cfg->dpdk.thread_mode) {
       ... proc_type = "primary";
       cfg->dpdk.nb_threads = cfg->dpdk.nb_procs;   /* 线程数 = lcore_mask 位数 */
       cfg->dpdk.nb_procs = 1;
       cfg->dpdk.proc_id = 0;
       proc_mask = strdup(lcore_mask);              /* 全位暴露给 EAL */
   }
   ```
3. `lib/ff_dpdk_if.c:427-455`（`init_lcore_conf`，thread_mode 分支）：
   ```c
   for (ti = 0; ti < ff_global_cfg.dpdk.nb_threads; ti++) {
       uint16_t lcore_id = ff_global_cfg.dpdk.proc_lcore[ti];
       struct lcore_conf *lc = &lcore_conf[lcore_id];
       lc->proc_id = ti;                /* ★ 稠密序号 0..N-1 已落到 lcore_conf */
   ```
4. `lib/ff_memory.h:104-111`：
   ```c
   static inline unsigned ff_lcore_conf_idx(void)
   { return ff_global_cfg.dpdk.thread_mode ? rte_lcore_id() : 0; }
   #define ff_cur_lcore_conf() (&lcore_conf[ff_lcore_conf_idx()])
   ```

**结论 U6-1**：worker 在`main_loop` 里可以直接用 **`ff_cur_lcore_conf()->proc_id`** 拿到稠密序号 `0..N-1`，**不需要**新增变量、**不要**用 `rte_lcore_id()`（稀疏）。`lib/ff_dpdk_if.c:2649` 现在传的是 `rte_lcore_id()`，应改为传 `ff_cur_lcore_conf()->proc_id`（或 `qconf->proc_id`，`qconf` 已在 `:2644` 取好）。

### 6.2 主线程与 worker 的槽位映射（撞车分析）

实测事实：
- `lib/ff_dpdk_if.c:2857` `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN);` → **EAL 主 lcore 也执行 `main_loop`**，即 thread_mode=1 的 N 个线程 = 1 个主 lcore 线程 + (N-1) 个 EAL worker 线程。
- 主线程在 `ff_init()`（`lib/ff_init.c:39-53`：`ff_load_config` → `ff_dpdk_init` → `ff_freebsd_init` → `ff_dpdk_if_up`）阶段已经在 `lib/ff_freebsd_init.c:293` 执行了 `ff_pcpu_thread_init(0)`，并在 `:348` 置 `ff_stack_inited = 1`；因此它进入 `main_loop` 后 `ff_stack_thread_init()` 在 `:177-178` 直接 return，**不会重复建 pcpu**。
- 主线程的 `proc_id`：EAL 主 lcore 是 coremask 中的第一个使能 lcore（thread_mode 下 `proc_mask == lcore_mask`），即 `proc_lcore[0]` → `lcore_conf[proc_lcore[0]].proc_id == 0`。

**建议映射方案（无撞车）**：

| 线程 | pcpu cpuid（=`zpcpu` 槽位） | 取得方式 |
|---|---|---|
| 主线程（= EAL main lcore = `proc_lcore[0]`） | **0** | 保持 `ff_freebsd_init.c:293` 的 `ff_pcpu_thread_init(0)` 不动 |
| worker `i`（`proc_lcore[i]`, i=1..N-1） | **i** | `ff_stack_thread_init(ff_cur_lcore_conf()->proc_id)`，且 `ff_pcpu_thread_init()` 改为真正使用形参 |

- 槽位数：`mp_maxid = nb_threads - 1`、`mp_ncpus`（是否同步抬高见 4.2的自由度讨论）、`CPU_SET(i,&all_cpus) for i in 0..nb_threads-1`、`MAXCPU ≥ nb_threads`。
- thread_mode=0（多进程）：`nb_threads == 0`，应保持 `mp_maxid=0`、`MAXCPU` 行为不变 → **零回归**。

⚠ **未坐实项 U6-a**：「EAL 主 lcore 一定等于 `proc_lcore[0]`」是根据 DPDK 默认「main lcore = coremask 最低位」推断的，**未经运行期验证**，且若将来传了 `--main-lcore` 就不成立。**建议**：不要依赖此推断，直接在 `ff_freebsd_init()` 里也用 `ff_cur_lcore_conf()->proc_id` 取主线程序号（thread_mode=1 时），或在 M5 打印 `rte_get_main_lcore()`/`rte_lcore_id()`/`proc_id`/`pc_zpcpu_offset` 三元组核对（DoD-1 已要求）。若主线程 `proc_id != 0`，上表仍成立（主线程占自己的 `proc_id`，仍不撞车），只是 `ff_freebsd_init.c:293` 的硬编码 0 需要改。

### 6.3 `ff_pcpu_thread_init` 相对 `uma_startup`/`smr_init`/`ff_freebsd_init` 的实际调用时序（实测）

```
应用 main()
└─ ff_init()                                   lib/ff_init.c:36
   ├─ ff_load_config()                          :39   ← nb_threads / proc_lcore[] 在此确定
   ├─ ff_dpdk_init()                :43   ← EAL init + init_lcore_conf(lc->proc_id=ti)
   │     + init_mem_pool + init_msg_ring
   ├─ ff_freebsd_init()                         :47
   │  ├─ ff_pcpu_thread_init(0)                 ff_freebsd_init.c:293   ← 主线程 pcpu
   │  ├─ CPU_SET(0, &all_cpus)                  :294
   │  ├─ ff_init_thread0()                      :296
   │  ├─ uma_startup1(bootmem)                  :301   ★ 按 mp_maxid 算 zsize (uma_core.c:3179-3181)
   │  ├─ uma_startup2()                         :302   ★ 内含 smr_init() (uma_core.c:3233)
   │  ├─ uma_page_slab_hash 建表                 :304-306
   │  ├─ mutex_init(); mi_startup()             :308-309 ★ 跑全部 SYSINIT：
   │  │        SYSINIT(pcpu_zones, SI_SUB_COUNTER)  subr_pcpu.c:157  → pcpu_zone_4..64
   │  │        各 counter_u64_sysinit / COUNTER_U64_DEFINE_EARLY
   │  │        SYSINIT(netisr_init, SI_SUB_SOFTINTR) / SYSINIT(netisr_start, SI_SUB_SMP)
   │  │        in_pcbinfo_init → uma_zcreate(UMA_ZONE_SMR) → smr_create()  (in_pcb.c:583,615-617)
   │  ├─ curthread->td_vnet = vnet0              :317
   │  ├─ lo_set_defaultaddr()                    :342
   │  └─ ff_stack_inited = 1                     :348
   └─ ff_dpdk_if_up()                           :51
应用 ff_run(loop, arg)
└─ ff_dpdk_run()   lib/ff_dpdk_if.c:2851
   └─ rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)   :2857
      └─ main_loop（每个 lcore 一个线程，含主 lcore）
         └─ ff_stack_thread_init(rte_lcore_id())            :2649
            └─ init_lock 临界区ff_freebsd_init.c:185-216
               └─ ff_pcpu_thread_init(cpuid)  :187   ← worker pcpu（当前恒传 0）
```

**结论 U6-2（关键时序约束）**：`mp_maxid` / `all_cpus` / `MAXCPU` 相关设置**必须在 `ff_freebsd_init.c:301 uma_startup1()` 之前完成**（最迟在 `ff_freebsd_init()` 函数体的开头，`:291-294` 附近），因为：
- `uma_startup1` 就用 `mp_maxid` 定死了**所有 zone 的字节尺寸**（H1）；
- `uma_startup2` → `smr_init()` 创建 "SMR CPU" zone；
- `mi_startup()` 里 `smr_create()`（`ipi_smr`）已按 `mp_maxid` 写 N 个槽（H2）。

而 `nb_threads` 在 `ff_load_config()`（更早）就已知，`ff_dpdk_init()` 也早于 `ff_freebsd_init()`，**信息可用性没有问题**。

---

## U7（第 2 部分）移除 `uma_crit_lock` 的前提论证

### 7.1 `critical_enter/exit` 在f-stack 中的实际语义（预处理实测）

```
PROBE_CRITICAL_ENTER = do { while (__sync_lock_test_and_set(&uma_crit_lock, 1)) ; } while(0);
PROBE_CRITICAL_EXIT  = do { __sync_lock_release(&uma_crit_lock); } while(0);
```
注意这是 **`lib/include/vm/uma_int.h:46-52` 的宏**，作用域是「凡 `#include <vm/uma_int.h>` 的编译单元」。在 254 个编译文件里主要是 `freebsd/vm/uma_core.c`。

**U7-a 已坐实（本轮补做实测）**：对 `freebsd/kern/subr_smr.c` 单独 `cc -E`（同第 0 节参数）后
```
grep -c 'uma_crit_lock' _m17_smr.i    ->   0
```
即 **`subr_smr.c` 里的 `critical_enter/exit` 与 `uma_crit_lock` 完全无关**（它不 include `vm/uma_int.h`）。它拿到的是 `freebsd/sys/systm.h:~200-210` 的定义，预处理输出实测为**空函数体**：
```c
static __inline void critical_enter(void) { }     /* 函数体被 f-stack 掏空 */
static __inline void critical_exit(void)  { }     /* #210 "freebsd/sys/systm.h" */
```
**两条关键推论**：
1. **SMR 的 read section（`smr_enter`/`smr_exit`/`smr_poll`）今天完全没有任何串行化保护。** 结合「所有 worker 的 `pc_zpcpu_offset` 都是 0 → 共享同一个 `c_seq` 槽位」，**doc-16 §8.1 记录的 UAF 理论窗口是代码级真实存在的**（并未被 `uma_crit_lock` 兜住）。这为 G1 的必要性提供了直接依据。
2. **移除 `uma_crit_lock` 不会削弱 SMR 的任何现有保护**（它从未保护过 SMR）。
3. 顺带说明：`freebsd/kern/subr_counter.c` 的 `counter_enter/exit` 也被 f-stack 置空（`lib/include/amd64/include/counter.h:38-39`），同理。

### 7.2 会进入 UMA 分配/释放快路径的执行上下文穷尽

| 上下文 | 是否存在（实测依据） | 是否调用 `ff_pcpu_thread_init` → 是否有独立 pcpu 槽 |
|---|---|---|
| **主线程**（= EAL main lcore，也跑 `main_loop`） | 是 | 是，`ff_freebsd_init.c:293`（cpuid 0） |
| **worker 线程**×(N-1) | 是，`rte_eal_mp_remote_launch(..., CALL_MAIN)`（`ff_dpdk_if.c:2857`） | 是，`ff_dpdk_if.c:2649` → `ff_freebsd_init.c:187` |
| **KNI 线程** | **不存在独立线程**。`lib/ff_dpdk_kni.c:93-96` `ff_kni_is_owner_thread()` = `rte_lcore_id() == proc_lcore[0]`；KNI 收发在 `main_loop` 内由owner 线程顺序执行 | 复用 owner 线程的 pcpu |
| **callout / timer 线程** | **不存在独立线程**。`lib/ff_kern_timeout.c:183-185` `__thread struct callout_cpu cc_cpu; #define CC_CPU(cpu) &cc_cpu`，每线程自己的 callwheel；`ff_hardclock()`/`ff_tcp_hpts_softclock()` 由 `main_loop` 周期调用 | 复用所属线程的 pcpu |
| **`ff_veth` 收发** | 在 `main_loop` 上下文内（`ff_veth.c` 的 `ff_veth_input`/`if_transmit` 由 worker 直接调用） | 复用worker pcpu |
| **控制面 `ff_msg`/IPC** | 在 `main_loop` 内处理（`init_msg_ring` 建 ring，消息在 loop 内消费） | 复用 worker pcpu |
| **netisr swi 线程** | **不存在**。`lib/ff_kern_intr.c:84-89swi_add(){ return 0; }`、`:91-95 swi_sched(){ }`、`:97-101 swi_remove(){ return 0; }`、`:103-107 intr_event_bind(){ return EOPNOTSUPP; }` —— **全是空stub，既不建线程也不调度**。故 `netisr_start_swi` 形同虚设，netisr 软中断路径实际不运行（U7-b 已坐实） | 不适用 |
| **`taskqueue` / netgraph / kproc 线程** | **不存在**。`lib/ff_compat.c:162-169 kproc_kthread_add(...){ return 0; }`、`:171-177 kthread_add(...){ return 0; }` —— **空 stub，不创建任何 OS 线程**（U7-c 已坐实）。因此 `lib/ff_ng_base.c:3253 kproc_kthread_add(ngthread,...)`（即使 `mp_ncpus` 抬高到 N）、`freebsd/kern/subr_taskqueue.c` 的 `taskqueue_start_threads*`、`so_splice` 的 `splice_work_thread` **都不会真起线程** | 不适用 |
| **`so_splice` kthread** | 同上，且 `splice_init()` 是 `SO_SPLICE` 首次使用时的懒初始化（`uipc_socket.c:435-441`），f-stack 无 `SO_SPLICE` 用户 | 不触发 |
| **应用自建线程（`ff_pthread_create`）** | API 存在：`lib/ff_thread.c:32-45`，`ff_start_routine` 只做 `ff_set_thread(p_data->parent)`（`ff_thread.c:16,26`），**不调用 `ff_pcpu_thread_init`** | **⚠ 高危：这类线程 `__thread pcpup == NULL`**。任何 `PCPU_GET(...)` 会解引用 NULL。这与本轮 G2 无关（今天就会崩），但**必须在 spec 里作为「不支持的用法」明确写出**，否则「每线程独占 pcpu 槽位」的前提在API 层面不成立 |
| **DPDK自有 rte 线程**（intr thread、telemetry、eal-intr-thread） | DPDK 内部线程存在，但**不进入 f-stack 协议栈**（不调用 `ff_*`/UMA） | 不适用 |

### 7.3 「每线程独占 pcpu 槽位」是否等价于上游的关抢占语义

- 上游 `critical_enter()` 的作用是：在同一个 CPU 上，禁止抢占 → 保证 `zone->uz_cpu[curcpu]` 这一槽位在临界区内**不会有第二个执行流**并发访问。
- 用户态等价条件：**「同一 pcpu 槽位在任意时刻只有一个线程会访问」**。
  - 在「稠密索引 + 每线程 1:1 独占槽位」下，`curcpu = PCPU_GET(cpuid) = pcpup->pc_cpuid` 是**线程私有常量**（`pcpup` 是 `__thread`，`ff_freebsd_init.c:85`），`&zone->uz_cpu[curcpu]` 因此是线程私有的→ **成立**，且**不依赖线程是否绑核、是否被 OS 迁移**（这比上游的「同 CPU」条件更强，因为槽位是按线程而非按物理 CPU 分的）。
    > 🔴 **【C-更正】本 bullet 的前提在 HEAD `ff09a17b2` 基线上不成立。** 实测 `git show HEAD:lib/include/sys/pcpu.h` 的 `:32 #undef curcpu` / `:34 #define curcpu 0` —— **`curcpu` 是字面量 `0`，不是 `PCPU_GET(cpuid)`**。故稠密 `pc_cpuid` **不会**让 `zone->uz_cpu[curcpu]` 变成线程私有，所有线程恒用 `uz_cpu[0]`。
    > 本 bullet 的结论**只有在同时把 `lib/include/sys/pcpu.h:34` 改成 `#define curcpu PCPU_GET(cpuid)` 之后才成立**（`coder` 已在工作树实施）。完整因果链与影响面穷尽见本文档 **C-更正§C.2/§C.3**。由 `designer` 发现、`leader` 复核、本 agent 独立坐实。
  - `uz_cpu[]` 的其它读者：`cache_drain()`（`uma_core.c:1408-1423`，zone 拆除时）、`zone_update_caches()`（`:2873`，zone 创建/flags 更新）、sysctl 统计（`:5096,5112,5127,5526,5593`，`atomic_load_64`）。前两者在启动/拆除期，后者是统计（可容忍不一致）。
  - **不等价的情形**：只要存在「两个线程共用同一 pcpu 槽位」的路径。实测存在**两类**：
    1. **`ff_pthread_create` 创建的应用线程**（7.2 表末）：`pcpup == NULL`，比"共用槽位"更糟（今天就是bug）。
    2. **⚠ 未坐实项 U7-b/U7-c 的 netisr swi / taskqueue kthread**：若它们是真 OS 线程且未调 `ff_pcpu_thread_init`，同样 `pcpup == NULL`。

- **另有一处独立于 pcpu 槽位的隐患（与 G2 直接相关）**：`critical_enter/exit` 这把全局锁**顺带**串行化了 UMA 快路径里对 zone 级共享结构的一部分访问。移除它以后，只有「per-cpu cache 命中」这条路径是真无锁安全的；**快路径 miss 后的 zone/keg 慢路径本来就在 `critical_exit()` 之后执行**（例如 `uma_core.c:3880-3891`：`cache_fetch_bucket` / `zone_alloc_bucket` 在临界区外，`:3891` 才重新 `critical_enter()`），**所以慢路径今天就没有被这把锁保护** —— 见 U8。

**结论 U7**：`uma_crit_lock` 可以移除的**充要前提**是：
1. 每个会进入 UMA 的线程都有**独立且合法**的 pcpu 槽位（→ G1 必须先落地，且 `MAXCPU`/`mp_maxid`/`all_cpus` 三者一致，H1~H4）；
2. 不存在未调用 `ff_pcpu_thread_init` 却进入 UMA 的线程（**须解决 U7-b/U7-c，并在文档中明确 `ff_pthread_create` 线程不得调用 f-stack API 或必须补pcpu 初始化**）；
3. 慢路径的并发安全性单独论证（见 U8，**结论是：移除该锁不降低慢路径的保护级别，因为慢路径本来就没被它保护**）。

---

## U8 跨线程分配/释放同一 zone 的路径 + UMA zone 级锁是否被 stub

### 8.1 结论（最重要的一条）

**f-stack 把 UMA 的全部 `mtx` 锁 stub 成了空操作。`ZONE_LOCK`/`ZDOM_LOCK`/`KEG_LOCK` 全部展开为 `((void)0)`。** 因此「去掉 `critical_enter` 后 bucket 交换是否仍有锁保护」的答案是：**没有，而且现在也没有** —— zone/keg 慢路径在f-stack 里**从来就是无锁的**。

### 8.2 证据（预处理实测，`lib/_m17_probe_u8.c`，同第 0 节参数）

```
PROBE_MTX_LOCK        = ((void)0);
PROBE_MTX_UNLOCK      = ((void)0);
PROBE_MTX_LOCK_SPIN   = ((void)0);
PROBE_MTX_UNLOCK_SPIN = ((void)0);
PROBE_MTX_ASSERT      = (void)0;
PROBE_ZONE_LOCK       = ((void)0);
PROBE_ZONE_UNLOCK     = ((void)0);
PROBE_ZDOM_LOCK       = ((void)0);
PROBE_KEG_LOCK        = ({ ((void)0); (struct mtx *)&(kkk)->uk_domain[(0)].ud_lock; });
PROBE_KEG_UNLOCK      = ((void)0);
PROBE_CRITICAL_ENTER  = do { while (__sync_lock_test_and_set(&uma_crit_lock, 1)) ; } while(0);
PROBE_CRITICAL_EXIT= do { __sync_lock_release(&uma_crit_lock); } while(0);
```

来源：`lib/include/sys/mutex.h`（f-stack override）
```c
:31-55  #undef __mtx_lock / __mtx_unlock / __mtx_lock_spin / __mtx_unlock_spin
        #undef _mtx_lock_flags / _mtx_unlock_flags / _mtx_lock_spin_flags / _mtx_unlock_spin_flags
        #undef thread_lock / thread_unlock / mtx_trylock_flags_ / mtx_init / mtx_destroy / mtx_owned
:57     #define DO_NOTHING ((void)0)
:59-67  #define __mtx_lock(...) DO_NOTHING   ... 全部 DO_NOTHING
:74-76  #define mtx_trylock_flags_(m,o,f,l) 1     /* trylock 永远"成功" */
:85     #define mtx_owned(m) (1)
```
而 `ZONE_LOCK`/`KEG_LOCK` 的原始定义确实建立在 `mtx_lock` 上（`freebsd/vm/uma_int.h:539-554,582-584`）：
```c
:551-552 #define KEG_LOCK(k, d)  ({ mtx_lock(KEG_LOCKPTR(k, d)); KEG_LOCKPTR(k, d); })
:582     #define ZONE_LOCK(z)    ZDOM_LOCK(ZDOM_GET((z), 0))
```
`freebsd/kern/kern_mutex.c` **不在 `lib/Makefile` 的 `KERN_SRCS` 里**（`lib/Makefile:339-377` 实测无此项），也没有 `kern_mutex.o`，佐证 mutex 完全走 override 宏；`lib/ff_lock.c` 只提供 `ff_mtx_init`/`mtx_sysinit`/`_mtx_destroy` 等**初始化/销毁**壳子，不提供加锁。

### 8.3 跨线程分配/释放同一 zone 的路径

**存在，且大量存在。** f-stack 的 zone 是**全进程共享**的（`uma_zcreate` 在 `mi_startup()` 里由主线程统一创建，不是 per-worker），因此：

| zone | 分配方 | 释放方 | 跨线程？ |
|---|---|---|---|
| mbuf / mbuf_cluster（`freebsd/kern/kern_mbuf.c`，编译集合内） | 收包线程 = 该队列的 worker | 发送完成/`m_freem` 通常在同一 worker；但 **loopback（`FF_LOOPBACK_SUPPORT=1`）、`if_bridge`、`netgraph`、KNI（owner 线程集中处理）** 可造成跨线程 | **是（存在路径）** |
| socket / pcb / tcpcb / syncache（`in_pcb.c`、`tcp_subr.c`、`tcp_syncache.c`） | 每 worker 有自己的 vnet（`ff_freebsd_init.c:209-214` 每 worker `vnet_alloc()` + 独立 prison），故连接不跨 worker | 同上| 设计上**否**，但 **zone 本身是共享的**（zone 不per-vnet） |
| `pcpu_zone_8`（counter）/ "SMR CPU" / "SMR SHARED" | 主线程（`mi_startup` 期）为主 | 极少释放 | 基本否 |
| bucket zones（`uma_core.c:486-511bucket_alloc` / `:514 bucket_free`） | **任意 worker**（快路径 miss 时） | **任意 worker** | **是，且是热路径** |

**关键点**：即使业务对象（socket/pcb）不跨线程，**bucket 与 slab 层一定跨线程**：worker A 的 cache miss 会从 zone 的共享 `zdom`/keg 拿 bucket，worker B 的 cache 满会把 bucket 还回同一个 `zdom`。这些操作走`zone_fetch_bucket`/`zone_put_bucket`/`keg_alloc_slab`，被 `ZDOM_LOCK`/`KEG_LOCK` 保护 —— **而这两个锁是no-op**。

同时 f-stack 自有的 `vsetzoneslab()`（`lib/include/vm/uma_int.h:105-126`）在每次新 slab 上线时 `malloc` 一个 `struct uma_page` 并 `LIST_INSERT_HEAD(hash_list, up, list_entry)`，**同样无锁**，多线程并发插入同一哈希桶会破链。

### 8.4 对方案的影响（**这是本轮最重要的风险裁决点**）

1. **去掉 `uma_crit_lock` 并不会「让原本有锁的 bucket 交换变成无锁」** —— 它本来就无锁（8.2/8.3）。所以 G2 在「不新增风险」这个意义上是成立的：G2 只移除对**per-cpu cache 快路径**的串行化，而该快路径在 G1 之后由「线程独占槽位」保证互斥。
2. **但 `uma_crit_lock` 目前事实上起到了「大幅缩小慢路径并发窗口」的副作用**：因为快路径 miss 与 refill 之间的窗口被这把锁挤压，两个 worker 同时进入 zone/keg 慢路径的概率被显著降低（不是消除）。**移除后，`zdom`/keg/`uma_page` 哈希的无锁竞争窗口会被放大**，压测下可能暴露今天被概率掩盖的破链/双重释放。
   - **这解释了为什么 `b90ddcba5` 加上这把锁就"修好了" `kqueue_kevent` 的 SIGSEGV**：它既修了共享 `uz_cpu[0]` 的竞态（真正原因），也顺带压住了慢路径竞态。
   > 🔵 **【C-更正·补强】** 上面括号里的「共享 `uz_cpu[0]`」当时是按「`pc_cpuid` 都是 0」推出的，**实际原因更强**：`curcpu` 在 `lib/include/sys/pcpu.h:34` 被硬编码成字面量 `0`，所以**无论 `pc_cpuid` 取何值，全部线程都必然落在 `uz_cpu[0]`**（`uma_core.c` 11 处 `&zone->uz_cpu[curcpu]`）。即这把锁保护的是一个**必然冲突**而非概率性竞态 —— 这也解释了为什么 `ff09a17b2` 把 cpuid 改回 0 后仍必须保留它。→ **G2 的前置条件必须写成「机制 A（`zpcpu_get`/SMR）与机制 B（`curcpu`/UMA cache）都做到每线程独占」**，详见 C-更正 §C.2。本段关于「慢路径窗口放大」的判断**不变**，仍需M5 压测（未坐实项 U8-perf）。
3. **因此建议 designer 考虑：G2 不是「删掉宏」这么简单**，至少要在下列方案中裁决（本文只列证据，不做裁决）：
   - **G2-a**：`critical_enter/exit` → `do {} while(0)`（回到 `b90ddcba5` 之前），同时**给 `ZDOM_LOCK`/`KEG_LOCK`/`vsetzoneslab` 补真锁**（把 `lib/include/sys/mutex.h` 对 `mtx_lock` 的 no-op 改为真实自旋/`pthread_mutex`，至少对 UMA 编译单元生效）。粒度从"全局一把"降到"per-zone/per-keg 一把" → 既安全又能拿到并发收益。
   - **G2-b**：`critical_enter/exit` → `do {} while(0)`，慢路径不动（承认现状），仅以压测验证。**风险由压测覆盖，须在 spec 中如实记录为残留风险。**
   - **G2-c**：保留全局锁但缩小到只包bucket 交换。
4. **辅助事实（降低难度）**：`lib/ff_glue.c:83 int __read_mostly vm_ndomains = 1;` 且 **`NUMA` 未定义**（编译命令与 `lib/opt/opt_global.h` 均无；`lib/opt/opt_global.h` 实测内容只有 `MUTEX_NOINLINE / RWLOCK_NOINLINE / SX_NOINLINE / DEV_RANDOM / NO_EVENTTIMERS / VIMAGE`）。因此 `uma_core.c` 里所有 `#ifdef NUMA` 的 **cross-domain bucket 路径全部编译掉**（`:1009,3926,3941,4161,4173,4189,4519,4536,4546,4622,4636,4662,4758,4812`），`itemdomain` 恒为 0（`:4535,4621`），`uc_crossbucket` 永不被装载（唯一装载点 `:1009-1014` 在 `#ifdef NUMA` 内）。**→ 跨 domain 这一层复杂度不存在，只需处理「跨线程」。**
5. **`cache_drain_safe()` 的一处非致命异常**（`uma_core.c:1497-1509`）：`CPU_FOREACH(cpu) { sched_bind(curthread, cpu); cache_drain_safe_cpu(...); }`，而 `lib/ff_glue.c:1187 sched_bind()` 是 stub，`cache_drain_safe_cpu()` 用的是 `&zone->uz_cpu[curcpu]`（`:1452`）。→ `mp_maxid>0` 后这个循环会把**调用线程自己的 cache 重复排空 N 次**，其它线程的 cache 不会被回收。**影响：仅回收不彻底（内存回收效率），无越界、无内存不安全。** 建议记录为已知限制。

---

---

## U9 以 `MAXCPU` 定尺寸 / 做边界判断的位置穷尽清单

**方法**：在 254 文件编译集合内 `grep -n -H -w MAXCPU`（实测输出已在U4 引用）。逐条判定「若线程数 N > MAXCPU 会发生什么」。

| # | 位置 | 形态 | `MAXCPU` 保持 1 而 cpuid 变成 0..N-1 时的后果 | 需要的动作 |
|---|---|---|---|---|
| 1 | `freebsd/kern/subr_pcpu.c:76` | `uintptr_t dpcpu_off[MAXCPU];` | `pcpu_destroy()` 写 `dpcpu_off[pc_cpuid]=0`（`:276`）会越界写；但 `pcpu_destroy` 在编译集合内**零调用者**，`dpcpu_init` 也零调用者 → 实际不触发 | `MAXCPU ≥ N` 后彻底无风险 |
| 2 | `freebsd/kern/subr_pcpu.c:77` | `struct pcpu *cpuid_to_pcpu[MAXCPU];` | **`pcpu_init()` `:91 cpuid_to_pcpu[cpuid]=pcpu` 直接越界写 8 字节 × (N-1) 个位置**，紧邻的 `cpuhead`（`:78`）会被覆盖 → 静默内存破坏（`:88` 的 `KASSERT` 因 `INVARIANTS` 未定义已编译掉，不报错）| **必须 `MAXCPU ≥ N`（阻断性）** |
| 3 | `freebsd/kern/subr_pcpu.c:88` | `KASSERT(cpuid >= 0 && cpuid < MAXCPU, ...)` | 编译掉，**不提供任何保护** | 不可依赖 |
| 4 | `lib/ff_kern_synch.c:59` + `:105` | `static uint8_t pause_wchan[MAXCPU];` / `pause_sbt()` → `_sleep(&pause_wchan[curcpu], ...)` | 🔴**【C-更正】归因修正**：HEAD 基线上 `curcpu` 是字面量 `0`（`lib/include/sys/pcpu.h:34`），故该处**本来并不越界**，恒取 `pause_wchan[0]`。越界风险是 **`curcpu` 改为 `PCPU_GET(cpuid)` 之后才引入的**：届时索引变成 `0..N-1`，`&pause_wchan[i]` 越出数组，但**只取地址不解引用**（仅作唯一 wait channel），故不崩；风险是与相邻静态变量地址混淆。另实测 `lib/ff_kern_synch.c:108-113wakeup()` 为空函数体，实际影响趋近 0 | **结论不变：必须 `MAXCPU ≥ N`**（消除 UB） |
| 5 | `lib/ff_kern_timeout.c:730` | `else if ((cpu >= MAXCPU) \|\| ((CC_CPU(cpu))->cc_inited == 0)) panic("Invalid CPU in callout %d", cpu);` | **必panic**（详见 U11） | **必须 `MAXCPU ≥ N`（阻断性）** |
| 6 | `lib/ff_glue.c:142` | `int mp_maxcpus = MAXCPU;` | 仅 sysctl 导出（`:154`），无功能读者 | 无 |
| 7 | `freebsd/netinet/tcp_hpts.c:316` | `int cpu[MAXCPU];`（`struct hpts_domain_info` 成员） | 写入点在 `tcp_hpts.c:2036hpts_domains[domain].cpu[count]=i`，位于 `#ifndef FSTACK` 段（`:2025`）内 → **未编译** | 无（但若将来放开须注意） |
| 8 | `freebsd/netinet/tcp_hpts.c:1864` | `uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;` | 只是取值，决定 `rp_num_hptss`；`mp_ncpus` 若保持 1 则完全不变 | 与 `mp_ncpus` 决策绑定 |
| 9 | `freebsd/net/netisr.c:243` | `static u_int nws_array[MAXCPU];` | 写入在 `netisr_start_swi()` 内，索引 `nws_count`（≤ `netisr_maxthreads`，默认 1，`netisr.c:169`）；且 `swi_add()` 是空 stub（`lib/ff_kern_intr.c:84-89`） | 无|
| 10 | `freebsd/net/netisr.c:1432,1457,1486,1516` | `malloc(... * MAXCPU ...)` + `KASSERT(counter <= MAXCPU)` | sysctl 统计路径；`malloc` 按 `MAXCPU` 变大只是多占内存 | 无 |
| 11 | `freebsd/amd64/include/pcpu_aux.h:47` | `_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE, "fix pcpu size");` | **与 MAXCPU 无关，但是一条重要的编译期保证**：既然 `lib/uma_core.o` 等已成功编译，说明 `sizeof(struct pcpu) == 4096` 成立（`freebsd/amd64/include/pcpu.h:104 char __pad[2900] /* pad to UMA_PCPU_ALLOC_SIZE */`）。故 `lib/ff_freebsd_init.c:106 malloc(sizeof(struct pcpu), ...)` 每线程分配的正是 4096 字节 | 无|

**U9 结论**：以 `MAXCPU` 定尺寸/判边界的**阻断性**位置有 3 处（#2 `cpuid_to_pcpu[]`、#5 callout panic、#4 `pause_wchan[]`的 UB）。因此**任何「抬高 cpuid 到 0..N-1」的方案都必须同时把 `MAXCPU` 抬到 ≥ N**（`freebsd/amd64/include/param.h:60-66` 在 `#else`(非 SMP) 分支**无条件** `#define MAXCPU 1`，故必须 `-DSMP` 或用 `lib/include/` 的 override 头改写；注意 `lib/include/sys/param.h` 目前只是 `#include_next` 直通，未改任何值）。而 `MAXCPU ≤ 64` 时 `sizeof(cpuset_t)` 不变（U4.4），**建议取一个略大于最大线程数的值（如 16 或 64），一次定死避免反复改ABI**。

---

## U10 `mp_maxid` 现状赋值点与 `uma_startup1/2`、`smr_init` 的精确调用序

### 10.1 `mp_maxid` 现在在哪里赋值 —— **答案：任何地方都没有赋值**

实测（U4.1 的 grep 输出）：`mp_maxid` 在编译集合内只有 3 处出现：
- `lib/ff_glue.c:145` `u_int mp_maxid;` —— **仅定义，无初值**（BSS → 0）
- `lib/ff_glue.c:151` `SYSCTL_INT(_kern_smp, OID_AUTO, maxid, ...)` —— 只读导出
- 其余 21 处全是**读者**

**结论 U10-1**：`mp_maxid` 全程保持 0，**没有任何运行期赋值点**。因此本轮必须**新增**一个赋值点。同理 `mp_ncpus` 只有 `lib/ff_glue.c:140 int mp_ncpus = 1;` 这一个静态初值，无运行期赋值；`all_cpus` 唯一写点是 `lib/ff_freebsd_init.c:294 CPU_SET(0, &all_cpus);`。

### 10.2 精确调用序（实测，file:line 逐级可核）

```
应用 main()
└─ ff_init(argc, argv)lib/ff_init.c:36
   ├─ ff_load_config(argc, argv)                           :39
   │     └─ ff_parse_args → parse_lcore_mask(ff_config.c:73-142)
   │        → proc_lcore[0..count-1], nb_procs=count       ff_config.c:118,139
   │        → thread_mode 塌缩: nb_threads=nb_procs, nb_procs=1, proc_id=0
   │ff_config.c:1465-1484
   │        ★ 此刻 nb_threads(=N) 已确定 —— 最早可设mp_maxid 的时点
   ├─ ff_dpdk_init(...)                                     :43
   │     ├─ rte_eal_init(...)
   │     ├─ init_lcore_conf()  → lcore_conf[proc_lcore[ti]].proc_id = ti
   │     │                                                  ff_dpdk_if.c:429-433
   │     ├─ init_mem_pool()   （按 nb_threads 建 N 个 mbuf pool）
   │     │                                                  ff_dpdk_if.c:526-527,547-551
   │     └─ init_msg_ring()   （按 nb_threads 建 N 个 ring） ff_dpdk_if.c:692-694
   ├─ ff_freebsd_init()                                     :47
   │  │《《《mp_maxid / mp_ncpus / all_cpus / MAXCPU 的赋值必须落在这里之前或此函数最开头 》》》
   │  ├─ kern_setenv("kern.hz", ...) / boot env / sysctl     ff_freebsd_init.c:274-289
   │  ├─ physmem = ...                                       :291
   │  ├─ ff_pcpu_thread_init(0)         ← 主线程 pcpu        :293   ★ 目前形参被忽略，恒传 0（:107）
   │  ├─ CPU_SET(0, &all_cpus)                               :294   ★ 只置了bit 0
   │  ├─ ff_init_thread0()                                   :296
   │  ├─ bootmem = kmem_malloc(16*PAGE_SIZE, M_ZERO)         :298-299
   │  ├─ uma_startup1((vm_offset_t)bootmem)                  :301
   │  │     └─ uma_core.c:3175-3182
   │  │            ksize = sizeof(uma_keg) + sizeof(uma_domain)*vm_ndomains
   │  │            zsize = sizeof(uma_zone)
   │  │                    + sizeof(struct uma_cache)*(mp_maxid + 1)   ★★★ H1
   │  │                    + sizeof(struct uma_zone_domain)*vm_ndomains
   │  │            → zones/kegs/zone-of-zones 的字节尺寸在此定死
   │  ├─ uma_startup2()                                      :302
   │  │     └─ uma_core.c:3223-3234
   │  │            slabzones[0]/[1]、hashzone、bucket_init()
   │  │            smr_init()                uma_core.c:3233
   │  │              └─ subr_smr.c:624-632
   │  │                   uma_zcreate("SMR SHARED", ...)
   │  │                   uma_zcreate("SMR CPU", sizeof(struct smr), ...,
   │  │                               UMA_ZONE_PCPU)   ★ PCPU 标记会被
   │  │                               keg_ctor(uma_core.c:2546-2548) 在 !SMP 下剥离
   │  ├─ uma_page_slab_hash = kmem_malloc(8192 * sizeof(uma_page)); uma_page_mask=8191
   │  │                :304-306
   │  ├─ mutex_init()                                        :308
   │  ├─ mi_startup()                                        :309   ★ 跑全部 SYSINIT：
   │  │     SI_SUB_COUNTER : SYSINIT(pcpu_zones, ...)  subr_pcpu.c:157
   │  │                       → pcpu_zone_4/8/16/32/64 = uma_zcreate(..., UMA_ZONE_PCPU)
   │  │                                subr_pcpu.c:146-155
   │  │     各 COUNTER_U64_DEFINE_EARLY / counter_u64_sysinit
   │  │                       → counter_u64_alloc() = uma_zalloc_pcpu(pcpu_zone_8,...)
   │  │                                                 subr_counter.c:63,227-233
   │  │     SI_SUB_SOFTINTR : SYSINIT(netisr_init)netisr.c:1344
   │  │     SI_SUB_SMP      : SYSINIT(netisr_start)     netisr.c:1365
   │  │     SI_SUB_PROTO_*  : in_pcbinfo_init → uma_zcreate(..., UMA_ZONE_SMR)
   │  │                       → zone_ctor: uz_smr = smr_create(...)  uma_core.c:3023-3024
   │  │→ smr_create: for(i=0;i<=mp_maxid;i++)
   │  │                            zpcpu_get_cpu(smr,i)->c_seq=...   subr_smr.c:598-605  ★★★ H2
   │  │                       ipi_smr = uma_zone_get_smr(...)        in_pcb.c:583,615-617
   │  │     SI_SUB_*        : callout_callwheel_init（全局 size pass）
   │  │                + ff_callout_thread_init（主线程 callwheel）
   │  │                                          ff_kern_timeout.c:247-259,262
   │  ├─ curthread->td_vnet = vnet0                          :317
   │  ├─ V_tcp_do_ecn = ...                                  :324
   │  ├─ sx_init(&proctree_lock) / ff_fdused_range            :326-327
   │  ├─ config里的 sysctl 逐条kernel_sysctlbyname          :329-340
   │  ├─ lo_set_defaultaddr()                                :342
   │  └─ ff_stack_inited = 1   （主线程标记，使其在 main_loop 跳过重复初始化）:348
   └─ ff_dpdk_if_up()                                        :51

应用 ff_run(loop, arg)   →  ff_dpdk_run()      lib/ff_dpdk_if.c:2851
└─ rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)        ff_dpdk_if.c:2857
   └─ main_loop（**每个 EAL lcore 一个线程，含主 lcore**）
      ├─ qconf = ff_cur_lcore_conf()                         ff_dpdk_if.c:2644
      ├─ ff_stack_thread_init(rte_lcore_id())                ff_dpdk_if.c:2649
      │    ├─ if (ff_stack_inited) return;   ← 主线程在此直接返回 ff_freebsd_init.c:177-178
      │    ├─ while(__sync_lock_test_and_set(&init_lock,1)); :185-186
      │    ├─ ff_pcpu_thread_init(cpuid)                     :187   ← worker pcpu（**当前恒传 0**，:107）
      │    ├─ ff_init_thread0(); td_i = ff_adapt_user_thread_add(&thread0)
      │    │                                                 :195-198
      │    ├─ff_callout_thread_init()                       :207
      │    │     └─ timeout_cpu = PCPU_GET(cpuid)  ★ 见 U11  ff_kern_timeout.c:254
      │    ├─ v = vnet_alloc(); curthread->td_vnet = v       :209-210
      │    ├─ ff_worker_prison_init(td_i, v)                 :214
      │    ├─ lo_set_defaultaddr()                           :215
      │    └─ __sync_lock_release(&init_lock)                :216
      └─ 数据面循环（收包/协议栈/发包/ff_hardclock/ff_msg/KNI）
```

### 10.3 结论

- **`mp_maxid` / `all_cpus` / `MAXCPU`（编译期）必须在 `lib/ff_freebsd_init.c:301uma_startup1()` 之前定型**。最自然的落点是 `ff_freebsd_init()` 开头 `:291-294` 一带（把 `CPU_SET(0,&all_cpus)`扩展成 `for (i=0;i<N;i++) CPU_SET(i,&all_cpus)`，并设 `mp_maxid = N-1`）。此时 `ff_global_cfg.dpdk.nb_threads` 已由 `ff_load_config()`（更早两级）确定，**信息完全可用**。
- **`ff_freebsd_init()` 之后再改 `mp_maxid` 一定出错**（H1：zone 尺寸已定死；H2：`smr_create` 已按旧值写槽）。
- **`uma_crit_lock` 宏的覆盖范围（补 U7遗留）**：`lib/include/vm/uma_int.h` 是 `vm/uma_int.h` 的 override，只有 `#include <vm/uma_int.h>` 的编译单元受影响。实测 `grep -l 'vm/uma_int.h' $(cat _m17_srcpaths.txt)` 在 254 文件集合内**只命中 2 个文件**：
  ```
  lib/ff_freebsd_init.c
  freebsd/vm/uma_core.c
  ```
  与 leader 提供的 gate-plan 结论**完全一致**。补充实测：`grep -c 'critical_enter\|critical_exit' lib/ff_freebsd_init.c` = **0**，即该文件虽然引入了这套宏，但**没有任何调用点** → **`uma_crit_lock` 事实上只作用于 `freebsd/vm/uma_core.c`**。

---

## U11 callout 的 cpuid 语义（**高优先，本轮最明确的阻断性缺陷**）

### 11.1 结论（三条）

1. **`timeout_cpu` 是非 `__thread` 的文件级全局变量，却被每个线程写。稠密 cpuid 后它会被覆盖成「最后一个完成 `ff_callout_thread_init()` 的线程的 cpuid」**（由于该调用在 `init_lock` 临界区内，写是串行的，不会撕裂，但**最终值不确定、且与任何单个线程都不对应**）。
2. **`lib/ff_kern_timeout.c:730` 的 `panic("Invalid CPU in callout %d")` 会被触发** —— 只要 `MAXCPU` 仍是 1 而有任何 cpuid ≥ 1 被传进 `callout_reset_tick_on`。触发路径**在数据面且必然发生**（见 11.3）。若把 `MAXCPU` 抬到 ≥ N，则 `cpu >= MAXCPU` 不再成立，而第二个条件 `(CC_CPU(cpu))->cc_inited == 0` 因 `CC_CPU(cpu)` **忽略参数**恒返回调用线程自己已初始化的 `cc_cpu`，也不成立 → **不panic**。
3. **`timeout_cpu` 应改成 `__thread`**（连同 `c->c_cpu` 的语义一并厘清）。理由与代价见 11.4。

### 11.2 证据：`timeout_cpu` 的全部读写点（实测 `grep -n 'c_cpu\|timeout_cpu\|cc_inited' lib/ff_kern_timeout.c`）

```
169:    u_int cc_inited;                        /* struct callout_cpu 成员 */
183:__thread struct callout_cpu cc_cpu;         /* ★ 每线程一份 callwheel */
184:#define CC_CPU(cpu)    &cc_cpu              /* ★ 完全忽略 cpu 参数 */
185:#define CC_SELF()      &cc_cpu
190:static int timeout_cpu;                     /* ★ 非 __thread 的全局变量 */
252:    memset(CC_SELF(), 0, sizeof(cc_cpu));   /* ff_callout_thread_init() */
254:    timeout_cpu = PCPU_GET(cpuid);          /* ★ 每个线程都写这个全局 */
255:    cc = CC_CPU(timeout_cpu);               /*但取到的仍是自己的 cc_cpu */
258:    callout_cpu_init(cc, timeout_cpu);      /*   cpu 只用于 snprintf 名字 */
300:    cc->cc_inited = 1;                      /* callout_cpu_init 内 */
367:        cpu = c->c_cpu;                     /* callout_lock()：cc = CC_CPU(cpu) 仍忽略 */
370:        if (cpu == c->c_cpu)
662:    cc = CC_CPU(timeout_cpu);               /* timeout(9)，取自己的 cc_cpu */
731:           ((CC_CPU(cpu))->cc_inited == 0)) /* ★ panic 判断的第二个条件 */
756:        cpu = c->c_cpu;
815:    return callout_reset_on(c, to_ticks, c->c_func, c->c_arg, c->c_cpu);  /* ★ 把 c_cpu 当cpu 传回 */
1061:    c->c_cpu = timeout_cpu;                 /* callout_init() */
1077:    c->c_cpu = timeout_cpu;                 /* _callout_init_lock() */
1181:    cc = CC_CPU(timeout_cpu);               /* sysctl kern.callout_stat */
1257: * Worker-thread clock: only advances this thread's own callwheel ...
```

`callout_cpu_init()`（实测函数体）里 `cpu` 参数只用于 `snprintf(cc->cc_ktr_event_name, ..., "callwheel cpu %d", cpu)`，**不参与任何寻址**；`if (cc->cc_callout == NULL) return;  /* Only cpu0 handles timeout(9) */` 也只看指针而非 cpu 值。

`callout_lock()`（实测函数体）`cpu = c->c_cpu; cc = CC_CPU(cpu);` —— 因 `CC_CPU` 忽略参数，**永远锁的是调用线程自己的 `cc_cpu`**；`if (cpu == c->c_cpu) break;` 恒真（无迁移）。

**综上：`timeout_cpu` / `c->c_cpu` 的数值在 f-stack 里对「用哪个 callwheel」毫无影响**（那由 `__thread cc_cpu` 决定）。它们**唯一**的实际作用就是被传进 `callout_reset_tick_on()` 后参与 `:730` 的合法性判断。

### 11.3 `:730` panic 会不会触发 —— 会，而且在数据面必然发生

`lib/ff_kern_timeout.c:719-734`：
```c
int
callout_reset_tick_on(struct callout *c, int to_ticks, void (*ftn)(void *),
    void *arg, int cpu, int flags)
{
    ...
    if (cpu == -1) {
        ignore_cpu = 1;
    } else if ((cpu >= MAXCPU) ||
           ((CC_CPU(cpu))->cc_inited == 0)) {
        /* Invalid CPU spec */
        panic("Invalid CPU in callout %d", cpu);
    }
```
宏链（`freebsd/sys/callout.h:96-120`）：
- `callout_reset(c,...)` / `callout_reset_sbt(...)` / `callout_schedule_sbt(...)` → **cpu = -1**，安全。
- `callout_reset_curcpu` / `callout_reset_sbt_curcpu` / `callout_schedule_sbt_curcpu` / `callout_schedule_curcpu` → **cpu = `PCPU_GET(cpuid)`**，稠密后 = 本线程序号 i。
- `callout_reset_on(c,...,cpu)` / `callout_reset_sbt_on(...,cpu,...)` / `callout_schedule_on(...,cpu)` → 由调用者给。
- `lib/ff_kern_timeout.c:815 callout_schedule(c,ticks)` → 传 **`c->c_cpu`**（= 某次 `callout_init` 时的 `timeout_cpu` 快照）。

编译集合内**传非 -1 cpu 的真实调用点**（实测 grep，已排除 `ff_kern_timeout.c` 自身）：

| 调用点 | 传入的 cpu | 是否数据面 | 稠密 cpuid + `MAXCPU==1` 时|
|---|---|---|---|
| `freebsd/kern/kern_event.c:790-791` `kqtimer_sched_callout()` → `callout_reset_sbt_on(&kc->c, ..., kc->cpuid, C_ABSOLUTE)`，而 `kern_event.c:935 kc->cpuid = PCPU_GET(cpuid);` | 本线程稠密序号 i | **是**（EVFILT_TIMER / kqueue） | **panic**。⚠ 特别注意：`b90ddcba5` 修的正是 **`kqueue_kevent` 路径的 SIGSEGV**，这条路径与 kqueue 强相关 |
| `freebsd/netinet/tcp_timer.c:894-896` 与 `:931-933` → `callout_reset_sbt_on(&tp->t_callout, ..., inp_to_cpuid(inp), C_ABSOLUTE)`，而 `inp_to_cpuid()`（`tcp_timer.c:246-249`）= `inp->inp_flowid % (mp_maxid + 1)`，`CPU_ABSENT` 通过则原样返回 | `0..mp_maxid` | **是**（每个 TCP 连接的定时器，最热路径之一） | **panic**（只要 `mp_maxid>0` 且某连接 flowid % (N) != 0） |
| `freebsd/netinet/tcp_hpts.c:1025-1027,1645-1647, 1807-1809, 2047-2049` → `callout_reset_sbt_on(&hpts->co, ..., hpts->p_cpu, ...)` | `0..rp_num_hptss-1`（见下方说明） | **是**（`TCPHPTS` 已开启 `-DTCPHPTS`） | `p_cpu >= MAXCPU` 时 **panic**；`rp_num_hptss` 上限来自 `tcp_hpts.c:1864 ncpus = mp_ncpus ? mp_ncpus : MAXCPU` → **若 `mp_ncpus` 保持 1 则 `p_cpu` 恒为 0，安全** |
| `freebsd/kern/subr_taskqueue.c:368` → `callout_reset_sbt_curcpu(&timeout_task->c, ...)` = `PCPU_GET(cpuid)` | 本线程稠密序号 i | 取决于 taskqueue 使用；`taskqueue_enqueue_timeout*` 在 f-stack 有调用者 | **panic**（若被走到） |
| `freebsd/netpfil/ipfw/ip_fw_dynamic.c:2843` → `callout_reset_on(&V_dyn_timeout, hz, dyn_tick, vnetx, 0)` | 常量 **0** | 是（`FF_IPFW=1`） | 安全（0 < MAXCPU=1） |

> **`p_cpu = 0xffff` 的澄清（原 U11-a，本轮已坐实，非风险）**：`tcp_hpts.c:1997 hpts->p_cpu = 0xffff;` 与 `:2010 hpts->p_cpu = i;` **位于两个不同的 for 循环**（实测 `sed -n '1900,1915p;2000,2016p'`：`:2008for (i = 0; i < tcp_pace.rp_num_hptss; i++) { hpts = tcp_pace.rp_ent[i]; hpts->p_cpu = i;` 是第二个循环）。第一个循环里 `0xffff` 只是占位，其后紧跟 `:1999 callout_init(&hpts->co, 1);`（`callout_init` 只写 `c->c_cpu = timeout_cpu`，**不调用 `callout_reset_tick_on`**），在任何 `callout_reset_sbt_on` 之前就已被 `:2010` 覆盖成 `i`。**故 `0xffff` 不会被当作 callout 的 cpu 传下去，不构成 panic 风险。**
> 另实测 `tcp_hpts.c:2002-2003 if (vm_ndomains == 1 && tcp_bind_threads == 2) tcp_bind_threads = 0;`，而 `lib/ff_glue.c:83 vm_ndomains = 1` → `tcp_bind_threads` 不会取 2，`:2025 #ifndef FSTACK` 段更是未编译。

**结论 11.3**：`kern_event.c:790` 与 `tcp_timer.c:894/931` 这两条**必经数据面**路径会在稠密 cpuid 后立即触发 `panic`。→ **`MAXCPU ≥ N` 是 G1 的硬前置条件**（与 U9 结论一致）。

> 🔴 **【C-更正·新增触发路径】** `inp_to_cpuid()` 除了 `:246 % (mp_maxid + 1)` 这条，还有两条兜底 `return (curcpu);`（`freebsd/netinet/tcp_timer.c:237` 与 `:249`）。在 HEAD 基线上 `curcpu` 是字面量 `0`（`lib/include/sys/pcpu.h:34`），这两条恒返回 0因而安全；但 **`curcpu` 改为 `PCPU_GET(cpuid)` 之后它们会返回 `0..N-1`**，同样流入 `:896/:932` 的 `callout_reset_sbt_on()` → 同样落到 `ff_kern_timeout.c:730` 的 `cpu >= MAXCPU` 判断。**这只是给「`MAXCPU ≥ N`」增加了第三条触发路径，结论不变。** 完整 `curcpu` 影响面见 C-更正 §C.3。

### 11.4 修复建议（本文只给依据与选项，不做裁决）

- **必做A**：`MAXCPU` 抬到 ≥线程数（否则 `:730` panic + `cpuid_to_pcpu[]` 越界）。
- **必做 B**：`static int timeout_cpu;`（`:190`）**应改为 `static __thread int timeout_cpu;`**。依据：
  - 它的唯一语义是「本线程 callwheel 对应的 cpuid」，被 `:254 timeout_cpu = PCPU_GET(cpuid)` 按线程赋值，本质是线程私有量（与旁边的 `__thread struct callout_cpu cc_cpu;`（`:183`）是配套的一对，`cc_cpu` 已经是 `__thread`，`timeout_cpu`漏了）。
  - 不改的后果：`callout_init()`/`_callout_init_lock()`（`:1061,:1077`）会把**别的线程的 cpuid** 写进 `c->c_cpu`，随后 `callout_schedule()`（`:815`）把它当 cpu 传回 `callout_reset_tick_on` → 即使 `MAXCPU` 足够大不panic，语义上也是「A线程的 callout 记着 B 线程的 cpuid」，属于隐性错误；同时 `timeout(9)`（`:662`）与 `sysctl kern.callout_stat`（`:1181`）读到的 `timeout_cpu` 也是别人的值（虽然因 `CC_CPU` 忽略参数而侥幸无害）。
  - 改成 `__thread` 的代价：**近乎为零**。`timeout_cpu` 没有任何跨线程语义需求；改后 `c->c_cpu` 恒等于创建该 callout 的线程自身 cpuid，`callout_schedule()` 传回的值必然合法（`< N≤ MAXCPU`）。
- **可选 C（更彻底）**：既然 `CC_CPU(cpu)` 恒忽略 `cpu`、`callout_lock()` 的迁移循环恒真，可考虑把 `:728-734` 的合法性判断改成`if (cpu != -1 && cpu > (int)mp_maxid) panic(...)`（用运行期 `mp_maxid` 而非编译期 `MAXCPU`），这样与 `MAXCPU` 的具体取值解耦、更贴近真实语义。**但这会改动 f-stack 已有语义，须由 designer/reviewer 裁决。**

---

## U13 无 `pcpup` / 未独占槽位的线程（G2 去锁的前置条件）

### 13.1 结论

**在 `helloworld` 这类「不调用 `ff_pthread_create`」的标准用法下，进入 UMA/SMR 快路径的线程只有「主线程 + (N-1) 个 worker」，全部经 `ff_pcpu_thread_init()` 建立了 `pcpup`，可以做到 1:1 独占槽位 → G2 的前置条件成立。**
**但存在一条 API 级缺口：`ff_pthread_create()` 创建的应用线程 `pcpup == NULL`，一旦它调用任何 `ff_*` 协议栈 API 就会解引用 NULL（今天就崩，与本轮无关但必须写入 spec 的「不支持用法」）。**

### 13.2 逐个线程模型核实

| 线程模型 | 实测依据 | 有 `pcpup`？ | 独占槽位？ | 进 UMA/SMR？ |
|---|---|---|---|---|
| **主线程**（应用 `main`，同时是 EAL main lcore，也执行 `main_loop`） | `lib/ff_init.c:36-56` → `ff_freebsd_init()`；`lib/ff_freebsd_init.c:293 ff_pcpu_thread_init(0)`；`:348 ff_stack_inited=1` 使其在 `main_loop` 里跳过重复初始化（`:177-178`） | 有 | 稠密方案下占 slot 0 | 是（启动期建全部 zone；运行期跑自己的那份数据面） |
| **EAL worker 线程**×(N-1) | `lib/ff_dpdk_if.c:2857 rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)` → `:2649 ff_stack_thread_init(rte_lcore_id())` → `lib/ff_freebsd_init.c:187 ff_pcpu_thread_init(cpuid)` | 有 | 稠密方案下占 slot 1..N-1 | 是（热路径） |
| **KNI** | **无独立线程**。`lib/ff_dpdk_kni.c:93-97`：<br>`ff_kni_is_owner_thread(void){ if (ff_global_cfg.dpdk.thread_mode) return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0]; ... }`，被 `:387,:434,:484,:537` 用于「只有 owner 线程做 KNI 的公共部分」；每lcore 自己的 ring 用 `rte_lcore_id()` 命名（`:396-415`）。`ff_kni_process()`（`:502`）由 `main_loop` 调用 | 复用所属worker 的 | 是 | 是（但走的是所属 worker 的槽位） |
| **`ff_veth` 收发** | `lib/ff_veth.c` 的 `ff_veth_input`/`ff_veth_transmit` 由 `main_loop` 直接调用（无线程创建代码；`lib/ff_veth.c` 内 grep 无 `pthread_create`/`kthread`） | 复用 worker 的 | 是 | 是 |
| **callout / timer** | **无独立线程**。`lib/ff_kern_timeout.c:183-185 __thread struct callout_cpu cc_cpu; #define CC_CPU(cpu) &cc_cpu`；`ff_hardclock()`/`ff_hardclock_worker()`/`ff_tcp_hpts_softclock()` 由 `main_loop` 周期调用（`lib/ff_dpdk_if.c:186-188` 的 extern 声明 + loop 内调用） | 复用 worker 的 | 是 | 是 |
| **netisr swi /ithread** | **无线程**。`lib/ff_kern_intr.c:84-89 swi_add(){return 0;}`、`:91-95 swi_sched(){}`、`:97-101 swi_remove(){return 0;}`、`:103-107 intr_event_bind(){return EOPNOTSUPP;}` 全空stub | — | — | 否（路径不运行） |
| **kthread / kproc / taskqueue / netgraph ngthread / so_splice** | **无线程**。`lib/ff_compat.c:162-169 kproc_kthread_add(...){ return 0; }`、`:171-177 kthread_add(...){ return 0; }` 全空 stub；`lib/ff_glue.c:1019-1023 kproc_exit(){ panic(...) }`、`lib/ff_compat.c:179-183 kthread_exit(){ panic(...) }` 说明这些路径本就不预期运行。故 `lib/ff_ng_base.c:3253 kproc_kthread_add(ngthread,...)`、`freebsd/kern/subr_taskqueue.c` 的 `taskqueue_start_threads*`、`freebsd/kern/uipc_socket.c:463-465` 的 `splice_work_thread` **都不会真起线程** | — | — | 否 |
| **DPDK 自有线程**（`eal-intr-thread`、telemetry、service lcore） | DPDK EAL 内部线程。**f-stack 未注册任何 rte_service**（在 254 文件集合外的 `lib/*.c` 内 grep `rte_service_component_register`/`rte_service_lcore` 为 0 命中）；EAL 中断线程只处理 link status/VFIO 等，不调用 `ff_*`/UMA | 无 | — | 否|
| **应用线程`ff_pthread_create`** | `lib/ff_thread.c:32-46`：`ff_pthread_create()` 把 `data->parent = pcurthread` 后 `pthread_create(thread, attr, ff_start_routine, data)`；`ff_start_routine`（`:20-30`）只做 `ff_set_thread(p_data->parent)`（`:16-18` 即 `pcurthread = other`）→ **不调用 `ff_pcpu_thread_init()`，`__thread pcpup` 保持 NULL** | **无（NULL）** | — | **若调用任何 `ff_*` 协议栈 API 即崩**（`PCPU_GET(x)` 展开为 `(pcpup->pc_x)`，见 U1） |

### 13.3 对 G2 的影响

- **前置条件 1（线程与槽位 1:1）**：在标准用法下成立。且因为 `pcpup` 是 `__thread`（`lib/ff_freebsd_init.c:85`）、`curcpu = PCPU_GET(cpuid) = pcpup->pc_cpuid` 是线程私有常量，「独占」**不依赖线程绑核、不受 OS 迁移影响** —— 这比上游 `critical_enter()` 的「同 CPU 内无抢占」条件更强。
- **前置条件 2（无 `pcpup==NULL` 的线程进 UMA）**：**成立，但依赖「应用不使用 `ff_pthread_create` + 不在其中调`ff_*`」这一约定**。建议 spec 里给出二选一：(a) 明确文档化为不支持；(b) 在 `ff_start_routine`（`lib/ff_thread.c:20-30`）里补 `ff_pcpu_thread_init(<新槽位>)`，但这会**要求额外预留槽位**（`mp_maxid` 需≥ 线程数 + 应用线程数），与 H1「`mp_maxid` 必须在 `uma_startup1` 前定型」冲突（应用线程数在启动时未知）→ **(b) 需要一个「预留 K 个额外槽位」的配置项**。这是 designer 需要裁决的设计点。

---

## U14 `lib/ff_ng_base.c:3249 numthreads = mp_ncpus;` 一句话结论

**无实际影响。** `lib/ff_ng_base.c:3249 numthreads = mp_ncpus;` 之后在 `:3253` 用 `kproc_kthread_add(ngthread, NULL, &p, &td, ...)` 起netgraph worker，而 `lib/ff_compat.c:162-169 kproc_kthread_add()` 是**返回 0 的空 stub，不创建任何线程**；因此即使 `mp_ncpus` 从 1 抬到 N，也只是循环变量变大、`kproc_kthread_add` 被多调用几次并原样返回 0，**不会产生任何线程、不会分配 per-cpu 资源**。（若将来 `mp_ncpus` 保持 1（U4.2 建议的自由度），则连这点都不变。）

## U15 `dpcpu_init()` 在 `freebsd/` 其它子目录是否有调用者 —— 一句话结论

**没有。** 在 254 个实际编译文件集合内 `grep -rn 'dpcpu_init'` 只命中 `freebsd/kern/subr_pcpu.c:100`（定义本身），**零调用点**。补充：对整个 `freebsd/` 树（不限编译集合）也只有 `subr_pcpu.c` 的定义与 `freebsd/sys/pcpu.h` 的声明；上游本应由 `amd64/amd64/mp_machdep.c`/`machdep.c` 调用，而这些文件**不在 `lib/Makefile` 的 SRCS 里**（`MACHINE_SRCS` 只有 `in_cksum.c`，见 `lib/Makefile:409-410`）。因此 `dpcpu_off[]` 全程为 0，`DPCPU_*` 动态 per-cpu 存储在 f-stack 中**完全未启用**，`mp_maxid` 抬高对它无影响（`subr_pcpu.c:263 dpcpu_copy()` 走的是 `#else` 分支 `memcpy((void *)(dpcpu_off[0] + (uintptr_t)s), s, size)` —— 注意 `dpcpu_off[0]==0` 意味着这是往 `s` 自己拷贝，是既有的no-op 行为，本轮不改变）。

---

## U16（leader 追加必答）`mp_ncpus` 是否必须随 `mp_maxid` 同步抬高 —— **明确结论**

>本节回答 U4.2 留下的自由度。leader 指出的越界疑虑是：`rp_ent[]` 只按 `mp_ncpus` 分配，而 `inp_to_cpuid()` 返回 `% (mp_maxid+1)`，若两者不一致是否越界。

### 16.1 结论（**给死**）

**`mp_ncpus` 可以安全地保持 1，不需要随 `mp_maxid` 同步抬高。`tcp_pace.rp_ent[]` 不会越界。**

**根本原因（一句话）**：`inp_to_cpuid()`（`tcp_timer.c:229-253`，基于 `mp_maxid+1`）**从来没有被用来索引 `rp_ent[]`**；它在全树只有 2 个使用点，都是作为 `callout_reset_sbt_on()` 的 `cpu` 实参。而 `rp_ent[]` 的**每一个**索引来源都独立地对 `mp_ncpus` / `rp_num_hptss` 取模。

### 16.2 证据一：`inp_to_cpuid()` 的全部使用点（全树 grep，非仅编译集合）

```
freebsd/netinet/tcp_var.h:1477:int inp_to_cpuid(struct inpcb *inp);          /* 声明 */
freebsd/netinet/tcp_timer.c:229: inp_to_cpuid(struct inpcb *inp)              /* 定义 */
freebsd/netinet/tcp_timer.c:896:     tp, inp_to_cpuid(inp), C_ABSOLUTE);     /* callout_reset_sbt_on 的 cpu 实参 */
freebsd/netinet/tcp_timer.c:932:     precision, tcp_timer_enter, tp, inp_to_cpuid(inp),   /* 同上 */
```
**共 4 处，其中 2 处是声明/定义，2 处是 callout 的 `cpu` 实参。与 `rp_ent[]`/`t_hpts_cpu` 零交集。**

### 16.3 证据二：`rp_ent[]` 的尺寸与**全部**索引来源（穷尽）

尺寸（`freebsd/netinet/tcp_hpts.c`）：
```c
:1864  uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;
:1872  tcp_pace.rp_num_hptss = ncpus;
:1885  sz = (tcp_pace.rp_num_hptss * sizeof(struct tcp_hpts_entry *));
:1886  tcp_pace.rp_ent = malloc(sz, M_TCPHPTS, M_WAITOK | M_ZERO);
:1887  sz = (sizeof(uint32_t) * tcp_pace.rp_num_hptss);
:1888  tcp_pace.cts_last_ran = malloc(sz, M_TCPHPTS, M_WAITOK);
:1921-1925  for (i = 0; i < tcp_pace.rp_num_hptss; i++) { rp_ent[i] = malloc(...); ... }
```

全部索引点（实测 `grep -n 'rp_ent\|rp_num_hptss' freebsd/netinet/tcp_hpts.c`）：

| 索引点 | 索引表达式 | 是否可能 ≥ `rp_num_hptss` |
|---|---|---|
| `:575` `tcp_hpts_lock()` | `rp_ent[tp->t_hpts_cpu]` | **否** —— `t_hpts_cpu` 的全部赋值点见16.4 |
| `:1585` `tcp_choose_hpts_to_run()` | `rp_ent[oldest_idx]`，`oldest_idx` 来自 `for (i = start; i < end; i++)`，`:1559 end = tcp_pace.rp_num_hptss`（`grp_cnt>1` 时 `end = cg_last+1`，但 `:1890 cpu_top==NULL → grp_cnt=1`，见 16.5） | 否 |
| `:1587` 同上 else分支 | `rp_ent[(curcpu % tcp_pace.rp_num_hptss)]` | 否（取模） |
| `:1922,1924,1925` | `for (i=0;i<rp_num_hptss;i++)` | 否 |
| `:2009` | `for (i=0;i<rp_num_hptss;i++)` | 否 |
| `:2077` | `for (int i=0;i<rp_num_hptss;i++)` | 否 |

### 16.4 证据三：`tp->t_hpts_cpu` 的**全部**赋值点（全树 grep）

```
freebsd/netinet/tcp_var.h:328uint16_t t_hpts_cpu;   /* CPU chosen by hpts_cpuid(). */
freebsd/netinet/tcp_var.h:330   #define HPTS_CPU_NONE ((uint16_t)-1)
freebsd/netinet/tcp_subr.c:2298 tp->t_hpts_cpu = HPTS_CPU_NONE;           /* tcpcb 初始化 */
freebsd/netinet/tcp_hpts.c:606  tp->t_hpts_cpu = hpts_random_cpu();       /* tcp_hpts_init() */
freebsd/netinet/tcp_hpts.c:1542 tp->t_hpts_cpu = hpts_cpuid(tp, &failed); /* tcp_set_hpts() */
```

逐个判定：

1. **`:606` `hpts_random_cpu()`** —— `tcp_hpts.c:473`：
   ```c
   cpuid = (((ran & 0xffff) % mp_ncpus) % tcp_pace.rp_num_hptss);
   ```
   **双重取模**，结果恒 `< rp_num_hptss`。**与 `mp_maxid` 无关**。安全。
   （`tcp_hpts_init()` 在 `:604-609`：`if (__predict_true(tp->t_hpts_cpu == HPTS_CPU_NONE)) tp->t_hpts_cpu = hpts_random_cpu();` —— 保证 `HPTS_CPU_NONE(=0xffff)` 不会残留到 `:575` 的索引。）

2. **`:1542` `hpts_cpuid()`** —— `tcp_hpts.c:1040-1099` 全文实测，四条返回路径：
   - `:1049-1051` `if (tp->t_flags2 & TF2_HPTS_CPU_SET) return (tp->t_hpts_cpu);` → 返回**上一次**已合法的值（归纳法安全）。
   - `:1056-1062` `if (tcp_use_irq_cpu) { if (tp->t_lro_cpu == HPTS_CPU_NONE) { *failed = 1; return (0); } return (tp->t_lro_cpu); }`
     - `tcp_hpts.c:286 static int tcp_use_irq_cpu = 0;`（默认关，`:373 TUNABLE_INT("net.inet.tcp.use_irq", ...)` 才可开）。
     - 且 `t_lro_cpu` 的唯一赋值点是 `freebsd/netinet/tcp_lro_hpts.c:576-577`，而 **`tcp_lro_hpts.c` 不在 `lib/Makefile` 的 `NETINET_SRCS` 内**（`lib/Makefile:515` 只有 `tcp_lro.c`），实测 `ls lib/tcp_lro_hpts.o` → **No such file**（`lib/tcp_lro.o` 存在）。→ `t_lro_cpu` 全程为 `HPTS_CPU_NONE` → 即使开了 `use_irq` 也走 `*failed=1; return 0;`。安全。
   - `:1064-1070` `#ifdef RSS` 分支 —— `RSS` 未定义（编译命令与 `lib/opt/opt_global.h` 均无），**未编译**。
   - `:1076-1079` `if (inp->inp_flowtype == M_HASHTYPE_NONE) return (hpts_random_cpu());` → 同1，安全。
   - `:1085-1096` 主分支：`#ifdef NUMA... #endif` 包着 `cpuid = inp->inp_flowid % mp_ncpus;`（`:1089`）。**`NUMA` 未定义**，故 `#ifdef NUMA` 的 `if/else` 骨架被剥掉，剩下的就是裸的 `cpuid = inp->inp_flowid % mp_ncpus;` → **用的是 `mp_ncpus`，不是 `mp_maxid`** → 恒 `< mp_ncpus == rp_num_hptss`。安全。
   >★ **这是本节最关键的一行**：`tcp_hpts.c:1089` 用 `% mp_ncpus`，而 `tcp_timer.c:246` 用 `% (mp_maxid + 1)`。两者是**不同的两套编号**，前者索引 `rp_ent[]`、后者只喂 callout。所以 `mp_ncpus` 与 `mp_maxid` **本来就允许不一致**。

3. **`:2298` `HPTS_CPU_NONE`** ——仅作哨兵，在 `tcp_hpts_init()`（`:604-609`）被替换后才会进入 `:575` 的索引路径。
   -⚠ 唯一残留：`:549 MPASS(hpts->p_cpu == tp->t_hpts_cpu);` 与 `:1539 hpts = tcp_hpts_lock(tp);`（在 `tcp_set_hpts()` 里**先**加锁再改 `t_hpts_cpu`）都依赖「进入时 `t_hpts_cpu` 已合法」。`MPASS` 因 `INVARIANTS` 未定义已编译掉，不提供保护；但赋值时序由 `tcp_hpts_init()` 保证（上游同样如此，**非本轮引入的问题**）。

### 16.5 顺带收录（leader 旁路坐实，本节交叉确认一致）

- **`smp_topo()` 返回 NULL 是安全的**：`tcp_hpts.c:1867-1871` `#ifdef SMP cpu_top = smp_topo(); #else cpu_top = NULL; #endif`；`:1890 if (cpu_top == NULL) { tcp_pace.grp_cnt = 1; }` 显式处理。本节实测 `sed -n '1855,1930p'` 输出与之一致。→ 若走候选 A（`-DSMP`）而 `res-build` 用返回 NULL 的 `smp_topo` stub，**行为等价于非 SMP**，`grp_cnt=1` → `tcp_choose_hpts_to_run()` 的 `end = rp_num_hptss`（`:1559`），无`cg_first/cg_last` 越界风险。
- **`hpts->p_cpu = 0xffff`（`:1997`）是瞬态值**：`:2008-2010` 的**第二个** `for` 循环立即 `hpts = tcp_pace.rp_ent[i]; hpts->p_cpu = i;`，而 `:2047 callout_reset_sbt_on(..., hpts->p_cpu, ...)` 在其后；`#ifndef FSTACK` 只覆盖 `:2025-2041`（NUMA 绑核段），`p_cpu = i` 在编译范围内。**U11-a 关闭，不会 panic。**（与本文档 U11 §11.3 的澄清块一致。）
- **`smp_started` 无语义风险**：编译集合内只有 `lib/ff_glue.c:219 active = smp_started;`（sysctl handler）一个读者；`kern_clocksource.c`/`kern_cpu.c`/`sched_4bsd.c`/`sched_ule.c`/`subr_atomic64.c`/`subr_smp.c` 均不在 `lib/Makefile` 的 SRCS。→ `-DSMP` 不引入 `smp_started` 语义风险。

### 16.6 对方案的影响（designer 可直接引用的裁决依据）

| 选项 | 是否安全（内存/越界） | 副作用 |
|---|---|---|
| **`mp_maxid = N-1`，`mp_ncpus` 保持 1** | **安全**（16.1~16.4 坐实） | `tcp_pace.rp_num_hptss == 1` → **N 个 worker 共享 1 个 hpts 实例**。而 `struct tcp_hpts_entry` 的 `HPTS_LOCK` 是 `mtx`（**no-op**，U8）→ **多 worker 并发操作同一个 hpts 队列且无锁保护**。⚠ 这是一个**真实的新增并发热点/风险**（不是越界，而是链表竞争）。另 `ff_ng_base.c:3249 numthreads = mp_ncpus` 无影响（U14） |
| **`mp_maxid = N-1`，`mp_ncpus = N`** | **安全**（`rp_num_hptss == N`，索引与尺寸一致），**但要求 `MAXCPU ≥ N`**（否则 `hpts->p_cpu = i`（`:2010`）传进 `callout_reset_sbt_on`（`:1025/1645/1807/2047`）会触发 `ff_kern_timeout.c:730` 的 panic —— 见 U11） | 每 worker 一个独立 hpts 实例（`hpts_cpuid()` 按 `inp_flowid % mp_ncpus` 分流），**并发热点自然消解**；代价是 N 份`p_hptss`（`asz = sizeof(struct hptsh) * NUM_OF_HPTSI_SLOTS`，`:1920,1924`）内存 + `netisr_maxthreads` 上限放开（默认仍 1，`netisr.c:169`）+ `ff_ng_base.c:3249` 循环变量变大（但 `kproc_kthread_add` 是空 stub，U14 无影响） |

**本节建议（供裁决，非裁决本身）**：从「不引入新的无锁并发热点」角度看，**`mp_ncpus = N` 与 `mp_maxid = N-1` 同步抬高更一致**（每 worker 独占一个 hpts 实例，与本轮 G1「per-thread 隔离」的主旨吻合）；`mp_ncpus` 保持 1 虽然**不越界**，但会让 N 个 worker竞争同一个无锁的 hpts 队列。
⚠ **未坐实项 U16-a**：`tcp_hpts` 在f-stack 里的实际活跃度。`tcp_hpts_thread` 由 `swi_add()` 注册，而 `lib/ff_kern_intr.c:84-89 swi_add(){ return 0; }` 是空 stub、`swi_sched()` 也是空 —— 所以 hpts 的 **swi 线程根本不运行**；但 `__tcp_run_hpts()`（`:1592`）/`tcp_choose_hpts_to_run()` 可能由 `lib/ff_dpdk_if.c` 的 `ff_tcp_hpts_softclock()`（`ff_dpdk_if.c:188` extern 声明）在 `main_loop` 内直接驱动。**若确实由 `main_loop` 驱动，则「N 个 worker 竞争同一个 hpts」的风险是真实的**；若 hpts 实际完全不活跃（例如仅 rack/bbr 栈使用而默认栈是 newreno），风险为 0。**建议手段**：读 `lib/ff_dpdk_if.c` 中 `ff_tcp_hpts_softclock()` 的定义与调用条件 + M5 运行期打印 `hpts->p_on_queue_cnt`/`tcp_pace.rp_num_hptss`。**这一项直接决定上表两个选项的优劣，建议 designer 在 M2 前让某个 agent 补掉。**

---

## 附录 A：未坐实项汇总（禁止在 spec 中当作已证事实使用）

### A.1 本轮**已补做坐实**、从"未坐实"移出的项

| 编号 | 原疑问 | 坐实结论 | 证据 |
|---|---|---|---|
| U2-a | 多页 slab（`uk_ppera>1`）在 f-stack 的 `UMA_PAGE_HASH` 反查表下是否**逐页**登记 | **是，逐页登记，无问题** | `freebsd/vm/uma_core.c:1822-1825`：`if (keg->uk_flags & UMA_ZFLAG_VTOSLAB) for (i = 0; i < keg->uk_ppera; i++) vsetzoneslab((vm_offset_t)mem + (i * PAGE_SIZE), zone, slab);` —— 对 slab 的**每一页**都调一次 `vsetzoneslab`，正好匹配 `lib/include/vm/uma_int.h:85 up_va == (va & ~(PAGE_SIZE-1))` 的单页精确匹配。且 PCPU keg 必然带 `UMA_ZFLAG_OFFPAGE`（`uma_core.c:2406-2407` 排除 inline slab 头、`:2426` 给 OFFPAGE）→ 经 `:2486-2491` 得到 `UMA_ZFLAG_VTOSLAB`（`pcpu_zone_*`/"SMR CPU" 均未设 `UMA_ZONE_NOTPAGE`）。**残留的仅是并发问题**：`vsetzoneslab()` 内 `malloc` + `LIST_INSERT_HEAD` 无锁（见 U8） |
| U2-b | `uma_page_slab_hash` 桶数 / `uma_page_mask` | **已坐实数值** | `lib/ff_freebsd_init.c:304-306`：`num_hash_buckets = 8192; uma_page_slab_hash = kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO); uma_page_mask = num_hash_buckets - 1;` → 8192 桶、mask=8191。放开 PCPU 后 slab 页数 ×N 只会让哈希链变长（**纯性能**，非正确性） |
| U7-a | `subr_smr.c` 的 `critical_enter/exit` 是否是 `uma_crit_lock` | **不是**；且它本身是**空函数体** | `cc -E freebsd/kern/subr_smr.c` 后 `grep -c uma_crit_lock` = **0**；`freebsd/sys/systm.h:~200-210` 的 `critical_enter/exit` 预处理为空体（见 U7 §7.1） |
| U7-b | netisr swi 是否真起 OS 线程 | **不起** | `lib/ff_kern_intr.c:84-89 swi_add(){return 0;}`、`:91-95 swi_sched(){}`、`:97-101 swi_remove(){return 0;}`、`:103-107 intr_event_bind(){return EOPNOTSUPP;}` |
| U7-c | `kproc_kthread_add`/`kthread_add` 是否真建线程 | **不建** | `lib/ff_compat.c:162-169`、`:171-177` 均 `return 0;` 空 stub；`:180-183 kthread_exit(){panic(...)}`、`lib/ff_glue.c:1029-1032 kproc_exit(){panic(...)}` 佐证这些路径本不预期运行 |
| U11-a | `tcp_hpts.c:1997 p_cpu = 0xffff` 是否会被当callout cpu 传下去 | **不会**（两个不同的 for 循环，`:2010 p_cpu = i` 在任何 `callout_reset_sbt_on` 之前覆盖它） | 见 U11 §11.3 的澄清块（`sed -n '1900,1915p;2000,2016p'` 实测） |
| U10 | `mp_maxid` 现状赋值点 | **全程无任何赋值点**（`lib/ff_glue.c:145` 仅 BSS 定义） | 见 U10 §10.1 |
| U16 | `mp_maxid=N-1` 而 `mp_ncpus=1` 时 `tcp_pace.rp_ent[]` 是否越界 | **不越界**（`rp_ent[]` 的每个索引都独立对 `mp_ncpus`/`rp_num_hptss`取模；`inp_to_cpuid()` 全树仅 2 个使用点、都只作 callout 的 cpu 实参） | 见 U16 §16.2~16.4 |
| （leader 旁路）| `smp_topo()` 返回 NULL 是否安全 | **安全**，`tcp_hpts.c:1890 if (cpu_top == NULL) { grp_cnt = 1; }` 显式处理 | 见 U16 §16.5，本文档 `sed -n '1855,1930p'` 实测交叉确认一致 |
| （leader 旁路） | `smp_started` 在 `-DSMP` 后是否引入语义风险 | **不引入**，编译集合内只有 `lib/ff_glue.c:219` 一个读者（sysctl handler） | 见 U16 §16.5 |

> **提示给designer**：U7-a / U7-b / U7-c 已在本表（A.1）中**坐实并关闭**，正文对应处为 §7.1（`_m17_smr.i` 的 `grep -c uma_crit_lock == 0`）、§7.2 与 §13.2（`lib/ff_kern_intr.c:84-107`、`lib/ff_compat.c:162-177`）。**请勿再按「未坐实」引用它们。**
>
> 🔴 **另请务必先读本文档的「C-更正」一节**（位于 U1 之前）：`curcpu` 在 HEAD 基线被硬编码为 `0`（`lib/include/sys/pcpu.h:34`），UMA per-cpu cache 走 `uz_cpu[curcpu]`（`uma_core.c` 11 处）而**不走 `zpcpu_get()`**。该事实由 `designer` 发现、`leader` 复核、本 agent 独立坐实，**推翻了本文档 U7 §7.3 的一处推断**（已就地标注更正），并修正了 U9 #4 的归因。**G1 必须同时改`curcpu`，仅改`pcpu_init()` 的稠密 cpuid 不足以隔离 UMA per-cpu cache。**

### A.2 **仍未坐实**的项（必须以「未坐实」措辞进入 spec）

| 编号 | 未坐实内容 | 原因 | 建议后续手段 |
|---|---|---|---|
| U5-a | `netisr_start`（`SYSINIT... SI_SUB_SMP`，`netisr.c:1365`）确实在 worker 建 pcpu 之前跑完 | 静态时序推断（`mi_startup()` 在 `ff_freebsd_init.c:309`，worker 的 `ff_stack_thread_init` 在 `ff_dpdk_run` 之后）；未运行期验证 | M5 打印 `nws_count` 与 `cpuhead` 长度。**注**：即使推断有误，因`swi_add()` 是空 stub（U7-b），实际影响趋近于 0 |
| U6-a | EAL 主 lcore 一定是 `proc_lcore[0]`（→ 主线程 `proc_id == 0`） | DPDK 默认行为推断，未运行期验证；传`--main-lcore` 可打破 | M5 打印 `rte_get_main_lcore()`/`rte_lcore_id()`/`proc_id`/`pc_zpcpu_offset` 四元组（DoD-1 已要求）。**方案上不应依赖该推断**：主线程也用 `ff_cur_lcore_conf()->proc_id` 取自己的槽位即可 |
| U12-ish | `freebsd/kern/subr_taskqueue.c:368 callout_reset_sbt_curcpu` 在 f-stack 下是否真被走到 | `taskqueue_enqueue_timeout*` 的调用者未穷尽（`taskqueue` 线程不存在，但 `callout_reset`仍可能被调用） | grep `taskqueue_enqueue_timeout` 的调用者；或 M5 运行期观察是否触发 `:730` panic |
| U8-perf | 移除 `uma_crit_lock` 后 zone/keg 慢路径 + `vsetzoneslab` 无锁竞争窗口放大到什么程度、是否会在压测下暴露破链 | **静态分析无法定论**，必须运行期数据 | M5 高并发 soak（`-t8 -c400 -d60s`）+ 去锁前后对比；必要时临时给 `ZDOM_LOCK`/`KEG_LOCK`/`vsetzoneslab` 加真锁做A/B |
| U3 | 全树 `#ifdef SMP` 分布与 `-DSMP` 后新激活/缺失的符号 | **本任务未负责**（由 `res-build` 的 M1-C 承担） | 见 `_m17_C_buildprobe.md` |
| **U16-a** | `tcp_hpts` 在 f-stack 里是否真的活跃（`__tcp_run_hpts()` 是否由 `main_loop` 的 `ff_tcp_hpts_softclock()` 驱动） | `swi_add()`/`swi_sched()` 是空 stub → hpts 的 swi 线程不运行；但 `lib/ff_dpdk_if.c:188` 有 `extern void ff_tcp_hpts_softclock(void);`，其定义与调用条件未读 | 读 `ff_tcp_hpts_softclock()` 定义 + `main_loop` 内调用条件；M5 打印 `tcp_pace.rp_num_hptss`与 `hpts->p_on_queue_cnt`。**这一项直接决定 U16.6 表中两个 `mp_ncpus` 选项的优劣，建议 M2 之前补掉** |

### A.3 本文档提出、需 designer 显式裁决的设计点（非未坐实，而是待决策）

1. **`mp_ncpus` 是否随 `mp_maxid` 一起抬高** —— **U16 已把「安全性」问题关闭：两种取法都不越界**。剩下的是**并发权衡**：`mp_ncpus=1` → N 个 worker 共享1 个无锁 hpts 队列（新增热点）；`mp_ncpus=N` → 每 worker 一个 hpts 实例（更一致），但要求 `MAXCPU ≥ N`。详见 U16.6 表+ 未坐实项 U16-a。
2. **`MAXCPU` 取什么值**（U9：必须 ≥ 线程数；≤64 时 `cpuset_t` ABI 不变；建议一次定死如 16/64）。
3. **`timeout_cpu` 改`__thread`**（U11.4 必做 B）以及是否顺带把 `ff_kern_timeout.c:730` 的判断从 `MAXCPU` 改为 `mp_maxid`（U11.4 可选 C）。
4. **`ff_pthread_create` 线程的处置**（U13.3）：文档化为不支持，还是补 `ff_pcpu_thread_init` + 预留 K 个额外槽位（后者与 H1「`mp_maxid` 须在 `uma_startup1` 前定型」冲突，需配置项）。
5. **G2 的三条路线（G2-a/b/c）**（U8.4）：是否顺带给 `ZDOM_LOCK`/`KEG_LOCK`/`vsetzoneslab` 补真锁。
6. **放开 `UMA_ZONE_PCPU` 的内存放大**（U4.5）：每个 counter 从 8 字节槽变成 `N*4096` 字节 slab，f-stack 内counter 数量众多，须估算总量。

## 附录 B：本文档使用的临时文件（已清理）

`lib/_m17_probe_u1.c`、`lib/_m17_probe_u1.i`、`lib/_m17_probe_u8.c`、`lib/_m17_probe_u8.i`、`_m17_uma_core.i`、`_m17_smr.i`、`_m17_srcset.txt`、`_m17_allc.txt`、`_m17_srcpaths.txt`
—— 全部通过 `/data/workspace/rm_tmp_file.sh` 删除（实测输出 `[OK] all 9 path(s) trashed to /data/workspace/.trash/20260804-051411-923376`），**本 agent 未修改任何源码**。

> 说明：`git status` 中残留的 `M lib/Makefile`、`M lib/ff_glue.c`、`?? lib/_m17_probe_build.c/.o`、`?? _m17_A_clean.log` **属于 `res-build`（M1-C）的编译探针**（见第 0 节的可复现性提示），**不是本 agent 的改动，本 agent 不予清理**。
