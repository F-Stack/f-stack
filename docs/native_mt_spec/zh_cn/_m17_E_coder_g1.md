# _m17_E：M3 编码里程碑 G1 交付（coder）

> 目标：G1 = 让 f-stack 内核视图SMP-aware，每个 stack 线程拥有稠密、独立的 pcpu 槽位，使 UMA/SMR per-cpu 存储按线程数分槽。
> 路线：`_m17_D_verdict.md` 裁决的**候选 A（全树 `-DSMP`）**，严格对齐 D1~D7、D9。
> **G2（移除 `uma_crit_lock`）本轮未做**，等 `designer` 完成 D8 三选一裁决后由 M4 实施。
> 所有编译数字来自实际 `make clean` + 完整 `make` 的输出，无估算。
> **本文含两轮**：第一轮见 §1~§4；**第二轮（bounce 1/3 打回后补做的 `curcpu` per-thread 化）见 §5**，最终状态与最终 clean build 数字以 §5 为准。

---

## 1. 第一轮改动清单（7 个文件，均在 `lib/` 内；`freebsd/` 上游树零改动）

### 1.1 `lib/Makefile`（+4 行）

`CFLAGS+= -DFSTACK` 之后新增：

```make
# SMP makes MAXCPU 1024 so UMA/SMR per-cpu storage is sized for all stack
# threads; without it MAXCPU is 1 and every thread shares slot 0.
CFLAGS+= -DSMP
```

对应 **D1**（`MAXCPU ≥ N` 的硬前置由 `-DSMP` 自动满足：`MAXCPU` 1 → 1024）。未使用 `lib/opt/opt_global.h` 入口，因两者等价而 `CFLAGS` 更显式；降级台阶（`#define MAXCPU 64`）保留给 M5 按需启用。

### 1.2 `lib/ff_glue.c`（+7 行，紧随 `smp_topology` 的 SYSCTL 之后）

```c
/* No CPU topology in userspace; callers must handle NULL (tcp_hpts.c:1890). */
struct cpu_group *
smp_topo(void)
{
    return (NULL);
}
```

`-DSMP` 唯一新增的缺失符号（`_m17_C_buildprobe.md` §2.2 实测）。返回 `NULL` 的安全性已由 leader 坐实：`tcp_hpts.c:1867-1871` 本就有 `#else cpu_top = NULL`，`:1890 if (cpu_top == NULL) grp_cnt = 1`，`:1565 if (grp_cnt > 1)` 才解引用 `grps[]`。落点选`ff_glue.c` 因该文件已 `#include <sys/smp.h>`（`:54`）并已定义 `mp_ncpus`/`mp_maxid`/`all_cpus`/`smp_started`/`smp_disabled`/`smp_topology`，是同类符号的既有归属地。

### 1.3 `lib/ff_freebsd_init.c`

| 位置 | 改动 |
|---|---|
| `:39` | 新增 `#include <sys/smp.h>`（`mp_ncpus`/`mp_maxid` 声明） |
| `:73-74` | 新增 `extern int ff_cur_proc_id(void);` + 一行说明 |
| `:98-115` `ff_pcpu_thread_init()` | **真正使用形参**：`pcpu_init(pcpup, cpuid, ...)`（原为恒 0）；新增**运行期**上界检查（**D6**）；重写了原「cpuid must stay 0」的过时注释 |
| `:281` | 局部变量增加 `int nb_cpus, i;` |
| `:302-324` | 用**三元组同步设置**替换原 `ff_pcpu_thread_init(0); CPU_SET(0, &all_cpus);`（**D2/D4/D7**） |

`ff_pcpu_thread_init()` 新增的上界检查：

```c
    if (cpuid < 0 || (u_int)cpuid > mp_maxid)
        panic("ff_pcpu_thread_init: cpuid %d out of range [0, %u]\n",
            cpuid, mp_maxid);
```

用 `panic()` 而非 `rte_exit()`：本文件是内核态 TU（`-nostdinc` + 内核头），不能引入 DPDK 头。

三元组设置（`uma_startup1()` 之前）：

```c
    nb_cpus = ff_global_cfg.dpdk.thread_mode ?
        ff_global_cfg.dpdk.nb_threads : 1;
    if (nb_cpus < 1)
        nb_cpus = 1;
    if (nb_cpus > MAXCPU)
        panic("nb_threads %d exceeds MAXCPU %d\n", nb_cpus, MAXCPU);

    mp_ncpus = nb_cpus;
    mp_maxid = nb_cpus - 1;
    for (i = 0; i < nb_cpus; i++)
        CPU_SET(i, &all_cpus);

    ff_pcpu_thread_init(ff_global_cfg.dpdk.thread_mode ? ff_cur_proc_id() : 0);
```

- **时序（D2）**：本段位于 `:302-324`，`uma_startup1()` 在 `:331`，`mi_startup()` 在 `:339` → 三元组在 UMA 定尺寸前已定型。
- **`mp_ncpus` 必须同抬（D2 的堆溢出点）**：`ip_fw_dynamic.c:3236` 按 `mp_ncpus` 分配、`:2086-2091` 按 `CPU_FOREACH`（即 `0..mp_maxid` 且 `CPU_ISSET`）填充；本段令 `mp_ncpus == mp_maxid + 1 == all_cpus` 置位数，三者口径一致，故 `cached_count ≤ mp_ncpus`，不溢出。
- **D7 零回归**：`thread_mode == 0` 时 `nb_cpus == 1` → `mp_ncpus=1`、`mp_maxid=0`、`all_cpus` 仅 bit 0、主线程槽位 0，与改动前**逐字等价**。

### 1.4 `lib/ff_dpdk_if.c`

| 位置 | 改动 |
|---|---|
| `:412-416`（`init_lcore_conf()` 之前） | 新增 `int ff_cur_proc_id(void) { return ff_cur_lcore_conf()->proc_id; }` |
| `:2655` | `ff_stack_thread_init(rte_lcore_id())` → `ff_stack_thread_init(qconf->proc_id)`（**D3**；`qconf` 已在 `:2650` 由 `ff_cur_lcore_conf()` 取好） |
### 1.5 `lib/ff_dpdk_if.h`（+2 行）

`int ff_cur_proc_id(void);` 原型声明。

### 1.6 `lib/ff_kern_timeout.c:190`（**D5**）

```c
-static int timeout_cpu;
+static __thread int timeout_cpu;
```

与 `:187__thread struct callout_cpu cc_cpu` 配套。必要性已复核：`:254 timeout_cpu = PCPU_GET(cpuid)` 被每个线程执行，`:1061/:1077 c->c_cpu = timeout_cpu` 会把值写进 callout。改动前 `timeout_cpu` 是共享全局（后写者覆盖），在 cpuid 恒 0 的旧 build 下恰好全为 0 所以无症状；本轮 cpuid 变成稠密非零后，若不加 `__thread` 就会把**别的线程的 cpuid** 写进 `c->c_cpu`，再经 `:815 callout_schedule()` 传回 `:730` 的 `cpu >= MAXCPU` 判断。

---

## 2. 主线程取号方式的说明与依据（D4，含实证链）

**结论：主线程与worker 使用同一取号来源 `lcore_conf[].proc_id`，不依赖「EAL main lcore == `proc_lcore[0]`」这一未坐实推断。**

实证链（逐条实际读码确认）：

1. `ff_init()`（`ff_init.c:38-52`）顺序为 `ff_load_config()` → `ff_dpdk_init()` → `ff_freebsd_init()` → `ff_dpdk_if_up()`；而 `init_lcore_conf()` 在 `ff_dpdk_init()` 内（`rte_eal_init()` 之后第 28 行）被调用。
   → **`ff_freebsd_init()` 执行时 `lcore_conf[].proc_id` 已填好，且 `rte_lcore_id()` 在主线程上已有效**（`rte_eal_init` 已为初始线程设好 per-lcore id）。
2. `ff_dpdk_if.c:436-439`：`thread_mode` 分支中 `for (ti = 0; ti < nb_threads; ti++) { lcore_id = proc_lcore[ti]; lcore_conf[lcore_id].proc_id = ti; }` → `proc_id` 就是 `0..nb_threads-1` 的**稠密序号**（**D3** 指定的现成字段）。
3. `ff_config.c:1477-1483`（`thread_mode` 塌缩）：`nb_threads = nb_procs`、`proc_mask = strdup(lcore_mask)`；`ff_config.c:1156` 把 `-c<proc_mask>` 传给 EAL。而 `parse_lcore_mask()`（`:116-120`）按位升序填 `proc_lcore[count] = idx`。
   → **EAL 的 lcore 集合 == `lcore_mask` 的置位集合 == `{proc_lcore[0..nb_threads-1]}`，三者恒等。**
4. 因此**主线程无论落在哪个 EAL lcore 上（含 `--main-lcore` 改变默认时），它必然是某个 `proc_lcore[k]`**，`lcore_conf[rte_lcore_id()].proc_id` 必为合法稠密值 `k`。取号只依赖「主线程是 EAL lcore」（由 EAL 保证），**不依赖 `k == 0`**。
5. `ff_memory.h:104-111ff_lcore_conf_idx()` = `thread_mode ? rte_lcore_id() : 0`，故 `ff_cur_proc_id()` 在 `thread_mode=1` 下即 `lcore_conf[rte_lcore_id()].proc_id`。

**不撞车证明**：`proc_id` 在 `lcore_conf[]` 中一lcore 一值且互不相同；主线程取自己lcore 的 `proc_id`，各 worker 取各自 lcore 的 `proc_id` → 全局唯一。又因 `rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)`（`ff_dpdk_if.c:2863`）令**主线程自己也跑 `main_loop`**，主线程既是「初始化者」又是「一个 worker」，其两处取号来源相同、值相同，不会出现同一线程两个槽位。主线程在 `main_loop` 里进入 `ff_stack_thread_init()` 时因 `ff_stack_inited`（`ff_freebsd_init.c:82` 定义，主线程在 `:378` 置 1；worker 自身在 `:187` 置 1）而提前返回，**不会重复 `pcpu_init()`**。

**为什么 `thread_mode=0` 不能用 `proc_id`**：`init_lcore_conf()` 的非 thread_mode 分支执行`ff_cur_lcore_conf()->proc_id = ff_global_cfg.dpdk.proc_id`，即**进程序号**（secondary 进程可为 1/2/…）。多进程下每进程独立地址空间、各自只有一个 stack 实例，槽位必须是 0；若误用 `proc_id` 会让 secondary 进程取到非 0 槽位而违反 D7。故代码显式写为 `thread_mode ? ff_cur_proc_id() : 0`。

**为什么内核态 TU 要经`ff_cur_proc_id()` 间接取**：`ff_freebsd_init.c` 以内核 flags 编译（`-nostdinc` + `-include opt_global.h` + FreeBSD 头），无法包含 `ff_memory.h`/DPDK 头（`__rte_cache_aligned`、`rte_lcore_id()` 等）。故在 host TU `ff_dpdk_if.c` 内提供一行访问器，内核侧用 `extern` 声明（与该文件既有的 `extern void mi_startup(void);` 等风格一致）。

---

## 3. clean build 实测记录

**均为「先 `make clean` 再完整 `make`」，无增量编译。**

### 3.1 `lib/`

```
cd /data/workspace/f-stack/lib && make clean && make -j16
```

| 指标 | 实测值 | DoD-3 基线 | 判定 |
|---|---|---|---|
| `make clean` 返回码 | 0 | — | — |
| `make` 返回码 | **0** | 0 | 通过 |
| `grep -c "error:"` | **0** | 0 | 通过 |
| `grep -c "warning:"` | **51** | 51（HEAD 基线） | **未增加**，通过 |
| `.o` 产出 | **248** | 248 | 通过 |
| `libfstack.a` | 生成成功，**7,003,932** 字节（HEAD 基线 6,995,792） | 生成 | 通过 |

### 3.2 `example/`

```
cd /data/workspace/f-stack/example && make clean && make
```

| 指标 | 实测值 | 判定 |
|---|---|---|
| `make clean` 返回码 | 0 | — |
| `make` 返回码 | **0** | 通过 |
| `grep -c "undefined reference"` | **0** | 通过 |
| `grep -c "error:"` | **0** | 通过 |
| `helloworld` | 生成成功，**30,392,712** 字节 | 通过 |
| `helloworld_epoll` | 生成成功，**30,390,208** 字节 | 通过 |

> `helloworld_zc` 按Makefile 既有逻辑跳过（未启用 `FF_ZC_SEND`），与 HEAD 基线行为一致。

### 3.3 工作区状态

`git status --short`（已跟踪文件）：

```
 M config.ini            ← 用户本地测试改动，本agent 全程未触碰
 M lib/Makefile
 M lib/ff_dpdk_if.c
 M lib/ff_dpdk_if.h
 M lib/ff_freebsd_init.c
 M lib/ff_glue.c
 M lib/ff_kern_timeout.c
```

`freebsd/`、`example/` 无跟踪文件改动。未执行 `git commit`（按要求留给 leader 的 M7）。

---

## 4. 请 `reviewer` 重点看的风险点

按我自评的优先级排列，**均为我已识别但未在本轮改动中解决/无法用编译验证的**：

1. **【最高】运行时未验证**：本轮只做到clean build 通过。「每 worker 的 `pc_zpcpu_offset` 互不相同且落在合法分配范围内」（DoD-1）**完全未验证**。特别是 `zpcpu_offset_cpu(cpu) = UMA_PCPU_ALLOC_SIZE * cpu = 4096 * cpu`（`_m17_C_buildprobe.md` §0.3 实测），worker N 的偏移是 4096×N，**必须确认 UMA per-cpu zone 实际分配了 `(mp_maxid+1) × 4096` 字节**，否则仍会越界。`_m17_C_buildprobe.md` 提到 U2（实际编译进来的是 `uma_core.c:1959` 的 `pcpu_page_alloc` 还是 `:2084` 的回退版）**至今未坐实**，而两者对「能否稳定分配 `(mp_maxid+1)*PAGE_SIZE`」的行为不同。**建议 reviewer 把此项列为M5 前必须补的实证**。
2. **【高】`ff_cur_proc_id()` 在 `ff_freebsd_init()` 期的有效性依赖 EAL 内部行为**：我用调用顺序（`ff_dpdk_init` → `ff_freebsd_init`）证明了 `init_lcore_conf()` 已跑、`rte_lcore_id()` 已有效，但「`rte_eal_init` 必然为初始线程设好 lcore id」是 DPDK 的行为约定，**我未用运行期打印实证**。建议 M5 打印 `rte_get_main_lcore()`/`rte_lcore_id()`/`ff_cur_proc_id()`/`PCPU_GET(cpuid)`/`pc_zpcpu_offset` 交叉核对（正好覆盖 `_m17_D_verdict.md` §3-6 的 U6-a 未坐实项）。
3. **【中】`smp_started` / `smp_cpus` 未同步**：`-DSMP` 下二者仍为 `0` / `1`（`ff_glue.c:144`、`:164`）。我按 D2 只改三元组，未擅自扩大范围。我在 `uma_core.c`/`subr_smr.c`/`subr_pcpu.c`/`tcp_hpts.c` 内grep 过这两个符号**无命中**，故判断当前无编译进来的消费者；但**未穷尽全部 238 个 TU**，请 reviewer 复核是否有其它读者（例如 sysctl 展示、`kern.smp.active`）需要一致性。
4. **【中】D9 未处理**：`ff_pthread_create()` 创建的应用线程 `pcpup == NULL`，调用 `ff_*` 即解引用 NULL。本轮**未改任何行为**（与 HEAD 一致），但我新增的 `panic()` 上界检查**不会**覆盖这种情况（它根本不调 `ff_pcpu_thread_init`）。按裁决 D9 应在 spec 记为「不支持的用法」，请确认由 `designer` 落文档而非由我改代码。
5. **【中】`timeout_cpu` 的 `__thread` 化改变了跨线程可见性**：若存在「线程 A 创建 callout、线程 B 处理」的路径，`c->c_cpu` 现在记录的是创建者的 cpuid。因 `CC_CPU(cpu)`/`CC_SELF()`（`ff_kern_timeout.c:184-185`）**忽略 cpu 实参**恒返回调用线程自己的 `cc_cpu`，我判断行为不变；但这条「宏忽略实参」的性质是安全性的**唯一**依托，请 reviewer 复核 `:662/:1181` 等取`cc` 的路径是否都成立。
6. **【低】`MAXCPU=1024` 的开销未量化**：`cpuset_t` 8→128 字节、`cpuid_to_pcpu[]`/`dpcpu_off[]` 1→1024 槽、`netisr.c` 若干 `malloc(...*MAXCPU)`。`libfstack.a` 增大 8,140 字节可作侧证，但**运行期 RSS 未测**。降级台阶见 `_m17_D_verdict.md` §1.3。
7. **【低】`nb_cpus > MAXCPU` 的 `panic()` 实际不可达**：`nb_threads` 上界是 `RTE_MAX_LCORE`（通常 128）< `MAXCPU`（1024）。保留该检查是为了「若将来启用 `MAXCPU=64` 降级台阶」时仍能 fail-loud，属有意的防御性代码，请确认不视为冗余。

### 4.1 我明确**没有**做的事（避免越界）

- **G2（移除 `uma_crit_lock`）未动**：`lib/include/vm/uma_int.h:45-52` 保持原样，等 D8 裁决。
- 未改 `freebsd/` 上游树任何文件。
- 未 `git commit`、未碰 `config.ini`。
- 未处理 `_m17_D_verdict.md` §3 列的 5 项已知偏差（counter(9) 去per-cpu 化、`cache_drain_safe()`、ipfw DPCPU hazard pointer 失效、NUMA 未定义、netisr 不创建真线程）—— 均被裁决明确列为**非本轮修复目标**。

---

## 5. 第二轮：`curcpu` per-thread 化（M3 bounce 1/3 打回后补做）

### 5.1 打回原因（leader / `designer` 指出，我已独立复核坐实）

第一轮只做到「稠密 `pc_cpuid`」，**只修好了 SMR 侧**（`smr.h:110` 走 `zpcpu_get()` → `pc_zpcpu_offset`）。
**UMA per-cpu cache 侧根本不走 `zpcpu_get()`，而是按 `zone->uz_cpu[curcpu]` 定位**，而 `lib/include/sys/pcpu.h:34` 把 `curcpu` 硬编码成了 `0`，覆盖掉上游 `freebsd/sys/pcpu.h:218 #define curcpu PCPU_GET(cpuid)`。
→ 第一轮之后**所有线程仍然共用 `uz_cpu[0]`**，DoD-1 的 UMA 侧必然不通过，且 G2 去掉 `uma_crit_lock` 会把 `b90ddcba5` 修掉的竞态原样放回。

我实际复核确认了 `uz_cpu[curcpu]` 的**全部 11 处**（与 leader 给出的清单逐个一致）：
`freebsd/vm/uma_core.c:1452, 3738, 3776, 3818, 3901, 4534, 4543, 4595, 4628, 4803, 4853`（`grep -c "uz_cpu\[curcpu\]"` = **11**）。

### 5.2 改动（1 个文件 1 行）

`lib/include/sys/pcpu.h:34`：

```c
-#define curcpu    0
+#define curcpu    PCPU_GET(cpuid)
```

保留 `:32#undef curcpu`（避免 `-Werror` 下的 redefined 告警）。因`lib/include/amd64/include/pcpu.h:49` 已把 `PCPU_GET(member)` 重定义为 `(pcpup->pc_ ## member)`，本行等价于 `pcpup->pc_cpuid`，也**正是上游原始语义**。按规约未加注释（改回上游定义，自解释）。

### 5.3 生效性坐实（预处理实测，非推断）

用第二轮 `uma_core.c` 的**真实编译命令**把 `-c` 换成 `-E`，统计 `uz_cpu[...]` 的最终展开：

```
     11 uz_cpu[(pcpup->pc_cpuid)]     ← 11 处 cache 定位，已per-thread
     12 uz_cpu[mp_maxid + 1]
      7 uz_cpu[i]
      1 uz_cpu[cpu]
      1 uz_cpu[]
```

- **11 处全部展开为 `(pcpup->pc_cpuid)`**，与 §5.1 的 11 个 file:line 数量吻合 → 改动确实生效，不是静默无效。
- **顺带闭合了我第一轮列为「最高风险」的一半**：`uma_core.c:3180` 为
  `(sizeof(struct uma_cache) * (mp_maxid + 1)) +` —— zone 的 `uz_cpu[]` **按 `mp_maxid + 1` 定尺寸**。因 `pcpup->pc_cpuid ∈ [0, mp_maxid]`（由 `ff_pcpu_thread_init()` 的运行期检查保证），`uz_cpu[curcpu]` **结构上不越界**。
  > 边界：这是**编译期/结构层面**的证据，运行时仍需按 DoD-1 打印实证；且 §4 风险 1 的另一半（`UMA_ZONE_PCPU` zone 的 `pcpu_page_alloc` 走 `:1959` 版还是 `:2084` 回退版，即 U2）**依旧未坐实**，那是 `zpcpu_get()` 路径的事，与本节的 `uz_cpu[]` 路径是两码事，**不可混为一谈**。

### 5.4 `curcpu` 索引点复核（leader 要求实际复核的 3 点 + 1）

| 使用点 | 索引行为 | 复核结论 |
|---|---|---|
| `lib/ff_kern_synch.c:105 _sleep(&pause_wchan[curcpu], ...)`，`:59 static uint8_t pause_wchan[MAXCPU];` | 直接索引 | **不越界**：`-DSMP` 下 `MAXCPU=1024`，而 `curcpu ≤ mp_maxid = N-1`，N 上界是 `RTE_MAX_LCORE` |
| `freebsd/netinet/tcp_hpts.c:1587 rp_ent[(curcpu % rp_num_hptss)]` | 取模 | **不越界**，且口径一致：`:1864ncpus = mp_ncpus ? mp_ncpus : MAXCPU` → 因本轮 `mp_ncpus = N > 0`，`:1872 rp_num_hptss = ncpus = N`。故 `curcpu % N` 在 `curcpu ∈ [0,N-1]` 时是恒等映射，不发生回绕 |
| `freebsd/net/netisr.c:839 netisr_get_cpuid(curcpu)` | 取模 | **不越界**：`netisr_get_cpuid()` 体为 `return (nws_array[cpunumber % nws_count]);` |
| `freebsd/netinet/tcp_timer.c:237,249 return (curcpu);` | 仅作 callout 的 cpu 实参 | `MAXCPU=1024` 下`ff_kern_timeout.c:730` 的 `cpu >= MAXCPU` 不触发 |

另复核 `freebsd/netinet/tcp_hpts.c:1566 CPU_ISSET(curcpu, &tcp_pace.grps[i]->cg_mask)`：位于 `:1564 if (tcp_pace.grp_cnt > 1)` 之内，而 `smp_topo()` 返回 `NULL` → `:1890 grp_cnt = 1` → **该分支不可达**，`grps[]` 不被解引用（与 `_m17_D_verdict.md` §1.1 对 `smp_topo` stub 的坐实一致）。

### 5.5 新引入风险：按 spec 裁决**不加 NULL 兜底**

`curcpu` 变为 `pcpup->pc_cpuid` 后，在 `pcpup == NULL` 的线程上求值 `curcpu` 会解引用 NULL。**按 spec 裁决刻意不加 NULL 判断**（fail-fast；兜底会把「不支持的用法」伪装成能跑，且必然退化为槽位共享）。前提成立性：主线程在 `ff_freebsd_init.c:324` 最早期即 `ff_pcpu_thread_init()`，worker 在 `ff_stack_thread_init()` 首步（`:195`）即 `ff_pcpu_thread_init()`。`ff_pthread_create()` 线程按 D9 以文档方式声明为不支持。

### 5.6 另一处修正：`ff_stack_thread_init()` 的 thread_mode=0 显式保护

`lib/ff_dpdk_if.c:2655`：

```c
-ff_stack_thread_init(qconf->proc_id);
+    ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0);
```

**我采纳了 leader 的建议，并同时给出「原写法当前确实安全」的论证**（两者不矛盾）：

- 原写法**当前安全**的依据：`ff_freebsd_init.c:378 ff_stack_inited = 1;` 位于 `ff_freebsd_init()` 函数体末尾、`return (0);`（`:380`）之前，**无任何条件包裹**；而 `ff_init()`（`ff_init.c:38-52`）必然在 `ff_run()` → `main_loop` 之前完成。故 `thread_mode=0` 下唯一的 stack 线程进入 `main_loop` 时 `ff_stack_inited == 1`，`ff_stack_thread_init()` 在 `:177-178` 即 `return`，实参根本不被使用。
- **仍然改**的理由：① 该安全性依赖「跨文件的置位时序」这一非局部不变量，而 `init_lcore_conf()` 非 thread_mode 分支确实会把 `lcore_conf[0].proc_id` 设成 `ff_global_cfg.dpdk.proc_id`（secondary 进程为 1/2/…），即**实参在语义上是错的**，只是恰好没被用到；② 一旦该不变量被将来改动破坏，后果是 `ff_pcpu_thread_init()` 的 `panic`（`mp_maxid == 0` 而 cpuid ≥ 1），属硬失败；③ 显式三元与 `ff_freebsd_init.c:324` 主线程取号写法**完全对称**，可读性更好。

### 5.7 第二轮 clean build 实测（最终状态）

**先 `make clean` 再完整 `make`，`lib/` 与 `example/` 均如此，无增量编译。**

`lib/`：

| 指标 | 实测值 | 基线/门槛 | 判定 |
|---|---|---|---|
| `make clean` 返回码 | 0 | — | — |
| `make -j16` 返回码 | **0** | 0 | 通过 |
| `grep -c "error:"` | **0** | 0 | 通过 |
| `grep -c "warning:"` | **51** |≤ 51（HEAD 基线） | **未增加**，通过 |
| `.o` 产出 | **248** | 248 | 通过 |
| `libfstack.a` | 生成成功，**7,002,076** 字节 | 生成 | 通过 |

`example/`：

| 指标 | 实测值 | 判定 |
|---|---|---|
| `make clean` 返回码 | 0 | — |
| `make` 返回码 | **0** | 通过 |
| `grep -c "undefined reference"` | **0** | 通过 |
| `grep -c "error:"` | **0** | 通过 |
| `helloworld` | 生成成功，**30,392,672** 字节 | 通过 |
| `helloworld_epoll` | 生成成功，**30,386,072** 字节 | 通过 |

### 5.8 第二轮后的完整改动面（G1 最终态，须作**同一个提交**）

`git status --short`（已跟踪文件，`config.ini` 为用户本地改动、本agent 全程未碰）：

```
 M config.ini
 M lib/Makefile
 M lib/ff_dpdk_if.c
 M lib/ff_dpdk_if.h
 M lib/ff_freebsd_init.c
 M lib/ff_glue.c
 M lib/ff_kern_timeout.c
 M lib/include/sys/pcpu.h      ← 第二轮新增
```

**8 个文件全部属于 G1 一个原子提交**：`curcpu` 变 `0..N-1` 的前提是 `uz_cpu[]` 已按 `mp_maxid+1` 分配（依赖三元组设置）且 `MAXCPU ≥ N`（依赖 `-DSMP`）。若拆开提交，任一中间态都会出现「`curcpu` 非零但 `uz_cpu[]` 只有 1 槽」或「`MAXCPU=1` 但 cpuid 非零」的**即崩状态**。`freebsd/` 上游树仍为零改动。

### 5.9 第二轮对 §4 风险清单的影响

- §4 风险 1（最高）：**部分闭合**。`uz_cpu[]` 侧的越界问题已由 `uma_core.c:3180` 的 `mp_maxid+1` 定尺寸在结构层面排除（§5.3）。**但 `zpcpu_get()` / `UMA_ZONE_PCPU` 侧的 U2 仍未坐实**，DoD-1 的运行时打印实证仍**完全未做**，风险等级维持「最高」。
- §4 风险 2/3/4/6/7：不变。
- §4 风险 5（`timeout_cpu` 的 `__thread` 化）：不变。
- **新增风险（第二轮引入）**：`curcpu` 现在会解引用 `pcpup`。任何在 `ff_pcpu_thread_init()` 之前、或在未做 per-thread init 的线程上求值 `curcpu` 的路径都会 NULL 解引用崩溃。已按 §5.5 裁决刻意不兜底。

  **我已就「`pcpup == NULL` 窗口」做完实际核查，结论是当前路径安全**（请`reviewer` 独立复核这条推理，它是第二轮最需要第二双眼睛的地方）：

  1. `ff_pcpu_thread_init()` 自身存在一个 `pcpup == NULL` 的窗口 —— `pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO)` 这行**在 `pcpup` 被赋值之前**就调用了 `malloc()`。若内核态 `malloc()` 走 UMA，就会命中 `uz_cpu[curcpu]` → NULL 解引用，**每个 worker 启动即崩**。
  2. 实际核查：**`freebsd/kern/kern_malloc.c` 不在 `lib/Makefile` 的 SRCS 内**（已 grep 确认），内核态 `malloc()` 由 `lib/ff_glue.c:1067-1082` 实现，函数体是 `alloc = ff_malloc(size)`（host侧 `malloc`）+ 可选 `bzero`，**完全不经UMA**。故该窗口安全。
  3. 但 `ff_glue.c:1076` 的失败重试分支 `pause("malloc", hz/100)` → `ff_kern_synch.c:105 _sleep(&pause_wchan[curcpu], ...)` **确实会求值 `curcpu`**。该分支仅在「`ff_malloc` 返回 NULL 且 `flags & M_WAITOK`」时进入；而 `ff_pcpu_thread_init()` 传的是 `M_ZERO`（**不含** `M_WAITOK`），故 `!(flags & M_WAITOK)` 成立、立即 `break`，**不会**走到 `pause()`。
  4. worker 侧顺序也已核：`main_loop`（`ff_dpdk_if.c:2625-2655`）在 `ff_stack_thread_init()` 之前只有局部赋值与 `ff_cur_lcore_conf()`，无任何 UMA/`pause` 路径；`ff_stack_thread_init()`（`:171-195`）的首个实质动作即`ff_pcpu_thread_init()`。主线程侧 `ff_freebsd_init.c:324` 更在 `uma_startup1()`（`:331`）之前，UMA 尚未初始化。
  5. **遗留（真正的残留风险）**：任何**未做 per-thread init 的线程**（即 D9 的 `ff_pthread_create()` 场景）一旦触发 UMA 分配或 `pause()`，现在会 NULL 解引用而非静默共享槽位。这是**刻意的 fail-fast**（§5.5），但意味着 D9 的「不支持的用法」从「静默错」变成了「立即崩」，**spec 的措辞需要相应更新**（请 `designer` 注意：原表述若是「会共享槽位」，现应改为「会 NULL 解引用崩溃」）。

---

## 6. 第三轮：DoD-1 探针（临时代码，M5 后移除）

>本节供 `tester` 直接照做。**我已自行做过一次短时冒烟运行**（thread_mode=1、`lcore_mask=6`），下文的「实测样例」是**真实输出**，不是示意。
> 冒烟运行结束后已用 `/data/workspace/kill_process.sh helloworld` 停止进程；**未修改 `config.ini`**（用的是仓库工作区当时已有的本地测试值）。

### 6.1 探针落点与包裹方式

全部用 `#if 1 /* M17 temporary probe ... */ … #endif` 显眼包裹，**不改变任何控制流**（只有 `printf`）。共 4 处：

| # | 文件:位置 | 内容 |
|---|---|---|
| P1 | `lib/ff_freebsd_init.c` `ff_pcpu_thread_init()` 末尾（`PCPU_SET` 之后） | 打印 `[M17-PROBE]` 标量行 |
| P2 | `lib/ff_freebsd_init.c` `ff_pcpu_thread_init()` 之后新增 `static void ff_probe_slots(int dense_idx)` | 打印 `[M17-PROBE-SLOT]` 槽位地址行 |
| P3 | `lib/ff_freebsd_init.c` `ff_stack_thread_init()` 末尾（`lo_set_defaultaddr()` 之后、`__sync_lock_release()` 之前） | worker 调 `ff_probe_slots(cpuid)` |
| P4 | `lib/ff_freebsd_init.c` `ff_freebsd_init()` 末尾（`ff_stack_inited = 1;` 之后、`return (0);` 之前） | 主线程调 `ff_probe_slots(PCPU_GET(cpuid))` |

配套临时辅助（同样 `#if 1` 包裹，M5 后一并移除）：
- `lib/ff_host_interface.c`：`uint64_t ff_probe_tid(void) { return((uint64_t)pthread_self()); }`
- `lib/ff_host_interface.h`：其声明

> 取 `pthread_self()` 而非 `syscall(SYS_gettid)`：`ff_host_interface.c:53` 本就`#include <pthread.h>`，而 `<unistd.h>`仅在 `FF_KERNEL_COEXIST` 下才包含，用 `pthread_self()` 不需要新增头文件。**注意该值是 pthread 句柄不是 OS tid**，仅用于区分线程，勿与 `ps -T` 的 LWP 对照。

`printf` 可用性已实测确认：内核态 `printf` 由 `lib/ff_subr_prf.c` 提供，`ff_freebsd_init.c:374` 本就在用（`printf("set loopback port default addr failed!")`）。

### 6.2 探针 2 的取值路径（leader 要求「自行确认可行路径」）—— **已取到真槽位地址，无需退化**

`ff_freebsd_init.c` 已包含 `<vm/uma_int.h>`（`:45`）、`<net/vnet.h>`（`:58`）、`<netinet/tcp_var.h>`（`:62`），故可直接取：

```c
    if (V_tcbinfo.ipi_smr != NULL)
        smr_slot = zpcpu_get(V_tcbinfo.ipi_smr);          /* 本线程的 SMR per-cpu 槽 */
    if (V_tcbinfo.ipi_zone != NULL)
        uma_cache = &V_tcbinfo.ipi_zone->uz_cpu[curcpu];  /* 本线程的 UMA cache 槽 */
```

- `ipi_smr`（`freebsd/netinet/in_pcb.h:380`，`smr_t`）与 `ipi_zone`（`:378`，`uma_zone_t`）都是启动期即创建的（TCP PCB info），正是上一轮 SIGSEGV 现场所用的那个 SMR。
- `uz_cpu[]` 可解引用是因为 `uma_int.h:507` 暴露了 `struct uma_cache uz_cpu[];`。
- 两处都做了 NULL 检查，**不会**因取不到而崩。
- `V_tcbinfo` 需要 VNET 上下文：P4 处主线程 `curthread->td_vnet = vnet0` 已在更早设好；P3 处 worker `curthread->td_vnet = v` 已在同函数内设好。**已由冒烟运行证实两处都取到了非 NULL 地址。**

### 6.3 输出格式

```
[M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
[M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
```

### 6.4 **日志落点（重要，与 leader 的预设不同，实测结论）**

`tester` 必须**同时看两个文件**，否则会漏掉主线程的探针行：

| 线程 | 探针行落点 |
|---|---|
| **主线程**（`ff_freebsd_init` 阶段，dense_idx=0） | **`example/f-stack-0.log`** |
| **worker**（`ff_stack_thread_init` 阶段，dense_idx≥1） | **`example/helloworld.log`** |

实测依据：`grep -rl "M17-PROBE"` 只命中这两个文件；`helloworld.log` 内`grep -c "M17-PROBE"` =2（worker 的 P1+P3），主线程的 P1+P4 在 `f-stack-0.log`。
（两者都是**追加写入**，读新增内容须先记旧行数再 `tail -n +N`。）

### 6.5 判定式（DoD-1）

对每个线程各取一组 `[M17-PROBE]` + `[M17-PROBE-SLOT]`：

1. **稠密且不越界**：所有 `dense_idx` 两两不同，取值恰好覆盖 `0..mp_maxid`，且 `dense_idx <= mp_maxid`。
2. **三者一致**：`dense_idx == pc_cpuid == curcpu`。
3. **偏移正确**：`pc_zpcpu_offset == 4096 * dense_idx`（4096 即 `UMA_PCPU_ALLOC_SIZE = PAGE_SIZE`，`zpcpu_offset_cpu(cpu) = UMA_PCPU_ALLOC_SIZE * cpu`）。
4. **三元组正确**：`mp_ncpus == nb_threads`、`mp_maxid == nb_threads - 1`。
5. **SMR 槽位隔离**：任意两线程 `smr_c_seq` 之差 == `4096 * (dense_idx 之差)`。
6. **UMA cache 槽位隔离**：任意两线程 `uma_cache` 之差 == `128 * (dense_idx 之差)`。128 = `sizeof(struct uma_cache)`，**已实测**（`nm --print-size` 取得 `0x80`）。
7. `thread_mode=0` 时：只有一组输出，`dense_idx=0`、`pc_zpcpu_offset=0`、`mp_ncpus=1`、`mp_maxid=0`（D7 零回归）。

### 6.6 我的冒烟运行实测样例（thread_mode=1，`lcore_mask=6` → nb_threads=2）

`example/f-stack-0.log`（主线程）：
```
[M17-PROBE] tid=140496878305280 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=2 mp_maxid=1 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7fc7f719dc80 uma_cache=0x7fc7f5ac9180
```
`example/helloworld.log`（worker）：
```
[M17-PROBE] tid=140496838099968 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=2 mp_maxid=1 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7fc7f719ec80 uma_cache=0x7fc7f5ac9200
```

**逐条对判定式核验（全部通过）**：

| 判定项 | 实测 | 结论 |
|---|---|---|
| ① 稠密不越界 | dense_idx = {0, 1}，mp_maxid=1 | ✓ |
| ② 三者一致 | 0==0==0；1==1==1 | ✓ |
| ③ 偏移 | 0 == 4096×0；4096 == 4096×1 | ✓ |
| ④ 三元组 | mp_ncpus=2=nb_threads；mp_maxid=1 | ✓ |
| ⑤ SMR隔离 | `0x7fc7f719ec80 - 0x7fc7f719dc80 = 0x1000 = 4096 == 4096×1` | ✓ |
| ⑥ UMA 隔离 | `0x7fc7f5ac9200 - 0x7fc7f5ac9180 = 0x80 = 128 == 128×1` | ✓ |
| 无崩溃 | 新增日志中 `grep -iE "panic|segmentation|out of range"` 无命中；进程存活 25s后由`kill_process.sh` 正常终止 | ✓ |

> **这组数据首次实证了 G1 的两个目标同时达成**：SMR 侧（`zpcpu_get()` 路径，槽距 4096）与 UMA cache 侧（`uz_cpu[curcpu]` 路径，槽距 128）**都已按线程隔离**，不再共用槽位。
> **边界（必须如实转述）**：这只是 **2 线程、启动期、单次短时** 冒烟，**不构成 DoD-1 的完整验收**。仍需 `tester` 跑 1/2/4 线程矩阵 + `thread_mode=0` 对照 + 负载下 soak。另外它**仍未回答 U2**（`UMA_ZONE_PCPU` zone 的 `pcpu_page_alloc` 走 `uma_core.c:1959` 还是 `:2084`）—— ⑤ 只证明了「相邻线程 SMR 槽距 4096」，**没有**证明「该 zone 真的分配了 `(mp_maxid+1)×4096` 字节而非越界访问到相邻内存」。**U2 仍须坐实**（建议 `tester` 在 4 线程下重点观察，若 zone 只分配了 1 页，dense_idx=1..3 的槽位就是越界内存，短时冒烟不一定立刻崩）。

### 6.7 第三轮 clean build 实测

**先 `make clean` 再完整 `make`。**

| 指标 | `lib/` | `example/` |
|---|---|---|
| `make clean` 返回码 | 0 | 0 |
| `make` 返回码 | **0** | **0** |
| `grep -c "error:"` | **0** | **0** |
| `grep -c "warning:"` | **51**（≤ 基线 51，**探针零新增告警**） | — |
| `undefined reference` | — | **0** |
| `.o` 产出 | **248** | — |
| 产物 | `libfstack.a` | `helloworld` **30,392,704** 字节、`helloworld_epoll` **30,386,112** 字节 |

探针确已进入二进制：`strings helloworld | grep -c "M17-PROBE"` = **2**（两条格式串）。

### 6.8 第三轮改动面（探针属**临时代码**，DoD-8 须清理）

在§5.8 的 8 个文件基础上新增 2 个：

```
 M lib/ff_host_interface.c    ← 临时：ff_probe_tid()
 M lib/ff_host_interface.h    ← 临时：其声明
```

`lib/ff_freebsd_init.c` 内的P1/P2/P3/P4 亦为临时。**M5 结束后一次性移除全部 5 个 `#if 1 /* M17 temporary probe */` 块**（`grep -rn "M17 temporary probe" lib/` 可一次列全）。

> **给 leader 的提交建议**：探针**不应**进入 G1 的正式提交。建议 G1 提交只含 §5.8 的 8 个文件中的**代码改动**，探针留在工作区供 `tester` 使用，M5 后移除；若为便于 `tester` 复现而必须提交，则应作为独立的临时提交并在 M5 后 revert。请leader 裁决。

---

## 7. 第四轮：M3 门禁打回修复（bounce 2/3，对应 `_m17_gate_code_g1.md`）

### 7.1 必改 1（P2）：`pause()` 路径在 `pcpup == NULL` 时的段错误—— 已修

**我接受 `reviewer` 的判定并纠正我自己第二轮 §5.9 的结论。**
我第二轮只核到「`ff_pcpu_thread_init()` 里那次 `malloc()` 传的是 `M_ZERO`、不含 `M_WAITOK`，故不会走到 `pause()`」，据此判定「当前路径安全」。**这个结论范围下得太窄了**：`pause()` 还可以从**其它**带 `M_WAITOK` 的早期分配（`ff_freebsd_init():284-298` 的 `kern_setenv` 系列）以及 D9 场景到达，那些路径同样处于 `pcpup == NULL` 窗口。

更关键的是 `reviewer` 指出的**性质判定**（我复核后完全同意）：改动前 `curcpu` 是**字面量 0**，`&pause_wchan[0]` 是合法地址、`_sleep` 走超时路径正常重试 → **原代码在该边角能正常工作**；`curcpu` per-thread 化后变成**确定性段错误**。这是第二轮**新引入的可用性回归**，不是既有脆弱点。

修复（`lib/ff_kern_synch.c:102-108`）：

```c
int
pause_sbt(const char *wmesg, sbintime_t sbt, sbintime_t pr, int flags)
{
    /* Reachable from malloc()'s OOM retry before this thread has a pcpu. */
    return (_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], NULL, 0, wmesg,
        sbt, pr, flags));
}
```

- 未新增 `extern` 声明：`pcpup` 经 `lib/include/amd64/include/pcpu.h:45 extern __thread struct pcpu *pcpup;`（由 `<sys/pcpu.h>` → `<machine/pcpu.h>` 链引入）**已可见**，而 `ff_kern_synch.c` 原本就在用 `curcpu`（同一条头链），故这是最小写法。
- **兜底范围严格限定在这一处**。按 leader 的裁决细化：D9（应用线程误调 `ff_*`）继续 **fail-fast，不加兜底**；只有 `pause()` 这条bootstrap/OOM 重试路径加兜底，因为它是正常代码的正常分支而非误用。

### 7.2 必改 2：假注释与冗长注释 —— 已修

**(a) `lib/ff_kern_timeout.c:179-181`（`reviewer` §2.5/§2.9判为硬规约违反）**

原注释括号内 `cpuid is always 0, MAXCPU=1` 在 G1 之后**两句都为假**，而它恰是「`CC_CPU` 忽略实参是安全的」的唯一书面依据，留着会误导维护者。改为陈述真正的理由：

```c
/* Per-thread callout_cpu: each stack instance drives its own callwheel.
 * CC_CPU/CC_SELF ignore the cpu arg and return the calling thread's own
 * instance, so c_cpu is only a record of which thread armed the callout. */
```

**(b) `lib/ff_freebsd_init.c` 主线程取号注释（§2.9 建议精简）**：4 行 → **2 行**：

```c
    /* Main thread is itself an EAL lcore worker (CALL_MAIN), so it takes its
     * own dense slot; thread_mode=0 has one stack per process -> slot 0. */
```

§2.9 判定为「必要、应保留」的 5 处注释均**未改动**。

### 7.3 必改 3：DoD-1 探针已于第三轮补齐 —— 供 `reviewer` 复审核对

`reviewer` 审核项 11判「不通过」是基于其**较早的工作区快照**（当时探针尚未加入）。**第三轮（§6）已补齐**，请复审时核对：

- 落点 4 处 + 临时辅助 2 处，全部 `#if 1 /* M17 temporary probe */` 包裹，**不改变控制流**（仅 `printf`）。清理清单：`grep -rn "M17 temporary probe" lib/` 共 6 行 / 5 个块。
- 输出格式：
  ```
  [M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
  [M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
  ```
- 判定式7 条见 §6.5；**日志落点见 §6.4（主线程在 `example/f-stack-0.log`、worker 在 `example/helloworld.log`，两个都要看）**。
- 已实测样例与逐条核验见 §6.6：2 线程下 SMR 槽距 = 4096、UMA cache 槽距 = 128（= 实测 `sizeof(struct uma_cache)`），均为 `×Δdense_idx`。

### 7.4 `curcpu` per-thread 化的两处语义变化（`reviewer` 发现，按要求如实记录供 `designer` 写入 spec 残留风险）

**A. `net.isr.dispatch` 必须保持 `direct`**
`netisr.c:155-157` 的 dispatch policy 是**可调 sysctl**。若被设为 `hybrid`/`deferred`，worker 的 `curcpu != nws_array[0]`，会在 `:1172` 走 `queue_fallback` 把报文投入 netisr 队列；而 f-stack 的 netisr swi 是空 stub（`ff_kern_intr.c`）→ **报文进队后无人处理（静默丢包/卡住）**。
改动前 `curcpu ≡ 0` 恒等于 `nws_array[0]`，故该分支不会命中；**per-thread 化后该保护消失**。
→ **结论：必须保持 `net.isr.dispatch = direct`（默认值即 direct）**。建议 spec 明确列为约束，并考虑在 M4/后续加启动期断言。

**B. `tcp_hpts` 实例数 1 → N，且callout 归属与驱动线程错配**
`tcp_hpts.c:1864ncpus = mp_ncpus` → 实例数由 1 变**N**，每实例分配 `p_hptss`（`sizeof(struct hptsh) * NUM_OF_HPTSI_SLOTS`），内存开销 ×N。
更实质的是**归属错配**：`tcp_hpts_init()` 由**主线程**在 `mi_startup()` 期执行 → N 个 callout 全部挂在**主线程**的 `__thread cc_cpu` callwheel 上；而 `__tcp_run_hpts()` 的 `:1587 rp_ent[curcpu % N]` 由**各 worker** 选取**不同** entry。即「worker 驱动的 hpts entry，其 callout 却归主线程 callwheel」。
`hpts->p_mtx` 是 `MTX_DEF`，而 f-stack 全部 `mtx` 已被 stub 成 `((void)0)`（`lib/include/sys/mutex.h`）→ **无实际互斥**，当前靠 Giant 掩盖。
→ 属**本轮未修复的残留风险**，请 `designer` 写入 spec；`FF_TCPHPTS=1` 已编译（`lib/Makefile:51`），M5 压测应关注 rack/bbr 相关路径。

### 7.5 第四轮 clean build 实测

**先 `make clean` 再完整 `make`。**

| 指标 | `lib/` | `example/` |
|---|---|---|
| `make clean` 返回码 | 0 | 0 |
| `make` 返回码 | **0** | **0** |
| `grep -c "error:"` | **0** | **0** |
| `grep -c "warning:"` | **51**（= HEAD 基线，含探针**零新增**） | — |
| `undefined reference` | — | **0** |
| `.o` 产出 | **248** | — |
| 产物 | `libfstack.a` | `helloworld` **30,392,704**字节、`helloworld_epoll` **30,386,112** 字节 |

### 7.6 一次与 `tester` 的运行时冲突（如实记录 + 我已采取的措施）

修完三项后我做了一次冒烟复验，**与 `tester` 的运行时工作发生了时间重叠**，两点如实记录：

1. **该次冒烟读到的配置不可信，其数据已作废**：`config.ini` 的 mtime 为 `14:16:01`，而我的进程约在 `14:16:00` 启动 —— 正好撞上 `tester` 编辑配置。该次输出为 `mp_ncpus=1 mp_maxid=0 dense_idx=0`（单实例），与 §6.6 那次（`mp_ncpus=2`）不一致。**我不把它当作 D7（thread_mode=0 零回归）的证据**，因为无法确定进程实际读到的是哪个版本的配置。D7 仍待 `tester` 在受控配置下验证。
2. **`kill_process.sh <name>` 按进程名匹配存在误伤 `tester` 进程的风险**。本次**经审计确认未误伤**：最后一次 kill 的审计快照 `/tmp/.trash/20260804-061609-988598-kill/` 内**只有 `kill_987958.snap`**（我自己的 pid，快照时间 `14:16:10`），而 `tester` 的 pid `988684` 启动于 `14:16:14`（晚于枚举时刻），未被纳入，且现仍存活。
   → **措施**：我**不再启动任何运行时进程**，运行时归 `tester`。**并建议团队约定**：`tester` 活跃期间，其他 agent 若必须用 `kill_process.sh`，一律**传具体 PID 而非进程名**，避免按名匹配连带击中他人进程。

### 7.7 第四轮后的完整改动面

正式代码改动（**9 个文件**，须同一原子提交）：

```
 M lib/Makefile
 M lib/ff_dpdk_if.c
 M lib/ff_dpdk_if.h
 M lib/ff_freebsd_init.c
 M lib/ff_glue.c
 M lib/ff_kern_synch.c        ← 第四轮新增
 M lib/ff_kern_timeout.c
 M lib/include/sys/pcpu.h
```
（上列8 项 + `lib/ff_freebsd_init.c` 内的正式改动；`freebsd/` 上游树仍**零改动**）

纯探针改动（**临时**，M5 后移除，建议不进G1 正式提交）：

```
 M lib/ff_host_interface.c
 M lib/ff_host_interface.h
 （+ lib/ff_freebsd_init.c 内的 4 个 #if 1 探针块）
```

`config.ini` 为 `tester`/用户的本地测试值，**本 agent 全程未修改**。未执行 `git commit`。

---

## 8. G1 最终交付清单（供 `tester` 与 `reviewer` 直接取用）

>状态：M3 bounce-2 三项**已全部完成**（§7），`lib/`与 `example/` clean build 通过。以下为最终态。

### 8.1 被测二进制指纹（`tester` 核对版本用）

构建时间 `2026-08-04 14:15:30/31`，已确认**无任何源文件比产物更新**（`find lib -newer lib/libfstack.a` 为空），即产物包含 §7 的全部修复。

| 文件 | 大小（字节） | md5 |
|---|---|---|
| `lib/libfstack.a` | 7,003,564 | `ed148bd32e14dc290b8ead23d091b1b5` |
| `example/helloworld` | 30,392,704 | `88b8cf93e0b8d3765e76b3c26c6a8f3b` |
| `example/helloworld_epoll` | 30,386,112 | `a828db8e06996143f8b83987c8a6127c` |

（以上三项均为 `md5sum` / `ls -l` 实测值。）

**若 `tester` 手上的 md5 与上表不符，说明版本不一致，请勿开跑**，先通知我重建。

### 8.2 最终文件清单（10 个文件，明确区分正式改动 / 临时探针）

**A. 正式改动 —— 应进入 commit-1（G1），共 8 个文件**

| # | 文件 | 改动要点 |对应约束 |
|---|---|---|---|
| 1 | `lib/Makefile` | `CFLAGS+= -DSMP` | D1 |
| 2 | `lib/ff_glue.c` | `smp_topo()` 返回 NULL | 候选 A 唯一缺失符号 |
| 3 | `lib/ff_freebsd_init.c` | 三元组（`mp_ncpus`/`mp_maxid`/`all_cpus`）早于 `uma_startup1()`；`ff_pcpu_thread_init()` 真正用形参 + 运行期上界检查；主线程按 `ff_cur_proc_id()` 取稠密槽位 | D2/D3/D4/D6/D7 |
| 4 | `lib/ff_dpdk_if.c` | 新增 `ff_cur_proc_id()`；worker 传稠密 `proc_id`（含 thread_mode=0 显式保护） | D3/D4/D7 |
| 5 | `lib/ff_dpdk_if.h` | `ff_cur_proc_id()` 原型 | — |
| 6 | `lib/ff_kern_timeout.c` | `timeout_cpu` 加 `__thread`；修正假注释 | D5 |
| 7 | `lib/include/sys/pcpu.h` | `curcpu` 由硬编码 `0` 改回 `PCPU_GET(cpuid)` | UMA cache 侧分槽（第二轮） |
| 8 | `lib/ff_kern_synch.c` | `pause_wchan[]` 索引加 `pcpup != NULL` 兜底 | 第四轮 P2 修复 |

**B. 临时探针 —— 建议不进 commit-1，M5 后移除（DoD-8 清理项），共 2 个文件 + 1 处内嵌**

| # | 文件 | 内容 |
|---|---|---|
| 9 | `lib/ff_host_interface.c` | `ff_probe_tid()`（`#if 1 /* M17 temporary probe */`） |
| 10 | `lib/ff_host_interface.h` | 其声明（同样包裹） |
| — | `lib/ff_freebsd_init.c` **内**的 4 个 `#if 1` 探针块 | P1/P2/P3/P4，与该文件的正式改动**同文件混存** |

> **给 leader 的提交提示**：第 10 项的存在意味着 `lib/ff_freebsd_init.c` 同时含正式改动与探针块。若要让 commit-1 干净，需在提交前先移除该文件内的 4 个探针块（`grep -rn "M17 temporary probe" lib/` 一次列全 5 个块 / 6 行）。是否如此处理，请 leader 裁决。
> `freebsd/` 上游树 **零改动**（已多次实测确认）。`config.ini` 本agent 全程未修改。

### 8.3 探针字段语义与判定式（`tester` 判定「两两相差 4096×Δidx」的依据）

**输出格式**

```
[M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
[M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
```

**字段含义**

| 字段 | 来源 | 含义 |
|---|---|---|
| `tid` | `ff_probe_tid()` = `(uint64_t)pthread_self()` | **pthread 句柄，不是 OS tid**，仅用于区分线程；**勿**与 `ps -T` 的 LWP 对照 |
| `dense_idx` | `ff_pcpu_thread_init()` 的形参 | 传入的稠密槽位号（thread_mode=1 时来自 `lcore_conf[].proc_id`） |
| `pc_cpuid` | `pcpup->pc_cpuid` | `pcpu_init()` 实际写入的 cpuid，应 == `dense_idx` |
| `pc_zpcpu_offset` | `pcpup->pc_zpcpu_offset` | `subr_pcpu.c` 置为 `zpcpu_offset_cpu(cpuid)` = `UMA_PCPU_ALLOC_SIZE * cpuid` = **4096 × cpuid** |
| `mp_ncpus` / `mp_maxid` | 全局 | 应为 `nb_threads` / `nb_threads - 1` |
| `curcpu` | 宏 → `pcpup->pc_cpuid` | 第二轮改动后的实际取值，应 == `dense_idx` |
| **`smr_c_seq`** | **`zpcpu_get(V_tcbinfo.ipi_smr)`** | **取的是 TCP PCB info 的 SMR**（`freebsd/netinet/in_pcb.h:380smr_t ipi_smr`，由 `in_pcb.c` 的 `uma_zone_get_smr()` 创建）**本线程的 per-cpu 槽地址**。这正是上一轮 SIGSEGV 现场所用的那个 SMR。槽距由 `zpcpu_offset_cpu()` 决定 → **应为 4096 × Δdense_idx** |
| **`uma_cache`** | **`&V_tcbinfo.ipi_zone->uz_cpu[curcpu]`** | **取的是 TCP PCB zone**（`in_pcb.h:378 uma_zone_t ipi_zone`，即 `uma_zcreate("tcp_inpcb", ...)` 那个 zone）**本线程的 UMA cache 槽地址**。槽距是 `sizeof(struct uma_cache)` → **应为 128 × Δdense_idx**（128 已由 `nm --print-size` 实测） |

> 两者都做了 NULL 检查：若 `ipi_smr`/`ipi_zone` 为 NULL 则打印 `(nil)`。**正常情况下不应出现 `(nil)`**（我的冒烟运行两处均取到非 NULL）。

**判定式（7 条，完整版见 §6.5）**：核心是
1. 所有 `dense_idx` 两两不同且恰好覆盖 `0..mp_maxid`；
2. `dense_idx == pc_cpuid == curcpu`；
3. `pc_zpcpu_offset == 4096 × dense_idx`；
4. `mp_ncpus == nb_threads`、`mp_maxid == nb_threads - 1`；
5. **任意两线程 `smr_c_seq` 之差 == 4096 × (dense_idx 之差)**；
6. **任意两线程 `uma_cache` 之差 == 128 × (dense_idx 之差)**；
7. `thread_mode=0`：单组输出，`dense_idx=0`、`pc_zpcpu_offset=0`、`mp_ncpus=1`、`mp_maxid=0`。

**日志落点（务必两个文件都看，见 §6.4）**：主线程 → `example/f-stack-0.log`；worker → `example/helloworld.log`。两者均**追加**写入，读新增内容须先记旧行数再 `tail -n +N`。

### 8.4 `tester` 报的 virtio PCI 报错—— **已定位：无害的既有告警，不是残留进程/hugepage/socket 冲突**

报错原文：
```
VIRTIO_INIT: eth_virtio_pci_init(): Failed to init PCI device
PCI_BUS: Requested device 0000:00:05.0 cannot be used
```

**实测的设备拓扑**（`dpdk-devbind.py --status-dev net`）：

```
Network devices using DPDK-compatible driver
0000:00:09.0 'Virtio network device 1000' drv=igb_uio unused=
Network devices using kernel driver
0000:00:05.0 'Virtio network device 1000' if=eth1 drv=virtio-pci unused=igb_uio *Active*
```

**成因**：`config.ini` 的 `[dpdk]` 段**没有** `allow`/`pci_whitelist` 条目（已grep 确认），故 EAL 会扫描**全部** PCI 设备。扫到 `0000:00:05.0` 时，因该设备是**内核占用且Active 的 `eth1`**（驱动 `virtio-pci`），DPDK 无法接管，于是打印上述两行；随后 EAL 继续使用 `0000:00:09.0`（`igb_uio`）作为 port 0（`config.ini:89 port_list=0`），启动正常继续。

**决定性证据**：该告警在**我自己成功的冒烟运行**中同样出现，且紧接其后就是正常的探针输出与建栈成功日志（`example/helloworld.log` 我那次运行的片段）：

```
EAL: Selected IOVA mode 'PA'
VIRTIO_INIT: eth_virtio_pci_init(): Failed to init PCI device
PCI_BUS: Requested device 0000:00:05.0 cannot be used
[M17-PROBE] tid=140496838099968 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=2 mp_maxid=1 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7fc7f719ec80 uma_cache=0x7fc7f5ac9200
```
同一次运行的 `f-stack-0.log` 亦有 `Successed to register dpdk interface`与 `Addr6: 2402:...`。

→ **结论：可以忽略，不影响 `tester` 的阶段 2/4。**

**⚠️ 严重警告（务必转达 `tester`）**：**绝对不要**把 `0000:00:05.0` 绑定到 DPDK（`igb_uio`/`vfio-pci`）。它是**内核侧 Active 的 `eth1`**，很可能承载本机管理/SSH 通道；一旦绑定会立即失去连通性。DPDK 侧该用的网卡是 `0000:00:09.0`（已绑 `igb_uio`），对应 `config.ini` 的 `<DPDK_NIC_IP>`。

**（可选）消除该告警**：在 `config.ini` 的 `[dpdk]` 段加 `allow=0000:00:09.0`，让 EAL 只探测DPDK 网卡。
> 但这属**本地测试值，严禁入库**（与 `lcore_mask`/`idle_sleep`/`[port0]` 本机 IP 同类）。若`tester` 采用，请在提交前回滚。

### 8.5 另一项运行环境观察（供 `tester` 参考，我未做任何清理）

我做只读探测时（当时 `pgrep -a helloworld` 为空、无进程运行）观察到：

```
HugePages_Total:    4096
HugePages_Free:     4063     ← 33 页在无进程状态下仍被占用
HugePages_Rsvd:        0
```

即存在**残留 hugepage 占用**（约 66 MB），推测为此前异常退出的进程留下的 `rtemap_*` 文件未释放；`/var/run/dpdk/rte/` 亦有较新 mtime 的运行时文件，另有一个陈旧的 `/var/run/dpdk/ff_kni_test/`（mtime 7-27）。
量级很小，一般不影响启动；但若 soak 阶段出现内存池分配失败可优先排查。

**清理时的强制规约**：删除残留文件**必须**用 `/data/workspace/rm_tmp_file.sh<绝对路径>`，终止残留进程**必须**用 `/data/workspace/kill_process.sh`，**严禁**直接 `rm`/`kill`。
**并请注意**（§7.6 已记录）：`kill_process.sh` 传**进程名**会按名匹配到**所有**同名进程，在多agent 并行期有误伤他人进程的风险 —— 建议一律**传具体 PID**。

---

## 9. 第五轮：修复 `mp_maxid >= 2` 启动崩溃（M3 bounce 3/3）

### 9.1 根因独立复核 —— **确认 leader/`tester` 的定位成立**

我**未盲抄**，逐点打开代码复核（结论：链条完整成立）：

| 环节 | 复核结果 |
|---|---|
| `zsize` 随 CPU 数增长 | `freebsd/vm/uma_core.c:3179-3182`：`zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + sizeof(struct uma_zone_domain)*vm_ndomains`，再 `roundup(zsize, UMA_SUPER_ALIGN)` ✓。**实测尺寸**（`nm --print-size`）：`uma_zone`=**384**、`uma_cache`=**128**、`uma_zone_domain`=**128**、`UMA_SUPER_ALIGN`=**128**；`vm_ndomains=1`（`ff_glue.c:83`）→ `zsize = roundup(512 + 128×N, 128) = 512 + 128×N`，每多 1 CPU 涨 **128** 字节 ✓ |
| 多页 slab 可被启用 | `uma_core.c:383 static int multipage_slabs = 1;`（默认开）；`:2440-2470` 的 `for ( ; ; i++)` 在 `kl.eff < UMA_MIN_EFF` 且 `multipage_slabs` 时继续增大 `slabsize` ✓ |
| 多页 → 置 VTOSLAB | `uma_core.c:2486-2492`：`if ((uk_flags & UMA_ZFLAG_OFFPAGE) != 0 \|\| (keg->uk_ipers - 1) * rsize >= PAGE_SIZE)` → 否则分支 `keg->uk_flags \|= UMA_ZFLAG_VTOSLAB` ✓ 单页时 `(ipers-1)*rsize < PAGE_SIZE` 不置；跨页时 `>= PAGE_SIZE` 置上 |
| VTOSLAB 的**实际调用点** | `uma_core.c:1822-1825`（`keg_alloc_slab()` 内）：`if (keg->uk_flags & UMA_ZFLAG_VTOSLAB) for (i = 0; i < keg->uk_ppera; i++) vsetzoneslab(...)` ✓ 与崩溃栈 `zone_import → zone_alloc_item → uma_startup1` 一致 |
| `vsetzoneslab` 依赖哈希表 | `lib/include/vm/uma_int.h:107-126`：`hash_list = &uma_page_slab_hash[UMA_PAGE_HASH(va)];` 随后 `LIST_FOREACH` → **`uma_page_slab_hash == NULL` 时解引用 NULL** ✓ |
| 初始化顺序倒置 | 修复前 `lib/ff_freebsd_init.c`：`uma_startup1()` → `uma_startup2()` → **之后**才 `uma_page_slab_hash = kmem_malloc(...)` / `uma_page_mask = ...` ✓ 即 `uma_startup1()` 全程 `uma_page_slab_hash == NULL`、`uma_page_mask == 0` |

**结论**：这**不是** G1 三元组设置本身有错，而是 f-stack「`uma_page_slab_hash` 在 `uma_startup1()` 之后才初始化」这一**既有隐含假设**，仅在 `mp_maxid == 0`（zone 小 → 单页 slab → 永不置 VTOSLAB）时成立。G1 抬高 `mp_maxid` 后假设破裂 → 确定性崩溃。**属 G1 暴露出的既有缺陷，非 G1 逻辑错误。**

> 关于精确阈值：我**没有**手工推导「恰好 N=3 越界」的 `ipers`/`eff` 数值—— `keg_layout_one()` 对 `UMA_ZFLAG_INTERNAL` 会 `slabsize += PAGE_SIZE`、并经 `slab_ipers_hdr()` 计入内联 slab 头，手算易错。**故本文不断言具体 N 的算术**，只断言机制（已逐点坐实）+ 实测行为（1/2 线程正常、3/4 线程崩溃、修复后 3/4 均正常）。

### 9.2 leader 要求我自行复核的三点

**① `kmem_malloc` 是否真的不依赖 UMA —— 确认不依赖。**
`lib/ff_glue.c:1032-1039` 直接走 host `mmap`：`void *alloc = ff_mmap(NULL, bytes, ...ff_MAP_ANON|ff_MAP_PRIVATE, -1, 0);` +可选 `bzero`，**零 UMA 依赖**。且修复前 `boot_pages` 的 `kmem_malloc` 本就在 `uma_startup1()` 之前成功调用 → 提前哈希表分配**不引入任何新依赖** ✓

**② `sizeof(struct uma_page) * 8192` 与 `struct uma_page_head` 的类型匹配性 —— 是既有的「过量分配」，安全，按要求未改。**
实测 `sizeof(struct uma_page)` = **40** 字节，`sizeof(struct uma_page_head)`（`LIST_HEAD`，单指针）= **8** 字节。数组元素类型是 `uma_page_head` 却按 `uma_page` 尺寸分配 → **多分配 5 倍**（320KB vs 实需 64KB）。方向**偏大而非偏小，不存在越界**，功能正确，仅浪费约 256KB。按指示**保持既有写法**，在此如实记录供 `designer` 作为「可选优化项」写入 spec（**不建议本轮改**，避免 bounce 3/3 引入无关变更）。
另确认 `M_ZERO` 全零内存等价于 `LIST_INIT` 后的空链表头（`LIST_HEAD` 唯一成员 `lh_first` 为 NULL 即空）→ 提前分配后无需额外 `LIST_INIT` ✓

**③ 提前后 `uma_startup2()`/`mi_startup()` 期的 `vtoslab`/`vtozoneslab` 是否正常 —— 正常。**
提前只是让哈希表**更早**可用；`uma_startup2()`/`mi_startup()` 原本就在哈希表初始化**之后**运行，故其所见状态不变或更好。已由 §9.4 的 3/4 线程实测佐证（`mi_startup()` 期会创建大量 zone，含走 VTOSLAB 的 `UMA_ZONE_MALLOC` keg —— 见 `uma_core.c:2543-2544` 的**另一条**独立 VTOSLAB 设置路径，这些在修复前后都发生在哈希表就绪之后）。

### 9.3 修法（采纳 leader 推荐，最小改动）

`lib/ff_freebsd_init.c`：把哈希表初始化**整体上移到 `uma_startup1()` 之前**，并加注释说明这个**非显而易见的时序不变式**：

```c
    /*
     * Must precede uma_startup1(): once mp_maxid > 0 the zone-of-zones grows
     * past the single-page slab threshold, which sets UMA_ZFLAG_VTOSLAB and
     * makes keg_alloc_slab() call vsetzoneslab() during uma_startup1().
     */
    num_hash_buckets = 8192;
    uma_page_slab_hash = (struct uma_page_head *)kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO);
    uma_page_mask = num_hash_buckets - 1;

    boot_pages = 16;
    bootmem = (void *)kmem_malloc(boot_pages*PAGE_SIZE, M_ZERO);
    //uma_startup(bootmem, boot_pages);
    uma_startup1((vm_offset_t)bootmem);
    uma_startup2();
```

**未采用**「给 `vsetzoneslab` 加 NULL 兜底」：会静默丢失 slab 登记，后续 `vtoslab()` 返回 NULL 在别处崩（且 `uma_int.h:80-101` 的 `vtozoneslab` 在 `LIST_FOREACH` 未命中时本就有 `*slab = up->up_slab` 解引用 NULL 的既有隐患），与 leader 判断一致。

### 9.4 运行时验证（我自己实跑，非引用 `tester`）

启动：`setsid nohup /data/workspace/f-stack/example/helloworld --conf /data/workspace/f-stack/config.ini --proc-type=primary --proc-id=0< /dev/null > <log> 2>&1 &`；停止**一律 `/data/workspace/kill_process.sh <具体 PID>`**（按 §7.6 自定规则，不用进程名以免误伤他人进程）。

**A. 3 线程档（`lcore_mask=e`）—— 通过，不再崩溃**

| dense_idx | pc_cpuid | curcpu | pc_zpcpu_offset | 4096×idx | smr_c_seq | uma_cache |
|---|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 0 ✓ | `0x7f48846d1c80` | `0x7f48846c3d80` |
| 1 | 1 | 1 | 4096 | 4096 ✓ | `0x7f48846d2c80` | `0x7f48846c3e00` |
| 2 | 2 | 2 | 8192 | 8192 ✓ | `0x7f48846d3c80` | `0x7f48846c3e80` |

`mp_ncpus=3`、`mp_maxid=3-1=2`（三行一致）✓；SMR槽距 `0x1000`/`0x1000` = **4096/4096** ✓；UMA cache 槽距 `0x80`/`0x80` = **128/128** ✓；进程存活 30s，日志无 `segmentation`/`SIGSEGV`/`panic`。

**B. 4 线程档（`lcore_mask=1e`）—— 通过，不再崩溃**

| dense_idx | pc_zpcpu_offset | 4096×idx | smr_c_seq | uma_cache |
|---|---|---|---|---|
| 0 | 0 | 0 ✓ | `0x7f46720c6c80` | `0x7f467209f980` |
| 1 | 4096 | 4096 ✓ | `0x7f46720c7c80` | `0x7f467209fa00` |
| 2 | （标量行丢失，见下） | — | `0x7f46720c8c80` | `0x7f467209fa80` |
| 3 | 12288 | 12288 ✓ | `0x7f46720c9c80` | `0x7f467209fb00` |

`mp_ncpus=4`、`mp_maxid=3` ✓；SMR 槽距 `0x1000`×3 段 → 4 槽两两相差 **4096×Δidx** ✓；UMA cache 槽距 `0x80`×3 段 → 两两相差 **128×Δidx** ✓；进程存活 32s，无崩溃。

**如实记录一处探针输出缺陷（非功能问题）**：4 线程档中 `dense_idx=2` 的 `[M17-PROBE]` **标量行未写入任何日志**（已在 `f-stack-0.log`/`helloworld.log`/运行日志全量grep，且未发现交错残行）。其 `[M17-PROBE-SLOT]` 行**存在且数值正确**。
**该线程确已正确初始化**，论证：SLOT 行的 `uma_cache = &ipi_zone->uz_cpu[curcpu]` 实测为 `base + 2×128`、`smr_c_seq` 为 `base + 2×4096` —— 两值均由 `curcpu`（= `pcpup->pc_cpuid`）推导，**只可能在该线程已完成 `ff_pcpu_thread_init(2)` 之后才打印出这个数**。故属**日志输出丢失**（f-stack 内核态 `printf` 无锁，多线程并发写同一 fd 会丢行），非初始化失败。
→ **给 `tester` 的提示**：判定以 `[M17-PROBE-SLOT]` 的**条数与地址间距**为主；`[M17-PROBE]` 标量行偶发缺行属探针自身输出竞争，**不应判为失败**，需齐全可逐档单独复跑。

### 9.5 第五轮 clean build 与二进制指纹

**先 `make clean` 再完整 `make`。**

| 指标 | `lib/` | `example/` |
|---|---|---|
| `make` 返回码 | **0** | **0** |
| `grep -c "error:"` | **0** | **0** |
| `grep -c "warning:"` | **51**（= HEAD 基线，未增加） | — |
| `undefined reference` | — | **0** |
| `.o` 产出 | **248** | — |

**被测二进制（`tester` 请用这一组，替换 §8.1）**：

| 文件 | 大小 | md5 |
|---|---|---|
| `example/helloworld` | 30,392,704 | **`d49268db362b8442bdc47f752efb5f14`** |
| `example/helloworld_epoll` | 30,386,112 | `e02b89e5c1764009dc13046796cd3f33` |
| `lib/libfstack.a` | 7,003,564 | `c2945491e3c834d459f9d9fd94edcb54` |

> **注意**：`libfstack.a` 的 md5 **不可复现**（`ar` 归档内嵌成员 mtime，同源两次构建 md5 不同，我实测为 `84c715e7…` 与 `c2945491…`）。**请以 `example/helloworld` 的 md5 为版本判据**（两次构建均稳定为 `d49268db…`）。

### 9.6 `config.ini` 还原证据

测试期临时改过 `lcore_mask`（`6` → `e` → `1e` → 还原 `6`）。还原后：
- `grep "^lcore_mask" config.ini` → `lcore_mask=6`（= 我测试前的值）
- `git diff --stat -- config.ini` → `14 insertions(+), 12 deletions(-)`，与测试前**完全一致**
- `git diff -- config.ini` 中该行为 `-lcore_mask=1` / `+lcore_mask=6`，即仅剩用户原有的本地测试改动
- **全程未 `git add`、未 `git commit`**

### 9.7 前两次打回项的完成确认

|轮次 | 项 | 状态 |
|---|---|---|
| bounce 1/3 | `curcpu` per-thread 化（`lib/include/sys/pcpu.h`） | 已完成（§5），预处理坐实 11 处 `uz_cpu[curcpu]` 全部展开为 `uz_cpu[(pcpup->pc_cpuid)]` |
| bounce 2/3 | `ff_kern_synch.c` 的 `pcpup != NULL` 兜底 | 已完成（§7.1） |
| bounce 2/3 | `ff_kern_timeout.c` 假注释（`cpuid is always 0, MAXCPU=1`） | 已完成（§7.2a） |
| bounce 2/3 | `ff_freebsd_init.c` 4 行注释精简 | 已完成（§7.2b），压到 2 行 |
| bounce 2/3 | 探针章节补写 | 已完成（§6 + §8.3） |

### 9.8 第五轮后的最终文件清单

正式改动 **8 个文件**（本轮再改 `ff_freebsd_init.c` 一处，文件数不变）：
`lib/Makefile`、`ff_glue.c`、`ff_freebsd_init.c`、`ff_dpdk_if.c`、`ff_dpdk_if.h`、`ff_kern_timeout.c`、`ff_kern_synch.c`、`include/sys/pcpu.h`
临时探针 **2 个文件**：`ff_host_interface.c`、`ff_host_interface.h`（+ `ff_freebsd_init.c` 内 4 个 `#if 1` 块）
`freebsd/` 上游树 **零改动**。

---

## 10. 第六轮：U2 探针（`UMA_ZONE_PCPU` 实际页数）—— **U2 已坐实**

### 10.1 可行性：keg 指针在 `lib/` 内可取到（无需跳过）

- `freebsd/vm/uma.h:685-689` 将 `pcpu_zone_4/8/16/32/64` 声明为 **`extern uma_zone_t`**，而 `ff_freebsd_init.c` 已包含 `<vm/uma.h>`；
- `freebsd/vm/uma_int.h:474` 的 `struct uma_zone` 含 `uma_keg_t uz_keg`，`ff_freebsd_init.c` 已包含 `<vm/uma_int.h>`（`:45`）；
- 故可直接取 `pcpu_zone_8->uz_keg->uk_ppera` / `->uk_rsize`。
- （`subr_smr.c:144 static uma_zone_t smr_zone;` 是 static不可达，但 `pcpu_zone_*` 与其同为 `UMA_ZONE_PCPU` zone，等效。）

**为什么 `uk_ppera` 就是 U2 的判据**：`uma_core.c:2471-2473`
```c
	pages = atop(kl.slabsize);
	if ((keg->uk_flags & UMA_ZONE_PCPU) != 0)
		pages *= mp_maxid + 1;
```
即 `UMA_ZONE_PCPU` keg 的 `uk_ppera` 会被乘上 `(mp_maxid + 1)`。打印它可**直接证明** per-cpu 后备存储按全部槽位分配，而非「靠槽距 4096 间接推断」（后者无法排除越界读到相邻内存）。

### 10.2 探针实现（临时，M5 后随其它探针一并移除）

`lib/ff_freebsd_init.c` 内新增 `static void ff_probe_pcpu_zone(void)`（在同一个 `#if 1 /* M17 temporary probe */` 块内），在 `ff_freebsd_init()` 末尾紧随 `ff_probe_slots()` 调用。对 `pcpu_zone_8` 与 `pcpu_zone_64` 各打印一行（均有 NULL 检查）：

```
[M17-PROBE-ZONE] name=%s uk_ppera=%u uk_rsize=%u mp_maxid=%u
```

### 10.3 实测结果（4 线程档，`lcore_mask=1e`）—— **U2 坐实通过**

```
[M17-PROBE-ZONE] name=pcpu_zone_8  uk_ppera=4 uk_rsize=8  mp_maxid=3
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=4 uk_rsize=64 mp_maxid=3
```

**判定**：`uk_ppera == 4 == mp_maxid + 1` ✓
→ `UMA_ZONE_PCPU` zone的每个 slab **确实分配了 4 页**（每 CPU 一页 = `UMA_PCPU_ALLOC_SIZE` = 4096）。因此 `zpcpu_get_cpu(base, cpu) = base + 4096×cpu`（`cpu ∈ [0,3]`）**全部落在该slab 的合法分配范围内**，**不是越界访问相邻内存**。
→ **U2 由此从「未坐实」转为「已坐实」**，我在§4 风险 1 与 §6.6 中标注的「最高风险」的**剩余一半也随之闭合**。

### 10.4 同一次运行的 DoD-1 完整数据（4 线程，本次 4 行标量全齐）

| dense_idx | pc_cpuid | curcpu | pc_zpcpu_offset | 4096×idx | smr_c_seq | uma_cache |
|---|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 0 ✓ | `0x7f861477fc80` | `0x7f8614758980` |
| 1 | 1 | 1 | 4096 | 4096 ✓ | `0x7f8614780c80` | `0x7f8614758a00` |
| 2 | 2 | 2 | 8192 | 8192 ✓ | `0x7f8614781c80` | `0x7f8614758a80` |
| 3 | 3 | 3 | 12288 | 12288 ✓ | `0x7f8614782c80` | `0x7f8614758b00` |

- `mp_ncpus=4`、`mp_maxid=3`，四行一致 ✓
- `dense_idx` 覆盖 **0..3**，`pc_cpuid`/`curcpu` 两两不同且等于 `dense_idx` ✓
- `pc_zpcpu_offset == 4096 × dense_idx` **四行全部成立** ✓
- SMR 槽距：`0x1000 / 0x1000 / 0x1000` = 4096 ×3 段 ✓
- UMA cache 槽距：`0x80 / 0x80 / 0x80` = 128 ×3 段 ✓
- 无 `segmentation`/`SIGSEGV`/`panic`，进程存活 30s 后由 `kill_process.sh <PID>` 正常终止

> 这也**回补了 §9.4-B 中缺失的 `dense_idx=2` 标量行** —— 本次同档位运行四行齐全，证明那次缺行确系 f-stack 内核态 `printf` 无锁并发写导致的**偶发输出丢失**，非初始化失败。

### 10.5 第六轮 clean build 与**最终**二进制指纹

| 指标 | `lib/` | `example/` |
|---|---|---|
| `make` 返回码 | **0** | **0** |
| `error:` | **0** | **0** |
| `warning:` | **51**（= HEAD 基线，未增加） | — |
| `undefined reference` | — | **0** |
| `.o` 产出 | **248** | — |

**最终被测二进制（`tester` 请用这一组，取代 §8.1 与 §9.5）**：

| 文件 | md5 |
|---|---|
| **`example/helloworld`** | **`751a8153d3b200229cff99b3fa7650b0`** |
| `example/helloworld_epoll` | `0d31850c7e447b140ea0a43647d07915` |
| `lib/libfstack.a` | `25c829a42deef544b1c22401af3a5c3d` |

> 仍请以 **`example/helloworld` 的 md5** 为版本判据（`libfstack.a` 因 `ar` 内嵌 mtime 而不可复现）。

### 10.6 `config.ini` 还原证据（第六轮）

`lcore_mask`：`6` → `1e`（测试）→ 还原 `6`。还原后 `git diff --stat -- config.ini` = `14 insertions(+), 12 deletions(-)`，与测试前完全一致；`git diff` 中该行为 `-lcore_mask=1` / `+lcore_mask=6`（仅用户原有本地改动）。全程未 `git add`/`git commit`。临时日志已用 `rm_tmp_file.sh` 清理，`f-stack/` 根下无 `_m17_*` 残留。

### 10.7 探针清理清单更新（DoD-8）

`grep -rn "M17 temporary probe" lib/` 现共 **5 个块/ 6 行**（`ff_host_interface.c`、`ff_host_interface.h`各 1，`ff_freebsd_init.c` 4 处），其中 `ff_freebsd_init.c` 的探针块现包含 `ff_probe_slots()` 与 `ff_probe_pcpu_zone()` 两个函数。M5 后一次性移除。
