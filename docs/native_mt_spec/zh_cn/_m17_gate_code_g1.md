# _m17_gate_code_g1：G1 代码门禁审核（reviewer）

> 审核对象：`coder` 的 G1（SMP-aware per-cpu 视图 + 稠密索引）改动，**含 leader bounce 1/3 后的第二轮**。
> 审核方式：全部结论均来自**实际打开代码 / 实际执行命令**。凡未实测者显式标注「未核实」。
> 我**未修改任何源码**，唯一写入文件为本文件。未`git commit`，未触碰 `config.ini`。

---

## 0. 审核基准（快照）

审核开始时我抓取的基准为 `coder` 第一轮（`lib/` 6 文件）；审核过程中 `coder` 第二轮落盘（新增 `lib/include/sys/pcpu.h`，并修订 `ff_dpdk_if.c` / `ff_freebsd_init.c`）。**本报告的最终判定针对第二轮**。

| 文件 | `git diff --numstat`（第二轮，终态） | mtime |
|---|---|---|
| `lib/Makefile` | +4 / -0 | 2026-08-04 13:36:29 |
| `lib/ff_glue.c` | +7 / -0 | 13:36:38 |
| `lib/ff_dpdk_if.h` | +1 / -0 | 13:40:06 |
| `lib/ff_kern_timeout.c` | +1 / -1 | 13:38:19 |
| `lib/include/sys/pcpu.h` | +1 / -1 | 13:53:21 |
| `lib/ff_dpdk_if.c` | +7 / -1 | 13:53:38 |
| `lib/ff_freebsd_init.c` | +36 / -10 | 13:53:47 |

**关键：我的 clean build 于 13:58:55 / 13:59:14 执行，晚于全部源文件 mtime（最晚 13:53:47）→ 我的编译数字完整覆盖第二轮终态，无需重跑。**

`git status --short freebsd/` 输出为**空** → 上游树零改动，实测确认。
`config.ini` 处于 ` M` 状态，但为用户本地测试改动，与本轮无关（我未触碰）。

---

## 1. 逐项审核表（1~16）

| # | 审核项 | 判定 | 依据（file:line，均为工作区终态行号） |
|---|---|---|---|
| 1 | D2 三元组与时序 | **通过** | 见 §2.1 |
| 2 | D7 thread_mode=0 零回归 | **通过（但「逐字等价」表述不准）** | 见 §2.2 |
| 3 | thread_mode=0 下`qconf->proc_id` 缺陷 | **通过（第二轮已修）**；原缺陷判定「必改」 | 见 §2.3 |
| 4 | D4 主线程取号 | **通过（不撞车已坐实）** | 见 §2.4 |
| 5 | D5 `timeout_cpu` → `__thread` | **通过**；但遗留假注释（必改） | 见 §2.5 |
| 6 | D6 上界检查 | **通过** | 见 §2.6 |
| 7 | D1 / `-DSMP` 范围与 `smp_topo` stub | **通过** | 见 §2.7 |
| 8 | 跨编译单元（`ff_cur_proc_id`） | **通过** | 见 §2.8 |
| 9 | lib 最小注释规约 | **基本通过**，1 处必改（假注释）+ 1 处建议精简 | 见 §2.9 |
| 10 | clean build 真实性（我自己跑） | **通过** | 见 §3 |
| 11 | DoD-1 可验证性 | **不通过 → 需 coder 补临时探针** | 见 §2.11 |
| 12 | 并发/内存风险（`pcpu_init` 全局写） | **通过** | 见 §2.12 |
| 13 | `curcpu` per-thread 化 | **通过（第二轮已实施，`#undef` 保留）** | 见 §2.13 |
| 14 | `curcpu` 全部使用点越界复核（我自己穷举） | **通过（无越界）**，但发现 2 项语义变化未记录 | 见 §2.14 |
| 15 | `pcpup == NULL` 上求值 `curcpu` | **不通过 → 1 处必改（1 行）** | 见 §2.15 |
| 16 | 中间态（`curcpu` per-thread + 全局锁仍在）自洽性 | **通过（自洽且严格更安全）** | 见 §2.16 |

---

## 2. 逐项依据

### 2.1 D2 三元组与时序 —— 通过

- 三元组全部设置：`ff_freebsd_init.c:314 mp_ncpus = nb_cpus;`、`:315 mp_maxid = nb_cpus - 1;`、`:316-317 for (i=0;i<nb_cpus;i++) CPU_SET(i,&all_cpus);`
- **严格早于 `uma_startup1()`**：三元组在 `:314-317`，`uma_startup1((vm_offset_t)bootmem)` 在 **`:331`**，`mi_startup()` 在 `:339`。
- **之后再无修改**：`grep` 全 `lib/` 与编译集合，`mp_ncpus` / `mp_maxid` 的写点仅 `ff_glue.c:140/145`（定义初值）与本处；`all_cpus` 写点仅 `ff_glue.c:138`（定义）与本处。`freebsd/kern/subr_smp.c`（上游会改这三者）**不在 `lib/Makefile` SRCS**，已确认。
- 核对 `uma_core.c:3179-3181`（在 `uma_startup1()` 内）：
  `zsize = sizeof(struct uma_zone) + (sizeof(struct uma_cache) * (mp_maxid + 1)) + (sizeof(struct uma_zone_domain) * vm_ndomains);`
  **比裁决D2 更严重的一层（我新发现，D文档未记）**：`freebsd/vm/uma_int.h:507 struct uma_cache uz_cpu[];` 是柔性数组，且 `:528-529 ZDOM_GET(z,n) = &((uma_zone_domain_t)&(z)->uz_cpu[mp_maxid + 1])[n]` —— **domain 数组紧跟在最后一个 cpu cache 之后、且用 `mp_maxid+1` 定位**。故若 `mp_maxid` 在 `uma_startup1()` 之后被抬高，不仅堆越界，还会让 `uz_cpu[]` 与 `zdom[]` **区域重叠**（cache 写坏 zdom 链表头）。当前代码时序正确，此风险不成立，但该约束的刚性应写入 spec。
- 核对 `subr_smr.c:598-605smr_create()`：`for (i = 0; i <= mp_maxid; i++) { c = zpcpu_get_cpu(smr, i); ... }` —— 逐槽写，依赖 `mp_maxid` 已定型✓。
- 核对 D2 的 ipfw 堆溢出点：`ip_fw_dynamic.c:3236 malloc(mp_ncpus * sizeof(void *), ...)`、`:2087 CPU_FOREACH(i)`。本轮令 `mp_ncpus == mp_maxid + 1 == popcount(all_cpus)`，三者口径一致 → `cached_count ≤ mp_ncpus`，**不溢出** ✓。

### 2.2 D7 thread_mode=0 零回归 —— 通过（但报告表述需修正）

`thread_mode == 0` → `nb_cpus = 1`（`:302-303`）→ `mp_ncpus = 1`、`mp_maxid = 0`、`all_cpus` 仅 bit 0、`ff_pcpu_thread_init(0)`（`:324` 三元运算符的 else 分支）→ `pcpu_init(pcpup, 0, ...)` → `pc_cpuid = 0`、`pc_zpcpu_offset = zpcpu_offset_cpu(0) = 0`（`subr_pcpu.c:97`）。**四项全部与改动前一致 ✓**

**但 `coder` 报告 §1.3 的「与改动前逐字等价」是不准确的**（我实测到 4 项非等价差异，且 `-DSMP` 本身即对 thread_mode=0 生效）：

1. `freebsd/vm/uma_core.c:2546-2548 #ifndef SMP keg->uk_flags &= ~UMA_ZONE_PCPU;` —— 现**不再剥离** `UMA_ZONE_PCPU`。后续 `:2473-2474 pages *= mp_maxid + 1`（=×1）、`:2577-2578 uk_allocf = pcpu_page_alloc`。我核实编译进来的是 `:2084`的 **FSTACK 版** `pcpu_page_alloc`（`:1958` 的上游版在 `#ifndef FSTACK` 内），其体为 `return page_alloc(...)` → 与原路径等效，但**不是同一条代码路径**。
2. CK：`-DSMP` 使 `CK_MD_UMP` 失效 → `ip_fw_dynamic.c` 的 `ck_pr_*` RMW 加上 `lock` 前缀（语义更强、有性能成本）。
3. 内存：`cpuset_t` 8→128 字节、`cpuid_to_pcpu[1024]`/`dpcpu_off[1024]`（`subr_pcpu.c:77-78`）、`nws_array[MAXCPU]`（`netisr.c:243`）、`pause_wchan[MAXCPU]`（`ff_kern_synch.c:59`）。
4. `curcpu` 由字面量 `0` 变为内存载入 `pcpup->pc_cpuid`，并新引入一个 NULL 解引用窗口（见 §2.15）。

→ **报告文档必改**：D7 是硬约束，M5 的 thread_mode=0 回归判据必须建立在准确表述上，否则会漏测上述 1/2/3 项。

### 2.3⚠ 重点核查：thread_mode=0 下的 `qconf->proc_id` —— 第一轮确为缺陷，第二轮已修

**① 该值是否真的不会被使用？—— 实测：确实不会，但结论链比`coder` 报告更窄。**

- `ff_stack_inited` 是 `__thread`（`ff_freebsd_init.c:86`），主线程在 **`ff_freebsd_init()` 的最后一行 `:378 ff_stack_inited = 1;`** 置位。
- 调用顺序：`ff_init()`（`ff_init.c:38-52`）= `ff_load_config` → `ff_dpdk_init` → `ff_freebsd_init` → `ff_dpdk_if_up`；`main_loop` 由 `ff_run()` → `ff_dpdk_run()`（`ff_dpdk_if.c:2857-2863 rte_eal_mp_remote_launch(main_loop, lr, CALL_MAIN)`）在其**之后**启动。
  → 主线程进入 `main_loop` 时 `ff_stack_inited == 1` → `ff_stack_thread_init()` 在 `:185-186` **必然提前返回** ✓
- **且thread_mode=0 下不存在第二个跑 `main_loop` 的线程**：`ff_config.c:116-120` 的 `parse_lcore_mask()` 在**非** thread_mode 时把 `proc_mask` 设为**单 bit**（`snprintf(buf,...,"%llx%s", 1<<shift, zero)`），`:1156 sprintf(temp,"-c%s",proc_mask)` → EAL 每进程只有 1 个 lcore → `rte_eal_mp_remote_launch` 只跑主lcore。

**② 是否应加显式保护？—— 判定：必改（第一轮），第二轮已落实。**

理由（第一轮若不改的实际危害）：`ff_memory.h:104-107 ff_lcore_conf_idx()` 在 thread_mode=0 时**恒返回 0**，而 `init_lcore_conf()` 非 thread_mode 分支 `ff_dpdk_if.c:466 ff_cur_lcore_conf()->proc_id = ff_global_cfg.dpdk.proc_id;` → secondary 进程下 `lcore_conf[0].proc_id == 1/2/…`。一旦 `ff_stack_inited` 的置位时机被将来任何改动打破（例如把 `:378` 提前、或把 `ff_freebsd_init` 拆分），`ff_pcpu_thread_init(1)` 会命中新增的 `:110`上界检查（`1 > mp_maxid==0`）而**`panic` 直接终止进程** —— 从「静默正确」变成「启动即挂」。这是把一个可用 1 个三元运算符消除的隐患留给未来，不可接受。

**第二轮实测已修**：`ff_dpdk_if.c:2655 ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0);` ✓ 通过。

### 2.4 D4 主线程取号 —— 通过，且「不撞车」已由我独立坐实

- **`rte_lcore_id()` 在 `ff_freebsd_init()` 期已可用**：`ff_dpdk_init()` 内 `rte_eal_init(argc, argv)` 在 `init_lcore_conf()` 之前（`ff_dpdk_if.c:1657-1660` → `:1678init_lcore_conf();`），而 `ff_dpdk_init` 整体先于 `ff_freebsd_init`（`ff_init.c:44/48`）✓
- **`lcore_conf[rte_lcore_id()].proc_id` 该时点已赋值**：thread_mode 分支 `ff_dpdk_if.c:435-439 for (ti=0; ti<nb_threads; ti++) { lcore_id = proc_lcore[ti]; lcore_conf[lcore_id].proc_id = ti; }` ✓
- **主线程 `proc_id` 是否可能与 worker 撞车？—— 实际推演：不会。** 关键是 `nb_threads` 恒等于 `lcore_mask` 的置位数：
  - `ff_config.c:139 cfg->dpdk.nb_procs = count;`（`count` = `parse_lcore_mask()` 数出的置位数）；配置项中**无** `nb_procs` 的独立入口（`grep MATCH("dpdk","nb_procs")` 零命中）。
  - `ff_config.c:1477-1478 nb_threads = nb_procs; nb_procs = 1;`、`:1480-1482 proc_mask = strdup(lcore_mask)`。
  → **EAL 的 lcore 集合 ≡ `lcore_mask` 置位集合 ≡ `{proc_lcore[0..nb_threads-1]}`，三者恒等**（无「EAL 有而 `proc_lcore[]` 无」的 lcore）。
  → 主线程无论落在哪个 EAL lcore（含将来传`--main-lcore`），必是某个 `proc_lcore[k]`，取到 `proc_id == k`（合法稠密值）；各 worker 取各自 lcore 的 `proc_id`，`lcore_conf[]` 中一 lcore 一值互不相同 → **全局唯一，不撞车** ✓
  → 主线程同时也是「worker k」（`CALL_MAIN`），其两处取号来源同一（`lcore_conf[rte_lcore_id()].proc_id`），且 `main_loop` 里因 `ff_stack_inited` 提前返回 → **不会重复 `pcpu_init()`、不会占两个槽** ✓
- 补充说明：即便 `k != 0`，也不撞车（worker k 就是主线程自己）。`coder` 报告此处结论正确。

### 2.5 D5 `timeout_cpu` —— 代码通过；注释必改

- `ff_kern_timeout.c:190 static __thread int timeout_cpu;` ✓ 已改。
- 必要性复核：`:254 timeout_cpu = PCPU_GET(cpuid);` 由每个线程执行；`c->c_cpu = timeout_cpu` 写入callout。
- **`:815 callout_schedule()` 传回的 `c->c_cpu` 必然合法**：`:815 return callout_reset_on(c, to_ticks, c->c_func, c->c_arg, c->c_cpu);` → `:730-733 else if ((cpu >= MAXCPU) || ((CC_CPU(cpu))->cc_inited == 0)) panic(...)`。
  - `cpu` 值域：`c_cpu` 来自某线程的 `PCPU_GET(cpuid)` ≤ `mp_maxid` ≤ `nb_threads-1` ≤ `RTE_MAX_LCORE-1` **≪ MAXCPU(1024)** ✓
  - `CC_CPU(cpu)` = `&cc_cpu`（`:184`，**忽略实参**）→ 返回**调用线程自己**的 `__thread cc_cpu`，其 `cc_inited` 由该线程的 `ff_callout_thread_init()`（`ff_stack_thread_init:215`）置 1 ✓
- **跨线程语义**（`coder` 自评风险 #5）我已复核并确认其判断成立：`:184-185 #define CC_CPU(cpu) &cc_cpu` / `#define CC_SELF() &cc_cpu` 都忽略 cpu 实参，故 `:662`/`:1181` 等取 `cc` 的路径**恒为调用线程自己的callwheel**，不会跨线程访问 → 无新增数据竞争。语义为「谁 schedule 谁拥有」，`c_cpu` 退化为纯记录字段。
- **必改（注释）**：`ff_kern_timeout.c:180-182` 的注释现为**假陈述**：
  ```
  /* Per-thread callout_cpu: each stack instance drives its own callwheel.
   * CC_CPU/CC_SELF ignore the cpu arg (cpuid is always 0, MAXCPU=1) and
   * return the calling thread's own instance. */
  ```
  `cpuid is always 0, MAXCPU=1` 在G1 之后**两句都为假**。而这段括号内的理由正是「`CC_CPU` 忽略实参是安全的」的唯一书面依据，留着会误导后续维护者。

### 2.6 D6 上界检查 —— 通过

`ff_freebsd_init.c:110-112`：
```c
if (cpuid < 0 || (u_int)cpuid > mp_maxid)
    panic("ff_pcpu_thread_init: cpuid %d out of range [0, %u]\n", cpuid, mp_maxid);
```
- **覆盖 `cpuid > mp_maxid`** ✓；**覆盖负值** ✓（先判 `cpuid < 0`，再 `(u_int)` 转换，顺序正确；若只写 `(u_int)cpuid > mp_maxid`也能拦住负值，但显式判负更清晰）。
- 该检查确有必要：`subr_pcpu.c:88-89 KASSERT(cpuid >= 0 && cpuid < MAXCPU, ...)` 在无 `INVARIANTS` 时被编译掉，越界会静默写坏 `:77-79` 的 `dpcpu_off[]` / `cpuid_to_pcpu[]` / 紧邻的 `cpuhead`。
- **`panic` 是否可用**：可用且是此处的正确选择。`ff_freebsd_init.c` 本身已在 `:286 panic("kern_setenv failed: ...")` 使用（既有惯例），且该文件是内核态 TU（`-nostdinc` + `-include opt_global.h`），**不能引入 DPDK 头** → `rte_exit()` 不可用。`panic` 由 `ff_subr_prf.c` 提供，已链接（clean build 零undefined reference 佐证）。
- `:306-307 if (nb_cpus > MAXCPU) panic(...)`：`coder` 自评 #7 称「实际不可达」。我认同其保留理由（为 `MAXCPU=64` 降级台阶预留fail-loud），**不视为冗余**，无需改。

### 2.7 D1 / MAXCPU / `-DSMP` 范围 / `smp_topo` stub —— 通过

- **`-DSMP` 只加在 `lib/Makefile:221-223`** ✓；`git status --short freebsd/` 输出**空** → 上游树零改动，实测确认。
- `MAXCPU`：`freebsd/amd64/include/param.h:60-66`，`#ifdef SMP` → `#ifndef MAXCPU` → `1024`；`#else` → `1`。故 `-DSMP` 使 `MAXCPU` 1→1024，且带 `#ifndef` 保护（降级台阶可用）✓
- **`-DSMP` 的实际行为影响面（我独立穷举，不依赖裁决文档）**：对 `freebsd/` 全树 grep `ifdef SMP|ifndef SMP|defined(SMP)` 得 57 个文件，与 `lib/Makefile` SRCS 交叉过滤后，**编译集合内只有 3 个 `.c` + 若干头**：
  | 文件 | SMP 分支 | 实测影响 |
  |---|---|---|
  | `kern/subr_pcpu.c:252-264` | `dpcpu_copy()` | SMP 分支 `CPU_FOREACH` + `if (dpcpu==0) continue`；`dpcpu_off[]` 恒 0（`dpcpu_init()` 无调用者）→ **空操作**。非 SMP 分支为 `memcpy(s,s,size)` → **亦为空操作**。等效✓ |
  | `vm/uma_core.c:2546/3498/3508/3526` | PCPU 逐槽路径 | `:2546` 不再剥离 `UMA_ZONE_PCPU`（这是 G1 生效的前提）；`:3509-3510 for (i=0;i<=mp_maxid;i++) bzero(zpcpu_get_cpu(...))` 逐槽清零；`:3501/3527` 为 `MPASS`（无 INVARIANTS 时编译掉）✓ |
  | `netinet/tcp_hpts.c:1867-1871` | `cpu_top = smp_topo()` vs `NULL` | 见下|
  | `sys/smp.h:113-166`, `:227-267` | 仅函数声明 | 链接期已验证（零 undefined reference）✓ |
  | `sys/mutex.h` | 被 `lib/include/sys/mutex.h` 覆盖 | `lib/Makefile:73 INCLUDES= -I${OVERRIDE_INCLUDES_ROOT} ...` 置于最前，覆盖生效 ✓ |
  非 SRCS 因此**不受影响**的高危文件（我逐一核对 Makefile 确认不在 SRCS）：`kern/subr_smp.c`、`kern/kern_mutex.c`、`kern/kern_timeout.c`、`kern/kern_intr.c`、`kern/kern_synch.c`、`kern/subr_epoch.c`、`kern/init_main.c`、`kern/sched_*.c`、`kern/subr_turnstile.c`、`kern/kern_clocksource.c`、`net/iflib.c`、`netinet/sctp_*.c`、`libkern/arc4random.c`、`x86/*`、`amd64/amd64/*`。
- **`smp_topo()` stub 返回 NULL 的安全性 —— 我独立坐实，与 `tcp_hpts.c:1890/:1565` 一致**：
  - `tcp_hpts.c:1867-1871`：`#ifdef SMP cpu_top = smp_topo(); #else cpu_top = NULL; #endif` → 返回 NULL **与原 `#else` 分支逐字等价** ✓
  - `:1889-1891 if (cpu_top == NULL) { tcp_pace.grp_cnt = 1; }` → `grp_cnt == 1`，且`tcp_pace.grps` **永不`malloc`**（只在 `else` 分支 `:1899` 分配）。
  - `:1564-1572if (tcp_pace.grp_cnt > 1) { ... CPU_ISSET(curcpu, &tcp_pace.grps[i]->cg_mask) ... }` → 条件为假 → **`grps[]` 永不解引用** ✓
  - `:2026-2041` 另一处 `grps[j]->cg_mask` 位于 `#ifndef FSTACK` 内 → **不编译** ✓
  - `:2076`的 `free`/卸载路径仅模块卸载时走。
- `ff_glue.c` 落点合理：该文件已`#include <sys/smp.h>` 且已定义 `mp_ncpus`/`mp_maxid`/`all_cpus`/`smp_started`/`smp_cpus`/`smp_topology`，同类符号归属地一致 ✓

### 2.8 跨编译单元问题 —— 通过

- **既有惯例（找到既有同类例子）**：`ff_freebsd_init.c:49 #include "ff_host_interface.h"` —— 该文件本身**已经**在调用 `HOST_SRCS` 的 `ff_host_interface.c` 提供的函数（`ff_malloc`/`ff_free` 等）；`ff_glue.c:77`、`ff_kern_synch.c:56` 同样。`ff_glue.c:1067-1083 malloc()` 直接调`ff_malloc()` 即典型既有例子。故「内核态 TU 调host TU 函数」是 f-stack 的**既有架构惯例**，本改动未开新范式 ✓
- **`-DSMP` 只作用于 `SRCS` 不作用于 `HOST_SRCS` 是否造成不一致 —— 实测无**：
  - `MAXCPU` / `cpuset_t` **未出现在 `ff_cur_proc_id()` 的签名中**（`int (void)`）✓
  - 我对全部 `HOST_SRCS`（`ff_host_interface.c`、`ff_thread.c`、`ff_config.c`、`ff_ini_parser.c`、`ff_dpdk_if.c`、`ff_dpdk_pcap.c`、`ff_epoll.c`、`ff_log.c`、`ff_init.c`、`ff_dpdk_kni.c`）grep `cpuset_t|MAXCPU` → **零命中** ✓
  - 结构层面：`HOST_INCLUDES = -I.`（`lib/Makefile:78`），host TU **根本看不到 `freebsd/sys/*.h`**，故不存在「两侧共享且布局依赖 SMP」的结构体 ✓
  - `struct lcore_conf`（`ff_memory.h:60-95`）为两侧共享的唯一候选，其中无 `cpuset_t`、无 `[MAXCPU]` 数组 ✓（且实际只有 host 侧使用）
- 风格小注（不列为问题）：`ff_freebsd_init.c` 该文件既有 `extern void mi_startup(void);` 等裸`extern` 惯例，新增 `:74 extern int ff_cur_proc_id(void);` 与之一致；同时 `ff_dpdk_if.h:81` 也给了原型（host 侧自检）✓

### 2.9 lib 最小注释规约 —— 基本通过，1 必改 + 1 建议

**必改（1处）**：`ff_kern_timeout.c:180-182`的假注释 —— 见 §2.5。这是硬规约（错误注释比无注释更有害），且 `coder` 两轮均未处理。

**建议精简（1 处）**：`ff_freebsd_init.c:319-323`（4 行）
```
/*
 * The main thread is an EAL lcore and runs main_loop too (CALL_MAIN), so
 * it takes its own dense slot from lcore_conf[] rather than assuming it
 * is proc_lcore[0]. thread_mode=0 keeps slot 0 (one stack per process).
 */
```
建议压到 2 行，例如：`/* Main thread is itself an EAL lcore worker (CALL_MAIN), so it takes its own dense slot; thread_mode=0 has one stack per process -> slot 0. */`

**判定为「必要、应保留」的注释（不删）**：
- `lib/Makefile:221-222`（2 行）：`-DSMP` 的动机极不直观，保留。
- `ff_freebsd_init.c:73`（1 行）：跨 TU `extern` 的语义说明，保留。
- `ff_freebsd_init.c:98-102`（3 行，第二轮已从 8 行精简）：解释上界检查的必要性（KASSERT 被编译掉），非显而易见，保留。
- `ff_freebsd_init.c:309-313`（4 行）：`uma_startup1` 时序约束是本改动最刚性的不变式，保留。
- `ff_glue.c:172`（1 行）：说明调用方须处理 NULL，保留。

第二轮已把 `ff_pcpu_thread_init` 的注释从 8 行减到 3 行、`ff_freebsd_init.c` 净行数 +39/-9 → +36/-10 ✓ 精简方向正确。

### 2.11 DoD-1 可验证性 —— **不通过：需 coder 补临时探针**

当前代码**没有任何**打印 `pc_zpcpu_offset` / `pc_cpuid` 的手段（全 `lib/` grep `pc_zpcpu_offset` 零命中），M5 `tester` 无法验证 DoD-1。

**我先把DoD-1 的静态侧做实了（这是 `coder` 自评风险 #1「完全未验证」的一半，可从 M5 清单降级）**：
- `subr_pcpu.c:97 pcpu->pc_zpcpu_offset = zpcpu_offset_cpu(cpuid);`，`freebsd/sys/pcpu.h:235 #define zpcpu_offset_cpu(cpu) (UMA_PCPU_ALLOC_SIZE * cpu)`，`:221 #define UMA_PCPU_ALLOC_SIZE PAGE_SIZE` → **`pc_zpcpu_offset == 4096 * cpuid` 由代码恒成立** ✓
- **UMA per-cpu zone 确实按 `(mp_maxid+1) × 4096` 分配**（`coder` 风险 #1 的核心疑点，我坐实）：`uma_core.c:2472-2476`
  ```c
  pages = atop(kl.slabsize);
  if ((keg->uk_flags & UMA_ZONE_PCPU) != 0)
          pages *= mp_maxid + 1;
  ...
  keg->uk_ppera = pages;
  ```
  → PCPU keg 的 `uk_ppera = mp_maxid+1` 页，`keg_alloc_slab` 按 `uk_ppera*PAGE_SIZE` 调`uk_allocf` ✓
- **`coder` 的 U2 疑点（编译进来的是 `:1959` 还是 `:2084` 的 `pcpu_page_alloc`）我已定论：是 `:2084` 的 FSTACK 版**。`:1958` 的上游版整体位于 `#ifndef FSTACK` 内（该`#endif /* !FSTACK */` 在 `:1932` 之后开启的块…… 精确地说：`:2081#else` 之前为 `#ifndef FSTACK` 区），FSTACK 版体为 `{ *pflag = UMA_SLAB_KERNEL; return page_alloc(zone, bytes, domain, pflag, wait); }` → `page_alloc` → `kmem_malloc_domainset(...)`。
  **重要副产品**：上游版 `:1982 pc = pcpu_find(cpu);`（在 `#ifdef NUMA` 内）**不编译**，因此不存在「boot 期对尚未创建 pcpu 的 worker 槽位调 `pcpu_find()` → NULL 解引用」的风险。我曾把这条列为疑似 FAIL 级，**实测排除** ✓

**仍需 coder 补的临时探针（明确到字段与函数）**：
1. **`ff_freebsd_init.c` 的 `ff_pcpu_thread_init()` 末尾**（内核TU，`printf` 可用）加一行临时打印：
   `printf("[G1probe] tid=%lu cpuid=%d zpcpu_off=%zu mp_ncpus=%d mp_maxid=%u\n", (unsigned long)pthread_self()等价物, cpuid, (size_t)pcpup->pc_zpcpu_offset, mp_ncpus, mp_maxid);`
   （若内核 TU 取不到线程 id，改打 `(void *)pcpup` 亦可区分线程）
   → 直接覆盖 DoD-1「各 worker `pc_zpcpu_offset == 4096*dense_idx` 且互不相同」。
2. **`ff_dpdk_if.c` 的 `main_loop()` 内、`ff_stack_thread_init()` 调用点之后**（host TU，可用 DPDK API）加一行：
   `printf("[G1probe] lcore=%u main_lcore=%u proc_id=%d\n", rte_lcore_id(), rte_get_main_lcore(), qconf->proc_id);`
   → 覆盖 `_m17_D_verdict.md` §3-6 的 **U6-a 未坐实项**（EAL main lcore 与 `proc_lcore[0]` 的关系）以及 §2.4 的「不撞车」运行期确认。
3. **UMA cache 隔离（DoD-1 判定式 ⑤）**：建议在 `ff_stack_thread_init()` 末尾打印任一已知 pcpu zone 的 `&zone->uz_cpu[curcpu]` 地址（或最简：打印 `curcpu` 求值结果 `PCPU_GET(cpuid)`），确认各线程落在不同 `uz_cpu` 槽。

探针须为**临时**代码，M5 验证后由 `coder` 移除并重跑 clean build（`_m17_D_verdict.md` §1.3 已明确「探针不得沉淀为产品代码」）。

### 2.12 并发/内存风险 —— 通过

`subr_pcpu.c:84-98pcpu_init()` 的全局写有两处：`:91 cpuid_to_pcpu[cpuid] = pcpu;`、`:92 STAILQ_INSERT_TAIL(&cpuhead, pcpu, pc_allcpu);`（均非原子）。

- **worker 路径受 `init_lock` 保护** ✓：`ff_freebsd_init.c:183 static volatile int init_lock = 0;`、`:193-194 while (__sync_lock_test_and_set(&init_lock, 1)) ;`、`:195 ff_pcpu_thread_init(cpuid);`、`:224 __sync_lock_release(&init_lock);` —— `pcpu_init` 严格在临界区内。
- **主线程路径先于任何 worker 完成** ✓：主线程的 `ff_pcpu_thread_init()` 在 `ff_freebsd_init():324`，未加锁；但 worker 线程由 `ff_run()` → `rte_eal_mp_remote_launch()` 创建，**发生在 `ff_init()` 返回之后**（`ff_init.c:44-52` 与应用 `main` 的 `ff_run()` 调用顺序）→ 主线程写`cpuid_to_pcpu[k]` 时不存在并发写者。不加锁是安全的。
- 残留（非本轮问题，已在 AI memory 84914768 / `_m17_D_verdict.md` §3 记录）：`ff_stack_thread_init()` 内`uifind(0)`/`crget`/`EVENTHANDLER_INVOKE` 等全局操作同样依赖 `init_lock` + `Giant`，本轮未改变其风险面。

### 2.13 `curcpu` per-thread 化 —— 通过

`lib/include/sys/pcpu.h` 终态（diff 实测）：
```c
#include_next <sys/pcpu.h>
#undef curcpu

-#define curcpu    0
+#define curcpu    PCPU_GET(cpuid)
```
- **`#undef curcpu` 保留** ✓（`:32`）—— 否则会与上游 `freebsd/sys/pcpu.h:218 #define curcpu PCPU_GET(cpuid)` 重定义。附注：本轮改后两者**文本相同**，即便漏了 `#undef` 也只是 benign redefinition（同一token 序列，C 标准允许），但保留是正确做法。
- `PCPU_GET(member)` = `(pcpup->pc_ ## member)`（`lib/include/amd64/include/pcpu.h:49`）→ `curcpu` = `pcpup->pc_cpuid`，per-thread ✓
- **该改动的必要性我独立确认**：`freebsd/vm/uma_core.c` 的 11 处 `cache = &zone->uz_cpu[curcpu];`（`:1452/3738/3776/3818/3901/4534/4543/4595/4628/4803/4853`）**不走 `zpcpu_get()`**，故仅靠稠密 `pc_cpuid` 无法隔离 UMA per-cpu cache。`designer` 的§2.3/§4.5 结论成立。
- 我的 clean build（13:58）**已包含**此改动，编译无新增 warning ✓

### 2.14 `curcpu` 全部使用点越界复核 —— 通过（无越界），但 2 项语义变化未记录

我对 `lib/` 与 `freebsd/{kern,net,netinet,netinet6,netpfil,netgraph,vm,libkern}` 穷举 grep `curcpu`，再逐一与 `lib/Makefile` SRCS 交叉过滤。**编译集合内的`curcpu` 使用点完整清单（8 个文件 / 19 处）**：

| 位置 | 索引对象与尺寸 | 越界判定 |
|---|---|---|
| `lib/ff_kern_synch.c:105` | `pause_wchan[curcpu]`，`:59`尺寸 `MAXCPU`=1024 | **安全**（`curcpu ≤ mp_maxid ≤ nb_threads-1 ≤ RTE_MAX_LCORE-1 ≪ 1024`）；但有 NULL 风险，见 §2.15 |
| `freebsd/vm/uma_core.c` ×11（`:1452,3738,3776,3818,3901,4534,4543,4595,4628,4803,4853`） | `zone->uz_cpu[curcpu]`，柔性数组，尺寸 `mp_maxid+1`（`:3179-3181` zsize） | **安全**（`curcpu ≤ mp_maxid`，由 `:110` 上界检查保证）✓ 关键：`uma_int.h:528-529 ZDOM_GET` 用 `uz_cpu[mp_maxid+1]` 定位 domain 区，口径一致 |
| `freebsd/netinet/tcp_hpts.c:1587` | `rp_ent[curcpu % rp_num_hptss]` | **安全**（取模）；`:1872 rp_num_hptss = ncpus`，`:1864 ncpus = mp_ncpus ? mp_ncpus : MAXCPU` = N > 0，`:1921-2000` 循环为全部 N 个下标分配 ✓ |
| `freebsd/netinet/tcp_hpts.c:1566` | `CPU_ISSET(curcpu, &grps[i]->cg_mask)` | **不可达**（`:1564 if (grp_cnt > 1)`；`grp_cnt` 恒为 1，见 §2.7）；即便可达，`cpuset_t` 现为 1024 位，`curcpu < 1024` 亦不越界 ✓ |
| `freebsd/netinet/tcp_timer.c:237,249` | `return (curcpu);`（作为 cpu 号返回） | **安全**（返回值 ≤ `mp_maxid`，消费方 `tcp_hpts` 已取模/忽略）✓ |
| `freebsd/netinet/tcp_lro.c:1210,1216` | `lc->lro_last_cpu == curcpu` / 赋值 | **安全**（纯比较/记录，无索引）✓ |
| `freebsd/net/netisr.c:839` | `netisr_get_cpuid(curcpu)` → `:278 nws_array[cpunumber % nws_count]` | **安全**（取模，`nws_array[MAXCPU]`）；但见下「语义变化 A」 |
| `freebsd/net/netisr.c:1172` | `if (cpuid != curcpu) goto queue_fallback;` |无索引；但见下「语义变化 A」 |
| `freebsd/kern/subr_taskqueue.c:368` | `callout_reset_sbt_curcpu(...)` | **未核实为`curcpu` 求值点**：我在 `freebsd/sys/callout.h` grep `callout_reset_sbt_curcpu` **零命中**（宏定义未找到），但 `subr_taskqueue.c` 编译通过 → 该宏必来自其它头。**该处不构成越界风险**（最终落到 `callout_reset_on(..., cpu, ...)`，`:730` 已有 `cpu >= MAXCPU` 兜底 + `CC_CPU` 忽略实参），但宏定义位置未坐实。|

**未编译**（已逐一核对不在 SRCS，故grep 命中不构成风险）：`kern/sched_ule.c`、`kern/subr_intr.c`、`kern/kern_timeout.c`、`kern/kern_clock.c`、`kern/init_main.c`、`kern/kern_synch.c`（f-stack 用 `ff_kern_synch.c`）、`kern/subr_epoch.c`（用 `ff_subr_epoch.c`，我grep 确认 `ff_subr_epoch.c` 内无 `curcpu`）、`kern/kern_clocksource.c`、`kern/kern_time.c`、`kern/vfs_subr.c`、`kern/subr_smp.c`、`net/iflib.c`、`netinet/tcp_lro_hpts.c`、`libkern/arc4random.c`。

**语义变化 A（新发现，建议改：记入 spec 已知风险）—— netisr HYBRID 策略下的入队回退**
- 默认路径**不受影响**：`netisr.c:151 #define NETISR_DISPATCH_POLICY_DEFAULT NETISR_DISPATCH_DIRECT`、`:153` 初值即 DIRECT、`:787-789 netisr_get_dispatch()` 返回全局值 → `:1146-1153` 无条件直发，**`:839`/`:1172` 的 `curcpu` 不可达** ✓
- **但 `net.isr.dispatch` 是可调 sysctl**（`:155-157`）。若有人在 `config.ini` 的 `[freebsd.sysctl]` 里设为 `hybrid`：`:810-811 if (nws_count == 1) *cpuidp = nws_array[0];`（`nws_array[0]` = boot 线程即主线程的 cpuid，通常 0）→ 对 worker N≠0，`:1172 cpuid != curcpu` **成立** → `goto queue_fallback` → netisr 队列路径，而 f-stack 的 swi 是空stub（`ff_kern_intr.c`，`_m17_D_verdict.md` §3-5）→ **报文进队后无人处理**。
- 改动前 `curcpu ≡ 0 == nws_array[0]` → 恒相等 → 直发，**不会命中**。故这是 `curcpu` per-thread 化**新引入**的条件性风险。
- 建议：spec 明确记为「`net.isr.dispatch` 必须保持 `direct`，不得设为 `hybrid`/`deferred`」，并考虑在 `ff_config.c` 校验或在文档中列为不支持配置。

**语义变化 B（新发现，建议改：记入 spec + M5 观察）—— `tcp_hpts` 实例数 1 → N**
`tcp_hpts.c:1864 ncpus = mp_ncpus ? mp_ncpus : MAXCPU` → `:1872 rp_num_hptss = ncpus`。改动前 `mp_ncpus==1` → 1 个 hpts；现为 **N 个**。`:1921-2000` 为每个 i 分配 `tcp_hpts_entry` + `p_hptss`（`asz = sizeof(struct hptsh) * NUM_OF_HPTSI_SLOTS`，非小额）并 `callout_init(&hpts->co, 1)`；`:2048-2050callout_reset_sbt_on(&hpts->co, ..., hpts->p_cpu, ...)`。
- 内存：per-hpts 的 `p_hptss` 数组×N，值得 M5 量化（`FF_TCPHPTS=1` 默认开启）。
- 语义：`tcp_hpts_init()` 在 `mi_startup()` 期由**主线程**执行 → N 个 callout 全部挂在**主线程的 `__thread cc_cpu` callwheel** 上（`CC_CPU` 忽略实参）；而 `__tcp_run_hpts()` → `:1587 rp_ent[curcpu % N]` 由**各 worker** 选取不同 hpts entry → 出现「worker N 驱动的 hpts entry，其 callout 归主线程 callwheel」的错配。`hpts->p_mtx` 为 `MTX_DEF` 而 f-stack 全部 `mtx` 已是 `((void)0)`（`lib/include/sys/mutex.h`）→ **无实际互斥**。当前 CM5-B 靠 Giant 串行化掩盖，但这是 CM6/CM7 缩锁时的明确风险点，应加入残留风险清单（与 AI memory 84914768 的 R1~R5 并列，建议记为 R6）。

### 2.15 `pcpup == NULL` 上求值 `curcpu` —— **不通过：1 处必改（1 行）**

**「鸡生蛋」主路径：已排除（我独立复核，与 leader 结论一致）**
- `ff_glue.c:1067-1083 malloc(unsigned long size, struct malloc_type *type, int flags)` 体内直接 `alloc = ff_malloc(size);`，**不走 UMA** ✓
- `freebsd/kern/kern_malloc.c` **不在 SRCS**（`grep -c kern_malloc lib/Makefile` = **0**）✓
- 故 `ff_pcpu_thread_init():114 malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO)` 不会触达 `uz_cpu[curcpu]` ✓
- 且 `ff_pcpu_thread_init()` 之前的语句无 `curcpu`/`PCPU_GET`：`:110-112` 只读 `mp_maxid`（普通全局）；`ff_stack_thread_init():185-194` 的 `ff_stack_inited` 判定与 `__sync_lock_test_and_set` 自旋均不涉及 pcpu ✓
- `ff_freebsd_init()` 中 `:324ff_pcpu_thread_init()` 之前的语句：`snprintf`、`kern_setenv`（→ `malloc` → `ff_malloc`）、`physmem` 赋值、三元组设置。**正常路径无 `curcpu` 求值** ✓
- `uma_startup1()` 在 `:331`，晚于 `:324` ✓；`kmem_malloc` 在 `:329`，亦晚于 ✓

**残留边角：确实存在，且判定为「必改」**
- 路径：`ff_glue.c:1076 pause("malloc", hz/100)` → `ff_kern_synch.c:105 return (_sleep(&pause_wchan[curcpu], NULL, 0, wmesg, sbt, pr, flags));` → 求值 `curcpu` = `pcpup->pc_cpuid`，**`pcpup == NULL` 时段错误**。
- 触发条件：`ff_malloc()` 返回 NULL 且 `M_WAITOK`，且发生在 `pcpup` 尚为 NULL 的窗口内—— 即 `ff_freebsd_init():284-298` 的 `kern_setenv` 系列，或 `ff_pcpu_thread_init():114` 自身那次 malloc；以及 **D9 场景：`ff_pthread_create()` 创建的应用线程**（永不调 `ff_pcpu_thread_init`）走到任何 `pause()`/UMA 路径。
- **与 leader 初判的分歧点（我独立判断）**：leader 认为「今天 `curcpu==0` 时同样会走到一个不合理的 wchan，属既有脆弱点」。我核实后认为**性质不同**：改动前 `curcpu` 是**字面量 0**，`&pause_wchan[0]` 是合法地址，`_sleep` 正常返回、重试循环正常工作（f-stack 的 `wakeup()` 是空操作，`_sleep` 走的是超时路径）→ **原代码在该边角是能正常工作的**；改动后变成**确定性段错误**。这是 round-2 `curcpu` 改动**新引入的可用性回归**，不是既有脆弱点。
- 严重性定级：**P2（必改，非阻断）**。触发概率低（OOM / D9 非支持用法），但修复成本 1 行、无任何副作用，且它把「优雅重试」变成「崩溃」，不符合最小惊讶。
- **最小改法（推荐）**：`lib/ff_kern_synch.c:105`
  ```c
  return (_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], NULL, 0, wmesg, sbt, pr, flags));
  ```
  （`pcpup` 已由 `ff_freebsd_init.c:89 __thread struct pcpu *pcpup;` 定义，`ff_kern_synch.c` 需 `extern __thread struct pcpu *pcpup;` 或经`sys/pcpu.h` 取得——由 `coder` 选择最小写法。）
- 关于 spec「不加兜底、fail-fast」的裁决：**对 D9（应用线程误用 `ff_*`）我认同fail-fast**——那里NULL 解引用能立刻暴露不支持的用法，优于静默共用槽位 0。**但对 `pause()` 这条 OOM 重试路径不适用**：那不是「误用」，是正常代码在压力下的正常分支。故建议裁决细化为「D9 误用 fail-fast；但内部bootstrap 期的 `pause()` 加最小兜底」。

### 2.16 中间态自洽性（`curcpu` per-thread + `uma_crit_lock` 仍在）—— 通过

- 现状确认：`lib/include/vm/uma_int.h:45-52` 的 `uma_crit_lock` 全局自旋锁**仍在**（`critical_enter()` = `while (__sync_lock_test_and_set(&uma_crit_lock,1));`），G2 未实施 ✓
- 自洽性推演：
  - 改动前 = 「全线程共用 `uz_cpu[0]` **+** 全局锁串行」→ 数据结构完整性**完全依赖**该全局锁（这正是它今天能跑的原因）。
  - 现在 = 「各线程独占 `uz_cpu[cpuid]` **+** 全局锁仍串行」→ 既有隔离又有串行，**严格更安全**，不引入任何新竞争；代价是并发度仍被全局锁压住（性能无收益）。
  - 未来 G2 = 「独占槽位 **-** 全局锁」→槽位隔离成为**唯一**保护。
  → 因此 **G1（含 `curcpu` per-thread 化）是 G2 的硬前置**：若先做 G2 而`curcpu` 仍为 0，会把`b90ddcba5` 修掉的崩溃原样放回。`designer` 的 §4.5 结论我复核成立。
- 结论：中间态**自洽、可安全进入 M5 运行时验证**（更安全但仍串行）✓
- 附带确认（`coder` 自评风险 #3）：`smp_started`/`smp_cpus` 未同步 —— 我在编译集合内穷举其消费者，**唯一命中是 `ff_glue.c:217 active = smp_started;`**（`sysctl_kern_smp_active` 处理函数）与 `:165` 自身的 SYSCTL 声明，即**纯 `kern.smp.active` 展示值**，无功能消费者→ **判定无需改**（可在 spec 记一句「`kern.smp.active` 仍报 0，为已知展示偏差」）。附：`designer` 校正的 HEAD 行号 `:210` 与我在工作区量到的 `:217` 相差 7—— 正是 `smp_topo()` 插入的 7 行，**两者一致，`designer` 的校正正确**。

---

## 3. clean build 实测数字（我自己执行，非引用 coder）

**命令（严格 `make clean` 先行，无增量）**：
```
cd /data/workspace/f-stack/lib     && make clean && make -j16
cd /data/workspace/f-stack/example && make clean && make
```

### 3.1 `lib/`

| 指标 | 我的实测值 | 门槛 | 判定 |
|---|---|---|---|
| `make clean` 返回码 | 0 | — | — |
| `make` 返回码 | **0** | 0 | 通过 |
| `grep -c "error:"` | **0** | 0 | 通过 |
| `grep -c "warning:"` | **51** | ≤ 51（HEAD 基线） | 通过（零新增） |
| `.o` 产出数 | **248** | 248 | 通过 |
| `libfstack.a` | 生成成功，**7,002,076** 字节 | 生成 | 通过 |

### 3.2 `example/`

| 指标 | 我的实测值 | 判定 |
|---|---|---|
| `make clean` 返回码 | 0 | — |
| `make` 返回码 | **0** | 通过 |
| `grep -c "error:"` | **0** | 通过 |
| `grep -c "undefined reference"` | **0** | 通过（`smp_topo` 是唯一新增符号，已补齐） |
| `grep -c "warning:"` | **0** | 通过 |
| `helloworld` | 生成成功，**30,392,672** 字节 | 通过 |
| `helloworld_epoll` | 生成成功，**30,386,072** 字节 | 通过 |

### 3.3 与 coder 数字的差异（已解释，非问题）

`libfstack.a`：我 7,002,076 vs coder 7,003,932（−1,856）；`helloworld`：我 30,392,672 vs coder 30,392,712（−40）。
原因：coder 的数字取自**第一轮**（`curcpu` 仍为 `0`），我的取自**第二轮**（`curcpu` = `PCPU_GET(cpuid)`）。`curcpu` 由字面量改为内存载入会改变 11 处 UMA 热路径的代码生成。**差异方向与幅度合理，且 error/warning/`.o` 数三项完全一致** → 视为一致 ✓

临时日志 `_rev_lib_build.log` / `_rev_ex_build.log` 已按规约用 `/data/workspace/rm_tmp_file.sh` 清理。

---

## 4. 必改项清单（按严重性排序）

> 无 FAIL 级（阻断 M5）缺陷。以下 4 项均可在 M5 之前或与 M5 并行修复。

| # | 级别 | 位置 | 问题 | 建议改法 |
|---|---|---|---|---|
| **M1** | P2 · 可用性回归 | `lib/ff_kern_synch.c:105` | `pause_wchan[curcpu]` 在 `pcpup == NULL` 时**确定性段错误**（改动前是合法的 `pause_wchan[0]`）。覆盖 bootstrap 期 OOM 重试路径与 D9 应用线程| `&pause_wchan[pcpup != NULL ? curcpu : 0]`（1 行；`pcpup` 定义于 `ff_freebsd_init.c:89`） |
| **M2** | P2 · 假注释（硬规约） | `lib/ff_kern_timeout.c:180-182` | 注释仍写 `cpuid is always 0, MAXCPU=1` —— G1 后**两句皆假**，且这段正是「`CC_CPU` 忽略 cpu 实参是安全的」的唯一书面依据 | 改为：`/* Per-thread callout_cpu: CC_CPU/CC_SELF ignore the cpu arg and always return the calling thread's own callwheel. */`（2 行） |
| **M3** | P2 · 文档准确性 | `docs/native_mt_spec/zh_cn/_m17_E_coder_g1.md` §1.3 | 「thread_mode=0 与改动前**逐字等价**」不成立。实测 4 项非等价差异：`uma_core.c:2546`不再剥离 `UMA_ZONE_PCPU`（走 FSTACK 版 `pcpu_page_alloc`）、CK RMW 加 `lock` 前缀、`MAXCPU` 相关 BSS 增长、`curcpu` 变为内存载入 + NULL 窗口。D7 是硬约束，M5 回归判据会因此漏测 | 改为「**逻辑值等价**（`mp_ncpus=1`/`mp_maxid=0`/`all_cpus`=bit0/槽位 0/`zpcpu_offset=0`），但存在 4 项非等价差异（逐条列出），M5 需一并回归」 |
| **M4** | P2 · 阻断 DoD-1 验证 | `lib/ff_freebsd_init.c` `ff_pcpu_thread_init()` + `lib/ff_dpdk_if.c` `main_loop()` | 当前**无任何**打印 `pc_zpcpu_offset`/`pc_cpuid` 的手段（全`lib/` grep `pc_zpcpu_offset` 零命中），M5 `tester` 无法验证 DoD-1 | 按 §2.11 的 3 条补**临时**探针（字段与落点已明确），M5 后移除并重跑 clean build |

## 5. 建议改项（不阻断，建议 designer 落 spec / coder 顺手处理）

| # | 位置 | 内容 |
|---|---|---|
| S1 | spec 已知风险 + `ff_config.c` 校验（可选） | **netisr HYBRID 回退风险**（§2.14 语义变化 A）：`net.isr.dispatch` 若被设为 `hybrid`/`deferred`，worker N≠0 会走 `queue_fallback` 而 f-stack swi 为空 stub → 报文无人处理。默认 `direct` 不受影响。建议 spec 明确列为不支持配置 |
| S2 | spec 残留风险清单（建议记为 R6） | **`tcp_hpts` 实例数 1→N**（§2.14 语义变化 B）：N 个 hpts entry + N 个 `p_hptss` 数组（内存）；N 个 callout 全挂**主线程** callwheel，而 `rp_ent[curcpu % N]` 由各 worker 选取→ CM6/CM7 缩 Giant 时的明确风险点 |
| S3 | spec 已知偏差 | `kern.smp.active` 仍报 0（`smp_started`/`smp_cpus`未同步）。我已穷举确认**无功能消费者**，仅展示偏差，**代码无需改** |
| S4 | spec D2 强化表述 | D2 的后果不止「堆越界」：`uma_int.h:528-529 ZDOM_GET` 用 `uz_cpu[mp_maxid+1]` 定位 domain 区 → `mp_maxid` 在 `uma_startup1()` 后被改会使 `uz_cpu[]` 与 `zdom[]` **区域重叠**。建议写入 spec 以强化该不变式|
| S5 | `lib/ff_freebsd_init.c:319-323` | 注释 4 行可压到 2 行（§2.9） |
| S6 | D9 裁决细化 | 「不加兜底、fail-fast」对 D9 误用成立；但不应涵盖内部 bootstrap 期的 `pause()` 重试路径（见 M1） |

## 6. 未核实边界（诚实记录）

1. **全部运行时行为均未验证**：我只做静态代码审查 + clean build。「各 worker `pc_zpcpu_offset` 互不相同」「UMA per-cpu zone 实际分配成功 `(mp_maxid+1)×4096`」「EAL main lcore 与 `proc_lcore[0]` 的实际关系（U6-a）」均需 M5 实测。我把 DoD-1 的**静态侧**做实了（§2.11），但 `kmem_malloc` 在 N 较大时能否稳定拿到 `(mp_maxid+1)` 页**未核实**。
2. **`freebsd/kern/subr_taskqueue.c:368callout_reset_sbt_curcpu` 的宏定义位置未坐实**：我在 `freebsd/sys/callout.h` grep 零命中。已论证其不构成越界风险（`:730` 有 `cpu >= MAXCPU` 兜底 + `CC_CPU` 忽略实参），但宏来源未定位。
3. **`-DSMP` 的影响面我按「SRCS 交叉过滤」穷举，但未逐一 `cc -E` 验证** 238 个 TU 的预处理结果。我核对的是 `#ifdef SMP` 的文本分布 + Makefile SRCS 归属，未做全量预处理比对。
4. **性能开销未量化**：CK RMW 的 `lock` 前缀、`curcpu` 由常量变内存载入（11 处 UMA 热路径 + 其它）、`MAXCPU=1024` 的 BSS/堆增长、`tcp_hpts`×N —— 全部待 M5 基线。
5. **`example/` 之外的构建目标未验证**（如 `tools/`、`tests/unit/`）。任务书只要求 `lib` + `example`。
6. **`config.ini` 的 ` M` 状态我未核对内容**（按规约不触碰），但需提醒 leader：M7 提交前必须按 AI memory 44404940 review `git diff config.ini`，剔除本地测试值。

---

## 7. 结论

# **PASS-with-fixes**

- **必改项：4 条**（M1 段错误边角 / M2 假注释 / M3 报告「逐字等价」表述 / M4 DoD-1 探针缺失），均为 **P2**，无 FAIL 级缺陷。
- **建议改项：6 条**（S1~S6，主要是 spec 需补记的语义变化与残留风险）。
- **是否阻断 M5 运行时验证：不阻断。** D1~D7、D9 全部满足；`-DSMP` 的行为影响面已穷举且可控；clean build 由我独立复现（`lib` error 0 / warning 51 / 248 `.o` / `libfstack.a` 7,002,076B；`example` error 0 / undefined 0 / `helloworld` 30,392,672B）。
- **唯一的前置条件**：**M4（临时探针）必须在 M5 开跑前落地**，否则 `tester` 无法验证 DoD-1 判定式，M5 会变成「跑起来没崩就算过」的弱验证。M1/M2/M3 可与 M5 并行修复。

---

## 8. 补审：`coder` 第三轮（DoD-1 探针）—— 我在本报告落盘后收到，已复审

第三轮于 **14:01:42 ~ 14:02:17** 落盘（晚于我 §3 的构建 13:58），新增 `lib/ff_host_interface.c` +8 / `lib/ff_host_interface.h` +4，`lib/ff_freebsd_init.c` 由 +36/-10 增至 **+67/-10**。**内容正是我的必改项 M4（DoD-1 探针）。**

### 8.1 探针内容与落点复核—— 通过

| 探针 | 位置 | 打印字段 | 判定 |
|---|---|---|---|
| `[M17-PROBE]` | `ff_freebsd_init.c:114-119`（`ff_pcpu_thread_init()` 末尾） | `tid` / `dense_idx` / `pc_cpuid` / `pc_zpcpu_offset` / `mp_ncpus` / `mp_maxid` / `curcpu` | **完整覆盖 DoD-1 主判定式** ✓ 覆盖面优于我 §2.11 的建议（多打了 `pc_cpuid` 与 `curcpu` 做交叉校验） |
| `[M17-PROBE-SLOT]` | `ff_freebsd_init.c:122-137` 定义；调用于 `:245`（worker）与 `:404`（主线程） | `dense_idx` / `zpcpu_get(V_tcbinfo.ipi_smr)` / `&V_tcbinfo.ipi_zone->uz_cpu[curcpu]` | **覆盖 DoD-1 判定式 ⑤（UMA cache 隔离）+ SMR 槽位隔离** ✓ 比我建议的方案更直接 |
| `ff_probe_tid()` | `ff_host_interface.c:152-158`（host TU），原型 `ff_host_interface.h:51-53` | `(uint64_t)pthread_self()` | 落点正确（内核 TU 取不到 `pthread_self`，走既有 host 访问器惯例；`ff_freebsd_init.c:49` 已 include该头）✓ |

**时序安全性（我重点核查的风险点）—— 实测安全**：`ff_probe_slots()` 触及 `V_tcbinfo`（VIMAGE 下经 `curthread->td_vnet` 解引用），若在 `curthread` / `td_vnet` 就绪前调用即段错误。实测两个调用点均在其后：
- worker 路径：`ff_pcpu_thread_init` `:215` → `ff_init_thread0()` `:223` → `curthread->td_vnet = v` `:238` → **探针 `:245`** ✓
- 主线程路径：`ff_pcpu_thread_init` `:347` → `ff_init_thread0()` `:349` → `mi_startup()` `:362`（`tcp_init` 在此创建 `ipi_zone`/`ipi_smr`）→ `curthread->td_vnet = vnet0` `:370` → **探针 `:404`**（`return (0);` 之前）✓
- `ff_pcpu_thread_init` 内的 `[M17-PROBE]` printf 只用 `pcpup`（刚在 `:111-112` 建好）与普通全局，**不触 `curthread`/vnet** ✓；其在 `ff_init_thread0()` 之前执行的合法性由既有先例保证（`ff_freebsd_init.c:294` 的 `printf` 与 `:286` 的 `panic` 同样早于 pcpu 初始化）。
- 两处探针均以 `#if 1 /* M17 temporary probe ... remove after M5 */` 包裹，摘除点清晰 ✓（`_m17_D_verdict.md` §1.3 要求探针不得沉淀为产品代码 —— 摘除后须重跑 clean build）。

### 8.2 第三轮 clean build（我重新执行，覆盖探针）

```
cd /data/workspace/f-stack/lib     && make clean && make -j16
cd /data/workspace/f-stack/example && make clean && make
```

| 指标 | 第三轮实测 | 门槛 | 判定 |
|---|---|---|---|
| `lib` `make` 返回码 | **0** | 0 | 通过 |
| `lib` `grep -c "error:"` | **0** | 0 | 通过 |
| `lib` `grep -c "warning:"` | **51** | ≤ 51 | 通过（零新增） |
| `lib` `.o` 产出数 | **248** | 248 | 通过 |
| `libfstack.a` | **7,003,564** 字节 | 生成 | 通过 |
| `example` `make` 返回码 | **0** | 0 | 通过 |
| `example` `error:` / `undefined reference` | **0** / **0** | 0 | 通过 |
| `helloworld` | **30,392,704** 字节 | 生成 | 通过 |

临时日志已用 `/data/workspace/rm_tmp_file.sh` 清理。

### 8.3 必改项状态更新（截至 14:09）

| # | 状态 | 依据 |
|---|---|---|
| **M4**（DoD-1 探针） | ✅ **已修** | 第三轮落盘 + 我复审通过 + clean build 通过（§8.1/§8.2） |
| **M3**（报告「逐字等价」表述） | ⚠️ **待复核** | `_m17_E_coder_g1.md` mtime 14:06:09（第三轮后有更新），但我落盘本报告时尚未逐字复核其修订内容 |
| **M1**（`ff_kern_synch.c:105` NULL 解引用） | ❌ **未修** | `lib/ff_kern_synch.c` mtime 仍为 **2026-03-20 18:48:54**（本轮从未被触碰） |
| **M2**（`ff_kern_timeout.c:180-182` 假注释） | ❌ **未修** | `lib/ff_kern_timeout.c` mtime 仍为 **13:38:19**（第一轮时间戳，注释未动） |

### 8.4 结论不变：**PASS-with-fixes**，且**不阻断 M5**

- 原「M5 开跑前的唯一前置条件」（M4）**已解除** → **M5 运行时验证现在可以立即启动**。
- 剩余 **M1 / M2**（各 1~2 行）+ **M3**（文档表述）可与 M5 并行修复，不构成阻断。
- 新增提醒：M5 结束后 `coder` 必须摘除两处 `#if 1 /* M17 temporary probe */` 探针及 `ff_probe_tid()`（含 `.h` 原型），并**重跑 clean build** 确认回到 error 0 / warning 51 / 248 `.o`。

---

# 9. 复审（bounce 3）：M3 门禁最终结论

> 这是 leader 指定的「复审（bounce 3）」一节（因本文已有 §5，改用 §9 编号以免歧义）。
> bounce 计数已达 **3/3 上限**，故本节严格区分「**阻断项**」与「**可记入残留风险的非阻断项**」，只有真正阻断的才判FAIL。
> 复审基准：`git diff` 终态，`lib/ff_freebsd_init.c` mtime **14:52:12**、`_m17_E_coder_g1.md` mtime **14:54:33**；`git status --short freebsd/` 仍为**空**（上游树零改动）。

## 9.1崩溃修复（`uma_page_slab_hash` 提前）—— 通过，且我判定修法**安全且彻底**

**根因链我独立复核，成立**（leader 的解析正确，仅一处行号偏差）：
- `uma_core.c:2485-2491`（leader 记 `:2486-2492`，**实际 2485-2491**，偏移 1）：
  ```c
  if ((keg->uk_flags & UMA_ZFLAG_OFFPAGE) != 0 ||
      (keg->uk_ipers - 1) * rsize >= PAGE_SIZE) {
          if ((keg->uk_flags & UMA_ZONE_NOTPAGE) != 0) keg->uk_flags |= UMA_ZFLAG_HASH;
          else                                         keg->uk_flags |= UMA_ZFLAG_VTOSLAB;
  }
  ```
- `uma_core.c:1821-1824`（`keg_alloc_slab()` 内，受 `UMA_ZFLAG_VTOSLAB` 保护）：
  ```c
  if (keg->uk_flags & UMA_ZFLAG_VTOSLAB)
          for (i = 0; i < keg->uk_ppera; i++)
                  vsetzoneslab((vm_offset_t)mem + (i * PAGE_SIZE), zone, slab);
  ```
- `lib/include/vm/uma_int.h:104-107`：`vsetzoneslab()` 首行即 `hash_list = &uma_page_slab_hash[UMA_PAGE_HASH(va)];` → `uma_page_slab_hash == NULL` 时**立即 NULL 解引用** ✓ 与 `tester` 的栈（`uma_startup1 → zone_alloc_item → zone_import`）一致。

### ① `kmem_malloc` 在该时点可用 —— 成立，且有更强依据

`lib/ff_glue.c:1032-1039`：
```c
void *kmem_malloc(vm_size_t bytes, int flags)
{
    void *alloc = ff_mmap(NULL, bytes, ff_PROT_READ|ff_PROT_WRITE, ff_MAP_ANON|ff_MAP_PRIVATE, -1, 0);
    ...
}
```
→ `kmem_malloc` **直接走宿主 `ff_mmap`，不经UMA、不读`uma_page_slab_hash`**✓ 因此它在UMA 尚未 bootstrap 的任何时点都可用。
比leader 提的「`boot_pages` 那次 kmem_malloc 本来就在 uma_startup1 之前」这一先例更强：**是实现层面的无依赖**，不只是位置先例。
另：`vsetzoneslab()` 内部插表用的是 `malloc(sizeof(*up), M_DEVBUF, M_WAITOK)`（`uma_int.h:120`）→ `ff_glue.c:1067` 的 `malloc` → `ff_malloc`，**也不回绕 UMA** → 修复无自递归风险 ✓

### ② 提前后只变好不变坏 —— 成立

|窗口 | 改动前 | 改动后 |
|---|---|---|
| `mp_maxid == 0`（thread_mode=0） | `VTOSLAB` 从不置位（`(uk_ipers-1)*rsize < PAGE_SIZE`）→ 该窗口内**从不触碰**哈希表 → 表为 NULL 无害 | 表已就绪但同样**从不被触碰** → **行为逐字等价，D7 零回归不受影响** ✓ |
| `mp_maxid >= 2` | `VTOSLAB` 置位 → `uma_startup1()` 内 `vsetzoneslab()` → **NULL 解引用崩溃** | 表已就绪 → 正常插表✓ |

→ 单向改善，无「变坏」路径。**且我确认该修复不影响 thread_mode=0 的零回归结论**（§2.2 仍成立）。

### ③ 是否有路径在哈希表初始化之前调用 `vsetzoneslab` —— **修复彻底**

- 全树穷举 `uma_page_slab_hash` 的**写点只有 1 处**（`ff_freebsd_init.c:381`，即被移动的那行）；**读点只在** `lib/include/vm/uma_int.h` 的 3 个 inline（`vtoslab`/`vtozoneslab`/`vsetzoneslab`）。
- 这3 个 inline 在**编译集合内的实际调用者只有 `uma_core.c`**：`:1824vsetzoneslab`、`:4930 vtoslab`、`:5819 vtoslab`。全部属UMA 运行期，**必然晚于 `uma_startup1()`**（`:385-387`）。
- 新位置（`:379-383`）**之前**的语句逐条核对**均不触达 UMA**：`kern_setenv`（→ 宿主 `malloc`）、`physmem` 赋值、三元组设置、`ff_pcpu_thread_init()`（→ 宿主 `malloc` + `printf`）、`ff_init_thread0()`（`ff_compat.c:156-160`，**函数体仅 `pcurthread = &thread0;` 一行赋值**）。
- 新位置与 `uma_startup1()` 之间只有 `boot_pages` / `bootmem = kmem_malloc(...)`（宿主 mmap）。
→ **不存在哈希表初始化之前调用 `vsetzoneslab` 的路径，修复彻底** ✓

**附带新发现（好消息，无需处理）**：f-stack 覆盖版 `vtozoneslab()`（`lib/include/vm/uma_int.h:91-102`）存在 `LIST_FOREACH` 后**未判 `up != NULL` 即 `*slab = up->up_slab`** 的隐患。我担心`VTOSLAB` 现在会被置位从而让它变得可达，故穷举其调用者：**仅 `freebsd/kern/kern_malloc.c:943/1039/1136`，而 `kern_malloc.c` 不在 SRCS**（`grep -c kern_malloc lib/Makefile` = **0**）→ 该函数是**死代码，零风险**，本轮无新暴露面。

### ④ `sizeof(struct uma_page)` vs `struct uma_page_head` 的类型不匹配 —— **判定：本轮不动（同意 leader），但给出确定性结论**

```c
uma_page_slab_hash = (struct uma_page_head *)kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO);
```
实测两结构（`lib/include/vm/uma_int.h:67-74`）：
- `struct uma_page` = `LIST_ENTRY`(2 指针 =16B) + `vm_offset_t`(8) + `uma_slab_t`(8) + `uma_zone_t`(8) = **40 B**
- `struct uma_page_head` = `LIST_HEAD`(1 指针 `lh_first`) = **8 B**

→ 实际分配 `40 × 8192 = 327,680 B`，实际需要 `8 × 8192 = 65,536 B` → **超额分配 5 倍**。

**结论：这是「多分配」而非「少分配」，因此是纯内存浪费（约 256 KB / 每stack 实例），无任何越界或正确性风险。** 该行为 diff 逐字搬移的既有写法（`git diff` 显示删除行与新增行内容完全一致）。**本轮不处理是正确的**：① 无正确性风险；② 与崩溃修复混在同一改动里会混淆关注点；③ 属独立技术债。**建议记入残留风险 R-a**（修法：`sizeof(struct uma_page_head)`；注意多实例下 256KB×N，thread_mode=1 时值得顺手修）。

## 9.2 必改 1（`pause_wchan` 兜底）—— 通过，实现正确

`lib/ff_kern_synch.c:102-108`：
```c
    /* Reachable from malloc()'s OOM retry before this thread has a pcpu. */
    return (_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], NULL, 0, wmesg,
        sbt, pr, flags));
```
- **语义等价性** ✓：`pcpup != NULL` 时取 `curcpu`（= `pcpup->pc_cpuid`），与原行为一致；为 NULL 时退回 slot 0，恢复改动前的合法行为。
- **`pcpup` 声明取得方式合法** ✓：`lib/include/amd64/include/pcpu.h:45extern __thread struct pcpu *pcpup;` —— 与 `curcpu`/`PCPU_GET` 同一声明来源（`:49`），经`<sys/param.h>`/`<sys/proc.h>` → `<sys/pcpu.h>` → `machine/pcpu.h` 链条可见。**未新增 include，也无需新增**（该文件原本就在用 `curcpu`，即已依赖同一声明）。
- **无新增warning** ✓：clean build warning 数仍为 **51**（§9.5）。
- 注释1 行、说明「为何可达」（非显而易见），符合最小注释规约 ✓。

## 9.3 必改 2（假注释）—— 通过；§2.9 建议精简项也已处理

- `lib/ff_kern_timeout.c:180-182` 已改为：
  `/* Per-thread callout_cpu: each stack instance drives its own callwheel. CC_CPU/CC_SELF ignore the cpu arg and return the calling thread's own instance, so c_cpu is only a record of which thread armed the callout. */`
  → 删除了 `cpuid is always 0, MAXCPU=1` 两句假陈述，并补上了 `c_cpu` 退化为「记录谁 arm 了callout」的准确语义 —— **与我 §2.5 的实测结论一致** ✓
- **§2.9 建议精简的 `ff_freebsd_init.c:319-323`（4 行）已压到 2 行** ✓：
  `/* Main thread is itself an EAL lcore worker (CALL_MAIN), so it takes its own dense slot; thread_mode=0 has one stack per process -> slot 0. */`
- 新增注释复核：`ff_kern_synch.c` 1 行（必要）、`ff_freebsd_init.c:376-380` 哈希表提前的 5 行（说明极不直观的 `VTOSLAB` 触发链与刚性时序，**必要，保留**）、`ff_probe_pcpu_zone` 的 U2 说明 5 行（属临时探针代码，随探针一并移除，可接受）。**注释规约：通过。**

## 9.4 探针复审（leader 的 3 个子问题）

### ① 探针不改变任何控制流 —— 确认

- `[M17-PROBE]`（`ff_freebsd_init.c:114-119`）：纯 `printf`，只读 `pcpup`/`cpuid`/`mp_ncpus`/`mp_maxid`/`curcpu` 与 host侧 `ff_probe_tid()`。**无分支、无赋值、无返回值影响** ✓
- `ff_probe_slots()`（`:122-137`）：两个局部变量 + 两个 `if (... != NULL)` **只用于保护自身读取**，不影响调用者；末尾 `printf` ✓
- `ff_probe_pcpu_zone()`（`:139-163`）：局部数组 + `continue` 跳过 NULL zone/keg，纯读 `uk_ppera`/`uk_rsize` ✓
- 3 处调用点（`:242` 间接经 `ff_pcpu_thread_init`、`:272`、`:430-431`）均为语句级插入，**不改变任何既有语句的顺序或条件** ✓

### ② 取证有效性 —— **对象取得正确，但两个字段的「步长」不同，`tester` 判定式必须分字段**（本节最关键）

对象选择**正确**：
- `zpcpu_get(V_tcbinfo.ipi_smr)` = `base + pcpup->pc_zpcpu_offset` → 直接证明 **SMR per-cpu 槽位隔离**；
- `&V_tcbinfo.ipi_zone->uz_cpu[curcpu]` → 直接证明 **UMA per-cpu cache 槽位隔离**，即 `designer` §2.3/§4.5 指出的、G1 第一轮漏掉的那个对象 ✓ 取的正是该缺口本身。

**⚠ 但 `uz_cpu[]` 的步长是 `sizeof(struct uma_cache)`，不是 `UMA_PCPU_ALLOC_SIZE`。** 我用 `tester` 的实测日志坐实（`example/f-stack-0.log:1189-1201` + `example/helloworld.log:499-514`，同一次 4 线程档运行）：

| dense_idx | `pc_zpcpu_offset` | `smr_c_seq` | `uma_cache` |
|---|---|---|---|
| 0（主线程） | 0 | `0x7f861477fc80` | `0x7f8614758980` |
| 1 | 4096 | `0x7f8614780c80` | `0x7f8614758a00` |
| 2 | 8192 | `0x7f8614781c80` | `0x7f8614758a80` |
| 3 | 12288 | `0x7f8614782c80` | `0x7f8614758b00` |
| **相邻差** | **+4096** | **+0x1000 = 4096** | **+0x80 = 128** |

→ `smr_c_seq` 步长 **4096**（`= UMA_PCPU_ALLOC_SIZE = PAGE_SIZE`，因 `zpcpu_get` 加的是 `pc_zpcpu_offset`）；
→ `uma_cache` 步长 **128**（`= sizeof(struct uma_cache)`，`struct uma_cache` 三个 `uma_cache_bucket`(16B)+2×`uint64_t` = 64B 再经 `UMA_ALIGN` 对齐到 128）。

**因此：若 `tester` 把「两两相差 `4096*Δidx`」套到 `uma_cache` 上，会得到「差 128 而非 4096」从而误判 FAIL。** 正确判定式应为：
1. `pc_cpuid == dense_idx == curcpu`
2. `pc_zpcpu_offset == 4096 * dense_idx`
3. `smr_c_seq` 构成公差 **4096** 的等差数列（等价于 `smr_c_seq(i) - smr_c_seq(0) == 4096*i`）
4. `uma_cache` 构成公差 **128** 的等差数列，且**两两互不相同**（隔离性的实质要求是「不同」，公差只是佐证）
5. `uk_ppera == mp_maxid + 1`

上表4 个槽位在 1~4 全部**精确成立** → **DoD-1 的取证已由现有探针实际产出，不只是「探针到位」**。

### ③ 便于一次性移除 —— 确认，DoD-8 可满足

全部探针统一以 `#if 1 /* M17 temporary probe ... */... #endif` 包裹，共 **6 处**：`ff_freebsd_init.c` 4 处（`:114-119` 标量探针、`:122-163` 两个 probe 函数定义、`:267-269` worker 调用、`:428-431` 主线程调用）+ `ff_host_interface.c:152-158`（`ff_probe_tid`）+ `ff_host_interface.h:51-53`（原型）。
`grep -rn "M17 temporary probe" lib/` 即可穷举，**一次性摘除可行** ✓
**M7 前必须摘除并重跑 clean build**，确认回到 error 0 / warning 51 / 248 `.o`（记为 R-d）。

### ④ `[M17-PROBE-ZONE]` 取值可信性 —— 可信，且有**自校验**

- `kg = zones[i]->uz_keg` 是该 zone 自己的 keg 指针，`uk_ppera`/`uk_rsize` 直接取自该 keg ✓
- **自校验（这点让我判定可信而非只是「看起来对」）**：打印的 `uk_rsize` 与 zone 名字**自洽** —— `pcpu_zone_8` → `uk_rsize=8`，`pcpu_zone_64` → `uk_rsize=64`。若 `uz_keg` 取错或别名到其它 keg，`rsize` 不可能同时对上两个 zone 的名义大小。
- **双工作点交叉验证**：`mp_maxid=3→ uk_ppera=4`（`f-stack-0.log:1200-1201`）与 `mp_maxid=1 → uk_ppera=2`（`:1227-1228`）→ **`uk_ppera == mp_maxid + 1` 在两个不同档位同时成立**，与 `uma_core.c:2472-2474 pages *= mp_maxid + 1` 完全吻合。
- → **U2 首次被直接坐实**：`UMA_ZONE_PCPU` zone 真的按 `(mp_maxid+1)` 页分配，`zpcpu_offset_cpu(cpu)=4096*cpu` 落在已分配范围内，**不是越界读相邻内存** ✓ 我在 §2.11 只能静态推证的结论现已有运行期实证。

## 9.5 clean build 复验（我自己跑，第四轮）

| 指标 | 我的实测值 | 门槛 | 判定 |
|---|---|---|---|
| `lib` `make clean` / `make` 返回码 | 0 / **0** | 0 | 通过 |
| `lib` `grep -c "error:"` | **0** | 0 | 通过 |
| `lib` `grep -c "warning:"` | **51** | ≤ 51（HEAD 基线） | 通过 —— **探针零新增 warning**，与 coder 报告一致 |
| `lib` `.o` 产出数 | **248** | 248 | 通过 |
| `libfstack.a` 大小 | 7,004,036 B | 生成 | 通过 |
| `example` `make` 返回码 | **0** | 0 | 通过 |
| `example` `error:` / `undefined reference` | **0** / **0** | 0 | 通过 |
| `helloworld` | **30,392,704** B | 生成 | 通过 |
| `helloworld_epoll` | **30,386,112** B | 生成 | 通过 |

### 版本判据 md5（`tester` 用）

```
751a8153d3b200229cff99b3fa7650b0  example/helloworld
0d31850c7e447b140ea0a43647d07915  example/helloworld_epoll
```

**⚠ 与 coder 报告的 `d49268db…` 不一致，且我做了可复现性验证：**
- 我连续做了**两次**完整clean build（`lib` + `example`），`helloworld` 的 md5 **两次完全相同**（`751a8153…`）→ **`helloworld` 的 md5 是可复现的**，可以作为版本判据。
- 同两次构建的 `libfstack.a` md5 **不同**（`4625a6d4…` vs `ddfc50ac…`）→ 证实 leader 的判断：`.a` 因 `ar` 内嵌 mtime **不可复现**，**不可作为版本判据** ✓
- 既然 `helloworld` 可复现而 coder 的值与我不同，**说明 coder 报的 md5 来自与当前工作区不同的源码状态**（`ff_freebsd_init.c` mtime **14:52:12**晚于其构建、报告 mtime 14:54:33）。属流程瑕疵，非代码缺陷。
- **要求**：`tester` 必须以 **`751a8153d3b200229cff99b3fa7650b0`** 为被测版本；若手上二进制 md5 不符，须先重跑 `make clean && make` 再测（记为 R-c）。

## 9.6 探针输出缺行（`dense_idx=2` 的 `[M17-PROBE]`）—— **判定：printf 输出丢失，不是线程未走到**

**结论依据（代码级充分证明，非推测）**：`ff_stack_thread_init()` 内的顺序为
`init_lock` 上锁（`:240-241`）→ **`ff_pcpu_thread_init(cpuid)`（`:242`，内含 `[M17-PROBE]`）** → `ff_callout_thread_init` → `vnet_alloc` → `lo_set_defaultaddr` → **`ff_probe_slots(cpuid)`（`:272`，即 `[M17-PROBE-SLOT]`）** → `__sync_lock_release`（`:274`）。
→ 两个探针在**同一临界区内**，且 `[M17-PROBE]` **严格先于** `[M17-PROBE-SLOT]`。
→ **`[M17-PROBE-SLOT] dense_idx=2` 存在（`helloworld.log:493`）⟹ 该线程必然已执行 `[M17-PROBE]` 的 printf。** 故不可能是「线程没走到探针」。

**统计佐证（非确定性 ⇒ 输出层问题）**：
```
dense_idx=1 : PROBE=6  SLOT=6
dense_idx=2 : PROBE=2  SLOT=3← 仅缺 1 条
dense_idx=3 : PROBE=2  SLOT=2
```
两次 4 线程档运行中，**只有一次**丢了 `idx=2` 的 PROBE 行（`helloworld.log:478-493` 缺；`:499-514` 完整含全部 6 行）→ 非确定性 → 输出层。

**丢失机制（已定位到代码）**：`lib/ff_subr_prf.c:86char bufr[PRINTF_BUFR_SIZE];` 是一个**全局、非 `__thread`、无锁保护**的行缓冲（配 `:89 static int putbuf_done`）。worker 的探针虽在 `init_lock` 内串行，但**主线程与其它线程在 `init_lock` 之外的 `printf`**（DPDK 链路状态、`lo_set_defaultaddr` 等）会并发改写同一 `bufr[]`，导致整行被覆盖丢弃。这是 **f-stack 既有缺陷，非本轮引入**（`__thread cc_cpu` 等已per-thread 化，但 `bufr` 未）。

**定级：非阻断**（探针可靠性问题，不影响产品代码正确性）。给 `tester` 的处置建议：
1. 以 **`[M17-PROBE-SLOT]` 出现 N 条互不相同的 `dense_idx`** 作为「N 个线程都完成初始化」的完备性判据；
2. 若某档位缺行，**重跑一次**即可（非确定性）；
3. 不要因缺行判FAIL —— 缺行只代表日志丢失。
（记为 R-b。可选改进：把 `bufr` 改 `__thread`，但属独立议题，不在M3 范围。）

## 9.7 M3 门禁最终结论

# **PASS**

**阻断项：0 条。** 我逐项复核了 leader 列出的 6 项，全部通过：崩溃修复的4 个子问题（①②③④）全部成立且**修复彻底**；必改 1/必改 2 实现正确；§2.9 建议精简项已处理；探针不改控制流、取证对象正确、可一次性移除、`[M17-PROBE-ZONE]` 可信并首次直接坐实 U2；clean build 由我独立复现（error 0 / warning **51** = HEAD 基线 / 248 `.o`）。**M3 可以关闭，无需转人工决策。**

**非阻断残留项（建议记入 spec 残留风险，不阻断 M3 关闭）**：

| # | 内容 | 定级 |
|---|---|---|
| **R-a** | `ff_freebsd_init.c:381` 用 `sizeof(struct uma_page)`(40B) 而非 `sizeof(struct uma_page_head)`(8B) 分配哈希桶 → **超额** 5 倍、浪费约 256 KB/实例。**多分配故内存安全**，既有写法逐字搬移 | 低（技术债；thread_mode=1 多实例时值得顺手修） |
| **R-b** | `ff_subr_prf.c:86` 全局无锁 `bufr[]` → 探针（及一切 `printf`）**可能整行丢失**。既有缺陷 | 低（影响探针可靠性，不影响产品正确性） |
| **R-c** | coder 报的 `helloworld` md5（`d49268db…`）与当前工作区构建结果（`751a8153…`）不一致；我已证实该 md5 **可复现**，故 coder 的值来自不同源码状态 | 中（流程；`tester` 必须按我的 md5 pin 版本） |
| **R-d** | 6 处 `#if 1 /* M17 temporary probe */` 探针 M7 前必须摘除并重跑 clean build（DoD-8） | 中（发布前必做） |
| **R-e** | **`tester` 判定式必须分字段**：`smr_c_seq` 公差 **4096**、`uma_cache` 公差 **128**（`sizeof(struct uma_cache)`）。套用统一的 `4096*Δidx` 会误判 FAIL | **高（会导致误判，必须在 M5 前传达到 tester）** |
| R-f | §2.14 的语义变化 A（`net.isr.dispatch` 须保持 `direct`）/ B（hpts 实例数 1→N，建议 R6）—— leader 已下发 `designer` | 中（文档） |

## 9.8 G2 放行结论

# **G2 可以开工**

`gate-design` E3 的硬前置**已满足**，依据（静态 + 运行期双重）：

1. **静态**：`lib/include/sys/pcpu.h:31-34` 终态为
   ```c
   #include_next <sys/pcpu.h>
   #undef curcpu            /* ← 保留 ✓ */
   #define curcpu    PCPU_GET(cpuid)
   ```
   `#undef curcpu` **保留** ✓（避免与上游 `freebsd/sys/pcpu.h:218` 重定义）；`PCPU_GET(member)` = `(pcpup->pc_ ## member)`（`lib/include/amd64/include/pcpu.h:49`）→ `curcpu` 已是 **per-thread** ✓
2. **运行期实证（新增，比静态更强）**：`tester` 日志显示 4 线程档 `curcpu` 实测取值为 **0/1/2/3 且与各自 `dense_idx`、`pc_cpuid` 三者一致**；对应的 `uz_cpu[curcpu]` 地址构成公差 128 的等差数列、**两两互不相同** → **UMA per-cpu cache 已真正按线程分槽**（这正是 `designer` 指出、G1 第一轮遗漏的那个缺口，现已闭合）✓
3. **G2 的安全前提成立**：G2 移除 `uma_crit_lock` 后，槽位隔离将成为**唯一**保护。现已实证隔离生效（第 2 点）+ `uk_ppera == mp_maxid+1` 保证槽位落在已分配范围内（§9.4④）→ 移除全局锁不会退回 `b90ddcba5` 修掉的崩溃。

**给 G2 的2 条附带要求**（不影响放行）：
- G2 独立提交（`designer` 的 D8裁决 G2-b + L0/L1/L2 降级台阶），不要与本轮 G1 混提交；
- G2 完成后需**重新**跑 §9.4② 的 5 项判定式（去锁后槽位隔离是唯一保护，必须复测而非沿用本轮数据）。
