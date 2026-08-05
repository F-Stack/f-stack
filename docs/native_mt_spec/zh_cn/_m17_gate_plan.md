# M17 plan 门禁审核报告（gate-plan）

被审对象：`/data/workspace/f-stack/docs/native_mt_spec/zh_cn/plan-17-SMP-aware-pcpu-smr.md`
审核者：`gate-plan`（只审不改；本文件是本agent 唯一写入的文件）
审核方式：逐条 `read_file` / `search_content` 实际打开代码核对，未核实项显式标注「未核实」，禁止推测。
仓库状态自核：`git log -1` = `ff09a17b2` ✓ 与 plan §1 声明一致；`b90ddcba5` 存在且 message 与 plan §1.4 引用**逐字一致** ✓。

---

## 一、结论

**PASS-with-fixes**

- 无阻断性缺陷：目标覆盖完整、规约覆盖 10/10 齐全、里程碑角色分离无「自写自审」、大部分 `file:line` 事实真实。
- 但存在 **2 处事实性错误**（§1.3 `pcpu_page_alloc` 编译开关归因错误；`UMA_PCPU_ALLOC_SIZE` 标为「待定位」而实际已可静态坐实）、**1 处误导性措辞**（把 `KASSERT` 称作「判断」）、**1 处 G2 核心事实缺失**（`critical_enter` 在 f-stack 非 UMA TU 中已是空操作），以及 **6 项会导致方案返工的关键未知量遗漏**（尤其 MAXCPU 尺寸数组跨 TU 一致性、`mp_maxid` 必须早于 `uma_startup` 的时序硬约束、callout 全局 `timeout_cpu` 竞争）。
- 必须修正项：**10 条**（F1~F10，见第四节）。修完可直接进入 M1，无需二次打回（bounce 计数建议记为 M0 第 1 次打回）。

---

## 二、逐项审核结果

| # | 审核项 | 结论 | 依据摘要 |
|---|---|---|---|
| 1 | file:line 引用真伪 | **PASS-with-fixes** | 22 行事实逐条核验：18 条内容完全一致（含 8 条逐行精确命中）；2 条事实错误（F1/F2）；1 条措辞误导（F3）；8 处行号偏差均在 ±5 内但建议校正（F8） |
| 2 | 目标完整性（G1+G2） | **PASS** | §0.2 明确「两个并列主目标」；G2 有独立里程碑 M4、独立验收 DoD-2 与性能对照 DoD-5、独立事实节 §1.4；§0.4 明确要求去锁前后吞吐对比 |
| 3 | 规约覆盖 | **PASS（10/10）** | §4.1 三脚本 +禁止 shell 串出现原命令；§4.2 make clean 先行（含 `lib/`与 `example/`）；§4.3 lib 最小注释；§4.4 commit 英文 1-3 句 + config.ini 不入库 + `git add` 前 review diff；§4.5 实测不臆测/以代码为准；§4.6 写审分离 + bounce≤3 + leader 不提前退出 + 超时轮询 + 旁路探测（细则见 §3.1/§3.2）；§4.7 外网须给可核查链接 |
| 4 | 未知量充分性 | **FAIL（须补）** | U1~U8 方向正确且 U4 已含 `cpuset_t`/`CPU_SETSIZE` ABI、U6 已含稠密索引来源、U7 已含辅助路径、U8 已含跨线程 alloc/free；但遗漏 6 项（建议 U9~U15，见第五节），其中 U9/U10/U11 属「不补必返工」级别 |
| 5 | 里程碑与门禁自洽性 | **PASS-with-fixes** | M0~M6 全部写审异构，无自写自审（见下表）；仅 M7 与 M5 的门禁归属措辞需收紧（F10） |
| 6 | 验收标准可测性 | **PASS-with-fixes** | DoD-2/4/6/7 可测；DoD-1 缺可执行手段（最重要一条）；DoD-3 缺 warning 基线锚点；DoD-5 缺通过阈值；缺临时产物清理项（F10） |

### 2.1 审核项 1 明细（逐行核验）

已核实**一致**（PASS）：

| plan 引用 | 实际核验| 判定 |
|---|---|---|
| `ff_freebsd_init.c:85` `__thread struct pcpu *pcpup;` | 实际 85 行逐字一致 | ✓ |
| `ff_pcpu_thread_init()` 三步 | 实际 103-109：`malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO)` → `pcpu_init(pcpup, 0, sizeof(struct pcpu))` → `PCPU_SET(prvspace, pcpup)`；98-101 注释明写 cpuid 必须为 0 | ✓ |
| `:~187` worker 调用点在 `init_lock` 临界区内 | `ff_stack_thread_init` 起于 171；`init_lock` 声明 175、自旋 185-186；`ff_pcpu_thread_init(cpuid)` 在 **187** | ✓ 精确 |
| `:~293` 主线程 `ff_pcpu_thread_init(0)` | 实际 **293** | ✓ 精确 |
| `pcpu.h:28-46` 的 10 项 `#undef` + `PCPU_*` 重定义 + `zpcpu_offset_cpu` undef 后未重定义 | `#undef` 实际 33-42（10 项与 plan 列举完全一致）；`PCPU_GET/ADD/INC/PTR/SET` 重定义 47-53；全文件（69 行）此后无 `zpcpu_offset_cpu` 定义 | ✓ 内容一致 |
| `freebsd/sys/pcpu.h:235-236` `#ifndef zpcpu_offset_cpu` / `#define ... (UMA_PCPU_ALLOC_SIZE * cpu)` | 实际 `#ifndef` 234、`#define` 235、`#endif` 236 | ✓ |
| `sys/pcpu.h` `zpcpu_offset()`/`zpcpu_get`/`zpcpu_get_cpu` | `zpcpu_offset` 237-239；`zpcpu_get` 249-252；`zpcpu_get_cpu` **254-257** | ✓ 内容一致 |
| `subr_pcpu.c:88,91-92,96` | 88-89 `KASSERT(cpuid >= 0 && cpuid < MAXCPU, ...)`；91 `cpuid_to_pcpu[cpuid]=pcpu`；92 `STAILQ_INSERT_TAIL`；96 `pc_zpcpu_offset = zpcpu_offset_cpu(cpuid)` | ✓ 逐行精确 |
| `subr_pcpu.c:252,269-287` | 252 `#ifdef SMP`（`dpcpu_copy`）；`pcpu_destroy` 270-277（274 `STAILQ_REMOVE`、275 清 `cpuid_to_pcpu`、276 清 `dpcpu_off`）；`pcpu_find` 282-287 | ✓ |
| `amd64/include/param.h:60-66` | 60 `#ifdef SMP`、62 `MAXCPU 1024`、64 `#else`、65 无条件 `#define MAXCPU 1`、66 `#endif` | ✓ 逐行精确 |
| `lib/Makefile` 无 `-DSMP`、无 `INVARIANTS` | `SMP|INVARIANTS|MAXCPU` 全文件零命中；仅 219 `CFLAGS+= -DFSTACK`、222/226 `FSTACK_ZC_*`。补充证据：`lib/opt/` 下 `SMP|INVARIANTS` 亦零命中 | ✓（M1-C 仍需覆盖 `mk/`） |
| `uma_core.c:2546-2548` `#ifndef SMP` 剥离 `UMA_ZONE_PCPU` | 2546/2547/2548 逐行一致，且不在任何 `#ifndef FSTACK` 块内 | ✓ |
| `uma_core.c:3494-3516` / `:3526` | `uma_zalloc_pcpu_arg` 3494-3516（3498 `#ifdef SMP`、3501 `MPASS`、3509-3510 `for(i=0;i<=mp_maxid;i++) bzero(zpcpu_get_cpu(...))`、3512 `#else` 单份）；`uma_zfree_pcpu_arg` 3521-3536（`MPASS` 在 3527） | ✓ 内容一致 |
| `uma_core.c:1959-1990` 逐 CPU 版含 `MPASS(bytes == (mp_maxid+1)*PAGE_SIZE)` | 函数 1958-；`MPASS` 1970；`for (cpu=0; cpu<=mp_maxid; cpu++)` 1975；`CPU_ABSENT` 1976 | ✓ 内容一致（**归因错误见 F1**） |
| `uma_core.c:2084-2089` 回退实现 | 实际 2083-2089（2087 `*pflag=UMA_SLAB_KERNEL;` 2088 `return page_alloc(...)`） | ✓ |
| `subr_smr.c:583-609` `smr_create` | 583-609；591 `uma_zalloc_pcpu(smr_zone, M_WAITOK)`；598-605 `for(i=0;i<=mp_maxid;i++){ zpcpu_get_cpu; c_seq=SMR_SEQ_INVALID; c_shared=s; ...}` | ✓ 精确 |
| `subr_smr.c:625-632` `smr_init` `UMA_ZONE_PCPU` | 实际 623-631，`uma_zcreate("SMR CPU", sizeof(struct smr), ..., UMA_ZONE_PCPU)` 在 629-630 | ✓ 内容一致 |
| `sys/smr.h:106-143` `smr_enter` 走 `zpcpu_get(smr)` | 函数 105-143，`zpcpu_get` 在 110 | ✓（**缺关键事实见 F4**） |
| `in_pcb.c:583,615-617` | 583 `pcbinfo->ipi_smr = uma_zone_get_smr(pcbinfo->ipi_zone);`；615-617 `uma_zcreate(..., UMA_ALIGN_CACHE, UMA_ZONE_SMR)` | ✓ 精确 |
| `uma_int.h:45-52` 全局自旋锁代码块 | 45 `extern volatile int uma_crit_lock;`、46-49 `critical_enter`、50-52 `critical_exit`，与 plan 引用的代码块逐字一致；同文件 43 `#undef UMA_MD_SMALL_ALLOC`、54-57 sleepq stub、59 `_vm_map_unlock`、65 `UMA_PAGE_HASH`、67-74 `struct uma_page` | ✓ |
| `ff_glue.c` 全局变量组 | 138 `cpuset_t all_cpus;`、140 `int mp_ncpus = 1;`、142 `int mp_maxcpus = MAXCPU;`、144 `volatile int smp_started;`、145 `u_int mp_maxid;`（无初值=BSS 零）、146 `volatile int uma_crit_lock;` | ✓ 内容一致|
| `counter.h:44` `counter_u64_fetch_inline()` | 实际 43-47 定义于 `#ifdef IN_SUBR_COUNTER_C`(41)，函数体 `return (*p);`，`counter_u64_fetch_inline` 名字在 44 | ✓（**推论强度需修，见 F6**） |
| `b90ddcba5` message | `git log` 输出 = "Fix UMA per-CPU cache race and sizeof mismatch for native-mt multi-thread startup" | ✓ 逐字一致 |

已核实**不一致 / 需修正**（详见第四节 F1~F3、F8）。

### 2.2 审核项 5 明细（写/审异构核验）

| 里程碑 | 写 | 审 | 是否异构 |
|---|---|---|---|
| M0 | leader | `gate-plan` | ✓（本报告即证据） |
| M1 | `res-code`/`res-web`/`res-build` | leader 汇总 + `gate-design` | ✓ |
| M2 | `designer` | `gate-design` | ✓ |
| M3 | `coder` | `reviewer` | ✓ |
| M4 | `coder` | `reviewer` | ✓ |
| M5 | `tester`（≠coder） | leader 汇总 + `reviewer` | ✓（reviewer 未参与产出数据） |
| M6 | `designer` | `gate-doc` | ✓ |
| M7 | leader（commit） | leader review diff + `gate-doc` | ⚠ 措辞需收紧（F10-d） |

§3.1 已写明「leader 接管任何『写』则审核必须新起子 agent」，与 §3.2 回退路径 ①②③ 自洽 ✓。

---

## 三、审核项 1 的关键纠错（必须以此为准）

1. **`pcpu_page_alloc` 的编译开关不是 `UMA_MD_SMALL_ALLOC`，而是 `FSTACK`，且结论可静态坐实**：
   - `freebsd/vm/uma_core.c:1957` `#ifndef FSTACK` → 逐 CPU 版（1958-…）；`:2082` `#else` → 回退版 `:2083-2089`；`:2114` `#endif`（中间 1966/1968、1979/1981/1990 的 `NUMA` 条件均已配平，核验方式：对该文件 `^#(if|ifdef|ifndef|else|elif|endif)` 全量列举后配对）。
   - `lib/Makefile:219` `CFLAGS+= -DFSTACK` → **必然编译 2083-2089 回退版**，无需预处理再猜。
   - `#undef UMA_MD_SMALL_ALLOC` 实际在 `lib/include/vm/uma_int.h:43`（plan 写 44），且它影响的是 `:2116`/`:2208` 的 `#if defined(UMA_USE_DMAP) && !defined(UMA_MD_SMALL_ALLOC)` 块，与 `pcpu_page_alloc` 选择**无关**。
2. **`UMA_PCPU_ALLOC_SIZE` 已定位**：`freebsd/sys/pcpu.h:221` `#define UMA_PCPU_ALLOC_SIZE PAGE_SIZE`；`freebsd/amd64/include/param.h:92-93` `PAGE_SHIFT 12` / `PAGE_SIZE (1<<PAGE_SHIFT)` → **4096**。
   展开链亦已坐实：`sys/pcpu.h:48` 先 `#include <machine/pcpu.h>`（即 f-stack 覆盖头，其 :40 `#undef zpcpu_offset_cpu`），故 `:234 #ifndef` 成立 → 最终 `zpcpu_offset_cpu(cpu) == 4096*cpu`（而非 `amd64/include/pcpu.h:270` 的 `&__pcpu[0]+...` 版）。附带约束：`freebsd/amd64/include/pcpu_aux.h:47` `_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE)`（由 `sys/pcpu.h:223` 引入）→ `struct pcpu` 必须恰好 4096 字节。
3. **`keg_layout` 的 `uk_size <= UMA_PCPU_ALLOC_SIZE` 是 `KASSERT` 的一部分**：`uma_core.c:2351-2356`，无 `INVARIANTS` 时整条编译掉 → 该「保护」在本build **不存在**。而`keg_layout` 内真正生效的 PCPU 逻辑是 `:2472-2478`：`pages = atop(kl.slabsize); if (UMA_ZONE_PCPU) pages *= mp_maxid + 1; keg->uk_ppera = pages;`。
4. **`critical_enter` 的真实作用域（G2 论证核心，plan 完全缺失）**：
   - `freebsd/sys/systm.h:179-193`：非 KLD分支的 inline `critical_enter()` 函数体被 `#ifndef FSTACK`(186) 整体排除 → **f-stack 下是空操作**；`critical_exit()` 同构（195-）。
   - 全树 `critical_enter` 的宏级覆盖仅 `lib/include/vm/uma_int.h:46/50`一处（`search_content` 全仓 `define\s+critical_enter`仅命中 uma_int.h 与 systm.h）。
   - include `vm/uma_int.h` 的 `.c` 共 11 个，其中在 `lib/Makefile` SRCS 内的只有 `freebsd/vm/uma_core.c`(:650) 与 `lib/ff_freebsd_init.c`；`kern_malloc.c`/`subr_vmem.c`/`vm_page.c`/`uma_dbg.c`/`memguard.c`/`kern_switch.c` 在 `lib/Makefile` 中**零命中**（未编译）。
   - 推论（对 G2 有利、须写入spec）：`uma_crit_lock` 实际只串行化 `uma_core.c` 的分配快路径；`smr_enter()`(smr.h:109) 的 `critical_enter()` 在 `in_pcb.c` 等 TU 里是**空操作** → SMR 读侧当前**毫无**抢占/并发保护，共享 `c_seq` 槽位是唯一实质风险，与 §0.1 的表述一致；同时说明「去掉 `uma_crit_lock` 后 UMA 只是回到与其它子系统相同的『空 critical section』语义」，等价性论证的落点应是「每线程独占 per-cpu 槽位」而非「关抢占」。
5. **counter(9) 结论强度**：`lib/include/amd64/include/counter.h` 已把 counter 完全去per-cpu 化（`counter_u64_add` 58-62 `*c += inc`；fetch 43-47 `*p`；zero 49-53 `*c=0`；`counter_enter/exit` 38-39 空操作），且 `freebsd/kern/subr_counter.c` 内 `mp_maxid|CPU_FOREACH|zpcpu` **零命中**，唯一 per-cpu 痕迹是 `:63 uma_zalloc_pcpu(pcpu_zone_8, ...)`。→ `mp_maxid` 提高后 counter 路径**不会越界**；真实影响是多线程写同一 slot（统计竞争/计数丢失）且 fetch 只读 slot 0。

---

## 四、必须修正项清单（10 条，含建议措辞）

> F1~F4 为事实/结论层（必须改），F5~F7 为事实补全，F8 为行号校正，F9~F10 为未知量与验收。

**F1（事实错误，必改）** §1.3 第 3 条。
建议替换为：
> - `freebsd/vm/uma_core.c:1957` `#ifndef FSTACK` → 逐 CPU `vm_page_alloc_noobj` 版 `pcpu_page_alloc`（`:1970 MPASS(bytes == (mp_maxid+1)*PAGE_SIZE)`、`:1975 for (cpu=0; cpu<=mp_maxid; cpu++)`）；`:2082 #else` → 回退版 `:2083-2089`（`return page_alloc(zone,bytes,domain,pflag,wait)`）。因 `lib/Makefile:219 CFLAGS+= -DFSTACK`，**本build 必然编译回退版（已静态坐实，非待验证）**。`lib/include/vm/uma_int.h:43 #undef UMA_MD_SMALL_ALLOC` 影响的是 `uma_core.c:2116`/`:2208` 的 `UMA_USE_DMAP && !UMA_MD_SMALL_ALLOC` 块，与本选择无关。

**F2（事实错误，必改）** §1.3 第 4 条「`UMA_PCPU_ALLOC_SIZE` 定义位置待定位」。
建议替换为：
> - `freebsd/sys/pcpu.h:221 #define UMA_PCPU_ALLOC_SIZE PAGE_SIZE`，`freebsd/amd64/include/param.h:92-93 PAGE_SHIFT 12 / PAGE_SIZE (1<<12)` → **4096**。因 `sys/pcpu.h:48` 先 include f-stack 覆盖的 `machine/pcpu.h`（其 `:40 #undef zpcpu_offset_cpu`），`sys/pcpu.h:234 #ifndef` 成立 → `zpcpu_offset_cpu(cpu) == 4096*cpu`（非 `freebsd/amd64/include/pcpu.h:270` 版）。另 `freebsd/amd64/include/pcpu_aux.h:47`（由 `sys/pcpu.h:223` 引入）`_Static_assert(sizeof(struct pcpu) == UMA_PCPU_ALLOC_SIZE)` 要求 `struct pcpu` 恰为 4096 字节。

同步把 **U1 降级**为确认性验证：
> U1（已静态坐实，`gcc -E`仅作交叉确认）：`zpcpu_offset_cpu(cpu) = 4096*cpu`，`UMA_PCPU_ALLOC_SIZE = PAGE_SIZE = 4096`。

**F3（措辞误导，必改）** §1.3 第 5 条「`keg_layout` 内有 … 判断」。
建议替换为：
> - `freebsd/vm/uma_core.c:2351-2356` 是 `KASSERT((uk_flags & UMA_ZONE_PCPU)==0 || (uk_size <= UMA_PCPU_ALLOC_SIZE && ...))`，**未定义 `INVARIANTS` 时整条编译掉，本build 无此运行期保护**。`keg_layout` 中真正生效的 PCPU 逻辑是 `:2472-2478`：`pages = atop(kl.slabsize); if (UMA_ZONE_PCPU) pages *= mp_maxid+1; keg->uk_ppera = pages;`。

**F4（G2 关键事实缺失，必补）** §1.4 增补一条（措辞见第三节第 4 点全文），至少须包含：`systm.h:179-193` 的 `#ifndef FSTACK` 空操作、`uma_crit_lock` 的实际覆盖面仅 `uma_core.c`（+`ff_freebsd_init.c`）、`smr_enter()` 不受该锁保护、以及由此得到的 G2 等价性论证落点。

**F5（时序硬约束，必补）** §1.3 增补，并配套新增 U10：
> - `freebsd/vm/uma_core.c:3179-3182`：zone 结构大小 `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + ...` 在 **uma_startup 期一次性算定**；`:2472-2478` keg 的 `uk_ppera`亦按 `mp_maxid+1` 放大；`:2873 zone_update_caches`、`:5589/:5620/:5674` 统计路径均按 `mp_maxid` 遍历 `uz_cpu[]`。→ **`mp_maxid` 必须在 `uma_startup1/2` 之前设定且此后不得再变**，否则 `uz_cpu[i>0]` 越界（堆溢出）。

**F6（结论强度，必改）** §1.4 最后一条 counter 相关，建议替换为：
> - `lib/include/amd64/include/counter.h:38-62` 把 counter(9) 完全去 per-cpu 化（`counter_u64_add` 为 `*c += inc`、`counter_u64_fetch_inline`(43-47) 为 `*p`、`counter_enter/exit` 空操作），`freebsd/kern/subr_counter.c` 内无任何 `mp_maxid`/`CPU_FOREACH` 遍历（仅 `:63 uma_zalloc_pcpu(pcpu_zone_8,...)`）。→ `mp_maxid` 提高后 counter **不会越界**；实际影响是多线程写同一 slot 造成统计竞争、fetch 仅读 slot 0，须在spec 中记录为已知偏差而非内存安全项。

**F7（事实补全，必补）** §1.1 表格增补两行：
> | `lib/ff_dpdk_if.c:2649` | `ff_stack_thread_init(rte_lcore_id());` —— **当前 cpuid 的实际来源就是 `rte_lcore_id()`**，G1 的稠密索引改造必须落在此调用点 |
> | `lib/ff_freebsd_init.c:294` | 主线程 `ff_pcpu_thread_init(0)` 之后紧跟 `CPU_SET(0, &all_cpus);` —— `all_cpus` 目前只含 CPU 0，`mp_maxid>0` 后须同步 |

**F8（行号校正，建议一次改齐）**
`ff_glue.c:143-147` → `138-146`；`uma_int.h:44`（`#undef UMA_MD_SMALL_ALLOC`）→ `:43`；`subr_smr.c:625-632`（`smr_init`）→ `:623-631`；`uma_core.c:3526`（`uma_zfree_pcpu_arg`）→ `:3521-3536`（`MPASS`在 3527）；`lib/include/amd64/include/pcpu.h:28-46` → `:33-42`（undef）+ `:47-53`（重定义）+ `:55-67`（`__curthread_ff`/`curthread` 重定义，plan 只写了undef 未写重定义）；`sys/pcpu.h:235-236` → `:234-236`；`:239-240` → `:237-239`，并补 `zpcpu_get_cpu` 实际在 `:254-257`；`subr_pcpu.c:88` 的 KASSERT 条件应写全 `cpuid >= 0 && cpuid < MAXCPU`。

**F9（未知量补全，必补）** 新增 U9~U15，全文见第五节。

**F10（验收标准，必改）**
- (a) **DoD-1 必须给出手段与判定式**，建议：
  > DoD-1：在 `ff_pcpu_thread_init()` 内（临时探针，M5 后按 §4.1 用 `/data/workspace/rm_tmp_file.sh` 清理或转为 `ff_log`）打印 `tid / dense_idx / pcpup->pc_cpuid / pcpup->pc_zpcpu_offset / mp_maxid`，并在 `smr_create()` 后打印各 worker `&zpcpu_get(ipi_smr)->c_seq`；判定式：① 各 worker `pc_zpcpu_offset == 4096 * dense_idx` 且 `dense_idx <= mp_maxid`；② 两两 `c_seq` 地址差`== 4096 * Δidx` 且全部落在 `[base, base + (mp_maxid+1)*4096)` 内；③ 日志从 `example/helloworld.log` 取证并落盘到 `_m17_E_runtime.md`。
- (b) **DoD-3** 增补 warning 基线锚点（当前仓库根已有未跟踪的 `_m17_build_base.log`、`_m17_base_clean.log` 可作基线）：「以 M1-C 记录的 clean build warning 条数为基线，改动后 `grep -c warning:` 不增加」。
- (c) **DoD-5** 增补阈值与失败处置：「去锁后吞吐不得低于去锁前（同机同客户端、≥3 轮取中位数，允许 ±2% 噪声）；若去锁后无提升，仍须给出代码级结论说明 G2 的正确性收益，并由 `reviewer` 门禁确认是否保留」。
- (d) **M7 门禁归属**收紧为：「门禁 = `gate-doc`（复核 commit 范围与 `git diff`）；leader 自身的 diff review仅作提交前自检，不计为门禁」；同理 M5 增补「若 leader 接管测试执行，则数据复核必须新起子 agent」。
- (e) **新增 DoD-8**：「仓库内临时产物（当前已存在：`lib/_m17_probe_u1.c`、根目录 `_m17_base_clean.log`/`_m17_build_base.log`/`_m17_srcpaths.txt`/`_m17_srcset.txt`/`_m17_uma_core.i`/`a.log`、`example/*.log` 等）在 M7 前一律通过 `/data/workspace/rm_tmp_file.sh` 清理或确认不入库；`config.ini` 当前处于修改态（`git status` 显示 `M config.ini`），提交前必须逐项 review并回滚本地测试值」。

---

## 五、建议新增未知量清单（U9~U15）

| # | 未知量 | 代码依据（已实际核验） | 优先级 |
|---|---|---|---|
| **U9** | `MAXCPU` 尺寸数组的**跨编译单元一致性**：候选 B 用覆盖头改写 `MAXCPU` 时，是否所有 TU 都见到同一个值？任何一个 TU 漏改即产生新的越界源 | `freebsd/kern/subr_pcpu.c:76-77` `uintptr_t dpcpu_off[MAXCPU]; struct pcpu *cpuid_to_pcpu[MAXCPU];`；`lib/ff_kern_synch.c:59` `static uint8_t pause_wchan[MAXCPU];`（`:105` 以 `curcpu` 索引）；`lib/ff_glue.c:142` `int mp_maxcpus = MAXCPU;`；`lib/ff_kern_timeout.c:730` `cpu >= MAXCPU` panic 判断；`freebsd/amd64/include/param.h:60-66` 非 SMP 分支为**无条件** `#define MAXCPU 1`（覆盖需先 `#undef`） | **高** |
| **U10** | `mp_maxid` 的**设置时序**：必须早于 `uma_startup1/2`（所有 zone 的 `uz_cpu[]` 尺寸在此定型），且此后不可变更；须确认 f-stack 启动序列中 `mp_maxid` 赋值点与 `uma_startup*`/`smr_init`/各 `uma_zcreate` 的先后 | `uma_core.c:3179-3182`（`zsize` 含 `sizeof(struct uma_cache)*(mp_maxid+1)`）、`:2472-2478`（`uk_ppera *= mp_maxid+1`）、`:2873zone_update_caches`、`:5589/:5620/:5674` 统计遍历；`subr_smr.c:598` 循环 | **高** |
| **U11** | callout 的 cpuid 语义在稠密索引下失真：`timeout_cpu` 是**非 `__thread` 全局**却被每个线程写；`CC_CPU/CC_SELF` 忽略 cpu 参数；`cpu >= MAXCPU` 判断会 panic | `lib/ff_kern_timeout.c:183-185`（`__thread struct callout_cpu cc_cpu; #define CC_CPU(cpu) &cc_cpu`，注释明写 "cpuid is always 0, MAXCPU=1"）、`:190 static int timeout_cpu;`、`:254 timeout_cpu = PCPU_GET(cpuid);`、`:662/:1181CC_CPU(timeout_cpu)`、`:1061/:1077 c->c_cpu = timeout_cpu;`、`:730-733 panic("Invalid CPU in callout %d")` | **高** |
| **U12** | 稠密 pcpu id 与 `rte_lcore_id()` 形成**两个索引空间**，须逐点确认无混用；DPDK 侧 `rte_mempool` per-lcore cache 仍按 `rte_lcore_id`，与 UMA per-cpu 槽位互不相关（须在 spec 中写清边界，避免把 mbuf 池误当UMA 问题） | `lib/ff_dpdk_if.c:2649`（cpuid 来源）、`:2745/:2841 veth_ctx[rte_lcore_id()][port_id]`、`:582-583 rte_pktmbuf_pool_create(..., MEMPOOL_CACHE_SIZE, ...)`、`:536/:600 nb_lcores*MEMPOOL_CACHE_SIZE`；同时 `lib/Makefile:346,372-373` 表明 `kern_mbuf.c`/`uipc_mbuf.c` **仍被编译**（UMA mbuf zone 与 DPDK 池并存，U8 的跨线程 free 风险确实存在） | 中 |
| **U13** | **无 `pcpup` 的线程**是否可能进入 UMA/SMR 快路径：`ff_pthread_create` 只继承 `pcurthread`，不做 `ff_pcpu_thread_init` → 该类线程 `pcpup == NULL`；G2 去锁后须先穷尽「哪些线程持有合法 pcpup」 | `lib/ff_thread.c:20-30`（`ff_start_routine` 仅 `ff_set_thread(p_data->parent)`）、`:33-46ff_pthread_create`；`lib/ff_freebsd_init.c:177-187`（只有走 `ff_stack_thread_init` 的线程才建 pcpu）。KNI / `ff_veth` / DPDK service 线程的线程模型**未核实**，须M1-A 补| 中 |
| **U14** | `mp_ncpus` 的其它读者（plan U4 清单遗漏） | `lib/ff_ng_base.c:3249 numthreads = mp_ncpus;`（netgraph）、`lib/ff_kern_timeout.c:1212-1216`（仅打印） | 中 |
| **U15** | DPCPU 路径可判定为低风险但须一句话结论，避免 M1 反复：`dpcpu_init()` 仅在 `freebsd/kern/subr_pcpu.c:100` 定义，`lib/` 与 `freebsd/kern/` 内**无调用者**（其余目录未穷尽核验）；但 `pcpu_destroy():276` 仍写 `dpcpu_off[pc_cpuid]`，故仍受 U9 的 `MAXCPU` 一致性约束 | `subr_pcpu.c:76,100,276`；`lib/*.c` 中 `dpcpu_init|DPCPU_` 零命中 | 低 |

关于 leader 点名的四项候选遗漏，逐一回应：
1. `cpuset_t`/`CPU_SETSIZE` ABI —— **plan 已覆盖**（U4 括注），无需新增；建议仅补一句依据（`lib/ff_freebsd_init.c:294 CPU_SET(0,&all_cpus)`、`lib/ff_glue.c:138`）。
2. `dpcpu` 路径 —— 已核实为低风险，见 **U15**（给结论而非留空）。
3. `ff_veth`/KNI/callout 线程是否走 UMA 快路径 —— callout 已坐实为**确定性问题**（**U11**）；`ff_veth`/KNI 线程模型**未核实**，归入 **U13**。
4. DPDK `rte_mempool` 与 UMA 的关系 —— 归入 **U12**（并已坐实 UMA mbuf zone 与 DPDK 池并存）。

---

## 六、未核实事项（诚实边界）

- `mk/` 目录与 `example/Makefile` 是否在别处注入 `-DSMP`/`-DINVARIANTS`：本次仅核验 `lib/Makefile` 与 `lib/opt/`，**未穷尽**（plan §1.2 已把它列为 M1-C 任务，保留即可）。
- `dpcpu_init()` 在 `freebsd/` 其它子目录（如 `amd64/`、`net*/`）是否有调用者：**未穷尽核验**（仅核`lib/` 与 `freebsd/kern/`）。
- KNI（`lib/ff_dpdk_kni.c`，`FF_KNI=1` 于 `lib/Makefile:36,90-91` 已开启）与 `ff_veth` 的线程归属、是否触达 UMA 快路径：**未核实**。
- `§5.1` 性能基线：已与 `16-多队列对照实验与根因纠偏.md:79-95` 交叉核对，E4/E5-a/E5-c 与 soak（497k req/s、29,834,366 请求/1.00m）**一致** ✓；`thread_mode=0` 1 进程 `209,946/209,367`（E5-b）未在本次 grep 命中行内，**未逐字核实**。
- 运行期行为（DoD-1/U2 的实际分配尺寸、去锁前后吞吐）：本门禁为静态审核，**未做任何运行时验证**。

---

审核完成时间：2026-08-04。本报告仅陈述已核实事实与必须修正项，plan.md 的修改由 leader 执行（写/审分离）。

---

## 七、复审（bounce=1）

复审范围：仅核验 F1~F10 是否正确落实 + 是否新引入事实错误（按 leader 指示不重跑全量 file:line）。
复审方式：重新完整读取修订后的 `plan-17-SMP-aware-pcpu-smr.md`，与本报告第三/四/五节的已核实事实逐字比对；对 leader 新写入的行号（`uma_core.c:2114`、`ff_kern_timeout.c:662/:1181`、`lib/Makefile:650`、`ff_dpdk_if.c:582-583`、`counter.h:58-62`、`uma_int.h:54-57/59/65/67-74`）再次与首轮核验留存的原始 grep/read 结果对齐。

### 7.1 结论

**PASS**

F1~F10 **全部正确落实（10/10）**，措辞与我给出的建议一致或更精确，**未发现任何新引入的事实错误、未发现夸大实证边界的表述**。
遗留 1 项中等溯源缺口（R1）+ 3 项 nit（R2~R4），**均不构成打回**；R1 建议在 spawn M1 子 agent 前用一行补齐。

### 7.2 F1~F10 落实核验表

| 项 | 落点 | 核验结果 |
|---|---|---|
| **F1** | §1.3 第 3 条（`:68`） | ✓ 正确。`uma_core.c:1957 #ifndef FSTACK` / `:1970 MPASS` / `:1975` 循环 / `:2082 #else` / `:2083-2089` 回退版 / `:2114 #endif` / `lib/Makefile:219 -DFSTACK` 全部与实测一致；「已静态坐实，非待验证」措辞准确；`uma_int.h:43 #undef UMA_MD_SMALL_ALLOC` 已更正且明确「与本选择无关」并正确指向 `:2116`/`:2208` 的 `UMA_USE_DMAP && !UMA_MD_SMALL_ALLOC` 块 |
| **F2** | §1.3 第 4 条（`:69`）+ U1（`:97`） | ✓ 正确。`sys/pcpu.h:221` / `param.h:92-93` / `4096` / `sys/pcpu.h:48` 先 include 覆盖头 / 覆盖头 `:40#undef` / `sys/pcpu.h:234 #ifndef` 成立 / 排除 `amd64/include/pcpu.h:270` 版 —— 展开链完整无误；U1 已降级为「已静态坐实，`gcc -E` 仅作交叉确认」 |
| **F3** | §1.3 第 5 条（`:70`） | ✓ 正确。已明确 `:2351-2356` 是 `KASSERT` 且「无 INVARIANTS 时整条编译掉，本 build 无此运行期保护」；已补真正生效逻辑 `:2472-2478 pages *= mp_maxid+1; uk_ppera = pages` |
| **F4** | §1.4 新增条（`:86-87`） | ✓ 正确且完整。`systm.h:179-193` + `:186 #ifndef FSTACK` 空操作 ✓；宏级覆盖仅 `uma_int.h:46/50` ✓；SRCS 内 include `vm/uma_int.h` 的 TU 只有 `uma_core.c`(`lib/Makefile:650`)与 `ff_freebsd_init.c`、并点名`kern_malloc.c/subr_vmem.c/vm_page.c/uma_dbg.c/memguard.c/kern_switch.c` 未编译 ✓；`smr_enter()`(smr.h:109) 不受该锁保护、「SMR 读侧当前毫无抢占/并发保护」✓；G2 等价性论证落点已改为「每线程独占 per-cpu 槽位」而非「关抢占」✓。另§1.3 `:74` 也同步加了交叉引用（`smr.h:105-143`、`:110`），前后自洽 |
| **F5** | §1.3 新增条（`:71`）+ U10（`:106`） | ✓ 正确。`uma_core.c:3179-3182` zsize 定型 / `:2472-2478` / `:2873 zone_update_caches` / `:5589/:5620/:5674` 统计遍历 / 「必须在 `uma_startup1/2` 之前设定且此后不得再变，否则 `uz_cpu[i>0]` 越界（堆溢出）」—— 与实测逐项吻合；U10 已落为「高」优先级 |
| **F6** | §1.4 末条（`:89`） | ✓ 正确。`counter.h:38-62`（`counter_u64_add:58-62`、`counter_u64_fetch_inline:43-47`、`counter_enter/exit:38-39`）+ `subr_counter.c` 无 `mp_maxid`/`CPU_FOREACH`/`zpcpu` 遍历、仅 `:63 uma_zalloc_pcpu(pcpu_zone_8,...)`；结论已改为「不会越界；实际是统计竞争 + fetch 仅读 slot 0 的**已知偏差**，非内存安全项」——强度准确 |
| **F7** | §1.1 新增 3 行（`:54-56`） | ✓ 正确。`ff_dpdk_if.c:2649 ff_stack_thread_init(rte_lcore_id())` 并点明「G1 改造必须落在此调用点」✓；`ff_freebsd_init.c:294 CPU_SET(0,&all_cpus)` ✓；`pcpu_aux.h:47`（经 `sys/pcpu.h:223` 引入）`_Static_assert(sizeof(struct pcpu)==UMA_PCPU_ALLOC_SIZE)`「必须恰为 4096 字节」✓ |
| **F8** | §1.1/§1.2/§1.3 多处 | ✓ 基本全落实（1 处漏改，见 R2）。已校正：`ff_glue.c:138-146` 且逐变量标注行号 ✓；`pcpu.h:33-42`(undef，标注10 项)/`:47-53`/`:55-67` ✓；`sys/pcpu.h:234-236`、`:237-239,249-252,254-257` ✓；`subr_pcpu.c:88-89` KASSERT 条件写全 `cpuid >= 0 && cpuid < MAXCPU` ✓、`:252,270-277,282-287` 且细标 `:274/:275/:276` ✓；`subr_smr.c:583-609`(细标 `:591`/`:598-605`)、`:623-631` ✓；`smr.h:105-143`(`:110`) ✓；`uma_int.h` 细标 `:43/:54-57/:59/:65/:67-74` ✓ |
| **F9** | 第 2 节 U9~U15（`:105-111`） | ✓ 正确且完整。7 项全部写入并带优先级（U9/U10/U11 高，U12/U13/U14 中，U15 低）；所有代码依据逐条复核无误：`subr_pcpu.c:76-77`、`ff_kern_synch.c:59`+`:105`、`ff_glue.c:142`、`ff_kern_timeout.c:730`（U9）；`ff_kern_timeout.c:183-185/:190/:254/:662/:1181/:1061/:1077/:730-733` 且保留「非 `__thread` 全局却被每线程写」这一关键定性（U11）；`ff_dpdk_if.c:2649/:2745/:2841/:582-583`+`lib/Makefile:346,372-373`（U12）；`ff_thread.c:20-30/33-46`+`lib/Makefile:36,90-91`（U13）；`ff_ng_base.c:3249`+`ff_kern_timeout.c:1212-1216`（U14）；`subr_pcpu.c:100/:276`（U15）。U2 亦已同步降级并正确引用 `keg_layout:2472-2478` |
| **F10** | §6 + §3 表 | ✓ 全部落实。(a) DoD-1 已给探针位置、5 个打印字段、3 条判定式（含 `pc_zpcpu_offset == 4096*dense_idx`、`c_seq` 地址差 `== 4096*Δidx`、落在 `[base, base+(mp_maxid+1)*4096)`）、取证路径与探针退出方式 ✓；(b) DoD-3 已加 warning 基线（措辞见 R3）✓；(c) DoD-5 已加「不得低于去锁前、≥3 轮中位数、±2% 噪声」+ 无提升时的处置✓；(d) M5 门禁已收紧为 `reviewer`（去掉 leader 汇总）并补「leader 接管测试则数据复核新起子 agent」、M7 门禁已明确为 `gate-doc`、leader 自审仅作提交前自检 ✓；(e) 新增 DoD-8 临时产物清理（`lib/_m17_probe_u1.c`、根目录 `_m17_*` 等），DoD-7 已补 `M config.ini` 提交前回滚 ✓ |

### 7.3 新引入错误核查

逐条比对修订新增/改写的全部行号与定性表述，**未发现新引入的事实错误**：
- 所有新增行号（`uma_core.c:2114`、`lib/Makefile:650`、`ff_kern_timeout.c:662/:1181`、`ff_dpdk_if.c:582-583`、`counter.h:58-62`、`uma_int.h:54-57/59/65/67-74`）均与首轮核验留存结果一致。
- 未出现「已实测/已验证」冒领：F1/F2 的「已静态坐实」限定为**静态**（预处理级）结论，U2 保留的运行期部分未被误标为已坐实，措辞未越边界。
- §0.3 候选 B 的「在 UMA/SMR 初始化前设 `mp_ncpus`/`mp_maxid`」现与 §1.3 `:71` + U10 形成证据闭环，无冲突。
- 门禁表改动未破坏写/审异构：M0~M7 复核后仍**全部异构、无自写自审**。

### 7.4 遗留项（不打回）

| # | 级别 | 内容 | 建议措辞 |
|---|---|---|---|
| **R1** | 中（建议 M1 spawn 前补） | **新增 U9~U15 未接入里程碑承担者**：§3 表 M1 行仍写「A 代码路径穷尽探测（U1/U2/U4/U5/U6/U7/U8 + `git show b90ddcba5`）」，U9~U15 无人承担，M1 交付易漏项（leader 已在消息中口头分派U3→`res-build`、U13/U15→`res-code`，但 plan 正文未体现） | M1-A 改为「U1/U2/U4~U8 + U9~U15（U3 归 C）」，并在交付物要求中加一句「`_m17_A_codepath.md` 须对 U1~U15 逐项回填，缺项即门禁不通过」 |
| **R2** | nit（±5 容差内） | §1.3 `:67`仍写 `:3526 uma_zfree_pcpu_arg`，F8 建议的 `:3521-3536`（`MPASS` 在 `:3527`）未落| 改为「`:3521-3536` `uma_zfree_pcpu_arg` 同构（`MPASS` 在 `:3527`）」 |
| **R3** | nit | DoD-3 把 warning 基线锚在「M1-C 记录的 clean build」，但 M1-C 是**双候选路线编译实证**（含 `-DSMP` 实验），其 warning 数不宜作基线 | 改为「基线 = 未改动 HEAD `ff09a17b2` 的 `lib/`+`example/` clean build warning 条数（M1-C 须单独记录该基线，与候选路线实验产生的 warning 分开登记）」 |
| **R4** | nit | §0.2 G2 描述「把 UMA 所有 `critical_enter/exit` 替换成单一全局自旋锁」与 §1.4 精确作用域并列时略易误读为全树 | 句末加「（实际作用域仅 include `vm/uma_int.h` 的编译单元，详见 §1.4）」 |

### 7.5 复审边界

- 本次复审**未**重跑全量 file:line 核验（按 leader 指示），首轮已核实的 22 条事实沿用首轮结论。
- 第六节列出的 3 项未核实事项（`mk/` 的 `-DSMP` 注入、`dpcpu_init` 其它目录调用者、KNI/`ff_veth` 线程归属）已由 leader 转交 `res-build`(U3)与 `res-code`(U13/U15)，本agent 不再跟进。
- 仍**未做任何运行时验证**；DoD-1/DoD-5 的可行性为静态判断（探针手段与判定式在代码层可实现），实际数据须 M5 由 `tester` 产出。

复审完成时间：2026-08-04（bounce=1/3，本轮不再打回）。

---

## 八、候选 A 语义风险独立核验（M1-C 后置审核，为 M2 裁决提供依据）

核验人：`gate-plan`（独立核验，未参考 `res-build` 的推理过程，仅在结论处与其报告对照）
方式：实际打开 `lib/ff_lock.c`、`lib/include/sys/mutex.h`、`freebsd/sys/mutex.h`、`lib/Makefile`、`lib/ff_glue.c`、`freebsd/contrib/ck/include/{ck_md.h,ck_pr.h,ck_queue.h,gcc/x86_64/ck_pr.h}`、`freebsd/net/if.c`、`freebsd/netpfil/ipfw/ip_fw_dynamic.c`、`freebsd/sys/{pcpu.h,smp.h,ck.h}`、`lib/ff_subr_epoch.c` 逐点核对。
`lib/include/sys/_mutex.h`：**不存在**（`lib/include/sys/` 下只有 `mutex.h`，已用文件搜索确认），故该文件的核验请求自动落空，不影响结论。

### 8.1 结论摘要

| 风险 | 结论 |
|---|---|
|风险 1（`-DSMP` 切换 spin 锁展开） | **不成立 —— 候选 A 不引入任何新的 spin 锁语义变化**（代码级坐实）。但坐实了一个既有前提事实：f-stack 下**所有** spin mutex 与 `thread_lock` 本来就是空操作 |
| 风险 2（`CK_MD_UMP` 失效 →恢复 `lock` 前缀） | **部分成立**：唯一受实质影响的编译单元是 `ip_fw_dynamic.c`（RMW 操作缺 `lock` 前缀）。`-DSMP` 属「消除潜在缺陷」的正确性收益，但**不得宣称修复了已复现 bug**；`CK_LIST`/`CK_SLIST`/`CK_STAILQ`/`net/if.c`/`ck_epoch` 均**不受影响** |
| **新发现（比上述两条更严重）** | `ip_fw_dynamic.c` 的 DPCPU + `CPU_FOREACH` 与 **G1 直接冲突**，存在**堆溢出**路径；须修正 U14/U15 定级，并把「`mp_ncpus`/`mp_maxid`/`all_cpus` 三元组必须同步」写入设计约束 |
| **流程发现** | M1-C 的探针改动（`-DSMP` + `smp_topo` stub）**当前仍在工作区生效**，影响 plan §1.2 事实时效性、DoD-3 基线口径与写/审分离，须在 M2 处置 |

### 8.2 风险 1：`-DSMP` 的 spin 锁展开切换 —— 已证伪（不引入新风险）

已核实事实：

1. `freebsd/sys/mutex.h` 的 `#ifdef SMP` 站点确实存在且如 res-build 所述：
   - `:110-117`：`#ifdef SMP` 内**仅**声明 `_mtx_lock_spin_cookie()` 原型（无定义、无调用）。
   - `:185-193`：`#ifdef SMP` → `#define _mtx_lock_spin(m,v,o,f,l) _mtx_lock_spin_cookie(&(m)->mtx_lock, v)`。
   - `:254-307`：`#ifdef SMP` → `__mtx_lock_spin` = `spinlock_enter()` + `_mtx_obtain_lock_fetch()` + 失败转 `_mtx_lock_spin()`；`#else`(:280) → `spinlock_enter()` + 内联递归计数。两分支**都**含 `spinlock_enter()`。
2. **但 f-stack 的覆盖头在 `#include_next` 之后把这些宏全部抹掉**：`lib/include/sys/mutex.h:29` `#include_next <sys/mutex.h>` → `:31-34` `#undef __mtx_lock/__mtx_unlock/__mtx_lock_spin/__mtx_unlock_spin`、`:36-39` `#undef _mtx_lock_spin_flags/_mtx_unlock_spin_flags`、`:41-44` `#undef thread_lock*/thread_unlock`、`:46-48` `#undef mtx_trylock_flags_/_mtx_trylock_spin_flags/__mtx_trylock_spin`；随后 `:59-62` 重定义为 `DO_NOTHING`(`:57 ((void)0)`)、`:69-72` `thread_lock*/thread_unlock` → `DO_NOTHING`、`:74-76` trylock 系 → 常量 `1`。
   → **无论是否定义 `SMP`，`spinlock_enter()`/`_mtx_lock_spin_cookie()` 都没有任何调用点**；`:185`/`:254` 的分支差异被完全旁路，`:110` 只是一个不会被引用的原型。
3. 交叉验证（链接侧）：全仓 `spinlock_enter|spinlock_exit` 的**定义**只出现在 `freebsd/{arm,arm64}/*/machdep.c` 等**未编译**文件；`lib/` 内**无任何定义**（仅预处理产物 `.i` 里有原型）。所有调用 `spinlock_enter()` 的 `.c`（`subr_smp.c`、`kern_mutex.c`、`kern_synch.c`、`kern_timeout.c`、`kern_time.c`、`kern_clocksource.c`、`sched_4bsd.c`、`sched_ule.c`、`kern_shutdown.c`、`x86/isa/atpic.c`、各 `machdep.c`）在 `lib/Makefile` 中**全部不在 SRCS**（f-stack 用 `ff_kern_synch.c`(:279)/`ff_kern_timeout.c`(:280) 替代）。若真有调用点，基线 build 早就链接失败。
4. `lib/ff_lock.c` 全文（449 行）已通读：**未定义** `spinlock_enter/exit`，也未定义 `_mtx_lock_spin_cookie`；它提供的是 `lock_class_*`、`ff_mtx_init`、`Giant`、以及把 `_rm_*`/`_sx_*` 全部 stub 成空操作/常量返回（`:251-279`、`:325-360`）。`lock_class_mtx_spin`(:402-408) 的 `lc_lock/lc_unlock` 甚至是 `printf("...called!")`（`:386-397`，注释 `XXX should never be used`）。

结论：**风险 1 证伪。候选 A 在 spin 锁层面是语义中性的**（这也解释了 res-build 观测到的「零新增缺失符号（除 `smp_topo`）」）。

顺带坐实两条对 G1/U11 有价值的既有事实（建议写入 spec，非候选 A 引入）：
- **f-stack 下所有 spin mutex 都是空操作** → `lib/ff_kern_timeout.c:186-188` 的 `CC_LOCK/CC_UNLOCK`(`mtx_lock_spin`) 实为无锁，callout 的线程隔离**完全依赖** `__thread struct callout_cpu cc_cpu`(:183)，与 U11 的判断一致且更强。
- `thread_lock/thread_unlock` 亦为空操作 → 任何依赖 `td_lock` 串行化的上游假设在 f-stack 均不成立。

### 8.3 风险 2：`CK_MD_UMP` 与 `lock` 前缀 —— 部分成立，仅 `ip_fw_dynamic.c` 受实质影响

1. `CK_MD_UMP` 的**唯一**效果已坐实：`freebsd/contrib/ck/include/gcc/x86_64/ck_pr.h:54-58` `#ifdef CK_MD_UMP → #define CK_PR_LOCK_PREFIX`（空）/`#else → "lock "`。受其影响的全是 **RMW** 原语：`cmpxchg16b`(:208/:501/:527)、`ck_pr_faa_*`(:293)、`ck_pr_inc/dec_*`(:327/:339)、`ck_pr_add/sub/and/or/xor_*`(:381)、`ck_pr_cas_*`(:419/:433/:448/:461)、`ck_pr_bt*`(:587)。
2. **`CK_MD_UMP` 不影响内存屏障**：通用 `ck_pr.h` 内`CK_MD_UMP` **零命中**；屏障由 `:142-164` 的 `#elif defined(CK_MD_TSO)` 分支决定（多数 `CK_PR_FENCE_NOOP`），而 `ck_md.h:113/:116` 已定 `CK_MD_TSO`。x86_64 侧 `CK_PR_FENCE(T,I)`(:71-76) 只生成 `ck_pr_fence_strict_##T`。→ 与 UMP 无关。
3. 编译进来的 CK 使用者盘点（全部实测）：
   - `freebsd/contrib/ck/src/*.c`（`ck_epoch.c`/`ck_ht.c`/`ck_hs.c`/`ck_rhs.c`/`ck_array.c`/`ck_hp.c`/`ck_ec.c`/`ck_barrier_*.c`）**均未编译**：`lib/Makefile` 只在 `:14` 引用 `contrib/ck/include` 头路径，SRCS 无任何 `ck_*.c`。
   - `ck_epoch` 已被整体 stub：`lib/ff_glue.c:1366-1404` 把 `ck_epoch_synchronize_wait`/`ck_epoch_poll_deferred`/`_ck_epoch_addref`/`_ck_epoch_delref`/`ck_epoch_register`/`ck_epoch_init` 实现为空操作/恒真；`lib/ff_subr_epoch.c`(lib/Makefile:281) 内 `ck_epoch|ck_pr_|ck_stack` **零命中**；`ck_epoch.h` 内 `ck_pr_` **零命中**。→ epoch 路径与 UMP 无关。
   - `ck_queue.h`（`freebsd/sys/ck.h:6-8` 在 `_KERNEL` 下引入）的 34 处 CK 原语使用**全部**是 `ck_pr_load_ptr`/`ck_pr_store_ptr`/`ck_pr_fence_store`（`:143-435`），**无一处 RMW**。→ `CK_LIST/CK_SLIST/CK_STAILQ`（`in_pcb.c` 等大量使用，`lib/Makefile:501` 已编译）在 x86_64 上**不受 UMP 影响**。
   - `freebsd/net/if.c`（`lib/Makefile:419` 已编译）5 处 CK 使用（`:373,:404` `ck_pr_load_ptr`、`:592,:602,:678` `ck_pr_store_ptr`）**全是load/store**。→ 不受影响。
   - **`freebsd/netpfil/ipfw/ip_fw_dynamic.c`（`lib/Makefile:604` 已编译，`FF_IPFW=1` 见 `:44`/`:115`）是唯一实质受影响者**，且用的正是 RMW：`ck_pr_dec_32`(:155,:376)、`ck_pr_inc_32`(:157,:290,:378)、`ck_pr_xor_32`(:982)、`ck_pr_or_32`(:984,:1001)。
4. 「当前是否本来就是 bug」的**准确**回答（避免越界）：
   - 就机器语义而言，**是**：非 SMP build 下这些 `inc/dec/or/xor` 编译为**无 `lock` 前缀**的 RMW，多线程并发同一地址时会丢更新/丢状态位。
   - 但就f-stack native-mt 的**实际共享面**而言：`V_dyn_*`、`DPARENT`、`dyn_data` 多为 **per-VNET** 数据，而 CM5-B 让每 worker 持有独立 `vnet_i`，故这些计数/状态位在当前设计下**大多不跨线程共享**，未必能复现。
   - 故 spec 中应表述为：**候选 A恢复 `lock` 前缀属于「消除潜在原子性缺陷」的正确性收益（成本为零、方向正确），但不能声称修复了某个已复现的 bug**；同时须记录「若未来放弃 per-worker vnet 隔离或引入共享 vnet 的 ipfw 使用，该缺陷会立即变成真实 bug」。

### 8.4 新发现（高价值）：ipfw 的 DPCPU + `CPU_FOREACH` 与 G1 直接冲突

这条比 8.2/8.3 都严重，且**现有 U1~U15 均未覆盖**：

1. **DPCPU 确实被编译单元使用**：`ip_fw_dynamic.c:224 DPCPU_DEFINE_STATIC(void *, dyn_hp)`、`:225 DYNSTATE_GET(cpu) = ck_pr_load_ptr(DPCPU_ID_PTR((cpu), dyn_hp))`、`:226 DYNSTATE_PROTECT(v) = ck_pr_store_ptr(DPCPU_PTR(dyn_hp), (v))`。
   → 我首轮给出的 U15 判断需**分拆修正**：「`dpcpu_init()` 无调用者」**仍成立**；但「DPCPU 路径低风险」**不成立**，须把 U15 从「低」提为「中」。
2. **因 `dpcpu_init()` 从未被调用，所有 cpu 的 DPCPU 槽位互相别名**：`freebsd/sys/pcpu.h:113-114 _DPCPU_PTR(b,n) = (typeof)*((b) + (uintptr_t)&DPCPU_NAME(n))`、`:121 DPCPU_PTR(n) = _DPCPU_PTR(PCPU_GET(dynamic), n)`、`:128 DPCPU_ID_PTR(i,n) = _DPCPU_PTR(dpcpu_off[(i)], n)`。而 `pc_dynamic` 由 `pcpu_init()` 的 `bzero` 置0 且无人再设，`dpcpu_off[]` 恒为 0 → **所有线程、所有 cpu id 都指向同一份 `&DPCPU_NAME(dyn_hp)` 主副本**。
   → ipfw 动态状态的 hazard-pointer 机制在多线程下**已经失效**（所有 worker 共用一个 HP 槽位），且 `-DSMP` **修不了**这一条。叠加 `:228 DYNSTATE_CRITICAL_ENTER() = critical_enter()` 在该TU 中是空操作（§1.4/F4 已坐实），HP 读侧毫无保护。
3. **G1 的具体堆溢出路径（必须写入 spec 的设计约束）**：
   - `ip_fw_dynamic.c:3236` `dyn_hp_cache = malloc(mp_ncpus * sizeof(void *), M_IPFW, M_WAITOK|M_ZERO)` —— 尺寸按 **`mp_ncpus`**（f-stack恒为 1，`lib/ff_glue.c:140`，且**无人按线程数提高**：我首轮核实其读者仅 `ff_ng_base.c:3249`、`ff_kern_timeout.c:1212-1216`）。
   - `:2086-2091` `cached_count = 0; CPU_FOREACH(i) { dyn_hp_cache[cached_count] = DYNSTATE_GET(i); if (... != NULL) cached_count++; }` —— 循环上界按 **`mp_maxid` + `all_cpus`**（`freebsd/sys/smp.h:197-199 CPU_FOREACH(i) = for (i=0;i<=mp_maxid;i++) if (!CPU_ABSENT(i))`、`:187 CPU_ABSENT(x) = !CPU_ISSET(x,&all_cpus)`）。
   - → 若 G1 提高 `mp_maxid` 并为 N 个 worker `CPU_SET` 到 `all_cpus`，却**不同步提高 `mp_ncpus`**，则该循环会连续写 `dyn_hp_cache[0..N-1]` 到只有 **1** 个槽位的缓冲区 → **堆溢出**。
   - 触发条件（诚实边界，三者同时满足）：① `all_cpus` 中 ≥ 2 个 cpu；② 该时刻共享 `dyn_hp` 槽位非 NULL（即 ipfw 动态规则被实际使用、有 reader 置过 HP）；③ `mp_ncpus` 未同步提高。若 ipfw 动态规则未被使用，`DYNSTATE_GET` 恒为 NULL、`cached_count` 恒为 0，则只写 index 0，不触发。
4. **由此得出的设计约束（建议 M2 spec 列为 D-约束，并回填 U14）**：`mp_ncpus`、`mp_maxid`、`all_cpus` **必须作为三元组同步设置**（且按 U10 全部早于 `uma_startup1/2`）；任何只改其中一两个的方案都会引入新的越界/漏遍历。这同时是候选 A 与候选 B 的**共同**约束。

### 8.5 对 `_m17_C_buildprobe.md` 的措辞纠正（2 处）

| 位置 | 原文问题 | 建议改法 |
|---|---|---|
| `_m17_C_buildprobe.md:169` | 「其依赖已被 f-stack 提前 stub（`spinlock_enter`/`_mtx_lock_spin_cookie` 等由 `lib/ff_lock.c`、`lib/include/sys/mutex.h` 覆盖）」——**归因不准**：`lib/ff_lock.c` 全文未定义这两个符号，`lib/` 内根本没有 `spinlock_enter` 定义| 改为「其**调用点**已被 `lib/include/sys/mutex.h:31-76` 在 `#include_next` 之后 `#undef` + 重定义为 `DO_NOTHING` 全部消除，且所有调用 `spinlock_enter()` 的 `.c` 均不在 `lib/Makefile` SRCS，故两分支都不会产生对这些符号的引用」 |
| `_m17_C_buildprobe.md:172` | 「属**运行时语义变更**，需 `res-code` 核验」——结论应更新 | 改为「经`gate-plan` 独立核验**证伪**：因 f-stack 覆盖头已抹除全部 spin 锁宏，`-DSMP` 在 spin 锁层面**语义中性**（详见 `_m17_gate_plan.md` §8.2）」 |

### 8.6 流程发现：M1-C 探针改动仍在工作区生效（须在 M2 处置）

已核实**当前工作区**状态（非 HEAD）：
- `lib/Makefile:221-222`：`# _M17_PROBE_A: temporary build probe, to be reverted` + `CFLAGS+= -DSMP`（**生效中**）。
- `lib/ff_glue.c:162-169`：`/* _M17_PROBE_A: temporary build probe, to be reverted */` + `#ifdef SMP struct cpu_group *smp_topo(void) { return (NULL); } #endif`（**生效中**）。

影响与处置建议（3 条）：
1. **事实时效性**：plan §1.2「`lib/Makefile` 未定义 `-DSMP`」现仅对 HEAD `ff09a17b2` 成立，对工作区已不成立。M2 spec 引用该事实时必须加「（HEAD `ff09a17b2`；M1-C 探针期工作区临时加过 `-DSMP`）」限定，否则 `gate-design`/`gate-doc` 复核会判为事实错误。
2. **DoD-3 基线口径**：51 条 warning 基线必须明确为「**未带探针补丁**的 HEAD clean build」；若该数字是在 `-DSMP` 生效期间测得，则须重测。建议 plan 在 DoD-3 补一句测量前置条件。
3. **写/审分离**：这两处是 `res-build`（调研角色）写入`lib/` 的代码。若 M2 裁决候选 A，**不得**让探针代码直接沉淀为产品代码，须由 M3 的 `coder` 正式重写（`smp_topo` 返回 `NULL` 是否安全需论证：`tcp_hpts.c:1868cpu_top = smp_topo()` 拿到 NULL 后的解引用风险须核验）并经 `reviewer` 门禁；若裁决候选 B，须在 M2 结束前回退这两处（属git 层面回退/正向修改，不适用 `rm_tmp_file.sh`）。

### 8.7 未核实边界

- `smp_topo()` 返回 `NULL` 之后 `freebsd/netinet/tcp_hpts.c:1868` 及其下游是否解引用该指针：**未核验**（建议列为候选 A 的必查项，交`res-code` 或 M3 `coder`）。
- ipfw 动态规则在本项目运行时是否真的被启用（`config.ini`/运行期规则集）：**未核验**，故 8.4 的堆溢出属「条件成立即触发」的静态结论，非已复现缺陷。
- `-DSMP` 是否还改变其它**非** spin 锁/CK 的运行时语义（如 `cpuset_t` 8→128 引起的按值传参/结构体嵌入 ABI 变化对已编译 DPDK 侧的影响）：**未核验**，超出本次两条委派范围，建议列入 M2 裁决前的补充核验项。
- 本节全程**静态核验，无运行时验证**。

独立核验完成时间：2026-08-04。
