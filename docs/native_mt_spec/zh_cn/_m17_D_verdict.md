# _m17_D：leader 方案裁决记录（M1 → M2）

> 本文是 leader 依据 M1 三路调研的**实测证据**做出的路线裁决，供 M2 `designer` 作为设计输入、`gate-design` 作为审核基准。
> 所有依据均指向 M1 产出文档与 `file:line`；凡未实测者明确标注。

裁决时间：2026-08-04HEAD：`ff09a17b2`　工作区状态：M1-C 探针已由 leader 还原，`lib/`、`freebsd/`、`example/` 无跟踪文件改动

---

## 1. 裁决：采用**候选 A（全树 `-DSMP`）**

### 1.1 决定性依据（全部实测/代码坐实）

| 维度 | 候选 A | 候选 B | 来源 |
|---|---|---|---|
| 编译代价 | **实测**：仅需 1 个 stub（`smp_topo`）；`error0`、`warning 51`（= HEAD 基线 51，零新增）；`lib` + `example` 双 clean build 通过，`helloworld` 二进制产出成功 | **无编译数字**（探测被 `git checkout` 门禁阻断，如实记录） | `_m17_C_buildprobe.md` §2.2/2.3/2.4 |
| 改动面| `lib/` 2 文件 2 处，**上游 `freebsd/` 树 0 处** | `lib/` 2 文件 + **上游 `freebsd/vm/uma_core.c` 4 处**（`:2546`/`:3498`/`:3508`/`:3526`），且四处强耦合、漏改无编译报错 | 同上 §3.2/3.3 |
| 逐槽路径一致性 | `uma_core.c:2546/3498/3508/3526`、`subr_pcpu.c:252` 的 SMP 分支**自动一致** | 需人工逐处放开，漏一处即脏内存/越界 | 同上 |
| spin 锁语义风险 | **已证伪**：`lib/include/sys/mutex.h:31-48` 在 `#include_next` 后 `#undef` 全部 spin 锁宏、`:59-76` 重定义为 `DO_NOTHING`/常量 1；`spinlock_enter/exit` 的定义与调用者所在 `.c` 全不在 SRCS → `-DSMP` 在 spin 锁层面**语义中性** | 同样中性 | `_m17_gate_plan.md` §8.2 |
| `smp_topo` stub 安全性 | **已坐实安全**：`tcp_hpts.c:1867-1871` 本就有 `#else cpu_top = NULL`，`:1890 if (cpu_top == NULL) grp_cnt = 1`；`:1565 if (grp_cnt > 1)` 才解引用 `grps[]`；`:2095` 的 `free(grps)` 仅模块卸载路径 | — | leader 实测（`tcp_hpts.c:1855-1935`、`:1548-1590`、`:2093-2097`） |
| 附带正确性收益 | `ck_md.h:95CK_MD_UMP` 失效 → CK **RMW** 原语恢复 `lock` 前缀。唯一实质受影响 TU 是 `ip_fw_dynamic.c`（`ck_pr_inc_32/dec_32/or_32/xor_32`）；`ck_queue.h`/`net/if.c` 全为 load/store 不受影响，`ck_epoch` 已被 `ff_glue.c:1366-1404` stub | 无 | `_m17_gate_plan.md` §8.3 |
| 主要开销 | `sizeof(cpuset_t)` 8→**128** 字节、`cpuid_to_pcpu[]`/`dpcpu_off[]` 1→1024 槽、`netisr.c` 若干`malloc(...*MAXCPU)`（**纯 BSS/堆增长，非正确性问题**）；CK `lock` 前缀有性能成本，待 M5 量化 | 槽数可控（64） | `_m17_C_buildprobe.md` §0.3/2.4 |
| 上游 diff 维护成本 | 低（13.0→15.0 升级语境下权重高） | 高| leader 判断 |

### 1.2 裁决理由

1. 候选 A 的代价被**实测**否证了 plan §0.3 的悲观预判（预判「需补大量 stub」，实测**仅 1 个**，且该 stub 返回 `NULL` 与上游 `#else` 分支**逐字等价**）。
2. 被plan 标为「最小侵入」的候选 B **实际更侵入**：要改上游 `uma_core.c` 4 处且强耦合。在 FreeBSD 13.0→15.0 升级项目语境下，上游树零补丁的权重很高。
3. 候选 A 让所有 `#ifdef SMP` 逐槽路径一次性自洽，规避候选 B「漏改一处即静默内存破坏」的高风险。
4. 附带修掉 CK RMW 缺 `lock` 前缀这一潜在原子性缺陷（成本为零、方向正确）。

### 1.3 诚实边界（M2 引用时必须一并转述）

- **候选 B 无任何编译数字**，其结论仅为代码审级别；若将来需回退到 B，必须先补做编译实证。
- 候选 A 的**运行时**行为（槽位是否真隔离、`uma_crit_lock` 能否移除、吞吐变化）均未验证，须 M3/M5 实测。
- 探针代码**不得**直接沉淀为产品代码：M3 由 `coder` 正式实现并经 `reviewer` 门禁（`_m17_gate_plan.md` §8.6-3）。
- `MAXCPU=1024` 的**降级台阶**（候选 A 内部，仍不动上游树）：`-DSMP` + 在 `lib/opt/opt_global.h` 定 `#define MAXCPU 64`（`freebsd/amd64/include/param.h:61-63` 的 SMP 分支带 `#ifndef MAXCPU` 保护）。仅在 M5 显示开销不可接受时启用。

---

## 2. 交给 M2 的强制设计约束（D 约束，均有实测依据）

| # | 约束 | 依据 |
|---|---|---|
| **D1** | `MAXCPU ≥ N`（N = `nb_threads`）是 G1 的**硬前置**：`subr_pcpu.c:77 cpuid_to_pcpu[MAXCPU]` 会被 `:91` 越界写并覆盖紧邻的 `cpuhead`（`:88` 的 `KASSERT` 因无 `INVARIANTS` 已编译掉）；`ff_kern_timeout.c:730 cpu >= MAXCPU` 会 `panic`；`ff_kern_synch.c:59 pause_wchan[MAXCPU]` 取址越界（UB）。候选 A 由 `-DSMP` 自动满足 | `_m17_A_codepath.md` U9 |
| **D2** | **`mp_ncpus` / `mp_maxid` / `all_cpus` 必须作为三元组同步设置**，且全部早于 `ff_freebsd_init.c:301 uma_startup1()`。理由：① `uma_core.c:3179-3182` zone尺寸含 `sizeof(uma_cache)*(mp_maxid+1)`，在`uma_startup1` 一次性定死，此后改 `mp_maxid` 即堆越界；② `subr_smr.c:598-605 smr_create()` 按 `mp_maxid` 逐槽写；③ **`ip_fw_dynamic.c:3236 malloc(mp_ncpus * sizeof(void*))` 与 `:2086-2091 CPU_FOREACH(i){ dyn_hp_cache[cached_count++] = ... }` 的尺寸/上界口径不同**——只抬 `mp_maxid`+`all_cpus` 而不抬 `mp_ncpus` 会**堆溢出**（`FF_IPFW=1` 已编译） | `_m17_A_codepath.md` U10；`_m17_gate_plan.md` §8.4 |
| **D3** | 稠密序号**用现成字段**：`ff_dpdk_if.c:429-433 lc->proc_id = ti`（`ti` 即 `0..nb_threads-1`），worker 取 `ff_cur_lcore_conf()->proc_id`（`ff_memory.h:104-111`）；`ff_dpdk_if.c:2649` 把 `rte_lcore_id()` 改为稠密取号，**落地实现为 `ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0)`**（thread_mode=0 时 `lcore_conf[0].proc_id` 是进程序号，必须门控，见 `_m17_gate_design.md` E2）；`ff_pcpu_thread_init()` 必须真正使用形参（原`:107` 恒传 0） | `_m17_A_codepath.md` U6.1 |
| **D4** | **主线程槽位不得与worker 撞车**，且**不要依赖「EAL main lcore == `proc_lcore[0]`」这一未验证推断**（`--main-lcore` 可打破）。建议主线程也走 `proc_id` 取号；`ff_freebsd_init.c:293` 的硬编码 0 需相应处理。`:294 CPU_SET(0,&all_cpus)` 须扩为 `0..N-1` | `_m17_A_codepath.md` U6.2（含未坐实项 U6-a） |
| **D5** | `ff_kern_timeout.c:190 static int timeout_cpu;` 必须改为 `static __thread`：它与 `:183 __thread struct callout_cpu cc_cpu` 是配套一对却漏了 `__thread`，`:254` 被每线程写、`:1061/:1077` 会把别的线程 cpuid 写进 `c->c_cpu`、`:815 callout_schedule()` 再把它当cpu 传回 `:730` 判断 | `_m17_A_codepath.md` U11 |
| **D6** | 应在 `ff_pcpu_thread_init()` 增加**运行期**上界检查（`cpuid <= mp_maxid` / `< mp_ncpus`），失败即 `rte_exit`/`panic`——因 `subr_pcpu.c:88` 的 `KASSERT` 已被编译掉。libuinet 的 `uinet_pcpu_get()` 正是在取槽位唯一入口做 `KASSERT(td_oncpu < mp_ncpus)` | `_m17_B_external.md` §3.1(b)(i) |
| **D7** | `thread_mode=0`（多进程）必须**零回归**：`nb_threads == 0` 时保持 `mp_maxid=0`、`mp_ncpus=1`、`all_cpus`仅 bit 0 | `_m17_A_codepath.md` U6.2 |
| **D8** | G2（去`uma_crit_lock`）的**真实语境**：① `critical_enter/exit` 在 f-stack 除UMA TU 外**本就是空操作**（`systm.h:186 #ifndef FSTACK`），`smr_enter()` 从未被该锁保护 → 去锁**不削弱 SMR 的任何现有保护**；② **UMA 的 `ZONE_LOCK`/`ZDOM_LOCK`/`KEG_LOCK` 与全部 `mtx` 在 f-stack 已是 `((void)0)`**（`lib/include/sys/mutex.h:57-85`，`kern_mutex.c` 不在 SRCS）→ zone/keg 慢路径**本来就无锁**；③ 但该全局锁**事实上压缩了慢路径的并发窗口**，移除后 `zdom`/keg/`uma_page` 哈希（`lib/include/vm/uma_int.h:105-126 vsetzoneslab` 的`LIST_INSERT_HEAD` 亦无锁）的竞争窗口会放大。**designer 必须在 G2-a（去锁 + 给 zone/keg 补真锁）/ G2-b（仅去锁 + 压测验证并如实记录残留风险）/ G2-c（缩小锁范围）中裁决，并给出理由**；另可参考 libuinet 的中间形态「per-cpu 一把锁」而非全局一把 | `_m17_A_codepath.md` U7/U8；`_m17_B_external.md` §3.1(a) |
| **D9** | `ff_pthread_create()`（`ff_thread.c:32-46`）创建的应用线程 `__thread pcpup == NULL`（不调 `ff_pcpu_thread_init`），一旦调用 `ff_*` 即解引用 NULL。**须在 spec 明确为「不支持的用法」**，或另立项按「预留 K 个槽位」方案支持（与 D2 的「`mp_maxid` 须在 `uma_startup1` 前定型」冲突，需配置项） | `_m17_A_codepath.md` U13 |

## 3. 须在 spec 中如实记录的已知偏差 / 残留风险（非本轮修复目标）

1. **counter(9) 已被去per-cpu 化**（`lib/include/amd64/include/counter.h:38-62`）：多线程写同一 slot（统计竞争）、fetch 只读 slot 0 → 统计不准，**非内存安全问题**。
2. **`cache_drain_safe()`**（`uma_core.c:1497-1509`）：`sched_bind()` 是 stub（HEAD `ff_glue.c:1178`），`mp_maxid>0` 后该循环会把**调用线程自己的 cache 重复排空 N 次**，其它线程 cache 不回收 →仅回收效率问题。
3. **ipfw DPCPU hazard pointer 已失效**：`dpcpu_init()` 全程无调用者、`dpcpu_off[]` 恒 0 → `ip_fw_dynamic.c:224-226` 的所有 cpu DPCPU 槽位**互相别名**，多worker 共用一个 HP 槽位。**候选 A 修不了这一条**，须记录（U15 定级由「低」提为「中」）。
4. **NUMA 未定义**（`vm_ndomains = 1`，`ff_glue.c:83`）→ `uma_core.c` 全部 `#ifdef NUMA` 跨 domain bucket 路径未编译、`uc_crossbucket` 永不装载 → 只需处理「跨线程」，不需处理「跨 domain」。
5. **netisr swi / taskqueue / kproc / netgraph ngthread / so_splice 均不创建真线程**（`ff_kern_intr.c:84-107`、`ff_compat.c:162-177` 全为空 stub）→ 「每线程独占槽位」的前提在标准用法下成立。
6. **U6-a 未坐实**：「EAL main lcore == `proc_lcore[0]`」为 DPDK 默认行为推断，须 M5 打印 `rte_get_main_lcore()`/`rte_lcore_id()`/`proc_id`/`pc_zpcpu_offset` 核对（DoD-1 已含）。

## 4. 外网交叉验证要点（与代码一致，代码为准）

- **SMR的 per-CPU `c_seq` 槽位独占性**是上游硬假设，共享会导致过早判定 grace period 结束 → UAF；且上游无独立设计文档，`subr_smr.c`顶部注释即权威说明（`_m17_B_external.md` §2.1/2.6）。
- **libuinet**（FreeBSD 9.1 用户态栈）是候选 B 的同构既有实现：不定义 `SMP`、`pcpu_init(&pcpup[i], i, ...)` 传稠密索引、`CPU_SET(i,&all_cpus)` 循环、per-cpu 存储按 `mp_ncpus` 分槽，并保留 `uinet_pcpu_locks[MAXCPU]`（**per-cpu 一把锁**，注释 `XXX temporary until final pcpu approach is determined`）。**但libuinet 无 SMR**（9.1 时代），SMR 这一层无先例（§3.1）。
- **rump kernel**（NetBSD）「虚拟 CPU 由线程独占持有」支撑「线程独占槽位≥ 关抢占」的论断（§3.2）；Seastar/ANS 为 shared-nothing 先例（§3.3/3.4）。
- **未找到可靠来源**（如实记录，不得编造）：f-stack 社区无 SMR/pcpu/-DSMP 相关讨论；mTCP 论文原文、OpenFastPath 官方设计文档未取得；「用户态多线程共享 SMR 槽位导致 UAF」无公开事故报告（合理解释：几乎无其他项目把 FreeBSD 13+ 的 SMR 搬到用户态多线程）（§1.4/§3.5）。
