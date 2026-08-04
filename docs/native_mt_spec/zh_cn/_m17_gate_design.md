# M17 M2 设计文档门禁报告（gate-design）

被审对象：`/data/workspace/f-stack/docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md`
审核者：`gate-design`（只审不改；**未修改 17 号文档**，本文件是本 agent 唯一写入的文件）
审核基准：`_m17_D_verdict.md`（D1~D9 + §3 六条残留风险）、`_m17_gate_plan.md`（U1~U15 + §8）、leader 追加的 2 批新增事实、**以实际代码为准**

**两轮审核的版本记录**
| 轮次 | 版本 | 结论 |
|---|---|---|
| 第1 轮 | `size=57578`，`mtime=13:50:11`（正文止于 §4.9 后的 `<!-- SECTIONS_5_TO_9_MARKER -->`） | **FAIL**（§5~§9 缺失，10 条必改） |
| **第 2 轮（本报告结论）** | **`size=93635`，`mtime=13:57`（§0~§9 完整）** | **PASS-with-fixes** |

核验强度：两轮合计实测约 **85 处** `file:line`。凡涉及被 `coder` 改动过的文件，**一律用 `git show HEAD:<file>` 取 HEAD 原文核对**（符合 spec §0.2 声明的行号约定）。

---

## 0. 结论

### **PASS-with-fixes**

- **必改项3 条**（F1~F3）：均**不阻断 M3 继续**（代码已按正确结论落地），但**必须在 M4 开工前修完**。
- **建议项 3 条**（F4~F6，nit 级）。
- 第 1 轮的 10 条必改中：**E1/E3/E4/E9 已解决**，**E5 由我主动撤回**（是我的错，见 §4），E6/E7/E8/E10 部分解决或未采纳 → 收敛进本轮 F1~F6。

### 判定要点

| # | leader 指定的审核要点 | 结论 |
|---|---|---|
| 1 | 证据链真伪 / 无越界表述 | **PASS-with-fixes**（1 处**前提事实错误** → F1；其余约 85 处一致；证据强度标记纪律良好） |
| 2 | D1~D9 合规 | **PASS**（D1~D9 全部满足；第 1 轮的 D7 缺口已由新版 §7.1 判定式 ⑧ 补上） |
| 3 | D8（G2-b）裁决依据 | **PASS**（三条否决理由我逐条独立坐实；慢路径窗口放大已如实记录于 §6.1） |
| 4 | 残留风险是否如实记录 | **PASS-with-fixes**（verdict §3 六条全部落位；但漏 netisr DPCPU → F2） |
| 5 | DoD-1 可执行性 | **PASS**（§7.1 给出 P1/P2 探针位置 + 12 个字段 + **8 条可机械核对的判定式**，`tester` 可直接执行；判定式 ④/⑤ 尤其到位） |
| 6 | 注释规约（lib 最小注释） | **PASS**（spec 处处给 ≤1~3 行上限；落地代码实测 1~4 行、无长篇） |

---

## 1. 审核前置基线：D 约束底层事实的独立核验（等待期完成，作为判定尺）

| 事实 | 核验结果 |
|---|---|
| `ff_freebsd_init.c:293/294/301/302`（HEAD）= `ff_pcpu_thread_init(0)` / `CPU_SET(0,&all_cpus)` / `uma_startup1()` / `uma_startup2()`；`:296 ff_init_thread0()`、`:308 mutex_init()`、`:309 mi_startup()` | ✓ 全部精确 → **三元组唯一安全窗口 = `:291`~`:293`**，与 spec §4.3.1 落点一致 |
| `ff_dpdk_if.c`（HEAD）`:429/:433/:460/:2644/:2649/:2794` | ✓ 全部精确 |
| `ff_kern_timeout.c`（HEAD）`:183/:190/:254/:662/:730/:815/:1061/:1077/:1181/:1291` | ✓ **10/10 精确** |
| **D8 锁塌缩链**：`uma_int.h:551-553 KEG_LOCK`、`:578-583 ZDOM_LOCK/ZONE_LOCK`、`:584 ZONE_LOCKPTR`、`:588-589 ZONE_CROSS_LOCK` → `mtx_lock` → `sys/mutex.h:386 → :451-452 → :417-418 _mtx_lock_flags`（`LOCK_DEBUG>0`）**或** `:428-429 __mtx_lock`（`==0`）；`lib/include/sys/mutex.h:31-37 #undef` + `:59-65 DO_NOTHING` **两条分支全覆盖** | ✓ **D8 前提坐实成立** |
| `uma_core.c:1497-1509 cache_drain_safe`、`:1725 msleep(zone, ZONE_LOCKPTR(zone), PVM, "zonedrain", 1)`、`:5433 sx_sleep`、`uma_int.h:540 KEG_LOCK_INIT`/`:566 ZDOM_LOCK_INIT`（均 `MTX_DEF\|MTX_DUPOK`） | ✓ 精确 |
| `tcp_hpts.c:1867-1871 / :1890 / :1564-1568 / :2061 / :2117 / :2142`、`kern_module.c:105-107`、`lib/Makefile:347kern_module.c`（HEAD） | ✓ → `smp_topo()` 返 NULL **安全**；U16-a「hpts 活跃」成立 |
| **C1（本轮最关键新发现）**：`lib/include/sys/pcpu.h:31-34#include_next` / `#undef curcpu` / `#define curcpu 0`（**原值已用 `git diff` 坐实**）；上游 `freebsd/sys/pcpu.h:218 #define curcpu PCPU_GET(cpuid)`；`uma_core.c` 的 **11 处** `uz_cpu[curcpu]`：`:1452,3738,3776,3818,3901,4534,4543,4595,4628,4803,4853` | ✓ **11/11 精确** → §2.3(d) 的结论成立：G1 单靠稠密 `pc_cpuid` **不能**隔离 UMA cache，G2 若在此前提下去锁将**原样放回 `b90ddcba5` 修掉的竞态** |
| §2.4 的 **21 处** `critical_enter/exit`：`:1451,1464,3727,3744,3775,3817,3859,3891,3900,3916,3918,4541,4554,4558,4626,4649,4653,4827,4850,4872,4874` | ✓ **21/21 全对**；慢路径确在临界区外（`:3859 critical_exit` → `:3880/3882`；`:3916` → `:3918`） |
| §4.5 影响点表：`ff_kern_synch.c:59/105`、`tcp_timer.c:237/249`、`tcp_hpts.c:1566/1587`、`tcp_lro.c:1210/1216`、`netisr.c:151/153/169/275-279/781/810/839/1146-1153/1164/1172` | ✓ **全对** |
| §4.3.4 的 D4 免疫性：`ff_config.c:1465-1484`（thread_mode 下 `proc_mask = strdup(lcore_mask)`、`nb_threads = nb_procs`） | ✓ 成立（主线程必属 coremask → `lcore_conf[main_lcore].proc_id∈ [0,N)`，对 `--main-lcore` 免疫） |
| spec 引用的 `_m17_A_codepath.md` **U16 章节** | ✓ **确实存在**（`:948`）→ spec 引用有效（回答 leader 问题 2①） |

---

## 2. 必改项（3 条）

### **F1（必改｜前提事实错误，但结论正确）§4.3.2 对 `rp_ent[]` 的安全性论证前提不成立**

spec `:348` 写：
> M1-A U16 已坐实「两种取法都不越界」（`rp_ent[]` 的**每个索引都独立对 `mp_ncpus`/`rp_num_hptss` 取模**；…）

**实测证伪该前提**：`rp_ent[]` 的索引点共 7 处，其中 **`freebsd/netinet/tcp_hpts.c:575 hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];`（`tcp_hpts_lock()`）根本没有取模**。其余：`:1585 rp_ent[oldest_idx]`（循环上界 `end = rp_num_hptss`）、`:1587 rp_ent[curcpu % rp_num_hptss]`（取模 ✓）、`:1922/1924/1925/2009/2077`（`i < rp_num_hptss` 初始化/拆除循环 ✓）。

**但结论（`mp_ncpus = N` 不越界）仍然成立**，只是理由必须换成**写侧有界**——我已逐点核实`t_hpts_cpu` 的**全部**赋值点：

| 赋值点 | 取值 | 有界性 |
|---|---|---|
| `freebsd/netinet/tcp_subr.c:2298` | `HPTS_CPU_NONE`（`tcp_var.h:330 ((uint16_t)-1)`） | 由 `tcp_hpts.c:604-609tcp_hpts_init()` 在 `== HPTS_CPU_NONE` 时**立即改写**为 `hpts_random_cpu()` |
| `tcp_hpts.c:606` | `hpts_random_cpu()`（`:467-474`）= `(((ran & 0xffff) % mp_ncpus) % tcp_pace.rp_num_hptss)` | **双重取模** → 与 `mp_ncpus`/`rp_num_hptss` 的关系无关，恒安全 ✓ |
| `tcp_hpts.c:1542` | `hpts_cpuid(tp, &failed)`（`:1040-1095`）四条分支：① `TF2_HPTS_CPU_SET` → 返回既有 `t_hpts_cpu`（归纳有界）；② `tcp_use_irq_cpu` → 返回 `t_lro_cpu`，而 `t_lro_cpu` **仅在未编译的 `tcp_lro_hpts.c` 中被赋值** → 恒为 `HPTS_CPU_NONE` → 走 `*failed = 1; return (0)`；③ `M_HASHTYPE_NONE` → `hpts_random_cpu()`；④ 否则 `inp->inp_flowid % mp_ncpus` | ④ 的安全性依赖 `rp_num_hptss == mp_ncpus`，由 `:1864 ncpus = mp_ncpus ? mp_ncpus : MAXCPU` + `:1872 tcp_pace.rp_num_hptss = ncpus` 保证 ✓ |

**且必须补一条时序论证（spec 缺，是 D2 的额外收益）**：`rp_num_hptss` 在 `tcp_hpts_mod_load()` 中设置，该函数经 `DECLARE_MODULE`(`:2142`) → `module_register_init`(`kern_module.c:105-107`) → `mi_startup()`（`lib/ff_freebsd_init.c:309`）执行，**晚于**三元组设置点（`:291`~`:293`）→ 必然看到最终的 `mp_ncpus = N`。

**建议措辞**（替换 `:348` 该句）：
> M1-A U16 的结论「两种取法都不越界」经`gate-design` 独立复核**成立**，但**理由需修正**：`rp_ent[]` 并非每个索引都取模 —— `tcp_hpts.c:575 rp_ent[tp->t_hpts_cpu]`（`tcp_hpts_lock()`）**无取模**【代码坐实】。真正的安全性来自**写侧有界**：`t_hpts_cpu` 的全部赋值点为 `tcp_subr.c:2298`(`HPTS_CPU_NONE`，随即被 `tcp_hpts.c:604-609 tcp_hpts_init()` 改写)、`tcp_hpts.c:606 hpts_random_cpu()`（`:467-474`，`% mp_ncpus` 后再 `% rp_num_hptss`，**双重取模**）、`:1542 hpts_cpuid()`（`TF2_HPTS_CPU_SET` 归纳有界／`t_lro_cpu` 因`tcp_lro_hpts.c` 未编译恒为 `HPTS_CPU_NONE` 而走 `*failed=1; return 0`／其余走 `hpts_random_cpu()` 或 `inp_flowid % mp_ncpus`）。而 `:1864/:1872` 保证 `rp_num_hptss == mp_ncpus`，且 `rp_num_hptss` 由 `mi_startup()`（`ff_freebsd_init.c:309`）在三元组设置（`:291`~`:293`）**之后**才初始化 → `mp_ncpus = N` 下所有索引恒 `< N`【代码坐实】。

### **F2（必改｜残留风险漏项）§6 缺 netisr 的 DPCPU 别名**

实测 `grep "DPCPU_PTR(nws)"` 在 spec 中**零命中**，§6.3 只记了 ipfw 的 DPCPU 别名。
**漏掉的事实**【代码坐实】：`freebsd/net/netisr.c:1147 nwsp = DPCPU_PTR(nws);`（`netisr.c` 已编译，HEAD `lib/Makefile:429`），因 `dpcpu_init()` 零调用者、`dpcpu_off[]` 与 `pc_dynamic` 恒 0（`freebsd/sys/pcpu.h:113-114/121/128`）→ **N 个 worker 共享同一份 `nws`**。且它**在每包热路径上**（DIRECT 直派）——比 ipfw 那条更常触发。
**定性（我已逐行核实，不夸大）**：DIRECT 分支只递增两个无锁计数器（`:1149 npwp->nw_dispatched++`、`:1150 npwp->nw_handled++`）随后调用 handler（`:1151`），上游注释 `:1141-1142` 自陈「Borrow the current CPU's stats」、`netisr_internal.h:88` 注明「written unlocked, but mostly from curcpu」→ **仅统计竞争，非内存安全问题**，与 counter(9)（§5-2）同级。
**建议措辞**（新增 §6.15）：
> ### 6.15 netisr 的 DPCPU 别名（与 §6.3 同类，但在每包热路径）
> - **依据**【代码坐实】：`freebsd/net/netisr.c:1147 nwsp = DPCPU_PTR(nws);`（HEAD `lib/Makefile:429` 已编译）。因 `dpcpu_init()` 零调用者、`dpcpu_off[]`/`pc_dynamic` 恒 0 → 所有 worker 共享同一 `nws`。
> - **影响范围**：DIRECT 直派分支仅递增 `:1149/:1150` 两个无锁计数器后调用 handler（`:1151`），上游注释 `:1141-1142`「Borrow the current CPU's stats」→ **仅统计竞争，无内存安全问题**，与 §5-2 counter(9) 同级。
> - **本轮是否修复**：**否**，候选 A 修不了（`-DSMP` 不产生 `dpcpu_init()` 调用者）。与 §6.3 合并登记为「DPCPU 独立立项」。

### **F3（必改｜自相矛盾 + 排除项缺失）§4.5 的「7 个文件」与 §9-14 的清单不一致**

- `:442` 写「编译集合内穷举，实测 grep：**只在 7 个文件中出现**」，而 `:852`（§9 证据 14）实际列出 **9 个文件**（多出 `freebsd/netinet/ip_input.c:139-149`、`freebsd/netinet6/ip6_input.c:138-148`）。两处必须一致。
- 另需补**被排除项的说明**，否则门禁无法复核「穷举」：`freebsd/libkern/arc4random.c:212 chacha20 = &chacha20inst[curcpu];` —— **未编译**（HEAD `lib/Makefile` 只列 `arc4random_uniform.c`，无 `arc4random.c`），故排除。
-建议把小节口径写成「**`curcpu` 标识符**在编译集合内的穷举（9 个文件）；另有 2 类不受影响：`freebsd/sys/callout.h:100-120` 的 `callout_*_curcpu` 宏族直接用 `PCPU_GET(cpuid)` 不经 `curcpu`（其使用者 `subr_taskqueue.c:368` 见 §6.13）、以及未编译文件 `arc4random.c:212`」。

---

## 3. 建议项（3 条，nit）

| # | 内容 | 建议 |
|---|---|---|
| **F4** | §2.3(c) `:155-158` 保留了预处理输出的具体行号（`11489:` / `13122:`）。方法学已在 `:30`/`:155` 声明为「只读`cc -E`、未写文件、未跑 `make`」（**回应了我第 1 轮的 E6**），但该行号**不可复现/不可复核**（依赖编译参数与头文件版本） | 建议改为「输出中对应行为`cache = &zone->uz_cpu[0];`（行号随编译参数变化，不作为可复核证据）」。**结论本身我已通过 C1 独立坐实，不推翻** |
| **F5** | §4.6 `:473`「主线程经 `:285`」为裸行号 | 我已核实其**正确**（`lib/ff_kern_timeout.c:285` 确为 `ff_callout_thread_init();`，SYSINIT 在 `:287`，经 `mi_startup()` 执行）。但与同句的全路径 `lib/ff_freebsd_init.c:207` 并列易误读为同一文件 → 建议写全 `lib/ff_kern_timeout.c:285`（可补 `:287 SYSINIT(callwheel_init, SI_SUB_CPU, ...)`） |
| **F6** | §6.5 的 fail-fast 面漏了一个 OOM 边角（回答 leader 问题 1③） | leader 已正确排除鸡生蛋（`lib/ff_glue.c`的 `malloc()` → `ff_malloc()`，不走 UMA；`kern_malloc.c` 不在 SRCS）。**残留边角**：`ff_glue.c:1076 pause("malloc", hz/100)` → `ff_kern_synch.c:105 &pause_wchan[curcpu]`，若 `ff_pcpu_thread_init()` 内**第一次** `malloc(sizeof(struct pcpu))` 恰好 OOM，此时 `pcpup` 尚未建立 → `curcpu` 解引用 NULL。**我的判定：可接受**——这是「启动期 OOM」，无论如何都起不来，崩在此处与崩在别处等价，且与 fail-fast 裁决自洽。建议 §6.5 补一句，避免 M5 遇到时误判为 G1 缺陷 |

---

## 4. 我在第 1 轮报告中的错误（主动更正，供leader 与 designer 对账）

designer 在 §6.14 提出的 **C4 反向纠正全部成立**，我已用 `git show HEAD:` 逐条复核并**接受**：

| 我的原引用（`_m17_gate_plan.md` §8） | HEAD 实际| 原因 |
|---|---|---|
| `ff_glue.c` ck_epoch stub 块 `:1366-1404` | **`:1358-1396`** | 我读的是**带 res-build 探针补丁的工作区**（`smp_topo` stub 使其后行号+8） |
| `lib/Makefile` 中 `ip_fw_dynamic.c` 在 `:604` | **`:601`** | 同上（`-DSMP` 探针行） |
| （第 1 轮 E5）`lib/Makefile:347 kern_module.c` 应改为 `:351` | **`:347` 本来就对** | 同上 → **E5 完全撤回，spec 无误** |
| （第 1 轮 §1.2 B1）`sched_bind` 在 `:1177-1181` | **`:1178`** | 同上 |

**教训已内化**：本轮所有涉及 `lib/` 被改文件的核验一律改用 `git show HEAD:`。这也验证了 spec §0.2/§6.14-2 提醒的必要性 —— 该提醒本身**质量很高**，建议保留在文档中。

---

## 5. 第 1 轮 10 条必改的收敛状态

| 第 1 轮 | 状态 |
|---|---|
| E1（§5~§9 缺失） | ✅ **已解决**：§5 九条排除项、§6 十四条风险、§7 DoD-1~8（含 8 条判定式）、§8 里程碑/两次提交清单/commit message英文草案、§9 证据索引 36 条 |
| E2（§4.4 缺 `thread_mode` 门控/ D7 未分析） | ✅ **实质解决**：§7.1 判定式 ⑧ 明确要求「`thread_mode=0` 下 1 进程与 2 进程都要跑，secondary 也必须 `dense_idx==0`（**C2 就是这里暴露**）」，D7 缺口已闭合。`:408` 仍写无门控的 `ff_stack_thread_init(qconf->proc_id)`，而**落地代码已是 `thread_mode ? qconf->proc_id : 0`** → 属§8.2 提交清单口径问题，建议 M6 回填时按代码校正（不再计为必改） |
| E3（`curcpu` 未落地） | ✅ **已解决**：`git diff lib/include/sys/pcpu.h` 确认 `-#define curcpu 0` → `+#define curcpu PCPU_GET(cpuid)`；§8.2 commit-1 表已含该文件；§6.14 如实记录了流程风险 |
| E4（`uma_int.h:583-586` 行号错） | ✅ **已解决**：`:501`/§9-19 均已改为 `:540 KEG_LOCK_INIT` / `:566ZDOM_LOCK_INIT`，并正确新增 `ZONE_LOCKPTR(z)` 见 `:584`（我复核 `:584` 确为 `ZONE_LOCKPTR`） |
| E5（`Makefile:347`） | ⛔ **我撤回**（见 §4） |
| E6（【实测】不可复核） | → 降为 **F4**（方法学已声明，仅行号仍不可复核） |
| E7（穷举需补排除项） | → 部分解决（`subr_taskqueue.c:368` 已进 §6.13 U12-ish ✓），剩余并入 **F3** |
| E8（netisr DPCPU） | ❌ **未采纳** → **F2**（必改） |
| E9（L1 判据不可靠） | ✅ **已解决**：§6.2 已写明「未命中时 `*slab = up->up_slab` 会对 NULL `up` 直接段错（这是 L1 台阶的观测症状）」 |
| E10（裸 `:285`） | → 降为 **F5** |

---

## 6. 对新版新增内容的专项评价（leader 指定的两处高风险增补）

### 6.1 §2.3 + §4.5「`curcpu` per-thread 化」——**核准，且是本轮最有价值的增补**

- 原值 `#define curcpu 0` 已用 `git diff` 坐实（回答 leader 问题 1 第一小项）。
- 11 处 UMA 影响点行号 **11/11 精确**；机理链（`curcpu`→`uz_cpu[0]`→G2 去锁即放回 `b90ddcba5` 竞态）**成立**。
- 8 类使用点清单：**实质穷尽**（与我独立 grep 的编译集合结果一致），仅计数与排除说明需修（F3）。
- 两条「不可达」论证**均成立**：`netisr.c:839/1172` —— `:151/:153` 默认 `NETISR_DISPATCH_DIRECT` + `:169 netisr_maxthreads = 1` + `:810 if (nws_count == 1)` 早返回 + `:1146-1153` 直派后 `goto out_unlock`；`tcp_hpts.c:1566` —— `:1890 cpu_top == NULL → grp_cnt = 1`、`:1564 if (grp_cnt > 1)` 才进入。
- fail-fast 不加 NULL 兜底：**可接受**（§5-1 的理由——「补槽位需 `mp_maxid≥ 栈线程数 + K`，与 H1『`uma_startup1()` 前定型』直接冲突」——是**代码级硬约束**，成立）。仅需补 OOM 边角（F6）。

### 6.2 §4.3.2「`mp_ncpus` 抬到 N」——**结论核准，论证前提须修（F1）**

- 引用的 `_m17_A_codepath.md` U16 章节**确实存在**（`:948`）→ 回答 leader 问题 2①：**不是引用不存在的章节**。
- leader 问题 2② 的怀疑**完全正确**：`:575 rp_ent[tp->t_hpts_cpu]` **确实不带取模**，spec 的「每个索引都独立取模」是**错的**。但我已把安全性用**写侧有界 + 时序**重新坐实（见 F1），故`mp_ncpus = N` 的裁决**可以保留**。
- 裁决的第二条理由（`mp_ncpus=1` 会让 N 个 worker 挤在唯一 hpts 实例，而 `HPTS_TRYLOCK` 恒真毫无互斥）**我已独立坐实**：`tcp_hpts.c:218 #define HPTS_TRYLOCK(hpts) mtx_trylock(&(hpts)->p_mtx)` + `:1603 if (!HPTS_TRYLOCK(hpts))` + `lib/include/sys/mutex.h:74` `mtx_trylock_flags_ → 1`✓。

---

## 7. 未核实边界（诚实声明）

- §3.1 候选 A 的编译数字（`error 0`/`warning 51`/二进制 30,392,616 字节）、§7.3 的 51 条基线：**未重跑编译核验**。
- §2.2 的 SMR 破坏链（A/B 交错 UAF）为源码语义推导，spec 已如实标注来源；我**未复核** `smr_poll_cpu`/`smr_poll_scan` 逐行实现。
- §2.3(c) 的预处理输出行号：**无法复核**（见 F4），但结论已由 C1 独立坐实。
- `_m17_A_codepath.md` U16 我只核验**章节存在性**与其被引用的两条结论，**未逐行复核该节全文**。
- ipfw 动态规则运行期是否启用（§6.3 的诚实边界）：**未核验**。
- 全程**静态审核，无任何运行时验证**；DoD-1~DoD-5 的实际结果须M5 由 `tester` 产出。

---

## 8. 给 leader 的处置建议

1. **可以放行 M3 继续 / 开始 M4 前必须先修F1~F3**：F1 是「结论对、理由错」，F2/F3 是记录完整性，均不影响已落地代码的正确性。
2. **建议顺序**：designer 修 F1~F3（+ 可选 F4~F6）→ 我做**第 3 轮**快速复核（预计只需核3 处）→ `reviewer`按最终 spec 复核 M3 代码 → M4。
3. **M2 bounce = 1/3**（第 1 轮 FAIL 计1 次；本轮 PASS-with-fixes 不计打回）。
4. `_m17_D_verdict.md` §3.2 的 `ff_glue.c:1187` 建议按 HEAD 改为 **`:1178`**（与designer 的 C4 一致）。
5. §8.2 提交清单里`ff_dpdk_if.c` 的改动描述建议按**落地代码**校正为 `thread_mode ? qconf->proc_id : 0`（见 §5 的 E2 说明）。

---

# 9. 复审（bounce=1）【= leader 指定的「复审」章节】

**复审基准版本：`size=125935`，`mtime=2026-08-04 14:24:05`，1060 行**（旁路探测记录：`13:5894663` → `14:15 107258` → `14:21 123537` → `14:24 125935`，连续 4 次 stat 无变化后开审）
复审范围：按 leader 指示**不重跑已通过的证据链**，只核 ① F1~F6 落实情况 ② §5~§9 新内容有无新引入的事实错误/越界表述 ③ leader 指定的三个盯防点。
新增实测：本轮又实测 **18 处** `file:line`（全部针对新写内容）。

## 9.1 复审结论

### **PASS-with-fixes**（必改 3 条：**F1 未修** + N1 + N2；建议 3 条：F4/F5/N3）

文档质量在本轮有**显著提升**：新增了 §6.15~§6.19 五条风险、§4.5(i) 的引导窗口兜底、§7.1 的判定式可靠性修正、§6.21 的流程风险，且**主动纠正了我两处行号错误**。其中 §6.18 与 §6.19 是**本轮新出现的真实发现**（非我提出），我已逐条核实**全部成立**（见 §9.4）。

## 9.2 F1~F6 落实核验

| # | 状态 | 依据 |
|---|---|---|
| **F1**（`rp_ent[]` 论证前提错误） | ❌ **未修，仍为必改** | `:350` 原文仍是「`rp_ent[]` 的**每个索引都独立对 `mp_ncpus`/`rp_num_hptss` 取模**」。我已实测证伪：`freebsd/netinet/tcp_hpts.c:575hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];`（`tcp_hpts_lock()`）**无取模**。结论仍成立，但理由必须换成**写侧有界**（完整替换措辞见本报告 §2-F1，含 `hpts_random_cpu()` 的双重取模 `:467-474`、`t_lro_cpu` 因 `tcp_lro_hpts.c` 未编译而恒 `HPTS_CPU_NONE`、`:1864/:1872` 保证 `rp_num_hptss == mp_ncpus`、以及 `rp_num_hptss` 由 `mi_startup()` 在三元组之后才初始化的时序论证） |
| **F2**（netisr DPCPU 别名缺失） | ✅ **已修** | 新增 §6.15，依据 `netisr.c:236 DPCPU_DEFINE(struct netisr_workstream, nws);`（我实测 `:236` ✓ 精确）+ `:1147`/`:1149`/`:1150`/`:1151`，定性为「**纯统计计数竞争，非内存安全问题**，与 counter(9) 同级」→ **与我的定性完全一致**；并正确写明「候选 A 修不了」「与 §6.3 合并登记为 DPCPU 独立立项」 |
| **F3**（7 vs 9 文件矛盾 + 排除项） | ✅ **已修** | `:456` 已把口径限定为「**`curcpu` 这个标识符**在实际参与编译的集合内的出现（编译集合以 `lib/*.o` 反推）」；新增「排除 X1」行，并给出**正确的 HEAD 行号** `lib/Makefile:582`（`LIBKERN_SRCS` 只列 `arc4random_uniform.c`）+ `ls lib/arc4random.o` 不存在的实测 |
| **F4**（预处理行号不可复核） | ⚠️ **未修（nit）** | `:158-159` 仍保留 `11489:` / `13122:`。结论不受影响（已由 C1 独立坐实），建议按本报告 §3-F4 改措辞 |
| **F5**（裸 `:285`） | ⚠️ **未修（nit）** | 仍是「主线程经 `:285`」。我已核实其**内容正确**（`lib/ff_kern_timeout.c:285` = `ff_callout_thread_init();`，SYSINIT 在 `:287`），仅建议写全文件名 |
| **F6**（OOM 边角） | ✅ **已修且超出预期** | 不仅在文档中登记，还新增 §4.5(i) 的**定点兜底设计**，且`coder` **已落地**：`git diff lib/ff_kern_synch.c` = `pause_wchan[curcpu]` → `pause_wchan[pcpup != NULL ? curcpu : 0]` + 1 行必要注释（`/* Reachable from malloc()'s OOM retry before this thread has a pcpu. */`）→ 注释规约合规；§8.2 commit-1 清单已同步加入该文件（8 个文件） |

## 9.3 leader 指定的三个盯防点

### 盯防点 1：§6 是否完整覆盖 7 条残留风险 + 定性是否准确 —— **PASS（7/7）**

| verdict §3 的 6条 + 我新增 1 条 | 落位 | 定性核验 |
|---|---|---|
| counter(9) 统计竞争 | §6.7 | ✅ 「统计准确性问题，不是内存安全问题」——准确 |
| `cache_drain_safe` 重复排空 | §6.6 | ✅ 「**仅回收效率问题，无越界、无内存不安全**」+ 正确补「`curcpu` per-thread 化**不改变**这一结论」——准确 |
| ipfw DPCPU 别名 | §6.3 | ✅ 「候选 A 修不了」+「`mp_ncpus=N` 只消除 `dyn_hp_cache` 的**堆溢出**，不消除**别名**」——准确且切中要害 |
| NUMA 未编译 | §6.16 | ✅ 定性为「**简化因素而非风险**」并登记「若将来引入 NUMA，`uc_crossbucket`/`ZONE_CROSS_LOCK`（`uma_int.h:586-590`）会成为新共享点，G2 结论须重新论证」——准确，且比verdict 更进一步 |
| 各类 stub 线程不存在 | §6.17 | ✅ 定性为「G1『线程↔槽位 1:1 且永不迁移』不变式**成立的前提**」，并明确「该不变式是当前代码形态的产物、不是被强制的约束」——准确。依据我已实测：`ff_kern_intr.c:84-89 swi_add`→0、`:91-95 swi_sched` **空**、`:97-101 swi_remove`→0、`:103-107 intr_event_bind`→`EOPNOTSUPP` ✓ 逐行精确 |
| U6-a | §6.12 | ⚠️ 定性正确（由「方案依赖项」降为「观测项」），但其**兜底手段与实际探针不符** → 见 N1 |
| **netisr DPCPU（我的 E8）** | §6.15 | ✅ 见 F2 |

另新增 §6.18/§6.19 两条（见 §9.4），使§6 共 21 小节。**未发现漏项**。

### 盯防点 2：§7 是否与 `coder` 实际探针一致 + 判定式可执行 —— **PASS-with-fixes（1 条必改 = N1）**

已对照 `_m17_E_coder_g1.md` §6 逐项核验：

| 对照项 | 结论 |
|---|---|
| 探针落点（P1~P4） | ✅ §7.1 开头新增了「与 `coder` 已实现探针的对齐说明」，4 处落点、输出格式两行**逐字一致** |
| 日志落点| ✅ 已按 `coder` 实测改为「**两个文件都要看**：主线程 P1+P4 在 `example/f-stack-0.log`，worker P1+P3 在 `example/helloworld.log`」，并保留「追加写入须先记旧行数再 `tail -n +N`」——**这正是我准备提的问题，已被吸收** |
| `tid` 语义 | ✅ 已注明是 `pthread_self()` 句柄、非 OS tid、勿与 `ps -T` 对照 |
| `sizeof(struct uma_cache)` | ✅ 采用 `coder` 的 `nm --print-size` 实测 **128（0x80）**，并明确「上游 `uma_int.h:280-281` 注释说 64 字节，与本地实测不符，以实测为准」——**处理得当**（未盲信上游注释） |
| **per-VNET 绝对地址比较缺陷** | ✅ **已完整吸收**：§7.1 的 ⚠ 段坐实 `tcp_var.h:1308/:1315` + `lib/opt/opt_global.h:6 #define VIMAGE 1` + `vnet.h:305`，指出跨线程绝对地址相减「**在数学上不成立**」，并给出 (a) 增打 `smr_base`/`zone_base` 两个 `%p` / (b) 改用规范形式（全局 `zone_mbuf` + 偏移判据）两条路径，且明令「**不得在未确认基址一致性的前提下把 `0x1000`/`0x80` 当作 DoD-1 已通过的证据**」——与我独立得出的结论**完全一致**，措辞更严谨 |
| 判定式 ①~⑧ | ✅ 全部可机械执行；⑤/⑥ 已改为「基址一致→绝对差；基址不一致→偏移判据」的双分支形式；⑦ 含 `MAXCPU` 校验；⑧ 含 `thread_mode=0` 的 1 进程 + 2 进程与 secondary `dense_idx==0` |
| **⑨（U2 补充判定式）** | ✅ 新增，且正确指出「⑥ 只证明相邻线程槽距 4096，**没有**证明该 PCPU zone 真分配了 `(mp_maxid+1)×4096`；若只分配 1 页，`dense_idx≥1` 的槽位就是越界内存，短时冒烟不一定崩」，并给出可行判据「打印所在 keg 的 `uk_ppera`（应 == `mp_maxid+1`）」——**这是很强的补充**，把 U2 从「静态未决」变成了可运行期坐实 |
| D7 专项 | ✅ §7.4 新增「D7 专项（gate-design E2 要求，不可省）」，明确 1 进程与 2 进程都要跑、两个日志都要 `grep "out of range"`、并写明「属**脆弱耦合**，**不接受仅静态推断**」 |

**N1（必改）**：§7.1 的 P1「必须打印的字段（9 个）」仍含 `rte_lcore_id()` 与 `rte_get_main_lcore()`，但**实际探针只打 7 个字段、不含这两个**（`_m17_E_coder_g1.md` §6.3 的格式串）；而 §6.12 明确承诺「兜底：DoD-1 探针打印 `rte_get_main_lcore()`/`rte_lcore_id()`/`proc_id`/`pc_zpcpu_offset` **四元组核对**」→ **该兜底当前无法执行**。
**建议措辞（二选一，推荐 a）**：
> **(a)** 在 §7.1 的 ⚠ 方案 (a) 增打 `smr_base`/`zone_base` 时**一并**增打 `rte_lcore_id()`/`rte_get_main_lcore()`（经 host 侧辅助函数导出，与 `ff_probe_tid()` 同侧，共 1 处改动），使 §6.12 的U6-a 核对可执行；
> **(b)** 或把 §6.12 的兜底改为「本轮**不核对** U6-a（实际探针未打印 `rte_*` 字段），仅登记为观测项；因 §4.3.4 的取号方式不依赖该推断，**不影响正确性**」。

### 盯防点 3：§8 两次提交划分 —— **PASS（1 条必改 = N2，1 条建议 = N3）**

- **每个提交可独立编译** ✅：commit-1 的 8 个文件自洽（`-DSMP` + `smp_topo` stub 同在其中，避免链接缺符号）；commit-2 只改 `uma_int.h` + `ff_glue.c`。§7.3 要求两次都 `make clean` 后完整编译。
- **不引入已知崩溃** ✅ 且顺序正确：commit-1 **保留** `uma_crit_lock` 而同时完成 `curcpu` per-thread 化 → 相对HEAD 是**严格更安全**（per-thread 槽位 + 锁仍在）；commit-2 才去锁，且 §4.7 有硬前置「`curcpu` 必须已 per-thread 化，否则等于放回 `b90ddcba5` 的竞态」。**这个顺序是正确的，不存在中间态崩溃窗口。**
- **§8.2 清单与落地代码一致** ✅：我实测 `git status` 现有 **10 个改动文件** = 清单的 8 个 + 探针的 `lib/ff_host_interface.c`/`.h`，与 §8.2 脚注「探针不计入本清单」**精确吻合**；新增的 `lib/ff_kern_synch.c` 已落地（见 F6）。
- **N2（必改｜操作性风险）**：§8.3 要求「探针不进 commit-1/commit-2」并「`git diff` 确认探针不在 diff 中」，但**没给操作方法**，而 P1~P4 与 G1 的真实改动**同处 `lib/ff_freebsd_init.c` 一个文件** → 直接 `git add lib/ff_freebsd_init.c` 必然把探针一起提交。建议补：
  > commit-1 之前**必须先通过正向修改删除全部 5 个 `#if1 /* M17 temporary probe */` 块**（`grep -rn "M17 temporary probe" lib/` 一次列全，含 `ff_freebsd_init.c` 的 P1~P4 与 `ff_host_interface.c/.h` 的 `ff_probe_tid()`），再整文件 `git add`；**不建议**用 `git add -p` 拆分同一文件（易漏改且留下不可编译的中间态）。若 M5 后仍需保留探针供复现，则按 §8.3 作为**独立临时提交**并在验收后 revert。
- **N3（建议）**：§8 未显式声明「**commit-2 可单独 `git revert` 而不影响 G1**」。虽然「2 个文件、不得混入其它改动」已隐含，但建议明写一句，作为 §4.7.4 台阶 L2（不可移除时回退）的操作保障。

## 9.4 §5~§9 新内容的事实核验（本轮新增 18 处实测，未发现事实错误）

| 新论断 | 核验结果 |
|---|---|
| **§6.18**「`net.isr.dispatch` 必须保持 `direct`，否则静默丢包」（来源 `reviewer`） | ✅ **全链坐实**：`netisr.c:155-158 SYSCTL_PROC(_net_isr, OID_AUTO, dispatch, CTLTYPE_STRING \| CTLFLAG_RWTUN \| CTLFLAG_NEEDGIANT, ...)` ✓（`RWTUN` 确认可由 tunable/`config.ini` 预置）；`:1172 if (cpuid != curcpu) goto queue_fallback;` ✓；`lib/ff_kern_intr.c:91-95 swi_sched(void *cookie, int flags) { }` ✓ **确为空函数体** → 「入队后无人处理 = 静默丢包」**成立**。且该条与 §4.5 表第7/8 行的「默认不可达」**不矛盾**（一个讲默认配置、一个讲改配置后），文档已自行说明这一点 |
| **§6.19（R6）**「hpts 实例数 1→N 的内存 + callout 归属错配 + 无互斥」 | ✅ **依据全部精确**：`tcp_hpts.c:169 #define NUM_OF_HPTSI_SLOTS 102400` ✓、`:243-247 struct hptsh { TAILQ_HEAD(, tcpcb) head; uint32_t count; uint32_t gencnt; } *p_hptss;` ✓（24 字节推导合理：16+4+4）、`:1999 callout_init(&hpts->co, 1)` ✓、`:2010 hpts->p_cpu = i` ✓、`:2047-2049 callout_reset_sbt_on(..., hpts->p_cpu, ...)` ✓、HEAD `lib/Makefile:51 FF_TCPHPTS=1` ✓ + `:161 CFLAGS+= -DTCPHPTS -DRATELIMIT` ✓。**「N 个实例的 callout 全挂主线程 callwheel」这一错配论证成立**（`ff_kern_timeout.c:184 CC_CPU(cpu)` 忽略实参、`tcp_hpts_init` 由主线程在 `mi_startup()` 期执行）。内存推导已诚实标注**【未坐实（推导）】**并要求 M5 用 RSS 实测 ✓ |
| §6.16 NUMA / §6.17 stub 线程 | ✅ 依据精确（见 §9.3 盯防点 1） |
| §7.1 的 ⚠ per-VNET 论证 | ✅ `tcp_var.h:1308/:1315` ✓、`in_pcb.h:378ipi_zone`/`:380 ipi_smr` ✓、`kern_mbuf.c:325 uma_zone_t zone_mbuf;`（**普通全局、非 VNET**）✓ → spec 选`zone_mbuf` 作规范形式是**正确**的 |
| §4.5(i) 引导窗口兜底 | ✅ 设计与落地代码一字不差 |
| 越界表述检查 | ✅ 新增内容的证据强度标记**纪律良好**：§6.19 内存推导标【未坐实（推导）】、§7.1-⑨ 标【未坐实】、§6.18 兜底标【未坐实】、§6.12 降级为观测项。**未发现把静态推断写成「已验证/已实测」的越界** |

## 9.5 我的第三次自我更正

spec §4.5「排除 X1」指出：我在第2 轮 F3 中引的 `lib/Makefile:586`（`arc4random_uniform.c`）是**含 M3 改动后的工作区行号**，HEAD 实为 **`:582`**。我已用 `git show HEAD:lib/Makefile | grep -n arc4random` 复核 → **确为 `:582`，我错，接受**。
这是我第三次被同一类问题绊到（前两次见本报告 §4）。**已彻底内化**：本轮 §9 的全部 18 处新实测，凡涉及 `lib/` 下被改动文件，一律先`git show HEAD:` 再取行号。

## 9.6 复审后的必改项汇总（3 条）

| # | 级别 | 内容 |
|---|---|---|
| **F1** | 必改（前提事实错误，结论正确） | §4.3.2 `:350` 的「`rp_ent[]` 每个索引都取模」→ 换成**写侧有界 + 时序**论证（措辞见本报告 §2-F1） |
| **N1** | 必改（承诺与实现不符） | §7.1 P1 的 9 字段 vs 实际探针 7 字段；§6.12 承诺的 U6-a 四元组核对当前**无法执行** → 增打 `rte_lcore_id()`/`rte_get_main_lcore()`，或降级 §6.12 兜底 |
| **N2** | 必改（M7 操作性风险） | §8.3 补「commit 前必须先正向删除 5 个 `#if 1 /* M17 temporary probe */` 块再整文件 `git add`」——因 P1~P4 与 G1 改动同处`ff_freebsd_init.c` |

建议项：**F4**（预处理行号措辞）、**F5**（`:285` 写全文件名）、**N3**（明写 commit-2 可单独 revert）。

## 9.7 复审边界

- 按 leader 指示**未重跑**第 1/2 轮已通过的约 65 处证据链；本轮只实测新内容 18 处。
- §6.19 的「`sizeof(struct hptsh)` = 24 字节 → 单实例 2.34 MiB」为结构布局推导，spec 已标【未坐实（推导）】，我**未用 `sizeof`/`nm` 实测**。
- §7.1 的 ⚠ 中「`coder` 冒烟的 `0x1000`/`0x80` 强烈提示两次读到同一个 `V_tcbinfo`」这一推断，spec 已标【未坐实】；**我同样无法静态定论**（需 M5 增打基址后才能判定是「worker vnet 数据由 vnet0 模板复制且未重跑 `tcp_init`」还是「`td_vnet` 未生效」）。这条**必须由 M5 实测关闭**。
- 全程**静态审核，无任何运行时验证**。
- bounce 计数：M2 = **1/3**（第 1 轮 FAIL 计1 次；第 2 轮与本轮均为 PASS-with-fixes，不计打回）。

---

# 10. 复审（bounce 1 收尾）【= leader 指定的「## 7 复审」章节】

**复审基准版本：`size=150518`，`mtime=2026-08-04 15:57:18`，1191 行，10 个一级章节（§0~§9）**
对照物：`_m17_F_runtime.md`（84,613 字节，mtime **15:52:35**，早于 spec 5 分钟）、`_m17_gate_code_g1.md`（67,418 字节，15:05:06）
本轮新增实测 **21 处**（含 5 项代码级独立核验 + 6 项文件系统实测）；按 leader 指示未重跑前几轮已通过的证据链。

## 10.1 复审结论

### **PASS**（不判 FAIL）+必改 **6** 条（其中 2 条为 **M7 实操阻断点**）+ nit 4 条

判**PASS** 的理由（严格按 leader 给的 FAIL 判准）：
- **无阻断性设计缺陷**：D1~D9 全满足；`reviewer` M4 门禁「必改-2」与「G2-S1」**均已完整落实，且其前提我已独立坐实**；§6 残留风险 **7/7** 齐备。
- **无越界表述**：leader 的FAIL 判准是「把未坐实/接近噪声写成确定结论」。逐项检查后，spec **没有**这类越界——相反它把 3 线程离群、`ipi_smr` 基址一致性等规范标注为【未坐实】。
- 剩余 6 条必改**全为文本层面**（1 处事实错误 + 2 处数据回填时效 + 3 处 M7 实操细节），不影响已落地代码的正确性，可在 **M6**（`designer` 回填、`gate-doc` 把关）一并完成。

⚠ **F1 已连续三轮未修**（见 10.2）。**建议 leader 明确：若 M6 回填时F1 仍未修，`gate-doc` 应直接判 FAIL。**

## 10.2 必改项（6 条）

### 必改-1｜F1 第三轮未修（本文档唯一的事实错误）

`:351` 仍为「…（`rp_ent[]` 的**每个索引都独立对 `mp_ncpus`/`rp_num_hptss` 取模**…）」。
我第 2 轮已实测证伪并两次给出替换措辞：`freebsd/netinet/tcp_hpts.c:575 hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];`（`tcp_hpts_lock()`）**无取模**。结论（`mp_ncpus=N` 不越界）成立，但理由必须换成**写侧有界 + 时序**（完整措辞见本报告 §2-F1）。

### 必改-2｜§7 未回填 M5 第三部分（DoD-5 A/B 交叉复测）——leader 本轮硬约束

`_m17_F_runtime.md`（15:52，**早于 spec 5 分钟**）第三部分已给出完整结果，而 spec §7.5（`:1008-1016`）仍是「**去锁前基线：已完整就绪**」+「去锁后**必须重做**」的待做语气，全文 `grep` 这些数字**零命中**：

| M5 实测（`_m17_F_runtime.md`） | spec §7 现状 |
|---|---|
| `:1307` 2 线程 **B−A = +0.50%**；`:1308` A 侧互校 **−0.41%** | 缺 |
| `:1322` 4 线程 **B−A = +1.67%**；`:1323` A 侧互校 **+0.71%** | 缺 |
| `:1350-1351` soak **+0.87%** / **+1.78%** | 缺 |
| `:1331/:1337` 3 线程 **+4.93%**「不可直接采信…**不作为 DoD-5 判定依据**」 | 缺 |
| `:1362` 判定表「2 线程 A/B 交叉各 6 轮 → PASS」 | 缺 |

同时**必须**把 M5 的诚实边界原样写入 §7（我已逐条核到出处）：
1. **+0.50%/+1.67% 接近噪声，不得宣称 G2 带来确定性能提升**（M5 `:1145` 自陈「±2% 对机器状态漂移极为敏感」）；
2. 3 线程 **+4.93% 不作判定依据**，离群根因**未坐实**（`:1337`，线索见 §6.19/R6）；
3. `[M17-PROBE]` 缺行/拼接污染根因 **`ff_subr_prf.c:86` 全局无锁 `bufr[]`**；
4. **secondary 探针未取到**（`:284`/`:657`：`example/f-stack-1.log` 全程60 行、`grep -c "M17-PROBE"` = 0，落点未定位）→ 2 进程档 D7 取证**仅覆盖 primary**；
5. **`MAXCPU=1024` 的 RSS 未测**（`:659`）；
6. `kmem_malloc` 在大 N 下能否稳定拿到 `(mp_maxid+1)` 页**未核实**。

> 说明：§7.6 已写「M6 须把 M5 实测数据回填 §7 各表」，即 designer 的立场是按里程碑推迟到 M6——该立场本身合规，故本条**不判 FAIL**；但 M5 数据在 spec 落盘前 5 分钟已就绪，建议立即回填，否则 §7 会以「待做」形态进入 M7。

### 必改-3｜`uk_ppera` 2 线程档的「待补/待复测」已过期

spec `:880` 表 2 线程档 `⑨` = 「待补（应== 2）」、`:969`「2 线程档…**待复测确认**」；而 M5 `:846-847` **已实测** `[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=2 uk_rsize=8 mp_maxid=1`（`pcpu_zone_64` 同）。
→ 应改为【实测】PASS，并把 §6.20/`:845` 的 U2 关闭说明从「4 线程档实测」升级为「**2/3/4 三档全部实测**」。

### 必改-4｜§8.3 探针行号与处数全部过期（**M7 实操阻断点**）

spec `:1072` 写「`lib/ff_freebsd_init.c`（P1~P4 + P5，`:115`/`:134`/`:160`）+ `lib/ff_host_interface.c`/`.h`」。
**我实测 `grep -rn "M17 temporary probe" lib/` = 6 处**：`ff_host_interface.c:152`、`ff_host_interface.h:51`、`ff_freebsd_init.c:114`、`:122`、`:271`、`:432`。
→ spec 给的 3 个行号中只有 `:115`≈`:114` 对得上，`:134`/`:160` 与实际 `:122`/`:271`/`:432` **完全不符且漏 1 处**。**按现有行号摘除会漏摘 → 探针会被带进 commit。**
**建议措辞**：
> 探针共 **6 处**（撰写时实测：`ff_host_interface.c:152`、`ff_host_interface.h:51`、`ff_freebsd_init.c:114/:122/:271/:432`）。**行号会随改动漂移，M7 摘除必须以 `grep -rn "M17 temporary probe" lib/` 的实时输出为准，摘除后复跑该 `grep` 确认返回空。**

### 必改-5｜§8 缺 `ff_glue.c` 的hunk 级分拆说明（**M7 实操阻断点**）

`lib/ff_glue.c` **同时出现在两个 commit**：commit-1 加 `smp_topo()` stub、commit-2 删 `:146 uma_crit_lock`。而**工作区两处改动已同时存在**（G2 已落地）→ commit-1 若整文件 `git add`，会把 G2 的删除一并带入，**破坏「commit-2 可单独 revert」**。spec 目前无任何相关说明（`grep "add -p"` 零命中）。
**建议措辞**（§8.3 或新增 §8.5）：
> `lib/ff_glue.c` 横跨两个提交，**commit-1 必须用 `git add -p lib/ff_glue.c` 只暂存 `smp_topo()` 那一处 hunk**，`uma_crit_lock` 的删除留给 commit-2；`git add` 后用 `git diff --cached lib/ff_glue.c` 复核。（与 §8.3 探针「整文件删除后再 add」的策略不同，此处必须 hunk 级拆分。）

并建议在 §8 显式声明两句（leader 要点 7；目前仅 `:511` 论证 `curcpu` 时附带提到该原则）：
> ① **每个提交都可独立编译且不引入已知崩溃**：commit-1 保留 `uma_crit_lock` 且已完成 `curcpu` per-thread 化 + §4.10 时序修复 → 相对 HEAD 严格更安全；commit-2 仅去锁，前置见 §4.7。② **commit-2 可单独 `git revert` 而不影响 G1**（仅 2 文件、不混入其它改动），这是 §4.7.4 台阶 L2 的操作保障。

### 必改-6｜DoD-8 临时产物清单不全（**有误入库风险**）

spec `:1025` 只列 `lib/_m17_probe_*.c/.o`、根目录 `_m17_*.log/.txt/.i/_m17_dep/`、`example/*.log`。**实测仍有未列项**：

| 实测残留 | 证据 |
|---|---|
| `example/helloworld_g1_prelock`（**30,392,704 字节**，15:00） | `ls -la` |
| `example/helloworld_g2_nolock`（**30,392,664 字节**，15:10） | `ls -la` |
| **`./config.m17_g2_2t.ini`、`./config.m17_g2_4t.ini`（f-stack 仓库根目录）** | `find . -name "config.m17*"` |
| `/tmp/m17ab_off.txt`、`/tmp/m17_e_cmd.sh`、`/tmp/m17_ffinit_before.c`、`/tmp/m17_g2_ex.log`、`/tmp/m17_g2_exclean.log` | `ls /tmp/m17*` |

**风险**：根目录两个 `config.m17_g2_*.ini` 会出现在 `git status`，**存在误入库风险**；两个 30MB 二进制若不清理长期占用。
→ DoD-8 须补齐四类，并明确「一律通过 `/data/workspace/rm_tmp_file.sh` 清理」（源码内探针除外，走正向修改）。

## 10.3 nit（4 条，非阻断）

| # | 内容 |
|---|---|
| nit-1 | `:158-159` 预处理输出行号 `11489:`/`13122:` **第三轮未修**（不可复现证据；结论已由 C1 独立坐实） |
| nit-2 | `:473` 裸`:285` **第三轮未修**（内容正确 = `lib/ff_kern_timeout.c:285`，仅建议写全文件名） |
| nit-3 | §6 小节编号**跳过 6.13/6.14**（6.12 → 6.15）。我已 `grep` 确认**无任何悬空引用**，纯cosmetic |
| nit-4 | §6.19（R6）「单实例 2.34 MiB」仍为布局推导【未坐实（推导）】，M5 未测 RSS（同必改-2 第5 条），建议就地标注 |

## 10.4 已落实项核验（leader 要点 1~5、7、8 逐条）

| leader 要点 | 结论 | 依据 |
|---|---|---|
| **1. E1 补齐 + §6 覆盖 7 条** | ✅ **PASS** | §5 十项排除、§6 **二十二**小节、§7 八个 DoD、§8 四小节、§9 三十余条证据索引全部存在。**锚点无悬空**：全文 `§x.y` 去重后逐个核查，`§10.3`/`§2.14-A/B`/`§5.1` 均为**对外部文档的引用**（M1-A U10 §10.3、`_m17_gate_code_g1.md` §2.14、plan §5.1），非本文内部锚点；`§5-1/§5-2/§5-5` 在 §5 表格第 1/2/5 项均有对应。**7 条残留风险 7/7**：counter→§6.7+§5-2、cache_drain_safe→§6.6、ipfw DPCPU→§6.3+§5-3、NUMA→§6.16+§5-9、stub 线程→§6.17、U6-a→§6.12、**netisr DPCPU（我的E8）→§6.15** |
| **2. E2** | ✅ **PASS（四处呼应，超出要求）** | `:416` 门控`thread_mode ? qconf->proc_id : 0`；`:423` **专段**「⚠ 脆弱耦合（必须显式登记，gate-design E2）」含「双重依赖 `__thread ff_stack_inited` 早返回」完整推演；`:606` D7 表新增 `main_loop` 行；`:1001` DoD-4「D7 专项（不可省）」要求 1+2 进程实测且两个日志都 `grep "out of range"` |
| **3. E4~E9** | ✅ 5 项已修，1 项 nit | E4 ✅ `:1126` 为 `uma_int.h:540`/`:566`；**E5 ✅ 未被我的错误建议改坏**——`:1131` 仍是正确的 `lib/Makefile:347`；E6 ⚠ nit-1；E7 ✅ `:474` 用正确 HEAD `:582` **并主动纠正我的 `:586`**；E8 ✅ §6.15；E9 ✅ 已从「歧义」升级为「**不可达/死代码**」（`:725-726`） |
| **4. `reviewer` 必改-2** | ✅ **PASS（完整重写，前提我独立坐实）** | `:566` L1 判据整体重写：**(c) 升首选**（节点数与登记次数不符，§4.7.5 给早期检测式「不必等崩溃」）、**(a′)** 崩点定位到 `vtoslab()`(`uma_int.h:77-88`,`:87 return NULL`)→`uma_core.c:4930`→`:4938 slab->us_domain` 或 `:5819`、**⛔ 禁用**「崩在 `uma_int.h:101/102`」。**我的独立核验**：`vtozoneslab` 全树调用者仅 `freebsd/kern/kern_malloc.c:943/1039/1136`，而 `git show HEAD:lib/Makefile \| grep kern_malloc` → **零命中** ⇒ **确为死代码、原判据恒不可触发** ✓；`uma_core.c:4930`/`:5819` 我 `sed` 实测**逐行精确** ✓ |
| **5. G2-S1** | ✅ **PASS（我独立坐实）** | §6.1 `:714-716` 写入两项事实并**下调定级**（「可能内存破坏」→「插入丢失→`vtoslab()` 返 NULL→调用者解引用崩溃」，fail-fast 可定位）。**独立核验**：`grep -rn "LIST_REMOVE\|le_prev" lib/include/vm/uma_int.h lib/ff_freebsd_init.c` → **NONE**；该哈希仅 `:125LIST_INSERT_HEAD` + `:84/:97/:111 LIST_FOREACH` ⇒ **只增不删、`le_prev` 无消费者、无 UAF 均成立** ✓ |
| **7. §8 提交计划** | ⚠ 清单正确，操作说明缺失（必改-4/-5） | commit-1 **8 文件**清单完整正确：含 **§4.10 `uma_page_slab_hash` 提前**（`:1052`，并在 `:1074` 警示「**不是探针、不得随探针删掉**」——很到位）、`ff_kern_synch.c` 兜底（`:1057`）、`curcpu`（`:1055`）；commit-2 **仅 2 文件**且「不得混入任何其它改动」。**commit message✅ 合规**：英文、commit-1 主题 1 句 + 正文 2 句、commit-2 主题 1 句 + 正文 1 句，均在 1~3 句内，且说明了 `uma_page_slab_hash` 提前的原因 |
| **8. DoD-8** | ⚠ 原则正确、清单/行号错 | 「探针须正向修改删除、不适用 `rm_tmp_file.sh`」的原则正确（`:1025`），但处数/行号错（必改-4）、产物清单不全（必改-6） |

## 10.5 复审边界（诚实声明）

- 按 leader 指示**未重跑**前几轮已通过的约 85 处证据链；本轮只做 21 处新实测。
- `_m17_F_runtime.md` 我**只核对了 leader 点名的数字与诚实边界的出处**（`:284/:657/:659/:846-847/:1145/:1294-1362`），**未逐行复核该 84KB 报告全文**，**未重跑任何压测**。
- §6.19 的 2.34 MiB 推导、`ipi_smr` 基址一致性（§7.1 ⚠）、3 线程离群根因：**均仍未坐实**，spec 标注正确，我无法静态定论。
- 全程**静态审核 + 文件系统实测，无任何运行时验证**。
- bounce 计数：M2 = **1/3**（仅第 1 轮 FAIL 计 1 次）。
