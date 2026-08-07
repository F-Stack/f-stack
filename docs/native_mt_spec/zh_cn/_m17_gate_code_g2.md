# _m17_gate_code_g2：G2 代码门禁审核（reviewer）

> 审核对象：`coder` 的 **G2-b（移除 `uma_crit_lock` 全局自旋锁）**，自述报告 `_m17_G_coder_g2.md`（24,147 B，mtime 15:28）。
> 角色分离：写 = `coder`，审 = `reviewer`（本文作者）。我**未修改任何源码**，唯一写入文件为本文件。未 `git commit`，未触碰 `config.ini`。
> 所有结论均来自**实际打开代码 / 实际执行命令**；凡未实测者显式标注「未核实」。

**审核基准**：`git diff` 终态；`git status --short freebsd/` 输出为**空**（上游树零改动，实测）。

---

## 0. 结论

# **PASS-with-fixes**

- **阻断项：0 条** → **不阻断 M5 去锁后复测**，可立即开跑。
- **必改项：2 条**（1条代码注释措辞、1 条 spec 判据），均为 P2，可与 M5 并行。
- G2-b 的**实现忠实于 spec §4.7裁决**，`uma_crit_lock` 删除**彻底**，clean build 与 md5 **与 coder 完全对账一致**。
- 我对 G2 的核心正确性论证做了**两条独立路径的验证**，结论：**G2 对 SMR 零影响**（可证），**UMA per-cpu cache 不变式在所有进入上下文中成立**（可证）；慢路径窗口放大是**真实残留风险**，但我发现了两项 spec 未记录的**减risk 事实**（见 §5.3），实际风险低于 spec 的假设。

---

## 1. 逐项审核表

| # | 审核项 | 判定 | 依据 |
|---|---|---|---|
| 1 | 改动是否严格等于 spec §4.7 的 G2-b（宏 vs inline 等价性） | **通过** | §2 |
| 2 | `uma_crit_lock` 删除彻底性（grep + nm/objdump） | **通过** | §3 |
| 3 | G1/G2 改动集可分性（能否干净拆两个 commit） | **通过**（可干净拆分，方案见 §4） | §4 |
| 4 | clean build 复验+ md5 对账 | **通过**（md5 与 coder **一致**） | §6 |
| 5 | G2 正确性论证复核（SMR + 不变式全上下文成立性） | **通过**（我用两条独立路径证实） | §5 |
| 6 | L1/L2 降级判据是否可用 | **不通过 → 必改-2**（L1 判据 (a) **不可达**，非仅歧义） | §7 |
| 7 | 注释规约 | **不通过 → 必改-1**（措辞陈述了一个**错误的**理由） | §8 |
| 8 | M5 复测要求 | 已给出（§9） | §9 |

---

## 2. 审核项 1：改动是否严格等于 G2-b —— 通过

### 2.1 改动集=恰好 2 处，与 spec §4.7.1 的 G2-b 逐字一致

`lib/include/vm/uma_int.h`（`+6/-8`）：删`extern volatile int uma_crit_lock;` 与两个自旋锁宏，替换为 `do {} while(0)` 空操作 + 3 行注释。
`lib/ff_glue.c`（该文件 `+7/-1`，其中 **`-1` 属G2**）：删 `:146 volatile int uma_crit_lock;`。

- **未擅自变成 G2-a**（未给 `ZDOM_LOCK`/`KEG_LOCK` 补真锁）✓：全diff 无任何 `mtx_init`/新锁变量。
- **未擅自变成 G2-c**（未缩小锁范围）✓：是彻底移除而非收窄。
- **未加任何新锁** ✓：`grep` 全 diff 无新增 `__sync_lock_test_and_set`/`pthread_mutex`/`mtx_*`。
- → **忠实实现 G2-b** ✓

### 2.2 保留为「空操作宏」而非「删除宏」—— 我判定这是**正确选择**，且两种形态对 `uma_core.c` **功能等价**

先坐实「即使落回上游也是空操作」：`freebsd/sys/systm.h:179-193`
```c
#if (defined(KLD_MODULE) && !defined(KLD_TIED)) || defined(KTR_CRITICAL) || !defined(_KERNEL) || defined(GENOFFSET)
#define critical_enter() critical_enter_KBI()
...
#else
static __inline void critical_enter(void)
{
#ifndef FSTACK
        struct thread_lite *td;
        td = (struct thread_lite *)curthread;
        td->td_critnest++;
        atomic_interrupt_fence();
#endif
}
```
- f-stack lib 构建下 `_KERNEL` 已定义、`KLD_MODULE`/`KTR_CRITICAL`/`GENOFFSET` 均未定义 →走 **`#else` 分支的 inline**；其函数体**整体在 `#ifndef FSTACK` 内** → **FSTACK 下是空函数体**（连 `atomic_interrupt_fence()` 都不在）✓
- 因此「删除宏 → 落回 inline」**也是空操作**，与保留空宏在**生成代码上完全一致**（都是零指令、零屏障）。

**宏形态 vs inline 形态对 `uma_core.c` 是否完全等价 —— 我的判定：等价，理由有三，且我逐条实测：**
1. **语法位置**：宏展开为 `do {} while(0)` 是**语句**，不能用于表达式位置。我逐一核对 `uma_core.c` 的全部 21 处调用（`:1451,1464,3727,3744,3775,3817,3859,3891,3900,3916,3918,4541,4554,4558,4626,4649,4653,4827,4850,4872,4874`）—— **全部为独占一行的语句位置**（形如 `\tcritical_enter();`），**无任何表达式位置使用** →宏形态安全 ✓
2. **无宏重定义警告**：`systm.h` 在当前编译配置下走的是 **inline 分支**（非 `#define` 分支），故 `uma_int.h` 的 `#define critical_enter()` **不构成宏重定义** → 无 `-Wmacro-redefined`。与我实测 warning 数仍为 **51**（零新增）相符✓
3. **屏障语义**：两者都**不含**任何编译器屏障或内存屏障（inline 版的 `atomic_interrupt_fence()` 被 `#ifndef FSTACK` 排除）→ 对编译器重排的约束**完全相同** ✓

**保留空宏优于删除宏的理由（我支持 coder 的选择）**：空宏使「此处刻意无保护」在`uma_int.h` 就地可见并可挂注释；删除宏会让读者以为仍有上游的 `td_critnest` 语义，需追两层 `#ifdef` 才能确认为空。

### 2.3 宏改动的**影响半径 = `uma_core.c` 单一TU**（我独立收敛，coder 报告未给这个边界）

`lib/include/vm/uma_int.h` 的宏只对 **include 它** 的 TU 生效。全树include 者共 7 个：
`freebsd/vm/{memguard.c, uma_core.c, uma_dbg.c, vm_page.c}`、`freebsd/kern/{kern_malloc.c, subr_vmem.c}`、`lib/ff_freebsd_init.c`。
与 `lib/Makefile` SRCS 交叉过滤后**在编译集合内的只有 2 个**：`uma_core.c`（`VM_SRCS`）与 `lib/ff_freebsd_init.c`（`FF_SRCS`）。
而 `lib/ff_freebsd_init.c` 的 `critical_enter|smr_enter` 命中数为 **0**（实测）→不受影响。
→ **G2 的行为改变严格局限于 `uma_core.c`**，正是预期目标，无溢出 ✓

---

## 3. 审核项 2：`uma_crit_lock` 删除彻底性 —— 通过

**全仓 grep（我自己重跑，无目录排除，含 `freebsd/`、`tools/`、`tests/`、`*.mk`）**：
```
grep -rn "uma_crit_lock" .（排除 .git/ 与 docs/）
→ 零命中
```
（`grep` 有效性自校验：同一模式在 `docs/` 下正常命中 3 个文件 —— `14-多线程crash深挖阶段性分析.md`、`_m17_gate_code_g1.md`、`plan-17-SMP-aware-pcpu-smr.md` → 证明不是模式写错导致的假阴性✓）

**符号级核验（我自己跑，基于我自己的 clean build）**：
```
nm      libfstack.a | grep -c uma_crit_lock  → 0
objdump -t libfstack.a | grep -c uma_crit_lock  → 0
```
**无任何 TU 仍 `extern` 它** ✓（唯一的 `extern` 声明在 `uma_int.h`，已随宏一并删除；定义在 `ff_glue.c:146`，已删）。
`example/` 链接 `undefined reference` 数 = **0** → 不存在「某 TU 仍引用但库里已无定义」的情况 ✓

→ 删除**彻底**，coder 自报数据经我独立复核**成立**。

---

## 4. 审核项 3：G1/G2 改动集可分性 —— 通过，可干净拆分

`lib/ff_glue.c` 是唯一同时承载 G1 与 G2 改动的文件。我用 `git diff -U0` 取精确 hunk 边界：
```
@@ -146+145,0 @@ u_int mp_maxid;                ← G2：删 uma_crit_lock 定义（1 行）
@@ -171,0 +171,7 @@ SYSCTL_INT(_kern_smp, ... topology ...)  ← G1：加 smp_topo() stub（7 行）
```
**两个 hunk 相距约 25 行、上下文零重叠** → `git add -p` 会将其呈现为**两个独立 hunk**，可分别 stage ✓

**推荐拆分方案（满足 spec §4.7.5 + D8 的独立提交要求）**：
- **commit-1（G1）**：`lib/Makefile`、`lib/ff_dpdk_if.c`、`lib/ff_dpdk_if.h`、`lib/ff_freebsd_init.c`、`lib/ff_kern_synch.c`、`lib/ff_kern_timeout.c`、`lib/include/sys/pcpu.h`（+ 探针相关 `lib/ff_host_interface.c/.h`，若届时未摘除）、以及 `lib/ff_glue.c` 的 **hunk 2 only**（`git add -p` 选 `s`/`y`）。
- **commit-2（G2）**：`lib/include/vm/uma_int.h` + `lib/ff_glue.c` 的 **hunk 1 only**。

**两个 commit 各自可独立编译（我已推演）**：
- commit-1 落地后的中间态：`uma_int.h` 仍含 `extern volatile int uma_crit_lock;` + 自旋锁宏，`ff_glue.c` 仍含其定义 → **声明与定义配对完整，可编译可链接** ✓
- commit-2 把声明与定义**同时**移除 → 亦配对完整 ✓
→ 满足 L0 台阶「commit-2 可单独 `git revert` 而不影响 G1」：revert 只回退 `uma_int.h` 全文与 `ff_glue.c` 的 `:146` 一行，与 G1 的 `smp_topo` 区域（`:171+`）**无交集，不会冲突** ✓

**提交顺序提醒（与 G1 审核的 R-d 联动）**：6 处 `#if1 /* M17 temporary probe */` 探针须在 M5 结束后摘除。若在 commit-1 之前摘除，则 commit-1 不含 `ff_host_interface.c/.h`；若 M5 之后才摘除，则需第三个「清理 commit」。建议 **M5 结束 → 摘探针 → 再拆 commit-1/commit-2**，避免探针代码进入产品提交（DoD-8）。

---

## 5. 审核项 5：G2 正确性论证复核（最关键）

### 5.1 「SMR 读侧从不受 `uma_crit_lock` 保护」—— **成立**，我用**两条独立路径**证实（强于 coder 的预处理行号证据）

`freebsd/sys/smr.h` 的 `smr_enter()`/`smr_exit()` 内部确实调用 `critical_enter()`/`critical_exit()`（`smr.h:109/167/178/218`）。问题在于**这些调用点看到的是哪个版本的 `critical_enter`**。

**路径 A（调用方视角，决定性）**：全编译集合内调用 `smr_enter`/`smr_exit` 的 TU 共 5 个（另 3 个`kern_rangelock.c`/`subr_pctrie.c`/`vfs_cache.c` 不在 SRCS）。逐一核验其是否 include `vm/uma_int.h`：

| TU | 在 SRCS | `grep -c uma_int.h` |
|---|---|---|
| `freebsd/netinet/in_pcb.c` | ✓ | **0** |
| `freebsd/netinet6/in6_pcb.c` | ✓ | **0** |
| `freebsd/netinet/tcp_hostcache.c` | ✓ | **0** |
| `freebsd/kern/subr_smr.c` | ✓ | **0** |
| `freebsd/kern/kern_descrip.c` | ✓ | **0** |

→ **全部为 0** → 这些 TU 的 `smr_enter()` 展开的是 `systm.h` 的**空 inline**，**从来不是** `uma_crit_lock` 自旋锁 ✓

**路径 B（唯一受影响 TU 的视角）**：`uma_core.c` 是唯一「`critical_enter` 曾等于自旋锁」的 TU。实测其`smr_enter`/`smr_exit` 调用点数 = **0**（只用 `smr_poll`(`:807,1064`)、`smr_wait`(`:1355`)、`smr_advance`(`:1407,4687,4837`)、`smr_create`(`:3024`)、`smr_synchronize`(`:4969`)，这些**都不含 critical section**）。

→ 两条路径交叉印证：**G2 对 SMR 的影响可证为零**，不是「大概不影响」✓ coder 的结论正确。

### 5.2 「每线程独占 `uz_cpu[curcpu]`」不变式在**所有**进入 UMA 的上下文中是否成立 —— 成立

**先修正一个关键论证基础（这也是必改-1 的由来）**：上游 `critical_enter()` 的作用是**禁止抢占/迁移**，从而保证 `curcpu` 在临界区内不变。f-stack 的栈线程是**普通 pthread，会被 Linux 调度器抢占和迁核**——所以「用户态无抢占」是**错的**。G2 之所以安全，真正的理由是：
> **f-stack 的 `curcpu` 已是「线程绑定」而非「CPU 绑定」**（`lib/include/sys/pcpu.h:34 #define curcpu PCPU_GET(cpuid)` → `pcpup->pc_cpuid`，`pcpup` 是 `__thread`）。因此**抢占与迁核都不会改变本线程的 `curcpu` 取值**，临界区对「保持 `curcpu` 稳定」这一目的**本就无必要**。

这一点有代码旁证：`uma_core.c:4534` 在 `critical_enter()`（`:4541`）**之前**已取 `cache = &zone->uz_cpu[curcpu]`，进入临界区后 `:4543` **再取一次** —— 上游需要重取是因为迁核会改 `curcpu`；f-stack 下两次取值**恒等**，重取无害。

**逐上下文核验「无并发共享槽位」**：

| # | 进入 UMA 的上下文 | 是否与他人并发 | 依据 |
|---|---|---|---|
| 1 | 主线程 `ff_freebsd_init()` → `uma_startup1/2` → `mi_startup()` 期**大量建 zone** | **否** | worker 由 `ff_run()` → `ff_dpdk_run()` → `rte_eal_mp_remote_launch()`（`ff_dpdk_if.c:2863`）创建，而 `ff_run()` 由应用在 **`ff_init()` 返回之后**才调用（`ff_init.c:38-52` 顺序：`ff_load_config`→`ff_dpdk_init`→`ff_freebsd_init`→`ff_dpdk_if_up`）→ **`mi_startup()` 期进程内只有主线程** ✓ |
| 2 | 主线程 `ff_dpdk_if_up()`（`ff_veth_attach` 建 ifnet，走 UMA） | **否** | 同样在 `ff_init()` 内，仍早于 `ff_run()` ✓ |
| 3 | worker 进入 `main_loop()` **之后、`ff_stack_thread_init()` 之前** | 不触UMA | `main_loop` 序言（`ff_dpdk_if.c:2636-2655`）逐条核对：局部声明、`rte_get_tsc_hz()`、`prev_tsc=0`、`usch_tsc=0`、`qconf = ff_cur_lcore_conf()`（纯数组取址）→ **无任何 UMA 调用** ✓ |
| 4 | worker `ff_stack_thread_init()` 内 | 槽位已就绪 | `ff_pcpu_thread_init(cpuid)` 是上锁后的**第一个**动作（`ff_freebsd_init.c:240-242`），其后才有 `ff_callout_thread_init`/`vnet_alloc`/`lo_set_defaultaddr` 等走 UMA 的调用 ✓ 且 `pcpu_init` 保证 `pc_cpuid = cpuid` 稠密唯一 |
| 5 | worker 稳态`main_loop` 收发包 | 各用自己的槽 | `curcpu` 为线程常量、`ff_pcpu_thread_init` 的上界检查（`:106-108`）保证 `cpuid ≤ mp_maxid`、G1 实测四线程 `uz_cpu` 地址公差 128 且两两不同（`_m17_gate_code_g1.md` §9.4②）✓ |
| 6 | `ff_pthread_create()` 应用线程（**D9**） | `pcpup == NULL` → fail-fast | **已文档化为不支持用法**：spec §5-1、§4.5、D8/D9 对齐表（`17-...md:508/603/652/717`）均明确「不加通用 NULL 兜底，fail-fast 是刻意选择」，并**唯一例外**保留了我在 G1 建议的 `pause_sbt()` 引导窗口定点兜底（§4.5(i)）✓ |
| 7 | DPDK 自有线程（intr / telemetry 等） | 不进f-stack UMA | 这些线程不调用任何 `ff_*` 协议栈 API（**未穷举核实**，见 §10-③） |

→ **不变式在全部受支持上下文中成立** ✓ G2 的快路径保护充分。

### 5.3慢路径窗口放大 —— 真实残留风险，但我发现**两项spec 未记录的减风险事实**

**风险确认（与 D8 ③一致）**：f-stack 中 `ZONE_LOCK`/`ZDOM_LOCK`/`KEG_LOCK` 及全部 `mtx` 已是 `((void)0)`（`lib/include/sys/mutex.h`，`kern_mutex.c` 不在 SRCS）→ zone/keg/`uma_page` 哈希的慢路径**本来就无锁**，此前仅靠 `uma_crit_lock` **附带地**串行化。G2 移除后窗口确实放大。这正是 designer 选 G2-b（接受 + 记录 + 降级台阶）的语境。

**但我发现两项减风险事实（`uma_int.h` 全文实测，spec §6.1/§6.2 未记录）**：
1. **`uma_page` 哈希是「只增不删」的**：全文件只有 `LIST_INSERT_HEAD`（`:123`），**没有任何 `LIST_REMOVE`**（实测 `grep -n "LIST_REMOVE\|LIST_INSERT" lib/include/vm/uma_int.h` 仅 1 行命中）→ 节点**永不摘除、永不释放** → 无锁读者**不可能读到已释放节点（无 UAF）**，最坏只是「漏看一个刚插入的节点」。这把最危险的一类并发故障（UAF /悬垂指针）**从根本上排除**。
2. **`le_prev` 反向指针永不被读**：`LIST_REMOVE` 从不使用 → 即使并发插入把 `le_prev` 写乱，也无消费者 → 无害。

→ **实际最坏故障模式收敛为「插入丢失」**：两线程并发对**同一桶** `LIST_INSERT_HEAD`，可能一次插入被覆盖（节点被孤立但不释放）→ 该页在哈希中查不到 → `vtoslab()` 返回 **NULL** → 由调用方解引用而崩。**注意：崩点在 `uma_core.c`，不在 `uma_int.h:101`** —— 这直接推翻了 spec 的 L1 触发判据（见 §7）。

---

## 6. 审核项 4：clean build 复验（我自己跑）+ md5 对账 —— 通过且**对账一致**

```
cd /data/workspace/f-stack/lib     && make clean && make -j16
cd /data/workspace/f-stack/example && make clean && make
```

| 指标 | 我的实测值 | coder 自报 | 门槛 | 判定 |
|---|---|---|---|---|
| `lib` `make` 返回码 | **0** | 0 | 0 | 通过 |
| `lib` `grep -c "error:"` | **0** | 0 | 0 | 通过 |
| `lib` `grep -c "warning:"` | **51** | 51 |≤ 51（HEAD 基线） | 通过（**去锁零新增 warning**） |
| `lib` `.o` 产出数 | **248** | — | 248 | 通过 |
| `nm libfstack.a \| grep -c uma_crit_lock` | **0** | 0 | 0 | 通过 |
| `objdump -t libfstack.a \| grep -c uma_crit_lock` | **0** | — | 0 | 通过（我额外加验） |
| `example` `make` 返回码 | **0** | 0 | 0 | 通过 |
| `example` `error:` / `undefined reference` | **0** / **0** | 0 / — | 0 | 通过 |
| `example/helloworld` 大小 | **30,392,664** B | 30,392,664 B | — | **一致** |
| **`example/helloworld` md5** | **`78c39a6f96e104412ce75351e402907b`** | `78c39a6f96e104412ce75351e402907b` | — | ✅ **完全一致** |

**md5 对账结论**：本轮 **coder 与我的 md5 完全一致**，与上一轮（G1，coder `d49268db…` vs 我 `751a8153…`）的错配情况不同。结合我在 G1 审核 §9.5 已实证的「`helloworld` md5 可复现、`libfstack.a` md5 不可复现（`ar` 内嵌 mtime）」，本次一致性构成**「coder 与 reviewer 构建自同一源码状态」的有效证据** ✓ coder 报告 §3.3 采取的「md5 与 `make clean` 在同一命令序列内立即取得」的做法有效地修正了上一轮的流程瑕疵。

**G1 改动完好性核查（我独立核对`--numstat`）**：`Makefile 4/0`、`ff_dpdk_if.c 7/1`、`ff_dpdk_if.h 1/0`、`ff_freebsd_init.c 101/14`、`ff_host_interface.c 8/0`、`ff_host_interface.h 4/0`、`ff_kern_synch.c 3/1`、`ff_kern_timeout.c 3/3`、`include/sys/pcpu.h 1/1` —— **与我在 `_m17_gate_code_g1.md` §9 审定的 G1 终态逐项相同**；`ff_glue.c` 由 `7/0` 变为 `7/1`（新增的 `-1` 即 G2 删除行）。→ **G2 是纯增量，G1 完好未被扰动** ✓

**临时日志** `_rv_g2_lib.log` / `_rv_g2_ex.log` 已按规约用 `/data/workspace/rm_tmp_file.sh` 清理。

---

## 7. 审核项 6：L1/L2 降级判据是否可用 —— **不通过（必改-2）**

### 7.1 L1 触发判据 (a) **不可达**，故整个复合判据**恒不成立**

spec §4.7.4 的 L1 触发判据为「**(a)** 崩溃点在 `lib/include/vm/uma_int.h:101 *slab = up->up_slab;` 或 `:102` **且 (b)** … **或 (c)** …」。`gate-design` E9 指出的问题是「该行也会因查表未命中而崩 → 有歧义」。

**我的复核结论比E9 更强：该行在本build 中根本不会被执行。**

- `:101/:102` 位于 **`vtozoneslab()`**（当前文件 `:88-101`，实测）。
- `vtozoneslab()` 在全仓的**唯一调用者是 `freebsd/kern/kern_malloc.c:943/1039/1136`**，而 **`kern_malloc.c` 不在 `lib/Makefile` SRCS**（`grep -c kern_malloc lib/Makefile` = **0**；f-stack 的 `malloc/free` 由 `ff_glue.c:1067/1085` 自行实现，走宿主 `ff_malloc`）。
- → **`vtozoneslab()` 是死代码**，`:101` **永不执行**。
- → 判据 (a) 恒假；而 L1 要求「(a) 且 (b/c)之一」→ **整个 L1 触发条件恒不成立，L1 台阶永远无法启动**。

（此结论与我在 `_m17_gate_code_g1.md` §9.1 的发现一致：当时我为确认 `VTOSLAB` 置位是否让该缺陷变得可达而穷举过它的调用者。）

### 7.2 必改-2：L1 判据的修正建议（依据 §5.3 推导出的真实故障模式）

**真实故障链**（`uma_page` 哈希只增不删 ⟹ 无UAF ⟹ 最坏是插入丢失）：
并发 `LIST_INSERT_HEAD` 丢失一次插入 → 该页在哈希中查不到 → **`vtoslab()`（`uma_int.h:83-88`，未命中返回 `NULL`）返回 NULL** → 调用方解引用 NULL 而崩。
`vtoslab()` 的**活跃**调用者（与 `vtozoneslab` 相反，这两处真的会跑）：
- `uma_core.c:4930`（`zone_release()` 内，`__predict_true((zone->uz_flags & UMA_ZFLAG_VTOSLAB) != 0)` 分支）
- `uma_core.c:5819`（`if (zone->uz_flags & UMA_ZFLAG_VTOSLAB) return (vtoslab((vm_offset_t)mem));`）

**建议把 (a) 改为 (a')**：
> **(a')** 崩溃/挂起的栈帧位于 **`vtoslab()`（`lib/include/vm/uma_int.h:83-88`）内部**（链表自环导致的死循环或野指针读），**或**位于 `uma_core.c:4930` / `:5819` 取得 `slab == NULL` 之后的解引用处（典型栈帧：`uma_zfree_arg` / `zone_release` / `zone_free_item`）。

**(b) 保持不变**（「只在 `thread_mode=1` 且 `nb_threads ≥ 2` 复现」仍是有效的并发判别器）。
**(c) 保持不变，并建议升为首选判据**：桶内自环 / 重复 `up_va` / 节点数与 `uk_ppera` 累计登记数不符。补充一条更直接的检测式：**因为从不 `LIST_REMOVE`，「已登记页节点数 < 按 `uk_ppera` 累计的应登记数」即可直接判定发生过插入丢失**，无需等崩溃。

### 7.3 spec 点名要我复核的 L1 内存序论证 —— **部分成立，须补编译器屏障**

spec §4.7.4 L1 的论证（标注【未坐实（推导）】并写明「须 `reviewer` 复核」）：只给写侧 `vsetzoneslab()` 加锁、读侧不加锁，理由是 `:122-125` 先填 `up_va`/`up_slab`/`up_zone` 再 `LIST_INSERT_HEAD` 发布，x86-TSO 下存储保序，读者不会看到半初始化节点。

**我的判定**：
- **硬件层面成立** ✓：x86-TSO 不允许 store→store 重排，读者若看到 `lh_first == up`，必然也看到先前对 `up->up_*` 的写入。
- **编译器层面不成立**✗：`LIST_INSERT_HEAD`（`sys/queue.h`）是**普通非volatile、非原子**赋值，**无 release 语义、无编译器屏障**。编译器可以合法地把 `up->up_va = va` 等存储**下沉到** `head->lh_first = up` 之后（单线程语义下不可观测）。上游对并发链表用的是 `CK_LIST`/`ck_queue` 的 `atomic_store_rel` 正是为此。
- **若采纳 L1，最小补强**：在 `LIST_INSERT_HEAD` 之前插入编译器屏障（`__compiler_membar()` / `atomic_thread_fence_rel()`），或把发布写改为 `atomic_store_rel_ptr(&hash_list->lh_first, up)`。
- **该论证未覆盖的一处**：`vsetzoneslab()` 的**「命中即改」分支**（`:117-121` 对既有节点原地改写 `up_slab`/`up_zone`）——读者可能读到两代之间的**撕裂组合**（`up_slab` 新、`up_zone` 旧）。这不是崩溃，而是**返回错配的 (zone, slab) 对**。若采纳 L1，应一并覆盖（例如读侧也加锁，或改为「新节点替换」而非原地改写）。
- **同时应记录减风险事实（§5.3）**：因从不 `LIST_REMOVE`，读侧不加锁**不存在 UAF**，故「读侧不加锁」这一取向本身是**比 spec 自己的论证所声称的更安全**的。

### 7.4 L2 判据 —— 可用

L2（`git revert` commit-2，保留 G1，把 `uma_crit_lock` 的必要性作为结论写回 spec，由 `reviewer` 门禁确认）**依赖的是 L1 失败或吞吐跌破 DoD-5**，不依赖那个不可达的行号 → **判据可用** ✓ 且 §4 已确认 commit-2 可干净 revert。

---

## 8. 审核项 7：注释规约 —— **不通过（必改-1）**

新增 3 行注释（`lib/include/vm/uma_int.h:44-47`）：
```c
/*
 * No preemption in f-stack userspace; UMA per-cpu cache is protected by each
 * stack thread owning a distinct dense pcpu slot (spec 17 §2.4).
 */
```
- **必要性**：✓ 必要。此处是「刻意移除保护」的位置，不写注释后人无从判断是不是漏删。
- **长度**：✓ 3 行不啰嗦，符合最小注释规约。
- **准确性**：✗ **第一个分句「No preemption in f-stack userspace」是错误陈述**。f-stack 的栈线程是普通 pthread，**会被 Linux 调度器抢占、也会迁核**；「用户态无抢占」不成立。G2 安全的真正理由是 **`curcpu` 已绑定到线程而非 CPU**（`lib/include/sys/pcpu.h:34` → `pcpup->pc_cpuid`，`pcpup` 为 `__thread`），故抢占/迁核**不改变**本线程使用的 `uz_cpu[]` 槽位（详见 §5.2，含 `uma_core.c:4534` vs `:4543` 两次取 `curcpu` 恒等的代码旁证）。

**定级：必改（P2）。** 与 G1 的必改-2（`ff_kern_timeout.c` 假注释 `cpuid is always 0, MAXCPU=1`）**同一类问题、同一判定标准** —— 错误注释比无注释更有害，且此处承载的是「为何可以去锁」这一最高风险决策的书面依据，后人若据「无抢占」这一错误前提继续移除其它保护会引入真实缺陷。

**建议改法（保持 3 行）**：
```c
/*
 * curcpu is per-thread here (sys/pcpu.h), not per-CPU, so preemption cannot
 * change which uz_cpu[] slot this thread uses and no other thread uses it;
 * the dense pcpu slot is the whole protection (spec 17 §2.4).
 */
```

---

## 9. 审核项 8：M5 去锁后必须重跑的判定式（请leader 转 `tester`）

**核心要求：G2 去锁后，槽位隔离成为 UMA per-cpu cache 的唯一保护，因此 G1 的槽位判定式必须全部重跑，不得沿用 G1 轮次的数据。**

**A. 槽位隔离5 项判定式（逐档位2/3/4 线程各跑一次）** —— 判据与 `_m17_gate_code_g1.md` §9.4② 相同，**特别注意分字段步长**：
1. `pc_cpuid == dense_idx == curcpu`
2. `pc_zpcpu_offset == 4096 * dense_idx`
3. `smr_c_seq` 构成公差 **4096** 的等差数列
4. `uma_cache` 构成公差 **128**（`= sizeof(struct uma_cache)`）的等差数列且两两互不相同 —— **⚠ 不是 4096，套用 4096 会误判 FAIL**
5. `uk_ppera == mp_maxid + 1`

**B. G2 专属新增项**：
6. **soak 必做**（DoD-4，60s / 400 连接）：这是慢路径无锁窗口放大的**唯一**检测器（§5.3）。
7. **崩溃分类按修正后的 (a') 判据**（§7.2），**不要**去比对 `uma_int.h:101`（该行不可达）。
8. **建议加一条无需等崩溃的直接检测**：soak 结束后统计 `uma_page_slab_hash` 全桶节点数，与按 `uk_ppera` 累计的应登记页数比对；**因哈希只增不删，两者不等即证明发生过并发插入丢失**（比等崩溃更早、更确定）。
9. **吞吐对账**：与 G1 轮次（未去锁）同档位对比。coder 自测 2 线程 219,241.92 req/s、4 线程 391,271.39 req/s，但其§4.4 已自限「可比性有限」→ **M5 须在同一方法学下重测G1/G2 两个版本**，否则不能作为 DoD-5 的判据。

**C. 版本 pin**：被测二进制 `example/helloworld` md5 必须为 **`78c39a6f96e104412ce75351e402907b`**（30,392,664 B）；不符先 `make clean && make`。

---

## 10. 未核实边界（诚实记录）

1. **G2 的运行期行为我未亲自跑**：本轮只做静态审查+ clean build + 符号核验。coder 自测的吞吐（2 线程 219,241.92 / 4 线程 391,271.39 req/s）与「不崩、槽位隔离维持」**我未复现**，且coder 自己已限定其可比性（§4.4）→ 一律待 M5。
2. **慢路径窗口放大的实际严重程度未量化**：§5.3 我把最坏故障模式收敛为「插入丢失」并排除了 UAF，但**放大到什么程度、soak 下是否真会触发，静态分析无法定论**（与 spec §6.1「U8-perf」的诚实标注一致）。
3. **DPDK 自有线程（intr / telemetry / KNI 等）是否绝不进入 f-stack UMA，我未穷举核实**（§5.2 表第 7 行）。判断依据是「它们不调用 `ff_*` 协议栈 API」，属合理推断而非穷举实证。
4. **`sys/queue.h` 的 `LIST_INSERT_HEAD` 展开我未逐字打开**（§7.3 的编译器重排论证基于「普通非原子赋值、无屏障」这一通用事实）；若 designer 要采纳 L1，建议再打开确认一次具体展开。
5. **我未验证 `git add -p` 的实际交互结果**（§4 的拆分方案基于 `git diff -U0` 的 hunk 边界推演，未真正执行 stage —— 按规约我不做 `git add`/`commit`）。
6. **spec 全文我只复核了 §4.7 / §5-1 / §6.1 / §6.2 与 D8/D9 对齐条目**，未逐章审 906 行全文（那是 `gate-design` 的职责范围）。

---

## 11. 必改项清单

| # | 级别 | 位置 | 问题 | 建议改法 |
|---|---|---|---|---|
| **必改-1** | P2 · 注释错误陈述 | `lib/include/vm/uma_int.h:45`（`coder`） | 「No preemption in f-stack userspace」**是错的**（栈线程是普通 pthread，会被抢占/迁核）。G2 安全的真正理由是 `curcpu` **绑线程不绑 CPU**。此处承载「为何可去锁」的书面依据，错误前提会误导后续维护者继续移除其它保护 | 见 §8 给出的 3 行替换文本|
| **必改-2** | P2 · spec 判据不可达 | spec §4.7.4 的 L1 触发判据 (a)（`designer`） | 判据 (a) 指向 `uma_int.h:101`，但 `vtozoneslab()` 在本 build 中是**死代码**（唯一调用者 `kern_malloc.c` 不在 SRCS）→ **该行永不执行 → L1 恒不可触发**。E9 说的「歧义」实际是「不可达」 | 改为 §7.2 的 (a')：崩点在 `vtoslab()` 内或`uma_core.c:4930`/`:5819` 取得 `slab==NULL` 后的解引用处；并把 (c) 升为首选判据、增加「哈希节点数比对」的早期检测式 |

## 12. 建议改项（非阻断）

| # | 内容 |
|---|---|
| G2-S1 | spec §6.1/§6.2 增记§5.3 的两项**减风险事实**：`uma_page` 哈希**只增不删**（无 `LIST_REMOVE`）⟹ 无 UAF、`le_prev` 无消费者⟹ 最坏故障收敛为「插入丢失」。这会实质下调该风险的定级 |
| G2-S2 | 若将来采纳 L1：须补编译器屏障 / release store（§7.3），并处理 `vsetzoneslab()`「命中即改」分支的撕裂读（§7.3 末段） |
| G2-S3 | 提交顺序：建议 **M5 结束 → 摘 6 处探针（DoD-8）→ 再拆 commit-1(G1)/commit-2(G2)**，避免探针进入产品提交；`ff_glue.c` 用 `git add -p` 分 hunk（§4） |
| G2-S4 | spec 可补记：G2 的行为改变**严格局限于 `uma_core.c` 单一 TU**（§2.3 的影响半径收敛），这让 G2 的风险面比「全局宏改动」的直觉小得多 |
| G2-S5 | `coder` 报告 §2.2「残留 4 处 `critical_enter/exit` 来自 `smr.h`」的表述建议补一句：那4 处是 `smr_enter/smr_exit` 的 **inline 函数体**，而 `uma_core.c` **从不调用**这两个函数（实测 0 命中）→ 故与 G2 无关的理由比「它们是既有行为」更强（§5.1路径 B） |

---

## 13. 结论重申

- **M4 门禁：PASS-with-fixes**，**必改 2 条**（均 P2：1 条注释措辞@coder、1 条 spec 判据 @designer），**阻断项 0 条**。
- **不阻断 M5 去锁后复测** —— 可立即开跑；两条必改与 M5 并行即可。
- G2-b 实现忠实、删除彻底、影响半径收敛于 `uma_core.c`、对 SMR 可证零影响、快路径不变式全上下文成立、clean build 与 md5 与 `coder` **完全对账一致**（error 0 / warning 51 / 248 `.o` / `helloworld` md5 `78c39a6f96e104412ce75351e402907b`）。
- 唯一需要 M5 用运行期数据回答的是**慢路径无锁窗口放大**，而我已把其最坏故障模式从「不确定的破链」收敛为「插入丢失」，并给出了**不必等崩溃**的早期检测式（§9-B8）。

---

# 14. 探针摘除复核（leader 接管，reviewer 审）

> 角色分离：`coder` 无响应 → **leader 接管写操作** → 本节由 `reviewer`（子agent）审核，符合「写 ≠ 审」铁律。
> 这是 **M7 提交前的最后一道门禁**。所有结论均为我实际打开代码 / 实际执行命令所得。
> 我**未修改任何源码**，唯一写入文件仍为本文件。

## 14.0 结论

# **PASS**（附 1 条必改，P3· 纯 diff 噪声，**不影响功能、不阻断提交**）

- 产品改动 **10 处全部完整保留**，逐字核对无一处受损。
- 探针**零残留**（源码层 0 命中；`ff_host_interface.c`/`.h` 逐字回到 HEAD）。
- clean build 与 `helloworld` md5 **与 leader 完全对账一致**。
- **提交拆法判定为「正确可行」**，但我给出 **5 条强制安全措施**（§14.4）——其中 1 条是必须补做的验证。
- 顺带确认：我在 §11 提的**G2 必改-1 与必改-2 均已闭环**（§14.6）。

## 14.1 审核项 1：只摘了探针、没伤产品代码 —— **通过（10/10 完整保留）**

逐字核对 `git diff` 全文，G1/G2 的产品改动**全部在位**：

| # | 产品改动 | 位置（工作区） | 核验 |
|---|---|---|---|
| 1 | `-DSMP` | `lib/Makefile:221-223`（+2 行注释） | ✓在位 |
| 2 | `smp_topo()` stub 返回 NULL | `lib/ff_glue.c:171-177` | ✓ 在位 |
| 3 | 三元组 `mp_ncpus`/`mp_maxid`/`all_cpus` + 时序注释 | `ff_freebsd_init.c:298-317` | ✓ 在位（`mp_ncpus = nb_cpus; mp_maxid = nb_cpus - 1;` + `CPU_SET` 循环） |
| 4 | `uma_page_slab_hash` **提前到 `uma_startup1()` 之前** | `ff_freebsd_init.c:322-330` 在 `:332-336` 的 `uma_startup1` 之前；原位置的 3 行已删除 | ✓ 在位（崩溃修复完好） |
| 5 | `ff_pcpu_thread_init` **真正使用形参** + 上界 `panic` | `ff_freebsd_init.c:106-112`（`if (cpuid < 0 \|\| (u_int)cpuid > mp_maxid) panic(...)` + `pcpu_init(pcpup, cpuid, ...)`） | ✓ 在位 |
| 6 | 主线程稠密取号（含 `thread_mode` 门控） | `ff_freebsd_init.c:317` `ff_pcpu_thread_init(ff_global_cfg.dpdk.thread_mode ? ff_cur_proc_id() : 0);` | ✓ 在位 |
| 6b | worker 稠密取号（含 `thread_mode` 门控） | `ff_dpdk_if.c:2652` `ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0);` | ✓ 在位 |
| 6c | `ff_cur_proc_id()` 定义 + 原型 | `ff_dpdk_if.c:412-417`、`ff_dpdk_if.h:81`、`ff_freebsd_init.c:73-74` 的 `extern` | ✓ 三处齐备 |
| 7 | `timeout_cpu` → `static __thread` + **修正后的**注释 | `ff_kern_timeout.c:190`；`:180-181` 注释已是 G1 必改-2 的修正版（无 `cpuid is always 0, MAXCPU=1`） | ✓ 在位 |
| 8 | `pause_wchan` 兜底 | `ff_kern_synch.c:105-107` `&pause_wchan[pcpup != NULL ? curcpu : 0]` + 1 行注释 | ✓ 在位 |
| 9 | `curcpu` per-thread | `lib/include/sys/pcpu.h:34` `#define curcpu PCPU_GET(cpuid)`（`#undef curcpu` 保留于 `:32`） | ✓ 在位 |
| 10 | `critical_enter/exit` 空操作 + 删 `uma_crit_lock`（声明 + 定义） | `uma_int.h:44-50`（含**已修正**的注释）+ `ff_glue.c` 删 `:146` | ✓ 在位 |

**`ff_stack_thread_init()` 的 CM5-B 主体未被误伤**：该函数区域（`init_lock` 自旋 / `ff_pcpu_thread_init` / `ff_callout_thread_init` / `vnet_alloc` / `ff_worker_prison_init` / `lo_set_defaultaddr`）在 `git diff` 中**完全没有 hunk** → 即与 HEAD 逐字相同 → 摘除探针调用块后**干净复原**，未连带删掉任何产品语句 ✓
同理，两个 `static` 探针函数（`ff_probe_slots`/`ff_probe_pcpu_zone`）所在区域也**无 hunk 残留** → 整块干净移除 ✓

## 14.2 审核项 2：无残留 —— **通过**

- **源码层零残留**（我自己重跑）：
  `grep -rn "M17\|ff_probe\|temporary probe" lib/ --include=*.c --include=*.h --include=Makefile` → **0 命中**
  全仓 `grep -rn "ff_probe_tid\|ff_probe_slots\|ff_probe_pcpu_zone\|M17-PROBE" .`（排除 `.git/`、`docs/`、`*.log`、二进制）→ **0 命中**
  > 说明：`grep "PROBE"` 会命中一批**无关的既有内容** —— `lib/ff_kern_timeout.c:89/90/493/495` 的 `SDT_PROBE_DEFINE1`/`SDT_PROBE1`（上游 DTrace 宏）与 `lib/{cryptodev_if,device_if,bus_if,vnode_if}.h` 的 `DEVICE_PROBE`/`SDT_PROBES_ENABLED`（构建期由 `.m` 生成的头文件）。**均与 M17 无关**，不构成残留。
- **`ff_host_interface.c` / `.h` 逐字回到 HEAD** ✓：`git --no-pager diff --stat lib/ff_host_interface.c lib/ff_host_interface.h` → **输出为空**；且两文件已从 `git status` 的修改列表中消失。
- **二进制层残留已随重编消失** ✓（我自己的 clean build 后核验）：
  `nm libfstack.a | grep -c uma_crit_lock` → **0**；`nm libfstack.a | grep -c ff_probe` → **0**
- **改动集收敛为 9 个文件**，`--numstat` 与 leader 自报一致（76 insertions / 29 deletions）。
- `git status --short freebsd/` → **空**（上游树零改动）✓

## 14.3 审核项 3：clean build 复验（我自己跑）—— **通过，md5 与 leader 一致**

```
cd /data/workspace/f-stack/lib     && make clean && make -j16
cd /data/workspace/f-stack/example && make clean && make
```

| 指标 | 我的实测值 | leader 自报 | 门槛 | 判定 |
|---|---|---|---|---|
| `lib` `make` 返回码 | **0** | 0 | 0 | 通过 |
| `lib` `grep -c "error:"` | **0** | 0 | 0 | 通过 |
| `lib` `grep -c "warning:"` | **51** | 51 | ≤ 51（HEAD 基线） | 通过（摘探针零变化） |
| `lib` `.o` 产出数 | **248** | — | 248 | 通过 |
| `nm libfstack.a \| grep -c uma_crit_lock` | **0** | — | 0 | 通过 |
| `nm libfstack.a \| grep -c ff_probe` | **0** | — | 0 | 通过（我额外加验） |
| `example` `make` 返回码 | **0** | 0 | 0 | 通过 |
| `example` `error:` / `undefined reference` | **0** / **0** | 0 | 0 | 通过 |
| `example/helloworld` 大小 | **30,392,632** B | 30,392,632 B | — | **一致** |
| **`example/helloworld` md5** | **`df05d2cd078d631ad2d8ee7caba8d387`** | `df05d2cd078d631ad2d8ee7caba8d387` | — | ✅ **完全一致** |

结合我在 `_m17_gate_code_g1.md` §9.5 已实证的「`helloworld` md5 可复现」，本次一致构成「leader 与 reviewer 构建自同一源码状态」的有效证据 ✓
临时日志 `_rv_fin_lib.log` / `_rv_fin_ex.log` 已用 `/data/workspace/rm_tmp_file.sh` 清理。

## 14.4 审核项 4：提交划分可行性 —— **判定：拆法正确可行**，但须加 5 条安全措施

### 14.4.1 拆法本身正确

leader 的方案（commit-1 临时把 `volatile int uma_crit_lock;` 加回 → 提交 8 文件；commit-2 再删掉 → 提交 `ff_glue.c` + `uma_int.h`）**逻辑正确**，理由：

- **commit-1 的树状态自洽**：`uma_int.h` 停留在 HEAD（含 `extern volatile int uma_crit_lock;` + 自旋锁宏）**要求**一个定义，而临时加回的 `ff_glue.c:146` 正好提供它 → **声明/定义配对完整**，编译与链接均成立。
- **commit-2 把声明与定义同时移除** → 亦配对完整。
- **两个 commit 的并集 = 当前工作区状态**（`ff_glue.c` 的临时行在 commit-2 被删回）→ 最终树正确。

### 14.4.2 commit-1 可编译性：证据链成立，**但该确切树状态从未被编译过 → 必须补验**

- 支持性证据：`-DSMP` + **HEAD 版 `uma_int.h`（自旋锁宏）** 这一组合在 M3 期间被我**成功 clean build 至少 3 次**（`_m17_gate_code_g1.md` §3、§8.2、§9.5，均 error 0 / warning 51 / 248 `.o`）；`uma_core.c` 的 21 处 `critical_enter/exit` 全在语句位置、与 HEAD 相同。
- 但 commit-1 = 「G1 **且已摘除探针**」，而**摘除探针后的 G1（未去锁）状态我和 leader 都没有单独编译过**（我们编的都是「摘探针 + 已去锁」的最终态）。差异仅限`ff_freebsd_init.c` 的探针块与 `ff_host_interface.c/.h`，与 `uma_int.h` 正交，**推断可编译**，但属推断。
- → **强制措施 S3（见下）**：在 commit-1 提交前后（此时工作区就是 commit-1 的状态）跑一次 `make clean && make` 实证。

**附带好消息（利于 bisect）**：commit-1 的语义状态 = 「G1 已落地、锁未移除」，正是 M5 实测过的 `example/helloworld_g1_prelock` 对应配置 → **该中间提交是运行期已验证过的状态**，`git bisect` 落在此提交上不会踩到未验证组合。

### 14.4.3 commit-2 可单独 `git revert` —— **成立**

commit-2 只触及两处：`ff_glue.c` 的 `:146`（1 行删除）与 `uma_int.h:44-50`（宏块替换）。
`git revert commit-2` 将重新加回该行并恢复自旋锁宏。**G1 的 `smp_topo` 区域在 `ff_glue.c:171+`，与 `:146` 相距约 25 行、无上下文重叠**（我用 `git diff -U0` 实测两hunk 为 `@@ -146 +145,0 @@` 与 `@@ -171,0 +171,7 @@`）→ revert 不会触碰 G1 区域、不会冲突 ✓ → **spec §4.7.4 的 L0 台阶（commit-2 可单独 revert 而不影响 G1）成立**。

### 14.4.4 更稳妥做法评估 —— **结论：leader 的做法已是最优，无需更换**

我评估了两个「不改工作区」的替代方案，**均不如现方案**：
- `git add -p`：**无法非交互执行**（leader 已指出），排除。
- `git diff lib/ff_glue.c` 拆 hunk 后 `git apply --cached`：可非交互，但**hunk 行号有偏移风险** —— G1 hunk 的头`@@ -171,0 +171,7 @@` 是在「G2 的 `-1` 删除已应用」的前提下算出的；单独往 HEAD 索引上打会产生 ±1 行偏移，依赖 `git apply` 的模糊匹配，**更脆弱**。
→ 因此 **维持 leader 的方案**（直接构造 commit-1 的文件内容 = HEAD + `smp_topo` 块），它最直观、无行号依赖。

### 14.4.5 强制安全措施（5 条，S1/S3/S4 为必做）

| # | 措施 | 理由 |
|---|---|---|
| **S1**（必做） | **先修§14.5 的必改（多余空行），再开始提交**。修完用 `git diff -w lib/ff_freebsd_init.c` 与修前对比 —— 若二者相同，即**证明该修改是纯空白改动、零语义变化**，故 M5 与冒烟结果**可直接沿用无需重测**；但须**重跑一次 clean build 取新md5** 作为 M7 的版本pin（我这份 `df05d2cd…` 对应**修前**状态） | 避免把 diff 噪声提交进产品历史；同时给出「无需重测」的严格论证 |
| **S2**（必做） | **严禁 `git add .` / `git add -A` / `git commit -a`**，必须逐个显式路径。`config.ini` 正处于` M` 且含本机测试值，任何通配 add 都会把它带进去 | 这是本仓已发生过两次的历史事故（AI memory 44404940：提交 `4b605b02d`、`7b6bcca2f` 均误带本地测试值） |
| **S3**（必做） | **commit-1 提交前（工作区已是其状态时）跑一次 `make clean && make`**（`lib/` + `example/`），确认 error 0 / warning 51 / 248 `.o` | §14.4.2：该确切树状态从未被编译过，不可只凭推断 |
| S4（强烈建议） | **commit-2 之后做三项端到端一致性核验**：① `git status --short lib/` 必须**干净**（证明临时加回的那行已确实删回）；② `git diff HEAD~2 --stat lib/` 必须等于 **9 文件 / 75 insertions / 29 deletions**（修完空行后的预期值）；③ `make clean && make` 复现S1 记录的新 md5 | 端到端证明「两个 commit 的并集 == 审核通过的最终态」，防止临时编辑残留 |
| S5（强烈建议） | 对两个 commit 各跑 `git show --stat<commit>`，肉眼确认**不含 `config.ini`、不含任何 `.log`/二进制/`*.ini` 临时文件** | 提交内容最终把关 |

**commit message（按 AI memory 73362122，英文、1-3 句）建议**：
- commit-1：`Make the FreeBSD kernel view SMP-aware with per-thread dense pcpu slots.` + 简述 `-DSMP`、三元组、稠密取号、`curcpu` per-thread、`uma_page_slab_hash` 前置修复。
- commit-2：`Remove the global uma_crit_lock now that each stack thread owns a distinct pcpu slot.`

## 14.5 必改项（1 条）

| # | 级别 | 位置 | 问题 | 改法 |
|---|---|---|---|---|
| **必改-3** | **P3 · 纯 diff 噪声（不影响功能）** | `lib/ff_freebsd_init.c`，`ff_stack_inited = 1;` 与 `return (0);` 之间 | 摘除探针块时**多留了一个空行**：HEAD 此处为 **1 个**空行，当前工作区为 **2 个**（我用 `cat -A` 与 `git show HEAD:...` 逐字对比确认）。这产生了一个**纯空白的 diff hunk** `@@ -347,5 +375,6 @@`（1 行`+` 空行），会作为无意义噪声进入产品提交 | 删掉其中一个空行，使该 hunk **完全消失**。修后预期：`ff_freebsd_init.c` 的 `--numstat` 由 **43/14→ 42/14**，`lib/` 合计由 **76/29 → 75/29** |

> 定级说明：这不影响任何功能，我判为 **P3**，**不构成提交阻断**；但既然本项目有「零不必要的 diff 字节」的一贯要求（且我在 G1/G2 已两次以同一标准判过注释类问题），提交前顺手修掉最干净。**若 leader 决定不修，我也不改判FAIL**，只需在提交说明中知悉即可。

## 14.6顺带确认：我在 §11 提的 2 条 G2 必改**均已闭环**

| 原必改 | 状态 | 依据 |
|---|---|---|
| **G2 必改-1**（`uma_int.h` 注释「No preemption in f-stack userspace」是错误陈述） | ✅ **已修** | 现注释为 `curcpu is per-thread here (sys/pcpu.h), not per-CPU, so preemption cannot change which uz_cpu[] slot this thread uses and no other thread uses it; the dense pcpu slot is the whole protection (spec 17 §2.4).` —— 与我 §8 给出的替换文本**逐字一致**，错误前提已消除 |
| **G2 必改-2**（spec §4.7.4 的 L1 判据 (a) 指向死代码、恒不可触发） | ✅ **已修** | spec（mtime 16:21）§4.7.4 的 L1 判据**整体重写**：**(c) 升为首选**（哈希结构异常直接证据 + 不必等崩溃的早期检测式）、**(a′) 次选**（崩点须落在 `vtoslab()` 返回 NULL 后被解引用处，具体到 `uma_core.c:4930 → :4938 slab->us_domain` 与 `:5819`）、**(b) 佐证**（仅 `thread_mode=1 && nb_threads≥2` 复现），并加 **⛔ 明确禁止**再用 `uma_int.h:101/102` 并附「`vtozoneslab()` 唯一调用者 `kern_malloc.c` 不在 SRCS ⇒ 死代码」的坐实说明。（残留的 2 处 `uma_int.h:101` 字样均在该 ⛔ 解释文本内，属正确用法而非漏改） |
| 建议项 G2-S1 / G2-S2 | ✅ 均已采纳 | S1（哈希只增不删⇒ 无 UAF、最坏为插入丢失）见 spec `:735` 的风险**下调**表述；S2（编译器屏障 / release store + 「命中即改」撕裂读）见 §4.7.6 与 `:610-611`，且 designer 进一步坐实「`vtoslab()` 不读 `up_zone` ⇒ 该撕裂读在当前编译集合内无消费者」 |

## 14.7 审核项 5：不应进入提交的文件（我完整枚举）

**A. 已跟踪但绝不可入库（1 个）**
- **`config.ini`**（` M`，14 insertions / 12 deletions）：含本机测试值 `lcore_mask=6` / `thread_mode=1` / `idle_sleep=20` / `addr=<DPDK_NIC_IP>` 等。**绝不入库**（AI memory 44404940）。

**B. 未跟踪的临时产物 —— 全部不可入库**
- **二进制（5 个，注意：这些 `.gitignore` 覆盖不到！）**：`example/helloworld_g1_prelock`、`example/helloworld_g2_nolock`、`example/helloworld_zc_base`、`example/helloworld_zc_recv`、`example/helloworld_stacksel/helloworld_stacksel`
  > **实测风险点**：`example/helloworld` 本体**已被 `.gitignore:12` 忽略**，但上述**改名/复制**的二进制**未被任何 ignore 规则覆盖**（`git check-ignore` 对 `helloworld_g1_prelock` 无输出）→ 一旦 `git add .` 就会把 5 个约 30 MB 的二进制提交进仓库。这是 S2 禁令最现实的危害。
- **日志（16 个）**：`_m17_final_lib.log`、`_m17_final_ex.log`、`a.log`、`f-stack-0.log`、`helloworld.log`、`ipv6diag_hello.log`、`start.log`，以及 `example/` 下的 `f-stack-0.log`、`f-stack-1.log`、`helloworld.log`、`helloworld_cm7{,_fix,_fix2,_mt,_mt2,_mt3}.log`、`m17_g2_2t.log`、`m17_g2_4t.log`
- **测试配置（3 个）**：`config.m17_g2_2t.ini`、`config.m17_g2_4t.ini`、`config.test-dpdk24-multi.ini`
- **其它（3 个）**：`dkdns_ospf.sh`（与本项目无关的脚本）、`dpdk.bak-23.11.5/`（大体积备份目录）、`.codebuddy/`（**注意：按项目规约此目录不得删除，但同样不得提交**）
- **`tests/unit/fixtures/valid_thread_mode.ini`**：可能是有意新增的单测 fixture，但**与 G1/G2 无关** → 不应混入这两个 commit；如确需入库请另开提交。

**C. 文档（14 个未跟踪）—— 建议独立第 3 个 commit，不要混入 commit-1/commit-2**
我核对了本仓既有惯例（`git ls-files docs/native_mt_spec/zh_cn/`）：**编号 spec（`00-`…`16-`）、`plan-16-…`、以及 `_m1_A_codepath.md`/`_m1_B_external.md`/`_m4_D_review.md`/`_material_*.md` 这类中间工作文档全部是被跟踪的** → 说明**本项目的惯例确实包含提交 `_m*` 过程文档**。因此这 14 个文件（`17-SMP-aware-pcpu视图与去全局锁.md`、`plan-17-…md`、`_m17_A`…`_m17_G`、`_m17_gate_*`、`_m17_C_probe_diff_A.patch`）**符合惯例、可以入库**，但请：
1. 放到**独立的 docs commit**（第 3 个），保持 commit-1/commit-2 为纯代码提交，便于 `git revert` 与 `git bisect`；
2. 提交前确认 `_m17_C_probe_diff_A.patch` 是否确为要留档的内容（它是 M1 期的探针 patch，若只是过程垃圾可不入库）。

## 14.8 未核实边界（诚实记录）

1. **我未编译 commit-1 的确切树状态**（§14.4.2）——按规约我不修改源码、不做 `git add`/`commit`，故无法构造该中间态。结论「可编译」是**基于证据链的推断**，因此把实证列为强制措施 **S3**。
2. **我未复现 leader 的冒烟测试**（2 线程 236,273.85 req/s、零error、日志无 `M17|panic|Segmentation|assert`）。我只做了静态核对 + clean build +符号核验。
3. **必改-3 修复后的 md5 我无法预先给出**：删空行理论上不改变生成代码，但若 `panic()`/断言宏内嵌 `__LINE__`/`__FILE__` 则可能变化。故 S1 要求**修后重新测量并以新值作 pin**；`git diff -w` 相同即可证明语义未变。
4. **我未逐字审 spec 全文**（906+ 行），§14.6 只复核了与我§11 两条必改直接相关的 §4.7.4 / §4.7.6 / §6 段落。
5. **`tests/unit/fixtures/valid_thread_mode.ini` 的用途我未核实**（是否为有意新增的单测 fixture）。

## 14.9 结论重申

- **探针摘除复核：PASS。** 产品改动 10/10 完整、探针零残留、`ff_host_interface.c/.h` 逐字回 HEAD、clean build 与 md5 与 leader **完全对账一致**（error 0 / warning 51 / 248 `.o` / `helloworld` `df05d2cd078d631ad2d8ee7caba8d387`）。
- **必改 1 条（必改-3，P3 纯空白噪声）**，**不阻断提交**；建议提交前顺手修掉并按 S1 重新 pin md5。
- **提交拆法：正确可行**（commit-1 树自洽、commit-2 可单独 `git revert`、L0 台阶成立），须执行 **S1/S3/S4 三项必做验证**，并严守 **S2「禁止通配 `git add`」**——本仓有 5 个未被 `.gitignore` 覆盖的 30 MB 级二进制，通配 add 的后果最严重。
- 我在 §11 提的 **2 条 G2 必改 + 2 条建议项均已闭环** → **M7 提交条件已具备**。
