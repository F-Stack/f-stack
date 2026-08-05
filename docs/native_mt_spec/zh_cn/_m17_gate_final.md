# M17 提交前门禁（reviewer2 独立复核）

- 审核人：`reviewer2`（只审不改；本轮未执行任何 `git add` / `git commit` / `git checkout` / `git stash`）
- 审核对象：leader 接管完成的「临时探针摘除」+「G1/G2 两段提交拆分方案」
- 仓库：`/data/workspace/f-stack`，HEAD = `ff09a17b2`
- 审核时间：2026-08-04
- 所有结论均由**实际执行命令 / 打开文件**得出；无法坐实处显式标注「未核实」。

---

# 总结论：**PASS-with-fixes —— 可以提交**

- **阻断项：0 条。**
- **必改项：1 条（R2-1，纯空白行噪声，删除后不影响 codegen，md5 必须仍为 `df05d2cd…`；见§7）。**
- **建议项：3 条（R2-S1 提交手法更稳妥做法、R2-S2 spec 17 文档未纳入提交、R2-S3 tracked 单测引用了 untracked fixture；见 §8）。**

给leader 的操作结论：**先做 §7 的 1 行空白清理（无需重编，md5 不变），然后按 §5 的拆分方案提交即可**；强烈建议采用 §8 R2-S1 的`git apply --cached` 手法替代「手工加回/再删 `uma_crit_lock` 那行」。

| # | 审核项 | 结论 | 章节 |
|---|---|---|---|
| 1 | 只摘探针、G1/G2 产品改动完整保留且语义正确 | **通过** | §1 |
| 2 | 探针无残留、`ff_host_interface.c/.h` 逐字回到 HEAD | **通过** | §2 |
| 3 | clean build 复验（自跑）+ md5 对账 | **通过（md5/字节数与 leader 完全一致）** | §3 |
| 4 |提交拆分方案（①可编译 ②可单独 revert ③更稳妥做法） | **通过（①②成立，③给出更优手法）** | §5 |
| 5 | 提交范围检查（`config.ini` 绝不入库+ 临时产物清单） | **通过（清单见 §6）** | §6 |
| 6 | commit message 规约（英文、1-3 句、简明） | **commit-2 通过；commit-1 判定过长 → 给出精简版** | §9 |
| 7 | 纯空白行噪声 | **不通过 → 必改R2-1** | §7 |

---

## 1. 审核项 1：只摘了探针、产品改动完整保留

依据：`git --no-pager diff --stat lib/` + `git --no-pager diff -U6/-U8 lib/<file>` 逐处打开。

```
 lib/Makefile             |  4 ++++
 lib/ff_dpdk_if.c         |  8 ++++++-
 lib/ff_dpdk_if.h         |  1 +
 lib/ff_freebsd_init.c| 57 ++++++++++++++++++++++++++++++++++++------------
 lib/ff_glue.c            |  8 ++++++-
 lib/ff_kern_synch.c      |  4 +++-
 lib/ff_kern_timeout.c    |  6 ++---
 lib/include/sys/pcpu.h   |  2 +-
 lib/include/vm/uma_int.h | 15 ++++++-------
 9 files changed, 76 insertions(+), 29 deletions(-)
```

**文件集合 = 8（G1）+ `include/vm/uma_int.h`（G2）= 9，与 `_m17_E_coder_g1.md` §5.8 记录的 G1 最终态（8 文件，不含 `ff_host_interface.c/.h`）+ G2 完全吻合**，无多余文件。

### 1.1 G1 逐项核对（leader 列出的 8 项，全部在位）

| 项 | 期望 | 实测 diff | 判定 |
|---|---|---|---|
| a | `lib/Makefile` 加 `-DSMP` | `+CFLAGS+= -DSMP`（含 2 行必要注释，说明 MAXCPU 1024 vs 1） | ✓ |
| b | `ff_glue.c` 加 `smp_topo()` 返回 NULL stub | `+struct cpu_group * smp_topo(void) { return (NULL); }`，注释点名调用方 `tcp_hpts.c:1890` 须处理 NULL | ✓ |
| c | `uma_startup1()` **之前**设三元组 | `mp_ncpus = nb_cpus; mp_maxid = nb_cpus - 1; for (i...) CPU_SET(i, &all_cpus);` —— 位置在 `ff_pcpu_thread_init()` 之前、`uma_startup1()` 之前；`nb_cpus` 由 `thread_mode ? nb_threads : 1` 推出，含 `<1` 夹紧与 `>MAXCPU` 的 `panic` | ✓ |
| d | `uma_page_slab_hash`/`uma_page_mask` 提前到 `uma_startup1()` 之前 | 原处 3 行（`num_hash_buckets=8192` / `kmem_malloc` / `uma_page_mask`）被删，同3 行整体上移到 `boot_pages = 16;` 之前，即 `uma_startup1()` 之前；附3 行注释说明「`mp_maxid>0` → zone-of-zones 越过单页阈值 → `UMA_ZFLAG_VTOSLAB` → `keg_alloc_slab()` 在 `uma_startup1()` 内即调 `vsetzoneslab()`」= 3/4 线程崩溃的真实成因 | ✓ |
| e | `ff_pcpu_thread_init()` 真正使用形参 + 运行期上界 panic | `pcpu_init(pcpup, cpuid, ...)`（原为硬编码 `0`）；前置 `if (cpuid < 0 \|\| (u_int)cpuid > mp_maxid) panic(...)`；旧那段「cpuid must stay 0 / MAXCPU==1」的过时注释已整体替换为正确理由（含「`subr_pcpu.c`的 KASSERT 因无 INVARIANTS 被编掉」→ 说明为何要自己加上界检查） | ✓ |
| f | 主线程用稠密 `ff_cur_proc_id()` 取号 | `ff_pcpu_thread_init(ff_global_cfg.dpdk.thread_mode ? ff_cur_proc_id() : 0);`，并在文件顶部加 `extern int ff_cur_proc_id(void);` + `#include <sys/smp.h>` | ✓ |
| g | `ff_dpdk_if.c/.h` 新增 `ff_cur_proc_id()`、`main_loop` 传稠密号 | `ff_dpdk_if.c:412-416` 定义 `return ff_cur_lcore_conf()->proc_id;`；`ff_dpdk_if.h:81` 加原型；`main_loop`：`ff_stack_thread_init(rte_lcore_id())` → `ff_stack_thread_init(ff_global_cfg.dpdk.thread_mode ? qconf->proc_id : 0)` | ✓ |
| h | `ff_kern_timeout.c` `timeout_cpu` 改 `__thread` | `-static int timeout_cpu;` / `+static __thread int timeout_cpu;`；并把 G1 门禁「必改-2」点名的假注释（`cpuid is always 0, MAXCPU=1`）改成正确表述（「忽略 cpu 形参、返回本线程实例，`c_cpu` 只是记录哪个线程 arm 的 callout」） | ✓（含 G1 必改-2 落地） |
| i | `ff_kern_synch.c` `pause_wchan[curcpu]` 加 `pcpup != NULL` 兜底 | `_sleep(&pause_wchan[pcpup != NULL ? curcpu : 0], ...)` + 1 行注释说明可达路径（`malloc()` OOM retry，pcpu 尚未建立） | ✓ |
| j | `include/sys/pcpu.h` `#define curcpu 0` → `PCPU_GET(cpuid)` | `-#define curcpu    0` / `+#define curcpu    PCPU_GET(cpuid)` | ✓ |

### 1.2 G2 逐项核对

| 项 | 实测 | 判定 |
|---|---|---|
| `uma_int.h` `critical_enter/exit` 改空操作 | `#define critical_enter() do {} while(0)` / `critical_exit()` 同 | ✓ |
| `uma_int.h` 删 `extern volatile int uma_crit_lock;` | 已删 | ✓ |
| `ff_glue.c` 删 `volatile int uma_crit_lock;` 定义 | 已删（`u_int mp_maxid;` 下一行） | ✓ |
| **全树无悬空引用** | `grep -rn "uma_crit_lock" . --include=*.c --include=*.h` → **0 命中**（含 `freebsd/`、`example/`、`tools/`、`tests/`） | ✓ |
| G2 门禁「必改-1」（注释错误陈述）是否落地 | 新注释为「`curcpu` is per-thread here (sys/pcpu.h), not per-CPU, so preemption cannot change which `uz_cpu[]` slot this thread uses…」—— **已不再出现「No preemption in f-stack userspace」这一错误前提**，改为 reviewer 要求的「`curcpu` 绑线程不绑 CPU」正确理由 | ✓ |
| G2 门禁「必改-2」（spec §4.7.4 L1 判据 (a) 不可达）是否落地 | `17-...md:585` 已整体重写为 (c) 升首选 + (a′) 崩点落在 `vtoslab()` / `uma_core.c:4930` / `:5819`，并加⛔ 注明 `vtozoneslab()` 是死代码 | ✓ |

### 1.3 语义正确性抽查（我独立坐实，非沿用他人结论）

1. **`ff_cur_proc_id()` 在 `ff_freebsd_init()` 时点是否已可用** —— 坐实**可用**：`lib/ff_init.c:43,47,51` 的次序是 `ff_dpdk_init()` → `ff_freebsd_init()` → `ff_dpdk_if_up()`，而 `init_lcore_conf()` 在 `ff_dpdk_if.c:1674`（即 `ff_dpdk_init()` 内）已给 `lcore_conf[lcore_id].proc_id = ti`（`:439`）赋值。故取号时 `lcore_conf[]` 已就绪，不是未初始化读。
2. **取号稠密性** —— `ff_memory.h:105-108` `ff_lcore_conf_idx()` = `thread_mode ? rte_lcore_id() : 0`；`init_lcore_conf()` thread_mode 分支按 `ti = 0..nb_threads-1` 给 `proc_lcore[ti]` 对应的 lcore 赋 `proc_id = ti` → **`proc_id` 天然稠密 `[0, nb_threads-1]`**，与 `mp_maxid = nb_cpus - 1` 的上界检查自洽，`panic` 不会误伤。
3. **上界检查所依赖的 `mp_maxid` 已先于使用被赋值** —— 主线程路径：三元组赋值在 `ff_pcpu_thread_init()` 调用之前（同一函数内、顺序在前）；worker 路径：`ff_stack_thread_init()` → `ff_pcpu_thread_init()` 发生在 `main_loop`，远晚于 `ff_freebsd_init()`。✓ 无「用 `mp_maxid=0` 去校验 `cpuid=1`」的窗口。
4. **主线程与 `main_loop` 取号一致** —— `main_loop` 用 `qconf->proc_id`（`qconf = ff_cur_lcore_conf()`，`:2650`），与 `ff_cur_proc_id()` 完全同源；主线程作为 EAL main lcore 也会进`main_loop`，但 `ff_stack_inited = 1` 使其跳过重复 init，且两处号一致 → 不会出现「主线程 pcpu 用 A 号、callout 用 B 号」的错配。✓
5. **`thread_mode=0` 退化路径逐字等价** —— `nb_cpus=1` → `mp_ncpus=1`/`mp_maxid=0`/`all_cpus={0}`；`ff_pcpu_thread_init(0)`；`ff_lcore_conf_idx()`恒 0；`curcpu = PCPU_GET(cpuid) = 0`。与改前行为一致（与 `_m17_F_runtime.md:202` 的 D7 实测六项吻合）。✓

**审核项 1 判定：通过。** 未发现任何产品改动被摘除、削弱或语义改变；亦未发现探针代码被误留为产品代码。

---

## 2. 审核项 2：探针无残留

| 检查 | 命令 | 结果 | 判定 |
|---|---|---|---|
| `M17` 标记 | `grep -rn "M17" lib/ --include=*.c --include=*.h \| wc -l` | **0** | ✓ |
| `ff_probe` 函数 | `grep -rn "ff_probe" lib/ --include=*.c --include=*.h \| wc -l` | **0** | ✓ |
| `PROBE`（含既有FreeBSD 代码） | `grep -rn "M17\|ff_probe\|PROBE" lib/ --include=*.c --include=*.h` | 78 行，但**逐行核对全部为上游既有代码**：`cryptodev_if.h`/`device_if.h`/`bus_if.h` 的 `*_PROBE*` 方法宏、`vnode_if.h` 的 `SDT_PROBES_ENABLED()`、`ff_kern_timeout.c:89/90/493/495` 的 `SDT_PROBE_DEFINE1/SDT_PROBE1(callout_execute…)`（HEAD 即有，非本轮新增）。**9 个被改文件中 `grep -c 'M17\|ff_probe'` 全部为 0** | ✓（无M17 探针残留） |
| 探针日志语句残留 | `git --no-pager diff lib/ \| grep "^+" \| grep -i "probe\|M17\|fprintf\|printf\|stderr"` | **空**（本轮 diff 未新增任何一行打印语句） | ✓ |
| `ff_host_interface.c/.h` 是否逐字回到 HEAD | `git --no-pager diff lib/ff_host_interface.c lib/ff_host_interface.h \| wc -c` | **0 字节**；且 `git status --short` 中这两个文件**完全不出现** | ✓ |

**审核项 2 判定：通过。** 探针摘除彻底（`_m17_gate_code_g2.md:126` 要求的「摘 6 处 `#if 1 /* M17 temporary probe */`」+ `ff_probe_tid()` 含 `.h` 原型，均已 0 残留），且满足 G1 门禁 R-d 与 DoD-8「探针不得进入产品提交」。

---

## 3. 审核项 3：clean build 复验（reviewer2 自跑，先 `make clean`）

```
cd /data/workspace/f-stack/lib     && make clean && make -j16
cd /data/workspace/f-stack/example && make clean && make
```

| 指标 | reviewer2 实测 | 期望 / leader 值 | 判定 |
|---|---|---|---|
| `lib` 退出码 | **0** | 0 | ✓ |
| `lib` `grep -c "error:"` | **0** | 0 | ✓ |
| `lib` `grep -c "warning:"` | **51** | 51（HEAD 基线，见 `_m17_gate_code_g1.md:320/418/593`、`_m17_gate_code_g2.md:196`） | ✓ **零新增 warning** |
| `example` 退出码 | **0** | 0 | ✓ |
| `example` `error:` / `warning:` | **0 / 0** | 0 / 0 | ✓ |
| `example` `undefined reference` | **0** | 0 | ✓ |
| `example/helloworld` md5 | **`df05d2cd078d631ad2d8ee7caba8d387`** | leader 实测 `df05d2cd078d631ad2d8ee7caba8d387` | ✓ **逐字节一致** |
| `example/helloworld` 字节数 | **30392632** | 30,392,632 | ✓ |

原始日志：`/data/workspace/f-stack/_m17_r2_lib.log`、`_m17_r2_ex.log`（审核结束后已按规约用 `/data/workspace/rm_tmp_file.sh` 清理）。

**审核项 3 判定：通过。** 我在**独立 clean build** 下复现出与 leader **完全相同的 md5 与字节数** —— 这同时证明：(a) 构建可重现；(b) 当前工作区就是 leader 报告的那份代码，中途未被第三方改动；(c) `warning` 数回到 HEAD 基线 51，探针摘除未留下任何影响 codegen 的残渣。

> **未核实（如实标注）**：HEAD 基线 `warning = 51` 这个数字我**未自行 checkout HEAD 重测**（本轮禁止 `git checkout`），而是引用 `_m17_gate_code_g1.md` / `_m17_gate_code_g2.md` 中 reviewer 已独立复现过的值。我实测值 51 与之相等。

---

## 4. 提交拆分方案的事实基础（两个中间二进制的存在性）

这是判定 §5 ① 的关键实证，不是推测：

```
$ ls -l example/helloworld_g1_prelock example/helloworld_g2_nolock
-rwxr-xr-x 30392704 Aug  4 15:00 example/helloworld_g1_prelock
-rwxr-xr-x 30392664 Aug  4 15:10 example/helloworld_g2_nolock
$ md5sum ...
751a8153d3b200229cff99b3fa7650b0  example/helloworld_g1_prelock
78c39a6f96e104412ce75351e402907b  example/helloworld_g2_nolock
```

- `helloworld_g1_prelock`（md5 `751a8153…`）= **G1 + `uma_crit_lock` 仍在（去锁前）**，符号级判据 `uma_crit_lock` 计数 **1**（`_m17_F_runtime.md:1147-1166` 的 X0 章节，tester 提出、`res-build` 复核）。**该二进制不仅编译链接成功，还被 tester 完整跑过并 PASS**（`_m17_F_runtime.md:812/1095/1175`：复测全程 md5 pin 在 `751a8153…`，1/2/3/4 线程 + `thread_mode=0` 各档 DoD-1/4 PASS）。
- `helloworld_g2_nolock`（md5 `78c39a6f…`）= `uma_crit_lock` 计数 **0** = 去锁后，亦经交叉复测。
- 三者字节数关系自洽：`g1_prelock` 30,392,704 > `g2_nolock` 30,392,664 > 现产品 30,392,632 —— 前两者含探针、现产品已摘探针，**递减符合预期**，可反证「探针确已摘除」。

> **需leader 知悉的残余风险（非阻断）**：runtime DoD 全PASS 的被测二进制是**含探针**的 `751a8153…` / `78c39a6f…`；即将提交的 `df05d2cd…`（摘探针后）**未做运行时冒烟**。我判为**非阻断**，理由三条且均可坐实：(a) 探针为纯打印（`ff_probe_tid()` + `[M17-PROBE*]` 日志），不改控制流（`_m17_gate_code_g1.md:641` 已坐实）；(b) 探针唯一落地的 `ff_host_interface.c/.h` 现为 **0 字节 diff**、其余9 文件 diff 中**零新增打印语句**；(c)摘除后 clean build error0 / warning 回到基线 51 / undefined 0。**建议但不强制**：提交后由 `tester` 用 `df05d2cd…` 补一次 `thread_mode=1` 2 线程启动冒烟（约1 分钟），作为收尾留档。

---

## 5. 审核项 4：提交拆分方案判定

leader 计划（因 `git add -p` 无法非交互执行）：
- **commit-1（G1）**：临时把 `volatile int uma_crit_lock;` 加回 `ff_glue.c` → `git add lib/Makefile lib/ff_glue.c lib/ff_freebsd_init.c lib/ff_dpdk_if.c lib/ff_dpdk_if.h lib/ff_kern_synch.c lib/ff_kern_timeout.c lib/include/sys/pcpu.h` → commit（此时 `uma_int.h` 仍是 HEAD 版）。
- **commit-2（G2）**：再删掉该行 → `git add lib/ff_glue.c lib/include/vm/uma_int.h` → commit。

### ① commit-1 的树状态是否真的可编译 —— **是，成立（且已被实证跑通）**

- **静态自洽性坐实**：commit-1 树中 `lib/include/vm/uma_int.h` = HEAD 版，含 `extern volatile int uma_crit_lock;` + 自旋锁版 `critical_enter/exit`；`ff_glue.c` 含临时加回的 `volatile int uma_crit_lock;` **定义**。声明侧（`uma_int.h`，被 `freebsd/vm/uma_core.c` 等包含）与定义侧（`ff_glue.c` → `libfstack.a`）**成对存在** → 编译期符号可见、链接期可解析，不会 `undefined reference`。
- **全树无第三方引用**：`grep -rn "uma_crit_lock"` 当前 0 命中 ⇒ 该符号的**声明与定义总共只出现在这两个文件**，不存在「某第三个文件也引用它、commit-1 少加了那个文件」的风险。
- **实证**：commit-1 的树状态（G1 + 去锁前 `uma_int.h`）正是 `helloworld_g1_prelock`（md5 `751a8153…`、`uma_crit_lock` 符号计数 1）所对应的代码版本，**该版本已由 tester 完整编译并运行 PASS**（§4）。故 commit-1 不是「从未编译过的中间态」。
- **语义安全性补充坐实**：commit-1 树中 `curcpu` 已是 `PCPU_GET(cpuid)`（稠密、按线程互不相同），而 `critical_enter/exit` 仍是全局自旋锁 —— 这是**比最终态更保守**的组合（多余的串行化，不缺保护），不会引入 commit-2 才修的缺陷；`__sync_lock_test_and_set` 版临界区在 HEAD 即存在且已长期运行，G1 未新增其嵌套调用点→ 无新增自死锁面。

### ② commit-2 是否可单独 `git revert` 而不影响 G1 —— **可以**

- commit-2 只触及 2 个文件、共 3 处改动：`uma_int.h` 的 `extern` 删除 + 2 个宏改写（该文件**只被 commit-2 触及**，commit-1 完全未动→ revert 无冲突面）；`ff_glue.c` 的 1 行删除。
- `ff_glue.c` 的 hunk 隔离性已坐实：`git --no-pager diff lib/ff_glue.c | grep -c "^@@"` = **2**，两个 hunk 分别为
  - hunk1 `@@ -138,17 +138,16 @@`：删`volatile int uma_crit_lock;`（上下文 `volatile int smp_started; u_int mp_maxid;` /空行 + `static SYSCTL_NODE(_kern, OID_AUTO, smp, …)`）= **G2**；
  - hunk2 `@@ -164,16 +163,23 @@`：加 `smp_topo()` stub（上下文 `smp_topology` SYSCTL / `vn_lock_pair_pause_max`）= **G1**。
  两 hunk 相距约 25 行、**上下文互不重叠** → `git revert commit-2` 对 hunk1 的反向应用不会碰到 commit-1 引入的 `smp_topo()`，可干净应用。
- revert 后的树= G1-only + 去锁前 `uma_int.h` =与 `helloworld_g1_prelock` 同一代码版本 = **已实测可编译可运行的状态**，故 revert 出来的不是理论上的死代码路径。✓ 满足 DoD-5 回退门要求。

### ③ 有无更稳妥的做法 —— **有，见 §8 R2-S1（推荐替换 leader 的手工编辑法）**

leader 的手工加回/再删法**在结果上正确**，但有两点可避免的操作风险：(a) 需要两次手工编辑工作区文件，若第二次忘删或删错行，**最终 HEAD 就与已验证的 `df05d2cd…` 代码不一致**；(b) 中途工作区处于「既非 commit-1 亦非最终态」的第三种状态，若此刻被误编译/误跑会污染留档。R2-S1 给出不改动工作区、纯索引操作的等价手法。

**审核项 4 判定：通过。** ①②成立，③有更优手法但原方案亦可安全执行（须配合 §8 R2-S1 的最后一步 md5 回归校验）。

---

## 6. 审核项 5：提交范围检查

### 6.1 **绝对不得入库（已跟踪但被本地测试值污染）**

| 文件 | 状态 | 实测污染项 | 处置 |
|---|---|---|---|
| `config.ini` | ` M` | `lcore_mask` `1`→**`6`**；`#thread_mode=0`→**`thread_mode=1`**；`idle_sleep` `0`→**`20`**；`#fstack_log_level=0`→**`fstack_log_level=7`**、`#fstack_log_file_prefix`→**取消注释**；`[port0]` `addr` `192.168.1.2`→**`9.134.214.176`**（另留一行 `#addr=9.134.213.67`）、`netmask`→`255.255.248.0`、`broadcast`→`9.134.215.255`、`gateway`→`9.134.208.1`；`#addr6/#prefix_len/#gateway6`→**取消注释并填本机 `2402:4e00:…` / `prefix_len=128` / `fe80::feee:…`**（另留 `#gateway6=::1`） | **绝不 `git add`**。全部 8 处均为本地双网卡测试环境值，**无一处与 M17 特性相关**（M17 不含任何 config 项新增）。按强制规约（AI memory 44404940）必须保持不入库。 |

**判定：`config.ini` 逐项核实完毕 —— 100% 为本地运行环境残留，零特性相关改动，确认绝不入库。** 提交后应保持 ` M` 状态。

### 6.2 不应入库的未跟踪临时产物（`??`）

**二进制/中间产物**（注意 `example/helloworld` 已被 `.gitignore:12` 忽略，但下列**未被忽略**，`git check-ignore` 对 `helloworld_g1_prelock` 无命中）：
- `example/helloworld_g1_prelock`、`example/helloworld_g2_nolock`（M17 对照副本，30MB 级）
- `example/helloworld_zc_base`、`example/helloworld_zc_recv`、`example/helloworld_stacksel/helloworld_stacksel`（往期遗留 30MB 级二进制）
- `dpdk.bak-23.11.5/`（整个 DPDK 备份目录）

**日志**：`_m17_final_ex.log`、`_m17_final_lib.log`、`a.log`、`start.log`、`helloworld.log`、`f-stack-0.log`、`ipv6diag_hello.log`、`example/f-stack-0.log`、`example/f-stack-1.log`、`example/helloworld.log`、`example/helloworld_cm7.log`、`example/helloworld_cm7_fix.log`、`example/helloworld_cm7_fix2.log`、`example/helloworld_cm7_mt.log`、`example/helloworld_cm7_mt2.log`、`example/helloworld_cm7_mt3.log`、`example/m17_g2_2t.log`、`example/m17_g2_4t.log`，以及我本轮产生的 `_m17_r2_lib.log`、`_m17_r2_ex.log`（**已清理**）。

**测试用配置副本**：`config.m17_g2_2t.ini`、`config.m17_g2_4t.ini`、`config.test-dpdk24-multi.ini`（均含本机 IP/lcore 值）。

**其它**：`.codebuddy/`（IDE 数据目录，**不得删除**，但也**不入库**）、`dkdns_ospf.sh`（与 f-stack 无关的外部脚本）。

### 6.3 **需leader 单独决策、不要混入 commit-1/2 的 `??` 项**

| 文件 | 说明 | 建议 |
|---|---|---|
| `docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md` | **M17 主spec，当前未跟踪**；而 `git ls-files docs/native_mt_spec/` 显示 `00-`~`16-` **全部 17篇编号 spec 均已入库** →惯例上17 篇之后应继续入库 | **建议独立 commit-3（docs）**，见 §8 R2-S2 |
| `docs/native_mt_spec/zh_cn/_m17_A_codepath.md`等 12篇 `_m17_*.md` + `plan-17-*.md` + `_m17_C_probe_diff_A.patch` | 过程工作稿。历史上有先例入库（`_m1_A_codepath.md`/`_m1_B_external.md`/`_m4_D_review.md` 已跟踪），也有大量未入库 | leader 决策；**不要混入 commit-1/2** |
| `tests/unit/fixtures/valid_thread_mode.ini` | **已跟踪**的 `tests/unit/test_ff_config.c:1169/1204` 引用了它，而 fixture 本身未跟踪 → 当前仓库的单测对新克隆者是**坏的** | **建议独立 commit 修复**，见 §8 R2-S3；**不要混入 commit-1/2** |

### 6.4 操作硬约束

**严禁 `git add -A` / `git add .` / `git add lib/`**（后者会把 `lib/` 下潜在未跟踪物一并纳入）。**必须逐个显式列出 §5 方案中的 9 个文件路径**。leader 方案已是显式路径列表✓。

**审核项 5 判定：通过（清单如上）。**

---

## 7. 必改项 R2-1（唯一必改，P3 · 纯空白噪声）

**位置**：`lib/ff_freebsd_init.c` 函数 `ff_freebsd_init()` 末尾。

**问题**：`git --no-pager diff` 的最后一个 hunk 是一处**纯空白行新增**（`@@ -344,8 +372,9 @@` 内的孤立 `+`），实测（`tail -12 … | cat -A`）为：

```
    ff_stack_inited = 1;
<空行>
<空行>
    return (0);
}
```

即 `ff_stack_inited = 1;` 与 `return (0);` 之间出现**两个连续空行**。这是探针摘除后的残留（原探针代码占据此处），**对产品无任何语义/codegen 贡献**，属零价值 diff 噪声，违反「最小 diff / 只改必要处」的工程约束（与本项目「lib 最小注释」同源的降噪要求）。

**改法**：删除其中 **1 个空行**，恢复为单空行分隔。

**验证门（leader 自证，无需再走一轮审核）**：该修改为whitespace-only，**不影响任何 codegen**。故 leader 改完后重跑 clean build，`example/helloworld`的 md5 **必须仍为 `df05d2cd078d631ad2d8ee7caba8d387`、字节数仍为 30392632**；若 md5 发生任何变化，说明误删了非空白内容，**必须立即停止提交并回报**（此时才需要重新审核）。同时 `git --no-pager diff --stat lib/ff_freebsd_init.c` 的insertions 应由 57 变化中的该 hunk 消失（`+`/`-` 各减1 行量级）。

> 若 leader 判断此项不值得占用一次修改窗口，可**降级为「建议」并直接提交** —— 它不构成功能/正确性风险。我在结论中已按「PASS-with-fixes」处理，**不阻断提交**。

---

## 8. 建议改项（非阻断）

### R2-S1（强烈建议）：用`git apply --cached` 替代「手工加回再删」，全程不动工作区

`ff_glue.c` 恰好只有 2 个 hunk 且 G1/G2 各占其一（§5②已坐实），因此 `git add -p` 的非交互等价物是**按 hunk 生成补丁再只暂存G1 那个 hunk**：

1. 导出该文件补丁：`git --no-pager diff lib/ff_glue.c > /data/workspace/f-stack/_r2_glue.patch`
2. 用文本编辑从中**只保留 hunk2（`@@ -164,16 +163,23 @@`，即 `smp_topo()` 新增）**，另存为 `_r2_glue_g1.patch`（保留 `diff --git` / `--- a/` / `+++ b/` 三行头）
3. commit-1：`git add lib/Makefile lib/ff_freebsd_init.c lib/ff_dpdk_if.c lib/ff_dpdk_if.h lib/ff_kern_synch.c lib/ff_kern_timeout.c lib/include/sys/pcpu.h` + `git apply --cached /data/workspace/f-stack/_r2_glue_g1.patch` → `git commit`
4. commit-2：`git add lib/ff_glue.c lib/include/vm/uma_int.h` → `git commit`（此时 `ff_glue.c` 索引中剩下的正是 hunk1 的删除）
5. 收尾：`/data/workspace/rm_tmp_file.sh /data/workspace/f-stack/_r2_glue.patch /data/workspace/f-stack/_r2_glue_g1.patch`

**优势**：工作区文件**一次都不被修改**，因此不存在「忘记把临时行删回去」的窗口，最终 HEAD 必然等于已验证的 `df05d2cd…` 代码。可用 `git diff --cached --stat` 在每次 commit 前自检暂存内容。

**若 leader 仍用原手工法**，则必须补一步硬校验：commit-2 完成后执行 `git status --short lib/`（应**只剩空**，即 lib/ 全部改动已入库）+ `make clean && make` 重编，**确认 md5 仍为 `df05d2cd078d631ad2d8ee7caba8d387`**。

### R2-S2：M17 spec 文档未纳入提交计划

`docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md` 目前 `??`，而 `00-`~`16-` 全部编号 spec 均已入库（`git ls-files` 实测 25 项）。本次代码提交若不带上 17 篇，仓库将出现「代码已落地、设计依据缺失」的断层，且 commit message 中「spec 17 §2.4 / §4.7」的引用在库内**指向不存在的文件**（`uma_int.h` 新注释里就有 `spec 17 §2.4` 字样）。**建议追加 commit-3（docs-only）**：`git add "docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md"`（并由 leader 决定是否一并带上 `plan-17-*.md` 与各 `_m17_*.md`）。**不阻断** commit-1/2。

### R2-S3：tracked 单测引用了 untracked fixture（既有缺陷，非 M17 引入）

`tests/unit/test_ff_config.c:1169` `load_with_fixture(FIXTURE_PATH("valid_thread_mode.ini"))` 与 `:1204` 均引用 `tests/unit/fixtures/valid_thread_mode.ini`，但该 fixture **未跟踪**（`git ls-files tests/unit/fixtures` 中无它）。→ 新克隆者跑单测会缺文件失败。属早前`thread_mode` 配置提交的遗漏，**与 M17 无关**。建议独立小 commit 补齐，**不要混入** commit-1/2。

---

## 9. 审核项 6：commit message 判定

规约：**英文、1-3 句、简单总结干了什么**。

### commit-1 —— **不通过（过长）**

leader 拟稿为**单句 61 词**，一句内塞了 5 个并列技术细节 + 1 句效果说明，属「详细技术描述」而非「简单总结」，与本项目历史 commit 风格（如 HEAD `ff09a17b2` 亦偏长，但 `82b409faf`「Drive per-thread callwheel on native-mt worker lcores」为佳例）相比明显冗长。**建议精简版（2 句，主题行≤72 字符）**：

```
Make the f-stack kernel view SMP-aware for native-mt

Define SMP and set mp_ncpus/mp_maxid/all_cpus from nb_threads before
uma_startup1(), and give each stack thread a dense pcpu id with a
per-thread curcpu. Each thread now owns disjoint UMA/SMR per-cpu slots
instead of sharing slot 0.
```

若leader 偏好不带独立主题行的单段式，则用：

```
Make the f-stack kernel view SMP-aware for native-mt: define SMP, set
mp_ncpus/mp_maxid/all_cpus from nb_threads before uma_startup1(), and give
each stack thread a dense pcpu id with per-thread curcpu. Each thread now
owns disjoint UMA/SMR per-cpu slots instead of sharing slot 0.
```

（两版均**主动删去**了「initialize the uma_page slab hash before uma_startup1()」这一从句—— 它是崩溃修复的实现细节，已由代码注释承载；如 leader 认为该修复必须在 message 中留痕，可把第二句换成 `Also move the uma_page slab hash init before uma_startup1(), which fixes the 3/4-thread startup crash.`，总长仍为 3 句、符合规约上限。）

### commit-2 —— **通过**

原稿 2 句、纯英文、准确概述「去掉全局自旋锁+ `critical_enter/exit` 回归空操作 + 与用户态栈其余部分一致」，且与代码实况吻合（我已核对 `uma_int.h` 新注释表述一致、无「无抢占」这一错误理由）。**无需修改。**唯一可选微调：把`now that each stack thread owns a distinct per-cpu slot` 改为 `now that curcpu is per-thread` 更贴近 G2 门禁必改-1 校正后的真实理由，但原表述亦不错误，**不作必改**。

---

## 10. 本轮审核的诚实边界（未核实项）

1. HEAD 基线 `warning = 51` 未由我自行 checkout 复测（本轮禁止 `git checkout`），引用前序 reviewer 已独立复现的值；我实测当前树为 51，与之相等。
2. 未运行任何 runtime 测试（不在我职责内、且 `config.ini` 处于本地测试态）；`df05d2cd…` 二进制的运行时冒烟见 §4 的建议。
3. 未逐字重做 G1/G2 的代码门禁（`_m17_gate_code_g1.md` PASS / `_m17_gate_code_g2.md` PASS-with-fixes 已由 `reviewer` 完成）；我只做了 §1.3 的独立抽查 + 两条必改项的落地确认。
4. commit-1/commit-2 我**未实际执行**（按指派禁止），①②为静态判定 + §4 中间二进制的实证支撑；**真正的最终校验点是 §8 R2-S1 最后一步的 md5 回归**。

---

## 11. 给 leader 的执行清单（按序）

1. （必改 R2-1）删掉 `lib/ff_freebsd_init.c` 末尾多余的1 个空行。
2. `cd lib && make clean && make -j16 && cd ../example && make clean && make` → 校验 md5 仍为 `df05d2cd078d631ad2d8ee7caba8d387`、字节 30392632。**不符即停。**
3. 按 §8 R2-S1 的 `git apply --cached` 手法（或原手工法）提交 commit-1、commit-2；commit message 用 §9 的commit-1 精简版 + commit-2 原稿。
4. **确认 `config.ini` 未被 `git add`**：`git status --short config.ini` 提交后应仍为 ` M`；`git show --stat HEAD` / `HEAD~1` 中**不得出现 `config.ini`**。
5. （建议）commit-3 补spec 17 文档；（建议）独立小 commit 补 `tests/unit/fixtures/valid_thread_mode.ini`。
6. （建议）请 `tester` 用最终二进制补 1 分钟 `thread_mode=1` 2 线程启动冒烟。
7. 清理 §6.2 列出的临时日志/二进制（用 `/data/workspace/rm_tmp_file.sh`，注意**保留** `.codebuddy/`）。

---

# 15、spec M6 收尾复核（`17-SMP-aware-pcpu视图与去全局锁.md`）

- 复核对象：`docs/native_mt_spec/zh_cn/17-SMP-aware-pcpu视图与去全局锁.md`，**158,383 字节 / mtime 16:21**（与 leader 描述一致，已`ls -l` 核实）
- 范围：**只核 leader 指定的 F1/ N1 / N2 三处 + 运行时结论一致性**，未重审全文
- 代码基线：spec §0 自述`T1 当前 HEAD = ff09a17b2`（G1/G2 提交前），本节所有 `file:line` 核对均按该基线

## 15.0 结论

| 对象 | 结论 |
|---|---|
| **F1（§4.3.2 `rp_ent[]` 论证）** | **PASS** —— 已换成「写侧有界」，且其 7 条事实我**逐条自行以代码坐实**，无一处说反 |
| **N1（§7.1 探针 7 字段 + §6.12 U6-a 降级）** | **PASS** |
| **N2（§8.3 提交操作方法）** | **PASS**（另发现 1 处与实际执行手法不符，列为建议 S3） |
| **运行时结论一致性 / 是否夸大** | **无夸大、无与 `_m17_F_runtime.md` 冲突** —— 但**发现 3 处 M5「第三部分」实测结论未回填**，违反spec 自身 §7.6 DoD-6 |

### **文档提交门禁：FAIL —— 必须先回填 3 条再提交**（必改 D1/D2/D3，均为机械回填，数据现成、不涉代码、不需重测）

> **注意**：这与 §1~§14 的**代码提交门禁 PASS 无关**，代码已按我上轮结论提交完毕（`c7996a94f` / `57b612d16`），本节只阻断**文档**入库。
>
> **bounce 计数提醒**：`designer` 此前已被 `gate-design` 打回 2 轮，本次为**第 3 次打回**（仍在 bounce≤3 规约内）。但本次 3 条必改**性质不同于前两轮**——不是分析错误，而是纯「把已有实测数字抄进表格」。**若第 3 次修复后仍不通过，按规约必须转人工决策，不得再循环。** 建议 leader 明确告知 designer 这一点，并把 §15.2 的三处替换文本直接交给它照抄，把返工风险压到最低。

---

## 15.1 F1：§4.3.2 `rp_ent[]` 论证 —— **PASS**

`sed -n '350,380p'` 通读该节。**错误前提已被显式作废并整段替换**：开头即写「**理由必须是「写侧有界」，不是「读侧取模」**……原文误称「`rp_ent[]` 的每个索引都独立对 `mp_ncpus`/`rp_num_hptss` 取模」，**该表述已被实测证伪**」。leader 特别叮嘋的那点也已正面写明：「`:575 hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];` —— **没有任何取模**」，**文档没有再说反**。✓

**我未采信文档自述，而是逐条自行坐实（全部命中）**：

| spec 论断 | 我的实测 | 判定 |
|---|---|---|
| `tcp_hpts.c:575` 无取模 | `sed -n '569,580p'` → `hpts = tcp_pace.rp_ent[tp->t_hpts_cpu];`，其上仅 `INP_LOCK_ASSERT`，**确无取模** | ✓ |
| `hpts_random_cpu()` `:473` 双重取模 | `sed -n '466,476p'` → `cpuid = (((ran & 0xffff) % mp_ncpus) % tcp_pace.rp_num_hptss);` | ✓ 逐字一致 |
| `hpts_cpuid()` `:1089` `inp_flowid % mp_ncpus` | 实读 → `cpuid = inp->inp_flowid % mp_ncpus;`，其上下正是 `#ifdef NUMA` 包裹 | ✓ |
| `t_lro_cpu` 分支 `:1057-1060` 有界 | 实读 → `if (tcp_use_irq_cpu) { if (tp->t_lro_cpu == HPTS_CPU_NONE) { *failed = 1; return (0); } return (tp->t_lro_cpu); }`，`:1050` 亦确为 `return (tp->t_hpts_cpu);` | ✓ |
| `tcp_lro_hpts.c` 未编译 ⇒ `t_lro_cpu` 恒 `HPTS_CPU_NONE` | `grep -n "tcp_lro" lib/Makefile` → **只有 `tcp_lro.c` 一行**；`ls lib/tcp_lro_hpts.o` → **No such file** | ✓ |
| `t_hpts_cpu` 全树仅 3 个写入点 | `grep -rn "t_hpts_cpu *=" freebsd/ --include=*.c` → 恰 3 个赋值：`tcp_subr.c:2298`、`tcp_hpts.c:606`、`tcp_hpts.c:1542`（另`:605` 是比较非赋值）→ **穷举完备，行号逐一对上** | ✓ |
| `HPTS_CPU_NONE == (uint16_t)-1`，`tcp_var.h:330` | `grep -n` → `330:#define HPTS_CPU_NONE ((uint16_t)-1)` | ✓ 行号精确 |
| `rp_num_hptss == mp_ncpus`（`:1864`/`:1872`） | 实读 → `:1864 uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;`、`:1872 tcp_pace.rp_num_hptss = ncpus;` | ✓ |
| `rack.o`/`bbr.o` 均已编译（维持 `HPTS_CPU_NONE` 不变式的依据） | `ls lib/rack.o lib/bbr.o` → **均存在** | ✓ |

**额外加分（我认可的两处诚实处理）**：
1. 该节把「写入点 3 的 `HPTS_CPU_NONE`=65535 本身越界、且 `tcp_set_hpts()` 是先 `:1540` 取用后 `:1542` 赋值」这条**既存不变式**如实登记，并正确论证「与 `mp_ncpus` 取值无关（`mp_ncpus=1` 时同样越界）⇒ **G1 既未引入也未加重**，本轮不处理」——这是恰当的责任边界划分，不是甩锅。
2. 顺带发现 `-DSMP` 使 `tcp_hpts.c:1867` 的 `cpu_top = smp_topo();` 分支被启用 —— 这正是 G1 必须提供 `smp_topo()` stub 的原因，与§1我核过的 `ff_glue.c` stub（注释点名 `tcp_hpts.c:1890` 须处理 NULL）**闭环自洽**。

**F1 判定：PASS，无必改。**

## 15.2 N1：§7.1 探针字段 + §6.12 U6-a —— **PASS**

- **§7.1 字段数已改对**（`:930`）：明文写「P1 实际打印的字段（**7 个**，与落地探针格式串逐字一致；本文按 `gate-design` 必改 N1 修正 —— 原先写「9 个」并含 `rte_lcore_id()`/`rte_get_main_lcore()`，**实际探针并未打印这两项**）」。`:939` 复述 7 个字段全名：`tid`/`dense_idx`/`pc_cpuid`/`pc_zpcpu_offset`/`mp_ncpus`/`mp_maxid`/`curcpu`，与 `:915` 的格式串 `[M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d` **逐字段一一对应、数量吻合**。`:940` 另把 `MAXCPU` 单列为「实际探针未打印，改由 §7.3 clean build + `-dM -E` 核对」。✓
- **§6.12 U6-a 已降级**（`:806-811`）：「**状态变更**：由「方案依赖项」降为**纯观测项**」+「**本轮处置（leader 裁决，`gate-design` 必改 N1 方案 (b)）：本轮不核对 U6-a。**」，并给出正确理由「因 §4.3.4 的取号方式（主线程用 `ff_cur_proc_id()`，即直接取 `lcore_conf[rte_lcore_id()].proc_id`）**不依赖**『EAL main lcore == `proc_lcore[0]`』这一推断，即使 `--main-lcore` 打破它也仍然正确」。✓ 与我在 §1.3 独立坐实的取号链路（`ff_lcore_conf_idx()` = `thread_mode ? rte_lcore_id() : 0`）**完全一致**。
- **旁证与核对的界限划得干净**：`:810` 把 `lcore_mask=6` 下 `dense_idx=0/1` 的实测明确标为「**这只是由 `dense_idx` 反推的旁证，不构成对 U6-a 的核对**」并打【未坐实】，且限定「只覆盖未使用 `--main-lcore` 的默认情形」。✓ 无夸大。

**N1 判定：PASS，无必改。**

## 15.3 N2：§8.3 提交操作方法 —— **PASS**（含 1 条建议）

`:1096-1105` 新增 §8.3.1「两类拆分场景，方法**不同**（`gate-design` 必改 N2）」，两行表格**正是 leader 要求的区分**：

| 场景 | spec 给的方法 | 核对 |
|---|---|---|
| 同一 commit 内探针 vs 正式改动（`ff_freebsd_init.c` P1~P4、`ff_host_interface.c/.h` 的 `ff_probe_tid()`） | 「**必须先通过正向修改删除全部探针块，再整文件 `git add`**」+ `grep -rn "M17 temporary probe" lib/` 一次列全 6 处 + 删后**必须 `make clean` 重跑完整编译 + 冒烟**；并给出**不用 `git add -p`** 的理由（探针与正式改动交错易漏改；会在索引留下**不可编译的中间态**，例如探针调用了已 stage 的辅助函数而其定义未 stage） | ✓ 齐全，且「不可编译中间态」这条理由与我 §5① 的判据同源、方向正确 |
| 跨 commit 的同一文件（`ff_glue.c`：`smp_topo()` vs 删 `uma_crit_lock`） | 「用 `git add -p` 按 hunk 拆分」，并说明两处在**不同位置、互不依赖**、`reviewer` 已确认拆后各自可编译 | ✓ 区分到位（该「各自可编译」正是我 §5①② 的结论） |

另`:1094` 特别加了防误删提示：「§4.10 的 `uma_page_slab_hash` 提前**不是探针**，而是**必须入库的正式修复**……清理探针时**不得**把它一并删掉」——与我 §1.1(d) 核过的实际 diff 一致。✓
`:1105` 的 M7 检查清单四项（`grep "M17 temporary probe"` 零命中 / clean build error 0 & warning 51 / `git diff --cached` 无探针 / `git diff config.ini` 未入库）与我 §2/§3/§6 的实测口径**完全对齐**。✓

**N2 判定：PASS。** 建议见 §15.5 S3（`git add -p` 与实际执行手法不符，需补记）。

## 15.4 运行时结论一致性 —— **无夸大，但发现 3 处未回填（必改 D1/D2/D3）**

### 15.4.1 一致性/夸大：**全部通过**

逐条把 spec 的「已实测」与 `_m17_F_runtime.md` 对账（用 `search_content` 精确比对数字）：

| spec 位置 | spec 数字 | `_m17_F_runtime.md` | 判定 |
|---|---|---|---|
| `:1008` 3 线程去锁前 6 轮中位 | **240,802.74** req/s，含 2 个离群值 | `:1331` 同值 **240,802.74** | ✓ 一致 |
| `:1017` 3 线程离群值 | **143,232 / 204,857**，其余 4 轮 240k~247k | 「6 轮内出现 143k / 205k 离群」 | ✓ 一致 |
| `:1011` `thread_mode=0` 1 进程 | 修复前 **+0.03%** / 修复后 **+0.05%** | `:1059` `209,825.01` vs `209,710 → +0.05%` | ✓ 一致 |
| `:1012` `thread_mode=0` 2 进程 | 修复前 **−1.25%** / 修复后 **+2.38%** | `:1060` `236,871.31` vs `231,360 → +2.38%` | ✓ 一致 |
| `:1015` DoD-4 整体 | **PASS**，六档零崩溃零socket error 零日志新增 | `:1118` DoD-4 **PASS**，措辞一致 | ✓ 一致 |
| `:900-904` DoD-1 五档快照 | 全PASS，槽距 128 / 4096，`uk_ppera` 3/4 已实测、**2 线程档标「待补（应 == 2）」** | R1.2~R1.4 一致；2 线程档确未采`uk_ppera` | ✓ 一致，**未把未采集项写成已通过** |
| `:1013` RSS 内存对照 | **「仍待采集」**（`_m17_F_runtime.md` 未含 RSS 项） | 确无 RSS 数据 | ✓ 如实标注 |
| `:896` / `:909` 被测二进制归属 | md5 `751a8153…` = **G2 去锁前** | X0 符号级判据：`g1_prelock` `uma_crit_lock` 计数 1 | ✓ 一致（我 §4 亦独立核过 md5） |

**未发现任何一处夸大或与 runtime 文档冲突。** 特别地：

- **`+0.50%` / `+1.67%` / `+4.93%` 这三个数字在 spec 全文中「零命中」**（`search_content` 精确检索 `0\.50%|1\.67%|4\.93%` →仅命中 3 处无关的「±2% 噪声」「纯噪声改动」表述）。→ 因此leader 关心的「是否保留了噪声边界 / 是否标注不作判定依据」这个问题，**前提不成立：spec 里根本还没有这些数字**。**既无夸大之虞，也意味着回填未做**（见下）。
- 反过来，spec **没有**任何地方提前宣称 DoD-5 PASS 或 DoD-2 PASS：`:1026-1034`（§7.5）与`:991-994`（§7.2）都仍是纯前瞻表述。→ **零夸大坐实。**

### 15.4.2 必改 D1（P1）：§7.5 DoD-5 未回填 M5「第三部分」的判定结论

`:1026-1034` 现状仍是**改动前的计划文本**：只有「对比对象」「阈值 ±2%」「档位选择」「去锁后必须重做」「若无提升则……」「若低于阈值则进 L1/L2」——**没有任何去锁后实测结果**。

而 `_m17_F_runtime.md` 第三部分已给出完整判定（我已读原文）：
- `:1362` **2 线程 A/B 交叉各6 轮**：去锁前 `234,867.29` → 去锁后 `236,032.94` = **+0.50%**，PASS
- `:1363` **4 线程 A/B 交叉各 6 轮**：`250,734.43` → `254,913.26` = **+1.67%**，PASS
- `:1369` **3 线程 顺序（不作判定依据）**：`240,802.74` → `252,683.63` = **+4.93%**，仅供参考（去锁前含离群值）
- `:1371` **DoD-5 判定：PASS**，A 侧与既有基线互校偏差仅 −0.41% / +0.71%（证明无机器状态漂移）
- `:1373` **诚实边界**：「+0.50% 与 +1.67% 的量级**接近噪声下限**，我不宣称『G2 带来了确定的性能提升』，只能给出……**去锁后吞吐不低于去锁前，DoD-5 的阈值要求满足**」；4 线程 > 2 线程「方向上与『线程数越多、锁争用越重』一致，但**样本量不足以坐实该因果**」

**必须回填，且回填时必须原样保留上述两条边界**（即 `:1337` 的「3 线程 +4.93% **不作判定依据**、差值很可能主要来自去锁前那两个离群值」，以及 `:1373` 的「接近噪声、不宣称确定性能提升」）。**建议 designer 直接照抄如下文本追加到 §7.5**：

```
- **实测结论（M5 第三部分 A/B 交叉复测，`_m17_F_runtime.md` X4.1）：DoD-5 PASS。**【实测】

| 档位 | 方法 | 去锁前中位 (req/s) | 去锁后中位 (req/s) | 差值 | 判定 |
|---|---|---|---|---|---|
| 2 线程 | A/B 交叉各 6 轮 | 234,867.29 | 236,032.94 | **+0.50%** | PASS |
| 4 线程 | A/B 交叉各 6 轮 | 250,734.43 | 254,913.26 | **+1.67%** | PASS |
| 3 线程 | 顺序，**不作判定依据** | 240,802.74 | 252,683.63 | +4.93% | 仅参考 |

- **诚实边界（不得删减）**：+0.50% / +1.67% **接近噪声下限**，**不宣称 G2 带来确定的性能提升**；
  可支撑的结论仅为「去锁后吞吐不低于去锁前，DoD-5 阈值满足」。4 线程差值大于 2 线程，方向上
  与「线程数越多、全局锁争用越重」一致，但**样本量不足以坐实该因果**。
- **3 线程 +4.93% 不可直接采信**：去锁前该档 6 轮含两个离群值（143k / 205k）拉低了中位数，
  而去锁后 3 轮极差仅 0.25%；该差值很可能主要来自离群值而非 G2 收益，且该档**未做 A/B 交叉**。
- **A/B 交叉法的必要性**：±2% 判据对机器状态漂移极敏感；A 侧与R5 既有中位互校偏差
  −0.41% / +0.71%，证明本轮无漂移。
```

### 15.4.3 必改 D2（P1）：§7.1(1) 与 §7.2 的「去锁后待复测」已过时

- `:909` §7.1 限定 (1) 仍写：「**去锁后必须用同一套探针重新验证槽位隔离，不可沿用本轮数据**」——语气是**未完成的待办**。
- 但 `_m17_F_runtime.md` **X1 章节已完成该复验**：`:1179` 「X1. 去锁后的 DoD-1 槽位隔离复验（`reviewer` 硬要求）」，`:1292` 「**去锁后 DoD-1 在 2 / 3 / 4 线程三档全部 PASS**，`thread_mode=0` 退化档亦正确。`reviewer` 要求的「去锁后重新验证槽位隔离」**已完成**」；`:1167` 另说明 `helloworld_g2_nolock` 三条探针格式串完好、无需重编即可复验。
- 同理 `:991-994` §7.2 DoD-2 仍只有判定式、无实测结论；而该判定式**现已可坐实**——我在本轮 §1.2 实测 `grep -rn "uma_crit_lock" . --include=*.c --include=*.h` = **0 命中**（全树，含 `freebsd/`），且 `uma_int.h` 的 `critical_enter/exit` 已是 `do {} while(0)`。

**后果**：spec 一旦按现状入库，读者会误以为「去锁后槽位隔离尚未验证」「DoD-2尚未确认」，而事实是两者都已 PASS。**这是实质性误导**，且直接违反 spec 自身 §7.6 DoD-6（`:1038`）的明文要求：「**M6 须把 M5 实测数据回填 §7 各表**」。

**改法**：§7.1 限定 (1) 改为「（1）本快照数据均为「G2 去锁前」；**去锁后的槽位隔离复验已于 M5 第三部分完成（`_m17_F_runtime.md` X1：2/3/4 线程三档 + `thread_mode=0` 退化档全部 PASS）** —— 去锁后「每线程独占槽位」是唯一保护，其有效性已实测。」§7.2 追加一行「**实测：`grep -rn "uma_crit_lock" lib/ freebsd/` 零命中，`critical_enter/exit` 已为 `do {} while(0)`（`reviewer2` 复核时全树 0 命中）→ DoD-2 PASS。**【实测】」

### 15.4.4 必改 D3（P2）：§7.4 表内3 线程/4 线程行未带去锁后数据，与 D1 表重复矛盾

`:1008`/`:1009` 的「基线」列写的是**去锁前**结果，但列头是「基线（plan §5.1【实测】）」，在 D1 回填后会与 §7.5 新表并存而无交叉引用。**改法（最省）**：在 `:1008`/`:1009` 两行末尾各加一句「去锁后数据见 §7.5」，避免读者拿 §7.4 的去锁前数字当最终结论。

## 15.5 建议改项（非阻断）

- **S1**：把 leader 提交前跑的那次冒烟补记进 §7.4 或 §7.5——`df05d2cd…`（**摘探针后的最终二进制**）`wrk -t5 -c100 -d10s` = **236,273.85 req/s**，与 X4.1 的去锁后 2 线程中位 236,032.94 相差 **+0.10%**，零error、日志无 `M17`/`panic`/`Segmentation`/`assert`。这条**价值很高**：它是**唯一**用「即将入库的那份二进制」跑出的数据，正好闭合我在 §4 提的「`df05d2cd…` 未做运行时冒烟」残余风险，建议明确标注为「最终产品二进制冒烟」。
- **S2**：§8.4 的两段 commit message 草案（`:1109-1129`）与**实际提交**（`c7996a94f` / `57b612d16`）措辞已不同。建议在 §8.4 开头加一行「以下为草案；实际提交见 `c7996a94f`（G1）/ `57b612d16`（G2）」，避免文档与库内历史对不上。
- **S3（对应 N2）**：§8.3.1 第二行规定 `ff_glue.c` 用 **`git add -p`** 拆 hunk，但**实际执行并非如此**——`git add -p` 只能交互运行，leader 采用的是「commit-1 前临时保留 `volatile int uma_crit_lock;`、commit-2 前再删」的正向编辑法（我在本文 §5 已判定其正确并实证）。建议补一句：「**`git add -p` 需交互，非交互场景的等价手法有两种：① 本轮实际采用的『临时保留 → 提交 → 再删除』正向编辑法；② `git diff <file>` 导出补丁后只保留目标 hunk，再 `git apply --cached`（见 `_m17_gate_final.md` §8 R2-S1）。**」——否则后人照文档执行会卡住。
- **S4（已核实为非缺陷，特此说明避免误报）**：spec 中`lib/Makefile:515`（`tcp_lro.c`）、`:584-586`（`rack.c`/`bbr.c`）、`:346`（`kern_mbuf.c`）等行号，在**当前工作区/新 HEAD** 中均**+4 行**（因 G1 的 `-DSMP` 在 `:218` 附近插入 4 行；我实测 `tcp_lro.c` 现位于 `:519`）。但 spec §0 已明确把基线钉在 `HEAD = ff09a17b2`，故这些引用**相对其声明基线是正确的**，**不算缺陷、无需修改**。若 designer 想更友好，可在 §9 证据索引处加一句「本文行号均相对 `ff09a17b2`；G1 提交后 `lib/Makefile` 行号 +4」。

## 15.6 给 leader 的最短闭环路径

1. 把 §15.4.2 的**现成替换文本**交designer 照抄进 §7.5（D1），按 §15.4.3 改§7.1(1) 与 §7.2（D2），按 §15.4.4 加两处交叉引用（D3）。**纯抄写，无需分析、无需重测。**
2. 顺手采纳 S1（补记最终二进制冒烟 236,273.85 req/s）、S2、S3 三条（各 1~2 行）。
3. 改完后我只需核对「回填数字与 `_m17_F_runtime.md` X4.1 逐字一致 + 两条诚实边界未被删减」，约 5 分钟即可给最终 PASS。
4. **提交文档时建议把 `_m17_F_runtime.md` 一并入库**（它是 §7.5 全部实测数据的唯一出处；若只提交 spec 而不提交它，spec 中「见 `_m17_F_runtime.md` X4.1」的引用在库内将悬空——与我§8 R2-S2 指出的「spec 17 未入库导致 `uma_int.h` 注释里`spec 17 §2.4` 悬空」是同一类问题）。

## 15.7 本节的诚实边界

1. **只核了 leader 指定的 3处 + 运行时一致性**，spec 其余约 15 万字**未复审**（`gate-design` 前两轮已覆盖）。
2. `_m17_F_runtime.md` 我只读了与 DoD-5 / DoD-1 去锁后复验 / `thread_mode=0` 回归相关的段落，**未通读全文**，故不对其内部数据自洽性背书。
3. leader 转述的提交后冒烟（236,273.85 req/s）**我未旁证**（未见日志文件，也未自行跑）——采信leader 转述，标为【他人实测，未旁证】。
4. `c7996a94f` / `57b612d16` 两个提交的**内容我未逐一打开复核**（本轮任务限定为 spec 复核；且 leader 已按我§11 要求自证 `git status --short lib/` 为空且重编md5 仍为 `df05d2cd…`）。

---

# 16、文档门禁复核（bounce 3 收尾）

- 复核对象：`17-SMP-aware-pcpu视图与去全局锁.md`，**166,343 字节 / mtime 17:01**（与 leader 描述一致）
- 范围：**只核D1 / D2 / D3 是否回填到位 + 新增内容有无夸大或冲突**；§15.1~§15.3（F1/N1/N2）已 PASS，本轮未重审；全文其余部分未重审

## 16.0 结论：**PASS —— 文档可以提交，无需转人工决策**

| 项 | 结论 |
|---|---|
| **D1**（§7.5 DoD-5 回填） | **PASS** —— 8 档数据**逐字与 `_m17_F_runtime.md` X4.1 一致**，两条边界**原样保留**，DoD-5 判定 PASS 到位 |
| **D2**（§7.1(1) + §7.2 过时表述） | **PASS** —— 两处均已改为「已完成」，且§7.2 额外补了二进制符号级 + 6 档运行时确认 |
| **D3**（§7.4 交叉引用） | **PASS** —— 列头 + 两行末尾均已加 |
| **新增内容夸大 / 冲突** | **无夸大、无冲突、无「未坐实→已验证」翻转**；反而**新增了 3 处更严格的诚实标注** |
| **第4 点两条补充事实** | **均已写入**（不止写入，还标注了证据归属），无需列为建议 |
| 我上轮的建议 S1/S2/S3/S4 | **4 条全部被采纳** |

**必改项：0 条。** 唯一发现列为**建议 P3（见 §16.5）**：`_m17_F_runtime.md`「第四部分」的一批数据未被引用，属**遗漏而非冲突**。

---

## 16.1 D1：§7.5 DoD-5 回填 —— **PASS**

标题已改为「**§7.5 DoD-5：G2 去锁前后吞吐对比 —— 已完成，PASS**」，`:1031` 明写「**实测结论（M5 第三部分 A/B 交叉复测，`_m17_F_runtime.md` X4.1）：DoD-5 PASS。**【实测】」。

**8 行数据我逐行回查 `_m17_F_runtime.md` 原文，全部逐字一致，零编造**（不采信 designer 自述，逐个数字精确检索比对）：

| spec §7.5 行 | spec 数字 | runtime doc 出处 | 判定 |
|---|---|---|---|
| 2 线程 A/B 交叉各 6 轮 | 234,867.29 → 236,032.94 = **+0.50%** PASS | X4.1 `:1362` | ✓逐字 |
| 4 线程 A/B 交叉各 6 轮 | 250,734.43 → 254,913.26 = **+1.67%** PASS | X4.1 `:1363` | ✓ 逐字 |
| 2 线程 soak | 499,223.54 → 503,590.01 = **+0.87%** | `:1364`，另`:1105`（去锁前，29,962,126 请求）/`:1343`（去锁后，30,228,695 请求）/`:1350` **三处互证** | ✓ 逐字 |
| 4 线程 soak | 487,968.74 → 496,646.19 = **+1.78%** | `:1365`，另 `:1106`/`:1344`/`:1351` 三处互证 | ✓ 逐字 |
| 1 线程 | 209,730.76 → 213,938.31 = **+2.01%** | `:1366`，另 `:1099`（去锁前 3 轮原始值）/`:1330`（去锁后 3 轮原始值） | ✓ 逐字 |
| `thread_mode=0` 1 进程 | 209,825.01 → 214,151.94 = **+2.06%** | `:1367`，另 `:1332` | ✓ 逐字 |
| `thread_mode=0` 2 进程 | 236,871.31 → 236,484.61 = **−0.16%**，PASS（在 ±2% 噪声内） | `:1368`，另 `:1104`/`:1333` | ✓ 逐字 |
| 3 线程 | 240,802.74 → 252,683.63 = **+4.93%**，**「顺序，不作判定依据」**、「仅参考（去锁前含离群值）」 | `:1369` 措辞为「顺序（**不作判定依据**）……参考（去锁前含离群值）」 | ✓ 一致，**「不作判定依据」标注在位** |

**两条边界原样保留，逐字核对通过**（`:1044`）：
- 「+0.50% / +1.67% **接近噪声下限**，**不宣称 G2 带来确定的性能提升**；可支撑的结论仅为「去锁后吞吐不低于去锁前，DoD-5 阈值满足」」 —— 对应 runtime `:1373`，**语义与措辞均未被稀释**（未出现「性能提升」「优化收益」之类的升格表述）。
- 「4 线程差值大于 2 线程，方向上与「线程数越多、全局锁争用越重」一致，但**样本量不足以坐实该因果**」 —— 对应 runtime `:1373` 后半句，✓。

**另两条支撑信息亦已写入**：`:1045` 3 线程 +4.93% 的完整免责说明（去锁前 6 轮含 143k/205k 离群拉低中位、去锁后 3 轮极差仅 0.25%、「很可能主要来自离群值而非 G2 收益」、「该档**未做 A/B 交叉**」）；`:1046` A/B 交叉法必要性 + **A 侧互校偏差 −0.41% / +0.71%** 证明无漂移。均与 runtime `:1337`/`:1371` 一致。✓

**处理方式加分**：`:1049` 把原计划口径整块以「**以下为原计划口径，保留备查**」保留，而不是删除 —— 既回填了结论，又保留了门槛/降级台阶的可追溯性，符合 DoD-6 精神。

## 16.2 D2：§7.1(1) 与 §7.2 —— **PASS**

**§7.1 限定(1)（`:909`）已改为**：「本快照数据均为「G2 去锁前」……**去锁后的槽位隔离复验已于M5 第三部分完成（`_m17_F_runtime.md` X1：2/3/4 线程三档 + `thread_mode=0` 退化档全部 PASS）** —— 去锁后「每线程独占槽位」是**唯一**保护，其有效性已实测。**【实测】**」，并补了「复验无需重编：`helloworld_g2_nolock` 的三条探针格式串完好」。→ 与我 §15.4.3 的改法要求**逐点吻合**，且与 runtime `:1179`/`:1292`/`:1167` 一致。✓

**§7.2 标题已改为「—— 已完成，PASS」**，并新增两条：
- `:994` 代码层：「`grep -rn "uma_crit_lock" lib/ freebsd/` 零命中，`critical_enter/exit` 已为 `do {} while(0)`（`reviewer2` 复核时全树0 命中）→ DoD-2 PASS」【实测】 —— 与我上轮 §1.2 实测一致（我实测范围更宽：全树 `--include=*.c --include=*.h` 0 命中）。✓
- `:995` 运行时层（**这是 designer 自己补的、超出我要求的内容，我逐字回查了原文**）：「去锁后二进制 `helloworld_g2_nolock` 中 `uma_crit_lock` 符号 `grep -c` = **0**，去锁前副本 = **1** → 该锁**确已从二进制中移除**，不是「代码改了但没编进去」；去锁后在 1/2/3/4 线程 + `thread_mode=0` 1/2 进程共 **6 档 + 2 个 60s soak（合计约 6,000 万请求）**下零崩溃、零 socket error、日志零新增字节」 —— 对照 runtime **X4.2 `:1377-1378`**，**逐项逐字吻合**（含「约 6,000 万请求」「日志零新增字节」）。✓ **不是编造，也未加码。**
- `:996` 另补「本轮未触发 L2，G2 已按 L0（G2-b）落地」，与实际一致。✓

## 16.3 D3：§7.4 交叉引用 —— **PASS**

- 列头已由「基线（plan §5.1【实测】）」改为「**基线 / 本轮结果（均为 G2 去锁前；去锁后数据统一见§7.5）**」（`:1007`）—— 比我建议的做法更彻底（在表头一次性声明口径）。✓
- `:1011`（3 线程）、`:1012`（4 线程）两行末尾均已加「**去锁后数据见 §7.5**」。✓
- **RSS 行仍如实标「仍待采集」**（`:1016`），未被顺手写成已完成。✓

## 16.4 夸大 / 冲突 / 「未坐实→已验证」翻转 —— **均无，且诚实度反而提高**

这是本轮最需要警惕的风险点，我逐处检查回填涉及的表述，结论是**没有任何一处把未坐实写成已验证**，并且新增了 3 处**更严格**的标注：

1. **§7.1 限定 (2)（`:910`）新增**：「故建议在去锁后复测时顺手增打基址……**本轮未做该增打**，故该缺口**保留为未闭合项**。**【未坐实】**」 —— 上一版只是「建议顺手增打」，**新版明确承认没做**。这是**反向加强诚实度**，与我 §15 的要求方向一致。✓
2. **§7.6（`:1063`）新增 DoD-6 自检清单**，逐条列出回填落点，并在末尾明写「**仍未闭合的三项已如实保留**：§7.1 ⚠ 的基址一致性（未增打基址）、§7.4 的 RSS 对照（未采集）、§6.19 的 hpts 内存增量量化（未采集）」。→ 没有借「DoD-6 已完成」之名宣称全部闭合。✓
3. **证据归属标注**：凡非 designer 亲测的数据均标【他人实测（leader），designer 未旁证】或【他人实测（leader/reviewer），designer 未旁证】（见 `:1000`、`:1047`、`:1067`、`:1107`）。→ 这正是我在§15.7 对自己使用的同一套标注纪律，designer 主动照做，**认识论卫生良好**。✓

另核：`:1000`/`:1003` 关于 clean build 的回填（`error 0` / `warning 51` = HEAD 基线、提交后重编 rc 0/0、md5 `df05d2cd…`逐字节一致）与我上轮 §3 的**独立实测完全一致**，无夸大。✓

## 16.5 建议（P3，非阻断，不影响 PASS）

**`_m17_F_runtime.md`「第四部分」（`:1402` 起「判据 #9 —— 摘探针后的收尾回归」）整块未被 spec 引用。** §7.5 `:1047` 只引了 leader 的单次冒烟（236,273.85req/s）。而第四部分其实是 **tester 用摘探针后的产物做的 A/B 回归**，信息量更大，且含两条应当留痕的诚实项：

- `:1522` **A vs B：211,721.91 vs 207,364.79 → +2.10%（无探针版反而更高）** —— 这是比单次冒烟**更强**的证据，正面支持「摘探针未引入回归」；
- `:1523`/`:1530` 环境漂移的如实记录：带探针版相对第三部分值 214,151.94 **−3.17%**；`thread_mode=0` 2 进程 229,490.57 vs 第三部分 236,484.61 = **−2.96%，略超 ±2%**，tester 判为**漂移而非回归**（依据：同一二进制复测的漂移量级为 −2.59%~−3.17%）；
- `:1524` **未解释的单点离群 116,887.05**，日志零错误、进程存活、后续恢复 211~212k，**未坐实根因**（无队列级/hpts 级计数探针）；
- `:1555` 另有「Y4. 第四部分的无法验证项」。

**为何仍判 PASS 而非 FAIL**：spec 现文**没有任何一处与上述数据冲突**，也没有宣称「摘探针后已做完整 A/B 回归」——它只声称了 leader 那一次冒烟，且如实标注了证据归属。因此这是**引用遗漏**，不属于「与实测冲突」或「未坐实写成已验证」，按 leader 设定的判据应列为建议。
**建议改法（1~2 行，可与提交同时做，也可后补）**：在 §7.5 `:1047` 之后补一条——「**摘探针后二进制的 A/B 回归（`_m17_F_runtime.md` 第四部分）**：1 线程档 A/B 为 211,721.91 vs 207,364.79（**无探针版更高 +2.10%**）；同期实测环境漂移达 −2.59%~−3.17%，故 `thread_mode=0` 2 进程的 −2.96% 由 tester 判为**漂移而非回归**；另有 1 个未解释的单点离群 116,887.05（零错误、进程存活、后续恢复）**根因未坐实**。**【未坐实（离群根因）】**」。

## 16.6 leader 第 4 点两条补充事实 —— **均已写入，无需列为建议**

| 事实 | 写入位置 | 核对 |
|---|---|---|
| ① 代码已提交 `c7996a94f`(G1) / `57b612d16`(G2)；`git status --short lib/ freebsd/` 为空；`config.ini` 未入库 | **§7.7 DoD-7 `:1067`**（「**已完成**」+ 两个 hash + 8 文件/2 文件 + `git status` 为空 + `config.ini` 保持 ` M` 未入库）；**§8.2 `:1107`** 重复登记并附「重编 rc 0/0、md5 逐字节一致」；**§8.4 `:1139`** 注明草案与实际提交的关系 | ✓ 三处登记，且均标注证据归属 |
| ② 摘探针后产品二进制 md5 `df05d2cd…` 冒烟 236,273.85 req/s / 2,365,694 requests / 零 error / 日志无 `M17\|panic\|Segmentation\|assert` | **§7.5 `:1047`**（含 30,392,632 B、与去锁后 2 线程中位相差 **+0.10%**、「**唯一一次用『即将入库的那份二进制』跑出的运行时数据**」、据此闭合残余风险）；**§7.7 DoD-8 `:1068`** 再次引用 | ✓ 完整，且措辞未夸大（明确是「冒烟」而非「完整回归」） |

**我上轮 4 条建议的采纳情况（全部落地）**：S1 → §7.5 `:1047` ✓；S2 → §8.4 `:1139` 加「以下为草案；实际提交见 …，以库内历史为准」✓；S3 → §8.3.1 `:1131` 改为「须按 hunk 拆分」+新增 `:1133` ⚠ 块，明写「**`git add -p` 只能交互运行，自动化/agent 环境会卡住，不要照抄**」并完整记录实际采用的正向编辑法与`git apply --cached` 等价手法 ✓（这条对后人价值最大）；S4 → §9 `:1167` 新增「行号基线声明」，明确全文行号相对 `ff09a17b2`、G1 提交后 `lib/Makefile` 行号 +4（并举`tcp_lro.c :515→:519`、`kern_mbuf.c :346→:350`）、「**这不是缺陷**」并给出 `git show ff09a17b2:<file> | grep -n` 的换算办法 ✓。

## 16.7 本节诚实边界

1. **只核了 D1/D2/D3 + 新增内容的夸大/冲突**；spec 其余约 16 万字未复审（F1/N1/N2 于 §15 已 PASS，本轮未重跑）。
2. `_m17_F_runtime.md` 我本轮只读了 X1/ X4.1 / X4.2 与第四部分 `:1500-1531` 相关段落，**未通读全文**，不对其内部自洽性背书。
3. leader 的两条事实（提交后 `git status` 为空、冒烟 236,273.85）**我未旁证**，与designer 同为【他人实测，未旁证】。
4. 我**未**重新执行 clean build（上轮 §3 已实测 md5 `df05d2cd…`，本轮无代码改动）。
