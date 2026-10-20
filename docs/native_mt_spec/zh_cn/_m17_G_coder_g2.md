# M17 / M4 —— G2 实施记录（`coder`）

> 任务：按 spec `17-SMP-aware-pcpu视图与去全局锁.md` §4.7 的 **D8 裁决 = G2-b**，把 `lib/include/vm/uma_int.h` 的 `critical_enter/exit` 覆盖宏改回空操作，慢路径不动。
> 所有编译数字与运行时数字均来自**实际执行**，无估算。凡未坐实处均标注【未坐实】。
> 本文与 `_m17_E_coder_g1.md`（G1）配套；G1 改动本轮**一行未动**。

---

## 0. 结论速览

| 项 | 结果 |
|---|---|
| G2-b 实施 | ✅ 完成，形态与 spec §4.7.1 逐字一致（`do {} while(0)`） |
| **M4 门禁必改-1（注释错误前提）** | ✅ **已修**：删掉「No preemption in f-stack userspace」，改为「`curcpu` per-thread → 抢占/迁核不改变槽位归属」（见 §1.1.1） |
| **必改-1 修正后复验** | ✅ `lib/`+`example/` 再次 clean build：error 0 / warning 51 / `.o` 248；**md5 未变、逐字节相同**（纯注释改动，见 §3.5） |
| **G2-S5（SMR 残留 4 处的更强理由）** | ✅ **已补**：`uma_core.c` 对 `smr_enter/smr_exit` 实测 **0 命中**，那 4 处仅是永不被调用的 inline 函数体（见 §2.2） |
| **G2-S3（摘探针）** | ✅ **已完成**：第三方于 16:22:10 摘除、16:40:46 补掉一处并排空行、全量重编；**判据全部转绿**（#3 由 380→379），#10 基线因 commit 失效（已按预登记风险处置，见 §7.3.1） |
| **摘除后产物** | `example/helloworld` = `df05d2cd078d631ad2d8ee7caba8d387`，30,392,632 字节；`strings \| grep -c M17-PROBE` = **0**；**md5 与本 agent 修补前给出的预期逐字一致** → `tester` 的 #9 对最终提交产物完全有效 |
| **提交状态** | ✅ commit-2 `57b612d16` = **恰好 2 个文件**（`ff_glue.c` + `uma_int.h`），符合 §4.7.5；commit-1 `c7996a94f` = 8 个文件；**`ff_glue.c` 的 hunk 级拆分已正确完成 → G2 可单独 revert**；两 commit 均无 `freebsd/` 路径 |
| **`tester` #9 收尾回归** | ✅ **PASS**（双侧±2%）：2T −0.24% / 4T +0.06% / tm0-1p +2.10% / tm0-2p −2.96%；hang 检查全档通过（见 §7.4） |
| **判据体系** | 11 条 + 3 处加固，与 `tester` 往复6 轮收敛；**两条高估已被实测修正**（#4 对等量替换是盲的；#1 只管「没多加」不管「没少删」）见 §7.5 |
| 改动文件数 | **2 个**（`lib/include/vm/uma_int.h`、`lib/ff_glue.c`），符合 §4.7.5 硬性限定 |
| `uma_crit_lock` 全树引用 | **0**（grep 坐实后才删定义） |
| `lib/` clean build | rc=0、**error 0**、**warning 51**（= HEAD 基线，未增加）、`.o` **248** |
| `example/` clean build | rc=0、error 0、`undefined reference` **0** |
| `example/helloworld` md5 | **`78c39a6f96e104412ce75351e402907b`**（30,392,664 字节；15:10:44 首建、15:48:44 修正后重建，**md5 相同**） |
| 去锁前对照二进制 | `example/helloworld_g1_prelock` = **`751a8153d3b200229cff99b3fa7650b0`**（30,392,704 字节，mtime 15:00:57） |
| 去锁后副本 | `example/helloworld_g2_nolock` = **`78c39a6f96e104412ce75351e402907b`**（与 `helloworld` **逐字节相同**，`cmp -s`坐实 → **`tester` 无需更换副本**） |
| 自测 2 线程 | ✅ 启动不崩+ 10s wrk **219,241.92 req/s**，槽位隔离维持 |
| 自测 4 线程 | ✅ 启动不崩 + 10s wrk **391,271.39 req/s**，槽位隔离维持 |
| R-a（`sizeof(struct uma_page)` 超额分配） | **本轮不修**，记为技术债；并**修正了它的影响面估计**（见 §6.1） |
| S5（4行注释压到 2 行） | **本轮不做**，理由见 §6.2 |
| R-d（6 处探针） | 未摘除（按 leader 指示保留给 `tester`），已在 G2 二进制中**核实 3 条格式串仍在** |

---

## 1. 改动内容（逐字）

### 1.1 `lib/include/vm/uma_int.h`（`:45-52` → `:45-50`）

改前：

```c
extern volatile int uma_crit_lock;
#define critical_enter() do { \
    while (__sync_lock_test_and_set(&uma_crit_lock, 1)) \
        ; \
} while(0)
#define critical_exit()  do { \
    __sync_lock_release(&uma_crit_lock); \
} while(0)
```

改后（**M4 门禁必改-1 修正后的最终形态**）：

```c
/*
 * curcpu is per-thread here (sys/pcpu.h), not per-CPU, so preemption cannot
 * change which uz_cpu[] slot this thread uses and no other thread uses it;
 * the dense pcpu slot is the whole protection (spec 17 §2.4).
 */
#define critical_enter() do {} while(0)
#define critical_exit()  do {} while(0)
```

- 形态与 spec §4.7.1 给出的目标代码**逐字一致**，未自行改成别的形态（例如未改成 per-cpu 锁、未改成缩小闭包）。
- **保留空宏而不是彻底删掉**：按 §4.7.1 的要求执行。理由是不依赖「`freebsd/sys/systm.h:186 #ifndef FSTACK` 永远存在」这一脆弱假设；已实测确认该`#ifndef FSTACK` 当前确实把inline 版函数体掏空（`systm.h:183-193`/`:195-204`，实测原文见 §3.3）。
- **注释 3 行**（含边框共 5 行，实质文字 3 行），满足 §4.7.1「须注释」与最小注释规约，不含长篇论证。内容说明「`curcpu` 是 per-thread 而非 per-CPU → 抢占既不会改变本线程使用的 `uz_cpu[]` 槽位、也不会让别的线程用到它 → 稠密 pcpu 槽位就是全部保护」，并指向 spec 17 §2.4。

#### 1.1.1 【M4 门禁必改-1】首版注释的错误前提及修正（如实记录）

我提交审核的首版注释首句为 `No preemption in f-stack userspace`，**这是错误陈述**，`reviewer` 判为必改-1（P2），我**接受该判定**：

- f-stack 的栈线程是**普通 pthread**，会被 Linux 调度器抢占、也会迁核；「用户态无抢占」在本工程根本不成立。
- G2 安全的真正理由是 **`curcpu` 绑线程而不绑 CPU**（`lib/include/sys/pcpu.h:34` `#define curcpu PCPU_GET(cpuid)` → `pcpup->pc_cpuid`，而 `pcpup` 是 `__thread` 变量）。因此不变式「同一 `uz_cpu[i]` 槽位在任意时刻只有一个线程访问」**不依赖是否被抢占、是否迁核** —— 这个条件比上游 FreeBSD 依赖的「同 CPU 内禁抢占」**更强**，而不是更弱。
- 危害等级：该注释是「为何可以去锁」这一最高风险决策的**唯一书面依据**。若后人据「无抢占」这个错误前提去移除其它保护（例如慢路径的 `ZDOM_LOCK`/`KEG_LOCK`），会引入真实缺陷。这与 G1 的必改-2（`ff_kern_timeout.c` 假注释 `cpuid is always 0, MAXCPU=1`）属**同一类问题**：错误注释比无注释更有害。
- 修正后已按 §3.5 重跑 clean build，**二进制逐字节不变**（纯注释改动），详见 §3.5。

### 1.2 `lib/ff_glue.c`（删`:146`）

```c
 volatile int smp_started;
 u_int mp_maxid;
-volatile int uma_crit_lock;
```

**删除前的全树引用核查**（先 grep 再删，非事后补证）：

```
$ cd /data/workspace/f-stack && grep -rn "uma_crit_lock" --include=*.c --include=*.h --include=*.S --include=Makefile* --include=*.mk .
./lib/ff_glue.c:146:volatile int uma_crit_lock;
./lib/include/vm/uma_int.h:45:extern volatile int uma_crit_lock;
./lib/include/vm/uma_int.h:47:    while (__sync_lock_test_and_set(&uma_crit_lock, 1)) \
./lib/include/vm/uma_int.h:51:    __sync_lock_release(&uma_crit_lock); \
```

→ 除这2 个文件外**零引用**，**含 `freebsd/` 上游树在内**（grep 覆盖全仓 `.c/.h/.S/Makefile*/*.mk`，未做目录排除）。删除后的二次验证见 §3.2（`nm libfstack.a | grep -c uma_crit_lock` = 0）。

### 1.3 改动集可分性（§4.7.5）

**须向 leader 更正一处事实**：leader 消息中说「G1 与 G2 的改动落在不同文件，天然可分」——**这个说法不准确**。`lib/ff_glue.c` **同时**承载G1 与 G2 的改动：

| 文件 | G1 改动 | G2 改动 |
|---|---|---|
| `lib/Makefile` | `-DSMP` | — |
| `lib/ff_dpdk_if.c` / `.h` | `ff_cur_proc_id()` 等 | — |
| `lib/ff_freebsd_init.c` | 三元组 /槽位 / hash 时序 | — |
| `lib/ff_kern_synch.c` / `ff_kern_timeout.c` / `lib/include/sys/pcpu.h` | `curcpu` / `timeout_cpu` / `pause_wchan` | — |
| **`lib/ff_glue.c`** | **`smp_topo()` stub（`:168` 附近新增 7 行）** | **删 `:146` 的 `uma_crit_lock`** |
| **`lib/include/vm/uma_int.h`** | — | **`critical_enter/exit` → 空操作** |

**但仍然可分，且`git revert` commit-2 仍是干净的**，依据是 `git diff` 实测这两处落在**两个互不相邻的 hunk**：

```
lib/ff_glue.c
@@ -143,7 +143,6 @@   ← G2（删 uma_crit_lock）
@@ -169,6 +168,13 @@  ← G1（smp_topo stub）
```

两个 hunk 相距约 25 行、无重叠上下文 → 拆分提交时对 `lib/ff_glue.c` 需要 **hunk 级暂存**（`git add -p` 或 `git apply --cached` 单 hunk），不能整文件 `git add`。**请 leader 在 M7 提交时注意这一点**：若对 `ff_glue.c` 整文件 `git add` 到 commit-1，G2 就无法单独 revert，违反 §4.7.5。

按 leader 指示**未执行 `git commit`**。当前工作区处于「G1 + G2 均已应用」的未提交状态。

---

## 2. 语义等价性依据（去锁为何不等于「无保护」）

按 spec §4.7.1 与 `_m17_gate_plan.md` F4 的落点整理，本轮**新增两项实测坐实**：

### 2.1 去锁后 UMA 快路径的展开形态【实测】

用 `-E` 预处理 `uma_core.c`（编译命令取自本轮 build log第 867 行，仅把 `-c` 换成 `-E`）：

| 检查项 | 结果 |
|---|---|
| `__sync_lock_test_and_set` 出现次数 | **0**（改前是锁的核心指令） |
| `uma_crit_lock` 出现次数 | **0** |
| 我方`uma_int.h`覆盖宏进入预处理输出的位置 | 第 **9736** 行 |
| `do {} while(0)` 出现次数（均在 9736 行之后） | **26** |

→ **`uma_core.c` 本体（预处理输出 9736 行之后）的 `critical_enter/exit` 调用点已全部展开为空语句**，不再有任何原子指令。

### 2.2 残留的 4 处 `critical_enter/exit` 是既有行为，与 G2 无关【实测】

预处理输出中仍有 4 处**未被宏展开**的调用：

```
2777:void critical_enter_KBI(void);      ← 仅声明，非调用
2796:critical_enter(void)← systm.h 的 inline 定义（#ifndef FSTACK 已掏空）
2808:critical_exit(void)                 ← 同上
6960: critical_enter();   ← freebsd/sys/smr.h 内 inline 函数（smr_enter）
6990: critical_exit();← 同上
7001: critical_enter();   ← 同上（smr_exit 侧）
7041: critical_exit();
```

- 这4 个调用点位于 `freebsd/sys/smr.h`，而 `smr.h` 在预处理顺序上**早于**（6960 < 9736）我方`uma_int.h` 的宏定义 → 它们绑定的是 `systm.h` 的 **inline 空函数**，**改前改后完全相同**。
- **更强的理由（`reviewer` 建议 G2-S5，本轮补测坐实）**：这 4 处根本**不是调用点**，而是 `smr_enter()` / `smr_exit()` 两个 inline 函数的**函数体**；而 `uma_core.c` **从不调用这两个函数** —— 实测 `grep -cE "smr_enter|smr_exit" freebsd/vm/uma_core.c` = **0**。`uma_core.c` 实际用到的 SMR 接口只有写侧/管理侧的6 个：`smr_advance(` ×3、`smr_poll(` ×2、`smr_create(` ×1、`smr_init(` ×1、`smr_synchronize(` ×1、`smr_wait(` ×1，**没有一个是读侧的 `smr_enter/smr_exit`**。且这 6 个是**跨 TU 的外部函数调用**（实现在 `freebsd/kern/subr_smr.c`，该 TU 编译时不包含我方 `lib/include/vm/uma_int.h`，不受覆盖宏影响）。
  → 因此那 4 处 inline 函数体在本 TU 内**永不被实例化调用**，「它们展开成什么」对 `uma_core.c` 的生成代码**没有任何影响**。这比「它们绑到systm.h 的空函数」是更强的论断：前者不依赖 `systm.h:186 #ifndef FSTACK` 的现状。
- 这与 `_m17_gate_plan.md` 第 93 条已坐实的事实一致：**SMR 读侧的 `critical_enter()` 本来就是空操作，从来不受 `uma_crit_lock` 保护**。→ **G2 对 SMR 零影响**（`_m17_B_external.md` X2 结论）。

### 2.3 因此 G2 的正确性落点

去锁后 UMA per-cpu cache 的唯一保护是 G1 建立的不变式「**每个栈线程独占一个稠密 pcpu 槽位、且线程与槽位 1:1 永不迁移**」。本轮 §4 的运行期数据是对该不变式在**去锁后**仍然成立的直接实证（`reviewer` 要求：去锁后不能沿用去锁前的数据）。

---

## 3. clean build 实测

**`lib/` 与 `example/` 两个目录都先 `make clean` 再完整 `make`，无增量编译**（遵守 clean-build 规约）。

### 3.1 `lib/`

```
cd /data/workspace/f-stack/lib && make clean && make -j16
```

| 指标 | 实测值 | 门槛 / 基线 | 判定 |
|---|---|---|---|
| `make clean` 返回码 | **0** | — | — |
| `make -j16` 返回码 | **0** | 0 | 通过 |
| `grep -c 'error:'` | **0** | 0 | 通过 |
| `grep -c 'warning:'` | **51** | ≤ 51（HEAD 基线） | **未增加**，通过 |
| `.o` 产出 | **248** | 248 | 通过 |
| `libfstack.a` | 生成成功，**7,000,540** 字节 | 生成 | 通过 |

（G1 第四轮同口径为 error 0 / warning 51 / 248 个 `.o`；G2 后**三项完全一致**，`libfstack.a` 略小，与删掉一个变量 + 两处内联原子指令相符。）

### 3.2 `example/`

```
cd /data/workspace/f-stack/example && make clean && make
```

| 指标 | 实测值 | 判定 |
|---|---|---|
| `make clean` 返回码 | **0** | — |
| `make` 返回码 | **0** | 通过 |
| `grep -c 'error:'` | **0** | 通过 |
| `grep -c 'undefined reference'` | **0** | 通过 |
| `nm libfstack.a \| grep -c uma_crit_lock` | **0** | 符号确已消失 |

### 3.3 md5（**与 `make clean` 在同一命令序列内立即取得**，避免上一轮的版本错配）

```
$ cd /data/workspace/f-stack/example && make clean && make && ls -l helloworld && md5sum helloworld helloworld_g1_prelock
-rwxr-xr-x 1 root root 30392664 Aug  4 15:10 helloworld
78c39a6f96e104412ce75351e402907b  helloworld
751a8153d3b200229cff99b3fa7650b0  helloworld_g1_prelock
```

| 二进制 | md5 | 大小 | mtime | 含义 |
|---|---|---|---|---|
| `example/helloworld` | `78c39a6f96e104412ce75351e402907b` | 30,392,664 | 2026-08-04 15:10:44 | 当前 = G1+G2（去锁后） |
| `example/helloworld_g2_nolock` | `78c39a6f96e104412ce75351e402907b` | 30,392,664 | 2026-08-04 15:10:44 | 去锁后副本（`cp -p`） |
| `example/helloworld_g1_prelock` | `751a8153d3b200229cff99b3fa7650b0` | 30,392,704 | 2026-08-04 15:00:57 | **去锁前**（G1-only，`uma_crit_lock` 仍在） |

**关于上一轮 md5 错配的说明（如实记录）**：我上一轮报的 `d49268db…` 与 `reviewer` 复核得到的 `751a8153…` 不一致。本轮开工时**先于任何改动**对未改动的二进制取md5，得到 **`751a8153d3b200229cff99b3fa7650b0`** —— **与 `reviewer` 的值一致**。因此可以确定：`reviewer` 的值是对的，我上一轮报的值来自一个更早的中间构建（探针增删过程中的某次），是我的报数错误，非源码状态分歧。本轮已按要求把 `md5sum` 放进 `make clean && make` 的同一命令序列，杜绝再次错配。

**比 md5 更硬的版本判据**（`tester` 提出，本文采纳并复核）：

```
$ grep -c "uma_crit_lock" helloworld_g1_prelock   → 1   ← 去锁前，符号在
$ grep -c "uma_crit_lock" helloworld_g2_nolock    → 0   ← 去锁后，符号已消失
```

md5 只能证明「两份是否同一份」，符号有无能直接证明「这份到底是去锁前还是去锁后」。

### 3.4 G1 改动完好性核查

```
$ git diff --stat
 config.ini               |  26 ++++++-----   ← 用户/tester 本地测试改动，本 agent 全程未触碰
 lib/Makefile             |   4 ++            ← G1（-DSMP）完好
 lib/ff_dpdk_if.c         |   8 +++-          ← G1 完好
 lib/ff_dpdk_if.h         |   1 +             ← G1 完好
 lib/ff_freebsd_init.c| 115 +++++++++++++ ← G1 完好
 lib/ff_glue.c            |   8 +++-          ← G1(smp_topo) + G2(删锁)
 lib/ff_host_interface.c  |   8 ++++          ← G1 探针
 lib/ff_host_interface.h  |   4 ++            ← G1 探针
 lib/ff_kern_synch.c      |   4 +-            ← G1 完好
 lib/ff_kern_timeout.c    |   6 +--← G1 完好
 lib/include/sys/pcpu.h   |   2 +-            ← G1（curcpu）完好
 lib/include/vm/uma_int.h |  14 +++---        ← G2
```

- `-DSMP` 仍在（本轮 build log 第 867 行的实际编译命令中可见 `-DFSTACK -DSMP`）。
- `lib/include/sys/pcpu.h` 的 `curcpu` → `PCPU_GET(cpuid)` 未被触碰。
- `freebsd/` 上游树**零改动**（`git status` 无任何 `freebsd/` 条目）。
- **`config.ini` 本agent 全程未触碰**（自测用的是另存的独立配置，见 §4.1），符合 config.ini 提交约束。

### 3.5 【M4 门禁必改-1】注释修正后的复验clean build（2026-08-04 15:48）

`lib/` 与 `example/` **再次各自 `make clean` 后完整重编**，`md5sum` 仍在同一命令序列内取得：

| 指标 | 修正前（15:10） | 修正后（15:48） | 判定 |
|---|---|---|---|
| `lib/` make clean rc / make rc | 0 / 0 | **0 / 0** | 通过 |
| `lib/` `error:` | 0 | **0** | 通过 |
| `lib/` `warning:` | 51 | **51** | 未增加，通过 |
| `lib/` `.o` 数（`find . -name '*.o' \| wc -l`） | 248 | **248** | 一致 |
| `libfstack.a` 字节| 7,000,540 | **7,000,540** | 一致 |
| `example/` make clean rc / make rc | 0 / 0 | **0 / 0** | 通过 |
| `example/` `error:` / `undefined reference` | 0 / 0 | **0 / 0** | 通过 |
| `example/helloworld` 字节 | 30,392,664 | **30,392,664** | 一致 |
| **`example/helloworld` md5** | `78c39a6f96e104412ce75351e402907b` | **`78c39a6f96e104412ce75351e402907b`** | **未变** |
| `strings helloworld \| grep -c M17-PROBE` | 3 | **3** | 探针完好 |
| `nm lib/libfstack.a \| grep -c uma_crit_lock` | 0 | **0** | 符号仍无 |

**关键结论：md5 未变，且逐字节相同**（`cmp -s helloworld helloworld_g2_nolock` → 相同）。因为必改-1 是**纯 C 注释**改动，不进入预处理输出的代码部分 → 生成代码完全一致。

→ **`tester` 正在跑的 `helloworld_g2_nolock` 副本无需更新、其去锁后矩阵数据无需作废**。这一点已直接告知 `tester`。

**顺带发现（重要，已避免一次事故）**：执行 leader 要求的 `cp -p helloworld helloworld_g2_nolock` 时报 **`cp: cannot create regular file 'helloworld_g2_nolock': Text file busy`**，`fuser` / `ps` 查证为 **`tester` 此刻正在执行该副本**（PID 1067944，`helloworld_g2_nolock --conf /data/workspace/f-stack/config.ini`，已运行 33s）。

- 因 md5 本就未变，**我没有重试 `cp`，也没有用任何方式强行覆盖**（覆盖正在执行的可执行文件会破坏 `tester` 正在进行的压测）。
- 记录一条通用教训：**向 `tester` 正在使用的副本路径写入前必须先查占用**。`cp`恰好被内核的ETXTBSY 保护挡住了，但若当时改用 `install`/`cat >` 之类会截断文件的写法，就会直接毁掉 `tester` 的运行中进程与本轮数据。后续如确需更新副本，必须先与 `tester` 约定窗口、待其进程退出后再做。

---

## 4. 自测（运行期）

### 4.1 方法与防撞车

- **不改 `config.ini`**：另存两个自测专用配置（内容除 `lcore_mask` 外与 `config.ini` 逐字相同，`md5sum` 已核对 2 线程档与 `config.ini` 一致）：
  - `/data/workspace/f-stack/config.m17_g2_2t.ini`（`lcore_mask=6` → 2 线程、`thread_mode=1`）
  - `/data/workspace/f-stack/config.m17_g2_4t.ini`（`lcore_mask=1e` → 4 线程、`thread_mode=1`）
- **与 `tester` 协调后才上机**：先 send_message 请求独占窗口，`tester` 明确回「现在可以，我不会在你自测期间启动任何进程」且 `ps` 无残留后才启动。
- **进程终止一律走 `/data/workspace/kill_process.sh <具体 PID>`**（不传进程名，避免误伤，遵守 §7.6 记录的风险与kill 规约）。
- **探针输出去向的一个坑（本轮踩到并解决）**：app 的 `printf` 并不落在 shell 重定向的目标文件里，而是落在 f-stack 自有日志 `example/helloworld.log`（worker/主线程混合）与 `example/f-stack-0.log`（栈实例 0）中。为保证数据归属无歧义，采用**字节偏移隔离**：启动前记录两个日志的 `wc -c`，运行后用 `tail -c +$((OFF+1))` 只取本次新增部分。本文数据全部来自该增量片段。

### 4.2 2 线程档（去锁后）

进程存活 106秒，`nlwp=5`（主线程 + worker + EAL intr/mp-msg/telemetry），无崩溃、无 panic。

| dense_idx | tid | pc_cpuid | pc_zpcpu_offset | curcpu | `smr_c_seq`（SMR 槽） | `uz_cpu[curcpu]`（UMA cache 槽） |
|---|---|---|---|---|---|---|
| 0 | 140363320057856 | 0 | 0 | 0 | `0x7fa8e1cc7c80` | `0x7fa8e1ca7180` |
| 1 | 140363278877696 | 1 | 4096 | 1 | `0x7fa8e1cc8c80` | `0x7fa8e1ca7200` |

- SMR 槽距 = `0x1000` = **4096** ✓（= `zpcpu_offset_cpu(cpu)` 的`UMA_PCPU_ALLOC_SIZE`）
- UMA cache 槽距 = `0x80` = **128** ✓（= `sizeof(struct uma_cache)`），两槽**互不相同** ✓
- `dense_idx == pc_cpuid == curcpu` 三者一致 ✓
- `[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=2 / name=pcpu_zone_64 uk_ppera=2`，`mp_maxid=1` → **`uk_ppera == mp_maxid + 1`** ✓（槽位落在已分配范围内）
- 10s wrk（`f-stack-client` 上 `/data/wrk/wrk -t2 -c100 -d10s http://<DPDK_NIC_IP>/`）：**219,241.92 req/s**，`2194165 requests / 0 error`，压测后日志零新增异常。

### 4.3 4 线程档（去锁后）

进程存活 76 秒，`nlwp=7`，无崩溃、无 panic。

| dense_idx | pc_cpuid | pc_zpcpu_offset | curcpu | `smr_c_seq` | `uz_cpu[curcpu]` |
|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | `0x7efdbaaf4c80` | `0x7efdbaad0980` |
| 1 | 1 | 4096 | 1 | `0x7efdbaaf5c80` | `0x7efdbaad0a00` |
| 2 | （标量行丢失，见下） | — | — | `0x7efdbaaf6c80` | `0x7efdbaad0a80` |
| 3 | 3 | 12288 | 3 | `0x7efdbaaf7c80` | `0x7efdbaad0b00` |

- SMR 槽：4 个地址构成**公差 4096** 的等差数列 ✓
- UMA cache 槽：4 个地址构成**公差 128** 的等差数列、**两两不同** ✓
- `uk_ppera=4`、`mp_maxid=3` → **`uk_ppera == mp_maxid + 1`** ✓
- **`dense_idx=2` 的 `[M17-PROBE]` 标量行再次丢失**（`[M17-PROBE-SLOT]` 行在）。原因与 G1 §7 记录的相同：探针用无锁 `printf`，多线程同时写同一 FILE\* 时整行可能被丢弃/交错。**这是探针自身的观测缺陷，不是被测逻辑的问题**——该线程的 `SLOT` 行地址（`0x7efdbaaf6c80` / `0x7efdbaad0a80`）恰好落在等差数列的第 3 项上，反推 `pc_zpcpu_offset=8192`、`curcpu=2`，与其它三个线程自洽。**【推导，非直接实测】**
- 10s wrk（`-t4 -c200 -d10s`）：**391,271.39 req/s**，`3921039 requests / 0 error`，压测后新增日志中零panic / 零 segfault。
  - 说明：日志关键字扫描曾出现1 处`fault` 命中，逐行核查为**假阳性** —— 匹配到ipfw 初始化行 `... de**fault** to accept ...`。已确认无真实故障。

### 4.4 自测吞吐数字的可比性限定（重要）

**我的 wrk 数字不能与 `tester` 的矩阵直接比较，不可用于 DoD-5 判定**：
- 我用 `-t2 -c100 -d10s` / `-t4 -c200 -d10s`（短时、低并发），目的只是「压一下无锁分配路径确认不崩」；
- `tester` 的去锁前矩阵（2 线程中位 235,845 req/s、4 线程 248,961 req/s、soak 2/4 线程 499,223/487,968req/s）用的是它自己的参数与轮次口径。
- 我的 4 线程 391k 明显高于 `tester` 的 4 线程 248k，**几乎肯定是 wrk 参数/连接数差异**而非 G2 带来的提升，**不得据此宣称性能收益**。DoD-5 的正式判定必须由 `tester` 用同口径 A/B 交叉复测给出。

### 4.5顺带观测到的一条（供 `designer`/`reviewer` 注意）

4 线程档日志出现：`TCP Hpts created 4 swi interrupt threads and bound 0 to cpus`。这与 G1 遗留风险清单里「`tcp_hpts` 实例数随 `mp_ncpus` 由 1 变 N、且 callout 归属可能错配」的记录一致，**现在已是可观测事实**（`mp_ncpus=4` → 4 个 hpts swi 线程），不再只是静态推断。本轮未改任何 hpts 代码；`bound 0 to cpus` 说明没有绑核，是否需要处置请 `designer` 裁决。

---

## 5. 与 spec §4.7 的逐条对齐

| spec 要求 | 落实 |
|---|---|
| §4.7 硬前置：`curcpu` 已 per-thread 化 + DoD-1 判定式 ⑤ 已通过 | 由 `reviewer` 在 M3 门禁确认；本轮 §4.2/§4.3 在**去锁后**再次实测通过 |
| §4.7.1 改成 `do {} while(0)` 空操作 | ✅ 逐字一致 |
| §4.7.1 删`uma_crit_lock` 定义 | ✅（先 grep 全树零引用） |
| §4.7.1 保留空宏而非彻底删掉 | ✅（并实测确认 `systm.h:186 #ifndef FSTACK` 现状） |
| §4.7.1 须注释（简短） | ✅ 实质文字 3 行；首版注释前提错误，已按 M4 门禁必改-1 修正（§1.1.1） |
| §4.7.1 慢路径不动 | ✅ 未碰 `ZDOM_LOCK`/`KEG_LOCK`/`vsetzoneslab`/`uma_page_slab_hash` 任何一处 |
| §4.7.2 / §4.7.3 不做 G2-a / G2-c | ✅ 未新增任何锁、未做 per-cpu 锁 |
| §4.7.4 台阶 L0 | ✅ 当前处于 L0（未触发 L1/L2） |
| §4.7.5 diff 面限定 2 文件、可单独 revert | ✅ 2 文件；**但 `ff_glue.c` 需 hunk 级拆分，见 §1.3** |

---

## 6. `reviewer` 建议项的处置（如实记录）

### 6.1 R-a（`lib/ff_freebsd_init.c:381` 用 `sizeof(struct uma_page)` 而非 `sizeof(struct uma_page_head)`）—— **本轮不修**

实测代码原文：

```c
    num_hash_buckets = 8192;
    uma_page_slab_hash = (struct uma_page_head *)kmem_malloc(sizeof(struct uma_page)*num_hash_buckets, M_ZERO);
    uma_page_mask = num_hash_buckets - 1;
```

判断依据（**并修正 `reviewer` 与 leader 对影响面的估计**）：

1. **内存安全**：`sizeof(struct uma_page)`(40B) > `sizeof(struct uma_page_head)`(8B)，是**超额分配**，只浪费不越界。桶数组按`struct uma_page_head *` 索引，步长仍是 8B，落在已分配区间内。
2. **浪费量不随线程数放大** —— 这一点很关键：该分配位于 `ff_freebsd_init()` 内，而 `ff_freebsd_init()` **每进程只执行一次**（主线程），`uma_page_slab_hash` 是**全进程单份全局表**，worker 线程并不各自分配。因此 `thread_mode=1` 下无论 2线程还是 16 线程，浪费恒为 `8192 × (40 − 8) = 262,144` 字节 ≈ **256KB / 进程**，**不是 256KB / 线程**。→ leader 消息中「浪费约 256KB/实例」若指「每栈线程」则偏高；按「每进程」理解才正确。
3. 因此 **`reviewer` 建议的「thread_mode=1 多实例时值得顺手修」这一动机不成立**（多线程并不放大它），我**无法证明它在多线程下会造成实际问题** —— 按 leader「除非你能证明它在多线程下会造成实际问题，我倾向不修」的指示，**本轮不修**。
4. 附带理由：它不属于 G2 的 2 文件 diff 面（§4.7.5 明令「任何其它改动都不得混入 commit-2」），修它就必须挂到 commit-1，而 commit-1 的 G1 门禁**已经 PASS**，改动会使门禁产物与二进制 md5 全部失效、需重新走一遍门禁。收益（256KB）远小于代价。

→ **记为技术债**：`lib/ff_freebsd_init.c:381`哈希桶数组超额分配 4 倍（40B/桶 vs 应为 8B/桶），浪费 256KB/进程，内存安全、非本轮引入（既有写法）。建议在独立的清理提交中修，并同时复核 `num_hash_buckets=8192` 这个固定值在大内存/多线程下是否仍合适。

### 6.2 S5（`lib/ff_freebsd_init.c:319-323` 的 4 行注释压到 2 行）—— **本轮不做**

同 §6.1 第4 点：该文件是 **G1（commit-1）** 的改动面，G1 门禁已PASS、二进制 md5 已被 `tester` 独立核验并用于 A/B 对照。**为压缩 2 行注释而使 G1 门禁产物与两个对照二进制全部失效，代价明显不成比例**。建议合并到 M7 前的探针摘除那次改动里一起做（那次本来就要重编 + 重跑 clean build）。

若leader/`reviewer` 认为必须本轮做，请明示，我会连带重新出G1/G2 两个二进制并更新所有 md5、并通知 `tester` 作废现有对照。

### 6.3 R-d（6 处 `#if1 /* M17 temporary probe */` 探针）—— 按指示**未摘除**

已在 G2 二进制中核实探针**完好可用**（`tester` 去锁后要重跑槽位隔离验证需要它）：

```
$ strings example/helloworld | grep "M17-PROBE"
[M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
[M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
[M17-PROBE-ZONE] name=%s uk_ppera=%u uk_rsize=%u mp_maxid=%u
```

等 leader 在 M5 结束后通知再摘（DoD-8），摘后须重跑 clean build。

---

## 7. DoD-8 清理清单（本轮新增的临时产物）

M7 前须用 `/data/workspace/rm_tmp_file.sh` 清理（**严禁直接 `rm`**）：

| 路径 | 说明 | 可清理时机 |
|---|---|---|
| `/data/workspace/f-stack/example/helloworld_g1_prelock` | 去锁前对照二进制 | **`tester` 明确确认 A/B 交叉 + 去锁后槽位复验都做完之后**（`tester` 已要求先别清理） |
| `/data/workspace/f-stack/example/helloworld_g2_nolock` | 去锁后对照二进制 | 同上 |
| `/data/workspace/f-stack/config.m17_g2_2t.ini` | 自测配置（2 线程） | 自测结束即可清|
| `/data/workspace/f-stack/config.m17_g2_4t.ini` | 自测配置（4 线程） | 自测结束即可清 |
| `/data/workspace/f-stack/example/m17_g2_2t.log`、`m17_g2_4t.log` | 自测 stdout 重定向日志 | 自测结束即可清 |

（G1 的 6 处探针属**代码**改动，由 R-d 走「摘除 + 重编」流程，不在本表。）

### 7.1 【G2-S3】M5 之后的收尾顺序（`reviewer` 建议，leader 已确认）

**必须按此顺序，否则探针会混进产品提交**：

1. M5 全部结束（`tester` 的去锁后矩阵 + A/B 交叉 + 槽位复验都完成）；
2. **leader 通知我**后，我摘掉 6 处 `#if 1 /* M17 temporary probe */` 探针（DoD-8 的代码部分）；
3. 我再跑一次 **`lib/` + `example/` clean build**，并在同一命令序列内给出 **新的 `example/helloworld` md5**（摘探针会真正改变生成代码，md5 **必然变化**，与本轮注释改动不同）；
4. 之后才由 leader 拆 **commit-1(G1) / commit-2(G2)**，其中 `lib/ff_glue.c` 用 `git add -p` 分 hunk（G2 的 `@@ -143,7 +143,6 @@` 与 G1 的 `@@ -169,6 +168,13 @@` 相距约 25 行、无重叠上下文）；
5. 清理本表中的临时二进制与配置/日志（走 `rm_tmp_file.sh`）。

**摘除前须先确认 `tester` 已无进程在跑**（本轮已踩过 `Text file busy`，见 §3.5）。

### 7.2 摘探针的判据体系（11 条 + 3 处加固）与其失效边界

判据由本agent 与 `tester` 往复 6 轮收敛而成。**这一节的价值不在清单本身，而在每条判据「证明不了什么」**——下面 §7.3 记录了两条被实测修正的高估。

| # | 判据 | 基线 → 期望 |
|---|---|---|
| 1 | `diff --new-line-format='%L' --old-line-format='' --unchanged-line-format='' BEFORE AFTER > f`，**须 `rc≤1` 且 `wc -c` = 0** | 0 / 0 / 0 |
| 2 | `git diff lib/ff_host_interface.c lib/ff_host_interface.h` | 非空 → **完全为空**（逐字节回 HEAD） |
| 3 | 三文件行数 | 438/625/206 → **379/617/202** |
| 4 | 列首 `}` 计数（ffinit / hi.c） | 7/52 → **5/51** |
| 5 | `grep -rl "M17" lib/`（整目录，含 `.o`/`.a`） | 5 个 → **无输出** |
| 6 | `nm lib/libfstack.a` 探针符号 | 2 → **0** |
| 7 | `strings<产物> \| grep -c M17-PROBE` | 3 → **0** |
| 8 | `lib/`+`example/` **均 clean build**，rc=0 / error 0 / **warning = 51**（≠51 亦算不通过） | 通过 |
| 9 | `tester` 收尾回归（2T/4T/tm=0），**双侧±2%** | 通过 |
| 10 | ① `git status --porcelain lib/` **集合比对**（非计数）11→9；② `^??` 0→0；③ `freebsd/ example/ tools/` 已跟踪改动 0→0；④ 全仓已跟踪 12→10 | 全部 |
| 11 | `md5sum -c` 8 个「本次不该动」的文件 | 8/8 OK |
| 加固 | `git diff --summary lib/`（mode change / 新增 / 删除 / 改名） | 空 → 空 |

**判据 before 侧位于 `/data/workspace/m17_judge_baseline/`（仓库之外）**，含 3 份摘除前源码原文、`m17_j11_baseline.txt`、`j10_lib_set_before.txt`、`j1_mode_summary_before.txt`。

- **为何必须放仓库外**：放进仓库内会使 `git status --porcelain lib/ | grep -c '^??'` 从 0 变非 0，**直接打破判据 #10-②——判据自己把判据搞失效**。已用 `git rev-parse --show-toplevel` 做机械确认（`= /data/workspace/f-stack`，基线目录不在其下），而非「我觉得它在仓库外」。
- **为何必须从 `/tmp` 迁出**（`tester` 提出）：`/tmp` 会被系统清理、重启即失；一旦被清，#1/#11 直接跑不了，而「事后重新采集基线」是毫无意义的（见下条纪律）。
- **`cp -p` 保留 mtime 带来一个副产品旁证**：`ff_freebsd_init.c` 自 14:52、`ff_host_interface.c/.h` 自 14:01 未再变动 —— 与「源码一行未动」互为独立印证，也证明 `tester` 15:29~15:46 的去锁后矩阵跑的正是该份源码对应的二进制，时间线自洽。

**【硬规矩】禁止为使判据通过而刷新基线。** #1/#11/#10-① 的基线取自 `reviewer` 已审过的状态（M3/M4 门禁已覆盖那 8 个文件）。若因 `reviewer` 要求的新改动导致 #11 FAIL，**必须先由 leader 或 `reviewer` 书面批准并说明原因**才能重采；重采时须记录「旧基线值、新基线值、重采原因、批准人」四项。**单方面刷新基线等同于删除该判据。**
> 该规矩针对的痛点是 `tester` 指出的「基线文件没有历史、事后看不出来」；「记录旧值」这一项的作用是让重采动作**自己留下痕迹**。

**【语义边界】#11 只证明「没被本次摘探针动过」，不证明「内容是对的」。** 内容正确性由 M3/M4 门禁负责，两者**不可互相替代**，禁止把 #11 当作正确性证明。

**【停手条件】#1 / #3 / #4 / #10 / #11 任一条对不上，立即停手并上报 leader 与 `tester`，禁止以「其它判据都过了」为理由继续。**

### 7.3 摘除实况：由第三方执行，判据 10/11 通过、#3 对不上（本 agent 已按停手条件停手）

**事实**：`lib/ff_freebsd_init.c` mtime **16:22:10**，随后全量重编（`.o` 16:22:29~45、`libfstack.a` 16:22:45、`example/helloworld` 16:22:55）。**本 agent 从未执行摘除动作**（最后一次改源码是 15:4x 的门禁必改-1，只改 `uma_int.h` 注释）。**摘除的实际执行方待leader 确认** —— 本文不能替不知情的执行方作证其「是否按§7.2 方案执行」。

**发现路径值得记录**：本agent 原本只是要核对 P3 相邻的 `__sync_lock_release(&init_lock);` 是否在第 274 行，结果 `grep -n init_lock` 报179/189/220，**行号与 14:52 的读数对不上**，才发现文件已变。即：**这次是「行号漂移」这个副产品信号暴露了改动，而不是任何一条判据主动报警** —— 判据是事后才跑的。

| # | 实测 | 判定 |
|---|---|---|
| 1 | rc=1、新增 **0 字节**（三文件） | ✅纯删除成立 |
| 2 | 空 | ✅逐字节回 HEAD |
| **3** | **380** / 617 / 202（期望 379/617/202） | ❌ **差 1 行** |
| 4 | 5 / 51 | ✅（但见下方更正） |
| 5 | 无输出 | ✅ |
| 8 | `.o` **248/248 全部落在 16:22**（16:22:29.335~16:22:45.521，跨度16s并行），无一残留旧 mtime → **全量重编** | ✅（`tester` 用 mtime 分布反推坐实；本 agent 原判「无法追溯」已关闭） |
| 9 | PASS，见 §7.4 | ✅ |
| 10 | 9 / 0 / 10 / 0 | ✅ |
| 11 | **8/8 OK** | ✅ G2 交付物未被误伤 |

**#3 的 1 行偏差已定位**：现`ff_freebsd_init.c` **377、378 两行是并排空行**（在 `ff_stack_inited = 1;` 之后）。成因是删 P4 块（原 432-435）时**未删相邻的原 436 空行**，于是原 431 与436 两个空行并列。`tester` 用 `cat -A` 取得字符级证据（连续两个 `<EOL>`）。**属纯格式瑕疵，无语义影响**；语义已双方各自逐行确认：`ff_pcpu_thread_init()` 现为 `... PCPU_SET(prvspace, pcpup); }`，与 HEAD 应有形态一致。

**本 agent 未自行修补**，依据是 §7.2 的停手条件（#3 在停手条件内）。已三次请 leader 裁决「修不修」，并给出建议：**修**。理由不是那个空行本身，而是——**留着一条长期 FAIL 的停手判据，会把「停手条件」这件事本身变成可以习惯性忽略的东西**，其危害大于多一个空行。

**修补动作自带验证（md5 预期）**：若裁决修，预期 clean build 后 `helloworld` md5 **仍为 `df05d2cd078d631ad2d8ee7caba8d387`**，依据三条：
1. **`lib/` 编译不带 `-g`**（`lib/Makefile:31` 的 `DEBUG=` 整行被注释；实际命令 `cc -c -O2 -fno-strict-aliasing …` 无 `-g`）。**这条最关键**：若带 `-g`，删一个空行会移动 DWARF 行表（`.debug_line`），`.o` 必然逐字节改变、md5 必变，**即使代码生成完全相同**。`tester` 原先的推理只排除了 `__LINE__`，未排除这条路径。
2. `ff_freebsd_init.c` **无 `__LINE__`/`__FILE__`**（grep 无命中）；`panic()` 在 106 行、位于空行之前且不嵌行号；`KASSERT` 因无 `INVARIANTS` 已编译掉。
3. **实证先例**：门禁必改-1 是纯注释改动，clean build 后 md5逐字节不变（§3.5）。注释与空白同属「不影响生成代码」的改动类别。
   - 反向提示：`example/Makefile:13` 确实带 `-O0 -g -gdwarf-2`，但只作用于**未改动的`main.c`**，`libfstack.a` 是预编译静态库 → 结论不变。**故「本项目不带 -g」不能笼统说，须区分 `lib/`（无）与 `example/`（有）。**

→ 于是：**md5 与预期一致 → 修补确认无副作用，且 `tester` 的 #9 结果可直接沿用；md5 若不一致 → 与上述三条依据矛盾，属需停手排查的异常信号**，须先上报而非让 `tester` 重跑。

### 7.3.1 后续实况：空行已被修掉、md5 预期被证实、commit 已完成

**时间线（全部 mtime/git 实测）**：
```
16:40:46  lib/ff_freebsd_init.c 再次被改（第三方，非本 agent）→ 380 行变379 行，并排空行消失
16:42:19  ff_freebsd_init.o 重编16:42:42 libfstack.a      16:42:44 example/helloworld
其后      commit 完成（工作区 lib/ 已无 modified）
```

**① 本 agent 的 md5 预期被证实（§7.3 的三条依据成立）**
```
修补+ 重编后 example/helloworld = df05d2cd078d631ad2d8ee7caba8d387   ← 与预期逐字一致
```
→ 删空行**确实没有改变生成代码**（`lib/` 无 `-g`、无 `__LINE__`、注释改动先例三条依据得到实证支持）。
→ **`tester` 的 #9 收尾回归对象（md5 `df05d2cd…`）与最终提交产物逐字节相同 → #9 结果对最终产物完全有效，无需重跑。** 这是本轮最重要的一处闭环：**收尾回归测的就是提交产物本身，不是它的近似物。**

**该 md5 预期的取证性质（`tester` 指出，值得单独记一笔）**：这个预期是在**修补动作发生之前**写下的（见 §7.3与 `_m17_F_runtime.md` 第四部分 Y4-2），属**事前预测被事后数据证实**，而非事后解释。因此 §7.3 那三条依据（`lib/` 无 `-g`、无 `__LINE__`、注释改动实证先例）是**被预测检验过的推理**，不是「讲得通的推理」—— 这个性质在取证链上比结论本身更值钱。

**独立复核**：上述 md5/字节数/行数/commit 清单，`tester` 已用只读命令自行跑过一遍，结果与本文逐项一致（其记录见 `_m17_F_runtime.md` 第五部分）。**本轮双方互报的每个数字都经过对方独立复算，未采用单方转述。**

**② 判据终态（commit 后重跑）**
| # | 期望 | 实测 | 判定 |
|---|---|---|---|
| 1 | 0 字节 ×3、rc≤1 | rc=1，**0 / 0 / 0** | ✅ |
| 2 | 空 | **0 字节** | ✅ |
| **3** | **379 / 617 / 202** | **379 / 617 / 202** | ✅ **已转绿**（原380） |
| 4 | 5 / 51 | 5 / 51 | ✅ |
| 5 | 无输出 | **0 个文件** | ✅ |
| 11 | 8/8 OK | **8/8 OK** | ✅ |
| 加固 | `git diff --summary lib/` 空 | **0 字节** | ✅ |
| 补充 | 连续空行扫描 | **无** | ✅ |
| **10** | 9 / 0 / 10 / 0 | **0 / 0 / 1 / 0** | ⚠ **基线已因commit 失效**（见下）|

**#10 的基线在 commit 后失效——这与§8 风险 10 预先登记的完全一致**，不是意外：`git status --porcelain lib/` 从 9 变0（lib/ 全部已提交）、全仓已跟踪改动从 10 变 1（仅剩 `config.ini`）。**#10 的 commit 后等价形态**应改为核对提交本身：

```
commit-257b612d16  "Drop the global uma_crit_lock spinlock ..."
          → lib/ff_glue.c、lib/include/vm/uma_int.h  ←恰好 2 个文件，符合 spec §4.7.5 硬性限定
commit-1  c7996a94f  "Make the f-stack kernel view SMP-aware for native-mt ..."
          → lib/Makefile、ff_dpdk_if.c、ff_dpdk_if.h、ff_freebsd_init.c、ff_glue.c、
             ff_kern_synch.c、ff_kern_timeout.c、include/sys/pcpu.h   ← 8 个文件
两个 commit 均未包含任何 freebsd/ 路径     ← 「上游树零改动」不变量在提交层再次坐实
lib/ff_host_interface.c / .h 不在任何一个 commit 中 ← 探针已摘净、两文件逐字节回到 HEAD（与 #2 一致）
```

**③ `ff_glue.c` 的 hunk 级拆分已正确完成** —— 这是本 agent 在 §1.3 提出更正并反复提醒的风险点：`lib/ff_glue.c` **同时**出现在 commit-1 与 commit-2 中，说明提交时确实按 hunk 拆分（`git add -p`）而非整文件 `git add`。**因此 commit-2（G2）可以被单独 `git revert`，spec §4.7.5 的可分性要求得到满足。**

---
### 7.4 `tester` 的#9 收尾回归：PASS，以及 ABA 救回的一次误判

**#9 已由单侧改为双侧判定**（`tester` 提出，本agent 复核其论证成立）：4 个探针块全在启动路径（P1 每线程一次、P3 每 worker 一次、P4 整进程一次、P2 仅函数定义），**收发包路径上一条都没有 → 每包开销为零 → 语义期望是「吞吐完全不变」而非「不变差」**。因此**偏高同样可疑**（可能误删了真在干活的逻辑），单侧判据会把这种情况误判为通过。

**结果（数据来源：`tester`）**：2线程 **−0.24%**、4 线程 **+0.06%**、tm=0 1 进程 **+2.10%**、tm=0 2 进程 −2.96%（弱证据已标注）→ **PASS**。Hang 检查全档通过（进程存活 + `curl`=200 + `NLWP` 5/7/4/4+3，新增日志 `panic|assert|segmentation` 全0）。**运行时实证探针确已消失**：各档新增日志 `grep -c M17-PROBE` = **0**（第三部分同位置必有 4~5 条）。

**#9 的一条失效模式（本 agent 提出，已纳入 `tester` 判定规则）**：P3 块紧邻 `__sync_lock_release(&init_lock);`（`init_lock` 用于 worker 串行化，见 `ff_freebsd_init.c:179/189/220`）。若误删该行，后果是**下一个 worker 启动时永久阻塞——表现为「卡死」而非「崩溃」**。故「启动后无流量 / 进程 hang / `wrk` 连不上」一律判 **FAIL，不得当作环境抖动重试**。本次该行完好（三处引用均在，运行时亦无阻塞）。

**ABA 同窗对照救回一次 FAIL 误判（重要方法学结论）**：若按预注册的**单点**判据，4 线程档无探针合并6 轮中位 247,068.79 vs 第三部分基线 254,913.26 = **−3.08%**，落在双侧区间 `[249,815, 260,011]` 之外 → **会判FAIL**。而ABA 显示：
```
A1 无探针 242,102.55（首块偏低）│ B 带探针 248,303.61 │ A2 无探针 248,459.02（与 B 相差 +0.06%）
```
**带探针版 `g2_nolock`（md5 未变、同配置、同客户端）在同窗只跑出 248,303.61，相对其自身第三部分的 254,913.26 也低 −2.59%** → 缺口来自**机器环境漂移，与代码无关**。

→ **方法学结论（建议推广到本项目所有性能判据）：在 ±2% 量级的判据下，跨数十分钟的「与旧基线单点比较」不可靠，必须同窗交叉 + 用「同一个未变的二进制」复测来量化漂移。本轮环境 1 小时内漂移 2.6%~3.2%，已超过判据自身的容差。**

**并且必须是 ABA 而非 AB —— A 块要重复两次。** 依据就是下面这次自我证伪：单看 `A1(242,102) vs B(248,303)`，A 偏低 2.5%，看上去像「无探针版更慢」，正好能被「二进制小了 32 字节 → 布局/i-cache 对齐变化」这个听起来合理的解释吸收；**只有 A2(248,459) 出现、与 B 相差 +0.06% 时，才能把 A1 的偏低归因于首块预热而非代码**。**若设计成AB 而不是 ABA，那个错误归因就会以「结论」的形式进 spec。**（该论证由 `tester` 提出。）

**`tester` 主动记录了一次自我证伪**（本文如实转载）：它在看数据**之前**预注册过一个归因——「二进制小了 32 字节 → 布局/i-cache 对齐变化」。该归因被 A2 块（248,459 ≈ B 的 248,303）**直接证伪**，真实原因是首块预热 + 环境漂移。**本文保留该错误归因而不抹除，价值在于让后来人知道哪些解释是被数据排除过的，而不是重新踩一遍。**

### 7.5 两条被实测修正的判据高估（须转`reviewer`，避免过度信赖）

**更正一：#4（列首 `}` 计数）对「等量替换」是盲的，证明力弱于原评估。**
`diff` 的删除清单显示，本次删除的是**原第 120 行 `}`（`ff_pcpu_thread_init()` 的收尾，属真实代码）**，而**保留了原第 163 行 `}`（`ff_probe_pcpu_zone()` 的收尾，属探针代码）**。这**正是**当初设定 #4 时想防的最坏形态——「误删一个 `}` 再从别处留/补一个凑平衡」——而 **#4 的计数照样是 5，完全隐形**。

本例**实际无害**：两种删法产生的净文本完全相同（`PCPU_SET(...);` 后紧跟 `}`），属 `diff` 的行对齐歧义而非真的删错，双方均已读原文确认。但结论必须更正：**真正兜住这类风险的是 #1（子序列/纯删除判据），#4 只能作为辅助判据。** 当初还为 #4 附加过一个错误论证（「误删再补会掉 3~4、对不上 5」）——等量替换时计数不变，该论证不成立。

**归属如实记录：这是 `tester` 提出设想、本 agent 采纳并附加错误论证，属双方共同高估**，不记为单方问题（`tester` 曾主动揽为己责，本 agent 未接受）。

**更正二：#1 与 #3 的分工比原描述更细—— #1 管「没多加」，#3 管「没少删」，方向相反、缺一不可。**
`#1 = 0` 只保证 after 是 before 的子序列（没有任何新增/修改行），**它保证不了「该删的没删干净」**。本轮 #3 差 1 行而#1 为 0，正是这个分工的实例。
**并且：我们反复预判「新增空行是本任务的结构性盲区」（那 9 处相邻空行 `113/121/165/431/436`、`.c:151/159`、`.h:50/54`），位置预判对了，方向猜反了** —— 实际出偏差的是「少删空行」而非「多加空行」。

### 7.6 判据体系的闭合性论证（供`reviewer` 复核完备性）

```
lib/ 下 11 个 modified 文件 = 该动的 3 个+ 不该动的 8 个        （3+8=11，与 #10-① 基线精确对齐）
内容层：#1（那 3 个：纯删除） + #11（那 8 个：逐字不变）        →覆盖全部 11 个文件的内容
集合层：#10 ①②③④                                              → 覆盖「有没有第 12 个文件被牵连」
产物层：#5#6 #7 #8                → 覆盖「产物里真没了 + 真做了全量重编」
运行层：#9                                                → 覆盖「无崩溃 / 无 hang / 无每包开销变化」
```
**#11 引入之前，内容层只覆盖 3/11** —— 即 `lib/include/vm/uma_int.h`（**G2 的全部交付物**）、`lib/ff_glue.c`（G2 删锁 + G1 `smp_topo`）、`lib/include/sys/pcpu.h`（G1 `curcpu` per-thread 化，**去锁安全性的根基**）当时**零判据保护**：#1 不含它们、#2 只看 `ff_host_interface.*`、#10-① 只数它们「还在 modified 列表里」而不看内容。

**已知的剩余盲区（如实登记）**：
1. **判据只覆盖「摘探针」这一个动作**。若在判据跑完之后、拆commit 之前再发生任何改动，需重跑 #1/#3/#4/#10/#11 才有效。判据窗口 = 「摘完之后、`git commit` 之前」（#10-④ 的 12→10 基线在 commit 后即失效）。
2. **摘探针后 DoD-1 的槽位隔离无法再直接验证**（探针没了就读不到 `pc_zpcpu_offset`/`smr_c_seq`/`uk_ppera`）。#9 只能证明「无崩溃、无吞吐回归」，**不能重新证明槽位隔离**。DoD-1 的取证只能引用带探针版本的数据，**并依赖「摘探针是纯删除、不改变正式逻辑」这一前提** —— 该前提由 #1 + #11 + `reviewer` 的逐行 diff 复核共同承担，**不能只靠运行时测试**。这是取证链上的一处**显式前提依赖**，在此明确标注而非含糊带过。

---

## 8. 残留风险与未坐实项

| # | 项 | 强度 |
|---|---|---|
| 1 | **慢路径无锁窗口是否放大到会破`uma_page_slab_hash` 链**：本轮只跑到 10s wrk，**未做 soak**。spec §4.7.4 的 L1 触发判据（崩在 `uma_int.h:101/:102` + 复合条件）需 `tester` 的 60s/400 连接 soak 才能检验 | 【未坐实】，与 `_m17_A_codepath.md` 附录 A.2 的 U8-perf 一致 |
| 2 | **`dense_idx=2` 的标量探针行丢失**：4 线程档该线程的 `pc_zpcpu_offset`/`curcpu` 是由 SLOT 行地址反推的| 【推导】。若 `reviewer` 要求直接实测，需给探针 `printf` 加锁或改用 per-thread 缓冲，属探针改造|
| 3 | **性能是否有提升未知**：我的 wrk 口径与 `tester` 不同，不可比（§4.4）。DoD-5 结论只能由 `tester` 的 A/B 交叉给出。若无提升，按 plan §DoD-5 需以「正确性收益」（§2.4/§4.7.1）论证保留 | 【待`tester`】 |
| 4 | **`tcp_hpts` 4 个 swi 线程且未绑核**（§4.5）：G1 引入的 `mp_ncpus=N` 的副作用，本轮实测确认存在，未处置 | 【实测存在，未评估影响】 |
| 5 | **`net.isr.dispatch` 必须保持 `direct`**（G1 遗留风险，未变）：若改为 deferred，netisr 线程无 `pcpup`，去锁后会由「静默共享槽位」变成「NULL 解引用崩溃」 | 【静态坐实，未运行期验证】 |
| 6 | **D9 场景的失败模式已变化**（G1 已记录，G2 不改变结论）：`ff_pthread_create()` 线程 `pcpup == NULL`，现在是立即崩而非静默错 | 【静态坐实】 |
| 7 | **摘探针的实际执行方未确认**：16:22:10 的改动非本 agent 所为，本文无法替其作证「是否按 §7.2 方案执行」。`reviewer` 的逐行 diff 复核因此**不可省略**——它是该动作唯一的独立取证 | 【待leader 确认】 |
| 8 | **#3 仍处 FAIL 状态**（一处并排空行，`ff_freebsd_init.c:377-378`）。修补方案与md5 预期见 §7.3，等leader 裁决。**在它被处置或被 `reviewer` 书面认可为已知偏差之前，判据体系不算全绿** | 【已定位，待裁决】 |
| 9 | **性能判据的方法学风险（新增，来自 §7.4 的实测）**：本轮环境 1 小时内漂移 **2.6%~3.2%**，**超过±2% 判据自身的容差**。任何跨数十分钟的「与旧基线单点比较」都可能给出错误的 PASS/FAIL；必须同窗 ABA + 用同一未变二进制量化漂移。本轮正是靠 ABA 才避免了一次 FAIL 误判 | 【实测坐实】 |
| 10 | **判据窗口是「摘完之后、`git commit` 之前」**：#10-④ 的 `12 → 10` 基线在 commit 后即失效。若该窗口内再发生任何改动，#1/#3/#4/#10/#11 必须全部重跑 | 【流程约束】 |
| 11 | **`config.ini` 合规已坐实，但吞吐绝对值不可复现**（本 agent 独立复核，非采信转述）：`git diff --cached` 空、两个 commit 均不含 `config.ini` → **不入库规约满足**。但工作区 `config.ini` 与仓库默认值存在**性能相关**差异，其中 `idle_sleep=0 → 20` 会改变轮询/让出行为，而 `_m17_F_runtime.md` 的全部吞吐绝对值都是在该配置下测得的。→ **DoD-5 的百分比结论安全**（A/B 两侧同配置，差值不受影响），但 **236,033 / 254,913 这类绝对值在 `config.ini` 被改回默认后将无法复现**。建议在 `_m17_F_runtime.md` 中固定记录测量时的有效配置（至少 `lcore_mask` / `thread_mode` / `idle_sleep`），否则后续审计只能重跑、不能复算 | 【实测坐实，建议留痕】 |
| 12 | **16:22 摘探针与 16:40 修空行的执行者身份未确认**：本 agent 声明非其所为，`tester` 亦声明非其所为。故这两次改动缺少执行方的自述取证，**`reviewer` 的逐行 diff 复核是其唯一独立取证，不可省略**。判据 before 侧 `/data/workspace/m17_judge_baseline/` 应保留至该复核完成 | 【待 leader 追查】 |
