# M18 遗留风险专项 —— P1/P3/P6 代码审核门禁报告（I）

审核者：reviewer2（独立审核，写审分离）。仓库 `/data/workspace/f-stack`，HEAD `e0fb11c9c`。
审核对象：本轮 P1/P3/P6 的**未提交工作区改动**（`git diff lib/ freebsd/ tests/`）。
文件：`freebsd/netpfil/ipfw/ip_fw_dynamic.c`、`freebsd/netinet/tcp_hpts.c`、`lib/include/amd64/include/pcpu.h`、`lib/ff_api.h`、`tests/unit/test_ff_thread.c`、`tests/unit/Makefile`。

**总结论：PASS-with-fixes**（唯一 fix 为规约提醒项，非代码缺陷，见 §5）。

---

## 1. P1（DPCPU 别名 → 显式数组）—— PASS

改动：`dyn_hp` 从 `DPCPU_DEFINE_STATIC(void *, dyn_hp)` 改为 `static void **dyn_hp`，`DYNSTATE_GET(cpu)`=`ck_pr_load_ptr(&dyn_hp[(cpu)])`、`DYNSTATE_PROTECT(v)`=`ck_pr_store_ptr(&dyn_hp[curcpu],(v))`。

### 1.1 类型/语义正确性（坐实）

- 原 `DPCPU_ID_PTR((cpu), dyn_hp)` 与 `DPCPU_PTR(dyn_hp)` 均返回 `void**`（指向该 cpu 槽位）；新 `&dyn_hp[(cpu)]`、`&dyn_hp[curcpu]` 亦为 `void**`。**类型完全等价**。
- `ck_pr_store_ptr(DST, VAL)`（`freebsd/contrib/ck/include/ck_pr.h:185`）DST 期望 `void**`、VAL 期望 `void*`；`DYNSTATE_PROTECT(s)` 传入 `&dyn_hp[curcpu]`（`void**`）+ `s`（`dyn_*_state*`，隐式转 `void*`）。匹配。`ck_pr_load_ptr(SRC)`（`:202-203`）SRC 为 `void**`，返回 `void*`。匹配。

### 1.2 malloc/free 对称（坐实）

- `dyn_init`：`if (IS_DEFAULT_VNET(curvnet))` 内 `dyn_hp_cache` 与 `dyn_hp` **并列** malloc（均 `mp_ncpus * sizeof(void*)`、`M_WAITOK|M_ZERO`）。
- `dyn_uninit`：同 `if (IS_DEFAULT_VNET(curvnet))` 内 `free(dyn_hp_cache)` 与 `free(dyn_hp)` **并列**。
- 与 `dyn_hp_cache` 完全对称，**无泄漏、无双重释放、无漏释放**。

### 1.3 索引越界（坐实）

- `mp_ncpus = nb_cpus`、`mp_maxid = nb_cpus - 1`（`lib/ff_freebsd_init.c:310-311`），`CPU_SET(0..nb_cpus-1)`（`:312-313`），无 `CPU_ABSENT`。
- `CPU_FOREACH(i)` 迭代 `i ∈ [0, mp_maxid] = [0, nb_cpus-1]`（`freebsd/sys/smp.h:197-199`），跳过 `CPU_ABSENT`（本场景无 absent）。
- `dyn_hp` 数组大小 = `mp_ncpus = nb_cpus`，索引 `0..nb_cpus-1`。`&dyn_hp[i]` **不越界**。
- `curcpu`（`DYNSTATE_PROTECT` 用）= `PCPU_GET(cpuid)` = `pc_cpuid`。`pc_cpuid` 由 `ff_pcpu_thread_init(cpuid)` 传入，主线程传 `ff_cur_proc_id()`（`ff_dpdk_if.c:471` `lc->proc_id = ti`，ti 为稠密 `0..nb_cpus-1`）或 `0`（多进程），worker 传 `qconf->proc_id`（同稠密）。`ff_pcpu_thread_init` 内有 `cpuid > mp_maxid` 越界 panic 兜底（`ff_freebsd_init.c:106-108`）。故 `dyn_hp[curcpu]` **不越界**。
- `curcpu` 宏在编译单元可用：include 链经 `lib/include/sys/pcpu.h:34`（`#define curcpu PCPU_GET(cpuid)`）。

### 1.4 旧引用残留（坐实）

- 全文件 `DPCPU_ID_PTR`/`DPCPU_PTR`/`DPCPU_DEFINE` 已无残留（仅 `DYNSTATE_GET/PROTECT` 宏内引用 `dyn_hp`）。clean build 0 error 佐证。

**结论：PASS。**

---

## 2. P3（tcp_hpts 原子互斥）—— PASS

改动：`__tcp_run_hpts` 用 `__atomic_exchange_n(&hpts->p_hpts_active, 1, __ATOMIC_ACQUIRE)` 抢占 + 结尾 `__atomic_store_n(..., 0, __ATOMIC_RELEASE)`，移除 `out_with_mtx`/`HPTS_UNLOCK`/二次检查。

### 2.1 原子互斥语义（坐实）

- 原 `HPTS_TRYLOCK(hpts)` 在 f-stack 下 `p_mtx` 塌缩为无互斥（`lib/include/sys/mutex.h` stub），实际**未提供互斥**。新 `__atomic_exchange_n` 返回旧值：旧值非 0 → 已有 worker 运行 → return；旧值 0 → 独占进入。这是标准 trylock+flag 语义，**真正 per-instance 互斥**，等价且更正确（修复了原无互斥缺陷）。

### 2.2 NET_EPOCH 配对（坐实）

- 新流程：抢占失败 → `return`（**未 enter**）；抢占成功 → `NET_EPOCH_ENTER(et)` → ... → `__atomic_store_n(...,0)` → `NET_EPOCH_EXIT(et)`。enter/exit **严格配对，无泄漏**。原 `out_with_mtx` 标签（enter 后 goto 跳出）已消除。

### 2.3 类型与内存序（坐实）

- `p_hpts_active` 为 `uint16_t`（`tcp_hpts.c:226`），`__atomic_exchange_n`/`__atomic_store_n` 对 `uint16_t*` 生成正确宽度的原子操作（x86 下 lock xchg / mov），返回值 `uint16_t`，`1` 隐式转换，类型匹配。
- ACQUIRE（获取互斥，保证临界区内读到的共享状态最新）/ RELEASE（释放互斥，保证临界区内写入对后续线程可见）为正确的 mutex 语义。

### 2.4 swi 路径影响（坐实）

- `tcp_hpts_thread`（`tcp_hpts.c:1656`）是 `p_hpts_active` 非原子读写（`:1682/1720/1794`）的另一条路径，但其唯一入口是 swi（`swi_add(&hpts->ie, "hpts", tcp_hpts_thread, ...)` `:2005`）。
- f-stack 下 `swi_add` 返回 0 不注册（`lib/ff_kern_intr.c:84-89`）、`swi_sched` 空函数（`:91-95`）→ `tcp_hpts_thread` **从不执行**，是死代码。非原子读写与 `__tcp_run_hpts` 的原子操作**不会并发混合**，不受影响。**已坐实**。

**结论：PASS。**

---

## 3. P6（惰性 fail-fast）—— PASS

改动：`pcpu.h` 加 `ff_pcpu_get()`（`__builtin_expect(pcpup==NULL,0)` → panic）+ `get_pcpu`/`PCPU_GET`/`PCPU_ADD`/`PCPU_INC`/`PCPU_PTR`/`PCPU_SET` 全改经 `ff_pcpu_get()`；`ff_api.h` 注释措辞更新。

### 3.1 语义等价（坐实）

- 原 `PCPU_GET(member)` = `pcpup->pc_##member`；新 = `ff_pcpu_get()->pc_##member`，而 `ff_pcpu_get()` 在 pcpup 非 NULL 时直接 `return (pcpup)`。**语义等价**（仅多一次空指针检查 + 内联函数调用开销，见 §3.3）。`PCPU_PTR`/`PCPU_SET`/`PCPU_ADD`/`PCPU_INC` 同理。

### 3.2 panic 前置声明冲突（坐实：无冲突）

- 新 `void panic(const char *fmt, ...) __attribute__((noreturn));`（`pcpu.h:47`）。
- 内核态已有 `freebsd/sys/kassert.h:116` `void panic(const char *, ...) __dead2 __printflike(1, 2);`，`__dead2` = `__attribute__((__noreturn__))`。两者签名**一致**（`void panic(const char*, ...)` + noreturn），C 对重复声明**不报错**，属兼容重复声明（仅丢失 `__printflike(1,2)` 格式检查属性，无功能影响）。
- host 态 `panic` 真实定义在 `lib/ff_host_interface.c:156-165`（`vprintf` + `abort()`），并有前置声明 `:152`。声明-定义关系正常。
- clean build 0 error 佐证无实际冲突。

### 3.3 性能评估（判断：可接受，建议后续压测确认）

- `ff_pcpu_get()` 为 `static __inline`，正常路径 `__builtin_expect(pcpup == NULL, 0)` 预测不跳转，仅一次指针判空 + 一次 TLS 读取 + return，**近似零开销**（与原来直接 `pcpup->` 相比，仅多一次分支预测友好的判空）。
- `PCPU_GET` 在数据面热路径大量使用（如 `curcpu`、`PCPU_GET(cpuid)`）。理论上每次多一次判空分支，但 CPU 分支预测器对 `__builtin_expect` 标记的恒定不命中路径可完美预测，实际开销可忽略。
- **判断**：可接受，无需阻塞；建议在后续性能基线（M18 后续阶段）用 thread_mode=1 数据面压测对比确认无热路径退化（本报告不阻塞，标「需压测确认」为低优先级）。

### 3.4 ff_thread.c / ff_api.symlist 回退（坐实）

- `git diff --stat lib/ff_thread.c lib/ff_api.symlist` 输出为空 → **已回退至 HEAD，无 diff**。
- `ff_api.h` 注释措辞已改为「lazy fail-fast (panic)」，与惰性方案一致，非「入口 abort」。

### 3.5 test_ff_thread.c 单测逻辑（坐实）

- `pcpup` 零初始化（`= NULL`，匹配真实 f-stack 语义）；`test_setup` 设 `pcpup = &g_dummy_pcpu`、`g_panic_fired = 0`。
- 4 个纯计算用例（basic/arg_passed/join_retval/malloc_failure）routine 仅 flag++/观察 pcurthread，**不触达 curcpu**，惰性 fail-fast 下正常。
- fail-fast 用例 `test_ff_pthread_create_failfast`：主线程设 `pcpup = NULL` → `sigsetjmp` → `curcpu`（`PCPU_GET(cpuid)` → `ff_pcpu_get()` → `panic`）→ `__wrap_panic` 设 `g_panic_fired=1` + `siglongjmp` → 断言 `g_panic_fired == 1`。逻辑自洽，fail-fast 发生在主线程（非子线程），`sigsetjmp/siglongjmp` 恢复正确。
- `__wrap_panic` 提供（而非重复定义 `panic`），`panic` 真实定义在 `ff_host_interface.o` 被 `-Wl,--wrap=panic` 重定向，避免 `multiple definition`。**Makefile 已含 `-Wl,--wrap=panic`**（`tests/unit/Makefile:211`）。

**结论：PASS。**

---

## 4. 零回归（thread_mode=0 多进程）—— PASS

- 四修复均不改变 thread_mode=0 路径的语义：
  - P1：`dyn_hp` 数组在多进程下 `mp_ncpus = nb_cpus = 1`，`curcpu = 0`（`ff_pcpu_thread_init(0)`），`dyn_hp[0]` 唯一槽位，等价原 DPCPU 单槽位。
  - P3：`__tcp_run_hpts` 原子互斥在多进程单线程下无并发，exchange 恒成功，行为等价。
  - P6：主线程/worker `pcpup` 非 NULL（`ff_pcpu_thread_init` 里 `malloc` + `pcpu_init` 赋值），`ff_pcpu_get()` 正常返回 `pcpup`，不触发 panic；多进程主线程亦经 `ff_pcpu_thread_init(0)` 建立 pcpu。
- `ff_pcpu_get()` 对**所有正常线程**（主线程/worker，pcpup 非 NULL）等价返回，零回归。

**结论：PASS。**

---

## 5. 规约审核 —— 发现项（1 项，非代码缺陷）

- 最小 diff：通过（6 文件，改动聚焦，无重构/美化/无关注释）。
- 注释：仅 P1 的 DPCPU 失效说明、P3 的原子互斥说明、P6 的 panic 声明原因 + 接口契约，均属必要；无冗余注释。通过。
- 未做 git 操作：通过（`git status` 显示均为未提交工作区改动，无 commit）。
- 未直接 rm/kill/chmod：通过（clean 走 `make clean` 构建 target）。

**发现项（规约提醒，非本轮代码缺陷）**：
- `config.ini` **存在未提交的本地测试值残留**（`git status` 显示 ` M config.ini`），diff 含：`lcore_mask=1→3`、`pkt_tx_delay=100→30`、`extra_eal_args` 取消注释、`fstack_log_level=7`、`[port0]` 段真实 IPv4（`9.134.x.x`）+ 真实 IPv6（`2402:4e00:...`）、`[kni] enable=1` 取消注释。
- 这与 coder2 文档 `_m18_H_p136_coder.md` §4 声称「未改动 config.ini」「无任何真实 IP」**不符**。
- **定性**：这些是 coder2 本地运行时验证所需的本地配置（DPDK 网卡 IP 等），**未纳入 git 提交**（未 staged/未 commit），因此不违反「config.ini 本地测试值不入库」的提交约束。但须注意：
  1. 后续 `git add config.ini` 前必须 review diff，**不得**将上述本地测试值（尤其真实 IP）提交入库（规约 44404940 / 47974415）。
  2. coder2 文档 §4 的「未改动 config.ini」「无真实 IP」表述**不准确**，建议修正为「config.ini 有本地运行配置改动但未纳入提交、不入库」。
- 此为规约提醒项，不阻塞 P1/P3/P6 代码的 PASS 结论。

---

## 6. 独立编译复核（clean build）

| 目标 | 命令 | error | warning | 结果 |
| --- | --- | --- | --- | --- |
| lib | `PATH=... make clean && make machine_includes && make -j16` | **0** | **51**（=基线，无新增） | `libfstack.a` 生成 |
| example | `PATH=... make clean && make` | 0 | 0 | `helloworld` 生成 |
| 单测 | `make -B test_ff_thread`（强制重编）+ `./test_ff_thread` | 0 | 0 | **5/5 PASSED** |

- 采用 team-lead 给定规避方式：(a) `PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin"` 规避 IDE safe-delete hook；(b) 先 `make machine_includes` 再 `make -j16` 规避并行竞态。
- lib 51 条 warning 均为 `freebsd/` 子目录源码基线既有（`-Warray-bounds`/`-Wformat` 等），**无一条来自本次改动文件**。
- 单测用 `make -B test_ff_thread` 强制 clean 重编（含 `test_ff_thread.c`/`ff_thread.c`/`ff_host_interface.c`），确认二进制含新 fail-fast 用例，5/5 通过（含新增 `test_ff_pthread_create_failfast`）。

---

## 7. 诚实边界

- 已坐实：P1 类型/索引/内存对称、P3 原子语义/swi 死路径/epoch 配对、P6 语义等价/panic 声明兼容/单测自洽/回退。
- 未坐实（标出，不臆断 PASS）：
  - **P6 热路径性能**：静态判断零开销可接受，但「是否引入数据面热路径可测量退化」需 thread_mode=1 压测数据坐实（§3.3）。此项不阻塞，标「需压测确认」低优先级。
  - **运行时行为**：P1/P3/P6 均未做运行时实测（本审核仅静态 + 编译 + 单测），`ipfw dynamic` 多 worker 下的 HP 保护、`__tcp_run_hpts` 并发重入是否彻底消除，需运行时验证（属 coder2 后续运行时测试范围，不在本轮静态门禁内）。

---

## 8. 最终结论

**PASS-with-fixes**

- P1 / P3 / P6 三项代码改动均**通过**（类型/语义/内存安全/互斥/回退/单测全部坐实，clean build 0 error / 51 基线 warning / 单测 5/5）。
- 唯一 fix（规约提醒，非代码缺陷）：`config.ini` 本地测试值（含真实 IP）须在提交时排除入库，coder2 文档 §4 相关表述需修正。
- 无必改项（代码层面零缺陷）；建议后续补 P6 热路径压测与运行时验证。
