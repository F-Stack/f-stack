# M18 遗留风险 P1 / P3 代码坐实分析

调研对象：`/data/workspace/f-stack`，HEAD `9ef6dc92e`。
本报告只读代码，未修改任何文件。所有结论附 file:line，以实际代码为准。

---

## 问题 P1：ipfw 动态状态 hazard pointer 的 DPCPU 槽位别名

### 代码依据

ipfw 动态状态（dynamic state）用 DPCPU 存储每个 CPU 的 hazard pointer（HP），保护正在被读取的 state 免于被过期回收线程释放：

- `freebsd/netpfil/ipfw/ip_fw_dynamic.c:224`：
  ```c
  static void **dyn_hp_cache;
  DPCPU_DEFINE_STATIC(void *, dyn_hp);
  ```
- `ip_fw_dynamic.c:225-226`：
  ```c
  #define DYNSTATE_GET(cpu)     ck_pr_load_ptr(DPCPU_ID_PTR((cpu), dyn_hp))
  #define DYNSTATE_PROTECT(v)   ck_pr_store_ptr(DPCPU_PTR(dyn_hp), (v))
  ```
- `ip_fw_dynamic.c:228-232`：`DYNSTATE_CRITICAL_ENTER()` = `critical_enter()`，`DYNSTATE_CRITICAL_EXIT()` 先 `DYNSTATE_RELEASE()` 再 `critical_exit()`。
- HP 回收读取在 `dyn_free_states()`：`ip_fw_dynamic.c:2086-2091` 用 `CPU_FOREACH(i)` 遍历所有 CPU，把每个 CPU 的 `DYNSTATE_GET(i)` 读进 `dyn_hp_cache[]`；`:2102-2124` 中凡出现在 `dyn_hp_cache[]` 里的 state 都跳过释放，其余才 free。

DPCPU 寻址宏：

- `freebsd/sys/pcpu.h:113-114`：
  ```c
  #define _DPCPU_PTR(b, n) \
      (__typeof(DPCPU_NAME(n))*)((b) + (uintptr_t)&DPCPU_NAME(n))
  ```
- `pcpu.h:121`：`DPCPU_PTR(n) = _DPCPU_PTR(PCPU_GET(dynamic), n)`
- `pcpu.h:128`：`DPCPU_ID_PTR(i, n) = _DPCPU_PTR(dpcpu_off[(i)], n)`

即：DPCPU 槽位地址 = 基址（`dpcpu_off[i]` 或 `pc_dynamic`）+ 符号 `&dpcpu_entry_dyn_hp` 的绝对地址偏移。

`dpcpu_off[]` / `pc_dynamic` 的赋值路径（`freebsd/kern/subr_pcpu.c`）：

- `subr_pcpu.c:76`：`uintptr_t dpcpu_off[MAXCPU];`（静态数组，默认全 0）
- `subr_pcpu.c:83-97` `pcpu_init()`：`bzero(pcpu, size)` 清零整个 `struct pcpu`，**从不设置 `pc_dynamic`**。
- `subr_pcpu.c:99-118` `dpcpu_init(void *dpcpu, int cpuid)`：**唯一**写入 `pcpu->pc_dynamic = (uintptr_t)dpcpu - DPCPU_START` 并 `dpcpu_off[cpuid] = pcpu->pc_dynamic` 的地方。
- `subr_pcpu.c:270-277` `pcpu_destroy()`：`dpcpu_off[pcpu->pc_cpuid] = 0`（只会清，不会设）。

`dpcpu_init()` 的调用者搜索（全仓）：

- `freebsd/kern/subr_pcpu.c`（定义处，无自调用）
- `freebsd/amd64/amd64/mp_machdep.c`、`freebsd/amd64/amd64/machdep.c`
- `freebsd/arm64/...`、`freebsd/arm/...`、`freebsd/i386/...` 的 `mp_machdep.c`/`machdep.c`/`pmap.c`
- 上述均属内核 SMP 启动路径，f-stack 用户态**不编译这些架构 machdep 文件**。
- `lib/` 目录下 `dpcpu_init` / `DPCPU_DEFINE` / `DPCPU_ID_PTR` / `DPCPU_PTR` 命中为 **0**（只有 `ip_fw_dynamic.o` 等已编译产物，源码层面 `lib/ff_freebsd_init.c`、`lib/ff_glue.c` 只出现 `pcpu_init`）。

f-stack 的 per-thread pcpu 初始化（`lib/ff_freebsd_init.c`）：

- `ff_freebsd_init.c:104-113` `ff_pcpu_thread_init()`：`pcpup = malloc(...)` → `pcpu_init(pcpup, cpuid, sizeof(struct pcpu))` → `PCPU_SET(prvspace, pcpup)`。**只调 `pcpu_init()`，从不调 `dpcpu_init()`，也不碰 `pc_dynamic`/`dpcpu_off[]`**。
- `ff_freebsd_init.c:317`、`:191` 分别为主线程、worker 调用 `ff_pcpu_thread_init`。
- `lib/Makefile:367` 直接把 `freebsd/kern/subr_pcpu.c` 编入（`subr_pcpu.c` 是共享同一份实现）。

### 存在性结论

**P1 真实存在，且不可通过 `-DSMP` 修复。**

链路：

1. `pcpu_init()` 用 `bzero` 清零 → 所有线程的 `pc_dynamic == 0`（`subr_pcpu.c:87` 之后无人改）。
2. `dpcpu_init()` 从未被调用 → `dpcpu_off[]` 全局数组恒为 0（`subr_pcpu.c:76` 静态 0 初始化，无写者）。
3. `DPCPU_ID_PTR(i, dyn_hp)` = `_DPCPU_PTR(0, dyn_hp)` = `(void**)((uintptr_t)0 + (uintptr_t)&dpcpu_entry_dyn_hp)` —— **与 `i` 无关，所有 CPU 都解析到同一个主副本 `&dpcpu_entry_dyn_hp`**。
4. `DPCPU_PTR(dyn_hp)` = `_DPCPU_PTR(pc_dynamic=0, dyn_hp)` = 同上同一地址。

因此：多 worker（多线程）下，所有线程读写的是**同一个 `dyn_hp` 槽位**，而不是各自独立的 HP 槽位。`dyn_free_states()` 的 `CPU_FOREACH` 收集到的是同一份值，HP 机制退化为单槽位，无法区分「哪个 CPU 正在用哪个 state」。

### 影响面

- hazard pointer 失效：`dyn_free_states()`（`ip_fw_dynamic.c:2052-2143`）本意是「凡被任一 CPU 的 `dyn_hp` 保护的 state 都暂缓释放」，现在所有 CPU 共用一个槽位，只能保护**最后一个被 `DYNSTATE_PROTECT` 写入的 state**。
- 并发读写串扰：worker A 刚 `DYNSTATE_PROTECT(s_a)`，worker B 覆盖写 `DYNSTATE_PROTECT(s_b)`，则 `s_a` 失去保护，过期回收线程可把它 free，导致 worker A 后续解引用 `s_a` 成为 use-after-free。
- 叠加 `critical_enter()/critical_exit()` 在本 TU 为无锁语义（f-stack 下 `critical_enter` 为 no-op / 不提供抢占保护），读侧基本裸奔。
- 触发条件：ipfw `keep-state` / `check-state` / `limit` 动态规则 + 多 worker 并发 + 状态过期回收同时发生。单线程（thread_mode=0）或不用 ipfw 动态规则时无影响。
- 严重度：中等偏高。属正确性 bug（潜在 UAF），但需要 ipfw 动态规则 + 多线程 + 状态过期三个条件叠加才触发。

### 修复方向（可选）

- 方案 A：把 `dyn_hp` 从 DPCPU 改为真正的 per-thread 存储，例如 `__thread void *dyn_hp_tls`，`DYNSTATE_GET/PROTECT` 直接用 TLS 槽位，`dyn_free_states` 的 `CPU_FOREACH` 改成遍历 f-stack 的实际线程集合（或维护一个线程 HP 槽位数组）。
- 方案 B：为 f-stack 补 `dpcpu_init()` 等价物 —— 在 `ff_pcpu_thread_init` 里为每个 cpuid 分配独立的 DPCPU 区并填充 `dpcpu_off[cpuid]`（同时让 `dpcpu_copy` 的初始值语义生效）。工作量更大（要模拟 linker set `DPCPU_START/DPCPU_BYTES`），且 `DPCPU_DEFINE_STATIC` 在用户态共享库里依赖 `__section(DPCPU_SETNAME)` 布局，不可靠。
- 建议：倾向方案 A（TLS），最小侵入且不依赖用户态 linker section。是否独立立项：P1 独立成一个小项即可，不必并入其它任务。

### 未坐实项

- `freebsd/netpfil/ipfw/` 之外的 DPCPU 消费者（其它 `DPCPU_DEFINE` / `DPCPU_GET` / `DPCPU_PTR` 使用点）是否同样受影响：本报告只针对 `ip_fw_dynamic.c` 的 `dyn_hp` 深入核验；全仓其它 DPCPU 使用点未穷尽，但机理相同（`dpcpu_off[]` 恒 0 是全局性的）。
- ipfw 是否在 f-stack 默认编译开启：`lib/` 下有 `ip_fw_dynamic.o` 等产物，说明该 TU 确被编入 libfstack.a；是否运行时启用取决于 `config.ini` 的 ipfw 配置，本报告未做运行时确认。

---

## 问题 P3：tcp_hpts 实例数 1→N 的 callout 归属错配（R6）

### 代码依据

hpts 初始化（`freebsd/netinet/tcp_hpts.c`）：

- `tcp_hpts.c:1864`：`uint32_t ncpus = mp_ncpus ? mp_ncpus : MAXCPU;`
- `tcp_hpts.c:1872`：`tcp_pace.rp_num_hptss = ncpus;`（hpts 实例数 = CPU 数，在 f-stack 多线程下即 N 个 worker 数）
- `tcp_hpts.c:1921-1931`（per-i malloc + mtx_init）：
  ```c
  for (i = 0; i < tcp_pace.rp_num_hptss; i++) {
      tcp_pace.rp_ent[i] = malloc(sizeof(struct tcp_hpts_entry), ...);
      tcp_pace.rp_ent[i]->p_hptss = malloc(asz, ...);
      hpts = tcp_pace.rp_ent[i];
      ...
      mtx_init(&hpts->p_mtx, "tcp_hpts_lck", "hpts", MTX_DEF | MTX_DUPOK);
  ```
- `tcp_hpts.c:1999`：`callout_init(&hpts->co, 1);`
- `tcp_hpts.c:2008-2010`：
  ```c
  for (i = 0; i < tcp_pace.rp_num_hptss; i++) {
      hpts = tcp_pace.rp_ent[i];
      hpts->p_cpu = i;
  ```
- `tcp_hpts.c:2047-2049`（初始挂载 + 后续重挂 `:1807-1809`、`:1025-1027`、`:1645-1647`）：
  ```c
  callout_reset_sbt_on(&hpts->co, sb, 0, hpts_timeout_swi, hpts,
      hpts->p_cpu, (C_DIRECT_EXEC | C_PREL(tcp_hpts_precision)));
  ```
  即 callout 的 `cpu` 参数 = `hpts->p_cpu = i`（意图挂到「第 i 个 CPU 的 callwheel」）。
- 驱动者：`swi_add(&hpts->ie, "hpts", tcp_hpts_thread, ..., SWI_NET, INTR_MPSAFE, ...)`（`:2012-2014`）创建 hpts swi 线程；`tcp_hpts_thread()`（`:1662`）在 callout 到期后真正跑 `tcp_hptsi()`。另 `tcp_hpts_mod_load` 末尾 `:2061` `tcp_hpts_softclock = __tcp_run_hpts;`。

p_mtx 在 f-stack 是否塌缩（`lib/include/sys/mutex.h`）：

- `mutex.h:59-67`：`__mtx_lock / __mtx_unlock / __mtx_lock_spin / __mtx_unlock_spin / _mtx_lock_flags / _mtx_unlock_flags / _mtx_lock_spin_flags / _mtx_unlock_spin_flags` 全部 `#define ... DO_NOTHING`。
- `mutex.h:74-76`：`mtx_trylock_flags_ / _mtx_trylock_spin_flags / __mtx_trylock_spin` 全部定义为常量 `1`。
- `mutex.h:80-85`：`mtx_init` 仅调 `ff_mtx_init`（初始化 lock_object），`mtx_destroy` = `DO_NOTHING`，`mtx_owned` = `(1)`。
- 结合 `tcp_hpts.c:216-219` 的 `HPTS_LOCK/HPTS_TRYLOCK/HPTS_UNLOCK`（分别 `mtx_lock/mtx_trylock/mtx_unlock`），**`HPTS_TRYLOCK` 恒返回 1、`HPTS_LOCK/HPTS_UNLOCK` 为无操作** → 在 f-stack 下 hpts 的 p_mtx 完全无互斥，多个 worker 可同时进入同一 hpts 实例的 `tcp_hptsi()`。

callout 驱动路径（`lib/ff_kern_timeout.c`）：

- `ff_kern_timeout.c:183-185`（关键）：
  ```c
  __thread struct callout_cpu cc_cpu;
  #define CC_CPU(cpu)    &cc_cpu
  #define CC_SELF()      &cc_cpu
  ```
  注释明确：`CC_CPU/CC_SELF ignore the cpu arg and return the calling thread's own instance, so c_cpu is only a record of which thread armed the callout.`
- `ff_kern_timeout.c:190`：`static __thread int timeout_cpu;`
- `ff_kern_timeout.c:1060`：`callout_init()` 里 `c->c_cpu = timeout_cpu;`（callout 归属 = 调用线程自己的 `timeout_cpu`）。
- `ff_kern_timeout.c:719-800` `callout_reset_tick_on()`：最终 `callout_cc_add()` 用 `cc = callout_lock(c)`（`:747`），而 `callout_lock()`（`:359-374`）取 `cpu = c->c_cpu` → `CC_CPU(cpu)` = **本线程的 `&cc_cpu`**。即 `callout_reset_sbt_on` 传入的 `cpu` 参数在 f-stack 被**忽略**，callout 实际永远挂到「执行 `callout_reset_sbt_on` 的这个线程」自己的 callwheel。
- `ff_kern_timeout.c:248-260` `ff_callout_thread_init()`：每个线程建自己的 callwheel；`timeout_cpu = PCPU_GET(cpuid)`。
- 驱动点：
  - `ff_kern_timeout.c:1243-1253` `ff_hardclock()`（主线程）：`atomic_add_int(&ticks,1)` + `callout_tick()` + timecounter 推进。
  - `ff_kern_timeout.c:1261-1265` `ff_hardclock_worker()`（worker）：**只 `callout_tick()`**（tick 本线程自己的 `cc_cpu` callwheel），不推进全局 `ticks`/timecounter。
  - `ff_kern_timeout.c:1290-1295` `ff_tcp_hpts_softclock()`：直接调 `tcp_hpts_softclock()` 函数指针（=`__tcp_run_hpts`），**绕过 callout 到期机制**。
- 调用者（`lib/ff_dpdk_if.c`）：
  - `ff_dpdk_if.c:1241-1257` `init_clock()`：主线程 `rte_timer_reset(&freebsd_clock, ..., &ff_hardclock_job)`。
  - `ff_dpdk_if.c:1262-1272` `init_clock_worker()`：worker `rte_timer_reset(&freebsd_clock, ..., &ff_hardclock_worker_job)`，每个 worker 在自己 lcore 上驱动自己的 callwheel。
  - `ff_dpdk_if.c:2934`：main_loop 每轮 `ff_tcp_hpts_softclock()` 主动跑 hpts。
- `swi_add/swi_sched/swi_remove/intr_event_bind` 在 f-stack 全是 no-op（`lib/ff_kern_intr.c:84-107`）：`swi_add` 返回 0（不创建线程）、`swi_sched` 空、`intr_event_bind` 返回 `EOPNOTSUPP`。

### 存在性结论

**P3 真实存在。** 具体机理：

1. **callout 归属错配**：`tcp_hpts_mod_load()` 在 f-stack 初始化阶段（主线程上下文）一次性创建 N 个 hpts 实例并对每个 `callout_init(&hpts->co, 1)` + `callout_reset_sbt_on(..., p_cpu=i)`。由于 `callout_init` 把 `c_cpu = timeout_cpu`（= 主线程自己的 cpuid，`ff_kern_timeout.c:1060`），且 `CC_CPU(cpu)` 忽略 `callout_reset_sbt_on` 传入的 `i` 直接返回调用线程的 `&cc_cpu`，所以 **N 个 hpts 的 `co` 全部挂到主线程的 callwheel 上**，而非各自的 `p_cpu=i`。
2. **驱动者错配**：驱动 callwheel 的是各线程的 `ff_hardclock`/`ff_hardclock_worker`（`callout_tick()` 只 tick **本线程**的 `cc_cpu`）。worker 的 `ff_hardclock_worker` tick 的是 worker 自己的空 callwheel，主线程的 `ff_hardclock` tick 的是挂着 N 个 hpts `co` 的主 callwheel。但主线程 `ff_hardclock` 里 `callout_tick()` → 到期 `softclock()` → `hpts_timeout_swi()` → `swi_sched()`（no-op），**不会真正触发 `tcp_hpts_thread()` 的 hpts 处理**（`tcp_hpts_thread` 是 swi 线程，而 swi 线程在 f-stack 根本不存在）。
3. **实际驱动依赖旁路**：f-stack 靠 `ff_tcp_hpts_softclock()`（main_loop 每轮）直接调用 `__tcp_run_hpts()`（`tcp_hpts.c:1590-1660`）绕过 callout 与 swi，主动选一个实例（`tcp_choose_hpts_to_run`，`:1549-1588`，基于 `curcpu`/最久未跑）跑 `tcp_hptsi()`。这条旁路是能跑的，但存在两个缺陷：
   - `tcp_choose_hpts_to_run()` 以 `curcpu` 分组/取模选实例，多 worker 并发调用时可能选中同一个实例（尤其 worker 数 != `rp_num_hptss` 或 NUMA 分组时），而 `p_mtx` 无互斥（见上）→ 同一 hpts 实例的 `tcp_hptsi()` 可能被并发重入。
   - 主线程 callwheel 上残留的 N 个 hpts `co` 是「死 callout」：它们被 `ff_hardclock` 触发后走 `swi_sched` no-op 路径，只白白占 callwheel 槽位、永不产生实际 hpts 处理，与旁路驱动并存，语义混乱。

### 影响面

- **症状**：
  - hpts 的 callout 到期机制在 f-stack 下整体失效，pacing（RACK/BBR 的 packet pacing、`tcp_output` 延迟调度）完全依赖 main_loop 的 `ff_tcp_hpts_softclock()` 旁路轮询，精度取决于 main_loop 迭代频率，而非 callout 的 10us 粒度。
  - `tcp_choose_hpts_to_run` 的 `curcpu` 选择在 worker 线程上可能错选实例，加 `p_mtx` 无互斥 → 潜在并发重入 `tcp_hptsi()`，可能造成 `p_on_queue_cnt`/wheel 状态损坏或同一 tcpcb 被并发 `tcp_output`。
  - 主线程 callwheel 上堆积 N 个永不生效的 hpts callout（伪工作）。
- 触发条件：启用 RACK/BBR（hpts 驱动的 TCP 栈）或任何依赖 `tcp_hpts_insert` 的 pacing 场景，且多 worker（thread_mode=1）。
- 严重度：中。当前 f-stack 已有 `ff_tcp_hpts_softclock` 旁路补偿（`ff_kern_timeout.c:1267-1295` 的注释明确记录了这一点），故功能「能跑」，但 callout 归属错配与 p_mtx 无互斥是真实存在的设计缺陷。

### 修复方向（可选）

- 方案 A（callout 归属对齐）：让每个 worker 在初始化自己的栈实例时，为该 worker 名下（`p_cpu == worker_cpuid`）的 hpts 实例重新 `callout_reset_sbt_on`，把 callout 挂到 worker 自己的 callwheel；并让 worker 的 `ff_hardclock_worker` 触发到期后真正调 `tcp_hptsi`（而非 `swi_sched` no-op）。
- 方案 B（保持旁路、显式收敛）：承认 f-stack 不用 callout 驱动 hpts，把 N 个 hpts 实例的 `co` 从主 callwheel 移除（或不再初始化），统一由 `ff_tcp_hpts_softclock` 驱动，并给 `tcp_choose_hpts_to_run` + `tcp_hptsi` 加明确的 per-instance 互斥（因 p_mtx 无互斥）。
- 建议：优先方案 B（最小改动、与现状旁路一致），补 per-instance 锁或确保单 worker 独占实例绑定。

### 未坐实项

- `mp_ncpus` 与 `nb_threads`（`ff_freebsd_init.c:298-310`）是否恒等于 DPDK worker 数、以及 `rp_num_hptss` 是否可能 > 实际 worker 数（导致存在无人驱动的 hpts 实例）：静态代码显示 `mp_ncpus = nb_cpus`（thread_mode ? nb_threads : 1），hpts 实例数 = `mp_ncpus`，二者一致，但未做运行时验证。
- 并发重入 `tcp_hptsi()` 是否会在实际负载下真实触发（依赖 worker 是否并发进入 `ff_tcp_hpts_softclock` 且选中同一实例）：未做运行时验证，属推断。
- RACK/BBR 是否在 f-stack 默认启用、hpts pacing 路径是否真的被 TCP 栈走到：未做运行时确认。
