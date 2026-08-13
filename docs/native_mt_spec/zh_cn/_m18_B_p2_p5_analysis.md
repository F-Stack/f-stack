# M18 遗留风险 P2 / P5 代码坐实分析

调研对象：`/data/workspace/f-stack`，HEAD `9ef6dc92e`。
本报告只读代码，未修改任何文件。所有结论附 file:line，以实际代码为准。

---

## 问题 P2：counter(9) 去 per-cpu 化后的多线程统计竞争

### 代码依据

**1. 实际编译生效的 counter 头是「去 per-cpu 化」的退化版，而非 freebsd 原生 per-cpu 版。**

f-stack 的 lib 编译用 include 覆盖目录 `lib/include/`，其中 `lib/include/machine/` 下只有两个覆盖头 `counter.h` 与 `pcpu.h`（与 `lib/include/amd64/include/` 下的同名文件逐字节一致，已 diff 确认 IDENTICAL）：

- `lib/include/machine/counter.h:58-62`（`counter_u64_add`）：
  ```c
  static inline void
  counter_u64_add(counter_u64_t c, int64_t inc)
  {
      *c += inc;              /* 非原子读-改-写 */
  }
  ```
- `lib/include/machine/counter.h:43-47`（`counter_u64_fetch_inline`）：
  ```c
  static inline uint64_t
  counter_u64_fetch_inline(uint64_t *p)
  {
      return (*p);            /* 只读第 0 个槽位 */
  }
  ```
- `lib/include/machine/counter.h:49-53`（`counter_u64_zero_inline`）：`*c = 0;`（只清第 0 槽）。
- `lib/include/machine/counter.h:38-39`：`counter_enter()` / `counter_exit()` 均为 `do {} while (0)` 空操作。
- `lib/include/machine/counter.h:56`：`counter_u64_add_protected(c, i)` 直接 `#define` 为 `counter_u64_add(c, i)`，即「受保护」版本与普通版无差别，同样非原子。

对照：freebsd 原生 per-cpu 版 `freebsd/amd64/include/counter.h:87-93` 的 `counter_u64_add` 是 `zpcpu_add(c, inc)`（写「当前 CPU 自己的槽位」），`:53-64` 的 `counter_u64_fetch_inline` 用 `CPU_FOREACH(cpu)` 累加所有 CPU 槽位，`:76-82` 的 `zero_inline` 用 `smp_rendezvous` 遍历清零。**lib 覆盖版把这三者全部退化成了对第 0 槽的裸读写。**

**2. include 命中链（坐实「lib 覆盖版确实被编译进去」）：**

- `freebsd/sys/counter.h:32`：`typedef uint64_t *counter_u64_t;` —— counter 退化为「普通 `uint64_t *` 指针」，不再是 per-cpu 数组句柄。
- `freebsd/sys/counter.h:35`：`#include <machine/counter.h>`。
- `lib/Makefile:73`：`INCLUDES = -I${OVERRIDE_INCLUDES_ROOT} ...`，其中 `OVERRIDE_INCLUDES_ROOT = lib/include`（`:16`），是最优先 include 路径。
- `lib/include/machine/counter.h` 存在（覆盖头），故 `<machine/counter.h>` 命中它，而非 `freebsd/amd64/include/counter.h`。

即：`counter_u64_t` 的类型定义来自 `freebsd/sys/counter.h:32`（仍是 `uint64_t *`），但其 `counter_u64_add/fetch/zero` 的实际实现来自 `lib/include/machine/counter.h` 的退化版。**`counter_u64_t` 本身确实退化为普通 `uint64_t *` 指针，可直接对 `*c` 做原子操作。**

**3. counter 的分配方式（`subr_counter.c`）仍是 per-cpu 数组：**

- `freebsd/kern/subr_counter.c:59-64` `counter_u64_alloc()`：
  ```c
  return (uma_zalloc_pcpu(pcpu_zone_8, flags | M_ZERO));
  ```
- `freebsd/kern/subr_pcpu.c:146-150`：`pcpu_zone_8 = uma_zcreate("pcpu-8", 8, ...)`（8 字节元素）。
- `freebsd/vm/uma_core.c:3495-3516` `uma_zalloc_pcpu_arg()`：`item = uma_zalloc_arg(...)` 分配 `UMA_PCPU_ALLOC_SIZE` 的大块，`pcpu_item = zpcpu_base_to_offset(item)` 返回 per-cpu 偏移基址；`#ifdef SMP` 分支下 `for (i = 0; i <= mp_maxid; i++) bzero(zpcpu_get_cpu(pcpu_item, i), zone->uz_size)` 清零所有 CPU 槽。
- `lib/Makefile:223`：`CFLAGS += -DSMP` —— **SMP 已定义**，故 `counter_u64_alloc` 实际会分配 `mp_maxid+1` 个 8 字节槽的 per-cpu 数组。

**关键不一致**：分配侧仍是 per-cpu 数组（`subr_counter.c:63` + `uma_zalloc_pcpu` + `-DSMP`），但读写侧（`lib/include/machine/counter.h`）退化成了只碰第 0 槽的裸指针操作。二者叠加的结果是：
- `counter_u64_add` 的 `*c += inc` 永远只累加 `c` 指向的**第 0 槽**（`zpcpu_base_to_offset` 返回的就是第 0 CPU 槽的地址）。
- `counter_u64_fetch` 的 `*p` 永远只读第 0 槽，其余 `mp_maxid` 个槽白分配、永不读写。
- 多线程（多 worker）同时 `counter_u64_add` 同一个 counter 时，`*c += inc` 是「load + add + store」三段，非原子，存在**丢失更新（lost update）**。

**4. counter 的典型使用点（全仓 `counter_u64_add(` 命中 ≥ 85 处）：**

以 IPv6 统计为例，调用链为：

- `freebsd/netinet6/ip6_var.h:268`：`VNET_PCPUSTAT_DECLARE(struct ip6stat, ip6stat);`
- `ip6_var.h:269-273` `IP6STAT_ADD` → `VNET_PCPUSTAT_ADD(...)`；`:275` `IP6STAT_INC(name)` = `IP6STAT_ADD(name, 1)`。
- `freebsd/net/vnet.h:91-92`：`VNET_PCPUSTAT_DECLARE(type, name)` = `VNET_DECLARE(counter_u64_t, name[sizeof(type)/sizeof(uint64_t)])`，即 `ip6stat` 是一个 `counter_u64_t` 数组，每个统计字段一个 counter。
- `vnet.h:106-107`：`VNET_PCPUSTAT_ADD(type, name, f, v)` = `counter_u64_add(VNET(name)[offsetof(type,f)/sizeof(uint64_t)], (v))`。
- `vnet.h:109-110`：`VNET_PCPUSTAT_FETCH` = `counter_u64_fetch(...)`。

所以 `IP6STAT_INC(ip6s_total)`（如 `freebsd/netinet6/ip6_input.c:590`）、`IP6STAT_INC(ip6s_badscope)`（`ip6_input.c:824`）等，最终都落到 `counter_u64_add(VNET(ip6stat)[i], 1)` → `*c += 1`（非原子）。

其它大面积使用点（count 命中）：`freebsd/netinet/tcp_stacks/bbr.c`（37）、`rack.c`（64）、`freebsd/netpfil/pf/pf.c`（41）、`freebsd/kern/uipc_ktls.c`（49）、`freebsd/vm/uma_core.c`（11）、`freebsd/netinet/tcp_reass.c`（13）、`freebsd/net/bpf.c`（16）、`freebsd/net/mp_ring.c`（16）等。这些 TCP/IP/pf/vm 统计在多 worker 并发收发包、并发连接、并发 pf 匹配时会被并发 `counter_u64_add` 写同一 `VNET(...)` counter。

### 存在性结论

**P2 真实存在。**

- counter(9) 在 f-stack lib 里被彻底去 per-cpu 化：`counter_u64_add` 是 `*c += inc` 的非原子「读-改-写」（`lib/include/machine/counter.h:58-62`），`counter_enter/exit` 是空操作（`:38-39`），`counter_u64_fetch` 只读第 0 槽（`:43-47`）。
- 分配侧却仍是 per-cpu 数组（`freebsd/kern/subr_counter.c:63` `uma_zalloc_pcpu` + `-DSMP`），但退化实现只碰第 0 槽 → 其它槽白分配、永不使用，且多线程写第 0 槽无任何原子/锁保护。
- 结论：**多线程写同一 counter 的丢失更新是真实存在的**，是「统计竞争（stat contention / lost update）」而非内存安全（不会越界，不会崩溃，只是计数不准确）。

### 影响面

- 症状：高并发下各类内核统计计数偏低、不精确（`netstat -s`、`sysctl` 读出的 `ip6s_total`/`ip6s_badscope`、TCP/pf/vm 各统计）。多 worker 同时 `IP6STAT_INC` 同一字段时，两次 `*c += 1` 可能合并成一次（丢一次计数）。
- 影响范围：所有经 `VNET_PCPUSTAT_ADD` / `counter_u64_add` 的统计，涵盖 IPv6/IPv4/TCP/pf/ipfw/vm/UMA/bpf/mp_ring 等全栈统计，是全仓性偏差（≥ 85 处调用点）。
- 严重度：**低**。属「观测/审计数据不准确」，不涉及正确性（不影响数据面转发、连接建立、内存分配正确性），不引发 crash。仅当依赖统计值做监控告警、容量规划或调试定位时受影响。
- 附带效应：`counter_u64_fetch` 只读第 0 槽，意味着即便未来把 `counter_u64_add` 改成原子，`fetch` 也读不到其它槽的累计值——不过当前退化实现下「所有写都进第 0 槽」，fetch 读第 0 槽反而自洽。若修复 add 为原子但保持单槽，统计仍只累加第 0 槽，语义不变（仍是单槽计数器）。

### 修复方向（可选）

- 方案 A（原子化，最小侵入）：把 `counter_u64_add` 的 `*c += inc` 改为原子操作。因 `counter_u64_t` 是普通 `uint64_t *`（`freebsd/sys/counter.h:32`），可直接对其原子操作：
  - 用 GCC 内建：`__atomic_fetch_add(c, inc, __ATOMIC_RELAXED);`（或 `__ATOMIC_SEQ_CST`）。
  - 或 `atomic_add_64((volatile uint64_t *)c, inc)`（若 atomic API 已引入 lib，需确认 `sys/atomic.h` 在 f-stack lib 下的可用性）。
  - `counter_u64_zero_inline` 的 `*c = 0` 可改 `atomic_store_64` 或 `__atomic_store_n`。
  - `counter_u64_fetch_inline` 的 `*p` 可改 `atomic_load_64` / `__atomic_load_n`（RELAXED 即可）。
  - `counter_u64_add_protected` 当前直接 `#define` 到 `counter_u64_add`（`:56`），改为原子后受保护版本与普通版仍等价，语义上无差别（原生 FreeBSD 中 protected 版本才在临界区内做非原子自增，f-stack 无临界区概念）。
- 注意点：
  - `counter_u64_t` 是裸指针，原子操作需注意 `volatile` 限定与对齐（8 字节对齐由 `pcpu_zone_8` 保证）。
  - 即便原子化，仍是「单槽计数器」，多线程高竞争会退化为单 cache line 上的原子热点（性能略降、有 cache 乒乓），但正确性（不丢更新）得到保证。若追求零竞争需恢复 per-cpu 语义（工作量更大，见下）。
  - 若选择「恢复 per-cpu」：需让 `counter_u64_add` 用 `zpcpu_add`（写当前线程自己的槽）、`fetch` 用 `CPU_FOREACH` 累加，并确保 `zpcpu_*` 宏在 lib 下未被 `lib/include/machine/pcpu.h:40-42` undef 掉——当前已被 undef，需先补回 per-thread 槽位映射（与 P1/P3 的 DPCPU/pcpu 重建联动，成本高）。
- 建议：若仅消除「丢失更新」，方案 A（原子化）即可，改动集中在 `lib/include/machine/counter.h` 一个文件。是否值得做取决于是否依赖精确统计；纯观测数据丢失更新影响小，可标记为「已知偏差、低优先级」。

### 未坐实项

- `atomic_add_64` / `atomic_load_64` 系列在 f-stack lib 编译环境（`-nostdinc` + override 头）下是否可用、头文件路径：本报告未做编译验证，需在改动时确认 `sys/atomic.h` 的引入路径与 `-nostdinc` 兼容性。
- `mp_maxid` 在 f-stack 下的实际取值与 `counter_u64_alloc` 分配槽数：静态上 `-DSMP` 已定义、`uma_zalloc_pcpu_arg` 走 `#ifdef SMP` 分支分配 `mp_maxid+1` 槽；但 `mp_maxid` 在用户态 f-stack 的赋值点未单独核验（M17 文档已覆盖 `mp_maxid` 提高后的越界分析，结论为「不会越界」）。
- 丢失更新在实际负载下的量化幅度（多少次计数被合并）：未做运行时统计压测，属机理推断。

---

## 问题 P5：ff_subr_prf.c 全局无锁行缓冲（printf 并发污染）

### 代码依据

**1. 全局非 `__thread` 无锁缓冲：**

- `lib/ff_subr_prf.c:81-83`：`#define PRINTF_BUFR_SIZE 256`（默认行缓冲 256 字节）。
- `lib/ff_subr_prf.c:85-87`：
  ```c
  #ifdef PRINTF_BUFR_SIZE
  char bufr[PRINTF_BUFR_SIZE];        /* 全局共享，非 __thread，无锁 */
  #endif
  ```
- `lib/ff_subr_prf.c:89`：`static int putbuf_done = 0;`（全局共享，非 `__thread`，无锁）。

**2. bufr 的完整使用路径：**

- `vprintf()`（`ff_subr_prf.c:550-581`）是行缓冲的核心入口：
  - `:558-563`：把 `pca.p_bufr = bufr;`、`pca.p_next = pca.p_bufr;`、`pca.n_bufr = sizeof(bufr);`、`pca.remain = sizeof(bufr);`、`*pca.p_next = '\0';` —— 全局 `bufr` 被用作本次 printf 的行缓冲。
  - `:569`：`putbuf_done = 0;`（重置 flush 标记）。
  - `:571`：`retval = kvprintf(fmt, kputchar, &pca, 10, ap);` —— 逐字符格式化，每字符经 `kputchar` → `putbuf`。
  - `:573-577`：`if (*pca.p_bufr != '\0' && putbuf_done == 0) puts(pca.p_bufr);` —— 末尾冲刷剩余缓冲。
- `kputchar()`（`:184-193`）→ `putbuf()`（`:136-177`）：
  - `:147-151`：`*ap->p_next++ = c; ap->remain--; *ap->p_next = '\0';` —— 逐字符写入 `ap->p_bufr`（即全局 `bufr`）。
  - `:154-163`：当 `ap->remain == 2 || c == '\n'` 时，`puts(ap->p_bufr)` 刷出整行，然后 `ap->p_next = ap->p_bufr`、`ap->remain = ap->n_bufr`、`putbuf_done = 1`。
- `puts`/`putchar` 在 f-stack 被重定向到日志（`:109-110`）：
  ```c
  #define putchar(c) ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_FREEBSD, "%c", c)
  #define puts(str)  ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_FREEBSD, "%s", str)
  ```
- `ff_log` → `ff_vlog`（`lib/ff_log.c:94-105`）→ `rte_vlog`（`lib/ff_log.c:108-111`）。

**3. 并发机理：**

`bufr` 是进程级全局（非 `__thread`、非 `static __thread`），`vprintf` 从 `:558` 拿 `bufr` 地址一路用到 `:577`，中间没有任何锁。两个 worker 线程同时调用 `printf`/`vlog`/`log` 时：
- 线程 A 在 `:558-563` 初始化 `bufr` 并把 `p_next` 指向 `bufr` 头；
- 线程 B 几乎同时进入 `vprintf`，也把 `p_next` 指向同一个全局 `bufr` 头，或在其 `kvprintf` 过程中逐字符写 `bufr`；
- 结果 A 与 B 的字符交错写入同一个 256 字节缓冲 → 整行拼接污染（A 的前半行 + B 的后半行粘成一行），或在 `:154` 刷行判断时把未刷完的半行当作完整行 `puts` 出去 → 整行丢失/截断。
- `putbuf_done`（`:89`）同样共享，`:569` 的 `putbuf_done = 0` 与 `:163` 的 `putbuf_done = 1` 并发交错，导致 `:575` 的「是否冲刷末尾」判断错乱。

注意：最终输出经 `ff_log` → `rte_vlog`（DPDK 日志，自身有内部同步），所以「跨线程最终写入日志文件」不会因 bufr 竞争而撕裂（DPDK 层另有锁），**但 `bufr` 作为行组装缓冲的竞争发生在进入 `rte_vlog` 之前**，会直接导致「一行日志的内容本身被另一个线程的日志内容污染/截断」。即并发 printf 时，单条日志的**内容正确性**受损。

**4. `__thread` 在本项目的既有先例（改动风格一致性）：**

- `lib/ff_kern_timeout.c:183`：`__thread struct callout_cpu cc_cpu;`（每个线程自己的 callwheel，`CC_CPU/CC_SELF` 忽略 cpu 参数返回调用线程自己的实例）。
- `lib/ff_kern_timeout.c:190`：`static __thread int timeout_cpu;`。
- `lib/ff_compat.c:59`：`__thread struct thread *pcurthread = NULL;`；`:80`：`__thread unsigned int seed = 0;`。
- `lib/ff_dpdk_if.c:111-113`：`static __thread int stop_loop;`、`static __thread struct rte_timer freebsd_clock;`。
- `lib/ff_dpdk_pcap.c:55-57`：`static __thread FILE* g_pcap_fp`、`__thread uint32_t seq/g_flen`。
- `lib/ff_freebsd_init.c:86`：`static __thread int ff_stack_inited;`；`:89`：`__thread struct pcpu *pcpup;`。
- `lib/ff_syscall_wrapper.c:225-226`：`static __thread struct iovec msg_iov_tmp[UIO_MAXIOV]`、`__thread size_t msg_iovlen_tmp`。

即：**本项目已大量使用 `__thread` 作为 per-thread 临时缓冲/状态的惯用手段**（`cc_cpu`、`msg_iov_tmp`、`seed` 等都是 per-thread 的临时/私有状态），把 `bufr`/`putbuf_done` 改成 `__thread` 与既有风格完全一致。

### 存在性结论

**P5 真实存在。**

`bufr`（`ff_subr_prf.c:86`）与 `putbuf_done`（`:89`）是全局非 `__thread`、无锁的行缓冲。`vprintf`（`:550-581`）在整段格式化过程中（`:558` 到 `:577`）无任何锁地使用全局 `bufr`，多 worker 并发 `printf`/`log`/`vlog` 时，同一 256 字节缓冲被并发写，导致「整行丢失/拼接污染」。这是真实存在的并发缺陷。

### 影响面

- 症状：多线程并发打印日志时，日志行内容错乱——不同线程的日志片段粘成一行、或一行日志被另一线程的写入截断/覆盖。日志的**内容正确性**受损（定位问题时读到的是被污染的日志）。
- 触发条件：多个 worker 线程（thread_mode=1）在同一时间段内同时触发 `printf`/`log`/`vlog`（例如多 worker 同时报错、同时打连接日志、同时打印统计）。单线程（thread_mode=0）无影响。
- 严重度：**低到中**。不影响数据面正确性、不引发 crash（`bufr` 是 256 字节固定数组，无越界写——`putbuf` 有 `KASSERT(ap->remain > 2, ...)` 且 `:154` 保证 `remain==2` 即刷，逐字符写不会溢出 256 字节），仅导致日志内容污染，影响可观测性/可调试性。
- 范围：所有经 `vprintf`（`printf`/`vlog`/`log` 都汇聚到 `vprintf`）的 FreeBSD 栈日志输出。

### 修复方向（可选）

- 方案 A（改为 `__thread`，最小侵入、与既有风格一致）：
  ```c
  __thread char bufr[PRINTF_BUFR_SIZE];
  __thread int putbuf_done = 0;   /* 或 static __thread */
  ```
  改动仅限 `ff_subr_prf.c:86` 与 `:89` 两行。`bufr` 只作为 `vprintf` 内部的临时行缓冲（每次 `vprintf` 从 `:558` 重新初始化 `p_next`/`remain`，结束后 `:577` 冲刷干净），不承载任何跨线程共享语义、不需要在函数调用之间保留状态，故改为 `__thread` 后语义完全等价，仅消除并发污染。
- 可行性确认：
  - `bufr` 无跨线程共享语义：全仓 `bufr`/`putbuf_done` 只在 `ff_subr_prf.c` 内引用（`:86/89/157/160-163/559-563/569/575-576`），无外部使用者，无「上一个 printf 写入、下一个 printf 续读」的依赖（每次 `vprintf` 都重新 `*p_next='\0'` 并复位）。→ 改 `__thread` 无副作用。
  - 本项目已有大量 `__thread` 先例（`ff_kern_timeout.c:183/190`、`ff_syscall_wrapper.c:225-226`、`ff_compat.c:59/80` 等），改动风格一致。
  - 若担心 `__thread` 对「动态 TLS」的依赖（DPDK lcore 线程是否支持 TLS）：本项目已在 lcore 线程上下文大量使用 `__thread`（`pcurthread`/`pcpup`/`freebsd_clock`/`cc_cpu` 等均工作正常），故无 TLS 兼容性问题。
- 备选：若不改 `__thread`，也可在 `vprintf` 入口加一把自旋锁/互斥串行化整个格式化段；但会降低并发日志吞吐，且 `printf` 可能在锁内再触发日志（重入），不如 `__thread` 干净。
- 建议：直接采用方案 A（`__thread`），两行改动，与既有 `__thread` 用法一致，风险最低。

### 未坐实项

- `rte_vlog` 内部的日志落盘/输出是否自身线程安全、以及 `bufr` 竞争是否可能在 `rte_vlog` 之前被某处提前串行化：本报告未逐行核验 DPDK 侧 `rte_vlog` 实现，但即便 DPDK 侧有锁，也无法修复 `bufr` 在进入 `rte_vlog` 之前的组装竞争，P5 结论不受影响。
- 多 worker 并发 `printf` 触发污染的实际复现频率与观测样本：未做运行时复现，属机理推断（全局无锁缓冲 + 多线程写，竞争机理确定，但实际触发概率取决于并发日志频率）。
