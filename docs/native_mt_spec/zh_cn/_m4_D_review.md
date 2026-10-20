# M4-D 独立代码审核报告

> 审核人：独立 code-explorer 子 agent（只读角色，非本次代码作者）
> 落盘人：leader（子 agent 无写文件工具，内容原样转录）
> 日期：2026-08-03
> 审核方式：只读静态审核（search_content / read_file / read_lints）+ leader 复核关键项

---

## 0. 前提事实核验（leader 依据是否成立）——**成立**

| 断言 | 证据 |
|---|---|
| 本 build 未定义 `SMP`，`MAXCPU == 1` | `freebsd/amd64/include/param.h:60-66`；`lib/opt/opt_global.h:1-6`（仅 MUTEX_NOINLINE/RWLOCK_NOINLINE/SX_NOINLINE/DEV_RANDOM/NO_EVENTTIMERS/VIMAGE，无 SMP）；`lib/Makefile:70-177` 无 `-DSMP` |
| `mp_ncpus=1`、`mp_maxid=0` | `lib/ff_glue.c:140,145`；`all_cpus` 仅bit0（`lib/ff_freebsd_init.c:294`） |
| per-cpu 数组只按 1 个 CPU 分配 | `freebsd/kern/subr_smr.c:597-605`（`for i<=mp_maxid`）；`freebsd/vm/uma_core.c:2472-2474`；**`:2546-2548` `#ifndef SMP` 直接剥掉 `UMA_ZONE_PCPU` 标志** |
| 非 0 cpuid 会让 `zpcpu_get()` 越界 | `freebsd/kern/subr_pcpu.c:96` → `freebsd/sys/pcpu.h:234-236,249-252` |
| `INVARIANTS` 未定义（KASSERT 被编译掉） | `lib/Makefile` / `lib/opt/*.h` 全树无 `INVARIANTS` |

### 旁证（审核额外发现，强化改动2 必要性）

- `freebsd/netinet/ip_id.c:270` `zpcpu_get(V_ip_id)` 位于 `else` 分支（`:250` 的 `V_ip_rfc6864 && IP_DF` 命中时不走该行），由 `ip_output.c:371` `ip_fillid()` 调用 → 改前走到该分支即 offset=8192 越界读写。
- `lib/ff_kern_timeout.c:254` `timeout_cpu = PCPU_GET(cpuid)`；`:730-734` `if (cpu >= MAXCPU) panic("Invalid CPU in callout %d")`。改前 worker `c_cpu = 2 >= MAXCPU(1)` → 任何 `callout_reset` 都应panic。且 `timeout_cpu` 是**非 `__thread` 静态全局**（`:190`），多 worker 写不同值本身即竞争；改后统一为 0，行为确定。

---

## 1. 改动2（`pcpu_init(pcpup, 0, ...)`）

### 1(a) `cpuid_to_pcpu[0]` 覆盖 / `cpuhead` 串多个 pcpu —— **PASS（本 build 无实际错误）**

穷举 `lib/Makefile` 的 SRCS（`:339-377` KERN、`:413-445` NET、`:492-536` NETINET、`:539-567` NETINET6、`:649-650` VM），核查三者的读者：

- `pcpu_find()` 全部调用点（`subr_smp.c:386,990,997`、`subr_witness.c:2335`、`uipc_ktls.c:510,3305`、`sched_4bsd.c:1265`、`kern_clock.c:146,318`、`kern_pmc.c:361`、`kern_timeout.c:321`、`x86/*`、`arm*/*`）**全部不在 SRCS 中**（注意编进来的是 `lib/ff_kern_timeout.c`，非 `freebsd/kern/kern_timeout.c`）。
- 唯二落在已编译文件中的调用点被 FSTACK 关掉：`freebsd/vm/uma_core.c:1982` 在 `#ifndef FSTACK`（`:1957` 起）；`freebsd/netinet/tcp_hpts.c:2032` 在 `#ifndef FSTACK`（`:2025`）。
- `cpuhead` 遍历者（`kern_idle.c:62`、`kern_rmlock.c:846`、`subr_kdb.c:647`、`sched_4bsd.c:1208,1243`、`kern_racct.c:1247`、`local_apic.c:801`）均未编译。
- `cpuid_to_pcpu[]` 直读者（`kern_rmlock.c:452,516`、`vfs_subr.c:1613`、`kern_membarrier.c:87,163`、`vm_kern.c:992`、`mp_x86.c:1293,1334`）均未编译。
- `dpcpu_init()`/`pcpu_destroy()`（`subr_pcpu.c:100-118,270-276`）本build 无调用者。

结论：覆盖 `cpuid_to_pcpu[0]`、`cpuhead` 串多项，本 build 内**无任何读者**，不产生实际错误。

**NIT（已修）**：`ff_pcpu_thread_init()` 原在 `init_lock` 自旋锁**之前**调用，而 `pcpu_init()` 内 `cpuid_to_pcpu[0]=pcpu`（`subr_pcpu.c:91`）与 `STAILQ_INSERT_TAIL(&cpuhead,...)`（`:92`）是多 worker 并发的无锁全局写，`cpuhead` 链表可被写坏。虽当前无读者而无害，属埋雷。
→ **leader 已按建议修复**：将 `ff_pcpu_thread_init(cpuid)` 移入 `init_lock` 临界区内（`lib/ff_freebsd_init.c:185-187`，锁 185-186、调用 187、释放 216），零性能影响（仅初始化路径）。

### 1(b) `PCPU_GET/PCPU_SET` 是否只经 `__thread pcpup` —— **PASS**

`lib/include/amd64/include/pcpu.h:33-53`：先 `#undef __curthread/get_pcpu/PCPU_GET/PCPU_ADD/PCPU_INC/PCPU_PTR/PCPU_SET/zpcpu_offset_cpu/...`，再定义为 `(pcpup->pc_ ## member)`，`pcpup` 为 `__thread`（定义于 `lib/ff_freebsd_init.c:85`）。`get_pcpu()` = `pcpup->pc_prvspace`，与 `PCPU_SET(prvspace, pcpup)` 自洽。**与 `cpuid_to_pcpu[]` 完全无关**；amd64 的 `%gs` 段访问路径（`freebsd/amd64/include/pcpu.h:139-259,269-273`）在 F-Stack 侧被 `#ifndef FSTACK` 整体替换。

### 1(c) 所有线程 `pc_zpcpu_offset==0` → 共享 UMA per-cpu cache / SMR 槽位 —— **APPROVE_WITH_NITS（残留风险，已记录）**

事实链：
- `#ifndef SMP` 剥掉 `UMA_ZONE_PCPU`（`freebsd/vm/uma_core.c:2546-2548`），故 `uma_zalloc_pcpu` 实际只分配 1 份槽位。
- `freebsd/netinet/in_pcb.c:615-617` `in_pcbstorage_init` 以 `UMA_ZONE_SMR` 建 zone；`:583` `pcbinfo->ipi_smr = uma_zone_get_smr(...)` → PCB 查找确实走 SMR（`in_pcblookup_mbuf` 内`smr_enter/smr_exit`，`in_pcb.c:1820,1839,1847,1854`）。
- `freebsd/sys/smr.h:106-143` `smr_enter` 做 `atomic_add_acq_int(&smr->c_seq, ...)`，`smr_exit` 置 `SMR_SEQ_INVALID`；`KASSERT(c_seq==0, 不支持递归)` 因无 `INVARIANTS`被编译掉。

判断：多 worker 共享同一 SMR per-cpu 槽位，理论上存在 A 线程 `smr_exit` 清掉 B 线程 read section 标记 → `smr_poll` 误判无读者 → PCB 提前回收（UAF）的**理论窗口**。

但必须明确两点：
1. **该风险不是本次改动引入的**。改动前 offset 非 0 → **必然越界**（已实测 SIGSEGV）；改动后变为「合法但共享」，是严格的改善。
2. 彻底消除需让 `mp_maxid > 0` 并真正按线程数分配 per-cpu 数组（等价于让 f-stack 内核视图 SMP-aware），属独立且远大于本次修复的改造范围。

**实测压力验证（leader 执行）**：8 线程 400 连接 60 秒 soak，2983 万请求、497,043 req/s，零 socket error、零 Non-2xx、进程存活。未观察到 UAF 症状，但静态风险窗口客观存在，已作为遗留风险条目记入16 号文档第 8 节。

---

## 2. 改动3（`ff_worker_prison_init`）内存/引用计数安全 —— **PASS（含 NIT）**

核对 `freebsd/sys/jail.h:182-251` 的 `struct prison`：

| 项 | 结论 | 证据 |
|---|---|---|
| `pr_cpuset` / `pr_root` 直接共享 prison0 指针未加引用计数 | **无实际风险**：per-worker prison 生命周期与进程等长（从不`prison_free`/`prison_deref`），prison0 亦为静态全局（`lib/ff_init_main.c:97`）永不释放，故不存在 UAF 或 refcount 失衡 | `lib/ff_glue.c` 中 `prison_free` 为 no-op stub |
| `pr_ip4`/`pr_ip6`/`pr_prison_racct` | 保持 `M_ZERO` 的 NULL，本build 无读者（`prison_check_ip4` 等全为 stub 返回 0） | `lib/ff_glue.c:257-259,299-302` |
| `pr_id = -1` | **无风险**：无任何代码把它当合法 jid 使用（jail 系统调用族未编译，`kern_jail.c` 不在 SRCS） | `lib/Makefile` SRCS 无 `kern_jail.c` |
| `PR_VNET` flag / `jailed()` | **TCP/UDP 数据面无行为改变**（详见下方订正） | `freebsd/sys/jail.h:449`、`lib/ff_glue.c:286-290,299-302`、`freebsd/netinet/in_pcb.c:2743-2746` |

**订正（二轮门禁发现，原表述有误）**：`lib/ff_glue.c:346-352` 的 `jailed()` stub 整段位于 `#if 0` 内（**未编译**）。实际生效的是宏 `freebsd/sys/jail.h:449` `#define jailed(cred) (cred->cr_prison != &prison0)`，故 per-worker prison 下 worker cred 的 `jailed()` **为真**。

但实质结论仍成立，已逐条坐实：
- **PCB 插入/查找顺序不受影响**：`in_pcbjailed()`（`freebsd/netinet/in_pcb.c:2743-2746`）走 `prison_flag()`，而 f-stack 的 `prison_flag` stub（`lib/ff_glue.c:286-290`）**完全忽略 cred**，只返回 `(flag & PR_HOST) != 0`；调用处传的是 `PR_IP4`/`PR_IP6`，故 `in_pcbjailed` 恒为 false，与 prison 改动无关。
- **已编译集合中 `jailed()` 的唯一读者是 `freebsd/netinet/raw_ip.c:500`**（`in_jail.c` / `in6_jail.c` / `kern_jail.c` / `kern_cpuset.c` 均不在 `lib/Makefile` SRCS），仅影响 raw IP + `IP_HDRINCL` 路径；且其内调用的 `prison_local_ip4` 为 stub 返回 0（`lib/ff_glue.c:299-302`）。
- `jailed_without_vnet()` 确为 stub 恒返回 false（`lib/ff_glue.c:359-362`，未在 `#if 0` 内）。

结论：本次 prison 改动对 TCP/UDP 数据面与 PCB 哈希顺序**无行为改变**；helloworld 不使用 raw IP，故本轮实测不受影响。
| 链表头与 mutex | `LIST_INIT(pr_children/pr_proclist/pr_descs)` + `mtx_init(pr_mtx)` 均已正确初始化；**未**挂入 `allprison`/prison0 children，避免全局链表并发 | `lib/ff_freebsd_init.c` 新增函数体 |

**NIT**：`malloc(..., M_ZERO | M_WAITOK)` 后仍判 `if (pr == NULL) return;`。`M_WAITOK` 语义下不会返回 NULL，该判断冗余但无害（防御式写法，保留可接受）。

---

## 3. thread_mode=0 零回归 —— **PASS**

- 改动2 对 mode0 是**no-op**：主线程路径 `lib/ff_freebsd_init.c:293` 原本就调用 `ff_pcpu_thread_init(0)`，传入值本就是 0，改成常量 0 后完全等价。
- worker 路径 `:187` 仅在 `thread_mode=1` 由 `main_loop`（`lib/ff_dpdk_if.c:2649`）进入；mode0 主线程因 `ff_stack_inited` 已在 `ff_freebsd_init` 置位而在 `:177-179` 直接 return。
- 改动1 由 `thread_mode` 三元判定，mode0 取 `nb_procs`，与原代码字面等价。
- 改动3 位于 worker 专属路径（`init_lock` 临界区内、`ff_stack_thread_init` 主体），mode0 不可达。

**实测佐证**：thread_mode=0 单进程 209,946/ 209,367 req/s；双进程 234,613 / 233,982 req/s，均与修复前基线一致。

---

## 4. 数据面零锁铁律 —— **PASS**

- 三处改动全部位于初始化路径：`init_mem_pool()`（`rte_eal_init` 后、`main_loop` 前）、`ff_pcpu_thread_init()`、`ff_stack_thread_init()`。
- `main_loop` 的 `while(1)` 内**无任何新增锁**（唯一 `rte_spinlock` 是既有的 `ifp_create_lock`，且只在 `veth_ctx[lcore][port]==NULL` 的一次性创建时取）。
- `mtx_init(&pr->pr_mtx, ...)` 仅**初始化**互斥体，不是加锁；全树无任何数据面路径 lock 该 `pr_mtx`（prison 相关函数均为 stub）。
- `init_lock` 自旋锁仅在每线程启动时各取一次，`main_loop` 稳态运行期不再触及。

---

## 5. 调试残留 —— **PASS**

- `grep -rn "DBG\|dbg_" lib/ example/` 零命中。
- `git diff --stat` 仅显示 `config.ini`、`lib/ff_dpdk_if.c`、`lib/ff_freebsd_init.c`；`lib/ff_veth.c`、`example/main.c`、`lib/ff_api.symlist` 与 HEAD 字节一致（`git diff --quiet` 验证通过）。
- （子agent 声明：其无 git 工具，此子项由 leader 复核完成。）

---

## 6. 注释规约 —— **PASS**

新增两段注释（`ff_pcpu_thread_init` 上方 6 行、`ff_worker_prison_init` 上方 6 行、`vnet_alloc` 后2 行）均针对**确实不直观**的机制：非 SMP 下`MAXCPU==1` 与 `zpcpu_get` 越界的因果、`CRED_TO_VNET` 而非 `curvnet` 决定 socket vnet 的反直觉事实、以及 prison 初始化必须早于 `lo_set_defaultaddr()` 的顺序约束。无一句是对"一看就懂"代码的复述，篇幅合理，符合最小注释规约。

---

## 7. 改动1 边界 —— **PASS**

- `proc_lcore` 为 `uint16_t *`（`lib/ff_config.h:313`），在 `parse_lcore_mask` 中以 `idx < RTE_MAX_LCORE` 双重设界填充（`lib/ff_config.c:110,116`），容量充足。
- thread_mode=1 时 `proc_lcore[]` 确实存放各 worker 的 lcore id：`parse_lcore_mask` 按 set-bit 顺序写入并置 `nb_procs=count`（`:138`），thread_mode 塌缩发生在其后（`:1465-1484`，`nb_threads = nb_procs; nb_procs = 1`），故 `nb_threads == count == proc_lcore[] 有效元素数`，语义正确。
- 类型：`nb_pools` 已按建议改为 `uint16_t`（原`int`），与循环变量 `i`（`uint16_t`）一致，消除符号比较告警隐患；`nb_threads`/`nb_procs` 为 `int`（`:290,293`）但取值 ≤ `RTE_MAX_LCORE`，无截断风险。

---

## 总体裁决

**APPROVE_WITH_NITS**

- 7项全 PASS。
- 2 条 NIT 中，1(a) 的「`pcpu_init` 未在锁内」已由 leader 按建议修复并重新 clean build + 复测通过；2 的 `M_WAITOK` 后判 NULL 属无害防御式写法，保留。
- 1(c) 的 SMR 共享槽位为**改动前既已存在且被本次修复由"必然越界"改善为"合法但共享"**的残留风险，非本次引入；需作为遗留风险条目明确记录，并在未来以「f-stack 内核视图 SMP-aware（`mp_maxid > 0` + 真正按线程数分配 per-cpu 数组）」独立立项解决。
