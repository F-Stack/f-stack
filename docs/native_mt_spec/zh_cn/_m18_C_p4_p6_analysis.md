# M18 遗留风险 P4 / P6 代码级坐实分析

> 调研方式：只读代码取证。所有结论均附 `file:line`，未做任何运行态验证，未修改任何文件。

---

## 问题 P4：net.isr.dispatch 必须保持 direct

### 代码依据

1. SYSCTL 定义（`freebsd/net/netisr.c`）
   - `:151` `#define NETISR_DISPATCH_POLICY_DEFAULT NETISR_DISPATCH_DIRECT` —— 全局默认策略就是 direct。
   - `:153` `static u_int netisr_dispatch_policy = NETISR_DISPATCH_POLICY_DEFAULT;`
   - `:155-158` `SYSCTL_PROC(_net_isr, OID_AUTO, dispatch, CTLTYPE_STRING | CTLFLAG_RWTUN | CTLFLAG_NEEDGIANT, 0, 0, sysctl_netisr_dispatch_policy, "A", "netisr dispatch policy");`
     - `CTLFLAG_RWTUN`：**运行时可写 + loader 可写**，即这个值可在启动后被任意改写，也可从 config 注入。
   - `:344-377` `sysctl_netisr_dispatch_policy`：`req->newptr != NULL` 时调用 `netisr_dispatch_policy_from_str` 解析字符串并写回 `netisr_dispatch_policy`，无任何对 direct 的强制校验（只拒绝 `NETISR_DISPATCH_DEFAULT`，`:368-369`）。

2. 分发策略选择（`netisr_get_dispatch`，`:780-790`）
   - `:787-788` 若 `npp->np_dispatch != NETISR_DISPATCH_DEFAULT` 则用协议自身策略，否则 `return (netisr_dispatch_policy);` 落回全局。
   - IP 协议注册（`freebsd/netinet/ip_input.c` `:139-150`）：非 RSS 编译下 `ip_nh` **没有设置 `.nh_dispatch` 字段**（`.nh_dispatch` 只在 `#ifdef RSS` 分支里设成 `NETISR_DISPATCH_HYBRID`，`:146`/`:166`）。因此**非 RSS 下 IP 的 dispatch 完全取决于全局 `net.isr.dispatch`**。

3. direct 路径（`netisr_dispatch_src`，`:1107-1236`）
   - `:1146-1153`：`NETISR_DISPATCH_DIRECT` 时**无条件** `netisr_proto[proto].np_handler(m)` 直接在当前线程跑完，不涉及 `swi_sched`，无丢包风险。
   - `:1136-1137`：`NETISR_DISPATCH_DEFERRED` 时直接走 `netisr_queue_src`。
   - hybrid 路径 `:1156-1236`：`netisr_select_cpuid` 后 `:1172` `if (cpuid != curcpu) goto queue_fallback;` —— 当选定 CPU 不是当前 CPU 时，走 `:1227` `queue_fallback` → `:1228` `netisr_queue_internal(proto, m, cpuid)`。

4. 队列 + 唤醒的空 stub（导致静默丢包）
   - `netisr_queue_internal`（`:1028-1052`）→ `netisr_queue_workstream`（`:987-1026`）把 mbuf 挂进 `npwp->nw_head/nw_tail` 队列并置 `nws_pendingbits`；当 workstream 不在 RUNNING/DISPATCHING/SCHEDULED 时置 `dosignal=1`（`:1014-1018`），返回后 `:1049-1050` `if (dosignal) NWS_SIGNAL(nwsp);`。
   - `:261` `#define NWS_SIGNAL(s) swi_sched((s)->nws_swi_cookie, 0)`。
   - `lib/ff_kern_intr.c` `:91-95`：`swi_sched` 是**空函数**（`void swi_sched(void *cookie, int flags) {}`）。而 `swi_net`（真正的 netisr worker，`netisr.c:944-985`）只被这个空 stub「唤醒」，**在 f-stack 用户态里根本没有 softintr 线程来跑 swi_net**。
   - 结论：任何进入 `netisr_queue_internal` 的包，只会被挂进队列、置 pendingbits，但永远没有后续线程把它取出来处理 → **静默丢包**（不 free、不报错、无计数反馈到调用方，除非 queue 满走 `:1022 m_freem` 的 qdrops 分支）。

### curcpu 与 cpuid != curcpu 的关系

- `lib/include/sys/pcpu.h` `:34` `#define curcpu PCPU_GET(cpuid)`。
- `lib/include/amd64/include/pcpu.h` `:49` `#define PCPU_GET(member) (pcpup->pc_ ## member)`，`pcpup` 是 `__thread`（`ff_freebsd_init.c:89`）。
- native-mt 下每个 worker 线程通过 `ff_pcpu_thread_init(cpuid)`（`ff_freebsd_init.c:104-113`）建立自己的 `pcpup`，其 `pc_cpuid` 即该线程的 dense cpuid。所以 `curcpu` 是 per-thread 的，返回「当前线程自己的 cpuid」。

### 为什么 hybrid / deferred 会触发 cpuid != curcpu → queue_fallback

- 非 RSS 时 IP 用 `NETISR_POLICY_FLOW`（`ip_input.c:148`），`netisr_select_cpuid`（`netisr.c:798-870`）按 `flowid % nws_count` / `(if_index + source) % nws_count` 选择目标 cpuid（`:867`/`:869`），这个 cpuid 是「包的归属 CPU」，**不是**「当前正在跑 dispatch 的线程的 curcpu」。
- 一旦选定 cpuid 与当前线程 curcpu 不同（多 worker、flow 分散到别的 CPU 时必然发生），`netisr.c:1172` 判 `cpuid != curcpu` 成立 → `goto queue_fallback` → `netisr_queue_internal` → `swi_sched` 空 stub → 丢包。
- 而 direct 模式完全跳过 `netisr_select_cpuid` 与 `cpuid != curcpu` 判断，`netisr.c:1146-1153` 无条件就地处理，因此不受影响。

### config.ini [freebsd.sysctl] 注入确认

- `lib/ff_config.c` `:1130-1131`：`[freebsd.sysctl]` 段路由到 `freebsd_conf_handler(pconfig, "sysctl", name, value)`。
- `freebsd_conf_handler`（`:157-210`）中 `section=="sysctl"` 分支（`:176-194`）：把 name/value 塞进 `cfg->freebsd.sysctl` 链表，整数按 `atoi/atol` 存 value，非整数按字符串存。
- `lib/ff_freebsd_init.c` `:357-368`：启动时遍历 `cfg->freebsd.sysctl` 链表，对每条调用 `kernel_sysctlbyname(curthread, cur->name, NULL, NULL, cur->value, cur->vlen, NULL, 0)`。
  - **没有任何对 `net.isr.dispatch` 名字的过滤或白名单**，因此用户完全可以在 config.ini 的 `[freebsd.sysctl]` 里写 `net.isr.dispatch = hybrid`（或 deferred），会被无条件注入，改写全局 `netisr_dispatch_policy`。

### 存在性结论

**真实存在，且是确定性缺陷**：

1. 约束「net.isr.dispatch 必须保持 direct」成立：在 f-stack 用户态无 softintr 线程、`swi_sched` 为空 stub（`ff_kern_intr.c:91-95`）的前提下，任何走到 deferred/hybrid-fallback 的包都会被永久挂起在 workstream 队列上（`netisr.c:987-1026` 入队，`swi_net:944` 无人执行），形成静默丢包。
2. 触发面：非 RSS 编译时 IP 协议 `.nh_dispatch` 缺省，dispatch 完全受全局 `net.isr.dispatch` 支配（`netisr_get_dispatch:787-789` + `ip_input.c:148`）。
3. 注入面真实存在：`[freebsd.sysctl]` 段无名字过滤（`ff_config.c:176-194`、`ff_freebsd_init.c:357-368`），`net.isr.dispatch` 是 `CTLFLAG_RWTUN`（`netisr.c:156`），可被静默改成非 direct。

### 影响面

- 若运维/用户误把 `net.isr.dispatch` 配成 `hybrid` 或 `deferred`（无论通过 config.ini `[freebsd.sysctl]` 还是运行时 `sysctl`），多 worker 环境下 IP 入站包会静默丢弃，表现为「网络不通、无报错、计数器无异常」的隐性故障。
- 单 worker（`nws_count == 1`）时 `netisr_select_cpuid` 有 `:810-813` 短路（直接 `*cpuidp = nws_array[0]`），hybrid 下若恰好 `cpuid == curcpu` 仍可 direct dispatch，故**单线程 thread_mode=0 下 deferred/hybrid 也不一定立刻暴露**；多线程 native-mt 下风险最高。
- 该问题与 P6 协同放大：若应用线程（见 P6）因 `pcpup==NULL` 未 fail-fast，其 `curcpu` 语义不确定，可能进一步把包推进 queue_fallback 路径。

### 修复方向（可选）

- **启动期防护（推荐，落点在 `ff_freebsd_init.c`）**：在 `ff_freebsd_init` 内、`mi_startup()` 之后（netisr 已 `netisr_init` 建立好 sysctl 树）追加一次检查：读 `net.isr.dispatch` 当前值，若非 direct 则 `printf` 告警并强制改回 direct（或直接 panic 拒绝）。落点可选在 `:337 mi_startup()` 之后、`:357 sysctl 注入循环` 之后（注入循环之后检查才能抓到 config.ini 注入的非 direct 值）。更简单：在 `:357-368` 注入循环里对 `net.isr.dispatch` 名字做特判，拒绝注入非 direct 值并告警。
- 由于该 sysctl 是 RWTUN 运行时仍可被外部改写，若要彻底封死，需在 `netisr.c` 或 f-stack 适配层把 `sysctl_netisr_dispatch_policy` 的写路径加保护（如非 direct 时拒绝），但这会改动 freebsd 内核源码，需单独评估。

### 未坐实项

- 未做运行时实测：未实际把 `net.isr.dispatch=hybrid` 注入 config.ini 复现丢包（属运行态，超出本次只读范围）。
- 未逐协议排查所有 netisr handler 的 `.nh_dispatch` 是否都缺省为 DEFAULT；仅确认了 IP（`ip_input.c:139-150`）。TCP/UDP 走 ip 分发，故影响面以 IP 为准，但其他协议（如 arp、rtsock 等）若显式设了非 DEFAULT 也需另行确认。
- `swi_sched` 空 stub 是否在早期版本被有意依赖（例如确有其它路径绕过 netisr 直接跑 swi_net），未深挖。

---

## 问题 P6：ff_pthread_create 创建的线程不支持调用 ff_*（fail-fast 缺口）

### 代码依据

1. `lib/ff_thread.c`
   - `:7` `extern __thread struct thread *pcurthread;`
   - `:15-18` `ff_set_thread`：只 `pcurthread = other;`。
   - `:20-30` `ff_start_routine`：`ff_set_thread(p_data->parent);`（`:26`，继承父线程的 `pcurthread`）→ `ff_free(data)` → `start_routine(arg)`。
   - `:32-46` `ff_pthread_create`：`data->parent = pcurthread;`（`:44`）→ `pthread_create(thread, attr, ff_start_routine, data)`（`:45`）。
   - **全程没有调用 `ff_pcpu_thread_init`，也没有任何对 `pcpup` 的初始化或检查**。

2. `pcpup` 是 `__thread`，新线程为 NULL
   - `lib/ff_freebsd_init.c` `:89` `__thread struct pcpu *pcpup;`（TLS 变量，每线程独立、初始值为 NULL）。
   - `:104-113` `ff_pcpu_thread_init(int cpuid)`：`pcpup = malloc(...)` + `pcpu_init(...)`，是**唯一**给 `pcpup` 赋值的路径。
   - `:34`（`pcpu.h`）`#define curcpu PCPU_GET(cpuid)`；`PCPU_GET(member) (pcpup->pc_ ## member)`（`amd64/include/pcpu.h:49`）。
   - 因此：`ff_pthread_create` 出的新线程，其 `pcpup == NULL`，一旦该线程代码路径触达 `PCPU_GET(...)`（最典型就是 `curcpu`）即对 NULL 指针 `pcpup` 解引用 → **段错误 / 崩溃**。

3. `ff_pcpu_thread_init` 的调用点（只有栈实例线程才建 pcpu）
   - `:191`：`ff_stack_thread_init` 内部调用（worker 线程路径）。
   - `:317`：`ff_freebsd_init` 内部调用（主线程 / EAL lcore 主 worker）。
   - 除上述两处外，全 lib 无其他调用（`search` 确认 `ff_pcpu_thread_init` 仅在 `ff_freebsd_init.c` 出现：声明 `:78`、定义 `:104`、调用 `:191`、`:317`）。
   - 即：**只有走 `ff_stack_thread_init`（栈实例线程）和 `ff_freebsd_init`（主线程）的线程才有 pcpu**；`ff_pthread_create` 出的普通应用线程不经过这两条路径。

### 存在性结论

**真实存在，是 fail-fast 缺口**：

- `ff_pthread_create`（`ff_thread.c:32-46`）只做了 `ff_set_thread(parent)` 继承父线程 `pcurthread`（`ff_thread.c:44` / `:26`），**既不给新线程建 pcpu，也不做任何「pcpup==NULL 则 fail-fast」的检查**。
- 新线程 `pcpup` 为 `__thread` 初始 NULL（`ff_freebsd_init.c:89`），`curcpu` 宏展开为 `pcpup->pc_cpuid`（`pcpu.h:34` + `amd64/include/pcpu.h:49`），首次触达即 NULL 解引用崩溃。
- 继承 `pcurthread = parent` 只能让部分依赖 `curthread`/`pcurthread` 的路径「看起来有 thread 上下文」，但**无法掩盖 `pcpup==NULL` 的问题**——因为 `curcpu` 走的是 `pcpup`（TLS）而非 `pcurthread`。这会造成「有的 ff_* 调用能跑、有的直接崩」的隐性、难排查局面。

### 影响面

- 任何通过 `ff_pthread_create` 起的应用线程，若在回调里调用任何内部触达 `PCPU_GET` 的 ff_* 接口（socket 收发、定时器、netisr 相关等，`ff_kern_timeout.c:255` 就是 `PCPU_GET(cpuid)` 的直接例子），都会崩溃。
- `ff_kern_synch.c:106` 用 `pcpup != NULL ? curcpu : 0` 做了防御（唯一一处对 pcpup 判空的例子），说明代码库已意识到 pcpup 可能为空，但**绝大多数路径（如 `curcpu`、`PCPU_GET` 宏本体）没有这层防御**，缺口普遍存在。
- 与 P4 协同：应用线程 `curcpu` 语义不确定，可能把包推进 P4 的 queue_fallback 丢包路径。

### 修复方向（可选）

- **fail-fast（推荐）**：在 `ff_start_routine`（`ff_thread.c:20-30`）入口，`ff_set_thread` 之后加一次检查：`if (pcpup == NULL) { ... abort/panic/返回错误 ... }`，让「ff_pthread_create 线程不支持 ff_*」从「运行到某处才 NULL 解引用崩溃」变成「入口即明确报错」。需要把 `pcpup` 的 extern 声明引入 `ff_thread.c`。
- **文档化**：在 `ff_api.h` 的 `ff_pthread_create`（`:186`）注释里明确「该线程不支持调用任何依赖 per-CPU 状态的 ff_* 接口；需要完整栈实例请用 worker 线程 / ff_stack_thread_init 路径」，作为最低成本兜底。
- 两者可叠加：fail-fast 保证不静默崩溃，文档化保证使用者知道边界。

### 修复方向与「预留 K 个应用线程槽位」的冲突

- `mp_ncpus` / `mp_maxid` 在 `ff_freebsd_init.c:310-311` 被定格为 `nb_cpus`（thread_mode 下 = `nb_threads`），且注释 `:305-309` 明确「must be final before uma_startup1()」，因为 UMA 在 `uma_startup1` 里按 `mp_maxid` 一次性定 zone 大小，后续 CPU_FOREACH 消费者（`ip_fw_dynamic.c`）也按 `mp_ncpus` 定数组大小。
- 若要「预留 K 个应用线程槽位」让 `ff_pthread_create` 出的线程也能合法持有 pcpu，意味着要么把 `mp_maxid` 在 `uma_startup1` 之前就扩到 `nb_threads + K`（这要求启动时就预知应用线程数，且 `pcpu_init` 会 touch 全局 `cpuid_to_pcpu[]`/`cpuhead`，见 `ff_freebsd_init.c:185-187`），要么在运行时动态增长 `mp_maxid`（与「mp_maxid 须在 uma_startup1 前定型」的硬约束直接冲突）。
- **结论**：`ff_pthread_create` 线程若要支持 ff_*，不能简单靠「预留槽位」，因为 `mp_maxid` 已与 UMA 启动深度耦合、不可事后增长。最务实的方案仍是 fail-fast + 文档化（把 ff_pthread_create 定位为「轻量线程，不支持完整 ff_* 栈实例」），或让这类线程改走 `ff_stack_thread_init` 完整初始化路径（但这需要为每个线程分配独立 vnet/proc，成本高，且同样受 mp_maxid 定格约束）。

### 未坐实项

- 未运行复现「ff_pthread_create 线程调用 ff_* 崩溃」的具体崩溃点（属运行态，超出只读范围）。
- 未逐一穷举所有会触达 `PCPU_GET`/`curcpu` 的 ff_* 接口清单；仅确认 `curcpu` 宏（`pcpu.h:34`）与 `ff_kern_timeout.c:255`、`ff_kern_synch.c:106` 两个直接实例。
- 「预留 K 槽位」是否可通过「把 mp_maxid 定格时直接多留 K」实现（即启动期预分配而非运行时增长），未评估其对 UMA zone 内存开销与 `pcpu_init` 全局结构的具体影响量级，留待后续设计阶段。

---

## 附：关键代码位置速查

| 主题 | 文件:行 | 说明 |
| --- | --- | --- |
| net.isr.dispatch 默认 DIRECT | `freebsd/net/netisr.c:151-158` | `RWTUN`，可运行时改 |
| dispatch 写回无 direct 校验 | `freebsd/net/netisr.c:344-377` | 仅拒绝 DEFAULT |
| 协议缺省落回全局 | `freebsd/net/netisr.c:787-789` | `netisr_get_dispatch` |
| IP 非 RSS 未设 .nh_dispatch | `freebsd/netinet/ip_input.c:139-150` | 依赖全局策略 |
| direct 无条件就地处理 | `freebsd/net/netisr.c:1146-1153` | 无丢包 |
| hybrid cpuid!=curcpu → fallback | `freebsd/net/netisr.c:1172-1173` / `1227-1228` | 进队列 |
| 队列入队 + 唤醒 | `freebsd/net/netisr.c:987-1026` / `1049-1050` | `NWS_SIGNAL` |
| `NWS_SIGNAL`=swi_sched | `freebsd/net/netisr.c:261` | 空实现 |
| swi_sched 空 stub | `lib/ff_kern_intr.c:91-95` | 无人唤醒 swi_net |
| curcpu = PCPU_GET(cpuid) | `lib/include/sys/pcpu.h:34` | per-thread |
| PCPU_GET 解引用 pcpup | `lib/include/amd64/include/pcpu.h:49` | pcpup NULL 即崩 |
| pcpup 是 __thread | `lib/ff_freebsd_init.c:89` | 新线程为 NULL |
| [freebsd.sysctl] 解析 | `lib/ff_config.c:176-194` | 无名字白名单 |
| sysctl 注入执行 | `lib/ff_freebsd_init.c:357-368` | 无 net.isr.dispatch 过滤 |
| ff_pthread_create 只继承 pcurthread | `lib/ff_thread.c:32-46` | 不建 pcpu |
| ff_start_routine 无 fail-fast | `lib/ff_thread.c:20-30` | pcpup 未检查 |
| ff_pcpu_thread_init 唯一赋值 pcpup | `lib/ff_freebsd_init.c:104-113` | 仅 :191/:317 两处调用 |
| mp_maxid 须在 uma_startup1 前定型 | `lib/ff_freebsd_init.c:305-311` | 与「预留槽位」冲突 |
