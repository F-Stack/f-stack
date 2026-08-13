# M18 遗留风险专项 —— 代码审核门禁报告（F）

审核方：reviewer（写审分离：coder 是写方，本报告是独立审核方）。
仓库 `/data/workspace/f-stack`，HEAD `9ef6dc92e`。
审核输入：设计 `_m18_D_design.md`、实施 `_m18_E_coder.md`、`git --no-pager diff lib/`（6 文件）。
审核结论：**PASS**（无 bounce，6 项修复全部通过，零回归、零新增 warning）。

---

## 0. 改动清单确认

`git diff lib/` 实际改动 6 文件，与 coder 报告一致：

| 文件 | 改动 | 对应问题 |
| --- | --- | --- |
| `lib/include/amd64/include/counter.h` | 3 函数改 `__atomic_*` | P2 |
| `lib/ff_freebsd_init.c` | `net.isr.dispatch` 特判 `continue` | P4 |
| `lib/ff_subr_prf.c` | 2 行加 `__thread` | P5 |
| `lib/ff_thread.c` | `pcpup`/`panic` 前置声明 + fail-fast | P6 |
| `lib/ff_api.h` | `ff_pthread_create` 接口契约注释 | P6 |
| `lib/ff_api.symlist` | 新增 `pcpup` 一行 | P6（设计遗漏的必要补充） |

无多余文件、无 config.ini 改动（其 `M` 状态为仓库既有本地测试值，见 §5）。

---

## 1. 正确性审核

### P2 —— counter 原子化（PASS）

- **类型/对齐**：`counter_u64_t` 是 `uint64_t *`（`freebsd/sys/counter.h:32`），8 字节对齐由 `pcpu_zone_8` 保证。`__atomic_fetch_add(c, inc, __ATOMIC_RELAXED)` 中 `c` 是 `uint64_t *`、`inc` 是 `int64_t`，与原 `*c += inc` 的 `uint64_t += int64_t` 隐式转换语义完全一致（含负值无符号回绕，见设计 §2.6.4）。类型/对齐正确。
- **内存序**：relaxed 对「仅统计计数、无跨线程同步语义」的 counter 正确且开销最低。设计 §2.5 已论证，采纳合理。
- **三个函数**：`counter_u64_fetch_inline`/`zero_inline` 在 `#ifdef IN_SUBR_COUNTER_C` 块内（仅 `subr_counter.c` 内编译），`counter_u64_add` 在块外（全局 inline）。三处均改为 `__atomic_load_n`/`__atomic_store_n`/`__atomic_fetch_add`，正确。
- **`__atomic_*` 可用性**：GCC 内建，不依赖 libc 头，`-nostdinc` 下可用（编译 0 error 已坐实）。
- `counter_u64_add_protected` 是 `#define` 到 `counter_u64_add`，自动等价，未改，符合最小 diff。

### P4 —— net.isr.dispatch 防护（PASS）

- **字段名**：`struct ff_freebsd_cfg` 定义于 `lib/ff_config.h:261-267`，字段确为 `name`/`str`/`value`/`vlen`/`next`。`cur->name` 是 `strdup(name)` 的字符串（`ff_config.c:168`），`strcmp(cur->name, "net.isr.dispatch")` 精确匹配正确。
- **语义**：`kernel_sysctlbyname(curthread, cur->name, NULL, NULL, cur->value, cur->vlen, ...)` 用的是 `value`/`vlen`（非 `str`）；`cur->str` 仅在错误打印处用（`:370`）。`continue` 跳过注入，因默认值本就是 direct（`netisr.c:151` `NETISR_DISPATCH_POLICY_DEFAULT = DIRECT`），跳过即保持 direct，语义正确。
- **注入前特判**：特判放在 `kernel_sysctlbyname` 之前（`:359-364`），连注入动作都不发生，比「注入后校验改回」更彻底，符合设计 §4.3。
- **风格**：用 `printf`（内核态 TU，与 `:369` 现有 `printf` 一致）。

### P5 —— 行缓冲 __thread（PASS）

- 两行改动：`__thread char bufr[PRINTF_BUFR_SIZE]` + `static __thread int putbuf_done = 0`。
- **语义等价**：`bufr`/`putbuf_done` 全仓仅在 `ff_subr_prf.c` 内引用，每次 `vprintf` 从 `:558` 重新初始化 `p_next`/`remain`，无「上一次 printf 写、下一次续读」的跨调用依赖，也无跨线程共享语义。改 `__thread` 后每线程一份，单线程下与全局变量行为完全一致，多线程下消除共享缓冲竞态，语义正确。
- **先例**：`__thread` 已大量使用（`pcpup`/`pcurthread`/`cc_cpu` 等），风格一致，无风险。

### P6 —— fail-fast + 文档化（PASS）

- **`pcpup` extern**：`extern __thread struct pcpu *pcpup;` 与 `ff_freebsd_init.c:89` 定义及 `amd64/include/pcpu.h:45` 声明一致，正确。
- **`panic` 前置声明**：`ff_thread.c` 是 **host 态 TU**（`FF_HOST_SRCS`，`HOST_INCLUDES=-I.`，无 `-nostdinc`/`-D_KERNEL`，见 `lib/Makefile:298-302`、`:78`、`:179`）。`panic` 声明仅在 `ff_host_interface.c:152`（.c 内部，对其他 TU 不可见），`ff_api.h`/`ff_host_interface.h`/`systm.h` 均未声明 `panic`。coder 加 `void panic(const char *, ...) __attribute__((__noreturn__));` 前置声明是**必要且正确**的（否则 `-Werror=implicit-function-declaration` 编译失败）。coder 报告 §2.1 对设计文档 §6.3 的纠正是正确的。
- **fail-fast 位置**：`ff_set_thread(p_data->parent)` 之后（先继承父 `pcurthread`，保证 `panic` 内部 `curthread` 可用）、`ff_free(data)` 之前（先判后 free，顺序稳妥），符合 leader 精确 diff。
- **symlist 补充**：libfstack.a 构建流程 `objcopy --localize-symbols`（本地化所有非 symlist 的 U 符号）→ `objcopy --globalize-symbols=ff_api.symlist`（`lib/Makefile:692-695`）。`pcpup` 定义在内核态 TU（BSS 段），首次被 host 态 `ff_thread.c` 引用，若不加入 symlist 会被本地化导致 `undefined reference to pcpup`。coder 补充 `ff_api.symlist` 第 78 行 `pcpup` 是**必要且正确**的最小 diff。这是设计文档遗漏项，coder 主动补全正确。
- **`ff_api.h` 注释**：准确反映真实约束「该线程不继承 pcpu（lightweight，inherit only pcurthread, not per-CPU pcpu）」，与代码事实（`ff_start_routine` 只 `ff_set_thread(parent)` 不建 pcpu）一致。
- **fail-fast 形式权衡**：coder 按 leader 指示采用无条件入口 panic（方案 6-A），未采用设计文档 §6.5/6.6 讨论的「惰性检测/纯文档化」。这是 leader 明确下达的实现指令，coder 已在报告 §2.3 记录取舍，属「遵循 leader 指令」而非 coder 擅自决定。此权衡（误伤从不调 ff_* 的纯计算线程）已在设计文档 §6.5 充分记录，作为已披露的边界，审核通过。

---

## 2. 最小 diff / 注释规约（PASS）

- 6 文件改动均为必要改动，无重构、无美化、无无关改动。
- 新增注释 2 处：P4 告警字符串（运行时输出，非注释）、P6 `ff_api.h` 接口契约注释（对外接口边界说明，符合「对外接口契约 + 复杂逻辑」的最小注释规约）。
- `ff_thread.c` 的 `pcpup`/`panic` 前置声明未加额外注释，符合最小注释规约。
- 无新增非必要注释。

---

## 3. 零回归静态分析（PASS）

- **P2**：thread_mode=0 单线程下 `__atomic_fetch_add` 与 `*c += inc` 结果完全一致；relaxed 无可见开销。`EARLY_COUNTER` 路径不受影响（仍静态定义 + 原子 add，语义不变）。
- **P4**：thread_mode=0 下默认 direct，注入循环本就不该出现该名字；加了特判后即使误配也仅跳过+告警，纯收益，零回归。
- **P5**：单线程 `__thread` 与全局变量行为一致，TLS 每线程一份（单线程一份），零回归。
- **P6**：单进程下若不用 `ff_pthread_create`，改动不生效；若用了且线程调 ff_*，原本就是崩溃（时机不定），现在 fail-fast 是纯改善。唯一行为变化是「从不调 ff_* 的纯计算线程」现在也会入口 panic——这是已披露的 6-A 权衡，非 thread_mode=0 场景引入的回归。

---

## 4. 独立复核编译（PASS）

按 coder 记录的规避方式（干净 PATH 绕过 safe-delete hook + 先 machine_includes 再 -j16）独立 clean build：

| 目标 | 命令 | exit | error | warning | 产物 |
| --- | --- | --- | --- | --- | --- |
| lib | `make clean && make machine_includes && make -j16` | 0 | **0** | **51** | `libfstack.a` (7.0 MB) |
| example | `make clean && make` | 0 | **0** | **0** | `helloworld` (30 MB) |

- **warning 51 条全部来自 `freebsd/` 子目录源码**（`sys/tree.h` 18、`netinet/if_ether.c` 15、`sys/systm.h` 4、`net/if_ethersubr.c` 4、`net/if_bridge.c` 4、`sys/atomic_common.h` 3、`kern/sys_generic.c` 2、`netinet/tcp_subr.c` 1），与 coder 报告 §3 一致，**无一条来自本次改动的 6 文件**，无新增 warning。
- 编译环境两问题（safe-delete hook、machine_includes 并行竞态）均用 coder 记录的规避方式稳定绕过，独立复核通过。

---

## 5. 规约遵守（PASS）

- **无真实 IP**：diff 及文档中无任何真实 IP（9.134.x / 2402:4e00: 等完整地址均未出现）。
- **未改 config.ini**：`git status` 显示 `config.ini` 为 `M` 状态，但这是仓库既有本地测试值（`lcore_mask`/`idle_sleep`/`[portN]` 本机 IP 等），非本轮改动；diff lib/ 六文件不涉及 config.ini。
- **未做 git 操作**：无 commit/add/checkout 等 git 操作（`git status` 仍显示未暂存改动，符合「改动留待 leader 统一处理」预期）。
- **make clean 先于编译**：符合规约（用构建 target 清理，非直接 rm）。

---

## 6. 未坐实项（诚实边界）

- **P4 的运行时面**：启动防护堵住了 config.ini 注入这一确定性入口，但 `net.isr.dispatch` 是 `CTLFLAG_RWTUN`，运行时理论可被外部改写（f-stack 用户态无 sysctl 命令行入口，实际面很小）。彻底封死需改 `netisr.c` 的 `sysctl_netisr_dispatch_policy`，属独立项。**静态可坐实「堵住 config.ini 注入」目标达成；运行时外部改写面未做运行时验证**。
- **P6 的 fail-fast 运行时行为**：`pcpup == NULL` 入口 panic 的运行时触发行为（panic 消息、abort）未做运行时验证，仅静态确认逻辑正确 + 编译链接通过。
- **P2 的多线程高并发正确性**：「不丢更新」由 `__atomic_fetch_add` 原子性保证（静态坐实）；但「单 cache line 原子热点」的性能退化（设计 §2.6.3）未做压测量化，属已披露的接受项。

---

## 7. 结论

**PASS**。6 文件改动全部符合设计意图，逻辑正确，最小 diff，零 thread_mode=0 回归，零新增 warning（error=0，warning=51=HEAD 基线），规约遵守到位。coder 报告对设计文档的两处纠错（`panic` host 态不可见、`pcpup` symlist 遗漏）均经独立复核坐实为正确且必要的补充。bounce 次数 = 0。
