# 13 · Spec 评审门禁（独立审核）

> 本文由独立审核门禁子 agent（spec-gatekeeper）出具。审核方**未参与**任何 spec 文档撰写。
> 审核原则：**一切以实际代码为准，不因文档写得好看放水**。所有关键 `file:line` 论断均已实际 `read_file` / `search_content` 抽验，抽验记录见第 2 节。
> 审核对象：`docs/multi_thread_spec/zh_cn/` 下 `plan.md`、`00`~`12` 全部文档 + `_material_code.md` / `_material_web.md`。
> 审核时间：2026-07-23。

---

## 0. 门禁结论（TL;DR）

**总体裁决：打回（FAIL），发现 1 个 FAIL 项。**

- 7 个审核维度中 **6 项 PASS，1 项 FAIL**。
- FAIL 项：**维度 1（代码 vs 文档一致性）** —— 文档 `02` / `06` / `07` 反复引用的 **`ff_api.h:1971-1972` "注释把 SOCK_KERNEL/SOCK_FSTACK 数值写反"** 的论断属**虚构**：`ff_api.h` 全文件仅 **495 行**，根本不存在第 1971-1972 行，且全文件无任何"数值写反"的注释。该虚构论断还被 `07` 列为编码里程碑 **A-M3**，属于把不存在的问题带入后续编码计划，直接违反 plan §4「代码为准、不臆测」铁律。
- 其余抽验的 **13 处**关键 `file:line` 论断（`lcore_conf`/`proc_type` 结构/socket flags 转换/KNI primary-only/ring SC-SP flag/pcurthread/msg_iov_tmp/ff_adapt_user_thread_add/SOCKET_OPS_CONTEXT_MAX_NUM 等）**全部与实际代码相符**（个别 SC ring flag 行号 618 vs 619 为可接受的 ±1 行漂移，事实正确）。

**按 plan §3 门禁约定与 bounce≤3 规约：本门禁失败，打回上一步（doc-writer 修复 `02`/`06`/`07` 的虚构 `ff_api.h:1971-1972` 论断）后重新提交审核。不搁置、不带病放行。**

---

## 1. 逐维度 PASS / FAIL 表

| # | 审核维度 | 结论 | 说明 |
|---|---|---|---|
| 1 | **代码 vs 文档一致性（核心）** | **FAIL** | 13 处关键 file:line 抽验相符；但 `ff_api.h:1971-1972` 注释笔误论断虚构（文件仅 495 行），被 02/06/07 三处引用并列为里程碑 A-M3。详见 §2、§3。 |
| 2 | issue #430 覆盖 | PASS | plan §0.3 第 9 项列为**强制**调研目标；00 §1.3 / 03 §1 / 04 §1 均给出结论（属概念 A、代码已闭环、评论区未抓到并诚实标注）。详见 §4。 |
| 3 | 概念 A/B 区分是否清晰、结论自洽 | PASS | 04 §0/§1 表格严格区分「应用侧多线程调用 API（A，已支持）」vs「协议栈多线程运行模型（B，原生不支持）」，00 §1.2 呼应，结论自洽。详见 §5。 |
| 4 | 诚实边界 | PASS | 外网未抓到内容（#430 评论区、官方多线程栈模式、VPP/Seastar、DPDK 官方 PG）均如实标注「未抓取到/不杜撰」，03 §5 抓取状态清单完整。详见 §6。 |
| 5 | 多进程零回归论证是否闭环 | PASS | 07 §1.4 路线 A 天然零回归；10 §4 一票否决门禁 + opt-in 门控；08 §4 零回归验收表闭环。详见 §7。 |
| 6 | 文档完整性 | PASS | plan + 00~13 + 两素材齐全，无空文件，结构清晰，索引一致。详见 §8。 |
| 7 | 规约遵循 | PASS | 全文未建议直接 rm/kill/chmod；测试/性能文档明确走 rm_tmp_file.sh/kill_process.sh/chmod_modify.sh；建议改动符合 lib 最小注释精神。详见 §9。 |

---

## 2. 抽验的 file:line 核验结果（实际读到的代码 vs 文档论断）

> 下表每一行都是审核方**实际 read_file / search_content 读到的代码**与文档论断的逐条比对。

| 抽验点 | 文档论断（出处） | 实际代码（审核方读到） | 判定 |
|---|---|---|---|
| lcore_conf 全局单例 | `ff_dpdk_if.c:123`（00/01/04/05/11） | `ff_dpdk_if.c:123` `struct lcore_conf lcore_conf;`（无 static、文件级全局单例） | ✅ 相符 |
| ff_config.dpdk 结构 | `ff_config.h:269-328`，proc_type@272 / lcore_mask@274 / proc_mask@276 / nb_procs@290 / proc_id@291 / proc_lcore@311（01/06） | 逐字段核验：`struct ff_config`@269 起、proc_type@272、lcore_mask@274、proc_mask@276、nb_procs@290、proc_id@291、proc_lcore@311、dpdk 块结束@328 | ✅ 相符 |
| linux2freebsd_socket_flags | `ff_syscall_wrapper.c:672-684`（00/03/04/06/10） | `ff_syscall_wrapper.c:672` 函数起，675-682 NONBLOCK/CLOEXEC 剥离转换，684 结束，与 03 §1.4 引用的代码块**逐字一致** | ✅ 相符 |
| ff_socket type 转换 | `ff_syscall_wrapper.c:943`（00/03/04/06） | `ff_syscall_wrapper.c:943` `sa.type = linux2freebsd_socket_flags(type);`（函数 ff_socket@917） | ✅ 相符 |
| ff_accept4 flags 转换 | `ff_syscall_wrapper.c:1679`（00/03/04/06） | `ff_syscall_wrapper.c:1679` `kern_accept4(curthread, s, pf, linux2freebsd_socket_flags(flags), &fp)`（函数 ff_accept4@1664） | ✅ 相符 |
| fstack_territory 剥离标志位 | `ff_hook_syscall.c:363-374`（02/03/04/08） | `ff_hook_syscall.c:359` 函数起，363-366 剥离 SOCK_CLOEXEC/NONBLOCK/FSTACK/KERNEL，368-369 判 AF_INET/INET6+STREAM/DGRAM，374 结束 | ✅ 相符 |
| pcurthread TLS | `ff_compat.c:59`（00/02/04/05） | `ff_compat.c:59` `__thread struct thread *pcurthread = NULL;` | ✅ 相符 |
| msg_iov_tmp 非 __thread | `ff_syscall_wrapper.c:225-226`（00/02/04/05/07/10） | `ff_syscall_wrapper.c:225` `static /*__thread*/ struct iovec msg_iov_tmp[UIO_MAXIOV];` / 226 `static /*__thread*/ size_t msg_iovlen_tmp;`（__thread **确被故意注释掉**） | ✅ 相符 |
| KNI primary-only（主循环） | `ff_dpdk_if.c:2661-2663`（00/01/08/10/12） | `ff_dpdk_if.c:2661` `if (enable_kni && rte_eal_process_type() == RTE_PROC_PRIMARY)` → 2662 `ff_kni_process(...)` | ✅ 相符 |
| KNI primary-only（init/alloc） | `ff_dpdk_kni.c:379/426`（12） | `ff_dpdk_kni.c:379` `if (rte_eal_process_type() == RTE_PROC_PRIMARY)`（ff_kni_init）/ `:426` 同（ff_kni_alloc） | ✅ 相符 |
| dispatch_ring SC flag | `ff_dpdk_if.c:618`（00/01/05/08/09）/ `:619`（11） | `ff_dpdk_if.c:619` `dispatch_ring[portid][queueid] = create_ring(name_buf, DISPATCH_RING_SIZE, socketid, RING_F_SC_DEQ);`（调用起于 618） | ⚠️ 事实正确，行号 618 为 ±1 漂移（可接受） |
| msg_ring SP/SC flag | `ff_dpdk_if.c:671`（11/12） | `ff_dpdk_if.c:671` `create_ring(..., RING_F_SP_ENQ \| RING_F_SC_DEQ)` | ✅ 相符 |
| proc_type 校验 | `ff_config.c:1316-1321`（仅 primary/secondary/auto）（01/04/06/08/10） | `ff_config.c:1316-1321` `strcmp(...,"primary") && strcmp(...,"secondary") && strcmp(...,"auto")` 才 invalid；默认 auto@1312-1314 | ✅ 相符 |
| ff_adapt_user_thread_add | `ff_compat.c:96`（02/05/07/10） | `ff_compat.c:96` `void * ff_adapt_user_thread_add(void *parent)`，parent==NULL 用 &thread0@102-103 | ✅ 相符 |
| SOCKET_OPS_CONTEXT_MAX_NUM=32 | `ff_socket_ops.h:45`=(1<<5)（04/06/12） | `ff_socket_ops.h:45` `#define SOCKET_OPS_CONTEXT_MAX_NUM (1 << 5)` = 32 | ✅ 相符 |
| worker→后端映射 | `ff_hook_syscall.c:3297`（02/04/06/08/12） | `ff_hook_syscall.c:3297` `sc = ff_attach_so_context(worker_id % nb_procs);` | ✅ 相符 |
| pcpup 单例 | `ff_freebsd_init.c:69`（02/05/10） | `ff_freebsd_init.c:69` `struct pcpu *pcpup;`（全局单例，非 TLS） | ✅ 相符 |
| ff_thread.c 共享父 td | `ff_thread.c:44`（02/05/10） | `ff_thread.c:44` `data->parent = pcurthread;`（子线程共享父 td） | ✅ 相符 |
| g_pcap_fp per-thread | `ff_dpdk_pcap.c:55-57`（05） | `ff_dpdk_pcap.c:55-57` `static __thread FILE* g_pcap_fp` / `seq` / `g_flen`（已 per-thread） | ✅ 相符 |
| SOCK_FSTACK/SOCK_KERNEL 宏值 | `ff_api.h:96`=0x01000000 / `:99`=0x02000000（02/06） | `ff_api.h:96` `#define SOCK_FSTACK 0x01000000` / `:99` `#define SOCK_KERNEL 0x02000000` | ✅ 相符 |
| **ff_api.h 注释笔误** | **`ff_api.h:1971-1972` 注释把 SOCK_KERNEL/SOCK_FSTACK 数值写反（02 §4 注、06 §3.3、07 A-M3）** | **`ff_api.h` 全文件仅 495 行，不存在第 1971-1972 行；全文件 `0x01000000/0x02000000` 仅出现在 95-99 行宏定义本身，无任何"数值写反"的注释** | ❌ **虚构，FAIL** |

---

## 3. FAIL 项详述与修复建议

### FAIL-1：虚构的 `ff_api.h:1971-1972` 注释笔误（维度 1）

**问题定位**：

- `02-线程基础设施现状与差距.md` §4 表格下方「注」：
  > `ff_api.h:1971-1972` 的注释把 `SOCK_KERNEL/SOCK_FSTACK` 的数值写反（注释称 SOCK_KERNEL=0x01000000、SOCK_FSTACK=0x02000000）……建议顺手修正。
- `06-配置与接口设计.md` §3.3：
  > `ff_api.h:1971-1972` 注释把 `SOCK_KERNEL/SOCK_FSTACK` 数值写反……建议后续修正注释。
- `07-里程碑与编码工作分解.md` 路线 A 里程碑表 **A-M3**：
  > 修正 `ff_api.h:1971-1972` 注释笔误（SOCK_KERNEL/SOCK_FSTACK 数值写反） | `ff_api.h:1971-1972` | 极低
- 素材 `_material_code.md` §4.3 亦为同一论断的来源。

**代码事实（审核方实测）**：

- `wc -l lib/ff_api.h` = **495 行**。文件根本没有第 1971-1972 行。
- `search_content` 全文件 `0x01000000|0x02000000`：仅命中 1 处，即 `:96 #define SOCK_FSTACK 0x01000000` / `:99 #define SOCK_KERNEL 0x02000000`（宏定义本身，数值正确、无写反）。
- 全文件不存在任何"把 SOCK_KERNEL/SOCK_FSTACK 数值写反"的注释文本。

**危害等级**：中高。

1. 直接违反 plan §4 / 项目铁律「代码为准、不臆测」——这是一处凭空杜撰的代码论断。
2. 该虚构论断被下游 `07` 采纳为一个**编码工作项（A-M3）**，若后续按此 WBS 执行，编码者会去 `ff_api.h:1971-1972` 找一个不存在的注释来"修正"，直接导致工作项无法落地、浪费工时、并可能误改无关代码。
3. 三处文档（02/06/07）+ 素材（_material_code.md §4.3）串联传递同一错误，属"错误结论自洽传递"，正是写审分离要拦截的盲区。

**修复建议（打回给文档撰写方）**：

- **首选**：删除 02 §4 注、06 §3.3、07 A-M3 及 `_material_code.md` §4.3 中关于 `ff_api.h:1971-1972` 注释笔误的全部内容（因该问题不存在，直接移除，不要改行号）。07 路线 A 里程碑表相应删除 A-M3 行（后续 A-M4/A-M5 编号可保留或顺延，由撰写方决定）。
- **如撰写方确实想保留"注释与宏值一致性核查"这一动作**：须先实际定位 `ff_api.h` 中真实存在的、涉及 SOCK_FSTACK/SOCK_KERNEL 的注释（如 `:87-88` 的功能描述性注释），确认其**是否真有数值/语义错误**；经审核方实测 `:87-88`、`:95-99` 的注释与宏值**均正确无误**，故不存在可修的笔误，应直接删除该工作项而非改写行号。
- 修复后重新提交 spec-gatekeeper 复审（bounce 计数 +1，当前为第 1 次打回，未超 3 次上限）。

---

## 4. 维度 2 — issue #430 覆盖（PASS）

- **plan 强制目标**：`plan.md` §0.3 第 9 项以「**【强制】GitHub Issue #430**」列出，明确要求「必须在 spec 中作为需求背景与用例引用」并交叉验证 `ff_syscall_wrapper.c:674-684` 等，满足"强制调研目标"要求。
- **结论给出情况**：
  - `00` §1.3：#430 属**概念 A**，代码已完备闭环（linux2freebsd_socket_flags + ff_socket:943 + ff_accept4:1679 + fstack_territory:363-366），评论区未抓到已诚实标注。
  - `03` §1：元信息+正文（已抓取，逐字引用 issue 正文）；§1.3 评论区/维护者回复/fix commit **明确标「未抓取到」**（GitHub 动态加载 + API 403 限流），§1.4 以代码为准坐实解决方案。
  - `04` §1：#430 归属概念 A，已完备处理。
- 审核方实测 `ff_syscall_wrapper.c:672-684/943/1679`、`ff_hook_syscall.c:363-366` 全部与文档结论相符（见 §2），**代码侧闭环成立**。

---

## 5. 维度 3 — 概念 A/B 区分与结论自洽（PASS）

- `04` §0/§1 用表格严格区分：
  - 概念 A（应用侧多线程调用 API，pthread+libuv）：**已支持**（adapter LD_PRELOAD 层，FF_THREAD_SOCKET/FF_MULTI_SC/SO_REUSEPORT）。
  - 概念 B（协议栈本身多线程运行模型，一进程多线程共栈）：**原生不支持**（lcore_conf 单例、pcpup 单例、msg_iov_tmp 非 __thread）。
- `00` §1.2 与 `04` 表述一致；`03` §2.3 亦明确「issue #430 属应用层多线程，非官方多线程栈运行模式」，建议 spec 区分两概念。
- 选型逻辑自洽：推荐选项 (c)（完善 adapter 多 worker，零回归、已闭环 #430）> 选项 (a)（单进程多线程独立栈，中长期进阶）> 选项 (b)（共享单栈+锁，不推荐，破坏 SC/SP ring 前提）。三选项 trade-off（04 §3）与代码事实（SC/SP ring flag、share-nothing 单例）一致。

---

## 6. 维度 4 — 诚实边界（PASS）

`03` §5「抓取状态清单」逐项诚实标注，未见杜撰：

| 目标 | 标注 |
|---|---|
| #430 评论区/维护者回复/fix commit | ❌ 未抓取到（动态加载+API 403），代码侧交叉坐实 |
| f-stack 官方"单进程多线程栈"模式 | ❌ 未检索到（不杜撰） |
| DPDK mempool/ring 精确语义 | ⚠️ 博客摘要级，建议以官方文档/仓库源码核实 |
| VPP / Seastar 多线程模型 | ❌ 未深入抓取（仅社区常识，需单独检索） |

- `00` §4、`04` §6、`11` §5 均重申诚实边界（选项 (a)/(b) 可行性基于本仓库代码而非官方背书；DPDK 行为为基于语义的推断，需以 dpdk-stable 源码核实）。
- 未发现把"未抓到"包装成"已确认"的情况。**诚实边界合格**。

---

## 7. 维度 5 — 多进程零回归论证闭环（PASS）

- `07` §1.4：路线 A（adapter 多 worker）**不触及 FreeBSD 全局单例**，默认路径不变，零回归天然成立。
- `10` §4：多进程零回归列为**一票否决门禁**，风险点（per-thread 化改动污染多进程路径）+ 缓解（编译宏/运行时 opt-in 门控、msg_iov_tmp 恢复 __thread 在每进程单线程下 TLS==全局等价、KNI 仍 primary-only、SC/SP flag 不变、proc_type 仍只放行三值）逐条对应。
- `08` §4：多进程零回归验收表（默认配置行为不变、KNI primary-only、SC/SP ring flag、配置解析兼容、API 兼容）+ bounce≤3 打回机制。
- `06` §2.4 / §4：选项 (a) 的 `thread_mode` 默认 0、全部新逻辑用 `if (thread_mode)` 包裹，保证默认路径逐字节不变。
- 审核方实测：msg_iov_tmp「每进程单线程 TLS==全局」的等价性、KNI primary-only、SC/SP flag、proc_type 三值校验均与代码相符 → **零回归论证闭环成立**。

---

## 8. 维度 6 — 文档完整性（PASS）

- 目录清单：`plan.md`、`00`~`13`（本文即 13）、`_material_code.md`、`_material_web.md` **齐全**。
- 无空文件：00~12 均有实质内容（结论先行 + file:line 证据 + 表格），无占位/空壳。
- 结构清晰：各文档统一「结论先行 → 分节论证（带 file:line）→ 诚实边界」范式；00 索引表与实际文档主题一致；plan §1 文档清单与实际产出一致。

---

## 9. 维度 7 — 规约遵循（PASS）

- **rm/kill/chmod**：全文档未建议直接调用 `rm`/`kill`/`chmod`。`08` §5、`09` §7 明确要求「删临时文件走 `/data/workspace/rm_tmp_file.sh`、杀进程走 `/data/workspace/kill_process.sh`、改权限走 `/data/workspace/chmod_modify.sh`」，符合脚本规约。
- **make clean**：`07` §2.3 注、`08` §5、`09` §7 均要求「编译前先 `make clean` 再全量编译」，符合 clean build 规约。
- **lib 最小注释**：`07` A-M3 注明「纯注释，遵守 lib 最小注释规约」（该里程碑本身因 FAIL-1 需删除，但其对最小注释精神的遵循意识正确）；建议的代码改动（恢复 __thread、per-thread 化）未引入冗余注释。
- **config.ini 本地值不入库**：`08` §5、`09` §5/§7 明确 lcore_mask/idle_sleep/IP 等本地测试值不入库。
- 本轮为 spec 阶段不改 lib、不编译，规约遵循以"文档不引导违规"为准 → **合格**。

---

## 10. 门禁裁决与后续动作

| 项 | 内容 |
|---|---|
| **总体裁决** | **打回（FAIL）** |
| FAIL 数 | 1（FAIL-1：虚构 `ff_api.h:1971-1972` 注释笔误） |
| PASS 维度 | 2/3/4/5/6/7（6 项） |
| FAIL 维度 | 1（代码 vs 文档一致性） |
| bounce 计数 | 第 1 次打回（未超 3 次上限，继续修复流程） |
| 打回目标 | 文档撰写方修复 `02` §4 注 / `06` §3.3 / `07` A-M3 / `_material_code.md` §4.3 中虚构的 `ff_api.h:1971-1972` 注释笔误论断（首选整体删除，见 §3 修复建议） |
| 复审要求 | 修复后重新提交 spec-gatekeeper 复审；复审仅需确认 FAIL-1 已消除且未引入新的 file:line 错误 |

**说明**：除 FAIL-1 外，本 spec 文档集在代码一致性（其余 20 处抽验相符）、issue #430 覆盖、概念区分、诚实边界、零回归论证、完整性、规约遵循七个方面质量良好。FAIL-1 是**孤立的、可精确定位的杜撰点**，修复成本极低（删除三处引用即可），修复后预计可一次性通过复审。

> **注**：§0~§10 为**首轮审核（bounce#0）**的记录，总体裁决为「打回（FAIL）」，予以**保留作审计轨迹**。bounce#1 修复后的复审记录见下方 §11，**最终裁决以 §11 为准**。

---

## 11. 复审记录（bounce#1 修复后）

> 复审时间：2026-07-23。复审方：spec-gatekeeper（同首轮，独立审核方，未参与撰写）。
> 复审范围（按 leader 复审请求）：仅确认 FAIL-1 是否消除 + 07 里程碑连贯性 + 无新错误；不重复全量抽验其余 20 处 file:line（首轮已 PASS）。

### 11.1 FAIL-1 消除核验（实测）

| 核验动作 | 结果 |
|---|---|
| `search_content "1971\|1972\|数值写反\|注释笔误\|写反\|笔误"`（全 zh_cn 目录） | 13 处命中**全部落在 `13-spec评审门禁.md` 自身的首轮记录**；`02`/`06`/`07`/`_material_code.md` **0 命中** |
| `search_content "A-M3\|A-M4\|A-M5\|ff_api.h:1971\|SOCK_KERNEL/SOCK_FSTACK\|数值写反"`（排除 13 文档） | **0 命中** |
| `02` §4 表格上下文 | 表格以 `SOCK_FSTACK 0x01000000@:96 / SOCK_KERNEL 0x02000000@:99`（数值正确）结尾，原虚构「注」已删除，直接接 §5，**通顺无断裂** |
| `06` §3.3 | 原「注释笔误建议」整节已删除，§3.2 第 3 条后直接接 §4，**通顺无悬挂** |

**结论：FAIL-1 已彻底消除**，`02`/`06`/`07`/`_material_code.md` 中不再存在任何 `ff_api.h:1971-1972` / 「注释把…数值写反」/ 「注释笔误」表述。

### 11.2 07 里程碑连贯性核验（实测）

- 路线 A 里程碑表（07 §1.3）现为：**A-M1**（编译宏矩阵）→ **A-M2**（ff_rss_self_queue_info 语义）→ **A-M3**（集成测试，复用 main_stack_thread_socket.c）→ **A-M4**（性能基线，多 worker vs 多进程）。
- WBS（07 §1.4）4 项与里程碑表**一一对应连贯**：编译宏矩阵(A-M1)/自检 API 语义(A-M2)/集成测试脚本(A-M3)/性能基线脚本(A-M4)，**无悬挂引用**。
- 原虚构的「ff_api.h 注释笔误」里程碑已删除；「集成测试」由原 A-M4 顺延为 A-M3、「性能基线」由原 A-M5 顺延为 A-M4，编号连续无跳号。与 leader 旁路确认一致（残留 A-M3=集成测试为合法顺延项，非杜撰）。
- 交叉引用检查：全 zh_cn 目录（除 13 自身）无对已删除的旧「ff_api.h 注释」里程碑的悬挂引用（08 等文档对集成测试/性能基线的引用指向 `08`/`09`，非编号，未受影响）。

### 11.3 无新错误确认

- 修复仅为**删除**操作，未新增/改写任何 file:line 论断，未引入新的代码论断。
- 首轮已 PASS 的其余 20 处 file:line 及维度 2~7 不受本次删除影响，无需重验。

### 11.4 最终裁决

| 项 | 内容 |
|---|---|
| **最终总体裁决** | **通过（PASS）** |
| FAIL-1 状态 | **已消除** |
| 7 维度结论 | 全部 **PASS**（维度 1 代码一致性在 FAIL-1 消除后转 PASS；维度 2~7 首轮即 PASS） |
| bounce 计数 | 第 1 次打回后修复通过（未超 3 次上限） |
| 后续 | spec 文档集通过门禁，可进入提交阶段（仅提交 docs/，不动 config.ini 本地值，commit message 英文 1-3 句） |

**独立审核声明**：本次复审严格以实际 `search_content`/`read_file` 结果为准，FAIL-1 确已消除、里程碑编号连贯、无新错误引入，据此出具 **PASS** 裁决，不因流程推进压力放水。
