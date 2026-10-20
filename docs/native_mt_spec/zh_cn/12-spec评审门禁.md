# 12 spec 评审门禁（独立 gatekeeper 出具）

> 本文档由**独立审核 agent（未参与任何文档撰写，文档由 leader 撰写）**出具，以 `lib/`、FreeBSD 15.0、DPDK 24.11.6 实际源码 file:line 为准，不臆测。
> 审核对象：`docs/native_mt_spec/zh_cn/` 下 plan.md + 00~11 全部 spec。
> 判定规则：逐维度 PASS/FAIL；行号漂移 ±若干行可接受，事实必须对；FAIL 给位置 + 修复建议。
> 本次为 gatekeeper 第二棒（前一棒因源码全树扫描超时被替换）。审核方法：仅对指定 file:line 精确 `read_file`（带 offset/limit），VNET 只读 vnet.h/vnet.c 指定行段，未对 freebsd-src 做全树扫描。

## 0. 总体结论

**PASS**（0 个 FAIL；3 个 INFO 级观察，不影响放行）。

| 维度 | 结论 |
|---|---|
| 1 代码一致性抽验 | **PASS**（27/27 抽验项与代码一致，行号漂移均 ≤1 行） |
| 2 方向正确性（无 adapter 推荐残留） | **PASS** |
| 3 VNET 主路径自洽 | **PASS** |
| 4 概念区分 + #430 定位 | **PASS** |
| 5 诚实边界 | **PASS** |
| 6 多进程零回归闭环 | **PASS** |
| 7 完整性 + 规约 | **PASS** |

spec 事实准确、方向聚焦原生多栈实例、诚实边界标注到位、多进程零回归闭环完整，**准予放行进入 SM6 提交**。

## 1. 维度一：代码一致性抽验（核心，实际 read_file 核验）

全部 27 项均由本 agent 实际 `read_file` 逐行核验，与 spec 断言一致（行号漂移记录在备注列）。

| # | spec 断言（file:line） | 实测结果 | 判定 |
|---|---|---|---|
| 1 | `lcore_conf` 全局单例 `ff_dpdk_if.c:123` | `struct lcore_conf lcore_conf;` @123 | ✅ |
| 2 | `struct lcore_conf` 定义 `ff_memory.h:82-95` | 定义 @82 起，`__rte_cache_aligned` @95 | ✅ |
| 3 | `msg_iov_tmp` static + `__thread` 被注释 `ff_syscall_wrapper.c:225` | `static /*__thread*/ struct iovec msg_iov_tmp[UIO_MAXIOV];` @225 | ✅ |
| 4 | `msg_iovlen_tmp` 同上 `:226` | `static /*__thread*/ size_t msg_iovlen_tmp;` @226 | ✅ |
| 5 | `pcpup` `ff_freebsd_init.c:69` | `struct pcpu *pcpup;` @69 | ✅ |
| 6 | `proc0` `ff_init_main.c:96` | `struct proc proc0;` @96 | ✅ |
| 7 | `thread0`/`thread0_st` `ff_init_main.c:98` | `struct thread0_storage thread0_st __aligned(16);` @98 | ✅ |
| 8 | `prison0`/`vmspace0`/`initproc` `:97,99,100` | prison0@97 / vmspace0@99 / initproc@100 | ✅ |
| 9 | `cc_cpu` 单例 `ff_kern_timeout.c:180` | `struct callout_cpu cc_cpu;` @180 | ✅ |
| 10 | `CC_CPU`/`CC_SELF` 硬编码 `&cc_cpu` `:181-182` | `#define CC_CPU(cpu) &cc_cpu` @181 / `#define CC_SELF() &cc_cpu` @182 | ✅ |
| 11 | `mi_startup` `ff_init_main.c:173-285` | `void mi_startup(void)` @173-174，函数体覆盖至打勾/收尾 | ✅ |
| 12 | `if(sysinit==NULL)` `:188` | `if (sysinit == NULL) {` @188 | ✅ |
| 13 | `SI_SUB_LAST continue` `:235-236` | `if ((*sipp)->subsystem == SI_SUB_LAST) continue;` @235-236 | ✅ |
| 14 | 打勾 `SI_SUB_LAST` `:271` | `(*sipp)->subsystem = SI_SUB_LAST;` @271 | ✅ |
| 15 | `dispatch_ring` `RING_F_SC_DEQ` 约 `:619` | `create_ring(..., RING_F_SC_DEQ)` @619 | ✅ |
| 16 | `msg_ring[RTE_MAX_LCORE]` `:177` | `static struct ff_msg_ring msg_ring[RTE_MAX_LCORE];` @177 | ✅ |
| 17 | `msg_ring` `SP_ENQ\|SC_DEQ` 约 `:670` | `RING_F_SP_ENQ \| RING_F_SC_DEQ` @671 | ✅（漂移+1行） |
| 18 | `pktmbuf_pool[NB_SOCKETS]` `:125` | `struct rte_mempool *pktmbuf_pool[NB_SOCKETS];` @125 | ✅ |
| 19 | cache_size `MEMPOOL_CACHE_SIZE` 约 `:540` + flag=0 | `rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0, ...)` @538-541 | ✅ |
| 20 | proc_type 校验 `ff_config.c:1316-1321` | primary/secondary/auto 三值校验 @1316-1321 | ✅ |
| 21 | `parse_lcore_mask` `:73-142`；`nb_procs=count` @139 | 函数 @72-142，`cfg->dpdk.nb_procs = count;` @139 | ✅ |
| 22 | KNI 校验 `:1392-1412` | primary + lcore_list 校验块 @1392-1412 | ✅ |
| 23 | `ff_init`/`ff_run` `ff_init.c:35-62` | `ff_init` @35-56，`ff_run→ff_dpdk_run` @58-62 | ✅ |
| 24 | KNI primary-only `ff_dpdk_kni.c:379,426` | `rte_eal_process_type()==RTE_PROC_PRIMARY` @379 与 @426 | ✅ |
| 25 | KNI 门控 `ff_dpdk_if.c:2661` | `if (enable_kni && rte_eal_process_type()==RTE_PROC_PRIMARY)` @2661 | ✅ |
| 26 | `ff_ipc` `--proc-type=secondary` `ff_ipc.c:67` | `"--proc-type=secondary",` @67 | ✅ |
| 27 | socket flags `ff_syscall_wrapper.c:672-684`/`:943`/`:1679` | `linux2freebsd_socket_flags` @672-684；`ff_socket` 调用 @943；`ff_accept4→kern_accept4(..., linux2freebsd_socket_flags(flags), ...)` @1679 | ✅ |

**附加核验（VNET/EAL/TLS/main_loop）：**

| 项 | spec 断言 | 实测 | 判定 |
|---|---|---|---|
| `opt_global.h` 无 VIMAGE | `03/04/09` 称无 VIMAGE | 全文仅 5 行（MUTEX/RWLOCK/SX_NOINLINE、DEV_RANDOM、NO_EVENTTIMERS），**确无 VIMAGE** | ✅ |
| `struct vnet` | `vnet.h:69` | `struct vnet {` @69 | ✅ |
| `curvnet=curthread->td_vnet` | `vnet.h:176` | `#define curvnet curthread->td_vnet` @176 | ✅ |
| `vnet_alloc()` | `vnet.c:239` | `struct vnet * vnet_alloc(void)` @238-239 | ✅ |
| `rte_eal_mp_remote_launch(main_loop,...)` | `ff_dpdk_if.c:2770` | @2770 + `rte_eal_mp_wait_lcore()` @2771 | ✅ |
| `main_loop qconf=&lcore_conf` | `ff_dpdk_if.c:2585` | `qconf = &lcore_conf;` @2585 | ✅ |
| `rte_eal_init` 全进程一次 | `ff_dpdk_if.c:1594` | `int ret = rte_eal_init(argc, argv);` @1594 | ✅ |
| `pcurthread` 已 `__thread` | `ff_compat.c:59` | `__thread struct thread *pcurthread = NULL;` @59 | ✅ |

**维度一结论：PASS。** 全部抽验项与源码一致，最大偏差为 msg_ring flag 行号 +1（约:670 实为:671，spec 已用"约"字，可接受）。

## 2. 维度二：方向正确性（原生多栈实例，无 adapter 推荐残留）

- `00 §3` 标题「推荐落地路径（原生，非 adapter）」；§3 末「非本方案：LD_PRELOAD adapter 多 worker 是应用侧适配，不是栈侧原生多线程运行模型」——adapter 明确排除在方案外。
- `00 §0` 旧版 adapter 推荐**显式作废**，本版只设计库内原生方案。
- `02 §4`「adapter 现状（客观记录，非本方案目标）」——仅现状记录，无推荐语气。
- `05 §4` 被否决备选对比表：adapter 与「共享单栈+锁」并列为**被否决/仅记录**；`05 §5` 首选明确为 VNET 原生路径。
- 对 `00-*.md`、`05-*.md` 检索「推荐/首选/建议」关键词：所有"推荐/首选"均指向 **VNET 原生路径**，"不推荐"均指向 adapter 与共享单栈；**无一处把 adapter 作为推荐或结论落点**。

**维度二结论：PASS。** 方向聚焦库内原生单进程多线程多栈实例，adapter 仅作现状记录，无残留推荐。

## 3. 维度三：VNET 主路径自洽（04/05/09 与源码一致 + 诚实标注运行时验证）

- 04/05/09 的 VNET 关键坐标（`struct vnet` vnet.h:69、`curvnet=td_vnet` vnet.h:176、`vnet_alloc` vnet.c:239）本 agent 已逐一实测一致（见 §1 附加核验）。
- 主路径逻辑自洽：VNET 覆盖 `VNET_DEFINE` 网络栈全局（一次启 VIMAGE），f-stack 自造全局（`lcore_conf`/`pcpup`/`thread0`/`cc_cpu`/`msg_iov_tmp`）VIMAGE 不覆盖须另行 per-thread 化——`04 §2` 明确指出"路线甲与路线乙并非纯二选一"，组合策略清晰，无逻辑跳跃。
- **诚实标注到位**：`00 §5-1`、`04 §1.2` 硬结论（mi_startup 不可 N 次，静态可判定）与 `04 §2 路线乙 诚实边界`、`09 §6`、`11 §5` 均明确「VIMAGE 在 f-stack 阉割用户态可用性**须运行时验证**，不得臆断可行」——**未断言 VIMAGE 一定跑通**，符合"代码为准、不臆测"。

**维度三结论：PASS。**

## 4. 维度四：概念区分 + #430 定位

- 术语表（`01 §4`）清晰区分「应用侧多线程」（pthread 调 socket API，#430 场景）与「栈侧多线程运行模型」（本轮目标）。
- #430 定位一致落在**佐证、非结论落点**：`plan §1 第9项`「作一手佐证记录，不作结论落点」、`00 §7`「与栈侧原生多线程运行模型是两个层面，不作本轮结论落点」、`09 §4`「属应用侧多线程调 API（已就绪）…非本轮结论落点」。三处表述一致。
- 代码坐实：`linux2freebsd_socket_flags`(:672-684)/`ff_socket`(:943)/`ff_accept4`(:1679) 组合标志位处理完备，本 agent 实测确认（§1 #27）。

**维度四结论：PASS。**

## 5. 维度五：诚实边界

- 外网未抓到项如实标注、未杜撰：`09 §3.2` Seastar/VPP「社区常识，未深抓，不杜撰细节」；`09 §3.3` f-stack 官方「未检索到单进程多线程栈模式，不杜撰」；`09 §4` #430「评论区/fix commit 未抓到（GitHub 动态加载+API 403 限流），以代码为准」；`09 §6` 取证状态表逐项标 ✅/⚠️/❌。
- 须运行时验证项集中标注：`00 §5`、`04 §5`、`06 §6`(mempool 容量)、`10 CM4`(VIMAGE PoC 门禁)、`11 §5` 诚实边界分层表（静态可判定 vs 须运行时验证分列）。

**维度五结论：PASS。**

## 6. 维度六：多进程零回归闭环

- `07 §3` 零回归策略三条：开关默认关（thread_mode=0 走既有分支字节级不变）、两模式互斥（thread_mode=1 与 secondary 组合报错）、新增而非改写（用 nb_threads 不污染 nb_procs）。
- `10 §3` 每里程碑「thread_mode=0 必须字节级零回归（一票否决）」；CM1 回滚点「开关默认 0 走既有分支字节不变」。
- `11 §1.4`「多进程零回归（一票否决）」+ `§3 R8`「thread_mode 默认关 + 两模式互斥 + 字节级回归门禁」。
- opt-in 默认关经代码基线确认合理：现状 proc_type 默认 auto（`ff_config.c:1312-1313`），新增 thread_mode 默认 0 不改变既有默认路径。

**维度六结论：PASS。** 默认关 + 互斥 + 字节级回归门禁闭环完整。

## 7. 维度七：完整性 + 规约

- **完整性**：plan.md + 00~11 共 13 份文档齐全，另有 4 份 `_material_*.md` 素材；本 agent 逐一 `read_file`，**无空文件、无占位残缺**。
- **规约**：全篇均为调研/spec，未建议直接 `rm`/`kill`/`chmod`（`plan §5`、`01 §6`、`10 §3` 均声明删除/kill/chmod 走脚本、改代码先 `make clean`）；lib 最小注释、commit 英文 1-3 句、config.ini 本地值不入库均在规约段明列。本轮纯文档不触及 lib 源码（本 agent 只读未改任何 lib 文件）。

**维度七结论：PASS。**

## 8. 问题清单与最终裁决

### 8.1 问题清单

无 FAIL 项。以下为 INFO 级观察（不影响放行，供后续编码阶段留意）：

| # | 级别 | 位置 | 观察 | 建议 |
|---|---|---|---|---|
| I1 | INFO | 多处「约:670」 | `msg_ring` 的 `SP_ENQ\|SC_DEQ` 实为 :671（+1 行） | spec 已用"约"字，可保留；如追求精确可改 :671 |
| I2 | INFO | `03 §1` thread0 行 | 表述为 `thread0`/`thread0_st @:98`，代码实为 `struct thread0_storage thread0_st __aligned(16)` | 事实一致，无需改；仅提示 thread0 本体经 thread0_st 承载 |
| I3 | INFO | `08`/`10` KNI 校验行号 | `08 §2`/`10 CM6` 引 `ff_config.c:1396-1411`，`07 §2.3` 引 `:1392-1412` | 两者均落在同一校验块（@1392-1412 含注释起始），一致，无需改 |

### 8.2 最终裁决

**总体：PASS（0 FAIL / 3 INFO）。**

spec 全部关键技术论断经独立源码抽验一致（27 主项 + 8 附加项全通过），方向正确（原生多栈实例、无 adapter 推荐残留）、VNET 主路径自洽且诚实标注运行时验证边界、概念区分与 #430 定位准确、诚实边界到位、多进程零回归闭环完整、文档完整且合规。

**准予放行进入 SM6（本地提交，仅 docs，英文 commit，config.ini 本地值不入库）。** 3 个 INFO 项为可选优化，不构成 bounce 打回条件。

---

> 审核方法说明：本 gatekeeper 未参与任何文档撰写（写审分离），仅独立 read_file 指定 file:line 核验，未对 freebsd-src 全树 search_content（避免超时）。所有 ✅ 均为本 agent 亲自读取源码行确认，非转述 spec 自述。
