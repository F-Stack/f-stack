# F-Stack native-mt 遗留风险专项（M18）—— 总体计划

> 本文档固化本专项的任务目标、6 个遗留问题的现状与处理策略、agent team 分工、里程碑、DoD 与强制规约。
> 代码事实基线：`git HEAD = 9ef6dc92e`（`/data/workspace/f-stack`）。

## 0. 任务定位

M17（`17-SMP-aware-pcpu视图与去全局锁.md`）已交付「SMP-aware pcpu 视图 + 去 `uma_crit_lock`」，并在 §5/§6 把 6 类残留风险「如实记录、本轮不修」。本专项（M18）对这 6 类遗留问题做**跟踪 → 分析 → 处理**：

1. 逐个用代码坐实「问题是否确实存在」；
2. 对可修的问题设计并实施修复（代码编写）；
3. 门禁审核（写/审分离）+ 单元测试 + 运行时测试；
4. 对确需独立立项的（DPCPU）如实记录，不强行修复。

## 1. 6 个遗留问题清单与现状

| # | 问题 | 代码依据（已初步坐实） | 性质 | 本轮策略 |
|---|---|---|---|---|
| P1 | ipfw/netisr 的 DPCPU 槽位别名 | `freebsd/netpfil/ipfw/ip_fw_dynamic.c:224-226` `DPCPU_DEFINE_STATIC(void *, dyn_hp)`；`dpcpu_init()` 零调用者、`dpcpu_off[]` 恒 0 → 全 cpu 槽位互相别名 | 内存/并发安全（需 DPCPU 独立立项） | 分析坐实 + 记录，不修 |
| P2 | counter(9) 统计竞争 | `lib/include/amd64/include/counter.h:58-62` `counter_u64_add` 为 `*c += inc`（非原子）、`counter_enter/exit` 空操作 | 统计准确性（丢失更新） | 分析 + 修复（原子化） |
| P3 | tcp_hpts 实例数 1→N 的 callout 归属错配（R6） | `tcp_hpts.c:1864/1872` `rp_num_hptss = mp_ncpus`；`:2040-2052` callout 挂 `p_cpu`；`p_mtx` 塌缩为无互斥（`mutex.h:74-76` 常量 1） | 并发语义错配 | 深入分析 + 修复/兜底 |
| P4 | net.isr.dispatch 必须保持 direct | `netisr.c:149-158` 可 RW-TUN；`curcpu` per-thread 化后 hybrid/deferred 触发 `:1172` queue_fallback → `swi_sched` 空 stub → 静默丢包 | 配置约束 | 文档化 + 启动期防护 |
| P5 | ff_subr_prf.c 全局无锁行缓冲 | `lib/ff_subr_prf.c:86 char bufr[PRINTF_BUFR_SIZE];` + `:89 static int putbuf_done;` 均非 `__thread` 无锁 | 日志丢失/拼接污染 | 修复（改 `__thread`） |
| P6 | ff_pthread_create 线程不支持调用 ff_* | `lib/ff_thread.c:32-46` 只 `ff_set_thread(parent)` 不调 `ff_pcpu_thread_init` → `pcpup == NULL` | fail-fast 缺口 | 文档化 + 运行时 fail-fast 防护 |

## 2. Agent Team 分工（1 leader + 若干子 agent，写审分离）

| 角色 | 阶段 | 职责 |
|------|------|------|
| leader（主 agent） | 全程 | 统筹、轮询等待、超时/旁路探测、异常回退补救、纯汇总类任务 |
| res-analyze（调研） | M1 | 逐条代码坐实 6 个问题是否真实存在（只读，产出 file:line 证据） |
| designer（设计） | M2 | 对 P2/P3/P4/P5/P6 给出修复方案，P1 给出独立立项结论 |
| coder（编码） | M3 | 实施 P2/P4/P5/P6 代码修复（P3 视设计结论） |
| builder（编译） | M4 | `make clean` 后完整重编 lib + example，error/warning 门禁 |
| reviewer（门禁） | M5 | 独立审核代码（≠ coder），写审分离，bounce≤3 |
| tester（测试） | M6 | 单元测试 + 运行时测试（本机双网卡约束） |
| gate-doc（文档门禁） | M7 | 审核 spec 文档（≠ 撰写方） |

## 3. 里程碑

- **M0** 写 plan.md（本步）
- **M1** res-analyze 深探：逐个坐实 6 个问题的存在性 + 影响面
- **M2** designer 出修复方案（P1 独立立项结论；P2/P4/P5 明确修；P6 防护；P3 裁决）
- **M3** coder 实施修复（最小 diff）
- **M4** builder clean build 门禁
- **M5** reviewer 代码门禁（bounce≤3）
- **M6** tester 单测 + 运行时测试
- **M7** spec 文档撰写 + gate-doc 审核 + 本地提交

## 4. DoD（完成定义）

- 每个问题有明确的「是否真实存在」结论（代码坐实，非臆测）；
- 可修问题：代码已改、clean build 通过、门禁 PASS、单测/运行时测试 PASS；
- 独立立项问题（P1）：结论 + 立项建议已记录；
- `thread_mode=0` 多进程零回归（一票否决）；
- 所有文档/代码无真实 IP、config.ini 本地值不入库。

## 5. 强制规约（全部沿用，零容忍）

- 实际执行不臆测、代码为准；交叉验证不一致以代码为准；引用附 file:line。
- 删除走 `/data/workspace/rm_tmp_file.sh`；kill 走 `/data/workspace/kill_process.sh`；chmod 走 `/data/workspace/chmod_modify.sh`。
- lib 最小注释；commit message 英文 1-3 句；config.ini 本地测试值不入库；改代码先 `make clean` 再编译。
- 本机双网卡：DPDK 独占网卡 IP `<DPDK_NIC_IP>` 需 `ssh f-stack-client` 测；内核栈测 `127.0.0.1` 的 lo。
- 写审分离：写代码/文档 ≠ 审核方；中间纯调研/汇总类可由 leader 兼任。
- leader 轮询等待 + 旁路探测优先 + 超时探测 + 异常回退；子 agent 全部完成前 leader 不提前退出。
- 门禁失败打回上一步重修；同一步骤 bounce≤3 否则转人工。
