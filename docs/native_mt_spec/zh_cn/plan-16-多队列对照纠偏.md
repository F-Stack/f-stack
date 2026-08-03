# plan-16 多队列对照纠偏：推翻「virtio 无 RSS 导致 native-mt 多线程失效」结论

> **文档编号**：PLAN-NMT-16
> **版本**：v1
> **日期**：2026-08-03
> **性质**：本轮总体计划（先落盘 plan，再执行）
> **实证铁律**：所有结论必须来自实际运行/实际代码，禁止臆测；代码与文档/外网不一致时**以代码为准**。

---

## 0. 本轮定位：纠偏 15 号文档结论

### 0.1 用户质疑（成立）

15 号文档（`15-worker时钟缺口修复与virtio-RSS限制.md` 第 5 节）结论为：

> 「2 线程吞吐受限的最终瓶颈定位为 virtio PMD 不支持 RSS/RETA（环境限制，非代码缺陷）」

用户指出该结论不成立，理由：
1. virtio 虽不支持标准 RSS（RETA 重定向表），但**有自己的接收端负载均衡**（`VIRTIO_NET_F_MQ` + vhost/tun 侧 flow steering）；
2. 若用 **`thread_mode=0` 且开启 2 个 worker（2 进程 / 2 队列）** 做对照测试，性能应当正常 —— 那么原结论即被推翻。

### 0.2 已核实的实证：原对照实验设计确有缺陷

15 号文档第 6 节的对照表：

| 已测配置 | 队列数 | 结果 |
|---|---|---|
| `thread_mode=1` + `lcore_mask=2` | **1** | 209,790 req/s |
| `thread_mode=1` + `lcore_mask=6` | **2** | 557 / 0 req/s |
| `thread_mode=0` + `lcore_mask=2` | **1** | 216,812 req/s |

**缺失项**：`thread_mode=0` + **2 进程 2 队列**。

因此原实验把「1 队列 vs 2 队列」的差异，错误归因为「进程模式 vs 线程模式」的差异。要证明「多队列在本 virtio 环境不可用」，必须证明 `thread_mode=0` 双队列**也**不可用；该实验从未做过。

### 0.3 已核实的代码事实（不是臆测）

| 事实 | 位置 | 内容 |
|---|---|---|
| virtio `reta_size` 依赖 `VIRTIO_NET_F_RSS` | `dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c:2660-2669` | host 宣告 `VIRTIO_NET_F_RSS` → `reta_size = VIRTIO_NET_RSS_RETA_SIZE`；否则 `reta_size = 0`、`flow_type_rss_offloads = 0`、`hash_key_size = 0` |
| 多队列能力是**独立**特性 | `dpdk-stable-24.11.6/drivers/net/virtio/virtio_ethdev.c:1840-1852` | `VIRTIO_NET_F_MQ` **或** `VIRTIO_NET_F_RSS` 任一被宣告即读取 `max_virtqueue_pairs`；两者都无才强制 `max_queue_pairs = 1` |
| f-stack 侧 RSS 配置被跳过 | `f-stack/lib/ff_dpdk_if.c:885-926` | 整段 RSS 配置（`mq_mode = RTE_ETH_MQ_RX_RSS`、`rss_hf`、`rss_key`、`ff_rss_thash_build_key`）被 `if (dev_info.flow_type_rss_offloads)` 包住；virtio 无 RSS → **整段不执行** |
| `rss_reta_size` 保持 0 | `f-stack/lib/ff_dpdk_if.c:1009-1016` | 仅 `dev_info.reta_size` 非零时才赋值并打印 `rss table size` |

**关键推论（本轮待验证的核心）**：上述「无 RSS」代码路径对 `thread_mode=0` 和 `thread_mode=1` 是**完全共享**的（`init_port_start` 不区分 thread_mode）。因此：

- 若 `thread_mode=0` 双队列**正常** → 「无 RSS 导致多队列失效」被**推翻**，`thread_mode=1` 的问题必在 thread_mode 专有代码路径；
- 若 `thread_mode=0` 双队列**同样失效** → 原结论方向成立，但仍须补齐 virtio MQ 是否协商成功的实证（不能仅凭「无 `rss table size` 日志」下结论）。

### 0.4 本轮唯一目标

用**实测**判定上述二分，并在判定为「代码缺陷」时定位并修复，使 `thread_mode=1` 多线程达到可用吞吐（不得以「遗留事项」搁置，除非 3 次打回后确认无法实现）。

**硬性边界（沿用，不可违反）**：
1. **核心数据面路径永不加锁，也不得尝试加锁方案**；仅初始化等非数据面路径允许加锁。
2. `thread_mode=0`（多进程）**零回归**。
3. per-vnet 协议栈隔离设计不得倒退为「共享单栈 + 全局锁」。

---

## 1. 假设清单（本轮待逐一实测判定）

| ID | 假设 | 判定方法 | 预期证据 |
|---|---|---|---|
| **H0** | `thread_mode=0` 双进程双队列在本 virtio 环境**正常** | E2 实验 | wrk req/s 量级正常（≥100k） |
| H5 | virtio MQ（`VIRTIO_NET_F_MQ`）已协商成功、双队列真实生效 | 读 ff_log/DPDK PMD 日志 + `rte_eth_dev_info` 实际值 | `max_rx_queues > 1`；rx_queue_setup 双队列成功 |
| H6 | `thread_mode=1` 下 `dispatch_ring` / `msg_ring` 数组按 `nb_procs`(=1) 而非 `nb_threads` 分配，worker `proc_id=1` 越界访问未初始化元素 | 代码走查 `ff_dpdk_if.c:548 / 690-692 / 2106 / 2335-2348` + 探针 | ring 指针为 NULL 或未创建 |
| H7 | `thread_mode=1` 下主线程 ifp（`veth_ctx` 索引）与 worker ifp 归属错位（`veth_ctx[lcore][port]` 中主线程条目由 `ff_freebsd_init` 阶段以不同 lcore 索引写入） | 代码走查 `ff_dpdk_if.c:2649-2664` + `ff_veth.c` | 主线程 lcore 的 `veth_ctx` 项为 NULL 或指向他人 |
| H8 | KNI 归属（`ff_kni_is_owner_thread`）在 thread_mode=1 双队列下吞掉了本应进协议栈的包 | 关闭 `kni.enable` 复测 + 探针 | 关 KNI 后吞吐恢复 |
| H9 | 无 RSS 时 f-stack 未配 `mq_mode`，网卡按 virtio 默认策略分发；包落到非 owner 队列后因 `packet_dispatcher` 未注册而**不做软件重分发**，直接进错 vnet | 代码走查 `ff_dpdk_if.c:1983-2029` + 每队列收包探针 | SYN 落在 A 队列但 socket 在 B vnet |

> H9 与 H0 互补：即使 `thread_mode=0` 双队列也走同一分发逻辑，但**多进程每进程独立 vnet 且都 listen 同一端口**，任一队列收到 SYN 都能就地完成握手；而 `thread_mode=1` 若 listen socket 只建在部分 vnet（取决于 app 行为），落错队列的 SYN 就无人应答。**此为当前最强候选**，须由实测坐实，禁止先写结论。

---

## 2. 实验矩阵（全部必须实际执行）

统一压测命令（用户指定，不得改动）：

```
ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://9.134.214.176:80/"
```

统一前置：每次启动前用 `pgrep` 确认无残留 helloworld 进程；有则用 `/data/workspace/kill_process.sh` 清理（**严禁** `kill`/`pkill`/`killall`）。

| 实验 | thread_mode | lcore_mask | 进程数 | 队列数 | 目的 |
|---|---|---|---|---|---|
| **E1** | 0 | 2 | 1 | 1 | 单队列基线复现（对照锚点） |
| **E2** | 0 | 6 | **2**（primary `--proc-id=0` + secondary `--proc-id=1`） | **2** | **本轮关键**：判定 H0 |
| **E3** | 1 | 6 | 1（2 线程） | 2 | 复现 15 号文档的失效现象 |
| E4 | 1 | 6 | 1（2 线程） | 2 | 修复后复测 |
| E5 | 0 | 2 / 6 | 1 / 2 | 1 / 2 | 修复后零回归复测 |

E2 执行要点（须先核实、不得臆测命令行）：
- `config.ini` 中 `[port0] lcore_list` 须显式覆盖两个 lcore；
- 两个进程各自 `--proc-id`，DPDK primary/secondary；
- KNI 仅 primary 处理（`ff_config.c` 中已有 primary lcore 必须在 lcore_list 的校验）。

**config.ini 本地测试值（`lcore_mask`/`thread_mode`/本机 IP/`idle_sleep` 等）一律不入库。**

---

## 3. Agent Team 分工（1 leader + 子 agent，写审分离）

团队名：`nmt-mq-parity`

| 角色 | Agent | 阶段 | 职责 | 允许写? |
|---|---|---|---|---|
| leader | 主 agent | 全程 | 统筹、轮询等待、旁路探测、超时/异常回退、实验执行与数据汇总（纯执行/汇总单一角色允许兼任） | 仅 plan/汇总 |
| A. 代码探测 | 子 agent（只读） | M1 | thread_mode=0 vs 1 的**全部代码路径差异**（ring 分配、veth_ctx、KNI 归属、queue 映射、vnet/listen socket 归属），核验 H6/H7/H8/H9 | 否（只读） |
| B. 外网调研 | 子 agent（只读） | M1 | virtio MQ/RSS、vhost flow steering、f-stack github issue/wiki/博客中「virtio 多队列 + f-stack 多进程」实证，交叉验证；不一致以代码为准 | 否（只读） |
| C. 修复实施 | 子 agent | M3 | 按裁决实施代码修复（数据面零锁）、`make clean` 后完整编译 | 是（代码） |
| D. 独立 review | 子 agent（≠C） | M4 | 审核 C 的改动：零锁约束、thread_mode=0 零回归、per-vnet 隔离完整性、无调试残留 | 否（只审） |
| E. 文档撰写 | 子 agent | M5 | 撰写 16 号 spec 文档（结论 + 实测数据 + 纠偏说明），并修订 15 号文档结论 | 是（文档） |
| F. 门禁 | 子 agent（≠E） | M6 | 逐条核验文档中每个 `file:line` 引用与每个数据点是否与实际一致，措辞是否越过实证边界 | 否（只审） |

**角色分离铁律**：写（C/E）与审（D/F）必须不同 agent；leader 若接管任何「写」任务，其后续审核环节必须 spawn 新子 agent 执行，不得自写自审。

**超时与回退机制（leader 必须执行）**：
- 每个子 agent 设 **8 分钟**软超时；
- 轮询周期 **90 秒**：`send_message` 询问 + **旁路探测优先**（直接读子 agent 应落盘的文件 / `git status` / 日志产物）；
- 消息无回应但旁路探测显示有产出 → 继续等待；
- 超时且无产出 → 回退：① leader 接管（后续必须新 spawn 审核 agent）；② 新 spawn 同角色子 agent 重跑；③ 按 bounce≤3 转人工。
- **子 agent 全部完成前，leader 严禁提前退出/提前汇总/`team_delete`。**

---

## 4. 里程碑与门禁

| 里程碑 | 内容 | 门禁（不通过则打回上一步） |
|---|---|---|
| **M0** | plan 落盘（本文档） | plan 覆盖假设/实验矩阵/分工/门禁/规约 |
| **M1** | 代码路径差异探测（A）+ 外网交叉调研（B）**并行** | 每条 H6-H9 均有 `file:line` 级证据或明确「无证据」结论；不得出现「推测」字样 |
| **M2** | 执行 E1/E2/E3，产出实测数据 | E2 必须真实跑通并有 wrk 原始输出；进程/队列数须有实证（日志或 `ps`） |
| **M3** | 裁决 + 修复实施（C） | `make clean` 后完整编译通过（**禁止增量编译**）；数据面零锁 |
| **M4** | 独立 review（D） | 6 项审核全 PASS |
| **M5** | E4/E5 复测 + 文档撰写（E） | 修复后 thread_mode=1 双线程吞吐可用；thread_mode=0 零回归 |
| **M6** | 门禁核验（F）+ 提交 | 文档所有引用/数据点逐条核对一致；commit message 英文 1-3 句；`config.ini` 本地值不入库 |

**bounce counter**：每步骤独立计数，同一步骤打回 **≤3 次**；第 3 次仍不通过 → **停止任务、转人工决策**，禁止带病放行、禁止以「遗留事项」搁置。

---

## 5. 强制规约（零容忍，全程适用）

1. **实际执行**：所有结论必须有实际运行输出或 `file:line` 代码证据；严禁未执行即给结果。
2. **交叉验证**：代码 / 文档 / 外网三方交叉；不一致处**以实际代码为准**。
3. **删除**：一律 `/data/workspace/rm_tmp_file.sh <path...>`；**严禁** `rm`（含注释、含远端 ssh 命令串内）。
4. **杀进程**：一律 `/data/workspace/kill_process.sh <pid|name>`；**严禁** `kill`/`pkill`/`killall`。
5. **改权限**：一律 `/data/workspace/chmod_modify.sh <mode> <path...>`；**严禁** `chmod`；`make install` 类允许。
6. **编译**：每次改代码 **先 `make clean` 再完整编译**；增量编译通过不作为「编译通过」依据。
7. **注释**：`lib/` 只写非常必要的注释；严禁长篇大论、严禁给一看就懂的代码加注释。
8. **提交**：commit message 英文、1-3 句；`config.ini` 本地测试改动不入库（`git add` 前必 review `git diff`）。
9. **数据面零锁**：核心数据面路径永不加锁，也不尝试加锁方案。

---

## 6. 交付物

| 交付物 | 路径 |
|---|---|
| 本计划 | `docs/native_mt_spec/zh_cn/plan-16-多队列对照纠偏.md` |
| 本轮结论文档 | `docs/native_mt_spec/zh_cn/16-多队列对照实验与根因纠偏.md` |
| 15 号文档结论修订 | `docs/native_mt_spec/zh_cn/15-worker时钟缺口修复与virtio-RSS限制.md`（第 5/9 节加纠偏指针） |
| 代码修复 | `lib/`（视裁决而定） |
| 本地 commit | 英文 message 1-3 句 |
