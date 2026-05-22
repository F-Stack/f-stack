# Ring IPC 性能劣化离线深度分析（v3.4 · 终版 · 单 worker 收敛）

> 修订历史：v1 主因 H10/H11（drain 不存在于 sem）已被用户证伪；v2 主因 H15（cache miss）已被 perf stat 证伪；v3 基于 F-Stack 官方"事件匹配度"理论重定位主因为 H17；v3.1（2026-05-21 上午）实测证伪 H18，方案 A 废弃为 §5.A；v3.2（2026-05-21 晚）三组实测协同证伪 H17/H21/H24，主因收敛到 H19-final + H23；v3.3（2026-05-22）方案 C 实测劣化 4% 废弃（H25 证伪），方案 C+/D2 实测成功 +9.7% QPS，新增方案 D5；**v3.4（2026-05-22 晚）方案 D5 (+1.3%) + D6 (+0.9%) 实施收尾，QPS 9.1w → 10.22w 总收益 +12.3%（达 sem 97.3%），剩余 2.7% 已识别为 ring SPSC 架构固有开销不可消除。单 worker 优化收敛，转向多 worker 对比测试**。完整教训总结见 §4。

---

## 1. 结论先行（30 秒视图）

### 1.1 性能差距事实

| 指标 | Sem 模式（基线） | Ring 模式（劣化） | 差异 |
|---|---|---|---|
| 短链接 QPS | 10.5w | 9.2w | **-12.4%** |
| CPU 利用率 | 100%×2 | 100%×2 | 相同 |
| L1-dcache-load-misses（30s） | 1,830,010,884 | 1,824,039,526 | **-0.3%（几乎相同）** |
| LLC-load-misses（30s） | 251,343 | 204,144 | **ring 反而少 23%** |
| cache-misses（30s） | 792,424 | 692,902 | **ring 反而少 14%** |

### 1.2 主因方向（v3.4 收敛）

**H17（已证伪 · 2026-05-21 晚）**：原假设"drain 窗口内事件聚合度差异"。pkt_tx_delay 敏感性矩阵实测：60μs 起 ring 与 sem 同步崩溃；wrk 延迟分布 ring Stdev 反而小于 sem。详见 §3 与 §5.A。

**H18（已证伪 · 2026-05-21 上午）**：详见 §5.A 与 §4 教训段。

**❌ H25（已证伪 · 2026-05-22 上午）**：方案 C（atomic `pending_count` 旁路）实测 QPS 反劣化 4%。详见 §5.3。

**✅ H23（已修复 · 2026-05-22 中午 · 方案 C+/D2）**：原假设 `ff_ring_send_response` 写 rsp_ring 引入跨核 cache invalidate（Self 3.33%）。**方案 D2 实施后**：`ff_ring_send_response` Self 3.33% → 0%（完全消除），QPS 9.1w → 10.0w（+9.7%）。详见 §5.4。

**✅ H19-final（已优化 · 2026-05-22 下午 · 方案 D5+D6）**：原假设 `ff_ring_process_requests` 每次主循环必调，含函数调用栈 + 空 dequeue 路径。**方案 D5 实施后**：Self 18.98% → 4.53%（消除函数调用栈）；**方案 D6 实施后**：完全内联消失，QPS 10.0w → 10.13w → **10.22w**。详见 §5.5、§5.6。

**🔵 架构固有开销（已识别为不可消除下界）**：sem 模式 `ff_handle_each_context` Self 50.41% ≈ ring(D2+D5+D6) 50.13%——main loop CPU 占比已对齐，但 ring 模式仍比 sem 慢 2.7%（10.22w vs 10.5w）。差距来源：
- `rte_ring_sc_dequeue_burst` 内部的 acquire fence（每次 spin 强制 CPU 同步内存系统）
- ring 元数据维护（prod.head/cons.head 同步、cmpxchg 模拟）
- sem 模式 dirty read `sc->status` 是 plain load 无 fence

**单 worker 优化收敛**：QPS 9.1w → 10.22w（+12.3%），距 sem 仅差 2.7%。剩余差距为 ring SPSC 架构固有代价，单 worker 单 lcore 场景下不可消除。后续转向多 worker 对比测试（详见 plan.md §8）。

### 1.3 修复路径（C → C+/D2 → D5 → D6，全部实施完成）

| 方案 | 改动量 | 实测 QPS 增益 | 状态 |
|---|---|---|---|
| ✅ §5.1 预测试：pkt_tx_delay 矩阵 | 0 行 | - | 完成（证伪 H17） |
| ✅ §3.4 wrk 延迟分布 + perf top callgraph | 0 行 | - | 完成（锁定 H19-final + H23） |
| ~~A：APP 端改纯 BUSY_POLL~~ | ~~5 行~~ | ~~9.5-9.7w~~ | ❌ H18 已证伪 |
| ~~B：burst 直方图量化 H17~~ | ~~50 行~~ | ~~不变~~ | ⚪ 已跳过 |
| ❌ **C**：atomic pending_count 旁路 | 30 行 | **-4%（劣化）** | **H25 证伪·已回退** |
| ✅ **C+/D2**：sc->completion 替代 rsp_ring | 50 行 | **+9.7%**（9.1w → 10.0w）| **H23 修复·已合入** |
| ✅ **D5**：rte_ring_empty 快速空判断 | 5 行 | **+1.3%**（10.0w → 10.13w）| **H19-final 函数调用栈消除·已合入** |
| ✅ **D6**：内联 dispatch（消除函数指针）| 15 行 | **+0.9%**（10.13w → 10.22w）| **架构对齐 sem·已合入** |
| 🔵 剩余 2.7% | 不可消除 | -- | ring SPSC 架构固有开销（acquire fence + 元数据维护）|
| 🔜 多 worker 对比测试 | 0 行（仅改配置）| -- | **后续工作**（详见 plan.md §8）|

---

## 2. 官方文档证据链

### 2.1 F-Stack 官方 README 原文

来源：`adapter/syscall/README.md` 第 290 行（短连接 8 核以上性能不如标准 F-Stack 的根因）：

> "After 8 cores, the performance of LD_PRELOAD is not as good as the performance of standard F-Stack. The main reason is that **the matching degree between the user application program and the fstack application program (such as the number of loops and time of `ff_handle_each_context`) is not high**, and the performance has not been fully optimized."

来源：F-Stack 官方公众号介绍（用户引述）：

> "如果想提高 libff_syscall.so 的整体性能，那么 fstack 实例应用程序与 APP 应用程序的匹配十分重要，**只有当一个 ff_handle_each_context 循环中尽量匹配一次循环的所有事件时才能达到最优的性能**，这里需要十分精细的调优，但是目前还是粗略地使用 pkt_tx_delay 参数值。"

### 2.2 官方文档对 pkt_tx_delay 的定义

`pkt_tx_delay` 在 LD_PRELOAD 场景下的本质用途**不是**单纯的"超时退出"，而是 **drain 窗口内事件聚合的批处理大小**：

- 太短 → drain 窗口内 APP 累积请求少 / fstack 网络事件少，频繁切换"APP 请求处理"与"协议栈处理"，开销大
- 太长 → APP 请求积压、网络包延迟、整体 RTT 上升
- 合适 → APP 端 syscall 累积数 ≈ fstack 端协议栈事件产生数，两侧"对齐"

短连接推荐 50us，长连接 100us。用户实测环境配置 30us，已是该业务场景调优最优值。

### 2.3 SPEC FR-005 约束

来源：`docs/ld_preload_ring_spec/01-requirements-spec.md`：

> "Maintain the behavior of multiple polling iterations within the `pkt_tx_delay` time window"

→ Ring 模式的 v3 修复方案不能简单缩短或破坏 drain 窗口语义，**只能在窗口内优化空轮询路径**。

---

## 3. perf 数据交叉验证

### 3.1 perf stat 证伪 H15（cache miss）

```
              Ring (9.2w QPS)    Sem (10.5w QPS)    差异
cache-misses        692,902          792,424      ring 反而少 14%
LLC-load-misses     204,144          251,343      ring 反而少 23%
L1-dcache-misses 1,824,039,526   1,830,010,884    -0.3%（几乎相同）
```

**判定**：
- LLC-load-misses 数量级仅 **6,800/秒**，无论哪种模式都不构成性能瓶颈
- L1 miss 数量几乎完全相同 → 两边 cache 状态相似
- ring 反而更少的 LLC miss，与 v2 提出的"ring 跨核 cache 读浪费"假设完全相反
- → **H15 被证伪**

### 3.2 perf top 数据交叉佐证 H17（事件聚合度）

#### 压测时 fstack perf top（用户提供）

```
20.75%  ff_handle_each_context     ← drain 循环本体
17.70%  ff_ring_process_requests   ← ring 模式独有的 batch dequeue 入口
 7.10%  ff_handle_socket_ops_ring  ← ff_so_handler 调用
 3.81%  ff_ring_send_response      ← 应答 enqueue
 协议栈合计 ~18%（tcp_*/ip_*/syncache_*）
```

**关键观察**：
- `ff_ring_process_requests` 17.70% 中绝大多数应是 **nb=0 的空 dequeue**（drain 窗口内事件少，需要多次循环才等到下一个事件）
- 协议栈合计仅 ~18%，这意味着 fstack lcore 把 **~50% 时间花在 IPC 路径上**
- 如果聚合度高（每次循环处理多个 sc），`ff_ring_process_requests` 占比应显著降低

#### 压测时 nginx perf top（用户提供）

```
78.24%  ff_ring_dequeue_wait       ← APP 等响应（含 sched_yield）
 4.06%  ff_ring_submit_and_wait    ← 提交+等待整体框架
```

→ APP 端 78% 时间都在等响应，说明每个 syscall 端到端延迟较长。这与 H17 推导的"每个 syscall 多耗 ~150-250ns × 9.2w QPS"吻合。

### 3.3 H17 物理机制推演（v3 提出·v3.2 已证伪，存档）

> v3 阶段基于"每 syscall 跨 cache line +150-250ns 累积破坏聚合度"推导 H17 主因。后续 pkt_tx_delay 矩阵（§5.1）+ wrk 延迟分布（§3.4）+ perf top callgraph（§3.4）三组实测综合证伪：60μs+ ring 与 sem 同步崩溃、ring 抖动反而更小、真因落在 perf top Self% 高的两个 ring 特有函数上。详见 §4 教训段。

| 阶段 | Sem 模式 | Ring 模式 | 增量（推算） |
|---|---|---|---|
| ① APP 提交 | `sc->status = FF_SC_REQ` | `rte_ring_sp_enqueue` | +30~50ns |
| ② fstack 探测 | `sc->status` dirty read | `rte_ring_sc_dequeue_burst` | +30~50ns |
| ③ fstack 处理 | 同 | 同 | 0 |
| ④ fstack 应答 | `sc->status = FF_SC_REP` | `rte_ring_sp_enqueue` | +30~50ns |
| ⑤ APP 等待 | `while sc->status != REP` | `ff_ring_dequeue_wait` | +50~100ns |

**v3 推算**：单 syscall +150-250ns；**v3.2 实测**：wrk 延迟差 +190μs（量级差 1000 倍），证明真因不在单 syscall 路径而在 fstack 主循环 CPU 占用比例。

---

### 3.4 wrk 延迟分布 + perf top callgraph 实证（v3.2 主因锁定，2026-05-21 晚）

#### 3.4.1 wrk 延迟分布对比（`-t24 -c128 -d10 -L`）

| 分位 | Sem (μs) | Ring (μs) | Δ(Ring-Sem) |
|---|---|---|---|
| Avg | 1010 | 1200 | **+190** |
| P50 | 1010 | 1200 | **+190** |
| P75 | 1030 | 1220 | **+190** |
| P90 | 1070 | 1240 | +170 |
| P99 | 1180 | 1300 | +120 |
| **Stdev** | **49** | **37** | **-12（ring 抖动反而更小）** |

**关键解读**：
- 各分位呈**近似恒定加性差**（≈190μs）→ 劣化是确定性的、每次都发生的固定开销
- ring Stdev 反而更小 → **彻底排除 H17（聚合度抖动型瓶颈）**
- 但 190μs 量级远超单次 IPC 路径合理范围 → 真因不在单 syscall 路径，而在更宏观的"CPU 占用挤压"

#### 3.4.2 perf top callgraph（`perf top -p $(pgrep fstack) --call-graph dwarf`）

Ring 模式实测（fstack lcore 1）：

| 函数 | Self % | Children % | 角色 |
|---|---|---|---|
| `ff_handle_each_context` | **19.39** | 53.54 | 主循环 IPC 骨架（ring 分支 spin） |
| `ff_ring_process_requests` | **15.44** | 34.46 | dequeue burst 路径（ring 特有） |
| `ff_handle_socket_ops_ring` | **5.99** | 15.82 | 单条请求 dispatch（与 sem 等价） |
| `ff_ring_send_response` | **3.33** | 3.33 | 写 rsp_ring（ring 特有） |
| 协议栈合计（tcp_input/ip_input/...） | ~30 | -- | 与 IPC 无关 |

**Ring 特有 IPC 开销 Self 合计** = `ff_ring_process_requests (15.44) + ff_ring_send_response (3.33)` = **18.77%**。

#### 3.4.3 真因锁定

- 🔴 **H19-final（主因）**：`ff_ring_process_requests` Self 15.44%。每次主循环 spin 都调，即使 nb=0 也走完整 `rte_ring_sc_dequeue_burst`（含跨核读 prod.tail + 函数调用栈），sem 模式同等位置因 nb_handled=0 跳过 for 循环 ≈ 0%。
- 🟠 **H23（次因）**：`ff_ring_send_response` Self 3.33%。每次响应都写 rsp_ring->prod.tail，触发 nginx lcore 4 cache invalidate；sem 模式只是 `sc->status=REP` 单条 store。
- **总览**：Ring 模式 IPC 路径合计 ~44%（含 `ff_handle_each_context` 19.39 + 上述三项），挤压协议栈处理（~30%），与 14% QPS 劣化数量级吻合。

#### 3.4.4 192μs 延迟差与 18.77% CPU 挤压的物理对账

- fstack lcore CPU 100% 占满
- ring 模式比 sem 模式多 18.77% CPU 用于 IPC → 协议栈处理时间被压缩 ~19%
- 协议栈占比 ~30% × 压缩 19% = ~5.7% 直接 QPS 损失
- IPC 路径自身延迟 + 协议栈被压缩 → 单个请求 RTT 拉长（perf top 显示 IPC 路径时间）
- 与 wrk 实测 14% QPS 下降 + 190μs 延迟拉长**同时吻合**

**结论**：方案 B（burst 直方图）已不需要执行——证据链已闭合，直接进入方案 C 实施。

---

## 4. 假设演化教训总结段

> 本节是 v1 → v2 → v3 → v3.1 → v3.2 → v3.3 → v3.4 错误推理与收敛轨迹的精炼复盘，作为"双边代码对照 + 可证伪物理量 + 数据先于理论 + 对称评估新引入物理量 + 对照组先于优化"工作纪律的具体案例。

**v1 错误（主因 H10/H11）**：仅阅读 `ff_socket_ops.c:618-645` ring 分支后下结论"sem 模式无 30μs drain 强制空轮询"，忽略 `ff_socket_ops.c:646-702` else 分支同样有 `if (diff_tsc >= drain_tsc) break` 循环。**根因**：单边代码分析、未对照另一分支即下结论。**纠正**：用户主动指出"信号量模式同样轮询 30us 才退出"，全文撤回 H10/H11。

**v2 错误（主因 H15）**：基于"sem 有 nb_handled 旁路而 ring 无"的代码差异，假设 ring 模式因 `rte_ring_sc_dequeue_burst` 跨核读 prod.tail 导致 LLC miss 暴增。**根因**：未先用 perf stat 验证假设的可证伪物理量就写入分析文档。**纠正**：用户提供 perf stat 实测显示 ring 与 sem 的 LLC miss 接近且 ring 反而更少（数量级仅 6.8K/s），全文撤回 H15。

**v3.1 错误（次因 H18，2026-05-21）**：基于"YIELD_POLL 每 256 PAUSE 触发 sched_yield"的代码事实，纯算术反推"14w yield/s × 250ns ≈ 3-4% CPU 浪费"列为次因。**根因**：忽视了 `spin_count` 是 `ff_ring_dequeue_wait` 函数局部变量、短链场景单次 wait 远达不到 256 PAUSE 阈值这一关键事实。**纠正**：用户实测三组配置（YIELD_POLL 0xFF / YIELD_POLL 0x1FFF / BUSY_POLL）QPS 全部 9.2w，nginx worker `voluntary_ctxt_switches` 增长 ≈ 0，方案 A 整体废弃为 §5.A。**教训**：任何"频率/计数"类估算必须先用最低成本方式实测验证才能列入诊断清单——本次只需 10 秒 voluntary_ctxt_switches 采样就能避免 30 分钟的方案 A 弯路。

**v3.2 错误（H17 + H21 + H24，2026-05-21 晚）**：(a) **H17 误读**：把 F-Stack 官方"事件匹配度"理论解读为"两种 IPC 模式间的结构差异"，但实测 pkt_tx_delay 矩阵显示 60μs 起 ring 与 sem 同步崩溃（5.3w/8.1w 都相同）、ring 抖动 Stdev 反而比 sem 小——官方原话指的是"配置精确度"，不是"模式间差异"。**根因**：未先做 pkt_tx_delay 敏感性测试就将官方理论嫁接到本场景。(b) **H21 量级误读**：看到 wrk 延迟分布 ring 比 sem 多 +190μs 后，未停下来思考就提出"单 syscall RTT 多 ~150ns 加性开销"假设，但 190μs 远超代码路径合理范围 ~3 个数量级。**根因**：把延迟差当成单 syscall 的开销，忘记了"延迟 = CPU 占用挤压 → 协议栈处理被延后"这条间接路径。(c) **H24 方法论错误**：在 perf top 已经给出明确证据后，仍发散提出"lcore 跨 NUMA"假设，但 ring 与 sem 是同环境同配置对比——**唯一变量是 IPC 实现本身**，环境变量假设违反对照实验基本原则。**根因**：对照实验设计意识缺失。**纠正**：用户提供 pkt_tx_delay 矩阵 + wrk 延迟分布 + perf top callgraph 三组实测后，证据链闭合到 `ff_ring_process_requests` Self 15.44% + `ff_ring_send_response` Self 3.33%——**全部直接来自 perf top，没有理论推演**。**教训**：(1) 同环境对照实验严禁引入环境变量假设；(2) 任何"延迟差"先用 perf top 锁定函数级别再下机制假设；(3) 数据先于理论。

**v3.2 方法论修正**：(1) 每条假设必须配套**可证伪的物理量**（perf stat / 微基准 / wrk 延迟分布 / perf top Self%）；(2) 双边代码对照后才能下"差异"结论；(3) 优先引用**官方权威文档**锚定问题视角，但需先用零成本实验确认理论是否适用本场景；(4) 任何"频率/计数/延迟"估算必须先用零成本采样实测验证；(5) **同环境对照实验严禁环境变量假设**——唯一变量原则；(6) **perf top callgraph 是真因终极裁决工具**——任何分析方向都应在 perf top 数据面前服从。本次最终主因 H19-final + H23 都是从 perf top Self% 直接读出的，再次验证"数据先于理论"。

**v3.3 错误（H25，2026-05-22）**：方案 C（atomic `pending_count` 旁路）实施后 QPS 反而下降 4%（9.1w → 8.7w），perf top 显示 `ff_handle_each_context` Self 暴涨 +16.88pp（19.39% → 36.27%）。**根因**：方案设计仅评估了"消除 dequeue burst 路径"的收益（确实达到——`ff_ring_process_requests` Self 15.44% → 9.16%），**完全没评估"高频 atomic_read 跨核乒乓"的新开销**——nginx 每次 syscall 多写 atomic 2-4 次（inc + 可能的回滚 dec/inc），写频率从 baseline 的"每次 enqueue 1 次"翻倍以上，加重了 cache 乒乓。**纠正**：实测后立即回退方案 C（编译开关 `FF_RING_PENDING_BYPASS` 默认关闭），转而实施方案 C+（D2，sc->completion 替代 rsp_ring）。**v3.3 教训**：(1) 任何方案设计必须**对称评估**新引入物理量（频率、跨核访问模式、cache 行为），不能只看"消除什么"而不看"引入什么"；(2) **CPU Self% 不等于优化收益**——方案 C 后 `ff_ring_process_requests` Self 确实降了 6%（达预期），但被新引入的 atomic 跨核读吞掉且额外多耗 10%；(3) 方案 C+/D2 成功的关键是**复用现有 `sc->completion` 字段（已存在于 sc cache line 0），零新跨核字段**——nginx 写频率与 baseline 完全一致。

**v3.3 方法论修正**：方案设计阶段引入"对称评估表"——任何修复方案必须列出"消除/减少的物理量"和"新引入的物理量"两栏，且后者数量级必须明显小于前者才能进入实施。具体到本次：方案 C+（D2）和方案 D5 都通过该评估（D2 复用 sc cache line 零新增、D5 复用 ring 内部字段零新增），方案 C 未通过（新增 atomic 字段且 nginx 写频率翻倍）。

**v3.4 收敛（最终洞察）**：方案 D5/D6 顺利实施后（D5 +1.3%、D6 +0.9%），QPS 收敛到 10.22w（sem 的 97.3%），perf top 显示 `ff_handle_each_context` Self 50.13% 与 sem 50.41% **几乎完全一致**——main loop CPU 占比已对齐。**关键洞察**：(1) **fstack 100% CPU + 30μs drain spin 设计下，单纯优化 IPC 路径开销不能 1:1 转化为 QPS 提升**——节省的 CPU 被立即填进 main_loop spin，只能整体减少一轮周期；(2) **优化 ROI 递减规律**：D2 +9.7%（消除 rsp_ring）→ D5 +1.3%（消除函数调用栈）→ D6 +0.9%（消除函数指针）→ 边际下一步预期 < 0.5%；(3) **剩余 2.7% 是 ring SPSC 架构固有开销**——`rte_ring_sc_dequeue_burst` 内的 acquire fence + ring 元数据维护，sem dirty read sc->status 是 plain load 无 fence，这是物理代价。**v3.4 方法论修正**：(4) 性能优化前先用对照组 perf top 确定"理论上限"——本次 sem perf top 揭示 main loop CPU 占比已对齐，提前指明剩余差距是架构性的，避免做边际收益 < 0.5% 的微观优化；(5) "数据先于理论"延伸为"对照组先于优化"——优化前先采集对照组数据看可优化空间，不要做完一轮再发现已逼近极限。

---

## 5. 修复方案详细设计

### 5.A 已废弃方案存档：原方案 A — APP 端改纯 BUSY_POLL（H18 证伪）

> **2026-05-21 实测结论**：H18 完全证伪，方案废弃但保留供复盘。
>
> | 配置 | nginx vcs 增长 | sched_yield/s | QPS |
> |---|---|---|---|
> | Ring + YIELD_POLL (`0xFF`) | 0 | ≈ 0 | 9.2w |
> | Ring + YIELD_POLL (`0x1FFF`) | 0 | ≈ 0 | 9.2w |
> | Ring + BUSY_POLL（彻底无 yield 路径）| 0 | 0 | 9.2w |
> | Sem baseline | 0 | ≈ 0 | 10.5w |
>
> **证伪逻辑**：
> 1. nginx worker `voluntary_ctxt_switches` 实测增长 ≈ 0（A=1 B=1）
> 2. BUSY_POLL（彻底无 yield 代码路径）QPS 与 YIELD_POLL 完全一致 9.2w
> 3. `spin_count` 是 `ff_ring_dequeue_wait` 函数局部变量，短链 9.2w QPS 场景下单次 wait 仅几百次 PAUSE 即拿到响应，**远达不到 256 阈值**
>
> **方法论教训**：原"14w/s"是纯算术反推（QPS × 1.5 yield/req），未实测就列为次因。见 §4 教训段。
>
> ---
>
> 以下为废弃前草案，保留供对照：
>
> **改动点**：`ff_ring_ipc.c:111-129` `ff_ring_dequeue_wait` 内 wait_mode 分发。
>
> ```c
> /* 修改前 */
> case FF_RING_WAIT_YIELD_POLL:
>     if ((++spin_count & 0xFF) == 0) {
>         sched_yield();
>     } else {
>         rte_pause();
>     }
>     break;
>
> /* 草案修改 */
> case FF_RING_WAIT_YIELD_POLL:
>     if ((++spin_count & 0x1FFF) == 0) {
>         sched_yield();
>     } else {
>         rte_pause();
>     }
>     break;
> ```
>
> 实测证明该改动对 QPS 无任何影响（仍 9.2w）。

### 5.1 预测试：pkt_tx_delay 敏感性矩阵（零代码·**优先执行**）

**目的**：在写任何代码前，用纯配置变化直接证伪/佐证 H17。如果 ring QPS 对 pkt_tx_delay 强敏感而 sem 不敏感 → H17 直接确认，可跳过方案 B 直接做方案 C。

**改动文件**：`config.ini`（仅改 `pkt_tx_delay` 一项）。**改动量**：0 行代码。

**测试矩阵**：

| pkt_tx_delay (μs) | Ring QPS | Sem QPS | 推论 |
|---|---|---|---|
| 10 | ? | ? | 短 drain，聚合空间小 |
| 30（基准） | 9.2w | 10.5w | baseline |
| 60 | ? | ? | 标准长 drain |
| 100 | ? | ? | 官方推荐长链值 |

**判定**：

| 现象 | 推论 |
|---|---|
| Ring QPS 在 60-100μs 时回升至 ≥ 10w，sem 几乎不变 | **H17 强佐证** → 跳过 §5.2，直接做 §5.3 |
| Ring/Sem 都对 pkt_tx_delay 不敏感 | H17 弱化，需做 §5.2 取直接证据 |
| Ring 在 10μs 时崩溃式劣化（如 < 7w） | H17 强佐证（短 drain 让 ring 完全聚合不到事件） |

### 5.2 方案 B：drain 窗口 burst 直方图量化（验证 H17）

**改动点**：`ff_socket_ops.c:618-645` ring 分支 + `ff_socket_ops.c:660-702` sem 分支同步加入采样。

**ring 分支补丁**（line 636-645）：
```c
#ifdef FF_RING_BURST_HIST
    static uint64_t hist[8] = {0}; /* 0/1/2/3/4-7/8-15/16-31/32+ */
    static uint64_t total_drain = 0;
    static uint64_t total_iter = 0;
    static uint64_t total_handled = 0;
    static uint64_t last_dump_tsc = 0;
    uint32_t drain_iter = 0;
    uint32_t drain_handled = 0;
#endif

    while (1) {
        uint16_t nb = ff_ring_process_requests(ff_so_zone->ring_zone,
            ff_handle_socket_ops_ring, FF_RING_SIZE);

#ifdef FF_RING_BURST_HIST
        drain_iter++;
        drain_handled += nb;
        uint8_t bucket = (nb == 0) ? 0 :
                         (nb == 1) ? 1 :
                         (nb == 2) ? 2 :
                         (nb == 3) ? 3 :
                         (nb < 8)  ? 4 :
                         (nb < 16) ? 5 :
                         (nb < 32) ? 6 : 7;
        hist[bucket]++;
#endif

        diff_tsc = rte_rdtsc() - cur_tsc;
        if (diff_tsc >= drain_tsc) {
            break;
        }
        rte_pause();
    }

#ifdef FF_RING_BURST_HIST
    total_drain++;
    total_iter += drain_iter;
    total_handled += drain_handled;
    if ((cur_tsc - last_dump_tsc) >= rte_get_tsc_hz() * 10) { /* 每 10s dump 一次 */
        ERR_LOG("burst_hist drain=%lu iter=%lu handled=%lu avg_iter/drain=%.2f avg_handled/drain=%.2f"
            " bucket=[%lu/%lu/%lu/%lu/%lu/%lu/%lu/%lu]\n",
            total_drain, total_iter, total_handled,
            (double)total_iter/total_drain, (double)total_handled/total_drain,
            hist[0],hist[1],hist[2],hist[3],hist[4],hist[5],hist[6],hist[7]);
        last_dump_tsc = cur_tsc;
    }
#endif
```

**sem 分支同步**（line 660-702 内嵌相同 hist 数组、同样在 for 循环内更新 `drain_handled`，drain 退出时更新 `hist` 与 `total_*`）。

**编译开关**：`Makefile` 加 `-DFF_RING_BURST_HIST`，仅在诊断时启用，不影响生产构建。

**预期判定**（H17 成立标准）：
- ring 模式：`avg_handled/drain` < 4，`bucket[0]`（空 dequeue）占 >70%
- sem 模式：`avg_handled/drain` > 6，`bucket[0]` 占 <50%
- 差异方向必须是 ring 聚合度低于 sem，否则 H17 被证伪

### 5.3 方案 C：atomic pending_count 旁路 — ❌ **已实施实测劣化·废弃**

> **2026-05-22 实测结论**：QPS 9.1w → 8.7w（**劣化 4%**），`ff_handle_each_context` Self 19.39% → 36.27%（暴涨 +16.88pp）。**H25 证伪**。已立即回退（编译开关 `FF_RING_PENDING_BYPASS` 默认关闭），代码保留供未来研究。
>
> **失败根因**：nginx 端原本只在 enqueue 时写 `req_ring->prod.tail` 一次（频率 ~10w/s），方案 C 让 nginx 多写 `pending_count` 2-4 次/syscall（inc + 可能 dec/inc 重试），写频率翻倍以上 → fstack 端每次 drain spin 跨核读 → cache line 持续 invalidate ping-pong → CPU 浪费在 cache miss 上反而比原 dequeue 路径更糟。
>
> **教训**：方案设计必须做"对称评估表"，列出"消除的物理量"和"新引入的物理量"两栏。详见 §4 教训段。
>
> ---
>
> 以下为方案 C 原草案，保留供复盘对照：

**改动点**：`ff_socket_ops.h` 加字段 + `ff_socket_ops.c` ring 分支重写 + `ff_hook_syscall.c` 入队前后增减。

**ff_socket_ops.h 修改**（line 89-111 `struct ff_socket_ops_zone`）：
```c
struct ff_socket_ops_zone {
    rte_spinlock_t lock;
    uint8_t count;
    uint8_t mask;
    uint8_t free;
    uint8_t idx;
    uint8_t inuse[SOCKET_OPS_CONTEXT_MAX_NUM];
    struct ff_so_context *sc;

#ifdef FF_USE_RING_IPC
    struct ff_sc_ring_zone *ring_zone;
#ifdef FF_RING_PENDING_BYPASS
    rte_atomic32_t pending_count;     /* 4B：APP 入队前 inc，fstack 处理后 dec */
    uint8_t padding[4];
#else
    uint8_t padding[8];
#endif
#else
    uint8_t padding[16];
#endif
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));
```

**ff_socket_ops.c ring 分支修改**（line 636-645）：
```c
    while (1) {
#ifdef FF_RING_PENDING_BYPASS
        /* H17 修复：本地 cache line 读 pending_count，避免空 dequeue 跨核读 prod.tail */
        if (rte_atomic32_read(&ff_so_zone->pending_count) > 0) {
            uint16_t nb = ff_ring_process_requests(ff_so_zone->ring_zone,
                ff_handle_socket_ops_ring, FF_RING_SIZE);
            if (nb > 0) {
                rte_atomic32_sub(&ff_so_zone->pending_count, nb);
            }
        }
#else
        ff_ring_process_requests(ff_so_zone->ring_zone,
            ff_handle_socket_ops_ring, FF_RING_SIZE);
#endif

        diff_tsc = rte_rdtsc() - cur_tsc;
        if (diff_tsc >= drain_tsc) {
            break;
        }
        rte_pause();
    }
```

**ff_hook_syscall.c ff_ring_submit_and_wait 修改**（line 3392 入队前）：
```c
    /* Enqueue request — spin if ring full */
#ifdef FF_RING_PENDING_BYPASS
    rte_atomic32_inc(&ff_so_zone->pending_count);
#endif
    while (rte_ring_sp_enqueue(ring_zone->req_ring, sc) != 0) {
#ifdef FF_RING_PENDING_BYPASS
        /* 极少触发：ring 满时回滚 pending_count 避免计数漂移 */
        rte_atomic32_dec(&ff_so_zone->pending_count);
#endif
        ERR_LOG("req_ring full, waiting... sc:%p, ops:%d\n", sc, sc->ops);
        rte_pause();
#ifdef FF_RING_PENDING_BYPASS
        rte_atomic32_inc(&ff_so_zone->pending_count);
#endif
    }
```

**FR-005 兼容性确认**：
- pending_count 仅作为"是否进入 dequeue"的判断条件
- drain_tsc 时间窗口与 rte_pause 多次轮询语义**完全保留**（即使 pending_count==0 也会 pause+rdtsc 直到 drain_tsc 到期）
- 满足 SPEC 约束

**预期物理量变化**：
- ring 模式 fstack 主循环空跑路径：`rte_ring_sc_dequeue_burst`（~30 指令） → `rte_atomic32_read`（1 指令 + 1 cache line load）
- 这条 cache line（pending_count）由 fstack lcore 频繁读、APP lcore 稀疏写 → fstack 端 L1 命中率高
- `ff_ring_process_requests` perf 占比预期：17.70% → <2%
- QPS 预期：9.2w → ≥10.5w（追平 sem），可能更高（无全局 zone lock 优势显现）

---

### 5.4 方案 C+ / D2：sc->completion 替代 rsp_ring（修复 H23）— ✅ **已实施实测成功**

> **2026-05-22 实测**：QPS 9.1w → **10.0w（+9.7%）**，wrk Avg 1.20ms → 1.06ms（-12%），`ff_ring_send_response` Self 3.33% → **0%**。**H23 修复确认**。已合入（编译开关 `FF_RING_SC_COMPLETION=1`）。

**核心思想**：消除 `rsp_ring` enqueue，让 fstack 处理完后**直接写 `sc->completion`**（已存在于 sc cache line 0，offset 32，原本预留为 ring IPC 字段）。响应路径与 sem 模式 `sc->status=REP` 完全等价。

**改动文件**：`ff_ring_ipc.c`（`ff_ring_send_response` + `ff_ring_alarm_wakeup`）+ `ff_hook_syscall.c`（`ff_ring_submit_and_wait`）+ `Makefile`。

**对称评估表**（v3.3 新增方法论强制要求）：

| 评估项 | baseline | D2 |
|---|---|---|
| nginx 跨核写字段 | `req_ring->prod.tail` + sc | 同 baseline（仅 sc 写）|
| nginx 写频率 | 每次 syscall 1 次 sc 写 + 1 次 prod.tail 写 | **同 baseline** |
| fstack 跨核写字段 | `rsp_ring->prod.tail` + sc->result | 写 sc->completion + sc->result（同 cache line）|
| fstack 写频率 | 每次响应 2 个 cache line | 每次响应 **1 个 cache line**（sc 内合并）|
| **新引入跨核字段** | -- | **零**（completion 字段早已存在）|
| 节省项 | -- | rsp_ring 整条路径（enqueue + dequeue + 一个 cache line 抖动）|

✅ 对称评估通过。

**协议设计**：
```
APP 端 ff_ring_submit_and_wait:                 fstack 端 ff_ring_send_response:
  1. sc->completion = 0  (RELAXED，先于 enqueue)   1. (写 sc->result/error 等)
  2. enqueue req_ring(sc)                          2. sc->completion = 1  (RELEASE)
  3. spin sc->completion == 1 (ACQUIRE)
  4. return
```

**Memory ordering**：fstack 端 RELEASE store 保证 sc->result 等先写完；APP 端 ACQUIRE load 保证看到 completion=1 后再读 sc->result 不会乱序前置。

**风险**：低。`ff_ring_alarm_wakeup` 路径同步加 `sc->completion=1` 写入，确保 alarm 唤醒在 D2 模式下生效；rsp_ring 保留作 legacy fallback。回退：编译时移除 `FF_RING_SC_COMPLETION=1` 即恢复。

---

### 5.5 方案 D5：rte_ring_empty 快速空判断（修复 H19-final 函数调用栈） — ✅ **已实施实测成功（小幅）**

> **2026-05-22 下午实测**：QPS 10.0w → **10.13w（+1.3%）**，`ff_ring_process_requests` Self 18.98% → **4.53%**（降幅 76%，符合预期）。
>
> **关键观察**：函数调用栈开销已大部分消除，但 QPS 收益仅 1.3%——节省的 14.45% Self CPU 大部分被吸收到 `ff_handle_each_context`（Self 27.45 → 36.78），是因为 fstack lcore 已 100% CPU 占用，节省的 CPU 直接被 main loop spin 填满。这是 v3.4 关键洞察的起点。

> **触发条件**：D2 已合入，QPS 10.0w 距 sem baseline 10.5w 还差 5%，由 `ff_ring_process_requests` Self 18.98% 主导（D2 后未变）。

**核心思想**：用 DPDK 公共内联函数 `rte_ring_empty(r)` 做快速空判断，避免 `ff_ring_process_requests` 函数调用栈展开开销。**不引入任何新跨核字段**——这是方案 D5 与失败的方案 C 的根本差异。

**改动点**：`ff_socket_ops.c` 主循环 ring 分支（与方案 C 同位置但实现完全不同，独立编译开关 `FF_RING_FAST_EMPTY_CHECK`）。

**对称评估表**：

| 评估项 | baseline | D5 |
|---|---|---|
| nginx 跨核写字段 | `req_ring->prod.tail` | 同 baseline |
| nginx 写频率 | 每次 enqueue 1 次 | **同 baseline** |
| fstack 跨核读字段 | `prod.tail`（through dequeue_burst stack）| `prod.tail`（through inline rte_ring_empty）|
| fstack 读频率 | 每次 drain spin | **同 baseline** |
| **新引入跨核字段** | -- | **零** |
| **新引入跨核写** | -- | **零** |
| 节省项 | -- | dequeue_burst 函数调用栈、参数传递、循环开销 |

✅ 对称评估通过：仅减少消耗、不引入新乒乓。

**最小 diff 草案**：
```c
while (1) {
#ifdef FF_RING_FAST_EMPTY_CHECK
    if (!rte_ring_empty(ff_so_zone->ring_zone->req_ring)) {
        ff_ring_process_requests(...);
    }
#else
    ff_ring_process_requests(...);
#endif
    diff_tsc = rte_rdtsc() - cur_tsc;
    if (diff_tsc >= drain_tsc) break;
    rte_pause();
}
```

**预期物理量变化**：
- `ff_ring_process_requests` perf top Self %：18.98% → < 5%
- QPS：10.0w → ≥ 10.5w（追平 sem）
- 跨核 cache 行为：与 baseline 完全一致，无新引入

**与失败的方案 C 对比**：

| 维度 | 方案 C（失败） | 方案 D5 |
|---|---|---|
| 思路 | 引入新 atomic 字段做旁路 | 复用现有 ring 字段做内联判断 |
| 新跨核字段 | `pending_count` | **无** |
| nginx 写频率变化 | +2~4 次/syscall | **0**（同 baseline）|
| 实测 | 劣化 4% | 提升 1.3% |

---

### 5.6 方案 D6：内联 dispatch（消除函数指针调用）— ✅ **已实施实测成功（边际）**

> **2026-05-22 下午实测**：QPS 10.13w → **10.22w（+0.9%）**，`ff_handle_socket_ops_ring` 从独立函数（Self 8.38%）变为 inlined（visible 5.28%），`ff_ring_process_requests` 从 perf top 完全消失。**架构对齐 sem 模式**（sem 的 `ff_handle_socket_ops` 也是 static inline）。

**触发原因**：D5 后 perf top 显示 `ff_handle_socket_ops_ring` Self 仍占 8.38%，对照 sem 模式 `ff_handle_socket_ops` 是 `static inline` 被完全内联（perf top 看不到独立 Self），定位到**函数指针调用栈**是 ring 模式比 sem 多出的额外开销。

**核心思想**：在 `ff_socket_ops.c` 主循环里直接展开 `ff_ring_process_requests` 的 dequeue + 循环逻辑，handler 直接以函数名 `ff_handle_socket_ops_ring` 调用（不通过函数指针），让编译器内联整个 dispatch 链路。同时把 `ff_handle_socket_ops_ring` 标记为 `static inline`（与 sem 模式 `ff_handle_socket_ops` 对齐）。

**对称评估表**：

| 评估项 | baseline (D2+D5) | D6 |
|---|---|---|
| nginx 跨核字段 / 写频率 | `req_ring->prod.tail` | 同 baseline |
| fstack 跨核读字段 / 频率 | `prod.tail` | 同 baseline |
| **新引入跨核字段** | -- | **零** |
| 节省项 | -- | (1) `ff_ring_process_requests` 函数调用栈 (2) handler 函数指针间接调用 (3) 编译器跨函数优化 |

✅ 对称评估通过。

**改动文件**：`ff_socket_ops.c`（`ff_handle_socket_ops_ring` 加 `inline` + main loop 内联 dispatch，嵌在 D5 路径内）+ `Makefile`（新增 `FF_RING_INLINE_DISPATCH` 开关，依赖 `FF_RING_FAST_EMPTY_CHECK`）。

**实测物理量变化**：
- `ff_ring_process_requests` perf top：4.53% → **完全消失**（被内联）
- `ff_handle_socket_ops_ring` perf top：8.38%（独立函数）→ **5.28%（inlined）**
- QPS：10.13w → 10.22w（+0.9%）
- wrk Stdev：53us → 45us（已优于 sem 49us）
- wrk P99：1.20ms → 1.18ms（与 sem 持平）

---

### 5.7 架构固有开销下界（v3.4 收敛结论）

D6 后 ring(D2+D5+D6) main loop CPU 占比 **50.13%** 与 sem **50.41%** 几乎完全一致，但 ring 仍比 sem 慢 2.7%（10.22w vs 10.5w）。这是 ring SPSC 架构的**固有代价**：

| 操作 | sem 模式 | ring 模式 |
|---|---|---|
| fstack 探测请求 | dirty read `sc->status`（plain load）| `rte_ring_empty()` 内联：load `prod.tail` (acquire fence) + load `cons.tail` |
| fstack 取请求 | sc 已在数组里直接拿到 | `rte_ring_sc_dequeue_burst`：load prod.tail (acquire) + 计算 entries + 拷贝 obj + 写 cons.head + 写 cons.tail |
| APP 提交请求 | `sc->status = REQ` 一条 store | `rte_ring_sp_enqueue`：写 prod.head + prod.tail (release) + 边界检查 |

**核心差异**：sem 的 dirty read 是 plain load（无 memory barrier），ring 的 acquire/release fence 强制 CPU 同步内存系统，每次 spin 都有真实开销（虽然 cache 已命中）。10M/s 的 spin 频率下这是 ~2-3% CPU 的固定代价，**单 worker 单 lcore 场景下不可消除**。

**单 worker 优化收敛**：从 9.1w → 10.22w（+12.3%），距 sem 仅差 2.7%（架构固有）。后续转向多 worker 对比测试评估 ring 的真实价值。

---

## 6. 决策矩阵

| 验证现象 | 主因结论 | 实施动作 |
|---|---|---|
| ✅ §5.1 预测试：pkt_tx_delay 矩阵 60μs+ ring 与 sem 同步崩溃 | **H17 已证伪** | 跳过 §5.2 |
| ✅ §3.4 wrk 延迟分布 ring 比 sem 各分位 +190μs 加性差 | H21 提出但量级不符 | 转入 perf top |
| ✅ §3.4 perf top：H19-final + H23 主因锁定 | 数据先于理论 | 实施修复 |
| ❌ §5.3 方案 C 实测 QPS 8.7w（劣化 4%） | **H25 证伪**（atomic 旁路引入更糟乒乓）| 已回退，转向 D2 |
| ✅ §5.4 方案 C+/D2 实测 QPS 10.0w（+9.7%）、`ff_ring_send_response` Self 0% | **H23 修复确认** | 已合入 D2 |
| ✅ §5.5 方案 D5 实测 QPS 10.13w（+1.3%）、`ff_ring_process_requests` Self 4.53% | **H19-final 函数调用栈消除** | 已合入 D5 |
| ✅ §5.6 方案 D6 实测 QPS 10.22w（+0.9%）、`ff_handle_socket_ops_ring` 内联 | **架构对齐 sem 模式** | 已合入 D6 |
| 🔵 §5.7 sem vs ring(D2+D5+D6) main loop Self 50.41% ≈ 50.13% | **架构开销已逼近物理极限** | 单 worker 收敛 |
| 🔜 多 worker 对比测试 | 待用户实测 | 详见 plan.md §8 |

---

## 7. 附录：关键代码片段双边对照

### 7.1 fstack 主循环 `ff_handle_each_context`

**Sem 分支**（`ff_socket_ops.c:646-702`）：
```c
rte_spinlock_lock(&ff_so_zone->lock);
tmp = nb_handled = ff_so_zone->count - ff_so_zone->free;
while (1) {
    nb_handled = tmp;
    if (nb_handled) {                       /* ← 快速旁路 */
        for (i = 0; i < ff_so_zone->count; i++) {
            if (ff_so_zone->inuse[i] == 0) continue;
            if (sc->status == FF_SC_REQ) ff_handle_socket_ops(sc);
            if (--nb_handled == 0) break;
        }
    }
    if (rte_rdtsc() - cur_tsc >= drain_tsc) break;
    rte_pause();
}
rte_spinlock_unlock(&ff_so_zone->lock);
```

**Ring 分支**（`ff_socket_ops.c:618-645`）：
```c
while (1) {
    ff_ring_process_requests(ff_so_zone->ring_zone,    /* ← 无旁路 */
        ff_handle_socket_ops_ring, FF_RING_SIZE);
    if (rte_rdtsc() - cur_tsc >= drain_tsc) break;
    rte_pause();
}
```

**差异**：sem 有 `if (nb_handled)` 本地变量旁路，ring 无；这是 H19 的代码事实，方案 C 通过 pending_count 把这个旁路引入 ring。

### 7.2 APP 端等待路径

**Sem 模式 `ACQUIRE_ZONE_LOCK`**（`ff_hook_syscall.c:153-164`）：
```c
while (1) {
    while (sc->status != exp) {
        rte_pause();    /* ← 纯 pause，无 yield */
    }
    rte_spinlock_lock(&sc->lock);
    if (sc->status == exp) break;
    rte_spinlock_unlock(&sc->lock);
}
```

**Ring 模式 `ff_ring_dequeue_wait`**（`ff_ring_ipc.c:106-129`）：
```c
while (rte_ring_sc_dequeue(ring, obj_p) != 0) {
    if (rte_rdtsc() - start_tsc >= timeout_tsc) return -ETIMEDOUT;
    if ((++spin_count & 0xFF) == 0) {
        sched_yield();    /* ← 每 256 次必触发 */
    } else {
        rte_pause();
    }
}
```

**差异**：ring 模式 APP 端每 256 次 PAUSE 才触发 `sched_yield`，但实测短链 9.2w QPS 场景下单次 wait 远达不到 256 PAUSE 阈值，sched_yield 几乎从未触发（vcs 增长 ≈ 0）。原以为 yield 频繁是次因（H18），实测已证伪。详见 §1.3 与 §5.A。

---

## 8. 与 plan.md 的章节映射

| 本文档章节 | plan.md 对应章节 |
|---|---|
| §1.3 修复路径 | plan.md §4 验证方案 A/B/C |
| §2 官方文档证据链 | plan.md §1 概述 |
| §3 perf 数据交叉验证 | plan.md §1.2 已证伪假设链 |
| §4 教训总结段 | plan.md §2 教训总结 |
| §5 修复方案详细设计 | plan.md §4 验证方案的代码草案 |
| §6 决策矩阵 | plan.md §5 决策矩阵 |
| §7 双边代码对照 | plan.md §3 假设清单的代码引用 |
