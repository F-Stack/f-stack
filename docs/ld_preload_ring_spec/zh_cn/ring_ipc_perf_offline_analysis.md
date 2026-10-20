# Ring IPC 性能劣化离线深度分析（v3.7 · 终版 · 短/长连接全场景收敛 · 编译开关收敛）

> 修订历史：v1 主因 H10/H11（drain 不存在于 sem）已被用户证伪；v2 主因 H15（cache miss）已被 perf stat 证伪；v3 基于 F-Stack 官方"事件匹配度"理论重定位主因为 H17；v3.1（2026-05-21 上午）实测证伪 H18，方案 A 废弃为 §5.A；v3.2（2026-05-21 晚）三组实测协同证伪 H17/H21/H24，主因收敛到 H19-final + H23；v3.3（2026-05-22）方案 C 实测劣化 4% 废弃（H25 证伪），方案 C+/D2 实测成功 +9.7% QPS，新增方案 D5；**v3.4（2026-05-22 晚）方案 D5 (+1.3%) + D6 (+0.9%) 实施收尾，QPS 9.1w → 10.22w 总收益 +12.3%（达 sem 97.3%），剩余 2.7% 已识别为 ring SPSC 架构固有开销不可消除**；v3.4.1（2026-05-25）补充 §9 附录 D，记录多 worker sem 模式 `idle_sleep=0` 启动饥饿现象；v3.4.2（2026-05-25）§9.6 同步源头修复进展（提交 `8125beece6`，正常负载零开销）；v3.5（2026-05-25 晚）多核短连接实测三组（1/2/4 核）联合证实"ring 在 FF_MULTI_SC 多 worker 短连接场景下相对 sem 无性能优势"；**v3.6（2026-05-25 晚）多核长连接实测三组（1/2/4 核）显示 ring 持续劣于 sem 2.4%–4.5%，差距方向稳定且大于短连接噪声范围。最终收敛：ring 路径在 LD_PRELOAD + FF_MULTI_SC 任何场景下均无性能优势，仅保留代码作为未来"多线程同进程共享 sc"和"多进程间共享 sc（worker 数量多于 fstack 实例数量）"扩展场景的预留能力。生产推荐配置回归 sem。详见 §1.4 与 §10 附录 E**；v3.7（2026-05-25 晚）三个独立编译开关 `FF_RING_SC_COMPLETION` / `FF_RING_FAST_EMPTY_CHECK` / `FF_RING_INLINE_DISPATCH` 已删除，对应 D2/D5/D6 实现作为 `FF_USE_RING_IPC` 分支的默认行为合入，旧的 rsp_ring 等待路径与函数指针 dispatch 分支已删除；同时删除 v3.3 已废弃的方案 C 编译开关 `FF_RING_PENDING_BYPASS`、`pending_count` 字段及其 inc/dec/atomic_read 路径（§5.3 仅保留教训记录）。完整教训总结见 §4。

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
| ✅ 多 worker 短连接对比测试 | 0 行（仅改配置）| -- | **已完成**（详见 §1.4.1 / §10.1-§10.4），ring ≡ sem |
| ✅ 多 worker 长连接对比测试 | 0 行（仅改配置）| -- | **已完成**（详见 §1.4.2 / §10.5-§10.7），ring **稳定劣于** sem 2.4%–4.5%，最终证伪 ring 设计目标 |

### 1.4 多核短连接 + 长连接实测收敛（v3.6 · 2026-05-25 晚 · 用户预判证实 + 长连接证伪 ring 设计目标）

> **用户预判**（贯穿 v3.0 起多次提出）："ring 在 FF_MULTI_SC 多 worker 模式下相对 sem 没有性能优势，因为每个 worker 已是独立 zone 独立 lock，本就无跨 worker 锁竞争。"
> **结论**：实测短连接 + 长连接共 6 组数据**完全证实**该预判，且**长连接下 ring 反而稳定劣势 2.4%–4.5%**。

#### 1.4.1 短连接实测（wrk 默认）

| lcores | Sem QPS（万）| Ring QPS（万）| 差距 |
|---|---|---|---|
| 1 | 10.4 | 10.2 | -1.92% |
| 2 | 20.8 | 20.8 | **0%** |
| 4 | 35.9 | 35.8 | **-0.3%** |

差距 ≤ 2% 噪声范围内，可视为 ring ≡ sem。详见 §10.1–§10.4。

#### 1.4.2 长连接实测（keep-alive）

| lcores | Sem QPS（万）| Ring QPS（万）| 差距 | Ring/Sem 比值 |
|---|---|---|---|---|
| 1 | 33.3 | 31.8 | **-4.50%** | 95.50% |
| 2 | 65.9 | 64.3 | **-2.43%** | 97.57% |
| 4 | 130.5 | 127.0 | **-2.68%** | 97.32% |

**关键观察**：
- **三组数据全部 ring 劣于 sem，方向稳定**（不同于短连接 0/-0.3%/-1.9% 的噪声分布）
- **长连接绝对 QPS 是短连接 ~3.1–3.6 倍**，更接近 IPC 层真实极限
- **多核扩展系数都很好**：sem 1→2 ×1.98、1→4 ×3.92；ring 1→2 ×2.02、1→4 ×3.99 → **再次证实 sem 无跨 worker 锁竞争**
- 长连接下 ring 的劣势比短连接更稳定，与单 worker v3.4 收敛的 2.7% 固有开销同量级

详见 §10.5–§10.7。

#### 1.4.3 为何长连接下 ring 反而稳定劣势（笔者预测被证伪）

笔者在 v3.5 §10.5 预测："长连接下 sem 全程持 zone lock 50-100μs，ring lock-free 优势可能显现"。**这一预测被实测证伪**。深层原因：

| 推断（旧）| 实际情况 |
|---|---|
| sem 长连接下 `tmp` 持续 > 0 → 全程持 zone lock → fstack lcore 与 nginx worker 锁竞争升高 | sem `FF_MULTI_SC` 下 fstack lcore 与 nginx worker **是 1:1 同 zone 关系**，但 nginx worker 进入 zone lock 的频率本就极低（仅 attach/detach），**正常 read/write 路径根本不抢 zone lock** |
| ring lock-free 主循环节省 sem 持锁开销 | sem 持锁是 fstack lcore **独占持有**，cache line 一直 exclusive 状态，持锁开销极低；ring 反而每次 `rte_ring_sc_dequeue_burst` 都要 acquire fence 同步内存系统 → **长连接高 QPS 把这个开销线性放大** |

**结论**：v3.4 §1.2 锁定的"ring SPSC 架构固有开销"在长连接高 QPS 下被**线性放大**而非被相对优势抵消。

#### 1.4.4 最终收尾结论

| 场景 | Ring vs Sem 差距 |
|---|---|
| 单 worker 短连接（v3.4）| -2.7% |
| 多 worker 短连接（§1.4.1）| -0.3% ~ -1.9%（噪声范围） |
| 多 worker 长连接（§1.4.2）| **-2.4% ~ -4.5%（持续稳定劣势）** |

**最终判定**：
1. **性能层面**：sem 仍是 LD_PRELOAD + FF_MULTI_SC 的最优配置，ring 在**任何已测场景下均无性能 net win**
2. **鲁棒性层面**：ring 主循环 lock-free 的理论价值（启动饥饿免疫）已被提交 `8125beece6` 在 sem 源头修复，**鲁棒性优势也已被消除**
3. **架构层面**：ring 路径**保留代码与编译开关**（`FF_USE_RING_IPC` + D2/D5/D6），作为"多线程同进程共享 sc"和"多进程间共享 sc（worker 数量多于 fstack 实例数量）"未来扩展场景的预留能力。当前 LD_PRELOAD fork 多进程场景**默认不启用 ring**

**生产推荐配置（2026-05-25 终版）**：

```bash
# LD_PRELOAD + nginx 多 worker 推荐（默认）
make FF_KERNEL_EVENT=1 FF_MULTI_SC=1
# config.ini: idle_sleep = 0（提交 8125beec 后安全），pkt_tx_delay = 50（短连接）/ 100（长连接）
```

ring 路径仅在以下任一情况启用：
- 单进程内有多线程需共享 sc（当前 LD_PRELOAD 不命中）
- 多进程间共享 sc（worker 数量多于 fstack 实例数量，当前 LD_PRELOAD 1:1 部署不命中）
- 用户接受 -2.4%~-4.5% 性能损失换取主循环 lock-free 设计

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

### 5.3 方案 C：atomic pending_count 旁路 — ❌ **已实施实测劣化·废弃·代码已删除**

> **2026-05-22 实测结论**：QPS 9.1w → 8.7w（**劣化 4%**），`ff_handle_each_context` Self 19.39% → 36.27%（暴涨 +16.88pp）。**H25 证伪**。已立即回退；后续（v3.7 之后）连同编译开关 `FF_RING_PENDING_BYPASS`、`pending_count` 字段及其 inc/dec 路径一并从代码中删除（`ff_socket_ops.h` / `ff_socket_ops.c` / `ff_hook_syscall.c` / `Makefile`），不再保留为研究分支。
>
> **失败根因**：nginx 端原本只在 enqueue 时写 `req_ring->prod.tail` 一次（频率 ~10w/s），方案 C 让 nginx 多写 `pending_count` 2-4 次/syscall（inc + 可能 dec/inc 重试），写频率翻倍以上 → fstack 端每次 drain spin 跨核读 → cache line 持续 invalidate ping-pong → CPU 浪费在 cache miss 上反而比原 dequeue 路径更糟。
>
> **教训**：方案设计必须做"对称评估表"，列出"消除的物理量"和"新引入的物理量"两栏。详见 §4 教训段。代码层最终走的是 §5.5 方案 D5（`rte_ring_empty` 内联快速空判断），实现同一目标——避免空 dequeue 的函数调用栈——但**复用现有 ring 元数据，零新跨核字段**，对称评估通过且实测成功。

---

### 5.4 方案 C+ / D2：sc->completion 替代 rsp_ring（修复 H23）— ✅ **已实施实测成功**

> **2026-05-22 实测**：QPS 9.1w → **10.0w（+9.7%）**，wrk Avg 1.20ms → 1.06ms（-12%），`ff_ring_send_response` Self 3.33% → **0%**。**H23 修复确认**。已合入并作为 `FF_USE_RING_IPC` 分支的**默认行为**（不再使用独立编译开关；旧 rsp_ring 路径已删除）。

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

**风险**：低。`ff_ring_alarm_wakeup` 路径同步加 `sc->completion=1` 写入，确保 alarm 唤醒在 D2 模式下生效；rsp_ring enqueue 保留作 alarm 路径的 sentinel/legacy fallback。该方案已作为 `FF_USE_RING_IPC` 默认行为合入主线，独立的 `FF_RING_SC_COMPLETION` 编译开关已移除（历史草案见后文 5.5/5.6 同样默认化处理）。

---

### 5.5 方案 D5：rte_ring_empty 快速空判断（修复 H19-final 函数调用栈） — ✅ **已实施实测成功（小幅）**

> **2026-05-22 下午实测**：QPS 10.0w → **10.13w（+1.3%）**，`ff_ring_process_requests` Self 18.98% → **4.53%**（降幅 76%，符合预期）。
>
> **关键观察**：函数调用栈开销已大部分消除，但 QPS 收益仅 1.3%——节省的 14.45% Self CPU 大部分被吸收到 `ff_handle_each_context`（Self 27.45 → 36.78），是因为 fstack lcore 已 100% CPU 占用，节省的 CPU 直接被 main loop spin 填满。这是 v3.4 关键洞察的起点。

> **触发条件**：D2 已合入，QPS 10.0w 距 sem baseline 10.5w 还差 5%，由 `ff_ring_process_requests` Self 18.98% 主导（D2 后未变）。

**核心思想**：用 DPDK 公共内联函数 `rte_ring_empty(r)` 做快速空判断，避免 `ff_ring_process_requests` 函数调用栈展开开销。**不引入任何新跨核字段**——这是方案 D5 与失败的方案 C 的根本差异。

**改动点**：`ff_socket_ops.c` 主循环 ring 分支（与方案 C 同位置但实现完全不同）。该方案已作为 `FF_USE_RING_IPC` 分支的**默认行为**合入主线，独立的 `FF_RING_FAST_EMPTY_CHECK` 编译开关已移除。

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

**历史草案（v3.3 评估期）**——该宏已在 v3.6 后默认化，主线代码不再依赖此开关：
```c
while (1) {
#ifdef FF_RING_FAST_EMPTY_CHECK     /* 历史：已默认化，主线不再判断 */
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

**改动文件**：`ff_socket_ops.c`（`ff_handle_socket_ops_ring` 加 `inline` + main loop 内联 dispatch，嵌在 D5 路径内）。该方案已作为 `FF_USE_RING_IPC` 分支的**默认行为**合入主线，独立的 `FF_RING_INLINE_DISPATCH` 编译开关已移除。

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
| §1.4 多核短连接 + 长连接收敛结论 | plan.md §8.2 / §8.3 / §8.5 实测数据 |
| §2 官方文档证据链 | plan.md §1 概述 |
| §3 perf 数据交叉验证 | plan.md §1.2 已证伪假设链 |
| §4 教训总结段 | plan.md §2 教训总结 |
| §5 修复方案详细设计 | plan.md §4 验证方案的代码草案 |
| §6 决策矩阵 | plan.md §5 决策矩阵 |
| §7 双边代码对照 | plan.md §3 假设清单的代码引用 |
| §9 附录 D 饥饿现象 | plan.md §8.6 启动饥饿 |
| §10 附录 E 多核短/长连接测试 | plan.md §8.2 / §8.5 |

---

## 9. 附录 D：sem 模式 `idle_sleep=0` + 多 worker 启动饥饿现象（非真死锁）

> 触发条件：`FF_USE_RING_IPC` **未开启**（即 sem 老路径） + `FF_MULTI_SC=1` + fstack `config.ini` 配置 `idle_sleep = 0` + nb_procs ≥ 2。
> 现象：fstack/nginx 启动完成、**尚未发起任何流量**时，nginx 第二个 worker 在 `ff_attach_so_context(idx=1)` 内 `rte_spinlock_lock(&ff_so_zone->lock)` 处永久 hang，gdb 堆栈表象与死锁完全一致。
> 用户验证（2026-05-25）：将 fstack 的 `idle_sleep` 从 `0` 改为 `1`（仅 1μs）即可正常启动。**与 ring 模式无关**（ring 主循环 lock-free，已规避此问题）。

### 9.1 现象的本质：自旋锁饥饿，非死锁

锁未被任何进程"持有不释放"。fstack secondary lcore 在 sem 老路径主循环里**高频抢占—释放**同一把 zone 锁，nginx worker 进程在持续 cmpxchg 竞争中**永远抢不到**，外观与死锁完全一致。

### 9.2 调用链与代码引用

**fstack secondary 进程主循环**（`adapter/syscall/fstack.c:7` → `ff_socket_ops.c:622`）：

```
ff_main_loop                                    # DPDK lcore 紧循环
  └─ ff_dpdk_if.c:2422-2428                     # idle_sleep==0 → 不让 CPU
  └─ ff_handle_each_context()
       └─ #else（sem 分支，ff_socket_ops.c:700-747）
            ├─ rte_spinlock_lock(&ff_so_zone->lock)    ← line 702
            ├─ while(1) { ... 遍历 sc，等待 drain_tsc 满 ... }
            └─ rte_spinlock_unlock(&ff_so_zone->lock)  ← line 747
```

**nginx worker 启动路径**（`adapter/syscall/ff_so_zone.c:160`）：

```
ff_adapter_init() → ff_attach_so_context(worker_id % nb_procs)
  └─ ff_so_zone.c:192  rte_spinlock_lock(&ff_so_zone->lock)   ← 卡死在这里
```

两条路径竞争**同一把锁**：fstack secondary（proc_id=1）的 `ff_so_zone` 指向 zone1（`ff_so_zone.c:153`），nginx worker1 的 attach 也针对 zone1（`ff_hook_syscall.c:3292` 计算 idx=1）。

### 9.3 饥饿三要素叠加

| 编号 | 要素 | 代码位置 | 量级 |
|---|---|---|---|
| **P1** | 持锁时长 = `pkt_tx_delay`（与 sc 数量无关） | `ff_socket_ops.c:700-744`，`while(1)` 直到 `diff_tsc ≥ drain_tsc` 才 break | 50–100 μs/次 |
| **P2** | 释锁后无 idle 让步 | `ff_dpdk_if.c:2423` `if (likely(idle && idle_sleep))`，`idle_sleep==0` 时直接 fall-through | 释锁→重新抢锁间隔 **<<1 μs** |
| **P3** | `rte_spinlock` 非公平（裸 cmpxchg） | DPDK rte_spinlock 实现：`while(__atomic_compare_exchange_n(&sl->locked, &exp=0, 1, ...) == 0) rte_pause();` | 无票据队列、无 backoff |

**叠加效应**：
- fstack lcore 专核 + 紧自旋 + 同 NUMA → 持续保有 zone 锁 cache line，**释锁瞬间下一个 tsc 就重新拿到**
- nginx worker 是普通调度进程，cmpxchg 频率低、cache line 需先拉到自己核心 → **每次释锁窗口都慢一拍**
- 持锁 50μs ≫ 空窗 <<1μs，nginx worker 命中空窗的概率趋近于 0

### 9.4 时间线对账

```
fstack lcore (idle_sleep=0)                 nginx worker 抢锁
  T0      lock zone1                            cmpxchg fail, rte_pause
  T0+50μs unlock                                ←  空窗 <<1μs（fstack 立刻 cmpxchg）
  T0+50μs lock zone1（fstack 抢回）              cmpxchg fail, rte_pause
  T0+100μs unlock                               ←  空窗 <<1μs
  ...                                           （持续饿死）

fstack lcore (idle_sleep=1μs)               nginx worker 抢锁
  T0      lock zone1                            cmpxchg fail, rte_pause
  T0+50μs unlock                                ←  空窗 ≥1μs ✓
  T0+50μs rte_delay_us_sleep(1)                 cmpxchg succeed → 持锁、初始化
```

cmpxchg 自身只需几十 ns，**1μs 空窗内成功概率趋近 100%**。

### 9.5 为何 ring 模式天然免疫

`ff_socket_ops.c:622-688`（`#ifdef FF_USE_RING_IPC` 分支）：

```c
624: #ifdef FF_USE_RING_IPC
626:  * Ring mode: O(1) batch dequeue from req_ring.
627:  * No global zone lock needed — ring is lock-free.
```

Ring 主循环**完全不锁 zone**，仅在 `ff_attach_so_context` 启动时一次性短暂持锁（毫秒级），不存在 fstack lcore 高频抢占。**v3.4 优化后的 ring 路径在架构上规避此问题**——这进一步佐证 ring 路径相对 sem 老路径的体系收益（不止性能，还有启动鲁棒性）。

### 9.6 解法（按代价递增）

| 方案 | 代价 | 效果 | 状态 |
|---|---|---|---|
| **A. 用户级 workaround** | fstack `config.ini` 设 `idle_sleep ≥ 1` | lcore CPU 占用从 100% 降至 ~95%，sem 模式可正常启动 | ✅ 已验证 |
| **B. 代码补丁**（仅 sem 路径，提交 `8125beec`） | `ff_socket_ops.c:744-752` 仅在 `tmp==0`（无 in-use sc）时让出锁窗口 | 启动期消除饥饿；**有负载时零影响**（`tmp>0` 走原路径，仍 `rte_pause()`，不释锁） | ✅ 已合入主线 |
| **C. 长期架构**（已完成） | 启用 ring 模式（`FF_USE_RING_IPC=1`），主循环 lock-free | 规避此问题；同时获得 +12.3% QPS | ✅ v3.4 已交付 |

### 9.6.1 方案 B 修复细节（提交 `8125beece6`，2026-05-25）

**修改位置**：`adapter/syscall/ff_socket_ops.c:707-752`（sem 分支 `ff_handle_each_context` 内 while 循环）

**修改要点**（仅 13+/5- 行）：

1. **line 705**：保留 `tmp = nb_handled = ff_so_zone->count - ff_so_zone->free`（进入循环时 in-use sc 总数快照）
2. **line 709**：`if (nb_handled)` → `if (likely(nb_handled))`，编译器分支预测提示（正常负载有 in-use sc）
3. **line 744-752**：新增"无负载时让出锁窗口"逻辑：

```c
if (unlikely(!tmp)) {                            // 本轮进入时 in-use sc 数为 0
    rte_spinlock_unlock(&ff_so_zone->lock);      // 释锁
    rte_pause();                                  // 暂停
    rte_spinlock_lock(&ff_so_zone->lock);        // 重新拿锁
}
```

**为什么用 `tmp` 而不是 `nb_handled`**：
- `tmp` 是**本轮进入循环时**的快照（line 705），整个 `drain_tsc` 窗口内保持不变
- `nb_handled` 在每轮 for 内会递减到 0（line 728），不能作为"是否有负载"的判据
- → `tmp==0` 精确表达"启动期/空闲期，本进程当前确实没有任何 sc"

**为什么这是最优修复**：

| 场景 | tmp 值 | 行为 | 影响 |
|---|---|---|---|
| 启动期（nginx 未 attach）| `tmp == 0` | 每轮释锁→pause→重锁，**给 attach 留窗口** | 解决饥饿 ✓ |
| 正常压测（多 sc 在用） | `tmp > 0` | 走 `rte_pause()` 不释锁，保持持锁 drain | **零性能影响** ✓ |
| 仅个别 sc 短暂空闲 | `tmp > 0` | 同上 | 不触发释锁，避免 sc 处理延迟 ✓ |

**与笔者 §9.6 方案 B 原始建议的差异**（提交方更优）：

- 笔者原建议：无条件 `unlock → pause → lock`，会让所有压测路径多两次原子操作
- 提交方修复：用 `unlikely(!tmp)` 限定到**仅启动/全空闲**场景，正常负载零开销
- 同时加了 `likely(nb_handled)` 优化常路径分支预测，体现作者对 sem 路径仍在生产使用的尊重

**回归风险**：
- 仅 sem 路径生效（`#else` 分支，line 689-754），不影响 ring 路径
- 不改变锁不变量：进入 while 前持锁、退出 while 后持锁、`unlock→lock` 间无对 zone 字段的访问
- `tmp` 是本地变量、不受 unlock 期间他人修改 zone 的影响

### 9.6.2 推荐配置组合

| 部署形态 | 编译开关 | config.ini | 备注 |
|---|---|---|---|
| 单实例 sem（兼容老部署）| `FF_KERNEL_EVENT=1`（不开 ring） | `idle_sleep = 0` 即可 | 需基于提交 `8125beec` 之后 |
| 单实例 sem（保守起见）| 同上 | `idle_sleep = 1` | 双重保险，CPU 占用 ~95% |
| 多 worker sem | 同上 | `idle_sleep = 0`（提交后）或 `1`（提交前）| 多 worker 是 `8125beec` 主要修复目标 |
| 多 worker ring（v3.4 推荐）| `FF_USE_RING_IPC=1 FF_KERNEL_EVENT=1 FF_MULTI_SC=1` | `idle_sleep` 任意（ring 主循环不锁 zone）| 性能 +12.3%，无饥饿问题（D2/D5/D6 自 v3.6 起作为 ring 默认行为，无需独立开关）

### 9.7 与本文主线的关系

本附录与 §1–§7 的单 worker ring 性能优化**正交**——不影响任何已实施方案（D2/D5/D6）的结论。但它揭示了 sem 老路径在多实例部署下**除性能差距之外的额外架构缺陷**，是 ring 路径必要性论证的补充证据。

**修复状态（2026-05-25）**：提交 `8125beece6` 已在 sem 路径源头修复（见 §9.6.1），生产 sem 部署不再需要依赖 `idle_sleep` workaround。Ring 路径自始就免疫此问题。

排查教训（与 §4 一脉相承）：
- 启动期 hang 优先排查"高频抢占 + 非公平锁"型饥饿，而非真死锁（gdb 堆栈一致，但锁状态会显示为短暂 locked，`*sl` 值在 0/1 之间快速翻转）
- 跨进程自旋锁竞争中，**专核 DPDK lcore 永远胜过普通调度进程**，这是物理机制而非代码 bug
- 用户提供的"`idle_sleep` 改 1 即可"是关键证据——能用配置消除的现象，根因 99% 是时间窗/调度类问题
- **最优补丁应是"条件性让出"而非"无条件让出"**：用 `unlikely(!tmp)` 把开销限定在饥饿场景，正常负载零影响（提交 `8125beec` 范式）
---

## 10. 附录 E：多核短连接 + 长连接实测数据（v3.6 · 2026-05-25 晚 · 终版）

> 本附录为 §1.4 收敛结论的完整数据存档。短连接（§10.1–§10.4）来自 v3.5；长连接（§10.5–§10.7）为 v3.6 新增，最终证伪 ring 路径设计目标。

### 10.1 测试环境（短连接 / 长连接共用）

- **平台**：与单 worker 测试同环境（同 NUMA、同 lcore 配置原则）
- **fstack worker 数**：与 nginx worker 数 1:1 匹配
- **编译开关**：
  - sem 路径：`FF_KERNEL_EVENT=1 FF_MULTI_SC=1`（含提交 `8125beece6` 启动饥饿修复）
  - ring 路径：`FF_USE_RING_IPC=1 FF_KERNEL_EVENT=1 FF_MULTI_SC=1`（D2+D5+D6 自 v3.6 起作为 ring 默认行为合入，独立开关 `FF_RING_SC_COMPLETION` / `FF_RING_FAST_EMPTY_CHECK` / `FF_RING_INLINE_DISPATCH` 已删除）
- **wrk 参数**：`-c 128 -t 24 -d 10 -L`（短连接默认；长连接使用 keep-alive 模式）
- **`config.ini`**：`pkt_tx_delay = 50`（短连接）/ `100`（长连接），`idle_sleep = 0`

### 10.2 实测数据

| lcores | Sem QPS（万）| Ring QPS（万）| Ring/Sem 差距 | Sem 单核效率 | Ring 单核效率 | 扩展系数 (Ring) |
|---|---|---|---|---|---|---|
| 1 | 10.4 | 10.2 | -1.92% | 10.40w | 10.20w | 基准 |
| 2 | 20.8 | 20.8 | 0.00% | 10.40w | 10.40w | ×2.04 |
| 4 | 35.9 | 35.8 | -0.28% | 8.98w | 8.95w | ×3.51 |

### 10.3 数据解读

**结论 1：ring ≡ sem（差距 ≤ 2% 噪声范围内）**

三组数据中，1 核场景 ring 略低 1.92%（与 §1.4 单 worker v3.4 收敛的 2.7% 接近），2/4 核基本完全持平。**统计上可视为两条路径性能等价**。

**结论 2：2 核接近线性扩展（×2.04），证实 sem 无跨 worker 锁竞争**

若 sem 模式存在跨 worker zone lock 竞争，2 核扩展系数会显著低于 ×2。实测 ×2.04 略超 ×2 的原因：1 核基线含一些固定开销（DPDK 元数据维护、系统中断）被 2 核分摊。**这是 v3.0 起用户预判"`FF_MULTI_SC` 下每个 worker 独立 zone 独立 lock"的直接证据**。

**结论 3：4 核亚线性（×3.51）瓶颈不在 IPC 层**

ring 与 sem 衰减系数完全一致（Ring ×3.51 vs Sem 实际 ×3.45 = 35.9/10.4），说明 4 核瓶颈两条路径**共享同一来源**：
- 候选 1：wrk 客户端 / 网卡 RSS 哈希分布不均
- 候选 2：NUMA 节点边界（lcore 4-7 是否跨 NUMA？）
- 候选 3：fstack 主循环跨核 cache（如 mempool 共享）

→ **不属于 IPC 层问题**，已超出本分析文档（ring vs sem 对比）的范畴。

### 10.4 与单 worker 收敛结论的一致性

| 场景 | Ring vs Sem 差距 | 解释 |
|---|---|---|
| 单 worker（§1）| -2.7%（10.22 vs 10.5）| ring SPSC 架构固有开销（acquire fence + 元数据）|
| 多 worker 1 核（§10.2）| -1.92%（10.2 vs 10.4）| 同上（差异 0.78% 为不同测试日的噪声）|
| 多 worker 2 核 | 0%（20.8 vs 20.8）| 噪声覆盖固有开销 |
| 多 worker 4 核 | -0.28%（35.8 vs 35.9）| 同上 |

→ **单 worker 的 2.7% 固有开销在多核下被噪声平均掉了**，未放大也未消除。两条路径的 scalability 完全一致。

### 10.5 长连接实测数据（v3.6 新增）

| lcores | Sem QPS（万）| Ring QPS（万）| Ring/Sem 差距 | Sem 单核效率 | Ring 单核效率 | Sem 扩展系数 | Ring 扩展系数 |
|---|---|---|---|---|---|---|---|
| 1 | 33.3 | 31.8 | **-4.50%** | 33.30w | 31.80w | 基准 | 基准 |
| 2 | 65.9 | 64.3 | **-2.43%** | 32.95w | 32.15w | ×1.98 | ×2.02 |
| 4 | 130.5 | 127.0 | **-2.68%** | 32.63w | 31.75w | ×3.92 | ×3.99 |

### 10.6 数据解读

**结论 1：ring 在长连接下持续劣于 sem 2.4%–4.5%，方向稳定**

不同于短连接 0/-0.3%/-1.9% 的噪声分布（无方向性），长连接三组数据**全部 ring 劣于 sem，且差距大于短连接的噪声范围**。这与单 worker v3.4 收敛的 -2.7% 固有开销同量级，说明该开销在长连接高 QPS 下被**线性放大**。

**结论 2：长连接绝对 QPS 是短连接的 ~3.1–3.6 倍**

| lcores | Sem 短/长 | Ring 短/长 |
|---|---|---|
| 1 | 10.4 → 33.3（×3.20）| 10.2 → 31.8（×3.12）|
| 2 | 20.8 → 65.9（×3.17）| 20.8 → 64.3（×3.09）|
| 4 | 35.9 → 130.5（×3.64）| 35.8 → 127.0（×3.55）|

短连接瓶颈主要在 socket/close 路径（每次都过 `ff_attach_so_context` 等慢路径），长连接绕过这些后**更接近 IPC 层真实极限**。两条路径吃到的"长连接红利"接近一致（~3.1-3.6×），说明 ring 没有从 sem 的"持锁压力升高"中获得相对优势。

**结论 3：多核扩展系数都很好，再次证实 sem 无跨 worker 锁竞争**

- sem：1→2 ×1.98（≈ 线性），1→4 ×3.92（≈ 线性）
- ring：1→2 ×2.02（≈ 线性），1→4 ×3.99（≈ 线性）

**长连接下 sem 不仅未出现锁竞争恶化，反而比短连接（4 核 ×3.45）扩展更好**。这彻底证伪了 v3.5 §10.5 的预测"长连接下 sem 持锁压力升高 → 锁竞争"。

### 10.7 设计假设的最终证伪与原因复盘

笔者在 v3.5 §10.5 预测："长连接下 sem 全程持 zone lock 50-100μs，ring lock-free 优势可能显现"。**实测彻底证伪**。

**深层原因复盘**：

| 推断（v3.5 旧）| 实际情况（v3.6 实测）|
|---|---|
| sem 长连接 `tmp` 持续 > 0 → 全程持 zone lock → fstack lcore 与 nginx worker 锁竞争升高 | sem `FF_MULTI_SC` 下 fstack lcore 与 nginx worker **是 1:1 同 zone 关系**，但 nginx worker 进入 zone lock 频率本就极低（仅 attach/detach），**正常 read/write 路径根本不抢 zone lock** → 持锁时间变长**不会引起额外竞争** |
| ring lock-free 主循环节省 sem 持锁开销 | sem 持锁是 fstack lcore **独占持有**，cache line 一直 exclusive 状态，持锁本身近乎零成本；ring 反而每次 `rte_ring_sc_dequeue_burst` 都要 acquire fence 同步内存系统 → **长连接高 QPS 把 acquire fence 开销线性放大** |
| 长连接 `tmp > 0` 时 sem 不进 §9.6.1 释锁分支 → 持锁更连续 → 与 ring lock-free 差距应缩小 | 持锁更连续**反而对 sem 有利**（cache line 不被 invalidate），ring 的相对劣势因此放大 |

**关键认知**：sem 路径的"持锁"在 `FF_MULTI_SC` 单 lcore 独占模型下**不是性能负担而是性能优势**——cache line 始终在 fstack lcore 上保持 exclusive 状态，无任何跨核同步开销；而 ring 的 SPSC 设计**始终需要跨核 acquire fence**（哪怕生产者消费者在不同核都已成立的常态），这个固有开销在高 QPS 下被线性放大。

### 10.8 与单 worker / 全场景的一致性总结

| 场景 | Ring vs Sem 差距 | 解释 |
|---|---|---|
| 单 worker（§1）| -2.7%（10.22 vs 10.5）| ring SPSC 架构固有开销（acquire fence + 元数据）|
| 多 worker 1 核 短连接（§10.2）| -1.92%（10.2 vs 10.4）| 同上（与 v3.4 单 worker 同量级）|
| 多 worker 2 核 短连接 | 0%（20.8 vs 20.8）| 噪声覆盖固有开销 |
| 多 worker 4 核 短连接 | -0.28%（35.8 vs 35.9）| 同上 |
| **多 worker 1 核 长连接（§10.5）**| **-4.50%（31.8 vs 33.3）**| **ring 固有开销在长连接高 QPS 下放大** |
| **多 worker 2 核 长连接** | **-2.43%（64.3 vs 65.9）**| **同上** |
| **多 worker 4 核 长连接** | **-2.68%（127.0 vs 130.5）**| **同上** |

**最终判定（已写入 §1.4.4）**：
- ring 在 LD_PRELOAD + FF_MULTI_SC **任何已测场景下均无性能 net win**
- sem 是生产推荐配置；ring 仅保留代码作未来"多线程同进程共享 sc"和"多进程间共享 sc（worker 数量多于 fstack 实例数量）"扩展场景预留
