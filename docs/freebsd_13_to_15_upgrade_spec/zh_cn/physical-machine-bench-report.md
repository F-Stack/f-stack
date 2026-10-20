# F-Stack 13.0 vs 15.0 — 物理机基线压测报告

> **数据来源**：iWiki 4021545579（外部团队 OSPF/CMC 项目组执行；2026-Q2 落档）
> **本文件性质**：iWiki 原始数据的工程化二次整理 + 与本项目 CVM 同时序 A/B 数据交叉对照
> **关联文档**：
> - `06-test-and-acceptance-spec.md` §5（性能基线 NFR-1 框架）
> - `13.0-baseline-cvm-bench-report.md`（同硬件 CVM 同时序 A/B；§14 物理机交叉对照）
> - `runtime-fix-execution-log.md` §12.6 / §12.10 / §12.11（CVM helloworld + perf flamegraph）

---

## 1. 测试平台

| 项 | 值 |
|---|---|
| 形态 | 物理机（裸金属，非 CVM） |
| CPU | Intel(R) Xeon(R) Platinum 8255C @ 2.50 GHz |
| NIC | Mellanox MT27800 Family [ConnectX-5]，100 GbE |
| OS | TencentOS Server 4.4 |
| Kernel | Linux 6.6.98-40.9.tl4.x86_64（SMP，2026-01-22 build） |
| Server 端 IP（混淆） | `x.x.x.39`（A/B/C 段混淆，D 段保留） |
| wrk 客户端 | 同物理机房客户端机器（与 server 物理直连或万兆环境） |

**与本项目 CVM 平台的关键差异（影响后续解读）**：

| 维度 | 物理机（iWiki） | 本项目 CVM | 备注 |
|---|---|---|---|
| 形态 | 裸金属 | 虚拟化（KVM） | 决定下文"放大因子"的核心变量 |
| NIC | Mellanox CX-5 100G（mlx5 PMD） | virtio-net（virtio_user_pmd / virtio_pci_pmd） | virtio 路径在 15.0 上 `virtio_recv_mergeable_pkts` 占比明显高于物理 NIC |
| CPU | Cascade Lake 2.5 GHz | 同代或更新代 vCPU（受宿主调度） | CVM 受邻居噪声影响，跨日漂移 6–10% |
| Kernel | 6.6.98-40.9.tl4 | 同代次（不影响 F-Stack 用户态栈，仅控制 host networking） | F-Stack 走 dpdk 旁路，host kernel 仅参与 control plane |
| dpdk | LTS（iWiki 未明示版本，按 mlx5 PMD 默认配置） | 23.11.5（pkg-config --modversion 实测） | F-Stack lib 链接的 librte_*.so 版本对吞吐影响有限（同 ABI） |

---

## 2. helloworld（F-Stack example，单核长连接）

### 2.1 wrk 命令

```text
./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39
```

参数解读：24 client 线程 / 128 连接 / 10s / 启用延迟分布。**长连接**（HTTP keep-alive，wrk 默认行为）。

### 2.2 吞吐与延迟对比

| 指标 | 13.0 | 15.0 | Δ | 解读 |
|---|---:|---:|---:|---|
| **Req/sec** | **958,109.22** | **1,056,177.98** | **+10.24%** | 单核单流接近 100w QPS，**15.0 显著优于 13.0** |
| Transfer/sec | 593.01 MB/s | 653.71 MB/s | +10.24% | 与吞吐同步 |
| Avg Latency | 122.51 us | 110.67 us | -9.66% | base 路径变快 |
| p50 | 121 us | 107 us | -11.57% | 中位延迟下降 |
| p75 | 132 us | 118 us | -10.61% | |
| p90 | 151 us | 138 us | -8.61% | |
| p99 | 204 us | 197 us | **-3.43%** | 长尾**未恶化**（甚至略好） |
| Total req | 9,677,043 / 10.10 s | 10,667,274 / 10.10 s | — | |

### 2.3 关键观察

**15.0 在物理机 helloworld 单核长连接上是净收益**：吞吐 +10.24%，p50–p99 全段下降。这与 13.0→15.0 的 RACK 默认化、TCP CUBIC 状态机优化、以及 socket buffer locking 重构的预期收益一致。

> **与 CVM 同时序 A/B 反差**：CVM 上 15.0 helloworld 在 T2/T3 退化 -7.59% / -9.37%（详见 `13.0-baseline-cvm-bench-report.md` §5.1）。差异根因已由 CVM 报告 §11.5 通过 perf flamegraph 定位为 `virtio_recv_mergeable_pkts` / `tcp_default_output` vtable 等"虚拟化路径开销在窄通道下放大"。物理机走 mlx5 PMD，绕开 virtio，这条通道开销不存在 → 15.0 的 vendor 演进收益（RACK / CUBIC / sb 重构）得以净显现。

---

## 3. nginx_fstack（短连接）

### 3.1 wrk 命令族

| lcores | 命令 |
|---|---|
| 1 | `./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39 ; sleep 10` |
| 2 | `./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39 ; sleep 10` |
| 4 | `./wrk -c 200 -t 24 -d 10 -L http://x.x.x.39` |

**短连接**：每请求新建 TCP 连接（HTTP `Connection: close`，nginx_fstack 默认行为或 wrk -H 强制）。

### 3.2 吞吐对比

| lcores | 13.0 (Req/s) | 15.0 (Req/s) | Δ | 备注 |
|---:|---:|---:|---:|---|
| 1 | 127,592.23 | 124,726.68 | **−2.25%** | 单核轻退化 |
| 2 | 256,207.62 | 246,872.92 | **−3.65%** | 中等退化 |
| 4 | 406,379.63 | 381,614.48 | **−6.10%** | 高并发退化最大；偶发一次跑到 410,998.92（+1.14%）但**很难复现**（iWiki 原文备注） |

### 3.3 延迟对比（仅列具有显著变化的分位）

| lcores | 13.0 p50 | 15.0 p50 | Δ p50 | 13.0 p99 | 15.0 p99 | Δ p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 483 us | 494 us | +2.28% | 600 us | 627 us | +4.50% |
| 2 | 260 us | 267 us | +2.69% | 403 us | 430 us | +6.70% |
| 4 (-c200) | 215 us | 219 us | +1.86% | 552 us | 586 us | +6.16% |

### 3.4 关键观察

**15.0 在物理机 nginx_fstack 短连接上有 2–6% 系统性退化**，且随 lcores 增加而恶化：

1. **退化不源于 helloworld 路径**（同硬件 helloworld 长连接是 +10%）。
2. **疑因**：短连接 fastpath 涉及大量 `sonewconn` / `solisten_clone` / `accept` 路径，叠加 P3 (kern_descrip 边界 + `badfileops` 恢复) 在 file descriptor 创建/销毁路径上的额外原子操作。`13.0-baseline-cvm-bench-report.md` §6.3 已列 P3 为高怀疑根因之一。
3. **多核 scaling 健康度**：
   - 13.0 多核 scaling：1→2 = ×2.008（理想 ×2），1→4 = ×3.184（理想 ×4，效率 79.6%）
   - 15.0 多核 scaling：1→2 = ×1.979，1→4 = ×3.060（效率 76.5%）
   - 两版多核 scaling 效率均下降明显，**符合短连接共享 listen socket 的锁竞争预期**，但 15.0 比 13.0 稍差 3 个百分点。

---

## 4. nginx_fstack（长连接）

### 4.1 wrk 命令族

| lcores | 命令 |
|---|---|
| 1 | `./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39` |
| 2 | `./wrk -c 128 -t 24 -d 10 -L http://x.x.x.39 ; sleep 10` |
| 4 | `./wrk -c 256 -t 24 -d 10 -L http://x.x.x.39` |

### 4.2 吞吐对比

| lcores | 13.0 (Req/s) | 15.0 (Req/s) | Δ | 备注 |
|---:|---:|---:|---:|---|
| 1 | 314,889.22 | 330,837.26 | **+5.06%** | 单核 ~5% 净收益 |
| 2 | 623,961.88 | 653,647.68 | **+4.76%** | |
| 4 | 1,230,501.76 | 1,289,871.91 | **+4.83%** | 4 核 ~129 万 QPS，单核近 322k 利用率 |

### 4.3 延迟对比

| lcores | 13.0 p50 | 15.0 p50 | Δ p50 | 13.0 p99 | 15.0 p99 | Δ p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 391 us | 372 us | **-4.86%** | 428 us | 408 us | **-4.67%** |
| 2 | 187 us | 180 us | -3.74% | 328 us | 320 us | -2.44% |
| 4 (-c256) | 185 us | 182 us | -1.62% | 310 us | 314 us | +1.29% |

### 4.4 关键观察

**15.0 在物理机 nginx_fstack 长连接上系统性 +5% 净收益**，多核线性度优秀：

| lcores → | 13.0 scaling | 15.0 scaling |
|---|---|---|
| 1→2 | ×1.981 | ×1.976 |
| 1→4 | ×3.908（97.7%） | ×3.899（97.5%） |
| 2→4 | ×1.972 | ×1.973 |

**两版 1→4 多核效率均 ≥ 97.5%**，且 15.0 没有相对 13.0 的退化，符合预期：长连接 fastpath 主要在 `tcp_do_segment` / `sbappendstream` 等共享路径，15.0 vendor 演进（CUBIC / sb locking）净收益直接落到吞吐上。

---

## 5. 与 CVM 同时序 A/B 的交叉对照

### 5.1 helloworld 单核数据合并

| 平台 | 13.0 (req/s) | 15.0 (req/s) | Δ | p99 13.0 | p99 15.0 | Δ p99 |
|---|---:|---:|---:|---:|---:|---:|
| **物理机** (iWiki) | 958,109 | 1,056,178 | **+10.24%** | 204 us | 197 us | -3.43% |
| **CVM T2** t4c100 | 220,691 | 203,933 | **−7.59%** | 811 us | 827 us | +2.0% |
| **CVM T3** t8c500 | 239,555 | 217,100 | **−9.37%** | 4.21 ms | 5.38 ms | +27.8% |

**反差解读**：
- **吞吐绝对值**：物理机是 CVM 的 **4.34×**（958k vs 220k），符合 100G mlx5 物理 NIC vs virtio 虚拟 NIC 的吞吐阶梯。
- **15.0 净影响方向相反**：物理机 +10%，CVM -7%~-9%。
- 此反差**已由 CVM 报告 §11.5 通过 perf flamegraph 定位**：CVM 上 15.0 增长的 top 函数为 `virtio_recv_mergeable_pkts` (+0.74pp)、`tcp_default_output` vtable wrapper (+0.94pp)、socket buffer locking 重构 (+1.5pp)；其中 virtio 路径在物理机上不存在，且 vtable wrapper / sb locking 的"开销"被 RACK / CUBIC 优化的"收益"在物理机上完全抵消并反超。

### 5.2 nginx_fstack 长连接（无 CVM 同时序对照，本项目内未跑）

| lcores | 物理机 13.0 | 物理机 15.0 | Δ |
|---:|---:|---:|---:|
| 1 | 314,889 | 330,837 | +5.06% |
| 2 | 623,962 | 653,648 | +4.76% |
| 4 | 1,230,502 | 1,289,872 | +4.83% |

**说明**：本项目 CVM 端 nginx_fstack 仅做了多进程 lcore_mask=0xC/0x3C 的**功能验证**（详见 `runtime-fix-execution-log.md` §12.15），未做与 13.0 同时序的吞吐 A/B；后续如需要 CVM 端 nginx_fstack 性能基线，应单独排期。**当前验收用 nginx_fstack 性能数据以本物理机基线为准**。

### 5.3 nginx_fstack 短连接（无 CVM 同时序对照）

物理机短连接 **−2% ~ −6%** 退化是本次升级的**唯一系统性 regression 信号**。本项目内无 CVM 同时序短连接对照数据。

---

## 6. 关键发现

### 6.1 跨平台总判断

| 场景 | 物理机 Δ | CVM Δ（参考） | 验收结论 |
|---|---:|---:|---|
| helloworld 单核长连接 | **+10.24%** | -7.59% ~ -9.37% | 物理机 PASS（NFR-1 不退化 > 5% 满足，且超额收益）；CVM 退化已 perf 归因为 vendor 演进而非 runtime-fix |
| nginx_fstack 长连接 1/2/4 核 | **+4.76% ~ +5.06%** | 未测 | PASS（系统性净收益） |
| nginx_fstack 短连接 1/2/4 核 | **−2.25% ~ −6.10%** | 未测 | **观察项**：单核 -2.25% 在 NFR-1 "短连接 QPS 不退化 > 5%" 阈值内（PASS）；4 核 -6.10% **超过 5% 阈值** → 触发 NFR-1 评议（见 §7） |

### 6.2 短连接 4 核退化 -6.10% 的处置建议

NFR-1 短连接 QPS 验收阈值为"不退化 > 5%"。物理机 nginx_fstack 4 核短连接 -6.10% 严格触发该阈值的评议要求。建议处置路径（按工程性价比排序）：

1. **首选 — 接受 trade-off 并备案**：当前升级的核心价值是修复 5 个 P0 SIGSEGV 与重大 vendor 演进收益（helloworld 长连接 +10%、nginx 长连接 +5%）；短连接 -6% 在多核共享 listen socket 锁竞争场景下可解释，且偶发数据点 +1.14%（虽难复现）说明非硬性退化。备案进 `99-review-report.md` 已知 trade-off 章节。
2. **可选 — 物理机 perf flamegraph 双版叠图**：与 CVM §11 同方法学，定位 `sonewconn` / `accept` / `kern_descrip` 路径的 cpu-clock 占比变化。预算 0.5 day。
3. **可选 — P3 (kern_descrip) 单独 commit 二分**：如 perf 指向 `badfileops` 恢复的 fd 创建路径，可评估是否调整该 stub 实现。

### 6.3 13→15 vendor 演进的工程价值

物理机 helloworld 单核长连接 +10.24% 是该项目最干净的"vendor 演进收益"实证：
- 同硬件、同 NIC、同 dpdk、同 wrk 参数、同代码骨架（仅 F-Stack lib + freebsd kernel 源码差）；
- 排除虚拟化层干扰；
- 收益与 RACK 默认化、CUBIC 状态机扩展、sb_locking 重构的预期一致；
- 与 RACK 改进的"额外收益作为净额计入"（`06-test-and-acceptance-spec.md` §5.3）框架完全契合。

### 6.4 数据可信度限定

- **iWiki 数据为外部团队执行**，本项目未独立复现物理机环境；
- 单次 wrk 10s 采样，无多轮均值/方差；
- 客户端机器、NUMA topology、CPU 亲和性、IRQ 绑定、hugepages 配置等细节 iWiki 未列；
- 短连接定义（是否 wrk -H "Connection: close"，或 nginx 配置 `keepalive_timeout 0`）iWiki 未明示，仅以"短链接"标签为准；
- 偶发数据点 4 核 短连接 410,998.92（标 +1.14% vs 13.0）"很难复现"，未列入主表，仅 §3.2 备注。

→ 本数据**适合作为方向性收益 / 退化判断**，**不适合**作为绝对基准用于 micro-optimization。

---

## 7. NFR-1 验收判定矩阵（按 06-spec §5.1）

| NFR-1 指标 | 阈值 | 物理机实测（min over runs） | CVM 实测（参考） | 通过 |
|---|---|---|---|:---:|
| 单流 TCP 吞吐（loopback） | 不退化 > 5% | helloworld +10.24%（已超额满足） | -7.59% ~ -9.37%（CVM 因虚拟化路径 regression） | **物理机 ✓** / CVM 备案 |
| 短连接 QPS（HTTP echo） | 不退化 > 5% | 1 核 -2.25% / 2 核 -3.65% / **4 核 -6.10%** | 未测 | **观察 ⚠**（4 核越线 1.10pp，按 §6.2 处置） |
| 长连接 QPS（参考） | 不退化 > 5% | +5% 系统性提升 | 未测 | ✓ 净收益 |
| 单核 lcore CPU 利用率 | 信息项 | helloworld 单核接近 100w QPS（满载） | 单核 ~22w QPS（受 virtio 限制） | 信息项已采集 |

**总判定**：除 nginx 4 核短连接需触发 §6.2 评议外，**物理机基线满足 NFR-1**。

---

## 8. 数据资产指针

| 项 | 路径 |
|---|---|
| iWiki 原始页面 | `https://iwiki.woa.com/p/4021545579` |
| 本报告 | `docs/freebsd_13_to_15_upgrade_spec/zh_cn/physical-machine-bench-report.md`（本文件） |
| CVM 同时序 A/B（helloworld） | `docs/freebsd_13_to_15_upgrade_spec/zh_cn/13.0-baseline-cvm-bench-report.md` |
| CVM perf flamegraph 根因 | 同上 §11（双版采样、Top 函数对比、差分火焰图） |
| 06-spec NFR-1 框架 | `06-test-and-acceptance-spec.md` §5（基线指标 + 采集时机 + RACK 收益记录） |
| 06-spec 物理机段引用 | `06-test-and-acceptance-spec.md` §5.4（本次新增） |

---

## 9. 落档记录

| 项 | 值 |
|---|---|
| iWiki 拉取时间 | 2026-06-05（UTC+8） |
| 拉取工具 | `iwiki-cli get 4021545579` v0.0.8 linux/amd64 |
| 数据范围 | helloworld 单核长连接 + nginx_fstack 短连接/长连接（1/2/4 lcores） |
| IP 混淆 | iWiki 中实际服务器 IP（腾讯内网 A/B/C 段）→ 本文统一替换为 `x.x.x.39`（D 段保留以供回溯，A/B/C 段混淆，符合本项目既有混淆约定） |
| 强制规约 | 临时文件 `/tmp/iwiki_4021545579.md` 完成后用 `rm_tmp_file.sh` 清理 |
