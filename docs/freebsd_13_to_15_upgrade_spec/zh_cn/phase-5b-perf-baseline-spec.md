# Phase-5b Perf Baseline Spec — F-Stack v1.26 / FreeBSD 15.0 (Phase-2 Feature Matrix)

**Author**: Phase-5b Leader
**Date**: 2026-06-08
**Predecessor**: Phase-2 M6~M13 + M-Final (commit `99cc538cd`, ahead 22)
**Methodology base**: `06-test-and-acceptance-spec.md §5` NFR-1 framework + `cvm-bench-methodology.md`
**Status**: ACTIVE

---

## 1. 目标

为 Phase-2 启用的 8 个 feature flag（M6~M13）建立**跨配置相对性能 delta 矩阵**，重点关闭两个已记录 follow-up：

- **M9-F1**：PA+ZC combo 1000 短连慢 3.5x（vs M8 ZC-only） —— 需根因分析或归类为 expected
- **M10-F2**：IPIP 隧道大流量吞吐基线未做 —— 受 client 工具限制改为 ping-RTT 时序基线

**非目标**：
- 绝对 QPS/吞吐数字（client 仅 curl，无 wrk/iperf3/ab；标准 NFR-1 数值在 M5 阶段已 PASS）
- 13.0 baseline 重测（M5 已 dual-baseline 落档）
- 物理机 + CVM 双基线（环境受限）

---

## 2. 环境约束（如实记录，不绕过）

| 维度 | 状态 |
|---|---|
| Server NIC | 1× virtio `0000:00:09.0`（同时承担 SSH transport）|
| Hugepages | 已配置（M6~M13 实测可用）|
| DPDK 绑定 | igb_uio 已 load |
| Client OS | Linux（Ubuntu/Debian 系，per `uname -a`）|
| Client 压测工具 | **仅 `curl`**（无 iperf3/wrk/ab/httping）|
| 链路 | server-client 同 VPC，ping RTT < 1 ms |
| ssh round-trip | ≈ 6-7 ms（前期实测，已成为 100/1000 串行 curl 的瓶颈）|

**不安装新工具**：尊重 OQ-1（client 用户独立维护）。

---

## 3. 方法学

### 3.1 Trial 单元（reusable harness）

`tools/sbin/p5b_perf_matrix.sh` 实现 **single trial = N 次串行 curl from f-stack-client**：

```
T_total = $(ssh f-stack-client "time (for i in 1..N; do curl ... ; done)")
QPS_eff = N / T_total      # 含 ssh round-trip，仅可作跨配置 delta 用
fail_rate = (N - http_200_count) / N
```

每个配置跑 **3 trials**，取 **median(T_total)** + **max-min jitter**，避免 single-shot 噪音。

### 3.2 Matrix 维度

| 配置 | lib/Makefile flags |
|---|---|
| **C0 BASELINE** | 仅 P0：FF_NETGRAPH+FF_IPFW（恢复未启 P1/P2 的最小集，但保留 LOOPBACK=1 因 ff_swi_net_excute stub 已落地）|
| **C7 M7** | C0 + FF_USE_PAGE_ARRAY=1 |
| **C8 M8** | C0 + FF_ZC_SEND=1 |
| **C9 M9** | C0 + FF_USE_PAGE_ARRAY=1 + FF_ZC_SEND=1 |
| **C10 M10** | C0 + FF_FLOW_IPIP=1（用于隧道 ping-RTT 序列 + 直连 HTTP 对照）|

P2 三件套（M11/M12/M13）属 smoke-only，**不进入 perf matrix**（rte_flow 在 virtio 上无 effect）。

### 3.3 测试用例（每个配置共测）

| TC | 描述 | 预期 |
|---|---|---|
| **TC1** | 100 串行 curl `/`（短连）| pass_rate = 100% / 跨配置 delta < 30% |
| **TC2** | 1000 串行 curl `/`（短连）| pass_rate ≥ 99% / 配置间 ratio 量化 M9-F1 |
| **TC3 (C10 only)** | 隧道内 100 ping `10.10.10.1`（IPIP 内网 IP）| 0% loss / RTT median ≤ 2 ms |

### 3.4 验收降级（per master plan OQ-2 + OQ-4）

- **observation-only**：所有数值仅作记录，不作为 PASS/FAIL gate
- **唯一 hard fail**：primary 进程 SIGSEGV / panic / pass_rate < 90%
- bounces ≤ 3 / milestone（与 phase-2 同标准）

---

## 4. 5-phase 流水线

| Phase | 输出 |
|---|---|
| A. Spec | 本文档 |
| B. Research | 合并入 §2 + §3（环境约束 + 工具复用 phase-2 经验）|
| C. Code | `tools/sbin/p5b_perf_matrix.sh` |
| D. Run | 5 配置 × 3 trials × 2 TC + 1 IPIP-tunnel TC = 33 runs；总耗时预估 ≤ 25 min |
| E. Gate | 写 `phase-5b-perf-baseline-report.md`（matrix CSV + delta 表 + 4 项 RCA） |

---

## 5. 决策点

完成后必须回答：

- **D1 M9-F1 处置**：3.5x 是 expected（PA mmap + ZC fast-path 协同放大 short-conn 上下文切换）/ 还是 regression（需修代码）/ 是否仅在小流量 + ssh round-trip 主导下被放大
- **D2 M10-F2 关闭依据**：ping-RTT 序列稳定即视作 IPIP 软件路径基线 PASS
- **D3 production default**：M-Final 后默认开启哪些 flag（P0 必开 + P1/P2 待用户决策）

---

## 6. Compliance

- 全程 `rm_tmp_file.sh` / `kill_process.sh` / `chmod_modify.sh`
- 进程探活 `[ -d /proc/$PID ]`，禁 `kill -0`
- Local commit only（不 push，per phase-2 规约延续）
- Commit message 用英文

---

> 进入 Phase C：实现 `p5b_perf_matrix.sh`。
