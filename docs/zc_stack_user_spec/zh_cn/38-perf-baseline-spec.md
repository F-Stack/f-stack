# 38. 性能基线规格

> 参考：21-m2-test-report.md（ZC-recv 单核 wrk A/B 实测）+ docs/freebsd_13_to_15_upgrade_spec/zh_cn/cvm-bench-methodology.md
> 目标：本期 spec 实施后，新方案与现魔改方案在小包/大包/多并发场景下 Δ ≤ ±3%（噪声内）

---

## §1 测试拓扑

```
[client: f-stack-client (8 核 CVM)]   ssh   [server: 本机 (单核 lcore4 + DPDK NIC)]
   /tmp/wrk/wrk -t* -c* -d30s        ───▶   helloworld_zc (HTTP echo, port 80)
        9.134.214.176                       data-plane: vfio-pci 0000:00:09.0
                                            control-plane: eth1 SSH
```

参考方法论：`docs/freebsd_13_to_15_upgrade_spec/zh_cn/cvm-bench-methodology.md`（13.0→15.0 升级时已建立的单核基线）。

---

## §2 测试矩阵

### §2.1 三档 wrk 压测档（与 21-m2-test-report 一致）

| 档 | 命令 | 用途 |
|---|---|---|
| T1 | `wrk -t2 -c10 -d5s --latency http://9.134.214.176/` | 低并发 smoke，建立基线 |
| T2 | `wrk -t4 -c100 -d30s --latency http://9.134.214.176/` | 中等并发，主对比档 |
| T3 | `wrk -t8 -c500 -d30s --latency http://9.134.214.176/` | 高并发，饱和或超饱和 |

### §2.2 三对比组

| 组 | 服务端构建 | 含义 |
|---|---|---|
| **A** baseline | 默认编译（无 ZC）| 普通 ff_read + ff_write，作为基线 |
| **B-old** | 现魔改 ZC-send | `FF_ZC_SEND=1` 旧实现（FSTACK_ZC_MAGIC + m_uiotombuf）|
| **B-new** | 新原生 ZC-send | `FF_ZC_SEND=1` 新实现（kern_zc_sendit + sosend(top)）|

注：B-old 即当前 master 已落地版本（commit de58b11e9 之前）；B-new 是本 spec 实施后版本。

### §2.3 大 payload 自定义 client（issue #712 场景）

| # | 场景 | 客户端 | 期望行为 |
|---|---|---|---|
| P1 | 小包（438 字节，main_zc 默认 HTML 大小） | wrk T1/T2/T3 | A ≈ B-old ≈ B-new（拷贝开销可忽略）|
| P2 | 中包（4 KB） | 自定义 client（写一次 4KB） | A < B-new；B-old 可能 crash/hang（issue #712） |
| P3 | 大包（64 KB） | 自定义 client | A << B-new；B-old crash/hang 风险高 |
| P4 | 巨包（1 MB） | 自定义 client | B-new 应分片发送（atomic + sb_max 约束，详见 36 §4）；A 顺序拷贝；B-old crash 概率最高 |

---

## §3 实测命令模板（spec 仅描述，实施期跑）

> spec 不提供可执行的"启动 / 停止"命令，因为这些会触及进程管理；实施期 agent 应严格遵守 `kill_process.sh` 与 `rm_tmp_file.sh` 规约（M2 阶段已有教训）。

测试流程伪代码（非可执行）：

```
1. 编译 server A: PKG_CONFIG_PATH=... make (default)
2. 编译 server B-new: PKG_CONFIG_PATH=... FF_ZC_SEND=1 make clean && make
3. 启动 server A → wrk T1/T2/T3 → 记录 r1/r2/r3
4. 停 server A: /data/workspace/kill_process.sh <pid>
5. 清理 hugepage: /data/workspace/rm_tmp_file.sh /dev/hugepages/rtemap_*
6. 启动 server B-new → wrk T1/T2/T3 → 记录 r1/r2/r3
7. 停 server B-new + 清理
8. 比较 A vs B-new → Δ 目标 ≤ ±3%
9. (可选) 启动 server B-old（git checkout 旧实现 + 重编） → wrk → 记录
10. 比较 B-old vs B-new → Δ 目标 ≤ ±3%
```

---

## §4 通过条件（AC3）

| 条款 | 通过判据 |
|---|---|
| **PERF-1** | T1/T2/T3 三档下 B-new vs A 的 Requests/sec Δ ≤ ±3%（噪声内）|
| **PERF-2** | T1/T2/T3 三档下 B-new vs B-old 的 Requests/sec Δ ≤ ±3%（噪声内，证明替换无回归）|
| **PERF-3** | T2 档 Latency p50 / p90 / p99 三 server 的 Δ ≤ ±5%（噪声含尾延迟扰动）|
| **PERF-4** | 单核 server CPU 使用率 T2 档 60-90%（未饱和）；三 server 接近一致 |
| **PERF-5** | wrk Socket errors / Non-2xx responses 三 server 均 = 0 |
| **PERF-6** | （issue #712 场景）P2 4KB 单包 B-new 不 crash；B-old 视环境而定（参考用，不强制 PASS）|
| **PERF-7** | （issue #712 场景）P3 64KB 单包 B-new 不 crash 且数据完整；B-old 已知风险 |

---

## §5 历史基线参考（来自 13.0 升级 baseline + 21-m2 报告）

| 指标 | 13.0 baseline | M2-A baseline (本机, 21-m2) | M2-B ZC-recv (本机, 21-m2) |
|---|---|---|---|
| T1 (-t2 -c10) | — | 22.4k | 22.1k |
| T2 (-t4 -c100) | ~220k 估 | ~31.1k | ~32.1k |
| T3 (-t8 -c500) | ~239k 估 | 28.6k | 28.3k |
| smoke RTT | 1.25ms | — | — |

> 13.0 与 M2 数值差异显著（13.0 是不同 fixture），因 main_zc 的 echo response 大小与 socket buffer 默认值差异；本期 spec 仅以 M2-A/B 为参考基线，不对齐 13.0 绝对值。

---

## §6 大 payload 自定义 client 示例（spec 描述，非可执行）

实施期可在 `tests/integration/zc_send_perf_client.c` 写一个自定义 TCP 客户端：
- 单连接，发起 N 次请求，每次发送固定大小 payload（4KB / 64KB / 1MB）；
- 服务端 echo 回；
- 客户端记录吞吐 / RTT / 错误率。

或复用 wrk 的 `-s` Lua script 选项注入自定义 body（推荐，无需自实现）：

```lua
-- /tmp/perf_4k.lua（在 client 端编辑，实施期）
wrk.method = "POST"
wrk.body = string.rep("x", 4096)
wrk.headers["Content-Type"] = "application/octet-stream"
```

启动：`/tmp/wrk/wrk -t4 -c100 -d30s -s /tmp/perf_4k.lua --latency http://9.134.214.176/`

> spec 中提供的 lua 脚本片段不属于"shell 命令"；实施期编辑该 lua 文件不触及 rm/kill/chmod 规约。

---

## §7 测量方法

### §7.1 wrk 输出解析

```
Running 30s test @ http://9.134.214.176/
  4 threads and 100 connections
  Latency Distribution
     50%   1.10ms
     90%   2.95ms
     99%   8.20ms
  Requests/sec:  31987.45      ← PERF-1/-2 用此
  Transfer/sec:   12.34MB
```

### §7.2 server 端 CPU

```
ps -o pid,pcpu,comm <pid>      ← 实施期由 leader 通过 ssh + kill_process.sh 配套查 PID
```

### §7.3 错误率

wrk 输出末尾 `Socket errors: connect 0, read 0, write 0, timeout 0` 应全 0。

### §7.4 三次取均值

每档跑 3 次，去掉最高/最低离群值，取平均（21-m2 阶段曾遇 39k vs 31k 的 warmup 离群，规约必须复测）。

---

## §8 风险与缓解

| 风险 | 缓解 |
|---|---|
| issue #712 大数据 crash 在 B-old 复现 | 不强求 B-old 跑过 P2-P4；仅作 B-new 不回归判定 |
| client wrk 端瓶颈（client 9.134.213.x 也是 8 核 VM） | 启用 -t4..-t8 利用 client 多核；监控 client 端 CPU |
| 网络抖动 | 每档 3 次取均值；保留所有原始日志 |
| stale .o（M2 教训） | 每次切 server 必 `make clean`；spec 39 §3 强调 |

---

## §9 可门禁验证条款（gatekeeper）

| 条款 | 验证方式 | 通过判据 |
|---|---|---|
| P-G1 | spec 列出 ≥3 档压测（T1/T2/T3）| 命中 |
| P-G2 | spec 列出 ≥3 个对比组（A/B-old/B-new）| 命中 |
| P-G3 | spec 列出 PERF-1..7 通过条件 | 命中 |
| P-G4 | spec 引用 21-m2-test-report 历史数据 | 命中 |
| P-G5 | spec 不出现直接 rm/kill/chmod 命令 | 自动 grep |

---

下一篇：**39-migration-guide.md**（已部署项目迁移指南）。
