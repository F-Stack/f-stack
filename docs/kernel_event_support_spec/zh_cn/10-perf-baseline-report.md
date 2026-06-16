# 10 性能基线报告（v3，已作废 / SUPERSEDED）

> **⚠️ 作废声明（v4，2026-06-16）**：本报告基于 v3 的**错误实现**——`ff_socket(SOCK_KERNEL)`→`ff_host_socket`→纯宿主 socket，**全程未跑 F-Stack 用户态栈**（A/B 两版本都是纯内核栈）。该口径根本没有测量「F-Stack + 内核栈共存」，结论无效，**整篇作废**。
> v4 性能基线改为：**证明内核栈共存不拖累 F-Stack 业务快路径**（PERF-1/PERF-2，见 `07-test-spec.md`），在 R4 阶段以「共存开/关对 F-Stack 业务压测对比」重新产出；本文仅作历史留档。

---

> **文档编号**：SPEC-KE-10（v3 历史留档）
> **日期**：2026-06-16
> **状态**：SUPERSEDED（已作废，见上方声明）
> **作用域**：在**本机 loopback** 用 wrk 对"本地 socket/fd/event 访问"特性（`ff_socket(SOCK_KERNEL)` 内核栈路径）做性能基线，并以同源原生 `libc socket()` 版本做 A/B 对压求开销 Δ%，以 `freebsd_13_to_15_upgrade_spec/` 既有 CVM 数据作背景对照。
> **实证铁律**：所有数字来自实际 wrk 运行（原始输出 `/tmp/keperf/{A,B}_T{1,2,3}_trial{1,2,3}.txt`），禁止臆造。

---

## 1. 测试目的

量化"内核访问特性"在**数据面**是否引入吞吐/延迟开销。本特性核心是 socket 创建时按标记选栈（`ff_socket(...,SOCK_KERNEL)` → `ff_host_socket` → 宿主 `socket()`），后续 `bind/listen/accept/recv/send/epoll` 走相同的内核 fd 路径。因此理论上 A/B 的差异**仅为每连接建连时一次 `ff_socket→ff_host_socket` 函数跳转**，对 keep-alive 长连接的数据面应为零额外开销。本测试用实测验证该判断。

---

## 2. 环境

| 项 | 值 |
|---|---|
| 主机 | 单台 CVM，16 vCPU，31 GiB |
| 压测器 | wrk **4.2.0 [epoll]**（GitHub `wg/wrk` 源码本机构建，`/tmp/wrk-build/wrk`；系统源无 wrk 包） |
| 被测端 | `example/helloworld_stacksel`，**单线程 epoll keep-alive HTTP server**（`bench <port>` 模式） |
| 协议 | HTTP/1.1，`Connection: keep-alive`，固定 15B 响应体（对标 freebsd 升级 CVM helloworld 场景） |
| 链路 | **loopback 127.0.0.1**（server 与 wrk 同机；server 绑 CPU0，wrk 绑 CPU2-15，`taskset` 降争用） |
| 编译 | A/B 同 `-O2 -g`，同源 `main.c`，均链接 `lib/libfstack.a` |

### 2.1 A/B 两版本（同源，仅 `ksock()` 不同）
| 版本 | 构建 | socket 创建 | 含义 |
|---|---|---|---|
| **A** `helloworld_stacksel_ffk` | `-DUSE_FF_KERNEL=1` | `ff_socket(AF_INET, SOCK_STREAM\|SOCK_KERNEL, 0)` | 本特性内核访问路径 |
| **B** `helloworld_stacksel_libc` | `-DUSE_FF_KERNEL=0` | `socket(AF_INET, SOCK_STREAM, 0)` | 纯内核栈参照 |

---

## 3. 方法（对齐既有 CVM 方法学档位）

| 档位 | wrk 参数 | 时长 | 用途 |
|---|---|---|---|
| T1 | `-t2 -c10  --latency` | 5s | 轻载 + 预热剔除 |
| T2 | `-t4 -c100 --latency` | 30s | 中负载主回归 |
| T3 | `-t8 -c500 --latency` | 30s | 高并发尾延迟 |

- 每档 **3 trial 取 median**；每版本前置一次 3s warmup（丢弃）。
- 命令模板：`taskset -c 2-15 /tmp/wrk-build/wrk -t4 -c100 -d30s --latency http://127.0.0.1:<port>/`
- server 启停经 `/data/workspace/kill_process.sh`；脚本 `/tmp/keperf/runbench.sh`。

---

## 4. 实测结果（median of 3 trials；原始见 `/tmp/keperf/`）

### 4.1 吞吐 req/s

| 档位 | A `SOCK_KERNEL` | B `libc socket` | Δ (A vs B) | 三次 trial（A / B） |
|---|---:|---:|---:|---|
| T1 (-t2 -c10 5s)   | 120,949 | 136,199 | **−11.2%** | A 119822/132566/120949 · B 137667/136199/118075 |
| T2 (-t4 -c100 30s) | 125,169 | 119,498 | **+4.7%**  | A 125169/113753/135646 · B 119498/135067/118084 |
| T3 (-t8 -c500 30s) | 107,298 | 112,728 | **−4.8%**  | A 102829/115724/107298 · B 114646/105920/112728 |

### 4.2 延迟（median of 3 trials）

| 档位 | A p50 | B p50 | A p99 | B p99 |
|---|---:|---:|---:|---:|
| T1 | 67us  | 60us  | 151us  | 133us  |
| T2 | 767us | 814us | 1.04ms | 1.15ms |
| T3 | 4.58ms| 4.37ms| 5.25ms | 5.11ms |

- **Socket errors：0**（所有 18 个 trial 均无 connect/read/write/timeout 错误）。

### 4.3 结论（A/B）

**A 与 B 的吞吐/延迟差异在 ±11% 的 trial 间噪声范围内、无系统性方向**（A 在 T2 略快、T1/T3 略慢，各 trial 区间高度重叠）。这与理论一致：`ff_socket(SOCK_KERNEL)` 仅在**建连时**比 `libc socket()` 多一次 `ff_host_socket` 函数跳转，对 keep-alive 数据面零额外开销。

→ **内核访问特性不引入可测量的数据面性能回归**（佐证 NFR-1 零开销 / NFR-2 业务快路径无回归）。波动主因：loopback 自压下 server 与 wrk 同机 CPU/软中断争用（实测 `sys` 时间占比极高），属测量噪声而非特性开销。

---

## 5. 背景对照：freebsd_13_to_15 既有 CVM 数据（口径不同，仅作参考）

来源 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/13.0-baseline-cvm-bench-report.md`（**双 CVM、server 跑 DPDK + F-Stack 用户态栈、相同 wrk 三档**）：

| 档位 | 13.0 baseline req/s | 15.0 rfix req/s | 本报告 A（内核栈 loopback）|
|---|---:|---:|---:|
| T1 | 24,414 | 23,757 | 120,949 |
| T2 | 220,691 | 203,933 | 125,169 |
| T3 | 239,555 | 217,100 | 107,298 |

**口径差异（不可直接等价，务必注意）**：
1. **栈不同**：CVM 数据是 **F-Stack 用户态栈经 DPDK 网卡**的数据面吞吐；本报告是 **Linux 内核栈 + loopback** 的吞吐——二者测的是不同协议栈的不同路径。
2. **拓扑不同**：CVM 为**双机网卡间**真实收发；本报告为**单机 loopback 自压**（server 与 wrk 争用同一组 CPU）。
3. **并发模型不同**：CVM helloworld 为 F-Stack `lcore=4`；本报告为**单线程 epoll**（用户已确认"单线程数字仅反映串行下限"）。
4. T1 在两边都波动较大（5s 短窗），仅作链路探活，不用于结论。

**用途说明**：本特性是在 F-Stack 之外**新增**一条"内核栈可访问"通道（供本机 ping/curl 与客户端连本机/外部内核服务），**不替代** F-Stack 业务数据面。CVM 数据用于说明 F-Stack 业务面的吞吐量级背景；本特性的开销由 §4 的 A/B 同环境对压给出（≈噪声、无回归）。

---

## 6. 局限与后续

- 本基线为**本机 loopback 单线程**自压，反映"串行/单 loop 下限"，**非** server 真实极限，也非双 CVM DPDK 数据面；绝对值仅在同口径内可比。
- 真实物理机/双 CVM 下的 hook 模式端到端与 F-Stack 业务面+内核管理面共存吞吐，待具备 DPDK 绑定物理 NIC 环境后按 `cvm-bench-methodology.md` 补跑（沿用 `freebsd_13_to_15` F-A3/F-A4 路径）。
- 如需更高单机吞吐基线，可启用多线程 `SO_REUSEPORT`（本轮按用户要求保持单线程）。

---

## 7. 复现实步

```bash
# 1) 构建 wrk（系统无包时源码构建）
git clone --depth 1 https://github.com/wg/wrk.git /tmp/wrk-build && make -C /tmp/wrk-build -j4

# 2) 构建 A/B 被测二进制
cd /data/workspace/f-stack/example/helloworld_stacksel && make bench
#   -> helloworld_stacksel_ffk (SOCK_KERNEL) / helloworld_stacksel_libc (libc)

# 3) 三档自压（server 绑 CPU0，wrk 绑 CPU2-15，各 3 trial）
bash /tmp/keperf/runbench.sh A helloworld_stacksel_ffk  18211
bash /tmp/keperf/runbench.sh B helloworld_stacksel_libc 18212
#   原始输出：/tmp/keperf/{A,B}_T{1,2,3}_trial{1,2,3}.txt
```

> 合规：wrk 进程经 `kill_process.sh` 停止、临时文件经 `rm_tmp_file.sh` 清理；无直接 rm/kill/chmod。
