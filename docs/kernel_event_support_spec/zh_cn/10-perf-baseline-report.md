# 10 性能基线报告（真共存口径）

> **文档编号**：SPEC-KE-10
> **版本**：v6（native 自动双栈范式；沿用 v4/v5 真共存口径，作废 v3 纯内核 loopback 口径）
> **日期**：2026-06-17
> **状态**：§4/§5 为 v5 R4 真机实测 FINAL（per-fd 二选一口径，仅切运行期 `kernel_coexist` 0/1）；**v6 自动双栈（commit 13b418191）功能正确性 + 宏关零回归 + PERF-1/2/4 F-Stack 快路径 A/B 均已真机实测 PASS（见 §10）**。
> **v6 口径声明**：v5 实测的是 per-fd 二选一（默认仅建 F-Stack）下「切 `kernel_coexist` 0/1」对 F-Stack 快路径的影响——结论 PERF-1/2 零回归。**v6 自动双栈引入「默认双建/双驱动」**，须**新测**：①默认双栈下 F-Stack 业务快路径仍无回归（PERF-1/2）；②**单栈连接热路径不因双栈机制查 `ff_native_fd_map`**（PERF-4，对应 `07` UT-17）。R6 编译宏关闭态（含 v6 `ff_native_fd_map` 不编译）零回归仍由 `07 §1bis` MT-1 nm 符号比对验证，宏关时与原 F-Stack 同二进制、无需重测性能。
> **作用域**：用实测验证共存对 **F-Stack 业务快路径无回归**（PERF-1/PERF-2/**PERF-4**），并给出**内核侧旁路吞吐**（PERF-3）管理面数据点。
> **实证铁律**：所有数字来自实际 wrk 运行的原始输出（`/tmp/helloworld-coexist-bench/`、`/tmp/kbench-perf/`），禁止臆造。真实 server/client IP 经源端 sed 掩码后才落盘（`9.134.214.176→192.168.1.1`、`9.134.211.87→192.168.1.2`）。

---

## 0. v3 作废说明

v3 报告测的是 `ff_socket(SOCK_KERNEL)→ff_host_socket→纯宿主 socket` 的本机 loopback，**全程未跑 F-Stack 用户态栈**（A/B 两版本都是纯内核），根本没测「共存」。v4 已回退该错误实现并按正确范式重测：**应用 on F-Stack 跑业务，per-fd `SOCK_KERNEL` 附加走内核栈，二者同进程共存**。本报告即 v4 正确口径的实测结果。

---

## 1. 测试目的

| 编号 | 指标 | 方法 | 门禁 |
|---|---|---|---|
| PERF-1 | F-Stack 业务快路径回归 | 共存关 vs 共存开，只压 F-Stack 业务 | 吞吐/时延偏差 ≤ 噪声阈值（NFR-2） |
| PERF-2 | 默认路径零开销 | 共存分支对默认/`SOCK_FSTACK` 路径影响 | 零/可忽略（NFR-1） |
| PERF-3 | 内核侧旁路吞吐 | 本机 loopback 压 `SOCK_KERNEL` 内核监听 | 满足管理面预期（非高速路径） |
| **PERF-4（v6）** | **热路径不查 map** | 单栈连接 recv/send 在自动双栈开/关下吞吐对比（默认双栈 listen accept 出的单栈连接） | 连接热路径零额外开销（NFR-2，对应 `07` UT-17）；**实测 PASS**（recv/send 仅 `ff_is_kernel_fd` 单次判定不查 map；§10.2 keep-alive 长连接吞吐 A1≈A0 佐证） |

> **§4/§5 为 v5 per-fd 二选一口径 FINAL**；**v6 自动双栈（默认双建/双驱动）下 PERF-1/2/4 已 R7 真机重测 PASS，见 §10**。

---

## 2. 环境（v5 R4 实测）

| 项 | 值 |
|---|---|
| 被测主机 | 腾讯 CVM，16 vCPU，DPDK 23.11.5 |
| 数据面 NIC | `0000:00:09.0` virtio_net，已绑定 `igb_uio`（DPDK PMD 接管，F-Stack 数据面） |
| 控制面 NIC | `eth1`（内核驱动，供 ssh 旁路；与数据面物理隔离） |
| F-Stack 并发模型 | 单 lcore（`lcore_mask=10`，CPU#4），单进程，监听端口 80，`idle_sleep=20us` |
| 被测端（向量 A） | `example/helloworld`：F-Stack 长连接 keep-alive HTTP，返回预置 438B `html[]`；A/B 同一二进制，仅切 config |
| 被测端（向量 B） | `example/helloworld_stacksel bench`：`ff_socket(SOCK_KERNEL)` 内核监听 + `ff_host_epoll_*` 非阻塞事件循环，返回预置 15B 体（免 EAL） |
| 压测器 | wrk 4.2.0 [epoll]；向量 A 在 f-stack-client（`192.168.1.2`，与数据面同 /21 直连），向量 B 在本机 loopback |
| 协议 | HTTP/1.1，`Connection: keep-alive` |

A/B 唯一变量 = `config.ini [stack] kernel_coexist`（`0` 关 / `1` 开）。helloworld 源码与二进制不变，消除链接产物差异。

---

## 3. 方法（对齐 freebsd_13_to_15 `cvm-bench-methodology.md`）

| 档位 | wrk 参数 | 时长 | 用途 |
|---|---|---|---|
| T1 | `-t2 -c10 --latency` | 5s | 轻载 + 预热 |
| T2 | `-t4 -c100 --latency` | 30s | **中负载主回归判据** |
| T3 | `-t8 -c500 --latency` | 30s | 高并发尾延迟 |

- 每档 **3 trial 取 median**。
- 向量 A 为**同一时间窗 A/B**：A0(`kernel_coexist=0`) 与 A1(`kernel_coexist=1`) 在同一分钟窗口内切换重跑，最大限度抑制跨时漂移；每轮经 `kill_process.sh` 停服务、`rm_tmp_file.sh` 清 rtemap 大页。
- 向量 B 为本机 loopback 自压：server 绑 CPU0，wrk 绑 CPU2-15（`taskset` 降争用）。

---

## 4. 向量 A：F-Stack 业务快路径 A/B（PERF-1 / PERF-2）

### 4.1 吞吐 req/s（median of 3）

| 档位 | A0 共存关 | A1 共存开 | Δ (A1 vs A0) | 三次 trial（A0 / A1） |
|---|---:|---:|---:|---|
| T1 (-t2 -c10 5s)   | 27,386 | 27,204 | **−0.66%** | A0 28401/27386/26876 · A1 27204/27042/27618 |
| T2 (-t4 -c100 30s) | 207,723 | 210,811 | **+1.49%** | A0 206927/208099/207723 · A1 212296/208933/210811 |
| T3 (-t8 -c500 30s) | 128,422 | 134,354 | **+4.62%** | A0 127391/133667/128422 · A1 134354/139085/130335 |

### 4.2 p99 延迟（median of 3）

| 档位 | A0 p99 | A1 p99 |
|---|---:|---:|
| T2 | 695 us | 713 us |
| T3 | 281 ms | 210 ms |

### 4.3 结论（A/B）

**共存开启（A1）与关闭（A0）的吞吐/延迟差异全部落在 trial 间噪声范围内、无系统性负向**：T1 −0.66%、T2 +1.49%、T3 +4.62%（开启侧持平或略快）；T2 p99 基本相等（~700us）。这与设计一致——共存仅在各 `ff_*` 入口前置一次 `ff_is_kernel_fd()` 分支，默认/`SOCK_FSTACK` 路径逐字节未改，对不带 `SOCK_KERNEL` 的 F-Stack 业务 fd 零额外开销。

→ **PERF-1 / PERF-2 通过：内核栈共存开关对 F-Stack 业务快路径不引入可测量回归（佐证 NFR-1 默认路径零开销、NFR-2 业务快路径无回归、NFR-3 F-Stack 始终在位）。**

---

## 5. 向量 B：内核侧旁路吞吐（PERF-3，管理面）

本机 loopback 用 wrk 压 `SOCK_KERNEL` 内核监听的 HTTP 长连接 server（单线程 host-epoll，预置 15B 体）。

| 档位 | req/s（median of 3） | p99 | socket errors | 三次 trial |
|---|---:|---:|---:|---|
| T1 (-t2 -c10 5s)   | 132,385 | — | 0 | 132385/130522/133348 |
| T2 (-t4 -c100 30s) | 127,501 | 1.43 ms | 0 | 128979/119463/127501 |
| T3 (-t8 -c500 30s) | 113,641 | 4.86 ms | 0 | 102595/113648/113641 |

- **全部 9 个 trial 零 socket error**（无 connect/read/write/timeout 错误）。
- **口径说明**：这是**单线程**内核栈 server 在**单机 loopback 自压**（server 与 wrk 争用同机 CPU）下的吞吐，仅反映「内核侧旁路管理面」的串行下限，**非** F-Stack 数据面、**不可**与向量 A 绝对值直接等价。其用途是证明 `SOCK_KERNEL` 通道在高并发长连接下功能正常、无错误、吞吐满足本机 ping/curl/管理连接等管理面预期。

→ **PERF-3 通过：内核侧旁路在 T1/T2/T3 三档长连接下稳定服务、零错误。**

---

## 6. 背景对照：freebsd_13_to_15 既有 CVM 数据（口径不同，仅参考）

来源 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/13.0-baseline-cvm-bench-report.md`（同为双机、server 跑 F-Stack、相同 wrk 三档，helloworld 438B）：

| 档位 | 15.0 既有参考 req/s | 本报告 A0 共存关 | 本报告 A1 共存开 |
|---|---:|---:|---:|
| T1 | 23,757 | 27,386 | 27,204 |
| T2 | 203,933 | 207,723 | 210,811 |
| T3 | 217,100 | 128,422 | 134,354 |

- **T2 高度一致**：本次 A0/A1 (207.7k/210.8k) 与既有 15.0 (203.9k) 在跨时漂移区间内吻合，交叉印证「共存关时与纯 F-Stack 一致」（NFR-1）。
- **T3 绝对值低于既有跨时参考**：本次 c500 下 p50 很快（1.26ms）但 p99 长尾大（~200-300ms），3 trial 一致——这是**本环境当日 c500 单 lcore 接受调度 + `idle_sleep=20us` 的特性**，A0/A1 同口径同现象，**与共存无关**，故不影响 A/B 结论。既有报告 §5.2 已指出 T3 跨时漂移大，绝对值仅同口径内可比；本报告以同窗口 A/B 的相对 Δ 为准。

---

## 7. 关键过程发现：头改动需全量重编 lib（ABI 偏斜）

首次将重链当前 lib 的 helloworld 启动时**段错误于 `ff_log_close()→fclose(野指针)`**。根因定位（gdb + mtime 交叉）：R3 给 `struct ff_config` 的 `stack` 子结构新增 `int kernel_coexist`，改变了其后 `log` 子结构（含 `log.f`）的偏移；而 lib 的 Makefile **不跟踪头依赖**，增量构建残留了**混用新旧 `ff_config.h` 布局的 .o**——`ff_log.o`（旧偏移）读 `log.f` 读到新布局里别的非零字段 → `fclose` 崩溃。

- **判别**：已知可用的 13.0-baseline helloworld 在同环境正常进入 `ff_run`（exit 124 timeout，不崩）→ 环境正常；问题在当前树的构建状态。
- **修复**：`rm_tmp_file.sh` 清除全部 245 个 `.o` + `libfstack.a` → 全量重编（15s）→ 所有对象用同一份头布局 → helloworld 启动正常（exit 124）。
- **结论**：**非源码回归**，纯构建卫生问题。共存特性代码本身正确；NFR-1（共存关时与基线一致）在 clean build 下成立。
- **行动项**：对 `ff_config.h` 等结构头的改动，必须 `clean` 后全量重编 lib（lib/Makefile 缺头依赖跟踪，属 F-Stack 既有构建特性）；建议后续在 spec/README 标注。

---

## 8. 合规与最终系统状态

| 项 | 证据 |
|---|---|
| `rm_tmp_file.sh` | 全程零直接 rm；rtemap 清理、`.o`/libfstack.a 清除、stray log 清理均经脚本 |
| `kill_process.sh` | 全程零直接 kill；A0/A1 helloworld、内核 bench server 停止均经脚本 |
| `chmod_modify.sh` | 本轮无权限改动 |
| config.ini | 测试期 `kernel_coexist` 0↔1 切换，**测后已恢复 0**；本机运行态值（lcore_mask/port0 IP）为既有未提交本地状态，**不提交** |
| IP 掩码 | 向量 A 所有 client stdout 经源端 sed 掩码后落盘；向量 B 为 loopback 无真实 IP |
| 最终状态 | 无残留进程、hugepages 清洁（0 rtemap）、config `kernel_coexist=0` |

## 9. 复现实步

```bash
# 0) 头改动后全量重编 lib（关键）
ls /data/workspace/f-stack/lib/*.o | xargs /data/workspace/rm_tmp_file.sh
/data/workspace/rm_tmp_file.sh /data/workspace/f-stack/lib/libfstack.a
make -C /data/workspace/f-stack/lib -j$(nproc)

# 1) 重链 helloworld（向量 A 被测端）
cd /data/workspace/f-stack/example && cc -O0 -g -gdwarf-2 $(pkg-config --cflags libdpdk) -DINET6 \
  -o helloworld main.c $(pkg-config --static --libs libdpdk) \
  -L../lib -Wl,--whole-archive,-lfstack,--no-whole-archive -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lz -pthread -lnuma

# 2) 构建内核侧 bench（向量 B 被测端）
cd /data/workspace/f-stack/example/helloworld_stacksel && make   # ./helloworld_stacksel bench <port>

# 3) 向量 A：A0/A1 同窗口（仅切 config kernel_coexist 0/1），f-stack-client wrk T1/T2/T3 各 3 trial（输出经 sed 掩码）
# 4) 向量 B：本机 loopback wrk（server 绑 CPU0，wrk 绑 CPU2-15）T1/T2/T3 各 3 trial
# 收尾：kill_process.sh 停服务；rm_tmp_file.sh 清 rtemap；config 恢复 kernel_coexist=0
```

> 原始 wrk 输出：向量 A `/tmp/helloworld-coexist-bench/A{0,1}_T{1,2,3}_trial{1,2,3}.txt`；向量 B `/tmp/kbench-perf/B_T{1,2,3}_trial{1,2,3}.txt`。

---

## 10. v6 R7 自动双栈实测结论（commit 13b418191）

> 本节为 v6 native 自动双栈的实测结论。§10.2 的 vector A A/B 吞吐为 **v6 默认双建/双驱动口径**真机实测（helloworld 纯 IPv4、链宏开 lib，仅切 config `kernel_coexist` 0/1，client wrk 4.2.0 压 DPDK 网卡 9.134.214.176:80）。§4/§5 仍为 v5 per-fd 二选一口径 FINAL，保留作历史对照。

### 10.1 实测 / 确证项

| 项 | 证据 | 结论 |
|---|---|---|
| 宏关零回归（编译期） | `nm libfstack.a` 共存符号=0；size 6539682 与基线逐字节一致 | PASS（与原 F-Stack 同二进制） |
| 宏开编译 | `make FF_KERNEL_COEXIST=1` rc=0；共存符号齐全（含 `ff_native_fd_map`） | PASS |
| 单测双态 | 宏关 P1 50/50；宏开 P1 含 `test_ff_native_fd_map`/`test_ff_kernel_fd_encode_roundtrip` | PASS |
| 真机双栈功能（一 listen 多用） | 单 `listen(80)`：内核 `curl 127.0.0.1:80=200`；F-Stack `ssh→9.134.214.176:80=200` | PASS |
| PERF-1/2 F-Stack 快路径无回归 | §10.2 vector A A/B 真机实测 | PASS |
| PERF-4 热路径不查 map | recv/send 仅 `ff_is_kernel_fd` 单次判定不查 map（代码）+ §10.2 keep-alive 长连接吞吐 A1≈A0（实测佐证） | PASS |

### 10.2 vector A：v6 默认双建对 F-Stack 业务快路径 A/B（PERF-1/2，真机实测）

> 同一 helloworld（纯 IPv4、链宏开 lib），仅切 `config.ini [stack] kernel_coexist`：A0=0（纯 F-Stack）/ A1=1（v6 默认双建/双驱动）。client（f-stack-client，掩码 192.168.1.2）wrk 4.2.0 压 DPDK 网卡 9.134.214.176:80（掩码 192.168.1.1）；每档 3 trial 取 median；环境/方法同 §2/§3（单 lcore `lcore_mask=10`、`idle_sleep=20`、keep-alive）。

吞吐 req/s（median of 3）：

| 档位 | A0 共存关 | A1 v6 双栈 | Δ (A1 vs A0) | 三次 trial（A0 / A1） |
|---|---:|---:|---:|---|
| T1 (-t2 -c10 5s)   | 28,216 | 27,729 | **−1.73%** | A0 28216/28213/28606 · A1 26873/27729/27911 |
| T2 (-t4 -c100 30s) | 202,805 | 206,219 | **+1.68%** | A0 206117/202805/202697 · A1 202045/206219/206744 |
| T3 (-t8 -c500 30s) | 120,702 | 127,784 | **+5.87%** | A0 120702/110394/125671 · A1 128306/117037/127784 |

p99 延迟（median of 3）：

| 档位 | A0 p99 | A1 p99 |
|---|---:|---:|
| T1 | 526 us | 528 us |
| T2 | 726 us | 733 us |
| T3 | 206.22 ms | 208.25 ms |

- 全部 18 个 trial 无 socket error。

### 10.3 结论

v6 默认双建/双驱动开启（A1）与关闭（A0）的吞吐差异全部落在 trial 噪声内、无系统性负向：T1 −1.73%、T2 +1.68%、T3 +5.87%（A1 在 T2/T3 略快）；p99 基本相等（T1 ~526us、T2 ~730us、T3 ~206-208ms 同口径 c500 单 lcore 长尾，A0/A1 同现象）。与 v5 §4 结论一致——双建成本仅在 listen socket 建立时一次性付出，keep-alive 连接的数据热路径（recv/send）单栈、不查 map（PERF-4），故对 F-Stack 业务快路径无可测量回归。

→ **PERF-1/2/4 PASS（v6 真机实测）：v6 native 自动双栈对 F-Stack 业务快路径不引入可测量回归（NFR-1/NFR-2），F-Stack 始终承担业务（NFR-3）。**

> 原始 wrk 输出（IP 掩码后）：`/tmp/perf/A{0,1}_T{1,2,3}_tr{1,2,3}.txt`（测后经 `rm_tmp_file.sh` 清理）。
