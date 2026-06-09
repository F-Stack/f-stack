# 01 — 需求规约（Requirements Spec）

> 文档版本：v0.1（2026-06-09）
> Parent plan：`plan.md`
> 上游文档：`00-overview-and-glossary.md`

---

## 1. 项目目标（What）

把 F-Stack 当前内嵌的 **DPDK 23.11.5 LTS** 升级到 **DPDK 24.11.6 LTS**，使 F-Stack 主要功能（helloworld primary、nginx 单/多进程）在新 DPDK 上**功能等价 + 性能不退化**地工作，同时保留 F-Stack 已积累的 3 个 DPDK 本地 patch。

---

## 2. 功能性需求（FR）

| ID | 描述 | 验收 |
|---|---|---|
| **FR-D-1** | F-Stack 整树替换 23.11.5 → 24.11.6 后，`dpdk/build/` 通过 `meson setup build && ninja -C build` 编译 0 errors（warnings 与 23.11.5 baseline 持平 ±10%） | TC-G1（见 06-test §G1）|
| **FR-D-2** | 重打 3 个 F-Stack 历史 patch（`5f3768c63` + `62f1c34df` + `92718178b`）后，`dpdk/build/` 仍 0 errors；patch 等价性自检（diff 与原 commit 相比仅有上下文行差异）| TC-G1.5 |
| **FR-D-3** | F-Stack 的 `lib/libfstack.a` 与 `example/{helloworld, helloworld_zc, helloworld_epoll}` 全编译通过（0 errors，warnings 不超过 freebsd-15 baseline 57 + 5 = 62）| TC-G2 |
| **FR-D-4** | `helloworld` primary 在 24.11.6 上起栈成功（含 `f-stack-0: Successed to register dpdk interface` 等关键 init log），存活 ≥12 秒无崩溃 | TC-A.G2 |
| **FR-D-5** | client → server (`9.134.214.176`) 单次 curl 返回 HTTP 200 + 真实 HTML body | TC-A.G3.1 |
| **FR-D-6** | client → server 100 次短连：100/100 PASS | TC-A.G3.2 |
| **FR-D-7** | nginx (`app/nginx-1.28.0/`) 单进程模式起栈 + curl 静态页 HTTP 200 + 100 短连 100/100 | TC-C.G3 |
| **FR-D-8** | nginx 多进程模式（`worker_processes 4`）起栈：1 master + 4 worker 全部 alive；客户端 curl + wrk 至少完成 1 次成功 HTTP 200 响应 | TC-E.G3 |
| **FR-D-9** | F-Stack patch `92718178b` 在 24.11.6 树上有效：secondary 进程退出（如 SIGTERM nginx worker）时 primary（nginx master）不崩溃 | TC-E.G3.exit |
| **FR-D-10** | F-Stack patch `62f1c34df` 在 24.11.6 树上有效：secondary 进程重启（如 nginx -s reload）时不进入 timer 死循环 | TC-E.G3.reload |
| **FR-D-11** | F-Stack 历史能力（IPFW、NETGRAPH、IPIP 隧道、VLAN+vip+ipfw_pr 等 phase-2 + vlan-test 启用 flag）在 24.11.6 上 single-pass smoke 通过（不做完整 5×3 矩阵）| TC-F.G3 |

---

## 3. 非功能性需求（NFR）

| ID | 描述 | 阈值 | 来源 |
|---|---|---|---|
| **NFR-D-1** | helloworld 单进程性能 trade-off vs 23.11.5 baseline | 短连（100 次）/ 长连（1000 次）median 时间 ≤ +5% | phase-5b 方法学 |
| **NFR-D-2** | nginx 单进程性能 trade-off vs 23.11.5 baseline | 同上 | 同上 |
| **NFR-D-3** | 编译时间不退化 | 24.11.6 全树 build 时间 ≤ 23.11.5 全树 build 时间 × 1.3（允许 +30%，因新增 2 lib + eal/ethdev 各 +2 KLoC） | 实测 |
| **NFR-D-4** | `libfstack.a` 大小不爆炸 | ≤ 23.11.5 baseline × 1.10（允许 +10%，因 ethdev/hash 增量）| 实测 |
| **NFR-D-5** | 内存占用稳态不增加 | helloworld primary RSS 与 23.11.5 baseline ±5% | sleep 60s 后 ps 实测 |
| **NFR-D-6** | 测试期间无新的 SIGSEGV/panic/abort/SIGBUS 关键字 | grep stdout/stderr = 0 hits | 各 G2/G3 |

> 性能 trade-off > 5% 时按 phase-5b 同款规则降级为 observation 标签 + 用户决策（不阻塞 spec 完成；详 06-test §G4 决策矩阵）。

---

## 4. 边界条件

### 4.1 In-scope 测试（本 spec 阶段定义）

| 测试 | 要求 |
|---|---|
| TC-A | helloworld 单进程功能 + 性能 |
| TC-B | helloworld 单进程性能（curl-bench 100/1000）|
| TC-C | nginx 单进程功能（HTTP 200 + 100 短连）|
| TC-D | nginx 单进程性能（wrk if available, else curl loop）|
| TC-E | nginx 多进程功能（curl）+ FR-D-9/10 验证 |
| TC-F | nginx 多进程 wrk 功能（仅功能，无水平扩展评估）|
| TC-G | F-Stack phase-2 + vlan-test 历史能力 single-pass smoke |

### 4.2 Out-of-scope 测试

| 项 | 理由 |
|---|---|
| nginx 多进程水平扩展性能（rps 随 worker 数线性扩展）| 用户后续物理机环境完成；CVM ssh round-trip ~6 ms 决定单进程吞吐上限 |
| iperf 大流量吞吐 | 同上 |
| F-A1 / F-A3 / F-A4 等 phase-5b 历史 followup | 与本次 DPDK 升级解耦 |
| 完整 phase-2 五配置 × 3 trial 矩阵 | 升级阶段仅 single-pass smoke；如需完整矩阵留给后续独立 phase-5c |
| KNI 子系统重启用 | 与本次升级解耦（详 §6 风险登记 R-D2）|

---

## 5. 验收门禁（Gate Matrix）

| Gate | 内容 | 失败处理 |
|---|---|---|
| **G1 build** | dpdk/build + lib/libfstack.a + example/* 三层全 0 errors | 阶段二 bounce → coder |
| **G2 startup** | helloworld primary alive ≥12 s | 阶段二 bounce → coder（罕见 spec）|
| **G3 functional** | TC-A ~ TC-G 全 PASS | bounce → coder（spec 不充分则 spec）|
| **G4 perf** | NFR-D-1 / NFR-D-2 在 ±5% 内 | observation 标签或 spec 修订阈值 |
| **G5 doc** | 本 spec + 顶层架构 doc DPDK 版本 anchor 同步 | doc-updater |
| **G6 lint** | `read_lints` 0 errors | doc-updater |
| **G7 commit** | 2 个独立 commit（`replace:` + `port:`，详 plan.md §4.4） | leader |

---

## 6. 风险登记（每条均有 detection + mitigation）

| ID | 风险 | 检测 | 缓解 | Owner |
|---|---|---|---|---|
| **R-D1** | rte_eth_dev_info_get / rte_flow_create / rte_eth_rx_queue_setup 等 24.11 ABI break | 编译期 unresolved reference / signature mismatch | diff-comparator 已实测：F-Stack 调用的所有 rte_* API 在 24.11.6 仍存在且位置相同（**0 改名 / 0 废弃**），仅行级签名变化由阶段二修复 | coder |
| **R-D2** | ~~KNI 子系统在 24.11 完全移除（DPDK 22.11+ 已 deprecated）~~ → **N/A**（user 2026-06-09 14:50 反馈后闭环） | F-Stack 的 FF_KNI 是 ring + virtio_user 自实现（lib/Makefile:34 注释 + ff_dpdk_kni.c 0 rte_kni 引用），与 DPDK librte_kni 无关；upstream 23.11.5 / 24.11.6 / F-Stack 当前 dpdk/ 三方 lib/kni 均不存在 | **风险消除** — `FF_KNI=1` 维持，dpdk/ 仅含 igb_uio 一个内核模块（详 02 §3.6） | leader |
| **R-D3** | igb_uio 在 24.11 上游已移除 | 实测 `ls dpdk-stable-24.11.6/kernel/linux/igb_uio/` | 不影响升级 — F-Stack 自带 igb_uio (Copyright 2010-2017 Intel)，整树替换后 `dpdk/kernel/linux/` 子树由 5f3768c63 重打恢复 | patch-scout 已确认 |
| **R-D4** | secondary process eal_bus_cleanup 行为变化 | 24.11.6 `lib/eal/linux/eal.c` 的 `rte_eal_cleanup` 内 `eal_bus_cleanup()` 是否仍无条件调用 | dpdk-24-analyzer 已实测：**仍无条件调用**，stable 未合 25.07 真正 fix → `92718178b` patch **必须 rebase 重打** | coder |
| **R-D5** | priv_timer.is_running 在 lib/timer 24.11 上游零变化但 cache_align 宏迁移可能影响 ABI 偏移 | diff-comparator 已实测：lib/timer 文件大小完全一致（27.46/27.61 KB）；仅 `__rte_cache_aligned` 宏位置调整（`struct __rte_cache_aligned priv_timer { ... }` 替代 `struct priv_timer { ... } __rte_cache_aligned;`）；ABI 偏移**不变** | 阶段二编译验证通过即可（无需源码改动）| coder |
| **R-D6** | meson 24 / gcc 版本要求变化 | 02 §3.8 实测 dpdk-stable-24.11.6/meson.build 顶层 + sys_reqs.rst | 当前 CVM gcc 11+ + meson 1.x 满足；如不足 spec 阶段标注升级路径 | dpdk-24-analyzer |
| **R-D7** | 性能 trade-off > 5% （24.11 内部优化可能引入开销）| TC-B / TC-D 测量 | observation 标签 + 用户决策（与 phase-5b OQ-2 同款）| gate-keeper |
| **R-D8** | 与 phase-2 启用的 7 个 FF_* flag 共存性回归 | TC-G single-pass smoke | 单 pass 失败 → 拆分为独立 phase 处理；不阻塞主升级 | coder |
| **R-D9** | 与 freebsd 15.0 移植 + 41 netgraph + 14 ipfw 等子系统兼容性 | helloworld 起栈 log（含 `ipfw2 (+ipv6) initialized` + `tcp_bbr is now available`）| TC-A.G2 包含此项 | gate-keeper |
| **R-D10** | DPDK 内部 ABI_VERSION 24.0 → 25.0，影响外部链接 libfstack.a 的二进制兼容 | F-Stack 默认 static lib 链接，无 ABI 直接断裂；但若用户系统部署 dynamic libdpdk 需重编 | doc 注明（98 章），不阻塞 | leader |
| **R-D11** | `rte_ip.h` 在 24.11 被清空（21.6 KB → 210 B），内容拆分到 `rte_ip4.h` / `rte_ip6.h` | F-Stack `lib/ff_dpdk_if.c` `#include <rte_ip.h>` 是否依赖具体 IPv4/IPv6 结构体 | 阶段二 grep `struct rte_ipv4_hdr / struct rte_ipv6_hdr` in `f-stack/lib/ff_dpdk_*.c`；如需要补 `#include <rte_ip4.h>` 或 `<rte_ip6.h>` | coder |
| **R-D12** | nginx multi-worker 多 secondary 模式 fork 时 EAL 状态共享回归 | TC-E `nginx -s reload` 测试 | 与 R-D4 / FR-D-9 / FR-D-10 联动 | coder |

---

## 7. 关键决策点（DP）

### 7.1 已决策

| DP | 决策 | 依据 |
|---|---|---|
| DP-A1 ~ A8 | 见 `plan.md` §7.1 | 用户 q1~q4 + 2026-06-09 14:36 追加 |

### 7.2 spec 阶段调研后已闭环（DP-Bx）

| DP | 决策内容 | 实测结论 | 闭环依据 |
|---|---|---|---|
| **DP-B1** | `92718178b` patch 是否已被 24.11.6 上游合入 | **未合入** — 24.11.6 stable 内 `eal_bus_cleanup()` 仍是无条件调用；上游真正 fix 在 DPDK 25.07 commit `4bc53f8f0d64` | dpdk-24-analyzer Q3.b |
| **DP-B2** | 24.11.6 KNI 子系统状态 | **N/A** — KNI 真相：F-Stack 早在 `29c7d5835` 已主动从 dpdk/ 删除 KNI；F-Stack ff_dpdk_kni.c 是 ring + virtio_user 自实现不依赖 librte_kni；24.11.6 上游本就无 KNI lib/kernel module；FF_KNI=1 维持 | user 2026-06-09 14:50 反馈 + 02 §3.6 实测 |
| **DP-B3** | igb_uio 在 24.11.6 上游状态 | 上游已无 igb_uio（21.05 移除）；F-Stack 自带版本由 `5f3768c63` 重打恢复 | patch-scout Q4.1 + dpdk-24-analyzer Q7 |
| **DP-B4** | argparse / ptr_compress 是否需启用 | **不启用** — F-Stack 0 引用 | diff-comparator Q5 |
| **DP-B5** | meson / gcc 最低版本 | 02 §3.8 实测填充 | dpdk-24-analyzer Q8 |
| **DP-B6** | rte_flow / rte_ethdev API ABI break 数 | **0 改名 / 0 废弃** — F-Stack 调用的所有公开 API 在 24.11.6 中位置相同；仅行级签名差异 | diff-comparator Q4 |
| **DP-B7** | 性能 trade-off 阈值 5% 是否合理 | **沿用 5%** 与 phase-5b 一致；超阈值降 observation | NFR-D-1 / NFR-D-2 |

### 7.3 阶段二待决（DP-Cx）

| DP | 决策内容 | 决策时机 |
|---|---|---|
| DP-C1 | 整树替换前是否保留 `dpdk.bak-23.11.5/` 至阶段二全部 PASS | 建议**保留**直到 TC-A ~ TC-G 全 PASS；用户决策清理时机 |
| DP-C2 | 性能 trade-off 5%~10% 时 observation 标签是否升级为阻塞 | 阶段二实测后 |
| DP-C3 | TC-G phase-2 历史能力 smoke 失败时是否拆分独立 phase 处理 | 阶段二 bounce 时 |

---

## 8. 实施先决条件（Pre-conditions）

| # | 条件 | 验证 |
|---|---|---|
| 1 | F-Stack git working tree clean | `git status -sb` |
| 2 | 当前 23.11.5 baseline 编译成功 | 实测：`f-stack/dpdk/build/` 已存在 + `compile_commands.json` 可读 |
| 3 | 23.11.5 baseline 性能数据可拿到 | 阶段二启动前先跑 phase-5b matrix 在 23.11.5 上抓基线 |
| 4 | upstream 24.11.6 源就位 | `ls /data/workspace/dpdk-stable-24.11.6/lib/argparse/` 应存在 |
| 5 | 3 个历史 commit 可读（`5f3768c63 + 62f1c34df + 92718178b`）| `git --no-pager show <hash>` 验证 |
| 6 | rm/kill/chmod wrapper 脚本可用 | `ls -l /data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh` |
| 7 | f-stack-client (9.134.211.87) 可 ssh 通 | 测试时验证 |

---

## 9. 文档元信息

- **状态**：v0.1 DRAFT — 待 gate-keeper 评审
- **下一步**：阅读 `02-current-and-target.md` 了解 F-Stack 当前 patch 与 24.11.6 关键变更详情
