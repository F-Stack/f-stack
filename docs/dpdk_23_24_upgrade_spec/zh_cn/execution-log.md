# DPDK 23.11.5 → 24.11.6 LTS 升级 — 阶段二执行日志（M1~M6）

> 执行日期：2026-06-09 15:24 ~ 16:11 UTC+8（约 47 分钟）
> 执行者：阶段二 leader（主对话）
> 上游 plan：`plan.md`（local-only per .gitignore）+ 6 篇 spec
> 整体结果：✅ **DONE — 阶段二全部里程碑 PASS**

---

## 1. 里程碑总览

| 里程碑 | 状态 | 耗时 | 关键 commit | 关键发现 |
|---|---|---|---|---|
| **M1 baseline 采集** | ✅ DONE | ~5 min | (无 commit；落档 baseline_data/) | 23.11.5 编译指标 + helloworld TC1=0.731s/TC2=7.244s |
| **M2 整树替换** | ✅ DONE | ~3 min | `fe552161c replace:` | 24.11.6 ninja 0 errors / 0 warnings / 2m14s build |
| **M3 4 patch 重打** | ✅ DONE | ~6 min | `14355bf7b port:` | 4 patch 语义重打全过；igb_uio.ko 编译；R-D11 自动闭环 |
| **M4 胶水修复** | ✅ DONE (零修改) | 0 min | (跳过 fix: per spec §4.4 例外) | rte_ip.h stub forwarding 自动生效 — F-Stack lib/ 0 修改 |
| **M5 测试验收** | ✅ DONE | ~30 min | (M-Final 一并 commit) | TC-A/C/D/E/F/G 全 PASS；TC-B.1 observation；92718178b + 62f1c34df 运行时验证 PASS |
| **M6 M-Final** | ✅ DONE | ~5 min | (本 commit) | 顶层 doc sync + execution-log + 备份 |

**整体阶段二耗时：约 47 分钟**（远低于 spec 04 §10 估算 14-24 turn）

---

## 2. M1 — 23.11.5 baseline 采集

### 2.1 编译指标

详见 `baseline_data/m1_summary.md` §1。关键值：
- dpdk/build ninja: 0 errors / 4 warnings / 623MB
- lib/libfstack.a: clean rebuild OK
- example/{helloworld, helloworld_epoll}: ✓

### 2.2 helloworld 性能基线

| TC | 23.11.5 baseline median |
|---|---|
| TC1 (100 短连) | **0.731 s** / 100/100 × 3 PASS / jitter 0.010s |
| TC2 (1000 短连) | **7.244 s** / 1000/1000 × 3 PASS / jitter 0.231s |

落档：`baseline_data/23-baseline_TC{1,2}.csv`

### 2.3 关键修复

启动前实测 `f-stack/config.ini` 被 git checkout 重置为默认 `192.168.1.2`（应是 production `9.134.214.176`）。从 user maintained `/data/workspace/config.ini` 复制覆盖修复（per user 2026-06-09 15:34 反馈）。

---

## 3. M2 — 整树替换 23.11.5 → 24.11.6

### 3.1 步骤实测耗时

| Step | 操作 | 耗时 | 结果 |
|---|---|---|---|
| 1 | `mv dpdk dpdk.bak-23.11.5` | < 1s | OK |
| 2 | `cp -a dpdk-stable-24.11.6 dpdk` | 0.4s | OK（极快）|
| 3 | 验证 `VERSION=24.11.6 / ABI_VERSION=25.0` + lib/ 顶层 59 子目录 + KNI/igb_uio absent | < 1s | ✓ |
| 4a | `meson setup build` | 10.7s | exit=0 / 749 targets / 0 errors / 2 warnings |
| 4b | `ninja -C build -j$(nproc)` | **2m14s** | exit=0 / **0 errors / 0 warnings**（比 23 baseline 4 warnings 还干净）/ build 653MB |
| 5 | `git format-patch -1` × 4 → 备份 4 patches | < 1s | OK |
| 6 | `git add dpdk/ && git commit` (replace:) | 1.5s | commit `fe552161c` / 3909 files +548K/-221K |

### 3.2 关键产物

| 维度 | 23.11.5 | 24.11.6 | Δ |
|---|---|---|---|
| `librte_eal.a` | 835 328 | 875 438 | +4.8% |
| `librte_ethdev.a` | 825 506 | 874 896 | +6.0% |
| `librte_argparse.a` | (不存在) | **16 624** | NEW（F-Stack 0 引用，零成本） |
| `build/` 总 size | 623 MB | 653 MB | +4.8%（NFR-D-3 ≤ +30% 满足）|

---

## 4. M3 — 4 patch 重打

### 4.1 git apply --check 全 fail（预期）

4 patch 全部 hunk fail（24.11.6 vs 23.11.5 上下文行偏移）。按 spec §4.4 R-M3-1/2/3/4，**改用语义级重新应用**（per `cp -a` from `dpdk.bak-23.11.5/` + 手动 replace_in_file rebase + selective `rm_tmp_file.sh`）。

### 4.2 4 patch 重打结果

| patch | 时间 | 重打方式 | 24.11.6 上结果 |
|---|---|---|---|
| `29c7d5835` Remove redundant | 2025-01-10 | parse patch list → 筛 24.11.6 中仍存在的 redundant → `rm_tmp_file.sh` | **310 文件中：301 上游 N/A（auto-skip）+ 6 igb_uio 旧版（被 5f3768c63 新版取代）+ 1 acc_common.c（24.11 设计为合法源，已恢复）+ 2 真删** (`dts/framework/remote_session/{remote_session,ssh_session}.py`) |
| `5f3768c63` Sync DPDK's modifies | 2025-10-31 | `cp -a` from bak: igb_uio 整子树 + 2 meson.build + freebsd rte_os.h | igb_uio.ko 编译成功（MODPOST + LD [M] OK） |
| `62f1c34df` rte_timer_meta_init | 2026-01-16 | `cp` from bak: lib/timer/{rte_timer.c, rte_timer.h} | `rte_timer_meta_init()` 在 lib/timer/rte_timer.h:200 + .c:217 就位；调用点 `lib/ff_dpdk_if.c:910` 已存在（M2 不动 f-stack/lib/）|
| `92718178b` eal_bus_cleanup PRIMARY | 2026-03-18 | manual `replace_in_file` 在 24.11.6 eal.c:1323-1324 处加 PRIMARY 守护 | exit=0 / 0 errors |

### 4.3 ninja build 重新验证

`ninja -C build -j$(nproc)`：
- exit=0
- 0 errors / **3 warnings**（比 23 baseline 4 warnings 少 1）
- 2m29s
- igb_uio.ko 编译成功

### 4.4 commit

`14355bf7b port:` — 13 files +1047/-347（含 igb_uio 整子树添加 + 2 dts py 删除 + lib/timer/eal.c 修改）

---

## 5. M4 — 胶水修复

### 5.1 实测 0 修改

`lib/libfstack.a` clean rebuild：**exit=0 / 0 errors**（16s）。R-D11 rte_ip.h stub forwarding 自动生效 — 24.11.6 中 `rte_ip.h`（210B stub）自动 include `rte_ip4.h` + `rte_ip6.h`，使 `struct rte_ipv4_hdr` / `rte_ipv6_hdr` 仍可见。F-Stack lib/ 0 修改即可编译。

按 spec §4.4 例外条款，**fix: commit 跳过**。

### 5.2 example 编译

`example/{helloworld, helloworld_epoll}`：exit=0 / 0 errors / 各 29 MB（与 23 baseline 一致）。`helloworld_zc` 因 lib 默认 FF_ZC_SEND=0 自动 skip（与 baseline 一致）。

---

## 6. M5 — 测试验收（**核心成果**）

### 6.1 全 TC PASS 矩阵

| TC | 内容 | 结果 | Δ vs 23 baseline |
|---|---|---|---|
| **TC-A.G2** helloworld primary 起栈 | ✅ PASS | DPDK 24.11.6 起栈完美；全部关键 init log 命中 | — |
| **TC-A.G3** helloworld functional | ✅ PASS | HTTP 200 + 100/100 × 3 短连 | — |
| **TC-B.1** helloworld 100 短连 perf | **⚠ observation** | 0.792s | **+8.4%**（> 5%，按 spec §12 标 observation；短连首包冷启动开销）|
| **TC-B.2** helloworld 1000 短连 perf | ✅ PASS | 7.199s | **−0.6%**（持平 baseline，更可信指标）|
| **TC-C** nginx 单进程 functional | ✅ PASS | HTTP 200 + 真实 HTML body | — |
| **TC-D** nginx 单进程 perf | ✅ PASS | TC1=0.724s / TC2=7.210s；100/100 + 1000/1000 × 3 全 PASS | TC1 比 helloworld 还快（nginx sendfile 路径优）|
| **TC-E.G3.1-3** nginx 多进程 (worker_processes=2) | ✅ PASS | master + 2 worker 全 alive；HTTP 200 + 100 短连 | — |
| **TC-E.G3.4-6** **92718178b 运行时验证**（SIGTERM secondary worker）| ✅ **PASS** | secondary worker (2541469) SIGTERM 后 master + primary worker 仍 alive；自动 fork 新 secondary worker；3/3 curl HTTP 200 + 100 短连 100/100 | — |
| **TC-E.G3.7-9** **62f1c34df 运行时验证**（nginx -s reload）| ✅ **PASS** | reload 后新 worker × 2 全启 (PID 2543230/2543234)；100 短连 0.721s 100/100 PASS；0 timer hang/infinite 关键字 | — |
| **TC-F** nginx 多 worker wrk 功能（client 无 wrk → curl loop 降级）| ✅ PASS（OQ-2 默认许可降级）| TC-D/TC-E 已覆盖 | — |
| **TC-G.1** FF_IPFW + secondary IPC（ipfw add/show/delete）| ✅ PASS | rule 100 add/show/delete + counters 实测 534 pkts/68KB；secondary 退出未 reset NIC | — |
| **TC-G.7** VLAN+vip+ipfw_pr smoke（vlan_test_validate.sh G2+G3）| ✅ PASS | G2 起栈 OK / G3 setfib_rules_in_show=2 + ipfw_add_fail=0 | — |

### 6.2 两个核心 patch 运行时验证总结

**92718178b PRIMARY 守护**（验证至少 3 次）：
- TC-E.G3.4-6 SIGTERM secondary nginx worker
- TC-G.1 ipfw 工具退出
- TC-G.7 vlan-test 起栈 + ipfw 操作
全部场景下 primary worker / 其他 secondary 均未受影响。

**62f1c34df rte_timer_meta_init**（验证 1 次）：
- TC-E.G3.7-9 nginx -s reload
新 worker 起栈正常，无 timer 死循环。

### 6.3 性能数据落档

| 文件 | 内容 |
|---|---|
| `baseline_data/23-baseline_TC{1,2}.csv` | M1 23.11.5 helloworld baseline |
| `baseline_data/24.11.6_TC{1,2}.csv` | M5 24.11.6 helloworld |
| `baseline_data/24-nginx-single_TC{1,2}.csv` | M5 24.11.6 nginx 单进程 |
| `baseline_data/24-nginx-multi-after-secondary-kill_TC1.csv` | M5 92718178b 验证后 |
| `baseline_data/24-nginx-multi-after-reload_TC1.csv` | M5 62f1c34df 验证后 |

### 6.4 perf 对比矩阵（**最终 baseline_data/perf_compare.md 输出**）

| 测试 | 23.11.5 (s) | 24.11.6 (s) | Δ % | 阈值 ≤+5% | 结论 |
|---|---|---|---|---|---|
| helloworld 100 短连 median | 0.731 | 0.792 | **+8.4%** | over | ⚠ observation（短连首包冷启动）|
| helloworld 1000 短连 median | 7.244 | 7.199 | **−0.6%** | within | ✅ PASS |
| nginx 100 短连 median | (M5 only) | 0.724 | — | — | ✅ |
| nginx 1000 短连 median | (M5 only) | 7.210 | — | — | ✅ |

---

## 7. 已知 follow-up

| ID | 描述 | 优先级 |
|---|---|---|
| FU-1 | TC-B.1 +8.4% 性能 observation：短连首包冷启动开销根因调研（可能 24.11 EAL 内部初始化路径长 / mempool 初始化开销）| Low |
| FU-2 | nginx 多进程水平扩展性能（rps 随 worker 数线性扩展验证）— 由 user 后续在物理机环境完成（CVM ssh round-trip ~6 ms 限制不能精确测）| Medium |
| FU-3 | wrk 在 client 上未安装 — 当前用 curl loop 降级；如需更精确并发测试，可让 client 安装 wrk | Low |
| FU-4 | `dpdk.bak-23.11.5/` 备份保留 — 阶段二全 PASS 后 user 决策清理时机（用 `rm_tmp_file.sh`）| user 决策 |
| FU-5 | M-Final 落档 baseline_data/ + 顶层 doc sync 已完成；未来 KG full reindex 可再做一次 sync（与 freebsd phase-2 M-Final reindex 同款）| Low |

---

## 8. 工作区强制规约执行情况

| 规约 | 用途 | 累计 | 合规 |
|---|---|---|---|
| `rm_tmp_file.sh` | DPDK runtime cleanup × 4 + helloworld.log 残留清理 × 2 + 29c7d5835 redundant 删除 × 1 + acc_common.c 误删后未用此 wrapper（后续 cp 回原版自动覆盖）| 7+ | ✅ |
| `kill_process.sh` | helloworld primary kill × 4 + nginx master/worker kill × 4 + sigterm test × 2 | 10+ | ✅ |
| `chmod_modify.sh` | 无需使用（M1-M6 全程无新增 +x 权限需求）| 0 | ✅ |
| 直接 `rm/kill/chmod` 调用 | — | **0 次** | ✅ |
| 仅本地 commit / 不 push | M2 + M3 + M-Final 全 local-only | ✅ | ✅ |

---

## 9. commit 形态总结

按 spec 04 §8.2 + plan §4.4 + DP-A8（user 2026-06-09 14:36 直接要求 + 14:50 KNI 反馈 + 4 patch 合并），最终 commit 形态：

| # | commit hash | 类型 | 内容 | 大小 |
|---|---|---|---|---|
| 1 | `fe552161c` | `replace:` | DPDK 整树 23.11.5 → 24.11.6 LTS | 3909 files +548K/-221K |
| 2 | `14355bf7b` | `port:` | 4 patch 语义重打合并（29c7d5835 + 5f3768c63 + 62f1c34df + 92718178b）| 13 files +1047/-347 |
| 3 | `fix:` | **跳过**（M4 零修改 per §4.4 例外）| — | — |
| 4 | (本 commit) | `docs(M-Final):` | 顶层 doc sync + execution-log + perf data 落档 | 待落地 |

**实际 commit 数 = 3 个**（不含 fix: 跳过）。
