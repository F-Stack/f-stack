# M1 — 23.11.5 Baseline 采集摘要

> 阶段二 - M1 实测落档（2026-06-09 15:35 UTC+8）
> 上游：spec 04 §M1
> Status：✅ DONE（编译指标 + helloworld 性能基线已采集；nginx 性能基线推迟到 M5 配对）

---

## 1. 编译指标（M1 Step 2.2.1）

| 指标 | 23.11.5 baseline 值 |
|---|---|
| `dpdk/build` ninja 增量 exit | 0 |
| `dpdk/build` errors | 0 |
| `dpdk/build` warnings | 4（含 1 个 kernel/compiler 不匹配 warning） |
| `dpdk/build` 总 size | 623 MB |
| `librte_eal.a` | 835 328 bytes |
| `librte_ethdev.a` | 825 506 bytes |
| `lib/libfstack.a` | clean rebuild OK / 0 errors |
| `example/helloworld` | 29 021 744 bytes |
| `example/helloworld_epoll` | 29 019 656 bytes |
| `example/helloworld_zc` | skip — `[M10 skip] libfstack.a built without FF_ZC_SEND` |

build log 落档：`/tmp/m1_dpdk_23_build.log` + `/tmp/m1_lib_build.log` + `/tmp/m1_example_build.log`

---

## 2. helloworld 性能基线（M1 Step 2.2.2）

### 2.1 测试环境

| 维度 | 值 |
|---|---|
| Server | 9.134.214.176 (CVM, virtio-net `0000:00:09.0`) |
| Client | f-stack-client (9.134.211.87) |
| Helloworld config | `/data/workspace/f-stack/config.ini`（与 production 同；从 `/data/workspace/config.ini` 复制覆盖以修复 git checkout 重置）|
| 关键 config | `lcore_mask=10` / `idle_sleep=20` / `addr=9.134.214.176` |
| Harness | `tools/sbin/p5b_perf_matrix.sh`（phase-5b methodology） |
| ssh round-trip | ~ 6 ms（物理上限；性能数字仅作跨配置 delta 用） |

### 2.2 helloworld primary init log（关键关键字命中）

```
EAL: Probe PCI driver: net_virtio (1af4:1000) device: 0000:00:09.0
Port 0 MAC: 20:90:6F:7D:5D:08
Port 0 Link Up - speed 4294967295 Mbps - full-duplex
ipfw2 (+ipv6) initialized, divert loadable, nat loadable, default to accept, logging disabled
tcp_bbr is now available
f-stack-0: Successed to register dpdk interface
```

### 2.3 网络连通性预检

| 测试 | 结果 |
|---|---|
| `ssh f-stack-client ping -c 3 -W 2 9.134.214.176` | **3/3 received, 0% loss, RTT 0.301-0.459 ms** |
| `ssh f-stack-client curl http://9.134.214.176/ -w '%{http_code} %{time_total}'` | **HTTP=200 / time=0.93 ms** |

### 2.4 TC1 — 100 短连 × 3 trials

| trial | t_total (s) | pass_count | fail_rate |
|---|---|---|---|
| 1 | 0.720842958 | 100/100 | 0.000 |
| 2 | 0.730526620 | 100/100 | 0.000 |
| 3 | 0.731231745 | 100/100 | 0.000 |

**Summary**：
- median = **0.731 s**
- min = 0.721 s / max = 0.731 s
- jitter = 0.010 s（极低噪音）
- pass_rate = **300/300 (100%)**

### 2.5 TC2 — 1000 短连 × 3 trials

| trial | t_total (s) | pass_count | fail_rate |
|---|---|---|---|
| 1 | 7.217576704 | 1000/1000 | 0.000 |
| 2 | 7.244315212 | 1000/1000 | 0.000 |
| 3 | 7.448975550 | 1000/1000 | 0.000 |

**Summary**：
- median = **7.244 s**
- min = 7.218 s / max = 7.449 s
- jitter = 0.231 s
- pass_rate = **3000/3000 (100%)**
- implied conn/s ≈ 1000 / 7.244 ≈ **138 conn/s**（与 phase-5b 同时段 ~137 一致；ssh round-trip dominated）

### 2.6 数据落档

| 文件 | 路径 |
|---|---|
| TC1 csv | `baseline_data/23-baseline_TC1.csv` |
| TC1 summary | `baseline_data/23-baseline_TC1.summary` |
| TC2 csv | `baseline_data/23-baseline_TC2.csv` |
| TC2 summary | `baseline_data/23-baseline_TC2.summary` |

---

## 3. nginx 性能基线 — 推迟到 M5

实测 `f-stack/app/nginx-1.28.0/objs/nginx` **不存在**（nginx_fstack binary 未 build）。按 06-test-and-acceptance-spec.md §6.2 OQ-2 默认许可降级路径，nginx 23.11.5 baseline 推迟到 M5 阶段：M5 启动前先 build nginx_fstack（在 23.11.5 树上）→ 跑 23 baseline → 切换到 24.11.6 → 跑 24 nginx → 配对对比。这避免单独为 23 baseline build 一遍 nginx。

---

## 4. 结论

✅ M1 完成。23.11.5 编译指标 + helloworld 性能基线全部落档：
- 编译指标：dpdk/build 623MB / lib/libfstack.a / example/helloworld 29 MB
- TC1 baseline = **0.731 s**（100/100 PASS）
- TC2 baseline = **7.244 s**（1000/1000 PASS）
- jitter 极低（TC1 0.010s / TC2 0.231s），数据可信

→ **进入 M2** 整树替换 23.11.5 → 24.11.6。
