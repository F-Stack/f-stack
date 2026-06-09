# 06 — 测试与验收 Spec（Test & Acceptance）

> 文档版本：v0.1（2026-06-09）
> Parent plan：`plan.md`
> 上游文档：`00 / 01 / 02 / 04`
> 复用方法学：`freebsd_13_to_15_upgrade_spec/zh_cn/phase-5b-perf-baseline-spec.md` 的 phase-5b curl-bench 模式

---

## 1. 测试矩阵总览

按 plan q3=A 决策，本 spec 单文档涵盖全部 7 个测试用例（TC-A ~ TC-G）。

| TC | 内容 | 分类 | Owner |
|---|---|---|---|
| **TC-A** | helloworld 单进程功能 | functional | gate-keeper |
| **TC-B** | helloworld 单进程性能 | perf | gate-keeper |
| **TC-C** | nginx 单进程功能 | functional | gate-keeper |
| **TC-D** | nginx 单进程性能 | perf | gate-keeper |
| **TC-E** | nginx 多进程功能（含 reload + worker exit） | functional | gate-keeper |
| **TC-F** | nginx 多进程 wrk 功能（无水平扩展评估） | functional | gate-keeper |
| **TC-G** | F-Stack phase-2 + vlan-test 历史能力 single-pass smoke | regression | gate-keeper |

---

## 2. 通用前置 / 后置

### 2.1 前置条件（每个 TC 启动前）

```bash
# 1. 清理 DPDK runtime 残留（防止 stale primary 干扰）
/data/workspace/rm_tmp_file.sh \
  /var/run/dpdk/rte/config \
  /var/run/dpdk/rte/fbarray_memseg-2048k-0-0 \
  /var/run/dpdk/rte/fbarray_memseg-2048k-0-1 \
  /var/run/dpdk/rte/fbarray_memseg-2048k-0-2 \
  /var/run/dpdk/rte/fbarray_memseg-2048k-0-3 \
  /var/run/dpdk/rte/fbarray_memzone \
  /var/run/dpdk/rte/hugepage_info

# 2. 杀掉残留进程（如有）
PIDS=$(ps -ef | grep -E 'helloworld|nginx_fstack' | grep -v grep | awk '{print $2}')
[ -n "$PIDS" ] && /data/workspace/kill_process.sh $PIDS
```

### 2.2 后置条件（每个 TC 结束后）

```bash
PID=$(ps -ef | grep -E 'helloworld|nginx_fstack' | grep -v grep | awk '{print $2}' | head -1)
[ -n "$PID" ] && /data/workspace/kill_process.sh $PID
sleep 2
```

### 2.3 工作区强制规约

- **0 直接 `rm/kill/chmod`** — 测试脚本内所有清理路径必须走 wrapper。违反即 G4 fail（gate-keeper 评审）。
- 进程探活用 `[ -d /proc/$PID ]`，**禁** `kill -0`。
- 失败截图 / log 落档至 `/tmp/dpdk24_test_<TC>_<timestamp>.log`，**禁** stdout 直接污染 spec 截图。

---

## 3. TC-A — helloworld 单进程功能

### 3.1 启动

```bash
cd /data/workspace/f-stack/example
setsid ./helloworld -c ../config.ini --proc-type=primary --proc-id=0 \
    </dev/null > /tmp/dpdk24_TC-A_hw.log 2>&1 &
LAUNCHED_PID=$!

# Poll up to 18s for primary to finish DPDK init + BSD stack init
t=0
while [ $t -lt 18 ]; do
    sleep 1; t=$((t+1))
    PID=$(ps -ef | grep './helloworld -c' | grep -v grep | awk '{print $2}' | head -1)
    [ -n "$PID" ] && [ -d "/proc/$PID" ] && \
        grep -q 'Successed to register dpdk interface' /tmp/dpdk24_TC-A_hw.log 2>/dev/null && break
done
```

### 3.2 G2 startup 验收

| AC | 检查 | PASS 条件 |
|---|---|---|
| TC-A.G2.1 | primary alive | `[ -d /proc/$PID ]` true |
| TC-A.G2.2 | DPDK init 关键字 | log 含 `EAL: Detected ...` + `Probe PCI driver ...` + `Port 0 Link Up` |
| TC-A.G2.3 | BSD stack init 关键字 | log 含 `ipfw2 (+ipv6) initialized` + `tcp_bbr is now available` + `f-stack-0: Successed to register dpdk interface` |
| TC-A.G2.4 | 0 SIGSEGV / panic / abort | grep `-iE 'sigsegv\|panic\|fatal\|abort'` = 0 hits |
| TC-A.G2.5 | 0 stub-called 关键字 | grep `'stub called'` = 0 hits |
| TC-A.G2.6 | DPDK 版本横幅 | log 含 `DPDK 24.11.6` 或 `RTE Version: ...24.11...` |

### 3.3 G3 functional 验收

```bash
# 在 server 端（DPDK primary 运行中）
ssh f-stack-client 'curl -sS -o /dev/null -w "%{http_code} %{size_download}\n" --connect-timeout 5 http://9.134.214.176/'
# 期望: 200 <body_size>

# 100x 短连
ssh f-stack-client 'OK=0; for i in $(seq 1 100); do
    CODE=$(curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 http://9.134.214.176/)
    [ "$CODE" = 200 ] && OK=$((OK+1))
done; echo $OK/100'
# 期望: 100/100
```

| AC | 检查 | PASS 条件 |
|---|---|---|
| TC-A.G3.1 | 单次 HTTP 200 + body | `200 <size>` 且 size > 0 |
| TC-A.G3.2 | 100x 短连 | `100/100` |

---

## 4. TC-B — helloworld 单进程性能（curl-bench）

### 4.1 方法学（复用 phase-5b）

- harness：`tools/sbin/p5b_perf_matrix.sh`
- 客户端：`f-stack-client (9.134.211.87)`
- 单 trial：N 次串行 curl from f-stack-client
- 每配置跑 3 trials，取 median + max-min jitter
- ssh round-trip ~ 6 ms 是物理上限（与 phase-5b 一致；本测试不追求绝对吞吐）

### 4.2 测试用例

| 子 TC | 命令 | 期望 |
|---|---|---|
| TC-B.1 (100 短连) | `time { for i in $(seq 1 100); do curl ... ; done; }` × 3 | median ≤ 23.11.5 baseline + 5%（NFR-D-1） |
| TC-B.2 (1000 短连) | `time { for i in $(seq 1 1000); do curl ... ; done; }` × 3 | 同上 |

### 4.3 G4 perf 验收

| AC | 检查 | PASS 条件 |
|---|---|---|
| TC-B.G4.1 | 100 短连 trade-off | median(24) / median(23) ≤ 1.05 |
| TC-B.G4.2 | 1000 短连 trade-off | 同上 |
| TC-B.G4.3 | pass_rate | 100/100 + 1000/1000 |
| TC-B.G4.4 | jitter | (max - min) / median ≤ 0.20 |

trade-off > 5% 时按 phase-5b OQ-2 规则降级为 observation 标签 + spec-author 修订阈值或用户决策。

### 4.4 落档

CSV：`/tmp/dpdk24_TC-B_curl_bench.csv` + 对照 23 baseline `m1_23_perf.csv`。

---

## 5. TC-C — nginx 单进程功能

### 5.1 nginx 单进程配置

```nginx
# /data/workspace/f-stack/app/nginx-1.28.0/conf/nginx_dpdk24_single.conf
worker_processes 1;
fstack_conf ../../../config.ini;

events {
    worker_connections 1024;
    use kqueue;
}

http {
    server {
        listen 80;
        server_name _;
        location / {
            return 200 "Hello from nginx single-worker on DPDK 24.11.6\n";
        }
    }
}
```

### 5.2 启动

```bash
cd /data/workspace/f-stack/app/nginx-1.28.0
setsid sudo ./objs/nginx -p . -c conf/nginx_dpdk24_single.conf </dev/null > /tmp/dpdk24_TC-C_nginx.log 2>&1 &
sleep 12
NGINX_PID=$(ps -ef | grep 'nginx_fstack\|nginx -p' | grep -v grep | grep -v worker | awk '{print $2}' | head -1)
```

### 5.3 G2 / G3 验收

| AC | 检查 | PASS 条件 |
|---|---|---|
| TC-C.G2.1 | nginx master alive | `[ -d /proc/$NGINX_PID ]` true |
| TC-C.G2.2 | DPDK + BSD init 同 TC-A | log 含 `Successed to register dpdk interface` |
| TC-C.G3.1 | 单次 curl HTTP 200 | `Hello from nginx single-worker on DPDK 24.11.6` |
| TC-C.G3.2 | 100x 短连 | 100/100 PASS |
| TC-C.G3.3 | 0 nginx error.log fatal | nginx 内部 error.log 0 fatal/segfault |

---

## 6. TC-D — nginx 单进程性能

### 6.1 测试方法

如 client 有 wrk 工具：
```bash
ssh f-stack-client 'wrk -t1 -c10 -d30s http://9.134.214.176/ 2>&1' | tail -10
```
否则降级为 100/1000 短连 curl loop（同 TC-B）。

### 6.2 G4 验收

| AC | 检查 | PASS 条件 |
|---|---|---|
| TC-D.G4.1 | wrk req/sec（如可用）| ≥ 23.11.5 baseline × 0.95 |
| TC-D.G4.2 | curl loop trade-off（降级路径）| 同 TC-B.G4.1 / 4.2 |

---

## 7. TC-E — nginx 多进程功能（**重点验证 92718178b + 62f1c34df**）

### 7.1 nginx 多进程配置

```nginx
worker_processes 4;
fstack_conf ../../../config.ini;
# ... 其余同 TC-C
```

### 7.2 启动 + 验证

```bash
cd /data/workspace/f-stack/app/nginx-1.28.0
setsid sudo ./objs/nginx -p . -c conf/nginx_dpdk24_multi.conf </dev/null > /tmp/dpdk24_TC-E_nginx.log 2>&1 &
sleep 18  # 多 worker init 时间长
ps -ef | grep nginx | grep -v grep
# 期望：1 master + 4 worker（按 lcore 绑定）
```

### 7.3 G3 验收

| AC | 检查 | PASS 条件 |
|---|---|---|
| TC-E.G3.1 | master + 4 worker 全 alive | ps grep 显示 5 个 nginx 进程 |
| TC-E.G3.2 | 单次 curl HTTP 200 | 200 |
| TC-E.G3.3 | 100x 短连 | 100/100 |

### 7.4 92718178b patch 有效性验证

```bash
# Step 1: 取一个 worker PID（secondary 进程）
WORKER_PID=$(ps -ef | grep 'nginx: worker' | grep -v grep | awk '{print $2}' | head -1)

# Step 2: SIGTERM 这个 worker（模拟 secondary 退出）
/data/workspace/kill_process.sh $WORKER_PID

# Step 3: 检查 master 是否仍 alive，是否仍能响应 curl
sleep 5
[ -d /proc/$NGINX_MASTER_PID ] && echo "Master alive after worker exit ✓"
ssh f-stack-client 'curl -sS http://9.134.214.176/ -w "%{http_code}\n" -o /dev/null'
# 期望 200
```

| AC | 检查 | PASS 条件 |
|---|---|---|
| TC-E.G3.4 | worker 退出后 master alive | `[ -d /proc/$NGINX_MASTER_PID ]` true |
| TC-E.G3.5 | 仍能 curl HTTP 200 | 200 |
| TC-E.G3.6 | master log 0 abort/SIGSEGV | grep 0 hits |

→ 此 AC 验证 `92718178b` patch 在 24.11.6 上有效（secondary 退出时不 reset 共享设备）。

### 7.5 62f1c34df patch 有效性验证（reload 测试）

```bash
# nginx -s reload 模拟 secondary 重启
sudo ./objs/nginx -p . -c conf/nginx_dpdk24_multi.conf -s reload
sleep 12

# 验证新 worker 起栈成功，无 timer 死循环
ps -ef | grep 'nginx: worker' | grep -v grep
# 期望：4 个 worker 全部新启
```

| AC | 检查 | PASS 条件 |
|---|---|---|
| TC-E.G3.7 | reload 后新 worker × 4 全启 | ps 显示 4 个 worker，PID 与 reload 前不同 |
| TC-E.G3.8 | reload 后 100x 短连 | 100/100 |
| TC-E.G3.9 | log 中无 timer 死循环关键字 | grep `-iE 'timer.*infinite\|stuck\|hang'` = 0 hits |

→ 此 AC 验证 `62f1c34df` patch 的 `rte_timer_meta_init()` 在 24.11.6 上有效（secondary 重启时清 priv_timer 状态）。

---

## 8. TC-F — nginx 多进程 wrk 功能（无水平扩展评估）

### 8.1 测试方法

```bash
ssh f-stack-client 'wrk -t1 -c20 -d10s http://9.134.214.176/ 2>&1' | tail -10
```

### 8.2 G3 验收（仅功能）

| AC | 检查 | PASS 条件 |
|---|---|---|
| TC-F.G3.1 | wrk 完成无 connection error | wrk output `Socket errors: connect 0, read 0, write 0, timeout 0` |
| TC-F.G3.2 | wrk 至少 1 次 HTTP 200 | wrk output `Non-2xx or 3xx responses: 0` |
| TC-F.G3.3 | nginx master + 4 worker 全 alive | ps grep 5 个 nginx 进程 |

> **注意**：本 TC **不**评估 wrk 的 req/sec、rps 随 worker 数线性扩展等水平扩展性能指标。这些指标由用户后续在物理机环境完成。本 TC 仅验证多 worker 同时承载并发请求时**功能正常**。

---

## 9. TC-G — F-Stack 历史能力 single-pass smoke

### 9.1 范围

按 plan §1.5 表，F-Stack phase-2 启用的 7 个 FF_* flag + vlan-test 配置在 24.11.6 上做 single-pass smoke：

| 子 TC | 测试 | 期望 |
|---|---|---|
| TC-G.1 | FF_NETGRAPH + FF_IPFW (M6 P0) | helloworld 起栈 + `tools/sbin/ipfw show` 列出默认规则 |
| TC-G.2 | FF_USE_PAGE_ARRAY (M7 P1a) + F-A1 fix 后稳定 | helloworld 起栈 + 100x curl 100/100 |
| TC-G.3 | FF_ZC_SEND (M8 P1b) | helloworld_zc 起栈 + 100x curl HTTP 200 |
| TC-G.4 | PA + ZC combo (M9 P1c) | 同上 |
| TC-G.5 | FF_FLOW_IPIP (M10 P1d) | helloworld 起栈 + GIF 隧道 ping 通（如 client 端可配）|
| TC-G.6 | FF_LOOPBACK_SUPPORT (M13 P2c) | helloworld 起栈即可 |
| TC-G.7 | VLAN + vip + ipfw_pr | 复用 `vlan_test_validate.sh G2 + G3`（必须 PASS clone_ok=2 + 0 vip fail + ipfw show 含 setfib 规则）|

### 9.2 G3 验收

每个子 TC 执行 ≤ 5 min；任一失败：

| 处理 | 触发条件 |
|---|---|
| **降级 observation** | 3 个或以下子 TC fail，且根因明确（如 NIC 硬件依赖）|
| **bounce → coder** | ≥ 4 个子 TC fail，且根因可能在 DPDK 24 升级 |
| **拆独立 phase** | 单个子 TC fail 但根因复杂（如 PA + 24 mbuf 字段微调互动），不阻塞主升级 |

### 9.3 命令范例（TC-G.7 vlan-test）

```bash
cd /data/workspace/f-stack
# 复用 vlan-test harness（已就位）
bash tools/sbin/vlan_test_validate.sh G2 2>&1 | tee /tmp/dpdk24_TC-G7_vlan.log
sleep 3
bash tools/sbin/vlan_test_validate.sh G3 2>&1 | tee -a /tmp/dpdk24_TC-G7_vlan.log
```

期望 G2 + G3 全 PASS（与 vlan-test 项目结束时一致）。

---

## 10. 验收门 G1 / G5 / G6 / G7（实施阶段补充）

| Gate | 验收 | 失败处理 |
|---|---|---|
| **G1** build | 见 04 §M2 / M4 ACs | bounce → coder |
| **G5** doc | 04 §M6 ACs（顶层 doc 同步）| doc-updater |
| **G6** lint | `read_lints` 0 errors | doc-updater |
| **G7** commit | 04 §8.2 commit 形态（3-4 commit）| leader |

---

## 11. 性能基线 23 vs 24 对比落档（M5 完成后）

`/data/workspace/f-stack/docs/dpdk_23_24_upgrade_spec/zh_cn/baseline_data/perf_compare.md`：

| 测试 | 23.11.5 median (s) | 24.11.6 median (s) | Δ % | 阈值 | PASS? |
|---|---|---|---|---|---|
| TC-B.1 (100 短连) | (M1 落档) | (M5 实测) | 计算 | ≤ +5% | Y/N |
| TC-B.2 (1000 短连) | 同上 | 同上 | 同上 | 同上 | 同上 |
| TC-D wrk req/sec | 同上 | 同上 | 同上 | ≥ 0.95× | 同上 |

---

## 12. observation 标签管理

按 phase-5b OQ-2 同款规则，性能 trade-off > 5% 但 < 10%：

- 标 `observation`，**不阻塞** spec / 实施完成
- spec-author 在 04-port-and-impl.md §6.1 加注 `Known perf observation: TC-X +N% vs baseline; reason: <hypothesis>`
- 阶段二完成时由用户决策：(a) 接受 (b) 拆独立 phase 优化 (c) 修订 NFR-D-1/D-2 阈值

---

## 13. 文档元信息

- **状态**：v0.1 DRAFT — 待 gate-keeper 评审
- **遗留待阶段二实测**：性能数据 baseline 与 24 对比、wrk 是否在 client 可用、TC-G 各子 TC 的具体 binary 是否就绪
- **下一步**：gate-keeper 出具 `99-review-report.md` 评审本 spec 与上游 4 篇的一致性 / 完整性 / 风险覆盖度 / 可执行性
