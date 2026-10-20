# F-Stack CVM 双机基准测试方法论

> 来源：从 §12.10 (helloworld) / §12.12 (helloworld_epoll) / §12.13 (nginx) / §12.14 (redis) / §12.15 (nginx 多进程) 共五次跨应用实测中抽象统一。
>
> 配套图：`cvm-bench-methodology.svg`（物理拓扑 + 操作泳道时序）。

---

## 0. 一句话概述

**两台 CVM、server 侧跑 DPDK + F-Stack** — server 侧 F-Stack 应用绑定 lcore 占管 NIC；**client 侧栈可选 kernel TCP/IP 或 F-Stack adapter**，按测试目的选择。同一时间窗口先后用 13.0 baseline 和 15.0 runtime-fix 两份二进制启动 server 做 A/B 对比。所有 client 端命令由 server 同机的 **AI AGENT 通过 ssh 下发**，stdout 经 ssh 隧道回流到 AI AGENT，落盘前由 sed 管道完成 IP 混淆。

---

## 1. 物理拓扑

| 角色          | 真实 IP（仅保留 D 段） | 文档混淆后    | 硬件 / 软件栈                                                       |
|---------------|------------------------|---------------|---------------------------------------------------------------------|
| server 数据面 | `x.x.x.176`            | `192.168.1.1` | server CVM 16 vCPU AMD EPYC 7K62 的弹性网卡，被 DPDK PMD 接管 → F-Stack 协议栈 |
| server 控制面 | `x.x.x.87`             | `192.168.1.3` | server 同机第二块网卡（未被 DPDK 接管，仍归 kernel），AI AGENT 通过此 IP 与 client 进行 ssh 通信 |
| client        | `x.x.x.67`             | `192.168.1.2` | CVM，virtio_net，运行 sshd + wrk / curl / redis-benchmark           |

**控制面 vs 数据面分离**（双 NIC + 单网卡架构）：
- 控制面（带外）：AI AGENT (本机) ── ssh ──> server 控制面 NIC (`x.x.x.87`) ──> client (`x.x.x.67`) sshd
- 数据面（带内）：client 注入工具 ──> server 数据面 NIC (`x.x.x.176`，DPDK PMD) ──> F-Stack 协议栈

server 数据面 NIC 必须由 DPDK PMD 接管（kernel 不再持有 IPv4 路径）；server 控制面 NIC 必须保留给 kernel，否则 AI AGENT 无法 ssh 到 client。

**Client 侧栈二选一**：

| 选项 | 路径                              | 用例                                               | 部署成本                |
|------|-----------------------------------|----------------------------------------------------|-------------------------|
| A    | Linux kernel TCP/IP（默认）       | 仅压 server，不关心 client 旁路                    | 最简，client NIC 归 kernel |
| B    | F-Stack adapter（fstack-client）  | 双端旁路、对齐生产、消除 kernel 网络抖动           | 需 client NIC 也由 DPDK 接管 |

栈选择不影响 A/B 结论的相对差异，但绝对吞吐会因栈不同而不同。

**两面互不干扰**：ssh 走 kernel 路径（server 端经控制面 NIC `x.x.x.87`，client 端不论是否启用 F-Stack 旁路 ssh 都走 kernel）；benchmark 数据面则走选定的栈，与 ssh 控制面物理上隔离在不同的 NIC 通道上。

---

## 2. 双树 A/B 切换约定

| 树            | 路径                                            | 用途                |
|---------------|-------------------------------------------------|---------------------|
| 15.0 rfix     | `/data/workspace/f-stack/`                      | 主开发树（runtime-fix） |
| 13.0 baseline | `/data/workspace/f-stack-13.0-baseline/`        | 历史基线对照        |

每棵树独立 build 出 `lib/libfstack.a` 和应用二进制（`helloworld` / `nginx_fstack_{15rfix,13baseline}` / `redis_fstack_{15rfix,13baseline}` 等），通过环境变量 `FF_PATH` 切换链接对象，避免互相覆盖。

---

## 3. 标准流程（10 步）

### ① 双树 build
```
make -C /data/workspace/f-stack/lib
make -C /data/workspace/f-stack-13.0-baseline/lib
```
产出 2 份独立的 `libfstack.a`。

### ② 应用双份编译
对每个被测应用 (helloworld / nginx / redis) 分别用两棵树的 `FF_PATH` 编译并安装到独立 prefix：
```
/usr/local/nginx_fstack_15rfix/    /usr/local/nginx_fstack_13baseline/
/usr/local/redis_fstack_15rfix/    /usr/local/redis_fstack_13baseline/
```
nginx 和 redis 因为受 chmod 规约约束，**不能跑 `make install`**（其内部含 `install -m`），改成手动 `mkdir -p + cp -p`。

### ③ Server 启动（其中一棵树）
```bash
cd /data/workspace/f-stack/example   # 或 /usr/local/<app>/sbin/
nohup ./<app> --conf <config.ini> --proc-type=primary >/tmp/<app>.log 2>&1 &
disown
```
- `nohup` + `disown`：脱终端后台运行，防 SIGHUP；
- `--proc-type=primary`：主进程身份，DPDK 申请 hugepage 并初始化 rtemap_*；
- 多进程模式：`config.ini` 的 `lcore_mask` 改成多 bit（`0x30` = 2 worker、`0xf0` = 4 worker），nginx.conf 的 `worker_processes` 必须等于 popcount(lcore_mask)，F-Stack 自动派生 `nb_procs / proc_id / proc_mask`。

### ④ Smoke 探测（AI AGENT 通过 ssh 下发，client 执行）
所有 client 端命令一律由 server 同机的 AI AGENT 通过 ssh 通道触发，命令 stdout 经 ssh 隧道回流到 AI AGENT，再写入 server 本地 `/tmp/<app>-bench/`：

| 应用           | AI AGENT 下发的命令                                              |
|----------------|-------------------------------------------------------------------|
| helloworld     | `ssh client "wrk -t2 -c10 -d5s http://192.168.1.1/" \| sed ...`   |
| nginx_fstack   | `ssh client 'for i in {1..10}; do curl -o /dev/null -s -w "%{http_code}\n" http://192.168.1.1/; done' \| sed ...`（期望 10× 200）|
| redis_fstack   | `ssh client "redis-cli -h 192.168.1.1 PING; redis-cli -h 192.168.1.1 SET smoke ..." \| sed ...` ⇒ `PONG` / `OK` |

smoke 必须在正式 benchmark 之前执行，以排除 server 启动失败 / 监听未就绪 / 协议栈异常。

### ⑤ Benchmark T1 / T2 / T3（AI AGENT 通过 ssh 下发）
| 档位 | wrk 参数               | redis-benchmark 等效                                  | 用途              |
|------|------------------------|--------------------------------------------------------|-------------------|
| T1   | `-t2 -c10 -d5s`        | `-c 10 -n 50000 --threads 2 -t ping,set,get`           | 轻载 + 冷启动剔除 |
| T2   | `-t4 -c100 -d30s`      | `-c 50 -n 500000 --threads 4 -t ping,set,get`          | 主回归判定        |
| T3   | `-t8 -c500 -d30s`      | `-c 200 -n 1000000 --threads 8 -P 16 -t set,get`       | 尾延迟敏感场景    |

下发模板：
```bash
ssh client "wrk -t4 -c100 -d30s http://192.168.1.1/" \
  | sed -e ...IP 混淆... \
  > /tmp/<app>-bench/wrk.txt
```

多进程功能验证（§12.15）只跑 T2 一档，因为目的是"功能 OK"而非 scaling。

### ⑥ 源头 IP 混淆（AI AGENT 落盘前 sed）
ssh 回流的 stdout 在写入工件前由 AI AGENT 的 sed 管道完成混淆（**真实 IP 仅在 ssh 隧道内出现，不会落盘**）：
```
| sed -e 's/x\.x\.x\.176/192.168.1.1/g' \
      -e 's/x\.x\.x\.67/192.168.1.2/g' \
      -e 's/x\.x\.x\.87/192.168.1.3/g' \
      -e 's/:<实际ssh端口>/:22/g'
```
> 此处 `x.x.x.176` 为占位写法表示真实 A/B/C 段被屏蔽、仅保留 D 段；实际命令中需替换成真实正则。
> `perf.data` 二进制不修改（信息密度低、可读性差，对外部信息泄漏风险极小）。

### ⑦ 终止 server master
```
/data/workspace/kill_process.sh <master_pid>
```
**绝不**直接 `kill` / `pkill` / `killall`；多进程场景只 kill master，secondary worker 收到 master 退出信号后自行退出。验证方式：`pgrep -af 'nginx: worker'` 或 `pstree -p <master_pid>`。

### ⑧ 清理 rtemap 残留
```
ls /dev/hugepages/rtemap_* | xargs /data/workspace/rm_tmp_file.sh
```
DPDK primary 退出后 hugepage 不会自动释放，必须 trash。漏清会导致下一次启动 "Cannot get hugepage information"。

### ⑨ 切换另一棵树
回到 ③，用另一份二进制重启 server，重复 ④⑤⑥⑦⑧。**同一时间窗口**完成 A/B 两轮，最大化降低 CPU 邻居 / 网络 jitter / clock skew 的基线漂移。

### ⑩ 文档落盘 + 配置还原
- 把 wrk / curl / redis-benchmark 的混淆后输出贴入 `runtime-fix-execution-log.md` 对应 §12.x：表格化对比 + 时间线 + 关键发现 + 工件清单 + 合规审计；
- 临时 sed 修改的 `*.conf` 必须从 `*.bak_1proc` 还原（多进程测试尤其重要，否则 server 下次启动会用错误的 lcore_mask）；
- `git commit` 用英文 message，**不 push**（按项目长效规约）。

---

## 4. 工件清单约定

| 路径                                        | 内容                            | 保留策略  |
|---------------------------------------------|---------------------------------|-----------|
| `/tmp/<app>-bench/curl_x10.txt`             | 10 次 curl HTTP code            | 单次测试  |
| `/tmp/<app>-bench/wrk.txt`                  | 30s wrk 输出（已 IP 混淆）      | 单次测试  |
| `/tmp/<app>-bench/T{1,2,3}.txt`             | redis-benchmark 三档输出        | 单次测试  |
| `/tmp/<app>-bench/<app>_stdout.log`         | server stdout（DPDK init / 异常）| 单次测试 |
| `/usr/local/<app>_fstack_*/`                | 双版本应用安装目录              | 永久保留  |
| `*.bak_1proc`                               | 配置还原备份                    | 永久保留  |
| `runtime-fix-execution-log.md §12.x`        | 实验记录正本                    | 永久（git） |

---

## 5. 跨应用结论一览（13 → 15 同环境同 lcore=4）

| 应用            | 模型                  | T2 Δ%       | T3 Δ%       | 备注                          |
|-----------------|-----------------------|-------------|-------------|-------------------------------|
| helloworld      | kqueue 同步阻塞       | −7.59%      | −9.37%      | **显著回归**                  |
| helloworld_epoll| epoll(LT) event loop  | (smoke OK)  | (单档)      | 仅功能验证                    |
| nginx_fstack    | epoll event loop      | −1.05%      | −0.55%      | 持平                          |
| redis_fstack    | ae(自定义) + pipeline | +0.10%~+5.37% | ≈0%       | **无回归甚至小幅领先**        |

结论：13→15 vendor 演进路径（tcp_default_output vtable wrapper / CUBIC 升级 / socket buffer locking 重构 / ether_nh_input pipeline）的负面影响被 event-driven 应用模型有效摊薄；redis 的 ae + pipeline 进一步将开销分摊到批处理中，对回归免疫力最强。

---

## 6. 检查清单（执行前过一遍）

- [ ] 双树 lib 是否最新（`ls -la lib/libfstack.a` 比对修改时间）
- [ ] 应用是否双份产出（两份二进制大小不同 ⇒ 链接的 lib 不同）
- [ ] `/dev/hugepages/` 启动前是否干净
- [ ] config.ini 的 `lcore_mask` 与多进程场景一致
- [ ] AI AGENT ↔ client 的 ssh 免密通道可用（`ssh client true` 一秒返回）
- [ ] client 侧栈选项确认（kernel 默认 / F-Stack adapter 需 fstack-client 已预装）
- [ ] sed IP 混淆管道是否串入了所有 ssh stdout 落盘路径（无真实 IP 漏写工件的风险）
- [ ] kill master 后是否所有 worker 已退出（`pgrep`）
- [ ] rtemap 是否清理（`ls /dev/hugepages/`）
- [ ] 临时 sed 改写的 conf 是否已从 bak 还原
- [ ] commit message 是否英文且未 push
