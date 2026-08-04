# _m17_F：M5 运行时验证实测记录（tester）

> 本文所有数据均为**实际执行**产出，命令与原始输出逐字摘录。凡未能实测者，明确写「无法验证 + 原因 + 原始报错」，**无任何估算或复制历史数字**。
> 历史基线（`plan-17` §5.1）仅作**对比参照**，与本轮实测数据分列，绝不混用。
> 测试机：本机（DPDK 独占网卡 IP `9.134.214.176`）；压测客户端：`f-stack-client`（hostname `VM-211-87-tencentos`，`/data/wrk/wrk`）。

---

## 阶段 0：被测版本指纹与构建新鲜度

### 0.1 工作区指纹（`git --no-pager diff --stat lib/`，2026-08-04 14:0x）

```
 lib/Makefile            |  4 ++++
 lib/ff_dpdk_if.c        |  8 +++++++-
 lib/ff_dpdk_if.h        |  1 +
 lib/ff_freebsd_init.c   | 46 ++++++++++++++++++++++++++++++++++++----------
 lib/ff_glue.c           |  7 +++++++
 lib/ff_host_interface.c |  8 ++++++++
 lib/ff_host_interface.h |  4 ++++
 lib/ff_kern_timeout.c   |  2 +-
 lib/include/sys/pcpu.h  |  2 +-
 9 files changed, 69 insertions(+), 13 deletions(-)
```

`git --no-pager status --short`（已跟踪文件部分）：

```
 M config.ini
 M lib/Makefile
 M lib/ff_dpdk_if.c
 M lib/ff_dpdk_if.h
 M lib/ff_freebsd_init.c
 M lib/ff_glue.c
 M lib/ff_host_interface.c
 M lib/ff_host_interface.h
 M lib/ff_kern_timeout.c
 M lib/include/sys/pcpu.h
```

> 注意：`_m17_E_coder_g1.md` §5.8 记录的 G1 最终态是**8 个文件**（不含 `ff_host_interface.c/.h`）。本轮实测时多出的这 2 个文件是 `coder` **正在补写的 DoD-1 探针**（`ff_probe_tid()`），见§0.3。

### 0.2 构建新鲜度（mtime 对比）

```
-rwxr-xr-x 30392672 2026-08-04 13:59:13.716146084 +0800 example/helloworld
-rwxr-xr-x 30386072 2026-08-04 13:59:14.774150269 +0800 example/helloworld_epoll
-rw-r--r--  7002076 2026-08-04 13:58:55.123072536 +0800 lib/libfstack.a
```

源码mtime（同一时刻抓取）：

| 文件 | mtime |
|---|---|
| `lib/Makefile` | 13:36:29|
| `lib/ff_glue.c` | 13:36:38 |
| `lib/ff_kern_timeout.c` | 13:38:19 |
| `lib/ff_dpdk_if.h` | 13:40:06 |
| `lib/include/sys/pcpu.h` | 13:53:21 |
| `lib/ff_dpdk_if.c` | 13:53:38 |
| `lib/ff_host_interface.c` | **14:01:42**（晚于二进制） |
| `lib/ff_host_interface.h` | **14:01:48**（晚于二进制） |
| `lib/ff_freebsd_init.c` | **14:02:17**（晚于二进制，且在我两次 `ls` 之间从 13:53:47 变为 14:02:17 —— 说明 `coder` 正在写） |

被测二进制指纹（`md5sum`）：

```
99f64556d93f61dc9493054c646d46c0example/helloworld
2bbd971525d7abec51cecd0c618674f4  lib/libfstack.a
```

### 0.3 探针就绪判定：**尚未就绪**

- `_m17_E_coder_g1.md` 中**无「第三轮：DoD-1 探针」一节**（只有 §1~§4 第一轮 + §5 第二轮）。
- 二进制中**不含探针字符串**（决定性证据）：

```
$ grep -c "M17-PROBE" example/helloworld
0
$ grep -c "M17-PROBE" lib/libfstack.a
0
```

- 但源码中探针已在写入：`git diff lib/ff_freebsd_init.c` 已含

```c
#if 1 /* M17 temporary probe (DoD-1): remove after M5 */
    printf("[M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu "
        "mp_ncpus=%d mp_maxid=%u curcpu=%d\n",
        (unsigned long)ff_probe_tid(), cpuid, pcpup->pc_cpuid,
        (unsigned long)pcpup->pc_zpcpu_offset, mp_ncpus, mp_maxid, curcpu);
#endif
```

以及 `ff_probe_slots()`（打印 `[M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p`），调用点

```
lib/ff_freebsd_init.c:245:    ff_probe_slots(cpuid);
lib/ff_freebsd_init.c:404:    ff_probe_slots(PCPU_GET(cpuid));
```

**结论**：当前磁盘上的 `example/helloworld`（md5 `99f6...46c0`）= **G1 第二轮改动、无探针**的构建。

**处置**（严格照leader 指派）：
1. 我**不自行 `make`**（源码正在被 `coder` 修改中，此刻编译得到的是半成品）。已 `send_message` 告知 leader 与`coder`：我在等探针构建完成。
2. 按指派「若探针尚未就绪，先做阶段 0 与阶段 3」，我用当前二进制（md5 `99f6...46c0`）先做**阶段 3（`thread_mode=0` 零回归）**——该档不依赖探针。
3. 阶段 3 每一轮前后都记录 `md5sum example/helloworld`，确保不会把 `coder` 中途替换的新二进制与旧数据混算。

### 0.4 阶段 0 开始时的 `config.ini` 状态（测完须逐项恢复）

| 键 | 值 |
|---|---|
| `[dpdk] lcore_mask` | `6` |
| `[dpdk] thread_mode` | `1` |
| `[dpdk] idle_sleep` | `20` |
| `[port0] addr` | `9.134.214.176` |

其余键未改动。恢复以文件编辑方式进行（**不用 `git checkout`**），且**全程不 `git add` / 不 `git commit`**。

### 0.5 环境自检

```
$ ps -ef | grep -E "helloworld" | grep -v grep
（空 —— 无残留进程）

$ wc -l example/helloworld.log example/f-stack-0.log example/f-stack-1.log
  379 example/helloworld.log
  934 example/f-stack-0.log
   60 example/f-stack-1.log

$ timeout 20 ssh f-stack-client "hostname; ls -l /data/wrk/wrk"
VM-211-87-tencentos
-rwxr-xr-x 1 root root 3181432 Jul 29 12:40 /data/wrk/wrk
```

日志基线行数（读新增内容时用 `tail -n +N`）：`helloworld.log` = 379、`f-stack-0.log` = 934、`f-stack-1.log` = 60。

**阶段 0 判定：PASS**（版本指纹已登记；构建新鲜度已核实并如实记录「探针未入二进制」；环境可用）。

---

## 阶段 0 补记：探针在阶段 3 执行期间就绪（被测二进制发生一次切换，已如实记录）

`coder` 于 **14:02:42 重建 `lib/libfstack.a`（7,003,564 字节）、14:02:53 重链 `example/helloworld`（30,392,704 字节）**，探针随之进入二进制。

| 时刻 | `example/helloworld` md5 | 含探针 |
|---|---|---|
| 阶段 0 早期抓取| `99f64556d93f61dc9493054c646d46c0` | 否（`grep -c "M17-PROBE"` = 0） |
| 14:02:53 之后（**阶段 3 与其后全部测试的实际被测二进制**） | `88b8cf93e0b8d3765e76b3c26c6a8f3b` | **是**（运行时确实打印 `[M17-PROBE]`） |

**阶段 3 的两个档位（1 进程 / 2 进程）都是用 md5 `88b8cf93…` 这一个二进制跑的**（启动前后各测一次 md5，值相同，未发生中途替换）。`git --no-pager diff --stat lib/` 在阶段 3 结束时为 `9 files changed, 100 insertions(+), 13 deletions(-)`（探针使 insertions 由 69 增至 100）。

---

## 阶段 3：`thread_mode=0` 零回归（DoD-4 / D7）

被测二进制：`example/helloworld` md5 **`88b8cf93e0b8d3765e76b3c26c6a8f3b`**（G1 + DoD-1 探针，`uma_crit_lock` **仍在** → 属「**G2 去锁前**」）。

### 3.1 档位 A：`thread_mode=0`、1 进程（`lcore_mask=2`）

`config.ini` 改动：`lcore_mask=6`→`2`、`thread_mode=1`→`0`（仅这两项，其余不动）。

启动命令（严格按规约用 `setsid nohup … < /dev/null &`，绝对路径）：

```bash
cd /data/workspace/f-stack/example
setsid nohup /data/workspace/f-stack/example/helloworld \
  --conf /data/workspace/f-stack/config.ini --proc-type=primary --proc-id=0 \
  < /dev/null >> /data/workspace/f-stack/example/helloworld.log 2>&1 &
```

启动成功，进程 `976023` 存活。`example/f-stack-0.log` 新增内容（原始摘录）：

```
lcore: 1, port: 0, queue: 0
create mbuf pool on socket 0
create ring:dispatch_ring_p0_q0 success, 2047 ring entries are now free!
Port 0 MAC:20:90:6F:7D:5D:08
LRO is disabled
TSO is disabled
set port 0 to promiscuous mode ok

Checking link statusdone
Port 0 Link Up - speed 4294967295 Mbps - full-duplex
[M17-PROBE] tid=140622480531456 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=1 mp_maxid=0 curcpu=0
link_elf_lookup_symbol: missing symbol hash table
link_elf_lookup_symbol: missing symbol hash table
TCP Hpts created 1 swi interrupt threads and bound 0 to cpus
Timecounters tick every 10.000 msec
Attempting to load tcp_bbr
tcp_bbr is now available
ipfw2 (+ipv6) initialized, divert loadable, nat loadable, default to accept, logging disabled
Timecounter "ff_clock" frequency 100 Hz quality 1
TCP_ratelimit: Is now initialized
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7fe538f8ec80 uma_cache=0x7fe538f83e00
f-stack-0: Addr6: 2402:4e00:1900:1:6:5522:de6a:7d84
f-stack-0: Gateway6: fe80::feee:ffff:feff:ffff
f-stack-0: Ethernet address: 20:90:6f:7d:5d:08
f-stack-0: Successed to register dpdk interface
```

**D7 逐字核验（`thread_mode=0` 必须与改动前等价）**：`mp_ncpus=1`、`mp_maxid=0`、`dense_idx=0`、`pc_cpuid=0`、`pc_zpcpu_offset=0`、`curcpu=0` —— **全部与非SMP旧行为一致，D7 PASS**。

预热 + 3 轮压测：

```bash
ssh f-stack-client "curl -s -o /dev/null -w 'curl_http_code=%{http_code}\n' http://9.134.214.176/"
→ curl_http_code=200
ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://9.134.214.176:80/"   # ×3
```

原始输出：

```
=== ROUND 1 ===
  Latency   468.37us  201.97us  10.05ms   98.17%
  Req/Sec    41.93k     1.29k   51.28k    76.65%
  2090071 requests in 10.10s, 1.26GB read
Requests/sec: 206955.49
=== ROUND 2 ===
  Latency   458.83us   98.51us   3.91ms   87.85%
  Req/Sec    42.41k     0.95k   50.43k    75.90%
  2118080 requests in 10.10s, 1.28GB read
Requests/sec: 209709.73
=== ROUND 3 ===
  Latency   463.27us  231.62us   9.23ms   98.66%
  Req/Sec    42.62k     1.04k   51.28k    78.04%
  2124493 requests in 10.10s, 1.28GB read
Requests/sec: 210362.40
```

- **socket errors：零**（wrk 未输出 `Socket errors` 行 = 无 connect/read/write/timeout 错误）。
- 压测后进程 `976023` **仍存活**。
- 收尾：`/data/workspace/kill_process.sh 976023` → `[OK] pid=976023 exited after SIGTERM`。

| 指标 | 本轮实测 | 历史基线（参照） | 偏差 |
|---|---|---|---|
| req/s 3轮 | 206,955 / **209,710**(中位) / 210,362 | 209,946 / 209,367（均值 209,657） | 中位 **+0.03%** |

**判定：零回归 PASS**（≤5%）。

### 3.2 档位 B：`thread_mode=0`、2 进程（primary + secondary，`lcore_mask=6`）

`config.ini`：`lcore_mask=2`→`6`，`thread_mode=0` 不变。已核实生效：

```
$ grep -n "^lcore_mask\|^thread_mode" /data/workspace/f-stack/config.ini
3:lcore_mask=6
8:thread_mode=0
```

启动命令（primary 起来后隔 14s 再起secondary，均绝对路径 + `setsid`）：

```bash
setsid nohup /data/workspace/f-stack/example/helloworld --conf /data/workspace/f-stack/config.ini \
  --proc-type=primary   --proc-id=0 < /dev/null >> /data/workspace/f-stack/example/helloworld.log 2>&1 &
setsid nohup /data/workspace/f-stack/example/helloworld --conf /data/workspace/f-stack/config.ini \
  --proc-type=secondary --proc-id=1 < /dev/null >> /data/workspace/f-stack/example/helloworld.log 2>&1 &
```

两进程均起来（`977891` primary、`978080` secondary）。`helloworld.log` 新增（原始摘录）：

```
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
...
thread init success on lcore 1.
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket_978080_1a32412c5e07b0
EAL: Selected IOVA mode 'PA'
ETHDEV: Device 0000:00:05.0 is not driven by the primary process
PCI_BUS: Requested device 0000:00:05.0 cannot be used
```

（`ETHDEV: … not driven by the primary process` 是 DPDK secondary attach 共享ethdev 的正常提示，非错误；本档实际打通了业务流量，见下方 `curl 200` 与 wrk 数据。）

primary 侧探针（`f-stack-0.log`）：

```
[M17-PROBE] tid=139623911104512 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=1 mp_maxid=0 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7efcb997cc80 uma_cache=0x7efcb9971e00
```

→ **D7 在多进程档同样成立**：每进程独立地址空间、各自 `mp_ncpus=1`/`mp_maxid=0`/槽位 0。

> **如实记录的一处未查清项**：secondary 进程（`--proc-id=1`）本轮的 f-stack 侧日志**未落到 `example/f-stack-1.log`**（该文件全程保持 60 行未变，`grep -c "M17-PROBE" f-stack-1.log` = 0），其落点我未能定位（排查命令被中止，未继续）。这是**既有的日志落点行为**、与 G1 改动无因果关系（secondary 的 EAL 输出确实进了 `helloworld.log`，且业务功能正常），但为诚实起见在此登记：**secondary 的 `[M17-PROBE]` 行未取到**，故2进程档的 D7 取证仅覆盖 primary。

预热 + 3 轮压测原始输出：

```
curl_http_code=200
=== ROUND 1 ===
  Latency   416.72us   96.18us   5.92ms   84.89%
  Req/Sec    46.87k     1.44k   51.95k    65.67%
  2336574 requests in 10.10s, 1.41GB read
Requests/sec: 231359.58
=== ROUND 2 ===
  Latency   424.24us  203.03us   9.86ms   98.81%
  Req/Sec    46.64k     1.05k   49.43k    71.00%
  2320469 requests in 10.02s, 1.40GB read
Requests/sec: 231623.03
=== ROUND 3 ===
  Latency   420.03us  101.71us   4.39ms   86.09%
  Req/Sec    46.56k     1.36k   51.69k    72.11%
  2324922 requests in 10.10s, 1.41GB read
Requests/sec: 230188.61
```

- **socket errors：零**（无 `Socket errors` 行）。
- 压测后两进程**均存活**。
- 收尾：`/data/workspace/kill_process.sh 977891 978080` → 两者均 `[OK] … exited after SIGTERM`。

| 指标 | 本轮实测 | 历史基线（参照） | 偏差 |
|---|---|---|---|
| req/s 3 轮 | **231,360**(中位) / 231,623 / 230,189 | 234,613 / 233,982（均值 234,298） | 中位 **−1.25%** |

**判定：零回归 PASS**（|−1.25%| ≤ 5%）。

### 3.3 阶段 3 小结

| 档位 | 本轮中位 req/s | 历史基线均值 | 偏差 | 崩溃 | socket error | 判定 |
|---|---|---|---|---|---|---|
| `thread_mode=0` 1 进程 | 209,710 | 209,657 | +0.03% | 无 | 0 | **PASS** |
| `thread_mode=0` 2 进程 | 231,360 | 234,298 | −1.25% | 无 | 0 | **PASS** |

（D7 实测成立：`-DSMP` + 稠密 cpuid + `curcpu` per-thread 化对多进程模式零回归。）

---

## 阶段 1：DoD-1 槽位隔离（`thread_mode=1`、2 线程）—— **PASS**

被测二进制：`example/helloworld` md5 **`88b8cf93e0b8d3765e76b3c26c6a8f3b`**（含探针）。
`config.ini`：`lcore_mask=6`、`thread_mode=1` → `nb_threads=2`（已 `grep` 核实生效）。
判定式与日志落点采用 `_m17_E_coder_g1.md` §6.4/§6.5（**主线程探针在 `f-stack-0.log`，worker 探针在 `helloworld.log`，两个文件都要看**）。

启动：

```bash
cd /data/workspace/f-stack/example
setsid nohup /data/workspace/f-stack/example/helloworld \
  --conf /data/workspace/f-stack/config.ini \
  < /dev/null >> /data/workspace/f-stack/example/helloworld.log 2>&1 &
```

进程 `988684` 存活。**原始探针日志行（逐字，本轮独立运行，地址与 `coder` §6.6冒烟样例不同 → 是独立取证而非复制）**：

`example/f-stack-0.log:1047,1057`（**主线程**）：

```
[M17-PROBE] tid=139973402664960 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=2 mp_maxid=1 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7f4e18ca6c80 uma_cache=0x7f4e18c86180
```

`example/helloworld.log:433,435`（**worker**）：

```
[M17-PROBE] tid=139973359600640 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=2 mp_maxid=1 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7f4e18ca7c80 uma_cache=0x7f4e18c86200
```

### 1.1 逐条判定（`_m17_E_coder_g1.md` §6.5 全部判定式）

| # | 判定式 | 实测代入 | 结论 |
|---|---|---|---|
| ① | 所有 `dense_idx` 两两不同、恰覆盖 `0..mp_maxid`、且 `<= mp_maxid` | `{0, 1}`，`mp_maxid=1` → 恰覆盖 `0..1` | **✓** |
| ② | `dense_idx == pc_cpuid == curcpu` | 线程 A `0==0==0`；线程 B `1==1==1` | **✓** |
| ③ | `pc_zpcpu_offset == 4096 * dense_idx` | `0 == 4096×0`；`4096 == 4096×1` | **✓** |
| ④ | `mp_ncpus == nb_threads`、`mp_maxid == nb_threads-1` | `mp_ncpus=2==2`、`mp_maxid=1==2-1` | **✓** |
| ⑤ | **SMR 槽位隔离**：两线程 `smr_c_seq` 之差 `== 4096 * Δdense_idx` | `0x7f4e18ca7c80 − 0x7f4e18ca6c80 = 0x1000 = 4096 == 4096×1` | **✓** |
| ⑥ | **UMA cache 槽位隔离**（`uz_cpu[curcpu]` 路径） | `0x7f4e18c86200 − 0x7f4e18c86180 = 0x80 = 128 == sizeof(uma_cache)×1` | **✓** |
| ⑦ | `curcpu` 两两不同（UMA per-cpu cache 隔离的关键） | `0` vs `1` | **✓** |
| ⑧ | 两线程确属**同一进程**（否则「隔离」无意义） | 两 tid 不同（`139973402664960` / `139973359600640`），且两组槽位地址同基址`0x7f4e18…` | **✓** |

**阶段 1 判定：DoD-1 在 2 线程档 PASS。** SMR 侧（`zpcpu_get()` → 槽距 4096）与 UMA cache 侧（`uz_cpu[curcpu]` → 槽距 128）**双路径同时实证隔离**。

### 1.2 顺带坐实的 U6-a（`_m17_D_verdict.md` §3-6 的未坐实项）

`lcore_mask=6` → `proc_lcore[0]=1`、`proc_lcore[1]=2`；实测**主线程取到 `dense_idx=0`**、worker 取到 `dense_idx=1`，且日志中 `thread init success on lcore 1.` 与 `on lcore 2.` 均出现。
→ 本机默认配置下 **EAL main lcore 确实是 `proc_lcore[0]`（lcore 1）**，与 D4 的推断一致。
**边界**：我未打印 `rte_get_main_lcore()` 本身（探针不含该字段，我无权改代码），故这是**由 `dense_idx=0` 反推**，不是直接打印取证；且只覆盖未使用 `--main-lcore` 的默认情形。D4 采用的「不依赖 `k==0`」写法仍是正确的稳健选择。

### 1.3 未能验证项（如实登记）

- **U2 仍未坐实**：⑤ 只证明「相邻线程 SMR 槽距 4096」，**没有**证明 `UMA_ZONE_PCPU` zone 真的分配了 `(mp_maxid+1)×4096` 字节。`coder` 建议「在 4 线程下重点观察」——**而 4 线程档启动即崩（见阶段 2）**，故 U2 **本轮无法用 4 线程实证**。

---

## 阶段 2：功能与稳定性矩阵（`thread_mode=1` 的 1/2/4 线程）—— **部分 FAIL**

被测二进制统一为 md5 **`88b8cf93e0b8d3765e76b3c26c6a8f3b`**（每档启动前后核对，全程未变）。

### 2.1 1 线程（`lcore_mask=2`）—— PASS

探针（`f-stack-0.log:1071,1081`）：

```
[M17-PROBE] tid=140015734714368 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=1 mp_maxid=0 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7f57f0e07c80 uma_cache=0x7f57ef9a1e00
```

3 轮 wrk 原始输出：

```
curl_http_code=200
=== ROUND 1 ===
    Latency   460.33us  117.51us   5.91ms   92.88%
    Req/Sec    42.37k     1.01k   51.14k    75.05%
  2111657 requests in 10.10s, 1.28GB read
Requests/sec: 209074.89
=== ROUND 2 ===
    Latency   462.38us  151.62us   8.78ms   97.02%
    Req/Sec    42.35k     1.12k   51.27k    77.84%
  2111184 requests in 10.10s, 1.28GB read
Requests/sec: 209041.78
=== ROUND 3 ===
    Latency   462.00us  122.72us   4.30ms   93.16%
    Req/Sec    42.23k     1.81k   44.42k    92.00%
  2101280 requests in 10.01s, 1.27GB read
Requests/sec: 209913.05
```

零 socket error（无 `Socket errors` 行）、进程 `992430` 压测后存活。收尾 `/data/workspace/kill_process.sh 992430` → `[OK] … exited after SIGTERM`。

### 2.2 2 线程（`lcore_mask=6`）—— PASS

探针见阶段 1。3 轮 wrk 原始输出：

```
curl_http_code=200
=== ROUND 1 ===
    Latency   413.09us   90.24us   3.50ms   80.24%
    Req/Sec    47.23k     1.25k   52.00k    67.47%
  2354657 requests in 10.10s, 1.42GB read
Requests/sec: 233133.96
=== ROUND 2 ===
    Latency   426.24us  261.47us  16.05ms   98.45%
    Req/Sec    47.05k     2.79k   51.34k    93.81%
  2345385 requests in 10.10s, 1.42GB read
Requests/sec: 232233.60
=== ROUND 3 ===
    Latency   410.08us  101.07us   3.93ms   87.60%
    Req/Sec    47.61k     1.01k   51.48k    73.71%
  2377462 requests in 10.10s, 1.44GB read
Requests/sec: 235390.60
```

零 socket error、进程 `988684` 存活（随后直接用于阶段 4 soak）。

### 2.3 4 线程（`lcore_mask=1e`）—— **FAIL：启动即 SIGSEGV**

```
$ grep -n "^lcore_mask\|^thread_mode" /data/workspace/f-stack/config.ini
3:lcore_mask=1e
8:thread_mode=1

$ setsid nohup /data/workspace/f-stack/example/helloworld --conf /data/workspace/f-stack/config.ini < /dev/null >> …/helloworld.log 2>&1 &
/bin/bash: line 1: 994097 Segmentation fault(core dumped) setsid nohup /data/workspace/f-stack/example/helloworld …
```

`example/f-stack-0.log` 新增内容（**全部**，逐字）：

```
create mbuf pool on socket 0
create ring:dispatch_ring_p0_q0 success, 2047 ring entries are now free!
create ring:dispatch_ring_p0_q1 success, 2047 ring entries are now free!
create ring:dispatch_ring_p0_q2 success, 2047 ring entries are now free!
create ring:dispatch_ring_p0_q3 success, 2047 ring entries are now free!
Port 0 MAC:20:90:6F:7D:5D:08
LRO is disabled
TSO is disabled
set port 0 to promiscuous mode ok

Checking link statusdone
Port 0 Link Up - speed 4294967295 Mbps - full-duplex
[M17-PROBE] tid=140230446718976 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=4 mp_maxid=3 curcpu=0
```

**日志到此中断**——`[M17-PROBE]` 之后本应出现的 `link_elf_lookup_symbol` / `TCP Hpts created` / `Timecounters tick` / `ipfw2… initialized` / `[M17-PROBE-SLOT]` **全部没有**。

> **决定性观察：这不是 virtio 多队列/RSS 限制。** 4 个 `dispatch_ring_p0_q0..q3` **全部创建成功**、`Port 0 Link Up` 也过了、DPDK 侧端口初始化完整走完；崩溃发生在其后的 FreeBSD 侧 UMA 启动，**worker 线程一个都还没进 `ff_stack_thread_init()`**。任务书预设的「4 线程可能因 virtio RSS 起不来」在本轮**被证伪**。

### 2.4 崩溃栈取证（gdb；core dump 被 `/proc/sys/kernel/core_pattern = |/bin/false` 禁用，按规约用 gdb）

命令文件 `/tmp/m17_gdb_4thread.cmd`（`file` / `set args` / `run` / `bt` / `info threads` / `info registers`），执行：

```bash
cd /data/workspace/f-stack/example
setsid nohup gdb -q -x /tmp/m17_gdb_4thread.cmd < /dev/null > /tmp/m17_gdb_4thread.log 2>&1 &
```

原始输出（摘录）：

```
Thread 1 "helloworld" received signal SIGSEGV, Segmentation fault.
0x00000000014ea26c in zone_import ()

===== BACKTRACE =====
#0  0x00000000014ea26c in zone_import ()
#1  0x00000000014ead44 in zone_alloc_item ()
#2  0x00000000014ebf03 in uma_startup1 ()
#3  0x00000000011bdda7 in ff_freebsd_init ()
#4  0x0000000001509f28 in ff_init ()
#5  0x00000000006b4d22 in main (argc=3, argv=0x7fffffffe228) at main.c:210

===== THREADS =====
* 1    Thread 0x7ffff79fe000 (LWP 995626) "helloworld"0x00000000014ea26c in zone_import ()
  2    Thread 0x7ffff720b400 (LWP 995629) "dpdk-intr"       epoll_wait () from /lib64/libc.so.6
  3    Thread 0x7ffff6a0a400 (LWP 995630) "dpdk-mp-msg"     recvmsg () from /lib64/libc.so.6
  4    Thread 0x7ffff5208400 (LWP 995631) "dpdk-worker2"    read () from /lib64/libc.so.6
  5    Thread 0x7ffff4a07400 (LWP 995632) "dpdk-worker3"    read () from /lib64/libc.so.6
  6    Thread 0x7ffff4206400 (LWP 995633) "dpdk-worker4"    read () from /lib64/libc.so.6
  7    Thread 0x7ffff3a05400 (LWP 995634) "dpdk-telemet-v2" accept () from /lib64/libc.so.6

===== REGISTERS =====
rip            0x14ea26c           0x14ea26c <zone_import+1148>
rsp            0x7fffffffdda0      0x7fffffffdda0
rbp            0x7ffff7fba000      0x7ffff7fba000
rax            0x20800000          545259520
rbx            0x7ffff7fbd000      140737353863168
```

- 崩溃线程是 **Thread 1 = 主线程**；其余 6 个线程全是 DPDK 自带线程，阻塞在 `read`/`epoll_wait`/`accept` —— **确认 f-stack worker 尚未启动**。
- 崩溃函数链 `uma_startup1() → zone_alloc_item() → zone_import()`，与日志中断位置（`ff_freebsd_init.c:344` 的探针之后、`:359mi_startup()` 之前，即 `:351 uma_startup1()`）**完全吻合**。

### 2.5 阈值定位实测：3 线程（`lcore_mask=e`）同样崩

```
$ grep -n "^lcore_mask\|^thread_mode" config.ini
3:lcore_mask=e
8:thread_mode=1
$ setsid nohup … helloworld --conf …/config.ini … &
/bin/bash: line 1: 997460 Segmentation fault      (core dumped) setsid nohup …
```

最后三条探针（`f-stack-0.log`）显示三次运行的三元组：

```
[M17-PROBE] tid=140230446718976 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=4 mp_maxid=3 curcpu=0   ← 4 线程，崩
[M17-PROBE] tid=140737347837952 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=4 mp_maxid=3 curcpu=0   ← 4 线程 gdb 复现，崩
[M17-PROBE] tid=139684502966272 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=3 mp_maxid=2 curcpu=0   ← 3 线程，同样崩
```

**阈值结论（实测）**：`mp_maxid <= 1`（1/2 线程）正常；**`mp_maxid >= 2`（3/4 线程）100% 在 `uma_startup1()` 内 SIGSEGV**。4 线程档跑了 2 次（裸跑 + gdb），均崩，**可稳定复现**。

### 2.6 这是 G1 引入的回归（判断依据）

G1 之前 `mp_maxid` **恒为 0**（`lib/ff_glue.c:145` BSS 零值，无人赋值），`uma_startup1()` 内的 zone 尺寸是常量，故该路径不可能随线程数变化 → **崩溃只可能由 G1 的三元组设置（`ff_freebsd_init.c:337-340`）触发**。

### 2.7 给 `coder` 的定位线索

**坐实的代码事实**（实际读码确认）：

| 依据 | 事实 |
|---|---|
| `freebsd/vm/uma_core.c:3179-3182` | `zsize = sizeof(struct uma_zone) + sizeof(struct uma_cache)*(mp_maxid+1) + sizeof(struct uma_zone_domain)*vm_ndomains`，`roundup(zsize, UMA_SUPER_ALIGN)` → **`zsize` 随 `mp_maxid` 单调增大**；实测 `sizeof(struct uma_cache) == 128`（由阶段 1 的 `uma_cache` 槽距 `0x80` 实测得出），故每多1 个 CPU 涨 128 字节 |
| `uma_core.c:3185-3191` | `size = (zsize*2) + ksize`，**一次 `startup_alloc()`** 取出 |
| `uma_core.c:2472-2478`（`keg_layout`） | `pages = atop(kl.slabsize); if (UMA_ZONE_PCPU) pages *= mp_maxid+1; keg->uk_ppera = pages;` |
| `uma_core.c:2486-2492`（`keg_layout`） | `if ((uk_flags & UMA_ZFLAG_OFFPAGE) != 0\|\| (uk_ipers-1)*rsize >= PAGE_SIZE)` → 打 `UMA_ZFLAG_HASH` 或 `UMA_ZFLAG_VTOSLAB`。**该判据依赖 `rsize`（对 zones keg 即 `zsize`），因此依赖 `mp_maxid`** |
| `freebsd/vm/uma_int.h:133,229,231` | `UMA_SLAB_SIZE = PAGE_SIZE`；`UMA_SUPER_ALIGN = CACHE_LINE_SIZE*2`（或 `CACHE_LINE_SIZE`） |
| `uma_core.c:2100-2106`（FSTACK 分支） | `startup_alloc()` 体为 `*pflag = UMA_SLAB_BOOT; return page_alloc(zone, bytes, domain, pflag, wait);` → **与 `lib/ff_freebsd_init.c:348 boot_pages=16` 那块 `bootmem` 无关**（该 16 页其实未被 UMA 使用；`uma_core.c:3171 bootstart=bootmem=virtual_avail` 只是记录，FSTACK 下 `uma_startup2()` 的 `vm_map_insert` 也被 `#ifndef FSTACK`(:3250) 排除） |
| `lib/ff_freebsd_init.c:351` vs `:354-356` | **`uma_startup1()` 先执行；`uma_page_slab_hash = kmem_malloc(...)` 与 `uma_page_mask = num_hash_buckets-1` 在其之后** → `uma_startup1()` 全程 `uma_page_slab_hash == NULL`、`uma_page_mask == 0` |

**假设（明确标注为未坐实，交 `coder` 判定，不得直接采信）**：`mp_maxid` 由 1 增到 2 使 `zsize` 越过 `keg_layout`（`uma_core.c:2486-2492`）的阈值，令boot 期的 zones/kegs keg 被打上 `UMA_ZFLAG_VTOSLAB`/`UMA_ZFLAG_HASH`；而该路径要用 `vsetzoneslab()`（`lib/include/vm/uma_int.h:105-126`）操作**此刻尚未分配的 `uma_page_slab_hash`** → `zone_import` 内解引用非法地址。若该假设成立，修法方向是把 `uma_page_slab_hash`/`uma_page_mask` 的初始化**提前到 `uma_startup1()` 之前**，而非回退 G1 的三元组。

**边界声明**：本节只做到「崩溃可稳定复现 + 栈帧精确 + 阈值 `mp_maxid>=2` + 相关代码事实穷举」。**根因未坐实**（tester 无权改 `lib/` 代码加打印、也未在 `keg_layout` 内部逐字段查看 `uk_flags`/`uk_ipers`/`uk_ppera`）。根因定位与修复归 `coder`。

---

## 阶段 4：60s / 400 连接 soak（`thread_mode=1` 2 线程）—— **PASS**

被测 md5 `88b8cf93e0b8d3765e76b3c26c6a8f3b`，沿用 §2.2 的进程 `988684`（未重启）。

soak 前记录日志旧行数：`f-stack-0.log = 1061`、`helloworld.log = 440`。

```bash
ssh f-stack-client "/data/wrk/wrk -t8 -c400 -d60s http://9.134.214.176:80/"
```

原始输出（逐字）：

```
Running 1m test @ http://9.134.214.176:80/
  8 threads and 400 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   728.52us    4.96ms 209.46ms   99.78%
    Req/Sec    62.48k     7.71k   85.32k    67.62%
  29841688 requests in 1.00m, 18.04GB read
Requests/sec: 497101.13
Transfer/sec:307.67MB
```

soak 后核验：

```
=== proc after soak ===
root  988684  988676 63 14:16?  00:02:02 /data/workspace/f-stack/example/helloworld --conf /data/workspace/f-stack/config.ini
=== log growth ===
 1061 f-stack-0.log
  440 helloworld.log
```

| 判定项 | 实测 | 结论 |
|---|---|---|
| 总请求数 | **29,841,688** | — |
| req/s | **497,101.13** | — |
| socket errors | **零**（wrk 未输出 `Socket errors` 行） | PASS |
| 进程存活 | 是（`988684`，CPU 时间 02:02） | PASS |
| 日志 panic/assert | **两个日志文件行数 soak 前后完全未变（1061/440 → 1061/440）** → 零新增输出，无 panic/assert/warning | PASS |

历史基线（参照）：497,043 req/s、29,834,366 请求、零error。本轮 **+0.01%**，等价。

收尾：`/data/workspace/kill_process.sh 988684` → `[OK] pid=988684 exited after SIGTERM`。

---

## 阶段 5：**「G2 去锁前」性能基线**（DoD-5 的对照组）

### 5.1 基线口径（G2 去锁后必须用同一口径复测）

- 同机（本机 DPDK 独占网卡 `9.134.214.176`）、同客户端（`f-stack-client` / `/data/wrk/wrk`）、同 `config.ini`（仅改 `lcore_mask`/`thread_mode`，`idle_sleep=20` 等其余键全程不动）。
- 短压：`wrk -t5 -c100 -d10s`，**≥3 轮取中位数**；soak：`wrk -t8 -c400 -d60s` 单轮。
- 每轮压测前先 `curl` 预热一次刷新 client 侧 ARP（本轮全部返回 `curl_http_code=200`）。
- 被测二进制 md5 **`88b8cf93e0b8d3765e76b3c26c6a8f3b`**（G1 三轮改动 + DoD-1 探针；**`lib/include/vm/uma_int.h:45-52` 的 `uma_crit_lock` 仍在**）。

### 5.2 **G2 去锁前基线表（本轮实测，全部为实际执行数据）**

| 场景 | 本轮 3 轮 req/s | **中位数（用于 G2 对比）** | socket err | 崩溃 | 历史基线（仅参照） | 偏差 |
|---|---|---|---|---|---|---|
| `thread_mode=1` **1 线程** | 209,075 / 209,042 / 209,913 | **209,075** | 0 | 无 | 209,611（均值） | −0.26% |
| `thread_mode=1` **2 线程** | 233,134 / 232,234 / 235,391 | **233,134** | 0 | 无 | 233,380（中位） | −0.11% |
| `thread_mode=1` **3 线程** | — | **无法测（启动即 SIGSEGV）** | — | **有** | 无 | — |
| `thread_mode=1` **4 线程** | — | **无法测（启动即 SIGSEGV）** | — | **有** | 无 | — |
| `thread_mode=0` **1 进程** | 206,955 / 209,710 / 210,362 | **209,710** | 0 | 无 | 209,657（均值） | +0.03% |
| `thread_mode=0` **2 进程** | 231,360 / 231,623 / 230,189 | **231,360** | 0 | 无 | 234,298（均值） | −1.25% |
| **soak** `thread_mode=1` 2 线程 `-t8 -c400 -d60s` | 497,101（单轮，29,841,688 请求） | **497,101** | 0 | 无 | 497,043 | +0.01% |

> **G2 去锁后的判定门槛（DoD-5）**：同口径 ≥3 轮中位数**不得低于**上表对应值，允许 ±2% 噪声。
> **注意**：上表 1 线程 / 2 线程 / `thread_mode=0` 各档在 `coder` 后续 M3 补修（`ff_kern_synch.c` 的 `pcpup != NULL` 兜底 + 删一处失效注释）之后**理论上不变**（两处改动不触及 pcpu/`curcpu`/UMA 语义），但**3/4 线程档必须在崩溃修复后重测**；且若 `coder` 的修复触及 UMA 启动序列（例如把 `uma_page_slab_hash` 提前），则**全部档位都应重测**以确保基线与最终 G1 提交对应。

---

## DoD 逐条结论

| DoD | 内容 | 结论 | 依据 |
|---|---|---|---|
| **DoD-1** | per-cpu 槽位真正隔离（判定式 8 条） | **PASS（仅 2 线程档）** | 阶段 1：SMR 槽距 4096×Δidx、UMA cache 槽距 128×Δidx、`dense_idx==pc_cpuid==curcpu`、三元组正确，原始日志已落盘 |
| | 同上，3/4 线程档 | **无法验证** | 阶段 2.3/2.5：启动即 SIGSEGV，探针只输出到主线程 `[M17-PROBE]` 就崩，worker 探针取不到 |
| **DoD-2** | 移除 `uma_crit_lock` | **不适用（G2 本轮未做）** | `_m17_E_coder_g1.md` §4.1 明确 G2 未动；本轮全部数据均为「去锁前」 |
| **DoD-3** | clean build 零错误、warning 不增 | **不由 tester 验证** | 属 `coder`/`reviewer` 范围（`_m17_E_coder_g1.md` §6.7）；tester 只核实了二进制新鲜度与探针是否入二进制 |
| **DoD-4** | 1/2/4 线程矩阵 + soak 全部零崩溃零 socket error；`thread_mode=0` 零回归 ≤5% | **FAIL** | 1 线程 PASS、2 线程 PASS、soak PASS、`thread_mode=0` 1 进程 +0.03% / 2 进程 −1.25% 均 PASS；但**4 线程（及 3 线程）启动即 SIGSEGV → 矩阵不完整，DoD-4 整体判 FAIL** |
| **DoD-5** | 去锁前后吞吐对比 | **去锁前基线已就绪（阶段 5）**；去锁后待 G2 完成后复测 | 阶段 5.2 表格 |
| — | **U2**（`UMA_ZONE_PCPU` zone 是否真分配 `(mp_maxid+1)×4096`） | **仍未坐实** | 原计划靠 4 线程档观察，因该档崩溃而落空 |
| — | **U6-a**（EAL main lcore == `proc_lcore[0]`） | **间接坐实（默认配置下）** | 阶段 1.2；边界：由 `dense_idx=0` 反推，未直接打印 `rte_get_main_lcore()` |

## 无法验证项清单（如实登记，无一项留空或编造）

1. **3 线程 / 4 线程档的功能、吞吐、槽位隔离** —— 启动即 SIGSEGV，`uma_startup1()` 内崩溃（阶段 2.3~2.6）。**须 `coder` 修复后重测。**
2. **U2** —— 依赖 4 线程档，同上。
3. **`thread_mode=0` 2 进程档中 secondary 进程的 `[M17-PROBE]` 行** —— secondary 的 f-stack 侧日志未落到 `example/f-stack-1.log`（该文件全程 60 行未变、`grep -c "M17-PROBE"` = 0），落点未定位（排查被中止，按 leader 指示不再花时间）。属既有日志落点行为，与 G1 无因果；2 进程档的 D7 取证仅覆盖 primary。
4. **4 线程崩溃的根因** —— 只做到稳定复现 + 精确栈帧 + 阈值 + 相关代码事实穷举；根因未坐实（tester 无权改 `lib/` 加打印）。归 `coder`。
5. **`MAXCPU=1024` 的运行期 RSS 开销** —— 本轮未测（任务书未要求，且崩溃档位优先）。

## 规约合规声明

- 全程**未出现** `rm`/`kill`/`pkill`/`killall`/`chmod` 任何命令字符串（含 ssh 远端命令）；停进程一律 `/data/workspace/kill_process.sh <pid>`，共 5 次，输出均已摘录。
- **未修改** `lib/`、`freebsd/`、`example/` 下任何源码（代码问题已回报leader 转 `coder`）。
- `config.ini` 仅改 `lcore_mask`/`thread_mode` 两个本地测试值，**全程未 `git add`、未 `git commit`**；测试结束后用文件编辑恢复到阶段 0 登记的起始状态（`lcore_mask=6`、`thread_mode=1`、`idle_sleep=20`、`addr=9.134.214.176`），**未使用 `git checkout`**。
- 所有 req/s、请求数、探针地址、栈帧均来自实际执行输出，**无估算、无复制历史数字**；历史基线仅作对照且单列。

###合规核验：`config.ini` 恢复实证（测试结束时实际执行）

```
$ grep -n "^lcore_mask\|^thread_mode\|^idle_sleep\|^addr=" /data/workspace/f-stack/config.ini
3:lcore_mask=6
8:thread_mode=1
46:idle_sleep=20
147:addr=9.134.214.176
```

与 §0.4 登记的阶段0 起始状态**逐键一致**，恢复完成（用文件编辑，未用 `git checkout`）。

`git --no-pager diff config.ini` 仍显示若干与仓库 HEAD 的差异（`lcore_mask=1→6`、`#thread_mode=0→thread_mode=1`、`idle_sleep=0→20`、`fstack_log_level`、`[port0]` 的本机真实 IP/netmask/gateway、IPv6 地址等）——这些**全部是我开始测试前工作区就已存在的用户本地测试值**（§0.4 已登记），**不是本轮 tester 引入的**，且按规约**一律不得入库**。本agent 全程未 `git add` / 未 `git commit`。

进程清理核验：`ps -ef | grep -E "helloworld|gdb"` 无残留（全部 5 次停进程均通过 `/data/workspace/kill_process.sh`）。

---

## 本轮数据的版本归属（固化标注，供G2 与后续复测引用）

**本文档阶段 0/1/2/3/4/5 的全部实测数据，被测二进制唯一为：**

| 项 | 值 |
|---|---|
| `example/helloworld` md5 | **`88b8cf93e0b8d3765e76b3c26c6a8f3b`** |
| 构建时间 | 2026-08-04 14:02:53（`lib/libfstack.a` 14:02:42） |
| 内容 | G1 第一/二/三轮改动（`-DSMP` + 稠密 cpuid + 三元组 + `curcpu` per-thread + `timeout_cpu __thread`）+ DoD-1 临时探针 |
| **状态限定 1** | **G2 未做** —— `lib/include/vm/uma_int.h:45-52` 的 `uma_crit_lock` **仍在** → 本文所有性能数字均为「**去锁前**」 |
| **状态限定 2** | **3/4 线程崩溃未修** —— `mp_maxid>=2` 时 `uma_startup1()` 内 SIGSEGV（阶段 2.3~2.6） |
| **状态限定 3** | **不含** `coder` 后续 M3 补修（`ff_kern_synch.c` 的 `pcpup != NULL` 兜底、删一处失效注释） |

→ 引用本文任何数字时**必须连带这三条状态限定**；G2 去锁后的对比必须以 §5.2 的中位数为基准且用同一口径（§5.1）。

---

## 附录：修复后复测清单（**尚未执行**，等 `coder` 的新 md5）

> leader 已确认：`coder` 的修法是把 `uma_page_slab_hash` / `uma_page_mask` 的初始化**提前到 `uma_startup1()` 之前**。**该修复改动了 `ff_freebsd_init()` 的初始化顺序**，因此 **`thread_mode=0` 各档也必须重跑**，不能沿用本文数据。

### A. 复测前置

1. 记录新二进制指纹：`md5sum /data/workspace/f-stack/example/helloworld /data/workspace/f-stack/lib/libfstack.a` + `ls -l --time-style=full-iso`，并与 `_m17_E_coder_g1.md` 给出的新 md5 核对（**不一致即停，回报 leader**）。
2. 确认探针仍在二进制：`grep -c "M17-PROBE" example/helloworld` 应> 0。
3. 记录 `git --no-pager diff --stat lib/` 作为新版本指纹。
4. 记录日志旧行数：`wc -l example/helloworld.log example/f-stack-0.log`（读新增内容一律`tail -n +N`）。
5. 确认无残留进程：`ps -ef | grep helloworld | grep -v grep`（清理只用 `/data/workspace/kill_process.sh`）。

### B. 复测矩阵（**全部 6 档都要重跑**，含本文已PASS 的档位）

| 档 | `config.ini` | 启动方式 | 必测项|
|---|---|---|---|
| B1 | `thread_mode=1`、`lcore_mask=2`（1 线程） | 单进程 | 探针判定式 8条 + 3 轮 `wrk -t5 -c100 -d10s` |
| B2 | `thread_mode=1`、`lcore_mask=6`（2 线程） | 单进程 | 同上 + **接 soak** |
| **B3** | `thread_mode=1`、`lcore_mask=e`（**3 线程**） | 单进程 | **首要**：能否启动；探针判定式；3 轮 wrk |
| **B4** | `thread_mode=1`、`lcore_mask=1e`（**4 线程**） | 单进程 | **首要**：能否启动；探针判定式；3 轮 wrk；**U2 核验（见 D）** |
| B5 | `thread_mode=0`、`lcore_mask=2`（1 进程） | `--proc-type=primary --proc-id=0` | D7 探针（`mp_ncpus=1`/`mp_maxid=0`/槽位 0）+ 3 轮 wrk |
| B6 | `thread_mode=0`、`lcore_mask=6`（2 进程） | primary `--proc-id=0` + secondary `--proc-id=1`（间隔 ≥14s，绝对路径） | 同上 + 两进程均存活 |

### C. 每档统一流程

```bash
# 1) 改 config.ini（仅 lcore_mask / thread_mode 两键），并 grep 核实生效
grep -n "^lcore_mask\|^thread_mode" /data/workspace/f-stack/config.ini
# 2) 记旧行数
cd /data/workspace/f-stack/example && wc -l helloworld.log f-stack-0.log
# 3) 启动（必须 setsid + 绝对路径 + < /dev/null，不能用 (nohup ... &) 子 shell）
setsid nohup /data/workspace/f-stack/example/helloworld \
  --conf /data/workspace/f-stack/config.ini \
  < /dev/null >> /data/workspace/f-stack/example/helloworld.log 2>&1 &
sleep 16 && ps -ef | grep helloworld | grep -v grep
# 4) 抓探针：主线程在 f-stack-0.log、worker 在 helloworld.log（两个都要看）
grep "M17-PROBE" f-stack-0.log | tail -N; grep "M17-PROBE" helloworld.log | tail -N
# 5) 预热 + 3 轮压测
ssh f-stack-client "curl -s -o /dev/null -w 'curl_http_code=%{http_code}\n' http://9.134.214.176/"
ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://9.134.214.176:80/"   # ×3
# 6) B2 追加 soak
ssh f-stack-client "/data/wrk/wrk -t8 -c400 -d60s http://9.134.214.176:80/"
# 7) 收尾核验：进程存活、日志新增行数、panic/assert 扫描
ps -ef | grep helloworld | grep -v grep ; wc -l helloworld.log f-stack-0.log
# 8) 停进程（唯一允许方式）
/data/workspace/kill_process.sh <pid>
```

崩溃时的取证方式（沿用本轮已验证有效的路径，core dump 被禁用）：
`setsid nohup gdb -q -x /tmp/m17_gdb_4thread.cmd < /dev/null > /tmp/m17_gdb_<档位>.log 2>&1 &`，取 `bt` / `info threads` / `info registers`。

### D. U2 的复测核验方法（leader 指定纳入）

**间接核验（我可独立完成，无需改代码）**：在 B4（4 线程，`mp_maxid=3`）下从探针取 4 组`[M17-PROBE-SLOT]`，核验

1. `dense_idx` 恰好覆盖 `{0,1,2,3}`；
2. **相邻 `smr_c_seq` 之差恒为 4096**，即 4 个地址构成公差 4096 的等差数列，全部落在 `[base, base + 4×4096)` 内；
3. 4 组 `uma_cache` 地址构成公差 128（`sizeof(struct uma_cache)`）的等差数列。

**局限（必须如实写明）**：上述只证明「槽位地址按4096 递进」，**仍不能证明该 zone 真的分配了 `(mp_maxid+1)×4096` 字节**——若zone 只分配了 1 页，`dense_idx=1..3` 的地址同样呈 4096 递进，只是落在了越界内存上，短时运行可能不立即崩。

**因此需要 `coder` 配合（已请leader 转达）**：在探针中加一行打印 SMR zone 的实际分配尺寸，任一形式即可：
- `ipi_smr` 所属 zone 的 `uk_ppera`（`uma_core.c:2472-2478` 对 `UMA_ZONE_PCPU` 会 `pages *= mp_maxid+1`，**这是最直接的判定量**：期望 `uk_ppera == mp_maxid+1`）；
- 或 `uk_size` / `uz_size` 与 `keg->uk_flags & UMA_ZONE_PCPU` 的取值；
- 或在 `smr_create()` 后遍历 `zpcpu_get_cpu(smr, i)`（`i = 0..mp_maxid`）打印各槽位地址，与 `[M17-PROBE-SLOT]` 的 `smr_c_seq` 交叉比对。

有了`uk_ppera` 一行，U2 即可**直接坐实**而不再依赖间接推断。

### E. 复测的判定与产出

- 判定门槛：DoD-1 判定式8 条（`_m17_E_coder_g1.md` §6.5 + 本文§1.1）全档通过；DoD-4 六档零崩溃零 socket error、`thread_mode=0` 相对**本文 §5.2 的去锁前数字**波动≤5%（同时也与历史基线对照）。
- 产出：在本文追加「复测（新 md5 `<待填>`）」章节，**不覆盖本文既有数据**，两版并列以便看出修复带来的差异。

---
---

# 第二部分：崩溃修复后的复测（**G2 去锁前的最终基线**）

> 本部分为`coder` 修复 3/4 线程崩溃（把 `uma_page_slab_hash`/`uma_page_mask` 初始化提前到 `uma_startup1()` 之前）后的完整复测。
> 与第一部分**并列保留、不覆盖**，以便看出修复带来的差异。
> 全部数据实测，`reviewer` 的三条复审结论（R-b探针缺行定性、R-c 版本 pin 方式、R-e 分字段公差）均已采用。

## R0. 版本指纹（按 R-c：**用我自己实测的值pin，不依赖他人报的 md5**）

```
$ md5sum /data/workspace/f-stack/example/helloworld
751a8153d3b200229cff99b3fa7650b0  example/helloworld

$ strings example/helloworld | grep "M17-PROBE"
[M17-PROBE] tid=%lu dense_idx=%d pc_cpuid=%u pc_zpcpu_offset=%lu mp_ncpus=%d mp_maxid=%u curcpu=%d
[M17-PROBE-SLOT] dense_idx=%d smr_c_seq=%p uma_cache=%p
[M17-PROBE-ZONE] name=%s uk_ppera=%u uk_rsize=%u mp_maxid=%u

$ git --no-pager diff --stat lib/
 lib/Makefile            |   4++
 lib/ff_dpdk_if.c        |   8 +++-
 lib/ff_dpdk_if.h|   1 +
 lib/ff_freebsd_init.c   | 115 ++++++++++++++++++++++++++++++++++++++++++------
 lib/ff_glue.c           |   7 +++
 lib/ff_host_interface.c |   8 ++++
 lib/ff_host_interface.h |   4 ++
 lib/ff_kern_synch.c     |   4 +-
 lib/ff_kern_timeout.c   |   6 +--
 lib/include/sys/pcpu.h  |   2 +-
 10 files changed, 139 insertions(+), 20 deletions(-)
```

| 项 | 值 |
|---|---|
| **版本判据：`example/helloworld` md5** | **`751a8153d3b200229cff99b3fa7650b0`**（复测开始时与结束时各测一次，**两次相同**） |
| 二进制 mtime | 复测开始时 `2026-08-04 14:52:38`；结束时 `2026-08-04 15:00:57` |
| `git diff --stat lib/` | **10 文件 / 139 insertions(+) / 20 deletions(-)** |
| 探针 | 三条格式串齐全（含新增的 `[M17-PROBE-ZONE]`） |
| 状态 | **G2 去锁前**（`uma_crit_lock` 仍在） |

**关于 md5 与 mtime 的两点如实记录**：

1. **与 leader 转达的 `d49268db…` 不符**。我实测为 `751a8153…`，与 `_m17_E_coder_g1.md` §10.5「第六轮**最终**指纹（`tester` 请用这一组，取代 §8.1 与 §9.5）」**逐字一致**；且该二进制含 §10.2 新增的 `[M17-PROBE-ZONE]` 探针（第五轮没有），可证明它是**更新**的构建。已`send_message` 告知 leader，leader 随后以 R-c 确认应改用我自己实测的值pin 版本。
2. **复测期间二进制被重建过一次（mtime 由 14:52:38 变为 15:00:57），但 md5 完全相同**（`751a8153…` → `751a8153…`）。据 leader 转述，这是 `reviewer` 用当前工作区做的复现性重建。**因内容字节相同，本部分全部档位的数据仍属同一份代码版本**，不存在跨版本混算。
3. mtime 核验（R-c 要求「二进制 mtime 晚于所有 `lib/` 源文件」）：二进制 `15:00:57`晚于 `lib/` 下最新文件 `15:00:39`（`vnode_if.h` 等构建生成头文件），**满足**。

环境：无残留 `helloworld`/`gdb` 进程；每档启动前记录日志旧行数、读新增一律 `tail -n +N`。

## R1. 阶段 1'：DoD-1 槽位隔离（**2/ 3 / 4 线程**）—— 全档 **PASS**

### R1.1 判定式（按 **R-e：分字段用不同公差**）

| 字段 | 公差 | 依据 |
|---|---|---|
| `pc_zpcpu_offset` | **4096 × dense_idx** | `zpcpu_offset_cpu(cpu) = UMA_PCPU_ALLOC_SIZE * cpu`，`UMA_PCPU_ALLOC_SIZE = PAGE_SIZE = 4096` |
| `smr_c_seq`（`zpcpu_get()` 路径） | **4096 × Δdense_idx** | 同上 |
| `uma_cache`（`&uz_cpu[curcpu]` 路径） | **128 × Δdense_idx** | `sizeof(struct uma_cache) = 128`（实测） |
| `uk_ppera`（新增） | **== mp_maxid + 1** | `uma_core.c:2472-2478` 对 `UMA_ZONE_PCPU` 做 `pages *= mp_maxid+1` |

完备性判据按 **R-b**：以 **`[M17-PROBE-SLOT]` 出现 N 条互不相同的 `dense_idx`** 判「N 个线程都完成初始化」；`[M17-PROBE]` 标量行缺行属`ff_subr_prf.c:86` 全局非`__thread` 行缓冲 `bufr[]` 被并发覆盖的既有缺陷，**不判DoD-1 FAIL**。

### R1.2 2 线程（`lcore_mask=6`）—— PASS

`f-stack-0.log`（主线程）：

```
[M17-PROBE] tid=140579588988928 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=2 mp_maxid=1 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7fdb3c6e6c80 uma_cache=0x7fdb3c6c6180
[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=2 uk_rsize=8 mp_maxid=1
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=2 uk_rsize=64 mp_maxid=1
```

`helloworld.log`（worker）：

```
[M17-PROBE] tid=140579547677696 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=2 mp_maxid=1 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7fdb3c6e7c80 uma_cache=0x7fdb3c6c6200
```

| 判定 | 代入 | 结论 |
|---|---|---|
| `dense_idx` 覆盖 `0..mp_maxid` | `{0,1}`，`mp_maxid=1` | ✓ |
| `dense_idx==pc_cpuid==curcpu` | `0==0==0`；`1==1==1` | ✓ |
| `pc_zpcpu_offset == 4096×idx` | `0`；`4096` | ✓ |
| `smr_c_seq` 公差 **4096** | `0x7fdb3c6e7c80 − 0x7fdb3c6e6c80 = 0x1000 = 4096` | ✓ |
| `uma_cache` 公差 **128** | `0x7fdb3c6c6200 − 0x7fdb3c6c6180 = 0x80 = 128` | ✓ |
| `uk_ppera == mp_maxid+1` | `2 == 1+1`（两个 zone 均为 2） | ✓ |
| `[M17-PROBE-SLOT]` 条数 | 2 条，`dense_idx` 互不相同 | ✓ |
| 标量行完整性 | 2 条全齐（**无缺行**） | ✓ |

### R1.3 3 线程（`lcore_mask=e`）—— **PASS（原崩溃档，已修复）**

**进程正常启动并存活**（原版本此档 100% SIGSEGV）。

`f-stack-0.log`（主线程）：

```
[M17-PROBE] tid=140544678899712 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=3 mp_maxid=2 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7fd31ba57c80 uma_cache=0x7fd31ba49d80
[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=3 uk_rsize=8 mp_maxid=2
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=3 uk_rsize=64 mp_maxid=2
```

`helloworld.log`（2 个 worker）：

```
[M17-PROBE] tid=140544638485504 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=3 mp_maxid=2 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7fd31ba58c80 uma_cache=0x7fd31ba49e00
[M17-PROBE] tid=140544630092800 dense_idx=2 pc_cpuid=2 pc_zpcpu_offset=8192 mp_ncpus=3 mp_maxid=2 curcpu=2
[M17-PROBE-SLOT] dense_idx=2 smr_c_seq=0x7fd31ba59c80 uma_cache=0x7fd31ba49e80
```

| dense_idx | pc_cpuid | curcpu | `pc_zpcpu_offset` | 期望 4096×idx | `smr_c_seq` | `uma_cache` |
|---|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 0 ✓ | `0x7fd31ba57c80` | `0x7fd31ba49d80` |
| 1 | 1 | 1 | 4096 | 4096 ✓ | `0x7fd31ba58c80` | `0x7fd31ba49e00` |
| 2 | 2 | 2 | 8192 | 8192 ✓ | `0x7fd31ba59c80` | `0x7fd31ba49e80` |

- `smr_c_seq` 相邻差：`0x1000`、`0x1000` → **公差恒 4096** ✓（3槽构成等差数列）
- `uma_cache` 相邻差：`0x80`、`0x80` → **公差恒 128** ✓
- `mp_ncpus=3`、`mp_maxid=2` ✓；`uk_ppera=3 == mp_maxid+1` ✓
- `[M17-PROBE-SLOT]` **3 条**、`dense_idx` 互不相同 ✓；标量行 **3 条全齐（无缺行）** ✓

### R1.4 4 线程（`lcore_mask=1e`）—— **PASS（原崩溃档，已修复）**

**进程正常启动并存活**（原版本此档 100% SIGSEGV）。

`f-stack-0.log`（主线程）：

```
[M17-PROBE] tid=139724012380160 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=4 mp_maxid=3 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7f1408164c80 uma_cache=0x7f140813d980
[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=4 uk_rsize=8 mp_maxid=3
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=4 uk_rsize=64 mp_maxid=3
```

`helloworld.log`（3 个 worker）：

```
[M17-PROBE] tid=139723970479104 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=4 mp_maxid=3 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7f1408165c80 uma_cache=0x7f140813da00
[M17-PROBE] tid=139723962086400 dense_idx=2 pc_cpuid=2 pc_zpcpu_offset=8192 mp_ncpus=4 mp_maxid=3 curcpu=2
[M17-PROBE-SLOT] dense_idx=2 smr_c_seq=0x7f1408166c80 uma_cache=0x7f140813da80
[M17-PROBE] tid=139723953693696 dense_idx=3 pc_cpuid=3 pc_zpcpu_offset=12288 mp_ncpus=4 mp_maxid=3 curcpu=3
[M17-PROBE-SLOT] dense_idx=3 smr_c_seq=0x7f1408167c80 uma_cache=0x7f140813db00
```

| dense_idx | pc_cpuid | curcpu | `pc_zpcpu_offset` | 期望 4096×idx | `smr_c_seq` | `uma_cache` |
|---|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 0 ✓ | `0x7f1408164c80` | `0x7f140813d980` |
| 1 | 1 | 1 | 4096 | 4096 ✓ | `0x7f1408165c80` | `0x7f140813da00` |
| 2 | 2 | 2 | 8192 | 8192 ✓ | `0x7f1408166c80` | `0x7f140813da80` |
| 3 | 3 | 3 | 12288 | 12288 ✓ | `0x7f1408167c80` | `0x7f140813db00` |

- `smr_c_seq` 相邻差：`0x1000` × 3 段 → **公差恒 4096**，4 槽全落在 `[0x7f1408164c80, 0x7f1408164c80 + 4×4096)` 内 ✓
- `uma_cache` 相邻差：`0x80` × 3 段 → **公差恒 128** ✓
- `mp_ncpus=4`、`mp_maxid=3` ✓；`uk_ppera=4 == mp_maxid+1` ✓
- `[M17-PROBE-SLOT]` **4 条**、`dense_idx` 互不相同 ✓
- **标量行 4 条全齐 —— `coder` 在 §9.4 记录的 `dense_idx=2` 缺行本轮未复现**，与 R-b 的「非确定性日志丢失」定性一致（我这一次运行恰好没丢）。

### R1.5 **U2 坐实**（本轮核心增量）

```
[M17-PROBE-ZONE] name=pcpu_zone_8  uk_ppera=1 uk_rsize=8  mp_maxid=0← 1 线程档
[M17-PROBE-ZONE] name=pcpu_zone_8  uk_ppera=2 uk_rsize=8  mp_maxid=1   ← 2 线程档
[M17-PROBE-ZONE] name=pcpu_zone_8  uk_ppera=3 uk_rsize=8  mp_maxid=2   ← 3 线程档
[M17-PROBE-ZONE] name=pcpu_zone_8  uk_ppera=4 uk_rsize=8  mp_maxid=3   ← 4 线程档
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=4 uk_rsize=64 mp_maxid=3   ← 4 线程档（第二个 zone）
```

**`uk_ppera == mp_maxid + 1` 在 1/2/3/4 四个档位全部成立**（两个 `UMA_ZONE_PCPU` zone 均如此）。

→ `UMA_ZONE_PCPU` zone 的每个 slab **确实按 `(mp_maxid+1)` 页分配**（每CPU 一页 = `UMA_PCPU_ALLOC_SIZE` = 4096），因此 `zpcpu_get_cpu(base, cpu) = base + 4096×cpu`（`cpu ∈ [0, mp_maxid]`）**全部落在该 slab 的合法分配范围内**。
→ **U2 由「未坐实」转为「已坐实」**。这正是我在第一部分 §1.3 指出的、间接推断无法排除的那一条（「若zone 只分配 1 页，槽距同样呈 4096 递进、只是落在越界内存上」）——`uk_ppera` 的直接读数把它彻底闭合。**这是我上一轮唯一无法自证、必须依赖 `coder` 加探针的项，现已完成。**

### R1.6 阶段 1' 判定

**DoD-1 在 2 / 3 / 4 线程三档全部 PASS**（外加 1 线程与 `thread_mode=0` 的退化档亦正确）。SMR 侧（公差 4096）与 UMA cache 侧（公差 128）双路径隔离 + `uk_ppera` 后备存储足量，三条证据链齐备。

## R2. 阶段 2'：吞吐矩阵（`thread_mode=1`）

每档 `ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://9.134.214.176:80/"`，压测前 `curl` 预热（**全部返回 `curl=200`**）。

### R2.1 1 线程（`lcore_mask=2`）

```
=== R1 ===  2118279 requests in 10.10s, 1.28GB readRequests/sec: 209730.76
=== R2 ===  2120663 requests in 10.10s, 1.28GB read   Requests/sec: 209978.84
=== R3 ===  2115435 requests in 10.10s, 1.28GB read   Requests/sec: 209456.00
```
零 socket error、进程 `1032029` 存活。**中位数 209,730.76**。

### R2.2 2 线程（`lcore_mask=6`）

```
=== R1 ===  2371434 requests in 10.10s, 1.43GB read   Requests/sec: 234800.58
=== R2 ===  2363691 requests in 10.01s, 1.43GB read   Requests/sec: 236208.41
=== R3 ===  2382022 requests in 10.10s, 1.44GB read   Requests/sec: 235845.37
```
零 socket error、进程 `1024297` 存活。**中位数 235,845.37**。

### R2.3 3 线程（`lcore_mask=e`）—— 波动大，**已补跑至 6 轮**

前 3 轮出现明显离群值，为避免用小样本下结论，**我主动补跑了 3 轮**（共 6 轮）：

```
=== R1 ===  2435892 requests in 10.10s, 1.47GB read   Requests/sec: 241184.59
=== R2 ===  1446612 requests in 10.10s, 0.87GB read   Requests/sec: 143232.19   ← 离群
=== R3 ===  2068904 requests in 10.10s, 1.25GB read   Requests/sec: 204857.21   ← 离群
=== R4 ===  2428247 requests in 10.10s, 1.47GB read   Requests/sec: 240420.88
=== R5 ===  2446213 requests in 10.10s, 1.48GB read   Requests/sec: 242217.25
=== R6 ===  2495526 requests in 10.10s, 1.51GB read   Requests/sec: 247079.56
```

- **零 socket error**（6 轮均无 `Socket errors` 行）、进程 `1026247` 全程存活。
- **日志零运行期新增**：`helloworld.log` 与 `f-stack-0.log` 在 6 轮压测期间行数完全未变（556 / 1260），逐字检查新增内容**全部是启动期输出**（`create ring:dispatch_ring_p0_q0/q1/q2`、`Port 0 Link Up`、`TCP Hpts created 3 swi interrupt threads`、探针行等），**无 panic / assert / error**。
- **中位数（6 轮）= 240,802.74**（排序后中间两值 240,420.88 与 241,184.59 的均值）。

**关于两个离群值（如实记录，不掩盖）**：R2 的 143,232 与 R3 的 204,857 明显偏低，而 R1/R4/R5/R6 稳定在 240k~247k。**我未能坐实其原因**，可排除的与不可排除的分列如下：
- **可排除**：进程崩溃/重启（进程 PID 全程未变、CPU 时间连续累积）；socket error（6 轮全零）；栈内报错（日志零新增）。
- **未坐实的可能原因**：3 是**非 2 的幂**的队列数，virtio RSS 的 reta 表在 3 队列下分布不均（已知 virtio 多队列限制，见 `15-worker时钟缺口修复与virtio-RSS限制.md`），叠加压测初期连接在 3 队列间的分配抖动；也不能排除客户端侧或宿主虚拟化层的瞬时干扰。**要定论需抓每队列收包计数，本轮未做（无对应探针，且我无权改代码）。**
- **对判定的影响**：DoD-4 要求「零崩溃、零 socket error」——**这两项均满足**。吞吐离群不构成功能失败，但**3 线程档的吞吐数字稳定性弱于 2/4 线程档**，这一点必须在 G2 前后对比时特别注意（建议 G2 对比优先用 2 线程与 4 线程档，3 线程档需增加轮次）。

### R2.4 4 线程（`lcore_mask=1e`）—— 最稳

```
=== R1 ===  2509441 requests in 10.10s, 1.52GB read   Requests/sec: 248461.42
=== R2 ===  2519507 requests in 10.10s, 1.52GB read   Requests/sec: 249461.20
=== R3 ===  2542782 requests in 10.10s, 1.54GB read   Requests/sec: 251764.26
=== R4 ===  2507622 requests in 10.10s, 1.52GB read   Requests/sec: 248285.65
```
零 socket error、进程 `1029870` 存活、日志零运行期新增。**中位数（4 轮）= 248,961.31**。

**这是本轮首次取得的 4 线程吞吐数据**（上一版本此档崩溃，无任何数字），且吞吐随线程数单调上升（1T210k → 2T 236k → 3T 241k → 4T 249k）。

## R3. 阶段 3'：`thread_mode=0` 零回归重跑（初始化顺序已变，必须重证）

### R3.1 1 进程（`thread_mode=0`、`lcore_mask=2`、`--proc-type=primary --proc-id=0`）

D7 探针（`f-stack-0.log`）：

```
[M17-PROBE] tid=139826732113920 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=1 mp_maxid=0 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7f2bf29a8c80 uma_cache=0x7f2bf299de00
[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=1 uk_rsize=8 mp_maxid=0
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=1 uk_rsize=64 mp_maxid=0
```

→ **D7 成立**：`mp_ncpus=1`、`mp_maxid=0`、`dense_idx=0`、`pc_zpcpu_offset=0`、`curcpu=0`、`uk_ppera=1`，与非 SMP 旧行为逐项等价。

```
=== R1 ===  2136495 requests in 10.10s, 1.29GB read   Requests/sec: 211545.34
=== R2 ===  2110954 requests in 10.10s, 1.28GB read   Requests/sec: 209009.75
=== R3 ===  2119225 requests in 10.10s, 1.28GB read   Requests/sec: 209825.01
```
零 socket error、进程 `1032953` 存活。**中位数 209,825.01**。

### R3.2 2 进程（`thread_mode=0`、`lcore_mask=6`、primary + secondary）

两进程均起来（`1034108` primary、`1034447` secondary），primary 侧 D7 探针：

```
[M17-PROBE] tid=139943128051712 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=1 mp_maxid=0 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7f470c680c80 uma_cache=0x7f470c675e00
[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=1 uk_rsize=8 mp_maxid=0
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=1 uk_rsize=64 mp_maxid=0
```

```
=== R1 ===  2395763 requests in 10.10s, 1.45GB read   Requests/sec: 237204.84
=== R2 ===  2392197 requests in 10.10s, 1.45GB read   Requests/sec: 236871.31
=== R3 ===  2381841 requests in 10.10s, 1.44GB read   Requests/sec: 235826.80
```
零 socket error、**两进程压测后均存活**。**中位数 236,871.31**。

> secondary 的 `[M17-PROBE]` 行仍未取到（与第一部分同因，属既有日志落点行为，按 leader 指示不再排查）。2 进程档 D7 取证仍仅覆盖 primary。

### R3.3 零回归判定（双基准对照）

| 档位 | 复测中位 | vs **修复前**（第一部分 §5.2） | vs **历史基线** | 判定 |
|---|---|---|---|---|
| `thread_mode=0` 1 进程 | 209,825.01 | 209,710 → **+0.05%** | 209,657 → **+0.08%** | **PASS** |
| `thread_mode=0` 2 进程 | 236,871.31 | 231,360 → **+2.38%** | 234,298 → **+1.10%** | **PASS** |

**结论**：`uma_page_slab_hash` 初始化提前**未对 `thread_mode=0` 造成回归**（两档均在 ±5% 内，且都略有提升）。零回归重新证明完成。

## R4. 阶段 4'：soak

### R4.1 2 线程 soak（`wrk -t8 -c400 -d60s`）

soak 前日志行数：`helloworld.log=534`、`f-stack-0.log=1232`。

```
    Latency   722.19us5.02ms 211.65ms   99.81%
  29962126 requests in 1.00m, 18.11GB read
Requests/sec: 499223.54
```

soak 后：进程 `1024297` 存活（CPU 时间 01:33）；日志行数 **534 / 1232 完全未变** → 零 panic/assert/warning；零 socket error。

### R4.2 4 线程 soak（**新增档，上一版本此档崩溃无法测**）

soak 前日志行数：`helloworld.log=583`、`f-stack-0.log=1289`。

```
    Latency   827.45us    6.61ms 210.20ms   99.68%
  29295356 requests in 1.00m, 17.71GB read
Requests/sec: 487968.74
```

soak 后：进程 `1029870` 存活（CPU 时间 02:26）；日志行数 **583 / 1289 完全未变** → 零 panic/assert/warning；零 socket error。

> 4 线程 soak（487,969）略低于 2 线程 soak（499,224），差 −2.25%。在 `-t8 -c400` 的高并发下客户端侧已接近瓶颈（两档都在 49万上下），**不能据此断言 4 线程更慢**；短压档（`-t5 -c100`）中 4 线程（248,961）明显高于 2 线程（235,845）。如实并列记录，不下超出数据的结论。

## R5. 阶段 5'：**G2 去锁前最终基线表**（DoD-5 对照组）

口径：同机（`9.134.214.176`）、同客户端（`f-stack-client` `/data/wrk/wrk`）、短压 `-t5 -c100 -d10s` ≥3 轮取**中位数**、soak `-t8 -c400 -d60s` 单轮；压测前 `curl` 预热；`config.ini` 仅改 `lcore_mask`/`thread_mode`。
被测二进制：`example/helloworld` md5 **`751a8153d3b200229cff99b3fa7650b0`**（**`uma_crit_lock` 仍在 = 去锁前**）。

| 场景 | 各轮 req/s | **中位数（G2 对比基准）** | socket err | 崩溃 | 日志新增 |
|---|---|---|---|---|---|
| `thread_mode=1` **1 线程** | 209,730.76 / 209,978.84 / 209,456.00 | **209,730.76** | 0 | 无 | 0 |
| `thread_mode=1` **2 线程** | 234,800.58 / 236,208.41 / 235,845.37 | **235,845.37** | 0 | 无 | 0 |
| `thread_mode=1` **3 线程** | 241,184.59 / 143,232.19 / 204,857.21 / 240,420.88 / 242,217.25 / 247,079.56（6 轮） | **240,802.74** | 0 | 无 | 0 |
| `thread_mode=1` **4 线程** | 248,461.42 / 249,461.20 / 251,764.26 / 248,285.65（4 轮） | **248,961.31** | 0 | 无 | 0 |
| `thread_mode=0` **1 进程** | 211,545.34 / 209,009.75 / 209,825.01 | **209,825.01** | 0 | 无 | 0 |
| `thread_mode=0` **2 进程** | 237,204.84 / 236,871.31 / 235,826.80 | **236,871.31** | 0 | 无 | 0 |
| **soak** 2 线程 `-t8 -c400 -d60s` | 499,223.54（29,962,126 请求 / 18.11GB） | **499,223.54** | 0 | 无 | 0 |
| **soak** 4 线程 `-t8 -c400 -d60s` | 487,968.74（29,295,356 请求 / 17.71GB） | **487,968.74** | 0 | 无 | 0 |

**G2 去锁后的判定门槛（DoD-5）**：同口径 ≥3 轮中位数**不得低于**上表对应值，允许 ±2% 噪声。
**给 G2 复测的两条提醒**：① **3 线程档吞吐稳定性差**（见 R2.3），用它做G2 对比须加轮次或改用 2/4 线程档；② 去锁后**必须重新验证槽位隔离**（R1 的探针全套），不可沿用本轮数据 —— 去锁后「每线程独占槽位」是唯一保护。

## R6. 复测后的 DoD 逐条结论

| DoD | 结论 | 依据 |
|---|---|---|
| **DoD-1** | **PASS（2/3/4 线程全档）** | R1.2~R1.4：`pc_zpcpu_offset==4096×idx`、`smr_c_seq` 公差 4096、`uma_cache` 公差 128、`dense_idx==pc_cpuid==curcpu`、三元组正确、`[M17-PROBE-SLOT]` 条数完备 |
| **DoD-2** | 不适用（G2 本轮仍未做） | 本部分全部数据为「去锁前」 |
| **DoD-3** | 不由 tester 验证 | 属 `coder`/`reviewer` 范围 |
| **DoD-4** | **PASS** | 1/2/3/4 线程 + `thread_mode=0` 1/2 进程 **六档零崩溃、零 socket error、日志零新增**；2 线程与 4 线程 soak 均通过；`thread_mode=0` 零回归 +0.05% / +2.38%（≤5%） |
| **DoD-5** | 去锁前基线**已完整就绪** | R5 表（8 个场景，含首次取得的 4 线程数据） |
| **U2** | **已坐实** | R1.5：`uk_ppera == mp_maxid+1` 在 1/2/3/4 四档、两个 `UMA_ZONE_PCPU` zone 全部成立 |
| **U6-a** | 间接坐实（默认配置） | 主线程恒取 `dense_idx=0`；未直接打印 `rte_get_main_lcore()` |
| 原 3/4 线程崩溃 | **已修复，实测消失** | R1.3/R1.4 两档均正常启动、完成 3~4 轮压测与 soak，无一次 SIGSEGV |

## R7. 复测的无法验证项（如实登记）

1. **3 线程档两个吞吐离群值的根因**（R2.3）——可排除崩溃/socket error/栈内报错；未坐实是否为 virtio 3队列 RSS 分布不均，需每队列收包计数探针，本轮无此探针且我无权改代码。
2. **`thread_mode=0` 2 进程档 secondary 的 `[M17-PROBE]` 行**（R3.2）——落点未定位，按 leader 指示不再排查；D7 取证仅覆盖 primary。
3. **`[M17-PROBE]` 标量行缺行的复现**——`coder` 报告的 4 线程 `dense_idx=2` 缺行**本轮未复现**（4 条全齐），与 R-b「非确定性日志丢失」一致；我无法证明它永不发生。
4. **`MAXCPU=1024` 的运行期 RSS 开销**——本轮仍未测（任务书未要求）。

## R8. 规约合规声明（复测部分）

- 全程**未出现** `rm`/`kill`/`pkill`/`killall`/`chmod` 任何命令字符串（含 ssh 远端命令）；停进程一律 `/data/workspace/kill_process.sh <具体 PID>`（复测共 6 次，**按 `coder` §7.6 的建议一律传 PID 而非进程名**，避免误伤他人进程），输出均已摘录。
- **未修改** `lib/`、`freebsd/`、`example/` 下任何源码。
- `config.ini` 仅改 `lcore_mask`/`thread_mode`，测毕已恢复到起始状态并实测核验：`lcore_mask=6`、`thread_mode=1`、`idle_sleep=20`、`addr=9.134.214.176`（未用 `git checkout`）；**全程未 `git add`、未 `git commit`**。
- 无残留 `helloworld`/`gdb` 进程（已`ps` 核验）。
- 所有数字来自实际执行输出，无估算、无复制历史数字；离群值与未坐实项均如实标注。

---
---

# 第三部分：G2 去锁前/去锁后 **A/B 交叉复测**（DoD-2 / DoD-5 判定）

> 方法上与前两部分的关键差异：**不是「先跑完一批去锁前、再跑完一批去锁后」，而是同一档位下两个二进制交替各跑 3 轮（A→B→A→B）**，使两侧数据落在同一时间窗内。
> 动机：DoD-5 的判据是「去锁后不得低于去锁前，允许 ±2% 噪声」，而 **±2% 对机器状态漂移极为敏感** —— 第二部分 R2.3 已实测到同一二进制 6 轮内出现 143k / 205k 离群。若两批数据相隔数十分钟，漂移可能直接吞掉判据。交叉法消除该风险，且 A 侧可与第二部分 R5 的既有中位数互校（**若 A 侧复现不出旧数字，则同轮 B 侧亦不可信**）。

## X0. 两个被测二进制的版本归属（**符号级判据**，比 md5 更硬）

`md5` 只能证明「两份是否同一份」；**`uma_crit_lock` 符号的有无能直接证明「这份到底是去锁前还是去锁后」**。本轮起全部版本归属均以该判据为准（本判据由tester 提出，`res-build` 已复核一致并记入 `_m17_G_coder_g2.md` §3.3）。

```
$ md5sum helloworld_g1_prelock helloworld_g2_nolock
751a8153d3b200229cff99b3fa7650b0  helloworld_g1_prelock
78c39a6f96e104412ce75351e402907b  helloworld_g2_nolock

$ grep -c "uma_crit_lock" helloworld_g1_prelock→ 1   ← 去锁前，符号在
$ grep -c "uma_crit_lock" helloworld_g2_nolock   → 0   ← 去锁后，符号已消失
```

| 二进制 | md5 | 字节 | mtime | `uma_crit_lock` | 版本 |
|---|---|---|---|---|---|
| `example/helloworld_g1_prelock`（**A 侧**） | `751a8153d3b200229cff99b3fa7650b0` | 30,392,704 | 15:00:57 | **在（1）** | **去锁前**（G1-only） |
| `example/helloworld_g2_nolock`（**B 侧**） | `78c39a6f96e104412ce75351e402907b` | 30,392,664 | 15:10:44 | **无（0）** | **去锁后**（G1+G2） |

两者相差 40 字节，与「删除一个 `volatile int` + 两处 `lock xchg`/`release` 内联」相符。
**交叉复测开始前与结束后各测一次两个副本的 md5，四次结果全部一致** → 全程未被覆盖。
`helloworld_g2_nolock` 的三条探针格式串完好（`[M17-PROBE]` / `[M17-PROBE-SLOT]` / `[M17-PROBE-ZONE]`），故去锁后可做全套 DoD-1 复验，无需重编。

### X0.1 第二部分数据的版本归属复核（回应 leader 的版本告警）

leader 于 G2 落地后要求核对「哪些数据是15:10 之前（去锁前）、哪些是之后」。**核对结论：第二部分全部 8 个场景均为「去锁前」，零污染、零返工。** 三重独立证据：

| # | 证据 |
|---|---|
| ① | 第二部分复测**开始与结束各测一次 md5，两次均为 `751a8153…`**（最后一次测于停掉 `thread_mode=0` 双进程之后） |
| ② | `751a8153…` 经**符号检查确认含 `uma_crit_lock`** = 去锁前；且它与 `res-build` 另存的 `helloworld_g1_prelock` **逐字节同一份** |
| ③ | **时间窗完全不重叠**：第二部分的 `kill_process.sh` 审计快照时间戳为 CST **14:53:48 → 15:08:20**；去锁后二进制 mtime 为 **15:10:44** —— 最后一个数据点比G2 落地**早 2 分 24 秒** |

## X1. 去锁后的 DoD-1 槽位隔离复验（`reviewer` 硬要求）

**必要性**：去锁后 `critical_enter/exit` 成为空操作，**「每线程独占 per-cpu 槽位」成为唯一保护**，故不可沿用去锁前结论。
判定公差不变：`pc_zpcpu_offset` 与 `smr_c_seq` 用 **4096**，`uma_cache` 用 **128**，另加 `uk_ppera == mp_maxid+1`。
完备性判据（R-b）：以 **`[M17-PROBE-SLOT]` 出现 N 条互不相同 `dense_idx`** 为准；`[M17-PROBE]` 标量行缺行**不判 FAIL**。

日志取法采用 `res-build` 提示的**字节偏移**法（`wc -c` 记偏移 → `tail -c +$((OFF+1))`），避免把历史数据或他人自测数据当成本轮结果。

### X1.1 去锁后 2 线程（`lcore_mask=6`）—— PASS

`f-stack-0.log`（主线程）：
```
[M17-PROBE] tid=140189238288384 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=2 mp_maxid=1 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7f8059b85c80 uma_cache=0x7f8059b66180
[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=2 uk_rsize=8 mp_maxid=1
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=2 uk_rsize=64 mp_maxid=1
```
`helloworld.log`（worker）：
```
[M17-PROBE] tid=140189196387328 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=2 mp_maxid=1 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7f8059b86c80 uma_cache=0x7f8059b66200
```
- `smr_c_seq` 差 `0x7f8059b86c80 − 0x7f8059b85c80 = 0x1000 = 4096` ✓
- `uma_cache` 差 `0x7f8059b66200 − 0x7f8059b66180 = 0x80 = 128` ✓
- `offset` 0 / 4096 = 4096×idx ✓；`dense_idx==pc_cpuid==curcpu` ✓；`uk_ppera=2 == mp_maxid+1` ✓
- `[M17-PROBE-SLOT]` 2 条、`dense_idx` 互不相同 ✓；标量行 2 条全齐
- panic/assert/segmentation 扫描（两个日志的本轮新增字节）：**0 / 0**

### X1.2 去锁后 3 线程（`lcore_mask=e`）—— PASS

`f-stack-0.log`：
```
[M17-PROBE] tid=140311576629248 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=3 mp_maxid=2 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7f9cd5a5ac80 uma_cache=0x7f9cd5a4cd80
[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=3 uk_rsize=8 mp_maxid=2
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=3 uk_rsize=64 mp_maxid=2
```
`helloworld.log`：
```
[M17-PROBE] tid=140311535846400 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=3 mp_maxid=2 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7f9cd5a5bc80 uma_cache=0x7f9cd5a4ce00
[M17-PROBE] tid=140311527453620:90:6f:7d:5d:08← 见 X1.4，R-b 缺陷的直接证据
[M17-PROBE-SLOT] dense_idx=2 smr_c_seq=0x7f9cd5a5cc80 uma_cache=0x7f9cd5a4ce80
```

| dense_idx | `smr_c_seq` | 相邻差 | `uma_cache` | 相邻差 |
|---|---|---|---|---|
| 0 | `0x7f9cd5a5ac80` | — | `0x7f9cd5a4cd80` | — |
| 1 | `0x7f9cd5a5bc80` | `0x1000` = 4096 ✓ | `0x7f9cd5a4ce00` | `0x80` = 128 ✓ |
| 2 | `0x7f9cd5a5cc80` | `0x1000` = 4096 ✓ | `0x7f9cd5a4ce80` | `0x80` = 128 ✓ |

`uk_ppera=3 == mp_maxid+1` ✓；`[M17-PROBE-SLOT]` **3 条**、`dense_idx` 互不相同 ✓ → **完备性成立，PASS**。

### X1.3 去锁后 4 线程（`lcore_mask=1e`）—— PASS

`f-stack-0.log`：
```
[M17-PROBE] tid=140321334202368 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=4 mp_maxid=3 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7f9f16da1c80 uma_cache=0x7f9f15216980
[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=4 uk_rsize=8 mp_maxid=3
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=4 uk_rsize=64 mp_maxid=3
```
`helloworld.log`（注意`dense_idx=2` 的标量行缺失、SLOT 行乱序但存在）：
```
[M17-PROBE] tid=140321293894656 dense_idx=1 pc_cpuid=1 pc_zpcpu_offset=4096 mp_ncpus=4 mp_maxid=3 curcpu=1
[M17-PROBE-SLOT] dense_idx=1 smr_c_seq=0x7f9f16da2c80 uma_cache=0x7f9f15216a00
[M17-PROBE] tid=140321277109248 dense_idx=3 pc_cpuid=3 pc_zpcpu_offset=12288 mp_ncpus=4 mp_maxid=3 curcpu=3
[M17-PROBE-SLOT] dense_idx=3 smr_c_seq=0x7f9f16da4c80 uma_cache=0x7f9f15216b00
[M17-PROBE-SLOT] dense_idx=2 smr_c_seq=0x7f9f16da3c80 uma_cache=0x7f9f15216a80
```

| dense_idx | `pc_zpcpu_offset` | 期望 4096×idx | `smr_c_seq` | `uma_cache` |
|---|---|---|---|---|
| 0 | 0 | 0 ✓ | `0x7f9f16da1c80` | `0x7f9f15216980` |
| 1 | 4096 | 4096 ✓ | `0x7f9f16da2c80` | `0x7f9f15216a00` |
| 2 | （标量行缺失） | — | `0x7f9f16da3c80` | `0x7f9f15216a80` |
| 3 | 12288 | 12288 ✓ | `0x7f9f16da4c80` | `0x7f9f15216b00` |

- `smr_c_seq` 四值构成**公差恒 4096** 的等差数列 ✓；`uma_cache` 四值构成**公差恒 128** 的等差数列 ✓
- `uk_ppera=4 == mp_maxid+1` ✓
- `[M17-PROBE-SLOT]` **4 条、`dense_idx` = {0,1,2,3} 互不相同** → **完备性成立**
- `dense_idx=2` 标量行缺失，按 R-b **不判 FAIL**；其 SLOT 行的 `smr_c_seq = base + 2×4096`、`uma_cache = base + 2×128` 两值均由 `curcpu`（`= pcpup->pc_cpuid`）推导，**只可能在该线程已完成 `ff_pcpu_thread_init(2)` 之后才打印得出**，故该线程确已正确初始化。
- panic/assert/segmentation 扫描：**0 / 0**

> **本轮首次复现了 `coder` 在 §9.4 报告的缺行现象，且缺的正是同一个 `dense_idx=2`。**

### X1.4 **R-b 缺陷的直接证据（本轮新取得，值得 `reviewer` / `coder` 收录）**

X1.2 的 3 线程档抓到一行**被拼接破坏的探针输出**：

```
[M17-PROBE] tid=140311527453620:90:6f:7d:5d:08
```

-前半 `[M17-PROBE] tid=1403115274536` 是 `dense_idx=2` 线程的探针（tid 被截断）；
- 后半 `20:90:6f:7d:5d:08` 是**另一条 printf**的内容 —— 即 `f-stack-0: Ethernet address: 20:90:6f:7d:5d:08` 的尾部。

→ **两条不同线程的 printf 输出被拼进了同一行**，这是 `lib/ff_subr_prf.c:86 char bufr[PRINTF_BUFR_SIZE];` 为**全局、非 `__thread`、无锁**行缓冲的**直接可视证据**，比「整行丢失」更有力（丢失只能推断，拼接是眼见）。
→ 进一步印证 R-b 的定性：**属f-stack 既有日志缺陷，非本轮引入，不影响产品正确性**；同时说明「标量行缺失」与「标量行被污染」是同一根因的两种表现，**判定必须以 `[M17-PROBE-SLOT]` 条数为准**。

### X1.5 去锁后 `thread_mode=0`的 D7 复验

1 进程档（`lcore_mask=2`）：
```
[M17-PROBE] tid=140407702908928 dense_idx=0 pc_cpuid=0 pc_zpcpu_offset=0 mp_ncpus=1 mp_maxid=0 curcpu=0
[M17-PROBE-SLOT] dense_idx=0 smr_c_seq=0x7fb33710ac80 uma_cache=0x7fb336f19e00
[M17-PROBE-ZONE] name=pcpu_zone_8 uk_ppera=1 uk_rsize=8 mp_maxid=0
[M17-PROBE-ZONE] name=pcpu_zone_64 uk_ppera=1 uk_rsize=64 mp_maxid=0
```
→ **D7 在去锁后仍成立**：`mp_ncpus=1`、`mp_maxid=0`、`dense_idx=0`、`offset=0`、`curcpu=0`、`uk_ppera=1`，与非 SMP 旧行为逐项等价。

### X1.6 阶段 X1 判定

**去锁后 DoD-1 在 2 / 3 / 4 线程三档全部 PASS**，`thread_mode=0` 退化档亦正确。`reviewer` 要求的「去锁后重新验证槽位隔离」**已完成**。

## X2. A/B 交叉吞吐（`wrk -t5 -c100 -d10s`，每块3 轮，压测前 `curl` 预热均 `curl=200`）

### X2.1 2 线程档（`lcore_mask=6`）

| 块| 二进制 | 各轮 req/s |
|---|---|---|
| **A1** | 去锁前 | 235,115.94 / 234,618.64 / 234,228.33 |
| **B1** | 去锁后 | 236,547.48 / 235,876.39 / 237,678.28 |
| **A2** | 去锁前 | 234,509.27 / 237,537.30 / 236,575.71 |
| **B2** | 去锁后 | 235,127.72 / 232,098.47 / 236,189.49 |

- **A 侧合并 6 轮排序**：234,228.33 / 234,509.27 / 234,618.64 / 235,115.94 / 236,575.71 / 237,537.30 → **中位 234,867.29**
- **B 侧合并 6 轮排序**：232,098.47 / 235,127.72 / 235,876.39 / 236,189.49 / 236,547.48 / 237,678.28 → **中位 236,032.94**
- **B − A = +0.50%**
- **A 侧互校**：A 侧中位 234,867 vs 第二部分 R5 的去锁前 2 线程中位 235,845 → 差 **−0.41%**，说明**机器状态未漂移，本轮 B 侧数据可信**。
- 零socket error（12 轮均无 `Socket errors` 行）、每块进程压测后均存活。

### X2.2 4 线程档（`lcore_mask=1e`）

| 块 | 二进制 | 各轮 req/s |
|---|---|---|
| **A3** | 去锁前 | 251,710.04 / 247,909.57 / 248,950.94 |
| **B3** | 去锁后 | 248,935.42 / 252,660.23 / 254,762.14 |
| **A4** | 去锁前 | 249,758.82 / 253,111.72 / 256,405.98 |
| **B4** | 去锁后 | 255,453.40 / 256,004.02 / 255,064.37 |

- **A 侧合并 6 轮排序**：247,909.57 / 248,950.94 / 249,758.82 / 251,710.04 / 253,111.72 / 256,405.98 → **中位 250,734.43**
- **B 侧合并 6 轮排序**：248,935.42 / 252,660.23 / 254,762.14 / 255,064.37 / 255,453.40 / 256,004.02 → **中位 254,913.26**
- **B − A = +1.67%**
- **A 侧互校**：A 侧中位 250,734 vs R5 的去锁前 4 线程中位 248,961 → 差 **+0.71%**，机器状态未漂移，B 侧可信。
- 零 socket error、进程全程存活。

### X2.3 其余档位（去锁后，单块3 轮；对照取第二部分 R5 的去锁前数字）

| 档位 | 去锁后各轮 req/s | 去锁后中位 | 去锁前中位（R5） | 差 |
|---|---|---|---|---|
| `thread_mode=1` 1 线程 | 212,526.80 / 213,938.31 / 214,735.16 | **213,938.31** | 209,730.76 | **+2.01%** |
| `thread_mode=1` 3 线程 | 252,683.63 / 252,557.12 / 253,193.25 | **252,683.63** | 240,802.74 | **+4.93%**（见下方说明） |
| `thread_mode=0` 1 进程 | 214,151.94 / 212,330.79 / 214,873.77 | **214,151.94** | 209,825.01 | **+2.06%** |
| `thread_mode=0` 2 进程 | 237,135.56 / 236,484.61 / 233,178.92 | **236,484.61** | 236,871.31 | **−0.16%** |

全部零 socket error、进程压测后存活。

> **3 线程档+4.93% 这个数字不可直接采信**（如实说明）：去锁前该档 6 轮中含两个离群值（143k / 205k），拉低了其中位数；而去锁后这3 轮异常平稳（252.6k / 252.6k / 253.2k，极差仅 0.25%）。**这个差值很可能主要来自去锁前那两个离群值，而非 G2 的收益。** 该档**未做 A/B 交叉**，故不作为 DoD-5 的判定依据；DoD-5 结论以已做交叉的 2 线程与 4 线程档为准。

## X3. 去锁后 soak（`wrk -t8 -c400 -d60s`）

| 档位 | req/s | 总请求数 | 传输量 | Latency avg / max | socket err | 进程 | 日志新增字节 |
|---|---|---|---|---|---|---|---|
| 去锁后 **2 线程** | **503,590.01** | 30,228,695 | 18.27GB | 700.74us / 210.49ms | **0** | 存活 | **0**（77,374 → 77,374 / 39,299 → 39,299） |
| 去锁后 **4 线程** | **496,646.19** | 29,815,310 | 18.02GB | 790.13us / 210.87ms | **0** | 存活 | **0**（76,085 → 76,085 / 38,562 → 38,562） |

与去锁前 soak 对比：

| 档位 | 去锁前 | 去锁后 | 差 |
|---|---|---|---|
| 2 线程 soak | 499,223.54 | 503,590.01 | **+0.87%** |
| 4 线程 soak | 487,968.74 | 496,646.19 | **+1.78%** |

> 日志「新增字节数为 0」是比「新增行数为 0」更严格的判据（连半行残字都没有），可确证 soak 期间**零panic / assert / warning**。
> 扫描关键字时**排除了 `fault` 的假阳性**（`res-build` 提示：ipfw 那行 `default to accept` 含 "fault"），实际用的是 `panic|assert|segmentation`。

## X4. **DoD-5 判定** 与 **DoD-2 运行时确认**

### X4.1 DoD-5：去锁后吞吐不得低于去锁前（±2% 噪声）

| 档位 | 方法 | 去锁前中位 | 去锁后中位 | 差 | 判定 |
|---|---|---|---|---|---|
| **2 线程** | **A/B 交叉各6 轮** | 234,867.29 | 236,032.94 | **+0.50%** | **PASS** |
| **4 线程** | **A/B 交叉各 6 轮** | 250,734.43 | 254,913.26 | **+1.67%** | **PASS** |
| 2 线程 soak |顺序 | 499,223.54 | 503,590.01 | +0.87% | PASS |
| 4 线程 soak | 顺序 | 487,968.74 | 496,646.19 | +1.78% | PASS |
| 1 线程 | 顺序 | 209,730.76 | 213,938.31 | +2.01% | PASS |
| `thread_mode=0` 1 进程 | 顺序 | 209,825.01 | 214,151.94 | +2.06% | PASS |
| `thread_mode=0` 2 进程 | 顺序 | 236,871.31 | 236,484.61 | −0.16% | PASS（在 ±2% 噪声内） |
| 3 线程 | 顺序（**不作判定依据**） | 240,802.74 | 252,683.63 | +4.93% | 参考（去锁前含离群值） |

**DoD-5 判定：PASS。** 去锁后吞吐在**所有档位均不低于**去锁前；两个做了 A/B 交叉的档位分别 **+0.50%** 与 **+1.67%**，且 A 侧与既有基线互校偏差仅 −0.41% / +0.71%（证明无机器状态漂移）。

**诚实边界**：+0.50% 与 +1.67% 的量级**接近噪声下限**，我不宣称「G2 带来了确定的性能提升」，只能给出实测可支撑的结论——**去锁后吞吐不低于去锁前，DoD-5 的阈值要求满足**。4 线程档的 +1.67% 大于 2 线程档的 +0.50%，方向上与「线程数越多、全局锁争用越重、去锁收益越大」一致，但**样本量不足以坐实该因果**。

### X4.2 DoD-2 的运行时确认（代码层归`reviewer`，此处只给运行时证据）

- 被测二进制 `helloworld_g2_nolock` 中 **`uma_crit_lock` 符号已不存在**（`grep -c` = 0），而去锁前副本中存在（= 1）→ 该锁**确已从二进制中移除**，不是「代码改了但没编进去」。
- 去锁后在**1/2/3/4 线程 + `thread_mode=0` 1/2 进程共 6 档 + 2 个 60s soak**（合计约 6,000 万请求）下：**零崩溃、零 socket error、日志零新增字节**。
- 去锁后**DoD-1 槽位隔离在 2/3/4 线程全档重新验证通过**（X1）——这是去锁后**唯一**的保护机制，其有效性已实测。

## X5. 第三部分的无法验证项（如实登记）

1. **G2 的性能收益是否真实存在** —— 实测差值 +0.50% / +1.67% 接近噪声，**无法坐实为G2 的因果收益**；只能判定「不低于去锁前」。要坐实需更大样本或perf 级别的锁争用计数，本轮未做。
2. **3 线程档去锁前的两个离群值（143k / 205k）根因** —— 仍未坐实。`res-build` 提出一条比「virtio 3 队列 RSS 分布不均」更有解释力的线索：4 线程日志出现 `TCP Hpts created 4 swi interrupt threads and bound 0 to cpus`，即 G1 把 `mp_ncpus` 抬到 N 后 **hpts 实例数由 1 变 N 且未绑核**，3 不是 2 的幂时「hpts 3 实例 + RSS 3 队列」可能叠加。**本轮未坐实**（需队列级/hpts 级计数探针，tester 无权改代码）。补充观察：**去锁后 3 线程档3 轮异常平稳（极差 0.25%）**，说明离群并非该档的必然属性。
3. **`[M17-PROBE]` 标量行缺失/污染无法穷尽** —— 本轮在4 线程档复现了缺行（同为 `dense_idx=2`）、在 3 线程档抓到拼接污染（X1.4），已确证根因表现形式，但**无法证明其出现概率或永不发生**。
4. **`thread_mode=0` 2 进程档 secondary 的 `[M17-PROBE]` 行** —— 仍未取到，按leader 指示不再排查；D7 取证仅覆盖 primary。
5. **`MAXCPU=1024` 的运行期 RSS 开销** —— 本轮仍未测。

## X6. 规约合规声明（第三部分）

- 全程**未出现** `rm`/`kill`/`pkill`/`killall`/`chmod`任何命令字符串（含 ssh 远端命令）；停进程一律 `/data/workspace/kill_process.sh <具体 PID>`（第三部分共 12 次，**全部传 PID 而非进程名**），输出均已核对。
- **未修改** `lib/`、`freebsd/`、`example/` 下任何源码；**未改动** `res-build` 的 `config.m17_g2_*.ini`，他亦未改我的 `config.ini`。
- 与 `res-build` 就网卡独占做了显式握手（同一 PCI 设备只能被一个 primary 接管）：他请求约 2 分钟自测窗口，我确认无残留进程后回复放行，其自测完成并释放后我才开始交叉复测 —— **两边未发生抢占，无数据作废**。
- `config.ini` 仅改 `lcore_mask`/`thread_mode`，测毕已恢复并实测核验：`lcore_mask=6`、`thread_mode=1`、`idle_sleep=20`、`addr=9.134.214.176`（未用 `git checkout`）；**全程未 `git add` / 未 `git commit`**。
- 收尾核验：无残留 `helloworld`/`wrk` 进程；两个副本 md5 与 `uma_crit_lock` 符号计数在复测前后一致（`g1_prelock` 1 / `g2_nolock` 0）。
- 临时产物：`example/helloworld_g1_prelock`、`example/helloworld_g2_nolock`（`res-build` 已记入 DoD-8 清理清单，走 `/data/workspace/rm_tmp_file.sh`）、`/tmp/m17ab_off.txt`、`/tmp/m17_gdb_4thread.{cmd,log}`。**建议在 M7 前保留两个副本**，以便对 DoD-5 结论做任何复核。
- 所有数字来自实际执行输出，无估算、无复制历史数字；离群值、噪声边界与未坐实项均如实标注。

---
---

# 第四部分：判据 #9 —— **摘探针后的收尾回归**（对提交产物的运行时验证）

> **背景（须如实记录）**：探针在 **16:22:10** 被摘除并重编（`lib/ff_freebsd_init.c` mtime 16:22:10 → `libfstack.a` 16:22:45 → `example/helloworld` 16:22:55）。**`res-build` 报告该摘除并非其执行**，他按停手条件停手并请leader 确认执行者。本部分是tester 对**摘探针后产物**的运行时验证，即判据 #9。
> **方法升级**：本轮不采用「与第三部分旧基线单点比较」，而是用**同窗 ABA 交叉**（无探针 → 带探针 → 无探针）。原因见§Y3 —— 若按单点比较，4 线程档会**误判 FAIL**。

## Y0. 被测产物与版本指纹（tester 自测，按 R-c）

| 二进制 | md5 | 字节 | mtime | 探针 | 角色 |
|---|---|---|---|---|---|
| `example/helloworld` | **`df05d2cd078d631ad2d8ee7caba8d387`** | 30,392,632 | 16:22:55 | **无** | **被测（提交产物）** |
| `example/helloworld_g2_nolock` | `78c39a6f96e104412ce75351e402907b` | 30,392,664 | 15:10:44 | 有 | 同窗对照 |
| `example/helloworld_g1_prelock` | `751a8153d3b200229cff99b3fa7650b0` | 30,392,704 | 15:00:57 | 有 | 去锁前（本部分未用） |

无探针版比带探针版**小 32 字节**。三个二进制的 md5 在本部分**开始与结束各测一次，全部未变**。

**探针确已从产物中消失（运行时实证，非仅 `strings`）**：本轮各档新增日志中 `grep -c "M17-PROBE"` = **0**（第三部分同样位置必有4~5 条）。

### Y0.1 tester 独立复核的判据结果（11 条）

| 判据 | 期望 | tester 实测 | 结论 |
|---|---|---|---|
| #1 纯删除 ×3 文件 | rc≤1 且新增 0 字节 | `rc=1`、`added_bytes=0 / 0 / 0` | **✅** |
| #2 `git diff` hi.c/.h | 完全为空 | **0 字节** | ✅ |
| #3 行数 | 379 / 617 / 202 | **380** / 617 / 202 | **❌ 差1 行** |
| #4 列首 `}` | 5 / 51 | 5 / 51 | ✅（但见 §Y0.3，证明力打折） |
| #5 `grep -rl M17 lib/` | 无输出 | 无输出；`strings` = 0 | ✅ |
| #8 clean build | 全量重编 | **248/248 `.o` 全部16:22 重生成** | **✅ 见 §Y0.2** |
| #10 ①②③④ | 9 / 0 / 10 / 0 | 9 / 0 / 10 / 0 | ✅ |
| #11 8 文件 md5 | 8/8 OK | **8/8 OK** | ✅ |
| mode/`--summary` | 0 | 0 字节 | ✅ |
| `init_lock` 完好 | 三处均在 | **179 / 189 / 220均在** | ✅ |

**#3 的 1 行差异（字符级取证）**：`cat -A` 显示 377、378 为**两个并排空行**——删 P4 块时未删相邻空行：

```
    ff_stack_inited = 1;<EOL>
<EOL>
<EOL>            ← 377、378
    return (0);<EOL>
}<EOL>
```

**纯格式瑕疵，无语义影响**。`ff_pcpu_thread_init()` 当前形态经逐行读码确认正确（`… PCPU_SET(prvspace, pcpup); }`），与 HEAD 应有形态一致。

### Y0.2 #8 的坐实方法（tester 提供，此前 `res-build` 判定不了）

`res-build` 原判「`.o`/`.a`/`helloworld` mtime 连续，看不出是否 clean build；`grep -rl M17` 为空只能证明 2 个文件被重生成」。tester 用 **`.o` 的 mtime 分布**直接判定：

```
$ ls -1 lib/*.o | wc -l                    → 248
$ ls -l --time-style=+%H:%M lib/*.o | awk '{print $6}' | sort | uniq -c
    248 16:22        ← 全部落在 16:22，无一残留旧 mtime
最早 ff_thread.o 16:22:29.335   最晚 rack.o 16:22:45.521   跨度约 16 秒（并行）
```

→ **248 个 `.o` 全部重新生成，无一复用旧对象** = 全量重编，不存在「只重编 `ff_freebsd_init.o` 就链接」的增量风险。**#8 通过。**

### Y0.3 判据 #4 的证明力更正（重要，两个 agent 共同高估）

`diff` 的删除清单显示：被算作删除的是**第 120 行 `}`（`ff_pcpu_thread_init()` 的收尾，真实代码）**，而第 163 行 `}`（探针函数收尾）被保留。这**正是先前预设的最坏形态**「误删真实 `}` 再从别处补一个凑括号平衡」，而 **#4 的计数仍是 5，完全隐形**。

本例**实际无害**（两种删法产生的文本完全相同，属`diff` 行对齐歧义；tester 已读原文确认函数体正确；删除清单中恰为 2 个 `-}`，对应删掉 2 个探针函数，7−2=5 自洽）。但结论必须更正：

- **真正兜住该风险的是 #1（子序列/纯删除判据），不是 #4**；
- **#4 对「删 A 的 `}`、留 B 的 `}`」这类等量替换是盲的**，只能作辅助判据。

> 责任归属如实记录：该高估由 **tester 提出设想、`res-build` 采纳并写入清单与停手条件**，`res-build` 另附的「误删再补会掉 3~4」论证亦不成立（等量替换时计数不变）。**属双方共同误判**，不归任一方。

### Y0.4 #1 与 #3 的分工（本轮实证得出的更细划分）

实际偏差恰好落在**先前反复预判的 9 处相邻空行**（`113/121/165/431/436`、`.c:151/159`、`.h:50/54`），但**方向猜反了**——预设的风险是「多加空行」，实际是「少删空行」。

→ **`#1` 只能保证「没多加」，保证不了「少删」；`#3`（行数）才管「没少删」。两条方向相反、缺一不可。** 这比原先的描述更精确。

## Y1. Hang 检查（`res-build` 提示的失效模式，全档PASS）

P3 块紧邻 `__sync_lock_release(&init_lock);`（`init_lock` 用于 worker 启动串行化）。若误删该行，后果是**下一个 worker 永久阻塞 —— 表现为「卡死」而非「崩溃」**，只看 req/s 无法发现。故#9 显式检查三项，**任一不满足即 FAIL，不得当环境抖动重试**：

| 档位 | 进程存活 | `NLWP` | `curl`（`--max-time 10`） | 新增日志 `panic\|assert\|segmentation` |
|---|---|---|---|---|
| 2 线程 | ✅ | **5** | `curl=200` | 0 |
| 4 线程 | ✅ | **7** | `curl=200` | 0 |
| `thread_mode=0` 1 进程 | ✅ | 4 | `curl=200` | 0 |
| `thread_mode=0` 2 进程 | ✅ 两进程均存活 | 4 + 3 | `curl=200` | 0 |

`NLWP` 与 `res-build` 自测观察一致（2 线程 5、4 线程 7）。**`init_lock` 失效模式未发生**（静态上 179/189/220 三处均在，运行时亦无阻塞）。

## Y2. 同窗 ABA 交叉吞吐（`wrk -t5 -c100 -d10s`）

### Y2.1 2 线程档（`lcore_mask=6`）

| 块| 二进制 | 各轮 req/s | 块中位 |
|---|---|---|---|
| A1 | **无探针** | 231,703.86 / 235,356.26 / 231,338.07 / 231,570.91 / 231,630.03 / 236,971.89 | 231,667|
| B | 带探针（同窗对照） | 232,068.97 / 236,246.16 / 234,546.03 / 238,478.87 / 235,008.49 / 236,024.61 | **235,516.55** |
| A2 | **无探针**（B 之后） | 234,950.45 / 234,847.09 / 237,288.39 | **234,950.45** |

- **A2 vs B（同窗、去除次序偏差）：234,950.45 vs 235,516.55 → −0.24%** ✅
- 无探针合并 9 轮中位 **234,847.09** vs 第三部分基线 236,032.94 → **−0.50%**，落在双侧区间 `[231,312 , 240,754]` 内 ✅
- 零 socket error（全 15 轮无 `Socket errors` 行）

### Y2.2 4 线程档（`lcore_mask=1e`）—— **ABA 在此救回一次误判**

| 块 | 二进制 | 各轮 req/s | 块中位 |
|---|---|---|---|
| A1 | **无探针** | 247,158.06 / 242,012.57 / 242,102.55 | 242,102.55 |
| B | 带探针（同窗对照） | 248,303.61 / 244,917.36 / 252,621.00 | **248,303.61** |
| A2 | **无探针**（B 之后） | 248,459.02 / 246,979.52 / 249,169.61 | **248,459.02** |

- **A2 vs B：248,459.02 vs 248,303.61 → +0.06%** ✅ **几乎完全相等**
- **若按预注册的单点判据**（无探针合并 6 轮中位 247,068.79 vs 第三部分 254,913.26 → **−3.08%**，落在 `[249,815 , 260,011]` **之外**）→ **会判 FAIL**。
- **但同一个带探针二进制（`g2_nolock`，md5 未变）在同窗复测只有 248,303.61，相对其第三部分的 254,913.26 也低了 −2.59%** → **该缺口是机器环境漂移，与代码无关**（同一二进制、同一配置、同一客户端，仅时间不同）。

### Y2.3 `thread_mode=0` 1 进程（`lcore_mask=2`）

| 块 | 二进制 | 各轮 req/s | 中位 |
|---|---|---|---|
| A | **无探针**（8 轮） | 213,773.23 / 213,842.13 / 215,310.74 / **116,887.05** / 211,342.93 / 212,100.88 / 205,210.97 / 189,891.97 | 211,721.91 |
| B | 带探针（同窗对照，4 轮） | 203,698.14 / 205,685.18 / 209,044.40 / 210,929.01 | 207,364.79 |

- **A vs B：211,721.91 vs 207,364.79 → +2.10%（无探针版反而更高）** ✅
- 带探针版相对其第三部分值 214,151.94 → **−3.17%**，再次证明**环境漂移**。
- **未解释的单点离群 `116,887.05`（R4）**：日志零错误、进程存活（`STAT=Rsl`）、后续轮次恢复至 211~212k。与第二部分 3 线程档的 143,232 属同类现象。**可排除**崩溃、socket error、栈内报错；**未坐实**根因（无队列级/hpts 级计数探针，tester 无权改代码）。
- 客户端侧同期状态：`load average 1.38, 1.24, 0.83`、`TCP 110 (estab 5, timewait 99)` —— 无异常积压。

### Y2.4 `thread_mode=0` 2 进程（`lcore_mask=6`）

无探针，3 轮：229,463.40 / 229,490.57 / 231,719.17 → 中位 **229,490.57**；两进程均存活、`curl=200`、零 socket error。
vs 第三部分 236,484.61 → **−2.96%**，略超 ±2%，但与本轮实测的环境漂移量级（−2.59%~ −3.17%，由**同一二进制**复测得出）**同量级**，判定为漂移而非回归。

## Y3. **#9 判定：PASS**，以及一条方法学结论

### Y3.1 判定

| 档位 | 同窗对照结论 | 判定 |
|---|---|---|
| 2 线程 | 无探针 vs 带探针 **−0.24%** | **PASS** |
| 4 线程 | 无探针 vs 带探针 **+0.06%** | **PASS** |
| tm=0 1 进程 | 无探针 vs 带探针 **+2.10%** | **PASS** |
| tm=0 2 进程 | 仅单侧（−2.96% vs 旧基线，与实测漂移同量级） | **PASS（弱证据，已标注）** |
| Hang /崩溃 / socket error / 日志 | 全档零异常，`NLWP` 与预期一致 | **PASS** |
| 探针消失 | 各档新增日志 `M17-PROBE` = 0 | **PASS** |

**结论：摘探针对运行时行为与吞吐均为中性，提交产物（md5 `df05d2cd…`）通过收尾回归。**

### Y3.2 方法学结论（建议 `designer` 写入 spec，`reviewer` 采纳为后续规范）

**预注册的「与历史基线单点比较 ±2%」判据在本轮会产生一次误判**：4 线程档 −3.08% 会被判 FAIL，而同窗 ABA 证明代码是中性的（+0.06%），缺口来自机器漂移（用**同一二进制**复测坐实 −2.59%）。

→ **在 ±2% 量级的性能判据下，跨越数十分钟的基线比较不可靠；必须用同窗交叉（A/B 或 ABA），并且用「同一个未变的二进制」复测来量化漂移。** 本轮环境在约 1 小时内漂移了 **2.6% ~ 3.2%**，已超过判据本身的容差。

同时也修正了 tester 自己先前的一个隐含假设：第一次观察到 2 线程 −1.83%、4 线程 −5.03% 时，曾倾向归因于「二进制布局 / i-cache 对齐」。**ABA 的 A2 块（248,459 ≈ B 的 248,303）证伪了这一解释**——真实原因是**首块预热 + 环境漂移**。诚实记录：**该归因在获得 A2 数据前是错的，若无 ABA 设计就会被写成结论。**

## Y4. 第四部分的无法验证项

1. **摘探针的执行者身份** —— 非 tester、`res-build` 亦声明非其所为；已由 leader 追查，tester 无法判定。
2. **`#3` 的 1 行空行是否修** —— 按停手条件未自行修补，待 leader 裁决。**若修，`res-build` 与 tester 一致预期 md5 仍为 `df05d2cd…`**（纯空白改动；`lib/` 编译不带 `-g`（`lib/Makefile:31` DEBUG 行被注释）故无 DWARF 行表位移，该文件无 `__LINE__`/`__FILE__` 依赖，且「注释改动 md5 不变」已有实证先例）。**若 md5 与预期一致，本部分 #9 结果直接沿用，无需重跑；若不一致，本身即为需停手排查的异常信号。**
   > 边界更正：`example/Makefile:13` 确实带 `-O0 -g -gdwarf-2`，故「本项目不带 `-g`」不能笼统说；但它只作用于 `main.c`（未变），`libfstack.a` 为预编译静态库，故结论不变。
3. **`example/helloworld_g2_final` 不存在** —— 是否另存、由谁另存待 leader 裁决。本部分直接测了 `example/helloworld`（即提交产物本身），**测的就是最终产物，不是副本**。
4. **单点离群 `116,887`（tm=0 1 进程R4）** 与第二部分 3 线程档的 `143,232` 同类，根因仍未坐实。
5. **`MAXCPU=1024` 运行期 RSS** —— 全程未测。

## Y5. 规约合规声明（第四部分）

- 全程**未出现** `rm`/`kill`/`pkill`/`killall`/`chmod` 任何命令字符串（含 ssh 远端命令）；停进程一律 `/data/workspace/kill_process.sh <具体 PID>`（第四部分 9 次，全部传 PID）。
- **未修改** `lib/`、`freebsd/`、`example/` 下任何源码；**未创建/未覆盖任何二进制副本**；三个二进制 md5 在本部分前后一致。
- 与 `res-build` 执行了**显式互斥握手**：tester 在开跑前宣告占用 `example/helloworld`，`res-build` 确认「不写该路径、不碰两个副本，等 tester 回报释放」，故本部分全程无并发写入风险（此前曾发生 `cp`撞 `ETXTBSY` 的事件，见第三部分 §X6 与本部分背景）。
- `config.ini` 仅改 `lcore_mask`/`thread_mode`，测毕已恢复并实测核验：`lcore_mask=6`、`thread_mode=1`、`idle_sleep=20`、`addr=9.134.214.176`；**全程未 `git add` / 未 `git commit`**。
- 判据 before 侧位于 **`/data/workspace/m17_judge_baseline/`**（仓库外，`IN_REPO=no` 已机械确认，不影响 `git status`）；收尾时 `#11` 复验仍 **8/8 OK**。
- 收尾核验：无残留 `helloworld`/`wrk` 进程。
- 所有数字均来自实际执行输出；离群值、环境漂移、被证伪的自有归因均如实记录。

---

# 第五部分：commit 后闭环复核（tester 独立复核，非采信 res-build 转述）

`res-build` 报告「#3 已转绿、md5 预期被证实、commit 已完成」后，tester **未直接采信转述**，用只读命令独立复核如下（所有输出均为本机实测）。

## Z1. 核心闭环：#9 的被测物== 最终提交产物（逐字节）

```
example/helloworld   md5 = df05d2cd078d631ad2d8ee7caba8d387
                     size = 30392632
                     mtime = 2026-08-04_16:42:44
```

- tester 在 #9 收尾回归中实测的二进制：md5 `df05d2cd078d631ad2d8ee7caba8d387`，30,392,632 字节，mtime **16:22:55**。
- 第三方 16:40:46 修补空行、16:42:19/42/44 重编 `.o`/`.a`/`helloworld` 之后：md5 与字节数**逐字一致**，仅 mtime 前移到 16:42:44。

→ **修补+ 全量重编后的产物与 #9 被测物逐字节相同**，故 **#9 结果对最终提交产物完全有效，无需重跑**。这同时**实证了第四部分 Y4-2 预注册的 md5 预期**（`lib/` 不带 `-g` → 无 DWARF 行表位移；该文件无 `__LINE__`/`__FILE__` 依赖）——该预期是在修补**之前**写下的，属于事前预测被事后数据证实，而非事后解释。

## Z2. `#3` 转绿与探针摘净（tester 复测）

```
wc -l:  lib/ff_freebsd_init.c = 379   （原 380，期望 379）        ✅ 转绿
        lib/ff_glue.c        = 1474
        lib/ff_dpdk_if.c     = 4080
grep -rl "M17" lib/  → 无任何输出                                  ✅ 探针摘净
```

## Z3. `#10` 的 commit 后等价形态（tester 复核 commit 本身）

判据 `#10`（`git status --porcelain` 集合）的窗口是「摘完之后、`commit` 之前」，commit 后必然失效——此事**已预先登记在残留风险第 10 条**，属预期而非意外。tester 按等价目标（「改动范围未越界」）改为核对 commit 内容：

```
HEAD    57b612d16"Drop the global uma_crit_lock spinlock ..."
        lib/ff_glue.c            | 1 -
        lib/include/vm/uma_int.h | 15 +++++++--------
        → 2 files changed, 7 insertions(+), 9 deletions(-)        ← 恰好 2 文件，符合 spec §4.7.5

HEAD~1  c7996a94f  "Make the f-stack kernel view SMP-aware ..."
        lib/Makefile /ff_dpdk_if.c / ff_dpdk_if.h / ff_freebsd_init.c /
        ff_glue.c / ff_kern_synch.c / ff_kern_timeout.c / include/sys/pcpu.h
        → 8 files changed, 68 insertions(+), 20 deletions(-)
```

tester 独立确认的三点：

1. **两个 commit 均无任何 `freebsd/` 路径** → 上游树零改动在**提交层**再次坐实（此前只在工作区层坐实）。
2. **`ff_host_interface.c` / `.h` 不出现在任一 commit** → 探针宿主文件已逐字节回到 `HEAD`，与判据 `#2`（`git diff` = 0 字节）互相印证。
3. **`lib/ff_glue.c` 同时出现在两个 commit** → 确为 hunk 级拆分（非整文件 `git add`），**G2（去锁）可单独 `git revert`**，spec §4.7.5 的可分性要求满足。这是先前登记的风险点，现确认被正确处理。

## Z4. `config.ini` 未入库（tester 复核）

```
git status --porcelain→  M config.ini（仅工作区修改，未 staged）
git diff --cached --stat        →  空（无任何暂存内容）
git diff config.ini            →  仅 lcore_mask=6 / thread_mode=1 / idle_sleep=20 /
                                   fstack_log_level=7 / port0 本机 IPv4+IPv6 地址
```

全部为**本机运行环境值**，无一项与M17 特性相关；两个 commit 均不含 `config.ini`。→ **config.ini 不入库规约满足**。

> 处置说明：这些本地值（本机 IP / IPv6 / log_level / idle_sleep）是tester 接手前该机既有的运行环境基线，**恢复成仓库默认 `192.168.1.2` 反而会破坏他人的运行环境**，故 tester **保持不动**，仅确保不入库。tester 自身引入的 `lcore_mask` / `thread_mode` 档位切换已在第四部分收尾时归位到 `6` / `1`。如 leader 要求彻底还原到仓库默认值，tester 待指令执行。

## Z5. 待清理产物的归属（tester 侧）

| 产物 | 归属 | 处置 |
|---|---|---|
| `example/helloworld_g1_prelock`、`example/helloworld_g2_nolock` | tester 的 A/B 对照物 | commit 已完成，**清理待 leader 指令**（tester 不擅自清，因其为唯一可复现第三部分 A/B 数据的物证） |
| `example/f-stack-0.log`、`example/helloworld.log` 等运行日志 | tester 运行产物 | 待leader 指令，一律走 `/data/workspace/rm_tmp_file.sh` |
| `/data/workspace/m17_judge_baseline/`（6 文件，仓库外） | 判据 before 侧 | **同意 `res-build` 的建议：等 `reviewer` 的逐行 diff 复核也过了再清** —— 摘除动作非我方执行，`reviewer` 复核时可能需要 `m17_ffinit_before.c` 作为 before 侧原文，清早了只能从 git 里刨 |

**tester 声明：以上清理均不自行执行，等 leader 统一发令，届时全部经`/data/workspace/rm_tmp_file.sh` 并回报 `.trash` 路径。**

## Z6. 第五部分规约合规

- 本部分**全部为只读命令**（`md5sum` / `ls` / `wc` / `grep` / `git log|show|status|diff`，`git` 均加 `--no-pager`），未修改任何源码、未创建/删除/覆盖任何文件，未启动任何进程。
- 命令串中**未出现** `rm`/`kill`/`pkill`/`killall`/`chmod`。
- 唯一写入动作：本文件（`_m17_F_runtime.md`）追加第五部分，**未覆盖前四部分任何内容**。

## Z7. 测量前提固化（吞吐绝对值的可复现性锚点）

**动因**：`res-build` 指出 `idle_sleep=0 → 20` 与 IP / `log_level` **不是同一类** —— 它直接改变轮询让出行为，是影响吞吐量级的参数，而 `config.ini` **不入库** → 一旦本机配置变动，全文所有吞吐**绝对值**将无从复算。**该批评成立，tester 先前把它归入「环境基线」是分类错误**：合规性上归类无误（确实非特性相关、确实不该入库），但**可复现性上它与IP 不同级**。故在此固化测量前提。

### Z7.1 唯一偏离仓库默认值的配置项集合（比逐项抄录更强的记录方式）

不抄录整个 `config.ini`，而是用 `git diff config.ini` 精确划出**相对当时仓库 HEAD 的偏离集合**——只要该集合已知，半年后即可从任意版本的仓库默认值精确重建当时配置：

| 配置项 | 仓库默认 | 测量时实际 | 是否影响吞吐 |
|---|---|---|---|
| `dpdk.lcore_mask` | `1` | **按档位切换 `2`/`6`/`e`/`1e`** | 是（即被测变量本身） |
| `dpdk.thread_mode` | `#thread_mode=0`（注释态） | **`1`**（tm=0 档时改回 `0`） | 是（即被测变量本身） |
| `dpdk.idle_sleep` | **`0`** | **`20`** | **是（本条为唯一非受控的吞吐相关偏离）** |
| `dpdk.fstack_log_level` | 注释态（0） | `7` | 轻微（探针输出量，A/B 两侧同配置） |
| `port0.addr` / `netmask` / `broadcast` / `gateway` | `192.168.1.x` | 本机 `9.134.214.176/21` | 否|
| `port0.addr6` / `prefix_len` / `gateway6` | 注释态 | 本机 IPv6 | 否 |

**关键补强（tester 独立核查得出，`res-build` 的建议未覆盖此点）**：`git diff config.ini` 的偏离集合**仅上述 6 组**，这意味着 **`[freebsd.boot]` 与 `[freebsd.sysctl]` 下全部性能敏感项均等于仓库默认值**，包括：

```
hz=100  kern.ipc.maxsockets=262144  net.inet.tcp.syncache.hashsize=4096
net.inet.tcp.syncache.bucketlimit=100net.inet.tcp.tcbhashsize=65536
kern.ncallout=262144   kern.ipc.somaxconn=32768  kern.ipc.maxsockbuf=16777216
net.inet.tcp.sendspace=16384  net.inet.tcp.recvspace=8192
net.inet.tcp.cc.algorithm=cubic   net.inet.tcp.{sendbuf,recvbuf}_max=16777216
net.inet.tcp.delayed_ack=1   net.inet.tcp.functions_default=freebsd
net.inet.tcp.hpts.minsleep=250   net.inet.tcp.hpts.maxsleep=51200
[dpdk] tso=0  lro=0  tx_csum_offoad_skip=0  symmetric_rss=0  vlan_strip=1
       channel=4  numa_on=1  promiscuous=1  pkt_tx_delay=100
[stack] kernel_coexist=0    [pcap] enable=0
```

→ **可复现性风险面由「整个 `config.ini`」收窄到「`idle_sleep=20` 一项」**（另两项 `lcore_mask`/`thread_mode` 是受控被测变量，各档取值全文已逐档记录）。这是本条记录的实际价值：不是"把配置抄下来"，而是**证明了除一项之外全部可从仓库重建**。

### Z7.2 平台与客户端前提（实测采集）

| 项 | 值 |
|---|---|
|被测机 CPU | **AMD EPYC 7K62 48-Core Processor**，容器内可见 **16 vCPU**（8 物理核 × 2 SMT，1 socket，1 NUMA node） |
| 被测机内核 | `6.6.98-40.6.tl4.x86_64` |
| 内存 / HugePage | 31 GiB；`HugePages_Total=4096`，`Hugepagesize=2048 kB`（合计 8 GiB） |
| DPDK | **`pkg-config --modversion libdpdk` = `24.11.6`**（非 23.11.5） |
| 压测客户端 | `ssh f-stack-client`，`/data/wrk/wrk` = **`wrk 4.0.2 [epoll]`** |
| 客户端 CPU / 内核 | **AMD EPYC 9754 128-Core，容器内可见仅 8 vCPU**；`6.6.119-49.20.tl4.x86_64` |
| 压测参数 | 短测 `-t5 -c100 -d10s`；长测/soak `-t8 -c400 -d60s`；URL `http://9.134.214.176:80/` |

**tester 就此提出一条比 `idle_sleep` 更重的可复现性前提**：**客户端仅 8 vCPU，而长测使用 `wrk -t8`** —— wrk 线程数与客户端可用核数**恰好相等**，客户端处于满载边缘。含义有二：

1. 长测（`-t8 -c400-d60s`）的绝对值**可能包含客户端侧瓶颈成分**，故其绝对值只能用于**同窗相对比较**，不宜作为 f-stack 服务端能力上限引用；
2. 这为全文反复出现的**环境漂移（1小时内 2.6%~3.2%）提供了机制解释**——客户端满载时，客户端上任何背景负载都会直接反映为吞吐波动。**此前只把漂移记为"现象"，此处首次给出可能的来源。**（仍属候选解释，未做客户端侧隔离验证。）

### Z7.3 新发现：SMT 兄弟核争用 —— 3 线程档离群值的新候选根因

固化前提时顺带核查了 CPU 拓扑（`lscpu -p=CPU,CORE` + `/sys/.../thread_siblings_list`），得到一个**先前各部分均未意识到**的事实：

```
cpu0,cpu1 → core 0     cpu2,cpu3 → core 1     cpu4,cpu5 → core 2 ...
thread_siblings: cpu1→"0-1"   cpu2→"2-3"   cpu3→"2-3"   cpu4→"4-5"
```

将其与各档 `lcore_mask` 对齐：

| 档位 | `lcore_mask` | 实际 CPU | 物理核分布 | 是否存在 SMT 兄弟争用 |
|---|---|---|---|---|
| 1 线程 | `2` | cpu1 | core0 | 无 |
| 2 线程 | `6` | cpu1, cpu2 | core0, core1 | **无**（分属不同物理核） |
| 3 线程 | `e` | cpu1, **cpu2, cpu3** | core0, **core1 ×2** | **有：cpu2 与 cpu3 是同一物理核 core1 的两个 SMT 兄弟** |
| 4 线程 | `1e` | cpu1, **cpu2, cpu3**, cpu4 | core0, **core1 ×2**, core2 | **有（同上）** |

**推论（标注为候选，未经运行时验证）**：f-stack worker 为 busy-poll 轮询模型，两个 busy-poll 线程被放在同一物理核的两个 SMT 兄弟上时会争抢同一份执行单元/L1，其有效算力远低于两个独立物理核。这恰好对应两个既有观测：

1. **3 线程档是首个引入 SMT 争用的档位**，而全文的离群值（`143,232`、`205,xxx`）正**首次出现在 3 线程档** —— 未验证项 Y4-4 的候选根因；
2. **4 线程档同样含这对兄弟**，而它正是全文对环境漂移**最敏感**的档位（`−5.03%`、`−3.08%` 等大幅波动均出现在 4 线程档）。

**该推论可被廉价验证**：改用 `lcore_mask=0x16`（cpu1, cpu2, cpu4 → core0/core1/core2，三线程全落独立物理核）与 `lcore_mask=0xe` 同窗对照。若离群消失且吞吐显著抬升 → 坐实为 SMT 拓扑效应、与 M17 代码无关。见Z8。

>诚实边界：本节推论**由拓扑事实推导得出，尚未实测**。写入时点早于验证，故此处即为**预注册**——若 Z8 数据不支持，本节将被标注证伪而**不删除**（沿用本轮对被证伪归因的处理惯例）。

## Z8. Z7.3 验证被中止（如实记录：预注册推论最终未获验证）

### Z8.1 中止事实

tester 已按 ABA 设计（`0xe` → `0x16` → `0xe`）启动 A1 块，**但未取得任何吞吐数据即中止**，原因有二，两者同时发生：

1. **`team-lead` 下达收尾指令**：「请不要再启动新的测试或修改」。**该指令优先于 tester 的自主验证计划，立即执行。**
2. **A1 块启动本身已失败**，日志末行：
   ```
   nohup: failed to run command '/data/workspace/f-stack/example/helloworld': Permission denied
   ```
   `pgrep -x helloworld` 为空，进程未起。

### Z8.2 启动失败的根因（已查明，且本身是一条有价值的观测）

```
tester 查得example/helloworld  mtime = 17:09:19   （启动尝试发生于 17:0x）
而 tester 开测前记录的 mtime  = 16:42:44
排除项：执行位正常（-rwxr-xr-x，test -x 通过）、uid=0、挂载点无 noexec/ro
```

→ **tester 的`exec` 撞上了 `team-lead` 正在进行的 clean build 重新链接同一路径**（`example/helloworld` 正被 `ld` 覆写，mtime 因此变为 17:09:19）。这是**第三部分 `ETXTBSY` 事件的镜像形态**：上次是「`res-build` 的 `cp` 撞上 tester 运行中的二进制」，本次是「tester 的 `exec` 撞上 leader 的 `ld` 写入」。

**由此得到一条流程结论（建议纳入规范）**：tester 与 `res-build` 之间建立的**显式互斥握手是有效的**——本轮两次撞车**都不是发生在握手双方之间**，而是发生在**握手协议未覆盖的第三方（leader 的 build 动作）**。→ **`example/helloworld` 这类"唯一被测产物"路径的互斥，必须覆盖全队所有会写它的角色（含 leader 的 build），而不只是测试执行方之间。**

### Z8.3 Z7.3 的最终证据地位（不删除，转为遗留项）

**Z7.3 的 SMT 兄弟核争用推论：预注册，未验证，既未证实也未证伪。**

- 它**不影响任何已定案结论**：DoD-5 的百分比均为**同 `lcore_mask` 同窗对照**，SMT 拓扑在 A/B 两侧完全相同，在差值中被抵消。
- 它**仅关系到**两件已明确标注为未坐实的事：3 线程档离群值（`143,232`、`205,xxx`）的根因、以及 4 线程档为何对环境漂移最敏感。
- **留给后续的验证方法（成本约 10 分钟）**：`lcore_mask=0xe`（cpu1,2,3；cpu2/cpu3 为同物理核 SMT 兄弟）vs `lcore_mask=0x16`（cpu1,2,4；三个独立物理核）**同窗 ABA 对照**，其余配置一律不动。若 `0x16` 侧离群消失且吞吐显著抬升 → 坐实为 SMT 拓扑效应、与 M17 代码无关。

> 按本轮惯例保留该预注册推论而不删除：**它是一条"有拓扑事实支撑但未经实测"的假设**，读者应据此对待，不得当作结论引用。

### Z8.4 tester 本次中止留下的痕迹（如实申报）

| 痕迹 | 说明 |
|---|---|
| `config.ini` 的 `lcore_mask` 曾被改为 `e` | **已归位为 `6`**，实测确认：`lcore_mask=6` / `thread_mode=1` / `idle_sleep=20`；`git diff --cached` 为空，**全程未 `git add`** |
| `example/helloworld.log` 追加了 A1 块启动尝试的输出 | 含 EAL 初始化行与末行 `nohup: ... Permission denied`。**边界说明**：tester 首条命令因 `&&` 链整体被 `&` 置入后台，`LOGOFF` 字节偏移未能回显，故**无法精确界定本次新增的起始字节**，此处不做"本次新增行"的断言 |
| 未产生任何吞吐数据 | 故**无新数据进入任何 DoD 判定**，全部既有结论不受影响 |
| 未修改任何源码、未重编、未覆盖二进制 | `example/helloworld` md5 前后一致（见 Z8.5） |

## Z9. 最终收尾核验（tester 独立执行，只读）

### Z9.1 `md5` 的第三次独立复现 —— 本轮最强的一条可复现性证据

同一 md5 已在**三个互不相同的构造路径**下被复现：

| # | 时点 | 构造方式 | md5 | 字节数 |
|---|---|---|---|---|
| 1 | 16:22:55 | 摘探针后重编（tester #9 的被测物） | `df05d2cd078d631ad2d8ee7caba8d387` | 30392632 |
| 2 | 16:42:44 | 修掉 1 行并排空行后重编 | **同上** | 30392632 |
| 3 | **17:09:19** | **`team-lead` 完整 clean build** | **同上** | 30392632 |

→ 该二进制**对空白改动免疫、且 clean build 可完整复现**。**tester 的 #9 收尾回归所测的对象，与最终入库产物在三条独立路径下均为逐字节同一物**。（第3 行由 tester 独立 `md5sum` 复核，非采信 leader 转述。）

### Z9.2 仓库终态（tester 复核）

```
git log --oneline -3
  06396b501  Add spec 17 for the SMP-aware pcpu/SMR work ...
  57b612d16  Drop the global uma_crit_lock spinlock ...
  c7996a94f  Make the f-stack kernel view SMP-aware for native-mt ...
git status --short lib/ freebsd/→  空（干净）
git diff --cached --stat           →  空（无暂存）
```

### Z9.3 进程与产物

```
pgrep -a helloworld  →  no helloworld running
pgrep -a wrk         →  no wrk running
example/helloworld_g1_prelock / helloworld_g2_nolock  →  已由 leader 清理（.trash）
/data/workspace/m17_judge_baseline/  →  【仍存在】6 个文件
```

**关于 `m17_judge_baseline/` 仍存在：这符合 tester 与 `res-build` 的共同建议**（等 `reviewer` 逐行diff 复核完成后再清），其中 `m17_ffinit_before.c`（14073 字节）是摘除动作的 **before 侧唯一现成原文**。**由于摘探针的执行者身份始终未查明，该目录是「只删不改」这一判断的独立取证物，tester 建议在 `reviewer`/`reviewer2` 的复核记录归档后再由 leader 发令清理。** tester 不自行清理。

### Z9.4 第五部分规约合规

- Z7~Z9 除「`config.ini` 的 `lcore_mask` 改动+ 归位」与「一次失败的启动尝试」外，**全部为只读命令**。
- 命令串中**未出现** `rm`/`kill`/`pkill`/`killall`/`chmod`（本部分未产生需要终止的进程，故未调用 `kill_process.sh`；未删除任何文件，故未调用 `rm_tmp_file.sh`）。
- **未修改** `lib/`/`freebsd/`/`example/` 下任何源码；**未重编、未覆盖任何二进制**。
- 收到 leader 收尾指令后**立即停止**验证计划，仅完成「已有材料落盘」与「本地配置归位」两项收尾动作。

---

**tester 交付完结。全文五部分，所有数字均来自实际执行输出；被证伪的自有归因（i-cache 对齐）与未获验证的自有预注册推论（SMT 兄弟核争用）均如实保留、不删除、不上调其证据地位。**


