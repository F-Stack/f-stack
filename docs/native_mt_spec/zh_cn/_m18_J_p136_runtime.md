# M18 遗留风险专项 —— 运行时验证报告（J / P1+P3+P6）

测试方：tester2（写方，与 coder2/reviewer2 分离）。
仓库 `/data/workspace/f-stack`，HEAD `e0fb11c9c`。
测试对象：本轮三处修复 —— P1（ipfw dyn_hp 显式数组）/ P3（tcp_hpts 原子互斥）/ P6（pcpu.h 惰性 fail-fast），以及 thread_mode=0 多进程零回归。
测试结论：**T1 PASS、T2 PASS、T3 未执行（环境 L2 不通）**。

---

## 0. 运行环境与版本指纹

- 本机双网卡：DPDK 独占网卡 IP `<DPDK_NIC_IP>`（igb_uio 接管的 PCI 设备）；内核栈用 `127.0.0.1` 回环。连通性验证需 `ssh f-stack-client` 从对端测。
- `config.ini` 本地测试值（**严禁提交入库**）：`lcore_mask=3`（lcore 0、1）、`thread_mode` 注释态 `#thread_mode=0`（=0 多进程）、`idle_sleep=0`、`fstack_log_level=7`、`kni.enable=1` 等。测试前已 `cp config.ini /tmp/_m18_J_config_baseline.ini` 备份。
- 二进制（clean build 最新产物）：

```
$ md5sum example/helloworld lib/libfstack.a
2da59cdd4780ee5cb3979145bc585593  example/helloworld
7d6f74146623308088670b59547c007e  lib/libfstack.a
-rwxr-xr-x 30413280 14:38:19 example/helloworld
-rw-r--r--  7032162 14:38:13 lib/libfstack.a
```

- 本轮改动文件指纹（`git diff --stat`）：

```
 config.ini                           | 33 ++++++++---------
 freebsd/netinet/tcp_hpts.c           | 17 ++++-------
 freebsd/netpfil/ipfw/ip_fw_dynamic.c | 17 ++++++++---
 lib/ff_api.h                         | 10 ++++---
 lib/include/amd64/include/pcpu.h     | 21 +++++++++---
 tests/unit/Makefile                  |  2 +-
 tests/unit/test_ff_thread.c          | 66 ++++++++++++++++++++++++++++++
 7 files changed, 121 insertions(+), 45 deletions(-)
```

- `ssh f-stack-client` 可达（hostname `VM-211-87-tencentos`）。

**P6 修复核心（实测前读码确认）**：`lib/include/amd64/include/pcpu.h` 中 `PCPU_GET/PCPU_ADD/PCPU_INC/PCPU_PTR/PCPU_SET/get_pcpu` 全部经 `ff_pcpu_get()`，`pcpup==NULL` 时 `panic("F-Stack: NULL per-CPU context ...")`。这是 T1/T2 的重点观察对象：**正常启动时 `pcpup` 非 NULL，不应触发 panic**；一旦出现 `NULL per-CPU context` 即判定 P6 破坏零回归。

---

## T1 —— thread_mode=0 多进程零回归（一票否决）

**操作**：
- 确认 `config.ini` 中 `thread_mode` 为注释态 `#thread_mode=0`（生效默认 0）。
- 清理旧日志（`rm_tmp_file.sh`），启动：
  `setsid nohup /data/workspace/f-stack/example/helloworld --conf /data/workspace/f-stack/config.ini --proc-type=primary --proc-id=0 < /dev/null > /tmp/_m18_t1.log 2>&1 &`
- 等待 8 秒，检查进程与日志。

**观察**：
- 进程存活（PID `1857456`）。
- `f-stack-0.log`（日志前缀 `./f-stack-` 相对进程 cwd，落在 `/data/workspace/f-stack/`）：
  ```
  lcore: 0, port: 0, queue: 0
  create mbuf pool on socket 0
  create ring:dispatch_ring_p0_q0 success, 2047 ring entries are now free!
  create ring:dispatch_ring_p0_q1 success, 2047 ring entries are now free!
  Port 0 MAC:20:90:6F:7D:5D:08
  LRO is disabled
  TSO is disabled
  set port 0 to promiscuous mode ok
  Checking link statusdone
  Port 0 Link Up - speed 4294967295 Mbps - full-duplex
  TCP Hpts created 1 swi interrupt threads and bound 0 to cpus
  ipfw2 (+ipv6) initialized, divert loadable, nat loadable, default to accept, logging disabled
  f-stack-0: Successed to register dpdk interface
  ```
- `grep -iE "panic|segmentation|assert|fatal|NULL per-CPU"` = **无任何命中**。
- 关键：**P6 的 `NULL per-CPU context` panic 未出现** → 主线程 pcpu 建立正常，所有 PCPU_GET 经 `ff_pcpu_get()` 时 `pcpup` 非 NULL，惰性 fail-fast 未误触发。

**结论**：**PASS**（进程正常启动、DPDK 网卡注册成功、`TCP Hpts created 1` 印证单 lcore、无 panic/seg/assert，P6 零回归）。

**证据**（脱敏后）：
```
lcore: 0, port: 0, queue: 0
...
Port 0 Link Up - speed 4294967295 Mbps - full-duplex
TCP Hpts created 1 swi interrupt threads and bound 0 to cpus
ipfw2 (+ipv6) initialized, divert loadable, nat loadable, default to accept, logging disabled
f-stack-0: Successed to register dpdk interface
```

> 注：日志中出现 `VDEV_BUS: vdev_probe_all_drivers(): ... virtio_user0`、`Port 1 MAC` / `set port 1 to promiscuous mode error`，是 vdev 探测 + 非 DPDK 目标卡的既知无害提示（与 `_m18_G_runtime.md` 记录一致），不影响启动成功判定。

---

## T2 —— thread_mode=1 多线程冒烟

**操作**：
- 临时改 `config.ini`：`#thread_mode=0` → `thread_mode=1`（`lcore_mask=3` 已覆盖 lcore 0、1 两个 lcore，满足 ≥2）。
- 清理日志，启动（同 T1 命令），等待 8 秒检查 N 个 worker 初始化。

**观察**：
- 进程存活（PID `1858346`），`ps -o nlwp` 显示 **NLWP=6**（主线程 + 2 worker + DPDK 内部线程），印证单进程多线程。
- `helloworld.log`（worker 侧，落 `/data/workspace/f-stack/helloworld.log`）：
  ```
  thread init success on lcore 0.
  thread init success on lcore 0.
  f-stack-0: Successed to register dpdk interface
  thread init success on lcore 1.
  ```
  → **2 个 worker（lcore 0、lcore 1）各自初始化成功**，对应 `lcore_mask=3`（0b11）。
- `f-stack-0.log` 关键行：
  ```
  TCP Hpts created 2 swi interrupt threads and bound 0 to cpus
  ```
  → thread_mode=1 下 hpts 实例数 = 2（= worker 数），印证 `mp_ncpus=2`。**P3（tcp_hpts 原子互斥）改动不影响启动，hpts 实例数正确**。
- `grep -iE "panic|segmentation|assert|fatal|NULL per-CPU"` = **无任何命中**。
- 关键：**P6 的 `NULL per-CPU context` panic 未出现** → 各 worker 的 pcpup 由 `ff_pcpu_thread_init` 建立、非 NULL，P6 惰性 fail-fast **未误伤正常 worker**。

**P1（ipfw dyn_hp 显式数组）覆盖情况**：本机未加载 ipfw dynamic 规则运行时场景，仅观察到 `ipfw2 (+ipv6) initialized` 正常初始化，**未覆盖 ipfw dynamic 运行时路径**（无 malloc 失败/越界 panic 可观察）。如实标注。

**结论**：**PASS**（单进程多线程正常启动、2 worker 各自初始化、`TCP Hpts created 2`、无 panic/seg/assert，P6 不误伤 worker）。

**证据**（脱敏后）：
```
thread init success on lcore 0.
f-stack-0: Successed to register dpdk interface
thread init success on lcore 1.
...
TCP Hpts created 2 swi interrupt threads and bound 0 to cpus
```

---

## T3 —— 连通性（可选，视环境）

**操作**：
- 从对端 `ssh f-stack-client` ping / curl `<DPDK_NIC_IP>:80`。

**观察**：
```
PING <DPDK_NIC_IP> ... 2 packets transmitted, 0 received, 100% packet loss
curl_http_code=000   （连接超时）
```

**结论**：**未执行（环境 L2 不通）**。ping 100% 丢包、curl 超时，与 `_m18_G_runtime.md` 记录的「环境 L2 不通」一致，属环境网络配置问题（DPDK 网卡 ARP/网关/路由），非本轮代码回归。如实记录，不强求。

---

## 3. 汇总与约束遵循

| 测试项 | 结论 | 说明 |
| --- | --- | --- |
| T1 thread_mode=0 多进程零回归 | **PASS** | 启动成功、网卡注册、`TCP Hpts created 1`、无 panic（P6 零回归）；连通性环境不满足 |
| T2 thread_mode=1 多线程冒烟 | **PASS** | 2 worker 各自初始化、`TCP Hpts created 2`（P3 不影响启动）、无 panic（P6 不误伤 worker） |
| T3 连通性 | **未执行** | 环境 L2 不通（ping 100% 丢包、curl 超时），非代码回归 |

约束遵循确认：
- 停止进程一律 `/data/workspace/kill_process.sh`（T1/T2 两次均用脚本传 PID，未直接 kill/pkill）。
- `config.ini` 临时改动（`thread_mode` 0→1→0）**测完已完全还原**，`diff config.ini /tmp/_m18_J_config_baseline.ini` 退出码 0、逐字节一致；未 `git add config.ini`（其 `M` 状态为仓库既有本地测试值，与测试前一致）。
- 文档中无真实 IP：`<DPDK_NIC_IP>`/`<DPDK_NIC_IPV6>` 占位、`127.0.0.1` 回环、`fe80::feee:ffff:feff:ffff`（link-local，非本地真实地址）；未出现任何 `9.134.x` / `2402:4e00:` 完整真实地址。
- 日志清理走 `/data/workspace/rm_tmp_file.sh`；本轮测试产生的 `f-stack-0.log`、`helloworld.log`（落在 `/data/workspace/f-stack/`，进程 cwd）为运行产物，待 leader 指令统一清理。

## 4. 诚实边界（未验证项）

1. **连通性（T3）**：DPDK 网卡 `<DPDK_NIC_IP>` 从对端 L2 层不通（ping 100% 丢包、curl 超时），属环境网络配置问题，非本轮代码回归；未验证到数据面连通。
2. **P1 ipfw dynamic 运行时路径**：本机未加载 ipfw dynamic 规则，仅观察到 `ipfw2 initialized`；dyn_hp 显式数组初始化未在真实动态规则场景下验证，仅代码级 review 确认（见 `_m18_I_p136_review.md`）。
3. **P6 fail-fast 崩溃路径**：正常运行不触发 `pcpup==NULL`，fail-fast 分支仅代码级 review 确认；本轮验证的是「正常路径不误触发 panic」（即零回归），非「异常路径正确 panic」。
4. **P3 tcp_hpts 原子互斥**：本轮仅验证「启动不受影响、hpts 实例数正确」，未做高并发锁争用压测；原子互斥的正确性由代码级 review 确认（见 `_m18_I_p136_review.md`）。
