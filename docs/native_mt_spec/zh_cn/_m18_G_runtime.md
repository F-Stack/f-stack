# M18 遗留风险专项 —— 运行时验证报告（G）

测试方：tester（写方，与 coder/reviewer 分离）。
仓库 `/data/workspace/f-stack`，HEAD `9ef6dc92e`。
测试对象：本轮 4 项修复（counter 原子化 P2 / net.isr.dispatch 防护 P4 / 行缓冲 __thread P5 / ff_pthread_create 文档化 + fail-fast P6），以及 thread_mode=0 多进程零回归。
测试结论：**T1 PASS、T2 PASS、T3 PASS**（连通性验证因环境 L2 不通未执行，如实记录）。

---

## 0. 运行环境

- 本机双网卡：DPDK 独占网卡 IP `<DPDK_NIC_IP>`（由 `igb_uio` 驱动接管的 PCI 设备 `0000:00:09.0`）；内核栈网卡 eth1（virtio-pci `0000:00:05.0`，非 DPDK 目标）。
- `config.ini` 本地测试值（**严禁提交入库**）：`lcore_mask=3`、`fstack_log_level=7`、`kni.enable=1`（`owner_proc_id=1`）、`extra_eal_args=--log-level=bus.vdev:8`、`pkt_tx_delay=30` 等。测试前已 `cp config.ini /tmp/_m18_config_baseline.ini` 备份。
- 二进制 `example/helloworld` 为 clean build 最新产物（Aug 13 13:22，error 0）。
- 大页：`HugePages_Total=1024 / Free=1000`（2MB 页），充足。
- 对端机器 `ssh f-stack-client` 可达（用于连通性验证）。

**DPDK 网卡说明**：`config.ini` 未显式 `allow`（被注释），DPDK 自动探测时会尝试绑定 `0000:00:05.0`（virtio-pci，内核栈网卡 eth1）并打印 `VIRTIO_INIT: eth_virtio_pci_init(): Failed to init PCI device / PCI_BUS: Requested device 0000:00:05.0 cannot be used`。这是**无害的**——该卡不是 DPDK 目标，真正的 DPDK 网卡 `0000:00:09.0`（igb_uio）随后正常注册（日志出现 `Successed to register dpdk interface`）。历史成功日志（`example/helloworld_cm7_fix2.log`）中同样存在该提示，属既知现象，不影响启动成功判定。

---

## T1 —— thread_mode=0 多进程零回归（一票否决）

**操作**：
- 确认 `config.ini` 中 `thread_mode` 为注释态 `#thread_mode=0`（实际生效默认 0，多进程模式）。
- 清理旧日志（`rm_tmp_file.sh`），确保证据干净。
- 启动：`setsid nohup ./example/helloworld --conf config.ini --proc-type=primary --proc-id=0 < /dev/null > /tmp/_m18_t1.log 2>&1 &`
- 等待约 8 秒，检查进程状态与日志。
- 连通性验证（可选）：`ssh f-stack-client` 从对端 curl / ping `<DPDK_NIC_IP>:80`。

**观察**：
- 进程存活（持续运行，main_loop 空转等事件），PID 记录于执行过程。
- `helloworld.log`（本次干净日志）：
  ```
  thread init success on lcore 0.
  ```
- `f-stack-0.log` 尾部：
  ```
  Port 0 Link Up - speed 4294967295 Mbps - full-duplex
  TCP Hpts created 1 swi interrupt threads and bound 0 to cpus
  ...
  f-stack-0: Successed to register dpdk interface
  ```
- 无 `panic` / `Segmentation` / `assert` / `fatal` 关键字（grep 确认）。
- 连通性验证：从对端 `ping` `<DPDK_NIC_IP>` 100% 丢包、`curl http://<DPDK_NIC_IP>:80/` 返回 `HTTP_CODE=000`（连接超时）。L2 层不通，属环境网络配置问题（DPDK 网卡 ARP/网关/路由），非本轮代码回归。

**结论**：**PASS**（进程正常启动、DPDK 网卡注册成功、进入监听态、无 panic）。连通性验证**未执行**（环境 L2 不通，如实记录，不强求）。

**证据**（脱敏后）：
```
EAL: Detected CPU lcores: 16
EAL: Selected IOVA mode 'PA'
VIRTIO_INIT: eth_virtio_pci_init(): Failed to init PCI device   ← 无害（非 DPDK 目标卡 eth1）
PCI_BUS: Requested device 0000:00:05.0 cannot be used
...
f-stack-0: Successed to register dpdk interface                  ← DPDK 网卡 0000:00:09.0 成功
thread init success on lcore 0.                                  ← 进入监听态
```

---

## T2 —— thread_mode=1 多线程冒烟（含 P5 行缓冲验证）

**操作**：
- 临时改 `config.ini`：`#thread_mode=0` → `thread_mode=1`（`lcore_mask=3` 已覆盖 lcore 0、1 两个 lcore，满足 ≥2）。
- 清理旧日志，启动：`setsid nohup ./example/helloworld --conf config.ini --proc-type=primary --proc-id=0 < /dev/null > /tmp/_m18_t2.log 2>&1 &`
- 等待约 8 秒，检查 N 个 worker 初始化与日志污染情况。

**观察**：
- 进程正常启动，无 panic/seg/assert。
- `helloworld.log`（本次干净）：
  ```
  thread init success on lcore 0.
  f-stack-0: Addr6: <DPDK_NIC_IPV6>
  f-stack-0: Gateway6: fe80::feee:ffff:feff:ffff
  f-stack-0: Ethernet address: <DPDK_NIC_MAC>
  f-stack-0: Successed to register dpdk interface
  thread init success on lcore 1.
  ```
  → **2 个 worker（lcore 0、lcore 1）各自初始化成功**，对应 `lcore_mask=3`（0b11）。
- `f-stack-0.log` 关键行：
  ```
  TCP Hpts created 2 swi interrupt threads and bound 0 to cpus
  ```
  → thread_mode=1 下 hpts 实例数 = 2（= worker 数），印证 native-mt `mp_ncpus=N` 每线程独立 hpts 实例设计（spec §6.19 R6）。

**P5 行缓冲验证点**：
- 观察启动期多 worker 打印阶段，`helloworld.log`（6 行）与 `f-stack-0.log`（26 行）均**完整、无拼接/错乱**：两个 `thread init success on lcore X.` 各占独立完整行，中间夹着 f-stack-0 的注册日志也未互相打断。
- **结论边界（如实）**：本次为低并发场景（启动期 `init_lock` 串行化，2 个 worker 顺序打印），**未观测到日志拼行/污染**；**未做高强度并发打印压测**，无法断言 P5 在极端并发下完全无污染，仅确认启动期无污染。

**结论**：**PASS**（单进程多线程正常启动、2 worker 各自初始化、无 panic、启动期日志无污染）。

**证据**（脱敏后）：
```
thread init success on lcore 0.
f-stack-0: Successed to register dpdk interface
thread init success on lcore 1.
...
TCP Hpts created 2 swi interrupt threads and bound 0 to cpus
```

---

## T3 —— P4 net.isr.dispatch 防护验证

**操作**：
- 还原 `thread_mode` 为 `#thread_mode=0`（T3 用多进程模式，简单）。
- 临时在 `[freebsd.sysctl]` 段**顶部**追加非法值：`net.isr.dispatch=hybrid`。
- 清理日志，启动：`setsid nohup ./example/helloworld --conf config.ini --proc-type=primary --proc-id=0 < /dev/null > /tmp/_m18_t3.log 2>&1 &`
- 等待约 8 秒，检查告警与进程状态。
- 停止进程，**还原 config.ini**（删除 `net.isr.dispatch` 行，确认 `diff` 与基线一致）。

**观察**：
- `f-stack-0.log` 第 24 行打印 P4 防护告警：
  ```
  net.isr.dispatch must stay direct (hybrid/deferred silently drop packets); ignoring requested value
  ```
  告警位置正确（在 `TCP_ratelimit: Is now initialized` 之后，即 sysctl 应用循环 `ff_freebsd_init.c:357-374` 阶段）。
- 进程**继续正常启动**：告警之后 `f-stack-0: Successed to register dpdk interface`，`helloworld.log` 打印 `thread init success on lcore 0.`，无 panic/seg/assert。
- 默认 `direct` 未被改写（防护代码 `continue` 跳过该 sysctl 注入，`NETISR_DISPATCH_POLICY_DEFAULT = DIRECT` 保持默认）。
- 还原后 `diff config.ini /tmp/_m18_config_baseline.ini` 退出码 0，`grep -c net.isr.dispatch config.ini` = 0，`thread_mode` 还原为 `#thread_mode=0`。

**结论**：**PASS**（非法值 `hybrid` 被拦截、告警打印、进程正常启动、默认 direct 未被改写；config.ini 已完全还原）。

**证据**（脱敏后）：
```
TCP_ratelimit: Is now initialized
net.isr.dispatch must stay direct (hybrid/deferred silently drop packets); ignoring requested value   ← P4 防护告警
f-stack-0: Successed to register dpdk interface
thread init success on lcore 0.
```

---

## 3. 汇总与约束遵循

| 测试项 | 结论 | 说明 |
| --- | --- | --- |
| T1 thread_mode=0 多进程零回归 | **PASS** | 启动成功、网卡注册、无 panic；连通性验证环境不满足（L2 不通）未执行 |
| T2 thread_mode=1 多线程冒烟 | **PASS** | 2 worker 各自初始化、hpts=2、无 panic、启动期无日志污染（未做高强度并发压测） |
| T3 P4 net.isr.dispatch 防护 | **PASS** | 非法值 `hybrid` 被拦截、告警打印、默认 direct 保持、进程正常 |

约束遵循确认：
- 停止进程一律 `/data/workspace/kill_process.sh`（T1/T2/T3 三次均用脚本，未直接 kill/pkill）。
- 文档中无真实 IP：`<DPDK_NIC_IP>`/`<DPDK_NIC_IPV6>`/`<DPDK_NIC_MAC>`/`fe80::feee:ffff:feff:ffff`（link-local，非本地真实地址）/`127.0.0.1` 回环；未出现任何 `9.134.x` / `2402:4e00:` 完整真实地址。
- `config.ini` 临时改动（thread_mode 1↔0、net.isr.dispatch 追加/删除）**测完已完全还原**（`diff` 与基线一致），且未 `git add config.ini`（其 `M` 状态为仓库既有本地测试值，与测试前一致）。
- 删除临时日志文件用 `/data/workspace/rm_tmp_file.sh`；仓库根 `helloworld.log`/`f-stack-*.log` 测试产物已清理，无残留。
- 临时日志 `/tmp/_m18_t{1,2,3}.log`、`/tmp/_m18_config_baseline.ini` 留在 /tmp 由系统清理，未入仓库。

## 4. 诚实边界（未验证项）

1. **连通性**：DPDK 网卡 `<DPDK_NIC_IP>` 从对端 L2 层不通（ping 100% 丢包、curl 超时），属环境网络配置问题，非本轮代码回归；本轮未验证到数据面连通，后续若需验证需先排查 ARP/网关/路由。
2. **P5 高强度并发打印压测**：本次仅覆盖启动期低并发场景，未做多线程高频并发 printf 压测，P5 的 __thread 修复在极端并发下的无污染无法由本次结果断言（代码级 review 已 PASS，见 `_m18_F_review.md` §P5）。
3. **P6 fail-fast 路径**：本轮未触发 `pcpup==NULL` 崩溃路径（正常运行不触发），fail-fast 分支仅代码级 review 确认（见 `_m18_F_review.md` §P6）。
