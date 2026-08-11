# 13. primary_slim=1 + KNI 开启时数据通路断裂修复

## 1. 问题现象

`primary_slim=1` + KNI `enable=1` + `owner_proc_id=1` 配置下：

- HTTP（TCP/80 数据面）正常，`http_code=200`，延迟约 1.3ms
- ping（ICMP，经 KNI 转发到 kernel）100% 丢包
- `veth0` 接口存在但 RX 统计不增长（包未到达 tap device）

对照组 `primary_slim=1` + KNI 关闭时 ping 0% 丢包、HTTP 200，问题仅在 KNI 开启时出现。

## 2. 根因定位

### 2.1 初始假设（被推翻）

假设 `primary_slim=1` 时 primary 在 `init_lcore_conf()` early return（`ff_dpdk_if.c:541-546`）跳过了 `init_kni()`，导致 KNI vdev/ring 未创建。

**实测推翻**：primary 的 f-stack lib 日志含 `VDEV_BUS: vdev_probe virtio_user0` 和 `ff_kni_alloc` 输出，`veth0` 接口也存在，证明 `init_kni()` 在 primary 中正常执行。`ff_dpdk_init()` 不检查 `init_lcore_conf()` 返回值，early return 后控制流继续到 `init_kni()`。

### 2.2 真实根因：virtio_user vdev 多进程 TX 限制

通过临时调试日志定位数据通路断裂点：

| 断裂点 | secondary 日志 | 结论 |
|--------|---------------|------|
| `ff_kni_enqueue` | `filter=-1 cnt=1..5` | ICMP 包正确入队 KNI ring ✓ |
| `kni_process_tx` dequeue | `dequeue=32` | 从 ring 取出包 ✓ |
| `kni_process_tx` tx_burst | `tx_burst=32 (to_kni_port=1)` | `rte_eth_tx_burst(Port 1)` 返回 32（"成功"）✓ |
| `veth0` RX 统计 | 181 → 181（不变） | **包未到达 tap device** ✗ |

**根因**：secondary 调用 `rte_eth_tx_burst(Port 1 = virtio_user0)` 返回成功（32 包），但包**未实际到达 veth0（tap device）**。

这是因为 `init_port_start()` 中 `total_nb_ports *= 2`（包含 virtio_user Port 1）**仅对 PRIMARY 生效**（`ff_dpdk_if.c:865-868`），secondary 的 `total_nb_ports = nb_ports`（仅物理端口），secondary 在端口循环中 `continue` 跳过 `dev_configure`/`queue_setup`/`dev_start`（`:1106-1108`）。

因此 secondary 侧 Port 1（virtio_user0）的 TX 队列未初始化，`rte_eth_tx_burst` 虽返回成功但写入无效 virtqueue，包被静默丢弃。这是 DPDK virtio_user PMD 的多进程限制——virtio_user 的 virtqueue 不能被未配置队列的 secondary 进程共享使用。

### 2.3 为什么 HTTP 正常但 ping 不通

- **HTTP（TCP）**：reject 模式下，TCP 不匹配 `tcp_port` 列表 → `FILTER_UNKNOWN` → 默认走 `ff_veth_input`（f-stack 协议栈处理），不经 KNI → 正常
- **ping（ICMP）**：ICMP 不在 filter 的 `switch` case 中 → `FILTER_UNKNOWN` → reject 模式下送 `ff_kni_enqueue` → KNI ring → secondary `kni_process_tx` → `rte_eth_tx_burst(Port 1)` → 丢失

## 3. 修复方案

### 3.1 核心思路

KNI vdev（virtio_user0）由 primary 创建（`rte_eal_hotplug_add`，DPDK 硬约束仅 primary）。因此 KNI 的 runtime TX/RX（`ff_kni_process`）也应由 primary 执行——primary 是 virtio_user 的合法操作者。

secondary 仍负责 `ff_kni_enqueue`（将数据面收到的 ICMP/ARP 等包入队 KNI ring），但不执行 `ff_kni_process`（virtio_user TX/RX）。

### 3.2 代码修改

**文件**：`lib/ff_dpdk_if.c`

**修改点**：`main_loop()` 中的 KNI process 门控（原 `:2906`）

修改前：
```c
#ifdef FF_KNI
        if (enable_kni && ff_kni_is_runtime_owner()) {
            for (i = 0; i < ff_global_cfg.dpdk.nb_ports; ++i) {
                uint16_t pid = ff_global_cfg.dpdk.portid_list[i];
                ff_kni_process(pid, 0, pkts_burst, MAX_PKT_BURST);
            }
        }
#endif
```

修改后：
```c
#ifdef FF_KNI
        if (enable_kni) {
            int do_kni;
            if (ff_global_cfg.dpdk.primary_slim)
                do_kni = (rte_eal_process_type() == RTE_PROC_PRIMARY);
            else
                do_kni = ff_kni_is_runtime_owner();
            if (do_kni) {
                for (i = 0; i < ff_global_cfg.dpdk.nb_ports; ++i) {
                    uint16_t pid = ff_global_cfg.dpdk.portid_list[i];
                    ff_kni_process(pid, 0, pkts_burst, MAX_PKT_BURST);
                }
            }
        }
#endif
```

### 3.3 修复逻辑

| 场景 | `do_kni` 计算 | KNI TX/RX 执行者 | 说明 |
|------|-------------|-----------------|------|
| `primary_slim=0` | `ff_kni_is_runtime_owner()` | primary（即 runtime owner） | 原行为不变，零回归 |
| `primary_slim=1` | `RTE_PROC_PRIMARY` | primary | primary 是 virtio_user 创建者，合法操作 |

`ff_kni_enqueue` 的门控不变（仍用 `ff_kni_is_runtime_owner()` 或 `enable_kni`），secondary 继续将 ICMP/ARP 等包入队 ring，primary 从 ring dequeue 后通过 virtio_user 发送到 veth0。

### 3.4 零回归保证

- `primary_slim=0`：`do_kni = ff_kni_is_runtime_owner()` = primary，行为与修改前完全一致
- `primary_slim=1` + KNI 关闭：`enable_kni=0`，整个块跳过，不受影响
- `primary_slim=1` + KNI 开启：primary 做 KNI TX/RX，secondary 只 enqueue

## 4. 测试验证

### 4.1 KNI 开启 + primary_slim=1（修复后）

配置：`primary_slim=1`，`[kni] enable=1 method=reject owner_proc_id=1`，`lcore_list=1`

从 `<CLIENT_IP>` 测试：

```
ping -c 5 <DPDK_NIC_IP>
5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/mdev = 0.411/0.720/1.093/0.264 ms

curl http://<DPDK_NIC_IP>/
http_code=200 time=0.001330s
```

### 4.2 KNI 关闭 + primary_slim=1（回归测试）

配置：`primary_slim=1`，`[kni] enable=0`，`lcore_list=1`

从 `<CLIENT_IP>` 测试：

```
ping -c 3 <DPDK_NIC_IP>
3 packets transmitted, 3 received, 0% packet loss
rtt min/avg/max/mdev = 0.242/0.263/0.276/0.015 ms

curl http://<DPDK_NIC_IP>/
http_code=200 time=0.001286s
```

veth0 不存在（KNI 关闭不创建 vdev），零回归确认。

### 4.3 测试环境说明

本机 `<KERNEL_NIC_IP>`（eth1）与 veth0 同属 `/21` 子网，路由冲突导致 kernel `rp_filter` 丢弃 ICMP reply。测试时需设 `rp_filter=0`：

```bash
echo 0 > /proc/sys/net/ipv4/conf/veth0/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
```

此为测试环境 workaround，非代码修复部分。生产环境 veth0 与 eth1 通常不同子网，无此问题。

## 5. 调试方法

定位 virtio_user 多进程 TX 问题的关键证据：

1. `veth0` RX 统计不增长 → TX 路径（f-stack → veth0）断裂
2. `kni_process_tx: tx_burst=32` 但 `veth0` RX 不变 → `rte_eth_tx_burst` "假成功"
3. secondary 的 `total_nb_ports=1`（不含 Port 1）→ secondary 未配置 virtio_user 队列
4. primary 的 `total_nb_ports=2`（含 Port 1）→ primary 是 virtio_user 合法操作者

修复验证：改为 primary 做 KNI TX/RX 后，`veth0` RX 统计正常增长，`kni_process_rx: rx_burst=1` 从 virtio_user 收到 kernel 回的 reply，`tx_burst=1 (to_phy_port=0)` 成功发出 reply。

## 6. 涉及文件

| 文件 | 修改类型 | 说明 |
|------|---------|------|
| `lib/ff_dpdk_if.c` | MODIFY | `main_loop()` 中 KNI process 门控：primary_slim 时由 primary 执行 |
