# 12. KNI 回归修复：primary_slim=0 时 owner_proc_id 误伤 KNI

## 一、问题现象

issue #1078 新增的 primary_slim 主进程瘦身功能引入了 KNI 回归：

- `primary_slim=0`（未开启主进程瘦身），`[kni] enable=1, owner_proc_id=1`
- 启动 helloworld 后运行 `dkdns_ospf.sh` 配置 veth0 的 IP 和路由
- 从 f-stack-client ping DPDK NIC IP 不通（无论 CVM 环境还是物理机）

## 二、根因分析

### 2.1 引入回归的 commit

`1c28aaa2d`（issue #1078 M1）把 `lib/ff_dpdk_if.c` 中两处 KNI 调用条件从 `ff_kni_is_owner_thread()` 改为 `ff_kni_is_runtime_owner()`：

- `ff_dpdk_if.c:2186` — `process_packets()` 中 KNI packet clone
- `ff_dpdk_if.c:2906` — `main_loop()` 中 `ff_kni_process()` 调用

### 2.2 两个函数的语义差异

`lib/ff_dpdk_kni.c` 中两个 owner 判断函数：

```c
/* ff_kni_is_owner_thread() — 传统行为：非 thread_mode 时只有 primary 是 owner */
int ff_kni_is_owner_thread(void) {
    if (ff_global_cfg.dpdk.thread_mode)
        return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0];
    return rte_eal_process_type() == RTE_PROC_PRIMARY;
}

/* ff_kni_is_runtime_owner() — #1078 新增：按 owner_proc_id 匹配 */
int ff_kni_is_runtime_owner(void) {
    if (ff_global_cfg.dpdk.thread_mode)
        return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0];
    return ff_global_cfg.dpdk.proc_id == ff_global_cfg.kni.owner_proc_id;
}
```

### 2.3 回归机制

当 `primary_slim=0` + `owner_proc_id=1` 时：

| 场景 | proc_id | ff_kni_is_runtime_owner() | 结果 |
|------|---------|---------------------------|------|
| 单进程 | 0 | `0 == 1` → false | KNI 完全不执行 → 不通 |
| 多进程 secondary | 1 | `1 == 1` → true | KNI 由 secondary 处理，但 vdev/ring 创建仍只 primary 能做 → 半初始化 → 不通 |
| 多进程 primary | 0 | `0 == 1` → false | KNI 不由 primary 处理 → 不通 |

而 `ff_kni_is_owner_thread()` 在所有场景下非 thread_mode 时都返回 `RTE_PROC_PRIMARY`，即只有 primary 处理 KNI——这是 #1078 之前的传统行为。

### 2.4 调用点全量清单

`ff_kni_is_runtime_owner()` 共 4 个调用点（code-explorer 子 agent 全量追踪确认）：

| # | 文件:行号 | 所在函数 | 条件上下文 | 修复后行为 |
|---|-----------|----------|------------|------------|
| R1 | `ff_dpdk_kni.c:395` | `ff_kni_init()` | `ff_kni_is_owner_thread() \|\| ff_kni_is_runtime_owner()` | primary \|\| primary = primary（冗余但无害） |
| R2 | `ff_dpdk_kni.c:442` | `ff_kni_alloc()` | `ff_kni_is_owner_thread() \|\| ff_kni_is_runtime_owner()` | 同上 |
| R3 | `ff_dpdk_if.c:2186` | `process_packets()` | `enable_kni && ff_kni_is_runtime_owner()` | **核心修复点**：primary_slim=0 时回退为 primary |
| R4 | `ff_dpdk_if.c:2906` | `main_loop()` | `enable_kni && ff_kni_is_runtime_owner()` | **核心修复点**：同上 |

`ff_kni_is_owner_thread()` 的 5 个调用点（O3/O4/O5 仍用 `ff_kni_is_owner_thread()` 是 DPDK 硬约束——vdev hotplug_add / ring_create / rx_dropped 统计只能 primary 做，保持正确）：

| # | 文件:行号 | 用途 | 是否需改 |
|---|-----------|------|----------|
| O1 | `ff_dpdk_kni.c:395` | kni_stat 分配（OR 组合） | 否 |
| O2 | `ff_dpdk_kni.c:442` | kni_stat[port_id] 分配（OR 组合） | 否 |
| O3 | `ff_dpdk_kni.c:482` | vdev hotplug_add（primary-only） | 否（DPDK 硬约束） |
| O4 | `ff_dpdk_kni.c:493` | ring_create / ring_lookup 分支 | 否（DPDK 硬约束） |
| O5 | `ff_dpdk_kni.c:546` | rx_dropped 统计 | 否 |

## 三、修复方案

### 3.1 方案选择

**方案 A（最小侵入，改函数本身）**：在 `ff_kni_is_runtime_owner()` 中 `proc_id == owner_proc_id` 判断前增加 `primary_slim=0` 短路。

**方案 B（改调用点条件）**：修改 `ff_dpdk_if.c` 两处调用点为 `ff_kni_is_owner_thread() || (primary_slim && ff_kni_is_runtime_owner())`。

选择方案 A：只改一个函数，覆盖全部 4 个调用点（R1~R4），无需逐个改调用点，blast radius 最小。

### 3.2 实际改动

`lib/ff_dpdk_kni.c`，`ff_kni_is_runtime_owner()` 函数，新增 2 行：

```diff
 int
 ff_kni_is_runtime_owner(void)
 {
     if (ff_global_cfg.dpdk.thread_mode)
         return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0];
+    if (!ff_global_cfg.dpdk.primary_slim)
+        return rte_eal_process_type() == RTE_PROC_PRIMARY;
     return ff_global_cfg.dpdk.proc_id == ff_global_cfg.kni.owner_proc_id;
 }
```

### 3.3 语义说明

修改后的 `ff_kni_is_runtime_owner()` 行为：

```
thread_mode=1 → lcore 判断（不变）
thread_mode=0, primary_slim=0 → primary 判断（恢复 #1078 前传统行为）
thread_mode=0, primary_slim=1 → proc_id == owner_proc_id（#1078 新行为，不变）
```

核心思想：`owner_proc_id` 只有在 `primary_slim=1` 时才有意义（让 secondary 接管 KNI）；`primary_slim=0` 时应忽略 `owner_proc_id`，KNI 由 primary 处理。

### 3.4 对 R1/R2 OR 条件的影响

R1（`ff_kni_init:395`）和 R2（`ff_kni_alloc:442`）的条件是 `ff_kni_is_owner_thread() || ff_kni_is_runtime_owner()`。修复后在 `primary_slim=0` 时两个分支都返回 primary 判断，即 `primary || primary = primary`，逻辑等价、冗余但无害。

## 四、编译验证

- `make clean` + `make`（f-stack/lib/）clean build 通过
- `libfstack.a` 生成成功（7,008,438 字节）
- helloworld 示例编译链接成功

## 五、回归测试

### 5.1 测试环境

| 项 | 值 |
|----|-----|
| 被测程序 | `example/helloworld`（HTTP keep-alive，监听 80） |
| 配置 | `primary_slim=0`（注释/默认），`[kni] enable=1, method=reject, owner_proc_id=1` |
| DPDK 端口 | 1 个，独占网卡（virtio 设备，`igb_uio`） |
| 服务端地址 | `<DPDK_NIC_IP>:80` |
| 客户端 | `f-stack-client` 主机（`<CLIENT_IP>`） |
| KNI veth | `dkdns_ospf.sh` 配置 veth0 的 IP/路由/IPv6 |

### 5.2 测试步骤

1. 机器重启后恢复环境：加载 `igb_uio` 模块 → 绑定 DPDK 网卡 → 设置 hugepages → 清理 DPDK 残留
2. 启动 helloworld，等待 ~25s 初始化完成
3. 运行 `dkdns_ospf.sh` 配置 veth0
4. 从 f-stack-client ping DPDK NIC IP

### 5.3 测试结果

**Ping 测试（从 f-stack-client → DPDK NIC IP）**：

```
PING <DPDK_NIC_IP> (<DPDK_NIC_IP>) 56(84) bytes of data.
64 bytes from <DPDK_NIC_IP>: icmp_seq=1 ttl=64 time=1.11 ms
64 bytes from <DPDK_NIC_IP>: icmp_seq=2 ttl=64 time=0.281 ms
64 bytes from <DPDK_NIC_IP>: icmp_seq=3 ttl=64 time=0.252 ms

--- <DPDK_NIC_IP> ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2040ms
rtt min/avg/max/mdev = 0.252/0.548/1.111/0.398 ms
```

**本机 ping veth0**：

```
PING <DPDK_NIC_IP> (<DPDK_NIC_IP>) from <DPDK_NIC_IP> veth0: 56(84) bytes of data.
64 bytes from <DPDK_NIC_IP>: icmp_seq=1 ttl=64 time=0.022 ms
64 bytes from <DPDK_NIC_IP>: icmp_seq=2 ttl=64 time=0.045 ms
```

**结论**：KNI 回归修复验证通过。`primary_slim=0` + `owner_proc_id=1` 时 KNI 路径恢复正常，ICMP 包从 f-stack-client 经 DPDK 网卡 → f-stack 协议栈 → KNI veth0 → 内核栈正常往返。

## 六、零回归保证

- `primary_slim=0`（默认）：`ff_kni_is_runtime_owner()` 退化为 `ff_kni_is_owner_thread()` 语义，恢复 #1078 前行为
- `primary_slim=1`：`ff_kni_is_runtime_owner()` 行为不变，仍按 `owner_proc_id` 匹配
- `thread_mode=1`：不受影响（lcore 判断在前）
- 零性能影响：新增一个 O(1) 的 `if` 分支判断

## 七、Traceability

- **引入回归的 commit**：`1c28aaa2d`（issue #1078 M1）
- **修复 commit**：见 git log
- **修改文件**：`lib/ff_dpdk_kni.c`（`ff_kni_is_runtime_owner()` 函数，+2 行）
- **验证**：clean build PASS + 实机 ping 测试 PASS（用户手动确认通过）
