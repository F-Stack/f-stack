# F-Stack v1.25 第一层：总体架构与模块边界

> **目标受众**: 系统架构师、技术负责人  
> **关键概念**: 模块划分、技术选型、数据流、进程模型  
> **生成日期**: 2026-03-20

## 1. 顶层架构概览

### 1.1 F-Stack 核心创新

F-Stack 采用了"用户态网络栈"架构，解决 Linux 内核网络处理的性能瓶颈：

```
应用层 (Applications)
  ↓ (ff_socket/ff_read/ff_write 等 Linux-like API)
F-Stack 库 (libfstack.a)
  ├─ FreeBSD TCP/IP 栈移植
  ├─ 粘合层 (ff_glue.c) - 内核模拟
  └─ 系统调用适配 (ff_syscall_wrapper.c)
  ↓
DPDK 库 (libdpdk)
  ├─ EAL (Environment Abstraction Layer)
  ├─ Mempool (mbuf 内存池)
  └─ Ethdev (网卡驱动无关接口)
  ↓
NIC 驱动 (igb_uio / vfio-pci)
  ↓
网卡硬件
```

### 1.2 三个核心支柱

| 支柱 | 组件 | 作用 |
|-----|------|------|
| **Kernel Bypass** | DPDK + PMD | 规避 Linux 内核网络瓶颈 |
| **成熟协议栈** | FreeBSD 13.0 移植 | 复用久经考验的 TCP/IP 实现 |
| **多核并行** | 多进程架构 + RSS | 充分利用多核处理能力 |

### 1.3 关键性能指标

- **并发连接**: 1000 万+
- **请求吞吐**: 500 万+ RPS (Request Per Second)
- **连接建立**: 100 万+ CPS (Connection Per Second)
- **延迟**: 微秒级 (vs 毫秒级内核栈)

> **注意**: 以上性能数据为参考值，实际结果取决于硬件配置 (CPU/网卡)、测试场景和报文大小等条件。

## 2. 目录结构与模块边界

### 2.1 核心目录布局

```
/data/workspace/f-stack/
├── lib/                          # F-Stack 核心库 (~21K 行 C 代码)
│   ├── ff_dpdk_if.c   (2855行) # DPDK 网卡接口层 - 最核心
│   ├── ff_glue.c      (1466行) # FreeBSD 粘合层
│   ├── ff_config.c    (1379行) # 配置解析
│   ├── ff_syscall_wrapper.c     # Linux→FreeBSD 系统调用适配
│   ├── ff_host_interface.c      # 主机接口 (pthread/mmap/时间)
│   ├── ff_init.c         (69行) # 初始化协调
│   ├── ff_epoll.c       (159行) # epoll 接口转换
│   ├── ff_dpdk_kni.c            # 虚拟网卡支持（通过 virtio_user 实现，已不依赖 rte_kni.ko）
│   ├── Makefile                 # 编译系统
│   └── include/                 # 头文件
│
├── freebsd/                      # FreeBSD 13.0 内核代码移植
│   ├── sys/
│   │   ├── netinet/   # IPv4 协议栈
│   │   ├── netinet6/  # IPv6 协议栈
│   │   ├── net/       # 通用网络接口
│   │   ├── kern/      # 内核服务 (malloc/锁/定时器)
│   │   └── vm/        # 虚拟内存
│   ├── amd64/         # x86 架构特定代码
│   └── contrib/ck/    # ConcurrencyKit 依赖
│
├── dpdk/                         # DPDK 23.11.5 (submodule)
│   └── build/                    # 编译产物
│
├── app/                          # 应用集成
│   ├── nginx-1.28.0/
│   └── redis-6.2.6/
│
├── example/                      # 示例代码
│   ├── main.c          (222行) # kqueue HTTP 服务器
│   └── main_epoll.c    (143行) # epoll HTTP 服务器
│
├── mk/                           # 编译系统
│   ├── kern.pre.mk     # FreeBSD 编译规则
│   ├── kern.mk         # 内核编译规则
│   └── compiler.mk     # 编译器配置
│
├── tools/                        # 工具脚本
├── adapter/                      # 网络适配器
│   ├── micro_thread/             # 微线程接口，方便有状态应用使用 F-Stack
│   └── syscall/                  # 通过 LD_PRELOAD 劫持 Linux syscall 为 F-Stack API
├── doc/                          # 原始英文文档
├── docs/                         # 三层架构知识库文档
└── config.ini                    # 默认配置文件
```

### 2.2 核心模块职责边界

| 模块 | 行数 | 职责 | 依赖 |
|-----|------|------|------|
| **ff_dpdk_if.c** | 2855 | NIC 驱动/DPDK 操作/收发包核心逻辑 | DPDK, ff_glue |
| **ff_glue.c** | 1466 | FreeBSD 内核模拟/内存/锁/中断 | FreeBSD headers, DPDK |
| **ff_config.c** | 1379 | INI 配置文件解析 | ff_ini_parser |
| **ff_syscall_wrapper.c** | 1825 | Linux 系统调用→FreeBSD 适配 | FreeBSD sys |
| **ff_init.c** | 69 | 初始化流程协调 | 上述所有模块 |
| **ff_epoll.c** | 159 | Linux epoll→FreeBSD kqueue 转换 | FreeBSD kqueue |
| **ff_host_interface.c** | -- | 主机 OS 接口 (mmap/pthread/rand) | 系统库 |
| **ff_dpdk_kni.c** | -- | 虚拟网卡支持（通过 virtio_user 实现，已不依赖 rte_kni.ko） | DPDK virtio_user |

## 3. FreeBSD TCP/IP 栈移植方式

### 3.1 移植策略

F-Stack 采用了**完整移植**策略：
- 从 FreeBSD 13.0 提取完整的 TCP/IP 协议栈代码
- 在 `freebsd/sys/netinet/` 中保留所有网络协议代码
- 通过 `ff_glue.c` 实现内核 API 的用户态模拟
- 通过条件编译支持可选功能 (IPv6, KNI, TCPHPTS 等)

### 3.2 FreeBSD 移植的子系统

```
freebsd/sys/
├── netinet/        # IPv4: tcp_*.c, udp_*.c, ip_*.c, if_arp.c
├── netinet6/       # IPv6: ip6_*.c, tcp6_*.c
├── net/            # 通用网络: if.c, route.c, netisr.c
├── kern/           # 内核服务: malloc, mutex, synch, callout
├── vm/             # 虚拟内存: vm_page.c (mbuf 映射)
└── sys/            # 系统定义: socket.h, mbuf.h 等
```

### 3.3 ff_glue.c 中的内核模拟

| 内核功能 | FreeBSD 原生 | F-Stack 模拟 |
|---------|-------------|-----------|
| 内存分配 | `malloc()` | DPDK `rte_malloc()` |
| 互斥锁 | `struct mtx` | `pthread_mutex_t` |
| 条件变量 | `struct condvar` | `pthread_cond_t` |
| 软中断 | `swi_*` | 内部 taskqueue |
| 定时器 | `callout{}` | DPDK `rte_timer` |
| 分页内存 | `vm_page_alloc()` | DPDK mempool |

## 4. DPDK 集成与 NIC 驱动层

### 4.1 ff_dpdk_if.c 核心职责

这是最核心的模块 (2855 行)，负责整个数据链路：

**初始化流程**:
```
ff_dpdk_init()
  ├─ rte_eal_init()              // DPDK 环境初始化
  ├─ init_lcore_conf()           // CPU 核心/端口映射
  ├─ init_mem_pool()             // mbuf 内存池创建
  ├─ init_dispatch_ring()        // 进程间消息队列
  ├─ init_port_start()           // NIC 启动 + RSS 配置
  ├─ ff_rss_tbl_init()           // RSS 分类表建立
  └─ init_clock()                // FreeBSD 时钟初始化
```

### 4.2 收包流程 (Ingress)

```
NIC 硬件 (RSS 处理器分发)
  ↓
多个 RX 队列 (per-CPU-core)
  ↓
DPDK PMD (rte_eth_rx_burst())
  ↓
process_packets() 函数
  ├─ 协议过滤 (ARP/IPv4/IPv6/Multicast)
  ├─ 虚拟网卡处理 (veth_input)
  └─ FreeBSD 栈 (if_input → eth_input → ip_input → tcp_input → sorecv)
```

### 4.3 发包流程 (Egress)

```
应用 (ff_write/ff_send/ff_sendto/ff_sendmsg)
  ↓
FreeBSD TCP/UDP 栈
  ├─ tcp_output() / udp_output()
  ├─ ip_output()
  └─ if_output()
  ↓
ff_glue.c if_start()
  ├─ 获取 mbuf
  ├─ 填充 L2/L3/L4 头
  ├─ 配置硬件卸载 (TSO/Checksum)
  └─ send_single_packet()
  ↓
DPDK rte_eth_tx_burst()
  ↓
NIC 硬件
```

## 5. 主处理循环

### 5.1 main_loop() 伪代码

```c
int main_loop(void *arg) {
    while (!stop_loop) {
        // [1] 驱动 FreeBSD 定时器
        if (freebsd_clock.expire < cur_tsc) {
            rte_timer_manage();
        }
        
        // [2] 轮询所有 RX 队列
        for (each_rx_queue) {
            nb_rx = rte_eth_rx_burst(...);
            process_packets(pkts_burst, nb_rx);
        }
        
        // [3] 定时刷新 TX 队列
        if (drain_tsc && (cur_tsc - prev_tsc) > drain_tsc) {
            for (each_port) {
                rte_eth_tx_burst(...);
            }
        }
        
        // [4] 执行用户回调
        if (usr_loop) {
            usr_loop(arg);
        }
    }
}
```

### 5.2 轮询特性

- **无中断**: → 低延迟、高吞吐
- **占用 CPU**: 100% 利用 (通过 CPU 隔离优化)
- **可配置睡眠**: `idle_sleep` 参数支持微秒级让步

## 6. 进程模型

### 6.1 单进程模式 (推荐)

```
F-Stack 进程 (1 个)
  └─ 单个 lcore (1 个 CPU 核心)
    ├─ NIC RX/TX 队列映射
    ├─ FreeBSD 协议栈运行
    └─ 应用逻辑执行
```

**适用场景**: 小型应用、专用设备

### 6.2 多进程模式

```
主进程 (Primary)
  ├─ DPDK EAL 初始化
  └─ 启动 N 个 Worker 进程

Worker-0 (CPU-0)  ┐
Worker-1 (CPU-1)  ├─ 各进程独立运行
...               │  通过 RSS 维持连接亲和性
Worker-N (CPU-N)  ┘

共享资源:
  ├─ DPDK Mempool
  ├─ RSS 分类表
  └─ 虚拟网卡 (KNI)
```

**优势**: 故障隔离、灵活扩展  
**劣势**: 进程间同步复杂

## 7. 技术选型分析

### 7.1 为什么选 DPDK 而非 NETMAP/PF_RING

| 对比项 | DPDK | NETMAP | PF_RING |
|-------|------|--------|---------|
| 社区活跃度 | ★★★★★ | ★★★ | ★★★ |
| 跨平台 | ✓ | ✓ | ✗ (Linux only) |
| 生态完整性 | ★★★★★ | ★★★ | ★★ |
| 企业采用 | ★★★★★ | ★★★ | ★★ |
| 硬件卸载支持 | ★★★★★ | ★★★ | ★★ |

**选择原因**:
- Tencent 已有 DPDK 积累 (DNSPod DNS)
- 多进程架构支持最完善
- 硬件卸载支持最广泛 (TSO/GSO/Checksum)

### 7.2 为什么选 FreeBSD 栈而非自研

| 方面 | FreeBSD 栈 | 自研栈 |
|-----|-----------|--------|
| 开发周期 | 即用 | 2-3 年 |
| 功能完整 | ★★★★★ | ★★★ |
| 性能优化 | ★★★★★ | ★★ |
| RFC 兼容性 | ★★★★★ | ★★★ |
| 社区反馈 | ★★★★★ | 无 |
| 维护成本 | ★★★ | ★★★★★ |

**历史背景**:
- 初期自研简单栈 → 稳定性不足
- 2017 年参考 libplebnet/libuinet → 完整移植 FreeBSD 栈
- 这决定了今天的架构

## 8. 硬件卸载特性

F-Stack 充分发挥现代 NIC 硬件能力：

### 8.1 RX 卸载

| 特性 | 效果 | 支持度 |
|-----|------|--------|
| **校验和卸载** | 验证 L3/L4 由硬件完成 | 广泛 |
| **LRO** (Large Receive Offload) | 合并小报文为大报文 | 部分 |

### 8.2 TX 卸载

| 特性 | 效果 | 支持度 |
|-----|------|--------|
| **TSO** (TCP Segmentation Offload) | 大报文由硬件分段 | 广泛 |
| **校验和卸载** | 计算 L3/L4 校验和 | 广泛 |
| **VLAN 插入** | 硬件添加 VLAN 标签 | 部分 |

### 8.3 流分类 (RSS)

- **硬件 RSS**: 基于 5 元组 (src-ip, dst-ip, src-port, dst-port, proto)
- **好处**: 同一连接总是路由到同一 RX 队列 → 避免 TCP 乱序

## 总结

F-Stack 的架构设计围绕三个核心支柱：
1. **Kernel Bypass**: 规避 Linux 内核瓶颈
2. **成熟协议栈**: 复用 FreeBSD 久经考验的实现
3. **多核并行**: 充分利用现代多核 CPU 和 NIC 硬件能力
   这使得 F-Stack 能够达到 500 万+ RPS、1000 万+ 并发连接的性能水平，是云计算核心网络设施的理想选择。
