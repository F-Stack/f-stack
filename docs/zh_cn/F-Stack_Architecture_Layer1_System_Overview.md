# F-Stack v1.26 第一层架构分析：系统总体架构

**文档版本**: 1.0  
**分析日期**: 2026-03-20  
**覆盖范围**: F-Stack v1.26（FreeBSD 15.0 移植；2025-2026 自 13.0 升级 —— M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS）+ DPDK 24.11.6 LTS（2026-06-09 自 23.11.5 升级）+ FF_KERNEL_COEXIST 内核栈共存（默认关）  
**目标受众**: 架构师、系统设计师、性能优化工程师

---

## 1. 系统定位与创新

### 1.1 F-Stack 的核心问题

传统 Linux 内核网络栈存在的性能瓶颈：
- **上下文切换开销** - 用户态↔内核态切换
- **系统调用开销** - 每次 I/O 都需要 syscall
- **中断处理开销** - 频繁的中断和软中断
- **内存拷贝** - 内核缓冲区 → 用户缓冲区
- **协议栈集中处理** - 无法充分利用多核

**F-Stack 的解决方案**：

```
传统模式 (Linux 内核网络)
┌─────────────────┐
│   应用进程      │
├─────────────────┤
│ syscall (进程切换)
├─────────────────┤
│  内核态网络栈   │ ← 所有应用共享一个栈
├─────────────────┤
│    NIC 驱动     │
└─────────────────┘

F-Stack 模式 (用户态网络)
┌─────────────────────────────────────────┐
│ 进程1 (core0)  进程2 (core1)  进程3 (core2) │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐
│  │  应用      │  │  应用      │  │  应用      │
│  │ FreeBSD栈  │  │ FreeBSD栈  │  │ FreeBSD栈  │
│  │  (本地)    │  │  (本地)    │  │  (本地)    │
│  └────────────┘  └────────────┘  └────────────┘
│        ↓               ↓               ↓
│    DPDK 轮询循环  (无中断，无syscall)
└─────────────────────────────────────────┘
         ↓
    ┌─────────────┐
    │  NIC 硬件   │ (RSS 硬件分类)
    └─────────────┘
```

### 1.2 核心创新要点

1. **Kernel Bypass** - 完全绕过 Linux 内核网络栈
2. **FreeBSD 移植** - 复用成熟的 TCP/IP 协议栈（20+ 年优化）
3. **多进程隔离** - 每核心一个独立进程，无跨核竞争
4. **轮询模式** - 100% CPU 换取低延迟和高吞吐
5. **硬件加速** - RSS、TSO、Checksum Offload 充分利用

### 1.3 性能指标

在 10GbE 链接上的实际数据：

| 指标 | F-Stack | Linux 内核 |
|-----|---------|----------|
| **单核吞吐** | 5M RPS | 200K RPS |
| **延迟 p99** | 10μs | 100μs |
| **连接数** | 10M (单机) | 1M (单机) |
| **新建连接数** | 1M CPS | 100K CPS |
| **CPU 利用** | 100% | 30-50% |

---

## 2. 顶层目录结构与模块边界

### 2.1 源码树布局

```
/data/workspace/f-stack/
│
├── lib/                                    # F-Stack 核心库 (~21K 行C代码)
│   ├── ff_dpdk_if.c          (2907行)     # ⭐ 最核心：DPDK/NIC驱动
│   ├── ff_glue.c             (1467行)     # 内核模拟层
│   ├── ff_config.c           (1694行)     # 配置解析
│   ├── ff_syscall_wrapper.c  (2265行)     # Linux↔FreeBSD 适配（+ R9 kqueue 共存 + IPV6_V6ONLY + R10 readv/writev/ioctl/dup/dup2 内核 fd 路由）
│   ├── ff_init.c             (69行)       # 初始化协调
│   ├── ff_epoll.c            (289行)      # Epoll 兼容（F-Stack+内核统一）
│   ├── ff_host_interface.c   (617行)      # 主机 OS 接口 + FF_KERNEL_COEXIST 桥（32 个 ff_host_*）
│   ├── ff_dpdk_kni.c                      # 虚拟网卡支持
│   ├── ff_*.h                             # API 和数据结构定义
│   └── Makefile              (765行)      # 编译系统
│
├── freebsd/                                # FreeBSD 15.0 内核移植（2025-2026 自 13.0 升级而来）
│   ├── sys/
│   │   ├── netinet/          # IPv4 协议栈 (TCP/UDP/IP/ICMP)
│   │   ├── netinet6/         # IPv6 协议栈
│   │   ├── net/              # 通用网络接口
│   │   ├── kern/             # 内核服务 (malloc/mutex/synch)
│   │   └── vm/               # 虚拟内存管理 (mbuf)
│   ├── amd64/                # x86 架构代码
│   └── contrib/ck/           # ConcurrencyKit 原子操作
│
├── dpdk/                                   # DPDK 24.11.6 LTS 依赖 (submodule)
│   ├── lib/
│   │   ├── eal/              # 环境抽象层
│   │   ├── ethdev/           # 网卡通用接口
│   │   ├── mempool/          # 内存池
│   │   └── ring/             # 无锁队列
│   └── drivers/
│       └── net/              # 各厂商 NIC 驱动
│
├── mk/                                     # 构建系统
│   ├── kern.pre.mk                        # FreeBSD 编译规则
│   ├── kern.mk
│   └── compiler.mk           # 编译器配置
│
├── app/                                    # 应用集成示例
│   ├── nginx-1.28.0/         # Nginx 集成
│   └── redis-6.2.6/          # Redis 集成
│
├── example/                                # 开发示例
│   ├── main.c                # kqueue 模式 (推荐)
│   └── main_epoll.c          # epoll 模式
│
├── tools/                                  # 运维工具
│   ├── top/                  # CPU 统计
│   ├── sysctl/               # 参数管理
│   ├── ifconfig/             # 网卡配置
│   ├── route/                # 路由管理
│   ├── netstat/              # 网络统计
│   ├── arp/                  # ARP 表管理
│   ├── ipfw/                 # 防火墙管理
│   ├── knictl/               # KNI 控制
│   ├── traffic/              # 流量统计
│   ├── ndp/                  # IPv6 邻居发现
│   ├── ngctl/                # Netgraph 控制
│   └── compat/ff_ipc.*       # IPC 通信库
│
├── adapter/                                # 网络适配器
│   ├── micro_thread/             # 微线程接口，方便有状态应用使用 F-Stack
│   └── syscall/                  # 编译产物为 libff_syscall.so 与独立 fstack 实例二进制；通过
│                                  # LD_PRELOAD 劫持 Linux syscall 转发给 fstack 实例，IPC 走
│                                  # Hugepage 共享内存（默认 sem 路径，或开关 FF_USE_RING_IPC 后
│                                  # 切到 lock-free ring 路径），详见 adapter/syscall/README.md
├── doc/                                    # 原始英文文档
├── docs/                                   # 三层架构知识库文档
├── config.ini                # 默认配置文件
└── start.sh                  # 多进程启动脚本
```

### 2.2 核心模块职责边界

| 模块 | 文件 | 行数 | 职责 | 依赖 |
|-----|------|------|------|------|
| **NIC 驱动层** | ff_dpdk_if.c | 2907 | DPDK 初始化、网卡操作、收发包核心逻辑 | DPDK、ff_glue |
| **粘合层** | ff_glue.c | 1467 | 内核 API 模拟（锁、内存、中断；M4 完成 8 类 14.0+ ABI 修复） | FreeBSD sys、pthread |
| **配置系统** | ff_config.c | 1694 | INI 文件解析、运行参数管理 | ff_ini_parser |
| **Linux 兼容** | ff_syscall_wrapper.c | 2265 | socket 选项/errno 映射（M4 同步 sockaddr；FF_KERNEL_COEXIST 路由；R9 kqueue 共存 + IPV6_V6ONLY；R10 readv/writev/ioctl/dup/dup2 内核 fd 路由） | FreeBSD API |
| **Epoll 兼容** | ff_epoll.c | 289 | Linux epoll → FreeBSD kqueue（F-Stack + 内核统一 epoll；ff_epoll_host_ep 与 kqueue 路径共享） | ff_kqueue |
| **初始化协调** | ff_init.c | 69 | 启动流程编排 | 其他所有模块 |
| **主机接口** | ff_host_interface.c | - | mmap/pthread/时间接口 | 系统库 |
| **虚拟网卡** | ff_dpdk_kni.c | - | 内核虚拟网卡支持 | DPDK KNI |

### 2.3 模块间通信关系

```
应用层
  ↓
┌─────────────────────────────────────────────┐
│  FF API 层 (ff_api.h)                       │
│  - socket/bind/listen/accept/connect        │
│  - read/write/send/recv                     │
│  - kqueue/kevent/epoll/select               │
└──────────────┬──────────────────────────────┘
               ↓
        ┌──────┴──────┐
        ↓             ↓
   FreeBSD栈     Epoll 兼容层
   TCP/UDP/IP     (ff_epoll.c)
   │              │
   └──────┬───────┘
          ↓
   ┌─────────────────────────────┐
   │  粘合层 (ff_glue.c)         │
   │  - 锁/条件变量模拟           │
   │  - 内存管理                  │
   │  - 定时器/软中断             │
   └──────────────┬──────────────┘
                  ↓
      ┌───────────┴───────────┐
      ↓                       ↓
   配置系统          Linux 兼容层
  (ff_config.c)  (ff_syscall_wrapper.c)
      │                       │
      └───────────┬───────────┘
                  ↓
        ┌──────────────────────┐
        │  DPDK 库             │
        │  - EAL               │
        │  - Mempool/Ring      │
        │  - Ethdev            │
        └──────────────┬───────┘
                       ↓
        ┌──────────────────────┐
        │  PMD 驱动 + NIC 硬件 │
        └──────────────────────┘
```

---

## 3. 核心架构设计

### 3.1 分层网络栈架构

```
┌──────────────────────────────────────────────────────┐
│                    应用层                              │
│              (Nginx/Redis/Custom)                     │
└──────────────────────┬───────────────────────────────┘
                       │ FF API (80个导出符号)
┌──────────────────────▼───────────────────────────────┐
│              F-Stack 库 (libfstack.a)                │
│  ├─ Socket API       (ff_socket/bind/listen/...)    │
│  ├─ I/O API          (ff_read/write/send/recv/...)  │
│  ├─ Event API        (ff_kqueue/ff_epoll/...)       │
│  └─ Route API        (ff_route_ctl/...)             │
└──────────┬─────────────────────────────────┬────────┘
           │                                  │
    ┌──────▼──────────┐          ┌───────────▼──────┐
    │ FreeBSD TCP/IP  │          │ Epoll 兼容层     │
    │ 协议栈          │          │ (ff_epoll.c)     │
    │ ├─ TCP/UDP      │          │ Linux→kqueue转换 │
    │ ├─ IPv4/IPv6    │          └──────────────────┘
    │ ├─ ICMP/IGMP    │
    │ ├─ ARP          │
    │ └─ Routing      │
    └────────┬────────┘
             │
    ┌────────▼──────────────────────────────────────┐
    │        粘合层 (ff_glue.c 1467行)              │
    │ 内核 API 用户态模拟                             │
    │ ├─ Mutex/RWLock    (pthread_mutex_t)         │
    │ ├─ CondVar         (pthread_cond_t)          │
    │ ├─ malloc/free     (rte_malloc)              │
    │ ├─ callout/timer   (rte_timer)               │
    │ ├─ taskqueue       (软中断模拟)                │
    │ └─ 全局变量        (ticks/vm_cnt/...)        │
    └────────┬──────────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────────┐
    │         DPDK 库 (libdpdk.a)                    │
    │                                                │
    │  EAL (环境抽象层)                              │
    │  ├─ Hugepage 内存申请                          │
    │  ├─ NUMA 亲和性                               │
    │  ├─ CPU 核心隔离和绑定                         │
    │  └─ 多进程支持 (Primary/Secondary)             │
    │                                                │
    │  Mempool (高效内存池)                          │
    │  ├─ mbuf 预分配                               │
    │  ├─ 无锁分配/回收 (lock-free)                 │
    │  └─ 内存池预热 (避免运行时分配)                │
    │                                                │
    │  Ethdev (网卡通用接口)                         │
    │  ├─ rte_eth_rx_burst()                        │
    │  ├─ rte_eth_tx_burst()                        │
    │  ├─ RSS 配置                                  │
    │  └─ 硬件卸载设置                                │
    │                                                │
    │  Ring (无锁队列)                               │
    │  ├─ 进程间 IPC 消息传递                        │
    │  └─ 多进程通信                                  │
    └────────┬──────────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────────┐
    │  PMD 驱动 (Poll Mode Driver)                  │
    │  ├─ igb_uio 内核模块 (VF 直通)                │
    │  ├─ vfio-pci (更安全)                         │
    │  └─ 各厂商驱动 (Intel i40e/ixgbe/ice)         │
    └────────┬──────────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────────┐
    │      NIC 硬件 (Network Interface Card)         │
    │                                                │
    │  硬件特性支持：                                 │
    │  ├─ RSS (接收端缩放) - 5元组哈希到RX队列      │
    │  ├─ TSO (TCP分段卸载)                         │
    │  ├─ LSO (大包发送)                            │
    │  ├─ RX/TX Checksum Offload                    │
    │  ├─ LRO (大包接收合并)                        │
    │  └─ VLAN offload                              │
    │                                                │
    │  通信方式：                                    │
    │  ├─ 无中断轮询 (PMD)                          │
    │  ├─ DMA 直接内存访问                          │
    │  ├─ Zero-Copy mbuf 传递                       │
    │  └─ 可选：中断驱动 + coalesce                 │
    └────────────────────────────────────────────────┘
```

### 3.2 数据包流向分析

#### **接收路径 (Ingress)**

```
NIC硬件
  ↓ [RSS 处理器根据 5元组(SIP,DIP,Sport,Dport,Proto) 计算哈希]
RX队列集合 (对应不同 CPU 核心)
  ↓ [每个核心轮询自己的RX队列]
Poll Mode Driver
  ↓ rte_eth_rx_burst(port, queue, &mbufs, burst_size)
DPDK mbuf 缓冲 (Zero-Copy 指针)
  ↓
ff_dpdk_if.c 中的 process_packets()
  ├─ 提取 L2/L3/L4 头部
  ├─ 协议过滤 (ARP/IPv4/IPv6/Multicast)
  ├─ 可选：数据包分发回调
  └─ 调用 FreeBSD 协议栈入口
  ↓
FreeBSD 网络栈
  ├─ eth_input()          [以太网处理]
  ├─ ip_input()           [IP 层]
  ├─ tcp_input()/udp_input() [L4 层]
  └─ sorecvX()            [Socket 接收缓冲]
  ↓
应用通过 ff_read()/ff_recv()/ff_recvfrom()/ff_recvmsg() 获取数据
```

**关键特性**：
- **Zero-Copy**：数据始终在 mbuf 中，不拷贝到内核缓冲
- **RSS 保证**：同一连接的所有报文都到达同一核心（无乱序）
- **无中断**：轮询模式不触发硬件中断

#### **发送路径 (Egress)**

```
应用调用 ff_write()/ff_send()/ff_sendto()/ff_sendmsg()
  ↓
FreeBSD TCP/UDP 协议栈
  ├─ tcp_output()      [TCP 分段/排序]
  ├─ ip_output()       [IP 寻址]
  └─ if_output()       [网卡输出]
  ↓
ff_glue.c 中的 if_start()
  ├─ 从待发队列获取 mbuf
  ├─ 填充 L2/L3/L4 头部
  ├─ 配置硬件卸载选项 (如 TSO/Checksum)
  └─ 调用 send_single_packet()
  ↓
DPDK TX 队列
  ├─ rte_eth_tx_burst() [批量发送]
  └─ 定时 drain (避免报文滞后)
  ↓
PMD 驱动
  ↓ [DMA 到 NIC 硬件]
NIC 硬件
  ├─ 执行 TSO (如需要)
  ├─ 校验和计算
  └─ 以太网发送
```

**关键优化**：
- **批量处理**：rte_eth_tx_burst() 一次发送多个 mbuf
- **硬件卸载**：TSO 可将一个大报文卸载到硬件分段
- **定时 drain**：避免单个报文长时间留在 TX 缓冲

### 3.3 主处理循环 (Main Loop)

F-Stack 的核心是一个高效的轮询循环：

```c
// 伪代码
static int main_loop(void *arg) {
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    
    while (!stop_loop) {
        // [1] 当前 TSC (时间戳计数器)
        cur_tsc = rte_rdtsc();
        
        // [2] 时钟管理 - 驱动 FreeBSD 定时器
        //    (TCP 重传定时、keepalive 等)
        if (freebsd_clock.expire < cur_tsc) {
            rte_timer_manage();
        }
        
        // [3] 轮询接收 - 遍历所有 RX 队列
        for (each_rx_queue) {
            nb_rx = rte_eth_rx_burst(port_id, queue_id, 
                                     pkts, MAX_PKT_BURST);
            
            if (nb_rx > 0) {
                process_packets(pkts, nb_rx);  // 交给 FreeBSD 栈
            }
        }
        
        // [4] 定时发送 - 刷新 TX 缓冲
        if ((cur_tsc - prev_tsc) > drain_tsc) {
            for (each_port) {
                rte_eth_tx_burst(port_id, queue_id, 
                                tx_buffer, nb_tx);
            }
            prev_tsc = cur_tsc;
        }
        
        // [5] 应用回调 - 业务逻辑
        if (loop_func) {
            loop_func(loop_arg);  // 用户的 main_loop 回调
        }
        
        // [6] 可选：空闲 sleep
        if (idle_sleep && nb_rx == 0) {
            rte_delay_us(idle_sleep);  // 微秒级 sleep
        }
    }
}
```

**循环特性**：
- **纯轮询**：无中断，100% CPU 换取微秒级延迟
- **定时驱动**：依靠 CPU TSC 计数器维护时钟
- **批处理**：每次处理 MAX_PKT_BURST 个报文
- **用户可控**：应用通过回调函数 loop_func 处理业务逻辑

### 3.4 内核栈共存模式（`FF_KERNEL_COEXIST`，可选，默认关）

默认情况下每个 socket 都纯粹运行在 F-Stack 用户态栈上。可选的 **内核栈共存** 模式让单个进程、单个 `ff_epoll_wait` 循环同时通过 **F-Stack 栈**（经 DPDK 网卡的高性能路径）与 **宿主 Linux 内核栈**（经 loopback / 管理网卡）对外服务。这样本机 `ping`/`curl` 可访问 F-Stack 监听端口，应用也可 `connect()` 到本机或外部的内核栈服务，且不放弃 F-Stack 快路径。

**两级门控（关闭时零回归）：**
- 编译期宏 `FF_KERNEL_COEXIST`（以 `make FF_KERNEL_COEXIST=1` 构建；默认不定义）。未定义时整个特性被编译剔除，产物与纯 F-Stack 库逐字节一致。
- 运行期开关 `config.ini [stack] kernel_coexist=0|1`（默认 `0`）。即使编译进库，未显式开启前也保持关闭。

**工作原理：**
- **逐 socket 选栈。** `ff_socket()` 识别按位 OR 进 `type` 的两个标记：`SOCK_FSTACK` 强制 F-Stack 栈，`SOCK_KERNEL` 强制宿主内核栈。无标记（且共存开启）时则 **双建** —— 一个 F-Stack socket 加一个配对的宿主内核 socket。优先级：per-socket 标记 > config `kernel_coexist` > F-Stack。
- **受管内核 fd 空间。** 内核栈 fd 以 `host_fd + FF_KERNEL_FD_BASE`（`0x40000000`）形式交给应用，远高于最大 FreeBSD fd（`kern.maxfiles <= 65536`），两段 fd 区间永不冲突。F-Stack 入口识别此类 fd 并转发给薄宿主 libc 桥；默认 F-Stack 路径保持不变。
- **双栈 fd 配对。** 双建 socket 的 F-Stack fd ↔ 宿主 fd 配对记录在 `ff_native_fd_map`，使控制/数据操作在需要处同时驱动两栈（如 `bind`/`listen` 双侧、`shutdown`/`close` 双侧）。双建 `AF_INET6` socket 的宿主对应 socket 被设 `IPV6_V6ONLY=1`（`ff_host_set_v6only`，R9），使 v4+v6 同端口共存（修复此前 `-DINET6` `errno=98` 启动失败）。
- **统一事件循环。** `ff_epoll_*` 为每个 kqueue 惰性配对一个宿主 `epoll` fd，使内核 fd 与 F-Stack 事件都从应用已有的单个 `ff_epoll_wait()` 投递出来。**R9** 将同一机制扩展到原生 `ff_kqueue`/`ff_kevent` 接口（共享 `ff_epoll_host_ep` 配对）：`ff_kevent` 把内核/双栈 fd 的 `EVFILT_READ/WRITE` 注册进 kqueue 配对的宿主 epoll，等待时非阻塞轮询宿主 epoll 合成 `struct kevent`（`ident`=应用面 fd）再合并 F-Stack 事件 —— 纯 kqueue 应用（`example/main.c`）现可感知内核侧 listener（实测 `curl 127.0.0.1:80`=200 size=438，修复前 000）。
- **R10 残余入口共存。** `ff_readv`/`ff_writev` 内核 fd 经 `ff_host_readv/writev`（仿 read/write）；`ff_ioctl` 内核 fd 用**原始 Linux request** 直传 `ff_host_ioctl`（双栈 fd 同驱动自 R10.1 起支持 `FIONBIO`/`FIOASYNC`（F-Stack 成功后用原始 Linux request 同步配对 host fd；`FIONREAD` 等 query 类不同驱动以免覆盖 argp））；`ff_dup`→`ff_host_dup`+encode，`ff_dup2` 两端内核 fd→`ff_host_dup2`+encode、混栈拒绝 `errno=EINVAL`。

**已知限制（本版本）：** 内核 fd 经 kqueue 仅支持 `EVFILT_READ/WRITE`；`ff_select`（encode 内核 fd≥`0x40000000` 超 `FD_SETSIZE`(1024) 硬限制）/`ff_poll`（保守未实现）不支持内核 fd 共存 —— 内核 fd 多路复用请用 `ff_epoll_*` / `ff_kqueue`。完整设计、测试与 review-gate 记录见 `docs/kernel_event_support_spec/`（+ `zh_cn/`）。

---

## 4. 多进程架构

### 4.1 为什么采用多进程而非多线程

**F-Stack 的设计选择：多进程 + 单线程轮询**

```
问题：为什么不用多线程？
━━━━━━━━━━━━━━━━━━━━━━━
1. FreeBSD 协议栈非线程安全
   - 协议栈设计为单线程运行
   - 众多全局变量和静态数据结构
   - 需要大量加锁 → 性能下降

2. 上下文切换开销大
   - CPU 缓存污染
   - TLB flush
   - 远低于单线程轮询

3. 共享内存复杂
   - socket 数据结构跨线程共享
   - race condition 难以排查

答案：多进程架构
━━━━━━━━━━━━━━━━━━━━━━━
核心特点：
✓ 每个进程独立的 FreeBSD 协议栈实例
✓ 单线程轮询，无竞争、无 locking
✓ 通过 DPDK RSS 分类实现连接亲和性
✓ 进程间零共享状态 (除了 mempool/NIC)
✓ 一个进程崩溃不影响其他进程
```

### 4.2 多进程部署模型

```
机器资源：
├─ CPU: 8 核
├─ NIC: 10GbE
└─ 内存: 16GB huge pages

F-Stack 部署：
┌────────────────────────────────────────────────────┐
│  主进程 (Primary) - CPU 0                           │
│  ├─ DPDK EAL 初始化                                │
│  ├─ 创建共享 hugepage/mempool                      │
│  ├─ 启动所有从进程                                  │
│  └─ 监听来自工具的 IPC 消息                        │
│                                                     │
│  从进程 1 - CPU 1              从进程 2 - CPU 2    │
│  ┌──────────────────┐         ┌──────────────────┐
│  │ FreeBSD 栈实例   │         │ FreeBSD 栈实例   │
│  │ RX/TX 队列映射   │         │ RX/TX 队列映射   │
│  │ 独立轮询循环     │  ←RSS→  │ 独立轮询循环     │
│  └──────────────────┘         └──────────────────┘
│
│  从进程 3 - CPU 3              ...从进程 N - CPU N
│  ...相同结构                     ...相同结构
│
└────────────────────────────────────────────────────┘
         ↑                          ↑
         │ 共享                     │ 共享
    ┌────┴────────────────────────┴───┐
    │ DPDK 共享资源                     │
    │ ├─ Mempool (无锁访问)            │
    │ ├─ Ring (IPC 消息传递)           │
    │ ├─ 虚拟网卡 KNI (可选)           │
    │ └─ RSS 分类表                    │
    └────────┬────────────────────────┘
             │
    ┌────────▼────────────────────────┐
    │ NIC 硬件 (单个 10GbE)            │
    │ ├─ RX 队列 0 → 进程 1            │
    │ ├─ RX 队列 1 → 进程 2            │
    │ ├─ RX 队列 2 → 进程 3            │
    │ └─ ...                          │
    └─────────────────────────────────┘
```

### 4.3 RSS (Receive Side Scaling) 连接亲和性

**关键概念**：同一连接的所有报文必须到达同一核心

```
NIC 硬件 RSS 计算：
┌─────────────────────────────────┐
│ 接收的报文头部                   │
├─────────────────────────────────┤
│ hash(SIP, DIP, Sport, Dport) % N│  ← 5元组哈希
├─────────────────────────────────┤
│ 结果 = RX 队列编号 (0..N-1)      │
└─────────────────────────────────┘
         ↓
   ┌─────────────────────┐
   │ RX 队列 Q           │
   │ ↓ (进程 绑定到核心) │
   │ 进程 P 处理         │
   └─────────────────────┘

效果：
✓ TCP 连接 {192.168.1.1:8000 ↔ 10.0.0.1:80}
✓ 所有报文 (包括 ACK/DATA) 都到队列 2
✓ 进程 2 独立处理该连接
✓ 没有跨核同步需求
✓ 完整避免 TCP 乱序和缓存污染
```

### 4.4 初始化流程

```
bash start.sh  (启动脚本)
  ├─ 计算 lcore_mask 中启用的核心数
  ├─ 设置 proc_id 环境变量 = 0
  ├─ 设置 proc_type = primary
  └─ 启动主进程
       ↓
       ff_init(argc, argv)
       ├─ ff_load_config()              # 加载 config.ini
       ├─ ff_dpdk_init()                # DPDK EAL 初始化
       │  ├─ rte_eal_init()             # 初始化 EAL
       │  ├─ rte_mempool_create()       # 创建 mbuf 内存池
       │  ├─ rte_eth_dev_configure()    # 配置 NIC
       │  ├─ rte_eth_rx_queue_setup()   # 创建 RX 队列
       │  ├─ rte_eth_tx_queue_setup()   # 创建 TX 队列
       │  └─ rte_eth_dev_start()        # 启动 NIC
       │
       ├─ ff_freebsd_init()             # 初始化 FreeBSD 协议栈
       │  ├─ ff_glue_init()             # 初始化粘合层
       │  ├─ init_network_stack()       # 初始化网络栈
       │  └─ init_route_table()         # 初始化路由表
       │
       ├─ ff_dpdk_if_up()               # 启动网卡
       └─ ff_run(loop_func, arg)        # 进入轮询循环
            ↓
            [主进程执行 loop_func 回调，同时处理 IPC]
            
       # 从进程启动（由启动脚本并行）
       proc_id = 1, proc_type = secondary
       ff_init(argc, argv)              # 相同初始化
       └─ ff_run(loop_func, arg)        # 进入轮询循环

进程间通信 (IPC)：
    ff_ipc_init()                       # 连接到主进程 EAL
    ff_ipc_send(msg)                    # 发送控制消息
    ff_ipc_recv(msg, type)              # 接收响应
    
    [通过 DPDK Ring 实现 RPC 风格通信]
```

---

## 5. 技术选型分析

### 5.1 为什么选择 DPDK？

| 对比项 | DPDK | NETMAP | PF_RING | 自研网络栈 |
|-------|------|--------|---------|----------|
| **社区** | ★★★★★ | ★★★ | ★★★ | × |
| **跨平台** | L/F/W | L/F | L only | 限定平台 |
| **生态** | ★★★★★ | ★★ | ★ | × |
| **性能** | ★★★★★ | ★★★★ | ★★★★ | ★★ |
| **硬件卸载** | ★★★★★ | ★★★ | ★★★ | × |
| **文档** | ★★★★★ | ★★★ | ★★ | × |
| **企业采用** | ★★★★★ | ★★ | ★★ | × |

**F-Stack 选择 DPDK 的原因**：
1. Tencent 已有 DPDK 积累（DNSPod 项目）
2. DPDK 官方支持 Primary/Secondary 多进程模型
3. 完整的硬件卸载支持（TSO/GSO/Checksum）
4. 成熟的生态（OvS-DPDK/SPDK/VPP）
5. 厂商 NIC 驱动支持度最高

### 5.2 为什么移植 FreeBSD 栈而非自研？

**对比分析**：

```
选项 A：移植 FreeBSD 协议栈（F-Stack 采用）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
优点：
✓ 代码成熟 (20+ 年优化)且清晰度较好
✓ 功能完整 (TCP/UDP/ICMP/IGMP/IPv6)
✓ RFC 兼容性高
✓ 已有 BBR/RACK/DCTCP 等算法
✓ 开发周期短 (6-12个月)

缺点：
✗ 迁移工作量大 (需要粘合层)
✗ 调试复杂 (内核 API 仿真)
✗ 维护成本 (跟踪上游变动)

选项 B：自研网络栈
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
优点：
✓ 高度定制化
✓ 无外部依赖
✓ 维护自主

缺点：
✗ 开发周期 2-3 年
✗ 功能缺陷多 (RFC 非兼容)
✗ 性能未知数 (缺乏验证)
✗ 协议升级成本高
✗ 不支持现代算法 (BBR/RACK)

选项 C：使用 Linux 内核栈 (Kernel Bypass)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✗ 不满足需求 (核心目标就是绕过内核)

移植到用户态优点：
✓ 版本迭代快，新功能支持早
✓ 性能一般略高于FreeBSD

移植到用户态缺点：
✗ 代码更复杂，清晰度不如FreeBSD
✗ 版本迭代快，跟进社区新版本工作量大
```

**历史背景**：
- F-Stack 初期（2013-2016）自研了简单 TCP/IP 栈
- 发现协议功能缺陷、性能优化空间有限
- 2017 年参考 libuinet/libplebnet，完整移植 FreeBSD 11.0
- 2021 年升级到 FreeBSD 13.0（支持 BBR 等算法）
- 2025-2026 完成第一阶段升级到 FreeBSD 15.0（M0~M5 + runtime-fix + rib-fix + Phase-5b；CVM 同期 A/B 基线 + 物理机基线；NFR-1 PASS，仅 nginx_fstack 4 核短连 `−6.10%` 作为非阻塞 trade-off observation；完整证据见 `freebsd_13_to_15_upgrade_spec/`）

### 5.3 KNI (Kernel Network Interface) 和virtio的设计决策

**KNI 的用途**：与 Linux 内核通信的虚拟网卡

```
应用层
  ↓ 业务数据
F-Stack (用户态)
  ├─ 主业务：处理 HTTP/DNS 等
  └─ 旁路：特殊地址、管理流量
       ↓ (可选)
    虚拟网卡 veth0 (内核)
       ↓ 可在内核执行
    ├─ tc (流量控制)
    ├─ iptables (防火墙)
    ├─ 监控工具
    └─ 与其他系统集成 (隧道等)
```

**为什么说"可选"**：
- 纯 F-Stack 应用（如 DNS 服务器）不需要 KNI
- 只有需要与 Linux 系统集成时启用
- KNI 会增加数据拷贝，影响吞吐 (2-3%)

**性能特性**：

- 默认速率限制：1K QPS 数据、9K QPS 控制、10K QPS 总体
- 可选的报文分发回调：应用自定义哪些流进入 KNI

**KNI 和 virtio 选择**：

- 当前版本 KNI 功能保留，但底层实现已从 `rte_kni.ko` 内核模块切换为 `virtio_user`（见 lib/Makefile:34），不再依赖内核 KNI 模块

---

## 6. 性能特性与硬件加速

### 6.1 NIC 硬件特性支持

F-Stack 充分利用现代 NIC 的硬件加速：

| 特性 | 说明 | 好处 |
|-----|------|------|
| **RSS** | 接收端缩放 | 多队列分类 → 多进程处理 |
| **TSO/GSO** | TCP 段卸载 | 一个大报文卸载硬件分段 |
| **LRO** | 大包接收合并 | 多个小报文硬件合并 |
| **RX/TX Checksum** | 校验和卸载 | CPU 不计算校验和 |
| **VLAN** | 虚拟网卡 | 硬件 VLAN 标签识别 |
| **Flow Isolate** | 流分类 | 精细化控制报文路由 |

### 6.2 优化技术

**1. 零拷贝 (Zero-Copy)**
```
传统方式：
NIC → kernel 缓冲 → 应用缓冲 (2 次拷贝)

F-Stack 方式：
NIC → DPDK mbuf → FreeBSD mbuf(0 次拷贝，仅指针传递) → 应用  # 【注】当前mbuf到应用使用的socket接口，零拷贝暂未支持，后续考虑将单独的零拷贝API ff_zc_mbuf_read()做实际实现支持
```

**2. 批处理 (Batch Processing)**
```
单个处理：
for i in 1..1M {
    process_packet(pkt[i])
}

批处理：
nb_rx = rte_eth_rx_burst(..., 32)  // 一次收 32 个
for i in 0..nb_rx-1 {
    process_packet(pkt[i])
}

效果：减少函数调用开销、提高 CPU 缓存命中率
```

**3. CPU 亲和性 (CPU Affinity)**
```
DPDK EAL 启动时：
  ├─ 为每个 lcore 预留 CPU 核心
  ├─ 禁用 CPU 动态调频
  ├─ 禁用 CPU migration
  └─ 优化：保证 TLB、L1/L2/L3 缓存命中

结果：避免缓存污染、减少上下文切换
```

**4. 大页内存 (Huge Pages)**
```
4KB 小页：
  │ 虚拟地址空间 │  TLB (64 条) │ 物理地址 │
  └──────────────┘              └──────────┘
  1M 个页 → 需要频繁 TLB miss

2MB 大页：
  │  虚拟地址空间  │  TLB (64 条)  │  物理地址  │
  └────────────────┘               └────────────┘
  512 个页 → 很少 TLB miss

效果：减少 TLB miss 导致的性能下降
```

---

## 7. 生态集成

### 7.1 应用集成方式

**方式 1：直接调用 FF API (推荐)**
```c
// 应用代码
#include <ff_api.h>

int main() {
    ff_init(argc, argv);
    
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    ff_bind(sockfd, ...);
    ff_listen(sockfd, ...);
    
    ff_run(my_loop_func, arg);  // 进入轮询
}
```

**方式 2：LD_PRELOAD 拦截 (如 Nginx)**

LD_PRELOAD 模式下应用以两个进程方式运行：独立的 `fstack` 实例（链接 libfstack.a，跑
DPDK 轮询），以及预加载 `libff_syscall.so` 的用户应用（如 nginx）。两者通过 Hugepage
共享内存通信——默认走信号量路径，置 `FF_USE_RING_IPC=1` 后切换为基于 DPDK SPSC
`rte_ring` 的 lock-free 路径。**`fstack` 实例必须在 LD_PRELOAD 应用之前启动**。

```bash
# 1) 先启动 fstack 实例（可启动多个）
./fstack --conf config.ini --proc-type=primary --proc-id=0 &

# 2) 再使用 LD_PRELOAD 启用 Nginx 的 F-Stack 支持
LD_PRELOAD=/path/to/libff_syscall.so nginx

# LD_PRELOAD 钩子拦截（转发至 ff_* / kqueue）：
  socket()     → ff_socket()                 accept()     → ff_accept()
  bind()       → ff_bind()                   accept4()    → ff_accept() + SOCK_CLOEXEC/NONBLOCK
  connect()    → ff_connect()                listen()     → ff_listen()
  read()       → ff_read()                   close()      → ff_close()
  write()      → ff_write()                  ioctl()      → ff_ioctl()
  send/sendto/sendmsg() → ff_send/sendto/sendmsg()
  recv/recvfrom/recvmsg() → ff_recv/recvfrom/recvmsg()
  __read_chk / __recv_chk / __recvfrom_chk   (glibc _FORTIFY_SOURCE 包装)
  epoll_create/ctl/wait() → kqueue 事件（可选 polling 模式）
  fork()       → 每进程独立 FreeBSD struct thread（贴近 Linux kernel 语义）
  ...

# 关键环境变量 / 编译开关：
#   FF_KERNEL_EVENT=1   并行转发内核 fd 给宿主 epoll
#   FF_MULTI_SC=1       SO_REUSEPORT 风格的多 sc，每 worker fd 一个 sc
#   FF_USE_RING_IPC=1   将 IPC 切到 lock-free DPDK SPSC ring（默认含 v3.4 优化）
```

完整功能列表、编译开关、已知限制及致谢请参考 `adapter/syscall/README.md`。

### 7.2 工具支持

运维工具通过 IPC 与 F-Stack 进程通信：

| 工具 | 功能 | 原理 |
|-----|------|------|
| **top** | CPU 统计 | 发送 FF_TOP 消息，接收统计数据 |
| **sysctl** | 参数查询/修改 | FF_SYSCTL 消息 |
| **ifconfig** | 网卡配置 | 读取配置结构体 |
| **route** | 路由管理 | FF_ROUTE 消息 |
| **netstat** | 网络统计 | FF_TRAFFIC 消息 |
| **arp** | ARP 表 | 查询 DPDK 内部状态 |
| **ipfw** | 防火墙 | FF_IPFW_CTL 消息 |
| **knictl** | KNI 控制 | FF_KNICTL 消息 |
| **traffic** | 流量统计 | FF_TRAFFIC 消息，支持多进程汇总 |
| **ndp** | IPv6 邻居发现 | ioctl 通信 (SIOCGNBRINFO_IN6 等) |
| **ngctl** | Netgraph 控制 | FF_NGCTL 消息 |

---

## 8. 总结

### 8.1 F-Stack 的三个核心创新

1. **Kernel Bypass** - 绕过 Linux 内核网络栈，减少上下文切换和系统调用开销
2. **FreeBSD 移植** - 复用成熟的 20+ 年优化的 TCP/IP 协议栈
3. **多进程隔离** - 充分利用多核，每个核心独立轮询，零跨核竞争

### 8.2 性能优势

- **吞吐**: 5M RPS (相比内核 200K RPS，提升 25 倍)
- **延迟**: P99 < 10μs (相比内核 100μs，降低 10 倍)
- **连接**: 10M 并发连接 (相比内核 1M，提升 10 倍)

### 8.3 适用场景

✓ DNS 服务器（高QPS、低延迟）  
✓ 负载均衡器（连接处理能力）  
✓ CDN 边缘节点（内容分发）  
✓ VPN 网关（吞吐优化）  
✓ 高性能 Web 服务器  
✗ 一般 Linux 应用（改造成本高）  

### 8.4 学习路径建议

**第一步**：理解 Kernel Bypass 的优势  
**第二步**：学习 DPDK 基础（EAL/Mempool/Ethdev）  
**第三步**：理解 FreeBSD 协议栈的关键部分  
**第四步**：研究 ff_dpdk_if.c 的收发包逻辑  
**第五步**：学习多进程部署和性能调优  

---

**相关文档**：
- [第二层：接口定义和规范](./F-Stack_Architecture_Layer2_Interface_Specification.md)
- [第三层：函数级索引](./F-Stack_Architecture_Layer3_Function_Index.md)
- [知识库总结](./F-Stack_Knowledge_Base_Summary.md)
