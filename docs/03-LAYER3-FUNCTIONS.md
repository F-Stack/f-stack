# F-Stack v1.25 第三层：函数级索引与数据模型

> **目标受众**: 内核/驱动开发工程师、性能优化工程师  
> **关键概念**: 函数索引、数据结构、系统调用适配、符号导出  
> **生成日期**: 2026-03-20

## 1. 导出函数完整索引 (80+ 函数)

<!-- 注: 此补充基于 2/3 评审意见一致 (GPT-5.4 + Claude) -->
> **符号导出层次**: 以下函数索引包含 `ff_api.h` 和 `ff_epoll.h` 中声明的全部接口。实际通过 `ff_api.symlist` 动态导出的符号是其子集。
> - ff_init / ff_run / ff_stop_run 在 `ff_api.h` 中声明但**不在** `ff_api.symlist` 中，仅通过静态链接可用
> - ff_epoll_* 系列函数声明在 `ff_epoll.h` 中，不在 `ff_api.h` 中

### 1.1 生命周期管理函数

| 函数 | 签名 | 功能 | 线程安全 |
|-----|------|------|--------|
| `ff_init` | `int ff_init(int argc, char *argv[])` | 初始化 DPDK/FreeBSD/网卡 | 否 |
| `ff_run` | `void ff_run(loop_func_t, void *arg)` | 启动主循环 (阻塞) | 否 |
| `ff_stop_run` | `void ff_stop_run(void)` | 优雅停止循环 | 是 |

### 1.2 Socket 族函数

| 函数 | 参数数 | 返回值 | 说明 |
|-----|--------|--------|------|
| `ff_socket` | 3 | int(fd) | 创建 socket |
| `ff_bind` | 3 | 0/error | 绑定地址 |
| `ff_listen` | 2 | 0/error | 监听 |
| `ff_accept` | 3 | int(fd) | 接受连接 |
| `ff_accept4` | 4 | int(fd) | 接受连接 (带标志) |
| `ff_connect` | 3 | 0/error | 发起连接 |
| `ff_close` | 1 | 0/error | 关闭 socket |
| `ff_shutdown` | 2 | 0/error | 关闭连接方向 |

### 1.3 数据 I/O 函数

| 函数 | 参数数 | 返回值 | 说明 |
|-----|--------|--------|------|
| `ff_read` | 3 | 字节数/-1 | 读取数据 |
| `ff_readv` | 3 | 字节数/-1 | 向量读 |
| `ff_write` | 3 | 字节数/-1 | 写入数据 |
| `ff_writev` | 3 | 字节数/-1 | 向量写 |
| `ff_send` | 4 | 字节数/-1 | 发送 |
| `ff_sendto` | 6 | 字节数/-1 | 发送到地址 |
| `ff_sendmsg` | 3 | 字节数/-1 | 发送消息 |
| `ff_recv` | 4 | 字节数/-1 | 接收 |
| `ff_recvfrom` | 6 | 字节数/-1 | 从地址接收 |
| `ff_recvmsg` | 3 | 字节数/-1 | 接收消息 |

### 1.4 事件多路复用函数

| 函数 | 用途 | 参数数 | 返回值 |
|-----|------|--------|--------|
| `ff_kqueue` | BSD 事件队列 | 1 | int(kq_fd) |
| `ff_kevent` | BSD 事件等待 | 6 | 事件数/-1 |
| `ff_kevent_do_each` | BSD 遍历事件 | 4 | void |
| `ff_epoll_create` | Linux epoll | 1 | int(ep_fd) |
| `ff_epoll_ctl` | epoll 控制 | 4 | 0/-1 |
| `ff_epoll_wait` | epoll 等待 | 4 | 事件数/-1 |
| `ff_select` | 传统 select | 5 | 就绪数/-1 |
| `ff_poll` | 传统 poll | 3 | 就绪数/-1 |

### 1.5 Socket 选项函数

| 函数 | 功能 | 说明 |
|-----|------|------|
| `ff_setsockopt` | 设置 socket 选项 | 支持 SO_*, TCP_*, IP_* 等 |
| `ff_getsockopt` | 获取 socket 选项 | 读取当前选项值 |
| `ff_fcntl` | 文件控制 | 支持 F_SETFL, F_GETFL 等 |
| `ff_ioctl` | 设备控制 | 支持 FIONBIO, FIONREAD 等 |

### 1.6 系统控制函数

| 函数 | 参数 | 功能 |
|-----|------|------|
| `ff_sysctl` | 6 | 读写内核变量 |
| `ff_route_ctl` | 2 | 路由表控制 |
| `ff_rtioctl` | 2 | 路由 ioctl |
| `ff_gettimeofday` | 2 | 获取系统时间 |

### 1.7 特殊功能函数

| 函数 | 功能 | 备注 |
|-----|------|------|
| `ff_zc_mbuf_get` | 获取零拷贝 mbuf | 直接访问 DMA 缓冲 |
| `ff_zc_mbuf_write` | 零拷贝写入 | 跳过内存拷贝 |
| `ff_zc_mbuf_read` | 零拷贝读取 | 接收原始 mbuf |
| `ff_mbuf_gethdr` | 获取 mbuf | DPDK 内存池分配 |
| `ff_mbuf_get` | 分配 mbuf | - |
| `ff_mbuf_free` | 释放 mbuf | - |
| `ff_mbuf_copydata` | 拷贝 mbuf 数据 | - |

### 1.8 多线程函数

| 函数 | 功能 |
|-----|------|
| `ff_pthread_create` | 创建 pthread |
| `ff_pthread_join` | 等待 pthread |
| `ff_msg_send` | 发送跨 lcore 消息 |

### 1.9 日志函数

| 函数 | 功能 |
|-----|------|
| `ff_log` | 格式化日志 |
| `ff_vlog` | va_list 日志 |
| `ff_openlog_stream` | 打开日志流 |
| `ff_log_set_global_level` | 设置全局日志级别 |
| `ff_log_set_level` | 设置模块日志级别 |
| `ff_log_close` | 关闭日志 |

## 2. 核心数据结构

### 2.1 kevent 结构 (BSD 事件)

```c
struct kevent {
    uintptr_t ident;           // 事件标识符 (fd 或定时器 ID)
    short filter;              // 事件过滤器类型
    u_short flags;             // 控制标志 (EV_ADD, EV_DELETE 等)
    u_int fflags;              // 过滤器特定标志
    intptr_t data;             // 事件数据 (就绪数、超时等)
    void *udata;               // 用户定义数据指针
};

// 过滤器类型 (filter 值)
#define EVFILT_READ      0     // 读就绪
#define EVFILT_WRITE     1     // 写就绪
#define EVFILT_AIO       2     // 异步 I/O
#define EVFILT_TIMER     3     // 定时器
#define EVFILT_SIGNAL    4     // 信号
#define EVFILT_VNODE     5     // 文件变化
#define EVFILT_PROC      6     // 进程事件
#define EVFILT_NETDEV    7     // 网卡事件
// ... 共 13 种过滤器

// 控制标志 (flags)
#define EV_ADD      0x0001     // 添加事件
#define EV_DELETE   0x0002     // 删除事件
#define EV_ENABLE   0x0004     // 启用事件
#define EV_DISABLE  0x0008     // 禁用事件
#define EV_ONESHOT  0x0010     // 一次性事件
#define EV_CLEAR    0x0020     // 边缘触发
#define EV_ERROR    0x4000     // 错误标志
#define EV_EOF      0x8000     // EOF 标志
```

### 2.2 ff_config 结构 (全局配置)

```c
struct ff_config {
    // DPDK 配置
    struct {
        char portid_list[32];        // NIC 端口列表
        uint32_t nb_ports;           // 端口数
        uint32_t lcore_mask;         // CPU 核心掩码
        char proc_type;              // 主/从进程
        uint32_t proc_id;            // 进程 ID
        uint32_t nb_procs;           // 进程总数
        uint32_t pktmbuf_pool_size;  // mbuf 池大小
        uint32_t numa_on;            // NUMA 支持
    } dpdk;
    
    // 主机配置
    struct {
        struct in_addr ipaddr;       // IP 地址
        struct in_addr netmask;      // 子网掩码
        struct in_addr gateway;      // 网关
        char iface[IFNAMSIZ];        // 网卡名称
    } host;
    
    // KNI 虚拟网卡配置
    struct {
        uint32_t enable;             // 启用标志
        char name[IFNAMSIZ];         // 网卡名
        uint32_t core;               // CPU 核心
    } kni;
    
    // 其他配置...
} ff_global_cfg;
```

### 2.3 ff_port_cfg 结构 (端口配置)

```c
struct ff_port_cfg {
    uint16_t port_id;               // 端口 ID
    
    // 硬件特性
    struct ff_hw_features {
        uint32_t rx_csum: 1;         // RX 校验和卸载
        uint32_t rx_lro: 1;          // LRO (合并报文)
        uint32_t tx_csum: 1;         // TX 校验和卸载
        uint32_t tx_tso: 1;          // TSO (分段卸载)
        uint32_t tx_vlan: 1;         // VLAN 插入
        // ... 更多标志
    } hw_features;
    
    // RSS 配置
    struct rte_eth_rss_conf rss_conf;
    
    // VLAN 配置
    uint32_t vlan_enable;
    uint16_t vlan_id;
};
```

### 2.4 ff_rss_tbl 结构 (RSS 查表)

```c
// RSS 表项：将源 IP/端口映射到目标队列
struct ff_rss_tbl_entry {
    struct in_addr saddr;          // 源 IP
    uint16_t sport;                // 源端口
    
    struct in_addr daddr;          // 目标 IP 范围开始
    uint16_t dport_start;          // 目标端口范围开始
    uint16_t dport_end;
    
    uint16_t queue_id;             // 目标 RX 队列
    uint16_t lcore_id;             // 目标 CPU 核心
};

// 查表函数
uint16_t ff_rss_tbl_lookup(struct in_addr saddr, uint16_t sport,
                           struct in_addr daddr, uint16_t dport);
```

### 2.5 ff_msg_ring 结构 (进程间通信)

```c
// 轻量级消息队列，用于跨 lcore 消息传递
struct ff_msg_ring {
    void (*cb)(void *arg);         // 回调函数指针
    void *arg;                     // 回调参数
};

// 发送消息到另一个 lcore
int ff_msg_send(unsigned lcore_id, 
                void (*cb)(void *), 
                void *arg);
```

### 2.6 ff_tx_offload 结构 (发送卸载)

```c
struct ff_tx_offload {
    uint16_t tso_seg_size;         // TSO 分段大小 (0 = 禁用)
    uint8_t tx_csum_ip;            // IP 校验和卸载
    uint8_t tx_csum_l4;            // L4 校验和卸载
    uint8_t vlan_insert;           // VLAN 插入标志
    uint16_t vlan_id;              // VLAN ID
};
```

### 2.7 ff_zc_mbuf 结构 (零拷贝)

```c
struct ff_zc_mbuf {
    struct rte_mbuf **m;           // mbuf 指针数组
    uint16_t nb_mbufs;             // 缓冲区数量
};
```

### 2.8 ff_dispatcher_context 结构 (包分发)

```c
struct ff_dispatcher_context {
    uint16_t port_id;              // 入口网卡
    uint16_t queue_id;             // 入口队列
    
    uint8_t *data;                 // 报文数据
    uint16_t len;                  // 报文长度
    
    // 解析结果
    uint16_t vlan_id;              // VLAN ID
    uint8_t *l3_data;              // L3 头指针
    uint8_t *l4_data;              // L4 头指针
    
    // 控制信息
    uint32_t flags;                // 标志位
};
```

## 3. 三个关键源文件分析

### 3.1 ff_syscall_wrapper.c (1825 行) - Linux/FreeBSD 适配

**主要职责**: 将 Linux 系统调用参数/选项转换为 FreeBSD 等价物

**Linux 选项映射示例**:

```c
// SOL_SOCKET 级选项
#define LINUX_SOL_SOCKET      1
#define LINUX_SO_REUSEADDR    2       // → SO_REUSEADDR
#define LINUX_SO_TYPE         3       // → SO_TYPE
#define LINUX_SO_ERROR        4       // → SO_ERROR
#define LINUX_SO_DONTROUTE    5       // → SO_DONTROUTE
#define LINUX_SO_BROADCAST    6       // → SO_BROADCAST
#define LINUX_SO_SNDBUF       7       // → SO_SNDBUF
#define LINUX_SO_RCVBUF       8       // → SO_RCVBUF
#define LINUX_SO_RCVLOWAT     18      // → SO_RCVLOWAT
#define LINUX_SO_SNDLOWAT     19      // → SO_SNDLOWAT
#define LINUX_SO_REUSEPORT    15      // → SO_REUSEPORT

// IPPROTO_IP 级选项
#define LINUX_IP_TOS          1       // → IP_TOS
#define LINUX_IP_TTL          2       // → IP_TTL
#define LINUX_IP_HDRINCL      3       // → IP_HDRINCL
#define LINUX_IP_MULTICAST_IF 32      // → IP_MULTICAST_IF
#define LINUX_IP_MULTICAST_TTL 33     // → IP_MULTICAST_TTL
#define LINUX_IP_ADD_MEMBERSHIP 35    // → IP_ADD_MEMBERSHIP

// IPPROTO_TCP 级选项
#define LINUX_TCP_NODELAY     1       // → TCP_NODELAY
#define LINUX_TCP_MAXSEG      2       // → TCP_MAXSEG
#define LINUX_TCP_KEEPIDLE    4       // → TCP_KEEPIDLE
#define LINUX_TCP_KEEPINTVL   5       // → TCP_KEEPINTVL
#define LINUX_TCP_KEEPCNT     6       // → TCP_KEEPCNT
```

**关键转换函数**:

```c
int ff_setsockopt(int s, int level, int optname,
                  const void *optval, socklen_t optlen) {
    // 1. 转换 level (SOL_SOCKET → SOL_SOCKET)
    // 2. 转换 optname (LINUX_SO_REUSEADDR → SO_REUSEADDR)
    // 3. 转换 optval 格式 (如果需要)
    // 4. 调用 FreeBSD setsockopt()
}
```

**支持的 ioctl 命令**:

```c
#define LINUX_FIONBIO       0x5421    // 非阻塞 I/O
#define LINUX_FIONREAD      0x541B    // 可读字节数
#define LINUX_SIOCGIFNAME   0x8910    // 获取网卡名
#define LINUX_SIOCGIFCONF   0x8912    // 获取网卡配置
#define LINUX_SIOCGIFFLAGS  0x8913    // 获取网卡标志
```

### 3.2 ff_dpdk_if.c (2855 行) - NIC 驱动层

**文件结构**:

```
ff_dpdk_if.c
├─ 全局变量 (行 50-150)
│  ├─ enable_kni
│  ├─ nb_dev_ports
│  ├─ idle_sleep
│  └─ pktmbuf_pool[]
│
├─ DPDK 初始化 (行 200-400)
│  ├─ ff_dpdk_init()
│  ├─ init_mem_pool()
│  ├─ init_lcore_conf()
│  └─ init_port_start()
│
├─ 报文处理 (行 1500-1800)
│  ├─ process_packets()
│  ├─ protocol_filter()
│  └─ veth_input()
│
└─ 主循环 (行 2000-2200)
   ├─ main_loop()
   ├─ ff_dpdk_run()
   └─ 定时器管理
```

**关键全局变量**:

```c
static uint32_t enable_kni = 0;              // KNI 启用标志
static uint16_t nb_dev_ports = 0;            // NIC 数量
static uint32_t idle_sleep = 100;            // 空闲睡眠微秒数
static struct rte_mempool *pktmbuf_pool[RTE_MAX_LCORE];  // 每核 mbuf 池
```

**初始化函数调用链**:

```
ff_dpdk_init()
├─ rte_eal_init(dpdk_argc, dpdk_argv)       // DPDK EAL
├─ init_mem_pool()
│  └─ rte_pktmbuf_pool_create()
├─ init_lcore_conf()
│  └─ 配置 lcore/port/queue 映射
├─ init_dispatch_ring()
│  └─ rte_ring_create()
├─ init_msg_ring()
│  └─ 进程间消息队列
├─ init_kni()
│  └─ rte_kni_init()                        (可选)
├─ init_port_start()
│  ├─ rte_eth_dev_configure()
│  ├─ rte_eth_rx_queue_setup()
│  ├─ rte_eth_tx_queue_setup()
│  ├─ rte_eth_promiscuous_enable()
│  ├─ rte_eth_dev_start()
│  └─ ff_rss_tbl_init()
└─ init_clock()
   └─ rte_get_tsc_hz()
```

**main_loop() 伪代码详解**:

```c
int main_loop(void *arg) {
    struct lcore_conf *lr = lcore_conf + lcore_id();
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    uint64_t cur_tsc, prev_tsc = 0;
    
    while (!stop_loop) {
        cur_tsc = rte_rdtsc();
        
        // === 1. 驱动 FreeBSD 定时器 ===
        if (unlikely(freebsd_clock.expire < cur_tsc)) {
            rte_timer_manage();        // 触发 TCP timers 等
            freebsd_clock.expire = cur_tsc + FREEBSD_CLOCK_TICK;
        }
        
        // === 2. 接收报文 ===
        for (each_port in lr->ports) {
            for (each_queue) {
                uint16_t nb_rx = rte_eth_rx_burst(
                    port_id, queue_id, 
                    pkts_burst, MAX_PKT_BURST
                );
                process_packets(pkts_burst, nb_rx);
            }
        }
        
        // === 3. 发送报文 (定时刷新) ===
        if (drain_tsc && (cur_tsc - prev_tsc) > drain_tsc) {
            for (each_port in lr->ports) {
                uint16_t nb_tx = rte_eth_tx_buffer_flush(
                    port_id, queue_id, tx_buffer
                );
            }
            prev_tsc = cur_tsc;
        }
        
        // === 4. 执行用户回调 ===
        if (lr->loop) {
            int ret = lr->loop(lr->arg);  // 应用业务逻辑
            if (ret < 0) {
                ff_stop_run();
            }
        }
    }
    
    return 0;
}
```

**KNI 速率限制**:

```c
struct ff_kni_rate_limit {
    uint32_t general_packets;              // 一般数据限制
    uint32_t console_packets;              // 控制消息限制
    uint32_t kernel_packets;               // 内核通信限制
    // 典型值: general=10K QPS, console=1K, kernel=9K
};
```

### 3.3 ff_glue.c (1466 行) - FreeBSD 粘合层

**核心职责**: 为用户态 FreeBSD 协议栈提供内核原语

**内存管理模拟**:

```c
#define M_DEVBUF     1             // 设备缓冲
#define M_TEMP       2             // 临时缓冲
#define M_CRED       3             // 凭证
#define M_IP6OPT     4             // IPv6 选项

void *malloc(size_t size, struct malloc_type *type, int flags) {
    // 底层使用 DPDK rte_malloc
    if (flags & M_NOWAIT) {
        return rte_malloc_socket(NULL, size, 0, rte_socket_id());
    } else {
        return rte_malloc(NULL, size, 0);
    }
}

void free(void *ptr, struct malloc_type *type) {
    rte_free(ptr);
}
```

**全局内核变量模拟**:

```c
// FreeBSD 内核变量
volatile int ticks = 0;                    // 内核滴答计数
int mp_ncpus = 1;                          // CPU 数量
int mp_maxcpus = RTE_MAX_LCORE;
cpuset_t all_cpus;                         // CPU 集合
struct vm_cnt vm_cnt = {0};                // 虚拟内存统计
```

**同步原语模拟**:

```c
// FreeBSD 互斥锁
struct mtx {
    void *ctx;                             // pthread_mutex_t
};

void mtx_init(struct mtx *m, const char *name, const char *type, int opts) {
    pthread_mutex_t *mutex = malloc(sizeof(*mutex), M_DEVBUF, M_NOWAIT);
    pthread_mutex_init(mutex, NULL);
    m->ctx = mutex;
}

void mtx_lock(struct mtx *m) {
    pthread_mutex_lock((pthread_mutex_t *)m->ctx);
}

// 条件变量类似...
```

**进程模拟**:

```c
// 全局进程对象
struct proc proc0;                         // 初始进程
struct thread thread0_st;                  // 初始线程
struct vmspace vmspace0;                   // 虚拟内存空间
struct prison prison0;                     // 命名空间
```

## 4. 关键头文件总览

| 头文件 | 行数 | 用途 |
|-------|------|------|
| `ff_api.h` | ~500 | 所有公开 API 声明 |
| `ff_config.h` | ~100 | 配置结构体定义 |
| `ff_event.h` | ~150 | kevent 结构和宏 |
| `ff_errno.h` | ~100 | 96 个 errno 映射 |
| `ff_host_interface.h` | ~80 | OS 抽象层 (pthread/mmap) |
| `ff_dpdk_if.h` | ~50 | DPDK 初始化接口 |
| `ff_veth.h` | ~100 | 虚拟以太网和 mbuf 操作 |
| `ff_log.h` | ~50 | 日志级别和宏 |
| `ff_memory.h` | ~80 | 内存管理函数 |
| `ff_msg.h` | ~60 | 跨 lcore 消息传递 |
| `ff_epoll.h` | ~80 | epoll 包装实现 |
| `ff_ini_parser.h` | ~50 | 配置文件解析 |
| `ff_dpdk_kni.h` | ~50 | KNI 接口 (可选) |

## 5. 编译链接指令

### 5.1 编译 F-Stack 库

```bash
cd /data/workspace/f-stack/lib

# 基础编译
make clean
make

# 带 IPv6 支持
FF_INET6=1 make

# 带 KNI 虚拟网卡
FF_KNI=1 make

# 带高精度 TCP 定时器
FF_TCPHPTS=1 make

# 安装到系统
make install PREFIX=/usr/local
```

### 5.2 编译应用

```bash
gcc -o myapp main.c \
    -lfstack \
    $(pkg-config --cflags --libs libdpdk) \
    -lpthread -lm -O2

# 运行示例
# 指定 CPU 核心和 NIC 端口
./myapp -l 0 -w 0000:01:00.0
```

## 6. 线程安全性规则

### 6.1 安全操作 (✓)

- Socket API (ff_socket, ff_read, ff_write)
- 配置查询 (ff_sysctl)
- 事件等待 (ff_kevent, ff_epoll_wait)
- **限制**: 必须在同一 lcore 内

### 6.2 非安全操作 (✗)

- 跨 lcore 的 socket 操作
- 运行中修改配置
- 运行中创建/销毁线程

### 6.3 原子操作 (✓)

DPDK 内存池原子操作:
```c
rte_pktmbuf_alloc(pool);       // 多进程安全
rte_pktmbuf_free(m);           // 多进程安全
```

## 7. 常见错误码

| 错误 | 值 | 说明 |
|-----|---|----|
| ENOTSOCK | 38 | 不是 socket |
| ECONNREFUSED | 61 | 连接被拒绝 |
| ETIMEDOUT | 60 | 操作超时 |
| ENOTCONN | 57 | socket 未连接 |
| EWOULDBLOCK | 35 | 资源暂不可用 |
| EMFILE | 24 | 打开文件过多 |
| ENOMEM | 12 | 内存不足 |

## 总结

F-Stack 的第三层定义了 80+ 导出函数、11 个核心数据结构、三个关键源文件 (ff_syscall_wrapper, ff_dpdk_if, ff_glue)。这些组件协同工作，实现了完整的用户态 TCP/IP 协议栈。掌握这些基础是高性能网络应用开发的前提。
