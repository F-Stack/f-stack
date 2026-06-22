# F-Stack v1.26 第三层：函数级索引与数据模型

> **目标受众**: 内核/驱动开发工程师、性能优化工程师  
> **关键概念**: 函数索引、数据结构、系统调用适配、符号导出  
> **生成日期**: 2026-03-20

## 1. 导出函数完整索引 (80+ 函数)

> **符号导出层次**: 以下函数索引包含 `ff_api.h` 和 `ff_epoll.h` 中声明的全部接口。实际通过 `ff_api.symlist` 动态导出的符号是其子集。
> - ff_init / ff_run / ff_stop_run 在 `ff_api.h` 中声明但**不在** `ff_api.symlist` 中，仅通过静态链接可用
> - ff_epoll_* 系列函数声明在 `ff_epoll.h` 中，不在 `ff_api.h` 中

### 1.1 生命周期管理函数

| 函数 | 签名 | 功能 | 线程安全 |
|-----|------|------|--------|
| `ff_init` | `int ff_init(int argc, char * const argv[])` | 初始化 DPDK/FreeBSD/网卡 | 否 |
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
| `ff_kqueue` | BSD 事件队列 | 0 | int(kq_fd) |
| `ff_kevent` | BSD 事件等待 | 6 | 事件数/-1 |
| `ff_kevent_do_each` | BSD 遍历事件 | 7 | int |
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
| `ff_route_ctl` | 5 | 路由表控制 |
| `ff_rtioctl` | 4 | 路由 ioctl |
| `ff_gettimeofday` | 2 | 获取系统时间 |

### 1.7 特殊功能函数

| 函数 | 功能 | 备注 |
|-----|------|------|
| `ff_zc_mbuf_get` | 获取零拷贝 mbuf | 直接访问 DMA 缓冲 |
| `ff_zc_mbuf_write` | 零拷贝写入 | 跳过内存拷贝 |
| `ff_zc_mbuf_read` | 零拷贝读取 | 接收原始 mbuf（**暂未实现，后续考虑支持**） |
| `ff_mbuf_gethdr` | 获取 mbuf | DPDK 内存池分配 |
| `ff_mbuf_get` | 分配 mbuf | - |
| `ff_mbuf_free` | 释放 mbuf | - |
| `ff_mbuf_copydata` | 拷贝 mbuf 数据 | - |

### 1.8 多线程函数

| 函数 | 功能 |
|-----|------|
| `ff_pthread_create` | 创建 pthread |
| `ff_pthread_join` | 等待 pthread |

### 1.9 日志函数

| 函数 | 签名 | 功能 |
|-----|------|------|
| `ff_log` | `int ff_log(uint32_t level, uint32_t logtype, const char *format, ...)` | 格式化日志 |
| `ff_vlog` | `int ff_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap)` | va_list 日志 |
| `ff_log_reset_stream` | `int ff_log_reset_stream(void *f)` | 重设日志输出流 |
| `ff_log_set_global_level` | `void ff_log_set_global_level(uint32_t level)` | 设置全局日志级别 |
| `ff_log_set_level` | `int ff_log_set_level(uint32_t logtype, uint32_t level)` | 设置模块日志级别 |
| `ff_log_close` | `void ff_log_close(void)` | 关闭日志 |

## 2. 核心数据结构

### 2.1 kevent 结构 (BSD 事件)

```c
struct kevent {
    uintptr_t ident;           // 事件标识符 (fd 或定时器 ID)
    short filter;              // 事件过滤器类型 (short，非 int16_t)
    unsigned short flags;      // 控制标志 (EV_ADD, EV_DELETE 等)
    unsigned int fflags;       // 过滤器特定标志
    __int64_t data;            // 事件数据 (就绪数、超时等，固定 64 位)
    void *udata;               // 用户定义数据指针
    __uint64_t ext[4];         // FreeBSD 13/15 扩展字段（升级前后 KBI 不变；M2 verify-only）
};

// 过滤器类型 (filter 值)
#define EVFILT_READ      -1     // 读就绪
#define EVFILT_WRITE     -2     // 写就绪
#define EVFILT_AIO       -3     // 异步 I/O
#define EVFILT_VNODE     -4     // 文件/目录 inode 事件
#define EVFILT_PROC      -5     // 进程事件	
#define EVFILT_SIGNAL    -6     // 信号递送
#define EVFILT_TIMER     -7     // 定时器
#define EVFILT_PROCDESC  -8     // 进程描述符事件
#define EVFILT_FS        -9     // 文件变化
#define EVFILT_LIO      -10     // 异步 I/O 列表
#define EVFILT_USER     -11     // 用户事件
#define EVFILT_SENDFILE -12     // 内核发送文件事件
#define EVFILT_EMPTY    -13     // 清空发送套接字缓冲区
#define EVFILT_SYSCOUNT  13     // ... 共 13 种过滤器

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

> **注意**: 以下为简化示意，非 `ff_config.h` 中的完整定义。实际结构中配置值均以字符串 (`char *`) 形式存储，由 `ff_load_config()` 解析 config.ini 后填充。关键字段类型如下：

```c
struct ff_config {
    char *filename;           // 配置文件路径
    struct {
        char *lcore_mask;     // CPU 核心掩码 (字符串，如 "0x01")
        char *proc_type;      // 进程类型 (字符串 "primary"/"secondary")
        uint32_t proc_id;     // 进程 ID
        uint32_t nb_procs;    // 进程总数
        uint32_t pktmbuf_pool_size;  // mbuf 池大小
        uint32_t numa_on;     // NUMA 支持
        uint16_t *portid_list; // NIC 端口 ID 列表
        uint32_t nb_ports;    // 端口数
    } dpdk;

    // 端口配置通过 dpdk.port_cfgs 访问 (struct ff_port_cfg 数组)
    // 每个 ff_port_cfg 包含 IP/mask/gw 等字段

    struct {
        uint32_t enable;      // KNI 启用标志
        char *kni_action;     // KNI 转发策略
    } kni;

    // ... 更多字段见 lib/ff_config.h
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

> **注意**: `ff_rss_tbl_lookup()` 函数不存在于公开 API 中，RSS 表仅供内部使用。实际结构体为 `ff_rss_tbl_type`（定义在 `lib/ff_dpdk_if.c`），外部无需直接访问。

```c
// 内部结构（仅供参考，不在公开头文件中）
struct ff_rss_tbl_type {
    uint32_t saddr;       // 源 IP
    uint16_t sport;       // 源端口
    uint16_t num;         // dip 表项数量
    struct ff_rss_tbl_dip_type dip_tbl[FF_RSS_TBL_MAX_DADDR];
} __rte_cache_aligned;

// 公开初始化接口 (ff_host_interface.h)
int ff_rss_tbl_init(void);
```

> **RSS 选端口优化（详见 `ff_rss_check_opt_spec`）**：connect 侧 RSS 源端口选择已扩展三项优化——（0.1）IPv4 内核侧 portrange 钩子回迁 FreeBSD 15.0（`freebsd/netinet/in_pcb.c`）；（0.3）动态快路径，用 `rte_thash_adjust_tuple` 反算源端口并强制软算复核兜底（`ff_rss_thash_ctx_init` / `ff_rss_adjust_sport`）；（0.2）IPv6 独立路径（`ff_rss_check6` / `ff_rss_tbl6_init` / `ff_rss_tbl6_set/get_portrange` / `ff_rss_adjust_sport6`），不改 IPv4 结构与签名。另有只读接口 `ff_rss_self_queue_info()` 暴露本进程 queueid / nb_queues / reta_size。实现与验证：`docs/ff_rss_check_opt_spec/zh_cn/`。R-D（2026-06，spec 10 §R-D）：`ff_rss_adjust_sport` / `ff_rss_adjust_sport6` 的二次软算复核改为运行时门控（`config.ini [rss_check] recheck=0`/`=1`），默认关闭以兑现 ~100 ns/call 性能收益；`recheck=1` 仅供 debug 复核。

### 2.5 ff_msg_ring 结构 (进程间通信)

> **注意**: `ff_msg_send()` 不是公开 API，在 `ff_api.h` 和 `ff_api.symlist` 中均不存在。进程间通信通过 `ff_msg` 消息队列（`lib/ff_msg.h`）实现，由 F-Stack 内部工具（knictl/sysctl 等）使用，应用层无需直接调用。

```c
// 消息类型枚举 (lib/ff_msg.h)
enum FF_MSG_TYPE {
    FF_UNKNOWN = 0,
    FF_SYSCTL,
    FF_IOCTL,
    FF_IOCTL6,
    FF_ROUTE,
    FF_TOP,
    FF_NGCTL,
    FF_IPFW_CTL,
    FF_TRAFFIC,
    FF_KNICTL,
    FF_MSG_NUM,
};

// 消息结构体 (简化)
struct ff_msg {
    enum FF_MSG_TYPE msg_type;
    int result;
    size_t buf_len;
    char *buf_addr;
    union {
        struct ff_sysctl_args sysctl;
        struct ff_route_args route;
        struct ff_traffic_args traffic;
        struct ff_knictl_args knictl;
        // ...
    };
} __attribute__((packed)) __rte_cache_aligned;
```

### 2.6 ff_tx_offload 结构 (发送卸载)

```c
struct ff_tx_offload {
    uint8_t ip_csum;               // IP 校验和卸载
    uint8_t tcp_csum;              // TCP 校验和卸载
    uint8_t udp_csum;              // UDP 校验和卸载
    uint8_t sctp_csum;             // SCTP 校验和卸载
    uint16_t tso_seg_size;         // TSO 分段大小 (0 = 禁用)
};
```

### 2.7 ff_zc_mbuf 结构 (零拷贝)

```c
// 定义于 lib/ff_api.h
struct ff_zc_mbuf {
    void *bsd_mbuf;         // 指向 mbuf 链头
    void *bsd_mbuf_off;     // 指向当前偏移处的 mbuf
    int off;                // 当前总偏移量 (APP 不应修改)
    int len;                // mbuf 链总长度
};

// 使用方法：
//   1. 调用方分配 struct ff_zc_mbuf zm; (栈上或堆上均可)
//   2. ff_zc_mbuf_get(&zm, len)   — 分配 mbuf 链，填充 zm
//   3. ff_zc_mbuf_write(&zm, data, len) — 写入数据到 mbuf 链
//   4. ff_write(fd, zm.bsd_mbuf, len)   — 以 bsd_mbuf 为 buf 发送
//
// 注意: ff_zc_mbuf_read() 暂未实现

int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);
int ff_zc_mbuf_read(struct ff_zc_mbuf *m, const char *data, int len);  // 暂未实现
```

### 2.8 ff_dispatcher_context 结构 (包分发)

> **注意**: 以下为 `ff_api.h` 中的实际定义。此结构作为 `dispatch_func_context_t` 回调的额外上下文参数传入，仅包含 VLAN 相关信息。报文数据、长度、队列等信息通过回调函数的其他参数传递。

```c
struct ff_dispatcher_context {
    struct {
        uint8_t stripped;          // VLAN 是否已剥离
        uint16_t vlan_tci;         // Priority (3) + CFI (1) + Identifier Code (12)
    } vlan;
};
```

## 3. 三个关键源文件分析

### 3.1 ff_syscall_wrapper.c (2265 行) - Linux/FreeBSD 适配

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

### 3.2 ff_dpdk_if.c (2907 行) - NIC 驱动层

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
int enable_kni = 0;                                   // KNI 启用标志（非 static）
int nb_dev_ports = 0;                                  // NIC 数量（非 static，非 uint16_t）
static unsigned idle_sleep;                            // 空闲睡眠微秒数（由配置赋值，无硬编码默认值）
struct rte_mempool *pktmbuf_pool[NB_SOCKETS];          // 按 NUMA socket 索引的 mbuf 池
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
    
    while (1) {
        if (unlikely(stop_loop)) break;
        
        cur_tsc = rte_rdtsc();
        
        // === 1. 驱动 FreeBSD 定时器 ===
        if (unlikely(freebsd_clock.expire < cur_tsc)) {
            rte_timer_manage();        // 触发 TCP timers 等
        }
        
        // === 2. TX burst queue drain (先于 RX) ===
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc >= drain_tsc)) {
            for (each_port in qconf->tx_ports) {
                send_burst(qconf, ...);
            }
            prev_tsc = cur_tsc;
        }
        
        // === 3. 接收报文 (RX) ===
        for (each_rx_queue in qconf->rx_queues) {
            uint16_t nb_rx = rte_eth_rx_burst(
                port_id, queue_id, 
                pkts_burst, MAX_PKT_BURST
            );
            process_packets(pkts_burst, nb_rx);
        }
        
        // === 4. 执行用户回调 ===
        if (lr->loop) {
            lr->loop(lr->arg);         // 应用业务逻辑
        }
        
        // === 5. 空闲睡眠 ===
        if (likely(idle && idle_sleep)) {
            rte_delay_us_sleep(idle_sleep);
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

### 3.3 ff_glue.c (1467 行) - FreeBSD 粘合层

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

### 3.4 内核栈共存文件（`FF_KERNEL_COEXIST`，可选）

仅 `FF_KERNEL_COEXIST=1` 时编译：
- **`ff_host_interface.c`（617 行）/ `.h`（187 行）**：`FF_KERNEL_FD_BASE=0x40000000` + inline `ff_is_kernel_fd/ff_kernel_fd_encode/ff_kernel_fd_real`；`ff_native_fd_map[65536]` + `ff_native_map_get/set/clear`；**32 个 `ff_host_*` 宿主 libc 桥**（R9 新增 `ff_host_set_v6only`、`ff_host_kqueue_ctl`、`ff_host_kqueue_poll`；R10 新增 `ff_host_readv`、`ff_host_writev`、`ff_host_ioctl`、`ff_host_dup`、`ff_host_dup2`）。
- **`ff_epoll.c`（289 行）**：`ff_epoll_pairs[64]` 为每个 kqueue 惰性配对宿主 `epoll`；`ff_epoll_wait` 先非阻塞轮询宿主 epoll 再合并 kqueue 事件（单线程，无锁）。`ff_epoll_host_ep` 共享（由 `static` 提升），供 R9 kqueue 路径复用同一配对表。
- **R9 kqueue/kevent 共存（`ff_syscall_wrapper.c`）**：`ff_kqueue`/`ff_kevent` 对称仿 epoll —— 把内核/双栈 fd 的 `EVFILT_READ/WRITE` 经 `ff_host_kqueue_ctl` 注册进 kqueue 配对的宿主 epoll，经非阻塞 `ff_host_kqueue_poll` 合成 `struct kevent`（`ident`=应用面 fd、`EV_EOF`↔`EPOLLHUP|ERR`），再合并 `ff_kevent_do_each` F-Stack 事件。修复 `example/main.c` kqueue 模型（内核侧 `curl 127.0.0.1:80`=200，修复前 000）。内核 fd 仅支持 `EVFILT_READ/WRITE`。
- **R9 IPv6**：双建 `AF_INET6` socket 的宿主对应 socket 被设 `IPV6_V6ONLY=1`（`ff_host_set_v6only`），使 `-DINET6` 构建以 v4+v6 同端口启动（修复此前 `errno=98 EADDRINUSE`）。
- **R10 残余入口共存（`ff_syscall_wrapper.c`）**：`ff_readv`（L1189）/`ff_writev`（L1251）内核 fd 经 `ff_host_readv/writev`（仿 read/write，连接 fd 单栈热路径）；`ff_ioctl`（L1067）内核 fd 用**原始 Linux request** 直传 `ff_host_ioctl`（不经 `linux2freebsd_ioctl`；双栈 fd 同驱动自 R10.1 起支持 `FIONBIO`/`FIOASYNC`（F-Stack 成功后用原始 Linux request 同步配对 host fd；`FIONREAD` 等 query 类不同驱动以免覆盖 argp））；`ff_dup`（L2130）内核 fd→`ff_host_dup`+encode；`ff_dup2`（L2156）两端内核 fd→`ff_host_dup2`+encode、混栈拒绝 `errno=EINVAL`。已知限制：`ff_select`（encode 内核 fd 超 `FD_SETSIZE` 硬限制）、`ff_poll`（保守未实现）不支持内核 fd 共存，改用 `ff_epoll_*`/`ff_kqueue`。
- **`ff_syscall_wrapper.c`**：`ff_socket` 双建 + 逐入口内核 fd 路由（含 R10 readv/writev/ioctl/dup/dup2）。

## 4. 关键头文件总览

| 头文件 | 行数 | 用途 |
|-------|------|------|
| `ff_api.h` | ~500 | 所有公开 API 声明 |
| `ff_config.h` | ~100 | 配置结构体定义 |
| `ff_event.h` | ~150 | kevent 结构和宏 |
| `ff_errno.h` | ~100 | 96 个 errno 映射 |
| `ff_host_interface.h` | 187 | OS 抽象层 (pthread/mmap) + `FF_KERNEL_COEXIST` 内核 fd 助手与 32 个 `ff_host_*` 桥声明（含 R9 set_v6only/kqueue_ctl/kqueue_poll、R10 readv/writev/ioctl/dup/dup2） |
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
# 使用 start.sh 指定 config.ini 配置文件启动（推荐方式）
bash start.sh -c config.ini -b ./myapp

# start.sh 会根据 config.ini 中的 lcore_mask 自动计算进程数，
# 依次启动主进程 (--proc-type=primary) 和从进程 (--proc-type=secondary)。
# 等效于:
#   ./myapp --conf config.ini --proc-type=primary --proc-id=0
#   ./myapp --conf config.ini --proc-type=secondary --proc-id=1
#   ...
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
