# F-Stack v1.26 第二层架构分析：接口定义与规范

**文档版本**: 1.0  
**分析日期**: 2026-03-20  
**覆盖范围**: F-Stack v1.26 公开 API、配置系统、开发规范（FreeBSD 15.0 移植；KBI/KPI delta 已捕获）  
**目标受众**: 应用开发者、系统集成工程师、性能优化人员

---

## 1. 公开 API 体系结构

### 1.1 API 概览

F-Stack 导出 **80+ 个公开符号**，分为以下几大类：

```
┌─────────────────────────────────────────────────┐
│      F-Stack 公开 API (ff_api.h 491行)         │
├─────────────────────────────────────────────────┤
│ 1. 生命周期管理 (3 个)                          │
│    ff_init / ff_run / ff_stop_run               │
│                                                 │
│ 2. Socket API (25+ 个)                         │
│    ff_socket / ff_bind / ff_listen / ff_accept │
│    ff_connect / ff_close / ff_dup / ff_dup2    │
│    ...                                          │
│                                                 │
│ 3. I/O 操作 (10+ 个)                           │
│    ff_read / ff_write / ff_readv / ff_writev   │
│    ff_send / ff_sendto / ff_sendmsg            │
│    ff_recv / ff_recvfrom / ff_recvmsg          │
│    ...                                          │
│                                                 │
│ 4. 事件多路复用 (5 个)                         │
│    ff_kqueue / ff_kevent / ff_kevent_do_each   │
│    ff_select / ff_poll                         │
│                                                 │
│ 5. Epoll 兼容层 (3 个)                         │
│    ff_epoll_create / ff_epoll_ctl / ff_epoll_wait
│                                                 │
│ 6. 控制操作 (10+ 个)                           │
│    ff_setsockopt / ff_getsockopt               │
│    ff_ioctl / ff_fcntl                         │
│    ...                                          │
│                                                 │
│ 7. 路由管理 (1 个)                             │
│    ff_route_ctl                                 │
│                                                 │
│ 8. 零拷贝 Mbuf (3 个)                          │
│    ff_zc_mbuf_get / ff_zc_mbuf_write           │
│    ff_zc_mbuf_read (暂未实现) / ...             │
│                                                 │
│ 9. 多线程支持 (2 个)                           │
│    ff_pthread_create / ff_pthread_join         │
│                                                 │
│ 10. 系统接口 (10+ 个)                          │
│     ff_gettimeofday / ff_clock_gettime         │
│     ff_log_open_set / ff_log / ff_vlog          │
│     ...                                         │
└─────────────────────────────────────────────────┘
```

### 1.2 六个主要头文件详解

#### **ff_api.h (491 行) - 主 API**

**初始化与启动**：
```c
int ff_init(int argc, char * const argv[]);
    // 初始化 F-Stack
    // 参数: DPDK 风格的命令行参数
    // 返回: 0 成功, -1 失败
    // 必须在主进程首先调用

void ff_run(loop_func_t loop, void *arg);
    // 启动主轮询循环
    // 参数: 用户回调函数、用户参数
    // 不返回 (除非 ff_stop_run() 调用)
    // 每个 lcore 会调用一次

void ff_stop_run(void);
    // 停止轮询循环
    // 安全关闭，等待所有报文处理完成
```

**Socket 操作 (POSIX 兼容)**：
```c
int ff_socket(int domain, int type, int protocol);
    // 创建套接字
    // domain: AF_INET (IPv4) 或 AF_INET6 (IPv6)
    // type: SOCK_STREAM (TCP) 或 SOCK_DGRAM (UDP)
    // 返回: 文件描述符 (>= 0)

int ff_bind(int sockfd, const struct linux_sockaddr *addr, socklen_t addrlen);
    // 绑定本地地址
    // addr: 指针指向地址结构体
    // 注意: 使用 struct linux_sockaddr，不是 FreeBSD 格式

int ff_listen(int sockfd, int backlog);
    // 监听连接 (仅 TCP)
    // backlog: 连接队列大小

int ff_accept(int sockfd, struct linux_sockaddr *addr, socklen_t *addrlen);
    // 接受连接 (仅 TCP)
    // 返回: 新连接的 fd

int ff_connect(int sockfd, const struct linux_sockaddr *addr, socklen_t addrlen);
    // 建立连接 (仅 TCP)
    // 返回: 0 成功, -1 失败 (非阻塞，可能返回 EINPROGRESS)

int ff_close(int sockfd);
    // 关闭套接字
    // 等待所有待发数据被发送
```

**I/O 操作 (非阻塞)**：
```c
ssize_t ff_read(int fd, void *buf, size_t nbytes);
    // 读取数据
    // 返回: > 0 读到字节数, 0 连接关闭, -1 出错
    // 非阻塞: 无数据时返回 -1 + errno=EAGAIN

ssize_t ff_write(int fd, const void *buf, size_t nbytes);
    // 写入数据
    // 返回: > 0 发送字节数, -1 缓冲满或出错
    // 特点: 缓冲满时返回 -1，不是部分发送
    // 应该监听 EVFILT_WRITE 事件处理

ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt);
    // 分散读 (scatter-gather)

ssize_t ff_writev(int fd, const struct iovec *iov, int iovcnt);
    // 分散写
    
ssize_t ff_send(int fd, const void *buf, size_t len, int flags);
ssize_t ff_sendto(int fd, const void *buf, size_t len, int flags,
                  const struct linux_sockaddr *to, socklen_t tolen);
ssize_t ff_sendmsg(int fd, const struct msghdr *msg, int flags);
    // 各种发送方式 (flags 支持 MSG_MORE 等)

ssize_t ff_recv(int fd, void *buf, size_t len, int flags);
ssize_t ff_recvfrom(int fd, void *buf, size_t len, int flags,
                    struct linux_sockaddr *from, socklen_t *fromlen);
ssize_t ff_recvmsg(int fd, struct msghdr *msg, int flags);
    // 各种接收方式
```

**事件多路复用 (Kqueue)**：
```c
int ff_kqueue(void);
    // 创建事件对象 (类似 epoll_create)
    // 返回: 事件对象 fd

int ff_kevent(int kq, const struct kevent *changelist, int nchanges,
              struct kevent *eventlist, int nevents,
              const struct timespec *timeout);
    // 注册事件和等待事件
    // changelist: 要注册的事件数组
    // eventlist: 返回已就绪的事件
    // timeout: NULL 阻塞, 0 非阻塞, > 0 超时等待
    // 返回: 返回的事件数

int ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges,
                      void *eventlist, int nevents,
                      const struct timespec *timeout,
                      void (*do_each)(void **, struct kevent *));
    // 便利函数: 内部调用 ff_kevent 并对每个事件回调 do_each

int ff_select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout);
    // select() 实现 (仅为了兼容)

int ff_poll(struct pollfd *fds, nfds_t nfds, int timeout);
    // poll() 实现 (仅为了兼容)
```

**Epoll 兼容层 (Linux API)**：
```c
int ff_epoll_create(int size);
    // 创建 epoll 对象 (实际调用 ff_kqueue)

int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
    // 注册/修改/删除 epoll 事件
    // op: EPOLL_CTL_ADD / EPOLL_CTL_MOD / EPOLL_CTL_DEL

int ff_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
    // 等待事件

// 支持 epoll 事件标志:
#define EPOLLIN   0x001      // 可读
#define EPOLLOUT  0x004      // 可写
#define EPOLLET   0x80000000 // 边缘触发 (EV_CLEAR)
#define EPOLLONESHOT 0x40000000 // 单次触发 (EV_ONESHOT)
```

**控制操作**：
```c
int ff_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);
    // 设置套接字选项
    // level: SOL_SOCKET / IPPROTO_IP / IPPROTO_TCP / ...

int ff_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);
    // 获取套接字选项

int ff_ioctl(int fd, unsigned long request, ...);
    // I/O 控制
    // 常用: FIONBIO (设置非阻塞), FIONREAD (查询可读字节)

int ff_fcntl(int fd, int cmd, ...);
    // 文件控制
    // 常用: F_SETFL O_NONBLOCK, F_GETFL

struct hostent * ff_gethostbyname(const char *name);
    // 域名解析 (仅基础实现)

struct hostent * ff_gethostbyname2(const char *name, int af);
    // 域名解析 (指定 AF_INET 或 AF_INET6)
```

**路由管理**：
```c
int ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
                 struct linux_sockaddr *dst, struct linux_sockaddr *gw,
                 struct linux_sockaddr *netmask);
    // 路由操作
    // req: FF_ROUTE_ADD / FF_ROUTE_DEL / FF_ROUTE_CHANGE
    // flag: FF_RTF_HOST / FF_RTF_GATEWAY
```

**零拷贝 Mbuf**：
```c
struct ff_mbuf * ff_mbuf_gethdr(void);
    // 获取 mbuf 头部

struct ff_mbuf * ff_mbuf_get(const void *data, uint16_t len);
    // 创建包含数据的 mbuf

void ff_mbuf_free(struct ff_mbuf *mbuf);
    // 释放 mbuf

ssize_t ff_mbuf_copydata(struct ff_mbuf *mbuf, uint16_t off,
                         uint16_t len, void *buf);
    // 从 mbuf 拷贝数据

// 零拷贝发送
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
    // 获取零拷贝 mbuf (0 成功，-1 失败)

ssize_t ff_zc_mbuf_write(int fd, struct ff_zc_mbuf *zm);
ssize_t ff_zc_mbuf_read(int fd, struct ff_zc_mbuf *zm);
    // 零拷贝 I/O  【注】ff_zc_mbuf_read 暂未实现，后续考虑支持
```

**日志接口**：
```c
#define FF_LOGTYPE_EAL         0
#define FF_LOGTYPE_MALLOC      1
#define FF_LOGTYPE_RING        2
#define FF_LOGTYPE_MEMPOOL     3
#define FF_LOGTYPE_USER1       20
#define FF_LOGTYPE_USER8       27

int ff_log_open_set(void);
    // 打开 F-Stack 日志文件（路径和级别均从 config.ini 读取）
    // 返回 0 成功，-1 失败

int ff_log_set_level(uint32_t logtype, uint32_t level);
    // 设置特定日志类型的级别

int ff_log(uint32_t level, uint32_t logtype, const char *format, ...);
    // 输出日志（level: FF_LOG_ERR 等；logtype: FF_LOGTYPE_USER1 等）

// 日志级别（值从 1 开始，0 为禁用）
#define FF_LOG_EMERG     1U
#define FF_LOG_ALERT     2U
#define FF_LOG_CRIT      3U
#define FF_LOG_ERR       4U
#define FF_LOG_WARNING   5U
#define FF_LOG_NOTICE    6U
#define FF_LOG_INFO      7U
#define FF_LOG_DEBUG     8U
```

**多线程支持**：
```c
int ff_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine)(void *), void *arg);
    // 创建线程

int ff_pthread_join(pthread_t thread, void **retval);
    // 等待线程结束
```

**系统接口**：
```c
int ff_gettimeofday(struct timeval *tv, struct timezone *tz);
    // 获取当前时间

int ff_clock_gettime(clockid_t clock_id, struct timespec *tp);
    // 高精度时间 (支持 CLOCK_REALTIME / CLOCK_MONOTONIC)
```

#### **ff_epoll.h (3 函数) - Epoll 兼容**

仅包装 ff_kqueue 为 epoll 接口，供 Linux 应用兼容性使用。

#### **ff_config.h (352 行) - 配置接口**

**核心结构体**：

```c
struct ff_config {
    char *filename;
  
    // DPDK 配置部分
    struct {
        char *proc_type;
        /* mask of enabled lcores */
        char *lcore_mask;         // [0x4] CPU 核心掩码 (十六进制)
        /* mask of current proc on all lcores */
        char *proc_mask;

        /* specify base virtual address to map. */
        char *base_virtaddr;

        /* allow processes that do not want to co-operate to have different memory regions */
        char *file_prefix;

        /* pci whiltelist */
        char *allow;

        int nb_channel;           // [0x8] 内存通道数
        int memory;               // [0xC] 预留内存 (MB)
        int no_huge;
        int nb_procs;
        int proc_id;
        int promiscuous;               // [0x10] 混杂模式
        int nb_vdev;
        int nb_bond;
        int numa_on;                   // [0x14] NUMA 支持
        int tso;
        int tx_csum_offoad_skip;
        int vlan_strip;
        int nb_vlan_filter;
        uint16_t vlan_filter_id[DPDK_MAX_VLAN_FILTER];
        int symmetric_rss;

        /* sleep x microseconds when no pkts incomming */
        unsigned idle_sleep;

        /* TX burst queue drain nodelay dalay time */
        unsigned pkt_tx_delay;

        /* list of proc-lcore */
        uint16_t *proc_lcore;

        int nb_ports;
        uint16_t max_portid;
        uint16_t *portid_list;

        // load dpdk log level
        uint16_t log_level;
        // MAP(portid => struct ff_port_cfg*)
        struct ff_port_cfg *port_cfgs;
        struct ff_vlan_cfg *vlan_cfgs;
        struct ff_vdev_cfg *vdev_cfgs;
        struct ff_bond_cfg *bond_cfgs;
        struct ff_rss_check_cfg *rss_check_cfgs;
    } dpdk;
    
    // KNI 配置
    struct {
        int enable;
        int console_packets_ratelimit;           // 速率限制 (QPS)
        int general_packets_ratelimit;
        int kernel_packets_ratelimit;
        char *kni_action;
        char *method;
        char *tcp_port;
        char *udp_port;
    } kni;

    struct {
        int level;
        const char *dir;
        void *f; /* FILE * */
    } log;
  
    // FreeBSD 启动参数
    struct {
        struct ff_freebsd_cfg *boot;
        struct ff_freebsd_cfg *sysctl;
        long physmem;
        int hz;                   // 时钟频率 (1000 = 1kHz)
        int fd_reserve;           // 预留 fd 数
        int mem_size;
    } freebsd;

    struct {
        uint16_t enable;
        uint16_t snap_len;
        uint32_t save_len;
        char*    save_path;
    } pcap;
};
```

#### **ff_event.h - Kevent 事件结构**

```c
struct kevent {
    uintptr_t ident;                     // 事件 ID (socket fd)
    int16_t filter;                      // 事件过滤器 (short，值为负数)
    uint16_t flags;                      // 事件标志
    uint32_t fflags;                     // 过滤器标志
    __int64_t data;                      // 数据 (就绪数/错误，固定 64 位)
    void *udata;                         // 用户数据指针
    __uint64_t ext[4];                   // FreeBSD 13/15 扩展字段（13.0 → 15.0 升级前后 KBI 不变；M2 verify-only）
};

// 支持的过滤器 (值为负数！)
#define EVFILT_READ     (-1)  // 套接字可读
#define EVFILT_WRITE    (-2)  // 套接字可写
#define EVFILT_AIO      (-3)  // 异步 I/O
#define EVFILT_VNODE    (-4)  // 文件系统事件
#define EVFILT_PROC     (-5)  // 进程事件
#define EVFILT_SIGNAL   (-6)  // 信号
#define EVFILT_TIMER    (-7)  // 定时器
// ... 还有 6 种，见 freebsd/sys/event.h

// 事件标志
#define EV_ADD      0x0001   // 添加事件
#define EV_DELETE   0x0002   // 删除事件
#define EV_ENABLE   0x0004   // 启用事件
#define EV_DISABLE  0x0008   // 禁用事件
#define EV_ONESHOT  0x0010   // 单次触发
#define EV_CLEAR    0x0020   // 自动清除 (边缘触发)
#define EV_EOF      0x8000   // 连接关闭

// 便利宏
#define EV_SET(kevp, a, b, c, d, e, f) do { \
        (kevp)->ident = (a); \
        (kevp)->filter = (b); \
        (kevp)->flags = (c); \
        (kevp)->fflags = (d); \
        (kevp)->data = (e); \
        (kevp)->udata = (f); \
    } while (0)
```

#### **ff_errno.h (96 错误码)**

提供 POSIX/FreeBSD 兼容的错误编号：

```c
#define ff_EPERM     1     // 操作不允许
#define ff_ENOENT    2     // 没有这样的文件或目录
#define ff_ECONNREFUSED  61  // 连接被拒绝
#define ff_ETIMEDOUT 60   // 连接超时
#define ff_ECONNRESET 54  // 连接重置
#define ff_EAGAIN    35    // 请重试
#define ff_EINPROGRESS 36 // 操作正在进行中
// ... 等等
```

#### **ff_log.h - 日志接口**

支持多种日志类型和级别的结构化日志系统。

---

## 2. 系统调用映射表

F-Stack 提供 Linux 兼容的系统调用接口，但底层依赖 FreeBSD 协议栈。关键映射关系：

### 2.1 Socket 操作映射

| 操作 | F-Stack API | POSIX 标准 | 主要差异 |
|-----|-----------|----------|--------|
| 创建 | ff_socket() | socket() | 地址格式: linux_sockaddr |
| 绑定 | ff_bind() | bind() | 非阻塞强制 |
| 监听 | ff_listen() | listen() | TCP only |
| 接受 | ff_accept() | accept() | 返回新连接 fd |
| 连接 | ff_connect() | connect() | 可能返回 EINPROGRESS |
| 关闭 | ff_close() | close() | 优雅关闭 |

### 2.2 I/O 操作映射

| 操作 | F-Stack API | POSIX 标准 | 主要差异 |
|-----|-----------|----------|--------|
| 读 | ff_read() | read() | 非阻塞，无数据返回 -1 |
| 写 | ff_write() | write() | 缓冲满返回 -1，不部分发送 |
| 分散读 | ff_readv() | readv() | 同上 |
| 分散写 | ff_writev() | writev() | 同上 |
| 发送 | ff_send() | send() | flags: MSG_MORE 等 |
| 接收 | ff_recv() | recv() | 同上 |
| 发送到 | ff_sendto() | sendto() | UDP only |
| 发送消息 | ff_sendmsg() | sendmsg() | 支持 msghdr 控制信息 |
| 接收自 | ff_recvfrom() | recvfrom() | UDP only |
| 接收消息 | ff_recvmsg() | recvmsg() | 支持 msghdr 控制信息 |

### 2.3 事件多路复用映射

| 操作 | F-Stack API | POSIX 标准 | 主要差异 |
|-----|-----------|----------|--------|
| 创建队列 | ff_kqueue() | epoll_create() | 使用 BSD kqueue |
| 注册事件 | ff_kevent() | epoll_ctl() | kevent 格式 |
| 等待事件 | ff_kevent() + ff_epoll_wait() | epoll_wait() | 支持 timeout |
| 遍历事件 | ff_kevent_do_each() | N/A | 便利函数 |

### 2.4 Socket 选项映射

#### **Linux SOL_SOCKET 选项 → FreeBSD 映射**

```c
#define LINUX_SO_REUSEADDR     2     → SO_REUSEADDR
#define LINUX_SO_TYPE          3     → SO_TYPE
#define LINUX_SO_ERROR         4     → SO_ERROR
#define LINUX_SO_DONTROUTE     5     → SO_DONTROUTE
#define LINUX_SO_BROADCAST     6     → SO_BROADCAST
#define LINUX_SO_SNDBUF        7     → SO_SNDBUF
#define LINUX_SO_RCVBUF        8     → SO_RCVBUF
#define LINUX_SO_KEEPALIVE    10     → SO_KEEPALIVE
#define LINUX_SO_OOBINLINE    11     → SO_OOBINLINE
#define LINUX_SO_REUSEPORT   15     → SO_REUSEPORT
```

#### **Linux IPPROTO_IP 选项 → FreeBSD 映射**

```c
#define LINUX_IP_TOS           1     → IP_TOS
#define LINUX_IP_TTL           2     → IP_TTL
#define LINUX_IP_HDRINCL       3     → IP_HDRINCL
#define LINUX_IP_OPTIONS       4     → IP_OPTIONS
#define LINUX_IP_ROUTER_ALERT  5     → IP_ROUTER_ALERT
#define LINUX_IP_RECVOPTS      6     → IP_RECVOPTS
#define LINUX_IP_RETOPTS       7     → IP_RETOPTS
#define LINUX_IP_MULTICAST_IF  32    → IP_MULTICAST_IF
#define LINUX_IP_MULTICAST_TTL 33    → IP_MULTICAST_TTL
```

#### **Linux IPPROTO_TCP 选项 → FreeBSD 映射**

```c
#define LINUX_TCP_NODELAY      1     → TCP_NODELAY
#define LINUX_TCP_MAXSEG       2     → TCP_MAXSEG
#define LINUX_TCP_CORK         3     → TCP_CORK
#define LINUX_TCP_KEEPIDLE     4     → TCP_KEEPIDLE
#define LINUX_TCP_KEEPINTVL    5     → TCP_KEEPINTVL
#define LINUX_TCP_KEEPCNT      6     → TCP_KEEPCNT
```

#### **Linux IOCTL → FreeBSD IOCTL 映射**

```c
#define LINUX_FIONBIO         0x5421    // 设置非阻塞
#define LINUX_FIONREAD        0x541B    // 查询可读字节
#define LINUX_SIOCGIFFLAGS    0x8913    // 获取网卡标志
#define LINUX_SIOCGIFADDR     0x8915    // 获取网卡 IP
#define LINUX_SIOCGIFNETMASK  0x891B    // 获取网卡掩码
```

---

## 3. 配置系统深度分析

### 3.1 配置文件结构 (config.ini)

F-Stack 使用 INI 格式配置文件，通过 `ff_load_config()` 加载：

```ini
# 示例配置
[dpdk]
# 硬件和 DPDK 基础配置
lcore_mask = 0xf              # 使用核心 0-3 (十六进制)
channel = 4                   # 内存通道数
memory = 4096                 # 预留内存 (MB)
promiscuous = 1               # 混杂模式
numa_on = 1                   # NUMA 支持

# 网卡配置
port_list = 0,1               # 使用网卡 0 和 1
nb_vdev = 0                   # 虚拟设备数
nb_bond = 0                   # bondding网卡数

# 性能调优
tso = 1                       # 启用 TSO (硬件分段)
vlan_strip = 1                # VLAN 硬件标签剥离
symmetric_rss = 0             # 双向 RSS 对称性
idle_sleep = 0                # 空闲时 sleep (微秒)
pkt_tx_delay = 100              # 包发送延迟 (关闭立即发)
enable_kni = 1                # 启用虚拟网卡

[port0]
# 网卡 0 的配置
addr = 10.0.0.1
netmask = 255.255.255.0
gateway = 10.0.0.254
broadcast = 10.0.0.255

# VIP (虚拟 IP，用于单机支持多IP)
vip_addr = 10.0.0.100; 10.0.0.101; 10.0.0.102

# IPv6 支持
addr6 = 2001:db8::1
prefix_len = 64
gateway6 = 2001:db8::ff

# 用于支持多网段IP时设置简单的策略路由
ipfw_pr = 10.0.0.100 255.255.255.0;192.168.0.0 255.255.255.0

# lcore 绑定 (可选)
lcore_list = 0,1

[port1]
# 网卡 1 的配置
addr = 192.168.1.1
netmask = 255.255.255.0
gateway = 192.168.1.254

[vlan<vlan id>]
# VLAN 配置 (优先级高于 [portN])
portid = 0
addr = 172.16.0.1
netmask = 255.255.0.0
gateway = 172.16.0.1
broadcast = 172.16.255.255

[kni]
# 虚拟网卡配置
enable=1
method=reject
# The format is same as port_list
tcp_port=80,443
udp_port=53
# KNI ratelimit value, default: 0, means disable ratelimit.
# example:
# The total speed limit for a single process entering the kni ring is 10,000 QPS,
# 1000 QPS for general packets, 9000 QPS for console packets (ospf/arp, etc.)
# The total speed limit for kni forwarding to the kernel is 20,000 QPS.
#console_packets_ratelimit=0
#general_packets_ratelimit=0
#kernel_packets_ratelimit=0

[stack]
kernel_coexist = 0           # 内核栈共存（仅在 FF_KERNEL_COEXIST=1 构建时生效）。
                             # 0=关（纯 F-Stack，默认），1=开（SOCK_KERNEL socket 同时走宿主内核栈）

[freebsd.boot]
# FreeBSD 启动时配置
hz = 100                     # 时钟频率 (Hz)
fd_reserve = 1204              # 预留文件描述符
kern.ipc.maxsockets = 1000000 # 最大 socket 数

[freebsd.sysctl]
# FreeBSD 运行时 sysctl 配置
kern.ipc.somaxconn = 32768     # socket 监听队列
net.inet.tcp.syncache.hashsize = 4096
net.inet.tcp.syncache.bucketlimit = 100

# TCP 算法
net.inet.tcp.cc.algorithm = cubic
net.inet.tcp.functions_default=freebsd    # freebsd/rack/bbr

# socket 缓冲 (关键性能参数)
net.inet.tcp.sendspace = 16384      # 发送缓冲 (字节)
net.inet.tcp.recvspace = 8192      # 接收缓冲

# TCP 特性
net.inet.tcp.sack.enable = 1        # SACK 选择性确认
net.inet.tcp.rfc1323 = 1            # 时间戳选项
net.inet.tcp.delayed_ack = 1        # 延迟确认高吞吐， 0则低延迟
```

### 3.2 配置优先级规则

```
配置优先级顺序 (从高到低):
1. VLAN 配置 ([vlanN]) - 如果定义则使用
2. 端口配置 ([portN])
3. 命令行参数 (例如 DPDK -l 选项)
4. 编译时默认值
5. 代码硬编码

含义: 如果同时定义 [port0] 和 [vlan0]，则 [vlan0] 生效，[port0] 被忽略
```

### 3.3 配置加载流程

```c
// ff_config.c
ff_load_config(argc, argv)
  ├─ 1. 解析命令行参数
  │     (例如 --config-file /path/config.ini)
  ├─ 2. 打开配置文件
  ├─ 3. 逐行解析 INI 格式
  │     [section] 标记
  │     key = value 对
  ├─ 4. 验证配置有效性
  │     (地址范围、核心数等)
  ├─ 5. 转换为 struct ff_config
  └─ 6. 生成 DPDK 参数数组
        (传给 rte_eal_init)
```

### 3.4 内核栈共存接口（`FF_KERNEL_COEXIST`，可选）

当库以 `make FF_KERNEL_COEXIST=1` 构建且 `config.ini [stack] kernel_coexist=1` 时，应用可把个别 socket 放到宿主 Linux 内核栈上，其余照常走 F-Stack 快路径 —— 全部在同一进程、同一事件循环内完成。该契约刻意保持小而增量（不改任何既有签名）：

**逐 socket 选栈标记**（定义在 `ff_api.h`，仅 `FF_KERNEL_COEXIST` 下）：

```c
#define SOCK_FSTACK 0x01000000   // 强制 F-Stack 用户态栈
#define SOCK_KERNEL 0x02000000   // 强制宿主 Linux 内核栈

int fk = ff_socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);  // 内核栈 socket
int ff = ff_socket(AF_INET, SOCK_STREAM | SOCK_FSTACK, 0);  // F-Stack socket
int du = ff_socket(AF_INET, SOCK_STREAM, 0);                // 双建（默认）
```

| `type` 标记 | `kernel_coexist=1` 时行为 | 返回 fd |
|-------------|---------------------------|---------|
| `SOCK_KERNEL`（无 `SOCK_FSTACK`） | 仅建宿主内核 socket | 受管内核 fd = `host_fd + 0x40000000` |
| `SOCK_FSTACK` | 仅建 F-Stack socket | F-Stack fd |
| 均无（默认） | **双建**：F-Stack + 配对宿主 socket | F-Stack fd（宿主 fd 存于 `ff_native_fd_map`） |

优先级：per-socket 标记 > `config.ini [stack] kernel_coexist` > F-Stack。未编译该宏时标记未定义，`ff_socket` 行为与此前完全一致。

**透明路由。** 所有标准 `ff_*` 调用都透明接受受管内核 fd：`ff_bind/listen/connect/accept[4]/close/read/write/recv*/send*/sendmsg/recvmsg/getpeername/getsockname/shutdown/setsockopt/getsockopt/fcntl`，以及 `ff_epoll_ctl/wait`。内部每个内核 fd 转发给薄 `ff_host_*` 宿主 libc 桥（`lib/ff_host_interface.c`）。**自 R10 起亦透明接受：** `ff_readv` / `ff_writev` / `ff_ioctl` / `ff_dup` / `ff_dup2`（内核 fd 经对应 `ff_host_*` 桥；`ff_ioctl` 用原始 Linux request；`ff_dup2` 混栈拒绝 `errno=EINVAL`）。完整设计与测试见 `docs/kernel_event_support_spec/`。

**R9 —— kqueue/kevent 共存 + IPv6。** 统一事件支持现已覆盖原生 `ff_kqueue` / `ff_kevent` 接口（此前仅 `ff_epoll_*`）：每个 kqueue 惰性配对一个宿主 epoll（共享 `ff_epoll_host_ep`，复用 `ff_epoll_pairs` 表）。`ff_kevent` 把内核/双栈 fd 的 `EVFILT_READ/WRITE` 注册进该宿主 epoll（内核-only 变更不下发 F-Stack kqueue），等待时先非阻塞轮询宿主 epoll 合成 `struct kevent`（`ident`=应用面 fd、`EV_EOF`↔`EPOLLHUP|ERR`）再合并 F-Stack kqueue 事件 —— 使纯 kqueue 应用（如 `example/main.c`）能感知内核侧 listener，实测 `curl 127.0.0.1:80`=200 size=438。内核 fd 经 kqueue 仅支持 `EVFILT_READ/WRITE`。IPv6 侧：双建 `AF_INET6` socket 的宿主对应 socket 被设 `IPV6_V6ONLY=1`（`ff_host_set_v6only`），使 `-DINET6` 构建以 v4+v6 同端口干净启动（修复此前宿主 IPv6 `errno=98 EADDRINUSE`）。

**R10 —— 残余入口共存。** `ff_readv`/`ff_writev`（内核 fd→`ff_host_readv/writev`，仿 read/write，连接 fd 单栈热路径）、`ff_ioctl`（内核 fd 用**原始 Linux request** 直传 `ff_host_ioctl`，不经 `linux2freebsd_ioctl`；双栈 fd 同驱动自 R10.1 起支持 `FIONBIO`/`FIOASYNC`（F-Stack 成功后用原始 Linux request 同步配对 host fd；`FIONREAD` 等 query 类不同驱动以免覆盖 argp））、`ff_dup`（内核 fd→`ff_host_dup`+encode）、`ff_dup2`（两端内核 fd→`ff_host_dup2`+encode；混栈拒绝 `errno=EINVAL`）。新增 5 个宿主桥 `ff_host_readv/writev/ioctl/dup/dup2`。已知限制：`ff_select`（encode 内核 fd 超 `FD_SETSIZE` 硬限制）/`ff_poll`（保守未实现）不支持内核 fd 共存 —— 改用 `ff_epoll_*`/`ff_kqueue`。

---

## 4. 多进程和多线程接口

### 4.1 多进程模型 (Primary-Secondary)

F-Stack 采用 DPDK 的 Primary-Secondary 进程模型：

#### **主进程 (Primary Process)**

```c
// 启动时命令行设置
proc_type=primary proc_id=0

ff_init(argc, argv)
  ├─ 初始化 DPDK EAL (rte_eal_init)
  │   ├─ 申请 hugepage 内存
  │   ├─ 创建共享内存映射
  │   └─ 初始化 core 0
  ├─ 创建 mempool (所有进程共享)
  ├─ 初始化网卡 (rte_eth_dev_configure)
  ├─ 启动网卡 (rte_eth_dev_start)
  └─ 进入轮询循环 (ff_run)
       ├─ 接收/处理报文
       └─ 处理来自 worker 的 IPC 消息
```

#### **从进程 (Secondary Process)**

```c
// 启动时命令行设置
proc_type=secondary proc_id=1  # 不同从进程使用不同 ID

ff_init(argc, argv)
  ├─ 连接到 DPDK 共享内存 (由主进程创建)
  │   ├─ 映射 hugepage 内存
  │   ├─ 连接到 mempool
  │   └─ 访问网卡配置
  ├─ 初始化本地 FreeBSD 栈实例
  └─ 进入轮询循环 (ff_run)
       ├─ 接收/处理属于本进程的报文 (via RSS)
       └─ 可选: 发送 IPC 消息给主进程
```

#### **进程启动脚本示例**

```bash
# 使用 F-Stack 自带的 start.sh 启动（推荐方式）
# start.sh 参数说明:
#   -c [conf]   配置文件路径 (默认 config.ini)
#   -b [bin]    应用程序路径 (默认 ./example/helloworld)
#   -o [args]   传递给应用的额外参数

# 示例: 使用 config.ini 启动自定义应用
bash start.sh -c config.ini -b ./app

# start.sh 会自动完成以下工作:
# 1. 读取 config.ini 中的 lcore_mask，计算需要启动的进程数
# 2. 启动主进程: ./app --conf config.ini --proc-type=primary --proc-id=0
# 3. 等待 5 秒后依次启动从进程:
#    ./app --conf config.ini --proc-type=secondary --proc-id=1
#    ./app --conf config.ini --proc-type=secondary --proc-id=2
#    ...

# 如需传递额外参数给应用:
bash start.sh -c config.ini -b ./app -o "--extra-arg value"
```

### 4.2 进程间通信 (IPC)

F-Stack 通过 DPDK Ring 实现高效的进程间消息传递：

#### **IPC 消息结构**

```c
struct ff_msg {
    uint32_t msg_type;           // 消息类型
    uint32_t msg_id;             // 消息 ID (用于配对请求/响应)
    uint32_t msg_len;            // 消息长度
    
    union {
        // 消息类型
        struct {
            uint32_t sysctl_id;  // sysctl 参数 ID
            uint32_t value;      // 参数值
        } sysctl;
        
        struct {
            uint32_t route_cmd;  // ROUTE_CMD_ADD/DEL/CHANGE
            struct sockaddr addr;
            struct sockaddr mask;
        } route;
        
        struct {
            uint64_t tx_packets;
            uint64_t rx_packets;
            uint64_t tx_bytes;
            uint64_t rx_bytes;
        } traffic;
        
        char data[256];          // 通用数据
    } msg_body;
};

// 消息类型
#define FF_MSG_SYSCTL       1
#define FF_MSG_IOCTL        2
#define FF_MSG_ROUTE        3
#define FF_MSG_TOP          4
#define FF_MSG_TRAFFIC      5
#define FF_MSG_NGCTL        6
#define FF_MSG_IPFW_CTL     7
#define FF_MSG_KNICTL       8
```

#### **IPC 通信示例**

```c
// 从进程向主进程查询参数

// 步骤 1: 连接到主进程
ff_ipc_init();  // 初始化 IPC (连接到主进程的 Ring)

// 步骤 2: 分配消息
struct ff_msg *msg = ff_ipc_msg_alloc();

// 步骤 3: 填充请求
msg->msg_type = FF_MSG_TRAFFIC;
msg->msg_id = 1;  // 请求 ID

// 步骤 4: 发送给主进程
ff_ipc_send(msg);

// 步骤 5: 等待响应 (主进程处理后回复)
struct ff_msg *retmsg = NULL;
ff_ipc_recv(&retmsg, FF_MSG_TRAFFIC);

// 步骤 6: 读取响应
printf("TX packets: %lu\n", retmsg->msg_body.traffic.tx_packets);

// 步骤 7: 释放消息
ff_ipc_msg_free(msg);
ff_ipc_msg_free(retmsg);
```

### 4.3 多线程接口

F-Stack 提供基础多线程支持，但线程之间**不共享** socket：

```c
// 创建线程
pthread_t thread;
int ret = ff_pthread_create(&thread, NULL, thread_func, arg);

// 每个线程必须:
1. 调用 ff_init() - 创建独立的 FreeBSD 栈实例
2. 获取独立的 lcore 编号
3. 使用 ff_run() 进入轮询循环

// 线程安全性
✓ 同一线程内的 socket 操作安全
✗ socket 不能跨线程共享
✗ ff_run() 后不能创建新线程
```

**示例 - 多线程应用**：

```c
struct thread_arg {
    int thread_id;
    const char *bind_addr;
    int bind_port;
};

void *thread_func(void *arg) {
    struct thread_arg *ta = (struct thread_arg *)arg;
    
    // 线程初始化
    ff_init(0, NULL);  // 获取独立 lcore
    
    // 创建本线程的 socket
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ta->bind_port),
        .sin_addr.s_addr = inet_addr(ta->bind_addr)
    };
    
    ff_bind(sockfd, (struct linux_sockaddr *)&addr, sizeof(addr));
    ff_listen(sockfd, 128);
    
    // 进入轮询
    ff_run(my_loop, (void *)(intptr_t)sockfd);
    
    return NULL;
}

int main() {
    // 启动多个线程
    pthread_t threads[4];
    struct thread_arg args[4] = {
        {0, "10.0.0.1", 80},
        {1, "10.0.0.2", 80},
        {2, "10.0.0.3", 80},
        {3, "10.0.0.4", 80}
    };
    
    for (int i = 0; i < 4; i++) {
        ff_pthread_create(&threads[i], NULL, thread_func, &args[i]);
    }
    
    for (int i = 0; i < 4; i++) {
        ff_pthread_join(threads[i], NULL);
    }
    
    return 0;
}
```

---

## 5. 应用开发规范

### 5.1 开发三大模式

#### **模式 1: Kqueue (推荐)**

```c
#include <ff_api.h>

int main_loop(void *arg) {
    // 事件就绪处理函数
    // 每个轮询周期调用一次
    // 必须在 100μs 内返回
    
    int kq = (int)(intptr_t)arg;
    struct kevent events[64];
    
    int nevents = ff_kevent(kq, NULL, 0, events, 64, NULL);
    
    for (int i = 0; i < nevents; i++) {
        if (events[i].flags & EV_EOF) {
            // 连接关闭
            ff_close((int)events[i].ident);
        } else if (events[i].filter == EVFILT_READ) {
            // 可读事件
            char buf[4096];
            ssize_t n = ff_read((int)events[i].ident, buf, sizeof(buf));
            // 处理读取的数据
        } else if (events[i].filter == EVFILT_WRITE) {
            // 可写事件
            // write 缓冲有空间，可以继续发送
        }
    }
    
    return 0;  // 继续循环
}

int main(int argc, char *argv[]) {
    ff_init(argc, argv);
    
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {...};
    ff_bind(sockfd, (struct linux_sockaddr *)&addr, sizeof(addr));
    ff_listen(sockfd, 128);
    
    int kq = ff_kqueue();
    struct kevent kev;
    EV_SET(&kev, sockfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    ff_kevent(kq, &kev, 1, NULL, 0, NULL);
    
    // 进入轮询循环
    ff_run(main_loop, (void *)(intptr_t)kq);
    
    return 0;
}
```

#### **模式 2: Epoll (Linux 兼容)**

```c
#include <ff_api.h>

int main_loop(void *arg) {
    int epfd = (int)(intptr_t)arg;
    struct epoll_event events[64];
    
    int nevents = ff_epoll_wait(epfd, events, 64, 0);  // 非阻塞
    
    for (int i = 0; i < nevents; i++) {
        int fd = events[i].data.fd;
        
        if (events[i].events & EPOLLIN) {
            // 可读
            char buf[4096];
            ff_read(fd, buf, sizeof(buf));
        }
        
        if (events[i].events & EPOLLOUT) {
            // 可写
            ff_write(fd, data, len);
        }
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    ff_init(argc, argv);
    
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    // ... bind/listen ...
    
    int epfd = ff_epoll_create(0);
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = sockfd;
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    
    ff_run(main_loop, (void *)(intptr_t)epfd);
    
    return 0;
}
```

### 5.2 关键开发规范

**规则 1: 强制非阻塞**
```c
int flags = 1;
ff_ioctl(sockfd, FIONBIO, &flags);  // 必须设置!
```

**规则 2: Main Loop 时间限制**

```c
// ✗ 错误: 阻塞太长
int main_loop(void *arg) {
    sleep(1);  // 阻塞 1 秒!
    return 0;
}

// ✓ 正确: 控制在 100μs 内
int main_loop(void *arg) {
    // 处理已就绪的事件 (< 100μs)
    ff_kevent(...);  // 非阻塞查询
    return 0;
}
```

**规则 3: Write 缓冲管理**
```c
// ✗ 错误: 假设 ff_write 总是成功
ssize_t n = ff_write(fd, data, len);
if (n < 0) {
    // 缓冲满，数据丢失!
    perror("write failed");
}

// ✓ 正确: 监听 EVFILT_WRITE 事件
ssize_t n = ff_write(fd, data, len);
if (n < 0) {
    // 监听 EVFILT_WRITE，稍后重试
    struct kevent kev;
    EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
    ff_kevent(kq, &kev, 1, NULL, 0, NULL);
}
```

**规则 4: 连接关闭处理**
```c
// ✗ 错误: 忘记检查 EV_EOF
if (events[i].filter == EVFILT_READ) {
    ff_read(fd, buf, size);  // 已关闭连接上读取，可能出错
}

// ✓ 正确: 先检查 EV_EOF
if (events[i].flags & EV_EOF) {
    ff_close(fd);
} else if (events[i].filter == EVFILT_READ) {
    ff_read(fd, buf, size);
}
```

**规则 5: Socket 线程隔离**
```c
// ✗ 错误: 跨线程共享 socket
int sockfd = ff_socket(...);  // 主线程创建
ff_pthread_create(&tid, NULL, worker_thread, (void *)(intptr_t)sockfd);

// ✓ 正确: 每个线程创建自己的 socket
void *worker_thread(void *arg) {
    int sockfd = ff_socket(...);  // 线程内创建
    // 使用 sockfd
}
```

### 5.3 常见陷阱与解决方案

| 陷阱 | 症状 | 根本原因 | 解决方案 |
|-----|------|--------|--------|
| 未设 FIONBIO | 死锁/延迟 | socket 阻塞模式 | `ff_ioctl(fd, FIONBIO, &on)` |
| Main loop 太长 | 丢包/延迟 | 轮询被阻塞 | 控制 loop 函数 < 100μs |
| 跨线程共享 socket | 崩溃/竞态 | FreeBSD 栈非线程安全 | 线程隔离 socket |
| 忽略 EV_EOF | fd 泄漏/异常 | 连接关闭未处理 | 检查 `ev.flags & EV_EOF` |
| Write 缓冲满不处理 | 数据丢失 | ff_write 返回 -1 | 监听 EVFILT_WRITE 重试 |
| 配置文件不存在 | 初始化失败 | 路径错误 | 检查 config.ini 位置 |
| 内存不足 (hugepage) | 初始化失败 | hugepage 申请失败 | `sysctl vm.nr_hugepages=2048` |
| CPU 隔离不充分 | 性能下降 | CPU 被其他进程占用 | 使用 CPU 亲和性工具 |

### 5.4 性能优化建议

**1. 调整 Socket 缓冲**
```ini
# config.ini
[freebsd.sysctl]
net.inet.tcp.sendspace = 65536    # 64KB 发送缓冲
net.inet.tcp.recvspace = 65536    # 64KB 接收缓冲
```

**2. 启用 TSO (TCP 段卸载)**
```ini
[dpdk]
tso = 1  # 启用硬件 TSO
```

**3. 优化包发送延迟**
```ini
[dpdk]
pkt_tx_delay = 0  # 立即发送，不等待 batch
```

**4. 启用对称 RSS**
```ini
[dpdk]
symmetric_rss = 1  # 双向连接到同一队列
```

**5. TCP 算法选择**
```ini
[freebsd.sysctl]
# 高延迟网络: bbr (瓶颈带宽和往返时间)
# hz=1000000
# net.inet.tcp.functions_default=bbr
# net.inet.tcp.hpts.minsleep=250
# net.inet.tcp.hpts.maxsleep=51200

# 低延迟网络: cubic (默认，平衡)
# hz=100
# net.inet.tcp.functions_default=freebsd
# net.inet.tcp.cc.algorithm = cubic

# 特定场景: rack (TCP 选择性确认)
# hz=1000000
# net.inet.tcp.functions_default=rack
# net.inet.tcp.hpts.minsleep=250
# net.inet.tcp.hpts.maxsleep=51200
```

---

## 6. 工具与集成接口

### 6.1 IPC 工具列表

| 工具 | 用途 | 底层消息类型 | 示例命令 |
|-----|------|------------|--------|
| **top** | 实时 CPU 统计 | FF_TOP | `top -p <pid>` |
| **sysctl** | 参数查询/修改 | FF_SYSCTL | `sysctl net.inet.tcp.sendspace` |
| **ifconfig** | 网卡状态 | 直接读配置 | `ifconfig -a` |
| **route** | 路由表管理 | FF_ROUTE | `route add/del` |
| **netstat** | 网络统计 | FF_TRAFFIC | `netstat -s` |
| **arp** | ARP 表查询 | 直接读内存 | `arp -a` |
| **ipfw** | 防火墙规则 | FF_IPFW_CTL | `ipfw add ...` |
| **knictl** | 虚拟网卡控制 | FF_KNICTL | `knictl set-rate ...` |
| **traffic** | 流量统计导出 | FF_TRAFFIC | `traffic -p <proc_id> -d <secs>` |
| **ndp** | IPv6 邻居发现 | ioctl (SIOCGNBRINFO_IN6) | `ndp -C <proc_id> -a` |
| **ngctl** | Netgraph 控制 | FF_NGCTL | `ngctl -p <proc_id> list` |

### 6.2 应用集成接口

**直接调用模式**：应用直接链接 libfstack.a 并调用 ff_* API。

**LD_PRELOAD 模式**：应用预加载 `libff_syscall.so`（由 `adapter/syscall/` 构建），与
独立的 `fstack` 实例**以两个进程方式运行**，两者通过 Hugepage 共享内存通信；默认走
信号量路径，置 `FF_USE_RING_IPC=1` 后切换为基于 DPDK SPSC `rte_ring` 的 lock-free
路径。**`fstack` 实例必须在 LD_PRELOAD 应用之前启动**。

```bash
# 先启动 fstack 实例（可启动多个）
./fstack --conf config.ini --proc-type=primary --proc-id=0 &

# Nginx 集成
LD_PRELOAD=/path/to/libff_syscall.so /usr/sbin/nginx -g "daemon off;"

# Redis 集成
LD_PRELOAD=/path/to/libff_syscall.so /usr/bin/redis-server /etc/redis.conf

# 自定义应用
LD_PRELOAD=/path/to/libff_syscall.so ./my_app
```

被劫持的 POSIX 入口包括：`socket / bind / connect / accept / accept4 / listen /
close / read / write / send / sendto / sendmsg / recv / recvfrom / recvmsg /
__read_chk / __recv_chk / __recvfrom_chk / ioctl / epoll_create|ctl|wait / fork`。

常用运行时 / 编译开关：

| 开关 | 默认 | 作用 |
|---|---|---|
| `FF_KERNEL_EVENT` | 关 | 并行转发内核 fd 给宿主 epoll |
| `FF_MULTI_SC` | 关 | SO_REUSEPORT 风格的多 sc，每 worker fd 一个 sc |
| `FF_USE_RING_IPC` | 关 | 将 IPC 切到 lock-free DPDK SPSC ring（默认含 v3.4 优化） |

完整设计、支持模式、环境变量、性能数据与已知限制详见 `adapter/syscall/README.md`。

---

## 总结

**关键接口特性**：
1. **POSIX 兼容** - Linux 应用可无修改迁移
2. **非阻塞强制** - 所有 I/O 操作都非阻塞
3. **事件驱动** - Kqueue/Epoll/Select 多种模式
4. **多进程支持** - Primary-Secondary 模型通过 IPC 通信
5. **硬件加速** - 充分利用 RSS/TSO/Checksum 等卸载

**开发路径**：
1. 编写 main_loop 回调处理事件
2. 注册 socket 到 kqueue/epoll
3. 调用 ff_run() 进入轮询
4. 使用 IPC 工具进行运维管理

---

**相关文档**：
- [第一层：系统总体架构](./F-Stack_Architecture_Layer1_System_Overview.md)
- [第三层：函数级索引](./F-Stack_Architecture_Layer3_Function_Index.md)
- [知识库总结](./F-Stack_Knowledge_Base_Summary.md)
