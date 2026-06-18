# F-Stack v1.26 第三层架构分析：函数级索引与数据模型

**文档版本**: 1.0  
**分析日期**: 2026-03-20  
**覆盖范围**: F-Stack v1.26 导出函数、数据结构、线程安全性（FreeBSD 15.0 移植；runtime-fix 落点函数已分类）  
**目标受众**: 内核开发者、性能分析师、调试工程师

---

## 1. 完整函数导出清单

### 1.1 80+ 导出函数分类总览

F-Stack 通过 `/data/workspace/f-stack/lib/ff_api.symlist` 定义所有公开符号。以下是完整清单按功能分类：

#### **生命周期管理 (3 个)**

```c
int ff_init(int argc, char * const argv[])
    // 初始化 F-Stack 库
    // 必须首先调用，仅主进程调用
    // 参数: DPDK EAL 格式的命令行参数
    // 返回: 0 成功, -1 失败
    // 线程安全: 否 (仅在初始化时调用)

void ff_run(loop_func_t loop, void *arg)
    // 启动主轮询循环
    // 每个 lcore 会调用一次
    // 参数: 用户回调函数指针, 回调参数
    // 不返回 (除非 ff_stop_run() 被调用)
    // 线程安全: 否 (阻塞直到停止)

void ff_stop_run(void)
    // 停止轮询循环
    // 可从任何线程调用
    // 安全关闭，等待所有报文处理完成
    // 线程安全: 是 (原子操作)
```

#### **Socket 生命周期 (12 个)**

```c
int ff_socket(int domain, int type, int protocol)
    // 创建套接字
    // domain: AF_INET(=2) / AF_INET6(=10 Linux/28 FreeBSD)
    // type: SOCK_STREAM(1) / SOCK_DGRAM(2) / SOCK_RAW(3)
    // protocol: 0 (自动), IPPROTO_TCP(6), IPPROTO_UDP(17)
    // 返回: fd >= 0, -1 on error
    // 线程安全: 是 (per-thread socket table)

int ff_bind(int sockfd, const struct linux_sockaddr *addr, socklen_t addrlen)
    // 绑定本地地址
    // addr: 指向 sockaddr 结构体的指针
    // addrlen: 地址结构体大小
    // 返回: 0 成功, -1 失败 + errno
    // 线程安全: 是 (fd 隔离)

int ff_listen(int sockfd, int backlog)
    // 标记 socket 为 listening 状态 (TCP only)
    // backlog: 未接受连接队列大小
    // 返回: 0 成功, -1 失败
    // 线程安全: 是

int ff_accept(int sockfd, struct linux_sockaddr *addr, socklen_t *addrlen)
    // 接受新连接 (TCP only)
    // 返回: 新 socket fd, -1 on error
    // 返回地址到 addr 结构体
    // 线程安全: 是

int ff_accept4(int sockfd, struct linux_sockaddr *addr, socklen_t *addrlen, int flags)
    // ff_accept() 增强版，支持 flags (如 SOCK_NONBLOCK)
    // 线程安全: 是

int ff_connect(int sockfd, const struct linux_sockaddr *addr, socklen_t addrlen)
    // 建立连接 (TCP only)
    // 非阻塞: 可能返回 -1 + errno=EINPROGRESS
    // 监听 EVFILT_WRITE 检测连接完成
    // 返回: 0 成功, -1 失败
    // 线程安全: 是

int ff_close(int sockfd)
    // 关闭套接字
    // 等待所有待发数据被发送，优雅关闭
    // 返回: 0 成功, -1 失败
    // 线程安全: 是

int ff_shutdown(int sockfd, int how)
    // 关闭通信的一个或两个方向
    // how: SHUT_RD(0), SHUT_WR(1), SHUT_RDWR(2)
    // 线程安全: 是

int ff_dup(int oldfd)
    // 复制文件描述符 (返回最小的空 fd)
    // 线程安全: 是

int ff_dup2(int oldfd, int newfd)
    // 复制文件描述符 (指定目标 fd)
    // 线程安全: 是

int ff_dup3(int oldfd, int newfd, int flags)
    // ff_dup2() 增强版，支持 flags
    // 线程安全: 是

int ff_getpeername(int sockfd, struct linux_sockaddr *addr, socklen_t *addrlen)
    // 获取对端地址
    // 线程安全: 是
```

#### **数据 I/O 操作 (13 个)**

```c
ssize_t ff_read(int fd, void *buf, size_t nbytes)
    // 读取数据
    // 返回: > 0 实际读取字节数, 0 EOF, -1 错误
    // 错误时 errno 设置
    // 非阻塞: 无数据时返回 -1 + EAGAIN
    // 线程安全: 是

ssize_t ff_write(int fd, const void *buf, size_t nbytes)
    // 写入数据
    // 返回: > 0 实际发送字节数, -1 缓冲满或错误
    // 特点: 缓冲满时返回 -1，不是部分发送!
    // 应监听 EVFILT_WRITE 事件后重试
    // 线程安全: 是

ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt)
    // 分散读 (scatter-gather read)
    // iov: iovec 数组指针
    // iovcnt: iovec 数组元素个数
    // 线程安全: 是

ssize_t ff_writev(int fd, const struct iovec *iov, int iovcnt)
    // 分散写
    // 线程安全: 是

ssize_t ff_pread(int fd, void *buf, size_t nbytes, off_t offset)
    // 从指定偏移读取 (仅文件)
    // 线程安全: 是

ssize_t ff_pwrite(int fd, const void *buf, size_t nbytes, off_t offset)
    // 从指定偏移写入 (仅文件)
    // 线程安全: 是

ssize_t ff_send(int fd, const void *buf, size_t len, int flags)
    // 发送数据 (TCP/UDP)
    // flags: MSG_MORE (不立即发送), MSG_OOB (带外数据)
    // 线程安全: 是

ssize_t ff_sendto(int fd, const void *buf, size_t len, int flags,
                  const struct linux_sockaddr *to, socklen_t tolen)
    // 发送数据到指定地址 (UDP only)
    // 线程安全: 是

ssize_t ff_sendmsg(int fd, const struct msghdr *msg, int flags)
    // 发送消息 (使用 msghdr 结构体，支持控制信息)
    // 线程安全: 是

ssize_t ff_recv(int fd, void *buf, size_t len, int flags)
    // 接收数据 (TCP/UDP)
    // 线程安全: 是

ssize_t ff_recvfrom(int fd, void *buf, size_t len, int flags,
                    struct linux_sockaddr *from, socklen_t *fromlen)
    // 接收数据和来源地址 (UDP)
    // 线程安全: 是

ssize_t ff_recvmsg(int fd, struct msghdr *msg, int flags)
    // 接收消息 (支持控制信息)
    // 线程安全: 是

ssize_t ff_recvfrom_timeout(int fd, void *buf, size_t len, int flags,
                           struct linux_sockaddr *from, socklen_t *fromlen,
                           int timeout)
    // ff_recvfrom() 增强版，支持超时
    // 线程安全: 是
```

#### **事件多路复用 (7 个)**

```c
int ff_kqueue(void)
    // 创建 kqueue 事件对象
    // 返回: kqueue fd, -1 on error
    // 线程安全: 是

int ff_kevent(int kq, const struct kevent *changelist, int nchanges,
              struct kevent *eventlist, int nevents,
              const struct timespec *timeout)
    // 注册事件并等待事件就绪
    // changelist: 要注册的事件数组 (可 NULL)
    // eventlist: 返回的就绪事件数组
    // timeout: NULL 阻塞, 0 非阻塞, > 0 超时
    // 返回: 就绪事件个数, -1 on error
    // 线程安全: 是

void ff_kevent_do_each(int kq, struct kevent *changelist, int nchanges,
                       void (*callback)(struct kevent *kev, void *arg),
                       void *arg)
    // 便利函数: 一次调用 kevent 并对每个事件调用 callback
    // 线程安全: 是

int ff_select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout)
    // select() 实现 (兼容性，不推荐)
    // 线程安全: 是

int ff_poll(struct pollfd *fds, nfds_t nfds, int timeout)
    // poll() 实现 (兼容性，不推荐)
    // timeout: -1 阻塞, 0 非阻塞, > 0 毫秒
    // 线程安全: 是

// Epoll 兼容 (3 个)
int ff_epoll_create(int size)
    // 创建 epoll 对象 (实际调用 ff_kqueue)
    // 线程安全: 是

int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
    // 注册/修改/删除 epoll 事件
    // op: EPOLL_CTL_ADD(1) / EPOLL_CTL_MOD(2) / EPOLL_CTL_DEL(3)
    // 线程安全: 是

int ff_epoll_wait(int epfd, struct epoll_event *events, 
                  int maxevents, int timeout)
    // 等待 epoll 事件
    // timeout: -1 阻塞, 0 非阻塞, > 0 毫秒
    // 线程安全: 是
```

#### **Socket 选项操作 (6 个)**

```c
int ff_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
    // 设置 socket 选项
    // level: SOL_SOCKET / IPPROTO_IP / IPPROTO_TCP / IPPROTO_IPV6
    // optname: SO_* / IP_* / TCP_* 常量
    // 线程安全: 是

int ff_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
    // 获取 socket 选项值
    // 线程安全: 是

int ff_ioctl(int fd, unsigned long request, ...)
    // I/O 控制 (可变参数)
    // 常用: FIONBIO (非阻塞), FIONREAD (可读字节)
    // 线程安全: 是

int ff_fcntl(int fd, int cmd, ...)
    // 文件控制 (可变参数)
    // cmd: F_GETFL / F_SETFL / F_GETFD / F_SETFD
    // 线程安全: 是

struct hostent * ff_gethostbyname(const char *name)
    // 域名 → IPv4 地址 (基础实现)
    // 返回: hostent 指针, NULL on error
    // 线程安全: 否 (返回静态缓冲，需 mutex)

struct hostent * ff_gethostbyname2(const char *name, int af)
    // 域名 → 地址 (支持 AF_INET / AF_INET6)
    // 线程安全: 否
```

#### **路由管理 (1 个)**

```c
int ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
                 struct linux_sockaddr *dst, struct linux_sockaddr *gw,
                 struct linux_sockaddr *netmask)
    // 路由表操作
    // req:  FF_ROUTE_ADD / FF_ROUTE_DEL / FF_ROUTE_CHANGE
    // flag: FF_RTF_HOST / FF_RTF_GATEWAY
    // dst: 目标网络地址
    // gw: 网关地址
    // netmask: 子网掩码
    // 返回: 0 成功, -1 失败
    // 线程安全: 是
```

#### **Zero-Copy Mbuf (5 个)**

```c
struct ff_mbuf * ff_mbuf_gethdr(void)
    // 获取空 mbuf 头部
    // 返回: mbuf 指针, NULL on error
    // 线程安全: 是 (内存池无锁分配)

struct ff_mbuf * ff_mbuf_get(const void *data, uint16_t len)
    // 创建包含数据的 mbuf
    // 返回: 新 mbuf, NULL on error
    // 线程安全: 是

void ff_mbuf_free(struct ff_mbuf *mbuf)
    // 释放 mbuf (返回内存池)
    // 线程安全: 是

ssize_t ff_mbuf_copydata(struct ff_mbuf *mbuf, uint16_t off,
                         uint16_t len, void *buf)
    // 从 mbuf 拷贝数据到缓冲区
    // off: 偏移量 (字节)
    // len: 要拷贝的长度
    // 返回: 实际拷贝的字节数, -1 on error
    // 线程安全: 是

// Zero-Copy 发送/接收 (3 个)
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len)
    // 分配零拷贝 mbuf 链（调用方提供已分配的 struct ff_zc_mbuf）
    // m: 调用方分配的 ff_zc_mbuf 指针（不能为 NULL）
    // len: 要分配的 mbuf 链总长度
    // 返回: 0 成功, -1 失败
    // 线程安全: 是

int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len)
    // 零拷贝写入数据到 mbuf 链（调用方再用 ff_write 发送）
    // 需先调用 ff_zc_mbuf_get
    // 线程安全: 是

int ff_zc_mbuf_read(struct ff_zc_mbuf *m, const char *data, int len)
    // 零拷贝读取（暂未实现，后续考虑支持）
    // 线程安全: 是
```

#### **多线程支持 (2 个)**

```c
int ff_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine)(void *), void *arg)
    // 创建线程 (包装 pthread_create)
    // 每个线程必须独立 ff_init() 和 ff_run()
    // 线程安全: 是

int ff_pthread_join(pthread_t thread, void **retval)
    // 等待线程结束 (包装 pthread_join)
    // 线程安全: 是
```

#### **日志和诊断 (8 个)**

```c
int ff_log_open_set(void)
    // 打开 F-Stack 日志文件（路径和级别均从 config.ini 读取）
    // 返回: 0 成功, -1 失败
    // 线程安全: 否 (需外部同步)

int ff_log_reset_stream(void *f)
    // 重置日志输出流（f 为 FILE *，由 APP 自行管理）
    // 用于将日志重定向到自定义 FILE 流
    // 线程安全: 否

void ff_log_set_global_level(uint32_t level)
    // 设置全局日志级别
    // 线程安全: 否

int ff_log_set_level(uint32_t logtype, uint32_t level)
    // 设置特定日志类型的级别
    // logtype: FF_LOGTYPE_* (如 FF_LOGTYPE_USER1)
    // 线程安全: 否

int ff_log(uint32_t level, uint32_t logtype, const char *format, ...)
    // 输出日志消息 (printf 风格)
    // level: FF_LOG_* (如 FF_LOG_INFO)
    // logtype: FF_LOGTYPE_* (如 FF_LOGTYPE_USER1)
    // 线程安全: 是 (每个线程独立缓冲)

int ff_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap)
    // ff_log() 的 va_list 版本
    // 线程安全: 是

void ff_log_close(void)
    // 关闭日志系统
    // 线程安全: 否
```

#### **系统接口 (8 个)**

```c
int ff_gettimeofday(struct timeval *tv, struct timezone *tz)
    // 获取当前时间 (壁钟时间)
    // 精度: 微秒 (μs)
    // 返回: 0 成功, -1 失败
    // 线程安全: 是

int ff_clock_gettime(clockid_t clock_id, struct timespec *tp)
    // 高精度时间查询
    // clock_id: CLOCK_REALTIME / CLOCK_MONOTONIC
    // 精度: 纳秒 (ns)
    // 线程安全: 是

int ff_usleep(unsigned int useconds)
    // 微秒级 sleep (仅在初始化期间使用)
    // 线程安全: 否

void ff_sync_time_to_freebsd(void)
    // 同步 Linux 系统时间到 FreeBSD 栈
    // 线程安全: 否 (仅初始化时)

time_t ff_time(time_t *tloc)
    // 获取秒级时间戳
    // 线程安全: 是

int ff_nanosleep(const struct timespec *req, struct timespec *rem)
    // 纳秒级 sleep
    // 线程安全: 是

// 数据包分发回调 (可选)
void ff_set_pkt_dispatcher(pkt_dispatcher_t func)
    // 注册自定义包分发函数
    // 功能: 在协议处理前拦截包，用户自定义处理 (如 VLAN 分类)
    // 线程安全: 否 (初始化时设置)

int ff_packet_filter(ff_pkt_type type, uint16_t proto)
    // 查询是否应该接收该类型的包
    // 线程安全: 是
```

#### **其他 (3+ 个)**

```c
int ff_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
              const void *newp, size_t newlen)
    // sysctl 接口 (查询/修改内核参数)
    // name: MIB 整数数组 (如 {CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_SENDSPACE})
    // namelen: MIB 数组长度
    // 线程安全: 是

int ff_arp_add(const char *ip, const char *mac)
    // 添加 ARP 条目
    // 线程安全: 是

int ff_arp_del(const char *ip)
    // 删除 ARP 条目
    // 线程安全: 是

// 其他实用函数...
const char * ff_strerror(int errnum)
    // 错误号 → 错误消息字符串
    // 线程安全: 是

// === 内核栈共存（仅在以 FF_KERNEL_COEXIST 构建时存在）===
// 逐 socket 选栈标记 (ff_api.h)：SOCK_FSTACK 0x01000000 / SOCK_KERNEL 0x02000000
// 内部机制 (lib/ff_host_interface.{c,h})：
//   32 个 ff_host_* 宿主 libc 桥：ff_host_socket/bind/listen/accept/accept4/
//     connect/close/read/write/recv/recvfrom/send/sendto/sendmsg/recvmsg/
//     shutdown/getpeername/getsockname/setsockopt/getsockopt/fcntl/
//     epoll_create1/epoll_ctl/epoll_wait
//     + R9：ff_host_set_v6only（对宿主 IPv6 socket setsockopt IPV6_V6ONLY=1）、
//           ff_host_kqueue_ctl / ff_host_kqueue_poll（kqueue<->宿主 epoll 桥）
//     + R10：ff_host_readv / ff_host_writev / ff_host_ioctl（原始 Linux request）/
//           ff_host_dup / ff_host_dup2
//   ff_native_map_get/set/clear     - F-Stack fd <-> 宿主 fd 配对表（65536 项）
//   ff_is_kernel_fd/ff_kernel_fd_encode/ff_kernel_fd_real（inline；FF_KERNEL_FD_BASE=0x40000000）
// R9 kqueue 共存 (lib/ff_syscall_wrapper.c)：ff_kqueue/ff_kevent 对称仿 epoll —— 每个
//   kqueue 惰性配对一个宿主 epoll（共享 ff_epoll_host_ep），把内核/双栈 fd 的 EVFILT_READ/WRITE
//   注册进去，从宿主 epoll 合成 struct kevent 再合并 ff_kevent_do_each F-Stack 事件。内核 fd 仅 READ/WRITE。
// FF_KERNEL_COEXIST 未定义时整体被编译剔除。
```

---

## 2. 核心数据结构详解

### 2.1 Kevent 事件结构

```c
struct kevent {
    uintptr_t ident;      // [0]  事件标识 (socket fd, PID, 定时器 ID 等)
    short filter;         // [8]  事件过滤器类型 (EVFILT_READ/WRITE/TIMER/...)，值为负数
    unsigned short flags; // [10] 事件标志 (EV_ADD/DELETE/ONESHOT/CLEAR/...)
    unsigned int fflags;  // [12] 过滤器特定标志 (ioctl/timeout 等)
    __int64_t data;       // [16] 过滤器返回的数据（固定 64 位）
                          //      EVFILT_READ: 可读字节数
                          //      EVFILT_WRITE: 可写字节数
                          //      EVFILT_TIMER: 触发次数
    void *udata;          // [24] 用户自定义数据指针 (回调参数)
    __uint64_t ext[4];    // [32] FreeBSD 13/15 扩展字段（升级前后 KBI 不变；M2 verify-only）
};

// 支持的过滤器类型
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

// 事件标志
#define EV_ADD       0x0001   // 添加事件 (注册)
#define EV_DELETE    0x0002   // 删除事件 (取消注册)
#define EV_ENABLE    0x0004   // 启用事件 (从禁用恢复)
#define EV_DISABLE   0x0008   // 禁用事件 (暂时关闭)
#define EV_ONESHOT   0x0010   // 单次触发 (自动删除)
#define EV_CLEAR     0x0020   // 自动清除 (边缘触发)
#define EV_RECEIPT   0x0040   // 事件状态反馈
#define EV_DISPATCH  0x0080   // 禁用事件在添加后
#define EV_EOF       0x8000   // 连接/文件关闭标志
#define EV_ERROR     0x4000   // 错误标志

// 便利宏
#define EV_SET(kevp, a, b, c, d, e, f) do { \
        (kevp)->ident = (a);      /* socket fd */ \
        (kevp)->filter = (b);     /* EVFILT_* */ \
        (kevp)->flags = (c);      /* EV_ADD/DELETE/... */ \
        (kevp)->fflags = (d);     /* 过滤器标志 */ \
        (kevp)->data = (e);       /* 初始数据 */ \
        (kevp)->udata = (f);      /* 用户指针 */ \
    } while (0)
```

### 2.2 Socket 地址结构体

```c
// Linux sockaddr (用于 F-Stack API)
struct linux_sockaddr {
    unsigned short sa_family;     // AF_INET (2) 或 AF_INET6 (10)
    char sa_data[14];             // 地址数据 (依赖协议族)
};

// IPv4 地址结构体
struct sockaddr_in {
    __kernel_sa_family_t sin_family;     // AF_INET
    __be16 sin_port;                      // 网络字节序端口 (htons())
    struct in_addr sin_addr;              // IPv4 地址
    unsigned char __pad[sizeof(struct sockaddr) - sizeof(short int) -
                        sizeof(unsigned short int) - sizeof(struct in_addr)];
};

// IPv6 地址结构体
struct sockaddr_in6 {
    __kernel_sa_family_t sin6_family;     // AF_INET6
    __be16 sin6_port;                      // 端口 (htons())
    __be32 sin6_flowinfo;                  // 流量信息
    struct in6_addr sin6_addr;             // IPv6 地址
    __u32 sin6_scope_id;                   // 域 ID
};

// 内存地址结构体
struct in_addr {
    __be32 s_addr;  // IPv4 地址 (网络字节序)
};

// IPv6 地址结构体
struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
#define s6_addr          in6_u.u6_addr8
#define s6_addr16        in6_u.u6_addr16
#define s6_addr32        in6_u.u6_addr32
};
```

### 2.3 Epoll 事件结构体

```c
struct epoll_event {
    uint32_t events;      // 事件掩码 (EPOLLIN/EPOLLOUT/...)
    epoll_data_t data;    // 用户数据

    union epoll_data {
        void *ptr;        // 指针 (常用)
        int fd;           // 文件描述符
        uint32_t u32;     // 32 位整数
        uint64_t u64;     // 64 位整数
    };
};

// 支持的事件
#define EPOLLIN   0x00000001      // 可读
#define EPOLLPRI  0x00000002      // 优先级数据
#define EPOLLOUT  0x00000004      // 可写
#define EPOLLRDNORM 0x00000040    // 正常数据可读
#define EPOLLRDBAND 0x00000080    // 优先级数据可读
#define EPOLLWRNORM 0x00000100    // 正常数据可写
#define EPOLLWRBAND 0x00000200    // 优先级数据可写
#define EPOLLERR  0x00000008      // 错误
#define EPOLLHUP  0x00000010      // 关闭
#define EPOLLRDHUP 0x00002000     // 对端关闭
#define EPOLLET   0x80000000      // 边缘触发 (EV_CLEAR)
#define EPOLLONESHOT 0x40000000   // 单次触发 (EV_ONESHOT)
```

### 2.4 Config 结构体

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

### 2.5 Iovec 结构体 (分散聚集 I/O)

```c
struct iovec {
    void  *iov_base;      // 缓冲区指针
    size_t iov_len;       // 缓冲区长度 (字节)
};

// 示例: 分散读 3 个缓冲区
struct iovec iov[3] = {
    {buf1, 1024},         // 读 1024 字节到 buf1
    {buf2, 2048},         // 读 2048 字节到 buf2
    {buf3, 512}           // 读 512 字节到 buf3
};

ssize_t n = ff_readv(sockfd, iov, 3);  // 一次系统调用读入 3 个缓冲区
```

### 2.6 Msghdr 结构体 (消息头)

```c
struct msghdr {
    void         *msg_name;           // 对端地址指针
    socklen_t     msg_namelen;        // 地址长度
    struct iovec *msg_iov;            // iovec 数组
    size_t        msg_iovlen;         // iovec 元素个数
    void         *msg_control;        // 控制信息 (辅助数据)
    socklen_t     msg_controllen;     // 控制信息长度
    int           msg_flags;          // 返回的标志 (MSG_EOR/MSG_TRUNC)
};

// 示例: 发送消息
char buf[] = "Hello";
struct iovec iov = {buf, strlen(buf)};
struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1
};

ff_sendmsg(sockfd, &msg, 0);
```

### 2.7 Pollfd 结构体 (poll 多路复用)

```c
struct pollfd {
    int fd;        // 文件描述符 (-1 忽略)
    short events;  // 关注的事件 (POLLIN/POLLOUT/...)
    short revents; // 返回的事件 (由 ff_poll() 填充)
};

// 事件类型
#define POLLIN    0x001   // 数据可读
#define POLLPRI   0x002   // 优先级数据
#define POLLOUT   0x004   // 可写
#define POLLERR   0x008   // 错误
#define POLLHUP   0x010   // 挂起
#define POLLNVAL  0x020   // 无效 fd

// 示例: poll 多个 fd
struct pollfd fds[2] = {
    {sockfd1, POLLIN | POLLOUT},
    {sockfd2, POLLIN}
};

ff_poll(fds, 2, -1);  // 阻塞直到事件到达
```

---

## 3. 三个关键源文件深度分析

### 3.1 ff_syscall_wrapper.c (2265 行)

**职责**：Linux ↔ FreeBSD 系统调用和参数映射

**关键映射表**：

```c
// Socket 选项级别映射
#define LINUX_SOL_SOCKET  1          // → SOL_SOCKET
#define LINUX_IPPROTO_IP  0          // → IPPROTO_IP
#define LINUX_IPPROTO_TCP 6          // → IPPROTO_TCP
#define LINUX_IPPROTO_UDP 17         // → IPPROTO_UDP

// IPv4 socket 选项映射 (Linux → FreeBSD)
struct linux_to_bsd_opt_map {
    int linux_opt;  // Linux 选项编号
    int bsd_opt;    // FreeBSD 选项编号
} ipv4_opt_map[] = {
    {LINUX_IP_TOS, IP_TOS},
    {LINUX_IP_TTL, IP_TTL},
    {LINUX_IP_HDRINCL, IP_HDRINCL},
    {LINUX_IP_MULTICAST_IF, IP_MULTICAST_IF},
    {LINUX_IP_MULTICAST_TTL, IP_MULTICAST_TTL},
    // ... 更多
};

// TCP socket 选项映射
struct linux_to_bsd_opt_map tcp_opt_map[] = {
    {LINUX_TCP_NODELAY, TCP_NODELAY},        // Nagle 算法关闭
    {LINUX_TCP_MAXSEG, TCP_MAXSEG},          // MSS (最大分段长度)
    {LINUX_TCP_CORK, TCP_CORK},              // 缓存数据
    {LINUX_TCP_KEEPIDLE, TCP_KEEPIDLE},      // TCP keepalive 空闲时间
    {LINUX_TCP_KEEPINTVL, TCP_KEEPINTVL},    // TCP keepalive 间隔
    {LINUX_TCP_KEEPCNT, TCP_KEEPCNT},        // TCP keepalive 重试次数
    // ... 更多
};

// 核心函数
int ff_setsockopt_wrapper(int s, int level, int optname,
                          const void *optval, socklen_t optlen) {
    int bsd_level = convert_level(level);      // 转换 level
    int bsd_optname = convert_optname(optname); // 转换 optname
    
    // 处理特殊参数值映射
    if (level == IPPROTO_IP && optname == IP_TOS) {
        // Linux 和 FreeBSD 的 TOS 值兼容，无需转换
    }
    
    // 处理 sockaddr 结构体映射 (如有需要)
    if (special_struct_conversion_needed()) {
        convert_params(...);
    }
    
    // 调用 FreeBSD 实现
    return ff_setsockopt_real(s, bsd_level, bsd_optname, 
                             converted_val, optlen);
}
```

**关键特性**：
- **IOCTL 映射**：FIONBIO (0x5421) → FIONBIO (不同码值)
- **Error Code 映射**：Linux errno → FreeBSD errno
- **Address Family 映射**：AF_INET6: 10 (Linux) ↔ 28 (FreeBSD)

### 3.2 ff_dpdk_if.c (2907 行) - NIC 驱动层

**全局变量**（影响性能的关键状态）：

```c
// 全局配置
static struct ff_config ff_global_cfg;
static volatile int stop_run = 0;      // 停止标志

// 网卡管理
static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];
static int nb_dev_ports = 0;           // 激活网卡数（源码为 int 非 uint32_t）
static uint32_t nb_lcores = 0;         // 激活 lcore 数
static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

// RSS 表 (连接亲和性)
static struct ff_rss_tbl ff_rss_tbl[FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES];

// 性能参数
static unsigned idle_sleep;             // 空闲 sleep (微秒，无默认值)
static uint32_t pkt_tx_delay = 1;      // 包发送延迟 (微秒)
int enable_kni = 0;                    // KNI 启用（非 static，全局可见）

// 定时器状态
static struct {
    uint64_t prev_tsc;
    uint64_t cur_tsc;
    uint64_t drain_tsc;    // TX drain 周期
} timer_state;
```

**关键函数**：

```c
// 初始化流程
int ff_dpdk_init(int argc, char *argv[]) {
    // 1. DPDK EAL 初始化
    if (rte_eal_init(dpdk_argc, dpdk_argv) < 0) {
        rte_exit(EXIT_FAILURE, "EAL init failed\n");
    }
    
    // 2. lcore 和 NIC 配置
    init_lcore_conf();
    init_mem_pool();
    
    // 3. NIC 初始化
    for (port_id = 0; port_id < nb_dev_ports; port_id++) {
        // 3.1 配置网卡
        rte_eth_dev_configure(port_id, nb_rx_queue, nb_tx_queue, &port_conf);
        
        // 3.2 配置 RSS
        struct rte_eth_rss_conf rss_conf = {
            .rss_key = rss_key,
            .rss_key_len = sizeof(rss_key),
            .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
        };
        rte_eth_dev_rss_hash_update(port_id, &rss_conf);
        
        // 3.3 配置卸载 (TSO/Checksum)
        configure_offload(port_id);
        
        // 3.4 启动网卡
        rte_eth_dev_start(port_id);
    }
    
    // 4. 初始化 RSS 分类表
    ff_rss_tbl_init();
    
    return 0;
}

// 报文处理
static inline void process_packets(struct rte_mbuf **m, uint16_t nb_m) {
    for (i = 0; i < nb_m; i++) {
        struct rte_mbuf *pkt = m[i];
        
        // 1. 获取以太网头部
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, ...);
        
        // 2. 协议过滤
        if (eth_hdr->ether_type == RTE_ETHER_TYPE_IPv4) {
            // 3. 调用 FreeBSD 协议栈
            if_input(ifp, pkt);
        }
    }
}

// 主轮询循环
static int main_loop(void *arg) {
    struct lcore_conf *qconf = rte_lcore_conf + rte_lcore_id();
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    
    while (!stop_run) {
        cur_tsc = rte_rdtsc();
        
        // [1] 时钟驱动
        if (freebsd_clock.expire < cur_tsc) {
            rte_timer_manage();  // 触发 TCP 定时器等
        }
        
        // [2] 接收报文
        for (qconf->port in port_list) {
            nb_rx = rte_eth_rx_burst(qconf->port, qconf->queue, 
                                     pkts, MAX_PKT_BURST);
            if (nb_rx > 0) {
                process_packets(pkts, nb_rx);
            }
        }
        
        // [3] 定时发送
        if ((cur_tsc - prev_tsc) > drain_tsc) {
            for (each port) {
                rte_eth_tx_burst(port, qconf->tx_queue, 
                                 tx_buffer, nb_tx);
            }
            prev_tsc = cur_tsc;
        }
        
        // [4] 应用回调
        if (loop_func) {
            loop_func(loop_arg);
        }
    }
    
    return 0;
}
```

**关键优化**：
- **无中断轮询**：100% CPU 换低延迟
- **批处理**：一次收/发 32 个报文
- **缓存亲和性**：RSS 确保连接不迁移
- **硬件卸载**：TSO、Checksum offload

### 3.3 ff_glue.c (1467 行) - 内核模拟层

**内核原语模拟**：

```c
// 互斥锁
struct mtx {
    void *ctx;  // 实际指向 pthread_mutex_t
};

void mtx_init(struct mtx *m, const char *name, const char *type, int opts) {
    pthread_mutex_t *mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(mutex, NULL);
    m->ctx = mutex;
}

void mtx_lock(struct mtx *m) {
    pthread_mutex_lock((pthread_mutex_t *)m->ctx);
}

// 条件变量
struct condvar {
    void *ctx;  // 实际指向 pthread_cond_t
};

void cv_init(struct condvar *cv, const char *desc) {
    pthread_cond_t *cond = malloc(sizeof(pthread_cond_t));
    pthread_cond_init(cond, NULL);
    cv->ctx = cond;
}

// 内存管理
void *malloc(size_t size, struct malloc_type *type, int flags) {
    // 使用 DPDK rte_malloc，支持 NUMA
    return rte_malloc("malloc", size, 0);
}

// 全局变量模拟
volatile int ticks = 0;           // 时钟滴答计数
int mp_ncpus = 1;                 // CPU 数量
struct vmspace *vmspace0;         // 全局地址空间
struct prison *prison0;           // 全局命名空间
```

**关键特性**：
- **无 VFS 支持**：文件操作有限
- **简化 IPC**：进程通信通过 DPDK Ring
- **软中断模拟**：通过 taskqueue 处理

### 3.4 内核栈共存源文件（`FF_KERNEL_COEXIST`，可选）

两个文件承载可选的共存机制（仅 `FF_KERNEL_COEXIST=1` 时编译）：

**`ff_host_interface.c`（617 行）/ `ff_host_interface.h`（187 行）**
- `FF_KERNEL_FD_BASE = 0x40000000` 与三个 inline 助手 `ff_is_kernel_fd / ff_kernel_fd_encode / ff_kernel_fd_real`（`.h` L113-128）。受管内核 fd = `host_fd + 0x40000000`，与 FreeBSD fd（`kern.maxfiles <= 65536`）永不冲突。
- `ff_native_fd_map[65536]` + `ff_native_map_get/set/clear`（`.c` L257-278）：F-Stack fd ↔ 宿主 fd 配对表（每实例单线程）。
- **32 个 `ff_host_*` 桥**：对宿主 libc 的薄透传（`socket/bind/listen/accept/accept4/connect/close/read/write/recv/recvfrom/send/sendto/sendmsg/recvmsg/shutdown/getpeername/getsockname/setsockopt/getsockopt/fcntl/epoll_create1/epoll_ctl/epoll_wait`）。**R9 新增 3 个**：`ff_host_set_v6only`（对宿主 IPv6 socket `setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 1)`，使其与同端口宿主 IPv4 socket 共存）、`ff_host_kqueue_ctl`、`ff_host_kqueue_poll`（服务 kqueue↔宿主 epoll 共存路径）。**R10 新增 5 个**：`ff_host_readv`、`ff_host_writev`、`ff_host_ioctl`（用原始 Linux request 直传宿主 libc）、`ff_host_dup`、`ff_host_dup2`。

**`ff_epoll.c`（289 行）- F-Stack + 内核统一 epoll**
- `ff_epoll_pairs[64]{kq, host_ep}`：为每个 kqueue 惰性配对一个宿主 `epoll` fd。
- `ff_epoll_ctl`：把受管内核 fd 路由到宿主 epoll，或对双栈 fd 在宿主 epoll 与 kqueue 上双注册。
- `ff_epoll_wait`：先非阻塞轮询宿主 epoll，再把 kqueue 事件合并进同一 `events[]` 数组。
- `ff_epoll_pairs_lock` 已移除 —— F-Stack 每实例单线程运行（commit `3e71f4699`）。
- **R9**：`ff_epoll_host_ep(kq, create)` 由 `static` 提升为共享符号（声明于 `ff_host_interface.h` L139），供 kqueue 共存路径复用同一 `ff_epoll_pairs` 配对表。

**R9：`ff_syscall_wrapper.c` 中的统一 kqueue/kevent 共存** —— `ff_kqueue`（L1895）与 `ff_kevent`（L2050）现对称仿 epoll 路径。`ff_kevent` 经 `ff_kevent_host_change`（L2006）分流 changelist：ident 为受管内核 fd（`ff_is_kernel_fd`）或双栈 fd（`ff_native_map_get>0`）的 `EVFILT_READ/WRITE` 经 `ff_host_kqueue_ctl` 注册进 kqueue 配对的宿主 epoll（内核-only 变更不下发 F-Stack kqueue；双栈 fd 仍下发）；eventlist 经 `ff_kevent_host_wait`（L2034）—— `ff_host_kqueue_poll(timeout=0)` 合成 `struct kevent`（`ident`=应用面 fd、`filter`=READ/WRITE、`EV_EOF`↔`EPOLLHUP|ERR`）—— 再合并 `ff_kevent_do_each` F-Stack 事件。修复 `example/main.c` kqueue 模型：内核侧 `curl 127.0.0.1:80` 返回 **200 size=438**（修复前 000）。已知限制：内核 fd 经 kqueue 仅支持 `EVFILT_READ/WRITE`。

**`ff_syscall_wrapper.c` 中的入口路由**（§3.1）：每个内核感知的 `ff_*` 入口通过 `ff_is_kernel_fd()` 识别受管内核 fd 并转发到对应 `ff_host_*` 桥；双建 socket 还会驱动经 `ff_native_map_get()` 查得的配对宿主 fd。`AF_INET6` 双建时 `ff_socket` 调 `ff_host_set_v6only(hfd)`（L952），使 `-DINET6` 构建以 v4+v6 同端口干净启动（修复此前宿主 IPv6 `errno=98 EADDRINUSE`）。

**R10：残余入口共存** —— `ff_ioctl`（L1067，内核 fd 用**原始 Linux request** 直传 `ff_host_ioctl`，不经 `linux2freebsd_ioctl`；双栈 fd 同驱动自 R10.1 起支持 `FIONBIO`/`FIOASYNC`）、`ff_readv`（L1189）/`ff_writev`（L1251，内核 fd→`ff_host_readv/writev`，仿 read/write，连接 fd 单栈热路径）、`ff_dup`（L2130，内核 fd→`ff_host_dup`+encode）、`ff_dup2`（L2156，两端内核 fd→`ff_host_dup2`+encode；混栈拒绝 `errno=EINVAL`）。已知限制：`ff_select`（encode 内核 fd 超 `FD_SETSIZE` 硬限制）/`ff_poll`（保守未实现）不支持内核 fd 共存 —— 改用 `ff_epoll_*`/`ff_kqueue`。

---

## 4. 线程安全性分析

### 4.1 线程安全分类

**完全线程安全** ✓ (可跨线程调用)：
- ff_socket / ff_bind / ff_listen / ff_accept / ff_connect / ff_close
- ff_read / ff_write / ff_send / ff_recv
- ff_kqueue / ff_kevent / ff_epoll_* (per-fd 隔离)
- ff_setsockopt / ff_getsockopt / ff_fcntl / ff_ioctl
- ff_route_ctl (路由操作原子)
- ff_gettimeofday / ff_clock_gettime
- ff_mbuf_get / ff_mbuf_free
- ff_pthread_create / ff_pthread_join

**条件线程安全** ⚠️ (需外部同步)：
- ff_init (仅初始化时，需单线程)
- ff_run (独占一个 lcore，不能并行)
- ff_log / ff_vlog (建议使用互斥锁)
- ff_gethostbyname / ff_gethostbyname2 (返回静态缓冲)

**非线程安全** ✗ (不可跨线程)：
- ff_stop_run (可从任意线程，但 ff_run 线程会退出)
- 配置相关函数 (仅初始化)
- ff_set_pkt_dispatcher (仅初始化)

### 4.2 Per-Thread Socket Table

```c
// 每个线程维护独立的 socket 表
struct ff_thread_local {
    struct socket *socket_table[FF_MAX_SOCKETS];
    int max_fd;
} __thread ff_tls;

// Socket 创建时分配本线程的 fd
int ff_socket(...) {
    struct socket *so = socreate(...);
    ff_tls.socket_table[fd] = so;
    return fd;
}

// 读写时查表
ssize_t ff_read(int fd, void *buf, size_t nbytes) {
    struct socket *so = ff_tls.socket_table[fd];
    return sorecvX(so, buf, nbytes);
}

// ✓ 线程安全：不同线程的 socket_table 独立
// ✓ 无竞态：每个 socket 只被创建该 socket 的线程访问
```

### 4.3 并发模型

```
多线程模型：

主线程                   Worker 线程 1
├─ ff_init()            ├─ ff_init()
├─ ff_run(loop1)        ├─ ff_run(loop2)
│  独占 lcore 0          │  独占 lcore 1
│  持续轮询              │  持续轮询
│  ├─ 接收报文           │  ├─ 接收报文
│  ├─ 处理报文           │  ├─ 处理报文
│  └─ 应用 loop1         │  └─ 应用 loop2
│                         │
└─ 通过共享 mempool      └─ 通过共享 mempool
  和 atomic 操作            和 atomic 操作
  实现通信                  实现通信

特点：
✓ 每个线程独占 lcore (无CPU竞争)
✓ 每个线程独立 socket table
✓ 共享资源 (mempool) 通过原子操作保护
✗ 不能跨线程共享 socket
```

---

## 5. 编译和链接

### 5.1 编译命令

```bash
# 编译 F-Stack 库
cd /data/workspace/f-stack/lib
make clean
make

# 输出: libfstack.a (4.7 MB)

# 安装头文件和库
make install PREFIX=/usr/local

# 目标位置:
#   /usr/local/lib/libfstack.a
#   /usr/local/include/ff_*.h
```

### 5.2 应用链接

```bash
# 编译选项
FSTACK_CFLAGS = $(shell pkg-config --cflags libfstack)
FSTACK_LIBS = $(shell pkg-config --libs libfstack)

# 或手动指定
FSTACK_CFLAGS = -I/usr/local/include
FSTACK_LIBS = -L/usr/local/lib -lfstack $(shell pkg-config --libs libdpdk)

# 编译应用
gcc -o app main.c $(FSTACK_CFLAGS) $(FSTACK_LIBS)

# 依赖库链接顺序
ld -o app main.o \
    -lfstack \
    -ldpdk \
    -lpthread \
    -lm \
    -lnuma
```

### 5.3 运行时依赖

```bash
# 必要的 DPDK 设置
# 1. hugepage 内存
sysctl vm.nr_hugepages=2048  # 申请 2GB huge pages

# 2. NIC 驱动绑定 (二选一)
# 方法 A: igb_uio (性能更好)
modprobe igb_uio
python dpdk_devbind.py -b igb_uio 0000:05:00.0  # 绑定网卡

# 方法 B: vfio-pci (更安全)
modprobe vfio_pci
python dpdk_devbind.py -b vfio-pci 0000:05:00.0

# 3. 运行应用（使用 start.sh 指定 config.ini 配置文件启动）
bash start.sh -c config.ini -b ./app
# start.sh 会根据 config.ini 中的 lcore_mask 自动启动主/从进程
```

---

## 总结

**关键数据结构**：
- `kevent` - BSD 事件结构体
- `epoll_event` - Linux epoll 兼容
- `ff_config` - F-Stack 全局配置
- Socket 地址结构体 (sockaddr_in/in6)

**线程安全**：
- Socket 操作：完全线程安全 (per-thread 隔离)
- 多线程模型：每个线程独占 lcore + socket table
- 共享资源：mempool 通过原子操作保护

**性能优化**：
- 批处理：单次收/发 32 个报文
- 缓存亲和性：RSS 分类 + CPU 隔离
- 硬件卸载：TSO、Checksum、LRO
- 零拷贝：mbuf 直接操作，无数据拷贝

---

**相关文档**：
- [第一层：系统总体架构](./F-Stack_Architecture_Layer1_System_Overview.md)
- [第二层：接口定义和规范](./F-Stack_Architecture_Layer2_Interface_Specification.md)
- [知识库总结](./F-Stack_Knowledge_Base_Summary.md)
