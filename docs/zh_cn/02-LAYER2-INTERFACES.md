# F-Stack v1.26 第二层：接口定义与开发规范

> **目标受众**: 应用开发工程师、集成工程师  
> **关键概念**: API 接口、配置系统、开发规范、最佳实践  
> **生成日期**: 2026-03-20

## 1. F-Stack API 完整列表 (80+ 导出函数)

> **API 层次说明**: F-Stack 的接口体系分为三个层级：
> 1. **`ff_api.h` 主接口** — 包含 ff_init/ff_run/ff_stop_run 等生命周期函数及所有 socket/kqueue/sysctl 等函数声明
> 2. **`ff_epoll.h` 补充接口** — epoll 兼容层 (ff_epoll_create/ff_epoll_ctl/ff_epoll_wait)，独立于 ff_api.h
> 3. **`ff_api.symlist` 动态导出符号表** — 定义实际动态链接时导出的符号。**注意**: ff_init/ff_run/ff_stop_run 不在此列表中，仅通过静态链接 (libfstack.a) 可用
>
> 做动态链接或语言绑定 (FFI) 时，应以 `ff_api.symlist` 为准确定可用符号。

### 1.1 核心生命周期函数

```c
// 初始化和清理
int ff_init(int argc, char * const argv[]);      // 初始化 F-Stack
void ff_run(loop_func_t loop, void *arg);        // 启动主循环 (阻塞)
void ff_stop_run(void);                          // 优雅停止循环
```

### 1.2 Socket API (POSIX 兼容)

```c
// Socket 创建和管理
int ff_socket(int domain, int type, int protocol);
int ff_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen);
int ff_listen(int s, int backlog);
int ff_accept(int s, struct linux_sockaddr *addr, socklen_t *addrlen);
int ff_accept4(int s, struct linux_sockaddr *addr, socklen_t *addrlen, int flags);
int ff_connect(int s, const struct linux_sockaddr *name, socklen_t namelen);
int ff_close(int fd);

// 数据 I/O
ssize_t ff_read(int d, void *buf, size_t nbytes);
ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t ff_write(int fd, const void *buf, size_t nbytes);
ssize_t ff_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t ff_send(int s, const void *buf, size_t len, int flags);
ssize_t ff_sendto(int s, const void *buf, size_t len, int flags,
                  const struct linux_sockaddr *to, socklen_t tolen);
ssize_t ff_sendmsg(int s, const struct msghdr *msg, int flags);
ssize_t ff_recv(int s, void *buf, size_t len, int flags);
ssize_t ff_recvfrom(int s, void *buf, size_t len, int flags,
                    struct linux_sockaddr *from, socklen_t *fromlen);
ssize_t ff_recvmsg(int s, struct msghdr *msg, int flags);

// Socket 选项
int ff_setsockopt(int s, int level, int optname,
                  const void *optval, socklen_t optlen);
int ff_getsockopt(int s, int level, int optname,
                  void *optval, socklen_t *optlen);
```

### 1.3 事件多路复用 API

```c
// BSD kqueue (推荐)
int ff_kqueue(void);
int ff_kevent(int kq, const struct kevent *changelist, int nchanges,
              struct kevent *eventlist, int nevents,
              const struct timespec *timeout);
int ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges,
                      void *eventlist, int nevents, const struct timespec *timeout,
                      void (*do_each)(void **, struct kevent *));

// Linux epoll (兼容)
int ff_epoll_create(int size);
int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int ff_epoll_wait(int epfd, struct epoll_event *events,
                  int maxevents, int timeout);

// 传统接口
int ff_select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout);
int ff_poll(struct pollfd *fds, nfds_t nfds, int timeout);
```

### 1.4 系统控制 API

```c
// fcntl 和 ioctl
int ff_fcntl(int s, int cmd, ...);
int ff_ioctl(int s, unsigned long request, ...);

// 系统配置
int ff_sysctl(const int *name, u_int namelen, void *oldp,
              size_t *oldlenp, const void *newp, size_t newlen);
```

### 1.5 特殊功能 API

```c
// 路由控制
int ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
                 struct linux_sockaddr *dst, struct linux_sockaddr *gw,
                 struct linux_sockaddr *netmask);
int ff_rtioctl(int fib, void *data, unsigned *plen, unsigned maxlen);

// 零拷贝 mbuf 操作
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);
int ff_zc_mbuf_read(struct ff_zc_mbuf *m, const char *data, int len);  // 【注】暂未实现

// 时间相关
int ff_gettimeofday(struct timeval *tv, struct timezone *tz);

// 日志
int ff_log(uint32_t level, uint32_t logtype, const char *format, ...);
int ff_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap);
int ff_log_reset_stream(void *f);
void ff_log_set_global_level(uint32_t level);
int ff_log_set_level(uint32_t logtype, uint32_t level);
void ff_log_close(void);

// 多线程支持
int ff_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine)(void *), void *arg);
int ff_pthread_join(pthread_t thread, void **value_ptr);
```

## 2. 配置系统

### 2.1 配置文件格式 (INI)

文件位置: `/data/workspace/f-stack/config.ini`

```ini
[dpdk]
# NIC 端口配置
portid_list = 0              # 使用的网卡端口 ID (逗号分隔)
nb_ports = 1                 # 端口数量

# CPU 核心配置
lcore_mask = 0x1             # 使用的 CPU 核心 (十六进制位掩码)
                             # 0x1 = CPU-0, 0x3 = CPU-0,1, 0x7 = CPU-0,1,2

# 内存配置
numa_on = 1                  # NUMA 支持 (0=关闭, 1=开启)

[host]
# 网络地址配置
ipaddr = 192.168.1.2         # IP 地址
netmask = 255.255.255.0      # 子网掩码
gateway = 192.168.1.1        # 网关地址

# 网络接口
iface = eth0                 # 物理网卡名称

[kni]
# 虚拟网卡支持 (可选)
enable = 0                   # 启用虚拟网卡 (0=禁用, 1=启用)
```

### 2.2 编程方式配置

```c
// 在调用 ff_init() 之前设置配置
struct ff_config *cfg = &ff_global_cfg;

// 设置 NIC 端口
cfg->dpdk.portid_list[0] = 0;
cfg->dpdk.nb_ports = 1;

// 设置 CPU 核心
cfg->dpdk.lcore_mask = 0x1;  // 使用 CPU-0

// 设置 IP 地址
inet_aton("192.168.1.2", &cfg->host.ipaddr);
inet_aton("255.255.255.0", &cfg->host.netmask);

// 初始化
ff_init(argc, argv);
```

### 2.3 内核栈共存（`FF_KERNEL_COEXIST`，可选，默认关）

以 `make FF_KERNEL_COEXIST=1` 构建并通过 `config.ini [stack] kernel_coexist=1` 开启后，应用可把个别 socket 放到宿主 Linux 内核栈，其余照常留在 F-Stack，全部在同一事件循环内：

```c
int fk = ff_socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0); // 宿主内核栈
int ff = ff_socket(AF_INET, SOCK_STREAM | SOCK_FSTACK, 0); // F-Stack 栈
int du = ff_socket(AF_INET, SOCK_STREAM, 0);               // 双建（默认）
```

内核栈 fd 以 `host_fd + 0x40000000` 返回，并被所有 `ff_*` 调用透明接受（转发到 `ff_host_*` 桥），含 `ff_epoll_*`，以及 —— 自 **R9** 起 —— `ff_kqueue`/`ff_kevent`：每个 kqueue 惰性配对一个宿主 epoll（共享 `ff_epoll_host_ep`），`ff_kevent` 把内核/双栈 fd 的 `EVFILT_READ/WRITE` 注册其中，等待时非阻塞轮询宿主 epoll 合成 `struct kevent`（`ident`=应用面 fd）再合并 F-Stack 事件 —— 使纯 kqueue 应用（`example/main.c`）能感知内核侧 listener（`curl 127.0.0.1:80`=200）。双建 `AF_INET6` socket 的宿主对应 socket 被设 `IPV6_V6ONLY=1`，使 `-DINET6` 构建以 v4+v6 同端口启动。自 **R10** 起 `ff_readv`/`ff_writev`/`ff_ioctl`/`ff_dup`/`ff_dup2` 亦支持内核 fd 路由（`ff_readv/writev` 经 `ff_host_readv/writev`；`ff_ioctl` 内核 fd 用原始 Linux request 直传 `ff_host_ioctl`，双栈 fd 同驱动自 R10.1 起支持 `FIONBIO`/`FIOASYNC`；`ff_dup2` 混栈拒绝 `errno=EINVAL`）。默认关闭 → 构建逐字节一致。已知限制：内核 fd 经 kqueue 仅支持 `EVFILT_READ/WRITE`；`ff_select`（encode 内核 fd 超 `FD_SETSIZE` 硬限制）/`ff_poll`（保守未实现）不支持内核 fd 共存，改用 `ff_epoll_*`/`ff_kqueue`。详见 `docs/kernel_event_support_spec/`。

## 3. 应用开发规范

### 3.1 三种事件模式

#### 模式 1: 推荐的 kqueue (BSD 风格)

```c
#include <ff_api.h>
#include <sys/types.h>
#include <sys/event.h>

int main(int argc, char *argv[]) {
    ff_init(argc, argv);
    
    // 创建 socket
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    
    // 绑定和监听
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(8080);
    
    ff_bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    ff_listen(sockfd, 32);
    
    // 创建 kqueue
    int kq = ff_kqueue();
    
    // 添加监听事件
    struct kevent kev;
    EV_SET(&kev, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
    ff_kevent(kq, &kev, 1, NULL, 0, NULL);
    
    // 启动主循环
    ff_run(loop_func, (void *)kq);
    
    return 0;
}

// 用户定义的循环函数
int loop_func(void *arg) {
    int kq = (int)(intptr_t)arg;
    struct kevent events[MAX_EVENTS];
    int nevents;
    
    // 等待事件
    nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    
    for (int i = 0; i < nevents; i++) {
        int fd = events[i].ident;
        
        if (events[i].filter == EVFILT_READ) {
            // 可读事件 - 接受连接或读数据
            if (fd == listening_socket) {
                int client = ff_accept(fd, NULL, NULL);
                // 添加客户端到 kqueue
                EV_SET(&kev, client, EVFILT_READ, EV_ADD, 0, 0, NULL);
                ff_kevent(kq, &kev, 1, NULL, 0, NULL);
            } else {
                // 读数据
                char buf[1024];
                ssize_t n = ff_read(fd, buf, sizeof(buf));
                if (n > 0) {
                    ff_write(fd, buf, n);  // Echo
                }
            }
        }
    }
    
    return 0;
}
```

#### 模式 2: Linux epoll (兼容)

```c
#include <ff_api.h>
#include <sys/epoll.h>

int main(int argc, char *argv[]) {
    ff_init(argc, argv);
    
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    // ... bind/listen ...
    
    // 创建 epoll
    int epfd = ff_epoll_create(0);
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sockfd;
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    
    ff_run(loop_func, (void *)(intptr_t)epfd);
    
    return 0;
}

int loop_func(void *arg) {
    int epfd = (int)(intptr_t)arg;
    struct epoll_event events[MAX_EVENTS];
    
    int nevents = ff_epoll_wait(epfd, events, MAX_EVENTS, -1);
    
    for (int i = 0; i < nevents; i++) {
        // 循环处理事件...
        // 特别注意，ff_accept时需要循环调用，直到失败
    }
    
    return 0;
}
```

### 3.2 关键开发规则

**必须遵循**:
1. **非阻塞模式**: 必须设置非阻塞
   ```c
   int on = 1;
   ff_ioctl(sockfd, FIONBIO, &on);
   ```

2. **单线程模型**: 每个 DPDK lcore 运行一个独立的 F-Stack 实例，无跨核同步

3. **正确的关闭**: 使用 `ff_stop_run()` 优雅关闭
   ```c
   // 在信号处理中
   signal(SIGTERM, sighandler);
   void sighandler(int sig) {
       ff_stop_run();  // 停止循环
   }
   ```

4. **内存管理**: 所有 socket/文件描述符操作保持在单个 lcore 内

### 3.3 性能优化建议

**1. 批量处理**
```c
// 一次处理多个事件
struct kevent events[MAX_BATCH];
int n = ff_kevent(kq, NULL, 0, events, MAX_BATCH, NULL);
for (int i = 0; i < n; i++) {
    handle_event(&events[i]);
}
```

**2. 零拷贝发送**
```c
// 使用零拷贝 mbuf
struct rte_mbuf *m = ff_zc_mbuf_get(sockfd);
if (m) {
    prepare_packet(m);
    ff_zc_mbuf_write(sockfd, m);
}
```

**3. CPU 亲和性**
通过配置文件指定 CPU 核心的亲和性绑定:

## 4. 多进程开发规范

### 4.1 主进程初始化

```c
int main(int argc, char *argv[]) {
    // 配置主进程
    struct ff_config *cfg = &ff_global_cfg;
    cfg->dpdk.proc_type = FF_PROC_PRIMARY;
    cfg->dpdk.nb_procs = 4;  // 4 个 worker
    
    ff_init(argc, argv);
    
    // 启动 worker 子进程
    for (int i = 0; i < 4; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            worker_main(i);
            exit(0);
        }
    }
    
    // 主进程继续运行
    ff_run(primary_loop, NULL);
}
```

### 4.2 Worker 进程初始化

```c
void worker_main(int worker_id) {
    struct ff_config *cfg = &ff_global_cfg;
    cfg->dpdk.proc_type = FF_PROC_SECONDARY;
    cfg->dpdk.proc_id = worker_id;
    
    // Worker 使用相同的配置初始化
    ff_init(0, NULL);
    
    // 各 worker 独立运行
    ff_run(worker_loop, (void *)(intptr_t)worker_id);
}
```

### 4.3 进程间通信

> **注意**: `ff_msg_send()` 不是公开 API，在 `ff_api.h` 和 `ff_api.symlist` 中均不存在。进程间通信通过 `ff_msg` 消息队列（`lib/ff_msg.h`）实现，由 F-Stack 内部工具（knictl/sysctl 等）使用，应用层无需直接调用。

## 5. 线程安全性

### 5.1 安全操作

✓ **线程安全** (在单个 lcore 内):
- Socket API (ff_socket, ff_read, ff_write 等)
- 配置查询
- 事件等待

✗ **非线程安全**:
- 运行中创建/销毁线程
- 在 ff_run() 之后注册新的回调
- 跨 lcore 的 socket 操作

### 5.2 DPDK 原子操作

```c
// DPDK 内存池是原子操作的
struct rte_mbuf *m = rte_pktmbuf_alloc(pool);  // 多进程安全
rte_pktmbuf_free(m);                           // 多进程安全
```

## 6. 编译和链接

### 6.1 编译 F-Stack 库

```bash
cd /data/workspace/f-stack/lib
make clean
make
make install PREFIX=/usr/local
```

### 6.2 编译用户应用

```bash
gcc -o myapp main.c \
    -lfstack \
    $(pkg-config --cflags --libs libdpdk) \
    -lpthread -lm

# 或使用 Makefile
CFLAGS = $(shell pkg-config --cflags libdpdk)
LDFLAGS = $(shell pkg-config --libs libdpdk) -lfstack -lpthread

myapp: main.o
	gcc -o $@ $< $(LDFLAGS)
```

### 6.3 条件编译选项

```makefile
# IPv6 支持
FF_INET6=1 make

# KNI 虚拟网卡支持
FF_KNI=1 make

# 高精度 TCP 定时器
FF_TCPHPTS=1 make
```

## 7. 常见错误和解决方案

| 错误 | 原因 | 解决方案 |
|-----|------|--------|
| `ff_read()` 返回 -1 | 缓冲区满或连接错误 | 检查 errno，非阻塞模式下应继续 |
| `ff_write()` 返回 -1 | 发送队列满 | 稍后重试，或增加内存池 |
| 段错误 | 跨 lcore 操作 socket | 确保每个 socket 在单个 lcore 内操作 |
| 连接断开 | 网络问题或超时 | 检查 RST/FIN 标志，重新连接 |
| RSS 流不均衡 | NIC 不支持或配置错误 | 检查 `ff_rss_tbl_init()` 日志 |

## 8. 最佳实践

1. **使用 kqueue** (BSD 风格) 而不是 select/poll，性能更好
2. **批量处理事件** 而不是一次一个
3. **设置合理的内存池大小** 根据预期连接数
4. **在多进程模式下使用 RSS** 维持连接亲和性
5. **监控 DPDK 统计信息** 了解性能瓶颈
6. **测试故障场景** 如 NIC 掉线、内存不足等

## 总结

F-Stack 提供了与 POSIX socket API 兼容的接口，同时增强了性能相关的特性 (kqueue, epoll, 零拷贝 mbuf 等)。应用开发需要遵循单线程 + 轮询的模型，充分利用多核和硬件卸载能力，才能获得最佳性能。
