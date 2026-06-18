# F-Stack v1.26 Layer 2: Interface Definitions and Development Guidelines

> **Target Audience**: Application developers, integration engineers  
> **Key Concepts**: API interfaces, configuration system, development guidelines, best practices  
> **Generation Date**: 2026-03-20

## 1. F-Stack Complete API List (80+ Exported Functions)

> **API Hierarchy Notes**: The F-Stack interface system is organized into three levels:
> 1. **`ff_api.h` main interface** — Contains lifecycle functions such as ff_init/ff_run/ff_stop_run and all socket/kqueue/sysctl function declarations
> 2. **`ff_epoll.h` supplementary interface** — epoll compatibility layer (ff_epoll_create/ff_epoll_ctl/ff_epoll_wait), independent of ff_api.h
> 3. **`ff_api.symlist` dynamic export symbol table** — Defines the symbols actually exported during dynamic linking. **Note**: ff_init/ff_run/ff_stop_run are not in this list; they are only available through static linking (libfstack.a)
>
> When doing dynamic linking or language bindings (FFI), use `ff_api.symlist` as the authoritative reference for available symbols.

### 1.1 Core Lifecycle Functions

```c
// Initialization and cleanup
int ff_init(int argc, char * const argv[]);      // Initialize F-Stack
void ff_run(loop_func_t loop, void *arg);        // Start main loop (blocking)
void ff_stop_run(void);                          // Gracefully stop loop
```

### 1.2 Socket API (POSIX Compatible)

```c
// Socket creation and management
int ff_socket(int domain, int type, int protocol);
int ff_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen);
int ff_listen(int s, int backlog);
int ff_accept(int s, struct linux_sockaddr *addr, socklen_t *addrlen);
int ff_accept4(int s, struct linux_sockaddr *addr, socklen_t *addrlen, int flags);
int ff_connect(int s, const struct linux_sockaddr *name, socklen_t namelen);
int ff_close(int fd);

// Data I/O
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

// Socket options
int ff_setsockopt(int s, int level, int optname,
                  const void *optval, socklen_t optlen);
int ff_getsockopt(int s, int level, int optname,
                  void *optval, socklen_t *optlen);
```

### 1.3 Event Multiplexing API

```c
// BSD kqueue (recommended)
int ff_kqueue(void);
int ff_kevent(int kq, const struct kevent *changelist, int nchanges,
              struct kevent *eventlist, int nevents,
              const struct timespec *timeout);
int ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges,
                      void *eventlist, int nevents, const struct timespec *timeout,
                      void (*do_each)(void **, struct kevent *));

// Linux epoll (compatible)
int ff_epoll_create(int size);
int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int ff_epoll_wait(int epfd, struct epoll_event *events,
                  int maxevents, int timeout);

// Traditional interfaces
int ff_select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout);
int ff_poll(struct pollfd *fds, nfds_t nfds, int timeout);
```

### 1.4 System Control API

```c
// fcntl and ioctl
int ff_fcntl(int s, int cmd, ...);
int ff_ioctl(int s, unsigned long request, ...);

// System configuration
int ff_sysctl(const int *name, u_int namelen, void *oldp,
              size_t *oldlenp, const void *newp, size_t newlen);
```

### 1.5 Special Feature API

```c
// Route control
int ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
                 struct linux_sockaddr *dst, struct linux_sockaddr *gw,
                 struct linux_sockaddr *netmask);
int ff_rtioctl(int fib, void *data, unsigned *plen, unsigned maxlen);

// Zero-copy mbuf operations
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);
int ff_zc_mbuf_read(struct ff_zc_mbuf *m, const char *data, int len);  // [Note] Not yet implemented

// Time-related
int ff_gettimeofday(struct timeval *tv, struct timezone *tz);

// Logging
int ff_log(uint32_t level, uint32_t logtype, const char *format, ...);
int ff_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap);
int ff_log_reset_stream(void *f);
void ff_log_set_global_level(uint32_t level);
int ff_log_set_level(uint32_t logtype, uint32_t level);
void ff_log_close(void);

// Multi-threading support
int ff_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine)(void *), void *arg);
int ff_pthread_join(pthread_t thread, void **value_ptr);
```

## 2. Configuration System

### 2.1 Configuration File Format (INI)

File location: `/data/workspace/f-stack/config.ini`

```ini
[dpdk]
# NIC port configuration
portid_list = 0              # NIC port IDs to use (comma-separated)
nb_ports = 1                 # Number of ports

# CPU core configuration
lcore_mask = 0x1             # CPU cores to use (hexadecimal bitmask)
                             # 0x1 = CPU-0, 0x3 = CPU-0,1, 0x7 = CPU-0,1,2

# Memory configuration
numa_on = 1                  # NUMA support (0=disabled, 1=enabled)

[host]
# Network address configuration
ipaddr = 192.168.1.2         # IP address
netmask = 255.255.255.0      # Subnet mask
gateway = 192.168.1.1        # Gateway address

# Network interface
iface = eth0                 # Physical NIC name

[kni]
# Virtual NIC support (optional)
enable = 0                   # Enable virtual NIC (0=disabled, 1=enabled)
```

### 2.2 Programmatic Configuration

```c
// Set configuration before calling ff_init()
struct ff_config *cfg = &ff_global_cfg;

// Set NIC ports
cfg->dpdk.portid_list[0] = 0;
cfg->dpdk.nb_ports = 1;

// Set CPU cores
cfg->dpdk.lcore_mask = 0x1;  // Use CPU-0

// Set IP address
inet_aton("192.168.1.2", &cfg->host.ipaddr);
inet_aton("255.255.255.0", &cfg->host.netmask);

// Initialize
ff_init(argc, argv);
```

### 2.3 Kernel-Stack Coexistence (`FF_KERNEL_COEXIST`, optional, default off)

Built with `make FF_KERNEL_COEXIST=1` and enabled via `config.ini [stack] kernel_coexist=1`, the app can place selected sockets on the host Linux kernel stack while the rest stay on F-Stack, all from one event loop:

```c
int fk = ff_socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0); // host kernel stack
int ff = ff_socket(AF_INET, SOCK_STREAM | SOCK_FSTACK, 0); // F-Stack stack
int du = ff_socket(AF_INET, SOCK_STREAM, 0);               // dual-created (default)
```

A kernel-stack fd is returned as `host_fd + 0x40000000` and is accepted transparently by all `ff_*` calls (forwarded to `ff_host_*` bridges), including `ff_epoll_*` and — since **R9** — `ff_kqueue`/`ff_kevent`: each kqueue lazily pairs one host epoll (shared `ff_epoll_host_ep`), `ff_kevent` registers a kernel/dual-stack fd's `EVFILT_READ/WRITE` there and synthesizes `struct kevent` (`ident`=app-side fd) from a non-blocking host-epoll poll before merging F-Stack events — so a pure-kqueue app (`example/main.c`) reaches the kernel-side listener (`curl 127.0.0.1:80`=200). A dual-built `AF_INET6` socket gets `IPV6_V6ONLY=1` on its host counterpart so a `-DINET6` build starts with v4+v6 on the same port. Since **R10**, `ff_readv`/`ff_writev`/`ff_ioctl`/`ff_dup`/`ff_dup2` also support kernel-fd routing (`ff_readv/writev` via `ff_host_readv/writev`; `ff_ioctl` kernel fd uses the raw Linux request straight to `ff_host_ioctl`, dual-stack fd same-driver since R10.1 syncs `FIONBIO`/`FIOASYNC`; `ff_dup2` cross-stack rejected `errno=EINVAL`). Off by default → byte-for-byte identical build. Known limitations: kernel fds via kqueue support `EVFILT_READ/WRITE` only; `ff_select` (encode kernel fd ≫ `FD_SETSIZE` hard limit) / `ff_poll` (conservatively not implemented) do not support kernel-fd coexistence — use `ff_epoll_*`/`ff_kqueue`. See `docs/kernel_event_support_spec/`.

## 3. Application Development Guidelines

### 3.1 Three Event Modes

#### Mode 1: Recommended kqueue (BSD Style)

```c
#include <ff_api.h>
#include <sys/types.h>
#include <sys/event.h>

int main(int argc, char *argv[]) {
    ff_init(argc, argv);
    
    // Create socket
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    
    // Bind and listen
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(8080);
    
    ff_bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    ff_listen(sockfd, 32);
    
    // Create kqueue
    int kq = ff_kqueue();
    
    // Add listen event
    struct kevent kev;
    EV_SET(&kev, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
    ff_kevent(kq, &kev, 1, NULL, 0, NULL);
    
    // Start main loop
    ff_run(loop_func, (void *)kq);
    
    return 0;
}

// User-defined loop function
int loop_func(void *arg) {
    int kq = (int)(intptr_t)arg;
    struct kevent events[MAX_EVENTS];
    int nevents;
    
    // Wait for events
    nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    
    for (int i = 0; i < nevents; i++) {
        int fd = events[i].ident;
        
        if (events[i].filter == EVFILT_READ) {
            // Read-ready event - accept connection or read data
            if (fd == listening_socket) {
                int client = ff_accept(fd, NULL, NULL);
                // Add client to kqueue
                EV_SET(&kev, client, EVFILT_READ, EV_ADD, 0, 0, NULL);
                ff_kevent(kq, &kev, 1, NULL, 0, NULL);
            } else {
                // Read data
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

#### Mode 2: Linux epoll (Compatible)

```c
#include <ff_api.h>
#include <sys/epoll.h>

int main(int argc, char *argv[]) {
    ff_init(argc, argv);
    
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    // ... bind/listen ...
    
    // Create epoll
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
        // Process events in loop...
        // Note: ff_accept should be called in a loop until it fails
    }
    
    return 0;
}
```

### 3.2 Key Development Rules

**Must follow**:
1. **Non-blocking mode**: Must set non-blocking
   ```c
   int on = 1;
   ff_ioctl(sockfd, FIONBIO, &on);
   ```

2. **Single-threaded model**: Each DPDK lcore runs an independent F-Stack instance, no cross-core synchronization

3. **Proper shutdown**: Use `ff_stop_run()` for graceful shutdown
   ```c
   // In signal handler
   signal(SIGTERM, sighandler);
   void sighandler(int sig) {
       ff_stop_run();  // Stop the loop
   }
   ```

4. **Memory management**: All socket/file descriptor operations stay within a single lcore

### 3.3 Performance Optimization Recommendations

**1. Batch processing**
```c
// Process multiple events at once
struct kevent events[MAX_BATCH];
int n = ff_kevent(kq, NULL, 0, events, MAX_BATCH, NULL);
for (int i = 0; i < n; i++) {
    handle_event(&events[i]);
}
```

**2. Zero-copy send**
```c
// Use zero-copy mbuf
struct rte_mbuf *m = ff_zc_mbuf_get(sockfd);
if (m) {
    prepare_packet(m);
    ff_zc_mbuf_write(sockfd, m);
}
```

**3. CPU affinity**
Specify CPU core affinity binding through the configuration file:

## 4. Multi-Process Development Guidelines

### 4.1 Primary Process Initialization

```c
int main(int argc, char *argv[]) {
    // Configure primary process
    struct ff_config *cfg = &ff_global_cfg;
    cfg->dpdk.proc_type = FF_PROC_PRIMARY;
    cfg->dpdk.nb_procs = 4;  // 4 workers
    
    ff_init(argc, argv);
    
    // Start worker child processes
    for (int i = 0; i < 4; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            worker_main(i);
            exit(0);
        }
    }
    
    // Primary process continues running
    ff_run(primary_loop, NULL);
}
```

### 4.2 Worker Process Initialization

```c
void worker_main(int worker_id) {
    struct ff_config *cfg = &ff_global_cfg;
    cfg->dpdk.proc_type = FF_PROC_SECONDARY;
    cfg->dpdk.proc_id = worker_id;
    
    // Worker initializes with the same configuration
    ff_init(0, NULL);
    
    // Each worker runs independently
    ff_run(worker_loop, (void *)(intptr_t)worker_id);
}
```

### 4.3 Inter-Process Communication

> **Note**: `ff_msg_send()` is not a public API; it does not exist in either `ff_api.h` or `ff_api.symlist`. Inter-process communication is implemented through the `ff_msg` message queue (`lib/ff_msg.h`), used by F-Stack internal tools (knictl/sysctl, etc.). Application-level code does not need to call it directly.

## 5. Thread Safety

### 5.1 Safe Operations

✓ **Thread-safe** (within a single lcore):
- Socket API (ff_socket, ff_read, ff_write, etc.)
- Configuration queries
- Event waiting

✗ **Not thread-safe**:
- Creating/destroying threads while running
- Registering new callbacks after ff_run()
- Cross-lcore socket operations

### 5.2 DPDK Atomic Operations

```c
// DPDK memory pool operations are atomic
struct rte_mbuf *m = rte_pktmbuf_alloc(pool);  // Multi-process safe
rte_pktmbuf_free(m);                           // Multi-process safe
```

## 6. Compilation and Linking

### 6.1 Compiling the F-Stack Library

```bash
cd /data/workspace/f-stack/lib
make clean
make
make install PREFIX=/usr/local
```

### 6.2 Compiling User Applications

```bash
gcc -o myapp main.c \
    -lfstack \
    $(pkg-config --cflags --libs libdpdk) \
    -lpthread -lm

# Or use a Makefile
CFLAGS = $(shell pkg-config --cflags libdpdk)
LDFLAGS = $(shell pkg-config --libs libdpdk) -lfstack -lpthread

myapp: main.o
	gcc -o $@ $< $(LDFLAGS)
```

### 6.3 Conditional Compilation Options

```makefile
# IPv6 support
FF_INET6=1 make

# KNI virtual NIC support
FF_KNI=1 make

# High-precision TCP timers
FF_TCPHPTS=1 make
```

## 7. Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `ff_read()` returns -1 | Buffer full or connection error | Check errno; in non-blocking mode, continue |
| `ff_write()` returns -1 | Send queue full | Retry later, or increase memory pool |
| Segmentation fault | Cross-lcore socket operation | Ensure each socket operates within a single lcore |
| Connection dropped | Network issue or timeout | Check RST/FIN flags, reconnect |
| Uneven RSS flow distribution | NIC not supported or misconfigured | Check `ff_rss_tbl_init()` logs |

## 8. Best Practices

1. **Use kqueue** (BSD style) instead of select/poll for better performance
2. **Batch process events** instead of one at a time
3. **Set appropriate memory pool size** based on expected connection count
4. **Use RSS in multi-process mode** to maintain connection affinity
5. **Monitor DPDK statistics** to identify performance bottlenecks
6. **Test failure scenarios** such as NIC disconnection, out of memory, etc.

## Summary

F-Stack provides POSIX socket API-compatible interfaces while enhancing performance-related features (kqueue, epoll, zero-copy mbuf, etc.). Application development must follow the single-threaded + polling model and fully leverage multi-core and hardware offload capabilities to achieve optimal performance.
