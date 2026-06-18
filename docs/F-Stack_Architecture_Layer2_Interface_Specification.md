# F-Stack v1.26 Layer 2 Architecture Analysis: Interface Definition & Specification

**Document Version**: 1.0  
**Analysis Date**: 2026-03-20  
**Coverage**: F-Stack v1.26 Public API, Configuration System, Development Guidelines (FreeBSD 15.0 port; KBI/KPI deltas captured)  
**Target Audience**: Application Developers, System Integration Engineers, Performance Optimization Engineers

---

## 1. Public API Architecture

### 1.1 API Overview

F-Stack exports **80+ public symbols**, divided into the following major categories:

```
┌─────────────────────────────────────────────────┐
│      F-Stack Public API (ff_api.h 491 lines)    │
├─────────────────────────────────────────────────┤
│ 1. Lifecycle Management (3)                      │
│    ff_init / ff_run / ff_stop_run               │
│                                                 │
│ 2. Socket API (25+)                             │
│    ff_socket / ff_bind / ff_listen / ff_accept  │
│    ff_connect / ff_close / ff_dup / ff_dup2     │
│    ...                                          │
│                                                 │
│ 3. I/O Operations (10+)                         │
│    ff_read / ff_write / ff_readv / ff_writev    │
│    ff_send / ff_sendto / ff_sendmsg             │
│    ff_recv / ff_recvfrom / ff_recvmsg           │
│    ...                                          │
│                                                 │
│ 4. Event Multiplexing (5)                       │
│    ff_kqueue / ff_kevent / ff_kevent_do_each    │
│    ff_select / ff_poll                          │
│                                                 │
│ 5. Epoll Compatibility Layer (3)                │
│    ff_epoll_create / ff_epoll_ctl / ff_epoll_wait│
│                                                 │
│ 6. Control Operations (10+)                     │
│    ff_setsockopt / ff_getsockopt                │
│    ff_ioctl / ff_fcntl                          │
│    ...                                          │
│                                                 │
│ 7. Route Management (1)                         │
│    ff_route_ctl                                 │
│                                                 │
│ 8. Zero-Copy Mbuf (3)                           │
│    ff_zc_mbuf_get / ff_zc_mbuf_write            │
│    ff_zc_mbuf_read (not yet implemented) / ...  │
│                                                 │
│ 9. Multi-Threading Support (2)                  │
│    ff_pthread_create / ff_pthread_join          │
│                                                 │
│ 10. System Interfaces (10+)                     │
│     ff_gettimeofday / ff_clock_gettime          │
│     ff_log_open_set / ff_log / ff_vlog           │
│     ...                                         │
└─────────────────────────────────────────────────┘
```

### 1.2 Detailed Description of Six Major Header Files

#### **ff_api.h (491 Lines) - Main API**

**Initialization & Startup**:
```c
int ff_init(int argc, char * const argv[]);
    // Initialize F-Stack
    // Parameters: Command-line arguments in DPDK style
    // Returns: 0 on success, -1 on failure
    // Must be called first by the primary process

void ff_run(loop_func_t loop, void *arg);
    // Start the main polling loop
    // Parameters: User callback function, user argument
    // Does not return (unless ff_stop_run() is called)
    // Called once per lcore

void ff_stop_run(void);
    // Stop the polling loop
    // Graceful shutdown, waits for all packet processing to complete
```

**Socket Operations (POSIX-Compatible)**:
```c
int ff_socket(int domain, int type, int protocol);
    // Create a socket
    // domain: AF_INET (IPv4) or AF_INET6 (IPv6)
    // type: SOCK_STREAM (TCP) or SOCK_DGRAM (UDP)
    // Returns: File descriptor (>= 0)

int ff_bind(int sockfd, const struct linux_sockaddr *addr, socklen_t addrlen);
    // Bind a local address
    // addr: Pointer to address structure
    // Note: Uses struct linux_sockaddr, not FreeBSD format

int ff_listen(int sockfd, int backlog);
    // Listen for connections (TCP only)
    // backlog: Connection queue size

int ff_accept(int sockfd, struct linux_sockaddr *addr, socklen_t *addrlen);
    // Accept a connection (TCP only)
    // Returns: fd of the new connection

int ff_connect(int sockfd, const struct linux_sockaddr *addr, socklen_t addrlen);
    // Establish a connection (TCP only)
    // Returns: 0 on success, -1 on failure (non-blocking, may return EINPROGRESS)

int ff_close(int sockfd);
    // Close a socket
    // Waits for all pending data to be sent
```

**I/O Operations (Non-Blocking)**:
```c
ssize_t ff_read(int fd, void *buf, size_t nbytes);
    // Read data
    // Returns: > 0 bytes read, 0 connection closed, -1 error
    // Non-blocking: Returns -1 + errno=EAGAIN when no data available

ssize_t ff_write(int fd, const void *buf, size_t nbytes);
    // Write data
    // Returns: > 0 bytes sent, -1 buffer full or error
    // Note: Returns -1 when buffer is full, NOT partial send
    // Should monitor EVFILT_WRITE events to handle

ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt);
    // Scatter-gather read

ssize_t ff_writev(int fd, const struct iovec *iov, int iovcnt);
    // Scatter-gather write

ssize_t ff_send(int fd, const void *buf, size_t len, int flags);
ssize_t ff_sendto(int fd, const void *buf, size_t len, int flags,
                  const struct linux_sockaddr *to, socklen_t tolen);
ssize_t ff_sendmsg(int fd, const struct msghdr *msg, int flags);
    // Various send methods (flags support MSG_MORE, etc.)

ssize_t ff_recv(int fd, void *buf, size_t len, int flags);
ssize_t ff_recvfrom(int fd, void *buf, size_t len, int flags,
                    struct linux_sockaddr *from, socklen_t *fromlen);
ssize_t ff_recvmsg(int fd, struct msghdr *msg, int flags);
    // Various receive methods
```

**Event Multiplexing (Kqueue)**:
```c
int ff_kqueue(void);
    // Create an event object (similar to epoll_create)
    // Returns: Event object fd

int ff_kevent(int kq, const struct kevent *changelist, int nchanges,
              struct kevent *eventlist, int nevents,
              const struct timespec *timeout);
    // Register events and wait for events
    // changelist: Array of events to register
    // eventlist: Array of returned ready events
    // timeout: NULL for blocking, 0 for non-blocking, > 0 for timeout wait
    // Returns: Number of returned events

int ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges,
                      void *eventlist, int nevents,
                      const struct timespec *timeout,
                      void (*do_each)(void **, struct kevent *));
    // Convenience function: internally calls ff_kevent and invokes do_each for each event

int ff_select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout);
    // select() implementation (for compatibility only)

int ff_poll(struct pollfd *fds, nfds_t nfds, int timeout);
    // poll() implementation (for compatibility only)
```

**Epoll Compatibility Layer (Linux API)**:
```c
int ff_epoll_create(int size);
    // Create an epoll object (actually calls ff_kqueue)

int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
    // Register/modify/delete epoll events
    // op: EPOLL_CTL_ADD / EPOLL_CTL_MOD / EPOLL_CTL_DEL

int ff_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
    // Wait for events

// Supported epoll event flags:
#define EPOLLIN   0x001      // Readable
#define EPOLLOUT  0x004      // Writable
#define EPOLLET   0x80000000 // Edge-triggered (EV_CLEAR)
#define EPOLLONESHOT 0x40000000 // One-shot trigger (EV_ONESHOT)
```

**Control Operations**:
```c
int ff_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);
    // Set socket options
    // level: SOL_SOCKET / IPPROTO_IP / IPPROTO_TCP / ...

int ff_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);
    // Get socket options

int ff_ioctl(int fd, unsigned long request, ...);
    // I/O control
    // Common: FIONBIO (set non-blocking), FIONREAD (query readable bytes)

int ff_fcntl(int fd, int cmd, ...);
    // File control
    // Common: F_SETFL O_NONBLOCK, F_GETFL

struct hostent * ff_gethostbyname(const char *name);
    // DNS resolution (basic implementation)

struct hostent * ff_gethostbyname2(const char *name, int af);
    // DNS resolution (specify AF_INET or AF_INET6)
```

**Route Management**:
```c
int ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
                 struct linux_sockaddr *dst, struct linux_sockaddr *gw,
                 struct linux_sockaddr *netmask);
    // Routing operations
    // req: FF_ROUTE_ADD / FF_ROUTE_DEL / FF_ROUTE_CHANGE
    // flag: FF_RTF_HOST / FF_RTF_GATEWAY
```

**Zero-Copy Mbuf**:
```c
struct ff_mbuf * ff_mbuf_gethdr(void);
struct ff_mbuf * ff_mbuf_get(const void *data, uint16_t len);
void ff_mbuf_free(struct ff_mbuf *mbuf);
ssize_t ff_mbuf_copydata(struct ff_mbuf *mbuf, uint16_t off, uint16_t len, void *buf);

int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
    // Get a zero-copy mbuf (0 on success, -1 on failure)
ssize_t ff_zc_mbuf_write(int fd, struct ff_zc_mbuf *zm);
ssize_t ff_zc_mbuf_read(int fd, struct ff_zc_mbuf *zm);
    // Zero-copy I/O  [Note] ff_zc_mbuf_read is not yet implemented
```

**Logging Interface**:
```c
#define FF_LOGTYPE_EAL         0
#define FF_LOGTYPE_MALLOC      1
#define FF_LOGTYPE_RING        2
#define FF_LOGTYPE_MEMPOOL     3
#define FF_LOGTYPE_USER1       20
#define FF_LOGTYPE_USER8       27

int ff_log_open_set(void);
int ff_log_set_level(uint32_t logtype, uint32_t level);
int ff_log(uint32_t level, uint32_t logtype, const char *format, ...);

// Log levels (values start from 1, 0 means disabled)
#define FF_LOG_EMERG     1U
#define FF_LOG_ALERT     2U
#define FF_LOG_CRIT      3U
#define FF_LOG_ERR       4U
#define FF_LOG_WARNING   5U
#define FF_LOG_NOTICE    6U
#define FF_LOG_INFO      7U
#define FF_LOG_DEBUG     8U
```

**Multi-Threading Support**:
```c
int ff_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine)(void *), void *arg);
int ff_pthread_join(pthread_t thread, void **retval);
```

**System Interfaces**:
```c
int ff_gettimeofday(struct timeval *tv, struct timezone *tz);
int ff_clock_gettime(clockid_t clock_id, struct timespec *tp);
    // High-precision time (supports CLOCK_REALTIME / CLOCK_MONOTONIC)
```

#### **ff_epoll.h (3 Functions) - Epoll Compatibility**

Wraps ff_kqueue as epoll interface for Linux application compatibility.

#### **ff_config.h (352 Lines) - Configuration Interface**

**Core Structure**:

```c
struct ff_config {
    char *filename;

    struct {  // DPDK configuration
        char *proc_type;
        char *lcore_mask;         // CPU core mask (hexadecimal)
        char *proc_mask;
        char *base_virtaddr;
        char *file_prefix;
        char *allow;              // PCI whitelist
        int nb_channel;           // Number of memory channels
        int memory;               // Reserved memory (MB)
        int no_huge;
        int nb_procs;
        int proc_id;
        int promiscuous;          // Promiscuous mode
        int nb_vdev;
        int nb_bond;
        int numa_on;              // NUMA support
        int tso;
        int tx_csum_offoad_skip;
        int vlan_strip;
        int nb_vlan_filter;
        uint16_t vlan_filter_id[DPDK_MAX_VLAN_FILTER];
        int symmetric_rss;
        unsigned idle_sleep;
        unsigned pkt_tx_delay;
        uint16_t *proc_lcore;
        int nb_ports;
        uint16_t max_portid;
        uint16_t *portid_list;
        uint16_t log_level;
        struct ff_port_cfg *port_cfgs;
        struct ff_vlan_cfg *vlan_cfgs;
        struct ff_vdev_cfg *vdev_cfgs;
        struct ff_bond_cfg *bond_cfgs;
        struct ff_rss_check_cfg *rss_check_cfgs;
    } dpdk;

    struct {  // KNI configuration
        int enable;
        int console_packets_ratelimit;
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

    struct {  // FreeBSD boot parameters
        struct ff_freebsd_cfg *boot;
        struct ff_freebsd_cfg *sysctl;
        long physmem;
        int hz;                   // Clock frequency (1000 = 1kHz)
        int fd_reserve;           // Reserved fd count
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

#### **ff_event.h - Kevent Event Structure**

```c
struct kevent {
    uintptr_t ident;       // Event ID (socket fd)
    int16_t filter;        // Event filter (values are negative)
    uint16_t flags;        // Event flags
    uint32_t fflags;       // Filter flags
    __int64_t data;        // Data (ready count/error, fixed 64-bit)
    void *udata;           // User data pointer
    __uint64_t ext[4];     // FreeBSD 13/15 extended fields (KBI unchanged across 13.0 → 15.0; M2 verify-only)
};

// Supported filters (values are negative!)
#define EVFILT_READ     (-1)  // Socket readable
#define EVFILT_WRITE    (-2)  // Socket writable
#define EVFILT_TIMER    (-7)  // Timer
// ... 10 more types, see freebsd/sys/event.h

// Event flags
#define EV_ADD      0x0001   // Add event
#define EV_DELETE   0x0002   // Delete event
#define EV_ONESHOT  0x0010   // One-shot trigger
#define EV_CLEAR    0x0020   // Auto-clear (edge-triggered)
#define EV_EOF      0x8000   // Connection closed
```

#### **ff_errno.h (96 Error Codes)**

Provides POSIX/FreeBSD-compatible error numbers:

```c
#define ff_EPERM     1     // Operation not permitted
#define ff_ENOENT    2     // No such file or directory
#define ff_ECONNREFUSED  61  // Connection refused
#define ff_ETIMEDOUT 60   // Connection timed out
#define ff_ECONNRESET 54  // Connection reset
#define ff_EAGAIN    35    // Try again
#define ff_EINPROGRESS 36 // Operation in progress
// ... etc.
```

#### **ff_log.h - Logging Interface**

A structured logging system supporting multiple log types and levels.

---

## 2. System Call Mapping Table

F-Stack provides Linux-compatible system call interfaces, but relies on the FreeBSD protocol stack underneath. Key mappings:

### 2.1 Socket Operation Mapping

| Operation | F-Stack API | POSIX Standard | Key Differences |
|-----------|-------------|----------------|-----------------|
| Create | ff_socket() | socket() | Address format: linux_sockaddr |
| Bind | ff_bind() | bind() | Non-blocking enforced |
| Listen | ff_listen() | listen() | TCP only |
| Accept | ff_accept() | accept() | Returns new connection fd |
| Connect | ff_connect() | connect() | May return EINPROGRESS |
| Close | ff_close() | close() | Graceful close |

### 2.2 I/O Operation Mapping

| Operation | F-Stack API | POSIX Standard | Key Differences |
|-----------|-------------|----------------|-----------------|
| Read | ff_read() | read() | Non-blocking, returns -1 when no data |
| Write | ff_write() | write() | Returns -1 when buffer full, no partial send |
| Scatter read | ff_readv() | readv() | Same as above |
| Scatter write | ff_writev() | writev() | Same as above |
| Send | ff_send() | send() | flags: MSG_MORE, etc. |
| Receive | ff_recv() | recv() | Same as above |
| Send to | ff_sendto() | sendto() | UDP only |
| Send message | ff_sendmsg() | sendmsg() | Supports msghdr control info |
| Receive from | ff_recvfrom() | recvfrom() | UDP only |
| Receive message | ff_recvmsg() | recvmsg() | Supports msghdr control info |

### 2.3 Event Multiplexing Mapping

| Operation | F-Stack API | POSIX Standard | Key Differences |
|-----------|-------------|----------------|-----------------|
| Create queue | ff_kqueue() | epoll_create() | Uses BSD kqueue |
| Register events | ff_kevent() | epoll_ctl() | kevent format |
| Wait for events | ff_kevent() + ff_epoll_wait() | epoll_wait() | Supports timeout |
| Iterate events | ff_kevent_do_each() | N/A | Convenience function |

### 2.4 Socket Option Mapping

#### **Linux SOL_SOCKET Options → FreeBSD Mapping**

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

#### **Linux IPPROTO_IP Options → FreeBSD Mapping**

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

#### **Linux IPPROTO_TCP Options → FreeBSD Mapping**

```c
#define LINUX_TCP_NODELAY      1     → TCP_NODELAY
#define LINUX_TCP_MAXSEG       2     → TCP_MAXSEG
#define LINUX_TCP_CORK         3     → TCP_CORK
#define LINUX_TCP_KEEPIDLE     4     → TCP_KEEPIDLE
#define LINUX_TCP_KEEPINTVL    5     → TCP_KEEPINTVL
#define LINUX_TCP_KEEPCNT      6     → TCP_KEEPCNT
```

#### **Linux IOCTL → FreeBSD IOCTL Mapping**

```c
#define LINUX_FIONBIO         0x5421    // Set non-blocking
#define LINUX_FIONREAD        0x541B    // Query readable bytes
#define LINUX_SIOCGIFFLAGS    0x8913    // Get NIC flags
#define LINUX_SIOCGIFADDR     0x8915    // Get NIC IP
#define LINUX_SIOCGIFNETMASK  0x891B    // Get NIC netmask
```

---

## 3. In-Depth Analysis of the Configuration System

### 3.1 Configuration File Structure (config.ini)

F-Stack uses INI format configuration files, loaded via `ff_load_config()`:

```ini
# Example configuration
[dpdk]
lcore_mask = 0xf              # Use cores 0-3 (hexadecimal)
channel = 4                   # Number of memory channels
memory = 4096                 # Reserved memory (MB)
promiscuous = 1               # Promiscuous mode
numa_on = 1                   # NUMA support
port_list = 0,1               # Use NICs 0 and 1
nb_vdev = 0                   # Number of virtual devices
nb_bond = 0                   # Number of bonding NICs
tso = 1                       # Enable TSO (hardware segmentation)
vlan_strip = 1                # VLAN hardware tag stripping
symmetric_rss = 0             # Bidirectional RSS symmetry
idle_sleep = 0                # Idle sleep (microseconds)
pkt_tx_delay = 100            # Packet TX delay (set 0 for immediate send)
enable_kni = 1                # Enable virtual NIC

[port0]
addr = 10.0.0.1
netmask = 255.255.255.0
gateway = 10.0.0.254
broadcast = 10.0.0.255
vip_addr = 10.0.0.100; 10.0.0.101; 10.0.0.102
addr6 = 2001:db8::1
prefix_len = 64
gateway6 = 2001:db8::ff
ipfw_pr = 10.0.0.100 255.255.255.0;192.168.0.0 255.255.255.0
lcore_list = 0,1

[port1]
addr = 192.168.1.1
netmask = 255.255.255.0
gateway = 192.168.1.254

[vlan<vlan id>]
# VLAN configuration (higher priority than [portN])
portid = 0
addr = 172.16.0.1
netmask = 255.255.0.0
gateway = 172.16.0.1
broadcast = 172.16.255.255

[kni]
enable=1
method=reject
tcp_port=80,443
udp_port=53

[stack]
kernel_coexist = 0           # Kernel-stack coexistence (only when built with
                             # FF_KERNEL_COEXIST=1). 0=off (pure F-Stack, default),
                             # 1=on (SOCK_KERNEL sockets also use the host kernel stack)

[freebsd.boot]
hz = 100                     # Clock frequency (Hz)
fd_reserve = 1204
kern.ipc.maxsockets = 1000000

[freebsd.sysctl]
kern.ipc.somaxconn = 32768
net.inet.tcp.syncache.hashsize = 4096
net.inet.tcp.syncache.bucketlimit = 100
net.inet.tcp.cc.algorithm = cubic
net.inet.tcp.functions_default=freebsd    # freebsd/rack/bbr
net.inet.tcp.sendspace = 16384            # Send buffer (bytes)
net.inet.tcp.recvspace = 8192             # Receive buffer
net.inet.tcp.sack.enable = 1              # SACK selective acknowledgment
net.inet.tcp.rfc1323 = 1                  # Timestamp option
net.inet.tcp.delayed_ack = 1              # Delayed ACK: 1 for high throughput, 0 for low latency
```

### 3.2 Configuration Priority Rules

```
Configuration priority order (highest to lowest):
1. VLAN configuration ([vlanN]) - Used if defined
2. Port configuration ([portN])
3. Command-line arguments (e.g., DPDK -l option)
4. Compile-time defaults
5. Hardcoded values in source code

Note: If both [port0] and [vlan0] are defined, [vlan0] takes effect and [port0] is ignored
```

### 3.3 Configuration Loading Flow

```c
// ff_config.c
ff_load_config(argc, argv)
  ├─ 1. Parse command-line arguments
  │     (e.g., --config-file /path/config.ini)
  ├─ 2. Open configuration file
  ├─ 3. Parse INI format line by line
  │     [section] markers
  │     key = value pairs
  ├─ 4. Validate configuration
  │     (address ranges, core count, etc.)
  ├─ 5. Convert to struct ff_config
  └─ 6. Generate DPDK parameter array
        (passed to rte_eal_init)
```

### 3.4 Kernel-Stack Coexistence Interface (`FF_KERNEL_COEXIST`, optional)

When the library is built with `make FF_KERNEL_COEXIST=1` and `config.ini [stack] kernel_coexist=1`, the application can place individual sockets on the host Linux kernel stack while everything else keeps using the F-Stack fast path — all from the same process and event loop. The contract is intentionally small and additive (no existing signature changes):

**Per-socket stack markers** (defined in `ff_api.h`, only under `FF_KERNEL_COEXIST`):

```c
#define SOCK_FSTACK 0x01000000   // force the F-Stack user-space stack
#define SOCK_KERNEL 0x02000000   // force the host Linux kernel stack

int fk = ff_socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);  // kernel-stack socket
int ff = ff_socket(AF_INET, SOCK_STREAM | SOCK_FSTACK, 0);  // F-Stack socket
int du = ff_socket(AF_INET, SOCK_STREAM, 0);                // dual-created (default)
```

| `type` flag | Behaviour when `kernel_coexist=1` | Returned fd |
|-------------|-----------------------------------|-------------|
| `SOCK_KERNEL` (no `SOCK_FSTACK`) | host kernel socket only | managed kernel fd = `host_fd + 0x40000000` |
| `SOCK_FSTACK` | F-Stack socket only | F-Stack fd |
| neither (default) | **dual-created**: F-Stack + paired host socket | F-Stack fd (host fd kept in `ff_native_fd_map`) |

Priority: per-socket marker > `config.ini [stack] kernel_coexist` > F-Stack. When the macro is not compiled in, the markers are undefined and `ff_socket` behaves exactly as before.

**Transparent routing.** All standard `ff_*` calls accept a managed kernel fd transparently: `ff_bind/listen/connect/accept[4]/close/read/write/recv*/send*/sendmsg/recvmsg/getpeername/getsockname/shutdown/setsockopt/getsockopt/fcntl`, and `ff_epoll_ctl/wait`. Internally each kernel fd is forwarded to a thin `ff_host_*` host-libc bridge (`lib/ff_host_interface.c`). **Since R10 also accepted transparently:** `ff_readv` / `ff_writev` / `ff_ioctl` / `ff_dup` / `ff_dup2` (kernel fd via the matching `ff_host_*` bridge; `ff_ioctl` uses the raw Linux request; `ff_dup2` cross-stack rejected `errno=EINVAL`). Full design and tests: `docs/kernel_event_support_spec/`.

**R9 — kqueue/kevent coexistence + IPv6.** The unified-event support now also covers the native `ff_kqueue` / `ff_kevent` interface (previously only `ff_epoll_*`): each kqueue lazily pairs one host epoll (shared `ff_epoll_host_ep`, reusing the `ff_epoll_pairs` table). `ff_kevent` registers a kernel/dual-stack fd's `EVFILT_READ/WRITE` into that host epoll (kernel-only changes are not forwarded to the F-Stack kqueue), and on wait it synthesizes `struct kevent` (`ident`=the app-side fd, `EV_EOF`↔`EPOLLHUP|ERR`) from a non-blocking host-epoll poll before merging F-Stack kqueue events. This makes a pure-kqueue application (e.g. `example/main.c`) reach the kernel-side listener — measured `curl 127.0.0.1:80` = 200 size=438. Kernel fds via kqueue support `EVFILT_READ/WRITE` only. On the IPv6 side, a dual-built `AF_INET6` socket has its host counterpart set to `IPV6_V6ONLY=1` (`ff_host_set_v6only`) so a `-DINET6` build starts cleanly with v4+v6 on the same port (fixes the prior host-IPv6 `errno=98 EADDRINUSE`).

**R10 — residual-entry coexistence.** `ff_readv`/`ff_writev` (kernel fd → `ff_host_readv/writev`, mimic read/write, connection fds single-stack hot path), `ff_ioctl` (kernel fd uses the **raw Linux request** straight to `ff_host_ioctl`, NOT via `linux2freebsd_ioctl`; dual-stack fd same-driver since R10.1 syncs `FIONBIO`/`FIOASYNC` to the paired host fd (query ioctls like `FIONREAD` not forwarded, to avoid clobbering argp)), `ff_dup` (kernel fd → `ff_host_dup`+encode), `ff_dup2` (both-kernel → `ff_host_dup2`+encode; cross-stack rejected `errno=EINVAL`). Adds 5 host bridges `ff_host_readv/writev/ioctl/dup/dup2`. Known limitation: `ff_select` (encode kernel fd ≫ `FD_SETSIZE` hard limit) / `ff_poll` (conservatively not implemented) do not support kernel-fd coexistence — use `ff_epoll_*`/`ff_kqueue`.

---

## 4. Multi-Process and Multi-Thread Interfaces

### 4.1 Multi-Process Model (Primary-Secondary)

F-Stack adopts DPDK's Primary-Secondary process model:

#### **Primary Process**

```c
// Command-line setting at startup
proc_type=primary proc_id=0

ff_init(argc, argv)
  ├─ Initialize DPDK EAL (rte_eal_init)
  │   ├─ Allocate hugepage memory
  │   ├─ Create shared memory mapping
  │   └─ Initialize core 0
  ├─ Create mempool (shared by all processes)
  ├─ Initialize NIC (rte_eth_dev_configure)
  ├─ Start NIC (rte_eth_dev_start)
  └─ Enter polling loop (ff_run)
       ├─ Receive/process packets
       └─ Handle IPC messages from workers
```

#### **Secondary Process**

```c
// Command-line setting at startup
proc_type=secondary proc_id=1  // Different secondary processes use different IDs

ff_init(argc, argv)
  ├─ Connect to DPDK shared memory (created by primary process)
  │   ├─ Map hugepage memory
  │   ├─ Connect to mempool
  │   └─ Access NIC configuration
  ├─ Initialize local FreeBSD stack instance
  └─ Enter polling loop (ff_run)
       ├─ Receive/process packets belonging to this process (via RSS)
       └─ Optional: Send IPC messages to primary process
```

#### **Process Startup Script Example**

```bash
# Use F-Stack's built-in start.sh to launch (recommended)
# start.sh parameter description:
#   -c [conf]   Configuration file path (default: config.ini)
#   -b [bin]    Application path (default: ./example/helloworld)
#   -o [args]   Extra arguments passed to the application

# Example: Launch a custom application with config.ini
bash start.sh -c config.ini -b ./app

# start.sh will automatically:
# 1. Read lcore_mask from config.ini to determine the number of processes
# 2. Start primary process: ./app --conf config.ini --proc-type=primary --proc-id=0
# 3. Wait 5 seconds then sequentially start secondary processes:
#    ./app --conf config.ini --proc-type=secondary --proc-id=1
#    ./app --conf config.ini --proc-type=secondary --proc-id=2

# To pass extra arguments to the application:
bash start.sh -c config.ini -b ./app -o "--extra-arg value"
```

### 4.2 Inter-Process Communication (IPC)

F-Stack implements efficient inter-process message passing via DPDK Ring:

#### **IPC Message Structure**

```c
struct ff_msg {
    uint32_t msg_type;           // Message type
    uint32_t msg_id;             // Message ID (for matching request/response)
    uint32_t msg_len;            // Message length

    union {
        struct {
            uint32_t sysctl_id;
            uint32_t value;
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

        char data[256];          // Generic data
    } msg_body;
};

// Message types
#define FF_MSG_SYSCTL       1
#define FF_MSG_IOCTL        2
#define FF_MSG_ROUTE        3
#define FF_MSG_TOP          4
#define FF_MSG_TRAFFIC      5
#define FF_MSG_NGCTL        6
#define FF_MSG_IPFW_CTL     7
#define FF_MSG_KNICTL       8
```

#### **IPC Communication Example**

```c
// Secondary process querying parameters from primary process

// Step 1: Connect to primary process
ff_ipc_init();  // Initialize IPC (connect to primary process's Ring)

// Step 2: Allocate message
struct ff_msg *msg = ff_ipc_msg_alloc();

// Step 3: Fill in request
msg->msg_type = FF_MSG_TRAFFIC;
msg->msg_id = 1;

// Step 4: Send to primary process
ff_ipc_send(msg);

// Step 5: Wait for response
struct ff_msg *retmsg = NULL;
ff_ipc_recv(&retmsg, FF_MSG_TRAFFIC);

// Step 6: Read response
printf("TX packets: %lu\n", retmsg->msg_body.traffic.tx_packets);

// Step 7: Free messages
ff_ipc_msg_free(msg);
ff_ipc_msg_free(retmsg);
```

### 4.3 Multi-Thread Interface

F-Stack provides basic multi-threading support, but sockets are **not shared** between threads:

```c
// Create a thread
pthread_t thread;
int ret = ff_pthread_create(&thread, NULL, thread_func, arg);

// Each thread must:
// 1. Call ff_init() - Create an independent FreeBSD stack instance
// 2. Obtain an independent lcore number
// 3. Use ff_run() to enter the polling loop

// Thread safety
// ✓ Socket operations within the same thread are safe
// ✗ Sockets cannot be shared across threads
// ✗ Cannot create new threads after ff_run()
```

**Example - Multi-Threaded Application**:

```c
struct thread_arg {
    int thread_id;
    const char *bind_addr;
    int bind_port;
};

void *thread_func(void *arg) {
    struct thread_arg *ta = (struct thread_arg *)arg;
    ff_init(0, NULL);  // Obtain independent lcore

    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ta->bind_port),
        .sin_addr.s_addr = inet_addr(ta->bind_addr)
    };

    ff_bind(sockfd, (struct linux_sockaddr *)&addr, sizeof(addr));
    ff_listen(sockfd, 128);
    ff_run(my_loop, (void *)(intptr_t)sockfd);
    return NULL;
}

int main() {
    pthread_t threads[4];
    struct thread_arg args[4] = {
        {0, "10.0.0.1", 80}, {1, "10.0.0.2", 80},
        {2, "10.0.0.3", 80}, {3, "10.0.0.4", 80}
    };
    for (int i = 0; i < 4; i++)
        ff_pthread_create(&threads[i], NULL, thread_func, &args[i]);
    for (int i = 0; i < 4; i++)
        ff_pthread_join(threads[i], NULL);
    return 0;
}
```

---

## 5. Application Development Guidelines

### 5.1 Three Development Modes

#### **Mode 1: Kqueue (Recommended)**

```c
#include <ff_api.h>

int main_loop(void *arg) {
    // Event-ready handler function
    // Called once per polling cycle; must return within 100μs

    int kq = (int)(intptr_t)arg;
    struct kevent events[64];
    int nevents = ff_kevent(kq, NULL, 0, events, 64, NULL);

    for (int i = 0; i < nevents; i++) {
        if (events[i].flags & EV_EOF) {
            ff_close((int)events[i].ident);
        } else if (events[i].filter == EVFILT_READ) {
            char buf[4096];
            ssize_t n = ff_read((int)events[i].ident, buf, sizeof(buf));
            // Process the read data
        } else if (events[i].filter == EVFILT_WRITE) {
            // Write buffer has space, can continue sending
        }
    }
    return 0;
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
    ff_run(main_loop, (void *)(intptr_t)kq);
    return 0;
}
```

#### **Mode 2: Epoll (Linux Compatible)**

```c
#include <ff_api.h>

int main_loop(void *arg) {
    int epfd = (int)(intptr_t)arg;
    struct epoll_event events[64];
    int nevents = ff_epoll_wait(epfd, events, 64, 0);  // Non-blocking

    for (int i = 0; i < nevents; i++) {
        int fd = events[i].data.fd;
        if (events[i].events & EPOLLIN)
            ff_read(fd, buf, sizeof(buf));
        if (events[i].events & EPOLLOUT)
            ff_write(fd, data, len);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    ff_init(argc, argv);
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    // ... bind/listen ...
    int epfd = ff_epoll_create(0);
    struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT, .data.fd = sockfd };
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    ff_run(main_loop, (void *)(intptr_t)epfd);
    return 0;
}
```

### 5.2 Key Development Guidelines

**Rule 1: Mandatory Non-Blocking**
```c
int flags = 1;
ff_ioctl(sockfd, FIONBIO, &flags);  // Must set!
```

**Rule 2: Main Loop Time Limit**
```c
// ✗ Wrong: Blocks too long
int main_loop(void *arg) { sleep(1); return 0; }

// ✓ Correct: Keep within 100μs
int main_loop(void *arg) {
    ff_kevent(...);  // Non-blocking query
    return 0;
}
```

**Rule 3: Write Buffer Management**
```c
// ✗ Wrong: Assume ff_write always succeeds
ssize_t n = ff_write(fd, data, len);

// ✓ Correct: Monitor EVFILT_WRITE events
ssize_t n = ff_write(fd, data, len);
if (n < 0) {
    struct kevent kev;
    EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
    ff_kevent(kq, &kev, 1, NULL, 0, NULL);
}
```

**Rule 4: Connection Close Handling**
```c
// ✓ Correct: Check EV_EOF first
if (events[i].flags & EV_EOF) {
    ff_close(fd);
} else if (events[i].filter == EVFILT_READ) {
    ff_read(fd, buf, size);
}
```

**Rule 5: Socket Thread Isolation**
```c
// ✗ Wrong: Share socket across threads
int sockfd = ff_socket(...);  // Created in main thread
ff_pthread_create(&tid, NULL, worker_thread, (void *)(intptr_t)sockfd);

// ✓ Correct: Each thread creates its own socket
void *worker_thread(void *arg) {
    int sockfd = ff_socket(...);  // Created within thread
}
```

### 5.3 Common Pitfalls and Solutions

| Pitfall | Symptom | Root Cause | Solution |
|---------|---------|------------|----------|
| FIONBIO not set | Deadlock/latency | Socket in blocking mode | `ff_ioctl(fd, FIONBIO, &on)` |
| Main loop too long | Packet loss/latency | Polling blocked | Keep loop function < 100μs |
| Cross-thread socket sharing | Crash/race condition | FreeBSD stack not thread-safe | Thread-isolate sockets |
| EV_EOF ignored | fd leak/anomaly | Unhandled connection close | Check `ev.flags & EV_EOF` |
| Write buffer full unhandled | Data loss | ff_write returns -1 | Monitor EVFILT_WRITE and retry |
| Config file missing | Init failure | Wrong path | Check config.ini location |
| Insufficient memory (hugepage) | Init failure | Hugepage allocation failed | `sysctl vm.nr_hugepages=2048` |
| Inadequate CPU isolation | Performance degradation | CPU occupied by other processes | Use CPU affinity tools |

### 5.4 Performance Optimization Tips

**1. Adjust Socket Buffers**
```ini
[freebsd.sysctl]
net.inet.tcp.sendspace = 65536    # 64KB send buffer
net.inet.tcp.recvspace = 65536    # 64KB receive buffer
```

**2. Enable TSO (TCP Segmentation Offload)**
```ini
[dpdk]
tso = 1  # Enable hardware TSO
```

**3. Optimize Packet TX Delay**
```ini
[dpdk]
pkt_tx_delay = 0  # Send immediately, do not wait for batch
```

**4. Enable Symmetric RSS**
```ini
[dpdk]
symmetric_rss = 1  # Bidirectional connections to same queue
```

**5. TCP Algorithm Selection**
```ini
[freebsd.sysctl]
# High-latency network: bbr (Bottleneck Bandwidth and Round-trip time)
# hz=1000000
# net.inet.tcp.functions_default=bbr

# Low-latency network: cubic (default, balanced)
# hz=100
# net.inet.tcp.functions_default=freebsd
# net.inet.tcp.cc.algorithm = cubic

# Specific scenarios: rack (TCP Selective Acknowledgment)
# hz=1000000
# net.inet.tcp.functions_default=rack
```

---

## 6. Tools and Integration Interfaces

### 6.1 IPC Tool List

| Tool | Purpose | Underlying Message Type | Example Command |
|------|---------|------------------------|-----------------|
| **top** | Real-time CPU stats | FF_TOP | `top -p <pid>` |
| **sysctl** | Parameter query/modify | FF_SYSCTL | `sysctl net.inet.tcp.sendspace` |
| **ifconfig** | NIC status | Direct config read | `ifconfig -a` |
| **route** | Routing table management | FF_ROUTE | `route add/del` |
| **netstat** | Network statistics | FF_TRAFFIC | `netstat -s` |
| **arp** | ARP table query | Direct memory read | `arp -a` |
| **ipfw** | Firewall rules | FF_IPFW_CTL | `ipfw add ...` |
| **knictl** | Virtual NIC control | FF_KNICTL | `knictl set-rate ...` |
| **traffic** | Traffic statistics export | FF_TRAFFIC | `traffic -p <proc_id> -d <secs>` |
| **ndp** | IPv6 Neighbor Discovery | ioctl (SIOCGNBRINFO_IN6) | `ndp -C <proc_id> -a` |
| **ngctl** | Netgraph control | FF_NGCTL | `ngctl -p <proc_id> list` |

### 6.2 Application Integration Interfaces

**Direct Call Mode**: Application directly links `libfstack.a` and calls `ff_*` APIs.

**LD_PRELOAD Mode**: Application is preloaded with `libff_syscall.so` (built from
`adapter/syscall/`); it runs as a **separate process** from the `fstack` instance
binary and the two communicate over Hugepage shared memory. The default IPC path is
semaphore-based; setting `FF_USE_RING_IPC=1` switches to a lock-free DPDK SPSC ring.
The `fstack` instance must be started before the LD_PRELOAD application.

```bash
# Start the fstack instance(s) first
./fstack --conf config.ini --proc-type=primary --proc-id=0 &

# Nginx integration
LD_PRELOAD=/path/to/libff_syscall.so /usr/sbin/nginx -g "daemon off;"

# Redis integration
LD_PRELOAD=/path/to/libff_syscall.so /usr/bin/redis-server /etc/redis.conf

# Custom application
LD_PRELOAD=/path/to/libff_syscall.so ./my_app
```

Hooked POSIX entries include `socket / bind / connect / accept / accept4 / listen /
close / read / write / send / sendto / sendmsg / recv / recvfrom / recvmsg /
__read_chk / __recv_chk / __recvfrom_chk / ioctl / epoll_create|ctl|wait / fork`.

Common runtime / compile switches:

| Switch | Default | Effect |
|---|---|---|
| `FF_KERNEL_EVENT` | off | Forward kernel-only fds to host epoll in parallel |
| `FF_MULTI_SC` | off | SO_REUSEPORT-style multi-sc, one sc per worker fd |
| `FF_USE_RING_IPC` | off | Switch IPC to lock-free DPDK SPSC ring (v3.4 opts on by default) |

For the full design, supported modes, environment variables, performance notes and
known limitations, see `adapter/syscall/README.md`.

---

## Summary

**Key Interface Features**:
1. **POSIX-Compatible** - Linux applications can migrate without modification
2. **Mandatory Non-Blocking** - All I/O operations are non-blocking
3. **Event-Driven** - Multiple modes: Kqueue/Epoll/Select
4. **Multi-Process Support** - Primary-Secondary model with IPC communication
5. **Hardware Acceleration** - Full use of RSS/TSO/Checksum and other offloads

**Development Path**:
1. Write a main_loop callback to handle events
2. Register sockets to kqueue/epoll
3. Call ff_run() to enter the polling loop
4. Use IPC tools for operations management

---

**Related Documents**:
- [Layer 1: System Architecture Overview](./F-Stack_Architecture_Layer1_System_Overview.md)
- [Layer 3: Function-Level Index](./F-Stack_Architecture_Layer3_Function_Index.md)
- [Knowledge Base Summary](./F-Stack_Knowledge_Base_Summary.md)
