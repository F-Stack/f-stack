# F-Stack v1.26 Layer 3 Architecture Analysis: Function-Level Index & Data Models

**Document Version**: 1.0  
**Analysis Date**: 2026-03-20  
**Coverage**: F-Stack v1.26 Exported Functions, Data Structures, Thread Safety (FreeBSD 15.0 port; runtime-fix landing functions catalogued)  
**Target Audience**: Kernel Developers, Performance Analysts, Debugging Engineers

---

## 1. Complete Function Export List

### 1.1 Overview of 80+ Exported Functions by Category

F-Stack defines all public symbols through `/data/workspace/f-stack/lib/ff_api.symlist`. The following is the complete list categorized by functionality:

#### **Lifecycle Management (3)**

```c
int ff_init(int argc, char * const argv[])
    // Initialize the F-Stack library
    // Must be called first, only by the primary process
    // Parameters: Command-line arguments in DPDK EAL format
    // Returns: 0 on success, -1 on failure
    // Thread safety: No (call only during initialization)

void ff_run(loop_func_t loop, void *arg)
    // Start the main polling loop
    // Called once per lcore
    // Parameters: User callback function pointer, callback argument
    // Does not return (unless ff_stop_run() is called)
    // Thread safety: No (blocks until stopped)

void ff_stop_run(void)
    // Stop the polling loop
    // Can be called from any thread
    // Graceful shutdown, waits for all packet processing to complete
    // Thread safety: Yes (atomic operation)
```

#### **Socket Lifecycle (12)**

```c
int ff_socket(int domain, int type, int protocol)
    // Create a socket
    // domain: AF_INET(=2) / AF_INET6(=10 Linux/28 FreeBSD)
    // type: SOCK_STREAM(1) / SOCK_DGRAM(2) / SOCK_RAW(3)
    // protocol: 0 (auto), IPPROTO_TCP(6), IPPROTO_UDP(17)
    // Returns: fd >= 0, -1 on error
    // Thread safety: Yes (per-thread socket table)

int ff_bind(int sockfd, const struct linux_sockaddr *addr, socklen_t addrlen)
    // Bind a local address
    // addr: Pointer to sockaddr structure
    // addrlen: Size of the address structure
    // Returns: 0 on success, -1 on failure + errno
    // Thread safety: Yes (fd isolation)

int ff_listen(int sockfd, int backlog)
    // Mark socket as listening state (TCP only)
    // backlog: Size of the pending connection queue
    // Returns: 0 on success, -1 on failure
    // Thread safety: Yes

int ff_accept(int sockfd, struct linux_sockaddr *addr, socklen_t *addrlen)
    // Accept a new connection (TCP only)
    // Returns: New socket fd, -1 on error
    // Returns the address to the addr structure
    // Thread safety: Yes

int ff_accept4(int sockfd, struct linux_sockaddr *addr, socklen_t *addrlen, int flags)
    // Enhanced version of ff_accept(), supports flags (e.g., SOCK_NONBLOCK)
    // Thread safety: Yes

int ff_connect(int sockfd, const struct linux_sockaddr *addr, socklen_t addrlen)
    // Establish a connection (TCP only)
    // Non-blocking: May return -1 + errno=EINPROGRESS
    // Monitor EVFILT_WRITE to detect connection completion
    // Returns: 0 on success, -1 on failure
    // Thread safety: Yes

int ff_close(int sockfd)
    // Close a socket
    // Waits for all pending data to be sent, graceful close
    // Returns: 0 on success, -1 on failure
    // Thread safety: Yes

int ff_shutdown(int sockfd, int how)
    // Shut down one or both directions of communication
    // how: SHUT_RD(0), SHUT_WR(1), SHUT_RDWR(2)
    // Thread safety: Yes

int ff_dup(int oldfd)
    // Duplicate a file descriptor (returns the lowest available fd)
    // Thread safety: Yes

int ff_dup2(int oldfd, int newfd)
    // Duplicate a file descriptor (to a specified target fd)
    // Thread safety: Yes

int ff_dup3(int oldfd, int newfd, int flags)
    // Enhanced version of ff_dup2(), supports flags
    // Thread safety: Yes

int ff_getpeername(int sockfd, struct linux_sockaddr *addr, socklen_t *addrlen)
    // Get the peer address
    // Thread safety: Yes
```

#### **Data I/O Operations (13)**

```c
ssize_t ff_read(int fd, void *buf, size_t nbytes)
    // Read data
    // Returns: > 0 actual bytes read, 0 EOF, -1 error
    // errno is set on error
    // Non-blocking: Returns -1 + EAGAIN when no data available
    // Thread safety: Yes

ssize_t ff_write(int fd, const void *buf, size_t nbytes)
    // Write data
    // Returns: > 0 actual bytes sent, -1 buffer full or error
    // Note: Returns -1 when buffer is full, NOT partial send!
    // Should monitor EVFILT_WRITE event then retry
    // Thread safety: Yes

ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt)
    // Scatter-gather read
    // iov: Pointer to iovec array
    // iovcnt: Number of elements in the iovec array
    // Thread safety: Yes

ssize_t ff_writev(int fd, const struct iovec *iov, int iovcnt)
    // Scatter-gather write
    // Thread safety: Yes

ssize_t ff_pread(int fd, void *buf, size_t nbytes, off_t offset)
    // Read from a specified offset (files only)
    // Thread safety: Yes

ssize_t ff_pwrite(int fd, const void *buf, size_t nbytes, off_t offset)
    // Write to a specified offset (files only)
    // Thread safety: Yes

ssize_t ff_send(int fd, const void *buf, size_t len, int flags)
    // Send data (TCP/UDP)
    // flags: MSG_MORE (do not send immediately), MSG_OOB (out-of-band data)
    // Thread safety: Yes

ssize_t ff_sendto(int fd, const void *buf, size_t len, int flags,
                  const struct linux_sockaddr *to, socklen_t tolen)
    // Send data to a specified address (UDP only)
    // Thread safety: Yes

ssize_t ff_sendmsg(int fd, const struct msghdr *msg, int flags)
    // Send a message (using msghdr structure, supports control information)
    // Thread safety: Yes

ssize_t ff_recv(int fd, void *buf, size_t len, int flags)
    // Receive data (TCP/UDP)
    // Thread safety: Yes

ssize_t ff_recvfrom(int fd, void *buf, size_t len, int flags,
                    struct linux_sockaddr *from, socklen_t *fromlen)
    // Receive data and source address (UDP)
    // Thread safety: Yes

ssize_t ff_recvmsg(int fd, struct msghdr *msg, int flags)
    // Receive a message (supports control information)
    // Thread safety: Yes

ssize_t ff_recvfrom_timeout(int fd, void *buf, size_t len, int flags,
                           struct linux_sockaddr *from, socklen_t *fromlen,
                           int timeout)
    // Enhanced version of ff_recvfrom(), supports timeout
    // Thread safety: Yes
```

#### **Event Multiplexing (7)**

```c
int ff_kqueue(void)
    // Create a kqueue event object
    // Returns: kqueue fd, -1 on error
    // Thread safety: Yes

int ff_kevent(int kq, const struct kevent *changelist, int nchanges,
              struct kevent *eventlist, int nevents,
              const struct timespec *timeout)
    // Register events and wait for events to be ready
    // changelist: Array of events to register (may be NULL)
    // eventlist: Array of ready events to return
    // timeout: NULL for blocking, 0 for non-blocking, > 0 for timeout
    // Returns: Number of ready events, -1 on error
    // Thread safety: Yes

void ff_kevent_do_each(int kq, struct kevent *changelist, int nchanges,
                       void (*callback)(struct kevent *kev, void *arg),
                       void *arg)
    // Convenience function: calls kevent once and invokes callback for each event
    // Thread safety: Yes

int ff_select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout)
    // select() implementation (for compatibility, not recommended)
    // Thread safety: Yes

int ff_poll(struct pollfd *fds, nfds_t nfds, int timeout)
    // poll() implementation (for compatibility, not recommended)
    // timeout: -1 blocking, 0 non-blocking, > 0 milliseconds
    // Thread safety: Yes

// Epoll compatibility (3)
int ff_epoll_create(int size)
    // Create an epoll object (actually calls ff_kqueue)
    // Thread safety: Yes

int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
    // Register/modify/delete epoll events
    // op: EPOLL_CTL_ADD(1) / EPOLL_CTL_MOD(2) / EPOLL_CTL_DEL(3)
    // Thread safety: Yes

int ff_epoll_wait(int epfd, struct epoll_event *events, 
                  int maxevents, int timeout)
    // Wait for epoll events
    // timeout: -1 blocking, 0 non-blocking, > 0 milliseconds
    // Thread safety: Yes
```

#### **Socket Option Operations (6)**

```c
int ff_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
    // Set socket options
    // level: SOL_SOCKET / IPPROTO_IP / IPPROTO_TCP / IPPROTO_IPV6
    // optname: SO_* / IP_* / TCP_* constants
    // Thread safety: Yes

int ff_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
    // Get socket option values
    // Thread safety: Yes

int ff_ioctl(int fd, unsigned long request, ...)
    // I/O control (variadic)
    // Common: FIONBIO (non-blocking), FIONREAD (readable bytes)
    // Thread safety: Yes

int ff_fcntl(int fd, int cmd, ...)
    // File control (variadic)
    // cmd: F_GETFL / F_SETFL / F_GETFD / F_SETFD
    // Thread safety: Yes

struct hostent * ff_gethostbyname(const char *name)
    // Domain name → IPv4 address (basic implementation)
    // Returns: hostent pointer, NULL on error
    // Thread safety: No (returns static buffer, requires mutex)

struct hostent * ff_gethostbyname2(const char *name, int af)
    // Domain name → address (supports AF_INET / AF_INET6)
    // Thread safety: No
```

#### **Route Management (1)**

```c
int ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
                 struct linux_sockaddr *dst, struct linux_sockaddr *gw,
                 struct linux_sockaddr *netmask)
    // Routing table operations
    // req:  FF_ROUTE_ADD / FF_ROUTE_DEL / FF_ROUTE_CHANGE
    // flag: FF_RTF_HOST / FF_RTF_GATEWAY
    // dst: Destination network address
    // gw: Gateway address
    // netmask: Subnet mask
    // Returns: 0 on success, -1 on failure
    // Thread safety: Yes
```

#### **Zero-Copy Mbuf (5)**

```c
struct ff_mbuf * ff_mbuf_gethdr(void)
    // Get an empty mbuf header
    // Returns: mbuf pointer, NULL on error
    // Thread safety: Yes (lock-free allocation from memory pool)

struct ff_mbuf * ff_mbuf_get(const void *data, uint16_t len)
    // Create an mbuf containing data
    // Returns: New mbuf, NULL on error
    // Thread safety: Yes

void ff_mbuf_free(struct ff_mbuf *mbuf)
    // Free an mbuf (return to memory pool)
    // Thread safety: Yes

ssize_t ff_mbuf_copydata(struct ff_mbuf *mbuf, uint16_t off,
                         uint16_t len, void *buf)
    // Copy data from mbuf to buffer
    // off: Offset (bytes)
    // len: Length to copy
    // Returns: Actual bytes copied, -1 on error
    // Thread safety: Yes

// Zero-Copy send/receive (3)
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len)
    // Allocate a zero-copy mbuf chain (caller provides pre-allocated struct ff_zc_mbuf)
    // m: Caller-allocated ff_zc_mbuf pointer (must not be NULL)
    // len: Total length of mbuf chain to allocate
    // Returns: 0 on success, -1 on failure
    // Thread safety: Yes

int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len)
    // Write data to mbuf chain in zero-copy mode (caller then sends with ff_write)
    // Requires prior call to ff_zc_mbuf_get
    // Thread safety: Yes

int ff_zc_mbuf_read(struct ff_zc_mbuf *m, const char *data, int len)
    // Zero-copy read (not yet implemented, planned for future support)
    // Thread safety: Yes
```

#### **Multi-Threading Support (2)**

```c
int ff_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine)(void *), void *arg)
    // Create a thread (wraps pthread_create)
    // Each thread must independently call ff_init() and ff_run()
    // Thread safety: Yes

int ff_pthread_join(pthread_t thread, void **retval)
    // Wait for thread termination (wraps pthread_join)
    // Thread safety: Yes
```

#### **Logging and Diagnostics (8)**

```c
int ff_log_open_set(void)
    // Open the F-Stack log file (path and level read from config.ini)
    // Returns: 0 on success, -1 on failure
    // Thread safety: No (requires external synchronization)

int ff_log_reset_stream(void *f)
    // Reset log output stream (f is FILE *, managed by the application)
    // Used to redirect logs to a custom FILE stream
    // Thread safety: No

void ff_log_set_global_level(uint32_t level)
    // Set the global log level
    // Thread safety: No

int ff_log_set_level(uint32_t logtype, uint32_t level)
    // Set the log level for a specific log type
    // logtype: FF_LOGTYPE_* (e.g., FF_LOGTYPE_USER1)
    // Thread safety: No

int ff_log(uint32_t level, uint32_t logtype, const char *format, ...)
    // Output a log message (printf-style)
    // level: FF_LOG_* (e.g., FF_LOG_INFO)
    // logtype: FF_LOGTYPE_* (e.g., FF_LOGTYPE_USER1)
    // Thread safety: Yes (per-thread independent buffer)

int ff_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap)
    // va_list version of ff_log()
    // Thread safety: Yes

void ff_log_close(void)
    // Close the logging system
    // Thread safety: No
```

#### **System Interfaces (8)**

```c
int ff_gettimeofday(struct timeval *tv, struct timezone *tz)
    // Get the current time (wall clock time)
    // Precision: Microseconds (μs)
    // Returns: 0 on success, -1 on failure
    // Thread safety: Yes

int ff_clock_gettime(clockid_t clock_id, struct timespec *tp)
    // High-precision time query
    // clock_id: CLOCK_REALTIME / CLOCK_MONOTONIC
    // Precision: Nanoseconds (ns)
    // Thread safety: Yes

int ff_usleep(unsigned int useconds)
    // Microsecond-level sleep (use only during initialization)
    // Thread safety: No

void ff_sync_time_to_freebsd(void)
    // Synchronize Linux system time to the FreeBSD stack
    // Thread safety: No (initialization only)

time_t ff_time(time_t *tloc)
    // Get second-level timestamp
    // Thread safety: Yes

int ff_nanosleep(const struct timespec *req, struct timespec *rem)
    // Nanosecond-level sleep
    // Thread safety: Yes

// Packet dispatch callback (optional)
void ff_set_pkt_dispatcher(pkt_dispatcher_t func)
    // Register a custom packet dispatch function
    // Function: Intercept packets before protocol processing for custom handling (e.g., VLAN classification)
    // Thread safety: No (set during initialization)

int ff_packet_filter(ff_pkt_type type, uint16_t proto)
    // Query whether this type of packet should be received
    // Thread safety: Yes
```

#### **Others (3+)**

```c
int ff_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
              const void *newp, size_t newlen)
    // sysctl interface (query/modify kernel parameters)
    // name: MIB integer array (e.g., {CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_SENDSPACE})
    // namelen: Length of the MIB array
    // Thread safety: Yes

int ff_arp_add(const char *ip, const char *mac)
    // Add an ARP entry
    // Thread safety: Yes

int ff_arp_del(const char *ip)
    // Delete an ARP entry
    // Thread safety: Yes

// Other utility functions...
const char * ff_strerror(int errnum)
    // Error number → error message string
    // Thread safety: Yes

// === Kernel-stack coexistence (only when built with FF_KERNEL_COEXIST) ===
// Per-socket stack markers (ff_api.h): SOCK_FSTACK 0x01000000 / SOCK_KERNEL 0x02000000
// Internal machinery (lib/ff_host_interface.{c,h}):
//   32 ff_host_* host-libc bridges: ff_host_socket/bind/listen/accept/accept4/
//     connect/close/read/write/recv/recvfrom/send/sendto/sendmsg/recvmsg/
//     shutdown/getpeername/getsockname/setsockopt/getsockopt/fcntl/
//     epoll_create1/epoll_ctl/epoll_wait
//     + R9: ff_host_set_v6only (setsockopt IPV6_V6ONLY=1 on host IPv6 socket),
//           ff_host_kqueue_ctl / ff_host_kqueue_poll (kqueue<->host-epoll bridge)
//     + R10: ff_host_readv / ff_host_writev / ff_host_ioctl (raw Linux request) /
//           ff_host_dup / ff_host_dup2
//   ff_native_map_get/set/clear     - F-Stack fd <-> host fd pairing table (65536 entries)
//   ff_is_kernel_fd/ff_kernel_fd_encode/ff_kernel_fd_real (inline; FF_KERNEL_FD_BASE=0x40000000)
// R9 kqueue coexistence (lib/ff_syscall_wrapper.c): ff_kqueue/ff_kevent mirror the epoll
//   path - lazily pair a host epoll per kqueue (shared ff_epoll_host_ep), register
//   kernel/dual-stack-fd EVFILT_READ/WRITE into it, synthesize struct kevent from the
//   host epoll then merge ff_kevent_do_each F-Stack events. Kernel fds: READ/WRITE only.
// Compiled out entirely when FF_KERNEL_COEXIST is undefined.
```

---

## 2. Core Data Structures in Detail

### 2.1 Kevent Event Structure

```c
struct kevent {
    uintptr_t ident;      // [0]  Event identifier (socket fd, PID, timer ID, etc.)
    short filter;         // [8]  Event filter type (EVFILT_READ/WRITE/TIMER/...), values are negative
    unsigned short flags; // [10] Event flags (EV_ADD/DELETE/ONESHOT/CLEAR/...)
    unsigned int fflags;  // [12] Filter-specific flags (ioctl/timeout, etc.)
    __int64_t data;       // [16] Data returned by the filter (fixed 64-bit)
                          //      EVFILT_READ: Number of readable bytes
                          //      EVFILT_WRITE: Number of writable bytes
                          //      EVFILT_TIMER: Number of triggers
    void *udata;          // [24] User-defined data pointer (callback argument)
    __uint64_t ext[4];    // [32] FreeBSD 13/15 extended fields (KBI unchanged across upgrade; M2 verify-only)
};

// Supported filter types
#define EVFILT_READ      -1     // Read ready
#define EVFILT_WRITE     -2     // Write ready
#define EVFILT_AIO       -3     // Asynchronous I/O
#define EVFILT_VNODE     -4     // File/directory inode events
#define EVFILT_PROC      -5     // Process events
#define EVFILT_SIGNAL    -6     // Signal delivery
#define EVFILT_TIMER     -7     // Timer
#define EVFILT_PROCDESC  -8     // Process descriptor events
#define EVFILT_FS        -9     // Filesystem changes
#define EVFILT_LIO      -10     // Asynchronous I/O list
#define EVFILT_USER     -11     // User events
#define EVFILT_SENDFILE -12     // Kernel sendfile events
#define EVFILT_EMPTY    -13     // Empty send socket buffer
#define EVFILT_SYSCOUNT  13     // ... 13 filter types in total

// Event flags
#define EV_ADD       0x0001   // Add event (register)
#define EV_DELETE    0x0002   // Delete event (unregister)
#define EV_ENABLE    0x0004   // Enable event (restore from disabled)
#define EV_DISABLE   0x0008   // Disable event (temporarily turn off)
#define EV_ONESHOT   0x0010   // One-shot trigger (auto-delete)
#define EV_CLEAR     0x0020   // Auto-clear (edge-triggered)
#define EV_RECEIPT   0x0040   // Event status feedback
#define EV_DISPATCH  0x0080   // Disable event after addition
#define EV_EOF       0x8000   // Connection/file close flag
#define EV_ERROR     0x4000   // Error flag

// Convenience macro
#define EV_SET(kevp, a, b, c, d, e, f) do { \
        (kevp)->ident = (a);      /* socket fd */ \
        (kevp)->filter = (b);     /* EVFILT_* */ \
        (kevp)->flags = (c);      /* EV_ADD/DELETE/... */ \
        (kevp)->fflags = (d);     /* filter flags */ \
        (kevp)->data = (e);       /* initial data */ \
        (kevp)->udata = (f);      /* user pointer */ \
    } while (0)
```

### 2.2 Socket Address Structures

```c
// Linux sockaddr (used for F-Stack API)
struct linux_sockaddr {
    unsigned short sa_family;     // AF_INET (2) or AF_INET6 (10)
    char sa_data[14];             // Address data (protocol-dependent)
};

// IPv4 address structure
struct sockaddr_in {
    __kernel_sa_family_t sin_family;     // AF_INET
    __be16 sin_port;                      // Port in network byte order (htons())
    struct in_addr sin_addr;              // IPv4 address
    unsigned char __pad[sizeof(struct sockaddr) - sizeof(short int) -
                        sizeof(unsigned short int) - sizeof(struct in_addr)];
};

// IPv6 address structure
struct sockaddr_in6 {
    __kernel_sa_family_t sin6_family;     // AF_INET6
    __be16 sin6_port;                      // Port (htons())
    __be32 sin6_flowinfo;                  // Flow information
    struct in6_addr sin6_addr;             // IPv6 address
    __u32 sin6_scope_id;                   // Scope ID
};

// IPv4 address
struct in_addr {
    __be32 s_addr;  // IPv4 address (network byte order)
};

// IPv6 address
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

### 2.3 Epoll Event Structure

```c
struct epoll_event {
    uint32_t events;      // Event mask (EPOLLIN/EPOLLOUT/...)
    epoll_data_t data;    // User data

    union epoll_data {
        void *ptr;        // Pointer (commonly used)
        int fd;           // File descriptor
        uint32_t u32;     // 32-bit integer
        uint64_t u64;     // 64-bit integer
    };
};

// Supported events
#define EPOLLIN   0x00000001      // Readable
#define EPOLLPRI  0x00000002      // Priority data
#define EPOLLOUT  0x00000004      // Writable
#define EPOLLRDNORM 0x00000040    // Normal data readable
#define EPOLLRDBAND 0x00000080    // Priority data readable
#define EPOLLWRNORM 0x00000100    // Normal data writable
#define EPOLLWRBAND 0x00000200    // Priority data writable
#define EPOLLERR  0x00000008      // Error
#define EPOLLHUP  0x00000010      // Hang up
#define EPOLLRDHUP 0x00002000     // Peer closed
#define EPOLLET   0x80000000      // Edge-triggered (EV_CLEAR)
#define EPOLLONESHOT 0x40000000   // One-shot trigger (EV_ONESHOT)
```

### 2.4 Config Structure

```c
struct ff_config {
    char *filename;
  
    // DPDK configuration section
    struct {
        char *proc_type;
        /* mask of enabled lcores */
        char *lcore_mask;         // [0x4] CPU core mask (hexadecimal)
        /* mask of current proc on all lcores */
        char *proc_mask;

        /* specify base virtual address to map. */
        char *base_virtaddr;

        /* allow processes that do not want to co-operate to have different memory regions */
        char *file_prefix;

        /* pci whitelist */
        char *allow;

        int nb_channel;           // [0x8] Number of memory channels
        int memory;               // [0xC] Reserved memory (MB)
        int no_huge;
        int nb_procs;
        int proc_id;
        int promiscuous;               // [0x10] Promiscuous mode
        int nb_vdev;
        int nb_bond;
        int numa_on;                   // [0x14] NUMA support
        int tso;
        int tx_csum_offoad_skip;
        int vlan_strip;
        int nb_vlan_filter;
        uint16_t vlan_filter_id[DPDK_MAX_VLAN_FILTER];
        int symmetric_rss;

        /* sleep x microseconds when no pkts incoming */
        unsigned idle_sleep;

        /* TX burst queue drain nodelay delay time */
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
    
    // KNI configuration
    struct {
        int enable;
        int console_packets_ratelimit;           // Rate limit (QPS)
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
  
    // FreeBSD boot parameters
    struct {
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

### 2.5 Iovec Structure (Scatter-Gather I/O)

```c
struct iovec {
    void  *iov_base;      // Buffer pointer
    size_t iov_len;       // Buffer length (bytes)
};

// Example: Scatter read into 3 buffers
struct iovec iov[3] = {
    {buf1, 1024},         // Read 1024 bytes into buf1
    {buf2, 2048},         // Read 2048 bytes into buf2
    {buf3, 512}           // Read 512 bytes into buf3
};

ssize_t n = ff_readv(sockfd, iov, 3);  // Read into 3 buffers in one system call
```

### 2.6 Msghdr Structure (Message Header)

```c
struct msghdr {
    void         *msg_name;           // Peer address pointer
    socklen_t     msg_namelen;        // Address length
    struct iovec *msg_iov;            // iovec array
    size_t        msg_iovlen;         // Number of iovec elements
    void         *msg_control;        // Control information (ancillary data)
    socklen_t     msg_controllen;     // Control information length
    int           msg_flags;          // Returned flags (MSG_EOR/MSG_TRUNC)
};

// Example: Send a message
char buf[] = "Hello";
struct iovec iov = {buf, strlen(buf)};
struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1
};

ff_sendmsg(sockfd, &msg, 0);
```

### 2.7 Pollfd Structure (poll Multiplexing)

```c
struct pollfd {
    int fd;        // File descriptor (-1 to ignore)
    short events;  // Events of interest (POLLIN/POLLOUT/...)
    short revents; // Returned events (filled by ff_poll())
};

// Event types
#define POLLIN    0x001   // Data readable
#define POLLPRI   0x002   // Priority data
#define POLLOUT   0x004   // Writable
#define POLLERR   0x008   // Error
#define POLLHUP   0x010   // Hang up
#define POLLNVAL  0x020   // Invalid fd

// Example: poll multiple fds
struct pollfd fds[2] = {
    {sockfd1, POLLIN | POLLOUT},
    {sockfd2, POLLIN}
};

ff_poll(fds, 2, -1);  // Block until events arrive
```

---

## 3. In-Depth Analysis of Three Key Source Files

### 3.1 ff_syscall_wrapper.c (2265 Lines)

**Responsibility**: Linux ↔ FreeBSD system call and parameter mapping

**Key Mapping Tables**:

```c
// Socket option level mapping
#define LINUX_SOL_SOCKET  1          // → SOL_SOCKET
#define LINUX_IPPROTO_IP  0          // → IPPROTO_IP
#define LINUX_IPPROTO_TCP 6          // → IPPROTO_TCP
#define LINUX_IPPROTO_UDP 17         // → IPPROTO_UDP

// IPv4 socket option mapping (Linux → FreeBSD)
struct linux_to_bsd_opt_map {
    int linux_opt;  // Linux option number
    int bsd_opt;    // FreeBSD option number
} ipv4_opt_map[] = {
    {LINUX_IP_TOS, IP_TOS},
    {LINUX_IP_TTL, IP_TTL},
    {LINUX_IP_HDRINCL, IP_HDRINCL},
    {LINUX_IP_MULTICAST_IF, IP_MULTICAST_IF},
    {LINUX_IP_MULTICAST_TTL, IP_MULTICAST_TTL},
    // ... more
};

// TCP socket option mapping
struct linux_to_bsd_opt_map tcp_opt_map[] = {
    {LINUX_TCP_NODELAY, TCP_NODELAY},        // Disable Nagle algorithm
    {LINUX_TCP_MAXSEG, TCP_MAXSEG},          // MSS (Maximum Segment Size)
    {LINUX_TCP_CORK, TCP_CORK},              // Buffer data
    {LINUX_TCP_KEEPIDLE, TCP_KEEPIDLE},      // TCP keepalive idle time
    {LINUX_TCP_KEEPINTVL, TCP_KEEPINTVL},    // TCP keepalive interval
    {LINUX_TCP_KEEPCNT, TCP_KEEPCNT},        // TCP keepalive retry count
    // ... more
};

// Core function
int ff_setsockopt_wrapper(int s, int level, int optname,
                          const void *optval, socklen_t optlen) {
    int bsd_level = convert_level(level);      // Convert level
    int bsd_optname = convert_optname(optname); // Convert optname
    
    // Handle special parameter value mapping
    if (level == IPPROTO_IP && optname == IP_TOS) {
        // Linux and FreeBSD TOS values are compatible, no conversion needed
    }
    
    // Handle sockaddr structure mapping (if needed)
    if (special_struct_conversion_needed()) {
        convert_params(...);
    }
    
    // Call FreeBSD implementation
    return ff_setsockopt_real(s, bsd_level, bsd_optname, 
                             converted_val, optlen);
}
```

**Key Features**:
- **IOCTL Mapping**: FIONBIO (0x5421) → FIONBIO (different code values)
- **Error Code Mapping**: Linux errno → FreeBSD errno
- **Address Family Mapping**: AF_INET6: 10 (Linux) ↔ 28 (FreeBSD)

### 3.2 ff_dpdk_if.c (2907 Lines) - NIC Driver Layer

**Global Variables** (key state affecting performance):

```c
// Global configuration
static struct ff_config ff_global_cfg;
static volatile int stop_run = 0;      // Stop flag

// NIC management
static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];
static int nb_dev_ports = 0;           // Number of active NICs (int in source, not uint32_t)
static uint32_t nb_lcores = 0;         // Number of active lcores
static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

// RSS table (connection affinity)
static struct ff_rss_tbl ff_rss_tbl[FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES];

// Performance parameters
static unsigned idle_sleep;             // Idle sleep (microseconds, no default value)
static uint32_t pkt_tx_delay = 1;      // Packet TX delay (microseconds)
int enable_kni = 0;                    // KNI enabled (non-static, globally visible)

// Timer state
static struct {
    uint64_t prev_tsc;
    uint64_t cur_tsc;
    uint64_t drain_tsc;    // TX drain period
} timer_state;
```

**Key Functions**:

```c
// Initialization flow
int ff_dpdk_init(int argc, char *argv[]) {
    // 1. DPDK EAL initialization
    if (rte_eal_init(dpdk_argc, dpdk_argv) < 0) {
        rte_exit(EXIT_FAILURE, "EAL init failed\n");
    }
    
    // 2. lcore and NIC configuration
    init_lcore_conf();
    init_mem_pool();
    
    // 3. NIC initialization
    for (port_id = 0; port_id < nb_dev_ports; port_id++) {
        // 3.1 Configure NIC
        rte_eth_dev_configure(port_id, nb_rx_queue, nb_tx_queue, &port_conf);
        
        // 3.2 Configure RSS
        struct rte_eth_rss_conf rss_conf = {
            .rss_key = rss_key,
            .rss_key_len = sizeof(rss_key),
            .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
        };
        rte_eth_dev_rss_hash_update(port_id, &rss_conf);
        
        // 3.3 Configure offloads (TSO/Checksum)
        configure_offload(port_id);
        
        // 3.4 Start NIC
        rte_eth_dev_start(port_id);
    }
    
    // 4. Initialize RSS classification table
    ff_rss_tbl_init();
    
    return 0;
}

// Packet processing
static inline void process_packets(struct rte_mbuf **m, uint16_t nb_m) {
    for (i = 0; i < nb_m; i++) {
        struct rte_mbuf *pkt = m[i];
        
        // 1. Get Ethernet header
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, ...);
        
        // 2. Protocol filtering
        if (eth_hdr->ether_type == RTE_ETHER_TYPE_IPv4) {
            // 3. Forward to FreeBSD protocol stack
            if_input(ifp, pkt);
        }
    }
}

// Main polling loop
static int main_loop(void *arg) {
    struct lcore_conf *qconf = rte_lcore_conf + rte_lcore_id();
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    
    while (!stop_run) {
        cur_tsc = rte_rdtsc();
        
        // [1] Clock-driven
        if (freebsd_clock.expire < cur_tsc) {
            rte_timer_manage();  // Trigger TCP timers, etc.
        }
        
        // [2] Receive packets
        for (qconf->port in port_list) {
            nb_rx = rte_eth_rx_burst(qconf->port, qconf->queue, 
                                     pkts, MAX_PKT_BURST);
            if (nb_rx > 0) {
                process_packets(pkts, nb_rx);
            }
        }
        
        // [3] Timed transmission
        if ((cur_tsc - prev_tsc) > drain_tsc) {
            for (each port) {
                rte_eth_tx_burst(port, qconf->tx_queue, 
                                 tx_buffer, nb_tx);
            }
            prev_tsc = cur_tsc;
        }
        
        // [4] Application callback
        if (loop_func) {
            loop_func(loop_arg);
        }
    }
    
    return 0;
}
```

**Key Optimizations**:
- **Interrupt-free polling**: 100% CPU for low latency
- **Batch processing**: Receive/send 32 packets at a time
- **Cache affinity**: RSS ensures connections do not migrate
- **Hardware offloading**: TSO, Checksum offload

### 3.3 ff_glue.c (1467 Lines) - Kernel Emulation Layer

**Kernel Primitive Emulation**:

```c
// Mutex
struct mtx {
    void *ctx;  // Actually points to pthread_mutex_t
};

void mtx_init(struct mtx *m, const char *name, const char *type, int opts) {
    pthread_mutex_t *mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(mutex, NULL);
    m->ctx = mutex;
}

void mtx_lock(struct mtx *m) {
    pthread_mutex_lock((pthread_mutex_t *)m->ctx);
}

// Condition variable
struct condvar {
    void *ctx;  // Actually points to pthread_cond_t
};

void cv_init(struct condvar *cv, const char *desc) {
    pthread_cond_t *cond = malloc(sizeof(pthread_cond_t));
    pthread_cond_init(cond, NULL);
    cv->ctx = cond;
}

// Memory management
void *malloc(size_t size, struct malloc_type *type, int flags) {
    // Uses DPDK rte_malloc with NUMA support
    return rte_malloc("malloc", size, 0);
}

// Global variable emulation
volatile int ticks = 0;           // Clock tick counter
int mp_ncpus = 1;                 // CPU count
struct vmspace *vmspace0;         // Global address space
struct prison *prison0;           // Global namespace
```

**Key Features**:
- **No VFS support**: Limited file operations
- **Simplified IPC**: Inter-process communication via DPDK Ring
- **Soft interrupt emulation**: Handled via taskqueue

### 3.4 Kernel-Stack Coexistence Source Files (`FF_KERNEL_COEXIST`, optional)

Two files carry the optional coexistence machinery (compiled only with `FF_KERNEL_COEXIST=1`):

**`ff_host_interface.c` (617 Lines) / `ff_host_interface.h` (187 Lines)**
- `FF_KERNEL_FD_BASE = 0x40000000` and three inline helpers `ff_is_kernel_fd / ff_kernel_fd_encode / ff_kernel_fd_real` (`.h` L113-128). A managed kernel fd = `host_fd + 0x40000000`, which never collides with FreeBSD fds (`kern.maxfiles <= 65536`).
- `ff_native_fd_map[65536]` + `ff_native_map_get/set/clear` (`.c` L257-278): the F-Stack fd ↔ host fd pairing table (single-threaded per instance).
- **32 `ff_host_*` bridges**: thin passthroughs to host libc (`socket/bind/listen/accept/accept4/connect/close/read/write/recv/recvfrom/send/sendto/sendmsg/recvmsg/shutdown/getpeername/getsockname/setsockopt/getsockopt/fcntl/epoll_create1/epoll_ctl/epoll_wait`). **R9 added 3**: `ff_host_set_v6only` (`setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 1)` on a host IPv6 socket so it coexists with the same-port host IPv4 socket), `ff_host_kqueue_ctl` and `ff_host_kqueue_poll` (servicing the kqueue↔host-epoll coexistence path). **R10 added 5**: `ff_host_readv`, `ff_host_writev`, `ff_host_ioctl` (raw Linux request passed straight to host libc), `ff_host_dup`, `ff_host_dup2`.

**`ff_epoll.c` (289 Lines) - unified F-Stack + kernel epoll**
- `ff_epoll_pairs[64]{kq, host_ep}`: lazily pairs one host `epoll` fd per kqueue.
- `ff_epoll_ctl`: routes a managed kernel fd to the host epoll, or dual-registers a dual-stack fd on both the host epoll and the kqueue.
- `ff_epoll_wait`: first non-blocking poll of the host epoll, then merge kqueue events into the same `events[]` array.
- `ff_epoll_pairs_lock` was removed — F-Stack runs single-threaded per instance (commit `3e71f4699`).
- **R9**: `ff_epoll_host_ep(kq, create)` promoted from `static` to a shared symbol (declared `ff_host_interface.h` L139) so the kqueue coexistence path reuses the same `ff_epoll_pairs` pairing table.

**R9: unified kqueue/kevent coexistence in `ff_syscall_wrapper.c`** — `ff_kqueue` (L1895) and `ff_kevent` (L2050) now mirror the epoll path. `ff_kevent` splits the changelist via `ff_kevent_host_change` (L2006): entries whose `ident` is a managed kernel fd (`ff_is_kernel_fd`) or a dual-stack fd (`ff_native_map_get>0`) have their `EVFILT_READ/WRITE` registered into the kqueue-paired host epoll through `ff_host_kqueue_ctl` (kernel-only changes are NOT forwarded to the F-Stack kqueue; dual-stack fds are still forwarded). The eventlist is filled by `ff_kevent_host_wait` (L2034) — `ff_host_kqueue_poll(timeout=0)` then synthesizes `struct kevent` (`ident`=app-side fd, `filter`=READ/WRITE, `EV_EOF`↔`EPOLLHUP|ERR`) — merged with `ff_kevent_do_each` F-Stack events. This fixes the `example/main.c` kqueue model so the kernel-side `curl 127.0.0.1:80` returns **200 size=438** (was 000). Known limitation: kernel fds via kqueue support `EVFILT_READ/WRITE` only.

**Entry routing in `ff_syscall_wrapper.c`** (§3.1): each kernel-aware `ff_*` entry detects a managed kernel fd via `ff_is_kernel_fd()` and forwards to the matching `ff_host_*` bridge; dual-created sockets additionally drive the paired host fd looked up via `ff_native_map_get()`. On `AF_INET6` dual-build, `ff_socket` calls `ff_host_set_v6only(hfd)` (L952) so the `-DINET6` build starts cleanly with v4+v6 on the same port (fixes the prior host-IPv6 `errno=98 EADDRINUSE`).

**R10: residual-entry coexistence** — `ff_ioctl` (L1067, kernel fd uses the **raw Linux request** straight to `ff_host_ioctl`, NOT via `linux2freebsd_ioctl`; dual-stack fd same-driver since R10.1 syncs `FIONBIO`/`FIOASYNC`), `ff_readv` (L1189)/`ff_writev` (L1251, kernel fd → `ff_host_readv/writev`, mimic read/write, connection fds single-stack hot path), `ff_dup` (L2130, kernel fd → `ff_host_dup`+encode), `ff_dup2` (L2156, both-kernel → `ff_host_dup2`+encode; cross-stack rejected `errno=EINVAL`). Known limitation: `ff_select` (encode kernel fd ≫ `FD_SETSIZE` hard limit) / `ff_poll` (conservatively not implemented) do not support kernel-fd coexistence — use `ff_epoll_*`/`ff_kqueue`.

---

## 4. Thread Safety Analysis

### 4.1 Thread Safety Classification

**Fully Thread-Safe** ✓ (can be called across threads):
- ff_socket / ff_bind / ff_listen / ff_accept / ff_connect / ff_close
- ff_read / ff_write / ff_send / ff_recv
- ff_kqueue / ff_kevent / ff_epoll_* (per-fd isolation)
- ff_setsockopt / ff_getsockopt / ff_fcntl / ff_ioctl
- ff_route_ctl (atomic routing operations)
- ff_gettimeofday / ff_clock_gettime
- ff_mbuf_get / ff_mbuf_free
- ff_pthread_create / ff_pthread_join

**Conditionally Thread-Safe** ⚠️ (requires external synchronization):
- ff_init (initialization only, requires single thread)
- ff_run (exclusive to one lcore, cannot run in parallel)
- ff_log / ff_vlog (recommend using a mutex)
- ff_gethostbyname / ff_gethostbyname2 (returns static buffer)

**Not Thread-Safe** ✗ (cannot be called across threads):
- ff_stop_run (can be called from any thread, but the ff_run thread will exit)
- Configuration-related functions (initialization only)
- ff_set_pkt_dispatcher (initialization only)

### 4.2 Per-Thread Socket Table

```c
// Each thread maintains an independent socket table
struct ff_thread_local {
    struct socket *socket_table[FF_MAX_SOCKETS];
    int max_fd;
} __thread ff_tls;

// Socket is assigned to the current thread's fd on creation
int ff_socket(...) {
    struct socket *so = socreate(...);
    ff_tls.socket_table[fd] = so;
    return fd;
}

// Table lookup during read/write
ssize_t ff_read(int fd, void *buf, size_t nbytes) {
    struct socket *so = ff_tls.socket_table[fd];
    return sorecvX(so, buf, nbytes);
}

// ✓ Thread-safe: socket_table is independent per thread
// ✓ No race conditions: each socket is accessed only by the thread that created it
```

### 4.3 Concurrency Model

```
Multi-threaded Model:

Main Thread                   Worker Thread 1
├─ ff_init()                 ├─ ff_init()
├─ ff_run(loop1)             ├─ ff_run(loop2)
│  Exclusive lcore 0          │  Exclusive lcore 1
│  Continuous polling          │  Continuous polling
│  ├─ Receive packets         │  ├─ Receive packets
│  ├─ Process packets         │  ├─ Process packets
│  └─ Application loop1       │  └─ Application loop2
│                              │
└─ Communication via shared   └─ Communication via shared
   mempool and atomic ops        mempool and atomic ops

Characteristics:
✓ Each thread has exclusive lcore (no CPU contention)
✓ Each thread has independent socket table
✓ Shared resources (mempool) protected by atomic operations
✗ Cannot share sockets across threads
```

---

## 5. Compilation and Linking

### 5.1 Compilation Commands

```bash
# Compile F-Stack library
cd /data/workspace/f-stack/lib
make clean
make

# Output: libfstack.a (4.7 MB)

# Install headers and library
make install PREFIX=/usr/local

# Target locations:
#   /usr/local/lib/libfstack.a
#   /usr/local/include/ff_*.h
```

### 5.2 Application Linking

```bash
# Compilation flags
FSTACK_CFLAGS = $(shell pkg-config --cflags libfstack)
FSTACK_LIBS = $(shell pkg-config --libs libfstack)

# Or specify manually
FSTACK_CFLAGS = -I/usr/local/include
FSTACK_LIBS = -L/usr/local/lib -lfstack $(shell pkg-config --libs libdpdk)

# Compile application
gcc -o app main.c $(FSTACK_CFLAGS) $(FSTACK_LIBS)

# Library link order
ld -o app main.o \
    -lfstack \
    -ldpdk \
    -lpthread \
    -lm \
    -lnuma
```

### 5.3 Runtime Dependencies

```bash
# Required DPDK setup
# 1. Hugepage memory
sysctl vm.nr_hugepages=2048  # Allocate 2GB huge pages

# 2. NIC driver binding (choose one)
# Method A: igb_uio (better performance)
modprobe igb_uio
python dpdk_devbind.py -b igb_uio 0000:05:00.0  # Bind NIC

# Method B: vfio-pci (more secure)
modprobe vfio_pci
python dpdk_devbind.py -b vfio-pci 0000:05:00.0

# 3. Run application (use start.sh with config.ini to launch)
bash start.sh -c config.ini -b ./app
# start.sh will automatically launch primary/secondary processes
# based on the lcore_mask in config.ini
```

---

## Summary

**Key Data Structures**:
- `kevent` - BSD event structure
- `epoll_event` - Linux epoll compatibility
- `ff_config` - F-Stack global configuration
- Socket address structures (sockaddr_in/in6)

**Thread Safety**:
- Socket operations: Fully thread-safe (per-thread isolation)
- Multi-threaded model: Each thread has exclusive lcore + socket table
- Shared resources: mempool protected by atomic operations

**Performance Optimizations**:
- Batch processing: Receive/send 32 packets at a time
- Cache affinity: RSS classification + CPU isolation
- Hardware offloading: TSO, Checksum, LRO
- Zero-copy: Direct mbuf operations, no data copying

---

**Related Documents**:
- [Layer 1: System Architecture Overview](./F-Stack_Architecture_Layer1_System_Overview.md)
- [Layer 2: Interface Definition and Specification](./F-Stack_Architecture_Layer2_Interface_Specification.md)
- [Knowledge Base Summary](./F-Stack_Knowledge_Base_Summary.md)
