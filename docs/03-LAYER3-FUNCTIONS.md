# F-Stack v1.26 Layer 3: Function-Level Index and Data Model

> **Target Audience**: Kernel/driver developers, performance optimization engineers  
> **Key Concepts**: Function index, data structures, system call adaptation, symbol export  
> **Generation Date**: 2026-03-20

## 1. Complete Exported Function Index (80+ Functions)

> **Symbol Export Hierarchy**: The following function index includes all interfaces declared in `ff_api.h` and `ff_epoll.h`. The symbols actually dynamically exported through `ff_api.symlist` are a subset.
> - ff_init / ff_run / ff_stop_run are declared in `ff_api.h` but are **not in** `ff_api.symlist`; they are only available through static linking
> - ff_epoll_* family functions are declared in `ff_epoll.h`, not in `ff_api.h`

### 1.1 Lifecycle Management Functions

| Function | Signature | Purpose | Thread-Safe |
|----------|-----------|---------|-------------|
| `ff_init` | `int ff_init(int argc, char * const argv[])` | Initialize DPDK/FreeBSD/NIC | No |
| `ff_run` | `void ff_run(loop_func_t, void *arg)` | Start main loop (blocking) | No |
| `ff_stop_run` | `void ff_stop_run(void)` | Gracefully stop loop | Yes |

### 1.2 Socket Family Functions

| Function | Param Count | Return Value | Description |
|----------|-------------|-------------|-------------|
| `ff_socket` | 3 | int(fd) | Create socket |
| `ff_bind` | 3 | 0/error | Bind address |
| `ff_listen` | 2 | 0/error | Listen |
| `ff_accept` | 3 | int(fd) | Accept connection |
| `ff_accept4` | 4 | int(fd) | Accept connection (with flags) |
| `ff_connect` | 3 | 0/error | Initiate connection |
| `ff_close` | 1 | 0/error | Close socket |
| `ff_shutdown` | 2 | 0/error | Shut down connection direction |

### 1.3 Data I/O Functions

| Function | Param Count | Return Value | Description |
|----------|-------------|-------------|-------------|
| `ff_read` | 3 | bytes/-1 | Read data |
| `ff_readv` | 3 | bytes/-1 | Scatter read |
| `ff_write` | 3 | bytes/-1 | Write data |
| `ff_writev` | 3 | bytes/-1 | Gather write |
| `ff_send` | 4 | bytes/-1 | Send |
| `ff_sendto` | 6 | bytes/-1 | Send to address |
| `ff_sendmsg` | 3 | bytes/-1 | Send message |
| `ff_recv` | 4 | bytes/-1 | Receive |
| `ff_recvfrom` | 6 | bytes/-1 | Receive from address |
| `ff_recvmsg` | 3 | bytes/-1 | Receive message |

### 1.4 Event Multiplexing Functions

| Function | Purpose | Param Count | Return Value |
|----------|---------|-------------|-------------|
| `ff_kqueue` | BSD event queue | 0 | int(kq_fd) |
| `ff_kevent` | BSD event wait | 6 | event_count/-1 |
| `ff_kevent_do_each` | BSD iterate events | 7 | int |
| `ff_epoll_create` | Linux epoll | 1 | int(ep_fd) |
| `ff_epoll_ctl` | epoll control | 4 | 0/-1 |
| `ff_epoll_wait` | epoll wait | 4 | event_count/-1 |
| `ff_select` | Traditional select | 5 | ready_count/-1 |
| `ff_poll` | Traditional poll | 3 | ready_count/-1 |

### 1.5 Socket Option Functions

| Function | Purpose | Description |
|----------|---------|-------------|
| `ff_setsockopt` | Set socket options | Supports SO_*, TCP_*, IP_*, etc. |
| `ff_getsockopt` | Get socket options | Read current option values |
| `ff_fcntl` | File control | Supports F_SETFL, F_GETFL, etc. |
| `ff_ioctl` | Device control | Supports FIONBIO, FIONREAD, etc. |

### 1.6 System Control Functions

| Function | Params | Purpose |
|----------|--------|---------|
| `ff_sysctl` | 6 | Read/write kernel variables |
| `ff_route_ctl` | 5 | Routing table control |
| `ff_rtioctl` | 4 | Routing ioctl |
| `ff_gettimeofday` | 2 | Get system time |

### 1.7 Special Feature Functions

| Function | Purpose | Notes |
|----------|---------|-------|
| `ff_zc_mbuf_get` | Get zero-copy mbuf | Direct access to DMA buffer |
| `ff_zc_mbuf_write` | Zero-copy write | Skip memory copy |
| `ff_zc_mbuf_read` | Zero-copy read | Receive raw mbuf (**not yet implemented, may be supported later**) |
| `ff_mbuf_gethdr` | Get mbuf | DPDK memory pool allocation |
| `ff_mbuf_get` | Allocate mbuf | - |
| `ff_mbuf_free` | Free mbuf | - |
| `ff_mbuf_copydata` | Copy mbuf data | - |

### 1.8 Multi-Threading Functions

| Function | Purpose |
|----------|---------|
| `ff_pthread_create` | Create pthread |
| `ff_pthread_join` | Wait for pthread |

### 1.9 Logging Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `ff_log` | `int ff_log(uint32_t level, uint32_t logtype, const char *format, ...)` | Formatted logging |
| `ff_vlog` | `int ff_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap)` | va_list logging |
| `ff_log_reset_stream` | `int ff_log_reset_stream(void *f)` | Reset log output stream |
| `ff_log_set_global_level` | `void ff_log_set_global_level(uint32_t level)` | Set global log level |
| `ff_log_set_level` | `int ff_log_set_level(uint32_t logtype, uint32_t level)` | Set module log level |
| `ff_log_close` | `void ff_log_close(void)` | Close logging |

## 2. Core Data Structures

### 2.1 kevent Structure (BSD Events)

```c
struct kevent {
    uintptr_t ident;           // Event identifier (fd or timer ID)
    short filter;              // Event filter type (short, not int16_t)
    unsigned short flags;      // Control flags (EV_ADD, EV_DELETE, etc.)
    unsigned int fflags;       // Filter-specific flags
    __int64_t data;            // Event data (ready count, timeout, etc., fixed 64-bit)
    void *udata;               // User-defined data pointer
    __uint64_t ext[4];         // FreeBSD 13/15 extension fields (KBI unchanged across the upgrade; M2 verify-only)
};

// Filter types (filter values)
#define EVFILT_READ      -1     // Read ready
#define EVFILT_WRITE     -2     // Write ready
#define EVFILT_AIO       -3     // Asynchronous I/O
#define EVFILT_VNODE     -4     // File/directory inode events
#define EVFILT_PROC      -5     // Process events
#define EVFILT_SIGNAL    -6     // Signal delivery
#define EVFILT_TIMER     -7     // Timer
#define EVFILT_PROCDESC  -8     // Process descriptor events
#define EVFILT_FS        -9     // File change
#define EVFILT_LIO      -10     // Asynchronous I/O list
#define EVFILT_USER     -11     // User events
#define EVFILT_SENDFILE -12     // Kernel sendfile events
#define EVFILT_EMPTY    -13     // Empty send socket buffer
#define EVFILT_SYSCOUNT  13     // ... 13 filter types total

// Control flags (flags)
#define EV_ADD      0x0001     // Add event
#define EV_DELETE   0x0002     // Delete event
#define EV_ENABLE   0x0004     // Enable event
#define EV_DISABLE  0x0008     // Disable event
#define EV_ONESHOT  0x0010     // One-shot event
#define EV_CLEAR    0x0020     // Edge-triggered
#define EV_ERROR    0x4000     // Error flag
#define EV_EOF      0x8000     // EOF flag
```

### 2.2 ff_config Structure (Global Configuration)

> **Note**: The following is a simplified illustration, not the complete definition from `ff_config.h`. In the actual structure, configuration values are stored as strings (`char *`), populated by `ff_load_config()` after parsing config.ini. Key field types are as follows:

```c
struct ff_config {
    char *filename;           // Configuration file path
    struct {
        char *lcore_mask;     // CPU core mask (string, e.g., "0x01")
        char *proc_type;      // Process type (string "primary"/"secondary")
        uint32_t proc_id;     // Process ID
        uint32_t nb_procs;    // Total number of processes
        uint32_t pktmbuf_pool_size;  // mbuf pool size
        uint32_t numa_on;     // NUMA support
        uint16_t *portid_list; // NIC port ID list
        uint32_t nb_ports;    // Number of ports
    } dpdk;

    // Port configuration accessed via dpdk.port_cfgs (struct ff_port_cfg array)
    // Each ff_port_cfg contains IP/mask/gw and other fields

    struct {
        uint32_t enable;      // KNI enable flag
        char *kni_action;     // KNI forwarding policy
    } kni;

    // ... more fields in lib/ff_config.h
} ff_global_cfg;
```

### 2.3 ff_port_cfg Structure (Port Configuration)

```c
struct ff_port_cfg {
    uint16_t port_id;               // Port ID
    
    // Hardware features
    struct ff_hw_features {
        uint32_t rx_csum: 1;         // RX checksum offload
        uint32_t rx_lro: 1;          // LRO (packet coalescing)
        uint32_t tx_csum: 1;         // TX checksum offload
        uint32_t tx_tso: 1;          // TSO (segmentation offload)
        uint32_t tx_vlan: 1;         // VLAN insertion
        // ... more flags
    } hw_features;
    
    // RSS configuration
    struct rte_eth_rss_conf rss_conf;
    
    // VLAN configuration
    uint32_t vlan_enable;
    uint16_t vlan_id;
};
```

### 2.4 ff_rss_tbl Structure (RSS Lookup Table)

> **Note**: The `ff_rss_tbl_lookup()` function does not exist in the public API; the RSS table is for internal use only. The actual structure is `ff_rss_tbl_type` (defined in `lib/ff_dpdk_if.c`), and external code does not need to access it directly.

```c
// Internal structure (for reference only, not in public headers)
struct ff_rss_tbl_type {
    uint32_t saddr;       // Source IP
    uint16_t sport;       // Source port
    uint16_t num;         // Number of dip entries
    struct ff_rss_tbl_dip_type dip_tbl[FF_RSS_TBL_MAX_DADDR];
} __rte_cache_aligned;

// Public initialization interface (ff_host_interface.h)
int ff_rss_tbl_init(void);
```

> **RSS lport optimization (see `ff_rss_check_opt_spec`)**: the connect-side RSS source-port selection has been extended with three optimizations — (0.1) IPv4 kernel-side port-range hooks migrated back to FreeBSD 15.0 (`freebsd/netinet/in_pcb.c`), (0.3) a dynamic fast path that reverse-calculates the source port via `rte_thash_adjust_tuple` with a forced soft re-verify (`ff_rss_thash_ctx_init` / `ff_rss_adjust_sport`), and (0.2) an independent IPv6 path (`ff_rss_check6` / `ff_rss_tbl6_init` / `ff_rss_tbl6_set/get_portrange` / `ff_rss_adjust_sport6`) that leaves the IPv4 structures/signatures untouched. A read-only helper `ff_rss_self_queue_info()` exposes the current process's queue id / nb_queues / reta_size. Details and verification: `docs/ff_rss_check_opt_spec/zh_cn/`. R-D (2026-06, spec 10 §R-D): the secondary soft re-verify in `ff_rss_adjust_sport` / `ff_rss_adjust_sport6` is now runtime-gated via `config.ini [rss_check] recheck=0`/`=1`, off by default to realize the ~100 ns/call performance saving; `recheck=1` is for debug re-verify only. R-E (2026-06, spec 10 §6, commit `ff9e3c449`): IP_BIND_ADDRESS_NO_PORT bind-then-connect RSS 端口选择移植到 FreeBSD 15.0；`freebsd/netinet/in_pcb.c` 在 `in_pcbbind`/`in_pcbbind_setup` 加 `#ifdef`/`#ifndef FSTACK` 门控，bind(addr,0) 时延迟端口分配并跳过入 hash，让后续 connect 走 R-A `INPLOOKUP_LPORT_RSS_CHECK` 路径选 RSS 亲和源端口；`freebsd/netinet6/in6_pcb.c` 同步 v6（路径 B：`in6_pcbconnect` 外层 if 在 FSTACK 下放宽为 `unspec || lport==0`，内层 `in6p_laddr` 赋值加 `IN6_IS_ADDR_UNSPECIFIED` 守卫保用户地址）。+16 / -1，零 lib 改动；FSTACK off 退回原生 15.0；REUSEPORT_LB MPASS 与 bind(addr,N) 零回归。

### 2.5 ff_msg_ring Structure (Inter-Process Communication)

> **Note**: `ff_msg_send()` is not a public API; it does not exist in either `ff_api.h` or `ff_api.symlist`. Inter-process communication is implemented through the `ff_msg` message queue (`lib/ff_msg.h`), used by F-Stack internal tools (knictl/sysctl, etc.). Application-level code does not need to call it directly.

```c
// Message type enumeration (lib/ff_msg.h)
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

// Message structure (simplified)
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

### 2.6 ff_tx_offload Structure (TX Offload)

```c
struct ff_tx_offload {
    uint8_t ip_csum;               // IP checksum offload
    uint8_t tcp_csum;              // TCP checksum offload
    uint8_t udp_csum;              // UDP checksum offload
    uint8_t sctp_csum;             // SCTP checksum offload
    uint16_t tso_seg_size;         // TSO segment size (0 = disabled)
};
```

### 2.7 ff_zc_mbuf Structure (Zero-Copy)

```c
// Defined in lib/ff_api.h
struct ff_zc_mbuf {
    void *bsd_mbuf;         // Pointer to mbuf chain head
    void *bsd_mbuf_off;     // Pointer to mbuf at current offset
    int off;                // Current total offset (APP should not modify)
    int len;                // Total length of mbuf chain
};

// Usage:
//   1. Caller allocates struct ff_zc_mbuf zm; (on stack or heap)
//   2. ff_zc_mbuf_get(&zm, len)   — Allocate mbuf chain, populate zm
//   3. ff_zc_mbuf_write(&zm, data, len) — Write data to mbuf chain
//   4. ff_write(fd, zm.bsd_mbuf, len)   — Send using bsd_mbuf as buf
//
// Note: ff_zc_mbuf_read() is not yet implemented

int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);
int ff_zc_mbuf_read(struct ff_zc_mbuf *m, const char *data, int len);  // Not yet implemented
```

### 2.8 ff_dispatcher_context Structure (Packet Dispatch)

> **Note**: The following is the actual definition from `ff_api.h`. This structure is passed as additional context to the `dispatch_func_context_t` callback and only contains VLAN-related information. Packet data, length, queue, and other information are passed through other callback function parameters.

```c
struct ff_dispatcher_context {
    struct {
        uint8_t stripped;          // Whether VLAN has been stripped
        uint16_t vlan_tci;         // Priority (3) + CFI (1) + Identifier Code (12)
    } vlan;
};
```

## 3. Three Key Source File Analyses

### 3.1 ff_syscall_wrapper.c (2265 Lines) - Linux/FreeBSD Adaptation

**Main Responsibility**: Convert Linux system call parameters/options to FreeBSD equivalents

**Linux Option Mapping Examples**:

```c
// SOL_SOCKET level options
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

// IPPROTO_IP level options
#define LINUX_IP_TOS          1       // → IP_TOS
#define LINUX_IP_TTL          2       // → IP_TTL
#define LINUX_IP_HDRINCL      3       // → IP_HDRINCL
#define LINUX_IP_MULTICAST_IF 32      // → IP_MULTICAST_IF
#define LINUX_IP_MULTICAST_TTL 33     // → IP_MULTICAST_TTL
#define LINUX_IP_ADD_MEMBERSHIP 35    // → IP_ADD_MEMBERSHIP

// IPPROTO_TCP level options
#define LINUX_TCP_NODELAY     1       // → TCP_NODELAY
#define LINUX_TCP_MAXSEG      2       // → TCP_MAXSEG
#define LINUX_TCP_KEEPIDLE    4       // → TCP_KEEPIDLE
#define LINUX_TCP_KEEPINTVL   5       // → TCP_KEEPINTVL
#define LINUX_TCP_KEEPCNT     6       // → TCP_KEEPCNT
```

**Key Conversion Functions**:

```c
int ff_setsockopt(int s, int level, int optname,
                  const void *optval, socklen_t optlen) {
    // 1. Convert level (SOL_SOCKET → SOL_SOCKET)
    // 2. Convert optname (LINUX_SO_REUSEADDR → SO_REUSEADDR)
    // 3. Convert optval format (if needed)
    // 4. Call FreeBSD setsockopt()
}
```

**Supported ioctl Commands**:

```c
#define LINUX_FIONBIO       0x5421    // Non-blocking I/O
#define LINUX_FIONREAD      0x541B    // Readable byte count
#define LINUX_SIOCGIFNAME   0x8910    // Get NIC name
#define LINUX_SIOCGIFCONF   0x8912    // Get NIC configuration
#define LINUX_SIOCGIFFLAGS  0x8913    // Get NIC flags
```

### 3.2 ff_dpdk_if.c (2907 Lines) - NIC Driver Layer

**File Structure**:

```
ff_dpdk_if.c
├─ Global variables (lines 50-150)
│  ├─ enable_kni
│  ├─ nb_dev_ports
│  ├─ idle_sleep
│  └─ pktmbuf_pool[]
│
├─ DPDK initialization (lines 200-400)
│  ├─ ff_dpdk_init()
│  ├─ init_mem_pool()
│  ├─ init_lcore_conf()
│  └─ init_port_start()
│
├─ Packet processing (lines 1500-1800)
│  ├─ process_packets()
│  ├─ protocol_filter()
│  └─ veth_input()
│
└─ Main loop (lines 2000-2200)
   ├─ main_loop()
   ├─ ff_dpdk_run()
   └─ Timer management
```

**Key Global Variables**:

```c
int enable_kni = 0;                                   // KNI enable flag (non-static)
int nb_dev_ports = 0;                                  // NIC count (non-static, not uint16_t)
static unsigned idle_sleep;                            // Idle sleep microseconds (assigned from config, no hardcoded default)
struct rte_mempool *pktmbuf_pool[NB_SOCKETS];          // mbuf pools indexed by NUMA socket
```

**Initialization Function Call Chain**:

```
ff_dpdk_init()
├─ rte_eal_init(dpdk_argc, dpdk_argv)       // DPDK EAL
├─ init_mem_pool()
│  └─ rte_pktmbuf_pool_create()
├─ init_lcore_conf()
│  └─ Configure lcore/port/queue mapping
├─ init_dispatch_ring()
│  └─ rte_ring_create()
├─ init_msg_ring()
│  └─ Inter-process message queue
├─ init_kni()
│  └─ rte_kni_init()                        (optional)
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

**main_loop() Detailed Pseudocode**:

```c
int main_loop(void *arg) {
    struct lcore_conf *lr = lcore_conf + lcore_id();
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    uint64_t cur_tsc, prev_tsc = 0;
    
    while (1) {
        if (unlikely(stop_loop)) break;
        
        cur_tsc = rte_rdtsc();
        
        // === 1. Drive FreeBSD timers ===
        if (unlikely(freebsd_clock.expire < cur_tsc)) {
            rte_timer_manage();        // Trigger TCP timers, etc.
        }
        
        // === 2. TX burst queue drain (before RX) ===
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc >= drain_tsc)) {
            for (each_port in qconf->tx_ports) {
                send_burst(qconf, ...);
            }
            prev_tsc = cur_tsc;
        }
        
        // === 3. Receive packets (RX) ===
        for (each_rx_queue in qconf->rx_queues) {
            uint16_t nb_rx = rte_eth_rx_burst(
                port_id, queue_id, 
                pkts_burst, MAX_PKT_BURST
            );
            process_packets(pkts_burst, nb_rx);
        }
        
        // === 4. Execute user callback ===
        if (lr->loop) {
            lr->loop(lr->arg);         // Application business logic
        }
        
        // === 5. Idle sleep ===
        if (likely(idle && idle_sleep)) {
            rte_delay_us_sleep(idle_sleep);
        }
    }
    
    return 0;
}
```

**KNI Rate Limiting**:

```c
struct ff_kni_rate_limit {
    uint32_t general_packets;              // General data limit
    uint32_t console_packets;              // Control message limit
    uint32_t kernel_packets;               // Kernel communication limit
    // Typical values: general=10K QPS, console=1K, kernel=9K
};
```

### 3.3 ff_glue.c (1467 Lines) - FreeBSD Glue Layer

**Core Responsibility**: Provide kernel primitives for the user-space FreeBSD protocol stack

**Memory Management Emulation**:

```c
#define M_DEVBUF     1             // Device buffer
#define M_TEMP       2             // Temporary buffer
#define M_CRED       3             // Credential
#define M_IP6OPT     4             // IPv6 option

void *malloc(size_t size, struct malloc_type *type, int flags) {
    // Underlying uses DPDK rte_malloc
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

**Global Kernel Variable Emulation**:

```c
// FreeBSD kernel variables
volatile int ticks = 0;                    // Kernel tick counter
int mp_ncpus = 1;                          // CPU count
int mp_maxcpus = RTE_MAX_LCORE;
cpuset_t all_cpus;                         // CPU set
struct vm_cnt vm_cnt = {0};                // Virtual memory statistics
```

**Synchronization Primitive Emulation**:

```c
// FreeBSD mutex
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

// Condition variables similar...
```

**Process Emulation**:

```c
// Global process objects
struct proc proc0;                         // Initial process
struct thread thread0_st;                  // Initial thread
struct vmspace vmspace0;                   // Virtual memory space
struct prison prison0;                     // Namespace
```

### 3.4 Kernel-Stack Coexistence Files (`FF_KERNEL_COEXIST`, optional)

Compiled only with `FF_KERNEL_COEXIST=1`:
- **`ff_host_interface.c` (617 L) / `.h` (187 L)**: `FF_KERNEL_FD_BASE=0x40000000` + inline `ff_is_kernel_fd/ff_kernel_fd_encode/ff_kernel_fd_real`; `ff_native_fd_map[65536]` + `ff_native_map_get/set/clear`; **32 `ff_host_*` host-libc bridges** (R9 added `ff_host_set_v6only`, `ff_host_kqueue_ctl`, `ff_host_kqueue_poll`; R10 added `ff_host_readv`, `ff_host_writev`, `ff_host_ioctl`, `ff_host_dup`, `ff_host_dup2`).
- **`ff_epoll.c` (289 L)**: `ff_epoll_pairs[64]` lazily pairs a host `epoll` per kqueue; `ff_epoll_wait` polls host epoll (non-blocking) then merges kqueue events (single-threaded, no lock). `ff_epoll_host_ep` is shared (promoted from `static`) so the R9 kqueue path reuses the same pairing table.
- **R9 kqueue/kevent coexistence (`ff_syscall_wrapper.c`)**: `ff_kqueue`/`ff_kevent` mirror the epoll path — register a kernel/dual-stack fd's `EVFILT_READ/WRITE` into the kqueue-paired host epoll (`ff_host_kqueue_ctl`), synthesize `struct kevent` from a non-blocking `ff_host_kqueue_poll` (`ident`=app-side fd, `EV_EOF`↔`EPOLLHUP|ERR`), then merge `ff_kevent_do_each` F-Stack events. Fixes the `example/main.c` kqueue model (kernel-side `curl 127.0.0.1:80`=200, was 000). Kernel fds: `EVFILT_READ/WRITE` only.
- **R9 IPv6**: a dual-built `AF_INET6` socket gets `IPV6_V6ONLY=1` on its host counterpart (`ff_host_set_v6only`), so a `-DINET6` build starts with v4+v6 on the same port (fixes the prior `errno=98 EADDRINUSE`).
- **R10 residual-entry coexistence (`ff_syscall_wrapper.c`)**: `ff_ioctl` (L1067) kernel fd uses the **raw Linux request** straight to `ff_host_ioctl` (NOT via `linux2freebsd_ioctl`; dual-stack fd same-driver since R10.1 syncs `FIONBIO`/`FIOASYNC` to the paired host fd (query ioctls like `FIONREAD` not forwarded, to avoid clobbering argp)); `ff_readv` (L1189)/`ff_writev` (L1251) kernel fd via `ff_host_readv/writev` (mimic read/write, connection fds single-stack hot path); `ff_dup` (L2130) kernel fd → `ff_host_dup`+encode; `ff_dup2` (L2156) both-kernel → `ff_host_dup2`+encode / cross-stack rejected `errno=EINVAL`. Known limits: `ff_select` (encode kernel fd ≫ `FD_SETSIZE` hard limit) / `ff_poll` (conservatively not implemented) do not support kernel-fd coexistence — use `ff_epoll_*`/`ff_kqueue`.
- **`ff_syscall_wrapper.c`**: `ff_socket` dual-create + per-entry kernel-fd routing (incl. R10 readv/writev/ioctl/dup/dup2).

## 4. Key Header File Overview

| Header | Lines | Purpose |
|--------|-------|---------|
| `ff_api.h` | ~500 | All public API declarations |
| `ff_config.h` | ~100 | Configuration structure definitions |
| `ff_event.h` | ~150 | kevent structures and macros |
| `ff_errno.h` | ~100 | 96 errno mappings |
| `ff_host_interface.h` | 187 | OS abstraction layer (pthread/mmap) + `FF_KERNEL_COEXIST` kernel-fd helpers & 32 `ff_host_*` bridge decls (incl. R9 set_v6only/kqueue_ctl/kqueue_poll, R10 readv/writev/ioctl/dup/dup2) |
| `ff_dpdk_if.h` | ~50 | DPDK initialization interface |
| `ff_veth.h` | ~100 | Virtual Ethernet and mbuf operations |
| `ff_log.h` | ~50 | Log levels and macros |
| `ff_memory.h` | ~80 | Memory management functions |
| `ff_msg.h` | ~60 | Cross-lcore message passing |
| `ff_epoll.h` | ~80 | epoll wrapper implementation |
| `ff_ini_parser.h` | ~50 | Configuration file parsing |
| `ff_dpdk_kni.h` | ~50 | KNI interface (optional) |

## 5. Compilation and Linking Instructions

### 5.1 Compiling the F-Stack Library

```bash
cd /data/workspace/f-stack/lib

# Basic compilation
make clean
make

# With IPv6 support
FF_INET6=1 make

# With KNI virtual NIC
FF_KNI=1 make

# With high-precision TCP timers
FF_TCPHPTS=1 make

# Install to system
make install PREFIX=/usr/local
```

### 5.2 Compiling Applications

```bash
gcc -o myapp main.c \
    -lfstack \
    $(pkg-config --cflags --libs libdpdk) \
    -lpthread -lm -O2

# Running examples
# Use start.sh to specify config.ini configuration file for startup (recommended approach)
bash start.sh -c config.ini -b ./myapp

# start.sh automatically calculates the number of processes based on lcore_mask in config.ini,
# and sequentially starts the primary process (--proc-type=primary) and secondary processes (--proc-type=secondary).
# Equivalent to:
#   ./myapp --conf config.ini --proc-type=primary --proc-id=0
#   ./myapp --conf config.ini --proc-type=secondary --proc-id=1
#   ...
```

## 6. Thread Safety Rules

### 6.1 Safe Operations (✓)

- Socket API (ff_socket, ff_read, ff_write)
- Configuration queries (ff_sysctl)
- Event waiting (ff_kevent, ff_epoll_wait)
- **Restriction**: Must be within the same lcore

### 6.2 Unsafe Operations (✗)

- Cross-lcore socket operations
- Modifying configuration while running
- Creating/destroying threads while running

### 6.3 Atomic Operations (✓)

DPDK memory pool atomic operations:
```c
rte_pktmbuf_alloc(pool);       // Multi-process safe
rte_pktmbuf_free(m);           // Multi-process safe
```

## 7. Common Error Codes

| Error | Value | Description |
|-------|-------|-------------|
| ENOTSOCK | 38 | Not a socket |
| ECONNREFUSED | 61 | Connection refused |
| ETIMEDOUT | 60 | Operation timed out |
| ENOTCONN | 57 | Socket not connected |
| EWOULDBLOCK | 35 | Resource temporarily unavailable |
| EMFILE | 24 | Too many open files |
| ENOMEM | 12 | Out of memory |

## Summary

F-Stack's Layer 3 defines 80+ exported functions, 11 core data structures, and three key source files (ff_syscall_wrapper, ff_dpdk_if, ff_glue). These components work together to implement a complete user-space TCP/IP protocol stack. Mastering these fundamentals is a prerequisite for high-performance network application development.
