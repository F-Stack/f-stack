# F-Stack v1.26 Layer 1 Architecture Analysis: System Overall Architecture

**Document Version**: 1.0  
**Analysis Date**: 2026-03-20  
**Coverage**: F-Stack v1.26 (FreeBSD 15.0 port, upgraded from 13.0 in 2025-2026 — M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS) + DPDK 24.11.6 LTS (upgraded from 23.11.5 on 2026-06-09) + FF_KERNEL_COEXIST kernel-stack coexistence (default off)  
**Target Audience**: Architects, system designers, performance optimization engineers

---

## 1. System Positioning and Innovation

### 1.1 The Core Problem F-Stack Solves

Performance bottlenecks in the traditional Linux kernel network stack:
- **Context switching overhead** - User-space ↔ kernel-space switching
- **System call overhead** - Every I/O requires a syscall
- **Interrupt handling overhead** - Frequent hard and soft interrupts
- **Memory copies** - Kernel buffer → user buffer
- **Centralized protocol stack processing** - Cannot fully utilize multi-core

**F-Stack's Solution**:

```
Traditional Mode (Linux Kernel Networking)
┌─────────────────┐
│   Application    │
├─────────────────┤
│ syscall (context switch)
├─────────────────┤
│  Kernel Network  │ ← All applications share one stack
│     Stack        │
├─────────────────┤
│    NIC Driver    │
└─────────────────┘

F-Stack Mode (User-Space Networking)
┌─────────────────────────────────────────┐
│ Process1 (core0)  Process2 (core1)  Process3 (core2) │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐
│  │  App       │  │  App       │  │  App       │
│  │ FreeBSD    │  │ FreeBSD    │  │ FreeBSD    │
│  │  Stack     │  │  Stack     │  │  Stack     │
│  │  (local)   │  │  (local)   │  │  (local)   │
│  └────────────┘  └────────────┘  └────────────┘
│        ↓               ↓               ↓
│    DPDK Polling Loop  (no interrupts, no syscalls)
└─────────────────────────────────────────┘
         ↓
    ┌─────────────┐
    │  NIC Hardware│ (RSS hardware classification)
    └─────────────┘
```

### 1.2 Core Innovation Points

1. **Kernel Bypass** - Completely bypass the Linux kernel network stack
2. **FreeBSD Porting** - Reuse mature TCP/IP protocol stack (20+ years of optimization)
3. **Multi-Process Isolation** - One independent process per core, no cross-core contention
4. **Polling Mode** - Trade 100% CPU for low latency and high throughput
5. **Hardware Acceleration** - Fully utilize RSS, TSO, Checksum Offload

### 1.3 Performance Metrics

Actual data on 10GbE link:

| Metric | F-Stack | Linux Kernel |
|--------|---------|-------------|
| **Single-core throughput** | 5M RPS | 200K RPS |
| **Latency p99** | 10μs | 100μs |
| **Connections** | 10M (single machine) | 1M (single machine) |
| **New connections** | 1M CPS | 100K CPS |
| **CPU utilization** | 100% | 30-50% |

---

## 2. Top-Level Directory Structure and Module Boundaries

### 2.1 Source Tree Layout

```
/data/workspace/f-stack/
│
├── lib/                                    # F-Stack core library (~21K lines of C code)
│   ├── ff_dpdk_if.c          (2907 lines) # ⭐ Most critical: DPDK/NIC driver
│   ├── ff_glue.c             (1467 lines) # Kernel emulation layer
│   ├── ff_config.c           (1694 lines) # Configuration parsing
│   ├── ff_syscall_wrapper.c  (2265 lines) # Linux↔FreeBSD adaptation (+ R9 kqueue coexist + IPV6_V6ONLY + R10 readv/writev/ioctl/dup/dup2 kernel-fd routing)
│   ├── ff_init.c             (69 lines)   # Initialization coordination
│   ├── ff_epoll.c            (289 lines)  # Epoll compat (unified F-Stack+kernel)
│   ├── ff_host_interface.c   (617 lines)  # Host OS iface + FF_KERNEL_COEXIST bridges (32 ff_host_*)
│   ├── ff_dpdk_kni.c                      # Virtual NIC support
│   ├── ff_*.h                             # API and data structure definitions
│   └── Makefile              (765 lines)  # Build system
│
├── freebsd/                                # FreeBSD 15.0 kernel port (upgraded from 13.0 in 2025-2026)
│   ├── sys/
│   │   ├── netinet/          # IPv4 protocol stack (TCP/UDP/IP/ICMP)
│   │   ├── netinet6/         # IPv6 protocol stack
│   │   ├── net/              # Generic network interfaces
│   │   ├── kern/             # Kernel services (malloc/mutex/synch)
│   │   └── vm/               # Virtual memory management (mbuf)
│   ├── amd64/                # x86 architecture code
│   └── contrib/ck/           # ConcurrencyKit atomic operations
│
├── dpdk/                                   # DPDK 24.11.6 LTS dependency (submodule)
│   ├── lib/
│   │   ├── eal/              # Environment Abstraction Layer
│   │   ├── ethdev/           # NIC generic interface
│   │   ├── mempool/          # Memory pool
│   │   └── ring/             # Lock-free queue
│   └── drivers/
│       └── net/              # Vendor NIC drivers
│
├── mk/                                     # Build system
│   ├── kern.pre.mk                        # FreeBSD build rules
│   ├── kern.mk
│   └── compiler.mk           # Compiler configuration
│
├── app/                                    # Application integration examples
│   ├── nginx-1.28.0/         # Nginx integration
│   └── redis-6.2.6/          # Redis integration
│
├── example/                                # Development examples
│   ├── main.c                # kqueue mode (recommended)
│   └── main_epoll.c          # epoll mode
│
├── tools/                                  # Operations tools
│   ├── top/                  # CPU statistics
│   ├── sysctl/               # Parameter management
│   ├── ifconfig/             # NIC configuration
│   ├── route/                # Route management
│   ├── netstat/              # Network statistics
│   ├── arp/                  # ARP table management
│   ├── ipfw/                 # Firewall management
│   ├── knictl/               # KNI control
│   ├── traffic/              # Traffic statistics
│   ├── ndp/                  # IPv6 Neighbor Discovery
│   ├── ngctl/                # Netgraph control
│   └── compat/ff_ipc.*       # IPC communication library
│
├── adapter/                                # Network adapters
│   ├── micro_thread/             # Micro-thread interface for stateful applications using F-Stack
│   └── syscall/                  # Builds libff_syscall.so + fstack instance binary; intercepts
│                                  # Linux syscalls via LD_PRELOAD and forwards them to the fstack
│                                  # instance through Hugepage shared memory (sem path or
│                                  # FF_USE_RING_IPC lock-free ring path). See adapter/syscall/README.md
├── doc/                                    # Original English documentation
├── docs/                                   # Three-layer architecture knowledge base docs
├── config.ini                # Default configuration file
└── start.sh                  # Multi-process startup script
```

### 2.2 Core Module Responsibility Boundaries

| Module | File | Lines | Responsibility | Dependencies |
|--------|------|-------|---------------|--------------|
| **NIC Driver Layer** | ff_dpdk_if.c | 2907 | DPDK initialization, NIC operations, core TX/RX logic | DPDK, ff_glue |
| **Glue Layer** | ff_glue.c | 1467 | Kernel API emulation (locks, memory, interrupts; M4 8-category 14.0+ ABI fixes) | FreeBSD sys, pthread |
| **Configuration System** | ff_config.c | 1694 | INI file parsing, runtime parameter management | ff_ini_parser |
| **Linux Compatibility** | ff_syscall_wrapper.c | 2265 | Socket option/errno mapping (M4 sockaddr update; FF_KERNEL_COEXIST routing; R9 kqueue coexist + IPV6_V6ONLY; R10 readv/writev/ioctl/dup/dup2 kernel-fd routing) | FreeBSD API |
| **Epoll Compatibility** | ff_epoll.c | 289 | Linux epoll → FreeBSD kqueue (unified F-Stack + kernel epoll; ff_epoll_host_ep shared with kqueue path) | ff_kqueue |
| **Initialization Coordination** | ff_init.c | 69 | Startup flow orchestration | All other modules |
| **Host Interface** | ff_host_interface.c | - | mmap/pthread/time interfaces | System libraries |
| **Virtual NIC** | ff_dpdk_kni.c | - | Kernel virtual NIC support | DPDK KNI |

### 2.3 Inter-Module Communication Relationships

```
Application Layer
  ↓
┌─────────────────────────────────────────────┐
│  FF API Layer (ff_api.h)                     │
│  - socket/bind/listen/accept/connect        │
│  - read/write/send/recv                     │
│  - kqueue/kevent/epoll/select               │
└──────────────┬──────────────────────────────┘
               ↓
        ┌──────┴──────┐
        ↓             ↓
   FreeBSD Stack  Epoll Compat Layer
   TCP/UDP/IP     (ff_epoll.c)
   │              │
   └──────┬───────┘
          ↓
   ┌─────────────────────────────┐
   │  Glue Layer (ff_glue.c)     │
   │  - Lock/condition var emulation │
   │  - Memory management         │
   │  - Timer/soft interrupt       │
   └──────────────┬──────────────┘
                  ↓
      ┌───────────┴───────────┐
      ↓                       ↓
   Config System      Linux Compat Layer
  (ff_config.c)  (ff_syscall_wrapper.c)
      │                       │
      └───────────┬───────────┘
                  ↓
        ┌──────────────────────┐
        │  DPDK Library        │
        │  - EAL               │
        │  - Mempool/Ring      │
        │  - Ethdev            │
        └──────────────┬───────┘
                       ↓
        ┌──────────────────────┐
        │  PMD Driver + NIC HW │
        └──────────────────────┘
```

---

## 3. Core Architecture Design

### 3.1 Layered Network Stack Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Application Layer                   │
│              (Nginx/Redis/Custom)                     │
└──────────────────────┬───────────────────────────────┘
                       │ FF API (80 export symbols)
┌──────────────────────▼───────────────────────────────┐
│              F-Stack Library (libfstack.a)            │
│  ├─ Socket API       (ff_socket/bind/listen/...)    │
│  ├─ I/O API          (ff_read/write/send/recv/...)  │
│  ├─ Event API        (ff_kqueue/ff_epoll/...)       │
│  └─ Route API        (ff_route_ctl/...)             │
└──────────┬─────────────────────────────────┬────────┘
           │                                  │
    ┌──────▼──────────┐          ┌───────────▼──────┐
    │ FreeBSD TCP/IP  │          │ Epoll Compat     │
    │ Protocol Stack  │          │ Layer            │
    │ ├─ TCP/UDP      │          │ (ff_epoll.c)     │
    │ ├─ IPv4/IPv6    │          │ Linux→kqueue     │
    │ ├─ ICMP/IGMP    │          │ conversion       │
    │ ├─ ARP          │          └──────────────────┘
    │ └─ Routing      │
    └────────┬────────┘
             │
    ┌────────▼──────────────────────────────────────┐
    │        Glue Layer (ff_glue.c 1467 lines)      │
    │ Kernel API User-Space Emulation                │
    │ ├─ Mutex/RWLock    (pthread_mutex_t)         │
    │ ├─ CondVar         (pthread_cond_t)          │
    │ ├─ malloc/free     (rte_malloc)              │
    │ ├─ callout/timer   (rte_timer)               │
    │ ├─ taskqueue       (soft interrupt emulation) │
    │ └─ Global vars     (ticks/vm_cnt/...)        │
    └────────┬──────────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────────┐
    │         DPDK Library (libdpdk.a)               │
    │                                                │
    │  EAL (Environment Abstraction Layer)           │
    │  ├─ Hugepage memory allocation                 │
    │  ├─ NUMA affinity                              │
    │  ├─ CPU core isolation and binding             │
    │  └─ Multi-process support (Primary/Secondary)  │
    │                                                │
    │  Mempool (High-efficiency memory pool)         │
    │  ├─ mbuf pre-allocation                        │
    │  ├─ Lock-free allocation/deallocation          │
    │  └─ Memory pool warm-up (avoid runtime alloc)  │
    │                                                │
    │  Ethdev (NIC generic interface)                │
    │  ├─ rte_eth_rx_burst()                        │
    │  ├─ rte_eth_tx_burst()                        │
    │  ├─ RSS configuration                          │
    │  └─ Hardware offload settings                  │
    │                                                │
    │  Ring (Lock-free queue)                        │
    │  ├─ Inter-process IPC message passing          │
    │  └─ Multi-process communication                │
    └────────┬──────────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────────┐
    │  PMD Driver (Poll Mode Driver)                │
    │  ├─ igb_uio kernel module (VF passthrough)    │
    │  ├─ vfio-pci (more secure)                    │
    │  └─ Vendor drivers (Intel i40e/ixgbe/ice)     │
    └────────┬──────────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────────┐
    │      NIC Hardware (Network Interface Card)     │
    │                                                │
    │  Hardware feature support:                     │
    │  ├─ RSS (Receive Side Scaling) - 5-tuple hash to RX queues │
    │  ├─ TSO (TCP Segmentation Offload)            │
    │  ├─ LSO (Large Send Offload)                  │
    │  ├─ RX/TX Checksum Offload                    │
    │  ├─ LRO (Large Receive Offload)               │
    │  └─ VLAN offload                              │
    │                                                │
    │  Communication method:                         │
    │  ├─ Interrupt-free polling (PMD)               │
    │  ├─ DMA direct memory access                   │
    │  ├─ Zero-Copy mbuf passing                     │
    │  └─ Optional: interrupt-driven + coalesce      │
    └────────────────────────────────────────────────┘
```

### 3.2 Packet Flow Analysis

#### **Ingress Path (Receive)**

```
NIC Hardware
  ↓ [RSS processor computes hash based on 5-tuple (SIP,DIP,Sport,Dport,Proto)]
RX Queue Set (corresponding to different CPU cores)
  ↓ [Each core polls its own RX queue]
Poll Mode Driver
  ↓ rte_eth_rx_burst(port, queue, &mbufs, burst_size)
DPDK mbuf Buffer (Zero-Copy pointer)
  ↓
process_packets() in ff_dpdk_if.c
  ├─ Extract L2/L3/L4 headers
  ├─ Protocol filtering (ARP/IPv4/IPv6/Multicast)
  ├─ Optional: packet dispatch callback
  └─ Call FreeBSD protocol stack entry
  ↓
FreeBSD Network Stack
  ├─ eth_input()          [Ethernet processing]
  ├─ ip_input()           [IP layer]
  ├─ tcp_input()/udp_input() [L4 layer]
  └─ sorecvX()            [Socket receive buffer]
  ↓
Application retrieves data via ff_read()/ff_recv()/ff_recvfrom()/ff_recvmsg()
```

**Key Features**:
- **Zero-Copy**: Data remains in mbuf throughout, no copy to kernel buffer
- **RSS Guarantee**: All packets of the same connection arrive at the same core (no reordering)
- **No Interrupts**: Polling mode does not trigger hardware interrupts

#### **Egress Path (Send)**

```
Application calls ff_write()/ff_send()/ff_sendto()/ff_sendmsg()
  ↓
FreeBSD TCP/UDP Protocol Stack
  ├─ tcp_output()      [TCP segmentation/sequencing]
  ├─ ip_output()       [IP addressing]
  └─ if_output()       [NIC output]
  ↓
if_start() in ff_glue.c
  ├─ Get mbuf from pending send queue
  ├─ Fill L2/L3/L4 headers
  ├─ Configure hardware offload options (e.g., TSO/Checksum)
  └─ Call send_single_packet()
  ↓
DPDK TX Queue
  ├─ rte_eth_tx_burst() [batch send]
  └─ Periodic drain (avoid packet delay)
  ↓
PMD Driver
  ↓ [DMA to NIC hardware]
NIC Hardware
  ├─ Execute TSO (if needed)
  ├─ Checksum computation
  └─ Ethernet transmission
```

**Key Optimizations**:
- **Batch Processing**: rte_eth_tx_burst() sends multiple mbufs at once
- **Hardware Offload**: TSO offloads large packet segmentation to hardware
- **Periodic Drain**: Prevents individual packets from staying in TX buffer too long

### 3.3 Main Processing Loop (Main Loop)

The core of F-Stack is an efficient polling loop:

```c
// Pseudocode
static int main_loop(void *arg) {
    struct rte_mbuf *pkts[MAX_PKT_BURST];
    
    while (!stop_loop) {
        // [1] Current TSC (Time Stamp Counter)
        cur_tsc = rte_rdtsc();
        
        // [2] Clock Management - Drive FreeBSD timers
        //    (TCP retransmission timers, keepalive, etc.)
        if (freebsd_clock.expire < cur_tsc) {
            rte_timer_manage();
        }
        
        // [3] Poll Receive - Iterate all RX queues
        for (each_rx_queue) {
            nb_rx = rte_eth_rx_burst(port_id, queue_id, 
                                     pkts, MAX_PKT_BURST);
            
            if (nb_rx > 0) {
                process_packets(pkts, nb_rx);  // Hand to FreeBSD stack
            }
        }
        
        // [4] Periodic Send - Flush TX buffer
        if ((cur_tsc - prev_tsc) > drain_tsc) {
            for (each_port) {
                rte_eth_tx_burst(port_id, queue_id, 
                                tx_buffer, nb_tx);
            }
            prev_tsc = cur_tsc;
        }
        
        // [5] Application Callback - Business logic
        if (loop_func) {
            loop_func(loop_arg);  // User's main_loop callback
        }
        
        // [6] Optional: Idle sleep
        if (idle_sleep && nb_rx == 0) {
            rte_delay_us(idle_sleep);  // Microsecond-level sleep
        }
    }
}
```

**Loop Characteristics**:
- **Pure polling**: No interrupts, trade 100% CPU for microsecond-level latency
- **Timer-driven**: Relies on CPU TSC counter for clock maintenance
- **Batch processing**: Process MAX_PKT_BURST packets per iteration
- **User-controllable**: Application handles business logic via loop_func callback

### 3.4 Kernel-Stack Coexistence Mode (`FF_KERNEL_COEXIST`, optional, default off)

By default every socket lives purely in the F-Stack user-space stack. The optional **kernel-stack coexistence** mode lets one process — and one `ff_epoll_wait` loop — serve traffic over **both** the F-Stack stack (high-performance path via the DPDK NIC) **and** the host Linux kernel stack (via loopback / the management NIC) at the same time. This lets a local `ping`/`curl` reach an F-Stack listener and lets the application `connect()` to local or external kernel-stack services, without giving up the F-Stack fast path.

**Two-level gate (zero regression when off):**
- Compile-time macro `FF_KERNEL_COEXIST` (built with `make FF_KERNEL_COEXIST=1`; default not defined). When undefined, the whole feature compiles out and the build is byte-for-byte identical to the pure-F-Stack library.
- Runtime switch `config.ini [stack] kernel_coexist=0|1` (default `0`). Even when compiled in, the feature stays off until explicitly enabled.

**How it works:**
- **Per-socket stack selection.** `ff_socket()` honours two flags OR-ed into `type`: `SOCK_FSTACK` forces the F-Stack stack, `SOCK_KERNEL` forces the host kernel stack. With no flag (and coexistence enabled) the socket is **dual-created** — an F-Stack socket plus a paired host-kernel socket. Priority: per-socket marker > config `kernel_coexist` > F-Stack.
- **Managed kernel-fd space.** A kernel-stack fd is handed to the application as `host_fd + FF_KERNEL_FD_BASE` (`0x40000000`), far above the maximum FreeBSD fd (`kern.maxfiles <= 65536`), so the two fd ranges never collide. F-Stack entry points recognise such an fd and route it to a thin host-libc bridge; the default F-Stack path is left untouched.
- **Dual-stack fd pairing.** For a dual-created socket the F-Stack fd ↔ host fd pairing is tracked in `ff_native_fd_map`, so control/data operations drive both stacks where it matters (e.g. `bind`/`listen` on both, `shutdown`/`close` on both). For a dual-created `AF_INET6` socket the host counterpart is set to `IPV6_V6ONLY=1` (`ff_host_set_v6only`, R9) so it coexists with the same-port host IPv4 socket; this fixes the prior `-DINET6` startup failure (`ff_bind` `errno=98 EADDRINUSE`).
- **Unified event loop.** `ff_epoll_*` lazily pairs one host `epoll` fd per kqueue, so kernel-fd and F-Stack events are delivered from the single `ff_epoll_wait()` the application already runs. **R9** extends the same mechanism to the native `ff_kqueue`/`ff_kevent` interface (shared `ff_epoll_host_ep` pairing): `ff_kevent` registers a kernel/dual-stack fd's `EVFILT_READ/WRITE` into the kqueue-paired host epoll and synthesizes `struct kevent` (`ident`=the app-side fd) from a non-blocking host-epoll poll before merging F-Stack kqueue events — so a pure-kqueue app (`example/main.c`) now reaches the kernel-side listener (measured `curl 127.0.0.1:80` = 200 size=438, was 000).
- **R10 residual-entry coexistence.** `ff_readv`/`ff_writev` kernel fd via `ff_host_readv/writev` (mimic read/write); `ff_ioctl` kernel fd uses the **raw Linux request** straight to `ff_host_ioctl` (dual-stack fd same-driver since R10.1 syncs `FIONBIO`/`FIOASYNC` to the paired host fd (query ioctls like `FIONREAD` not forwarded, to avoid clobbering argp)); `ff_dup`→`ff_host_dup`+encode, `ff_dup2` both-kernel→`ff_host_dup2`+encode / cross-stack rejected `errno=EINVAL`.

**Known limitations (this release):** kernel fds via kqueue support `EVFILT_READ/WRITE` only; `ff_select` (encode kernel fd ≥ `0x40000000` ≫ `FD_SETSIZE`(1024), hard limit) and `ff_poll` (conservatively not implemented) do not support kernel-fd coexistence — use `ff_epoll_*` / `ff_kqueue` for kernel-fd multiplexing. Full design, test, and review-gate record: `docs/kernel_event_support_spec/` (+ `zh_cn/`).

---

## 4. Multi-Process Architecture

### 4.1 Why Multi-Process Instead of Multi-Thread

**F-Stack's Design Choice: Multi-Process + Single-Thread Polling**

```
Question: Why not multi-thread?
━━━━━━━━━━━━━━━━━━━━━━━
1. FreeBSD protocol stack is not thread-safe
   - Protocol stack designed for single-thread execution
   - Numerous global variables and static data structures
   - Heavy locking needed → performance degradation

2. High context switching overhead
   - CPU cache pollution
   - TLB flush
   - Far inferior to single-thread polling

3. Shared memory complexity
   - Socket data structures shared across threads
   - Race conditions difficult to debug

Answer: Multi-process architecture
━━━━━━━━━━━━━━━━━━━━━━━
Core features:
✓ Each process has an independent FreeBSD protocol stack instance
✓ Single-thread polling, no contention, no locking
✓ Connection affinity via DPDK RSS classification
✓ Zero shared state between processes (except mempool/NIC)
✓ One process crash does not affect other processes
```

### 4.2 Multi-Process Deployment Model

```
Machine Resources:
├─ CPU: 8 cores
├─ NIC: 10GbE
└─ Memory: 16GB huge pages

F-Stack Deployment:
┌────────────────────────────────────────────────────┐
│  Primary Process - CPU 0                            │
│  ├─ DPDK EAL initialization                        │
│  ├─ Create shared hugepage/mempool                 │
│  ├─ Start all secondary processes                  │
│  └─ Listen for IPC messages from tools             │
│                                                     │
│  Secondary 1 - CPU 1         Secondary 2 - CPU 2  │
│  ┌──────────────────┐         ┌──────────────────┐
│  │ FreeBSD Stack     │         │ FreeBSD Stack     │
│  │ Instance          │         │ Instance          │
│  │ RX/TX Queue Map   │         │ RX/TX Queue Map   │
│  │ Independent Poll  │  ←RSS→  │ Independent Poll  │
│  └──────────────────┘         └──────────────────┘
│
│  Secondary 3 - CPU 3          ...Secondary N - CPU N
│  ...same structure              ...same structure
│
└────────────────────────────────────────────────────┘
         ↑                          ↑
         │ Shared                   │ Shared
    ┌────┴────────────────────────┴───┐
    │ DPDK Shared Resources            │
    │ ├─ Mempool (lock-free access)   │
    │ ├─ Ring (IPC message passing)   │
    │ ├─ Virtual NIC KNI (optional)   │
    │ └─ RSS Classification Table     │
    └────────┬────────────────────────┘
             │
    ┌────────▼────────────────────────┐
    │ NIC Hardware (single 10GbE)     │
    │ ├─ RX Queue 0 → Process 1      │
    │ ├─ RX Queue 1 → Process 2      │
    │ ├─ RX Queue 2 → Process 3      │
    │ └─ ...                          │
    └─────────────────────────────────┘
```

### 4.3 RSS (Receive Side Scaling) Connection Affinity

**Key Concept**: All packets of the same connection must arrive at the same core

```
NIC Hardware RSS Computation:
┌─────────────────────────────────┐
│ Received packet header           │
├─────────────────────────────────┤
│ hash(SIP, DIP, Sport, Dport) % N│  ← 5-tuple hash
├─────────────────────────────────┤
│ Result = RX queue number (0..N-1)│
└─────────────────────────────────┘
         ↓
   ┌─────────────────────┐
   │ RX Queue Q           │
   │ ↓ (process bound to core) │
   │ Process P handles    │
   └─────────────────────┘

Effect:
✓ TCP connection {192.168.1.1:8000 ↔ 10.0.0.1:80}
✓ All packets (including ACK/DATA) go to queue 2
✓ Process 2 handles this connection independently
✓ No cross-core synchronization needed
✓ Completely avoids TCP reordering and cache pollution
```

### 4.4 Initialization Flow

```
bash start.sh  (startup script)
  ├─ Calculate number of enabled cores in lcore_mask
  ├─ Set proc_id environment variable = 0
  ├─ Set proc_type = primary
  └─ Start primary process
       ↓
       ff_init(argc, argv)
       ├─ ff_load_config()              # Load config.ini
       ├─ ff_dpdk_init()                # DPDK EAL initialization
       │  ├─ rte_eal_init()             # Initialize EAL
       │  ├─ rte_mempool_create()       # Create mbuf memory pool
       │  ├─ rte_eth_dev_configure()    # Configure NIC
       │  ├─ rte_eth_rx_queue_setup()   # Create RX queues
       │  ├─ rte_eth_tx_queue_setup()   # Create TX queues
       │  └─ rte_eth_dev_start()        # Start NIC
       │
       ├─ ff_freebsd_init()             # Initialize FreeBSD protocol stack
       │  ├─ ff_glue_init()             # Initialize glue layer
       │  ├─ init_network_stack()       # Initialize network stack
       │  └─ init_route_table()         # Initialize routing table
       │
       ├─ ff_dpdk_if_up()               # Bring up NIC
       └─ ff_run(loop_func, arg)        # Enter polling loop
            ↓
            [Primary process executes loop_func callback while handling IPC]
            
       # Secondary process startup (parallelized by startup script)
       proc_id = 1, proc_type = secondary
       ff_init(argc, argv)              # Same initialization
       └─ ff_run(loop_func, arg)        # Enter polling loop

Inter-Process Communication (IPC):
    ff_ipc_init()                       # Connect to primary process EAL
    ff_ipc_send(msg)                    # Send control message
    ff_ipc_recv(msg, type)              # Receive response
    
    [RPC-style communication via DPDK Ring]
```

---

## 5. Technology Selection Analysis

### 5.1 Why Choose DPDK?

| Comparison | DPDK | NETMAP | PF_RING | Custom Stack |
|-----------|------|--------|---------|-------------|
| **Community** | ★★★★★ | ★★★ | ★★★ | × |
| **Cross-platform** | L/F/W | L/F | L only | Limited |
| **Ecosystem** | ★★★★★ | ★★ | ★ | × |
| **Performance** | ★★★★★ | ★★★★ | ★★★★ | ★★ |
| **HW Offload** | ★★★★★ | ★★★ | ★★★ | × |
| **Documentation** | ★★★★★ | ★★★ | ★★ | × |
| **Enterprise Adoption** | ★★★★★ | ★★ | ★★ | × |

**Reasons F-Stack Chose DPDK**:
1. Tencent already had DPDK experience (DNSPod project)
2. DPDK officially supports Primary/Secondary multi-process model
3. Complete hardware offload support (TSO/GSO/Checksum)
4. Mature ecosystem (OvS-DPDK/SPDK/VPP)
5. Highest vendor NIC driver support

### 5.2 Why Port FreeBSD Stack Instead of Custom?

**Comparison Analysis**:

```
Option A: Port FreeBSD Protocol Stack (F-Stack's choice)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pros:
✓ Mature code (20+ years of optimization) with good clarity
✓ Feature-complete (TCP/UDP/ICMP/IGMP/IPv6)
✓ High RFC compliance
✓ Already has BBR/RACK/DCTCP algorithms
✓ Short development cycle (6-12 months)

Cons:
✗ Large migration effort (glue layer needed)
✗ Complex debugging (kernel API emulation)
✗ Maintenance cost (tracking upstream changes)

Option B: Custom Network Stack
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pros:
✓ Highly customizable
✓ No external dependencies
✓ Autonomous maintenance

Cons:
✗ 2-3 year development cycle
✗ Many functional defects (non-RFC-compliant)
✗ Unknown performance (lack of validation)
✗ High protocol upgrade costs
✗ No modern algorithm support (BBR/RACK)

Option C: Use Linux Kernel Stack (Kernel Bypass)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✗ Does not meet requirements (core goal is to bypass kernel)

Porting to user-space pros:
✓ Fast iteration, early support for new features
✓ Generally slightly higher performance than FreeBSD

Porting to user-space cons:
✗ More complex code, less clear than FreeBSD
✗ Fast iteration means high effort to track community updates
```

**Historical Background**:
- F-Stack initially (2013-2016) developed a simple custom TCP/IP stack
- Discovered protocol functional defects and limited performance optimization potential
- In 2017, referenced libuinet/libplebnet, completely ported FreeBSD 11.0
- In 2021, upgraded to FreeBSD 13.0 (supporting BBR and other algorithms)
- In 2025-2026, completed first-stage upgrade to FreeBSD 15.0 (M0~M5 + runtime-fix + rib-fix + Phase-5b; CVM same-window A/B baseline + bare-metal physical baseline; NFR-1 PASS with one nginx_fstack 4-core short-conn `−6.10%` filed as a non-blocking trade-off observation; full evidence in `freebsd_13_to_15_upgrade_spec/`)

### 5.3 KNI (Kernel Network Interface) and virtio Design Decision

**KNI's Purpose**: Virtual NIC for communication with the Linux kernel

```
Application Layer
  ↓ Business data
F-Stack (User-space)
  ├─ Main business: Handle HTTP/DNS, etc.
  └─ Side path: Special addresses, management traffic
       ↓ (optional)
    Virtual NIC veth0 (kernel)
       ↓ Executable in kernel
    ├─ tc (traffic control)
    ├─ iptables (firewall)
    ├─ Monitoring tools
    └─ Integration with other systems (tunnels, etc.)
```

**Why "Optional"**:
- Pure F-Stack applications (e.g., DNS servers) don't need KNI
- Only enable when Linux system integration is needed
- KNI adds data copies, affects throughput (2-3%)

**Performance Characteristics**:

- Default rate limits: 1K QPS data, 9K QPS control, 10K QPS total
- Optional packet dispatch callback: application customizes which flows enter KNI

**KNI and virtio Selection**:

- In the current version, KNI functionality is retained, but the underlying implementation has switched from the `rte_kni.ko` kernel module to `virtio_user` (see lib/Makefile:34), no longer depending on the kernel KNI module

---

## 6. Performance Features and Hardware Acceleration

### 6.1 NIC Hardware Feature Support

F-Stack fully leverages modern NIC hardware acceleration:

| Feature | Description | Benefit |
|---------|-------------|---------|
| **RSS** | Receive Side Scaling | Multi-queue classification → multi-process handling |
| **TSO/GSO** | TCP Segment Offload | Offload large packet segmentation to hardware |
| **LRO** | Large Receive Offload | Hardware merges multiple small packets |
| **RX/TX Checksum** | Checksum offload | CPU doesn't compute checksums |
| **VLAN** | Virtual NIC | Hardware VLAN tag recognition |
| **Flow Isolate** | Flow classification | Fine-grained packet routing control |

### 6.2 Optimization Techniques

**1. Zero-Copy**
```
Traditional approach:
NIC → kernel buffer → application buffer (2 copies)

F-Stack approach:
NIC → DPDK mbuf → FreeBSD mbuf (0 copies, pointer passing only) → application
# [Note] Zero-copy from mbuf to application via socket interface is not yet supported;
# the separate zero-copy API ff_zc_mbuf_read() is planned for future implementation
```

**2. Batch Processing**
```
Single processing:
for i in 1..1M {
    process_packet(pkt[i])
}

Batch processing:
nb_rx = rte_eth_rx_burst(..., 32)  // Receive 32 at once
for i in 0..nb_rx-1 {
    process_packet(pkt[i])
}

Effect: Reduces function call overhead, improves CPU cache hit rate
```

**3. CPU Affinity**
```
At DPDK EAL startup:
  ├─ Reserve CPU cores for each lcore
  ├─ Disable CPU frequency scaling
  ├─ Disable CPU migration
  └─ Optimization: Ensure TLB, L1/L2/L3 cache hits

Result: Avoids cache pollution, reduces context switches
```

**4. Huge Pages**
```
4KB small pages:
  │ Virtual address space │  TLB (64 entries) │ Physical address │
  └───────────────────────┘                    └──────────────────┘
  1M pages → Frequent TLB misses

2MB huge pages:
  │  Virtual address space  │  TLB (64 entries)  │  Physical address  │
  └─────────────────────────┘                     └────────────────────┘
  512 pages → Very few TLB misses

Effect: Reduces performance degradation from TLB misses
```

---

## 7. Ecosystem Integration

### 7.1 Application Integration Methods

**Method 1: Direct FF API Calls (Recommended)**
```c
// Application code
#include <ff_api.h>

int main() {
    ff_init(argc, argv);
    
    int sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    ff_bind(sockfd, ...);
    ff_listen(sockfd, ...);
    
    ff_run(my_loop_func, arg);  // Enter polling
}
```

**Method 2: LD_PRELOAD Interception (e.g., Nginx)**

In LD_PRELOAD mode the application runs in two separate processes: a standalone `fstack`
instance (links libfstack.a, polls DPDK) plus the user application (e.g. nginx) preloaded
with `libff_syscall.so`. The two processes communicate over Hugepage shared memory — the
default is a semaphore-based path; setting `FF_USE_RING_IPC=1` switches the data plane to
a lock-free DPDK SPSC `rte_ring`. The `fstack` instance must be started before the
LD_PRELOAD application.

```bash
# 1) Start the fstack instance first (one or more instances)
./fstack --conf config.ini --proc-type=primary --proc-id=0 &

# 2) Then enable F-Stack support for Nginx via LD_PRELOAD
LD_PRELOAD=/path/to/libff_syscall.so nginx

# Hooked POSIX entries forwarded to ff_* / kqueue:
  socket()     → ff_socket()                 accept()     → ff_accept()
  bind()       → ff_bind()                   accept4()    → ff_accept() + SOCK_CLOEXEC/NONBLOCK
  connect()    → ff_connect()                listen()     → ff_listen()
  read()       → ff_read()                   close()      → ff_close()
  write()      → ff_write()                  ioctl()      → ff_ioctl()
  send/sendto/sendmsg() → ff_send/sendto/sendmsg()
  recv/recvfrom/recvmsg() → ff_recv/recvfrom/recvmsg()
  __read_chk / __recv_chk / __recvfrom_chk   (glibc _FORTIFY_SOURCE wrappers)
  epoll_create/ctl/wait() → kqueue-backed events (optional polling mode)
  fork()       → per-process FreeBSD struct thread (Linux-kernel-like semantics)
  ...

# Key environment variables / compile switches:
#   FF_KERNEL_EVENT=1   Forward kernel-only fds to host epoll in parallel
#   FF_MULTI_SC=1       SO_REUSEPORT-style multi-sc, one sc per worker fd
#   FF_USE_RING_IPC=1   Switch IPC to lock-free DPDK SPSC ring (default v3.4 opts)
```

See `adapter/syscall/README.md` for the full feature list, compile flags, known
limitations, and acknowledgements.

### 7.2 Tool Support

Operations tools communicate with F-Stack processes via IPC:

| Tool | Function | Mechanism |
|------|----------|-----------|
| **top** | CPU statistics | Send FF_TOP message, receive stats data |
| **sysctl** | Parameter query/modify | FF_SYSCTL message |
| **ifconfig** | NIC configuration | Read configuration structures |
| **route** | Route management | FF_ROUTE message |
| **netstat** | Network statistics | FF_TRAFFIC message |
| **arp** | ARP table | Query DPDK internal state |
| **ipfw** | Firewall | FF_IPFW_CTL message |
| **knictl** | KNI control | FF_KNICTL message |
| **traffic** | Traffic statistics | FF_TRAFFIC message, supports multi-process aggregation |
| **ndp** | IPv6 Neighbor Discovery | ioctl communication (SIOCGNBRINFO_IN6, etc.) |
| **ngctl** | Netgraph control | FF_NGCTL message |

---

## 8. Summary

### 8.1 Three Core Innovations of F-Stack

1. **Kernel Bypass** - Bypass the Linux kernel network stack, reduce context switching and system call overhead
2. **FreeBSD Porting** - Reuse mature 20+ year optimized TCP/IP protocol stack
3. **Multi-Process Isolation** - Fully utilize multi-core, each core polls independently, zero cross-core contention

### 8.2 Performance Advantages

- **Throughput**: 5M RPS (compared to kernel 200K RPS, 25x improvement)
- **Latency**: P99 < 10μs (compared to kernel 100μs, 10x reduction)
- **Connections**: 10M concurrent connections (compared to kernel 1M, 10x improvement)

### 8.3 Use Cases

✓ DNS servers (high QPS, low latency)  
✓ Load balancers (connection handling capacity)  
✓ CDN edge nodes (content delivery)  
✓ VPN gateways (throughput optimization)  
✓ High-performance web servers  
✗ General Linux applications (high modification cost)  

### 8.4 Learning Path Recommendations

**Step 1**: Understand the advantages of Kernel Bypass  
**Step 2**: Learn DPDK basics (EAL/Mempool/Ethdev)  
**Step 3**: Understand key parts of the FreeBSD protocol stack  
**Step 4**: Study the TX/RX logic in ff_dpdk_if.c  
**Step 5**: Learn multi-process deployment and performance tuning  

---

**Related Documents**:
- [Layer 2: Interface Definitions and Specifications](./F-Stack_Architecture_Layer2_Interface_Specification.md)
- [Layer 3: Function-Level Index](./F-Stack_Architecture_Layer3_Function_Index.md)
- [Knowledge Base Summary](./F-Stack_Knowledge_Base_Summary.md)
