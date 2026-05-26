# F-Stack v1.25 Layer 1: Overall Architecture and Module Boundaries

> **Target Audience**: System architects, technical leads  
> **Key Concepts**: Module partitioning, technology selection, data flow, process model  
> **Generation Date**: 2026-03-20

## 1. Top-Level Architecture Overview

### 1.1 F-Stack Core Innovations

F-Stack adopts a "user-space network stack" architecture to address the performance bottleneck of Linux kernel network processing:

```text
Application Layer (Applications)
  ↓ (ff_socket/ff_read/ff_write and other Linux-like APIs)
F-Stack Library (libfstack.a)
  ├─ FreeBSD TCP/IP stack port
  ├─ Glue layer (ff_glue.c) - Kernel emulation
  └─ System call adaptation (ff_syscall_wrapper.c)
  ↓
DPDK Library (libdpdk)
  ├─ EAL (Environment Abstraction Layer)
  ├─ Mempool (mbuf memory pool)
  └─ Ethdev (NIC driver-agnostic interface)
  ↓
NIC Driver (igb_uio / vfio-pci)
  ↓
NIC Hardware
```

### 1.2 Three Core Pillars

| Pillar | Component | Purpose |
|--------|-----------|---------|
| **Kernel Bypass** | DPDK + PMD | Bypass Linux kernel network bottleneck |
| **Mature Protocol Stack** | FreeBSD 13.0 port | Reuse battle-tested TCP/IP implementation |
| **Multi-Core Parallelism** | Multi-process architecture + RSS | Fully utilize multi-core processing capability |

### 1.3 Key Performance Metrics

- **Concurrent connections**: 10M+
- **Request throughput**: 5M+ RPS (Requests Per Second)
- **Connection establishment**: 1M+ CPS (Connections Per Second)
- **Latency**: Microsecond-level (vs. millisecond-level kernel stack)

> **Note**: The above performance data is for reference only. Actual results depend on hardware configuration (CPU/NIC), test scenarios, and packet sizes.

## 2. Directory Structure and Module Boundaries

### 2.1 Core Directory Layout

```text
/data/workspace/f-stack/
├── lib/                          # F-Stack core library (~21K lines of C code)
│   ├── ff_dpdk_if.c   (2855 lines) # DPDK NIC interface layer - most critical
│   ├── ff_glue.c      (1466 lines) # FreeBSD glue layer
│   ├── ff_config.c    (1379 lines) # Configuration parsing
│   ├── ff_syscall_wrapper.c     # Linux→FreeBSD system call adaptation
│   ├── ff_host_interface.c      # Host interface (pthread/mmap/time)
│   ├── ff_init.c         (69 lines) # Initialization coordination
│   ├── ff_epoll.c       (159 lines) # epoll interface conversion
│   ├── ff_dpdk_kni.c            # Virtual NIC support (via virtio_user, no longer depends on rte_kni.ko)
│   ├── Makefile                 # Build system
│   └── include/                 # Header files
│
├── freebsd/                      # FreeBSD 13.0 kernel code port
│   ├── sys/
│   │   ├── netinet/   # IPv4 protocol stack
│   │   ├── netinet6/  # IPv6 protocol stack
│   │   ├── net/       # Generic network interfaces
│   │   ├── kern/      # Kernel services (malloc/locks/timers)
│   │   └── vm/        # Virtual memory
│   ├── amd64/         # x86 architecture-specific code
│   └── contrib/ck/    # ConcurrencyKit dependency
│
├── dpdk/                         # DPDK 23.11.5 (submodule)
│   └── build/                    # Build artifacts
│
├── app/                          # Application integration
│   ├── nginx-1.28.0/
│   └── redis-6.2.6/
│
├── example/                      # Example code
│   ├── main.c          (222 lines) # kqueue HTTP server
│   └── main_epoll.c    (143 lines) # epoll HTTP server
│
├── mk/                           # Build system
│   ├── kern.pre.mk     # FreeBSD build rules
│   ├── kern.mk         # Kernel build rules
│   └── compiler.mk     # Compiler configuration
│
├── tools/                        # Tool scripts
├── adapter/                      # Network adapters
│   ├── micro_thread/             # Micro-thread interface for stateful applications using F-Stack
│   └── syscall/                  # Builds libff_syscall.so + an fstack instance binary; intercepts
│                                  # Linux syscalls (socket/bind/connect/read/write/send/recv/
│                                  # epoll/accept4/__recv_chk/fork/ioctl ...) via LD_PRELOAD and
│                                  # forwards them to the fstack instance through Hugepage-backed
│                                  # shared memory (sem path or FF_USE_RING_IPC lock-free ring path)
├── doc/                          # Original English documentation
├── docs/                         # Three-layer architecture knowledge base docs
└── config.ini                    # Default configuration file
```

### 2.2 Core Module Responsibility Boundaries

| Module | Lines | Responsibility | Dependencies |
|--------|-------|---------------|--------------|
| **ff_dpdk_if.c** | 2855 | NIC driver/DPDK operations/core TX/RX logic | DPDK, ff_glue |
| **ff_glue.c** | 1466 | FreeBSD kernel emulation/memory/locks/interrupts | FreeBSD headers, DPDK |
| **ff_config.c** | 1379 | INI configuration file parsing | ff_ini_parser |
| **ff_syscall_wrapper.c** | 1825 | Linux system call → FreeBSD adaptation | FreeBSD sys |
| **ff_init.c** | 69 | Initialization flow coordination | All above modules |
| **ff_epoll.c** | 159 | Linux epoll → FreeBSD kqueue conversion | FreeBSD kqueue |
| **ff_host_interface.c** | -- | Host OS interface (mmap/pthread/rand) | System libraries |
| **ff_dpdk_kni.c** | -- | Virtual NIC support (via virtio_user, no longer depends on rte_kni.ko) | DPDK virtio_user |

## 3. FreeBSD TCP/IP Stack Porting Approach

### 3.1 Porting Strategy

F-Stack adopted a **complete porting** strategy:
- Extracted the full TCP/IP protocol stack code from FreeBSD 13.0
- Retained all network protocol code in `freebsd/sys/netinet/`
- Implemented user-space emulation of kernel APIs through `ff_glue.c`
- Supported optional features through conditional compilation (IPv6, KNI, TCPHPTS, etc.)

### 3.2 Ported FreeBSD Subsystems

```text
freebsd/sys/
├── netinet/        # IPv4: tcp_*.c, udp_*.c, ip_*.c, if_arp.c
├── netinet6/       # IPv6: ip6_*.c, tcp6_*.c
├── net/            # Generic network: if.c, route.c, netisr.c
├── kern/           # Kernel services: malloc, mutex, synch, callout
├── vm/             # Virtual memory: vm_page.c (mbuf mapping)
└── sys/            # System definitions: socket.h, mbuf.h, etc.
```

### 3.3 Kernel Emulation in ff_glue.c

| Kernel Feature | FreeBSD Native | F-Stack Emulation |
|---------------|----------------|-------------------|
| Memory allocation | `malloc()` | DPDK `rte_malloc()` |
| Mutexes | `struct mtx` | `pthread_mutex_t` |
| Condition variables | `struct condvar` | `pthread_cond_t` |
| Soft interrupts | `swi_*` | Internal taskqueue |
| Timers | `callout{}` | DPDK `rte_timer` |
| Paged memory | `vm_page_alloc()` | DPDK mempool |

## 4. DPDK Integration and NIC Driver Layer

### 4.1 ff_dpdk_if.c Core Responsibilities

This is the most critical module (2855 lines), responsible for the entire data link:

**Initialization Flow**:
```text
ff_dpdk_init()
  ├─ rte_eal_init()              // DPDK environment initialization
  ├─ init_lcore_conf()           // CPU core/port mapping
  ├─ init_mem_pool()             // mbuf memory pool creation
  ├─ init_dispatch_ring()        // Inter-process message queue
  ├─ init_port_start()           // NIC startup + RSS configuration
  ├─ ff_rss_tbl_init()           // RSS classification table setup
  └─ init_clock()                // FreeBSD clock initialization
```

### 4.2 Ingress Packet Flow

```text
NIC Hardware (RSS processor distribution)
  ↓
Multiple RX Queues (per-CPU-core)
  ↓
DPDK PMD (rte_eth_rx_burst())
  ↓
process_packets() function
  ├─ Protocol filtering (ARP/IPv4/IPv6/Multicast)
  ├─ Virtual NIC processing (veth_input)
  └─ FreeBSD stack (if_input → eth_input → ip_input → tcp_input → sorecv)
```

### 4.3 Egress Packet Flow

```text
Application (ff_write/ff_send/ff_sendto/ff_sendmsg)
  ↓
FreeBSD TCP/UDP Stack
  ├─ tcp_output() / udp_output()
  ├─ ip_output()
  └─ if_output()
  ↓
ff_glue.c if_start()
  ├─ Retrieve mbuf
  ├─ Fill L2/L3/L4 headers
  ├─ Configure hardware offload (TSO/Checksum)
  └─ send_single_packet()
  ↓
DPDK rte_eth_tx_burst()
  ↓
NIC Hardware
```

## 5. Main Processing Loop

### 5.1 main_loop() Pseudocode

```c
int main_loop(void *arg) {
    while (!stop_loop) {
        // [1] Drive FreeBSD timers
        if (freebsd_clock.expire < cur_tsc) {
            rte_timer_manage();
        }
        
        // [2] Poll all RX queues
        for (each_rx_queue) {
            nb_rx = rte_eth_rx_burst(...);
            process_packets(pkts_burst, nb_rx);
        }
        
        // [3] Periodically flush TX queues
        if (drain_tsc && (cur_tsc - prev_tsc) > drain_tsc) {
            for (each_port) {
                rte_eth_tx_burst(...);
            }
        }
        
        // [4] Execute user callback
        if (usr_loop) {
            usr_loop(arg);
        }
    }
}
```

### 5.2 Polling Characteristics

- **No interrupts**: → Low latency, high throughput
- **CPU-intensive**: 100% utilization (optimized through CPU isolation)
- **Configurable sleep**: `idle_sleep` parameter supports microsecond-level yielding

## 6. Process Model

### 6.1 Single-Process Mode (Recommended)

```text
F-Stack Process (1)
  └─ Single lcore (1 CPU core)
    ├─ NIC RX/TX queue mapping
    ├─ FreeBSD protocol stack execution
    └─ Application logic execution
```

**Use case**: Small applications, dedicated appliances

### 6.2 Multi-Process Mode

```text
Primary Process
  ├─ DPDK EAL initialization
  └─ Start N worker processes

Worker-0 (CPU-0)  ┐
Worker-1 (CPU-1)  ├─ Each process runs independently
...               │  Connection affinity maintained via RSS
Worker-N (CPU-N)  ┘

Shared Resources:
  ├─ DPDK Mempool
  ├─ RSS Classification Table
  └─ Virtual NIC (KNI)
```

**Advantages**: Fault isolation, flexible scaling  
**Disadvantages**: Complex inter-process synchronization

## 7. Technology Selection Analysis

### 7.1 Why DPDK Instead of NETMAP/PF_RING

| Comparison | DPDK | NETMAP | PF_RING |
|-----------|------|--------|---------|
| Community activity | ★★★★★ | ★★★ | ★★★ |
| Cross-platform | ✓ | ✓ | ✗ (Linux only) |
| Ecosystem completeness | ★★★★★ | ★★★ | ★★ |
| Enterprise adoption | ★★★★★ | ★★★ | ★★ |
| Hardware offload support | ★★★★★ | ★★★ | ★★ |

**Selection rationale**:
- Tencent already had DPDK experience (DNSPod DNS)
- Most comprehensive multi-process architecture support
- Broadest hardware offload support (TSO/GSO/Checksum)

### 7.2 Why FreeBSD Stack Instead of Custom Implementation

| Aspect | FreeBSD Stack | Custom Stack |
|--------|--------------|--------------|
| Development cycle | Ready to use | 2-3 years |
| Feature completeness | ★★★★★ | ★★★ |
| Performance optimization | ★★★★★ | ★★ |
| RFC compliance | ★★★★★ | ★★★ |
| Community feedback | ★★★★★ | None |
| Maintenance cost | ★★★ | ★★★★★ |

**Historical background**:
- Initially developed a simple custom stack → insufficient stability
- In 2017, referenced libplebnet/libuinet → complete FreeBSD stack port
- This decision shaped today's architecture

## 8. Hardware Offload Features

F-Stack fully leverages modern NIC hardware capabilities:

### 8.1 RX Offload

| Feature | Effect | Support Level |
|---------|--------|--------------|
| **Checksum offload** | L3/L4 verification done by hardware | Widespread |
| **LRO** (Large Receive Offload) | Merge small packets into large ones | Partial |

### 8.2 TX Offload

| Feature | Effect | Support Level |
|---------|--------|--------------|
| **TSO** (TCP Segmentation Offload) | Large packets segmented by hardware | Widespread |
| **Checksum offload** | L3/L4 checksum computation | Widespread |
| **VLAN insertion** | Hardware adds VLAN tags | Partial |

### 8.3 Flow Classification (RSS)

- **Hardware RSS**: Based on 5-tuple (src-ip, dst-ip, src-port, dst-port, proto)
- **Benefits**: Same connection always routed to the same RX queue → avoids TCP reordering

## Summary

F-Stack's architecture design revolves around three core pillars:
1. **Kernel Bypass**: Bypass Linux kernel bottleneck
2. **Mature Protocol Stack**: Reuse FreeBSD's battle-tested implementation
3. **Multi-Core Parallelism**: Fully utilize modern multi-core CPUs and NIC hardware capabilities

This enables F-Stack to achieve 5M+ RPS and 10M+ concurrent connections, making it an ideal choice for core cloud computing network infrastructure.
