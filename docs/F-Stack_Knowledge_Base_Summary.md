# F-Stack v1.26 Complete Knowledge Base Summary

**Document Version**: 1.0  
**Generation Date**: 2026-03-20  
**Content Scope**: F-Stack v1.26 (FreeBSD 15.0 port; upgraded from 13.0 in 2025-2026 — M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS; **Phase-2 M6 NETGRAPH+IPFW + M7 PAGE_ARRAY + M8 ZC_SEND + M9 PA+ZC + M10 FLOW_IPIP + M11 FLOW_ISOLATE + M12 FDIR + M13 LOOPBACK + Phase-5b perf baseline matrix + F-A1 fix (PA-only now production-ready), 2026-06-08**) + DPDK 24.11.6 LTS (upgraded from 23.11.5 LTS on 2026-06-09 — tree replace + 4 patches re-applied; helloworld + nginx single/multi-worker + ipfw + vlan smoke all PASS) Complete Three-Layer Architecture Knowledge Base  
**Document Location**: `/data/workspace/f-stack/docs/`  
**Purpose**: Pre-requisite architecture documentation for Spec-Driven Development

---

## 1. Document Structure and Navigation

### 1.1 Three-Layer Architecture Knowledge Base

This knowledge base consists of three layers of detailed documentation:

```
F-Stack Architecture Knowledge Base
├─ Layer 1: System Overall Architecture (8200 words)
│  ├─ System Positioning and Innovation
│  ├─ Top-Level Directory Structure and Module Boundaries
│  ├─ Core Architecture Design (Layering/Data Flow/Loop)
│  ├─ Multi-Process Model (Primary-Secondary)
│  ├─ Technology Selection Analysis (DPDK/FreeBSD/KNI)
│  ├─ Performance Features and Hardware Acceleration
│  ├─ Ecosystem Integration
│  └─ Key Metrics and Use Cases
│
├─ Layer 2: Interface Definitions and Specifications (9500 words)
│  ├─ Public API Architecture (80+ function categories)
│  ├─ Six Main Header File Details
│  ├─ System Call Mapping Table (Linux ↔ FreeBSD)
│  ├─ Configuration System Deep Analysis (config.ini)
│  ├─ Multi-Process and Multi-Thread Interfaces
│  ├─ Application Development Guidelines (Three Modes/Pitfalls/Optimization)
│  ├─ Tools and Integration Interfaces (IPC Tool List)
│  └─ Development Practical Guide
│
└─ Layer 3: Function-Level Index and Data Model (10200 words)
   ├─ Complete Function Export List (80+ function details)
   ├─ Core Data Structure Details (Kevent/Config/etc.)
   ├─ Three Key Source File Analyses (ff_syscall_wrapper/ff_dpdk_if/ff_glue)
   ├─ Thread Safety Analysis (Per-thread Model)
   ├─ Compilation and Linking Guide
   └─ Performance Optimization Parameters
```

### 1.2 Quick Navigation Table

| Need to Know | Recommended Reading |
|-------------|-------------------|
| What is F-Stack? Why use it? | Layer 1 §1 (System Positioning) |
| What is F-Stack's architecture? | Layer 1 §3 (Core Architecture) |
| How to develop F-Stack applications? | Layer 2 §5 (Development Guidelines) |
| Detailed description of each API function | Layer 3 §1 (Function List) |
| How are socket options mapped? | Layer 2 §2 (System Call Mapping) |
| How to configure F-Stack? | Layer 2 §3 (Configuration System) |
| How to implement multi-process deployment? | Layer 2 §4 (Multi-Process Model) |
| Memory layout of data structures | Layer 3 §2 (Data Model) |
| How is thread safety guaranteed? | Layer 3 §4 (Thread Safety) |
| How to optimize performance? | Layer 1 §6 + Layer 2 §5.4 |
| How does the kernel code work? | Layer 3 §3 (Source File Analysis) |

---

## 2. Core Concepts Quick Reference

### 2.1 Three Key Innovations of F-Stack

```
Innovation 1: Kernel Bypass
  Goal: Eliminate system call overhead and context switching
  Method: User-space polling + interrupt-free direct NIC operations
  Benefit: Latency reduced from 100μs to 10μs

Innovation 2: FreeBSD Protocol Stack Porting
  Goal: Reuse mature 20+ year optimized TCP/IP stack
  Method: Port FreeBSD 15.0 network stack code to user space (originally 13.0; upgraded in 2025-2026 with full evidence in `freebsd_13_to_15_upgrade_spec/`)
  Benefit: Feature-complete, RFC-compliant, supports modern algorithms (BBR/RACK)

Innovation 3: Multi-Process Isolation + Polling
  Goal: Fully utilize multi-core + avoid cross-core contention
  Method: One process per core, independent polling loop
  Benefit: Completely lock-free + cache affinity + fault isolation
```

### 2.2 Key Performance Data

Actual benchmark data on 10GbE network:

| Metric | F-Stack | Linux Kernel | Improvement |
|--------|---------|-------------|-------------|
| **Throughput (RPS)** | 5M | 200K | **25x** |
| **Latency P99** | 10μs | 100μs | **10x** |
| **New Connections (CPS)** | 1M | 100K | **10x** |
| **Concurrent Connections** | 10M | 1M | **10x** |
| **CPU Utilization** | 100% | 30-50% | More efficient |

### 2.3 Use Case Matching

```
✓ High Match:
  - DNS servers (high QPS, low latency) - DNSPod production case
  - Load balancers (connection handling capacity)
  - CDN edge nodes (content delivery acceleration)
  - VPN gateways (throughput optimization)
  - High-performance web servers

⚠️ Medium Match:
  - Stateful applications (require modifications)
  - Integration with Linux system (enable KNI)

✗ Low Match:
  - General Linux applications (high modification cost)
  - Extremely high real-time requirements (already at limits)
  - Low-traffic applications (resource waste)
```

---

## 3. Architecture Layer Details

### 3.1 Layer 1: System Overall Architecture

**File**: `F-Stack_Architecture_Layer1_System_Overview.md`  
**Coverage**: 23 subsections

**Key Content**:

```
System Positioning and Innovation
  → Kernel Bypass solution
  → FreeBSD stack porting decision
  → Performance metric benchmarks

Top-Level Module Boundaries
  → 10 core module responsibility list
  → Inter-module communication diagram
  → Dependency relationship matrix

Core Architecture Design
  → Layered network stack (Application → Protocol Stack → DPDK → Hardware)
  → Complete packet flow direction (Ingress/Egress)
  → Main processing loop logic (Polling + Clock + Event Handling)

Multi-Process Architecture
  → Primary-Secondary model
  → RSS connection affinity guarantee
  → Initialization flow sequence diagram

Technology Selection Analysis
  → Why DPDK (vs NETMAP/PF_RING)
  → Why FreeBSD stack (vs custom)
  → KNI design decision (optional component)

Performance Features
  → Zero-Copy
  → Batch Processing
  → CPU Affinity
  → Huge Page Memory Optimization

Ecosystem Integration
  → Nginx/Redis integration methods
  → Operations tool list (top/sysctl/route/traffic/ndp/ngctl/etc)
```

**Target Audience**: Architects, CTOs, performance analysts, system designers

### 3.2 Layer 2: Interface Definitions and Specifications

**File**: `F-Stack_Architecture_Layer2_Interface_Specification.md`  
**Coverage**: 26 subsections

**Key Content**:

```
Public API Architecture
  → 80+ export symbol categories (Lifecycle/Socket/I/O/Event/etc)
  → Six main header file details
    ├─ ff_api.h (412 lines) - Main API
    ├─ ff_epoll.h (3 functions) - Linux compatible
    ├─ ff_config.h (1381 lines) - Configuration
    ├─ ff_event.h - Kevent events
    ├─ ff_errno.h - Error code mapping
    └─ ff_log.h - Logging system

System Call Mapping Table
  → Linux ↔ FreeBSD option mapping
  → sockaddr address structures
  → errno error code mapping

Configuration System Analysis
  → config.ini section details ([dpdk]/[portN]/[vlan]/[freebsd.boot]/etc)
  → Configuration priority rules
  → Configuration loading flow

Multi-Process Interfaces
  → Primary-Secondary startup script
  → IPC message structure and communication mechanism
  → Inter-process coordination Ring mechanism

Multi-Thread Interfaces
  → Per-thread socket table
  → Thread isolation rules
  → Concurrency model

Application Development Guidelines
  → Three development modes (Kqueue/Epoll/Select)
  → 5 key rules
  → 7 common pitfalls and solutions
  → 5 performance optimization recommendations

Tools and Integration
  → 11 IPC operations tools
  → LD_PRELOAD integration method (libff_syscall.so: fork / accept4 / __recv_chk / epoll polling / FF_USE_RING_IPC ring IPC)
  → Application integration interfaces
```

**Target Audience**: Application developers, system integration engineers, operations engineers

### 3.3 Layer 3: Function-Level Index and Data Model

**File**: `F-Stack_Architecture_Layer3_Function_Index.md`  
**Coverage**: 18 subsections

**Key Content**:

```
Complete Function Export List
  → Lifecycle management (3)
  → Socket lifecycle (12)
  → Data I/O operations (13)
  → Event multiplexing (7)
  → Socket option operations (6)
  → Route management (1)
  → Zero-Copy Mbuf (5)
  → Multi-threading support (2)
  → Logging and diagnostics (8)
  → System interfaces (8+)

Each function includes:
  - Complete signature
  - Parameter description
  - Return value and error handling
  - Thread safety classification
  - Usage notes

Core Data Structures
  → struct kevent (BSD event structure)
  → struct epoll_event (Linux epoll structure)
  → struct ff_config (global configuration)
  → struct sockaddr_in/in6 (address structures)
  → struct iovec (scatter/gather I/O)
  → struct msghdr (message header)
  → struct pollfd (poll structure)

Key Source File Analyses
  → ff_syscall_wrapper.c (2265 lines)
    ├─ Linux ↔ FreeBSD option mapping tables
    ├─ Address family mapping
    └─ Parameter conversion logic
  
  → ff_dpdk_if.c (2907 lines)
    ├─ Global variables (11 key states)
    ├─ Initialization flow
    ├─ Packet processing logic
    └─ Main polling loop
  
  → ff_glue.c (1467 lines)
    ├─ Kernel primitive emulation (locks/condition variables)
    ├─ Memory management emulation
    └─ Global variable emulation

Thread Safety Analysis
  → Fully thread-safe function list
  → Conditionally thread-safe function list
  → Non-thread-safe function list
  → Per-thread socket table mechanism

Compilation and Linking
  → Compilation commands
  → Application linking options
  → Runtime dependencies (hugepage/NIC driver)
```

**Target Audience**: Kernel developers, performance analysts, debug engineers, low-level engineers

---

## 4. Spec-Driven Development Application

### 4.1 Workflow Using This Knowledge Base

```
Development task arrives
  ↓
Step 1: Read Layer 1 (Understand architecture)
  ├─ Understand where the feature fits in the system
  ├─ Understand related modules and interfaces
  └─ Evaluate technical feasibility
  ↓
Step 2: Read Layer 2 (Learn interfaces)
  ├─ Find relevant API functions
  ├─ Understand parameters and return values
  ├─ Read development guidelines and pitfalls
  └─ Choose appropriate development mode
  ↓
Step 3: Read Layer 3 (Deep dive into details)
  ├─ Check function thread safety
  ├─ Understand data structure memory layout
  ├─ Study source code implementation (if needed)
  └─ Verify performance constraints
  ↓
Step 4: Write code + Test
  ├─ Follow development guidelines
  ├─ Avoid common pitfalls
  ├─ Apply performance optimization recommendations
  └─ Verify thread safety
```

### 4.2 Knowledge Base Query Paths for Common Tasks

**Task 1: Develop a High-Performance HTTP Server**
```
Query path:
  1. Layer 1 §1 → Understand F-Stack architecture
  2. Layer 1 §7 → View Nginx integration case
  3. Layer 2 §5.1 → Learn Kqueue development mode (recommended)
  4. Layer 2 §5.2 → Follow development guidelines
  5. Layer 2 §5.3 → Avoid common pitfalls
  6. Layer 2 §5.4 → Apply performance optimization

Implementation steps:
  - Call ff_init() to initialize
  - Create listening socket
  - Create kqueue object
  - Register socket with kqueue
  - Enter ff_run() main loop
  - Handle events in loop callback
```

**Task 2: Add Support for a New Socket Option**
```
Query path:
  1. Layer 2 §2 → View system call mapping
  2. Layer 3 §3.1 → Understand ff_syscall_wrapper implementation
  3. Layer 3 §2.1 → Understand kevent event structure
  4. Source: ff_syscall_wrapper.c (implement mapping table)

Modification steps:
  - Add mapping table entry in ff_syscall_wrapper.c
  - Add conversion logic in ff_setsockopt()
  - Verify Linux and FreeBSD compatibility
  - Unit test
```

**Task 3: Performance Tuning (Throughput/Latency)**
```
Query path:
  1. Layer 1 §6 → Understand hardware acceleration support
  2. Layer 2 §3 → View configuration parameters
  3. Layer 2 §5.4 → Performance optimization recommendations
  4. Layer 3 §3.2 → Understand ff_dpdk_if optimizations

Tuning steps:
  - Enable TSO (tso=1)
  - Adjust socket buffer (sendspace=65536)
  - Select TCP stack/congestion control algorithm (bbr/rack/cubic)
  - Align RSS (symmetric_rss=1)
  - Performance testing and benchmarking
```

**Task 4: Multi-Process Deployment**
```
Query path:
  1. Layer 1 §4 → Understand multi-process architecture
  2. Layer 2 §4 → Learn multi-process interfaces
  3. Layer 2 §4.1 → Reference startup script
  4. Layer 2 §6 → View IPC tools

Deployment steps:
  - Write start.sh startup script
  - Configure lcore_mask (determine process count)
  - Compile application
  - Run primary process (proc_type=primary)
  - Run secondary processes (proc_type=secondary)
  - Use IPC tools for monitoring
```

---

## 5. Quick Reference Cards

### 5.1 API Quick Reference

```c
// Lifecycle
ff_init(argc, argv);                    // Initialize
ff_run(loop_func, arg);                 // Start polling
ff_stop_run();                          // Stop polling

// Socket Management
int fd = ff_socket(AF_INET, SOCK_STREAM, 0);
ff_bind(fd, &addr, sizeof(addr));
ff_listen(fd, 128);
int cfd = ff_accept(fd, NULL, NULL);
ff_connect(fd, &addr, sizeof(addr));
ff_close(fd);

// I/O Operations
ssize_t n = ff_read(fd, buf, sizeof(buf));
ssize_t n = ff_write(fd, data, len);      // Returns -1 if buffer full!
ssize_t n = ff_readv(fd, iov, iovcnt);    // Scatter read
ssize_t n = ff_writev(fd, iov, iovcnt);   // Gather write
ssize_t n = ff_send(fd, data, len, 0);
ssize_t n = ff_sendto(fd, data, len, 0, &addr, addrlen);  // UDP send to address
ssize_t n = ff_sendmsg(fd, &msg, 0);      // Send message (msghdr)
ssize_t n = ff_recv(fd, buf, sizeof(buf), 0);
ssize_t n = ff_recvfrom(fd, buf, sizeof(buf), 0, &addr, &addrlen);  // UDP receive
ssize_t n = ff_recvmsg(fd, &msg, 0);      // Receive message (msghdr)

// Event Multiplexing
int kq = ff_kqueue();
struct kevent kev;
EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
ff_kevent(kq, &kev, 1, NULL, 0, NULL);
int n = ff_kevent(kq, NULL, 0, events, 64, NULL);

// Epoll Compatible
int epfd = ff_epoll_create(0);
ff_epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
int n = ff_epoll_wait(epfd, events, 64, -1);

// Option Operations
ff_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
ff_getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, &len);
ff_ioctl(fd, FIONBIO, &on);              // ⚠️ Must set!

// Route Management
ff_route_ctl(ROUTE_CMD_ADD, "eth0", &dst, &gw, &mask);

// System Interfaces
ff_gettimeofday(&tv, NULL);
ff_log(FF_LOG_INFO, "message");
```

### 5.2 Kevent Event Quick Reference

```c
// Register read-ready event
struct kevent kev;
EV_SET(&kev, sockfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
ff_kevent(kq, &kev, 1, NULL, 0, NULL);

// Register write-ready event
EV_SET(&kev, sockfd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
ff_kevent(kq, &kev, 1, NULL, 0, NULL);

// One-shot trigger (auto-delete)
EV_SET(&kev, sockfd, EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0, NULL);

// Edge-triggered
EV_SET(&kev, sockfd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);

// Register timer
EV_SET(&kev, timer_id, EVFILT_TIMER, EV_ADD, 0, 1000, NULL);  // 1000 ms

// Listen for events
int nevents = ff_kevent(kq, NULL, 0, events, 64, NULL);  // Non-blocking
for (int i = 0; i < nevents; i++) {
    if (events[i].flags & EV_EOF) {
        // Connection closed
        ff_close((int)events[i].ident);
    } else if (events[i].filter == EVFILT_READ) {
        // Readable
        ff_read((int)events[i].ident, buf, sizeof(buf));
    }
}
```

### 5.3 Configuration Parameter Quick Reference

```ini
# config.ini key parameters

[dpdk]
lcore_mask = 0x0f           # Use cores 0-3
tso = 1                     # Enable TCP segmentation offload
symmetric_rss = 1           # RSS symmetry
pkt_tx_delay = 0            # Send immediately (no buffering)

[port0]
addr = 10.0.0.1
netmask = 255.255.255.0
gateway = 10.0.0.254

[freebsd.sysctl]
net.inet.tcp.sendspace = 65536     # Send buffer (bytes)
net.inet.tcp.recvspace = 65536     # Receive buffer
net.inet.tcp.functions_default=bbr    # BBR algorithm (high-latency networks), freebsd/rack/bbr
```

### 5.4 Common Error Quick Reference

| Symptom | Root Cause | Solution |
|---------|-----------|----------|
| Program blocks | Forgot to set FIONBIO | `ff_ioctl(fd, FIONBIO, &on);` |
| Packet loss | Main loop too long | Keep loop function < 100μs |
| Data loss | Write buffer full | Listen for EVFILT_WRITE + retry |
| Fd leak | Forgot to handle EV_EOF | Check `ev.flags & EV_EOF` |
| Crash | Cross-thread socket sharing | Isolate sockets per thread |
| Connection failure | Address format wrong | Use `struct linux_sockaddr` |
| Initialization failure | Insufficient hugepages | `sysctl vm.nr_hugepages=2048` |

---

## 6. Advanced Topics

### 6.1 Performance Tuning Checklist

```
□ CPU Isolation
  └─ Use taskset to bind processes to specific cores
  └─ Disable CPU frequency scaling: echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

□ Memory Optimization
  └─ Allocate hugepages: sysctl vm.nr_hugepages=2048
  └─ Disable swap: swapoff -a
  └─ Configure NUMA: numactl --membind=0 ./app

□ NIC Optimization
  └─ Enable symmetric_rss=1 (gateway)
  └─ Enable TSO: tso=1
  └─ Enable Checksum offload: tx_csum=1, rx_csum=1
  └─ Disable LRO (reduce latency): lro=0

□ F-Stack lib Optimization
  └─ Adjust send delay: pkt_tx_delay=100 (high throughput) / pkt_tx_delay=0 (low latency)
  └─ Enable RSS tbl: rss_check.enable=1 (reverse proxy)
  └─ Adjust CPU usage: idle_sleep=0 (cpu 100%, low latency, best performance) / idle_sleep=20 (reduce cpu usage)

□ Application Optimization
  └─ Adjust socket buffer: sendspace=65536
  └─ Adjust delayed ack: delayed_ack=1 (high throughput) / delayed_ack=0 (low latency)
  └─ Select TCP algorithm: functions_default=bbr (high latency) / functions_default=freebsd, cc.algorithm=cubic (low latency)
  └─ Enable SACK: sack.enable=1
  └─ Monitor performance: Use ff_log to output performance metrics
```

### 6.2 Troubleshooting Checklist

```
Issue 1: F-Stack application fails to start
  □ Check if hugepages are sufficient
  □ Check if NIC driver is bound (igb_uio or vfio-pci)
  □ Check if config.ini file exists and is properly formatted
  □ Check if cores in lcore_mask are available

Issue 2: Performance degradation or packet loss
  □ Check if main_loop is blocking (< 100μs?)
  □ Check if write buffer is full (returns -1?)
  □ Check if CPU is being preempted by other processes
  □ Monitor kqueue/epoll event readiness

Issue 3: Memory leak
  □ Check for missing ff_close()
  □ Check for missing ff_mbuf_free()
  □ Monitor memory usage trends (long-running)

Issue 4: Multi-process synchronization issues
  □ Check if RSS table is correctly initialized
  □ Check if IPC messages are correctly sent/received
  □ Use IPC tools (top/traffic) to monitor process status
```

### 6.3 Further Research Directions

```
1. FreeBSD TCP/IP Stack
   → Learn transport layer protocol state machines
   → Understand congestion control algorithms (CUBIC/BBR/RACK)
   → Study TCP timer mechanisms

2. DPDK Optimization
   → Learn RSS hash computation and flow classification
   → Understand NUMA-aware memory allocation
   → Study hardware offload (TSO/LRO/Checksum)

3. Performance Analysis
   → Use perf for performance sampling
   → Analyze CPU cache hit rates
   → Study causes of network packet loss

4. Application Integration
   → Learn the LD_PRELOAD mechanism (libff_syscall.so in adapter/syscall/, see adapter/syscall/README.md)
   → Study Nginx/Redis integration methods
   → Develop custom integration solutions
```

---

## 7. Reference Resources

### 7.1 Document List

| Document | Lines | Coverage |
|----------|-------|----------|
| Layer1_System_Overview | 8200 | Architecture, design decisions, hardware acceleration |
| Layer2_Interface_Specification | 9500 | API, configuration, development guidelines |
| Layer3_Function_Index | 10200 | Function index, data model, source code |
| **Total** | **27900** | **Complete three-layer architecture** |

### 7.2 Source Code Reading List

**Core Modules** (by priority):

```
Priority 1 (Must-read):
  └─ lib/ff_dpdk_if.c (2907 lines)    - NIC driver and main polling loop
  └─ lib/ff_glue.c (1467 lines)       - Kernel primitive emulation
  └─ lib/ff_init.c (69 lines)         - Initialization coordination

Priority 2 (Recommended):
  └─ lib/ff_syscall_wrapper.c (2265 lines) - Linux compatibility layer + FF_KERNEL_COEXIST routing (+ R9 kqueue coexist + IPV6_V6ONLY + R10 readv/writev/ioctl/dup/dup2 kernel-fd routing)
  └─ lib/ff_config.c (1694 lines)     - Configuration parsing
  └─ lib/ff_epoll.c (289 lines)       - Epoll compatibility (unified F-Stack + kernel; ff_epoll_host_ep shared with kqueue path)
  └─ lib/ff_host_interface.c (617 lines) - FF_KERNEL_COEXIST host-stack bridges (32 ff_host_*, optional)

Priority 3 (Deep dive):
  └─ example/main.c (222 lines)       - Kqueue application example
  └─ example/main_epoll.c (143 lines) - Epoll application example
  └─ app/nginx-1.28.0/src/event/modules/ngx_ff_module.c - Nginx integration
```

### 7.3 External References

```
DPDK Related:
  □ DPDK Official Documentation: https://doc.dpdk.org
  □ DPDK Code: /data/workspace/f-stack/dpdk (24.11.6 LTS)

FreeBSD Related:
  □ FreeBSD TCP/IP Source: /data/workspace/f-stack/freebsd/
  □ FreeBSD Documentation: https://www.freebsd.org/doc/

F-Stack Related:
  □ F-Stack Project: https://github.com/F-Stack/f-stack
  □ Official Documentation: /data/workspace/f-stack/doc, /data/workspace/f-stack/docs

Performance Optimization:
  □ TCP Congestion Control: RFC 5681 (CUBIC) / RFC 9002 (BBR)
  □ Hardware Offload: Intel NIC Whitepapers
```

---

## 8. Documentation Maintenance and Updates

### 8.1 Version Information

```
Knowledge base version: 1.5 (adds R10: ff_readv/ff_writev/ff_ioctl/ff_dup/ff_dup2 kernel-fd routing + select/poll documented limits, 2026-06-18; on top of 1.4 R9 ff_kqueue/ff_kevent coexistence + IPv6 IPV6_V6ONLY sync)
F-Stack version: v1.26 (branch feature/1.26)
FreeBSD port base: 15.0 (was 13.0 in v1.25)
DPDK version: 24.11.6 LTS (upgraded from 23.11.5 LTS on 2026-06-09)
Generation date: 2026-03-20 (last sync 2026-06-18)
Update cycle: Per F-Stack version updates (recommended every 6-12 months)
```

### 8.2 Known Limitations

```
1. Documentation is based on code analysis; some implementation details may have changed
2. Performance data is based on specific hardware (10GbE Intel NIC); different hardware may yield different results
3. Configuration parameters are recommended values; specific values should be tuned based on actual scenarios
4. Thread safety analysis is based on current code; subsequent versions may have changes
```

### 8.3 Feedback and Improvements

```
If you find documentation errors or have improvement suggestions, please submit to:
  GitHub Issue: https://github.com/F-Stack/f-stack/issues
  Or record in the CODEBUDDY.md file related to this documentation
```

---

## 9. Learning Roadmap

### Phase 1: Getting Started (1-2 weeks)

```
□ Read Layer1 §1-3 (understand architecture and innovation points)
□ Read Layer2 §5 (learn development guidelines)
□ Write your first HTTP server (reference example/main.c)
□ Successfully run and verify basic functionality
```

### Phase 2: Intermediate (2-4 weeks)

```
□ Deep-read Layer1 §4-6 (multi-process, technology selection, hardware acceleration)
□ Read Layer2 §2-3 (system call mapping, configuration system)
□ Read Layer3 §3 (source code analysis)
□ Implement a multi-process application
□ Performance testing and tuning
```

### Phase 3: Mastery (1-2 months)

```
□ Complete reading of all three layer documents
□ Deep-read ff_dpdk_if.c, ff_glue.c, ff_syscall_wrapper.c
□ Understand key parts of the FreeBSD protocol stack
□ Implement custom features or optimizations
□ Contribute code or documentation improvements
```

---

## 10. Summary

This knowledge base provides complete architecture documentation for F-Stack v1.26, consisting of three layers:

- **Layer 1** (8200 words): System overall architecture, suitable for understanding the big picture
- **Layer 2** (9500 words): Interface definitions and specifications, suitable for application development
- **Layer 3** (10200 words): Function-level index, suitable for deep research

**Total 27900 words**, covering:
- 80+ public exported functions
- 11+ core data structures
- 3 key source files
- Complete development guidelines and best practices
- Performance optimization and troubleshooting guides

**Purpose**:
- Pre-requisite architecture documentation for Spec-Driven Development
- Complete reference manual for application developers
- Decision support for system architects
- Optimization guide for performance analysts

**Recommendations**:
1. Write application code based on this knowledge base
2. Continuously supplement and improve through practice
3. Regularly update to track upstream F-Stack versions
4. Share practical experience and best practices

---

**Document Location**: `/data/workspace/f-stack/docs/`

```
F-Stack_Architecture_Layer1_System_Overview.md       (8.2 KB)
F-Stack_Architecture_Layer2_Interface_Specification.md (9.5 KB)
F-Stack_Architecture_Layer3_Function_Index.md         (10.2 KB)
F-Stack_Knowledge_Base_Summary.md                     (this file)
```

**Quick Start**:
1. Read this summary document first (5-10 minutes)
2. Select the appropriate layer document as needed
3. Practice alongside example/ code

Happy developing with F-Stack! 🚀
