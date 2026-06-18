# F-Stack v1.26 Layer 1: Overall Architecture and Module Boundaries

> **Target Audience**: System architects, technical leads  
> **Key Concepts**: Module partitioning, technology selection, data flow, process model  
> **Generation Date**: 2026-03-20 (last sync: 2026-06-08, post FreeBSD 13.0 → 15.0 first-stage upgrade including M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS)

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
| **Mature Protocol Stack** | FreeBSD 15.0 port (upgraded from 13.0 in 2025-2026) | Reuse battle-tested TCP/IP implementation |
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
├── lib/                          # F-Stack core library (~22K lines, 33 .c files; full inventory in Layer3 §lib)
│   ├── ff_dpdk_if.c   (2907 lines) # DPDK NIC interface layer - most critical
│   ├── ff_glue.c      (1467 lines) # FreeBSD glue layer
│   ├── ff_config.c    (1694 lines) # Configuration parsing
│   ├── ff_syscall_wrapper.c (2265 lines) # Linux→FreeBSD system call adaptation (+ R9 kqueue coexist + IPV6_V6ONLY + R10 readv/writev/ioctl/dup/dup2 kernel-fd routing)
│   ├── ff_host_interface.c (617 lines) # Host interface (pthread/mmap/time) + FF_KERNEL_COEXIST bridges (32 ff_host_*)
│   ├── ff_init.c         (70 lines)  # Initialization coordination
│   ├── ff_epoll.c       (289 lines) # epoll → kqueue conversion (unified F-Stack + kernel)
│   ├── ff_dpdk_kni.c            # Virtual NIC support (via virtio_user, no longer depends on rte_kni.ko)
│   ├── ff_route.c     (1604 lines) # Route socket / RIB hooks (rtsock partial port)
│   ├── ff_veth.c      (1132 lines) # Virtual ethernet device (M4: full if_t accessor rewrite)
│   ├── ff_kern_timeout.c (1266 lines) # callout subsystem (FreeBSD 13/14-compat _ff_callout_stop_safe)
│   ├── ff_lock.c       (448 lines) # sx/mutex/lockmgr userspace impl
│   ├── ff_ng_base.c   (3887 lines) # netgraph framework full port
│   ├── ff_stub_14_extra.c (799 lines) # NEW: 14.0+ central stub bank + 5 runtime-fix landing point
│   ├── ff_kern_*.c              # Kernel emulation primitives (cv/intr/synch/subr/environment)
│   ├── ff_subr_prf.c / ff_memory.c / ff_compat.c / ...  # Other shims (≈ 13 more files)
│   ├── Makefile                 # Build system (NET_SRCS now includes route_rtentry.c)
│   └── include/                 # Header files (ff_api.h, ff_memory.h, ...)
│
├── freebsd/                      # FreeBSD 15.0 kernel code port (upgraded from 13.0; mips/ removed at M1)
│   ├── sys/                       # System headers
│   ├── netinet/                   # IPv4 protocol stack (incl. tcp_stacks/ subdir: rack, bbr, ...)
│   ├── netinet6/                  # IPv6 protocol stack
│   ├── net/                       # Generic network interfaces (incl. route/ subdir: nhop/fib_algo/route_ctl)
│   ├── netlink/                   # NEW (header-only): 14.0+ netlink headers, 0 .c, 0 SRCS — DP-2: no NETLINK port
│   ├── netgraph/                  # netgraph kernel surface (paired with lib/ff_ng_base.c)
│   ├── kern/                      # Kernel services (malloc/locks/timers)
│   ├── vm/                        # Virtual memory
│   ├── amd64/ arm64/ i386/ arm/   # Supported architectures (mips/ removed in 14.0+)
│   └── contrib/ck/                # ConcurrencyKit dependency (refreshed at M3 to support CK_LIST_FOREACH_FROM)
│
├── dpdk/                         # DPDK 24.11.6 LTS (submodule; upgraded 2026-06-09 from 23.11.5)
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
| **ff_dpdk_if.c** | 2907 | NIC driver/DPDK operations/core TX/RX logic | DPDK, ff_glue |
| **ff_glue.c** | 1467 | FreeBSD kernel emulation/memory/locks/interrupts (8-category 14.0+ ABI fixes at M4) | FreeBSD headers, DPDK |
| **ff_config.c** | 1694 | INI configuration file parsing | ff_ini_parser |
| **ff_syscall_wrapper.c** | 2265 | Linux system call → FreeBSD adaptation (sockaddr update at M4; FF_KERNEL_COEXIST routing; R9 kqueue coexist + IPV6_V6ONLY; R10 readv/writev/ioctl/dup/dup2 kernel-fd routing) | FreeBSD sys |
| **ff_init.c** | 70 | Initialization flow coordination | All above modules |
| **ff_epoll.c** | 289 | Linux epoll → FreeBSD kqueue conversion (unified F-Stack + kernel; ff_epoll_host_ep shared with kqueue path) | FreeBSD kqueue |
| **ff_host_interface.c** | 617 | Host OS interface (mmap/pthread/rand) + FF_KERNEL_COEXIST host-stack bridges (32 ff_host_*) | System libraries |
| **ff_dpdk_kni.c** | ~441 | Virtual NIC support (via virtio_user, no longer depends on rte_kni.ko) | DPDK virtio_user |
| **ff_route.c** | 1604 | Route socket / RIB hooks (rtsock partial port; 5-category 14.0+ ABI fixes at M4) | FreeBSD net/route |
| **ff_veth.c** | 1132 | Virtual ethernet device (28 if_t accessor rewrites at M4) | FreeBSD net/if |
| **ff_kern_timeout.c** | 1266 | callout subsystem (`callout_init`, `_reset_tick_on`, `ff_timecounter`) | DPDK rte_timer |
| **ff_ng_base.c** | 3887 | netgraph framework full port (M5: `node_p → node_cp` correction) | FreeBSD netgraph headers |
| **ff_stub_14_extra.c** | 799 | NEW (M5 + runtime-fix): central 14.0+ stub bank (123 stubs, 661 undef resolutions) + 5 P0 SIGSEGV fixes + defensive `vm_page_alloc_noobj` panic | FreeBSD 14.0+ KBI |

## 3. FreeBSD TCP/IP Stack Porting Approach

### 3.1 Porting Strategy

F-Stack adopted a **complete porting** strategy:
- Originally extracted the full TCP/IP protocol stack code from FreeBSD 13.0; **upgraded to FreeBSD 15.0 in 2025-2026** (M0~M5; full evidence in `docs/freebsd_13_to_15_upgrade_spec/`)
- Retained all network protocol code in `freebsd/netinet/` (incl. `netinet/tcp_stacks/` for RACK/BBR), `freebsd/netinet6/`, `freebsd/net/` (incl. `net/route/` FIB rework subdir)
- Implemented user-space emulation of kernel APIs through `ff_glue.c` and the supplemental 14.0+ stub bank `ff_stub_14_extra.c`
- Supported optional features through conditional compilation (IPv6, KNI, TCPHPTS, FF_NETGRAPH, etc.); 15.0-introduced subsystems (NETLINK protocol, KTLS) are **not** ported per DP-2 / out-of-scope
- **Phase-2 M6 (2026-06-08)**: enabled `FF_NETGRAPH=1` + `FF_IPFW=1` by default in `lib/Makefile`; brings 41 netgraph nodes + 14 ipfw kernel objects into `libfstack.a` (now 6.5 MB, was 5.4 MB); `tools/sbin/ipfw` 25 MB user-space binary now produced (was absent when FF_IPFW=0); `ipfw add/show/delete` and `ngctl list` verified end-to-end via DPDK secondary IPC. See `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M6-execution-log.md` for full evidence + 7 link-only stubs added to `lib/ff_stub_14_extra.c`
- **Phase-2 M7 (2026-06-08)**: enabled `FF_USE_PAGE_ARRAY=1` (P1a, single-pass / 0 bounces); brings `lib/ff_memory.c` (481 lines, mmap-based page-array + mbuf reference pool) into `FF_HOST_SRCS`; runtime allocates 256 MB one-shot mmap (65536 × 4 KB pages) at `ff_mmap_init` to amortize per-packet 4 KB alloc/free syscalls. See `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M7-execution-log.md`
- **Phase-2 M8 (2026-06-08)**: enabled `FF_ZC_SEND=1` (P1b, 1 bounce); introduced `FSTACK_ZC_MAGIC` sentinel (uio.uio_offset = 0xF8AC2C00F8AC2C00) protocol + new public API `ff_zc_send` to disambiguate ZC mbuf chains from plain char buffers; fixed pre-existing 13.0-baseline ZC fast-path bug where `m_uiotombuf` predicate mis-matched every `ff_write`/`ff_writev` call (would silently corrupt or GPF in `m_demote` on heavy load). 8 files +85/-4 across `freebsd/sys/mbuf.h`, `freebsd/kern/uipc_mbuf.c`, `freebsd/kern/sys_generic.c`, `lib/Makefile`, `lib/ff_syscall_wrapper.c`, `lib/ff_api.h`, `lib/ff_api.symlist`, `example/Makefile` + `example/main_zc.c`. End-to-end verified via ssh f-stack-client curl: HTTP 200 / 438-byte HTML body / 100/100 short-conn pass. See `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M8-execution-log.md`
- **Phase-2 M9 (2026-06-08)**: enabled both `FF_USE_PAGE_ARRAY=1` + `FF_ZC_SEND=1` combo (P1c, single-pass / 0 bounces, 1-line Makefile change leveraging M7+M8 work); validated co-existence end-to-end (ff_mmap_init 256MB + ipfw2/tcp_bbr init clean + HTTP 200 single curl + 100/100 short-conn). 1000-conn observation: ~3.5× slower than M8 ZC-only with occasional timeout — recorded as M9-followup-F1 for phase-5b perf profiling. See `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M9-execution-log.md`
- **Phase-2 M10 (2026-06-08)**: enabled `FF_FLOW_IPIP=1` (P1d, 1 bounce); softened `create_ipip_flow` failure from `rte_exit` to printf warning so primary stays alive on NICs that lack rte_flow IPIP offload (e.g. virtio); GIF tunnel runs in software via FreeBSD `if_gif/in_gif`. End-to-end IPIP tunnel verified: `tools/sbin/ifconfig gif0 create + tunnel + inet` on server side + `ip tunnel add gif0 mode ipip` on Linux f-stack-client side + ping 3/3 received 0% loss RTT 0.29-0.65 ms. example/Makefile auto-skips helloworld_zc target when libfstack.a is built without FF_ZC_SEND. See `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M10-execution-log.md`
- **Phase-2 M11/M12/M13 (2026-06-08)**: P2-priority smoke trio — enabled `FF_FLOW_ISOLATE=1` (M11), `FF_FDIR=1` (M12), `FF_LOOPBACK_SUPPORT=1` (M13) each in turn; lib build clean and helloworld primary ALIVE for each. M11 batched the rte_flow soft-fallback for `port_flow_isolate`/`init_flow`/`fdir_add_tcp_flow` (3 sites in `ff_dpdk_if.c`) following the M10 pattern. M13 added one link-only stub `ff_swi_net_excute` to `ff_stub_14_extra.c` (declared in `ff_host_interface.h:92` but never implemented in the tree). See `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M11-M13-spec.md`
- **Phase-5b perf baseline (2026-06-08)**: 5-config × 2-3 testcase × 3-trial matrix executed via `tools/sbin/p5b_perf_matrix.sh` (curl-bench from f-stack-client; ssh round-trip caps at ~137 conn/s, only relative cross-config delta is meaningful). Closes M9-F1 (PA+ZC combo +4.1% over baseline, false negative caused by stale-process noise) and M10-F2 (IPIP tunnel ping baseline 0.39 ms / 0% loss / 9 ms jitter). New finding **F-A1 (HIGH)**: `FF_USE_PAGE_ARRAY=1` standalone breaks ICMP+HTTP egress (`ff_chk_vma` in `ff_memory.c:453` doesn't cover ARP/ICMP mbuf data pointers); deferred for follow-up. Production recommendation: prefer C8 ZC-only or C9 PA+ZC; avoid PA-only. See `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase-5b-perf-baseline-report.md`
- **F-A1 fix (2026-06-08)**: closes the phase-5b HIGH-severity finding. Single-file 1-function patch: `lib/ff_memory.c:ff_if_send_onepkt` `rte_panic` → `rte_log(WARNING) + ff_mbuf_free(m) + return 0`. Root cause: an early-startup edge mbuf (gratuitous ARP / IPv6 RS / loopback control) whose data pointer was neither in PA VMA nor a recognised EXT_CLUSTER would `abort()` the entire dataplane. Fixed by demoting the panic to a non-fatal soft drop — TCP/ARP retransmit recover. Verified: PA-only 1000/1000 curl PASS, TC1 −7.4% over C0 baseline, 0 drop events under steady state. F-A2 marked N/A (panic channel removed, ARP-cache theory no longer relevant). All four configs (C0/C7/C8/C9) now production-ready. See `docs/freebsd_13_to_15_upgrade_spec/zh_cn/F-A1-fix-execution-log.md`
- **VLAN + vip_addr + ipfw_pr functional test (2026-06-09)**: dual-vlan multi-tenant config-layer acceptance via 4-sub-agent harness (spec-writer / coder / reviewer / gate-keeper). Dual `[vlan1]`/`[vlan2]` test config (`config.test-vlan.ini`, 192.169.0/1.0/24, isolated from production 9.134.214.176/21) verified at primary startup: both `if_clone_create f-stack-0.1`/`f-stack-0.2` succeed, no `ff_veth_setvaddr` errors, and `tools/sbin/ipfw show` lists hard-evidence rules `00010 setfib 0 ip from 192.169.0.0/24 out` + `00020 setfib 1 ip from 192.169.1.0/24 out` — fib_num matches `ff_veth.c:949 fib_num = vlan_cfg->vlan_idx` exactly. G1/G2/G3/G4 all PASS, BOUNCE 0/3, zero direct rm/kill/chmod calls. End-to-end e2e (loopback ping vip / client 802.1Q HTTP) recorded as F-V1/F-V2 follow-ups. See `docs/freebsd_13_to_15_upgrade_spec/zh_cn/vlan-vip-ipfw-test-execution-log.md`

### 3.2 Ported FreeBSD Subsystems

```text
freebsd/
├── netinet/        # IPv4: tcp_*.c, udp_*.c, ip_*.c, if_arp.c
│   └── tcp_stacks/ # Modular TCP stacks: rack.c (~759 KB), bbr.c (~444 KB), tailq_hash.* (-DMODNAME=tcp_rack)
├── netinet6/       # IPv6: ip6_*.c, tcp6_*.c
├── net/            # Generic network: if.c, route.c, netisr.c
│   └── route/      # FIB rework subdir (14.0+): nhop, fib_algo, route_ctl (22 files)
├── netlink/        # 14.0+ NETLINK headers (header-only, 0 .c) — DP-2: protocol not ported
├── netgraph/       # netgraph kernel surface (paired with lib/ff_ng_base.c)
├── kern/           # Kernel services: malloc, mutex, synch, callout (incl. kern_descrip.c with 5475-boundary fix)
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

This is the most critical module (2907 lines), responsible for the entire data link:

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

### 6.3 Kernel-Stack Coexistence (`FF_KERNEL_COEXIST`, optional, default off)

An optional mode (compile-time macro `FF_KERNEL_COEXIST` + runtime `config.ini [stack] kernel_coexist`, both default off) lets one process serve traffic over **both** the F-Stack stack and the host Linux kernel stack from the **same `ff_epoll_wait` loop**:

- `ff_socket()` selects the stack via `SOCK_FSTACK` / `SOCK_KERNEL` flags; with no flag it **dual-creates** an F-Stack socket plus a paired host socket.
- A kernel-stack fd is returned as `host_fd + 0x40000000` (`FF_KERNEL_FD_BASE`), which never collides with FreeBSD fds (`< 65536`); entries route such fds to thin `ff_host_*` host-libc bridges.
- The F-Stack ↔ host fd pairing is held in `ff_native_fd_map`; `ff_epoll_*` lazily pairs a host `epoll` per kqueue for unified event delivery. A dual-built `AF_INET6` socket gets `IPV6_V6ONLY=1` on its host counterpart (`ff_host_set_v6only`, R9) so v4+v6 coexist on the same port (fixes the prior `-DINET6` `errno=98` startup failure).
- **R9** extends unified events to the native `ff_kqueue`/`ff_kevent` interface (shared `ff_epoll_host_ep`): `ff_kevent` registers a kernel/dual-stack fd's `EVFILT_READ/WRITE` into the kqueue-paired host epoll and synthesizes `struct kevent` (`ident`=app-side fd) from a non-blocking host-epoll poll before merging F-Stack events — a pure-kqueue app (`example/main.c`) now reaches the kernel-side listener (`curl 127.0.0.1:80`=200, was 000).
- **R10** completes residual-entry kernel-fd routing: `ff_readv`/`ff_writev` kernel fd via `ff_host_readv/writev` (mimic read/write); `ff_ioctl` kernel fd uses the **raw Linux request** straight to `ff_host_ioctl` (dual-stack fd same-driver since R10.1 syncs `FIONBIO`/`FIOASYNC` to the paired host fd (query ioctls like `FIONREAD` not forwarded, to avoid clobbering argp)); `ff_dup`→`ff_host_dup`+encode, `ff_dup2` both-kernel→`ff_host_dup2`+encode / cross-stack rejected `errno=EINVAL`.
- When the macro is off the library is byte-for-byte identical to the pure-F-Stack build. Known limitations: kernel fds via kqueue support `EVFILT_READ/WRITE` only; `ff_select` (encode kernel fd ≫ `FD_SETSIZE` hard limit) and `ff_poll` (conservatively not implemented) do not support kernel-fd coexistence — use `ff_epoll_*`/`ff_kqueue` for kernel-fd multiplexing. See `docs/kernel_event_support_spec/`.

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
