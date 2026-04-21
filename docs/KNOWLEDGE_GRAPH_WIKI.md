# F-Stack Knowledge Graph Wiki

> This document was auto-extracted from the GitNexus knowledge graph + AI generated. Index time: 2026-04-09, commit: a695757.

---

## 1. Project Overview

| Metric | Data |
|--------|------|
| Indexed files | 25,723 |
| Symbol nodes | 710,596 |
| Relation edges | 1,270,994 |
| Function clusters | 11,375 (communities) |
| Execution flows | 300 (processes) |
| Excluded directories | `freebsd/`, `dpdk/` (excluded from indexing only, reference relationships preserved) |

### Node Type Distribution

| Type | Count | Description |
|------|-------|-------------|
| Macro | 311,802 | C preprocessor macro definitions |
| Function | 159,305 | Function definitions |
| Property | 103,447 | Struct fields/properties |
| Struct | 74,359 | Struct definitions |
| File | 25,723 | Source files |
| Community | 11,375 | Function clusters |
| Typedef | 10,634 | Type aliases |
| Enum | 5,759 | Enumeration types |
| Union | 3,458 | Union types |
| Folder | 1,880 | Directories |
| Method | 1,268 | Methods (C++ / ObjC) |
| Section | 1,010 | Document sections |
| Process | 300 | Execution flows |
| Class | 255 | Classes (C++ portion) |
| Namespace | 19 | Namespaces |

---

## 2. Core Function Clusters (Top Communities)

Clusters are automatically identified by the GitNexus community detection algorithm. Higher `cohesion` indicates tighter internal coupling within the cluster.

### 2.1 Network Protocol Stack Core

| Cluster | Symbol Count | Cohesion | Description |
|---------|-------------|----------|-------------|
| **Net** | 823 | 0.921 | Network subsystem core (TCP/IP protocol stack) |
| **Netinet** | 245 | 0.900 | Internet protocol family (IPv4/IPv6/TCP/UDP) |
| **Tcp_stacks** | 91 | 0.771 | TCP protocol stack implementation |
| **Netstat** | 158 | 0.947 | Network statistics tool |

### 2.2 Kernel Infrastructure

| Cluster | Symbol Count | Cohesion | Description |
|---------|-------------|----------|-------------|
| **Sys** | 932 | 0.903 | System calls and kernel base interfaces |
| **Kern** (comm_307) | 212 | 0.926 | Kernel core functionality |
| **Kern** (comm_89) | 213 | 0.256 | Kernel extensions (low cohesion, many cross-module dependencies) |
| **Kern** (comm_294) | 137 | 0.692 | Kernel auxiliary modules |
| **Vm** | 101 | 0.679 | Virtual memory management |
| **Amd64** | 188 | 0.490 | x86-64 architecture-specific code |
| **Arm** | 149 | 0.973 | ARM architecture support |

### 2.3 DPDK Related

| Cluster | Symbol Count | Cohesion | Description |
|---------|-------------|----------|-------------|
| **Ethdev** | 148 | 0.759 | DPDK Ethernet device abstraction layer |
| **Kvargs** | 115 | 0.813 | DPDK Key-Value argument parsing |
| **Cnxk** | 686 | 0.721 | Marvell CNXK NIC driver |
| **Mlx5** (comm_5663) | 146 | 0.689 | Mellanox ConnectX-5 driver |
| **Mlx5** (comm_6413) | 110 | 0.443 | Mlx5 extended features |
| **Sfc** | 224 | 0.836 | Solarflare NIC driver |
| **I40e** | 108 | 0.556 | Intel XL710 NIC driver |
| **Bnx2x** | 148 | 0.947 | Broadcom NetXtreme II driver |
| **Qede** | 86 | 0.889 | QLogic NIC driver |
| **Nvidia** | 128 | 0.613 | NVIDIA NIC support |

### 2.4 File Systems

| Cluster | Symbol Count | Cohesion | Description |
|---------|-------------|----------|-------------|
| **Zfs** (comm_9633) | 1,015 | 0.812 | ZFS file system core |
| **Zfs** (comm_9624) | 819 | 0.762 | ZFS data management layer |
| **Libzfs** | 256 | 0.728 | ZFS user-space library |
| **Libzfs_input_check** | 142 | 0.673 | ZFS input validation |

### 2.5 Applications and Tools

| Cluster | Symbol Count | Cohesion | Description |
|---------|-------------|----------|-------------|
| **Test** (multiple) | 282–84 | 0.38–0.90 | Test code for various modules |
| **Vhost** | 275 | 0.805 | Virtio/Vhost user-space network device |
| **Hiredis** | 85 | 0.726 | Redis C client library |
| **Lua** | 125 | 0.787 | Lua scripting engine integration |
| **Debugger** | 194 | 0.686 | Kernel debugger (DDB) |
| **Modules** | 131 | 0.926 | Kernel loadable module framework |

---

## 3. High-Frequency Functions (Call Hotspots)

The following are the Top 50 most-called functions, reflecting the core dependency relationships in the codebase:

### 3.1 Memory Management (Highest Frequency)

| Function | In-Degree | Source |
|----------|-----------|--------|
| `rte_free()` | 1,166 | DPDK memory deallocation |
| `rte_zmalloc()` | 477 | DPDK zero-initialized memory allocation |
| `rte_zmalloc_socket()` | 286 | DPDK NUMA-aware memory allocation |
| `rte_malloc()` | 180 | DPDK general memory allocation |
| `mlx5_free()` | 171 | Mlx5 driver memory deallocation |
| `rte_pktmbuf_free()` | 459 | DPDK packet mbuf deallocation |
| `rte_pktmbuf_alloc()` | 152 | DPDK mbuf allocation |
| `rte_pktmbuf_free_seg()` | 149 | DPDK mbuf segment deallocation |
| `rte_mempool_put()` | 152 | DPDK memory pool return |
| `m_freem()` | 517 | FreeBSD mbuf chain deallocation |
| `m_pullup()` | 157 | FreeBSD mbuf data alignment |
| `m_adj()` | 142 | FreeBSD mbuf length adjustment |

### 3.2 Devices and Drivers

| Function | In-Degree | Source |
|----------|-----------|--------|
| `device_get_softc()` | 1,809 | FreeBSD driver get private data (**global #1**) |
| `device_printf()` | 1,122 | Device log printing |
| `device_set_desc()` | 412 | Device description setting |
| `device_get_nameunit()` | 153 | Get device name |
| `device_get_parent()` | 148 | Get parent device |
| `bus_alloc_resource_any()` | 181 | Bus resource allocation |
| `bus_release_resource()` | 179 | Bus resource release |
| `bus_setup_intr()` | 145 | Interrupt registration |

### 3.3 Synchronization Primitives

| Function | In-Degree | Source |
|----------|-----------|--------|
| `mutex_enter()` / `mutex_exit()` | 585 / 589 | ZFS mutexes |
| `pthread_mutex_lock()` / `unlock()` | 257 / 256 | POSIX mutexes |
| `rte_spinlock_lock()` / `unlock()` | 190 / 198 | DPDK spinlocks |

### 3.4 Error Handling and Logging

| Function | In-Degree | Source |
|----------|-----------|--------|
| `panic()` | 1,071 | Kernel panic |
| `rte_exit()` | 236 | DPDK fatal exit |
| `AcpiOsPrintf()` | 312 | ACPI logging |
| `db_printf()` | 271 | Kernel debugger output |
| `rte_flow_error_set()` | 345 | DPDK flow rule error setting |
| `ngx_conf_log_error()` | 201 | Nginx configuration error logging |

### 3.5 Network Data Operations

| Function | In-Degree | Source |
|----------|-----------|--------|
| `rte_ether_addr_copy()` | 167 | MAC address copy |
| `mc_send_command()` | 213 | FSLMC bus command send |
| `mc_encode_cmd_header()` | 213 | FSLMC command header encoding |
| `mbox_get()` / `mbox_put()` | 210 / 210 | CNXK mailbox communication |
| `roc_nix_to_nix_priv()` | 228 | CNXK NIX private data conversion |
| `cnxk_eth_pmd_priv()` | 187 | CNXK Ethernet PMD private data |

---

## 4. Key Execution Flows (Processes)

Execution flows are cross-function call chains automatically detected by GitNexus. `cross_community` indicates cross-cluster calls, `intra_community` indicates intra-cluster calls.

### 4.1 Data Plane Critical Paths

| Execution Flow | Steps | Type | Description |
|---------------|-------|------|-------------|
| Main → Rte_vlog | 5-6 | cross | Application main loop → DPDK log output |
| Cmd_send_parsed → Rte_mempool_get_ops | 9 | cross | **Longest execution flow**: command parsing → memory pool operation retrieval |
| Cmd_send_parsed → Rte_mempool_default_cache | 6 | cross | Command parsing → memory pool cache |
| T4_eth_xmit → RTE_MBUF_DIRECT | 5 | cross | Chelsio T4 NIC transmit → mbuf check |
| T4_sge_alloc_rxq → RTE_MEMPOOL_HEADER_SIZE | 5 | cross | T4 receive queue allocation → memory pool header size calculation |
| Run_regex → RTE_MBUF_* | 5-6 | cross | Regex matching engine → mbuf operation family |
| Ice_init_hw → Ice_msec_delay | 5 | cross | Intel ICE NIC initialization → delay wait |

### 4.2 Storage Paths

| Execution Flow | Steps | Type | Description |
|---------------|-------|------|-------------|
| Dsl_dataset_promote_sync → multiple targets | 5-6 | mixed | ZFS dataset promotion (snapshot → clone) |
| Dsl_scan_sync → Kmem_free | 5 | cross | ZFS scan sync → memory deallocation |
| Zfs_create → KUID_TO_SUID | 5 | cross | ZFS create → UID conversion |
| Zfs_acl_ids_create → Zfs_acl_valid_ace_type | 5 | cross | ZFS ACL create → ACE type validation |

### 4.3 Architecture-Specific Paths

| Execution Flow | Steps | Type | Description |
|---------------|-------|------|-------------|
| Pmap_enter → Pt2tab_index | 7 | cross | ARM page table mapping (second longest execution flow) |
| X86emu_exec_one_byte → Longjmp | 6 | cross | x86 emulator → long jump |
| Cvmx_helper_shutdown → CVMX_ADD_IO_SEG | 6 | cross | MIPS Cavium network shutdown → IO segment operation |

### 4.4 Application Layer Paths

| Execution Flow | Steps | Type | Description |
|---------------|-------|------|-------------|
| ClientCommand → ClientInstallWriteHandler | 5 | cross | Redis client command → write handler |
| ClientCommand → ServerAssert | 5 | cross | Redis command → server assertion |
| ZiplistTest → ZIPLIST_BYTES | 5 | intra | Redis ziplist test → byte operations |

---

## 5. Directory Structure

```
f-stack/
├── lib/            # F-Stack core library (ff_api, ff_dpdk_if, ff_config, etc.)
├── adapter/        # LD_PRELOAD adaptation layer (syscall hook, socket ops)
├── app/            # Applications (F-Stack-modified Nginx, Redis, etc.)
├── example/        # Example programs (helloworld, kqueue usage, etc.)
├── tools/          # Tools (user-space ports of ifconfig, netstat, arp, route, etc.)
├── mk/             # Build system (Makefile include files)
├── doc/            # Original documentation
├── docs/           # Architecture documentation and LD_PRELOAD Ring IPC Spec docs
├── dpdk/           # DPDK 23.11.5 submodule (excluded from indexing)
└── freebsd/        # FreeBSD 13.1 kernel source (excluded from indexing)
```

### 5.1 Core Library Files (`lib/`)

| File | Responsibility |
|------|---------------|
| `ff_api.h` / `ff_api.c` | F-Stack public API (Socket, KQueue, Route, Log, etc.) |
| `ff_dpdk_if.h` / `ff_dpdk_if.c` | DPDK interface layer (packet TX/RX, main_loop, device initialization) |
| `ff_config.h` / `ff_config.c` | Configuration parsing (INI format) |
| `ff_host_interface.h` / `ff_host_interface.c` | Host interface abstraction |
| `ff_veth.h` / `ff_veth.c` | Virtual Ethernet device |
| `ff_msg.h` / `ff_msg.c` | F-Stack inter-process messaging |
| `ff_log.h` | Logging API (ff_log, ff_vlog, ff_log_reset_stream) |
| `ff_epoll.h` / `ff_epoll.c` | Epoll compatibility layer |
| `ff_errno.h` | Error code mapping |

### 5.2 Adapter Layer (`adapter/`)

| File | Responsibility |
|------|---------------|
| `syscall/ff_hook_syscall.c` | LD_PRELOAD system call interception (3254 lines) |
| `syscall/ff_socket_ops.h` / `.c` | Socket operation context and handling |
| `syscall/ff_so_zone.c` | Shared memory zone management |
| `syscall/ff_epoll.c` | Epoll adaptation |

---

## 6. Dependency Overview

```
                    ┌──────────────┐
                    │  Applications │
                    │ (Nginx/Redis) │
                    └──────┬───────┘
                           │ ff_* API
                    ┌──────▼───────┐
                    │   lib/       │
                    │  F-Stack Core │
                    └──┬───────┬───┘
                       │       │
              ┌────────▼──┐ ┌──▼────────┐
              │  FreeBSD   │ │   DPDK     │
              │  TCP/IP    │ │  23.11.5   │
              │  Stack     │ │ (PMD/EAL)  │
              └────────────┘ └────────────┘

  adapter/                    tools/
  LD_PRELOAD Hook ──────►  ifconfig/netstat
  (syscall redirect)       (user-space network tools)
```

### Relation Types

All relationships in the knowledge graph are of `CodeRelation` type (1,270,994 total), covering:
- Function calls (CALL)
- Type references (USES_TYPE)
- Macro expansions (EXPANDS)
- File includes (INCLUDES)
- Struct member access (HAS_MEMBER)
- Community membership (BELONGS_TO)

---

## 7. Knowledge Graph Usage Guide

### Query Tools

| Tool | Purpose | Example |
|------|---------|---------|
| `gitnexus_query` | Search execution flows by concept | "packet receive" |
| `gitnexus_context` | View 360° relationships of a symbol | All callers/callees of "ff_init" |
| `gitnexus_impact` | Pre-modification impact analysis | Impact radius of changing ff_dpdk_if.c |
| `gitnexus_detect_changes` | Pre-commit change scope check | Verify impact of staged files |
| `gitnexus_rename` | Safe renaming | Batch rename across multiple files |
| `gitnexus_cypher` | Custom graph queries | Advanced analysis |

### Updating the Index

```bash
# Environment variables (required for TencentOS 4.4)
export LD_LIBRARY_PATH="/opt/OpenCloudOS/gcc-toolset-14/root/usr/lib64:$LD_LIBRARY_PATH"
export PATH="/root/.workbuddy/binaries/node/versions/20.18.0/bin:$PATH"

# Check status
cd /data/workspace/f-stack && npx gitnexus@1.5.3 status

# Re-index
npx gitnexus@1.5.3 analyze

# Force full rebuild
npx gitnexus@1.5.3 analyze --force
```

> **Auto-update**: A Git `post-commit` hook has been configured to automatically re-index in the background after each commit.

---

*Generated from GitNexus knowledge graph (710,596 nodes, 1,270,994 edges) — 2026-04-09*
