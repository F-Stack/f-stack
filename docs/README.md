# F-Stack Complete Knowledge Base

## 📚 Documentation Overview

This directory contains the complete three-layer architecture knowledge base for F-Stack v1.26 (FreeBSD 15.0 port; upgraded from 13.0 in 2025-2026 — M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS) + DPDK 24.11.6 LTS (upgraded from 23.11.5 LTS on 2026-06-09 — see `freebsd_13_to_15_upgrade_spec/zh_cn/00-project-closure.md` and `dpdk_23_24_upgrade_spec/zh_cn/`), serving as pre-requisite architecture documentation for Spec-Driven Development.

### Document List

```
1. F-Stack_Knowledge_Base_Summary.md (751 lines)
   ├─ Overview document - Quick navigation and reference
   ├─ Contains navigation tables and quick reference cards for all documents
   └─ ⭐ Recommended to read first

2. F-Stack_Architecture_Layer1_System_Overview.md (825 lines)
   ├─ Layer 1: System Overall Architecture
   ├─ Module boundaries, technology selection, core design
   └─ Suitable for architects and system designers

3. F-Stack_Architecture_Layer2_Interface_Specification.md (1183 lines)
   ├─ Layer 2: Interface Definitions and Specifications
   ├─ API details, configuration system, development guidelines
   └─ Suitable for application developers and system integration engineers

4. F-Stack_Architecture_Layer3_Function_Index.md (1112 lines)
   ├─ Layer 3: Function-Level Index and Data Model
   ├─ 80+ function details, source code analysis, thread safety
   └─ Suitable for kernel developers and performance analysts

<!-- Note: This modification is based on 2/3 review consensus (GPT-5.4 + Claude) -->
Total: 3120 lines full version (+ 1436 lines simplified version) = **4556 lines** (including navigation + summary ~5839 lines)
```

## 🚀 Quick Start

### Scenario 1: I Want to Quickly Understand What F-Stack Is

```
Reading order:
  1. The "Core Concepts" section of this file (5 minutes)
  2. F-Stack_Knowledge_Base_Summary.md §2 (10 minutes)
  3. F-Stack_Architecture_Layer1_System_Overview.md §1 (15 minutes)
```

### Scenario 2: I Want to Develop an F-Stack Application

```
Reading order:
  1. F-Stack_Knowledge_Base_Summary.md §4 (15 minutes)
  2. F-Stack_Architecture_Layer2_Interface_Specification.md §5 (30 minutes)
  3. Reference /data/workspace/f-stack/example/main.c (10 minutes)
  4. Start coding!
```

### Scenario 3: I Want to Deeply Understand F-Stack Internals

```
Reading order:
  1. F-Stack_Architecture_Layer1_System_Overview.md (full read, 1 hour)
  2. F-Stack_Architecture_Layer2_Interface_Specification.md (full read, 1 hour)
  3. F-Stack_Architecture_Layer3_Function_Index.md (full read, 1.5 hours)
  4. Deep-dive into source code (verified against current HEAD):
     - lib/ff_dpdk_if.c (2907 lines)
     - lib/ff_glue.c (1467 lines)
     - lib/ff_syscall_wrapper.c (2265 lines)
     - lib/ff_ng_base.c (3887 lines, full netgraph port)
     - lib/ff_route.c (1604 lines, rtsock partial port)
     - lib/ff_stub_14_extra.c (799 lines, NEW: 14.0+ central stub bank)
     - lib/ff_host_interface.c (617 lines, 32 ff_host_*) / ff_epoll.c (289 lines) / ff_syscall_wrapper.c (2265 lines, NEW: FF_KERNEL_COEXIST coexistence + R9 kqueue/kevent coexistence + IPv6 IPV6_V6ONLY + R10 readv/writev/ioctl/dup/dup2 kernel-fd routing)
```

### Scenario 4: I Want to Look Up the Usage of a Specific API Function

```
How to:
  1. Check the API quick reference table in F-Stack_Knowledge_Base_Summary.md §5.1
  2. Or check the complete function list in F-Stack_Architecture_Layer3_Function_Index.md §1
  3. Or use grep to search for the function name in the layer2 or layer3 documents
```

### Scenario 5: I Want to Optimize Application Performance

```
Steps:
  1. F-Stack_Knowledge_Base_Summary.md §6.1 (Performance tuning checklist)
  2. F-Stack_Architecture_Layer1_System_Overview.md §6 (Hardware acceleration)
  3. F-Stack_Architecture_Layer2_Interface_Specification.md §5.4 (Optimization recommendations)
```

## 📖 Core Concepts Quick Reference

### Three Key Innovations of F-Stack

| Innovation | Description | Effect |
|-----------|-------------|--------|
| **Kernel Bypass** | Bypass Linux kernel network stack | Latency ↓ 10x (100μs → 10μs) |
| **FreeBSD Porting** | Reuse 20+ years of optimized protocol stack | Feature-complete, RFC-compliant |
| **Multi-Process Isolation** | One process per core + polling | Throughput ↑ 25x, lock-free design |

### Performance Benchmark

Actual data on 10GbE network:

| Metric | F-Stack | Linux Kernel | Improvement |
|--------|---------|-------------|-------------|
| Throughput (RPS) | 5M | 200K | **25x** |
| Latency P99 | 10μs | 100μs | **10x** |
| New connections | 1M CPS | 100K CPS | **10x** |
| Concurrent connections | 10M | 1M | **10x** |

> **Note**: The above performance data is for reference only. Actual results depend on hardware configuration (CPU model/core count, NIC model, memory), test scenarios, and packet sizes. Detailed test conditions to be supplemented.

### 80+ Public API Categories

```c
// Lifecycle (3)
ff_init / ff_run / ff_stop_run

// Socket (25+)
ff_socket / ff_bind / ff_listen / ff_accept / ff_connect / ff_close
ff_read / ff_write / ff_readv / ff_writev
ff_send / ff_sendto / ff_sendmsg
ff_recv / ff_recvfrom / ff_recvmsg / ...

// Event Multiplexing (5)
ff_kqueue / ff_kevent / ff_select / ff_poll
ff_epoll_create / ff_epoll_ctl / ff_epoll_wait

// Control Operations (10+)
ff_setsockopt / ff_getsockopt / ff_ioctl / ff_fcntl / ...

// Others (30+)
ff_route_ctl / ff_gettimeofday / ff_log / ...
```

## 📋 Document Structure Details

### Layer 1: System Overall Architecture (825 lines)

Coverage:
- ✓ System positioning and innovation (benefits of Kernel Bypass)
- ✓ Top-level module boundaries (10 core modules)
- ✓ Core architecture design (layering, data flow, polling loop)
- ✓ Multi-process architecture (Primary-Secondary, RSS)
- ✓ Technology selection analysis (why DPDK/FreeBSD)
- ✓ Performance features and hardware acceleration (TSO/LSO/Checksum)
- ✓ Ecosystem integration (Nginx/Redis)

**Target audience**: Architects, CTOs, system designers

**Reading time**: 60-90 minutes

### Layer 2: Interface Definitions and Specifications (1183 lines)

Coverage:
- ✓ 80+ exported function details (signatures, parameters, return values)
- ✓ 6 main header file analyses
- ✓ Linux ↔ FreeBSD system call mapping tables
- ✓ config.ini complete configuration system
- ✓ Multi-process and multi-thread interfaces
- ✓ Application development guidelines (3 modes, 7 pitfalls)
- ✓ 8 IPC tools and integration methods

**Target audience**: Application developers, system integration engineers

**Reading time**: 90-120 minutes

### Layer 3: Function-Level Index and Data Model (1112 lines)

Coverage:
- ✓ Complete function export list (signature, parameters, thread safety for each function)
- ✓ 11 core data structure details (kevent, config, sockaddr, etc.)
- ✓ 3 key source file deep analyses
  - ff_syscall_wrapper.c (Linux ↔ FreeBSD mapping)
  - ff_dpdk_if.c (NIC driver and main polling loop)
  - ff_glue.c (kernel primitive emulation)
- ✓ Thread safety analysis (Per-thread socket table)
- ✓ Compilation and linking guide

**Target audience**: Kernel developers, performance analysts, debug engineers

**Reading time**: 120-180 minutes

## 🎯 Usage Recommendations

### 1. First Contact with F-Stack

```
Recommended reading order (2-3 hours):
  1. The "Core Concepts" section of this README
  2. F-Stack_Knowledge_Base_Summary.md §1-3
  3. F-Stack_Architecture_Layer1_System_Overview.md §1-3
  4. F-Stack_Architecture_Layer2_Interface_Specification.md §5
  ↓
  Suggestion: Then read the code in /data/workspace/f-stack/example/main.c
```

### 2. Developing an F-Stack Application

```
Required reading:
  □ Layer2 §5 (Development guidelines) - Avoid common pitfalls
  □ Layer2 §2 (System call mapping) - Understand parameter conversion
  □ Layer3 §1 (Function list) - Look up function signatures
  
Supplementary reference:
  □ Layer1 §3 (Core architecture) - Understand design philosophy
  □ Layer1 §6 (Hardware acceleration) - Performance optimization
```

### 3. Performance Optimization and Debugging

```
Reference materials:
  □ Summary §5.2 (Kevent event quick reference)
  □ Summary §5.3 (Configuration parameter quick reference)
  □ Summary §5.4 (Common error quick reference)
  □ Layer1 §6 (Performance features)
  □ Layer3 §3.2 (ff_dpdk_if source code)
```

### 4. In-Depth Internal Implementation Research

```
Recommended path:
  1. Layer1 (full read, understand overall design)
  2. Layer3 §3 (key source file analysis)
  3. Deep-dive into source code (lib/ff_*.c)
  4. Understand FreeBSD protocol stack (freebsd/sys/netinet/)
```

## 📌 Quick Lookup Reference

### I Want to...

| Need | Where to Look |
|------|--------------|
| Understand F-Stack architecture | Summary §2 + Layer1 §1-3 |
| Look up function usage | Summary §5.1 + Layer3 §1 |
| Understand APIs | Layer2 §1 (API architecture) |
| Learn development | Layer2 §5 (Development guidelines) |
| Look up configuration parameters | Summary §5.3 + Layer2 §3 |
| Avoid common errors | Summary §5.4 + Layer2 §5.3 |
| Optimize performance | Summary §6.1 + Layer1 §6 |
| Understand multi-process | Layer1 §4 + Layer2 §4 |
| Look up data structures | Layer3 §2 (Data model) |
| Thread safety | Layer3 §4 (Thread safety analysis) |

## 🔧 Documentation Maintenance

### Version Information

```
Knowledge base version: 1.5 (adds R10: ff_readv/ff_writev/ff_ioctl/ff_dup/ff_dup2 kernel-fd routing + select/poll documented limits, 2026-06-18; on top of 1.4 R9 ff_kqueue/ff_kevent coexistence + IPv6 IPV6_V6ONLY + 1.3 FF_KERNEL_COEXIST kernel-stack coexistence + 1.2 FreeBSD 13.0 → 15.0 first-stage + Phase-2 M6-M13 + Phase-5b + F-A1 fix + vlan-vip-ipfw test)
F-Stack version: v1.26 (branch feature/1.26)
FreeBSD port base: 15.0 (was 13.0 in v1.25)
DPDK version: 24.11.6 LTS (upgraded from 23.11.5 LTS on 2026-06-09 via tree replace + 4 patches re-applied; see dpdk_23_24_upgrade_spec/zh_cn/)
New feature reflected: FF_KERNEL_COEXIST automatic dual-stack coexistence (default off; commits ba148589d → 55a84f313) + R9 kqueue/kevent coexistence + IPv6 IPV6_V6ONLY (kqueue-model kernel-side curl 127.0.0.1:80 = 200; -DINET6 v4+v6 same-port startup fixed) + R10 ff_readv/ff_writev/ff_ioctl/ff_dup/ff_dup2 kernel-fd routing (ff_ioctl uses raw Linux request; ff_dup2 cross-stack rejected EINVAL; select/poll are documented limits, use epoll/kqueue). See docs/kernel_event_support_spec/ (incl. plan-r9-kqueue-coexist-ipv6.md, plan-r10-readv-writev-ioctl-coexist.md).
Generation date: 2026-03-20 (last sync 2026-06-18)
Total lines: ~5839 lines (based on actual file count)
```

### Update Plan

- [ ] Track F-Stack new releases (recommended every 6-12 months)
- [ ] Supplement performance benchmark data
- [ ] Add more application integration examples (including complex scenario practical cases and troubleshooting guides)
- [ ] Collect user feedback and best practices

### Maintenance Rules

> The following maintenance rules were unanimously recommended by three independent model reviewers.

1. **Version sync**: When F-Stack version upgrades, check if integrated application versions in the `app/` directory (such as nginx, redis) have changed, and update directory path references in the documentation accordingly
2. **Statistics**: Statistics such as line counts and word counts in the documentation tend to become outdated. It is recommended to generate them automatically via scripts (e.g., `wc -l docs/*.md`) rather than maintaining them manually
3. **Code cross-validation**: Specific values in the documentation (line counts, constant values, struct fields) should be periodically cross-validated against the source code

## Important Notes

### Documentation Version Notes

1. **Full version vs. simplified version**: This knowledge base contains both full versions (`F-Stack_Architecture_Layer*.md`) and simplified versions (`01/02/03-LAYER*.md`). Full versions contain all details, while simplified versions are for quick reference. **When content differs between the two, the full version takes precedence.**

2. **Known content to be supplemented**:
   - Missing a centralized "Important Constraints and Risk Notes" section (single-thread/non-blocking constraints, application integration boundaries, etc.)
   - Complete test conditions for performance data to be supplemented

## 📚 Related Resources

### Source Code Locations

```
/data/workspace/f-stack/
├── lib/               # Core library (~21K lines)
├── freebsd/           # FreeBSD protocol stack port
├── dpdk/              # DPDK 24.11.6 LTS dependency (upgraded 2026-06-09)
├── adapter/           # Middleware adapters: micro_thread + syscall (builds libff_syscall.so for LD_PRELOAD)
├── example/           # Application examples (main.c recommended)
├── app/               # Nginx/Redis integration
├── tools/             # Operations tools
└── docs/              # ⬅️ This knowledge base (here)
```

### External References

```
Official Resources:
  - F-Stack project: https://github.com/F-Stack/f-stack
  - DPDK documentation: https://doc.dpdk.org
  - FreeBSD source: https://github.com/freebsd/freebsd-src

Technical Standards:
  - TCP/IP protocol: RFC 793/791/768
  - Hardware offload: Intel NIC whitepapers
  - Congestion control: RFC 5681 (CUBIC) / RFC 9002 (BBR)
```

## ❓ FAQ

### Q: What order should I read the documents in?

A: Choose based on your role:
- **Architect**: Layer1 full → Layer2 §1-2 (30-40 minutes)
- **Developer**: Layer2 §5 + Layer3 §1 (40-50 minutes)
- **Operations**: Summary §5 + Layer2 §3 (20-30 minutes)
- **Deep Research**: Layer1-3 full (4-5 hours)

### Q: How to read documentation alongside source code?

A: Recommended approach:
1. Read the corresponding documentation section first (theory)
2. Locate the relevant source code file
3. Read through the source code line by line with the documentation
4. Return to the documentation to verify understanding

### Q: How to quickly look up a parameter's description?

A: Three methods:
1. Use `grep` to search the documentation directory
2. Check Summary §5.3 (Configuration parameter quick reference table)
3. Check Layer2 §3 (Complete configuration system analysis)

### Q: When will the documentation be updated?

A: Plan:
- Track F-Stack major version updates (v1.26 → v1.27, etc.)
- Supplement new optimization techniques and best practices
- Collect user feedback and corrections
- For 13.0 → 15.0 first-stage upgrade traceability, see `freebsd_13_to_15_upgrade_spec/` (M0~M5, runtime-fix, Phase-5b, rib-fix, dual baselines, Phase-2 M6-M13, F-A1 fix, vlan-vip-ipfw test; project-level wrap-up: `freebsd_13_to_15_upgrade_spec/zh_cn/00-project-closure.md`)

## 📞 Feedback and Support

- Found a bug? Submit an Issue
- Have improvement suggestions? Pull Requests welcome
- Need additional content? Contact maintainers

---

**Quick start**: Read `F-Stack_Knowledge_Base_Summary.md` first, then select the appropriate layer document as needed.

**Key takeaway**: This knowledge base covers the complete F-Stack architecture, including 80+ APIs, 11 core data structures, 3 key source file analyses, as well as complete development guidelines and performance optimization guides.

Happy developing with F-Stack! 🚀
