# F-Stack v1.26 第一层：总体架构与模块边界

> **目标受众**: 系统架构师、技术负责人  
> **关键概念**: 模块划分、技术选型、数据流、进程模型  
> **生成日期**: 2026-03-20（最近一次同步：2026-06-08，FreeBSD 13.0 → 15.0 第一阶段升级完成后：含 M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS）

## 1. 顶层架构概览

### 1.1 F-Stack 核心创新

F-Stack 采用了"用户态网络栈"架构，解决 Linux 内核网络处理的性能瓶颈：

```text
应用层 (Applications)
  ↓ (ff_socket/ff_read/ff_write 等 Linux-like API)
F-Stack 库 (libfstack.a)
  ├─ FreeBSD TCP/IP 栈移植
  ├─ 粘合层 (ff_glue.c) - 内核模拟
  └─ 系统调用适配 (ff_syscall_wrapper.c)
  ↓
DPDK 库 (libdpdk)
  ├─ EAL (Environment Abstraction Layer)
  ├─ Mempool (mbuf 内存池)
  └─ Ethdev (网卡驱动无关接口)
  ↓
NIC 驱动 (igb_uio / vfio-pci)
  ↓
网卡硬件
```

### 1.2 三个核心支柱

| 支柱 | 组件 | 作用 |
|-----|------|------|
| **Kernel Bypass** | DPDK + PMD | 规避 Linux 内核网络瓶颈 |
| **成熟协议栈** | FreeBSD 15.0 移植（2025-2026 自 13.0 升级而来） | 复用久经考验的 TCP/IP 实现 |
| **多核并行** | 多进程架构 + RSS | 充分利用多核处理能力 |

### 1.3 关键性能指标

- **并发连接**: 1000 万+
- **请求吞吐**: 500 万+ RPS (Request Per Second)
- **连接建立**: 100 万+ CPS (Connection Per Second)
- **延迟**: 微秒级 (vs 毫秒级内核栈)

> **注意**: 以上性能数据为参考值，实际结果取决于硬件配置 (CPU/网卡)、测试场景和报文大小等条件。

## 2. 目录结构与模块边界

### 2.1 核心目录布局

```text
/data/workspace/f-stack/
├── lib/                          # F-Stack 核心库（~22K 行 C 代码，33 个 .c 文件；完整清单见 Layer3 §lib）
│   ├── ff_dpdk_if.c   (2907行) # DPDK 网卡接口层 - 最核心
│   ├── ff_glue.c      (1467行) # FreeBSD 粘合层
│   ├── ff_config.c    (1694行) # 配置解析
│   ├── ff_syscall_wrapper.c (2265行) # Linux→FreeBSD 系统调用适配（+ R9 kqueue 共存 + IPV6_V6ONLY + R10 readv/writev/ioctl/dup/dup2 内核 fd 路由）
│   ├── ff_host_interface.c (617行) # 主机接口（pthread/mmap/时间）+ FF_KERNEL_COEXIST 桥（32 个 ff_host_*）
│   ├── ff_init.c         (70行) # 初始化协调
│   ├── ff_epoll.c       (289行) # epoll → kqueue 转换（F-Stack + 内核统一）
│   ├── ff_dpdk_kni.c            # 虚拟网卡支持（通过 virtio_user 实现，已不依赖 rte_kni.ko）
│   ├── ff_route.c     (1604行) # 路由套接字 / RIB 钩子（rtsock 部分移植）
│   ├── ff_veth.c      (1132行) # 虚拟以太网设备（M4 完成 if_t accessor 全量重写）
│   ├── ff_kern_timeout.c (1266行) # callout 子系统（FreeBSD 13/14 兼容 _ff_callout_stop_safe）
│   ├── ff_lock.c       (448行) # sx/mutex/lockmgr 用户态实现
│   ├── ff_ng_base.c   (3887行) # netgraph 框架完整移植
│   ├── ff_stub_14_extra.c (799行) # 新增：14.0+ 中央 stub 库 + 5 个 runtime-fix 落点
│   ├── ff_kern_*.c              # 内核仿真原语（cv/intr/synch/subr/environment）
│   ├── ff_subr_prf.c / ff_memory.c / ff_compat.c / ...  # 其它 shim（约 13 个文件）
│   ├── Makefile                 # 编译系统（NET_SRCS 现含 route_rtentry.c）
│   └── include/                 # 头文件（ff_api.h、ff_memory.h 等）
│
├── freebsd/                      # FreeBSD 15.0 内核代码移植（M1 已自 13.0 升级；mips/ 已删）
│   ├── sys/                       # 系统头文件
│   ├── netinet/                   # IPv4 协议栈（含 tcp_stacks/ 子目录：rack、bbr 等）
│   ├── netinet6/                  # IPv6 协议栈
│   ├── net/                       # 通用网络接口（含 route/ 子目录：nhop/fib_algo/route_ctl）
│   ├── netlink/                   # 新增（仅头文件）：14.0+ netlink 头，0 个 .c，0 个 SRCS —— DP-2：不引入 NETLINK 协议
│   ├── netgraph/                  # netgraph 内核侧（与 lib/ff_ng_base.c 配对）
│   ├── kern/                      # 内核服务（malloc/锁/定时器）
│   ├── vm/                        # 虚拟内存
│   ├── amd64/ arm64/ i386/ arm/   # 受支持架构（mips/ 已在 14.0+ 移除）
│   └── contrib/ck/                # ConcurrencyKit 依赖（M3 已升级以支持 CK_LIST_FOREACH_FROM）
│
├── dpdk/                         # DPDK 24.11.6 LTS (submodule; 2026-06-09 自 23.11.5 升级)
│   └── build/                    # 编译产物
│
├── app/                          # 应用集成
│   ├── nginx-1.28.0/
│   └── redis-6.2.6/
│
├── example/                      # 示例代码
│   ├── main.c          (222行) # kqueue HTTP 服务器
│   └── main_epoll.c    (143行) # epoll HTTP 服务器
│
├── mk/                           # 编译系统
│   ├── kern.pre.mk     # FreeBSD 编译规则
│   ├── kern.mk         # 内核编译规则
│   └── compiler.mk     # 编译器配置
│
├── tools/                        # 工具脚本
├── adapter/                      # 网络适配器
│   ├── micro_thread/             # 微线程接口，方便有状态应用使用 F-Stack
│   └── syscall/                  # 编译产物为 libff_syscall.so 与独立 fstack 实例二进制；通过
│                                  # LD_PRELOAD 劫持 Linux syscall（socket/bind/connect/read/write/
│                                  # send/recv/epoll/accept4/__recv_chk/fork/ioctl 等）转发给
│                                  # fstack 实例，IPC 走 Hugepage 共享内存（sem 路径或开关
│                                  # FF_USE_RING_IPC 后的 lock-free ring 路径）
├── doc/                          # 原始英文文档
├── docs/                         # 三层架构知识库文档
└── config.ini                    # 默认配置文件
```

### 2.2 核心模块职责边界

| 模块 | 行数 | 职责 | 依赖 |
|-----|------|------|------|
| **ff_dpdk_if.c** | 2907 | NIC 驱动/DPDK 操作/收发包核心逻辑 | DPDK, ff_glue |
| **ff_glue.c** | 1467 | FreeBSD 内核模拟/内存/锁/中断（M4 完成 8 类 14.0+ ABI 修复） | FreeBSD headers, DPDK |
| **ff_config.c** | 1694 | INI 配置文件解析 | ff_ini_parser |
| **ff_syscall_wrapper.c** | 2265 | Linux 系统调用→FreeBSD 适配（M4 同步 sockaddr；FF_KERNEL_COEXIST 路由；R9 kqueue 共存 + IPV6_V6ONLY；R10 readv/writev/ioctl/dup/dup2 内核 fd 路由） | FreeBSD sys |
| **ff_init.c** | 70 | 初始化流程协调 | 上述所有模块 |
| **ff_epoll.c** | 289 | Linux epoll→FreeBSD kqueue 转换（F-Stack + 内核统一；ff_epoll_host_ep 与 kqueue 路径共享） | FreeBSD kqueue |
| **ff_host_interface.c** | 617 | 主机 OS 接口 (mmap/pthread/rand) + FF_KERNEL_COEXIST 宿主栈桥（32 个 ff_host_*） | 系统库 |
| **ff_dpdk_kni.c** | ~441 | 虚拟网卡支持（通过 virtio_user 实现，已不依赖 rte_kni.ko） | DPDK virtio_user |
| **ff_route.c** | 1604 | 路由套接字 / RIB 钩子（rtsock 部分移植；M4 完成 5 类 14.0+ ABI 修复） | FreeBSD net/route |
| **ff_veth.c** | 1132 | 虚拟以太网设备（M4 完成 28 处 if_t accessor 重写） | FreeBSD net/if |
| **ff_kern_timeout.c** | 1266 | callout 子系统（`callout_init`、`_reset_tick_on`、`ff_timecounter`） | DPDK rte_timer |
| **ff_ng_base.c** | 3887 | netgraph 框架完整移植（M5：`node_p → node_cp` 修正） | FreeBSD netgraph 头文件 |
| **ff_stub_14_extra.c** | 799 | 新增（M5 + runtime-fix）：14.0+ 中央 stub 库（123 个 stub，661 个 undef 解决） + 5 个 P0 SIGSEGV 修复 + 防御性 `vm_page_alloc_noobj` panic | FreeBSD 14.0+ KBI |

## 3. FreeBSD TCP/IP 栈移植方式

### 3.1 移植策略

F-Stack 采用了**完整移植**策略：
- 早期从 FreeBSD 13.0 提取了完整的 TCP/IP 协议栈代码；**2025-2026 已升级到 FreeBSD 15.0**（M0~M5；完整证据见 `docs/freebsd_13_to_15_upgrade_spec/`）
- 在 `freebsd/netinet/`（含 `netinet/tcp_stacks/`，提供 RACK/BBR）、`freebsd/netinet6/`、`freebsd/net/`（含 `net/route/` FIB 重写子目录）中保留所有网络协议代码
- 通过 `ff_glue.c` 与新增的 14.0+ stub 中央库 `ff_stub_14_extra.c` 实现内核 API 的用户态模拟
- 通过条件编译支持可选功能（IPv6、KNI、TCPHPTS、FF_NETGRAPH 等）；15.0 引入的 NETLINK 协议、KTLS 等子系统按 DP-2 / out-of-scope 决策**不**移植
- **Phase-2 M6（2026-06-08）**：在 `lib/Makefile` 中默认启用 `FF_NETGRAPH=1` + `FF_IPFW=1`；引入 41 个 netgraph 节点 + 14 个 ipfw 内核对象到 `libfstack.a`（现为 6.5 MB，原 5.4 MB）；`tools/sbin/ipfw` 25 MB 用户态二进制现已产出（FF_IPFW=0 时不编译）；`ipfw add/show/delete` 与 `ngctl list` 通过 DPDK secondary IPC 端到端验证。完整证据 + `lib/ff_stub_14_extra.c` 新增 7 个 link-only stub 见 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M6-execution-log.md`
- **Phase-2 M7（2026-06-08）**：默认启用 `FF_USE_PAGE_ARRAY=1`（P1a，单次过 / 0 打回）；将 `lib/ff_memory.c`（481 行，mmap-based page-array + mbuf reference pool）纳入 `FF_HOST_SRCS`；运行时 `ff_mmap_init` 一次性预留 256 MB（65536 × 4 KB 页）以摊销每包 4 KB alloc/free 系统调用开销。详见 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M7-execution-log.md`
- **Phase-2 M8（2026-06-08）**：默认启用 `FF_ZC_SEND=1`（P1b，1 次打回）；引入 `FSTACK_ZC_MAGIC` sentinel（uio.uio_offset = 0xF8AC2C00F8AC2C00）协议 + 新公开 API `ff_zc_send`，用于区分 ZC mbuf chain 与普通 char buffer；修复 13.0 baseline 遗留 ZC fast-path bug —— 原 `m_uiotombuf` 谓词命中所有 `ff_write`/`ff_writev` 调用，在高压下会静默破坏数据或 `m_demote` GPF。共 8 文件 +85/-4，覆盖 `freebsd/sys/mbuf.h`、`freebsd/kern/uipc_mbuf.c`、`freebsd/kern/sys_generic.c`、`lib/Makefile`、`lib/ff_syscall_wrapper.c`、`lib/ff_api.h`、`lib/ff_api.symlist`、`example/Makefile` + `example/main_zc.c`。通过 ssh f-stack-client curl 端到端验证：HTTP 200 / 438 字节真实 HTML body / 100x 短连 100/100 通过。详见 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M8-execution-log.md`
- **Phase-2 M9（2026-06-08）**：同时启用 `FF_USE_PAGE_ARRAY=1` + `FF_ZC_SEND=1` combo（P1c，单次过 / 0 打回，1 行 Makefile diff 复用 M7+M8 已有代码）；端到端验证共存能力（ff_mmap_init 256MB + ipfw2/tcp_bbr init 干净 + HTTP 200 单次 curl + 100/100 短连）。1000 短连 observation：约 M8 ZC-only 的 3.5 倍耗时且偶发 timeout —— 记为 M9-followup-F1，推迟到 phase-5b 阶段做性能 profiling。详见 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M9-execution-log.md`
- **Phase-2 M10（2026-06-08）**：启用 `FF_FLOW_IPIP=1`（P1d，1 次打回）；将 `create_ipip_flow` 失败从 `rte_exit` 软化为 printf warning，使 primary 在不支持 rte_flow IPIP 卸载的 NIC（如 virtio）上仍可起栈；GIF 隧道走 FreeBSD `if_gif/in_gif` 软件路径。端到端 IPIP 隧道实测：服务端 `tools/sbin/ifconfig gif0 create + tunnel + inet` + 客户端 Linux `ip tunnel add gif0 mode ipip` + ping 3/3 received 0% loss RTT 0.29-0.65 ms。example/Makefile 在 libfstack.a 未启 FF_ZC_SEND 时自动跳过 helloworld_zc target。详见 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M10-execution-log.md`
- **Phase-2 M11/M12/M13（2026-06-08）**：P2 优先级 smoke 三件套 —— 依次启用 `FF_FLOW_ISOLATE=1`（M11）、`FF_FDIR=1`（M12）、`FF_LOOPBACK_SUPPORT=1`（M13）；每个里程碑 lib 编译干净 + helloworld primary 起栈成功。M11 按 M10 模式批量软化了 `port_flow_isolate`/`init_flow`/`fdir_add_tcp_flow` 三处 rte_exit。M13 在 `ff_stub_14_extra.c` 加了一个链接-only stub `ff_swi_net_excute`（声明于 `ff_host_interface.h:92`，但仓库内从未实现）。详见 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase2-M11-M13-spec.md`
- **Phase-5b 性能基线（2026-06-08）**：通过 `tools/sbin/p5b_perf_matrix.sh`（curl-bench from f-stack-client；ssh round-trip 上限 ~137 conn/s，仅跨配置 delta 有意义）执行 5 配置 × 2-3 testcase × 3-trial 矩阵。关闭 M9-F1（PA+ZC combo 仅 +4.1%，phase-2 当时 3.5x 是残留进程噪音误判）+ M10-F2（IPIP 隧道 ping 基线 0.39 ms / 0% loss / 9 ms jitter）。新增 **finding F-A1（HIGH）**：`FF_USE_PAGE_ARRAY=1` 单独启用时 ICMP+HTTP 全断（`lib/ff_memory.c:453` 的 `ff_chk_vma` 不覆盖 ARP/ICMP mbuf 数据指针），留 followup 不在本阶段修复。生产推荐：优先 C8 ZC-only 或 C9 PA+ZC，避免 PA-only。详见 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/phase-5b-perf-baseline-report.md`
- **F-A1 修复（2026-06-08）**：关闭 phase-5b HIGH 级 finding。单文件单函数补丁：`lib/ff_memory.c:ff_if_send_onepkt` 把 `rte_panic` 改为 `rte_log(WARNING) + ff_mbuf_free(m) + return 0`。根因：某个启动早期边界 mbuf（gratuitous ARP / IPv6 RS / loopback 控制包）的数据指针既不在 PA VMA 内也不是已知 EXT_CLUSTER 时，会 `abort()` 整个 dataplane。修复方案是把 panic 降级为非致命软 drop —— 由 TCP/ARP 重传自动恢复。实测：PA-only 1000/1000 curl PASS、TC1 比 C0 baseline 快 7.4%、稳态 0 drop 事件。F-A2 标 N/A（panic 通道彻底移除，ARP-cache 因素不再相关）。**4 个配置（C0/C7/C8/C9）现在全部 production-ready**。详见 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/F-A1-fix-execution-log.md`
- **VLAN + vip_addr + ipfw_pr 配置层功能测试（2026-06-09）**：双 vlan multi-tenant 配置层验收，使用 4-子-agent harness（spec-writer / coder / reviewer / gate-keeper）。双 `[vlan1]`/`[vlan2]` 测试配置（`config.test-vlan.ini`，192.169.0/1.0/24 与 production 9.134.214.176/21 隔离）在 primary 启动时验证：`if_clone_create f-stack-0.1`/`f-stack-0.2` 双双成功，无 `ff_veth_setvaddr` 错误，`tools/sbin/ipfw show` 列出硬证据规则 `00010 setfib 0 ip from 192.169.0.0/24 out` + `00020 setfib 1 ip from 192.169.1.0/24 out` —— fib_num 与 `ff_veth.c:949 fib_num = vlan_cfg->vlan_idx` 完全吻合。G1/G2/G3/G4 全 PASS，BOUNCE 0/3，0 次直接 rm/kill/chmod 调用。端到端 e2e（loopback ping vip / client 802.1Q HTTP）记为 F-V1/F-V2 follow-up。详见 `docs/freebsd_13_to_15_upgrade_spec/zh_cn/vlan-vip-ipfw-test-execution-log.md`

### 3.2 FreeBSD 移植的子系统

```text
freebsd/
├── netinet/        # IPv4: tcp_*.c, udp_*.c, ip_*.c, if_arp.c
│   └── tcp_stacks/ # 模块化 TCP stacks: rack.c (~759 KB), bbr.c (~444 KB), tailq_hash.* (-DMODNAME=tcp_rack)
├── netinet6/       # IPv6: ip6_*.c, tcp6_*.c
├── net/            # 通用网络: if.c, route.c, netisr.c
│   └── route/      # FIB 重写子目录（14.0+）：nhop、fib_algo、route_ctl（22 文件）
├── netlink/        # 14.0+ NETLINK 头文件（仅头文件，0 个 .c）—— DP-2：协议未移植
├── netgraph/       # netgraph 内核侧（与 lib/ff_ng_base.c 配对）
├── kern/           # 内核服务: malloc, mutex, synch, callout（含 kern_descrip.c 5475 边界修正）
├── vm/             # 虚拟内存: vm_page.c (mbuf 映射)
└── sys/            # 系统定义: socket.h, mbuf.h 等
```

### 3.3 ff_glue.c 中的内核模拟

| 内核功能 | FreeBSD 原生 | F-Stack 模拟 |
|---------|-------------|-----------|
| 内存分配 | `malloc()` | DPDK `rte_malloc()` |
| 互斥锁 | `struct mtx` | `pthread_mutex_t` |
| 条件变量 | `struct condvar` | `pthread_cond_t` |
| 软中断 | `swi_*` | 内部 taskqueue |
| 定时器 | `callout{}` | DPDK `rte_timer` |
| 分页内存 | `vm_page_alloc()` | DPDK mempool |

## 4. DPDK 集成与 NIC 驱动层

### 4.1 ff_dpdk_if.c 核心职责

这是最核心的模块 (2907 行)，负责整个数据链路：

**初始化流程**:
```text
ff_dpdk_init()
  ├─ rte_eal_init()              // DPDK 环境初始化
  ├─ init_lcore_conf()           // CPU 核心/端口映射
  ├─ init_mem_pool()             // mbuf 内存池创建
  ├─ init_dispatch_ring()        // 进程间消息队列
  ├─ init_port_start()           // NIC 启动 + RSS 配置
  ├─ ff_rss_tbl_init()           // RSS 分类表建立
  └─ init_clock()                // FreeBSD 时钟初始化
```

### 4.2 收包流程 (Ingress)

```text
NIC 硬件 (RSS 处理器分发)
  ↓
多个 RX 队列 (per-CPU-core)
  ↓
DPDK PMD (rte_eth_rx_burst())
  ↓
process_packets() 函数
  ├─ 协议过滤 (ARP/IPv4/IPv6/Multicast)
  ├─ 虚拟网卡处理 (veth_input)
  └─ FreeBSD 栈 (if_input → eth_input → ip_input → tcp_input → sorecv)
```

### 4.3 发包流程 (Egress)

```text
应用 (ff_write/ff_send/ff_sendto/ff_sendmsg)
  ↓
FreeBSD TCP/UDP 栈
  ├─ tcp_output() / udp_output()
  ├─ ip_output()
  └─ if_output()
  ↓
ff_glue.c if_start()
  ├─ 获取 mbuf
  ├─ 填充 L2/L3/L4 头
  ├─ 配置硬件卸载 (TSO/Checksum)
  └─ send_single_packet()
  ↓
DPDK rte_eth_tx_burst()
  ↓
NIC 硬件
```

## 5. 主处理循环

### 5.1 main_loop() 伪代码

```c
int main_loop(void *arg) {
    while (!stop_loop) {
        // [1] 驱动 FreeBSD 定时器
        if (freebsd_clock.expire < cur_tsc) {
            rte_timer_manage();
        }
        
        // [2] 轮询所有 RX 队列
        for (each_rx_queue) {
            nb_rx = rte_eth_rx_burst(...);
            process_packets(pkts_burst, nb_rx);
        }
        
        // [3] 定时刷新 TX 队列
        if (drain_tsc && (cur_tsc - prev_tsc) > drain_tsc) {
            for (each_port) {
                rte_eth_tx_burst(...);
            }
        }
        
        // [4] 执行用户回调
        if (usr_loop) {
            usr_loop(arg);
        }
    }
}
```

### 5.2 轮询特性

- **无中断**: → 低延迟、高吞吐
- **占用 CPU**: 100% 利用 (通过 CPU 隔离优化)
- **可配置睡眠**: `idle_sleep` 参数支持微秒级让步

## 6. 进程模型

### 6.1 单进程模式 (推荐)

```text
F-Stack 进程 (1 个)
  └─ 单个 lcore (1 个 CPU 核心)
    ├─ NIC RX/TX 队列映射
    ├─ FreeBSD 协议栈运行
    └─ 应用逻辑执行
```

**适用场景**: 小型应用、专用设备

### 6.2 多进程模式

```text
主进程 (Primary)
  ├─ DPDK EAL 初始化
  └─ 启动 N 个 Worker 进程

Worker-0 (CPU-0)  ┐
Worker-1 (CPU-1)  ├─ 各进程独立运行
...               │  通过 RSS 维持连接亲和性
Worker-N (CPU-N)  ┘

共享资源:
  ├─ DPDK Mempool
  ├─ RSS 分类表
  └─ 虚拟网卡 (KNI)
```

**优势**: 故障隔离、灵活扩展  
**劣势**: 进程间同步复杂

### 6.3 内核栈共存（`FF_KERNEL_COEXIST`，可选，默认关）

可选模式（编译期宏 `FF_KERNEL_COEXIST` + 运行期 `config.ini [stack] kernel_coexist`，二者均默认关）让单进程从 **同一个 `ff_epoll_wait` 循环** 同时通过 **F-Stack 栈** 与 **宿主 Linux 内核栈** 对外服务：

- `ff_socket()` 通过 `SOCK_FSTACK` / `SOCK_KERNEL` 标记选栈；无标记时 **双建** 一个 F-Stack socket 加一个配对宿主 socket。
- 内核栈 fd 以 `host_fd + 0x40000000`（`FF_KERNEL_FD_BASE`）返回，与 FreeBSD fd（`< 65536`）永不冲突；入口将此类 fd 路由到薄 `ff_host_*` 宿主 libc 桥。
- F-Stack ↔ 宿主 fd 配对存于 `ff_native_fd_map`；`ff_epoll_*` 为每个 kqueue 惰性配对一个宿主 `epoll` 实现统一事件投递。双建 `AF_INET6` socket 的宿主对应 socket 被设 `IPV6_V6ONLY=1`（`ff_host_set_v6only`，R9），使 v4+v6 同端口共存（修复此前 `-DINET6` `errno=98` 启动失败）。
- **R9** 将统一事件扩展到原生 `ff_kqueue`/`ff_kevent`（共享 `ff_epoll_host_ep`）：`ff_kevent` 把内核/双栈 fd 的 `EVFILT_READ/WRITE` 注册进 kqueue 配对的宿主 epoll，等待时非阻塞轮询合成 `struct kevent`（`ident`=应用面 fd）再合并 F-Stack 事件 —— 纯 kqueue 应用（`example/main.c`）现可感知内核侧 listener（`curl 127.0.0.1:80`=200，修复前 000）。
- **R10** 补齐残余入口内核 fd 路由：`ff_readv`/`ff_writev` 内核 fd 经 `ff_host_readv/writev`（仿 read/write）；`ff_ioctl` 内核 fd 用**原始 Linux request** 直传 `ff_host_ioctl`（双栈 fd 同驱动自 R10.1 起支持 `FIONBIO`/`FIOASYNC`）；`ff_dup`→`ff_host_dup`+encode，`ff_dup2` 两端内核 fd→`ff_host_dup2`+encode、混栈拒绝 `errno=EINVAL`。
- 宏关闭时库与纯 F-Stack 构建逐字节一致。已知限制：内核 fd 经 kqueue 仅支持 `EVFILT_READ/WRITE`；`ff_select`（encode 内核 fd 超 `FD_SETSIZE` 硬限制）与 `ff_poll`（保守未实现）不支持内核 fd 共存 —— 改用 `ff_epoll_*`/`ff_kqueue` 多路复用。详见 `docs/kernel_event_support_spec/`。

## 7. 技术选型分析

### 7.1 为什么选 DPDK 而非 NETMAP/PF_RING

| 对比项 | DPDK | NETMAP | PF_RING |
|-------|------|--------|---------|
| 社区活跃度 | ★★★★★ | ★★★ | ★★★ |
| 跨平台 | ✓ | ✓ | ✗ (Linux only) |
| 生态完整性 | ★★★★★ | ★★★ | ★★ |
| 企业采用 | ★★★★★ | ★★★ | ★★ |
| 硬件卸载支持 | ★★★★★ | ★★★ | ★★ |

**选择原因**:
- Tencent 已有 DPDK 积累 (DNSPod DNS)
- 多进程架构支持最完善
- 硬件卸载支持最广泛 (TSO/GSO/Checksum)

### 7.2 为什么选 FreeBSD 栈而非自研

| 方面 | FreeBSD 栈 | 自研栈 |
|-----|-----------|--------|
| 开发周期 | 即用 | 2-3 年 |
| 功能完整 | ★★★★★ | ★★★ |
| 性能优化 | ★★★★★ | ★★ |
| RFC 兼容性 | ★★★★★ | ★★★ |
| 社区反馈 | ★★★★★ | 无 |
| 维护成本 | ★★★ | ★★★★★ |

**历史背景**:
- 初期自研简单栈 → 稳定性不足
- 2017 年参考 libplebnet/libuinet → 完整移植 FreeBSD 栈
- 这决定了今天的架构

## 8. 硬件卸载特性

F-Stack 充分发挥现代 NIC 硬件能力：

### 8.1 RX 卸载

| 特性 | 效果 | 支持度 |
|-----|------|--------|
| **校验和卸载** | 验证 L3/L4 由硬件完成 | 广泛 |
| **LRO** (Large Receive Offload) | 合并小报文为大报文 | 部分 |

### 8.2 TX 卸载

| 特性 | 效果 | 支持度 |
|-----|------|--------|
| **TSO** (TCP Segmentation Offload) | 大报文由硬件分段 | 广泛 |
| **校验和卸载** | 计算 L3/L4 校验和 | 广泛 |
| **VLAN 插入** | 硬件添加 VLAN 标签 | 部分 |

### 8.3 流分类 (RSS)

- **硬件 RSS**: 基于 5 元组 (src-ip, dst-ip, src-port, dst-port, proto)
- **好处**: 同一连接总是路由到同一 RX 队列 → 避免 TCP 乱序

## 总结

F-Stack 的架构设计围绕三个核心支柱：
1. **Kernel Bypass**: 规避 Linux 内核瓶颈
2. **成熟协议栈**: 复用 FreeBSD 久经考验的实现
3. **多核并行**: 充分利用现代多核 CPU 和 NIC 硬件能力

这使得 F-Stack 能够达到 500 万+ RPS、1000 万+ 并发连接的性能水平，是云计算核心网络设施的理想选择。
