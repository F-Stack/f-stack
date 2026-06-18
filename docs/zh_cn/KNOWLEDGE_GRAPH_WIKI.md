# F-Stack 知识图谱 Wiki

> 由 GitNexus 知识图谱（schema v1）自动提取并结合源码人工交叉核对生成。**索引时间：2026-06-08T03:37:02Z，commit `208b0c4`**（`dev` 分支，FreeBSD 13.0 → 15.0 第一阶段升级完成后：含 M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS）。

---

## 1. 项目概览

| 指标 | 数据 |
|------|------|
| 索引文件数 | 2,656 |
| 符号节点 | 64,855 |
| 关系边 | 113,858 |
| 功能聚类 | 981 (communities) |
| 执行流 | 300 (processes) |
| 嵌入向量节点 | 0（本轮未启用语义搜索） |
| 有效范围 | 仅 F-Stack 自有源面（gitnexus 1.6.5 schema 已正确排除 DPDK / FreeBSD 第三方树） |
| 索引器 | gitnexus 1.6.5（ladybugdb provider；FTS 可用，向量搜索未启用） |

> **Schema 迁移说明**：旧版 wiki 快照（commit `a695757`，索引时间 2026-04-09）报告 25,723 文件 / 710,596 节点，使用 gitnexus 1.5.x 时部分节点类别将 vendored 的 FreeBSD/DPDK 树也计入。Schema v1 已正确将图谱限定在 F-Stack 自有代码面，节点数大幅下降是 **测量范围修正，并非代码退化**。

> **节点类型 / 命名聚类细分表已不可用**：schema v1 的 `meta.json` 仅暴露顶层总数。早期的逐类型表（Macro / Function / Property / …）与命名聚类表（Net / Netinet / Tcp_stacks / …）是 schema v0 通过 LLM 增强生成的产物。如需复现等价分类，须运行 `npx gitnexus wiki` 并配置 LLM API key（本轮未配置）。如需在不依赖 LLM 的前提下重新派生，可直接查询 `.gitnexus/lbug` 下的 ladybugdb，或参考 `docs/freebsd_13_to_15_upgrade_spec/02-architecture-analysis.md` 中的权威子系统分组。

---

## 2. F-Stack 13.0 → 15.0 升级 Delta 映射

本索引在第一阶段 13.0 → 15.0 升级 **完成之后** 重建，因此图谱已反映以下差异：

| 维度 | 在图谱中的体现 |
|------|----------------|
| 33 个 `lib/*.c` 文件（其中 17 个为 13.0 之后新增/重构） | `lib/` 目录与文件节点；新 stub 总枢 `lib/ff_stub_14_extra.c`（799 L，M5 + runtime-fix 落点） |
| 14.0+ KBI/KPI 偏差（`pr_usrreqs` 合入 `protosw`；`if_t` 不透明化；`rt_alloc` 第 3 参签名变化；`rt_ifmsg` 走 rtbridge 派发；8 类 14.0+ ABI delta） | `lib/ff_glue.c`、`lib/ff_route.c`、`lib/ff_veth.c`、`lib/ff_kern_timeout.c`、`lib/ff_lock.c`、`lib/ff_syscall_wrapper.c` 与新中央 stub 库之间的边 |
| 5 P0 SIGSEGV runtime-fix 落点（UMA `UMA_USE_DMAP`、`smr_create %gs` barrier、`rt_ifmsg` NULL、`ff_veth_setaddr` ENOBUFS、`kern_accept` `badfileops`）+ 1 防御性 `vm_page_alloc_noobj` panic | 文件 `freebsd/{amd64,arm64}/include/vmparam.h`、`freebsd/amd64/include/atomic.h`、`freebsd/kern/kern_descrip.c`、`lib/Makefile`、`lib/ff_stub_14_extra.c` |
| 架构移除：`freebsd/mips/`（同步上游 FreeBSD 14.0 移除） | F-Stack 图谱中无 mips 架构节点；残余 `mips` 字符串仅出现在 `freebsd/contrib/device-tree/`（DTS，不参与编译） |
| 新增的纯头文件子系统 port：`freebsd/netlink/`（18 `.h`，0 `.c`，0 `SRCS`）—— DP-2 决策"不引入 NETLINK 协议 port" | netlink 文件夹节点没有指向 F-Stack 库的任何 CALL 出边 |
| 路由 FIB 重写子目录：`freebsd/net/route/`（22 文件：`nhop`、`fib_algo`、`route_ctl`） | route_ctl 节点新增聚类，由 `lib/ff_route.c` 与 `lib/ff_stub_14_extra.c` 连入 |
| TCP stacks 模块化（`-DMODNAME=tcp_rack -DSTACKNAME=rack`）；F-Stack H-5 模块重命名 `tcp_rack_fstack` 已重应用 | `freebsd/netinet/tcp_stacks/`（11 文件，含 `rack.c` ~759 KB、`bbr.c` ~444 KB） |

每条 delta 的逐证据可追溯链：参见 `docs/freebsd_13_to_15_upgrade_spec/{00-overview-and-glossary, 01-requirements-spec, 02-architecture-analysis, 03-freebsd-15-changes, 04-diff-and-port-strategy, 05-implementation-plan, 06-test-and-acceptance-spec}.md`，里程碑日志 `M1~M5-execution-log.md`，`runtime-fix-execution-log.md`，`rib-fix-plan.md`，以及双基线（`13.0-baseline-cvm-bench-report.md` + `physical-machine-bench-report.md`）。

---

## 2A. 索引后代码 delta：`FF_KERNEL_COEXIST` 内核栈共存

> **人工补录（尚未重索引）**：上方图谱索引于 commit `208b0c4`（2026-06-08）。此后 `feature/1.26` 分支落地了 **`FF_KERNEL_COEXIST` 自动双栈共存** 特性（commits `ba148589d` → `55a84f313`），**R9** 增量（kqueue/kevent 共存 + IPv6 `IPV6_V6ONLY`），以及 **R10** 增量（`ff_readv`/`ff_writev`/`ff_ioctl` 内核 fd 路由 + `ff_dup`/`ff_dup2`）。在下次 `npx gitnexus analyze` 之前，以下表面以当前源码为准人工记录。

该特性让单进程从同一个事件循环里（`ff_epoll_wait`，自 R9 起也支持 `ff_kqueue`/`ff_kevent`），同时通过 F-Stack 用户态栈（经 DPDK 网卡）与宿主 Linux 内核栈（经 loopback / 管理网卡）对外服务。**默认关闭**（编译期宏 + 运行期 `kernel_coexist` 开关双门控）；关闭时默认 / `SOCK_FSTACK` 路径逐字节不变。

| 维度 | 源码位置 |
|------|----------|
| 编译 & 运行双门控（默认关） | `lib/Makefile` L174-177 向 `CFLAGS` 与 `HOST_CFLAGS` 双侧注入 `-DFF_KERNEL_COEXIST`；运行期 `config.ini [stack] kernel_coexist=0` 默认关（`ff_config.c` L1027-1033 解析 / L1366 默认；`ff_config.h` L321-325 `stack` 结构体） |
| 受管内核 fd 空间 | `lib/ff_host_interface.h` L113-128：`FF_KERNEL_FD_BASE 0x40000000` + inline `ff_is_kernel_fd / ff_kernel_fd_encode / ff_kernel_fd_real`；受管内核 fd = `host_fd + 0x40000000`，与 FreeBSD fd（`kern.maxfiles <= 65536`）永不冲突 |
| 双栈 fd 映射 | `lib/ff_host_interface.c` L257-278：`ff_native_fd_map[65536]` + `ff_native_map_get/set/clear`（每 F-Stack 实例单线程） |
| 32 个宿主栈桥 | `lib/ff_host_interface.c`（`ff_host_socket` … `ff_host_getsockname`），声明于 `lib/ff_host_interface.h` —— 每个均为对宿主 libc 的薄透传。**R9 新增 3 个**：`ff_host_set_v6only`（对宿主 IPv6 socket `setsockopt IPV6_V6ONLY`）、`ff_host_kqueue_ctl`、`ff_host_kqueue_poll`（后两者服务 kqueue↔宿主 epoll 共存路径）。**R10 新增 5 个**：`ff_host_readv`、`ff_host_writev`、`ff_host_ioctl`（用原始 Linux request 直传宿主 libc）、`ff_host_dup`、`ff_host_dup2` |
| 单 socket 栈标记 | `lib/ff_api.h` L95-100：`SOCK_FSTACK 0x01000000`、`SOCK_KERNEL 0x02000000`；优先级：per-socket 标记 > config `kernel_coexist` > F-Stack |
| 入口路由 | `lib/ff_syscall_wrapper.c`：`ff_socket` 双建（L916-958；`AF_INET6` 双建时在 L952 调 `ff_host_set_v6only(hfd)`，使宿主 IPv6 socket 为 `IPV6_V6ONLY` 与同端口宿主 IPv4 socket 共存 —— R9/P1）；内核 fd 热路由 + 双栈 map 双驱动，覆盖 `socket/bind/listen/connect/accept[4]/close/read/write/recv*/send*/sendmsg/recvmsg/getpeername/getsockname/shutdown/setsockopt/getsockopt/fcntl`；`LINUX_IPV6_V6ONLY 26`→`IPV6_V6ONLY` 映射在 L620-621。**R10 已补内核 fd 路由：`ff_readv` / `ff_writev` / `ff_ioctl` / `ff_dup` / `ff_dup2`**（详见下方 R10 行） |
| 统一 epoll | `lib/ff_epoll.c`（289 行）：`ff_epoll_pairs[64]{kq, host_ep}` 为每个 kqueue 惰性配对一个宿主 epoll fd；`ff_epoll_ctl` 把内核 fd 转发宿主 epoll / 对双栈 fd 双注册；`ff_epoll_wait` 先非阻塞轮询宿主 epoll 再合并 kqueue 事件。`ff_epoll_pairs_lock` 已移除 —— 单线程模型（commit `3e71f4699`）。`ff_epoll_host_ep` 由 `static` 提升为共享符号（声明于 `ff_host_interface.h` L139），供 kqueue 路径复用同一配对表 |
| 统一 kqueue/kevent（R9/P2） | `lib/ff_syscall_wrapper.c`：`ff_kqueue`（L1895）+ `ff_kevent`（L2050）现与 epoll 对称共存。`ff_kevent` 处理 changelist → `ff_kevent_host_change`（L2006）：ident 为内核 fd（`ff_is_kernel_fd`）或双栈 fd（`ff_native_map_get>0`）的 `EVFILT_READ/WRITE` 经 `ff_host_kqueue_ctl` 注册进 kqueue 配对的宿主 epoll（内核-only 变更不下发 F-Stack kqueue；双栈 fd 仍下发）；eventlist → `ff_kevent_host_wait`（L2034）经 `ff_host_kqueue_poll`（`timeout=0`）合成 `struct kevent`（`ident`=应用面 fd，`EV_EOF`↔`EPOLLHUP|ERR`），再合并 `ff_kevent_do_each` F-Stack 事件。修复 `example/main.c` kqueue 模型：内核侧 `curl 127.0.0.1:80` 实测 **200 size=438**（修复前 000）。已知限制：内核 fd 经 kqueue 仅支持 `EVFILT_READ/WRITE` |
| 残余入口共存（R10） | `lib/ff_syscall_wrapper.c`：`ff_ioctl`（L1067）内核 fd 用**原始 Linux request** 直传 `ff_host_ioctl`（不经 `linux2freebsd_ioctl`，因 `_IO/_IOR/_IOW(type,nr,size)` 编码在 Linux 与 FreeBSD 不同源；双栈 fd 同驱动自 R10.1 起支持 `FIONBIO`/`FIOASYNC`（F-Stack 成功后用原始 Linux request 同步配对 host fd；`FIONREAD` 等 query 类不同驱动以免覆盖 argp））；`ff_readv`（L1189）/`ff_writev`（L1251）内核 fd 经 `ff_host_readv/writev`（仿 `ff_read/write`，连接 fd 单栈热路径）；`ff_dup`（L2130）内核 fd→`ff_host_dup` 返回新 encode fd；`ff_dup2`（L2156）两端内核 fd→`ff_host_dup2` 返回 encode，**混栈（一端内核一端 F-Stack）拒绝 `errno=EINVAL`**。**已知限制**：`ff_select`（encode 内核 fd≥`0x40000000` 远超 `FD_SETSIZE`(1024) 无法装入 `fd_set`，硬限制不支持）、`ff_poll`（合并复杂度/回归风险高，保守未实现）—— 内核 fd 多路复用请用 `ff_epoll_*`/`ff_kqueue`（R9 已支持） |

可追溯：`docs/kernel_event_support_spec/` 与 `docs/kernel_event_support_spec/zh_cn/`（00-10），含 R8 review-gate 日志、R9 计划 `plan-r9-kqueue-coexist-ipv6.md` 与 R10 计划 `plan-r10-readv-writev-ioctl-coexist.md`。

---

## 3. 目录结构

```
f-stack/
├── lib/            # F-Stack 核心库（33 个 .c；ff_stub_14_extra.c 为 14.0+ stub 中央枢）
├── adapter/        # LD_PRELOAD 适配层（syscall hook、micro_thread 桥接）
├── app/            # 集成应用（nginx-1.28.0/、redis-6.2.6/）
├── example/        # 示例程序（helloworld、helloworld_epoll、main_zc.c 零拷贝）
├── tools/          # ifconfig / netstat / arp / route 用户态移植
├── mk/             # 构建系统（Makefile include 文件）
├── doc/            # 上游原始文档
├── docs/           # 三层架构知识库 + LD_PRELOAD Ring IPC spec + 13.0→15.0 升级 spec
├── dpdk/           # DPDK 24.11.6 LTS 子模块（2026-06-09 由 23.11.5 升级；已从 gitnexus 索引排除）
└── freebsd/        # FreeBSD 15.0 内核源码移植（已从 gitnexus 索引排除）
```

### 3.1 核心库文件 (`lib/`)

`lib/` 下 33 个 `.c` 文件（已经直接 read 验证）按职责分为 6 类。下表给出代表性 anchor；完整清单与逐文件行数见 `docs/zh_cn/F-Stack_Architecture_Layer3_Function_Index.md` §"lib/ 文件索引" 与 `docs/freebsd_13_to_15_upgrade_spec/docs-sync-2026-06-08-update-matrix.md` §1.2。

| 职责 | 代表文件 |
|------|----------|
| 公开 API 与初始化 | `ff_api.h`、`ff_init.c`（70 行）、`ff_init_main.c`（~660+ 行）、`ff_freebsd_init.c`（~154 行） |
| 配置 | `ff_config.c`（1,694 行；含 `[stack] kernel_coexist` 解析）、`ff_ini_parser.c`（第三方 inih） |
| DPDK 适配 | `ff_dpdk_if.c`（2,907 行；`main_loop` 在此）、`ff_dpdk_kni.c`（~441 行）、`ff_dpdk_pcap.c`（~118 行） |
| Linux→FreeBSD 胶水 | `ff_glue.c`（1,467 行）、`ff_syscall_wrapper.c`（2,265 行；含 `FF_KERNEL_COEXIST` 入口路由 + R9 `ff_kqueue/ff_kevent` 共存 + `IPV6_V6ONLY` + R10 `ff_readv/writev/ioctl/dup/dup2` 内核 fd 路由）、`ff_host_interface.c`（617 行；32 个 `ff_host_*` 宿主栈桥含 R9 `ff_host_kqueue_ctl/poll` + `ff_host_set_v6only`、R10 `ff_host_readv/writev/ioctl/dup/dup2` + `ff_native_fd_map`）、`ff_host_interface.h`（187 行）、`ff_epoll.c`（289 行；F-Stack + 内核统一 epoll，`ff_epoll_host_ep` 与 kqueue 路径共享）、`ff_compat.c`（~360 行） |
| 内核仿真（源自 libplebnet / libuinet） | `ff_kern_condvar.c`、`ff_kern_environment.c`（509 行）、`ff_kern_intr.c`（108 行）、`ff_kern_subr.c`（271 行）、`ff_kern_synch.c`（132 行）、`ff_kern_timeout.c`（1,266 行；callout 子系统）、`ff_lock.c`（448 行；sx/mutex/lockmgr）、`ff_log.c`（111 行）、`ff_memory.c`（481 行）、`ff_subr_epoch.c`（83 行；M2 verify-only）、`ff_subr_prf.c`（604 行）、`ff_thread.c`（51 行）、`ff_vfs_ops.c`（117 行） |
| 网络与 netgraph | `ff_route.c`（1,604 行；rtsock 部分 port + ff_rtioctl）、`ff_veth.c`（1,132 行；M4 if_t accessor 重写）、`ff_ng_base.c`（3,887 行；netgraph 框架完整移植）、`ff_ngctl.c`（131 行） |
| **14.0+ stub 中央枢（新增）** | `ff_stub_14_extra.c`（799 行）—— 14.0+ ABI 缺口的中央 stub 库 + 5 个 runtime-fix 补丁的落点 + 防御性 `vm_page_alloc_noobj` `panic()` |

### 3.2 适配器层 (`adapter/`)

`adapter/syscall/` 同时构建出 `libff_syscall.so`（被预加载到用户应用进程）与独立的 `fstack` 实例二进制，二者共同实现 LD_PRELOAD 模式。主要文件：

| 文件 | 职责 |
|------|------|
| `syscall/ff_hook_syscall.c` / `.h` | LD_PRELOAD POSIX hook（`socket / bind / connect / accept[4] / listen / close / read / write / send* / recv* / __read_chk / __recv_chk / __recvfrom_chk / ioctl / epoll_* / fork`），经共享内存转发给 `ff_*` |
| `syscall/ff_linux_syscall.c` / `ff_declare_syscalls.h` | Linux 标志位 → FreeBSD 标志位转换（如 `LINUX_SOCK_CLOEXEC`、`LINUX_SOCK_NONBLOCK`）与 hook 声明 |
| `syscall/ff_socket_ops.h` / `.c` | 单 socket 操作上下文（`sc`）以及生产/消费派发逻辑 |
| `syscall/ff_sysproto.h` | 跨进程 syscall 参数结构定义 |
| `syscall/ff_so_zone.c` | Hugepage 共享内存 zone 管理（信号量 IPC 路径） |
| `syscall/ff_event.c` / `ff_epoll.c` | Epoll 适配（含 polling 模式）与事件投递 |
| `syscall/ff_ring_ops.c` / `.h` *(FF_USE_RING_IPC)* | Lock-free DPDK SPSC `rte_ring` IPC 路径，移除 `ff_so_zone` 全局锁 |
| `syscall/Makefile` | 同时编译 `libff_syscall.so` 与 `fstack` 实例二进制 |

LD_PRELOAD 模式下应用以 **两个独立进程** 运行：`fstack` 实例（链接 `libfstack.a` + DPDK）与预加载 `libff_syscall.so` 的用户应用。二者通过 Hugepage 共享内存通信——默认走信号量路径，置 `FF_USE_RING_IPC=1` 后切换为 lock-free DPDK SPSC ring 路径。编译/运行期开关 `FF_KERNEL_EVENT`、`FF_MULTI_SC`、`FF_USE_RING_IPC` 用于进一步调整行为；完整说明参见 `adapter/syscall/README.md` 与 `docs/ld_preload_ring_spec/`。

---

## 4. 依赖关系概览

```
                    ┌──────────────┐
                    │  应用层      │
                    │ (Nginx 1.28, │
                    │  Redis 6.2.6)│
                    └──────┬───────┘
                           │ ff_* API
                    ┌──────▼───────┐
                    │   lib/       │
                    │ F-Stack Core │
                    └──┬───────┬───┘
                       │       │
              ┌────────▼──┐ ┌──▼────────┐
              │  FreeBSD  │ │   DPDK    │
              │  15.0     │ │ 24.11.6   │
              │ TCP/IP 栈 │ │ (PMD/EAL) │
              └────────────┘ └──────────┘

  adapter/                    tools/
  LD_PRELOAD Hook ─────────►  ifconfig/netstat/arp/route
  (syscall 重定向)            (用户态网络工具)
```

### 关系类型

知识图谱中所有关系均为 `CodeRelation` 类型（当前索引共 113,858 条），涵盖：
- 函数调用（CALL）
- 类型引用（USES_TYPE）
- 宏展开（EXPANDS）
- 文件包含（INCLUDES）
- 结构体成员访问（HAS_MEMBER）
- 社区归属（BELONGS_TO）

---

## 5. 知识图谱使用指南

### 查询工具（经 GitNexus MCP 服务）

| 工具 | 用途 | 示例 |
|------|------|------|
| `gitnexus_query` | 按概念搜索执行流 | "packet receive" |
| `gitnexus_context` | 查看符号的 360° 关系 | `ff_init` 的所有调用者/被调用者 |
| `gitnexus_impact` | 修改前影响分析 | 改 `lib/ff_dpdk_if.c` 的影响半径 |
| `gitnexus_detect_changes` | 提交前变更范围检查 | 确认 staged 文件的影响 |
| `gitnexus_rename` | 安全重命名 | 多文件批量重命名 |
| `gitnexus_cypher` | 自定义图查询 | 高级分析 |

### 更新索引

```bash
# 须在仓库根目录执行
cd /data/workspace/f-stack

# 检查状态
npx gitnexus status

# 增量重索引
npx gitnexus analyze

# 强制完全重建
npx gitnexus analyze --force

# 重新生成可读 wiki（需要在 ~/.gitnexus/config.json 中配置 LLM API key）
npx gitnexus wiki --force
```

> **自动更新**：可在 `.git/hooks/post-commit` 中加入 `npx gitnexus analyze` 后台调用，每次 commit 后自动重新索引。

> **重建耗时**：当前 2,656 个文件的 F-Stack 自有源面，全量重建约 11 分钟（2026-06-08 实测）。

---

## 6. 参考资料

- **升级证据**：`docs/freebsd_13_to_15_upgrade_spec/` —— M0~M5、runtime-fix、Phase-5b、rib-fix 与双基线的完整 Markdown 记录。
- **三层架构（本知识库）**：`docs/zh_cn/01-LAYER1-ARCHITECTURE.md` + `docs/zh_cn/F-Stack_Architecture_Layer1_System_Overview.md`；Layer 2 / Layer 3 同名。
- **LD_PRELOAD Ring IPC 规约**：`docs/ld_preload_ring_spec/`。

---

*Generated from GitNexus knowledge graph (64,855 nodes, 113,858 edges) — 2026-06-08，commit `208b0c4`。Schema v1 / ladybugdb provider.*
