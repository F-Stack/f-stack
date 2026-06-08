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
├── dpdk/           # DPDK 23.11.5 子模块（已从 gitnexus 索引排除）
└── freebsd/        # FreeBSD 15.0 内核源码移植（已从 gitnexus 索引排除）
```

### 3.1 核心库文件 (`lib/`)

`lib/` 下 33 个 `.c` 文件（已经直接 read 验证）按职责分为 6 类。下表给出代表性 anchor；完整清单与逐文件行数见 `docs/zh_cn/F-Stack_Architecture_Layer3_Function_Index.md` §"lib/ 文件索引" 与 `docs/freebsd_13_to_15_upgrade_spec/docs-sync-2026-06-08-update-matrix.md` §1.2。

| 职责 | 代表文件 |
|------|----------|
| 公开 API 与初始化 | `ff_api.h`、`ff_init.c`（70 行）、`ff_init_main.c`（~660+ 行）、`ff_freebsd_init.c`（~154 行） |
| 配置 | `ff_config.c`（1,381 行）、`ff_ini_parser.c`（第三方 inih） |
| DPDK 适配 | `ff_dpdk_if.c`（2,856 行；`main_loop` 在此）、`ff_dpdk_kni.c`（~441 行）、`ff_dpdk_pcap.c`（~118 行） |
| Linux→FreeBSD 胶水 | `ff_glue.c`（1,468 行）、`ff_syscall_wrapper.c`（1,815 行）、`ff_host_interface.c`（~285 行）、`ff_epoll.c`（~134 行）、`ff_compat.c`（~360 行） |
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
              │  15.0     │ │  23.11.5  │
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
