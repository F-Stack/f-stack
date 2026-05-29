# 02 — F-Stack 当前架构分析（对 FreeBSD 13.0 的改造点全景）

> English version: ../02-architecture-analysis.md

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-26）
> 数据来源：**Sub-Agent A（Analyzer-13）** 实测调研产物 + leader 后续整理
> 验证基线：13.0/f-stack-lib（25 freebsd + 22 tools 子目录）vs f-stack/freebsd + f-stack/tools

---

## 1. 改造手法总览

F-Stack 把 FreeBSD 协议栈"剥离到用户态 + DPDK 化"的过程中，对 13.0 上游做了 9 种通用改造手法：

| ID | 标签 | 含义 | 代表场景 |
|---|---|---|---|
| H-1 | `FSTACK-stub` | `#ifndef FSTACK` 包住函数体，短路到空实现 | `kern_event.c::kqueue_schedtask`、`uipc_socket.c::TASK_INIT(soaio_*)` |
| H-2 | `FSTACK-altimpl` | `#ifdef FSTACK ... #else` 走另一份实现 | `kern_descrip.c::fhold` 改 CAS 自检版、`uipc_syscalls.c::sendit/recvit` 改外部可见 |
| H-3 | `FSTACK-include` | 增/删头文件包含 | `sys/systm.h` 屏蔽 `<sys/kpilite.h>`、工具屏蔽 `<libifconfig.h>` |
| H-4 | `FSTACK-rss-ext` | 为 F-Stack 加 RSS / lport 扩展 | `in_pcb.c` 端口范围、lport 检查、ladddr 推导 |
| H-5 | `FSTACK-modname` | TCP 栈改 module name 防与上游冲突 | `tcp_stacks/rack.c`、`bbr.c` |
| H-6 | `IPC-replace` | 用户态工具用 `ff_ipc_*` 替换 raw socket / sysctl | `tools/ifconfig`、`tools/netstat`、`tools/ipfw` 等 12 个工具 |
| H-7 | `Makefile-fstack` | 工具 Makefile 接入 libffcompat / libdpdk / `-DFSTACK` / `-include compat.h` | 同上 12 个工具的 Makefile |
| H-8 | `header-glue` | 头文件加 F-Stack 宏 / 数据结构裁剪 | `sys/refcount.h::refcount_acquire_if_not_zero` 重写 |
| H-9 | `vhost-removal` | 删除 BPF / KVM / DTRACE / RACCT 等 host 路径 | `sys_socket.c::soo_fill_kinfo/soo_aio_queue/soo_sendfile` |

> **改造分布统计（实测）**：
> - `search_content "FSTACK"` 在 `f-stack/freebsd/` 命中 **48 个文件**
> - `search_content "#ifdef FSTACK"` 命中 **45 个文件**
> - 加上 size-diff 比对（同名但不同字节的 `_callout.h / callout.h / kern_tc.c / kern_uuid.c` 等），合计 **~50 个文件**有实质语义改造
> - 102 处文件差异中其余 ~50 处为 SKIP（元数据 / 行尾空白 / license 微改 / VPATH 编译产物）

---

## 2. sys/ 子目录改造点逐项分析

> 数据基线：`/data/workspace/freebsd-src-releng-13.0/f-stack-lib/freebsd/` vs `/data/workspace/f-stack/freebsd/`

### 2.1 `kern/`（内核公共子系统）—— 改造最重

| 文件 | 类型 | 标签 | 动机 |
|---|---|---|---|
| `kern_descrip.c` | MOD | H-2 | `fhold` / `refcount` fast-path 替换成 CAS 自检版（注释 "if loop dead in this function"）；屏蔽 `fdrop/closefp` 中的 RACCT/CAP_RIGHTS |
| `kern_event.c` | MOD | H-1 | `kqueue_schedtask` 整段 stub；knote 唤醒走直接 `KNOTE_UNLOCKED`（F-Stack 无 SWI 任务队列） |
| `kern_linker.c` | MOD | H-2 | `link_elf_load_file` 中 `vattr.va_size==0` 视为成功（fake VFS）；`elf_cpu_parse_dynamic` stub 返回 0 |
| `kern_mbuf.c` | MOD | H-1 / H-2 | `realmem` 不依赖 `vm_kmem_size`；屏蔽 `mb_unmapped_*` / `pcpu_page_alloc` / `mb_alloc_ext_pgs`（F-Stack 无 unmapped/extpg） |
| `kern_sysctl.c` | MOD | H-1 | 屏蔽 `__sysctl` 系统调用入口（走自家 sysctl_handle） |
| `link_elf.c` | MOD | H-1 | 同 kern_linker，stub `elf_cpu_parse_dynamic` |
| `subr_epoch.c` | MOD | H-1 | `taskqgroup_attach_cpu` 屏蔽（由 `ff_subr_epoch.c` 提供 stub） |
| `subr_param.c` | MOD | H-1 | `ticks = INT_MAX - hz*10*60` wrap 测试初值在 F-Stack 不需要 |
| `subr_taskqueue.c` | MOD | H-1 / H-2 | `_taskqueue_start_threads` 全 stub；t_barrier static 化绕 GCC dangling-pointer warning |
| `sys_generic.c` | MOD | H-1 | `kern_pselect` 中 `kern_sigprocmask` 段屏蔽（F-Stack 单进程不处理信号 mask） |
| `sys_socket.c` | MOD | H-1 / H-9 | 屏蔽 `soo_fill_kinfo / soo_aio_queue / soo_sendfile`（procfs/AIO 依赖） |
| `uipc_mbuf.c` | MOD | H-1 + 自家扩展 `FSTACK_ZC_SEND` | mbuf_ext_pgs 全屏蔽；**新增 zero-copy 路径**：`#ifdef FSTACK_ZC_SEND` 在 `m_uiotombuf` 中直接挂 iov_base 为 mbuf 数据指针 |
| `uipc_sockbuf.c` | MOD | H-1 / H-9 | `sb_aio` 唤醒、RLIMIT_SBSIZE 检查屏蔽 |
| `uipc_socket.c` | MOD | H-1 / H-9 | `TASK_INIT(soaio_*)` 屏蔽 |
| `uipc_syscalls.c` | MOD | H-2 | 把 `sendit`/`recvit` 的 `static` 去掉，改成外部可见，便于 `ff_syscall_wrapper.c` 直接调 |

**改造统计**：kern/ 实质改造 ~15 个文件；其余 KERN_SRCS 中 ~23 个文件未改造（F-Stack 直接编译 13.0 原文）。

### 2.2 `sys/`（公共头文件）

| 文件 | 类型 | 标签 | 动机 |
|---|---|---|---|
| `sys/systm.h` | MOD | H-1 + H-8 | 屏蔽 `<sys/kpilite.h>`；`critical_enter/exit` stub 成空操作（用户态无 td_critnest） |
| `sys/refcount.h` | MOD | H-2 | `refcount_acquire_if_not_zero` 用 CAS 自检版重写 |
| `sys/callout.h` | MOD | H-8 | F-Stack callout 子系统简化 |
| `sys/_callout.h` | MOD | H-8 | 配套 _callout 头 |

### 2.3 `netinet/`（IPv4 / TCP / UDP）

| 文件 | 类型 | 标签 | 动机 |
|---|---|---|---|
| `tcp_input.c` | MOD | H-2 / H-4 | inpcb hashlookup 加 RSS 端口范围；epoch_call 改 stub |
| `tcp_output.c` | MOD | H-2 | `tcp_default_output` 边界条件适配 |
| `tcp_subr.c` | MOD | H-1 / H-9 | 移除 BPF tap 相关；移除 IPSEC 紧耦合分支 |
| `tcp_var.h` | MOD | H-8 | 配套 tcpcb 字段微调 |
| `tcp_stacks/rack.c` | MOD | H-5 | module name 改 `tcp_rack_fstack` 防冲突 |
| `tcp_stacks/bbr.c` | MOD | H-5 | 同上 |
| `in_pcb.c` | MOD | H-4 | RSS 端口范围扩展、lport 检查、ladddr 推导 |

### 2.4 `net/`（链路层 / VNET / route）

| 文件 | 类型 | 标签 | 动机 |
|---|---|---|---|
| `if.c` | MOD | H-1 / H-9 | 屏蔽 `if_alloc` 走 host malloc 路径；走 F-Stack 自家内存池 |
| `if_var.h` | MOD | H-8 | ifnet 字段裁剪 |
| `if_ethersubr.c` | MOD | H-1 | 屏蔽 vlan/lagg 中 BPF tap |
| `netisr.c` | MOD | H-1 | netisr 主循环走 ff_veth 调度 |
| `route.c` | MOD | H-2 | rtinit 走 ff_route.c 桥接 |

### 2.5 `netgraph/` / `netinet6/` / 其他

| 子目录 | 实测改造数 | 主要手法 | 备注 |
|---|---|---|---|
| `netgraph/` | 1-2 个（`ng_socket.c`、`ng_socket.h` 微差） | H-2 | 主要走 IPC，让 ng socket 用户态可达 |
| `netinet6/` | 极少 | H-2 | IPv6 改动最少 |
| `netinet/libalias/` | 1 个（`alias_sctp.h`） | 头文件微差 | F-Stack 几乎不改 libalias |
| `netipsec/`、`opencrypto/`、`vm/`、`libkern/`、`crypto/` | 0 或 1-2 个 | — | 实质改造稀少 |
| `amd64/`、`arm64/`、`x86/` | 极少（多在头） | H-8 | 主要是头文件裁剪 |
| `contrib/` | 几乎不改 | — | F-Stack 走 `#include <contrib/ck/...>` 调用 ck 即可 |

### 2.6 `mips/`

F-Stack 工程中保留了 mips 子目录（来自 13.0 拷贝），但 **F-Stack 实际只在 amd64/x86_64 + arm64 上跑**，mips/ 是死代码。15.0 已移除整个 mips 架构 → 本次升级 **FR-4** 要求清理。

---

## 3. tools/ 子目录改造点逐项分析

> 数据基线：`/data/workspace/freebsd-src-releng-13.0/f-stack-lib/tools/` vs `/data/workspace/f-stack/tools/`
> 总差异 **163 处**；主要分布如下。

### 3.1 12 个 freebsd 原生工具的 F-Stack 化模式（H-6 + H-7）

| 工具 | 改造主线 |
|---|---|
| `arp/` | raw socket 改 ff_ipc 命令通道 |
| `ifconfig/` | sysctl + raw socket 改 ff_ipc；屏蔽 libifconfig 依赖 |
| `ipfw/` | raw socket 改 ff_ipc |
| `libmemstat/` | sysctl 改 ff_ipc |
| `libnetgraph/` | NgSendMsg/NgRecvMsg 改 ff_ipc 桥接 |
| `libutil/` | 极少改动（基础 lib） |
| `libxo/` | 0 或极少（基础 lib） |
| `ndp/` | raw socket 改 ff_ipc |
| `netstat/` | sysctl 改 ff_ipc，最大改动量集中地 |
| `ngctl/` | NgSendMsg 改 ff_ipc |
| `route/` | RTM_* 改 ff_ipc |
| `sysctl/` | __sysctl syscall 改 ff_ipc 命令通道 |

**通用手法**：
- 工具 main 入口前置 `ff_ipc_init()`
- 所有 `socket(PF_ROUTE, ...)` / `sysctl()` / `NgSendMsg()` 调用替换成对应的 `ff_ipc_*` 函数
- Makefile 加 `-DFSTACK -include compat.h`，链接 libffcompat 与 libdpdk

### 3.2 f-stack-lib 自带辅助目录（compat / sbin）

| 目录 | 内容 | 角色 |
|---|---|---|
| `tools/compat/` | 199 文件，含 `ff_ipc.c` / `ff_ipc.h` / `compat.h` 等 | **F-Stack 自家 IPC 桥**，所有 12 个工具都 -include 它 |
| `tools/sbin/` | 空目录 | 占位，无实际内容 |

### 3.3 f-stack 自带工具（不来源于 freebsd-src）

| 工具 | 角色 |
|---|---|
| `tools/knictl/` | KNI（内核网络接口）控制工具，F-Stack 自实现 |
| `tools/traffic/` | 流量统计工具 |
| `tools/top/` | F-Stack 版 top（非 freebsd 原生 top） |

> 这三个工具**不**走 freebsd-src 升级路径，本次只做 Phase 1.4 的占位拷贝；自身演进归 M5 里程碑。

### 3.4 辅助构建文件

`lib.mk / Makefile / opts.mk / prog.mk / README.md` 是 f-stack-lib 自己组织的构建索引，不来源于 freebsd-src。

---

## 4. f-stack/lib/ff_*.c & ff_*.h 胶水文件全景

> 数据基线：`f-stack/lib/Makefile` 的 `FF_SRCS+=` 与 `FF_HOST_SRCS+=` 实测；共 **30 个 .c + 14 个 .h**。

### 4.1 FF_SRCS（链接进 kernel 部分，21 个 .c）

| 文件 | 功能 | 引用的关键 freebsd kernel 头 / 符号 |
|---|---|---|
| `ff_compat.c` | 通用 compat shim | `<sys/types.h>`, `<sys/systm.h>` |
| `ff_glue.c` | 协议栈 glue（与 `protosw` / socket 交互） | `<sys/protosw.h>`, `<sys/socket.h>`, `pr_usrreqs` |
| `ff_freebsd_init.c` | freebsd 子系统初始化序列 | `SYSINIT(*)`, `sysent[]` |
| `ff_init_main.c` | 主入口 | `proc0`, `mi_startup()` |
| `ff_kern_condvar.c` | condvar wrapper（pthread → cv） | `<sys/condvar.h>::cv_*` |
| `ff_kern_environment.c` | kenv | `<sys/kenv.h>::kern_setenv` |
| `ff_kern_intr.c` | intr wrapper | `<sys/interrupt.h>::ithd_create` |
| `ff_kern_subr.c` | misc subr | `<sys/subr_*>` |
| `ff_kern_synch.c` | sleep/wakeup wrapper | `<sys/proc.h>::pause/tsleep` |
| `ff_kern_timeout.c` | callout wrapper | `<sys/callout.h>::callout_*` |
| `ff_subr_epoch.c` | epoch stub | `<sys/epoch.h>::epoch_*` |
| `ff_lock.c` | mtx/rmlock wrapper | `<sys/lock.h>`, `<sys/mutex.h>` |
| `ff_syscall_wrapper.c` | **关键**：把 send/recv/accept/connect/bind 等 syscall 暴露给用户态 | `kern_pselect`, **`sendit`/`recvit`**, `kern_accept` |
| `ff_subr_prf.c` | printf 桥 | `<sys/systm.h>::printf` |
| `ff_vfs_ops.c` | VFS stub | `<sys/vnode.h>`（fake VFS） |
| `ff_veth.c` | 虚拟 ethernet → DPDK 桥 | `<net/if.h>::if_alloc`/**`if_t`**, `<net/if_var.h>` |
| `ff_route.c` | 路由桥 | `<net/route.h>::rtinit`/**`rib`/`nexthop`** |
| `ff_ng_base.c` | NETGRAPH base | `<netgraph/ng_*.h>` |
| `ff_ngctl.c` | NETGRAPH 控制 | 同上 |
| （还有 2 个隐式） | — | — |

### 4.2 FF_HOST_SRCS（user-space 侧，9 个 .c）

| 文件 | 功能 |
|---|---|
| `ff_host_interface.c` | host 接口（lcore / mempool 等） |
| `ff_thread.c` | F-Stack 线程模型 |
| `ff_config.c` | 配置加载 |
| `ff_ini_parser.c` | ini 解析 |
| `ff_dpdk_if.c` | DPDK 网卡接口 |
| `ff_dpdk_pcap.c` | DPDK pcap 抓包 |
| `ff_epoll.c` | epoll 兼容（用户态） |
| `ff_log.c` | 日志 |
| `ff_init.c` | host 端初始化 |
| `ff_dpdk_kni.c`、`ff_memory.c`（条件） | KNI 桥、自家 mempool |

### 4.3 ff_*.h（14 个）

`ff_api.h / ff_config.h / ff_dpdk_if.h / ff_dpdk_kni.h / ff_dpdk_pcap.h / ff_epoll.h / ff_errno.h / ff_event.h / ff_host_interface.h / ff_ini_parser.h / ff_log.h / ff_memory.h / ff_msg.h / ff_veth.h`

### 4.4 ff_* 与 freebsd-src 的接口依赖矩阵（升级关键点）

下表是 ff_*.c 中每个文件**最受 13→15 接口变更影响**的部分（决定 FR-3 的工作量）：

| ff_*.c | 受 15.0 哪个 P0 变更影响 | 影响等级 |
|---|---|---|
| `ff_glue.c` | **`pr_usrreqs` 合并入 `protosw`** | **P0** |
| `ff_syscall_wrapper.c` | `sendit`/`recvit` 在 15.0 中签名稳定，但 `kern_pselect` 内部接口可能变 | P1 |
| `ff_veth.c` | **`if_t` 不透明化** + `if_alloc()` 签名变 | **P0** |
| `ff_route.c` | **rib / nexthop 新表结构** | **P0** |
| `ff_subr_epoch.c` | epoch → SMR 部分场景，需评估 stub 是否还能编 | P1 |
| `ff_kern_intr.c` | ithd_create 签名稳定，但 intr 子系统在 14/15 有微调 | P1 |
| `ff_kern_timeout.c` | callout 子系统稳定 | P2 |
| 其他 ff_*.c | 多为 stub 性质，跨版本接口稳定 | P2-P3 |

---

## 5. 与 F-Stack 既有架构文档的对照

| 既有文档 | 本节复用 | 增量 |
|---|---|---|
| `docs/01-LAYER1-ARCHITECTURE.md` | 复用 freebsd/ tools/ lib/ 三层划分 | 补充每个文件的改造标签 |
| `docs/F-Stack_Architecture_Layer1_System_Overview.md` | 复用 sys 子目录划分 | 补充 102 处差异的实测分类 |
| `docs/F-Stack_Architecture_Layer2_Interface_Specification.md` | 复用 ff_*.c 的接口清单 | 补充对 freebsd kernel 的依赖矩阵 |
| `docs/KNOWLEDGE_GRAPH_WIKI.md` | 复用依赖关系图 | 补充 ff_glue/ff_veth/ff_route 与 15.0 P0 变更点的连线 |

---

## 6. 本节关键产物（用于 04 移植策略）

| 产物 | 用途 |
|---|---|
| 9 大改造手法表（§1） | 04 中"按手法分组"的 port 任务 |
| sys/ 50 个实质改造文件清单（§2） | 04 中"按文件分组"的 port 任务 |
| tools/ 163 处差异分类（§3） | 04 中 tools 升级清单 |
| ff_* 44 个胶水 + 接口依赖矩阵（§4） | 04 中 FR-3 的具体子任务 |

> 下一步：`03-freebsd-15-changes.md` 列出 13→14→15 的全量上游变更；然后 `04-diff-and-port-strategy.md` 把本节 + 03 节交叉，产出最终的 port 任务清单。
