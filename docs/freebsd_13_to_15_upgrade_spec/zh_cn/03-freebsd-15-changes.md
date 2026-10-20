# 03 — FreeBSD 13.0 → 14.x → 15.0 关键变更清单

> English version: ../03-freebsd-15-changes.md

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-26）
> 数据来源：**Sub-Agent B（Analyzer-15）** 调研产物 + 本地双版本源码实测对比
> 校验：所有 P0/P1 结论均可在本地 `/data/workspace/freebsd-src-releng-{13.0,15.0}/sys/` 源码中复核

---

## 0. 一句话结论

FreeBSD 13.0 → 15.0 跨越了 4 年 + 6 个 release（13.0 → 14.0 → 14.1 → 14.2 → 14.3 → 14.4 → 15.0），其中**网络栈核心 KBI/KPI 多处不兼容**。F-Stack 的 `freebsd/` 子树 **不能简单 patch** 升级，必须基于 15.0 `sys/` 重做"裁剪 + 改造"基线（对应 `02-architecture-analysis.md` 的 9 大改造手法在 15.0 基线上重新应用）。

### 0.1 优先级两维度约定（2026-05-28 增补；响应审计 §6.2-1）

本系列 spec 中所有 `P0` / `P1` / `P2` / `P3` 标签**分两个独立维度**使用，读者在交叉文档时应明确所引用的是哪一维：

| 维度 | 含义 | 决定因素 |
|---|---|---|
| **风险等级**（risk level） | 该上游变化对 F-Stack 的破坏严重度 | KBI/KPI 是否破坏；范围与可恢复性；是 fact 维 |
| **任务优先级**（task priority） | 该任务在实施进度中的迫切度 | 是否阻塞其它里程碑；是否必修（mandatory cleanup）；是 schedule 维 |

二者**可独立**——典型对照：

- **mips 移除（R-001）**：风险等级 = P2（上游事实，与 F-Stack 不强相关）；任务优先级 = **P0**（必须在 M1 清理掉 `f-stack/freebsd/mips/` 才能继续推进，否则 build 链断）
- **netlink 引入（R-002）**：风险等级 = P1（15.0 新增重要子系统）；任务优先级 = P3（DP-2 决策"不引入"，本次升级不触碰）
- **多数 P0 风险与 P0 任务一致**：`pr_usrreqs` 合并 / inpcb SMR / `if_t` / mbuf / routing 重写等

为避免歧义，本文档 §2/§3 各小节的 heading 中括号 `[Pn]` **统一表示任务优先级**；`§4.1`、`§7` 等"风险表"中的"优先级"列**统一表示风险等级**；不一致处会在表内显式分两列（参见 §3.7 / §3.8）。`plan.md §4.1` 已按本约定改为两列。

---

## 1. 版本号事实

| 项目 | 13.0 | 15.0 |
|---|---|---|
| `REVISION` | 13.0 | 15.0 |
| `BRANCH` | RELEASE-p2 | RELEASE-p9 |
| `__FreeBSD_version` | **1300139** | **1500068** |
| 实测路径 | `sys/sys/param.h:63` | `sys/sys/param.h:77` |
| 最大 syscall 号 | `SYS_aio_readv=579` | `SYS_jail_remove_jd=598` |
| `SYS_MAXSYSCALL` | 580 | 599 |

---

## 2. 架构级变更（影响整体编译边界）

### 2.1 [P0] mips 架构整体移除

| 维度 | 内容 |
|---|---|
| **事实** | 14.0 移除；本地 `freebsd-src-releng-15.0/sys/` 中无 `mips/` 子目录 |
| **来源** | FreeBSD 14.0R Release Notes —— "Removal of the mips architecture from the tree as Tier 2 platform" |
| **对 F-Stack 影响** | `f-stack/freebsd/mips/`（来自 13.0 拷贝）必须删除；所有 Makefile / mk 中 mips-条件分支需清理 |
| **动作** | FR-4 / DP-1 → 删除 |
| **优先级** | **任务优先级 P0**（不删除会引入大量编译错误，M1 必修）；**风险等级 P2**（上游事实，与 F-Stack 业务能力无关）。详见 `§0.1` 两维度约定与 `plan.md §4.1` R-001。 |

### 2.2 [P1] clang/llvm 工具链版本要求

| 维度 | 内容 |
|---|---|
| **事实** | 13.0R 默认 clang/lld 11.0.1，要求 GCC ≥ 6；14.0R clang 16，要求 GCC ≥ 9；15.0R clang/llvm 19.x |
| **对 F-Stack 影响** | F-Stack 头文件用 GCC 扩展（`__attribute__((packed))` 等向后兼容）；但 15.0 内核大量使用 C11 `_Atomic(T)` / `atomic_load_explicit`，宿主编译器需 ≥ clang 11 / GCC 9 |
| **动作** | 在 `05-implementation-plan.md` §前置中固化 |
| **优先级** | P1 |

### 2.3 [P3] pkgbase / EXPERIMENTAL knob

| 维度 | 内容 |
|---|---|
| **事实** | 14.0R/15.0R 引入 pkgbase 作为可选发布形态；15.0 默认仍为 installworld + installkernel |
| **对 F-Stack 影响** | 无影响（F-Stack 不依赖 base 安装） |
| **优先级** | P3（out of scope） |

### 2.4 [P3] 13→15 syscall 表增量（实测）

13.0 `SYS_MAXSYSCALL=580`（共 420 个 `SYS_*` 名称），15.0 `SYS_MAXSYSCALL=599`（共 439 个）。**13→15 净新增 22 项，删除 3 项**（按 `SYS_*` 名称集求差实测）。

#### 2.4.1 13→15 新增 22 项（按 15.0 编号）

| 项目 | 15.0 syscall 号 | 类型 | 优先级 | 备注 |
|---|---:|---|---|---|
| `fspacectl` | 580 | 新功能 | P3 | 文件空洞分配 |
| `sched_getcpu` | 581 | 新功能 | P3 | — |
| `freebsd13_swapoff` | （compat） | compat shim | P3 | 13.0 中 `swapoff=424`，15.0 重排为 582 并保留旧号兼容入口 |
| `kqueuex` | 583 | 新功能 | P3 | kqueue 扩展 |
| `membarrier` | 584 | 新功能 | P3 | — |
| `timerfd_create` | 585 | 新功能 | P3 | Linux 兼容 |
| `timerfd_gettime` | 586 | 新功能 | P3 | Linux 兼容 |
| `timerfd_settime` | 587 | 新功能 | P3 | Linux 兼容 |
| `kcmp` | 588 | 新功能 | P3 | — |
| `getrlimitusage` | 589 | 新功能 | P3 | — |
| `fchroot` | 590 | 新功能 | P3 | — |
| `setcred` | 591 | 新功能 | P3 | — |
| `exterrctl` | 592 | 新功能 | P3 | — |
| **`inotify_add_watch_at`** | 593 | 新功能 | P3 (OOS) | 约束 C-1 不引入 |
| **`inotify_rm_watch`** | 594 | 新功能 | P3 (OOS) | 约束 C-1 不引入 |
| `freebsd14_getgroups` | （compat） | compat shim | P3 | 13.0 中 `getgroups=79`，15.0 重排为 595 并保留旧号兼容入口 |
| `freebsd14_setgroups` | （compat） | compat shim | P3 | 13.0 中 `setgroups=80`，15.0 重排为 596 并保留旧号兼容入口 |
| `jail_attach_jd` | 597 | 新功能 | P3 | — |
| `jail_remove_jd` | 598 | 新功能 | P3 | — |
| `_exit` | （compat） | compat shim | P3 | 旧编号 1 的兼容别名 |
| `freebsd10__umtx_lock` | （compat） | compat shim | P3 | freebsd10 兼容 |
| `freebsd10__umtx_unlock` | （compat） | compat shim | P3 | freebsd10 兼容 |

#### 2.4.2 13→15 删除 3 项

| 项目 | 13.0 syscall 号 | 删除原因 | 优先级 |
|---|---:|---|---|
| `gssd_syscall` | 505 | gssd 用户态 daemon 接口废弃 | P3 |
| `sbrk` | 69 | brk/sbrk 用户态接口在 14.0 移除 syscall 实现（仅保留 libc 模拟） | P3 |
| `sstk` | 70 | 与 `sbrk` 同期废除 | P3 |

#### 2.4.3 13.0 中已存在的 syscall（**不属 13→15 新增**）

以下 syscall 在 13.0 `sys/sys/syscall.h` 已经定义，**只是文档此前误列为 15.0 新增**：`SYS___realpathat=574`、`SYS_close_range=575`、`SYS_rpctls_syscall=576`、`SYS___specialfd=577`、`SYS_aio_writev=578`、`SYS_aio_readv=579`。

> **实测来源**：`grep '^#define[[:space:]]\+SYS_' /data/workspace/freebsd-src-releng-{13.0,15.0}/sys/sys/syscall.h | awk '{print $2}' | sort | comm`（2026-05-28 实测）。
>
> F-Stack 不走 host syscall 层（用户态自家分发），上述对 F-Stack 无直接影响。仅当 `ff_syscall_wrapper.c` 需要暴露这些时才动手。本次升级不引入新 syscall（约束 C-1）。

### 2.5 [P2] syscall 表扩展整体影响

虽然单 syscall out-of-scope，但 `init_sysent.c` 体系变化会影响 F-Stack 静态链接整体大小与编译。**P2**：监控编译告警即可。

---

## 3. 协议栈级变更（核心战场）

### 3.1 [P0 ★] `pr_usrreqs` 整体废除合并入 `protosw`

| 维度 | 内容 |
|---|---|
| **事实** | 13.0：`struct protosw` 含 `struct pr_usrreqs *pr_usrreqs;` 字段，protocol 用户请求向量通过此结构暴露。15.0：`pr_usrreqs` 整体取消，所有方法直接合并入 `protosw` 顶层字段（`pru_*` 系列直接挂在 `struct protosw`） |
| **影响文件** | 所有 protocol 注册点（tcp_usrreq.c / udp_usrreq.c / raw_ip.c 等）+ 所有调用 `pr->pr_usrreqs->pru_*()` 的位置 |
| **对 F-Stack 影响** | `ff_glue.c` + `kern_event.c` + `uipc_socket.c` 中所有 `pru_*` 函数指针引用都要改写 |
| **风险 ID** | R-011 |
| **优先级** | **P0**（编译破坏） |

### 3.2 [P0 ★] `struct inpcb` 从 epoch 转 SMR

| 维度 | 内容 |
|---|---|
| **事实** | 13.0：`inpcb` hash lookup 走 NET_EPOCH 保护。15.0：改用 SMR（Safe Memory Reclamation），`inpcbgroup` 哈希重写 |
| **影响文件** | `in_pcb.c` / `in_pcb.h` / `tcp_input.c` / `udp_usrreq.c` / `raw_ip.c` |
| **对 F-Stack 影响** | F-Stack 现状把 epoch 用 `ff_subr_epoch.c` stub 成空（FSTACK-stub）；SMR 出现后需评估：是 stub 化（更简单）还是引入新 SMR wrapper |
| **风险 ID** | R-012 |
| **优先级** | **P0** |

### 3.3 [P0 ★] `struct ifnet` 不透明化为 `if_t`

| 维度 | 内容 |
|---|---|
| **事实** | 13.0：`sys/net/if_var.h:127` 已有 `typedef struct ifnet * if_t;`，但内核 API 仍以 `struct ifnet *` 出现（如 `if_alloc()` 返回 `struct ifnet *`），驱动/桥接代码普遍直接访问字段（`ifp->if_flags`、`ifp->if_xname` 等）。15.0：将该 typedef 上提到 `sys/net/if.h:667`（`typedef struct ifnet *if_t;`），并把 `if_alloc()` 等内核 API 签名统一改用 `if_t`；同时配套提供大量 `if_getflags(ifp)`、`if_name(ifp)`、`if_setname(ifp, ...)` 等访问函数（`sys/net/if_var.h`）。**底层类型并未变成 `void *`，"不透明化"指的是 API 契约：外部代码应通过 `if_get*/if_set*` 访问函数操作 `if_t`，不应直接依赖 `struct ifnet` 字段布局**。 |
| **影响文件** | `net/if.c` / `if_var.h` / 所有驱动 / `ff_veth.c` |
| **对 F-Stack 影响** | `ff_veth.c` 是 F-Stack 自家的 DPDK 桥，必须改用 `if_t` 访问函数；F-Stack `freebsd/net/if.c` 改造点需重新评估（H-1 / H-9 标签的 stub 是否还成立） |
| **风险 ID** | R-013 |
| **优先级** | **P0** |

### 3.4 [P0] mbuf 字段调整（13→14→15）

| 维度 | 内容 |
|---|---|
| **事实** | 14.0 调整 `m_pkthdr`（加 `numa_domain` 等）；15.0 进一步调整 `m_ext`（refcnt / ext_type / ext_free 重组） |
| **影响文件** | `uipc_mbuf.c` / `kern_mbuf.c` / `mbuf.h` / 所有 `m_*` 操作宏 |
| **对 F-Stack 影响** | F-Stack 在 `uipc_mbuf.c` 中已有 `FSTACK-stub` + `FSTACK_ZC_SEND` 改造，需基于 15.0 新字段重新落地；`FSTACK_ZC_SEND` 路径中 `m_uiotombuf` 的 iov_base 挂载要适配新 `m_ext` 布局 |
| **风险 ID** | R-003 |
| **优先级** | **P0** |

### 3.5 [P1] netlink 子系统（15.0 新增）

| 维度 | 内容 |
|---|---|
| **事实** | 14.0 引入 `sys/netlink/` 子目录（10 个 .c：netlink_domain.c / netlink_io.c / netlink_message_parser.c / netlink_message_writer.c / netlink_module.c / netlink_route.c 等），Linux netlink 兼容层 |
| **对 F-Stack 影响** | 本次约束 C-1 决定 **不引入**（DP-2），但需在 spec 中显式记录 |
| **次生影响** | 15.0 中 `route.c` / `if.c` 的内部 API 与 netlink 紧耦合，删除 netlink 后部分 #include 与符号引用需 stub 化 |
| **风险 ID** | R-002 |
| **优先级** | P1（DP-2 暂不引入，但实施时仍需处理依赖切断） |

### 3.6 [P1] TCP RACK 默认化

| 维度 | 内容 |
|---|---|
| **事实** | 14.0 起 `tcp_stacks/rack` 进入 base；15.0 默认 TCP 栈仍是 freebsd default，但 RACK 已经更成熟，符号、统计、`sysctl` knob 大量增加 |
| **影响文件** | `tcp_stacks/rack.c` + 配套 `rack_bbr_common.c` |
| **对 F-Stack 影响** | F-Stack 现有 `tcp_stacks/rack.c` 改了 module name（H-5），需在 15.0 新基线上重新应用此改名 |
| **风险 ID** | R-004 |
| **优先级** | P1 |

### 3.7 [P2] kernel TLS API 变化

| 维度 | 内容 |
|---|---|
| **事实** | 14.0 引入 KTLS 完整 API；15.0 进一步重构 |
| **对 F-Stack 影响** | F-Stack 当前未启用 KTLS，无直接破坏；但 `sys_socket.c` / `uipc_socket.c` 中含 KTLS 相关 #ifdef 分支，stub 化策略需评估 |
| **风险 ID** | R-006 |
| **优先级** | **任务优先级 P2 / 风险等级 P2**（详见 `§0.1` 两维度约定） |

### 3.8 [P0] routing 表结构变更（rib / nexthop）

| 维度 | 内容 |
|---|---|
| **事实** | 14.0 把 routing 表从老 `rtentry` 重构为 `rib` + `nexthop`；15.0 稳定到新结构 |
| **影响文件** | `net/route.c` / `net/route.h` / `net/route_var.h` / 所有 `rtinit / rtalloc` 调用点 |
| **对 F-Stack 影响** | `ff_route.c` 必须重写为 rib/nexthop API |
| **优先级** | **任务优先级 P0 / 风险等级 P0**（与 R-013 并列，KPI 破坏；详见 `§0.1` 两维度约定） |

### 3.9 [P1] VNET API 演进

| 维度 | 内容 |
|---|---|
| **事实** | VNET 在 14.0 / 15.0 多次内部重构（vnet_data_*、CURVNET_SET 优化） |
| **对 F-Stack 影响** | F-Stack 不开 VNET（单实例），但所有引用 `VNET(*)` 的源文件随上游升级 |
| **优先级** | P2 |

### 3.10 [P1] epoch / rmlock 同步原语调整

| 维度 | 内容 |
|---|---|
| **事实** | 14.0 多个 NET_EPOCH 场景替换为 SMR / rmlock；epoch_call 函数语义在 15.0 微调 |
| **对 F-Stack 影响** | `ff_subr_epoch.c` 的 stub 需要重新评估覆盖面 |
| **优先级** | P1 |

### 3.11 [P2] wifi 栈 / pf / dummynet / netgraph 改动

| 子项 | 优先级 | F-Stack 影响 |
|---|---|---|
| wifi 栈重构 | P3 | F-Stack 不用 wifi |
| pf 升级（13.x → 15.x） | P2 | F-Stack 不直接用 pf |
| dummynet | P3 | F-Stack 不直接用 |
| netgraph | P1 | `ng_socket.c` 改动小，F-Stack 已有 H-2 改造 |

---

## 4. ABI / KPI / KBI 变更（影响用户态 libff）

### 4.1 关键 struct 布局变化（全部不兼容）

| struct | 13→15 变化 | 优先级 |
|---|---|---|
| `struct protosw` | 合并 `pr_usrreqs` 进顶层 | **P0** |
| `struct inpcb` | epoch → SMR；字段重排 | **P0** |
| `struct tcpcb` | RACK 相关字段增 | **P0** |
| `struct sockbuf` | KTLS / mbuf 字段增 | **P0** |
| `struct ifnet` → `if_t` | 不透明化 | **P0** |
| `struct mbuf::m_pkthdr` | 加 numa_domain 等 | **P0** |
| `struct mbuf::m_ext` | 字段重组 | **P0** |
| `struct rtentry` → `rib`+`nexthop` | 整表重写 | **P0** |

### 4.2 用户态 libc 接口

仅 `libc` 中 F-Stack 引用部分相关；本次升级 F-Stack 不切换 libc，故 P3。

### 4.3 ABI break 总体

13→15 跨 2 个主版本，按 FreeBSD 政策 ABI 不保证向后兼容。F-Stack 用户态 libff 的 ABI 需重新审视，特别是：
- `struct ff_ev`（在 `ff_event.h`）
- `ff_msg`（在 `ff_msg.h`，IPC 命令通道）
- `ff_veth_softc`（在 `ff_veth.h`）

→ `01-requirements-spec.md` 的 R-007。

---

## 5. 构建级变更

### 5.1 src.conf / src.opts.mk 的 KNOB 增减

13→15 增减约 60 个 KNOB（如 `WITHOUT_GOOGLETEST` → `WITH_GOOGLETEST`，新增 `WITH_LLVM_AWK` 等）。F-Stack 不使用 freebsd base 构建系统，影响 P3。

### 5.2 Makefile.inc 体系演进

`bsd.prog.mk / bsd.lib.mk` 在 15.0 有微调，新增 PIE 支持等。F-Stack 工具构建走自家 Makefile，需确认 `include` 路径是否包含 `<bsd.prog.mk>` —— 实测 F-Stack 工具 Makefile 用 `lib.mk / prog.mk`（在 `f-stack-lib/tools/`），与 base 解耦，**P3**。

### 5.3 CTF / DTrace 等可选项

F-Stack 不启用，P3。

---

## 6. crypto/ 子目录变更

| 项 | 13.0 | 15.0 | 优先级 |
|---|---|---|---|
| `chacha20_poly1305.c/.h` | 不存在 | 新增 | P2（F-Stack 不直接用） |
| `curve25519.c/.h` | 不存在 | 新增 | P3 |
| `blowfish/` | 存在 | **删除** | P3 |
| `sha1.c` 内容微调 | 8.64 KB | 8.6 KB | P3 |

---

## 7. 升级风险全景表（按优先级排序）

| ID | 风险 | 优先级 | 来源 | 处置 |
|---|---|---|---|---|
| **R-011** | `pr_usrreqs` 合并入 `protosw` | **P0** | §3.1 | 重写 `ff_glue.c` 等所有 pru_* 引用 |
| **R-012** | `inpcb` epoch → SMR | **P0** | §3.2 | 评估 stub vs 重写 `ff_subr_epoch.c` |
| **R-013** | `ifnet` → `if_t` 不透明化 | **P0** | §3.3 | 重写 `ff_veth.c` |
| R-003 | mbuf 字段调整 | **P0** | §3.4 | 适配 `m_pkthdr`/`m_ext` 新布局 |
| **新** | rib/nexthop 路由表重写 | **P0** | §3.8 | 重写 `ff_route.c` |
| R-001 / FR-4 | mips 整体移除 | **P0** | §2.1 | 删除 `f-stack/freebsd/mips/` |
| R-002 | netlink 新增 | P1 (DP-2) | §3.5 | 不引入；切断依赖 |
| R-004 | RACK 默认化 / tcp_stacks 改动 | P1 | §3.6 | 重新应用 H-5 改名 |
| R-007 | ABI break | P1 | §4 | 用户态 libff ABI 审视 |
| R-009 | clang/llvm 14→15 提升 | P1 | §2.2 | 编译环境前置 |
| R-006 | KTLS / wlan API 变化 | P2 | §3.7 | stub 化策略评估 |
| R-008 | f-stack-lib 与 f-stack 漂移 | P2 | §1.4 of 01 | diff -rq 实测清理 SKIP 噪声 |
| R-005 | pkgbase | P3 | §2.3 | 信息留档 |
| R-010 | inotify / 抗量子加密 | P3 (OOS) | §2.4 | 信息留档 |

> P0 共 **6 项**；P1 共 4 项；P2 共 3 项；P3 共 2 项。这是 04 / 05 排里程碑的依据。

---

## 8. 14.0 → 14.4 中间版本里程碑事件（选录）

| 版本 | 时间 | 关键事件 |
|---|---|---|
| 14.0R | 2023-11 | mips 移除；clang 16；KTLS 完整；rib/nexthop 稳定；netlink 引入；RACK 进 base |
| 14.1R | 2024-05 | OpenSSH 9.7；ZFS 2.2.4 |
| 14.2R | 2024-12 | ZFS 2.2.6；vnet 路由微调 |
| 14.3R | 2025-06 | clang 18；netlink 强化 |
| 14.4R | 2025-12 | 进入 ESR；最后一个 14.x |
| 15.0R | 2025 末 | clang/llvm 19；pr_usrreqs 合并；inpcb SMR；if_t 不透明化；mbuf m_ext 字段重组；syscall 表扩到 599 |
| 15.1R | 2026 上半年 | 后续维护 |

---

## 9. 与本系列其他文档的衔接

| 本节产物 | 衔接对象 |
|---|---|
| 6 项 P0 风险（§7） | `04-diff-and-port-strategy.md` 的"必修任务" |
| 改造文件矩阵（§3） | `04-diff-and-port-strategy.md` 的"按 P0 风险定位文件" |
| ABI break（§4.3） | `01-requirements-spec.md` FR-3 + R-007 |
| 升级里程碑（§8） | `05-implementation-plan.md` 引用作为 baseline 时间线参考 |

> 下一步：`04-diff-and-port-strategy.md` 把本节风险与 02 改造点交叉，产出最终 port 任务清单。

## 10. 外部资料引用与待核验清单（2026-05-28 增补）

> 本节响应独立审计 §P1-005：本文档大量引用上游事实（mips 移除、clang/llvm 19、pkgbase、`pr_usrreqs` 合并、inpcb SMR、`if_t` 不透明化、netlink、RACK 默认化、KTLS、routing/rib/nexthop、14.4/15.1 时间线等），但在 v0.1 中没有逐条给出 URL / 引文片段 / 抓取日期。本节按"§10.1 本地权威源（可立即复核）"与"§10.2 外部 URL 待核验清单"两类，把每条事实的来源补上；§10.3 给出"待核验"条目的转正条件。
> 全部引文均为 2026-05-28 实测；本地路径均位于 `/data/workspace/freebsd-src-releng-15.0/`（除非另注）。

### 10.1 本地权威源（可立即复核）

下表中每条引文的形式为「文件路径 + 行号 + 简短引文」，读者可直接 `sed -n '<line>p' <path>` 复核。

| 03 章节 | 事实 | 本地权威源（路径:行号 + 引文） |
|---|---|---|
| §1 / §2.1 | 13.0 = `RELEASE-p2`，15.0 = `RELEASE-p9` | `freebsd-src-releng-13.0/sys/conf/newvers.sh`：`REVISION="13.0" / BRANCH="RELEASE-p2"`；`freebsd-src-releng-15.0/sys/conf/newvers.sh`：`REVISION="15.0" / BRANCH="RELEASE-p9"` |
| §1 / §6 | `__FreeBSD_version`：13.0=`1300139`，15.0=`1500068` | `freebsd-src-releng-13.0/sys/sys/param.h`：`#define __FreeBSD_version 1300139`；`freebsd-src-releng-15.0/sys/sys/param.h:#define __FreeBSD_version 1500068` |
| §2.1 | mips 整体移除（始于 14.0，commit 2021-12-09） | `freebsd-src-releng-15.0/UPDATING:929-932`：`20211209: Remove mips as a recognized target. This starts the decommissioning of mips support in FreeBSD. mips related items will be removed wholesale in the coming days and weeks.`；行 971：`Mips has been removed from universe builds`；行 1463：`mips, powerpc, and sparc64 are no longer built as part of universe`；行 1643：`mips GXEMUL support has been removed`；行 751：`Following the general removal of MIPS support, the ath(4) AHB bus-…` |
| §2.2 | clang/llvm 18 阶梯升级（→ 19 待 14.x→15 RELNOTES 校核） | `freebsd-src-releng-15.0/UPDATING:621-628`：`20240406: Clang, llvm, lld, lldb, compiler-rt, libc++, libunwind and openmp have been upgraded to 18.1.6.`；clang 19 升级条目留待 §10.2 待核验（UPDATING 文本未在本仓库版本中检出 19.x 升级行） |
| §2.3 | pkgbase 在 15.0 阶段密集落地 | `freebsd-src-releng-15.0/UPDATING` 行 80/90/157/159/166/184/188/211/227/243/265/358/373/381/386/458/463/527/556/613/618/622/712/716/717/718（共 40+ 处），代表性引文：行 157：`release engineering builds on pkgbase.freebsd.org`；行 527：`different transport - netlink(4) socket instead of unix(4). Users of …`（同时关联 netlink） |
| §2.4 | 13→15 syscall 表实测（22 项新增 + 3 项删除） | `grep '^#define[[:space:]]\+SYS_' freebsd-src-releng-{13.0,15.0}/sys/sys/syscall.h \| awk '{print $2}' \| sort \| comm`（详见 99 §12.1） |
| §3.1 | `pr_usrreqs` 在 15.0 已被合并入 `protosw` | `freebsd-src-releng-13.0/sys/sys/protosw.h:95`：`struct pr_usrreqs *pr_usrreqs;`；`freebsd-src-releng-13.0/sys/sys/protosw.h:188`：`struct pr_usrreqs {`；15.0 同名头文件中已无 `pr_usrreqs` 字段（grep 0 行） |
| §3.2 | `inpcb` 转 SMR | `freebsd-src-releng-15.0/sys/netinet/in_pcb.h:141-142`：`are be performed inside SMR section. Once desired PCB is found its own lock is to be obtained and SMR section exited.`；行 192：`smr_seq_t inp_smr; /* (i) sequence number at disconnect */`；行 342：`The pcbs are protected with SMR section…` |
| §3.3 | `if_t` typedef（详见 99 §12.2） | `freebsd-src-releng-13.0/sys/net/if_var.h:127`：`typedef struct ifnet * if_t;`；`freebsd-src-releng-15.0/sys/net/if.h:667`：`typedef struct ifnet *if_t;` |
| §3.5 | netlink 子系统 15.0 引入 | `freebsd-src-releng-15.0/sys/netlink/`（目录存在，3907 行 `.c`，13.0 该目录不存在）；`freebsd-src-releng-15.0/UPDATING:851-853`：`As of commit 7c40e2d5f685, the dependency on netlink(4) has been added … to compile netlink(4) module if it is not present in their kernel.` |
| §3.6 | RACK / BBR / extra TCP stacks 模块化 | `freebsd-src-releng-15.0/sys/conf/files:4451-4456`：`netinet/tcp_stacks/rack.c optional inet tcphpts tcp_rack \| inet6 tcphpts tcp_rack \\` 与 `compile-with "${NORMAL_C} -DMODNAME=tcp_rack -DSTACKNAME=rack"`；同时 `rack_bbr_common.c` / `sack_filter.c` / `tailq_hash.c` / `rack_pcm.c` 也在该处声明 |
| §3.7 | KTLS 在 GENERIC 默认开启 | `freebsd-src-releng-15.0/RELNOTES:227-228`：`Kernel TLS is now enabled by default in kernels including KTLS support. KTLS is included in GENERIC kernels for aarch64, …` |
| §3.8 | routing / rib / nexthop 安全相关 | `freebsd-src-releng-15.0/UPDATING:107-109`：`15.0-RELEASE-p4 SA-26:05.route … Local DoS and possible privilege escalation via routing sockets.`（侧证 routing 子系统在 15.0 仍处活跃维护） |

### 10.2 外部 URL 待核验清单

下表中的事实需要外部网络访问才能补全 URL / 抓取日期；按本审计回合的范围，这些条目暂以"待核验"留存，由 M1 启动前的人工 review 阶段补完。

| 03 章节 | 事实 | 候选 URL（待核验） | 转正条件 |
|---|---|---|---|
| §2.2 | clang/llvm 19 升级时间点（v0.1 写"clang/llvm 19"） | `https://www.freebsd.org/releases/15.0R/relnotes/`（FreeBSD 15.0 官方 release notes）；`https://lists.freebsd.org/archives/freebsd-current/`（搜索 "Clang 19 import"） | 在线打开 → 截取关键句 → 记入本节 + 99 §12.6 |
| §2.3 | pkgbase 在 15.0 状态（v0.1 写"P3 / EXPERIMENTAL knob"） | `https://wiki.freebsd.org/PkgBase`；`https://docs.freebsd.org/en/articles/explaining-bsd/`（pkgbase 章节） | 同上 |
| §3.5 | netlink 引入年份（v0.1 写"实际 14.0 引入"）的官方说明 | `https://www.freebsd.org/releases/14.0R/relnotes/`；`man.freebsd.org/cgi/man.cgi?netlink(4)` | 同上 |
| §3.6 | RACK 在 15.0 base 的 default knob 状态 | `https://www.freebsd.org/releases/15.0R/relnotes/`；`https://lists.freebsd.org/archives/freebsd-net/`（搜索 "RACK default"） | 同上 |
| §3.7 | KTLS API 14→15 变化的具体 commit / phabricator review | `https://reviews.freebsd.org/`；`https://cgit.freebsd.org/src/log/sys/sys/ktls.h` | 同上 |
| §3.8 | routing/rib/nexthop 重写设计文档 | `https://reviews.freebsd.org/D26577`（route_ctl 引入）；FreeBSD wiki "FIB / NHOP" 词条 | 同上 |
| §6 | 14.0R 至 14.4R 时间线表 | `https://www.freebsd.org/releases/`（每个 14.x 版本主页） | 同上 |
| §6 | 15.1R 时间线占位 | `https://www.freebsd.org/releases/15.1R/`（暂未发布） | 发布后回填 |

### 10.3 待核验条目的转正条件与流程

1. **触发时机**：本批"待核验"条目应在 M1 实施阶段启动前，由人工 review 补 URL，**不阻塞** Spec 阶段交付（§7 Go/No-Go 判断中"作为 Spec 草案 = GO"）
2. **核验方式**：访问 §10.2 列出的候选 URL → 截取与本文档事实相关的不超过 3 句原文 → 在本节追加「URL + 抓取日期 + 引文片段」 → 把对应行的"候选 URL（待核验）"改为"已核验 URL"
3. **不可用回退**：若 URL 失效或与文档事实不一致，应在本节记录"已尝试核验，结论与 v0.1 不符 / 无法访问"并联动订正主体章节
4. **Phase 4 reviewer 责任**：未来再次评审本文档时，若发现 §10.2 列表为空（表示已全部核验完），应在 99 §3 / §7 增加一条"外部事实 100% 可复核"的质量指标
