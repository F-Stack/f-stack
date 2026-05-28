# 04 — 13↔15 差异分析与移植策略（Diff & Port Strategy）

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-26）
> 数据来源：**Sub-Agent A + B + C 三路调研交叉** + 02 / 03 文档汇总
> 本文档是整个 Spec 系列**最核心的可执行产物**，后续 AI 代理可直接据此拾取 port 任务

---

## 0. 移植总策略

**核心思想**：基于 15.0 上游 `sys/` **重做**"裁剪 + F-Stack 改造"基线；而不是在 13.0 改造结果上"打补丁"升级。

理由：
1. 13→15 跨 2 个主版本，KBI/KPI 6 项 P0 破坏；patch 路径每个文件都要 3-way merge，工作量与重做相近但错误率高
2. 15.0 备份已就绪（Phase 1.4 产出 25 044 文件），可直接 cp 后改
3. 改造手法已在 02 中归纳为 9 大类标签，可批量复用

**核心流程**：

```
（基线）15.0 上游 sys/                                  （目标）f-stack/freebsd/
        │                                                       ▲
        ├─→ cp -a → f-stack-lib/freebsd/（已完成，Phase 1.4）   │
        │                                                       │
        └─→ 应用 02 的 9 大改造手法 ──────────────────────────┘
                  ↑
            （基于 03 的 P0 风险，针对性调整每个改造点）
```

---

## 1. 子目录级 diff 全景（实测）

> **数据口径（已订正 2026-05-28，详见 `99-review-report.md` §12.3）**：
> - **13 / 15 列**：该子目录递归下所有 `*.c` / `*.h` / `*.S` 文件总数（`find -type f`）
> - **DEL / NEW / MOD 列**：基于 `diff -rq freebsd-src-releng-{13.0,15.0}/sys/<subdir>` 的文件级实测，DEL = 仅 13.0 存在，NEW = 仅 15.0 存在，MOD = 两侧均存在但内容不同
> - **MOD 计数为绝对值**（不再是"启发式：大小变化即 MOD"），因此普遍高于本表 v0.1 给出的估算
> - **P 标志**：该子目录对 F-Stack 的影响优先级（与 diff 数字独立判定）
> - 实测命令见本节末尾脚注

| 子目录 | 13 | 15 | DEL | NEW | MOD | P | F-Stack 链接 |
|---|---:|---:|---:|---:|---:|---|---|
| **kern** | 217 | 234 | 2 | 18 | **231** | **P0** | 38 KERN_SRCS |
| **net** | 158 | 159 | 10 | 11 | **149** | **P0** | NET_SRCS（详见 §2.X） |
| **netinet** | 185 | 191 | 6 | 12 | **181** | **P0** | NETINET_SRCS（详见 §2.X） |
| **netinet6** | 59 | 57 | 2 | 0 | **57** | **P0** | NETINET6_SRCS（详见 §2.X） |
| **sys** (头) | 342 | 376 | 4 | 38 | **339** | **P0** | 大部分 `.h` |
| **libkern** | 85 | 80 | 9 | 4 | 77 | P1 | LIBKERN_SRCS |
| **opencrypto** | 35 | 35 | 3 | 3 | 33 | P1 | OPENCRYPTO_SRCS（可选） |
| **netipsec** | 30 | 32 | 0 | 2 | 30 | P1 | NETIPSEC_SRCS（可选） |
| **netgraph** | 170 | 152 | 7 | 4 | 152 | P1 | NETGRAPH_SRCS（可选） |
| **netpfil/ipfw** | 59 | 59 | 1 | 1 | 60 | P1 | NETIPFW_SRCS（可选） |
| **vm** | 53 | 52 | 2 | 1 | 51 | P1 | VM_SRCS |
| **amd64** | 231 | 234 | 17 | 24 | 238 | P1 | 极少（F-Stack 仅取部分 `.h`） |
| **arm64** | 270 | 317 | 20 | 98 | 248 | P1 | 极少（同上） |
| **x86** | 124 | 142 | 9 | 29 | 116 | P1 | 极少（同上） |
| **crypto**（顶） | 191 | 299 | 1 | 48 | 189 | P2 | 不直链 |
| **contrib** | 巨量 | 巨量 | 多 | 多 | 数千 | P3 | 只 `#include`，不直链；本表不再给具体数字（`diff -rq` 在该子目录耗时过长，不属本审计回合范围） |
| **bsm** | 8 | 8 | 0 | 0 | 8 | P3 | 不链 |
| **ddb** | 29 | 32 | 0 | 3 | 29 | P3 | 不链 |
| **netlink** | — | 39 | — | — | — | DP-2 | **不引入**（13.0 不存在该子目录，15.0 共 39 个文件，详见 03 §3.5） |

> **实测来源脚注**（2026-05-28）：
> ```bash
> for d in kern net netinet netinet6 sys libkern opencrypto netipsec \
>          netgraph netpfil/ipfw vm amd64 arm64 x86 crypto bsm ddb netlink; do
>   a=$(find freebsd-src-releng-13.0/sys/$d -type f \( -name '*.c' -o -name '*.h' -o -name '*.S' \) | wc -l)
>   b=$(find freebsd-src-releng-15.0/sys/$d -type f \( -name '*.c' -o -name '*.h' -o -name '*.S' \) | wc -l)
>   diff -rq freebsd-src-releng-13.0/sys/$d freebsd-src-releng-15.0/sys/$d \
>     | awk '/^Only in.*-13\.0/{del++} /^Only in.*-15\.0/{new++} /^Files /{mod++}
>            END{print del, new, mod}'
> done
> ```
> 与本表 v0.1（启发式估算）相比的主要差异：`kern` MOD 从 ~95 升到 231；`netinet` 从 ~52 升到 181；`net` 从 ~38 升到 149；`netinet6` 从 ~28 升到 57；`amd64`/`arm64`/`x86` 因递归口径调整，13/15 文件总数同步上调。**这意味着 04 §9 的任务规模与 05 §3 的排期需在 M1 启动前以本表为新基线复评**（不在本次审计修订回合范围内，记入 P2-001 跟踪）。


---

## 2. F-Stack 实际链接清单（来自 f-stack/lib/Makefile，Sub-Agent C 实测）

> 这是**真正影响"是否需要 port"的过滤器**：只有列在 `*_SRCS` 中的文件才会被链接进 `libff.a`，未列出的 freebsd 文件可以延后或永不处理。

### 2.1 KERN_SRCS（38 个 .c，全部来自 `sys/kern/`）

```
kern_descrip.c, kern_event.c, kern_fail.c, kern_khelp.c, kern_hhook.c,
kern_linker.c, kern_mbuf.c, kern_module.c, kern_mtxpool.c, kern_ntptime.c,
kern_osd.c, kern_sysctl.c, kern_tc.c, kern_uuid.c, link_elf.c, md5c.c,
subr_capability.c, subr_counter.c, subr_eventhandler.c, subr_kobj.c,
subr_lock.c, subr_module.c, subr_param.c, subr_pcpu.c, subr_sbuf.c,
subr_taskqueue.c, subr_unit.c, subr_smr.c, sys_capability.c, sys_generic.c,
sys_socket.c, uipc_accf.c, uipc_mbuf.c, uipc_mbuf2.c, uipc_domain.c,
uipc_sockbuf.c, uipc_socket.c, uipc_syscalls.c
```

### 2.2 NET_SRCS（典型，来自 `sys/net/`）

```
if.c, if_ethersubr.c, if_loop.c, if_clone.c, if_disc.c, if_epair.c,
if_ethersubr.c, if_iso88025subr.c, if_llatbl.c, if_media.c, if_mib.c,
if_tap.c, if_tun.c, if_vlan.c, if_lagg.c, netisr.c, route.c,
rtsock.c, raw_cb.c, raw_usrreq.c, route_ctl.c, route_helpers.c, ...
```

### 2.3 NETINET_SRCS（典型，来自 `sys/netinet/`）

```
in.c, in_pcb.c, in_proto.c, in_rmx.c, ip_id.c, ip_input.c, ip_output.c,
ip_options.c, raw_ip.c, tcp_input.c, tcp_output.c, tcp_reass.c,
tcp_subr.c, tcp_syncache.c, tcp_timer.c, tcp_timewait.c, tcp_usrreq.c,
udp_usrreq.c, igmp.c, ip_icmp.c, ...
```

### 2.4 NETINET6_SRCS（典型，来自 `sys/netinet6/`）

```
in6.c, in6_proto.c, in6_pcb.c, in6_src.c, in6_rmx.c, in6_ifattach.c,
ip6_input.c, ip6_output.c, ip6_forward.c, icmp6.c, nd6.c, nd6_nbr.c,
udp6_usrreq.c, ...
```

### 2.5 LIBKERN_SRCS（典型，来自 `sys/libkern/`）

```
arc4random.c, bsearch.c, fnmatch.c, gmtime_r.c, inet_aton.c, inet_pton.c,
inet_ntoa.c, inet_ntop.c, jenkins_hash.c, lookup_path.c, mcount.c,
memmem.c, qsort.c, qsort_r.c, random.c, strcasecmp.c, strncmp.c,
strdup.c, strlcpy.c, strlcat.c, ...
```

### 2.6 FF_SRCS（17-21 个 ff_*.c）+ FF_HOST_SRCS（9 个）

详见 `02-architecture-analysis.md` §4。

### 2.7 条件可选 SRCS

- `NETIPSEC_SRCS`：IPSEC 启用时
- `NETGRAPH_SRCS`：NETGRAPH 启用时
- `IPFW_SRCS`：IPFW 启用时
- `VM_SRCS`：vm 子集
- `OPENCRYPTO_SRCS`：opencrypto 子集

---

## 3. 交集热点（Part 1 ∩ Part 2 = F-Stack **真正受影响**的文件清单）

> 这是 04 文档**最关键的可执行清单**。每条标 P0/P1/P2，是 05 里程碑任务拆分的输入。

### 3.1 [P0] kern/ 受影响文件（按 02 改造手法分组）

| 文件 | 13.0 改造手法 | 15.0 上游变化 | port 任务 |
|---|---|---|---|
| `kern_descrip.c` | H-2（fhold CAS 自检版）+ H-1（屏蔽 RACCT） | refcount API 微调 | T-kern-01：基于 15.0 重做 fhold CAS 改造；保持 RACCT 屏蔽 |
| `kern_event.c` | H-1（kqueue_schedtask stub） | knote 部分内部接口微调 | T-kern-02：重做 stub；评估 `kqueuex` syscall 是否影响（C-1 不引入） |
| `kern_linker.c` | H-2（va_size==0 视为成功）+ H-1 | 略 | T-kern-03：重做 |
| `kern_mbuf.c` | H-1（屏蔽 mb_unmapped_* / pcpu_page_alloc / mb_alloc_ext_pgs） | **m_ext 字段重组（R-003）** | **T-kern-04 [P0]**：重做 stub；适配新 m_ext |
| `kern_sysctl.c` | H-1（屏蔽 __sysctl syscall） | sysctl 内部接口稳定 | T-kern-05：重做 |
| `link_elf.c` | H-1（stub elf_cpu_parse_dynamic） | 略 | T-kern-06：重做 |
| `subr_epoch.c` | H-1（屏蔽 taskqgroup_attach_cpu） | **epoch → SMR 部分场景（R-012）** | **T-kern-07 [P0]**：重做 stub；评估 SMR 接管面 |
| `subr_param.c` | H-1（屏蔽 ticks wrap 初值） | 略 | T-kern-08：重做 |
| `subr_taskqueue.c` | H-1 + H-2（stub _taskqueue_start_threads） | 略 | T-kern-09：重做 |
| `sys_generic.c` | H-1（屏蔽 kern_sigprocmask 段） | `kern_pselect` 内部接口微调 | T-kern-10：重做；同步 `ff_syscall_wrapper.c` |
| `sys_socket.c` | H-1 + H-9（屏蔽 soo_fill_kinfo 等） | KTLS 相关分支 | T-kern-11：重做；评估 KTLS stub |
| `uipc_mbuf.c` | H-1 + 自家 `FSTACK_ZC_SEND` 扩展 | **m_ext 字段重组（R-003）** | **T-kern-12 [P0]**：重做；`FSTACK_ZC_SEND` 路径适配 |
| `uipc_sockbuf.c` | H-1 + H-9（屏蔽 sb_aio 唤醒、RLIMIT_SBSIZE） | sockbuf KTLS 字段加入 | T-kern-13：重做 |
| `uipc_socket.c` | H-1 + H-9（屏蔽 TASK_INIT soaio_*） | **pr_usrreqs 合并入 protosw（R-011）** | **T-kern-14 [P0]**：重做；适配新 protosw 调用约定 |
| `uipc_syscalls.c` | H-2（sendit/recvit 外部可见） | 接口稳定 | T-kern-15：重做（小改） |

### 3.2 [P0] netinet/ 受影响文件

| 文件 | 13.0 改造手法 | 15.0 上游变化 | port 任务 |
|---|---|---|---|
| `tcp_input.c` | H-2 + H-4（inpcb hashlookup RSS） | **inpcb SMR 改造（R-012）**+ RACK 默认化 | **T-netinet-01 [P0]**：重做 RSS 扩展；适配 SMR |
| `tcp_output.c` | H-2 | 略 | T-netinet-02：重做 |
| `tcp_subr.c` | H-1 + H-9（移除 BPF tap、IPSEC 紧耦合） | 略 | T-netinet-03：重做 |
| `tcp_var.h` | H-8（tcpcb 字段微调） | **RACK 字段加入 tcpcb（R-004）** | **T-netinet-04 [P0]**：重做字段裁剪 |
| `tcp_stacks/rack.c` | H-5（module name 改 fstack） | RACK 大量更新 | T-netinet-05：重做 H-5 |
| `tcp_stacks/bbr.c` | H-5（module name 改 fstack） | 略 | T-netinet-06：重做 H-5 |
| `in_pcb.c` | H-4（RSS 端口范围 / lport 检查 / ladddr 推导） | **inpcb SMR 改造（R-012）** | **T-netinet-07 [P0]**：重做 H-4；适配 SMR |
| `tcp_usrreq.c` | （未实质改造） | **pr_usrreqs 合并入 protosw（R-011）** | T-netinet-08：评估是否需要重做（取决于 protosw 改写后是否还需修改） |
| `udp_usrreq.c` | （未实质改造） | **pr_usrreqs 合并入 protosw（R-011）** | T-netinet-09：同上 |
| `raw_ip.c` | （未实质改造） | **pr_usrreqs 合并入 protosw（R-011）** | T-netinet-10：同上 |

### 3.3 [P0] net/ 受影响文件

| 文件 | 13.0 改造手法 | 15.0 上游变化 | port 任务 |
|---|---|---|---|
| `if.c` | H-1 + H-9（屏蔽 if_alloc 走 host malloc） | **if_t 不透明化（R-013）**+ `if_alloc` 签名变 | **T-net-01 [P0]**：重做；适配 if_t 与新 if_alloc |
| `if_var.h` | H-8（ifnet 字段裁剪） | **if_t 不透明化** | **T-net-02 [P0]**：重做裁剪 |
| `if_ethersubr.c` | H-1（屏蔽 vlan/lagg BPF tap） | if 访问改函数 | T-net-03：重做 stub；适配 if 访问 |
| `netisr.c` | H-1（走 ff_veth 调度） | 略 | T-net-04：重做 |
| `route.c` | H-2（rtinit 走 ff_route.c 桥接） | **rib/nexthop 重写（R-008-新）** | **T-net-05 [P0]**：重做；rtinit 适配 rib/nexthop |

### 3.4 [P0] sys/（公共头）受影响文件

| 文件 | 13.0 改造手法 | 15.0 上游变化 | port 任务 |
|---|---|---|---|
| `sys/systm.h` | H-1 + H-8（屏蔽 kpilite.h；critical_enter/exit stub） | 略 | T-sys-01：重做 |
| `sys/refcount.h` | H-2（refcount_acquire_if_not_zero CAS 自检） | refcount API 微调 | T-sys-02：重做 |
| `sys/callout.h` / `sys/_callout.h` | H-8（callout 简化） | 略 | T-sys-03：重做 |

### 3.5 [P1] 其他子目录的 F-Stack 改造点

| 子目录 | 受影响文件 | 主要任务 |
|---|---|---|
| `netinet6/` | （改动稀少）| T-netinet6-01：基于 15.0 上游 cp + 最小化改造 |
| `netgraph/` | `ng_socket.c / ng_socket.h`（微差） | T-netgraph-01：重做 H-2 |
| `netinet/libalias/` | `alias_sctp.h`（微差） | T-libalias-01：评估是否仍需改 |
| `netipsec/` / `opencrypto/` / `crypto/` / `vm/` / `libkern/` | （0 或 1-2 个改造）| T-misc-01..N：基于 15.0 上游 cp + 检查现有改造是否还需要 |
| `amd64/` `arm64/` `x86/` | （改动多在头） | T-arch-01..03：跟随上游升级，可能受 if_t / m_ext 间接影响 |

### 3.6 [P0] f-stack/lib/ff_*.c 配套升级（FR-3）

| ff_*.c | 受 15.0 哪个 P0 影响 | port 任务 |
|---|---|---|
| `ff_glue.c` | **R-011 pr_usrreqs 合并** | **T-ff-01 [P0]**：所有 `pr->pr_usrreqs->pru_*()` 改 `pr->pru_*()` |
| `ff_veth.c` | **R-013 if_t 不透明化** | **T-ff-02 [P0]**：所有 `ifp->if_*` 改访问函数；`if_alloc` 签名适配 |
| `ff_route.c` | **rib/nexthop 重写** | **T-ff-03 [P0]**：rtinit 等改 rib/nexthop API |
| `ff_subr_epoch.c` | **R-012 epoch → SMR** | **T-ff-04 [P0]**：评估覆盖面；可能加 SMR stub |
| `ff_syscall_wrapper.c` | sendit/recvit 接口稳定；kern_pselect 微调 | T-ff-05：跟随 kern/sys_generic.c 改动 |
| `ff_kern_intr.c` | ithd 子系统 14/15 微调 | T-ff-06：评估 |
| `ff_kern_*.c`（其他） | 接口稳定 | T-ff-07..N：跟随 |

### 3.7 [P0] f-stack/freebsd/mips/ 删除

| 任务 | 详情 |
|---|---|
| **T-cleanup-01** | `rm -rf f-stack/freebsd/mips/`；同步清理 Makefile / mk 中 mips 条件分支 |

---

## 4. tools/ 移植策略

### 4.1 12 个原生工具：基于 15.0 上游重做 H-6 + H-7

| 工具 | 15.0 源路径 | F-Stack 改造工作量 |
|---|---|---|
| `arp/` | 15.0/usr.sbin/arp | 中（raw socket → ff_ipc 重做） |
| `ifconfig/` | 15.0/sbin/ifconfig | **大**（含 libifconfig 抽象层变化） |
| `ipfw/` | 15.0/sbin/ipfw | 中（IPFW set 命令通道） |
| `libmemstat/` | 15.0/lib/libmemstat | 小（sysctl 改 ff_ipc） |
| `libnetgraph/` | 15.0/lib/libnetgraph | 中 |
| `libutil/` | 15.0/lib/libutil | 极小（极少改） |
| `libxo/` | 15.0/lib/libxo | 极小（基础 lib，几乎不改） |
| `ndp/` | 15.0/usr.sbin/ndp | 中 |
| `netstat/` | 15.0/usr.bin/netstat | **大**（sysctl 接管最多）|
| `ngctl/` | 15.0/usr.sbin/ngctl | 中 |
| `route/` | 15.0/sbin/route | **大**（RTM_* 通道重做 + rib/nexthop 用户态 API 跟随）|
| `sysctl/` | 15.0/sbin/sysctl | 中（__sysctl syscall → ff_ipc） |

每个工具的通用流程：

```
1. cp -a 15.0/<src-path>/<tool> → f-stack/tools/<tool>/.staging/
2. diff f-stack/tools/<tool>/.staging vs 13.0/f-stack-lib/tools/<tool>
   → 看上游 13→15 的改动
3. diff f-stack/tools/<tool> vs 13.0/f-stack-lib/tools/<tool>
   → 看 F-Stack 已有改造手法（H-6 / H-7）
4. 在 .staging 上重新应用 H-6 / H-7，得到新版本
5. mv .staging → f-stack/tools/<tool>
```

### 4.2 f-stack 自带工具

| 工具 | 处置 |
|---|---|
| `knictl/` `traffic/` `top/` | 不动；保持 13.0 占位（M5 末才视情况评估） |

### 4.3 f-stack-lib 自带辅助

| 项 | 处置 |
|---|---|
| `tools/compat/`（含 ff_ipc.c/h）| 跟随 ff_* 升级（FR-3）|
| `tools/sbin/` | 空目录，保留 |
| `tools/lib.mk / Makefile / opts.mk / prog.mk / README.md` | 评估 15.0 base Makefile 体系是否需要适配 |

---

## 5. F-Stack 特有扩展保留清单（FR-7）

升级过程中必须保留：

| 扩展 | 位置 | 验收 |
|---|---|---|
| `FSTACK_ZC_SEND` | `f-stack/freebsd/kern/uipc_mbuf.c::m_uiotombuf` | grep 命中 ≥ 升级前 |
| RSS 端口范围 / lport 检查 | `f-stack/freebsd/netinet/in_pcb.c` + `tcp_input.c` | grep `FSTACK-rss-ext` 注释或对应宏 |
| TCP RACK/BBR module name 改名 | `tcp_stacks/rack.c` + `bbr.c` | grep `tcp_rack_fstack` |
| ff_ipc.c/.h IPC 桥 | `f-stack/tools/compat/` | 工具编译链路保留 |
| ff_*.c 全 30 个 | `f-stack/lib/` | 文件清单 30 个 |

---

## 6. 移植策略小结：每个文件的 5 步法

对每个 P0 改造文件，统一走：

```
1. baseline-15  = freebsd-src-releng-15.0/sys/<subdir>/<file>
2. baseline-13  = freebsd-src-releng-13.0/sys/<subdir>/<file> (= f-stack-lib/freebsd/<subdir>/<file>)
3. fstack-13    = f-stack/freebsd/<subdir>/<file>
4. delta-13     = diff baseline-13 vs fstack-13   # F-Stack 已有的改造 patch
5. baseline-15 + delta-13 → fstack-15-draft
   → 手工 review，重点看：
     - delta-13 中触及的接口/符号在 15.0 是否还存在
     - 15.0 上游新增的代码段，F-Stack 是否需要施加同类改造（如 m_ext 新字段是否进 FSTACK-stub）
   → 落盘为 f-stack/freebsd/<subdir>/<file>
```

> 该 5 步法可被 `c-precision-surgery` skill 直接消化。每个 P0 任务的"输入边界 + 输出标准"由本节定义。

---

## 7. 风险与策略对照表

| 风险 ID | 03 中位置 | 04 中应对任务 |
|---|---|---|
| R-011 | §3.1 pr_usrreqs 合并 | T-kern-14 / T-netinet-08/09/10 / T-ff-01 |
| R-012 | §3.2 inpcb SMR | T-netinet-01 / T-netinet-07 / T-kern-07 / T-ff-04 |
| R-013 | §3.3 if_t 不透明化 | T-net-01 / T-net-02 / T-net-03 / T-ff-02 |
| R-003 | §3.4 mbuf 字段调整 | T-kern-04 / T-kern-12 |
| 新 | §3.8 rib/nexthop | T-net-05 / T-ff-03 / T-tools-route |
| R-001/FR-4 | §2.1 mips 移除 | T-cleanup-01 |
| R-002 | §3.5 netlink | 不引入（DP-2），无任务 |
| R-004 | §3.6 RACK 默认化 | T-netinet-05/06 |
| R-007 | §4 ABI break | M5 末验收时审视 libff ABI |
| R-009 | §2.2 clang/llvm | 前置：GCC ≥ 10 / clang ≥ 12 |
| R-006 | §3.7 KTLS / wlan | T-kern-11（评估 KTLS stub） |
| R-008 | §1.4 of 01 漂移 | 实施前 `diff -rq` 清理 SKIP 噪声 |

---

## 8. 工作量估算（基于热点交集）

| 里程碑 | 任务数 | 文件数 | 工作量档 |
|---|---|---|---|
| M1（基础设施 + 头文件 + mips 清理 + libkern + crypto） | T-sys-01/02/03 + T-cleanup-01 + T-misc-01..N | ~50 | 小 |
| M2（kern 核心 38 KERN_SRCS）| T-kern-01..15 | 15 实质改造 + 23 直拷 | **大** |
| M3（网络栈 net + netinet + netinet6）| T-net-01..05 + T-netinet-01..10 + T-netinet6-01 | ~20 | **大** |
| M4（边缘子系统 netipsec / netgraph / netpfil / vm）| T-misc / T-netgraph-01 | 5-8 | 中 |
| M5（tools 12 个 + ff_*.c + lib 验收）| T-tools-01..12 + T-ff-01..N + 验收 | ~30 | **大** |

---

## 9. 移植任务总数总览

| P 级 | 任务数 | 说明 |
|---|---|---|
| **P0** | 24 个（kern 4 + netinet 5 + net 5 + ff 4 + cleanup 1 + tools 大改 5） | 必修，编译/运行阻塞 |
| **P1** | 18 个（其余 kern / netinet / net / tools 中改）| 编译可过但语义需验证 |
| **P2** | 10 个（边缘子系统） | 非核心 |
| **P3** | 5 个（crypto / arch 头 / 其他） | 信息留档 / 跟随升级 |
| **合计** | **~57 个移植任务** | 见 `05-implementation-plan.md` §3 拆分 |

---

## 10. 与其他文档的衔接

| 本节产物 | 衔接对象 |
|---|---|
| §3 交集热点（57 个 T-* 任务） | `05-implementation-plan.md` §3 任务分配 |
| §6 5 步法 | `05-implementation-plan.md` §4 SOP |
| §1 子目录 diff 全景 | `06-test-and-acceptance-spec.md` §1 编译矩阵 |
| §7 风险策略对照 | `99-review-report.md` 风险覆盖度审查 |

> 下一步：`05-implementation-plan.md` 把 57 个 T-* 任务拆到 M1-M5，给出资源、时序、回滚方案。
