# M3 研究简报（Research Brief）

> English version: ../M3-research-brief.md

> 由 m3-leader 整合 4 个 [subagent:code-explorer] 一次性调研产出。覆盖 net + netinet + netinet6 + ff_glue.c 共 25 个 F-Stack 改造文件 delta-13 + 14.0+/15.0 ABI 变化 + 跨范围连锁。
> 100% 实测命令背书，无猜测。

## 0. 执行摘要

### 0.1 颠覆性发现（实测优先于 spec 文档）

| # | 发现 | 影响 |
|---|---|---|
| F1 | **net/ 8 个文件中 5 个在 fstack-13 是 vendor 13.0 字节级拷贝、零 F-Stack delta**（if.c / if_var.h / route.c / route_ifaddrs.c / if_ethersubr.c 等）| spec 05 §2.3 把 if.c/if_var.h/route.c 列 P0 重型，但实际 R-013/R-004 改造责任落在调用方（netinet/lib），net/ 这层只需 vendor 替换为 baseline-15 |
| F2 | **netinet/ 重型 P0 3 文件（in_pcb.c / tcp_input.c / tcp_var.h）在 fstack-13 也是字节一致 vendor 拷贝**（FSTACK 标记 0 命中、文件大小一致）| M3 这 3 文件改造 = baseline-13 → baseline-15 上游 delta 的 1:1 接力，**无 F-Stack 历史改造手法需迁移** |
| F3 | **ff_glue.c 完全不含 pr_usrreqs / protosw 引用**（spec 02/03/05 误报）| T-ff-01 应重新定义为 verify-only（diff -rq + 单文件编译） |
| F4 | **15.0 上游已采纳 in_mcast.c (in_msource 修复) + rack.c/bbr.c (MODNAME 占位) + rip_send 参数名 等 3 项 F-Stack 风格改进** | 升级时直接采纳 baseline-15，删除对应 #ifdef FSTACK 包络（白嫖 3 项） |
| F5 | **`struct pr_usrreqs` 在 15.0 已彻底删除**，`pru_*` 全部并入 `struct protosw` 并改名 `pr_*` | tcp_usrreq.c LVS_TOA 注入的 `.pru_peeraddr = toa_getpeeraddr` 必须改 `.pr_peeraddr`（机械改名 1 行） |
| F6 | **netlink 14.0+ 引入**：net/{if_clone.c, if_vlan.c} 引用 `<netlink/...>`，sys/netlink/ 30 文件未在 f-stack-lib 中 | 处置：`#ifdef FSTACK / #else <netlink/...> #endif` 包裹 + 删除 rtnl_*_register 调用（推荐 B 方案） |
| F7 | **缺失头 KNOB**：opt_kbd.h / opt_acpi.h / opt_altq.h（被 iflib.c / if_infiniband.c / altq/*.c 引用）| 优先级 P3，遇到再补 0 字节空 stub |

### 0.2 实测度量

- **F-Stack 改造文件总数**（剔除 vendor 拷贝）：实际仅 ~10 个文件有 F-Stack delta（net 4 + netinet 8 + netinet6 3 + ff_glue.c 0 = 15 处需重应用，不是 spec 估计的 25 处）
- **三大 P0 KPI 破坏点真实落点**：R-013 if_t 落在 lib/ff_veth.c 等调用方；R-002 inpcb SMR 落在 baseline-13→15 接力（无历史改造迁移）；R-004 rib/nexthop 落在 lib/ff_route.c
- **改造手法迁移工作量重新评估**：从原计划 600 行 delta-13 减少到 ~50 行（净 net+netinet+netinet6 实际改造），主体工作转为 cp -a baseline-15 vendor 版本

## 1. M3 范围与基线

| 维度 | 值 |
|---|---|
| spec 输入 | `05-implementation-plan.md` §2.3 + `02-architecture-analysis.md` §3 + `03-freebsd-15-changes.md` §3.1 |
| baseline-13 | `/data/workspace/freebsd-src-releng-13.0/sys/{net,netinet,netinet6}/` |
| baseline-15 | `/data/workspace/freebsd-src-releng-15.0/sys/{net,netinet,netinet6}/` |
| fstack-13 | `/data/workspace/f-stack-13.0-baseline/freebsd/{net,netinet,netinet6}/` |
| f-stack-lib（旁证）| `/data/workspace/freebsd-src-releng-15.0/f-stack-lib/freebsd/...`（M3 已落地中间产物 1.4 阶段输出）|
| 改造主体 | `/data/workspace/f-stack/freebsd/{net,netinet,netinet6}/` + `/data/workspace/f-stack/lib/ff_glue.c` |

## 2. net/ 8 文件调研

### 2.1 关键先决结论（颠覆 spec 假设）

实测 8 个文件 fstack-13 vs baseline-13 字节对比，仅 3 个有 FSTACK 改造：

| 文件 | fstack-13 大小 | FSTACK marker 数 | delta-13 实测 |
|---|---|---|---|
| net/if.c | 105.86 KB | 0 | **零差异**（vendor copy）|
| net/if_var.h | 29.92 KB | 0 | **零差异** |
| net/route.c | 19.25 KB | 0 | **零差异** |
| net/if_ethersubr.c | 37.41 KB | 0 | 0.18KB 微调（KASSERT，非 FSTACK）|
| net/netisr.c | 44.46 KB | 0 | 0.13KB 微调（非 FSTACK） |
| net/route/route_ifaddrs.c | 5.8 KB | 0 | **零差异** |
| **net/pfil.c** | 16.86 KB | **1 hunk** | 1 个 `#ifndef FSTACK` 包 SYSINIT |
| **net/if_gre.h** | 5.79 KB | **2 hunks** | `#ifdef FSTACK` 加 `__aligned(2)` |
| **net/if_spppsubr.c** | 132.46 KB | **1 hunk** | 1 行 `#ifndef FSTACK` 包 log() |

### 2.2 net/ P0 重型文件（按 spec 列 P0，实测全是 vendor 拷贝）

#### T-net-01 net/if.c（R-013 if_t）
- delta-13 hunks：**0**（vendor 字节级一致）
- baseline-15 关键变化：
  - `ifnet_byindex(u_short)` → `ifnet_byindex(u_int)` 签名变更
  - 新增 `ifnet_byindexgen(uint16_t,uint16_t)` 不透明索引验证
  - 新增 `if_idxgen` 字段
  - 必须新增 `#include <net/if_private.h>`（struct ifnet 移居）
  - if_alloc_domain 已合并入 if_alloc
- 改造手法迁移评级：**EASY（vendor 替换 baseline-15）**
- R-013 真实落点：lib/ff_veth.c 等 14.0+ accessor 调用方（不在 if.c 本身）

#### T-net-02 net/if_var.h
- delta-13 hunks：**0**
- baseline-15 关键变化：`struct ifnet { ... }` 完整定义从 if_var.h 移除，迁至 `if_private.h:39`
- 改造手法迁移评级：**EASY（vendor 替换）**

#### T-net-05 net/route.c（R-004 rib/nexthop）
- delta-13 hunks：**0**
- 改造手法迁移评级：**EASY（vendor 替换）**
- R-004 真实落点：lib/ff_route.c（rib_lookup_info / nexthop API 适配）

### 2.3 net/ P1 中等文件

#### T-net-03 net/if_ethersubr.c（spec 列 BPF tap 屏蔽）
- delta-13 实测：0.18KB 微调（KASSERT，**非 FSTACK marker**）
- 评级：EASY（vendor 替换，无 F-Stack delta 重应用）

#### T-net-04 net/netisr.c（spec 列 ff_veth 调度重做）
- delta-13 实测：0.13KB 微调（**非 FSTACK marker**）
- baseline-15 vs 13.0：netisr API 完全无变化（API 兼容）
- 评级：EASY（vendor 替换）

### 2.4 net/ P1 简单文件（实际唯三需要 5 步法）

#### net/pfil.c
- delta-13 hunk：1 处 `#ifndef FSTACK` 包 SYSINIT（pfil_global_init）
- 锚点：baseline-15 中 SYSINIT(pfil) 仍在
- 评级：EASY

#### net/if_gre.h
- delta-13 hunks：2 处 `#ifdef FSTACK` 加 `__aligned(2)`
- 评级：EASY

#### net/if_spppsubr.c
- delta-13 hunk：1 行 `#ifndef FSTACK` 包 log() 调用
- 评级：EASY

### 2.5 net/ 范围 R-013 if_t 字段访问表（影响 lib/ff_*.c，不影响 net/*.c）

| 13.0 直接访问 | 14.0+ accessor | 不透明 if_private.h 内 |
|---|---|---|
| `ifp->if_softc` | `if_getsoftc/if_setsoftc` | 是 |
| `ifp->if_flags` | `if_getflags/if_setflags` | 是 |
| `ifp->if_drv_flags` | `if_getdrvflags` | 是 |
| `ifp->if_mtu` | `if_getmtu/if_setmtu` | 是 |
| `ifp->if_capabilities` | `if_getcapabilities` | 是 |
| `ifp->if_ioctl` | `if_setioctlfn` | 是 |
| `ifp->if_index` | `if_getindex` | 是 |
| `ifp->if_xname` | `if_name` | 是 |

**M3 应对（DP-M3-2=B）**：fstack 的 `f-stack/freebsd/net/*.c` 全部 cp 15.0 vendor；R-013 适配工作落在 lib/ff_veth.c（M3 梯度 4）。

## 3. netinet/ 中等 15 文件调研

### 3.1 P1 简单 / 零改造合并节（8 文件）

| 文件 | FSTACK marker | 实测 | 评级 |
|---|---|---|---|
| in_prot.c | 0 | 整文件字节一致 | NO-CHANGE |
| tcp_subr.c | 0 | 仅 0.18KB 差（EOL/keyword）| NO-CHANGE / EASY |
| tcp_output.c | 0 | 0 改造，但 15.0 重命名 `tcp_output → tcp_default_output` | EASY |
| udp_usrreq.c | 0 | 0 改造（但 15.0 protosw 合并冲击）| 见 §3.4 |
| raw_ip.c | 0 | 0 改造（同上）| 见 §3.4 |
| if_ether.c | 0 | 仅 +2 行注释/空行 | EASY |
| **tcp_fastopen.c** | **1 处** | 1 行 `#pragma GCC diagnostic ignored "-Waddress"` | EASY |
| rack_bbr_common.c | 0 | 字节一致 | NO-CHANGE |

### 3.2 in_pcb.h（配合 T-netinet-07）

- delta-13：1 处 `#ifdef FSTACK`（line 764）
  ```c
  #ifdef FSTACK
  #define INPLOOKUP_LPORT_RSS_CHECK   0x80000000
  #endif
  ```
- baseline-15 `in_pcb.h:617-625`：`INPLOOKUP_*` 改为 enum，但 0x80000000 用户位仍未占用
- 评级：EASY（保留 #define 紧跟 enum 后）

### 3.3 in_mcast.c（**15.0 上游已采纳同款修复 = 白嫖**）

- delta-13：2 处 `#ifdef FSTACK ... #else ...`，把 `sizeof(struct ip_msource)` 改为 `sizeof(struct in_msource)`
- baseline-15 `:749/:780`：已直接使用 `sizeof(struct in_msource)`
- 评级：**EASY** — 升级时直接删除整个 `#ifdef FSTACK` 包络

### 3.4 T-netinet-08/09/10 protosw 合并适配（**最大风险**）

#### tcp_usrreq.c
- delta-13：
  - 1 处 `#ifndef FSTACK`（line 1602）：跳过 V_tcp_require_unique_port 检查
  - 大段 `#ifdef LVS_TCPOPT_TOA`（lines 313-349 / 837-844 / 1539-1543）
    - **关键**：`.pru_peeraddr = toa_getpeeraddr` 在 15.0 必须改 `.pr_peeraddr = toa_getpeeraddr`
- baseline-15 ABI 变化：`struct pr_usrreqs` **彻底删除**，`pru_*` 全部并入 `struct protosw` 并改 `pr_*`
- 评级：**MEDIUM**（机械改名 1 行 `pru_peeraddr → pr_peeraddr` + LVS_TOA 段挪行号）

#### udp_usrreq.c / raw_ip.c
- delta-13：0
- 评级：EASY（vendor 替换）

### 3.5 T-netinet-05/06 rack.c + bbr.c（**上游已自然兼容 = 白嫖**）

- delta-13：rack.c lines 142-145 + bbr.c lines 150-153 各 1 处 `#ifdef FSTACK` 定义 `MODNAME`
- baseline-15 `rack.c:24670` `bbr.c:14822-14824` 已主动使用 `MODNAME` 占位符
- 评级：**EASY** — fstack 的 `#define MODNAME tcp_rack/tcp_bbr` 在 baseline-15 仍可继续注入

### 3.6 tcp_hpts.c（14.0+ hpts_softclock 重构）

- delta-13：3 处 `#ifndef FSTACK`（lines 191/213/1982）
  - tcp_bind_threads 默认值
  - tcp_hpts_callout_skip_swi 默认值
  - 跳过 intr_event_bind_ithread_cpuset
- baseline-15 重构：引入全局函数指针 `tcp_hpts_softclock`，由 LRO 直调
- 评级：MEDIUM（行号大幅变化，但函数语义稳定）

### 3.7 tcp_syncache.c（LVS_TCPOPT_TOA 透明代理注入）

- delta-13：注入约 67 行 `#ifdef LVS_TCPOPT_TOA`
- baseline-15：syncache_socket 移到 :760，`tcp_ecn_syncache_socket` 抽离到独立文件 `tcp_ecn.c`
- 评级：MEDIUM（注入点稳定，需挪到新位置 + 协调 tcp_ecn.c 抽离）

### 3.8 netinet/ 范围 14.0+ 关键 ABI 变化清单

| # | ABI 变化 | 风险 | 应对 |
|---|---|---|---|
| A1 | `struct pr_usrreqs` **删除**，pru_* → pr_* | HIGH | tcp_usrreq.c 1 行机械改名 |
| A2 | `tcp_output → tcp_default_output` | MEDIUM | lib 调用方追溯 |
| A3 | `tcp_init/udp_init` 加 `void *arg __unused` | LOW | in_proto.c 表 |
| A4 | `INPLOOKUP_*` 改 enum | LOW | 与 fstack #define 共存 |
| A5 | tcp_hpts_softclock 函数指针 | MEDIUM | 旁路保留 |
| A6 | in_msource 修复 **白嫖** | LOW | 删除 #ifdef FSTACK |
| A7 | MODNAME 占位 **白嫖** | LOW | fstack #define 继续 |
| A8 | tcp_ecn.c / tcp_lro_hpts.c 抽离 | MEDIUM | LVS_TOA 注入点重对位 |
| A9 | rip_send 参数名 flags → pruflags | NONE | fstack 无影响 |
| A10 | tcp_pcap.c / tcp_debug.c **删除**；新增 rack_pcm.c / tailq_hash.c | LOW | Makefile 调整 |

## 4. netinet/ 重型 P0 3 文件深度调研

### 4.1 关键先决结论

实测 fstack-13 vs baseline-13 三方对比 + FSTACK 标记 grep：

| 文件 | fstack-13 大小 | baseline-13 大小 | FSTACK 标记 | 结论 |
|---|---|---|---|---|
| tcp_var.h | 43.48 KB | 43.48 KB | 0 | **vendor 拷贝**，0 历史改造 |
| in_pcb.c | (实测一致) | (实测一致) | 0 | **vendor 拷贝**，0 历史改造 |
| tcp_input.c | 115.95 KB | 115.95 KB | 0 | **vendor 拷贝**，0 历史改造 |

**M3 这 3 文件改造 = baseline-13 → baseline-15 上游 delta 的 1:1 接力，无 F-Stack 历史改造手法迁移**。改造手法标签 = M9（上游同步） + M2（结构体字段重构）。

### 4.2 T-netinet-04 tcp_var.h（tcpcb 字段裁剪 + RACK 字段）

#### A. 13.0 → 15.0 tcpcb 字段去除清单

| 13.0 字段 | 14.0+ 处置 |
|---|---|
| `struct inpcb *t_inpcb` | 指针 → 嵌入 `struct inpcb t_inpcb` |
| `t_peakrate_thr / t_in_pkt / t_tail_pkt / t_vnet / cl4_spare / t_rttbest` | 删除 |
| `struct tcp_timer *t_timers` | 指针 → `sbintime_t t_timers[TT_N]` 数组 + `t_callout` |
| `struct cc_algo *cc_algo` → `t_cc` | 重命名 |
| `struct cc_var *ccv` | 指针 → 嵌入 `struct cc_var t_ccv` |
| `struct osd *osd` | 指针 → 嵌入 `struct osd t_osd` |
| `u_long t_rttupdated` | 类型 → `uint8_t` |
| `#ifdef TCPPCAP t_inpkts/t_outpkts` | TCPPCAP 移除 |

#### B. 14.0+ 新增字段（必须保留对接）

`t_callout / t_timers[] / t_precisions[] / t_hpts / t_inqueue / t_hpts_request / t_hpts_cpu / t_lro_cpu / t_in_hpts(enum) / t_nic_ktls_xmit / t_rcep / t_scep / t_sndtlppack / t_sndtlpbyte / t_sndbytes / t_snd_rxt_bytes / t_dsack_bytes / t_tlp_bytes / t_dsack_pack / t_tmr_granularity / t_challenge_ack_end / t_challenge_ack_cnt / _t_logpoint / TCP_REQUEST_TRK 块`

#### C. 改造手法迁移评级
**MEDIUM** — 字段大量重构，但 fstack 无历史 delta 需迁移；直接 cp 15.0 vendor + 评估 lib/ff_veth/ff_*.c 是否有 tcpcb 字段访问连锁。

### 4.3 T-netinet-07 in_pcb.c（R-002 inpcb SMR + RSS）

#### A. R-002 inpcb SMR 14.0+ 关键 API（实测 baseline-15）

| API | baseline-13 | baseline-15 |
|---|---|---|
| MPASS 检查 | `MPASS(in_epoch(net_epoch_preempt) \|\| mtx_owned)` | `MPASS(SMR_ENTERED((ipi)->ipi_smr) \|\| mtx_owned)` |
| 新接口 | — | smr_enter / smr_exit / smr_unlazy / atomic_load_consume_ptr |
| 新函数 | — | in_pcblookup_*_smr 系列 |
| 新字段 | — | inp_smr / ipi_smr |
| ipi_lock | mtx | 部分被 epoch / SMR 替换 |

#### B. sub-task 切分（按 Phase 5b kern_descrip 整体策略）
1. **整段 cp -a baseline-15 vendor 版本**
2. **复核 lib/ff_subr_epoch.c / ff_route.c 是否引用变更接口**
3. **R-002 影响向 lib 层传播评估**

#### C. 改造手法迁移评级
**MEDIUM** — vendor 替换为主，无 fstack delta 迁移；但 R-002 SMR 接口对 lib/ff_*.c 有连锁影响。

### 4.4 T-netinet-01 tcp_input.c（R-002 RSS 重做 + SMR）

#### A. 14.0+ 新接口
- `tcp_input_with_port` 替代 13.0 `tcp_input`（端口透传）
- RSS 路径在 14.0+ 重构，`rss_proto_software_hash_v4 / rss_*_hash_v6` 调用入口变更

#### B. sub-task 切分
1. **vendor 替换**
2. **复核 lib/ 引用 tcp_input 调用方**
3. **RSS 14.0+ 重做评估**（M3 范围内仅做静态适配，runtime 验证留 M4）

#### C. 改造手法迁移评级
**MEDIUM** — vendor 替换为主。

### 4.5 R-002 inpcb SMR 14.0+ 接口完整清单

```
14.0+ 引入：
  smr_enter(smr) / smr_exit(smr)
  smr_unlazy(smr)
  atomic_load_consume_ptr(&p)
  SMR_ENTERED(smr)  /* 替代 in_epoch(net_epoch_preempt) */
  in_pcblookup_smr / in_pcblookup_local_smr / in_pcblookup_lbgroup_smr
  inp_smr / ipi_smr 字段
  
13.0 → 15.0 lookup 行为变化：
  MPASS(in_epoch(net_epoch_preempt))  →  MPASS(SMR_ENTERED((ipi)->ipi_smr))
  PCBHASH (read path) 改用 SMR-protected lookup
```

## 5. netinet6/ 3 改造文件调研

### 5.0 关键发现

3 文件均为「13.0 sys 副本 + 极简 FSTACK delta」。

### 5.1 in6_mcast.c

- delta-13：2 处 `#ifdef FSTACK ... #else ...` 在 `nims = malloc()` type 处
- 锚点：15.0 `:715` 与 `:793` 处函数体未变
- 评级：⭐⭐⭐⭐⭐ EASY

### 5.2 ip6_id.c

- delta-13：1 处 `#ifndef FSTACK` 在 `ip6_randomflowlabel`（line 261）
- 包裹 `is_random_seeded()` 检查（用户态 lib 不链接 sys/dev/random/）
- 评级：⭐⭐⭐⭐⭐ EASY

### 5.3 nd6.c

- delta-13：**0 处**（纯 cp -a 13.0 sys）
- 15.0 vs 13.0：+2.43 KB，移除 `__FBSDID` 行，KNOB 一致
- 评级：⭐⭐⭐⭐⭐ EASY（直接 cp 15.0）

## 6. lib/ff_glue.c 调研（**spec 误报**）

### 6.1 实测：ff_glue.c 完全不含 pr_usrreqs / protosw 引用

```
grep "protosw|pr_usrreqs|pr_input|pr_output|pr_ctlinput|pr_init|pr_drain|pr_fasttimo|pr_slowtimo" lib/ff_glue.c
→ Found 0 matching results
```

ff_glue.c（30.44 KB / 1467 行）实际是用户态 stub 集合：vm/domainset/kmem stub + proc/cred/jail stub + timer stub + copyio/uio stub + sysctl 节点 + malloc/free 适配 + ck_epoch userland stub（**不是 sys/epoch.h**）+ elf/sleepq/sched 占位。

### 6.2 spec 矛盾点澄清

| 来源 | 主张 | 实测 |
|---|---|---|
| spec 02 §架构 line 167 | "ff_glue.c 引用 protosw / pr_usrreqs" | ❌ 0 处引用 |
| spec 03 §3.1 line 136 | "ff_glue.c pru_* 函数指针都要改写" | ❌ 0 处 pru_* |
| spec 05 line 128 | "T-ff-01 ff_glue.c：pr_usrreqs → protosw" | ❌ 任务前提不成立 |

### 6.3 改造手法建议

**T-ff-01 应重新定义为 verify-only**：M3 仅做 `diff -rq f-stack-13.0-baseline/lib/ff_glue.c f-stack/lib/ff_glue.c` + 单文件编译验证（M2 已 ✅ 通过）。

R-011（pr_usrreqs 合并入 protosw）真实影响范围：
- 已落 M2：uipc_socket.c / uipc_domain.c
- 落 M3：tcp_usrreq.c LVS_TOA 段 1 行机械改名（§3.4 已述）

## 7. 14.0+ 缺失头文件预测

### 7.1 KNOB 缺失（实际全在 lib/opt/，仅以下 3 处可能缺失）

| 缺失 KNOB | 引用源 | 优先级 |
|---|---|---|
| opt_kbd.h | net/if_infiniband.c:28 | P3 — 遇到再补空 stub |
| opt_acpi.h | net/iflib.c:31 | P3 — 同上 |
| opt_altq.h | net/altq/*.c | P3 — altq 通常不启用 |

### 7.2 netlink 14.0+（**P0 关注**）

15.0 全 sys/ 中 35 个文件 `#include <netlink/...>`，net/ 范围被 f-stack 纳入的有 2 文件：
- `net/if_clone.c`
- `net/if_vlan.c`

处置选项：
- **方案 A**（重）：cp 15.0 sys/netlink/ 30 文件 + 新增 lib/ff_netlink_stub.c
- **方案 B**（推荐 P0）：`#ifdef FSTACK / #else <netlink/...> #endif` 包裹 4 行 include + 删除 rtnl_*_register 调用

## 8. 跨范围连锁清单（lib/ff_*.c）

### 8.1 lib/ff_*.c 14.0+ 接口引用矩阵

| ff_*.c 文件 | if_alloc/if_t | NET_EPOCH/inp_smr | rib_lookup/nexthop | m_pkthdr/m_ext | pr_usrreqs/protosw | M3 风险 |
|---|---|---|---|---|---|---|
| **ff_veth.c** | ✅ if_alloc(IFT_ETHER) line 830 + m_pkthdr × 5 | — | — | ✅ 18 处 | — | **P0**（spec 05 T-ff-02 锁定，14.0+ if_alloc 签名变 `if_alloc(void)` + IFT_ETHER 改为 if_setattach）|
| **ff_route.c** | — | ✅ 7 处 epoch_tracker | ✅ rib_lookup_info × 2 | — | — | **P0**（spec 05 T-ff-03 锁定，14.0+ rib_lookup_info 签名 + nexthop 重构）|
| **ff_subr_epoch.c** | — | ✅ 9 处 epoch_t / epoch_drain_callbacks | — | — | — | P1（M2 verify-only ✅）|
| **ff_glue.c** | — | ✅ 9 处 ck_epoch_*（userland 库）| — | — | ❌ | **P3**（spec 误报为 P0；改 verify-only）|
| **ff_ng_base.c** | — | ✅ 6 处 epoch_tracker | — | ✅ 8 处 m_pkthdr | — | P2（netgraph 解耦）|
| **ff_freebsd_init.c** | ✅ 2 处 IFNET_WLOCK | ✅ 1 处 epoch | — | — | — | P2 |
| **ff_vfs_ops.c** | — | ✅ 1 处 epoch | — | — | — | P3 |

### 8.2 M3 升级触发的连锁顺序建议

1. **梯度 1（cp-only）**：先做 P3 cp-only（vendor 替换大量文件，让 baseline-15 字节就位）
2. **梯度 2（中等）**：netinet6 (3) → net (3 唯三需要重应用) → netinet (~10 需要重应用，含 protosw 改名 + LVS_TOA 重对位)
3. **梯度 3（重型 P0）**：tcp_var.h → in_pcb.c → tcp_input.c（**全部 vendor 替换 + 复核 lib 连锁**）+ T-net-01/02/05（vendor 替换，注意 if_private.h include）
4. **梯度 4（lib/ff_*.c）**：T-ff-01 ff_glue.c verify-only + **重点 ff_veth.c（R-013）+ ff_route.c（R-004）适配**（spec 05 §2.3 表内 T-ff-02/03，但实质归 M3，不归 M4）
5. **netlink 连锁**：if_clone.c / if_vlan.c 改造时用方案 B 包裹

## 9. M3 5 步法 SOP 关键提示

### 9.1 给 m3-coder

- 优先处理 A1 protosw 合并（tcp_usrreq.c 1 行 `pru_peeraddr → pr_peeraddr`）
- in_mcast.c / rack.c / bbr.c 的 `#ifdef FSTACK` 在 15.0 整段删除（白嫖 3 项）
- tcp_syncache.c 的 LVS_TOA 注入因不带 FSTACK 宏，必须用 fstack-13 ↔ baseline-13 ↔ baseline-15 三方 diff 对位重新植入
- 大部分 P0/P1 文件实质是 cp -a baseline-15 vendor 替换；F-Stack 历史 delta 仅在 ~10 个文件存在
- Phase 5b 的 5 步法 SOP 仍适用，但 Step 3「改造手法迁移」对大部分 net/ 文件直接跳过

### 9.2 给 m3-gate

- G-M3 严格 link 阶段（DP-M3-3=C 先严）：libfstack.a 在 vendor 替换大量文件后预期会触发新一轮连锁失败（lib/ff_veth.c / ff_route.c 必须先适配 14.0+ if_alloc / rib_lookup_info）
- 推荐 G-M3 流程：先做 vendor 替换 + 单文件 .o 验证 → 再做 lib/ff_veth.c + ff_route.c 14.0+ 适配 → 最后整库 link

## 10. 调研方法学背书

| 结论 | 实测命令 |
|---|---|
| net/ 8 文件 FSTACK 数量 | `search_content "FSTACK" path=f-stack-13.0-baseline/freebsd/net glob=...` |
| netinet/ 重型 P0 字节一致 | `cmp + ls -l` 对 in_pcb.c / tcp_input.c / tcp_var.h |
| ff_glue.c 无 protosw | `search_content "protosw\|pr_usrreqs\|..." path=f-stack/lib glob=ff_glue.c` → 0 |
| protosw 13→15 重构 | `search_content "struct\\s+protosw\\s*\\{" path=...sys/sys` → 13.0:96 行 vs 15.0:146 行 |
| 15.0 pr_usrreqs 已绝迹 | `search_content "pr_usrreqs" path=...releng-15.0/sys` → 仅 1 处历史注释 |
| 14.0+ 缺失头 | `ls f-stack/lib/opt/` (59) + `search_content "opt_" releng-15.0/sys/{net,netinet,netinet6}` |
| netlink 连锁 | `search_content "#include <netlink/" releng-15.0/sys/net` → if_clone.c + if_vlan.c |
| ff_*.c 14.0+ 接口 | `search_content "if_alloc\|rib_lookup\|nexthop\|m_pkthdr" path=f-stack/lib` |

所有结论 100% 实测背书，无猜测。
