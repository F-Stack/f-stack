# 04 — 13↔15 差异分析与移植策略（Diff & Port Strategy）

> English version: ../04-diff-and-port-strategy.md

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-26）；§11 于 2026-06-22 增补
> 数据来源：**Sub-Agent A + B + C 三路调研交叉** + 02 / 03 文档汇总
> 本文档是整个 Spec 系列**最核心的可执行产物**，后续 AI 代理可直接据此拾取 port 任务
>
> **2026-06 补充**：新增 **§11「13.0 FSTACK 定制未移植 15.0 gap 扫描清单」**，登记 13.0 baseline 有 `FSTACK` 标记而当前 15.0 缺失/未移植/不适用的改动（供用户决策，非实施）。

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

## 2. F-Stack 实际链接清单（来自 `f-stack/lib/Makefile` 全量抽取）

> 本节为 `f-stack/lib/Makefile`（765 行，16 个 `*_SRCS` 变量、24 处 `+=`）的完整结构化展开，**已订正 2026-05-28，详见 `99-review-report.md` §12.4**。
> - 数据来源：`grep -nE '^[A-Z_]+_SRCS' /data/workspace/f-stack/lib/Makefile` + `sed -n` 直接抽取
> - 每节标注变量名、来源 VPATH（即 `sys/` 子目录）、默认与各条件块文件清单
> - 真正影响"是否需要 port"的过滤器：只有列在 `*_SRCS` 中的文件才会被链接进 `libff.a`，未列出的 freebsd 文件可以延后或永不处理

变量索引（共 16 个 `_SRCS`，按 Makefile 出现顺序）：

| # | 变量 | 默认数 | 条件分支 | 主要来源 VPATH |
|---|---|---:|---|---|
| 1 | `FF_SRCS` | 17 | `FF_NETGRAPH` (+2) | F-Stack 自家 `lib/`（`ff_*.c`） |
| 2 | `FF_HOST_SRCS` | 9 | `FF_KNI` (+1) / `FF_USE_PAGE_ARRAY` (+1) / `!FreeBSD && !FF_KNI` (+1, dup) | F-Stack 自家 `lib/`（`ff_*.c` 用户态部分） |
| 3 | `CRYPTO_SRCS` | 2 / 14 | else 默认 2；`FF_IPSEC` 14 | `sys/crypto/` 各算法子目录 |
| 4 | `KERN_SRCS` | 38 | — | `sys/kern/` |
| 5 | `KERN_MHEADERS` / `KERN_MSRCS` | 3 / 1 | — | `sys/kern/`（`*.m` 接口模板） |
| 6 | `LIBKERN_SRCS` | 7 / 6 | `arm64` 7；else 6 | `sys/libkern/` |
| 7 | `MACHINE_SRCS` | 1 | — | `sys/${MACHINE_CPUARCH}/${MACHINE_CPUARCH}/` |
| 8 | `NET_SRCS` | 33 | — | `sys/net/` + `sys/net/route/` |
| 9 | `NETGRAPH_SRCS` | 0 / 43 | `FF_NETGRAPH` 43 | `sys/netgraph/` |
| 10 | `NETINET_SRCS` | 44 | — | `sys/netinet/` + `sys/netinet/cc/` + `sys/netinet/libalias/` |
| 11 | `NETINET6_SRCS` | 0 / 29 | `FF_INET6` 29 | `sys/netinet6/` |
| 12 | `EXTRA_TCP_STACKS_SRCS` | 0 | `FF_TCPHPTS` (+1) / `FF_EXTRA_TCP_STACKS` (+7) | `sys/netinet/tcp_stacks/` |
| 13 | `NETIPFW_SRCS` | 0 / 13 | `FF_IPFW` 13 | `sys/netpfil/ipfw/` + `sys/netpfil/ipfw/pmod/` |
| 14 | `NETIPSEC_SRCS` | 0 / 10 | `FF_IPSEC` 10 | `sys/netipsec/` |
| 15 | `OPENCRYPTO_SRCS` (+ MHEADERS/MSRCS) | 0 / 6 (+1 m) | `FF_IPSEC` 6 | `sys/opencrypto/` |
| 16 | `VM_SRCS` | 1 | — | `sys/vm/` |
| 17 | `ASM_SRCS` | `${CRYPTO_ASM_SRCS}` | 由 mk 文件生成 | `sys/crypto/.../*.S` |
| 18 | `HOST_SRCS` | `${FF_HOST_SRCS}` | 别名 | 同 `FF_HOST_SRCS` |

> 注：以默认配置（`FF_INET6=1, FF_TCPHPTS=1, FF_EXTRA_TCP_STACKS=1`，无 `FF_NETGRAPH/FF_IPFW/FF_IPSEC/FF_USE_PAGE_ARRAY/FF_LOOPBACK_SUPPORT/FF_ZC_SEND`）下，链接进 `libff.a` 的 `.c` 文件总数：FF_SRCS(17) + FF_HOST_SRCS(9) + CRYPTO_SRCS(2) + KERN_SRCS(38) + LIBKERN_SRCS(6) + MACHINE_SRCS(1) + NET_SRCS(33) + NETINET_SRCS(44) + NETINET6_SRCS(29) + EXTRA_TCP_STACKS_SRCS(8) + VM_SRCS(1) = **188 个 `.c`**（不含 `*.m` 与 ASM）。

### 2.1 `FF_SRCS`（F-Stack 自家内核胶水层，共 17，`FF_NETGRAPH` +2）

**默认（17）**：
```
ff_compat.c, ff_glue.c, ff_freebsd_init.c, ff_init_main.c,
ff_kern_condvar.c, ff_kern_environment.c, ff_kern_intr.c,
ff_kern_subr.c, ff_kern_synch.c, ff_kern_timeout.c, ff_subr_epoch.c,
ff_lock.c, ff_syscall_wrapper.c, ff_subr_prf.c, ff_vfs_ops.c,
ff_veth.c, ff_route.c
```

**`ifdef FF_NETGRAPH` 增加 2**：
```
ff_ng_base.c, ff_ngctl.c
```

### 2.2 `FF_HOST_SRCS`（F-Stack 用户态部分，默认 9，多条件可加）

**默认（9）**：
```
ff_host_interface.c, ff_thread.c, ff_config.c, ff_ini_parser.c,
ff_dpdk_if.c, ff_dpdk_pcap.c, ff_epoll.c, ff_log.c, ff_init.c
```

**`ifdef FF_KNI` 增加 1**：
```
ff_dpdk_kni.c
```

**`ifdef FF_USE_PAGE_ARRAY` 增加 1**：
```
ff_memory.c
```

**`ifneq ($(TGT_OS),FreeBSD) && ifndef FF_KNI` 增加 1**（与 `FF_KNI` 互斥的非 FreeBSD 旁路）：
```
ff_dpdk_kni.c
```

### 2.3 `CRYPTO_SRCS`（来自 `sys/crypto/...`，`FF_IPSEC` 决定大小）

**默认 / else（无 `FF_IPSEC`，2 个）**：
```
sha1.c, siphash.c
```

**`ifdef FF_IPSEC`（14 个）**：
```
aesni_wrap.c, bf_ecb.c, bf_enc.c, bf_skey.c, camellia.c,
camellia-api.c, des_ecb.c, des_enc.c, des_setkey.c,
rijndael-alg-fst.c, rijndael-api.c, sha1.c, sha256c.c, sha512c.c,
siphash.c
```
> Makefile 行 301 中 `aesni.c` 被注释（`#aesni.c`），实际不参与链接。

### 2.4 `KERN_SRCS`（38 个，全部来自 `sys/kern/`，无条件）

```
kern_descrip.c, kern_event.c, kern_fail.c, kern_khelp.c, kern_hhook.c,
kern_linker.c, kern_mbuf.c, kern_module.c, kern_mtxpool.c,
kern_ntptime.c, kern_osd.c, kern_sysctl.c, kern_tc.c, kern_uuid.c,
link_elf.c, md5c.c, subr_capability.c, subr_counter.c,
subr_eventhandler.c, subr_kobj.c, subr_lock.c, subr_module.c,
subr_param.c, subr_pcpu.c, subr_sbuf.c, subr_taskqueue.c, subr_unit.c,
subr_smr.c, sys_capability.c, sys_generic.c, sys_socket.c,
uipc_accf.c, uipc_mbuf.c, uipc_mbuf2.c, uipc_domain.c,
uipc_sockbuf.c, uipc_socket.c, uipc_syscalls.c
```

### 2.5 `KERN_MHEADERS` / `KERN_MSRCS`（接口模板）

`KERN_MHEADERS`（3 个 `.m`，`MHEADERS = $(patsubst %.m,%.h,...)`）：
```
bus_if.m, device_if.m, linker_if.m
```

`KERN_MSRCS`（1 个）：
```
linker_if.m
```

### 2.6 `LIBKERN_SRCS`（按架构分支，arm64 7 / else 6，无 `gsb_crc32` 仅 arm64）

**`ifeq (${MACHINE_CPUARCH},arm64)`（7 个）**：
```
bcd.c, inet_ntoa.c, jenkins_hash.c, strlcpy.c, strnlen.c, fls.c, flsl.c
```

**else（amd64 / arm / i386 / aarch64 / mips，6 个）**：
```
bcd.c, gsb_crc32.c, inet_ntoa.c, jenkins_hash.c, strlcpy.c, strnlen.c
```

### 2.7 `MACHINE_SRCS`（1 个，来自 `sys/${MACHINE_CPUARCH}/${MACHINE_CPUARCH}/`）

```
in_cksum.c
```

### 2.8 `NET_SRCS`（33 个，来自 `sys/net/` + `sys/net/route/`）

```
bpf.c, bridgestp.c, if.c, if_bridge.c, if_clone.c, if_dead.c,
if_ethersubr.c, if_loop.c, if_llatbl.c, if_media.c, if_spppfr.c,
if_spppsubr.c, if_vlan.c, if_vxlan.c, in_fib.c, in_gif.c, ip_reass.c,
netisr.c, pfil.c, radix.c, raw_cb.c, raw_usrreq.c, route.c,
route_ctl.c, route_tables.c, route_helpers.c, route_ifaddrs.c,
route_temporal.c, nhop_utils.c, nhop.c, nhop_ctl.c, rtsock.c,
slcompress.c
```
> 注：本节明确包含 13.0 版本的 `route_*.c` / `nhop*.c`；15.0 routing/rib/nexthop 重写后这些文件**全数受 R-014 影响**（详见 03 §3.8）。

### 2.9 `NETGRAPH_SRCS`（默认 0，`FF_NETGRAPH` 时 43 个，来自 `sys/netgraph/`）

**`ifdef FF_NETGRAPH`（43 个）**：
```
ng_async.c, ng_atmllc.c, ng_bridge.c, ng_car.c, ng_cisco.c,
ng_deflate.c, ng_echo.c, ng_eiface.c, ng_etf.c, ng_ether.c,
ng_ether_echo.c, ng_frame_relay.c, ng_gif.c, ng_gif_demux.c,
ng_hole.c, ng_hub.c, ng_iface.c, ng_ip_input.c, ng_ipfw.c,
ng_ksocket.c, ng_l2tp.c, ng_lmi.c, ng_nat.c, ng_one2many.c,
ng_parse.c, ng_patch.c, ng_pipe.c, ng_ppp.c, ng_pppoe.c, ng_pptpgre.c,
ng_pred1.c, ng_rfc1490.c, ng_sample.c, ng_socket.c, ng_source.c,
ng_split.c, ng_sppp.c, ng_tag.c, ng_tcpmss.c, ng_tee.c, ng_UI.c,
ng_vjc.c, ng_vlan.c
```

### 2.10 `NETINET_SRCS`（44 个，无条件，来自 `sys/netinet/` + `cc/` + `libalias/`）

```
if_ether.c, if_gif.c, igmp.c, in.c, in_mcast.c, in_pcb.c, in_proto.c,
in_rmx.c, ip_carp.c, ip_divert.c, ip_ecn.c, ip_encap.c, ip_fastfwd.c,
ip_icmp.c, ip_id.c, ip_input.c, ip_mroute.c, ip_options.c, ip_output.c,
raw_ip.c, tcp_debug.c, tcp_hostcache.c, tcp_input.c, tcp_lro.c,
tcp_offload.c, tcp_output.c, tcp_reass.c, tcp_sack.c, tcp_subr.c,
tcp_syncache.c, tcp_timer.c, tcp_timewait.c, tcp_usrreq.c,
udp_usrreq.c, cc.c, cc_newreno.c, cc_htcp.c, cc_cubic.c, alias.c,
alias_db.c, alias_mod.c, alias_proxy.c, alias_sctp.c, alias_util.c
```
> 注：包含 13.0 时代的 `tcp_debug.c`（15.0 已删除）；本节多个 TCP 文件直接受 R-001 / R-002 / R-005（pr_usrreqs / inpcb SMR / mbuf）影响。

### 2.11 `NETINET6_SRCS`（默认 0，`FF_INET6` 时 29 个，来自 `sys/netinet6/`）

**`ifdef FF_INET6`（29 个）**：
```
dest6.c, frag6.c, icmp6.c, in6.c, in6_ifattach.c, in6_mcast.c,
in6_pcb.c, in6_pcbgroup.c, in6_proto.c, in6_rmx.c, in6_src.c,
ip6_forward.c, ip6_id.c, ip6_input.c, ip6_fastfwd.c, ip6_mroute.c,
ip6_output.c, mld6.c, nd6.c, nd6_nbr.c, nd6_rtr.c, raw_ip6.c, route6.c,
scope6.c, send.c, udp6_usrreq.c, in6_cksum.c, in6_fib.c, in6_gif.c
```
> Makefile 行 555-558 中 `ip6_gre.c` / `ip6_ipsec.c` / `sctp6_usrreq.c` / `in6_rss.c` 被注释（`#`），不参与链接。

### 2.12 `EXTRA_TCP_STACKS_SRCS`（按 `FF_TCPHPTS` / `FF_EXTRA_TCP_STACKS` 分支累加）

**`ifdef FF_TCPHPTS`（+1）**：
```
tcp_hpts.c
```

**`ifdef FF_EXTRA_TCP_STACKS`（+7）**：
```
subr_filter.c, tcp_ratelimit.c, arc4random_uniform.c, sack_filter.c,
rack_bbr_common.c, rack.c, bbr.c
```

### 2.13 `NETIPFW_SRCS`（默认 0，`FF_IPFW` 时 13 个，来自 `sys/netpfil/ipfw/`）

**`ifdef FF_IPFW`（13 个）**：
```
ip_fw_dynamic.c, ip_fw_eaction.c, ip_fw_iface.c, ip_fw_log.c,
ip_fw_nat.c, ip_fw_pfil.c, ip_fw_sockopt.c, ip_fw_table.c,
ip_fw_table_algo.c, ip_fw_table_value.c, ip_fw2.c, ip_fw_pmod.c,
tcpmod.c
```

### 2.14 `NETIPSEC_SRCS`（默认 0，`FF_IPSEC` 时 10 个，来自 `sys/netipsec/`）

**`ifdef FF_IPSEC`（10 个）**：
```
ipsec.c, ipsec_input.c, ipsec_mbuf.c, ipsec_output.c, key.c,
key_debug.c, keysock.c, xform_ah.c, xform_esp.c, xform_ipcomp.c
```
> Makefile 行 617-618 注释了 `xform_tcp.c`（仅当 `TCP_SIGNATURE` 定义时启用）。

### 2.15 `OPENCRYPTO_SRCS` / `OPENCRYPTO_MHEADERS` / `OPENCRYPTO_MSRCS`

**`ifdef FF_IPSEC`（6 个）**：
```
criov.c, crypto.c, cryptosoft.c, cryptodeflate.c, rmd160.c, xform.c
```
> Makefile 行 631 注释了 `cryptodev.c`。

**`OPENCRYPTO_MHEADERS`（无条件 1）**：`cryptodev_if.m`
**`OPENCRYPTO_MSRCS`（无条件 1）**：`cryptodev_if.m`

### 2.16 `VM_SRCS`（1 个，无条件，来自 `sys/vm/`）

```
uma_core.c
```

### 2.17 间接变量：`ASM_SRCS` 与 `HOST_SRCS`

- `ASM_SRCS+= ${CRYPTO_ASM_SRCS}`：由 `mk/kern.pre.mk` 体系基于架构动态生成（amd64 / arm64 / x86 各架构的 SHA / AES / ChaCha 优化汇编），不在 Makefile 文本中静态枚举
- `HOST_SRCS+= ${FF_HOST_SRCS}`：等同于 `FF_HOST_SRCS`（见 §2.2），仅作为目标变量传入用户态构建链

### 2.18 mips 架构在 `f-stack/lib/Makefile` 中的实际形态

Makefile 行 197-207 的 `ifeq (${MACHINE_CPUARCH},mips)` 块只设置 `ARCH_FLAGS=-march=mips32` 和 `HACK_EXTRA_FLAGS=-shared`，**不引用任何 `*_SRCS+=`**。这意味着 13.0 时代的 F-Stack mips 路径仅有编译参数，**没有对应的链接文件清单**。结合 03 §2.1（15.0 上游 mips 整体移除）、03 §3.7（mips 删除任务），mips 在 `lib/Makefile` 中的逻辑残留可与 `freebsd/mips/` 删除任务一并清理（详见 03 §3.7 / 04 §3.7）。


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

### 9.1 任务数口径关系（2026-05-28 增补；响应审计 §6.2-2）

本系列 spec 中先后出现 **57 / 75 / 24 / 18 / 19** 五个数字，分别属于不同观察维度。为避免歧义，统一台账如下：

| 维度 | 数字 | 含义 | 唯一基准位置 |
|---|---:|---|---|
| **全局任务总数（实施基准）** | **75** | 含 cp -a 直拷类（M1/M2/M3/M4 批量任务）+ 移植类 | `05-implementation-plan.md §3` 行 204 |
| **狭义移植任务（差异分析视角）** | **57** | 仅 04 §3 交集热点 + ff_*/tools 改造，**不含 cp -a 直拷** | `04-diff-and-port-strategy.md §9`（本表） |
| **P0 任务（实施视角）** | **18** | 按 75 任务中文件级"必修"项归并；mips 整体清理算 1 项 | `05 §3` 行 204 |
| **P0 任务（风险视角）** | **19** | 按 6 项 P0 风险归属计数；mips "整体清理"被拆为"目录删除 + Makefile 改造"2 步 | `99-review-report.md §4.2` |
| **P0 移植任务（04 §9 表内 P0 行）** | **24** | 04 §9 P0 行 = kern 4 + netinet 5 + net 5 + ff 4 + cleanup 1 + tools 5；统计单元为"移植决策点"而非"实施任务" | 本表 |

**唯一全局基准 = 05 §3 的 75 任务 / 18 P0**。其它四个数字是不同视角的子集或附属视角，不再视为独立口径：

- 75 - 57 = 18 个 cp -a 直拷类任务（在 05 §3 的 M1/M2/M3/M4 中各占数项；详见 05 §3 行 206 注释）
- 18 vs 19：`99 §4.3 RI-01` 已记录为 P3 信息项（mips 是目录级清理，按风险归属拆 2 项 = 19，按实施任务归并 1 项 = 18）
- 24 是 04 §9 表内"移植决策点"分类合计，与 18 的差距来源是：(a) 04 §9 把"tools 大改"统计为 5 个决策点，但 05 §3 把它拆到 M5 的 15 个 tools 任务里再以 P0 计 3 项；(b) 04 §9 不含"05 视角下的纯 cp -a 任务"。

后续 PM/QA 引用任务数时，**应**优先使用 75 / 18 / 57，并标注是否含 cp -a 直拷；引用 24 / 19 时应注明视角（"04 §9 移植决策点 P0" / "99 §4.2 风险归属 P0"）。详见 `99-review-report.md §12.8`。

---

## 10. 与其他文档的衔接

| 本节产物 | 衔接对象 |
|---|---|
| §3 交集热点（57 个 T-* 任务） | `05-implementation-plan.md` §3 任务分配 |
| §6 5 步法 | `05-implementation-plan.md` §4 SOP |
| §1 子目录 diff 全景 | `06-test-and-acceptance-spec.md` §1 编译矩阵 |
| §7 风险策略对照 | `99-review-report.md` 风险覆盖度审查 |

> 下一步：`05-implementation-plan.md` 把 57 个 T-* 任务拆到 M1-M5，给出资源、时序、回滚方案。

---

## 11. 13.0 FSTACK 定制未移植 15.0 gap 扫描清单（2026-06 补充）

> 本节是「**供用户决策的 gap 扫描登记**」，不是实施方案。目的：把 13.0 baseline 上带 `FSTACK` 标记、而当前 15.0 工作树缺失/未移植/不适用的定制改动逐条登记、定性、给决策建议。
> 本节不重复 §3-§6 的 port 任务方法论；其中 #1/#2（IP_BIND/RSS bind-then-connect）的**详细方案不在本 spec 重复**，指向独立 spec `docs/ff_rss_check_opt_spec/zh_cn/` 的 **R-E**（见该系列 `01-需求规格.md` §0.5 R-E）。

### 11.1 扫描方法与数据口径

- **方法**：对两侧 `freebsd/` 子树分别 `git grep -l FSTACK`（含 `#ifdef FSTACK` / `#ifndef FSTACK` / `#ifdef FF_*` 等定制标记）得到「带 FSTACK 标记文件集合」，做集合 diff；再对差异文件做内容级（函数/hunk 级）人工比对。
- **对比基线**：
  - 13.0 baseline = `/data/workspace/f-stack-13.0-baseline/freebsd/`（**46 个** FSTACK 标记文件）
  - 当前 15.0 = `/data/workspace/f-stack/freebsd/`（**41 个** FSTACK 标记文件）
- **扫描时间**：2026-06-22。
- **证据口径**：每条结论给 `文件:行号`；不确定项标「待确认」；复核与 arch-probe 初稿不一致处在 §11.6 单列。
- **本节范围铁律**：只做 gap 登记 + 决策建议，**不改任何 `lib/freebsd` 代码、不提交代码**。

### 11.2 文件集合差异（FSTACK 标记文件）

> 文件名相对各自 `freebsd/` 根。

**A. baseline 有 / 当前无 FSTACK 标记（8 个）**

| # | 文件 | 备注 |
|---|---|---|
| 1 | `netgraph/ng_socket.c` | 当前文件存在，但 FSTACK 屏蔽未移植（见 gap #6） |
| 2 | `net/if_spppsubr.c` | 15.0 仍有该文件但 FSTACK hunk 未移植；log() 屏蔽（见 gap #9） |
| 3 | `netinet6/in6_mcast.c` | mcast 大结构分配未移植（见 gap #4） |
| 4 | `netinet/in_mcast.c` | mcast 大结构分配未移植（见 gap #3） |
| 5 | `netinet/tcp_usrreq.c` | require_unique_port 屏蔽，15.0 已无该路径（见 gap #5） |
| 6 | `netpfil/ipfw/ip_fw2.c` | 已用 stub 等价移植（见 gap #7） |
| 7 | `netpfil/ipfw/ip_fw_log.c` | 已用 stub 等价移植（见 gap #8） |
| 8 | `sys/namei.h` | 15.0 NDFREE 宏重构，不适用（见 gap #10） |

**B. 当前有 / baseline 无 FSTACK 标记（3 个）**

| # | 文件 | 性质 |
|---|---|---|
| 1 | `netinet6/in6_pcb.c` | **15.0 新增定制**：已含 RSS `INPLOOKUP_LPORT_RSS_CHECK`，但 bind-then-connect 未闭合（= gap #2） |
| 2 | `arm64/vmparam.h` | 15.0 新增适配，**非 gap**；如需可后续补查（待确认是否纯架构跟随） |
| 3 | `sys/syscallsubr.h` | 15.0 新增适配，**非 gap**；如需可后续补查 |

### 11.3 gap 清单主表（10 项）

> 行号已逐项 `read_file`/`grep` 复核（2026-06-22）；与 arch-probe 初稿不一致处见 §11.6。
> 简记：`B:` = `f-stack-13.0-baseline/freebsd/`；`C:` = `f-stack/freebsd/`（当前 15.0 工作树）。

| # | 文件:函数 | 13.0 定制语义 | 15.0 现状 | 必要性 | 风险 | 决策建议 |
|---|---|---|---|---|---|---|
| 1 | `netinet/in_pcb.c`（IP_BIND v4） | RSS 端口范围 / lport 检查 / IP_BIND_ADDRESS_NO_PORT 相关 hunk1/hunk2 | **未移植**：`C:netinet/in_pcb.c` grep `IP_BIND_ADDRESS_NO_PORT` / `INPLOOKUP_LPORT_RSS_CHECK` = **0 命中**；hunk3 等价能力 15.0 connect 重构已含 | **高** | bind(addr,0)-then-connect 绕过 RSS 选端口，连接 RSS 落核错配 | **优先决策**；详细方案见 `ff_rss_check_opt_spec` **R-E**，本表只登记 |
| 2 | `netinet6/in6_pcb.c`（IP_BIND v6） | 13.0 无此能力 | **部分**：RSS 框架已具备（`C:netinet6/in6_pcb.c:521` `INPLOOKUP_LPORT_RSS_CHECK`），但 bind 阶段 `in6_pcbbind` 提前分配端口（`C:...:354` `if (lport==0) in6_pcbsetport(...)`），导致 connect 期 RSS 条件（`C:...:515-516` `IN6_IS_ADDR_UNSPECIFIED && inp_lport==0`）被破，**bind-then-connect 未闭合** | **中-高** | 同 #1 的 v6 版本 | 建议**随 R-E 同步**决策；方案见 `ff_rss_check_opt_spec` R-E |
| 3 | `netinet/in_mcast.c::imf_get_source` | FSTACK 用 `malloc(sizeof(struct ip_msource))` 替代 `in_msource`（`B:netinet/in_mcast.c:763-767` `#ifdef FSTACK`），意在按大结构分配防 RB 树越界 | **不适用/上游设计正确**：15.0 两棵 `ip_msource_tree` 严格分层——socket 层 `imf->imf_sources` 节点全按小结构 `in_msource` 分配（`C:netinet/in_mcast.c:749/780`）且遍历时只 cast `in_msource` 读 `imsl_st`（`C:...:829/856/872/888/1026`）；in-kernel 层 `inm->inm_srcs` 节点按大结构 `ip_msource` 分配（`C:...:698/942`），`ims_get_mode(inm,ims,1)`（`C:...:2907`）的 `ims` 来自 `RB_FOREACH(...,&inm->inm_srcs)`（`C:...:2901`） | **低** | **无越界**：socket 层小节点从不被 `ims_get_mode` 访问 `ims_st`，字段与结构一一匹配（详见 §11.5/§11.6 leader 实证裁决） | 归类 (c)，**无需移植**（13.0 FSTACK 大结构分配为旧代码历史 workaround，15.0 上游已无此必要） |
| 4 | `netinet6/in6_mcast.c`（v6 版） | 同 #3 的 v6 版，FSTACK 用 `ip6_msource` 大小（`B:netinet6/in6_mcast.c:765/796` 区域 `#ifdef FSTACK`） | **不适用/上游设计正确**：同 #3，v6 两树同样严格分层（socket 层 `in6_msource` / in-kernel 层 `ip6_msource`），字段与结构匹配 | **低** | **无越界**（同 #3 v6 版） | 归类 (c)，**无需移植**（同 #3） |
| 5 | `netinet/tcp_usrreq.c::tcp_connect` | `#ifndef FSTACK` 跳过 `tcp_require_unique_port → in_pcbbind`（`B:netinet/tcp_usrreq.c:1602-1607`；sysctl 定义 `B:...:153`） | **不适用/天然等价**：`C:freebsd/` 全树 grep `require_unique_port` = **0 命中**，该 sysctl 路径 15.0 已不存在；15.0 行为天然等价于 baseline FSTACK 屏蔽后行为 | **低** | 无（路径不存在） | 归类 (c)，**无需移植** |
| 6 | `netgraph/ng_socket.c`（NGM_MKPEER） | `#ifndef FSTACK` 跳过 `kern_kldload`（动态加载 ng 模块）（`B:netgraph/ng_socket.c:290`） | **未移植**：`C:netgraph/ng_socket.c:293` 直接调 `kern_kldload`，无 `#ifndef FSTACK` | **中** | 用户态 f-stack 无 kldload，运行到 NGM_MKPEER 该路径可能失败；非默认路径，仅 `FF_NETGRAPH` 开启且动态建节点时触发 | 建议补 `#ifndef FSTACK`（仅 `FF_NETGRAPH` 用户需要） |
| 7 | `netpfil/ipfw/ip_fw2.c` | `#ifndef FSTACK` 跳过 `sctp_calculate_cksum`、`ipfw_bpf_init/uninit`（`B:netpfil/ipfw/ip_fw2.c:615/3702/3770`） | **已等价移植**：改「编译排除」为「link-only stub」——`C:lib/ff_stub_14_extra.c:828-853`（`ipfw_bpf_init` 828 / `ipfw_bpf_uninit` 834 / `ipfw_bpf_tap` 840 / `sctp_calculate_cksum` 847，均 no-op，M5/M6） | — | 已处理（行为等价：符号存在但 no-op） | 归类 (b)，**无需额外动作**；仅留档 |
| 8 | `netpfil/ipfw/ip_fw_log.c` | `#ifndef FSTACK` 跳过 `ipfw_bpf_tap/mtap/mtap2`（`B:netpfil/ipfw/ip_fw_log.c:103/106` 区域） | **已等价移植**：`C:lib/ff_stub_14_extra.c` 提供 stub——`ipfw_bpf_mtap` 866 / `ipfw_bpf_mtap2` 872 / `ipfw_bpf_tap` 840；另补 `prng32_bounded` 860（M6 第二次链接 surfaced） | — | 已处理 | 归类 (b)，**无需额外动作**；仅留档 |
| 9 | `net/if_spppsubr.c::sppp_print_bytes` | `#ifndef FSTACK` 跳过 `log()` | **不适用（文件不存在）**：当前 `f-stack/freebsd/` 全树搜 `if_spppsubr*` = **0 命中**，文件**不存在**（FreeBSD 15.0 已移除 sppp 源）。§2.8 `NET_SRCS` 文本列表中的 `if_spppsubr.c` 为残留条目，不代表实体文件存在 | — | 无（文件不存在，无可移植对象） | 归类 (c)，**无需移植**。**详见 §11.6 leader 实证裁决** |
| 10 | `sys/namei.h`（NDFREE 宏） | `#ifndef FSTACK` 屏蔽旧 `NDFREE()` 宏（`B:sys/namei.h:277` 区域） | **不适用/已重构**：15.0 已删旧 `NDFREE` 宏，改为 `NDFREE_IOCTLCAPS`（`C:sys/namei.h:290`）/ `NDFREE_PNBUF`（`C:sys/namei.h:297`）。旧宏不存在则旧 FSTACK 屏蔽自然失效 | **低** | 取决于调用方是否已全改用新宏（见 §11.5 待确认） | 归类 (c)；**待确认**调用方已迁移后即可忽略 |

### 11.4 三分类归纳

- **(a) 确认未移植且应移植**：
  - **#1** IP_BIND v4（**高**，已有 `ff_rss_check_opt_spec` R-E 方案）
  - **#2** IP_BIND v6 / bind-then-connect（**中-高**，随 R-E 同步）
  - **#6** `ng_socket.c` kldload 屏蔽（**中**，仅 `FF_NETGRAPH` 用户）
- **(b) 已用 15.0 等价方式移植（仅留档，无需动作）**：
  - **#7 / #8** ipfw → `lib/ff_stub_14_extra.c` link-only stub
  - **#1 的 hunk3** → 15.0 connect 重构已含 `RSS_CHECK` 等价能力
- **(c) 13.0 特有但 15.0 不适用 / 天然等价**：
  - **#3 / #4** mcast 源过滤节点分配（15.0 两树严格分层、字段与结构匹配，**不越界**，上游设计正确，见 §11.5/§11.6）
  - **#5** `tcp_require_unique_port`（15.0 已无该路径）
  - **#9** `if_spppsubr.c`（文件 15.0 不存在，无可移植对象，见 §11.6）
  - **#10** `namei.h` NDFREE 宏（15.0 重构为新宏）

### 11.5 待人工确认 / 卡点

| 项 | 待确认内容 | 复核进展（2026-06-22） |
|---|---|---|
| #3/#4 RB 树字段访问 | 15.0 RB 树代码是否实际访问 `ims_st`/`ims_stp` 字段，从而坐实小结构分配越界 | **已实证：不越界（leader 裁决）**。15.0 两棵 `ip_msource_tree` 严格分层：socket 层 `imf->imf_sources` 节点按小结构 `in_msource` 分配（`C:netinet/in_mcast.c:749/780`），遍历时全部 `lims=(struct in_msource *)ims` 仅访问 `imsl_st`（`C:...:829/856/872/888/1026`），**从不访问 `ims_st`**；唯一访问 `ims_st` 的 `ims_get_mode`（`C:in_var.h:346-356`）其 `ims` 来自 `inm->inm_srcs`（大结构树，`C:in_mcast.c:2901→2907`），`ims_merge`（`C:...:965/1034`）第一参 `nims` 同来自 `inm_srcs`、第二参 `lims` 为小结构仅读 `imsl_st`。字段与结构一一匹配，**无越界**。结论：#3/#4 归 (c)，13.0 FSTACK 大结构分配为旧代码历史 workaround，15.0 无此必要 |
| #5 require_unique_port 全仓搜 | 15.0 是否别处仍有 `require_unique_port` 逻辑 | **已确认**：`C:freebsd/` 全树 grep = **0 命中**，路径确不存在，#5 归 (c) 成立 |
| #6 ng_socket 是否补屏蔽 | 是否需为 `kern_kldload` 补 `#ifndef FSTACK` | **未决（留用户决策）**：仅 `FF_NETGRAPH` + 动态建节点路径触发；建议补但优先级中 |
| #10 NDFREE 调用方 | 15.0 链接进 libff 的源是否已全部改用 `NDFREE_IOCTLCAPS`/`NDFREE_PNBUF`，无残留旧 `NDFREE()` 调用 | **未决（待人工确认）**：需对 `KERN_SRCS`/VFS 相关源 grep 旧 `NDFREE(` 调用残留 |
| B 表 #2/#3 新增文件 | `arm64/vmparam.h`、`sys/syscallsubr.h` 是否纯架构/接口跟随，确非 gap | **未深入**：标「15.0 新增定制，非 gap，如需可后续补查」 |

### 11.6 复核中发现的与 arch-probe 初稿不一致处

1. **gap #9 `if_spppsubr.c` 最终归 (c)「文件不存在」（leader 实证裁决）**：spec-writer-gap 初稿一度改为「文件仍存在且列于 `NET_SRCS`」，但 leader 复核 `search_file if_spppsubr*` 于 `f-stack/freebsd/` = **0 命中**，文件**确不存在**（FreeBSD 15.0 已移除 sppp 源）；§2.8 `NET_SRCS` 文本中的条目为残留列表项，不代表实体存在。最终裁决：arch-probe 正确，#9 归 (c)「文件不存在/无可移植对象」。
2. **gap #3/#4 mcast「越界」判断撤销（leader 实证裁决）**：spec-writer-gap 初稿一度判「越界已坐实、应升 P1」，leader 复核代码确认：socket 层 `imf->imf_sources` 小节点（`in_msource`）遍历时只读 `imsl_st`、**从不访问 `ims_st`**；唯一访问 `ims_st` 的 `ims_get_mode`（`C:in_mcast.c:2907`）其 `ims` 来自大结构树 `inm->inm_srcs`（`C:...:2901`），`ims_merge` 第一参亦来自 `inm_srcs`（`C:...:1034`）。两树严格分层、字段与结构一一匹配，**不越界**。最终裁决：撤销越界判断，#3/#4 归 (c)（13.0 FSTACK 大结构分配为旧代码历史 workaround）。
3. **gap #3 `in_var.h` 结构体行号**：arch-probe 给 `L183`(ip_msource)/`L196`(in_msource) 对应的是**当前 `f-stack/freebsd/netinet/in_var.h`**（`ip_msource` 183 / `in_msource` 196），在 **baseline** `f-stack-13.0-baseline/freebsd/netinet/in_var.h` 中则为 `196`/`209`（头部 FSTACK include 造成偏移）。本表已按「当前 15.0 文件」与「baseline 文件」分别标注。
4. **gap #6 `ng_socket.c` `kern_kldload` 行号**：baseline 为 `B:netgraph/ng_socket.c:290`；当前 15.0 为 `C:netgraph/ng_socket.c:293`。arch-probe 的 L293 指当前文件，正确。
5. **gap #5 `tcp_usrreq.c` 行号**：baseline `V_tcp_require_unique_port` 定义 **L153** ✓、`#ifndef FSTACK` 跳过块 **L1602** ✓，与 arch-probe 一致。
6. **gap #7/#8 `ff_stub_14_extra.c` 落点细化**：arch-probe 给「L828-853」为大致区间；逐函数落点为 `ipfw_bpf_init`828 / `ipfw_bpf_uninit`834 / `ipfw_bpf_tap`840 / `sctp_calculate_cksum`847 / `prng32_bounded`860 / `ipfw_bpf_mtap`866 / `ipfw_bpf_mtap2`872。
7. **gap #10 `namei.h` 行号**：当前 15.0 `NDFREE_IOCTLCAPS` **L290** ✓、`NDFREE_PNBUF` **L297** ✓，与 arch-probe 一致。

### 11.7 决策建议小结

| 优先级 | gap | 建议动作 |
|---|---|---|
| **P0（优先决策）** | #1 v4 IP_BIND | 已有 `ff_rss_check_opt_spec` R-E 完整方案，建议优先排期实施 |
| **P0-1（随 #1 同步）** | #2 v6 IP_BIND | 复用 R-E，与 #1 同批决策 |
| **P2** | #6 ng_socket kldload | 仅 `FF_NETGRAPH` 用户需要；建议补 `#ifndef FSTACK` |
| **留档（无需动作）** | #7 / #8 | 已用 stub 等价移植，仅留档 |
| **可忽略 / 不适用** | #3 / #4 / #5 / #9 / #10 | 15.0 不适用或天然等价：#3/#4 两树分层**不越界**、#5 路径已移除、#9 文件不存在；#10 待确认调用方已迁移新宏 |

> **本节产物衔接**：#1/#2 → `docs/ff_rss_check_opt_spec/zh_cn/`（R-E）；#3/#4/#6 若决策实施，按本文档 §6「5 步法」拾取，纳入 `05-implementation-plan.md` 后续里程碑（建议归 M3 网络栈 / M4 边缘子系统）。
