# 04 — 13↔15 Diff Analysis & Port Strategy

> Chinese version: ./zh_cn/04-diff-and-port-strategy.md
>
> Series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-26)
> Data source: cross-cut of three Sub-Agents A + B + C + summaries from 02 / 03
> This document is the **most actionable artifact** of the whole Spec series; downstream AI agents can directly pick up port tasks here.

---

## 0. Overall Port Strategy

**Core idea**: **redo** the "subset + F-Stack adaptation" baseline on top of 15.0 upstream `sys/`, instead of "patching" the 13.0-adapted result.

Rationale:
1. 13→15 spans 2 major versions with 6 P0 KBI/KPI breakages; on the patch path every file requires a 3-way merge — workload comparable to a redo but error rate higher
2. The 15.0 backup is already in place (Phase 1.4 produced 25,044 files), so cp + adapt is feasible directly
3. The adaptation patterns are already grouped into 9 tags in 02, so they can be reused in batches

**Core flow**:

```
(baseline) 15.0 upstream sys/                              (target) f-stack/freebsd/
        │                                                          ▲
        ├─→ cp -a → f-stack-lib/freebsd/  (done in Phase 1.4)      │
        │                                                          │
        └─→ apply the 9 adaptation patterns from 02 ───────────────┘
                  ↑
            (target each adaptation point per the P0 risks in 03)
```

---

## 1. Subdirectory-Level Diff Panorama (measured)

> **Data convention (corrected on 2026-05-28; see `99-review-report.md` §12.3)**:
> - **13 / 15 columns**: total `*.c` / `*.h` / `*.S` files under that subdir recursively (`find -type f`)
> - **DEL / NEW / MOD columns**: file-level measurement based on `diff -rq freebsd-src-releng-{13.0,15.0}/sys/<subdir>`; DEL = only in 13.0, NEW = only in 15.0, MOD = present in both but content differs
> - **MOD count is absolute** (no longer "heuristic: any size change is MOD"), so it is generally higher than the v0.1 estimate of this table
> - **P column**: priority of the subdir's impact on F-Stack (independent of the diff figures)
> - The measurement command is in the footnote at the end of this section

| Subdir | 13 | 15 | DEL | NEW | MOD | P | F-Stack link |
|---|---:|---:|---:|---:|---:|---|---|
| **kern** | 217 | 234 | 2 | 18 | **231** | **P0** | 38 KERN_SRCS |
| **net** | 158 | 159 | 10 | 11 | **149** | **P0** | NET_SRCS (see §2.X) |
| **netinet** | 185 | 191 | 6 | 12 | **181** | **P0** | NETINET_SRCS (see §2.X) |
| **netinet6** | 59 | 57 | 2 | 0 | **57** | **P0** | NETINET6_SRCS (see §2.X) |
| **sys** (headers) | 342 | 376 | 4 | 38 | **339** | **P0** | majority of `.h` |
| **libkern** | 85 | 80 | 9 | 4 | 77 | P1 | LIBKERN_SRCS |
| **opencrypto** | 35 | 35 | 3 | 3 | 33 | P1 | OPENCRYPTO_SRCS (optional) |
| **netipsec** | 30 | 32 | 0 | 2 | 30 | P1 | NETIPSEC_SRCS (optional) |
| **netgraph** | 170 | 152 | 7 | 4 | 152 | P1 | NETGRAPH_SRCS (optional) |
| **netpfil/ipfw** | 59 | 59 | 1 | 1 | 60 | P1 | NETIPFW_SRCS (optional) |
| **vm** | 53 | 52 | 2 | 1 | 51 | P1 | VM_SRCS |
| **amd64** | 231 | 234 | 17 | 24 | 238 | P1 | very few (F-Stack picks only some `.h`) |
| **arm64** | 270 | 317 | 20 | 98 | 248 | P1 | very few (same as above) |
| **x86** | 124 | 142 | 9 | 29 | 116 | P1 | very few (same as above) |
| **crypto** (top) | 191 | 299 | 1 | 48 | 189 | P2 | not directly linked |
| **contrib** | huge | huge | many | many | thousands | P3 | only `#include`, not directly linked; this table omits exact numbers (`diff -rq` is too slow on this subdir; out of scope for this audit cycle) |
| **bsm** | 8 | 8 | 0 | 0 | 8 | P3 | not linked |
| **ddb** | 29 | 32 | 0 | 3 | 29 | P3 | not linked |
| **netlink** | — | 39 | — | — | — | DP-2 | **not introduced** (subdir does not exist in 13.0; 15.0 has 39 files; see 03 §3.5) |

> **Measurement command footnote** (2026-05-28):
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
> Main differences vs the v0.1 (heuristic estimate) of this table: `kern` MOD goes from ~95 to 231; `netinet` from ~52 to 181; `net` from ~38 to 149; `netinet6` from ~28 to 57; `amd64`/`arm64`/`x86` totals go up too because the recursive scope was adjusted. **This means the task scale in 04 §9 and the schedule in 05 §3 must be re-evaluated against this table as the new baseline before M1 starts** (out of scope for this audit revision cycle; tracked as P2-001).


---

## 2. F-Stack Actual Link Inventory (full extraction from `f-stack/lib/Makefile`)

> This section is the full structural expansion of `f-stack/lib/Makefile` (765 lines, 16 `*_SRCS` variables, 24 `+=` sites) — **corrected on 2026-05-28; see `99-review-report.md` §12.4**.
> - Data source: `grep -nE '^[A-Z_]+_SRCS' /data/workspace/f-stack/lib/Makefile` + `sed -n` direct extraction
> - Each subsection labels the variable name, source VPATH (the `sys/` subdir), default and conditional file lists
> - The real "needs port" filter: only files listed in `*_SRCS` are linked into `libff.a`; freebsd files not listed can be deferred or left untouched

Variable index (16 `_SRCS` in total, in Makefile appearance order):

| # | Variable | Default count | Conditional branch | Main source VPATH |
|---|---|---:|---|---|
| 1 | `FF_SRCS` | 17 | `FF_NETGRAPH` (+2) | F-Stack's own `lib/` (`ff_*.c`) |
| 2 | `FF_HOST_SRCS` | 9 | `FF_KNI` (+1) / `FF_USE_PAGE_ARRAY` (+1) / `!FreeBSD && !FF_KNI` (+1, dup) | F-Stack's own `lib/` (user-space part of `ff_*.c`) |
| 3 | `CRYPTO_SRCS` | 2 / 14 | else default 2; `FF_IPSEC` 14 | various `sys/crypto/` algo subdirs |
| 4 | `KERN_SRCS` | 38 | — | `sys/kern/` |
| 5 | `KERN_MHEADERS` / `KERN_MSRCS` | 3 / 1 | — | `sys/kern/` (`*.m` interface templates) |
| 6 | `LIBKERN_SRCS` | 7 / 6 | `arm64` 7; else 6 | `sys/libkern/` |
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
| 17 | `ASM_SRCS` | `${CRYPTO_ASM_SRCS}` | generated by mk files | `sys/crypto/.../*.S` |
| 18 | `HOST_SRCS` | `${FF_HOST_SRCS}` | alias | same as `FF_HOST_SRCS` |

> Note: under the default config (`FF_INET6=1, FF_TCPHPTS=1, FF_EXTRA_TCP_STACKS=1`, no `FF_NETGRAPH/FF_IPFW/FF_IPSEC/FF_USE_PAGE_ARRAY/FF_LOOPBACK_SUPPORT/FF_ZC_SEND`), the total `.c` files linked into `libff.a`: FF_SRCS(17) + FF_HOST_SRCS(9) + CRYPTO_SRCS(2) + KERN_SRCS(38) + LIBKERN_SRCS(6) + MACHINE_SRCS(1) + NET_SRCS(33) + NETINET_SRCS(44) + NETINET6_SRCS(29) + EXTRA_TCP_STACKS_SRCS(8) + VM_SRCS(1) = **188 `.c`** (not counting `*.m` and ASM).

### 2.1 `FF_SRCS` (F-Stack's own kernel-side glue, 17 default; `FF_NETGRAPH` +2)

**default (17)**:
```
ff_compat.c, ff_glue.c, ff_freebsd_init.c, ff_init_main.c,
ff_kern_condvar.c, ff_kern_environment.c, ff_kern_intr.c,
ff_kern_subr.c, ff_kern_synch.c, ff_kern_timeout.c, ff_subr_epoch.c,
ff_lock.c, ff_syscall_wrapper.c, ff_subr_prf.c, ff_vfs_ops.c,
ff_veth.c, ff_route.c
```

**`ifdef FF_NETGRAPH` adds 2**:
```
ff_ng_base.c, ff_ngctl.c
```

### 2.2 `FF_HOST_SRCS` (F-Stack user-space part; default 9, several conditional adds)

**default (9)**:
```
ff_host_interface.c, ff_thread.c, ff_config.c, ff_ini_parser.c,
ff_dpdk_if.c, ff_dpdk_pcap.c, ff_epoll.c, ff_log.c, ff_init.c
```

**`ifdef FF_KNI` adds 1**:
```
ff_dpdk_kni.c
```

**`ifdef FF_USE_PAGE_ARRAY` adds 1**:
```
ff_memory.c
```

**`ifneq ($(TGT_OS),FreeBSD) && ifndef FF_KNI` adds 1** (mutually exclusive with `FF_KNI`, non-FreeBSD bypass):
```
ff_dpdk_kni.c
```

### 2.3 `CRYPTO_SRCS` (from `sys/crypto/...`; size determined by `FF_IPSEC`)

**default / else (no `FF_IPSEC`, 2)**:
```
sha1.c, siphash.c
```

**`ifdef FF_IPSEC` (14)**:
```
aesni_wrap.c, bf_ecb.c, bf_enc.c, bf_skey.c, camellia.c,
camellia-api.c, des_ecb.c, des_enc.c, des_setkey.c,
rijndael-alg-fst.c, rijndael-api.c, sha1.c, sha256c.c, sha512c.c,
siphash.c
```
> `aesni.c` on Makefile line 301 is commented out (`#aesni.c`) and not actually linked.

### 2.4 `KERN_SRCS` (38; all from `sys/kern/`; unconditional)

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

### 2.5 `KERN_MHEADERS` / `KERN_MSRCS` (interface templates)

`KERN_MHEADERS` (3 `.m`, `MHEADERS = $(patsubst %.m,%.h,...)`):
```
bus_if.m, device_if.m, linker_if.m
```

`KERN_MSRCS` (1):
```
linker_if.m
```

### 2.6 `LIBKERN_SRCS` (arch-conditional; arm64 7 / else 6; `gsb_crc32` not on arm64 only)

**`ifeq (${MACHINE_CPUARCH},arm64)` (7)**:
```
bcd.c, inet_ntoa.c, jenkins_hash.c, strlcpy.c, strnlen.c, fls.c, flsl.c
```

**else (amd64 / arm / i386 / aarch64 / mips, 6)**:
```
bcd.c, gsb_crc32.c, inet_ntoa.c, jenkins_hash.c, strlcpy.c, strnlen.c
```

### 2.7 `MACHINE_SRCS` (1; from `sys/${MACHINE_CPUARCH}/${MACHINE_CPUARCH}/`)

```
in_cksum.c
```

### 2.8 `NET_SRCS` (33; from `sys/net/` + `sys/net/route/`)

```
bpf.c, bridgestp.c, if.c, if_bridge.c, if_clone.c, if_dead.c,
if_ethersubr.c, if_loop.c, if_llatbl.c, if_media.c, if_spppfr.c,
if_spppsubr.c, if_vlan.c, if_vxlan.c, in_fib.c, in_gif.c, ip_reass.c,
netisr.c, pfil.c, radix.c, raw_cb.c, raw_usrreq.c, route.c,
route_ctl.c, route_tables.c, route_helpers.c, route_ifaddrs.c,
route_temporal.c, nhop_utils.c, nhop.c, nhop_ctl.c, rtsock.c,
slcompress.c
```
> Note: this section explicitly contains the 13.0 versions of `route_*.c` / `nhop*.c`; after 15.0 routing/rib/nexthop rewrite, all of these files are **affected by R-014** (see 03 §3.8).

### 2.9 `NETGRAPH_SRCS` (default 0; with `FF_NETGRAPH` 43; from `sys/netgraph/`)

**`ifdef FF_NETGRAPH` (43)**:
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

### 2.10 `NETINET_SRCS` (44; unconditional; from `sys/netinet/` + `cc/` + `libalias/`)

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
> Note: includes 13.0-era `tcp_debug.c` (deleted in 15.0); several TCP files in this section are directly affected by R-001 / R-002 / R-005 (pr_usrreqs / inpcb SMR / mbuf).

### 2.11 `NETINET6_SRCS` (default 0; with `FF_INET6` 29; from `sys/netinet6/`)

**`ifdef FF_INET6` (29)**:
```
dest6.c, frag6.c, icmp6.c, in6.c, in6_ifattach.c, in6_mcast.c,
in6_pcb.c, in6_pcbgroup.c, in6_proto.c, in6_rmx.c, in6_src.c,
ip6_forward.c, ip6_id.c, ip6_input.c, ip6_fastfwd.c, ip6_mroute.c,
ip6_output.c, mld6.c, nd6.c, nd6_nbr.c, nd6_rtr.c, raw_ip6.c, route6.c,
scope6.c, send.c, udp6_usrreq.c, in6_cksum.c, in6_fib.c, in6_gif.c
```
> `ip6_gre.c` / `ip6_ipsec.c` / `sctp6_usrreq.c` / `in6_rss.c` on Makefile lines 555-558 are commented out (`#`) and not linked.

### 2.12 `EXTRA_TCP_STACKS_SRCS` (cumulative under `FF_TCPHPTS` / `FF_EXTRA_TCP_STACKS`)

**`ifdef FF_TCPHPTS` (+1)**:
```
tcp_hpts.c
```

**`ifdef FF_EXTRA_TCP_STACKS` (+7)**:
```
subr_filter.c, tcp_ratelimit.c, arc4random_uniform.c, sack_filter.c,
rack_bbr_common.c, rack.c, bbr.c
```

### 2.13 `NETIPFW_SRCS` (default 0; with `FF_IPFW` 13; from `sys/netpfil/ipfw/`)

**`ifdef FF_IPFW` (13)**:
```
ip_fw_dynamic.c, ip_fw_eaction.c, ip_fw_iface.c, ip_fw_log.c,
ip_fw_nat.c, ip_fw_pfil.c, ip_fw_sockopt.c, ip_fw_table.c,
ip_fw_table_algo.c, ip_fw_table_value.c, ip_fw2.c, ip_fw_pmod.c,
tcpmod.c
```

### 2.14 `NETIPSEC_SRCS` (default 0; with `FF_IPSEC` 10; from `sys/netipsec/`)

**`ifdef FF_IPSEC` (10)**:
```
ipsec.c, ipsec_input.c, ipsec_mbuf.c, ipsec_output.c, key.c,
key_debug.c, keysock.c, xform_ah.c, xform_esp.c, xform_ipcomp.c
```
> `xform_tcp.c` on Makefile lines 617-618 is commented out (only enabled when `TCP_SIGNATURE` is defined).

### 2.15 `OPENCRYPTO_SRCS` / `OPENCRYPTO_MHEADERS` / `OPENCRYPTO_MSRCS`

**`ifdef FF_IPSEC` (6)**:
```
criov.c, crypto.c, cryptosoft.c, cryptodeflate.c, rmd160.c, xform.c
```
> `cryptodev.c` on Makefile line 631 is commented out.

**`OPENCRYPTO_MHEADERS` (unconditional 1)**: `cryptodev_if.m`
**`OPENCRYPTO_MSRCS` (unconditional 1)**: `cryptodev_if.m`

### 2.16 `VM_SRCS` (1; unconditional; from `sys/vm/`)

```
uma_core.c
```

### 2.17 Indirect variables: `ASM_SRCS` and `HOST_SRCS`

- `ASM_SRCS+= ${CRYPTO_ASM_SRCS}`: dynamically generated by the `mk/kern.pre.mk` system based on architecture (SHA / AES / ChaCha optimization assembly for amd64 / arm64 / x86); not statically enumerated in the Makefile text
- `HOST_SRCS+= ${FF_HOST_SRCS}`: equivalent to `FF_HOST_SRCS` (see §2.2); only used as a target variable into the user-space build chain

### 2.18 Actual mips form in `f-stack/lib/Makefile`

The `ifeq (${MACHINE_CPUARCH},mips)` block at Makefile lines 197-207 only sets `ARCH_FLAGS=-march=mips32` and `HACK_EXTRA_FLAGS=-shared`; **it does NOT reference any `*_SRCS+=`**. This means the 13.0-era F-Stack mips path only has compile flags and **no corresponding link file list**. Combined with 03 §2.1 (15.0 upstream removes mips entirely) and 03 §3.7 (mips removal task), the logical residue of mips in `lib/Makefile` can be cleaned up together with the `freebsd/mips/` removal task (see 03 §3.7 / 04 §3.7).


---

## 3. Hot-Spot Intersection (Part 1 ∩ Part 2 = files **really affected** in F-Stack)

> This is the **most actionable inventory** of doc 04. Each entry is tagged P0/P1/P2 and is the input for the milestone task split in 05.

### 3.1 [P0] kern/ affected files (grouped by adaptation pattern from 02)

| File | 13.0 adaptation pattern | 15.0 upstream change | Port task |
|---|---|---|---|
| `kern_descrip.c` | H-2 (fhold CAS self-check) + H-1 (mask RACCT) | refcount API minor changes | T-kern-01: redo fhold CAS adaptation on top of 15.0; keep RACCT mask |
| `kern_event.c` | H-1 (kqueue_schedtask stub) | knote internal API tweaks | T-kern-02: redo stub; assess whether `kqueuex` syscall is in scope (C-1 says no) |
| `kern_linker.c` | H-2 (va_size==0 treated as success) + H-1 | minor | T-kern-03: redo |
| `kern_mbuf.c` | H-1 (mask mb_unmapped_* / pcpu_page_alloc / mb_alloc_ext_pgs) | **m_ext field rearrangement (R-003)** | **T-kern-04 [P0]**: redo stub; adapt to new m_ext |
| `kern_sysctl.c` | H-1 (mask __sysctl syscall) | sysctl internal API stable | T-kern-05: redo |
| `link_elf.c` | H-1 (stub elf_cpu_parse_dynamic) | minor | T-kern-06: redo |
| `subr_epoch.c` | H-1 (mask taskqgroup_attach_cpu) | **partial epoch → SMR (R-012)** | **T-kern-07 [P0]**: redo stub; assess SMR takeover area |
| `subr_param.c` | H-1 (mask ticks wrap initializer) | minor | T-kern-08: redo |
| `subr_taskqueue.c` | H-1 + H-2 (stub _taskqueue_start_threads) | minor | T-kern-09: redo |
| `sys_generic.c` | H-1 (mask kern_sigprocmask block) | `kern_pselect` internals tweaks | T-kern-10: redo; sync `ff_syscall_wrapper.c` |
| `sys_socket.c` | H-1 + H-9 (mask soo_fill_kinfo etc.) | KTLS branches | T-kern-11: redo; assess KTLS stub |
| `uipc_mbuf.c` | H-1 + in-house `FSTACK_ZC_SEND` extension | **m_ext field rearrangement (R-003)** | **T-kern-12 [P0]**: redo; adapt `FSTACK_ZC_SEND` path |
| `uipc_sockbuf.c` | H-1 + H-9 (mask sb_aio wakeups, RLIMIT_SBSIZE) | sockbuf KTLS fields added | T-kern-13: redo |
| `uipc_socket.c` | H-1 + H-9 (mask TASK_INIT soaio_*) | **pr_usrreqs merged into protosw (R-011)** | **T-kern-14 [P0]**: redo; adapt to new protosw call convention |
| `uipc_syscalls.c` | H-2 (sendit/recvit external) | API stable | T-kern-15: redo (small change) |

### 3.2 [P0] netinet/ affected files

| File | 13.0 adaptation | 15.0 upstream change | Port task |
|---|---|---|---|
| `tcp_input.c` | H-2 + H-4 (inpcb hashlookup RSS) | **inpcb SMR (R-012)** + RACK as default | **T-netinet-01 [P0]**: redo RSS extension; adapt SMR |
| `tcp_output.c` | H-2 | minor | T-netinet-02: redo |
| `tcp_subr.c` | H-1 + H-9 (remove BPF tap, IPSEC tight coupling) | minor | T-netinet-03: redo |
| `tcp_var.h` | H-8 (tcpcb field tweaks) | **RACK fields added to tcpcb (R-004)** | **T-netinet-04 [P0]**: redo field trim |
| `tcp_stacks/rack.c` | H-5 (module name → fstack) | RACK heavily updated | T-netinet-05: redo H-5 |
| `tcp_stacks/bbr.c` | H-5 (module name → fstack) | minor | T-netinet-06: redo H-5 |
| `in_pcb.c` | H-4 (RSS port range / lport check / ladddr derivation) | **inpcb SMR (R-012)** | **T-netinet-07 [P0]**: redo H-4; adapt SMR |
| `tcp_usrreq.c` | (no substantive adaptation) | **pr_usrreqs merged into protosw (R-011)** | T-netinet-08: assess whether redo is needed (depends on whether it still needs modification after the protosw rewrite) |
| `udp_usrreq.c` | (no substantive adaptation) | **pr_usrreqs merged into protosw (R-011)** | T-netinet-09: same |
| `raw_ip.c` | (no substantive adaptation) | **pr_usrreqs merged into protosw (R-011)** | T-netinet-10: same |

### 3.3 [P0] net/ affected files

| File | 13.0 adaptation | 15.0 upstream change | Port task |
|---|---|---|---|
| `if.c` | H-1 + H-9 (mask if_alloc host malloc path) | **if_t opaque-ization (R-013)** + `if_alloc` signature change | **T-net-01 [P0]**: redo; adapt to if_t and new if_alloc |
| `if_var.h` | H-8 (ifnet field trim) | **if_t opaque-ization** | **T-net-02 [P0]**: redo trim |
| `if_ethersubr.c` | H-1 (mask vlan/lagg BPF tap) | if access via accessors | T-net-03: redo stub; adapt to if accessors |
| `netisr.c` | H-1 (driven by ff_veth scheduler) | minor | T-net-04: redo |
| `route.c` | H-2 (rtinit via ff_route.c bridge) | **rib/nexthop rewrite (new R-008)** | **T-net-05 [P0]**: redo; rtinit adapts to rib/nexthop |

### 3.4 [P0] sys/ (common headers) affected files

| File | 13.0 adaptation | 15.0 upstream change | Port task |
|---|---|---|---|
| `sys/systm.h` | H-1 + H-8 (mask kpilite.h; critical_enter/exit stub) | minor | T-sys-01: redo |
| `sys/refcount.h` | H-2 (refcount_acquire_if_not_zero CAS self-check) | refcount API tweak | T-sys-02: redo |
| `sys/callout.h` / `sys/_callout.h` | H-8 (callout simplification) | minor | T-sys-03: redo |

### 3.5 [P1] F-Stack adaptation points in other subdirs

| Subdir | Affected files | Main task |
|---|---|---|
| `netinet6/` | (changes are rare) | T-netinet6-01: cp from 15.0 upstream + minimal adaptation |
| `netgraph/` | `ng_socket.c / ng_socket.h` (minor diff) | T-netgraph-01: redo H-2 |
| `netinet/libalias/` | `alias_sctp.h` (minor diff) | T-libalias-01: assess whether the change is still needed |
| `netipsec/` / `opencrypto/` / `crypto/` / `vm/` / `libkern/` | (0 or 1-2 adaptations) | T-misc-01..N: cp from 15.0 upstream + check whether existing adaptations are still needed |
| `amd64/` `arm64/` `x86/` | (changes mostly in headers) | T-arch-01..03: follow upstream upgrade; possibly indirectly affected by if_t / m_ext |

### 3.6 [P0] f-stack/lib/ff_*.c companion upgrade (FR-3)

| ff_*.c | Affected by which 15.0 P0 | Port task |
|---|---|---|
| `ff_glue.c` | **R-011 pr_usrreqs merge** | **T-ff-01 [P0]**: change all `pr->pr_usrreqs->pru_*()` to `pr->pru_*()` |
| `ff_veth.c` | **R-013 if_t opaque-ization** | **T-ff-02 [P0]**: change all `ifp->if_*` to accessors; adapt to new `if_alloc` signature |
| `ff_route.c` | **rib/nexthop rewrite** | **T-ff-03 [P0]**: change rtinit etc. to rib/nexthop API |
| `ff_subr_epoch.c` | **R-012 epoch → SMR** | **T-ff-04 [P0]**: assess coverage; possibly add SMR stub |
| `ff_syscall_wrapper.c` | sendit/recvit stable; kern_pselect tweak | T-ff-05: follow kern/sys_generic.c changes |
| `ff_kern_intr.c` | ithd subsystem tweaks in 14/15 | T-ff-06: assess |
| `ff_kern_*.c` (others) | API stable | T-ff-07..N: follow |

### 3.7 [P0] f-stack/freebsd/mips/ removal

| Task | Detail |
|---|---|
| **T-cleanup-01** | `rm -rf f-stack/freebsd/mips/`; sync the cleanup of mips conditional branches in Makefile / mk |

---

## 4. tools/ Port Strategy

### 4.1 12 native tools: redo H-6 + H-7 on top of 15.0 upstream

| Tool | 15.0 source path | F-Stack adaptation workload |
|---|---|---|
| `arp/` | 15.0/usr.sbin/arp | medium (raw socket → ff_ipc redo) |
| `ifconfig/` | 15.0/sbin/ifconfig | **large** (libifconfig abstraction layer changes) |
| `ipfw/` | 15.0/sbin/ipfw | medium (IPFW set command channel) |
| `libmemstat/` | 15.0/lib/libmemstat | small (sysctl → ff_ipc) |
| `libnetgraph/` | 15.0/lib/libnetgraph | medium |
| `libutil/` | 15.0/lib/libutil | very small (almost no change) |
| `libxo/` | 15.0/lib/libxo | very small (foundation lib, almost no change) |
| `ndp/` | 15.0/usr.sbin/ndp | medium |
| `netstat/` | 15.0/usr.bin/netstat | **large** (the largest concentration of sysctl takeover) |
| `ngctl/` | 15.0/usr.sbin/ngctl | medium |
| `route/` | 15.0/sbin/route | **large** (RTM_* channel redo + rib/nexthop user-space API follow) |
| `sysctl/` | 15.0/sbin/sysctl | medium (__sysctl syscall → ff_ipc) |

Common per-tool flow:

```
1. cp -a 15.0/<src-path>/<tool> → f-stack/tools/<tool>/.staging/
2. diff f-stack/tools/<tool>/.staging vs 13.0/f-stack-lib/tools/<tool>
   → see 13→15 upstream changes
3. diff f-stack/tools/<tool> vs 13.0/f-stack-lib/tools/<tool>
   → see existing F-Stack adaptations (H-6 / H-7)
4. re-apply H-6 / H-7 on .staging to obtain the new version
5. mv .staging → f-stack/tools/<tool>
```

### 4.2 F-Stack-shipped tools

| Tool | Disposition |
|---|---|
| `knictl/` `traffic/` `top/` | unchanged; keep 13.0 placeholder (re-evaluated only at end of M5) |

### 4.3 f-stack-lib helper

| Item | Disposition |
|---|---|
| `tools/compat/` (with ff_ipc.c/h) | upgrade together with ff_* (FR-3) |
| `tools/sbin/` | empty directory; keep |
| `tools/lib.mk / Makefile / opts.mk / prog.mk / README.md` | assess whether 15.0 base Makefile system needs adaptation |

---

## 5. F-Stack-Specific Extensions Preservation List (FR-7)

These must be preserved through the upgrade:

| Extension | Location | Acceptance |
|---|---|---|
| `FSTACK_ZC_SEND` | `f-stack/freebsd/kern/uipc_mbuf.c::m_uiotombuf` | grep hits ≥ pre-upgrade |
| RSS port range / lport check | `f-stack/freebsd/netinet/in_pcb.c` + `tcp_input.c` | grep `FSTACK-rss-ext` annotations or the macro |
| TCP RACK/BBR module-name renames | `tcp_stacks/rack.c` + `bbr.c` | grep `tcp_rack_fstack` |
| ff_ipc.c/.h IPC bridge | `f-stack/tools/compat/` | tool build chain preserved |
| All 30 ff_*.c | `f-stack/lib/` | file count = 30 |

---

## 6. Port Strategy Summary: 5-Step SOP per File

For each P0 adaptation file, follow this unified flow:

```
1. baseline-15  = freebsd-src-releng-15.0/sys/<subdir>/<file>
2. baseline-13  = freebsd-src-releng-13.0/sys/<subdir>/<file> (= f-stack-lib/freebsd/<subdir>/<file>)
3. fstack-13    = f-stack/freebsd/<subdir>/<file>
4. delta-13     = diff baseline-13 vs fstack-13   # F-Stack's existing adaptation patch
5. baseline-15 + delta-13 → fstack-15-draft
   → manual review, focusing on:
     - whether the interfaces/symbols touched by delta-13 still exist in 15.0
     - whether F-Stack needs to apply the same kind of adaptation to newly added 15.0 code (e.g. whether new m_ext fields need FSTACK-stub)
   → land as f-stack/freebsd/<subdir>/<file>
```

> This 5-step SOP can be directly consumed by the `c-precision-surgery` skill. Each P0 task's "input boundary + output standard" is defined here.

---

## 7. Risk-vs-Strategy Cross-reference

| Risk ID | Location in 03 | Coping task in 04 |
|---|---|---|
| R-011 | §3.1 pr_usrreqs merge | T-kern-14 / T-netinet-08/09/10 / T-ff-01 |
| R-012 | §3.2 inpcb SMR | T-netinet-01 / T-netinet-07 / T-kern-07 / T-ff-04 |
| R-013 | §3.3 if_t opaque | T-net-01 / T-net-02 / T-net-03 / T-ff-02 |
| R-003 | §3.4 mbuf field adjustments | T-kern-04 / T-kern-12 |
| new | §3.8 rib/nexthop | T-net-05 / T-ff-03 / T-tools-route |
| R-001/FR-4 | §2.1 mips removal | T-cleanup-01 |
| R-002 | §3.5 netlink | not introduced (DP-2), no task |
| R-004 | §3.6 RACK as default | T-netinet-05/06 |
| R-007 | §4 ABI break | review libff ABI at the end of M5 |
| R-009 | §2.2 clang/llvm | prerequisite: GCC ≥ 10 / clang ≥ 12 |
| R-006 | §3.7 KTLS / wlan | T-kern-11 (assess KTLS stub) |
| R-008 | §1.4 of 01 drift | run `diff -rq` cleanup of SKIP noise before implementation |

---

## 8. Workload Estimate (based on hot-spot intersection)

| Milestone | # tasks | # files | Workload tier |
|---|---|---|---|
| M1 (infrastructure + headers + mips cleanup + libkern + crypto) | T-sys-01/02/03 + T-cleanup-01 + T-misc-01..N | ~50 | small |
| M2 (kern core, 38 KERN_SRCS) | T-kern-01..15 | 15 substantive + 23 direct copy | **large** |
| M3 (network stack net + netinet + netinet6) | T-net-01..05 + T-netinet-01..10 + T-netinet6-01 | ~20 | **large** |
| M4 (edge subsystems netipsec / netgraph / netpfil / vm) | T-misc / T-netgraph-01 | 5-8 | medium |
| M5 (12 tools + ff_*.c + lib acceptance) | T-tools-01..12 + T-ff-01..N + acceptance | ~30 | **large** |

---

## 9. Port Task Total Overview

| P-level | # tasks | Description |
|---|---|---|
| **P0** | 24 (kern 4 + netinet 5 + net 5 + ff 4 + cleanup 1 + tools-large 5) | mandatory; build/run-blocking |
| **P1** | 18 (rest of kern / netinet / net / tools mid-changes) | compile passes but semantics need verification |
| **P2** | 10 (edge subsystems) | non-core |
| **P3** | 5 (crypto / arch headers / others) | informational / follow upgrade |
| **Total** | **~57 port tasks** | see split in `05-implementation-plan.md` §3 |

### 9.1 Task-count convention reconciliation (added 2026-05-28; addresses audit §6.2-2)

This Spec series uses the numbers **57 / 75 / 24 / 18 / 19** in different places, each with a different observation axis. To avoid ambiguity, the unified ledger is:

| Axis | Number | Meaning | Single source of truth |
|---|---:|---|---|
| **Global task total (implementation baseline)** | **75** | includes cp -a direct copies (M1/M2/M3/M4 batch tasks) + ports | `05-implementation-plan.md §3` line 204 |
| **Narrow port tasks (diff-analysis view)** | **57** | only 04 §3 hot-spot intersection + ff_*/tools adaptations, **excluding cp -a direct copies** | `04-diff-and-port-strategy.md §9` (this table) |
| **P0 tasks (implementation view)** | **18** | merging file-level "mandatory" items among 75; mips full cleanup counts as 1 | `05 §3` line 204 |
| **P0 tasks (risk view)** | **19** | counts based on 6 P0 risks; mips "full cleanup" is split into "directory removal + Makefile adaptation" 2 steps | `99-review-report.md §4.2` |
| **P0 port tasks (P0 row in the 04 §9 table)** | **24** | 04 §9 P0 row = kern 4 + netinet 5 + net 5 + ff 4 + cleanup 1 + tools 5; the unit is "port decision point" not "implementation task" | this table |

**Sole global baseline = 75 tasks / 18 P0 in 05 §3**. The other four numbers are subsets or accessory views from different perspectives and should not be treated as independent conventions:

- 75 - 57 = 18 cp -a direct-copy tasks (occupying several entries each in M1/M2/M3/M4 in 05 §3; see footnote at 05 §3 line 206)
- 18 vs 19: `99 §4.3 RI-01` records this as a P3 informational item (mips is a directory-level cleanup; the risk-view splits into 2 = 19; the implementation-view merges into 1 = 18)
- 24 is a "port decision point" classification subtotal in the 04 §9 table; the gap to 18 comes from: (a) 04 §9 counts "tools-large change" as 5 decision points, but 05 §3 splits them into 15 tools tasks under M5 with 3 P0 items; (b) 04 §9 does NOT include "pure cp -a tasks under the 05 view".

When PM/QA quote task counts in subsequent work, **prefer** 75 / 18 / 57 and indicate whether cp -a is included; when quoting 24 / 19, indicate the view ("04 §9 port decision points P0" / "99 §4.2 risk-view P0"). See `99-review-report.md §12.8`.

---

## 10. Hand-off to Other Documents

| Artifact from this section | Hand-off target |
|---|---|
| §3 hot-spot intersection (57 T-* tasks) | task allocation in `05-implementation-plan.md` §3 |
| §6 5-step SOP | SOP in `05-implementation-plan.md` §4 |
| §1 subdir diff panorama | compile matrix in `06-test-and-acceptance-spec.md` §1 |
| §7 risk-strategy cross-reference | risk-coverage review in `99-review-report.md` |

> Next: `05-implementation-plan.md` splits the 57 T-* tasks across M1-M5 and provides resourcing, scheduling, and rollback.
