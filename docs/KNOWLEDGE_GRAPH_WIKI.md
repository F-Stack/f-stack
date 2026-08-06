# F-Stack Knowledge Graph Wiki

> Auto-extracted from the GitNexus knowledge graph (schema v1) plus manual cross-checking against current source. **Indexed: 2026-06-08T03:37:02Z, commit `208b0c4`** (`dev` branch, post FreeBSD 13.0 → 15.0 first-stage upgrade including M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS).

---

## 1. Project Overview

| Metric | Data |
|--------|------|
| Indexed files | 2,656 |
| Symbol nodes | 64,855 |
| Relation edges | 113,858 |
| Function clusters | 981 (communities) |
| Execution flows | 300 (processes) |
| Embedding nodes | 0 (semantic search not enabled this round) |
| Effective scope | F-Stack source surface only (DPDK / FreeBSD vendored trees excluded by gitnexus 1.6.5 schema) |
| Indexer | gitnexus 1.6.5 (ladybugdb provider; FTS available, vector search disabled) |

> **Schema migration note**: prior wiki snapshots (commit `a695757`, indexed 2026-04-09) reported 25,723 files / 710,596 nodes under gitnexus 1.5.x, which counted vendored FreeBSD/DPDK trees in some node categories. Schema v1 now correctly restricts the graph to the F-Stack-authored surface; the dramatic count drop is **a measurement-scope correction, not a code regression**.

> **Detailed node-type / named-cluster breakdown unavailable**: schema v1 `meta.json` only exposes top-level totals. Earlier per-type tables (Macro / Function / Property / …) and named-cluster tables (Net / Netinet / Tcp_stacks / …) were schema-v0 outputs produced via LLM enrichment. Regenerating them requires running `npx gitnexus wiki` with an LLM API key (not configured this round). To re-derive the equivalent taxonomy without LLM, query the underlying ladybugdb directly under `.gitnexus/lbug` or refer to the authoritative subsystem grouping in `docs/freebsd_13_to_15_upgrade_spec/02-architecture-analysis.md`.

---

## 2. F-Stack 13.0 → 15.0 Upgrade Delta Map

This index has been rebuilt **after** the first-stage 13.0 → 15.0 upgrade. The graph therefore reflects:

| Area | Where reflected in the graph |
|------|------------------------------|
| 33 `lib/*.c` files (17 newly authored / re-platformed since 13.0) | `lib/` folder & file nodes; new bank `lib/ff_stub_14_extra.c` (799 LoC, M5 + runtime-fix landing point) |
| 14.0+ KBI/KPI deltas (`pr_usrreqs` merged into `protosw`; `if_t` opaquification; `rt_alloc` 3rd-arg signature; `rt_ifmsg` rtbridge dispatch; 8-category 14.0+ ABI deltas) | Edges between `lib/ff_glue.c`, `lib/ff_route.c`, `lib/ff_veth.c`, `lib/ff_kern_timeout.c`, `lib/ff_lock.c`, `lib/ff_syscall_wrapper.c` and the new central stub bank |
| 5 P0 SIGSEGV runtime-fix landing points (UMA `UMA_USE_DMAP`, `smr_create %gs` barrier, `rt_ifmsg` NULL, `ff_veth_setaddr` ENOBUFS, `kern_accept` `badfileops`) plus 1 defensive `vm_page_alloc_noobj` panic | Files `freebsd/{amd64,arm64}/include/vmparam.h`, `freebsd/amd64/include/atomic.h`, `freebsd/kern/kern_descrip.c`, `lib/Makefile`, `lib/ff_stub_14_extra.c` |
| Architecture removal: `freebsd/mips/` (synced to FreeBSD 14.0 upstream removal) | mips arch nodes are absent from the F-Stack graph; remaining `mips` strings live only in `freebsd/contrib/device-tree/` (DTS, not compiled) |
| New header-only subsystem port: `freebsd/netlink/` (18 `.h`, 0 `.c`, 0 `SRCS`) — DP-2 "no NETLINK protocol port" | netlink folder node has zero outbound CALL edges into F-Stack libraries |
| Routing FIB rework subdir: `freebsd/net/route/` (22 files: `nhop`, `fib_algo`, `route_ctl`) | New cluster of route_ctl nodes connected from `lib/ff_route.c` and `lib/ff_stub_14_extra.c` |
| TCP stacks modularization (`-DMODNAME=tcp_rack -DSTACKNAME=rack`); F-Stack H-5 module rename `tcp_rack_fstack` re-applied | `freebsd/netinet/tcp_stacks/` (11 files including `rack.c` ~759 KB, `bbr.c` ~444 KB) |

For evidence-level traceability of each delta, see the upgrade spec series: `docs/freebsd_13_to_15_upgrade_spec/{00-overview-and-glossary, 01-requirements-spec, 02-architecture-analysis, 03-freebsd-15-changes, 04-diff-and-port-strategy, 05-implementation-plan, 06-test-and-acceptance-spec}.md`, the milestone logs `M1~M5-execution-log.md`, the `runtime-fix-execution-log.md`, the `rib-fix-plan.md`, and the dual baselines (`13.0-baseline-cvm-bench-report.md` + `physical-machine-bench-report.md`).

---

## 2A. Post-index code delta: `FF_KERNEL_COEXIST` kernel-stack coexistence

> **Manual addendum (not yet re-indexed)**: the graph above was indexed at commit `208b0c4` (2026-06-08). The `feature/1.26` branch has since landed the **`FF_KERNEL_COEXIST` automatic dual-stack coexistence** feature (commits `ba148589d` → `55a84f313`), the **R9** increment (kqueue/kevent coexistence + IPv6 `IPV6_V6ONLY`), and the **R10** increment (`ff_readv`/`ff_writev`/`ff_ioctl` kernel-fd routing + `ff_dup`/`ff_dup2`). The surface below is documented manually against current source until the next `npx gitnexus analyze`.

The feature lets a single process serve a listener over both the F-Stack user-space stack (via the DPDK NIC) and the host Linux kernel stack (via loopback / the management NIC) from one event loop — either `ff_epoll_wait` or, since R9, `ff_kqueue`/`ff_kevent`. It is **off by default** (compile-time macro + runtime `kernel_coexist` switch), and when off the default / `SOCK_FSTACK` path is byte-for-byte unchanged.

| Area | Where in source |
|------|-----------------|
| Build & runtime gating (default OFF) | `lib/Makefile` L174-177 injects `-DFF_KERNEL_COEXIST` into both `CFLAGS` and `HOST_CFLAGS`; runtime `config.ini [stack] kernel_coexist=0` default (`ff_config.c` L1027-1033 parse / L1366 default; `ff_config.h` L321-325 `stack` struct) |
| Managed kernel-fd space | `lib/ff_host_interface.h` L113-128: `FF_KERNEL_FD_BASE 0x40000000` + inline `ff_is_kernel_fd / ff_kernel_fd_encode / ff_kernel_fd_real`; a managed kernel fd = `host_fd + 0x40000000`, which never collides with FreeBSD fds (`kern.maxfiles <= 65536`) |
| Dual-stack fd map | `lib/ff_host_interface.c` L257-278: `ff_native_fd_map[65536]` + `ff_native_map_get/set/clear` (single-threaded per F-Stack instance) |
| 32 host-stack bridges | `lib/ff_host_interface.c` (`ff_host_socket` … `ff_host_getsockname`), declared `lib/ff_host_interface.h` — each a thin passthrough to host libc. **R9 added 3**: `ff_host_set_v6only` (`setsockopt IPV6_V6ONLY`), `ff_host_kqueue_ctl`, `ff_host_kqueue_poll` (the latter two service the kqueue↔host-epoll coexistence path). **R10 added 5**: `ff_host_readv`, `ff_host_writev`, `ff_host_ioctl` (raw Linux request passed straight to host libc), `ff_host_dup`, `ff_host_dup2` |
| Per-socket stack markers | `lib/ff_api.h` L95-100: `SOCK_FSTACK 0x01000000`, `SOCK_KERNEL 0x02000000`; priority: per-socket marker > config `kernel_coexist` > F-Stack |
| Entry routing | `lib/ff_syscall_wrapper.c`: `ff_socket` dual-create (L916-958; on `AF_INET6` dual-build calls `ff_host_set_v6only(hfd)` at L952 so the host IPv6 socket is `IPV6_V6ONLY` and coexists with the same-port host IPv4 socket — R9/P1); kernel-fd hot-routes + dual-stack map dual-drive across `socket/bind/listen/connect/accept[4]/close/read/write/recv*/send*/sendmsg/recvmsg/getpeername/getsockname/shutdown/setsockopt/getsockopt/fcntl`. `LINUX_IPV6_V6ONLY 26`→`IPV6_V6ONLY` translation at L620-621. **R10 added kernel-fd routing: `ff_readv` / `ff_writev` / `ff_ioctl` / `ff_dup` / `ff_dup2`** (see the R10 row below) |
| Unified epoll | `lib/ff_epoll.c` (289 L): `ff_epoll_pairs[64]{kq, host_ep}` lazily pairs one host epoll fd per kqueue; `ff_epoll_ctl` routes kernel fds to the host epoll / dual-registers dual-stack fds; `ff_epoll_wait` polls the host epoll (non-blocking) then merges kqueue events. `ff_epoll_pairs_lock` removed — single-threaded model (commit `3e71f4699`). `ff_epoll_host_ep` promoted from `static` to a shared symbol (declared `ff_host_interface.h` L139) so the kqueue path reuses the same pairing table |
| Unified kqueue/kevent (R9/P2) | `lib/ff_syscall_wrapper.c`: `ff_kqueue` (L1895) + `ff_kevent` (L2050) now coexist symmetrically with epoll. `ff_kevent` changelist → `ff_kevent_host_change` (L2006) registers kernel/dual-stack-fd `EVFILT_READ/WRITE` into the kqueue-paired host epoll via `ff_host_kqueue_ctl` (kernel-only changes are NOT forwarded to the F-Stack kqueue; dual-stack fds are still forwarded); eventlist → `ff_kevent_host_wait` (L2034) polls the host epoll via `ff_host_kqueue_poll` (`timeout=0`), synthesizes `struct kevent` (`ident`=app-side fd, `EV_EOF`↔`EPOLLHUP|ERR`), then merges `ff_kevent_do_each` F-Stack events. Fixes the `example/main.c` kqueue model: kernel-side `curl 127.0.0.1:80` measured **200 size=438** (was 000). Known limit: kernel fds via kqueue support `EVFILT_READ/WRITE` only |
| Residual-entry coexistence (R10) | `lib/ff_syscall_wrapper.c`: `ff_ioctl` (L1067) kernel fd uses the **raw Linux request** passed straight to `ff_host_ioctl` (NOT via `linux2freebsd_ioctl`, because `_IO/_IOR/_IOW(type,nr,size)` encodings differ between Linux and FreeBSD; dual-stack fd same-driver since R10.1 syncs `FIONBIO`/`FIOASYNC` to the paired host fd (query ioctls like `FIONREAD` not forwarded, to avoid clobbering argp)); `ff_readv` (L1189)/`ff_writev` (L1251) kernel fd via `ff_host_readv/writev` (mimic `ff_read/write`, connection fds single-stack hot path); `ff_dup` (L2130) kernel fd → `ff_host_dup`+encode; `ff_dup2` (L2156) both-kernel → `ff_host_dup2`+encode, **cross-stack (one kernel, one F-Stack) rejected `errno=EINVAL`**. **Known limits**: `ff_select` (encode kernel fd ≥ `0x40000000` ≫ `FD_SETSIZE`(1024), cannot fit in `fd_set` — hard limit) and `ff_poll` (merge complexity/regression risk, conservatively not implemented) — use `ff_epoll_*`/`ff_kqueue` (R9) for kernel-fd multiplexing |

Traceability: `docs/kernel_event_support_spec/` and `docs/kernel_event_support_spec/zh_cn/` (00-10), including the R8 review-gate logs, the R9 plan `plan-r9-kqueue-coexist-ipv6.md` and the R10 plan `plan-r10-readv-writev-ioctl-coexist.md`.

---

## 2B. Post-index code delta: RSS thash reverse path (R-F) + IPv6 reverse-proxy address fix

> **Manual addendum (not yet re-indexed)**: documented against current source (2026-07). Covers the RSS connect-side reverse-computation fix (`ff_rss_check_opt_spec` R-F) and the IPv6 reverse-proxy VIP/gateway/DAD fix (`ff_rss_check_opt_spec/zh_cn/11-*`). Re-index with `npx gitnexus analyze` to fold into the graph.

The feature makes the **inbound reply (SYN-ACK)** of an outbound connect land on the local RX queue, and fixes IPv6 reverse-proxy VIP reachability on FreeBSD 15. Reverse computation + NIC RSS key sync are gated by `[rss_check] thash_adjust` (default on, **decoupled from `rss_check.enable`**); diagnostics are gated by the compile macro `FF_RSS_DIAG` (default off, no dataplane impact).

| Symbol / Area | Where in source |
|---------------|-----------------|
| `ff_rss_adjust_sport` (**signature +`first,last`**) | `lib/ff_dpdk_if.c:3242` `int ff_rss_adjust_sport(void *softc, uint32_t saddr, uint32_t daddr, uint16_t dport, uint16_t *out_sport, uint16_t first, uint16_t last)` — aligns candidate to a reta_size-aligned block inside `[first,last]` (L3293-3302), builds the tuple in **reply field order** (remote/local/dport=80/localPort), calls `rte_thash_adjust_tuple`, then a defensive `[first,last]` range guard (L3352). Caller `freebsd/netinet/in_pcb.c` L962-964 passes `first,last`. |
| `ff_rss_adjust_sport6` (**signature +`first,last`**) | `lib/ff_dpdk_if.c:3681` `int ff_rss_adjust_sport6(void *softc, const uint8_t *saddr6, const uint8_t *daddr6, uint16_t dport, uint16_t *out_sport, uint16_t first, uint16_t last)`. Caller `in_pcb.c` L899-901. v6 addrs are `const uint8_t *` (not `struct in6_addr *`). |
| `recheck` re-verify (reply order) | On adjust success: `if (!recheck \|\| ff_rss_check(softc, saddr, daddr, dport, sport))` (`ff_dpdk_if.c:3362-3363`) — note `dport`/`sport` are the **reply** src/dst. `recheck` from `[rss_check] recheck` (default 0). |
| `ff_rss_thash_build_key(port_id, reta_size)` | `lib/ff_dpdk_if.c:3016`, declared L168. Built **before** `dev_configure` (`init_port_start` L758-761 calls it when `nb_queues>1 && thash_adjust`), constructs v4 ctx (`rte_thash_add_helper "sport"` at `FF_RSS_THASH_V4_SPORT_OFF=80`, L152) + v6 ctx seeded from v4-rewritten key (`FF_RSS_THASH_V6_SPORT_OFF=272`, L163; helper len `FF_RSS_THASH_SPORT_HELPER_LEN=16`, L153), then publishes KEY_FINAL into the global `rsskey` (L3159+). |
| `ff_rss_thash_ctx_init(void)` | `lib/ff_dpdk_if.c:3177` (primary only). Post-start diagnostic read-back of NIC key/RETA for cross-check; gated by `thash_adjust` at `ff_dpdk_if.c:1490-1492`. |
| `thash_adjust` switch | `lib/ff_config.c`: default set `rcc->thash_adjust = 1` (L946), parsed `thash_adjust=` (L956-957). Gates `build_key` (`ff_dpdk_if.c:758-761`), `ctx_init` (L1490-1492), and the route② soft-scan fallback guard in `adjust_sport[6]` (L3261-3263 / L3701-3703). NULL cfg ⇒ treated as 1. |
| `FF_RSS_DIAG` gating | `ff_rss_diag_dump_key` (`ff_dpdk_if.c:2980`) and its call sites (e.g. L3146-3156 in `build_key`, NIC-readback in `ctx_init`) wrapped in `#ifdef FF_RSS_DIAG`, **default off**. |
| IPv6 VIP6 /128 host addr | `lib/ff_veth.c:861` `ff_veth_setvaddr6`: `memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, 16)` (L879-880) — /128, avoids on-link prefix route so same-subnet traffic goes via the gateway. |
| IPv6 link-local gateway scope | `lib/ff_veth.c:829` `ff_veth_set_gateway6`: `if (IN6_IS_ADDR_LINKLOCAL(&gw.sin6_addr)) in6_setscope(&gw.sin6_addr, sc->ifp, NULL)` (L849-850) — completes the zone id for a `fe80::/10` gateway. |
| IPv6 skip DAD | `lib/ff_veth.c:908` `ff_veth_setup_interface`: `ND_IFINFO(ifp)->flags \|= ND6_IFF_NO_DAD` (L980) — user-space has no timer to complete DAD, and FreeBSD 15 `ip6_input` silently drops unicast to `NOTREADY`/`TENTATIVE` addresses. |

Traceability: `docs/ff_rss_check_opt_spec/zh_cn/` (00-11), esp. `05-接口设计.md` (signatures), `11-IPv6反代VIP-onlink修复.md` (v6 address fix), and `10-实施与验证报告.md`.

---

## 2C. Post-index code delta: IP_BIND_ADDRESS_NO_PORT setsockopt wiring (R-E setsockopt layer)

- **Symbol**: `LINUX_IP_BIND_ADDRESS_NO_PORT` (=24), `ff_setsockopt`, `ff_getsockopt`
- **File**: `lib/ff_syscall_wrapper.c` (commit `a2537e143`, +17/-0)
- **Root cause**: Linux `IP_BIND_ADDRESS_NO_PORT` (24) collides numerically with FreeBSD `IP_BINDANY` (24, `freebsd/netinet/in.h:462`); `ip_opt_convert` had no branch for it, so `default: return optname` passed 24 through → v6 sockets got EINVAL from `ip6_ctloutput` (level != IPPROTO_IPV6), v4 sockets were silently misrouted to set INP_BINDANY.
- **Fix**: intercept `IPPROTO_IP + LINUX_IP_BIND_ADDRESS_NO_PORT` in `ff_setsockopt`/`ff_getsockopt` before `linux2freebsd_opt`, return success no-op. FreeBSD already defers ephemeral port selection to connect; F-Stack RSS reverse path (`ff_rss_adjust_sport/6`) picks the source port at connect. Covers both v4 and v6 (nginx calls setsockopt at IPPROTO_IP level for both).
- **Complements R-E (§6 of ff_rss 10)**: R-E fixed the kernel-side bind gate (`in_pcb.c`/`in6_pcb.c`); this patch fixes the setsockopt option wiring so nginx can actually request the delayed-port behavior without EINVAL.

---

## 2D. Post-index code delta: MTU/jumbo-frame configuration support

> **Manual addendum (not yet re-indexed)**: documented against current source (2026-07). Covers the MTU change feature set (`mtu_change_spec/`): jumbo-frame enablement, KNI/MTU mutual-exclusion removal, IPv6 `nd_ifinfo.maxmtu` sync, and SIOCSIFMTU ioctl dedup. Re-index with `npx gitnexus analyze` to fold into the graph.

The feature allows runtime MTU changes on DPDK-backed veth interfaces, including jumbo frames up to the NIC's hardware limit. The KNI/MTU mutual exclusion that previously blocked `mtu_enable` when KNI was enabled has been removed; IPv6 `nd_ifinfo.maxmtu` is now synced via `if_notifymtu` so IPv6 path MTU discovery tracks the configured MTU.

| Area | Where in source |
|------|-----------------|
| MTU capability query | `lib/ff_dpdk_if.c`: `ff_mtu_capability()` queries `rte_eth_dev_info` for `max_mtu`/`min_mtu`; uses `uint8_t` (not `bool`) for the jumbo-capable flag (commit `4c30d118f` clean-build fix). Magic numbers replaced with named macros `FF_MTU_DEFAULT`, `FF_MTU_JUMBO_THRESHOLD` etc. (commit `0f8f6991e`). |
| SIOCSIFMTU ioctl handler | `lib/ff_veth.c`: dedup'd via fall-through so v4 and v6 share one code path (commit `332abf997`); validates against `if_getmtu` + hw capability, calls `rte_eth_dev_set_mtu` for DPDK-backed NICs. |
| KNI/MTU mutex removal | `lib/ff_dpdk_if.c` / `lib/ff_config.c`: removed the `mtu_enable`/`kni.enable` mutual-exclusion check (commit `989f1d2da`); both can now be enabled simultaneously. |
| IPv6 nd_ifinfo maxmtu sync | `lib/ff_veth.c`: `if_notifymtu` called on MTU change to propagate to `nd_ifinfo.maxmtu` (commit `0f25ac495`), ensuring IPv6 path MTU discovery and neighbor discovery use the updated MTU. |
| config.ini `[portN]` | New per-port `mtu` configuration item (default 1500); parsed in `ff_config.c`. |
| IPv6 fragmentation | `freebsd/netinet6/`: IPv6 fragment reassembly respects the updated `maxmtu` (FreeBSD 15.0 `ip6_input` path). |

Traceability: `docs/mtu_change_spec/` (00-09, zh_cn/), esp. `06-solution-and-conclusion.md` (jumbo validation complete), `09-implementation-and-code-change-design.md`. Key commits: `0f8f6991e`, `332abf997`, `4c30d118f`, `989f1d2da`, `0f25ac495`, `1336077d0`.

---

## 2E. Post-index code delta: native-mt SMP-aware pcpu/SMR slot isolation + global lock removal

> **Manual addendum (not yet re-indexed)**: documented against current source (2026-08). Covers the `native_mt_spec/` spec 17 work: making the FreeBSD kernel view SMP-aware for `thread_mode=1`, giving each stack thread a dense pcpu slot with per-thread `curcpu`, and removing the `uma_crit_lock` global spinlock that was serializing the UMA per-CPU cache fast path. Re-index with `npx gitnexus analyze` to fold into the graph.

Before this change, all stack threads shared pcpu slot 0 (because `ff_pcpu_thread_init` ignored its `cpuid` parameter, `mp_ncpus=1`, `mp_maxid=0`, `MAXCPU=1`, and `curcpu` was hardcoded to 0). This caused SMR read-side sequence numbers to be overwritten across threads, creating a UAF window. A global spinlock `uma_crit_lock` was introduced as a band-aid to serialize UMA per-CPU cache access, but it was a dataplane bottleneck. This work (G1+G2) makes each thread own a distinct dense pcpu slot and removes the lock.

| Area | Where in source |
|------|-----------------|
| `-DSMP` build flag | `lib/Makefile:221-223`: `CFLAGS+= -DSMP` — activates `MAXCPU=1024`, `UMA_ZONE_PCPU` not stripped, per-cpu `M_ZERO` full-slot zeroing, `smp_topo()` call site in `tcp_hpts.c`. |
| `smp_topo()` stub | `lib/ff_glue.c:171-177`: returns `NULL` (safe: `tcp_hpts.c:1890 if (cpu_top == NULL) grp_cnt = 1`; `grps[]` never `malloc`'d). |
| Triple `mp_ncpus`/`mp_maxid`/`all_cpus` | `lib/ff_freebsd_init.c:314-317`: `nb_cpus = thread_mode ? nb_threads : 1; mp_ncpus = nb_cpus; mp_maxid = nb_cpus - 1; for (i...) CPU_SET(i, &all_cpus);` — set **before** `uma_startup1()` (`:331`) and `mi_startup()` (`:339`); never modified after. |
| `uma_page_slab_hash` advance | `lib/ff_freebsd_init.c:379-387`: moved hash init **before** `uma_startup1()` — when `mp_maxid ≥ 2`, zone-of-zones item size exceeds 1 page → `UMA_ZFLAG_VTOSLAB` set → `keg_alloc_slab()` calls `vsetzoneslab()` during `uma_startup1()` → NULL deref crash without this fix. |
| `ff_pcpu_thread_init(cpuid)` uses parameter | `lib/ff_freebsd_init.c:106-112`: now `pcpu_init(pcpup, cpuid, ...)` (was hardcoded `0`); upper-bound `panic` if `cpuid > mp_maxid` (because `subr_pcpu.c:88 KASSERT` is compiled out without `INVARIANTS`). |
| Dense pcpu id for main/worker | `lib/ff_freebsd_init.c:317`: `ff_pcpu_thread_init(thread_mode ? ff_cur_proc_id() : 0)`; `lib/ff_dpdk_if.c:2652`: `ff_stack_thread_init(thread_mode ? qconf->proc_id : 0)`. `ff_cur_proc_id()` = `ff_cur_lcore_conf()->proc_id` (dense `[0, nb_threads-1]`). |
| `curcpu` per-thread | `lib/include/sys/pcpu.h:34`: `#define curcpu PCPU_GET(cpuid)` = `pcpup->pc_cpuid` (was `0`); `#undef curcpu` retained to avoid redefinition with upstream `freebsd/sys/pcpu.h:218`. |
| `timeout_cpu` per-thread | `lib/ff_kern_timeout.c:190`: `static __thread int timeout_cpu` (was `static int`); `CC_CPU(cpu)` ignores arg and returns calling thread's own `__thread cc_cpu`. |
| `pause_wchan` bootstrap fallback | `lib/ff_kern_synch.c:105`: `&pause_wchan[pcpup != NULL ? curcpu : 0]` — reachable from `malloc()` OOM retry before pcpu is built. |
| `uma_crit_lock` removal (G2) | `lib/include/vm/uma_int.h:44-50`: `critical_enter/exit` → `do {} while(0)` + 3-line comment; `lib/ff_glue.c`: deleted `volatile int uma_crit_lock;` definition. Safe because `curcpu` is per-thread (preemption/migration doesn't change slot), and SMR read-side `critical_enter` was already a no-op in non-UMA TUs. |
| `thread_mode=0` zero regression | All paths gated by `thread_mode ?` ternary; `mp_ncpus=1`, `mp_maxid=0`, `all_cpus={0}`, `curcpu=0`, `ff_pcpu_thread_init(0)` — value-identical to pre-change (4 known non-equivalent differences: `UMA_ZONE_PCPU` no longer stripped, CK `lock` prefix restored, `MAXCPU`-sized BSS growth, `curcpu` memory load). |

Traceability: `docs/native_mt_spec/zh_cn/` (00-17 + `_m17_*` + `plan-17-*`), esp. `17-SMP-aware-pcpu视图与去全局锁.md` (main spec), `_m17_F_runtime.md` (runtime test report), `_m17_gate_code_g1.md`/`_m17_gate_code_g2.md` (gate reviews). English translation in `docs/native_mt_spec/` root. Key commits: `c7996a94f` (G1), `57b612d16` (G2).

**Physical-machine verification (2026-08-06)**: functionality and performance both PASS on physical hardware. Residual risks honestly recorded (not fixed this round): ipfw/netisr DPCPU slot aliasing (needs separate DPCPU project), counter(9) statistics contention, tcp_hpts instance 1→N callout ownership mismatch (R6), net.isr.dispatch must stay `direct`, ff_subr_prf.c global lockless line buffer, ff_pthread_create threads unsupported for ff_* calls. **New residual risk §6.23**: intermittent process crash under repeated wrk stress (non-deterministic, requires multiple runs to reproduce → capture crash stack → root-cause). See spec 17 §6.23 and `_m17_F_runtime.md` Part 6.

## 3. Directory Structure

```
f-stack/
├── lib/            # F-Stack core library (33 .c files; ff_stub_14_extra.c is the central 14.0+ stub bank)
├── adapter/        # LD_PRELOAD adaptation layer (syscall hook, micro_thread bridge)
├── app/            # Integrated applications (nginx-1.28.0/, redis-6.2.6/)
├── example/        # Example programs (helloworld, helloworld_epoll, main_zc.c zero-copy)
├── tools/          # User-space ports of ifconfig / netstat / arp / route
├── mk/             # Build system (Makefile include files)
├── doc/            # Original upstream documentation
├── docs/           # 3-tier architecture knowledge base + LD_PRELOAD Ring IPC spec + 13.0→15.0 upgrade spec
├── dpdk/           # DPDK 24.11.6 LTS submodule (upgraded from 23.11.5 on 2026-06-09; excluded from gitnexus indexing)
└── freebsd/        # FreeBSD 15.0 kernel source port (excluded from gitnexus indexing)
```

### 3.1 Core Library Files (`lib/`)

The 33 `.c` files in `lib/` (verified by direct read) group into six roles. Selected anchors below; full inventory and verified line counts in `docs/F-Stack_Architecture_Layer3_Function_Index.md` §"lib/ file index" and `docs/freebsd_13_to_15_upgrade_spec/docs-sync-2026-06-08-update-matrix.md` §1.2.

| Role | Representative files |
|------|----------------------|
| Public API & init | `ff_api.h`, `ff_init.c` (70 L), `ff_init_main.c` (~660+ L), `ff_freebsd_init.c` (~154 L) |
| Configuration | `ff_config.c` (1,694 L; incl. `[stack] kernel_coexist` parse), `ff_ini_parser.c` (3rd-party inih) |
| DPDK adapter | `ff_dpdk_if.c` (2,907 L; `main_loop` lives here), `ff_dpdk_kni.c` (~441 L), `ff_dpdk_pcap.c` (~118 L) |
| Linux→FreeBSD glue | `ff_glue.c` (1,467 L), `ff_syscall_wrapper.c` (2,265 L; incl. `FF_KERNEL_COEXIST` entry routing + R9 `ff_kqueue/ff_kevent` coexistence + `IPV6_V6ONLY` + R10 `ff_readv/writev/ioctl/dup/dup2` kernel-fd routing), `ff_host_interface.c` (617 L; 32 `ff_host_*` host-stack bridges incl. R9 `ff_host_kqueue_ctl/poll` + `ff_host_set_v6only`, R10 `ff_host_readv/writev/ioctl/dup/dup2`, + `ff_native_fd_map`), `ff_host_interface.h` (187 L), `ff_epoll.c` (289 L; unified F-Stack + kernel epoll, `ff_epoll_host_ep` shared with the kqueue path), `ff_compat.c` (~360 L) |
| Kernel emulation (libplebnet/libuinet derived) | `ff_kern_condvar.c`, `ff_kern_environment.c` (509 L), `ff_kern_intr.c` (108 L), `ff_kern_subr.c` (271 L), `ff_kern_synch.c` (132 L), `ff_kern_timeout.c` (1,266 L; callout subsystem), `ff_lock.c` (448 L; sx/mutex/lockmgr), `ff_log.c` (111 L), `ff_memory.c` (481 L), `ff_subr_epoch.c` (83 L; verify-only), `ff_subr_prf.c` (604 L), `ff_thread.c` (51 L), `ff_vfs_ops.c` (117 L) |
| Networking & netgraph | `ff_route.c` (1,604 L; rtsock partial port + ff_rtioctl), `ff_veth.c` (1,132 L; if_t accessors rewrite at M4), `ff_ng_base.c` (3,887 L; full netgraph framework port), `ff_ngctl.c` (131 L) |
| **14.0+ stub bank (NEW)** | `ff_stub_14_extra.c` (799 L) — central bank for 14.0+ ABI gaps + landing point for 5 runtime-fix patches + defensive `vm_page_alloc_noobj` `panic()` |

### 3.2 Adapter Layer (`adapter/`)

The `adapter/syscall/` directory builds two binaries — `libff_syscall.so` (preloaded into the user application) and a standalone `fstack` instance — that together implement the LD_PRELOAD path. Key files:

| File | Responsibility |
|------|---------------|
| `syscall/ff_hook_syscall.c` / `.h` | LD_PRELOAD POSIX hooks (`socket / bind / connect / accept[4] / listen / close / read / write / send* / recv* / __read_chk / __recv_chk / __recvfrom_chk / ioctl / epoll_* / fork`), dispatched to `ff_*` via shared memory |
| `syscall/ff_linux_syscall.c` / `ff_declare_syscalls.h` | Linux-flag → FreeBSD-flag translation (e.g. `LINUX_SOCK_CLOEXEC`, `LINUX_SOCK_NONBLOCK`) and hook declarations |
| `syscall/ff_socket_ops.h` / `.c` | Per-socket operation context (`sc`) and producer/consumer dispatch logic |
| `syscall/ff_sysproto.h` | Cross-boundary syscall argument struct definitions |
| `syscall/ff_so_zone.c` | Hugepage shared-memory zone management (semaphore IPC path) |
| `syscall/ff_event.c` / `ff_epoll.c` | Epoll adaptation (incl. polling mode) and event delivery |
| `syscall/ff_ring_ops.c` / `.h` *(FF_USE_RING_IPC)* | Lock-free DPDK SPSC `rte_ring` IPC path; replaces the `ff_so_zone` global lock |
| `syscall/Makefile` | Builds both `libff_syscall.so` and the `fstack` instance binary |

LD_PRELOAD-mode applications run as **two separate processes**: the `fstack` instance (links `libfstack.a` + DPDK) plus the user app preloaded with `libff_syscall.so`. The two communicate over Hugepage shared memory — sem-based by default, or a lock-free DPDK SPSC ring when `FF_USE_RING_IPC=1` is set. Compile / runtime switches `FF_KERNEL_EVENT`, `FF_MULTI_SC` and `FF_USE_RING_IPC` further tune behavior; full details in `adapter/syscall/README.md` and `docs/ld_preload_ring_spec/`.

---

## 4. Dependency Overview

```
                    ┌──────────────┐
                    │ Applications │
                    │ (Nginx 1.28, │
                    │  Redis 6.2.6)│
                    └──────┬───────┘
                           │ ff_* API
                    ┌──────▼───────┐
                    │   lib/       │
                    │  F-Stack Core│
                    └──┬───────┬───┘
                       │       │
              ┌────────▼──┐ ┌──▼────────┐
              │  FreeBSD  │ │   DPDK    │
              │  15.0 TCP/│ │ 24.11.6   │
              │  IP Stack │ │ (PMD/EAL) │
              └────────────┘ └──────────┘

  adapter/                    tools/
  LD_PRELOAD Hook ─────────►  ifconfig/netstat/arp/route
  (syscall redirect)          (user-space network tools)
```

### Relation Types

All relationships in the knowledge graph are of `CodeRelation` type (113,858 total in current index), covering:
- Function calls (CALL)
- Type references (USES_TYPE)
- Macro expansions (EXPANDS)
- File includes (INCLUDES)
- Struct member access (HAS_MEMBER)
- Community membership (BELONGS_TO)

---

## 5. Knowledge Graph Usage Guide

### Query Tools (via the GitNexus MCP server)

| Tool | Purpose | Example |
|------|---------|---------|
| `gitnexus_query` | Search execution flows by concept | "packet receive" |
| `gitnexus_context` | View 360° relationships of a symbol | All callers/callees of `ff_init` |
| `gitnexus_impact` | Pre-modification impact analysis | Impact radius of changing `lib/ff_dpdk_if.c` |
| `gitnexus_detect_changes` | Pre-commit change scope check | Verify impact of staged files |
| `gitnexus_rename` | Safe renaming | Batch rename across multiple files |
| `gitnexus_cypher` | Custom graph queries | Advanced analysis |

### Updating the Index

```bash
# Run from the repository root
cd /data/workspace/f-stack

# Check status
npx gitnexus status

# Re-index (incremental)
npx gitnexus analyze

# Force full rebuild
npx gitnexus analyze --force

# Regenerate the human-readable wiki (requires LLM API key in ~/.gitnexus/config.json)
npx gitnexus wiki --force
```

> **Auto-update**: a `post-commit` hook can re-run `npx gitnexus analyze` in the background after each commit; configure once in `.git/hooks/post-commit`.

> **Re-indexing duration**: full rebuild on the current 2,656-file F-Stack surface takes ~11 minutes on this workspace (verified 2026-06-08).

---

## 6. References

- **Upgrade evidence**: `docs/freebsd_13_to_15_upgrade_spec/` — full Markdown record of M0~M5, runtime-fix, Phase-5b, rib-fix, plus dual baselines.
- **3-tier architecture (this knowledge base)**: `docs/01-LAYER1-ARCHITECTURE.md` + `docs/F-Stack_Architecture_Layer1_System_Overview.md`; same for Layer 2 / Layer 3.
- **LD_PRELOAD Ring IPC spec**: `docs/ld_preload_ring_spec/`.

---

*Generated from GitNexus knowledge graph (64,855 nodes, 113,858 edges) — 2026-06-08, commit `208b0c4`. Schema v1 / ladybugdb provider.*
