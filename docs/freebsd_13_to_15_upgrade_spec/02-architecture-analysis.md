# 02 — F-Stack Current Architecture Analysis (Panorama of Adaptation Points vs FreeBSD 13.0)

> Chinese version: ./zh_cn/02-architecture-analysis.md
>
> Series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-26)
> Data source: artifact from **Sub-Agent A (Analyzer-13)** measurement + leader's follow-up consolidation
> Verification baseline: 13.0/f-stack-lib (25 freebsd + 22 tools subdirs) vs f-stack/freebsd + f-stack/tools

---

## 1. Adaptation-Pattern Overview

In the process of "extracting the FreeBSD network stack into user-space + DPDK-izing it", F-Stack applies 9 generic adaptation patterns on top of 13.0 upstream:

| ID | Tag | Meaning | Representative scene |
|---|---|---|---|
| H-1 | `FSTACK-stub` | Wrap the function body with `#ifndef FSTACK` and short-circuit to an empty implementation | `kern_event.c::kqueue_schedtask`, `uipc_socket.c::TASK_INIT(soaio_*)` |
| H-2 | `FSTACK-altimpl` | `#ifdef FSTACK ... #else` to switch to a different implementation | `kern_descrip.c::fhold` rewritten with a self-checking CAS, `uipc_syscalls.c::sendit/recvit` made externally visible |
| H-3 | `FSTACK-include` | Add or drop header includes | `sys/systm.h` masks `<sys/kpilite.h>`, tools mask `<libifconfig.h>` |
| H-4 | `FSTACK-rss-ext` | Add RSS / lport extensions for F-Stack | `in_pcb.c` port range, lport check, ladddr derivation |
| H-5 | `FSTACK-modname` | Rename TCP-stack module names to avoid clashing with upstream | `tcp_stacks/rack.c`, `bbr.c` |
| H-6 | `IPC-replace` | User-space tools replace raw socket / sysctl with `ff_ipc_*` | `tools/ifconfig`, `tools/netstat`, `tools/ipfw`, plus 12 tools in total |
| H-7 | `Makefile-fstack` | Tools' Makefiles wire in libffcompat / libdpdk / `-DFSTACK` / `-include compat.h` | The same 12 tools' Makefiles |
| H-8 | `header-glue` | Add F-Stack macros / trim data structures inside header files | `sys/refcount.h::refcount_acquire_if_not_zero` rewritten |
| H-9 | `vhost-removal` | Remove BPF / KVM / DTRACE / RACCT and similar host paths | `sys_socket.c::soo_fill_kinfo/soo_aio_queue/soo_sendfile` |

> **Adaptation distribution (measured)**:
> - `search_content "FSTACK"` matches **48 files** in `f-stack/freebsd/`
> - `search_content "#ifdef FSTACK"` matches **45 files**
> - Plus size-diff comparison (same name but different bytes: `_callout.h / callout.h / kern_tc.c / kern_uuid.c`, etc.), totaling **~50 files** with substantive semantic adaptations
> - The remaining ~50 of the 102 file diffs are SKIP (metadata / line-ending whitespace / minor license edits / VPATH build artifacts)

---

## 2. Per-File Adaptation Analysis under sys/ Subdirectories

> Data baseline: `/data/workspace/freebsd-src-releng-13.0/f-stack-lib/freebsd/` vs `/data/workspace/f-stack/freebsd/`

### 2.1 `kern/` (kernel common subsystems) — heaviest adaptation

| File | Type | Tag | Motivation |
|---|---|---|---|
| `kern_descrip.c` | MOD | H-2 | `fhold` / `refcount` fast path rewritten with a self-checking CAS (comment: "if loop dead in this function"); RACCT/CAP_RIGHTS in `fdrop/closefp` masked |
| `kern_event.c` | MOD | H-1 | `kqueue_schedtask` body fully stubbed; knote wakeups use direct `KNOTE_UNLOCKED` (F-Stack has no SWI task queue) |
| `kern_linker.c` | MOD | H-2 | In `link_elf_load_file`, `vattr.va_size==0` is treated as success (fake VFS); `elf_cpu_parse_dynamic` stubbed to return 0 |
| `kern_mbuf.c` | MOD | H-1 / H-2 | `realmem` no longer depends on `vm_kmem_size`; `mb_unmapped_*` / `pcpu_page_alloc` / `mb_alloc_ext_pgs` masked (F-Stack has no unmapped/extpg) |
| `kern_sysctl.c` | MOD | H-1 | The `__sysctl` syscall entry is masked (the in-house sysctl_handle path is used) |
| `link_elf.c` | MOD | H-1 | Same as kern_linker, `elf_cpu_parse_dynamic` stubbed |
| `subr_epoch.c` | MOD | H-1 | `taskqgroup_attach_cpu` masked (the stub is provided by `ff_subr_epoch.c`) |
| `subr_param.c` | MOD | H-1 | The wrap-test initializer `ticks = INT_MAX - hz*10*60` is unnecessary in F-Stack |
| `subr_taskqueue.c` | MOD | H-1 / H-2 | `_taskqueue_start_threads` fully stubbed; t_barrier made static to dodge a GCC dangling-pointer warning |
| `sys_generic.c` | MOD | H-1 | The `kern_sigprocmask` block in `kern_pselect` is masked (single-process F-Stack does not handle sigmask) |
| `sys_socket.c` | MOD | H-1 / H-9 | `soo_fill_kinfo / soo_aio_queue / soo_sendfile` (procfs/AIO dependencies) masked |
| `uipc_mbuf.c` | MOD | H-1 + in-house extension `FSTACK_ZC_SEND` | `mbuf_ext_pgs` fully masked; **adds zero-copy path**: under `#ifdef FSTACK_ZC_SEND`, `m_uiotombuf` directly hangs `iov_base` as the mbuf data pointer |
| `uipc_sockbuf.c` | MOD | H-1 / H-9 | `sb_aio` wakeups, RLIMIT_SBSIZE check masked |
| `uipc_socket.c` | MOD | H-1 / H-9 | `TASK_INIT(soaio_*)` masked |
| `uipc_syscalls.c` | MOD | H-2 | The `static` qualifier on `sendit`/`recvit` is removed and they become externally visible, so that `ff_syscall_wrapper.c` can call them directly |

**Adaptation stats**: ~15 files in kern/ have substantive adaptations; the rest (~23 files) of KERN_SRCS are unmodified (F-Stack compiles 13.0 source as-is).

### 2.2 `sys/` (common headers)

| File | Type | Tag | Motivation |
|---|---|---|---|
| `sys/systm.h` | MOD | H-1 + H-8 | Masks `<sys/kpilite.h>`; `critical_enter/exit` stubbed to no-op (no td_critnest in user-space) |
| `sys/refcount.h` | MOD | H-2 | `refcount_acquire_if_not_zero` rewritten with a self-checking CAS |
| `sys/callout.h` | MOD | H-8 | F-Stack callout subsystem simplification |
| `sys/_callout.h` | MOD | H-8 | Companion _callout header |

### 2.3 `netinet/` (IPv4 / TCP / UDP)

| File | Type | Tag | Motivation |
|---|---|---|---|
| `tcp_input.c` | MOD | H-2 / H-4 | inpcb hashlookup adds RSS port range; epoch_call stubbed |
| `tcp_output.c` | MOD | H-2 | `tcp_default_output` boundary-condition adaptation |
| `tcp_subr.c` | MOD | H-1 / H-9 | BPF tap removed; tightly-coupled IPSEC branches removed |
| `tcp_var.h` | MOD | H-8 | Companion tcpcb field tweaks |
| `tcp_stacks/rack.c` | MOD | H-5 | Module name changed to `tcp_rack_fstack` to avoid clashes |
| `tcp_stacks/bbr.c` | MOD | H-5 | Same as above |
| `in_pcb.c` | MOD | H-4 | RSS port-range extension, lport check, ladddr derivation |

### 2.4 `net/` (link layer / VNET / route)

| File | Type | Tag | Motivation |
|---|---|---|---|
| `if.c` | MOD | H-1 / H-9 | Masks the `if_alloc` host-malloc path; uses F-Stack's in-house memory pool |
| `if_var.h` | MOD | H-8 | ifnet field trimming |
| `if_ethersubr.c` | MOD | H-1 | Masks BPF tap inside vlan/lagg |
| `netisr.c` | MOD | H-1 | The netisr main loop is driven by the ff_veth scheduler |
| `route.c` | MOD | H-2 | `rtinit` is bridged via ff_route.c |

### 2.5 `netgraph/` / `netinet6/` / others

| Subdir | Adaptation count | Main pattern | Note |
|---|---|---|---|
| `netgraph/` | 1-2 (`ng_socket.c`, `ng_socket.h` minor diffs) | H-2 | Mostly IPC, exposes ng socket to user-space |
| `netinet6/` | very few | H-2 | IPv6 has the fewest changes |
| `netinet/libalias/` | 1 (`alias_sctp.h`) | header tweaks | F-Stack barely changes libalias |
| `netipsec/`, `opencrypto/`, `vm/`, `libkern/`, `crypto/` | 0 or 1-2 | — | Substantive adaptation is rare |
| `amd64/`, `arm64/`, `x86/` | very few (mostly headers) | H-8 | Mainly header trimming |
| `contrib/` | almost none | — | F-Stack uses `#include <contrib/ck/...>` to call ck and that's enough |

### 2.6 `mips/`

The F-Stack project keeps a mips subdirectory (carried over from the 13.0 copy), but **F-Stack actually only runs on amd64/x86_64 + arm64**, so mips/ is dead code. 15.0 has fully removed the mips architecture → this upgrade's **FR-4** requires its cleanup.

---

## 3. Per-File Adaptation Analysis under tools/

> Data baseline: `/data/workspace/freebsd-src-releng-13.0/f-stack-lib/tools/` vs `/data/workspace/f-stack/tools/`
> Total diffs **163**; main distribution below.

### 3.1 F-Stack-ization mode of the 12 freebsd-native tools (H-6 + H-7)

| Tool | Adaptation thread |
|---|---|
| `arp/` | raw socket → ff_ipc command channel |
| `ifconfig/` | sysctl + raw socket → ff_ipc; libifconfig dependency masked |
| `ipfw/` | raw socket → ff_ipc |
| `libmemstat/` | sysctl → ff_ipc |
| `libnetgraph/` | NgSendMsg/NgRecvMsg → ff_ipc bridge |
| `libutil/` | very few changes (foundation lib) |
| `libxo/` | 0 or very few (foundation lib) |
| `ndp/` | raw socket → ff_ipc |
| `netstat/` | sysctl → ff_ipc; the largest concentration of changes |
| `ngctl/` | NgSendMsg → ff_ipc |
| `route/` | RTM_* → ff_ipc |
| `sysctl/` | __sysctl syscall → ff_ipc command channel |

**Common patterns**:
- The tool's main entry pre-calls `ff_ipc_init()`
- All `socket(PF_ROUTE, ...)` / `sysctl()` / `NgSendMsg()` calls are replaced by the corresponding `ff_ipc_*` functions
- The Makefile adds `-DFSTACK -include compat.h`, links libffcompat and libdpdk

### 3.2 f-stack-lib helper directories (compat / sbin)

| Directory | Content | Role |
|---|---|---|
| `tools/compat/` | 199 files, including `ff_ipc.c` / `ff_ipc.h` / `compat.h` | **F-Stack's in-house IPC bridge**; all 12 tools `-include` it |
| `tools/sbin/` | empty directory | placeholder, no actual content |

### 3.3 f-stack-shipped tools (not from freebsd-src)

| Tool | Role |
|---|---|
| `tools/knictl/` | KNI (kernel network interface) control tool, F-Stack's own implementation |
| `tools/traffic/` | Traffic statistics tool |
| `tools/top/` | F-Stack version of top (not the freebsd-native top) |

> These three tools **do NOT** follow the freebsd-src upgrade path; this Phase 1.4 only does placeholder copies; their evolution belongs to milestone M5.

### 3.4 Helper build files

`lib.mk / Makefile / opts.mk / prog.mk / README.md` form f-stack-lib's own build index; they are not from freebsd-src.

---

## 4. Panorama of f-stack/lib/ ff_*.c & ff_*.h Glue Files

> Data baseline: measured against `f-stack/lib/Makefile`'s `FF_SRCS+=` and `FF_HOST_SRCS+=`; **30 .c + 14 .h** in total.

### 4.1 FF_SRCS (linked into the kernel side, 21 .c)

| File | Function | Key referenced freebsd kernel headers / symbols |
|---|---|---|
| `ff_compat.c` | Generic compat shim | `<sys/types.h>`, `<sys/systm.h>` |
| `ff_glue.c` | Network-stack glue (interacts with `protosw` / socket) | `<sys/protosw.h>`, `<sys/socket.h>`, `pr_usrreqs` |
| `ff_freebsd_init.c` | freebsd subsystem init sequence | `SYSINIT(*)`, `sysent[]` |
| `ff_init_main.c` | main entry | `proc0`, `mi_startup()` |
| `ff_kern_condvar.c` | condvar wrapper (pthread → cv) | `<sys/condvar.h>::cv_*` |
| `ff_kern_environment.c` | kenv | `<sys/kenv.h>::kern_setenv` |
| `ff_kern_intr.c` | intr wrapper | `<sys/interrupt.h>::ithd_create` |
| `ff_kern_subr.c` | misc subr | `<sys/subr_*>` |
| `ff_kern_synch.c` | sleep/wakeup wrapper | `<sys/proc.h>::pause/tsleep` |
| `ff_kern_timeout.c` | callout wrapper | `<sys/callout.h>::callout_*` |
| `ff_subr_epoch.c` | epoch stub | `<sys/epoch.h>::epoch_*` |
| `ff_lock.c` | mtx/rmlock wrapper | `<sys/lock.h>`, `<sys/mutex.h>` |
| `ff_syscall_wrapper.c` | **Critical**: exposes send/recv/accept/connect/bind syscalls to user-space | `kern_pselect`, **`sendit`/`recvit`**, `kern_accept` |
| `ff_subr_prf.c` | printf bridge | `<sys/systm.h>::printf` |
| `ff_vfs_ops.c` | VFS stub | `<sys/vnode.h>` (fake VFS) |
| `ff_veth.c` | virtual ethernet → DPDK bridge | `<net/if.h>::if_alloc`/**`if_t`**, `<net/if_var.h>` |
| `ff_route.c` | route bridge | `<net/route.h>::rtinit`/**`rib`/`nexthop`** |
| `ff_ng_base.c` | NETGRAPH base | `<netgraph/ng_*.h>` |
| `ff_ngctl.c` | NETGRAPH control | same as above |
| (2 implicit ones) | — | — |

### 4.2 FF_HOST_SRCS (user-space side, 9 .c)

| File | Function |
|---|---|
| `ff_host_interface.c` | host interface (lcore / mempool, etc.) |
| `ff_thread.c` | F-Stack threading model |
| `ff_config.c` | configuration loading |
| `ff_ini_parser.c` | ini parser |
| `ff_dpdk_if.c` | DPDK NIC interface |
| `ff_dpdk_pcap.c` | DPDK pcap capture |
| `ff_epoll.c` | epoll compat (user-space) |
| `ff_log.c` | logging |
| `ff_init.c` | host-side init |
| `ff_dpdk_kni.c`, `ff_memory.c` (conditional) | KNI bridge, in-house mempool |

### 4.3 ff_*.h (14 files)

`ff_api.h / ff_config.h / ff_dpdk_if.h / ff_dpdk_kni.h / ff_dpdk_pcap.h / ff_epoll.h / ff_errno.h / ff_event.h / ff_host_interface.h / ff_ini_parser.h / ff_log.h / ff_memory.h / ff_msg.h / ff_veth.h`

### 4.4 ff_* — freebsd-src interface dependency matrix (upgrade-critical)

The table below shows, for each ff_*.c file, the part **most affected by 13→15 interface changes** (it determines the workload of FR-3):

| ff_*.c | Affected by which 15.0 P0 change | Impact level |
|---|---|---|
| `ff_glue.c` | **`pr_usrreqs` merged into `protosw`** | **P0** |
| `ff_syscall_wrapper.c` | `sendit`/`recvit` signatures stable in 15.0, but `kern_pselect` internals may change | P1 |
| `ff_veth.c` | **`if_t` opaque-ization** + `if_alloc()` signature change | **P0** |
| `ff_route.c` | **rib / nexthop new table structure** | **P0** |
| `ff_subr_epoch.c` | Some epoch → SMR scenarios; need to evaluate whether the stub still compiles | P1 |
| `ff_kern_intr.c` | ithd_create signature stable, but the intr subsystem has minor adjustments in 14/15 | P1 |
| `ff_kern_timeout.c` | callout subsystem stable | P2 |
| Other ff_*.c | Mostly stub-like, cross-version stable | P2-P3 |

---

## 5. Cross-reference with Existing F-Stack Architecture Docs

| Existing doc | This section reuses | Increment |
|---|---|---|
| `docs/01-LAYER1-ARCHITECTURE.md` | The freebsd/ tools/ lib/ three-layer split | Adds an adaptation tag for each file |
| `docs/F-Stack_Architecture_Layer1_System_Overview.md` | The sys-subdir partition | Adds the measured 102-diff classification |
| `docs/F-Stack_Architecture_Layer2_Interface_Specification.md` | The ff_*.c interface inventory | Adds the dependency matrix vs the freebsd kernel |
| `docs/KNOWLEDGE_GRAPH_WIKI.md` | The dependency graph | Adds the connections from ff_glue/ff_veth/ff_route to 15.0 P0 change points |

---

## 6. Key Artifacts of This Section (for use by 04 port strategy)

| Artifact | Purpose |
|---|---|
| 9 adaptation patterns table (§1) | "Group by pattern" port tasks in 04 |
| List of 50 substantively-adapted files under sys/ (§2) | "Group by file" port tasks in 04 |
| Classification of 163 diffs under tools/ (§3) | tools upgrade list in 04 |
| 44 ff_* glue files + interface dependency matrix (§4) | FR-3 sub-tasks in 04 |

> Next step: `03-freebsd-15-changes.md` enumerates the full set of 13→14→15 upstream changes; then `04-diff-and-port-strategy.md` cross-cuts this section with 03 to produce the final port task list.
