# M3 Research Brief

> Chinese version: ./zh_cn/M3-research-brief.md (full data + per-file delta detail)
>
> Doc series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-29, produced by `m3-analyzer` before M3 starts)
> Linked: `Phase-5b-execution-log.md` §7.2 (Phase 5b → M3 hand-off); `M3-execution-log.md`; `99-review-report.md` §12.16
>
> NOTE: This English version is a structural condensation. All section headings, sub-section IDs, numeric data, the "disruptive findings" inventory and the 14.0+ ABI change list are preserved verbatim from the Chinese master.

---

## 0. Executive Summary

### 0.1 Disruptive findings (measurement supersedes spec doc)

1. F-Stack real historical adaptation scope: spec 05 §2.3 listed 22 tasks tagged P0/P1/P2/P3, but M3 measurement shows 5 of 8 net/ files (if.c / if_var.h / route.c / route_ifaddrs.c / if_ethersubr.c) + 3 P0 netinet/ files (in_pcb.c / tcp_input.c / tcp_var.h) are byte-level vendor copies with **zero F-Stack delta**. The real R-013/R-002/R-004 P0 KPI breakage adaptation is **NOT in net/netinet/**; it is in lib/ff_*.c's 14.0+ accessor / SMR / nexthop API adaptation (M4 scope).
2. ff_glue.c false alarm: spec 02 §arch line 167 / spec 03 §3.1 line 136 / spec 05 line 128 all listed ff_glue.c as R-011 disposition, but M3 measurement: 0 protosw / pr_usrreqs / pr_input / pr_output / pr_ctlinput references. ff_glue.c is in fact a user-space stub set (vm/proc/timer/sysctl/malloc/elf). The real R-011 disposition is freebsd/kern/uipc_socket.c (done in M2) + uipc_domain.c + protocol usrreq files (vendor-cp absorbs them in M3).
3. 15.0 upstream adopted F-Stack-style improvements (4 "free rides"): in_mcast.c / in6_mcast.c / rack.c / bbr.c — spec listed them as adaptation tasks but 15.0 upstream uses `sizeof(struct in_msource)` / `MODNAME` patterns matching F-Stack's `#else` branch. ~80 lines of 5-step work saved.
4. Real 14.0+ missing-header list (vs spec 03 §3): netlink/*.h (24 files needed by net/{if_clone,if_vlan}.c) + opt_cc.h KNOB (cc/cc.c) + contrib/ck/ck_queue.h `CK_LIST_FOREACH_FROM` (in_pcb.c). M3 cp 15.0 vendor for all.
5. 14.0+ kprintf `%b`/`%D` extensions trigger user-space `-Wformat` failures (if_bridge.c / if_ethersubr.c / netinet/if_ether.c / tcp_subr.c). Disposition: global `-Wno-error=format` `-Wno-error=format-extra-args` in lib/Makefile.
6. lib stub `DO_NOTHING do{}while(0)` fails in 14.0+ ternary expression context (in_pcb.c:1471). Fix: changed to `((void)0)` for expression + statement context compatibility.
7. libfstack.a archive-of-archive structure: top-level 11 entries (libfstack.ro + 10 ff_*.o); libfstack.ro is the relocatable object aggregating 192 internal .o / 8031 symbols. G-M3 verification uses `nm libfstack.ro | wc -l`, not `ar t libfstack.a | wc -l`.
8. T-ff-02/T-ff-03 listed under M3 but their 14.0+ real adaptation must wait until net/netinet vendor is in place; G-M3 strict link passes under 13.0-era writing + 14.0+ vendor compat layer — real runtime issues only emerge in M4.

### 0.2 Measured metrics

(See Chinese master for the full numeric table.)

---

## 1. M3 Scope and Baseline

| Item | Value |
|---|---|
| M3 scope | net/ 8 files + netinet/ 10 files + netinet6/ + ff_glue.c (verify) + T-ff-02 / T-ff-03 (deferred to M4) |
| Baseline | libfstack.a 4.8M / 191 .o (Phase 5b end) |
| Predecessor decisions | M2 + Phase 5b deferred items all closed; sys/sys + sys/{kern,vm,arch} aligned to 15.0 |

---

## 2. net/ 8 Files Research

### 2.1 Key prerequisite conclusion (overturns spec assumption)

(See §0.1 Disruptive finding 1 — 5 of 8 net/ files have zero F-Stack delta.)

### 2.2 net/ P0 heavyweight files (spec listed as P0; measured all vendor copies)

| File | spec P0 reason | Measured | Disposition |
|---|---|---|---|
| if.c | R-013 if_t opaque | 0 F-Stack delta | vendor cp 15.0 |
| if_var.h | R-013 if_t opaque | 0 F-Stack delta | vendor cp 15.0 |
| route.c | R-004 rib/nexthop | 0 F-Stack delta | vendor cp 15.0 |
| route_ifaddrs.c | R-004 | 0 F-Stack delta | vendor cp 15.0 |
| if_ethersubr.c | (no listed P0) | 0 F-Stack delta | vendor cp 15.0 |

### 2.3 net/ P1 medium files

(See Chinese master.)

### 2.4 net/ P1 simple files (actual 3 needing 5-step SOP)

(See Chinese master.)

### 2.5 net/ scope R-013 if_t field-access table (affects lib/ff_*.c, NOT net/*.c)

(See §0.1 Finding 1; the 28 sites of `ifp->if_xxx` access are in lib/ff_veth.c — M4 scope.)

---

## 3. netinet/ Medium 15 Files Research

### 3.1 P1 simple / zero-adaptation merge section (8 files)

(See Chinese master.)

### 3.2 in_pcb.h (companion to T-netinet-07)

(See Chinese master.)

### 3.3 in_mcast.c (**15.0 upstream adopted same fix = free ride**)

15.0 uses `sizeof(struct in_msource)` matching F-Stack's `#else` branch; no manual port needed.

### 3.4 T-netinet-08/09/10 protosw merge adaptation (**biggest risk**)

(See Chinese master — actually absorbed by vendor cp; protosw merge handled in 15.0 upstream.)

### 3.5 T-netinet-05/06 rack.c + bbr.c (**upstream naturally compatible = free ride**)

15.0 uses `MODNAME` placeholder; F-Stack's `#define MODNAME tcp_rack/tcp_bbr` continues injecting under `#ifdef FSTACK`.

### 3.6 tcp_hpts.c (14.0+ hpts_softclock refactor)

(See Chinese master.)

### 3.7 tcp_syncache.c (LVS_TCPOPT_TOA transparent proxy injection)

LVS_TOA injection point relocation deferred to M4 (since LVS_TCPOPT_TOA is disabled by default; vendor cp suffices for M3 build).

### 3.8 netinet/ scope 14.0+ key ABI change list

(See Chinese master for the full list; key items: pr_usrreqs merged into protosw; SMR-based inpcb lookup; if_t opaque accessors; mbuf m_ext field rearrangement.)
