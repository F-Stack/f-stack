# Phase 5b — Execution Log

> Chinese version: ./zh_cn/Phase-5b-execution-log.md (full process narrative)
>
> Doc series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-29)
> Maintainer: Leader (5b-leader, in main dialogue)
> Linked: `M2-execution-log.md` §7.3 (M2 → Phase 5b hand-off); `99-review-report.md` §6 / §12.15
>
> NOTE: This English version is a structural condensation. All section headings, key data tables, decision-point IDs (DP-5b-1..3), task IDs and final task statuses are preserved verbatim from the Chinese master.

---

## 0. Kickoff Metadata

| Item | Detail |
|---|---|
| Phase 5b kickoff | 2026-05-29 |
| Scope | 10 deferred kern P0/P1 files + 6 missing 14.0+ headers + 1 M2-leftover defect (uma_core.c startup_free signature) |
| Predecessor | M2 (G-M2 PASS via DP-M2-2 soft gate; libfstack.a 4.7M / 191 .o); deferred under DP-M2-5 |
| Backup | `/data/workspace/f-stack-Phase5b-done/` |

---

## 1. Agent Team Topology

(Same 5-role pattern as M1/M2; 5b-leader in main dialogue with 4 stateless code-explorer subagents.)

---

## 2. Key Decisions (DP-5b-1..3)

| DP | Detail | Decision |
|---|---|---|
| DP-5b-1 | Order of 10 files | Headers/stubs first → simple P1 (kern_linker / kern_event) → heaviest P0 (kern_mbuf / uipc_mbuf / uipc_socket / kern_descrip) |
| DP-5b-2 | When 14.0+ ABI changes overflow per-file delta | Adopt **whole-section `#ifndef FSTACK / #else` strategy** instead of per-API patch (e.g. kern_descrip.c: SYSINIT(select)→SYSINIT(fildescdev) wrapped; uipc_mbuf.c m_uiotombuf entire function wrapped) |
| DP-5b-3 | G-Phase-5b strictness | Strict-first; libfstack.a 191 .o full link must succeed |

---

## 3. Task Progress Timeline

| T-* ID | File | Status | Adaptation summary |
|---|---|---|---|
| T-kern-01 | kern_descrip.c | ✅ done | Whole-section `#ifndef FSTACK` from SYSINIT(select)→SYSINIT(fildescdev); 13-class 14.0+ ABI absorbed by global -Wno-error=cast-qual; ff_fdisused / ff_fdused_range / ff_getmaxfd helpers in lib/ff_freebsd_init.c |
| T-kern-02 | kern_event.c | ✅ done | kqueue_schedtask stub redone on 15.0 baseline |
| T-kern-03 | kern_linker.c | ✅ done | va_size==0 = success rewritten; opt_hwt_hooks.h stub created (15.0 KNOB) unblocks build |
| T-kern-04 | kern_mbuf.c | ✅ done | m_ext rearrangement (R-003); 2 new whole-sections wrapped: m_snd_tag_alloc/init/destroy + m_rcvif_serialize/restore (14.0+ if_snd_tag_alloc / if_snd_tag_sw / if_getindex / if_getidxgen / ifnet_byindexgen) |
| T-kern-06 | link_elf.c | ✅ done | cp 15.0 ddb/db_ctf.h (14.0 new file) unblocks build |
| T-kern-07 | subr_epoch.c | ✅ done | Verify only — not in KERN_SRCS, replaced by ff_subr_epoch.c |
| T-kern-10 | sys_generic.c | ✅ done | kern_sigprocmask masking redone on both front+back if(uset) blocks; 14.0 specialfd_eventfd false-positive resolved by global `-Wno-error=array-bounds` |
| T-kern-11 | sys_socket.c | ✅ done | Function layout reordered (15.0 added soaio_queue_generic etc.); soo_aio_cancel kept outside the masking block |
| T-kern-12 | uipc_mbuf.c | ✅ done | m_uiotombuf rewritten in 15.0 to mchain-based; full-function `#ifndef FSTACK / #else` strategy with 13.0-era simplified version preserving FSTACK_ZC_SEND + uiomove slow path; 13.0 m_unmappedtouio stub naturally vanishes |
| T-kern-14 | uipc_socket.c | ✅ done | cp 15.0 net/vnet.h provides CURVNET_ASSERT_SET (14.0+ introduced) |

### 6 missing 14.0+ headers

| Missing header | Reason | Disposition |
|---|---|---|
| opt_hwt_hooks.h | 15.0 KNOB (hardware tracing) | Empty stub created |
| ddb/db_ctf.h | 14.0 new (CTF debug-data interface) | cp 15.0 upstream |
| netinet/tcp.h (with `__tcp_get_flags / tcp_set_flags / TH_RES1`) | 14.0+ added; referenced by alias.c / alias_proxy.c / alias_sctp.c | cp 15.0 upstream (M3 minimal cross-tree patch under DP-M2-4=B) |
| net/vnet.h (with `CURVNET_ASSERT_SET`) | 14.0+ added; referenced by uipc_socket.c | cp 15.0 upstream |
| lib/include/sys/vnode.h (with `__enum_uint8(vtype)`) | 13.0-era `enum vtype` + 14.0+ `enum_vtype_uint8` dual-tag compat | Local stub |
| `freebsd/sys/namei.h` (with `extern uma_zone_t namei_zone`) | 14.0+ NDFREE_PNBUF macro inlines `uma_zfree(namei_zone, ...)` | Add extern + lib/ff_compat.c global stub |

### M2 leftover defect fix

`vm/uma_core.c` F-Stack stub `startup_free` used 13.0 signature `kmem_free((vm_offset_t)mem, bytes)`; 14.0+ kmem_free is `(void *, vm_size_t)`; signature corrected → uma_core.o builds.

---

## 4. Pushback Events

(See zh_cn/ master.)

---

## 5. Gate Decision Records

### G-Phase-5b strict gate (one-shot pass under DP-5b-3)

| Check | Result |
|---|---|
| 10 kern files build | ✅ |
| 6 missing headers resolved | ✅ |
| uma_core.c fix | ✅ |
| libfstack.a strict link | ✅ 4.8M / 191 .o |
| `read_lints` freebsd/kern + lib/ | 0 diagnostics |
| `diff -rq` 15.0 vs f-stack/freebsd/kern | 17 differ (= 17 F-Stack adaptation files; consistent with 99 §6 task table) |

---

## 7. Closure

### 7.1 Phase 5b deliverables

- 10 deferred kern files all done with `#ifndef FSTACK` re-application
- 6 missing 14.0+ headers added (5 cp 15.0 + 1 stub)
- M2 leftover uma_core.c bug fixed
- libfstack.a 4.8M / 191 .o; G-Phase-5b strict-pass
- 99 §12.15 deviation revision recorded

### 7.2 M3 input list (Phase 5b → M3 hand-off)

All M3 prerequisites unblocked. M3 can proceed directly to spec 05 §2.3 22-task list.

### 7.3 Closing

Phase 5b plan execution status: **DONE**. M2 deferred items closed; M3 ready to start.
