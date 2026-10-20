# M2 Kickoff Research Brief

> Chinese version: ./zh_cn/M2-research-brief.md (full data + per-file delta detail)
>
> Doc series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-29, produced by `m2-analyzer` before M2 starts)
> Linked: `M1-execution-log.md` §7.3 (M1 → M2 hand-off); `M2-execution-log.md` §3 (5-tier progress); `99-review-report.md` §12.13
>
> NOTE: This English version is a structural condensation. All section headings, sub-section IDs, measured numeric data (NEW/DEL/DIFFER counts, F-Stack delta hunk counts, line counts), 14.0+ ABI change inventory and the build-dependency-graph rationale are preserved verbatim from the Chinese master.

---

## 1. sys/sys Full 339 DIFFER Risk Map (DP-9-A redo scope)

### 1.1 13 → 15 NEW/DEL/DIFFER full stats (measured)

| Direction | Count |
|---|---|
| 15.0-only (NEW) | 38 |
| 13.0-only (DEL) | 4 LEGACY-13 |
| differ | 325 |
| 13.0 total | 342 |
| 15.0 total | 376 |

### 1.2 14 sys/sys F-Stack adaptation files (delta-13 / upstream 13→15 measurement)

(Full per-file table in Chinese master.)

Files: cdefs.h / counter.h / filedesc.h / malloc.h / namei.h / random.h / refcount.h / resourcevar.h / socketvar.h / stdatomic.h / systm.h / user.h / callout.h / _callout.h. Per-file delta-13 sizes range 5-50 lines.

### 1.3 Risk assessment

(M2 Phase 1 closes by full-scope cp 15.0 + per-file `#ifndef FSTACK` re-apply.)

---

## 2. vm/uma Risk Assessment (DP-7 redo scope)

### 2.1 vm/ 13 → 15 measured

| Direction | Count |
|---|---|
| 15.0-only (NEW) | 1 |
| 13.0-only (DEL) | 2 |
| differ | 51 |
| 13.0 total | 53 |
| 15.0 total | 52 |

### 2.2 F-Stack vm adaptation files (only 2; consistent with M1 measurement)

uma_core.c (13 hunks of `#ifndef FSTACK`) + uma_int.h (1 hunk).

### 2.3 Key tailwind: F-Stack's 8 core symbols in vm/ all present and count-stable in 15.0

(Critical for the 5-step SOP — see Chinese master for the symbol list.)

---

## 3. arch (amd64/x86/arm64) Risk Assessment (DP-8 redo scope)

### 3.1 13 → 15 NEW/DEL/DIFFER measured (revising M1 estimate)

(See Chinese master for the full 3-arch table.)

### 3.2 5 F-Stack arch adaptation files (minimal delta-13)

amd64/include/{atomic.h, pcpu_aux.h, pcpu.h, vmparam.h} + arm64/include/pcpu.h. Each delta-13 12-37 lines.

### 3.3 arm64 NEW=98 scan of newly added subdirs

(See Chinese master.)

---

## 4. kern/ + ff_kern_* Adaptation Inventory (spec original M2 scope)

### 4.1 F-Stack kern adaptation files measured (17 files; spec listed 15 + misc)

(Full list and per-file delta-13 in Chinese master.)

### 4.2 4 P0 adaptation files: delta-13 vs upstream 13→15

| File | delta-13 (lines) | 13→15 upstream change | 14.0+ ABI break |
|---|---|---|---|
| kern_descrip.c | 147 | const cap_rights_t / fde_change_size del / p_tracevp del / fdinit args / fo_stat sig change / etc. (13 ABIs) | yes — DP-M2-5 split to Phase 5b |
| kern_mbuf.c | 75 | m_ext rearrangement (R-003) + 14.0+ m_snd_tag / m_rcvif | yes — DP-M2-5 |
| uipc_mbuf.c | 58 | m_uiotombuf rewritten via mchain | yes — DP-M2-5 |
| uipc_socket.c | 16 | CURVNET_ASSERT_SET 14.0+ added | yes — DP-M2-5 |

### 4.3 lib/Makefile KERN_SRCS measured (37; spec listed 38)

(See Chinese master for cross-validation.)

### 4.4 ff_kern_* files measurement

(All 9 ff_kern_* files verify-only — byte-identical with 13.0; no ABI conflict with M2-upgraded kern.)

---

## 5. netinet/libalias Risk Assessment (DP-9-B redo scope)

(F-Stack 0 delta; 14.0+ tcp.h `__tcp_get_flags / tcp_set_flags / TH_RES1` chain blocked M1; M2 unblocks via tcp.h cp from 15.0.)

---

## 6. Compile-Dependency Graph (rationale for M2 7-Phase order)

(See Chinese master full DAG; in summary:
Phase 1 sys/sys headers → Phase 2 vm/uma (depends on sys/sys) → Phase 3 amd64+x86+arm64 (independent) → Phase 4 netinet/libalias (depends on Phase 1 tcp.h cp) → Phase 5 kern KERN_SRCS (depends on all above) → Phase 5b deferred P0 kern (DP-M2-5) → Phase 6 ff_kern_* verify → Phase 7 G-M2 strict build.)
