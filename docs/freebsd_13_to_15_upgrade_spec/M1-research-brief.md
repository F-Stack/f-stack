# M1 — Research Brief

> Chinese version: ./zh_cn/M1-research-brief.md (full data + external citation detail)
>
> Doc series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-28, produced by Sub-agent A `m1-analyzer` before M1 starts)
> Linked: `M1-execution-log.md` §0.1 (kickoff baseline metrics)
>
> NOTE: This English version is a structural condensation. All section headings, sub-section IDs (§1.1 etc.), measured numeric data (NEW/DEL/DIFFER counts, file totals, line numbers, commit references) and the "must-fix spec deviation" entries are preserved verbatim from the Chinese master. Long external-citation prose and per-file 5-step SOP plans are summarized to a few lines; consult the Chinese master for the full narrative.

---

## Table of Contents

§1 mips removal evidence in FreeBSD 15.0 / §2 libkern 13→15 changes / §3 opencrypto 13→15 changes / §4 crypto/ subdir (blowfish / chacha20_poly1305 / curve25519) / §5 vm/ 13→15 changes / §6 arch headers (amd64 / x86 / arm64) changes / §7 netipsec / netgraph / netinet/libalias changes / §8 F-Stack community research / §9 spec-vs-code cross-validation (must-fix items) / §10 Pre-M1 verdict.

---

## §1 mips Architecture Removal Evidence in FreeBSD 15.0

### 1.1 Measured: 15.0 sys/ tree has no mips subdir

Measurement: `ls -d /data/workspace/freebsd-src-releng-15.0/sys/mips/` → not found. Local 15.0 source confirms the removal.

### 1.2 Measured: 15.0 `sys/conf/files` has no mips references

`grep -n 'mips' /data/workspace/freebsd-src-releng-15.0/sys/conf/files` → 0 hits (other than the unrelated word "compile").

### 1.3 Measured: 15.0 `UPDATING` has multiple mips-removal entries

Lines 929-932 / 971 / 1463 / 1643 / 751 of `freebsd-src-releng-15.0/UPDATING` carry mips-related removal notices. Full quotes see Chinese master.

### 1.4 External citation: FreeBSD 15.0 release notes

(To-verify URL — full list in 03 §10.2.)

### 1.5 Conclusion

mips removed entirely from 15.0 upstream; T-cleanup-01 (M1) must delete `f-stack/freebsd/mips/` (586 files).

---

## §2 libkern 13.0→15.0 Changes

### 2.1 NEW / DEL / DIFFER stats (measured)

| Direction | Count |
|---|---|
| 15.0-only (NEW) | 4 |
| 13.0-only (DEL) | 9 |
| differ | 77 |
| 13.0 total | 85 |
| 15.0 total | 80 |

### 2.2 NEW/DEL file inventory

DEL (9): bcmp.c / ffs.c / ffsl.c / ffsll.c / fls.c / flsl.c / flsll.c / mcount.c + arm/ffs.S
NEW (4): see Chinese master §2.2

### 2.3 F-Stack existing adaptation (very small)

Only gsb_crc32.c has 1 F-Stack adaptation (ifunc block `#ifndef FSTACK` wrap). The 15.0 upstream version requires the same wrap to be re-applied as `&& !defined(FSTACK)` inline condition.

---

## §3 opencrypto 13.0→15.0 Changes

### 3.1 NEW / DEL / DIFFER stats

| Direction | Count |
|---|---|
| 15.0-only (NEW) | 3 (ktls.h / xform_aes_cbc.c / xform_chacha20_poly1305.c) |
| 13.0-only (DEL) | 3 (xform.c / xform_poly1305.h / xform_rijndael.c) |
| differ | 33 |
| 13.0 total | 35 |
| 15.0 total | 35 |

### 3.2 NEW/DEL inventory (measured)

(See Chinese master.)

### 3.3 F-Stack existing adaptation

0 adaptation files. Pure cp -a upgrade.

---

## §4 crypto/ Subdir Changes (focus: blowfish / chacha20_poly1305 / curve25519)

### 4.1 NEW / DEL / DIFFER

(See Chinese master.)

### 4.2 Important fact correction: blowfish does NOT exist under either 13.0 or 15.0 sys/crypto

This corrects spec 03 §6 wording: blowfish is removed from the FreeBSD base in 13.0 already (it was in the 12.x era); the 03 wording of "13.0 has, 15.0 removes" is wrong. Recorded in 99 §12.13 (Deviation 1).

### 4.3 chacha20_poly1305 / curve25519: new in 15.0

Added per the 15.0 base crypto refresh; F-Stack does NOT use them; pure cp -a follow.

### 4.4 F-Stack existing adaptation (only 1 case: lowercase filename)

skein/amd64/skein_block_asm.s (lowercase) vs 15.0 upstream skein_block_asm.S (uppercase) — content byte-identical, only the case differs.

---

## §5 vm/ 13.0→15.0 Changes

### 5.1 NEW / DEL / DIFFER

| Direction | Count |
|---|---|
| 15.0-only (NEW) | 1 |
| 13.0-only (DEL) | 2 |
| differ | 51 |
| 13.0 total | 53 |
| 15.0 total | 52 |

### 5.2 NEW/DEL inventory

(See Chinese master.)

### 5.3 F-Stack existing adaptation (2 files)

uma_core.c (13 hunks) + uma_int.h (1 hunk); total 8+1 substantive adaptation blocks.

---

## §6 arch Headers Changes (amd64 / x86 / arm64)

### 6.1 amd64/include 13→15

| Direction | Count |
|---|---|
| 15.0-only (NEW) | 24 |
| 13.0-only (DEL) | 17 (incl. cloudabi32/cloudabi64 subtrees) |
| differ | 238 |
| 13.0 total | 231 |
| 15.0 total | 234 |

### 6.2 x86/include 13→15

(See Chinese master.)

### 6.3 arm64/include 13→15

(See Chinese master.)

### 6.4 F-Stack adaptations on these arch subdirs

5 files total: amd64/include/{atomic.h, pcpu_aux.h, pcpu.h, vmparam.h} + arm64/include/pcpu.h.

---

## §7 netipsec / netgraph / netinet/libalias Changes

### 7.1 netipsec 13→15

| Direction | Count |
|---|---|
| NEW | 2 |
| DEL | 0 |
| differ | 30 |
| F-Stack delta | 0 |

### 7.2 netgraph 13→15

| Direction | Count |
|---|---|
| NEW | 4 |
| DEL | 7 |
| differ | 152 |
| F-Stack delta | 23 LEGACY-13 (ng_socket.c H-2 adaptation) |

### 7.3 netinet/libalias 13→15

(See Chinese master.)

---

## §8 F-Stack Community Research

### 8.1 External search results

Sparse: F-Stack upstream has no documented FreeBSD 15.0 upgrade work; this project is the first attempt.

### 8.2 Indirectly related: FreeBSD 14→15 upgrade community blogs

A few blog posts discuss base FreeBSD 14→15; none address user-space stack ports.

### 8.3 Implications

F-Stack 13→15 must be done from-scratch; no community PR / patch / discussion to inherit.

---

## §9 Spec-vs-Code Cross-validation (must-fix items)

### §9-1 ⚠️ Partial: mips removal timing

spec 03 §2.1 says "removed in 14.0"; precise UPDATING evidence shows the removal started in 14.0 but spans 14.0 → 14.1; this is a small detail (see Chinese master full quote).

### §9-2 ⚠️ Major: blowfish wording in spec 03 §6

spec 03 §6 says "blowfish removed from 15.0"; measurement shows blowfish absent already in 13.0; recorded as 99 §12.13 Deviation 1 spec correction. The wording in spec 03 §6 is wrong.

### §9-3 ⚠️ Wording: `if_t` description

Already corrected in 99 §12.2 (R-2026-05-28-02).

### §9-N (other) — see Chinese master.

---

## §10 Pre-M1 Verdict

| Subdir | Workload tier | Risk |
|---|---|---|
| mips/ (cleanup) | small (1 dir remove) | none |
| libkern/ | small (cp -a 80 + 1 F-Stack reapply) | low |
| opencrypto/ | small (cp -a 36) | low |
| crypto/ | medium (cp -a 300 + 1 F-Stack reapply) | low |
| vm/ | medium (cp -a 50 + uma 8+1 hunks reapply) | medium (DP-9 risk: kassert.h chain → realised; rolled back; M2 redo) |
| amd64/x86/arm64 | large (786 files, 5 F-Stack reapply) | medium (DP-8 defer: 380+286 files; M2 redo) |
| netipsec/ | small (cp -a 32) | low |
| netgraph/ | medium (cp -a 156 + 23 LEGACY + ng_socket.c) | low |
| netinet/libalias/ | small (cp -a 19 + alias_sctp.h) | medium (DP-9 risk: tcp.h __tcp_get_flags chain → realised; rolled back; M2 redo) |
| sys/sys/ (4 headers) | small (per spec only 4 files) | high (DP-9: real scope = 14 adapt + 339 differ; M2 redo) |

**Verdict**: M1 can start; the 4 high-risk items above will likely trigger DP-9 rollback to M2; this is expected and documented.
