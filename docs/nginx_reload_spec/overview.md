# Overview — F-Stack nginx Lossless Reload Specification Set (English)

> **English mirror** of `docs/nginx_reload_spec/zh_cn/00-overview.md` (v1.9.11). The Chinese text is
> authoritative; where the two differ, the Chinese original governs. This edition is a structural
> and content sync of the Chinese document, not a line-by-line translation of all 700+ lines.
> Revised 2026-09-30.

---

## 1. Background

nginx on F-Stack runs with a DPDK-owned NIC and a user-space FreeBSD network stack. A plain HUP or USR2
reload replaces the workers, and the question this specification set answers is how to do that **without
losing traffic**: new connections must still be accepted at every instant of the change, and connections
established before it must continue to be served until they close naturally.

## 2. Research scope and method

Two external research lines (VPP/VCL and comparable user-space-stack projects) were run first and converged
independently; their conclusions anchor the evaluation in `06-solution-design.md`. Legacy internal material
(the orange30/iWiki scheme) was analysed to explain why it cannot work on the current stack.

## 3. Core conclusions

### 3.1 Three baseline conclusions (the two external lines converge on these)

1. **No precedent for migrating established TCP connections was found** in the searched range (search cut-off
   2026-09; this does not claim none exists objectively).
2. **Decoupling NIC queue / receive ownership from the business process lifetime** is the structural
   precondition for a lossless reload on a user-space stack.
3. **The "do not cut traffic over before ready" pattern exists isomorphically in both architectures**
   (Facebook LPC 2021: traffic keeps going to the old instance until the new one is ready).

### 3.2 One-line conclusion

- **Why S3 is recommended** — S3 (native multi-process evolution; v1.9 form **M1′**: resident slim primary +
  generation-independent `queue_id` mapping) is the only candidate that satisfies the three baseline
  conclusions without new configuration surface.
  > Note (v1.9): the v1.0–v1.5 form ("ping-pong lcore segment + atomic reta cut-over") was **abandoned in
  > v1.6** — reta is not modified and NIC RSS capability is not required.
- **Why the legacy scheme fails** — the orange30/iWiki scheme relies on "old and new processes coexisting on
  the same core" via a DPDK 18.11 timer-library property that no longer holds.
- **Where LD_PRELOAD sits** — S2 (the `adapter/syscall` LD_PRELOAD route) is a **parallel, alternative product
  line**, appropriate where existing applications cannot be modified; it is not the recommended main line.

### 3.3 Landing path

S3 is decomposed into M0 pre-research → M1 resident primary → M2 coexistence (**both generations on the same
`lcore_id`** + self-driven hardclock) → M3 simultaneous takeover + TX exclusivity + flow_map → M4 drain
completion → M5 USR2 upgrade → M6 gate completion (M7 dispatcher centralisation is optional).

Core elements of the v1.9 form (M1′):

| Element | Content |
| --- | --- |
| Queue | Same queue (generation-independent `queue_id` mapping); reta unchanged, so the four RSS paths (`ff_rss_check`, `adjust_sport`, `tbl`, `thash`) are untouched |
| Hardware ownership | **G_new owns rx poll + tx exclusively**; after the takeover G_old is fully off the hardware (no-hardware mode, protocol stack only) |
| Bidirectional channel | `drain_ring_rx` (G_new → G_old, inbound for existing connections) + `drain_ring_tx` (G_old → G_new, outbound) |
| New-connection decision | flow_map software dispatch table: **the SYN is recorded on admission, before the SYN-ACK goes out** (2026-09-28 A1: single phase, visible at once) |
| Half-open window | G_old stops accepting but **delays closing the listening socket** until its own syncache has drained |
| `lcore_id` / generation isolation | **Both generations use the same `lcore_id`** (human decision D-A; corrected 2026-09-17 by R-05/R-04) |
| Cross-master generation isolation (M5) | Generation directory in hugepage inside the resident primary |

## 4. Reading guide

| Document | Content |
| --- | --- |
| 00 (this one) | Overview, background, conclusions, numbering |
| 01 | VPP/VCL research |
| 02 | Other-project research |
| 03 | Legacy F-Stack scheme |
| 04 | Current F-Stack analysis |
| 05 | LD_PRELOAD alternative |
| 06 | Solution design: candidate comparison and the recommended S3 design |
| 07 | Milestones M0–M7 and the coding work list |
| 08 | Test plan: unit, integration, performance baselines, acceptance criteria |
| 09 | Independent gate audit report |

## 5. Unconfirmed items

Registered, not closed: cross-process MP integration is not wired into the runtime matrix; the extended
fault/boundary matrix has no harness cases for several plan-level paths; the targeted runtime assertions for
the per-generation pool (PT-NR-09 / RV1) are not executed; the `graceful_reload=1` + `syncookies_only=1`
combination is unmeasured (registered as a note 2026-09-30).

## 6. Numbering system

- **RV-xx** research verification items, **DR-xx** decision records, **C-NR-xxx** coding work points,
  **A-NR-xx** acceptance criteria, **UT-NR-xx** unit tests, **IT-NR-xxx** integration tests,
  **PT-NR-xx** performance baselines, **RT-xx** runtime cases, **RG-NR-xx** regression groups,
  **E-NR-xx** experiments, **R-xx** cross-audit findings, **P0-x / 致命 x** severity classes.

## 7. Changes since the previous English edition (2026-09-22)

- New-connection decision restated as "recorded on SYN admission, before the SYN-ACK" (A1 single phase).
- Orphan half-open entry investigation and the undo-on-failure contract added to the design (see
  `solution-design.md`).
- `syncookies_only=1` registered as a note rather than an open defect.
