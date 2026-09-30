# Milestones — M0 to M7 and the Coding Work List (English)

> **English mirror** of `docs/nginx_reload_spec/zh_cn/07-milestones.md` (v1.27). The Chinese text is
> authoritative; where the two differ, the Chinese original governs. This is a structural and content sync
> (numbering, milestone table, coding points, key requirements), not a line-by-line translation of all
> ~700 lines. Revised 2026-09-30.

---

## 1. Numbering and allocation

Coding work points are numbered **C-NR-xxx** per milestone (C-NR-1xx for M1, 2xx for M2, 3xx for M3, 4xx for
M4, 5xx for M5, 6xx for M6). Each work point maps to acceptance criteria (A-NR-xx) and cases in
`08-testing.md`.

## 2. Milestone overview

| Milestone | Goal | Work points | Main files | Prerequisite | Independent acceptance | Rollback point |
| --- | --- | --- | --- | --- | --- | --- |
| **M0** pre-research | One-veto items RV7/RV3/RV10 concluded; DR4 decided, DR2 first assessment; baseline data | — | research docs | — | research report | — |
| **M1** resident primary | All nginx workers are secondaries; the slim primary stays resident across reloads; `graceful_reload` gating | C-NR-1xx | `lib/ff_reload.c`, nginx module | M0 | unit + true-EAL integration | config default 0 |
| **M2** coexistence | Generation-independent `queue_id` mapping; both generations on the same `lcore_id` (D-A); self-driven hardclock | C-NR-2xx | `lib/ff_dpdk_if.c`, `lib/ff_reload.c` | M1 | RT-10, RV1 | per work point |
| **M3** takeover + TX exclusivity + flow_map | flow_map software dispatch table; rx cross-process mutual exclusion; TX exclusivity | C-NR-3xx | `lib/ff_flow_map.c/.h`, `ff_drain_ring.c` | M2 | RT-02/RT-03 | per work point |
| **M4** drain completion | Shutdown timer, drain reporting and forced exit, **half-open connection window (delayed listen close)** | C-NR-4xx | `lib/ff_reload.c`, nginx module | M3 | RT-02/RT-06 | per work point |
| **M5** USR2 upgrade | master exec replaces the generation; the new master attaches to the resident primary; WINCH/QUIT semantics | C-NR-501~504 | nginx module, `lib/ff_reload_gendir.c` | M4 | RT-04/04b | per work point |
| **M6** gate completion | RV9 final gate, RV8/zc/KNI regression, documentation | C-NR-601~604 | `tests/`, docs | M4 (M5 partial) | matrix | — |
| **M7** (optional) | Centralised dispatcher (S3-M2) | separate spec | — | triggered by DR7 | — | separate evolution line |

### Rules that apply to every milestone

- After any code change: `make clean && make` (both `lib/` and the example must exit 0); an incremental build
  passing does not count.
- Comments in `lib/` are minimal; F-Stack code comments are in English; commit messages are English, 1–3
  sentences. `config.ini` local test values are never committed.
- **Each milestone is one or more independently revertable commits** (one per C-NR work point is suggested).
- Documents and test scripts must not contain real IP addresses; shell cleanup / kill / chmod go only through
  `rm_tmp_file.sh`, `kill_process.sh`, `chmod_modify.sh`.
- Definition of done per milestone: unit tests green (no regression in existing ones) + clean build +
  machine runtime regression gates.

## 3. Key requirements (selected)

- **C-NR-301 / A-NR-25**: the four-tuple is recorded **on SYN admission, before the SYN-ACK goes out**, never
  at `accept()` — otherwise the third handshake ACK misses the table and is forwarded to a generation that has
  no half-open entry for it, and the connection is reset. With A1 (2026-09-28) the record is visible
  immediately; the two-phase placeholder form is removed.
- **Admission rule** (2026-09-28): no window ⇒ admit (an untracked window is not a reason to refuse); a window
  that cannot record the four-tuple ⇒ refuse the SYN rather than send a SYN-ACK the draining generation would
  reset.
- **Undo on failure** (2026-09-29): if the SYN-ACK never goes out, the admission is undone — only the record
  this admission created.
- **Half-open window**: G_old stops accepting but delays closing the listening socket until its syncache has
  drained.
- **TX exclusivity**: only G_new calls `rte_eth_tx_burst`; G_old's egress goes through `drain_ring_tx`.
- **Drain bounds**: progress must be observable, and a forced exit path must exist after the budget.

## 4. Changes since the previous English edition (2026-09-22)

- C-NR-301 wording updated to "recorded on SYN admission, before the SYN-ACK" (was "when the SYN-ACK is
  sent"), and the reason restated.
- The admission rule and its first automated assertion registered against C-NR-301.
- The orphan half-open entry investigation registered: the dominant source is the client retransmitting, which
  is generation-agnostic; the A1-specific unbounded source is closed by the undo on failure.
