# Solution Design — Candidate Comparison and the Recommended S3 Design (English)

> **English mirror** of `docs/nginx_reload_spec/zh_cn/06-solution-design.md` (v1.9.16). The Chinese text is
> authoritative; where the two differ, the Chinese original governs. This is a structural and content sync
> (section outline, semantics, key contracts and decisions), not a line-by-line translation of all ~900 lines.
> Revised 2026-09-30.

---

## 1. Evaluation dimensions and criteria

Candidates are compared on: feasibility on the current stack, behaviour under load, intrusion into existing
code and configuration, observability, rollback, and whether the change can be reverted per milestone.

## 2. Target semantics — what "lossless" means exactly

1. **Zero loss for new connections** — at every instant an arriving SYN is taken by some process and accepted;
   brief queueing is allowed, RST or silent drop is not.
2. **Graceful drain of existing connections** — served by the old workers until natural close; old TCP timers
   (RTO / keepalive / delayed ACK) keep running; **TCP state migration across processes is out of scope**.
3. **Configuration failure rolls back** — aligned with kernel nginx HUP.
4. **Both HUP and USR2** — same data-plane mechanism for both.
5. **Lossless in the engineering sense** — the HAProxy-documented boundary applies; acceptance is gated on
   zero client errors under load.
6. **Flow table active only during the reload window; reload is re-entry protected** — created for the window,
   closed afterwards; a reload during a window is refused rather than nested.
7. **Simultaneous takeover of rx + tx + listen after READY; G_old becomes a software-parasitic process.**
8. **Both generations use the same `lcore_id`** (final v1.9 decision D-A; corrected 2026-09-17).
9. **ARP/NDP and other protocol packets are cloned to G_old** during the window.
10. **reta is not modified; NIC RSS capability is not required.**
11. **Self-driven hardclock**, avoiding the DPDK shared timer slot (mandatory because of D-A).
12. **Per-generation mempools and the shared RX pool** (mandatory because of D-A).
13. **TX exclusivity and the bidirectional `drain_ring`** (added in v1.9, resolves P0-1/P0-2).
14. **Half-open connection window** (added in v1.9, resolves P0-5) — a SYN taken by G_old before the handover
    whose ACK arrives after it is still completed.
15. **Generation-independent `queue_id` mapping plus msg_ring / KNI generation isolation rules.**

## 3. Candidate set and comparison

Candidates S1 (restart-based), S2 (LD_PRELOAD adapter), S3 (native multi-process evolution) and the legacy
scheme are compared in §3–§4 of the Chinese document; S3 wins because it is the only one that keeps queue
ownership decoupled from process lifetime without new configuration surface and without requiring NIC RSS.

## 4. Recommended design (S3 / M1′) — key points

### 4.1 Data plane

- Resident slim primary; all nginx workers are secondaries.
- Same `queue_id` for both generations; reta untouched.
- On READY, G_new takes rx + tx + listen simultaneously; G_old goes off hardware and runs parasitic.
- `drain_ring_rx` / `drain_ring_tx` carry G_old's traffic; a full `drain_ring_rx` drops established-connection
  packets and must be counted and logged.
- Self-driven hardclock and per-generation mempools resolve the two same-`lcore_id` conflicts
  (`priv_timer[lcore_id]`, `local_cache[lcore_id]`).

### 4.2 Flow map (software dispatch table)

- Active only during the window; created on window open, closed afterwards.
- **A SYN is recorded on admission, inside `syncache_add`, before the SYN-ACK goes out, and the entry is
  visible to `ff_flow_map_lookup()` immediately (A1, 2026-09-28).** The two-phase placeholder form is removed.
- Public API (installed header `lib/ff_flow_map.h`):
  - `ff_flow_map_active()` — cheap gate, so steady state does not even build a key;
  - `ff_flow_map_admit(key, created)` — the admission rule: admits unconditionally with no window open,
    otherwise admits only when the four-tuple can be recorded, and reports whether it created the record;
  - `ff_flow_map_insert(key)` — records a four-tuple; idempotent (a repeat returns 1 and takes no second slot);
  - `ff_flow_map_lookup(key)` — the dispatcher's decision (hit = this generation, miss = forward to G_old);
  - `ff_flow_map_revoke(key)` — undoes an admission, used when the SYN-ACK never went out;
  - `ff_flow_map_cap_set(cap)`, `ff_flow_map_stats2(...)` (inserted / duplicate / full / grown / grow-fail /
    alloc-fail / capacity / revoked), `ff_flow_map_close()`.
- Capacity `FF_FLOW_MAP_ENTRIES = 1<<16`, linear-probe limit `FF_FLOW_MAP_PROBE_MAX = 16`; the table may
  double once within bounds. There is **no general delete interface** — the only reclaim is closing the table.
  A full table **refuses the SYN**: the stack frees the entry and counts `tcps_sc_dropped`, and never sends a
  SYN-ACK that the draining generation would only answer with an RST.

### 4.3 Failure path

If the SYN-ACK cannot be sent, the half-open entry is dropped (`syncache_free`, `tcps_sc_dropped`) and the
admission is **undone** by `ff_flow_map_revoke()` — only when this admission created the record. Two counters
(`SYN-ACK failures`, `handshake ACK mismatches`) plus the revoked count are printed at ~1 Hz as deltas, so a
healthy round stays silent, and case **rt26** asserts them on a real stack.

### 4.4 Orphan half-open entries (investigated 2026-09-29)

A retransmitted SYN is a pure SYN and is **always kept local** (the dispatcher never forwards it), so each
generation holds its own half-open entry with its own ISN. Three sources were identified:

| Source | Relation to A1 |
| --- | --- |
| ① the client retransmits (the first SYN-ACK was lost or abandoned) | **generation-agnostic** — the same under the two-phase form |
| ② double SYN-ACK (the client ACKs G_old's ISN but the ACK arrives after G_new recorded the tuple) | A1 is worse, but only inside the sub-millisecond window between recording and sending |
| ③ G_new's SYN-ACK never goes out | A1 is worse and the window was unbounded — **closed by `ff_flow_map_revoke()`** |

Measured: over ≈1.26 M connections the double-SYN-ACK case did not occur; forcing retransmission (0.1 % of
SYN-ACKs dropped at the client) reproduces the stranded entries, which are now bounded by the drain grace.

## 5. Risks and unconfirmed items

The DPDK multi-process prohibition is isolated for the **two identified paths only** (mempool, timer); other
per-`lcore_id` shared slots are not enumerated. Takeover proof, slot recycling, USR2 state machine and
hardclock acceptance are verified at unit / true-EAL integration level, with the runtime matrix for some paths
still not executed and registered as such.

## 6. Changes since the previous English edition (2026-09-22)

- Semantics restated: the flow is recorded on SYN admission before the SYN-ACK (A1 single phase).
- `ff_flow_map_admit(key, created)` and `ff_flow_map_revoke(key)` added to the public API; the admission rule
  and the refusal path are now testable and asserted on a real machine.
- Orphan half-open entry investigation recorded, with the three sources and their relation to A1.
- R-23 ("full table consequence") corrected: the stack refuses the SYN; it does not forward a flow that will
  be reset.
- R-24 residual (`graceful_reload=1` with `syncookies_only=1`) registered as a note: admission is unchanged in
  cookies-only mode and no syncache entry is ever created, so the drain is not held up; the cross-generation
  cookie case is unmeasured (the cookie secret is per process).
