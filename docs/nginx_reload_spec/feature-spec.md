# F-Stack nginx Lossless Reload — Feature Specification (English)

> **Status of this document.** This is the English feature edition. It mirrors the Chinese specification under
> `docs/nginx_reload_spec/zh_cn/` (00–09). **The Chinese text is authoritative**: where the two differ, the Chinese
> original governs, and any correction is applied there first and then reflected here.
> Chinese source versions at this revision: 00 v1.9.11, 06 v1.9.16, 07 v1.27, 08 v1.23, 09 v1.9.14.
> Previous edition: 2026-09-22 (00 v1.9.9, 06 v1.9.10, 07 v1.22, 08 v1.20). Revised 2026-09-30.
> IP addresses below are descriptive placeholders (see §7).

---

## 1. Goal and scope

Deliver a **lossless reload** for nginx on F-Stack (DPDK-owned NIC, user-space FreeBSD network stack), i.e. a
reload that keeps serving traffic across a generation change. Scope:

1. **Zero loss for new connections** — at every instant of the reload, an arriving SYN is taken by some process and
   accepted. Brief queueing in the NIC rx ring or the stack backlog is allowed; RST or silent drop is not.
2. **Graceful drain of existing connections** — connections established before the reload are served by the old
   workers until they close naturally (client close or keepalive timeout). During drain, the old workers' TCP timers
   (RTO / keepalive / delayed ACK) keep running. **Migration of TCP state across processes is explicitly out of scope.**
3. **Rollback on configuration failure** — aligned with kernel nginx HUP semantics: a configuration that fails to
   parse rolls back and the old configuration keeps running.
4. **Both HUP and USR2** — HUP replaces the configuration, USR2 replaces the binary (exec); the two share the same
   data-plane mechanism.
5. **Flow table is active only during the reload window, and reload is re-entry protected** — the software dispatch
   table is created for the window and closed afterwards, and a reload requested while one is in progress is refused
   rather than nested.
6. **Lossless in the engineering sense** — following the boundary stated in the HAProxy documentation cited by the
   Chinese spec: connections sitting in a backlog may still be lost with very small probability at the boundary.
   Acceptance is gated on **zero client errors under load**, not on an absolute claim. (Items 1–4 above are the first
four of the fifteen target semantics of the Chinese source; item 5 — flow-table windowing and re-entry protection —
is included here because the runtime evidence in §4 depends on it; item 6 is the engineering-sense boundary.)

## 2. Chosen form (M1′)

Retained form after the v1.9 cross-audit: **resident slim primary + same `queue_id` (generation-independent queue
mapping) + simultaneous takeover of rx + tx + listen once the new generation is READY + G_new exclusively owning the
hardware with G_old running software-parasitic + bidirectional per-generation `drain_ring` + flow_map software
dispatch table + rx mutual exclusion + both generations on the same `lcore_id` + same-`lcore_id` resource isolation
(self-driven hardclock and per-generation mempools) + msg_ring/KNI generation isolation + heartbeat and rx return +
ARP/NDP clone**.

Decisions that constrain the design:

- **D-A: both generations use the same `lcore_id`** (human decision, 2026-09-01). Consequence: `lcore_mask`,
  `nb_procs` and queue counts stay at N — no new configuration surface. Two real same-slot conflicts follow and are
  mandatory to solve: `priv_timer[lcore_id]` (solved by the self-driven hardclock) and the mempool
  `local_cache[lcore_id]` (solved by the per-generation pool layout).
- **DPDK multi-process prohibition**: `multi_proc_support.rst:169-172` forbids primary/secondary on the same logical
  core, and its stated reason is corruption of memory pool caches, *among other issues*. This design isolates
  **the two identified paths (mempool and timer) only**; other per-`lcore_id` shared slots are **not enumerated**.
  It does not claim the prohibition "does not apply".
- **TX exclusivity**: G_new is the only process calling `rte_eth_tx_burst`. G_old's drain-time egress (retransmits,
  keepalives, FINs, data ACKs, SYN-ACK retransmits) is forwarded through `drain_ring_tx` and sent by G_new.
  Both rings are created per generation with explicit flags; a full `drain_ring_rx` drops **established-connection
  packets** and must be counted and logged, unlike the silent `dispatch_ring` drop path.
- **When a flow is recorded (A1, 2026-09-28)**: a SYN is recorded inside `syncache_add`, **before the SYN-ACK goes
  out**, and the entry is **visible to `ff_flow_map_lookup()` immediately**. The earlier two-phase form — an
  invisible `RESERVED` placeholder promoted by `ff_flow_map_commit()` once the SYN-ACK was out — is **removed**;
  `ff_flow_map_commit()` and `FF_FLOW_SLOT_RESERVED` no longer exist. The insertion point (SYN admission, before the
  SYN-ACK) and the "a table that cannot hold the four-tuple refuses the SYN" protection are both kept.

## 3. Key contracts (selected, with current status)

| Contract | Current state |
| --- | --- |
| Per-generation application pool cache (`ff_shared_pool_cache_size`, `lib/ff_dpdk_if.c:669-673`) | **Fixed by R-01**: `graceful_reload=1 ⇒ cache_size=0`, so cross-generation frees never touch `local_cache`. Mechanism + build/unit level only; the targeted runtime assertions (PT-NR-09 / RV1) are **still not executed** and remain registered. Not a claim that all cross-generation races are zero. |
| Generation directory in hugepage (`lib/ff_reload_gendir.c`) | Registration failure is **fail-closed** (no fallback to epoch 0, no slot hopping); cross-master epoch isolation. |
| Takeover proof | A takeover (USR2 release, heartbeat reclaim, generation-directory reclaim) requires proof that the hardware users of the displaced coordinate have stopped or exited; heartbeat-stall takeover is counted as forced. *Verified at unit / red-green / true-EAL integration level; the runtime matrix for these paths is not executed and remains registered.* |
| Slot recycling | Requires master death **and** a stale slot stamp; orphan workers still refreshing the stamp keep the epoch live. A temporarily unrecyclable slot is retried within a bounded budget **on the same slot** instead of hopping to another slot (R-16); budget exhaustion fails the attach and counts `reclaim_refused`. *Same verification status as the row above.* |
| USR2 state machine | The generic FSM header (`ngx_ff_reload_fsm.h:29-36`) defines `T0_IDLE…T5_GOLD_QUIT/T_ERROR` only; the USR2-specific states (`PENDING`/`HANDED`) live in `ngx_process_cycle.c` (`ngx_ff_usr2_state`, plus `ngx_ff_usr2_begin/handover/reclaim/check`). WINCH registration is **not** proof that all workers are READY. |
| Hardclock acceptance | Bound to the **PT-NR-08 functional criterion (single-shot deviation ≤ 1 tick)**; the earlier "≤5% versus baseline" figure is retired because the `rte_timer` (hooked-tick) baseline is unmeasurable. Short timers take the stricter of absolute and relative bounds. |
| SYN admission rule (I-5, 2026-09-28) | `ff_flow_map_admit(key, created)` is the single authority. With no window open it always admits — an untracked window is not a reason to refuse a connection. Inside a window it admits only when the four-tuple can be recorded; otherwise the SYN is **refused** (no SYN-ACK, `syncache_free` + `tcps_sc_dropped`), because a SYN-ACK the draining generation can only answer with an RST is worse than a refused SYN. Unit tested (`test_a1_flow_map_admission_rule`) with a discriminating negative control. |
| Undoing an admission (2026-09-29) | When the SYN-ACK never goes out, the admission is undone by `ff_flow_map_revoke()` — **only** when this admission created the record (`created`); a duplicate four-tuple belongs to an earlier SYN and is kept. Deletion shifts the following probe-chain entries back so none of them becomes unreachable. Asserted on a real stack by case **rt26** (`synack_fail > 0` and `revoked > 0`). |

## 4. Verification performed

Runtime harness: `tests/integration/test_graceful_reload.sh`
(default cases: precheck, baseline, rt01, rt02, rv9, gr0, rt12, rt13; the rt2x fault cases and rt30/rt31 are opt-in).

| Case | Result (representative) |
| --- | --- |
| rt01 (unloaded HUP) | PASS — FSM 6/6, drain ≈1000 ms |
| rt02 (HUP under 12 active streams) | PASS — drain ≈48 s, 3 waves × 12 streams, `ok=36 md5_ok=36 eof_clean=36 stalls=0` |
| rv9 (100 reload rounds, IPv4) | PASS — `ok=100/100`, rtemap flat (138→138), hugepages restored (2048) |
| rt01 / rv9 (IPv6, 20 rounds) | PASS — `ok=20/20`, fresh connections 1949, `fresh_fail=0` |
| gr0 (`graceful_reload=0` control) | PASS — longest outage 1.001 s |
| rt12 (KNI / virtio_user management plane) | PASS — veth survives the reload (`veth_before=1 veth_after=1`); client-side ICMP crosses the KNI path (`ping_client=ok`, the authoritative probe); the server-local ping is recorded only as a weak, local-scope observation (`ping_local=ok(local-scope,weak)`), and `control_http=n/a` |
| rt13 (zero-copy form) | Excluded by decision — not tested, not supported |
| baseline (long-run control) | PASS — 9600 requests, `fail=0 reconnects=0 fresh_fail=0` |
| rt30 (high CPS, 110 s) | PASS — ≈820 k connections at ≈7450 req/s, `fail=0`, drain ≈1–4 s |
| rt31 (48 long connections, 110 s) | PASS — ≈52.7 k requests, one closure per connection, `fresh_fail=0` |
| rt26 (SYN-ACK that cannot be sent) | PASS (fault-injection build only) — `synack_fail=4 revoked=2`, reload completes, worker count restored |

Harness changes in the recent rounds:

- A probe that reports a summary but fails its own criterion is recorded as **FAIL**, never as `NO_DATA`/`SKIP`;
  oversized payloads are rejected instead of decaying into `NO_DATA`.
- The reload is **anchored on the probe's own progress** instead of a fixed sleep: the HUP is sent once the probe
  has run for a given time and produced a given number of requests, and the anchor and the remaining probe time are
  recorded in the measured text.
- The generated nginx configuration sets `keepalive_requests` explicitly. nginx's default of 1000 closes a
  long-lived connection a second time on a 110 s run, which the long-connection criterion would count as another
  failure even though the drain only closed it once.
- The supervisor control channel no longer treats a refused signal as a failed run: the controlled signal helper
  legitimately refuses while its target is exiting, so a refusal is retried once and is moot once the target is
  gone; only a target that is still alive after a short grace fails the run. Failures now report the operation, the
  elapsed time and the exception instead of a bare exit code.

## 5. Known gaps (registered, not closed)

- Extended fault/boundary matrix: some plan-level paths still have **no harness cases** — re-entry, READY
  late/absent, handover failure, primary death, worker stall, USR2→WINCH with two distinguishable binaries,
  listen timing, keepalive/timeout, same-`lcore_id` alloc/free, ARP/NDP, full ring/table, unregister reuse,
  slot holes vs. live master, KNI-off control, pool audit.
- Cross-process MP integration is not wired into the runtime matrix.
- `D-NEW-3`: the exceptional TX-guard drop (integration test `it_a09_send_burst_guard`) is real but its magnitude
  under real load is unmeasured; it does not invalidate A-NR-24's steady-state verdict.
- The combination `graceful_reload=1` with `net.inet.tcp.syncookies_only=1` is **not measured** (no case, no runtime
  data). Registered 2026-09-30 as a note rather than as an open defect. What the code does prove: admission is
  unchanged in cookies-only mode, and no syncache entry is ever created, so the drain is not held up by half-open
  entries; what is unknown is the failure mode when one generation claims an ACK carrying a cookie minted by the
  other (the cookie secret is per process).
- The SYN-ACK failure fault fires **once per process**, so it proves the failure branch and the undo but not
  sustained failures, and it does not pin the failure to the drain phase.

## 6. Audit closure

29 cross-audit findings (A01-*, B01-*, B02-1, C01-*, M02-*, M03-*) are all closed: 12 in code or harness, 17 by
documentation alignment. Per-finding state, fix batch and evidence are recorded in
`work/recheck-20260918/findings.json`.

## 7. Reporting convention

Documents and plans use **descriptive IP placeholders**. Real runtime configuration, captures and the archived logs
under `work/` may contain real addresses, but that directory is git-ignored (`.gitignore:52`) and is **never
committed**. Local `config.ini` is not part of any commit.

## 8. Changes since the 2026-09-22 edition

| Area | Change |
| --- | --- |
| Flow-map admission (A1) | Two-phase admission removed; the SYN is recorded before the SYN-ACK and is visible at once. Insertion point and the "table full refuses the SYN" protection kept. |
| Admission rule (I-5) | `ff_flow_map_admit(key, created)` added and unit tested; refusal semantics made explicit and testable without the stack. |
| Orphan half-open entries | Investigated on a real machine: a retransmitted SYN is always kept local (a pure SYN is never forwarded), so the two generations each hold their own half-open entry with their own ISN. Three sources identified; the dominant one (the client retransmitting after a lost or abandoned SYN-ACK) is generation-agnostic. Measured over ≈1.26 M connections: the "double SYN-ACK" case did not occur; forcing retransmission reproduces the stranded entries. |
| Undo on failure | `ff_flow_map_revoke()` added, with a backward-shift delete, and asserted on a real stack (rt26). |
| Long-connection criterion | `keepalive_requests` set explicitly so the criterion measures the drain's one closure per connection. |
| Supervisor control channel | A refused controlled signal is moot once the target is gone, retried once while it is alive, and only a target alive past a short grace fails the run; `exited()` polls instead of using `select()` (which failed with EINVAL once a pidfd number passed `FD_SETSIZE`); failures carry the cause. |
| Reproducibility | The reload is anchored on the probe's progress; the anchor and the remaining probe time are recorded. |
| syncookies-only | Registered as a note (not measured) with the parts the code does prove. |
