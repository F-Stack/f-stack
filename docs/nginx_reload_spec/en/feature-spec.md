# F-Stack nginx Lossless Reload — Feature Specification (English)

> **Status of this document.** This is the English feature edition generated after functional acceptance.
> It mirrors the Chinese specification under `docs/nginx_reload_spec/zh_cn/` (00–09). **The Chinese text is
> authoritative**: where the two differ, the Chinese original governs, and any correction is applied there first
> and then reflected here. Chinese source versions at generation time: 00 v1.9.9, 06 v1.9.10, 07 v1.22, 08 v1.20.
> Generated 2026-09-22. IP addresses below are descriptive placeholders (see §7).

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

## 3. Key contracts (selected, with current status)

| Contract | Current state |
| --- | --- |
| Per-generation application pool cache (`ff_shared_pool_cache_size`, `lib/ff_dpdk_if.c:669-673`) | **Fixed by R-01**: `graceful_reload=1 ⇒ cache_size=0`, so cross-generation frees never touch `local_cache`. Mechanism + build/unit level only; the targeted runtime assertions (PT-NR-09 / RV1) are **still not executed** and remain registered. Not a claim that all cross-generation races are zero. |
| Generation directory in hugepage (`lib/ff_reload_gendir.c`) | Registration failure is **fail-closed** (no fallback to epoch 0, no slot hopping); cross-master epoch isolation. |
| Takeover proof | A takeover (USR2 release, heartbeat reclaim, generation-directory reclaim) requires proof that the hardware users of the displaced coordinate have stopped or exited; heartbeat-stall takeover is counted as forced. *Verified at unit / red-green / true-EAL integration level; the runtime matrix for these paths is not executed and remains registered.* |
| Slot recycling | Requires master death **and** a stale slot stamp; orphan workers still refreshing the stamp keep the epoch live. A temporarily unrecyclable slot is retried within a bounded budget **on the same slot** instead of hopping to another slot (R-16); budget exhaustion fails the attach and counts `reclaim_refused`. *Same verification status as the row above.* |
| USR2 state machine | The generic FSM header (`ngx_ff_reload_fsm.h:29-36`) defines `T0_IDLE…T5_GOLD_QUIT/T_ERROR` only; the USR2-specific states (`PENDING`/`HANDED`) live in `ngx_process_cycle.c` (`ngx_ff_usr2_state`, plus `ngx_ff_usr2_begin/handover/reclaim/check`). WINCH registration is **not** proof that all workers are READY. |
| Hardclock acceptance | Bound to the **PT-NR-08 functional criterion (single-shot deviation ≤ 1 tick)**; the earlier "≤5% versus baseline" figure is retired because the `rte_timer` (hooked-tick) baseline is unmeasurable. Short timers take the stricter of absolute and relative bounds. |

## 4. Verification performed (this round)

Runtime harness: `tests/integration/test_graceful_reload.sh` (cases: precheck, baseline, rt01, rt02, rv9, gr0, rt12, rt13).

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

Harness safety changes in this round: a probe that reports a summary but fails its own criterion is now recorded as
**FAIL**, never as `NO_DATA`/`SKIP`; the active-stream probe runs for a bounded duration so that "still running after
the reload" is observable; oversized payloads are rejected instead of decaying into `NO_DATA`.

## 5. Known gaps (registered, not closed)

- Extended fault/boundary matrix has **no harness cases yet** (source: `docs/nginx_reload_spec/plan.md` §4 runtime
  matrix; listed here as plan-level gaps, not as verified findings): re-entry, READY late/absent, handover failure, primary
  death, worker stall, USR2→WINCH with two distinguishable binaries, SYN-before-cutover / ACK-after, half-open
  follow-up data, listen timing, keepalive/timeout, same-`lcore_id` alloc/free, ARP/NDP, full ring/table, unregister
  reuse, slot holes vs. live master, KNI-off control, PT-NR performance comparison, pool audit.
- Cross-process MP integration is not wired into the runtime matrix.
- `D-NEW-3`: the exceptional TX-guard drop (integration test `it_a09_send_burst_guard`) is real but its magnitude under
  real load is unmeasured; it does not invalidate A-NR-24's steady-state verdict.
- Pending slot-ring retry channel, pid-reuse guard on hardware-user entries, and unbounded USR2/WINCH retry are
  reviewer suggestions that remain unimplemented (non-blocking).

## 6. Audit closure

29 cross-audit findings (A01-*, B01-*, B02-1, C01-*, M02-*, M03-*) are all closed: 12 in code or harness, 17 by
documentation alignment. Per-finding state, fix batch and evidence are recorded in
`work/recheck-20260918/findings.json`.

## 7. Reporting convention

Documents and plans use **descriptive IP placeholders**. Real runtime configuration, captures and the archived logs
under `work/` may contain real addresses, but that directory is git-ignored (`.gitignore:52`) and is **never
committed**. Local `config.ini` is not part of any commit.
