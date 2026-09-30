# Test Plan — Units, Integration, Performance Baselines and Acceptance (English)

> **English mirror** of `docs/nginx_reload_spec/zh_cn/08-testing.md` (v1.23). The Chinese text is
> authoritative; where the two differ, the Chinese original governs. This is a structural and content sync
> (case list, criteria table, coverage boundaries), not a line-by-line translation of all ~500 lines.
> Revised 2026-09-30.

---

## 1. Unit tests

Unit level covers the library contract without DPDK: configuration validation, the reload state block, the
flow map (insert / lookup / admit / revoke / capacity), the generation directory, the drain ring and the IPC
paths. Cases are named **UT-NR-xx** and are run by `tests/unit`.

Notable unit coverage added recently:

- `test_a1_flow_map_single_phase` — a recorded SYN is visible to `ff_flow_map_lookup()` at once.
- `test_a1_flow_map_admission_rule` — no window admits; a window admits only when the four-tuple can be
  recorded; a refused four-tuple is not recorded.
- `test_a1_flow_map_revoke` — the undo removes only the record this admission created, keeps a duplicate
  four-tuple, and keeps every probe-chain entry behind the cleared slot reachable.

## 2. Integration tests

True-EAL integration (`tests/integration`) runs real DPDK processes:

- `test_ff_reload_integration` — reload-plane assertions, main-loop parking, dispatch and drain behaviour.
- `test_ff_dpdk_if_integration` — data-plane and reload-plane interaction on a real EAL.
- `test_ff_gendir_mp_integration` — multi-process generation directory: slot acquisition, dual-master
  isolation, slot recycling, the tools probe contract and the USR2 chain.

## 3. Runtime harness

`tests/integration/test_graceful_reload.sh` drives a real machine, a real client (`f-stack-client`) and the
supervised stack. Default cases: `precheck, baseline, rt01, rt02, rv9, gr0, rt12, rt13`; the **rt2x** fault
cases and **rt30 / rt31** are opt-in; **rt26** (SYN-ACK failure) needs a fault-injection build.

Selected cases:

| Case | What it proves |
| --- | --- |
| precheck | no leftover processes, no stale runtime files, hugepages free |
| baseline | long-run control without a reload |
| rt01 | unloaded HUP: FSM 6/6, drain bounded |
| rt02 | HUP under active streams: no stall, integrity of streamed payload |
| rv9 | 100 reload rounds: no error, no leak (rtemap flat, hugepages restored) |
| gr0 | `graceful_reload=0` control: nothing new is active |
| rt12 / rt13 | KNI management plane / zero-copy form (rt13 excluded by decision) |
| rt30 | high CPS: new connections under load, zero client errors |
| rt31 | long connections: one closure per connection, no failure on fresh connections |
| rt26 | (fault build) a SYN-ACK that cannot be sent is counted, its admission is undone, the reload completes |

### Harness behaviour worth knowing

- A probe that reports a summary but fails its own criterion is recorded **FAIL**, never `NO_DATA`/`SKIP`.
- The reload is **anchored on the probe's own progress** (elapsed time and produced requests), and the anchor
  and the remaining probe time are recorded in the measured text.
- The generated configuration sets `keepalive_requests` explicitly: nginx's default of 1000 closes a
  long-lived connection a second time on a long run, which the long-connection criterion would otherwise count
  as another failure.
- A refused controlled signal is moot once its target is gone, is retried once while the target is alive, and
  only a target still alive past a short grace fails the run.

## 4. Acceptance criteria (A-NR-01~28, condensed)

| ID | Content | Criterion |
| --- | --- | --- |
| A-NR-01 | `graceful_reload` default 0 | default 0; with `=0` none of the new checks is active |
| A-NR-02 | configuration validation chain | mutually exclusive / dependent / oversized combinations refused at configuration time |
| A-NR-03 | workers all secondary + resident primary | starts; no worker0 primary contention |
| A-NR-04 | two generations coexist stably | coexist ≥30 min + RT-10 green |
| A-NR-05 | explicit READY protocol | no reliance on 500 ms / 15 s empirical waits; provable by instrumentation |
| A-NR-06 | multiple generations listening | E-NR-01 + RT-01/02 |
| A-NR-07 | simultaneous takeover correctness | RT-01/02 evidence (reta atomic cut-over retired) |
| A-NR-08 | forwarding fallback | flow_map miss → `drain_ring_rx` to G_old; egress → `drain_ring_tx` |
| A-NR-09 | reload under traffic with zero errors | RT-02/RT-03 criteria |
| A-NR-10 | timer isolation | self-driven hardclock; `priv_timer[lcore_id]` conflict resolved |
| A-NR-11 / 12 | drain semantics / forced exit | existing connections close naturally, progress observable; RT-06 |
| A-NR-13 | failure rollback | RT-05/07/09 |
| A-NR-14 | reload duration bound | T0→T3 ≤ baseline × 1.5; T0→T5 ≤ forced-exit threshold |
| A-NR-15 | USR2 upgrade and rollback | RT-04/04b |
| A-NR-16 | reload loop final gate | ≥100 rounds with zero errors, no deadlock, no leak |
| A-NR-17 | steady state has zero **per-packet** cost | flow map and drain ring are windowed |
| A-NR-18 | KNI / zero-copy regression | RT-12 or an explicit limitation |
| A-NR-19 | clean build over the matrix | matrix exit 0; `make check` exit 0 |
| A-NR-20 | documents and runbook | deployment / downgrade / thresholds |
| A-NR-21 | self-driven hardclock accuracy | PT-NR-08 single-shot deviation ≤ 1 tick |
| A-NR-22 | same-core switching is lossless | RT-14 / PT-NR-07 |
| A-NR-23 | per-generation mempool correctness | C-NR-308/314/315 |
| A-NR-24 | TX exclusivity | zero `rte_eth_tx_burst` from G_old during drain |
| A-NR-25 | half-open window handshake succeeds | SYN before the takeover, ACK after → the connection completes |
| A-NR-26~28 | (see the Chinese document for the remaining rows) | — |

## 5. Coverage boundaries (honest statement)

- The extended fault/boundary matrix has no harness cases for several plan-level paths.
- Cross-process MP integration is not wired into the runtime matrix.
- The `graceful_reload=1` + `syncookies_only=1` combination is unmeasured (registered as a note 2026-09-30).
- The SYN-ACK failure fault fires once per process: it proves the branch and the undo, not sustained failures.

## 6. Changes since the previous English edition (2026-09-22)

- Unit coverage for the single-phase admission, the admission rule and the revoke added.
- rt26 added with its own criterion (counters, not borrowed from rt30).
- Long-connection criterion clarified (`keepalive_requests`), probe-progress anchoring recorded, harness
  control-channel fixes recorded.
