# Test Plan — Units, Integration, Performance Baselines and Acceptance (English)

> **English mirror** of `docs/nginx_reload_spec/zh_cn/08-testing.md` (v1.32). The Chinese text is
> authoritative; where the two differ, the Chinese original governs. This is a structural and content sync
> (case list, criteria table, coverage boundaries), not a line-by-line translation of all ~500 lines.
> Revised 2026-10-08; rt27 and build K added on 2026-10-10; rt28 and rt29 on 2026-10-12, rt32, rt33, rt34 and rt35 on 2026-10-13.

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
supervised stack. Default cases (no `-c`): `precheck, rt01, rv9`; `-c all`: `precheck, baseline, rt01, rt02, rv9, gr0, rt12, rt27, rt13`
(rt13 permanently excluded); the **rt2x** fault
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

## 7. Changes in the 2026-10-08 to 2026-10-13 editions (mirror of zh_cn 08 §2.3.0 / §2.3.2 / §2.3.3)

**Harness interface (2026-10-10 edition; since 2026-10-13 there are 25 cases with rt28, rt29, rt32, rt33, rt34 and rt35, and `ALL_CASES` has 14 entries, see the RX-37 to RX-40 paragraphs below).** `tests/integration/test_graceful_reload.sh` had 19 cases (`reload_checks.py:
CASES`): precheck, baseline, rt01, rt02, rv9, gr0, rt12, rt27 (2026-10-10, resident primary
vs a changed f-stack config; needs /dev/vhost-net), rt13, rt20, rt20b, rt21, rt22, rt23, rt24, rt25, rt26,
rt30, rt31. `-c all` (ALL_CASES) is precheck, baseline, rt01, rt02, rv9, gr0, rt12, rt27 and rt13, the last one permanently
excluded. Seven fault names:
ready_never, ready_delay, park_never, flip_fail, mutex_timeout (manual use only, no case), flip_fail_once,
synack_fail. Extra options: `--perf-threads/--perf-conns/--perf-duration/--hup-anchor-sec/--hup-anchor-count`,
`--capture`, `--client-if`. The aggregator also returns exit code 6 (no FAIL but SKIP/LIMITED). RT-04 maps to
rt25; gr0 covers only the `graceful_reload=0` HUP, not the `=0` USR2.

**Acceptance criteria (current).** Because the drain closes idle keep-alive connections, "lossless" now means:
zero failed new requests (`fresh_fail=0`) plus a bounded number of closures of existing long connections
(`fail ≤ conns`, `reconnects ≤ conns`; `2 × conns` for the USR2 case that drains twice). This is a total bound,
not a per-connection one. The bound applies only to the long-connection cases that go through a drain (perf mode: rt20b, rt24,
rt26, rt31; usr2 mode: rt25); baseline, rv9 and rt12 keep the default criterion `fail=0`, `reconnects=0`. Streams: all of `ok`, `md5_ok`, `eof_clean` equal `streams`, no stall over 3 s.
`hup_once()`: exactly one completion, exactly 6 FSM transitions, no illegal event, worker count restored. rv9:
fails on rtemap slope > 0.05, rtemap range > 32, hugepage drop > 64, rtemap ≠ 0 after stop, or > 32 hugepages
unreclaimed. gr0: longest outage within 0.3–2.5 s and no reload log line (no probe data with no reload log line is SKIP,
aggregate exit code 6). rt02: drain ≥ 100 ms. rt24: round 2
drain ≤ 15000 ms. The gendir MP integration test must run through `make -C tests/integration test`, and no
built source file may change while the harness runs (the build-identity gate then refuses to start a stack).

**2026-10-08 runtime results** (every build clean, lib warnings equal to the baseline, production builds with
no fault hooks; full table in the Chinese 08 §2.3.3). Production IPv4 on the code-final build D: precheck,
baseline, rt01, rt02, gr0, rt23, rt25, rt30, rt31 all PASS; IPv6: precheck, rt01, rv9 100 rounds PASS
(`ok=100/100`, `fresh_fail=0`, flat rtemap). Fault-injection build F: rt20, rt20b, rt21, rt22, rt24, rt26 all
PASS. The restored production build E repeated precheck, rt01, rt23 and rt12 (with the KNI management plane) and
IPv4 rv9 100 rounds (`ok=100/100`, flat rtemap): all PASS. Build G2 (comment-only follow-up to late reviews;
the nginx binary hash is unchanged) repeated precheck, rt01, rt02 and rt23: all PASS. Build RX3 (the RX-15/29/30 fixes) passed
IPv4 precheck, rt01, rt02, rt23, rt25, rt30, rt31 and rv9 30 rounds, and IPv6 precheck, rt01, rt02, rv9 20 rounds all PASS; new unit tests
`test_rx15_ring_user_census_and_purge_lock`, `test_rx15_primary_purges_orphaned_rings` and the binary
`test_ff_config_pa`. A batch on an intermediate
build was voided because a source comment was edited during the run and the build-identity gate refused to
start the remaining stacks.

**2026-10-10 build K (RX-35).** rt27 (all ten steps) and rt12 with the management plane pass (rt12 was LIMITED in the first batch, which had
no `--kernel-nic-ip`, and passed when rerun with the management plane). The IPv4 batch (precheck, baseline, rt01, rt02, gr0, rt23, rt25, rt30, rt31) passes 9/9, IPv4 and IPv6 rv9 pass 100/100 each (flat rtemap, hugepages back to 2048), IPv6 precheck, rt01, rt02 and rt27 pass, and rt27 rerun with per-step evidence lines still passes on both families (no KILL request; no exited master left a snapshot behind: at step 10 no master runs any more, and on the user
instance the snapshot count drops to 0 when the master stops and is 1 at every sample taken while it runs). Test-evidence audit: TA FAIL (four evidence-chain items) → TA2 PASS.
The supervisor gained `launch` (running phase and no supervisor failure only, always the current stack, sha256
re-checked, `NGINX` stripped, the start launcher untouched) so a case can
start another master inside its stack.

**2026-10-12 tools build t5 (RX-36).** On the user's instance (file_prefix set, KNI on) 23/23 checks pass: every
tool once, four samplers through three HUPs and a USR2/WINCH/QUIT upgrade (no error, no wrapped value, client
8889/0 failures), every tool again after the upgrade and after SIGINTs. A `graceful_reload=0` stack on the default
prefix, with the record of an exited primary left behind, passes 6/6; `test_ff_ipc` 16/16.

**2026-10-13 builds A3 and A4 (RX-39).** New case rt32 (reverse proxy across a reload; IPv4 and `--workers 1`, SKIP
otherwise): the upstream `common/reload_upstream.py` runs on the client as a bounded `reload_remote.py` job (`/ok`
returns the connection's peer port, `/slow?sec=N`, `/big` 64 MiB) and nginx has no upstream keep-alive, so each
request connects upstream. It requires 5/5 before the reload on one port parity, a 30 s stream and a 64 MiB download
through the old generation, 20/20 inside the window on the opposite parity with the window still open and no
`upstream timed out`, the stream `200 2457600` and a matching md5, and 5/5 afterwards. 22 cases, `ALL_CASES` 12;
`gen_nginx_conf` gained the `NGX_EXTRA_HTTP`/`NGX_EXTRA_LOC` hooks. Before the fix (the RX-38 M2 build, sha256
989709ed..., repro.sh) the 5 recorded window requests got 504; A3 20/20 over one reused upstream connection. A3: rt32
only logged that its upstream job did not start, inferred (not archived) to be the client port taken by the
reproduction's upstream (moved to 18932, the job log is now printed on failure; that run also had two workers); A4
with two workers: rt32 failed before the reload already, inferred to be the missing RSS on this host (stated by the
user, not probed), so it now needs one worker; A4: precheck, rt01, rt02, rt25, rt27, rt28, rt29 7/7 PASS with two
workers, precheck, rt01, rt32 3/3 PASS with one worker; IPv6 precheck, rt01, rt02, rt27, rt29 5/5 PASS (inbound IPv6;
rt32 SKIP by design); USR2 through the proxy passes (20/20 on the new master's parity, the new master refuses a HUP
while the old one runs, after QUIT a HUP held open by a 25 s stream gets 10/10 inside its window on the other
parity).

**2026-10-12 builds M1 and M2 (RX-38).** New case rt29 (stop of a 1500 stack; `[port0] mtu=9000` alone must be
refused within 20 s by an EMERG `slim primary exited during initialization` carrying `requires mtu_enable=1`, with
the master gone, nginx.pid removed, no primary and no 60 s timeout; then `mtu_enable=1` + `max_mtu=9000` must serve
with `f-stack-0` mtu 9000 and reload once), 21 cases, `ALL_CASES` 11. `expect_refused` takes the refused master's pid
from its EMERG line (`emerg_pid`) and then requires the pid file to be gone. M1: IPv4 precheck, rt29, rt27, rt28 4/4
PASS. M2: IPv4 precheck, rt01, rt02, rt25, rt27, rt28, rt29 7/7 PASS (rt02 streams=36 md5_ok=36 stalls=0; rt25
fail=24, at most 2 x conns, fresh_fail=0; rt29 refused in 1 s), rt12 with the management plane PASS; IPv6 precheck,
rt01, rt27, rt28 and rt29 5/5 PASS. On the user's instance, after adding `mtu_enable=1` and `max_mtu=9000`, both
workers show mtu 9000, HTTP returns 200 and a HUP hands over to new workers.

**2026-10-12 builds S5 to S8 (RX-37).** New case rt28 (stop, quit, SIGKILL with an immediate start, SIGKILL with a wait, USR2+WINCH+QUIT then stop) passes on IPv4 and IPv6, and rt27 now creates its left-behind primary by SIGKILLing the master and its workers. On S5 the IPv4 batch (precheck, rt01, rt02, rt23, rt25, rt30, rt31), rt12 with the management plane, IPv4 rv9 30 rounds and IPv6 precheck, rt01, rt02, rt27 and rv9 20 rounds pass; IPv6 rt28 step 4 failed (master and workers died within the primary's first second) and was fixed in S7, where IPv4 precheck, rt01, rt02, rt25, rt27, rt28, rt12, rv9 10 rounds and IPv6 precheck, rt01, rt27, rt28 pass. S8 (pid in the self-exit line) reruns IPv4 precheck, rt01, rt27, rt28 and IPv6 precheck, rt28: all pass. On the user's default instance stop, quit and a SIGKILL by name leave nothing behind (the primary exits on its own 10 s after the SIGKILL) and every restart serves. The supervisor gained the fixed tuning allowlist `TUNING_ENV_KEYS` (only `NGX_FF_SLIM_PRIMARY_ORPHAN_MS`).

**2026-10-13 builds u0 and u7 (RX-40, RX-41).** New cases rt33 (UDP server across HUPs), rt34 (UDP reverse proxy
across a HUP; IPv4 and `--workers 1`, SKIP otherwise) and rt35 (UDP server across USR2 + WINCH, called explicitly
like rt25), with the probe `common/reload_udp.py` (a whitelisted remote job: a UDP echo upstream that answers with
the peer port it sees, and stop-and-wait flows of one connected socket each, a datagram every 0.2 s, 1 s timeout
counted as a loss, late replies counted apart as stray), the `NGX_EXTRA_MAIN` hook of `gen_nginx_conf` and the
`FSTACK_EXTRA_DPDK` hook of `gen_fstack_ini`. Before the fix (u0, clean build of HEAD 646902e65): rt33 FAIL (6 of 8
new flows answered by the old generation, both HUPs ran into the deadline at about 91 s, the long flow never handed
over), rt34 FAIL (a SIGSEGV per proxied datagram, 8 in about 3 s), rt35 FAIL (24/24 new datagrams unanswered after
the handover, 63/259 old ones lost). On u7: IPv4 with two workers precheck, rt01, rt02, rt25, rt27, rt28, rt29 and
rt33 8/8 PASS, and precheck plus rt33 2/2 PASS again with the reviewed probe (reloads of 15 s and 26 s); IPv4 with
one worker precheck, rt32, rt34 and rt35 4/4 PASS (rt34 upstream port parity 0 then 1, 493/493 and 120/120 datagrams;
rt35 linger over after 18200 ms with 0 flows still active); IPv6 with two workers precheck, rt01, rt27 and rt33 4/4
PASS; precheck and rt12 2/2 PASS.
