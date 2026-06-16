# 07 Test and Performance-Baseline Spec

> **Document ID**: SPEC-KE-07
> **Version**: v3 (paradigm-correction rework)
> **Date**: 2026-06-15
> **Status**: Drafting
> **Scope**: The unit/integration/performance-baseline test plan and gate standard for this feature (single API+marker-based selection / config default switch / client-side selection / dual mode).
> **Alignment**: F-Stack's existing test system `tests/unit` (**cmocka**, *.c + *.ini), `tests/integration`, coverage `tests/run_full_coverage.sh` (lcov, `tests/full_coverage_report/`).
> **Note**: an early draft of the spec wrote Unity, but the actual repo `tests/unit` uses **cmocka** (mapped via the `c-unittest-expert` methodology); the actual repo is authoritative, and this document is unified to cmocka.

---

## 1. Test Layering

| Level | Directory | Framework/method | Coverage target |
|---|---|---|---|
| Unit test | `tests/unit/` (new selection cases) | cmocka (aligned with existing `*.c`+`*.ini`) | marker selection / ownership determination / config parsing / event merging |
| Integration test | `tests/integration/` | end-to-end process + local tools | server-side local direct access, client connecting to local/external, dual-stack coexistence |
| Performance baseline | `tests/` (performance scripts) | stress test + comparison | regression comparison of default / enabled-selection |

---

## 2. Unit-Test Cases (cmocka)

| ID | Case | Assertion | Mapped requirement |
|---|---|---|---|
| UT-1 | `socket(SOCK_STREAM\|SOCK_KERNEL)` (hook) | Returns a kernel fd, `is_fstack_fd==false` | FR-1/FR-6 |
| UT-2 | `socket(SOCK_STREAM)` default | Goes to F-Stack, `is_fstack_fd==true` | FR-6 |
| UT-3 | `type` has both `SOCK_KERNEL\|SOCK_FSTACK` set | Goes to F-Stack per priority (`ff_hook_socket:387` condition not satisfied) | boundary/`05 §8` |
| UT-4 | config `default_stack=kernel` + no marker | Defaults to the kernel stack | FR-5 |
| UT-5 | config `default_stack=kernel` + with `SOCK_FSTACK` | App marker overrides, goes to F-Stack | FR-5/priority |
| UT-6 | `ini_parse_handler` parses `[stack] default_stack` | Correctly fills `ff_config.stack.default_to_kernel` | FR-5 |
| UT-7 | native `ff_socket(SOCK_KERNEL)` (after enhancement) | Goes to the kernel stack (before enhancement, records always-F-Stack, `02 §5`/D4) | FR-6 |
| UT-8 | client `connect` fd-ownership routing | kernel fd → `ff_linux_connect`; F-Stack fd → F-Stack | FR-3/FR-4 |
| UT-9 | `epoll_wait(maxevents=1)` | Returns `-EINVAL` (per `:2212-2218`) | boundary |
| UT-10 | epoll registering both a kernel fd and an F-Stack fd | Both event types are returned without loss | FR-7 |
| UT-11 | `close` a kernel-side fd | Both stacks' resources are linked-released, no leak (per `:1874-1883`) | FR-8 |
| UT-12 | compile switch off / default F-Stack | Behavior equivalent to pure F-Stack, zero-overhead | NFR-1/FR-9 |

> Cases land by following the existing `*.c`+`*.ini` (cmocka) organization in `tests/unit/`; the `[skill:c-unittest-expert]` (cmocka) spec may be referenced as needed.

---

## 3. Integration-Test Cases

| ID | Scenario | Steps | Pass criteria | Mapped requirement |
|---|---|---|---|---|
| IT-1 | Server-side local curl direct access | Start the example (`SOCK_KERNEL` kernel-stack listen) → local `curl 127.0.0.1:port` / `curl <host_ip>` | HTTP 200 | FR-1 |
| IT-2 | Local ping | `ping <host_ip>` | Has replies | FR-2 |
| IT-3 | **Client connects to a local service** | Start a server locally (kernel stack) → F-Stack app (`SOCK_KERNEL`) `connect 127.0.0.1`/host IP | Connection established, send/recv normal | FR-3 |
| IT-4 | **Client connects to an external kernel service** | F-Stack app (`SOCK_KERNEL`) `connect <external kernel-stack service>` | Connection established, send/recv normal | FR-4 |
| IT-5 | config default stack | Change config `default_stack=kernel` and restart → sockets without a marker go to the kernel | Default stack takes effect; marker can override | FR-5 |
| IT-6 | Multi-process differentiation | Two processes use different configs (fstack/kernel default) | Each default stack takes effect independently | NFR-6 |
| IT-7 | Dual-stack coexistence | Within the same process, F-Stack business listen + kernel-stack management listen | Business via DPDK NIC, management via kernel, without interference | FR-6/FR-7 |
| IT-8 | Long-run/leak | A large number of short connections repeatedly opened/closed (including the client) | fd count stable, no leak | FR-8 |

> Process cleanup uses `/data/workspace/kill_process.sh`, temporary files use `/data/workspace/rm_tmp_file.sh`, permission changes use `/data/workspace/chmod_modify.sh`.

---

## 4. Performance Baseline

| ID | Metric | Method | Gate |
|---|---|---|---|
| PERF-1 | F-Stack business-path regression | selection off/default F-Stack vs baseline | throughput/latency deviation ≤ noise threshold (NFR-2) |
| PERF-2 | enabled-selection business-path regression | idle kernel-side listen, stress-test the F-Stack business | no significant regression on the business fast path |
| PERF-3 | native `ff_socket` enhancement overhead | the impact of the marker recognition branch on the default path | zero/negligible overhead on the default path (NFR-1) |
| PERF-4 | event-merging latency | the latency impact of throttled kernel-event fetching (`:2324+`) | latency within an acceptable range |
| PERF-5 | kernel-side management-plane/client throughput | local curl concurrency / client connect stress test | meets management-plane expectations (not the fast path) |

---

## 5. Coverage and Gate Standard

- Reuse `tests/run_full_coverage.sh` (lcov) to measure the coverage of this feature's changes (the new section in `ff_config.{c,h}`, the `ff_socket` marker branch, the `ff_hook_*` selection path).
- **Gate standard**:
  1. All UTs pass; the line coverage of new code reaches the existing project standard.
  2. IT-1~IT-8 all pass (server-side local direct access + client connecting to local/external + config default + multi-process measured successfully).
  3. PERF-1/PERF-2/PERF-3 show no regression on the business fast path and the default path.
  4. When off/default F-Stack, behavior/performance is consistent with pure F-Stack (NFR-1/2).
- Any item failing → bounce back to the previous milestone for repair per the plan's bounce convention (≤3 times for the same step, escalate to manual when exceeded).

---

## 6. Cross-Validation Requirements
- All tests must **actually be executed for evidence** (logs/packet captures/coverage reports); speculation is forbidden.
- The code line numbers referenced in test assertions must match the actual code; on conflict, code is authoritative.
- Client cases must measure that `connect` reaches via the kernel stack (confirm by packet capture that it goes through the kernel rather than the DPDK NIC).
