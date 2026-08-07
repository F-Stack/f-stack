# ff_rss_check Three-Item Optimization Spec — Overview Index (00)

> This directory contains the **spec documentation phase** deliverables for the three optimizations to F-Stack's `lib/ff_dpdk_if.c::ff_rss_check`. This phase only produces documents, no code is written, and (as originally noted) no English version was planned initially (pending human audit). This file is the English translation of the Chinese spec set.
> Baseline commit: `2422d12eb` (feature/1.26). Gate conclusion: **CONDITIONAL PASS** (19 assertions all PASS, 0 FAIL, 18 coding-phase confirmation items do not block finalization).

## Three Optimization Requirements
| No. | Requirement | Positioning |
|------|------|------|
| 0.1 | Kernel-side port selection hookup for `ff_rss_tbl_get_portrange` was not ported during the 13.0→15.0 upgrade; needs to be back-ported and tested on 15.0 | Back-port upstream capability |
| 0.2 | `ff_rss_check` / `ff_rss_tbl_get_portrange` support IPv6 hash (currently IPv4 only) | Brand-new addition (upstream also lacks IPv6) |
| 0.3 | While keeping the static `ff_rss_tbl`, use `rte_thash_adjust_tuple()` to optimize the dynamic-computation scenario, and interoperate with the FreeBSD source-port-selection flow | Beyond upstream (upstream does not use adjust_tuple) |
| 0.4 | Secondary software recheck after reverse-derivation in `ff_rss_check` / `ff_rss_check6` is disabled by default, enabled only as a debug option (runtime switch) | Incremental optimization (runtime switch) |
| 0.5 | `IP_BIND_ADDRESS_NO_PORT` bind-then-connect RSS port selection port (aligning with Linux semantics + RSS queue affinity): let `bind(local_addr, port=0)` defer port allocation until connect, so that `ff_rss_check`'s RSS-aware port selection takes effect at connect time | Back-port upstream capability (upstream commit `cb9b4d462`, IPv4; v6 is a brand-new addition synchronized for 15.0) |

## Document Map
| File | Milestone | Content |
|------|--------|------|
| `plan.md` | M0 | Overall plan, evidence-based current state, direction of the three solutions, milestone gates, agent-team division of labor |
| `01-requirements-spec.md` | M1 | Background/goals/in-out scope/acceptance criteria for the three requirements |
| `02-current-state-and-gap-analysis.md` | M1 | User-space RSS current state, 13.0↔15.0 in_pcb differences, IPv6 gap, rte_thash current state, config/test current state |
| `03-external-research.md` | M2 | F-Stack official wiki (static-table optimization), DPDK Toeplitz Hash documentation, and mapping of the three repository `rte_thash.h` sources to this project |
| `04-architecture-and-design.md` | M2 | The three design solutions, data-flow diagrams, **0.3 `desired_value∈{v%Q==q,v<R}` → queue-mapping derivation**, IPv6 solution A, decision table |
| `05-interface-design.md` | M3 | lib API changes (v4 signature unchanged + new v6/thash functions), kernel hook contract, config v6 parsing, IPv4 zero-regression matrix |
| `06-milestones-and-worklist.md` | M3 | Coding milestones R-A (0.1 back-port) → R-B (0.3 thash) → R-C (0.2 IPv6), with per-item file/function change table, test points, risk rollback, bounce gate |
| `07-test-specification.md` | M4 | 14 unit + 5 integration + 4 real-machine + 9 zero-regression criteria + acceptance matrix; mock strategy |
| `08-performance-baseline-plan.md` | M4 | Comparison methodology across static-table/software-computation/thash paths, TSC instrumentation, QPS, real-machine (<DPDK_NIC_IP>) procedure, pass criteria |
| `09-spec-review-gate.md` | M5 | 19 assertions checked one by one PASS/FAIL (verified against code) + a master table of 18 pending-confirmation items + CONDITIONAL PASS conclusion |
| `10-implementation-and-verification-report.md` | Coding | Commit/function:line for all three landed items, design highlights, 31 unit-test cases + real-machine 200×2 results, real-machine limitations, F1-F18 fulfillment mapping, coding-gate PASS |

## Requirement ↔ Milestone ↔ Key Test-Case Navigation
| Requirement | Coding Milestone | Core Test Cases |
|------|-----------|----------|
| 0.1 back-port | R-A | TC-U-RSS-01-01~06, IT-RSS-01/02, RT-RSS-01/02 |
| 0.3 thash | R-B | TC-U-RSS-03-01~05, IT-RSS-03/05, RT-RSS-03 |
| 0.2 IPv6 | R-C | TC-U-RSS-02-01~05, IT-RSS-04, RT-RSS-04 |
| 0.4 recheck switch | R-D | TC-U-RSS-04-01~06, IT-RSS-03/05, RT-RSS-03 |
| 0.5 bind no port | R-E | TC-U-RSS-05-01~05, IT-RSS-06, RT-RSS-05/06 |

## Key Design Decisions (quick reference)
1. **IPv6 uses an independent v6 table/functions (Solution A)**, not a union — to keep IPv4 zero-regression and avoid changing the v4 interface signatures.
2. **0.3 queue-placement alignment**: `desired_value∈{v|v%Q==q,v<R}` + mandatory software-recompute recheck via `ff_rss_check` as a backstop (zero tolerance for selecting the wrong queue) + fallback to software computation once attempts are exhausted + graceful degradation to pure software computation on ctx-init failure.
3. **`INPLOOKUP_LPORT_RSS_CHECK`** remains outside the `in_pcb.h` enum as `#define 0x80000000`, is cleared after being parsed at the entry point, and is not included in `INPLOOKUP_MASK` (following 13.0 behavior).
4. **The static-table fast path is unchanged**; only the dynamic scan for misses is optimized.

## Next Steps
Once the spec is finalized, the project moves to the coding phase (R-A→R-B→R-C); the 18 pending-confirmation items (see the F table in 09) must be verified before starting each milestone, with conclusions written back into the spec. The English version was originally to be revisited after human audit (this document is that English translation).
