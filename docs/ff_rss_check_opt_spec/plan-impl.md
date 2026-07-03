# ff_rss_check Three Optimizations — Coding Implementation Phase Execution Plan (plan-impl.md)

> Phase: spec finalized (commit e5389cb52, gate CONDITIONAL PASS) → this phase is **formal coding implementation + testing**.
> Method: harness + spec-driven + agent team (leader + sub-agents).
> Baseline commit: `e5389cb52` (feature/1.26).
> Spec basis: `docs/ff_rss_check_opt_spec/zh_cn/` 00-09 (landing points in 06/05, facts in 02, gate assertions in 09).
> Mandatory rules: no speculation during actual execution, code takes precedence, cross-verification; rm/kill/chmod go through `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh` (make install-type operations are fine); lib comments kept minimal; commit messages in English, 1-3 sentences; config.ini local test values not committed (review git diff before committing); on gate failure, bounce back to the previous step (per-step bounce≤3, otherwise stop and escalate to manual decision — no leftover unresolved items unless truly infeasible); leader must not exit before all sub-agents have finished, and must actively poll and wait.
> Test environment: DPDK NIC `9.134.214.176` (tested via ssh f-stack-client); kernel stack `127.0.0.1`. Currently helloworld is not running, symmetric_rss=0, kernel_coexist=0.

## 0. Implementation milestones (strictly following spec 06's R-A→R-B→R-C order, with dependencies)

| Milestone | Requirement | Content | Dependency |
|--------|------|------|------|
| **R-A** | 0.1 | Kernel-side RSS port-selection migration (IPv4): in_pcb.c in_pcb_lport_dest + in_pcbconnect + in_pcb.h | spec |
| **R-B** | 0.3 | rte_thash dynamic path optimization (IPv4): ff_dpdk_if.c new thash ctx/adjust_sport + hooked into in_pcb_lport_dest's miss branch | R-A |
| **R-C** | 0.2 | IPv6 full path: ff_dpdk_if.c v6 tables/functions + in_pcb/in6_pcb integration + ff_config v6 parsing | R-A/R-B |

Sub-phases within each milestone (each must pass its gate before proceeding to the next milestone):
1. **Startup verification** (before coding, grep/read code to verify this milestone's to-be-confirmed items F#, write conclusions back to the spec, no speculation)
2. **Coding** (minimal diff, fully gated by `#ifdef FSTACK`, minimal comments)
3. **Compilation** (compile with FSTACK on and off, 0 errors; zero regression with the macro off)
4. **Unit testing** (cmocka, including correctness + regression)
5. **Review** (leader independently reads the code for review, does not rely solely on a sub-agent's own conclusion)
6. **Real-machine/integration testing** (leader coordinates: 9.134.214.176 + 127.0.0.1)
7. **Milestone gate** (spec 06's R-?.4 gate items all PASS one by one) → PASS before committing + proceeding to the next milestone

## 1. To-be-confirmed items per milestone (verify at startup, corresponding to spec 09's table F)

- **R-A startup verification**: F1 (precise insertion point of ff_in_pcbladdr in in_pcbconnect), F2 (whether protosw affects lookupflags pass-through), F3 (get_portrange return semantics = hit 0/miss -ENOENT, already confirmed L2843-2848), F4 (port rotation dport[0] self-increment mechanism), F11 (unit-test rss_reta_size injection), F15 (connect client carrier).
- **R-B startup verification**: F9 (asymmetric key attempts initial value 16 tuning), F10 (helper v4 offset=64bit/len 16), F13 (backfill line numbers of new functions), F14 (desired_value observability), F16 (perf instrumentation macro), F17/F18 (real-machine magnitude/reta_size·nb_queues).
- **R-C startup verification**: F5 (whether v6 connect goes through the unified in_pcb_lport_dest or an independent in6_pcb path), F6 (NIC v6 RSS offload), F7 (whether rte_flow IPV4_TCP is in scope, leans toward no), F8 (v6 table capacity macro/memory), F12 (rss_tbl_cfg_handler not static), F10 (v6 offset=256bit), F13 (v6 function line numbers).

## 2. Key implementation constraints (spec 04/05, zero-tolerance items)

- **0.3 zero tolerance for wrong-queue landing**: the sport back-derived by `ff_rss_adjust_sport` must be re-verified via soft-compute `ff_rss_check()==1` before being returned; if re-verification fails/attempts are exhausted/ctx init fails → fall back to port-by-port soft scan (functionality does not degrade). desired_value ∈ {v|v%nb_queues==queueid, v<reta_size} rotation.
- **Zero IPv4 regression**: 0.2 uses a v6-independent table/functions (Plan A), not changing any v4 interface signature/struct layout; 0.1/0.3 are fully `#ifdef FSTACK` gated, with FSTACK off / rss enable=0 / single queue (nb_queues<=1) → falls back to native behavior.
- **15.0 adaptation**: in_pcb_lport_dest's signature is const inpcb (the migration logic must not modify what inp points to); lookup uses 15.0's signature (in_pcblookup_local with RT_ALL_FIBS, in_pcblookup_hash_locked with M_NODOM,RT_ALL_FIBS); INPLOOKUP_LPORT_RSS_CHECK stays outside the enum at 0x80000000, is cleared at the entry point, and is not included in MASK.
- **LOOPBACK**: in_pcb_lport_dest breaks out directly for loopback without doing RSS, keeping 127.0.0.1 working normally.

## 3. Agent team division of labor

- **leader** (this conversation): overall coordination, startup-verification gatekeeping, independent review + real-machine test coordination + gate review + commit for each milestone, polling and waiting, final summary; does not exit before all sub-agents have finished.
- **impl**: coding for each milestone (in_pcb.c/in6_pcb.c/in_pcb.h, ff_dpdk_if.c, ff_config.{c,h}), self-checks for zero regression in both compile modes.
- **tester**: writes cmocka unit tests + runs in both modes (per spec 07's TC-U-RSS-* test cases).
- **reviewer** (optional, or the leader may take this role): code review gate.
> Real-machine/integration testing (9.134.214.176 / 127.0.0.1, starting/stopping helloworld) is personally coordinated by the leader (kill goes through the script).

## 4. Commit strategy

- Commit once after each milestone's gate passes, commit message in English, brief, 1-3 sentences.
- Commit set = lib + freebsd + tests (per milestone); **excludes config.ini local test values** (review git diff before committing; only feature-related notes in the rss_check section may be committed).
- After all milestones are complete, do a final item-by-item review against spec 09's gate assertions.

## 5. Risks and rollback

- R-A: incorrect modification of const inpcb / flag contamination → fully `#ifdef FSTACK`, any compile/unit-test failure triggers an immediate bounce.
- R-B: wrong-queue selection → guarded by soft-compute re-verification (zero tolerance); if it doesn't converge → fall back to soft-compute.
- R-C: IPv4 regression → Plan A doesn't touch v4; the v6 kernel integration point is based on the actual call chain (F5 startup verification).
- If any milestone's same step bounces ≤3 times and still doesn't pass → stop and escalate to manual decision; do not force it through, do not leave behind unresolved defects.
