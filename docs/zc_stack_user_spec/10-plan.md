# FSTACK_ZC_RECV Zero-Copy Receive Implementation-Level Spec — Plan

> Status: PLAN-READY → (execution) BUILDING → FINISHED
> Prerequisite: feasibility investigation passed (docs/zc_stack_user_spec/zh_cn/00-09, conclusion "feasible", commit 875532e35)
> Scope of this phase: produce the **implementation-level specification document** (spec) to guide subsequent coding; **still no implementation code is written in this phase**
> Document language: Chinese only (docs/zc_stack_user_spec/zh_cn/)
> Method: harness engineering + spec-driven + agent team (leader + architecture-probe / doc-writer / spec-review gatekeeper sub-agents)
> Iron rule: all spec entries are governed by **measured code**, external/docs only inspire; when inconsistent, code prevails; never give a conclusion without execution

---

## §1 Goals
Based on the feasibility conclusion (recommended Plan A: reuse the `mp0` output parameter of soreceive), produce a zero-copy receive specification that can directly guide implementation: architecture design, kernel patch detailed spec, userspace API contract, mbuf lifecycle state machine, boundary & fallback matrix, CMocka test spec, acceptance criteria and milestones.

## §2 Phase 0 spec-level measured supplement (completed)
> On top of the feasibility investigation (01-09), this phase adds the following measured evidence:

| Item | Measured | Purpose |
|---|---|---|
| Compile switch paradigm | `lib/Makefile:210-212  ifdef FF_ZC_SEND → CFLAGS+=-DFSTACK_ZC_SEND` | Symmetric definition `FF_ZC_RECV→-DFSTACK_ZC_RECV` |
| kern_recvit signature | `uipc_syscalls.c:895 kern_recvit(td,s,mp,fromseg,controlp)`; soreceive 4th arg=NULL (L948) | Kernel patch point |
| read() path | `sys_socket.c:122 soo_read → soreceive(so,0,uio,0,0,0)` (L133, mp0=0) | Kernel patch point (read also needs it) |
| Example call sequence | `example/main_zc.c`: ff_zc_mbuf_get→ff_zc_mbuf_write(can be multiple)→ff_zc_send (L185-220) | Symmetric design of recv example spec |
| Test status | **No** ff_zc_* tests under tests/ | Test spec is greenfield, needs new creation |

(Other measured evidence see 01-05; this plan does not repeat them.)

## §3 Spec Document List (docs/zc_stack_user_spec/zh_cn/, new 10-19 series)
| Document | Content | Responsible sub-agent |
|---|---|---|
| `10-spec-overview.md` | scope/terminology/goals/bridge to feasibility conclusion/compile switch FSTACK_ZC_RECV | leader |
| `11-architecture-design.md` | layered architecture (userspace API ↔ kernel mp passthrough ↔ soreceive mp0 ↔ ext-mbuf) + data flow diagram | spec-writer-arch |
| `12-kernel-patch-spec.md` | kernel change detailed spec: kern_recvit/kern_zc_recvit variant + soo_read passthrough + FSTACK_ZC_RECV macro; change points/before-after comparison/constraints that do not break existing recv | spec-writer-kernel |
| `13-userspace-api-spec.md` | API contract: ff_zc_recv / ff_zc_mbuf_read rewrite / ff_zc_recv_free; struct ff_zc_mbuf reuse semantics; error codes/parameters/return values | spec-writer-api |
| `14-mbuf-lifecycle-spec.md` | mbuf ownership state machine (sockbuf→APP→release) + refcnt contract + leak protection + sequence diagram | spec-writer-life |
| `15-boundary-and-fallback-spec.md` | boundary matrix detailed spec (whole/split/PEEK/WAITALL/DONTWAIT/OOB/SCM/TLS/UDP) + fallback strategy | spec-writer-arch |
| `16-test-spec.md` | CMocka test spec (reference c-unittest-expert methodology, API switched to CMocka): case naming/setup-teardown/assertion granularity/boundary coverage/mock strategy | spec-writer-test |
| `17-acceptance-and-milestones.md` | acceptance criteria (functional/performance/memory safety/compatibility) + M0-M5 milestones + DoD | leader |
| `19-spec-review.md` | spec review gate (4 dimensions + implementability + self-consistency + reference authenticity) | gatekeeper |

## §4 Agent Team Topology
| Role | Responsibility | Mode |
|---|---|---|
| **leader (main agent)** | orchestration/dispatch/aggregation/gate adjudication/landing 10/17/finishing commit | main agent |
| **probe-spec** (architecture probe · async code-explorer) | supplement spec-level measured evidence (kern_recvit callers, soo_read, msghdr flow, m_freem, mbuf flags), ensure spec entries are traceable | read-only |
| **spec-writer-kernel** | write 12 kernel patch detailed spec | serial |
| **spec-writer-api** | write 13 userspace API spec | serial |
| **spec-writer-life** | write 14 lifecycle state machine | serial |
| **spec-writer-arch** | write 11 architecture + 15 boundary matrix | serial |
| **spec-writer-test** | write 16 CMocka test spec (reference c-unittest-expert) | serial |
| **gatekeeper** | 19 review gate: reference authenticity/line number match/implementability/self-consistency/no speculation; any failure bounces back for rewrite | serial |

**Failure rollback SOP**: gatekeeper fails → bounce back to the corresponding spec-writer for rewrite; if a contradiction with code is found → code prevails and annotate.

## §5 Phase Schedule
- **P0** spec-level measured supplement (✅ see §2)
- **P1** document skeleton landing (10-19 series skeleton)
- **P2** architecture probe corroboration (probe-spec, ensure kernel/call references in 12/13/14 are traceable)
- **P3** serial writing of 11/12/13/14/15/16 (each spec-writer)
- **P4** land 10 overview + 17 acceptance/milestones
- **P5** gatekeeper review gate (19); on failure rollback to P3
- **P6** finishing commit (concise English message)

## §6 Acceptance Gate (acceptance gate for this spec)
| Gate | Content |
|---|---|
| G-SPEC-1 | All kernel/code references file:line:symbol verified by measurement, gatekeeper spot-check 100% hit |
| G-SPEC-2 | Kernel patch detailed spec gives change points of both read() and recv() paths + argumentation of constraints that do not break existing recv |
| G-SPEC-3 | API contract complete (signature/parameters/return/error codes/call sequence/misuse protection) |
| G-SPEC-4 | mbuf lifecycle state machine closed loop (state argumentation of no use-after-free / no leak / no double free) |
| G-SPEC-5 | Boundary matrix + fallback strategy cover all scenarios |
| G-SPEC-6 | CMocka test spec is implementable (naming/setup-teardown/assertions/boundary/mock) |
| G-SPEC-7 | Compile switch FSTACK_ZC_RECV consistent with existing FSTACK_ZC_SEND paradigm |
| G-SPEC-8 | Chinese only; no speculation (every entry traced to code or annotated "verified at implementation time") |

## §7 Scope and Constraints
**In-scope**: implementation-level specification documents (architecture/kernel/API/lifecycle/boundary/test/acceptance).
**Out-of-scope (not done this period)**: implementation code, kernel patch landing, actual test compilation/run, performance stress testing, English documentation.
**Workspace conventions**: rm→rm_tmp_file.sh; kill→kill_process.sh; chmod→chmod_modify.sh; make install and other non-direct chmod executions are allowed. commit message in English.
**Test methodology**: CMocka, reference c-unittest-expert (Unity-based ideas are general, API switched to CMocka: assert_int_equal etc.).

## §8 Risks
| Risk | Mitigation |
|---|---|
| spec entries detached from actual code | every kernel/API spec mandatorily traced by file:line; gatekeeper spot-check |
| read()/recv() two paths omitted | 12 mandatorily covers soo_read(sys_socket.c:133) + kern_recvit(uipc_syscalls.c:948) |
| lifecycle state machine not closed loop | 14 uses state machine + sequence diagram + 03 measured refcnt chain support |
| test spec not implementable | 16 aligns with existing tests/unit framework (cmocka + Makefile per-target paradigm) |
