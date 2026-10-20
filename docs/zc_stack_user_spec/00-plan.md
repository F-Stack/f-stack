# FSTACK_ZC_RECV (Zero-Copy read) Feasibility Study — Plan

> Status: PLAN-READY → (pending execution) BUILDING → FINISHED
> Scope: **feasibility study + design + documentation only**; no implementation code this round
> Baseline reference: the already-landed FSTACK_ZC_SEND (M8)
> Documentation language: **Chinese only** (docs/zc_stack_user_spec/zh_cn/); the English version will be considered after manual audit
> Method: harness engineering + spec-driven + agent team (leader + sub-agents)
> Anti-drift iron rule: all conclusions are **grounded in actually-measured code**; docs/external web are inspiration only; where inconsistent, code prevails; never give a conclusion without execution

---

## §1 Background and Goals

f-stack already supports zero-copy **write** (FSTACK_ZC_SEND / M8): the APP uses `ff_zc_mbuf_get`+`ff_zc_mbuf_write` to directly fill the BSD mbuf chain, then uses `ff_zc_send` with the `FSTACK_ZC_MAGIC` sentinel to let the kernel `m_uiotombuf` skip the copy and directly attach the mbuf.

Goal of this study: assess the feasibility of symmetrically supporting zero-copy **read** (tentatively named FSTACK_ZC_RECV) — letting the APP directly obtain the BSD mbuf chain in the socket receive buffer (whose data already zero-copy points to the DPDK mbuf), eliminating the sole mbuf→user-buffer copy in `soreceive → uiomove`.

**Deliverables**: feasibility conclusion (feasible/partially feasible/infeasible + rationale), kernel- and user-space design, API design, lifecycle/ownership scheme, risk and effort assessment, and follow-up implementation milestone recommendations.

---

## §2 Phase 0 Hands-On Reconnaissance Conclusions (completed, code prevails)

> All of the following are grep/read measurements of this phase, not speculation. Line numbers are per the current working tree.

### 2.1 ZC-SEND Baseline Reference (already-landed M8)
| Item | Location | Description |
|---|---|---|
| Data structure | `ff_api.h:347` | `struct ff_zc_mbuf{ void *bsd_mbuf; void *bsd_mbuf_off; int off; int len; }` |
| Allocate mbuf | `ff_veth.c:306` | `ff_zc_mbuf_get(m,len)` |
| Write mbuf | `ff_veth.c:326` | `ff_zc_mbuf_write(zm,data,len)` (bcopy into M_TRAILINGSPACE) |
| Send entry | `ff_syscall_wrapper.c:1199` | `ff_zc_send(fd,mb,nbytes)` sets `uio_offset=FSTACK_ZC_MAGIC`→`kern_writev` |
| Kernel hook | `freebsd/kern/uipc_mbuf.c:2028-2046` | `#ifdef FSTACK_ZC_SEND` detects magic→attaches mbuf, skips copy |
| Sentinel | `freebsd/sys/mbuf.h:1868` | `FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)` |
| Compile switch | `lib/Makefile:212` | `CFLAGS+= -DFSTACK_ZC_SEND` |
| Mis-trigger guard | `ff_syscall_wrapper.c:1151/1175` | ordinary `ff_write/ff_writev` explicitly `uio_offset=0` opt-out |
| Example | `example/main_zc.c` | — |

### 2.2 ZC-READ Current State (target hook point)
- `ff_veth.c:359  ff_zc_mbuf_read(...)` = **empty stub** (`// DOTO: Support read zero copy; return 0;`)
- `ff_api.h:400` declared, comment "not implemented now"
- **Missing**: `ff_zc_recv` entry, `FSTACK_ZC_RECV` macro, Makefile switch, release/consume API

### 2.3 RX-Side Zero-Copy Foundation (already exists = favorable)
- `ff_mbuf_gethdr` (ff_veth.c) uses `m_extadd(m,data,len,ff_mbuf_ext_free,pkt,...,EXT_DISPOSABLE)` to zero-copy attach DPDK mbuf data as an external mbuf; `ff_mbuf_ext_free` is responsible for returning the DPDK mbuf.
- Conclusion: **NIC→DPDK mbuf→BSD mbuf(ext) is already zero-copy; the sole copy point is soreceive→uiomove**.

### 2.4 READ Path and Symmetric Hook Point
- User entries: `ff_read`(1077)/`ff_readv`(1105)/`ff_recv`(1313)/`ff_recvfrom`(1319)/`ff_recvmsg`(1359) → `kern_readv`/`kern_recvit`
- Kernel copy point: inside `freebsd/kern/uipc_socket.c soreceive_generic_locked`(L2744), `uiomove(mtod(m,...),len,uio)`(L3031)
- **Key advantage**: `soreceive_generic(so,psa,uio,mp0,controlp,flagsp)` natively carries the `mp0` out-parameter — when `mp0!=NULL`, FreeBSD hands out the sockbuf mbuf directly without uiomove, a natural in-kernel mechanism candidate for ZC-read.

---

## §3 Key Design Questions to Investigate (answered in Phase 2-3, no speculation allowed)

1. **Kernel mechanism selection**: reuse `soreceive`'s `mp0` out-parameter (FreeBSD native, small change) vs. mimicking send's `FSTACK_ZC_MAGIC` sentinel hook (symmetric with send). Compare pros/cons, change surface, risk.
2. **mbuf ownership/lifecycle**: while the APP holds the ext-mbuf, when is the original DPDK mbuf returned? How do the `m_ext` refcount and `ff_mbuf_ext_free` cooperate to avoid use-after-free or premature recycling.
3. **API form**: the current `ff_zc_mbuf_read(struct ff_zc_mbuf*, const char *data, int len)`'s `const char*data` contradicts "read out" semantics and needs redesign; whether to add `ff_zc_recv(fd, struct ff_zc_mbuf*, len)`.
4. **Release semantics**: symmetric to send's get/write/send, the read side needs three stages receive→consume→release; how the APP explicitly returns the mbuf chain after reading.
5. **sockbuf accounting**: after soreceive takes the mbuf, `sbfree`/`sb_cc` accounting and window update.
6. **Boundaries**: MSG_PEEK / MSG_WAITALL / non-blocking / partial packet / spanning multiple mbufs / control messages (SCM_RIGHTS etc.) / OOB.
7. **Relationship and conflicts with LD_PRELOAD ring mode and FF_USE_PAGE_ARRAY**.
8. **Performance expectations and applicable scenarios** (large-packet receiving, proxy forwarding, splice, etc.) + non-applicable scenarios.

---

## §4 Agent Team Topology (leader + sub-agents, harness+spec)

> Execution uses a hybrid mode: parallel spawn of multiple code-explorer sub-agents during the probe phase, serial during the design/review phase.

| Role | Responsibility | Tool/Mode |
|---|---|---|
| **leader (main agent)** | Coordination, task dispatch, result aggregation, gate adjudication, doc landing, rollback decision | main agent |
| **probe-zcsend** | Map the full ZC-SEND chain (API→syscall→m_uiotombuf→sbappend) as the "baseline reference" | async code-explorer (read-only) |
| **probe-recvpath** | Map the full READ chain (ff_recv*→kern_recvit→soreceive_generic_locked→uiomove/mp0 path) + sockbuf accounting | async code-explorer (read-only) |
| **probe-extmbuf** | Map the RX-side ext-mbuf lifecycle (ff_mbuf_gethdr/m_extadd/ff_mbuf_ext_free/refcount/DPDK mbuf return) | async code-explorer (read-only) |
| **research-ext** | External research (GitHub F-Stack issue/PR/wiki, DPDK docs, FreeBSD soreceive/mp0 material, related blogs/official accounts) → inspiration but requires code verification | web_search/web_fetch |
| **design-arch** | Synthesize and produce the design (kernel mechanism selection + API + lifecycle + boundaries) | serial (scheduled by leader) |
| **gatekeeper** | Doc review gate: for each doc, verify across 4 dimensions "whether measured code references really exist, whether line numbers/symbols match, whether conclusions have rationale, whether speculation exists"; failing any bounces back to design/probe redo | serial |

**Failure-rollback SOP**: gatekeeper fails → bounce back to the corresponding probe/design sub-agent to re-gather evidence/rewrite; if a probe finds contradiction with a doc → code prevails and the correction is annotated.

---

## §5 Phase Schedule

| Phase | Name | Output | Sub-agent |
|---|---|---|---|
| **P0** | Hands-on reconnaissance (✅ completed, see §2) | this plan §2 | leader |
| **P1** | Doc skeleton landing | skeletons of `00-plan.md`(this doc) / `01-zcsend-baseline.md` / `02-recv-path-analysis.md` / `03-extmbuf-lifecycle.md` / `04-external-research.md` / `05-design-and-feasibility.md` / `09-review.md` | leader |
| **P2** | Parallel architecture probing | fill in 01/02/03 (all measured code references + line-number cross-verification) | probe-zcsend / probe-recvpath / probe-extmbuf |
| **P3** | External research | fill in 04 (GitHub/DPDK/FreeBSD/blogs, annotated for consistency with code) | research-ext |
| **P4** | Design | fill in 05 (kernel mechanism selection comparison + API design + lifecycle scheme + boundary matrix + risk + effort + milestone recommendations + feasibility conclusion) | design-arch |
| **P5** | Doc review gate | 09-review (4-dimension verification results); on failure, roll back P2/P4 | gatekeeper |
| **P6** | Wrap-up | aggregate conclusions; local commit (concise English message) | leader |

---

## §6 Document List (docs/zc_stack_user_spec/zh_cn/, Chinese only)

- `00-plan.md` —— this plan
- `01-zcsend-baseline.md` —— full ZC-SEND baseline reference chain
- `02-recv-path-analysis.md` —— READ path + soreceive/mp0 + sockbuf accounting analysis
- `03-extmbuf-lifecycle.md` —— RX ext-mbuf lifecycle and ownership
- `04-external-research.md` —— external material research and cross-verification
- `05-design-and-feasibility.md` —— design + feasibility conclusion + risk/effort/milestones
- `09-review.md` —— doc review gate record

---

## §7 Acceptance Gate (this study's acceptance gate)

| Gate | Content |
|---|---|
| G-ZCR-1 | All code references (file:line:symbol) verified to really exist by measurement; gatekeeper spot-check hits 100% |
| G-ZCR-2 | Kernel mechanism selection provides ≥2 alternative comparison (mp0 reuse vs ZC_MAGIC symmetric hook) + explicit recommendation |
| G-ZCR-3 | mbuf lifecycle/ownership scheme is closed-loop (argument for no use-after-free / no leak) |
| G-ZCR-4 | Boundary matrix covers all scenarios in §3.6 |
| G-ZCR-5 | Explicit feasibility conclusion (feasible/partially feasible/infeasible) + effort and milestone recommendations |
| G-ZCR-6 | Where external material and code are inconsistent, explicitly let code prevail and annotate |
| G-ZCR-7 | Chinese-only docs; no speculative wording (every conclusion traceable to code or annotated "pending implementation verification") |

---

## §8 Scope and Constraints

**In-scope**: feasibility study, design/API/lifecycle design, risk and effort assessment, documentation.
**Out-of-scope (not done this round)**: implementation code, kernel patch, unit/integration tests, performance stress tests, English docs.
**Workspace conventions**: deletion→`rm_tmp_file.sh`; process termination→`kill_process.sh`; permission change→`chmod_modify.sh`; non-direct-chmod commands such as `make install` may be executed. Commit message in English.

---

## §9 Risks

| Risk | Mitigation |
|---|---|
| The soreceive mp0 path may already have been modified in f-stack's reworked kernel | P2 probe-recvpath must measure the f-stack version of uipc_socket.c, not assume native FreeBSD behavior |
| ext-mbuf refcount and DPDK mbuf return timing are complex | dedicated P2 probe-extmbuf + P4 lifecycle closed-loop argument |
| External material outdated / inconsistent with the f-stack branch | always let measured code prevail; external is inspiration only |
| Sub-agent output contains speculation | gatekeeper 4-dimension gate; bounce back if not traceable to source |
