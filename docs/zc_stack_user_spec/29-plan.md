# 29. Userspace Zero-copy Stack spec Phase Plan (ZC-send Nativization)

> Phase: this cycle only produces spec documents, no code implementation
> Directory: Chinese only (`docs/zc_stack_user_spec/zh_cn/`, renamed from the former `zc_read_spec`)
> Prerequisite: 22-native-zc-send-research (already confirmed sosend(top) is the FreeBSD 15.0 native path)
> Target commit msg: English (per memory rule)

---

## §1 Goal

Add a symmetric `kern_zc_sendit` (calling `sosend(uio=NULL, top=mbuf chain)`) native send-side zero-copy interface for f-stack, **replacing** the existing `FSTACK_ZC_MAGIC` + `m_uiotombuf` kernel hack, forming a fully symmetric "userspace zero-copy stack" with the already-implemented `kern_zc_recvit` (soreceive `mp0` out-param).

### §1.1 Key Decisions (from requirement clarification)

| Decision item | Choice | Meaning |
|---|---|---|
| scope | **C** | Full "userspace zero-copy stack" spec: ZC-send nativization + ZC-recv symmetric integration + test spec + performance baseline spec + migration guide |
| Old-path disposition (compat) | **A** | Tear down immediately: when the new solution merges, simultaneously delete the `FSTACK_ZC_MAGIC` macro and the `m_uiotombuf` kernel patch |
| Rename timing (rename) | **A** | plan's first step `git mv` + fix self-reference, the new spec lands directly in the new directory |

---

## §2 Mandatory Regulations (throughout the cycle, in effect alongside existing regulations)

1. **Measurement first**: every spec entry must have a `file:line:symbol` measured source; external material is for cross-validation only; conflicts defer to the code.
2. **Harness multi-agent gate rollback (memory 86071475)**: any phase gate failure bounces back to the previous step, **single-step loop cap is 3 times**, on the 4th failure immediately stop the task and switch to human decision.
3. **rm/kill/chmod go through scripts (memories 81725399 / 90098233 / 21626578)**:
   - All shell command strings (including ssh remote commands, sed/awk embedded scripts, Makefile fragments) are strictly forbidden from directly using `rm`/`pkill`/`kill`/`killall`/`chmod`/`setfacl`/`install -m`/`find -delete`/`shred`;
   - Uniformly go through `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`;
   - **The example code in this cycle's spec documents likewise complies** (cannot give `rm` etc. commands in the spec).
4. **commit message in English** (memory 73362122), conversation in Chinese.

---

## §3 Document List (`docs/zc_stack_user_spec/zh_cn/`, the 30+ series are new this cycle)

| # | Document | Responsible sub-agent |
|---|---|---|
| 29-plan.md | This cycle's plan (this file) | Leader |
| 30-spec-overview.md | Overview / scope / terminology / decision table | spec-writer |
| 31-current-state-and-removal.md | Full map of the 5 existing ZC-send hack sites + removal list + external-behavior-invariance proof | probe-zcsend-current → spec-writer |
| 32-native-arch-design.md | New symmetric architecture (kern_zc_sendit ↔ kern_zc_recvit mirror) | probe-sosend-native + probe-zcrecv-symmetry → spec-writer |
| 33-kernel-patch-spec.md | Detailed kernel change spec | probe-sosend-native → spec-writer |
| 34-userspace-api-spec.md | ff_zc_send rewrite + ff_zc_mbuf_get adding M_PKTHDR + ff_zc_mbuf_write maintaining pkthdr.len | probe-zcsend-current → spec-writer |
| 35-mbuf-lifecycle-spec.md | mbuf chain ownership state machine + invariants INV1-3 | probe-sosend-native → spec-writer |
| 36-boundary-and-fallback-spec.md | TCP/UDP/SCTP/PR_ATOMIC/EWOULDBLOCK/SIGPIPE/SCM/aio/PAGE_ARRAY boundary matrix | spec-writer |
| 37-test-spec.md | CMocka unit + integration test spec (inheriting the 16 style) | spec-writer |
| 38-perf-baseline-spec.md | wrk T1/T2/T3 + large-payload custom client + single-core cvm | spec-writer |
| 39-migration-guide.md | Upgrade path for deployed projects (including the necessity of `make clean`) | spec-writer |
| 40-acceptance-and-milestones.md | AC + M0-M5 milestones | spec-writer |
| 49-spec-review.md | Gate review record + bounce counter | gatekeeper |

---

## §4 Execution Phases (8 steps, advanced per the plan todolist)

| # | Phase | Key deliverable | Dependency |
|---|---|---|---|
| S1 | Rename + fix self-ref + land plan | This file + lib/ff_veth.c comment sync | — |
| S2 | Parallel architecture probing (3 sub-agents) | Three Chinese reports: probe-zcsend-current / probe-sosend-native / probe-zcrecv-symmetry | S1 |
| S3 | External cross-validation | research-ext-zcsend report | S1 |
| S4 | Write 30/31/32 three pieces + gatekeeper | Overview + current-state removal + symmetric architecture spec | S2/S3 |
| S5 | Write 33/34/35 three pieces + gatekeeper | Kernel patch + API + lifecycle spec | S4 |
| S6 | Write 36/37/38 three pieces + gatekeeper | Boundary + test + performance spec | S5 |
| S7 | Write 39/40 two pieces + gatekeeper | Migration guide + AC | S6 |
| S8 | Final review + 49 review record + batch commit | 49-spec-review + 1 commit | S7 |

After each phase's deliverable lands, it immediately passes a gatekeeper spot-check; if it fails it is counted into the bounce counter and bounced back to spec-writer for revision; bouncing the same step ≥3 times stops the task.

---

## §5 Agent Team Topology

```
Leader (main conversation, this agent)
├── probe-zcsend-current  [code-explorer, READ-ONLY]
├── probe-sosend-native   [code-explorer, READ-ONLY]
├── probe-zcrecv-symmetry [code-explorer, READ-ONLY]
├── research-ext-zcsend   [web_search + web_fetch]
├── spec-writer           [serially invoked by Leader, each piece an independent task]
└── gatekeeper            [code-explorer + grep]
```

Leader responsibilities: phase scheduling, bounce counter, gate arbitration, document landing, commit.

---

## §6 Key Technical Decision Preview (see 32/33/34 spec for details)

### §6.1 Kernel entry: call sosend directly, not sousrsend

Measured: inside `sousrsend` (uipc_socket.c:2615) the `pr_sosend(..., uio, NULL, ...)` 4th argument top is hard-coded NULL → sousrsend cannot be reused. The new `kern_zc_sendit` directly calls `sosend(so, addr, NULL, top, control, flags, td)` (uipc_socket.c:2599), fully symmetric with `kern_zc_recvit` directly calling `soreceive`.

### §6.2 ff_zc_mbuf_get/write Mandatory-fix Gap

Measured:
- `ff_zc_mbuf_get`(ff_veth.c:306) uses `m_getm2(NULL, len, M_WAITOK, MT_DATA, /*flags*/0)` —— without `M_PKTHDR`;
- in `ff_zc_mbuf_write`(ff_veth.c:326) the `pkthdr.len` accumulation is commented out.

Consequence: sosend in the `uio == NULL` branch uses `top->m_pkthdr.len` as resid → under the status quo `resid=0` → immediately returns 0 bytes. The spec mandates the fix:
- `m_getm2(NULL, len, M_WAITOK, MT_DATA, M_PKTHDR)`;
- ff_zc_mbuf_write maintains `((struct mbuf *)zm->bsd_mbuf)->m_pkthdr.len += length` at the chain head.

### §6.3 Old-path Deletion List (see 31 for details)

| File | Line | Disposition |
|---|---|---|
| `freebsd/sys/mbuf.h` | 1856-1868 | Delete the whole block (FSTACK_ZC_MAGIC macro) |
| `freebsd/kern/uipc_mbuf.c` | 2028-2070 | Delete the whole block (m_uiotombuf #ifdef FSTACK_ZC_SEND branch) |
| `freebsd/kern/sys_generic.c` | 560-569 | Delete the whole block (kern_writev uio_offset preservation logic) |
| `lib/ff_syscall_wrapper.c` | 1146 / 1186-1226 | Delete opt-out + rewrite ff_zc_send |

### §6.4 Error-path Ownership (see 35 for details)

Default contract: on success sosend takes over top → app must not use it again; on error `kern_zc_sendit` calls `m_freem(top)` as a fallback (to avoid protosw inconsistency).

---

## §7 Acceptance Preview (see 40 for details)

| AC | Clause |
|---|---|
| AC1 compile | Three combinations default + `FF_ZC_SEND=1` + `FF_ZC_RECV=1` are `-Werror` clean |
| AC2 function | example/main_zc.c unchanged, curl http=200 PASS |
| AC3 performance | wrk T1/T2/T3 vs the current hack solution Δ ≤ ±3% (within noise) |
| AC4 kernel diff | Compared with vanilla FreeBSD 15.0, only two new functions `kern_zc_sendit` + `kern_zc_recvit` are added (no `m_uiotombuf` modification) |

---

> After this cycle's spec is complete, the next phase (implementation) will land the patch per 33/34/35, write tests per 37, run baselines per 38, and complete acceptance per 40.
