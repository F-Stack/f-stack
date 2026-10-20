# 30. Userspace Zero-copy Stack spec — Overview

> Scope: full "userspace zero-copy stack" (zc_stack_user) spec
> Key change: add a symmetric `kern_zc_sendit`, **replacing** the existing `FSTACK_ZC_MAGIC` + `m_uiotombuf` kernel hack
> Directory: `docs/zc_stack_user_spec/zh_cn/` (Chinese only)
> Status: spec phase (no code implementation)

---

## §1 Background and Motivation

In the M8 phase (commit ca83653c1 etc.) f-stack landed `FSTACK_ZC_SEND` application-layer → protocol-stack zero-copy, and more recently implemented `FSTACK_ZC_RECV` (M0+M1, commit b87f5f0d2). The two paths are independently designed and mechanistically asymmetric:

| Dimension | ZC-send (current) | ZC-recv (landed) |
|---|---|---|
| Kernel entry | Hacked `#ifdef FSTACK_ZC_SEND` branch of `m_uiotombuf` | New `kern_zc_recvit` passing through `soreceive`'s `mp0` out-param |
| Sentinel mechanism | Relies on `uio->uio_offset == FSTACK_ZC_MAGIC` (off_t 0xF8AC2C00F8AC2C00) + the `UIO_SYSSPACE/UIO_WRITE` trio | **No sentinel**: directly uses the FreeBSD native `mp0` out-param contract |
| Upstream consistency | Low (5-file hack + uio_offset threaded through the whole syscall path) | High (only 2 new functions; soreceive core 0 changes) |
| Accidental-trigger risk | **Exists** (plain `ff_write/ff_writev` must explicitly opt out with `uio_offset=0` to prevent accidental triggering; in the M2 phase a stale .o once lacked the hook causing a GPF) | None |
| Upgrade-maintenance cost | High (when FreeBSD 15.x → N.0, the surroundings of `m_uiotombuf` need re-auditing) | Low (only adds, does not modify) |

External cross-validation (see 31 for details):
- F-Stack official documentation (Tencent Cloud Developer Community, 2022-04-17) states the ZC-send performance gain is only 2-3%;
- F-Stack upstream issue [#712](https://github.com/F-Stack/f-stack/issues/712) (2022-11-01 to present, OPEN): sending large amounts of data will crash/hang, no community fix;
- The FreeBSD `sosend(9)` manual (since FreeBSD 7.0, author Robert Watson) states verbatim: "Data may be sent ... as an mbuf chain via *top*, **avoiding a data copy**. Only one of the *uio* or *top* pointers may be non-NULL."

→ **Conclusion**: FreeBSD 15.0 already natively supports the equivalent send-side zero-copy (`sosend(uio=NULL, top=chain)`), the current `FSTACK_ZC_MAGIC` solution is an "unnecessary reinvention" of an already-existing upstream capability, and should switch to the native path.

---

## §2 Goals

| No. | Goal |
|---|---|
| G1 | Add the `kern_zc_sendit(td, s, top, flags)` kernel entry, directly calling `sosend(uio=NULL, top=chain)` (uipc_socket.c:2599) |
| G2 | Tear down the `FSTACK_ZC_MAGIC` macro + the `#ifdef FSTACK_ZC_SEND` branch of `m_uiotombuf` + the `uio_offset` preservation logic of `kern_writev` + the `uio_offset=0` opt-out of `ff_write/ff_writev` (5 sites total) |
| G3 | Fix the `M_PKTHDR`/`pkthdr.len` gap in `ff_zc_mbuf_get`/`ff_zc_mbuf_write` (sosend in the `uio==NULL` branch uses `top->m_pkthdr.len` as resid; missing it means resid=0 and no data is sent) |
| G4 | Keep the external ABI unchanged: the `ff_zc_send` / `ff_zc_mbuf_get` / `ff_zc_mbuf_write` function signatures and the example/main_zc.c call sequence are **zero-modified**; the `FF_ZC_SEND` Makefile switch name is retained (only its meaning switches) |
| G5 | Form a fully symmetric "userspace zero-copy stack" with `kern_zc_recvit` (API form, lifecycle, error path, ABI delta, Makefile switch) |
| G6 | Performance vs the current hack solution Δ ≤ ±3% (within noise); function example curl http=200 PASS |

---

## §3 Scope

### §3.1 In-scope (this cycle's spec must cover)

| Module | spec document |
|---|---|
| Current-state mapping and removal list | 31-current-state-and-removal.md |
| Symmetric architecture design | 32-native-arch-design.md |
| Detailed kernel patch spec (with anchors) | 33-kernel-patch-spec.md |
| Userspace API spec (ABI unchanged + M_PKTHDR fix) | 34-userspace-api-spec.md |
| mbuf chain ownership state machine + invariants | 35-mbuf-lifecycle-spec.md |
| Boundary and fallback matrix (TCP/UDP/SCTP/ATOMIC/NBIO/SCM/aio/PAGE_ARRAY etc.) | 36-boundary-and-fallback-spec.md |
| CMocka test spec | 37-test-spec.md |
| Performance baseline spec (wrk + large payload) | 38-perf-baseline-spec.md |
| Migration guide for deployed projects | 39-migration-guide.md |
| Acceptance + M0-M5 milestones | 40-acceptance-and-milestones.md |
| Gate review and bounce counter | 49-spec-review.md |

### §3.2 Out-of-scope (not handled this cycle)

- Implementation code (this cycle is spec only; the implementation phase starts with an independent plan).
- ZC-recv (kern_zc_recvit/mp0) has landed; this spec only reuses its pattern in the "symmetric reference" sub-sections; it does not rewrite the existing 11-17 series ZC-recv spec.
- `FF_USE_PAGE_ARRAY` (protocol-stack → DPDK stage-one zero-copy): no direct coupling with this spec, only appears in the 36 boundary matrix.
- English-version documents: to be discussed after manual audit.

---

## §4 Terminology (Glossary)

| Term | Definition / anchor |
|---|---|
| **ZC-send (zero-copy send)** | Zero-copy send in the application-layer → protocol-stack direction, corresponding to the `FSTACK_ZC_SEND` compile switch |
| **ZC-recv (zero-copy receive)** | Zero-copy receive in the protocol-stack → application-layer direction, corresponding to the `FSTACK_ZC_RECV` compile switch |
| **FSTACK_ZC_MAGIC (old)** | `((off_t)0xF8AC2C00F8AC2C00LL)`, freebsd/sys/mbuf.h:1868; deleted by this spec |
| **`top` parameter** | The 4th argument of `sosend()` (`struct mbuf *top`), uipc_socket.c:2600; the FreeBSD native zero-copy send entry |
| **`mp0` parameter** | The 4th argument of `soreceive()` (`struct mbuf **mp0`); the FreeBSD native zero-copy receive out-param |
| **kern_zc_sendit** | The new kernel function in this spec, the zero-copy sibling of sousrsend (the `top!=NULL` path) |
| **kern_zc_recvit** | Already landed (uipc_syscalls.c:1049), the zero-copy sibling of kern_recvit (the `mp0!=NULL` path) |
| **ff_zc_mbuf** | `struct ff_zc_mbuf { void *bsd_mbuf; void *bsd_mbuf_off; int off; int len; }`, ff_api.h:347 |
| **PR_ATOMIC** | protosw flag, requiring one-shot delivery (UDP/SCTP/UNIX dgram); see 36 |
| **bounce counter** | Single-step bounce count, incremented on gate failure; cap 3 times (per memory rule 86071475) |

---

## §5 Decision Table (user confirmed C+A+A)

| Decision item | Choice | Meaning | Affected spec |
|---|---|---|---|
| scope | **C** | Full "userspace zero-copy stack" spec | Full 33-40 set, including ZC-recv symmetric reference sub-sections |
| Old-path disposition (compat) | **A** | Tear down immediately | 31 removal list + 33 kernel patch take effect at the same time |
| Rename timing (rename) | **A** | plan's first step git mv + fix self-ref | S1 done |

---

## §6 Relationship with Existing Documents

```
docs/zc_stack_user_spec/zh_cn/
├── 00-09 feasibility study (PRESERVED, commit 875532e35)
├── 10-19 ZC-recv first-version spec (PRESERVED, commit e62afc541)
├── 20-22 implementation-phase deliverables (20 execution plan / 21 M2 test report / 22 native ZC-send research)
│        ↑ direct prerequisite of this spec (22's conclusion "Yes —— sosend(top) natively supported")
├── 29 this cycle's spec-phase plan
├── 30 this file
├── 31-40 ZC-send nativization spec (new this cycle)
└── 49 gate review record
```

22-research (commit 0294a9baa) has measured and verified that sosend `top` has no `FSTACK_*` hack in its FreeBSD 15.0 section, skips the `m_uiotombuf` copy when `uio==NULL`, and resid is taken from `top->m_pkthdr.len` (uipc_socket.c:2341/2170) —— this is the **global technical premise** of the 30+ series spec.

---

## §7 Mandatory Regulations (throughout the spec phase)

1. **Measurement first**: every spec entry must have a `file:line:symbol` measured source; external is for cross-validation only; conflicts defer to the code.
2. **harness multi-agent gate rollback** (memory 86071475): the single-step bounce loop cap is 3 times, on the 4th failure immediately stop the task and switch to human.
3. **rm/kill/chmod go through scripts** (memories 81725399 / 90098233 / 21626578): all shell command strings are strictly forbidden from directly using `rm`/`kill`/`pkill`/`killall`/`chmod`/`setfacl`/`install -m`/`find -delete`/`shred`; uniformly go through `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`; **the spec document examples likewise comply**.
4. commit message in English (memory 73362122), conversation in Chinese.
5. The spec must not provide executable "how to patch" commands; it must provide c-precision-surgery-style "line number + context anchors", to be converted into a patch by the implementation-phase agent.

---

## §8 Reading Path Suggestions

| Role | Order |
|---|---|
| Design auditor | 30 → 31 → 32 → 35 → 36 → 40 |
| Kernel implementation engineer | 30 → 32 → 33 → 35 → 36 |
| Userspace implementation engineer | 30 → 32 → 34 → 35 → 39 |
| QA / test engineer | 30 → 35 → 36 → 37 → 38 → 40 |
| Upstream migration engineer | 30 → 39 → 40 |

Next: **31-current-state-and-removal.md** (current-state mapping + 5-site removal list).
