# 40. Acceptance Conditions and Implementation Milestones

> This spec phase's deliverable = the 30-39 + 49 document set; the implementation phase (M0-M5) starts as an independent plan
> AC is the implementation-phase completion criterion; milestones are the implementation-phase task breakdown

---

## §1 Acceptance Conditions (AC)

### AC1 Clean Compilation

| Compile combination | Expected |
|---|---|
| Default (without FF_ZC_*) | `-Werror` clean, rc=0 |
| `FF_ZC_SEND=1` | `-Werror` clean, rc=0 |
| `FF_ZC_RECV=1` | `-Werror` clean, rc=0 (coexists with ZC-recv) |
| `FF_ZC_SEND=1 FF_ZC_RECV=1` | `-Werror` clean, rc=0 |

Verification method:
```
cd lib
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig make clean
PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig <FLAGS> make
```

### AC2 Functional PASS

| Test | Expected |
|---|---|
| chain head has M_PKTHDR after `ff_zc_mbuf_get` | unit test U1 PASS |
| multiple `ff_zc_mbuf_write` accumulate pkthdr.len | unit test U5 PASS |
| `ff_zc_send` succeeds via the `kern_zc_sendit → sosend(top)` path | integration I1/I2 PASS |
| example/main_zc.c **zero modification** + curl http=200 | E2E PASS |
| coexistence with `FSTACK_ZC_RECV` (main_zc starts send+recv at the same time) | E2E PASS |

### AC3 Performance On Par (Δ ≤ ±3% within noise)

| Comparison | wrk profile | Pass criterion |
|---|---|---|
| B-new vs A baseline | T1/T2/T3 | Requests/sec Δ ≤ ±3% |
| B-new vs B-old (hacked version) | T1/T2/T3 | Requests/sec Δ ≤ ±3% |
| Latency p50/p90/p99 | T2 | Δ ≤ ±5% |
| Error rate | All profiles | Socket errors / Non-2xx = 0 |

See 38-perf-baseline-spec.md.

### AC4 Kernel diff Shrinkage

| diff base | Scope | Expected difference |
|---|---|---|
| vanilla FreeBSD 15.0 sys/kern/uipc_mbuf.c | m_uiotombuf function | **0 lines of difference** (returns to vanilla) |
| vanilla FreeBSD 15.0 sys/sys/mbuf.h | FSTACK_ZC_MAGIC section | **0 lines of difference** (deleted) |
| vanilla FreeBSD 15.0 sys/kern/sys_generic.c | dofilewrite uio_offset | **0 lines of difference** |
| vanilla FreeBSD 15.0 sys/kern/uipc_syscalls.c | recvit / sendit / sousrsend | 0 lines of difference |
| vanilla FreeBSD 15.0 sys/kern/uipc_syscalls.c | overall | **+kern_zc_recvit + kern_zc_sendit two new functions**, no other modifications |
| vanilla FreeBSD 15.0 sys/sys/syscallsubr.h | overall | +2 declarations (kern_zc_recvit already landed + kern_zc_sendit newly added), no other modifications |

### AC5 Memory Safety

| Test | Expected |
|---|---|
| valgrind on ff_zc_send + EPIPE 100 times | 0 definite leak |
| `rte_mempool_in_use_count` before vs after | closed (diff 0) |
| mock m_freem count under invalid input (top NULL / no PKTHDR) | consistent with spec INV-3 |

### AC6 spec Documentation Complete

| Document | Status |
|---|---|
| 30-spec-overview ~ 40-acceptance-and-milestones | all landed |
| 49-spec-review | includes gatekeeper sampling table + bounce counter |
| all cross-references accurate (line-number tolerance ±5) | gatekeeper PASS |
| spec documents have no direct rm/kill/chmod commands | grep 0 hits |

---

## §2 Implementation-Phase Milestones (M0-M5, start as an independent plan)

### M0 — Kernel additions + deletion list (kern_zc_sendit + 5 DELETEs)

| Subtask | File | Verification |
|---|---|---|
| 0.1 Add kern_zc_sendit declaration | freebsd/sys/syscallsubr.h | compiles |
| 0.2 Add kern_zc_sendit implementation | freebsd/kern/uipc_syscalls.c | compiles |
| 0.3 Delete FSTACK_ZC_MAGIC macro | freebsd/sys/mbuf.h | compiles (old ff_zc_send deleted, no leftover references) |
| 0.4 Revert m_uiotombuf to vanilla | freebsd/kern/uipc_mbuf.c | diff vs vanilla = 0 (in the m_uiotombuf region) |
| 0.5 Delete sys_generic.c uio_offset guard | freebsd/kern/sys_generic.c | compiles |

Milestone exit: `PKG_CONFIG_PATH=... FF_ZC_SEND=1 make clean && make` passes in lib/; libfstack.a contains the `T kern_zc_sendit` symbol.

### M1 — Userspace API rewrite + M_PKTHDR fix

| Subtask | File | Verification |
|---|---|---|
| 1.1 Rewrite ff_zc_send | lib/ff_syscall_wrapper.c | compiles; nm contains ff_zc_send |
| 1.2 Fix ff_zc_mbuf_get (add M_PKTHDR) | lib/ff_veth.c | compiles; unit U1 PASS |
| 1.3 Fix ff_zc_mbuf_write (maintain pkthdr.len) | lib/ff_veth.c | compiles; unit U5 PASS |
| 1.4 Delete ff_write/ff_writev opt-out | lib/ff_syscall_wrapper.c | compiles; grep 0 hits |
| 1.5 Update ff_api.h doc block | lib/ff_api.h | doc-level |

Milestone exit: `example/helloworld_zc` recompiles successfully; smoke curl http=200.

### M2 — Unit testing

| Subtask | Content | Verification |
|---|---|---|
| 2.1 Create tests/unit/test_ff_zc_send.c | U1-U12 all cases | 12 PASS |
| 2.2 Makefile adds test_ff_zc_send + per-target -DFSTACK_ZC_SEND + --wrap=kern_zc_sendit | tests/unit/Makefile | compile + link PASS |
| 2.3 INV safety cases L1-L2 (mock m_freem) | as above | PASS |
| 2.4 valgrind unit test | make check | 0 leak |
| 2.5 Coverage | gcov | ff_zc_mbuf_get/write/send ≥ 90% line |

### M3 — Integration testing

| Subtask | Content | Verification |
|---|---|---|
| 3.1 Create tests/integration/test_ff_zc_send_integration.c | I1-I10 | PASS |
| 3.2 Real EAL + loopback path | mimics ZC-recv | PASS |
| 3.3 INV safety cases L3-L5 (valgrind + mempool count) | same | 0 leak + closed |
| 3.4 issue #712 scenario large-packet test | 4KB / 64KB / 1MB | B-new does not crash |

### M4 — E2E performance baseline

| Subtask | Content | Verification |
|---|---|---|
| 4.1 Start server A baseline; wrk T1/T2/T3 x3 take average | helloworld | data archived to 21-perf-... |
| 4.2 Start server B-new; wrk T1/T2/T3 x3 | helloworld_zc | Δ vs A ≤ ±3% |
| 4.3 (optional) Start server B-old; same | git checkout old version | Δ vs B-new ≤ ±3% |
| 4.4 Large payload P2-P4 custom client | wrk + lua / self-implemented | B-new does not crash |

### M5 — Wrap-up + documentation archiving

| Subtask | Content | Verification |
|---|---|---|
| 5.1 ratchet G8 threshold | tests/unit/coverage_threshold.sh | gcov passes |
| 5.2 Write implementation-phase review doc | docs/zc_stack_user_spec/zh_cn/4x-impl-review.md | gatekeeper PASS |
| 5.3 Batch commit (English msg) | git | ahead +N |
| 5.4 ratchet AC1-6 all-PASS annotation | upgrade 49-spec-review | completed |

---

## §3 Time Estimate (reference; actual decided by the implementation-phase plan)

| Phase | Estimate |
|---|---|
| M0 | 0.5 day |
| M1 | 0.5 day |
| M2 | 1 day |
| M3 | 1 day |
| M4 | 0.5-1 day |
| M5 | 0.5 day |
| **Total** | **4-4.5 days** |

Includes slack for 1 gatekeeper bounce.

---

## §4 Entry Conditions (required before the implementation-phase plan starts)

- [ ] This spec (30-49) all landed and passed by the gatekeeper
- [ ] 49-spec-review.md shows bounce counter < 3 / step
- [ ] User has audited/confirmed this spec (manual review)
- [ ] Implementation-phase plan broken down into an executable plan_create per the milestones in §2 of this 40

---

## §5 Exit Conditions (implementation phase complete)

- [ ] AC1-AC6 all PASS
- [ ] Batch commit (English msg) pushed to the feature branch
- [ ] 21/22-style performance + implementation review docs archived to docs/zc_stack_user_spec/zh_cn/4x-
- [ ] 41+ series implementation review landed

---

Next: **49-spec-review.md** (gatekeeper audit record + bounce counter).
