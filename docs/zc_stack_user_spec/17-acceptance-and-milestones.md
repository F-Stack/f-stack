# 17 · Acceptance Criteria and Milestones

## 1. Acceptance Criteria (DoD)
### Functional
- [ ] AC-F1: ff_zc_recv zero-copy receives a whole mbuf segment over TCP, data consistent with the sender.
- [ ] AC-F2: ff_zc_mbuf_segment/read correctly traverses/reads out a multi-segment chain.
- [ ] AC-F3: ff_zc_recv_free correctly returns the whole chain (including mixed ext/copym segments).
- [ ] AC-F4: ordinary ff_read/ff_recv/ff_recvfrom/ff_recvmsg behavior has zero regression.

### Memory Safety
- [ ] AC-M1: after recv+free loop, rte_mempool_in_use_count returns to baseline (no leak).
- [ ] AC-M2: valgrind 0 definite leak (unit + integration make check).
- [ ] AC-M3: post-free access protection (segment returns -1, no use-after-free).

### Boundary
- [ ] AC-B1: split/PEEK/OOB/TLS/UDP fallback path data correct.
- [ ] AC-B2: non-blocking EAGAIN / connection closed 0 / partial packet semantics correct.

### Compatibility/Engineering
- [ ] AC-C1: when FSTACK_ZC_RECV is undefined, all changes do not participate in compilation, existing build zero impact.
- [ ] AC-C2: compile switch FF_ZC_RECV→FSTACK_ZC_RECV consistent with SEND paradigm.
- [ ] AC-C3: example example/main_zc.c (or new one) demonstrates the recv sequence.

### Performance (baseline comparison)
- [ ] AC-P1: in large-packet receive scenarios, the ZC path has measurable CPU/throughput benefit relative to the copy path (M4 baseline report).

## 2. Milestones (implementation phase, after this spec)
| Milestone | Content | Exit Condition |
|---|---|---|
| **M0** kernel mp passthrough | kern_zc_recvit + soreceive(&mp) passthrough (FSTACK_ZC_RECV gated) | kernel compiles; mbuf chain can be handed out |
| **M1** userspace API | ff_zc_recv + ff_zc_mbuf_read rewrite + ff_zc_recv_free | API unit tests pass (16 §3) |
| **M2** lifecycle closed loop | refcnt + release contract + leak detection | AC-M1/M2/M3 pass |
| **M3** boundary complete | split/PEEK/WAITALL/DONTWAIT/UDP fallback | AC-B1/B2 pass |
| **M4** example+performance baseline | recv example + ZC vs copy baseline | AC-P1 report produced |
| **M5** page-array compatibility | verify under FF_USE_PAGE_ARRAY=1 | AC-F/M all pass under this mode |

## 3. Risks and Rollback
- If any AC-M (memory safety) fails → roll back to M2 to redo the lifecycle.
- read() path ZC (K2) is optional; if M0-M3 schedule is tight it can be deferred, not blocking the recv-family main function.

## 4. Workload Restatement (from 05 §5)
Kernel ~50-100 lines + userspace ~100-150 lines + tests + example, rough estimate 8-15 person-days (excluding large-scale performance tuning).
