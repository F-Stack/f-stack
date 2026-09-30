# Independent Gate Audit Report — Specification Set 00–08 (English)

> **English mirror** of `docs/nginx_reload_spec/zh_cn/09-review-report.md` (v1.9.14). The Chinese text is
> authoritative; where the two differ, the Chinese original governs. This is a structural and content sync
> (audit scope, gates, findings and closure), not a line-by-line translation of all ~900 lines.
> Revised 2026-09-30.

---

## 1. Scope and method

Independent audit of the specification set 00–08: evidence-chain spot checks, IP-compliance re-verification,
consistency, completeness, and rule conformance. Findings are graded and every grade has an explicit return
path (which gate the work goes back to).

## 2. Gates

| Gate | Release condition | On failure |
| --- | --- | --- |
| **G0** | plan approved; team / recovery / bounded execution and resource ownership established | stop implementation |
| **G-A** | A/B/C and source re-verification; requirement coverage and change list explicit | return for evidence |
| **G-H** | driver safety and negative self-tests pass; no PASS on missing data | return to instrumentation |
| **G-B** | code review, clean build, unit / true-EAL pass, no new warnings | fix and rebuild completely |
| **G-R** | after smoke: matrix and dual-end independent recomputation | instrumentation → G-H, product → G-B |
| **G-D** | Chinese text, historical state, test mapping and architecture consistent; **English translation review after functional acceptance** | D revises |
| **G-F** | all in-scope problems closed; recovery / stash / commit / agent final state checked | back to the corresponding stage; no unhealthy ending |

**G-D status (2026-09-30): done.** The English edition was refreshed from the current Chinese sources
(00 v1.9.11, 06 v1.9.16, 07 v1.27, 08 v1.23, 09 v1.9.14), and English mirrors of the specification documents
were added next to the Chinese ones.

## 3. Evidence-chain spot checks

Spot checks cover the load-bearing claims: the absence of established-connection migration precedent, the
queue-ownership decoupling precondition, the "ready before cut-over" pattern, the退役 of the ping-pong lcore
segment, and the self-driven hardclock necessity that follows from D-A.

## 4. Consistency and completeness

Consistency is checked across the documents (numbering, versions, alignment baselines and cross references);
completeness is checked against the requirement list (every acceptance criterion must have a case, and every
case must have a criterion).

## 5. Findings and closure

The 29 cross-audit findings (A01-*, B01-*, B02-1, C01-*, M02-*, M03-*) are closed: 12 in code or harness, 17
by documentation alignment. Per-finding state, fix batch and evidence live in
`work/recheck-20260918/findings.json`.

## 6. Historical addenda (abridged)

Sections 10–25 of the Chinese document record, in order: the bounce-1 closure, U1 confirmation, the flow-map
windowing revision, the cross-audit conclusions with human decisions X1/X2/X3, the no-RSS fallback, the
S3-M1 scheme-level revision, the self-driven hardclock and per-generation mempool decision, the flow-map
insertion-timing correction, the v1.9 cross-audit and M1′ upgrade, the independent re-audit, the D-A reversal,
the C-NR-314/315/316 anchor confirmation, the G1 gate re-confirmation, the DR11 re-judgement, and the
third-party cross-audit closure.

The most recent additions concern the flow-map admission: the insertion point is **SYN admission, before the
SYN-ACK**, the admission rule is a single authority that can refuse a SYN, and a failed SYN-ACK undoes the
admission. All three are now asserted on a real machine.

## 7. Changes since the previous English edition (2026-09-22)

- G-D recorded as done, with the refreshed English edition and the English mirrors.
- The flow-map admission addenda (insertion point, admission rule, undo on failure) summarised.
- The orphan half-open entry investigation and the `syncookies_only=1` note registered as known, not open.
