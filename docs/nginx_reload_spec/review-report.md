# Independent Gate Audit Report — Specification Set 00–08 (English)

> **English mirror** of `docs/nginx_reload_spec/zh_cn/09-review-report.md` (v1.9.21). The Chinese text is
> authoritative; where the two differ, the Chinese original governs. This is a structural and content sync
> (audit scope, gates, findings and closure), not a line-by-line translation of all ~900 lines.
> Revised 2026-10-08; §10 added on 2026-10-10, §11 to §13 on 2026-10-12.

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

**G-D status (2026-10-08): done** — the 2026-10-08 sync was reviewed by R4′ (one bounce, three fixes) and
rechecked by R4″. **G-D status (2026-09-30): done.** The English edition was refreshed from the current Chinese sources
(00 v1.9.11, 06 v1.9.16, 07 v1.27, 08 v1.23, 09 v1.9.14), and English mirrors of the specification documents
were added next to the Chinese ones.

## 3. Evidence-chain spot checks

Spot checks cover the load-bearing claims: the absence of established-connection migration precedent, the
queue-ownership decoupling precondition, the "ready before cut-over" pattern, the retirement of the ping-pong lcore
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

## 7. Changes in the 2026-09-30 edition (relative to 2026-09-22)

- G-D recorded as done, with the refreshed English edition and the English mirrors.
- The flow-map admission addenda (insertion point, admission rule, undo on failure) summarised.
- The orphan half-open entry investigation and the `syncookies_only=1` note registered as known, not open.

## 8. 2026-09-23 formal closure and the 2026-10-08 round (mirror of zh_cn 09 §27/§28)

**Formal closure (2026-09-23).** G-F **PASS, no blocking item** on HEAD `ca5dcb03b`; the seven conditions of the
preliminary closure and N-UT-01 were all closed. Functional acceptance: production form precheck / rt01 / rt02 /
gr0 / rt12 / baseline / rv9-IPv4 100 rounds / rt01-IPv6 / rv9-IPv6 100 rounds. Fault cases rt20/rt21/rt22/rt20b
count only for their fault-path criteria; rt13 is permanently excluded. P-2 and P-13 stayed open.

**2026-10-08 round.** Three read-only auditors (docs/sources, data plane, control plane/tests) cross-checked
zh_cn 00–09 against HEAD `eb6b32c82`; an independent reviewer de-duplicated and graded the findings (34 items,
R-01..R-34). The asynchronous team channel stopped delivering results during the delta code review and the
documentation review, so those were redone by fresh synchronous reviewers (R3′, R4′); no item was reviewed by
its writer. Highlights:

- **Code fix R-02 (P1).** Every tx packet used to run `ff_reload_dir_sync()`; after a USR2 the dead old master's
  directory slot stays LIVE, so each tx packet of the new master's workers issued a `kill(pid, 0)`. Now the
  per-packet tx paths call `ff_no_hw_mode_nosync()`, the neighbour-clone and miss-forward gates read
  `ff_reload_peer_mirror_draining()`, and the pid probe is cached per slot for 50 ms. Measured with strace on one
  worker: steady state 0 kill(2); USR2 coexistence about 20/s per worker (intermediate build B with a 1 ms cache: about 1000/s; the final code caches 50 ms).
- **Harness fixes.** rt23 now parses its own errlog (exactly 6 transitions, one round, refusal in `T3_DRAIN`,
  stream verdict checked) — this closes **P-2**. `hup_once()` requires exactly 6 transitions and no illegal event.
  rt25's `drain_before_quit` only looks after the USR2 handover. Early-return branches stop the stack. The unit
  fixture was updated for the 09-28 validator keys (the formal-close "51 tests OK" no longer held on HEAD).
  The process supervisor no longer aborts a whole run when `/proc/<pid>/exe` of a child that is just exiting
  returns EACCES (seen once in rt24; a live process that stays unreadable still fails the run).
- **P-13 closed** as expected semantics: after an abort the master returns to T0 and keeps running; rt24 shows the
  same master completing a HUP after an abort.
- **Documentation.** The 09-30 symbol-anchor conversion had mapped many anchors to unrelated functions; all anchors
  were re-checked. 06 gained §10 (errata, the R-02 fix, risks registered but not closed), 07/08 the current drain
  timing and acceptance criteria, 08 a rewritten harness interface, and the three-layer knowledge base a Chinese
  edition of the graceful reload sections.

Runtime results of the round are listed in the Chinese 09 §28 and in testing-plan §7.

## 9. Second round on 2026-10-08: RX-15, RX-29 and RX-30 (mirror of zh_cn 09 §29)

The maintainers asked for RX-15, RX-29 and RX-30 to be fixed with chosen approaches (the primary resets the rings
when the window closes; attach on the hw_locked edge or before a park ack; refuse graceful_reload=1 in
FF_USE_PAGE_ARRAY builds); the other seven items stay registered only. The writer did not review its own work:
CR-RX reviewed the change (PASS, six SHOULD items: a possibly blocking attach in the main loop, log flooding on
failure, a lost reset when the lock is busy, table capacity, retire/park flapping, stale comments) and a fresh
reviewer, CR-RX2, re-checked the fixes (PASS; its remaining suggestions were applied). Every .c/.h change was
followed by a clean full build (RX, RX2, RX3; lib warnings equal to the baseline of 51); results are in the
testing plan and in the RX3 rows of zh_cn 08 §2.3.3. Limits: the RX-29 timing is backed by runtime
logs only, and the RX-15 runtime evidence is one natural purge in the rt25 stack, not a targeted fault test.

## 10. 2026-10-10: RX-35 (mirror of zh_cn 09 §30)

Reproduced on a clean host (kni=0 primary stays → kni=1 → restart master → every worker panics) against a clean
KNI start that works; two independent researchers agreed on the root cause, unrelated to 35bf93dc1 (gh search was
not run: the token returned 401). The plan took four gate rounds (PR-K 6 MUST, PR-K2 3 MUST, PR-K3 1 MUST, PR-K4
PASS), within the three-bounce limit. Code review: CR-K PASS (four SHOULD items fixed, signalling moved to a pidfd),
CR-K2 and CR-K3 PASS on the follow-ups, then CR-K4 FAIL → CR-K5 PASS on the rt27 evidence lines (one
code-stage bounce); every reviewer was a fresh instance and none reviewed its own work. Each
.c/.h change was followed by a clean full build. The test-evidence audit failed once (TA: four evidence-chain gaps)
and passed after rt27 gained per-step evidence lines, the build counts and the raw
user-instance output were recorded and rv9 was extended to 100 rounds per family (TA2 PASS). The documentation gate failed twice (GD-K: four MUST items, GD-K2: the default case list of
the English testing plan) and passed with GD-K3; the final gate G-K passed. Residuals are listed in the solution
design §10.5.

## 11. 2026-10-12: RX-36 (mirror of zh_cn 09 §31)

Reproduced on the user's instance: the missing EAL file prefix (A), the PCI probe and its leaked ethdev lock (B,
lock value read with gdb), the ngctl exit crash (C) and the long-running samplers dying or wrapping across a
reload (D). The gh token returned 401; the GitHub REST search and raw sources showed the same hard-coded EAL
arguments upstream and issue #419 as a related case. Code review: CR-T PASS (its SHOULD items applied, the vdev
path registered), CR-T2 FAIL on the follow-up (TTL refresh applied to every tool would move ngctl sessions; the
probe did not free its own late replies), one bounce, CR-T3 PASS; every reviewer was a fresh instance. The
documentation review failed twice (GD-T: a duplicated README section, no archived output for the
`graceful_reload=0` and stale-record checks, no ledger of the review rounds; GD-T2: the build log was not
archived) and passed with GD-T3. Every tools change
was followed by a clean full build; only `tools/` changed, and the residuals are listed in the solution design
§10.6.

## 12. 2026-10-12: RX-37 (mirror of zh_cn 09 §32)

Reproduced on the user's default instance: stop, quit and a SIGKILL by process name all leave the resident primary
behind, and a graceful_reload=0 start then fails with `Is another primary process running?`. Design gate: DR-S FAIL
(deleting the files before the self-exit opens a window while the EAL lock is still held; rt27 must export its grace
before the stack starts), one bounce; the revisions were checked item by item by the code review CR-S (MUST-1 and the
SHOULD items) and the harness review CR-H (MUST-2) instead of a separate design re-review. Code review: CR-S FAIL (a unit test wrote past the slot array, `main` lacked its
return type), one bounce, CR-S2 PASS; CR-H PASS on the harness; IPv6 rt28 step 4 failed on the host, one bounce, fixed
with `ff_reload_gendir_masters_seen()` and passed CR-S3. Test-evidence audit: TA-S FAIL (it could not open the build logs, which do exist, and some reproduction
outputs were not archived; the self-exit line also gained the pid), TA-S2 PASS. Documentation review: GD-S FAIL (the ff_reload.c line count, the guide's upgrade entry
missing builds that have a record but whose master does not stop the primary on exit, review rounds missing from the ledger), one bounce;
GD-S2 FAIL (one line count left in the Chinese Layer 1 tree), second bounce, fixed together with
the guide's USR2 command examples turned into prose; GD-S3 PASS (section 9 of the ledger). Every reviewer was a fresh instance; every .c/.h change was followed by a clean full build
(S1 to S8). Residuals are listed in the solution design §10.7.

## 13. 2026-10-12: RX-38 (mirror of zh_cn 09 §33)

Reproduced on the user's default instance with only `[port0] mtu=9000`: a 60 s wait, a generic `failed to become
ready` and a stale nginx.pid, while the primary log has `port0 mtu 9000 > 1500 requires mtu_enable=1`;
graceful_reload=0 rejects the same config, so the contract stays and the graceful defect is the hidden reason, the 60
s wait and the pid file. `mtu_enable=1` with large and scatter mbufs was measured to start, reload, upgrade and pass
md5 downloads, so the lib is unchanged; end-to-end jumbo TCP cannot be checked behind the cloud path's MSS clamp.
Design review PASS (0 MUST, 6 SHOULD, all applied; a pipe was chosen over the planned shm{sem,pid}). Code review
CR-M1 PASS (0 MUST, 3 SHOULD: an ALERT on a failed read, the `(void) write` under FORTIFY, the same stale pid file on
the worker-0 attach exit), applied and rebuilt clean as M2, CR-M2 PASS (0 MUST, 0 SHOULD). Every reviewer was a fresh
instance. Residuals are listed in the solution design §10.8.
