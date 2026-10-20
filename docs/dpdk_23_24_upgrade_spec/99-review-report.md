# 99 — Gate-keeper Review Report

> Document version: **v0.2 (2026-06-09 14:55 UTC+8) — revised after user feedback**
> Reviewer: gate-keeper (independent reviewer role)
> Review target: the 6 spec documents in this directory `dpdk_23_24_upgrade_spec/` (plan + 00 + 01 + 02 + 04 + 06)
> Review criteria: the 4-dimension criteria of plan.md §2.6 (consistency / completeness / risk coverage / executability)
>
> **v0.2 revision log** (2026-06-09 14:55):
> - user feedback at 2026-06-09 14:50 on the KNI truth: F-Stack's `FF_KNI` is unrelated to DPDK librte_kni, it is a ring + virtio_user self-implementation
> - patch-scout's first report missed commit `29c7d5835` ("Remove redundant dpdk files", 310 files / -43195 lines) — the `diff -rq | head -25` truncation failed to capture the redundant-files deletion list
> - revision locations: 00 §5.1 (patch count 3→4) / 01 §6 R-D2 (raised P1 → lowered N/A) / 01 §7.2 DP-B2 (re-closed) / 02 §2 + §2.4 + §2.5 + §2.6 + §3.6 (KNI truth rewritten) / 04 §M2 + §M3 + §8.2 (patch count 3→4, including the new §4.2.0 for re-applying 29c7d5835)
> - this review conclusion: **still PASS** (the revision is more accurate than v0.1); the Must-Fix-1 (KNI decision) listed in v0.1 **is cancelled**

---

## 0. Review Conclusion (**final v0.2**)

✅ **PASS — 6 specs pass the gate-keeper review, no P0/P1 blockers; after the v0.2 revision there are no pending Must-Fix-x items**

| Dimension | Score v0.1 | Score v0.2 | Note |
|---|---|---|---|
| Consistency | A | **A** | the revised patch count (3→4) is consistent across all 6 documents |
| Completeness | A | **A+** | v0.2 completes the 4th patch + KNI truth; zero drift between spec and reality |
| Risk coverage | A | **A+** | R-D2 lowered from P1 to N/A (no risk); new risk point M3-R3 (24.11.6 redundant-file renames) added to 04 §4.4 |
| Executability | A- | **A** | M3 step-by-step commands updated to 4 patches; §4.2.0 adds the explicit 29c7d5835 re-application strategy |

**Total: 6 specs + plan + this review report = 7 documents** (plan §0.2 requires 7).

---

## 1. v0.2 Key Revision Points (after user feedback)

### 1.1 The KNI Truth (**major correction**)

| v0.1 misjudgment | v0.2 measured truth |
|---|---|
| 24.11.6 upstream KNI fully removed → R-D2 raised to P1 | **F-Stack's `FF_KNI` is unrelated to DPDK librte_kni**; the `lib/Makefile:34` comment is explicit: "No DPDK KNI support on FreeBSD" + "Enable KNI, via virtio only, no longer support rte_kni.ko"; `ff_dpdk_kni.c` self-implements with `rte_ring + virtio_user` |
| Must-Fix-1: KNI A/B decision needed before M2 starts | **cancelled** — KNI is a zero-risk item in the upgrade |
| recommended Plan A (FF_KNI=0) or B (keep the KNI subtree) | **both wrong**; the user's actual intent: keep FF_KNI=1 + dpdk/ contains only the single igb_uio kernel module (naturally achieved: 24.11.6 upstream never had KNI, plus the 29c7d5835 re-application keeps it deleted) |

### 1.2 Supplementary Identification of the 4th Patch (29c7d5835)

patch-scout's first report judged Q1+Q3 as "empty difference set, nothing missed" based on the truncated output of `diff -rq | head -25`. The full diff without head truncation + `git log --diff-filter=D` revealed:

| commit | Type | patch-scout v1 miss reason |
|---|---|---|
| `29c7d5835 Remove redundant dpdk files` (2025-01-10) | DELETE 310 files / -43195 lines | head -25 didn't show it + diff -rq only shows Common subdirectories (does not descend into subdirectories) |

**The actual F-Stack patch list = 4** (chronological):
1. `29c7d5835` (2025-01-10) DELETE redundant
2. `5f3768c63` (2025-10-31) ADD igb_uio + freebsd rte_os.h
3. `62f1c34df` (2026-01-16) ADD rte_timer_meta_init
4. `92718178b` (2026-03-18) MODIFY eal.c PRIMARY guard

Per plan §4.4 + DP-A8, the 4 patches are still merged into one `port:` commit.

### 1.3 The igb_uio Timeline Paradox Clarified

| commit | Date | igb_uio operation |
|---|---|---|
| 29c7d5835 | 2025-01-10 | **deletes the old** igb_uio (5 files / -874 lines) |
| 5f3768c63 | 2025-10-31 | **re-adds the new** igb_uio (with kernel 6.x compatibility + RHEL kernel < 3.18 fallback) |

→ The two serve different purposes; the new version supports the new host kernels during the FreeBSD 15.0 upgrade period; fully consistent with the user's expectation that "dpdk/ keeps only the single igb_uio kernel module".

---

## 2. Consistency Review (A) — v0.2

### 2.1 Cross-Document Consistency Cross-Check (after the v0.2 revision)

| Item | v0.1 status | v0.2 status |
|---|---|---|
| total patch count | all 6 specs marked "3 patches" | all 6 specs synced to "4 patches" (00 §5.1 / 01 §6 / 02 §2.5 / 04 §M2 §M3 §8.2 / 99 v0.2) |
| KNI risk level | R-D2 raised to P1 | R-D2 lowered to N/A (see 02 §3.6 + 01 §6) |
| Must-Fix-1 | listed (KNI decision) | **cancelled** (see this section) |
| commit message template | 3-patch list | 4-patch list + KNI clarification |

### 2.2 Consistency Minor Issues

None (the v0.2 revision process exists to eliminate the internal inconsistency of v0.1 — correcting the "24.11.6 fully removes KNI" narrative to the true situation).

---

## 3. Risk Coverage Review (A+) — v0.2

### 3.1 R-D1~D12 v0.2 Status Update

| ID | v0.1 level | v0.2 level | change reason |
|---|---|---|---|
| **R-D2** KNI removal | P1 (raised in v0.1) | **N/A** | F-Stack does not depend on librte_kni (confirmed by user-feedback measurement) |
| new **M3-R2** 29c7d5835 KNI/igb_uio parts automatically N/A | — | added (04 §4.4) | some hunks automatically N/A when re-applying the 4 patches |
| new **M3-R3** 24.11.6 redundant-file renames | — | added (04 §4.4) | 24 upstream may rename redundant files; partially failed hunks can be fixed manually |

The other R-D1 / R-D3~D12 statuses unchanged, all with detection + mitigation in place.

### 3.2 Risk Escalation Alert (**revoked**)

The v0.1 alert "R-D2 (KNI fully removed in 24.11.6) raised from P2 to P1" is **revoked**. F-Stack's self-implemented KNI is unaffected.

---

## 4. Executability Review (A) — v0.2

| Phase | v0.1 score | v0.2 score | revision points |
|---|---|---|---|
| M3 patch re-application | A- | **A** | 04 §4.2.0 adds the 29c7d5835 re-application step; the §4.3 AC table adds M3-AC4 (KNI subtree verification) + M3-AC5 (igb_uio subtree verification) |

---

## 5. Nine Measurements Closed Directly in the Spec Phase (v0.2 adds 3)

| Measurement | Command | Conclusion | Revision Location |
|---|---|---|---|
| **new v0.2-1** does F-Stack KNI depend on librte_kni | `head lib/ff_dpdk_kni.c + grep rte_kni lib/ff_dpdk_kni.c + nm libfstack.a \| grep rte_kni` | **0 dependency**; ring + virtio_user self-implementation | 02 §3.6 |
| **new v0.2-2** the real patch count of F-Stack inside dpdk/ | `diff -rq + git log --diff-filter=D` | **4** (patch-scout v1 missed 29c7d5835) | 02 §2.4 + §2.5 |
| **new v0.2-3** the 29c7d5835 deletion list | `git show 29c7d5835 --stat` | 310 files / -43195 lines | 02 §2.4 |
| DP-B2 KNI (done in v0.1 but with a wrong conclusion) | `ls dpdk-stable-24.11.6/lib/kni/ kernel/linux/kni/` | both absent; but unrelated to F-Stack's KNI | 02 §3.6 rewritten |
| DP-B3 igb_uio | `ls dpdk-stable-24.11.6/kernel/linux/` | only uapi (no igb_uio) | 02 §3.7 |
| DP-B5 meson | `head -20 dpdk-stable-{23,24}.11.{5,6}/meson.build` | 23 ≥ 0.53.2 / 24 ≥ 0.57 | 02 §3.8 |
| R-D11 rte_ip.h | `grep struct rte_ipv{4,6}_hdr f-stack/lib/` | 10 uses + 3 includes | 02 §3.7 |
| total spec lines | `wc -l` | v0.1 = 1916; v0.2 roughly +200 (4th patch + KNI truth supplement) | — |
| compliance self-check | grep `rm \|kill \|chmod ` 0 direct calls | ✅ | — |

---

## 6. Must-Fix / Optional Items (**v0.2 rewritten**)

### 6.1 Must-Fix (must be handled before M2 starts)

| ID | Description | v0.1 → v0.2 change |
|---|---|---|
| ~~Must-Fix-1 KNI decision~~ | ~~FF_KNI=0 or keep the KNI subtree~~ | **cancelled** — the user has directly given the plan: keep FF_KNI=1 + dpdk/ contains only igb_uio. Spec 02 §3.6 + 04 §4.2.0 already implement it |

**v0.2 must-fix count: 0**

### 6.2 Optional (non-blocking in the spec phase)

| ID | Description | Timing |
|---|---|---|
| Nice-1 | the 92718178b rebase pseudo-diff hint for 04 §M3.4 R-M3-1 | before M3 starts |
| Nice-2 | fill the actual data of the 06 §11 performance baseline comparison table | after M5 completes |
| Nice-3 | M4 compile-time verification of R-D11 (whether the rte_ip.h stub auto-forwards rte_ip4/rte_ip6.h) | at M4 compile time |
| **new Nice-4** | record the N/A / apply / fail status of each hunk when re-applying 29c7d5835 in M3 §4.2.0 | at M3 execution time |
| **new Nice-5** | whether argparse / ptr_compress enter the 29c7d5835-equivalent deletion list (conservative = keep / aggressive = also delete) | decided by user/leader before M3 starts |

---

## 7. Phase 1 Wrap-Up Suggestion (**v0.2 updated**)

| Action | Timing |
|---|---|
| **new** land the v0.2 revision commit (on top of d25ba1e26) | immediately |
| commit message subject | `docs(spec): revise dpdk-23-24 spec — 4 patches via user KNI feedback (3->4)` |
| commit message body | list the 4 spec revision summaries + KNI truth + 29c7d5835 supplementary identification + R-D2 lowered to N/A |
| sync backup to `dpdk-stable-24.11.6/f-stack-lib/test-configs/dpdk-23-24-upgrade/` | together with the commit |
| **no push** | wait for user decision |

---

## 8. Document Meta-Information

- **Status v0.1**: review passed (based on the v1 patch-scout report)
- **Status v0.2**: revised based on user feedback at 2026-06-09 14:50, review still passes (and is more accurate)
- **PASS sign-off v0.2**: gate-keeper (independent reviewer)
- **Next**: the leader immediately lands the v0.2 revision commit, waits for the user decision before starting Phase 2 (M1 baseline capture)
