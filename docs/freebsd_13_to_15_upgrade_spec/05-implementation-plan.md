# 05 — Detailed Implementation Plan

> Chinese version: ./zh_cn/05-implementation-plan.md
>
> Series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-26)
> Input: 57 T-* tasks from `04-diff-and-port-strategy.md`
> Output: milestones + tasks + SOP + rollback that downstream AI agents can pick up directly

---

## 1. Overall Cadence and Decision Points

### 1.1 Milestone overview

```
M1 → M2 → M3 → M4 → M5 → GATE-Acceptance
infra  kern  net   edge  tools+ff  acceptance
small  big   big   med   big
```

### 1.2 Five key decision points (final)

| DP | Decision | Outcome | Affected milestone |
|---|---|---|---|
| DP-1 | Whether to delete `f-stack/freebsd/mips/` | **Delete** | M1 |
| DP-2 | Whether to introduce sys/netlink/ | **Do not** | All (C-1) |
| DP-3 | Sync strategy | **Progressive (M1→M5)** | All |
| DP-4 | When to upgrade ff_*.c | **In lockstep with freebsd/** (not separately at end of M5) | M2/M3/M4 each phase synced |
| DP-5 | tools/ upgrade | **Independent milestone M5** | M5 |

---

## 2. Milestone Detailed Definitions

### 2.1 M1 — Infrastructure + headers + mips cleanup

**Goal**: stand up the new 15.0 baseline + handle low-coupling subdirs + clean up mips.

**Inputs**:
- `freebsd-src-releng-15.0/f-stack-lib/` (Phase 1.4 artifact)
- Current state of `f-stack/freebsd/sys/` `f-stack/freebsd/libkern/` `f-stack/freebsd/opencrypto/` `f-stack/freebsd/crypto/`

**Tasks**:

| Task ID | Detail | # files | Priority |
|---|---|---|---|
| T-cleanup-01 | Delete `f-stack/freebsd/mips/`; clean mips conditions in Makefile / mk | 1 dir | P0 |
| T-sys-01 | `sys/systm.h`: redo kpilite.h masking + critical_enter/exit stub | 1 | P0 |
| T-sys-02 | `sys/refcount.h`: redo refcount_acquire_if_not_zero CAS self-check | 1 | P0 |
| T-sys-03 | `sys/callout.h` + `sys/_callout.h`: redo simplification | 2 | P1 |
| T-libkern-01 | libkern/ full cp -a from 15.0 upstream; assess whether existing adaptations are still needed | ~70 | P1 |
| T-crypto-01 | crypto/ top-level cp -a from 15.0; blowfish removed (already removed upstream); the new chacha20_poly1305.c/.h and curve25519.c/.h are kept but not introduced | ~22 | P2 |
| T-opencrypto-01 | opencrypto/ full cp -a from 15.0; assess xform_* changes | ~23 | P1 |
| T-vm-01 | vm/ full cp -a from 15.0; assess whether uma_core changes touch F-Stack | ~26 | P1 |
| T-arch-01 | amd64/x86 headers follow 15.0; assess F-Stack impact | ~20 | P2 |
| T-arch-02 | arm64 headers follow 15.0; handle new cmn600/ptrauth (F-Stack does not use, stub out) | ~7 NEW | P2 |
| T-misc-01 | netipsec/ netgraph/ netinet/libalias/ etc. cp -a follow upgrade | ~40 | P2 |

**M1 exit criteria**:
- `find f-stack/freebsd/mips -type f` is empty
- All `*.c *.h` in libkern/ opencrypto/ crypto/ vm/ amd64/ x86/ arm64/ are byte-aligned with 15.0 upstream (or aligned with the 02 adaptation patterns)
- M1 does not yet touch libff compilation; only the sys/ subtree is updated
- Verify via `diff -rq` that all files in M1 scope are **either from 15.0 or have a matching tag in 02 adaptation patterns**

**Estimate**: 1-2 weeks (including 1 reviewer mid-review)

### 2.2 M2 — kern core (38 KERN_SRCS)

**Goal**: complete the upgrade of the heaviest-affected kern/ subdir + the ff_* glue files affected by kern changes.

**Tasks**:

| Task ID | File | Priority | Note |
|---|---|---|---|
| T-kern-01 | `kern_descrip.c` | P0 | refcount API adaptation |
| T-kern-02 | `kern_event.c` | P0 | redo kqueue stub |
| T-kern-03 | `kern_linker.c` | P1 | redo "va_size 0 = success" |
| **T-kern-04** | **`kern_mbuf.c`** | **P0** | **adapt to new m_ext fields (R-003)** |
| T-kern-05 | `kern_sysctl.c` | P1 | redo __sysctl masking |
| T-kern-06 | `link_elf.c` | P1 | redo elf stub |
| **T-kern-07** | **`subr_epoch.c`** | **P0** | **assess epoch → SMR (R-012)** |
| T-kern-08 | `subr_param.c` | P2 | mask ticks wrap |
| T-kern-09 | `subr_taskqueue.c` | P1 | redo taskqueue stub |
| T-kern-10 | `sys_generic.c` | P1 | redo kern_sigprocmask masking; sync ff_syscall_wrapper.c |
| T-kern-11 | `sys_socket.c` | P1 | redo soo_* masking; assess KTLS stub |
| **T-kern-12** | **`uipc_mbuf.c`** | **P0** | **FSTACK_ZC_SEND adaptation + new m_ext layout** |
| T-kern-13 | `uipc_sockbuf.c` | P1 | redo sb_aio masking |
| **T-kern-14** | **`uipc_socket.c`** | **P0** | **adapt pr_usrreqs merge (R-011)** |
| T-kern-15 | `uipc_syscalls.c` | P1 | redo sendit/recvit external |
| T-kern-misc | The other 23 KERN_SRCS (unmodified) cp -a from 15.0 | P3 | direct copy |
| **T-ff-04** | **`ff_subr_epoch.c`** | **P0** | **co-work with T-kern-07** |
| T-ff-05 | `ff_syscall_wrapper.c` | P1 | co-work with T-kern-15 |
| T-ff-06 | `ff_kern_intr.c` | P1 | ithd subsystem tweaks |
| T-ff-misc | Remaining `ff_kern_*` wrappers (condvar/environment/subr/synch/timeout) | P2 | API stable; small change |

**M2 exit criteria**:
- All 38 KERN_SRCS landed on 15.0 + F-Stack adaptation patterns
- ff_subr_epoch.c / ff_kern_*.c all upgraded
- `make` phase: **first attempt to build libff.a after M2** (allowed to fail before M3 finishes due to net/ netinet/ not yet upgraded; the kern/ portion should already compile cleanly)

**Estimate**: 2-3 weeks

### 2.3 M3 — Network stack (net + netinet + netinet6)

**Goal**: complete the most core network-stack upgrade for F-Stack; resolve the three P0 KPI breakages: if_t / inpcb SMR / rib-nexthop.

**Tasks**:

| Task ID | File | Priority | Note |
|---|---|---|---|
| **T-net-01** | **`net/if.c`** | **P0** | **if_t opaque-ization (R-013)** |
| **T-net-02** | **`net/if_var.h`** | **P0** | **co-work with T-net-01** |
| T-net-03 | `net/if_ethersubr.c` | P1 | redo BPF tap masking |
| T-net-04 | `net/netisr.c` | P1 | redo ff_veth scheduling |
| **T-net-05** | **`net/route.c`** | **P0** | **rib/nexthop adaptation** |
| T-net-misc | The other 17 NET_SRCS (unmodified) cp -a | P3 | direct copy |
| **T-netinet-01** | **`tcp_input.c`** | **P0** | **redo RSS + SMR adaptation** |
| T-netinet-02 | `tcp_output.c` | P1 | |
| T-netinet-03 | `tcp_subr.c` | P1 | |
| **T-netinet-04** | **`tcp_var.h`** | **P0** | **tcpcb field trimming + RACK fields** |
| T-netinet-05 | `tcp_stacks/rack.c` | P1 | redo module-name → fstack |
| T-netinet-06 | `tcp_stacks/bbr.c` | P1 | same as above |
| **T-netinet-07** | **`in_pcb.c`** | **P0** | **RSS port range + SMR adaptation** |
| T-netinet-08 | `tcp_usrreq.c` | P1 | adapt protosw merge |
| T-netinet-09 | `udp_usrreq.c` | P1 | same as above |
| T-netinet-10 | `raw_ip.c` | P1 | same as above |
| T-netinet-misc | The other 12 NETINET_SRCS cp -a | P3 | direct copy |
| T-netinet6-01 | netinet6/ full cp -a + adaptation assessment | P2 | rare changes |
| **T-ff-01** | **`ff_glue.c`** | **P0** | **pr_usrreqs → protosw direct call** |
| **T-ff-02** | **`ff_veth.c`** | **P0** | **if_t accessors + new if_alloc signature** |
| **T-ff-03** | **`ff_route.c`** | **P0** | **rib/nexthop API** |

**M3 exit criteria**:
- Full network-stack upgrade
- `libff.a` **builds cleanly** at end of M3
- Single-unit boot smoke: the `fstack` main program at least gets to the completion of `mi_startup()`

**Estimate**: 3-4 weeks (heaviest milestone)

### 2.4 M4 — Edge subsystems (netipsec / netgraph / netpfil / others)

**Goal**: handle optional-subsystem upgrades; ensure 0 errors across the entire compile matrix.

**Tasks**:

| Task ID | Detail | Priority |
|---|---|---|
| T-netipsec-01 | netipsec/ full cp -a + assessment (new ipsec_offload.c) | P1 |
| T-netgraph-01 | netgraph/ full cp -a + redo ng_socket H-2 adaptation | P1 |
| T-netpfil-01 | netpfil/ipfw/ full cp -a + assess ip_fw_compat.c (new) | P1 |
| T-netpfil-02 | netpfil/pf/ (if F-Stack enables it) follow upgrade | P2 |
| T-bsm-01 | bsm/ cp -a (very few changes) | P3 |
| T-ddb-01 | Whether ddb/ is needed (F-Stack typically does not use) | P3 |

**M4 exit criteria**:
- All optional subsystems upgraded
- `libff.a` builds cleanly across all supported KNOB combinations (IPSEC / IPFW / NETGRAPH)
- No new build warnings vs the 13.0 baseline (or any new ones recorded in 99)

**Estimate**: 1-2 weeks

### 2.5 M5 — 12 tools + ff_compat + acceptance

**Goal**: complete user-space tool upgrade + IPC bridge + full-stack acceptance test.

**Tasks**:

| Task ID | Detail | Priority | Workload |
|---|---|---|---|
| T-tools-arp | arp/ redo H-6/H-7 (based on 15.0 usr.sbin/arp) | P1 | medium |
| **T-tools-ifconfig** | **ifconfig/ redo (impacted by libifconfig abstraction changes)** | **P0** | **large** |
| T-tools-ipfw | ipfw/ redo | P1 | medium |
| T-tools-libmemstat | libmemstat/ redo | P2 | small |
| T-tools-libnetgraph | libnetgraph/ redo | P1 | medium |
| T-tools-libutil | libutil/ assessment (very few changes) | P3 | small |
| T-tools-libxo | libxo/ assessment | P3 | small |
| T-tools-ndp | ndp/ redo | P1 | medium |
| **T-tools-netstat** | **netstat/ redo (largest sysctl takeover)** | **P0** | **large** |
| T-tools-ngctl | ngctl/ redo | P1 | medium |
| **T-tools-route** | **route/ redo (RTM_* channel + rib/nexthop user-space API)** | **P0** | **large** |
| T-tools-sysctl | sysctl/ redo | P1 | medium |
| T-compat-01 | `tools/compat/` (ff_ipc.c/h) follows ff_* upgrade; preserve IPC protocol compatibility | P1 | medium |
| T-acceptance | Run the 9 acceptance cases from 06 | — | — |
| T-perf | Run 06 §5 performance baseline | — | — |

**M5 exit criteria**:
- All 12 tool binaries can be built
- All 9 cases in 06 §3 pass
- 06 §5 performance regression ≤ 5%
- libff ABI review shows no unintended breakage

**Estimate**: 3-4 weeks

---

## 3. Task Counts and Schedule

| Milestone | T-* tasks | Estimated weeks | # P0 |
|---|---|---|---|
| M1 | 11 | 1-2 | 2 |
| M2 | 21 | 2-3 | 4 |
| M3 | 22 | 3-4 | **9** |
| M4 | 6 | 1-2 | 0 |
| M5 | 15 | 3-4 | 3 |
| **Total** | **75 tasks** | **10-15 weeks** | **18 P0** |

> The 75 total is slightly higher than the 57 in 04 §9, because 05 adds "direct-copy of unmodified files" batch tasks under M1/M2/M3/M4 (cp -a class; small workload but must be recorded). **This 75 tasks / 18 P0 table is the sole global ledger** (response to audit §6.2-2, closed 2026-05-28). The 57 / 24 in 04 §9 are subsets of "narrow port / port decision points"; the 19 in 99 §4.2 is an accessory "by-risk-attribution" view; see `04-diff-and-port-strategy.md §9.1` and `99-review-report.md §12.8`.

---

## 4. Per-P0-Task Execution SOP (5-step + Gate)

> This SOP can be directly consumed by the `c-precision-surgery` skill.

```
[Step 1] Prepare 3 baselines
  - baseline-15 = freebsd-src-releng-15.0/sys/<subdir>/<file>
  - baseline-13 = freebsd-src-releng-13.0/sys/<subdir>/<file>
  - fstack-13   = f-stack/freebsd/<subdir>/<file>

[Step 2] Compute the F-Stack patch
  - delta-13 = diff baseline-13 vs fstack-13
  - Classify delta-13 with the 9 adaptation tags from 02

[Step 3] Re-apply delta-13 on baseline-15
  - Key review:
    * Whether the symbols touched by delta-13 still exist in 15.0
    * Whether new 15.0 code requires the same kind of adaptation
    * Interface signature changes (R-011/012/013/003/rib) must be explicitly adapted
  - Output: fstack-15-draft

[Step 4] Single-file Gate
  - Compile check: try single-file build (if the project allows it)
  - lint: read_lints
  - grep preserved extensions: FSTACK_ZC_SEND / ff_ipc must not be lost

[Step 5] Land + record
  - mv fstack-15-draft → f-stack/freebsd/<subdir>/<file>
  - Mark ✓ in the task tracking table of 99-review-report.md
  - Submit review (in batches of 5 P0 tasks)
```

---

## 5. Resource and Staffing

| Role | Headcount | Main task |
|---|---|---|
| Tech Lead | 1 | overall ownership, P0 task review, final decision-point arbitration |
| Senior Engineer × 2 | 2 | M2 / M3 core port tasks (kern + net + netinet) |
| Engineer × 1 | 1 | M5 tools work (highest parallelism) |
| Reviewer / QA | 1 | 06 acceptance cases + maintain 99 review report |
| AI Agent (c-precision-surgery) | continuous assist | per-file 5-step SOP execution |

> AI-agent-friendly: per-T-* single-file adaptation (5-step SOP is clear, context is bounded).
> Not AI-friendly: cross-module design decisions (e.g. SMR takeover area / libff ABI change assessment).

---

## 6. Rollback (NFR-4)

### 6.1 Dual workspaces & dual backups

```
/data/workspace/f-stack/                  ← upgrade main workspace
/data/workspace/f-stack-13.0-baseline/    ← cp -a backup taken before upgrade starts (user op, not in this Spec series)
```

Mandatory action before upgrade starts:
```bash
cp -a /data/workspace/f-stack /data/workspace/f-stack-13.0-baseline
```

### 6.2 Per-milestone rollback

Tag-style backup at each milestone completion:
```bash
cp -a /data/workspace/f-stack /data/workspace/f-stack-M<N>-done
```

Any milestone failure can fall back to the previous `f-stack-M<N-1>-done`.

### 6.3 Per-task rollback

Each P0 task backs up the single file before Step 5 land:
```bash
cp -a <file> <file>.bak.before-T-<id>
```

> Note: this plan does not touch Git. All backups are filesystem cp.

---

## 7. Risk Monitoring and Escalation Path

### 7.1 Gate failure handling

| Phase | Gate failure | Disposition |
|---|---|---|
| End of M1 | Headers cannot align | Spot review; do not block M2 start (unless it impacts kern compilation) |
| End of M2 | KERN_SRCS build errors | Tech Lead intervenes; consider expanding stub coverage |
| End of M3 | libff.a does not build | **Most severe**: pause M4 start; the 3 large P0 KPI tasks (T-net-01 / T-netinet-01 / T-net-05) are rolled back and redone one by one |
| End of M4 | Optional subsystem fails | Disable the corresponding KNOB; record as R-006-class risk |
| End of M5 | Acceptance case fails | Roll back to mid-M3 or mid-M5 depending on case severity |

### 7.2 Time-box

- Per-P0-task time-box: **2 days**; Tech Lead intervenes if exceeded
- Per-milestone hard cap: M2 / M3 each 4 weeks; M5 4 weeks; total ≤ 16 weeks

---

## 8. Integration with F-Stack Existing build/CI

| Integration point | Action |
|---|---|
| `f-stack/Makefile` | Verify mips-related conditions are removed |
| `f-stack/lib/Makefile` | Track whether `KERN_SRCS+=` etc. need adjustment due to 15.0 NEW/DEL files |
| `f-stack/tools/<tool>/Makefile` | Sync-check during M5 redo of H-7 |
| F-Stack CI (if any) | Run full acceptance suite at end of M5 |

---

## 9. Things Out of Scope (re-stating C-1)

| Item | Note |
|---|---|
| netlink port | Explicitly excluded by C-1; if needed, open a new workstream |
| Post-quantum crypto ML-KEM introduction | Same as above |
| Exposing inotify / timerfd / kqueuex etc. to ff_syscall_wrapper.c | Same as above |
| DPDK upgrade | Same as above; if 15.0 needs new DPDK, open a new workstream |
| Git commit | C-4 |
| Performance benchmark rebuild | Only "regression ≤ 5%" comparison; no new baseline |

---

## 10. Hand-off to 06 Acceptance

| Artifact from this section | 06 chapter |
|---|---|
| M2-M5 exit criteria | `06 §2` compile matrix |
| FR-6 9 acceptance cases | `06 §3` case list |
| NFR-1 5% regression cap | `06 §5` performance baseline |
| 75 T-* task tracking | implementation progress table in `99-review-report.md` |

---

## 11. Pre-Implementation Checklist

- [ ] Backup the original f-stack workspace
- [ ] Verify host GCC ≥ 10 or clang ≥ 12
- [ ] Verify the DPDK LTS version is compatible with 15.0 (assumption A-3)
- [ ] Verify F-Stack existing build is 0-error on 13.0 baseline (assumption A-2)
- [ ] Test environment for the 9 acceptance cases in 06 is ready
- [ ] Tech Lead reviews execution order and time-box for the 18 P0 tasks
- [ ] Reviewer confirms the 99-report framework is in place (although 99 is a Spec-phase artifact, the implementation phase keeps filling it with progress)
- [ ] AI Agent context: 04 + 05 + 02 + 03 are the standard input for downstream AI agents to pick up tasks
