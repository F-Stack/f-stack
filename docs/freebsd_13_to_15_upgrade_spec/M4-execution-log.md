# M4 — Execution Log

> Chinese version: ./zh_cn/M4-execution-log.md (full process narrative)
>
> Doc series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> Document version: v0.1 (2026-05-29)
> Maintainer: Leader (m4-leader, in main dialogue)
> Linked: spec `05-implementation-plan.md` §2.4 (M4 task list); `06-test-and-acceptance-spec.md` §2.2 G-M4; `99-review-report.md` §6.4 / §12.17
>
> NOTE: This English version is a structural condensation. All section headings, key data tables, decision-point IDs (DP-M4-1..3), task IDs and final task statuses are preserved verbatim from the Chinese master.

---

## 0. Kickoff Metadata

| Item | Detail |
|---|---|
| M4 kickoff | 2026-05-29 |
| Scope | 5 edge subsystems (bsm/ddb/netgraph/netpfil/netipsec) + M3 deferred T-ff-02 ff_veth.c R-013 + T-ff-03 ff_route.c R-004 + 11 lib/ff_*.c 14.0+ ABI fix |
| Predecessor | M3 (libfstack.a 5.2M / 192 .o; 20 ✅ + 2 deferred) |
| Spec baseline | v0.3 + 99 §12.16 |
| M4 backup | `/data/workspace/f-stack-M4-done/` (32,585 files) |
| Tier split | Tier 1 (P0 lib/ff_*.c real fix) → Tier 2 (P1 edge-subsys batch) → Tier 3 (P3 closure) → Tier 4 (strict force rebuild + G-M4) |

---

## 1. Agent Team Topology (5 roles, same)

---

## 2. Key Decisions (DP-M4-1..3)

| DP | Detail | Decision |
|---|---|---|
| DP-M4-1 | M4 order | **C: risk-inversion** — P0 ff_veth/ff_route first → P1 edge subsystems → P3 closure → Gate |
| DP-M4-2 | ff_veth.c R-013 strategy | **A: full rewrite to if_get*/if_set* accessors** (rather than compat-macro layer) |
| DP-M4-3 | G-M4 acceptance strictness | **A: STRICT** — `make clean && make` full rebuild + libfstack.a strict link mandatory |

---

## 3. Task Progress Timeline

22 tasks total: 5 cp-only + 11 lib real fix + 1 P0 verify + 5 edge cp. (Full per-task table in 99 §6.4.)

| Tier | Range | Result |
|---|---|---|
| Tier 1.A | ff_veth.c R-013 | ✅ 28 ifp->if_xxx → if_get*/if_set* accessors; one-shot pass 0 errors / 0 warnings (DP-M4-2=A) |
| Tier 1.B | ff_route.c R-004 | ✅ 5-class 14.0+ ABI fix + `#include <net/if_private.h>` makes struct ifnet fully visible; 0 errors |
| Tier 1.C | 11 lib/ff_*.c chain fix | ✅ ff_freebsd_init / ff_glue / ff_init_main / ff_kern_environment / ff_kern_timeout / ff_lock / ff_syscall_wrapper / ff_vfs_ops / ff_api.h / ff_memory.h |
| Tier 2 | 5 edge subsystems | ✅ bsm/ddb/netgraph/netpfil cp -af 15.0 vendor → all 0 differ; netipsec verify-only (already 0 differ) |
| Tier 3+4 | G-M4 strict rebuild | ✅ DP-M4-3=A `make clean && make` one-shot pass; libfstack.a 5.2M / 192 .o / 0 errors / 0 lints |

---

## 4. Disruptive Findings (exposed by DP-M4-3=A strict rebuild)

1. **M3-end .o cache illusion**: ff_veth.o / ff_route.o were stale 5/28 cached objects; M3 `make` passed but the real state had 30+ 14.0+ ABI breakages. DP-M4-3=A strict policy core value: forces past .o cache illusion.
2. **spec 03 §3 if_alloc description wrong**: 15.0 still `if_alloc(u_char type)` — no change. R-013 real landing point is struct ifnet opaque, not signature.
3. **lib/ff_route.c does NOT need full if_t rewrite**: `#include <net/if_private.h>` makes struct ifnet fully visible; workload reduced an order of magnitude.
4. **rib_lookup_info fully removed in 14.0+** (not "signature change" as spec 03 §3.8 said).
5. **Edge subsystem 5 all 0 differ**: under FF_NETGRAPH/FF_IPFW/FF_IPSEC default-disabled, cp -af 15.0 vendor suffices.

---

## 5. Pushback Events / Gate Decision Records

### 5.1 Pushback events

(See zh_cn/ master.)

### 5.2 Gate fail-mode root cause

N/A — G-M4 STRICT one-shot pass.

---

## 6. 8-class 14.0+ lib stub ABI changes (deviation log)

(a) bool-ification (prison_*); (b) const void * (mtx_sysinit / tunable_*_init); (c) void * (kmem_*); (d) sockaddr calling convention (kern_accept etc.); (e) field deletion (sysentvec.sv_transtrap, rtentry.rt_expire); (f) macro deletion (CALLOUT_LOCAL_ALLOC / CS_EXECUTING / SI_SUB_DONE / RTF_RNH_LOCKED); (g) signature change (fdinit / _callout_stop_safe / NDFREE→NDFREE_PNBUF); (h) cred const (groupmember).

---

## 7. M4 Closure

### 7.1 Task completion summary

22 tasks ✅. G-M4 STRICT one-shot pass.

### 7.2 M4 deliverables

- libfstack.a 5.2M / 192 .o / 0 errors / 0 lints (DP-M4-3=A force-rebuild verified)
- ff_veth.c / ff_route.c real 14.0+ adaptation done
- 5 edge subsystems aligned to 15.0 vendor (0 differ)
- 11 lib/ff_*.c 14.0+ chain fix
- M4-done snapshot 32,585 files
- 99 §6.4 M4-row updates; §12.17 deviation revision (8 categories)

### 7.3 M5 input list (M4 → M5 hand-off) — ✅ M5 already started (2026-05-29 17:28)

Pre-read for M5:
- §4 disruptive findings (5 measured items)
- §5.1.3 11-file ABI change list (reuse in M5 perf baseline / compiler optimization)
- 99 §6 M4-row ✅
- 99 §12.17 DP-M4 8-class ABI deviation revision

**M5 scope recommendation**:
- **M5 P0**: (1) spec 06 9 cases runtime; (2) compile matrix (GCC 12+ / Clang 14+ / aarch64 / arm64); (3) RSS / inpcb SMR runtime verification (M3 deferred)
- **M5 P1**: (1) LVS_TCPOPT_TOA adaptation re-locating on 15.0 (M3 deferred); (2) Performance baseline vs 13.0 / Linux benchmark; (3) FF_IPFW / FF_NETGRAPH / FF_IPSEC / FF_USE_PAGE_ARRAY optional-feature build verification
- **M5 P2**: deeper compiler optimization (re-enable some -Werror) + cross-platform (aarch64 / arm64) regression + stale-.o-cache prevention (CI must `make clean`)

**M5 kickoff confirmation**:
- M5 plan ID: freebsd_13_to_15_upgrade_M5 (plan status=building)
- M5 kickoff backup: `/data/workspace/f-stack-M5-start/` 32,797 files
- M5 decision points: DP-M5-1=B / DP-M5-2=B / DP-M5-3=B (user accepted defaults)
- M5 execution log: `M5-execution-log.md` created

### 7.4 Closing

- M4 plan execution status: **DONE & READY-TO-COMMIT**
- 5-role team kept (DP-M2-3=A)
- Decision-point responses across the run: DP-M4-1 (order C risk-inversion) / DP-M4-2 (accessor strategy A full rewrite) / DP-M4-3 (acceptance strict full rebuild) / DP-10-reinforce (user reaffirmed rm_tmp_file.sh)
- M5 onward continues 5-role logical split + harness+spec framework + DP-10 rule + spec 06 full-acceptance path
- M4-end git diff range: freebsd/{bsm,ddb,netgraph,netpfil} 162 files vendor cp + lib/ 12 files 14.0+ ABI fix + docs/zh_cn + 99 review revision
