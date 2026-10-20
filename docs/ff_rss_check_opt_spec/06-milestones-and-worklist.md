# 06 Milestones and Worklist — ff_rss_check Three Optimizations (Subsequent Coding Phase)

> Scope: this document plans the executable milestones (R-A/R-B/R-C) for the **subsequent coding/testing phase**, distinct from the spec phase (M0-M5).
> Each milestone lists "Files:Functions to change", "Test points", "Risks and rollback", and "bounce gate". Landing points are based on 04/05, facts are based on 02.
> Mandatory conventions: execute based on facts, not speculation; code is the source of truth; rm/kill/chmod go through `/data/workspace/*.sh`; keep lib comments minimal; do not commit local test values in config.ini; on gate failure, bounce back to the previous step (per-step bounce ≤3, stop and escalate to human beyond that).

---

## 0. Coding Milestone Overview and Dependencies

| Milestone | Corresponding Requirement | Content | Dependency | Suggested Order |
|--------|----------|------|------|----------|
| **R-A** | 0.1 | Kernel-side RSS source-port selection back-port (IPv4) | spec(01-05) | 1 (prerequisite) |
| **R-B** | 0.3 | rte_thash dynamic path optimization (IPv4) | R-A (hangs off its miss branch) | 2 |
| **R-C** | 0.2 | IPv6 full chain (userspace + kernel + config) | Reuse R-A/R-B framework | 3 |
| **R-D** | 0.4 | reverse re-check disabled by default (runtime switch, IPv4+IPv6 symmetric) | R-B/R-C (incremental, hangs off the reverse-computation path) | 4 |
| **R-E** | 0.5 | `IP_BIND_ADDRESS_NO_PORT` bind-then-connect RSS port selection port (v4 mandatory + v6 recommended in sync) | R-A (reuses the RSS path during connect) | 5 |

> Order rationale (04 §0.2): 0.1 is the carrier for 0.3; 0.2 reuses the already-verified framework of 0.1/0.3, doing it last is safest. R-E depends on R-A's `INPLOOKUP_LPORT_RSS_CHECK` path during connect already being landed; it only adds a gate so that bind doesn't grab a port, hence it's placed last; R-E has no direct coupling with R-B/R-C/R-D (it automatically inherits the port-selection mechanism after connect).

---

## R-A: 0.1 Kernel-side Back-port (IPv4)

### R-A.1 Files:Functions to Change
| # | File:Function | Change | Landing Basis |
|---|-----------|------|----------|
| A1 | `freebsd/netinet/in_pcb.c` : `in_pcb_lport_dest`(L756) | Back-port the `#ifdef FSTACK` body: rss_* local variables, flag parsing+clearing, `ff_rss_tbl_set/get_portrange`, hit-rotation/miss-softcompute, LOOPBACK special-case | 04 §1.2; 13.0 L703-915 |
| A2 | `freebsd/netinet/in_pcb.c` : `in_pcbconnect`(L1083) | Insert `ff_in_pcbladdr(AF_INET,...)` before `in_pcbladdr`(L1129) inside the L1128 branch; add `INPLOOKUP_LPORT_RSS_CHECK` to lookupflags at L1145-1147 | 04 §1.1(B/C); 13.0 L1526-1530/L1583-1589 |
| A3 | `freebsd/netinet/in_pcb.h`(L623-625) | Keep `INPLOOKUP_LPORT_RSS_CHECK` as-is (do not enter MASK) | 04 §1.3 |
| A4 | (verify) protosw pass-through in the connect call chain | Verify only, adjust as needed | 02 §2.3 pending confirmation |

### R-A.2 Test Points
- Unit test (`tests/unit/test_ff_dpdk_if.c`): existing set/get_portrange cases (L361-455) must still pass (regression).
- Integration: with `rss_check` enabled (config.ini) + multi-queue (multi-process), the source port selected by connect must pass independent `ff_rss_check` re-verification and land in the local queue.
- Regression: compiles successfully with FSTACK disabled; when `rss_check` enable=0 / single queue → falls back to native port selection (unchanged behavior).
- Real machine: `<DPDK_NIC_IP>` (DPDK NIC) multi-process connect verifies landing on the correct queue; `127.0.0.1` (kernel stack) LOOPBACK works normally.

### R-A.3 Risks and Rollback
- Risk: mistakenly modifying a const inpcb, lookup signature misalignment, flag not cleared polluting downstream.
- Rollback: entirely `#ifdef FSTACK`, disabling it reverts to native behavior; any compile/unit-test failure → bounce back for fixes.

### R-A.4 Bounce Gate (must PASS before proceeding to R-B)
1. Compiles successfully with FSTACK both enabled and disabled.
2. All existing unit tests pass (no regression).
3. Under multi-queue, the source port correctly lands in the local queue (soft-compute re-verification assertion passes).
4. Single-queue/enable=0/LOOPBACK behavior is consistent with native.
> Any failure bounces back to the corresponding A1-A4 item; same-step bounce ≤3, beyond that stop and escalate to human.

---

## R-B: 0.3 rte_thash Dynamic Path Optimization (IPv4)

### R-B.1 Files:Functions to Change
| # | File:Function | Change | Landing Basis |
|---|-----------|------|----------|
| B1 | `lib/ff_dpdk_if.c` (global region, near L85-172) | Add `rss_thash_ctx[RTE_MAX_ETHPORTS]` + helper pointer array | 05 §1.3 |
| B2 | `lib/ff_dpdk_if.c` : `ff_rss_thash_ctx_init` (new static) | `rte_thash_init_ctx`+`add_helper`(sport, offset=64bit, len≥reta_sz_log2); call once after port configuration/near `ff_rss_tbl_init` | 04 §3.2; `rte_thash.h:303/348` |
| B3 | `lib/ff_dpdk_if.c` : `ff_rss_adjust_sport` (new static) | desired_value=∈{v|v%nb_queues==queueid,v<reta_size} rotation; `rte_thash_adjust_tuple`(tuple_len=12); take sport; **soft-compute `ff_rss_check` re-verification**; return <0 on failure | 04 §3.3; `rte_thash.h:456` |
| B4 | `freebsd/netinet/in_pcb.c` : `in_pcb_lport_dest` miss branch | Replace the per-port soft-compute scan with `ff_rss_adjust_sport`; fall back to soft-compute on failure (keeping R-A's soft-compute path) | 04 §3.1/§3.5 |

### R-B.2 Test Points
- Unit test: new `ff_rss_adjust_sport` test case — the reversed-computed sport must return 1 (lands in local queue) via `ff_rss_check`; cover combinations of different (nb_queues, reta_size, queueid) (including `reta%nb_queues!=0`) per the mapping in 04 §3.3; when attempts are exhausted, return <0 with the caller falling back correctly.
- Integration: under multi-queue, both the thash path and the soft-compute path result in port selection landing in the local queue (consistency).
- Performance: for the miss-on-static-table scenario, compare time cost of thash reverse computation vs. per-port soft-compute scan (M4/M5 performance spec scope, real machine `<DPDK_NIC_IP>`).
- Regression: when ctx init fails, degrade to pure soft-compute (equivalent to R-A), functionality unchanged.

### R-B.3 Risks and Rollback
- **Selecting the wrong queue (zero tolerance)**: B3 enforces soft-compute re-verification as a fallback — if re-verification fails, discard the port and fall back to soft-compute.
- Non-convergent reverse computation (asymmetric key): fall back to soft-compute when attempts are exhausted (performance degradation, no functional degradation); enable `symmetric_rss` (config, no code change) if necessary.
- ctx thread-safety: build ctx/helper only during initialization; runtime only uses the thread-safe `adjust_tuple` (04 §3.2).
- Rollback: B4 keeps R-A's soft-compute scan branch as a fallback; the entire 0.3 feature can be downgraded with one switch.

### R-B.4 Bounce Gate
1. Reverse-computed ports land in the local queue 100% of the time when re-verified by soft-compute (correctness, including the `reta%nb_queues!=0` case).
2. Both ctx init failure and attempts exhaustion correctly fall back to soft-compute.
3. No regression in existing R-A behavior.
4. Performance is no worse than pure soft-compute (at least on par, expected to be better).
> Any failure bounces back to B1-B4; same-step bounce ≤3, beyond that stop and escalate to human.

---

## R-C: 0.2 IPv6 Full Chain (Userspace + Kernel + Config)

### R-C.1 Files:Functions to Change
| # | File:Function | Change | Landing Basis |
|---|-----------|------|----------|
| C1 | `lib/ff_dpdk_if.c` (struct region, after L155-172) | Add `struct ff_rss_tbl6_type`/`dip6` + `ff_rss_tbl6[]` (Scheme A, v6 independent) | 04 §2.2; 05 §1.4 |
| C2 | `lib/ff_dpdk_if.c` : `ff_rss_check6` / `ff_rss_tbl6_get/set_portrange` / `ff_rss_tbl6_init` (new) | v6 hash layout 16+16+2+2=36B, reuse `toeplitz_hash`; table lookup logic mirrors v4 | 04 §2.1; 05 §1.2 |
| C3 | `lib/ff_api.h` | Export v6 interfaces (if needed by kernel-side calls) | 05 §1.2 |
| C4 | `lib/ff_dpdk_if.c` : `ff_rss_adjust_sport6` (new) | v6 thash: tuple_len=36, helper offset=256bit; soft-compute re-verified via `ff_rss_check6` | 04 §3.5; 05 §1.3 |
| C5 | `freebsd/netinet/in_pcb.c` : `in_pcb_lport_dest` INET6 branch (L818-826/L851-872) | Use laddr6/faddr6 to call v6 interface and hook RSS (if v6 goes through the unified function) | 04 §2.3 |
| C6 | `freebsd/netinet6/in6_pcb.c` : `in6_pcbconnect` family | Select local address `ff_in_pcbladdr(AF_INET6_FREEBSD,...)` + pass the RSS flag when selecting a port (or create a separate hook) | 04 §2.3; 05 §2.4 |
| C7 | `lib/ff_config.c` : `rss_tbl_cfg_handler`(L880-921) | If daddr/saddr contains `:`, go through `inet_pton(AF_INET6,...)`; IPv4 branch unchanged | 04 §2.5; 05 §3.2 |
| C8 | `lib/ff_config.h` : `struct ff_rss_check_cfg` rule item | Add family + 16B address storage | 05 §3.2 |
| C9 | (verify) NIC rss_hf | Confirm `flow_type_rss_offloads` includes v6 fields (already included in default PROTO_MASK) | 04 §2.4 |

### R-C.2 Test Points
- Unit test: `ff_rss_check6` queue-landing determination; v6 static table set/get_portrange smoke + hit correctness; v6 thash reverse-computation re-verification.
- Integration: v6 multi-queue connect port selection lands in the local queue; v6 config (including `:` addresses) parses correctly.
- Regression: **zero regression in pure IPv4 path functionality/performance** (v4 struct/interfaces untouched, regression assertions are the focus); pure v4 config.ini parsing unchanged.
- Real machine: `<DPDK_NIC_IP>` (if a v6 address is available) v6 connect lands in the local queue; confirm NIC v6 RSS offload capability.

### R-C.3 Risks and Rollback
- IPv4 regression: Scheme A does not touch v4 struct/interfaces (04 §2.2), guarded by regression assertions.
- Kernel integration point (v6 via unified path vs. independent path): decided based on the actual call chain (choose C5 or C6, verify via grep during coding, 04 §2.3/05 §2.4 pending confirmation).
- v6 table memory: re-verify capacity macros against the budget (04 §2.2 pending confirmation).
- Rollback: v6 entirely `#ifdef FSTACK` + triggered only by v6 sockets, can be independently disabled without affecting v4.

### R-C.4 Bounce Gate
1. Zero regression in v4 path functionality/performance (mandatory assertion).
2. v6 multi-queue port selection lands in the local queue (v6 soft-compute re-verification passes).
3. v6 config parsing is correct, pure v4 config parsing unchanged.
4. Kernel v6 integration point verified against the actual call chain (not speculated).
> Any failure bounces back to C1-C9; same-step bounce ≤3, beyond that stop and escalate to human.

---

## R-D: 0.4 Reverse Re-check Disabled by Default, Debug-only Enable (IPv4 + IPv6 Symmetric)

### R-D.1 Files:Functions to Change

| # | File:Function | Change | Landing Basis |
|---|-----------|------|----------|
| D1 | `lib/ff_config.h` : `struct ff_rss_check_cfg`(L241-246) | Append `int recheck;` (immediately after `int enable;`) | 04 §3-bis.5; 05 §3-bis.1 |
| D2 | `lib/ff_config.c` : `rss_check_cfg_handler`(L932-958) | Insert between `enable` and `rss_tbl`: `else if (strcmp(name, "recheck") == 0) cur->recheck = atoi(value);` | 04 §3-bis.5; 05 §3-bis.2 |
| D3 | `config.ini` : `[rss_check]` section (after L264) | Add `recheck=0` default line + 3-5 lines of comments (debug hint) | 04 §3-bis.5; 05 §3-bis.3 |
| D4 | `lib/ff_dpdk_if.c` : `ff_rss_adjust_sport`(L3053-3114) | Entry: read `int recheck = (ff_global_cfg.dpdk.rss_check_cfgs ? ff_global_cfg.dpdk.rss_check_cfgs->recheck : 0);`; change the re-verification if at L3104 to `if (!recheck \|\| ff_rss_check(...)) {` | 04 §3-bis.5; 05 §3-bis.4 |
| D5 | `lib/ff_dpdk_if.c` : `ff_rss_adjust_sport6`(L3391-3446) | Symmetric: read recheck at entry; change L3436 to `if (!recheck \|\| ff_rss_check6(...)) {` | 04 §3-bis.5; 05 §3-bis.4 |
| D6 | `tests/unit/test_ff_dpdk_if.c` | Add TC-U-RSS-04-01~05 (v4/v6 recheck=0/1 dual path + microbench); existing hitrate/equivalence cases explicitly set `g_rss_cfg.recheck = 1` to maintain the 100% hard assertion | 07 §1.4 |
| D7 | `example/rss_ct.c` (optional) | Add `--recheck=0\|1` parameter (or rely solely on ini) for real-machine on/off comparison benchmarks | 08 §1.4 |
| D8 | `docs/ff_rss_check_opt_spec/01/02/04/05/07/08/10` + three-layer architecture §2.4 | Sync incremental sections; #10 backfilled with actual measurements after R-D implementation is complete | Cross-section |

### R-D.2 Test Points

- **Unit tests** (cmocka, mimicking the existing style):
  - TC-U-RSS-04-01 v4 recheck=0: inject `g_rss_cfg.recheck = 0`; call `ff_rss_adjust_sport`; assert: return value 0 ∧ `ff_rss_check` call count is 0 (via count mock or wrap).
  - TC-U-RSS-04-02 v4 recheck=1: `g_rss_cfg.recheck = 1`; behavior same as R-B (mandatory re-verification fallback, full-loop 100% queue landing).
  - TC-U-RSS-04-03 v6 recheck=0 + TC-U-RSS-04-04 v6 recheck=1: symmetric to v4.
  - TC-U-RSS-04-05 microbench: N=10000 calls to `ff_rss_adjust_sport`, cumulative time measured with `clock_gettime(CLOCK_MONOTONIC)`; assert recheck=0 vs recheck=1 comparison (off strictly < on, report ratio).
- **Integration**: (reuse R-B/R-C's IT-RSS-03/05), add recheck on/off comparison scope (08 corresponding section).
- **Real machine**: `<DPDK_NIC_IP>` (if virtio reta=0 can't reach the thash path, run microbench only as fallback, record limitation in spec 10); `example/rss_ct.c` runs recheck=0 vs recheck=1 comparison benchmark.
- **Regression**:
  - Existing hitrate/equivalence cases must explicitly set `g_rss_cfg.recheck = 1` and all PASS (IPv4/IPv6 zero regression).
  - Compiles successfully with FSTACK disabled (same as R-A/R-B/R-C; 0.4 is a userspace change, zero kernel-side changes).
  - When `recheck=` is not written in the config file, calloc zero-init = 0 → equivalent to default-off.

### R-D.3 Risks and Rollback

- **Null pointer**: `ff_global_cfg.dpdk.rss_check_cfgs == NULL` entry guard treats it as 0; will not crash.
- **Existing test case failures**: since the hitrate cases' 100% hard assertion depends on recheck=1 behavior, must be synced in D6 with explicit injection; missing changes will be bounced back.
- **Config compatibility**: for users' old `[rss_check]` config files (without `recheck=`), calloc zero-init = 0 defaults to disabled — consistent with the new behavior, **no silent behavior change** risk (old configs enabling thash reverse-computation originally expected "performance first", which happens to align with 0.4's default).
- **Rollback**: changing `config.ini` to `recheck=1` restores the R-B/R-C status quo; any production issue can be switched online without recompiling.
- **Real machine virtio reta=0**: the existing helloworld real-machine environment has reta_size=0 → the reverse path is unreachable (thash ctx init guard returns -1), real-device data is missing; microbench unit tests serve as a fallback (spec 08).

### R-D.4 Bounce Gate (must PASS before proceeding to R-E / project delivery)

1. After starting with `recheck=0` by default, at runtime `ff_global_cfg.dpdk.rss_check_cfgs->recheck == 0` (or NULL → 0).
2. v4/v6 recheck=0 unit test: after a successful `adjust_tuple`, `ff_rss_check[6]` is **not called** (verified via count mock).
3. v4/v6 recheck=1 unit test: maintains R-B/R-C behavior, full-loop 100% queue landing.
4. microbench: recheck=0 cumulative time strictly < recheck=1 (one group each for v4/v6), ratio data written into spec 10.
5. Existing hitrate/equivalence cases all PASS with explicit `recheck=1`; zero regression for IPv4/IPv6.
6. `git diff lib/ff_dpdk_if.c` change ≤10 lines added / 0 lines deleted (v4 + v6 combined), function signatures/outer flow unchanged.
7. `git diff config.ini` contains only "the `recheck=0` line + 3-5 lines of comments", no local test state.
8. Real-machine/microbench data backfilled into spec 10's R-D section.

> Any failure bounces back to the corresponding D1-D8 item; same-step bounce ≤3, beyond that stop and escalate to human.

---

## R-E: 0.5 `IP_BIND_ADDRESS_NO_PORT` Bind-then-connect RSS Port Selection Port (v4 mandatory + v6 recommended in sync)

> Reference upstream commit `cb9b4d462a0cd8c47b6f514e2af0111cd26597b3` (based on 13.0, only modifies `in_pcb.c`, +9/-2, 3 hunks). 15.0's connect-time RSS path already exists (R-A); R-E only adds a gate so that bind doesn't grab a port.

### R-E.1 Files:Functions to Change

| # | File:Function | Change | Landing Basis |
|---|-----------|------|----------|
| E1 | `freebsd/netinet/in_pcb.c` : `in_pcbbind`(L720) | **hunk1**: wrap the hash-insertion block (L739-745) with `#ifdef FSTACK if (inp->inp_lport != 0) { ... } #endif`, skip hash insertion when lport==0; must preserve the `MPASS(SO_REUSEPORT_LB)` failure-rollback semantics at L740 | 04 §3-ter.3; 02 §6-ter.2(A); commit hunk1 |
| E2 | `freebsd/netinet/in_pcb.c` : `in_pcbbind_setup`(L1275-1279) | **hunk2**: wrap `if (lport == 0) { in_pcb_lport(...); }` with `#ifndef FSTACK`; under FSTACK, `bind(addr,0)` does not allocate a port | 04 §3-ter.3; 02 §6-ter.2(B); commit hunk2 |
| E3 | `freebsd/netinet/in_pcb.c` : `in_pcbconnect`(L1313/L1363-1366) | **No change** (verify 15.0 already equivalently has hunk3: anonport + RSS branch) | 04 §3-ter.3; 02 §6-ter.2(C) |
| E4 | `freebsd/netinet6/in6_pcb.c` : `in6_pcbbind`(L354/L361-369) | **v6 sync (brand-new design)**: skip `in6_pcbsetport` + skip `in_pcbinshash` when lport==0; after bind, inp_lport==0 | 04 §3-ter.4; 02 §6-ter.3(A) |
| E5 | `freebsd/netinet6/in6_pcb.c` : `in6_pcbconnect`(L515-516) | **v6 coordination (to be verified during coding)**: the condition for entering the RSS branch may need to be relaxed from "in6p_laddr unspec && inp_lport==0" to "inp_lport==0" (04 §3-ter.4 Path B) | 04 §3-ter.4; 02 §6-ter.3(B) |
| E6 | (verify) whether the 13.0 baseline `in_pcb.c` already contains the commit's three hunks | Grep verification only (determines whether v4 is a "missed back-port" or "new addition relative to baseline") | 02 §6-ter.4 |

- Estimated diff: v4 (E1+E2) `+8` lines / 0 deletions; v6 (E4+E5) `+6~10` lines. All gated by `#ifdef FSTACK`/`#ifndef FSTACK`.
- **No userspace changes**: reuses R-A's `INPLOOKUP_LPORT_RSS_CHECK` path during connect, no lib/interface changes.

### R-E.2 Test Points

- Unit test: verify `inp_lport==0` after `bind(addr,0)`; verify connect enters the RSS_CHECK branch (anonport=true); zero regression for `bind(addr,N)` (see 07 §1.6 TC-U-RSS-05-*).
- Integration: bind-then-connect port lands in the local queue (IT-RSS-06).
- Real machine: `<DPDK_NIC_IP>` DPDK NIC bind vip (configured on f-stack-x nic) + connect, verify return packets land on the local worker; kernel-stack `127.0.0.1` for comparison (RT-RSS-05/06).
- v6: bind(v6_addr,0)+connect6 lands in the local queue (following v6 path verification, TC-U-RSS-05-04/05).
- Regression: compiles successfully with FSTACK disabled; `bind(addr,N)` behavior unchanged; REUSEPORT_LB bind(addr,0) is correct; single-queue/enable=0 connect RSS branch automatically degrades.

### R-E.3 Risks and Rollback

- **Regression in bind with a specified port**: the gate only affects the `lport==0` branch, `bind(addr,N)` unchanged (AC-05-4).
- **Adapting v4 hunk1 to 15.0's hash-insertion block (including failure rollback)**: must ensure the entire block is skipped when lport==0, and the rollback semantics are maintained when lport≠0 (04 §3-ter.6), requires careful re-review during coding.
- **v6 connect L515 condition coordination**: closing the v6 loop may require relaxing L515 (Path B), which goes beyond a pure bind gate, medium risk (04 §3-ter.4), to be finalized after coding evidence.
- **REUSEPORT_LB**: must not break the L740 MPASS (AC-05-6).
- **Rollback**: entirely `#ifdef FSTACK`/`#ifndef FSTACK`, disabling it reverts to native bind/connect.

### R-E.4 Bounce Gate (must PASS before project delivery)

1. Compiles successfully with FSTACK both enabled and disabled.
2. v4: after `bind(v4_addr,0)`, `inp_lport==0` and no hash insertion; connect anonport=true enters the L1363-1366 RSS branch; the source port passes `ff_rss_check` re-verification and lands in the local queue.
3. v4: `bind(addr,N)` behavior is completely unchanged (port fixed + normal hash insertion), zero regression.
4. v6: after `bind(v6_addr,0)`, `inp_lport==0`; connect enters the L515 RSS branch (condition coordination scheme confirmed by evidence); the source port passes `ff_rss_check6` re-verification and lands in the local queue.
5. REUSEPORT_LB `bind(addr,0)` behavior is correct (does not break L740 MPASS).
6. Disabling FSTACK / enable=0 / single-queue reverts to native bind/connect behavior.
7. E6: whether the 13.0 baseline contains the three hunks has been verified via grep, conclusion written back to the spec.
8. `git diff in_pcb.c` v4 ≤8 lines added / 0 deletions; `git diff in6_pcb.c` v6 ≤10 lines added; config.ini carries no local test values.

> Any failure bounces back to the corresponding E1-E6 item; same-step bounce ≤3, beyond that stop and escalate to human.
> For v6 (E4/E5), if the L515 coordination change proves too risky during coding evidence-gathering, it may be downgraded to "v4 mandatory delivery first + v6 marked as a follow-up increment" (v6 was originally "recommended in sync", not hard-mandatory), escalate to human decision.

---

## 1. Cross-milestone Common Matters

- **Closing pending items** (04 §5 / 05): for each pending item, **first grep/read the code to verify** at the start of coding for the corresponding milestone before proceeding; write the verification conclusion back to the spec (do not speculate).
  - `in_pcbconnect` insertion point → verify at the start of R-A.
  - protosw pass-through → verify at the start of R-A.
  - v6 connect call chain → verify at the start of R-C.
  - NIC v6 offload → verify at the start of R-C.
  - Asymmetric key convergence rate/attempts → tune via R-B unit tests/real-machine measurements.
  - v6 table capacity macro → re-verify memory budget during R-C.
  - 0.5 v4 hunk1's adaptation to the 15.0 hash-insertion block (including failure rollback) / effects of hunk2's lport=0 write-back → verify at the start of R-E.
  - 0.5 v6 connect L515 entry-condition coordination / whether the 13.0 baseline contains the three hunks → grep-verify at the start of R-E.
  - 0.5 REUSEPORT_LB `bind(addr,0)` behavior / whether a per-socket option is needed → verify/decide during R-E.
- **Test baseline**: for detailed unit/integration/real-machine/performance scope, see M4 test spec (07/08, produced by test-spec-writer); this document only lists milestone-level test points.
- **Gate review**: after all milestones are complete, go through the M5 gate (09) for item-by-item assertion; any milestone gate failure follows the bounce≤3 process, beyond that stop and escalate to human.
- **Commit**: only commit after a milestone PASSes; commit messages in short English; re-review `git diff` before committing config.ini to ensure it contains no local test values.
