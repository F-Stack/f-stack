# 12 Spec Review Gate (Issued by Independent Gatekeeper)

> This document is issued by an **independent review agent (did not participate in any document writing; documents were written by the leader)**, based on actual `lib/`, FreeBSD 15.0, DPDK 24.11.6 source code file:line, without speculation.
> Review target: all specs under `docs/native_mt_spec/zh_cn/` — plan.md + 00~11.
> Judgment rules: PASS/FAIL per dimension; line-number drift of ±a few lines acceptable, facts must be correct; FAIL gives location + fix suggestion.
> This is the gatekeeper's second leg (the previous leg was replaced for timing out on a full-tree source scan). Review method: precise `read_file` (with offset/limit) on the specified file:line only; VNET reads only the specified line ranges of vnet.h/vnet.c; no full-tree scan of freebsd-src.

## 0. Overall Conclusion

**PASS** (0 FAIL; 3 INFO-level observations, do not block release).

| Dimension | Conclusion |
|---|---|
| 1 Code-consistency spot-check | **PASS** (27/27 spot-check items consistent with code; line drift all ≤1 line) |
| 2 Direction correctness (no adapter recommendation residue) | **PASS** |
| 3 VNET main path self-consistency | **PASS** |
| 4 Concept distinction + #430 positioning | **PASS** |
| 5 Honest boundaries | **PASS** |
| 6 Multi-process zero-regression closed loop | **PASS** |
| 7 Completeness + conventions | **PASS** |

The spec is factually accurate, focused on native multi-stack-instance, honest boundaries well marked, multi-process zero-regression closed loop complete; **approved to proceed to SM6 commit**.

## 1. Dimension One: Code-Consistency Spot-Check (Core; verified by actual read_file)

All 27 items were verified line-by-line by this agent via actual `read_file`, consistent with the spec assertions (line drift recorded in the remark column).

| # | spec assertion (file:line) | Measured result | Verdict |
|---|---|---|---|
| 1 | `lcore_conf` global singleton `ff_dpdk_if.c:123` | `struct lcore_conf lcore_conf;` @123 | ✅ |
| 2 | `struct lcore_conf` def `ff_memory.h:82-95` | def starts @82, `__rte_cache_aligned` @95 | ✅ |
| 3 | `msg_iov_tmp` static + `__thread` commented `ff_syscall_wrapper.c:225` | `static /*__thread*/ struct iovec msg_iov_tmp[UIO_MAXIOV];` @225 | ✅ |
| 4 | `msg_iovlen_tmp` same `:226` | `static /*__thread*/ size_t msg_iovlen_tmp;` @226 | ✅ |
| 5 | `pcpup` `ff_freebsd_init.c:69` | `struct pcpu *pcpup;` @69 | ✅ |
| 6 | `proc0` `ff_init_main.c:96` | `struct proc proc0;` @96 | ✅ |
| 7 | `thread0`/`thread0_st` `ff_init_main.c:98` | `struct thread0_storage thread0_st __aligned(16);` @98 | ✅ |
| 8 | `prison0`/`vmspace0`/`initproc` `:97,99,100` | prison0@97 / vmspace0@99 / initproc@100 | ✅ |
| 9 | `cc_cpu` singleton `ff_kern_timeout.c:180` | `struct callout_cpu cc_cpu;` @180 | ✅ |
| 10 | `CC_CPU`/`CC_SELF` hardcoded `&cc_cpu` `:181-182` | `#define CC_CPU(cpu) &cc_cpu` @181 / `#define CC_SELF() &cc_cpu` @182 | ✅ |
| 11 | `mi_startup` `ff_init_main.c:173-285` | `void mi_startup(void)` @173-174, function body covers to tick/close | ✅ |
| 12 | `if(sysinit==NULL)` `:188` | `if (sysinit == NULL) {` @188 | ✅ |
| 13 | `SI_SUB_LAST continue` `:235-236` | `if ((*sipp)->subsystem == SI_SUB_LAST) continue;` @235-236 | ✅ |
| 14 | tick `SI_SUB_LAST` `:271` | `(*sipp)->subsystem = SI_SUB_LAST;` @271 | ✅ |
| 15 | `dispatch_ring` `RING_F_SC_DEQ` approx `:619` | `create_ring(..., RING_F_SC_DEQ)` @619 | ✅ |
| 16 | `msg_ring[RTE_MAX_LCORE]` `:177` | `static struct ff_msg_ring msg_ring[RTE_MAX_LCORE];` @177 | ✅ |
| 17 | `msg_ring` `SP_ENQ\|SC_DEQ` approx `:670` | `RING_F_SP_ENQ \| RING_F_SC_DEQ` @671 | ✅ (drift +1 line) |
| 18 | `pktmbuf_pool[NB_SOCKETS]` `:125` | `struct rte_mempool *pktmbuf_pool[NB_SOCKETS];` @125 | ✅ |
| 19 | cache_size `MEMPOOL_CACHE_SIZE` approx `:540` + flag=0 | `rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0, ...)` @538-541 | ✅ |
| 20 | proc_type validation `ff_config.c:1316-1321` | primary/secondary/auto three-value validation @1316-1321 | ✅ |
| 21 | `parse_lcore_mask` `:73-142`; `nb_procs=count` @139 | function @72-142, `cfg->dpdk.nb_procs = count;` @139 | ✅ |
| 22 | KNI validation `:1392-1412` | primary + lcore_list validation block @1392-1412 | ✅ |
| 23 | `ff_init`/`ff_run` `ff_init.c:35-62` | `ff_init` @35-56, `ff_run→ff_dpdk_run` @58-62 | ✅ |
| 24 | KNI primary-only `ff_dpdk_kni.c:379,426` | `rte_eal_process_type()==RTE_PROC_PRIMARY` @379 and @426 | ✅ |
| 25 | KNI gating `ff_dpdk_if.c:2661` | `if (enable_kni && rte_eal_process_type()==RTE_PROC_PRIMARY)` @2661 | ✅ |
| 26 | `ff_ipc` `--proc-type=secondary` `ff_ipc.c:67` | `"--proc-type=secondary",` @67 | ✅ |
| 27 | socket flags `ff_syscall_wrapper.c:672-684`/`:943`/`:1679` | `linux2freebsd_socket_flags` @672-684; `ff_socket` call @943; `ff_accept4→kern_accept4(..., linux2freebsd_socket_flags(flags), ...)` @1679 | ✅ |

**Additional verification (VNET/EAL/TLS/main_loop):**

| Item | spec assertion | Measured | Verdict |
|---|---|---|---|
| `opt_global.h` has no VIMAGE | `03/04/09` claim no VIMAGE | whole file only 5 lines (MUTEX/RWLOCK/SX_NOINLINE, DEV_RANDOM, NO_EVENTTIMERS), **indeed no VIMAGE** | ✅ |
| `struct vnet` | `vnet.h:69` | `struct vnet {` @69 | ✅ |
| `curvnet=curthread->td_vnet` | `vnet.h:176` | `#define curvnet curthread->td_vnet` @176 | ✅ |
| `vnet_alloc()` | `vnet.c:239` | `struct vnet * vnet_alloc(void)` @238-239 | ✅ |
| `rte_eal_mp_remote_launch(main_loop,...)` | `ff_dpdk_if.c:2770` | @2770 + `rte_eal_mp_wait_lcore()` @2771 | ✅ |
| `main_loop qconf=&lcore_conf` | `ff_dpdk_if.c:2585` | `qconf = &lcore_conf;` @2585 | ✅ |
| `rte_eal_init` once per process | `ff_dpdk_if.c:1594` | `int ret = rte_eal_init(argc, argv);` @1594 | ✅ |
| `pcurthread` already `__thread` | `ff_compat.c:59` | `__thread struct thread *pcurthread = NULL;` @59 | ✅ |

**Dimension One Conclusion: PASS.** All spot-check items consistent with source; maximum deviation is msg_ring flag line +1 (approx :670 actually :671; spec used "approx", acceptable).

## 2. Dimension Two: Direction Correctness (Native Multi-Stack-Instance, No Adapter Recommendation Residue)

- `00 §3` heading "Recommended implementation path (native, not adapter)"; §3 end "Not this solution: LD_PRELOAD adapter multi-worker is application-side adaptation, not a stack-side native multi-threaded run model" — adapter explicitly excluded from the solution.
- `00 §0` old adapter recommendation **explicitly invalidated**; this version designs only the in-library native solution.
- `02 §4` "Adapter current state (objective record, not this solution's goal)" — current-state record only, no recommendation tone.
- `05 §4` rejected alternatives comparison table: adapter and "shared single stack + locks" both listed as **rejected/recorded-only**; `05 §5` first choice explicitly the VNET native path.
- Searching "recommend/preferred/suggest" keywords in `00-*.md`, `05-*.md`: all "recommend/preferred" point to the **VNET native path**; "not recommended" points to the adapter and shared single stack; **nowhere is the adapter a recommendation or conclusion anchor**.

**Dimension Two Conclusion: PASS.** Direction focused on in-library native single-process multi-thread multi-stack-instance; adapter is a current-state record only, no residue recommendation.

## 3. Dimension Three: VNET Main Path Self-Consistency (04/05/09 consistent with source + honestly marked runtime validation)

- The VNET key coordinates of 04/05/09 (`struct vnet` vnet.h:69, `curvnet=td_vnet` vnet.h:176, `vnet_alloc` vnet.c:239) were each verified consistent by this agent (see §1 additional verification).
- Main-path logic self-consistent: VNET covers `VNET_DEFINE` network-stack globals (one-shot VIMAGE enable); f-stack self-made globals (`lcore_conf`/`pcpup`/`thread0`/`cc_cpu`/`msg_iov_tmp`) are not covered by VIMAGE and need separate per-thread-ization — `04 §2` explicitly states "Route A and Route B are not strictly an either/or"; the combination strategy is clear with no logical jumps.
- **Honest marking in place**: `00 §5-1`, `04 §1.2` hard conclusions (mi_startup cannot run N times, statically determinable) and `04 §2 Route B honest boundary`, `09 §6`, `11 §5` all explicitly state "VIMAGE availability in f-stack's emasculated userspace **requires runtime validation; feasibility must not be asserted**" — **no assertion that VIMAGE definitely runs**, consistent with "code is the source of truth, no speculation".

**Dimension Three Conclusion: PASS.**

## 4. Dimension Four: Concept Distinction + #430 Positioning

- The terminology table (`01 §4`) clearly distinguishes "application-side multi-threading" (pthread calling socket APIs, #430 scenario) from "stack-side multi-threaded run model" (this round's goal).
- #430 positioning consistently lands on **evidence, not conclusion anchor**: `plan §1 item 9` "record as first-hand evidence, not a conclusion anchor", `00 §7` "a different layer from the stack-side native multi-threaded run model, not this round's conclusion anchor", `09 §4` "application-side multi-threaded API calls (already ready)… not this round's conclusion anchor". The three statements are consistent.
- Code-verified: `linux2freebsd_socket_flags`(:672-684)/`ff_socket`(:943)/`ff_accept4`(:1679) combined-flag handling complete, measured and confirmed by this agent (§1 #27).

**Dimension Four Conclusion: PASS.**

## 5. Dimension Five: Honest Boundaries

- Un-fetched external items honestly marked, no fabrication: `09 §3.2` Seastar/VPP "community common knowledge, not deep-fetched, no fabricated details"; `09 §3.3` f-stack official "no single-process multi-thread stack mode found, no fabrication"; `09 §4` #430 "comment section/fix commit not fetched (GitHub dynamic loading + API 403 rate limiting), code is the source of truth"; `09 §6` evidence status table marks each item ✅/⚠️/❌.
- Items requiring runtime validation centrally marked: `00 §5`, `04 §5`, `06 §6`(mempool capacity), `10 CM4`(VIMAGE PoC gate), `11 §5` honest-boundary layering table (statically determinable vs requires-runtime-validation columns).

**Dimension Five Conclusion: PASS.**

## 6. Dimension Six: Multi-Process Zero-Regression Closed Loop

- `07 §3` three zero-regression strategies: switch off by default (thread_mode=0 takes existing branches byte-identically), two modes mutually exclusive (thread_mode=1 + secondary combination errors), add rather than rewrite (nb_threads, not polluting nb_procs).
- `10 §3` every milestone "thread_mode=0 must be byte-level zero-regression (one-vote veto)"; CM1 rollback point "switch defaults 0, existing branches byte-identical".
- `11 §1.4` "multi-process zero regression (one-vote veto)" + `§3 R8` "thread_mode off by default + two modes mutually exclusive + byte-level regression gate".
- opt-in off-by-default confirmed reasonable against the code baseline: current proc_type defaults to auto (`ff_config.c:1312-1313`); the new thread_mode defaults to 0, not changing the existing default path.

**Dimension Six Conclusion: PASS.** Off-by-default + mutual exclusion + byte-level regression gate closed loop complete.

## 7. Dimension Seven: Completeness + Conventions

- **Completeness**: plan.md + 00~11, 13 documents in total, plus 4 `_material_*.md` files; this agent `read_file`-ed each, **no empty files, no placeholder truncation**.
- **Conventions**: the whole text is research/spec, no direct `rm`/`kill`/`chmod` suggested (`plan §5`, `01 §6`, `10 §3` all declare deletion/kill/chmod through scripts, `make clean` before compiling after code changes); lib minimal comments, English commit 1-3 sentences, config.ini local values not committed all listed in the conventions sections. This round is pure documentation without touching lib source (this agent only read, modified no lib files).

**Dimension Seven Conclusion: PASS.**

## 8. Issue List and Final Verdict

### 8.1 Issue List

No FAIL items. The following are INFO-level observations (do not block release; noted for the subsequent coding phase):

| # | Level | Location | Observation | Suggestion |
|---|---|---|---|---|
| I1 | INFO | multiple "approx :670" | `msg_ring`'s `SP_ENQ\|SC_DEQ` actually :671 (+1 line) | spec already used "approx"; can keep; if precision desired change to :671 |
| I2 | INFO | `03 §1` thread0 line | states `thread0`/`thread0_st @:98`, code actually `struct thread0_storage thread0_st __aligned(16)` | facts consistent, no change needed; only note thread0 itself is carried via thread0_st |
| I3 | INFO | `08`/`10` KNI validation line numbers | `08 §2`/`10 CM6` cite `ff_config.c:1396-1411`, `07 §2.3` cites `:1392-1412` | both fall in the same validation block (@1392-1412 includes comment start), consistent, no change needed |

### 8.2 Final Verdict

**Overall: PASS (0 FAIL / 3 INFO).**

All key technical assertions of the spec passed independent source spot-check (27 main + 8 additional items all passed), direction correct (native multi-stack-instance, no adapter recommendation residue), VNET main path self-consistent with honest runtime-validation boundaries, concept distinction and #430 positioning accurate, honest boundaries in place, multi-process zero-regression closed loop complete, documents complete and compliant.

**Approved to proceed to SM6 (local commit, docs only, English commit, config.ini local values not committed).** The 3 INFO items are optional optimizations and do not constitute a bounce-back condition.

---

> Review-method note: this gatekeeper did not participate in any document writing (writer/reviewer separation), only independently read_file-verified the specified file:line, no full-tree search_content over freebsd-src (to avoid timeout). All ✅ are this agent's own line-by-line source reads, not relayed from the spec's self-description.
