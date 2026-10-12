# 06 Solution Design: Candidate Comparison and the Key Design of the Recommended S3 (English)

> **English translation** of `docs/nginx_reload_spec/zh_cn/06-solution-design.md` (v1.9.23). The Chinese text is
> authoritative; where the two differ, the Chinese original governs.
> Translated 2026-09-30; §10 added on 2026-10-08, §10.4 in its second round, §10.5 on 2026-10-10, §10.6, §10.7 and §10.8 on 2026-10-12.

| Item | Value |
| --- | --- |
| Document ID | 06 |
| Title | Comparison of the F-Stack nginx lossless reload candidates (S1~S4) plus the design of the recommended S3 |
| Version | v1.9.23 (2026-10-12: §10.8 fixes RX-38, nginx not starting once mtu=9000 is set) — v1.9.22 (2026-10-12: §10.7 fixes RX-37, the resident primary left behind when nginx stops; §10.5 corrected) — v1.9.21 (2026-10-12: §10.6 fixes RX-36, the tools on a graceful deployment) — v1.9.20 (2026-10-10: §10.5 fixes RX-35, a resident primary reused with a different config) — v1.9.19 (2026-10-08: §10 cross-audit errata and registrations, then the RX-15/RX-29/RX-30 fixes in §10.4; the rest of this table describes v1.9.16) — v1.9.16 (on v1.9.15: **2026-09-30: the `syncookies_only=1` residual changes from "to-do" to "registered note (not measured, with the code facts and the boundary)"**) — v1.9.15 (on v1.9.14: **2026-09-29 orphan half-open entry investigation: the A1 trade-off corrected to "eliminated by revoke", the three sources ①②③ registered with measured shares; `ff_flow_map_revoke()` registered in §5.4**) — v1.9.14 (on v1.9.13: **2026-09-28 I-5: `ff_flow_map_admit()` admission rule registered and the R-23 full-table consequence corrected**) — v1.9.13 (on v1.9.12: **2026-09-28 A1: the recording-time wording completed for the §4 ASCII diagram / DR2 / acceptance items**) — v1.9.12 (on v1.9.11: **2026-09-28 correction: the R-24 conclusion (syncookies-only does not record) is obsolete and corrected; the flow_map two-phase form (RESERVED/commit) removed**) — v1.9.11 (on v1.9.10: **2026-09-22 G-D correction: the zc form is permanently excluded (not built, not tested, no support), and §5.5's `zc_stack` requirement "include a zc scenario regression in the M1 tests" is annulled**) — v1.9.10 (on v1.9.9: **the R-01 code fix has landed and this document's R-01 wording is synced** (final gate G-D rework item F-01) + **F-02 registers R-30** + **F-04 registers BR-02** — cross-generation frees of the per-generation application pool **have been eliminated** (§2 semantics 12(3)(4), §6.6.2 table rows 2/4/5, §6.6.3, §6.6.6, the §7 self-check table and the §9 decision summary synced; §6.6.2 row 4's verdict column changed back to "no" with the audit chain "original verdict wrong → corrected → code fixed" kept); R-30 (KNI bidirectional service stop in the drain window) registered in §2 semantics 15 as two separate entries per G-A §7.5/§7.8 — the inject side (secondary) and the delivery side (pre-existing); BR-02 (the coupling of the R-15 drain path with the R-01 rollback) registered in §6.6.2. v1.9.7 = corrected per the `plan_cross_audit` G-A verdicts R-01/R-03/R-04/R-05/R-11/R-17/R-22/R-23/R-24/R-29 — the cross-generation free of the per-generation application pool not zeroed (§2 semantics 12(4), §6.6.2 table rows 2/4, §6.6.3), the incomplete wording of the DPDK hard-prohibition exception argument (§6.3), the explicit registration that two generations on the same `lcore_id` cannot be validated (§6.4 admission conditions), the DR6 appendix gaining the global granularity boundary of the heartbeat (§6.2), the P0-1/P0-3 evidence anchors re-scanned against HEAD (§0/§2.1-15/§5.1/§7), the three API names in §5.4-1 corrected to the real layers, the flow_map capacity and the syncookies-only limitation registered, the `avail_count` criterion specified per pool, and §8 gaining a "not evaluated / not adopted" registration item) |
| Revision notes | **v1.9.16 (2026-09-30): the R-24 residual (`graceful_reload=1` combined with `syncookies_only=1`) changes from "to-do" to "registered note" — adding that the cookie secret is per process, that a claim by the other generation fails validation, and that in cookies-only mode the drain is not held up by half-open entries, pointing at the full note in §16** — **v1.9.15 (2026-09-29): orphan half-open entry investigation — the A1 trade-off corrected (the SYN-ACK failure path undoes the admission) plus the three sources and the measurements; `ff_flow_map_revoke()` registered** — **v1.9.14 (2026-09-28): §5.4 registers `ff_flow_map_admit()` (the SYN admission rule, which always admits with no window open); R-23's "full-table consequence" corrected to "refuse the SYN directly, no SYN-ACK"** — **v1.9.13 (2026-09-28, A1): §2 semantics 6's normative definition of the recording point, the §4 ASCII diagram note, DR2 and the acceptance items completed — unified to "recorded on SYN admission, before the SYN-ACK"; the comment line numbers cited by R-24 updated with the code** — **v1.9.12 (2026-09-28): R-24 corrected (syncookie entries have been recorded since e8287375b) plus A1's single-phase flow_map** — **v1.9.11 (2026-09-22, G-D): the zc form is permanently excluded; §5.5's `zc_stack` requirement "include a zc scenario regression" is annulled; the remaining content is historical wording kept as is** — v1.9.6 (2026-09-17): corrected by this round's plan_audit P1 independent dual-reviewer cross-audit (F-01/F-02/F-08/F-09 plus the R1 re-verification write-back), with the actual code authoritative. **v1.9.7 (2026-09-17): corrected per the `plan_cross_audit` G-A verdict** — ① **R-01**: §2 semantics 12(3)(4) and §6.6.2 table rows 2/4 plus §6.6.3's "cross-generation free is naturally correct / application-side races go to zero" rewritten to "`m->pool` only guarantees the mbuf returns to the right pool, not that the pool's per-lcore `local_cache` is untouched; the per-generation application pool still carries `cache_size=256` (`ff_dpdk_if.c:667-669`, not covered by M-A), and the two cross-generation free paths (the ARP/NDP clone `ff_dpdk_if.c:2654-2678` and the drain_tx send-on-behalf `ff_drain_ring.c:475`/`:479`) land in the same `local_cache[L]` ⇒ the invariant self-declared in `ff_memory.h:40-44` is not honoured; the code must be fixed and PT-NR-09/RV1 re-measured"; ② **R-05**: §6.3 and §6.4 admission condition 6's "the DPDK hard-prohibition reason is the mempool cache, eliminated by the per-generation mempool ⇒ the exception applies" changed to "the official text says *among other issues*; only the two identified paths, mempool and timer, have been isolated; the other per-lcore shared slots are not enumerated", adding that `rte_ethdev.h`'s original text speaks of logical cores/threads and that cross-process is an equivalent extrapolation; ③ **R-04**: §6.4 admission conditions gain item 7, stating explicitly that two generations on the same `lcore_id` cannot be validated in principle and is a known, accepted risk (do not write "validation to be added"); ④ **R-03**: the §6.2 DR6 appendix gains the boundary of the **single-word granularity of the whole process group** for the heartbeat and rx return (per-queue death is undetectable; detection flips globally); ⑤ **R-11**: the P0-1/P0-3 evidence anchors re-scanned against HEAD (`:2478-2495` → `:3029`/`:3071`; `:486/:534` → `:598`/`:595`; `:508`/`:518-524` → `:572`/`:584-587`/`:598`); ⑥ **R-17**: §5.4-1's `ff_drain_ring_create/destroy` → `ff_drain_ring_init()/unregist()` (`ff_drain_ring.h:73/92`); `ff_arp_ndp_clone_to_old` → inlined in `ff_dpdk_if.c:2655-2678`; `ff_listen_defer_close`/`ff_syncache_export_pending` → not implemented (in reality nginx's `ngx_ff_listen_close_pending` plus `ff_syncache_count()`); ⑦ **R-22**: the `rte_mempool_avail_count` criterion specified per pool (for per-generation pools either flush before reading or judge the trend); ⑧ **R-23/R-24**: flow_map 64K / probe 16 / no delete interface / a full table forwarding to G_old → RST; the wording mismatch that the SYN watermark check measures the shared pool; 100% not recorded under syncookies-only; ⑨ **R-29**: §8 gains a "not evaluated / not adopted" registration. **v1.9.8 (2026-09-18): final gate G-D rework (F-01/F-02/F-04)** — ① **the R-01 code fix has landed and this document's R-01 wording is synced**: on the same day code-fixer changed the per-generation application pool creation point to `ff_shared_pool_cache_size(ff_global_cfg.dpdk.graceful_reload, MEMPOOL_CACHE_SIZE)` (`lib/ff_dpdk_if.c:669-673`), so `graceful_reload=1 ⇒ cache_size=0 ⇒ rte_mempool_default_cache()` is always NULL ⇒ the per-generation pool has no per-lcore cache. Accordingly, the wording written in v1.9.7 ("still a bare `MEMPOOL_CACHE_SIZE` (256) / M-A does not cover the per-generation application pool / the cross-generation free is not eliminated / the code must be fixed") in §2 semantics 12(3)(4), §6.6.2 table rows 2 and 4, the last item of §6.6.3, the §7 self-check table and the §9 decision summary is rewritten to "**eliminated (mechanism layer + build/unit layer); the targeted runtime assertions (PT-NR-09/RV1) are not executed and remain registered**", **§6.6.2 table row 4's verdict column changes back from "yes (R-01)" to "no"** with the three-step audit chain kept (original verdict wrong → corrected → code fixed), and **the strikethrough keeps the original wording rather than deleting it**; ② **R-22 synced re-check (the prerequisite action self-declared in v1.9.7 is complete)**: the qualification in §2 semantics 12(5) and §6.6.6 that "`avail_count` is not trustworthy for per-generation pools (undercounted twice)" is **withdrawn** (the per-generation pool's `cache_size=0` ⇒ the criterion is trustworthy again), while "read after flush" and "trend judgement" remain as prudent practice; ③ **F-02 registers R-30**: §2 semantics 15 gains an R-30 entry, written **separately** per G-A §7.5 action-1 and the §7.8 correction — the inject side (`ff_dpdk_kni.c:581`, a **secondary behaviour** of this R-02 fix) and the delivery side (`ff_dpdk_if.c:2685`, a **pre-existing gap of the T5 flip design, not introduced here**), noting "not a deadlock, not a crash; it degrades into packet loss counted in `kni_stat[port_id]->tx_dropped`; the magnitude is not confirmed"; ④ **F-04 registers BR-02**: §6.6.2's table gains row 5 plus a BR-02 note under the table, recording that "the R-15 drain path frees mbufs of the other generation's pool, and its safety depends entirely on R-01's `cache_size=0`; rolling back R-01 alone would make R-15 a new source of cross-generation cache races"; ⑤ **F-02 addition (the R-02 qualification)**: the R-30 entry in §2 semantics 15 gains the G-D ruling "**R-02 = mechanism closed, behavioural closure incomplete (no KNI TX inject targeted real-machine test)**" (listing that all four `rte_eth_tx_burst` call sites are unreachable as the basis for closure, with the two unclosed items kept); ⑥ **F-04 addition D-NEW-1**: §5.4-1 registers that "the R-16 degraded path lands in the `_e0_g<gen>` namespace, the same shape as the resident primary's pre-created ring set (`ff_drain_ring_init()` has no process-type gate)"; the consequence is not confirmed and is non-blocking (D-NEW-2 and the suggested case IT-NR-A15 are registered in [08](testing-plan.md) §2.2). **v1.9.9 (2026-09-18): completing the remaining landing points of the R-01 mechanism error (G-D "must be completed before commit")** — that mechanism error has **7 occurrences** in the whole corpus; the v1.9.8 round fixed 3 (the §7 self-check table, the §9 decision summary, [00](overview.md) §3.3); this round completes the remaining **2** in this document: ① **§2 semantics 12(1)**: the inference "with each generation using its own pool there is no cache race" is annulled (changed to "it only excludes races between two pools, not between two processes inside one pool"), and **v1.9's "correction" of v1.7's "they still race in the same-numbered cache slot even inside different pools" is withdrawn — that v1.7 sentence was right**; ② **the "key fact" paragraph of §6.6.1 (right above the §6.6.2 table)**: "once the per-generation mempools are split … they do not conflict even on the same lcore_id" is struck through and corrected to "a cross-generation free falls back into G_old's pool's `local_cache[L]` ⇒ a conflict is unavoidable", and the same paragraph's mistaken "correction" of v1.7 is withdrawn, noting "consistent with §6.6.2 table row 4 immediately below and its three-step audit chain". Both places gain the current state (**eliminated by the R-01 fix**: `ff_dpdk_if.c:669-673` `cache_size=0`; the targeted runtime assertions are not executed and remain registered) and the dependency coupling (rolling back R-01 requires a joint evaluation, see BR-02). **v1.9.10 (2026-09-18): wide-wording sweep completion (G-D bounce 2/3)** — the previous self-check used the keywords `mutually non-overlapping/two different memory regions/non-overlapping` and **missed one class of synonymous variants**; this batch re-sweeps with wider keywords (`eliminate application-side races`/`races go to zero`/`no longer mandatory`/`splitting by generation eliminates`/`local_cache`/`cache_size=0 no longer`) and corrects 4 places of current text in this document: ① **§2 semantics 8, decision reason item 2** (`:112`) gains the note "the solution is not achieved by splitting per generation alone, but by splitting per generation **plus** the per-generation pool's `cache_size=0`"; ② **the §6.3 D-A overturning reason paragraph** (`:574`) gains the note "the same slot is not only in the shared RX pool; the per-generation application pool had it too before R-01; after the fix all four pools have `cache_size=0` before it is eliminated as a whole; the trade-off conclusion is unaffected"; ③ **the §6.6.x same-slot table row** (`:581`) "exists only in the shared RX pool" is struck through and corrected to "pre-fix wording and inaccurate; after the fix all four pools have `cache_size=0` ⇒ that shared slot does not exist at all", and its "solution" column's "independent caches, races go to zero" is corrected in the same batch to "splitting by generation alone is not enough to zero them; zeroing is achieved by R-01"; ④ **§6.6.x rejected option B** (`:690`) "since the per-mempool cache isolates naturally, this is no longer necessary" is struck through and corrected to "**the rejection stands but the reason was wrong**: the real cause is that R-01 makes the per-generation pools `cache_size=0` too ⇒ there is no per-lcore cache at all, not natural isolation". Also **§9's decision summary row (`:710`) is confirmed consistent with the post-R-01 state** (it already contains the correction "R-01 brought the per-generation application pool into M-A as well ⇒ all race paths go to zero"), so **no change is needed** |
| Date | 2026-09-02 |
| Status | pending human audit (v1.9 cross-audit revision plus the human decisions written down) |
| Revision source | the 2026-09-01 independent cross-audit (read-only, no code change, no git write operation); every conclusion carries `file:line` evidence and distinguishes "confirmed in code" from "inference" |
| Decisions settled | **D-A = both generations use the same `lcore_id`** (2026-09-01 human decision, overturning the previous version's "different lcore_id" in this round; ~~the DPDK hard-prohibition reason is eliminated by the per-generation mempool ⇒ the exception applies~~ **[2026-09-17 correction, R-05] changed to "the prohibition reason is *among other issues*; the two identified paths, mempool and timer, are isolated; the rest is not enumerated"; and (R-04) two generations on the same `lcore_id` cannot be validated in principle and is a known, accepted risk**); D-B = **adopt the M1′ form**; D-C = **M2 stays an optional evolution** (triggered by DR7, not earlier); **DR5 cancelled**; **DR6 = option ①, return rx to G_old** (the heartbeat is a global switch marker in shared memory incremented every loop; it dies with the flow map after G_old drains; the timeout defaults to 1 s and is configurable); **[v1.9.4 M4 implementation note] the executor changes from "the primary writes back" to "G_old's workers autonomously reclaim"** (the two are semantically equivalent, and the autonomous form naturally prevents an empty return; the spec is revised to the implementation form and must not be redone literally, which would introduce a two-writer race); **semantics 11/12 restored as mandatory** |
| v1.9.1 changes | semantics 8/11/12/15, §6.2 (DR5 cancelled / DR6 decided plus appendix / DR8 reversed / DR11 added), §6.3 (rewritten), §6.6 (rewritten as the detailed per-generation mempool design), §4.1 D5, §5.4-3, §7, §9 |
| Source artefact | `work/solution-design.md` (solution designer `solution-designer`, filed 2026-08-18). This document is the formalised rewrite: its inputs are the predecessor artefacts of [01](vpp-vcl-research.md)/[02](other-projects-research.md)/[03](legacy-solution.md)/[04](current-analysis.md)/[05](ld-preload-alternative.md) (all read in full) plus cross-verification of key mechanisms against the actual code (read-only); all factual evidence, single-source declarations and unconfirmed markings are kept |

Related: [00 Overview](overview.md) | [04 Current Analysis](current-analysis.md) | [07 Milestones](milestones.md) | [08 Test Plan](testing-plan.md)

### v1.9 revision summary (2026-09-01 cross-audit)

Audit scope: code-based re-verification of the semantics added by v1.6/v1.7/v1.8 (an incremental audit against v1.3, which the four historical audit reports of 2026-08-21 targeted).

| # | Defect (as v1.8 reads) | Key evidence | v1.9 handling |
| --- | --- | --- | --- |
| P0-1 | **Exclusive TX queue concurrency violates the DPDK contract**: after T3, G_old's drain egress and G_new's service egress use the same `tx_queue_id`, and 06 only makes rx mutually exclusive with zero tx protection | `ff_dpdk_if.c:598`/`:595` (tx and rx have the same number; the `thread_mode` branches at `:550`/`:548`; **[2026-09-17 re-scan against HEAD, R-11] the previous `:486/:534` is stale**), `send_burst` **`:3029`** and the `rte_eth_tx_burst` inside it at **`:3071`** (the only tx exit; **the previous `:2478-2495` is stale**), `:2532`/`:2557` (inside the `FF_USE_PAGE_ARRAY` branch)/`:2844-2856` (three flush entries; corrected in the v1.9 re-check, which previously wrote "two" and missed `:2557`); `dpdk/lib/ethdev/rte_ethdev.h:6575-6577` (only an `RTE_ETH_TX_OFFLOAD_MT_LOCKFREE` PMD allows lock-free concurrency, and virtio does not declare it; **note added: the official text speaks of logical cores/threads, so "two processes on the same lcore" in this scheme is an equivalent extrapolation**) | semantics 13: G_new owns tx exclusively; G_old's egress is sent on its behalf through `drain_ring_tx` |
| P0-2 | **dispatch_ring's two consumers violate `RING_F_SC_DEQ`**: under the same queue, two generations dequeue the same ring | `ff_dpdk_if.c:710-713` (`RING_F_SC_DEQ`), `:2865-2870` (dequeue with the same `queue_id` in the same loop), `:2144-2147` (silent drop when full) | semantics 13: switch to per-generation `drain_ring_rx`/`drain_ring_tx`, each with explicit flags (rx MP/SC, tx SP/SC) |
| P0-3 | **"Same queue + different lcore_id" deadlocks with the nb_procs/lcore_mask semantics** | `ff_config.c:118/:127/:139` (the number of set bits in lcore_mask = nb_procs), `ff_dpdk_if.c:572` (taking `proc_lcore[proc_id]` → lcore_id)/`:584-587` (the lcore_list index → queueid)/`:598` (`tx_queue_id[port] = queueid`) (**[2026-09-17 re-scan against HEAD, R-11] the previous `:508`/`:518-524` is stale**), `ff_config.c:555-574` (nb_lcores = nb_procs) | ~~semantics 15: four-chain decoupling rules plus new configuration surface~~ → **resolved in v1.9.1 by the D-A reversal to "same lcore_id"**: 2N lcore_ids are not needed, `lcore_mask`/`nb_procs`/queue counts stay at N, and no configuration surface is added |
| P0-4 | **The `lcore_id` wording contradicts itself**: §6.3 says "different lcore_id" while semantics 11/§6.6 are designed around "same lcore_id" | 06 §6.3:388, §3.3:176 vs §2 semantics 11:73, §6.6:413-426 | **v1.9.1 final: unified to "same lcore_id"** (D-A human decision); §6.3 rewritten and **semantics 11/12 restored as mandatory** (v1.9 had decided "different lcore_id + the two changes downgraded to hardening items", which is overturned) |
| P0-5 | **A half-open connection has no owner at the handover instant**: after G_old closes listening, its syncache half-open entries cannot complete the handshake | `tcp_syncache.c:1033-1055` (expand needs lsop), `tcp_subr.c:2517-2553` (`tcp_close` does not clear the syncache for LISTEN, only `in_pcbdrop`) | semantics 14: delay closing the listening socket until the syncache has drained (or export the half-open four-tuples at T3) |
| P0-6 | **msg_rings collide by proc_id**: two generations dequeue the same msg ring, so control messages are received by the wrong side | `ff_dpdk_if.c:2903`/`:2457-2470`, `:764-777` (`RING_F_SP_ENQ\|RING_F_SC_DEQ`); `ff_dpdk_kni.c:101-109` (the same class of problem for the KNI runtime owner) | semantics 15: msg_ring and KNI owner isolated per generation |

Also fixed: P1-3 (the D5 rating and the `cache_size=0` wording), P1-4 (the precise definition of G_old stopping poll), P1-5 (the specification of the handover mutual-exclusion primitive), P1-7 (the declaration that kernel_coexist is not evaluated) and the remaining P2 items (the §5.3 reta wording, the §0 line numbers, the §8 single-source wording).

**Scheme form upgrade**: v1.6's "both generations sharing the same set of hardware queues (mutually exclusive rx handover + unprotected tx)" becomes v1.9's **M1′ "single hardware owner + drain-generation software parasitic"** — after T3, G_new owns rx+tx exclusively, G_old leaves the hardware completely and runs only the protocol stack, with both directions forwarded over two new rings (see §3.3 and §5.2).

---

## 0. Input list and cross-verification declaration

This design is based on the following five artefacts (all read in full):

| Code | Document | Nature |
| --- | --- | --- |
| R-A | [01 VPP/VCL Research](vpp-vcl-research.md) | VPP VCL mechanisms + engineering problems + the queue-ownership conclusion |
| R-B | [02 Other Project Research](other-projects-research.md) | kernel baseline / other user-space stacks / general patterns |
| E-C | [03 Legacy Community Scheme Verification](legacy-solution.md) | issues #547/#12, the iWiki legacy scheme, and the timer evolution git chain |
| P-D | [04 F-Stack Current State Analysis](current-analysis.md) | the F-Stack current state + the 8-item obstacle list |
| P-E | [05 ld_preload Alternative Route](ld-preload-alternative.md) | the advantages/gaps of the ld_preload route |

Code re-checked when designing the key mechanisms (line numbers consistent with the artefacts above; the actual code is authoritative):

- `lib/ff_dpdk_if.c:2105-2150`: the packet_dispatcher callback plus dispatch_ring cross-process forwarding (**key confirmation: the callback only fires for packets with `!pkts_from_ring`; the gate is at `:2105` — `:2100-2103` is the receive-counting gate (`ff_traffic.rx_packets/rx_bytes`) and is unrelated to the callback; v1.8's reference to `:2100` was wrong and v1.9 corrects it**; packets arriving from the ring short-circuit with `pkts_from_ring=1` and do not re-enter the callback — the forwarding fallback is naturally free of loop risk).
- `lib/ff_dpdk_if.c:2222-2236`: `process_dispatch_ring` dequeues from the per-(port,queue) ring (`:2228`) and then enters `process_packets` with `pkts_from_ring=1` (`:2232`) → `ff_veth_input`. **Its semantics are "inbound into the protocol stack", so outbound send-on-behalf cannot reuse this path** (the basis of v1.9 semantics 13).
- `lib/ff_dpdk_if.c:3029` (`send_burst()`, with `:3071` the `rte_eth_tx_burst` inside it): the only `rte_eth_tx_burst` call site in the whole file, with `queueid = qconf->tx_queue_id[port]`; `ff_dpdk_if.c:598`/`:595` show that `tx_queue_id` and the rx `queue_id` have the same number (both derived from the lcore_list index at `:584-587`, the lcore being taken at `:572`). **This forms the evidence for v1.9's P0-1.** **[2026-09-17 re-scan against HEAD, R-11] the previous anchors `:2478-2495` (send_burst), `:486/:534` (tx/rx same number) and `:518-524` (lcore_list index) are all stale; the values above are measured.**
- `app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c:223-270`: `#if (NGX_HAVE_FSTACK)` two-stage serial reload (all exit first, then start new).
- `app/nginx-1.28.0/src/event/modules/ngx_ff_module.c:169-187`: `ff_mod_init` assembles `--proc-type=primary/secondary` hard-coded by proc_type.

Also skimmed `docs/primary_slim_spec/03-solution-design.md` and `10-feasibility-conclusion.md` as the basis for S3.

### 0.1 The common conclusion baseline of the two external research lines (criterion 1, the anchor of the scheme evaluation)

R-A §6.2 and the added paragraph of R-B §5.2 reach isomorphic conclusions independently; this design takes them as the first criterion:

1. **No precedent in the industry for migrating established TCP connections** (R-B §4 P4: Envoy's original sentence "existing connections are not transferred"; corroborated by R-A §4.2 point 5, where in VCL the old worker's connections close on drain). The target semantics must therefore be "**seamless new connections + the old process drains**", and connection state migration is not pursued.
2. **Decoupling NIC queue / receive ownership from the business process lifetime is the structural precondition for a lossless reload on a user-space stack** (R-A §6.2: VPP's queues belong to an independent process, so a no-owner window does not exist structurally; the #1078 primary_slim PoC where 12/12 connections had zero interruption after killing the primary; the centralised design of adapter/syscall — three sources pointing independently at the same conclusion). **Listening fd ownership is a second-order control-plane problem** (P-D obstacle 2's precondition is weakened).
3. Facebook's "do not cut traffic over before ready" (R-B §2.4(a)) and VCL's app_listener workers bitmap (R-A §2.2/§4.2) are isomorphic: before a new worker is registered in the bitmap / the application is ready, accept is not distributed to it and traffic keeps going to the old instance.

### 0.2 Code re-checked for v1.9 (actually read in this round's cross-audit; all current content of this branch's release/2.0)

| File | Section | Used to confirm |
| --- | --- | --- |
| `lib/ff_dpdk_if.c` | `:598`/`:595` (tx/rx same number; previously `:486/:534`), `:584-587` (lcore_list index; previously `:518-524`), `send_burst` `:3029` / `rte_eth_tx_burst` `:3071` (previously `:2478-2495`), `:2532`/`:2557`/`:2853` (three flush entries), `:2840-2901`, `:710-713`, `:764-777`, `:2457-2470` | tx and rx having the same number, the only tx exit, the coupling of dequeue and rx_burst in the same loop within main_loop, and the flags of the two rings |
| `lib/ff_config.c` | `:118/:127/:139`, `:555-574` | the number of set bits in lcore_mask = nb_procs and nb_lcores = nb_procs (the four-chain deadlock) |
| `lib/ff_dpdk_kni.c` | `:101-109` (`:108` compares `proc_id == kni.owner_proc_id`) | the KNI runtime owner is bound to proc_id, so after a generation change it lands on an exited generation |
| `freebsd/netinet/tcp_syncache.c` | `:1033-1055` (the `static` declaration of `syncache_lookup` is at `:586`) | `syncache_expand` relies on a VNET-private global hash and needs lsop to create the socket |
| `freebsd/netinet/tcp_syncache.h` | `:36-48` | only seven exported interfaces, **no half-open entry counting interface** (C-NR-312 must add one) |
| `freebsd/netinet/tcp_subr.c` | `:2517-2553` (the only call site of `syncache_destroy` is `tcp_destroy` at `:1583`) | `tcp_close` only does `in_pcbdrop` for `TCPS_LISTEN` and does not clear the syncache |
| `dpdk/lib/ethdev/rte_ethdev.h` | `:6575-6577` | only an `RTE_ETH_TX_OFFLOAD_MT_LOCKFREE` PMD allows lock-free concurrency on the same tx queue |
| `dpdk/doc/guides/prog_guide/multi_proc_support.rst` | `:169-172` | primary/secondary are forbidden from sharing the same logical core (the DPDK hard prohibition) |

> The line numbers in the table above have been re-checked and confirmed one by one by an **independent re-reviewer** (write/review separation); the re-check conclusion is in [09](review-report.md) §20.

## 1. Evaluation dimensions and criteria

| # | Dimension | High-score standard (basis of the score) |
| --- | --- | --- |
| D1 | Losslessness / packet-loss window | structurally lossless: the receive queue always has an owner throughout the reload and the new-connection switch is atomic (compare R-A §6.2's VPP model). Medium: engineering losslessness — the switch window relies on buffering (NIC rx ring / dispatch ring), so the window is tiny but must be measured. Low: an unbuffered service gap exists |
| D2 | Connection-retention semantics | aligned with baseline 1: new connections seamless + existing connections drained completely (the old process stays alive and runs RTO/keepalive to natural close). Bonus: an explicit guarantee for the old connections' receive path during drain; penalty: needing a mechanism such as "TCP state migration" that has no industry precedent (risk transfer) |
| D3 | Change surface and risk | code volume, layers touched (nginx adaptation layer / lib / DPDK patches / NIC driver), intrusiveness into the existing steady-state path, and whether there is a verified PoC basis |
| D4 | Compatibility with mainline evolution | the relation with primary_slim (#1078, already implemented in production), native_mt (the single-process multi-thread line), zc_stack and the DPDK 23→24 upgrade line: does it continue them or create a long-term fork |
| D5 | Performance impact | steady-state (non-reload) per-packet path cost; reload-window resource cost (double cores / double instances?) |
| D6 | Operational complexity | deployment form changes (a new resident process?), the number of configuration items, and whether monitoring / downgrade / rollback means are explicit |
| D7 | Testability | can the VPP community's verification pattern be applied (R-A §6.3-7: reload in a loop under traffic + no deadlock, no crash + zero errors as the gate; adapted in v1.6 for the re-entry-protection semantics: the cadence follows the drain confirmation plus READY, ≥100 times); can it be delivered incrementally, and can failure scenarios be injected |

One additional veto criterion (from E-C §9-1 and the lesson of R-A §6.4): the reload logic must be an **explicit, observable state machine** (every stage instrumentable and revertible), not implicit logic scattered across fork/signal hooks — VPP's #3547/#3645 going unfixed for three years is the cautionary example (R-A §4.3/§6.4).

## 2. Target semantics — what "lossless" means exactly

Based on baselines 1/2 and on R-B §2.2 (kernel HUP semantics) and §2.1 (USR2 semantics), the target semantics of this design are:

1. **Zero loss for new connections** — at every instant of the reload, an arriving SYN is taken by some process and accepted (brief queueing in the NIC rx ring / the stack backlog during the window is allowed; RST or drop is not).
2. **Graceful drain of existing connections** — connections established before the reload are served by the old workers until they close naturally (client close or keepalive timeout); during drain the old workers' TCP timers (RTO / keepalive / delayed ACK) keep running. Cross-process **TCP state migration is not done** (no industry precedent, R-B §4 P4).
3. **A configuration failure can be rolled back** — aligned with kernel HUP (R-B §2.2: a configuration that fails to parse rolls back and the old configuration keeps running).
4. **Both HUP and USR2 are supported** — HUP changes the configuration, USR2 changes the binary (exec); both share the same data-plane mechanism.
5. **Lossless in the engineering sense** — accepting the boundary from the HAProxy documentation cited by R-B §2.2: at the boundary, connections sitting in a backlog may still be lost with very small probability; acceptance is gated on zero errors under load, not on an absolute claim.
6. **The flow table is active only during the reload window, and reload is re-entry protected** (semantics added in v1.3, rewritten in v1.6 per the 2026-08-21 scheme revision): in steady state **no packet goes through the flow table** (zero extra per-packet cost); the table takes effect automatically once the new worker has finished initialisation (READY) and simultaneously takes over the queues and listen, and it is closed after the old worker's drain is confirmed. The table (**flow_map**, the software dispatch table) **records only the four-tuples of connections created by this generation**; **the recording point is the moment this stack receives the SYN** (inside `syncache_add`, **before the SYN-ACK goes out**; 2026-09-28 A1: single phase, visible as soon as it is recorded. At that moment the connection has no inpcb yet — this is not the stack's inpcb table) — it **must not be deferred until `accept()` returns**, or the third handshake ACK will miss (the connection is still in the syncache) and be forwarded to G_old (which has no syncache entry for it → RST), making every new connection in the reload window fail (corrected in v1.8, see §5.2 T3); a table miss (a packet of an existing connection) **is always forwarded to the old worker over `drain_ring_rx`** (v1.9: `dispatch_ring` is no longer reused, see semantics 13 for the reason). **flow_map solves only the half "G_new receives the SYN"** — the other half, "G_old received the SYN and the third ACK arrives only after the handover", is handled by semantics 14. After the old worker drains, the new worker notices and closes flow_map, entering steady state as the new "old worker" (preventing performance decay). **Fast successive reloads before the old worker has drained are not supported**: until the previous batch of old workers has drained, a new reload request is intercepted (refused and logged).
7. **Simultaneous takeover of rx+tx+listen after ready, with G_old degrading into a software-parasitic process** (rewritten in v1.9, replacing v1.6's "both generations sharing the same set of hardware queues"; v1.6's decision "take over as soon as ready, not at the last moment" is kept): once G_new is ready it **takes over rx poll + tx + listen simultaneously** (the new configuration takes effect immediately) and from then on is **the only process touching the hardware queues**; G_old **leaves the hardware completely** — it no longer calls `rte_eth_rx_burst` or `rte_eth_tx_burst`, runs only the protocol stack and the timers, and drains the existing connections. The handover is guaranteed by a **cross-process mutual-exclusion primitive** (a shared-memory marker, not a msg ring) so that G_new starts rx poll only after G_old has stopped it, avoiding concurrent polling of the same queue; the handover window is backed by NIC rx ring buffering (RX_QUEUE_SIZE 512→4096, an 8× increase). **v1.6's defect**: it only made rx mutually exclusive, so on the tx side G_old was still calling `rte_eth_tx_burst` concurrently with G_new on the same queue (P0-1).
8. **`lcore_id` strategy: both generations use the same `lcore_id` (same core, same `lcore_id`)** (**v1.9 final decision D-A**, 2026-09-01 human decision; overturning the previous version's "different lcore_id" decision in this round):
   - **Decision reason (key points of the original human decision)**: switching to different `lcore_id`s would move the global resource allocation chain `lcore_mask → nb_procs → lcore_id → queue_id`, and **the conflicts and reallocation of the various pools it would cause (mempool / msg_ring / dispatch_ring / timer slots / queue pools) are far more severe than the single problem of `priv_timer` and `mempool.local_cache` sharing a slot**. The right approach is to **accept the same `lcore_id` and refine the per-generation isolation of the mempool** (see semantics 12 and §6.6), rather than dismantling the whole chain to avoid one shared slot.
   - **Problems dissolved as a result**: P0-3 (the four-chain deadlock) **no longer holds** — 2N `lcore_id`s are not needed, `lcore_mask` / `nb_procs` / the queue count all stay at N, and the "per-generation lcore pool" configuration item in semantics 15 is **cancelled**.
   - **The two real conflicts of the same `lcore_id` (which must be solved by semantics 11/12, and which therefore become mandatory again)**:
     1. the `priv_timer[lcore_id]` shared slot → solved by **semantics 11, the self-driven hardclock** (mandatory).
     2. the mempool `local_cache[lcore_id]` shared slot → solved by **semantics 12, the refined per-generation mempool scheme** (mandatory). **[2026-09-18 note, R-01 mechanism]** the "solution" here is **not** achieved by "splitting per generation" alone: `local_cache` is a per-mempool member, so two pools each having their own **only excludes conflicts between the two pools, not conflicts between two processes inside the same pool** — a cross-generation free sends the mbuf back to the **allocating** pool's `local_cache[L]`. The real solution is **splitting per generation + the per-generation pool also having `cache_size=0`** (R-01, `ff_dpdk_if.c:669-673`); see the R-01 mechanism correction block in semantics 12(1).
   - **Relation to the DPDK hard prohibition (the exception argument, which must be written into the review record)**: `dpdk/doc/guides/prog_guide/multi_proc_support.rst:169-172` forbids primary/secondary from sharing the same logical core, and **the reason it gives is precisely "mempool per-lcore caches can be corrupted"**. This scheme **directly eliminates the failure mechanism the prohibition points at** through "per-generation mempool separation + making the shared RX pool cache-less / freeing on its behalf" (semantics 12), so it is an **exception that applies because the reason does not hold**, not an ignoring of the prohibition. This argument must be recorded explicitly at the M2 review and corroborated by measurement in RV1/RV6/PT-NR-09 (observing mbuf watermarks, no double free, no pool mismatch). **[2026-09-17 correction, R-05] the wording above is incomplete and must no longer be quoted as it stands**: the official text is *"…can cause corruption of memory pool caches, **among other issues**."* — the mempool cache is only **one example**, and the prohibition's reason **includes but is not limited to** it. This scheme isolates only the **two identified paths, mempool (semantics 12) and timer (semantics 11)**, and **the risk of the other per-`lcore_id` shared slots is not enumerated** (the comment at `lib/ff_dpdk_if.c:1511-1516` self-reports having hit two **non-mempool** failures: an N-1 memset trigger and an N-5 locked-critical-section crash) ⇒ the correct wording is "**the identified paths are isolated, the rest is not enumerated**", not "the reason does not hold". **And (R-01, 2026-09-22 sync, B01-7)** the cross-generation free of the per-generation application pool **has been eliminated by the R-01 fix** (`graceful_reload=1` ⇒ the per-generation application pool also has `cache_size=0`, see §6.6.2 row 4), while **the targeted runtime assertions (PT-NR-09/RV1) are not executed and remain registered**. The corroboration set expands to RV1/RV6/RV15 + PT-NR-08/09 + IT-NR-A13.
   - **Physical core**: the same `lcore_id` for both generations ⇒ naturally the same physical core, so no `--lcores` affinity is needed; the X3 decision (2N physical cores not required) is satisfied automatically. Compute contention during drain is measured by RV10.
9. **ARP/NDP and other protocol packets are cloned to G_old** (added in v1.6): during the reload window, while ARP/NDP and similar packets are handed to G_new's stack, **an extra copy is forwarded to every G_old process** (the existing cloning to other G_new processes and to KNI is unchanged) — ensuring that G_old's neighbour tables stay healthy during drain and that it can send RTO/FIN/ACK.
10. **reta is not modified and NIC RSS capability is not required** (added in v1.6, also resolving audit fatal items 1/2/3): S3-M1′ no longer relies on reta cut-over primitives — the same queue plus a **generation-independent fixed `queue_id` mapping** keeps reta unchanged, keeps the `ff_rss_check` four-piece unchanged, and does not configure 2N queues (no loss of half the traffic). **It works on both virtio and physical NICs** (no guest-side RSS capability required).
11. **Self-driven hardclock, avoiding the DPDK shared timer slot** (**v1.9 final decision: mandatory**, restored because D-A settled on "same `lcore_id`"; v1.7 per the 2026-08-24 timer research plus a human decision): when old and new processes coexist on the **same `lcore_id`**, DPDK's `priv_timer[lcore_id]` shared slot is unusable (the memset in `rte_timer_meta_init` would trample the timer list G_old has hooked → its hardclock would never fire again → the RTO/keepalive of existing connections would silently stall; and the shared list holds private address pointers of the other process, so `rte_timer_manage` traversing it dereferences private virtual addresses across processes → crash/data corruption, unpatchable). **Scheme**: give up the rte_timer hooking approach; main_loop calls `ff_hardclock()` directly on a TSC interval (`if (next_hardclock_tsc < cur_tsc) { ff_hardclock(); ff_update_current_ts(); next_hardclock_tsc += interval; }`); under the graceful branch **secondaries register no timer at all**; **the primary keeps `rte_timer_subsystem_init()` to create the `rte_timer_mz` memzone** (`lib/ff_dpdk_if.c:1517-1518`), while `rte_timer_meta_init/rte_timer_init/reset` are removed and replaced by computing `interval = hz_tsc / freebsd.hz` (default 100 → 10 ms); the `graceful_reload=0` branch keeps all four calls intact with literally unchanged behaviour (`:1534-1542`). Each process's hardclock is fully independent with zero shared state, so there is no conflict on the same `lcore_id`. Basis: across the whole F-Stack tree `freebsd_clock` is the only rte_timer user (two places in `lib/app`, both in `ff_dpdk_if.c`), and it does not depend on any cross-core/synchronisation feature of rte_timer. Change points: three places in `ff_dpdk_if.c` — `init_clock`/`init_clock_worker`/`main_loop`. It is equivalent for `graceful_reload=0` (self-driving and hooking behave the same), and timer precision needs a regression test (RTO/keepalive).
    **v1.9 final decision (D-A = same `lcore_id`)**: `priv_timer` necessarily shares the slot, so this item **becomes mandatory for M1′**, not optional. There are two additional benefits — (a) no dependence on the correctness of `--lcores` mapping; (b) under M1′ G_old no longer polls hardware and main_loop becomes a "pure software loop", so the self-driven hardclock removes the dependence on `rte_timer_manage`'s lcore semantics and the implementation is simpler. **Regression requirement**: the PT-NR-08 precision regression is a **merge gate and cannot be skipped** [2026-09-22 sync, M03-1: the criterion is the functional wording **single-shot deviation ≤1 tick**; the previous "precision deviation ≤5% versus the `graceful_reload=0` baseline (threshold calibrated in M0)" depended on an unmeasurable hooked-slot baseline (P0-NEW) and has been replaced]; RTO/keepalive/delayed ACK **single-shot deviation ≤1 tick** (the PT-NR-08 functional wording; short timers take the stricter of absolute ≤1 tick and relative ≤5%, with the divisor being the configured value), with no missed or duplicated firing.
12. **Refined scheme for the per-generation mempools and the shared RX pool** (**v1.9 final decision: mandatory**, restored and refined because D-A settled on "same `lcore_id`"; proposed in v1.7 per the 2026-08-24 human decision, expanded in v1.9 per the human decision "refine the concrete implementation of the per-generation mempools"):

    **(1) Key fact: the cache is per-mempool, not global** [2026-09-18 correction, R-01 mechanism]
    `struct rte_mempool` has a member `struct rte_mempool_cache *local_cache` (`dpdk/lib/mempool/rte_mempool.h:258`), accessed as `&mp->local_cache[lcore_id]` (same file `:1340-1341`). **That is, every mempool owns its own independent local_cache array** — this **fact itself holds**.
    ~~Inference: the same-numbered `local_cache[L]` of two different mempools are two different memory regions, so there is no cache race when the two generations each use their own pool. v1.7's original statement that "two generations on the same `lcore_id` still race in the same-numbered cache slot even inside different pools" was **inaccurate**, and v1.9 corrected it.~~
    **[2026-09-18 correction] The inference above, together with its "correction" of v1.7, is wrong and both are annulled**:
    - "the same-numbered `local_cache[L]` of two different mempools are two different memory regions" **holds**, but it **only excludes conflicts "between the two pools", not conflicts "between two processes inside one pool"**;
    - the key is the **cross-generation free**: when an mbuf allocated by G_old is freed by G_new, `m->pool` points at **G_old's pool**, and G_new's `rte_pktmbuf_free` falls back into **G_old's pool's `local_cache[L]`** — which is exactly the slot G_old itself is using ⇒ **the premise "each generation uses its own pool" is broken by the cross-generation free, and the two processes run concurrently on the same `local_cache[L]`**;
    - therefore **v1.7's sentence "they still race in the same-numbered cache slot even inside different pools" was right**, and **v1.9's "correction" of it was the error** (corrected this round): it is not "inaccurate wording" but **accurate**;
    - **Current state**: this risk **has been eliminated by the R-01 fix** — the per-generation application pool creation point now wraps `ff_shared_pool_cache_size(graceful_reload, MEMPOOL_CACHE_SIZE)` (`lib/ff_dpdk_if.c:669-673`), so `graceful_reload=1 ⇒ cache_size=0 ⇒ rte_mempool_default_cache()` is always NULL ⇒ a cross-generation free no longer touches any `local_cache`. **Eliminated at the mechanism layer plus the build/unit layer; the targeted runtime assertions (PT-NR-09 / RV1) are not executed and remain registered. Rolling back R-01 would make this a live risk again (a dependency coupling, as is BR-02 under the §6.6.2 table).**

    **(2) The race surface therefore converges to a single place: the shared RX pool**
    - **The RX pool cannot be split per generation**: `pktmbuf_pool[socketid]` (`ff_dpdk_if.c:149`) is bound at init by `rte_eth_rx_queue_setup(..., mbuf_pool)` (`:1141`) and **cannot be replaced at run time** (virtio has no queue stop/setup).
    - The access matrix under M1′ (the decisive fact):

      | Path | Who does it | Shared across generations? |
      | --- | --- | --- |
      | RX refill (`mempool_get` inside `rx_burst`) | **G_new only** (G_old does not poll rx) | no |
      | application-side alloc (TX/clone/egress construction, `ff_ref_pool`) | each generation separately | separable (see (3)) |
      | free of an RX mbuf | **both G_new and G_old** (packets G_old receives from `drain_ring_rx` must be freed back to the RX pool after use) | **yes ← the only race** |

    **(3) Application side: per-generation mempools (eliminating all races on this side)**
    - G_old uses `mbuf_pool_%d_gen0` (i.e. the application-side semantics of today's `pktmbuf_pool[socketid]`), G_new uses `mbuf_pool_%d_gen1`; both are **pre-created at init** (with `graceful_reload=1`), avoiding creation-timing problems on the reload trigger path; G_new does an `rte_mempool_lookup` as a secondary.
    - The generation number is reused in ping-pong between gen0/gen1 by reload round; after G_old exits its generation pool is emptied and can be reused by the next generation, so the pool count does not grow with the number of reloads.
    - **Cross-generation frees are naturally correct**: an mbuf carries its own `m->pool` pointer, so `rte_pktmbuf_free` automatically returns it to the right pool with no extra bookkeeping. **[2026-09-17 correction, R-01]** what `m->pool` guarantees is **returning to the right pool**, **not avoiding that pool's per-lcore `local_cache`** — as long as the pool still has a cache, the two cross-generation free paths (the ARP/NDP clone `ff_dpdk_if.c:2654-2678` and the drain_tx send-on-behalf `ff_drain_ring.c:475`/`:479`) put the other generation's process in concurrent access to the same `local_cache[L]`. ~~The per-generation application pool is still created with a bare `MEMPOOL_CACHE_SIZE` (256) (`lib/ff_dpdk_if.c:667-669`), while DR11's M-A (`ff_shared_pool_cache_size()`) covers only the shared RX pool / `message_pool` / `ff_ref_pool` and **does not cover the per-generation application pool**; the two cross-generation free paths (ARP/NDP clone `ff_dpdk_if.c:2654-2678`, drain_tx send-on-behalf `ff_drain_ring.c:475`/`:479`) put the other generation's process in concurrent access to the same `local_cache[L]` ⇒ **the cross-generation free is not eliminated on the per-generation application pool**, and the invariant this design self-declares (`lib/ff_memory.h:40-44`, "local_cache[] is never shared by two processes on the same lcore_id") is not honoured. It must be fixed by C-NR-31x with PT-NR-09 / RV1 re-measurement.~~ **[2026-09-17, same day: the obsolete part above has been annulled by the R-01 fix]** the per-generation application pool creation point has changed to `ff_shared_pool_cache_size(ff_global_cfg.dpdk.graceful_reload, MEMPOOL_CACHE_SIZE)` (**`lib/ff_dpdk_if.c:669-673`**), so `graceful_reload=1 ⇒ cache_size=0 ⇒ rte_mempool_default_cache()` is always NULL ⇒ **the per-generation pool no longer has a per-lcore cache**, the two cross-generation free paths no longer touch `local_cache[L]`, and the invariant self-declared in `ff_memory.h:40-44` **is honoured**. **Current state: eliminated (mechanism layer + build/unit layer); the targeted runtime assertions (`rte_mempool_avail_count` / `rte_mempool_audit()` under heavy drain-time TX plus ARP/NDP injection) are not executed and remain registered, attached to PT-NR-09 / RV1.**
    - ~~The `local_cache[L]` of the two pools are independent of each other ⇒ the cache races of application-side alloc/free go to **zero**~~ **[2026-09-17 correction, R-01]**: splitting per generation only achieves "the two pool objects differ"; **if the pool still carries a per-lcore cache** a cross-generation free still lands in the same `local_cache[L]`. ~~But **each pool carries 256 per-lcore cache entries**; a cross-generation free still lands in the same `local_cache[L]` ⇒ the application-side race **goes to zero only within the subset "each allocates its own and frees its own", not on cross-generation transfer paths**.~~ **[2026-09-17, same day: the obsolete part above has been annulled by the R-01 fix]** the per-generation application pool's `cache_size=0` (`ff_dpdk_if.c:669-673`) ⇒ **the cache races of application-side alloc/free go to zero on all paths** (both the steady-state path and the cross-generation transfer path), and the original sentence holds again.

    **(4) RX pool: two candidate options (DR11 decided with M-A as the main option, M-B as the alternative)**
    - **M-A (simple, with a steady-state cost)**: the RX pool is created with `cache_size=0` (`ff_dpdk_if.c:633-634`, `MEMPOOL_CACHE_SIZE→0`), so alloc/free all go through the common pool's lock-free MP/MC ring. The price is that **it stays in effect in steady state** — two extra ring operations per packet on the RX path. **v1.9.3's DR11 decided M-A as the main option** ⇒ this cost is an accepted item, must be quantified by PT-NR-09, and must lower the §4.1 D5 rating (see §6.6.4).
    - **M-B (alternative, zero steady-state cost)**: the RX pool **keeps its cache**; RX mbufs that G_old has finished with are **not freed directly** but enqueued in batches to `free_ring` (G_old → G_new), and G_new does the unified `rte_pktmbuf_free`. Then both alloc and free of the RX pool involve **only G_new**, so the cache race disappears and cache performance is retained. **v1.9.3: re-judged as the alternative** — merging its free_ring with drain_ring_tx carries the risk of confusing the "to be sent / to be freed" markers, and it adds one more inbound hold compared with M-A (see §24.2).
      - Zero steady-state extra cost: `free_ring` carries traffic only during drain; when G_old does not exist the path never fires.
      - In implementation it can be **merged into one channel** with the existing `drain_ring_tx` (the same G_old → G_new direction), using a private marker on the mbuf (such as `mbuf->udata64` or a free bit of `ol_flags`) to distinguish "to be sent" from "to be freed", avoiding a second ring.
      - Price: during drain each finished mbuf takes one more batched ring round trip; drain traffic decays over time and can be processed in bursts.
    - **Decision (v1.9.3 DR11)**: take **M-A** by default (`cache_size=0`, simple to implement, steady-state cost quantified by PT-NR-09 and required to lower the §4.1 D5 rating); if PT-NR-09 shows M-A's steady-state cost to be unacceptable, upgrade to **M-B** (accepting the implementation volume of `free_ring` and the inbound hold).

    **(5) Regression and observation**: no leak in cross-generation alloc/free (`rte_mempool_avail_count` does not fall monotonically), no pool mismatch (no mbuf check errors/crash), no double free — covered by PT-NR-09 plus the RV1 long-stability observation; **[2026-09-17 note, R-22]** `rte_mempool_avail_count` covers only the common pool and **does not count objects inside the per-lcore cache**; ~~the per-generation application pool keeps 256 cache entries and the two generations are on the same `lcore_id` ⇒ this criterion is **not trustworthy for the per-generation pool (undercounted twice)**~~ **[2026-09-17, same day: annulled by the R-01 fix]** the per-generation application pool's `cache_size=0` (`ff_dpdk_if.c:669-673`) ⇒ `avail_count` **is trustworthy again for the per-generation pool and can be used as an absolute value directly**. **Kept as a prudent practice**: call `rte_mempool_cache_flush()` before asserting (a no-op for a `cache_size=0` pool, which does not change the correctness of the reading, only guards against a future pool configuration rollback), or judge the **trend**. The shared RX pool has `cache_size=0`, so an absolute value can be used. M-A/M-B has been decided by DR11 (**M-A as the main option**), and PT-NR-09 is responsible for quantifying M-A's steady-state cost and giving the basis for whether to switch to M-B.

### 2.1 Target semantics added in v1.9 (13~15)

13. **TX exclusivity and bidirectional `drain_ring` forwarding** (added in v1.9, resolving P0-1/P0-2):
    - **TX exclusivity**: G_new is the only process calling `rte_eth_tx_burst`. G_old's egress during drain (RTO retransmit / keepalive / FIN / data ACK / SYN-ACK retransmit) is **no longer sent by itself** but enqueued to `drain_ring_tx` and sent by G_new on its behalf. **Basis (confirmed in code)**: `ff_dpdk_if.c:2478-2495` is the only `rte_eth_tx_burst` call site in the whole file and `queueid = qconf->tx_queue_id[port]`, while `tx_queue_id` and the rx `queue_id` have the same number (`:486/:534`); `dpdk/lib/ethdev/rte_ethdev.h:6575-6577` restricts lock-free concurrency on the same tx queue to `RTE_ETH_TX_OFFLOAD_MT_LOCKFREE` PMDs (virtio does not declare that capability and F-Stack does no capability probing). Therefore, in the "two generations sharing the hardware queues" form, tx concurrency is a **contract violation** that must be **eliminated at the mechanism level** rather than masked with a lock.
    - **Both rings are created per generation with explicit flags (M4 implementation wording, re-checked against HEAD `28e751259` on 2026-09-17)**:
      - `drain_ring_rx` (G_new → G_old): flags = `RING_F_SC_DEQ` (**MP/SC**) — there are two classes of producer: the flow_map miss forwarding of the owner generation's queue-Q worker, and the ARP/NDP clone fanned out by any owner-generation worker to **each** peer queue (with `nb_queues >= 2` there are necessarily multiple producers); using `RING_F_SP_ENQ` would corrupt the prod head. G_old is the only consumer. Basis: `lib/ff_drain_ring.c:270-273` and the design comments at `:213-224` (the P1-a fix).
      - `drain_ring_tx` (G_old → G_new): flags = `RING_F_SP_ENQ | RING_F_SC_DEQ` (**SP/SC**) — the only producer is `ff_divert_tx_mbuf`, keeping the zero-CAS fast path. G_new is the only consumer and calls `rte_eth_tx_burst` directly after taking them out. Basis: `lib/ff_drain_ring.c:279-282`.
    - **Why `dispatch_ring` cannot be reused**: first, `dispatch_ring` is per-(port,queue) with `RING_F_SC_DEQ` (`ff_dpdk_if.c:710-713`), so under the same queue the two generations would become **two consumers of the same ring** (P0-2); second, `process_dispatch_ring` (`:2222-2236`) dequeues and then enters `process_packets → ff_veth_input` with `pkts_from_ring=1`, i.e. **inbound into the protocol stack**, which is the opposite of the "outbound send-on-behalf" semantics and cannot be reused.
    - **Full-ring behaviour**: a drop when `drain_ring_rx` is full is a drop of **a packet of an established connection** and must be counted and alerted explicitly (today a full `dispatch_ring` is a silent `rx_dropped++`, `:2144-2147`); it must not be silent (see the RV4 revision).
    - **Alternative forms** (DR9 pending review, not the current main path): (a) configure `nb_tx_queues = 2N` at init so each generation uses its own set of tx queues (zero hop, lock-free, but it requires changing the tx/rx same-number allocation at `:486/:534` and depends on hardware multi-queue); (b) G_old does tx directly with a shared-memory spinlock protecting the tx queue (`rte_ethdev.h:6575-6577` allows an application to add its own SW lock; the smallest change, but with lock overhead and priority-inversion risk).
14. **Half-open connection window handling** (added in v1.9, resolving P0-5): for a connection whose SYN was received by G_old before the handover and whose handshake has not completed, the third ACK will land on G_new after the handover → flow_map miss (G_new did not receive the SYN) → forwarded back to G_old → if G_old has already closed listening, `syncache_expand` cannot create the socket → the connection fails. **Basis (confirmed in code)**: `freebsd/netinet/tcp_syncache.c:1033-1055` — after finding the entry through the VNET-private global hash, `syncache_expand` needs `*lsop` (the listening socket) to create the child socket; `freebsd/netinet/tcp_subr.c:2517-2553` — `tcp_close` does only `tcp_offload_listen_stop` + `in_pcbdrop` for `TCPS_LISTEN` and **does not clear the syncache** (`syncache_destroy()` is called only at global destruction in `tcp_subr.c:1583`).
    **Handling (one of the two, (a) preferred)**:
    - (a) **Delayed listening close**: at T4 G_old only **stops accepting**, keeping the listening socket until its own syncache half-open entries have drained or timed out (the syncache has its own timeout and SYN-ACK retransmission), with the shutdown timer as a backstop forcing exit. At this point all new SYNs already belong to G_new (the queues belong to G_new), so keeping listen does not steal new connections.
    - (b) **Export the half-open four-tuples at T3**: at the handover, export the half-open four-tuples in G_old's syncache to G_new and register them in G_new's flow_map as "forward to G_old", so the third ACK is correctly forwarded back.
15. **Generation-independent `queue_id` mapping plus msg_ring / KNI generation isolation rules** (added in v1.9; **simplified in the v1.9 final version per D-A = same `lcore_id`**):
    - **Background (code fact, kept for reference)**: in the current code the number of set bits in `lcore_mask` equals `nb_procs` (`ff_config.c:118/:127/:139`) → `proc_lcore[proc_id]` determines the lcore_id (`ff_dpdk_if.c:572`) → `queueid` = the index of the lcore_id in `lcore_list[]` (`:584-587`) → `tx_queue_id[port] = queueid` (`:598`) → the queue count `nb_lcores = nb_procs` (`ff_config.c:555-574`): the four are bound into one chain. **[2026-09-17 re-scan against HEAD, R-11] the previous anchors `:508`/`:518-524` are stale.** **The v1.9 previous version once tried to add a "per-generation lcore pool" so the two generations would take different lcore_ids; that scheme was rejected and cancelled by the human decision** — see semantics 8 for the reason (the conflict surface of dismantling the chain far exceeds the shared-slot problem). Therefore:
    - **`queue_id`**: generation-independent fixed mapping (continuing v1.6); both generations use the same batch of queues, and `rx_queue_list / tx_queue_id / reta / rss_check` four-piece all stay unchanged.
    - **`lcore_id`**: both generations **take the same `lcore_id`** (D-A decision). `lcore_mask` / `nb_procs` / the queue count **all stay at N with no new configuration items**. The `priv_timer` and mempool shared-slot problems caused by the same `lcore_id` are solved by semantics 11 / semantics 12.
    - **`proc_id`**: the same value for both generations (continuing v1.6's generation-independent mapping, eliminating the ping-pong generation overlap of audit B-1), keeping only its existing `msg_ring[proc_id]` index and the `ff_kni_is_runtime_owner` (`ff_dpdk_kni.c:101-109`) semantics — **and both of these must be isolated per generation**:
      - `msg_ring`: `ff_dpdk_if.c:2903`'s `process_msg_ring(qconf->proc_id, ...)` and the dequeue at `:2457-2470` are both indexed by proc_id, with ring flags `RING_F_SP_ENQ | RING_F_SC_DEQ` (`:764-777`). The same proc_id for both generations would dequeue the same ring, causing READY / DRAIN_DONE / REJECT / HANDOVER_ACK to be received by the wrong side. **Handling**: index msg rings two-dimensionally by `(proc_id, generation number)`, or build one set of rings per generation.
      - **KNI runtime owner**: `ff_dpdk_kni.c:101-109`'s `ff_kni_is_runtime_owner` compares `proc_id == kni.owner_proc_id` fixedly, so after a generation change the owner lands on an exited generation. **Handling**: change the owner marker to follow the **currently active generation**, updated by the master/primary when the handover succeeds (previously RV8, raised to a design constraint in v1.9).
      - **[2026-09-17 registration, R-30 (P2, known degradation; the two sides must be written separately)] KNI bidirectional service stop in the drain window (T3→T5)**:
        - **Mechanism root cause (shared by both sides)**: `kni_owner_gen` flips only in `ff_reload_master_complete()` (T5, `lib/ff_reload.c:1348`) ⇒ throughout the drain window T3→T5 the KNI runtime owner is **still G_old**; and G_old is parked at that point (`no_hw=1`), not polling hardware and not matched by the owner, while G_new fails `ff_reload_kni_owner_match()` ⇒ **no process serves either side of KNI during that window**.
        - **(a) the inject side (kernel → NIC direction, dequeue point `lib/ff_dpdk_kni.c:581`) = a secondary behaviour of this R-02 fix**: after R-02 added a `likely(!no_hw)` gate to `ff_kni_inject_process` (`ff_dpdk_if.c:3676`), G_old no longer dequeues `kni_inject_rp` during drain (its only enqueue point is `ff_dpdk_kni.c:220`, primary_slim && PRIMARY) ⇒ **the ring has zero consumers**. **This is a known degradation newly introduced by this fix** (the direction is right: the previous behaviour was a concurrent TX violation, now degraded to packet loss).
        - **(b) the delivery side (NIC → kernel direction, `ff_dpdk_if.c:2685` receive clone → `ff_kni_enqueue`) = a pre-existing gap of the T5 flip design, not introduced by this R-02**: this path was never gated by `no_hw`, only by `ff_kni_is_runtime_owner()`; within T3→T5 the owner is the parked G_old (which does not poll rx and therefore never reaches `:2685`), and G_new cannot match the owner either ⇒ likewise nobody delivers.
        - **Consequence (same on both sides)**: **no deadlock, no crash**; the primary's enqueue overflows when full, and the mbuf is freed and counted in **`kni_stat[port_id]->tx_dropped`** (`ff_dpdk_kni.c:222-226`); the new generation restores service after T5. **The magnitude is not confirmed** (no targeted real-machine test: rt12 is a KNI form but has no inject load in the window and lasts only 1 s, so `tx_dropped` is always 0 — zero discriminating power).
        - **Trigger conditions**: `[kni] enable=1` + `[dpdk] primary_slim=1` + `graceful_reload=1`, with KNI inject traffic from the kernel side during the drain window. **Not a default combination**.
        - **Fix (not adopted, registered)**: move the `kni_owner_gen` flip from T5 forward to the **T3 hardware takeover moment**. **[G-A §7.8 correction]** that fix is **not self-consistent** on its own and must be extended to flip synchronously at 4 "hardware ownership change points" (including the rollback in `ff_reload_master_abort()` and the heartbeat reclaim at `ff_dpdk_if.c:3727-3728`), of which the "abort rollback" and the "heartbeat reclaim" are **mandatory** — missing either would worsen R-30 from "packet loss during drain" into "the KNI owner hanging on a dead generation and stopping permanently", which is worse than the status quo. Mechanism: `ff_reload_kni_owner_match()` (`ff_reload.c:469-481`) **reads only `d->kni_owner_word`** when the directory is valid, so the flip block must be published through `ff_reload_dir_sync():419-431` to take effect.
        - **Current handling**: code-fixer did not adopt the T3 flip (path B, awaiting the team-lead decision) ⇒ **no supplementary run**; R-30 is closed as "**registered item + known degradation**", with the magnitude still **unconfirmed**, left to a follow-up special topic.
        - **[The qualification of R-02 (G-D ruling; the spec always writes it this way)] R-02 = "mechanism closed, behavioural closure incomplete (no KNI TX inject targeted real-machine test)"**. Closed part: after adding `likely(!no_hw)`, **all four** of G_old's `rte_eth_tx_burst` call sites are unreachable during drain (`send_burst :3075` has a `no_hw` fallback; `ff_kni_process :192/:232` are structurally unreachable as primary-only; `ff_kni_inject_process :586` is newly gated; `ff_drain_ring_tx_drain :505` already had a gate) ⇒ the **original defect of the TX-exclusivity violation is eliminated structurally**. Unclosed parts: ① no targeted real-machine test with KNI TX injection (rt12 is a KNI form but has no inject load in the window and lasts only 1 s, so `tx_dropped` is always 0 — zero discriminating power); ② the secondary behaviour R-30 has not been observed on a real machine. **Therefore R-02 must not claim "completely fixed"** — always write "R-02 is fixed (the TX-exclusivity violation is eliminated); the KNI inject service stop during drain is a known secondary degradation (R-30), magnitude unconfirmed".

---

## 3–9. Remaining sections (summary; to be replaced by a full translation)

> **Status note.** Sections §0–§2.1 above are a full translation of the Chinese document.
> The sections below (Chinese §3–§9, lines 187–744) are still being translated; the content here
> is a faithful summary so that no information is lost in the meantime. The Chinese text remains
> authoritative throughout.

### 3. Candidate set

- **S1 — revive the legacy iWiki scheme (a modernised dispatch middle layer on DPDK 24.11.6)**: a dispatch process holds the global connection table and decides the destination by five-tuple; workers talk to dispatch over lock-free rings; the DPDK primary identity moves from the first worker to the dispatch process. Old and new workers coexist **on the same CPU cores**, relying on (a) different mempools for old and new processes plus disabling the cache / CAS-shrinking the conflict domain for the NIC driver's mempool, and (b) dynamic nice-value CPU weighting (CFS formula `1024/(1.25^nice)`, the new worker starting at nice=19 with 1.7% of a CPU, bound to a reserved core for 1 second at the traffic switch and then bound back).
- **S2 — the ld_preload (adapter/syscall) route**: the stack process holds the connections and nginx acts as a client; see [05](ld-preload-alternative.md) for the mechanism, the three deviations from the existing `ld_preload_ring_spec`, the nginx HUP/USR2 feasibility, the 7 natural advantages and the 10 gaps.
- **S3 — native multi-process evolution (primary_slim-style decoupling + independent worker respawn) [recommended]**: the resident slim primary, generation-independent queue mapping, simultaneous takeover after ready, G_old running software-parasitic, bidirectional drain rings, flow_map, rx mutual exclusion, both generations on the same `lcore_id`, self-driven hardclock and per-generation mempools.
- **S4 — two-process hot standby plus traffic switch (a user-space port of Facebook's "do not cut traffic over before ready")**: old and new instances run in parallel, new connections switch to the new instance, the old instance drains.
- **3.5 combination notes**: the relation of S2+S3 and S1→S3-M2.

### 4. Comparison matrix and grading conclusion

- **4.1 comparison matrix (qualitative rating + one-line basis)** over D1~D7.
- **4.2 grading conclusion**: S3-M1′ recommended, S2 as the alternative, S4 recommended for virtio scenarios, S1 not implemented standalone.

### 5. Key design of the recommended S3

- **5.1 the four-layer ownership model** (process / queue / listening fd / connection), with L2 split into rx/tx/ring rows.
- **5.2 the reload timeline (textual timing diagram, HUP)** — rewritten in v1.9 for "same queue + simultaneous takeover + TX exclusivity".
- **5.3 the mapping to nginx's HUP/USR2 semantics**.
- **5.4 the ff_api / config.ini / ff_msg interface surface to add** (a design list, not an implementation commitment) — including `ff_flow_map_lookup/insert/admit/revoke/cap_set/stats2/close`, the drain-ring interfaces `ff_drain_ring_init()/unregist()`, the KNI-related ownership handling, and the `[reload]` configuration entries; §5.5 covers the relation with existing evolution lines (primary_slim, native_mt, zc_stack, DPDK 23→24).

### 6. Risk list and unconfirmed items

- **6.1 runtime verification (RV)** and **6.2 design review (DR)** lists; **6.3** the `lcore_id` strategy and same-core performance considerations; **6.4** the applicable scope (reta unchanged, usable on virtio and physical NICs); **6.5** the abandonment notes of v1.6 against v1.4/v1.5; **6.6** the detailed design of the per-generation mempools and the shared RX pool (final v1.9: D-A = same `lcore_id`).

### 7. Acceptance against the target semantics (self-check of the recommended scheme)

### 8. Single-source declaration

### 9. v1.9 decision summary (decision record)

## 10. 2026-10-08 cross-audit errata and registrations (mirror of zh_cn 06 §10)

Audited baseline: HEAD `eb6b32c82` (release/2.0). Where this section disagrees with the body, this section wins;
where it disagrees with the code, the code wins.

### 10.1 Code fix

| ID | Problem | Fix | Verification |
|---|---|---|---|
| RX-02 | With `graceful_reload=1` every tx packet ran `ff_no_hw_mode()` → `ff_reload_dir_sync()` (a clock read, a directory scan and a dozen atomics). After a USR2 the dead old master's slot stays LIVE, so every tx packet of the new master's workers issued a `kill(pid, 0)`, breaking the contract in `ff_reload.h` that the full scan must stay off the datapath. | `ff_no_hw_mode_nosync()` (same verdict, no directory sync) for `send_burst()`, `ff_dpdk_if_send()` and `ff_dpdk_raw_packet_send()`; the directory is synced once per main-loop pass and by the ~1 Hz housekeeping. The verdict is not cached (a heartbeat takeover must be seen on the next packet). The neighbour-clone and miss-forward gates read `ff_reload_peer_mirror_draining()`. `epoch_slot_live()` caches the pid probe per slot for 50 ms. | Clean production build with the baseline warning count; unit, harness-unit and integration tests pass; IPv4/IPv6 runtime matrix passes; strace on one worker: 0 kill(2) in steady state, about 20/s during USR2 coexistence. |

### 10.2 Documentation errata

| ID | Where | Old statement | Current statement (per code) |
|---|---|---|---|
| RX-01 | All anchors | The 09-30 conversion from `file:line` to `file: symbol` resolved old line numbers against the new files and pointed many anchors at unrelated functions | Re-checked and re-mapped; anchors that could not be confirmed are marked in place |
| RX-02 | §2 item 6, §7 | "Zero extra per-packet cost in steady state" | Holds for the flow map and drain rings only; each tx packet still reads the rx-ownership words and the directory mirror (no system call), and the directory is synced once per pass |
| RX-03 | §2 items 4/14, §5.2 T4 | The drain starts when G_old receives QUIT; keep-alive can stretch T3 to the deadline | The drain starts when the generation loses rx ownership (after the T3 handover), latched once per round; idle connections are closed then and about once a second afterwards; QUIT still stops accept and closes the listeners late, waiting for half-open entries for at most min(3 s grace, cap). Idle keep-alive connections are therefore closed once per reload; acceptance is zero failed new requests plus a bounded number of closures |
| RX-06 | §5.2 ③-5 | A miss is forwarded only after checking that G_old is alive; otherwise the stack answers RST | No liveness check: the gate is `hw_locked` or `peer_mirror_draining` plus a successful enqueue; otherwise the packet is dropped, counted and logged at a limited rate, never answered with RST |
| RX-09 | §5.4 R-23 | close() memsets the table; a full table is only counted, not reported; capacity fixed at 64K | close() frees the table; 64K entries and probe limit 16 initially; a full table doubles up to 4 times per window (cap `FF_FLOW_MAP_CAP_MAX`); after that, or on an allocation failure, the SYN is refused; full / grow_fail / alloc_fail are reported by the 1 Hz housekeeping |
| RX-12 | §2 item 6, §5.2 ③-5 | Look up first, insert after the SYN-ACK; every miss goes to G_old | Fast path without a window; a pure SYN stays local before any key is built; syncache admits the flow on SYN admission, before the SYN-ACK (cookie entries too), refuses the SYN on a full table or allocation failure, and revokes the admission when the SYN-ACK fails synchronously; UDP is never admitted, so in the window every UDP packet misses (RX-11) |
| RX-13 | §2.1-15 R-30(b) | No one delivers to KNI during T3→T5 | Delivery continues: non-ARP traffic is delivered by G_new, ARP clones by G_old as runtime owner; only the inject side (kernel to NIC) stops. Not re-verified with `enable_kni=1` |
| RX-14 | §5.4-1 handover mutex | A hugepage `struct ff_handover_state` created by the primary | Design-time text: `rx_owner_gen`/`rx_stopped` live in the anonymous `MAP_SHARED` block the nginx master creates before fork; the yielding side writes `rx_stopped=1` then `rx_owner_gen`, the receiver clears `rx_stopped` once it owns; T2 adds the `rx_parked[]` barrier; cross-master ownership is the gendir `rx_owner_word` |
| RX-16 | DR6 note | main_loop is a non-blocking busy loop | The heartbeat tick and the nginx event loop run serially in one pass; if every G_new worker blocks longer than the timeout (default 1000 ms) in one iteration, G_old declares a stall, takes rx back and the master aborts (registered in 10.3) |
| RX-19 | §2 item 1 | Every SYN is accepted at any time | A design goal, not an absolute: a full flow map or allocation failure refuses the SYN, the mbuf low watermark drops SYNs, and a full drain ring drops packets |
| RX-28 | Small items | revoke "fixes" a missing SYN-ACK; T5 is triggered by DRAIN_DONE after the rings are confirmed empty; msg_ring is SP/SC; `ff_ref_pool` is per generation; syncache has no counters; rx ring "8 times larger"; ring names are (port, generation) | revoke covers synchronous send failures only; G_new retires on its own in the 1 Hz housekeeping without checking the rings or waiting for a message; the rings are pre-built by the primary at init and re-attached by the workers when a window opens; the flow map is armed in `ff_mod_init` (before READY); `FF_MSG_RING_FLAGS` = 0 (MP/MC); `ff_ref_pool_%d` is one per socket with cache 0; `ff_syncache_count()` and `ff_syncache_counters()` exist; 4096 is a request the PMD may clamp; names include port, queue, epoch slot and generation; the ring-full counters are plain per-process counters, not atomics |

### 10.3 Registered, not closed (none verified at runtime)

Second round on 2026-10-08: RX-15, RX-29 and RX-30 are fixed with the approaches chosen by the maintainers
(§10.4). RX-10, RX-11, RX-16, RX-20, RX-32, RX-33 and RX-34 stay **registered only; no change is made for
now**.

RX-10 flow-map growth latency spike on the SYN path; RX-11 every UDP packet misses during the window and goes to
G_old; RX-15 (fixed, §10.4) stale packets left in an exited G_old's drain_rx can surface in a later round; RX-16 heartbeat
false positive when the event loop blocks; RX-20 workers that crash during T1~T5 are not respawned; RX-29 (fixed) the
drain ring re-attach can lag a park by up to ~1 s; RX-30 (fixed) `FF_USE_PAGE_ARRAY` builds leak `bsd_m_table` at park;
RX-32 zero-copy rx mbufs held by an exiting G_old are not returned (no growth seen over 100 rounds), and the
§6.6.3 statement that a generation's pools are emptied after G_old exits has no code behind it; RX-33 pid
reuse can keep a dead slot "alive"; RX-34 USR2 requires both binaries built from the same libfstack (already
stated in the nginx guide; second-round correction: `ff_reload_gendir_install()`, called by the primary and the
secondaries alike, already checks magic, version, length, slot_max and gen_max and fails the process on a
mismatch, so the suggested secondary check exists).

### 10.4 Second round on 2026-10-08: RX-15, RX-29 and RX-30

Build RX3 (clean full build): lib 0 errors and 51 warnings (the baseline; none in the changed files), nginx 0
warnings, no fault hooks in the production form. Independent reviews CR-RX and CR-RX2 both PASS; their SHOULD
items were addressed.

| ID | Chosen approach | Implementation | Verification |
|---|---|---|---|
| RX-15 | the resident primary resets the rings when the window closes | The directory moves to version 3 and gains a drain-ring user table `ring_user[2 × FF_RELOAD_MAX_PROCS]` and a purge lock `ring_purge_owner`. A secondary registers an ACTIVE entry before `drain_ring_up = 1` and removes it at the end of `ff_drain_ring_unregist()`; a worker that leaves with exit(0) keeps its entry, and an ACTIVE entry with a dead pid marks rings whose consumer is gone. The primary calls `ff_drain_ring_purge_orphans()` at about 10 Hz: when a ring is non-empty it takes the lock, then counts the users (`ff_reload_gendir_ring_census()`). drain_rx(slot, gen) is emptied when that coordinate has a dead user and no live one; drain_tx only when no secondary has the rings attached (its reader is the hardware owner). Once a slot has no live user its dead entries are forgotten, so in the next round packets for a process that has not attached yet are kept. Attach registers first and reads the lock second; the purge takes the lock first and reads the table second (all SEQ_CST), so either the purge skips the coordinate or the attach waits (the init path up to the reclaim timeout, the main loop not at all). `ff_drain_ring_reset_slot()` runs under the same lock. At most one NOTICE per second: `drain rings: freed N orphaned mbuf(s)`. | Unit tests `test_rx15_ring_user_census_and_purge_lock` (test_ff_config) and `test_rx15_primary_purges_orphaned_rings` (test_ff_dpdk_if, real rte_rings, including the reset under a busy and a free lock and mbuf conservation). At runtime the primary of the rt25 (USR2) stack freed 2 orphaned mbufs. |
| RX-29 | attach synchronously on the hw_locked edge and before a park ack | `ff_reload_plane_attach()` in `ff_dpdk_if.c`: a secondary attaches on the rising edge of `ff_reload_hw_locked()` (`window open`) and again before acking a park (`park`); the housekeeping attach uses the same function (`peer master` under USR2). It never blocks the loop (`ff_drain_ring_try_init()`); a failure is retried after 10 ms and logged at most once a second, and the ack does not wait for it. Retirement also requires `!ff_no_hw_mode_nosync()`, so a parked process never retires and re-attaches in turn. | rt01 went from T1 to T2 in 161 ms (the old code could take up to ~1 s to attach, dropping what a parked G_old sent meanwhile). G_old logs `reload data plane attached (window open, generation N)` as the window opens: 12 times in the IPv4 batch, 60 in rv9 30 rounds, plus 2 `peer master` under USR2; no attach failure. |
| RX-30 | refuse graceful_reload=1 in that build | The graceful check in `ff_config.c` fails with `graceful_reload=1 is not supported in FF_USE_PAGE_ARRAY builds` under `FF_USE_PAGE_ARRAY` (ff_config.c is a host source and gets the macro from `HOST_CFLAGS`). The refusal happens when the resident primary loads its config; the master only reports that the slim primary did not become ready, the reason is in `/var/run/ff_slim_primary.log`. | New test binary `test_ff_config_pa` (ff_config.c built with `-DFF_USE_PAGE_ARRAY`): graceful=1 refused, graceful=0 loads. |

The approaches were chosen by the maintainers; where this text and the code differ, the code wins.

Runtime (build RX3, production form): IPv4 precheck, rt01, rt02, rt23, rt25, rt30, rt31 **7/7 PASS**; IPv4 rv9
30 rounds `ok=30/30`, flat rtemap, hugepages back to 2048; IPv6 precheck, rt01, rt02, rv9 20 rounds
**4/4 PASS** (rt02 36/36 streams intact, rv9 `ok=20/20`, flat rtemap). Unit tests pass (UT_RC=0), harness unit tests 53
OK, integration 4/4.

Residuals (registered): back-to-back HUP drops ARP/NDP clones sent to the next process before it attaches (the
dead marker is still there; the process resolves on demand); counting is per (slot, gen), not per queue, so a
single worker respawned while its siblings live still meets its queue's leftovers (related to RX-20); under
USR2 the old slot's markers are forgotten once it has no live user, and what is forwarded afterwards (until the
slot stamp goes stale, about 2 s) is freed by `ff_drain_ring_reset_slot()` when a new master recycles the slot;
the directory layout changed, so old and new libfstack builds cannot be mixed — restart everything, including
the resident primary.

### 10.5 2026-10-10: RX-35, the resident primary is reused without comparing configs (no worker starts once KNI is enabled)

Plan: `docs/nginx_reload_spec/plan_kni_fix.md` (version 4, four plan-gate rounds). Where this text and the code
differ, the code wins.

**Symptom.** With graceful_reload=1, start without `[kni]` (the resident slim primary comes up and stays), stop the
master (the primary stays by design; corrected 2026-10-12: since RX-37 stop and quit stop it too; the scenario now
needs a SIGKILL of the master and its workers, since surviving workers count as users and the start is refused,
and a start before the primary exits on its own, or a larger `NGX_FF_SLIM_PRIMARY_ORPHAN_MS`, as rt27 does, see
§10.7), switch the f-stack config to `[kni] enable=1` and start the master again: it
logs `resident slim primary found, reusing`, every worker logs `vdev_scan(): Received 0 vdevs` and then
`EAL: PANIC in ff_kni_alloc(): create kni ring failed!`, and no worker survives. A clean start with KNI works.

**Root cause.** `ngx_ff_slim_primary_ensure()` reused any live primary (pidfile, `kill(pid,0)`, comm) and never
compared the f-stack config the primary was started with; the primary reads it once. Device-side shared objects
(ports and queues, mbuf pools, rings, the KNI virtio_user and `kni_ring_<port>`/`kni_inject_<port>`) are created by
the primary from its own config, while each secondary looks them up according to its own config and panics when a
KNI ring is missing. Not related to 35bf93dc1; the gap dates from the M1 resident primary (13d1b4ec7). The same
holds for every other primary-side setting, which the fix covers as well.

**Fix** (graceful_reload=1 only; graceful_reload=0 and single-process mode do not reach it):
- `ff_primary_conf_digest()` (lib/ff_config.c): FNV-1a 64 over the device-side keys, parsed with the library's own
  `ini_parse()` (the same section/name/value split, whitespace trimming and `;` comments as `ff_load_config()`);
  the digest covers the parsed value text, only `[kni] enable` is also read with `atoi` for the log lines. `[dpdk]` minus the
  per-process keys (log levels and prefix, idle_sleep, pkt_tx_delay, reload_heartbeat_timeout_ms); `[kni]`
  enable/owner_proc_id/kernel_packets_ratelimit (method, tcp_port, udp_port, console_*, general_* and kni_action
  are per process); `[portN]`/`[vdevN]`/`[bondN]`/`[vlanN]` minus addr, netmask, broadcast, gateway, addr6,
  prefix_len, gateway6, vip_*, if_name and ipfw_pr. Every other section (FreeBSD, pcap, stack, rss_check, ...) is left out.
- The primary writes `/var/run/ff_slim_primary.conf` (pid, start time, digest, kni, the EAL runtime directory it
  really uses via `ff_eal_runtime_dir()`) before its pidfile; a record only counts if pid and start time match.
- `ff_primary_users()` counts the primary's live secondaries by `connect()`ing their `mp_socket_*`; only
  ECONNREFUSED/ENOENT mean gone, an unreadable directory means "in use".
- `ff_primary_reuse_check()`: no valid record → refuse; same digest → reuse; different digest with users (or an
  unknown count), on a USR2 start, or in the "externally-started" branch after a spawn timeout → refuse; different
  digest, no user, fresh start → rebuild: re-count users, `pidfd_open()`, verify comm and start time,
  `pidfd_send_signal(SIGTERM)`, wait up to 10 s until the process is gone, its start time changed, or it is Z/X
  with only the thread-group leader left; then drop pidfile and record and spawn again. **A refusal signals
  nothing**; its EMERG names the pid and the reason (the record file; both kni values and the user count when the
  primary is in use; both kni values on a USR2 or externally-started start).
  During a rebuild, users found on the re-count, a failed identity check or no pidfd support also refuse without
  a signal. If SIGTERM was sent but the primary does not exit within 10 s, the master logs `did not exit within
  10s after SIGTERM; not escalating` and refuses; it never sends KILL, and the pending SIGTERM still ends the
  primary once it runs again. Without pidfd support the log says `pidfd unsupported`.
- HUP: after the USR2 rollback, in-flight, binary-upgrade and shared-state checks and before the FSM leaves T0, a
  different digest is rejected with `graceful reload rejected: fstack config differs from the resident slim primary
  (kni A -> B); restart nginx and the slim primary to apply it` (a missing record with `... has no valid record;
  restart nginx and the slim primary`); the FSM does not move and G_old is untouched. If the new nginx.conf points
  `fstack_conf` elsewhere, the new path is compared again after `ngx_init_cycle` and a mismatch takes the existing
  abort path (`the new fstack_conf differs from the resident slim primary`, FSM already in T1, G_old untouched).
- Each generation reads a private 0600 snapshot `/var/run/ff_nginx_fstack.<pid>.<start>.<seq>.conf`; a HUP switches
  it only after the precheck and `ngx_init_cycle` succeed, before spawning G_new. A rejected HUP or a crash after the
  file was edited therefore respawns from the generation's own snapshot instead of looping on a panic. Every exit
  path drops its snapshots; a starting master sweeps those of masters that are gone.
- The secondary's panic text is now `kni ring %s not found: the primary did not create it (is [kni] enable=1 in the
  primary's config?)`.

**Verification** (build K, clean full build, lib warnings equal to the baseline of 51, nginx 0, no fault hooks):
unit tests `test_rx35_*`, `test_ff_eal_runtime_dir_forward` and the harness test for `launch` pass with the whole
suite (harness unit tests 54, integration 4/4). New case **rt27** passes all ten steps: HUP, USR2, a second master,
a missing record and a stopped primary are refused without touching the service; kni 0→1 and 1→0 each rebuild the
primary (`veth0` appears / disappears); no panic and no leaked snapshot. rt12 with the management plane passes
(`ping_client=ok`). The IPv4 batch (precheck, baseline, rt01, rt02, gr0, rt23, rt25, rt30, rt31) passes 9/9, IPv4 and IPv6 rv9 pass 100/100 each (flat rtemap, hugepages back to 2048), IPv6 precheck, rt01, rt02 and rt27 pass, and rt27 rerun with per-step evidence lines still passes on both families (no KILL request; no exited master left a snapshot behind, see the testing plan for the
evidence). Test-evidence audit: TA FAIL (four evidence-chain items) → TA2 PASS. User instance: the reported steps (kni=0 primary stays → `[kni] enable=1` → master restarted) now log `restarting the resident slim primary ... ([kni] enable 0 -> 1)`, a new primary comes up with `veth0`, both workers run, no panic; a HUP under client traffic completes with 2014/0 short requests and an intact 50 MB download, leaving one snapshot. The instance is left running with KNI on.

**Residuals (registered).** Secondaries between fork and EAL socket creation are invisible to the user count (the users are
re-counted right before the signal); a HUP
aborted after the snapshot switch respawns G_old from the new snapshot (same digest, per-process keys apply early);
the precheck passes when the primary is dead (unchanged); a rebuild needs pidfd (Linux 5.3+ and libc headers that define `SYS_pidfd_open` and `SYS_pidfd_send_signal`) and its DMA safety was
measured on igb_uio only (vfio-pci is argued, not tested); the digest covers value text in file order, so a missing
`[kni]` section and `enable=0`, or `lcore_mask=7` and `0x7`, differ (handled on the safe side); a rebuild refused
because the primary did not exit leaves the SIGTERM pending, so that primary exits once it runs again; an older
build's primary has no record, so upgrading across this fix needs nginx and the resident primary fully stopped
(USR2 across it is refused); this still holds after RX-37, whose fix does not reach the master of an older build.

### 10.6 2026-10-12: RX-36, the F-Stack tools do not work on a graceful deployment

Only `tools/` changed. Where this text and the code differ, the code wins.

| ID | Symptom | Root cause |
|---|---|---|
| A | With `[dpdk] file_prefix` set, every tool fails at once: `EAL: Cannot open '/var/run/dpdk/rte/config'` / `Error with EAL initialization` | `ff_ipc_init()` hard-codes its EAL arguments without `--file-prefix`, while the stack runs with `--file-prefix=container-<file_prefix>` (`container` for a `[vdevN]` setup without file_prefix). Same in upstream dev; see also F-Stack issue #419. |
| B | Every tool prints `ETHDEV: Device <kernel NIC> is not driven by the primary process`; a tool interrupted inside `rte_eal_init` leaves every later secondary (tools and the workers of the next HUP) hanging in `rte_eth_dev_attach_secondary()` | The tools probed every PCI device while holding the ethdev spinlock in the primary's shared memory; the lock was read as 1 with gdb on the live host. |
| C | `ff_ngctl` crashes on every run | `ff_ipc_exit()` ran `rte_eal_cleanup()`, then the `close_ng_socks()` destructor allocated from the unmapped pool. Dates from 2021, unrelated to reload. |
| D | A long-running `ff_top`/`ff_traffic` exits with `fstack ipc message error` when the old generation leaves; the sample spanning the switch shows wrapped values such as 18446744073709551398 | The auto-resolved generation was probed once and cached; the new generation's counters start at zero. |

Fix: the EAL file prefix comes from `FF_FILE_PREFIX` (validated), else from `runtime_dir` in the live resident
primary's record `/var/run/ff_slim_primary.conf` (pid and start time checked, direct child of `/var/run/dpdk/`,
no heap use before the EAL), else the DPDK default, and a failed EAL start suggests `FF_FILE_PREFIX`; the tools pass
`--no-pci`; ngctl closes its sockets before
`ff_ipc_exit()`, which is idempotent and makes later allocations fail cleanly. A follow mode
(`ff_ipc_set_follow()`, off by default, enabled only by `ff_top` and `ff_traffic`) re-probes the auto-resolved
generation before a send once it is older than 100 ms, keeps the old coordinate if the probe fails, and bumps
`ff_ipc_target_seq()` when the target moves; the two tools skip that delta (and the `-P` total) and retry a
failed request once after `ff_ipc_gen_invalidate()`. The probe asks the pair that answered last first and frees
its own late replies, so a slow primary cannot fill the reload out ring or exhaust the message pool. Also fixed:
`ff_traffic`'s usage text and its `-s -P` drop columns.

Verification: clean tools build with no compiler warnings (`-Werror`; the log has two awk notes from the build
scripts); `test_ff_ipc` 16/16 including
`test_ff_ipc_file_prefix`, `test_ff_ipc_alloc_after_exit`, `test_p4_gen_refresh` and
`test_p4_probe_releases_late_reply` (which fails without the fix), all unit tests and the ring-name mirror check
pass; on the user's instance (file_prefix set, KNI
on) all eleven tools work with no extra option, four samplers run through three HUPs and a USR2/WINCH/QUIT
upgrade with no error and no wrapped value while the client sees 8889/0 failures, the tools work in the
dual-master window, after the upgrade and after SIGINTs; a `graceful_reload=0` stack on the default prefix, with the
record of an exited primary left behind, passes 6/6.

Residuals (registered): only `ff_top`/`ff_traffic` follow reloads (`netstat -w` and the like still exit when
their generation leaves); two reloads between samples that land on the same generation are not seen; a stack on
a non-default prefix without a primary record needs `FF_FILE_PREFIX`, and with a graceful and a default-prefix
stack on one host the tools pick the graceful one (`FF_FILE_PREFIX=rte` selects the other); an ethdev lock already leaked by an older tool needs a
primary restart, and with KNI on the tools still attach `virtio_user0` through the vdev scan (a brief lock hold).

### 10.7 2026-10-12: RX-37, the resident primary is left behind when nginx stops

Plan and ledger in the local `work/stop-fix-20261012/` (sections 5 to 8 of plan.md are the revisions after each
gate, section 9 is the review ledger). Where this text and the code differ, the code wins.

**Symptom.** With graceful_reload=1, `nginx -s stop`, `nginx -s quit` and a SIGKILL of nginx by process name (pkill
without `-f` matches comm) all leave the resident slim primary behind (comm `ff_slim_primary`, shown by ps under the
master's title `nginx: master process ...`). It keeps the EAL primary lock of the file prefix, the NIC, the
hugepages and the KNI port: a start that needs to be the primary of that prefix (a graceful_reload=0 start, for
example) fails with `EAL: Cannot create lock on '.../config'. Is another primary process running?` and `primary
worker process failed to initialize`; other configs depend on the reuse verdict (refused with an invalid record or
while it is in use).

**Root cause.** The M1 decision (milestones §M1, DR1 candidate b) detached the primary from the master with a
double fork and setsid and only considered that an exiting old master must not take it down;
`ngx_master_process_exit()` never stopped it and the primary never checked whether a master was left. That is the
"the primary stays by design" of the §10.5 symptom and the full stop of nginx and the primary that its residual
6 asks for.

**Fix** (graceful_reload=1, master mode only):
- `ngx_master_process_exit()` calls `ngx_ff_slim_primary_release()` before nginx.pid is removed, after every worker
  of this master has been reaped; stop and quit (TERM/INT/QUIT) take this exit. It keeps the primary, with a
  NOTICE, for the other master of a USR2 upgrade (`ngx_new_binary != 0`, or `ngx_inherited && getppid() ==
  ngx_parent`), for an invalid record and while `ff_primary_users()` is not 0 (-1 counts as in use); otherwise the
  existing `ngx_ff_slim_primary_stop()` (pidfd, comm and start time checked, SIGTERM, up to 10 s, never KILL) runs
  and logs `graceful_reload: stopped the resident slim primary (pid N)`.
- Once a second, `ngx_ff_slim_primary_loop()` in the primary reads `ff_primary_users(ff_eal_runtime_dir())` and
  the new lib query `ff_reload_gendir_masters_live()` (masters in the directory slots that still run; the primary
  slot and the caller are skipped, Z/X counts as gone, -1 without a directory). With both at 0 (either -1 counts as
  in use) for 10 s after it had a user (`NGX_FF_SLIM_PRIMARY_ORPHAN_MS` from the master's environment, 3000 to
  3600000 ms, otherwise the default) it logs `ff slim primary (pid P): no master or worker for N ms, exiting` to
  `/var/run/ff_slim_primary.log` and calls `ff_stop_run()`; at least 180 s (the larger of ORPHAN and 180 s) if it
  never had a user, unless a directory slot
  was already claimed by a master (`ff_reload_gendir_masters_seen()`, the primary slot and self skipped), which
  covers a master and its workers dying within the first second. A primary that creates the directory always
  clears it instead of trusting reused hugepage content. It leaves pidfile and record
  in place (both are self-checking), so a master starting while the EAL lock is still held cannot race it.
- A primary that had a user and is counting writes `/var/run/ff_slim_primary.idle` (`pid start_time`, atomic rename)
  and removes it once it is used again. `ff_primary_reuse_check()` gains `idle`: invalid record → refuse; inherited
  → reuse with the same digest, else refuse; no user and (idle or a different digest) → rebuild; same digest →
  reuse; else refuse (identical to the old verdict with idle=0). A start right after the masters were killed
  therefore rebuilds the primary (`restarting the resident slim primary (pid N): no master or worker uses it`)
  instead of reusing one that is about to exit.
- `ngx_ff_slim_primary_stop()` treats a target that is already gone (ESRCH from pidfd_open/pidfd_send_signal,
  ENOENT/ESRCH from `/proc`, a changed start time) as stopped and only removes the pidfile, record and idle files
  that still name it; a new primary only drops an idle marker whose primary is gone.

**Verification** (final build S10: S7 closed the gap IPv6 rt28 step 4 found on S5, S8 adds the pid to the self-exit line, S9 and S10 change comments only and each had a targeted rerun; clean full build, lib warnings equal to the baseline of 51, nginx 0, no fault hooks):
`test_rx37_primary_reuse_check_idle`, `test_rx37_gendir_masters_live` (no directory, primary slot and self skipped,
a running master counts, a reaped or zombie one does not; `masters_seen` counts an exited master but never the
primary slot or self) and `test_rx35_primary_reuse_check` (unchanged with
idle=0) pass with the whole suite (harness unit tests 54, integration 4/4). New case **rt28** (KNI on) passes all six
steps: stop and quit take the primary with the last master (pidfile, record and idle file gone, veth0 gone); a new
start reloads with fsm=6; after SIGKILL of master and workers the primary reports idle and the next start rebuilds
it; after another SIGKILL it exits on its own after 11 to 12 s (criterion: at least 8 s, within 40 s) with its
log line carrying the pid; the old master of a USR2+WINCH upgrade
keeps it on QUIT and stopping the new master stops it. rt27 now creates its left-behind primary by SIGKILLing the
master and its workers (ORPHAN 600 s inside the case) and passes all ten steps. Regression: On build S5 the IPv4 batch (precheck, rt01, rt02, rt23, rt25, rt30, rt31) passes 7/7 (rt02/rt23 36/36 streams intact, rt25 fresh_fail=0, rt30 n=203252 fail=0), rt12 with the management plane passes, IPv4 rv9 passes 30/30 (flat rtemap, hugepages back to 2048) and IPv6 precheck, rt01, rt02, rt27 and rv9 20 rounds pass. IPv6 rt28 step 4 failed on S5: master and workers died within the first second of the primary, so its once-a-second check never saw a user, took the 180 s branch without an idle marker and the next start reused it. Build S7 closes this with `ff_reload_gendir_masters_seen()` and always clears a directory it creates; on S7 the IPv4 precheck, rt01, rt02, rt25, rt27 and rt28 pass 6/6, rt12 passes, IPv4 rv9 passes 10/10 and IPv6 precheck, rt01, rt27 and rt28 pass 4/4. Build S8 only adds the pid to the self-exit line; IPv4 precheck, rt01, rt27, rt28 and IPv6 precheck, rt28 pass on it, and the self-exit lines match the pids of step 5. Every .c/.h change was followed by a clean full build (S1 to S8, lib warnings 51, nginx 0). User instance
`/usr/local/nginx_fstack` (file_prefix=gr_live, KNI on): about 2 s after `nginx -s stop` and after `nginx -s quit` the master, workers and primary are all gone together with pidfile, record and veth0; after a SIGKILL by process name (comm nginx) of master and workers the primary writes its idle marker and exits on its own 10 s later (`ff slim primary (pid N): no master or worker for 10002 ms, exiting`); every restart serves (client HTTP 200), and the instance is left running with KNI on.

**Residuals (registered).** The release only looks at users: another master with no worker at that moment (starting,
or between worker respawns) can lose its primary, and two fresh masters starting at once are not supported; with
TERM to both masters during USR2 neither stops it and the self-exit takes about 10 s; a reused master pid keeps the
primary up (same class as RX-33) and hidepid on `/proc` can mislead the liveness checks (root is not affected); a tool
attaching to an idle primary before the next start makes that start reuse it, and a new worker then has 10 s to
attach (seconds measured); a USR2 new binary gets an environment rebuilt by nginx without
`NGX_FF_SLIM_PRIMARY_ORPHAN_MS` unless the `env` directive passes it, which only matters for a primary that master spawns later; after a stop the hugepage files and `/var/run/dpdk/<prefix>` stay, as with
graceful_reload=0, until the next primary of that prefix; an older build's master does not stop its primary
(upgrade as in §10.5 residual 6), and two graceful stacks with different prefixes share `/var/run/ff_slim_primary.*`
(existing limitation); the occasional `kevent() error on 1024 ... (9: Bad file descriptor)` ALERT of a draining
worker predates this fix (it is in the RX3 and G2 logs) and is not addressed here; an unreadable runtime directory
(`ff_primary_users()` = -1) keeps the primary up for good, on the safe side, as before.

### 10.8 2026-10-12: RX-38, nginx does not start once mtu=9000 is set

Plan and ledger in the local `work/mtu-fix-20261012/` (01-root-cause.md is the reproduction, 02-plan.md the design
and its review). Where this text and the code differ, the code wins.

**Symptom.** With graceful_reload=1, a `[port0] mtu=9000` in the f-stack config keeps nginx from starting; commenting
it out works. The daemonized master waits the full 60 s, error.log only has `graceful_reload: slim primary failed to
become ready within 60s`, and `logs/nginx.pid` keeps the pid of the master that is gone (seen with `cat` at the time,
raw output not archived).

**Root cause.** Two layers. (1) The config is invalid: by the MTU feature's contract a `[portN] mtu` above 1500 needs
`[dpdk] mtu_enable=1` (`docs/mtu_change_spec/08-interface-and-config-design.md`; `ff_check_config()`: `port%d mtu
%u > 1500 requires mtu_enable=1`), and `mtu_enable`, `max_mtu` and `mbuf_mode` were still commented out.
graceful_reload=0 rejects the same config (reason on the terminal, `primary worker process failed to initialize` in
error.log; seen on the terminal and a temporary instance, raw output not archived), so this layer is not a graceful
issue and the contract stays. (2) Graceful mode hid the reason, which is the defect fixed here: the resident primary
exits in `ff_init()` -> `ff_load_config()`, before EAL, with the reason only in its own stderr
(`/var/run/ff_slim_primary.log`, already noted for RX-30 in §10.4); `ngx_ff_slim_primary_ensure()` waited once on a
POSIX semaphore in shm for 60 s and could not see the grandchild die; and the seven fatal `exit(2)` of the graceful
start block, plus the worker-0 attach failure at first start, did not remove nginx.pid, whose pid may be reused so
that a later `nginx -s stop` signals an unrelated process.

**Fix** (nginx side, `ngx_process_cycle.c` only; lib unchanged):
- Readiness is a pipe instead of shm + semaphore: `pipe2(O_CLOEXEC)`, both ends moved above fd 2 with
  `F_DUPFD_CLOEXEC` (the grandchild rebinds 0-2). The grandchild keeps the write end when it closes inherited fds and
  writes one byte where it used to `sem_post`; the master closes the write end right after fork and `poll()`s the
  read end until the same 60 s deadline (`NGX_FF_SLIM_PRIMARY_READY_SEC`, on `ngx_current_msec`, monotonic). One byte
  means ready (log unchanged); EOF means the grandchild, or the intermediate child, died before it got ready,
  reported by the kernel at exit whoever reaps it and whatever the pid becomes; a timeout keeps the old logic (reuse
  an externally started primary, or `failed to become ready within 60s`).
- The reason: before fork the master notes the size of `/var/run/ff_slim_primary.log`; on EOF
  `ngx_ff_slim_primary_log_reason()` reads only what was added since (at most the last 1023 bytes, from the start if
  the file was truncated; `O_NOFOLLOW` + `S_ISREG`), takes the last non-empty line and replaces unprintable bytes
  with `?`. The EMERG reads `graceful_reload: slim primary exited during initialization: "<reason>" (see
  /var/run/ff_slim_primary.log)`, without the reason part when none is found.
- Concurrent cold starts: if the added text has EAL's `Is another primary` (another master is bringing a primary up
  and ours lost the lock), the master checks `ngx_ff_slim_primary_alive()` every 200 ms until the deadline and then
  reuses it as an externally started primary, with a NOTICE; otherwise it fails.
- `ngx_ff_master_start_fatal()` (`ngx_ff_conf_snapshot_drop_all()` + `ngx_delete_pidfile()` + `exit(2)`) replaces the
  seven fatal exits of the graceful start block and the worker-0 attach failure outside a reload round, which covers
  every call of `ngx_start_worker_processes()` outside a reload round: the first start, the 15 s primary-worker gate
  of graceful_reload=0 (`primary worker process failed to initialize`), the graceful_reload=0 HUP and USR2 binary
  paths, `ngx_restart` and the worker respawn of a HUP rollback during USR2; these now remove nginx.pid too, with the
  timeout unchanged. A failing USR2 binary removes the nginx.pid it wrote itself; the old master still renames
  `nginx.pid.oldbin` back when it reaps it.

**Verification** (build M2: M1 plus the review items, an ALERT on a failed read, a checked write, the worker-0 attach
exit and a few small ones; clean full build, lib 0 error / 51 warning as the baseline, nginx 0 warning, 0 fault hooks
in the production form). The user's default instance as is (only `mtu=9000`): before, 60 s and a generic error (the
three EMERG lines are copied in `user-errorlog-excerpt.txt`) and a stale nginx.pid (not archived); after, on M2 the
master exits in 0.15 s (`user-m2-a.txt`; about 0.25 s on M1, backed only by its EMERG line (line 6 of the excerpt),
timing not archived) with `slim primary exited during initialization: "port0 mtu 9000 > 1500 requires mtu_enable=1"`,
no nginx.pid (`user-m2-a.txt`) and no process left (seen with ps, not archived; rt29 step 2 asserts on M1 and M2,
IPv4 and IPv6, that the refused master is gone and no primary is alive). With `mtu_enable=1` and `max_mtu=9000`
(measured on the build before the fix on a temporary instance; these paths are not touched; **raw output not
archived**, only the notes in 01-root-cause.md): `mbuf_mode=large` and `scatter` both start within 2 s under graceful
reload, HUP works, USR2 + WINCH + QUIT works with scatter (the new master reuses the primary), 64 MiB downloads match
by md5 (large 3/3, scatter 3/3, scatter after USR2 2/2, graceful_reload=0 2/2); graceful_reload=0 behaves the same;
the lib MTU code needs no change. Archived on M2 (`user-m2-mtu-evidence.txt`, the user's instance with
`mtu_enable=1`, `max_mtu=9000`, default large mbufs): the installed binary's sha256 equals the M2 manifest,
`f-stack-0` and the route to the client show mtu 9000 on both workers, the hostcache is empty, four client requests
return 200, and the client sees `mss 8460` in its SYN and `mss 1424` in the SYN-ACK of both F-Stack and the host's
kernel stack (eth1, mtu 1500, recorded at the end of `user-errorlog-excerpt.txt`). The HUP on the user's instance is
backed by the `signal process started` line and the new worker pids in the same excerpt. New case **rt29** passes its
three steps (stop of a 1500 stack; `mtu=9000` alone refused, criterion 20 s, measured 1 s with the reason, no
nginx.pid, no primary, no 60 s timeout; with `mtu_enable=1` ready, HTTP 200, mtu 9000 and a HUP with fsm=6). The
harness's `expect_refused` now takes the refused master's pid from its `[emerg] <pid>#0:` line and then requires the
pid file to be gone. IPv4 on M2: precheck, rt01, rt02, rt25, rt27, rt28 and rt29 7/7 PASS, rt12 with the management
plane PASS; IPv6 precheck, rt01, rt27, rt28 and rt29 5/5 PASS. On the user's instance, after adding `mtu_enable=1`
and `max_mtu=9000`, both workers show mtu 9000, HTTP returns 200 and a HUP hands over to new workers.

**Residuals (registered only).** End-to-end jumbo TCP cannot be checked here: the client NIC has mtu 8500 and its SYN
says `mss 8460`, while the SYN-ACK of F-Stack and of the host's kernel stack (eth1, mtu 1500) both arrive as `mss
1424` (captured on M2 in user-m2-mtu-evidence.txt; seen the same way before the fix with both graceful forms and
graceful_reload=0, raw output not archived), which suggests that the cloud path clamps the MSS (inferred only)
(F-Stack side: empty hostcache, route mtu 9000, `tcp_mssopt()` should offer 8960; not captured on the F-Stack side,
`[pcap] enable=1` wrote no file under graceful reload (the ledger `pcap/` directory is empty), not pursued). The KNI
port stays at 1500 (existing design); set the kernel-side veth0 by hand (`ip link set veth0 mtu 9000`) if needed.
Only the last added log line is reported: a failure after EAL may yield a generic `Cause: ...` line, and two
primaries writing at once may yield the other one's line. The single-process refusal of graceful mode and the
master-title allocation failure still keep nginx.pid; after a worker-0 attach failure the primary is left to its own
exit (§10.7) and the worker semaphore in /dev/shm stays, as before; the code comment above that exit still says
"First-start and respawn paths keep the native exit(2)", registered and left for the next code change. The MTU keys
are device-side and part of the primary digest: a HUP is rejected, a full restart applies them. `ff_dpdk_init()`
reports nb_procs/proc_id errors with `printf` to stdout, which is /dev/null for the primary (existing).
