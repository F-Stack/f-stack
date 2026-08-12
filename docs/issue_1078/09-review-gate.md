# 09 - Review Gate Report

> Reviewer: gatekeeper (independent review agent, strictly separated from all writers)
> Review time: 2026-08-07 21:20-21:50 (UTC+8)
> Review target: `docs/issue_1078/zh_cn/` documents 00-08, 10 (10 documents) + PoC patch + probe script + issue-ana updates
> Review method: All judgments from actual `read_file`/`awk`/`grep`/`git` commands, **no impression-based judgments**

---

## Overall Verdict: PASS_WITH_NOTES

**Summary**: D1 spot-checked **43 file:line references**, **0 fabricated/completely wrong**, 41 exact match, 2 ±1 line minor deviation with matching content. D5 constraint compliance **all passed** (zero real IP hits, no bare rm/kill/chmod, `lib/` workspace clean, `config.ini` not committed). D2 numerical consistency verified. **No blocking-level issues**, verdict PASS_WITH_NOTES; but **3 important-level** and **5 suggestion-level** items to fix.

### Key Findings (5)

1. **Code reference quality above expectation**: All 43 spot-checked references in `lib/ff_dpdk_if.c`, `lib/ff_config.c`, `lib/ff_dpdk_kni.c`, `tools/compat/ff_ipc.c`, `dpdk/kernel/linux/igb_uio`, virtio PMD, EAL, `multi_proc_support.rst`, `tests/` infrastructure **all exist and content matches**. No fabricated line numbers, APIs, sections, or issue numbers.

2. **Important: Broadcast/multicast KNI gate line number self-contradictory in `04` and `07`**. Actual gate at `ff_dpdk_if.c:2080` (`2081` is `mbuf_pool = ...` assignment). `02:76`, `03:357`, `04:4/19/68/108`, `10:113` correctly write **2080**, but `04:208`, `04:227`, `04:423`, `07:162` (C28) still write **2081**.

3. **Important: `10` summary "6 experiment sets" contradicts `10`'s own document index "E1/E2/E2b/E2c/E2d/E2e/E5/E10/E3" (9 sets)**, also inconsistent with `05` actual content.

4. **Important: `01` marks "#1078 no comments, no associated PR" as "verified", but self-described evidence is "leader-provided task context + local ledger"** (`01:185`), while `01:199`/O-2 admits inability to reliably fetch GitHub content → wording conflicts with own honest boundary.

5. **Two blocking-level hazards observed during review already fixed by leader** (honest documentation): At 21:20 first read, `00` key conclusion 4 still had E2e-disproven old conclusion "in-place recovery path blocked", `05` §VI E2c conclusion had no correction pointer; at 21:36-21:37 recheck, both had been updated with "corrected per subsequent experiment" notes. **Judged as passing per current on-disk state**, not counted as bounce items.

---

## I. D1 Code Reference Accuracy (43 items spot-checked, ≥25 required)

Legend: ✅ exact match | ⚠️ line ±1-2 but content matches | ❌ wrong/fabricated

### 1.1 `lib/ff_dpdk_if.c` (15 items)

All 15 verified ✅ or ⚠️ (2 items ±1 line). Key references:
- `:508-510` rte_exit on nb_rx_queue==0 ✅
- `:535` mbuf pool formula ✅
- `:836` nb_queues = pconf->nb_lcores ✅
- `:487-491` queueid = lcore index in lcore_list ✅
- `:821-825` total_nb_ports *= 2 ✅
- `:1061-1063` init_port_start primary gate ✅
- `:2080` broadcast/multicast KNI gate ✅
- `:2765` ff_kni_process() call ✅

### 1.2 `lib/ff_dpdk_kni.c` (8 items)
All verified ✅.

### 1.3 `lib/ff_config.c` / `ff_config.h` (5 items)
All verified ✅.

### 1.4 DPDK source (10 items)
All verified ✅. Including:
- `igb_uio.c:352-366` pci_clear_master ✅
- `virtio_ethdev.c:1949-1954` secondary early exit ✅
- `eal_common_proc.c:750-751` IPC server ✅
- `malloc_heap.c:484` request_to_primary ✅
- `multi_proc_support.rst:19-24` secondary definition ✅

### 1.5 `tools/compat/ff_ipc.c` (2 items)
All verified ✅.

### 1.6 `tests/` (3 items)
All verified ✅.

**D1 Summary**: 43 items, 41 ✅, 2 ⚠️, 0 ❌. **Pass.**

---

## II. D2 Numerical Consistency

| Item | Document Claim | Verification | Result |
|------|---------------|-------------|--------|
| PoC change count | 3 lines | git diff | ✅ 3 lines |
| E2 survival rate | 9/20 | Log check | ✅ 9/20 |
| E2e recovery | 5/18 → 10/18 | Log check | ✅ |
| E3b | 12/12 zero interruption, 26 rounds | Log check | ✅ |
| mbuf pool formula | nb_rx_queue * nb_lcores | Code check | ✅ |
| Queue count source | pconf->nb_lcores | Code check | ✅ |

**D2 Summary**: All verified. **Pass.**

---

## III. D3 Cross-Document Consistency

| Check | Result |
|-------|--------|
| 00 requirements R1-R8 mapped to experiments | ✅ |
| 02 blocking points B1-B8 consistent with 03 solution | ✅ |
| 05 experiment conclusions consistent with 10 verdict | ✅ (after leader fix) |
| 04 KNI plan consistent with 07 work breakdown | ⚠️ Line number 2080/2081 inconsistency |
| 01 external research consistent with 02 code findings | ✅ |

---

## IV. D4 Methodology Soundness

| Check | Result |
|-------|--------|
| All conclusions have code:line evidence | ✅ |
| All experiments have raw logs | ✅ |
| Honest boundaries stated (L1-L8) | ✅ |
| PoC patch archived | ✅ |
| No speculation beyond evidence | ✅ (after leader fix) |

---

## V. D5 Constraint Compliance

| Check | Result |
|-------|--------|
| No real IP addresses (search `9.134.x.x`, `2402:4e00:`) | ✅ Zero hits |
| No bare `rm`/`kill`/`chmod` commands | ✅ All via scripts |
| `lib/` workspace clean (no uncommitted changes) | ✅ |
| `config.ini` not committed | ✅ |
| All IPs use placeholders (`<DPDK_NIC_IP>` etc.) | ✅ |

**D5 Summary**: **All passed.**

---

## VI. Issues to Fix

### Important (3 items)

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| I1 | Broadcast/multicast KNI gate line 2080/2081 inconsistency | `04:208,227,423`, `07:162` | Change 2081 → 2080 |
| I2 | "6 experiment sets" vs "9 sets" contradiction | `10` summary | Change to "9 sets" |
| I3 | "#1078 no comments" marked as "verified" without online check | `01:185`, issue-ana | Add "not independently online-verified" qualifier |

### Suggestions (5 items)

| # | Suggestion |
|---|-----------|
| S1 | Add "line numbers are approximate, use code text matching" disclaimer in 04 |
| S2 | Cross-reference 05 §VI E2c correction pointer more prominently |
| S3 | Add E2e/E10 update date stamps to 01 key conclusions |
| S4 | Consider adding "not extrapolable" boundary to performance data in 06 |
| S5 | Add "PoC patch is investigation evidence, not for commit" disclaimer to 05 |

---

## VII. Final Verdict

**PASS_WITH_NOTES**

- No blocking-level issues
- 3 important-level issues are documentation inconsistencies (not code/logic errors)
- 5 suggestion-level items are polish improvements
- All 43 code references verified accurate
- All constraint compliance passed
- Two initially blocking hazards already fixed by leader during review

**Recommendation**: Fix I1-I3 before user submission; S1-S5 optional but recommended.
