# 07 Test Specification — ff_rss_check Three Optimizations

> Scope: M4 test specification (unit / integration / real-machine + zero-regression criteria + acceptance matrix). This phase **only writes the test specification, not the test code**.
> Principle: test points must correspond to **actual functions / landing points (file:line number)**, not speculation; items that are uncontrollable at runtime / to be determined during coding are marked "pending confirmation".
> Basis: 01 requirements, 02 current state, 04 design, 05 interface design, 06 milestones; existing unit tests `tests/unit/test_ff_dpdk_if.c` (cmocka).
> Test environment (plan §Test Environment): local machine with dual NICs, DPDK-dedicated NIC IP `9.134.214.176` (tested via ssh `f-stack-client`); kernel stack tested via `127.0.0.1`.
> Mandatory conventions: test code deletion / process cleanup / permission changes must all go through `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`; local test values in config.ini must not be committed.

---

## 0. Test Framework and Existing Constraints (Fact Verification)

### 0.1 Existing Unit Test Status (`tests/unit/test_ff_dpdk_if.c`)

- Framework: cmocka, `main()` (L502-530) registers via `cmocka_run_group_tests`.
- Linking method: links the real DPDK shared library (`pkg-config libdpdk`, see file header L129-131); local no-op stubs are provided for ~30 `ff_*`/`rte_*` symbols not triggered by test cases (L57-127).
- Key stub: `ff_veth_softc_to_hostc` (L101) **currently returns NULL**.
- Existing RSS-related test cases (L361-455, 6 total, guard + smoke only):
  | Test Case | Line | Coverage |
  |------|------|------|
  | `test_ff_rss_tbl_set_portrange_no_cfg` | L361 | cfg=NULL → -1 (guard) |
  | `test_ff_rss_tbl_set_portrange_disabled` | L375 | enable=0 → -1 (guard) |
  | `test_ff_rss_tbl_set_portrange_inverted_range` | L390 | first>last → -1 (guard) |
  | `test_ff_rss_tbl_get_portrange_no_cfg` | L405 | cfg=NULL → -1 (guard) |
  | `test_ff_rss_tbl_get_portrange_disabled` | L421 | enable=0 → -1 (guard) |
  | `test_ff_rss_tbl_get_portrange_smoke` | L441 | any four-tuple does not crash (smoke) |
- **Gaps**: no hash-hit correctness, no portrange port-selection landing-in-queue correctness, no IPv6, no thash dynamic-path coverage. This specification fills these gaps.

### 0.2 Symbol Visibility of Functions Under Test (Determines Mock Strategy, Fact Verification)

| Symbol | Line | Linkage Attribute | Directly Accessible by Unit Test? | Impact |
|------|------|----------|------------------|------|
| `ff_rss_check` | `ff_dpdk_if.c:2851` | extern (non-static) | Yes (directly callable) | Can be called directly |
| `ff_rss_tbl_get_portrange` | `ff_dpdk_if.c:2796` | extern | Yes | Can be called directly |
| `ff_rss_tbl_set_portrange` | `ff_dpdk_if.c:2737` | extern | Yes | Can be called directly |
| `ff_rss_tbl_init` | `ff_dpdk_if.c:2598` | extern | Yes | Can be called directly |
| `toeplitz_hash` | `ff_dpdk_if.c:2548` | **static** | No | The expected hash must be either **independently re-implemented as an equivalent Toeplitz** within the test, or compared against precomputed constants |
| `lcore_conf` | `ff_dpdk_if.c:123` | **extern global** (non-static) | Yes | Can set `nb_queue_list[port]`/`tx_queue_id[port]` within the test |
| `rss_reta_size[]` | `ff_dpdk_if.c:133` | **static** | No | reta_size cannot be set directly by the test; must go through a path that can set it, or use `__wrap_` |
| `rsskey`/`rsskey_len` | `ff_dpdk_if.c:121/120` | **static** | No | The key used for the expected hash must match it → copy `default_rsskey_40bytes` value within the test |
| `ff_rss_tbl[]` | `ff_dpdk_if.c:172` | **static** | No | Static table contents can only be built indirectly via `ff_rss_tbl_init`/`set_portrange` |
| `ff_veth_softc_to_hostc` | stub (L101) | Test-local stub | Yes (modify the stub) | **Key**: `ff_rss_check` L2855 calls this to get `ctx->port_id`; must modify the stub to return a controlled ctx |

> 【Key fact】`ff_rss_check` (L2855) depends on `ff_veth_softc_to_hostc(softc)->port_id`, and uses that `port_id` to index the static `lcore_conf.nb_queue_list[]`/`tx_queue_id[]` (L2856/2863) and `rss_reta_size[]` (L2862). The existing stub returns NULL → calling `ff_rss_check` directly would crash with a null pointer.
> 【Mock strategy conclusion】For hit-correctness test cases, it is **required to**: (a) make the `ff_veth_softc_to_hostc` stub return a `struct ff_dpdk_if_context` held by the test (with `port_id` under test control); (b) set `lcore_conf.nb_queue_list[port]` (nb_queues) and `tx_queue_id[port]` (queueid); (c) resolve the setup of static `rss_reta_size[port]` (see §0.3).

### 0.3 Difficulty of Setting Static `rss_reta_size` (Pending Confirmation)

- `ff_rss_check` (L2862) reads static `rss_reta_size[ctx->port_id]`, which the test cannot write directly.
- Candidate approaches (choose one during coding, marked "pending confirmation"):
  1. **Link-time wrap**: not feasible for `ff_rss_check`'s internal uncontrollable values (it reads the global directly), so wrapping is not viable;
  2. **Add a test-visible setter/accessor** (enabled only for the test build): lowest cost, most reliable, preferred approach;
  3. **Set via the initialization path**: `rss_reta_size` is written by the `ff_dpdk_init_port`/RSS configuration path; bringing up a full port configuration in a unit test is costly, not recommended.
- 【Pending confirmation: the injection method for `rss_reta_size` in unit tests (leaning toward adding a test-only accessor, or placing the hit-correctness assertion into an "expected queue independently computed by the test side" equivalence check, avoiding dependency on the static value). The assertion style of the test cases in this specification is based on "expected value independently re-computed by the test side" (detailed in §1.1), and does not assume the static array can be overwritten.】

### 0.4 Independent Re-computation of the Expected Hash (Source of Assertion Baseline)

Since `toeplitz_hash`/`rsskey` are static, the "expected queue" for hit-correctness test cases **cannot** be obtained by directly calling the internal function under test (that would be self-referential); the test side must **independently implement** an equivalent Toeplitz hash:

- The test defines a built-in `expected_toeplitz(key, key_len, data, data_len)`, whose algorithm is strictly aligned with `toeplitz_hash` (`ff_dpdk_if.c:2548-2568`, standard Toeplitz with bit-by-bit shift XOR).
- The key uses `default_rsskey_40bytes` (same value as `ff_dpdk_if.c:92`, constant copied into the test).
- The data layout is aligned with `ff_rss_check` (L2865-2880): `saddr(4)+daddr(4)+sport(2)+dport(2)` (for v6, 16+16+2+2, see §2.1).
- Expected queue = `(expected_hash & (reta_size-1)) % nb_queues`, consistent with the determination formula in `ff_rss_check` (L2885).
- Assertion: `ff_rss_check(...) == (expected_queue == queueid ? 1 : 0)`.
- 【Note】This approach makes the unit test independent of whether the static value can be overwritten: the test side re-computes the expected result using "the same input, same key, same formula" to verify that the function under test's return value matches the expectation; reta_size/nb_queues/queueid are held by the test side as a single consistent set of values (source of reta_size, see §0.3 pending confirmation; if it cannot be injected, hit-correctness coverage falls back to the integration/real-machine layer, and unit-test-layer coverage is downgraded to "self-consistency + guard + smoke", see §1.1 remarks).

---

## 1. Unit Test Specification (cmocka, Mimicking the Existing `test_ff_dpdk_if.c` Style)

> Naming follows the existing `test_ff_rss_*` style; IDs use `TC-U-RSS-<requirement>-<sequence>`. Each test case specifies: function under test:line number / preconditions / input / assertion / expectation / mock approach.
> All new test cases must be registered in the `tests[]` array within `main()` (L505-528).

### 1.1 Requirement 0.1: Portrange Port-selection Correctness (Extending the Existing 6-case Gap)

#### TC-U-RSS-01-01 get_portrange Hit — Resulting Port Set Lands in the Local Queue

- Under test: `ff_rss_tbl_get_portrange` (`ff_dpdk_if.c:2796`) + `ff_rss_tbl_init` (L2598) + `ff_rss_check` (L2851).
- Preconditions: build a `ff_rss_check_cfg` (enable=1) containing one v4 rule (port/daddr/saddr/sport); call `ff_rss_tbl_init()` to pre-build the static table (L2690-2700 iterates over each dport calling `ff_rss_check` to fill the table); set `lcore_conf.nb_queue_list[port]=Q`, `tx_queue_id[port]=q`; the `ff_veth_softc_to_hostc` stub returns a controlled ctx (port_id=port).
- Input: call `ff_rss_tbl_get_portrange(saddr,daddr,sport,&first,&last,&portrange)` with the same `(saddr,daddr,sport)` used during pre-build.
- Assertion: return value indicates a hit (0, per the contract in 05 §1.1 that "hit returns 0 and fills the port set", **the actual return code is based on the existing implementation at `ff_dpdk_if.c:2796`** 【pending confirmation of current return semantics】); `portrange` is non-empty; for **each dport** in the returned port set, the test side independently re-computes `(expected_toeplitz(...) & (reta-1)) % Q == q` (i.e., all land in the local queue).
- Expectation: 100% of the port set in the table lands in the local queue (consistent with `ff_rss_tbl_init`'s table-filling logic).
- Mock: `ff_veth_softc_to_hostc` returns a controlled ctx; `lcore_conf` written directly; reta_size injection per §0.3.
- Remark: if reta cannot be injected per §0.3, this test case degrades to a **self-consistency** assertion of "after building the table, get hits, the port set is non-empty, and each port independently returns 1 when re-verified by the `ff_rss_check` under test itself" (no external expectation introduced), and formal hit-correctness verification moves to the integration/real-machine layer (§2/§3).

#### TC-U-RSS-01-02 get_portrange Port Rotation (Consecutive Calls Take Different Ports)

- Under test: `ff_rss_tbl_get_portrange` (L2796), focusing on its internal semantics of using "`dport[0]` as the index of the last selected port to rotate" (`ff_dpdk_if.c:155-163` comment `[0] used as the idx of last seleted port`).
- Preconditions: same table build as 01-01.
- Input: call get_portrange multiple times consecutively with the same `(saddr,daddr,sport)` (simulating consecutive connects selecting a port).
- Assertion: consecutive "suggested start points" advance with rotation (do not remain the same port every time), and each extracted port still lands in the local queue.
- Expectation: rotation is dispersed, avoiding port hotspots (consistent with 04 §3.3 Algorithm 1 "rotational selection for dispersion").
- Mock: same as 01-01.
- 【Pending confirmation: whether `ff_rss_tbl_get_portrange` self-increments the `dport[0]` index internally, or whether the caller advances it — based on the actual implementation at `ff_dpdk_if.c:2796-2848`, finalize the assertion once verified during coding.】

#### TC-U-RSS-01-03 get_portrange Miss Fallback

- Under test: `ff_rss_tbl_get_portrange` (L2796) miss branch.
- Preconditions: after building the table, query with a `(saddr,daddr,sport)` that **does not exist** in the table (e.g., an unconfigured saddr).
- Input: `ff_rss_tbl_get_portrange(other_saddr, other_daddr, other_sport, ...)`.
- Assertion: returns a miss code (per 05 §1.1 "miss returns -ENOENT", **based on the existing implementation** 【pending confirmation】); `portrange` is not filled with a valid port set.
- Expectation: on a miss, the kernel side falls back to dynamic soft-computation / thash (this test case only verifies the lib layer's miss signal).
- Mock: same as 01-01.

#### TC-U-RSS-01-04 ~ 01-06 Existing 6 Guard/Smoke Cases Retained as Regression

- Directly retain the 6 existing `test_ff_rss_tbl_set_portrange_*` (L361/375/390) + `test_ff_rss_tbl_get_portrange_*` (L405/421/441) cases unchanged (regression baseline; 0.1 changes the kernel, not these lib functions).

### 1.2 Requirement 0.2: IPv6 Hash and Table (Brand New)

> Under test are the new functions from 05 §1.2, `ff_rss_check6`/`ff_rss_tbl6_*` (added during coding; this specification defines test points per the 05 contract, function landing line numbers "pending confirmation (to be backfilled after addition)").

#### TC-U-RSS-02-01 ff_rss_check6 Hash Queue-landing Correctness (Known v6 Five-tuple vs. Expected Queue)

- Under test: `ff_rss_check6` (new, 05 §1.2).
- Preconditions: `lcore_conf.nb_queue_list[port]=Q`, `tx_queue_id[port]=q`, ctx controlled; reta injection per §0.3.
- Input: known `(saddr6,daddr6,sport,dport)` (fixed v6 five-tuple constants).
- Assertion: the test side independently re-computes the expected queue using `expected_toeplitz` for the 36B layout (16+16+2+2, 04 §2.1); `ff_rss_check6(...) == (expected_q==q?1:0)`.
- Expectation: v6 hash lands in the queue consistent with the soft-compute formula; when `nb_queues<=1`, always returns 1 (aligned with the v4 contract, 05 §1.2).
- Mock: same as v4; additionally verify the 36B layout assembly order is correct (saddr6 first, then daddr6).
- 【Pending confirmation: whether `ff_rss_check6` reuses the static `toeplitz_hash` and the same `rsskey`/reta, must match v4's scope; backfill line number after coding.】

#### TC-U-RSS-02-02 ff_rss_check6 Always True for Single Queue

- Under test: `ff_rss_check6`.
- Preconditions: `lcore_conf.nb_queue_list[port]=1`.
- Input: any v6 five-tuple.
- Assertion: returns 1 (aligned with v4's L2858-2860 "returns 1 when nb_queues<=1").
- Expectation: single queue does not enforce RSS constraints.

#### TC-U-RSS-02-03 v6 Static Table init / get_portrange smoke + Hit

- Under test: `ff_rss_tbl6_init`/`ff_rss_tbl6_get_portrange`/`ff_rss_tbl6_set_portrange` (new).
- Preconditions: build a cfg containing one v6 rule (enable=1), call `ff_rss_tbl6_init`.
- Input: (a) guard: cfg=NULL / enable=0 → returns -1 (aligned with v4 guard isomorphism at L361-433); (b) smoke: any v6 triplet does not crash; (c) hit: get with the same v6 triplet used to build the table → hit and the port set lands in the local queue (self-consistency, same as §1.1 remark).
- Assertion: guard returns -1; smoke does not crash; hit port set independently re-verified by `ff_rss_check6` returns 1.
- Mock: same as v4.

#### TC-U-RSS-02-04 Config v6 Rule Parsing

- Under test: `rss_tbl_cfg_handler` (`ff_config.c:880-921`), v6 branch (05 §3.2: daddr/saddr containing `:` goes through `inet_pton(AF_INET6,...)`).
- Preconditions: construct a v6 text rule string containing `:` (e.g., `0 2001:db8::1 2001:db8::2 80`).
- Input: call `rss_tbl_cfg_handler` (or its testable entry point).
- Assertion: the parsed rule marks family as v6, with the 16B address matching the result of `inet_pton(AF_INET6)`; pure v4 rule string parsing results are completely consistent with the current behavior (zero regression).
- Mock: none (pure parsing, independently testable).
- 【Pending confirmation: whether `rss_tbl_cfg_handler` is static (`ff_config.c`); if static, must go through `ff_load_config` or a new test-only entry point; based on the linkage attribute at `ff_config.c:880`.】

#### TC-U-RSS-02-05 Full IPv4 Case Regression

- Under test: all v4 cases in §1.1 + the existing 6 cases.
- Assertion: after introducing v6 symbols/changing config parsing in 0.2, all v4 cases still PASS (IPv4 zero-regression hard constraint, 01 §2.5 / 06 R-C.4).

### 1.3 Requirement 0.3: Thash Dynamic Reverse-computation (Brand New)

> Under test are the new static functions from 05 §1.3, `ff_rss_adjust_sport` (v4)/`ff_rss_adjust_sport6` (v6); static functions need test-only exposure (same as §0.2). Function landing points "pending confirmation (to be backfilled after addition)".

#### TC-U-RSS-03-01 desired_value Mapping Correctness (D(q) Set)

- Under test: the desired_value computation inside `ff_rss_adjust_sport` (04 §3.3: `D(q)={v∈[0,R)|v%Q==q}`).
- Preconditions: given multiple groups of `(R=reta_size, Q=nb_queues, q=queueid)` (including §3.4 edge cases).
- Input: trigger desired_value selection.
- Assertion: each selected desired_value satisfies `v < R` and `v % Q == q`.
- Expectation: the mapping set is consistent with the derivation in 04 §3.3.
- Verification combinations (coverage matrix):
  | Combination | R | Q | q | Focus |
  |------|---|---|---|--------|
  | a | 128 | 4 | 0..3 | R%Q==0 uniform |
  | b | 128 | 8 | 0..7 | R%Q==0 |
  | c | 128 | 6 | 0..5 | **R%Q!=0** (each \|D(q)\| unequal, 04 §3.3 edge case) |
  | d | 64 | 64 | any | \|D(q)\|=1 boundary |
  | e | — | 1 | 0 | Q==1: does not enter thash (`ff_rss_check` directly returns 1, L2858) |
- 【Pending confirmation: whether desired_value selection can be independently asserted within adjust_sport — based on the new implementation. If not independently observable, cover it indirectly via the end-to-end assertion in 03-02.】

#### TC-U-RSS-03-02 Adjust_tuple Reverse-computed Port, Verified by ff_rss_check to Land in Local Queue (Core Correctness)

- Under test: `ff_rss_adjust_sport` (05 §1.3) full flow → internally includes `rte_thash_adjust_tuple` (`rte_thash.h:456`) + mandatory `ff_rss_check` re-verification (04 §3.3 Algorithm 5 / 05 §1.3 Step 4).
- Preconditions: build ctx via `ff_rss_thash_ctx_init` (05 §1.3) (key=runtime rsskey, reta_sz_log2=log2(R), helper sport offset=64bit/len≥reta_sz_log2); `lcore_conf`/ctx controlled.
- Input: given `(saddr,daddr,dport, target queueid=q)`.
- Assertion: returns 0 (success) and `*out_sport` is valid; for the returned sport, **independently** call `ff_rss_check(softc,saddr,daddr,out_sport,dport)==1` (lands in local queue).
- Expectation: 100% of reverse-computed ports pass soft-compute re-verification and land in the local queue (01 §3.5 "must not select the wrong queue" zero tolerance).
- Mock: `ff_veth_softc_to_hostc` returns a controlled ctx; ctx init uses real DPDK `rte_thash_*` (already linked).
- Coverage: run once for each of the (R,Q,q) groups from §3-01, including R%Q!=0.

#### TC-U-RSS-03-03 Fallback When Attempts Are Exhausted (Failure Path)

- Under test: `ff_rss_adjust_sport` failure branch (04 §3.6 / 05 §1.3 Step 5).
- Preconditions: construct a scenario where the adjustment struggles to converge (e.g., set attempts extremely small=1 + a demanding desired_value), or ctx init fails.
- Input: trigger reverse-computation failure.
- Assertion: returns <0; the caller (simulated kernel hook) correctly falls back to soft-compute scanning (lib layer only verifies the <0 signal).
- Expectation: does not crash on failure, does not return the wrong port; functionality degrades to soft-compute (correctness does not degrade).

#### TC-U-RSS-03-04 ctx Init Failure Degrades to Pure Soft-compute

- Under test: `ff_rss_thash_ctx_init` (05 §1.3) failure handling (04 §3.6 "init_ctx failure → degrade to pure soft-compute").
- Preconditions: simulate `rte_thash_init_ctx` returning NULL (e.g., invalid name / resource limit, or `__wrap_rte_thash_init_ctx` returns NULL).
- Input: call init.
- Assertion: init returns a failure code but does not crash; subsequently `ff_rss_adjust_sport` directly returns <0 due to no ctx (caller falls back to soft-compute).
- Expectation: equivalent to 0.1's pure soft-compute behavior, 0.1's functionality unaffected.
- Mock: `__wrap_rte_thash_init_ctx` (link-time wrap, mimicking existing `__wrap_rte_get_tsc_hz` L45-49).

#### TC-U-RSS-03-05 v6 Thash Reverse-computation Re-verification (Alongside 0.2)

- Under test: `ff_rss_adjust_sport6` (05 §1.3, tuple_len=36, offset=256bit, re-verified via `ff_rss_check6`).
- Assertion: the reverse-computed v6 sport passes `ff_rss_check6` re-verification and returns 1 (lands in local queue).
- Otherwise same as 03-02.

### 1.4 Requirement 0.4: Reverse Re-check Runtime Switch (Brand New)

> Under test: the recheck branching in `ff_rss_adjust_sport` (`lib/ff_dpdk_if.c:3053-3114`) / `ff_rss_adjust_sport6` (L3391-3446); `struct ff_rss_check_cfg.recheck` (`lib/ff_config.h:241-246` incremental field).
> Existing test context (already verified in `tests/unit/test_ff_dpdk_if.c`):
> - `g_rss_cfg` (test L583) + `ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg` (L596/L995) injection pattern can be directly reused; 0.4 only needs to add `g_rss_cfg.recheck = 0/1`.
> - `ff_rss_check`/`ff_rss_check6` are extern (directly callable, §0.2).
> - Count-mock strategy (key): existing cases directly link the real `ff_rss_check` symbol, with no existing wrap. 0.4 cases need to introduce a link-time wrap `__wrap_ff_rss_check` / `__wrap_ff_rss_check6` (mimicking `__wrap_rte_get_tsc_hz` test L53-57), accumulating a call count inside the mock. 【Pending confirmation: whether the internal call to `ff_rss_check` within `ff_rss_adjust_sport` is intercepted when wrapped — `-Wl,--wrap=ff_rss_check` intercepts calls both from within the library and from the test code, which fits the 0.4 counting requirement; the wrap implementation needs to handle both "when recheck=1, return the real queue-landing result" and "when recheck=0, should not be called at all". Alternative: accumulate the count directly + call `__real_ff_rss_check` to pass through the computation.】

#### TC-U-RSS-04-01: v4 recheck=0 → Adjust Succeeds and Returns Directly, ff_rss_check Call Count is 0

- Under test: `ff_rss_adjust_sport` (L3053) + recheck branch (04 §3-bis.5; 05 §3-bis.4).
- Preconditions:
  - `test_rss_build_table(saddr, daddr, sport)` (test L587) injects cfg; explicitly `g_rss_cfg.recheck = 0`.
  - `lcore_conf.nb_queue_list[port] = TEST_RSS_NBQ`, `tx_queue_id[port] = TEST_RSS_QID`, `test_rss_softc(port)` same as R-B cases.
  - `__wrap_ff_rss_check` static counter `wrap_ff_rss_check_cnt = 0`.
  - thash ctx already initialized (depends on R-B's already-landed `ff_rss_thash_ctx_init` path; reta_size injection is still constrained by the unit test, construct per the same style as the existing R-B hitrate cases).
- Input: `ff_rss_adjust_sport(softc, saddr, daddr, dport, &out_sport)`.
- Assertion:
  1. Return value is 0 (adjust succeeded) or -1 (in environment-limited scenarios such as reta=0, the ctx is not ready and takes the -1 path — degrade fallback per the same style as existing hitrate cases, cannot directly assert success). 【Pending confirmation: in the unit test environment, static `rss_reta_size[]` in BSS=0 → ctx_init returns -1 early; this case needs the R-B existing hitrate-quantification context (test near L595) to reach the successful reverse-computation path.】
  2. **Key**: `wrap_ff_rss_check_cnt == 0` (should not be called when recheck=0).
- Expectation: when recheck=0, the successful reverse-computation path returns sport directly, bypassing soft-compute re-verification.
- Mock: `__wrap_ff_rss_check` accumulates the count + calls `__real_ff_rss_check` to return the real determination (does not affect the recheck=0 flow, since it never reaches here).
- Remark: if the thash ctx cannot be readied in the unit test environment, this case degrades to a self-consistency assertion of "`ff_rss_adjust_sport` returns -1 (ctx not ready) + wrap_ff_rss_check_cnt == 0"; the core assertion of "recheck=0 count is 0" moves to the microbench (04-05) or is covered by integration tests.

#### TC-U-RSS-04-02: v4 recheck=1 → Maintains R-B Mandatory Re-verification Behavior

- Under test: `ff_rss_adjust_sport` (L3053) recheck=1 branch.
- Preconditions: same as 04-01; **change `g_rss_cfg.recheck = 1`**.
- Input: same as 04-01.
- Assertion:
  1. Return value same as existing R-B hitrate-quantification cases (adjust succeeds and passes soft-compute re-verification → return 0; fails → advance to the next candidate; all fail → -1).
  2. **Key**: `wrap_ff_rss_check_cnt > 0` (when recheck=1 enters the reverse main loop and adjust succeeds at least once, `ff_rss_check` must be called).
  3. When returning 0, independently call `__real_ff_rss_check(softc, saddr, daddr, out_sport, dport)` on `out_sport`, returning 1 (hard assertion of landing in the local queue, equivalent to R-B).
- Expectation: recheck=1 is equivalent to the current R-B/R-C status quo (zero-tolerance re-verification hard gate).
- Mock: same as 04-01.

#### TC-U-RSS-04-03: v6 recheck=0 (Symmetric to 04-01)

- Under test: `ff_rss_adjust_sport6` (L3391) recheck=0 branch.
- Preconditions: `test_rss6_build_table(saddr6, daddr6, sport)` (test L984) + `g_rss_cfg.recheck = 0`; `__wrap_ff_rss_check6` counter cleared.
- Input: `ff_rss_adjust_sport6(softc, saddr6, daddr6, dport, &out_sport)`.
- Assertion: return-value contract same as 04-01; `wrap_ff_rss_check6_cnt == 0`.
- Mock: `__wrap_ff_rss_check6` in the same style as v4.

#### TC-U-RSS-04-04: v6 recheck=1 (Symmetric to 04-02)

- Under test: `ff_rss_adjust_sport6` (L3391) recheck=1 branch.
- Preconditions: `g_rss_cfg.recheck = 1`.
- Assertion: `wrap_ff_rss_check6_cnt > 0`; when returning 0, `out_sport` re-verified as 1 via `__real_ff_rss_check6`.
- Equivalent to R-C status quo.

#### TC-U-RSS-04-05: Microbench recheck=0 vs recheck=1 Cumulative Time Comparison

- Under test: `ff_rss_adjust_sport` (v4 primary) + `ff_rss_adjust_sport6` (v6 secondary, sampled synchronously).
- Measurement tool: `clock_gettime(CLOCK_MONOTONIC, &ts)` taking the start/end difference (ns precision), compared against `rte_rdtsc()` for better compatibility with the unit test environment.
- Preconditions: table built + ctx ready (same context as R-B hitrate-quantification); `N = 10000` (adjustable via a compile-time macro `FF_RSS_RECHECK_MICROBENCH_N`).
- Steps:
  1. `g_rss_cfg.recheck = 0`: loop calling `ff_rss_adjust_sport(softc, saddr, daddr, dport, &out_sport)` N times (slightly perturbing daddr or dport each time to avoid extreme cache hits), cumulative time → `t_off_v4_ns`.
  2. Switch to `g_rss_cfg.recheck = 1`, same loop of N times → `t_on_v4_ns`.
  3. v6 symmetric (using `ff_rss_adjust_sport6` + perturbing saddr6/dport) → `t_off_v6_ns` / `t_on_v6_ns`.
- Assertion:
  1. `t_off_v4_ns < t_on_v4_ns` (recheck=0 is strictly faster); record the ratio `t_on_v4_ns / t_off_v4_ns` (expected >1, backfilled with real measurements in spec 10).
  2. v6 in sync: `t_off_v6_ns < t_on_v6_ns`.
  3. The per-call average (`t_*_ns / N`) is reasonable (no negative values or abnormal fluctuations).
  4. No absolute values required (environment-dependent), only the relative relationship + ratio printout (log_message).
- Mock: `__wrap_ff_rss_check` can still be attached to accumulate the count, verifying the count is 0 during the recheck=0 phase and > 0 during the recheck=1 phase.
- Remark: if in the unit test environment reta=0 → ctx not ready → `ff_rss_adjust_sport` directly returns -1 → the two states' time costs are nearly identical → this case prints "skipped: thash ctx not ready in unit env" and returns PASS (avoiding false failure); real data is backfilled by real-machine data via spec 08 / `example/rss_ct.c`.

#### TC-U-RSS-04-06 (Implicit): Existing hitrate/equivalence Cases Switch to recheck=1

- Under test: existing R-B/R-C hitrate-quantification cases (test near L595, table-build + reverse-computation call).
- Change: append a `g_rss_cfg.recheck = 1;` line after each case's build_table (preserving the existing 100% queue-landing hard assertion without degradation).
- Assertion: consistent with the existing cases (PASS unchanged).
- This is the **mandatory closing step** for the R-D implementation — missing this change would cause the "hitrate cases degrading from 100% to 22-27%" failure.

### 1.5-ter Requirement 0.5: Bind No Port Bind-then-connect (Brand New)

> Under test primarily is the gating behavior of kernel-side `in_pcbbind`/`in_pcbbind_setup`/`in6_pcbbind` (line numbers backfilled after R-E implementation); the unit-test level focuses on "state observable at the userspace/unit-test level" (inp_lport after bind, whether connect enters the anonport branch); end-to-end queue-landing in the kernel is verified via integration/real-machine testing.
> 【Key fact】R-E changes the kernel `freebsd/netinet/in_pcb.c` / `in6_pcb.c`, which is **not** covered by `tests/unit/test_ff_dpdk_if.c` (that unit test targets the lib `ff_dpdk_if.c`). Unit-testing R-E's kernel functions depends on a kernel-level test carrier (e.g., a FreeBSD kernel unit test framework / a self-built minimal in_pcb test stub); the existing cmocka lib unit tests **do not directly cover** this — hence R-E's cases are primarily integration (§2.6) + real-machine (§3.6), with the unit-test items marked "pending confirmation (requires a kernel test carrier)".

#### TC-U-RSS-05-01 After bind(v4_addr,0), inp_lport==0 (Port Not Pre-allocated)

- Under test: `in_pcbbind` (`in_pcb.c:720`) + `in_pcbbind_setup` (L1275-1279 hunk2 gate).
- Preconditions: FSTACK compilation enabled; construct an inpcb, `bind(local_v4_addr, sin_port=0)`.
- Input: call `in_pcbbind` (or the bind syscall path).
- Assertion: returns success; `inp->inp_lport == 0` (under FSTACK, port not allocated at bind time); the socket is not inserted into the hash (`INP_INHASHLIST` not set / does not occupy the port space).
- Expectation: hunk2 takes effect, port allocation is deferred to connect.
- 【Pending confirmation: kernel test carrier (needs to be able to drive `in_pcbbind` and read inp_lport); the existing lib cmocka unit test does not cover the kernel in_pcb, requires a FreeBSD kernel unit test framework or integration-layer verification.】

#### TC-U-RSS-05-02 bind(v4_addr,0)+connect → anonport=true Enters RSS_CHECK Branch

- Under test: `in_pcbconnect` (L1294, L1313 anonport / L1363-1366 RSS branch).
- Preconditions: the socket from TC-05-01 (inp_lport==0); multi-queue + `rss_check` enable=1.
- Input: `connect(remote_v4)`.
- Assertion: at connect time, `anonport == (inp_lport==0) == true` (L1313) → enters `in_pcb_lport_dest(... INPLOOKUP_LPORT_RSS_CHECK)` (L1363-1366) → the selected `inp_lport` passes independent `ff_rss_check(softc, saddr, daddr, inp_lport, dport)==1` (lands in local queue).
- Expectation: bind-then-connect port selection lands in the local worker queue (AC-05-2).
- 【Pending confirmation: same kernel test carrier as 05-01; the queue-landing hard assertion is based on integration/real-machine testing (§2.6/§3.6).】

#### TC-U-RSS-05-03 bind(v4_addr, N) (N≠0) Zero Regression

- Under test: `in_pcbbind` (L720) + `in_pcbbind_setup` (lport≠0 branch).
- Preconditions: FSTACK enabled; `bind(local_v4_addr, sin_port=N)` (N≠0).
- Input: call `in_pcbbind`.
- Assertion: returns success; `inp->inp_lport == N` (port fixed at bind time, consistent with native); socket normally inserted into the hash (hunk1's gate only affects lport==0, N≠0 is unaffected).
- Expectation: bind with a specified port behaves completely unchanged (AC-05-4, zero regression).

#### TC-U-RSS-05-04 After bind(v6_addr,0), inp_lport==0 (v6 Sync)

- Under test: `in6_pcbbind` (`in6_pcb.c:306`, L354/L361-369 gate).
- Preconditions: FSTACK enabled; `bind(local_v6_addr, sin6_port=0)`.
- Assertion: returns success; `inp->inp_lport == 0` (v6 bind does not allocate a port); in6p_laddr handling matches the selected path in 04 §3-ter.4 (Path B: still set laddr / or temporarily stored, to be determined during coding).
- Expectation: v6's equivalent hunk gate takes effect.
- 【Pending confirmation: v6's in6p_laddr handling and its coordination scheme with connect L515 (04 §3-ter.4); kernel test carrier same as 05-01.】

#### TC-U-RSS-05-05 bind(v6_addr,0)+connect6 → Enters L515 RSS Branch (v6 Sync)

- Under test: `in6_pcbconnect` (`in6_pcb.c`, L515-527 RSS branch).
- Preconditions: the socket from TC-05-04; multi-queue + v6 `rss_check` rules.
- Input: `connect(remote_v6)`.
- Assertion: connect enters the L515 RSS branch (per the selected scheme in 04 §3-ter.4: condition `inp_lport==0`, possibly relaxed from the original `IN6_IS_ADDR_UNSPECIFIED` constraint) → the selected `inp_lport` passes `ff_rss_check6` re-verification and lands in the local queue.
- Expectation: v6 bind-then-connect lands in the local queue (AC-05-3).
- 【Pending confirmation: L515 condition coordination scheme; kernel test carrier; v6 queue-landing verified against real-machine testing (§3.6 RT-RSS-06).】

### 1.5 Unit Test Case Summary

| ID | Requirement | Function Under Test:Line | Type | Newly Added? |
|----|------|---------------|------|----------|
| TC-U-RSS-01-01 | 0.1 | `ff_rss_tbl_get_portrange`:2796 / `ff_rss_check`:2851 | Hit correctness | New |
| TC-U-RSS-01-02 | 0.1 | `ff_rss_tbl_get_portrange`:2796 | Port rotation | New |
| TC-U-RSS-01-03 | 0.1 | `ff_rss_tbl_get_portrange`:2796 | Miss fallback | New |
| TC-U-RSS-01-04~06 | 0.1 | set/get_portrange guard+smoke | Guard/smoke | Retained (L361-455) |
| TC-U-RSS-02-01 | 0.2 | `ff_rss_check6` (new) | v6 hash correctness | New |
| TC-U-RSS-02-02 | 0.2 | `ff_rss_check6` (new) | v6 single-queue always true | New |
| TC-U-RSS-02-03 | 0.2 | `ff_rss_tbl6_*` (new) | v6 table init/get | New |
| TC-U-RSS-02-04 | 0.2 | `rss_tbl_cfg_handler`:`ff_config.c:880` | v6 config parsing | New |
| TC-U-RSS-02-05 | 0.2 | All v4 cases | IPv4 regression | Reused |
| TC-U-RSS-03-01 | 0.3 | `ff_rss_adjust_sport` (new) | desired_value mapping | New |
| TC-U-RSS-03-02 | 0.3 | `ff_rss_adjust_sport` (new)+`ff_rss_check`:2851 | Reverse-computation re-verified queue landing | New |
| TC-U-RSS-03-03 | 0.3 | `ff_rss_adjust_sport` (new) | Fallback when attempts exhausted | New |
| TC-U-RSS-03-04 | 0.3 | `ff_rss_thash_ctx_init` (new) | Degrade on init failure | New |
| TC-U-RSS-03-05 | 0.3+0.2 | `ff_rss_adjust_sport6` (new)+`ff_rss_check6` | v6 reverse-computation re-verification | New |
| TC-U-RSS-04-01 | 0.4 | `ff_rss_adjust_sport`:3053 + recheck branch | v4 recheck=0 does not call ff_rss_check (count mock) | New |
| TC-U-RSS-04-02 | 0.4 | `ff_rss_adjust_sport`:3053 + recheck branch | v4 recheck=1 maintains R-B mandatory re-verification | New |
| TC-U-RSS-04-03 | 0.4 | `ff_rss_adjust_sport6`:3391 + recheck branch | v6 recheck=0 does not call ff_rss_check6 | New |
| TC-U-RSS-04-04 | 0.4 | `ff_rss_adjust_sport6`:3391 + recheck branch | v6 recheck=1 maintains R-C mandatory re-verification | New |
| TC-U-RSS-04-05 | 0.4 | `ff_rss_adjust_sport[6]` microbench | recheck=0 vs =1 cumulative time comparison (N=10000) | New |
| TC-U-RSS-04-06 | 0.4 regression | Existing R-B/R-C hitrate cases | Explicit `g_rss_cfg.recheck=1` to maintain the 100% hard assertion | Modified |
| TC-U-RSS-05-01 | 0.5 | `in_pcbbind`/`in_pcbbind_setup` (kernel, backfilled after R-E) | inp_lport==0 without hash insertion after bind(v4,0) | New (pending kernel test carrier) |
| TC-U-RSS-05-02 | 0.5 | `in_pcbconnect`:1294 (L1313/L1363-1366) | bind-then-connect anonport=true enters RSS_CHECK | New (pending kernel test carrier) |
| TC-U-RSS-05-03 | 0.5 regression | `in_pcbbind`:720 (lport≠0 branch) | bind(v4,N) port fixed+hash inserted, zero regression | New |
| TC-U-RSS-05-04 | 0.5 v6 | `in6_pcbbind`:306 | inp_lport==0 after bind(v6,0) | New (pending kernel test carrier) |
| TC-U-RSS-05-05 | 0.5 v6 | `in6_pcbconnect` (L515-527) | bind(v6,0)-then-connect6 enters L515 RSS branch | New (pending kernel test carrier) |

---

## 2. Integration Test Specification

> Uses `example/` (helloworld / multi-process) as the carrier, verifying "kernel hook + lib" end-to-end: the local source port selected by an actively-initiated connect indeed lands in the local process's queue.
> Basis: 06 R-A.2 / R-B.2 / R-C.2 integration test points.

### 2.1 IT-RSS-01: IPv4 Multi-queue Connect Source Port Lands in Local Queue (0.1)

- Preconditions: config.ini `[dpdk]` with `rss_check` enabled (enable=1, configured with v4 `rss_tbl` rules); multi-queue/multi-process (`lcore_mask` multi-core); FSTACK compilation enabled.
- Steps: use helloworld (or echo) as the **client** to initiate connects to the peer (multiple times), record the local source ports selected by the kernel.
- Assertion: for each selected source port, verify with an independent `ff_rss_check` (or by capturing packets and checking against the NIC's actual RSS queue assignment) that it lands in **the local process's corresponding queue**; 0% land in the wrong queue.
- Regression comparison: under the same config, behavior is consistent with the 13.0 baseline (ports all land in the local queue).
- 【Pending confirmation: whether helloworld has an active connect client path, or whether echo's client mode / a self-built minimal connect test program is needed — based on the actual samples in `example/`, confirm the client carrier during coding.】

### 2.2 IT-RSS-02: Single-queue / rss_check Disabled Fallback (0.1 Zero Regression)

- Preconditions: (a) single queue (`lcore_mask` single core); (b) `rss_check` enable=0.
- Steps: same connect.
- Assertion: port selection follows the native FreeBSD path (`ff_rss_check` returns 1 when nb_queues<=1 / `ff_rss_tbl_get_portrange` returns -1, 04 §1.4), behavior consistent with not having introduced this feature at all; no crashes.

### 2.3 IT-RSS-03: Thash Dynamic Path vs. Soft-compute Path Consistency (0.3)

- Preconditions: `rss_check` enabled with multi-queue; construct a connection **missing the static table** (saddr/daddr/sport not in the `rss_tbl` config → goes down the dynamic branch, 04 §3.1).
- Steps: initiate the same connect under both the "thash reverse-computation path" and the "forced soft-compute scan path" (e.g., temporarily disable thash / degrade via ctx init failure).
- Assertion: both paths' selected ports land in the local queue (consistency); the thash path's selected ports pass soft-compute re-verification 100% of the time.
- Comparison: consistent with the IT-RSS-01 static-table hit path result (both land in the local queue).

### 2.4 IT-RSS-04: IPv6 Multi-queue Connect Lands in Local Queue (0.2)

- Preconditions: `rss_check` enabled with multi-queue + v6 `rss_tbl` rules (including `:` addresses); the local/peer end has a v6 address; NIC v6 RSS offload is available (04 §2.4).
- Steps: v6 connect multiple times.
- Assertion: v6 source ports land in the local queue (verified via `ff_rss_check6` or packet capture); simultaneously, IPv4 connects still work normally (v4/v6 coexist without interference).
- 【Pending confirmation: v6 connect's kernel integration point (unified `in_pcb_lport_dest` vs. independent `in6_pcb` path, 04 §2.3) — integration verification must cover the actually-effective path.】

### 2.5 IT-RSS-05: Multi-process Scale-out (0.1/0.3)

- Preconditions: multi-process (primary + N secondary, each bound to a different queue).
- Steps: each process concurrently initiates connects.
- Assertion: each process's selected source ports all land in its **own** queue (no cross-process misassignment); verify RSS port selection isolation is correct under multi-process.

### 2.6 IT-RSS-06: Bind-then-connect Port Lands in Local Queue (0.5)

- Preconditions: `rss_check` enabled with multi-queue + FSTACK; the local addr (vip) is configured on the DPDK NIC (`f-stack-x`, **not lo**, AC-05-7).
- Steps: use a minimal client program to first `bind(vip, 0)` then `connect(remote)` for each connection (multiple times), record the selected local source port.
- Assertion:
  1. After each connection's `bind`, no port is prematurely occupied (the port space does not shrink linearly with the number of bind calls — comparing against the "bind occupies a port first" port-exhaustion behavior, verifying the port-reuse semantics of IP_BIND_ADDRESS_NO_PORT).
  2. For each connection, the source port selected by connect passes verification via independent `ff_rss_check` (or packet capture against the NIC's actual RSS queue) that it lands in **the local process's corresponding queue**; 0% land in the wrong queue.
- Comparison: consistent with IT-RSS-01 (direct connect) results (both land in the local queue) — verifying that 0.5 pulls bind-then-connect back onto the same RSS path as direct connect.
- v6: bind(v6_vip,0)+connect6 verified the same way (following v6 path verification, corresponding to RT-RSS-06).
- 【Pending confirmation: minimal bind-then-connect client carrier (whether `example/` includes one, or self-built), same pending item as §2.1's client carrier.】

---

## 3. Real-machine Test Specification

> Environment (plan §Test Environment): DPDK-dedicated NIC IP `9.134.214.176` (DPDK side, reachable via ssh `f-stack-client`); kernel stack tested via `127.0.0.1`.
> DPDK: 24.11.6 (dpdk-stable-24.11.6).
> Mandatory conventions: real-machine process cleanup goes through `/data/workspace/kill_process.sh`; temporary artifact deletion goes through `rm_tmp_file.sh`; local values such as config.ini's local IP/lcore_mask **must not be committed**.

### 3.1 RT-RSS-01: DPDK-side IPv4 Multi-queue Source Port Distribution Lands on Local Core (0.1)

- Topology: F-Stack under test (DPDK NIC `9.134.214.176`, multi-queue/multi-process); `f-stack-client` as the peer.
- Steps:
  1. Configure multi-queue (multi-lcore) in config.ini + enable `rss_check` v4 rules; record the environment (dpdk 24.11.6, NIC model, queue count, reta_size, nb_queues, whether the key is symmetric).
  2. The tested end initiates a large number of active connects to `f-stack-client`.
  3. Verify via packet capture / NIC queue statistics + per-queue `ff_rss_check` counting that each connection's packets land on the correct process/queue.
- Assertion: the source-port distribution from connects results in 100% of packets landing on the local core/queue (no misassignment); consistent with 13.0 baseline behavior.
- Measurement hook: connection-establishment rate, per-queue distribution (shared instrumentation with the 08 performance baseline).

### 3.2 RT-RSS-02: Kernel Stack / LOOPBACK Regression (0.1)

- Topology: `127.0.0.1` kernel-stack path.
- Steps: local loopback connect.
- Assertion: the LOOPBACK special-case takes effect (no RSS, direct break, 04 §1.4 / 13.0 L902-903); kernel-stack local loopback connections work normally without exceptions.

### 3.3 RT-RSS-03: Thash Dynamic Path Real-machine Test (0.3)

- Steps: under `9.134.214.176` multi-queue, construct connections that miss the static table (dynamic branch), enable thash reverse-computation.
- Assertion: the dynamic path's selected ports have a 100% correct queue-landing rate (0 soft-compute re-verification failures); performance comparison per 08.
- Rollback verification: temporarily force ctx init to fail (or set attempts=extremely small) and observe that functionality remains normal after degrading to soft-compute.

### 3.4 RT-RSS-04: IPv6 Real-machine Test (0.2)

- Preconditions: `9.134.214.176` side / `f-stack-client` has a v6 address; NIC `flow_type_rss_offloads` includes v6 fields (04 §2.4, confirmed on real machine).
- Steps: v6 multi-queue connect.
- Assertion: v6 source ports land in the local queue; IPv4 simultaneously regresses normally.
- 【Real-machine NIC v6 RSS offload: confirmed supported on a physical machine with v6 RSS capability; when unsupported (e.g. local virtio) v6 falls into a single queue (L705 narrowing), a hardware capability limitation, not a bug.】
- **Execution conclusion (2026-07): PASS.** v6 multi-queue connect verified end-to-end: v6 source ports land in the local queue with IPv4 zero regression (see 10 §4-bis). The IPv6 server scenario (helloworld v6 listen + client `curl -6`) was also verified on this machine's runtime (see `freebsd_13_to_15_upgrade_spec/ipv6-tentative-fix-execution-log.md`).

### 3.5-bis RT-RSS-05: DPDK-side Bind-then-connect Lands on Local Core (0.5 v4)

- Topology: F-Stack under test (DPDK NIC `9.134.214.176`, multi-queue/multi-process, vip configured on `f-stack-x` NIC); `f-stack-client` as the peer.
- Steps:
  1. Configure multi-queue in config.ini + enable `rss_check` v4 rules; vip serves as the local addr (DPDK NIC).
  2. The tested end uses a minimal client: for each connection, `bind(vip, 0)` → `connect(f-stack-client)`, initiating a large number of active connections.
  3. Verify via packet capture/NIC queue statistics + per-queue `ff_rss_check` counting that packets land on the correct process/queue.
- Assertion: the bind-then-connect source-port distribution results in 100% of packets landing on the local core/queue (consistent with RT-RSS-01's direct connect, 0% misassigned); bind does not prematurely occupy a port (port reuse works normally).
- Comparison: when the vip is bound on `lo` (kernel stack), DPDK RSS is not engaged (AC-05-7, recorded as an expected difference, not a bug).

### 3.6 RT-RSS-06: Bind-then-connect v6 + Kernel-stack Comparison (0.5 v6)

- Preconditions: `9.134.214.176` side/`f-stack-client` has a v6 address; NIC `flow_type_rss_offloads` includes v6 fields (04 §2.4 confirmed on real machine); v6 vip configured on the DPDK NIC.
- Steps: bind(v6_vip,0)+connect6 multiple times.
- Assertion: v6 source ports land in the local queue (verified via `ff_rss_check6` or packet capture); v4 bind-then-connect simultaneously continues working normally (v4/v6 coexist without interference).
- Kernel-stack comparison: `127.0.0.1`/lo bind(0)+connect via the kernel stack works normally (does not go through RSS, comparison verifying that the 0.5 change did not break the kernel stack's local path).
- 【v6 connect kernel integration path (04 §3-ter.4) and real-machine NIC v6 RSS offload capability: the effective path and hardware support were confirmed on a physical machine.】
- **Execution conclusion (2026-07): PASS.** v6 bind-then-connect multiple times: source ports land in the local queue (`ff_rss_check6`/packet capture); v4 bind-then-connect coexists normally; `127.0.0.1`/lo kernel-stack bind(0)+connect comparison is normal (kernel-stack local path not broken). The reverse-proxy scenario (nginx `--with-ff_module` + F-Stack side v6 VIP listen, proxy to upstream) was also verified end-to-end on a physical machine (see 10 §4-bis / §6-ter.3).

### 3.5 Real-machine Execution and Cleanup Constraints

- Starting/stopping F-Stack processes: clean up with `/data/workspace/kill_process.sh <pid|pattern>` (direct kill is strictly forbidden).
- Packet capture/log temp file deletion: `/data/workspace/rm_tmp_file.sh <path>` (direct rm is strictly forbidden).
- Adding execute permission to scripts, etc.: `/data/workspace/chmod_modify.sh <mode> <path>` (direct chmod is strictly forbidden).
- config.ini local real-machine values (`portN` local IP `9.134.x`, `lcore_mask`, `idle_sleep`) are **for local use only; roll back to the repository default values via `git diff` before committing** (consistent with existing conventions).

---

## 4. Zero-regression Criteria (Hard Constraints)

> Corresponds to 01 §1.5/§2.5/§3.5, and 06's per-milestone bounce gates. All are PASS/FAIL assertions.

| No. | Criterion | Verification Method | Source |
|------|------|----------|------|
| RG-1 | Compiles successfully with FSTACK disabled and behavior reverts to native FreeBSD | Compile with FSTACK disabled + native port-selection behavior | 04 §1.4; 06 R-A.4 |
| RG-2 | When FSTACK is enabled but `rss_check` enable=0, behavior is consistent with not having introduced this feature at all | IT-RSS-02 | 04 §1.4 |
| RG-3 | When single-queue (nb_queues<=1), `ff_rss_check` always returns 1, falling back to native port selection | Unit test (L2858) + IT-RSS-02 | `ff_dpdk_if.c:2858` |
| RG-4 | LOOPBACK (`127.0.0.1`) does not do RSS, kernel-stack loopback works normally | RT-RSS-02 | 04 §1.4 |
| RG-5 | All 6 existing RSS unit tests (L361-455) pass | Unit-test regression | `test_ff_dpdk_if.c:361-455` |
| RG-6 | After introducing 0.2/0.3, **the pure IPv4 path's functionality is unchanged** (structs/interface signatures untouched) | TC-U-RSS-02-05 full v4 regression + RT-RSS-01 | 01 §2.5; 05 §4; 06 R-C.4 |
| RG-7 | Pure IPv4 config.ini parsing results are unchanged (the v6 branch does not affect v4) | TC-U-RSS-02-04 v4-branch assertion | 05 §3.2 |
| RG-8 | All new + existing unit tests PASS in a single `cmocka_run_group_tests` run | CI / local unit test run | §1.4 |
| RG-9 | 0.3's reverse-computed ports have 0 soft-compute re-verification failures (never select the wrong queue) | TC-U-RSS-03-02 + RT-RSS-03 | 01 §3.5 (zero tolerance) |
| RG-10 | 0.5's bind(addr,N) (N≠0) behavior unchanged (port fixed + normally inserted into hash) | TC-U-RSS-05-03 | 01 §3-ter.7 AC-05-4 |
| RG-11 | 0.5's disabling FSTACK / single-queue / enable=0 reverts bind/connect to native behavior | Same chain as RG-1/2/3 + RT-RSS-05 comparison | 01 §3-ter.7 AC-05-5 |
| RG-12 | 0.5's REUSEPORT_LB bind(addr,0) behaves correctly (does not break the L740 MPASS) | TC-U-RSS-05-01 variant / integration | 01 §3-ter.7 AC-05-6 |

---

## 5. Acceptance Matrix (Requirement × Test Case Coverage)

| Requirement | Acceptance Point (01 Acceptance Criteria) | Unit | Integration | Real-machine | Zero Regression |
|------|----------------------|------|------|------|--------|
| **0.1** | Kernel hook back-port, connect port selection lands in local queue, fallback on disable/single-queue, existing unit tests pass | 01-01~01-06 | IT-RSS-01/02/05 | RT-RSS-01/02 | RG-1~5 |
| **0.2** | v6 connect lands in local queue, IPv4 zero regression, v6 unit test/integration passes | 02-01~02-05 | IT-RSS-04 | RT-RSS-04 | RG-6/7 |
| **0.3** | Reverse-computed ports pass soft-compute re-verification and land in local queue (never select wrong), static-table fast path does not degrade, fallback on init failure/attempts exhaustion | 03-01~03-05 | IT-RSS-03 | RT-RSS-03 | RG-9 |
| **0.5** | inp_lport==0 after bind(addr,0), connect enters RSS_CHECK branch and lands in local queue, bind(addr,N) zero regression, v6 sync, reverts to native on disable-FSTACK/single-queue | 05-01~05-05 | IT-RSS-06 | RT-RSS-05/06 | RG-10/11/12 |

- Coverage completeness: every acceptance criterion in 01 for each requirement has ≥1 corresponding test case; the zero-tolerance item (0.3 never selecting the wrong queue) has triple-layer protection via unit test + real machine + mandatory soft-compute re-verification; 0.5, since it changes the kernel in_pcb (not directly covered by lib cmocka unit tests), has its queue-landing correctness primarily verified via integration (IT-RSS-06) + real machine (RT-RSS-05/06), with the unit-test layer only verifying inp_lport state after bind (pending kernel test carrier, §1.5-ter).
- **IPv6 functional-test execution conclusion (2026-07): all passed.** IPv6 server (this machine's runtime: helloworld v6 listen + client `curl -6`), client (physical-machine v6 connect / RSS reverse path RT-RSS-04/06), and reverse proxy (physical-machine nginx `--with-ff_module` + v6 VIP) functional tests are all completed and passed (evidence and conclusions in 10 §4-bis / §6-bis.8 / §6-ter.3 and `freebsd_13_to_15_upgrade_spec/ipv6-tentative-fix-execution-log.md`).

---

## 6. Pending-confirmation Item List (Handed Off to Coding/Subsequent Phases for Verification, Not Speculated)

1. 【Pending confirmation】The injection method for the static `rss_reta_size` (`ff_dpdk_if.c:133`) in unit tests (§0.3); if it cannot be injected, formal hit-correctness verification degrades to the integration/real-machine layer.
2. 【Pending confirmation】The existing return semantics of `ff_rss_tbl_get_portrange` (L2796) (the specific return codes for hit/miss/error), assertions based on the actual implementation (§1.1).
3. 【Pending confirmation】Whether `ff_rss_tbl_get_portrange`'s port rotation is via the function self-incrementing the `dport[0]` index or the caller advancing it (§1.1 TC-01-02).
4. 【Pending confirmation】`ff_rss_check6`/`ff_rss_tbl6_*`/`ff_rss_adjust_sport[6]`/`ff_rss_thash_ctx_init` are new functions, landing line numbers to be backfilled after coding; test points follow the 05 contract in advance.
5. 【Pending confirmation】The linkage attribute of `rss_tbl_cfg_handler` (`ff_config.c:880`) (static?), determining the v6 parsing unit-test entry point (§1.2 TC-02-04).
6. 【Pending confirmation】Whether desired_value selection can be independently observed and asserted within `ff_rss_adjust_sport` (§1.3 TC-03-01).
7. 【Pending confirmation】The active-connect client carrier for integration/real-machine testing (whether helloworld includes connect, or uses an echo client / self-built minimal program) (§2.1).
8. 【Pending confirmation】The actual kernel integration path for v6 connect (unified `in_pcb_lport_dest` vs. independent `in6_pcb`), integration/real-machine must cover the effective path (§2.4).
9. 【Pending confirmation】Real-machine NIC v6 RSS offload capability (§3.4); if unsupported, the v6 real-machine item is recorded as unmet condition (hardware limitation).
10. 【Pending confirmation】The unit-test carrier for 0.5's R-E kernel in_pcb/in6_pcb functions (FreeBSD kernel unit test framework / self-built stub) — the existing lib cmocka unit test does not cover kernel in_pcb, TC-U-RSS-05-*'s kernel-level assertions depend on a kernel test carrier, otherwise degrade to the integration/real-machine layer (§1.5-ter).
11. 【Pending confirmation】0.5's minimal bind-then-connect client carrier (whether `example/` includes one / self-built) (§2.6/§3.5-bis).
12. 【Pending confirmation】0.5's v6 connect L515 entry-into-RSS-branch condition coordination scheme (04 §3-ter.4 Path B)'s actually effective path, integration/real-machine must cover the effective path (§1.5-ter TC-05-05 / §3.6 RT-RSS-06).
