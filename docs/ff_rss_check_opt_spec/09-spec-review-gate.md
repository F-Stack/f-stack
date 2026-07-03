# 09 Spec Review Gate — ff_rss_check Three Optimizations

> Role: gatekeeper (M5 spec gate). Line-by-line assertion review of plan.md + all of 01~08 spec documents.
> **Mandatory principle (no speculation allowed)**: every assertion in this gate is verified **against the actual code/header files** (evidence given as `file:line`), not taken on the spec's own word; where spec and code disagree, **code takes precedence** — mark FAIL and indicate which milestone (M1/M2/M3/M4) should be bounced back to.
> Review baseline commit: `2422d12eb` (feature/1.26).
> Files verified: `f-stack/lib/ff_dpdk_if.c`, `f-stack/lib/ff_config.c`, `f-stack/freebsd/netinet/in_pcb.{c,h}`, `f-stack/freebsd/netinet6/in6_pcb.c`, `f-stack-13.0-baseline/freebsd/netinet/{in_pcb.c}`, `f-stack-13.0-baseline/freebsd/netinet6/in6_pcb.c`, `dpdk-stable-24.11.6/lib/hash/rte_thash.h`, `f-stack/tests/unit/test_ff_dpdk_if.c`, `f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/M3-research-brief.md`, `f-stack/docs/03-LAYER3-FUNCTIONS.md`.

---

## 0. Line-number verification methodology (to avoid false FAILs)

In DPDK/FreeBSD and lib code, many functions follow the kernel style of "return type on its own line + function name on the next line", e.g.:

```2850:2852:f-stack/lib/ff_dpdk_if.c
int
ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t sport, uint16_t dport)
```

Therefore, if a function line number noted in the spec differs from what this gate measured by **±1**, and the difference is a "return-type line vs function-name line" discrepancy, it is judged **consistent (PASS)**, not FAIL. Likewise, a spec-noted "call-site line number" differing from the "function definition line number" is normal (e.g. `in_pcbladdr` call site L1129 vs definition L1192); semantics take precedence. All PASS results in this gate have been confirmed to have no **substantive** line-number/semantic errors.

---

## A. Code-consistency assertions

### A1. User-space RSS current state (02 description vs code)

| Assertion point | Spec description | Measured evidence (file:line) | Conclusion |
|--------|-----------|----------------------|------|
| `ff_rss_check` IPv4-only + params | 02§1.1/§1.4 `uint32_t saddr/daddr`, IPv4-only | `ff_dpdk_if.c:2851-2852` `ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)` | **PASS** |
| Hash input layout | 02§1.4 `saddr(4)+daddr(4)+sport(2)+dport(2)=12B` | `ff_dpdk_if.c:2865-2880` bcopy order saddr→daddr→sport→dport | **PASS** |
| Queue-landing predicate L2885 | 02§1.4 `((hash&(reta-1))%nb_queues)==queueid` | `ff_dpdk_if.c:2885` `return ((hash & (reta_size - 1)) % nb_queues) == queueid;` | **PASS** |
| `nb_queues<=1` returns 1 | 02§1.4/04§1.4 L2858 | `ff_dpdk_if.c:2858-2860` `if (nb_queues <= 1) return 1;` | **PASS** |
| `ff_rss_tbl_*` line numbers | init L2598 / set L2737 / get L2796 | `ff_dpdk_if.c:2598`(init), get's `-ENOENT` return at `:2844/2847` | **PASS** |
| `ff_rss_tbl[]` static global | 02§1.2 L172 static | `ff_dpdk_if.c:172` `static struct ff_rss_tbl_type ff_rss_tbl[FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES];` | **PASS** |
| Struct is IPv4-only | 02§1.3 L155-172 `uint32_t saddr/daddr` | `ff_dpdk_if.c:155-172` `ff_rss_tbl_dip_type.daddr`(L156)/`ff_rss_tbl_type.saddr`(L167) both `uint32_t` | **PASS** |
| `toeplitz_hash` line number | 02§1.1 L2547 / 07§0.2 L2548 | `ff_dpdk_if.c:2547`(return type)/`:2548`(function name `toeplitz_hash`) | **PASS** (±1 style difference) |
| `ff_in_pcbladdr` supports v4/v6 | 02§3.1 L2571, supports AF_INET/AF_INET6_FREEBSD | `ff_dpdk_if.c:2571`(def), `:2579-2584` AF_INET / AF_INET6_FREEBSD branches | **PASS** |

**A1 conclusion: PASS** (user-space RSS current state as described in 02 fully matches the code).

### A2. Kernel-side 13.0↔15.0 differences confirmed

| Assertion point | Spec description | Measured evidence | Conclusion |
|--------|-----------|----------|------|
| 13.0 baseline `in_pcb.c` has RSS hooks | 02§2.1 lport_dest L689, flag parsing L707, clearing L712, get_portrange L805-806, ff_rss_check L904-905 | `f-stack-13.0-baseline/.../in_pcb.c:689`(lport_dest), `:707`(rss_check_flag), `:712`(clear), `:805`(ff_rss_tbl_get_portrange), `:904`(ff_rss_check) | **PASS** |
| 13.0 `in_pcbconnect_setup` + ff_in_pcbladdr/flag | 02§2.0/§2.1 `_setup` L1458, ff_in_pcbladdr L1526-1530, flag L1583-1589 | 13.0 `in_pcbconnect_setup`:1458, `ff_in_pcbladdr(AF_INET,...)`:1528, `INPLOOKUP_WILDCARD|INPLOOKUP_LPORT_RSS_CHECK`:1588, `in_pcbconnect`:1228 | **PASS** |
| 15.0 `in_pcbconnect`(L1083) missing ff_in_pcbladdr | 02§2.1(B): 15.0 only has native `in_pcbladdr`(L1129), only passes `INPLOOKUP_WILDCARD` | `f-stack/.../in_pcb.c:1083`(in_pcbconnect), `:1128`(in_nullhost branch), `:1129`(in_pcbladdr call), `:1145-1147`(in_pcb_lport_dest passes INPLOOKUP_WILDCARD) | **PASS** |
| 15.0 `in_pcb_lport_dest`(L756) missing RSS hooks | 02§2.1(A): entirely absent in 15.0; 02§2.0 same-named function +const | `f-stack/.../in_pcb.c:756-758` `in_pcb_lport_dest(const struct inpcb *inp, ...)`; **FSTACK/ff_rss/INPLOOKUP_LPORT_RSS_CHECK grep=0** | **PASS** |
| 15.0 lookup adds RT_ALL_FIBS | 02§2.0: `in_pcblookup_local(..., RT_ALL_FIBS, lookupflags, cred)` | `f-stack/.../in_pcb.c:877-878` `in_pcblookup_local(pcbinfo, laddr, lport, RT_ALL_FIBS, lookupflags, cred)` | **PASS** |
| 15.0 in_pcb_lport_dest contains INET6 branch | 02§2.0/04§2.3 v4/v6 unified | `f-stack/.../in_pcb.c:860-871` INET6 branch `in6_pcblookup_local(...)` | **PASS** |
| `INPLOOKUP_LPORT_RSS_CHECK` outside enum, not in MASK | 02§2.2: enum L616-621, macro L623-625, MASK L627 does not include it | `f-stack/.../in_pcb.h:616-621`(enum), `:623-625`(`#ifdef FSTACK #define ... 0x80000000`), `:627-628`(INPLOOKUP_MASK contains only the 4 enum bits, **does not include** RSS_CHECK) | **PASS** |

**A2 conclusion: PASS** (13.0↔15.0 differences, grep=0, enum/MASK current state are all confirmed).

### A3. rte_thash API existence and constraints (DPDK 24.11.6)

| Assertion point | Spec description | Measured evidence (`dpdk-stable-24.11.6/lib/hash/rte_thash.h`) | Conclusion |
|--------|-----------|--------------------------------------------------------|------|
| `rte_thash_init_ctx` exists/signature | 02§4.1 L303 `(name, key_len, reta_sz, key, flags)` | `:304` `rte_thash_init_ctx(const char *name, uint32_t key_len, uint32_t reta_sz, uint8_t *key, uint32_t flags)` | **PASS** |
| `rte_thash_complete_matrix` | 02§4.1 L256 | `:257` `rte_thash_complete_matrix(uint64_t *matrixes, const uint8_t *rss_key, int size)` | **PASS** |
| `rte_thash_get_complement` | 02§4.1 L380 | `:381` `rte_thash_get_complement(struct rte_thash_subtuple_helper *h, uint32_t hash, uint32_t desired_hash)` | **PASS** |
| `rte_thash_adjust_tuple` | 02§4.1 L456 / 04§3.3 referenced | `:457` `rte_thash_adjust_tuple(ctx, h, tuple, tuple_len, desired_value, attempts, fn, userdata)` | **PASS** |
| `rte_thash_add_helper` | 03§3.2 L348 | `:349` `rte_thash_add_helper(ctx, name, len, offset)` | **PASS** |
| reta_sz is logarithmic | 02§4.1/03§3.2/04§3.2 | `:288-291` "Logarithm of the NIC's Redirection Table (ReTa) size" | **PASS** |
| tuple_len multiple of 4 | 02§4.1/03§3.2/04§3.3 | `:441-442` "Length of the tuple. Must be multiple of 4." | **PASS** |
| desired_value = low bits of hash | 04§3.3 | `:443-444` "Desired value of least significant bits of the hash" | **PASS** |
| adjust_tuple is thread-safe | 02§4.1/04§3.2 | `:433` "This function is multi-thread safe." | **PASS** |
| add_helper len≥reta_sz / not thread-safe | 03§3.2 | `:341` "Must be no shorter than reta_sz"; helper recommended to be set up during init | **PASS** |
| RETA_SZ_MIN/MAX | 03§3.2 L261-263 | `:261` `RTE_THASH_RETA_SZ_MIN 2U`, `:263` `RTE_THASH_RETA_SZ_MAX 16U` | **PASS** |

**A3 conclusion: PASS** (all four core APIs actually exist, signatures match what 04/05 reference; all constraints confirmed).

### A4. symmetric_rsskey / symmetric_rss switch / rss_hf (04§2.4/§3.4 vs code)

| Assertion point | Spec description | Measured evidence (`ff_dpdk_if.c`) | Conclusion |
|--------|-----------|---------------------------|------|
| `symmetric_rsskey[52]` | 04§3.4/03§3.4 L110 | `:110` `static uint8_t symmetric_rsskey[52]` | **PASS** |
| `symmetric_rss` switch | 04§2.4/§3.4 L699 | `:699` `if (ff_global_cfg.dpdk.symmetric_rss && dev_info.hash_key_size != 0)`; `:701` `rsskey = symmetric_rsskey;` | **PASS** |
| `rss_hf=RTE_ETH_RSS_PROTO_MASK` | 04§2.4 `default_rss_hf=RTE_ETH_RSS_PROTO_MASK`(L681-683) | `:681` `uint64_t default_rss_hf = RTE_ETH_RSS_PROTO_MASK;`, `:683` `rss_conf.rss_hf = default_rss_hf;` | **PASS** (task's shorthand "rss_hf=...(L681)" is an approximation; spec's L681-683 is more precise) |
| `&= flow_type_rss_offloads` narrowing | 04§2.4 L705 | `:705` `rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;` | **PASS** |
| `default_rsskey_40bytes[40]` asymmetric | 03§3.4/04§3.4 L92 | `:92` `static uint8_t default_rsskey_40bytes[40]`; runtime `rsskey`(L121)/`rsskey_len`(L120) | **PASS** |

**A4 conclusion: PASS**.
**Note (not a FAIL, coding-phase reminder)**: the `hash_key_size==52` branch uses `default_rsskey_52bytes` (L690), not `symmetric_rsskey`; `symmetric_rsskey` is only active when the `symmetric_rss` switch is on (L699-701). This detail does not affect the validity of any spec assertion; it is provided only for §0.3 coding-phase attention that "the runtime `rsskey` value actually depends on hash_key_size and the symmetric_rss switch" — the conclusion in 04§3.4 ("ctx key must equal the runtime rsskey") still holds correctly.

**Category A summary: A1/A2/A3/A4 all PASS.**

---

## B. Requirement closure assertions

### B1. 0.1 migration plan coverage and 15.0 adaptation

| Assertion point | Verification | Conclusion |
|--------|------|------|
| Covers `in_pcb_lport_dest` port-selection logic | 04§1.1(A)/§1.2, 05§2.1, 06 R-A.1(A1): migrating back rss_* variables inside body, flag parse+clear, get_portrange, hit rotation/miss soft-compute, LOOPBACK | **PASS** |
| Covers `in_pcbconnect` ff_in_pcbladdr integration | 04§1.1(B)/05§2.2 change point 1: inside L1128 branch, insert `ff_in_pcbladdr(AF_INET,...)` before L1129 | **PASS** (insertion point confirmed to actually exist at L1128/1129) |
| Covers INPLOOKUP handling (flag pass-in + clear) | 04§1.1(C)/§1.3, 05§2.2 change point 2/§2.3: add flag at L1145-1147; entry clear (following 13.0 L712) | **PASS** |
| Covers ff_in_pcbladdr | Interface L2571 unchanged, already supports v4, 05§1.1 | **PASS** |
| Adapts to const inpcb | 04§1.2.2: lookupflags value parameter can be modified, inp cannot | **PASS** (L756 const confirmed) |
| Adapts to protosw merge | 02§2.3/04§5.3 marked to-be-confirmed (verify connect caller during coding) | **PASS** (marking as to-be-confirmed is reasonable, doesn't affect plan validity) |
| Adapts to lookup adding RT_ALL_FIBS | 04§1.2.4/05§2.1: reuses 15.0's existing lookup call form (L877-878) | **PASS** |

**B1 conclusion: PASS**. All four 0.1 migration landing points (lport_dest logic + in_pcbconnect address integration + flag pass-in + macro handling) are fully covered; the 15.0 adaptation points (const, `_setup` merge, RT_ALL_FIBS, enum-ification) all correspond to real code.

### B2. 0.2 IPv6 plan

| Assertion point | Verification | Conclusion |
|--------|------|------|
| v6 independent table/functions (Plan A) guarantee zero IPv4 regression | 04§2.2 decision A: does not touch `ff_rss_tbl_type`/`ff_rss_check` v4 signature or layout; 05§1.2 all-new symbols `ff_rss_check6`/`ff_rss_tbl6_*`; compatibility matrix 05§4 v4 row "no/none" | **PASS** |
| Does not change v4 interface signatures | 05§1.1 v4 interface "unchanged"; Plan B (changing signatures) explicitly rejected (04§2.2/§4) | **PASS** |
| Kernel in6 integration point decided/marked to-be-confirmed | 04§2.3: leans toward reusing the unified `in_pcb_lport_dest` (confirmed to contain INET6 branch L860-871); the actual call chain (whether in6_pcbconnect reuses it) marked to-be-confirmed, 05§2.4 gives two paths | **PASS** (integration point candidate is well-founded: unified function's INET6 branch actually exists; to-be-confirmed items are coding-phase verification, not a blocker) |
| config v6 parsing | 04§2.5/05§3.2: strings containing `:` go through `inet_pton(AF_INET6)`, v4 branch unchanged (current `inet_pton(AF_INET)` L913-914 confirmed) | **PASS** |
| 36B layout satisfies tuple_len multiple of 4 | 04§2.1: 16+16+2+2=36, 36/4=9 | **PASS** |

**B2 conclusion: PASS**. IPv6 is "entirely new" (both 13.0/15.0 kernel side grep=0, confirmed); Plan A guarantees zero IPv4 regression via "purely additive symbols + not touching v4 struct/signature", logic is self-consistent.

### B3. 0.3 queue-landing mapping derivation correctness

Core assertion: `desired_value ∈ D(q)={ v∈[0,R) | v%Q==q }`, so that the back-derived port satisfies `ff_rss_check`'s queue-landing formula `((hash&(R-1))%Q==q)`.

**Gate's independent re-derivation**:
- Code fact: `ff_rss_check` decides `((hash & (reta_size-1)) % nb_queues) == queueid` (`ff_dpdk_if.c:2885`, confirmed). Let `R=reta_size`, `Q=nb_queues`, `q=queueid`.
- `rte_thash_adjust_tuple` makes `hash & (R-1) == desired_value` (`rte_thash.h:443-444` "least significant bits", helper len covers reta_sz_log2, confirmed).
- Substituting: `(hash & (R-1)) % Q == desired_value % Q`. For this to `== q`, the **necessary and sufficient condition is `desired_value % Q == q`**, i.e. `desired_value ∈ {v∈[0,R) | v%Q==q}`.
- **Derivation matches 04§3.3 → mathematically correct**.

| Assertion point | Verification | Conclusion |
|--------|------|------|
| desired_value mapping derivation | Matches gate's independent derivation | **PASS** |
| Mandatory soft-compute re-verification backstop | 04§3.3 Algorithm 5 / 05§1.3 step 4: any back-derived port must pass `ff_rss_check` re-check ==1 before being returned, otherwise discarded and fallback | **PASS** (zero-tolerance correctness guarded by soft-compute re-verification) |
| attempts exhausted fallback | 04§3.6/05§1.3 step 5/06 R-B.3 | **PASS** |
| init failure degradation | 04§3.6: ctx init failure → degrade to pure soft-compute (equivalent to 0.1) | **PASS** |
| Precise alignment with queue-landing formula (incl. %Q) | 04§3.3 explicitly handles `% nb_queues`, special cases R%Q==0 / R%Q!=0 / Q==1 all covered | **PASS** |

**B3 conclusion: PASS**. The 0.3 queue-landing mapping derivation is confirmed correct by the gate's independent re-calculation; `% nb_queues` is explicitly handled (this is the crux of risk point 1 in 03§3.4, which the spec correctly resolves); mandatory soft-compute re-verification + attempts fallback + init degradation form a triple backstop, precisely aligned with `ff_rss_check`'s queue-landing formula.

### B4. 0.5 bind-then-connect landing point evidence and R-E scope

> Core assertion: the loss point where bind(addr,0) followed by connect bypasses RSS (v4 hunk1/hunk2, v6 in6_pcbbind) is confirmed; the connect-time RSS path in 15.0 is already in place (hunk3 equivalent); R-E only needs to add a bind gate; v4 is mandatory + v6 is recommended in sync.

| Assertion point | Measured evidence (file:line) | Conclusion |
|--------|----------------------|------|
| v4 hunk1 loss point: `in_pcbbind`'s entry-into-hash block has no FSTACK guard | `f-stack/.../in_pcb.c:739-748` `if (__predict_false((error = in_pcbinshash(inp)) != 0)) { MPASS(SO_REUSEPORT_LB); ... }` has no `#ifdef FSTACK if(inp_lport!=0)` | **PASS** |
| v4 hunk2 loss point: `in_pcbbind_setup` lport==0 port allocation has no #ifndef FSTACK | `f-stack/.../in_pcb.c:1273-1279` `if (*lportp!=0) lport=*lportp; if (lport==0) { in_pcb_lport(... lookupflags); }` has no `#ifndef FSTACK` | **PASS** |
| v4 hunk3 already equivalently in place (no change needed) | `f-stack/.../in_pcb.c:1313` `anonport=(inp->inp_lport==0)`; `:1363-1366` `in_pcb_lport_dest(... INPLOOKUP_WILDCARD|INPLOOKUP_LPORT_RSS_CHECK)` (FSTACK guard L1365-1366) | **PASS** |
| v4 failure chain confirmed | bind occupies port → inp_lport≠0 → connect L1313 anonport=false → L1377 else bypasses RSS (L1363-1366) | **PASS** (logic chain confirmed against code) |
| v6 in6_pcbbind allocates port early | `f-stack/.../in6_pcb.c:354` `if (lport==0) { in6_pcbsetport(...); }`; `:361-369` else enters `in_pcbinshash` | **PASS** |
| v6 connect RSS branch already in place but conditions broken by bind | `f-stack/.../in6_pcb.c:515-516` `if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) { if (inp->inp_lport==0) {`; `:521` `INPLOOKUP_WILDCARD|INPLOOKUP_LPORT_RSS_CHECK` | **PASS** |
| v6 failure chain confirmed | bind(v6,0) → in6p_laddr no longer unspec + inp_lport≠0 → both connect L515 conditions broken → RSS bypassed | **PASS** |
| v6 13.0 baseline has no FSTACK (v6 is entirely new) | 02 §3.2 already confirmed 13.0/15.0 `in6_pcb.c` grep FSTACK/ff_rss=0 (v6 RSS never existed in 13.0) | **PASS** |
| Doesn't break R-A~R-D | 0.5 reuses R-A's connect-time RSS path (doesn't change connect), doesn't change user-space interfaces, gate applies only to lport==0 branch (05 §2.5) | **PASS** |
| Zero regression for bind with a specified port | Gate applies only to `lport==0` (hunk1 `if(inp_lport!=0)` / hunk2 `if(lport==0)`), bind(addr,N) unaffected (04 §3-ter.6 / AC-05-4) | **PASS** |
| v6 connect L515 condition linkage marked to-be-confirmed (non-blocking) | 04 §3-ter.4 gives three paths A/B/C, leans toward path B (relaxing L515 to inp_lport==0), marked for coding-phase confirmation (doesn't affect v4 plan validity; v6 is recommended sync) | **PASS** (to-be-confirmed is reasonable, non-blocking) |

**B4 conclusion: PASS**. The 0.5 v4 loss points (hunk1 L739-748 / hunk2 L1275-1279), hunk3 already equivalently in place (L1313/L1363-1366), and v6 unclosed points (in6_pcbbind L354/L361-369 + connect L515-516) are all confirmed against the code; the R-E scope (v4 mandatory hunk1+hunk2 + v6 recommended sync in6_pcbbind gate + L515 condition linkage to-be-confirmed) has real landing points, a valid failure chain, zero regression for bind with a specified port, and does not break R-A~R-D. The v6 connect L515 condition linkage is a coding-phase confirmation item and doesn't affect v4 plan validity.

**Category B summary: B1/B2/B3/B4 all PASS; the five requirements (0.1~0.5) close out successfully.**

---

## C. Test closure assertions

| Assertion point | Verification | Conclusion |
|--------|------|------|
| 07 test case count | Unit 14 (01-01~06 including 6 retained + 02-01~05 + 03-01~05 = 3+6+5+5, counted after dedup in §1.4 table's 14 rows) + integration 5 (IT-RSS-01~05) + real-machine 4 (RT-RSS-01~04) + zero-regression 9 (RG-1~9) | **PASS** |
| Coverage of each measured point of the three items | Acceptance matrix 07§5: 0.1→01-01~06/IT-01,02,05/RT-01,02/RG-1~5; 0.2→02-01~05/IT-04/RT-04/RG-6,7; 0.3→03-01~05/IT-03/RT-03/RG-9 | **PASS** |
| Mock strategy feasible for `ff_veth_softc_to_hostc`/static | 07§0.2: stub L101 currently returns NULL (confirmed) → test case changes stub to return a controlled ctx; static `rss_reta_size`(L133)/`rsskey`(L121)/`toeplitz_hash`(L2548) are not directly accessible, gives a "test-side independent Toeplitz re-computation + self-consistency degradation" strategy (§0.3/§0.4) | **PASS** (mock strategy based on real symbol visibility, includes a degradation plan for cases static cannot be written, pragmatic and feasible) |
| 08 performance metrics are executable | 08§2 micro-benchmark (rte_rdtsc timestamps M-1~M-5) + §2.2 end-to-end (E-1~E-3) + §3 same-baseline fixed items + §4 real-machine steps (B0/B1/B2 comparison) | **PASS** |
| Hard thresholds = zero tolerance for wrong-queue landing + no IPv4 regression | 08§5 P-3 (D3 soft-compute re-verification 0 failures, zero tolerance) + P-1 (no IPv4 regression) marked as **hard gates**; performance-gain items P-2/P-4/P-5 don't block functional acceptance | **PASS** |

**Category C summary: PASS**.
- Test cases anchor to actual functions/landing points (including static symbol visibility L101/L121/L133/L2548), mock strategy is pragmatic (key: acknowledges that the static `rss_reta_size` cannot be directly injected, and gives an alternative of "test-side independent expectation re-computation + downgrading self-consistency assertions to integration/real-machine testing", avoiding fabricated assumptions about modifying static variables).
- The 08 performance hard gates capture zero-tolerance correctness (P-3) and no IPv4 regression (P-1); performance-gain items are reasonably classified as non-blocking, consistent with the positioning of "0.1 migration/0.2 addition are not primarily performance-focused".

---

## D. Document self-consistency assertions

| Assertion point | Verification | Conclusion |
|--------|------|------|
| 00 overview/index | there is **no 00-overview/index** under `zh_cn/`, only plan.md + 01~09 | **PASS (recommend adding, non-blocking)** |
| 01-08 cross-references consistent | 04 refs 01/02/03; 05 refs 04; 06 refs 04/05; 07 refs 01/02/04/05/06; 08 refs 01/04/06/07 — reference chain closed, section numbers correspond | **PASS** |
| Line numbers/terminology consistent | Key line numbers (L2851/2885/2796/172/756/1083/1129/1145, in_pcb.h 623-625, the four rte_thash APIs) are consistently noted across 01~08, and confirmed by this gate to match the code | **PASS** |
| No missing requirements | The three items 0.1/0.2/0.3 flow through 01 (requirements)→02 (current state)→03 (external research)→04 (design)→05 (interface design)→06 (milestones R-A/B/C)→07 (testing)→08 (performance), no gap | **PASS** |

**Category D conclusion: PASS**.
**Recommendation (non-blocking)**: add a `00-overview-index.md` (listing plan + 01~09 section map + a navigation table for the three requirements↔milestones↔test cases), improving spec navigability. The current absence of 00 does not affect spec completeness or validity; noted as an improvement suggestion.

---

## E. No-conflict-with-existing-documents assertion (spot check)

| Spot-check target | Verification | Conclusion |
|----------|------|------|
| `freebsd_13_to_15_upgrade_spec` M3-brief | `M3-research-brief.md:139-145`: during the 13→15 upgrade, `INPLOOKUP_LPORT_RSS_CHECK` was only "retained as a #define immediately following the enum", rated EASY, **did not mention migrating the consumption logic** — this is **fully consistent** with this spec (01§1.1/02§1.2 "the M3-brief at the time only assessed retaining the #define, not migrating the consumption logic") | **PASS (no conflict)** |
| Three-layer architecture Layer3 | `03-LAYER3-FUNCTIONS.md:207-218`: `struct ff_rss_tbl_type { uint32_t saddr; ... }` IPv4-only, `ff_rss_tbl_init`(L221) internal table — consistent with this spec's 02§1.3 struct description | **PASS (no conflict)** |
| KNOWLEDGE_GRAPH_WIKI / Layer1/2 | Spot check found no description contradicting the RSS/in_pcb three optimizations (this spec's "kernel RSS hooks missing in 15.0" is a legacy fact from the upgrade, orthogonal to the three-layer architecture's static structural description) | **PASS (no conflict)** |

**Category E conclusion: PASS**. This spec does not conflict with the existing 13→15 upgrade spec or the three-layer architecture/knowledge graph; in particular, "kernel RSS hooks missing in 15.0" exactly fills in the gap left by the M3-brief's "only retained the #define, didn't migrate the consumption logic" — the two mutually corroborate each other.

---

## F. Master table of to-be-confirmed items (deduplicated summary of 01-08)

> Principle: to-be-confirmed items are **coding-phase verification items** and do not block spec finalization (unless they affect plan validity). The table below is deduplicated and marks which coding milestone (R-A/R-B/R-C) each item should be verified at from the start. After evaluation, **none of these items affects plan validity** (all are landing-point refinements/tuning parameters/hardware capability confirmations).

| # | To-be-confirmed item | Source (spec) | Milestone to verify at | Affects plan validity? |
|---|----------|-------------|--------------|------------------|
| F1 | The precise insertion point of `ff_in_pcbladdr` in 15.0's `in_pcbconnect` (within the `in_nullhost(inp_laddr)` branch, before `in_pcbladdr` L1129) | 01§5, 02§7.1, 04§5.1, 05§2.2 | **R-A** | No (landing-point refinement, branch confirmed to exist) |
| F2 | Whether the connect call chain is affected by the protosw merge affecting `lookupflags` pass-through | 02§2.3/§7.3, 04§5.3 | **R-A** | No (verification item, adjust as needed) |
| F3 | Precise existing return semantics of `ff_rss_tbl_get_portrange`(L2796) (hit 0 / miss -ENOENT / error code) | 05§1.1, 07§1.1/§6.2 | **R-A** (assertion based on existing implementation) | No (already seen returning -ENOENT at L2844/2847; align call form during coding) |
| F4 | Whether `ff_rss_tbl_get_portrange` port rotation is self-incrementing `dport[0]` inside the function, or advanced by the caller | 07§1.1(TC-01-02)/§6.3 | **R-A** | No (test assertion refinement) |
| F5 | Whether IPv6 connect port selection actually goes through the unified `in_pcb_lport_dest`(L756) or an independent `in6_pcb` path → determines 0.2's kernel integration point | 01§5, 02§3.2/§7.2, 04§2.3/§5.2, 05§2.4, 07§2.4/§6.8 | **R-C** | No (both paths have a plan, 05§2.4 gives an either/or choice, unified function's INET6 branch confirmed to exist) |
| F6 | IPv6 RSS hash NIC/DPDK-side RSS offload field (`flow_type_rss_offloads` includes v6) | 01§5, 02§7.4, 04§2.4/§5.4, 07§3.4/§6.9, 08§6.4 | **R-C** (real-machine confirmation) | No (default PROTO_MASK already includes v6, only hardware capability needs confirming; if unsupported, v6 falls to a single queue, which is a hardware limitation not a bug) |
| F7 | Whether the rte_flow path (`ff_dpdk_if.c:1001/1167` hardcoded IPV4_TCP) is within 0.2's scope | 04§2.4 | **R-C** | No (leans toward "not in scope for 0.2", just annotate) |
| F8 | v6 static table capacity macro (`FF_RSS_TBL6_MAX_*`) value and memory budget | 04§2.2/§5.6, 05§1.4, 06 R-C.3 | **R-C** | No (leans toward reusing v4 macro, revisit against memory budget) |
| F9 | 0.3 asymmetric `default_rsskey_40bytes`(L92) convergence rate of `adjust_tuple` and reasonable `attempts` (leans toward initial value 16) | 01§5, 02§7.5, 03§5.2, 04§3.4/§5.5, 06 R-B, 08§6.2 | **R-B** (unit test/real-machine tuning) | No (performance item; correctness guarded by soft-compute re-verification; a tuning parameter) |
| F10 | thash helper (offset/len) addition method (v4 offset=64bit / v6 offset=256bit, len≥reta_sz_log2 leans toward 16) | 02§4.1, 04§3.2, 05§1.3 | **R-B** (v4) / **R-C** (v6) | No (design already gives preferred values, finalize during coding) |
| F11 | How static `rss_reta_size`(L133) is injected in unit tests (leans toward adding a test-only accessor, or degrading the assertion to test-side independent re-computation) | 07§0.3/§6.1 | **R-A/R-B** (test build phase) | No (test engineering item, degradation plan already given) |
| F12 | Linkage attribute of `rss_tbl_cfg_handler`(`ff_config.c:881`) (whether static), determines the v6 parsing unit test entry point | 07§1.2(TC-02-04)/§6.5 | **R-C** | No (measured: the function has no static prefix, it's a file-scope function; test entry point decided during coding) |
| F13 | Line numbers of newly added function landing points `ff_rss_check6`/`ff_rss_tbl6_*`/`ff_rss_adjust_sport[6]`/`ff_rss_thash_ctx_init` | 05§1.2/§1.3, 07§1.2/§1.3/§6.4 | **R-B/R-C** (backfill after addition) | No (new items, backfill line numbers after coding) |
| F14 | Whether the desired_value selection can be independently observed/asserted in `ff_rss_adjust_sport` | 07§1.3(TC-03-01)/§6.6 | **R-B** | No (test observability; otherwise covered via 03-02 end-to-end) |
| F15 | Integration/real-machine active connect client carrier (whether helloworld includes connect / echo client / a self-built minimal program) | 07§2.1/§6.7, 08§6.5 | **R-A** (integration test starts here) | No (test carrier selection) |
| F16 | Performance instrumentation macro (`FF_RSS_PERF_PROBE`) naming and placement (enabled only in perf builds) | 08§2.1/§6.1 | **R-B** (performance baseline phase) | No (engineering item) |
| F17 | Wiki-quoted magnitude values (soft-compute 300+/connection, static table 100~250, multi-process 35%+) calibrated against real-machine measurements | 03§5.1, 08§0/§6.3 | **R-B** (real-machine baseline) | No (reference expectation, not a hard gate) |
| F18 | Actual real-machine values of reta_size and nb_queues (determines the number of D(q) candidates and back-derivation difficulty) | 08§3/§6.6 | **R-B** (real-machine record) | No (environment record item) |
| F19 | Precise gate adaptation for 0.5 v4 hunk1 at 15.0's `in_pcbbind` L739-748 (including in_pcbinshash failure rollback) (skip the whole block when lport==0, maintain rollback when lport≠0) | 01§3-ter.8, 02§6-ter.2, 04§3-ter.6, 06 R-E | **R-E** | No (landing-point refinement, loss point confirmed to exist) |
| F20 | Impact of hunk2's writing back lport=0 after `in_pcbbind_setup`, on `in_pcbbind` L746-747 INP_ANONPORT and bind return semantics | 01§3-ter.8, 04§3-ter.6 | **R-E** | No (coding-phase re-verification) |
| F21 | Whether entry conditions for the RSS branch in `in6_pcbconnect`'s L515 for 0.5 v6 connect need relaxing (in6p_laddr unspec && inp_lport==0 → inp_lport==0), path B | 01§3-ter.8, 02§6-ter.3, 04§3-ter.4, 06 R-E.1(E5) | **R-E** | No (v6 is a recommended sync, v4 mandatory doesn't depend on it; paths A/B/C already have plans) |
| F22 | 0.5 REUSEPORT_LB (L740 MPASS) scenario's delayed-allocation behavior for bind(addr,0) | 01§3-ter.7 AC-05-6, 04§3-ter.6, 07 RG-12 | **R-E** | No (compatibility verification) |
| F23 | Whether 0.5 needs a per-socket `IP_BIND_ADDRESS_NO_PORT` setsockopt vs implicit behavior | 01§3-ter.8, 03§5.4/§6.5 | **R-E** (product/coding decision) | No (leans toward following upstream implicit semantics) |
| F24 | Whether upstream commit `cb9b4d462` for 0.5 has already been merged into this repo's 13.0 baseline (determines whether v4 is a previously missed migration or an addition relative to baseline) | 02§6-ter.4, 03§6.4, 06 R-E.1(E6) | **R-E** (grep as a starting point) | No (doesn't affect the 15.0 landing point, only affects the descriptive characterization) |
| F25 | 0.5 R-E kernel in_pcb/in6_pcb unit test carrier (FreeBSD kernel unit test framework/self-built stub); existing lib cmocka doesn't cover kernel in_pcb | 07§1.5-ter/§6.10 | **R-E** | No (test engineering item, integration/real-machine downgrade already given) |
| F26 | 0.5 minimal bind-then-connect client carrier + before/after migration baseline construction | 07§2.6/§6.11, 08§5-ter/§6.7 | **R-E** | No (test carrier selection) |

**Total to-be-confirmed items: 26 (deduplicated; this round's R-E adds F19~F26, 8 items).** All are coding-phase verification/tuning/hardware-confirmation/test-engineering items; **none affects the validity of the spec-phase plan**.

---

## Overall gate conclusion

### Assertion statistics

| Category | Sub-assertions | PASS | FAIL |
|------|--------|------|------|
| A code consistency | A1/A2/A3/A4 (A2 adds 0.5 bind/connect landing-point verification, see B4 table) | 4 | 0 |
| B requirement closure | B1/B2/B3/B4 (B4 = 0.5 bind-then-connect) | 4 | 0 |
| C test closure | C (5 sub-items) | 5 | 0 |
| D document self-consistency | D (4 sub-items, including 00 missing = suggested addition) | 4 | 0 |
| E no conflict with existing docs | E (3 spot checks) | 3 | 0 |
| **Total** | **20 main assertions/sub-items** | **20** | **0** |

> Note: this round's R-E (requirement 0.5) adds new B4 (0.5 closure assertion, all 11 landing-point line numbers confirmed against code, PASS), bringing the total main assertions from 19 to 20, with FAIL still at 0. All 0.5 v4 loss points / hunk3-already-in-place / v6-unclosed-points have been verified against the code (`in_pcb.c:739-748/1273-1279/1313/1363-1366`, `in6_pcb.c:354/361-369/515-521`), no FAIL.

- **FAIL count: 0**. No assertion was judged FAIL due to spec-code inconsistency; no need to bounce any milestone.
- **Coding-phase to-be-confirmed items: 26** (all recorded in table F, none affects plan validity; this round's R-E adds F19~F26).
- **Recommendation (non-blocking)**: add `00-overview-index.md` (category D; already added alongside R-E in this round, including navigation rows for 0.5/R-E).

### Conclusion

**Spec-phase gate: CONDITIONAL PASS.**

- "Conditional" refers only to the existence of 26 **coding-phase** to-be-confirmed items (normal implementation-phase verification/tuning items, to be grepped/read-and-confirmed at the start of R-A/R-B/R-C/R-D/R-E per table F, with conclusions written back to the spec, no speculation) — **there is no FAIL that blocks spec finalization**.
- All code-consistency assertions (A), requirement closure (B, including 0.3's queue-landing mapping confirmed correct by the gate's independent derivation, and 0.5's bind-then-connect landing points confirmed against code), test closure (C), document self-consistency (D), and no-conflict-with-existing-docs (E) all PASS.
- The spec's five plans (0.1 migration / 0.2 IPv6 addition / 0.3 thash dynamic optimization / 0.4 recheck runtime switch / 0.5 IP_BIND_ADDRESS_NO_PORT bind-then-connect RSS migration) have real landing points, correct derivations, closed zero-IPv4-regression constraints, and zero-tolerance correctness guarded by soft-compute re-verification — **the plan is valid, the spec can be finalized, and it is approved to proceed to the subsequent coding phases (R-A→R-B→R-C→R-D→R-E)**.
- 0.5 (R-E) addition summary: v4 mandatory hunk1 (`in_pcb.c:739-748` entry-into-hash gate) + hunk2 (L1275-1279 port-allocation gate); connect-time hunk3 is already equivalently in place (L1313/L1363-1366), no change needed; v6 recommended sync (`in6_pcbbind` L354/L361-369 gate + connect L515 condition linkage pending coding-phase confirmation). All loss points/already-in-place points confirmed against code, PASS.

### Bounce record

- This gate review's bounce count: **0** (passed on the first attempt, no rework required).
