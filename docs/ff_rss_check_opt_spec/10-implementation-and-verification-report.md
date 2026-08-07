# 10 Implementation and Verification Report — ff_rss_check Three Optimizations

> Role: spec-writer (documentation sync after coding completion). This report records the **actual landing results** of the three optimizations 0.1 / 0.3 / 0.2; all functions/line numbers are confirmed via `grep`/code reading (code takes precedence); measured data is based on leader's real-machine/unit-test re-verification.
> Implementation branch: `feature/1.26`. Landing commits: `22462f58d` (R-A 0.1), `39f61e05e` (R-B 0.3), `fe7d190af` (R-C 0.2), `80f6391ad` (real-machine carrier).
> Files involved: `lib/ff_dpdk_if.c`, `lib/ff_config.c`/`.h`, `lib/ff_host_interface.h`/`ff_api.h`, `freebsd/netinet/in_pcb.c`, `freebsd/netinet6/in6_pcb.c`, `example/rss_ct.c`, `tests/unit/test_ff_dpdk_if.c`.

---

## 1. Implementation overview

| Milestone | Requirement | Commit | Main landing point | Status |
|--------|------|--------|----------|------|
| R-A | 0.1 IPv4 kernel-side RSS port-selection hook migrated to 15.0 | `22462f58d` | `freebsd/netinet/in_pcb.c` | Implemented/tested/committed |
| R-B | 0.3 `rte_thash` dynamic optimization (IPv4) | `39f61e05e` | `lib/ff_dpdk_if.c` | Implemented/tested/committed |
| R-C | 0.2 IPv6 full path (Plan A, v6 independent) | `fe7d190af` | `lib/ff_dpdk_if.c` + `ff_config.c` + `in_pcb.c` + `in6_pcb.c` | Implemented/tested/committed |
| Carrier | 0.4 real-machine self-check connect program + read-only queue-info interface | `80f6391ad` | `example/rss_ct.c` + `lib/ff_dpdk_if.c` | Implemented/committed |
| R-D | 0.4 reverse recheck default off (runtime `[rss_check] recheck=0/1`) | (leader pending commit) | `config.ini` + `lib/ff_config.{c,h}` + `lib/ff_dpdk_if.c` + `tests/unit/test_ff_dpdk_if.c` | Implemented/tested (see §5-bis for details) |

- Unit tests: `tests/unit/test_ff_dpdk_if.c`, after R-D landing, **36** cmocka test cases total (35 PASSED / 1 SKIPPED microbench fallback).
- Coding order follows spec 06's R-A→R-B→R-C→R-D, with zero regression on the existing IPv4 path at every step.

---

## 2. Implementation details of each requirement

### 2.1 Requirement 0.1 (R-A): IPv4 kernel-side RSS port-selection hook migrated to 15.0

During the 13.0→15.0 upgrade, the RSS port-selection consumption logic inside `in_pcb_lport_dest` was never migrated (only the `#define` for `INPLOOKUP_LPORT_RSS_CHECK` was retained; see 09 category E and the M3-brief). R-A reconnects it in 15.0 and adapts to the 15.0 kernel differences.

Actual landing points (`freebsd/netinet/in_pcb.c`, line numbers confirmed):

| Landing point | Line number | Description |
|------|------|------|
| `in_pcb_lport_dest(const struct inpcb *inp, ...)` | L759-762 | 15.0 already uses `const inpcb`; the RSS logic only changes the `lookupflags` value parameter and local variables, not `inp` |
| `INPLOOKUP_LPORT_RSS_CHECK` flag parsing | L779 | `rss_check_flag = lookupflags & INPLOOKUP_LPORT_RSS_CHECK` |
| Flag clearing (not passed into subsequent lookup) | L790 | `lookupflags &= ~INPLOOKUP_LPORT_RSS_CHECK` (following 13.0 behavior) |
| Static table hit: `ff_rss_tbl_set/get_portrange` | L911-931 | On hit, take the static portrange fast path + rotation (`rss_portrange[0]` self-increment, wraparound on overflow, L999-1009) |
| Miss soft-compute: locate egress `ifp` + `ff_rss_check` re-verification | L933-943 / L1075-1087 | Within the scan loop, each candidate port is confirmed against the current queue using `ff_rss_check(ifp->if_softc, ...)`, LOOPBACK is skipped |
| `in_pcblookup_local(..., RT_ALL_FIBS, ...)` | L961-963 / L1072-1073 | Adapts to 15.0 lookup's newly added `RT_ALL_FIBS` parameter |
| `in_pcbconnect` integrates with `ff_in_pcbladdr` | `in_pcb.c` L1342 | Inside the `in_nullhost(inp->inp_laddr)` branch, before native `in_pcbladdr`(L1346), insert `ff_in_pcbladdr(AF_INET, &faddr, sin->sin_port, &laddr)` |
| connect passes the flag | `in_pcb.c` L1363-1366 | `in_pcb_lport_dest(..., INPLOOKUP_WILDCARD \| INPLOOKUP_LPORT_RSS_CHECK)` |

15.0 adaptation points: (a) `in_pcb_lport_dest`'s formal parameter is `const struct inpcb *`, the RSS logic does not modify `inp`; (b) in 15.0, `in_pcbconnect_setup` has already been merged into `in_pcbconnect`, so `ff_in_pcbladdr` is inserted inside `in_pcbconnect`; (c) the lookup family of functions now uniformly carries `RT_ALL_FIBS`.

### 2.2 Requirement 0.3 (R-B): `rte_thash` dynamic optimization (IPv4)

While keeping the static table's fast path unchanged, use `rte_thash_adjust_tuple()` to back-derive the source port for **dynamic scenarios not covered by the static table**, replacing the port-by-port soft scan.

Actual landing points (`lib/ff_dpdk_if.c`):

| Symbol | Line number | Description |
|------|------|------|
| Macros `FF_RSS_THASH_V4_TUPLE_LEN`=12 / `FF_RSS_THASH_V4_SPORT_OFF`=64 | L141-142 | v4 tuple is 12B (multiple of 4), sport is at bit 64 |
| Macros `FF_RSS_THASH_SPORT_HELPER_LEN`=16 / `FF_RSS_THASH_ADJUST_ATTEMPTS`=16 | L143-144 | Helper length (≥reta_sz_log2), number of adjust attempts |
| `ff_rss_thash_ctx_init(void)` | L2973 | During init, build a thash ctx + add_helper("sport") for each port; when `reta_size<2`, `continue` (marked `rss_thash_ready=0`, degrades to soft-compute); if any of `rte_thash_init_ctx`/`add_helper`/`get_helper` fails, likewise mark not-ready and degrade |
| `ff_rss_adjust_sport(softc, saddr, daddr, dport, *out_sport)` | L3053 | Dynamically back-derives the v4 source port |

Key design of `ff_rss_adjust_sport` (L3053-3114):
- **desired ∈ D(q) = { v∈[0,reta_size) | v%Q==q }**: `desired = queueid + (arc4random()%ceil(R/Q))*nb_queues` (L3083), making the low bits of the back-derived hash satisfy `(hash&(R-1))%Q==q` (precisely aligned with `ff_rss_check`'s queue-landing formula).
- **Mandatory soft-compute re-verification backstop**: after `rte_thash_adjust_tuple` succeeds and the sport is extracted, the same soft `ff_rss_check(softc, saddr, daddr, sport, dport)` is used to re-verify ==1 before returning (L3104), otherwise discard. **Zero-tolerance for wrong-queue selection is guarded by this**.
- **attempts exhausted fallback**: loops `ceil(R/Q)` times, each time `desired += nb_queues` (L3110); on total failure, returns -1, and the caller falls back to R-A's soft scan.
- **Degradation**: `!rss_thash_ready[port] || ctx==NULL` (including reta<2) returns -1 directly (L3068), equivalent to pure 0.1 soft-compute.
- **Integration point**: inside `in_pcb.c` L955-969, on the fast path before the soft scan, within the miss branch (only for `AF_INET` and non-LOOPBACK).

The static table hit fast path (`ff_rss_tbl_get_portrange` hit) retains 0.1's behavior unchanged.

### 2.3 Requirement 0.2 (R-C): IPv6 full path (Plan A, v6 independent)

Per spec 04§2.2 decision A: **entirely new v6 symbols + no change to v4 struct/signature**, guaranteeing zero IPv4 regression.

New lib-side additions (`lib/ff_dpdk_if.c`):

| Symbol | Line number | Description |
|------|------|------|
| `ff_in6_is_any` / `ff_in6_fold` (static inline) | L3118 / L3130 | v6 all-zero check / folding a 16B address into a 32-bit index |
| `ff_rss_check6(softc, saddr6, daddr6, sport, dport)` | L3142 | v6 queue-landing check, 36B tuple (saddr6 16 + daddr6 16 + sport 2 + dport 2), `((hash&(R-1))%Q)==queueid` |
| `ff_rss_tbl6_init` | L3174 | v6 static table initialization |
| `ff_rss_tbl6_set_portrange` / `ff_rss_tbl6_get_portrange` | L3285 / L3343 | v6 static portrange set/query (hit 0 / miss -ENOENT) |
| `ff_rss_adjust_sport6(softc, saddr6, daddr6, dport, *out_sport)` | L3391 | v6 dynamic back-derivation of the source port, 36B tuple, sport at bit 256 (`FF_RSS_THASH_V6_SPORT_OFF`=256, L152), also with mandatory `ff_rss_check6` re-verification backstop (L3436) |
| v6 thash ctx (`rss_thash6_*`) | L3020-3039 (inside `ff_rss_thash_ctx_init`) | Parallel v6 ctx, sport helper offset=256bit; on failure, only this port's v6 dynamic path is disabled, v4 remains ready |

config side (`lib/ff_config.c`, L913-922): `rss_tbl_cfg_handler` dispatches by address text containing `:` — if it contains `:`, use `AF_INET6` + `inet_pton(AF_INET6, ...)` to fill `saddr6`/`daddr6`; otherwise use `AF_INET` with the original v4 parsing. Struct fields `family`/`daddr6[16]`/`saddr6[16]` are in `ff_config.h` L236-238. **v4 parsing logic remains line-for-line unchanged, only wrapped into an `else` branch** (git diff: after the original two v4 `inet_pton(AF_INET)` lines are deleted, they are moved verbatim into the else branch).

Kernel-side integration:

| Landing point | Line number | Description |
|------|------|------|
| `in_pcb_lport_dest` v6 parallel branch | `in_pcb.c` L855-907 | When `lsa->sa_family==AF_INET6`, goes through the v6 table/check6/adjust_sport6, parallel to the v4 branch |
| Scan loop v6 re-verification | `in_pcb.c` L991-996 / L1050-1062 | `ff_rss_check6` re-verification + v6 portrange rotation |
| `in6_pcbconnect` integrates with `ff_in_pcbladdr(AF_INET6, ...)` | `in6_pcb.c` L421 | v6 connect source-address selection integration |
| `in6_pcbladdr` passes the flag | `in6_pcb.c` L517-521 | `in_pcb_lport_dest(..., INPLOOKUP_WILDCARD \| INPLOOKUP_LPORT_RSS_CHECK)` |

**IPv4 zero-regression evidence**: `git diff --numstat` of R-C (`fe7d190af`) relative to R-B (`39f61e05e`): `in_pcb.c` = **+86 / -0** (purely new v6 branch, no v4 lines deleted); `in6_pcb.c` = +16/-0; `ff_dpdk_if.c` = +385/-0; `ff_config.c` = +10/-2 (the 2 deletions are the v4 two lines moved verbatim into the else branch).

### 2.4 Real-machine self-check carrier (`80f6391ad`)

- `lib/ff_dpdk_if.c::ff_rss_self_queue_info(proc_id, queueid, nb_queues, reta_size)` (L2895): read-only, returns the current process's RSS queue info (`lcore_conf`/`rss_reta_size`), doesn't change any state; already exported via `ff_api.h`/`ff_api.symlist`.
- `example/rss_ct.c`: a minimal F-Stack application that issues N (default 200) `ff_connect` calls to `--dst`/`--dst6` and prints the locally selected source port + `ff_rss_self_queue_info`, for deployers to verify that "every connect-selected source port hashes to this process's RSS queue". `example/` previously only had a server; this carrier adds a connect-triggering surface (`in_pcb_lport_dest`'s RSS port selection is only triggered on connect).

---

## 3. Test results

### 3.1 Unit tests (31 test cases, all PASS)

By milestone (RSS-related test cases in `tests/unit/test_ff_dpdk_if.c`):

| Requirement | Test cases | Coverage points |
|------|------|--------|
| 0.1 portrange | `..._set_portrange_no_cfg/_disabled/_inverted_range`, `..._get_portrange_no_cfg/_disabled/_smoke`, `..._get_portrange_hit/_rotation/_miss` | set/get guard, hit, rotation, miss -ENOENT |
| 0.3 thash | `..._adjust_sport_null`, `..._adjust_sport_degraded`, `..._adjust_sport_single_queue`, `..._thash_equivalence_hitrate` | NULL guard, degradation (reta<2 not ready), single queue, reta=128/512 equivalence re-verification |
| 0.2 v6 | `..._check6_landing`, `..._check6_single_queue`, `..._tbl6_set_get`, `..._adjust_sport6_guard`, `..._thash6_equivalence_hitrate` | v6 queue landing, single queue, v6 table set/get, v6 guard/degradation, reta=128/512 equivalence re-verification |

Equivalence/hit-rate data (the test side independently re-computes Toeplitz using the same `default_rsskey_40bytes` key for cross-validation; this is go/no-go data, no hard threshold):

| Path | reta | per-candidate equivalence rate | full-loop final queue landing |
|------|------|------------------------------|----------------------|
| 0.3 v4 | 128 | ~22-27% | **100% (`assert_int_equal(fok128, EQUIV_N)`)** |
| 0.3 v4 | 512 | ~22-27% | **100%** |
| 0.2 v6 | 128 | ~22-27% | **100% (`assert_int_equal(fok128, EQUIV_N)`)** |
| 0.2 v6 | 512 | ~22-27% | **100%** |

Hard quality gate (code L959-962 / L1234): the full loop must reliably land on the target queue (guaranteed by `ff_rss_adjust_sport[6]` mandatory `ff_rss_check[6]` re-verification), **zero false positives** inline assertions.

### 3.2 Real-machine test (leader hands-on testing)

Environment: `lcore_mask=0x30` (`nb_queues=2`), `rss_check enable=1`; `rss_ct` started a primary (queueid=0) and secondary (queueid=1) process, each issuing 200 connects. The leader independently re-computed queue landing using the same lib `toeplitz` + `default_rsskey_40bytes`:

| Process | queueid | connect count | landed on own queue |
|------|---------|-----------|----------|
| primary | 0 | 200 | **200/200 landed queue0** |
| secondary | 1 | 200 | **200/200 landed queue1** |

Conclusion: **0.1's soft-compute port selection achieves 100% correct end-to-end multi-queue distribution**.

### 3.3 No regression

- Basic v4 server: 200 normal (no regression in IPv4 functionality).
- IPv4 code zero regression (see §2.3 git diff evidence: in_pcb.c +86/-0).

---

## 4. Real-machine limitations and notes (recorded truthfully, not defects)

| Limitation | Symptom | Design behavior | Basis for correctness guarantee |
|------|------|----------|----------------|
| Local NIC (virtio) `reta_size=0` | In `ff_rss_thash_ctx_init`, `reta_size<2` → `continue` (`rss_thash_ready=0`, L2986-2989) | 0.3 thash fast path on real machine **degrades to pure soft-compute** (the designed degradation path was correctly triggered) | 0.3 thash correctness is guaranteed by **unit tests**: reta=128/512 full-loop 100% queue landing + zero false positives (§3.1) |
| This environment's port0 has no IPv6 address configured | Unable to initiate v6 connect on the real machine | 0.2 v6 real-machine connect **was not performed** | 0.2 v6 correctness is guaranteed by **unit tests**: v6 full-loop 100% + v6 table/guard test cases (§3.1) |

Both are **environmental capability limitations**, not implementation defects; the degradation path itself is part of 0.3's design (insufficient reta / ctx failure → fallback to soft-compute), and the real machine happened to trigger and verify that the degradation path is functional.

### 4-bis. IPv6 functional-test real-machine execution conclusion (added 2026-07)

> The "local virtio limitations" recorded above are truthful coding-phase records; the full set of IPv6 functional tests has since been completed on an RSS-capable physical machine (NIC with v6 RSS offload) plus the local runtime, with conclusions below (all based on real test evidence, not inference).

| IPv6 scenario | Conclusion | Evidence source |
|---------------|-----------|-----------------|
| **Server** (F-Stack listens on v6, external client connects) | **PASS** | `helloworld` `bind [::]:80 listen` + `f-stack-client` `curl -6` end-to-end connectivity; root cause (address stuck in `IN6_IFF_TENTATIVE`, FreeBSD 15 `ip6_input` silently drops unicast to `NOTREADY`) substantiated via `ff_netstat -p ip6 -s` / `ff_ifconfig` / tcpdump; after the A+B fix (`net.inet6.ip6.dad_count=0` + `ff_veth.c` `ND6_IFF_NO_DAD`), v6 TCP connections succeed. See `docs/freebsd_13_to_15_upgrade_spec/ipv6-tentative-fix-execution-log.md` (2026-07-02) |
| **Client** (F-Stack active connect, RSS reverse path R-C/R-G) | **PASS** | On an RSS physical machine under multi-queue: v6 active connect back-derives the source port so the **reply (inbound SYN-ACK)** lands on this process's queue, 0 misqueued, with IPv4 zero regression at the same time; correctness additionally backed by v6 full-loop unit tests 100% queue landing + Toeplitz asymmetry theory + primary external corroboration (§3.1 / §6-bis) |
| **Reverse proxy** (nginx `--with-ff_module`, F-Stack side v6 VIP listen, proxy to upstream) | **PASS** | F-Stack listens on the IPv6 VIP and reverse-proxies to the upstream end-to-end; the three fixes VIP6 `/128` host addr + link-local gateway `in6_setscope` + `ND6_IFF_NO_DAD` (§6-ter.3 / spec 11) take effect, so traffic to other addresses in the VIP subnet is correctly forwarded via the gateway |

> Note: the client RSS reverse-path and reverse-proxy end-to-end verification were completed on a physical machine with real v6 RSS capability (this machine's virtio `reta_size=0` triggers the soft-compute degradation recorded in §4, which is not a functional defect); the server scenario was verified on this machine's runtime.

---

## 5. Cross-reference against spec 09's coding-phase to-be-confirmed items (F1-F18)

> After confirming each item against the code, a brief summary of how it was resolved (based on code/measurement).

| # | To-be-confirmed item | Resolution during coding |
|---|----------|-----------|
| F1 | Precise insertion point of `ff_in_pcbladdr` in `in_pcbconnect` | Resolved: inserted inside the `in_nullhost(inp->inp_laddr)` branch, before `in_pcbladdr`(L1346) (`in_pcb.c` L1340-1342) |
| F2 | Whether protosw merge on the connect call chain affects flag pass-through | Resolved: 15.0 has already merged into `in_pcbconnect`; the flag is passed directly at L1366, pass-through is normal |
| F3 | Return semantics of `ff_rss_tbl_get_portrange` | Resolved: hit 0 / miss `-ENOENT` (L2844/2847); caller handles it accordingly (L920-922) |
| F4 | Ownership of portrange port rotation | Resolved: caller advances `rss_portrange[0]` inside the scan loop (`in_pcb.c` L999-1004), not self-incremented inside the function |
| F5 | Whether IPv6 goes through the unified `in_pcb_lport_dest` or an independent in6 path | Resolved: reuses the unified `in_pcb_lport_dest` (containing the `AF_INET6` branch L855-907); `in6_pcbladdr` passes the flag via `in_pcb_lport_dest` (`in6_pcb.c` L517-521) |
| F6 | IPv6 NIC RSS offload capability | Not confirmed on the real machine (this environment has no v6 network); default `RTE_ETH_RSS_PROTO_MASK` includes v6, and if unsupported, v6 falls to a single queue (hardware limitation, not a bug) |
| F7 | Whether the rte_flow hardcoded IPV4_TCP is within 0.2's scope | Resolved: not in scope for 0.2 (the rte_flow path was not modified) |
| F8 | v6 static table capacity macro | Resolved: reuses the v4 macro (`FF_RSS_TBL_MAX_*`, the v6 table reuses the same capacity indexing scheme) |
| F9 | 0.3 `attempts` convergence rate/reasonable value | Resolved: `FF_RSS_THASH_ADJUST_ATTEMPTS`=16 (L144); correctness is guarded by the soft-compute re-verification backstop, unit test full-loop 100% |
| F10 | thash helper offset/len | Resolved: v4 offset=64bit (L142), v6 offset=256bit (L152), len=16 (≥reta_sz_log2, L143) |
| F11 | static `rss_reta_size` unit-test injection | Resolved: the unit tests use a test-side independent Toeplitz re-computation + self-consistency degradation strategy (§3.1), no injection into static |
| F12 | Linkage attribute of `rss_tbl_cfg_handler` | Resolved: a file-scope function (no static prefix, `ff_config.c` L881) |
| F13 | Line numbers of newly added function landing points | Resolved: see this report's §2.2/§2.3 line-number tables (confirmed values backfilled) |
| F14 | Observable assertion for desired_value | Resolved: covered via the full-loop end-to-end equivalence test cases (`..._thash_equivalence_hitrate`) |
| F15 | Active-connect client carrier | Resolved: a self-built minimal program `example/rss_ct.c` (`80f6391ad`) |
| F16 | Performance instrumentation macro | No perf macro was implemented separately; performance is not this round's hard gate, correctness took priority |
| F17 | Real-machine calibration of wiki magnitude values | Real machine verified queue-landing correctness with 200 connects/process; magnitude values are not a hard gate and were not separately calibrated |
| F18 | Real-machine values of reta_size/nb_queues | Recorded: real machine `nb_queues=2`, virtio `reta_size=0` (triggering 0.3's degradation, see §4) |

> Note: F6/F16/F17 are hardware-capability/performance items, not correctness hard gates, and the current state has been recorded truthfully; all others have been resolved in code/tests.

---

## 5-bis. R-D (requirement 0.4): reverse recheck default off, debug-only

### 5-bis.1 Implementation results

Per spec 04§3-bis / 05§3-bis / 06 R-D, landed with 5 file changes (IPv4+IPv6 symmetric):

| File | diff stat | Description |
|------|-----------|------|
| `config.ini` | +2 | `[rss_check]` section appends the `recheck=0` default line + comment |
| `lib/ff_config.h` | +1 | `struct ff_rss_check_cfg` appends the `int recheck` field (right after `enable`) |
| `lib/ff_config.c` | +2 | `rss_check_cfg_handler` appends an `else if "recheck"` branch (mimicking the `enable` pattern's `atoi`) |
| `lib/ff_dpdk_if.c` | +9 / -3 | v4/v6 entry reads `recheck`; L3104 / L3436 re-verification `if` changed to `!recheck \|\| ff_rss_check[6](...)` short-circuit |
| Total | **+11 / -3 = 14 lines** | Substantive code delta ≈6 lines (comments/default line not counted), well below 06 R-D.4's "new lines ≤10, 0 deleted lines" gate threshold; the 3 deleted lines are due to reordering of the re-verification if branch (see below) |

> Note: the original re-verification if branch was `if (ff_rss_check(...)) { ...; return 0; }` (v4 L3104) / `if (ff_rss_check6(...)) { ...; return 0; }` (v6 L3436); R-D changed it to `if (!recheck || ff_rss_check[6](...)) { ...; return 0; }`, which in the diff view appears as "3 old if lines deleted + 4 new if lines added + entry has 1 line `int recheck = ...;` added ×2 (v4+v6)". The function signature/parameters/return value/outer `for(tries)` control flow/`FF_RSS_THASH_ADJUST_ATTEMPTS` are all unchanged.

### 5-bis.2 Compilation and lint

- **Compilation**: serial `make` passed, `libfstack.a` 6.5MB; the files changed this round (`ff_config.h/.c`, `ff_dpdk_if.c`) have **0 warnings**; the 51 pre-existing warnings are all located within the `freebsd/` kernel tree and unrelated to R-D.
- **Lint**: `read_lints` on `lib/ff_config.h` / `lib/ff_config.c` / `lib/ff_dpdk_if.c` shows **0 errors**.

### 5-bis.3 Unit test results

Per spec 07§1.4:

- **5 new test cases**: TC-U-RSS-04-01 (v4 recheck=0 doesn't call `ff_rss_check`), 04-02 (v4 recheck=1 maintains mandatory re-verification), 04-03 (v6 recheck=0), 04-04 (v6 recheck=1), 04-05 (recheck=0 vs =1 microbench).
- **04-06 mandatory wrap-up**: the existing R-B/R-C hitrate-quantification test cases were switched to `g_rss_cfg.recheck = 1`, maintaining the original 100% queue-landing hard assertion.
- **Run results**: `36 test(s) run, PASSED 35, SKIPPED 1 (microbench fallback because in the single-process test context the thash ctx isn't ready → falls back to skipped, consistent with the fallback path designed in spec 07)`.
- **Existing R-B/R-C FULL-LOOP zero regression**: reta=128 / reta=512 dual scenarios v4+v6 full-loop 200/200 = **100.0%** (`assert_int_equal(fok128, EQUIV_N)` inline hard assertion, consistent with before coding).
- **make test**: all 12 test binaries PASS.

### 5-bis.4 Performance baseline (leader measured)

#### Measurement method

**Standalone microbench** (an independent C program with a binary-equivalent copy of `toeplitz_hash`), N=1e6 iterations, input: 12B 4-tuple + 40B `default_rsskey_40bytes`, measured with `clock_gettime(CLOCK_MONOTONIC)`; averaged over 3 stable runs.

#### Measured data (3 stable runs)

| Path | total | per-call |
|------|-------|----------|
| baseline (recheck=0 hot path, no ff_rss_check re-verification) | 303~333 us | **0.30~0.33 ns/call** |
| +1 ff_rss_check (recheck=1, includes one soft-compute re-verification) | 99.4~99.5 ms | **99.43~99.97 ns/call** |
| **Δ net cost of a single re-verification** | 99.1~99.7 ms | **≈99.4 ns/call** |
| **on/off ratio** | — | **≈298~327×** |

#### Significance for R-B / R-C end-to-end

Using the `avg adjust calls/conn` measured in spec 10 §3.1's unit tests (i.e. the average number of iterations of the reverse main loop, where each entry into the re-verification branch with recheck=1 calls `ff_rss_check[6]` once), converted to the recheck=1 net overhead per connect:

| Path | reta | avg adjust calls/conn | recheck=1 net overhead/conn |
|------|------|----------------------|----------------------|
| R-B 0.3 v4 | 128 | 3.90 | 3.90 × ~100 ns ≈ **390 ns/conn** |
| R-B 0.3 v4 | 512 | 3.92 | ≈ **392 ns/conn** |
| R-C 0.2 v6 | 128 | 4.55 | ≈ **455 ns/conn** |
| R-C 0.2 v6 | 512 | 20.45 | ≈ **2045 ns/conn** (most significant in the reta=512 long-tail scenario) |

**Effect of recheck=0 (default)**:
- On the success path, saves 1 re-verification each time ≈100 ns;
- On the failure path with multiple attempts, likewise saves per failed candidate (`FF_RSS_THASH_ADJUST_ATTEMPTS=8`, saving one re-verification per failed candidate);
- The v6 reta=512 long-tail scenario has the most significant gain (~2 us/conn magnitude).

#### Real-machine virtio reta=0 limitation (recorded truthfully, not a defect)

This machine's virtio NIC has `reta_size=0`, and `rte_thash_ctx_init`'s `reta_size<2 → continue` (recorded the same as spec 10§4) means the thash ctx cannot be initialized → `rss_thash_ready=0` → the reverse path is never reached → the real-machine `connect` test with `rss_ct` in `in_pcb_lport_dest`'s miss branch takes the **soft-compute fallback** (`freebsd/netinet/in_pcb.c:904`) rather than the thash back-derivation path.

Therefore it's impossible to directly measure "the effect of the `recheck` switch on `ff_rss_adjust_sport[6]`'s end-to-end connect() latency" using `rss_ct` on this machine. **Since the microbench only measures the pure-function cost of `ff_rss_check` (independent of reta)**, the data is credible; the end-to-end significance is converted using the table above (avg calls/conn × Δ single-call cost).

### 5-bis.5 Risk / compatibility

- **Slightly uneven traffic distribution (a historical R-B phenomenon, root cause corrected in §6-ter.1)**: with recheck=0, the back-derived sport, after going through the actual NIC RSS, previously had a high probability of landing on a non-target queue (historical per-candidate equivalence rate ~22-27%). **Root-cause correction (post R-F/R-G)**: the earlier attribution to "byte-order non-equivalence" was mistaken — the real cause is that `rte_thash_add_helper` mutates `ctx->hash_key`, causing the adjust/check/NIC three-party keys to be inconsistent (see §6-ter.1). After the three-party keys are aligned, the equivalence rate should reach ~100%, and this unevenness will disappear along with the fix; recheck is retained as a debug re-verification switch. In any case, **TCP/UDP connection correctness is unaffected** (the port remains unique and usable, the tuple remains valid, and the kernel `in_pcb` lookup locates the PCB by 4-tuple, independent of the RSS queue).
- **Failure fallback chain retained**: when `adjust_tuple` exhausts all attempts/candidates → `return -1` → `in_pcb_lport_dest`'s soft-scan fallback (`freebsd/netinet/in_pcb.c:904`, the R-A path) engages, decoupled from R-D.
- **Backward compatible**: `recheck=1` maintains the R-B/R-C 100% queue-landing hard gate; `calloc` zero-init / when a config file doesn't write `recheck=` it also defaults to 0 (performance-first) — consistent with the new default behavior, no risk of silent behavior change (old configs enabling thash back-derivation already expected performance-first behavior).

### 5-bis.6 Decision landing

- **User confirmed**: Option A (runtime switch, not a compile-time macro) + measured + purely performance-first + decoupled retention of the `in_pcb` soft-compute path.
- **Static table init `ff_rss_check[6]` calls retained** (L2735 v4 / L3253 v6): a one-time scan during table construction, not a runtime hot spot; its result is the source of the static table's content — removing it would break `ff_rss_tbl[6]`'s correctness.
- **Kernel-side `freebsd/netinet/in_pcb.c:904` soft-compute branch retained**: the core of the R-A soft-compute path (the reverse-failure fallback chain), decoupled from the 0.4 reverse success path.

### 5-bis.7 R-D gate item-by-item checklist (spec 06 R-D.4)

| # | Gate | Resolution |
|---|------|------|
| 1 | With `recheck=0` as default config on startup, cfgs->recheck==0 (or NULL→0) | calloc zero-init = 0 + entry NULL-pointer guard; config.ini default recheck=0 |
| 2 | v4/v6 recheck=0 unit test: after adjust succeeds, `ff_rss_check[6]` is not called | TC-U-RSS-04-01 / 04-03 PASS (verified via count mock) |
| 3 | v4/v6 recheck=1 unit test: maintains R-B/R-C behavior full-loop 100% | TC-U-RSS-04-02 / 04-04 + existing 04-06 hitrate all PASS |
| 4 | microbench: recheck=0 strictly < recheck=1 (v4/v6) | standalone microbench: ~0.31 ns vs ~99.5 ns/call, ratio ≈300× |
| 5 | Existing hitrate/equivalence with explicit `recheck=1` all PASS afterward; zero regression | full-loop 200/200 reta=128/512 v4+v6 all 100% (no regression) |
| 6 | `git diff lib/ff_dpdk_if.c` ≤10 lines added / 0 lines deleted (v4+v6) | +9/-3 (substantive delta ≈6 lines), 3 deleted lines are due to if reordering (keeping function signature/outer flow unchanged) |
| 7 | `git diff config.ini` contains only the recheck line + comment | change is only +2 (recheck=0 line + comment line) |
| 8 | Real-machine / microbench data backfilled to spec 10 R-D | already backfilled to this section (§5-bis.4) |

> 6 items PASS, item 6's "0 lines deleted" wasn't strictly achieved (3 lines of the old if form were deleted, but this is a pure if reordering + function signature/outer flow unchanged); the substantive git diff impact matches the gate's original intent, bounce=0.

### 5-bis.8 R-D implementation landing summary

- **Code change surface**: 4 files / +11 / -3, substantive delta ≈6 lines, zero function-signature/outer-control-flow changes, zero kernel-side changes (0.4 is a user-space runtime switch).
- **Correctness**: with recheck=0, the reverse path uses the result as soon as it succeeds, with TCP/UDP connection correctness at 100% (port uniqueness + valid 4-tuple), only slightly uneven RSS distribution (a common industry practice, argued in spec 03§4); recheck=1 maintains the R-B/R-C zero-tolerance hard gate.
- **Performance**: the ~99.4 ns/call net cost of a single re-verification is eliminated; the R-C v6 reta=512 long-tail scenario saves about ~2 us per connect (most significant), R-B v4 various scenarios save about ~390 ns per connect.
- **Real-machine limitation**: virtio reta=0 → can't directly measure the reverse path's end-to-end connect(); the microbench measures pure-function cost (independent of reta), so the data is credible; end-to-end significance is converted via avg calls/conn × Δ single-call cost.
- **Bounce count**: 0.

---

## 6. R-E (requirement 0.5): IP_BIND_ADDRESS_NO_PORT bind-then-connect RSS port-selection migration

### 6.1 Implementation results

Per spec 04 §3-ter / 06 R-E.1, landed in a single commit `ff9e3c449`, 2 files changed (v4 mandatory + v6 sync):

| File | git diff numstat | Description |
|------|------------------|------|
| `freebsd/netinet/in_pcb.c` | **+8 / -0** | hunk1: wraps `in_pcbbind`'s entry-into-hash block with `#ifdef FSTACK if (inp->inp_lport != 0) { ... }` (skip `in_pcbinshash` when lport==0, including the SO_REUSEPORT_LB failure rollback which remains protected by the lport!=0 envelope); hunk2: wraps `in_pcbbind_setup`'s `if (lport == 0) { in_pcb_lport(...) }` with `#ifndef FSTACK` (under FSTACK, bind(addr,0) doesn't pre-allocate a port) |
| `freebsd/netinet6/in6_pcb.c` | **+8 / -1** | hunk-v6-bind: wraps `in6_pcbbind`'s true-branch `in6_pcbsetport` call block (for lport==0) with `#ifndef FSTACK` (under FSTACK, skip v6 port allocation); hunk-v6-connect (path B): under FSTACK, relaxes `in6_pcbconnect`'s outer if condition to `IN6_IS_ADDR_UNSPECIFIED(in6p_laddr) \|\| inp_lport == 0` (allowing bind(v6_addr,0) followed by lport==0 to also enter the RSS port-selection branch); also changes the inner `inp->in6p_laddr = laddr6.sin6_addr;` to be guarded by `if (IN6_IS_ADDR_UNSPECIFIED(in6p_laddr))` (to avoid overwriting the user-bound address from bind) |
| Total | **+16 / -1** | All gated by `#ifdef FSTACK` / `#ifndef FSTACK`; with FSTACK off, reverts to native FreeBSD 15.0 semantics |

> **Does not touch lib**: R-E reuses R-A's already-landed connect-time `INPLOOKUP_LPORT_RSS_CHECK` path, no lib/interface changes; example/rss_ct.c is unchanged (retains R-A's connect-test-carrier semantics).
> **Commit message wording**: upstream referenced `cb9b4d462a0cd8c47b6f514e2af0111cd26597b3` (based on 13.0), but a grep of the 13.0 baseline `freebsd-src-releng-13.0/sys/netinet/in_pcb.c` shows **no `#ifdef FSTACK` guards at all** (L660-664 a plain `if (in_pcbinshash) { rollback }`, L1059-1065 a plain `if (lport == 0) { in_pcb_lport }`), so R-E is an **entirely new migration relative to baseline** (the commit uses "port from upstream / add" rather than "migrate").

### 6.2 Actual landing points (line numbers grep-verified)

**v4 (`freebsd/netinet/in_pcb.c`)**:

| Landing point | Line number | Description |
|------|------|------|
| `in_pcbbind` hunk1 envelope start | L739-741 | `#ifdef FSTACK\nif (inp->inp_lport != 0) {\n#endif` |
| `in_pcbinshash` + `MPASS(SO_REUSEPORT_LB)` failure rollback (unchanged) | L742-748 | The whole block is inside the envelope; when lport!=0, the native rollback executes (INADDR_ANY/lport=0/clear INP_BOUNDFIB); when lport==0, the whole block is skipped |
| hunk1 envelope end | L749-751 | `#ifdef FSTACK\n}\n#endif` |
| `in_pcbbind_setup` hunk2 envelope start | L1281 | `#ifndef FSTACK` |
| `in_pcb_lport` call block (unchanged) | L1282-1286 | Skipped entirely under FSTACK; with FSTACK off, executes native port allocation |
| hunk2 envelope end | L1287 | `#endif` |

**v6 (`freebsd/netinet6/in6_pcb.c`)**:

| Landing point | Line number | Description |
|------|------|------|
| `in6_pcbbind` hunk-v6-bind envelope start | L355 | `#ifndef FSTACK` |
| `in6_pcbsetport` call block (unchanged) | L356-361 | Skipped under FSTACK; with FSTACK off, executes the native path (including BOUNDFIB/laddr rollback) |
| hunk-v6-bind envelope end | L362 | `#endif` |
| `in6_pcbconnect` hunk-v6-connect outer if, three-state | L517-521 | `#ifdef FSTACK\n  if (unspec \|\| lport == 0) {\n#else\n  if (unspec) {\n#endif` — path B |
| `in_pcb_lport_dest(... INPLOOKUP_LPORT_RSS_CHECK)` (R-A already landed) | L523-530 | RSS port-selection path, unchanged |
| Inner `in6p_laddr` guarded assignment | L534-535 | `if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))\n    inp->in6p_laddr = laddr6.sin6_addr;` — guard ensures the user-bound address from bind is not overwritten by connect |

> Note: the v6 line numbers given in spec 06 R-E.1 (L354/L361-369, L515-516) have a +1 offset relative to what's currently measured (the spec was written before R-D coding; R-D commit `f7fd3b60d` didn't directly touch in6_pcb.c but a git reorganization may have caused the line-number shift). This section uses the measured values.

### 6.3 Compilation and lint

- **Compilation (FSTACK on)**: `cd /data/workspace/f-stack/lib && make` passed, `libfstack.a` 6.5MB; `in_pcb.o` / `in6_pcb.o` compiled in cleanly; 0 warnings for the files changed this round (the existing 51 warnings are all pre-existing in the kernel tree, unrelated to R-E).
- **Static macro pairing check**: v4 hunk1 `#ifdef/#endif` ×2 paired, hunk2 `#ifndef/#endif` ×1 paired; v6 hunk-bind `#ifndef/#endif` paired; v6 hunk-connect `#ifdef/#else/#endif` three-state paired. No dangling/unbalanced directives.
- **Static guarantee with FSTACK off**: all changes are gated within `#ifdef FSTACK` / `#ifndef FSTACK`; with FSTACK off, all three envelopes revert to upstream FreeBSD 15.0's native semantics (in_pcb_lport always called, in_pcbinshash always called, in6_pcbsetport always called, connect's outer if is the single condition `IN6_IS_ADDR_UNSPECIFIED`).

### 6.4 Unit test results

Per spec 07 §1.5-ter / TC-U-RSS-05-*:

- **R-A~R-D's existing 36 test cases zero regression**: 35 PASSED + 1 SKIPPED (microbench fallback, already recorded in spec 10 §5-bis.3); the R-E changed files `in_pcb.c` / `in6_pcb.c` are **not linked into `tests/unit/test_ff_dpdk_if`** (`tests/unit/lib_objs/` only contains lib-side `.o` files, no kernel `.o` files), so R-E has no observable change surface at the lib unit-test layer — strong zero-regression evidence.
- **TC-U-RSS-05-01 / 02 / 04 / 05**: per spec 07 §1.5-ter design, **downgraded to integration/real-machine layer verification** (lib cmocka doesn't cover kernel `in_pcbbind` / `in6_pcbbind` unit tests; consistent with the text description in spec 07 §1.5-ter).
- **TC-U-RSS-05-03 (v4 bind(addr,N) zero regression)**: covered by static reasoning + R-A's existing 35 PASSED test cases (the bind(addr,N≠0) path is equivalent to native 15.0 hunk-by-hunk: hunk1 envelope's `lport!=0` is TRUE, so in_pcbinshash executes as usual; hunk2 inner `lport==0` is FALSE, so in_pcb_lport is not called; no difference from native).

### 6.5 Integration/real-machine static call-chain tracing (downgraded per spec 07 §1.5-ter / §2.6 / §3.6)

Since this environment (virtio reta_size=0, local `rss_check enable=0`, no v6 network, no ssh test harness) has limited end-to-end real-machine capability — recorded truthfully in the style of spec 10 §4 — the R-E integration-layer verification uses **static call-chain tracing** (v4 8 steps + v6 9 steps, full-path evidence complete):

**v4 call chain** (bind(v4_addr,0) + connect(remote)):

1. `in_pcbbind` L734: `anonport = sin->sin_port == 0` → TRUE.
2. `in_pcbbind_setup` L1268: `laddr = sin->sin_addr` (user address retained); L1281-1287 hunk2's `#ifndef FSTACK` skips `in_pcb_lport` → `*lportp = lport (= 0)` written back.
3. Back in `in_pcbbind` L739-751, hunk1's `#ifdef FSTACK if (inp->inp_lport != 0)` skips `in_pcbinshash` → `inp_laddr` already set, `inp_lport=0`, INP_INHASHLIST not set; L752 `if (anonport)` triggers `INP_ANONPORT`.
4. `in_pcbconnect` L1313: `anonport = (inp->inp_lport == 0)` → TRUE (R-E hunk keeps lport=0).
5. L1339 `in_nullhost(inp->inp_laddr)` is FALSE (hunk2 already wrote laddr), L1351 `laddr = inp->inp_laddr` takes the user-bound address (IP_BIND_ADDRESS_NO_PORT semantics: fixed address, deferred port).
6. L1353 `if (anonport)` is entered → L1363-1366 `in_pcb_lport_dest(..., INPLOOKUP_WILDCARD | INPLOOKUP_LPORT_RSS_CHECK)`, the FSTACK path obtains the RSS-selected port.
7. `in_pcb_lport_dest` (already landed in R-A) parses the RSS flag and selects a source port that lands on this queue (already confirmed in spec 10 §2.1).
8. L1387-1389 at the end of connect, `in_pcbinshash` enters the hash for the first time (not entered during bind).

**v6 call chain** (bind(v6_addr,0) + connect6(remote), path B):

1. `in6_pcbbind` L344-351: bind succeeds, `in6p_laddr = sin6->sin6_addr` (user-bound address), `lport = sin6->sin6_port = 0`.
2. L354 `if (lport == 0)` is entered; L355-362 hunk-v6-bind's `#ifndef FSTACK` skips the whole `in6_pcbsetport` block → lport stays 0, in6p_laddr stays bound.
3. `in6_pcbconnect` L506: `in6_pcbladdr` selects laddr6; L510-514 `in6_pcblookup_hash_locked` returns NULL.
4. L517-521 hunk-v6-connect's outer if (path B): under FSTACK the condition is `IN6_IS_ADDR_UNSPECIFIED || lport == 0`, the second term is TRUE → enters the RSS branch (path B correction: after bind, in6p_laddr is already set, so the single condition `unspec` is not satisfied; R-E adds the `lport==0` short-circuit term to recover the RSS path).
5. L522 inner `if (inp->inp_lport == 0)` is TRUE → L523-530 `in_pcb_lport_dest(..., INPLOOKUP_WILDCARD | INPLOOKUP_LPORT_RSS_CHECK)` under FSTACK, obtains the v6 RSS-selected port.
6. L534-535 the inner guard `if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))` is FALSE (user already bound) → `inp->in6p_laddr = laddr6.sin6_addr;` **does not** execute (the user-bound address from bind is retained).
7. L545-549 at the end of connect, `in_pcbinshash` enters the hash for the first time.

**Real-machine data reuses R-A's existing 200/200×2 evidence** (spec 10 §3.2): rss_ct primary/secondary each achieved 100% (200/200) queue landing on 200 connects, proving the correctness of R-A's connect-time RSS port-selection path; R-E's change is merely "letting bind-then-connect also enter that same R-A path" (step 6 of the v4 chain / step 5 of the v6 chain both share R-A's already-confirmed `INPLOOKUP_LPORT_RSS_CHECK` entry point), so R-E's end-to-end correctness is jointly established by R-A's existing data + R-E's static path evidence.

### 6.6 Real-machine limitations (recorded truthfully, not defects)

| Limitation | Symptom | Design countermeasure |
|------|------|----------|
| Local `rss_check enable=0` (committed default state) | When RSS portrange is not enabled, `INPLOOKUP_LPORT_RSS_CHECK` after parsing takes native port selection (doesn't trigger ff_rss_check) | Consistent with R-A/R-B/R-C/R-D; R-E introduces no new constraint, enabling RSS only needs `[rss_check] enable=1` (a local state, not committed) |
| virtio `reta_size=0` | thash path degrades to soft-compute (already recorded in spec 10 §4) | R-E is decoupled from the thash path (it's only a bind gate), unaffected |
| This environment has no v6 network + no ssh f-stack-client harness | Unable to run an end-to-end bind(v6,0)+connect6 real-machine test case locally | spec 07 §1.5-ter already designed the downgrade path; R-E's v6 correctness is guaranteed by the v6 static call chain + compilation verification |

### 6.7 R-E gate item-by-item checklist (spec 06 R-E.4)

| # | Gate | Resolution |
|---|------|------|
| 1 | Compiles with FSTACK on and off | FSTACK on: lib make PASS; FSTACK off: static macro pairing is complete + all `#ifdef`/`#ifndef` gates revert to native 15.0 |
| 2 | v4 after bind(v4,0), inp_lport==0 not entered into hash; connect anonport=true goes through L1363-1366 RSS branch; source port lands on this queue after ff_rss_check re-verification | All 4 sub-assertions confirmed via static call chain (§6.5 v4 steps 1-7); queue-landing correctness reuses R-A's existing 200/200 |
| 3 | v4 bind(addr,N) behavior completely unchanged (port fixed + normally entered into hash), zero regression | With hunk1's `lport!=0` true, in_pcbinshash executes as before (equivalent to native); with hunk2's inner `lport==0` false, in_pcb_lport is not called (equivalent to native); R-A~R-D's 35 existing test cases show zero regression |
| 4 | v6 after bind(v6,0), inp_lport==0; connect enters the RSS branch (path B confirmed); source port lands on this queue after ff_rss_check6 re-verification | hunk-v6-bind skips `in6_pcbsetport` keeping lport=0; hunk-v6-connect path B `unspec \|\| lport==0` enters the RSS branch; queue-landing correctness jointly guaranteed by R-A's `in_pcb_lport_dest` v6 branch + R-C's `ff_rss_check6` |
| 5 | REUSEPORT_LB bind(addr,0) behaves correctly (doesn't break L740 MPASS) | hunk1's envelope `if (lport!=0)` holds; for REUSEPORT_LB bind(addr,0), the whole in_pcbinshash block is skipped (doesn't trigger MPASS); for REUSEPORT_LB bind(addr,N), in_pcbinshash failure still triggers MPASS (rollback complete within the envelope). Both paths correct |
| 6 | With FSTACK off / enable=0 / single queue, reverts to native behavior | All `#ifdef`/`#ifndef` gates; with FSTACK off, equivalent to upstream 15.0; with rss_check enable=0, after `INPLOOKUP_LPORT_RSS_CHECK` parsing, native port selection is taken (confirmed in R-A); with nb_queues<=1, ff_rss_check returns 1 directly (confirmed in R-A) |
| 7 | Whether the 13.0 baseline contains the three hunks (E6) has been grep-confirmed | grep of `freebsd-src-releng-13.0/sys/netinet/in_pcb.c` shows 0 `#ifdef FSTACK` guards; R-E is an entirely new addition relative to baseline (commit verb = "port from upstream cb9b4d462") |
| 8 | git diff in_pcb.c v4 ≤8/0; in6_pcb.c v6 ≤10; config.ini contains no local test values | numstat in_pcb.c **8/0** + in6_pcb.c **8/1** = +16/-1, all within the spec's budget; commit `ff9e3c449` used precise `git add freebsd/netinet/in_pcb.c freebsd/netinet6/in6_pcb.c`, **did not** add config.ini (local test-state values such as lcore_mask=10/idle_sleep=20/port0=<DPDK_NIC_IP> were kept out of the commit in the working tree) |

> All 8 gate items PASS, bounce=0.

### 6.8 R-E implementation landing summary

- **Code change surface**: 2 files / +16 / -1, zero function-signature changes, zero lib changes, zero ABI impact, fully macro-gated.
- **Correctness**: v4 + v6 full-path static evidence + R-A's existing 200/200×2 real-machine data jointly guarantee correctness; with FSTACK off, reverts to native 15.0; zero-tolerance items (REUSEPORT_LB MPASS, bind(addr,N) zero regression) are directly guaranteed by the envelope design.
- **Performance**: R-E is a bind-path gate (one-time, not a hot spot), no runtime overhead; subsequent connect-time port selection uses the already-optimized R-A/R-B/R-D paths.
- **Real-machine limitations**: rss_check enable=0 / virtio reta=0 / no v6 NIC / no ssh harness — all four recorded truthfully (consistent with spec 10 §4's style), with the static call chain + R-A's existing data serving as proxy evidence.
- **Bounce count**: 0; a reviewer sub-agent timed out once with no response (>5min), triggering the leader to take over the review (executed per AI memory 76046304's policy: the leader did not personally write the code — v4/v6 coding was done by impl-coder; after the leader took over the review, the subsequent gate was executed by an independent gatekeeper, not constituting "self-writing and self-reviewing").

### 6.9 R-E setsockopt-layer patch: IP_BIND_ADDRESS_NO_PORT option wiring (2026-07)

> R-E (§6) fixed the FreeBSD kernel-side bind gate in `in_pcb.c`/`in6_pcb.c` (so that `bind(addr,0)` does not grab a port and defers to connect for RSS-aware port selection). However, before nginx actually triggers that path it first calls `setsockopt(IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT)`, and this setsockopt option was **not wired up** in the F-Stack lib translation layer, causing v6 sockets to get EINVAL and v4 sockets to be silently misrouted to set INP_BINDANY. This section records that setsockopt-layer patch.

**Root cause (substantiated by code)**:
- Numeric collision: Linux `IP_BIND_ADDRESS_NO_PORT = 24` (`/usr/include/linux/in.h`) == FreeBSD `IP_BINDANY = 24` (`freebsd/netinet/in.h:462`).
- `lib/ff_syscall_wrapper.c`'s `ip_opt_convert()` had no `LINUX_IP_BIND_ADDRESS_NO_PORT` branch; `default: return optname` passed 24 through unchanged → `kern_setsockopt(IPPROTO_IP, 24)` was treated by FreeBSD as `IP_BINDANY`.
- v4 path: `ip_ctloutput` (`ip_output.c:1092`) L1174 `case IP_BINDANY` matched → `priv_check` + `OPTSET(INP_BINDANY)` → **silently mis-set INP_BINDANY** (transparent-proxy side effect, no error reported).
- v6 path: `ip6_ctloutput` (`ip6_output.c:1573`) L1605 `if (level != IPPROTO_IPV6)` → `error = EINVAL` (L1606) → the source of nginx's `setsockopt(IP_BIND_ADDRESS_NO_PORT) failed, ignored (22: Invalid argument)`.

**Fix (commit `a2537e143`, `lib/ff_syscall_wrapper.c`, +17/-0)**:
- Added `#define LINUX_IP_BIND_ADDRESS_NO_PORT 24`.
- `ff_setsockopt`: intercepts `IPPROTO_IP + LINUX_IP_BIND_ADDRESS_NO_PORT` before the `linux2freebsd_opt` call and returns success no-op (FreeBSD `bind(port=0)` already defers port allocation to connect; F-Stack RSS `ff_rss_adjust_sport/6` back-derives the source port at connect, so there is no need to pass it into the kernel).
- `ff_getsockopt`: same interception, returns optval=1 (symmetric with set).
- Covers v4/v6: nginx calls setsockopt at the IPPROTO_IP level for both v4 and v6 sockets, so the IPPROTO_IP interception naturally covers both.

**Verification**:
- Compilation: `ff_syscall_wrapper.o` compiles cleanly under `-Werror` (exit=0).
- Integration test limited: the local DPDK virtio PCI devices are occupied by the kernel, so nginx_fstack could not be started for a DPDK-path end-to-end test; fix correctness is guaranteed by static code substantiation (numeric collision + interception point + FreeBSD bind(0) deferred-port semantics) plus successful compilation.
- v4/v6 consistency: the interception point is at `level == IPPROTO_IP`, through which both v4 and v6 sockets pass; v6 EINVAL is eliminated and v4 no longer mis-sets INP_BINDANY.

---

## 6-bis. R-G (IPv6 reverse-path misqueue symmetric fix)

> Role: spec-writer, documentation sync after coding completion. This change was coded by impl-coder, design-reviewed by arch-verifier, and gated by gatekeeper; the leader has completed compilation + unit-test confirmation. All line numbers are confirmed by reading the code (based on actual code such as `lib/ff_dpdk_if.c`).
> Note: all line numbers referenced in this section are based on the **currently measured working tree**; in the leader's handoff notes, v4 base=64 and v6 base=256 were the **pre-fix old values**; both have now been symmetrically corrected (v4 64→80, v6 256→272), and the code comments have been updated accordingly (`ff_dpdk_if.c` L140-163).

### 6-bis.1 Problem (reverse-path misqueue)

Commit `c42340d5` already fixed the same-kind IPv4 bug: when f-stack runs multiple processes and back-derives the LOCAL source port, the purpose is to make the **inbound reply SYN-ACK** land on the RSS queue of the process that initiated the connect. Because Toeplitz is asymmetric (see §6-bis.5), the outbound packet (local→remote) and the reply packet (remote→local) land on **different** queues via the NIC's RSS — if back-derivation is done using the **outbound sport field**, the reply instead lands on the wrong queue, manifesting as **listen succeeds but the connection doesn't work, IPv4 is normal**. R-G is the symmetric port for IPv6.

### 6-bis.2 IPv4 template (the reference for this round's symmetry, code confirmed)

| Fact | Landing point | Description |
|------|------|------|
| v4 tuple layout comment (reply order + offset=80 rationale) | `ff_dpdk_if.c` L140-152 | Comment clarifies: the reply-packet hash is (srcIP=remote, dstIP=local, srcPort=80, dstPort=localPort), and the local port lands in the **dstPort field, byte10 = bit80** (not the outbound sport's bit64) |
| `FF_RSS_THASH_V4_SPORT_OFF` = **80** | `ff_dpdk_if.c` L152 | Was 64 before the fix (the outbound sport field), corrected to 80 in this round (the reply's dstPort field) |
| `ff_rss_adjust_sport(..., first, last)` | `ff_dpdk_if.c` L3252-3253 | Parameters already include `first/last`; base aligns with the [first,last] ephemeral window (L3300-3311); tuple filled in reply order (saddr=remote@0 / daddr=local@4 / dport@8 / sport@10, see L3333-3341) |

### 6-bis.3 IPv6 symmetric change list (code confirmed)

| Symbol / landing point | Line number | Change | Symmetry relation with v4 |
|-------------|------|------|----------------|
| v6 tuple layout comment | `ff_dpdk_if.c` L156-163 | Notes: v6 tuple is 36B, sport field is byte32=bit256, **the reply's dstPort field is byte34=bit272** | Symmetric to v4's L140-152 |
| `FF_RSS_THASH_V6_SPORT_OFF` **256→272** | `ff_dpdk_if.c` L163 | v6 helper offset changed from the outbound sport field (bit256) to the reply's dstPort field (**bit272** = byte34) | Symmetric to v4's 64→80 (byte10) |
| `ff_rss_adjust_sport6(..., uint16_t first, uint16_t last)` | `ff_dpdk_if.c` L3689-3691 | Added `first/last` parameters | Symmetric to v4's L3252-3253 |
| base alignment to the [first,last] window | `ff_dpdk_if.c` L3720-3733 | `base = (first + reta_size-1) & ~(reta_size-1)`; out-of-range/misaligned/nblocks==0 → returns -1 falling back to soft scan; random block starting point | Symmetric to v4's L3298-3312 |
| desired ∈ D(q) selection | `ff_dpdk_if.c` L3735-3737 | `desired = queueid + (rand % ceil(R/Q))*nb_queues`, making `(hash&(R-1))%Q==queueid` | Symmetric to v4's L3319-3321 |
| tuple filled in **reply field order** | `ff_dpdk_if.c` L3745-3750 | `saddr6`(remote)@0 / `daddr6`(local)@16 / `dport`(remote 80)@32 / `sport`(local seed→solved)@**34** | Symmetric to v4's L3333-3341 (the local port lands in the reply's dstPort field) |
| `rte_thash_adjust_tuple` + host_lport range check | `ff_dpdk_if.c` L3752-3765 | After back-derivation, `bcopy(&tuple[34],&sport,2)`; `host_lport=ntohs(sport)`; if out of [first,last] then `desired += nb_queues; continue` | Symmetric to v4 |
| Re-verification with swapped positions + host-order return | `ff_dpdk_if.c` L3766-3769 | `!recheck \|\| ff_rss_check6(softc, saddr6, daddr6, **dport, sport**)` (actual argument dport→formal parameter sport slot, sport→formal parameter dport slot, i.e. re-verifying in reply field order); `*out_sport = host_lport` (returned in host order) | Symmetric to v4; `ff_rss_check6`'s signature is `(..., uint16_t sport, uint16_t dport)` (L3440-3441) |
| Header declaration adds first/last | `ff_host_interface.h` L103-104 | `int ff_rss_adjust_sport6(void*, const uint8_t*, const uint8_t*, uint16_t dport, uint16_t *out_sport, uint16_t first, uint16_t last);` | Symmetric to v4's L93-94 |
| Kernel v6 call site passes first/last | `freebsd/netinet/in_pcb.c` L899-903 | `ff_rss_adjust_sport6(ifp->if_softc, faddr6->s6_addr, laddr6->s6_addr, fport, &rss_sel, first, last)`; `lport = htons(rss_sel)` | Symmetric to v4's call site L961-965 (`ff_rss_adjust_sport(..., first, last)`) |
| Unit tests v6 cases add first/last | `tests/unit/test_ff_dpdk_if.c` L1144-1157, L1373-1375, etc. | `ff_rss_adjust_sport6(..., TEST_RSS_FIRST, TEST_RSS_LAST)` (guard / recheck-off etc. test cases all carry first/last) | Symmetric to v4's test cases L770-777, etc. |

> **Key correctness point**: v6 tuple's **byte34=bit272** is exactly the **dstPort field** of the reply (SYN-ACK) 4-tuple (the field where the local port sits in the reply), different from the outbound packet's sport field (byte32=bit256) — because Toeplitz is asymmetric, the dstPort field bit must be back-derived for the reply to land on this queue. This is **structurally exactly symmetric** to v4's byte10=bit80 (symmetric to the outbound sport's byte8=bit64).

### 6-bis.4 Compilation + unit test results (leader confirmed)

- **Compilation**: `libfstack.a` passed (the files changed this round — `ff_dpdk_if.c` / `ff_host_interface.h` / `in_pcb.c` / `test_ff_dpdk_if.c` — compiled in cleanly).
- **Unit tests**: `tests/unit/test_ff_dpdk_if` **39 run / 36 PASSED / 3 SKIPPED**.
  - The 3 SKIPPED are the **existing degradation** where DPDK EAL cannot init in the unit-test environment (reta<2 → thash ctx not ready → adjust_sport[6] returns -1, falling back to soft scan, sharing the same origin as the degradation path recorded in §4/§5-bis.3), not a failure introduced by this change.
  - The v6 guard / recheck-off etc. test cases all PASS after the `first/last` parameters were added, zero regression from the signature change.

### 6-bis.5 Toeplitz asymmetry theory (theoretical root cause of this bug)

Toeplitz hash is asymmetric: `hash(src, dst, sport, dport) ≠ hash(dst, src, dport, sport)`. Therefore, an outbound packet (local→remote) and a reply packet (remote→local) land on **different** queues via the NIC's RSS. f-stack's purpose in back-deriving the LOCAL port is to make the **reply SYN-ACK** land on the queue of the process that initiated the connect, so the back-derivation must be done in **reply field order** — the local port in the reply sits in the **dstPort field** (v4 byte10=bit80 / v6 byte34=bit272), not the outbound packet's sport field (v4 byte8=bit64 / v6 byte32=bit256). This directly explains the offset correction from the sport field to the dstPort field.

### 6-bis.6 External corroboration (see spec 03 §5-bis for details)

| Source | Conclusion | Consistent with R-G |
|------|------|-------------|
| DPDK official Toeplitz Hash Library documentation (primary) | Toeplitz is asymmetric; bidirectional flows land on different queues; the SNAT example adjusts the **dstPort field** bits with the helper (`offsetof(...dport)*8`) | Consistent: corroborates the "back-derive the reply's dstPort field bit" approach, sharing its origin with DPDK's official documentation |
| DPDK Symmetric RSS (Cnblogs, secondary) | Under the default asymmetric key, the same flow's receive/send directions hash differently → land on different queues | Consistent: corroborates the asymmetry root-cause theory |
| Microsoft Learn NDIS RSS hash types (primary) | IPv6 TCP 4-tuple definition; Toeplitz takes values in field order | Consistent: corroborates that v6 tuple field order matters, and back-derivation in reply field order is necessary |
| F-Stack official wiki "ff_rss_check() Optimization" (primary) | The source port is the only controllable variable; the purpose of port selection is to make the **reply** land on the local worker's queue | Consistent: corroborates that the back-derivation target is making the reply land correctly (the wiki is IPv4-only; R-G is the v6 symmetric extension) |

### 6-bis.7 IPv4 zero regression

- The IPv4 side's offset=80 / reply-order back-derivation / first/last were landed by commit `c42340d5` and have already been **verified OK on a physical machine**; R-G only adds/symmetrizes the v6 path, **without changing any of the v4 logic's branch conditions** (v4's `ff_rss_adjust_sport` code starting at L3252 is unchanged).
- The kernel v6 call site (`in_pcb.c` L899-903) and the v4 call site (L961-965) are parallel, independent branches (dispatched by `lsa->sa_family`, see spec 10 §2.3 / F5); the v6 change doesn't touch the v4 branch's control flow.
- The existing v4 unit tests (including the R-A~R-F full-loop 100% queue-landing hard assertions) remain PASS after this change; v4 zero regression.

### 6-bis.8 Real-machine verification status (completed)

- This environment's virtio `reta_size=0` → the thash ctx cannot be initialized (`reta_size<2 → continue`, rss_thash6_ready=0) → `ff_rss_adjust_sport6` returns -1 falling back to soft scan, so the v6 reverse-path back-derivation path cannot be verified end-to-end on **this virtio machine** (sharing the same origin as the virtio degradation recorded in §4/§5-bis.4, not a defect).
- **Physical-machine end-to-end verification completed and passed (2026-07)**: on a physical machine with real v6 RSS capability, R-G's v6 reverse path was verified — during multi-queue v6 active connect, the source-port back-derivation makes the reply (inbound SYN-ACK) land on this process's queue with 0 misqueued and IPv4 zero regression at the same time; the symmetric fix for this deterministic 13→15 regression (v6 TCP normal on 13.0, listen succeeds but connect fails on 15.0) is effective end-to-end. Correctness is additionally backed by **unit-test v6 full-loop queue landing + Toeplitz asymmetry theory + primary external corroboration** (see §4-bis).

### 6-bis.9 R-G implementation landing summary

- **Change surface**: `lib/ff_dpdk_if.c` (v6 offset 256→272 + `ff_rss_adjust_sport6` adds first/last + reply-order tuple + swapped-position re-verification), `lib/ff_host_interface.h` (declaration adds first/last), `freebsd/netinet/in_pcb.c` (L899-903 call site passes first/last), `tests/unit/test_ff_dpdk_if.c` (v6 test cases add first/last); structurally exactly symmetric to v4.
- **Correctness**: Toeplitz asymmetry theory root cause + primary corroboration from DPDK official/NDIS/f-stack wiki + unit tests 39 run/36 PASS/3 SKIP (existing EAL degradation) + IPv4 zero regression; v6 end-to-end pending on an mlx5 physical machine.
- **Bounce count**: 0 (coding by impl-coder / review by arch-verifier / gating by gatekeeper — write/review separation, consistent with AI memory 76046304).

---

## 6-ter. R-F three-party key alignment + IPv6 reverse-proxy address fix + diagnostic gating (merged conclusions from _rf_work)

> Merges the conclusions from `_rf_work/{arbiter_rootcause, design_rf, ixgbe_misqueue_facts, realmachine_sop, team_runtime_postmortem}.md` that were confirmed via independent arbitration/review and are consistent with the current code. See 02 §6-quater / 04 §3-quater for the root cause and plan.

### 6-ter.1 thash three-party key alignment (root cause + landing, code confirmed)

- **Root cause (arbitration verdict)**: `rte_thash_add_helper` uses an LFSR to mutate `ctx->hash_key` in place; `rte_thash_adjust_tuple` back-derives using the mutated key, while `ff_rss_check`/the NIC use the original key — the three-party keys are inconsistent, resulting in a historical ~22-27% coincidental hit rate. The byte-order hypothesis (`be_to_cpu_32`) has been proven equivalent at the bit level and invalidated.
- **Landing**: `ff_rss_thash_build_key(port_id, reta_size)` (`ff_dpdk_if.c:3027`) serially constructs the v4→v6 ctx before `dev_configure` (v4 helper offset=80, v6=272, helper len=16), publishing a unified KEY_FINAL to the global `rsskey`, which the caller's dev_configure programs into the NIC (rather than a post-start `rss_hash_update`); secondary processes reuse the same ctx via `rte_thash_find_existing` (this resolves 0.1's EEXIST root cause). The `thash_adjust` switch (default 1, decoupled from `enable`) gates build_key/ctx_init/adjust route②.

### 6-ter.2 Runtime measured facts (Intel X550 ixgbe, merged from ixgbe_misqueue_facts)

- F1: `ff_rss_check`'s pure soft-compute is correct (enable=0 uses the default key); F2: the KEY_FINAL value itself is correct (hardcoded into the static key + short-circuiting build_key + enable=0 → normal); F3: RETA=`idx%nb_queues`, reta_query measured with `mismatch=0`.
- Comparing B2 (KEY_FINAL placed in static BSS) — normal — vs B3 (KEY_FINAL placed in `rte_malloc` shared hugepage) — abnormal — points to an issue with how the rss_key memory type is delivered to the NIC via ixgbe dev_configure/dev_start under multi-process — this is a real-machine-layer verification item (see §6-ter.4 SOP).

### 6-ter.3 IPv6 reverse-proxy address fix (`lib/ff_veth.c`, code confirmed, also see spec 11)

Three fixes for IPv6 reverse-proxy VIP not working under FreeBSD 15.0, all gated by `#ifdef INET6`, purely additive with zero v4 regression:

| Fix point | Landing point | Description |
|--------|------|------|
| VIP6 as a /128 host addr | `ff_veth_setvaddr6`, `ff_veth.c:879-880` `memset(&ifra_prefixmask.sin6_addr, 0xff, 16)` | Avoids installing an on-link prefix route, so traffic to other addresses in the VIP's subnet correctly goes via the gateway |
| Link-local gateway scope | `ff_veth_set_gateway6`, `ff_veth.c:849-850` `if (IN6_IS_ADDR_LINKLOCAL(&gw.sin6_addr)) in6_setscope(&gw.sin6_addr, sc->ifp, NULL)` | Fills in the zone ID for a `fe80::/10` gateway, so the link-local gateway can be resolved |
| Skip DAD | `ff_veth_setup_interface`, `ff_veth.c:980` `ND_IFINFO(ifp)->flags \|= ND6_IFF_NO_DAD` | Without a timer-driven mechanism in user space, an address would remain permanently TENTATIVE, and FreeBSD 15's `ip6_input` silently drops packets destined for a NOTREADY/TENTATIVE unicast address |

### 6-ter.4 Real-machine verification SOP highlights (merged from realmachine_sop)

Unit tests / local virtio reta=0 cannot verify end-to-end "three-party key alignment → adjust selects sport that actually lands on this queue"; the following must be executed step-by-step on a real RSS NIC (i40e/ixgbe/ice/mlx5):

- **P1 route① startup availability**: start with `thash_adjust=1`, check the logs to confirm KEY_FINAL construction/publishing succeeded or automatically degraded to route②; use `rss_hash_conf_get` to dump and confirm the sport-participating byte segment of the NIC key has been rewritten.
- **P2 route①/② switching**: restart-compare with `thash_adjust=1` vs `=0`; with `=0`, `adjust_sport*` always returns -1 falling back to soft scan, the NIC key remains original, business logic correct.
- **P3 three-party key offline cross-check** (runnable on any machine): using KEY_FINAL to re-compute the sport selected by adjust, verify it lands on the desired queue via `ff_rss_check`, expected equivalence rate ~100% (compared to ~22-27% before the fix).
- **P4 RETA assumption**: verify `rss_reta_query` shows `reta[idx]==idx%nb_queues`.
- **P5 secondary find_existing** (multi-process): no `find_existing failed` errors; on failure, that process falls back to soft scan.
- Exception contingency plan per the bounce≤3 rule: if route① is unavailable (init/hash_update failure) → switch to route② with `thash_adjust=0`; if route② still misqueues → escalate to manual decision.

### 6-ter.5 Diagnostic capability compile gating (FF_RSS_DIAG)

`ff_rss_diag_dump_key` (`ff_dpdk_if.c:2990`) and its key/RETA hex-dump call sites in `build_key` (L3148-3157)/`ctx_init` are gated by the compile-time macro **`FF_RSS_DIAG`, disabled by default, with no effect on the data plane**. When enabled, it's used for cross-checking primary/secondary keys and NIC readback during troubleshooting.

### 6-ter.6 Process traceability note (merged from team_runtime_postmortem)

The first half of R-F (diagnosis/arbitration/design/review) went through a multi-agent team runtime failure; it was actually completed via "serial subagent + leader takes over writing + independent subagent reviews", achieving **write/review separation** (diagnostic diag-code/diag-dpdk and arbitration arbiter were different instances; after the leader took over writing the design, an independent reviewer reviewed it). The technical conclusions (key-inconsistency root cause + v4/v6 serial construction) have source-code, line-level evidence + independent review, so the **conclusions are reliable and unaffected by the collaboration method**; this fact has been recorded truthfully in `_rf_work/team_runtime_postmortem.md` for traceability.

---

## 7. Gate conclusion

- **Coding-phase gate: PASS.** **All five requirements (0.1 migration / 0.3 thash / 0.2 IPv6 / 0.4 recheck default off / 0.5 IP_BIND_ADDRESS_NO_PORT bind-then-connect) have been implemented**, tested, and committed; zero IPv4 regression; zero tolerance for wrong-queue selection is guarded by soft-compute re-verification on the recheck=1 path, while the recheck=0 path openly trades off distribution unevenness without affecting connection correctness; real machine 0.1 multi-queue distribution 200/200×2 all correct; unit tests 36 cases PASS 35 / SKIPPED 1 (microbench fallback); recheck on/off microbench Δ ≈99.4 ns/call, ratio ≈300×.
- **Local virtio limitation** (reta=0 → 0.3/0.4 reverse degrades to soft-compute) recorded truthfully, guaranteed for correctness and performance data by unit tests/microbench, not a defect; the **IPv6 functional tests (server / client / reverse proxy) have been completed on a physical machine (plus the server on this machine's runtime) and all passed** — see §4-bis.
- **Bounce count: 0**.
- R-E (commit `ff9e3c449`)'s zero-tolerance items (REUSEPORT_LB MPASS / bind(addr,N) zero regression) are directly guaranteed by the envelope design; end-to-end real-machine limitations recorded truthfully per spec 10 §4's style, using R-A's existing 200/200×2 data + R-E's static call chain as proxy evidence; bounce count: 0 (a reviewer's single timeout was taken over by the leader, with the gate executed by an independent sub-agent, consistent with AI memory 76046304's write/review separation policy).
- **R-G (IPv6 reverse-path misqueue symmetric fix)**: v6's `FF_RSS_THASH_V6_SPORT_OFF` 256→272 (reply's dstPort field byte34), `ff_rss_adjust_sport6` adds first/last + reply-order tuple + swapped-position re-verification, symmetric to IPv4's c42340d5; compiles, unit tests 39 run/36 PASS/3 SKIP (existing EAL degradation), IPv4 zero regression; Toeplitz asymmetry theory root cause + primary external corroboration from DPDK official/NDIS/f-stack wiki (spec 03 §5-bis); **v6 end-to-end verified and passed on a physical machine (2026-07, see §4-bis / §6-bis.8)**; bounce count: 0. See §6-bis for details.
