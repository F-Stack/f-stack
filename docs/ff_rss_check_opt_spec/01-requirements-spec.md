# 01 Requirements Spec — ff_rss_check Three-Item Optimization

> Scope: Three optimizations to the RSS (Receive Side Scaling) capabilities in F-Stack's `lib/ff_dpdk_if.c`.
> Baseline commit: `2422d12eb` (feature/1.26).
> Principle: All conclusions are based on actual code/header files, with `file:line` evidence; items of uncertainty are marked "Pending Confirmation".
> This document only describes "what to do / why / acceptance criteria"; see 04 for design.

---

## 0. Background: Overview of the RSS Source-Port Selection Mechanism

Under multi-queue (multi-queue / multi-process) deployment, to ensure that the local source port chosen when actively initiating a connection (connect) allows packets of that 4-tuple, after NIC RSS hashing, to return to **the receive queue corresponding to this process**, F-Stack introduces an RSS port selection mechanism:

- User space (`lib/ff_dpdk_if.c`): computes a software Toeplitz hash (`toeplitz_hash` L2547) to emulate NIC RSS, determining whether a given 4-tuple lands in this queue (`ff_rss_check` L2851); it also pre-builds a static table `ff_rss_tbl` (L172) caching, for a given saddr/daddr/sport, which dport values land in this queue, queried by `ff_rss_tbl_get_portrange` (L2796) during port selection.
- Kernel space (`freebsd/netinet/in_pcb.c`): in `in_pcb_lport_dest`, which selects the local port, for requests carrying the `INPLOOKUP_LPORT_RSS_CHECK` flag, calls the above user-space interface to select the source port only from the "set of ports that land in this queue".

This mechanism had complete kernel-side hookup in the 13.0 baseline (IPv4 only), but the kernel-side hookup was lost after the 13.0→15.0 upgrade (see 02 for details). The three optimizations revolve around "completing / extending / optimizing" this mechanism.

---

## 1. Requirement 0.1: Back-port `ff_rss_tbl_get_portrange` Kernel Hookup to 15.0

### 1.1 Background
- The user-space interfaces `ff_rss_tbl_get_portrange` (`lib/ff_dpdk_if.c:2796`), `ff_rss_tbl_set_portrange` (L2737), `ff_rss_tbl_init` (L2598), `ff_rss_check` (L2851), and `ff_in_pcbladdr` (L2571) **still exist and remain intact** on 15.0.
- However, the kernel-side (`freebsd/netinet/in_pcb.c`) `#ifdef FSTACK` RSS hooks that consume these interfaces were **not ported** during the 13.0→15.0 upgrade: grepping the current 15.0 `in_pcb.c` for `FSTACK / ff_rss_* / ff_in_pcbladdr / INPLOOKUP_LPORT_RSS_CHECK` yields 0 hits; only `in_pcb.h:624` retains the `#define` of `INPLOOKUP_LPORT_RSS_CHECK`.
- Result: the `INPLOOKUP_LPORT_RSS_CHECK` macro exists but **is consumed by no code**, so the RSS port-selection mechanism is **completely non-functional** on the kernel side of 15.0.

### 1.2 Goal
Re-hook (back-port) the 13.0 FSTACK RSS port-selection logic into the current 15.0 kernel `in_pcb.c`, following 15.0's code structure, so that on an active connect the user-space `ff_rss_tbl_get_portrange` / `ff_rss_check` can be reused to select a source port that lands in this queue, and complete functional testing after migration.

### 1.3 In Scope
- The RSS portrange port-selection logic in `in_pcb_lport_dest` (15.0 L756) in `in_pcb.c`.
- The hookup of `ff_in_pcbladdr` at the local-address-selection site in `in_pcb.c` (in 13.0 this is in `in_pcbconnect_setup`; on 15.0 the corresponding function is `in_pcbconnect`, see 02).
- Passing the `INPLOOKUP_LPORT_RSS_CHECK` flag at the port-selection call site.
- All gated by `#ifdef FSTACK`, minimal intrusion.
- Functional/regression testing (IPv4) after the back-port.

### 1.4 Out of Scope
- IPv6 is not included in this requirement (belongs to 0.2).
- Introducing `rte_thash_*` is not included in this requirement (belongs to 0.3).
- The user-space `ff_rss_*` interface signatures are not changed (they already exist and are retained).

### 1.5 Acceptance Criteria
- The `#ifdef FSTACK` RSS hooks reappear in 15.0's `in_pcb.c`, and it compiles successfully (with FSTACK enabled).
- With `rss_check` enabled (config.ini `[dpdk]`), under a multi-queue scenario, the source port selected by connect passes `ff_rss_check` validation and lands in this queue (consistent with 13.0 behavior).
- With `rss_check` disabled (enable=0) or single-queue, behavior falls back to native FreeBSD port selection (no regression).
- Existing unit tests (`tests/unit/test_ff_dpdk_if.c` L358-455 set/get_portrange cases) still pass.

---

## 2. Requirement 0.2: `ff_rss_check` / `ff_rss_tbl_get_portrange` Support for IPv6 Hash

### 2.1 Background
- The current user-space RSS pipeline **supports IPv4 only**:
  - `ff_rss_check` (L2851) takes `uint32_t saddr/daddr` parameters, with hash-input layout `saddr(4)+daddr(4)+sport(2)+dport(2)` (L2865-2880), no 16-byte v6-address path.
  - `ff_rss_tbl_get_portrange` (L2796) / `ff_rss_tbl_set_portrange` (L2737) / `ff_rss_tbl_init` (L2598) all key on `uint32_t saddr/daddr`.
  - The static-table structures `struct ff_rss_tbl_type` / `ff_rss_tbl_dip_type` (L155-172) have `uint32_t saddr/daddr` fields.
- Kernel side: grepping the 13.0-baseline `netinet6/in6_pcb.c` for `FSTACK / ff_rss / INPLOOKUP_LPORT_RSS_CHECK` yields 0 hits; likewise 0 hits on 15.0. **That is, RSS port selection is IPv4-only even in 13.0 itself**.

### 2.2 Goal
Extend `ff_rss_check` / `ff_rss_tbl_get_portrange` (and the related static table and init/set functions) to support RSS hash computation and port selection for IPv6 addresses (16 bytes); and newly build the hookup in the kernel `in6_pcb` port-selection flow.

### 2.3 In Scope
- Support IPv6 (16+16+2+2) in the user-space hash-input layout, with RSS hash field configuration including IPv6/TCP_IPV6 (NIC/DPDK config item pending confirmation, see 02/04).
- IPv6-ification of the static table `ff_rss_tbl` and the portrange structures (whether to add a new v6 table versus a union is a tradeoff left to 04).
- Family/IPv6 overload or new function for `ff_rss_check` / `ff_rss_tbl_get_portrange`.
- Hookup in the kernel `netinet6/in6_pcb.c` port-selection flow (**entirely new; 13.0 also has none**).

### 2.4 Out of Scope
- No impact on and no regression of the existing IPv4 fast path and static-table layout.
- 0.2 is a "brand-new capability", not a "13.0 back-port" (differs in nature from 0.1).

### 2.5 Acceptance Criteria
- The source port selected by a multi-queue IPv6 connect passes IPv6 RSS hash validation and lands in this queue.
- No regression in IPv4 path functionality/performance.
- New IPv6 unit/integration tests pass (real-machine criteria see M4 spec).

---

## 3. Requirement 0.3: Use `rte_thash_adjust_tuple()` to Optimize the Dynamic Computation of `ff_rss_check()`

### 3.1 Background
- Currently `ff_rss_check` (L2851) computes `toeplitz_hash` (L2883) in software for every candidate dport to determine whether it lands in this queue; `ff_rss_tbl_init` (L2598) even calls `ff_rss_check` for all 65536 dports one by one (L2690-2700) to pre-build the static table, incurring considerable overhead.
- The static table `ff_rss_tbl` is the fast path on a hit (better performance, must be **retained**); but the dynamic scenario that **misses** the static table still walks a per-port software scan, which is inefficient.
- DPDK 24.11.6 already provides the `rte_thash_*` reverse-tuple-adjustment capability: `rte_thash_init_ctx` (`dpdk/lib/hash/rte_thash.h:303`), `rte_thash_complete_matrix` (L256), `rte_thash_get_complement` (L380), `rte_thash_adjust_tuple` (L456). `lib/ff_dpdk_if.c:51` already `#include <rte_thash.h>` but uses none of the `rte_thash_*` symbols.

### 3.2 Goal
While **retaining the static `ff_rss_tbl` fast path**, for the dynamic-computation scenario that misses the static table, use `rte_thash_adjust_tuple()` (directly deriving a tuple/port that satisfies the target-queue constraint) to replace/augment the per-port software scan, interoperating with the FreeBSD source-port-selection flow, ensuring the selected port still satisfies the RSS queue-placement constraint.

### 3.3 In Scope
- Introduce `rte_thash_init_ctx` + `rte_thash_adjust_tuple` into the dynamic path (reta_sz aligned with `rss_reta_size` L133; key aligned with `rsskey`/`default_rsskey_40bytes` L92-121).
- Interoperate with `in_pcb_lport_dest`'s port-selection semantics (the selected port is verified to actually land in this queue).
- Retain the `ff_rss_tbl` static table and `ff_rss_check` software computation as the fast path/fallback.

### 3.4 Out of Scope
- The static table is not removed (the static table has better performance and is explicitly retained).
- The external configuration semantics of RSS key / reta_size are not changed.

### 3.5 Acceptance Criteria and Constraints
- The source port selected by the dynamic path, after independent `ff_rss_check` (software) recheck, still lands in this queue (**must not select the wrong queue**).
- No performance/behavior degradation on the static-table hit path.
- The key and reta_sz used by `rte_thash_adjust_tuple` strictly align with the actual NIC RSS configuration (symmetric key / reta_size, see 04 for details).
- Correct cooperation with the `in_pcb_lport_dest` port-selection flow after the 0.1 back-port.

---

## 3-bis. Requirement 0.4: Re-verification in `ff_rss_check` / `ff_rss_check6` Disabled by Default, Enabled Only as a Debug Option

### 3-bis.1 Background

After R-B/R-C (0.3 + 0.2) land, `ff_rss_adjust_sport` (`lib/ff_dpdk_if.c:3053`)/`ff_rss_adjust_sport6` (L3391), once `rte_thash_adjust_tuple` succeeds, **mandatorily** invoke `ff_rss_check` (L3104)/`ff_rss_check6` (L3436) once more for software recheck as a "zero-tolerance" backstop — the sport is only returned once the recheck passes; otherwise it proceeds to the next candidate. This hard-gate design aims to guard against selecting the wrong queue due to key/offset/desired_value derivation deviations.

However, actual testing (spec 10 / unit-test hitrate) found that:
- `rte_thash_adjust_tuple` internally uses `softrss_be` (big-endian linear Toeplitz), which is **not bit-for-bit equivalent** algorithmically/byte-order-wise to this repository's `toeplitz_hash` (`ff_dpdk_if.c:2548`, bit-shift, host-order) — the single-candidate equivalence rate is only ~22%-27%.
- Consequence: each connect reverse-derivation needs ~3-6 candidates on average before one passes the software-recheck backstop; every failed candidate additionally costs one extra `toeplitz_hash` computation (v4 12B / v6 36B full loop).
- This partially offsets the original intent of 0.3 (using reverse derivation to replace per-port software scanning in order to **cut cost**).

The industry (Linux RPS/RFS, DPDK documentation examples, Seastar/mTCP and other user-space stacks) **does not** perform a secondary software recheck after reverse derivation (see 03 for research details); this project's recheck hard gate is a "conservative safety net" introduced by R-B/R-C, which can be turned off as a debug option to realize the performance expectation of 0.3, while still retaining the failure fallback chain of "attempts exhausted → return -1 → in_pcb software scan" (`freebsd/netinet/in_pcb.c:904`, decoupled from 0.4).

### 3-bis.2 Goal

Introduce a runtime switch for "secondary software recheck after a successful adjust", **disabled by default** (performance-first); keep a debug path (allowing ops/dev to enable it to retain the current zero-tolerance semantics). Zero compile-time macros, zero interface signature changes, zero kernel-side changes, zero degradation of the existing R-A/R-B/R-C paths (except the controllable degradation of the recheck hard gate itself).

### 3-bis.3 In Scope

- `lib/ff_config.h`: add an `int recheck` field to `struct ff_rss_check_cfg` (L241).
- `lib/ff_config.c`: `rss_check_cfg_handler` (L932) adds parsing for the `"recheck"` name (following the `enable` pattern with `atoi`).
- `config.ini`: the `[rss_check]` section (L264-266) adds a `recheck=0` default line + a brief comment (debug hint).
- `lib/ff_dpdk_if.c`: `ff_rss_adjust_sport` (L3053-3114) reads `recheck` into a local variable at entry; the recheck `if` at `L3104` is gated by `recheck`; `ff_rss_adjust_sport6` (L3391-3446)/`L3436` mirrored. Function signatures/outer `for(tries)`/failure `-1` unchanged.
- `tests/unit/test_ff_dpdk_if.c`: add recheck=0 / recheck=1 dual-path test cases + microbench comparison; existing hitrate/equivalence tests explicitly inject `recheck=1` to keep the 100% queue-placement hard assertion.
- Performance baseline (spec 08): add recheck on/off comparison benchmarks (`example/rss_ct.c` real machine + unit-test microbench backstop).

### 3-bis.4 Out of Scope

- **No compile-time macro is introduced** (user decision: runtime switch in the same section/structure as `enable`, ops-friendly, no recompile needed).
- The signature/implementation of `ff_rss_check` / `ff_rss_check6` itself is not changed.
- The `ff_rss_check` (L2735)/`ff_rss_check6` (L3253) calls inside `ff_rss_tbl_init` / `ff_rss_tbl6_init`'s table-build scanning are not touched — this is a one-time O(R/Q) table-build routine, not a runtime hotpath per connect, and is out of scope for "re-verification overhead".
- The kernel-side `ff_rss_check` software branch at `freebsd/netinet/in_pcb.c:904` is not touched (the core of the R-A software path, decoupled from this change).
- The default value of `attempts` (still 16, controlled by `FF_RSS_THASH_ADJUST_ATTEMPTS`) is not changed.
- No new runtime logging is added (hot path); existing logging on degradation/init failure is retained.

### 3-bis.5 Acceptance Criteria

- **AC-04-1 (Safe by default)**: Starting with a pristine `config.ini` (without explicit `recheck=`), at runtime `ff_global_cfg.dpdk.rss_check_cfgs->recheck == 0`; after `adjust_tuple` succeeds, `ff_rss_adjust_sport[6]` **does not call** `ff_rss_check[6]` and returns 0 directly. Null-pointer guard: treated as 0 when `rss_check_cfgs == NULL`.
- **AC-04-2 (Debug-enable-able)**: With `config.ini` set to `recheck=1`, `ff_rss_adjust_sport[6]` maintains the R-B/R-C status quo (returns 0 only when adjust succeeds AND `ff_rss_check[6]==1` both pass), with the queue-placement hard assertion at 100%.
- **AC-04-3 (Failure fallback chain unchanged)**: In either recheck=0/1 state, once `adjust_tuple` exhausts all attempts / all candidates are exhausted → returns -1 → `in_pcb_lport_dest` software-scan fallback (same behavior as R-A).
- **AC-04-4 (Performance baseline)**: spec 10 provides an empirical comparison of recheck=0 vs recheck=1 (one group each for v4/v6):
  - Unit-test microbench: N=10000 calls to `ff_rss_adjust_sport[6]`, cumulative CLOCK_MONOTONIC time, **recheck=0 strictly < recheck=1** (with the ratio given).
  - Real machine (e.g. if virtio reta=0 never reaches the thash path, run only the microbench backstop and record the limitation): compare connection-establishment QPS and queue distribution.
- **AC-04-5 (Correctness boundary clarified)**: spec 04 / comments explicitly state: when recheck=0, RSS distribution is **slightly uneven** (some connects' sport hash may, via the NIC's actual RSS, land in a queue other than this one), but TCP/UDP connection correctness is unaffected (the port remains uniquely usable, the tuple remains valid, and kernel in_pcb lookup still locates the PCB by the 4-tuple).
- **AC-04-6 (IPv4/IPv6 zero regression with R-A/R-B/R-C)**: existing hitrate/equivalence unit tests pass fully after explicitly injecting `recheck=1`; config.ini adds only the `recheck=` line + comment, with no local test values carried into the commit.
- **AC-04-7 (git diff convergence)**: changes to `lib/ff_dpdk_if.c` are ≤10 lines added / 0 lines removed (v4 + v6 combined), without touching function signatures/outer control flow.

---

## 3-ter. Requirement 0.5: `IP_BIND_ADDRESS_NO_PORT` bind-then-connect RSS Port Selection Port

### 3-ter.1 Background

- References upstream commit `cb9b4d462a0cd8c47b6f514e2af0111cd26597b3` (f-stack upstream, based on 13.0, changes only `freebsd/netinet/in_pcb.c`, +9/-2, 3 hunks), release note "Support bind no port like linux's IP_BIND_ADDRESS_NO_PORT", from the same source as this batch's `ff_rss_check` optimizations (see 03 §5 for research details).
- **Typical usage / failure chain**: an application does `bind(local_addr, port=0)` followed by `connect(remote)`.
  - Native FreeBSD path: at `bind` time, the socket is immediately allocated an anonymous local port (`in_pcbbind` → `in_pcbbind_setup` → `in_pcb_lport`); this port selection is **not RSS-aware** (does not carry `INPLOOKUP_LPORT_RSS_CHECK`).
  - Subsequently at `connect`, because `inp->inp_lport` is already non-zero, connect takes the "port already assigned" branch (`in_pcbconnect:1377` else / `in_pcb.c` anonport=false), **bypassing** the R-A-back-ported RSS-aware port selection via `in_pcb_lport_dest(... INPLOOKUP_LPORT_RSS_CHECK)` (`in_pcb.c:1363-1366`).
  - Result: packets of that 4-tuple may, after NIC RSS, **land in a worker queue other than this one**, breaking the "reply lands on this core" premise of F-Stack's multi-process share-nothing model (same underlying scenario as 0.1, but the trigger path is at bind rather than connect).
- **Upstream fix semantics** (commit `cb9b4d462`, three hunks, based on 13.0, evidence see 02 §6-ter):
  - hunk1 (`in_pcbbind`): wrap the `in_pcbinshash` hash-insertion block with `#ifdef FSTACK if (inp->inp_lport != 0) { ... } #endif` — when binding a local addr with port=0, **do not insert into the hash** (i.e. do not pin down a port).
  - hunk2 (`in_pcbbind_setup`): wrap `if (lport==0) { in_pcb_lport(...); }` with `#ifndef FSTACK` — under FSTACK, do **not** allocate a port at bind time when bind(port=0), keeping `inp->inp_lport` at 0.
  - hunk3 (13.0 `in_pcbconnect_setup`): change `in_pcbbind_setup(...)` to `in_pcb_lport(inp, &laddr, &lport, cred, INPLOOKUP_WILDCARD)` — reselect the port at connect time.
- **Semantic alignment**: consistent with Linux's `IP_BIND_ADDRESS_NO_PORT` (introduced in Linux 4.2, `bind(addr,0)` does not reserve a port, deferring it to connect to select a port with the full 4-tuple); but F-Stack additionally adds **RSS queue-affinity constraints** on top of this — the deferred port selection at connect time takes the R-A `INPLOOKUP_LPORT_RSS_CHECK` path, and the selected port must land in this worker's queue.
- **Deployment constraint**: the local addr (vip) must be configured on the NIC managed by DPDK (`f-stack-x`, config.ini `[portN]` default), **not on `lo`** (lo goes through the kernel stack and does not pass through DPDK RSS).

### 3-ter.2 15.0 Landing Conclusion (Core, Already Verified, Line Numbers per Current Code)

Current 15.0 `freebsd/netinet/in_pcb.c` (already verified, see 02 §6-ter):

- `in_pcbbind` (L720): the `in_pcbinshash` block at L739-745 (with `__predict_false` + `MPASS(SO_REUSEPORT_LB)` + clearing `INADDR_ANY`/`inp_lport`/`INP_BOUNDFIB`) has **no FSTACK guard** → **hunk1 missing point**.
- `in_pcbbind_setup`: L1273 `if (*lportp != 0) lport = *lportp;`, L1275-1279 `if (lport == 0) { in_pcb_lport(... lookupflags); }` has **no `#ifndef FSTACK`** → **hunk2 missing point**.
- Connect path: 15.0 no longer has a separate `in_pcbconnect_setup` (merged into `in_pcbconnect` L1294); L1313 `anonport = (inp->inp_lport == 0)`; L1363-1366 the anonport branch already uses `in_pcb_lport_dest(... INPLOOKUP_WILDCARD | INPLOOKUP_LPORT_RSS_CHECK)` (FSTACK-guarded L1365-1366); L1377 else uses the already-allocated port. **hunk3 is already equivalently present in 15.0, no change needed**.
- **Failure chain**: port allocated during bind → `inp_lport ≠ 0` → connect L1313 `anonport = false` → takes the L1377 else branch, bypassing RSS.

**Landing conclusion**: 15.0 only needs to add **hunk1** (`in_pcbbind` L739-745 hash-insertion block wrapped with `if (inp->inp_lport != 0)`) + **hunk2** (`in_pcbbind_setup` L1275-1279 wrapped with `#ifndef FSTACK`), so that after `bind(addr, 0)`, `inp_lport = 0` → connect naturally enters `anonport=true` → the `INPLOOKUP_LPORT_RSS_CHECK` branch. Estimated v4 change: `+8` lines.

### 3-ter.3 IPv6 Symmetry (Important, Already Verified)

- 13.0-baseline `in6_pcb.c` has no FSTACK; this capability simply **did not exist** for v6 in 13.0; the reference commit also only changes v4.
- 15.0 `in6_pcb.c` has already added FSTACK: the `in6_pcbconnect` RSS branch at L515-527 (condition `IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr) && inp->inp_lport == 0`, using `INPLOOKUP_LPORT_RSS_CHECK` at L521); but `in6_pcbbind` (L306)'s L354 `if (lport == 0) { in6_pcbsetport(...); }` allocates the port ahead of time (`in6_pcbsetport` → `in_pcb_lport`, no RSS_CHECK), and L361-369 else directly calls `in_pcbinshash` to insert into the hash.
- **v6 failure chain**: after binding a v6 local addr, `in6p_laddr` is non-unspecified **and** `inp_lport ≠ 0` → both conditions at connect L515 are broken → bypasses RSS. **The v6 bind-then-connect path is likewise not closed**, and needs to be ported in sync (`in6_pcbbind` deferred allocation + hash-insertion gating), falling under the brand-new-for-15.0 category (no 13.0 diff to copy), estimated `in6_pcb.c` change `+6~10` lines.

### 3-ter.4 Goal

1. **v4 (mandatory)**: Add hunk1 + hunk2 (`#ifdef FSTACK`/`#ifndef FSTACK` gates) to 15.0 `in_pcb.c`, so that after `bind(v4_addr, 0)`, connect enters the RSS-aware port-selection path, and the selected source port lands in this worker's queue; aligned with Linux `IP_BIND_ADDRESS_NO_PORT` + RSS affinity semantics.
2. **v6 (recommended in sync, brand-new design)**: symmetrically modify 15.0 `in6_pcb.c`'s `in6_pcbbind` (deferred port allocation + hash-insertion gating), so that after `bind(v6_addr, 0)`, connect enters the L515 RSS branch. **Marked as a brand-new design for 15.0 (no 13.0 diff to copy)**.

### 3-ter.5 In Scope

- `freebsd/netinet/in_pcb.c`: `in_pcbbind` (L720, hash-insertion block gating) + `in_pcbbind_setup` (L1275-1279, port-allocation gating).
- `freebsd/netinet6/in6_pcb.c`: `in6_pcbbind` (L306, L354 port allocation + L361-369 hash-insertion gating) — the v6 synchronization item.
- All `#ifdef FSTACK`/`#ifndef FSTACK` gates, minimal intrusion; reuses the connect-time `INPLOOKUP_LPORT_RSS_CHECK` path already provided by R-A (no new user-space interfaces).
- bind-then-connect functional/regression testing (v4 mandatory, v6 recommended in sync).

### 3-ter.6 Out of Scope

- The user-space `ff_rss_*` interface signatures are not changed (this feature is purely internal gating adjustments in `in_pcbbind`/`in6_pcbbind` in the kernel, reusing R-A's connect-time RSS path).
- The connect path is not changed (hunk3 is already equivalently present on 15.0, L1363-1366 / in6 L515-527).
- No new socket option parsing is introduced (F-Stack reuses the existing RSS switch, and the behavior applies to all bind(addr,0) calls; whether a per-socket `IP_BIND_ADDRESS_NO_PORT` setsockopt semantic is needed is left pending confirmation, see §3-ter.8).
- The direct-connect scenarios already covered by 0.1~0.4 are not included in this requirement (this requirement only closes the bind-then-connect unclosed path).

### 3-ter.7 Acceptance Criteria

- **AC-05-1 (v4 bind does not pre-allocate a port)**: With FSTACK enabled + `rss_check` multi-queue, after `bind(v4_addr, 0)` returns success, `inp->inp_lport == 0` (the port has not been pinned down at bind time); the socket is not inserted into the hash (does not occupy port space).
- **AC-05-2 (v4 connect takes the RSS path)**: When the above socket `connect`s, `anonport == true` (L1313) → takes `in_pcb_lport_dest(... INPLOOKUP_LPORT_RSS_CHECK)` (L1363-1366) → the selected source port, after independent `ff_rss_check` verification, **lands in this worker's queue**.
- **AC-05-3 (v6 in sync)**: after `bind(v6_addr, 0)`, `inp->inp_lport == 0` and `in6p_laddr` is still set per bind; at connect it enters the L515 RSS branch (the actual condition of `IN6_IS_ADDR_UNSPECIFIED` and `inp_lport==0` is subject to coding-phase verification, see §3-ter.8) → the source port, after `ff_rss_check6` verification, lands in this queue.
- **AC-05-4 (Zero regression for bind with a specified port)**: `bind(addr, port=N)` (N≠0) behavior is **completely unchanged** — the port is still pinned down at bind time, and the socket is still inserted into the hash normally (hunk1/hunk2 gating only applies to the `lport == 0` branch).
- **AC-05-5 (Zero regression with FSTACK disabled / single queue)**: with FSTACK disabled, compilation succeeds and bind/connect fall back to native FreeBSD behavior; with `rss_check` enable=0 or single queue, the connect-time RSS branch automatically degrades (`ff_rss_check` returns 1 when nb_queues<=1).
- **AC-05-6 (REUSEPORT_LB compatibility)**: bind(addr,0) behaves correctly for sockets with `SO_REUSEPORT_LB` enabled (hunk1 gating does not break the existing L740 `MPASS(SO_REUSEPORT_LB)` semantics, see §3-ter.8 pending confirmation).
- **AC-05-7 (local addr configuration constraint)**: when the vip (local addr) is configured on a DPDK NIC (`f-stack-x`), queue placement takes effect; when configured on `lo`, it goes through the kernel stack and bypasses RSS (expected, documented explicitly).

### 3-ter.8 Pending Confirmation Items (to be verified at coding time, no speculation)

- 【Pending confirmation】After hunk1's gate `if (inp->inp_lport != 0)` wraps the L739-745 hash-insertion block, the interaction with L740's `MPASS(inp->inp_socket->so_options & SO_REUSEPORT_LB)` — the structure of this block differs between upstream 13.0 and 15.0 (15.0 includes an `in_pcbinshash` failure rollback), so the gate placement must be precise: "skip inshash when `lport==0`, keep current behavior when `lport!=0`"; re-verify the hunk adaptation at coding time (02 §6-ter).
- 【Pending confirmation】After hunk2 wraps 15.0's `in_pcbbind_setup` (L1275-1279) with `#ifndef FSTACK`, whether keeping `lport` at 0 under FSTACK affects the downstream use of L1280-1281 `*laddrp = laddr.s_addr; *lportp = lport;` (writing lport=0 back into inp_lport), and how `in_pcbbind` (L735-748) handles `inp->inp_lport==0 + anonport` (L746-747 `INP_ANONPORT`).
- 【Pending confirmation】The exact modification for v6 `in6_pcbbind` (L354/L361-369) deferred allocation — v6 has no 13.0 diff to copy, so must mimic the v4 hunk1/hunk2 design of "skip in6_pcbsetport + skip in_pcbinshash when lport==0", while ensuring the connect L515 condition (`in6p_laddr` non-unspecified but `inp_lport==0`) can enter the RSS branch (i.e. bind still sets in6p_laddr but not lport).
- 【Pending confirmation】Whether a per-socket `IP_BIND_ADDRESS_NO_PORT` setsockopt is needed (Linux explicitly opts in per-socket) vs F-Stack applying it implicitly to all `bind(addr,0)` calls — the upstream commit is implicit (under FSTACK, all bind(addr,0) calls are deferred); this project leans toward following the upstream implicit semantics, and whether an explicit option is needed is left to a coding-phase/product decision.

---

## 4. Summary of the Relationships Between the Five Requirements

| Requirement | Nature | User-space change | Kernel-space change | IPv6 |
|------|------|------------|------------|------|
| 0.1 | Back-port (existed in 13.0, missing in 15.0) | None (interfaces already exist and are retained) | Back-port FSTACK RSS hooks in `in_pcb.c` | No (IPv4) |
| 0.2 | Brand new (absent even in 13.0) | IPv6-ify hash/table structures/interfaces | New hookup in `in6_pcb.c` | Yes |
| 0.3 | Optimization (dynamic path) | Introduce `rte_thash` in the `ff_rss_check` dynamic path | Coordination with 0.1 hookup | Extends with 0.2 |
| 0.4 | Incremental optimization (runtime switch) | Add `recheck` to `ff_rss_check_cfg`; gate the recheck in the reverse functions `ff_rss_check[6]` | None | v4/v6 symmetric |
| 0.5 | Back-port (existed for v4 in 13.0, missing in 15.0; brand new for v6) | None (reuses R-A connect-time RSS path, no user-space interface change) | Gating deferred allocation in `in_pcbbind`/`in_pcbbind_setup`; `in6_pcbbind` in sync (brand-new design for v6) | v4 mandatory + v6 recommended in sync |

> Relationship between 0.5 and 0.1: 0.1 (R-A) fills in the RSS port selection for the **direct connect** period; 0.5 (R-E) fills in the unclosed branch of **bind(addr,0)-then-connect**, where bind pre-allocates the port and bypasses the 0.1 path. 0.5 reuses the connect-time `INPLOOKUP_LPORT_RSS_CHECK` path already landed by 0.1, and only needs bind to "not grab the port ahead of time" for connect to naturally take the RSS path.

---

## 5. Pending Confirmation Items (to be verified in subsequent M2/coding phase)

- 【Pending confirmation】After 15.0's `in_pcbconnect` (L1083) merges 13.0's `in_pcbconnect_setup`, the exact insertion point of the `ff_in_pcbladdr` hookup relative to the ordering/conditions of the native `in_pcbladdr` (L1129).
- 【Pending confirmation】The RSS offload field on the DPDK/NIC side that needs to be enabled for IPv6 RSS hash (`RTE_ETH_RSS_IPV6` / `RTE_ETH_RSS_NONFRAG_IPV4_TCP` etc.) and its alignment with the existing port configuration.
- 【Pending confirmation】Whether the symmetric-RSS-key assumption required by 0.3's `rte_thash_adjust_tuple` is consistent with the current NIC's `default_rsskey_40bytes` (L92); feasibility of reverse-derivation under an asymmetric key.
