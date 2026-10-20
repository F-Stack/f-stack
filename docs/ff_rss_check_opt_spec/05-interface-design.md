# 05 Interface Design — ff_rss_check Three Optimizations

> Principle: for each interface, give the "signature/contract/compatibility"; based on the existing code signatures (`file:line`); new items are marked "new", changed items give a before/after comparison; unresolved items are marked "pending confirmation".
> Compatibility overview: **zero regression on the existing IPv4 path** — existing interface signatures remain unchanged across the board (IPv6 uses new functions); kernel hooks are all gated by `#ifdef FSTACK`.

---

## 1. User-Space lib API (`lib/ff_dpdk_if.c` / `lib/ff_api.h`)

### 1.1 Existing Interfaces (Reused by 0.1, Signatures Unchanged)

| Interface | Signature (current state, file:line) | 0.1 impact |
|------|------------------------|----------|
| `ff_rss_check` | `int ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)` (`ff_dpdk_if.c:2929`) | **Unchanged**, called directly by the kernel back-port |
| `ff_rss_tbl_get_portrange` | `int ff_rss_tbl_get_portrange(uint32_t saddr, uint32_t daddr, uint16_t sport, u_short *first, u_short *last, u_short **portrange)` (`ff_dpdk_if.c:2850`, signature based on the existing one) | **Unchanged** |
| `ff_rss_tbl_set_portrange` | `int ff_rss_tbl_set_portrange(uint16_t first, uint16_t last)` (`ff_dpdk_if.c:2791`) | **Unchanged** |
| `ff_rss_tbl_init` | `int ff_rss_tbl_init(void)` (`ff_dpdk_if.c:2649`) | **Unchanged** |
| `ff_in_pcbladdr` | `int ff_in_pcbladdr(uint16_t family, void *faddr, uint16_t fport, void *laddr)` (`ff_dpdk_if.c:2622`) | **Unchanged** (already supports AF_INET/AF_INET6_FREEBSD, L2630-2635) |
| `ff_regist_pcblddr_fun` | `void ff_regist_pcblddr_fun(pcblddr_func_t func)` (`ff_dpdk_if.c:2643`) | **Unchanged** |

> Contract: `ff_rss_check` returns 1=lands in the local queue/0=does not; always returns 1 when `nb_queues<=1` (`ff_dpdk_if.c:2936`). `ff_rss_tbl_get_portrange` returns 0 and fills the port set on a hit, returns `-ENOENT` on a miss, and returns <0 when disabled/on error.
> 【Pending confirmation: the exact existing signature of `ff_rss_tbl_get_portrange` (parameter types/count) is based on the actual state at `ff_dpdk_if.c:2850`; during coding, integrate against the existing prototype — this table's assumption follows the 13.0 call form at L805-806.】

### 1.2 New Interfaces (0.2 IPv6, Approach A)

> All are **new**, changing none of the existing IPv4 interfaces (IPv4 zero regression). Exported in sync via `ff_api.h` (if it needs to be called from the kernel side).

```c
/* New: IPv6 RSS queue-landing determination, the v6 counterpart of ff_rss_check */
int ff_rss_check6(void *softc, const struct in6_addr *saddr6,
                  const struct in6_addr *daddr6, uint16_t sport, uint16_t dport);

/* New: IPv6 static-table port-range lookup, the v6 counterpart of ff_rss_tbl_get_portrange */
int ff_rss_tbl6_get_portrange(const struct in6_addr *saddr6,
                  const struct in6_addr *daddr6, uint16_t sport,
                  u_short *first, u_short *last, u_short **portrange);

/* New: IPv6 static-table set/init (if an independent v6 table is needed) */
int ff_rss_tbl6_set_portrange(uint16_t first, uint16_t last);
int ff_rss_tbl6_init(void);
```

- Contract (aligned with v4): `ff_rss_check6` returns 1/0, and returns 1 when `nb_queues<=1`; the hash input layout is `saddr6(16)+daddr6(16)+sport(2)+dport(2)=36B`, and the queue-landing determination formula is the same as v4 (`(hash & (reta_size-1)) % nb_queues == queueid`).
- Compatibility: purely new symbols, no impact on v4; when IPv6 RSS is not enabled, these functions may never be called (kernel side is `#ifdef FSTACK` and only triggered by v6 socket paths).
- Implementation note: the hash soft computation reuses `toeplitz_hash` (`ff_dpdk_if.c:2599`, byte-stream based, family-agnostic), only the input data layout differs.
- 【Pending confirmation: whether `ff_rss_check6` needs a `family` parameter vs. an independent function name — leaning toward an independent function name `*6` (more explicit, avoids v4-branch overhead); the final decision will be made based on coding and the convenience of the kernel call sites.】

### 1.3 New Interfaces (0.3 rte_thash Dynamic Path)

> Mainly for internal use (`static`); if not needed to be visible to the kernel side, not exported in `ff_api.h`.

```c
/* thash ctx / diag (initialization phase). Based on actual code:
 * ff_rss_thash_ctx_init takes no parameters, returns int, and is only used by the primary
 * process at startup to read back the NIC key/RETA for cross-checking (diagnostics);
 * building/publishing KEY_FINAL is handled by ff_rss_thash_build_key. */
int ff_rss_thash_build_key(uint16_t port_id, uint16_t reta_size); /* ff_dpdk_if.c:3016 */
int ff_rss_thash_ctx_init(void);                                  /* ff_dpdk_if.c:3177 */

/* Dynamically reverse-compute a source port that lands in the local queue (runtime, adjust_tuple
 * is thread-safe).
 * Returns 0 on success and fills *out_sport (host order), <0 on failure (the caller falls back to
 * the soft-computation scan).
 * Note: first/last are the temporary port range passed in by the caller (in_pcb.c); the
 * reverse-computation result is constrained to fall within [first,last] (see §3-bis.4 and 04 §3.3). */
int ff_rss_adjust_sport(void *softc, uint32_t saddr, uint32_t daddr,
                  uint16_t dport, uint16_t *out_sport,
                  uint16_t first, uint16_t last);          /* v4, ff_dpdk_if.c:3242 */
int ff_rss_adjust_sport6(void *softc, const uint8_t *saddr6,
                  const uint8_t *daddr6, uint16_t dport,
                  uint16_t *out_sport,
                  uint16_t first, uint16_t last);          /* v6, ff_dpdk_if.c:3681 */
```

> Notes (based on actual code, correcting the earlier statement of "signature unchanged/no range parameters"):
> - `ff_rss_adjust_sport[6]` **has two new parameters `uint16_t first, uint16_t last`** (the temporary port range), passed in by the caller `in_pcb.c` (see §2.1, L962-964 / L899-901). During reverse-computation, the candidate port is aligned to a reta_size-aligned block within `[first,last]` (`ff_dpdk_if.c:3293-3302`), and after solving for the port, it is defensively verified to fall within `[first,last]` (`ff_dpdk_if.c:3352`).
> - The v6 address parameter type is `const uint8_t *saddr6/daddr6` (not `struct in6_addr *`), consistent with `in_pcb.c` passing `s6_addr`.
> - Both are no longer `static` (externally visible within `ff_dpdk_if.c`, for the kernel-side `in_pcb.c` to call).

- thash ctx lifecycle (based on actual code, `ff_dpdk_if.c` `ff_rss_thash_build_key`):
  - **The ctx is built by `ff_rss_thash_build_key` (`ff_dpdk_if.c:3016`) before `dev_configure`**: the primary process calls `rte_thash_init_ctx(name, orig_rsskey_len, reta_log2, ...)` to build the v4 ctx, `rte_thash_add_helper(ctx, "sport", FF_RSS_THASH_SPORT_HELPER_LEN=16, FF_RSS_THASH_V4_SPORT_OFF)`; the v6 ctx is seeded serially from the v4-rewritten key, then `add_helper(... FF_RSS_THASH_V6_SPORT_OFF)`. The secondary process uses `rte_thash_find_existing`.
  - **sport helper bit offsets (actual constants, correcting the earlier statement of 64/256)**: `FF_RSS_THASH_V4_SPORT_OFF = 80` (v4; under reply semantics, the local port falls in the dstPort field byte10=bit80), `FF_RSS_THASH_V6_SPORT_OFF = 272`; helper length `FF_RSS_THASH_SPORT_HELPER_LEN = 16`. **Built during initialization, read-only at runtime**.
  - After build_key completes, KEY_FINAL is published to the global `rsskey` (starting at `ff_dpdk_if.c:3159`), programmed into the NIC by the caller's `dev_configure`; `ff_rss_thash_ctx_init()` (`ff_dpdk_if.c:3177`, primary only) reads back the NIC key/RETA after startup for diagnostic cross-checking, **no longer** doing a post-start `rss_hash_update`.
  - Per-port storage: `static struct rte_thash_ctx *rss_thash_ctx[RTE_MAX_ETHPORTS]` / `rss_thash6_ctx[...]` + corresponding helper pointer arrays + `rss_thash_ready[]` / `rss_thash6_ready[]`.
- `ff_rss_adjust_sport` contract (based on actual code):
  1. Aligns the candidate port to a reta_size-aligned block within the caller-supplied temporary port range `[first,last]` (`ff_dpdk_if.c:3293-3302`), randomly choosing an aligned base.
  2. Computes `desired ∈ { v | v % nb_queues == queueid, v < reta_size }` (rotating through them to pick one).
  3. Constructs the tuple in **reply (inbound SYN-ACK) field order** (remote IP / local IP / dport=80 / localPort), with the local port falling in the field pointed to by the sport helper.
  4. Calls `rte_thash_adjust_tuple(ctx, h, tuple, tuple_len, desired & (reta_size-1), FF_RSS_THASH_ADJUST_ATTEMPTS=16, NULL, NULL)` (`rte_thash.h`); on success, extracts the solved port from the tuple.
  5. **`[first,last]` range guard** (`ff_dpdk_if.c:3352`): if out of range, advance to the next candidate.
  6. recheck branching (04 §3-bis): with `recheck==0` (default) return directly; with `recheck==1` (debug) return only after also confirming `ff_rss_check(softc, saddr, daddr, dport, sport)==1` in reply field order.
  7. When all candidates are exhausted → returns <0, and the caller (kernel `in_pcb.c`) falls back to the soft-computation scan.
- Compatibility: if ctx construction/publishing fails, the whole thing degrades to route ② soft computation (equivalent to 0.1), without affecting existing functionality. thash reverse-computation + KEY_FINAL publishing is gated by the `thash_adjust` switch (§3-ter), decoupled from `rss_check.enable`.
- **Diagnostic gating**: `ff_rss_diag_dump_key` and other key/RETA hex-dump diagnostics are gated by the compile-time macro **`FF_RSS_DIAG`, disabled by default, not affecting the data plane** (`ff_dpdk_if.c:3146-3156` etc. under `#ifdef FF_RSS_DIAG`).

### 1.4 Table Structure Changes/Additions

```c
/* Existing, untouched by 0.1/0.3 (IPv4 fast-path zero regression): ff_dpdk_if.c:155-172 */
struct ff_rss_tbl_dip_type { uint32_t daddr; ...; };
struct ff_rss_tbl_type    { uint32_t saddr; ...; };

/* New for 0.2 (Approach A, v6-independent table): */
struct ff_rss_tbl6_dip_type {
    struct in6_addr daddr6;   /* 16B */
    uint16_t first, last, first_idx, last_idx, num;
    uint16_t dport[FF_RSS_TBL_MAX_DPORT + 1];
} __rte_cache_aligned;
struct ff_rss_tbl6_type {
    struct in6_addr saddr6;   /* 16B */
    uint16_t sport, num;
    struct ff_rss_tbl6_dip_type dip_tbl[FF_RSS_TBL_MAX_DADDR];
} __rte_cache_aligned;
static struct ff_rss_tbl6_type ff_rss_tbl6[FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES];
```
- Contract: the v6 table exists in parallel with the v4 table without affecting each other. Capacity macros follow v4 (`ff_config.h:62-76`) or define separate `FF_RSS_TBL6_*` macros 【pending confirmation, 04 §2.2】.

---

## 2. Kernel Hook Contracts (`freebsd/netinet/in_pcb.c` / `in6_pcb.c` / `in_pcb.h`)

> All gated by `#ifdef FSTACK`; disabling FSTACK reverts to native behavior (no regression).

### 2.1 `in_pcb_lport_dest` (`in_pcb.c:756`) — 0.1 Back-Port + 0.3 Attachment Point

- **Signature unchanged** (`const struct inpcb *inp, ...`, L756-758); the back-ported logic must not modify the content pointed to by `inp` (const).
- Entry contract:
  - `rss_check_flag = lookupflags & INPLOOKUP_LPORT_RSS_CHECK;` followed immediately by `lookupflags &= ~INPLOOKUP_LPORT_RSS_CHECK;` (clearing, to avoid polluting downstream lookups, corresponding to 13.0 L712).
- Behavioral contract:
  - Static-table hit (`ff_rss_tbl_get_portrange` returns 0): rotate `*lportp` through the port set that lands in the local queue.
  - Miss: 【0.3】first try `ff_rss_adjust_sport` (reverse-computation); on failure fall back to the per-port `ff_rss_check` soft-computation scan (13.0 L896-911 form).
  - LOOPBACK: break directly (no RSS applied, 13.0 L902-903), ensuring `127.0.0.1` works normally.
- Lookup calls aligned with the 15.0 signature: `in_pcblookup_local(..., RT_ALL_FIBS, lookupflags, cred)` (L877), `in_pcblookup_hash_locked(..., M_NODOM, RT_ALL_FIBS)` (L848) — the back-ported code reuses the existing calls, without reverting to the 13.0 signature.
- IPv6 (0.2): in this function's INET6 branch (L818-826/L851-872), use `laddr6/faddr6` to call `ff_rss_check6`/`ff_rss_tbl6_get_portrange` (call chain pending confirmation, 04 §2.3).

### 2.2 `in_pcbconnect` (`in_pcb.c:1083`) — 0.1 Address Integration + Flag Passing

- **Signature unchanged** (`struct inpcb *inp, struct sockaddr_in *sin, struct ucred *cred`, L1083).
- Change point 1 (local address, corresponding to 13.0's `in_pcbconnect_setup` L1526-1530): inside the `in_nullhost(inp->inp_laddr)` branch (L1128), before calling native `in_pcbladdr` (L1129), insert `ff_in_pcbladdr(AF_INET, &faddr, sin->sin_port, &laddr)` under `#ifdef FSTACK`; contract: on success, use the filled `laddr`; on failure/if the callback is unregistered (`pcblddr_fun==NULL` returns 0, `ff_dpdk_if.c:2627-2628`), continue with native `in_pcbladdr`.
- Change point 2 (flag, corresponding to 13.0 L1583-1589): when calling `in_pcb_lport_dest` (L1145-1147) in the `anonport` branch, change lookupflags from `INPLOOKUP_WILDCARD` to `#ifdef FSTACK INPLOOKUP_WILDCARD | INPLOOKUP_LPORT_RSS_CHECK #else INPLOOKUP_WILDCARD #endif`.
- 【Pending confirmation: the exact insertion location of change point 1, 04 §5.1.】

### 2.3 The `INPLOOKUP_LPORT_RSS_CHECK` Macro (`in_pcb.h:623-625`)

- **Maintain the status quo**: `#ifdef FSTACK #define INPLOOKUP_LPORT_RSS_CHECK 0x80000000 #endif` (value unchanged, kept outside the enum, not included in `INPLOOKUP_MASK` L627).
- Contract: only consumed and cleared at the entry of `in_pcb_lport_dest` (§2.1); downstream `in_pcblookup_*` is unaware of it.
- Decision rationale see 04 §1.3 (the alternative of "including it in MASK" is not recommended).

### 2.4 IPv6 Kernel Integration (`in6_pcb.c`, 0.2 Brand New)

- 【Integration point pending confirmation, 04 §2.3】Leaning: if `in6_pcbconnect` reuses `in_pcb_lport_dest` for port selection, then
  - pass `INPLOOKUP_LPORT_RSS_CHECK` at the port-selection call site in `in6_pcbconnect`;
  - at the local-address selection point in `in6_pcbconnect`, call `ff_in_pcbladdr(AF_INET6_FREEBSD, &faddr6, fport, &laddr6)` under `#ifdef FSTACK` (`ff_in_pcbladdr` already supports v6, `ff_dpdk_if.c:2632-2635`).
- If there is an independent path, then create an equivalent hook in `in6_pcb.c` (following §2.1's logic, calling the v6 interfaces).
- All gated by `#ifdef FSTACK`; when v6 is unavailable it is not triggered, and IPv4 is unaffected.

### 2.5 `in_pcbbind` / `in_pcbbind_setup` / `in6_pcbbind` (0.5 bind no port) — Internal Gating Adjustment, No New Interfaces

- **No new user-space interfaces**: 0.5 is purely a kernel-side bind-path gating adjustment, **reusing** the connect-time RSS port selection already present via R-A (`in_pcb_lport_dest(... INPLOOKUP_LPORT_RSS_CHECK)`, v4 `in_pcb.c:1363-1366` / v6 `in6_pcb.c:515-527`); the user-space `ff_rss_*` interface signatures **are all unchanged**.
- **No socket interface signature changes**: `in_pcbbind` (`in_pcb.c:720`), `in_pcbbind_setup`, `in_pcbconnect` (L1294), `in6_pcbbind` (`in6_pcb.c:306`), `in6_pcbconnect` function signatures **all remain unchanged** — only body-internal `#ifdef FSTACK`/`#ifndef FSTACK` gating adjustments.
- **Internal contract adjustments** (behavioral contract, not signature):
  - `in_pcbbind` (v4): under FSTACK, `bind(addr, port=0)` does **not** allocate a port at bind time, does **not** enter the hash, and returns success with `inp->inp_lport == 0`; the contract for `bind(addr, port=N)` (N≠0) is unchanged.
  - `in_pcbbind_setup` (v4): under FSTACK, the `lport==0` branch skips `in_pcb_lport` (hunk2), and `*lportp` is written back as 0; `lport!=0` is unchanged.
  - `in6_pcbbind` (v6): under FSTACK, `bind(v6_addr, port=0)` skips `in6_pcbsetport` + skips `in_pcbinshash`, returning success with `inp->inp_lport == 0` (the handling of in6p_laddr is per the path choice in 04 §3-ter.4).
- **Connect contract (unchanged, reused)**: `in_pcbconnect` (L1313 `anonport=(inp_lport==0)`) / `in6_pcbconnect` (L515-516) enters the RSS branch because bind did not claim a port — 0.5 does not change connect, and relies only on bind's change to make `inp_lport==0` hold.
- **Gating**: all under `#ifdef FSTACK`/`#ifndef FSTACK`; disabling FSTACK reverts to native bind/connect (no regression).
- 【Pending confirmation: whether the v6 connect L515 entry condition needs to be relaxed (04 §3-ter.4 Path B); the exact adaptation of hunk1 to the 15.0 enter-hash block (which includes a failure rollback) (04 §3-ter.6).】

---

## 3. Configuration Item Changes (`lib/ff_config.{c,h}` / config.ini)

### 3.1 Existing (0.1 Unchanged)
- `[dpdk]` → `rss_check` section: `enable` + `rss_tbl` (`ff_config.c:923-953`).
- `rss_tbl` single-entry format: `port_id daddr saddr sport`, multiple entries separated by `;`; daddr/saddr parsed via `inet_pton(AF_INET,...)` (`ff_config.c:913-914`).
- Structure `struct ff_rss_check_cfg.rss_tbl_cfgs[FF_RSS_TBL_MAX_ENTRIES]` (`ff_config.h:242`).
- `symmetric_rss` (`ff_global_cfg.dpdk.symmetric_rss`, `ff_dpdk_if.c:750`): **already exists**, 0.3 does not add it, only documents its impact on thash reverse-computation (04 §3.4).

### 3.2 Changes (0.2 IPv6)
- `rss_tbl` parsing: `rss_tbl_cfg_handler` (`ff_config.c:880-921`) determines v6 by whether the daddr/saddr text contains `:`, going through `inet_pton(AF_INET6,...)` to parse into 16B; text without `:` continues to use `inet_pton(AF_INET,...)` (IPv4 format and behavior zero regression).
- Configuration structure: a single rule in `struct ff_rss_check_cfg` needs to be able to store a 16B address + a family marker (a new field or a v6 sub-structure). 【Pending confirmation: reuse the same structure with an added family union vs. add a separate v6 rule array — leaning toward adding a family + 16B union for storage, with parsing branching accordingly; to be decided during coding.】
- config.ini documentation: in the `rss_check.rss_tbl` comment, add an example noting "supports IPv6 text addresses (containing `:`)".
- Contract/compatibility: pure-IPv4 configuration file parsing results are unchanged; new support is added for mixed/pure-v6 configurations.

### 3.3 Submission Constraint (Mandatory Convention)
- config.ini should only submit changes related to this feature (such as `rss_check` section format explanations); **do not submit** local test values (`lcore_mask`/`portN` local machine IP/`idle_sleep`, etc.); review `git diff` item by item before submission (consistent with existing conventions).

---

## 3-bis. Requirement 0.4: Reverse-Path Recheck Runtime Switch

### 3-bis.1 `struct ff_rss_check_cfg` Field Addition (`lib/ff_config.h`)

Current state (L241-246):

```c
struct ff_rss_check_cfg {
    int enable;
    int nb_rss_tbl;
    char *rss_tbl_str;
    struct ff_rss_tbl_cfg rss_tbl_cfgs[FF_RSS_TBL_MAX_ENTRIES];
};
```

After the R-D change:

```c
struct ff_rss_check_cfg {
    int enable;
    int recheck;        /* 0=off (default, perf-first); 1=on (debug, R-B/R-C zero-tolerance) */
    int nb_rss_tbl;
    char *rss_tbl_str;
    struct ff_rss_tbl_cfg rss_tbl_cfgs[FF_RSS_TBL_MAX_ENTRIES];
};
```

- Field semantics:
  - `recheck == 0` (default): after `rte_thash_adjust_tuple` succeeds, `ff_rss_adjust_sport[6]` does **not call** `ff_rss_check[6]`, returning sport directly.
  - `recheck != 0` (debug, conventionally written as 1): maintains the R-B/R-C mandatory soft-computation recheck hard gate (only returns when `adjust_tuple` succeeds ∧ `ff_rss_check[6]==1`).
  - Null-pointer guard: when `ff_global_cfg.dpdk.rss_check_cfgs == NULL`, treat as 0.
- Compatibility: purely a field addition right after `enable`; `calloc(1, sizeof(...))` (`ff_config.c:941`) guarantees that when `recheck=` is not configured, the field's zero-init = 0 (consistent with the default semantics), with **zero regression** on existing IPv4/IPv6 paths.
- Field order: placed right after `enable` (same semantic category), clearly distinguished from the "table data" semantic category of `nb_rss_tbl`/`rss_tbl_str`/`rss_tbl_cfgs[]`.

### 3-bis.2 `rss_check_cfg_handler` Parsing Addition (`lib/ff_config.c:932`)

Current key excerpt (L949-958):

```c
struct ff_rss_check_cfg *cur = cfg->dpdk.rss_check_cfgs;

if (strcmp(name, "enable") == 0) {
    cur->enable = atoi(value);
} else if (strcmp(name, "rss_tbl") == 0) {
    cur->rss_tbl_str = strdup(value);
    if (cur->rss_tbl_str) {
        return rss_tbl_cfg_handler(cur);
    }
}

return 1;
```

R-D change: insert a `recheck` branch between `enable` and `rss_tbl` (mirroring the `enable` pattern):

```c
if (strcmp(name, "enable") == 0) {
    cur->enable = atoi(value);
} else if (strcmp(name, "recheck") == 0) {
    cur->recheck = atoi(value);
} else if (strcmp(name, "rss_tbl") == 0) {
    /* ... unchanged ... */
}
```

- Contract:
  - `recheck=0` → off (default).
  - `recheck=1` → on (debug).
  - Any other non-zero integer → equivalent to on (`atoi` tolerance), as noted in spec 04 §3-bis.7.
  - Configuration file without a `recheck=` line → the field remains at the calloc zero-init value of 0 (off by default).
- Compatibility: purely a new `else if` branch; parsing results for pure-IPv4 / existing `[rss_check]` configuration files are unchanged.

### 3-bis.3 `config.ini` `[rss_check]` Section Configuration Item Contract

Current state (L264-266):

```ini
[rss_check]
enable=0
rss_tbl=0 192.168.1.1 192.168.2.1 80;0 192.168.1.1 192.168.2.1 443
```

R-D change: append a `recheck=0` default line + a short comment after `enable=0` (comment line count kept to 3-5 lines, consistent with the existing project style):

```ini
[rss_check]
enable=0
# recheck: re-verify reversed sport with soft toeplitz_hash before returning.
#   0 (default) = perf-first, trust rte_thash_adjust_tuple result;
#   1 (debug)   = zero-tolerance, drop candidates that fail soft re-check.
# softrss_be vs toeplitz host-order have ~22-27% per-candidate equivalence;
# turn on only when investigating queue distribution skew (see spec 0.4).
recheck=0
rss_tbl=0 192.168.1.1 192.168.2.1 80;0 192.168.1.1 192.168.2.1 443
```

- Contract:
  - Configuration item name: `recheck` (lowercase, consistent with the `enable` style).
  - Value: `0` (default)/`1` (debug); other non-zero values are treated as on.
  - Default value: `0`.
  - Scope: the `[rss_check]` section, same section as `enable` / `rss_tbl`.
  - Is it required: no (defaults to 0 when omitted).
- Submission constraint (mandatory convention §3.3): only submit "the new `recheck=0` line + 3-5 lines of comment" for this change; **do not submit** any local test-state changes (`enable=1` / real-machine IPs for `rss_tbl` / other sections' lcore_mask / port IPs / vlan / idle_sleep, etc.). Review `git diff config.ini` item by item before submission.

### 3-bis.4 `ff_rss_adjust_sport` / `ff_rss_adjust_sport6` Behavioral Contract (`lib/ff_dpdk_if.c`)

Signature (based on actual code, including the `first,last` range parameters, see §1.3):

```c
int ff_rss_adjust_sport(void *softc, uint32_t saddr, uint32_t daddr,
        uint16_t dport, uint16_t *out_sport,
        uint16_t first, uint16_t last);                            /* ff_dpdk_if.c:3242 */
int ff_rss_adjust_sport6(void *softc, const uint8_t *saddr6,
        const uint8_t *daddr6, uint16_t dport, uint16_t *out_sport,
        uint16_t first, uint16_t last);                            /* ff_dpdk_if.c:3681 */
```

Behavioral contract (recheck branching):

- Read once at entry (avoiding repeated memory access within the loop + an early null-pointer guard):
  ```c
  int recheck = (ff_global_cfg.dpdk.rss_check_cfgs
                 ? ff_global_cfg.dpdk.rss_check_cfgs->recheck : 0);
  ```
- Within the main loop (`for (tries = 0; tries < ...; tries++)`), in the `rte_thash_adjust_tuple == 0` branch: first do the `[first,last]` range guard (`ff_dpdk_if.c:3352`, advance to the next candidate if out of range), then do the recheck branching. The recheck calls `ff_rss_check` in **REPLY (SYN-ACK) field order** (`ff_dpdk_if.c:3362-3363`):
  ```c
  /* recheck=0: trust adjust result; recheck=1 (debug): verify with soft hash.
   * Note the sport/dport swap in the reply tuple: srcPort=dport(80), dstPort=sport(localPort). */
  if (!recheck || ff_rss_check(softc, saddr, daddr, dport, sport)) {
      *out_sport = sport;
      return 0;
  }
  ```
  v6 symmetric (starting at `ff_dpdk_if.c:3681`).
- Failure fallback (in either state): when all `tries` are exhausted → `return -1` → the caller `in_pcb_lport_dest` falls back to the soft-computation scan (retained).
- Unchanged contract items: return-value semantics / the outer `for(tries)` control flow / `FF_RSS_THASH_ADJUST_ATTEMPTS=16` / failure `-1`. **Changed items**: new `first,last` parameters (see §1.3), and the recheck call uses reply field order.

### 3-bis.5 Compatibility Matrix Addendum (IPv4 / IPv6 / R-A/R-B/R-C Zero Regression)

| Scenario | recheck=0 behavior | recheck=1 behavior | Relationship to R-A/R-B/R-C |
|------|----------------|----------------|---------------------|
| `[rss_check]` enable=0 / single queue | Already guarded to return -1 by the nb_queues<=1 check before the reverse-path entry | Same as left | Existing R-A/R-B/R-C guards unchanged |
| Reverse-path hit (adjust succeeds) | Returns sport directly (does not call ff_rss_check) | Maintains the R-B/R-C mandatory recheck hard gate | recheck=1 is equivalent to the current R-B/R-C state |
| Reverse-path does not converge (attempts exhausted) | Advances to the next candidate; on total failure → -1 | Same as left | Fallback chain unchanged |
| `in_pcb_lport_dest` soft-computation scan | Fully retained | Fully retained | R-A fallback fully intact |
| Static-table init (L2735/L3253) | Fully retained | Fully retained | Table-construction basis unchanged |
| Existing hitrate unit tests | `recheck=1` injected to maintain the 100% hard assertion | Same as left | Test code must explicitly set recheck=1 |

### 3-bis.6 Kernel-Side Contract: No Change

- `freebsd/netinet/in_pcb.c` / `in_pcb.h` / `in6_pcb.c`: **0 changes** (0.4 is a user-space runtime switch; the kernel side is unaware of it).
- The R-A back-ported `INPLOOKUP_LPORT_RSS_CHECK` propagation is unchanged; the soft-computation branch at `in_pcb.c:904` is unchanged.

## 3-ter. Configuration Item Change: The `thash_adjust` Switch (R-F, Decoupled from `enable`)

- **Configuration item**: a new `thash_adjust` in the `[rss_check]` section (`struct ff_rss_check_cfg.thash_adjust`), default value `1`.
- **Semantics**: an independent switch for thash reverse-computation + NIC RSS key synchronization. `1` (default) = enable Route ① (retrieve the rewritten key, sync the global rsskey, upload via `rss_hash_update` to the NIC, taking effect under multi-queue); `0` = Route ②, going through the kernel-side soft scan only.
- **Gating scope**: `thash_adjust` gates the following calls, **decoupled from `rss_check.enable`**:
  - `ff_rss_thash_build_key` (`init_port_start`, multi-queue KEY_FINAL construction);
  - `ff_rss_thash_ctx_init` (thash diag readback, moved out of the `enable` block, independently gated by `thash_adjust`);
  - the route ② guard in `ff_rss_adjust_sport` / `ff_rss_adjust_sport6`.
  - `ff_rss_tbl_init` / `ff_rss_tbl6_init` still belong to `rss_check.enable`, unaffected by `thash_adjust`.
- **Null-pointer semantics**: when `ff_global_cfg.dpdk.rss_check_cfgs == NULL`, treat as `1` (i.e., on), consistent with historical default behavior.
- **Parsing and default**: `rss_check_cfg_handler` explicitly sets `rcc->thash_adjust = 1;` right after the first `calloc`, then overridden by a `thash_adjust=` line.
- **Submission constraint**: config.ini should only submit the new `thash_adjust=1` line + comment, and not submit local test values (consistent with §3.3).

---

## 4. Interface Compatibility Matrix (IPv4 Zero-Regression Verification)

| Interface/structure | Signature changed? | IPv4 path impact | Gating |
|-----------|------------|---------------|------|
| `ff_rss_check` / `ff_rss_tbl_*` (v4) | No | None | — |
| `ff_in_pcbladdr` | No (already supports v6) | None | — |
| `ff_rss_check6` / `ff_rss_tbl6_*` | New | None (independent symbol) | — |
| `ff_rss_adjust_sport[6]` / thash ctx | New static | None (degrades to soft computation on init failure) | — |
| `struct ff_rss_tbl_type` (v4) | No | None (layout untouched) | — |
| `struct ff_rss_tbl6_type` | New | None | — |
| `in_pcb_lport_dest` / `in_pcbconnect` | No (hooks added only in the body) | None with FSTACK off; with FSTACK on and rss enable=0/single queue, automatically goes native | `#ifdef FSTACK` |
| `INPLOOKUP_LPORT_RSS_CHECK` | No (status quo maintained) | None | `#ifdef FSTACK` |
| config `rss_tbl` parsing | Extended (v6 branch) | Pure v4 configuration unchanged | — |
| `struct ff_rss_check_cfg.recheck` (0.4) | New field | None (calloc zero-init = default 0) | — |
| config `[rss_check] recheck=` (0.4) | New ini item (default 0 + comment) | Behavior unchanged for pure v4 configurations that do not write this item | — |
| `ff_rss_adjust_sport[6]` (0.4) | Single-point gating within the body | Function signature/outer flow unchanged; skips the soft-computation recheck when recheck=0 | — |
| `in_pcbbind` / `in_pcbbind_setup` (0.5 v4) | No (gating in body only) | None with FSTACK off; bind(addr,N) unchanged; bind(addr,0) deferred allocation under FSTACK | `#ifdef/#ifndef FSTACK` |
| `in6_pcbbind` (0.5 v6) | No (gating in body only, brand new design) | None with FSTACK off; v6 bind(addr,0) deferred allocation under FSTACK | `#ifdef FSTACK` |
| `in_pcbconnect` / `in6_pcbconnect` (0.5) | No (unchanged, reuses the R-A RSS path) | Only bind's change makes anonport=true, causing it to enter the RSS branch | `#ifdef FSTACK` (existing) |
