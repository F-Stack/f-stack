# 02 Current State and Gap Analysis — ff_rss_check Three-Item Optimization

> Principle: All conclusions are based on actual code/header files, with `file:line` evidence; items of uncertainty are marked "Pending Confirmation".
> Files involved:
> - User space: `f-stack/lib/ff_dpdk_if.c`, `f-stack/lib/ff_config.{c,h}`, `f-stack/lib/ff_api.h`
> - Kernel 15.0: `f-stack/freebsd/netinet/in_pcb.c`, `in_pcb.h`, `netinet6/in6_pcb.c`
> - Kernel 13.0 baseline: `f-stack-13.0-baseline/freebsd/netinet/in_pcb.c`, `netinet6/in6_pcb.c`
> - DPDK: `dpdk-stable-24.11.6/lib/hash/rte_thash.h`
> - Tests: `f-stack/tests/unit/test_ff_dpdk_if.c`

---

## 1. Full Picture of the User-Space RSS Current State (`lib/ff_dpdk_if.c`)

### 1.1 Core Functions

| Function | Line | Purpose | Family |
|------|------|------|--------|
| `toeplitz_hash` | L2547-2568 | Software Toeplitz hash (emulates NIC RSS) | Byte-stream, input-agnostic |
| `ff_in_pcbladdr` | L2571-2589 | Local-address-selection callback bridge (calls `pcblddr_fun`) | AF_INET / AF_INET6_FREEBSD (L2579-2584) |
| `ff_regist_pcblddr_fun` | L2591-2595 | Registers the local-address-selection callback | — |
| `ff_rss_tbl_init` | L2598-2734 | Pre-builds the static table (calling `ff_rss_check` per dport) | IPv4-only |
| `ff_rss_tbl_set_portrange` | L2737-2793 | Narrows the port range within the table by first/last | IPv4-only |
| `ff_rss_tbl_get_portrange` | L2796-2848 | Looks up the table to get the set of dports landing in this queue for a given saddr/daddr/sport | IPv4-only (`uint32_t saddr/daddr`) |
| `ff_rss_check` | L2851-2886 | Determines whether a 4-tuple lands in this queue | IPv4-only (`uint32_t saddr/daddr`) |

### 1.2 Global Variables and the Static Table

- RSS key: `default_rsskey_40bytes[40]` (L92), `rsskey` (L121), `rsskey_len` (L120).
- `rss_reta_size[RTE_MAX_ETHPORTS]` (L133): reta size per port.
- Local-address callback: `pcblddr_fun` (L127, type `pcblddr_func_t`, defined in `ff_api.h:329`).
- Static-table instance: `ff_rss_tbl[FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES]` (L172).

### 1.3 Static Table Structure (Key IPv4-only Points)

```155:172:f-stack/lib/ff_dpdk_if.c
struct ff_rss_tbl_dip_type {
    uint32_t daddr;
    uint16_t first; /* The start port in portrange */
    uint16_t last; /* The end port in portrange */
    uint16_t first_idx; /* The idx of the start port in portrange */
    uint16_t last_idx; /* The idx of the end port in portrange */
    uint16_t num;
    uint16_t dport[FF_RSS_TBL_MAX_DPORT + 1]; /* [0] used as the idx of last seleted port */
} __rte_cache_aligned;

struct ff_rss_tbl_type {
    //enum ff_rss_tbl_init_type init;
    uint32_t saddr;
    uint16_t sport;
    uint16_t num;
    struct ff_rss_tbl_dip_type dip_tbl[FF_RSS_TBL_MAX_DADDR];
} __rte_cache_aligned;
```

- Table capacity macros (`lib/ff_config.h:62-76`): `FF_RSS_TBL_MAX_SADDR=4`, `MAX_SPORT=4`, `MAX_DADDR=4`, `MAX_DPORT=65536`, `MAX_SADDR_SPORT_ENTRIES=16`, `MAX_ENTRIES=64`.
- Key point: `saddr`/`daddr` are both `uint32_t`, which **cannot hold a 16-byte IPv6 address** → 0.2 must extend the structures.

### 1.4 `ff_rss_check` Hash-Input Layout (IPv4-only)

```2865:2885:f-stack/lib/ff_dpdk_if.c
    uint8_t data[sizeof(saddr) + sizeof(daddr) + sizeof(sport) +
            sizeof(dport)];
    ...
    bcopy(&saddr, &data[datalen], sizeof(saddr));  /* 4B */
    bcopy(&daddr, &data[datalen], sizeof(daddr));  /* 4B */
    bcopy(&sport, &data[datalen], sizeof(sport));  /* 2B */
    bcopy(&dport, &data[datalen], sizeof(dport));  /* 2B */
    hash = toeplitz_hash(rsskey_len, rsskey, datalen, data);
    return ((hash & (reta_size - 1)) % nb_queues) == queueid;
```

- Layout = `saddr(4)+daddr(4)+sport(2)+dport(2)` = 12 bytes; when `nb_queues<=1`, returns 1 directly (L2858-2860).
- Queue-placement determination: `(hash & (reta_size-1)) % nb_queues == queueid` (L2885).

### 1.5 Current State of User-Space Usage of `rte_thash`

- `#include <rte_thash.h>` (L51) is already present; but grepping for `rte_thash_*` in `ff_dpdk_if.c` shows **no symbol references at all** (include only). To be introduced by 0.3.

---

## 2. Detailed 13.0 ↔ 15.0 `in_pcb.c` Differences (Core of 0.1)

### 2.0 Overview of Function Naming/Signature Changes (per Code)

| Item | 13.0 baseline | Current 15.0 | Impact |
|----|---------------|-----------|------|
| Port-selection function | `in_pcb_lport_dest(struct inpcb *inp, ...)` (L689) | `in_pcb_lport_dest(const struct inpcb *inp, ...)` (L756) | Same name; `inp` gains `const`, the ported code must not modify inp |
| Connect setup function | `in_pcbconnect_setup(...)` (L1458) + `in_pcbconnect(struct inpcb*, struct sockaddr *nam, ...)` (L1228) | **Merged into** `in_pcbconnect(struct inpcb *inp, struct sockaddr_in *sin, struct ucred *cred)` (L1083) | The intermediate `_setup` layer in 13.0 disappears in 15.0; the `ff_in_pcbladdr` hookup point must move inside `in_pcbconnect` |
| `INPLOOKUP_*` | Plain `#define` | **Enum-ified** as `inp_lookup_t` (`in_pcb.h:616-621`) | `INPLOOKUP_LPORT_RSS_CHECK` still stays outside the enum as `#define 0x80000000` (`in_pcb.h:623-625`), needs care coexisting with the enum since `INPLOOKUP_MASK` (L627) does not include it |
| pcblookup signature | `in_pcblookup_local(pcbinfo, laddr, lport, lookupflags, cred)` (13.0 L894) | `in_pcblookup_local(pcbinfo, laddr, lport, RT_ALL_FIBS, lookupflags, cred)` (15.0 L877) | New `RT_ALL_FIBS` parameter; back-ported internal lookup calls must align with the 15.0 signature |
| INET6 port selection | 13.0's `in_pcb_lport_dest` already has an INET6 branch | 15.0's `in_pcb_lport_dest` likewise has an INET6 branch (L818-826, L851-872) | This function on 15.0 was already unified for v4/v6; 0.2 can extend within it |

### 2.1 FSTACK RSS Hooks Present in 13.0 but Missing in 15.0 (Section by Section)

#### (A) RSS Port-Selection Logic Inside `in_pcb_lport_dest` (Present in 13.0 / Entirely Missing in 15.0)

13.0-baseline `in_pcb.c`:

- Local declarations (L703-713): `rss_first/rss_last/*rss_portrange`, `rss_tbl_init`, `rss_check_flag = lookupflags & INPLOOKUP_LPORT_RSS_CHECK` (L707), `rss_match`, `ifaddr/ifnet`; and `lookupflags &= ~INPLOOKUP_LPORT_RSS_CHECK` (L712).
- Portrange retrieval (L794-830):
  - First calls `ff_rss_tbl_set_portrange(first, last)` to initialize (L797).
  - Calls `ff_rss_tbl_get_portrange(faddr.s_addr, laddr.s_addr, fport, &rss_first, &rss_last, &rss_portrange)` (L805-806) to obtain the set of ports landing in this queue; on a hit, sets `rss_match=1` (L812).
  - On a miss (`!rss_match`), computes `ifp` via `ifa_ifwithnet` (L819-829), for use by `ff_rss_check` software computation later.
- Main port-selection loop (L842-915):
  - On a static-table hit (`rss_check_flag && rss_match`, L846-851): rotates through `rss_portrange[]` to take `*lastport`; the port set already guarantees landing in this queue.
  - On a miss (`!rss_check_flag || !rss_match`, L853-860): falls back to native `++*lastport`.
  - Dynamic validation on a miss (L896-911): after `in_pcblookup_local` finds an available slot, breaks directly for LOOPBACK (L902-903); otherwise performs software `ff_rss_check(ifp->if_softc, faddr.s_addr, laddr.s_addr, fport, lport)` (L904-905) validation, breaking only when it lands in this queue, otherwise `tmpinp++` continues to the next port (L909).

Current 15.0 `in_pcb.c` `in_pcb_lport_dest` (L756-886): **all of the above FSTACK sections are absent**, retaining only the native port-selection loop (L835-881), with no `rss_*` variables, no `ff_rss_*` calls, and no parsing of `INPLOOKUP_LPORT_RSS_CHECK`.

#### (B) `ff_in_pcbladdr` + `INPLOOKUP_LPORT_RSS_CHECK` Hookup in the Connect Flow (Present in 13.0 / Entirely Missing in 15.0)

13.0-baseline `in_pcbconnect_setup`:

```1526:1530:f-stack-13.0-baseline/freebsd/netinet/in_pcb.c
#ifdef FSTACK
	if (laddr.s_addr == INADDR_ANY) {
		ff_in_pcbladdr(AF_INET, &faddr, fport, &laddr);
	}
#endif
```

```1583:1589:f-stack-13.0-baseline/freebsd/netinet/in_pcb.c
		error = in_pcb_lport_dest(inp, (struct sockaddr *) &lsin,
		    &lport, (struct sockaddr *)& fsin, fport, cred,
#ifndef FSTACK
		    INPLOOKUP_WILDCARD);
#else
		    INPLOOKUP_WILDCARD | INPLOOKUP_LPORT_RSS_CHECK);
#endif
```

Current 15.0 `in_pcbconnect` (merged with `_setup`):

```1128:1147:f-stack/freebsd/netinet/in_pcb.c
	if (in_nullhost(inp->inp_laddr)) {
		error = in_pcbladdr(inp, &faddr, &laddr, cred);
		...
	} else
		laddr = inp->inp_laddr;

	if (anonport) {
		...
		error = in_pcb_lport_dest(inp, (struct sockaddr *)&lsin,
		    &lport, (struct sockaddr *)&fsin, sin->sin_port, cred,
		    INPLOOKUP_WILDCARD);
```

- On 15.0 here: **there is no `ff_in_pcbladdr` call** (only the native `in_pcbladdr` at L1129); port selection passes only `INPLOOKUP_WILDCARD` (L1147), **without** `INPLOOKUP_LPORT_RSS_CHECK`.
- Note: 15.0's local-address check uses `in_nullhost(inp->inp_laddr)` (L1128), corresponding in semantics to but written differently from 13.0's `laddr.s_addr == INADDR_ANY` (L1527); the back-port insertion point should be placed before/inside the `in_pcbladdr` call. 【Pending confirmation: the exact insertion location (inside the `in_nullhost` branch, before setting `laddr`) to be decided at the coding phase】

### 2.2 Current State of the `INPLOOKUP_LPORT_RSS_CHECK` Macro (15.0)

```616:625:f-stack/freebsd/netinet/in_pcb.h
typedef	enum {
	INPLOOKUP_WILDCARD = 0x00000001,
	INPLOOKUP_RLOCKPCB = 0x00000002,
	INPLOOKUP_WLOCKPCB = 0x00000004,
	INPLOOKUP_FIB = 0x00000008,
} inp_lookup_t;

#ifdef FSTACK
#define	INPLOOKUP_LPORT_RSS_CHECK	0x80000000	/* F-Stack lport RSS check */
#endif
```

- Macro value `0x80000000` does not collide with any enum bit; but `INPLOOKUP_MASK` (`in_pcb.h:627`) **does not include** `INPLOOKUP_LPORT_RSS_CHECK`. When back-porting, `in_pcb_lport_dest` must, as in 13.0, first extract this flag and then clear it from `lookupflags` (13.0 L712) to avoid polluting downstream lookups.

### 2.3 Summary of 0.1 Back-port Impact

- There are two missing hook points: `in_pcb_lport_dest` (port-selection logic) + `in_pcbconnect` (address hookup + flag passing).
- Adaptation points: `const inpcb`, the merging of `in_pcbconnect_setup`, `in_pcblookup_local`'s new `RT_ALL_FIBS` parameter, the enum-ification of `INPLOOKUP_*`.
- protosw merge: this path does not directly involve protosw dispatch, but whether the connect call chain has been changed by protosw in a way that affects lookupflags propagation is 【pending confirmation, to be checked against the connect caller at coding time】.

---

## 3. IPv6 Gap (0.2)

### 3.1 Specific Locations of IPv4-only in User Space

| Location | Line | IPv4-only Manifestation |
|------|------|----------------|
| `struct ff_rss_tbl_dip_type.daddr` | L156 | `uint32_t` (cannot hold a 16B v6 address) |
| `struct ff_rss_tbl_type.saddr` | L167 | `uint32_t` |
| `ff_rss_check` parameters | L2851 | `uint32_t saddr/daddr` |
| `ff_rss_check` hash layout | L2865-2880 | Only 4+4+2+2, no 16B branch |
| `ff_rss_tbl_get_portrange` parameters | L2796 | `uint32_t saddr/daddr` |
| `ff_rss_tbl_set_portrange` / `ff_rss_tbl_init` | L2737 / L2598 | Table keys are `uint32_t` |
| `rss_tbl_cfg_handler` config parsing | `ff_config.c:913-914` | `inet_pton(AF_INET, ...)` parses daddr/saddr |

- Note: `ff_in_pcbladdr` (L2571) itself already supports `AF_INET6_FREEBSD` (L2581-2584), which is a link in the IPv6 pipeline that **already exists**. `ff_api.h:48-51` defines `AF_INET6_LINUX=10` / `AF_INET6_FREEBSD=28`.

### 3.2 Kernel-Side IPv6 Port-Selection Hookup Point (Absent Even in 13.0 → Entirely New)

- `f-stack/freebsd/netinet6/in6_pcb.c`: grepping for `FSTACK / ff_rss / ff_in_pcbladdr / INPLOOKUP_LPORT_RSS` yields **0** hits.
- `f-stack-13.0-baseline/freebsd/netinet6/in6_pcb.c`: likewise **0** hits.
- Conclusion: the IPv6 RSS port-selection hookup **does not exist in either 13.0 or 15.0**; 0.2 is a brand-new capability that requires new hookup work in 15.0's `in6_pcb.c` connect/port-selection flow (the exact function to target is pending confirmation at 04/coding phase, with candidates being `in6_pcb_lport` / the `in6_pcbconnect` family).
- Note: 15.0's `in_pcb_lport_dest` (L756) is itself already a unified v4/v6 function (INET6 branches L818-826/L851-872), and IPv6 sockets may also select ports via this function; but it **has no RSS hook**. 【Pending confirmation: whether IPv6 connect actually reuses `in_pcb_lport_dest` or takes an independent `in6_pcb` path, to be confirmed at coding time】

---

## 4. Current State of `rte_thash` (0.3, DPDK 24.11.6)

### 4.1 Available API Signatures (`dpdk-stable-24.11.6/lib/hash/rte_thash.h`)

```303:305:dpdk-stable-24.11.6/lib/hash/rte_thash.h
struct rte_thash_ctx *
rte_thash_init_ctx(const char *name, uint32_t key_len, uint32_t reta_sz,
	uint8_t *key, uint32_t flags);
```
- `reta_sz`: the **logarithm** of the reta size (L288-291); `key` may be NULL (random, L292-294); `flags` supports `RTE_THASH_IGNORE_PERIOD_OVERFLOW`(0x1)/`RTE_THASH_MINIMAL_SEQ`(0x2) (L269-274).

```256:258:dpdk-stable-24.11.6/lib/hash/rte_thash.h
int
rte_thash_complete_matrix(uint64_t *matrixes, const uint8_t *rss_key,
	int size);
```

```380:382:dpdk-stable-24.11.6/lib/hash/rte_thash.h
uint32_t
rte_thash_get_complement(struct rte_thash_subtuple_helper *h,
	uint32_t hash, uint32_t desired_hash);
```

```456:461:dpdk-stable-24.11.6/lib/hash/rte_thash.h
int
rte_thash_adjust_tuple(struct rte_thash_ctx *ctx,
	struct rte_thash_subtuple_helper *h,
	uint8_t *tuple, unsigned int tuple_len,
	uint32_t desired_value, unsigned int attempts,
	rte_thash_check_tuple_t fn, void *userdata);
```
- `tuple_len` must be a multiple of 4 (L441-442); `desired_value` is the desired low-order bits of the hash (L443-444); `fn` is a validation callback, may be NULL (L447-448):
```428:428:dpdk-stable-24.11.6/lib/hash/rte_thash.h
typedef int (*rte_thash_check_tuple_t)(void *userdata, uint8_t *tuple);
```
- Notes: `rte_thash_adjust_tuple` adjusts the tuple so that the low bits of the Toeplitz hash equal `desired_value` (L430-432), and is thread-safe (L433). A ctx must first be built via `rte_thash_init_ctx`, and a subtuple helper obtained via `rte_thash_add_helper` (L348-349) to get `h`. 【Pending confirmation: the offset/len approach for adding the helper needed for this scenario, to be designed in 04】

### 4.2 Differences Between the Existing Software `toeplitz_hash` and `rte_thash`

| Dimension | Existing `toeplitz_hash` (L2547) | `rte_thash_adjust_tuple` |
|------|------------------------------|--------------------------|
| Direction | Forward: computes a hash for a tuple, tries each port | Reverse: given a target hash low-order value, adjusts the tuple (port) so it lands in the target queue |
| Port-selection complexity | O(number of ports): per-dport software computation (`ff_rss_tbl_init` L2690-2700 scans 65536) | Reverse derivation + up to `attempts` validations, expected to significantly reduce cost |
| Queue determination | `(hash & (reta_size-1)) % nb_queues == queueid` (L2885) | `desired_value` aligns with the low bits of the reta (queueid→desired_value mapping needed) |
| Key | `default_rsskey_40bytes` (L92), asymmetric | Reverse-adjust is more robust with a **symmetric key** 【Pending confirmation: feasibility of reverse derivation with the current asymmetric key, and the choice of `attempts`】 |

- **Key constraint**: the queue-placement determination in `ff_rss_check` includes `% nb_queues` (L2885), while `rte_thash`'s `desired_value` directly aligns with reta low bits (reta entry); the mapping relationship between these two (reta_size, nb_queues, queueid) must be precisely aligned in the 0.3 design, otherwise the reverse-derived port will land in the wrong queue.

---

## 5. Configuration and Testing Current State

### 5.1 Configuration (`lib/ff_config.c`)

- `rss_check_cfg_handler` (L923-953): parses the `enable` (L943) and `rss_tbl` (L945) settings under the `rss_check` section in config.ini's `[dpdk]`, with the latter handed off to `rss_tbl_cfg_handler`.
- `rss_tbl_cfg_handler` (L880-921): splits multiple entries by `;`, each entry `port_id daddr saddr sport` (L903-915), **parses daddr/saddr via `inet_pton(AF_INET, ...)`** (L913-914) → **IPv4-only**; 0.2 needs to extend this to support v6 textual addresses.
- Config structure `struct ff_rss_check_cfg` contains `rss_tbl_cfgs[FF_RSS_TBL_MAX_ENTRIES]` (`ff_config.h:242`).

### 5.2 Unit Tests (`tests/unit/test_ff_dpdk_if.c`)

- Existing cases (L361-455):
  - `test_ff_rss_tbl_set_portrange_no_cfg` (L361, cfg=NULL→-1)
  - `test_ff_rss_tbl_set_portrange_disabled` (L375, enable=0→-1)
  - `test_ff_rss_tbl_set_portrange_inverted_range` (L390, first>last→-1)
  - `test_ff_rss_tbl_get_portrange_no_cfg` (L405, cfg=NULL→-1)
  - `test_ff_rss_tbl_get_portrange_disabled` (L421, enable=0→-1)
  - `test_ff_rss_tbl_get_portrange_smoke` (L441, no crash for an arbitrary 4-tuple)
- Existing cases cover only **guard branches and smoke tests**, and do not cover: actual hash-hit correctness, portrange port-selection queue-placement correctness, IPv6, or the thash dynamic path. 0.1/0.2/0.3 need corresponding new test cases (details in the M4 spec).

---

## 6. Summary of Gap/Difference Conclusions

| Item | Current-state conclusion | Key evidence |
|----|----------|----------|
| User-space RSS interfaces | Fully retained on 15.0 (IPv4) | `ff_dpdk_if.c:2599-2964` |
| 0.1 kernel hooks | **Entirely missing on 15.0** (fully present in 13.0), only the `#define` retained | 15.0 `in_pcb.c` grep=0; `in_pcb.h:623-625` |
| 0.1 adaptation points | Same function name plus const, `_setup` merged into `in_pcbconnect`, lookup gains `RT_ALL_FIBS`, `INPLOOKUP_*` enum-ified | `in_pcb.c:756/1083`, `in_pcb.h:616-625` |
| 0.2 IPv6 | **Entirely new** (kernel-side RSS-for-IPv6 absent in both 13.0/15.0) | grep=0 for `in6_pcb.c` on both versions; user-space structures are `uint32_t` |
| 0.3 rte_thash | API complete, currently included but unused | `rte_thash.h:256/304/380/456`; `ff_dpdk_if.c:51` |
| Configuration | IPv4-only (`inet_pton(AF_INET)`) | `ff_config.c:913-914` |
| Testing | Only guard/smoke, lacking correctness/IPv6/thash coverage | `test_ff_dpdk_if.c:361-455` |

---

## 6-bis. R-B/R-C Current State: Mandatory Software Recheck → Performance Discount (0.4 Background)

### 6-bis.1 Current Location of the Mandatory Recheck

After R-B and R-C landed, the reverse-derivation path **mandatorily** performs one additional software recheck as a zero-tolerance backstop after `rte_thash_adjust_tuple` succeeds. Evidence:

```3098:3108:f-stack/lib/ff_dpdk_if.c
        if (rte_thash_adjust_tuple(rss_thash_ctx[port_id],
                rss_thash_sport_h[port_id], tuple, sizeof(tuple),
                desired & (reta_size - 1), FF_RSS_THASH_ADJUST_ATTEMPTS,
                NULL, NULL) == 0) {
            bcopy(&tuple[8], &sport, sizeof(sport));
            /* zero tolerance: confirm with the same soft hash. */
            if (ff_rss_check(softc, saddr, daddr, sport, dport)) {
                *out_sport = sport;
                return 0;
            }
        }
```

```3431:3440:f-stack/lib/ff_dpdk_if.c
        if (rte_thash_adjust_tuple(rss_thash6_ctx[port_id],
                rss_thash6_sport_h[port_id], tuple, sizeof(tuple),
                desired & (reta_size - 1), FF_RSS_THASH_ADJUST_ATTEMPTS,
                NULL, NULL) == 0) {
            bcopy(&tuple[32], &sport, sizeof(sport));
            if (ff_rss_check6(softc, saddr6, daddr6, sport, dport)) {
                *out_sport = sport;
                return 0;
            }
        }
```

- v4: `ff_dpdk_if.c:3362-3363` mandatorily calls `ff_rss_check`; on a recheck failure, the candidate is discarded → the outer `for(tries)` moves on to the next `desired`.
- v6: L3758-3759 mandatorily calls `ff_rss_check6` symmetrically.
- Failure fallback chain: once all `tries` are exhausted → `return -1` (v4 L3403 / v6 L3768) → the caller `in_pcb_lport_dest` falls back to a software scan (`freebsd/netinet/in_pcb.c:904`).

### 6-bis.2 Quantified Performance Discount (spec 10 real-measurement basis)

- Historical R-B real-machine measurement: the single-candidate equivalence rate for a reverse-derived candidate passing the software recheck is only ~22%-27% (spec 10 R-B hitrate).
- **Root-cause attribution correction (per the R-F arbitration ruling, see §6-quater)**: this low equivalence rate is **not caused by byte-order differences** (`rte_softrss(be_to_cpu_32(bytes)) ≡ toeplitz_hash(bytes)` has been proven bit-for-bit equivalent, and neither byte order nor the GFNI/scalar branch differences are the root cause). The true cause is that `rte_thash_add_helper`, in order to build the port-complement table, uses an LFSR to **rewrite `ctx->hash_key` in place**, while `ff_rss_check`/the NIC still use the **original** `rsskey` — the **three-way key mismatch** causes the reverse-derived port to essentially land in a queue at random within the original key's hash space (~22-27% coincidental hits). The R-F fix aligns the three keys (KEY_FINAL published to the NIC), after which the equivalence rate should reach ~100%.
- Effect of the current mandatory recheck: on average, each connect's reverse derivation requires ~3-6 candidates to hit one that is "adjust succeeds ∧ software recheck passes"; each failed candidate additionally costs one extra `toeplitz_hash` computation (v4 12B / v6 36B full loop).
- This partially offsets the original intent of 0.3 (using reverse derivation to replace O(number of ports) software scanning to cut cost): when the reverse-derivation hit rate is insufficient, the amortized time of the reverse-derivation path degrades to ~3-6 software computations plus the reverse derivation itself.

### 6-bis.3 `ff_rss_check`/`ff_rss_check6` in Static-Table Init: Retained

- `ff_rss_tbl_init` calls `ff_rss_check` at L2735, and `ff_rss_tbl6_init` calls `ff_rss_check6` at L3253:
  - Purpose: during **table-build time**, scans per-dport to determine "which dports land in this queue" and writes into the static tables `ff_rss_tbl[]`/`ff_rss_tbl6[]`.
  - Call frequency: once at process startup, O(MAX_DPORT × MAX_*ENTRIES), **not a runtime hotpath per connect**.
  - 0.4 does not touch this — the static table's content must be consistent with `ff_rss_check[6]`; using software-computed results as the "authoritative landing-queue set" during table build is the semantic source of the table itself, and removing it would break the static table's correctness.

### 6-bis.4 Kernel-Side `ff_rss_check` Software Branch: Retained

- The `ff_rss_check` call at `freebsd/netinet/in_pcb.c:904` is the core of the R-A software path (the final fallback when the static table is missed and thash reverse derivation returns -1, scanning per-port to determine landing in this queue).
- 0.4 does not change this — it is the "failure fallback" chain (worst case), decoupled in semantics from this change's "secondary recheck on the success path":
  - 0.4 only removes the "mandatory software-recheck hard gate after a successful reverse derivation" (performance optimization).
  - The fallback chain "reverse derivation fully fails → in_pcb software scan" is **fully retained** (no functional regression).

### 6-bis.5 Control-Flow Before/After Comparison

| Stage | Current state (equivalent to recheck forced on) | 0.4 default (recheck=0) | 0.4 debug (recheck=1) |
|------|-----------------------------|----------------------|------------------------|
| `adjust_tuple` fails | Moves to the next candidate; on total failure → -1 → in_pcb software scan | Same as left (unchanged) | Same as left (unchanged) |
| `adjust_tuple` succeeds | **Mandatorily requires `ff_rss_check[6]==1`** before returning the sport, otherwise the candidate is discarded | **Directly `*out_sport=sport; return 0`** (trusts the reverse-derivation result) | Same as "current state" (mandatory recheck) |
| Failure fallback (in_pcb software scan) | Fully retained | Fully retained | Fully retained |
| Static-table build (L2735/L3253) | Fully retained | Fully retained | Fully retained |
| Function signature | Unchanged | Unchanged | Unchanged |
| Outer `for(tries)` and `attempts=16` | Unchanged | Unchanged | Unchanged |

---

## 6-ter. Current State of the bind-then-connect Failure Chain (0.5 Background)

> Goal: empirically demonstrate the missing point where `bind(local_addr, port=0)` followed by connect bypasses RSS port selection, comparing against the 13.0 baseline and the upstream commit `cb9b4d462a0cd8c47b6f514e2af0111cd26597b3`. Line numbers reflect actual current-code measurements.

### 6-ter.1 Reference Commit `cb9b4d462` (Based on 13.0, +9/-2, 3 hunks, Only Changes `freebsd/netinet/in_pcb.c`)

| Hunk | Function | Change (semantics) |
|------|------|-------------|
| hunk1 | `in_pcbbind` | Wraps the `in_pcbinshash` hash-insertion block with `#ifdef FSTACK if (inp->inp_lport != 0) { ... } #endif` — bind(addr,0) does not insert into the hash (does not pin down the port) |
| hunk2 | `in_pcbbind_setup` | Wraps `if (lport == 0) { in_pcb_lport(...); }` with `#ifndef FSTACK` — under FSTACK, bind(addr,0) does not allocate a port at bind time, `inp_lport` stays 0 |
| hunk3 | `in_pcbconnect_setup` (13.0) | Changes `in_pcbbind_setup(...)` to `in_pcb_lport(inp, &laddr, &lport, cred, INPLOOKUP_WILDCARD)` — reselects the port at connect time |

- Semantics: defers `bind(local_addr, port=0)` port allocation to connect time, so that connect takes the RSS-aware port-selection path; aligns with Linux `IP_BIND_ADDRESS_NO_PORT` + RSS queue affinity (see 03 §5 for details).

### 6-ter.2 15.0 v4 Current State (`f-stack/freebsd/netinet/in_pcb.c`, Already Verified)

#### (A) `in_pcbbind` (L720) Hash-Insertion Block — hunk1 Missing Point

```739:748:f-stack/freebsd/netinet/in_pcb.c
	if (__predict_false((error = in_pcbinshash(inp)) != 0)) {
		MPASS(inp->inp_socket->so_options & SO_REUSEPORT_LB);
		inp->inp_laddr.s_addr = INADDR_ANY;
		inp->inp_lport = 0;
		inp->inp_flags &= ~INP_BOUNDFIB;
		return (error);
	}
	if (anonport)
		inp->inp_flags |= INP_ANONPORT;
	return (0);
```

- L735-736 calls `in_pcbbind_setup(... &inp->inp_lport ...)`, which already sets `inp_lport` for the bind; L739 unconditionally calls `in_pcbinshash(inp)` to insert into the hash (pinning down the port). **No `#ifdef FSTACK if (inp->inp_lport != 0)` guard = hunk1 missing point**.

#### (B) `in_pcbbind_setup` Port Allocation — hunk2 Missing Point

```1273:1281:f-stack/freebsd/netinet/in_pcb.c
	if (*lportp != 0)
		lport = *lportp;
	if (lport == 0) {
		error = in_pcb_lport(inp, &laddr, &lport, cred, lookupflags);
		if (error != 0)
			return (error);
	}
	*laddrp = laddr.s_addr;
	*lportp = lport;
```

- L1275-1279 `if (lport == 0) { in_pcb_lport(... lookupflags); }`: an anonymous port is allocated right at bind(addr,0), and `lookupflags` **does not include** `INPLOOKUP_LPORT_RSS_CHECK` (the flags passed by in_pcbbind lack this bit) → port selection is not RSS-aware. **No `#ifndef FSTACK` wrapping = hunk2 missing point**.

#### (C) Connect Path — hunk3 Already Equivalently Present in 15.0 (No Change Needed)

```1313:1313:f-stack/freebsd/netinet/in_pcb.c
	anonport = (inp->inp_lport == 0);
```

```1363:1369:f-stack/freebsd/netinet/in_pcb.c
		error = in_pcb_lport_dest(inp, (struct sockaddr *)&lsin,
		    &lport, (struct sockaddr *)&fsin, sin->sin_port, cred,
#ifdef FSTACK
		    INPLOOKUP_WILDCARD | INPLOOKUP_LPORT_RSS_CHECK);
#else
		    INPLOOKUP_WILDCARD);
#endif
```

- 15.0 no longer has a separate `in_pcbconnect_setup` (merged into `in_pcbconnect` L1294); L1313 `anonport = (inp->inp_lport == 0)`; L1353 the anonport branch already uses `in_pcb_lport_dest(... INPLOOKUP_WILDCARD | INPLOOKUP_LPORT_RSS_CHECK)` (FSTACK-guarded L1365-1366, already landed by the R-A back-port); L1377 else uses the already-allocated port. **hunk3 is equivalently present, no change needed**.

#### (D) v4 Failure Chain

```
bind(addr, 0)
  └─ in_pcbbind_setup (L1275): lport==0 → in_pcb_lport (no RSS_CHECK) allocates a port
  └─ in_pcbbind (L739): in_pcbinshash inserts into the hash, inp_lport ≠ 0 pinned down
connect(remote)
  └─ in_pcbconnect (L1313): anonport = (inp_lport==0) = false
  └─ takes L1377 else: lport = inp->inp_lport (already allocated, not an RSS port)
       ⇒ bypasses the L1363-1366 INPLOOKUP_LPORT_RSS_CHECK port selection ⇒ the packet may land in a queue other than this one
```

- **Closure method (0.5)**: add hunk1 (L739-745 wrapped with `if (inp->inp_lport != 0)`) + hunk2 (L1275-1279 wrapped with `#ifndef FSTACK`), so that after bind(addr,0), `inp_lport = 0` → connect L1313 `anonport = true` → naturally enters the L1363-1366 RSS branch. Estimated v4 change: `+8` lines.

### 6-ter.3 15.0 v6 Current State (`f-stack/freebsd/netinet6/in6_pcb.c`, Already Verified)

#### (A) `in6_pcbbind` (L306) Pre-Allocates the Port + Inserts into the Hash — v6 Unclosed Point

```354:369:f-stack/freebsd/netinet6/in6_pcb.c
	if (lport == 0) {
		if ((error = in6_pcbsetport(&inp->in6p_laddr, inp, cred)) != 0) {
			/* Undo an address bind that may have occurred. */
			inp->inp_flags &= ~INP_BOUNDFIB;
			inp->in6p_laddr = in6addr_any;
			return (error);
		}
	} else {
		inp->inp_lport = lport;
		if (in_pcbinshash(inp) != 0) {
			inp->inp_flags &= ~INP_BOUNDFIB;
			inp->in6p_laddr = in6addr_any;
			inp->inp_lport = 0;
			return (EAGAIN);
		}
	}
	return (0);
```

- L354 `if (lport == 0) { in6_pcbsetport(...); }`: an anonymous port is allocated right at bind(v6_addr,0) (`in6_pcbsetport` → `in_pcb_lport`, no RSS_CHECK); L361-369 else (lport≠0) inserts into the hash. After binding a v6 local addr, `in6p_laddr` is non-unspecified and `inp_lport ≠ 0`.

#### (B) Connect Path (L515-527, Already Has an RSS Branch but Its Condition Is Broken by bind)

```515:527:f-stack/freebsd/netinet6/in6_pcb.c
	if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) {
		if (inp->inp_lport == 0) {
			error = in_pcb_lport_dest(inp,
			    (struct sockaddr *) &laddr6, &inp->inp_lport,
			    (struct sockaddr *) sin6, sin6->sin6_port, cred,
#ifdef FSTACK
			    INPLOOKUP_WILDCARD | INPLOOKUP_LPORT_RSS_CHECK);
#else
			    INPLOOKUP_WILDCARD);
#endif
			if (error)
				return (error);
		}
		inp->in6p_laddr = laddr6.sin6_addr;
	}
```

- The L515 RSS-branch condition = `IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)` **and** L516 `inp->inp_lport == 0`. After bind(v6_addr,0), both conditions are broken (`in6p_laddr` non-unspecified + `inp_lport` non-zero) → connect bypasses RSS (same as v4).

#### (C) v6 Failure Chain and Closure Method

```
bind(v6_addr, 0)
  └─ in6_pcbbind (L354): lport==0 → in6_pcbsetport (no RSS_CHECK) allocates a port
  └─ sets in6p_laddr to non-unspecified, inp_lport ≠ 0
connect(remote6)
  └─ in6_pcbconnect (L515): IN6_IS_ADDR_UNSPECIFIED(in6p_laddr)=false ⇒ does not enter the RSS branch
       ⇒ bypasses L521 INPLOOKUP_LPORT_RSS_CHECK
```

- **Closure method (0.5 v6, brand-new design, no 13.0 diff to copy)**: mimicking v4 hunk1/hunk2, in `in6_pcbbind` (L354/L361-369), gate "skip in6_pcbsetport + skip in_pcbinshash when lport==0, but still set in6p_laddr", so that after bind, `inp_lport = 0` (with in6p_laddr still set). But the connect L515 condition must be reverified — **the current L515 requires `IN6_IS_ADDR_UNSPECIFIED(in6p_laddr)`**, and if bind already sets in6p_laddr, that condition remains false. **The v6 closure may also need a coordinated adjustment of the L515 condition (or bind should not set in6p_laddr and only record it)**, which is a coding-phase verification item (01 §3-ter.8 pending confirmation). Estimated `in6_pcb.c` change `+6~10` lines.

### 6-ter.4 Comparison Against the 13.0 Baseline

- 13.0-baseline `in_pcb.c`: hunk1/hunk2/hunk3 of commit `cb9b4d462` were introduced **on top of 13.0** (whether this feature is present in the 13.0-baseline repository is subject to actual measurement); this project's task is to re-land this v4 capability following 15.0's structure (`in_pcbbind`/`in_pcbbind_setup` + connect already merged into `in_pcbconnect`).
- 13.0-baseline `in6_pcb.c` **has no FSTACK** (already verified in 02 §3.2, grep=0) → the v6 bind-no-port capability never existed in 13.0; 0.5 v6 is brand new for 15.0 (similar in nature to 0.2 IPv6).
- 【Pending confirmation: whether 13.0-baseline `in_pcb.c` already contains the three hunks of `cb9b4d462` (i.e. whether this commit has already been merged into the 13.0-baseline branch) — if so, the v4 part is a "missing 13.0→15.0 port migration back-port"; if 13.0-baseline also lacks it, then v4 is likewise new relative to the 13.0 baseline. To be verified at coding time by grepping the 13.0-baseline `in_pcbbind`/`in_pcbbind_setup` for `#ifdef FSTACK` guards.】

---

## 6-quater. R-F Current State: Root Cause of the thash Reverse-Derivation Failure + Secondary Init Failure (Merged from _rf_work Diagnosis/Arbitration)

> This section merges the conclusions from `_rf_work/{arbiter_rootcause, diag_code_findings, diag_dpdk_findings}.md` that were **independently arbitrated and confirmed to be consistent with the current code**. The byte-order hypothesis has been disproven at the bit level and is deprecated — it must not be mistakenly reintroduced later.

### 6-quater.1 Root Cause One: The Reverse-Derived sport in 0.2 Frequently Fails to Land in This Queue = Three-Way Key Mismatch (Authoritative Ruling)

- `rte_thash_add_helper → generate_subkey` (DPDK `rte_thash.c`), in order to build the port-complement table, uses an LFSR m-sequence to **rewrite `ctx->hash_key` in place**: the v4 helper (offset/len) rewrites the byte segment of the key covering the sport-participating bits, and the v6 helper rewrites a different byte segment (the two byte segments do not overlap).
- `rte_thash_adjust_tuple` internally uses `rte_thash_get_key(ctx)` to fetch the **rewritten** key for reverse derivation of the sport; while `ff_rss_check` (software) and the **NIC hardware** use the **original** `rsskey`. The **three-way key mismatch** causes the reverse-derived port to systematically land in the wrong queue within the original key's hash space (~22-27% coincidental hits); `recheck` still fails to pass after multiple attempts; with `enable=0`, pure software computation is self-consistent with the original key throughout → correct on the real machine.
- **Deprecated, invalidated hypothesis**: byte-order differences from `be_to_cpu_32` / GFNI≠scalar. The arbitration proved at the bit level that `rte_softrss(be_to_cpu_32(bytes)) ≡ toeplitz_hash(bytes)`, and that the GFNI matrix path and the scalar branch derive from the same (rewritten) `ctx->hash_key`, producing the same result for the same input — neither byte order nor implementation-branch differences are the root cause.
- **Key v4/v6 coupling point**: the v6 tuple uses the first 40 bytes of the key (including both the v4-rewritten segment and the v6-rewritten segment), and a given NIC can only be programmed with one key ⇒ when fixing this, the v6 ctx **must be constructed serially based on the "already v4-rewritten key"** (it cannot be independently initialized from the original key on its own), ultimately yielding a unified KEY_FINAL. See 04 §R-F and the code `ff_rss_thash_build_key` for details.

### 6-quater.2 Root Cause Two: thash ctx Initialization Fails Entirely in Secondary Processes for 0.1 (Confirmed by Code)

- The thash ctx's name only contains `port_id` (`ff_rss_thash_%u` / `ff_rss_thash6_%u`), not proc_id; `rte_thash_init_ctx` performs a global name-collision check on a **shared EAL tailq** (`"RTE_THASH"`), returning `EEXIST`→NULL on a match.
- The primary process claims the name first and succeeds; every secondary process, re-initializing with the same name, necessarily hits EEXIST → ctx=NULL → the dynamic path degrades to a software scan in all secondary processes. This matches the observed phenomenon of "primary succeeds, all secondaries fail".
- **Correct solution (standard DPDK multi-process pattern)**: primary calls `init_ctx + add_helper` to create it; secondary should switch to `rte_thash_find_existing(name) + rte_thash_get_helper`. The ctx/helper reside in shared hugepage memory, and secondary read-only `adjust` calls (MT-safe) are safe; the `add_helper` documentation explicitly states it is "not concurrency-safe", implying semantically a single writer (the primary) should construct it. The current code's `ff_rss_thash_build_key` is already implemented this way (primary creates / secondary finds existing).

### 6-quater.3 Real-Machine Empirical Facts (Intel X550 ixgbe, Merged from ixgbe_misqueue_facts)

- F1: `ff_rss_check` pure software computation is correct (`enable=0` uses the default key, consistent with the NIC).
- F2: The KEY_FINAL value itself is correct (hard-coded into a static key array + short-circuited build_key + `enable=0` pure software computation → normal).
- F3: The RETA table = `idx % nb_queues`; a real-machine RETA query shows `mismatch=0`, confirming the assumption.
- Decisive comparison (B2 static BSS key vs B3 `rte_malloc` shared-hugepage key, with identical KEY_FINAL content) once exposed a runtime issue of "the memory type the rss_key pointer refers to differs", which is a landing-point issue in the real-machine multi-process NIC dev_configure/dev_start dispatch (real-machine verification details see 10 §R-F and the SOP).

---

## 7. List of Pending Confirmation Items

1. 【Pending confirmation】The exact insertion point of `ff_in_pcbladdr` within 15.0's `in_pcbconnect` (L1083) after merging in 13.0's `in_pcbconnect_setup` (inside the `in_nullhost(inp->inp_laddr)` branch, before `in_pcbladdr`).
2. 【Pending confirmation】Whether IPv6 connect port selection actually goes through `in_pcb_lport_dest` (L756, unified v4/v6) or an independent `in6_pcb` path, determining the 0.2 kernel hookup point.
3. 【Pending confirmation】Whether the connect call chain has been changed by a protosw merge affecting the propagation of `lookupflags` (protosw-merge impact).
4. 【Pending confirmation】The RSS offload field on the NIC/DPDK side needed for IPv6 RSS hash, and its alignment with the existing port configuration.
5. 【Pending confirmation】Feasibility of `rte_thash_adjust_tuple`'s reverse derivation under the current asymmetric `default_rsskey_40bytes` (L92) for 0.3, the choice of `attempts`, the offset/len approach for adding the helper, and the precise mapping from `queueid → desired_value` (including `% nb_queues`).
