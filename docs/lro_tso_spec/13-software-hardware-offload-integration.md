# F-Stack Software/Hardware Offload Integration Solution

> Document tier: Software/hardware offload integration solution (software offload supplementary design 3 / unified integration design)
> Design basis: `04-solution-and-architecture-design.md` (hardware LRO/TSO), `05-interface-and-config-design.md` (interface contracts), `11-software-lro-solution.md`, `12-software-tso-and-segmentation-solution.md`. This document unifies software and hardware offload capability detection, switch semantics, path coordination, and zero-regression guarantee.
> Authoritative version: DPDK `dpdk-stable-24.11.6`, FreeBSD 15.0 port (`f-stack/freebsd/`).
> Iron rule: This round **does not write code, does not change lib, does not commit**. All code references include precise `file:line`; all conclusions involving specific PMD/runtime behavior are marked "**pending runtime validation**".

---

## 0. Integration Current Status Overview (Code Verified)

| Direction | Hardware Path | Software Path | Integration Gap |
| --- | --- | --- | --- |
| **LRO (receive)** | `ff_dpdk_if.c` detects `RTE_ETH_RX_OFFLOAD_TCP_LRO` (`04` doc 1.2); `IFCAP_LRO` already driven by `hw_features.rx_lro` (`ff_veth.c:945-947`) | `tcp_lro.c` compiled (`Makefile:513`) but **not integrated into `ff_veth_input`** (`ff_dpdk_if.c:1707`) | **Only substantive gap: software LRO not integrated into receive path** (doc 11) |
| **TSO (transmit)** | `ff_dpdk_if.c` detects `RTE_ETH_TX_OFFLOAD_TCP_TSO`; `IFCAP_TSO`+`if_hw_tsomax*` already set (`ff_veth.c:955-961`) | Protocol stack MSS segmentation (`tcp_output.c:558` `tso=0` path), **already working, no gap** | **Transmit side has no gap** (doc 12) |

- **Transmit side naturally consistent** (`02` doc / doc 12 2.2): `ff_mbuf_tx_offload` (`ff_veth.c:305-306`) only takes `tso_segsz` when `CSUM_TSO`; NIC without TSO → protocol stack doesn't set `CSUM_TSO` → transmit TSO branch automatically skipped.
- **`ff_hw_features` fields** (`ff_config.h:112-118`): `rx_csum`(L113)/`rx_lro`(L114)/`tx_csum_ip`(L115)/`tx_csum_l4`(L116)/`tx_tso`(L117). Population points `ff_dpdk_if.c` (csum/tso/lro detection blocks); consumption points `ff_veth.c:942-961`.
- **config.ini offload items**: `tx_csum_offoad_skip=0` (L19), `tso=0` (L22), `lro=0` (L24).

---

## 1. Capability Detection and Priority Design

### 1.1 Detection Layering

Offload capability has three layers, detection order: **hardware capability → user intent → software fallback**.

| Layer | Data Source | Location | Semantics |
| --- | --- | --- | --- |
| Hardware capability | `dev_info.rx_offload_capa` / `tx_offload_capa` | `ff_dpdk_if.c` port setup | What offloads PMD objectively supports |
| User intent | `dpdk.lro` / `dpdk.tso` | `config.ini` → `ff_config.c` parsing | Whether user wishes to enable |
| Effective state | `hw_features.rx_lro` / `tx_tso` | `ff_dpdk_if.c` detection block set | Actually effective (intent ∧ hardware capability) |
| Software fallback | `ctx->sw_lro_enabled` (new, only LRO needs) | `ff_dpdk_if.c` detection block derivation | Software supplement when hardware unsupported |

### 1.2 LRO Priority: Hardware First, Software Fallback

```
lro=0: don't enable any LRO (both hardware and software off) — default, zero regression
lro=1:
    detect dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO:
      ├─ supported → hw_features.rx_lro = 1; sw_lro_enabled = 0 (use hardware, not software)
      └─ unsupported → hw_features.rx_lro = 0; sw_lro_enabled = 1 (fallback to software LRO)
```

- **Priority rationale**: Hardware LRO has zero CPU overhead, high aggregation quality, use preferentially; only when hardware doesn't support (e.g., local virtio, **pending runtime validation**) fallback to software LRO (CPU aggregation, has overhead but functionally equivalent).
- **Mutual exclusion guarantee**: `hw_features.rx_lro` and `sw_lro_enabled` never both 1 simultaneously (see section 4).

### 1.3 TSO Priority: Hardware Acceleration, Protocol Stack Fallback

```
tso=0: don't enable hardware TSO — default, protocol stack sends segment by segment per MSS (software segmentation fallback always exists)
tso=1:
    detect dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO:
      ├─ supported → hw_features.tx_tso = 1 (hardware TSO, protocol stack sends large segment for hardware to cut)
      └─ unsupported → hw_features.tx_tso = 0 (protocol stack sends segment by segment per MSS, same effect as tso=0)
```

- TSO doesn't need a "software fallback switch": when hardware TSO unsupported, protocol stack **automatically** sends segment by segment (doc 12 1.5 logic chain), this is inherent fallback, no additional switch needed.
- Therefore TSO side software/hardware integration **is already complete**; this round's TSO work is only hardware path correctness enhancement (`04` doc section 2).

---

## 2. Switch Semantics Unified Design (Key Decision)

### 2.1 Three Candidate Options

| Option | Key | Value Semantics | Pros | Cons |
| --- | --- | --- | --- | --- |
| **Option A: Single switch auto-select (recommended)** | `lro` (reuse existing key) | `0`=off; `1`=enable (hardware first, auto-fallback to software if unsupported) | User only needs one switch, semantics symmetric with `tso`, auto-select; old config zero regression | User can't "force hardware only" or "force software only" (but this is advanced need, can add later) |
| **Option B: Independent software switch** | `lro` + new `sw_lro` | `lro`=hardware LRO switch; `sw_lro`=software LRO switch (orthogonal) | User can precisely control hardware/software; debug-friendly | Two switch combination semantics need user understanding; `lro=1 && sw_lro=1` mutual exclusion needs additional adjudication; new config item |
| **Option C: Three-state single key** | `lro` | `0`=off; `1`=hardware preferred + software fallback; `2`=force software | One key covers three states; can force software (debug/no-hardware-certain scenarios) | Value `2` semantics obscure; `atoi` needs range validation; asymmetric with `tso`'s 0/1 binary |

### 2.2 Recommended Option A (Single Switch Auto-Select) + Internal Software Fallback Flag

**Recommend A**, rationale:

1. **Fully symmetric with existing `tso` semantics**: `tso=0/1`, `lro=0/1`, consistent user mental model (`05` doc 1.1 already defines `lro=0` default).
2. **Zero new config items**: Don't introduce `sw_lro`; `config.ini` has only one `lro` (`config.ini:24` already has `lro=0`), conforms to "config.ini minimal changes + local test values not committed" convention.
3. **Auto-select**: When `lro=1`, hardware first, auto-fallback to software if unsupported, transparent to user, no need to understand hardware/software differences.
4. **Software fallback flag internalized**: `sw_lro_enabled` is **internal derived state** (not exposed to config.ini), derived in `ff_dpdk_if.c` detection block from `dpdk.lro && !hw_features.rx_lro`, placed in `ff_dpdk_if_context` or per-lcore context, consumed by `ff_veth_input` (doc 11 2.3).

**Internal state derivation (design)**:

```c
/* ff_dpdk_if.c port setup, within LRO detection block (extension of 04 doc 1.2) */
if (ff_global_cfg.dpdk.lro) {
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO) {
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_LRO;
        /* max_lro_pkt_size setting see 04 doc 1.3 */
        pconf->hw_features.rx_lro = 1;      /* hardware LRO */
        pconf->sw_lro_enabled = 0;          /* don't use software */
        ff_log(..., "LRO: hardware\n");
    } else {
        pconf->hw_features.rx_lro = 0;
        pconf->sw_lro_enabled = 1;          /* fallback to software LRO (doc 11) */
        ff_log(..., "LRO: hardware not supported, fallback to software\n");
    }
} else {
    pconf->hw_features.rx_lro = 0;
    pconf->sw_lro_enabled = 0;
    ff_log(..., "LRO: disabled\n");
}
```

- **`sw_lro_enabled` field placement**: Design placed in `ff_dpdk_if_context` (`ff_veth_input` can directly access via `ctx`) or per-lcore context; **not in** `ff_hw_features` (`ff_hw_features` is per-port hardware capability description shared with config, software fallback is a runtime strategy, semantically should be separated). **Coding phase verify** `ff_dpdk_if_context` struct definition location and align.
- **Upgrade path to B/C**: Option A doesn't block future extension — if subsequent debugging needs "force software/force hardware", can add `sw_lro` independent switch (Option B) or value `2` (Option C); at that point `sw_lro_enabled` derivation logic extends, A's default behavior unchanged.

### 2.3 Why B/C Not Recommended (This Round)

- **B (independent sw_lro)**: New config.ini item violates minimal changes; `lro=1 && sw_lro=1` needs additional mutual exclusion adjudication; high user cognitive burden. **During debugging** if truly need force software, can temporarily use Option C's approach or code-level switch, no need to固化 as config item.
- **C (three-state)**: `lro=2` semantics obscure, asymmetric with `tso` binary, needs range validation; "force software" is niche advanced need, not worth making main switch complex.

---

## 3. Receive/Transmit Path Offload Flag Passthrough and Coordination

### 3.1 Receive Direction (LRO) Flag Passthrough

| Step | Hardware LRO | Software LRO |
| --- | --- | --- |
| PMD output | Large segment mbuf (large `pkt_len`, possibly `nb_segs>1`, `ol_flags & RTE_MBUF_F_RX_LRO`) | Normal per-packet mbuf |
| csum validation | PMD has validated aggregated segment, sets `RTE_MBUF_F_RX_L4_CKSUM_GOOD/BAD` | Normal packet csum, `ff_veth_input:1710-1715` check |
| `ff_veth_input` | Moves into FreeBSD mbuf via `pkt_len` + multi-segment traversal (`04` doc 1.4, length dimension supported) | Per-packet `ff_mbuf_gethdr` then hand to `tcp_lro_rx` for aggregation (doc 11 2.3) |
| Deliver to protocol stack | Direct `if_input` large segment | `tcp_lro_rx` aggregates then LRO flush delivers large segment |
| ifnet capability | `IFCAP_LRO` (`ff_veth.c:945-947`, `rx_lro` driven) | Also needs `IFCAP_LRO` (condition extension see 3.3) |

- **`RTE_MBUF_F_RX_LRO` passthrough**: Hardware LRO large segments carry this flag, but FreeBSD `if_input` receives per mbuf length; `RTE_MBUF_F_RX_LRO` passthrough is **not required** for protocol stack reception (`04` doc 1.4 already demonstrated), first version can skip passthrough. Software LRO produced large segments don't have this flag (merged by LRO engine on protocol stack side), also doesn't affect reception.

### 3.2 Transmit Direction (TSO) Flag Passthrough

| Step | Hardware TSO (`tso=1` and PMD supports) | Software Segmentation (`tso=0` or PMD unsupported) |
| --- | --- | --- |
| Protocol stack | Sends large segment, sets `CSUM_TSO` + `tso_segsz` (`tcp_output.c`) | Sends segment by segment, doesn't set `CSUM_TSO` |
| `ff_mbuf_tx_offload` | `ff_veth.c:305` takes `tso_seg_size` | `CSUM_TSO` not set, `tso_seg_size=0` |
| Transmit offload population | `ff_dpdk_if.c:2455` / `ff_memory.c:358` TSO branch sets `RTE_MBUF_F_TX_TCP_SEG` + pseudo-header + `l2/l3/l4_len/tso_segsz` (`04` doc 2.1 branches by version) | `if (offload.tso_seg_size)` not entered, normal transmission |
| PMD | Hardware segments | Receives already MSS-segmented, sends directly |

- **Passthrough self-consistency**: Transmit direction TSO flag passthrough is entirely driven by `CSUM_TSO` (protocol stack) → `tso_seg_size` (`ff_mbuf_tx_offload`) → `RTE_MBUF_F_TX_TCP_SEG` (transmit population) one-way chain; when NIC has no TSO, entire chain automatically skips (doc 12 2.2).

### 3.3 IFCAP_LRO Setting Condition Unification (Software/Hardware Coordination Key Change Point)

**Current**: `ff_veth.c:945-947` only drives `IFCAP_LRO` by `hw_features.rx_lro`:
```c
if (cfg->hw_features.rx_lro) {
    if_setcapabilitiesbit(ifp, IFCAP_LRO, 0);
}
```

**Problem**: When software LRO enabled (`sw_lro_enabled=1`, `hw_features.rx_lro=0`), this condition doesn't hold, `IFCAP_LRO` not declared, protocol stack doesn't consider interface supports LRO segment reception → software LRO aggregated large segments may be abnormally handled by protocol stack.

**Unified solution**: `IFCAP_LRO` setting condition extended to "hardware LRO effective **or** software LRO enabled":
```c
if (cfg->hw_features.rx_lro || <software LRO enabled flag>) {
    if_setcapabilitiesbit(ifp, IFCAP_LRO, 0);
}
```

- **Software LRO flag visibility issue**: `ff_veth.c` capability setting block parameter is `cfg` (`ff_hw_features`), while `sw_lro_enabled` is designed in `ff_dpdk_if_context` (2.2). **Coding phase needs to verify** whether `ff_veth.c:942-961` can access `sw_lro_enabled`:
  - **Option 1**: Include software LRO enabled flag in `ff_hw_features` (add `uint8_t sw_lro;`), then `ff_veth.c` can directly check `cfg->sw_lro` — **cost**: `ff_hw_features` adds field (`ff_config.h:112-118`).
  - **Option 2**: `ff_veth.c` reads via other means (`ctx`/global cfg).
  - **Recommend Option 1**: Semantically clear (`ff_hw_features` describes "interface's finally effective offload capabilities", software LRO is also an effective capability), and `ff_veth.c` consumer unified (parallel to `rx_lro`/`tx_tso`). At this point 2.2's `sw_lro_enabled` is `hw_features.sw_lro`. **Coding phase final decision on field placement**.

> **Decision convergence**: Combining 2.2 and 3.3, **recommend placing software LRO enabled flag in `ff_hw_features` (add `uint8_t sw_lro;`)**, parallel to `rx_lro` (hardware) and mutually exclusive. This way: detection block (`ff_dpdk_if.c`) unified population, `ff_veth.c` unified consumption, `ff_veth_input` gates software aggregation via `ctx->hw_features.sw_lro`. Both satisfies mutual exclusion semantics and keeps single consumer point.

---

## 4. Software LRO and Hardware LRO Mutual Exclusion/Stacking Analysis

### 4.1 Must Be Mutually Exclusive (Cannot Stack)

**Conclusion: Hardware LRO and software LRO are strictly mutually exclusive; only one enabled at any time.**

- **Technical reason**: When hardware LRO enabled, PMD delivers already-aggregated large segments (`ol_flags & RTE_MBUF_F_RX_LRO`, large `pkt_len`). If `tcp_lro_rx` software aggregation is called again on this large segment in `ff_veth_input`:
  - Double aggregation of already-aggregated large segments, no additional benefit (hardware already merged);
  - Large segments may exceed software LRO's `TCP_LRO_LENGTH_MAX` (`tcp_lro.h:200` = `65535-255`), triggering LRO engine anomaly/rejection path for超长 segments;
  - Semantic confusion (who is responsible for aggregation boundaries).
- **Guarantee mechanism**: Per 2.2's derivation logic, `hw_features.rx_lro` and `hw_features.sw_lro` (software) are **mutually exclusive assignment** in detection block (hardware supports→rx_lro=1,sw_lro=0; unsupported and lro=1→rx_lro=0,sw_lro=1; lro=0→both 0), guaranteeing from source that only one is 1 at any time.

### 4.2 Mutual Exclusion Truth Table

| `dpdk.lro` | PMD Hardware LRO Capability | `hw_features.rx_lro` | `hw_features.sw_lro` | `ff_veth_input` Behavior |
| --- | --- | --- | --- | --- |
| 0 | any | 0 | 0 | No LRO, original path (zero regression) |
| 1 | supported | 1 | 0 | Hardware LRO large segment direct delivery |
| 1 | unsupported | 0 | 1 | Software `tcp_lro_rx` aggregation (doc 11) |

- **`IFCAP_LRO`**: Declared when either `rx_lro` or `sw_lro` is 1 (3.3).
- **Receive gating**: In `ff_veth_input` `if (ctx->hw_features.sw_lro) tcp_lro_rx(...)`; when hardware LRO, `sw_lro=0` doesn't enter software aggregation, large segment goes original path delivery.

### 4.3 No Legitimate "Stacking" Scenario

- The only theoretical "stacking" is tunnel scenario (outer hardware doesn't aggregate, inner software aggregates), but F-Stack currently doesn't involve tunnel inner TCP termination, no such need. This round explicitly **doesn't support stacking**.

---

## 5. Zero Regression Guarantee (When All Default Off, Byte-for-Byte Identical to Current)

### 5.1 LRO Zero Regression

When `dpdk.lro=0` (default, `config.ini:24`):
- `ff_dpdk_if.c` detection block `if (dpdk.lro)` not entered → `hw_features.rx_lro=0`, `sw_lro=0`, `rxmode.offloads` doesn't include LRO bit.
- `ff_veth.c:945` `if (cfg->hw_features.rx_lro || sw_lro)` doesn't hold → doesn't set `IFCAP_LRO`.
- `ff_veth_input` (`ff_dpdk_if.c:1707`) `if (ctx->hw_features.sw_lro)` not entered → receive path **has no LRO branches whatsoever**, byte-for-byte identical to current (`ff_mbuf_gethdr` → multi-segment attach → `if_input`).

**Conclusion: `lro=0` receive path completely identical to current, zero regression.**

### 5.2 TSO Zero Regression

When `dpdk.tso=0` (default, `config.ini:22`) (doc 12 / `05` doc section 8):
- `ff_dpdk_if.c` TSO detection block not entered → `hw_features.tx_tso=0`.
- `ff_veth.c:955` `if (cfg->hw_features.tx_tso)` not entered → doesn't set `IFCAP_TSO`/`CSUM_TSO`/`if_hw_tsomax*`.
- Protocol stack doesn't set `CSUM_TSO` → `ff_mbuf_tx_offload` (`ff_veth.c:305`) `tso_seg_size=0` → transmit TSO branch (`ff_dpdk_if.c:2455` / `ff_memory.c:358` `if (offload.tso_seg_size)`) not entered.
- IPv6 branching/IP_CKSUM self-consistency/duplicate convergence etc. new logic (`04` doc section 2) all hang under TSO branch, not touched when `tso=0`.

**Conclusion: `tso=0` transmit path identical to current; new IPv6 branching etc. logic only effective when `tso=1` and PMD supports.**

### 5.3 Zero Regression Verification Method (Test Milestone)

- **Static**: Under default config.ini (`tso=0`, `lro=0`), all new code branches unreachable (hanging under `if (dpdk.lro)`/`if (tx_tso)`/`if (sw_lro)`/`if (offload.tso_seg_size)`).
- **Dynamic** (`07-test-and-acceptance-specification.md`): Under default config, receive/transmit function and performance baseline aligned with pre-change (**pending runtime validation**).

---

## 6. Integration Change Points Summary Table (File:Function:Line)

> "Change points" are design descriptions, not actual changes. All `file:line` include code verification locations; use latest code as authoritative during coding (read_file first).

### 6.1 Hardware LRO (`04`/`05` docs detailed, summarized here)

| Change Point | File:Function:Line | Action |
| --- | --- | --- |
| Config item | `config.ini:24` (`lro=0` already exists) | Keep default 0 |
| Struct member | After `ff_config.h:295` (dpdk struct) | Add `int lro;` (if not yet added) |
| Parsing | `ff_config.c` `ini_parse_handler` (near tso branch) | Add `MATCH("dpdk","lro")` |
| Hardware detection | `ff_dpdk_if.c` LRO detection block | Remove `#if 0`, change macro `RTE_ETH_RX_OFFLOAD_TCP_LRO`, set `rx_lro`/`max_lro_pkt_size` |
| ifnet capability | `ff_veth.c:945-947` (`IFCAP_LRO` already exists, driven by `rx_lro`) | Extend condition to `rx_lro \|\| sw_lro` (see 3.3) |

### 6.2 Software LRO (doc 11)

| Change Point | File:Function:Line | Action |
| --- | --- | --- |
| Software fallback flag | `ff_config.h:112-118` (`ff_hw_features`) | Add `uint8_t sw_lro;` (3.3 decision) |
| Flag derivation | `ff_dpdk_if.c` LRO detection block | `lro=1 && !hardware supported` → `sw_lro=1` (2.2) |
| lro_ctrl field | `ff_dpdk_if_context` or per-lcore context | Add `struct lro_ctrl lro` (doc 11 2.2) |
| Initialization | Port/lcore init path | `tcp_lro_init(&lro)` (classic mode), bind `lro.ifp` |
| Receive integration | `ff_veth_input` (after `ff_dpdk_if.c:1720`) | `if (sw_lro) tcp_lro_rx(&lro, hdr, 0)` (doc 11 2.3) |
| Batch-end flush | Receive batch loop end | `tcp_lro_flush_inactive` (**not** `tcp_lro_flush_all`, avoids `tcp_lro.c:1261` NULL bare-call) |
| Free | Port/lcore cleanup path | `tcp_lro_free(&lro)` |
| ifnet capability | `ff_veth.c:945` (same as 6.1) | Condition includes `sw_lro` |

### 6.3 Hardware TSO Enhancement (`04` doc section 2, this round's real TSO work)

| Change Point | File:Function:Line | Action |
| --- | --- | --- |
| IPv6 branching | `ff_dpdk_if.c:2467-2491` (`:2452-2466` are comments), `ff_memory.c:358-368` | Branch pseudo-header/`l3_len` by `iph->version` (`04` doc 2.1) |
| IP_CKSUM self-consistency | Same | IPv4 TSO branch explicitly sets `RTE_MBUF_F_TX_IP_CKSUM` |
| tsomax verification | `ff_veth.c:958-960` (`IP_MAXPACKET`/`35`/`2048` already set) | Verify whether matches target PMD (**pending runtime validation**) |
| Duplicate convergence | `ff_dpdk_if.c:2405-2472`, `ff_memory.c:331-375` | Extract common function (`04` doc 2.4 Option A) |
| CSUM_IP6_TSO | `ff_veth.c:305` | Extend `CSUM_TSO \| CSUM_IP6_TSO` (verify macro relationship) |

### 6.4 Software TSO / rte_gso

| Change Point | Conclusion |
| --- | --- |
| Software TSO | **No changes** (protocol stack MSS segmentation inherent, doc 12) |
| rte_gso | **Not introduced this round** (optional optimization, future evaluation) |

---

## 7. Software/Hardware Integration Data Flow Overview

```
                        ┌───────────────── config.ini ─────────────────┐
                        │  tso=0 (L22)      lro=0 (L24)   csum_skip=0(L19) │
                        └──────────────────┬────────────────────────────┘
                                           │ ff_config.c parsing
                                           ▼
        ┌──────────── ff_dpdk_if.c port setup (capability detection gating)────────────┐
        │  TSO: if(dpdk.tso) && (tx_offload_capa & TCP_TSO)              │
        │         → hw_features.tx_tso=1                                 │
        │  LRO: if(dpdk.lro):                                            │
        │         rx_offload_capa & TCP_LRO ? hw_features.rx_lro=1       │
        │                                    : hw_features.sw_lro=1(fallback)│
        └──────────────────┬────────────────────────────┬──────────────┘
                Receive(RX/LRO)  │                            │  Transmit(TX/TSO)
                                  ▼                            ▼
   ┌── ff_veth_input (ff_dpdk_if.c:1707) ──┐   ┌── tcp_output → ff_mbuf_tx_offload ──┐
   │  Hardware LRO: large segment direct chain delivery    │   │  Hardware TSO(tx_tso): CSUM_TSO+tso_segsz │
   │  Software LRO(sw_lro): tcp_lro_rx aggregation          │   │    → ff_dpdk_if.c:2455 branch by version  │
   │    (doc 11, classic mode avoids 1261 NULL)             │   │  Software segmentation(tso=0/no hardware): protocol stack per-segment │
   └───────────────┬───────────────────────┘   └───────────────┬───────────────────┘
                   ▼                                            ▼
        ff_veth.c:945 IFCAP_LRO (rx_lro||sw_lro)      ff_veth.c:955 IFCAP_TSO+tsomax(tx_tso)
                   ▼                                            ▼
              FreeBSD protocol stack receives large segment    PMD hardware segments / already-segmented direct send
```

---

## 8. Honest Boundary (Pending Runtime Validation Checklist)

1. Whether local virtio `dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO` is 0 (determines hardware vs software LRO fallback).
2. `ff_dpdk_if_context` / `ff_hw_features` struct final placement of `sw_lro` field (3.3 recommends including in `ff_hw_features`, verify during coding).
3. Feasibility of `ff_veth.c:945-961` capability setting block accessing `sw_lro` (verify during coding).
4. Consistency of software/hardware LRO mutual exclusion derivation logic under multi-process/multi-lcore.
5. Whether `ff_veth.c:958-960` current tsomax values (`IP_MAXPACKET`/`35`/`2048`) match target PMD.
6. Under default all-off (`tso=0`/`lro=0`), receive/transmit function and performance byte-for-byte/metric-for-metric identical to pre-change (zero regression dynamic verification).

> All the above are runtime/subsequent milestone validation items, not tested this round. Test environment: DPDK dedicated NIC IP `<DPDK_NIC_IP>` (`ssh f-stack-client` side initiates), kernel stack testing via `127.0.0.1` on `lo`.

---

## 9. This Document's Conclusion Summary

1. **Integration's only substantive gap = software LRO not integrated into `ff_veth_input` (`ff_dpdk_if.c:1707`)**; transmit side TSO has no gap (`CSUM_TSO` gating naturally consistent).
2. **Switch semantics recommends Option A (single `lro` switch auto-select)**: `lro=0` off / `lro=1` hardware preferred + software fallback; software fallback flag internally derived (recommend including in `ff_hw_features.sw_lro`), no new config.ini item, symmetric with `tso` semantics, zero regression.
3. **Software/hardware LRO strictly mutually exclusive**: Detection block mutually exclusive assignment of `rx_lro`/`sw_lro`, only one enabled at any time, eliminates double aggregation (section 4 truth table).
4. **`IFCAP_LRO` condition needs extension from `rx_lro` to `rx_lro || sw_lro`** (`ff_veth.c:945`), so software LRO also declares capability to protocol stack (3.3).
5. **Zero regression guarantee**: When `lro=0`/`tso=0`, all new branches unreachable, byte-for-byte identical to current (section 5).
6. **Change points summary in section 6 table**; software TSO has no changes, rte_gso not introduced this round.
