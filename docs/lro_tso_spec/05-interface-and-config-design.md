# F-Stack LRO/TSO Interface and Config Design

> Document tier: Interface and config design (M3 phase deliverable 2)
> Design basis: `04-solution-and-architecture-design.md`. This document translates the solution into **specific file change points, interface contracts, return codes, default policies** for direct reference by subsequent coding milestones.
> Iron rule: This round **does not write code, does not change lib, does not commit**. The following "change points" are design descriptions, not actual changes; all `file:line` include code verification locations; use latest code as authoritative during coding (read_file first).

---

## I. config.ini Change Design

### 1.1 Add `[dpdk] lro` Option

**Position**: `[dpdk]` section, adjacent to `tso=0` (`config.ini:22`), aligned with tso style (comment + key-value, default off).

**Design content** (comment form explaining semantics):
```ini
# TCP large receive offload, default: disabled.
lro=0
```

**Constraints (config.ini local test values not committed convention)**:
- Committed default value must be `lro=0`. If locally changed to `lro=1` for running/debugging, must roll back to `0` before commit.
- This option is semantically symmetric with `tso=0`: `0`=off (default, zero regression), `1`=attempt to enable (gated by PMD capability).

**Compatibility**: When old config.ini has no `lro` option, parsing doesn't hit `MATCH("dpdk","lro")`, `dpdk.lro` keeps default `0` (see 3.2 default policy), behavior identical to current status.

---

## II. ff_config.h Change Design

### 2.1 `struct ff_hw_features` (`ff_config.h:112-118`)

- **`uint8_t rx_lro;` (L114) already exists**, no need to add. This round activates it from "dead field": production point in `ff_dpdk_if.c` LRO detection block (04-solution-and-architecture-design.md 1.2), consumption point in `ff_veth.c` `IFCAP_LRO` setting (04-solution-and-architecture-design.md 1.5).
- No other `ff_hw_features` changes (`tx_tso` L117 reused for TSO enhancement, no new field).

### 2.2 `struct ... dpdk` (`ff_config.h:288-300`)

- **Add** `int lro;`, after `int tso;` (L295), symmetric with `tso`:
  ```c
  int tso;
  int lro;                 /* TCP large receive offload switch, 0=off */
  int tx_csum_offoad_skip;
  ```
- Type `int` (consistent with `tso`, parsed via `atoi`).

**Contract**: `dpdk.lro` is **user config intent** (0/1); `hw_features.rx_lro` is **actual effective state** (1 only when PMD supports and enabled). The two are separated, consistent with the existing separation pattern of `dpdk.tso` (intent) vs `hw_features.tx_tso` (effective).

---

## III. ff_config.c Change Design

### 3.1 Parsing Branch (`ff_config.c:1054-1057` area)

After `MATCH("dpdk", "tso")` branch (L1054-1055), add:
```c
} else if (MATCH("dpdk", "lro")) {
    pconfig->dpdk.lro = atoi(value);
}
```
- **Contract**: Verbatim symmetric with `tso` parsing (`atoi(value)`).
- **Return**: `ini_parse_handler` returns 1 after hitting assignment branch (success, following the handler's existing return convention; read_file to verify the handler's success return value during coding).

### 3.2 Default Value Setting

- **Requirement**: In the config default init path (`ff_default_config` or struct zeroing + explicit default setting) set `pconfig->dpdk.lro = 0`.
- **Verification todo (coding phase)**: Whether `ff_config.c` has a centralized `ff_default_config` that explicitly sets `tso` default, or relies on memset zeroing. If relying on zeroing, `int lro` is naturally 0, no explicit setting needed; if there's an explicit default block, add `lro=0` alongside tso. During coding, read_file to locate `tso` default assignment and align.
- **Default-off compatibility policy**: Regardless of whether config.ini has `lro` option, `dpdk.lro` defaults to 0, guaranteeing old config zero regression.

**Validation/error handling**: `lro` only does `atoi` (consistent with tso), no range validation (non-0 treated as enabled, final adjudication by PMD capability gating); no new error codes needed.

---

## IV. ff_dpdk_if.c Change Points

### 4.1 LRO Enablement Block Rewrite (`ff_dpdk_if.c:891-898`)

- **Delete** `#if 0 ... #endif` (L892/L898).
- **Change macro**: `DEV_RX_OFFLOAD_TCP_LRO` → `RTE_ETH_RX_OFFLOAD_TCP_LRO` (`rte_ethdev.h:1556`).
- **Add switch gating**: Entire block hangs under `if (ff_global_cfg.dpdk.lro)` (aligned with TSO's `if (ff_global_cfg.dpdk.tso)` L931).
- **Add `max_lro_pkt_size`**: See 4.2.
- **Interface contract**:
  - Input: `dev_info.rx_offload_capa`, `ff_global_cfg.dpdk.lro`.
  - Output: `port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_LRO`, `pconf->hw_features.rx_lro = 1` (only when lro=1 and PMD supports).
  - Log: supported→"LRO is supported"; unsupported→"LRO is not supported"; disabled→"LRO is disabled" (aligned with TSO three-state log L933/938/941).

### 4.2 `max_lro_pkt_size` Setting (within 4.1 block)

- When setting `rx_lro=1`, set `port_conf.rxmode.max_lro_pkt_size`:
  - Prefer `dev_info.max_lro_pkt_size` (`rte_ethdev.h:1792`, PMD-advertised configurable limit).
  - When PMD doesn't advertise (0), take conservative default (not exceeding mbuf capacity, and `>= mtu`).
- **Contract**: `max_lro_pkt_size` must be `>= mtu` (04-solution-and-architecture-design.md 1.3); value must be set in `port_conf.rxmode` before `dev_configure`.

### 4.3 TSO Offload Population IPv6 Branching (`ff_dpdk_if.c:2455-2465`)

- TSO branch branches by `iph->version` (04-solution-and-architecture-design.md 2.1 code):
  - IPv4: `RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM`, `rte_ipv4_phdr_cksum`, `l3_len=iph_len`.
  - IPv6: `RTE_MBUF_F_TX_IPV6` (no IP_CKSUM), `rte_ipv6_phdr_cksum`, `l3_len=40` (no extension headers first version).
- **Self-consistency**: TSO branch explicitly sets `l2_len=RTE_ETHER_HDR_LEN`, `RTE_MBUF_F_TX_TCP_SEG`, `l4_len`, `tso_segsz` within itself, not depending on preceding `ip_csum`/`tcp_csum` branch hitting.
- **Interface contract**: Input is `offload.tso_seg_size` (from `ff_mbuf_tx_offload`) + mbuf data area IP header; output is `head->ol_flags`/`l2_len`/`l3_len`/`l4_len`/`tso_segsz` and TCP pseudo-header checksum.

### 4.4 Duplicate Logic Convergence (`ff_dpdk_if.c:2405-2472` and `ff_memory.c:331-375`)

- Prefer extracting common function (04-solution-and-architecture-design.md 2.4 Option A):
  ```c
  /* Suggested signature (placed in a common position both can include) */
  void ff_fill_tx_offload(struct rte_mbuf *head, void *data,
                          const struct ff_tx_offload *offload,
                          uint8_t tx_csum_l4);
  ```
- Both call sites (`ff_dpdk_if.c:2410-2472`, `ff_memory.c:326-375`) change to call this function.
- If cross-compilation-unit dependencies are complex, fall back to Option B (synchronize both + cross-reference comments).

---

## V. ff_veth.c Change Points

### 5.1 `IFCAP_LRO` Setting (`ff_veth.c:941-956`)

- Add to capability setting block (parallel to `IFCAP_TSO` L951-953):
  ```c
  if (cfg->hw_features.rx_lro) {
      if_setcapabilitiesbit(ifp, IFCAP_LRO, 0);
  }
  ```
- `if_setcapenable(ifp, if_getcapabilities(ifp))` (L956) auto-enables.
- **Contract**: Only declared when `rx_lro=1` (04-solution-and-architecture-design.md 1.2 production); LRO receive direction has no hwassist requirement.

### 5.2 `if_hw_tsomax` Series Setting (within `ff_veth.c:951-953` TSO block)

- After `IFCAP_TSO` setting, add three limits (04-solution-and-architecture-design.md 2.3):
  ```c
  if_sethwtsomax(ifp, <total length limit>);
  if_sethwtsomaxsegcount(ifp, <segment count limit>);
  if_sethwtsomaxsegsize(ifp, <segment size limit>);
  ```
- **Verification todo (coding phase)**: The exact API names `if_sethwtsomax`/`if_sethwtsomaxsegcount`/`if_sethwtsomaxsegsize` per FreeBSD 15.0 port `freebsd/net/if.h`/`if_var.h` actual exports (some versions use `ifp->if_hw_tsomax = ...` direct assignment). read_file to verify and select correct interface.
- **Value contract**: All three must be **non-0** (when 0, `tcp_output.c:927` doesn't take effect, falls back to unconstrained); values follow 04-solution-and-architecture-design.md 2.3 principles (total length ≤ IP_MAXPACKET dimension, segcount/segsize conservative defaults + runtime calibration).

### 5.3 `ff_mbuf_tx_offload` Compatible with `CSUM_IP6_TSO` (`ff_veth.c:304-306`)

- Extend TSO recognition (04-solution-and-architecture-design.md 2.6):
  ```c
  if (mb->m_pkthdr.csum_flags & (CSUM_TSO | CSUM_IP6_TSO)) {
      offload->tso_seg_size = mb->m_pkthdr.tso_segsz;
  }
  ```
- **Verification todo (coding phase first item)**: Confirm `CSUM_IP6_TSO` and `CSUM_TSO` macro bit relationship (`freebsd/sys/... mbuf` header). If `CSUM_IP6_TSO` already includes `CSUM_TSO` bit, this change can be omitted; if independent bit, required.

---

## VI. Interface Contract Summary Table

| Interface/Variable | Type/Location | Producer | Consumer | Contract |
| --- | --- | --- | --- | --- |
| `dpdk.lro` | `int`, `ff_config.h` dpdk struct (new, after L295) | `ff_config.c` parsing (new MATCH); default 0 | `ff_dpdk_if.c:891` detection block | 0=off (default zero regression), 1=attempt enable |
| `hw_features.rx_lro` | `uint8_t`, `ff_config.h:114` (existing) | `ff_dpdk_if.c` LRO detection (new set 1) | `ff_veth.c` IFCAP_LRO (new consume) | 1 only when lro=1 and PMD supports |
| `rxmode.offloads` LRO bit | DPDK `port_conf` | `ff_dpdk_if.c:891` block | DPDK `dev_configure` | Only set PMD `rx_offload_capa` advertised bits |
| `rxmode.max_lro_pkt_size` | `uint32_t` `rte_ethdev.h:432` | `ff_dpdk_if.c:891` block (new) | DPDK PMD | `>= mtu`; prefer `dev_info.max_lro_pkt_size` |
| `IFCAP_LRO` | ifnet capability bit | `ff_veth.c:941-956` (new) | FreeBSD protocol stack | Declares interface supports LRO segment receive |
| TSO offload fields | mbuf `ol_flags`/`l2_len`/`l3_len`/`l4_len`/`tso_segsz` | `ff_dpdk_if.c:2455` / `ff_memory.c:358` (modified: version branching) | DPDK PMD | IPv4 with IP_CKSUM+v4 pseudo-header; IPv6 with v6 pseudo-header no IP_CKSUM |
| `if_hw_tsomax*` | ifnet limits | `ff_veth.c:951` (new) | `tcp_output.c:905-931` | Non-0; constrains TSO segmentation |
| `offload.tso_seg_size` | `ff_tx_offload` | `ff_veth.c:304` (modified: add CSUM_IP6_TSO) | `ff_dpdk_if.c`/`ff_memory.c` TSO branch | Protocol-agnostic, v4/v6 by downstream version check |

---

## VII. Return Codes and Error Handling Design

| Scenario | Handling | Rationale |
| --- | --- | --- |
| config.ini has no `lro` option | Default 0, no error | Old config compatibility |
| `lro=1` but PMD doesn't support | Log "LRO is not supported", `rx_lro` stays 0, continue startup | Consistent with TSO unsupported handling (`ff_dpdk_if.c:938`), not fatal |
| `max_lro_pkt_size` rejected by PMD | `dev_configure`/`rte_eth_dev_start` returns error → follows existing port init error handling (rte_exit/log) | Runtime exposure, not spec phase |
| `tso=1` + `tx_csum_offoad_skip=1` inconsistent combination | Log WARN (04-solution-and-architecture-design.md 2.5), don't change behavior | Avoid changing existing default path |
| IPv6 with extension headers TSO | First version uses l3_len=40, extension header scenario marked for enhancement | Known boundary, doesn't block core |
| `CSUM_IP6_TSO` independent bit not recognized | After coding-phase macro verification, decide whether to extend | See 5.3 |

---

## VIII. Default-Off Compatibility Policy (Zero Regression Guarantee)

1. **LRO**: `dpdk.lro` default 0 → `if (dpdk.lro)` not entered → LRO detection block, `max_lro_pkt_size`, `rx_lro` all ineffective → `ff_veth.c` `if (rx_lro)` doesn't set `IFCAP_LRO` → receive path has no LRO branch changes. **Conclusion: lro=0 byte-for-byte identical to current status**.
2. **TSO**: `tso=0` (default) → `if (dpdk.tso)` not entered → `tx_tso=0` → `ff_veth.c` `if (tx_tso)` doesn't set IFCAP_TSO/tsomax; transmit path `if (offload.tso_seg_size)` depends on `CSUM_TSO`, when `tso=0` protocol stack doesn't set CSUM_TSO → TSO branch not entered. **Conclusion: tso=0 IPv6 branching/tsomax etc. new logic all untouched**.
3. `IFCAP_LRO`/`if_hw_tsomax` both hang under `hw_features` switches; when default off, not declared, not set.

---

## IX. lib Minimal Comment Principle (Coding Constraint)

- New code only adds concise comments at **contracts/non-intuitive points**, e.g.:
  - `dpdk.lro` struct member: one line "TCP large receive offload switch, 0=off".
  - IPv6 TSO branch: one line "IPv6 has no IP header checksum".
  - `max_lro_pkt_size`: one line on value source (dev_info preferred).
- **Prohibited** adding comments to self-explanatory calls like `atoi(value)`, `if_setcapabilitiesbit`.
- Follow existing file comment style (e.g., TSO branch existing large DPDK contract comments `ff_dpdk_if.c:2440-2454` can be retained/reused, not duplicated).
