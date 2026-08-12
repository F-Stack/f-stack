# 06 - Review Gate Report

> Reviewer: gatekeeper (independent review agent)
> Review date: 2026-08-10
> Review scope: All 6 investigation documents (00-05)
> Review method: Code location spot-check + document cross-consistency + constraint compliance check

---

## 1. Review Overview

| Document | Accuracy | Completeness | Constraints | Conclusion |
|----------|----------|-------------|-------------|------------|
| 00-issue original | Pass | Pass | Pass | Pass |
| 01-external research | Pass | Pass | Pass | Pass |
| 02-code investigation | Pass (line number偏差 see §3.1) | Pass | Pass | Conditional pass |
| 03-solution design | Conditional pass (ff_ipc mbuf dependency inaccurate, see §3.2) | Pass | Pass | Conditional pass |
| 04-hands-on test | Pass | Pass | Pass | Pass |
| 05-conclusions | Conditional pass (inherits 03's ff_ipc issue, see §3.2) | Pass | Pass | Conditional pass |

---

## 2. Code Location Spot-Check

### 2.1-2.5 Summary

30+ key code locations spot-checked — all verified accurate (file:line matched). 4 native mechanisms (maxsockets/ipfw limit/somaxconn/syncache) code completeness conclusions reliable.

Key verifications:
- maxsockets: `uma_zone_set_max` at :320/:689, `zone_alloc_item` at :4461, `zone_alloc_limit` at :4311 — all confirmed
- ipfw limit: `O_LIMIT` at :2937, `ipfw_dyn_install_state` at :2025, `DPARENT_COUNT` at :158/:1873 — all confirmed
- somaxconn: `V_somaxconn` at :242, backlog truncation at :1538, queue overflow at :1030 — all confirmed
- syncache: hashsize/bucketlimit at :162/:249, zone max at :295, bucket full at :377 — all confirmed
- mbuf pool: `rte_pktmbuf_pool_create` at :632, formula at :583-593, `message_pool` at :750 — all confirmed
- `rte_mempool_avail`/`rte_mempool_count` search: zero hits (confirms no water level check)

---

## 3. Issues Found

### 3.1 [Low] Document 02 config.ini Line Number Discrepancy

Document 02 references config.ini:346/348-349, actual values at config.ini:327/329-330. Doesn't affect core conclusions (config values and section correct, only line numbers偏差). **Suggestion**: Correct to 327 and 329-330.

### 3.2 [Medium] Documents 03 and 05 ff_ipc mbuf Dependency Description Inaccurate

**Issue**: Documents 03 and 05 claim `ff_mbuf_gethdr()` allocates from DPDK `pktmbuf_pool`, but actual code shows `ff_mbuf_gethdr()` calls `m_gethdr()` which allocates from FreeBSD mbuf UMA zone, **not from DPDK pktmbuf_pool**.

ff_ipc tool side (`tools/compat/ff_ipc.c`) only uses `message_pool`, does not call `ff_mbuf_gethdr`, does not depend on `pktmbuf_pool`.

**Impact**: Document 02's conclusion ("ff_ipc not affected by pktmbuf_pool exhaustion") is **correct**. Documents 03 and 05 tried to "correct" document 02 but introduced new inaccuracy.

issue #1076 user's "ff_ipc netstat also unavailable" likely because f-stack main loop can't reach `process_msg_ring` when mbuf exhausts, indirectly affecting ff_ipc.

**Suggestion**: Correct documents 03 and 05 to state ff_ipc uses independent message_pool, not directly dependent on pktmbuf_pool. F-stack main loop may not reach ff_ipc processing path when mbuf exhausts.

### 3.3 [Low] Document 03 mbuf Pool Size Alignment Calculation Contradiction

Document 03 §2.2: total 33088, "aligned to 8192 → 32768", but 33088 > 32768. `RTE_ALIGN_CEIL` rounds up, so should be 40960. **Suggestion**: Correct to 40960.

### 3.4 [Info] Hands-on Test Not Completed — Honestly Documented

Document 04 honestly records that hands-on testing couldn't complete due to DPDK NIC L2 network connectivity issue. Environment limitation, properly marked.

---

## 4. Gate Conclusion

- [x] **Conditional pass**: Minor issues but doesn't affect core conclusions

**Rationale**:

1. **Accuracy**: 30+ key code locations verified accurate. 4 native mechanisms' code completeness conclusions reliable.

2. **Completeness**: Core requirement (CC limiting solution investigation) fully covered. 4 native mechanisms have code-level verification. Solution design includes 3 tiers. Hands-on test environment limitation honestly stated.

3. **Solution Reasonableness**:
   - Solution A maxsockets calculation method reasonable
   - Solution B insertion point (process_packets entry) reasonable
   - Solution C recommendation well-justified
   - Config examples use placeholder IPs

4. **Constraint Compliance**:
   - No real IP leaks (search `9.134.x.x` and `2402:4e00:` zero hits)
   - All IPs use placeholders (`<DPDK_NIC_IP>`, `<KERNEL_NIC_IP>`, `<CLIENT_IP>`)
   - Hands-on test report honestly states environment limitation

5. **Issues to Fix**:
   - §3.2 ff_ipc mbuf dependency description inaccurate (medium priority, must fix)
   - §3.1 config.ini line numbers (low priority, suggest fix)
   - §3.3 mbuf pool alignment calculation (low priority, suggest fix)

Above issues don't affect core conclusions (4 native mechanisms fully usable, 3-tier solution design reasonable, recommend Solution C). But suggest fixing §3.2 description before user review.
