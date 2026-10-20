# Phase-2 M11/M12/M13 Joint Spec — P2 Smoke Trio

> Chinese version: ./zh_cn/phase2-M11-M13-spec.md (authoritative)

> Status: DRAFT → ready
> Upstream basis: M10 commit `90c730496`
> Complexity: S (combines three P2 single-flag smokes; rte_flow fallback follows the M10 pattern)

---

## 1. Goal

Per plan priority, **P2 = build + primary stack-up + docs** is enough (no functional/hardware dependence required):

- **M11 — FF_FLOW_ISOLATE** (enabled alone)
- **M12 — FF_FDIR** (enabled alone)
- **M13 — FF_LOOPBACK_SUPPORT** (enabled alone)

Combined into one spec + sequential execution + one commit per milestone.

---

## 2. Design

### 2.1 Known rte_flow dependencies (continue the M10 pattern)

| Flag | rte_flow call | Line | Current failure behavior |
|---|---|---|---|
| FF_FLOW_ISOLATE | `port_flow_isolate(0,1)` | ff_dpdk_if.c:1407-1408 | rte_exit |
| FF_FLOW_ISOLATE | `init_flow(0, 80)` | ff_dpdk_if.c:1432-1435 | rte_exit |
| FF_FDIR | `fdir_add_tcp_flow(0, 0, FF_FLOW_INGRESS, 0, 80)` | ff_dpdk_if.c:1463-1465 | rte_exit |
| FF_LOOPBACK_SUPPORT | (only at ff_dpdk_if.c:2423 software-loopback mbuf path; doesn't depend on rte_flow) | – | – |

### 2.2 Fix strategy

Same as M10's `create_ipip_flow`: change the 4 `rte_exit` sites to `printf` warnings so the primary still comes up on NICs without rte_flow hardware support.

---

## 3. Acceptance Criteria

| ID | Criterion |
|---|---|
| AC-M11-1..3 | with FF_FLOW_ISOLATE=1 alone, lib build PASS, helloworld primary alive ≥12 s no panic |
| AC-M12-1..3 | with FF_FDIR=1 alone, same |
| AC-M13-1..3 | with FF_LOOPBACK_SUPPORT=1 alone, same |
| AC-Mxx-doc | each milestone has its own anchor sentence + its own commit |

---

## 4. Risks

| ID | Risk | Mitigation |
|---|---|---|
| R-Mxx-1 | rte_flow fallback edits may affect future deployments enabling other flow flags on hardware-capable NICs | comment explicitly: fallback only takes effect when hardware doesn't support; the ret=0 path stays intact when it does |
| R-Mxx-2 | The LOOPBACK path's software-loopback mbuf may interact with PA/ZC | for M13 testing, disable PA/ZC (same as M10) |

---

## 5. Workflow (5 same steps per milestone)

1. Enable the corresponding Makefile line (M10-style PA/ZC commented out).
2. Convert the 4 `rte_exit` sites to `printf` warnings in one go (folded into the first M11 commit; M12/M13 reuse).
3. Rebuild lib + example → G1 PASS.
4. Stack-up alive ≥12 s → G2 PASS.
5. Doc anchor + commit.

---

> Next: start M11.
