# 00 - Issue Original Text and Requirements Analysis

## Summary

F-Stack upstream issue #1078 "primary stability control" raises: DPDK multi-process mode has excessive stability dependency on primary process — secondary crashes can be individually restarted without affecting other processes, but primary abnormal exit requires entire process group restart, all connections affected. Proposes separating/"slimming" primary to only do NIC queue config, binding, initialization (control plane), moving packet reception and subsequent processing entirely to secondary, to reduce primary anomaly probability and narrow fault impact. This document archives original text, breaks down requirements item by item, provides success criteria and investigation boundaries.

## Key Conclusions

1. Issue requirements can be decomposed into **two independently assessable sub-goals**: (a) reduce primary anomaly probability (slimming); (b) narrow primary anomaly impact (decoupling). Their feasibility and cost differ significantly; must be adjudicated separately.

2. Issue's premise assumption "secondary anomaly can be restarted without affecting other processes" verified **valid** by hands-on testing (see `05-实机对照实验报告.md` E2d).

3. Issue's implicit assumption "primary anomaly affects all connections" verified **only partially valid**: after primary exits, secondary processes **survive and continue serving connections on their RSS queues**; affected traffic is that hashed to primary's queue (see E2/E2b).

4. **(Corrected per subsequent experiments)** Previously inferred from E2c that "primary exit prevents secondary restart, recovery path blocked" — this inference was **wrong**: E2e proves that as long as at least one process holds `/dev/uioX` (uio refcnt ≥ 1), secondary **can** restart successfully without primary; E2c's actual root cause was entire process group exited (refcnt → 0 → `pci_clear_master()` stops device DMA). Residual boundary from E10: primary itself **cannot be restarted in place** (EAL `Cannot allocate memzone list`); process group stays in control-plane degraded state, needs **opportunistic** full group restart.

5. **Final verdict: "conditionally feasible, recommended for adoption"**: PoC measured only 3 lines code + 1 config item; after killing slim primary, established connections 12/12 zero interruption, new connections 12/12, no performance regression (see `05` section 11 E3 series, `10-可行性结论与建议.md`).

6. This round is feasibility investigation only; no production feature implementation; PoC patch is evidence-only, not for formal commit.

## I. Issue Original Text Archive

- Source: F-Stack GitHub Issue #1078
- Title: primary stability control
- Submitter: hei1046035362
- Submitted: 2026-07-03
- Status: Open, **no comments, no associated PR**
- Link: `https://github.com/F-Stack/f-stack/issues/1078`

Original text (verbatim):

> Want to ask if you have plans to separate primary? In DPDK multi-process mode, stability dependency on primary is very high. If secondary crashes, it can be restarted without affecting other processes' queues and established connections. But if primary exits abnormally, the entire process group must be restarted, all connections affected. If primary is separated to only do simple NIC queue setup, binding, initialization, and secondary does packet reception and subsequent operations, primary would be less likely to crash, and connection impact scope would be smaller.

## II. Requirements Breakdown

| No. | Original Text Fragment | Technical Meaning | Nature |
|-----|----------------------|-------------------|--------|
| R1 | "plans to separate primary" | Ask about upstream roadmap | Informational |
| R2 | "stability dependency on primary is very high" | Current state: primary is single point | To verify |
| R3 | "secondary crashes can be restarted, not affecting other processes" | Premise A | Verified → **E2d valid** |
| R4 | "primary exits, entire group must restart, all connections affected" | Premise B | Tested → **Partially invalid** |
| R5 | "separate primary, only NIC queue setup, binding, init" | Solution: primary → pure control plane | Core feasibility |
| R6 | "secondary does packet reception and subsequent operations" | Solution: data plane to secondary | Core feasibility |
| R7 | "primary less likely to crash" | Benefit 1: reduce fault probability | Qualitative assessment |
| R8 | "smaller connection impact scope" | Benefit 2: narrow impact | Align with E2/E2c |

### Two Sub-Goal Separation

- **Sub-goal (a) reduce probability**: Make primary not run protocol stack, not receive/send packets, not carry business; its code path shrinks significantly, anomaly probability decreases. This is **statistical improvement**, doesn't change "primary is single point" structural fact.

- **Sub-goal (b) narrow impact**: Make primary not hold any rx/tx queues when it exits, so no "orphan queues." Otherwise queues become unpolled, traffic to those queues black-holed.

## III. Success Criteria

| Criterion | Content | Verification |
|-----------|---------|-------------|
| C1 | Both premises (R3/R4) have hands-on data support | `05` experiment report |
| C2 | Each blocking point has precise `file:line` and code snippet | `02` blocking point list |
| C3 | DPDK hard constraints have official docs/source basis | `01` part 1 |
| C4 | Solution design provides change point list and risks, alternatives have rejection reasons | `03`/`04` |
| C5 | If sub-goal (b) unreachable, conclusion must honestly downgrade | `10` final verdict + `09` gate review |
| C6 | All docs no real IP, no direct rm/kill/chmod, config.ini not committed | `09` compliance check |

### Three-Tier "Feasible" Definition

- **Feasible**: Both (a) and (b) achievable, change volume and risk acceptable
- **Conditionally feasible**: (a) achievable; (b) achievable under specific prerequisites (e.g., must disable KNI, must have ≥2 secondaries)
- **Infeasible**: (b) has unbypassable DPDK constraint, and (a)'s benefit insufficient to justify cost

## IV. Investigation Boundaries (Honest Boundaries)

**This round does**:
- Read code to verify blocking points; research DPDK official constraints and upstream/similar projects; hands-on experiments; solution design and alternatives; coding work breakdown and test specs; independent gate review.

**This round does not**:
- No production feature implementation; no functional changes to `lib/` production code path
- PoC patch is **investigation evidence** only, not for formal commit
- No English documentation (pending Chinese version audit)
- No config.ini commit (local test values stay in workspace only)

**Known limitations**:
- Test environment: single DPDK port + 2 processes (`lcore_mask=3`) virtualization (virtio devices), not physical multi-queue high-end NIC. RSS distribution, PMD multi-process behavior may differ on other PMDs.
- Test uses `example/helloworld` (HTTP keep-alive), may not represent all nginx production behaviors.

## V. Related Document Index

| Document | Purpose |
|----------|---------|
| `01-外网调研与交叉验证.md` | DPDK official multi-process constraints, upstream community research, similar project comparison |
| `02-架构代码探测与阻塞点清单.md` | primary/secondary responsibility boundary, B1~B8 blocking points, key call chains |
| `03-方案设计与备选对比.md` | `lcore_list` reuse solution design and alternative comparison |
| `04-KNI与控制流归属方案.md` | KNI three candidate paths, control-plane operation reassignment |
| `05-实机对照实验报告.md` | E1/E2/E2b/E2c/E2d test data and conclusions (**decisive evidence**) |
| `06-性能基线对照报告.md` | Pre/post PoC data-plane performance comparison |
| `07-后续编码工作分解.md` | If feasible, itemized change list and sequence |
| `08-测试规格.md` | Unit/integration/performance baseline test cases and acceptance criteria |
| `09-审核门禁报告.md` | Independent review conclusion (PASS / NEEDS_CHANGES) |
| `10-可行性结论与建议.md` | Final verdict and upstream issue reply suggestion |
