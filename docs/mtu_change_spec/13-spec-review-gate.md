# Full MTU Modification Support — Spec Review Gate

> This document is a gate checklist for reviewers to check item by item, **not** a review conclusion. Each item must give pass/fail with evidence (file:line/reference). Any item failing bounces back to the previous step per the bounce protocol.

## 1. Consistency with 06 Conclusion

- [ ] The plans in 07–13 are consistent with `06-solution-and-conclusion.md`'s four modification points (config, ff_veth init set mtu, ff_veth_ioctl intercept SIOCSIFMTU, DPDK mbuf/rxmode/scatter).
- [ ] The conclusion "decrease MTU works out of the box, increase requires modification" is not altered by the spec.
- [ ] Investigation docs 00–06 are not modified without authorization.

## 2. Code file:line Consistency

Check spec references against the actual repo item by item (`/data/workspace/f-stack` and DPDK 24.11.6 source):

- [ ] `ff_veth_ioctl()` is at `lib/ff_veth.c:235`, main `switch(cmd)` default branch `ether_ioctl()` (currently no SIOCSIFMTU case).
- [ ] `ff_veth_setup_interface()` is at `lib/ff_veth.c:910`.
- [ ] `struct ff_port_cfg`/`struct ff_config.dpdk` line numbers (`ff_config.h`) consistent with 08/09 references.
- [ ] `ff_config.c`'s `ff_default_config()`, `ini_parse_handler()`, `port_cfg_handler()` line numbers consistent.
- [ ] `ff_dpdk_if.c`'s pool creation, `init_port_start`, `rte_eth_dev_info_get`, configure/queue setup/start line numbers consistent.
- [ ] DPDK ethdev field/interface line numbers (`rte_eth_rxmode.mtu`, `dev_info.*`, `rte_eth_dev_set/get_mtu`) consistent.
- [ ] `rte_eal_process_type() == RTE_PROC_PRIMARY` determination is an existing usage in the codebase (e.g., `ff_dpdk_if.c`/`ff_dpdk_kni.c`).
- [ ] All DPDK API names and return value semantics match actual headers; no fabricated symbols.

## 3. Q1–Q4 Decision Implementation

- [ ] Q1 mbuf approach: large and scatter dual mode, config-selected, no implicit downgrade (07 R-MTU-004/005, 09 M2).
- [ ] Q2 max_mtu upper bound: configurable, enabled default 9000, large derived data_room≤UINT16_MAX deterministic failure (07 R-MTU-002, 08 §1.1, 09 §3.2).
- [ ] Q3 This task is spec only; coding/testing in separate tasks (07 §7, 10).
- [ ] Q4 End-to-end validation: best-effort; if link does not support jumbo, record honestly, no faking (11 §7 honest boundary).

## 4. Scope Convergence Decision Implementation (No IPC Transaction Residue)

Core gate items, confirmed item by item:

- [ ] 07 R-MTU-006/007 changed to per-process-role (primary soft+hard, secondary soft only) + each process sets once, no cross-process transactions.
- [ ] 07 AC-06 changed to "each proc setting yields consistent views; no cross-process auto-sync this phase".
- [ ] 07 §7 scope: In=multi-process independent setting (no IPC transaction); Out=runtime dynamic MTU cross-process IPC transaction coordination deferred to later milestone.
- [ ] 08 original 4.2 IPC transport (ff_mtu_msg, ff_mtu_phase, request/command/ack rings, message pools, transaction flow) section entirely deleted, replaced by "Multi-Process MTU Setting Model (No IPC)".
- [ ] 08 §4.1 explicitly states `ff_dpdk_if_set_mtu()` is primary-only.
- [ ] 08 §5.1, §6, §7 return codes removed coordinator/multi-process coordination timeout (ETIMEDOUT) wording.
- [ ] 09 §1 principle 4 removed "multi-process sync", changed to in-process.
- [ ] 09 §5.3 quiesce explicitly limited to this primary's lcores.
- [ ] 09 §6 ioctl pseudocode distinguishes primary/secondary branches by `RTE_PROC_PRIMARY`.
- [ ] 09 §7 entirely rewritten as "Multi-Process MTU Consistency (No IPC Coordination)": static model, usage convention and known constraints, why no IPC, bond primary in-process handling.
- [ ] 09 §9 unit tests deleted cross-process transaction/rings/transaction items; retained config, primary state machine, veth ioctl (role-distinguished), multi-seg.
- [ ] 09 §10 retains "secondary must not directly stop/start shared port".
- [ ] 10 M4 rewritten as "Multi-Process MTU Consistency (No IPC)", DoD=each proc setting yields consistent views, no cross-process transaction code.
- [ ] 11 deleted multi-process IPC transaction/two-phase/rings/transaction cases, replaced by each-process-setting consistency, secondary soft-only, missed-setting keeps old value.
- [ ] 12 deleted IPC transaction/coordinator risk items, added "missed setting causes proc view inconsistency" usage constraint risk; retained PMD/link, memory estimate, scatter overhead, TSO interaction, default compatibility, rollback.
- [ ] Global grep: 07–13 no longer contain request/prepare/commit/ack transactions, ff_mtu_msg, transaction_id, rings broadcast, coordinator and other IPC concepts (00–06 not checked).

## 5. Hard Constraints

- [ ] Pure documentation; no `lib/`, `freebsd/` code modified.
- [ ] Retains "do not modify `freebsd/net/if_ethersubr.c`", "ff_veth.c does not reference rte_eth*" and other existing constraints.
- [ ] config.ini-related wording only contains feature defaults/comments, no local test values (`lcore_mask/idle_sleep/addr` etc.).
- [ ] Document wording concise, no redundancy.

## 6. Bounce Protocol

- [ ] Any gate item failing → bounce back to previous step (doc-writing agent) for repair; must not be shelved as a leftover item.
- [ ] Max 3 bounces per step; if still failing, escalate to human decision.
- [ ] Doc authoring and review are different agents (role separation).
