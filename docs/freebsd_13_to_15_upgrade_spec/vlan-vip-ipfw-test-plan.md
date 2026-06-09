# VLAN + VIP + IPFW_PR Functional Test Plan

> Chinese version: ./zh_cn/vlan-vip-ipfw-test-plan.md (authoritative)
>
> Doc: VLAN dual-vlan config + vip_addr/vip_addr6 + ipfw_pr functional test plan v0.1 (2026-06-09)
> Sibling of `plan.md` (the Phase-2 feature-enable plan); independent deliverable for this follow-up task.
> Working style: **harness engineering + spec-driven + multi-agent team (1 leader + 4 sub-agents)**
> Doc series root: `/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/`
> HEAD at task start: `cb1fe9950` (feature/1.26 ahead 25 vs upstream/feature/1.26 — user already pushed earlier work to ahead 0 before this task)
> Document language: Chinese-first; English mirror authored at task wrap-up.

---

## 0. Goal and Scope

### 0.1 Overall goal

On F-Stack v1.26 (FreeBSD 15.0 port, after Phase-2 + Phase-5b + F-A1 fix all PASS), validate the **VLAN multi-tenant configuration path**:

1. The `config.test-vlan.ini` file (a dedicated test config, **does not pollute the production `config.ini`**) enables `dpdk.vlan_filter=1,2` plus `[vlan1]` and `[vlan2]` sections, each with primary IP, `vip_addr` (≥1 VIP) and `ipfw_pr` (one simple policy-route rule).
2. At helloworld primary startup the program must:
    - parse both vlan sections correctly (`vlan_cfg_handler`),
    - `if_clone_create` an `f-stack-0.<vlanid>` interface for each vlan (stdout shows `Successed to if_clone_create vlan interface`),
    - install every `vip_addr` on the vlan iface (`ff_veth_setvaddr` returns success),
    - translate `ipfw_pr` into `IP_FW_XADD` rules and load them (`ff_ipfw show` lists them).
3. Any of the above failing → enter the RCA + fix loop (≤3 cross-stage bounces).
4. The 4th bounce → write `vlan-test-ESCALATION-INFO.md`, pause, escalate to a human.

### 0.2 Scope boundary (decided by the user, q1=D)

| Item | In this iteration's scope |
|---|---|
| Config parses OK | ✅ in |
| `if_clone_create` of vlanN iface | ✅ in |
| `ifconfig` / stdout shows primary IP + VIP on the vlan iface | ✅ in |
| `ff_ipfw show` shows the setfib rules | ✅ in |
| Local-host loopback ping vip to verify the fib is actually used | ❌ **F-V1 (follow-up)** |
| client → server 802.1Q-tagged HTTP 200 + ipfw counter increment | ❌ **F-V2 (follow-up)** |
| Adding the `rte_eth_dev_set_vlan_filter()` HW-filter call | ❌ **F-V3 (follow-up, paired with F-V2)** |
| Interaction between `vlan_strip=1` and the `nb_vlan!=0` path | ❌ **F-V4 (follow-up, risk recorded)** |

---

## 1. Team Topology (4 sub-agents + 1 leader)

| Role | Primary skill / sub-agent | Responsibility |
|---|---|---|
| **agent-leader** | `harness-engineering-orchestrator` + `claw-multi-agent` | Overall orchestration; dispatches the 4 sub-agents; maintains `BOUNCE_COUNT`; writes plan/execution-log; triggers commit / escalation. |
| **spec-writer** | `spec-driven` + `code-explorer` + `RAG_search` (web + internal KB) | Produces `vlan-vip-ipfw-test-spec.md`: config matrix / TC-V1~TC-V5 / 3-source cross-check / risk register. |
| **coder** | `c-precision-surgery` | Authors `config.test-vlan.ini`, `tools/sbin/vlan_test_orchestrator.sh`, `tools/sbin/vlan_test_validate.sh`; if source fix is needed, makes minimal diffs to `lib/ff_config.c` / `lib/ff_veth.c` and copies originals to `freebsd-src-releng-15.0/f-stack-lib/`. |
| **reviewer** | `gitnexus-impact-analysis` + `gitnexus-exploring` + `iwiki-doc` + `RAG_search` | KG impact-surface analysis / call-chain / 3-source cross-check (real code vs spec vs 13.0 baseline); on issues, bounces to coder. |
| **gate-keeper** | `gitnexus-debugging` (only during RCA) | Runs G1~G4: build / start primary / keyword grep / `ff_ipfw show` / compliance; bounces on any failure per the rules. |

### 1.1 State machine + bounce rules

```
phases:    spec_writing → coding → reviewing → gating → done
escalate:                                              ↓
                                              BOUNCE_COUNT >= 4

bounce paths:
  reviewer → coder           (bounce#1, artifact defect)
  gate-keeper → coder        (bounce#2, build / G2 / G3 failure)
  gate-keeper → spec-writer  (bounce#3, spec itself is wrong)
```

`BOUNCE_COUNT >= 4` → stop: leader writes `vlan-test-ESCALATION-INFO.md` listing the failed step + stderr + tried hypotheses + items needing human decision.

---

## 2. G1~G4 Acceptance Gates

| Gate | Command / check | Pass criterion | On failure |
|---|---|---|---|
| **G1 Build** | `cd lib && make clean && make` + `cd example && make` | exit=0; `grep -ic 'error:'`=0; warnings on par with baseline (57) | bounce → coder |
| **G2 Startup** | `sudo ./helloworld -c ../config.test-vlan.ini --proc-type=primary --proc-id=0`, `sleep 12 && [ -d /proc/$PID ]` | PID still alive | bounce → coder |
| **G3 Functional** | grep helloworld stdout: `Successed to if_clone_create vlan interface` ×2; no `ff_veth_setvaddr` ERROR; `ff_ipfw_add_simple_v4` call OK; `ff_ipfw -P 0 show` lists vlan1's and vlan2's setfib rules | all 4 evidences present | bounce → coder (small bug) or spec-writer (spec wrong) |
| **G4 Compliance** | `grep -E '^[+ ]*(rm |kill |chmod )' commit-diff` + `grep -E '\brm |\bkill |\bchmod ' tools/sbin/*.sh` | 0 hits (excluding wrapper invocations); commit local only / unpushed | bounce → coder |

When G1~G4 all PASS: state → done, triggers the `local-commit` step.

---

## 3. Inputs and Dependencies (verified at plan_create stage)

### 3.1 Key code locations (real code = single source of truth)

| Path | Line | Role |
|---|---|---|
| `lib/ff_config.h:38` | `DPDK_MAX_VLAN_FILTER 128` | vlan filter capacity ceiling |
| `lib/ff_config.h:58` | `VIP_MAX_NUM 64` | vip ceiling |
| `lib/ff_config.h:125` | `struct ff_vlan_cfg` | vlan config struct |
| `lib/ff_config.c:373-377` | `parse_vlan_filter_list` | parses `dpdk.vlan_filter=` |
| `lib/ff_config.c:381-477` | `vip_cfg_handler` / `vip6_cfg_handler` | parse `vip_addr` / `vip_addr6` |
| `lib/ff_config.c:479-538` | `ipfw_pr_cfg_handler` (`#ifdef FF_IPFW`) | parse `ipfw_pr=` |
| `lib/ff_config.c:641-744` | `vlan_cfg_handler` | top of `[vlanN]` section parsing |
| `lib/ff_veth.c:152-200` | `ff_veth_vlan_config` | vlan vip inet_pton |
| `lib/ff_veth.c:551-...` | `ff_ipfw_add_simple_v4` | install ipfw rules (v4 only) |
| `lib/ff_veth.c:916-991` | **`nb_vlan!=0` branch** | one-shot vlan iface create + addr/gw/vip/ipfw_pr (**core path of this task**) |

### 3.2 Known constraints / risks

| ID | Risk | Impact | Mitigation |
|---|---|---|---|
| R-V1 | When `nb_vlan!=0`, the `[portN]` section is fully skipped → port0 9.134.214.176 SSH cuts | server unreachable | use a **dedicated config file** + explicit `-c` flag; SSH still rides host kernel eth1 during the test, the DPDK takeover window is announced and known to be temporary |
| R-V2 | `lib/ff_dpdk_if.c` does not call `rte_eth_dev_set_vlan_filter()` | HW vlan filter inactive; e2e traffic needs this call | scope D doesn't depend on the HW filter; recorded as F-V3 follow-up |
| R-V3 | virtio-net vlan offload capability is limited | for end-to-end tests one may need promisc + soft filter | not validated this iteration; recorded as F-V2 follow-up |
| R-V4 | Possible conflict between `vlan_strip=1` and the `nb_vlan!=0` rx path | tags stripped → vlan iface cannot receive packets | not validated this iteration; recorded as F-V4 follow-up |
| R-V5 | `vlan_cfg_handler` lines 668-677 — odd loop layout (the `vlan_index >= nb_vlan_filter` test sits inside the loop) | might fall through to a wrong vlan_index | reviewer cross-checks via KG call-chain + static read |

### 3.3 Reference spec corpus

`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/` — 38 files; the new spec follows the same naming (`vlan-vip-ipfw-test-*.md`) and section style as `phase2-M*-spec.md`, `Phase-5b-execution-log.md`, `F-A1-fix-execution-log.md`.

### 3.4 Workspace mandate (every sub-agent must follow; violation = G4 fail)

- delete: `/data/workspace/rm_tmp_file.sh <path...>` (**no** raw `rm`)
- kill: `/data/workspace/kill_process.sh <pid>` (**no** raw `kill / pkill / killall`)
- chmod: `/data/workspace/chmod_modify.sh +x <file>` (**no** raw `chmod`)
- local commit only, no push (push timing is a human decision)

---

## 4. Stage Artifacts

| Stage | Artifact | Owner |
|---|---|---|
| T1 leader bootstrap | `vlan-vip-ipfw-test-plan.md` (this file) | leader |
| T2 spec | `vlan-vip-ipfw-test-spec.md` | spec-writer |
| T3 code | `config.test-vlan.ini` + `tools/sbin/vlan_test_orchestrator.sh` + `tools/sbin/vlan_test_validate.sh` + `freebsd-src-releng-15.0/f-stack-lib/` backup (if source code is changed) | coder |
| T4 review | review brief (folded into the execution-log §reviewer block) | reviewer |
| T5 gate | G1~G4 measured evidence (folded into the execution-log §gate-keeper block) | gate-keeper |
| T6 closure | `vlan-vip-ipfw-test-execution-log.md` (success) OR `vlan-test-ESCALATION-INFO.md` (halted) | leader |
| T7 anchor sync | 4-doc mirror update (en/zh L1 architecture + KB summary) | leader |
| T8 commit | local commit | leader |

---

## 5. Follow-up Backlog (out of this iteration)

| ID | Description | Priority |
|---|---|---|
| **F-V1** | Local loopback: ping/curl the vip on the vlan iface → confirm `ipfw_pr setfib` truly takes effect | Medium |
| **F-V2** | End-to-end: client configures a 802.1Q vlan iface in the same subnet → curl the server vlan vip, get HTTP 200 + watch ipfw counters increment | Medium |
| **F-V3** | Add `rte_eth_dev_set_vlan_filter()` calls to `lib/ff_dpdk_if.c` (paired with F-V2) | Medium |
| **F-V4** | Validate `vlan_strip=1` × `nb_vlan!=0` interaction (after HW strips the tag, can the vlan iface still receive?) | Low |
| **F-V5** | Static + dynamic confirmation of the odd `vlan_cfg_handler:668-677` loop shape (possible latent bug) | Low |

---

## 6. Execution Trigger

- This plan v0.1 done → enter T2 spec-writer stage.
- Any stage with BOUNCE_COUNT ≥ 4 → ESCALATION halt.
- T1~T8 all PASS → leader fires the local commit + notifies the user.
