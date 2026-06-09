# VLAN + VIP + IPFW_PR Functional Test Spec (v0.1, 2026-06-09)

> Chinese version: ./zh_cn/vlan-vip-ipfw-test-spec.md (authoritative)
>
> Authored by the spec-writer sub-agent using the `spec-driven` skill, paired with plan `vlan-vip-ipfw-test-plan.md`.
> Scope: q1=D (config-layer acceptance only — loopback / e2e / HW filter call all deferred to follow-up) + q2=C (dual-vlan multi-tenant).

---

## 1. Requirements

### 1.1 Functional Requirements (FR)

| ID | Description | Source |
|---|---|---|
| FR-V-1 | When the program reads dedicated config `config.test-vlan.ini`, `dpdk.vlan_filter=1,2` must parse so that `cfg->dpdk.vlan_filter_id[0]=1, [1]=2, nb_vlan_filter=2` | `lib/ff_config.c:373-377`+`982` |
| FR-V-2 | `[vlan1]` and `[vlan2]` sections must be dispatched by `ini_parse_handler` to `vlan_cfg_handler` (`strncmp("vlan",4)`) | `lib/ff_config.c:1021-1022` |
| FR-V-3 | All 11 fields of each vlan section (portid/addr/netmask/broadcast/gateway/vip_addr/ipfw_pr/addr6/prefix_len/gateway6/vip_addr6) must land in the matching `cfg->dpdk.vlan_cfgs[idx]` field | `lib/ff_config.c:690-740` |
| FR-V-4 | At program startup the `nb_vlan!=0` branch is taken; for each vlan it calls `if_clone_create` to bring up `f-stack-0.1` and `f-stack-0.2` | `lib/ff_veth.c:916-933` |
| FR-V-5 | On every vlan iface, `ff_veth_setaddr` + `ff_veth_set_gateway(fib_num=vlan_idx)` + `ff_veth_setvaddr` (vip list) must succeed (no ERROR lines) | `lib/ff_veth.c:944-957` |
| FR-V-6 | Each vlan's `ipfw_pr` is installed via `ff_ipfw_add_simple_v4(NULL, vlan_cfg, fib_num=vlan_idx)` | `lib/ff_veth.c:959-963` |
| FR-V-7 | At runtime `ff_ipfw -P 0 show` lists each vlan's setfib rules | reference: Tencent Cloud blog `/2161403` |

### 1.2 Non-functional Requirements (NFR)

| ID | Description | Threshold |
|---|---|---|
| NFR-V-1 | lib + example build: errors=0; warnings on par with baseline | warnings=57 (M-Final baseline) |
| NFR-V-2 | helloworld primary up to alive | after `sleep 12s`, `[ -d /proc/$PID ]` true |
| NFR-V-3 | Do not pollute production `config.ini`; do not flip any flag in `lib/Makefile` | git diff contains only new files / new anchors / new spec |
| NFR-V-4 | 0 direct `rm/kill/chmod`; commit local only | grep diff 0 hits |

---

## 2. Dual-VLAN Config Matrix (q2=C)

| Field | `[vlan1]` | `[vlan2]` |
|---|---|---|
| `portid` | 0 | 0 |
| `addr` | 192.169.0.2 | 192.169.1.2 |
| `netmask` | 255.255.255.0 | 255.255.255.0 |
| `broadcast` | 192.169.0.255 | 192.169.1.255 |
| `gateway` | 192.169.0.1 | 192.169.1.1 |
| `vip_addr` | 192.169.0.3;192.169.0.4 | 192.169.1.3;192.169.1.4 |
| `ipfw_pr` | 192.169.0.0 255.255.255.0 | 192.169.1.0 255.255.255.0 |

Field values are taken from the comment template at `f-stack-13.0-baseline/config.ini:151-194` (verified to be byte-identical to the comment block at the same position in the current `f-stack/config.ini`); they **do not collide with the production 9.134.214.0/21 subnet**.

`vlan_filter=1,2` must appear before any `[vlanN]` section (line 647 has the `nb_vlan_filter==0` early-return guard).

---

## 3. Test Cases

### TC-V1: parse OK

| Item | Content |
|---|---|
| Pre-condition | `lib/Makefile` at current baseline (`FF_IPFW=1` already enabled by default) |
| Step | `sudo ./helloworld -c ../config.test-vlan.ini --proc-type=primary --proc-id=0` |
| Forbidden stdout keywords | no `vlan_cfg_handler section[...] error`, no `vlan_cfg_handler portid ... bigger`, no `vlan_cfg_handler ... not match vlan filter`, no `vip_cfg_handler ... not set vip_addr`, no `ipfw_pr_cfg_handler ... format error` |
| Pass criterion | grep over the above keywords yields 0 hits |

### TC-V2: dual-vlan iface creation

| Step | Expected |
|---|---|
| (after TC-V1) `grep "Successed to if_clone_create vlan interface"` | hits=2 (vlan1 + vlan2, one each) |
| `grep "Failed to if_clone_create"` | 0 hits |

### TC-V3: primary IP + VIP on the vlan iface

| Step | Expected |
|---|---|
| `grep "ff_veth_setaddr failed"` | 0 hits (both vlan primaries) |
| `grep "ff_veth_setvaddr.*error\|ff_veth_setvaddr.*failed"` | 0 hits |
| `grep "inet_pton vip .* failed"` | 0 hits (all 4 VIPs inet_pton successfully) |

### TC-V4: ipfw_pr rule install

| Step | Expected |
|---|---|
| `tools/sbin/ff_ipfw -P 0 show` | contains both `setfib 0 ip from 192.169.0.0/24 to any out` and `setfib 1 ip from 192.169.1.0/24 to any out` (`fib_num=vlan_idx` decides 0/1) |
| Note | the actual fib number from `ff_ipfw show` uses `vlan_idx`, not `vlan_id` (see `lib/ff_veth.c:949`) |

### TC-V5: compliance + commit

| Step | Expected |
|---|---|
| `git --no-pager diff --staged \| grep -E '^\+.*\b(rm \|kill \|chmod )\b'` | 0 hits (excluding wrapper invocations inside `*.sh`) |
| `git --no-pager log @{u}..` | ≥1 commit; no push |
| Every cleanup path inside `tools/sbin/vlan_test_orchestrator.sh` | all go through wrapper scripts |

---

## 4. Three-Source Cross-Check

| Item | Source 1: real code (only authority) | Source 2: 13.0 baseline | Source 3: external docs / KG | Consistent? |
|---|---|---|---|---|
| vlan iface naming | `f-stack-%s.%d` (host_ifname.vlanid) `ff_veth.c:927` | identical (line equivalent) | Tencent Cloud blog example `f-stack-0.10` | ✅ |
| fib_num source | `vlan_cfg->vlan_idx` (`ff_veth.c:949`) | identical | the blog uses `setfib 10/20/30` (vlanid), inconsistent with the code | ⚠ **code wins**: fib uses 0/1, not vlanid 1/2 |
| ipfw rule opcode | `IP_FW_XADD` (`ff_veth.c:600`) | identical | KG node has this symbol | ✅ |
| `dpdk.vlan_filter` must come first | line 647 `nb_vlan_filter==0` early return | identical | docs imply but don't spell it out | ✅ |
| When `nb_vlan!=0`, `[portN]` skipped | comment is explicit (`config.ini:150`) + branch at line 868 | identical | docs don't spell it out | ✅ |
| HW vlan filter pushdown | **not implemented** (`ff_dpdk_if.c` grep 0 hits) | identical | F-Stack release notes mention RSS only, not the explicit HW-filter call | ✅ R-V2 risk |

---

## 5. Risk Register

| ID | Risk | Impact | Mitigation |
|---|---|---|---|
| R-V1 | When `nb_vlan!=0`, `[portN]` is skipped → 9.134.214.176 SSH dies | server unreachable, test halts | use a dedicated config + explicit `-c`; SSH stays on host kernel eth1 during the test rather than the DPDK-claimed NIC (host and DPDK share the PCI takeover window briefly) |
| R-V2 | DPDK rx vlan filter not pushed down | for e2e, RX cannot receive tagged frames | not in scope this iteration (F-V3 follow-up) |
| R-V3 | virtio-net vlan offload limits | same as R-V2 | same |
| R-V4 | `vlan_strip=1` × `nb_vlan!=0` interaction | after HW strips the tag, the vlan iface might miss packets | not in scope this iteration (F-V4) |
| R-V5 | `vlan_cfg_handler:668-677` loop shape (`if (vlan_index >= nb_vlan_filter)` inside the loop) | possible miss | reviewer's static cross-check confirmed no impact in practice (vlanid=1 hits idx=0, vlanid=2 hits idx=1) |
| R-V6 | Spec literature uses different fib numbers from the code (blog uses vlanid, code uses vlan_idx) | confusion when reading `ipfw show` | this spec §4 makes it explicit; TC-V4 acceptance uses 0/1 |

---

## 6. Follow-up

| ID | Description | Priority |
|---|---|---|
| F-V1 | Local loopback: ping/curl the vip → confirm `ipfw_pr setfib` truly used | Medium |
| F-V2 | Client configures 802.1Q vlan iface → end-to-end HTTP 200 + ipfw counters increment | Medium |
| F-V3 | Add `rte_eth_dev_set_vlan_filter()` calls in `lib/ff_dpdk_if.c` (paired with F-V2) | Medium |
| F-V4 | Validate `vlan_strip=1` × `nb_vlan!=0` rx path | Low |
| F-V5 | Static + dynamic confirmation of the `vlan_cfg_handler:668-677` loop shape | Low |
