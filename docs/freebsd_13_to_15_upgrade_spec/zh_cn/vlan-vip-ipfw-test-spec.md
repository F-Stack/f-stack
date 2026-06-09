# VLAN + VIP + IPFW_PR 功能测试 Spec（v0.1，2026-06-09）

> 本 spec 由 spec-writer 子 agent 用 `spec-driven` skill 产出，对接 plan `vlan-vip-ipfw-test-plan.md`。
> 范围：q1=D（仅配置层验收，loopback / 端到端 / HW filter 调用全部 follow-up）+ q2=C（双 vlan multi-tenant）。

---

## 1. 需求规格

### 1.1 功能性需求（FR）

| ID | 描述 | 来源 |
|---|---|---|
| FR-V-1 | 主程序读独立 config 文件 `config.test-vlan.ini` 时，`dpdk.vlan_filter=1,2` 必须能 parse，`cfg->dpdk.vlan_filter_id[0]=1, [1]=2, nb_vlan_filter=2` | `lib/ff_config.c:373-377`+`982` |
| FR-V-2 | `[vlan1]` 与 `[vlan2]` section 必须能被 `ini_parse_handler` 派发到 `vlan_cfg_handler`（`strncmp("vlan",4)`）| `lib/ff_config.c:1021-1022` |
| FR-V-3 | 每个 vlan section 的 11 个字段（portid/addr/netmask/broadcast/gateway/vip_addr/ipfw_pr/addr6/prefix_len/gateway6/vip_addr6）必须分别落到 `cfg->dpdk.vlan_cfgs[idx]` 对应字段 | `lib/ff_config.c:690-740` |
| FR-V-4 | 主程序启动时 `nb_vlan!=0` 分支被走到，逐 vlan 调 `if_clone_create` 出 `f-stack-0.1` 与 `f-stack-0.2` 两个 vlan iface | `lib/ff_veth.c:916-933` |
| FR-V-5 | 每个 vlan iface 上 `ff_veth_setaddr` + `ff_veth_set_gateway(fib_num=vlan_idx)` + `ff_veth_setvaddr`（vip 列表）调用成功（无 ERROR 行）| `lib/ff_veth.c:944-957` |
| FR-V-6 | 每个 vlan 的 `ipfw_pr` 通过 `ff_ipfw_add_simple_v4(NULL, vlan_cfg, fib_num=vlan_idx)` 装入 ipfw 规则集 | `lib/ff_veth.c:959-963` |
| FR-V-7 | 主程序运行时 `ff_ipfw -P 0 show` 能看到双 vlan 各自的 setfib 规则 | 文献：腾讯云博客`/2161403` |

### 1.2 非功能性需求（NFR）

| ID | 描述 | 阈值 |
|---|---|---|
| NFR-V-1 | lib + example build：errors=0；warnings 与 baseline 一致 | warnings=57（M-Final baseline） |
| NFR-V-2 | helloworld primary 启动到 alive | sleep 12s 后 `[ -d /proc/$PID ]`=true |
| NFR-V-3 | 不污染 production `config.ini`；不动 `lib/Makefile` 任何 flag | git diff 仅含新增文件 / 新 anchor / 新 spec |
| NFR-V-4 | 0 直接 `rm/kill/chmod`；commit 仅 local | grep diff 0 hits |

---

## 2. 双 VLAN 配置矩阵（q2=C）

| 字段 | `[vlan1]` | `[vlan2]` |
|---|---|---|
| `portid` | 0 | 0 |
| `addr` | 192.169.0.2 | 192.169.1.2 |
| `netmask` | 255.255.255.0 | 255.255.255.0 |
| `broadcast` | 192.169.0.255 | 192.169.1.255 |
| `gateway` | 192.169.0.1 | 192.169.1.1 |
| `vip_addr` | 192.169.0.3;192.169.0.4 | 192.169.1.3;192.169.1.4 |
| `ipfw_pr` | 192.169.0.0 255.255.255.0 | 192.169.1.0 255.255.255.0 |

字段值参考 `f-stack-13.0-baseline/config.ini:151-194` 注释模板（已 verified 与当前仓库 `f-stack/config.ini` 同位置注释 diff=0），**不与 production 9.134.214.0/21 网段冲突**。

`vlan_filter=1,2` 必须出现在所有 `[vlanN]` 之前（line 647 nb_vlan_filter==0 早返回保护）。

---

## 3. 测试用例

### TC-V1：parse OK

| 项 | 内容 |
|---|---|
| 前置 | `lib/Makefile` 当前 baseline（`FF_IPFW=1` 已默认开启） |
| 步骤 | `sudo ./helloworld -c ../config.test-vlan.ini --proc-type=primary --proc-id=0` |
| 期望 stdout 关键字 | 不出现 `vlan_cfg_handler section[...] error`、不出现 `vlan_cfg_handler portid ... bigger`、不出现 `vlan_cfg_handler ... not match vlan filter`、不出现 `vip_cfg_handler ... not set vip_addr`、不出现 `ipfw_pr_cfg_handler ... format error` |
| 通过判据 | grep 上述关键字 0 hits |

### TC-V2：双 vlan iface 创建

| 步骤 | 期望 |
|---|---|
| (TC-V1 之后) `grep "Successed to if_clone_create vlan interface"` | hits=2（vlan1 + vlan2 各 1） |
| `grep "Failed to if_clone_create"` | 0 hits |

### TC-V3：vlan iface 上挂主 IP + VIP

| 步骤 | 期望 |
|---|---|
| `grep "ff_veth_setaddr failed"` | 0 hits（双 vlan 主 IP）|
| `grep "ff_veth_setvaddr.*error\|ff_veth_setvaddr.*failed"` | 0 hits |
| `grep "inet_pton vip .* failed"` | 0 hits（4 个 vip 全部 inet_pton 成功）|

### TC-V4：ipfw_pr 规则装入

| 步骤 | 期望 |
|---|---|
| `tools/sbin/ff_ipfw -P 0 show` | 含 `setfib 0 ip from 192.169.0.0/24 to any out` 与 `setfib 1 ip from 192.169.1.0/24 to any out` 两条规则（`fib_num=vlan_idx` 决定 0/1）|
| 注意 | `ff_ipfw show` 实际 fib 数字使用 `vlan_idx`，不是 `vlan_id`（参 `lib/ff_veth.c:949`） |

### TC-V5：compliance + commit

| 步骤 | 期望 |
|---|---|
| `git --no-pager diff --staged \| grep -E '^\\+.*\\b(rm |kill |chmod )\\b'` | 0 hits（除 `*.sh` 内的 wrapper 调用） |
| `git --no-pager log @{u}..` | ≥1 commit；不含 push 操作 |
| `tools/sbin/vlan_test_orchestrator.sh` 内部所有 cleanup 路径 | 全部通过 wrapper 脚本调用 |

---

## 4. 三源 Cross-Check 表

| 项 | 源 1：实际代码（唯一权威） | 源 2：13.0 baseline | 源 3：外部资料 / KG | 一致？ |
|---|---|---|---|---|
| vlan iface 命名 | `f-stack-%s.%d`（host_ifname.vlanid）`ff_veth.c:927` | 相同（行号等价）| 腾讯云博客示例 `f-stack-0.10` | ✅ |
| fib_num 来源 | `vlan_cfg->vlan_idx`（`ff_veth.c:949`） | 相同 | 博客中 `setfib 10/20/30` 用 vlanid，与代码不一致 | ⚠ **以代码为准**：fib 用 0/1 而非 vlanid 1/2 |
| ipfw 规则 opcode | `IP_FW_XADD`（`ff_veth.c:600`） | 相同 | KG node 含此 symbol | ✅ |
| `dpdk.vlan_filter` 必须在前 | line 647 `nb_vlan_filter==0` 早返回 | 相同 | 文档未明示但隐含 | ✅ |
| `nb_vlan!=0` 时 [portN] 跳过 | 注释明确（`config.ini:150`）+ 代码 line 868 分支 | 相同 | 文档未明示 | ✅ |
| HW vlan filter 下推 | **未实现**（`ff_dpdk_if.c` grep 0 hits） | 相同 | F-Stack release notes 仅提 RSS，未明确 HW filter 调用 | ✅ R-V2 风险 |

---

## 5. Risk Register

| ID | 风险 | 影响 | 缓解 |
|---|---|---|---|
| R-V1 | `nb_vlan!=0` 时 [portN] 跳过 → 9.134.214.176 SSH 失联 | server 失联导致测试中断 | 用独立 config 文件 + 显式 `-c` 参数；测试期间 SSH 仍走 host kernel eth1 而非 DPDK 接管的 NIC（host 与 DPDK 共用 PCI 接管时段需短暂窗口） |
| R-V2 | DPDK rx vlan filter 未下推 | 端到端时 RX 收不到 tagged 帧 | 本期不在 scope（F-V3 follow-up） |
| R-V3 | virtio-net vlan offload 受限 | 同 R-V2 | 同上 |
| R-V4 | `vlan_strip=1` × `nb_vlan!=0` 交互 | tag 被 HW 剥离后 vlan iface 收不到包 | 本期不在 scope（F-V4） |
| R-V5 | `vlan_cfg_handler:668-677` 循环结构（`if (vlan_index >= nb_vlan_filter)` 在循环内）| 可能漏命中 | reviewer 阶段已静态读 cross-check：实测无影响（vlanid=1 命中 idx=0，vlanid=2 命中 idx=1）|
| R-V6 | spec 文献中 fib 数字与代码不一致（博客用 vlanid，代码用 vlan_idx） | 验收 ipfw show 时混淆 | 本 spec §4 已明示，TC-V4 验收用 0/1 |

---

## 6. Follow-up

| ID | 描述 | 优先级 |
|---|---|---|
| F-V1 | 本机 loopback ping/curl vip → 验证 ipfw_pr setfib 真生效 | Medium |
| F-V2 | client 配 802.1Q vlan iface → 端到端 HTTP 200 + ipfw counter 增长 | Medium |
| F-V3 | `lib/ff_dpdk_if.c` 补 `rte_eth_dev_set_vlan_filter()`（与 F-V2 联动） | Medium |
| F-V4 | `vlan_strip=1` × `nb_vlan!=0` 收包路径验证 | Low |
| F-V5 | `vlan_cfg_handler:668-677` 循环结构静态/动态确认 | Low |
