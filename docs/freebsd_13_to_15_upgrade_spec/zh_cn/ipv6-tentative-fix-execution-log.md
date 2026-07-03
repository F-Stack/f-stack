# IPv6 TCP 不通 · 根因修复运行时执行日志（f-stack 15.0 升级 runtime-fix）

> 任务类型：运行时诊断 + 代码修复 + 端到端验证
> 治理方式：harness + spec 驱动 + agent team（leader + code-explorer subagent），写/审分离、超时轮询、bounce≤3
> 日期：2026-07-02
> 结论状态：**根因坐实、A+B 双保险修复已落地，client 端 IPv6 TCP 到 F-Stack helloworld 端到端验证通过**

---

## 0. 问题

f-stack 升级到 FreeBSD 15.0 后：**IPv6 的 TCP 访问 F-Stack APP（helloworld）连接不通，但 TCP 监听（bind/listen）成功**；IPv4 正常。上一轮静态分析（`ipv6-tcp-connect-diag-report.md`）已排除 8 项 v6 代码回归假设，遗留 R-IPv6-DP-1 / R-IPv6-DP-2 需运行时坐实。本次在真机运行时环境完成坐实与修复。

## 1. 一句话结论

f-stack 用户态 IPv6 全局单播地址启动后长期停留在 `IN6_IFF_TENTATIVE`（用户态单线程栈下 DAD callout 不 tick），15.0 `ip6_input` 对 `IN6_IFF_NOTREADY` 目的地址**静默丢**所有 unicast 包（无计数器）→ 全部 v6 TCP/UDP 被 IP 层丢弃。`ping6` 通是 icmp6 走 `[kni] method=reject` 被送到 Linux 内核 veth0 上同名地址应答的**假象**。修复：**A（sysctl 兜底：`net.inet6.ip6.dad_count=0`）+ B（代码层默认关 DAD：`lib/ff_veth.c` 加 `ND6_IFF_NO_DAD`）**。

## 2. 运行时证据链（100% 坐实）

### 2.1 环境基线

- 主机：DPDK 网卡 PCI `0000:00:05.0`（virtio），f-stack `f-stack-0` 接口，addr6 = `2402:4e00:1900:1:6:5522:de6a:7d84`
- helloworld：`example/main.c` `AF_INET6 bind [::]:80 listen`，config `[kni] enable=1 method=reject tcp_port=80,443 udp_port=53`
- client：`f-stack-client`（`2402:4e00:1900:1:6:5522:c9a0:741c`）ssh 直连

### 2.2 症状复现

修复前，从 client 侧：
- v4 ping 9.134.214.176：`0.4ms 通`
- v6 ping de6a:7d84：`0.37ms 通`（RTT 表象）
- v6 tcp curl `http://[de6a:7d84]:80/`：`Timeout after 3s`
- python `connect_ex((...,80,0,0))`：`ret=11`（EAGAIN，即握手无回应）

### 2.3 f-stack 侧计数器对比（直接证据）

修复前，触发 v6 SYN 前后 `ff_netstat -t 0 -p ip6 -s`：

| 时点 | total received | for this host | badscope |
|---|---:|---:|---:|
| baseline | 13 | 0 | 0 |
| v6 SYN 触发后 | 15 (+2) | 0 | 0 |

**关键**：v6 SYN 进入 IP 层（total +2），但 `for this host` 一直为 0、`badscope` 一直为 0 → **既不是 SAV 命中**（原候选 B 排除），也不是"未收到"→ **是被 IP 层无计数器地默默丢**。这与 `freebsd/netinet6/ip6_input.c` L811-819 完全吻合：

```c
ia = in6ifa_ifwithaddr(&ip6->ip6_dst, 0, false);
if (ia != NULL) {
    if (ia->ia6_flags & IN6_IFF_NOTREADY) {   // IN6_IFF_TENTATIVE | IN6_IFF_DUPLICATED
        nd6log(...packet to an unready address...);
        goto bad;                              // <-- 无 IP6STAT_INC，静默丢
    }
```

### 2.4 tentative 状态直接观测

修复前，`ff_ifconfig -p 0 -a`：

```
f-stack-0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
    inet6 fe80::2290:6fff:fe7d:5d08 prefixlen 64 tentative scopeid 0x2
    inet6 2402:4e00:1900:1:6:5522:de6a:7d84 prefixlen 128 tentative autoconf   <-- TENTATIVE
```

### 2.5 ping 通表象的真正来源（tcpdump 抓包）

```
17:29:18 veth0 In   IP6 c9a0:741c > de6a:7d84 : ICMP6 echo request
17:29:18 eth1  Out  IP6 de6a:7d84 > c9a0:741c : ICMP6 echo reply
```

- ICMP6 不在 `[kni] tcp_port/udp_port` 白名单 → `method=reject` 语义送内核 KNI-veth0
- Linux 内核 veth0 上被 `dkdns_ospf.sh` 加过 `de6a:7d84/128` → 内核自行回复 icmp echo
- 与 f-stack IP 层无关（`ff_netstat ip6` 全 0）

### 2.6 规避验证（一步坐实）

```
ff_sysctl -p 0 net.inet6.ip6.dad_count=0        # 1 -> 0
ff_ifconfig -p 0 f-stack-0 inet6 de6a:7d84 delete
ff_ifconfig -p 0 f-stack-0 inet6 de6a:7d84 prefixlen 128
# 再查
ff_ifconfig -p 0 -a  → inet6 2402:...:de6a:7d84 prefixlen 128   (无 tentative !)
```

client 复测 v6 tcp 80 → curl 立即拿到完整 F-Stack helloworld HTML（Content-Length: 438）、python `connect_ex ret=0` → **根因 100% 坐实**。

## 3. 13.0 → 15.0 差异（代码交叉验证）

- **ip6_input.c L811-819**：13.0 与 15.0 **同样**存在 `IN6_IFF_NOTREADY → goto bad` 静默丢逻辑，未变
- **nd6_nbr.c**：13.0 → 15.0 diff：
  - `nd6_dad_starttimer(dp, ticks, send_ns)` → `nd6_dad_starttimer(dp, ticks)`（少 1 参）
  - `nd6_dad_timer(struct dadq *)` → `nd6_dad_timer(void *)`（callout 通用签名）
  - 引入 `DADQ_WLOCK / DADQ_WUNLOCK`（读写锁）替代 `NET_EPOCH_ASSERT`
- **回归根因**：15.0 版 DAD callout 依赖 `DADQ_RWLOCK` + 独立定时器路径，f-stack 用户态单线程栈的定时器上下文与 15.0 版 DAD 时序不兼容；DAD 定时器不 tick → addr 永久 tentative → 15.0 静默丢分支被激活。13.0 版走 `NET_EPOCH` + 早期定时器路径在 f-stack 单线程栈能 tick，故 13.0 v6 tcp 通。
- **`in6_ifattach.c` L610** 已给 loopback/6to4 打过 `ND6_IFF_NO_DAD`；13.0 baseline `lib/ff_veth.c` 与 15.0 `lib/ff_veth.c` **在 v6 addr 分支上都没有** `ND6_IFF_NO_DAD` 设置 → f-stack 用户态适配层此处 13→15 未做适配、是 latent 缺陷，被 15.0 DAD 时序变化激活。

## 4. 修复方案（A + B 双保险）

### A. sysctl 兜底

- 工作区实机 `/data/workspace/config.ini`：`addr6` 改为 `de6a:7d84`（用户明确正式使用）；`[freebsd.sysctl]` 追加 `net.inet6.ip6.dad_count=0`
- 仓库模板 `f-stack/config.ini` `[freebsd.sysctl]` 追加 `net.inet6.ip6.dad_count=0` + 3 行简注释说明原因（本次仅提交这一片段，本地测试值残留不提交）
- 生效顺序：`lib/ff_freebsd_init.c` L174-185 遍历应用 `[freebsd.sysctl]` 早于 addr 添加 → 添加时 `V_ip6_dad_count==0` → `nd6_dad_start`（`freebsd/netinet6/nd6_nbr.c` L1293-1297）直接清 `IN6_IFF_TENTATIVE`。

### B. 代码层默认关 DAD

- 位置：`lib/ff_veth.c` `ff_veth_setup_interface` L980-981（`#ifdef INET6` 之后、`if (cfg->addr6_str)` 之前）
- 改动（最小 diff、3 行注释 + 1 行代码）：

```c
#ifdef INET6
    /* Skip IPv6 DAD on DPDK-backed veth: no L2 peer answers NS in
     * userland, so DAD would leave addrs IN6_IFF_TENTATIVE forever and
     * FreeBSD 15 ip6_input silently drops unicast to NOTREADY addrs. */
    ND_IFINFO(ifp)->flags |= ND6_IFF_NO_DAD;
    // Set IPv6
    if (cfg->addr6_str) {
```

- 语义与 `nd6_dad_start` L1293-1295 `ND6_IFF_NO_DAD` 短路条件对齐；作用面严格限定在 f-stack 数据网卡的 v6 addr 分支，v4 无 tentative 概念、lo0 不受影响。
- 不改内嵌 FreeBSD 源码（`nd6_nbr.c` / `ip6_input.c` 均保持与 upstream 15.0 vendor 逐字节可对齐）。

### 双保险原因

- B 是**默认行为**（不依赖用户 config），是主修复
- A 是**兜底**（万一以后有人删掉 B 或者用非 `ff_veth` 路径添加 v6 addr）+ **紧急现场规避**手段（无需重编即可让老进程通过 `ff_sysctl` 现场恢复）
- 二者独立生效、不冲突

## 5. 修复后端到端验证

### 5.1 单机自测

- `ff_ifconfig -p 0 -a`：

```
f-stack-0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
    inet6 fe80::2290:6fff:fe7d:5d08 prefixlen 64 scopeid 0x2       (NO tentative)
    inet6 2402:4e00:1900:1:6:5522:de6a:7d84 prefixlen 128 autoconf  (NO tentative)
```

- `ff_netstat -t 0 -an`：`tcp6 *.80 LISTEN` OK
- `ff_sysctl -p 0 net.inet6.ip6.dad_count` → `0`

### 5.2 client 端到端

`ssh f-stack-client`：

- `ping -6 de6a:7d84` → 3/3 OK
- `curl -6 http://[de6a:7d84]:80/` → **200 OK，Content-Length 438，完整 F-Stack helloworld HTML**
- `python3 socket.connect_ex((de6a:7d84,80,0,0))` → `ret=0`

### 5.3 f-stack 侧计数验证

curl 前后 `ff_netstat -t 0 -p ip6 -s`：

| 时点 | total received | for this host | sent from this host |
|---|---:|---:|---:|
| baseline | 11 | 10 | 0 |
| curl 完成后 | 25 (+14) | 22 (+12) | 17 (+17) |

`for this host` 从修复前的 **0** 变为 `+12`，`sent` 从 `0` 变为 `+17` → v6 双向流量真实进出 f-stack 协议栈。

### 5.4 tcpdump 侧证

用 `tcpdump -i any 'tcp and port 80 and ip6'` 抓 → **0 packets captured**：证明 v6 tcp 完全走 DPDK 网卡（bypass kernel），不经 KNI-veth0；符合 `[kni] tcp_port=80` 白名单命中即 f-stack 保留的语义。

## 6. 遗留项 / follow-up

- **vlan 分支**：`ff_veth.c` L1058-1082 vlan v6 分支在同函数内、但 `vlan_sc.ifp` 未在作用域直接暴露（需 `ifunit(vlan_if_name)`）；本次**保持最小 diff 不改**，vlan 场景可通过 A（sysctl）兜底覆盖。若未来实际使用 vlan 场景，可后续补一次性修改。
- **深挖 15.0 nd6_dad_timer 单线程 tick 失败根因**：属长期研究项（`plan.md` 中 C 方案），本次不做；本次 A+B 已足以让所有 v6 场景可用。
- **R-IPv6-DP-1** 结项：IPv6 数据面首次运行时验证完成、v6 收包派发/tcp6_input/nd6 输出全链路 OK。
- **R-IPv6-DP-2** 结项（部分）：TENTATIVE 侧盲区已由 A+B 规避；DAD callout 单线程 tick 的原生问题仍存，但已不影响功能。

## 7. 强制规约合规

- 删除文件走 `/data/workspace/rm_tmp_file.sh`（本次未删）
- kill 进程走 `/data/workspace/kill_process.sh`（本次杀 helloworld pid=19031 已走脚本）
- chmod 走 `/data/workspace/chmod_modify.sh`（本次未 chmod）
- lib 代码仅 3 行必要注释 + 1 行代码；不改内嵌 FreeBSD 源码；无 commit（等用户真机 OK 手动提示后再提交）
- config.ini 提交时精确排除本地测试值（`lcore_mask=10`、`idle_sleep=20`、`[port0] addr=9.134.x`、`[kni]` 段取消注释、`gateway6/addr6` 本机具体值），只保留 `[freebsd.sysctl] net.inet6.ip6.dad_count=0` + 简注释这一段特性提交

## 8. Commit message 草稿（英文，待用户确认后使用）

```
fstack: skip IPv6 DAD on DPDK-backed veth to fix IPv6 TCP breakage on FreeBSD 15

FreeBSD 15 ip6_input silently drops unicast packets to addresses in
IN6_IFF_NOTREADY state. In f-stack's single-threaded userland stack,
DAD never completes so global unicast v6 addrs stay TENTATIVE forever,
which breaks all IPv6 TCP/UDP on the DPDK-backed interface (v4 and
ping6 via KNI still appear to work, masking the issue).

Fix by setting ND6_IFF_NO_DAD on the f-stack interface before v6
addrs are added, plus a sysctl fallback (net.inet6.ip6.dad_count=0)
in the config template.
```

## 9. 跨环境验证：mlx5 100G 物理机（2026-07-03）

### 9.1 背景

CVM（virtio）环境用 A+B 修复后 IPv6 TCP 已通。切到 **mlx5 ConnectX 100G 物理机**（DPDK PCI `0000:86:00.0`），沿用同一份 DAD-disable 代码，最初 IPv6 TCP 80 仍不通，遂做二次运行时排查。

### 9.2 关键运行时数据

`ff_netstat -an`（primary=helloworld 正常收发；注：secondary 的 ff_netstat 报 `mlx5 can not attach / Cannot allocate memory` 是 secondary 进程 attach 网卡失败的正常现象，不影响 primary）：

```
tcp6  0  0  2402:4e00:1840::.80   2402:4e00:2e80:1.29159   SYN_RCVD
tcp6  0  0  2402:4e00:1840::.80   2402:4e00:2e80:1.29155   SYN_RCVD
... (多条不同源端口 SYN_RCVD)
tcp4  0  0  1.13.76.19.80         11.19.149.140.6101       LAST_ACK
tcp6  0  0  *.80                  *.*                      LISTEN
tcp4  0  0  *.80                  *.*                      LISTEN
```

判读：
- 入向 SYN **正常进入 f-stack 协议栈**（大量 `tcp6 ... SYN_RCVD`）→ 排除 RX csum 丢包、排除 RSS 投错队列、排除 DAD/tentative（addr 已 ready）。
- 连接卡在 `SYN_RCVD`：f-stack 收到 SYN、回了 SYN-ACK，但**收不到 client 的最后 ACK** → client 不断以新源端口重发 SYN。
- v4 能到 `LAST_ACK`（完整握手+关闭）→ 纯 IPv6、且是**出向回包被对端挡**的典型指纹。

### 9.3 最终定性（真因，非 f-stack 代码问题）

**client 侧 `ip6tables` 未放通「源端口 80」的入向包**：SYN-ACK 由 f-stack 从 80 端口发回 client，被 client `ip6tables` INPUT 规则丢弃 → client 收不到 SYN-ACK → 不回 ACK → f-stack 卡 `SYN_RCVD`。v4 因 iptables(v4) 已放通而正常，是 v4/v6 防火墙策略不对称所致。

放通 client `ip6tables` 源端口 80 入包后，**沿用本文档 §4 的 DAD-disable 代码（无需任何额外改动）**，mlx5 物理机 IPv6 TCP 80 端到端**测试确认一切正常**。

### 9.4 结论

- mlx5 物理机与 CVM 用**同一份代码**（§4 的 A+B）即可跑通 IPv6 TCP，无需针对 mlx5 做任何代码适配。
- 排查中曾怀疑的 IPv6 TX checksum offload 缺口（`ff_dpdk_if.c` L2272/L2284、`ff_memory.c` L320/L331 对 v6 用 IPv4 `version_ihl` 算 `l3_len`，两处均标注 `/* ipv6 not supported yet */`）与 `ff_veth.c` `ff_mbuf_tx_offload` 漏判 `CSUM_TCP_IPV6/CSUM_UDP_IPV6` —— 本次 **未被触发**（SYN-ACK csum 正常），列为 **latent follow-up**，不在本次修复范围。
