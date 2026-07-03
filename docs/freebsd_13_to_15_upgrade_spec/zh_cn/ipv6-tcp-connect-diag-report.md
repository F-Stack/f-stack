# IPv6 TCP 连接不通（监听成功）根因分析报告

> 任务类型：纯代码根因分析（不改代码修复）
> 治理方式：harness + spec 驱动 + agent team（leader + explorer-datapath + explorer-research + reviewer-gate）
> 日期：2026-07-01
> 结论状态：静态分析已闭环（门禁通过，bounce=0）；决定性运行时验证因环境阻塞未做

---

## 0. 问题描述

f-stack 升级到 FreeBSD 15.0 后：**IPv6 的 TCP 访问 F-Stack APP（example/helloworld）连接不通，但 TCP 监听（bind/listen）成功**；IPv4 正常。

- helloworld 确为 IPv6 被动 server：`example/main.c:183-193`，`ff_socket(AF_INET6, SOCK_STREAM, 0)` bind `in6addr_any:80` + listen + accept。

---

## 1. 一句话结论

**纯代码层面未发现确定性回归 bug**：IPv6 被动 accept 全链路（收包派发 → inpcb 查找 → syncache → nd6 出包）经三方交叉 + 独立门禁均已逐项排除。最可能根因是**环境/配置层**（v6 数据面从未真正启动过 + 当前网卡不在 DPDK + 云网络/安全组 v6 入向），而非 FreeBSD 协议栈代码回归。剩余唯一静态盲区（单线程用户态 nd6 的 NS/NA 异步邻居解析能否运行时闭环）须运行时坐实。

---

## 2. 已逐一排除的代码侧假设（8 项，门禁签核成立）

| # | 假设 | 排除依据（f-stack 实际代码，文件:行号） |
|---|---|---|
| ① | 15.0 `ip6_protox[]` 函数指针化后 `IPPROTO_TCP` 退化为 `rip6_input`（SYN 派到 raw 而非 tcp6） | `ip6_input.c:129-130` 静态初值全 `rip6_input`；`ip6_init`(L286-315) 运行时**不重置数组**、注册表不含 TCP；`tcp_subr.c:1568-1572` `#ifdef INET6` 内 `IP6PROTO_REGISTER(IPPROTO_TCP, tcp6_input)` + `SYSINIT(tcp_init, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD)`；`ff_init_main.c:230-283` `mi_startup` 确定执行全部 SYSINIT；`Makefile:155-157` `FF_INET6=1→-DINET6`（全局），`opt_inet6.h` 定义 `INET6`。排序风险已排查：ip6_init 与 tcp_init 同 subsystem/order，但 ip6_init 不碰 TCP 槽，谁先执行都能成功写入 → 运行时 `ip6_protox[IPPROTO_TCP]==tcp6_input` |
| ② | RX 校验和 flag 对 IPv6 误判丢包 | `ff_veth.c:465-469` rx_csum 置 `CSUM_DATA_VALID\|CSUM_PSEUDO_HDR`+`csum_data=0xffff`；`tcp_input.c` v6 分支 `th_sum=0xffff^0xffff=0` 通过；13/15 逐字节一致 |
| ③ | TX csum 对 IPv6 `l3_len` 算错致 SYN-ACK 坏校验和 | `ff_dpdk_if.c:2284-2299` 用 IPv4 解析 `l3_len`；但 `f-stack-13.0-baseline/lib/ff_dpdk_if.c:2181-2196` **逐字节相同**，非升级回归（且默认 virtio 场景 tx_csum_l4 未必生效） |
| ④ | `INPLOOKUP_FIB`（14/15 新增）误伤 | `tcp_input.c` `bind_all_fibs=1` 默认不加该 flag → `fib=RT_ALL_FIBS`，wild_match fib 判定短路 |
| ⑤ | pr_usrreqs 合并后 `tcp6_protosw` 的 `pr_*` 漏填/NULL | `tcp_usrreq.c:1431-1458` 22 字段齐全，7 处 v6 变体（accept/bind/connect/control/listen/peeraddr/sockaddr）正确，`pr_attach=tcp_usr_attach` 满足强断言，无 NULL、无残留 `pru_`；`inp_vflag&INP_IPV6` 判定链完整（`in6_pcb.c:680-683`） |
| ⑥ | IPv6 RSS 落到非 listen 队列 / 回包源地址选择失败 | `ff_rss_check6`(`ff_dpdk_if.c:3446-3448`) `nb_queues<=1` 短路 `return 1`；helloworld 单队列(`lcore_mask=10`)不触发；被动 SYN-ACK 走 syncache_respond 源地址=SYN 目的地址，不经 in6_selectsrc |
| ⑦ | 15.0 `in6_pcblookup` exact/wild 双表 + SMR 致 v6 listener 匹配不到 | 插入(`in_pcb.c` in_pcbinshash)与查找(`in6_pcb.c` `in6_pcblookup_hash_wild_smr`)均用 `INP_PCBHASH_WILD(lport)` 定位桶，**插入桶==查找桶**；SMR 基础设施完整且 v4 共用同机制正常 |
| ⑧ | rte_flow 硬编码只 IPv4_TCP 隔离掉 v6 | `Makefile:39` `#FF_FLOW_ISOLATE=1`（**注释掉/未启用**），`create_tcp_flow`(v4 硬编码 rte_flow, `ff_dpdk_if.c:1033` 起 `#ifdef FF_FLOW_ISOLATE`)整段**不编译** |

补充：`f-stack/freebsd/netinet6/nd6.c` 与 15.0 vendor **逐字节一致（diff=0）**，纯 cp 未做用户态适配；出包 nd6 解析链路代码完整（`if_ethersubr.c:236-240` `ether_requestencap(AF_INET6)→nd6_resolve`；`nd6.c` `nd6_resolve→nd6_resolve_slow→nd6_output_ifp`）。

---

## 3. 决定性背景事实（文档铁证）

**IPv6 数据面在整个 13→15 升级中从未真正验证过**：
- `runtime-fix-execution-log.md §12.7`：「IPv6 监听 ⚪N/A — config.ini 未配 addr6/gateway6，跳过」
- `M5-execution-log.md TC-04`：「TCP IPv6 收发」实测 = ❌env-limit
- `ff_rss_check_opt_spec/zh_cn/10-*.md §F6/§148`：「IPv6 RSS 真机 connect 未做，仅单测」
- 升级 spec 对 IPv6 收包派发（ip6_protox / ip6proto_register）**0 覆盖**（全目录 grep=0），netinet6 仅按「cp 15.0 vendor」处理。

→ 这不是「升级把跑通的 v6 改坏」，而是「v6 数据面首次真跑、暴露一批未适配/未验证点」。

---

## 4. 运行时观测（leader 上机实测）

- **f-stack 当前无法运行**：网卡 `0000:00:09.0` 已被 Linux 内核 `virtio_net` 占用作 `cirename0`（前序网络配置任务所致），不在 DPDK/vfio；`HugePages_Total=0`。
- helloworld 启动即 `EAL: No free 2048 kB hugepages` + 网卡未绑 vfio → 退出。→ v6 数据面根本没起来；"监听成功"是用户态 socket 层纯内存操作，与"包能否收发"是两回事。
- f-stack-client 的 IPv6 邻居表：f-stack 侧所有 v6 地址（含 `de6a:7d84`）均解析到**云网关 MAC `fe:ee:2e:9c:ed:94`**，即 v6 流量走云网关转发；且 `de6a:7d84` 入向此前已确认被云网络策略拦截（与安全组排查同源）。

---

## 5. 外网佐证（commit）

- protosw pr_usrreqs 合并：`e7d02be19d40`(D36232)
- pr_input/pr_ctlinput 拆出 → `ip6_protox` 函数指针表 + `ip6proto_register`：`78b1fc05b205`(D36157)
- `INPLOOKUP_FIB`（默认不启用，No functional change）：`685d1d78bf9c`(D48662)
- IPv6 raw socket 配套小修：`61f7427f02a3`

---

## 6. 遗留项（可写入升级 spec）

- **R-IPv6-DP-1**：IPv6 数据面（收包派发 `ip6proto_register` 运行时生效、被动 accept、nd6 NS/NA 邻居解析、SYN/SYN-ACK 收发）在升级中**从未运行时验证**。需在环境就绪后补做真机验证。
- **R-IPv6-DP-2（静态盲区）**：单线程用户态栈下 nd6 的 NS/NA 异步邻居解析能否闭环，静态无法证伪，须运行时抓包坐实。

---

## 7. 建议的下一步（须用户决策）

运行时一锤定音需要：(1) 恢复 hugepage；(2) 将 `0000:00:09.0` 从 `cirename0` 解绑重绑到 vfio-pci（**会中断刚配好的 cirename0 网络**）；(3) config 配 `addr6`，跑 helloworld，抓包确认：v6 SYN 是否到达网卡队列/进 `tcp6_input`、`in6_pcblookup` 是否命中 listener、SYN-ACK 是否发出、nd6 NS/NA 是否闭环。

若不重绑网卡，则依据现有证据，**根因高概率在环境/配置与云网络（安全组/VPC v6 入向）侧，而非 f-stack 代码**。
