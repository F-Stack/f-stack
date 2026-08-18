F-Stack 2.0 前瞻7：MTU 修改支持纪实，从「1500 硬上限」到 9000 巨帧的打通与两个坑

1. 本功能主要作用和特点

F-Stack 的 DPDK 接管网卡之前只能锁死在 MTU 1500，这次把「减小 MTU 已可用、增大 MTU（jumbo frame）完全不可用」的现状，改造成「启动时按配置设置 1500~9000 任意 MTU、运行时通过标准 SIOCSIFMTU ioctl 动态修改、协议栈与 DPDK 硬件联动」的完整支持。

改造前的基线是这么个情况。2026-07 中旬做了一次结论性调研（见 `docs/mtu_change_spec/zh_cn/00~15`），三方证据交叉得出的结论是「部分支持」：

- 减小 MTU（≤1500）：开箱可用。`ff_ioctl(SIOCSIFMTU)` 走 FreeBSD `ether_ioctl`，对 ≤ETHERMTU 的值直接写入 `if_mtu` 即生效
- 增大 MTU（>1500，jumbo）：双重阻断。协议栈层 `ether_ioctl` 对 `ifr_mtu > ETHERMTU(1500)` 硬编码返回 `EINVAL`；DPDK 硬件层完全没有 MTU 接线——没有 `rte_eth_dev_set_mtu` 调用、mbuf 池固定 `RTE_MBUF_DEFAULT_BUF_SIZE`（2048 可用 dataroom）、`rxmode` 无 jumbo/scatter 配置

这个结论和 F-Stack 官方 issue #239/#490/#720 完全一致：jumbo 支持 issue 挂了很久一直是 OPEN，维护者明确回复「mtu 不能超过 1500」。所以这次任务不是打补丁，是把协议栈、DPDK 硬件层、配置体系三个断层全部接上。几个关键词：

- **软硬联动**：一个 MTU 三个视图——协议栈 `if_mtu`、DPDK 端口 MTU、mbuf 池承载能力，三者必须一致，任一不一致启动即失败
- **多进程分工**：DPDK 物理端口是共享状态，primary 唯一负责硬件（设软+硬），secondary 只设本进程软件 MTU，进程间零 IPC
- **零回归承诺**：新增 `mtu_enable` 总开关，不启用时旧配置的 MTU 1500、2176B mbuf、ioctl 行为完全不变

2. 本功能的主要适用场景

2.1 大包吞吐优化场景

这是最直接的动机。issue #1033 的历史结论里就有：大包场景性能下降的根本原因部分与 MTU 1500 导致 IP 分片有关。启用巨帧后 8500 字节的包不再被拆成 6 片，分片重组开销归零。适合内部高速网络、大数据块传输、存储网络这类能统一链路 MTU 的环境。

2.2 需要灵活调小 MTU 的隧道/叠加网络场景

减小 MTU 本来就能用，但这次改造后运行时动态修改统一走标准 SIOCSIFMTU 语义，`ff_ifconfig f-stack-0 mtu <N>` 一条命令改完协议栈+硬件。VXLAN/GRE/隧道叠加场景常需要把 MTU 压到 1400 级别给隧道头留空间。

2.3 多进程生产部署的巨帧统一

1 primary + N secondary 的经典部署下，每个进程各自设置一次 MTU 即可保持一致（primary 管硬件、secondary 管自己的软件视图），无需任何跨进程协调机制。

2.4 不太适合的场景

- 链路对端不支持 jumbo：virtio 等 PMD 的 jumbo 能力有限，且需要底层网卡/vSwitch/对端统一支持，否则大帧中途被丢或分片——代码支持了，链路不支持也是白搭
- KNI 与内核共存做深度 MTU 联动的场景：KNI veth 接口的 MTU 联动不在本期范围（只验证了互斥解除后各自独立工作）
- 想要跨进程事务级 MTU 一致性：本期明确不做 IPC 协调，未设置的进程软件 MTU 保持旧值，这是已知使用约束

3. 本功能的架构特征

3.1 改造前的三层断层

调研阶段画出的根因图，这是理解所有改造的起点：

```
┌────────────────────────────────────────────────┐
│ 应用层：ff_ifconfig f-stack-0 mtu 9000          │
│   ff_ioctl(SIOCSIFMTU)                          │
└───────────────────┬────────────────────────────┘
                    ▼
┌────────────────────────────────────────────────┐
│ 协议栈层（ff_veth.c + FreeBSD 裁剪栈）           │
│   ff_veth_ioctl → ether_ioctl                   │
│   if (ifr_mtu > ETHERMTU) → EINVAL  ← 硬编码1500 │
│   if_mtu 只写在 ifnet，与硬件无联动              │
└───────────────────┬────────────────────────────┘
                    ▼（断层：即使改成功也不下发）
┌────────────────────────────────────────────────┐
│ DPDK 硬件层（ff_dpdk_if.c）                     │
│   无 rte_eth_dev_set_mtu 调用                   │
│   rxmode 无 mtu/max_rx_pkt_len/jumbo 配置       │
│   mbuf 池固定 2048 dataroom ← 装不下大帧        │
└────────────────────────────────────────────────┘
```

3.2 改造后的 SIOCSIFMTU 路径（按进程角色分流）

```
                ff_ifconfig mtu <N>
                       │
              ff_veth_ioctl(SIOCSIFMTU)   ← 拦截，不再委托 ether_ioctl
                       │
         rte_eal_process_type() 判定角色
            ┌──────────┴──────────┐
            ▼                     ▼
       primary                secondary
   ff_dpdk_if_set_mtu()     if_setmtu() 仅设软 MTU
   ① -EBUSY → stop 端口         │（绝不触达 DPDK 端口控制接口）
   ② rte_eth_dev_set_mtu        │
   ③ rte_eth_dev_get_mtu 回读   │
   ④ 失败回滚：restore 旧 MTU   │
      + 重启端口                │
   ⑤ 成功 → if_setmtu(ifp)      │
   ⑥ if_notifymtu(ifp)          │
      ├ nd6_setmtu（IPv6 同步） │
      └ rt_updatemtu（路由同步）│
```

关键设计约束：`ff_veth.c` 不 include `rte_ethdev.h`，所有硬件操作走 `ff_dpdk_if.h` 的不透明接口 `ff_dpdk_if_get_mtu/set_mtu/get_mtu_capability`，DPDK 负 errno 经 `ff_dpdk_errno_to_bsd()` 统一转 BSD 正 errno。

3.3 mbuf 两种承载模式

```
large 模式                          scatter 模式
┌──────────────────────────┐        ┌──────────┐┌──────────┐
│ 单 mbuf，data_room 按      │        │ 标准 mbuf ││ 标准 mbuf │→ ...
│ HEADROOM+max_mtu+         │        │ 2048B    ││ 2048B    │
│ L2_overhead 对齐放大      │        └────┬─────┘└────┬─────┘
└──────────────────────────┘             │  RX_OFFLOAD_SCATTER
     内存开销大，路径简单                │  多段链拼接
                                         ▼
                                    内存省，但要求 PMD 支持
                                    scatter + multi_segs，且
                                    多段 mbuf 转换路径要验证
```

large 模式 `data_room_size = align(HEADROOM + max_mtu + L2_overhead)`，超过 UINT16_MAX 必须确定性失败，所以 large 模式 `max_mtu=65535` 不可用；scatter 模式保持标准 mbuf，可配到 65535 但必须满足 PMD 能力。

4. 具体做了哪些改造、遇到了哪些问题、怎么解决的

后续比较枯燥，不需要深入研究实现过程的可以跳过本节，直接看第 5 节怎么用。

4.1 调研结论直接转化为需求决策（D-MTU-01~06）

调研收尾时定了 6 条决策，全部贯穿实现：

| ID | 决策 |
|---|---|
| D-MTU-01 | mbuf 同时实现 large 与 scatter 两种模式，配置选择 |
| D-MTU-02 | `max_mtu` 可配置，启用功能且缺省时为 9000 |
| D-MTU-05 | **不修改 freebsd/ 树**，在 lib/ff_veth.c 拦截 SIOCSIFMTU 绕过 ether_ioctl 的 1500 硬校验 |
| D-MTU-06 | `mtu_enable=0` 时行为与旧版本完全一致（1500 MTU、2176B mbuf、ioctl 不变） |

其中 D-MTU-05 最值得说一句：`ether_ioctl` 的 ETHERMTU 硬校验是 FreeBSD 通用语义，f-stack 的选择不是在裁剪栈里改它，而是在 ff_veth 驱动层拦截 SIOCSIFMTU 自己处理。这样 freebsd/ 子树零改动，升级 FreeBSD 基线时不会引入新的 patch 维护负担。

4.2 代码实施（M1~M5，2026-07-21）

| 里程碑 | commit | 内容 |
|---|---|---|
| M1 | 97452db34 | 配置解析与校验：enum ff_mbuf_mode、ff_port_cfg.mtu、dpdk.{mtu_enable,max_mtu,mbuf_mode}；严格 strtoul 解析；跨字段校验；8 个单测 +7 fixtures |
| M2 | eec178902 | DPDK 层：ff_mtu_data_room_size() 对齐计算、large 模式 data_room 尺寸、rxmode.mtu + PMD 能力检查 + scatter offload、set/get_mtu 回读 |
| M3 | 0849f9f3a | ff_veth 集成：不透明 MTU API、DPDK errno→BSD errno 转换、SIOCSIFMTU 拦截（primary 软+硬 / secondary 仅软）、启动时从硬件读初始 if_mtu |
| M4 | ef20b1abf | EBUSY 状态机：-EBUSY → stop/set_mtu/get_mtu/start；失败回滚 restore 旧 MTU + 重启端口 |
| M5 | 314df8a0a | 集成测试 + 架构文档更新 |
| 收尾 | 0f8f6991e / 332abf997 / 4c30d118f | magic number 宏化、SIOCSIFMTU handler fall-through 去重、bool→uint8_t 干净编译修复 |

配置解析有一条铁律：禁止 `atoi()`。新增 `ff_parse_u16/ff_parse_mbuf_mode` 严格解析（strtoul + errno/endptr/范围检查），任一配置非法在启动阶段明确报错终止，绝不静默回退到 1500。`mtu_enable=0` 且配置 `mtu>1500` 直接解析失败并提示先启用功能。

4.3 问题一：IPv6 巨帧回包被按 1448 分片（最大的坑）

功能上线物理机验证时，出现一个诡异现象：**IPv4 巨帧双向正常，IPv6 收 8500 字节 ping 正常、但回包被拆成 6 个 1448 字节分片**。

抓包反推：6 片 = 1448×5 + 1268 = 8508，对应分片公式 `len = (mtu - 40 - 8) & ~7`，反解出来 mtu=1500——协议栈明明 if_mtu 已经设成 9000，IPv6 分片用的 MTU 却还是 1500。

根因链拉了 12 个 file:line（完整分析见 `15-IPv6巨帧分片异常分析.md`），总结下来就一句：

```
ether_ifattach(if_mtu=1500) → nd6_ifattach → nd6_setmtu0(ndi->maxmtu=1500)
        ↓
ff_veth if_setmtu(9000) → if_mtu=9000，但【未调 nd6_setmtu】→ ndi->maxmtu 停在 1500
        ↓
IN6_LINKMTU = min 语义 → maxmtu(1500) < if_mtu(9000) → 返回 1500
        ↓
路由 nh_mtu=1500 → ip6_getpmtu → ip6_calcmtu → 分片 len=(1500-48)&~7=1448
```

真正的坑：`if_setmtu()` 只写 `ifp->if_mtu`，**不含协议族通知**。标准 FreeBSD 内核路径 `ifhwioctl → if_setmtu → if_notifymtu → nd6_setmtu + rt_updatemtu` 会同步 IPv6 的 `ndi->maxmtu` 和路由 MTU，而 f-stack 为绕过 ether_ioctl 的 1500 硬校验走了"直接 if_setmtu"的捷径，把 `if_notifymtu` 这一步丢了。IPv4 输出路径直接用 `ifp->if_mtu` 判断分片所以没事，IPv6 走 IN6_LINKMTU 就中招。

修复（commit 0f25ac495，+163/-1）：`ff_veth.c` 启动初始化和运行时 SIOCSIFMTU 两条路径的 `if_setmtu` 之后都补调 `if_notifymtu(ifp)`，与标准内核语义对齐。物理机复测：`ping6 -M do -s 8500` 回包不再分片，IPv6 巨帧收发正常。

【注1】这个坑有普适价值：FreeBSD 里「改 if_mtu」和「通知协议族」是两件事，任何绕过标准 ifhwioctl 路径直接调 if_setmtu 的代码（驱动初始化、ioctl 拦截）都必须自己补 if_notifymtu，否则 IPv6 的 nd_ifinfo 和路由 nh_mtu 会永远停在旧值。顺带一提，当时还排查了次因 RA 通告压低 linkmtu 的可能性，运行时验证确认 linkmtu=0（未受 RA 影响），主因修复后即闭环。

4.4 问题二：KNI/MTU 互斥，先禁止后解除

需求规格 R-MTU-009 初版约定：检测到 `mtu_enable=1` 与 KNI/内核共存同时启用时，配置阶段以 EOPNOTSUPP 拒绝。理由是双栈 MTU 不一致风险。

物理机实测后推翻了这个保守决定（commit 989f1d2da，+1/-6）：`mtu_enable=1` 与 `kni.enable=1` 共存完全正常——veth0 MTU=1500 时内核栈正常拆包收发，`ifconfig veth0 mtu 9000` 时 KNI 通路巨帧收发同样正常。互斥是个不必要的限制，解除后 KNI 用户也能用巨帧。

【注2】这个来回说明 spec 阶段的保守约束值得在实测后重新审视：EOPNOTSUPP 拒绝是最安全的写法，但如果有实测证据表明共存无问题，解除互斥比维持"纸面风险"对用户更友好。

4.5 其他工程细节

- **EBUSY 状态机**：`rte_eth_dev_set_mtu` 对运行中端口可能返回 -EBUSY，M4 实现 primary 进程内的 stop/set_mtu/get_mtu/start，失败回滚 restore 旧 MTU + 重启端口；secondary 直接返回 0 不做硬件操作
- **多进程一致性靠使用约定**：进程间零 IPC、零事务、零消息环，每个进程各自触发一次 SIOCSIFMTU；未设置的进程软件 MTU 保持旧值（已知约束，spec 明示）
- **门禁**：-Werror 编译、freebsd/ 树 git diff 验证零改动、ff_veth.c 无 rte_eth* 引用、无 atoi、无 IPC 残留、mtu_enable=0 全路径零回归——六项全 PASS

5. 如何使用、如何配置、使用效果

5.1 配置

```ini
[dpdk]
mtu_enable=1          # 功能总开关，缺省 0（不启用时行为与旧版完全一致）
max_mtu=9000          # 运行时 MTU 上限 + large 模式 pool 预分配依据，缺省 9000
mbuf_mode=large       # large：单 mbuf 承载巨帧；scatter：标准 mbuf 多段链

[port0]
mtu=9000              # 端口启动时的协议栈+硬件 MTU，缺省 1500
```

约束速查：

- `mtu_enable=0` 且配置 `mtu>1500`：解析失败，提示先启用 MTU 功能
- large 模式 `max_mtu` 上限受 `data_room_size <= UINT16_MAX` 约束（65535 不可用）；scatter 模式可到 65535 但受 PMD 能力限制
- 非法配置启动即报错，不会静默回退

5.2 运行时修改

```bash
# primary 进程：软+硬件一起改（含 EBUSY→stop/set/start）
ff_ifconfig -p 0 f-stack-0 mtu 9000

# 查询
ff_ifconfig -p 0 f-stack-0
f-stack-0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 9000
```

多进程约定：primary 的修改同时更新软/硬件；每个 secondary 需各自触发一次（只改本进程软件视图）。这是使用约定不是 bug，跨进程 IPC 协调是范围外的后续里程碑。

5.3 使用效果（物理机实测）

| 测试项 | 结果 |
|---|---|
| IPv4 巨帧 | `ping -M do -s 8972` 双向 8500 字节收发正常，MTU=9000 不分片 ✅ |
| IPv6 巨帧 | `ping6 -M do -s 8500` 收发正常（修复前回包被按 1448 分 6 片，补 if_notifymtu 后不分片）✅ |
| KNI/MTU 共存 | `mtu_enable=1` + `kni.enable=1` 共存正常；veth0 MTU 1500/9000 收发均正常 ✅ |
| 单元测试 | 59 通过（含 8 个新增 MTU 测试），12 个测试二进制全 PASS ✅ |
| 门禁 | -Werror / freebsd 树零改动 / 无 rte_eth 泄漏 / 无 atoi / 无 IPC 残留 / 零回归 全 PASS ✅ |

单测覆盖：配置解析 8 个新用例（UT-CFG-01..08）+ 7 个 fixtures，重点打配置校验边界（缺省值、跨字段冲突、非法字符串、溢出）。

5.4 对使用者的建议

- 要开巨帧先确认链路：物理网卡、vSwitch、对端全部支持 jumbo 才有意义，链路不支持时大帧中途被丢比 1500 更糟
- 内存敏感场景选 scatter：large 模式 mbuf 池按 max_mtu 预分配，内存开销显著；scatter 省内存但要求 PMD 支持 RX_SCATTER + TX_MULTI_SEGS
- 只想调小 MTU：不用开 mtu_enable，直接 `ff_ifconfig ... mtu 1400` 就是

延伸阅读：

- 调研结论总览与三方证据：docs/mtu_change_spec/zh_cn/00-调研结论总览.md
- IPv6 巨帧分片异常根因链（12 个 file:line）：docs/mtu_change_spec/zh_cn/15-IPv6巨帧分片异常分析.md
- 实施报告（M0~M5 + Post-M5）：docs/mtu_change_spec/zh_cn/14-实施报告.md
- 接口与配置设计：docs/mtu_change_spec/zh_cn/08-接口与配置设计.md
- 相关 issue：#239（set MTU in example）、#490（Why MTU MAX CONF is 1500）、#720（Enabling jumbo frames）、#1033（大包性能与 MTU）
- 三层架构文档：docs/zh_cn/01-LAYER1-ARCHITECTURE.md
- 知识图谱：docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md
