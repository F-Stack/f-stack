# F-Stack 软件 TSO 与分段方案（中文）

> 文档层级：软件 TSO / 分段方案（软件 offload 补充设计之二）
> 设计依据：`02-现状与差距分析.md`（TSO 现状）、`04-方案与架构设计.md`（硬件 TSO 完善）。本文档回答"是否需要软件 TSO"这一问题，并评估 DPDK `rte_gso` 可选路径。
> 权威版本：DPDK `dpdk-stable-24.11.6`、FreeBSD 15.0 移植（`f-stack/freebsd/`）。
> 铁律：本轮**不写代码、不改 lib、不提交**。所有代码引用附精确 `file:line`，凡涉及具体 PMD/运行时行为一律标注"**待运行时验证**"。

---

## 0. 核心结论（先给答案）

> **软件 TSO 无需开发。** F-Stack 的"软件 TSO"本质就是协议栈的正常 MSS 分段：当网卡不支持硬件 TSO 时，FreeBSD TCP 协议栈按 `t_maxseg` 逐段发送，这是协议栈**固有能力**、**已经在工作**、**无任何代码缺口**。DPDK `rte_gso`（发送软分段库）是一条**可选优化路径**（协议栈发大段 + DPDK 软件分段），并非必需，本轮不纳入开发范围，列为未来可选优化。

下文给出完整的坐实逻辑链。

---

## 1. 坐实：软件 TSO = 协议栈 MSS 分段（完整 file:line 逻辑链）

### 1.1 TSO 是否启用取决于 `TF_TSO` 标志

- **TSO 决策点**：`tcp_output.c:558-565`：
  ```c
  if ((tp->t_flags & TF_TSO) && V_tcp_do_tso && len > tp->t_maxseg &&
      (tp->t_port == 0) &&
      ((tp->t_flags & TF_SIGNATURE) == 0) &&
      (!sack_rxmit || V_tcp_sack_tso) &&
      (ipoptlen == 0 || ...) &&
      !(flags & TH_SYN))
      tso = 1;                          /* tcp_output.c:565 */
  ```
  → **只有 `tp->t_flags & TF_TSO` 置位时 `tso=1`**，才把大段交硬件/软件分段；否则 `tso=0`，协议栈按 `t_maxseg` **逐段构造并发送**。

### 1.2 `TF_TSO` 的唯一置位点

- **唯一置位**：`tcp_input.c:3973-3974`：
  ```c
  /* Check the interface for TSO capabilities. */
  if (cap.ifcap & CSUM_TSO) {           /* tcp_input.c:3973 */
      tp->t_flags |= TF_TSO;            /* tcp_input.c:3974 */
      tp->t_tsomax = cap.tsomax;
      tp->t_tsomaxsegcount = cap.tsomaxsegcount;
      tp->t_tsomaxsegsize = cap.tsomaxsegsize;
      ...
  }
  ```
  → `TF_TSO` **仅当接口能力 `cap.ifcap & CSUM_TSO` 为真时置位**。

### 1.3 `cap.ifcap & CSUM_TSO` 的来源

- **IPv4**：`tcp_subr.c:3657-3660`：
  ```c
  if (ifp->if_capenable & IFCAP_TSO4 &&
      ifp->if_hwassist & CSUM_TSO) {    /* tcp_subr.c:3657-3658 */
      cap->ifcap |= CSUM_TSO;           /* tcp_subr.c:3659 */
      cap->tsomax = ifp->if_hw_tsomax;
      ...
  }
  ```
- **IPv6**：`tcp_subr.c:3699-3701`（`IFCAP_TSO6 && if_hwassist & CSUM_TSO`，结构对称）。
- → `cap.ifcap & CSUM_TSO` 为真 **⟺ 接口设置了 `IFCAP_TSO4/6` 且 `if_hwassist & CSUM_TSO`**。

### 1.4 F-Stack 接口能力由 `hw_features.tx_tso` 门控

- **能力设置**：`ff_veth.c:955-961`：
  ```c
  if (cfg->hw_features.tx_tso) {                 /* ff_veth.c:955 */
      if_setcapabilitiesbit(ifp, IFCAP_TSO, 0);  /* ff_veth.c:956 */
      if_sethwassistbits(ifp, CSUM_TSO, 0);      /* ff_veth.c:957 */
      if_sethwtsomax(ifp, IP_MAXPACKET);         /* ff_veth.c:958 */
      if_sethwtsomaxsegcount(ifp, 35);           /* ff_veth.c:959 */
      if_sethwtsomaxsegsize(ifp, 2048);          /* ff_veth.c:960 */
  }
  ```
  → **只有 `hw_features.tx_tso=1` 时才设 `IFCAP_TSO` + `CSUM_TSO` hwassist**。
- **`tx_tso` 的来源**：`ff_dpdk_if.c` TSO 探测块（`04-方案与架构设计.md` 2 节 / `02-现状与差距分析.md` 2.2）：`if (dpdk.tso)` 且 `dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO` 时才置 `hw_features.tx_tso = 1`。

### 1.5 完整逻辑链闭环

```
NIC 无硬件 TSO
  → dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO == 0
  → ff_dpdk_if.c TSO 探测块不置 hw_features.tx_tso（保持 0）
  → ff_veth.c:955 if(cfg->hw_features.tx_tso) 不进入
  → 不设 IFCAP_TSO、不设 if_hwassist & CSUM_TSO
  → tcp_subr.c:3657/3699 cap->ifcap 不含 CSUM_TSO
  → tcp_input.c:3973 if(cap.ifcap & CSUM_TSO) 不进入 → TF_TSO 不置
  → tcp_output.c:558 (tp->t_flags & TF_TSO) 为假 → tso=0
  → 协议栈按 t_maxseg 逐段构造发送（正常 MSS 分段）
```

**这条链已经在工作，无任何断点，无需任何代码开发。** 网卡无 TSO 时，TCP 数据自动走协议栈逐段发送；网卡有 TSO 且 `tso=1` 时，走硬件 TSO（`04` 文档完善其 IPv6/tsomax 正确性）。

---

## 2. 为什么不需要额外的软件 TSO 开发

### 2.1 "软件 TSO" 是伪需求

- 硬件 TSO 的价值：协议栈把一个大段（远超 MSS）交给网卡，网卡硬件切分成多个 MSS 大小的 TCP 段发送，**节省 CPU 分段开销**。
- 所谓"软件 TSO"如果指"用 CPU 做同样的分段"——那就是**协议栈本来就在做的 MSS 分段**（`tcp_output.c` 在 `tso=0` 时逐段发送）。没有独立的"软件 TSO 模块"需要开发，因为**分段本身就是 TCP 协议栈的固有职责**。
- 换言之：**TSO 是"把分段外包给硬件"的优化；不外包时，分段回落到协议栈本身**。协议栈的分段能力永远存在，是硬件 TSO 的天然兜底。

### 2.2 发端无缺口（与硬件路径的一致性）

- `ff_mbuf_tx_offload`（`ff_veth.c:284-307`）：仅当 `mb->m_pkthdr.csum_flags & CSUM_TSO`（`ff_veth.c:305`）时才取 `tso_seg_size = mb->m_pkthdr.tso_segsz`（`ff_veth.c:306`）。
- 由 1.5 的逻辑链：NIC 无 TSO → 协议栈不置 `CSUM_TSO` → `ff_veth.c:305` 分支不进入 → `offload.tso_seg_size` 保持 0 → 下游 `ff_dpdk_if.c` / `ff_memory.c` TSO 分支（`if (offload.tso_seg_size)`）不进入 → 发包按普通（已分好的 MSS 段）路径发送。
- **天然一致**：发端 offload 标记的置位与消费完全由 `CSUM_TSO` 门控，NIC 无 TSO 时全链路自动跳过 TSO 逻辑，不会产生"协议栈发大段但发端不分段"的错配。

### 2.3 与 MTU/巨帧的关系

- 逐段发送时，每段不超过 `t_maxseg`（由 MSS 协商，受路径 MTU 约束）。巨帧（jumbo，`mtu_enable`）场景下 `t_maxseg` 更大，单段可携带更多数据，本身即降低段数，无需额外软件 TSO。
- 硬件 TSO 时 `if_hw_tsomax`（`ff_veth.c:958`，当前 `IP_MAXPACKET`）约束大段总长；软件分段时无此约束（每段本就 ≤ MSS）。

---

## 3. DPDK rte_gso 可选路径评估

### 3.1 rte_gso 是什么

- DPDK 的 **GSO（Generic Segmentation Offload）软件库**：`dpdk-stable-24.11.6/lib/gso/`，核心 API `rte_gso_segment`（`rte_gso.h:120`）。
- 模式：协议栈/应用把一个**大段 mbuf** 交给 `rte_gso_segment`，DPDK 在**软件层**将其切分为多个 MSS 大小的段（输出 mbuf 数组），再发送。
- 采用 **two-part mbuf（零拷贝）** 技术：分段结果的每个 mbuf 头部为新分配的头（含各段独立的 L2/L3/L4 头），数据区通过 `indirect mbuf` 引用原大段数据，避免数据拷贝。

### 3.2 rte_gso 与协议栈 MSS 分段的区别

| 维度 | 协议栈 MSS 分段（现状，`tso=0`） | rte_gso 软分段 |
| --- | --- | --- |
| 分段者 | FreeBSD TCP 协议栈（`tcp_output.c`） | DPDK GSO 库（`rte_gso_segment`） |
| 分段时机 | 协议栈构造报文时逐段 | 协议栈发大段后，发送前由 DPDK 切 |
| 每段开销 | 协议栈逐段走完整 `tcp_output` 路径 | 协议栈只走一次大段路径，DPDK 批量切 |
| 潜在收益 | 无额外收益（基准） | 减少协议栈 per-段处理、减少 tx 描述符生成开销 |
| F-Stack 现状 | **已工作** | **零使用**（`lib/*.c` 搜索 `rte_gso` 命中 0） |

### 3.3 rte_gso 的限制与代价（`03-外网调研.md` / DPDK 文档）

- **需显式调用**：应用/驱动层必须显式调用 `rte_gso_segment`，不会自动 fallback。
- **不重算校验和**：GSO 不负责计算各段的 L3/L4 校验和，需调用方自行处理或依赖硬件 csum offload。
- **仅 IPv4**：`rte_gso` 当前主要支持 IPv4 TCP/UDP（VxLAN、GRE 隧道内层 IPv4）；IPv6 支持受限。
- **two-part mbuf 复杂度**：输出的 indirect mbuf 需正确管理引用计数，出口驱动必须支持多段包（`RTE_ETH_TX_OFFLOAD_MULTI_SEGS`）。
- **需手动填 `l2_len`/`l3_len`/`l4_len`/`tso_segsz`**：与硬件 TSO 的 mbuf 字段填充要求类似。

### 3.4 何时 rte_gso 可能有价值

- **网卡完全无硬件 TSO 且吞吐瓶颈在协议栈逐段开销**：协议栈发大段一次、DPDK 批量切，可减少 `tcp_output` 的 per-段调用开销。
- **软件转发/隧道场景**：VxLAN 等隧道大段需在出口切分。
- **需减少 tx 描述符生成压力**：大段注入 + 出口批量切。

但对 F-Stack 典型场景（协议栈终结型、有 socket 语义），协议栈 MSS 分段已足够，rte_gso 的收益需实测证明，且引入显式调用/csum 管理/two-part mbuf 复杂度。

---

## 4. 结论与建议

### 4.1 软件 TSO：不需开发

1. **软件 TSO = 协议栈 MSS 分段，是协议栈固有能力，已在工作**（1 节完整逻辑链坐实）。
2. **发端无缺口**：NIC 无 TSO 时全链路自动跳过 TSO offload 逻辑，`ff_mbuf_tx_offload`（`ff_veth.c:305`）门控天然一致（2.2）。
3. **本轮不做任何软件 TSO 开发**。

### 4.2 rte_gso：列为未来可选优化，不在本轮范围

- rte_gso 是"协议栈发大段 + DPDK 软分段"的**性能优化**路径，**非功能必需**。
- 引入代价（显式调用、不重算校验和、仅 IPv4、two-part mbuf 复杂度）较高，收益需运行时性能基线证明。
- **建议**：本轮**不引入 rte_gso**；若未来性能基线（`08-性能基线方案.md`）显示协议栈逐段发送的 CPU 开销是瓶颈，再作为独立优化项评估。

### 4.3 与硬件 TSO 的关系（本轮真正的 TSO 工作）

- **硬件 TSO 是加速，软件分段是永远存在的兜底**：二者不是替代关系而是"有硬件用硬件、无硬件回落协议栈"。
- 本轮 TSO 的**真正工作**在硬件 TSO 路径的**正确性完善**（`04-方案与架构设计.md` 2 节），不在"软件 TSO 开发"：
  - IPv6 TSO 伪头/`l3_len` 分流（`ff_dpdk_if.c:2467-2491`，`:2452-2466` 为注释、真正分支起点 `:2467`；`ff_memory.c:358-368`）；
  - IPv4 TSO 显式置 `RTE_MBUF_F_TX_IP_CKSUM` 自洽；
  - `if_hw_tsomax`/`tsomaxsegcount`/`tsomaxsegsize` 取值合理性核对（现状 `ff_veth.c:958-960`：`IP_MAXPACKET`/`35`/`2048`，**待运行时验证**是否匹配目标 PMD）；
  - `ff_dpdk_if.c` 与 `ff_memory.c` 双份逻辑收敛；
  - `ff_mbuf_tx_offload` 兼容 `CSUM_IP6_TSO`（`ff_veth.c:305`）。

---

## 5. 诚实边界（待运行时验证清单）

1. `ff_veth.c:958-960` 现有 `if_hw_tsomax=IP_MAXPACKET` / `tsomaxsegcount=35` / `tsomaxsegsize=2048` 是否匹配目标 PMD（virtio/ixgbe/i40e 各异）——**这是硬件 TSO 完善项，非软件 TSO**。
2. 若未来引入 rte_gso，其在 F-Stack 发包路径的 two-part mbuf 与出口驱动 `MULTI_SEGS` 兼容性。
3. 协议栈逐段发送的 CPU 开销是否构成吞吐瓶颈（决定 rte_gso 是否值得引入）。

> 以上均为运行时/后续里程碑验证项，本轮 spec 不实测。测试环境：DPDK 独占网卡 IP `9.134.214.176`（`ssh f-stack-client` 侧发起），内核栈测试走 `127.0.0.1` 的 `lo`。

---

## 6. 本文档结论摘要

1. **软件 TSO 无需开发**：它就是协议栈 MSS 分段（`tcp_output.c:558` `TF_TSO` 未置时的默认路径），协议栈固有能力，已工作，发端无缺口（完整逻辑链 1 节坐实）。
2. **rte_gso（`rte_gso.h:120`）是可选优化，非必需**：F-Stack 零使用，引入代价高（显式调用/不重算 csum/仅 IPv4/two-part mbuf），本轮不纳入，列为未来性能优化候选。
3. **硬件 TSO 是加速、软件分段是兜底**：本轮 TSO 真正工作在硬件 TSO 正确性完善（IPv6 伪头、IP_CKSUM 自洽、tsomax 核对、双份收敛、CSUM_IP6_TSO 兼容），详见 `04-方案与架构设计.md` 2 节。
