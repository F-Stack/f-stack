# F-Stack 软件 LRO 方案（中文）

> 文档层级：软件 LRO 方案（软件 offload 补充设计之一）
> 设计依据：`02-现状与差距分析.md`、`04-方案与架构设计.md`（硬件 LRO 路径）；本文档聚焦**软件 LRO**（FreeBSD `tcp_lro.c`），作为硬件 LRO 不可用时的补充/回退路径。
> 权威版本：DPDK `dpdk-stable-24.11.6`、FreeBSD 15.0 移植（`f-stack/freebsd/`）。
> 铁律：本轮**不写代码、不改 lib、不提交**，仅出可落地方案。所有代码引用附精确 `file:line`，凡涉及具体 PMD/运行时行为一律标注"**待运行时验证**"。

---

## 0. 为什么需要软件 LRO

### 0.1 硬件 LRO 的局限

硬件 LRO（`04-方案与架构设计.md` 一节）依赖网卡 PMD 在 `dev_info.rx_offload_capa` 宣告 `RTE_ETH_RX_OFFLOAD_TCP_LRO`（`dpdk-stable-24.11.6/lib/ethdev/rte_ethdev.h:1556`）。当满足以下任一条件时，硬件 LRO 不可用：

- **PMD 不支持 LRO offload**：例如本机 virtio（`03-外网调研.md` 2.3：virtio offload 能力受后端 `VIRTIO_NET_F_HOST_TSO4/6`、`GUEST_TSO4/6` 等 feature 协商限制，本机实测 `guest_features=0x110ef8020` **不含 LRO/大接收相关位**）——**待运行时验证**：`dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO` 在本机 virtio 下是否为 0。
- **软件转发/隧道场景**：VxLAN 等隧道内层 TCP 硬件无法聚合。
- **需要在无专用硬件的通用环境获得 LRO 收益**。

因此软件 LRO 是硬件 LRO 的**功能等价补充**：由 CPU 在收包路径上聚合同一 TCP 流的多个报文为一个大段后再上送协议栈，降低协议栈 per-packet 处理开销。

### 0.2 F-Stack 软件 LRO 现状（代码坐实）

- **已编译**：`lib/Makefile:513` 编译 `tcp_lro.c`（软件 LRO 核心已进入编译单元）。
- **无调用点**：全 `lib/*.c` 搜索 `tcp_lro_init` / `tcp_lro_rx` / `tcp_lro_queue_mbuf` / `tcp_lro_flush_all` 等 **命中 0** → 软件 LRO 处于"**编译进来但完全无人调用**"状态。
- **收包入口未接通**：`ff_veth_input`（`ff_dpdk_if.c:1707`）直接 `ff_mbuf_gethdr` → `ff_veth_process_packet` → `if_input`，**中间没有任何 LRO 聚合环节**。

**结论**：软件 LRO 的唯一实质缺口 = **未接入 `ff_veth_input` 收包路径**。API 与核心算法已具备，只差"生命周期管理 + 收包路径接入"两块胶水代码。

---

## 1. tcp_lro API 与 struct lro_ctrl 生命周期

### 1.1 核心 API（`tcp_lro.c` / `tcp_lro.h`）

| API | 定义位置 | 声明 | 作用 |
| --- | --- | --- | --- |
| `tcp_lro_init(struct lro_ctrl *)` | `tcp_lro.c:167` | `tcp_lro.h:215` | 简单初始化，内部转调 `tcp_lro_init_args(lc, NULL, tcp_lro_entries, 0)`（`tcp_lro.c:170`，`lro_mbufs=0` → **经典模式**，无排序数组） |
| `tcp_lro_init_args(struct lro_ctrl *, struct ifnet *, unsigned lro_entries, unsigned lro_mbufs)` | `tcp_lro.c:173` | `tcp_lro.h:216` | 完整初始化，`lro_mbufs>0` 时分配排序数组 → **现代 RSS 排序模式** |
| `tcp_lro_free(struct lro_ctrl *)` | `tcp_lro.c:491` | `tcp_lro.h:217` | 释放 `lro_ctrl` 内部资源（hash 表、mbuf 数组、active/free 链） |
| `tcp_lro_rx(struct lro_ctrl *, struct mbuf *, uint32_t csum)` | `tcp_lro.c:1426` | `tcp_lro.h:221` | **经典模式**逐包入口：直接尝试聚合，失败则 `tcp_lro_flush_active`（`tcp_lro.c:1441`）保序 |
| `tcp_lro_queue_mbuf(struct lro_ctrl *, struct mbuf *)` | `tcp_lro.c:1448` | `tcp_lro.h:222` | **现代模式**逐包入口：把 mbuf 排队进 `lro_mbuf_data` 数组，满时触发 flush |
| `tcp_lro_flush_all(struct lro_ctrl *)` | `tcp_lro.c:1199` | `tcp_lro.h:219` | **现代模式**批末聚合：对排序数组按流排序（`tcp_lro_sort`）后逐流聚合 |
| `tcp_lro_flush`（static） | `tcp_lro.c:1108` | 内部 | 单流聚合落地：`tcp_lro_condense` + `tcp_flush_out_entry` |

### 1.2 struct lro_ctrl（`tcp_lro.h:161-181`）

```c
struct lro_ctrl {
    struct ifnet    *ifp;                 /* L162：绑定接口，flush 时 (*ifp->if_input)() 上送 */
    struct lro_mbuf_sort *lro_mbuf_data;  /* L163：现代模式排序数组（经典模式为 NULL） */
    struct bintime  lro_last_queue_time;  /* L164 */
    uint64_t        lro_queued;           /* L165：统计 */
    uint64_t        lro_flushed;          /* L166 */
    uint64_t        lro_bad_csum;         /* L167 */
    unsigned        lro_cnt;              /* L168：lro_entry 数（活跃流上限） */
    unsigned        lro_mbuf_count;       /* L169：当前排队 mbuf 数 */
    unsigned        lro_mbuf_max;         /* L170：排序数组容量（=init_args 的 lro_mbufs） */
    ...
    struct lro_head *lro_hash;            /* L177：流 hash 桶 */
    struct lro_head lro_active;           /* L178：活跃聚合流链 */
    struct lro_head lro_free;             /* L179：空闲 entry 链 */
    uint8_t         lro_cpu_is_set;       /* L180 */
};
```

- **`ifp` 必填**：flush 落地时通过 `lc->ifp->if_input` 上送（`tcp_lro.c:1252`）。软件 LRO 接入 F-Stack 时，`ifp` 必须绑定 F-Stack 的 veth 接口（即 `ctx->ifp`）。
- **`lro_mbuf_data`**：仅现代模式分配；`lro_mbuf_max=0`（`tcp_lro_init` 默认）时为 NULL，`tcp_lro_queue_mbuf` 会因 `lro_mbuf_max==0` 直接丢包（`tcp_lro.c:1453-1457`）→ **经典模式禁用 queue_mbuf**。

### 1.3 两种模式对比

| 维度 | 经典模式（init + rx） | 现代 RSS 排序模式（init_args + queue_mbuf + flush_all） |
| --- | --- | --- |
| 初始化 | `tcp_lro_init(lc)`（`tcp_lro.c:167`，lro_mbufs=0） | `tcp_lro_init_args(lc, ifp, entries, mbufs>0)`（`tcp_lro.c:173`） |
| 逐包入口 | `tcp_lro_rx(lc, m, csum)`（`tcp_lro.c:1426`）**立即尝试聚合** | `tcp_lro_queue_mbuf(lc, m)`（`tcp_lro.c:1448`）**仅排队** |
| 批末处理 | 无需（rx 内部即聚合，失败即 flush_active） | `tcp_lro_flush_all(lc)`（`tcp_lro.c:1199`）**排序后成批聚合** |
| 排序数组 | 不用 | 用 `lro_mbuf_data`，按流 seq 基数排序（`tcp_lro_sort` `tcp_lro.c:1135`）提高聚合率 |
| 保序 | rx 内失败即 `tcp_lro_flush_active`（`tcp_lro.c:1441`） | flush_all 内按流分组，跨流排序不影响流内保序 |
| **NULL 裸调风险** | **无**（`tcp_lro_rx` 不调 `tcp_hpts_softclock`） | **有**（`tcp_lro_flush_all:1261` 裸调，见 3 节） |
| 适用场景 | 单队列/简单聚合 | 硬件 RSS 已分流、批量收包（iflib 采用） |

**关键结论**：经典模式（`tcp_lro_rx`）**不触发** `tcp_lro.c:1261` 的 `tcp_hpts_softclock()` 裸调用，是 F-Stack 首选接入路径（见 3 节）。

### 1.4 iflib 黄金范式（仅参考，F-Stack 不使用 iflib）

FreeBSD 通用驱动框架 iflib 的软件 LRO 用法是"教科书范式"，F-Stack 接入时**复刻其结构**（但不用 iflib 本身）：

| 阶段 | iflib 位置 | 动作 |
| --- | --- | --- |
| 字段 | `iflib.c:462` | 每个 rxq 一个 `struct lro_ctrl ifr_lc`（per-queue 放置） |
| 初始化 | `iflib.c:6035` | `tcp_lro_init_args(&rxq->ifr_lc, ...)`（每 rxq 一次） |
| 门控 | `iflib.c:2999` | `if (lro_enabled)`（`IFCAP_LRO` 开启才走 LRO） |
| 逐包 | `iflib.c:3000` | `tcp_lro_queue_mbuf(&rxq->ifr_lc, m)`（现代模式排队） |
| 批末 | `iflib.c:3029` | `tcp_lro_flush_all(&rxq->ifr_lc)`（收包批处理结束时 flush） |
| 释放 | `iflib.c:6056` / `iflib.c:6079` | `tcp_lro_free(&rxq->ifr_lc)`（rxq 销毁时） |

**F-Stack 与 iflib 的关键差异**：
- iflib 用**现代模式**（queue_mbuf + flush_all），因此踩 `tcp_lro.c:1261` 裸调；iflib 环境下 `tcp_hpts_softclock` 是**真实实现**（非 NULL），故不崩。**F-Stack 的 `tcp_hpts_softclock` 是 NULL stub**（`ff_stub_14_extra.c:627`），直接复刻现代模式会崩（见 3 节）。
- iflib 是多队列多线程；F-Stack 是**单线程 run-to-completion**（每 lcore 独占一组队列），`lro_ctrl` 宜 **per-lcore/per-port** 放置，无需锁。

---

## 2. F-Stack 软件 LRO 接入方案

### 2.1 收包接入点

- **入口**：`ff_veth_input`（`ff_dpdk_if.c:1707`）。当前流程：
  - `ff_dpdk_if.c:1710-1715`：`rx_csum` 时检查 `RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD`，坏则丢。
  - `ff_dpdk_if.c:1720`：`ff_mbuf_gethdr(pkt, pkt->pkt_len, data, len, rx_csum)` 建 FreeBSD mbuf 头。
  - `ff_dpdk_if.c:1737-1751`：遍历 `pkt->next` 多段挂链。
  - `ff_dpdk_if.c:1753`：`ff_veth_process_packet(ctx->ifp, hdr)` → `if_input`。
- **软件 LRO 插入位置**：在 `ff_mbuf_gethdr`（`ff_dpdk_if.c:1720`）**建成 FreeBSD mbuf（`hdr`）之后**、上送 `if_input` 之前，把 `hdr`（FreeBSD `struct mbuf *`）投喂给 `tcp_lro_rx`（经典模式），聚合成功由 LRO 内部延后上送，聚合失败/非 TCP 由 LRO 内部或回退逻辑走原 `if_input`。

**关键约束**：`tcp_lro_rx` 的入参是 **FreeBSD `struct mbuf *`**（不是 DPDK `rte_mbuf`）。F-Stack 收包路径在 `ff_mbuf_gethdr` 之后已得到 FreeBSD mbuf（`hdr`），因此软件 LRO 接入点必须在 `ff_mbuf_gethdr` **之后**，多段挂链完成后（`hdr` 是完整 mbuf 链头）再交给 LRO。

### 2.2 per-lcore/per-port lro_ctrl 放置

F-Stack 单线程 run-to-completion，每 lcore 独占队列，**无需锁**。`lro_ctrl` 放置：

| 阶段 | 放置位置（设计） | 动作 |
| --- | --- | --- |
| 定义 | `ff_dpdk_if_context` 或 per-lcore/per-port 上下文中新增 `struct lro_ctrl lro`（每端口/每 lcore 一个） | 与 iflib `ifr_lc`（`iflib.c:462`）对应 |
| 初始化 | 端口/lcore 初始化路径（`ff_dpdk_if.c` 端口 setup 或 `ff_veth` 注册后），仅当软件 LRO 开关开启 | `tcp_lro_init(&lro)` 绑定 `lro.ifp = ctx->ifp`（**经典模式**） |
| 逐包 | `ff_veth_input`（`ff_dpdk_if.c:1720` 之后） | `tcp_lro_rx(&lro, hdr, 0)`；返回非 0（未聚合/非 TCP）时回退 `ff_veth_process_packet` 原路径 |
| 批末 | 收包批处理循环末（`ff_dpdk_process_packets` 等一批 `rte_eth_rx_burst` 处理完处） | 经典模式下 `tcp_lro_rx` 已即时聚合，批末可选调用 `tcp_lro_flush_inactive`（`tcp_lro.h:218`，按时间 flush 超时未满流），**不调 `tcp_lro_flush_all`** |
| 释放 | 端口/lcore 清理路径 | `tcp_lro_free(&lro)` |

> **`lro.ifp` 绑定**：`tcp_lro_rx` 聚合成功后由 `tcp_lro_flush` → `tcp_flush_out_entry` → 最终经 `lc->ifp->if_input`（`tcp_lro.c:1252` 是 flush_all 路径的上送；经典 flush 路径同样依赖 `ifp`）上送。因此 `lro.ifp` 必须绑定 F-Stack veth 接口，与 `ctx->ifp` 一致。

### 2.3 经典模式接入伪代码（设计说明，非落地代码）

```c
/* ff_veth_input 内，ff_mbuf_gethdr + 多段挂链完成得到 hdr 之后 */
if (ctx->sw_lro_enabled) {                       /* 软件 LRO 开关，见 4 节 */
    /* hdr 是完整 FreeBSD mbuf 链头 */
    if (tcp_lro_rx(&ctx->lro, (struct mbuf *)hdr, 0) == 0) {
        return;                                  /* 已被 LRO 接管（聚合或暂存），不再直接上送 */
    }
    /* 返回非 0：非 TCP / 无法聚合，tcp_lro_rx 内部已 flush_active 保序，
       此处按原路径上送剩余包 */
}
ff_veth_process_packet(ctx->ifp, hdr);
```

- **返回值语义**（`tcp_lro.c:1426-1445`）：`tcp_lro_rx` 返回 0 = 已入 LRO 引擎（后续由 LRO flush 上送）；返回非 0 = 不可 LRO（如非 TCP、csum 坏），内部已 `tcp_lro_flush_active`（`tcp_lro.c:1441`）保序，调用方需自行上送该包。
- **csum 入参**：`tcp_lro_rx(lc, m, csum)` 第三参 `csum` 为预校验和。F-Stack 收包若已由 PMD 校验（`rx_csum`），可传 0（表示交由 LRO 自行处理/信任）；**待运行时验证**：csum 传参对聚合正确性的影响。

---

## 3. ⚠ 关键风险：tcp_lro.c:1261 `tcp_hpts_softclock()` NULL 裸调用

### 3.1 风险坐实

- **裸调用点**：`tcp_lro_flush_all`（`tcp_lro.c:1199`）函数体结尾：
  ```c
  done:
      tcp_lro_rx_done(lc);
      tcp_hpts_softclock();   /* tcp_lro.c:1261 —— 无判空的裸调用 */
      lc->lro_mbuf_count = 0;
  ```
- **函数指针为 NULL**：`tcp_hpts_softclock` 在 F-Stack 被定义为 NULL 函数指针：
  ```c
  void (*tcp_hpts_softclock)(void) = NULL;   /* ff_stub_14_extra.c:627 */
  ```
- **后果**：若软件 LRO 走**现代模式**（`tcp_lro_flush_all`），执行到 `tcp_lro.c:1261` 会**解引用 NULL 函数指针 → 崩溃**。

### 3.2 经典模式天然规���（首选依据）

- `tcp_lro_rx`（`tcp_lro.c:1426`）与其内部 `tcp_lro_flush`（`tcp_lro.c:1108`）**不含** `tcp_hpts_softclock()` 调用。
- `tcp_lro_flush`（`tcp_lro.c:1108-1122`）内另有一个 hpts 相关函数指针 `tcp_lro_flush_tcphpts`（`tcp_lro.h:220`）：
  ```c
  if (tcp_lro_flush_tcphpts == NULL ||
      tcp_lro_flush_tcphpts(lc, le) != 0) {
      tcp_lro_condense(lc, le);         /* tcp_lro.c:1116：核心聚合 */
      tcp_flush_out_entry(lc, le);      /* tcp_lro.c:1117：上送 */
  }
  ```
  当 `tcp_lro_flush_tcphpts == NULL` 时**安全回退**到 `tcp_lro_condense`（核心聚合可完全脱离 hpts）。**待坐实（编码阶段 read_file）**：`tcp_lro_flush_tcphpts` 在 F-Stack 是否也为 NULL（若为 NULL，则经典 flush 路径完全安全）。
- **结论**：经典模式（`tcp_lro_rx`）路径**不触碰** `tcp_lro.c:1261`，是规避 NULL 裸调最干净的方案。

### 3.3 三个候选处理方案对比

| 候选 | 做法 | 优点 | 缺点 | 适用 |
| --- | --- | --- | --- | --- |
| **A. 走经典模式（首选）** | 接入用 `tcp_lro_init` + `tcp_lro_rx`，**不用** `tcp_lro_flush_all`；批末改用 `tcp_lro_flush_inactive`（不含 1261 裸调） | 零改 `tcp_lro.c`；不触碰 NULL 裸调；无 lib 侵入 | 无排序聚合，聚合率可能略低于 RSS 排序模式（F-Stack RSS 已分流到 per-lcore，同 lcore 内本就同流，影响小） | **本轮首选** |
| **B. 给 `tcp_hpts_softclock` 设安全 stub** | 在 `ff_stub_14_extra.c:627` 把 NULL 改为一个空实现 `static void ff_hpts_softclock_noop(void){}`，指针指向它 | 允许后续使用现代模式；一处修改全局生效 | 改 stub 属改 lib（本轮不改代码）；空实现是否满足 hpts 语义需评估（当前 F-Stack 无 hpts，空实现语义上等价"无 hpts 定时器推进"，可接受） | 若将来需现代模式 |
| **C. 条件判空跳过** | 若必须用 `tcp_lro_flush_all`，在其调用前后不改源码无法插入判空（1261 在函数内部）；只能改 `tcp_lro.c:1261` 为 `if (tcp_hpts_softclock) tcp_hpts_softclock();` | 精确、最小语义改动 | **改 FreeBSD 移植源码**（`tcp_lro.c`），违背"不改 FreeBSD 移植"惯例，且未来同步上游有冲突风险 | 最不推荐 |

**推荐**：**方案 A（经典模式）**。理由：(1) 零改 lib、零改 FreeBSD 移植；(2) 从路径上彻底绕开 `tcp_lro.c:1261` NULL 裸调；(3) F-Stack RSS 已把同流报文分流到同一 lcore 队列，经典模式在 per-lcore 上下文中聚合率损失有限。若后续性能基线显示经典模式聚合率不足，再评估方案 B（设安全 stub 后启用现代模式）。方案 C（改 FreeBSD 移植源码）仅作最后手段。

---

## 4. 与硬件 LRO 的开关协同

> 完整的软硬开关统一语义见 `13-软硬offload对接方案.md`，本节给出软件 LRO 侧视角。

### 4.1 软件 LRO 何时启用

三种候选策略（推荐详见文档 13）：

- **策略 1：硬件优先 + 软件回退（推荐）**：`lro=1` 时先探测硬件（`dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO`），硬件支持则用硬件 LRO、**不启用软件 LRO**；硬件不支持则回退启用软件 LRO。用户只需一个 `lro` 开关，实现自动选优。
- **策略 2：独立开关**：新增 `sw_lro` 独立开关，与硬件 `lro` 正交，用户显式控制。灵活但需用户理解两个开关的组合语义。
- **策略 3：三态 lro**：`lro=0` 关 / `lro=1` 硬件优先+软件回退 / `lro=2` 强制软件。语义集中在一个键但值语义较隐晦。

### 4.2 软硬互斥（关键）

**硬件 LRO 与软件 LRO 必须互斥，不可叠加**：

- 硬件 LRO 启用时，PMD 上送的已是**聚合大段**（`pkt->ol_flags & RTE_MBUF_F_RX_LRO`，`pkt_len` 大）。若再走软件 `tcp_lro_rx`，会对已聚合的大段二次聚合 —— 语义错误、无收益、且可能触发 LRO 引擎对超长段的异常处理。
- 因此：`ctx->sw_lro_enabled` 与 `hw_features.rx_lro` **互斥**。硬件 LRO（`rx_lro=1`）生效时，软件 LRO 开关必须为 0。

### 4.3 IFCAP_LRO 的协同

- `ff_veth.c:945-947` 现有代码：`if (cfg->hw_features.rx_lro) if_setcapabilitiesbit(ifp, IFCAP_LRO, 0)`（**当前仅由硬件 `rx_lro` 驱动**）。
- 软件 LRO 启用时也需向协议栈声明 `IFCAP_LRO`（让协议栈按 LRO 语义接收大段），故 `IFCAP_LRO` 的设置条件应扩展为 `hw_features.rx_lro || sw_lro_enabled`（具体见文档 13 的统一开关设计）。

---

## 5. 软件 LRO 副作用与风险

### 5.1 协议语义副作用（外网调研 + FreeBSD 通识）

- **丢失各段到达时间戳**：LRO 把多个报文合并为一个大段，只保留聚合内某个报文的时间戳，RTT 测量精度下降，影响 TCP 拥塞控制的 RTT 采样。
- **丢失/合并 ECN 位**：多段的 ECN（Explicit Congestion Notification）位在合并时被归并，拥塞信号可能被削弱或丢失，影响拥塞响应。
- **对丢包恢复的影响**：聚合大段掩盖了原始报文边界，SACK/快速重传的粒度变粗。
- **基础栈 vs RACK/BBR**：FreeBSD 基础 TCP 栈（非 RACK/BBR）的软件 LRO 走"拼大段 → 注入接口层 `if_input`"路径（本方案即此路径）；RACK/BBR 有更精细的 LRO/hpts 协同（依赖 `tcp_lro_flush_tcphpts`/`tcp_hpts_softclock`，F-Stack 当前 stub 掉）。**F-Stack 走基础栈路径**，不涉及 hpts 精细协同。

### 5.2 资源与性能副作用

- **内存**：`lro_ctrl` 的 hash 表、entry 池、（现代模式的）排序数组占用内存，per-lcore 一份。经典模式无排序数组，内存开销较小。
- **时延**：聚合本身引入排队时延（等待同流后续报文），`tcp_lro_flush_inactive` 的超时参数决定最大暂存时延。对时延敏感场景（如短连接、请求-响应）可能是负收益，对吞吐型大流是正收益。
- **乱序**：`tcp_lro_rx` 内对不可聚合包 `tcp_lro_flush_active`（`tcp_lro.c:1441`）保序，但聚合与非聚合流交织时需确保上送顺序正确 —— **待运行时验证**：F-Stack 单线程经典模式下的保序正确性。

### 5.3 风险等级

| 风险 | 等级 | 缓解 |
| --- | --- | --- |
| NULL 裸调崩溃（`tcp_lro.c:1261`） | 高（若误用现代模式） | 方案 A 经典模式规避；默认关闭 |
| 拥塞控制/RTT 精度下降 | 中 | 文档化；对时延敏感业务不建议开启 |
| 保序/乱序 | 中 | 经典模式 flush_active 保序；运行时验证 |
| 内存开销 | 低 | 经典模式无排序数组；per-lcore 可控 |
| 与硬件 LRO 叠加 | 中 | 4.2 强制互斥 |

---

## 6. 与 RSS 多队列 / 多进程的关系

- **RSS 正交**：RSS 按流 hash 把不同流分散到不同队列/lcore，软件 LRO 在**每个 lcore 的 per-lcore `lro_ctrl`** 内聚合本 lcore 收到的流。由于 RSS 保证"同流同队列"，同一 lcore 内本就是同流报文聚集，经典模式无需跨 lcore 排序即可高效聚合。
- **多进程（primary/secondary）**：每个进程/lcore 独立持有 `lro_ctrl`，互不共享（无需锁）。secondary 进程按同样开关（共享配置 `hw_features` + 软件 LRO 开关）在各自收包路径接入。**待运行时验证**：多进程下各 lcore 独立聚合的正确性与统计汇总。
- **单线程 run-to-completion 优势**：F-Stack 无中断上下文、无软中断，收包批处理天然是"一批 `rte_eth_rx_burst` → 逐包处理 → 批末"，与 iflib 的 rxq 批处理结构一致，`tcp_lro_flush_inactive` 可放在批末，无并发风险。

---

## 7. 诚实边界（待运行时验证清单）

1. 本机 virtio `dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO` 是否为 0（决定软件 LRO 是否为唯一 LRO 路径）。
2. `tcp_lro_flush_tcphpts`（`tcp_lro.h:220`）在 F-Stack 是否为 NULL（若是，经典 flush 路径 `tcp_lro.c:1114-1116` 完全走 `tcp_lro_condense`，安全）。
3. `tcp_lro_rx` csum 入参（第三参）在 F-Stack `rx_csum` 已校验场景下应传何值。
4. 经典模式在 F-Stack 单线程 per-lcore 下的聚合率（是否需要升级到现代模式 + 方案 B 安全 stub）。
5. 聚合引入的时延对时延敏感业务的影响（`tcp_lro_flush_inactive` 超时参数调优）。
6. 单线程经典模式下聚合流与非聚合流交织的保序正确性。
7. 多进程 primary/secondary 各 lcore 独立聚合的正确性。

> 以上均为运行时/后续里程碑验证项，本轮 spec 不实测。测试环境：DPDK 独占网卡 IP `<DPDK_NIC_IP>`（`ssh f-stack-client` 侧发起），内核栈测试走 `127.0.0.1` 的 `lo`。

---

## 8. 本文档结论摘要

1. **软件 LRO 唯一缺口 = 未接入 `ff_veth_input`（`ff_dpdk_if.c:1707`）**。`tcp_lro.c` 已编译（`Makefile:513`），API 与算法齐全，只差生命周期管理 + 收包接入胶水。
2. **首选经典模式**（`tcp_lro_init` + `tcp_lro_rx` + `tcp_lro_flush_inactive`），per-lcore/per-port `lro_ctrl`，接入点在 `ff_mbuf_gethdr`（`ff_dpdk_if.c:1720`）之后。
3. **⚠ `tcp_lro.c:1261` `tcp_hpts_softclock()` NULL 裸调（`ff_stub_14_extra.c:627`）是最大风险**。**推荐方案 A（经典模式天然规避）**，方案 B（设安全 stub）备选，方案 C（改 FreeBSD 移植源码）仅最后手段。
4. **软硬 LRO 强制互斥**：硬件 LRO 生效时不启用软件 LRO（避免二次聚合）。开关协同推荐"硬件优先 + 软件回退"（详见文档 13）。
5. 软件 LRO 有拥塞控制/RTT/时延副作用，**默认关闭**，对时延敏感业务不建议开启。
