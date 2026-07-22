# F-Stack 软硬 offload 对接方案（中文）

> 文档层级：软硬 offload 对接方案（软件 offload 补充设计之三 / 统一集成设计）
> 设计依据：`04-方案与架构设计.md`（硬件 LRO/TSO）、`05-接口与配置设计.md`（接口契约）、`11-软件LRO方案.md`、`12-软件TSO与分段方案.md`。本文档统一软件与硬件 offload 的能力探测、开关语义、路径协同与零回归保证。
> 权威版本：DPDK `dpdk-stable-24.11.6`、FreeBSD 15.0 移植（`f-stack/freebsd/`）。
> 铁律：本轮**不写代码、不改 lib、不提交**。所有代码引用附精确 `file:line`，凡涉及具体 PMD/运行时行为一律标注"**待运行时验证**"。

---

## 0. 对接现状总览（代码坐实）

| 方向 | 硬件路径 | 软件路径 | 对接缺口 |
| --- | --- | --- | --- |
| **LRO（收）** | `ff_dpdk_if.c` 探测 `RTE_ETH_RX_OFFLOAD_TCP_LRO`（`04` 文档 1.2）；`IFCAP_LRO` 已由 `hw_features.rx_lro` 驱动（`ff_veth.c:945-947`） | `tcp_lro.c` 已编译（`Makefile:513`）但**未接入 `ff_veth_input`**（`ff_dpdk_if.c:1707`） | **唯一实质缺口：软件 LRO 未接入收包路径**（文档 11） |
| **TSO（发）** | `ff_dpdk_if.c` 探测 `RTE_ETH_TX_OFFLOAD_TCP_TSO`；`IFCAP_TSO`+`if_hw_tsomax*` 已设（`ff_veth.c:955-961`） | 协议栈 MSS 分段（`tcp_output.c:558` `tso=0` 路径），**已工作，无缺口** | **发端无缺口**（文档 12） |

- **发端天然一致**（`02` 文档 / 文档 12 2.2）：`ff_mbuf_tx_offload`（`ff_veth.c:305-306`）仅 `CSUM_TSO` 时取 `tso_segsz`；NIC 无 TSO → 协议栈不置 `CSUM_TSO` → 发端 TSO 分支自动跳过。
- **`ff_hw_features` 字段**（`ff_config.h:112-118`）：`rx_csum`(L113)/`rx_lro`(L114)/`tx_csum_ip`(L115)/`tx_csum_l4`(L116)/`tx_tso`(L117)。填充点 `ff_dpdk_if.c`（csum/tso/lro 探测块）；消费点 `ff_veth.c:942-961`。
- **config.ini offload 项**：`tx_csum_offoad_skip=0`（L19）、`tso=0`（L22）、`lro=0`（L24）。

---

## 1. 能力探测与优先级设计

### 1.1 探测分层

offload 能力分三层，探测顺序：**硬件能力 → 用户意图 → 软件回退**。

| 层 | 数据源 | 位置 | 语义 |
| --- | --- | --- | --- |
| 硬件能力 | `dev_info.rx_offload_capa` / `tx_offload_capa` | `ff_dpdk_if.c` 端口 setup | PMD 客观支持哪些 offload |
| 用户意图 | `dpdk.lro` / `dpdk.tso` | `config.ini` → `ff_config.c` 解析 | 用户是否希望启用 |
| 生效状态 | `hw_features.rx_lro` / `tx_tso` | `ff_dpdk_if.c` 探测块置位 | 实际生效（意图 ∧ 硬件能力） |
| 软件回退 | `ctx->sw_lro_enabled`（新增，仅 LRO 需要） | `ff_dpdk_if.c` 探测块推导 | 硬件不支持时的软件补充 |

### 1.2 LRO 优先级：硬件优先，软件回退

```
lro=0：不启用任何 LRO（硬件、软件都关）——默认，零回归
lro=1：
    探测 dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO：
      ├─ 支持 → hw_features.rx_lro = 1；sw_lro_enabled = 0（用硬件，不用软件）
      └─ 不支持 → hw_features.rx_lro = 0；sw_lro_enabled = 1（回退软件 LRO）
```

- **优先级理由**：硬件 LRO 零 CPU 开销、聚合质量高，优先使用；仅当硬件不支持（如本机 virtio，**待运行时验证**）才回退软件 LRO（CPU 聚合，有开销但功能等价）。
- **互斥保证**：`hw_features.rx_lro` 与 `sw_lro_enabled` 永不同时为 1（见 4 节）。

### 1.3 TSO 优先级：硬件加速，协议栈兜底

```
tso=0：不启用硬件 TSO——默认，协议栈按 MSS 逐段发送（软件分段兜底始终存在）
tso=1：
    探测 dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO：
      ├─ 支持 → hw_features.tx_tso = 1（硬件 TSO，协议栈发大段交硬件切）
      └─ 不支持 → hw_features.tx_tso = 0（协议栈按 MSS 逐段发送，同 tso=0 效果）
```

- TSO 无需"软件回退开关"：不支持硬件 TSO 时协议栈**自动**逐段发送（文档 12 1.5 逻辑链），这是固有兜底，不需要额外开关。
- 因此 TSO 侧的软硬对接**已完备**，本轮 TSO 工作仅在硬件路径正确性完善（`04` 文档 2 节）。

---

## 2. 开关语义统一设计（关键决策）

### 2.1 三个候选方案

| 方案 | 键 | 值语义 | 优点 | 缺点 |
| --- | --- | --- | --- | --- |
| **方案 A：单开关自动选优（推荐）** | `lro`（复用现有键） | `0`=关；`1`=启用（硬件优先，硬件不支持自动回退软件） | 用户只需一个开关，语义与 `tso` 对称，自动选优；老配置零回归 | 用户无法"强制只用硬件"或"强制只用软件"（但这是高级需求，可后续加） |
| **方案 B：独立软件开关** | `lro` + 新增 `sw_lro` | `lro`=硬件 LRO 开关；`sw_lro`=软件 LRO 开关（正交） | 用户可精确控制硬件/软件；调试友好 | 两开关组合语义需用户理解；`lro=1 && sw_lro=1` 的互斥需额外裁决；新增配置项 |
| **方案 C：三态单键** | `lro` | `0`=关；`1`=硬件优先+软件回退；`2`=强制软件 | 一个键覆盖三态；可强制软件（调试/无硬件确定场景） | 值 `2` 语义隐晦；`atoi` 后需范围校验；与 `tso` 的 0/1 二态不对称 |

### 2.2 推荐方案 A（单开关自动选优）+ 内部软件回退标志

**推荐 A**，理由：

1. **与既有 `tso` 语义完全对称**：`tso=0/1`、`lro=0/1`，用户心智一致（`05` 文档 1.1 已定义 `lro=0` 默认）。
2. **零新增配置项**：不引入 `sw_lro`，`config.ini` 只有一个 `lro`（`config.ini:24` 已存在 `lro=0`），符合"config.ini 最小改动 + 本地测试值不入库"规约。
3. **自动选优**：`lro=1` 时硬件优先、硬件不支持自动回退软件，对用户透明，无需理解硬件/软件差异。
4. **软件回退标志内部化**：`sw_lro_enabled` 是**内部推导状态**（不暴露给 config.ini），在 `ff_dpdk_if.c` 探测块由 `dpdk.lro && !hw_features.rx_lro` 推导，放入 `ff_dpdk_if_context` 或 per-lcore 上下文，供 `ff_veth_input`（文档 11 2.3）消费。

**内部状态推导（设计）**：

```c
/* ff_dpdk_if.c 端口 setup，LRO 探测块内（04 文档 1.2 的扩展） */
if (ff_global_cfg.dpdk.lro) {
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO) {
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_LRO;
        /* max_lro_pkt_size 设置见 04 文档 1.3 */
        pconf->hw_features.rx_lro = 1;      /* 硬件 LRO */
        pconf->sw_lro_enabled = 0;          /* 不用软件 */
        ff_log(..., "LRO: hardware\n");
    } else {
        pconf->hw_features.rx_lro = 0;
        pconf->sw_lro_enabled = 1;          /* 回退软件 LRO（文档 11） */
        ff_log(..., "LRO: hardware not supported, fallback to software\n");
    }
} else {
    pconf->hw_features.rx_lro = 0;
    pconf->sw_lro_enabled = 0;
    ff_log(..., "LRO: disabled\n");
}
```

- **`sw_lro_enabled` 字段归属**：设计放在 `ff_dpdk_if_context`（`ff_veth_input` 通过 `ctx` 可直接访问）或 per-lcore 上下文；**不放** `ff_hw_features`（`ff_hw_features` 是随 config 共享的 per-port 硬件能力描述，软件回退是运行策略，语义上应分离）。**编码阶段坐实** `ff_dpdk_if_context` 结构定义位置并对齐。
- **升级到 B/C 的兼容路径**：方案 A 不阻断未来扩展——若后续调试需要"强制软件/强制硬件"，可再加 `sw_lro` 独立开关（方案 B）或值 `2`（方案 C），届时 `sw_lro_enabled` 的推导逻辑扩展即可，A 的默认行为不变。

### 2.3 为何不推荐 B/C（本轮）

- **B（独立 sw_lro）**：新增 config.ini 项违背最小改动；`lro=1 && sw_lro=1` 需额外互斥裁决；用户认知负担高。**调试期**若确实需要强制软件，可临时用方案 C 的思路或代码级开关，不必固化为 config 项。
- **C（三态）**：`lro=2` 语义隐晦、与 `tso` 二态不对称、需范围校验；"强制软件"是小众高级需求，不值得让主开关变复杂。

---

## 3. 收发路径的 offload 标记透传与协同

### 3.1 收方向（LRO）标记透传

| 环节 | 硬件 LRO | 软件 LRO |
| --- | --- | --- |
| PMD 产出 | 大段 mbuf（`pkt_len` 大、可能 `nb_segs>1`、`ol_flags & RTE_MBUF_F_RX_LRO`） | 普通逐包 mbuf |
| csum 校验 | PMD 已校验聚合段，置 `RTE_MBUF_F_RX_L4_CKSUM_GOOD/BAD` | 普通包 csum，`ff_veth_input:1710-1715` 检查 |
| `ff_veth_input` | 凭 `pkt_len` + 多段遍历搬进 FreeBSD mbuf（`04` 文档 1.4，长度维度已支持） | 逐包 `ff_mbuf_gethdr` 后交 `tcp_lro_rx` 聚合（文档 11 2.3） |
| 上送协议栈 | 直接 `if_input` 大段 | `tcp_lro_rx` 聚合后由 LRO flush 上送大段 |
| ifnet 能力 | `IFCAP_LRO`（`ff_veth.c:945-947`，`rx_lro` 驱动） | 同样需 `IFCAP_LRO`（条件扩展见 3.3） |

- **`RTE_MBUF_F_RX_LRO` 透传**：硬件 LRO 大段带此标记，但 FreeBSD `if_input` 按 mbuf 长度接收，`RTE_MBUF_F_RX_LRO` 透传对协议栈接收**非必需**（`04` 文档 1.4 已论证），首版可不透传。软件 LRO 产出的大段无此标记（是 LRO 引擎在协议栈侧合并），亦不影响接收。

### 3.2 发方向（TSO）标记透传

| 环节 | 硬件 TSO（`tso=1` 且 PMD 支持） | 软件分段（`tso=0` 或 PMD 不支持） |
| --- | --- | --- |
| 协议栈 | 发大段，置 `CSUM_TSO` + `tso_segsz`（`tcp_output.c`） | 逐段发送，不置 `CSUM_TSO` |
| `ff_mbuf_tx_offload` | `ff_veth.c:305` 取 `tso_seg_size` | `CSUM_TSO` 未置，`tso_seg_size=0` |
| 发包 offload 填充 | `ff_dpdk_if.c:2455` / `ff_memory.c:358` TSO 分支置 `RTE_MBUF_F_TX_TCP_SEG` + 伪头 + `l2/l3/l4_len/tso_segsz`（`04` 文档 2.1 按 version 分流） | `if (offload.tso_seg_size)` 不进入，普通发送 |
| PMD | 硬件切段 | 收到已分好的 MSS 段直接发 |

- **透传自洽**：发方向 TSO 标记透传完全由 `CSUM_TSO`（协议栈）→ `tso_seg_size`（`ff_mbuf_tx_offload`）→ `RTE_MBUF_F_TX_TCP_SEG`（发包填充）单向链驱动，NIC 无 TSO 时全链自动跳过（文档 12 2.2）。

### 3.3 IFCAP_LRO 设置条件统一（软硬协同关键改动点）

**现状**：`ff_veth.c:945-947` 仅由 `hw_features.rx_lro` 驱动 `IFCAP_LRO`：
```c
if (cfg->hw_features.rx_lro) {
    if_setcapabilitiesbit(ifp, IFCAP_LRO, 0);
}
```

**问题**：软件 LRO 启用时（`sw_lro_enabled=1`，`hw_features.rx_lro=0`），该条件不成立，`IFCAP_LRO` 不会声明，协议栈不认为接口支持 LRO 段接收 → 软件 LRO 聚合的大段可能被协议栈异常处理。

**统一方案**：`IFCAP_LRO` 设置条件扩展为"硬件 LRO 生效 **或** 软件 LRO 启用"：
```c
if (cfg->hw_features.rx_lro || <软件 LRO 启用标志>) {
    if_setcapabilitiesbit(ifp, IFCAP_LRO, 0);
}
```

- **软件 LRO 标志的可见性问题**：`ff_veth.c` 的能力设置块入参是 `cfg`（`ff_hw_features`），而 `sw_lro_enabled` 设计放在 `ff_dpdk_if_context`（2.2）。**编码阶段需坐实** `ff_veth.c:942-961` 能否访问 `sw_lro_enabled`：
  - **选项 1**：把软件 LRO 启用标志也纳入 `ff_hw_features`（新增 `uint8_t sw_lro;`），则 `ff_veth.c` 可直接 `cfg->sw_lro` 判断——**代价**：`ff_hw_features` 增字段（`ff_config.h:112-118`）。
  - **选项 2**：`ff_veth.c` 通过其他途径（`ctx`/全局 cfg）读取。
  - **推荐选项 1**：语义清晰（`ff_hw_features` 描述"接口最终生效的 offload 能力"，软件 LRO 也是一种生效能力），且 `ff_veth.c` 消费点统一（与 `rx_lro`/`tx_tso` 并列）。此时 2.2 的 `sw_lro_enabled` 即 `hw_features.sw_lro`。**编码阶段最终定夺字段归属**。

> **决策收敛**：综合 2.2 与 3.3，**推荐把软件 LRO 启用标志放入 `ff_hw_features`（新增 `uint8_t sw_lro;`）**，与 `rx_lro`（硬件）并列且互斥。这样：探测块（`ff_dpdk_if.c`）统一填充、`ff_veth.c` 统一消费、`ff_veth_input` 通过 `ctx->hw_features.sw_lro` 门控软件聚合。既满足互斥语义，又保持消费点单一。

---

## 4. 软件 LRO 与硬件 LRO 互斥/叠加分析

### 4.1 必须互斥（不可叠加）

**结论：硬件 LRO 与软件 LRO 严格互斥，任一时刻只启用其一。**

- **技术原因**：硬件 LRO 启用时，PMD 上送的已是聚合大段（`ol_flags & RTE_MBUF_F_RX_LRO`、`pkt_len` 大）。若在 `ff_veth_input` 再对该大段调 `tcp_lro_rx` 软件聚合：
  - 对已聚合的大段二次聚合，无额外收益（硬件已合并）；
  - 大段可能超过软件 LRO 的 `TCP_LRO_LENGTH_MAX`（`tcp_lro.h:200` = `65535-255`），触发 LRO 引擎对超长段的异常/拒绝路径；
  - 语义混乱（谁负责聚合边界）。
- **保证机制**：由 2.2 的推导逻辑，`hw_features.rx_lro` 与 `hw_features.sw_lro`（软件）在探测块中**互斥赋值**（硬件支持→rx_lro=1,sw_lro=0；不支持且 lro=1→rx_lro=0,sw_lro=1；lro=0→都为 0），从源头保证任一时刻只有一个为 1。

### 4.2 互斥真值表

| `dpdk.lro` | PMD 硬件 LRO 能力 | `hw_features.rx_lro` | `hw_features.sw_lro` | `ff_veth_input` 行为 |
| --- | --- | --- | --- | --- |
| 0 | 任意 | 0 | 0 | 无 LRO，原路径（零回归） |
| 1 | 支持 | 1 | 0 | 硬件 LRO 大段直接上送 |
| 1 | 不支持 | 0 | 1 | 软件 `tcp_lro_rx` 聚合（文档 11） |

- **`IFCAP_LRO`**：`rx_lro || sw_lro` 任一为 1 时声明（3.3）。
- **收包门控**：`ff_veth_input` 中 `if (ctx->hw_features.sw_lro) tcp_lro_rx(...)`；硬件 LRO 时 `sw_lro=0` 不进入软件聚合，大段走原路径上送。

### 4.3 不存在"叠加"合法场景

- 唯一理论上的"叠加"是隧道场景（外层硬件不聚合、内层软件聚合），但 F-Stack 当前不涉及隧道内层 TCP 终结，无此需求。本轮明确**不支持叠加**。

---

## 5. 零回归保证（默认全关时与现状逐字节一致）

### 5.1 LRO 零回归

`dpdk.lro=0`（默认，`config.ini:24`）时：
- `ff_dpdk_if.c` 探测块 `if (dpdk.lro)` 不进入 → `hw_features.rx_lro=0`、`sw_lro=0`、`rxmode.offloads` 不含 LRO 位。
- `ff_veth.c:945` `if (cfg->hw_features.rx_lro || sw_lro)` 不成立 → 不设 `IFCAP_LRO`。
- `ff_veth_input`（`ff_dpdk_if.c:1707`）`if (ctx->hw_features.sw_lro)` 不进入 → 收包路径**无任何 LRO 分支**，与现状（`ff_mbuf_gethdr` → 多段挂链 → `if_input`）逐字节一致。

**结论：`lro=0` 时收包路径与现状完全一致，零回归。**

### 5.2 TSO 零回归

`dpdk.tso=0`（默认，`config.ini:22`）时（文档 12 / `05` 文档 8 节）：
- `ff_dpdk_if.c` TSO 探测块不进入 → `hw_features.tx_tso=0`。
- `ff_veth.c:955` `if (cfg->hw_features.tx_tso)` 不进入 → 不设 `IFCAP_TSO`/`CSUM_TSO`/`if_hw_tsomax*`。
- 协议栈不置 `CSUM_TSO` → `ff_mbuf_tx_offload`（`ff_veth.c:305`）`tso_seg_size=0` → 发包 TSO 分支（`ff_dpdk_if.c:2455` / `ff_memory.c:358` `if (offload.tso_seg_size)`）不进入。
- IPv6 分流/IP_CKSUM 自洽/双份收敛等新增逻辑（`04` 文档 2 节）全部挂在 TSO 分支下，`tso=0` 时不触及。

**结论：`tso=0` 时发包路径与现状一致；新增的 IPv6 分流等逻辑仅在 `tso=1` 且 PMD 支持时生效。**

### 5.3 零回归验证方法（测试里程碑）

- **静态**：默认 config.ini（`tso=0`、`lro=0`）下，所有新增代码分支均不可达（挂在 `if (dpdk.lro)`/`if (tx_tso)`/`if (sw_lro)`/`if (offload.tso_seg_size)` 下）。
- **动态**（`07-测试与验收规格.md`）：默认配置下收发功能与性能基线与改动前对齐（**待运行时验证**）。

---

## 6. 对接改动点汇总表（文件:函数:行）

> "变更点"为设计说明，非实际改动。所有 `file:line` 附代码坐实位置，编码时以最新代码为准（先 read_file 复核）。

### 6.1 硬件 LRO（`04`/`05` 文档已详述，此处汇总）

| 改动点 | 文件:函数:行 | 动作 |
| --- | --- | --- |
| config 项 | `config.ini:24`（`lro=0` 已存在） | 保持默认 0 |
| 结构成员 | `ff_config.h:295` 后（dpdk 结构） | 新增 `int lro;`（若尚未加） |
| 解析 | `ff_config.c` `ini_parse_handler`（tso 分支附近） | 新增 `MATCH("dpdk","lro")` |
| 硬件探测 | `ff_dpdk_if.c` LRO 探测块 | 解 `#if 0`、改宏 `RTE_ETH_RX_OFFLOAD_TCP_LRO`、置 `rx_lro`/`max_lro_pkt_size` |
| ifnet 能力 | `ff_veth.c:945-947`（`IFCAP_LRO` 已存在，由 `rx_lro` 驱动） | 扩展条件为 `rx_lro || sw_lro`（见 3.3） |

### 6.2 软件 LRO（文档 11）

| 改动点 | 文件:函数:行 | 动作 |
| --- | --- | --- |
| 软件回退标志 | `ff_config.h:112-118`（`ff_hw_features`） | 新增 `uint8_t sw_lro;`（3.3 决策） |
| 标志推导 | `ff_dpdk_if.c` LRO 探测块 | `lro=1 && !硬件支持` → `sw_lro=1`（2.2） |
| lro_ctrl 字段 | `ff_dpdk_if_context` 或 per-lcore 上下文 | 新增 `struct lro_ctrl lro`（文档 11 2.2） |
| 初始化 | 端口/lcore 初始化路径 | `tcp_lro_init(&lro)`（经典模式）、绑 `lro.ifp` |
| 收包接入 | `ff_veth_input`（`ff_dpdk_if.c:1720` 之后） | `if (sw_lro) tcp_lro_rx(&lro, hdr, 0)`（文档 11 2.3） |
| 批末 flush | 收包批处理循环末 | `tcp_lro_flush_inactive`（**不用** `tcp_lro_flush_all`，规避 `tcp_lro.c:1261` NULL 裸调） |
| 释放 | 端口/lcore 清理路径 | `tcp_lro_free(&lro)` |
| ifnet 能力 | `ff_veth.c:945`（同 6.1） | 条件含 `sw_lro` |

### 6.3 硬件 TSO 完善（`04` 文档 2 节，本轮 TSO 真正工作）

| 改动点 | 文件:函数:行 | 动作 |
| --- | --- | --- |
| IPv6 分流 | `ff_dpdk_if.c:2467-2491`（`:2452-2466` 为注释）、`ff_memory.c:358-368` | 按 `iph->version` 分流伪头/`l3_len`（`04` 文档 2.1） |
| IP_CKSUM 自洽 | 同上 | IPv4 TSO 分支显式置 `RTE_MBUF_F_TX_IP_CKSUM` |
| tsomax 核对 | `ff_veth.c:958-960`（`IP_MAXPACKET`/`35`/`2048` 已设） | 核对是否匹配目标 PMD（**待运行时验证**） |
| 双份收敛 | `ff_dpdk_if.c:2405-2472`、`ff_memory.c:331-375` | 抽公共函数（`04` 文档 2.4 方案 A） |
| CSUM_IP6_TSO | `ff_veth.c:305` | 扩展 `CSUM_TSO | CSUM_IP6_TSO`（坐实宏关系） |

### 6.4 软件 TSO / rte_gso

| 改动点 | 结论 |
| --- | --- |
| 软件 TSO | **无改动**（协议栈 MSS 分段固有能力，文档 12） |
| rte_gso | **本轮不引入**（可选优化，未来评估） |

---

## 7. 软硬对接数据流总图

```
                        ┌───────────────── config.ini ─────────────────┐
                        │  tso=0 (L22)      lro=0 (L24)   csum_skip=0(L19) │
                        └──────────────────┬────────────────────────────┘
                                           │ ff_config.c 解析
                                           ▼
        ┌──────────── ff_dpdk_if.c 端口 setup（能力探测门控）────────────┐
        │  TSO: if(dpdk.tso) && (tx_offload_capa & TCP_TSO)              │
        │         → hw_features.tx_tso=1                                 │
        │  LRO: if(dpdk.lro):                                            │
        │         rx_offload_capa & TCP_LRO ? hw_features.rx_lro=1       │
        │                                    : hw_features.sw_lro=1(回退)│
        └──────────────────┬────────────────────────────┬──────────────┘
                收(RX/LRO)  │                            │  发(TX/TSO)
                            ▼                            ▼
   ┌── ff_veth_input (ff_dpdk_if.c:1707) ──┐   ┌── tcp_output → ff_mbuf_tx_offload ──┐
   │  硬件LRO: 大段直接搬链上送            │   │  硬件TSO(tx_tso): CSUM_TSO+tso_segsz │
   │  软件LRO(sw_lro): tcp_lro_rx 聚合     │   │    → ff_dpdk_if.c:2455 按version分流  │
   │    (文档11, 经典模式规避1261 NULL)    │   │  软件分段(tso=0/无硬件): 协议栈逐段   │
   └───────────────┬───────────────────────┘   └───────────────┬───────────────────┘
                   ▼                                            ▼
        ff_veth.c:945 IFCAP_LRO (rx_lro||sw_lro)      ff_veth.c:955 IFCAP_TSO+tsomax(tx_tso)
                   ▼                                            ▼
              FreeBSD 协议栈接收大段                    PMD 硬件切段 / 已分段直发
```

---

## 8. 诚实边界（待运行时验证清单）

1. 本机 virtio `dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO` 是否为 0（决定走硬件还是软件 LRO 回退）。
2. `ff_dpdk_if_context` / `ff_hw_features` 结构最终归属 `sw_lro` 字段（3.3 推荐纳入 `ff_hw_features`，编码坐实）。
3. `ff_veth.c:945-961` 能力设置块访问 `sw_lro` 的可行性（编码坐实）。
4. 软硬 LRO 互斥推导逻辑在多进程/多 lcore 下的一致性。
5. `ff_veth.c:958-960` 现有 tsomax 值（`IP_MAXPACKET`/`35`/`2048`）与目标 PMD 匹配性。
6. 默认全关（`tso=0`/`lro=0`）下收发功能与性能与改动前逐字节/逐指标一致（零回归动态验证）。

> 以上均为运行时/后续里程碑验证项，本轮 spec 不实测。测试环境：DPDK 独占网卡 IP `9.134.214.176`（`ssh f-stack-client` 侧发起），内核栈测试走 `127.0.0.1` 的 `lo`。

---

## 9. 本文档结论摘要

1. **对接唯一实质缺口 = 软件 LRO 未接入 `ff_veth_input`（`ff_dpdk_if.c:1707`）**；发端 TSO 无缺口（`CSUM_TSO` 门控天然一致）。
2. **开关语义推荐方案 A（单 `lro` 开关自动选优）**：`lro=0` 关 / `lro=1` 硬件优先+软件回退；软件回退标志内部推导（推荐纳入 `ff_hw_features.sw_lro`），不新增 config.ini 项，与 `tso` 语义对称，零回归。
3. **软硬 LRO 严格互斥**：探测块互斥赋值 `rx_lro`/`sw_lro`，任一时刻只启用其一，杜绝二次聚合（4 节真值表）。
4. **`IFCAP_LRO` 条件需从 `rx_lro` 扩展为 `rx_lro || sw_lro`**（`ff_veth.c:945`），使软件 LRO 也向协议栈声明能力（3.3）。
5. **零回归保证**：`lro=0`/`tso=0` 时所有新增分支不可达，与现状逐字节一致（5 节）。
6. **改动点汇总见 6 节表**；软件 TSO 无改动、rte_gso 本轮不引入。
