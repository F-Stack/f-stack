# F-Stack LRO/TSO spec 评审门禁（中文）

> 文档层级：spec 评审门禁（M5 阶段产出，独立审核 agent 出具）
> 审核对象：`00`~`08` 共 9 份中文 spec 文档 + `plan.md`。
> 审核方法：**独立审核 agent（与写文档 agent 不同，严格写审分离）逐条 `read_file` 实际代码复核，代码为准、不臆测**。凡文档引用的 `file:line`/宏名/结构，审核阶段均以工作区实际文件重新核对。
> 权威版本：DPDK `dpdk-stable-24.11.6`、FreeBSD 15.0 移植（`f-stack/freebsd/`）。
> 铁律：本轮为**纯文档阶段**（未写代码、未改 lib、未提交）。本门禁只审文档 + 出结论，不改 `00`~`08` 内容。

---

## 一、审核维度与判据

| 维度 | 判据 |
| --- | --- |
| M1 代码 file:line 一致性 | 抽查关键引用，审核 agent `read_file` 实际代码复核，一致即 PASS |
| M2 LRO 六层闭环 | config→解析→结构→DPDK 使能→rxmode→收包→IFCAP 无缺口 |
| M3 TSO 完善闭环 | IPv6 分流/IP_CKSUM 自洽/tsomax/双份收敛/CSUM_IP6_TSO/组合约束 均有方案+测试 |
| M4 需求覆盖 | Q0（硬件 LRO 路径）/Q1（LRO 全新+TSO 完善）落实 |
| M5 诚实边界 | 待运行时验证项如实标注，无臆测冒充 |
| M6 文档间一致性 | 01-08 交叉引用/结论/file:line 自洽无矛盾 |
| M7 硬性约束 | 纯文档未改代码；config.ini 本地值不入库表述；lib 最小注释；宏名正确 |

---

## 二、代码 file:line 一致性核对（审核 agent 实测）

> 下表每行的"实测"列均为本次审核 `read_file`/`search_content` 工作区实际文件的结果。

| 引用点 | 文档声称 | 审核实测 | 结论 |
| --- | --- | --- | --- |
| LRO capa 宏 `RTE_ETH_RX_OFFLOAD_TCP_LRO` | `rte_ethdev.h:1556` = `RTE_BIT64(4)` | `dpdk-stable-24.11.6/lib/ethdev/rte_ethdev.h:1556 #define RTE_ETH_RX_OFFLOAD_TCP_LRO RTE_BIT64(4)` | **PASS** |
| 旧宏 `DEV_RX_OFFLOAD_TCP_LRO` 不存在 | 24.11.6 命中 0 | `rte_ethdev.h` 搜索命中 **0** | **PASS** |
| `max_lro_pkt_size`（rxmode / dev_info） | `rte_ethdev.h:432` / `:1792` | `:432`（rxmode）/`:1792`（dev_info），注释 "Maximum allowed/configurable size of LRO aggregated packet" | **PASS** |
| LRO `#if 0` 块 | `ff_dpdk_if.c:891-898`，用旧宏 | `:891` FIXME 注释、`:892 #if 0`、`:893/895 DEV_RX_OFFLOAD_TCP_LRO`、`:896 rx_lro=1`、`:898 #endif` | **PASS** |
| TSO 探测三态 | `ff_dpdk_if.c:931-942` | `:931 if (dpdk.tso)`、`:932 RTE_ETH_TX_OFFLOAD_TCP_TSO`、`:933/938/941` 三态日志 | **PASS** |
| TSO offload 填充/伪头 | `ff_dpdk_if.c:2455-2465`，`rte_ipv4_phdr_cksum` | `:2455 if(offload.tso_seg_size)`、`:2460 rte_ipv4_phdr_cksum(iph, RTE_MBUF_F_TX_TCP_SEG)`、`:2462 TCP_SEG`、`:2463 l4_len`、`:2464 tso_segsz` | **PASS** |
| ip_csum 分支置 TX_IP_CKSUM | `ff_dpdk_if.c:2417`（TSO 依赖此命中） | `:2417 head->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4` | **PASS** |
| `ff_config.h` rx_lro 字段 | `:114`（rx_csum:113 与 tx_csum_ip:115 间） | `:113 rx_csum`、`:114 uint8_t rx_lro`、`:115 tx_csum_ip`、`:117 tx_tso` | **PASS** |
| `ff_config.h` dpdk 结构 tso，无 lro | `:295 int tso;` | `:295 int tso;`、`:296 int tx_csum_offoad_skip;`，无 `int lro` | **PASS** |
| `ff_config.c` tso 解析、无 lro | `:1054-1057` | `:1054-1055 MATCH("dpdk","tso")`、`:1056-1057 tx_csum_offoad_skip`；`lro` 命中 **0** | **PASS** |
| `ff_veth.c` CSUM_TSO 映射 | `:304-306` 仅识别 `CSUM_TSO` | `:304 if(csum_flags & CSUM_TSO)`、`:305 tso_seg_size=tso_segsz`；`:292 CSUM_TCP|CSUM_TCP_IPV6` | **PASS** |
| `ff_veth.c` 能力块/无 IFCAP_LRO | `:941-956`，TSO `:951-953` | `:941 rx_csum→IFCAP_RXCSUM`、`:951-953 tx_tso→IFCAP_TSO+CSUM_TSO`、`:956 setcapenable`；`IFCAP_LRO` 全 lib 命中 **0** | **PASS** |
| `ff_mbuf_gethdr` | `:464-485`，csum 标记 `:479-483` | `:464 ff_mbuf_gethdr`、`:474 m_pkthdr.len=total`、`:479-482 CSUM_*_VALID/PSEUDO_HDR+csum_data=0xffff` | **PASS** |
| `ff_memory.c` TSO 填充 | `:358-368`，`:363 rte_ipv4_phdr_cksum` | `:358 if(offload.tso_seg_size)`、`:363 rte_ipv4_phdr_cksum`、`:365 TCP_SEG`、`:366 l4_len`、`:367 tso_segsz` | **PASS** |
| `ff_stub_14_extra.c` LRO/HPTS stub | `:629-639` 空 stub | `:627 tcp_hpts_softclock=NULL`、`:630-633 tcp_lro_hpts_init 返回0`、`:636-639 tcp_lro_hpts_uninit 空体` | **PASS** |
| `ff_veth_input` 收包路径 | `:1694-1742` | `:1694 ff_veth_input`、`:1698-1703 rx_csum BAD 丢包`、`:1708 ff_mbuf_gethdr(pkt,pkt->pkt_len,...)`、`:1725-1739 多段遍历`、`:1741 ff_veth_process_packet` | **PASS** |
| `tcp_output.c` tsomax | `:905-931`，`:927 if(if_hw_tsomax!=0)` | `:905 if(tso)`、`:911-913 t_tsomax/segcount/segsize`、`:927 if(if_hw_tsomax!=0)`、`:929 max_len` | **PASS** |
| `config.ini` tso=0，无 lro | `:22 tso=0` | `:21 注释`、`:22 tso=0`；`lro` 命中 **0** | **PASS** |
| Makefile 编译列表 | `:513 tcp_lro.c`、`:572 tcp_hpts.c`，tcp_lro_hpts.c 未编译 | `:513 tcp_lro.c`、`:572 tcp_hpts.c`；`tcp_lro_hpts.c` 命中 **0** | **PASS** |
| `rx_lro` 死字段 | 有字段无消费点 | 全 lib 仅 2 处：`ff_config.h:114`（定义）+`ff_dpdk_if.c:896`（`#if 0` 内死赋值），无生效消费 | **PASS** |
| `if_hw_tsomax` 未设 | 全 lib 命中 0 | 全 lib 命中 **0** | **PASS** |

**维度 M1 结论：PASS**（19/19 抽查点与实际代码完全一致；文档 `00` 中 `890-897`/`2448-2465` 为 M0 plan-mode 预读值，已在 `01`/`02` 用精确值 `891-898`/`2455-2465` 纠正并显式标注，属正常收敛，非矛盾。）

**审核额外坐实（超出文档、补强诚实边界）**：`freebsd/sys/mbuf.h:735 #define CSUM_TSO (CSUM_IP_TSO|CSUM_IP6_TSO)`、`:670 CSUM_IP6_TSO=0x1000`。证明 `CSUM_TSO` 已含 `CSUM_IP6_TSO` 位 → `ff_veth.c:304` 现状已能识别 IPv6 TSO 段。此点 `04`/`05` 文档均**诚实地标为"待坐实、若等价则可省"**（未臆断为"必需"），审核认定为诚实边界处理得当；本审核已在 `09` 文档 R-TSO-05 前置消解并回填。

---

## 三、逐维度断言 checklist

### M2：LRO 六层闭环

| # | 断言 | 结论 | 证据 |
| --- | --- | --- | --- |
| G-LRO-1 | 配置层有 `dpdk.lro` 新增设计（默认 0） | PASS | `04` 1.1、`05` 1.1；对齐 `config.ini:22 tso=0` |
| G-LRO-2 | 解析层有 `MATCH("dpdk","lro")` 设计 | PASS | `05` 3.1，紧邻 `ff_config.c:1054` tso 解析 |
| G-LRO-3 | 结构层激活 `rx_lro`（`ff_config.h:114`）+ 新增 `int lro` | PASS | `05` 2.1/2.2；实测 `:114` 存在、`:295` 无 lro |
| G-LRO-4 | DPDK 使能层解除 `#if 0` + 更正宏 + 按 capa 探测 | PASS | `04` 1.2、`05` 4.1；宏 `:1556` 已核 |
| G-LRO-5 | rxmode 层设 `max_lro_pkt_size`（`>=mtu`，优先 dev_info） | PASS | `04` 1.3、`05` 4.2；`rte_ethdev.h:432/1792` 已核 |
| G-LRO-6 | 收包层处理 LRO 大段（长度搬运已支持 + LRO 标记可选） | PASS | `04` 1.4；`ff_dpdk_if.c:1708/1725-1739` 已核 |
| G-LRO-7 | 协议栈/ifnet 层设 `IFCAP_LRO` | PASS | `04` 1.5、`05` 5.1；`ff_veth.c:941-956` 已核无 LRO |
| G-LRO-8 | 默认关闭零回归（六层均挂开关下） | PASS | `05` 八、`09` C-01 |

**M2 结论：PASS（六层闭环无缺口）。**

### M3：TSO 完善闭环

| # | 断言 | 结论 | 证据 |
| --- | --- | --- | --- |
| G-TSO-1 | IPv6 TSO 按 version 分流（`rte_ipv6_phdr_cksum`+l3_len=40） | PASS | `04` 2.1、`05` 4.3；下游 `:2455-2465`/`:358-368` 现状仅 IPv4 已核实 |
| G-TSO-2 | IPv4 TSO 显式置 `RTE_MBUF_F_TX_IP_CKSUM` 自洽 | PASS | `04` 2.2、`05` 4.3；现状 `:2417` 依赖前置分支已核实 |
| G-TSO-3 | `if_hw_tsomax` 系列设非 0 上限 | PASS | `04` 2.3、`05` 5.2；`tcp_output.c:927`/lib 命中 0 已核 |
| G-TSO-4 | 双份逻辑收敛（方案 A/B） | PASS | `04` 2.4、`05` 4.4；`:2405-2472` vs `:331-375` 重复已核 |
| G-TSO-5 | `CSUM_IP6_TSO` 兼容（坐实后决定改/省） | PASS | `04` 2.6、`05` 5.3 诚实标"待坐实"；审核已坐实=可省（mbuf.h:735） |
| G-TSO-6 | 与 `tx_csum_offoad_skip` 组合约束（WARN） | PASS | `04` 2.5、`05` 7；`ff_dpdk_if.c:914-942` 已核 |
| G-TSO-7 | 每个完善点有对应测试用例 | PASS | `07` TC-TSO-FILL/MAP/CONV、IT-TSO-20..24 |

**M3 结论：PASS（TSO 完善点全部有方案 + 测试；核心 IPv6 断链定位准确，坐实真实断链在下游伪头计算而非 `ff_veth.c:304`）。**

### M4：需求覆盖（Q0/Q1）

| # | 断言 | 结论 | 证据 |
| --- | --- | --- | --- |
| G-REQ-1 | Q0 硬件 LRO / DPDK offload 路径（非软件 LRO 首选） | PASS | `01` 3.2、`04` 0.1；软件 LRO（tcp_lro.c 已编译无调用）明确后评估 |
| G-REQ-2 | Q1-LRO 全新开发完整支持落地 | PASS | `04` 一（六层）、`06` CM1-CM3 |
| G-REQ-3 | Q1-TSO 完善点全部落地 | PASS | `04` 二、`06` CM4-CM5 |
| G-REQ-4 | 测试/性能基线覆盖 LRO+TSO+IPv4/IPv6 | PASS | `07` 四矩阵、`08` 三矩阵 |

**M4 结论：PASS。**

### M5：诚实边界

| # | 断言 | 结论 | 证据 |
| --- | --- | --- | --- |
| G-HB-1 | virtio LRO/TSO 能力标"待运行时验证" | PASS | `03` 2.3、`04` 四.1、`07` HB-1、`08` 六 |
| G-HB-2 | IPv6 扩展头场景标"待增强" | PASS | `04` 2.1、`07` HB-4、`09` R-TSO-02 |
| G-HB-3 | tsomax 精确值 / max_lro_pkt_size 匹配标运行时校准 | PASS | `04` 四.2/.5、`07` HB-2/HB-5 |
| G-HB-4 | CSUM_IP6_TSO 宏位关系标"编码阶段坐实"（未臆断） | PASS | `04` 2.6、`05` 5.3；审核已坐实并回填 `09` R-TSO-05 |
| G-HB-5 | 多进程 per-queue 聚合标运行时验证 | PASS | `04` 1.7、`07` HB-7 |
| G-HB-6 | 测试分层：代码路径通过 ≠ 端到端通过 | PASS | `07` 一.3、第五节模板、`08` 六 |

**M5 结论：PASS（诚实边界完备；尤其宏位关系未臆断为"必需"，而是标坐实，审核实测证明该谨慎处理正确）。**

### M6：文档间一致性

| # | 断言 | 结论 | 证据 |
| --- | --- | --- | --- |
| G-DOC-1 | LRO 宏名全文档统一为 `RTE_ETH_RX_OFFLOAD_TCP_LRO` | PASS | `00`~`08` 一致；旧宏仅在"纠正记录"上下文出现 |
| G-DOC-2 | 关键 file:line 跨文档一致（891-898/2455-2465/114/295 等） | PASS | `01`/`02`/`04`/`05`/`07`/`08` 一致；`00` 预读值已在 `01`/`02` 纠正 |
| G-DOC-3 | 六层/完善点/CM/测试/HB 编号跨文档可追溯 | PASS | `04`↔`05`↔`06`(CM)↔`07`(TC/IT/HB)↔`08`(PB) 链完整 |
| G-DOC-4 | 零回归结论全文档一致（lro=0/tso=0 逐字节一致） | PASS | `01` 4.2、`04` 0.2、`05` 八、`07` 一.2、`08` 一.1 |
| G-DOC-5 | 索引（`00` 文档索引）与实际文件齐全 | PASS | `00`~`08` + `plan.md` 均存在；`09`/`10` 本轮补齐 |

**M6 结论：PASS（无实质矛盾；`00` 与 `01`/`02` 的行号差异是"M0 预读→M1 纠正"的显式收敛，文档已明确标注纠正记录，不构成矛盾）。**

### M7：硬性约束

| # | 断言 | 结论 | 证据 |
| --- | --- | --- | --- |
| G-CON-1 | 本轮纯文档，未改任何 lib 代码 | PASS | 仅生成 `docs/lro_tso_spec/zh_cn/*.md`；lib 实测与文档描述现状一致（未被改动） |
| G-CON-2 | config.ini 本地测试值不入库表述完备 | PASS | `05` 1.1、`06` 四、`09` E-01；只允许 `lro=0` 特性改动 |
| G-CON-3 | lib 最小注释原则贯彻 | PASS | `04` 0.2.4、`05` 九；禁自解释代码加注释 |
| G-CON-4 | 宏名正确（LRO 用 RTE_ETH_*，禁旧宏） | PASS | `06` 四表、`02` 三；审核实测 `:1556` |
| G-CON-5 | rm/kill/chmod 走脚本、clean build、commit 英文等规约在编码里程碑显式登记 | PASS | `06` 四规约表、`07` 一.6 |

**M7 结论：PASS。**

---

## 四、bounce 规约说明

- 本门禁属**文档阶段门禁**：审核 agent 只出审核结论，**不改写** `00`~`08`（写审分离）。若发现不通过项，由 leader 打回对应写文档 agent 修复。
- 任一维度 FAIL → 打回上一步修复；同一问题打回**不超过 3 次**；超 3 次转人工决策，禁止搁置为"已知问题"或带病放行。
- 编码阶段（CM1-CM7）门禁 bounce 规约见 `06` 文档三、`07` 文档一.5：门禁失败打回对应 CM，bounce≤3，超限转人工。
- 本轮 bounce 计数：**0**（首轮审核全维度 PASS，无打回）。

---

## 五、发现的问题清单

> 审核实测未发现导致返工的实质缺陷。以下为**建议性/增强性**观察项（不阻塞交付，供编码里程碑参考）：

1. **[建议·已在 09 前置消解] `CSUM_IP6_TSO` 扩展冗余**：`04` 2.6 / `05` 5.3 建议扩展 `ff_veth.c:304` 为 `& (CSUM_TSO | CSUM_IP6_TSO)`。审核实测 `freebsd/sys/mbuf.h:735 CSUM_TSO=(CSUM_IP_TSO|CSUM_IP6_TSO)` 已含该位，此扩展冗余（结果等价）、可省。文档将其标为"待坐实"是**正确的谨慎处理**；`09` 文档 R-TSO-05 已回填坐实结论。**非缺陷**。
2. **[提示·非缺陷] `00` 与 `01`/`02` 行号差异**：`00` 文档为 M0 plan-mode 预读（`890-897`/`2448-2465`），`01`/`02` 已用精确值（`891-898`/`2455-2465`）纠正并在"关键纠正记录"显式标注。属正常收敛，`00` 文档头部已注明"M0 预读、M1 复核"。建议（可选）在 `00` 顶部再加一句"行号以 01/02 为准"，进一步降低误读。**不阻塞**。
3. **[提示·非缺陷] `ff_memory.c` 与 `ff_dpdk_if.c` 差异度**：`02` 2.3 称两处"结构几乎逐行相同"。审核实测 `ff_memory.c:331-375` **缺少** `ff_dpdk_if.c:2410-2420` 的 `if (offload.ip_csum)` 前置块与 `:2428-2432` 的 version 标记分支，即 `ff_memory.c` 填充更简（只有 tcp_csum/tso/udp_csum 三分支）。文档"几乎相同"表述略宽，但 TSO 分支（本项目焦点）确实逐行一致，收敛方案（`04` 2.4）仍成立。建议编码阶段收敛时注意两处 IPv4/IPv6 标记设置的差异。**不阻塞**。

---

## 六、总体审核结论

**审核结论：CONDITIONAL PASS（可交付，含 3 项建议性/提示性观察，均不阻塞）。**

裁决依据：

- **代码 file:line 一致性（M1）**：19/19 抽查点经审核 agent 实际 `read_file`/`search_content` 复核，与工作区实际代码**完全一致**（含 DPDK 宏 `:1556`、旧宏命中 0、`#if 0` 块 `:891-898`、TSO `:2455-2465`、`rx_lro:114`、`tso:295`、`IFCAP_LRO`/`if_hw_tsomax` 命中 0 等）。
- **LRO 六层闭环（M2）/ TSO 完善闭环（M3）/ 需求覆盖（M4）/ 诚实边界（M5）/ 文档一致性（M6）/ 硬性约束（M7）**：全部 PASS。
- **诚实边界处理尤为可靠**：文档对 virtio 能力、IPv6 扩展头、tsomax 精确值、`CSUM_IP6_TSO` 宏位关系均未臆断，而是标"待运行时/编码阶段坐实"。审核对宏位关系的实测（`CSUM_TSO` 已含 `CSUM_IP6_TSO`）证明该谨慎处理**正确**——若文档臆断"扩展必需"反而会引入冗余代码。这体现"代码为准、不臆测"规约的落实。
- **无返工级缺陷**：3 项观察均为建议/提示（宏扩展冗余可省、`00` 预读行号已纠正、`ff_memory.c` 差异度表述略宽），不影响方案可落地性与文档正确性，故判 CONDITIONAL PASS 而非 FAIL。

**升级为完全 PASS 的（可选）条件**：编码阶段以本门禁 §五 三项观察为准（宏扩展可省、注意 `ff_memory.c` 差异），并（可选）在 `00` 顶部补一句行号以 `01`/`02` 为准。以上均为增强项，非交付前置条件。

**遗留待运行时验证项（非文档缺陷，编码阶段闭环）**：virtio LRO/TSO 能力（HB-1）、`max_lro_pkt_size` 匹配（HB-2）、LRO 大段协议栈接收（HB-3）、IPv6 扩展头 l3_len（HB-4）、tsomax 精确值（HB-5）、多进程 per-queue 聚合（HB-7）。均已在文档如实标注，须在 CM0/CM3/CM6 运行时坐实。

---

## 七、审核追溯锚点

| 审核项 | 实测文件:行 |
| --- | --- |
| LRO capa 宏 | `dpdk-stable-24.11.6/lib/ethdev/rte_ethdev.h:1556` |
| max_lro_pkt_size | `rte_ethdev.h:432`（rxmode）/`:1792`（dev_info） |
| LRO #if 0 块 | `f-stack/lib/ff_dpdk_if.c:891-898` |
| TSO 探测 | `ff_dpdk_if.c:931-942` |
| TSO offload 填充 | `ff_dpdk_if.c:2405-2472`（TSO 分支 `:2455-2465`） |
| ff_memory TSO 填充 | `ff_memory.c:331-375`（TSO 分支 `:358-368`） |
| rx_lro 字段/dpdk 结构 | `ff_config.h:114` / `:295` |
| config 解析 | `ff_config.c:1054-1057` |
| ff_mbuf_tx_offload / CSUM_TSO | `ff_veth.c:282-307`（`:304-306`） |
| 能力块 / IFCAP_LRO 缺失 | `ff_veth.c:941-956` |
| ff_mbuf_gethdr | `ff_veth.c:464-485` |
| ff_veth_input | `ff_dpdk_if.c:1694-1742` |
| LRO/HPTS stub | `ff_stub_14_extra.c:627-639` |
| tcp_output tsomax | `freebsd/netinet/tcp_output.c:905-931` |
| CSUM_TSO 宏位关系 | `freebsd/sys/mbuf.h:670`（CSUM_IP6_TSO）/`:735`（CSUM_TSO 复合） |
| config.ini | `f-stack/config.ini:22` |
| 编译列表 | `f-stack/lib/Makefile:513`（tcp_lro.c）/`:572`（tcp_hpts.c） |
