# F-Stack LRO/TSO 支持与完善 —— 总体计划（plan.md）

> 项目：F-Stack `lib/` 的 LRO（全新开发完整支持）与 TSO（已支持，分析并完善）。
> 方法：harness 工程 + spec 驱动 + agent team（leader + 子 agent）。本阶段产物 = **spec 调研/设计文档（仅中文）**，落 `docs/lro_tso_spec/zh_cn/`，暂不出英文版。
> 强制规约：实际执行不臆测、代码为准；rm/kill/chmod 走 `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`；lib 注释精简；commit 英文简短 1-3 句；config.ini 本地测试改动不提交；改代码先 make clean 再编译；门禁失败打回上一步（单步 bounce≤3，超则停转人工）；写文档与审核不同 agent（角色分离）；子 agent 全部完成前 leader 严禁退出，主动轮询等待（消息+旁路读盘/git/产物双探测）+超时机制+异常回退补救。
> 测试环境：本机双网卡，DPDK 独占网卡 IP `9.134.214.176`（经 ssh `f-stack-client` 测）；内核栈测 `127.0.0.1`。

---

## 0. 需求与已确认决策

### 0.1 需求
- **LRO（Large Receive Offload）**：之前不支持，此次全新开发完整支持。
- **TSO（TCP Segmentation Offload）**：之前已支持，需分析是否有可完善的地方并一并完善。
- 本轮第一步：仅生成中文 spec 文档，不写代码、不改 lib、不出英文版。

### 0.2 用户澄清（已确认）
- **Q0 LRO 实现路径**：**硬件 LRO（DPDK offload）为主**——解除 `ff_dpdk_if.c:890-897` 的 `#if 0`，按 `dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO` 启用网卡硬件 LRO，接入收包路径投递协议栈。
- **Q1 产出范围**：**LRO 全新完整实现型 spec + TSO 完善型 spec，二者合一套文档，都要落地方案**（配置项/收包接入/协议栈对接/mbuf/多进程/回归 + TSO 完善点与改造方案）。

## 1. 实证现状（本轮 plan mode 预读，file:line 为准，代码为准；须在 M1 由子 agent 用实际代码复核，不一致以代码为准）

### 1.1 LRO 现状（当前不支持，被禁用）
- **配置结构有字段但无配置项解析**：`lib/ff_config.h:112-118` `struct ff_hw_features` 有 `uint8_t rx_lro;`；但 `lib/ff_config.c:1054-1057` 只解析 `dpdk.tso`/`tx_csum_offoad_skip`/`vlan_strip`，**无 lro 配置项**；`config.ini` 无 lro 项。
- **DPDK 层 LRO 配置被 `#if 0` 完全禁用**：`lib/ff_dpdk_if.c:890-897`：
  ```c
  /* FIXME: Enable TCP LRO ?*/
  #if 0
  if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_LRO) {
      ff_log(...,"LRO is supported\n");
      port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TCP_LRO;
      pconf->hw_features.rx_lro = 1;
  }
  #endif
  ```
  用的是**旧宏 `DEV_RX_OFFLOAD_TCP_LRO`**（DPDK 24.11 应为 `RTE_ETH_RX_OFFLOAD_TCP_LRO`，M1 须核对头文件）。
- **收包路径（LRO 接入点）**：`ff_dpdk_if.c:1695 ff_veth_input` → `ff_mbuf_gethdr(pkt,...,rx_csum)`（L1708）→ `ff_veth.c:511 ff_veth_process_packet` → `if_input(ifp, mb)`（L518）。硬件 LRO 由网卡聚合大段后经此路径上送，须评估 mbuf/csum 标记与 ifnet IFCAP_LRO。
- **FreeBSD 侧**：`freebsd/netinet/tcp_lro.c`、`tcp_lro_hpts.c` 源码完整存在；但 `lib/ff_stub_14_extra.c:629-638` 把 `tcp_lro_hpts_init/uninit` stub 成空返回。硬件 LRO 方案下 tcp_lro 软件聚合非必需，但 IFCAP_LRO/接收大段的协议栈处理须核实。

### 1.2 TSO 现状（已支持，需分析完善点）
- **配置**：`config.ini:21-22` `tso=0`（默认禁用）；`ff_config.c:1054-1055` 解析 `dpdk.tso`；`ff_config.h:117` `hw_features.tx_tso`、`:295` `dpdk.tso`。
- **DPDK 层启用**：`ff_dpdk_if.c:931-942`：若 `ff_global_cfg.dpdk.tso` 且 `dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO` → `txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_TSO` + `hw_features.tx_tso=1`；否则日志“not supported/disabled”。
- **offload 信息填充**：`ff_veth.c:304-306` `CSUM_TSO`→`offload->tso_seg_size = tso_segsz`；`ff_memory.c:358-368` + `ff_dpdk_if.c:2448-2465` 填充 `head->l4_len=tcph_len`、`head->tso_segsz`、伪头校验和。
- **M1 待分析完善点**（方向，须代码核实）：`l2_len`/`l3_len` 是否正确填充（当前预读只见 `l4_len`/`tso_segsz`）；IPv4 vs IPv6 TSO；TSO 与 checksum offload/`tx_csum_offoad_skip` 组合；TSO 与 scatter/`MULTI_SEGS` 组合；TSO 与 `mtu_enable`(jumbo) 组合；多进程 primary/secondary；PMD 能力校验完整性；`RTE_ETH_TX_OFFLOAD_UDP_TSO`/`RTE_MBUF_F_TX_TCP_SEG` 标记链路完整性。

## 2. 关键代码位置（本 spec 需覆盖/交叉验证）
- `lib/ff_config.h:112-118`（`ff_hw_features` rx_lro/tx_tso）、`:294-297`（dpdk.tso/tx_csum_offoad_skip/vlan_strip）
- `lib/ff_config.c:1054-1057`（tso/tx_csum_offoad_skip 解析，LRO 需新增 lro）
- `lib/ff_dpdk_if.c:890-897`（LRO `#if 0`）、`:931-942`（TSO 启用）、`:1695-1741`（ff_veth_input 收包）、`:1989-2011`（收包分发）、`:2448-2465`（TSO offload 填充）、init_port_start offload 配置段
- `lib/ff_veth.c:304-306`（CSUM_TSO→tso_seg_size）、`:464-518`（ff_mbuf_gethdr/get/ff_veth_process_packet→if_input）
- `lib/ff_memory.c:351-369`（TSO offload 填充）
- `lib/ff_stub_14_extra.c:629-638`（tcp_lro_hpts stub 空）
- `freebsd/netinet/tcp_lro.c`、`tcp_lro_hpts.c`（FreeBSD LRO 实现，是否接入/IFCAP_LRO）
- `freebsd/netinet/tcp_output.c`（TSO 分段决策）
- `freebsd/net/if.c`（IFCAP_LRO/IFCAP_TSO capability）
- `config.ini:21-22`（tso 配置项，LRO 需新增 lro）
- DPDK 24.11.6 `dpdk/lib/ethdev/rte_ethdev.h`（RTE_ETH_RX_OFFLOAD_TCP_LRO / RTE_ETH_TX_OFFLOAD_TCP_TSO / dev_info、RTE_MBUF_F_TX_TCP_SEG 等宏，M1 须核对实际行号与宏名）

## 3. 里程碑与门禁（本阶段只到 spec 文档；编码/测试为后续阶段）

| 里程碑 | 内容 | 产出文档 | 门禁 |
|--------|------|----------|------|
| **M0** 组队+计划 | 本 plan + 调研结论总览（分工/轮询/超时/回退/门禁） | plan.md、00-调研结论总览 | 现状与代码一致、需求边界清晰 |
| **M1** 代码探测 | 坐实 LRO(#if 0 禁用)/TSO(已启用) 现状 + 收包/发包路径 + FreeBSD LRO/TSO 侧 + config/宏，file:line 为准 | 01-需求规格、02-现状与差距分析 | 文件:行号证据、以代码为准、与预读不一致处标注纠正 |
| **M2** 外网调研 | DPDK RTE_ETH_RX_OFFLOAD_TCP_LRO/TSO 语义、FreeBSD tcp_lro、f-stack github issue/wiki/博客，与代码交叉验证 | 03-外网调研 | 外网结论与代码交叉核对、冲突以代码为准 |
| **M3** 方案与接口设计 | LRO 硬件 offload 完整方案（config/能力探测/rxmode/收包接入/IFCAP_LRO/mbuf/多进程/回归）+ TSO 完善方案（l2/l3_len、IPv6、csum 组合、与 MTU/scatter 组合）+ 接口/配置设计 + 里程碑与编码工作分解 | 04-方案与架构设计、05-接口与配置设计、06-里程碑与工作清单 | 方案可落地、风险标注、接口契约清晰、工作量可执行 |
| **M4** 测试与性能基线 | 单测/集成/真机（LRO 收聚合验证、TSO 分段验证、IPv4/IPv6、9.134.214.176 真机、吞吐/CPU 基线） | 07-测试与验收规格、08-性能基线方案 | 用例可验证、基线方法明确、含诚实边界 |
| **M5** 风险+门禁审核 | 风险与兼容性 + spec 评审门禁（独立 gatekeeper，写审分离，逐项断言） | 09-风险与兼容性、10-spec评审门禁 | 全断言 PASS，否则打回对应 M（bounce≤3） |

> 本阶段**不写代码、不改 lib、不出英文版**；仅产出 `docs/lro_tso_spec/zh_cn/` 下 00-10 中文 spec。后续编码/测试阶段另行启动。

## 4. 子 agent 分工（agent team：kni? 否，本项目 team = lro-tso-spec）

- **leader**（本对话）：统筹、外网调研兜底、门禁独立复核、定时轮询探测（消息+旁路读盘/git/产物双探测）、超时机制、异常回退补救、最终汇总；**子 agent 全部完成前严禁提前退出/严禁 team_delete**。纯调研/纯探测/纯汇总等单一角色可由 leader 兼任。
- **arch-explorer**（M1 代码探测）：坐实 LRO/TSO 五类现状 + 收发包路径 + FreeBSD 侧 + config/宏，产 01/02。
- **design-writer**（M3 方案设计）：LRO 硬件 offload 完整设计 + TSO 完善方案 + 接口 + 里程碑，产 04/05/06。（与 gatekeeper 必须不同 agent）
- **test-spec-writer**（M4 测试规格）：单测/集成/性能基线，产 07/08。
- **gatekeeper**（M5 门禁审核）：独立于所有写文档 agent，逐项断言、不通过指明打回的 M，产 09/10。
- 外网调研（M2/03）由 leader 兼任（单一角色纯调研），后续由 gatekeeper 独立审核，符合写审分离。

## 5. 轮询/超时/回退机制（铁律）
- leader 对每个 spawn 的子 agent 设合理超时（分钟级），定时轮询（send_message 询问 + 主动旁路探测：读子 agent 应落盘的文件、git 状态、产物路径），**旁路探测优先于消息探测**，不以“未回消息”消极判断。
- 子 agent 异常（超时/输出错误/卡死/与裁决冲突）→ 回退补救：①leader 接管该写任务（接管后审核环节必须 spawn 新子 agent，不得自审）；②启新子 agent 重做（角色须与下游审核 agent 不同）；③按 bounce≤3 转人工。任何回退不得违反“写 vs 审核不同 agent”铁律。

## 6. 约束与风险
- 严禁臆测；LRO/TSO 宏名/行号、FreeBSD tcp_lro/tcp_output、DPDK offload capability 均以实际代码/头文件为准；预读用旧宏 `DEV_RX_OFFLOAD_TCP_LRO` 须核对 24.11 是否已改名 `RTE_ETH_RX_OFFLOAD_TCP_LRO`。
- 硬件 LRO 依赖 PMD/网卡能力：本机 virtio 是否支持 `RTE_ETH_RX_OFFLOAD_TCP_LRO` 须运行时 dev_info 确认（spec 阶段标“待运行时验证”，不臆断）。
- LRO 改变收包语义（大段聚合），须评估对 RSS/csum/时间戳/PMTU/转发场景的影响，及与 mtu_enable(jumbo)/scatter 的组合。
- TSO 完善须先坐实当前 l2/l3_len 填充是否缺失（预读只见 l4_len），再定完善面。
- 本阶段仅文档；不触碰运行环境、不提交代码。
