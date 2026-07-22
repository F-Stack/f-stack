# f-stack 软件 LRO 实现与测试 plan.md

> 状态：执行中 | 生成时间：2026-07-22 | 依据 spec：11/12/13

## 一、目标

按 spec 文档（11-软件LRO方案/12-软件TSO与分段方案/13-软硬offload对接方案）实现用户态协议栈软件 LRO：硬件优先、硬件不支持时（本机 virtio）回退软件 LRO。软件 TSO 经 spec 确认为协议栈固有 MSS 分段，无需开发。

## 二、核心设计决策（已门禁通过）

1. **开关方案 A**：单 `lro` 开关自动选优，`sw_lro` 纳入 `ff_hw_features`，与 `rx_lro` 严格互斥（`rx_lro & sw_lro == 0` 恒成立）
2. **1261 规避方案 A**：经典模式（`tcp_lro_init`+`tcp_lro_rx`+`tcp_lro_flush_inactive`+`tcp_lro_free`）天然不含 `tcp_lro.c:1261` 对 NULL `tcp_hpts_softclock` 的裸调用
3. **软件 TSO 无需开发**：协议栈 MSS 分段固有（`tcp_output.c:558` `tso` 需 `TF_TSO`，NIC 无 TSO→`TF_TSO` 不置→逐段发）
4. **零回归**：`lro=0` 时所有新增分支不可达

## 三、里程碑（SM1-SM5）

### SM1：sw_lro 字段与推导
- `ff_config.h:117` 后加 `uint8_t sw_lro;`
- `ff_dpdk_if.c:901-903` else 分支加 `pconf->hw_features.sw_lro=1` + 日志

### SM2：软件 LRO 接入 ff_veth_input
- `ff_memory.h:64` 后加 `struct lro_ctrl lro;`（处理 tcp_lro.h 类型可见性）
- `ff_dpdk_if.c:233-251` ff_dpdk_register_if：sw_lro 时 `tcp_lro_init` + 设 ifp
- `ff_dpdk_if.c:325-329` ff_dpdk_deregister_if：sw_lro 时 `tcp_lro_free`
- `ff_dpdk_if.c:1753` ff_veth_input：插入 `tcp_lro_rx`（ctx 参数去 const）
- `ff_dpdk_if.c:2676` main_loop 每轮末尾：`tcp_lro_flush_inactive`
- process_packets/process_dispatch_ring ctx 参数去 const

### SM3：IFCAP_LRO 条件扩展 + 1261 规避验证
- `ff_veth.c:945` `if(rx_lro)` → `if(rx_lro || sw_lro)`
- 静态确认经典模式路径不含 1261 裸调

### SM4：测试
- 单测：sw_lro 推导/互斥/IFCAP（tests/unit/test_ff_dpdk_if.c）
- 集成测试：本机 virtio lro=1 软件回退 + IPv4/IPv6 HTTP 200 + 无崩溃

### SM5：独立门禁 + 提交
- code-explorer 子 agent 独立审核（写审分离）
- git commit 英文 1-3 句，config.ini 不入库

## 四、关键代码位置（file:line 已坐实）

| 修改点 | 文件:行 | 说明 |
|--------|---------|------|
| sw_lro 字段 | ff_config.h:112-118 | ff_hw_features 新增 uint8_t sw_lro |
| LRO 探测块 | ff_dpdk_if.c:891-906 | else 分支加 sw_lro=1 |
| lro_ctrl 字段 | ff_memory.h:60-68 | ff_dpdk_if_context 新增 struct lro_ctrl lro |
| lro init | ff_dpdk_if.c:233-251 | ff_dpdk_register_if |
| lro free | ff_dpdk_if.c:325-329 | ff_dpdk_deregister_if |
| rx 接入 | ff_dpdk_if.c:1706-1754 | ff_veth_input :1753 前 |
| flush 时机 | ff_dpdk_if.c:2648-2687 | main_loop 每轮末尾 |
| IFCAP_LRO | ff_veth.c:945-947 | 扩展 rx_lro\|\|sw_lro |
| tcp_lro API | tcp_lro.h:215-222 | init/rx/flush_inactive/free |

## 五、agent team 分工（写审分离）

- **leader**（本 agent）：统筹 + SM1-SM4 编码 + 测试执行 + spec 文档更新
- **code-explorer**（子 agent）：SM5 独立门禁审核（与 leader 严格写审分离）

## 六、规约（零容忍）

- rm→rm_tmp_file.sh，kill→kill_process.sh，chmod→chmod_modify.sh
- lib 最小注释，commit 英文 1-3 句，config.ini 本地值不入库
- 改代码先 make clean 再 make
- 写审分离铁律，bounce≤3，leader 不提前退出
