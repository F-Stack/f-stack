# 完整支持 MTU 修改——spec 评审门禁

> 本文是门禁检查项清单（checklist），供 reviewer 逐项核对，**不是**审核结论。每项须给出通过/不通过与证据（文件:行/引用）。任一项不通过按 bounce 规约打回上一步修复。

## 1. 与 06 结论一致性

- [ ] 07~13 的方案与 `06-方案与结论.md` 的四个改造点（config、ff_veth 初始化设 mtu、ff_veth_ioctl 拦截 SIOCSIFMTU、DPDK mbuf/rxmode/scatter）一致。
- [ ] “减小 MTU 开箱可用、增大需改造”的结论未被 spec 篡改。
- [ ] 未擅自修改 00~06 调研文档。

## 2. 代码 file:line 一致性

逐条核对 spec 引用与实际仓库一致（`/data/workspace/f-stack` 与 DPDK 24.11.6 源码）：

- [ ] `ff_veth_ioctl()` 位于 `lib/ff_veth.c:235`，主体 `switch(cmd)` 默认分支 `ether_ioctl()`（当前无 SIOCSIFMTU case）。
- [ ] `ff_veth_setup_interface()` 位于 `lib/ff_veth.c:910`。
- [ ] `struct ff_port_cfg`/`struct ff_config.dpdk` 行号（`ff_config.h`）与 08/09 引用一致。
- [ ] `ff_config.c` 的 `ff_default_config()`、`ini_parse_handler()`、`port_cfg_handler()` 行号一致。
- [ ] `ff_dpdk_if.c` 的 pool 创建、`init_port_start`、`rte_eth_dev_info_get`、configure/queue setup/start 行号一致。
- [ ] DPDK ethdev 字段/接口行号（`rte_eth_rxmode.mtu`、`dev_info.*`、`rte_eth_dev_set/get_mtu`）一致。
- [ ] `rte_eal_process_type() == RTE_PROC_PRIMARY` 判定在代码库中确为既有用法（如 `ff_dpdk_if.c`/`ff_dpdk_kni.c`）。
- [ ] 所有 DPDK API 名称与返回值语义与实际头文件一致，无臆造符号。

## 3. Q1~Q4 决策落地

- [ ] Q1 mbuf 方案：large 与 scatter 双模式，配置选择，不隐式降级（07 R-MTU-004/005、09 M2）。
- [ ] Q2 max_mtu 上限：可配置、启用缺省 9000、large 派生 data_room≤UINT16_MAX 确定性失败（07 R-MTU-002、08 §1.1、09 §3.2）。
- [ ] Q3 本次仅生成 spec，编码/测试另立任务（07 §7、10）。
- [ ] Q4 端到端验证：尽力实测，链路不支持 jumbo 据实登记不伪造（11 §7 诚实边界）。

## 4. 范围收敛决策落地（无 IPC 事务残留）

核心门禁项，逐条确认：

- [ ] 07 R-MTU-006/007 已改为按进程角色（primary 软+硬、secondary 仅软）+ 每进程各设一次，无跨进程事务。
- [ ] 07 AC-06 已改为“每 proc 各设后视图一致，本期不提供跨进程自动同步”。
- [ ] 07 §7 范围：In=多进程各自设置（无 IPC 事务）；Out=运行时动态 MTU 跨进程 IPC 事务协调降级为后续里程碑。
- [ ] 08 原 4.2 IPC transport（ff_mtu_msg、ff_mtu_phase、request/command/ack rings、消息池、事务流程）已整节删除，替换为“多进程 MTU 设置模型（无 IPC）”。
- [ ] 08 §4.1 明确 `ff_dpdk_if_set_mtu()` 仅 primary 调用。
- [ ] 08 §5.1、§6、§7 返回码已去除协调器/多进程协调超时（ETIMEDOUT）表述。
- [ ] 09 §1 原则第 4 条去除“多进程同步”，改为本进程内。
- [ ] 09 §5.3 quiesce 明确仅限本 primary 进程多 lcore。
- [ ] 09 §6 ioctl 伪代码按 `RTE_PROC_PRIMARY` 区分 primary/secondary 分支。
- [ ] 09 §7 已整节重写为“多进程 MTU 一致性（无 IPC 协调）”：静态模型、使用约定与已知约束、为何不做 IPC、bond primary 内处理。
- [ ] 09 §9 单测删除跨进程事务/rings/transaction 项，保留 config、primary 状态机、veth ioctl（区分角色）、multi-seg。
- [ ] 09 §10 保留“不允许 secondary 直接 stop/start 共享端口”。
- [ ] 10 M4 重写为“多进程 MTU 一致性（无 IPC）”，DoD=每 proc 各设后视图一致、无跨进程事务代码。
- [ ] 11 删除多进程 IPC 事务/两阶段/rings/transaction 用例，改为每进程各设一致、secondary 仅软、漏设保持旧值。
- [ ] 12 删除 IPC 事务/协调器风险条目，新增“漏设致 proc 视图不一致”使用约束风险；保留 PMD/链路、内存估算、scatter 开销、TSO 联动、默认兼容、回滚。
- [ ] 全局 grep：07~13 内不再残留 request/prepare/commit/ack 事务、ff_mtu_msg、transaction_id、rings 广播、协调器等 IPC 概念（00~06 不检查）。

## 5. 硬性约束

- [ ] 纯文档，未改任何 `lib/`、`freebsd/` 代码。
- [ ] 保留“不修改 `freebsd/net/if_ethersubr.c`”“ff_veth.c 不引用 rte_eth*”等既有约束。
- [ ] config.ini 相关表述仅含功能默认/注释项，不含本机测试值（`lcore_mask/idle_sleep/addr` 等）。
- [ ] 文档措辞精炼，无冗余。

## 6. bounce 规约

- [ ] 任一门禁项不通过 → 打回上一步（写文档 agent）修复，不得当作遗留项搁置。
- [ ] 同一步骤 bounce 最多 3 次，仍不通过转人工决策。
- [ ] 写文档与 review 为不同 agent（角色分离）。
