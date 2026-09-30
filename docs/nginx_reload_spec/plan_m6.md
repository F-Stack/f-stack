# M6 实现计划：终门禁、特殊场景回归与文档收尾

> 依据：`docs/nginx_reload_spec/zh_cn/07-milestones.md` v1.11 §2.7（M6）、`08-testing.md` v1.8（PT-NR-05 行 225 / RT-12 行 188 / RT-13 行 189 / A-NR-16 行 257 / A-NR-18 行 259 / RT-15 行 191 / F-M4-7 行 201 / U-NR-10 行 316）、`06-solution-design.md` v1.9.5 §5.5（zc 正交性）。
> 基线：`f6d602076`（M0~M5 已全部提交）。事实源：实际代码 + spec + `work/impl/` 既有产物。零真实 IP。

## 1. 产品概述

完成 **M6：终门禁、特殊场景回归与文档收尾**——关闭全部 RV（RV9 循环 reload ≥100 次、RV8 KNI、zc 正交回归），把 M3~M5 的无损 reload 能力写入产品文档，并按用户决策消解三项高价值移交项与 F2 尸检。

## 2. 用户四项决策（本轮约束）

| 项 | 决策 |
|---|---|
| 范围 | spec 四点（C-NR-601~604）+ RV9 终门禁 + 全量 RT 矩阵复跑 + 三项高价值移交项（F-M5-2 / P2-10·F-M5-4 / F-M4-1） |
| RV9 机时配置 | 无 keepalive + 显式 `worker_shutdown_timeout`（10~20s），每轮 10~20s 自然排空，100 轮 ≈ 30~60 分钟 |
| RT-12 / RT-13 | **实机执行**（`enable_kni=1` 与 zc 配置各跑 RT-02 复跑），出问题按需另立修复项 |
| F2 尸检 | **本轮做**：改 `core_pattern` 抓 core + 构造同槽 respawn 复现，定位根因并给修复或声明性结论 |

## 3. 编码工作清单

| 编号 | 要点 |
|---|---|
| **C-NR-601** | 新增 `tests/integration/test_graceful_reload.sh`（实机 B 组 harness）：真实执行 + 逐用例判定 + 退出码汇总；`TARGET_IP` 必填；进程终止走 `kill_process.sh`、清理走 `rm_tmp_file.sh`（硬性规约）；内嵌循环 reload 驱动（次数/间隔可配），承载 RV9/PT-NR-05 |
| **C-NR-602** | RT-12：`enable_kni=1` 下 RT-02 复跑，同判据 + KNI 管理面（ping/ssh 旁路）reload 后仍可用 |
| **C-NR-603** | RT-13：zc 收包路径下 RT-02 复跑，验证分派回调判定与 mbuf 来源无关（06 §5.5 正交性） |
| **C-NR-604** | 文档入库：`doc/F-Stack_Nginx_APP_Guide.md`（部署形态 + 运维手册）、`doc/F-Stack_Release_Note.md`、`config.ini` 注释 |
| **F-M5-2** | `tools/compat/ff_ipc.c` 显式 `-g`/`-p id:gen` 现强制 epoch 0 → 改为支持 `id:gen[:epoch]` 跨 epoch 寻址；保留「probe 失败显式报错、绝不静默回落 epoch 0」契约 |
| **P2-10/F-M5-4** | `NGX_FF_LISTEN_CLOSE_MAX_MS` 30s 固定值 → 可配（新指令或与 `worker_shutdown_timeout` 取 max），默认不变 |
| **F-M4-1** | `lib/ff_drain_ring.c` drain_ring_tx 满环：加限频告警（复用 `ff_divert_drop_warn` 同款）+ 水位观测面，评估默认 `drain_ring_size` 是否上调 |
| **F2 尸检** | core_pattern 抓 core + 构造「worker 非正常死亡 → 同槽 respawn 撞脏 EAL → SIGABRT 风暴」复现；无法稳定复现则给只读调研 + 复现障碍 + 规避建议，**禁止臆测根因** |

## 4. Agent team 编排与写审分离

- **leader**：统筹/派单/轮询/bounce/裁决/转人工；子 agent 全部完成前严禁提前退出；旁路轮询 10 分钟、硬超时 60 分钟；超时发探测，无响应则 spawn 替补（替补仍守写审分离）
- **子 agent**：`m6-anchor-verifier`（Phase0）→ `m6-coder-harness`（C-NR-601）/ `m6-coder-fixes`（三项移交项）并行 → `m6-reviewer-a`（G-A6 CR）→ `m6-test-runner`（RV9 + RT-12/13 + RT 矩阵）/ `m6-f2-forensics`（F2 尸检）并行 → `m6-doc-writer`（C-NR-604）/ `m6-reviewer-b`（文档复审）→ leader 裁决提交
- bounce 持久化在 `work/impl/state.json`，**每阶段 >3 停止转人工**

## 5. 门禁判据

| 门禁 | 判据 | 失败处理 |
|---|---|---|
| **G-A6** | clean build 零 error / warn 51 零新增 + install + nginx 重链 + 单测 13/13 + 集成 4/4 + harness 可执行（干跑/小样本）且三脚本合规 + 三项移交项 CR 通过 + =0 等价自证 | 打回对应 coder，bounce+1 |
| **G-M6** | ① RV9/PT-NR-05 ≥100 次零错误、无死锁无 crash、无泄漏趋势；② RT-12/RT-13 通过或明确限制结论；③ 全量 RT 矩阵复跑不劣化；④ F2 尸检有结论 | 打回对应阶段，bounce+1；用尽转人工 |

## 6. 测试设计要点

- **RV9/PT-NR-05**：客户端关 keepalive + 显式 `worker_shutdown_timeout`；每 5s 检测共享内存「所有 G_old 已退出」后 reload 一次（成功计一次）；判据错误数 0、无死锁无 crash、rtemap/大页无逐轮累积趋势；**判据构造遵守 F-M4-7（必须活跃连接）**
- **RT-12**：`enable_kni=1` 构建 + KNI 网口配置；reload 后 KNI 管理面 ping/ssh 旁路仍可用
- **RT-13**：zc 配置；验证分派回调判定与 mbuf 来源无关
- **RT 矩阵复跑**：RT-01/02/03/05/06/07/09/10/14 + RT-04/04b + RG-NR-01 不劣化
- **既有陷阱固化进 harness**：`worker_shutdown_timeout` 与活跃流 drain 判据互斥（RT-02/RT-04 类用无该行 conf）；USR2 双二进制须与被测 lib 同批重建；nginx configure 须 `env -i`；DPDK primary 退出不 unlink rtemap（FINDING-3，256×2MB/次，Makefile test 目标已自动清理）

## 7. 工程规约（全团队强制）

- Shell 三件套：删除 `rm_tmp_file.sh`、停进程 `kill_process.sh`、加权限 `chmod_modify.sh`（harness 内亦须如此）
- 改码前 `make clean`；lib 三步法（`PATH` 规避 IDE hook → `make machine_includes` → `make -o machine_includes -j16` → `make libfstack.a`）+ `make install`；nginx `make clean` 后重跑 configure（五参数）+ `make -j16`
- `lib/` 注释最小化、英文（仅 `ff_api.h` 新接口、新指令、复杂逻辑可加）
- commit message 英文 1-3 句；**config.ini 本地测试值不入库**
- 文档零真实 IP（占位符 `<DPDK_NIC_IP>` / `<CLIENT_IP>` / `<GATEWAY_IP>`）
- 网卡独占三查（ps / hugepages rtemap=0 / `/var/run/dpdk/rte` 无近期 mtime）；`--proc-type` 显式禁 auto；各 agent 私有目录
- 提交按层切分：harness + 移交项修复 / 文档 / spec 回写

## 8. 风险与回退

- **风险**：① RV9 长循环暴露低概率状态错位（VPP #3547/#3645 前车之鉴）——暴露即回修；② KNI/zc 配置可行性（构建/网口/正交性）——不可行则出明确限制声明；③ F2 复现可能不稳定或触及 DPDK 清理逻辑——控制改动面，环境配置须可还原；④ 三项移交项改动虽小但跨层（tools/nginx/lib），须各自 =0 等价自证
- **回退**：harness 与文档为纯新增，可整体 revert；移交项修复分文件 revert 后 M5 行为保留
