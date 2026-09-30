# M5 实现计划：USR2 二进制升级（含跨 master 世代撞号硬前置）

> 依据：`docs/nginx_reload_spec/zh_cn/07-milestones.md` v1.10 §2.6（M5）、`08-testing.md` v1.7（RT-04/RT-04b、RG-NR-01）、`06-solution-design.md` v1.9.4（5.2 USR2 段、DR1 候选 b）。
> 基线：`244d2508d`（M4 全套已提交）。事实源：实际代码 + spec + `work/impl/` 既有产物。零真实 IP。

## 1. 产品概述

在 M0~M4 已提交基础上实现 **M5：USR2 二进制升级**（C-NR-501~504）——master 无 ff 状态可安全 exec，新 master 对接常驻 primary、fork 全 secondary worker，复用 M2~M4 全套 T1-T5 机制完成接管与 drain，老 master 保留回退能力。

同时解决 **M2 CR 移交的硬前置**：跨 master 世代 gen/ring 撞号。

## 2. 硬前置：跨 master 世代撞号（用户已决策）

**问题（已代码坐实）**：`lib/ff_reload.c:114-125` 的 ring 名格式为 `(base, proc_id[, msg_type][, gen])`，`lib/ff_dpdk_if.c:931-947` 的 msg_ring 同样以 proc_id 命名 —— **无 master 世代维度**。控制块是 master 的匿名 MAP_SHARED（`ff_reload.h:39`），新 master exec 后重建、gen 从 0 起步；而 DPDK ring/mempool 名字空间跨 master 共享 ⇒ 老 worker（偶数次 reload 后 gen=0）与新 worker 撞号 ⇒ 共享 gen0 ring 双消费者 + KNI 双主。

**决策**：
- **载体**：常驻 slim primary 内 **hugepage memzone 世代目录**（primary 是唯一不随 exec 换代的实体，天然跨 master 权威；与 `ff_dpdk_if.c:95/106` 的 "primary creates / secondary looks up" 先例同源；无需 POSIX shm；RT-04b 的「老 master 夺回 rx owner」也需要两 master 都可写的权威位）
- **proc_id**：**复用同 proc_id + 世代维度区分命名**，不改 config 约束（不扩容 nb_procs）⇒ 必须逐一审计所有以 proc_id 命名的跨进程资源，遗漏即撞号

## 3. 编码工作清单

| 编号 | 要点 |
|---|---|
| **硬前置·世代目录** | 新增 `lib/ff_reload_gendir.c`：memzone 目录（primary 创建、secondary 查找），登记 `next_epoch` mint、`rx_owner(epoch,gen)`、`kni_owner(epoch,gen)`、代际表（epoch/gen/master_pid/state）；全部 SEQ_CST；无 primary（=0 或非 graceful）时目录不存在、全部走既有路径 |
| **硬前置·命名上下文** | 所有 proc_id 命名的跨进程资源掺入所属 master epoch：旧代际 ring 保持其原 epoch（使新代际可跨 master 寻址老代际 drain_ring，M3/M4 drain 通道继续可用）；新代际用新 epoch（同 proc_id 不撞名） |
| **C-NR-501** | 复核 master 侧零 ff 状态（[04] §2.2 已证，实机复核）；USR2 exec 前后 `nginx.pid` / `nginx.pid.oldbin`、channel、primary 归属的共存处理（`ngx_exec_new_binary` @ `src/core/nginx.c:718`，调用点 `ngx_process_cycle.c:425`） |
| **C-NR-502** | 新 master 启动分支：探测既有 primary（`ngx_ff_slim_primary_alive`，不重复 spawn）→ 从目录 mint 自身 epoch → 全 secondary fork（复用 C-NR-100~104，proc_id 移位）→ READY → 切流（复用 M3 T2 park barrier / T3 接管，owner 记 `(epoch,gen)`）→ 老 master worker 即 G_old 代际，复用 M4 drain |
| **C-NR-503** | WINCH/QUIT 语义：老 master 收 WINCH → 对老 worker 走 M4 drain；老 master QUIT 收尾**显式豁免常驻 primary**（primary 是其子进程，候选 b 形态必需） |
| **C-NR-504** | 回退（RT-04b）：新二进制异常 → 对老 master 发 HUP → 老 master 经世代目录夺回 rx owner 并继续服务；回退后 HUP/QUIT 链路正常。复用 M3 rx 交还原语 + M4 DR6① 心跳/崩溃检测，经目录仲裁避免双主 |

## 4. Agent team 编排与写审分离

- **leader**（主 agent）：统筹/派单/轮询/bounce/裁决/转人工；**子 agent 全部完成前严禁提前退出**，旁路轮询每 10 分钟一次、硬超时 60 分钟；超时未落盘即发状态探测，仍无响应则 spawn 替补（替补仍须遵守写审分离）
- **子 agent**：`m5-anchor-verifier`（Phase0）→ `m5-coder-gendir`（Batch A 硬前置）/ `m5-reviewer-a`（CR）→ `m5-coder-usr2`（Batch B：C-NR-501~504）/ `m5-reviewer-b`（CR）→ 并行 `m5-coder-test`（Batch C 测试）/ `m5-reviewer-c`（CR）→ `m5-test-runner`（实机）→ `m5-doc-writer`（spec 回写）/ `m5-reviewer-c`（回写复审）→ leader 裁决提交
- **铁律**：写方与审方必须是不同 agent；leader 严禁自写自审（只做运营性任务与汇总）；bounce 计数持久化在 `work/impl/state.json`，**每阶段 >3 立即停止转人工**

## 5. 批次划分（按文件归属，共享文件严格串行）

| 批次 | 内容 | 依赖 |
|---|---|---|
| Phase0 | 锚点复核 + **proc_id 命名资源全量审计**（产出白名单） | — |
| Batch A | 世代目录 + 命名上下文升级（lib 侧） | Phase0 |
| Batch B | C-NR-501/502/503/504（nginx 侧） | **G-A5 通过**（目录语义是 B 的输入） |
| Batch C | UT/IT + 双二进制构建脚本 | G-A5 通过（与 B 并行，文件无交集） |
| Phase3 | 实机 RT-04 / RT-04b / RG-NR-01 / HUP 回归 | G-B5 + G-C5 |
| Phase4 | spec 07/08 回写 + 复审 | G-M5 |
| Phase5 | leader 裁决 + 提交 | — |

## 6. 门禁判据

| 门禁 | 判据 | 失败处理 |
|---|---|---|
| **G-A5** | clean build 零 error / warning 51 零新增 + install + nginx 重链 + 单测全绿零回归 + **命名资源审计白名单全覆盖** + 目录原子性与「无 primary」退化安全 + =0 等价静态自证 + CR 通过 | 打回 A，bounce+1 |
| **G-B5** | 同上 + USR2 全路径（exec / pid / channel / primary 豁免 / 回退）CR 通过 + 双 master 世代仲裁无双主论证 | 打回 B，bounce+1 |
| **G-C5** | UT（世代目录 / epoch minting / 命名上下文 / 回退状态机）+ IT（真 EAL 双世代命名隔离）+ 双二进制构建脚本可用 + CR | 打回 C，bounce+1 |
| **G-M5** | **RT-04**（USR2 带流量：错误 0、新 master+G_new 接管、老 worker drain、pid 双文件共存期正确）+ **RT-04b**（新二进制配置错 → 老 master HUP 回退，老代际继续服务、回退后 HUP/QUIT 链路正常）+ **RG-NR-01**（=0 全量回归）+ HUP 回归（RT-01/02/03/05/06/07/09/10 关键项不劣化） | 打回对应批次，bounce+1；用尽转人工 |

## 7. 测试设计要点

- **RT-04**：需**两个不同二进制**（同一源码、不同构建输出路径/版本标识），USR2 在两者间切换；流量构造复用 M4 的 RT-02/RT-03（12 路活跃长连接 + 8 线程 CPS），判据：客户端错误 0、新 master + G_new 接管、老 worker drain、pid 双文件共存期正确
- **RT-04b**：新二进制配置错误（如未知指令）→ 对老 master 发 HUP → 老代际继续服务且回退后 HUP/QUIT 链路正常
- **RG-NR-01**：=0 全量回归（旧两段式行为不变、单测零变红）
- **HUP 回归**：M4 关键实机项复跑不劣化（防止 lib 命名/目录改动影响既有 HUP 链路）
- **USR2 期双 master 并存**：三查口径相应放宽（记录活跃 master 列表而非要求为空）

## 8. 工程规约（全团队强制）

- Shell 三件套：删除一律 `rm_tmp_file.sh`、停进程一律 `kill_process.sh`、加执行权限一律 `chmod_modify.sh`
- 改码前 `make clean`；lib 三步法（`PATH` 规避 IDE hook → `make machine_includes` → `make -o machine_includes -j16` → `make libfstack.a`）+ `make install`；nginx `make clean` 后重跑 configure（五参数）+ `make -j16`
- `lib/` 注释最小化、英文（仅 `ff_api.h` 新接口、目录结构、epoch 语义、复杂仲裁逻辑可加）
- commit message 英文 1-3 句；**config.ini 本地测试值不入库**
- 文档零真实 IP（`<DPDK_NIC_IP>` / `<CLIENT_IP>` / `<GATEWAY_IP>` 等占位符）
- 网卡独占三查（ps / hugepages rtemap=0 / `/var/run/dpdk/rte` 无近期 mtime）；`--proc-type` 显式禁 auto；各 agent 私有目录
- 提交按层切分（参照 M4 五层经验：lib → nginx → 测试 → spec），每层自洽可编、可按层 revert

## 9. 风险与回退

- **风险**：① 命名资源审计遗漏 → 撞号双消费者（审计 + IT 用例双保险）② 两 master 并发 mint/夺回 → 单一权威位 + SEQ_CST ③ primary 被老 master QUIT 误杀 → 显式豁免 + 实机验证 ④ 老代际 drain 跨 master 寻址失败 → RT-04 直接暴露 ⑤ 夺回瞬间极窄窗口（与 M4 DR6① 同族，登记观察）
- **回退**：不使用 USR2 即无影响（HUP 路径不依赖 M5）；硬前置（目录 + 命名）与 C-NR-501~504 可分 commit，各自 revert 后 M4 行为保留
