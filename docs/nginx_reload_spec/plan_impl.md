# Nginx 无损 reload 实现计划（plan_impl.md）

> **性质**：功能实现与验收阶段计划（spec 已人工审核通过，spec 版本 v1.9.3）
> **范围**：M0（PoC 预研验证）+ M1（常驻 primary 化，7 编码点）+ M2（新旧并存，13 编码点）= **20 编码点**
> **方式**：harness 工程 + spec 驱动 + 多 agent team（leader 统筹轮询、写审分离、bounce≤3、门禁失败转人工）
> **基线**：分支 `release/2.0`，base commit `34065f139`
> **本阶段目标**：reload 顺序回归 nginx 原生「先起新再退旧」+ 同 lcore_id 资源隔离 + 代际隔离。**尚未无损**（无损能力在 M3）

---

## 1. 已核实的关键前提

| 项 | 结论 | 证据 |
|---|---|---|
| `primary_slim` 已合入主线 | ✅ M1 前置满足 | `lib/ff_config.c:1037-1038` 解析、`:1423-1461` 校验、`:1526-1538` 互斥校验、`:1578-1579` 默认值；`ff_dpdk_if.c:320/:444`、`ff_dpdk_kni.c` 引用 |
| cmocka 1.1.7+ 可用 | ✅ 单测基建就绪 | `/usr/include/cmocka.h`；`tests/unit/Makefile` 独立 CFLAGS + `-DFF_UNIT_TEST=1` + fixtures |
| M0 五项一票否决实验 | ❌ **全部未执行** | `work/` 仅调研/审核文档，`_poc_*.patch` 零命中 |
| 规约脚本 | ✅ 均存在可执行 | `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh` |

**结论：M0 不可跳过。** 5 项一票否决（RV7/RV3/RV10/RV11/RV12）必须在真机跑出数据才能进入 M1。

## 2. 设计决策（spec v1.9.3 已定案，实现须遵守）

| 决策 | 结论 | 影响编码点 |
|---|---|---|
| **DR1** | 候选 b：nginx master 编排（FF_RELOAD + 等 READY + QUIT），slim primary 仅提供原子原语 | C-NR-100/101/205 |
| **U-NR-1** | slim primary 由 master 代管 + double-fork/setsid 脱离，运维零新增 | C-NR-100 |
| **DR8** | 两代**相同 lcore_id**，`lcore_mask`/`nb_procs`/队列数保持 N，无新增配置面 | C-NR-201/206/307/314 |
| **DR11** | 共享 RX 池 **M-A 为主**（`cache_size=0`，稳态有损耗由 PT-NR-09 量化）；M-B 仅留常量位 | C-NR-315 |
| **DR5** | 已取消（代际 lcore 池/四链解耦），P0-3 消解，C-NR-311 取消 | — |
| **DR6** | T3 后 G_new 崩溃 → 心跳超时（默认 1s）→ primary 将 rx 交还 G_old | C-NR-316 |

## 3. Agent team 编排

### 3.1 角色

| 角色 | 类型 | 职责 |
|---|---|---|
| `reload-leader` | 主 agent | 统筹/派单/轮询探测/bounce 计数/门禁裁决/转人工。**严禁提前退出** |
| `poc-runner` | 写方 | M0 八项 PoC 脚本与临时补丁，实际执行并采集数据 |
| `poc-reviewer` | 审方 | 独立复核五项一票否决结论与原始数据 |
| `m1-coder` | 写方 | C-NR-100~106 |
| `m1-reviewer` | 审方 | M1 独立 CR |
| `m2-coder-cp` | 写方 | C-NR-201~206（控制面） |
| `m2-coder-iso` | 写方 | C-NR-307/313/314/315/316（资源隔离） |
| `m2-reviewer` | 审方 | M2 独立 CR |
| `build-guard` | 门禁 | `make clean` + 全量编译，比对 warning 基线 |
| `test-runner` | 写方 | 单测/集成/实机执行 |
| `test-reviewer` | 审方 | 测试结果复核 |

### 3.2 写审分离铁律

- 写方（`*-coder` / `poc-runner` / `test-runner`）与审方（`*-reviewer`）**必须不同 agent**
- leader **严禁自写自审**，纯调研/探测/汇总可由 leader 兼任
- 异常回退时 spawn 替补 agent，替补仍须遵守写审分离，不得由 leader 顶替写方

### 3.3 轮询探测与超时

- 子 agent 一律落盘到 `work/impl/<stage>-<role>.md`
- leader 用**旁路探测**（读落盘文件 / `git status` / 产物路径）每 **10 分钟**一次，硬超时 **60 分钟**
- **禁止无超时死等消息返回**

### 3.4 bounce 与转人工

- `work/impl/state.json` 持久化各阶段 bounce 计数
- 任一门禁失败 → 打回对应写方，bounce+1
- **bounce > 3 → 立即停止，输出报告转人工决策**（用户已确认此策略）

## 4. 里程碑门禁

| 门禁 | 判据 | 裁决 | 失败处理 |
|---|---|---|---|
| **G-M0** | E-NR-01(RV7)/02b(RV3)/06(RV10)/07(RV11)/08(RV12) 五项一票否决全 PASS + 基线落盘 + DR2/DR4 初评有结论 | poc-reviewer → leader | **停止转人工** |
| **G-M1** | clean build 零 error 零新增 warning + UT-NR-01~03/07~09 全绿 + 既有 TC 零回归 + RT-00 实机正常 + `graceful_reload=0` 逐字等价 + CR 通过 | m1-reviewer + test-reviewer → leader | 打回 m1-coder，bounce+1 |
| **G-M2** | clean build + UT-NR-12/17/18/20/21/22 全绿 + IT-NR-A12/A13 + **PT-NR-08 精度等价（合入门槛，不可省略）** + RT-10 多轮 reload + CR 通过 | m2-reviewer + test-reviewer → leader | 打回对应 coder，bounce+1 |

## 5. 编码点清单

### M1（7 点）

| 编号 | 锚点 | 要点 |
|---|---|---|
| C-NR-100 | `ngx_process_cycle.c` master 启动分支 | slim primary 拉起（DR1 候选 b：double-fork/setsid） |
| C-NR-101 | `lib/ff_config.h:295-316` / `ff_config.c:1035-1036` | `[dpdk] graceful_reload`（默认 0）+ 校验链（要求 `primary_slim=1`、`nb_procs>=2`、与 `thread_mode=1` 互斥） |
| C-NR-102 | `ngx_ff_module.c:169-187` | `ff_mod_init` 拼参全 secondary |
| C-NR-103 | `ngx_process_cycle.c:1117-1121` + `.h:40-44` | `ngx_ff_process` 全 worker → SECONDARY；枚举扩展 primary 角色 |
| C-NR-104 | `ngx_process_cycle.c:443-510` | `=1` 跳过 15s sem 等待，改 attach 确认；`=0` 逐字保留 |
| C-NR-105 | `ngx_process_cycle.c:1251-1256` | primary 退前 500ms 分支条件化 |
| C-NR-106 | `config.ini` + `doc/F-Stack_Nginx_APP_Guide.md` | 注释块与示例项；**本地测试值不入库** |

### M2（13 点）

| 编号 | 锚点 | 要点 |
|---|---|---|
| C-NR-201 | `ff_config.h` dpdk 段 + `ff_config.c:1414-1519` | queue_id 代际无关固定映射 + V-NR 校验链 |
| C-NR-202 | `ff_msg.h:37-53` | FF_RELOAD 消息族 |
| C-NR-203 | `ff_dpdk_if.c:2404-2454` | 消息处理器注册与分派 |
| C-NR-204 | `ngx_process_cycle.c:223-270` | 两段式 reload 条件化 + 防重入 |
| C-NR-205 | 新增 `ngx_ff_reload.c` + `auto/sources` | T0-T5 编排状态机（master 侧驱动） |
| C-NR-206 | `ff_config.c` proc_lcore + `ff_dpdk_if.c:508-538` | proc_id 代际无关映射。**必须与 C-NR-313 成套，不得单独合入** |
| C-NR-307 | main_loop | 自驱 hardclock（按 TSC 直调 `ff_hardclock()`），**必需无退路** |
| C-NR-313 | msg_ring / KNI owner | 按 (proc_id, 代际) 索引；owner 跟随活跃代际 |
| C-NR-314 | 代际 mempool 应用侧 | `gen0/gen1` init 期预建 + 乒乓复用 |
| C-NR-315 | `ff_dpdk_if.c:634` / `:1128` / `:1140-1141` | RX 池 M-A（`cache_size=0`）；M-B 常量位 `ff_memory.h:37` |
| C-NR-316 | 共享内存心跳 + primary | 每 loop 递增心跳、1s 超时、rx 交还 G_old |

## 6. 执行规约（全部 agent 强制）

1. **Shell**：删文件走 `rm_tmp_file.sh`、停进程走 `kill_process.sh`、加执行位走 `chmod_modify.sh`；严禁直接 rm/kill/chmod
2. **编译**：先 `make machine_includes` 再 `make -j16`；`make clean` 用 `PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin" make clean` 规避 IDE hook；lib warning 基线 51，不得新增
3. **注释**：`lib/` 最小注释、一律英文；仅 `ff_api.h` 接口、`config.ini` 配置项、复杂逻辑可加
4. **提交**：英文 1-3 句；config.ini 本地测试值不入库；按里程碑拆可独立 revert 的 commit
5. **文档 IP**：严禁真实 IP，用 `<DPDK_NIC_IP>` / `<CLIENT_IP>` / `<GATEWAY_IP>` 等占位符；`127.0.0.1` 可写
6. **测试通路**：DPDK 侧 `ssh f-stack-client` 访问 `<DPDK_NIC_IP>`；内核栈用 `127.0.0.1`
7. **实事求是**：所有行动实际执行，代码/文档/外部资料交叉验证，不一致以实际代码为准；无法坐实的如实标注

## 7. 已知风险

- **RV3 / RV11 若不成立** → M1′ 主路径不成立，立即停止转人工
- **virtio PMD 无 `imissed`** → 丢包 guest 侧不可观测，RV3 判据须用端到端业务指标 + 宿主机侧统计
- **spec 锚点漂移** → 编码前必须用 code-explorer 复核每个 `file:line`
- **C-NR-206/313 强耦合** → 单独合入会引入 P0-6 控制消息错收
