# ff_rss_check 三项优化 —— 编码实现阶段执行计划（plan-impl.md）

> 阶段：spec 已定稿（commit e5389cb52，门禁 CONDITIONAL PASS）→ 本阶段**正式编码实现 + 测试**。
> 方法：harness + spec 驱动 + agent team（leader + 子 agent）。
> 基线 commit：`e5389cb52`（feature/1.26）。
> spec 依据：`docs/ff_rss_check_opt_spec/zh_cn/` 00-09（落点见 06/05，事实见 02，门禁断言见 09）。
> 强制规约：实际执行不臆测、代码为准、交叉验证；rm/kill/chmod 走 `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`（make install 类可）；lib 注释精简；commit 英文 1-3 句；config.ini 本地测试值不提交（提交前 git diff 复核）；门禁失败打回上一步（单步 bounce≤3，超则停转人工，除非实在无法实现否则不留遗留项）；子 agent 全部完成前 leader 严禁退出、主动轮询等待。
> 测试环境：DPDK 网卡 `9.134.214.176`（经 ssh f-stack-client 测）；内核栈 `127.0.0.1`。当前 helloworld 未运行、symmetric_rss=0、kernel_coexist=0。

## 0. 实现里程碑（严格按 spec 06 的 R-A→R-B→R-C 顺序，有依赖）

| 里程碑 | 需求 | 内容 | 依赖 |
|--------|------|------|------|
| **R-A** | 0.1 | 内核侧 RSS 选端口回迁（IPv4）：in_pcb.c in_pcb_lport_dest + in_pcbconnect + in_pcb.h | spec |
| **R-B** | 0.3 | rte_thash 动态路径优化（IPv4）：ff_dpdk_if.c 新增 thash ctx/adjust_sport + 挂 in_pcb_lport_dest 未命中分支 | R-A |
| **R-C** | 0.2 | IPv6 全链路：ff_dpdk_if.c v6 表/函数 + in_pcb/in6_pcb 对接 + ff_config v6 解析 | R-A/R-B |

每里程碑内部子阶段（均过门禁才进下一里程碑）：
1. **起步核实**（编码前先 grep/读码核实该里程碑的待确认项 F#，结论回写 spec，禁臆测）
2. **编码**（最小 diff、全 `#ifdef FSTACK` 门控、注释精简）
3. **编译**（开/关 FSTACK 双编译，0 error；宏关零回归）
4. **单测**（cmocka，含正确性 + 回归）
5. **review**（leader 独立读码复核，不依赖子 agent 单方结论）
6. **真机/集成测试**（leader 统筹：9.134.214.176 + 127.0.0.1）
7. **里程碑门禁**（spec 06 的 R-?.4 门禁项逐条 PASS）→ PASS 才提交 + 进下一里程碑

## 1. 各里程碑待确认项（起步先核实，对应 spec 09 F 表）

- **R-A 起步核实**：F1(in_pcbconnect 中 ff_in_pcbladdr 精确插入点)、F2(protosw 是否影响 lookupflags 透传)、F3(get_portrange 返回语义=命中0/未命中-ENOENT，已确认 L2843-2848)、F4(端口轮转 dport[0] 自增机制)、F11(单测 rss_reta_size 注入)、F15(connect 客户端载体)。
- **R-B 起步核实**：F9(非对称 key attempts 初值 16 调优)、F10(helper v4 offset=64bit/len 16)、F13(新增函数行号回填)、F14(desired_value 可观测性)、F16(perf 打点宏)、F17/F18(真机量级/reta_size·nb_queues)。
- **R-C 起步核实**：F5(v6 connect 走统一 in_pcb_lport_dest 还是 in6_pcb 独立路径)、F6(网卡 v6 RSS offload)、F7(rte_flow IPV4_TCP 是否在范围，倾向否)、F8(v6 表容量宏/内存)、F12(rss_tbl_cfg_handler 非 static)、F10(v6 offset=256bit)、F13(v6 函数行号)。

## 2. 关键实现约束（spec 04/05，零容忍项）

- **0.3 落队列零容忍**：`ff_rss_adjust_sport` 反算出的 sport 必须经软算 `ff_rss_check()==1` 复核才返回成功；复核失败/attempts 用尽/ctx init 失败 → 回退逐端口软算扫描（功能不退化）。desired_value ∈ {v|v%nb_queues==queueid, v<reta_size} 轮转。
- **IPv4 零回归**：0.2 用 v6 独立表/函数（方案A），不改任何 v4 接口签名/结构布局；0.1/0.3 全 `#ifdef FSTACK` 门控，关 FSTACK / rss enable=0 / 单队列(nb_queues<=1) → 走原生。
- **15.0 适配**：in_pcb_lport_dest 签名 const inpcb（回迁逻辑勿改 inp 指向内容）；lookup 用 15.0 签名（in_pcblookup_local 带 RT_ALL_FIBS、in_pcblookup_hash_locked 带 M_NODOM,RT_ALL_FIBS）；INPLOOKUP_LPORT_RSS_CHECK 维持 enum 外 0x80000000、入口清除、不入 MASK。
- **LOOPBACK**：in_pcb_lport_dest 对 loopback 直接 break 不做 RSS，保 127.0.0.1 正常。

## 3. agent team 分工

- **leader**（本对话）：统筹、起步核实把关、每里程碑独立 review + 真机测试统筹 + 门禁复核 + 提交、轮询等待、最终汇总；子 agent 全部完成前不退出。
- **impl**：各里程碑编码（in_pcb.c/in6_pcb.c/in_pcb.h、ff_dpdk_if.c、ff_config.{c,h}），双编译零回归自检。
- **tester**：cmocka 单测编写 + 双态运行（按 spec 07 用例 TC-U-RSS-*）。
- **reviewer**（可选，或由 leader 兼任）：代码 review 门禁。
> 真机/集成测试（9.134.214.176 / 127.0.0.1、起停 helloworld）由 leader 亲自统筹（kill 走脚本）。

## 4. 提交策略

- 每里程碑门禁 PASS 后提交一次，commit message 英文简短 1-3 句。
- 提交集 = lib + freebsd + tests（按里程碑）；**排除 config.ini 本地测试值**（提交前 git diff 复核，仅 rss_check 段特性相关说明可提交）。
- 全部里程碑完成后经 spec 09 门禁逐项断言复核。

## 5. 风险与回退

- R-A const inpcb 误改/flag 污染 → 全 #ifdef FSTACK，编译/单测失败即打回。
- R-B 选错队列 → 软算复核兜底（零容忍）；不收敛 → 回退软算。
- R-C IPv4 回归 → 方案A 不动 v4；v6 内核对接点以实际调用链为准（F5 起步核实）。
- 任一里程碑同一步 bounce≤3 仍不过 → 停转人工决策，不强行放行、不留病灶遗留项。
