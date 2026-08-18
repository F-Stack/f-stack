# 09 独立门禁审核报告：Nginx 无损 reload spec 文档集（00~08）

| 项 | 值 |
|---|---|
| 文档编号 | 09 |
| 标题 | 独立门禁审核报告（G1~G6 逐项审核 + 问题清单 + 门禁判定） |
| 版本 | v1.3（v1.0 初审打回；v1.1 复核闭环；v1.2 U1 坐实增补；v1.3 S3 流表窗口化修订增补） |
| 日期 | 2026-08-18 |
| 状态 | 已出具（bounce 1 修复已复核闭环，最终判定：门禁通过；v1.2/v1.3 为用户指令的增量修订，见 §11/§12） |
| 审核人 | 独立门禁审核员 R（gate-reviewer，与全部写者 agent 不同实例，写审分离；初审与复核同为 R，复核按 §9 预定 diff 级方式执行） |

---

## 1. 审核范围与方法

- **审核对象**：`docs/nginx_reload_spec/zh_cn/` 下 00~08 共 9 篇（每篇全文实读）。
- **对照材料**：`work/` 下 6 份中间产物（evidence-legacy / milestones-testing / probe-fstack-current / probe-ld-preload / research-other-projects / research-vpp-vcl / solution-design，实为 7 份文件）；本地代码（/data/workspace/f-stack，HEAD）；git 只读命令（log/show/rev-parse/tag -l/status/diff --cached）；gh api 只读（FDio/vpp 与 F-Stack/f-stack 的 commit/issue/PR）；web_fetch 抽核外部 URL 原句。
- **方法**：按审核清单 G1~G6 逐项执行并记录证据；行号类证据用 read_file 直接读本地代码比对；commit 用 `git log -1 --format` 与 `gh api repos/.../commits/<sha>` 核对存在性与摘要；issue/PR 用 gh api 核对元数据；URL 用 web_fetch 逐字核对引文。审核全程只读，未修改 00~08 与 work/ 任何文件，未执行任何 git 写操作（本报告为唯一产出文件）。
- **抽查规模**：行号类约 45 处、commit 17 个（本地 10 + VPP 7）、issue/PR 7 个、URL 2 个（含 6 句引文逐字比对）、跨文档一致性数字/编号映射全量核对。

## 2. G1 证据链抽查（重点项）

### 2.1 文件:行号类（抽 04/05/06/07 篇，读本地代码逐条比对）

抽查明细（全部实读本地代码核对）：

| 引用（篇:位置） | 核对结果 |
|---|---|
| 04 §2.2/§2.5：`ngx_process_cycle.c:223-237`（两段串行 reload）、`:224-230`/`:232-234`/`:236-269` | 相符（实际 FSTACK 条件块 224-237，sig_worker_quit 逻辑逐行吻合） |
| 04 §2.2：`:443-475`（shm+sem_init pshared=1）、`:487-510`（sem_timedwait 15s，:494 `ts.tv_sec += 15`，超时 exit(2)） | 相符 |
| 04 §2.2：`:480-483` spawn、`:762-764` respawn 追加 `&& !ngx_reconfigure`、`:888-899` worker QUIT 分支、`:924` ff_run、`:1109-1128` ff_mod_init、`:1117-1121` worker0=PRIMARY、`:1130-1132` sem_post、`:1134-1138` open_listening、`:1251-1256` primary 退前 ngx_msleep(500)、`:1258` exit(0) | 全部相符 |
| 04 §2.3：`ngx_ff_module.c:129`（inited）、`:147-167`（convert/is_fstack_fd 偏移 ngx_max_sockets）、`:169-187`（ff_mod_init 硬编码 --proc-type）、`:194-197`（INT_MAX 校验）、`:439-447`（close 劫持）、`:515-546`（kqueue/kevent 劫持 + ident restore） | 全部相符 |
| 04 §2.2：`ngx_connection.c:25-34`（ngx_ff_skip_listening_socket master 分支跳过） | 相符 |
| 04/03：`ff_dpdk_if.c:113`（`static __thread struct rte_timer freebsd_clock`）、`:254-258`/`:261-265`（hardclock job）、`:1241-1257`（init_clock）、`:1244-1245`（subsystem_init+meta_init）、`:1262-1272`（init_clock_worker） | 相符 |
| 04 §3.2：`:508-538`（lcore↔RX queue 映射）、`:616-639`（mempool primary create/secondary lookup）、`:660-680`（create_ring）、`:1699-1836`（ff_dpdk_init）、`:1702-1710`（nb_procs 校验）、`:1712`（rte_eal_init） | 相符 |
| 06 §0：`ff_dpdk_if.c:2100/:2105`（回调仅对 `!pkts_from_ring` 包触发）、`:2111`（usr_cb_tsc 统计）、`:2142-2150`（回调转发 enqueue dispatch_ring）、`:2223-2236`（process_dispatch_ring dequeue 后 pkts_from_ring=1） | 相符（06 §0「转发无循环风险」的机制确认与代码一致） |
| 04 §3.3：`:2404-2454`（handle_msg 按 msg_type 分发）、`:2456-2474`（process_msg_ring）；`ff_msg.h:37-53`（FF_MSG_TYPE 九种消息） | 相符 |
| 04 §3.1/§3.4：`:2803-2805`（rte_timer_manage 驱动）、`:2865+`（rx_burst）、`:3009`（rte_eal_mp_remote_launch CALL_MAIN）、`:3014-3022`（rte_eal_cleanup 段）、`:3026-3033`（stop_loop） | 相符 |
| 04 §3.1：`ff_api.h:57/59/61`（ff_init/ff_run/ff_stop_run）、`:299-303`（ff_regist_packet_dispatcher 族）；`ff_config.c:1159-1270`（dpdk_args_setup）、`:1185-1188`/`:1343-1344`/`:1347-1350`（proc_type）、`:1547-1552`（thread_mode 与 secondary 互斥） | 相符 |
| 04 §2.4：`ff_syscall_wrapper.c:916-958`（ff_socket → sys_socket → td_retval[0]）；`ff_freebsd_init.c:355`（ff_fdused_range） | 相符 |
| 05 §3.2：`ff_hook_syscall.c:2426-2496`（ff_hook_fork 全函数：:2434-2435 切 sc/zone、:2438-2440 持锁、:2447 refcount++、:2451 current_worker_id++、:2455-2457 forking 自旋、:2470 child_process_init、:2482 thread handle） | 相符 |
| 05 §6-1/§3.7：`:3335-3347`（child_process_init 固定 attach(0)，:3338）、`:2333-2345`（内核 epoll 每 256 次轮询，:2335 `(count & 0xff) == 0`） | 相符 |
| 05 §3.3/§3.4：`ff_socket_ops.c:42`（ff_bound_fds）、`:131-147`（ff_sys_bind → sockaddr_is_bound → ff_dup2 复用）；`ff_socket_ops.h:45`（SOCKET_OPS_CONTEXT_MAX_NUM=1<<5=32）；`ff_so_zone.c:124-125`（FF_RING_DEFAULT_WAIT_MODE 编译期常量、无 getenv——spec 偏差一坐实）、`:165-167`（FF_MULTI_SC 切 zone）；`ff_ring_ipc.c:49-75`（v3.3 D2/H23 注释 + completion release 语义 :61） | 相符 |
| 03 §5.3：`dpdk/lib/timer/rte_timer.c:122-185`（subsystem_init 共享 memzone）、`:216-228`（rte_timer_meta_init memset 本 lcore 槽）；03 §7：`docs/zh_cn/f-stack-issue-ana.md:2074-2076`（#547）、`:2175-2177`（#12）、`:557-559`（#528） | 相符 |
| 06 §3.3/§5.1-L2 与 07 C-NR-302：`set_rss_table` 引 `ff_dpdk_if.c:801/:1169-1174` | **不符**（详见问题 P2）：实际 set_rss_table 定义于 **:832**，rte_eth_dev_rss_reta_update 调用于 **:850**，既有调用点 **:1218**；:801 为 init_kni，:1169-1174 为 bond/MTU 段 |

**G1-行号结论**：约 45 处抽查中 44 处相符，1 组（3 处引用）行号错误（函数名正确、全局唯一可 grep 定位，不影响机制结论，但须修正）。

### 2.2 commit hash 类（抽 03/06 篇）

本地 f-stack 仓库（`git log -1 --format='%h %ad %an %s'`）：

| hash | 实际 | 03/06 篇声称 | 结果 |
|---|---|---|---|
| 406002113 | 2017-08-23 16:54:32 +0800 logwang "Support nginx reload." | 同（§2.4） | 相符 |
| 37a7c72f0 / 4418919fe | 2020-06-18 johnjiang "DPDK: upgrade to DPDK 19.11.2(LTS)." | 同（§5.1 失效分水岭） | 相符 |
| 62f1c34df | 2026-01-16 17:41:18 +0800 jinliu777 "Fix infinite loop when restarting DPDK secondary process" | 同（§5.4 精确到秒） | 相符 |
| a9643ea85 | 2017-04-21 logwang "init" | 同 | 相符 |
| 82b409faf | 2026-08-03 fengbojiang "Drive per-thread callwheel on native-mt worker lcores" | "2026 native-mt callwheel per-thread" | 相符 |
| 9817534a2 | 2020-11-19 14:43:26 +0800 "Merge pull request #559 from hawkxiang/..." | PR#559 合入时间 2020-11-19 14:43:26 +0800 | 相符（精确吻合） |
| 14355bf7b | 2026-06-09 "port: re-apply F-Stack local DPDK patches onto 24.11.6 (4 patches: ... rte_timer ...)" | 2026-06-09 4 补丁 re-apply | 相符 |
| 2df8fe233 | 2021-01-29 "Update release note for 1.21."；且 `git rev-parse v1.21` = 2df8fe233 | tag v1.21 | 相符 |
| 4b05018ff | 2019-11-23 "DPDK: update to 18.11.5."；且 `git rev-parse v1.20` = 4b05018ff | tag v1.20 | 相符 |

VPP 仓库（`gh api repos/FDio/vpp/commits/<sha>`，7 个全查）：

| sha | 实际（日期/作者/标题） | 01 篇 §3.5 表 | 结果 |
|---|---|---|---|
| 2e005bbbdf | 2017-11-07 Dave Wallace "VCL: handle process fork." | 同 | 相符 |
| 053a0e44ed | 2018-11-13 Florin Coras "vcl/session: apps with process workers" | 同 | 相符 |
| 47c40e2d94 | 2018-11-27 "vcl: basic support for apps that fork" | 同 | 相符 |
| 30e79c2e38 | 2019-01-03 "vcl/session: add api for changing session app worker"；**commit message 正文与 01 §3.3 引文逐字一致**（"In case of multi process apps, after forking, the parent may decide to close part or all of the sessions ... moved to the child's segment manager."） | 同 | 相符 |
| f9240dc920 | 2019-01-15 "vcl: move forking logic to vls" | 同 | 相符 |
| 5788a34be6 | 2021-06-22 wanghanlin "vcl: validate vep handle when copying sessions on fork" | 同 | 相符 |
| 4d9df5cb3d | 2025-01-06 Florin Coras "vcl: fix vls wrk index on fork" | 同 | 相符 |

**G1-commit 结论**：17/17 全部存在且日期、作者、摘要一致。PASS。

### 2.3 issue / PR / URL 类（抽 01/02/03 篇）

gh api 元数据核对：

| 对象 | 实际 | 文档声称 | 结果 |
|---|---|---|---|
| F-Stack #547 | orange30，created 2020-09-18T08:05:02Z，closed 2021-09-22T14:14:17Z | 03 §1.1 元数据表逐字段 | 相符 |
| F-Stack #12 | beacer，2017-05-23T06:33:25Z → closed 2017-08-23T09:01:33Z | 03 §2.1 | 相符 |
| F-Stack #1036 | 存在（closed，2025-12-16 创建） | 00/01/02 引用其根因结论（与本地档案 L557-559 一致） | 相符 |
| F-Stack PR#559 | hawkxiang，merged 2020-11-19，标题 "Config: Support parse "--file-prefix"&"--pci-whitelist" for multi-processes" | 03 §4.2 | 相符 |
| VPP #3547 | closed（2025-05-19），标题 "[VPP-2086] VCL and VPP(V2306) will crash when reloading nginx using **jemter** test" | 01 §4.3 "CLOSED，未实际修复关闭" | 状态相符；**标题原文拼写为 "jemter"，01 篇规范化写作 "jmeter"**（问题 P3，建议级） |
| VPP #3645 | open，created 2025-11-18，标题 "VPP main thread stuck at session_wrk_handle_evts_main_rpc() ..." | 01 §4.3 "OPEN，2025-11-18 报告" | 相符 |

URL 引文逐字核对（web_fetch）：

- nginx 官方 control.html：02 §2.1/§2.2 引用的 3 句——"The master process first checks the syntax validity, then tries to apply new configuration"、"After that all worker processes (old and new ones) continue to accept requests."、"the old master process does not close its listen sockets"——**3/3 逐字命中**。
- Envoy hot restart 架构文档：02 §2.3/P1 引用的 3 句——"existing connections are not transferred to the new Envoy process"、"Envoy passes each socket to the new process by worker index"、"some connections may be dropped in the accept queues of the old process workers"——**3/3 逐字命中**（基线 1 的关键引文坐实）。

**G1-issue/URL 结论**：6 个 issue/PR 元数据相符，6 句 URL 引文逐字命中，1 处拼写规范化备注（P3）。PASS（附 P3）。

## 3. G2 IP 合规独立复验

- `search_content` 于 zh_cn/ 全目录搜 `\b(9\.134|10\.160|2402:4e00)\b`：**0 命中**。
- 全量 IPv4 模式 `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` 扫描：仅 3 处命中，全部为 `127.0.0.1`（08 §2.1 拓扑图 L95、RT-11 L132、RG-NR-05 L203）——本机 lo 回环测试地址，属任务书明确合规项。
- 03 篇图 5 实测命令已按规约替换为 `<DPDK_NIC_IP>` 占位符并在正文注明（03 文头与 §3.3 图 5）；08 篇拓扑与 ab 命令同用该占位符。无真实内网 IP、无 MAC/主机名特征残留。

**G2 结论：PASS（0 违规）。**

## 4. G3 一致性检查

### 4.1 一致项（PASS 部分）

- **三条基线**：00 §3.1 的三条基线表述与 01 §6.2/§4.2、02 §4 P4/§5 增补段、06 §0.1 逐条对应一致（Envoy 原句经 URL 核实，见 G1）。
- **S3 推荐与分档**：00 §3.2 与 06 §4.2 分档表一致（推荐 S3、备选 S2 限定场景、S1/S4 不独立实施）；S3 机制描述（乒乓 lcore 段、reta 切流、dispatch_ring 转发兜底、承接 primary_slim #1078）在 00/06/07 三篇口径一致。
- **M0-M7 与映射**：00 §3.3/§6 注 与 07 §0.2 映射表一致（07 的 M1~M4 合计=06 的 S3-M1；07 的 M7=S3-M2）；M0 两项一票否决（RV2/RV7）与 07 关键结论 2 一致。
- **RV/DR 编号体系**：06 §6.1 RV1~RV9 与 07 §0.3 分配表的 RV 名称逐项一致；06 §6.2 DR1~DR7 与 07 §0.4 一致，DR7 阈值两处均为「转发路径稳态损耗 >5% 或 drain 期 P99 劣化 >10%」。
- **C-NR/RG/UT/PT/A/U 编号**：00 §6 编号体系表与 07 §0.1、08 各节前缀一致；07 各里程碑 DoD 引用的用例编号（UT-NR-01~03/07~09、RT-00、IT-NR-A02/A03、RT-01~RT-13、PT-NR-05 等）在 08 正文表格中全部存在。
- **0 回退原则**：`graceful_reload=0` 默认值与配置级总回退点在 00 §3.3、06 §5.4-3、07 关键结论 1、08 A-NR-01 贯穿一致。
- **交叉链接**：zh_cn/ 内 9 篇互链的相对路径目标（00~08 九个 .md）全部存在；06/07/08 引用的 `docs/primary_slim_spec/`（00~15 篇均在，含 03/10）、`docs/issue_1078/zh_cn/`、`docs/ld_preload_ring_spec/zh_cn/`（01~04 + support + perf 分析）均实际存在。
- **测试规模数字中的一致项**：16 条单测（UT-NR-01~16）、9 个 fixture（F-NR-1~9）、6 条性能基线（PT-NR-01~06）、20 项验收（A-NR-01~20）、6 项回归（RG-NR-01~06）在 00 §4/§5、07 摘要、08 正文之间互相一致且与正文清单相符。
- **未坐实总览**：00 §5 表各类计数（A 类 9+11、B 类 7、C 类 6+8、D 类 9+7、E 类 9）与 01 §7（9 项）、02 §6（11 项）、03 §8（U1-U7）、04 §5（6 项）、05 §6（8 项）、06 §6/§8 逐篇实数核对一致。

### 4.2 不一致项（FAIL 部分，详见问题清单 P1）

| # | 声称 | 出现位置 | 实际（正文清单逐一清点） | 溯源 |
|---|---|---|---|---|
| 1 | "41 个编码改动点（C-NR-101~604）" | 00 §2.1/§3.3/§4；07 摘要/§3 | C-NR 全集为 **35 个**（100~106=7、201~208=8、301~306=6、401~406=6、501~504=4、601~604=4）；且 "101~604" 的范围写法本身只覆盖 34 个、与含 C-NR-100 的清单自相矛盾；07 §1 总览表 M1 行写 "6（C-NR-101~106）" 而 M1 详述含 C-NR-100~106 共 7 项 | work/milestones-testing.md L12/L305/L546 原文即写 41（源头错误），正式化沿用未核 |
| 2 | "6 条 cmocka 真 EAL 集成用例（IT-NR-A01~05）" | 00 §4；07 摘要；08 摘要 | 08 §2.2 A 组表实际 **5 条**（A01~A05） | work L12 同样写 "6 条" 而其正文也只有 A01~A05 |
| 3 | "13 条实机用例（RT-00~13）" | 00 §4；07 摘要（IT-NR-RT 13 条）；08 摘要 | 08 §2.3 B 组表实际 **15 行**（RT-00~13 共 14 个编号 + RT-04b） | work 原文编号为 "IT-NR-RT-01~13"（恰 13 个），正式化改用 RT-00~13 后计数未同步 |

**G3 结论：FAIL（3 组规模数字与正文清单不符，均为机械性修正；其余全量一致性核对通过）。**

## 5. G4 完整性检查

- **文头齐备**：9/9 篇均有「文档编号 / 标题 / 版本 v1.0 / 日期 2026-08-18 / 状态：待人工审计 / 来源产物声明」六要素（00 为汇总来源声明，01-08 均声明对应 work/ 产物与正式化改写说明）。
- **「实际执行的操作清单 / 证据可追溯」节**：01 §1（搜索/抓取操作表 + 交叉验证情况）、02 §1（19 项操作表）、03 §0（完整只读命令清单）、04 §1（读过文件清单 + 搜索关键词 + 只读声明）、05 §1（通读文件清单 + 方法 + 未做项声明）全部存在；06 以 §0「输入清单与交叉验证声明」（含 4 处代码回查行号，本审核已实证其中 4/4 相符）承担同等职能（00 §2.2 的强制要求针对调研/探测篇，06 为设计篇，处理合理）；07/08 为规划拆分篇，其可追溯性经来源声明 + work 映射核对覆盖。
- **未坐实/单来源标注未丢失**（对照 work/ 原产物抽样）：
  - work/research-vpp-vcl.md §7（9 项）与 01 §7 逐字一致；
  - work/probe-fstack-current.md §5（6 项）与 04 §5 逐字一致；
  - work/milestones-testing.md 的 C-NR 编号全集与 07 完全一致（35 个，进一步佐证 41 为源头数字笔误而非正式化丢失）；
  - 6 份 work 产物的末尾章节结构（未坐实/单来源/来源索引）与正式篇章节一一映射，未见正式化时删改实质内容。
- 03 篇真实测试地址占位符替换已在文头显式声明（符合 G2 与工作区规约）。

**G4 结论：PASS。**

## 6. G5 规约符合性

- **git 写操作零执行**：`git status --porcelain docs/nginx_reload_spec/` 输出仅 `?? docs/nginx_reload_spec/`（整目录 untracked 新文件）；`git diff --cached` 为空（无 staged）。本审核自身仅执行只读命令（status / diff --cached / log / show / rev-parse / tag -l）。
- **work/ 未被正式化写者改动**：mtime 证据——work/ 7 份文件最后修改时间 12:39:46~13:21:43，全部早于 zh_cn/ 最早文件 00-overview.md（13:25:12），即正式化改写时段（13:25~13:35）内 work/ 无写入；内容证据——C-NR 清单、§7/§5 未坐实清单等抽样逐字一致（见 G4），无编辑痕迹。
- **00~08 未被本审核改动**：本审核唯一写出的文件为 09-review-report.md。

**G5 结论：PASS。**

## 7. 问题清单（分级）

### 阻塞（须修复后复核）

- **P1【规模数字失实，3 组】**（G3）：
  a) 编码点总数：`41 个（C-NR-101~604）` → 应为 **35 个（C-NR-100~604）**；涉及 00 §2.1/§3.3/§4 共 3 处、07 摘要与 §3 共 2 处；07 §1 总览表 M1 行 "6（C-NR-101~106）" 应改为 "7（C-NR-100~106）" 以与详述一致。
  b) 集成用例数：`6 条（IT-NR-A01~05）` → 应为 **5 条（IT-NR-A01~05）**；涉及 00 §4、07 摘要、08 摘要各 1 处。
  c) 实机用例数：`13 条（RT-00~13）` → 应为 **15 条（RT-00~13 含 RT-04b）**（或按主编号口径统一改写为 "14 个编号 15 条用例"，二选一并全篇统一）；涉及 00 §4、07 摘要、08 摘要各 1 处。
  责任：milestone-planner（07/08 正文与源头口径）、spec-writer（00 汇总沿用）。
- **P2【行号引用错误，1 组 3 处】**（G1）：`set_rss_table` 引 `ff_dpdk_if.c:801/:1169-1174` → 应为 **:832（函数定义）/ :850（rte_eth_dev_rss_reta_update 调用）/ :1218（init_port_start 内既有调用点）**；涉及 06 §3.3（S3-M1 机制描述）、06 §5.1 所有权表 L2 行、07 C-NR-302 锚点。函数名正确且全局唯一，机制结论不受影响，但 C-NR-302 的实现锚点必须修正。责任：solution-designer（06 两处）、milestone-planner（07 一处）。

### 建议（不阻塞）

- **P3【引文拼写规范化未注明】**（G1）：VPP issue #3547 原始标题拼写为 "jemter"（GitHub 原文如此），01 §4.3 引作 "jmeter"。建议按「引原文逐字」原则改为 "jemter" 或加注「原文拼写如此」。
- **P4【work/ 源头同源数字】**：P1 的三个数字在 work/milestones-testing.md 中同样失实（41/6/13）。work/ 为中间产物按规约不强制修复，但若保留作追溯依据，建议在修复 P1 时于 07/08 文头加一句「规模计数以本篇修正后数字为准」即可，不必回改 work/。

## 8. 门禁判定

| 审核项 | 结论 | 说明 |
|---|---|---|
| G1 证据链抽查 | **PASS（附 P2/P3）** | 行号 ~45 处对 44 处；commit 17/17；issue/PR 6/6；URL 引文 6/6 逐字命中。唯 set_rss_table 一组行号错误（P2）+ 一处拼写规范化（P3） |
| G2 IP 合规 | **PASS** | 内网段 0 命中；仅 127.0.0.1 合规使用；占位符规范 |
| G3 一致性 | **FAIL（P1）** | 3 组规模数字与正文清单不符；其余（基线/分档/M 映射/RV/DR/编号/交叉链接/其余规模数字/未坐实计数）全量核对一致 |
| G4 完整性 | **PASS** | 文头 9/9、操作清单 5/5、未坐实与单来源标注无丢失（work 对照抽样一致） |
| G5 规约符合性 | **PASS** | untracked 无 staged；git 写零执行；work/ 未被改动（mtime + 内容双证） |
| G6 总体 | **打回（定向轻量修复，bounce 1）** | 证据链与工程结论质量高（抽查近 80 项仅上述问题），但规模数字失实会误导人工审计的工作量与测试规模认知、行号错误影响编码锚点，须修复后复核；无需全文重审 |

**总体判定：打回（bounce 计数 1）。** 修复范围小且机械（约 10 处文字改动，全部集中在 00/06/07/08 四篇），不涉及任何技术结论、机制描述、证据真伪的改动。修复后由审核员 R 仅对改动点做快速复核（diff 级），无需重走全量审核。

## 9. 打回记录

| 项 | 内容 |
|---|---|
| 轮次 | bounce 1（首次打回，计数从 0 开始后的第 1 轮） |
| 修复责任人 | P1：milestone-planner（07 §1 表 M1 行/摘要/§3、08 摘要）+ spec-writer（00 §2.1/§3.3/§4）；P2：solution-designer（06 §3.3、§5.1）+ milestone-planner（07 C-NR-302）；P3：建议 spec-writer（01 §4.3）随手处理，可豁免 |
| 修复内容 | P1：41→35（并统一 C-NR-100~604 写法与 M1=7 项口径）；6→5；13→15（或统一主编号口径）；P2：:801/:1169-1174 → :832/:850/:1218（三处）；P3：#3547 标题 "jemter"（原文拼写）或加注 |
| 验收标准 | 修复后 grep 全目录不再出现 `41 个编码`、`6 条.*集成`、`13 条实机`；`801`、`1169-1174` 不再作为 set_rss_table 锚点出现；修复仅限上述点位，不得顺带改动其他内容（保持 diff 最小） |
| 复核方式 | 审核员 R 对 00/06/07/08 的 diff 定向复核（预计 10 分钟），通过即出具备忘「门禁通过（bounce 1 后）」 |

---

**审核声明**：本报告全部结论基于实际执行的只读核查（代码实读、git/gh api 只读、URL 抓取、work/ 对照），无推测性判定；抽查未覆盖到的证据不等于已验证，人工审计时仍可按 00 §5 未坐实总览表重点关注证据强度。本审核未修改 00~08 与 work/ 任何文件，未执行任何 git 写操作。

---

## 10. 复核记录（bounce 1 闭环，v1.1 追加）

### 10.1 闭环与分离声明

| 项 | 内容 |
|---|---|
| 复核时间 | 2026-08-18（修复编辑 mtime 15:02:50~15:04:58 之后随即执行） |
| 修复者 | spec-writer（16 处编辑；其曾被误判超时、Leader 一度 spawn doc-fixer 接管，但 doc-fixer 零写操作回报 NONE，最终修复全部由 spec-writer 完成） |
| 复核者 | 审核员 R（gate-reviewer）——与修复者 spec-writer 不同实例，写审分离不破；初审与复核同为 R，按 §9 预定的 diff 级定向复核方式执行，未重走全量审核 |
| 复核方式 | 负向/正向 grep（验收标准逐条）+ mtime 核查 + 16 处修改点位上下文实读 |

### 10.2 逐项复核结果（对照 §9 验收标准）

| # | 验收项 | 结果 | 证据 |
|---|---|---|---|
| 1 | 「41 个编码」类残留 | **通过** | grep `41 个\|41 编码` 于 00-08 全目录 0 命中（exit 1）；新值「35 个编码改动点（C-NR-100~604）」在 00 §2.1 表（L34）/§3.3（L60）/§4 导读（L70）、07 标题（L6）/摘要（L18）/§3（L305）全部在位 |
| 2 | 「6 条+集成」组合残留 | **通过** | 全部 `6 条` 命中逐条判别：均为合法保留（6 条性能基线 PT-NR-01~06 属正确计数、02 篇「#1036 条目」子串、08 §1.5「16 条全绿」）；集成用例处 00/07/08 已统一为「5 条 cmocka/真 EAL 集成用例（IT-NR-A01~05）」 |
| 3 | 「13 条实机」残留 | **通过** | grep 0 命中；00 §4/07 摘要/08 摘要统一为「15 行实机用例（RT-00~13，含 RT-04b）」，口径与 08 §2.3 B 组表 15 行一致 |
| 4 | `:801` / `1169-1174` 锚点残留 | **通过** | grep `:801\|1169` 于 00-08 全目录 0 命中；三处改为 06 L148（:832 定义/:850 rss_reta_update/:1218 既有调用点）、06 L233（L2 行 :832/:850/:1218）、07 L213（C-NR-302）——与初审时核实的实际代码（ff_dpdk_if.c L832/L850/L1218）完全一致 |
| 5 | P1 附带口径 | **通过** | 07 §1 总览表 M1 行已改「7（C-NR-100~106）」，与 M1 详述表（C-NR-100~106 共 7 项）一致；07 标题范围写法同步改「C-NR-100~604」（即修复清单所称「文头同源遗漏」） |
| 6 | P3 加注 | **通过** | 01 §4.3（L184）标题已改用原文「jemter」并加注「标题为报告者原文逐字引用，"jemter" 系其原始拼写，未作纠正」 |
| 7 | P4 口径声明 | **通过** | 07 L20 与 08 L20 各加【数字口径说明】blockquote：声明 work/ 同源旧数字系中间产物原文不回改、冲突以本篇为准（07 注明 41/6/13，08 注明 6/13，各覆盖本篇同源数字） |
| 8 | 最小 diff | **通过** | mtime：02（13:27:46）/03（13:29:23）/04（13:30:32）/05（13:31:36）/09（13:49:57）保持原值未被触碰；改动仅 00/01/06/07/08（15:02:50~15:04:58）；16 处编辑点位（P1×10/P2×3/P3×1/P4×2）全部落在 §9 打回范围内，无越界改动 |
| 9 | 一致性回归 | **通过** | 修正后数字（编码 35 / M1=7 / 集成 5 / 实机 15 行）与正文实际清单重新比对一致，00/07/08 跨篇口径统一 |

### 10.3 最终门禁判定

**门禁通过（bounce 1 后）。**

- 闭环路径：初审（v1.0，G1~G6 全量，打回：阻塞 2 + 建议 2）→ bounce 1 修复（spec-writer 16 处编辑，doc-fixer 零写操作 NONE）→ 本节 diff 级复核（9/9 验收项通过）。
- 00~08 文档集（修复后）证据链、一致性、完整性、规约符合性全部达标，**可交付人工审计**；初审发现的 4 个问题（P1~P4）全部闭环，其中 P1/P2 阻塞项已消除、P3 按建议落地、P4 按建议以口径声明方式处理。
- 后续如进入实现阶段，M0 报告（work/m0-poc-report.md）产出后按 08 §尾注要求回填 A-NR-14 数值与 DR 定案引用，不属本门禁范围。

## 11. U1 坐实增补记录（v1.2 追加，2026-08-18）

### 11.1 事实修正

原文档集中「`IP_BIND_ADDRESS_NO_PORT` 在 FreeBSD 15.0 是否已支持」标注为**未坐实**（03 §8-U1、06 §3.1 S1 风险项 4、00 §5 B 类清单）。经用户指认 commit 并全量核实后**坐实为：F-Stack 15.0 栈已支持**（系 F-Stack 本地扩展，非上游合入）。

### 11.2 坐实证据链（全部只读 git 核实，均 `git merge-base --is-ancestor` 确认 IN-HEAD）

| commit | 日期 | 作者 | 内容 |
|---|---|---|---|
| cb9b4d462 | 2025-07-25 | fengbojiang | 原始实现：`freebsd/netinet/in_pcb.c` bind(laddr,0) 不分配端口、connect 时 `in_pcb_lport(..., INPLOOKUP_WILDCARD)` 按 RSS 一致性选源端口（回包回原 worker） |
| ff9e3c449 | 2026-06-22 | fengbojiang | 将上述实现 port 到 FreeBSD 15.0 树，`#ifdef FSTACK` 块在当前 HEAD 在位 |
| a2537e143 | 2026-07-16 | fengbojiang | `lib/ff_syscall_wrapper.c:100/979/1041-1046`：ff_setsockopt/ff_getsockopt 拦截 `LINUX_IP_BIND_ADDRESS_NO_PORT(24)` 为成功 no-op，处理与 FreeBSD `IP_BINDANY(24)` 数值冲突（否则 v4 静默误设 INP_BINDANY、v6 EINVAL） |

配套 commit：35aa95846（R-E spec）、23e545932（impl/verification 报告）、458e91288/699c763b4（知识图谱/英文文档），`git log --all --grep=IP_BIND_ADDRESS_NO_PORT` 共 8 个。

对照事实（防误导，已写入 03/06）：上游原生 FreeBSD 15.0（freebsd-src-releng-15.0）`sys/netinet/` 无此选项，Linux 兼容层 `sys/compat/linux/linux_socket.c:245-249` 显式报 unsupported——该支持为 F-Stack 本地扩展，升级 freebsd 树时须保留补丁。

### 11.3 修改清单（最小 diff，仅文档）

| 文件 | 修改 |
|---|---|
| 03 §6.2 对照表 U1 行、§8 U1 行、§7 结论 2(b)、末尾证据强度声明计数（7→6，注明 U1 已坐实） | 4 处 |
| 06 §3.1 S1 风险项 4 | 1 处（改为已坐实已支持，风险消除） |
| 00 §5 B 类清单 | 1 处（移除 U1，计数 7→6） |
| work/evidence-legacy.md §8 U1 行 | 追加坐实注记行（原文保留） |

历史事实叙述（F-Stack 1.20 时代 freebsd 11/13 不支持需新开发）保留不动。

### 11.4 考证流程教训（如实记录）

初版考证的两个失误：(1) 未按 f-stack-info-search 技能第二部分执行 `git log --grep=IP_BIND_ADDRESS_NO_PORT`（执行即命中 8 个 commit）；(2) 全树标识符 grep 误报「0 命中」后未交叉验证——该实现分布在 `#ifdef FSTACK` 行为改动（netinet 无裸选项名）与 `lib/ff_syscall_wrapper.c`（宏名 LINUX_IP_BIND_ADDRESS_NO_PORT），单一关键词检索存在盲区。

### 11.5 门禁判定声明

本次为事实性修正（未坐实→已坐实），不改变 00~08 文档集的方案结构、S1~S4 评估结论（S1 风险项 4 消除反而强化「S1 思想可承接」的原判断）与 M0~M7 里程碑；§10 门禁通过判定**维持有效**。修改由主 agent 执行、呈报用户（人工审计者）闭环确认——本次修正规模属规约 12 小任务直执范围，未重组团队，特此声明。

## 12. S3 流表窗口化修订增补记录（v1.3 追加，2026-08-18）

### 12.1 修订内容

依据用户 4 条原则，对 S3 方案的「流表/连接归属判断」机制做定向修订：

1. **流表仅 reload 窗口生效**：稳态所有数据包不经过流表（回调不注册，零每包开销）；新 worker 初始化完成（READY）后流表自动生效（回调随 READY 注册）。
2. **只记新流、miss 一律转老 worker**：流表=本栈连接表实时查询（ff_conn_owner_query），只记录本代际新建流（新 SYN 匹配本栈 listen → accept 隐式入表）；表项 miss（旧连接包因 reta 重哈希落入新队列）一律经 dispatch_ring 转 G_old。
3. **排空感知、关表回稳态**：G_old 排空（连接数=0 + 全退 + DRAIN_DONE）→ G_new 感知后注销回调/关闭流表，进入稳态成为下一轮「老 worker」，防止性能退化。
4. **reload 防重入**：上一批 G_old 排空前，master 拦截（拒绝并记日志）新的 reload 请求；不支持老 worker 排空前的快速连续 reload（防重入随排空确认解除）。

### 12.2 修改清单（最小 diff，仅文档；已落定为 [06] 第 2 节「目标语义 6」）

| 文件 | 修改点 |
|---|---|
| 06-solution-design.md | §2 新增语义 6（四原则成文）；§3.3 S3-M1 兜底两条改写+防重入新增；§5.1 L4 行补窗口语义；§5.2 时序 T0（防重入）/T2（READY 自动注册）/T3（命中/miss 判定语义）/T5（排空确认+关表+防重入解除）改写；§5.4-1 ff_conn_owner_query 窗口语义、§5.4-2 消息族补 DRAIN_DONE/REJECT；§6.1 RV5 改为窗口内度量+关表验证；§6.2 DR2 倾向补强（快照形态同样须窗口化）、DR7 判据修订（原稳态损耗判据失效，改为 reload 窗口开销判据）。共 10 处 |
| 07-milestones.md | C-NR-202（消息族补 DRAIN_DONE/REJECT）、C-NR-204（T1~T5 防重入拒绝）、C-NR-303（READY 后自动注册+miss 一律转发）、C-NR-402（DRAIN_DONE 上报）、C-NR-403（关表通知+防重入解除）、§0.3 DR2 行（两形态均须窗口化）、M7 触发判据修订。共 7 处 |
| 08-testing.md | §1.2 诚实标注补窗口语义覆盖说明、IT-NR-A02 判定语义改写、RT-02 判据补「排空后关表回稳态验证」（里程碑归属 M3→M3/M4）、RT-10 判据补「抢先 HUP 被拒」注入。共 4 处 |
| 00-overview.md | §3.3 落地路径摘要同步（M3/M4 描述补流表窗口化）。共 1 处 |

### 12.3 一致性与门禁声明

- 4 条原则已收敛为 [06] §2「目标语义定义 6」，全文档集统一引用该锚点（「第 2 节语义 6」）；原「非本栈连接转发」「实时查询 vs 快照」等表述与新语义兼容（实时查询形态即流表的实现载体），无残留矛盾。
- RV5/DR7 的度量与判据随窗口化调整：稳态零开销由设计属性变为可验证判据（RT-02 关表后回调计数停止增长 + 稳态 pps 基线一致）。
- 修订属方案语义细化（不改变 S1~S4 分档、M0~M7 结构、35 个编码点数量与编号、测试用例计数），§10 门禁通过判定**维持有效**；RT-02 里程碑归属 M3→M3/M4（关表验证落在 M4 的 C-NR-403），已在 08 如实标注。由主 agent 执行、呈报用户闭环确认，规约 12 小任务直执范围。
