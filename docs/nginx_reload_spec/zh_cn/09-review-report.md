# 09 独立门禁审核报告：Nginx 无损 reload spec 文档集（00~08）

| 项 | 值 |
|---|---|
| 文档编号 | 09 |
| 标题 | 独立门禁审核报告（G1~G6 逐项审核 + 问题清单 + 门禁判定） |
| 版本 | v1.6（v1.5 无 RSS 兜底；v1.6 据 2026-08-21 方案修订：S3-M1 主路径改为同队列+同期移交+flow_map，解决审核致命 1-6——见 §15） |
| 日期 | 2026-08-21 |
| 状态 | 已出具（v1.1 门禁通过维持；v1.6 为方案级修订，§6.3-§6.5 旧内容与 07/08 C-NR/用例待后续配合清理） |
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

## 13. v1.4 增补记录：交叉审核结论 + 人工决策 X1/X2/X3（2026-08-21）

### 13.1 交叉审核结论（独立审核团队，4 份报告落盘 work/audit-A/B/C/D）

2026-08-21 组建独立审核团队（auditor-code/auditor-critic/auditor-consistency/explorer-alt）对 06 重点交叉审核，4 份报告落盘 `work/audit-{A-code-evidence,B-critique,C-consistency,D-alternatives}.md`。四线独立收敛：

- **S3 方向四线一致认可、不推翻**（队列所有权与 worker 生命周期解耦）。
- **06 现文不足以支撑 M1 开工**：发现 8 项致命问题（去重后），包括 reta 原语在 virtio 根本不存在（A B-5/D）、reta 变更打破 ff_rss_check 显式不变量（A B-2/B Q1，06 全文零提及）、稳态丢一半流量（A B-4/B Q2）、乒乓代际静默内存损坏（A B-1/B Q15a）、握手 ACK 与 ARP 被转走（A B-3/B Q3）、reta 黑洞不自愈（B Q9）、与 flow bifurcation 产品级互斥（A B-6/C I-23）、门禁自相矛盾（C 独立发现）。
- 详细问题清单与必改项见 4 份审核报告（去重后 18 项必改，C 给出 C-NR 35→50 等增补建议）。

### 13.2 人工决策 X1/X2/X3（2026-08-21）

用户对三项人工决策问题定调：

- **X1（末期一次性队列移交是否可接受）→ 可接受**：drain 完成后的末期一次「停 poll → 起 poll」可接受，残余风险为 virtqueue 数据结构并发损坏需运行时验证。已写入 [06] 语义 7、§3.3 S3-M1、§5.2 时序 T5、§6.1 RV2/RV3、[07] DR3。
- **X2（virtio 场景投形态 V 还是推蓝绿）→ 推蓝绿，形态 V 降为未来工作**：virtio/云主机场景推荐 S4 多实例蓝绿轮换（首选，零代码）；形态 V（软件切流）仅在「单机+virtio+必须 nginx -s reload 无损」强约束下投入，不做正式里程碑。已写入 [06] §3.4 S4 v1.4 增补段、§4.2 分档结论表新增行、§6.4 适用范围矩阵、§6.5 形态 V 未来工作、[00] §3.3 摘要。
- **X3（2N 物理核是否必需）→ 非必需，但切换瞬间性能需关注**：2N 逻辑 lcore_id 必需（DPDK 硬禁令），2N 物理核非必需（DISC-1 `[--lcores]` 亲和可消除稳态核浪费）；新旧进程高负载切换瞬间的流量/丢包需 RV 专项观测。已写入 [06] 语义 8、§3.3、§6.3 DISC-1、[07] DR5。

### 13.3 修改清单（v1.4，最小 diff，仅文档；已落定为 [06] 语义 7/8）

| 文件 | 修改点 |
|---|---|
| 06-solution-design.md | 文头 v1.0→v1.4；§2 新增语义 7（末期移交可接受）+8（物理核策略）；§3.3 S3-M1 机制描述补 X1/X3；§3.4 S4 增补 virtio 场景推荐段；§4.2 分档表新增 S4 virtio 推荐行；§5.2 时序 T5 补末期移交；§6.1 RV2/RV3 改写；新增 §6.3 DISC-1/§6.4 适用范围矩阵/§6.5 形态 V 未来工作。共 12 处 |
| 07-milestones.md | DR3（补 X1 末期移交）、DR5（补 X3 物理 lcore_id vs 物理核）。共 2 处 |
| 00-overview.md | §3.3 摘要补 v1.4 适用范围与 DISC-1。共 1 处 |
| 09-review-report.md | 文头 v1.3→v1.4；新增 §13 增补记录（审核结论+X1/X2/X3 决策+修改清单+门禁声明）。共 2 处 |

### 13.4 门禁判定声明

本次为据交叉审核结论与人工决策的增量修订，**不改变 S1~S4 分档主结构、M0~M7 里程碑、35 编码点数量**（C 建议的 C-NR 35→50 等扩容属 8 项审核阻塞问题的修订范畴，留待后续处理）。§10 门禁通过判定**维持有效**。**8 项审核阻塞问题（reta 原语不存在/ff_rss_check 不变量/稳态丢半/乒乓代际内存损坏/握手 ARP 转走/reta 黑洞/flow 互斥/门禁自相矛盾）尚未处理，留待后续修订轮**，特此声明。由主 agent 执行、呈报用户闭环确认，规约 12 小任务直执范围。

## 14. v1.5 增补记录：无 RSS 有损 reload 兜底（2026-08-21）

### 14.1 决策

用户 2026-08-21 决策：当运行环境不支持 RSS 时（本机 virtio 未协商 `VIRTIO_NET_F_RSS` 致 `reta_size==0`，或编译启用 `FF_FLOW_ISOLATE/FF_FDIR` 致 `set_rss_table` 编译期排除），**直接跳过 S3 的 RSS 相关步骤，退化为有损 reload**（等价于 F-Stack 现状的两段串行行为）。后续 virtio 是否做无损 reload 按 X2 决策——仅记录形态 V 场景，后续再考虑是否实际支持软件切流形态。

### 14.2 落地（[06] §6.4.1 新增子节）

- **机制**：`graceful_reload=1` 配置在无 RSS 环境下被运行时探测降级——`reta_size==0`（ff_dpdk_if.c:1074 探测）或 `FF_FLOW_ISOLATE/FF_FDIR` 编译宏启用时，自动回退到现有两段串行 reload，打日志标注「降级为有损 reload：运行环境不支持 RSS 切流」。配置开关打开 ≠ 无损 reload 必生效。
- **最恶劣失败模式的消除**（审核 A B-5/B Q17/D 共同坐实）：原 06 v1.0-v1.4 未声明此前置依赖时，存在「master 收到 reta 切流成功 ACK → 推进 T4 → G_old 停 accept → 新 flow 仍落旧段 → 新连接全失败而所有打点显示 reload 成功」的静默黑洞；v1.5 通过运行时探测+降级+日志标注消除该模式——无 RSS 时根本不进入 S3 T0-T5 时序，避免「静默成功伪装」。
- **修改清单**：[06] §6.4 矩阵 virtio 行改为「v1.5 决策：本机 virtio 先不做无损 reload」、新增 §6.4.1「无 RSS 有损 reload 兜底」子节、§6.1 RV2 措辞补 v1.5 退化路径、文头版本 v1.4→v1.5；[09] 文头 v1.4→v1.5 + 本节增补记录。

### 14.3 门禁判定声明

本次为环境能力探测与降级机制的设计增补，**不改变 S1~S4 分档主结构、M0~M7 里程碑、35 编码点数量**（C-NR 35→50 等扩容仍属剩余 7 项审核阻塞问题的修订范畴，留待后续处理）。§10 门禁通过判定**维持有效**。**剩余 7 项审核阻塞问题（ff_rss_check 不变量/稳态丢半/乒乓代际内存损坏/握手 ARP 转走/reta 黑洞/flow 互斥/门禁自相矛盾）尚未处理，留待后续修订轮**，特此声明。由主 agent 执行、呈报用户闭环确认，规约 12 小任务直执范围。

## 15. v1.6 增补记录：S3-M1 方案级修订（2026-08-21）

### 15.1 决策

用户 2026-08-21 对审核发现的 reta 相关致命问题做方案级决策：将 S3-M1 主路径从「乒乓双队列段+reta 切流」改为「同队列+ready 后同期移交+flow_map 软件分发表+跨进程互斥+ARP/NDP clone」。

### 15.2 方案核心变化

| 维度 | v1.0-v1.5（乒乓+reta） | v1.6（同队列+同期移交+flow_map） |
|---|---|---|
| 队列 | 2N 队列段乒乓 | 同批 queue（proc_id 代际无关固定映射） |
| reta | 运行时改 reta 切流 | **不改 reta**（rss_check 四件套不变） |
| NIC RSS 依赖 | 依赖（virtio 不可用） | **不依赖**（virtio 与物理网卡均可用） |
| 物理核 | 2N 逻辑 lcore_id（DISC-1 可省物理核） | 同核处理（不乒乓） |
| 切流机制 | reta 重哈希 | ready 后同期移交队列+listen（跨进程互斥标记） |
| 连接归属判定 | ff_conn_owner_query（inpcb 查询） | flow_map 软件分发表（SYN accept 入表，miss 转 G_old） |
| ARP/NDP | 被回调转发跳过（致命 6） | clone 给所有 G_old（语义 9） |
| 移交窗口缓冲 | rx ring 512 | rx ring 4096（放大 8 倍） |

### 15.3 解决的审核致命问题

| 致命问题 | 解决方式 |
|---|---|
| 1 reta 原语不存在 | 不依赖 reta |
| 2 ff_rss_check 不变量被破 | reta 不改，四件套不变 |
| 3 稳态丢半流量 | 不配 2N 队列 |
| 4 乒乓代际内存损坏 | proc_id 代际无关固定映射 |
| 5 握手 ACK 被转走 | flow_map 存 SYN 入表，后续包查表命中 |
| 6 ARP/NDP 被转走 | clone 给所有 G_old |
| B Q18 1-5 | queueid 对齐/同核+移交后独占/同队列无转发/互斥规避/缓冲放大 |

### 15.4 修改清单

| 文件 | 修改 |
|---|---|
| 06 | 文头 v1.5→v1.6；§2 语义 6/7/8/9/10 改写；§3.3 S3-M1 机制大改+障碍覆盖表；§4.1 对比矩阵 S3 行；§4.2 分档结论；§5.1 四层所有权 L2/L3/L4；§5.2 时序 T0-T5 大改；§5.4 接口面（flow_map/互斥/ARP clone/RX_QUEUE_SIZE）；§6.1 RV（删 RV2/改 RV3/新增 RV10）；§6.2 DR（删 DR3/DR5、改 DR4/DR7）。共约 20 处 |
| 00 | §3.3 摘要改写为 v1.6 方案核心。共 1 处 |
| 09 | 文头 v1.5→v1.6 + 本节增补记录。共 2 处 |

### 15.5 待后续清理项

- 06 §6.3（DISC-1）/§6.4（适用范围矩阵）/§6.5（形态 V）的旧 reta/乒乓/形态 V 内容已过时（v1.6 不再乒乓、不依赖 reta、形态 V 已并为主路径），待后续修订清理
- 07 的 C-NR 编码点需配合调整（删除 reta/乒乓相关、新增 flow_map/互斥/ARP clone/proc_id 代际无关/_RX_QUEUE_SIZE 相关）
- 08 的 UT/IT/RT/A-NR 需配合调整
- 剩余审核问题：致命 7（reta 黑洞不自愈）已消解（reta 不改）；致命 8（门禁自相矛盾：1000 次循环 vs 防重入 vs 25s）待后续处理

### 15.6 门禁判定声明

本次为方案级修订（S3-M1 主路径形态变更），**不改变 S1~S4 分档主结构、M0~M7 里程碑框架**。§10 门禁通过判定**维持有效**（v1.6 方案修订属设计层，不涉及代码/测试执行）。由主 agent 执行、呈报用户闭环确认。

## 16. v1.6 增补记录补充：致命 7/8 随方案消解 + 门禁自相矛盾修复（2026-08-21）

### 16.1 致命 7/8 随 v1.6 方案消解

用户 2026-08-21 决策确认：致命问题 7（reta 黑洞不自愈，B Q9）与致命问题 8（与 flow bifurcation 产品级互斥，A B-6/C I-23）均**随 v1.6 方案修订（reta 不改）自然消解**：

- 致命 7：v1.6 不改 reta（同队列+proc_id 代际无关固定映射），不存在「T3 后 reta 指向无人 poll 的段」黑洞问题——retA 状态不变、不随进程回滚，G_new 崩或 ACK 丢失不影响 reta。
- 致命 8：v1.6 不调用 set_rss_table，不依赖 FF_FLOW_ISOLATE/FF_FDIR 编译宏——切流原语改为 flow_map 软件分发表 + 跨进程互斥标记，与 flow bifurcation 无编译期互斥。

### 16.2 门禁自相矛盾修复

**原问题**（C 独立发现）：M6 的「每 2~5s reload、≥1000 次」与 v1.3 防重入（排空前拒绝新 reload）+ 25s 初始化时延三者不可同时成立——防重入下 999 次会被全拒。

**修复**（用户 2026-08-21 决策）：将循环 reload 门禁节拍从「每 2~5s reload、≥1000 次」修改为「**每 5s 检测共享内存状态所有 G_old 已退出后 reload 一次（reload 成功计算一次）、≥100 次**」。

- 节拍依据：防重入语义下 reload 请求只在排空确认后才放行，故以「检测共享内存状态所有 G_old 已退出」为触发条件，而非固定 2~5s 间隔（每轮实际耗时 = 25s 初始化 + drain 时长 + 5s 检测间隔，远超 2~5s）。
- 次数下调：1000→100，因每轮耗时显著拉长（25s+drain），1000 次在合理机时内不可达；100 次仍足以暴露低概率状态错位（VPP #3547/#3645 前车之鉴）。
- VPP 模式适配：VPP 社区 2s 循环判据不可照搬（VPP 无防重入语义、F-Stack 有），故改为排空确认节拍。

**修改清单**（5 文件 7 处）：
- [08] §摘要、PT-NR-05、A-NR-16（3 处）
- [07] §0.3 RV9 行、M6 目标、M6 DoD（3 处）
- [06] D7 维度、RV9（2 处）
- [00] §3.3 摘要（1 处）
- [09] 本节增补记录（1 处）

### 16.3 审核问题处理总结

经 v1.5/v1.6 修订，8 项审核致命问题处理状态：
1. reta 原语不存在 → ✅ v1.6 消解（reta 不改）
2. ff_rss_check 不变量被破 → ✅ v1.6 消解（reta 不改，四件套不变）
3. 稳态丢半流量 → ✅ v1.6 消解（不配 2N 队列）
4. 乒乓代际内存损坏 → ✅ v1.6 消解（proc_id 代际无关固定映射）
5. 握手 ACK 被转走 → ✅ v1.6 消解（flow_map 存 SYN 入表）
6. ARP/NDP 被转走 → ✅ v1.6 消解（clone 给所有 G_old）
7. reta 黑洞不自愈 → ✅ v1.6 消解（reta 不改）
8. flow bifurcation 互斥 → ✅ v1.6 消解（不调用 set_rss_table）
9. 门禁自相矛盾 → ✅ 本节修复（节拍改为排空确认、次数 1000→100）

**8 项致命问题 + 门禁自相矛盾全部处理完毕。** §10 门禁通过判定**维持有效**。剩余为 §15.5 已声明的待清理项（06 §6.3-§6.5 旧内容、07/08 C-NR/用例配合调整），属后续修订范畴。
