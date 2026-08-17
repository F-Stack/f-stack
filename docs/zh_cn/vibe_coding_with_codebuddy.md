F-Stack 使用 CodeBuddy 开发工作流：三个自建 Skill + harness 多 agent 门禁体系，2026 年 13 个大功能全由 AI 辅助完成的实践

1. 本功能主要作用和特点

直接说目的：F-Stack 项目从 2026 年初开始用 CodeBuddy 做 AI 辅助开发，到今天已经把「怎么让 AI 在这个大 C 语言项目里干活干得靠谱」沉淀成了一套可复用的工作流——三个自建 Skill（f-stack-dev-rule / f-stack-info-search / f-stack-issue-process）+ harness 工程化多 agent 流程 + 全链路门禁体系。这篇文章把这套工作流讲清楚：它由哪些部分组成、每部分解决什么问题、2026 年实战效果如何。

先说结论，2026 年至今（8 月中旬），F-Stack 通过这套工作流由 AI 辅助完成的大功能清单（数据来自项目 iwiki 工作清单）：

| 功能 | 完成时间 | 耗时 |
|---|---|---|
| LD_PRELOAD 信号量 → 无锁 ring IPC | 2026.05.25 | 10 天 |
| FreeBSD 13.0 → 15.0 协议栈升级 | 2026.06.09 | 10 天 |
| DPDK 升级到 24.11（dev 分支） | 2026.06.10 | 1 天 |
| 单元测试框架（Unity/CMocka） | 2026.06.11 | 2 天 |
| 接收零拷贝 ff_zc_mbuf_read | 2026.06.11 | 1 天 |
| 发送零拷贝原生化（去掉 MAGIC 魔改） | 2026.06.12 | 1 天 |
| lib 库本地 socket 访问 | 2026.06.18 | 4 天 |
| io_uring 对标调研 | 2026.06.18 | 1 天 |
| ff_rss_check 优化（IPv6 + rte_thash） | 2026.07.16 | 15 天 |
| MTU 修改支持（jumbo frame） | 2026.07.22 | 3 天 |
| LRO 支持 + TSO 完善 | 2026.07.23 | 1 天 |
| 多进程 vnet bonding / 单进程多线程多协议栈（native-mt） | 2026.08.05 | 5 天 |
| issue 批量处理 320 → 0 | 2026.08.10 | 持续 |

这些功能的统一分工模式是：**所有代码由 AI 完成，人工只做提示词、spec 文档、plan、纠正方向、结果审核和测试验收**。本文的三个关键词：

- **规约先行**：AI 在 F-Stack 里干活的第一件事不是写代码，是加载 f-stack-dev-rule——13 节强制规约零容忍，把"AI 容易翻车的点"（rm/kill/chmod、增量编译、config.ini 污染、真实 IP 泄漏、注释风格）全部前置成规则
- **skill 分层**：三个 skill 各管一段——dev-rule 管"怎么改"、info-search 管"怎么搜"、issue-process 管"issue 怎么处理"，另有一批通用 skill（spec 驱动、harness 工程、C 语言开发、单测等）可以对应安装，不在本文范围
- **harness 多 agent 门禁**：大任务强制走"调研出中文 spec → 人工审核 → 多 agent 实现 → 门禁审核 → 里程碑提交"的完整链路，写审分离、单步打回上限 3 次

2. 本功能的主要适用场景

2.1 大功能开发（调研 + spec + 实现 + 验收）

F-Stack 里凡是"一个新功能/一次大升级"级别的任务，都走 harness 流程：先多 agent 调研产出中文 spec 文档（放 docs/<FEATURE>_spec/zh_cn/），人工审核通过后另起多 agent 做实现和验收，按里程碑多次提交，验收完成后才翻译英文 spec。2026 年的 freebsd 13→15 升级（47 篇 spec 文档）、native-mt、LRO/TSO 都是这么干的。

2.2 issue 分析与批量处理

f-stack-issue-process skill 定义了 issue 处理三步 SOP（读全文 → 搜资料 → 综合判断），配合五类结论模板。2026 年项目把 issue 从 320 个清理到 0 个，全程半自动化：AI 按 SOP 分析归档、人工确认或修复后回复关闭。

2.3 性能优化攻坚（需要对照实验的）

ring IPC 性能优化、RSS check 优化这类"优化"任务，AI 的价值不在写代码而在执行对照实验纪律：对照组先于优化、数据先于理论、每条假设配套可证伪的物理量。ring IPC 的 v1~v3.7 七轮迭代就是 AI 在规约约束下自我证伪的完整案例。

2.4 不太适合的场景

- 一句话的小改动：直接说需求就行，别套 harness 流程（任务规模判断规约里小任务直接执行）
- 需要物理环境验证且环境不齐的：规约要求"未实际执行不臆测"，环境不满足时 AI 只能如实标注「未坐实」，硬要结论反而有害
- token 额度紧张时期：native-mt 这种"堪比重做一个小 f-stack"的任务消耗巨大（iwiki 原话），适合额度重置后再做

3. 本功能的架构特征

3.1 工作流总图

```
用户需求
   │
   ▼
┌─────────────────────────────────────────────┐
│ 任务规模判断（f-stack-dev-rule 第 12 节）      │
│   小任务 → 直接分析执行                       │
│   大任务 → harness 流程（下）                 │
└────────────────────┬────────────────────────┘
                     ▼
┌─────────────────────────────────────────────┐
│ 大任务 harness 流程                           │
│ 12.1 功能调研：多 agent 出中文 spec + 门禁审核 │
│      （leader + 资料搜索/架构探测/方案设计/    │
│        撰写/审核等子 agent）                  │
│   ↓ 人工审核 spec                             │
│ 12.2 实现与验收：多 agent 编码 + CR + 测试     │
│ 12.3 每个阶段先生成 plan.md 人工审核再执行     │
│ 12.4 按里程碑多次 git 提交                    │
│ 12.5 验收完成后翻译英文 spec                  │
└────────────────────┬────────────────────────┘
                     ▼
┌─────────────────────────────────────────────┐
│ 执行期三 skill 支撑                           │
│ ┌──────────────┐ ┌──────────────┐ ┌────────────────┐ │
│ │dev-rule      │ │info-search   │ │issue-process   │ │
│ │13节强制规约   │ │五部分搜索流程 │ │三步SOP+五类结论 │ │
│ └──────────────┘ └──────────────┘ └────────────────┘ │
└────────────────────┬────────────────────────┘
                     ▼
              门禁体系（写审分离 + bounce≤3 + 测试门禁）
```

3.2 三个自建 Skill 的分工

**f-stack-dev-rule（怎么改）**：F-Stack 工作区一切任务的强制规约合集，13 节零容忍。核心几条：Shell 操作必须走 rm_tmp_file.sh/kill_process.sh/chmod_modify.sh 三个脚本（严禁直接 rm/kill/chmod）；改代码先 make clean 再完整编译（增量编译不作为依据）；config.ini 本地测试值不入库；文档严禁真实 IP 用占位符；commit message 英文 1-3 句；lib 最小注释；多 agent 写审分离/bounce≤3/leader 轮询不提前退出；所有调研类任务必须用 info-search 搜资料；任务规模判断与 harness 流程；代码改动必须过单测和运行时回归测试。

**f-stack-info-search（怎么搜）**：一切提问/分析/调研类任务的资料搜索 SOP，五部分：查三层架构文档与知识图谱（docs/ 下 LAYER1/2/3 + KNOWLEDGE_GRAPH_WIKI）→ 查代码提交记录（本地 git log + DPDK 上游）→ 查关联 issue/PR（先查本地 issue 分析档案再 gh search）→ 查公开资料（DPDK Bugzilla/Patchwork/邮件列表）→ 内外网技术资料（博客/公众号/iWiki，中英双语关键词）。核心纪律是三方证据收敛：内部文档 + 外部资料 + 实际代码，不一致处以实际代码为准。

**f-stack-issue-process（issue 怎么处理）**：三步 SOP——读 issue 全文（含全部评论，不可只看标题）→ 调 info-search 搜资料 → 综合判断。五类结论模板（已修复/有上游 patch 未合入/未修复/有 workaround/非 bug），关键约束是**不可自动操作 issue**：分析完必须人工确认后才能评论关闭，回复用英文只讲核心结论。**每次处理后同步更新中英文 issue 分析档案（f-stack-issue-ana.md，可以不断增加新的知识点供后续的issue分析和问题调研使用）**。

3.3 门禁体系（AI 干活的刹车）

```
写代码/文档 ──► 独立 agent 审核 ──► PASS ──► 下一里程碑
                    │ FAIL
                    ▼
               打回修正（bounce 计数）
                    │
               bounce > 3 → 停止任务转人工决策
```

- **写审分离铁律**：写代码/文档与审核必须不同 agent，leader 严禁自写自审；纯调研/探测/汇总等单一角色可由 leader 兼任
- **leader 轮询**：子 agent 全部完成前 leader 严禁提前退出；禁止无超时死等，旁路探测（读落盘文件、git 状态）优先于消息探测，否则CodeBuddy等Agent经常出现子进程因为各种原因异常退出导致的整个任务中断，需要人工继续任务的情况。
- **异常回退**：子 agent 超时/卡死时 leader 接管或 spawn 新 agent 重做，但不得违反写审分离
- **测试门禁**：代码改动必须完成单测和运行时回归测试，同样受门禁规则限制

4. 具体做了哪些改造、遇到了哪些问题、怎么解决的

后续比较枯燥，不需要深入研究实现过程的可以跳过本节，直接看第 5 节怎么用。

4.1 skill 体系是怎么长出来的（从零散规则到三个 Skill）

这套体系不是一次设计出来的，是被实战问题逼出来的。从最早的裸奔，在 AI 开发过程中逐步踩坑晚上，并在后期整理合并成 f-stack-dev-rule 一个 skill 统一加载（13 节），替代分散的十余条分条规约。info-search 和 issue-process 则是从 issue 处理实战中提炼的：issue 处理要先搜索资料再下结论、搜索有固定的五部分流程、结论有五类模板、档案要中英同步——这些"怎么做对"的经验固化成了 skill。

skill 的落地方式是"库 + 源"双份：安装到 ~/.codebuddy/skills/ 供 CodeBuddy 加载，同时在 docs/zh_cn/skills/ 保留一份源码，规约明确"安装前若 use_skill 不可用，直接读取 docs/zh_cn/skills/ 下对应 SKILL.md 全文作为规约执行"。零容忍条款一旦违反任务直接打回。

【注1】规约里有一条值得单独说：rm_tmp_file.sh/kill_process.sh/chmod_modify.sh 三个脚本不是形式主义——2026 年 6 月 ZC-recv 实测期间就发生过一次误用 rm -rf 的违规（M2 报告里记录并修复）。规约约束的是 AI 最常见的危险动作，脚本带审计日志（chmod 快照到 /tmp/.trash/、审计到 /tmp/.chmod_audit.log），出了问题可回查。

4.2 实战问题一：AI 会"看起来很对，实际全错"

本地 socket 访问功能（2026.06.18，4 天）是典型的反面案例——iwiki 原话："本功能 AI 表现不好，人工打回返工多次才最终完成"。这说明流程里最值钱的是"人工审核"和"打回"这两个环节，而不是 AI 一次写对的能力。对应到规约里就是 bounce≤3 的打回链：门禁失败必须打回上一步修复，同一单步打回超 3 次立即停止转人工决策，不许带病放行。

4.3 实战问题二：AI 会臆测，必须用"实事求是规约"压住

规约第 9 节（实事求是）和第 10 节（资料搜索）专门治这个：所有行动必须实际执行，严禁未执行就猜测给结果；代码/文档/外部数据源交叉验证，不一致处以实际代码为准；无法静态坐实或环境不满足的项，如实标注「未坐实/未执行」。ring IPC 性能分析的 v1~v3.7 七轮迭代是这个规约的最好注脚：v1 的单边代码分析错误、v2 的未验证假设、v3.3 的方案 C 实测劣化 4% 当天回退——每一步错误的证伪都靠实测数据，最终收敛出"ring 无 net win、生产推荐 sem"这个反直觉但正确的结论。

4.4 实战问题三：编译卫生和增量陷阱

AI 写 C 代码最常见的坑是增量编译：FF_ZC_* 开关切换后 make 按时间戳跳过 .o 重编译，导致内核 hook 缺失、http=000 的诡异现象（ZC M2 报告）。规约把"改代码先 make clean、编译验证以 clean build 通过为准、增量编译通过不作为依据"写死，还附了本机两个已知坑的规避（IDE safe-delete hook 拦截 make clean 用 PATH 前缀规避、make -j16 竞态先 make machine_includes）。freebsd 13→15 升级踩的"宏改名丢包裹"坑（UMA_MD_SMALL_ALLOC → UMA_USE_DMAP）和"结构头改动未 clean 重编 ABI 偏斜"坑，也都沉淀成了规约条款。

4.5 实战问题四：token 消耗与任务切分

native-mt（2026.08.05，5 天）的 iwiki 备注很诚实："本功能超级复杂，堪比重做一个小 f-stack，消耗 token 较多"，残留风险如实记录后暂停，等 token 额度重置后继续。这说明 harness 流程还有一层现实约束：任务要按 token 预算切里程碑，做不完的宁可如实留档（残留风险清单），也不要糊弄收尾。issue 批量处理 320→0 则是另一个方向的实践——用 imate（内网版OpenClaw）按 SOP 半自动化处理，穿插在 token 紧张期（GLM-5.2不计算额度）。

【注意】截止目前（2026.08.17）大任务初始的调研、架构文档、任务拆分等任务依然推荐使用 OPUS-5/Codex 等高价模型（**额度消耗非常非常大，需要特别注意**），完成任务拆分后实际的代码编写等小任务或具体任务可以交由 GLM-5.2/DSV4 等模型执行。备注：目前 Deepseek-V4.0-pro-0813 在大仓库大任务的调研分析和架构设计上表现的依然一塌糊涂；GLM-5.3 的效果则尚未实测。

4.6 2026 年各功能沉淀的文档资产

每个大功能都按 harness 流程留下了完整文档：freebsd_13_to_15_upgrade_spec（47 篇）、zc_stack_user_spec（37 篇）、ld_preload_ring_spec、mtu_change_spec、lro_tso_spec、native_mt_spec、rss check 优化 spec 等，加上三层架构文档（LAYER1/2/3）和知识图谱（KNOWLEDGE_GRAPH_WIKI）。这些文档反过来又成了 info-search 的搜索源——文档 → 代码 → 决策形成了闭环。

【注意】新功能更新后应该对应更新架构文档和知识图谱，否则 info-search 的搜索源会失真，后续调研拿到的是过期结论。更新可以靠流程约束（里程碑里带文档更新项），也可以靠自动化——比如 git 操作自动触发知识图谱重建（此前每次提交后 GitNexus 在后台更新知识图谱即是此类机制）。

5. 如何使用、如何配置、使用效果

5.1 Skill 安装与加载

三个 skill 都装在 ~/.codebuddy/skills/（f-stack-dev-rule / f-stack-info-search / f-stack-issue-process），CodeBuddy 会话中用 use_skill 按需加载。F-Stack 工作区的任何任务第一步先加载 f-stack-dev-rule；提问/分析/调研类任务必须加载 f-stack-info-search；issue 分析处理加载 f-stack-issue-process（其搜索环节内部调用 info-search）。

5.2 配套通用 Skill（对应安装，本文不展开）

spec 驱动开发（spec-driven）、harness 工程（harness-engineering）、C 语言开发/单测（c-pro、c-unittest-expert 等）、C 精准外科手术式修改（c-precision-surgery）等通用 skill 与 F-Stack 自有三个 skill 组合使用——自有 skill 管"F-Stack 特有约束"，通用 skill 管"通用工程方法"。

5.3 使用效果（2026 年实测数据）

| 维度 | 数据 |
|---|---|
| AI 辅助完成大功能 | 13 个（累计约 54 个工作日，实际日历时间远短于 AI 并行） |
| 最大单任务 | FreeBSD 13→15 升级（10 天，47 篇 spec，26 个 commit，编译矩阵 5 格全绿） |
| issue 清理 | 320 → 0（2026.08.10 清零） |
| 编译基线 | lib error 0 / warning 51（既有 baseline，新改动零新增 warning） |
| 文档资产 | 7 个功能 spec 目录 + 三层架构文档 + 知识图谱 + 中英双语 issue 档案 |
| 博客文章 | F-Stack 2.0 前瞻系列 8 篇（含中英文版），后续将陆续发出。 |

5.4 对使用者的建议

- 先把规约读一遍再让 AI 动手：dev-rule 的 13 节每条都是实战换来的，AI 违反任何一条任务都会被人工打回
- 大任务别跳过 spec 环节：中文 spec + 人工审核是成本最低的方向纠偏点，本地 socket 功能的返工证明"跳过调研直接写代码"更贵
- 信任门禁不信单次输出：AI 写的东西必须过独立 agent 审核，bounce 是正常流程不是失败
- 让 AI 如实说"不知道"：环境不满足就标「未坐实」，这比硬给结论值钱得多

延伸阅读：

- 开发强制规约：docs/zh_cn/skills/f-stack-dev-rule/SKILL.md
- 资料搜索技能：docs/zh_cn/skills/f-stack-info-search/SKILL.md
- issue 处理 SOP：docs/zh_cn/skills/f-stack-issue-process/SKILL.md
- 三层架构文档：docs/zh_cn/01-LAYER1-ARCHITECTURE.md
- 知识图谱：docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md
- 历史 issue 档案：docs/zh_cn/f-stack-issue-ana.md
- 2026 年各功能 spec：docs/<FEATURE>_spec/（freebsd_13_to_15_upgrade_spec、zc_stack_user_spec、ld_preload_ring_spec、mtu_change_spec、lro_tso_spec、native_mt_spec 等）
