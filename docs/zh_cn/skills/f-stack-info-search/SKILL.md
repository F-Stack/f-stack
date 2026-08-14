---
name: f-stack-info-search
description: F-Stack 资料搜索技能。当需要为 F-Stack/f-stack 仓库的 issue 分析、bug 定位或功能调研搜集证据时使用，包含五部分：查项目架构文档与知识图谱（docs/ 下三层架构文档 LAYER1/2/3 与 KNOWLEDGE_GRAPH_WIKI）、查代码提交记录（本地 git log 搜索修复性提交 + DPDK 上游）、查关联 Issue 和 PR（先查本地 issue 分析档案 docs/f-stack-issue-ana.md 与 docs/zh_cn/f-stack-issue-ana.md，再 gh search issues/prs + DPDK Patchwork）、查公开资料（DPDK Bugzilla/Patchwork/inbox.dpdk.org/外网搜索）、常规分析调研任务的内外网资料搜索（技术博客/公众号/技术社区/内网知识库/iWiki，中英双语关键词构造与三方证据收敛）。由 f-stack-issue-process 技能的搜索环节调用，也可独立使用。触发词：查提交记录、搜索资料、查关联 issue、查公开资料、git log 搜索、gh search、架构文档、知识图谱、调研资料。
---

# F-Stack 资料搜索技能

为 F-Stack issue 分析、bug 定位、功能调研搜集证据。可被 f-stack-issue-process 技能的搜索环节调用，也可独立使用。

## 环境准备

- GitHub Token 已配置（GH_TOKEN 环境变量）
- F-Stack 官方仓库已 clone 至 /data/workspace/f-stack
- gh CLI 已安装

## 第一部分：查项目架构文档与知识图谱

搜索代码前，先查阅 f-stack 已有的三层架构文档与知识图谱（`/data/workspace/f-stack/docs/`），快速定位问题涉及的层次、模块、接口与函数，缩小后续检索范围。

三层架构文档（中英双语，内容一致）：

- Layer1 系统总览：`01-LAYER1-ARCHITECTURE.md`（中）/ `F-Stack_Architecture_Layer1_System_Overview.md`（英）
- Layer2 接口规范：`02-LAYER2-INTERFACES.md`（中）/ `F-Stack_Architecture_Layer2_Interface_Specification.md`（英）
- Layer3 函数索引：`03-LAYER3-FUNCTIONS.md`（中）/ `F-Stack_Architecture_Layer3_Function_Index.md`（英）

知识图谱：

- `KNOWLEDGE_GRAPH_WIKI.md`：知识图谱 Wiki
- `F-Stack_Knowledge_Base_Summary.md`：知识库总览

用法：

- 按关键词/模块名在架构文档中定位涉及的层次与组件（如协议栈层、DPDK 抽象层、接口层）
- 结合知识图谱定位相关代码路径与函数，据此缩小 git log / gh search 的检索范围
- 中英文内容一致，查阅任一语言即可

## 第二部分：查代码提交记录

在本地 F-Stack 仓库中搜索相关修复。

```bash
cd /data/workspace/f-stack

# 按关键词搜索 commit message
git log --all --oneline --grep='<关键词>'

# 按文件路径搜索变更历史
git log --all --oneline -- <文件路径>

# 搜索修复性提交
git log --all --oneline --grep='fix' --grep='<关键词>' --all-match

# 查看某个 commit 的详细变更
git show <commit-hash>
```

同时检查 f-stack 对 DPDK 的自行修改（本地 dpdk/ 目录是 f-stack 仓库内的普通目录，**没有 DPDK 上游提交历史**，git log 只能查到 f-stack 自己的少量修改）：

```bash
# f-stack 对 dpdk/ 目录的自行修改（非上游提交）
git log --all --oneline -- dpdk/
git show <commit-hash>
```

检查 DPDK 上游修复须走外部渠道（本地无上游历史）：

```bash
# DPDK 官方仓库搜索修复性 commit
gh search commits '<关键词>' -R DPDK/dpdk --limit 20
```

或使用 DPDK Patchwork API（见第三部分）、DPDK Bugzilla/邮件列表（见第四部分）。

关注点：

- issue 提及版本之后 DPDK 上游是否有修复性提交（Fixes/fix/patch）
- 修复是否已 backport 到当前使用的版本（F-Stack 当前用 DPDK 24.11.6）
- f-stack 的 dpdk/ 是否有对应本地 patch 或遗漏未 port

## 第三部分：查关联 Issue 和 PR

先查本地 issue 分析档案（最高优先级，避免重复分析）：

- 中文：docs/zh_cn/f-stack-issue-ana.md
- 英文：docs/f-stack-issue-ana.md

查找同类 issue 时，先检索这两份档案中是否已有分析记录（issue 编号、关键词、错误现象），有则直接引用已有结论，无则分析后补充。中英文档案内容保持同步。

```bash
export GH_TOKEN='<token>'

# 搜索相关 issue（open + closed）
gh search issues '<关键词>' -R F-Stack/f-stack --limit 20

# 搜索相关 PR（尤其是已合并的）
gh search prs '<关键词>' -R F-Stack/f-stack --limit 20

# 查看特定 PR 详情
gh pr view <NUMBER> -R F-Stack/f-stack

# 查看 PR 的 diff
gh pr diff <NUMBER> -R F-Stack/f-stack
```

DPDK 上游 Patchwork（如需追踪上游 patch）：

- API: `https://patches.dpdk.org/api/patches/?q=<关键词>`
- 使用 WebFetch 工具获取

## 第四部分：查公开资料

按优先级搜索以下来源：

1. DPDK Bugzilla: https://bugs.dpdk.org
2. DPDK Patchwork: https://patches.dpdk.org
3. DPDK 邮件列表归档: https://inbox.dpdk.org（优先用 API，避免 Anubis bot 拦截）
4. 外网搜索: Stack Overflow、CSDN、GitHub 全局搜索

注意：lore.kernel.org 等站点可能被 Anubis bot 拦截，优先使用 API 接口或 inbox.dpdk.org。

## 第五部分：常规分析/调研任务的内外网资料搜索

适用于 issue 分析、bug 定位、功能调研等常规任务，在完成前四部分的基础上，进一步搜索技术网站、博客、公众号等内外网资料，用于交叉验证与补充背景。

### 5.1 搜索目标

- 同类问题的既有分析与解决方案（他人踩坑记录、修复思路）
- 相关功能的原理讲解与实现细节（帮助理解代码设计意图）
- 上游/社区对该问题的讨论与处理动态
- 业界最佳实践与性能数据（供方案设计参考）

### 5.2 搜索渠道（按优先级）

1. 外网技术资料（web_search / web_fetch）：
   - GitHub issues / wiki / discussions（F-Stack、DPDK、FreeBSD 上游仓库）
   - 技术博客与个人站点（如 medium、dev.to、个人技术博客）
   - 技术社区（Stack Overflow、Server Fault、Unix & Linux SE、CSDN、知乎、掘金、SegmentFault）
   - 微信公众号文章（搜狗微信搜索 weixin.sogou.com 检索，再 web_fetch 抓取正文）
2. 内网知识库（RAG_search，如已连接企业知识库）：检索内部最佳实践、历史处理记录、内部组件文档
3. 腾讯内网 iWiki（若涉及 iWiki 文档，用 iwiki-doc 技能检索 iwiki.woa.com 的文档、空间、目录树）

### 5.3 关键词构造方法

- 中英文双语各搜一轮，中文关键词与英文关键词分开构造
- 组合方式：`<技术名词> + <版本号>`（如 "DPDK 24.11 RSS hash"）、`<错误信息原文>`（贴日志/报错原文搜索命中率最高）、`<函数名> + <现象>`（如 "rte_thash_adjust_tuple misqueue"）、`<issue 标题关键词> + fix/regression`
- 加限定词：`site:github.com`、`site:stackoverflow.com`、`inurl:blog` 等
- 注意版本时效：优先找与当前使用版本（F-Stack v2.0 / DPDK 24.11.6 / FreeBSD 15.0）相近时间的资料，避免过时结论

### 5.4 交叉验证与证据收敛

- 三方证据收敛：内部文档 + 外部资料 + 实际代码/实测，三方向互相印证
- 外部资料结论必须与本地实际代码核对，**不一致处以实际代码为准**
- 外部资料标注来源与发布时间，单一来源的结论标「仅此来源，未二次坐实」
- 无法坐实处如实标「未坐实/未执行」，不臆断

## 搜索产出要求

- 每个来源给出检索词与命中结果摘要，附具体链接或 commit hash
- 交叉验证：代码/文档/外部数据源三方证据收敛，不一致处以实际代码为准
- 无法坐实或环境不满足处，如实标注「未坐实/未执行」，不臆断
- 输出中严禁真实 IP（用 `<DPDK_NIC_IP>` 等占位符）
