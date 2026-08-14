---
name: f-stack-issue-process
description: F-Stack GitHub issue 分析处理标准操作流程（SOP）。当需要分析、判断状态、回复、关闭或批量处理 F-Stack/f-stack 仓库的 issue 时使用。包含三步流程（读 issue 全文→搜索资料(调用 f-stack-info-search 技能)→综合判断）、五类结论模板、本地 issue 分析档案（docs/f-stack-issue-ana.md 与 docs/zh_cn/f-stack-issue-ana.md）同步更新规则、不可自动操作 issue 的安全约束、DPDK 版本追踪与问题归属判定。触发词：分析 issue、issue 处理、issue #N、批量分析 issue、回复 issue、关闭 issue。
---

# F-Stack Issue 分析处理标准操作流程（SOP）

适用范围：分析 F-Stack GitHub 仓库（F-Stack/f-stack）的 issue，判断状态并给出处理建议。

## 环境准备

- GitHub Token 已配置（GH_TOKEN 环境变量）
- F-Stack 官方仓库已 clone 至 /data/workspace/f-stack
- gh CLI 已安装

## 第一步：读 Issue 全文

必须完整获取 issue 原文及全部讨论，不可仅看标题。

```bash
export GH_TOKEN='<token>'

# 获取 issue 正文
gh issue view <NUMBER> -R F-Stack/f-stack

# 获取全部评论（API 方式，无截断）
gh api repos/F-Stack/f-stack/issues/<NUMBER>/comments --jq '.[] | {user: .user.login, created_at: .created_at, body: .body}'
```

记录以下信息：

- 报告者（author）
- F-Stack / DPDK 版本
- 错误现象（crash、性能、编译失败、功能异常等）
- 复现步骤或环境描述
- 已有讨论结论（维护者是否回复、是否有解决方案）

## 第二步：搜索资料

调用 **f-stack-info-search** 技能完成资料搜索，包含五部分：

- 查项目架构文档与知识图谱：docs/ 下三层架构文档（LAYER1/2/3）+ KNOWLEDGE_GRAPH_WIKI
- 查代码提交记录：本地 git log 搜索修复性提交 + DPDK 上游
- 查关联 Issue 和 PR：先查本地 issue 分析档案（docs/zh_cn/f-stack-issue-ana.md、docs/f-stack-issue-ana.md），再 gh search issues/prs + DPDK Patchwork
- 查公开资料：DPDK Bugzilla / Patchwork / inbox.dpdk.org / 外网搜索
- 常规分析调研任务的内外网资料搜索：技术博客 / 公众号 / 技术社区 / 内网知识库 / iWiki，中英双语关键词构造与三方证据收敛

搜索完成后回到本技能继续第三步综合判断。

## 第三步：综合判断

使用中文给出明确结论，格式如下：

### 结论模板

```
## Issue #<NUMBER> 分析结论

**标题:** <issue 标题>
**状态判断:** <以下之一>

### 情况一：已修复
- 结论: 已修复
- 修复 commit: <hash> (<commit message>)
- 修复版本: F-Stack v<x.y> / DPDK <版本>
- 是否已 backport: 是/否
- 建议操作: 可关闭，回复告知用户升级到 v<x.y> 即可

### 情况二：有上游 patch 未合入
- 结论: 有上游 patch 未合入
- Patch 链接: <URL>
- Patch 状态: Accepted / Under Review / Superseded
- 影响版本: DPDK 22.11 / 23.11 / 24.11 各 LTS 修复状态
- 建议操作: 等待合入 / 手动 cherry-pick

### 情况三：未修复
- 结论: 未修复
- 根因分析: <详细描述>
- 影响范围: <哪些版本/场景受影响>
- 修复方案: <建议的修复思路>
- 建议操作: 需要开发修复

### 情况四：有 Workaround
- 结论: 有 workaround
- Workaround 步骤: <具体操作>
- 是否需要根本修复: 是/否
- 建议操作: 回复告知 workaround，保持 issue open 等待根本修复

### 情况五：非 Bug（使用咨询/已过时/无法复现）
- 结论: 非 Bug / 已过时 / 无法复现
- 理由: <详细说明>
- 建议操作: 可关闭，回复说明原因
```

## 关键注意事项

1. **不可自动操作 Issue**
   - 分析完成后，必须人工确认无误后才可以评论或关闭 issue
   - 给出建议操作，但不直接执行
   - 等待用户明确指令后再操作（评论、关闭、打标签等）
   - 回复 issue 的评论都使用英文，不要@任何人，不要长篇大论分析，不要重复回复历史回复已有的内容，只说核心结论和关键步骤

2. **区分问题归属**
   - F-Stack 自身问题: lib/ 目录下的代码、FreeBSD 移植层、ff_* API
   - DPDK 上游问题: dpdk/ 目录下的代码、驱动、EAL 层
   - 用户配置问题: config.ini、hugepage、NIC offload、ASLR 等
   - 应用集成问题: Nginx/Redis 集成、多进程架构

3. **DPDK 版本追踪**
   
   - F-Stack v2.0 → DPDK 24.11.6
   - F-Stack v1.25 → DPDK 23.11.5
   - F-Stack v1.24 → DPDK 22.11.6
   - F-Stack v1.22.1 → DPDK 20.11.9
   - F-Stack v1.21.x → DPDK 19.11.14
   - 涉及 DPDK 版本时，明确 22.11 / 23.11 / 24.11 各 LTS 的修复状态
   
4. **同步更新 issue 分析档案**
   - 每次提交回复或修改 issue 后，必须同步更新本地 issue 分析档案：
     - 中文：docs/zh_cn/f-stack-issue-ana.md
     - 英文：docs/f-stack-issue-ana.md
   - 两份档案内容保持一致（中英对照），记录：issue 编号、标题、分析结论、处理动作（回复/关闭/修复 commit）

5. **编译修复规则**
   - 修复文件后，必须确保所有依赖该文件的其他文件也能正常编译
   - 修改公共头文件后，需逐一验证所有 include 它的文件
   - PR 前必须执行完整 make 确认无 error
   - 编译验证命令：

     ```bash
     # F-Stack lib 编译验证
     cd /data/workspace/f-stack/lib && make clean && make
     
     # ftdns-dev src 编译验证
     cd /data/workspace/ftdns-dev/src && make clean && make
     ```

## 批量分析流程

当需要批量分析多个 issue 时：

```bash
# 1. 获取指定范围内所有 open issue
gh issue list -R F-Stack/f-stack --state open --limit 500 \
  --json number,title,labels,createdAt,author \
  --jq '[.[] | select(.number >= <START> and .number <= <END>)] | sort_by(.number)'

# 2. 逐个执行上述三步分析流程

# 3. 汇总分类报告，包含：
#    - 总数统计
#    - 按类型分类（Bug / 功能请求 / 使用咨询 / 编译问题）
#    - 按状态分类（已修复 / 未修复 / 有 workaround / 过时）
#    - 建议操作清单（哪些可关闭、哪些需修复、哪些需回复）
```

## 与开发规约的关系

issue 处理过程中若涉及代码修改，必须同时遵守 f-stack-dev-rule 技能的全部强制规约（rm/kill/chmod 脚本、make clean 编译、config.ini 不入库、文档禁真实 IP、代码注释英文、lib 最小注释等）。
