# CODEBUDDY.md

This file provides guidance to CodeBuddy Code when working with the F-Stack open source project.

## Project Overview

F-Stack is an open source high-performance network framework based on DPDK, porting the FreeBSD TCP/IP stack to user space. It achieves 10 million concurrent connections, 5 million RPS, 1 million CPS.

- **Primary Language:** C
- **F-Stack Version:** 1.25
- **DPDK Version:** 23.11.5
- **Repository:** https://github.com/F-Stack/f-stack
- **Local Clone:** `/data/workspace/f-stack`

## Build Commands

```bash
# 1. 编译 DPDK
cd /data/workspace/f-stack/dpdk
meson setup -Denable_kmods=true build
ninja -C build
ninja -C build install

# 2. 编译 F-Stack
export FF_PATH=/data/workspace/f-stack
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig
cd /data/workspace/f-stack/lib
make          # 编译
make install  # 安装（libfstack.a → /usr/local/lib，ff_*.h → /usr/local/include）

# 3. 清理重编
cd /data/workspace/f-stack/lib && make clean && make
```

## F-Stack Issue 分析处理标准操作流程 (SOP)

**适用范围:** 分析 F-Stack GitHub 仓库 (`F-Stack/f-stack`) 的 issue，判断状态并给出处理建议。

**环境准备:**
- GitHub Token 已配置（`GH_TOKEN` 环境变量）
- F-Stack 官方仓库已 clone 至 `/data/workspace/f-stack`
- `gh` CLI 已安装

### 第一步：读 Issue 全文

**必须完整获取 issue 原文及全部讨论，不可仅看标题。**

```bash
export GH_TOKEN='<token>'

# 获取 issue 正文
gh issue view <NUMBER> -R F-Stack/f-stack

# 获取全部评论（API 方式，无截断）
gh api repos/F-Stack/f-stack/issues/<NUMBER>/comments --jq '.[] | {user: .user.login, created_at: .created_at, body: .body}'
```

**记录以下信息：**
- 报告者（author）
- F-Stack / DPDK 版本
- 错误现象（crash、性能、编译失败、功能异常等）
- 复现步骤或环境描述
- 已有讨论结论（维护者是否回复、是否有解决方案）

### 第二步：查代码提交记录

**在本地 F-Stack 仓库中搜索相关修复。**

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

**同时检查 DPDK 上游：**
```bash
cd /data/workspace/f-stack/dpdk

# 搜索 DPDK 中的相关修复
git log --all --oneline --grep='<关键词>'
```

**关注点：**
- issue 提及版本之后是否有修复性提交（Fixes/fix/patch）
- 修复是否已 backport 到当前使用的分支

### 第三步：查关联 Issue 和 PR

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

**DPDK 上游 Patchwork（如需追踪上游 patch）：**
- API: `https://patches.dpdk.org/api/patches/?q=<关键词>`
- 使用 `WebFetch` 工具获取

### 第四步：查公开资料

**按优先级搜索以下来源：**

1. **DPDK Bugzilla**: `https://bugs.dpdk.org`
2. **DPDK Patchwork**: `https://patches.dpdk.org`
3. **DPDK 邮件列表归档**: `https://inbox.dpdk.org`（优先用 API，避免 Anubis bot 拦截）
4. **外网搜索**: Stack Overflow、CSDN、GitHub 全局搜索

```bash
# 使用 WebSearch 搜索
# 示例：搜索 F-Stack + 具体错误信息
```

**注意:** `lore.kernel.org` 等站点可能被 Anubis bot 拦截，优先使用 API 接口或 `inbox.dpdk.org`。

### 第五步：综合判断

**使用中文给出明确结论，格式如下：**

#### 结论模板

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

### 关键注意事项

1. **不可自动操作 Issue**
   - 分析完成后，**必须人工确认无误后才可以评论或关闭 issue**
   - 给出建议操作，但不直接执行
   - 等待用户明确指令后再操作（评论、关闭、打标签等）
   - 回复issue的评论都使用英文

2. **区分问题归属**
   - **F-Stack 自身问题**: lib/ 目录下的代码、FreeBSD 移植层、ff_* API
   - **DPDK 上游问题**: dpdk/ 目录下的代码、驱动、EAL 层
   - **用户配置问题**: config.ini、hugepage、NIC offload、ASLR 等
   - **应用集成问题**: Nginx/Redis 集成、多进程架构

3. **DPDK 版本追踪**
   - F-Stack v1.25 → DPDK 23.11.5
   - F-Stack v1.24 → DPDK 22.11.6
   - F-Stack v1.22.1 → DPDK 20.11.9
   - F-Stack v1.21.x → DPDK 19.11.14
   - 涉及 DPDK 版本时，**明确 22.11 / 23.11 / 24.11 各 LTS 的修复状态**

4. **编译修复规则**
   - 修复文件后，**必须确保所有依赖该文件的其他文件也能正常编译**
   - 修改公共头文件后，需逐一验证所有 include 它的文件
   - PR 前必须执行完整 `make` 确认无 error
   - 编译验证命令：
     ```bash
     # F-Stack lib 编译验证
     cd /data/workspace/f-stack/lib && make clean && make

     # ftdns-dev src 编译验证
     cd /data/workspace/ftdns-dev/src && make clean && make
     ```

### 批量分析流程

当需要批量分析多个 issue 时：

```bash
# 1. 获取指定范围内所有 open issue
gh issue list -R F-Stack/f-stack --state open --limit 500 \
  --json number,title,labels,createdAt,author \
  --jq '[.[] | select(.number >= <START> and .number <= <END>)] | sort_by(.number)'

# 2. 逐个执行上述五步分析流程

# 3. 汇总分类报告，包含：
#    - 总数统计
#    - 按类型分类（Bug / 功能请求 / 使用咨询 / 编译问题）
#    - 按状态分类（已修复 / 未修复 / 有 workaround / 过时）
#    - 建议操作清单（哪些可关闭、哪些需修复、哪些需回复）
```
