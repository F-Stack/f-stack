---
name: f-stack-dev-rule
description: F-Stack 工程开发强制规约（零容忍）。覆盖：Shell 操作必须走 rm_tmp_file.sh / kill_process.sh / chmod_modify.sh 脚本、改代码先 make clean 再完整编译、config.ini 本地测试值不入库、文档禁止真实 IP（用占位符）、commit message 英文 1-3 句、F-Stack 代码注释与提交信息只用简短英文、lib/ 最小注释、多 agent 协作规约（写审分离 / bounce≤3 / leader 轮询不提前退出）、实际执行不臆测以代码为准、所有提问/分析/调研类任务必须使用 f-stack-info-search 技能搜索资料、任务规模判断与 harness 流程（大任务先多 agent 调研出中文 spec 人工审核→人工触发实现验收→plan.md 先审→按里程碑多次提交→验收后翻译英文 spec）、代码改动必须完成单测与运行时回归测试并受门禁限制。当在 /data/workspace/f-stack 工作区执行任何开发、调试、测试、提交任务时使用本技能。
---

# F-Stack 开发强制规约

本技能是 /data/workspace/f-stack 工作区所有开发任务的强制规约合集，违反任何一条都会导致任务被打回修正，零容忍。

## 1. Shell 操作脚本规约

严禁直接调用 rm / kill / chmod 系列命令，必须一律通过本 skill 附带的以下脚本执行（位于本 skill 目录的 `scripts/` 子目录，以 SKILL 加载时注入的 base directory 为根拼接绝对路径调用）：

### 1.1 删除文件 → scripts/rm_tmp_file.sh

- 单文件：`scripts/rm_tmp_file.sh /full/path/to/file`
- 多文件：`scripts/rm_tmp_file.sh /path/a /path/b`
- 目录：`scripts/rm_tmp_file.sh /full/path/to/dir`
- 回收站位置：`/tmp/.trash`（自动保留路径前缀便于回查）
- 永久清理：`scripts/rm_tmp_file.sh --purge <trash_path> [--older-than Nd] [--dry-run]`（purge 白名单仅 /tmp/.trash、/data/.Trash-0/files、/data/.Trash-0/info）
- 禁止：直接 `rm`、`rm -rf`、`find -delete`、嵌入 bash 片段
- 批量删除 *.o 等：先用 `ls`/`find` 收集绝对路径再一次性传给脚本

### 1.2 停止进程 → scripts/kill_process.sh

- 单 PID：`scripts/kill_process.sh <pid>`
- 多 PID：`scripts/kill_process.sh <pid1> <pid2>`
- 禁止：`kill`、`pkill`、`killall`、`kill -9`、`pgrep | xargs kill`、trap/cleanup 内嵌 kill 等任何形式

### 1.3 修改权限 → scripts/chmod_modify.sh

- 用法：`scripts/chmod_modify.sh <mode> <path1> <path2> ...`（mode 与 chmod(1) 兼容，八进制/符号式均可）
- 禁止：直接 `chmod`、`chmod -R`、`install -m`、`setfacl` 等任何形式
- 说明：脚本会先快照变更前权限到 /tmp/.trash/、审计到 /tmp/.chmod_audit.log、拒绝高危路径、对 setuid/setgid 位 WARN

### 1.4 通用规则

- make clean / make install 等构建系统 target 属于构建工具操作，允许直接执行
- 若脚本缺少所需功能（如 --reference=），先扩展脚本再调用，不允许临时绕过

## 2. 编译规约

- 修改任何 .c/.h 后，必须先 `make clean`（或等效完整清理 target）再完整编译，严禁依赖增量编译
- 头文件改动会影响所有 include 它的编译单元，即使只改一个文件也必须 clean
- 编译验证以 clean build 通过为准；增量编译通过不作为依据
- 修改公共头文件后，逐一验证所有 include 它的文件可编译；PR 前必须完整 make 无 error
- 本机编译环境两个已知坑及规避方式：
  - IDE 注入 safe-delete hook 会拦截 make clean 内嵌的 rm：用 `PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin" make clean` 规避
  - `make -j16` 与 machine_includes 存在并行竞态：先 `make machine_includes` 再 `make -j16`
- 编译基线参考：lib error 0 / warning 51（既有 baseline，新改动不允许新增 warning）

## 3. config.ini 规约

- config.ini 及类似入库配置文件，提交时只允许提交与当前功能特性直接相关的改动
- 严禁提交本地测试/调试环境临时改动：lcore_mask、vlan_filter、idle_sleep、[portN] 本机真实 IP、性能调优临时值等
- 每次 `git add config.ini` 之前必须先 review `git diff` 逐项确认
- 严禁用 `git checkout config.ini` 还原本地测试值（本地配置是运行所必需的，必须保留）
- 正确做法：git add 时不选中 config.ini，让本地测试值自然留在未暂存区

## 4. 文档真实 IP 规约

- 严禁在任何文档（docs、README、spec、测试报告、执行日志、commit message、PR 评论等）中记录本地运行时环境的真实 IP
- 必须使用描述性占位符：`<DPDK_NIC_IP>`、`<DPDK_NIC_IPV6>`、`<KERNEL_NIC_IP>`、`<CLIENT_IP>`、`<CLIENT_IPV6>`、`<GATEWAY_IP>`、`<GATEWAY_IPV6>`、`<BROADCAST_IP>`、`<NETWORK_PREFIX>`、`<VIP_IPV6>`、`<BACKEND_IPV6>` 等
- 泛指写法（如 9.134.x）允许，完整真实地址禁止
- `127.0.0.1`、`fe80::` link-local 可写

## 5. 提交规约

- commit message 一律英文，1-3 句话简单总结，不长篇大论
- config.ini 本地测试值不入库（见第 3 节）
- 误提交修复采用 forward-fix（新提交回滚），不改写历史

## 6. 代码注释语言规约

- F-Stack 工程（/data/workspace/f-stack，含 lib/、freebsd/、example/、tests/ 等所有代码文件）：注释和 git 提交信息都必须使用简短的英文，禁止中文
- 文档类（docs/*.md、spec 中文文档）不受此限，按文档语言要求撰写

## 7. lib 最小注释规约

- 仅确有必要处写注释：对外接口契约（如 ff_api.h）、配置项含义（如 config.ini）、确实复杂不直观的算法/边界处理
- 严禁给一看就懂的代码加注释（简单赋值、显而易见的分支、自解释调用）
- 复杂逻辑的注释也要精炼，优先用清晰命名让代码自解释

## 8. 多 agent 协作规约

适用于 harness 工程 + 多 agent（agent team / spec 驱动）任务：

- **leader 严禁提前退出**：任一子 agent 未回报最终结果前不得结束任务，必须主动轮询等待
- **子 agent 超时探测**：禁止无超时死等；旁路探测（读落盘文件、git 状态、产物路径）优先于消息探测
- **写审分离铁律**：写代码/文档 与 审核 必须不同 agent；leader 严禁自写自审；纯调研/探测/汇总等单一角色可由 leader 兼任
- **bounce≤3**：任一阶段门禁失败必须打回上一步修复，不得带病放行；同一单步骤打回超 3 次立即停止转人工决策
- **异常回退**：子 agent 超时/卡死/与裁决冲突时，可 leader 接管或 spawn 新 agent 重做，但不得违反写审分离

## 9. 实事求是规约

- 所有行动必须实际执行，严禁未执行就猜测给结果
- 代码/文档/外部数据源交叉验证，不一致处以实际代码为准
- 无法静态坐实或环境不满足的项，如实标注「未坐实/未执行」，不得臆断 PASS

## 10. 资料搜索规约

- 所有提问、分析、调研类任务，必须使用 **f-stack-info-search** 技能来搜索资料
- 覆盖范围：issue 分析、bug 定位、功能调研、方案设计前的资料搜集、技术问题答疑等一切需要查资料的场景
- 搜索流程按 f-stack-info-search 的五部分执行：项目架构文档与知识图谱 → 代码提交记录 → 关联 issue/PR → 公开资料 → 内外网技术网站/博客/公众号等
- 交叉验证：内部文档 + 外部资料 + 实际代码/实测三方证据收敛，不一致处以实际代码为准
- 严禁不搜索资料直接凭猜测回答或给出结论

## 11. 运行时测试环境

- 本机双网卡：DPDK 独占网卡与 eth1 是不同卡
- 测试 DPDK 网卡程序：通过 `ssh f-stack-client` 从对端机器访问本机 DPDK 接管网卡（IP 用 `<DPDK_NIC_IP>` 占位符）
- 本机内核栈测试：用 127.0.0.1 的 lo
- 停进程走 kill_process.sh，临时文件清理走 rm_tmp_file.sh，config.ini 临时测试值测完还原且不入库

## 12. 任务规模判断与 harness 流程规约

- 由提示词或大模型自动判断任务规模：小任务可以直接分析执行；大任务必须按以下步骤进行：
- 12.1 功能调研：先使用多 agent harness 方式完成功能调研，产出中文 spec 文档（可安装使用其他 spec 相关 skill）+ 门禁审核；中文文档存放目录 `docs/<FEATURE_NAME>_spec/zh_cn/`；**暂不生成英文 spec 文档**（功能验收完成后再翻译生成英文 spec 文档）；交由人工审核
- 12.2 功能实现与验收：人工审核 spec 文档通过后，由人工提示词触发进入功能实际实现和验收阶段（使用多 agent harness 方式，遵循多 agent 各种相关规则），完成代码编写、CR、测试（单元测试和运行时测试）、文档更新、各里程碑步骤的门禁审核
- 12.3 spec 文档生成和功能实际实现都必须先生成 plan.md 交由人工审核后再执行
- 12.4 按里程碑进行多次 git 提交
- 12.5 测试验收完成后，将 `docs/<FEATURE_NAME>_spec/zh_cn/` 下的中文 spec 文档翻译为英文文档（文件名和文件内容都需要翻译），存放目录 `docs/<FEATURE_NAME>_spec/`

## 13. 测试门禁规约

- 涉及代码改动必须完成单元测试和运行时回归测试
- 单元测试和运行时回归测试同样受门禁规则限制（bounce≤3、写审分离等，见第 8 节）
