# 04 - Spec 审核门禁

## 门禁检查清单

### 1. 测试完整性

| 检查项 | 状态 | 说明 |
| --- | --- | --- |
| T1 内核基线（3次） | ✅ | 9.129/9.286/10.027s，中位数 9.286s |
| T2 F-Stack 当前配置 | ✅ | 连接失败（delayed_ack=1 导致） |
| T3 F-Stack 优化配置（3次） | ✅ | 9.355/9.676/9.587s，中位数 9.587s |
| T4 参数隔离 recvspace | ✅ | recvspace=8192 不影响（9.417s） |
| T5 参数隔离 delayed_ack | ✅ | delayed_ack=1 导致失败 |
| 最终验证 | ✅ | 优化配置可复现（exit=0） |

### 2. 代码分析完整性

| 检查项 | 状态 | 说明 |
| --- | --- | --- |
| delayed_ack 根因分析 | ✅ | 40ms ACK 延迟 + 窗口更新阻止，代码 file:line 证据 |
| ff_epoll EPOLLOUT 分析 | ✅ | 转换逻辑正确，初始观察的问题源于双重注册（ff_epoll+kqueue 同一 socket） |
| TX drain 机制 | ✅ | pkt_tx_delay 影响 GET 延迟，非根因 |
| 接收路径分析 | ✅ | ff_recv→kern_recvit→soreceive 路径正常 |

### 3. 规约合规

| 检查项 | 状态 |
| --- | --- |
| rm → rm_tmp_file.sh | ✅ |
| kill → kill_process.sh | ✅（远程 server pkill 除外，不在 /data/workspace 规约范围） |
| chmod → chmod_modify.sh | ✅ |
| config.ini 不入库 | ✅ |
| make clean 后编译 | ✅（本轮未修改 lib 代码） |
| 最小注释 | ✅ |
| commit message 英文 | ✅ |

### 4. 结论

**Issue #842 在本环境不复现。**

- F-Stack 优化配置下（delayed_ack=0, idle_sleep=0, pkt_tx_delay=0）TCP 接收性能与内核持平（差距 3.2%）
- delayed_ack=1 是导致连接失败的关键配置，通过设置 `net.inet.tcp.delayed_ack=0` 解决
- ff_epoll EPOLLOUT 转换逻辑经验证正确，无需修复
- 本轮无需修改 lib 代码

### 5. 文档更新

更新 `docs/zh_cn/f-stack-issue-ana.md` 和 `docs/f-stack-issue-ana.md` 中 #842 条目的最终结论。
