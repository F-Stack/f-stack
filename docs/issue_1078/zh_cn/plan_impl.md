# issue #1078 最终实现计划

## 里程碑顺序
1. **M1**（C01~C16）：primary_slim 开关 + 校验链 + 启动路径 + 主循环 — 核心功能
2. **M3**（C23~C31）：KNI K4 完善 — C26 移出 rx 循环 + C29 放开 C05 + C32 N2 修正
3. **M2**（C17~C22）：控制面完整性 — MTU 门禁 + RSS 诊断
4. **M4**（C32~C38）：加固清理 — nb_dev_ports + init_flow 门禁 + ff_is_slim_primary API

## Agent Team
- leader: 统筹 + 编译 + 实机测试 + 提交
- coder-m1: 实现 M1（C01~C16）
- coder-m3: 完善 M3（C26 移出 rx 循环 + C29 + C32）
- coder-m2m4: 实现 M2 + M4
- gatekeeper: 审核门禁

## 规约
- 改代码先 make clean（用 rm_tmp_file.sh 清 .o）
- config.ini 不提交
- 文档无真实 IP
- lib 最小注释
- commit message 英文 1-3 句
- rm/kill/chmod 走脚本
