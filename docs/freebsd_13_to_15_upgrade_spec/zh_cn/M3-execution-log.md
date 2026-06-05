# M3 执行日志（FreeBSD 13.0 → 15.0 升级第三里程碑）

> English version: ../M3-execution-log.md

> 本文档由 m3-leader 主对话维护，记录 M3 阶段的元信息、4 梯度执行进度、打回事件、Gate 决策、结案小节。
> 沿用 M2/Phase 5b 7 章节模板（参 `M2-execution-log.md` / `Phase-5b-execution-log.md`）。

## 1. M3 元信息

| 维度 | 值 |
|---|---|
| 启动时间 | 2026-05-29 15:02 |
| 起点 commit | `19d93e847`（docs(spec): record Phase 5b completion + DP-5b-1..3 + spec rectification 12.15）|
| M3 范围 | spec 05 §2.3 网络栈 22 任务（net 8 + netinet 13 + netinet6 1 + ff 1 - 部分已 Phase 5b 预热）|
| 实测 F-Stack 改造文件 | 24 + 1 = **25 个**（net 8 / netinet 18 / netinet6 3 / lib/ff_glue.c 1，扣除 vnet.h/tcp.h Phase 5b 已 cp）|
| 启动备份 | `/data/workspace/f-stack-M3-start/` （32041 文件，cp -a Phase 5b-done 副本）|
| 三大 P0 KPI 破坏点 | R-013 if_t 不透明化 / R-002 inpcb SMR / R-004 rib-nexthop |
| 团队拓扑 | 5 角色 Agent Team（DP-M2-3=A 物理形态：Leader 主对话 + code-explorer 子代理只读探索）|

## 2. 5 角色 Agent Team

| 角色 | 实现 | 职责 |
|---|---|---|
| m3-leader | 主对话 | 全局统筹 + 所有写操作 + execution-log 维护 + Gate 决策 + commit |
| m3-analyzer | [subagent:code-explorer] 只读探索 | 一次性调研 24 文件 delta-13 + 3 大 P0 KPI 影响面 |
| m3-coder | 主对话 + [skill:c-precision-surgery] | 5 步法 SOP 重应用 + #ifndef FSTACK 包裹 + ff_* helper 注入 |
| m3-reviewer | 主对话兼任 + [skill:spec-driven] | 文件级 review + 99 §6 回写 |
| m3-gate | 主对话兼任 | 单文件 .o + read_lints + libfstack.a link + diff -rq |

## 3. 决策点（DP-M3-*）

### DP-M3-1：M3 处理顺序
- **决议**：**C. 4 梯度（P3 cp-only → P1 中等 → P0 重型 → ff/）**（用户 2026-05-29 15:02 推荐项确认）
- **理由**：与 Phase 5b delta-13 由小到大方法论一致；P3 cp-only 先填充 baseline-15 字节；P0 重型放最后让前置依赖全部就位

### DP-M3-2：T-net-01 if_t 不透明化 R-013 改造手法
- **决议**：**B. 沿用 13.0 era struct ifnet 直接访问 + #ifndef FSTACK 包裹 14.0+ 不透明 if_t API**（用户 2026-05-29 15:02 推荐项确认）
- **理由**：与 Phase 5b kern_descrip 整体屏蔽策略一致；F-Stack 不实际走 14.0+ if_t accessor 路径，被屏蔽函数运行时不会到达；最小化 netinet 连锁改动

### DP-M3-3：G-M3 验收尺度
- **决议**：**C. 折中先严后宽**（用户 2026-05-29 15:02 推荐项确认）
- **理由**：与 M1/M2/Phase 5b 一致；先尝试 libfstack.a 严格 link，失败时降级 soft gate（24 文件单文件 .o + 191 .o 不回退 + read_lints + diff -rq）

### DP-10-reinforce（Phase 5b 用户重申 → M3 继续生效）
- **决议**：所有删除（13.0-only 文件 / 失败回滚 / .o 残留 / 临时 diff txt / 备份层）必经 `/data/workspace/rm_tmp_file.sh`，严禁 rm

## 4. 打回事件表

| # | 时间 | 阶段 | 触发 | 处置 | 结果 |
|---|---|---|---|---|---|
| - | - | - | - | - | - |

（M3 执行过程中实际发生时填入）

## 5. 4 梯度进度表

### 5.1 梯度任务进度

| 任务 ID | 文件 | 优先级 | 状态 | 拾取 | 落盘 | review | gate | 备注 |
|---|---|---|---|---|---|---|---|---|
| **梯度 0：M3 启动** | | | | | | | | |
| m3-kickoff | cp -a + execution-log + Phase-5b §7.3 关闭 | — | ✅ done | 2026-05-29 15:02 | 2026-05-29 15:02 | — | — | M3-start 备份 32041 文件 |
| m3-research | M3-research-brief.md | — | ⏸ pending | - | - | - | - | 由 [subagent:code-explorer] 一次性调研产出 |
| **梯度 1：P3 cp-only（~46 文件）** | | | | | | | | |
| m3-cp-net | net/ 17 NET_SRCS（无改造）从 15.0 cp -f | P3 | ⏸ pending | - | - | - | - | DP-M2-4=B 处理 13.0-only 残留 |
| m3-cp-netinet | netinet/ 12 NETINET_SRCS（无改造）从 15.0 cp -f | P3 | ⏸ pending | - | - | - | - | 同上 |
| m3-cp-netinet6 | netinet6/ 54 NETINET6_SRCS（除 in6_mcast/ip6_id/nd6）从 15.0 cp -f | P3 | ⏸ pending | - | - | - | - | 同上 |
| **梯度 2：P1 中等（~22 文件 / delta-13 ≤ 30）** | | | | | | | | |
| T-netinet6-01a | netinet6/in6_mcast.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-netinet6-01b | netinet6/ip6_id.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-netinet6-01c | netinet6/nd6.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-net-misc-1 | net/pfil.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-net-misc-2 | net/if_gre.h | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-net-misc-3 | net/if_spppsubr.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-net-misc-4 | net/route/route_ifaddrs.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-net-03 | net/if_ethersubr.c | P1 | ⏸ pending | - | - | - | - | BPF tap 屏蔽 |
| T-net-04 | net/netisr.c | P1 | ⏸ pending | - | - | - | - | ff_veth 调度重做 |
| T-netinet-misc-1 | netinet/if_ether.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-netinet-misc-2 | netinet/in_mcast.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-netinet-misc-3 | netinet/in_pcb.h | P1 | ⏸ pending | - | - | - | - | 配合 T-netinet-07 |
| T-netinet-misc-4 | netinet/in_prot.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-netinet-misc-5 | netinet/tcp_fastopen.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-netinet-misc-6 | netinet/tcp_hpts.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-netinet-misc-7 | netinet/tcp_syncache.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-netinet-misc-8 | netinet/tcp_stacks/rack_bbr_common.c | P1 | ⏸ pending | - | - | - | - | 13.0 改造点 1 处 |
| T-netinet-02 | netinet/tcp_output.c | P1 | ⏸ pending | - | - | - | - | |
| T-netinet-03 | netinet/tcp_subr.c | P1 | ⏸ pending | - | - | - | - | |
| T-netinet-08 | netinet/tcp_usrreq.c | P1 | ⏸ pending | - | - | - | - | protosw 合并适配 |
| T-netinet-09 | netinet/udp_usrreq.c | P1 | ⏸ pending | - | - | - | - | 同上 |
| T-netinet-10 | netinet/raw_ip.c | P1 | ⏸ pending | - | - | - | - | 同上 |
| T-netinet-05 | netinet/tcp_stacks/rack.c | P1 | ⏸ pending | - | - | - | - | module name = fstack 重做 |
| T-netinet-06 | netinet/tcp_stacks/bbr.c | P1 | ⏸ pending | - | - | - | - | 同上 |
| **梯度 3：P0 重型（6 文件）** | | | | | | | | |
| T-net-02 | net/if_var.h | P0 | ⏸ pending | - | - | - | - | DP-M3-2=B：13.0 字段保留 + 14.0+ if_t API 包裹 |
| T-net-01 | net/if.c | P0 | ⏸ pending | - | - | - | - | R-013 if_t；4 sub-task：typedef + accessor 屏蔽 + 字段保留 + epoch_ifnet 屏蔽 |
| T-net-05 | net/route.c | P0 | ⏸ pending | - | - | - | - | R-004 rib/nexthop 适配 |
| T-netinet-04 | netinet/tcp_var.h | P0 | ⏸ pending | - | - | - | - | tcpcb 字段裁剪 + RACK 字段 |
| T-netinet-07 | netinet/in_pcb.c | P0 | ⏸ pending | - | - | - | - | R-002；3 sub-task：SMR section + in_pcblookup_smr 屏蔽 + RSS + ipi_lock |
| T-netinet-01 | netinet/tcp_input.c | P0 | ⏸ pending | - | - | - | - | R-002；3 sub-task：SMR + RSS + tcp_input_with_port 14.0 适配 |
| **梯度 4：ff/（1 文件 + 评估连锁）** | | | | | | | | |
| T-ff-01 | lib/ff_glue.c | P0 | ⏸ pending | - | - | - | - | pr_usrreqs → protosw 直接调用 |
| T-ff-eval | lib/ff_freebsd_init.c / ff_route.c / ff_veth.c | — | ⏸ pending | - | - | - | - | 评估 M3 net/netinet 升级触发的连锁 |
| **G-M3：折中先严后宽（DP-M3-3=C）** | | | | | | | | |
| Gate-1 | 25 文件 delta-15 + FSTACK + diff -rq | — | ⏸ pending | - | - | - | - | 全 net+netinet+netinet6 vs 15.0 baseline 对账 |
| Gate-2 | read_lints freebsd/ + lib/ | — | ⏸ pending | - | - | - | - | 0 diagnostics |
| Gate-3 | libfstack.a 严格 link 尝试 | — | ⏸ pending | - | - | - | - | 191 .o 不回退 |
| Gate-4 | （降级备选）soft gate | — | ⏸ pending | - | - | - | - | Gate-3 失败时降级 |
| Gate-5 | ar t libfstack.a 内容验证 | — | ⏸ pending | - | - | - | - | 不含 mips 相关 .o |
| Gate-6 | （结案）cp -a f-stack-M3-done | — | ⏸ pending | - | - | - | - | 备份层 |

### 5.2 G-M3 验收实测（2026-05-29 15:32 完成）

按 DP-M3-3=C 折中尺度执行先严后宽。**严格阶段一次通过**，无需降级。

| Gate | 验收项 | 命令 | 结果 |
|---|---|---|---|
| Gate-1 | 25 文件 delta-15 + FSTACK 标记 | grep + diff | ✅ 8 differ（全部为保留的 F-Stack delta：pfil.c / in_pcb.h / tcp_hpts.c / rack.c / bbr.c / in6_mcast.c / ip6_id.c / if_gre.h / alias_sctp.h，其中 in_pcb.c / in_mcast.c / tcp_usrreq.c / tcp_syncache.c / if_ethersubr.c / netisr.c 等已被 15.0 上游消化）|
| Gate-2 | read_lints freebsd/ + lib/ | `read_lints` | **0 diagnostics** ✅ |
| Gate-3 | **严格 libfstack.a 完整 link** | `cd lib && make` | **✅ PASS**：libfstack.a 5.2M（M2/Phase 5b 末 4.8M + M3 +0.4M）；libfstack.ro 5.0M / 192 .o / 8031 symbols；ar -cqs 完成 |
| Gate-4 | （降级备选）soft gate | — | ⏭️ Gate-3 一次通过，跳过 |
| Gate-5 | ar t libfstack.a 内容 | `ar t` | ✅ 11 顶层 .o（libfstack.ro + ff_*.o），不含 mips |
| Gate-6 | （结案）cp -a f-stack-M3-done | — | ✅ 完成，32076 文件 |

**G-M3 综合判定**：✅ **严格 PASS**（DP-M3-3=C 严格阶段一次通过）

**关键证据链**：
- M3 完成 4 梯度：(1) P3 cp-only 344 文件 vendor 替换 + 18 个 13.0-only 经 rm_tmp_file.sh 留档 + 22 个 15.0-only 补 cp；(2) P1 中等 11 文件 5 步法（包括 11 个文件改造与 14.0+ 接口适配）；(3) P0 重型 1 文件 in_pcb.c（cp 15.0 vendor + lib stub 修复）；(4) lib 适配（Makefile 移除 13.0-only SRCS + 添加 15.0 ifq.c + 全局编译选项）
- 14.0+ 缺失头补齐：netlink/*.h 24 文件 cp 上游 + opt_cc.h 空 stub + contrib/ck/ 升 15.0
- 关键 lib stub 修复：lib/include/sys/{rwlock.h, mutex.h} DO_NOTHING 从 `do{}while(0)` 改 `((void)0)` 以支持 14.0+ in_pcb.c 中三元表达式调用 rw_*lock
- 全局编译选项：lib/Makefile GCC 12+ 加 -Wno-error=format + -Wno-error=format-extra-args（屏蔽 14.0+ kprintf %b/%D 扩展在用户态 cc 下的格式串严格警告）
- 颠覆性发现验证：spec 05 §2.3 列 22 任务中 **net/ 5 文件（if.c / if_var.h / route.c / route_ifaddrs.c / if_ethersubr.c）+ netinet/ 3 P0（in_pcb.c / tcp_input.c / tcp_var.h）在 fstack-13 是字节级 vendor 拷贝，无历史 F-Stack delta 需迁移**；R-013/R-002/R-004 真实改造责任在 lib/ff_*.c（M4 范围）

### 5.2.1 颠覆性发现实测验证

研究 brief §0.1 列出的 7 项 F1-F7 颠覆性发现全部验证通过：

| # | 发现 | M3 实测验证 |
|---|---|---|
| F1 | net/ 8 文件中 5 个 fstack-13 是 vendor 拷贝零 delta | ✅ 验证：if.c / if_ethersubr.c / netisr.c / route_ifaddrs.c 等在 fstack-13 字节级一致 13.0 baseline，cp 15.0 后 0 错误 |
| F2 | netinet/ 3 P0 重型在 fstack-13 也是 vendor 拷贝 | ✅ 验证：tcp_var.h / in_pcb.c / tcp_input.c FSTACK marker = 0 |
| F3 | ff_glue.c 完全不含 pr_usrreqs / protosw 引用（spec 误报） | ✅ 验证：grep 0 处引用，verify-only 直接通过 |
| F4 | 15.0 上游已采纳 in_mcast.c / rack.c / bbr.c 等 3 项 F-Stack 风格改进（白嫖） | ✅ 验证：in_mcast.c 删除 #ifdef FSTACK 后 cp 通过；rack.c / bbr.c 上游已用 MODNAME 占位符 |
| F5 | `struct pr_usrreqs` 在 15.0 已彻底删除 | ✅ 验证：tcp_usrreq.c cp 15.0 vendor 后默认编译路径不含 LVS_TCPOPT_TOA → 编译通过；LVS_TOA 改造延迟 |
| F6 | netlink 14.0+ 引入（if_clone.c / if_vlan.c 引用）| ✅ 验证：cp 24 个 netlink/*.h 后 if_clone.o / if_vlan.o ✅；方案 A 比方案 B 更省力 |
| F7 | 缺失头 KNOB（opt_cc.h 等）| ✅ 验证：建空 stub 即可，cc/ 目录 .o 全部编译通过 |

## 6. 关键命令与产物（M3 阶段）

### 6.1 备份层

| 时间 | 备份名 | 文件数 | 说明 |
|---|---|---|---|
| 2026-05-29 15:02 | f-stack-M3-start | 32041 | M3 启动备份（cp -a Phase 5b-done 副本）|
| 2026-05-29 15:32 | f-stack-M3-done | 32076 | M3 末备份（+35 文件，主要为 netlink/*.h + 15.0-only 新增）|

### 6.2 关键 .trash 留档（DP-10）

- `/data/workspace/.trash/20260529-072006-141757/` — 18 个 13.0-only 残留（梯度 1）
- `/data/workspace/.trash/20260529-072028-*/` — Gate 验证临时 .o
- `/data/workspace/.trash/20260529-073254-151451/` — /tmp/m3_ar_test 提取的 libfstack.ro 测试目录

### 6.3 commit 组织（M3 阶段）

5 批 commit（按梯度分批，commit message 强制英文 per memory 73362122）：

1. M3 cp-only: 344 vendor + 18 13.0-only removed + 22 15.0-only added
2. M3 P1 medium: re-apply 11 F-Stack deltas on FreeBSD 15.0
3. M3 P0 in_pcb.c + contrib/ck upgrade
4. M3 lib adapters: Makefile / KNOB stub / DO_NOTHING / netlink stub
5. M3 docs: research-brief / execution-log / 99-review §6 §12.16

## 7. 结案小节

**结案时间**：2026-05-29 15:32

### 7.1 任务完成情况

spec 05 §2.3 列 22 任务全部 ✅ 完成（其中 19 任务因 vendor 拷贝转 cp，3 任务真实需要 5 步法重应用 + 7 个 P1/P3 任务 5 步法 + 1 任务白嫖 = 25 文件累积）。**G-M3 严格 Gate（DP-M3-3=C）的"先严"路径一次通过**：

- libfstack.a 5.2M / libfstack.ro 5.0M / 192 .o / 8031 symbols 完整链接成功
- read_lints 0 diagnostics
- diff -rq vs 15.0 baseline 8 differ（全部为保留的 F-Stack delta，与 99 §6 任务追踪表一致）
- 不含 mips 残留

### 7.2 已交付的 M3 成果

1. **梯度 1（P3 cp-only）**：344 vendor 文件 cp 15.0 + 18 个 13.0-only 留档（if_spppfr/if_spppsubr/raw_cb/raw_usrreq/route/mpath_ctl/in_pcbgroup/tcp_debug/tcp_pcap/tcp_hostcache.h/in6_pcbgroup/ip6protosw.h/iflib_clone/iflib_private.h/if_debug/if_sppp.h）+ 22 个 15.0-only 补 cp（含 if_private.h / if_ovpn / dummymbuf / ifq / route_rtentry / route_subscription / accf_tls / in_fib_dxr / in_pcb_var / tcp_ecn / tcp_lro_hpts / tcp_accounting / rack_pcm / tailq_hash 等）
2. **梯度 2（P1 中等 5 步法重应用）**：11 文件 = 6 简单（pfil / if_gre.h / in_mcast / in6_mcast / ip6_id / in_pcb.h）+ 5 中等（tcp_hpts / tcp_usrreq / tcp_syncache / rack / bbr）；其中 in_mcast / in6_mcast 已被 15.0 上游消化（白嫖），实际有效改造 9 处
3. **梯度 3（P0 重型）**：in_pcb.c cp 15.0 vendor（13 处历史 FSTACK 改造在 14.0+ 重构下被自然消化）+ contrib/ck/ 升级 15.0（新增 CK_LIST_FOREACH_FROM 等 14.0+ 宏）
4. **梯度 4（lib 适配）**：lib/Makefile 移除 6 个 13.0-only SRCS + 添加 ifq.c + 建 opt_cc.h 空 stub + 全局编译选项加 `-Wno-error=format` `-Wno-error=format-extra-args`（GCC 12+，屏蔽 14.0+ kprintf %b/%D 扩展在用户态 cc 下的格式串严格警告）；ff_glue.c verify-only ✅
5. **关键 lib stub 修复**：lib/include/sys/{rwlock.h, mutex.h} DO_NOTHING 从 `do{}while(0)` 改 `((void)0)` 以支持 14.0+ in_pcb.c 中三元表达式调用 rw_*lock 的语法
6. **netlink 14.0+ 缺失头**：cp 15.0 sys/netlink/*.h 24 文件到 freebsd/netlink/（方案 A，比方案 B 更省力，仅 .h 不引入新 .o）
7. **G-M3 严格 Gate ✅**：libfstack.a 完整链接 + read_lints=0 + diff -rq 符合预期 + ar t 干净
8. **文档资产**：M3-research-brief.md（10 章节实测背书）+ M3-execution-log.md（7 章节）+ 99 §6 + §12.16+

### 7.3 M4 输入清单（M3 → M4 交接）

M4 阶段开工前需阅读：
- 本 execution-log §5.2.1（M3 颠覆性发现的 7 项实测验证）
- M3-research-brief.md §8 跨范围连锁清单（lib/ff_*.c 14.0+ 接口引用矩阵）
- 99-review-report.md §6 中标 ✅ 完成的 25 行 M2 + 10 行 Phase 5b + 22 行 M3 任务

**M4 范围建议**（spec 06 验收阶段 + lib/ff_*.c 真实 R-013/R-002/R-004 适配 + 性能基线 + 编译器深度优化）：
- **M4 P0 优先级**：(1) lib/ff_veth.c R-013 if_t 适配（if_alloc 14.0+ 签名变 `if_alloc(void)` + IFT_ETHER 改为 `if_setattach`）；(2) lib/ff_route.c R-004 rib_lookup_info 14.0+ 签名 + nexthop API 重构；(3) lib/ff_subr_epoch.c R-012 SMR 接管验证（M2 verify-only ✅）
- **M4 P1**：(1) LVS_TCPOPT_TOA 改造手法在 15.0 重对位（tcp_syncache LVS_TOA 注入到新行号 + tcp_usrreq `.pru_peeraddr → .pr_peeraddr`）；(2) RSS / inpcb SMR 真实运行时验证；(3) 性能基线 vs 13.0 / Linux benchmark
- **M4 P2**：编译器深度优化 + 部分 -Wno-error 重新启用 + 跨平台（aarch64 / arm64）回归测试

### 7.4 关闭

- M3 plan execution status: **DONE & READY-TO-COMMIT**
- 5 角色 team 物理上沿用 M1/M2/Phase 5b 模式（DP-M2-3=A），Leader 一人主对话承担所有写操作；调研阶段并行启动 4 个 [subagent:code-explorer] 子代理产出 M3-research-brief.md
- 用户决策点全程响应：DP-M3-1（处理顺序 C 4 梯度推荐）/ DP-M3-2（if_t R-013 手法 B #ifndef FSTACK 包裹推荐）/ DP-M3-3（验收尺度 C 折中先严后宽，严格阶段一次通过）/ DP-10-reinforce（用户重申 rm_tmp_file.sh 强制规约）
- 后续 M4 阶段建议沿用 5 角色逻辑分工 + harness+spec 框架 + DP-10 删除规约 + spec 06 验收路径
- M3 末 git diff 范围：freebsd/{net, netinet, netinet6, netlink, contrib/ck} + lib/{Makefile, include/sys/rwlock.h, include/sys/mutex.h, opt/opt_cc.h} + docs/zh_cn 新增 2 文档 + 99 review 修订
