# F-Stack 完整知识库

## 📚 文档概览

本目录包含 F-Stack v1.26（FreeBSD 15.0 移植；2025-2026 自 13.0 升级而来 —— M0~M5 + runtime-fix + rib-fix + Phase-5b NFR-1 PASS）+ DPDK 24.11.6 LTS（2026-06-09 自 23.11.5 LTS 升级）的完整三层架构知识库，用于规格驱动开发 (Spec-Driven Development) 的前置架构文档。

### 文档清单

```
1. F-Stack_Knowledge_Base_Summary.md (751 行)
   ├─ 总览文档 - 快速导航和参考
   ├─ 包含所有文档的导航表和快速查询卡
   └─ ⭐ 建议首先阅读

2. F-Stack_Architecture_Layer1_System_Overview.md (825 行)
   ├─ 第一层：系统总体架构
   ├─ 模块边界、技术选型、核心设计
   └─ 适合架构师和系统设计师

3. F-Stack_Architecture_Layer2_Interface_Specification.md (1183 行)
   ├─ 第二层：接口定义与规范
   ├─ API 详解、配置系统、开发规范
   └─ 适合应用开发者和系统集成工程师

4. F-Stack_Architecture_Layer3_Function_Index.md (1112 行)
   ├─ 第三层：函数级索引与数据模型
   ├─ 80+ 函数详解、源代码分析、线程安全
   └─ 适合内核开发者和性能分析师

<!-- 注: 此修改基于 2/3 评审意见一致 (GPT-5.4 + Claude) -->
总计: 3120 行完整版 (+ 1436 行简化版本) = **4556 行** (含导览+汇总约 5839 行)
```

## 🚀 快速开始

### 场景 1：我想快速了解 F-Stack 是什么

```
阅读顺序:
  1. 本文件的"核心概念"部分 (5 分钟)
  2. F-Stack_Knowledge_Base_Summary.md §2 (10 分钟)
  3. F-Stack_Architecture_Layer1_System_Overview.md §1 (15 分钟)
```

### 场景 2：我想开发一个 F-Stack 应用

```
阅读顺序:
  1. F-Stack_Knowledge_Base_Summary.md §4 (15 分钟)
  2. F-Stack_Architecture_Layer2_Interface_Specification.md §5 (30 分钟)
  3. 参考 /data/workspace/f-stack/example/main.c (10 分钟)
  4. 开始编码！
```

### 场景 3：我想深入理解 F-Stack 内部实现

```
阅读顺序:
  1. F-Stack_Architecture_Layer1_System_Overview.md (完整阅读，1 小时)
  2. F-Stack_Architecture_Layer2_Interface_Specification.md (完整阅读，1 小时)
  3. F-Stack_Architecture_Layer3_Function_Index.md (完整阅读，1.5 小时)
  4. 精读源码（已对当前 HEAD 校验）:
     - lib/ff_dpdk_if.c (2907 行)
     - lib/ff_glue.c (1467 行)
     - lib/ff_syscall_wrapper.c (2265 行，新增：FF_KERNEL_COEXIST 共存 + R9 kqueue/kevent 共存 + IPv6 IPV6_V6ONLY + R10 readv/writev/ioctl/dup/dup2 内核 fd 路由)
     - lib/ff_ng_base.c (3887 行，netgraph 完整移植)
     - lib/ff_route.c (1604 行，rtsock 部分移植)
     - lib/ff_stub_14_extra.c (799 行，新增：14.0+ 中央 stub 库)
     - lib/ff_host_interface.c (617 行，32 个 ff_host_*) / ff_epoll.c (289 行，FF_KERNEL_COEXIST 内核栈共存)
```

### 场景 4：我想查某个 API 函数的用法

```
使用方法:
  1. 在 F-Stack_Knowledge_Base_Summary.md §5.1 查 API 速查表
  2. 或查 F-Stack_Architecture_Layer3_Function_Index.md §1 的完整函数清单
  3. 或用 grep 搜索函数名在 layer2 或 layer3 文档中的说明
```

### 场景 5：我想优化应用的性能

```
查询步骤:
  1. F-Stack_Knowledge_Base_Summary.md §6.1 (性能调优清单)
  2. F-Stack_Architecture_Layer1_System_Overview.md §6 (硬件加速)
  3. F-Stack_Architecture_Layer2_Interface_Specification.md §5.4 (优化建议)
```

## 📖 核心概念速记

### F-Stack 的三大创新

| 创新 | 说明 | 效果 |
|-----|------|------|
| **Kernel Bypass** | 绕过 Linux 内核网络栈 | 延迟 ↓ 10x (100μs → 10μs) |
| **FreeBSD 移植** | 复用 20+ 年优化的协议栈 | 功能完整、RFC 兼容 |
| **多进程隔离** | 每核心一个进程 + 轮询 | 吞吐 ↑ 25x、无锁设计 |

### 性能对标

在 10GbE 网络上实际数据：

| 指标 | F-Stack | Linux 内核 | 提升 |
|-----|---------|----------|------|
| 吞吐 (RPS) | 5M | 200K | **25x** |
| 延迟 P99 | 10μs | 100μs | **10x** |
| 新建连接 | 1M CPS | 100K CPS | **10x** |
| 并发连接 | 10M | 1M | **10x** |

> **注意**: 以上性能数据为参考值，实际结果取决于硬件配置 (CPU 型号/核心数、网卡型号、内存)、测试场景和报文大小。详细测试条件待补充。

### 80+ 公开 API 分类

```c
// 生命周期 (3)
ff_init / ff_run / ff_stop_run

// Socket (25+)
ff_socket / ff_bind / ff_listen / ff_accept / ff_connect / ff_close
ff_read / ff_write / ff_readv / ff_writev
ff_send / ff_sendto / ff_sendmsg
ff_recv / ff_recvfrom / ff_recvmsg / ...

// 事件多路复用 (5)
ff_kqueue / ff_kevent / ff_select / ff_poll
ff_epoll_create / ff_epoll_ctl / ff_epoll_wait

// 控制操作 (10+)
ff_setsockopt / ff_getsockopt / ff_ioctl / ff_fcntl / ...

// 其他 (30+)
ff_route_ctl / ff_gettimeofday / ff_log / ...
```

## 📋 文档结构详解

### 第一层：系统总体架构 (825 行)

涵盖内容：
- ✓ 系统定位与创新 (Kernel Bypass 的好处)
- ✓ 顶层模块边界 (10 个核心模块)
- ✓ 核心架构设计 (分层、数据流、轮询循环)
- ✓ 多进程架构 (Primary-Secondary、RSS)
- ✓ 技术选型分析 (为什么选 DPDK/FreeBSD)
- ✓ 性能特性与硬件加速 (TSO/LSO/Checksum)
- ✓ 生态集成 (Nginx/Redis)

**适合人群**: 架构师、CTO、系统设计师

**阅读时间**: 60-90 分钟

### 第二层：接口定义与规范 (1183 行)

涵盖内容：
- ✓ 80+ 导出函数详解 (签名、参数、返回值)
- ✓ 6 个主要头文件分析
- ✓ Linux ↔ FreeBSD 系统调用映射表
- ✓ config.ini 完整配置系统
- ✓ 多进程与多线程接口
- ✓ 应用开发规范 (3 种模式、7 个陷阱)
- ✓ 8 个 IPC 工具和集成方式

**适合人群**: 应用开发者、系统集成工程师

**阅读时间**: 90-120 分钟

### 第三层：函数级索引与数据模型 (1112 行)

涵盖内容：
- ✓ 完整函数导出清单 (每个函数的签名、参数、线程安全性)
- ✓ 11 个核心数据结构详解 (kevent、config、sockaddr、等)
- ✓ 3 个关键源文件深度分析
  - ff_syscall_wrapper.c (Linux ↔ FreeBSD 映射)
  - ff_dpdk_if.c (NIC 驱动和主轮询循环)
  - ff_glue.c (内核原语模拟)
- ✓ 线程安全性分析 (Per-thread socket table)
- ✓ 编译和链接指南

**适合人群**: 内核开发者、性能分析师、调试工程师

**阅读时间**: 120-180 分钟

## 🎯 使用建议

### 1. 首次接触 F-Stack

```
推荐阅读顺序 (2-3 小时):
  1. 本 README 的"核心概念"部分
  2. F-Stack_Knowledge_Base_Summary.md §1-3
  3. F-Stack_Architecture_Layer1_System_Overview.md §1-3
  4. F-Stack_Architecture_Layer2_Interface_Specification.md §5
  ↓
  建议: 然后阅读 /data/workspace/f-stack/example/main.c 的代码
```

### 2. 开发 F-Stack 应用

```
必读部分:
  □ Layer2 §5 (开发规范) - 避免常见陷阱
  □ Layer2 §2 (系统调用映射) - 理解参数转换
  □ Layer3 §1 (函数清单) - 查询函数签名
  
辅助参考:
  □ Layer1 §3 (核心架构) - 理解设计思想
  □ Layer1 §6 (硬件加速) - 性能优化
```

### 3. 性能优化和调试

```
参考资料:
  □ Summary §5.2 (Kevent 事件速查)
  □ Summary §5.3 (配置参数速查)
  □ Summary §5.4 (常见错误速查)
  □ Layer1 §6 (性能特性)
  □ Layer3 §3.2 (ff_dpdk_if 源码)
```

### 4. 深入研究内部实现

```
推荐路径:
  1. Layer1 (完整阅读，理解整体设计)
  2. Layer3 §3 (关键源文件分析)
  3. 精读源码 (lib/ff_*.c)
  4. 理解 FreeBSD 协议栈 (freebsd/sys/netinet/)
```

## 📌 关键快速查询

### 我想...

| 需求 | 查询位置 |
|-----|--------|
| 了解 F-Stack 架构 | Summary §2 + Layer1 §1-3 |
| 查函数用法 | Summary §5.1 + Layer3 §1 |
| 了解 API | Layer2 §1 (API 体系结构) |
| 学习开发 | Layer2 §5 (开发规范) |
| 查配置参数 | Summary §5.3 + Layer2 §3 |
| 避免常见错误 | Summary §5.4 + Layer2 §5.3 |
| 优化性能 | Summary §6.1 + Layer1 §6 |
| 理解多进程 | Layer1 §4 + Layer2 §4 |
| 查数据结构 | Layer3 §2 (数据模型) |
| 线程安全性 | Layer3 §4 (线程安全分析) |

## 🔧 文档维护

### 版本信息

```
知识库版本: 1.5（新增 R10：ff_readv/ff_writev/ff_ioctl/ff_dup/ff_dup2 内核 fd 路由 + select/poll 文档限制，2026-06-18；基于 1.4 R9 ff_kqueue/ff_kevent 共存 + IPv6 IPV6_V6ONLY + 1.3 FF_KERNEL_COEXIST 内核栈共存 + 1.2 的 FreeBSD 13.0 → 15.0 第一阶段 + Phase-2 M6-M13 + Phase-5b + F-A1 fix + vlan-vip-ipfw 测试）
F-Stack 版本: v1.26（分支 feature/1.26）
FreeBSD 移植基线: 15.0（v1.25 时为 13.0）
DPDK 版本: 24.11.6 LTS（2026-06-09 由 23.11.5 LTS 升级；详见 dpdk_23_24_upgrade_spec/zh_cn/）
反映的新特性: FF_KERNEL_COEXIST 自动双栈共存（默认关；commits ba148589d → 55a84f313）+ R9 kqueue/kevent 共存 + IPv6 IPV6_V6ONLY（kqueue 模型内核侧 curl 127.0.0.1:80=200；-DINET6 v4+v6 同端口启动修复）+ R10 ff_readv/ff_writev/ff_ioctl/ff_dup/ff_dup2 内核 fd 路由（ff_ioctl 用原始 Linux request；ff_dup2 混栈拒绝 EINVAL；select/poll 为已知限制，改用 epoll/kqueue）。详见 docs/kernel_event_support_spec/（含 plan-r9-kqueue-coexist-ipv6.md、plan-r10-readv-writev-ioctl-coexist.md）。
生成日期: 2026-03-20（最近同步 2026-06-18）
总行数: 约 5839 行 (以实际文件统计为准)
```

### 更新计划

- [ ] 跟踪 F-Stack 新版本 (建议每 6-12 个月)
- [ ] 补充性能基准测试数据
- [ ] 添加更多应用集成示例 (包括复杂场景实战案例和故障排查指南)
- [ ] 收集用户反馈和最佳实践

### 维护规则

> 以下维护规则由三个独立模型评审一致建议补充。

1. **版本同步**: 每次 F-Stack 版本升级时，检查 `app/` 目录下集成应用版本 (如 nginx, redis) 是否变更，同步更新文档中的目录路径引用
2. **统计信息**: 文档中的行数/字数等统计信息容易过期，建议通过脚本自动生成 (如 `wc -l docs/*.md`)，而非人工维护
3. **代码交叉验证**: 文档中涉及具体数值 (行数、常量值、结构体字段) 的地方，应定期与源码交叉验证

## 重要说明

### 文档版本说明

1. **完整版 vs 简化版**: 本知识库包含完整版 (`F-Stack_Architecture_Layer*.md`) 和简化版 (`01/02/03-LAYER*.md`) 两套文档。完整版包含全量细节，简化版为快速参考版。**当两者内容存在差异时，以完整版为准。**

2. **已知待补充内容**:
   - 缺少集中的“重要约束与风险提示”章节 (单线程/非阻塞约束、应用集成边界等)
   - 性能数据的完整测试条件待补充

## 📚 相关资源

### 源代码位置

```
/data/workspace/f-stack/
├── lib/               # 核心库 (~21K 行)
├── freebsd/           # FreeBSD 协议栈移植
├── dpdk/              # DPDK 24.11.6 LTS 依赖
├── adapter/           # 中间适配器：micro_thread + syscall（构建 libff_syscall.so 供 LD_PRELOAD 使用）
├── example/           # 应用示例 (main.c 推荐)
├── app/               # Nginx/Redis 集成
├── tools/             # 运维工具
└── docs/              # ⬅️ 本知识库 (此处)
```

### 外部参考

```
官方资源:
  - F-Stack 项目: https://github.com/F-Stack/f-stack
  - DPDK 文档: https://doc.dpdk.org
  - FreeBSD 源码: https://github.com/freebsd/freebsd-src

技术标准:
  - TCP/IP 协议: RFC 793/791/768
  - 硬件卸载: Intel 网卡白皮书
  - 拥塞控制: RFC 5681 (CUBIC) / RFC 9002 (BBR)
```

## ❓ FAQ

### Q: 应该按什么顺序阅读文档？

A: 根据你的角色选择：
- **架构师**: Layer1 完整 → Layer2 §1-2 (30-40 分钟)
- **开发者**: Layer2 §5 + Layer3 §1 (40-50 分钟)
- **运维**: Summary §5 + Layer2 §3 (20-30 分钟)
- **深度研究**: Layer1-3 完整 (4-5 小时)

### Q: 文档和源码如何结合阅读？

A: 推荐方式：
1. 先读对应的文档部分（理论）
2. 找到相关源码文件
3. 对照源码逐行理解
4. 回到文档验证理解

### Q: 怎么快速查某个参数的说明？

A: 三种方式：
1. 用 `grep` 搜索文档目录
2. 查 Summary §5.3 (配置参数速查表)
3. 查 Layer2 §3 (完整配置系统分析)

### Q: 文档何时更新？

A: 计划：
- 跟踪 F-Stack 主版本更新 (v1.26 → v1.27 等)
- 补充新的优化技巧和最佳实践
- 收集用户反馈和修正
- 13.0 → 15.0 第一阶段升级的可追溯证据见 `freebsd_13_to_15_upgrade_spec/`（M0~M5、runtime-fix、Phase-5b、rib-fix、双基线）

## 📞 反馈与支持

- 发现错误？提交 Issue
- 有改进建议？欢迎 Pull Request
- 需要补充内容？联系维护者

---

**快速开始**: 先读 `F-Stack_Knowledge_Base_Summary.md`，然后根据需要选择相应层级文档。

**核心收获**: 本知识库涵盖 F-Stack 的完整架构，包括 80+ API、11 个核心数据结构、3 个关键源文件分析，以及完整的开发规范和性能优化指南。

祝你使用 F-Stack 开发顺利！🚀
