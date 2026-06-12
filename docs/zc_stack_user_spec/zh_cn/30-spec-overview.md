# 30. 用户态零拷贝栈 spec — 总览

> 范围：完整"用户态零拷贝栈"（zc_stack_user）spec
> 关键变更：新增对称的 `kern_zc_sendit`，**替换**现有 `FSTACK_ZC_MAGIC` + `m_uiotombuf` 内核魔改方案
> 目录：`docs/zc_stack_user_spec/zh_cn/`（仅中文）
> 状态：spec 阶段（不实现代码）

---

## §1 背景与动机

f-stack 在 M8 阶段（commit ca83653c1 等）落地了 `FSTACK_ZC_SEND` 应用层 → 协议栈零拷贝，并已在更近期实现了 `FSTACK_ZC_RECV`（M0+M1, commit b87f5f0d2）。两条路径独立设计、机制不对称：

| 维度 | ZC-send（现状）| ZC-recv（已落地）|
|---|---|---|
| 内核入口 | 魔改 `m_uiotombuf` 的 `#ifdef FSTACK_ZC_SEND` 分支 | 新增 `kern_zc_recvit` 透传 `soreceive` 的 `mp0` 出参 |
| 哨兵机制 | 依赖 `uio->uio_offset == FSTACK_ZC_MAGIC`（off_t 0xF8AC2C00F8AC2C00）+ `UIO_SYSSPACE/UIO_WRITE` 三件套 | **无哨兵**：直接走 FreeBSD 原生 `mp0` 出参契约 |
| 上游一致性 | 低（5 处文件魔改 + uio_offset 在 syscall 全路径透传）| 高（仅 2 个新函数；soreceive 核心 0 改动）|
| 误触风险 | **存在**（普通 `ff_write/ff_writev` 须显式 `uio_offset=0` opt-out 防误触；M2 阶段曾因 stale .o 缺 hook 致 GPF）| 无 |
| 升级维护成本 | 高（FreeBSD 15.x → N.0 时 `m_uiotombuf` 周边需重新审计）| 低（只新增、不改动）|

外网交叉验证（详见 31）：
- F-Stack 官方文档（腾讯云开发者社区，2022-04-17）声明 ZC-send 性能提升仅 2-3%；
- F-Stack 上游 issue [#712](https://github.com/F-Stack/f-stack/issues/712)（2022-11-01 至今 OPEN）：大数据量发送会 crash/hang，社区无修复；
- FreeBSD `sosend(9)` 手册（FreeBSD 7.0 起，作者 Robert Watson）原文："Data may be sent ... as an mbuf chain via *top*, **avoiding a data copy**. Only one of the *uio* or *top* pointers may be non-NULL."

→ **结论**：FreeBSD 15.0 已经原生支持等价的发送端零拷贝（`sosend(uio=NULL, top=链)`），现 `FSTACK_ZC_MAGIC` 方案是上游已有能力的"非必要重新发明"，应改用原生路径。

---

## §2 目标

| 编号 | 目标 |
|---|---|
| G1 | 新增 `kern_zc_sendit(td, s, top, flags)` 内核入口，直接调用 `sosend(uio=NULL, top=链)`（uipc_socket.c:2599）|
| G2 | 拆除 `FSTACK_ZC_MAGIC` 宏 + `m_uiotombuf` 的 `#ifdef FSTACK_ZC_SEND` 分支 + `kern_writev` 的 `uio_offset` 保留逻辑 + `ff_write/ff_writev` 的 `uio_offset=0` opt-out（共 5 处）|
| G3 | 修复 `ff_zc_mbuf_get`/`ff_zc_mbuf_write` 的 `M_PKTHDR`/`pkthdr.len` 缺口（sosend 在 `uio==NULL` 分支以 `top->m_pkthdr.len` 作 resid，缺则 resid=0 不发送任何数据）|
| G4 | 保持外部 ABI 不变：`ff_zc_send` / `ff_zc_mbuf_get` / `ff_zc_mbuf_write` 函数签名与 example/main_zc.c 调用序列**零修改**；`FF_ZC_SEND` Makefile 开关名保留（仅含义切换）|
| G5 | 与 `kern_zc_recvit` 形成完全对称的"用户态零拷贝栈"（API 形态、生命周期、错误路径、ABI 增量、Makefile 开关）|
| G6 | 性能与现魔改方案 Δ ≤ ±3%（噪声内）；功能 example curl http=200 PASS |

---

## §3 范围（scope）

### §3.1 In-scope（本期 spec 必须覆盖）

| 模块 | spec 文档 |
|---|---|
| 现状测绘与拆除清单 | 31-current-state-and-removal.md |
| 对称架构设计 | 32-native-arch-design.md |
| 内核 patch 详规（含锚点） | 33-kernel-patch-spec.md |
| 用户态 API 规格（ABI 不变 + M_PKTHDR 修复）| 34-userspace-api-spec.md |
| mbuf 链所有权状态机 + 不变量 | 35-mbuf-lifecycle-spec.md |
| 边界与回退矩阵（TCP/UDP/SCTP/ATOMIC/NBIO/SCM/aio/PAGE_ARRAY 等）| 36-boundary-and-fallback-spec.md |
| CMocka 测试规格 | 37-test-spec.md |
| 性能基线规格（wrk + 大 payload）| 38-perf-baseline-spec.md |
| 已部署项目迁移指南 | 39-migration-guide.md |
| 验收 + M0-M5 里程碑 | 40-acceptance-and-milestones.md |
| 门禁审核与 bounce counter | 49-spec-review.md |

### §3.2 Out-of-scope（本期不处理）

- 实施代码（本期 spec only，实施期独立 plan 启动）。
- ZC-recv（kern_zc_recvit/mp0）已落地，本 spec 仅在"对称参考"小节复用其模式；不重写 11-17 系列既有 ZC-recv spec。
- `FF_USE_PAGE_ARRAY`（协议栈 → DPDK 阶段一零拷贝）：与本 spec 无直接耦合，仅在 36 边界矩阵中出现。
- 英文版文档：人工审计后再议。

---

## §4 术语（Glossary）

| 术语 | 定义 / 锚点 |
|---|---|
| **ZC-send（zero-copy send）** | 应用层 → 协议栈方向的零拷贝发送，对应 `FSTACK_ZC_SEND` 编译开关 |
| **ZC-recv（zero-copy receive）** | 协议栈 → 应用层方向的零拷贝接收，对应 `FSTACK_ZC_RECV` 编译开关 |
| **FSTACK_ZC_MAGIC（旧）** | `((off_t)0xF8AC2C00F8AC2C00LL)`，freebsd/sys/mbuf.h:1868；本 spec 删除 |
| **`top` 参数** | `sosend()` 第 4 参（`struct mbuf *top`），uipc_socket.c:2600；FreeBSD 原生零拷贝发送入口 |
| **`mp0` 参数** | `soreceive()` 第 4 参（`struct mbuf **mp0`）；FreeBSD 原生零拷贝接收出参 |
| **kern_zc_sendit** | 本 spec 新增内核函数，sousrsend 的零拷贝兄弟函数（`top!=NULL` 路径） |
| **kern_zc_recvit** | 已落地（uipc_syscalls.c:1049），kern_recvit 的零拷贝兄弟函数（`mp0!=NULL` 路径）|
| **ff_zc_mbuf** | `struct ff_zc_mbuf { void *bsd_mbuf; void *bsd_mbuf_off; int off; int len; }`，ff_api.h:347 |
| **PR_ATOMIC** | protosw 标志，要求一次性投递（UDP/SCTP/UNIX dgram）；详见 36 |
| **bounce counter** | 单步骤打回计数，门禁失败计入；上限 3 次（per memory rule 86071475）|

---

## §5 决策表（用户已确认 C+A+A）

| 决策项 | 选择 | 含义 | 影响 spec |
|---|---|---|---|
| 范围（scope） | **C** | 完整"用户态零拷贝栈" spec | 33-40 全集，含 ZC-recv 对称参考小节 |
| 旧路径处置（compat） | **A** | 立即拆除 | 31 删除清单 + 33 内核 patch 同期生效 |
| 改名时机（rename） | **A** | plan 第一步 git mv + 修复 self-ref | S1 已完成 |

---

## §6 与既有文档关系

```
docs/zc_stack_user_spec/zh_cn/
├── 00-09 可行性研究（PRESERVED，commit 875532e35）
├── 10-19 ZC-recv 首版 spec（PRESERVED，commit e62afc541）
├── 20-22 实施期产物（20 执行 plan / 21 M2 测试报告 / 22 native ZC-send 调研）
│        ↑ 本 spec 直接前置（22 的结论"是—— sosend(top) 原生支持"）
├── 29 本期 spec 阶段 plan
├── 30 本文件
├── 31-40 ZC-send 原生化 spec（本期新增）
└── 49 门禁审核记录
```

22-research（commit 0294a9baa）已实测验证 sosend `top` 在 FreeBSD 15.0 区段无任何 `FSTACK_*` 魔改、`uio==NULL` 时跳过 `m_uiotombuf` 拷贝、resid 取自 `top->m_pkthdr.len`（uipc_socket.c:2341/2170）—— 是 30+ 系列 spec 的**全局技术前提**。

---

## §7 强制规约（贯穿全 spec 阶段）

1. **实测优先**：每条 spec 条目须有 `file:line:symbol` 实测来源；外网仅交叉验证；冲突以代码为准。
2. **harness 多 agent 门禁回退**（memory 86071475）：单步骤打回循环上限 3 次，第 4 次失败立即停止任务转人工。
3. **rm/kill/chmod 走脚本**（memories 81725399 / 90098233 / 21626578）：所有 shell 命令字符串严禁直接 `rm`/`kill`/`pkill`/`killall`/`chmod`/`setfacl`/`install -m`/`find -delete`/`shred`；统一走 `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`；**spec 文档示例同样遵守**。
4. commit message 英文（memory 73362122），对话中文。
5. spec 不得提供"如何 patch"的可执行命令；必须提供 c-precision-surgery 风格的"行号 + 上下文锚点"，由实施期 agent 转换为 patch。

---

## §8 阅读路径建议

| 角色 | 顺序 |
|---|---|
| 设计审计者 | 30 → 31 → 32 → 35 → 36 → 40 |
| 内核实现工程师 | 30 → 32 → 33 → 35 → 36 |
| 用户态实现工程师 | 30 → 32 → 34 → 35 → 39 |
| QA / 测试工程师 | 30 → 35 → 36 → 37 → 38 → 40 |
| 上游迁移工程师 | 30 → 39 → 40 |

下一篇：**31-current-state-and-removal.md**（现状测绘 + 5 处删除清单）。
