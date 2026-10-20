# 29. 用户态零拷贝栈 spec 阶段 plan（ZC-send 原生化）

> 阶段：本期仅产出 spec 文档，不实现代码
> 目录：仅中文（`docs/zc_stack_user_spec/zh_cn/`，由原 `zc_read_spec` 改名而来）
> 前置：22-native-zc-send-research（已确认 sosend(top) 是 FreeBSD 15.0 原生路径）
> 目标 commit msg：英文（per memory rule）

---

## §1 目标

为 f-stack 新增对称的 `kern_zc_sendit`（调 `sosend(uio=NULL, top=mbuf 链)`）原生发送端零拷贝接口，**替换**现有 `FSTACK_ZC_MAGIC` + `m_uiotombuf` 内核魔改方案，与已实现的 `kern_zc_recvit`（soreceive `mp0` 出参）形成完全对称的"用户态零拷贝栈"。

### §1.1 关键决策（来自需求澄清）

| 决策项 | 选择 | 含义 |
|---|---|---|
| 范围（scope） | **C** | 完整"用户态零拷贝栈" spec：ZC-send 原生化 + ZC-recv 对称整合 + 测试规格 + 性能基线规格 + 迁移指南 |
| 旧路径处置（compat） | **A** | 立即拆除：新方案合入即同期删除 `FSTACK_ZC_MAGIC` 宏与 `m_uiotombuf` 内核 patch |
| 改名时机（rename） | **A** | plan 第一步 `git mv` + 修复 self-reference，新 spec 直接落到新目录 |

---

## §2 强制规约（贯穿全期，与既有规约并列生效）

1. **实测优先**：每条 spec 条目必须有 `file:line:symbol` 实测来源；外网资料只做交叉验证；冲突以代码为准。
2. **Harness 多 agent 门禁回退（memory 86071475）**：任一阶段门禁失败打回上一步，**单步骤循环上限 3 次**，第 4 次失败立即停止任务转人工决策。
3. **rm/kill/chmod 走脚本（memories 81725399 / 90098233 / 21626578）**：
   - 所有 shell 命令字符串（含 ssh 远程命令、sed/awk 内嵌脚本、Makefile 片段）严禁直接 `rm`/`pkill`/`kill`/`killall`/`chmod`/`setfacl`/`install -m`/`find -delete`/`shred`；
   - 统一走 `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`；
   - **本期 spec 文档示例代码同样遵守**（不能在 spec 里给出 `rm` 等命令）。
4. **commit message 英文**（memory 73362122），对话中文。

---

## §3 文档清单（`docs/zc_stack_user_spec/zh_cn/`，30+ 系列为本期新增）

| # | 文档 | 责任子 agent |
|---|---|---|
| 29-plan.md | 本期 plan（本文件）| Leader |
| 30-spec-overview.md | 总览 / 范围 / 术语 / 决策表 | spec-writer |
| 31-current-state-and-removal.md | 现有 ZC-send 魔改 5 处全图 + 拆除清单 + 对外行为不变性证明 | probe-zcsend-current → spec-writer |
| 32-native-arch-design.md | 新对称架构（kern_zc_sendit ↔ kern_zc_recvit 镜像） | probe-sosend-native + probe-zcrecv-symmetry → spec-writer |
| 33-kernel-patch-spec.md | 内核改动详规 | probe-sosend-native → spec-writer |
| 34-userspace-api-spec.md | ff_zc_send 重写 + ff_zc_mbuf_get 加 M_PKTHDR + ff_zc_mbuf_write 维护 pkthdr.len | probe-zcsend-current → spec-writer |
| 35-mbuf-lifecycle-spec.md | mbuf 链所有权状态机 + 不变量 INV1-3 | probe-sosend-native → spec-writer |
| 36-boundary-and-fallback-spec.md | TCP/UDP/SCTP/PR_ATOMIC/EWOULDBLOCK/SIGPIPE/SCM/aio/PAGE_ARRAY 边界矩阵 | spec-writer |
| 37-test-spec.md | CMocka 单元 + 集成测试规格（继承 16 风格）| spec-writer |
| 38-perf-baseline-spec.md | wrk T1/T2/T3 + 大 payload 自定义 client + 单核 cvm | spec-writer |
| 39-migration-guide.md | 已部署项目升级路径（含 `make clean` 必要性）| spec-writer |
| 40-acceptance-and-milestones.md | AC + M0-M5 里程碑 | spec-writer |
| 49-spec-review.md | 门禁审核记录 + bounce counter | gatekeeper |

---

## §4 执行阶段（8 步，按 plan todolist 推进）

| # | 阶段 | 关键产物 | 依赖 |
|---|---|---|---|
| S1 | 改名 + 修复 self-ref + 落 plan | 本文件 + lib/ff_veth.c 注释同步 | — |
| S2 | 并行架构探测（3 子 agent）| probe-zcsend-current / probe-sosend-native / probe-zcrecv-symmetry 三份中文报告 | S1 |
| S3 | 外网交叉验证 | research-ext-zcsend 报告 | S1 |
| S4 | 编写 30/31/32 三篇 + gatekeeper | 总览 + 现状拆除 + 对称架构 spec | S2/S3 |
| S5 | 编写 33/34/35 三篇 + gatekeeper | 内核 patch + API + 生命周期 spec | S4 |
| S6 | 编写 36/37/38 三篇 + gatekeeper | 边界 + 测试 + 性能 spec | S5 |
| S7 | 编写 39/40 两篇 + gatekeeper | 迁移指南 + AC | S6 |
| S8 | 终审 + 49 审核记录 + 整批 commit | 49-spec-review + 1 个 commit | S7 |

每阶段产出落盘后立即过 gatekeeper 抽检；不通过则计入 bounce counter 打回 spec-writer 修订；同步骤打回 ≥3 次即停止任务。

---

## §5 Agent Team 拓扑

```
Leader（主对话，本 agent）
├── probe-zcsend-current  [code-explorer, READ-ONLY]
├── probe-sosend-native   [code-explorer, READ-ONLY]
├── probe-zcrecv-symmetry [code-explorer, READ-ONLY]
├── research-ext-zcsend   [web_search + web_fetch]
├── spec-writer           [Leader 串行调用，每篇独立 task]
└── gatekeeper            [code-explorer + grep]
```

Leader 职责：阶段调度、bounce counter、门禁裁决、文档落盘、commit。

---

## §6 关键技术决策预览（详见 32/33/34 spec）

### §6.1 内核入口：直接调 sosend，而非 sousrsend

实测 `sousrsend`（uipc_socket.c:2615）内 `pr_sosend(..., uio, NULL, ...)` 第 4 参 top 写死 NULL → sousrsend 不可复用。新 `kern_zc_sendit` 直接调 `sosend(so, addr, NULL, top, control, flags, td)`（uipc_socket.c:2599），与 `kern_zc_recvit` 直调 `soreceive` 完全对称。

### §6.2 ff_zc_mbuf_get/write 必修缺口

实测：
- `ff_zc_mbuf_get`(ff_veth.c:306) 用 `m_getm2(NULL, len, M_WAITOK, MT_DATA, /*flags*/0)` —— 不带 `M_PKTHDR`；
- `ff_zc_mbuf_write`(ff_veth.c:326) 中 `pkthdr.len` 累加被注释掉。

后果：sosend 在 `uio == NULL` 分支用 `top->m_pkthdr.len` 作 resid → 现状下 `resid=0` → 立即返回 0 字节。spec 强制规定修复：
- `m_getm2(NULL, len, M_WAITOK, MT_DATA, M_PKTHDR)`；
- ff_zc_mbuf_write 在链首维护 `((struct mbuf *)zm->bsd_mbuf)->m_pkthdr.len += length`。

### §6.3 旧路径删除清单（详见 31）

| 文件 | 行 | 处置 |
|---|---|---|
| `freebsd/sys/mbuf.h` | 1856-1868 | 整段删除（FSTACK_ZC_MAGIC 宏） |
| `freebsd/kern/uipc_mbuf.c` | 2028-2070 | 整段删除（m_uiotombuf #ifdef FSTACK_ZC_SEND 分支） |
| `freebsd/kern/sys_generic.c` | 560-569 | 整段删除（kern_writev uio_offset 保留逻辑） |
| `lib/ff_syscall_wrapper.c` | 1146 / 1186-1226 | 删 opt-out + 重写 ff_zc_send |

### §6.4 错误路径所有权（详见 35）

默认契约：成功时 sosend 接管 top → app 不得再用；错误时由 `kern_zc_sendit` 调 `m_freem(top)` 兜底（避免 protosw 不一致）。

---

## §7 验收预览（详见 40）

| AC | 条款 |
|---|---|
| AC1 编译 | 默认 + `FF_ZC_SEND=1` + `FF_ZC_RECV=1` 三种组合 `-Werror` clean |
| AC2 功能 | example/main_zc.c 不修改，curl http=200 PASS |
| AC3 性能 | wrk T1/T2/T3 与现魔改方案 Δ ≤ ±3%（噪声内）|
| AC4 内核 diff | 相比 vanilla FreeBSD 15.0，仅新增 `kern_zc_sendit` + `kern_zc_recvit` 两个新函数（无 `m_uiotombuf` 修改）|

---

> 本期 spec 完成后，下一阶段（实现期）将依据 33/34/35 落 patch、依据 37 写测试、依据 38 跑基线、依据 40 完成验收。
