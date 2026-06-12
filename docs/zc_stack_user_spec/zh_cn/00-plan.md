# FSTACK_ZC_RECV（零拷贝 read）可行性调研 — Plan

> 状态：PLAN-READY → （待执行）BUILDING → FINISHED
> 范围：**仅可行性调研 + 方案设计 + 文档产出**，本期不写实现代码
> 对标基线：已落地的 FSTACK_ZC_SEND（M8）
> 文档语言：**仅中文**（docs/zc_stack_user_spec/zh_cn/），英文版待人工审计后再议
> 方法：harness 工程 + spec 驱动 + agent team（leader + 子 agent）
> 防漂移铁律：所有结论以**实测代码为准**，文档/外网仅作启发，不一致处以代码为准；严禁未执行即给结论

---

## §1 背景与目标

f-stack 已支持零拷贝**写入**（FSTACK_ZC_SEND / M8）：APP 通过 `ff_zc_mbuf_get`+`ff_zc_mbuf_write` 直接填充 BSD mbuf 链，再用 `ff_zc_send` 经 `FSTACK_ZC_MAGIC` 哨兵让内核 `m_uiotombuf` 跳过拷贝直接挂载 mbuf。

本调研目标：评估对称地支持零拷贝**读取**（暂命名 FSTACK_ZC_RECV）的可行性 —— 让 APP 直接拿到 socket 接收缓冲区中的 BSD mbuf 链（其数据已零拷贝指向 DPDK mbuf），消除 `soreceive → uiomove` 这唯一的 mbuf→用户 buffer 拷贝。

**交付物**：可行性结论（可行/部分可行/不可行 + 依据）、内核与用户态方案设计、API 设计、生命周期/所有权方案、风险与工作量评估、后续实现里程碑建议。

---

## §2 Phase 0 实测侦察结论（已完成，代码为准）

> 下列均为本阶段 grep/read 实测，非推测。行号以当前工作树为准。

### 2.1 ZC-SEND 对标基线（已落地 M8）
| 项 | 位置 | 说明 |
|---|---|---|
| 数据结构 | `ff_api.h:347` | `struct ff_zc_mbuf{ void *bsd_mbuf; void *bsd_mbuf_off; int off; int len; }` |
| 申请 mbuf | `ff_veth.c:306` | `ff_zc_mbuf_get(m,len)` |
| 写入 mbuf | `ff_veth.c:326` | `ff_zc_mbuf_write(zm,data,len)`（bcopy 进 M_TRAILINGSPACE）|
| 发送入口 | `ff_syscall_wrapper.c:1199` | `ff_zc_send(fd,mb,nbytes)` 设 `uio_offset=FSTACK_ZC_MAGIC`→`kern_writev` |
| 内核 hook | `freebsd/kern/uipc_mbuf.c:2028-2046` | `#ifdef FSTACK_ZC_SEND` 检测 magic→挂载 mbuf 跳过拷贝 |
| 哨兵 | `freebsd/sys/mbuf.h:1868` | `FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)` |
| 编译开关 | `lib/Makefile:212` | `CFLAGS+= -DFSTACK_ZC_SEND` |
| 防误触 | `ff_syscall_wrapper.c:1151/1175` | 普通 `ff_write/ff_writev` 显式 `uio_offset=0` opt-out |
| 示例 | `example/main_zc.c` | — |

### 2.2 ZC-READ 现状（目标埋点）
- `ff_veth.c:359  ff_zc_mbuf_read(...)` = **空 stub**（`// DOTO: Support read zero copy; return 0;`）
- `ff_api.h:400` 声明，注释 "not implemented now"
- **缺失**：`ff_zc_recv` 入口、`FSTACK_ZC_RECV` 宏、Makefile 开关、release/consume API

### 2.3 RX 侧零拷贝基础（已存在 = 利好）
- `ff_mbuf_gethdr`（ff_veth.c）用 `m_extadd(m,data,len,ff_mbuf_ext_free,pkt,...,EXT_DISPOSABLE)` 把 DPDK mbuf 数据零拷贝挂为 external mbuf；`ff_mbuf_ext_free` 负责归还 DPDK mbuf。
- 结论：**NIC→DPDK mbuf→BSD mbuf(ext) 已零拷贝；唯一拷贝点在 soreceive→uiomove**。

### 2.4 READ 路径与对称 hook 点
- 用户入口：`ff_read`(1077)/`ff_readv`(1105)/`ff_recv`(1313)/`ff_recvfrom`(1319)/`ff_recvmsg`(1359) → `kern_readv`/`kern_recvit`
- 内核拷贝点：`freebsd/kern/uipc_socket.c soreceive_generic_locked`(L2744) 内 `uiomove(mtod(m,...),len,uio)`(L3031)
- **关键利好**：`soreceive_generic(so,psa,uio,mp0,controlp,flagsp)` 原生带 `mp0` 出参——`mp0!=NULL` 时 FreeBSD 把 sockbuf mbuf 直接交出而不 uiomove，是 ZC-read 的天然内核机制候选。

---

## §3 待调研的关键设计问题（Phase 2-3 回答，禁止臆测）

1. **内核机制选型**：复用 `soreceive` 的 `mp0` 出参（FreeBSD 原生，改动小）vs 仿 send 的 `FSTACK_ZC_MAGIC` 哨兵 hook（与 send 对称）。优劣、改动面、风险对比。
2. **mbuf 所有权/生命周期**：APP 持有 ext-mbuf 期间，DPDK 原始 mbuf 何时归还？`m_ext` refcount 与 `ff_mbuf_ext_free` 如何协同，避免 use-after-free 或提前回收。
3. **API 形态**：现 `ff_zc_mbuf_read(struct ff_zc_mbuf*, const char *data, int len)` 的 `const char*data` 与"读出"语义矛盾，需重新设计；是否新增 `ff_zc_recv(fd, struct ff_zc_mbuf*, len)`。
4. **释放语义**：对称于 send 的 get/write/send，read 侧需 receive→consume→release 三段；APP 读完如何显式归还 mbuf 链。
5. **sockbuf 记账**：soreceive 取走 mbuf 后 `sbfree`/`sb_cc` 记账与窗口更新。
6. **边界**：MSG_PEEK / MSG_WAITALL / 非阻塞 / 半包 / 跨多 mbuf / 控制消息(SCM_RIGHTS 等) / OOB。
7. **与 LD_PRELOAD ring 模式、FF_USE_PAGE_ARRAY 的关系与冲突**。
8. **性能预期与适用场景**（大包收取、代理转发、splice 等）+ 不适用场景。

---

## §4 Agent Team 拓扑（leader + 子 agent，harness+spec）

> 执行采用混合模式：探测阶段并行 spawn 多个 code-explorer 子 agent，设计/审核阶段串行。

| 角色 | 职责 | 工具/模式 |
|---|---|---|
| **leader（主 agent）** | 统筹、任务分发、结果汇总、门禁裁决、文档落盘、回滚决策 | 主 agent |
| **probe-zcsend** | 测绘 ZC-SEND 全链路（API→syscall→m_uiotombuf→sbappend）作"对标基线" | async code-explorer（只读）|
| **probe-recvpath** | 测绘 READ 全链路（ff_recv*→kern_recvit→soreceive_generic_locked→uiomove/mp0 路径）+ sockbuf 记账 | async code-explorer（只读）|
| **probe-extmbuf** | 测绘 RX 侧 ext-mbuf 生命周期（ff_mbuf_gethdr/m_extadd/ff_mbuf_ext_free/refcount/DPDK mbuf 归还） | async code-explorer（只读）|
| **research-ext** | 外网调研（GitHub F-Stack issue/PR/wiki、DPDK 文档、FreeBSD soreceive/mp0 资料、相关博客/公众号）→ 启发但需代码验证 | web_search/web_fetch |
| **design-arch** | 综合产出方案设计（内核机制选型 + API + 生命周期 + 边界）| 串行（leader 调度）|
| **gatekeeper** | 文档审核门禁：每篇文档对照"实测代码引用是否真实存在、行号/符号是否吻合、结论是否有依据、是否存在臆测" 4 维校验，任一不过打回 design/probe 重做 | 串行 |

**失败回滚 SOP**：gatekeeper 不通过 → 打回对应 probe/design 子 agent 重新取证/重写；probe 发现与文档矛盾 → 以代码为准并标注修正。

---

## §5 Phase Schedule

| Phase | 名称 | 产物 | 子 agent |
|---|---|---|---|
| **P0** | 实测侦察（✅ 已完成，见 §2） | 本 plan §2 | leader |
| **P1** | 文档骨架落盘 | `00-plan.md`(本文) / `01-zcsend-baseline.md` / `02-recv-path-analysis.md` / `03-extmbuf-lifecycle.md` / `04-external-research.md` / `05-design-and-feasibility.md` / `09-review.md` 骨架 | leader |
| **P2** | 并行架构探测 | 填充 01/02/03（全部实测代码引用 + 行号交叉验证） | probe-zcsend / probe-recvpath / probe-extmbuf |
| **P3** | 外网调研 | 填充 04（GitHub/DPDK/FreeBSD/博客，标注与代码一致性） | research-ext |
| **P4** | 方案设计 | 填充 05（内核机制选型对比 + API 设计 + 生命周期方案 + 边界矩阵 + 风险 + 工作量 + 里程碑建议 + 可行性结论） | design-arch |
| **P5** | 文档审核门禁 | 09-review（4 维校验结果）；不过则回滚 P2/P4 | gatekeeper |
| **P6** | 收尾 | 汇总结论；本地 commit（简洁英文 message） | leader |

---

## §6 文档清单（docs/zc_stack_user_spec/zh_cn/，仅中文）

- `00-plan.md` —— 本规划
- `01-zcsend-baseline.md` —— ZC-SEND 对标基线全链路
- `02-recv-path-analysis.md` —— READ 路径 + soreceive/mp0 + sockbuf 记账分析
- `03-extmbuf-lifecycle.md` —— RX ext-mbuf 生命周期与所有权
- `04-external-research.md` —— 外网资料调研与交叉验证
- `05-design-and-feasibility.md` —— 方案设计 + 可行性结论 + 风险/工作量/里程碑
- `09-review.md` —— 文档审核门禁记录

---

## §7 验收门禁（本调研的 acceptance gate）

| Gate | 内容 |
|---|---|
| G-ZCR-1 | 所有代码引用（文件:行号:符号）均经实测核对真实存在，gatekeeper 抽检 100% 命中 |
| G-ZCR-2 | 内核机制选型给出 ≥2 方案对比（mp0 复用 vs ZC_MAGIC 对称 hook）+ 明确推荐 |
| G-ZCR-3 | mbuf 生命周期/所有权方案闭环（无 use-after-free / 无泄漏的论证）|
| G-ZCR-4 | 边界矩阵覆盖 §3.6 全部场景 |
| G-ZCR-5 | 给出明确可行性结论（可行/部分可行/不可行）+ 工作量与里程碑建议 |
| G-ZCR-6 | 外网资料与代码不一致处，明确以代码为准并标注 |
| G-ZCR-7 | 仅中文文档；无臆测表述（凡结论可溯源到代码或标注"待实现验证"）|

---

## §8 范围与约束

**In-scope**：可行性调研、方案/API/生命周期设计、风险与工作量评估、文档产出。
**Out-of-scope（本期不做）**：实现代码、内核 patch、单元/集成测试、性能压测、英文文档。
**工作区规约**：删除→`rm_tmp_file.sh`；终止进程→`kill_process.sh`；改权限→`chmod_modify.sh`；`make install` 等非直接 chmod 命令可执行。commit message 英文。

---

## §9 风险

| 风险 | 缓解 |
|---|---|
| soreceive mp0 路径在 f-stack 改造内核中可能已被改动 | P2 probe-recvpath 必须实测 f-stack 版 uipc_socket.c，不假设原生 FreeBSD 行为 |
| ext-mbuf refcount 与 DPDK mbuf 归还时序复杂 | P2 probe-extmbuf 专项 + P4 生命周期闭环论证 |
| 外网资料过时/与 f-stack 分支不符 | 一律以实测代码为准，外网仅启发 |
| 子 agent 产出含臆测 | gatekeeper 4 维门禁，未溯源即打回 |
