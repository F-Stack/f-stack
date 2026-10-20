# FSTACK_ZC_RECV 零拷贝收包 实现级 Spec — Plan

> 状态：PLAN-READY →（执行）BUILDING → FINISHED
> 前置：可行性调研已通过（docs/zc_stack_user_spec/zh_cn/00-09，结论"可行"，commit 875532e35）
> 本阶段范围：产出**实现级规格文档**（spec），指导后续编码；**本阶段仍不写实现代码**
> 文档语言：仅中文（docs/zc_stack_user_spec/zh_cn/）
> 方法：harness 工程 + spec 驱动 + agent team（leader + 架构探测/文档编写/spec 审核门禁子 agent）
> 铁律：所有规格条目以**实测代码为准**，外网/文档仅启发；不一致以代码为准；严禁未执行即给结论

---

## §1 目标
基于可行性结论（推荐方案A：复用 soreceive 的 `mp0` 出参），产出可直接指导实现的零拷贝收包规格：架构设计、内核 patch 详规、用户态 API 契约、mbuf 生命周期状态机、边界与回退矩阵、CMocka 测试规格、验收标准与里程碑。

## §2 Phase 0 spec 级实测补充（已完成）
> 在可行性调研（01-09）基础上，本阶段新增以下实测依据：

| 项 | 实测 | 用途 |
|---|---|---|
| 编译开关范式 | `lib/Makefile:210-212  ifdef FF_ZC_SEND → CFLAGS+=-DFSTACK_ZC_SEND` | 对称定义 `FF_ZC_RECV→-DFSTACK_ZC_RECV` |
| kern_recvit 签名 | `uipc_syscalls.c:895 kern_recvit(td,s,mp,fromseg,controlp)`；soreceive 第4参=NULL（L948）| 内核 patch 点 |
| read() 路径 | `sys_socket.c:122 soo_read → soreceive(so,0,uio,0,0,0)`（L133，mp0=0）| 内核 patch 点（read 亦需）|
| 示例调用序列 | `example/main_zc.c`：ff_zc_mbuf_get→ff_zc_mbuf_write(可多次)→ff_zc_send（L185-220）| 对称设计 recv 示例规格 |
| 测试现状 | tests/ 下**无** ff_zc_* 测试 | 测试规格为 greenfield，需新建 |

（其余实测见 01-05，本 plan 不重复。）

## §3 Spec 文档清单（docs/zc_stack_user_spec/zh_cn/，新增 10-19 系列）
| 文档 | 内容 | 负责子 agent |
|---|---|---|
| `10-spec-overview.md` | 范围/术语/目标/与可行性结论衔接/编译开关 FSTACK_ZC_RECV | leader |
| `11-architecture-design.md` | 分层架构（用户态 API ↔ 内核 mp 贯通 ↔ soreceive mp0 ↔ ext-mbuf）+ 数据流图 | spec-writer-arch |
| `12-kernel-patch-spec.md` | 内核改动详规：kern_recvit/kern_zc_recvit 变体 + soo_read 透传 + FSTACK_ZC_RECV 宏；改动点/前后对比/不破坏现有 recv 的约束 | spec-writer-kernel |
| `13-userspace-api-spec.md` | API 契约：ff_zc_recv / ff_zc_mbuf_read 重写 / ff_zc_recv_free；struct ff_zc_mbuf 复用语义；错误码/参数/返回值 | spec-writer-api |
| `14-mbuf-lifecycle-spec.md` | mbuf 所有权状态机（sockbuf→APP→release）+ refcnt 契约 + 泄漏防护 + 时序图 | spec-writer-life |
| `15-boundary-and-fallback-spec.md` | 边界矩阵详规（整/split/PEEK/WAITALL/DONTWAIT/OOB/SCM/TLS/UDP）+ 回退策略 | spec-writer-arch |
| `16-test-spec.md` | CMocka 测试规格（参考 c-unittest-expert 方法论，API 换 CMocka）：用例命名/setup-teardown/断言粒度/边界覆盖/mock 策略 | spec-writer-test |
| `17-acceptance-and-milestones.md` | 验收标准（功能/性能/内存安全/兼容）+ M0-M5 里程碑 + DoD | leader |
| `19-spec-review.md` | spec 审核门禁（4 维 + 可实现性 + 自洽性 + 引用真实性）| gatekeeper |

## §4 Agent Team 拓扑
| 角色 | 职责 | 模式 |
|---|---|---|
| **leader（主 agent）** | 统筹/分发/汇总/门禁裁决/落盘 10/17/收尾 commit | 主 agent |
| **probe-spec**（架构探测·async code-explorer）| 补充 spec 级实测（kern_recvit 调用方、soo_read、msghdr 流、m_freem、mbuf flags），确保规格条目可溯源 | 只读 |
| **spec-writer-kernel** | 编写 12 内核 patch 详规 | 串行 |
| **spec-writer-api** | 编写 13 用户态 API 规格 | 串行 |
| **spec-writer-life** | 编写 14 生命周期状态机 | 串行 |
| **spec-writer-arch** | 编写 11 架构 + 15 边界矩阵 | 串行 |
| **spec-writer-test** | 编写 16 CMocka 测试规格（参考 c-unittest-expert）| 串行 |
| **gatekeeper** | 19 审核门禁：引用真实性/行号吻合/可实现性/自洽性/无臆测，任一不过打回重写 | 串行 |

**失败回滚 SOP**：gatekeeper 不通过 → 打回对应 spec-writer 重写；发现与代码矛盾 → 以代码为准并标注。

## §5 Phase Schedule
- **P0** spec 级实测补充（✅ 见 §2）
- **P1** 文档骨架落盘（10-19 系列骨架）
- **P2** 架构探测补证（probe-spec，确保 12/13/14 的内核/调用引用可溯源）
- **P3** 串行编写 11/12/13/14/15/16（各 spec-writer）
- **P4** 落盘 10 overview + 17 acceptance/milestones
- **P5** gatekeeper 审核门禁（19）；不过回滚 P3
- **P6** 收尾 commit（简洁英文 message）

## §6 验收门禁（本 spec 的 acceptance gate）
| Gate | 内容 |
|---|---|
| G-SPEC-1 | 所有内核/代码引用 file:line:symbol 经实测核对，gatekeeper 抽检 100% 命中 |
| G-SPEC-2 | 内核 patch 详规给出 read()+recv() 两条路径的改动点 + 不破坏现有 recv 的约束论证 |
| G-SPEC-3 | API 契约完整（签名/参数/返回/错误码/调用序列/误用防护）|
| G-SPEC-4 | mbuf 生命周期状态机闭环（无 use-after-free / 无泄漏 / 无双重 free 的状态论证）|
| G-SPEC-5 | 边界矩阵 + 回退策略覆盖全场景 |
| G-SPEC-6 | CMocka 测试规格可落地（命名/setup-teardown/断言/边界/mock）|
| G-SPEC-7 | 编译开关 FSTACK_ZC_RECV 与现有 FSTACK_ZC_SEND 范式一致 |
| G-SPEC-8 | 仅中文；无臆测（凡条目溯源到代码或标注"实现期验证"）|

## §7 范围与约束
**In-scope**：实现级规格文档（架构/内核/API/生命周期/边界/测试/验收）。
**Out-of-scope（本期不做）**：实现代码、内核 patch 落地、实际测试编译运行、性能压测、英文文档。
**工作区规约**：rm→rm_tmp_file.sh；kill→kill_process.sh；chmod→chmod_modify.sh；make install 等非直接 chmod 可执行。commit message 英文。
**测试方法论**：CMocka，参考 c-unittest-expert（Unity-based 思路通用，API 换 CMocka：assert_int_equal 等）。

## §8 风险
| 风险 | 缓解 |
|---|---|
| spec 条目脱离实际代码 | 每条内核/API 规格强制 file:line 溯源；gatekeeper 抽检 |
| read()/recv() 两路径遗漏 | 12 强制覆盖 soo_read(sys_socket.c:133) + kern_recvit(uipc_syscalls.c:948) |
| 生命周期状态机不闭环 | 14 用状态机 + 时序图 + 03 实测 refcnt 链支撑 |
| 测试规格不可落地 | 16 对齐现有 tests/unit 框架（cmocka + Makefile per-target 范式）|
