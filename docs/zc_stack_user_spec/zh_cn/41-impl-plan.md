# 41. 发包零拷贝（用户态 → 协议栈）原生化 —— 实施期 plan

> 阶段：实施期（spec 30-40 已就绪并经 gatekeeper PASS）
> 模式：harness 工程 + spec 驱动 + agent team（leader + 子 agent）
> 目标：把 `FSTACK_ZC_SEND` 从 `FSTACK_ZC_MAGIC + m_uiotombuf` 魔改切换为
>       FreeBSD 原生 `sosend(uio=NULL, top=链)` 路径（新增对称 `kern_zc_sendit`），
>       消除 m_uiotombuf 内核 patch，降低误触与升级维护成本。
> 强制规约：DP-10（rm/kill/chmod 一律走 `/data/workspace/{rm_tmp_file,kill_process,chmod_modify}.sh`）；
>           实测优先、禁止臆测；门禁失败打回上一步，单步打回 ≤3 次，超限停人工决策。

---

## §0 Phase-0 实测侦察结论（已完成，全部 file:line 实测，代码为准）

### 0.1 现有 5 处魔改触点（确认与 31-spec 一致）

| # | 文件 | 实测行 | 现状 | 处置 |
|---|---|---|---|---|
| 1 | `freebsd/sys/mbuf.h` | 1856-1869 | `#ifdef FSTACK_ZC_SEND` + `#define FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)` | DELETE |
| 2 | `freebsd/kern/uipc_mbuf.c` | 1955-2077 | `#ifndef FSTACK`(vanilla 15.0) / `#else`(13.0 简化版+ZC 分支) / `#endif` 包裹 m_uiotombuf | RESTORE→vanilla |
| 3 | `freebsd/kern/uipc_mbuf.c` | 2028-2049,2070-2072 | m_uiotombuf 内 `#ifdef FSTACK_ZC_SEND` 快路径 | DELETE（随 #2）|
| 4 | `freebsd/kern/sys_generic.c` | 57 | `#include <sys/mbuf.h> /* M8 */` | 视依赖删除 |
| 5 | `freebsd/kern/sys_generic.c` | 560-573 | dofilewrite `#ifdef FSTACK_ZC_SEND` uio_offset 守护 | DELETE→单行 |
| 6 | `lib/ff_syscall_wrapper.c` | 1146-1151 | ff_write `auio.uio_offset = 0;` opt-out + 注释 | DELETE |
| 7 | `lib/ff_syscall_wrapper.c` | 1175 | ff_writev `auio.uio_offset = 0;` | DELETE |
| 8 | `lib/ff_syscall_wrapper.c` | 1186-1226 | 旧 ff_zc_send（构造 uio + MAGIC + kern_writev）| REWRITE |
| 9 | `lib/ff_veth.c` | 306-323 | ff_zc_mbuf_get `m_getm2(...,MT_DATA,0)` 无 M_PKTHDR | REWRITE +M_PKTHDR |
| 10 | `lib/ff_veth.c` | 325-356 | ff_zc_mbuf_write 注释掉 pkthdr.len 累加(L349-350) | REWRITE 维护 pkthdr.len |

### 0.2 原生 sosend(top) 入口（确认）
- `kern_zc_recvit` 实测在 `uipc_syscalls.c:1064-1108`，紧随 `#endif /* FSTACK_ZC_RECV */`(L1109) —— `kern_zc_sendit` 对称插入点。
- `syscallsubr.h:304-310` 为 `kern_zc_recvit` 声明，新声明插其后(L310 之后)。
- `kern_sendit` 模式实测：`getsock(td, s, &cap_send_rights, &fp)`(L745/750) + `mac_socket_check_send`(L770) —— `kern_zc_sendit` 复用。

### 0.3 m_uiotombuf 回退可行性（关键编译风险，已预验证）
- f-stack 树中 `m_uiotombuf_nomap`(L1865)、`mc_split`/`mc_first`(L1122/1127)、`struct mchain` 均存在；
- vanilla `freebsd-src-releng-15.0/sys/kern/uipc_mbuf.c` 的 `m_uiotombuf` 在 L1950，与 f-stack `#ifndef FSTACK` 分支(L1956-1992)对齐；
- 回退 = 删除 `#else` 13.0 分支 + 去 `#ifndef FSTACK/#else/#endif` 包裹，保留 vanilla 分支为无条件代码；
- ⚠ M0 必须以**实际编译**验证 vanilla 分支可链接（mc_uiotomc 是否定义齐全），失败则打回。

### 0.4 构建环境（已确认就绪）
- DPDK 23.11.5 pkgconfig @ `/usr/local/lib64/pkgconfig`；cmocka 1.1.7；
- `uipc_mbuf.c` 编入 lib（lib/Makefile:361）；`lib/libfstack.a` 上次 M2 构建产物存在。

### 0.5 ⚠ 关键交叉验证落差（spec 文档 vs 代码实测，以代码为准）
1. **spec 37 §8.3 引用的 `tests/integration/test_ff_zc_recv_integration.c`（称 commit 8a06862cd 建立）不存在**：实测 8a06862cd 仅改 docs + example/main_zc.c + ff_api.symlist，无任何 zc 测试文件。当前 `tests/unit` 与 `tests/integration` 均无 zc 测试。→ ZC-send 测试须以**真实存在**的范式为准（`test_ff_dpdk_kni.c` 的 EAL+cmocka、`test_ff_dpdk_pcap.c` 的 mbuf 构造、`test_ff_dpdk_if_integration.c` 的真 EAL）。
2. **`ff_veth.c` / `ff_syscall_wrapper.c` 深度依赖 FreeBSD 内核头**（`sys/socketvar.h`、`net/if_var.h`、`netinet/in.h`…），现有 host-based unit harness（把 `lib/*.c` 用 host 头编入 `lib_objs`）**无法 host 编译**这两个文件。→ spec 37 的 U1-U12 纯逻辑单测假设不直接成立；M2 须务实调整（见 §3 M2）。

---

## §1 Agent Team 拓扑（team: zc-send-impl）

| 角色 | 实现方式 | 职责 |
|---|---|---|
| **Leader**（本对话）| 主 agent | 里程碑调度、实际代码编辑/编译/测试执行、门禁裁决、bounce counter、commit |
| **impl-review** | `Task(code-explorer)` 只读 | 每个里程碑代码改动后 review：与 spec/实测一致性、diff 最小化、规约合规 |
| **gatekeeper** | `Task(code-explorer)` 只读 | 里程碑门禁终审：grep/编译产物/符号/diff-vs-vanilla 抽检，PASS/FAIL |

> 编辑动作用 `c-precision-surgery`（内核精准 patch）+ `c-unittest-expert`（单测）技能由 Leader 执行；
> 子 agent 为只读分析（与 spec 阶段一致的高效模式）。

### 门禁回退规约（per memory 86071475）
- 任一里程碑门禁 FAIL → 打回该里程碑修复；
- **单里程碑打回 ≤3 次**；第 4 次仍 FAIL → **停止任务，转人工决策**；
- 每里程碑维护 `bounce[Mx]` 计数，落 49/4x review。

---

## §2 里程碑总览与门禁

| 里程碑 | 内容 | 门禁（gate）|
|---|---|---|
| **M0 内核** | K1 kern_zc_sendit 声明 + K2 实现；D1 删 MAGIC 宏；D2 回退 m_uiotombuf→vanilla；D3 删 sys_generic 守护 | 编译 4 组合 `-Werror` clean；`nm` 含 `kern_zc_sendit`；grep C2/K-G3/4/5=0；diff m_uiotombuf vs vanilla=0 |
| **M1 用户态** | U1 重写 ff_zc_send→kern_zc_sendit；U2 ff_zc_mbuf_get +M_PKTHDR；U3 ff_zc_mbuf_write 维护 pkthdr.len；U4 删 ff_write/writev opt-out；U5 ff_api.h 注释 | 编译 clean；`nm` 含 `ff_zc_send`；`example/main_zc.c` diff=0；U-G1/3/4/5 grep；helloworld_zc 链接 |
| **M2 单测** | 据 §0.5 务实方案：可 host 编译的纯逻辑用例 + 不可编译部分以编译期/集成期覆盖 | 测试编译+run PASS；valgrind 0 definite leak；无新增规约违规 |
| **M3 功能/集成** | 复刻 21-m2-report 的 E2E 路径（helloworld_zc + HTTP，发包路径）；环境允许则真跑 | http=200（发包零拷贝路径）；或如实记录环境限制 + 退化为 libfstack 链接级验证 |
| **M4 性能基线** | wrk T1/T2/T3 + 大包；对照 baseline | best-effort；环境不足则**如实标注 deferred，禁止臆造数据** |
| **M5 收尾** | 实施 review 文档（42-impl-review.md）+ bounce 汇总 + 分批 commit（简短英文 msg）| gatekeeper 终审 PASS |

> M3/M4 受 DPDK 运行时（hugepage/NIC/vdev）约束；凡无法实跑者，**如实记录**，不臆造结果（规约 #4）。
> 范围补充：若实施中发现**收包层（ZC-recv）问题**，一并修复（用户授权）。

---

## §3 里程碑详规

### M0 — 内核 patch（c-precision-surgery）
- **K1** `freebsd/sys/syscallsubr.h` L310 后插 `#ifdef FSTACK_ZC_SEND ... int kern_zc_sendit(...); #endif`（对称 kern_zc_recvit）。
- **K2** `freebsd/kern/uipc_syscalls.c` L1109 后插 `kern_zc_sendit` 实现（33 §2.2 版：入参校验 m_freem→getsock→MAC→sosend(so,NULL,NULL,top,NULL,flags,td)→成功 td_retval=len/失败 SIGPIPE→fdrop）。
- **D1** `freebsd/sys/mbuf.h` 删 1856-1869 整段。
- **D2** `freebsd/kern/uipc_mbuf.c` 删 `#else`(13.0+ZC)分支 + 去 `#ifndef FSTACK/#else/#endif` 包裹，保留 vanilla 分支。
- **D3** `freebsd/kern/sys_generic.c` 560-573→单行 `auio->uio_offset = offset;`；grep 验证 L57 include 是否可删。
- **门禁 M0**：
  1. `cd lib && PKG_CONFIG_PATH=... make clean && FF_ZC_SEND=1 make`（再测默认 / FF_ZC_RECV=1 / 双开）四组合 `-Werror` clean；
  2. `nm libfstack.a | grep kern_zc_sendit` = 1 T 符号；
  3. `grep FSTACK_ZC_SEND freebsd/kern/uipc_mbuf.c freebsd/kern/sys_generic.c freebsd/sys/mbuf.h` = 0；
  4. `grep FSTACK_ZC_MAGIC freebsd/ lib/` 源码 0；
  5. diff m_uiotombuf 区 vs `freebsd-src-releng-15.0/sys/kern/uipc_mbuf.c` = 0。
  - FAIL → bounce[M0]++（≤3）。

### M1 — 用户态 API（c-precision-surgery）
- **U1** `lib/ff_syscall_wrapper.c:1186-1226` 重写 ff_zc_send（34 §3.3 版：cast top + kern_zc_sendit(curthread,fd,top,0)）。
- **U2** `lib/ff_veth.c:306-323` ff_zc_mbuf_get：`m_getm2(...,MT_DATA,0)`→`M_PKTHDR`，加 `len<0` 校验。
- **U3** `lib/ff_veth.c:325-356` ff_zc_mbuf_write：链头 `head->m_pkthdr.len += progress`（O(1)），加 data!=NULL/len<0/len==0 处理，删未用 ret。
- **U4** 删 `lib/ff_syscall_wrapper.c:1146-1151`（ff_write opt-out）+ `:1175`（ff_writev opt-out）。
- **U5** `lib/ff_api.h:437-446` 更新文档块（签名不变）。
- **门禁 M1**：编译 clean；`nm libfstack.a | grep ff_zc_send`=1；`grep -n "auio.uio_offset = 0" lib/ff_syscall_wrapper.c`=0；ff_zc_mbuf_get 含 M_PKTHDR、ff_zc_mbuf_write 含未注释 m_pkthdr.len；`git diff --stat example/main_zc.c`=空；`cd example && FF_PATH=... make` helloworld_zc 链接通过。
  - FAIL → bounce[M1]++（≤3）。

### M2 — 单元测试（务实，c-unittest-expert）
- 受 §0.5(2) 限制，`ff_veth.c`/`ff_syscall_wrapper.c` 不可 host 编译。务实策略：
  - **方案 A（首选）**：新建 `tests/unit/test_ff_zc_send_logic.c`，**提取被测函数的纯逻辑**（ff_zc_mbuf_write 的 pkthdr.len 累加/边界 + ff_zc_send 入参校验）以本地 mbuf shim + `--wrap` 方式覆盖 U5/U6/U7/U8/U9/U10/U11/U12 类断言；Makefile 仿 `test_ff_dpdk_pcap` 加 per-target `-DFSTACK_ZC_SEND`。
  - **若方案 A 因 BSD 头耦合不可行 → bounce 一次**，改 **方案 B**：M_PKTHDR/pkthdr.len 正确性以 **M0/M1 编译期断言 + M3 集成功能** 覆盖，单测仅保留可独立编译的 ff_zc_send 入参校验桩；并在 42-impl-review 如实记录 harness 限制。
- **门禁 M2**：测试 binary 编译 + run PASS；`make check`(valgrind) 0 definite leak。
  - FAIL → bounce[M2]++（≤3）。

### M3 — 功能/集成
- 复刻 `21-m2-test-report.md` 的 E2E：`FF_PATH`/`FF_DPDK` 配好后用 `example/helloworld_zc`（FF_ZC_SEND=1）起服务 + HTTP GET 验证发包零拷贝路径 http=200；进程清理走 `/data/workspace/kill_process.sh`，临时文件走 `rm_tmp_file.sh`。
- 环境不足（无 hugepage/NIC/vdev）→ 退化为：libfstack.a + helloworld_zc 链接级 + symbol 验证，并**如实记录**。
- **门禁 M3**：http=200（理想）或链接级 PASS + 限制记录。FAIL → bounce[M3]++（≤3）。

### M4 — 性能（best-effort）
- 环境允许：wrk T1/T2/T3 + 大包 vs baseline，Δ≤±3%；否则 **deferred 如实标注**，禁止臆造。

### M5 — 收尾
- 写 `docs/zc_stack_user_spec/zh_cn/42-impl-review.md`（每里程碑结果 + bounce counter + 门禁抽检 + 与 spec 偏差说明）。
- 分批 `git commit`（简短英文 msg，per 规约 #5 + memory 73362122）：M0 内核 / M1 用户态 / M2 单测 / (M3 如有产物) / M5 review。
- gatekeeper 终审。

---

## §4 风险与回退

| 风险 | 触发 | 处置 |
|---|---|---|
| R-M0-1 | vanilla m_uiotombuf 回退后链接失败（mc_uiotomc 未定义）| bounce M0；改为"仅删 ZC 分支、保留 13.0 简化版"折中（达成消除魔改核心目标，AC4 diff 项降级标注）|
| R-M0-2 | kern_zc_sendit 未被引用导致 `-Werror=unused` | M1 的 ff_zc_send 即引用方；M0 单独编译时该函数 gated 但被 symlist/调用方引用，必要时 M0+M1 合并编译验证 |
| R-M2-1 | ff_veth.c 不可 host 编译 | 方案 A→B 退化（§3 M2）|
| R-M3-1 | DPDK 运行时不可用 | 退化为链接级 + 如实记录，不臆造 http=200 |
| 通用 | 单步 bounce ≥3 | **停止任务，转人工决策**（memory 86071475）|

---

## §5 bounce counter（执行期维护）

```
M0=0  M1=0  M2=0  M3=0  M4=0  M5=0
```

（执行中实时更新；任一 =3 触发人工。）
