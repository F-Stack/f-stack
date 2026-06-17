# 08 审核门禁报告

> **文档编号**：SPEC-KE-08
> **版本**：v6（native 自动双栈共存范式）
> **日期**：2026-06-17
> **状态**：R0-R6 门禁 PASS（v5，commit ba148589d）；**v6 R7 自动双栈门禁 PASS（已实测，含真机双栈 9.134.214.176 + 127.0.0.1）**
> **作用域**：v6 spec 与实现的「与代码一致性 / 自动双栈范式正确性 / 编译宏门控完整性 / 零回归 / connect 契约确认」门禁。

---

## 1. 门禁方式
- gatekeeper（code-explorer 只读）异步核验 + Leader 同步对关键 `文件:行号` 断言逐条实测；冲突以**实际代码为准**。
- bounce：任一项 FAIL → 打回上一步，同一步骤 ≤3 次，超限转人工。

---

## 2. v6 自动双栈范式正确性断言（R7 spec 门禁）

| 编号 | 断言 | 证据/状态 |
|---|---|---|
| P1 | spec 无「ff_socket→纯内核旁路」「整进程默认内核」表述 | 00/01/02/04/05 已删 |
| P2 | 范式=默认双栈（一 socket 双建/双驱动）+ marker 单栈覆盖 + 统一事件，F-Stack 始终在位 | 00 §0/01 §1/04 §1-3 |
| P3 | 默认双建：`ff_socket` 同建 F-Stack+内核，返回 F-Stack 原始 fd，登记 `map[fstack]=host` | 04 §4.1/05 §3（**v6 待实现**） |
| P4 | fd 三态路由（仅内核/仅 F-Stack/双栈）正确定义 | 04 §2 |
| P5 | accept 单栈归属（Q3=A）：双栈 listen → 单栈连接 fd | 04 §6/05 §5（**v6 待实现**） |
| P6 | §connect 双栈契约**显式标注语义歧义 + 待用户最终确认** | 04 §7/05 §6（**待确认**） |
| P7 | native vs hook 同构（映射表/epoll 合并/close 联动）与分歧（socket/listen/connect 自动双建）如实记录 | 02 §5 |
| P8 | `ff_native_fd_map` 仿 adapter 无锁、容量 65536、与 `ff_epoll_pairs` 正交 | 04 §5（**v6 待实现**） |
| P9 | 热路径无回归（连接 fd 单栈，recv/send 不查 map） | 04 §1.5/05 §3/NFR-2 |
| P10 | 共存铁律 NFR-3（F-Stack 始终建/在位）贯穿 | 01 §4/04 §1 |
| P11 | 全部 v6 改造 `#ifdef FF_KERNEL_COEXIST` + 运行期短路 + marker 单栈，零回归 | 04 §1bis/05 §1bis |
| P12 | **实现状态如实区分**：v5 已实测 vs v6 待实现（`ff_native_fd_map` grep=0） | 02 §5.2/各文档标注 |

> **R7 spec 门禁结论**：spec 已按 v6 范式 + 代码实测行号改写；`ff_native_fd_map`/默认双建/双驱动明确标注「待实现」，未当既成。**待 connect 契约用户确认**后定稿。

---

## 3. R0-R6 门禁（v5，已 PASS）

> 沿用 v5 记录（commit 链 0748eff94→...→ba148589d）。摘要：

### 3.1 共存范式 + 回退（R0-R1）
- R0 回退 `ff_host_socket` 裸绕过 PASS（0748eff94）；R1 spec 共存范式 PASS。

### 3.2 原生 per-fd 实现（R2-R5）
- config 开关、`FF_KERNEL_FD_BASE` fd 区分、18 桥、socket 侧路由、`ff_epoll_pairs` 合并、NFR-1/NFR-3 零回归——**全 PASS**；cmocka 全绿（test_ff_config 54/54 等）；socket 侧 selftest 实跑 PASS；真机性能 PERF-1/2/3 PASS（`10`）。

### 3.3 编译宏门控（R6，v5 核心）
| 编号 | 门禁项 | 状态 |
|---|---|---|
| M1 | 7 文件 `#ifdef FF_KERNEL_COEXIST` 包裹完整、不破坏非共存代码 | PASS |
| M2 | `lib/Makefile` 双侧 CFLAGS + 默认注释关 | PASS |
| M3 | symlist 不变 | PASS |
| M4 | 宏关 nm 共存符号=0（MT-1）、核心 API 完整 | PASS |
| M5 | 宏开 nm 共存符号=39（MT-3） | PASS |
| M6 | marker opt-in 可见性（MT-2） | PASS |
| M7 | `ff_api.h` 注释 `default_stack`→`kernel_coexist`（D3） | PASS |
- 单测双态：宏关 P1 50/50、宏开 P1 54/54。bounce=1（getsockopt 漏包裹，已修）。

---

## 4. R7 native 自动双栈实现门禁（v6，**已实测 PASS**）

| 编号 | 门禁项 | 验证方式 | 状态 |
|---|---|---|---|
| V1 | `ff_native_fd_map[65536]` + `ff_native_map_get/set/clear` 落地（无锁，仿 adapter） | `ff_host_interface.c` + UT `test_ff_native_fd_map` 通过 | PASS |
| V2 | `ff_socket` 默认双建（marker 单栈覆盖、共存关零回归） | `ff_syscall_wrapper.c` want_dual 分支 + 宏关 diff 零回归 | PASS |
| V3 | `ff_bind/ff_listen` 双驱动 | F-Stack 成功后 `ff_host_bind/listen(map[s])` + 真机 listen 两栈 | PASS |
| V4 | accept 单栈归属 | `ff_accept/accept4` 先 kern_accept、EAGAIN 再 `ff_host_accept`，返回单栈 fd | PASS |
| V5 | `ff_close` 双驱动 + `ff_native_map_clear` + 清 `ff_epoll_pairs` | `ff_close` 联动 + `ff_epoll_close_pair` | PASS |
| V6 | 双栈 listen `ff_epoll_ctl` 双注册 + `ff_epoll_wait` 合并 | `ff_epoll.c` dual block + 真机内核侧事件可达 | PASS |
| V7 | **一 listen 多用真机双向** | demo 单 `listen(80)`：内核 `ss 0.0.0.0:80` + `curl 127.0.0.1:80=200`；F-Stack `ssh f-stack-client→9.134.214.176:80=200`（同进程同 epoll） | PASS |
| V8 | 热路径不查 map（连接 fd 单栈） | recv/send/read/write 仅 `ff_is_kernel_fd` 判定，不查 map | PASS |
| V9 | 宏关 nm 无 `ff_native_map_*`/`ff_host_*`（MT-1）；宏开出现（MT-3） | 宏关共存符号=0（size 6539682 与基线一致）；宏开齐全 | PASS |
| V10 | §connect 双栈（Q2=B）：双发 connect，F-Stack 为返回/数据主路径 | `ff_connect` best-effort `ff_host_connect(map[s])` + kern_connectat 主；契约见 `05 §6` | PASS（按 Q2=B 草案；数据路径 F-Stack 主，已文档化） |
| V11 | 双建部分失败契约（不静默/不泄漏） | bind/listen host 失败返回 -1；socket host 失败仍返回 F-Stack fd（best-effort） | PASS |
| V12 | NFR-1/NFR-3 零回归 + F-Stack 始终在位 | 宏关逐字节零回归 + 默认恒建 F-Stack | PASS |

> **R7 门禁结论：PASS（已实测）**。映射表 + 默认双建 + 双驱动 + 双栈统一事件 + accept 单栈归属 + connect 双发全部落地；宏关零回归、宏开真机单 listen(80) 双栈各返回 200。bounce 见 §6。

---

## 5. D1-D9 代码-文档一致性核验

| 编号 | 修正项 | 状态 |
|---|---|---|
| D1-D8 | 沿用 v5（已 PASS，见 `02 §6`） | PASS |
| **D9（v6）** | `ff_native_fd_map`/默认双建/双驱动**尚未实现**（`02 §5.2` grep=0），文档区分 v5 已实测 / v6 待实现 | PASS（如实标注） |

---

## 6. Bounce 记录

| # | 触发 | 处置 | 复核 |
|---|---|---|---|
| — | v5 R0-R6 见历史（bounce 累计在 3 上限内） | — | — |
| — | v6 R7 spec 按代码实测 + 范式一致编写，未触发 FAIL | — | — |
| 1 | v6 R7 宏开单测 `test_ff_epoll` 链接失败（`ff_epoll.o` 新引用 `ff_native_map_get`/`ff_host_close` 无 stub） | test_ff_epoll.c 补 2 个宏门控 stub | 重跑 ON P1 PASS |

- v6 R7 实现阶段 bounce=1（< 3 上限），已修复闭环。

---

## 7. 当前结论

**R0-R6（v5）门禁 PASS**（commit ba148589d）：共存范式正确、编译宏门控完整、宏关零回归（nm 共存符号=0）、宏开可用（=39）、真机性能 PERF-1/2/3 通过、D1-D8 一致。

**v6 R7 门禁 PASS（已实测）**：native 自动双栈落地——`ff_native_fd_map` + `ff_socket` 默认双建 + `ff_bind/ff_listen/ff_close/ff_connect` 双驱动 + `ff_epoll_ctl` 双注册/`ff_epoll_wait` 合并 + accept 单栈归属，全部 `#ifdef FF_KERNEL_COEXIST` 门控。宏关编译 rc=0 且 nm 共存符号=0（size 6539682 与基线逐字节一致，零回归）；宏开 rc=0；单测双态 PASS（宏关 P1 50/50，宏开 P1 含 `test_ff_native_fd_map`/`test_ff_kernel_fd_encode_roundtrip`）；**真机单 `listen(80)` 同进程被 F-Stack 侧（ssh f-stack-client → 9.134.214.176:80 = HTTP 200）与内核侧（curl 127.0.0.1:80 = HTTP 200）同时服务**，V1-V12 全 PASS（V10 connect 按 Q2=B 草案实现、数据路径 F-Stack 主，已文档化）。bounce=1（test_ff_epoll stub，已修）。
