# 09 实现版 Plan：F-Stack + 内核栈共存（R0-R5）

> **文档编号**：SPEC-KE-09（实现阶段计划）
> **版本**：v5（编译宏门控范式）
> **日期**：2026-06-17
> **状态**：执行中（R0-R5 已完成；R6 编译宏门控待落地）
> **依据**：本目录 v5 spec（00-08）；行号以实际代码为准，gatekeeper 复核。

---

## 0. 范围与门禁

- **R0-R5 全做**：回退错误 → spec 重写 → hook 共存固化+demo → 原生统一事件共存 → 测试/性能 → 门禁+提交。
- **硬门禁（无条件全绿）**：编译通过 + cmocka 单测全绿 + 覆盖率达标 + **F-Stack 业务快路径零回归（NFR-1/NFR-2）**。
- **共存铁律（NFR-3）**：任何阶段 F-Stack 用户态栈始终承担业务、绝不被内核栈旁路；违反即打回。
- **目标门禁**：尽力实搭 DPDK 运行时实跑同进程双栈集成；不具备真实 NIC 时业务面 skip+实测证据，内核侧 loopback 必测。

---

## 1. Agent Team 拓扑（harness + spec 驱动）

| Agent | 角色 | 职责 |
|---|---|---|
| **Leader** | 统筹+执笔+裁决 | 编排、改码、门禁裁决、commit、bounce 计数 |
| **arch-probe** | 架构探测（只读） | 实测 hook FF_KERNEL_EVENT / nginx / 原生事件层 |
| **spec-writer** | spec 重写 | v4 中英文文档 |
| **build** | 编译（实跑） | lib / libff_syscall.so / tests |
| **unit-test** | 单测 | cmocka 共存用例 |
| **review** | 评审（只读） | 最小 diff/零回归/共存铁律/规约 |
| **test** | 集成/性能 | 同进程双栈端到端 + F-Stack 快路径无回归 |
| **gatekeeper** | 门禁（只读） | 逐条断言 + 门禁条目 |

**门禁回退**：任一阶段失败打回上一步；同一步骤 bounce≤3 次，超限停止转人工；bounce 记入 `08`。

---

## 2. 改造点（实测锚点，以代码为准）

| 里程碑 | 文件 | 改动 |
|---|---|---|
| R0 | `lib/ff_syscall_wrapper.c`、`lib/ff_host_interface.{c,h}` | 回退 ff_host_socket 旁路（**已完成 0748eff94**） |
| R2 | `adapter/syscall/`（Makefile FF_KERNEL_EVENT）、新 demo | 编译 libff_syscall.so；正确同进程双栈 demo（对照 `main_stack_epoll_kernel.c`），替换 v3 纯内核 helloworld_stacksel |
| R3 | `lib/ff_config.{c,h}` | `stack.kernel_coexist`（`ff_config.c:1027-1031` 解析、`:1363` 默认 0、`ff_config.h:321-323` 结构）；调用方直接读 `ff_global_cfg.stack.kernel_coexist`（无访问器） |
| R3 | `lib/ff_host_interface.{c,h}` | 新增受管内核侧桥（宿主 socket/bind/listen/accept/connect/close/epoll_*），供 lib 建受管内核 fd |
| R3 | `lib/ff_syscall_wrapper.c` `ff_socket` 及 ff_bind/listen/accept/connect/close | 共存启用时 SOCK_KERNEL→受管内核 fd+登记归属；按归属路由；默认/`SOCK_FSTACK` 零回归 |
| R3 | `lib/ff_epoll.c` | `ff_epoll_create` 兼建内核 epoll；`ff_epoll_ctl` 分流；`ff_epoll_wait` 合并 kqueue⊕epoll；close 联动 |
| R3 | `config.ini` | `[stack] kernel_coexist=0` 示例段（替换 v3 default_stack） |
| R4 | `tests/unit/`、`tests/integration/` | cmocka 共存用例 + 同进程双栈集成 |
| **R6** | `lib/Makefile` + `02 §4bis.2` 7 文件 | **编译宏 `FF_KERNEL_COEXIST` 门控**：Makefile 宏块（默认注释关，已就位 `:174-177`）+ 逐文件 `#ifdef` 包裹已落地共存代码 |
| 文档 | `docs/kernel_event_support_spec/`（中英文 00-10） | v5 编译宏门控范式（已重写中文；英文 R5/R6 同步） |

---

## 2bis. R6 编译宏门控落地步骤（v5 核心）

### 2bis.1 Makefile（已就位，确认即可）
```
# lib/Makefile:57-60（默认注释关）
#FF_KERNEL_COEXIST=1
# lib/Makefile:174-177（仿 FF_LOOPBACK_SUPPORT/FF_IPFW，双侧 CFLAGS）
ifdef FF_KERNEL_COEXIST
HOST_CFLAGS+= -DFF_KERNEL_COEXIST
CFLAGS+= -DFF_KERNEL_COEXIST
endif
```

### 2bis.2 逐文件 `#ifdef FF_KERNEL_COEXIST` 包裹清单（按 `02 §4bis.2`，实测行号）

| # | 文件 | 包裹点 | 注意 |
|---|---|---|---|
| 1 | `lib/ff_api.h` | `:81-99` `SOCK_FSTACK/SOCK_KERNEL` 宏块 | 保留内层 `#ifndef`；顺带删 `:91` 注释 "default_stack"（D3） |
| 2 | `lib/ff_host_interface.h` | `:94-158` `FF_KERNEL_FD_BASE`+3 inline+18 桥声明 | 整块包裹 |
| 3 | `lib/ff_host_interface.c` | `:29-31`(`_GNU_SOURCE`)+`:42-45`(include)+`:246-367`(18 桥实现) | 不影响同文件其他非共存函数 |
| 4 | `lib/ff_config.h` | `:321-323` `struct{int kernel_coexist;}stack;` | 注意改结构体布局须 clean 全量重编（ABI 偏斜，`10 §7`） |
| 5 | `lib/ff_config.c` | `:1027-1031`(解析)+`:1363`(默认赋值) | `else if` 链中包裹该分支 |
| 6 | `lib/ff_epoll.c` | `:25-68`(配对表+lock+`ff_epoll_host_ep`)+`:97-111`(ctl 分支)+`:210-241`(wait 合并) | wait 合并须保留宏关时的原 kqueue-only 路径 |
| 7 | `lib/ff_syscall_wrapper.c` | `:64`(include)+`:919-931`(`ff_socket` 分支)+13 入口路由块（`02 §4.3` 行号） | 各 `ff_*` 默认路径须留在 `#ifdef` 外 |

> `ff_api.symlist` 无需改动。改头后 clean 全量重编（`rm_tmp_file.sh` 清 .o + libfstack.a）。

### 2bis.3 验证（双编译 nm 零回归，见 `07 §1bis` MT-1~MT-5）
- 宏关 `make` → `nm libfstack.a` 无共存符号；宏开 `make FF_KERNEL_COEXIST=1` → 符号出现 + 功能可用。

---

## 3. 关键设计决策
- **复用优先**：hook 共存已实现，R2 以复核固化 + 正确 demo 为主。
- **原生共存核心**：受管内核 fd（**非裸绕过**，lib 登记归属并纳入统一事件）+ `ff_epoll_wait` 合并；默认路径逐字节零回归。
- **fd 空间区分**：仿 nginx `ngx_max_sockets` 偏移或 hook 编码偏移，实现阶段定。
- **可达性分层**：config/fd 归属/事件合并走 cmocka 单测（host 编译）；同进程双栈端到端走集成（DPDK 运行时，优先 vdev+--no-huge 规避物理 NIC）。

---

## 4. 执行步骤
1. R0 回退（已完成）。
2. R1 spec 重写 + v5 编译宏门控范式升级（中文已完成，英文 R5/R6 同步）。
3. R2 hook 共存固化 + demo + 编译（已完成）。
4. R3 原生统一事件共存 + config 改造 + 编译（已完成）。
5. R4 单测/集成/性能（已完成）。
6. R5 门禁 + 英文 spec + 提交。
7. **R6 编译宏门控**：Makefile 宏块（已就位）+ 逐文件 `#ifdef FF_KERNEL_COEXIST` 包裹（2bis.2）+ 双编译 nm 零回归验证（`07 §1bis`）+ `ff_api.h:91` 注释修正。

## 5. 工作区脚本规约
删文件 `/data/workspace/rm_tmp_file.sh`；停进程 `/data/workspace/kill_process.sh`；改权限 `/data/workspace/chmod_modify.sh`；`make install` 类（非直接 chmod）可执行。
