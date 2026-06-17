# 09 实现版 Plan：F-Stack + 内核栈自动双栈共存（R0-R7）

> **文档编号**：SPEC-KE-09（实现阶段计划）
> **版本**：v6（native 自动双栈共存范式）
> **日期**：2026-06-17
> **状态**：R0-R7 全部完成并门禁 PASS（**R7 v6 自动双栈已实测，commit 13b418191**；真机单 listen(80) 双栈 9.134.214.176 + 127.0.0.1 各 HTTP 200）
> **依据**：本目录 v6 spec（00-08）；行号以实际代码为准，gatekeeper 复核。**v6 改造已落地，下述 §3 为已实现代码。**

---

## 0. 范围与门禁

- **R0-R6 已完成**：回退 → spec → hook 固化 → 原生 per-fd 共存 → 测试/性能 → 门禁/提交 → 编译宏门控（ba148589d）。
- **R7 已完成（commit 13b418191）**：native 自动双栈（默认双建/双驱动 + `ff_native_fd_map` + 双栈事件 + accept 归属 + connect 双发）落地并门禁 PASS。
- **硬门禁（已满足）**：双态编译通过 + cmocka 双态全绿 + **宏关 nm 共存符号=0（size 6539682 与基线逐字节一致，零回归）** + **F-Stack 业务快路径 + 单栈连接热路径零回归（NFR-1/NFR-2）**。
- **共存铁律（NFR-3）**：F-Stack fd 始终建、始终承担业务；已落实。
- **connect 契约**：`05 §6` 已按用户确认 Q2=B（双发 connect、F-Stack 为返回/数据主路径）实现。

---

## 1. Agent Team 拓扑

| Agent | 角色 | 职责 |
|---|---|---|
| Leader | 统筹+执笔+裁决 | 编排、改码、门禁裁决、commit、bounce 计数 |
| arch-probe | 架构探测（只读） | 实测 v5 现状 + hook 同构/分歧 |
| spec-writer | spec 升级 | v6 中英文文档（本轮产物） |
| build | 编译（实跑） | lib 双编译 / tests |
| unit-test | 单测 | cmocka v6 双态用例 |
| review | 评审（只读） | 最小 diff/零回归/共存铁律/规约 |
| test | 集成/性能 | 一 listen 多用真机双栈 + 快路径无回归 |
| gatekeeper | 门禁（只读） | 逐条断言 + 门禁条目 |

**门禁回退**：任一阶段失败打回上一步；同一步骤 bounce≤3 次，超限转人工；bounce 记入 `08`。

---

## 2. R0-R6 改造点（已完成，实测锚点）

| 里程碑 | 文件 | 改动 |
|---|---|---|
| R0 | `ff_syscall_wrapper.c`、`ff_host_interface.{c,h}` | 回退 ff_host_socket 旁路（0748eff94） |
| R2 | `adapter/syscall/`、demo | hook 固化 + 同进程双栈 demo |
| R3 | `ff_config.{c,h}` | `stack.kernel_coexist`（`:1027-1031`/`:1363`/`:321-323`） |
| R3 | `ff_host_interface.{c,h}` | 18 个 `ff_host_*` 桥 + `FF_KERNEL_FD_BASE` |
| R3 | `ff_syscall_wrapper.c` | `ff_socket` per-fd 二选一 + 13 入口 `ff_is_kernel_fd` 路由 |
| R3 | `ff_epoll.c` | `ff_epoll_pairs` 合并 |
| R6 | `lib/Makefile` + 7 文件 | `FF_KERNEL_COEXIST` 包裹（`:174-177` 双侧 CFLAGS） |

---

## 3. R7 native 自动双栈逐文件改造步骤（v6 核心，已实现 commit 13b418191）

> 全部新增代码置于 `#ifdef FF_KERNEL_COEXIST` 内；运行期 `kernel_coexist=0` 短路；`SOCK_FSTACK`/共存关逐字节零回归。

### 3.1 `lib/ff_host_interface.h`（HOST_CFLAGS 头）
- 在 `#ifdef FF_KERNEL_COEXIST` 块（现 `:94-160`）内新增访问器声明：
  ```c
  int  ff_native_map_get(int fstack_fd);
  void ff_native_map_set(int fstack_fd, int host_fd);
  void ff_native_map_clear(int fstack_fd);
  ```
- **不改结构头**（避免 ABI 偏斜，`10 §7`）。

### 3.2 `lib/ff_host_interface.c`（HOST_CFLAGS）
- 在现有 18 桥实现块（`#ifdef FF_KERNEL_COEXIST` 内）新增：
  ```c
  static int ff_native_fd_map[FF_MAX_FREEBSD_FILES];   /* =65536，仿 ff_hook_syscall.c:258，无锁 */
  int  ff_native_map_get(int fd){ return (fd>=0 && fd<FF_MAX_FREEBSD_FILES) ? ff_native_fd_map[fd] : 0; }
  void ff_native_map_set(int fd,int h){ if(fd>=0 && fd<FF_MAX_FREEBSD_FILES) ff_native_fd_map[fd]=h; }
  void ff_native_map_clear(int fd){ if(fd>=0 && fd<FF_MAX_FREEBSD_FILES) ff_native_fd_map[fd]=0; }
  ```
- `FF_MAX_FREEBSD_FILES` 若 lib 未定义则在此 `#define`（仿 adapter）。

### 3.3 `lib/ff_syscall_wrapper.c`（CFLAGS）
- `ff_socket`(`:915-947`)：在 `#ifdef FF_KERNEL_COEXIST` 块重构——
  - `SOCK_KERNEL && !SOCK_FSTACK && coexist`：保留 v5（仅内核 + encode）。
  - **新增默认双栈**：`!SOCK_FSTACK && coexist`（无 marker）→ 先 `sys_socket` 建 F-Stack fd `s`，再 `ff_host_socket(...)` 建 host `h`，`ff_native_map_set(s,h)`，返回 `s`；`ff_host_socket` 失败按 `05 §7` 契约。
  - `SOCK_FSTACK` / 共存关：原 `sys_socket` 路径（`:937-943` 不变）。
- `ff_bind`(`:1607-1627`)：现 `#ifdef` 块 `ff_is_kernel_fd` 后保留；在 `kern_bindat` 成功（`:1620-1623`）后加 `#ifdef` 块：`int h=ff_native_map_get(s); if(h>0) ff_host_bind(h, addr, addrlen);`（用**原始 linux addr**，非 bsdaddr）。
- `ff_listen`(`:1584-1605`)：`sys_listen` 成功后加 `int h=ff_native_map_get(s); if(h>0) ff_host_listen(h, backlog);`。
- `ff_close`(`:1095-1112`)：`kern_close` 成功后加 `int h=ff_native_map_get(fd); if(h>0){ ff_host_close(h); ff_native_map_clear(fd); }`；并对 kqueue fd 清 `ff_epoll_pairs`（与 `ff_epoll.c` 协作，见 3.4）。
- `ff_accept`/`ff_accept4`(`:1514-1582`)：双栈 listen fd（`ff_native_map_get(s)>0`）按 `05 §5` 单栈归属（kern_accept→EAGAIN→ff_host_accept+encode）。
- `ff_setsockopt`(`:999`)/`ff_fcntl`(`:1495`)：双栈 fd 在 F-Stack 路径后对 `map[s]` 同步 `ff_host_setsockopt/fcntl`。
- `ff_connect`(`:1629-1649`)：已按 Q2=B 实现——`kern_connectat` 主、best-effort `ff_host_connect(map[s])` 双发（`05 §6`）。
- **热路径不改**：recv/send/read/write/recvfrom/sendto 保留 v5 `ff_is_kernel_fd` 单次判定，**不加 `ff_native_map_get`**（NFR-2）。

### 3.4 `lib/ff_epoll.c`（HOST_CFLAGS）
- `ff_epoll_ctl`(`:99-115`)：现 `ff_is_kernel_fd(fd)` 分支保留（仅内核 fd）；**新增**：对 `ff_native_map_get(fd)>0` 的双栈 listen fd——既走 kqueue 注册（原路径，`:120+`）**又** `ff_host_epoll_ctl(ff_epoll_host_ep(epfd,1), op, ff_native_map_get(fd), event)`（透传 `event.data`）。
- `ff_epoll_wait`(`:214-252`)：现有合并骨架已支持（先 host `timeout=0` 再 kqueue），无需大改；确认双栈 listen 两栈事件均入合并。
- `ff_close` 协作：kqueue fd close 时清 `ff_epoll_pairs` 配对 + `ff_host_close(host_ep)`（新增 helper，如 `ff_epoll_close_pair(kq)`）。

### 3.5 `lib/Makefile`
- 已就位（`:174-177` 双侧 CFLAGS）；无需改动（`ff_native_fd_map` 在 HOST_CFLAGS 的 `ff_host_interface.c`，双驱动分支在 CFLAGS 的 `ff_syscall_wrapper.c`，已覆盖）。

### 3.6 demo
- 改造 `example/helloworld_stacksel` 或新建：默认 `ff_socket`+`bind(80)`+`listen`（无 marker）+ `ff_epoll` 循环 accept 处理两栈连接；返回预置 HTTP 体。用于 IT-1/2/3 真机双栈。

---

## 4. 关键设计决策
- **复用优先**：`FF_KERNEL_FD_BASE`/`ff_host_*`/`ff_epoll_pairs` 复用 v5；v6 仅叠加 `ff_native_fd_map` + 默认双建/双驱动。
- **映射表无锁**：单线程轮询模型，仿 hook `fstack_kernel_fd_map`（NFR-5）。
- **热路径零开销**：连接 fd 单栈，recv/send 不查 map（NFR-2）。
- **connect 歧义**：草案待用户确认；纯内核客户端用 `SOCK_KERNEL` 规避歧义。
- **可达性分层**：映射表/双建/双驱动/accept 归属/事件合并走 cmocka（host 编译 + mock `ff_host_*`）；一 listen 多用走真机 DPDK 双栈集成。

---

## 5. 执行步骤（已完成）
1. R0-R6 已完成（见 §2）。
2. R7 spec 升级为 v6（中英文已同步）。
3. **R7 实现已完成**（connect 契约 Q2=B 已确认）：3.1→3.2（映射表）→3.3（socket 双建 + bind/listen/close/accept 双驱动 + setsockopt/fcntl）→3.4（epoll 双注册 + close 清配对）→3.6（demo）。
4. R7 测试已完成：cmocka 双态（宏关 P1 50/50；宏开 P1 含 `test_ff_native_fd_map`/`test_ff_kernel_fd_encode_roundtrip`）+ 真机双栈（单 listen(80)：内核 `curl 127.0.0.1:80=200`、F-Stack `ssh f-stack-client→9.134.214.176:80=200`）+ 性能 A/B（v6 默认双建 vs 纯 F-Stack，T1/T2/T3 各 3 trial，Δ −1.73%/+1.68%/+5.87% 全落噪声内无回归，见 `10 §10`）。
5. R7 门禁 PASS：`08 §4` V1-V12 已实测；双编译 nm 零回归（宏关共存符号=0、size 6539682 与基线一致；宏开含 `ff_native_fd_map`）；中英文 spec 已同步；英文简短 commit `13b418191`；config 本机值未提交。bounce=1（test_ff_epoll stub，已修）。

## 6. 工作区脚本规约
删文件 `/data/workspace/rm_tmp_file.sh`；停进程 `/data/workspace/kill_process.sh`；改权限 `/data/workspace/chmod_modify.sh`；改头后 clean 全量重编 lib（`10 §7`）。
