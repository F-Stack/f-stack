# 06 里程碑与编码工作清单

> **文档编号**：SPEC-KE-06
> **版本**：v6（native 自动双栈共存范式）
> **日期**：2026-06-17
> **状态**：编写中（R0-R6 已完成；R7 v6 自动双栈待实现）
> **作用域**：本特性返工 + 编译宏门控 + **v6 自动双栈**实施路线图。

---

## 0. 里程碑总览

| 里程碑 | 名称 | 目标 | 状态 |
|---|---|---|---|
| R0 | 回退错误代码 | 回退 v3 `ff_host_socket` 裸绕过 | 已完成（0748eff94） |
| R1 | spec 重写 | 共存范式 | 已完成 |
| R2 | hook 共存固化 + demo | FF_KERNEL_EVENT 同进程双栈 demo | 已完成 |
| R3 | 原生 per-fd 共存 | 受管内核 fd + `ff_epoll_pairs` 合并 + config | 已完成 |
| R4 | 测试与性能基线 | 单测/集成/真机性能 | 已完成 |
| R5 | 门禁 + 提交 | gatekeeper + 英文 spec | 已完成 |
| R6 | 编译宏门控（v5） | `FF_KERNEL_COEXIST` 包裹 7 文件 + 双编译 nm 零回归 | 已完成（ba148589d） |
| **R7** | **native 自动双栈（v6）** | 默认双建/双驱动 + `ff_native_fd_map` + 双栈事件 + accept 归属 + connect 草案 | **本轮设计；待实现** |

> **共存铁律**：所有里程碑保证 F-Stack 用户态栈始终承担业务、绝不被旁路（NFR-3）。

---

## 1-5. R0-R6（已完成）

- R0 回退（0748eff94）；R1-R5 共存范式 + per-fd 实现 + 测试 + 真机性能（`08 §4`/`10`）；R6 编译宏门控（7 文件 `#ifdef FF_KERNEL_COEXIST`，宏关 nm 共存符号=0、宏开=39，单测双态通过，`08 §4bis` M1-M7 PASS）。详见 v5 记录与 `08`。

---

## 6. R7 native 自动双栈（v6 核心，编码工作清单）

> **前置现状（实测）**：v5 是 per-fd 二选一（`ff_socket` 默认仅建 F-Stack）；`ff_native_fd_map` **不存在**（`02 §5.2` grep=0）；编译宏门控已就位。R7 在 v5 基础上把默认语义改为自动双栈。

### 6.1 映射表（新增）
- `ff_host_interface.c`（`#ifdef FF_KERNEL_COEXIST`，HOST_CFLAGS）：`static int ff_native_fd_map[FF_MAX_FREEBSD_FILES];`（=65536，仿 adapter `ff_hook_syscall.c:258`，无锁）。
- `ff_host_interface.h`：声明 `ff_native_map_get/set/clear`（`#ifdef FF_KERNEL_COEXIST`，§`05 §3bis`）。

### 6.2 `ff_socket` 重构默认双建（`:915-947`）
- 默认（无 marker）+ coexist 开：`sys_socket`(s) + `ff_host_socket`(h) + `ff_native_map_set(s,h)`，返回 s。
- `SOCK_KERNEL`（保留 v5）：仅 `ff_host_socket`+encode。
- `SOCK_FSTACK` / 共存关：仅 `sys_socket`（零回归，逐字节不变）。
- 部分失败契约（`05 §7`）：`ff_host_socket` 失败时降级/回滚（R7 定稿）。

### 6.3 双驱动入口
- `ff_bind`(`:1607-1627`)：`kern_bindat` 成功后，若 `ff_native_map_get(s)>0` 则 `ff_host_bind(map[s], 原始 linux addr, addrlen)`。
- `ff_listen`(`:1584-1605`)：`sys_listen` 后，`map[s]>0` 则 `ff_host_listen(map[s], backlog)`。
- `ff_close`(`:1095-1112`)：`kern_close` 后，`map[fd]>0` 则 `ff_host_close(map[fd])`+`ff_native_map_clear(fd)`；kqueue fd 清 `ff_epoll_pairs`+关 host_ep。
- `ff_setsockopt`(`:999`)/`ff_fcntl`(`:1495`)：双栈 fd 两栈同步设置。
- `ff_connect`(`:1629-1649`)：§connect 草案（`05 §6`，待用户确认）。

### 6.4 accept 单栈归属（`ff_accept`/`ff_accept4` `:1514-1582`）
- 按 `05 §5`：双栈 listen fd 先 `kern_accept`，EAGAIN 再 `ff_host_accept(map[s])`+encode；连接 fd 单栈。

### 6.5 双栈事件（`ff_epoll.c`）
- `ff_epoll_ctl`(`:99-115`)：对双栈 listen fd（`ff_native_map_get(fd)>0`）在 kqueue 注册 fd + 内核 epoll 注册 `map[fd]`（透传 `ev.data`）；复用 `ff_epoll_host_ep` 懒建配对。
- `ff_epoll_wait`(`:214-252`)：现有合并骨架已支持（先 host `timeout=0` 再 kqueue）；确认双栈 listen 两栈事件均合并。
- `ff_close` 对 kqueue fd 清配对（6.3）。

### 6.6 热路径（recv/send/read/write/recvfrom/sendto）
- **不改双驱动**：连接 fd 单栈，只保留 v5 `ff_is_kernel_fd` 一次判定（NFR-2，不查 map）。

### 6.7 编译宏门控
- 6.1-6.5 全部新增代码置于 `#ifdef FF_KERNEL_COEXIST` 内；`ff_native_fd_map`/访问器/双驱动分支宏关时不编译。
- 双编译 nm 验证（`07 §1bis`）：宏关无 `ff_native_fd_map`/`ff_native_map_*` 等新符号、与 v6 之前一致；宏开符号出现、功能可用。

### 6.8 验收
- 自动双栈 socket/bind/listen 双建/双驱动（FR-2/FR-3）；一 listen 多用真机双向可达（FR-4）；统一事件双栈（FR-5）；accept 单栈归属（FR-6）；close 双驱动无泄漏（FR-7）；marker 单栈（FR-8/FR-9）；connect 契约确认后（FR-10）；config 开关（FR-11）；宏关/SOCK_FSTACK 零回归（NFR-1）；热路径无回归（NFR-2）；F-Stack 始终在位（NFR-3）。详见 `07`/`08`。

---

## 7. 风险与回退
- `ff_socket`/`ff_bind`/`ff_listen` 触及创建路径：默认双栈分支条件前置（marker 单栈 + coexist 开），单测覆盖零回归。
- 改 `ff_host_interface.c`（加 `ff_native_fd_map`）不改结构头，避免 ABI 偏斜；若改头须 clean 全量重编（`10 §7`）。
- **共存铁律**：任何阶段若 F-Stack fd 未建/被旁路 → 立即打回（违 NFR-3）。
- **connect 歧义**：§connect 草案未经用户确认前不得当定稿；门禁列「connect 契约确认」项。
- 严禁引入 KNI/`rte_kni`。

## 8. 工作区脚本规约
清理临时文件 `/data/workspace/rm_tmp_file.sh`、停进程 `/data/workspace/kill_process.sh`、改权限 `/data/workspace/chmod_modify.sh`。

## 9. 门禁回退
任一阶段失败打回上一步；同一步骤 bounce≤3 次，超限停止转人工；bounce 记入 `08`。
