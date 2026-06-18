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
| **R7** | **native 自动双栈（v6）** | 默认双建/双驱动 + `ff_native_fd_map` + 双栈事件 + accept 归属 + connect 草案 | 已完成（门禁 PASS） |
| R8 | 内核路由补齐 | `sendmsg/recvmsg/getpeername/getsockname/shutdown` 内核 fd 路由（D8） | 已完成 |
| **R9** | **kqueue 共存 + IPv6 V6ONLY** | `ff_kqueue/ff_kevent/ff_kevent_do_each` 共存（仿 `ff_epoll`，P2）+ host IPv6 socket `IPV6_V6ONLY=1`（P1） | 已完成 |
| **R10** | **残余入口共存补齐** | `readv/writev/ioctl` 内核 fd 路由（仿 `read/write`，D12-D13）+ `dup/dup2`（D14）+ `select/poll` 文档限制（D15）+ 新增 host 桥 `ff_host_readv/writev/ioctl/dup/dup2` | **本轮设计；impl 已落地编译通过（真机/单测待验）** |

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

## 6bis. R9 kqueue 共存 + IPv6 V6ONLY（编码工作清单）

> **前置现状（实测，`02 §7`）**：R7 双栈事件仅覆盖 `ff_epoll_*`；`ff_kqueue/ff_kevent/ff_kevent_do_each` 无共存路由（grep 仅 `ff_epoll.c` 命中宏）；`example/main.c` kqueue 模型内核侧 `curl 127.0.0.1:80=000`。`-DINET6` 双建因 host IPv6 V6ONLY 缺失 `ff_bind errno=98` 启动失败。

### 6bis.1 `ff_kqueue/ff_kevent` 共存（P2，核心）
- `ff_syscall_wrapper.c::ff_kqueue`（`#ifdef FF_KERNEL_COEXIST`）：coexist 开时返回 F-Stack kqueue fd，首次 `ff_kevent` 惰性配对 host epoll（复用 `ff_epoll.c` 的 `ff_epoll_host_ep(kq,create)`/`ff_epoll_pairs`）。
- `ff_syscall_wrapper.c::ff_kevent`（`#ifdef FF_KERNEL_COEXIST`）：
  - **changelist**：对 ident 为内核 fd（`ff_is_kernel_fd`）或双栈 fd（`ff_native_map_get>0`）的 EV_ADD/EV_DELETE → `ff_host_epoll_ctl`（`EVFILT_READ↔EPOLLIN`/`EVFILT_WRITE↔EPOLLOUT`，`epoll_event.data`=应用面 fd）；内核-only 变更不下发 F-Stack kqueue。
  - **eventlist**：先 `ff_host_epoll_wait(host_ep, timeout=0)` 合成 `struct kevent`（`ident`=app fd 还原、`filter`=READ/WRITE、`EV_EOF`=EPOLLHUP/ERR），再 `ff_kevent_do_each` 填 F-Stack 事件，合并计数。
- `ff_close` 对 kqueue fd 清 `ff_epoll_pairs`+关 host_ep（复用 `ff_epoll_close_pair`，R7 已含）；复核 kqueue 与 epoll 共享 `ff_epoll_pairs` 时各自 kq 独立配对，不混用。
- **落点/行号执行期以代码实测为准**（禁臆测）。

### 6bis.2 IPv6 双建 V6ONLY（P1）
- `ff_socket` 双建 host IPv6 socket 后、或 `ff_host_socket` 内：对 `domain==AF_INET6/LINUX_AF_INET6` 的 host socket `setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 1)`（落点执行期实测择优）。
- best-effort：V6ONLY 从根消除 v4/v6 同端口冲突；host bind 失败保持可诊断（`05 §7`）。

### 6bis.3 编译宏门控
- 6bis.1/6bis.2 全部新增代码置于 `#ifdef FF_KERNEL_COEXIST` 内；宏关时 `ff_kqueue/ff_kevent` 逐字节零回归、无新符号（`07 §1bis` nm 比对）。

### 6bis.4 验收
- plain helloworld（kqueue，coexist=1）内核侧 `curl 127.0.0.1:80=200 size=438`，且 F-Stack 侧 `ssh f-stack-client→9.134.214.176:80=200` 不回归（FR-5/FR-6）。
- `-DINET6` helloworld（coexist=1）成功启动（v4+v6 listen 均建立），抓包确认内核侧 200。
- 宏关/coexist=0/`SOCK_FSTACK` 逐字节零回归（NFR-1）；F-Stack 始终在位（NFR-3）。详见 `07`/`08`。

---

## 6ter. R10 残余入口共存补齐（编码工作清单）

> **前置现状（实测，`02 §7bis`）**：`ff_readv`/`ff_writev`/`ff_ioctl` 无 `FF_KERNEL_COEXIST` 内核 fd 路由（read/write 有）；额外发现 `ff_dup`/`ff_dup2`/`ff_select`/`ff_poll` 亦无共存路由。改动后实际行号：`ff_ioctl:1067`/`ff_readv:1189`/`ff_writev:1251`/`ff_select:1879`(注释)/`ff_poll:1903`(注释)/`ff_dup:2130`/`ff_dup2:2156`。

### 6ter.1 host 桥（新增，仿 `ff_host_read/write`，声明 `ff_host_interface.h:178-184`）
- `ff_host_interface.{c,h}`（`#ifdef FF_KERNEL_COEXIST`，HOST_CFLAGS）：`ff_host_readv`/`ff_host_writev`/`ff_host_ioctl`/`ff_host_dup`/`ff_host_dup2`。直接调宿主 libc 同名函数；`iov` 以 `void*` 透传规避命名空间冲突（仿 sendmsg/recvmsg），实现处 cast `const struct iovec*`。include 块新增 `sys/uio.h`、`sys/ioctl.h`。

### 6ter.2 readv / writev 路由（D12，主，低风险）
- `ff_readv`/`ff_writev`（`#ifdef FF_KERNEL_COEXIST`）：前置 `if (ff_is_kernel_fd(fd)) return ff_host_readv/writev(ff_kernel_fd_real(fd), iov, iovcnt);`，仿 `ff_read`/`ff_write`。连接 fd 单栈，热路径只一次判定（NFR-2）。

### 6ter.3 ioctl 路由（D13，主，中风险）
- `ff_ioctl`：在 `va_arg` 取 `argp` 后、`linux2freebsd_ioctl` 翻译**之前**插入 `if (ff_is_kernel_fd(fd)) return ff_host_ioctl(real, request, argp);`（**原始 Linux request，不翻译**）。
- **双栈 fd 同驱动 R10.1 已实现**（仿 `ff_fcntl`）：F-Stack 成功后对 `FIONBIO`/`FIOASYNC` 用原始 Linux request 同步配对 host fd；`FIONREAD` 等 query 类不同驱动以免覆盖 argp。

### 6ter.4 dup / dup2（D14，额外发现）
- `ff_dup`：内核 fd→`ff_host_dup(real)`+`ff_kernel_fd_encode`（n<0 返回 -1）。
- `ff_dup2`：两端内核 fd→`ff_host_dup2`+encode；混栈（一端内核一端 F-Stack）明确拒绝 **errno=EINVAL**；两端 F-Stack 走原 `sys_dup2`。

### 6ter.5 select / poll（D15，额外发现，均不实现降级文档限制）
- `ff_select`：encode 内核 fd≫`FD_SETSIZE`(1024)→**硬限制不实现**，仅加注释。
- `ff_poll`：混合纯内核 fd 子集需拆分/索引映射/合并 revents，复杂度与回归风险高→**保守不实现**，仅加注释。均建议内核 fd 用 `ff_epoll_*`/`ff_kqueue`（R9 已支持）。

### 6ter.6 编译宏门控
- 6ter.1-6ter.5 全部新增代码置于 `#ifdef FF_KERNEL_COEXIST` 内；宏关时 `ff_readv/writev/ioctl/dup/dup2/select/poll` 逐字节零回归、无新符号（含新增 host 桥，`07 §1bis` nm 比对，impl 已验证）。

### 6ter.7 验收
- UT：`ff_host_readv/writev/ioctl/dup` host 桥（真实 socketpair/pipe/socket）+ encode 内核 fd 经 `ff_readv/writev/ioctl/dup` 命中 host 桥（mock/真实 host fd）。
- 真机：内核侧（127.0.0.1）对受管内核 fd 做 readv/writev/ioctl 行为正确；helloworld 不回归（内核侧 200、F-Stack 侧 200）。
- 宏关/coexist=0/`SOCK_FSTACK` 逐字节零回归（NFR-1）。详见 `07`/`08`。

---

## 7. 风险与回退
- `ff_socket`/`ff_bind`/`ff_listen` 触及创建路径：默认双栈分支条件前置（marker 单栈 + coexist 开），单测覆盖零回归。
- 改 `ff_host_interface.c`（加 `ff_native_fd_map`）不改结构头，避免 ABI 偏斜；若改头须 clean 全量重编（`10 §7`）。
- **共存铁律**：任何阶段若 F-Stack fd 未建/被旁路 → 立即打回（违 NFR-3）。
- **connect 歧义**：§connect 草案未经用户确认前不得当定稿；门禁列「connect 契约确认」项。
- **R9 kqueue 与 epoll 共享 `ff_epoll_pairs`**：须确认同一 kq 不被 epoll 与 kevent 两种语义混用（`ff_epoll_create` 返回独立 kqueue，风险低，仍须 review）；`FF_EPOLL_COEXIST_MAX` 容量在多 kq 场景须评估是否够用。
- **R9 IPV6_V6ONLY 落点**：须实测（`ff_host_socket` 通用 vs `ff_socket` 双建处），避免影响纯内核 `SOCK_KERNEL` IPv6。
- **R10-R1 ioctl 双栈同驱动范围过宽**：仅对明确必要的控制 ioctl（如 `FIONBIO`）同驱动 host，其余仅 encode 内核 fd 路由，以实测为准，避免回归。
- **R10-R2 dup2 混栈语义**：明确拒绝 errno=EINVAL 并文档化，不臆造（已实测）。
- **R10-R3 poll 实现复杂度**：经评估高风险，已降级为文档限制，未强行实现（避免 bounce 超限，已实测）。
- **R10-R4 iovec 跨命名空间**：沿用 sendmsg/recvmsg 的 `void*` 透传。
- 严禁引入 KNI/`rte_kni`。

## 8. 工作区脚本规约
清理临时文件 `/data/workspace/rm_tmp_file.sh`、停进程 `/data/workspace/kill_process.sh`、改权限 `/data/workspace/chmod_modify.sh`。

## 9. 门禁回退
任一阶段失败打回上一步；同一步骤 bounce≤3 次，超限停止转人工；bounce 记入 `08`。
