# 05 接口设计：自动双栈契约 + marker 语义 + config + connect 草案 + 异常矩阵

> **文档编号**：SPEC-KE-05
> **版本**：v6（native 自动双栈共存范式）
> **日期**：2026-06-17
> **状态**：编写中（v6 设计）
> **作用域**：编译宏 + opt-in 契约、marker 语义、各 `ff_*` 双栈/双驱动契约、`ff_native_fd_map` 访问器、config 开关、connect 契约草案（待确认）、异常矩阵。
> **核心原则**：**不新造旁路 API**；复用单 API（`ff_*`），靠编译宏门控 + 默认双栈 + marker 单栈覆盖 + 运行期 config 开关，F-Stack 始终在位。
> **依据**：`02`（代码现状，含实测行号）、`04`（架构）。行号以代码为准。**v6 新增契约均为待实现设计。**

---

## 1. 接口基线（全部复用，不重造）

| 类别 | 复用接口 | 来源 |
|---|---|---|
| 原生模式 | `ff_socket/ff_bind/ff_listen/ff_accept/ff_accept4/ff_connect/ff_close/ff_setsockopt/ff_fcntl`、`ff_epoll_*`、`ff_kqueue/ff_kevent` | `lib/ff_api.h`、`lib/ff_epoll.c`、`lib/ff_syscall_wrapper.c` |
| 受管内核侧桥（v5 已落地） | 18 个 `ff_host_*`（`socket/bind/listen/accept/accept4/connect/close/...epoll_*`） | `lib/ff_host_interface.{c,h}` |
| **native 映射表 + 访问器（v6 新增）** | `ff_native_fd_map` + `ff_native_map_get/set/clear` | `lib/ff_host_interface.{c,h}`（待实现） |

> v6 **不增加对外 socket/epoll API**，只升级默认语义为自动双栈 + 新增库内访问器；`ff_api.symlist` 无需改动（访问器/桥仅库内调用）。

---

## 1bis. 编译宏 `FF_KERNEL_COEXIST` 与 opt-in 契约

| 项 | 约定 |
|---|---|
| 宏定义位置 | `lib/Makefile:57-60` `#FF_KERNEL_COEXIST=1`（默认注释关）；`:174-177` `ifdef` 给 `HOST_CFLAGS`+`CFLAGS` 加 `-DFF_KERNEL_COEXIST` |
| 开启方式 | `make FF_KERNEL_COEXIST=1` 或取消 `lib/Makefile:60` 注释 |
| 编译期语义 | 未定义 → 共存代码（含 `ff_native_fd_map`、默认双建/双驱动、marker 宏）全部 `#ifdef` 排除，`libfstack.a` 逐字节零回归；定义 → 编译进共存 |
| **opt-in 可见性** | `SOCK_FSTACK`/`SOCK_KERNEL` 被 `FF_KERNEL_COEXIST` 包裹（`ff_api.h:81-99`）。APP 须在含 `ff_api.h` 前定义 `FF_KERNEL_COEXIST` 才可见 marker（编译加 `-DFF_KERNEL_COEXIST`）。**注意**：v6 默认双栈无需 marker，故仅当 APP 想单栈覆盖时才需 marker 可见 |
| 运行期语义 | 仅编译宏开启时，`[stack] kernel_coexist=1` 才启用自动双栈 |

---

## 2. marker 语义（v6：单栈覆盖默认双栈）

```c
/* lib/ff_api.h:81-99，被 #ifdef FF_KERNEL_COEXIST 包裹；值同 adapter/syscall/ff_adapter.h:7-8 */
#ifndef SOCK_FSTACK
#define SOCK_FSTACK 0x01000000   /* 仅 F-Stack 用户态栈（单栈覆盖，零回归路径） */
#endif
#ifndef SOCK_KERNEL
#define SOCK_KERNEL 0x02000000   /* 仅宿主内核栈（单栈覆盖） */
#endif
```

| `type` marker | v6 语义 | 返回 fd | map 项 |
|---|---|---|---|
| 无 marker（默认） | **双栈**：建 F-Stack + 内核 | F-Stack 原始 fd | `map[fstack]=host` |
| `SOCK_KERNEL`（且无 `SOCK_FSTACK`） | 仅内核 | `ff_kernel_fd_encode(host)`≥BASE | 无 |
| `SOCK_FSTACK`（或同置二者） | 仅 F-Stack | F-Stack 原始 fd | 无 |

- 判定（实测 `ff_socket:929`）：`(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)` → 仅内核；带 `SOCK_FSTACK` → 仅 F-Stack；都不带 + coexist 开 → 默认双栈（v6 新增分支）。**`SOCK_FSTACK` 优先**。
- **选栈优先级链（v6，D3）**：`per-socket marker(SOCK_KERNEL/SOCK_FSTACK)` > `自动双栈(kernel_coexist 启用)` > `F-Stack（默认/共存关）`。

### 用法（自动双栈，无需 marker）
```c
/* v6：默认 listen 同时在 F-Stack(DPDK NIC) 与 内核栈 监听 80 */
int s = ff_socket(AF_INET, SOCK_STREAM, 0);          /* 双栈：建 F-Stack fd + 内核 host fd */
ff_bind(s, &addr80, sizeof(addr80));                  /* 双驱动：两栈各 bind 80 */
ff_listen(s, backlog);                                /* 双驱动：两栈各 listen */
ff_epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev);              /* 双注册：kqueue + 内核 epoll，透传 ev.data */
/* 远端 curl 9.134.214.176:80（F-Stack 侧）+ 本机 curl 127.0.0.1:80（内核侧）皆可达 */

/* 需要单栈时用 marker 覆盖 */
int konly = ff_socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);   /* 仅内核 */
int fonly = ff_socket(AF_INET, SOCK_STREAM | SOCK_FSTACK, 0);   /* 仅 F-Stack（零回归） */
```

---

## 3. 各 `ff_*` 双栈/双驱动契约（v6）

> 三态路由前缀（所有改造在 `#ifdef FF_KERNEL_COEXIST` 内，运行期 `kernel_coexist=0` 短路）：
> ```c
> if (ff_is_kernel_fd(fd)) return ff_host_xxx(ff_kernel_fd_real(fd), ...);  /* 单栈内核（v5 已有） */
> /* ... F-Stack 原路径（kern_*/sys_*） ... */
> int hfd = ff_native_map_get(fd);                                          /* v6 双栈检测 */
> if (hfd > 0) ff_host_xxx(hfd, ...);                                       /* 双驱动 */
> ```

| 接口 | 实测行号 | 单栈内核(v5) | F-Stack 路径 | 双栈双驱动(v6 新增) |
|---|---|---|---|---|
| `ff_socket` | :915-947 | `SOCK_KERNEL`→`ff_host_socket`+encode | 默认/`SOCK_FSTACK`→`sys_socket` | 默认→`sys_socket`(s)+`ff_host_socket`(h)+`ff_native_map_set(s,h)`，返回 s |
| `ff_bind` | :1607-1627 | `ff_host_bind(real)` | `kern_bindat` | `kern_bindat` 成功后 `ff_host_bind(map[s], 原始 linux addr)` |
| `ff_listen` | :1584-1605 | `ff_host_listen(real)` | `sys_listen` | `sys_listen` 后 `ff_host_listen(map[s], backlog)` |
| `ff_accept` | :1514-1547 | `ff_host_accept(real)`+encode | `kern_accept` | 双栈 listen → §accept 单栈归属 |
| `ff_accept4` | :1549-1582 | `ff_host_accept4(real)`+encode | `kern_accept4` | 同 §accept |
| `ff_connect` | :1629-1649 | `ff_host_connect(real)` | `kern_connectat` | §connect 契约草案（待确认） |
| `ff_close` | :1095-1112 | `ff_host_close(real)` | `kern_close` | `kern_close` 后 `ff_host_close(map[fd])`+`ff_native_map_clear`；kqueue fd 清 `ff_epoll_pairs`+关 host_ep |
| `ff_setsockopt` | :999 | `ff_host_setsockopt(real)` | `kern_setsockopt` | 双栈 fd 两栈同步设置 |
| `ff_fcntl` | :1495 | `ff_host_fcntl(real)` | `kern_fcntl` | 双栈 fd 两栈同步设置（如 O_NONBLOCK） |
| recv/send/read/write/recvfrom/sendto | 各入口 | `ff_host_*(real)` | F-Stack 原路径 | **不双驱动**：只按 `ff_is_kernel_fd` 路由（连接 fd 单栈，热路径 NFR-2，不查 map） |

> **热路径铁律**：accept 后的连接 fd 是单栈，recv/send 等只做一次 `ff_is_kernel_fd` 判定，**不查 `ff_native_fd_map`**——零额外开销（NFR-2）。

---

## 3ter. R9：`ff_kqueue/ff_kevent` 共存契约 + IPv6 V6ONLY

> R7 双栈事件仅覆盖 `ff_epoll_*`；R9 对称补 `ff_kqueue/ff_kevent` 共存（复用 `ff_epoll_pairs`）与 host IPv6 socket `IPV6_V6ONLY=1`。全程 `#ifdef FF_KERNEL_COEXIST`，运行期 `kernel_coexist=0` 短路，宏关零回归。

| 接口 | 实测落点 | 单栈内核(R7 等) | F-Stack 路径 | R9 共存（新增） |
|---|---|---|---|---|
| `ff_kqueue` | `ff_syscall_wrapper.c` | — | 原 kqueue fd | coexist 开：返回 F-Stack kqueue fd；首次 `ff_kevent` 惰性配对 host epoll（复用 `ff_epoll_host_ep`） |
| `ff_kevent`（changelist） | `ff_syscall_wrapper.c` | — | `ff_kevent_do_each` 下发 F-Stack kqueue | ident 为内核 fd/双栈 fd 的 EV_ADD/EV_DELETE → `ff_host_epoll_ctl`（`EVFILT_READ↔EPOLLIN`/`EVFILT_WRITE↔EPOLLOUT`，`data`=应用面 fd）；内核-only 变更不下发 F-Stack kqueue |
| `ff_kevent`（eventlist） | `ff_syscall_wrapper.c` | — | `ff_kevent_do_each` 取 F-Stack 就绪 | 先 `ff_host_epoll_wait(timeout=0)` 取内核就绪→合成 `struct kevent`（`ident`=app fd 还原、`filter`=READ/WRITE、`EV_EOF`=EPOLLHUP/ERR），再 `ff_kevent_do_each` 合并计数 |
| `ff_socket(AF_INET6)` host 侧 | `ff_socket`/`ff_host_socket` | — | — | host IPv6 socket `setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 1)`，只处理 IPv6、与 host IPv4 同端口共存 |

- **app fd 还原契约**：注册进 host epoll 时 `epoll_event.data` 存「应用面 fd」（双栈=F-Stack 原始 fd、内核-only=encode fd）；等待时还原为 `kevent.ident`，应用对同一 ident 的 `EVFILT_READ` 分支照常 `ff_accept`/read/write（R7 已 coexist 路由）。
- **close 联动**：kqueue fd `ff_close` 清 `ff_epoll_pairs` + 关 host_ep（复用 `ff_epoll_close_pair`，§3 `ff_close` 已含）。
- **IPV6_V6ONLY best-effort**：优先从根消除 v4/v6 同端口冲突；host bind 失败仍可诊断，是否「非致命」由 R9 实现期按代码实测定（仿 `ff_connect`）。仅作用于 host socket，不影响 `SOCK_KERNEL` IPv6 与 F-Stack 路径。

---

## 3quater. R10：readv/writev/ioctl 内核 fd 路由 + dup/dup2/select/poll 契约

> R8 后 `readv/writev/ioctl` 仍列 D8 已知限制；R10 补齐内核 fd 路由（仿 `ff_read/write`），并对额外发现的 `dup/dup2/select/poll` 给出契约或文档限制。全程 `#ifdef FF_KERNEL_COEXIST`，运行期 `kernel_coexist=0` 短路，宏关零回归。**impl 已落地编译通过、宏关零回归已验证。**

| 接口 | 实际行号 | 单栈内核(R10 新增) | F-Stack 路径 | 双栈 fd 双驱动 |
|---|---|---|---|---|
| `ff_readv` | L1189 | `ff_host_readv(real, iov, iovcnt)` | `kern_readv` | **不双驱动**（连接 fd 单栈，热路径 NFR-2，仿 `ff_read`） |
| `ff_writev` | L1251 | `ff_host_writev(real, iov, iovcnt)` | `kern_writev` | **不双驱动**（仿 `ff_write`） |
| `ff_ioctl` | L1067 | `ff_host_ioctl(real, 原始 Linux request, argp)`（不经 `linux2freebsd_ioctl`） | `linux2freebsd_ioctl`→`kern_ioctl` | **R10.1 已实现**（`FIONBIO`/`FIOASYNC` 同步配对 host fd，仿 `ff_fcntl`；`FIONREAD` 等 query 类不同驱动） |
| `ff_dup` | L2130 | 内核 fd→`ff_host_dup(real)`+`ff_kernel_fd_encode`（n<0 返回 -1） | `sys_dup` | — |
| `ff_dup2` | L2156 | 两端内核 fd→`ff_host_dup2`+encode；混栈→拒绝 errno=EINVAL | `sys_dup2` | — |
| `ff_select` | L1879 | **不实现（硬限制，仅注释）**：encode fd≫`FD_SETSIZE`(1024) | `kern_select` | — |
| `ff_poll` | L1903 | **不实现（文档限制，仅注释）**：合并复杂度/回归风险高 | `kern_poll` | — |

- **ioctl request 契约**：内核 host fd 必须用**原始 Linux request**（`_IO/_IOR/_IOW(type,nr,size)` 编码在 Linux/FreeBSD 不同源，`03` 交叉验证），`ff_host_ioctl` 直传 host libc；F-Stack 路径仍 `linux2freebsd_ioctl` 翻译。`va_arg` 取 `argp` 方式与现有一致。**双栈 fd 同驱动 R10.1 已实现**（`FIONBIO`/`FIOASYNC` 同步配对 host fd，仿 `ff_fcntl`；`FIONREAD` 等 query 类不同驱动以免覆盖 argp）。
- **dup2 混栈拒绝**：一端内核 fd 一端 F-Stack fd 的 dup2 语义不成立，明确拒绝置 **errno=EINVAL**（两 fd 各自有效但语义不成立，比 EBADF 贴切，已实测），不臆造。
- **select 硬限制**：encode 内核 fd（≥`0x40000000`）远超 `fd_set` 的 `FD_SETSIZE`(1024) 索引上限，无法放入 `fd_set`——`ff_select` 对内核 fd **不支持共存**（仅加注释）；推荐内核 fd 用 `ff_epoll_*`/`ff_kqueue`（R9 已共存）多路复用。
- **poll 文档限制**：`pollfd.fd` 虽可容 encode fd，但 `kern_poll` 直接操作 FreeBSD pollfd，混合纯内核 fd 子集需拆分数组/索引映射/合并 revents/超时合并，复杂度与回归风险高——R10 **保守不实现**（仅加注释），建议改用 `ff_epoll_*`/`ff_kqueue`。

---

## 3bis. `ff_native_fd_map` 访问器契约（v6 待实现）

```c
/* ff_host_interface.h，#ifdef FF_KERNEL_COEXIST */
int  ff_native_map_get(int fstack_fd);   /* 返回 host_fd（>0）或 0（无映射）；fstack_fd 越界返回 0 */
void ff_native_map_set(int fstack_fd, int host_fd);
void ff_native_map_clear(int fstack_fd);
/* ff_host_interface.c：static int ff_native_fd_map[FF_MAX_FREEBSD_FILES](=65536)，无锁（单线程轮询，NFR-5） */
```
- `get` 返回 `>0` 即双栈 fd；`0` 即单栈 F-Stack。
- 下标 = fstack fd（<65536）；越界（不应发生）保护性返回 0。

---

## 4. config.ini 共存能力开关

```ini
[stack]
# 是否启用「内核栈自动双栈共存」能力：0=禁用(纯 F-Stack)，1=启用(默认 socket 自动双栈)
# 启用后：默认无 marker 的 socket 同时建 F-Stack + 内核双栈；SOCK_FSTACK 仅 F-Stack、SOCK_KERNEL 仅内核。
# 不提供「整进程默认走内核」选项（那会旁路 F-Stack）。
kernel_coexist = 0
```
- 解析（实测）：`lib/ff_config.c:1027-1031` `MATCH("stack","kernel_coexist")`（`1/on/true/yes`→1）；默认 `:1363` `=0`。结构 `ff_config.h:321-323` `struct{int kernel_coexist;}stack;`。读取直接读 `ff_global_cfg.stack.kernel_coexist`（`ff_socket:930`）。
- 全段被 `FF_KERNEL_COEXIST` 包裹；宏关时子结构与解析/默认均不编译。
- 多进程靠各自 config.ini（`ff_config.filename:254`，NFR-6）。
- **本机测试改动不提交**（lcore_mask/port IP/idle_sleep 等本地值），提交仅含 `[stack]` 特性改动。

---

## 5. §accept 单栈归属契约（Q3=A）

```
ff_accept(s, addr, addrlen)   要求 s 非阻塞（epoll 驱动典型）
  if ff_is_kernel_fd(s):        ─► ff_host_accept(real(s)) + encode（单栈内核 listen，v5 已有）
  else:
    rc = kern_accept(s, ...)    ─► 成功: 返回 F-Stack 原始连接 fd（单栈 F-Stack）
    if errno in {EAGAIN, EWOULDBLOCK} and ff_native_map_get(s) > 0:
        kc = ff_host_accept(map[s], ...)  ─► 成功: 返回 ff_kernel_fd_encode(kc)（单栈内核）
        if kc EAGAIN: 返回 EAGAIN
    else: 返回 kern_accept 结果/错误
```
- 连接 fd **单栈**，无 map 项；后续 recv/send/close 按 `ff_is_kernel_fd` 路由。
- 两栈皆 EAGAIN 才返回 EAGAIN（epoll 触发后总有一栈就绪）。
- `ff_accept4` 同构（flags 透传两栈）。

---

## 6. §connect 双栈契约草案（Q2=B，**待用户最终确认**）

> **语义歧义声明**：一条客户端逻辑连接（一个 fd 上的 send/recv）**无法真双工于两栈**——数据物理上只能走一栈。默认双栈 connect 只能「两栈各建连，选一为数据主路径」。

**v6 契约草案**：
```
ff_connect(s, name, namelen)   s 为双栈 fd (ff_native_map_get(s)>0)
  ├─ kern_connectat(s, name)        ─► F-Stack 侧 connect（数据主路径，返回主导）
  └─ ff_host_connect(map[s], name)  ─► 内核侧 connect（并发建连，双网可达备援）
  返回：以 F-Stack 为主（非阻塞下 EINPROGRESS）
  数据路径：默认 F-Stack 主；内核侧并发建连用于双网可达
  close：联动拆两栈（§3 ff_close 双驱动）
```
- **明确分流**：
  - 纯内核客户端 → `SOCK_KERNEL`（无歧义，仅内核）。
  - kernel-primary / failover / Happy-Eyeballs → **为后续，不在 v6 保证**。
- **本契约须经用户最终确认后定稿**（spec 显式标注；门禁 `08` 列「connect 契约确认」项）。

### 6bis §connect 异常矩阵（草案）

| 场景 | F-Stack 侧 | 内核侧 | 契约行为 |
|---|---|---|---|
| 两栈都 EINPROGRESS（非阻塞典型） | EINPROGRESS | EINPROGRESS | 返回 EINPROGRESS（以 F-Stack 为准）；epoll 关注两栈可写 |
| F-Stack 成功、内核失败 | 0 | 失败 | 返回 0（F-Stack 主路径可用）；内核侧标记不可用、记日志（可观测，D5 未实现） |
| F-Stack 失败、内核成功 | 失败 | 0 | **契约待确认**：草案返回 F-Stack 错误（F-Stack 主）；若需内核兜底为后续 failover |
| 两栈都失败 | 失败 | 失败 | 返回 F-Stack 错误（errno 以 F-Stack 为准） |
| 阻塞 fd | 同步 connect | — | **建议**：双栈 connect 要求非阻塞；阻塞场景契约待确认 |
| 目的地址仅内核可达（如 127.0.0.1） | 可能失败 | 成功 | 草案 F-Stack 失败 → 需用户确认是否内核兜底（否则建议用 `SOCK_KERNEL`） |

> 异常矩阵随 §connect 契约一并待用户确认。

---

## 7. 错误处理约定

| 场景 | 行为 |
|---|---|
| 编译宏 `FF_KERNEL_COEXIST` 未定义 | marker 不可见、无双建/双驱动——等价原 F-Stack（NFR-1） |
| `kernel_coexist=0` | 双建/双驱动分支运行期短路，仅建 F-Stack（NFR-1，不静默旁路） |
| `type` 同置 `SOCK_KERNEL`+`SOCK_FSTACK` | 走仅 F-Stack（`SOCK_FSTACK` 优先，`ff_socket:929` 条件不成立） |
| **双建部分失败**（F-Stack 成功、`ff_host_socket` 失败） | **契约**：不静默——草案为「降级为仅 F-Stack 单栈（不登记 map）+ 记日志」，或回滚返回错误；**须 R7 实现时定稿并测**（边界） |
| `ff_epoll_wait maxevents<1` | `-EINVAL`（`ff_epoll.c:221`） |
| 内核/F-Stack 地址端口冲突 | 返回原生 errno（双栈某栈 bind 失败按部分失败契约处理） |
| close 双栈 fd | 两栈 close + `ff_native_map_clear`；kqueue fd 清 `ff_epoll_pairs`（避免内核 fd 泄漏，FR-7） |
| 内核 fd 调用 `sendmsg/recvmsg/getpeername/getsockname/shutdown` | R8 已加内核路由：前 4 内核 fd 走 `ff_host_*` 单栈；`shutdown` 内核 fd 走 host，双栈 map fd 两侧双驱动半关闭（仿 `ff_close`） |
| 内核 fd 调用 `readv/writev/ioctl/dup/dup2` | **R10 已加内核路由**：`readv/writev` 内核 fd 走 `ff_host_readv/writev(real)`（仿 read/write 单栈）；`ioctl` 内核 fd 走 `ff_host_ioctl(real, 原始 Linux request)`（双栈 fd 同驱动 R10.1 已支持 `FIONBIO`/`FIOASYNC`）；`dup` 内核 fd→`ff_host_dup`+encode；`dup2` 两端内核 fd→`ff_host_dup2`+encode，**混栈拒绝 errno=EINVAL**。详见 §3quater |
| 内核 fd 调用 `select`/`poll`（D15） | **均不支持共存**：`select` encode 内核 fd≫`FD_SETSIZE`(1024) 无法装入 `fd_set`（硬限制）；`poll` 合并复杂度/回归风险高，R10 保守不实现（文档限制）。推荐内核 fd 用 `ff_epoll_*`/`ff_kqueue`（R9 已共存） |
| **R9：`ff_kevent` 内核 fd 仅支持 `EVFILT_READ/WRITE`** | 内核侧经 host epoll，仅 `EPOLLIN/EPOLLOUT` 语义；`EVFILT_TIMER/SIGNAL/PROC/VNODE` 等非 READ/WRITE filter 对内核 fd **不经 host epoll 共存**（已知限制，仍走 F-Stack kqueue 原语义）；`EV_EOF` 映射 `EPOLLHUP\|EPOLLERR` |
| **R9：IPv6 双建 V6ONLY 失败** | host IPv6 socket `setsockopt(IPV6_V6ONLY,1)` 失败时按部分失败契约（记日志，不静默；不影响 F-Stack v6 listen） |

---

## 8. 兼容矩阵

| 维度 | 取值 | 说明 |
|---|---|---|
| DPDK | 23.11.5 / 24.11.6 | 不依赖已移除 `rte_kni` |
| 编译宏 | `FF_KERNEL_COEXIST` 关（默认）/ 开 | 关→零回归；开→可用（opt-in） |
| 运行期 | `kernel_coexist` 0/1 | 0→纯 F-Stack；1→自动双栈 |
| 创建形态 | 默认双栈 / `SOCK_KERNEL` 仅内核 / `SOCK_FSTACK` 仅 F-Stack | §2 |
| 连接 fd | 单栈（accept/marker 决定） | §5 |
| 业务面 | 始终 F-Stack | NFR-3 |
| `kern.maxfiles` | ≤ 65536 | `ff_native_fd_map` 容量与 fd 空间前提 |

---

## 9. 可观测（NFR）——**当前未实现（D5）**

> `ff_stack_get_stats` 草案（两栈 fd 数/事件数）**代码未实现**，不得当既成。connect 部分失败的内核侧标记可借此暴露，是否纳入本轮见 `04 §12`/`09`。

---

## 10. 待决问题
- §connect 双栈数据路径契约 + 异常矩阵（**待用户最终确认**）。
- 双建部分失败的回滚/降级契约（R7 定稿）。
- 双栈 fd 对未路由接口行为（默认仅 F-Stack 驱动）。
- `ff_close` 对 `ff_epoll_pairs` 清理完整性（fd leak 复核）。
- 可观测统计未实现（D5）。

> 已确定（实测）：config `kernel_coexist`（默认 0，`ff_config.c:1027-1031`/`:1363`）；`FF_KERNEL_FD_BASE=0x40000000` 编码偏移（`ff_host_interface.h:113`）；`ff_epoll_pairs[64]` 配对（`ff_epoll.c:38`）。**v6 新增**：`ff_native_fd_map`/默认双建/双驱动/双栈 listen 双注册——**待 R7 实现**。
