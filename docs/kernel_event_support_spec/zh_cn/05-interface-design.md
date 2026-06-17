# 05 接口设计：标记选栈 + config 共存开关 + hook/原生双模式契约

> **文档编号**：SPEC-KE-05
> **版本**：v5（编译宏门控范式）
> **日期**：2026-06-17
> **状态**：编写中
> **作用域**：编译宏 `FF_KERNEL_COEXIST` 与 opt-in 契约、选栈标记约定、config 运行期共存开关、服务端/客户端用法、hook 与原生双模式适配、数据结构与错误处理。
> **核心原则**：**不新造旁路 API、不新造绕开 F-Stack 的 socket**；复用单 API（hook POSIX + 原生 `ff_*`），靠编译宏门控 + per-fd 标记 + 运行期 config 开关，F-Stack 始终在位。
> **依据**：`02`（代码现状，含实测行号）、`04`（架构）。行号以代码为准。

---

## 1. 接口基线（全部复用，不重造）

| 类别 | 复用接口 | 来源 |
|---|---|---|
| hook 模式（LD_PRELOAD + FF_KERNEL_EVENT） | POSIX `socket/bind/listen/accept/connect/close/epoll_*`（`ff_hook_*` 接管） | `adapter/syscall/ff_hook_syscall.c` |
| 原生模式 | `ff_socket/ff_bind/ff_listen/ff_accept/ff_connect/ff_close/ff_kqueue/ff_kevent`、`ff_epoll_*` | `lib/ff_api.h`、`lib/ff_epoll.c` |
| 内核侧封装 | hook：`ff_linux_*`（`ff_linux_syscall.c`）；原生：经 `ff_host_interface` 受管桥（本轮新增） | `ff_linux_syscall.c` / `ff_host_interface.c` |

> 本特性**不增加新的 socket/epoll API**，只标准化「选栈标记」+「config 运行期共存开关」两个约定，并由编译宏 `FF_KERNEL_COEXIST` 门控（默认关）。

---

## 1bis. 编译宏 `FF_KERNEL_COEXIST` 与 opt-in 契约（v5 核心）

| 项 | 约定 |
|---|---|
| 宏定义位置 | `lib/Makefile`：`#FF_KERNEL_COEXIST=1`（`:57-60` **默认注释关闭**）；`ifdef FF_KERNEL_COEXIST` 给 `HOST_CFLAGS`+`CFLAGS` 加 `-DFF_KERNEL_COEXIST`（`:174-177`） |
| 开启方式 | `make FF_KERNEL_COEXIST=1` 或取消 `lib/Makefile:60` 注释 |
| 编译期语义 | 未定义 → 共存代码（`02 §4bis.2` 7 文件包裹点）全部 `#ifdef` 排除，不编译，`libfstack.a` 逐字节零回归；定义 → 编译进共存 |
| **opt-in 可见性** | `SOCK_FSTACK`/`SOCK_KERNEL` 宏被 `FF_KERNEL_COEXIST` 包裹（`ff_api.h:81-99`）。**消费方 APP 须在包含 `ff_api.h` 前定义 `FF_KERNEL_COEXIST`**（如编译加 `-DFF_KERNEL_COEXIST`），否则见不到这两个标记宏，无法使用共存——这是「默认关闭、显式开启」的合理代价 |
| 运行期语义 | 仅编译宏已开启时，config `[stack] kernel_coexist=1` 才真正启用 per-fd `SOCK_KERNEL` 走内核栈 |

> **契约要点**：编译宏与 config 是**两层 gate**，缺一不可（`04 §1bis`）。`ff_api.symlist` 无需改动（桥函数仅库内调用、`static inline` 无导出符号）。

---

## 2. 选栈标记约定（per-fd，默认 F-Stack，被 `FF_KERNEL_COEXIST` 包裹）

```c
/* lib/ff_api.h:81-99，被 #ifdef FF_KERNEL_COEXIST 包裹（v5）；值同 adapter/syscall/ff_adapter.h:7-8 */
#ifndef SOCK_FSTACK
#define SOCK_FSTACK 0x01000000   /* 该 socket 走 F-Stack 用户态栈（默认） */
#endif
#ifndef SOCK_KERNEL
#define SOCK_KERNEL 0x02000000   /* 该 socket 走宿主 Linux 内核栈（需启用共存） */
#endif
```
- 叠加在 `type` 高位，不与 glibc `SOCK_*` 冲突；保留内层 `#ifndef` 双保护（与 adapter 头共存时不重定义）。
- 语义/优先级（实测 hook `ff_hook_socket:387` / 原生 `ff_syscall_wrapper.c:926`）：`(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)` → 内核；否则 → F-Stack。**`SOCK_FSTACK` 优先**。
- **选栈优先级链（修正 D3，代码无 `default_stack`）**：`per-socket marker（SOCK_KERNEL/SOCK_FSTACK）` > `config kernel_coexist 是否启用` > `F-Stack（默认）`。`ff_api.h:91` 注释残留的 "default_stack" 字样属过时，应忽略。

### 用法（同进程双栈共存）
```c
/* 业务监听走 F-Stack（默认，无需标记） */
int biz = socket(AF_INET, SOCK_STREAM, 0);          /* 或 |SOCK_FSTACK */
bind(biz, ...); listen(biz, backlog);                /* 经 DPDK NIC 服务业务 */

/* 同进程内：内核栈监听（本机 curl/ssh 直访） */
int mgmt = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
bind(mgmt, ...); listen(mgmt, backlog);              /* 落内核栈 */

/* 内核栈客户端 connect 本机/外部内核服务（FR-4/FR-5） */
int c = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
connect(c, (struct sockaddr*)&srv, sizeof(srv));     /* 按 fd 归属走内核 */

/* 同一 epoll 同时收 biz / mgmt / c 三类事件（统一事件） */
```

---

## 3. config.ini 共存能力开关（弱化版，不改默认语义）

### 3.1 配置项（设计草案）
```ini
[stack]
# 是否启用「内核栈共存」能力：0=禁用(纯 F-Stack)，1=启用(允许 per-fd SOCK_KERNEL 走内核栈)
# 注意：启用后默认仍 per-fd F-Stack，仅当 socket 显式带 SOCK_KERNEL 才走内核栈。
# 不提供「整进程默认走内核」选项（那会旁路 F-Stack）。
kernel_coexist = 0
```
- **解析落点（修正 D2，代码实测）**：`lib/ff_config.c:1027-1031` `MATCH("stack","kernel_coexist")`（`1/on/true/yes`→1，仿 KNI 段解析风格）。**非** v4 所称的 `:956`/`MATCH("kni","enable"):1011`。
- 结构落点（实测）：`struct ff_config`（`ff_config.h`）嵌套段 `:321-323`：
```c
struct {
    int kernel_coexist;
} stack;
```
- 默认值：`cfg->stack.kernel_coexist = 0`（`ff_config.c:1363`）。
- 读取：调用方直接读 `ff_global_cfg.stack.kernel_coexist`（如 `ff_socket` `:927`），无访问器。
- **与 v3 区别**：代码无 `default_stack`(fstack/kernel) / `default_to_kernel`「整进程默认内核」语义。
- **本段由 `FF_KERNEL_COEXIST` 包裹（v5）**：宏关闭时 `stack` 子结构与解析/默认赋值均不编译。

### 3.2 与 hook 模式关系
- hook 模式共存由编译宏 `FF_KERNEL_EVENT` 决定（README）。原生模式共存由编译宏 `FF_KERNEL_COEXIST` + 运行期 `[stack] kernel_coexist` 双层决定。两套编译宏相互独立（hook 在 `adapter/syscall`，原生在 `lib`）。hook 层 `ff_global_cfg` 为 stub（`ff_hook_syscall.c:31` "Just for so, no used"），故 hook 模式仍以其编译宏 `FF_KERNEL_EVENT` 为准（如实记录）。

### 3.3 多进程差异化
- 每进程经各自 config.ini 独立设 `kernel_coexist`（`ff_config.filename:254`）——多进程靠不同配置文件，无需线程级（NFR-6）。

---

## 4. 双模式适配契约

| 模式 | 共存现状 | v4 契约 |
|---|---|---|
| **hook（LD_PRELOAD + FF_KERNEL_EVENT）** | **已支持**（`ff_hook_socket:387-390`、`ff_hook_connect:858`、epoll 合并 `:2324+`） | **固化为主基线**，复核 + 正确同进程双栈 demo；行为不变 |
| **原生 `ff_api`** | **已实现**（`02 §4`，实测）：`ff_socket(SOCK_KERNEL)`+coexist→受管内核 fd（`ff_syscall_wrapper.c:926-931`）、`ff_epoll_pairs` 合并（`ff_epoll.c:210-241`） | **加 `FF_KERNEL_COEXIST` 编译宏门控（默认关）**：宏开时 `ff_socket(SOCK_KERNEL)` 建受管内核 fd；`ff_getsockopt/setsockopt/close/read/write/sendto/recvfrom/fcntl/accept/accept4/listen/bind/connect` 按 fd 路由（13 入口，见 `02 §4.3`）；`ff_epoll_wait` 合并；默认/`SOCK_FSTACK` 逐字节零回归。**路由未覆盖** `ff_readv/writev/send/recv/getpeername/getsockname/shutdown/ioctl/sendmsg/recvmsg`（D8 已知限制） |

> 实现须保证：两模式下「编译宏关 / 未启用共存 / 默认 / `SOCK_FSTACK`」行为与改造前**逐字节一致**（NFR-1），F-Stack 业务面始终在位（NFR-3）。

---

## 5. 关键数据结构（实测，修正 D6）

> v4 草案设计的 `enum ff_stack_owner`/「归属表」**未被采用**。实际实现用**编码偏移阈值 + 配对表**：

```c
/* config 段（ff_config.h:321-323），被 FF_KERNEL_COEXIST 包裹 */
struct { int kernel_coexist; } stack;

/* fd 区分：编码偏移 + 阈值判定（ff_host_interface.h:112-127），非 enum/归属表 */
#define FF_KERNEL_FD_BASE 0x40000000
/* 受管内核 fd = 宿主 fd + BASE；ff_is_kernel_fd(fd)=fd>=BASE；
   ff_kernel_fd_encode/real 编解码。远高于 FreeBSD fd 上限，区间不冲突。 */

/* epoll 配对表（ff_epoll.c:36-37），非「内核 epoll 镜像表」 */
#define FF_EPOLL_COEXIST_MAX 64
static struct { int kq; int host_ep; } ff_epoll_pairs[FF_EPOLL_COEXIST_MAX];
/* kqueue fd ↔ 惰性建的宿主 epoll fd 配对；ff_epoll_pairs_lock 保护。 */
```

---

## 6. 可观测（NFR-5）——**当前未实现（D5）**

> v4 草案的 `struct ff_stack_stats` / `ff_stack_get_stats` **代码尚未实现**，仅为设计意向，**不得当既成事实**。是否纳入本轮见 `04 §9` / `09`。

```c
/* 设计草案（未实现）：两栈 fd 数/事件数统计，若实现则不新增对外 socket API */
/* struct ff_stack_stats { uint64_t fstack_fds, kernel_fds, fstack_events, kernel_events; }; */
/* int ff_stack_get_stats(struct ff_stack_stats *out); */
```

---

## 7. 兼容矩阵

| 维度 | 取值 | 说明 |
|---|---|---|
| DPDK | 23.11.5 / 24.11.6 | 不依赖已移除 `rte_kni` |
| 编译宏 | `FF_KERNEL_COEXIST` 关（默认）/ 开 | 关→共存代码不编译、零回归；开→可用（opt-in，APP 须同样定义） |
| 模式 | hook（FF_KERNEL_EVENT）/ 原生（FF_KERNEL_COEXIST + kernel_coexist） | 见 §4 |
| 方向 | 服务端 + 客户端 | FR-2~FR-5 |
| 默认态 | 编译宏关 / 运行期未启用 / 不带标记 | 等价纯 F-Stack（NFR-1） |
| 业务面 | 始终 F-Stack | NFR-3 |
| `kern.maxfiles` | ≤ 65536 | fd 空间区分前提（`FF_KERNEL_FD_BASE` 远高于此） |

---

## 8. 错误处理约定

| 场景 | 行为 |
|---|---|
| 编译宏 `FF_KERNEL_COEXIST` 未定义 | `SOCK_*` 标记不可见、无内核分支——等价原 F-Stack |
| `type` 同置 `SOCK_KERNEL`+`SOCK_FSTACK` | 按优先级走 F-Stack（`ff_syscall_wrapper.c:926` / `ff_hook_socket:387` 条件不成立）；文档明示 |
| 运行期共存未启用却带 `SOCK_KERNEL`（原生） | **退化为 F-Stack**（实测 `ff_syscall_wrapper.c:926` 条件含 `&& ff_global_cfg.stack.kernel_coexist`，不满足则走原 `sys_socket`）；**不静默旁路** |
| 原生 `ff_epoll_wait maxevents < 1` | 返回 `-EINVAL`（`ff_epoll.c:215`）；hook `maxevents < 2` 返回 `-EINVAL`（`adapter/syscall/ff_hook_syscall.c:2212-2218`） |
| 内核侧 socket/connect 失败 | 返回原生 `errno`，不静默回退 |
| 内核/F-Stack 地址端口冲突 | 返回 `-EADDRINUSE` |
| 关闭受管内核 fd | `ff_close:1092-1093` 路由 `ff_host_close`；`ff_epoll_pairs` 配对清理需 review 复核（`03 §2.6`），避免内核 fd 泄漏（FR-8） |
| 对受管内核 fd 调用未路由接口 | `ff_readv/writev/send/recv/getpeername/getsockname/shutdown/ioctl/sendmsg/recvmsg` 会误走 F-Stack（D8 已知限制） |

---

## 9. 待决问题
- `FF_KERNEL_COEXIST` 包裹边界精确性（确保不破坏 `ff_host_interface.c` 等文件的非共存部分）。
- `ff_close` 对 `ff_epoll_pairs` 配对的清理是否完整（fd leak 复核，`03 §2.6`）。
- D8 路由覆盖是否补齐 `ff_readv/writev/send/recv/...`，或接受为已知限制。
- 可观测统计（`ff_stack_get_stats`）**未实现**（D5），是否纳入本轮。

> 已确定（实测）：config 项 `kernel_coexist`（默认 0，`ff_config.c:1027-1031`/`:1363`）；fd 区分用 `FF_KERNEL_FD_BASE` 编码偏移（非归属表/enum，D6）；`ff_epoll_wait` 内核事件 `timeout=0` 取（`ff_epoll.c:228`）。引用行号以代码为准。
