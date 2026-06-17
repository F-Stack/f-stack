# 02 现状分析：F-Stack 现有「双栈共存」机制（以代码为准）

> **文档编号**：SPEC-KE-02
> **版本**：v5（编译宏门控范式）
> **日期**：2026-06-17
> **状态**：编写中
> **作用域**：实测 F-Stack 中「同一进程内 F-Stack 用户态栈 + 宿主内核栈共存」的现有机制与**当前已落地的原生共存代码**，作为 v5 的**直接复用基线（hook 模式）+ 参考（nginx）+ 待加编译宏门控的现有原生实现**。覆盖：选栈标记、hook FF_KERNEL_EVENT 共存、nginx kernel_network_stack 共存、**原生模式共存现状（已实现、当前无条件编译）**、编译宏门控现状与 7 文件包裹点、v3 错误回退核对。
> **铁律**：所有断言带 `相对路径:行号`（相对 `/data/workspace/f-stack/`）；与文档/注释冲突以**实际代码为准**并显式标注。

---

## 0. v5 现状定位

| 现状能力 | 位置 | 形态 | v5 角色 |
|---|---|---|---|
| **hook 模式 FF_KERNEL_EVENT 双栈共存** | `adapter/syscall/`（LD_PRELOAD） | 标记选栈 + `fstack_kernel_fd_map` 双栈 epoll 合并 | **直接复用并固化为主基线** |
| **nginx kernel_network_stack 双栈共存** | `app/nginx-1.28.0/` | per-listen `belong_to_host` + 双事件后端（kqueue+epoll） | **参考实现（同构证明共存可行）** |
| **原生 `ff_api` 双栈共存（已落地）** | `lib/`（`ff_socket`/`ff_epoll.c`/`ff_host_interface`/`ff_config`） | 受管内核 fd（`FF_KERNEL_FD_BASE` 偏移）+ `ff_epoll_pairs` 配对合并 + 各 `ff_*` 入口路由 | **已实现，当前无条件编译；v5 加 `FF_KERNEL_COEXIST` 门控（默认关）** |
| 选栈标记 | `adapter/syscall/ff_adapter.h:7-8`、`lib/ff_api.h:94-99` | `SOCK_FSTACK`/`SOCK_KERNEL` type 高位 | **复用为 per-fd 共存标记，v5 由 `FF_KERNEL_COEXIST` 包裹（opt-in）** |

> KNI（`lib/ff_dpdk_kni.c` + `config.ini [kni]`）是另一套独立「报文回灌」机制，**不属于本特性**（见 `00`/`03`）。

> **关键现状修正（对照 v4 描述）**：v4 spec 把原生 `ff_api` 事件层描述为「纯 kqueue 封装、无内核 fd 感知」的**缺口**。**实测代码该缺口已被填补**——`lib/` 中已有完整的原生共存实现（见 §4）。v5 的核心工作不是「新设计」，而是给这些**已存在但当前无条件编译**的代码**加上 `FF_KERNEL_COEXIST` 编译宏门控（默认关闭）**，使不开启共存的部署逐字节零回归。

---

## 1. 选栈标记（已实测）

`adapter/syscall/ff_adapter.h:5-8`：
```c
//#define SOCK_CLOEXEC  0x10000000
//#define SOCK_NONBLOCK 0x20000000
#define SOCK_FSTACK 0x01000000
#define SOCK_KERNEL 0x02000000
```
- 叠加在标准 `socket()` 的 `type` 高位，不与 glibc `SOCK_*` 真值冲突。
- 默认（不置标记）走 F-Stack；带 `SOCK_KERNEL`（且无 `SOCK_FSTACK`）走内核栈。`lib/ff_api.h` 已 `#ifndef` 暴露这两个宏（v3 遗留，正确，保留）。

---

## 2. hook 模式 FF_KERNEL_EVENT：双栈共存主基线（已实测）

> README（`adapter/syscall/README.md:169-186`）原文："This mode can support both F-Stack and the system kernel's socket interface at the same time." 启用：`Makefile` 或 `export FF_KERNEL_EVENT=1`。demo=`main_stack_epoll_kernel.c`。

### 2.1 标记选栈（应用 on F-Stack，业务默认走 F-Stack）
`adapter/syscall/ff_hook_syscall.c`：
- `fstack_territory(domain,type,protocol)` `:360`：剥离 `SOCK_CLOEXEC/NONBLOCK/FSTACK/KERNEL`（:363-366），仅 `AF_INET/INET6`+`SOCK_STREAM/DGRAM` 属 F-Stack 领域。
- `ff_hook_socket` `:380`：
  ```c
  if (fstack_territory(...)==0) return ff_linux_socket(...);        /* :383-385 非领域 → 内核 */
  if ((type & SOCK_KERNEL) && !(type & SOCK_FSTACK)) {             /* :387 显式内核 */
      type &= ~SOCK_KERNEL; return ff_linux_socket(...);          /* :388-390 → 内核栈 */
  }
  ... type &= ~SOCK_FSTACK;                                        /* :406 默认 → F-Stack 业务栈 */
  ```
  注释 `:376-378`："APP need set type |= SOCK_FSTACK"。**默认业务走 F-Stack，per-fd `SOCK_KERNEL` 走内核——二者在同一进程共存。**

### 2.2 fd 归属与后续路由
- `CHECK_FD_OWNERSHIP(name,args)` `:57-61`：`if(!is_fstack_fd(fd)) return ff_linux_##name args;`——非 F-Stack fd 转内核。
- `is_fstack_fd(sockfd)` `:309`：F-Stack fd 经编码偏移区分（配 `convert_fstack_fd`/`restore_fstack_fd`）。
- `bind/listen/accept/connect/recv/send/close` 入口均经 `CHECK_FD_OWNERSHIP` 按归属分流；客户端 `ff_hook_connect` `:847-886`（`:858` CHECK_FD_OWNERSHIP、`:881` `SYSCALL(FF_SO_CONNECT)`）纯按 fd 归属路由。

### 2.3 双栈统一事件（FF_KERNEL_EVENT 核心）
- 映射表 `:257-258` `int fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES];`（`=65536`）。
- `ff_hook_epoll_create` `:1981`：按 `SOCK_KERNEL` 选内核 epoll（`:1982-1983`），并镜像内核 epoll fd（`:1996-1998` `fstack_kernel_fd_map[ret]`）。
- ctl 路由非 fstack fd `:2016-2023`；wait 合并（先 `timeout=0` 取内核事件+节流，再合并 F-Stack 事件）`:2324+`（`:2333-2336`）；`maxevents>=2` `:2212-2218`。
- close 联动释放两栈 fd `:1874-1883`。
- 内核侧封装 `adapter/syscall/ff_linux_syscall.c`（dlsym 宿主 libc）：socket:81/bind:88/listen:96/accept:131/connect:144/close:217/epoll_create:233/epoll_ctl:239/epoll_wait:247。

> **结论**：hook 模式已是「应用 on F-Stack + per-fd 标记选栈 + 双栈 epoll 合并」的完整共存实现，**v4 固化为主基线**，并补正确的同进程双栈 demo（v3 demo 是纯内核、错误）。

---

## 3. nginx kernel_network_stack：双栈共存参考（已实测）

- 指令 `src/http/ngx_http_core_module.c:298-303`（`NGX_HAVE_FSTACK`，`ngx_conf_set_flag_slot` → `offsetof(ngx_http_core_srv_conf_t, kernel_network_stack)`）；字段 `ngx_http_core_module.h:206` `ngx_flag_t kernel_network_stack;`；merge 默认 `0`（`:3540-3541`，注释 `:3539` "By default, we set up a server on fstack"）。stream/mail 同有实现。
- 落归属：`src/http/ngx_http.c:1890` `ls->belong_to_host = cscf->kernel_network_stack;`（stream `ngx_stream.c:1049`）。
- socket 按归属加/不加 `SOCK_FSTACK`：`ngx_ff_skip_listening_socket()` `src/core/ngx_connection.c:22-49`（worker 非内核监听 `*type |= SOCK_FSTACK` `:46`）。
- **双事件后端共存**：F-Stack=kqueue 主后端 `ngx_event_actions`；内核=独立 Linux epoll 后端 `ngx_ff_host_event_actions`（`src/event/modules/ngx_ff_host_event_module.c:441`）；`ngx_add_event/ngx_del_event` 按 `ev->belong_to_host` 分流（`src/event/ngx_event.h:408-424`）；事件循环同时跑两栈（`src/event/ngx_event.c:258-280`：先 `ngx_process_events`(kqueue) 再 `ngx_ff_process_host_events`(epoll)）。
- fd 区分：`convert/restore_fstack_fd` + `is_fstack_fd`（fd≥`ngx_max_sockets`，`src/event/modules/ngx_ff_module.c:147-167`）。
- 归属传播：listen→event `ngx_event.c:889`；accept 继承 `ngx_event_accept.c:236`；connect 按 fd 判定 `ngx_connection.c:1310` `is_fstack_fd(s)?0:1`。

> **结论**：nginx 进程整体 on F-Stack（worker 跑 DPDK+FreeBSD 栈），per-server `kernel_network_stack on` 让该 server 走内核栈，双事件后端在同一 worker 共存——与 v4「共存」范式完全同构，作为参考。

---

## 4. 原生 ff_api 模式共存实现现状（已落地，实测；v5 待加编译宏门控）

> **D7 修正**：v4 称原生模式「无法共存 / `ff_socket` 恒建 F-Stack socket / `ff_epoll.c` 纯 kqueue」——**该缺口已被代码填补**。以下为实测的已落地实现，**当前全部无条件编译**，v5 需用 `#ifdef FF_KERNEL_COEXIST` 包裹。

### 4.1 fd 空间区分（受管内核 fd，非裸绕过）
- `lib/ff_host_interface.h:112` `#define FF_KERNEL_FD_BASE 0x40000000`；`:114-127` 三个 `static inline`：`ff_is_kernel_fd(fd)=fd>=BASE`、`ff_kernel_fd_encode(host_fd)=host_fd+BASE`、`ff_kernel_fd_real(fd)=fd-BASE`。受管内核 fd 对应用呈现为 `host_fd+BASE`，远高于 FreeBSD fd 上限（`kern.maxfiles`≤65536），与 F-Stack fd 区间不冲突。

### 4.2 受管内核侧桥（宿主 socket 族封装）
- `lib/ff_host_interface.h:136-158`：18 个 `ff_host_*` 桥声明（`socket/bind/listen/accept/connect/close/read/write/recv/send/sendto/recvfrom/accept4/setsockopt/getsockopt/fcntl/epoll_create1/epoll_ctl/epoll_wait`）。声明用 `unsigned int`（见 §6 D4）。
- `lib/ff_host_interface.c:246-367`：上述 18 个桥的实现（直接调宿主 libc 同名函数）；实现签名用 `socklen_t`。配套 `:29-31` `#ifndef _GNU_SOURCE`（为 `accept4`/`epoll_create1`）、`:42-45` 新增 `<sys/socket.h>/<sys/epoll.h>/<fcntl.h>/<unistd.h>`。

### 4.3 socket 创建与归属路由
- `lib/ff_syscall_wrapper.c:913-943 ff_socket`：`:926-931` 当 `(type & SOCK_KERNEL) && !(type & SOCK_FSTACK) && ff_global_cfg.stack.kernel_coexist` → `ff_host_socket(...)` 建宿主 socket 并 `ff_kernel_fd_encode` 返回受管内核 fd；否则 `:933-939` 原 `linux2freebsd_socket_flags`+`sys_socket` 路径**逐字节未改**。
- 各入口前置 `ff_is_kernel_fd` 路由块（实测行号）：`ff_getsockopt:951-953`、`ff_setsockopt:998-1000`、`ff_close:1092-1093`、`ff_read:1111-1112`、`ff_write:1166-1167`、`ff_sendto:1316-1320`、`ff_recvfrom:1407-1409`、`ff_fcntl:1480-1481`、`ff_accept:1503-1506`、`ff_accept4:1536-1539`、`ff_listen:1565-1566`、`ff_bind:1587-1588`、`ff_connect:1607-1608`。命中即转对应 `ff_host_*` 桥（`ff_kernel_fd_real(fd)`）。
- `lib/ff_syscall_wrapper.c:64` `#include "ff_config.h"`（为读 `ff_global_cfg.stack.kernel_coexist`）。

### 4.4 统一事件合并
- `lib/ff_epoll.c:36-37` `#define FF_EPOLL_COEXIST_MAX 64` + `static struct { int kq; int host_ep; } ff_epoll_pairs[64];`；`:38` 互斥锁；`:42-68` `ff_epoll_host_ep(kq,create)` 惰性建并查 kqueue↔宿主 epoll 配对。
- `ff_epoll_create:71-75` 仍 `return ff_kqueue();`（不变）。
- `ff_epoll_ctl:97-111`：`ff_is_kernel_fd(fd)` 命中 → 惰性取/建配对 host epoll → `ff_host_epoll_ctl`；否则走原 kqueue 路径（不变）。
- `ff_epoll_wait:210-241`：`:226` 若有配对 host epoll，`:228` 先 `ff_host_epoll_wait(timeout=0)` 取内核事件，`:235-236` 再 `ff_kevent_do_each` 取 F-Stack 事件合并；无内核 fd 时退化原 kqueue-only 行为（零回归）。

### 4.5 config 运行期开关
- `lib/ff_config.h:321-323` `struct { int kernel_coexist; } stack;`。
- `lib/ff_config.c:1027-1031` `MATCH("stack","kernel_coexist")` 解析（`1/on/true/yes`→1）；`:1363` 默认 `cfg->stack.kernel_coexist = 0`。

### 4.6 选栈标记宏（lib 侧）
- `lib/ff_api.h:81-99`：`SOCK_FSTACK 0x01000000`/`SOCK_KERNEL 0x02000000`，内层 `#ifndef` 双保护（`:94-99`）。注：`:91` 注释残留 "default_stack" 字样属过时（见 §6 D3）。

> **现状结论**：原生模式共存**已实现并可运行**（见 `08`/`10` 实测）。当前问题是**全部无条件编译**——即使不用共存也链接进 `ff_host_*`/`ff_epoll_pairs` 等代码，无法对原 F-Stack 保证逐字节零回归。v5 的工作即用 `#ifdef FF_KERNEL_COEXIST` 包裹这些代码（默认关）。

---

## 4bis. 编译宏 `FF_KERNEL_COEXIST` 门控现状与 7 文件包裹点

### 4bis.1 Makefile 现状（实测）
- `lib/Makefile:57-60`：已有注释说明 + `#FF_KERNEL_COEXIST=1`（**默认注释关闭**）。
- `lib/Makefile:174-177`：`ifdef FF_KERNEL_COEXIST` / `HOST_CFLAGS+= -DFF_KERNEL_COEXIST` / `CFLAGS+= -DFF_KERNEL_COEXIST` / `endif`（仿 `FF_LOOPBACK_SUPPORT:169-172` / `FF_IPFW:113-116`，已是双侧 CFLAGS）。
- **当前差距**：Makefile 的宏基础设施已就位（默认关），但**源码 `.c/.h` 尚无任何 `#ifdef FF_KERNEL_COEXIST` 包裹**（`grep FF_KERNEL_COEXIST lib/` 仅命中 Makefile）——故当前即便宏关闭，共存代码仍被编译。v5 须补齐源码包裹。

### 4bis.2 待包裹 7 文件（编译单元归属）

| # | 文件 | 待包裹点（实测行号） | 编译单元 |
|---|---|---|---|
| 1 | `lib/ff_api.h` | `:81-99` `SOCK_FSTACK`/`SOCK_KERNEL` 宏块（保留内层 `#ifndef`） | 两侧头 |
| 2 | `lib/ff_host_interface.h` | `:94-158` `FF_KERNEL_FD_BASE`+3 inline+18 `ff_host_*` 声明 | 两侧头 |
| 3 | `lib/ff_host_interface.c` | `:29-31`(`_GNU_SOURCE`)+`:42-45`(新增 include)+`:246-367`(18 桥实现) | HOST_CFLAGS |
| 4 | `lib/ff_config.h` | `:321-323` `struct{int kernel_coexist;}stack;` | HOST_CFLAGS |
| 5 | `lib/ff_config.c` | `:1027-1031`(解析)+`:1363`(默认赋值) | HOST_CFLAGS |
| 6 | `lib/ff_epoll.c` | `:25-68`(注释+`FF_EPOLL_COEXIST_MAX`+`ff_epoll_pairs`+lock+`ff_epoll_host_ep`)+`:97-111`(`ff_epoll_ctl` 分支)+`:210-241`(`ff_epoll_wait` 合并) | HOST_CFLAGS |
| 7 | `lib/ff_syscall_wrapper.c` | `:64`(`#include "ff_config.h"`)+`:919-931`(`ff_socket` 分支)+各入口路由块（见 §4.3 行号） | CFLAGS |

- 三头被两侧包含；`ff_host_interface.c`/`ff_config.c`/`ff_epoll.c` 属 HOST_CFLAGS，`ff_syscall_wrapper.c` 属 CFLAGS——故 Makefile 须同时给 `HOST_CFLAGS` 与 `CFLAGS` 加 `-DFF_KERNEL_COEXIST`（已满足 `:174-177`）。
- `ff_api.symlist` **无需改动**（桥函数仅库内调用，`static inline` 无导出符号）。

---

## 5. v3 错误回退核对（已回退，commit 0748eff94）

| 项 | v3 错误 | v4 处置 |
|---|---|---|
| `lib/ff_syscall_wrapper.c` ff_socket | `SOCK_KERNEL→ff_host_socket` 裸宿主 socket（绕开 F-Stack） | **已回退**为干净 F-Stack 路径 |
| `lib/ff_host_interface.{c,h}` | `ff_host_socket`=裸 `socket()`、`ff_default_stack_is_kernel` 声明 | **已回退** |
| `example/helloworld_stacksel/` | 全程纯内核 socket、无 F-Stack 业务 | 待 R2/R3 重写为**同进程双栈共存** demo |
| `lib/ff_config.{c,h}` `[stack] default_stack` | 整进程默认内核（反 F-Stack） | 待 R3 改为**共存能力开关**（不改默认 per-fd F-Stack） |
| `10-perf-baseline-report` | 基于纯内核 bench | 作废/重写为共存对 F-Stack 快路径无回归 |

---

## 6. 交叉验证差异清单（文档/注释 vs 代码，以代码为准）

| 编号 | 出处（文档/注释声称） | 代码实测 | 实际结论 |
|---|---|---|---|
| D1 | v3 误把「ff_socket→纯内核 socket」当方案 | hook/nginx 均为「应用 on F-Stack + 内核 fd 共存」 | v3 方向错误；已改为共存，F-Stack 始终在位 |
| D2 | v4 `05 §3.1` 称解析在 `ff_config.c:956`、仿 `MATCH("kni","enable"):1011` | 解析块实际在 `ff_config.c:1027-1031` | **行号修正**：解析在 `:1027-1031`，默认赋值 `:1363` |
| D3 | `ff_api.h:91` 注释「优先级…> config.ini [stack] default_stack > F-Stack」；v4 多处提 `default_stack` | 代码无 `default_stack` 配置项（仅 `kernel_coexist`），`ff_api.h:91` 注释残留属过时 | 优先级链改为「per-socket marker > config `kernel_coexist` 启用 > F-Stack」 |
| D4 | — | `ff_host_interface.h` 声明用 `unsigned int`，`ff_host_interface.c` 实现用 `socklen_t` | Linux 下二者等价可编译；如实记录此签名差异 |
| D5 | v4 `05 §6` 设计 `struct ff_stack_stats`/`ff_stack_get_stats` | 代码**未实现** | 标注「未实现/待定」，不得当既成事实 |
| D6 | v4 `05 §5` 设计 `enum ff_stack_owner`/「归属表」 | 实际为 `FF_KERNEL_FD_BASE` 阈值编码偏移 + `ff_epoll.c ff_epoll_pairs[64]` 配对表 | **非** enum/归属表；按实现描述 fd 区分与配对 |
| D7 | v4 `02 §4` 称原生「无法共存 / `ff_socket` 恒建 F-Stack socket / `ff_epoll.c` 纯 kqueue」 | 缺口**已被代码填补**（见 §4） | 改为「已实现，本轮新增编译宏门控」 |
| D8 | — | 路由仅覆盖 13 个入口（见 §4.3）；`ff_readv/ff_writev/ff_send/ff_recv/ff_getpeername/ff_getsockname/ff_shutdown/ff_ioctl/ff_sendmsg/ff_recvmsg` **未加** `ff_is_kernel_fd` 路由 | 路由覆盖不完整，须在「已知限制」如实列出 |

---

## 7. 用于撰写 04/05/06/09 的要点清单

- **主基线=hook FF_KERNEL_EVENT**：复用标记选栈（`ff_hook_socket:387-390`）+ 双栈 epoll 合并（`fstack_kernel_fd_map:257-258`/`:2324+`）+ close 联动（`:1874-1883`），固化并补正确 demo。
- **参考=nginx kernel_network_stack**：per-listen 开关 + 双事件后端（kqueue+epoll）同 worker 共存。
- **原生统一事件共存（已落地）**：lib 内 fd 区分（`FF_KERNEL_FD_BASE` 偏移）+ 受管内核 fd（`ff_host_*` 桥，非裸绕过）+ `ff_epoll.c ff_epoll_pairs` 合并 kqueue⊕epoll；默认/`SOCK_FSTACK` 零回归。
- **编译宏门控（v5 核心）**：`FF_KERNEL_COEXIST` 包裹 §4bis.2 的 7 文件；`lib/Makefile` 默认注释关；宏关闭 → 共存代码不编译、`libfstack.a` 与原 F-Stack 逐字节零回归。
- **config**：仿 `[kni]` 增**运行期共存开关** `kernel_coexist`（`:1027-1031`/`:1363`），无整进程默认内核语义。
- **共存铁律**：F-Stack 用户态栈始终承担业务，内核栈仅附加旁路（NFR-3）。
