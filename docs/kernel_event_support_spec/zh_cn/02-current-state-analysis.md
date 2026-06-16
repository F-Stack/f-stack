# 02 现状分析：F-Stack 现有「双栈共存」机制（以代码为准）

> **文档编号**：SPEC-KE-02
> **版本**：v4（共存范式返工重写）
> **日期**：2026-06-16
> **状态**：编写中
> **作用域**：实测 F-Stack 中「同一进程内 F-Stack 用户态栈 + 宿主内核栈共存」的现有机制，作为 v4 的**直接复用基线（hook 模式）+ 参考（nginx）+ 新设计落点（原生模式）**。覆盖：选栈标记、hook FF_KERNEL_EVENT 共存、nginx kernel_network_stack 共存、原生事件层缺口、v3 错误回退核对。
> **铁律**：所有断言带 `相对路径:行号`（相对 `/data/workspace/f-stack/`）；与文档/注释冲突以**实际代码为准**并显式标注。

---

## 0. v4 现状定位

| 现状能力 | 位置 | 形态 | v4 角色 |
|---|---|---|---|
| **hook 模式 FF_KERNEL_EVENT 双栈共存** | `adapter/syscall/`（LD_PRELOAD） | 标记选栈 + `fstack_kernel_fd_map` 双栈 epoll 合并 | **直接复用并固化为主基线** |
| **nginx kernel_network_stack 双栈共存** | `app/nginx-1.28.0/` | per-listen `belong_to_host` + 双事件后端（kqueue+epoll） | **参考实现（同构证明共存可行）** |
| 原生 `ff_api` 事件层 | `lib/ff_epoll.c` | 纯 kqueue 封装，无内核 fd 感知 | **缺口**：原生共存需新设计（见 §4） |
| 选栈标记 | `adapter/syscall/ff_adapter.h:7-8` | `SOCK_FSTACK`/`SOCK_KERNEL` type 高位 | **复用为 per-fd 共存标记** |

> KNI（`lib/ff_dpdk_kni.c` + `config.ini [kni]`）是另一套独立「报文回灌」机制，**不属于本特性**（见 `00`/`03`）。

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

## 4. 原生 ff_api 模式的事件层缺口（v4 新设计落点，已实测）

- `lib/ff_epoll.c`：`ff_epoll_create(size)` `:25-28` = `return ff_kqueue();`；`ff_epoll_ctl` `:31-104` → `ff_kevent`；`ff_epoll_wait` `:148-158` → `ff_kevent_do_each`。**纯 F-Stack kqueue 封装，零内核 fd 感知**。
- 原生入口 `lib/ff_syscall_wrapper.c:912 ff_socket` → `linux2freebsd_socket_flags(type)` `:668-677`（仅 NONBLOCK/CLOEXEC，**不识别 SOCK_KERNEL/SOCK_FSTACK**）→ `sys_socket` 必进 FreeBSD 栈。
- 原生应用跑 `ff_run(loop,arg)`（`ff_api.h:59`）DPDK 主循环；事件用 `ff_kqueue/ff_kevent`（`ff_api.h:158-159`）或 `ff_epoll_*`。
- **缺口结论**：原生模式当前**无法共存**——没有 fd 归属表、内核 epoll 镜像、事件合并；`ff_socket` 恒建 F-Stack socket。要让原生应用一进程双栈共存，v4 需在 lib 内**仿 hook/nginx 新建**：(a) fd 归属登记；(b) `ff_socket(SOCK_KERNEL)` 经 `ff_host_interface` 建**受管内核 fd**（登记归属，**非 v3 的裸绕过**）；(c) `ff_bind/ff_listen/ff_accept/ff_connect/ff_close/ff_epoll_ctl` 按归属路由到宿主 syscall；(d) `ff_epoll_wait` 合并 kqueue⊕内核 epoll。默认/`SOCK_FSTACK` 路径逐字节零回归。详见 `04`/`05`/`06`。

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

## 6. 交叉验证差异清单（文档/注释 vs 代码）

| 编号 | 出处 | 代码出处 | 实际结论 |
|---|---|---|---|
| D1 | v3 误把「ff_socket→纯内核 socket」当方案 | hook/nginx 均为「应用 on F-Stack + 内核 fd 共存」 | v3 方向错误；v4 改为共存，F-Stack 始终在位 |
| D2 | 注释「首版不支持 ff_linux_epoll_wait」 | `:2324+` 实际已调用（带节流） | 以代码为准：已调用 |
| D3 | 原生 `ff_socket` 识别 SOCK_KERNEL？ | `:918`+`linux2freebsd_socket_flags:668-677` | 不识别，恒建 F-Stack socket；原生共存需 §4 新设计 |

---

## 7. 用于撰写 04/05/06 的要点清单

- **主基线=hook FF_KERNEL_EVENT**：复用标记选栈（`ff_hook_socket:387-390`）+ 双栈 epoll 合并（`fstack_kernel_fd_map:257-258`/`:2324+`）+ close 联动（`:1874-1883`），固化并补正确 demo。
- **参考=nginx kernel_network_stack**：per-listen 开关 + 双事件后端（kqueue+epoll）同 worker 共存。
- **新设计=原生统一事件共存**：lib 内 fd 归属 + 受管内核 fd（`ff_host_interface` 宿主 socket，非裸绕过）+ `ff_epoll_wait` 合并 kqueue⊕epoll；默认/`SOCK_FSTACK` 零回归。
- **config**：仿 `[kni]` 增**共存能力开关**（启用/禁用内核栈共存），删除整进程默认内核语义。
- **共存铁律**：F-Stack 用户态栈始终承担业务，内核栈仅附加旁路（NFR-3）。
