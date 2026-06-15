# 02 现状分析：F-Stack 现有"连接级选栈"机制（以代码为准）

> **文档编号**：SPEC-KE-02
> **版本**：v2（全量重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：实测 F-Stack 中两类"让某连接/事件走宿主机内核栈"的现有机制（机制 A/B），作为本特性 lib 的代码基线。
> **铁律**：所有断言带 `相对路径:行号`（相对 `/data/workspace/f-stack/`）；与文档/README 冲突以**实际代码为准**。

---

## 0. 两类机制定位

| 机制 | 位置 | 粒度 | 本特性中的角色 |
|---|---|---|---|
| **A** nginx `kernel_network_stack` | `app/nginx-1.28.0/` | **连接/监听级** | **首要参考**：1-bit 标志选栈 + 双事件后端 |
| **B** `FF_KERNEL_EVENT` | `adapter/syscall/` | **fd / event 级** | **次要参考**：fd 归属判定 + 双栈 epoll 合并 |

> KNI（`lib/ff_dpdk_kni.c` + `config.ini [kni]`）是**另一套独立的"报文回灌内核"机制**，解决"裸报文回内核"，**不属于本特性**（详见 `00-overview.md` 范围声明），本文不展开。

---

## 1. 机制 A：nginx `kernel_network_stack`（连接级选栈）

### 1.1 配置开关注册
- 指令定义：`app/nginx-1.28.0/src/http/ngx_http_core_module.c:297-304`，名为 `kernel_network_stack`，作用域 `NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG`，`ngx_conf_set_flag_slot`，存入 `ngx_http_core_srv_conf_t.kernel_network_stack`。
- 默认值：`create_srv_conf` 设 `NGX_CONF_UNSET`（`ngx_http_core_module.c:3492-3494`）；`merge_srv_conf` 默认 0（`:3538-3542`），即**默认走 F-Stack**。
- 受 `NGX_HAVE_FSTACK` 宏保护（F-Stack 适配编译期开关）。

### 1.2 标志传播链（配置 → 监听 → 连接）
- 监听级：`src/http/ngx_http.c:1890` `ls->belong_to_host = cscf->kernel_network_stack;`（`#if (NGX_HAVE_FSTACK)` 保护，:1889-1891）。
- 位字段定义：
  - 连接结构 `struct ngx_connection_s`：`src/core/ngx_connection.h:93` `unsigned belong_to_host:1;`（:92-94）。
  - 事件结构 `ngx_event_t`：`src/event/ngx_event.h:140` `unsigned belong_to_host:1;`（:139-141）。

### 1.3 选栈核心（决定 socket 走哪栈）
- `src/event/ngx_event_connect.c:46-50`：

```c
if (!pc->belong_to_host) {
    s = ngx_socket(pc->sockaddr->sa_family, type | SOCK_FSTACK, 0);
} else {
    s = ngx_socket(pc->sockaddr->sa_family, type, 0);
}
```

`belong_to_host==0` → `type|SOCK_FSTACK` 走 F-Stack；`==1` → 普通 `socket()` 走**内核栈**。`SOCK_FSTACK` 是 F-Stack 适配层在 socket type 上附加的标志位。

### 1.4 双事件后端（内核 fd 与 fstack fd 分别投递）
- `src/event/ngx_event.h:195` `extern ngx_event_actions_t ngx_ff_host_event_actions;`（内核侧事件动作集，`#if (NGX_HAVE_FSTACK)`）。
- `src/event/ngx_event.h:408-414` `ngx_add_event`：`if (1 == ev->belong_to_host) return ngx_ff_host_event_actions.add(...) else return ngx_event_actions.add(...)`；`ngx_del_event` 同理（:417-423）。
- `src/event/ngx_event.h:446` `#define ngx_ff_process_host_events ngx_ff_host_event_actions.process_events`（内核侧事件循环处理入口）。
- 内核侧事件模块：存在文件 `src/event/modules/ngx_ff_host_event_module.c`（实现 `ngx_ff_host_event_actions`，承接 `belong_to_host` 连接的内核 epoll 事件）。

### 1.5 机制 A 小结（对本特性的启示）
- **选栈粒度**：per-server（`server{}` 内 `kernel_network_stack on;`）→ 传播到 listen → 连接 → 事件。
- **关键范式**：用 **1-bit 标志**在 `socket()` 处选栈 + 为内核栈连接配**独立事件后端**，使同一进程内"内核栈连接"与"F-Stack 连接"并存且各自正确收事件。
- **本机访问语义**：某 `server{}` 开 `kernel_network_stack on` 后其监听 socket 是普通内核 socket，本机 `curl` 可经内核栈直达。

---

## 2. 机制 B：`FF_KERNEL_EVENT`（fd/event 级双栈合并）

### 2.1 编译开关
- `adapter/syscall/Makefile`：`FF_KERNEL_EVENT` 通过 `-DFF_KERNEL_EVENT` 开启；对应 demo 目标 `helloworld_stack_epoll_kernel`（源 `main_stack_epoll_kernel.c`）。

### 2.2 fd 归属判定与映射表
- `ff_hook_syscall.c:57-61` `CHECK_FD_OWNERSHIP` 宏：`if (!is_fstack_fd(fd)) return ff_linux_##name args;`——**非 F-Stack fd 直接转内核 `ff_linux_*`**。
- `ff_hook_syscall.c:309` `is_fstack_fd(int sockfd)`：判定某 fd 是否属于 F-Stack（F-Stack fd 经编码偏移区分；配套 `convert_fstack_fd`/`restore_fstack_fd`）。
- `ff_hook_syscall.c:257-258` `int fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES];`（`FF_MAX_FREEBSD_FILES=65536`）——记录"F-Stack epoll fd → 内核 epoll fd"的映射。

### 2.3 双栈 epoll 链路
- create：`ff_hook_epoll_create` 在 `FF_KERNEL_EVENT` 下同时 `ff_linux_epoll_create` 建内核 epoll，存入 `fstack_kernel_fd_map[ret]`（`:1996-1998`）。
- ctl：`ff_hook_epoll_ctl` 对非 fstack fd 路由到内核 epoll（`:2016-2023`，用 `restore_fstack_fd(epfd)` 取回 `fstack_kernel_fd_map[ff_epfd]`）。
- wait：`ff_hook_epoll_wait` 先按节流调用 `ff_linux_epoll_wait(fstack_kernel_fd_map[fd], ...timeout=0)` 取内核事件再与 F-Stack 事件合并（`:2329-2338`）；`maxevents>=2` 约束（`:2212-2218` 附近）。
- close：`ff_hook_close` 联动关闭内核侧 fd（`:1874-1883`）。

### 2.4 连接级选栈标志 `SOCK_KERNEL`（重要事实，已实测）
机制 B 同样具备**连接级选栈**能力，且与机制 A 同构——通过 socket type 上的标志位选栈：
- 标志定义：`adapter/syscall/ff_adapter.h:7-8`：`#define SOCK_FSTACK 0x01000000`、`#define SOCK_KERNEL 0x02000000`。
- `ff_hook_socket`（`:379-427`）选栈分支（实测）：

```c
if (fstack_territory(domain, type, protocol) == 0)       /* :383 非 fstack 领域 */
    return ff_linux_socket(domain, type, protocol);      /* → 内核栈 */
if ((type & SOCK_KERNEL) && !(type & SOCK_FSTACK)) {     /* :387 显式选内核 */
    type &= ~SOCK_KERNEL;
    return ff_linux_socket(domain, type, protocol);      /* → 内核栈 */
}
...                                                       /* 否则 → F-Stack socket（:406 去 SOCK_FSTACK 后 FF_SO_SOCKET）*/
```

**结论（以代码为准）**：
- 机制 B 的选栈靠 **`SOCK_KERNEL` 标志**（显式让该 socket 走内核栈）与 `fstack_territory` 判定，**与机制 A 的 `SOCK_FSTACK` 取反逻辑同构**。
- 普通 socket **不做"内核镜像双写"**：一个 socket 要么落内核、要么落 F-Stack；`fstack_kernel_fd_map` 仅服务于 **epoll fd 的双栈合并**（§2.3），不用于普通数据 socket。

> 这进一步印证：A/B 两机制的"连接级选栈"本质相同——**per-socket type 标志选栈 + 内核栈侧独立事件后端**，正是本特性 lib 要抽象的核心。

### 2.5 内核侧封装
- `adapter/syscall/ff_linux_syscall.c` 提供 `ff_linux_socket/ff_linux_bind/ff_linux_listen/ff_linux_accept/ff_linux_epoll_create/ff_linux_epoll_ctl/ff_linux_epoll_wait/ff_linux_close` 等真实内核侧封装（具体行号由 gatekeeper 复核）。

### 2.6 机制 B 小结（对本特性的启示）
- **关键范式**：以 `is_fstack_fd` 做 **fd 归属判定**，用 `fstack_kernel_fd_map` 让**一个事件循环同时等待并合并内核 + F-Stack 事件**。
- **粒度**：fd / event 级，比机制 A 的 per-server 更细。

---

## 3. F-Stack 对外 API（接口设计基线）

`lib/ff_api.h` 关键导出：
- socket 族：`ff_socket:81`、`ff_listen:89`、`ff_bind:90`、`ff_accept:91`、`ff_accept4:92`、`ff_connect:93`、`ff_close:94`。
- 事件：`ff_kqueue:138`、`ff_kevent:139`（**F-Stack 原生是 kqueue/kevent 模型**，epoll 兼容由适配层提供）。
- 路由：`ff_route_ctl:191`（含 `enum FF_ROUTE_CTL`:176）。

> 影响：本特性 lib 的"内核栈侧"用原生 Linux `socket/epoll`，"F-Stack 侧"用 `ff_*`；事件模型差异（kqueue vs epoll）需在接口层统一（详见 `05`）。

---

## 4. 交叉验证差异清单（文档/README vs 代码）

| 编号 | 描述出处 | 代码出处 | 实际结论 |
|---|---|---|---|
| D1 | 用户最初表述"两种机制都已支持本地 socket 访问" | `ngx_event_connect.c:46-50`、`ff_hook_syscall.c:57-61/2329-2338` | 属实，二者均为"连接/ fd 级选栈"，本特性以其为参考 |
| D2 | 旧 v1 spec 误以 KNI/virtio-user 为方案基座 | 机制 A/B 均与 KNI 无关 | v1 方向错误，已全量打回；本特性与 KNI 无关 |
| D3 | 机制 B "首版不支持 `ff_linux_epoll_wait`"（README 注释） | `ff_hook_syscall.c:2329-2338` 实际已调用 | 以代码为准：当前实现**已**调用 `ff_linux_epoll_wait`（带节流） |

> D3 等"README vs 代码"差异以 gatekeeper 复核为准，结论统一以代码为准。

---

## 5. 用于撰写架构(04)/接口(05)的要点清单
- 选栈标志范式：借鉴机制 A 的 `belong_to_host` 1-bit（连接/监听级）。
- 双事件后端范式：借鉴机制 A 的 `ngx_ff_host_event_actions` 与机制 B 的 `fstack_kernel_fd_map` 合并。
- fd 归属判定：借鉴机制 B 的 `is_fstack_fd`。
- 事件模型统一：F-Stack kqueue/kevent ↔ 内核 epoll，需接口层抹平。
- API 基线：`lib/ff_api.h` 的 `ff_socket/ff_bind/ff_listen/ff_accept/ff_connect/ff_close/ff_kqueue/ff_kevent`。
