# 02 现状分析：F-Stack 现有"单 API + 标记选栈"机制（以代码为准）

> **文档编号**：SPEC-KE-02
> **版本**：v3（范式修正重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：实测 F-Stack 中"用标记/配置让某 fd 走宿主机内核栈"的现有机制，作为 v3 lib 的**直接复用基线**（而非另造双 API）。覆盖：选栈标记、hook 模式单 API 选栈、客户端 connect 路径、config.ini 解析、原生 ff_api 模式差异、双栈事件合并。
> **铁律**：所有断言带 `相对路径:行号`（相对 `/data/workspace/f-stack/`）；与文档/README/注释冲突以**实际代码为准**并显式标注。

---

## 0. v3 现状定位

| 现状能力 | 位置 | 形态 | v3 中的角色 |
|---|---|---|---|
| **单 API + `SOCK_KERNEL`/`SOCK_FSTACK` 标记选栈** | `adapter/syscall/`（hook 模式） | POSIX 单 API + type 标记 + 胶水自动适配 | **直接复用并标准化**（v3 核心范式） |
| **双栈 fd/event 合并** | `adapter/syscall/`（`FF_KERNEL_EVENT`） | `fstack_kernel_fd_map` + 双栈 epoll | **复用**（统一事件） |
| 连接级选栈（nginx） | `app/nginx-1.28.0/` | `belong_to_host` 1-bit + 双事件后端 | **同构旁证**（证明范式可行） |
| 原生 `ff_socket` 选栈 | `lib/`（原生模式） | 不识别选栈标记，恒建 F-Stack socket | **差异点**：原生模式需补标准化（见 §5） |

> KNI（`lib/ff_dpdk_kni.c` + `config.ini [kni]`）是**另一套独立的"报文回灌内核"机制**，**不属于本特性**（见 `00`/`03`），本文不展开。

---

## 1. 选栈标记（v3 核心，已实测）

`adapter/syscall/ff_adapter.h:5-8`：
```c
//#define SOCK_CLOEXEC  0x10000000
//#define SOCK_NONBLOCK 0x20000000
#define SOCK_FSTACK 0x01000000
#define SOCK_KERNEL 0x02000000
```
- `SOCK_FSTACK`/`SOCK_KERNEL` 是 F-Stack 适配层在标准 `socket()` 的 `type` 参数高位上附加的**选栈标记**（不与 glibc 的 `SOCK_*` 真值冲突）。
- **这正是 v3 要标准化的"特定标记"**：应用无需调用多套 API，只需在 `type` 上按需置标记即可选栈；不置标记则按默认（hook 模式默认 F-Stack，详见 §2）。

---

## 2. hook 模式：单 API + 标记选栈（v3 首要复用基线）

### 2.1 领域判定
`adapter/syscall/ff_hook_syscall.c:360` `fstack_territory(domain, type, protocol)`：先剥离 `SOCK_CLOEXEC/SOCK_NONBLOCK/SOCK_FSTACK/SOCK_KERNEL`（:363-366），仅当 `domain∈{AF_INET,AF_INET6}` 且 `type∈{SOCK_STREAM,SOCK_DGRAM}` 才属 F-Stack 领域（:368-373），否则返回 0（→ 内核栈）。

### 2.2 选栈核心（`ff_hook_socket`）
`ff_hook_syscall.c:380` `ff_hook_socket(domain, type, protocol)`：
```c
if (unlikely(fstack_territory(domain, type, protocol) == 0))     /* :383 非 fstack 领域 → 内核 */
    return ff_linux_socket(domain, type, protocol);
if (unlikely(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)) {     /* :387 显式选内核 */
    type &= ~SOCK_KERNEL;                                        /* :388 清标记 */
    return ff_linux_socket(domain, type, protocol);             /* :389 → 内核栈 */
}
...
type &= ~SOCK_FSTACK;                                            /* :406 清标记后建 F-Stack socket */
```
- 注释 `:376-378`："APP need set type |= SOCK_FSTACK"。
- **结论**：默认走 F-Stack；带 `SOCK_KERNEL`（且无 `SOCK_FSTACK`）→ 走内核栈。**单一 `socket()` 入口 + 标记**即完成选栈，胶水层自动适配——v3 直接复用此范式。

### 2.3 epoll 同范式
`ff_hook_syscall.c:1981` `ff_hook_epoll_create`：`(fdsize & SOCK_KERNEL) && !(fdsize & SOCK_FSTACK)` → `ff_linux_epoll_create`（:1982-1983），同样以标记选内核侧 epoll。

### 2.4 后续操作按 fd 归属自动路由
- fd 归属宏：`ff_hook_syscall.c:57-61` `CHECK_FD_OWNERSHIP(name, args)`：`if (!is_fstack_fd(fd)) return ff_linux_##name args;`——**非 F-Stack fd 直接转内核 `ff_linux_*`**。
- 归属判定：`ff_hook_syscall.c:309` `is_fstack_fd(int sockfd)`（F-Stack fd 经编码偏移区分；配套 `convert_fstack_fd`/`restore_fstack_fd`）。
- `bind/listen/accept/connect/recv/send/close` 等 hook 函数均通过 `CHECK_FD_OWNERSHIP` 在入口按归属分流：socket 创建时的标记**一次决定**该 fd 后续所有操作走哪栈。

---

## 3. 客户端 connect 选栈路径（v3 新增能力，已实测）

`adapter/syscall/ff_hook_syscall.c:847-886` `ff_hook_connect(fd, addr, addrlen)`：
```c
CHECK_FD_OWNERSHIP(connect, (fd, addr, addrlen));   /* :858 非 fstack fd → ff_linux_connect */
...
SYSCALL(FF_SO_CONNECT, args);                        /* :881 否则走 F-Stack connect */
```
- **关键事实**：`connect` **纯按 fd 归属路由**，不看目的地址。即：
  - 若该 socket 创建时带 `SOCK_KERNEL`（或在"默认内核栈"配置下创建）→ 是内核 fd → `connect` 走 `ff_linux_connect`（`ff_linux_syscall.c:144`）→ **可连本机 `127.0.0.1`/本机内核栈 IP 及任意外部内核栈服务**。
  - 若是 F-Stack fd → `connect` 走 F-Stack 栈（经 DPDK 网卡）。
- **v3 客户端用法（据代码推导，可行）**：F-Stack 应用作客户端要连内核栈服务（本机或外部），只需让该 socket 走内核栈（hook 模式：`socket(AF_INET, SOCK_STREAM|SOCK_KERNEL, 0)`；或在 config.ini 默认内核栈进程中直接 `socket(...)`），随后 `connect()` 即自动走内核栈。**与服务端选栈是同一套标记机制的两个方向**。

---

## 4. config.ini 解析层（v3 全局默认开关落点，已实测）

- 解析入口：`lib/ff_config.c:956` `ini_parse_handler(user, section, name, value)`；匹配宏 `:963` `#define MATCH(s,n) strcmp(section,s)==0 && strcmp(name,n)==0`。
- 现有分节范式（可仿照）：`[dpdk]` 段 `:964-1010`、**`[kni]` 段 `:1011-1026`**（如 `MATCH("kni","enable") → pconfig->kni.enable=atoi(value)` :1011-1012）。
- 配置校验：`:1261+`（如 kni.method 合法性 :1266-1281）；默认值设置：`:1358+`；字符串字段释放：`:1647+`。
- 配置结构：`lib/ff_config.h:253` `struct ff_config`，含匿名嵌套段 `dpdk`（:255-308）、**`kni`（:310-319）**、`log`（:321-325）、`freebsd`（:327-334）、`pcap`（:336-342）；`extern struct ff_config ff_global_cfg;`（:345）。
- **v3 落点**：新增"全局默认栈开关"应仿 `[kni]` 范式——在 `struct ff_config` 增一个嵌套段（如 `stack`，含 `int default_to_kernel;`）+ 在 `ini_parse_handler` 增 `MATCH("stack","default_stack")` 分支 + 默认值。
- **多进程模型佐证**：F-Stack 每进程一个实例、各持自己的 config.ini（`struct ff_config.filename` :254；`ff_load_config` 声明 `ff_config.h:347`）。故"不同进程走不同默认栈"靠**不同 config 文件**实现，**无需线程级选栈**。

---

## 5. 原生 ff_api 模式的标记差异（重要，已实测，以代码为准）

- 原生入口：`lib/ff_syscall_wrapper.c:912-926` `ff_socket(domain, type, protocol)`：
```c
sa.type = linux2freebsd_socket_flags(type);   /* :918 */
... sys_socket(curthread, &sa);                /* :920 直接进 FreeBSD 栈 */
```
- `linux2freebsd_socket_flags`（`:668-` ）**只处理 `LINUX_SOCK_NONBLOCK`/`LINUX_SOCK_CLOEXEC`**（:671-677），**不识别 `SOCK_FSTACK`/`SOCK_KERNEL`**。
- **结论（以代码为准）**：**原生 `ff_socket` 恒建 F-Stack socket，不做标记选栈**。即"单 API + 标记选栈 + 胶水自动适配"**目前仅在 hook 模式成立**；原生模式下选内核栈现状需应用自行调用 libc `socket()`。
- **v3 设计含义**：要让原生模式也"单 API + 标记选栈"，需在原生 glue 层做**标准化补强**（仿 `ff_hook_socket:387-390`，在 `ff_socket` 入口识别 `SOCK_KERNEL` → 转 libc `socket`/`ff_linux_socket` 等价路径），属实现阶段工作（见 `05`/`06`）；本阶段如实记录此差异，作为 v3 的设计点而非既成事实。

---

## 6. 双栈事件合并（沿用并复核，已实测）

`adapter/syscall/ff_hook_syscall.c`：
- 映射表：`:257-258` `int fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES];`（`FF_MAX_FREEBSD_FILES=65536`）。
- create 镜像内核 epoll：`:1996-1998`（`fstack_kernel_fd_map[ret]`）。
- ctl 路由非 fstack fd：`:2016-2023`。
- wait 合并（先取内核事件 `timeout=0` + 节流，再合并 F-Stack 事件）：`:2324+`；`maxevents>=2` 约束 `:2212-2218`。
- close 联动：`:1874-1883`。
- 内核侧封装：`adapter/syscall/ff_linux_syscall.c` socket:81/bind:88/listen:96/accept:131/connect:144/close:217/epoll_create:233/epoll_ctl:239/epoll_wait:247。

---

## 7. 交叉验证差异清单（文档/README/注释 vs 代码）

| 编号 | 出处 | 代码出处 | 实际结论 |
|---|---|---|---|
| D1 | 用户表述"两种已有模式都支持本地 socket 访问" | `ff_hook_socket:387-390`、`ff_hook_connect:858` | 属实（hook 模式靠标记选栈，含客户端 connect） |
| D2 | v2 spec 误以"新造 `ff_local_*` 双 API"为方案 | hook 层本就是单 API + 标记 | v2 方向错误，v3 改为复用现有单 API + 标记 |
| D3 | `ff_hook_syscall.c` 注释称"首版不支持 `ff_linux_epoll_wait`" | `:2324+` 实际已调用 | 以代码为准：已调用（带节流） |
| D4 | 直觉认为"原生 `ff_socket` 也识别 `SOCK_KERNEL`" | `ff_socket:918` + `linux2freebsd_socket_flags:668-677` | **不识别**：原生模式恒建 F-Stack socket，选内核栈需标准化补强（§5） |

---

## 8. 用于撰写 04/05/06 的要点清单

- **选栈标记标准化**：以 `SOCK_KERNEL`/`SOCK_FSTACK`（`ff_adapter.h:7-8`）为唯一选栈标记，hook 模式直接复用（`ff_hook_socket:387-390`），原生模式补识别分支。
- **config.ini 全局默认开关**：仿 `[kni]`（`ff_config.c:1011`/`ff_config.h:310-319`）新增 `[stack] default_stack` + `struct ff_config.stack` 字段；优先级 **app 标记 > config 默认**。
- **客户端选栈**：socket 创建时标记/配置定栈，`connect`（`ff_hook_connect:858`）按 fd 归属自动走内核/F-Stack，覆盖连本机回环/本机 IP/外部内核服务。
- **fd 归属与事件**：`is_fstack_fd:309` + `CHECK_FD_OWNERSHIP:57-61` 自动分流；双栈事件用 `fstack_kernel_fd_map` 合并（§6）。
- **双模式覆盖**：hook 模式（完整成立）+ 原生模式（需 §5 标准化补强）。
