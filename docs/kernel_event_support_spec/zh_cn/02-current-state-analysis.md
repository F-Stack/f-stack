# 02 现状分析：F-Stack 现有共存机制 + v5 已落地代码 + v6 映射表缺口（以代码为准）

> **文档编号**：SPEC-KE-02
> **版本**：v6（native 自动双栈共存范式）
> **日期**：2026-06-17
> **状态**：编写中（v6 设计）
> **作用域**：实测 hook `FF_KERNEL_EVENT` / nginx `kernel_network_stack` / **原生 `ff_api` v5 已落地共存代码**，作为 v6 自动双栈的复用基线与改造起点；并给出 **native vs hook 同构/分歧对照** 与 **v6 待补的 `ff_native_fd_map` 缺口**。
> **铁律**：所有断言带 `相对路径:行号`（相对 `/data/workspace/f-stack/`）；与文档/注释冲突以**实际代码为准**并显式标注。

---

## 0. v6 现状定位

| 现状能力 | 位置 | 形态 | v6 角色 |
|---|---|---|---|
| hook `FF_KERNEL_EVENT` 共存 | `adapter/syscall/`（LD_PRELOAD） | 标记选栈 + `fstack_kernel_fd_map` epoll 双建合并 + close 联动；**socket/listen 不双建** | **交叉参考**（同构映射/合并/联动；分歧=socket 不双建） |
| nginx `kernel_network_stack` 共存 | `app/nginx-1.28.0/` | per-listen `belong_to_host` + 双事件后端 | 参考（双事件后端可行性证明） |
| **原生 `ff_api` v5 共存（已落地 + 编译宏已包裹）** | `lib/` | per-fd 二选一：`SOCK_KERNEL`→受管内核 fd（encode），否则仅 F-Stack；`ff_epoll_pairs` 合并；全部 `#ifdef FF_KERNEL_COEXIST` 包裹 | **v6 改造起点**：把默认改为双建/双驱动 |
| 选栈标记 | `adapter/syscall/ff_adapter.h:7-8`、`lib/ff_api.h:81-99` | `SOCK_FSTACK`/`SOCK_KERNEL` type 高位 | v6 复用为**单栈覆盖** marker |
| **native 映射表 `ff_native_fd_map`** | — | **不存在** | **v6 待新增**（§5） |

> KNI（`lib/ff_dpdk_kni.c` + `[kni]`）是独立「报文回灌」机制，**不属于本特性**。

---

## 1. 选栈标记（已实测）

`adapter/syscall/ff_adapter.h:5-8`：
```c
#define SOCK_FSTACK 0x01000000
#define SOCK_KERNEL 0x02000000
```
- 叠加在 `type` 高位，不与 glibc `SOCK_*` 冲突。
- **v5 语义（per-fd 二选一）**：带 `SOCK_KERNEL`（且无 `SOCK_FSTACK`）→ 仅内核；否则 → 仅 F-Stack。
- **v6 语义（自动双栈）**：无 marker → 双栈；`SOCK_KERNEL` → 仅内核；`SOCK_FSTACK` → 仅 F-Stack。marker 是**单栈覆盖**。
- `lib/ff_api.h:81-99` 已用 `#ifdef FF_KERNEL_COEXIST` 包裹（v5 R6，opt-in，内层保留 `#ifndef`）。

---

## 2. hook 模式 `FF_KERNEL_EVENT`（已实测，交叉参考）

> README（`adapter/syscall/README.md:169-186`）："This mode can support both F-Stack and the system kernel's socket interface at the same time."

`adapter/syscall/ff_hook_syscall.c`：
- 映射表 `:257-258` `#define FF_MAX_FREEBSD_FILES 65536` / `int fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES];`（**全局裸数组，无锁**——单线程轮询模型）。
- 选栈 `ff_hook_socket:380`：`fstack_territory==0`→内核(`:383-385`)；`(type&SOCK_KERNEL)&&!(type&SOCK_FSTACK)`→内核(`:387-390`)；否则 F-Stack(`:406`)。**socket 不双建**。
- fd 归属 `is_fstack_fd:309` + `CHECK_FD_OWNERSHIP:57-61`；`bind/listen/accept/connect/recv/send/close` 按归属分流；**listen 不双建**（内核 listen 需显式 `SOCK_KERNEL`）。
- **epoll 双建合并**（核心同构）：`ff_hook_epoll_create:1981`（`:1990-2000` 映射内核 epoll fd 到 `fstack_kernel_fd_map[ret]`）；`ff_hook_epoll_ctl:2014+` 路由非 fstack fd(`:2020-2021`)；`ff_hook_epoll_wait:2324+` 先 `timeout=0` 取内核事件 + 节流(`count&0xff`)再合并(`:2333-2336`)；`maxevents>=2` `:2212-2218`。
- close 联动 `:1871-1884`：`fstack_kernel_fd_map[fd]` 非 0 时同关内核 fd 并清表(`:1881`)。
- 内核侧封装 `ff_linux_syscall.c`：socket:81/bind:88/listen:96/accept:131/connect:144/close:217/epoll_*:233/239/247。

> **结论**：hook 提供「epoll 层双建合并 + close 联动」的成熟实现，但 **socket/listen 不自动双建**——这正是 v6 native 的分歧点。

---

## 3. nginx `kernel_network_stack`（已实测，参考）

- 指令 `src/http/ngx_http_core_module.c:298-303`；字段 `ngx_http_core_module.h:206`；merge 默认 0（`:3540-3541`）。
- 归属 `src/http/ngx_http.c:1890` `ls->belong_to_host = cscf->kernel_network_stack;`。
- socket 按归属加/不加 `SOCK_FSTACK`：`ngx_ff_skip_listening_socket() src/core/ngx_connection.c:22-49`(`:46`)。
- **双事件后端**：kqueue 主后端 + 内核 Linux epoll 后端 `ngx_ff_host_event_module.c:441`，按 `ev->belong_to_host` 分流（`ngx_event.h:408-424`），事件循环同跑两栈（`ngx_event.c:258-280`）。
- fd 区分 `is_fstack_fd`(fd≥`ngx_max_sockets`，`ngx_ff_module.c:147-167`）。

> **结论**：nginx 是 per-listen 二选一（非自动双栈），但证明「同 worker 双事件后端」范式成熟，作为 v6 双栈事件的可行性参考。

---

## 4. 原生 `ff_api` v5 共存实现现状（已落地，实测）

> v5（commit ba148589d）已落地 per-fd 二选一共存 + 编译宏门控。**全部代码已 `#ifdef FF_KERNEL_COEXIST` 包裹**（grep 确认 `lib/` 多处命中宏）。v6 在此基础上改造默认语义。

### 4.1 fd 空间区分（受管内核 fd）
- `lib/ff_host_interface.h:113` `#define FF_KERNEL_FD_BASE 0x40000000`；`:115-128` 三 inline：`ff_is_kernel_fd(fd)=fd>=BASE`、`ff_kernel_fd_encode(host)=host+BASE`、`ff_kernel_fd_real(fd)=fd-BASE`。受管内核 fd 远高于 FreeBSD fd 上限，区间不冲突。整块在 `:94-160` `#ifdef FF_KERNEL_COEXIST` 内。

### 4.2 受管内核侧桥
- `lib/ff_host_interface.h:137-159`：18 个 `ff_host_*` 桥声明（`socket/bind/listen/accept/connect/close/read/write/recv/send/sendto/recvfrom/accept4/setsockopt/getsockopt/fcntl/epoll_create1/epoll_ctl/epoll_wait`）。声明用 `unsigned int`（D4）。
- `lib/ff_host_interface.c`：18 桥实现（直接调宿主 libc 同名函数），实现签名用 `socklen_t`；含 `_GNU_SOURCE`（accept4/epoll_create1）。整块 `#ifdef FF_KERNEL_COEXIST`，HOST_CFLAGS 编译单元。

### 4.3 socket 创建与路由（v5 per-fd 二选一）
- `ff_socket:915-947`：`:921-935` `#ifdef FF_KERNEL_COEXIST` 块——`(type&SOCK_KERNEL)&&!(type&SOCK_FSTACK)&&ff_global_cfg.stack.kernel_coexist`(`:929-930`)→`ff_host_socket`(`:931-932`)+`ff_kernel_fd_encode`(`:933`)；否则 `:937-943` 原 `linux2freebsd_socket_flags`+`sys_socket` **逐字节未改**。**当前默认仅建 F-Stack，不双建。**
- 各入口 `#ifdef FF_KERNEL_COEXIST` 内前置 `ff_is_kernel_fd` 路由（实测行号）：`ff_getsockopt:955-959`、`ff_setsockopt:999`附近、`ff_close:1100-1103`、`ff_read`、`ff_write`、`ff_sendto`、`ff_recvfrom`、`ff_fcntl:1498-1501`、`ff_accept:1523-1528`、`ff_accept4:1558-1563`、`ff_listen:1589-1592`、`ff_bind:1613-1616`、`ff_connect:1635-1638`。命中即转对应 `ff_host_*`（`ff_kernel_fd_real(fd)`）。**当前对非内核 fd 不查 map、不双驱动。**

### 4.4 统一事件合并（v5）
- `lib/ff_epoll.c:37-39` `#define FF_EPOLL_COEXIST_MAX 64` + `static struct{int kq;int host_ep;}ff_epoll_pairs[64];` + `pthread_mutex_t`；`:43-69` `ff_epoll_host_ep(kq,create)` 惰性建配对。整段 `:22-70` `#ifdef FF_KERNEL_COEXIST`。
- `ff_epoll_create:73-77` 仍 `return ff_kqueue();`（不变）。
- `ff_epoll_ctl:99-115`：`ff_is_kernel_fd(fd)` 命中→配对 host epoll→`ff_host_epoll_ctl`；否则原 kqueue 路径。**当前只对纯内核 fd 路由，对双栈 listen fd 无概念。**
- `ff_epoll_wait:214-252`：`:233` 取配对 host_ep，`:235` 先 `ff_host_epoll_wait(timeout=0)`，`:242-243` 再 `ff_kevent_do_each` 合并；`#else`(`:248-250`) 宏关时原 kqueue-only（零回归）。

### 4.5 config 运行期开关
- `lib/ff_config.h:321-323` `struct{int kernel_coexist;}stack;`（`#ifdef FF_KERNEL_COEXIST`，HOST_CFLAGS）。
- `lib/ff_config.c:1027-1031` `MATCH("stack","kernel_coexist")`（`1/on/true/yes`→1）；`:1363` 默认 0。

### 4.6 Makefile 门控（已就位）
- `lib/Makefile:57-60` `#FF_KERNEL_COEXIST=1`（默认注释关）；`:174-177` `ifdef FF_KERNEL_COEXIST` 给 `HOST_CFLAGS`+`CFLAGS` 加 `-DFF_KERNEL_COEXIST`（仿 `FF_LOOPBACK_SUPPORT:169-172`/`FF_IPFW:113-116`）。

> **v5 现状结论**：原生模式是 **per-fd 二选一**——默认仅 F-Stack，`SOCK_KERNEL` 仅内核；编译宏门控完整、宏关零回归（`08 §4bis` 实测 nm 共存符号=0/宏开=39）。v6 须把默认改为双建/双驱动。

---

## 5. native vs hook 同构/分歧 + v6 映射表缺口

### 5.1 同构与分歧对照

| 维度 | hook（`FF_KERNEL_EVENT`，已实测） | native v6（自动双栈，待实现） | 关系 |
|---|---|---|---|
| 映射表 | `fstack_kernel_fd_map[65536]`(:258)，**仅 epoll fd 映射** | `ff_native_fd_map[65536]`，**socket/listen 双栈 fd 映射** | **同构**（裸数组无锁，单线程模型） |
| socket | 不双建（marker 选栈） | **默认双建**（marker 单栈覆盖） | **分歧（v6 独有）** |
| bind/listen | 不双建 | **双驱动**两栈 | **分歧（v6 独有）** |
| connect | 按归属单栈 | 双栈并发建连（契约草案，待确认） | **分歧（v6 独有）** |
| accept | 按 listen 归属 | 双栈 listen → 单栈连接归属 | 类似（v6 两栈各 accept 一次） |
| epoll 双建合并 | `:1990-2000`/`:2324+` | `ff_epoll_pairs` + 双栈 listen 两栈各注册 | **同构** |
| close 联动 | `:1871-1884` | `ff_host_close(map[fd])`+`ff_native_map_clear`+清 `ff_epoll_pairs` | **同构** |

### 5.2 v6 待补缺口（grep 实测）
- `grep -r 'ff_native_fd_map\|ff_native_map_get\|ff_native_map_set\|ff_native_map_clear' lib/` → **0 命中**。`FF_MAX_FREEBSD_FILES` 仅在 `adapter/syscall/ff_hook_syscall.c:257` 与本目录文档。
- 即 v6 的 **native 映射表与默认双建/双驱动逻辑完全未落地**，属 R7 待实现。
- v6 须新增（`#ifdef FF_KERNEL_COEXIST`，HOST_CFLAGS）：`ff_host_interface.c` 定义 `static int ff_native_fd_map[FF_MAX_FREEBSD_FILES];` + `ff_native_map_get/set/clear`；`ff_host_interface.h` 声明访问器。仿 `fstack_kernel_fd_map` 无锁。

---

## 6. 交叉验证差异清单（沿用 v5 D1-D8，以代码为准）

| 编号 | 实际结论 |
|---|---|
| D1 | v3「ff_socket→纯内核旁路」方向错误，已回退（0748eff94）；v6 双栈≠旁路，F-Stack 始终建 |
| D2 | config 解析在 `ff_config.c:1027-1031`，默认 `:1363`（非 v4 称的 `:956`） |
| D3 | 优先级链无 `default_stack`；v6=「marker(SOCK_KERNEL/FSTACK) > 自动双栈(kernel_coexist 启用) > F-Stack」；`ff_api.h` 注释残留已改 `kernel_coexist`（v5 M7 PASS） |
| D4 | 桥声明 `unsigned int` vs 实现 `socklen_t`（Linux 等价可编译），如实记录 |
| D5 | `ff_stack_stats`/`ff_stack_get_stats` **未实现**，标注待定 |
| D6 | fd 区分=`FF_KERNEL_FD_BASE` 偏移 + `ff_epoll_pairs` 配对；v6 增 `ff_native_fd_map` 双栈映射（仍非 enum/归属表） |
| D7 | 原生 v5 共存已落地（编译宏已包裹）；v6 在其上改默认语义为双栈 |
| D8 | 路由仅 13 入口；`readv/writev/getpeername/getsockname/shutdown/ioctl/sendmsg/recvmsg` 等未加路由（已知限制）；v6 双栈 fd 对这些接口默认仅 F-Stack 驱动 |
| **D9（v6）** | `ff_native_fd_map`/默认双建/双驱动**尚未实现**（§5.2 grep=0）——文档区分「v5 已实测」与「v6 待实现」，不当既成 |

---

## 7. 用于撰写 04/05/06/09 的要点清单

- **改造起点=原生 v5 per-fd 二选一**（已落地 + 编译宏已包裹）。
- **v6 核心改动**：(a) 新增 `ff_native_fd_map` + 访问器（仿 hook `fstack_kernel_fd_map`）；(b) `ff_socket` 默认双建（marker 单栈覆盖）；(c) `ff_bind/listen/close/connect/accept/setsockopt/fcntl` 双驱动；(d) `ff_epoll_ctl/wait` 双栈 listen 两栈各注册 + 合并。
- **hook 交叉验证**：同构（映射表/epoll 合并/close 联动），分歧（socket/listen/connect 自动双建——v6 独有）。
- **热路径**：已 accept 单栈连接 recv/send 只按 `ff_is_kernel_fd` 路由，不查 map（NFR-2）。
- **零回归**：全部 `#ifdef FF_KERNEL_COEXIST` + 运行期 `kernel_coexist=0` 短路 + `SOCK_FSTACK` 单栈。
