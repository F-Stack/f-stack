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

## 6. 交叉验证差异清单（v5 D1-D8 + v6 D9 + R9 D10-D11 + R10 D12-D15，以代码为准）

| 编号 | 实际结论 |
|---|---|
| D1 | v3「ff_socket→纯内核旁路」方向错误，已回退（0748eff94）；v6 双栈≠旁路，F-Stack 始终建 |
| D2 | config 解析在 `ff_config.c:1027-1031`，默认 `:1363`（非 v4 称的 `:956`） |
| D3 | 优先级链无 `default_stack`；v6=「marker(SOCK_KERNEL/FSTACK) > 自动双栈(kernel_coexist 启用) > F-Stack」；`ff_api.h` 注释残留已改 `kernel_coexist`（v5 M7 PASS） |
| D4 | 桥声明 `unsigned int` vs 实现 `socklen_t`（Linux 等价可编译），如实记录 |
| D5 | `ff_stack_stats`/`ff_stack_get_stats` **未实现**，标注待定 |
| D6 | fd 区分=`FF_KERNEL_FD_BASE` 偏移 + `ff_epoll_pairs` 配对；v6 增 `ff_native_fd_map` 双栈映射（仍非 enum/归属表） |
| D7 | 原生 v5 共存已落地（编译宏已包裹）；v6 在其上改默认语义为双栈 |
| D8 | R8 补齐 `sendmsg/recvmsg/getpeername/getsockname/shutdown` 内核路由（前 4 单栈热路由，shutdown 内核路由+双栈双驱动）；剩 `readv/writev/ioctl` 仍未加路由（已知限制），v6 双栈 fd 对其默认仅 F-Stack 驱动 |
| **D9（v6）** | `ff_native_fd_map`/默认双建/双驱动**尚未实现**（§5.2 grep=0）——文档区分「v5 已实测」与「v6 待实现」，不当既成 |
| **D10（R9）** | **R7 双栈事件仅覆盖 `ff_epoll_*`**：`ff_kqueue`/`ff_kevent`/`ff_kevent_do_each` **无 FF_KERNEL_COEXIST 路由/双注册**（grep 实测仅 `ff_epoll.c` 命中宏，`ff_syscall_wrapper.c` 的 `ff_kqueue/ff_kevent` 无共存分支）。直接用 `ff_kqueue`+`ff_kevent`（如 `example/main.c`）的应用**感知不到内核侧连接**——实测内核侧 `curl 127.0.0.1:80=000`（握手完成、GET 被内核 TCP `ack 73`，但应用永不被唤醒去 accept），F-Stack 侧 `9.134.214.176:80=200`。R9 待补 |
| **D11（R9）** | **IPv6 双建端口冲突**：`-DINET6` 下默认 `ff_socket(AF_INET6)` 双建，host IPv6 socket `ff_bind([::]:80)` 因本机 `net.ipv6.bindv6only=0`（实测）连带占用 IPv4，与同进程 host IPv4 `0.0.0.0:80` 冲突——**实测 `ff_bind failed, sockfd6:1026, errno:98 EADDRINUSE`**，进程退出无法启动。host IPv6 socket 未设 `IPV6_V6ONLY=1`。R9 待补 |
| **D12（R10）** | **`ff_readv`/`ff_writev` 无内核 fd 路由**：`ff_syscall_wrapper.c` 的 `ff_readv`(L1179)/`ff_writev`(L1236) 仅走 `kern_readv`/`kern_writev`，**无 `FF_KERNEL_COEXIST` 内核 fd 分支**（对照 `ff_read`/`ff_write` 已有路由）——对 encode 内核 fd 调用会误走 F-Stack（D8 子项的具体化）。R10 仿 `ff_read`/`ff_write` 补齐（新增 host 桥 `ff_host_readv/writev`）。**R10 待实现**，行号以实现为准 |
| **D13（R10）** | **`ff_ioctl` 无内核 fd 路由**：`ff_ioctl`(L1067) 经 `linux2freebsd_ioctl`→`kern_ioctl`，**无内核 fd 分支**。ioctl request 经 `_IO/_IOR/_IOW(type,nr,size)` 编码，Linux 与 FreeBSD 数值**不同源**（外网交叉验证），故内核 host fd 须用**原始 Linux request**直传 `ff_host_ioctl`（不经 `linux2freebsd_ioctl` 翻译）。**R10 已实现**：内核 fd 分支（在 va_arg 取 argp 后、`linux2freebsd_ioctl` 之前 return `ff_host_ioctl(real, request, argp)`）；**双栈 fd 同驱动 R10.1 已实现**（`FIONBIO`/`FIOASYNC` 同步配对 host fd，仿 `ff_fcntl`；`FIONREAD` 等 query 类不同驱动以免覆盖 argp） |
| **D14（R10）** | **`ff_dup`/`ff_dup2` 无内核 fd 路由**：`ff_dup`(L2130)/`ff_dup2`(L2156) 仅走 `sys_dup`/`sys_dup2`。**R10 已实现**：`ff_dup` 内核 fd→`ff_host_dup(real)` 返回新 encode fd（n<0 返回 -1）；`ff_dup2` 两端均内核 fd→`ff_host_dup2(real,real)` 返回 encode，**混栈（一端内核一端 F-Stack）明确拒绝 errno=EINVAL**（两 fd 各自有效但语义不成立），两端均 F-Stack 走原 `sys_dup2` 不变 |
| **D15（R10）** | **`ff_select`/`ff_poll` 无内核 fd 路由**：`ff_select`(L1879)/`ff_poll`(L1903) 仅走 `kern_select`/`kern_poll`。**R10：两者均不实现共存，降级为文档限制（仅加注释，逻辑不变）**。`ff_select`：encode 内核 fd（≥`0x40000000`）**远超 `FD_SETSIZE`(1024)**，无法装入 `fd_set`——**硬限制**（外网交叉验证）。`ff_poll`：`pollfd.fd` 虽可容 encode fd，但 `kern_poll` 直接操作 FreeBSD pollfd，混合纯内核 fd 子集需拆分数组/索引映射/合并 revents/超时合并，复杂度与回归风险高，**保守降级文档限制**。均建议内核 fd 用 `ff_epoll_*`/`ff_kqueue`（R9 已支持 host epoll 桥）多路复用 |

---

## 7. R9 现状缺口（kqueue/kevent 未共存 + IPv6 双建冲突，实测）

> R7 已落地默认双建/双驱动 + `ff_epoll_*` 双栈合并并 PASS（`08 §4`）。R9 锁定其两处剩余缺口，均经代码 + 抓包 + errno 三重交叉验证（不臆测）。

### 7.1 P2：`ff_kqueue/ff_kevent` 系列未支持共存（核心缺口）
- `lib/ff_syscall_wrapper.c` 的 `ff_kqueue`/`ff_kevent`/`ff_kevent_do_each` **完全无 FF_KERNEL_COEXIST 路由**——仅 `ff_epoll.c` 经 `ff_epoll_pairs[kq→host_ep]` 做了配对+双注册+合并。`example/main.c` 用 `ff_kqueue()`+`EV_SET(sockfd,EVFILT_READ)`+`ff_kevent(kq,...)`，**只把 F-Stack listen fd 注册进 F-Stack kqueue**，双栈 listen 的内核侧 host fd 从未进入任何事件后端。
- **实测链路**：内核 TCP 完成握手、GET 入内核缓冲并被 TCP 层 ACK（抓包 `ack 73` 吻合），但应用永不被唤醒去 `ff_accept` 内核 listen fd → 永不 read/write → 无 200。内核侧 `curl 127.0.0.1:80=http_code 000`（6s 超时）；同进程 F-Stack 侧 client 压 `9.134.214.176=http_code 200 size=438`。
- 结论：**双栈 listen 的内核侧事件无法被 kqueue 模型应用感知**——`ff_kqueue/ff_kevent` 须对称仿 `ff_epoll` 做共存（外网已证 F-Stack epoll 即基于 kqueue 封装，可复用同一 `ff_epoll_pairs` 基础设施）。

### 7.2 P1：IPv6 双建端口冲突（启动失败）
- `lib/ff_syscall_wrapper.c::ff_bind`：F-Stack bind 成功后调 `ff_host_bind(map[s])`，失败即 `return -1`。
- 本机 `net.ipv6.bindv6only=0`（实测）→ host IPv6 socket 绑 `[::]:80` 连带占用 IPv4 → 与同进程 host IPv4 `0.0.0.0:80`（v4/v6 默认双建各自产生的 host socket）冲突。**实测 errno=98 EADDRINUSE**，`-DINET6` helloworld 在 coexist=1 下无法启动。
- 结论：host 侧 IPv6 socket 须设 `IPV6_V6ONLY=1` 只处理 IPv6、与 host IPv4 同端口共存（外网交叉验证：bindv6only=0 时 `::` 通配连带 IPv4，标准解法即 `IPV6_V6ONLY=1`，多篇技术资料一致）。

> **R9 缺口结论**：R7 共存对 `ff_epoll_*` 完整，但 `ff_kqueue/ff_kevent`（P2）与 host IPv6 socket V6ONLY（P1）两项**待 R9 实现**——不当既成，区分「R7 已实测」与「R9 待实现」。

---

## 7bis. R10 现状缺口（readv/writev/ioctl 未路由 + dup/dup2/select/poll 评估，实测）

> R8 补齐 `sendmsg/recvmsg/getpeername/getsockname/shutdown`，但 `readv/writev/ioctl` 仍列「D8 已知限制」未加路由（`02 §6 D8`/`05 §7`）。R10 收口 `ff_syscall_wrapper.c` 全部 42 个 `ff_*` 入口中剩余的 fd 类残余入口（实测分类见 §7bis.1），把 readv/writev/ioctl 由「已知限制」改为「已支持（R10）」，并对额外发现的 dup/dup2/select/poll 给出实现或文档限制。**全部以代码为准、`#ifdef FF_KERNEL_COEXIST` 门控、宏关零回归**；行号占位以实现期实测为准。

### 7bis.1 残余入口实测分类（`ff_syscall_wrapper.c`）

| 入口 | 改动后行号 | 现状（R10 前） | R10 处置（已实现） |
|---|---|---|---|
| `ff_readv` | L1189 | 仅 `kern_readv`，无内核 fd 路由 | 内核 fd→`ff_host_readv(real, iov, iovcnt)`（仿 `ff_read`） |
| `ff_writev` | L1251 | 仅 `kern_writev`，无内核 fd 路由 | 内核 fd→`ff_host_writev(real, iov, iovcnt)`（仿 `ff_write`） |
| `ff_ioctl` | L1067 | `linux2freebsd_ioctl`→`kern_ioctl`，无内核 fd 路由 | 内核 fd 用**原始 Linux request** 直传 `ff_host_ioctl`（va_arg 取 argp 后、翻译之前）；**双栈 fd 同驱动 R10.1 已实现**（`FIONBIO`/`FIOASYNC`） |
| `ff_dup` | L2130 | `sys_dup`，无内核 fd 路由 | 内核 fd→`ff_host_dup(real)`+encode（n<0 返回 -1） |
| `ff_dup2` | L2156 | `sys_dup2`，无内核 fd 路由 | 两端内核 fd→`ff_host_dup2`+encode；**混栈拒绝 errno=EINVAL**；两端 F-Stack 走原 `sys_dup2` |
| `ff_select` | L1879 | `kern_select`，无内核 fd 路由 | **不实现（硬限制）**：encode 内核 fd(≥0x40000000)≫`FD_SETSIZE`(1024) 无法装入 `fd_set`（仅加注释） |
| `ff_poll` | L1903 | `kern_poll`，无内核 fd 路由 | **不实现（文档限制）**：拆分/索引映射/合并复杂度高，保守降级（仅加注释） |

> 其余非 fd / F-Stack 专属语义入口（`ff_zc_send/zc_recv`/`ff_sysctl`/`ff_gettimeofday`/`ff_route_ctl`）不纳入（N/A）。

### 7bis.2 新增 host 桥（R10，仿 `ff_host_read/write`，声明 `ff_host_interface.h:178-184`）

- `ssize_t ff_host_readv(int fd, const void *iov, int iovcnt)` → libc `readv`（`iov` cast `const struct iovec*`）
- `ssize_t ff_host_writev(int fd, const void *iov, int iovcnt)` → libc `writev`
- `int ff_host_ioctl(int fd, unsigned long request, void *argp)` → libc `ioctl`（host 命名空间，原始 Linux request）
- `int ff_host_dup(int fd)` → libc `dup`
- `int ff_host_dup2(int oldfd, int newfd)` → libc `dup2`

> 实现在 `ff_host_interface.c`（coexist include 块新增 `sys/uio.h`、`sys/ioctl.h`）；`struct iovec` 在 FreeBSD/host 同 ABI（`void* + size_t`），沿用 `sendmsg/recvmsg` 的 `void*` 透传经验规避命名空间冲突。

> **R10 缺口结论**：readv/writev/ioctl/dup/dup2 路由已落地（impl 编译通过、宏关零回归已验证）；select/poll 经评估保守降级为文档限制。区分「R10 前未路由（实测 grep）」与「R10 已实现」，未当既成。

---

## 8. 用于撰写 04/05/06/09 的要点清单

- **改造起点=原生 v5 per-fd 二选一**（已落地 + 编译宏已包裹）。
- **v6 核心改动**：(a) 新增 `ff_native_fd_map` + 访问器（仿 hook `fstack_kernel_fd_map`）；(b) `ff_socket` 默认双建（marker 单栈覆盖）；(c) `ff_bind/listen/close/connect/accept/setsockopt/fcntl` 双驱动；(d) `ff_epoll_ctl/wait` 双栈 listen 两栈各注册 + 合并。
- **hook 交叉验证**：同构（映射表/epoll 合并/close 联动），分歧（socket/listen/connect 自动双建——v6 独有）。
- **热路径**：已 accept 单栈连接 recv/send 只按 `ff_is_kernel_fd` 路由，不查 map（NFR-2）。
- **零回归**：全部 `#ifdef FF_KERNEL_COEXIST` + 运行期 `kernel_coexist=0` 短路 + `SOCK_FSTACK` 单栈。
