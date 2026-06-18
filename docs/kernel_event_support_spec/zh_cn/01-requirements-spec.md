# 01 需求规格：F-Stack 用户态栈 + 本地内核栈「自动双栈共存」

> **文档编号**：SPEC-KE-01
> **版本**：v6（native 自动双栈共存范式）
> **日期**：2026-06-17
> **状态**：编写中（v6 设计）
> **作用域**：定义本特性的问题域、目标/非目标、功能与非功能需求、成功标准。

---

## 1. 问题域

F-Stack 通过 DPDK 接管网卡后，该网卡流量绕过 Linux 内核协议栈。一个 F-Stack 应用希望**在用 F-Stack 跑业务的同时**：

1. **服务端方向**：同一个 `listen(80)` 既经 DPDK 网卡对外服务（F-Stack 侧，如 `9.134.214.176:80`），又能被本机 `curl 127.0.0.1:80`/`ping`/`ssh` 直访（内核栈侧）——**无需为每个用途分别开 socket、无需 marker**。
2. **客户端方向**：作客户端连本机/外部内核服务。
3. **统一事件**：两栈 fd 在**同一事件循环**统一处理。

**v6 关键**：上述「服务端双向可达」在 v5 需要应用为内核侧**额外**开一个 `SOCK_KERNEL` socket（per-fd 二选一）；**v6 把它做成默认行为**——一次 socket 自动双建、各 `ff_*` 双驱动两栈。F-Stack 用户态栈**始终在位**，内核栈是**并行附加**的第二条栈，**绝不替代/旁路 F-Stack**（v3 错误）。

**演进**：
- **v5（commit ba148589d）**：`FF_KERNEL_COEXIST` 编译宏门控（默认关）+ per-fd 二选一共存，宏关逐字节零回归、宏开 per-fd 可用，已实测（`08`/`10`）。
- **v6（本轮）**：默认语义升级为自动双栈（默认双建/双驱动/一 listen 多用），marker 仍可单栈覆盖。

> **实现状态**：v6 的 `ff_native_fd_map` + 默认双建/双驱动**尚未落地**（lib 无该符号），本文 FR/NFR 中 v6 新增项均为**待实现需求**，验收待 R7 实测。

---

## 2. 目标与非目标

### 2.1 目标（In Scope）

- **G1（自动双栈，v6 核心）**：`FF_KERNEL_COEXIST` 编译开 + `kernel_coexist=1` 时，默认（无 marker）`ff_socket` 同建 F-Stack fd + 内核 host fd，登记 `ff_native_fd_map[fstack_fd]=host_fd`，返回 F-Stack 原始 fd；`ff_bind/ff_listen/ff_close/ff_connect` 等双驱动两栈。
- **G2（marker 单栈覆盖，兼容 v5）**：`SOCK_KERNEL`=仅内核（返回 encode fd，无 map）；`SOCK_FSTACK`=仅 F-Stack（无 map，零回归）。`SOCK_FSTACK` 优先于 `SOCK_KERNEL`。
- **G3（一 listen 多用）**：单个默认 `listen(80)` 同时在 F-Stack(DPDK) 与 Linux 内核栈监听 80；`ff_netstat`(F-Stack) 与 `ss`(内核) 各见一个 80。
- **G4（统一事件双栈）**：对双栈 listen fd，`ff_epoll_ctl` 在 F-Stack kqueue 与内核 epoll 各注册一次（透传 app `event.data`），`ff_epoll_wait` 合并两栈事件；连接 fd 单栈，按 `ff_is_kernel_fd` 路由。
- **G5（accept 单栈归属）**：双栈 listen fd accept 返回**单栈**连接 fd——F-Stack 侧连接返回原始 fd，内核侧连接返回 encode fd；后续 recv/send/close 按 fd 路由，热路径不查 map。
- **G6（config 运行期开关）**：`kernel_coexist` 启用/禁用自动双栈，默认仍纯 F-Stack；**不提供「整进程默认内核」选项**。
- **G7（编译宏门控 + opt-in）**：`lib/` 全部共存代码由 `FF_KERNEL_COEXIST` 包裹，默认关；`SOCK_FSTACK`/`SOCK_KERNEL` 宏亦被包裹，APP 须同样定义该宏方可见。
- **G8（连内核服务）**：客户端可经内核栈连本机/外部内核服务（默认双栈 connect 并发建连，或 `SOCK_KERNEL` 纯内核客户端）。

### 2.2 非目标（Out of Scope）

- **N1**：**不**新造绕开 F-Stack 的旁路 socket（v3 `ff_host_socket` 裸绕过作废）；内核 fd 必须「受管 + 纳入统一事件」。
- **N2**：**不**设「整进程默认走内核栈」开关（v3 `default_stack=kernel` 作废，反 F-Stack）。
- **N3**：**不**新造 `ff_local_*` 双 API / 类 mTCP 双命名空间。
- **N4**：**不**做 gazelle 式线程级选栈（多进程靠不同 config 文件）。
- **N5**：**不**采用 KNI/`rte_kni`/virtio-user 报文回灌。
- **N6**：不实现两栈间 socket 自动迁移/透明代理（创建时确定形态：双栈 / 仅内核 / 仅 F-Stack）。
- **N7（connect 数据双工，待确认）**：默认双栈 connect 的「数据路径同时双工于两栈」**不在 v6 保证范围**——单逻辑连接流不能真双工于两栈；v6 契约为「F-Stack 主 + 内核并发建连用于双网可达」，纯内核客户端用 `SOCK_KERNEL`，kernel-primary/failover 为后续（见 `05 §connect`，**待用户最终确认**）。

---

## 3. 功能需求（FR）

| 编号 | 需求 | 验收要点 | 代码依据/状态 |
|---|---|---|---|
| FR-1 | **零回归默认（marker/开关粒度）**：宏关 / `kernel_coexist=0` / `SOCK_FSTACK` → 纯 F-Stack | 经 DPDK NIC 正常收发，逐字节零回归 | v5 已实测；v6 须维持 |
| FR-2 | **自动双栈 socket（v6）**：默认无 marker 同建 F-Stack+内核双 fd，返回 F-Stack 原始 fd，登记 `map[fstack]=host` | `ff_socket` 双建成功、map 项正确、返回原始 fd | v6 待实现（`ff_syscall_wrapper.c:915-947` 重构） |
| FR-3 | **双驱动 bind/listen（v6）**：双栈 fd `ff_bind/ff_listen` 同时落 F-Stack 与内核栈 | 一 `listen(80)`：`ff_netstat` 与 `ss` 各见 80 | v6 待实现（`:1607-1627`/`:1584-1605`） |
| FR-4 | **一 listen 多用（v6）**：F-Stack 侧（DPDK NIC）+ 内核侧（`127.0.0.1`/本机 IP）同时可访问同一端口 | 远端 `curl 9.134.214.176:80` + 本机 `curl 127.0.0.1:80` 皆 200 | v6 待实现，真机验证 |
| FR-5 | **统一事件双栈（v6）**：双栈 listen fd 在 kqueue + 内核 epoll 各注册一次，`ff_epoll_wait` 合并 | 两栈连接事件均投递、不丢、`event.data` 透传 | `ff_epoll.c` 现有合并骨架 + v6 双注册 |
| FR-6 | **accept 单栈归属（v6）**：双栈 listen fd accept 返回单栈连接 fd（F-Stack 原始 / 内核 encode） | 连接 fd 单栈，后续 recv/send/close 正确路由 | v6 待实现（`:1514-1582`） |
| FR-7 | **双驱动 close（v6）**：双栈 fd `ff_close` 关两栈 + `ff_native_map_clear` + 清 `ff_epoll_pairs` | 无 fd 泄漏（两栈一致释放） | v6 待实现（`:1095-1112`） |
| FR-8 | **marker 仅内核**：`SOCK_KERNEL` → 仅内核 fd（encode），无 map | 本机直访内核监听成功 | v5 已实测（`ff_socket:929-934`） |
| FR-9 | **marker 仅 F-Stack**：`SOCK_FSTACK` → 仅 F-Stack（零回归） | 等价原 F-Stack | v5 已实测 |
| FR-10 | **客户端连内核服务**：默认双栈 connect 并发建连 / `SOCK_KERNEL` 纯内核 connect 本机/外部 | 连接建立、收发正常（contract 见 `05 §connect`） | v6 双栈 connect 待实现（`:1629-1649`） |
| FR-11 | **config 运行期开关**：启用/禁用自动双栈，默认 per-fd F-Stack 不变 | 开关生效；关闭等价纯 F-Stack | v5 已实测（`ff_config.c:1027-1031`/`:1363`） |
| FR-12 | **编译宏门控（默认关，opt-in）**：`lib/` 共存代码由 `FF_KERNEL_COEXIST` 包裹 | 宏关 `nm` 无共存符号、逐字节零回归；宏开可用 | v5 已实测（`08 §4bis`）；v6 新增 `ff_native_fd_map` 等亦须包裹 |
| FR-13 | **标记宏 opt-in 可见性**：`SOCK_FSTACK`/`SOCK_KERNEL` 被宏包裹 | APP 未定义宏不可见 | v5 已实测（`ff_api.h:81-99`） |

---

## 4. 非功能需求（NFR）

| 编号 | 需求 |
|---|---|
| NFR-1 | **默认零回归（编译期 + 运行期 + marker 三重保证）**：①`FF_KERNEL_COEXIST` 未定义 → 共存代码不编译，`libfstack.a` 与原 F-Stack 逐字节一致（`nm`/`objdump` 验证）；②`kernel_coexist=0` → 双建/双驱动分支运行期短路；③`SOCK_FSTACK` → 仅 F-Stack。三者任一满足即纯 F-Stack 行为 |
| NFR-2 | **热路径无回归**：①F-Stack 业务快路径性能不受影响；②已 accept 的单栈连接 recv/send/read/write/recvfrom/sendto 只按 `ff_is_kernel_fd` 一次判定路由，**不查 map**（热路径零额外开销，基线见 `07`/`10`） |
| NFR-3 | **F-Stack 始终在位**：自动双栈下 F-Stack fd 始终建、始终承担业务高速路径；内核栈为并行附加栈，任何场景不得替代/旁路 F-Stack |
| NFR-4 | **可移植**：兼容 DPDK 23.11.5 / 24.11.6 与移植后的 FreeBSD 栈 |
| NFR-5 | **无锁映射表**：`ff_native_fd_map` 仿 adapter `fstack_kernel_fd_map` 无锁（F-Stack 每进程单线程轮询模型，`ff_hook_syscall.c:258`） |
| NFR-6 | **多进程一致**：每进程经各自 config.ini 独立设共存开关（`ff_config.filename:254`） |

---

## 5. 边界与异常场景

- **三态 fd 路由（v6）**：`ff_is_kernel_fd(fd)`(≥`FF_KERNEL_FD_BASE`)=仅内核（v5 `ff_host_*` 路径）；否则 F-Stack 路径，且 `ff_native_map_get(fd)>0` 则再双驱动 host_fd。
- **marker 优先级**：`(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)` → 仅内核；`SOCK_FSTACK` → 仅 F-Stack；都不带 → 默认双栈（v6）。**`SOCK_FSTACK` 优先**（`ff_socket:929`）。
- **双建部分失败**：F-Stack 建成功但内核 `ff_host_socket` 失败时的契约（回滚 F-Stack？降级为仅 F-Stack？）须在 `05` 明确，不得静默泄漏。
- **accept 两栈皆 EAGAIN**：才返回 EAGAIN；任一栈有连接即返回该栈单栈 fd（`05 §accept`）。要求 listen socket 非阻塞（epoll 驱动典型）。
- **connect 数据双工歧义（N7/待确认）**：默认双栈 connect 同时向两栈发起，单逻辑流不能真双工——见 `05 §connect` 契约草案，**待用户最终确认**。
- **映射表容量**：`ff_native_fd_map[65536]`；F-Stack `kern.maxfiles`≤65536 前提（与 adapter 同）。三类返回 fd 空间不冲突（fstack<65536≪0x40000000；host 受 RLIMIT_NOFILE）。
- **close fd leak（参考上游）**：上游「`FF_KERNEL_EVENT` kernel epoll fd leak fix」——双栈 close 须清 host 侧 fd 与 `ff_epoll_pairs` 配对。
- **路由覆盖（v5 D8 → R8/R10 收口）**：`getpeername/getsockname/shutdown/sendmsg/recvmsg` 已由 **R8** 补内核 fd 路由；`readv/writev/ioctl/dup/dup2` 已由 **R10** 补内核 fd 路由（D12-D14，见 `02 §7bis`）。`select/poll`（D15）因 `FD_SETSIZE` 硬限制/合并复杂度，R10 不实现共存（文档限制，内核 fd 改用 epoll/kqueue 多路复用）。

---

## 6. 成功标准

1. **宏关 / `kernel_coexist=0` / `SOCK_FSTACK`**：`libfstack.a` 与原 F-Stack `nm`/`objdump` 无共存符号差异、逐字节零回归（FR-1/FR-12/NFR-1）。
2. **自动双栈（v6）**：默认 `listen(80)` 同时在 F-Stack(DPDK NIC) 与内核栈监听——远端经 `9.134.214.176:80`、本机 `curl 127.0.0.1:80` 皆成功，`ff_netstat` 与 `ss` 各见 80（FR-2/FR-3/FR-4/NFR-3）。
3. **统一事件 + accept 归属（v6）**：单 epoll 同时收两栈连接事件，accept 返回的单栈连接 fd 正确收发与 close（FR-5/FR-6/FR-7）。
4. **marker 单栈覆盖**：`SOCK_KERNEL`/`SOCK_FSTACK` 各按单栈语义工作（FR-8/FR-9）。
5. **热路径无回归**：F-Stack 业务快路径与单栈连接热路径性能零回归（NFR-2）。
6. **connect 契约确认**：`05 §connect` 草案经用户确认后定稿。
7. spec 全集过 `08-review-gate.md` 门禁（v6 R7「待实测」转 PASS）。
