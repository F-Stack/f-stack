# 01 需求规格：F-Stack 用户态栈 + 本地内核栈「共存」访问

> **文档编号**：SPEC-KE-01
> **版本**：v5（编译宏门控范式：`FF_KERNEL_COEXIST` 默认关闭 + 运行期 `kernel_coexist` 双层开关）
> **日期**：2026-06-17
> **状态**：编写中
> **作用域**：定义本特性的问题域、目标/非目标、功能与非功能需求、成功标准。

---

## 1. 问题域

F-Stack 通过 DPDK 接管网卡后，该网卡流量绕过 Linux 内核协议栈。一个 F-Stack 应用希望**在继续用 F-Stack 用户态栈跑业务的同时**，还能：

1. **服务端方向**：让某些监听 socket 走宿主内核栈，使本机 `ping`/`curl`/`ssh` 可直访（如管理面/健康检查/本机调试）。
2. **客户端方向**：作客户端经内核栈 `connect` 本机服务（`127.0.0.1`/本机内核栈 IP）或外部内核栈服务。
3. **统一事件**：业务（F-Stack）与内核栈 fd 在**同一事件循环**中统一处理，不必拆成两个进程/两套循环。

**关键**：这必须是**共存**——F-Stack 用户态栈始终承担业务高速路径，内核栈只是按 fd 粒度**附加**的旁路通道；**绝不是**用内核栈替代/旁路掉 F-Stack（v3 的错误）。

F-Stack 已有两个共存实现可直接复用/借鉴（见 `02`）：
- **hook 模式 `FF_KERNEL_EVENT`**（`adapter/syscall`）：`socket(type|SOCK_KERNEL)` 走内核栈，其余走 F-Stack，epoll 同时处理两栈并建立 F-Stack fd↔内核 fd 映射——**共存已完整实现**。
- **nginx `kernel_network_stack`**（`app/nginx-1.28.0`）：per-server 开关置 `belong_to_host`，双事件后端（kqueue + Linux epoll）在同一 worker 共存。

演进过程：
- hook 模式的共存能力一直存在（`FF_KERNEL_EVENT`），v4 固化为主基线并补正确 demo；
- 原生 `ff_api` 模式在 v4 改造**前**确为纯 kqueue 封装、无内核 fd 感知、无法共存；**v4 已补齐**——`lib/` 中已落地受管内核 fd + `ff_epoll_pairs` 合并（见 `02 §4`，已实测可运行）；
- config.ini 已加运行期开关 `kernel_coexist`（v3 引入的反 F-Stack `default_stack=kernel` 已废弃）。

v5 本轮即：**给已落地的原生共存代码加编译宏 `FF_KERNEL_COEXIST` 门控（默认关闭）+ 修正代码-文档不一致（D1-D8）+ 同步 spec**，确保不开启共存的部署逐字节零回归。

---

## 2. 目标与非目标

### 2.1 目标（In Scope）
- **G1（共存语义标准化）**：以 `SOCK_KERNEL`/`SOCK_FSTACK`（`ff_adapter.h:7-8`）为 per-fd 选栈标记（默认 F-Stack）；标准化为任意 F-Stack 应用可依赖的共存约定。**不新造旁路 API、不新造 `belong_to_host` 参数式接口**。
- **G2（hook 模式固化）**：以 `FF_KERNEL_EVENT` 为共存主基线，复核固化 `ff_hook_socket` 标记选栈 + `fstack_kernel_fd_map` 双栈 epoll 合并 + close 联动，并提供正确的「同进程 F-Stack 业务 + SOCK_KERNEL 内核」共存 demo。
- **G3（原生模式统一事件共存，已实现）**：lib 内已落地 fd 区分（`FF_KERNEL_FD_BASE` 编码偏移，非归属表，D6）+ `ff_epoll_pairs` 合并 kqueue⊕宿主 epoll，使原生 `ff_*` 应用一进程双栈共存；`ff_socket(SOCK_KERNEL)` 建**受管内核 fd**（经 `ff_host_socket` 宿主 socket + `ff_kernel_fd_encode`，纳入统一事件），后续 `ff_close/ff_read/ff_write/ff_sendto/ff_recvfrom/ff_accept/ff_accept4/ff_listen/ff_bind/ff_connect/ff_getsockopt/ff_setsockopt/ff_fcntl/ff_epoll_ctl` 按 fd 路由（13 入口，D8 未覆盖 `readv/writev/send/recv/...`）。
- **G4（config 运行期共存能力开关）**：config.ini 增**一个运行期开关** `kernel_coexist` 控制是否启用内核栈共存（运行期等价 `FF_KERNEL_EVENT` 的启用语义，仅当编译宏 `FF_KERNEL_COEXIST` 已开启时生效），**默认 per-fd F-Stack 不变**；**不提供「整进程默认内核」选项**。
- **G8（编译宏门控 + opt-in，v5 新增）**：`lib/` 下全部共存代码由编译宏 `FF_KERNEL_COEXIST` 门控，`lib/Makefile` **默认注释关闭**；只有 `make FF_KERNEL_COEXIST=1`（或取消注释）才编译共存能力。`ff_api.h` 的 `SOCK_FSTACK`/`SOCK_KERNEL` 标记宏亦被该宏包裹，APP 须同样定义 `FF_KERNEL_COEXIST` 方可见到这两个标记（opt-in 语义）。
- **G5（服务端共存）**：F-Stack 业务监听照常走用户态栈；带 `SOCK_KERNEL` 的监听走内核栈，本机 `ping`/`curl` 直访。
- **G6（客户端共存）**：业务客户端走 F-Stack；带 `SOCK_KERNEL` 的客户端经内核栈 `connect` 本机/外部内核服务。
- **G7（默认零开销/零回归）**：未启用共存或未标记时，行为与原 F-Stack **逐字节一致**；F-Stack 业务快路径性能不受影响。

### 2.2 非目标（Out of Scope）
- **N1**：**不**新造绕开 F-Stack 的旁路 socket（v3 `ff_host_socket` 作废）；内核 fd 必须是「受管 + 纳入统一事件」的。
- **N2**：**不**设「整进程默认走内核栈」开关（v3 `default_stack=kernel` 作废，反 F-Stack）。
- **N3**：**不**新造 `ff_local_*` 双 API / 类 mTCP 双命名空间。
- **N4**：**不**做 gazelle 式线程级选栈（多进程靠不同 config 文件）。
- **N5**：**不**采用 KNI/`rte_kni`/virtio-user 报文回灌。
- **N6**：不实现内核栈与 F-Stack 间 socket 自动迁移/透明代理（归属创建时确定）。

---

## 3. 功能需求（FR）

| 编号 | 需求 | 验收要点 | 代码依据/参考 |
|---|---|---|---|
| FR-1 | **F-Stack 业务不受影响**：默认/`SOCK_FSTACK` 的 socket 仍走 F-Stack 用户态栈 | 业务监听/连接经 DPDK NIC 正常收发 | `ff_hook_socket:406`/`ff_socket` 默认路径 |
| FR-2 | **服务端内核栈共存**：带 `SOCK_KERNEL` 的监听走内核栈，本机 `curl`/`ssh` 可访问 | 同进程内 F-Stack 业务监听 + 内核监听并存，本机访问内核监听成功 | `ff_hook_socket:387-390` |
| FR-3 | 本机 `ping`（ICMP）对内核栈侧地址可达 | ping 通 | 内核栈原生处理 ICMP |
| FR-4 | **客户端内核栈共存**：F-Stack 应用经内核栈 `connect` 本机回环/本机 IP 服务 | 本机 server + 该应用 client connect 通（同时其业务连接仍走 F-Stack） | `ff_hook_connect:858` + `is_fstack_fd:309` |
| FR-5 | **客户端连外部内核服务**：经内核栈 `connect` 外部内核栈服务 | 连外部内核服务成功 | `ff_hook_connect:858`→`ff_linux_connect:144` |
| FR-6 | **统一事件循环**：单 epoll 同时收 F-Stack 与内核栈事件 | 两栈事件均正确投递、不丢失 | hook：`fstack_kernel_fd_map:257-258`+合并 `:2324+`；原生：`ff_epoll.c:210-241` 已实现 |
| FR-7 | **双模式覆盖**：hook 模式（FF_KERNEL_EVENT）+ 原生 `ff_api` 模式（统一事件共存，已实现，v5 加编译宏门控） | 两模式均可同进程双栈共存 | `02 §2`（hook）/`02 §4`（原生已实现） |
| FR-8 | **fd 归属 + 资源联动**：按归属分流，close/异常时两栈 fd 一致释放，无泄漏 | 行为正确、无 fd 泄漏 | hook `is_fstack_fd:309`+close 联动 `:1874-1883`；原生本轮补 |
| FR-9 | **config 运行期共存能力开关**：可启用/禁用内核栈共存，默认 per-fd F-Stack 不变 | 开关生效；关闭时等价纯 F-Stack | 仿 `[kni]`：`ff_config.c:1027-1031`/`ff_config.h:321-323` |
| FR-10 | **编译宏门控（默认关闭，opt-in）**：`lib/` 全部共存代码由 `FF_KERNEL_COEXIST` 包裹，`lib/Makefile` 默认注释关闭；宏未定义时共存代码不编译 | 宏关闭时 `libfstack.a` 与原 F-Stack 逐字节零回归（`nm`/`objdump` 无 `ff_host_*`/`ff_epoll_pairs` 符号）；宏打开时共存功能可用 | `lib/Makefile:57-60`(注释关) + `:174-177`(`ifdef` 双 CFLAGS) |
| FR-11 | **标记宏 opt-in 可见性**：`SOCK_FSTACK`/`SOCK_KERNEL` 被 `FF_KERNEL_COEXIST` 包裹 | APP 未定义 `FF_KERNEL_COEXIST` 时见不到这两个标记宏；定义后可见 | `ff_api.h:81-99` |

---

## 4. 非功能需求（NFR）

| 编号 | 需求 |
|---|---|
| NFR-1 | **默认零开销/零回归（编译期保证）**：编译宏 `FF_KERNEL_COEXIST` 未定义时，全部共存代码不参与编译，`libfstack.a` 与原 F-Stack **逐字节一致**（由 `nm`/`objdump` 符号比对验证）；即使宏开启，未启用共存或默认/`SOCK_FSTACK` 路径亦与原 F-Stack 行为一致 |
| NFR-2 | **业务快路径无回归**：F-Stack 用户态栈高速路径性能不受共存影响（基线见 `07`） |
| NFR-3 | **F-Stack 始终在位**：内核栈仅为附加旁路，任何场景下不得替代/旁路 F-Stack 业务面 |
| NFR-4 | **可移植**：兼容 DPDK 23.11.5 / 24.11.6 与移植后的 FreeBSD 栈 |
| NFR-5 | **可观测**：提供两栈 fd 数/事件数等基本统计 |
| NFR-6 | **多进程一致**：每进程经各自 config.ini 独立设共存开关，互不影响（`ff_config.filename:254`） |

---

## 5. 边界与异常场景

- **编译宏未定义（默认）**：`SOCK_FSTACK`/`SOCK_KERNEL` 标记宏不可见，`ff_socket` 无内核分支、`ff_epoll` 无合并、各 `ff_*` 无 `ff_is_kernel_fd` 路由——等价原 F-Stack。
- `SOCK_KERNEL` 与 `SOCK_FSTACK` 同时置位的优先级（实测 hook `ff_hook_socket:387` 与原生 `ff_socket`（`ff_syscall_wrapper.c:926`）均要求 `SOCK_KERNEL && !SOCK_FSTACK` 才走内核，否则 F-Stack）；接口契约须明确「`SOCK_FSTACK` 优先」。
- 运行期共存开关关闭（`kernel_coexist=0`）时，带 `SOCK_KERNEL` 的原生 `ff_socket` 退化为 F-Stack 路径（实测 `ff_syscall_wrapper.c:926-931` 条件含 `&& ff_global_cfg.stack.kernel_coexist`）。
- 内核栈侧地址/端口与 F-Stack 侧冲突时报错而非静默。
- hook 模式 `maxevents` 过小（机制要求 `>=2`，`adapter/syscall/ff_hook_syscall.c:2212-2218`）；原生 `ff_epoll_wait` 要求 `maxevents>=1`（`ff_epoll.c:215`）。
- 客户端 `connect` 时 fd 归属与目的地址栈不匹配的行为约定。
- **原生模式路由覆盖范围限制（D8，实测）**：当前原生入口中已加 `ff_is_kernel_fd` 路由的为 `ff_getsockopt/ff_setsockopt/ff_close/ff_read/ff_write/ff_sendto/ff_recvfrom/ff_fcntl/ff_accept/ff_accept4/ff_listen/ff_bind/ff_connect`；**尚未覆盖** `ff_readv/ff_writev/ff_send/ff_recv/ff_getpeername/ff_getsockname/ff_shutdown/ff_ioctl/ff_sendmsg/ff_recvmsg` 等——对受管内核 fd 调用这些未覆盖接口将走 F-Stack 路径而非宿主桥，属已知限制，使用受管内核 fd 时应避开。
- F-Stack `kern.maxfiles` ≤ 65536 的前提（fd 空间区分约束：受管内核 fd = 宿主 fd + `FF_KERNEL_FD_BASE`(0x40000000)，`ff_host_interface.h:112`，远高于 FreeBSD fd 上限，故两区间不冲突）。
- **close 资源联动复核项（参考上游）**：上游 README 提及「`FF_KERNEL_EVENT` kernel epoll fd leak fix」——长稳运行下 close 时须清理 host epoll 配对，当前原生 `ff_close` 对 `ff_epoll_pairs` 的清理需 review 复核（见 `03`/`07`）。

---

## 6. 成功标准

1. **同一个 F-Stack 应用进程**内：F-Stack 业务监听/连接经 DPDK NIC 正常（FR-1），**同时**带 `SOCK_KERNEL` 的内核监听被本机 `curl`/`ping` 访问成功（FR-2/FR-3）——证明 F-Stack 未被旁路、双栈真正共存。
2. 该应用作客户端经内核栈 `connect` 本机/外部内核服务成功（FR-4/FR-5），同时其业务客户端仍走 F-Stack。
3. 单 epoll 同时正确收发两栈事件（FR-6/FR-8）；hook 与原生两模式均共存（FR-7）。
4. config 运行期共存开关生效；关闭/默认时业务功能与性能**零回归**（FR-9/NFR-1/NFR-2/NFR-3）。
5. **编译宏 `FF_KERNEL_COEXIST` 未定义时**，`libfstack.a` 与原 F-Stack 经 `nm`/`objdump` 比对**无共存符号**（`ff_host_*`/`ff_epoll_pairs` 等）、逐字节零回归；宏定义后共存功能可用（FR-10/FR-11）。
6. spec 全集过 `08-review-gate.md` 门禁。
