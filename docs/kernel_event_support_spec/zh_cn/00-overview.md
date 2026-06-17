# 00 总览：F-Stack 用户态栈 + 本地内核栈「自动双栈共存」（编译宏门控 + 默认双栈 + marker 单栈覆盖 + 统一事件）

> **文档编号**：SPEC-KE-00
> **版本**：v6（**native 自动双栈共存**范式：默认无 marker 即同建 F-Stack+内核双栈、双驱动、统一事件；marker 单栈覆盖兼容 v5；外层仍由 `FF_KERNEL_COEXIST` 编译宏 + 运行期 `kernel_coexist` 双层门控）
> **日期**：2026-06-17
> **状态**：编写中（v6 设计）
> **作用域**：本目录中文 spec 的导航、术语与范围声明

---

## 0. v6 背景：从「per-fd 二选一」到「自动双栈」（必读）

v5（commit ba148589d）已把 `lib/` 全部共存代码用编译宏 `FF_KERNEL_COEXIST` 包裹（`lib/Makefile` 默认关），形成**编译期 + 运行期双层开关**，并实测宏关逐字节零回归、宏开 per-fd 共存可用（真机性能见 `10`）。v5 的语义是 **per-fd 二选一**：

- `ff_socket(type|SOCK_KERNEL)` → **仅**建内核 fd，返回 `ff_kernel_fd_encode(host_fd)`（≥`FF_KERNEL_FD_BASE`）；
- 否则 → **仅**建 F-Stack fd（原始 fd）。

**v6 把默认语义升级为「自动双栈」**：当 `FF_KERNEL_COEXIST` 编译开 **且** `config.ini [stack] kernel_coexist=1` 时——

- **默认（无 marker）= 双栈**：一次 `ff_socket` **同时**建 F-Stack fd + 内核 host fd，登记映射表 `ff_native_fd_map[fstack_fd]=host_fd`，**返回 F-Stack 原始 fd**；`ff_bind/ff_listen/ff_close/ff_connect` 等对该双栈 fd **同时驱动两栈**——**一个 `listen(80)` 同时在 F-Stack(DPDK) 与 Linux 内核栈监听**，本机 `curl 127.0.0.1:80` 与远端经 DPDK 网卡访问 `:80` 同时可达，无需任何 marker。
- **marker 单栈覆盖（兼容 v5）**：`type|SOCK_KERNEL`=仅内核；`type|SOCK_FSTACK`=仅 F-Stack。
- **零回归**：编译宏关 **或** `kernel_coexist=0` **或** `SOCK_FSTACK` → 逐字节零回归（原 F-Stack 路径）。

> **实现状态声明（防臆测）**：v6 的 native 映射表 `ff_native_fd_map` 与默认双建/双驱动逻辑**尚未在 `lib/` 落地**（grep 确认 lib 无 `ff_native_fd_map` 符号）——本目录 v6 文档是**升级后的设计**，明确区分「v5 已实测落地」与「v6 待实现设计」，任何 v6 行为均不得当既成事实。

> **v3 历史错误（已回退）**：v3 曾把 `ff_socket(SOCK_KERNEL)` 接到 `ff_host_socket()`→纯宿主 `socket()`，**完全绕开 F-Stack**——根本性错误，已回退（commit 0748eff94）。v6 的「双栈」绝不是旁路：F-Stack 始终建、始终在位，内核栈是**并行附加**的第二条栈。

---

## 1. 一句话目标

让一个 F-Stack 应用**默认就能双栈共存**：同一个 socket/listen **同时**在 F-Stack 用户态栈（DPDK+FreeBSD，业务高速路径）与宿主 Linux 内核栈上工作，本机 `ping`/`curl`/`ssh` 直访内核栈侧、远端经 DPDK 网卡访问 F-Stack 侧，两栈事件在**同一 epoll/事件循环**统一收发——**F-Stack 始终在位、绝不被旁路替代**；需要单栈时用 `SOCK_KERNEL`/`SOCK_FSTACK` marker 覆盖。

## 2. 范围声明（重要）

- **本特性 = 自动双栈共存**：默认无 marker 即 F-Stack + 内核双栈、双驱动、统一事件；marker 单栈覆盖。
- **编译宏门控（最外层）**：全部共存代码由 `FF_KERNEL_COEXIST` 门控，`lib/Makefile` **默认注释关闭**；未开启时共存代码不编译、与原 F-Stack 逐字节零回归。
- **运行期开关**：`config.ini [stack] kernel_coexist`（编译宏已开启时才生效），`=1` 启用自动双栈，`=0` 退化为纯 F-Stack（零回归）。
- **选栈 marker**：`SOCK_KERNEL`（仅内核）/`SOCK_FSTACK`（仅 F-Stack），覆盖默认双栈。
- **hook 模式（参考主基线）**：`adapter/syscall` 的 `FF_KERNEL_EVENT` 已支持「应用 on F-Stack + epoll 双建合并 + close 联动」，**但 socket/listen 不双建**（内核 listen 需显式 `SOCK_KERNEL`）。native v6 的分歧点=socket/bind/listen/connect **也自动双建/双驱动**。
- **明确排除**：
  - **不**新造绕开 F-Stack 的旁路 socket（v3 `ff_host_socket` 裸绕过作废）。
  - **不**设「整进程默认内核」反 F-Stack 全局开关（v3 `default_stack=kernel` 作废）。
  - **不**新造 `ff_local_*` 双 API / 类 mTCP 双命名空间。
  - **不**做 gazelle 式线程级选栈（F-Stack 多进程靠不同 config 文件）。
  - **不**采用 KNI/`rte_kni`/virtio-user 报文回灌（仅边界澄清）。

## 3. 阅读路径

| 顺序 | 文档 | 用途 |
|---|---|---|
| 1 | `plan.md` | v6 升级摘要、设计契约、团队、门禁 |
| 2 | `01-requirements-spec.md` | 需求与目标/非目标（自动双栈 + marker 单栈覆盖） |
| 3 | `02-current-state-analysis.md` | v5 实测现状 + native vs hook 同构/分歧表 + v6 映射表缺口 |
| 4 | `03-external-research.md` | 外部方案调研（附 URL，低信任佐证） |
| 5 | `04-architecture-design.md` | 双驱动数据流 + fd 三态路由 + 事件双栈 + 映射表 |
| 6 | `05-interface-design.md` | socket/bind/listen/connect/accept/close/epoll_* 双栈契约 + marker 语义 + connect 契约草案 + 异常矩阵 |
| 7 | `06-milestones.md` | R6→R7 自动双栈实现里程碑 |
| 8 | `07-test-spec.md` | cmocka 双态用例 + 真机双栈方案 |
| 9 | `08-review-gate.md` | 门禁结论（v6 R7「待实测」） |
| 10 | `09-impl-plan.md` | 逐文件改造步骤 |
| 11 | `10-perf-baseline-report.md` | 双栈对 F-Stack 快路径无回归口径 |

## 4. 术语表

| 术语 | 含义 |
|---|---|
| F-Stack 栈 | DPDK PMD + 用户态 FreeBSD 协议栈（业务高速路径，**始终在位**） |
| 内核栈 | 宿主机 Linux 内核协议栈（本机/管理/客户端连本机或外部内核服务） |
| **自动双栈（v6）** | 默认无 marker 时一次 socket 同建 F-Stack fd + 内核 host fd，各 `ff_*` 双驱动两栈 |
| **双栈 fd（v6）** | 返回给 app 的 F-Stack 原始 fd，在 `ff_native_fd_map` 中映射到一个内核 host fd |
| **native 映射表（v6 待实现）** | `ff_native_fd_map[fstack_fd]=host_fd`（`ff_host_interface.c`，65536 项），仿 adapter `fstack_kernel_fd_map` |
| 受管内核 fd（单栈内核） | `ff_kernel_fd_encode(host_fd)`(≥`FF_KERNEL_FD_BASE`=0x40000000)，`SOCK_KERNEL` 或 accept 内核侧连接返回，无 map 项 |
| `FF_KERNEL_COEXIST` | **编译宏**，门控全部共存代码是否参与编译；`lib/Makefile` 默认注释关闭（编译期开关） |
| 选栈 marker | socket `type` 上的 `SOCK_KERNEL`(0x02000000)/`SOCK_FSTACK`(0x01000000)，单栈覆盖默认双栈（被 `FF_KERNEL_COEXIST` 包裹，opt-in） |
| 共存能力开关 | `config.ini [stack] kernel_coexist`，**运行期**启用自动双栈（仅编译宏开启时生效） |
| fd 三态路由 | `ff_is_kernel_fd(fd)`(≥BASE)=仅内核；否则 F-Stack 路径，且 `ff_native_map_get(fd)>0` 则再双驱动 host_fd |
| 统一事件 | 对外 epoll 风格，内部合并 F-Stack kqueue 事件 + 内核 epoll 事件（双栈 listen 两栈各注册一次） |
| hook 模式 | LD_PRELOAD 接管 POSIX API（`ff_hook_*`）+ `FF_KERNEL_EVENT`，epoll 双建合并，socket/listen 不双建 |
| 原生模式 | 应用直接调 `ff_*`（`ff_api.h`）+ `ff_run` 主循环；v6 实现自动双栈 |

## 5. 依据来源

- F-Stack 实际代码（`lib/`、`adapter/syscall/`、`app/nginx-1.28.0/`）——**最高优先级，冲突以代码为准**。
- F-Stack 三层架构文档与知识图谱（`docs/`）、`adapter/syscall/README.md`。
- 外网公开资料（GitHub/技术博客等），均在 `03` 附可访问 URL，**低信任仅佐证**。
