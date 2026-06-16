# 00 总览：F-Stack 用户态栈 + 本地内核栈「共存」访问（per-fd 标记选栈 + 统一事件）

> **文档编号**：SPEC-KE-00
> **版本**：v4（共存范式返工重写）
> **日期**：2026-06-16
> **状态**：编写中
> **作用域**：本目录中文 spec 的导航、术语与范围声明

---

## 0. v4 返工背景（必读）

v3 实现把 `ff_socket(SOCK_KERNEL)` 接到 `ff_host_socket()`→纯宿主 `socket()`，**完全绕开 F-Stack 用户态 FreeBSD 栈**，示例全程纯内核——等于在 F-Stack 进程里单独跑内核栈、把 F-Stack 扔了。**这是根本性错误**。

**v4 正确范式**：**同一个 F-Stack 应用进程内**，业务连接走 **F-Stack 用户态栈（DPDK + FreeBSD）**，同时带 `SOCK_KERNEL` 标记的 fd 走**宿主 Linux 内核栈**，二者**纳入同一事件循环共存**。这正是 F-Stack 已有的两个实现所做的事：
- `adapter/syscall` 的 **`FF_KERNEL_EVENT`** 编译模式（hook/LD_PRELOAD）；
- nginx 的 **`kernel_network_stack`** 配置开关。

本特性 = 把上述「共存」能力**固化为主基线（hook 模式）** + **补齐原生 `ff_api` 模式的统一事件共存**，而非另造绕开 F-Stack 的旁路。

## 1. 一句话目标

让一个 F-Stack 应用**在用 F-Stack 用户态栈跑业务高速路径的同时**，按 fd 粒度让某些 socket/listen/connect 走宿主机内核栈（使本机 `ping`/`curl`/`ssh` 可直访其内核栈服务、且应用作客户端可经内核栈 `connect` 本机/外部内核服务），两栈 fd 在**同一 epoll/事件循环**中统一收发——**F-Stack 始终在位、绝不被旁路替代**。

## 2. 范围声明（重要）

- **本特性 = 双栈共存**：F-Stack 用户态栈（业务，默认）+ 宿主内核栈（per-fd `SOCK_KERNEL`），同进程同事件循环。
- **选栈方式**：per-fd `SOCK_KERNEL`/`SOCK_FSTACK` 标记（默认 F-Stack）；config.ini 一个**共存能力开关**（是否启用内核栈共存，不改变默认 per-fd F-Stack 语义）。
- **hook 模式（主基线，已支持）**：直接复用 `FF_KERNEL_EVENT`——`ff_hook_socket` 按标记选栈 + `fstack_kernel_fd_map` 双栈 epoll 合并；本轮固化并提供正确的共存 demo。
- **原生 `ff_api` 模式（新设计）**：当前 `ff_epoll_*` 是纯 kqueue 封装、无内核 fd 感知；本轮在 lib 内补 fd 归属表 + 内核 epoll 镜像 + `ff_epoll_wait` 合并 kqueue⊕epoll，使原生链接应用也能一进程双栈共存。
- **明确排除**：
  - **不**新造绕开 F-Stack 的旁路 socket（v3 `ff_host_socket` 做法作废）。
  - **不**设「整进程默认走内核栈」这种反 F-Stack 的全局开关（v3 `default_stack=kernel` 作废）。
  - **不**新造 `ff_local_*` 双 API / 类 mTCP 双命名空间。
  - **不**做 gazelle 式线程级选栈（F-Stack 多进程模型靠不同 config 文件）。
  - **不**采用 KNI/`rte_kni`/virtio-user 报文回灌（仅边界澄清）。

## 3. 阅读路径

| 顺序 | 文档 | 用途 |
|---|---|---|
| 1 | `plan.md` | 计划、团队、门禁、返工范式 |
| 2 | `01-requirements-spec.md` | 需求与目标/非目标（共存） |
| 3 | `02-current-state-analysis.md` | hook FF_KERNEL_EVENT / nginx kernel_network_stack / 原生事件层 现状（以代码为准） |
| 4 | `03-external-research.md` | 外部方案调研（附 URL） |
| 5 | `04-architecture-design.md` | 共存架构、双栈统一事件、双向数据流 |
| 6 | `05-interface-design.md` | 标记/config 契约、hook 与原生双模式适配 |
| 7 | `06-milestones.md` | 里程碑与编码工作清单 |
| 8 | `07-test-spec.md` | 测试与性能基线方案 |
| 9 | `08-review-gate.md` | 审核门禁结论 |

## 4. 术语表

| 术语 | 含义 |
|---|---|
| F-Stack 栈 | DPDK PMD + 用户态 FreeBSD 协议栈（业务高速路径，**默认栈**） |
| 内核栈 | 宿主机 Linux 内核协议栈（本机/管理/客户端连本机或外部内核服务） |
| 共存 | **同一进程同一事件循环**内 F-Stack fd 与内核 fd 并存，各走各栈 |
| 选栈标记 | socket `type` 上的 `SOCK_KERNEL`(0x02000000)/`SOCK_FSTACK`(0x01000000)，per-fd |
| 共存能力开关 | config.ini 中是否启用内核栈共存的开关（不改变默认 per-fd F-Stack 语义） |
| fd 归属 | 创建时标记定 fd 属 F-Stack 或内核，后续 syscall/事件按归属路由（`is_fstack_fd`/`CHECK_FD_OWNERSHIP`） |
| 统一事件 | 对外 epoll 风格，内部合并 F-Stack kqueue 事件 + 内核 epoll 事件 |
| hook 模式 | LD_PRELOAD 接管 POSIX API（`ff_hook_*`）+ `FF_KERNEL_EVENT`，共存已支持 |
| 原生模式 | 应用直接调 `ff_*`（`ff_api.h`）+ `ff_run` 主循环；本轮补统一事件共存 |

## 5. 依据来源

- F-Stack 实际代码（`adapter/syscall/`、`app/nginx-1.28.0/`、`lib/`）——**最高优先级，冲突以代码为准**。
- F-Stack 三层架构文档与知识图谱（`docs/`）、`adapter/syscall/README.md`。
- 外网公开资料（GitHub/技术博客等），均在 `03` 附可访问 URL。
