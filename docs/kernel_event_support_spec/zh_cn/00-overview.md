# 00 总览：F-Stack 用户态栈 + 本地内核栈「共存」访问（编译宏门控 + per-fd 标记选栈 + 统一事件）

> **文档编号**：SPEC-KE-00
> **版本**：v5（编译宏门控范式：`FF_KERNEL_COEXIST` 默认关闭 + 运行期 `kernel_coexist` 双层开关）
> **日期**：2026-06-17
> **状态**：编写中
> **作用域**：本目录中文 spec 的导航、术语与范围声明

---

## 0. v5 编译宏门控背景（必读）

v4 已把「共存」实现落地（应用 on F-Stack + per-fd `SOCK_KERNEL` 走内核栈 + 统一事件）。但 v4 的全部共存代码在 `lib/` 中**无条件编译**，意味着即使不用共存能力的部署也会链接进这些代码，无法保证与原 F-Stack「逐字节零回归」。

**v5 新增要求**：对 `lib/` 下本特性的全部代码修改，**统一增加一个编译宏 `FF_KERNEL_COEXIST`**，在 `lib/Makefile` 中**默认关闭（注释掉）**，形成**编译期 + 运行期双层开关**：

- **编译期（`FF_KERNEL_COEXIST`）**：未定义 → 全部共存代码（受管内核 fd 桥、fd 归属判定、`ff_epoll` 合并、`ff_socket` 内核分支、各 `ff_*` 入口路由、config `kernel_coexist`、`SOCK_FSTACK/SOCK_KERNEL` 宏）**不参与编译**，`libfstack.a` 与原 F-Stack **逐字节零回归**；定义（`make FF_KERNEL_COEXIST=1` 或取消 Makefile 注释）→ 编译进共存能力。
- **运行期（config `kernel_coexist`）**：**仅当编译期已开启**，`config.ini [stack] kernel_coexist=1` 才真正启用 per-fd `SOCK_KERNEL` 走内核栈；默认 `=0` 仍 per-fd F-Stack。
- **opt-in 影响**：`ff_api.h` 中 `SOCK_FSTACK`/`SOCK_KERNEL` 宏也被 `FF_KERNEL_COEXIST` 包裹，故消费方（APP）需同样定义该宏才能见到这两个标记——这是「默认关闭、显式开启」的合理语义。

> **v4 历史背景**：v3 实现曾把 `ff_socket(SOCK_KERNEL)` 接到 `ff_host_socket()`→纯宿主 `socket()`，**完全绕开 F-Stack 用户态 FreeBSD 栈**，示例全程纯内核——等于在 F-Stack 进程里单独跑内核栈、把 F-Stack 扔了，是**根本性错误**，已在 v4 回退并重写为下述正确范式。

v3 实现把 `ff_socket(SOCK_KERNEL)` 接到 `ff_host_socket()`→纯宿主 `socket()`，**完全绕开 F-Stack 用户态 FreeBSD 栈**，示例全程纯内核——等于在 F-Stack 进程里单独跑内核栈、把 F-Stack 扔了。**这是根本性错误**。

**正确范式**：**同一个 F-Stack 应用进程内**，业务连接走 **F-Stack 用户态栈（DPDK + FreeBSD）**，同时带 `SOCK_KERNEL` 标记的 fd 走**宿主 Linux 内核栈**，二者**纳入同一事件循环共存**。这正是 F-Stack 已有的两个实现所做的事：
- `adapter/syscall` 的 **`FF_KERNEL_EVENT`** 编译模式（hook/LD_PRELOAD）；
- nginx 的 **`kernel_network_stack`** 配置开关。

本特性 = 把上述「共存」能力**固化为主基线（hook 模式）** + **补齐原生 `ff_api` 模式的统一事件共存**，并由**编译宏 `FF_KERNEL_COEXIST` 门控（默认关闭）**，而非另造绕开 F-Stack 的旁路。

## 1. 一句话目标

让一个 F-Stack 应用**在用 F-Stack 用户态栈跑业务高速路径的同时**，按 fd 粒度让某些 socket/listen/connect 走宿主机内核栈（使本机 `ping`/`curl`/`ssh` 可直访其内核栈服务、且应用作客户端可经内核栈 `connect` 本机/外部内核服务），两栈 fd 在**同一 epoll/事件循环**中统一收发——**F-Stack 始终在位、绝不被旁路替代**。

## 2. 范围声明（重要）

- **本特性 = 双栈共存**：F-Stack 用户态栈（业务，默认）+ 宿主内核栈（per-fd `SOCK_KERNEL`），同进程同事件循环。
- **编译宏门控（v5 新增，最外层）**：全部共存代码由 `FF_KERNEL_COEXIST` 门控，`lib/Makefile` **默认注释关闭**；未开启时共存代码不编译、与原 F-Stack 逐字节零回归。
- **选栈方式**：per-fd `SOCK_KERNEL`/`SOCK_FSTACK` 标记（默认 F-Stack）；config.ini 一个**运行期共存能力开关** `kernel_coexist`（编译宏已开启时才生效，是否启用内核栈共存，不改变默认 per-fd F-Stack 语义）。
- **hook 模式（主基线，已支持）**：直接复用 `FF_KERNEL_EVENT`——`ff_hook_socket` 按标记选栈 + `fstack_kernel_fd_map` 双栈 epoll 合并；本轮固化并提供正确的共存 demo。
- **原生 `ff_api` 模式（已实现，v5 加编译宏门控）**：lib 内已落地 fd 区分（`FF_KERNEL_FD_BASE` 编码偏移）+ 受管内核 fd（`ff_host_*` 桥）+ `ff_epoll_pairs` 合并 kqueue⊕宿主 epoll（见 `02 §4`）；v5 用 `FF_KERNEL_COEXIST` 包裹（默认关）。
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
| `FF_KERNEL_COEXIST` | **编译宏**，门控全部共存代码是否参与编译；`lib/Makefile` 默认注释关闭（编译期开关） |
| 选栈标记 | socket `type` 上的 `SOCK_KERNEL`(0x02000000)/`SOCK_FSTACK`(0x01000000)，per-fd（被 `FF_KERNEL_COEXIST` 包裹，需 APP 同样定义该宏才可见） |
| 共存能力开关 | config.ini `[stack] kernel_coexist`，**运行期**是否启用内核栈共存的开关（仅编译宏已开启时生效，不改变默认 per-fd F-Stack 语义） |
| fd 归属 | 创建时标记定 fd 属 F-Stack 或内核，后续 syscall/事件按归属路由（`is_fstack_fd`/`CHECK_FD_OWNERSHIP`） |
| 统一事件 | 对外 epoll 风格，内部合并 F-Stack kqueue 事件 + 内核 epoll 事件 |
| hook 模式 | LD_PRELOAD 接管 POSIX API（`ff_hook_*`）+ `FF_KERNEL_EVENT`，共存已支持 |
| 原生模式 | 应用直接调 `ff_*`（`ff_api.h`）+ `ff_run` 主循环；本轮补统一事件共存 |

## 5. 依据来源

- F-Stack 实际代码（`adapter/syscall/`、`app/nginx-1.28.0/`、`lib/`）——**最高优先级，冲突以代码为准**。
- F-Stack 三层架构文档与知识图谱（`docs/`）、`adapter/syscall/README.md`。
- 外网公开资料（GitHub/技术博客等），均在 `03` 附可访问 URL。
