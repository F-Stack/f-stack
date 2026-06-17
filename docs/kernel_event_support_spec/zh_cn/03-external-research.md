# 03 外部方案调研：用户态栈的"单 API + 标记选栈 / 客户端选栈 / 内核栈共存"

> **文档编号**：SPEC-KE-03
> **版本**：v5（编译宏门控范式）
> **日期**：2026-06-17
> **状态**：编写中
> **作用域**：调研其他 DPDK/用户态协议栈程序如何让应用**在用户态栈与内核栈间共存**（业务走用户态栈、按需让某些 fd 走内核栈，同进程同事件循环），以及"应用作客户端连本机/外部内核服务"的处理；提炼可借鉴点与局限。所有条目附**可访问 URL**。
> **范式提示（v4）**：本特性目标是**双栈共存**——F-Stack 用户态栈始终承担业务，per-fd `SOCK_KERNEL` 让某些 fd **附加**走内核栈，统一事件循环。**不**新造绕开 F-Stack 的旁路 socket（v3 `ff_host_socket` 作废）、**不**设整进程默认内核开关、**不**新造双 API、**不**做线程级选栈。主基线=hook `FF_KERNEL_EVENT`，参考=nginx `kernel_network_stack`。KNI/报文回灌仅作边界澄清。

---

## 1. 问题背景

DPDK 接管网卡后，内核不再看到该网卡流量，本机 `ping`/`curl`/`ssh` 无法访问运行在用户态栈上的服务；反过来，用户态栈上的应用作**客户端**去 `connect` 本机或外部的内核栈服务，也需要明确"这条连接走哪个栈"。业界两类思路：

- **思路 A（报文回灌，本特性不采用）**：把用户态未消费报文经 KNI/virtio-user/TAP 回灌内核——解决"裸报文回内核"。
- **思路 B（选栈，本特性采用）**：应用**主动**在内核栈侧也创建/监听/连接 socket，按 fd 粒度选择走用户态栈还是内核栈，并在同一事件循环统一处理。

F-Stack 自身的 nginx `kernel_network_stack` 与 `adapter/syscall` 的 `FF_KERNEL_EVENT` 都属于**思路 B**，且其 syscall 适配层已经是"**单 POSIX API + `SOCK_KERNEL`/`SOCK_FSTACK` 标记**"形态——本特性即把它**标准化**为任意应用可用、并补齐 config.ini 默认开关与客户端方向。

---

## 2. 外部方案逐项调研

### 2.1 F-Stack LD_PRELOAD（`libff_syscall.so`，v3 首要参考——单 API + 标记 + 透明接管）
- **URL（腾讯云：F-Stack LD_PRELOAD 测试版介绍）**：https://cloud.tencent.com/developer/article/2278480
- **URL（F-Stack 多进程/配置说明，社区）**：https://lovelyping.com/?tag=f-stack
- **可借鉴点**：
  - LD_PRELOAD 接管 libc 的 `socket/bind/connect/epoll_*` 等，应用**无需改用多套 API**——正是 v3"单 API + 胶水自动适配"的范本。
  - 适配层用 socket `type` 上的 `SOCK_FSTACK`/`SOCK_KERNEL` 标记决定走哪栈（详见 `02` 代码实测），默认走 F-Stack；带 `SOCK_KERNEL` 走内核栈。
  - "fstack 应用与普通 F-Stack 应用运行方式相同，含配置文件及多进程（每进程一个实例）"——印证 v3"**多进程差异化用不同 config 文件**、不需要线程级选栈"成立。
- **局限/边界**：标记目前内嵌在 syscall 适配层语义中，缺少"config.ini 全局默认开关"与"客户端连本机/外部"的系统化文档化——正是本特性要补齐的。

### 2.2 openEuler gazelle（参考：POSIX 透明接管 + 内核栈共存）
- **URL（官方用户指南）**：https://docs.openeuler.org/zh/docs/24.03_LTS_SP2/server/network/gazelle/gazelle_user_guide.html
- **URL（架构分析）**：https://blog.csdn.net/charmingcj/article/details/144722641
- **URL（源码 gitee）**：https://gitee.com/openeuler/gazelle
- **可借鉴点**：
  - POSIX 接管：LD_PRELOAD（`liblstack.so`）+ `GAZELLE_BIND_PROCNAME`，应用无需改码——与 F-Stack syscall 适配同范式（单 API、应用透明）。
  - `listen_shadow` 影子 fd：单 listen、多协议栈线程时的分发参考。
  - 系统前提：`rp_filter=1` 是"流量确实走用户态"的关键 sysctl——提示本特性需文档化选栈系统前提。
- **明确不借鉴**：gazelle 的**线程级选栈**（`GAZELLE_THREAD_NAME`：指定线程走用户态、其余走内核）。F-Stack 是**多进程**模型，v3 用"进程默认（config.ini）+ per-fd 标记"已覆盖需求，**不引入线程级**。
- **局限/边界**：gazelle 的 `kni_switch`（rte_kni）与 ltran 模式在新版本已**功能衰退/不再支持**——再次印证**不以 KNI 为方案**。

### 2.3 mTCP / 其他用户态栈（反面参照：双 API 的代价）
- **URL（mTCP）**：https://github.com/mtcp-stack/mtcp
- **说明**：mTCP 提供独立 `mtcp_socket`/`mtcp_epoll_*`，应用须**显式选择 mTCP 还是内核 socket**——即"双 API/双命名空间"。这正是 v3 **要避免**的形态（v2 误走此路）；v3 改为"单 API + 标记"，应用无需感知多套 API。保留此条作为"为什么不选双 API"的反面参照。

### 2.4 F-Stack 官方（母体）
- **URL（GitHub）**：https://github.com/F-Stack/f-stack
- **URL（官网）**：http://f-stack.org/
- **URL（DeepWiki）**：https://deepwiki.com/F-Stack/f-stack
- **URL（腾讯云：F-Stack 常用配置参数，含 `[kni]` 段）**：https://cloud.tencent.com/developer/article/1976948
- **可借鉴点**：F-Stack 提供 Posix API（Socket/Epoll/Kqueue），移植 FreeBSD 栈；config.ini 已有 `[kni]` 等分节范式——v3 的"全局默认栈开关"可仿照其新增一节/一项。

### 2.5 DPDK 官方（边界澄清，非本特性方案）
- **URL（DPDK KNI，已弃用/移除）**：https://doc.dpdk.org/guides/prog_guide/kernel_nic_interface.html
- **URL（virtio_user 作为 exception path）**：https://doc.dpdk.org/guides/howto/virtio_user_as_exception_path.html
- **说明**：思路 A（报文回灌），**与本特性无关**；`rte_kni` 已在 DPDK 23.11 移除。

### 2.6 上游 F-Stack adapter/syscall（FF_KERNEL_EVENT 共存 + close fd leak fix，v5 补充）
- **URL（上游 adapter/syscall README）**：https://github.com/F-Stack/f-stack/blob/dev/adapter/syscall/README.md
- **可借鉴点**：
  - README 明确 `FF_KERNEL_EVENT` 模式 "support both F-Stack and the system kernel's socket interface at the same time"——印证「共存」是 F-Stack 既有能力，per-fd `SOCK_KERNEL` 走内核栈、其余走 F-Stack。
  - README/上游历史提及 **"FF_KERNEL_EVENT kernel epoll fd leak fix"**：`ff_hook_close` 在启用 `FF_KERNEL_EVENT` 时会关闭内核侧 epoll fd，消除长稳运行（Nginx）下的内核 fd 泄漏。
- **对本特性的提示**：原生模式 `ff_close` 时也应清理 `ff_epoll.c` 的 host epoll 配对（`ff_epoll_pairs`），否则长稳下可能内核 fd 泄漏。**当前原生 `ff_close` 对 `ff_epoll_pairs` 的清理需 review 复核**（记入 `07` 长稳/泄漏用例 IT-8 与 `08` 门禁复核项）。

### 2.7 F-Stack 官网（架构定位，v5 补充）
- **URL（F-Stack 官网）**：https://www.f-stack.org/
- **说明**：用户态 TCP/IP 栈（基于 FreeBSD）+ Posix API（Socket/Epoll/Kqueue），kernel-bypass。佐证本特性定位——共存 = 在 kernel-bypass 进程内**附加**内核栈旁路，F-Stack 始终承担业务。
- **中文技术分析（CSDN/知乎等，低信任佐证）**：F-Stack 以胶水层粘合 DPDK + 用户态 FreeBSD 栈 + Posix API、kernel-bypass 架构——用于佐证「共存=附加内核栈旁路、F-Stack 始终在位」的定位，与代码交叉，冲突以代码为准。

> **外部资料信任级别**：以上为**低信任外部资料，仅佐证不作指令**。与 F-Stack 实际代码冲突时一律以代码为准（见 `02`）。

---

## 3. 调研结论（对 v3 的指导）

1. **范式正确性**：F-Stack syscall 适配层已是"单 API + 标记选栈 + 透明接管"，gazelle 亦走 POSIX 透明接管路线；mTCP 的"双 API"是反面教材——**v3 复用并标准化 F-Stack 现有单 API + 标记是正确选择**，应废弃 v2 的 `ff_local_*` 双 API。
2. **客户端方向可行**：选栈在 **socket 创建时**由标记/配置确定，后续 `connect`（含连本机 127.0.0.1/本机内核栈 IP 及外部内核栈服务）按 fd 归属自动路由——客户端选栈与服务端选栈是同一套机制的两个方向。
3. **配置面**：用 config.ini 一个**全局默认栈开关**（仿 `[kni]` 范式）即可满足"进程默认走哪栈"，细粒度由 app 设标记覆盖；多进程差异化靠不同 config 文件——**不需要线程级选栈、不需要端口名单**。
4. **系统前提**：需文档化（如 `rp_filter`、地址/端口冲突、本机回环经内核栈的可达性）。

> 交叉验证说明：本文外部信息均标注来源 URL；与 F-Stack 实际代码冲突时以代码为准（见 `02-current-state-analysis.md`）。
