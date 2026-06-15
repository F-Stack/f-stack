# 03 外部方案调研：DPDK/用户态栈应用的"本机直访 / 内核栈共存"方案

> **文档编号**：SPEC-KE-03
> **版本**：v2（全量重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：调研其他 DPDK / 用户态协议栈程序如何让"本机仍可访问服务"或"用户态栈与内核栈共存/选栈"，提炼可借鉴点与局限。所有条目附**可访问 URL**。
> **范围提示**：本文聚焦"**连接/线程级选栈 + 双栈事件**"思路；KNI/virtio-user 等"报文回灌"方案仅作边界澄清，不作为本特性方案。

---

## 1. 问题背景

DPDK 接管网卡后，内核不再看到该网卡的流量，本机 `ping`/`curl`/`ssh` 无法访问运行在用户态栈上的服务。业界两类思路：

- **思路 A（报文回灌，本特性不采用）**：把用户态未消费的报文经 KNI / virtio-user / TAP 回灌内核，让内核栈"看到"网卡——解决的是"裸报文回内核"。
- **思路 B（连接级选栈，本特性采用）**：应用**主动**在内核栈侧也创建/监听 socket，按连接/线程/监听粒度选择走用户态栈还是内核栈，并在同一事件循环中统一处理——解决的是"应用服务在内核侧也可被访问"。

F-Stack 自身的 nginx `kernel_network_stack` 与 `adapter/syscall` 的 `FF_KERNEL_EVENT` 都属于**思路 B**，本特性即把它们抽象为通用 lib。

---

## 2. 外部方案逐项调研

### 2.1 openEuler gazelle（强参考：线程级选栈 + 内核栈共存）
- **URL（官方用户指南）**：https://docs.openeuler.org/zh/docs/24.03_LTS_SP2/server/network/gazelle/gazelle_user_guide.html
- **URL（源码 gitee）**：https://gitee.com/openeuler/gazelle ；GitHub 镜像：https://github.com/gitee2github/gazelle
- **可借鉴点**：
  - **线程级选栈**：`GAZELLE_THREAD_NAME` 环境变量——**仅指定名字的线程走用户态 LwIP 栈，其余线程走内核栈**（默认绑定进程内所有线程）。这是"粒度化选栈、双栈共存"的直接范例，与本特性"连接级选栈"同源。
  - **影子 fd（`listen_shadow`）**：单 listen 线程、多协议栈线程时用影子 fd 监听——对本特性"一个监听在多栈/多线程间分发"有参考价值。
  - **POSIX 接管**：LD_PRELOAD（`liblstack.so`）+ `GAZELLE_BIND_PROCNAME`，应用无需改码——与机制 B 的 LD_PRELOAD 范式一致。
  - **系统前提**：`rp_filter=1` 是"流量确实走用户态"的关键 sysctl，否则可能仍走内核——提示本特性需文档化选栈的系统前提。
- **局限/边界**：
  - gazelle 的 **`kni_switch`（rte_kni）与 ltran 模式在 24.03 LTS SP2 已"功能衰退、不再支持"**——再次印证**不应以 KNI 为方案基座**。
  - ARP/ICMP/IPv4/UDP/TCP 由 LwIP 用户态栈处理，最多 1500 TCP 连接（`tcp_conn_count`）。

### 2.2 F-Stack 官方（本特性的母体）
- **URL（GitHub）**：https://github.com/F-Stack/f-stack
- **URL（官网）**：http://f-stack.org/
- **URL（DeepWiki，DPDK 集成）**：https://deepwiki.com/F-Stack/f-stack/2.2-dpdk-integration
- **URL（腾讯云：F-Stack 常用配置参数，含 [kni] 段）**：https://cloud.tencent.com/developer/article/1976948
- **可借鉴点**：F-Stack 提供 Posix API（Socket/Epoll/Kqueue），移植 FreeBSD 栈；nginx 适配层已内置 `kernel_network_stack`（连接级选栈）、syscall 适配层已内置 `FF_KERNEL_EVENT`（双栈 epoll）。本特性是把这两处"应用内嵌实现"提炼为**通用 lib**。

### 2.3 mTCP / 其他用户态栈
- **URL（mTCP）**：https://github.com/mtcp-stack/mtcp
- **可借鉴点**：mTCP 同样提供独立的 epoll 接口（`mtcp_epoll_*`），应用需显式选择 mTCP socket 还是内核 socket——印证"双 API/双 fd 命名空间"是用户态栈的通用范式，本特性需在接口层处理"fd 归属判定"。

### 2.4 DPDK 官方文档（边界澄清，非本特性方案）
- **URL（DPDK KNI，已弃用/移除）**：https://doc.dpdk.org/guides/prog_guide/kernel_nic_interface.html
- **URL（virtio_user 作为 exception path）**：https://doc.dpdk.org/guides/howto/virtio_user_as_exception_path.html
- **说明**：这些是"报文回灌内核"（思路 A），**与本特性无关**；列出仅为澄清"为什么不选 KNI"：`rte_kni` 已在 DPDK 23.11 移除，且它解决的是裸报文旁路，而非"应用在内核侧暴露服务"。

---

## 3. 调研结论（对本特性的指导）

1. **方向正确性**：业界主流（gazelle 线程级选栈、mTCP 双 API、F-Stack 自身两处实现）都走"**连接/线程级选栈 + 双栈事件**"路线；KNI 在 DPDK 与 gazelle 均已衰退/移除——**本特性聚焦连接级选栈是正确选择**。
2. **可借鉴范式**：
   - 选栈粒度可下沉到连接/监听/线程（gazelle 线程级、nginx 连接级 `belong_to_host`）。
   - 双栈需要统一事件循环 + fd 归属判定（F-Stack `is_fstack_fd` / `fstack_kernel_fd_map`、mTCP 双 epoll）。
   - 需明确系统前提（如 gazelle 的 `rp_filter=1`）与连接上限等约束。
3. **本特性独特价值**：把 F-Stack 现有的"nginx 内嵌选栈 + syscall 内嵌双栈 epoll"抽象为**应用无关的通用 lib**，降低任意 F-Stack 应用获得"本机直访"能力的门槛。

> 交叉验证说明：本文外部信息均标注来源 URL；与 F-Stack 实际代码冲突时以代码为准（见 `02-current-state-analysis.md`）。
