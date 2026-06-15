# 外部方案调研：DPDK 程序的"流量回内核"架构（03-external-research.md）

> **文档编号**：SPEC-KE-03
> **版本**：v0.1 草稿
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：业界 DPDK 程序实现"本机/异常流量回内核协议栈"的主流架构调研，附**可访问 URL**
> **调研方法**：联网检索 + 与 F-Stack 实际代码（见 `02-current-state-analysis.md`）交叉印证

---

## 0. 背景：什么是 exception path

DPDK 旁路内核做高速转发，但**部分"异常"包**（发给本机的控制/管理报文、ICMP/ping、ssh、ARP/OSPF 等）不需要转发，需交回内核协议栈处理——把这类包从 DPDK 送回内核的路径，业界称为 **exception path（异常路径）**。这正是"DPDK 接管网卡后本机仍可 ping/curl"所依赖的能力。主流实现有 4 类：**TAP/TUN、KNI、virtio-user + vhost-net、AF_XDP/af_packet 旁路**。

参考综述：
- DPDK 官方 How-to：《Virtio_user as Exception Path》— https://doc.dpdk.org/guides/howto/virtio_user_as_exception_path.html （**F-Stack 代码 `lib/ff_dpdk_kni.c:450-452` 注释直接引用此文档**）
- 《把报文再扔回内核，DPDK 这样做》（TAP/TUN、KNI、virtio-user 三法对比）— https://blog.csdn.net/lingshengxiyou/article/details/128025223
- 《DPDK 程序 exception path 的实现方案》— https://blog.51cto.com/u_15911260/5934813
- 《DPDK Exception path 方案：Virtio-user》— https://gy23333.github.io/2025/04/25/DPDK-Exception-path-%E6%96%B9%E6%A1%88%EF%BC%9AVirtio-user/

---

## 1. 四类主流方案对比

| 方案 | 原理 | 优点 | 缺点 | 内核侧呈现 |
|---|---|---|---|---|
| **TAP/TUN** | DPDK 通过 `net_tap` PMD 或直接 open `/dev/net/tun` 创建 tap 设备，包以 syscall read/write 在用户态↔内核间搬运 | 实现简单、依赖少 | 每包一次 syscall，性能低；二层 tap/三层 tun 语义不同 | 一个 `tapX` 网卡 |
| **KNI（旧）** | `rte_kni` 内核模块 + 用户态 `rte_kni` 库，零拷贝 FIFO 在 DPDK 与内核间传包 | 性能较 tap 好、内核见到真实网卡 | **内核模块非 upstream、维护差**，DPDK **23.11 已移除 KNI 库与驱动** | 一个 `vEthX` 网卡 |
| **virtio-user + vhost-net** | DPDK 侧建 `virtio_user` vdev，后端接内核 `vhost-net`（`/dev/vhost-net`），自动生成内核 `veth`/tap 口 | 纯 upstream、无自研内核模块、性能优于 tap、是 KNI 的官方替代 | 需 `vhost-net` 模块、配置略复杂 | 一个 `vethX`/tap 口 |
| **AF_XDP / af_packet** | 用 XDP/af_packet socket 在内核 fast path 旁挂，部分场景做 slowpath | 内核原生、无额外设备 | 与"DPDK 完全接管网卡"模型不完全契合 | socket 级 |

**关键时间线（影响选型）**：
- DPDK 23.03 起 KNI 默认禁用（需从 `disable_libs` 移除才编译）— https://doc.dpdk.org/guides-23.03/prog_guide/kernel_nic_interface.html
- KNI 在 **DPDK 23.11 被移除**；社区推荐迁移到 **virtio-user / af_packet** — DPDK deprecation 说明：https://github.com/napatech/dpdk/blob/master/doc/guides/rel_notes/deprecation.rst ；NXP 社区《An alternative to DPDK KNI》：https://community.nxp.com/t5/Layerscape/An-alternative-to-DPDK-KNI/m-p/1950037
- 本工作区 DPDK 版本为 **23.11.5 / 24.11.6**（均已无 KNI），故 **virtio-user 是唯一可行的 exception path**——这与 F-Stack 实际代码已迁移到 virtio-user（`02` 文档机制 C / 差异 D1）完全吻合。

---

## 2. virtio-user as exception path（重点，F-Stack 现采用）

DPDK 官方方案（https://doc.dpdk.org/guides/howto/virtio_user_as_exception_path.html ）：
- DPDK 应用创建 `virtio_user` vdev（`--vdev=virtio_user0,path=/dev/vhost-net,queues=...,iface=tapX,mac=...`），后端为内核 `vhost-net`。
- 内核侧自动出现一个 `tap/veth` 网卡；DPDK 把要交内核的包 `tx_burst` 到 virtio_user 口，内核协议栈即可收到；反向同理。
- F-Stack 实现一致：`lib/ff_dpdk_kni.c:458-466` 用 `rte_eal_hotplug_add("vdev","virtio_user%u","path=/dev/vhost-net,...,iface=veth%d,...")`，并以 `kni_process_tx/rx`（`:136-184`）做双向 burst。

补充资料：
- 《DPDK-22.11.2 Virtio_user as Exception Path》— https://jishuzhan.net/article/1712020078922305537
- 《DPDK 之 Virtio-user 介绍》（知乎）— https://zhuanlan.zhihu.com/p/10680616770
- 《DPDK virtio-user 介绍及使用》— http://blog.chinaunix.net/uid-28541347-id-5856225.html
- 《告别 KNI？用 DPDK Virtio-user + vfio-pci 构建用户态到内核协议栈高性能通道》— https://wenku.csdn.net/column/n49dtiv2333

**对本特性可借鉴点**：F-Stack 已落地此路径，本特性 lib 应直接复用 `ff_kni_*` 数据面，无需重造 exception path。

---

## 3. F-Stack 自身 KNI 文档（官方配置与语义）

- 腾讯云《F-Stack KNI 配置注意事项》— https://cloud.tencent.com/developer/article/1005182 ；https://cloud.tencent.com/developer/news/11042
  - 要点：KNI 默认关闭（开启会对所有收包做转发策略检查，影响性能）；`config.ini` 配置 `enable`、`method`、`tcp_port`/`udp_port`；适用于"网卡全部被 F-Stack 接管"或"单网卡"场景需本机访问时。
  - 与实际代码印证：`config.ini:250-267`、`lib/ff_dpdk_if.c:1779-1801` 的 reject/accept 分流逻辑一致。

---

## 4. 同类用户态协议栈的双栈/分流参考（架构借鉴）

### 4.1 openEuler Gazelle（lstack + ltran）
- 文档：https://docs.openeuler.org/zh/docs/23.09/docs/Gazelle/Gazelle.html ；仓库：https://github.com/openeuler-mirror/gazelle ；使用指南：https://github.com/gitee2github/gazelle/blob/master/doc/Gazelle%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97.md
- 架构：基于 DPDK + 轻量级 LwIP 用户态栈，通过 `LD_PRELOAD`（lstack）接管 POSIX 接口；提供 ko 提供"虚拟网口"与网卡绑定能力；亦面临 KNI 移除问题（Gazelle 的 DPDK 23.11 适配 PR 移除了 kni_switch 相关函数：https://gitee.com/openeuler/gazelle/pulls/624 ）。
- **可借鉴点**：`LD_PRELOAD` 统一 POSIX 接口 + 配置项分流（哪些走用户态栈），与本特性"统一 lib 接口"目标接近；其 DPDK 23.11 去 KNI 的工程经验可直接参考。

### 4.2 DPVS（爱奇艺 LB）
- KNI 弃用跟踪 issue：https://github.com/iqiyi/dpvs/issues/892 （DPVS 同样需在 23.11 后迁移 KNI 替代方案）。
- **可借鉴点**：作为大规模生产 DPDK 程序，其 KNI→替代方案迁移决策可作旁证。

---

## 5. 对本特性的结论与选型倾向（详见 04 架构设计）

1. **数据面**：直接复用 F-Stack 已有的 **virtio-user exception path（机制 C）**，不重造轮子；KNI 已被 DPDK 23.11 移除，virtio-user 是唯一正确路径。
2. **分流策略**：以 `config.ini [kni] method/tcp_port/udp_port` + 运行时 `FF_KNICTL`（`ALL_TO_KNI/ALL_TO_FF/DEFAULT`）为基础，向上抽象统一开关。
3. **编程接口**：借鉴机制 A（per-连接选栈 1-bit 标志 + 双事件后端）与机制 B（`fstack_kernel_fd_map` fd 映射 + 事件合并），为本特性 lib 提供"本地 socket/fd/event"统一 API，使非 nginx 应用也能透明使用本机内核栈。
4. **风险**：依赖内核 `vhost-net`/`veth`、需 hugepage/特权；性能受 KNI 转发策略检查影响（官方提示默认关闭）。

> 所有 URL 于 2026-06-15 检索可访问；引用的版本时间线（KNI 23.03 默认禁用、23.11 移除）与本工作区 DPDK 23.11.5/24.11.6 自洽。
