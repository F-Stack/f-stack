# 需求与问题域规格（01-requirements-spec.md）

> **文档编号**：SPEC-KE-01
> **版本**：v0.1 草稿
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：F-Stack 本地 socket/fd/event 访问能力的需求边界

---

## 1. 问题域

### 1.1 根因
F-Stack 启动后，DPDK 通过 UIO/VFIO 将物理网卡从内核驱动解绑并独占（PMD 轮询），内核协议栈**不再能看到该网卡**。因此本机基于内核栈的工具——`ping`、`curl`、`ssh`、`ntpdate`、监控 agent 等——**无法经该网卡收发**，运维/管理面受阻。

### 1.2 现状（详见 `02-current-state-analysis.md`，以代码为准）
F-Stack 已存在三类"流量回内核"机制：
- **机制 A** nginx `kernel_network_stack`：仅服务 nginx，per-server/upstream 选栈，强耦合 nginx 源码。
- **机制 B** `FF_KERNEL_EVENT`：LD_PRELOAD 层，仅镜像 epoll 事件，不覆盖数据 socket。
- **机制 C** KNI（已迁移为 **virtio-user + vhost-net** exception path）：报文级分流、可运行时调控，**已能支撑本机 ping/curl**，但缺少面向通用应用的统一编程接口与易用封装。

### 1.3 缺口
机制 C 提供了数据面通路，但：
- 配置分散（`config.ini [kni]` + 运行时 `FF_KNICTL` IPC），无统一 lib API；
- 缺少面向"本地 socket/fd/event"的应用编程模型（应用难以显式声明"这条连接走内核栈"）；
- 缺少独立可复用的 lib 形态（当前能力散落在 `lib/ff_dpdk_if.c`、`lib/ff_dpdk_kni.c`、`adapter/syscall/`、nginx 补丁中）。

## 2. 目标

提供一个**lib 库**，使**任意本机应用**（不限 nginx）在 DPDK 接管网卡的前提下，仍可：
1. 通过内核协议栈完成本机/管理面网络操作（ping、本地 curl 等）；
2. 以统一、显式的接口声明某个 socket/fd/事件走"内核栈"或"F-Stack 用户态栈"；
3. 复用 F-Stack 既有 virtio-user exception path 数据面（机制 C），不重造轮子。

## 3. 范围

### 3.1 本阶段（spec 文档）
- **仅产出中文 spec 文档**，不写实现代码、不改源码。
- 交付：需求/现状/外部调研/架构/接口/里程碑/测试/门禁 共 9 篇（见 `plan.md`）。

### 3.2 后续实现阶段（本 spec 规划，非本阶段交付）
- 在 mechanism C 之上抽象统一 lib（暂名 `libff_local` / `ff_local_*`）。
- 提供编译开关与运行时控制对齐。
- 单测/集成/性能基线。

### 3.3 不在范围
- 不改变 F-Stack 业务快路径性能模型；
- 不引入新的自研内核模块（KNI 内核模块已被 DPDK 23.11 移除，禁止回退）；
- 本阶段不产出英文文档。

## 4. 功能性需求（FR）

| 编号 | 需求 | 验收线索 |
|---|---|---|
| FR-1 | 本机可经内核栈 `ping` F-Stack 主机网卡 IP | 启用方案后 `ping <nic_ip>` 通 |
| FR-2 | 本机可经内核栈 `curl` 本机/外部地址 | `curl` 成功，走 veth/virtio-user |
| FR-3 | 提供统一开关：全部走内核 / 全部走 F-Stack / 默认按规则 | 对齐 `FF_KNICTL_ACTION_*`（`lib/ff_msg.h:118-123`） |
| FR-4 | 支持按 tcp/udp 端口、协议（ICMP/ARP/OSPF）分流 | 对齐 `config.ini [kni] method/tcp_port/udp_port` |
| FR-5 | 提供运行时动态调整分流策略的接口 | 对齐 `handle_knictl_msg`（`lib/ff_dpdk_if.c:1960-1977`） |
| FR-6 | 提供本地 socket/fd/event 编程接口（供应用显式选栈） | 借鉴机制 A 的 1-bit 选栈与机制 B 的 fd 映射 |

## 5. 非功能性需求（NFR）

| 编号 | 需求 |
|---|---|
| NFR-1 | 关闭本能力时对业务快路径**零额外开销**（默认 KNI 关闭，见官方提示） |
| NFR-2 | 开启时分流检查开销可控、可限速（对齐 `console_packets_ratelimit`/`general_packets_ratelimit`/`kernel_packets_ratelimit`） |
| NFR-3 | 不依赖已移除的 `rte_kni`；仅用 upstream 能力（virtio-user/vhost-net） |
| NFR-4 | 与现有 `config.ini`、`FF_KNICTL` 语义兼容，不破坏既有部署 |
| NFR-5 | 多进程（primary/secondary）模型下行为明确 |

## 6. 边界与异常场景

- 内核 `vhost-net` 模块缺失 / 无权限 / hugepage 不足 → 明确报错路径。
- `method=accept` vs `reject` 语义边界（见 `config.ini:250-253`）。
- 单网卡场景：管理流量与业务流量共网卡时的端口规划。
- secondary 进程不创建 virtio_user 口（`lib/ff_dpdk_if.c:609-611` 仅 primary 翻倍端口）。

## 7. 成功标准

1. 文档层面：架构/接口/里程碑/测试方案完整、与代码交叉验证一致、外部方案附 URL，通过 `08-review-gate.md` 门禁。
2. （后续实现阶段）功能层面：FR-1~FR-6 可演示；NFR 满足；性能基线达标（详见 `07-test-spec.md`）。
