# 里程碑拆解与编码工作清单（06-milestones.md）

> **文档编号**：SPEC-KE-06
> **版本**：v0.1 草稿
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：本地 socket/fd/event 访问 lib 的实施里程碑（后续实现阶段路线图，非本阶段交付）

---

## 0. 里程碑总览

| 里程碑 | 名称 | 目标 | 依赖 | 主要验收 |
|---|---|---|---|---|
| **M0** | spec 文档（**本阶段**） | 完成中文 spec 全集并过门禁 | — | `08-review-gate.md` 全 PASS |
| **M1** | 数据面打通（最小可用） | 启用 virtio-user 后本机 `ping`/`curl` 通 | M0 | FR-1、FR-2 |
| **M2** | 策略与运行时控制封装 | `ff_local_*` 封装 method/端口/action | M1 | FR-3、FR-4、FR-5 |
| **M3** | 统一 lib 形态 | 独立 `libff_local`（`FF_LOCAL` 开关）+ 头文件 | M2 | 可独立链接、示例程序 |
| **M4** | 连接级选栈增强（可选） | `ff_local_socket`/`ff_local_epoll_*` | M3 | FR-6、双栈事件合并 |
| **M5** | 测试与性能基线 | 单测/集成/性能基线达标 | M1-M4 | `07-test-spec.md` 门禁 |

> M1 即可满足"DPDK 接管网卡后本机 ping/curl"的核心诉求（复用机制 C），M4 为通用编程接口增强。

## 1. M1 数据面打通（最小可用）

**编码工作清单**：
1. 梳理并验证 `config.ini [kni] enable=1, method=reject, tcp_port/udp_port` 路径（`lib/ff_config.c` 解析 → `lib/ff_dpdk_if.c:1393-1398` 初始化）。
2. 验证 virtio-user vdev 创建（`lib/ff_dpdk_kni.c:458-466`）在 DPDK 23.11.5/24.11.6 下可用，确认 `/dev/vhost-net` 依赖与 `vethX` 生成。
3. 验证报文级分流（`lib/ff_dpdk_if.c:1779-1801`）对 ICMP/未知端口正确送内核。
4. 文档化启用步骤（依赖内核模块 `vhost_net`、权限、hugepage）。

**验收**：`ping <nic_ip>` 通、`curl` 成功；业务快路径无回归。

## 2. M2 策略与运行时控制封装

**编码工作清单**：
1. 暴露 `knictl_action`/`kni_accept` 的 getter/setter（当前为 `static`，`lib/ff_dpdk_if.c:75-76`）。
2. 封装 `FF_KNICTL` IPC（`lib/ff_msg.h:112-127`、`handle_knictl_msg` `:1960-1977`）为 `ff_local_set_action/get_action`。
3. 端口规则动态更新接口 `ff_local_rule_set`（对齐 `tcp_port_bitmap`/`udp_port_bitmap`，`ff_dpdk_kni.c:68-69`）。

**验收**：运行时 `ALL_TO_KNI/ALL_TO_FF/DEFAULT` 切换生效、端口规则热更新。

## 3. M3 统一 lib 形态

**编码工作清单**：
1. 新增 `lib/ff_local.{h,c}`，`FF_LOCAL` 编译开关（依赖 `FF_KNI`），更新 `lib/Makefile`。
2. 实现 `ff_local_init/cleanup/get_stats`（封装 `kni_interface_stats`，`ff_dpdk_kni.c:72-90`）。
3. 提供示例程序（参照 `adapter/syscall/helloworld_stack*` 与 `tests/` 风格）。

**验收**：独立链接 `libff_local`，示例跑通。

## 4. M4 连接级选栈增强（可选）

**编码工作清单**：
1. `ff_local_socket`（显式内核 socket，类比 `ngx_socket` 不带 `SOCK_FSTACK`，`src/event/ngx_event_connect.c:41-53`）。
2. `ff_local_epoll_*`：引入 `local_fd_map`（类比 `fstack_kernel_fd_map`，`ff_hook_syscall.c:255-258`），实现双栈事件合并（参照 `:2324-2399`）。
3. 处理 `maxevents>=2`、fd 关闭联动（参照 `:1874-1880`、`:2212-2218`）。

**验收**：单事件循环同时服务内核 fd 与 fstack 事件。

## 5. 风险与回退

- virtio-user 依赖内核 `vhost-net`：缺失时回退到禁用本能力（不影响业务）。
- 严禁回退 `rte_kni`（DPDK 23.11 已移除）。
- 改动集中在 KNI/接口暴露，避免触碰报文快路径热点。

## 6. 与工作区脚本规约
实现阶段如需清理临时文件用 `/data/workspace/rm_tmp_file.sh`、停进程用 `/data/workspace/kill_process.sh`、改权限用 `/data/workspace/chmod_modify.sh`；`make install` 类命令可直接执行。
