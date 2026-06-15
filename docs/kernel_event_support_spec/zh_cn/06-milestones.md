# 06 里程碑与编码工作清单

> **文档编号**：SPEC-KE-06
> **版本**：v2（全量重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：连接级选栈增强 lib 的实施路线图（后续实现阶段，非本阶段交付）。

---

## 0. 里程碑总览

| 里程碑 | 名称 | 目标 | 依赖 | 主要验收 |
|---|---|---|---|---|
| **M0** | spec 文档（**本阶段**） | 中文 spec 全集过门禁 | — | `08-review-gate.md` 全 PASS |
| **M1** | 内核栈侧监听（最小可用） | `ff_local_socket`/`ff_local_listen_on_host` 让本机 `curl` 通 | M0 | FR-1、FR-2 |
| **M2** | 双栈统一事件循环 | `ff_local_epoll_*` 单循环服务两栈 | M1 | FR-4、FR-5 |
| **M3** | 选栈与资源联动 | 监听/连接级 `belong_to_host` + close 联动 | M2 | FR-3、FR-6 |
| **M4** | 统一 lib 形态 | 独立 `libff_local`（`FF_LOCAL_STACK` 开关）+ 头文件 + 示例 | M3 | FR-7、可独立链接 |
| **M5** | 测试与性能基线 | 单测/集成/性能基线达标 | M1-M4 | `07-test-spec.md` 门禁 |

> 注：M1 即满足"本机直访 F-Stack 服务"的核心诉求（连接级选栈，**不涉及 KNI**）。

---

## 1. M1 内核栈侧监听（最小可用）

**编码工作清单**：
1. 新增 `lib/ff_local.{h,c}` 骨架，定义 `ff_local_socket(domain,type,proto,belong_to_host)`：`belong_to_host=1` 走原生 `socket`，`=0` 走 `ff_socket`（对照机制 A `app/nginx-1.28.0/src/event/ngx_event_connect.c:46-50`）。
2. 实现 `ff_local_listen_on_host`：在内核栈侧 `bind+listen`，使本机 `curl`/`ssh` 可达。
3. 验证 ICMP：内核栈侧地址 `ping` 通（内核原生处理）。
4. `lib/Makefile` 增加 `FF_LOCAL_STACK` 条件编译单元。

**验收**：本机 `curl <host_ip:port>` 成功、`ping <host_ip>` 通；F-Stack 业务无回归。

## 2. M2 双栈统一事件循环

**编码工作清单**：
1. 实现 `ff_local_epoll_create`：内部同时建内核 epoll，维护"统一 epoll fd → 内核 epoll fd"映射（类比 `adapter/syscall/ff_hook_syscall.c:257-258` `fstack_kernel_fd_map`）。
2. 实现 `ff_local_epoll_ctl`：按 fd 归属路由（对照 `ff_hook_syscall.c:2016-2023`）。
3. 实现 `ff_local_epoll_wait`：先取内核事件（`timeout=0`，可节流，对照 `:2329-2338`）再合并 F-Stack 事件；强制 `maxevents>=2`（对照 `:2212-2218`）。
4. F-Stack 侧事件用 `ff_kqueue`/`ff_kevent`（`lib/ff_api.h:138,139`）适配为 epoll 风格。

**验收**：单事件循环同时正确收发内核 fd 与 F-Stack fd 事件。

## 3. M3 选栈与资源联动

**编码工作清单**：
1. 实现 `ff_local_fd_owner`（归属判定，借鉴 `is_fstack_fd` `ff_hook_syscall.c:309`）。
2. `read/write/close` 按归属自动分流；`close` 联动释放两栈 fd（对照 `:1874-1883`），杜绝泄漏。
3. 监听/连接级 `belong_to_host` 语义与缺省策略（`ff_local_cfg.default_belong_to_host`）。

**验收**：两栈 fd 混用无错；无 fd 泄漏（FR-6）。

## 4. M4 统一 lib 形态

**编码工作清单**：
1. 固化 `libff_local`（独立编译/链接单元，`FF_LOCAL_STACK` 默认关闭→零开销，对照机制 B `Makefile -DFF_KERNEL_EVENT`）。
2. 整理对外头文件（`lib/ff_local.h` 或并入 `ff_api.h`，见 `05` 待决）。
3. 示例程序（参照 `adapter/syscall/helloworld_stack*` 与 `tests/` 风格）：一个进程内同时跑 F-Stack 业务监听 + 内核栈管理监听。
4.（可选）LD_PRELOAD 透明接管层调研，复用机制 B 的 hook 范式。

**验收**：独立链接 `libff_local`，示例跑通；关闭开关时纯 F-Stack 行为零回归。

## 5. M5 测试与性能基线
见 `07-test-spec.md`。

---

## 6. 风险与回退
- 事件合并引入延迟：用机制 B 的"节流取内核事件"（`ff_hook_syscall.c:2333-2336`）控制。
- 事件模型差异（kqueue vs epoll）：在 lib 接口层抹平，单元测试覆盖。
- **严禁引入 KNI/`rte_kni`**（DPDK 23.11 已移除）作为回退路径。
- 改动集中在新增 `ff_local.{h,c}`，避免触碰报文快路径热点。

## 7. 与工作区脚本规约
实现阶段清理临时文件用 `/data/workspace/rm_tmp_file.sh`、停进程用 `/data/workspace/kill_process.sh`、改权限用 `/data/workspace/chmod_modify.sh`；`make install` 类（非直接 chmod）命令可执行。
