# 06 里程碑与编码工作清单

> **文档编号**：SPEC-KE-06
> **版本**：v4（共存范式返工重写）
> **日期**：2026-06-16
> **状态**：编写中
> **作用域**：本特性返工实施路线图。

---

## 0. 里程碑总览

| 里程碑 | 名称 | 目标 | 依赖 | 主要验收 |
|---|---|---|---|---|
| **R0** | 回退错误代码 | 回退 v3 绕开 F-Stack 的 `ff_host_socket`/`ff_socket` 旁路 | — | 编译+单测无回归（已完成 commit 0748eff94） |
| **R1** | spec 全面重写（**本阶段**） | 中英文 spec 改为「共存」范式 | R0 | `08-review-gate.md` PASS |
| **R2** | hook 模式共存固化 + 正确 demo | FF_KERNEL_EVENT 编译；同进程 F-Stack 业务 + SOCK_KERNEL 内核共存 demo | R1 | FR-1/FR-2/FR-6（hook） |
| **R3** | 原生 ff_api 统一事件共存 | lib 内 fd 归属 + 受管内核 fd + `ff_epoll_wait` 合并；config 共存开关 | R1 | FR-7/FR-9/NFR-1/NFR-3 |
| **R4** | 测试与性能基线 | 单测/集成（同进程双栈）/性能（F-Stack 快路径无回归） | R2,R3 | `07-test-spec.md` 门禁 |
| **R5** | 门禁 + 提交 | gatekeeper 核验 + 英文 spec 同步 + 英文简短 commit | R1-R4 | 全门禁 PASS |

> **共存铁律**：所有里程碑必须保证 F-Stack 用户态栈始终承担业务、绝不被旁路（NFR-3）。

---

## 1. R0 回退错误代码（已完成）
- `lib/ff_syscall_wrapper.c` `ff_socket`：回退 `SOCK_KERNEL→ff_host_socket` 旁路分支 → 干净 F-Stack 路径。
- `lib/ff_host_interface.{c,h}`：移除 `ff_host_socket`、`ff_default_stack_is_kernel` 声明及多余 include。
- 验收：lib 编译（`-Werror`）通过、`test_ff_config` 54/54 无回归。commit `0748eff94`。
- 遗留待 R3 处理：`ff_config` 的 `stack.default_to_kernel`/`ff_default_stack_is_kernel`（休眠），R3 改为 `kernel_coexist`。

## 2. R2 hook 模式共存固化 + 正确 demo
**编码工作清单**：
1. 以 `FF_KERNEL_EVENT=1` 编译 `adapter/syscall/libff_syscall.so`（需 `FF_PATH`/`PKG_CONFIG_PATH`）。
2. 复核固化共存链路：`ff_hook_socket:387-390`（SOCK_KERNEL→内核）、`ff_hook_connect:858`、epoll 合并 `:2324+`、close 联动 `:1874-1883`（只读复核，不改既有正确实现）。
3. 提供**正确的同进程双栈 demo**（对照 `main_stack_epoll_kernel.c`）：同一进程内既有 F-Stack 业务监听（默认 socket）又有 `SOCK_KERNEL` 内核监听，同一 epoll 收两栈事件；替换/废弃 v3 纯内核 `helloworld_stacksel`。
**验收**：demo 跑通——本机 `curl` 内核监听成功、F-Stack 业务监听经 NIC 正常；两栈事件同 epoll 投递（FR-1/FR-2/FR-6）。需 DPDK 运行时；不具备真实 NIC 时业务面按 skip+实测证据，内核侧 loopback 仍实测。

## 3. R3 原生 ff_api 统一事件共存（新设计，核心改造）
**编码工作清单**：
1. `lib/ff_config.{c,h}`：将 v3 `stack.default_to_kernel`/`default_stack` 改为 `stack.kernel_coexist`（`MATCH("stack","kernel_coexist")`，默认 0）；同步更新 `test_ff_config` 用例与 fixtures、`config.ini` 示例段；调用方直接读 `ff_global_cfg.stack.kernel_coexist`，不引入访问器。
2. `lib/ff_host_interface.{c,h}`：新增**受管内核侧桥**（宿主 `socket/bind/listen/accept/connect/close/epoll_create1/epoll_ctl/epoll_wait`），供 lib 调用建受管内核 fd（**非裸绕过**，由 lib 登记归属）。
3. lib 内 fd 归属机制：归属表/编码偏移区分受管内核 fd 与 F-Stack fd；`ff_socket(SOCK_KERNEL)`（启用共存时）建受管内核 fd 并登记；默认/`SOCK_FSTACK` 走原 `sys_socket`（逐字节零回归）。
4. `ff_bind/ff_listen/ff_accept/ff_connect/ff_close`：入口按归属路由（内核 fd → 受管宿主桥；F-Stack fd → 原路径）。
5. `lib/ff_epoll.c`：`ff_epoll_create` 兼建内核 epoll；`ff_epoll_ctl` 按归属分流；`ff_epoll_wait` 合并内核 epoll 事件（`timeout=0`+节流）+ `ff_kevent_do_each` F-Stack 事件；`ff_close` 联动。
6. 可观测：`ff_stack_get_stats` 草案。
**验收**：原生应用一进程双栈共存；默认/`SOCK_FSTACK` 逐字节零回归（NFR-1）；F-Stack 业务面始终在位（NFR-3）；config 共存开关生效（FR-9）。

## 4. R4 测试与性能基线
见 `07-test-spec.md`。要点：cmocka 单测（共存开关解析、fd 归属、受管内核 fd、事件合并边界、零回归）；集成（**同进程双栈**：F-Stack 业务 + 本机 curl/ping 内核监听 + 客户端 connect）；性能（共存开/关对 F-Stack 快路径无回归）；覆盖率达标。

## 5. R5 门禁 + 提交
- gatekeeper 只读核验全部断言/门禁条目；英文 spec（00-10）同步重写为 v4；英文简短 commit；不 push。

---

## 6. 风险与回退
- 原生统一事件共存触及 `ff_socket`/`ff_epoll.c` 热路径：默认/`SOCK_FSTACK` 走原路径，共存分支条件前置，单测覆盖零回归。
- **共存铁律**：任何阶段若发现内核栈替代/旁路了 F-Stack 业务面 → 立即打回（违背 NFR-3）。
- 严禁引入 KNI/`rte_kni`。
- 改动集中在标记/`ff_config` 开关/`ff_socket` 入口/`ff_epoll.c` 合并/受管桥/demo，避免触碰报文快路径热点。

## 7. 工作区脚本规约
清理临时文件 `/data/workspace/rm_tmp_file.sh`、停进程 `/data/workspace/kill_process.sh`、改权限 `/data/workspace/chmod_modify.sh`；`make install` 类（非直接 chmod）可执行。

## 8. 门禁回退
任一阶段失败打回上一步；同一步骤 bounce≤3 次，超限停止转人工；bounce 记入 `08`。
