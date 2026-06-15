# 06 里程碑与编码工作清单

> **文档编号**：SPEC-KE-06
> **版本**：v3（范式修正重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：本特性实施路线图（后续实现阶段，非本阶段交付）。本阶段仅 spec。

---

## 0. 里程碑总览

| 里程碑 | 名称 | 目标 | 依赖 | 主要验收 |
|---|---|---|---|---|
| **M0** | spec 文档（**本阶段**） | 中文 spec 全集过门禁 | — | `08-review-gate.md` 全 PASS |
| **M1** | 标记标准化 + 服务端内核栈监听 | 标准化 `SOCK_KERNEL`/`SOCK_FSTACK`，hook 模式带标记监听让本机 `curl`/`ping` 通 | M0 | FR-1/FR-2 |
| **M2** | 客户端选栈 connect | hook 模式经内核栈 `connect` 本机/外部内核服务 | M1 | FR-3/FR-4 |
| **M3** | config.ini 全局默认开关 | 新增 `[stack] default_stack`，进程默认栈 + 标记覆盖 | M1 | FR-5/NFR-6 |
| **M4** | 原生 `ff_api` 模式标记识别 | `ff_socket` 识别 `SOCK_KERNEL`，双模式对齐 | M1-M3 | FR-6 |
| **M5** | 双栈统一事件 + 资源联动 | 单循环服务两栈、close 联动、可观测 | M1-M4 | FR-7/FR-8/NFR-4 |
| **M6** | 测试与性能基线 | 单测/集成/性能基线达标 | M1-M5 | `07-test-spec.md` 门禁 |

> 注：M1+M2 即满足"本机直访 F-Stack 主机服务"与"F-Stack 应用作客户端连本机/外部内核服务"两大核心诉求，**不涉及 KNI、不新增 API**。

---

## 1. M1 标记标准化 + 服务端内核栈监听

**编码工作清单**：
1. 将 `SOCK_KERNEL`/`SOCK_FSTACK`（`adapter/syscall/ff_adapter.h:7-8`）提升为**对外可依赖约定**（对外头文件暴露 + 文档化语义/优先级，对照 `ff_hook_socket:387-390`）。
2. 复核/固化 hook 模式选栈：`socket(type|SOCK_KERNEL)` → `ff_linux_socket`；`bind/listen/accept` 经 `CHECK_FD_OWNERSHIP:57-61` 自动落内核栈。
3. 验证 ICMP：内核栈侧地址 `ping` 通（内核原生处理）。

**验收**：`curl <内核栈监听 IP:port>` 成功、`ping <内核栈 IP>` 通；默认/F-Stack 业务无回归。

## 2. M2 客户端选栈 connect（新增核心）

**编码工作清单**：
1. 复核/固化 `ff_hook_connect:858` 按 fd 归属路由：内核 fd → `ff_linux_connect:144`。
2. 文档化并验证客户端用法：`socket(SOCK_KERNEL) + connect(127.0.0.1 / 本机内核栈 IP)` 与 `connect(<外部内核栈服务>)`。
3. 覆盖 TCP/UDP 客户端；确认 `send/recv/close` 按归属自动分流。

**验收**：本机起 server（内核栈），F-Stack client `connect` 通（FR-3）；连外部内核栈服务 `connect` 通（FR-4）。

## 3. M3 config.ini 全局默认开关

**编码工作清单**：
1. `lib/ff_config.h:253` `struct ff_config` 新增 `struct { int default_to_kernel; } stack;`。
2. `lib/ff_config.c:956` `ini_parse_handler` 增 `MATCH("stack","default_stack")` 分支（仿 `MATCH("kni","enable")` :1011），解析 `fstack|kernel`。
3. 默认值（`:1358+`）`default_to_kernel=0`；如有字符串字段在 `:1647+` 释放（本项为 int，无需）。
4. 胶水层：app 未带标记时按 `ff_global_cfg.stack.default_to_kernel` 注入等价 `SOCK_KERNEL`（保证 app 标记优先）。
5. config.ini 增 `[stack] default_stack=fstack` 示例段。

**验收**：改 config 默认栈生效；app 标记覆盖生效；多进程用不同 config 文件得不同默认栈（NFR-6）。

## 4. M4 原生 `ff_api` 模式标记识别

**编码工作清单**：
1. 在 `lib/ff_syscall_wrapper.c:912` `ff_socket` 入口仿 `ff_hook_socket:387-390` 增 `SOCK_KERNEL` 识别分支（`02 §5`/D4：现状恒建 F-Stack socket）。
2. 保证 `linux2freebsd_socket_flags:668` 路径对默认/`SOCK_FSTACK` 行为不变（零开销）。
3. 原生模式客户端/服务端选栈与 hook 模式语义对齐。

**验收**：原生模式可用标记选栈；默认路径逐字节无回归（FR-6/NFR-1）。

## 5. M5 双栈统一事件 + 资源联动

**编码工作清单**：
1. 复用 `fstack_kernel_fd_map:257-258` + epoll 双栈：create 镜像（`:1996-1998`）、ctl 路由（`:2016-2023`）、wait 合并（`:2324+`，`timeout=0`+节流）、`maxevents>=2`（`:2212-2218`）。
2. `close` 联动释放两栈 fd（`:1874-1883`）；`is_fstack_fd:309` 归属判定。
3. 可观测：两栈 fd 数/事件数统计（`ff_stack_get_stats` 草案，`05 §6`）。

**验收**：单事件循环正确收发两栈事件；无 fd 泄漏（FR-7/FR-8/NFR-4）。

## 6. M6 测试与性能基线
见 `07-test-spec.md`。

---

## 7. 风险与回退
- 原生模式标记识别改动触及 `ff_socket` 热路径：用条件分支前置 + 默认零开销分支，单测覆盖（M4）。
- config 默认注入与 app 标记优先级混淆：用例 UT 明确覆盖（`07`）。
- 事件合并延迟：用机制 B 的"节流取内核事件"（`:2324+`）控制。
- **严禁引入 KNI/`rte_kni`**（DPDK 23.11 已移除）作为回退路径。
- 改动集中在标记约定/`ff_config`/`ff_socket` 入口/客户端文档化，避免触碰报文快路径热点。

## 8. 与工作区脚本规约
实现阶段清理临时文件用 `/data/workspace/rm_tmp_file.sh`、停进程用 `/data/workspace/kill_process.sh`、改权限用 `/data/workspace/chmod_modify.sh`；`make install` 类（非直接 chmod）命令可执行。
