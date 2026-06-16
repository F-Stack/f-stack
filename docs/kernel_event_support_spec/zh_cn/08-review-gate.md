# 08 审核门禁报告

> **文档编号**：SPEC-KE-08
> **版本**：v4（共存范式返工重写）
> **日期**：2026-06-16
> **状态**：进行中（R1 spec 门禁；R2-R5 实现门禁待补）
> **作用域**：对 v4 spec 与实现做「与实际代码一致性 / 共存范式正确性 / 零回归」门禁核验。

---

## 1. 门禁方式
- gatekeeper（code-explorer 只读）异步核验 + Leader 同步对关键 `文件:行号` 断言逐条实测；冲突以**实际代码为准**。
- bounce 规约：任一项 FAIL → 打回上一步，同一步骤 ≤3 次，超限转人工。

## 2. 共存范式正确性断言（R1 spec 门禁）

| 编号 | 断言 | 证据 |
|---|---|---|
| P1 | spec 不再有「ff_socket→纯内核旁路」「整进程默认内核」表述 | 00/01/02/04/05/06 已删 `ff_host_socket`/`default_stack=kernel` |
| P2 | 范式=应用 on F-Stack + per-fd `SOCK_KERNEL` 附加内核旁路 + 统一事件共存 | 00 §1/01 §1/04 §1 |
| P3 | hook FF_KERNEL_EVENT 为主基线（共存已实现） | 02 §2、`README.md:169-186`、`ff_hook_socket:387-390`/`fstack_kernel_fd_map:257-258` |
| P4 | nginx kernel_network_stack 为同构参考 | 02 §3、`ngx_http_core_module.c:298-303`/双后端 `ngx_ff_host_event_module.c:441` |
| P5 | 原生模式共存为新设计（事件层缺口如实记录） | 02 §4、`ff_epoll.c:25-28/103/157`（纯 kqueue 封装） |
| P6 | config 改为共存能力开关（删整进程默认内核） | 05 §3、06 R3 |
| P7 | 共存铁律 NFR-3（F-Stack 始终在位）贯穿 | 01 §4、04 §1、06 §6 |

## 3. R0 回退核验（已完成）

| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| RV1 | `ff_socket` 旁路分支已回退 | PASS | `lib/ff_syscall_wrapper.c` ff_socket 复原为 sa.domain/linux2freebsd_socket_flags/sys_socket 路径 |
| RV2 | `ff_host_socket` 已移除 | PASS | `lib/ff_host_interface.c`/`.h` 无 `ff_host_socket` |
| RV3 | 编译/单测无回归 | PASS | lib `-Werror` 重链通过；`test_ff_config` 54/54 |
| RV4 | commit | PASS | `0748eff94 revert(stack-select): drop ff_host_socket bypass...` |

## 4. R2-R5 实现门禁（待补）
- R2 hook 共存固化 + 正确 demo；R3 原生统一事件共存（含 config `kernel_coexist` 改造）；R4 测试/性能；R5 英文 spec 同步 + 提交。每阶段实测填表，bounce 记录于本节。

## 5. Bounce 记录

| # | 触发 | 处置 | 复核 |
|---|---|---|---|
| — | R1 spec 重写按共存范式一致，未触发 FAIL | — | — |

- bounce：0（< 3 上限）。

## 6. 当前结论
**R1 spec 门禁 PASS**（共存范式正确、删除 v3 旁路/默认内核错误表述、代码锚点一致）。R2-R5 实现门禁随后补充。
