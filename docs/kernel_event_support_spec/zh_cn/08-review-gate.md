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

## 4. R2-R5 实现门禁（实测）

> 结论均来自实际编译/运行；证据可复现。提交链：0748eff94(R0)→32d6f8837(R1)→7b6bcca2f(R3.1)→74f365a62(R3.2/3.3)→7b38bca62(R3.4)→4b29dd8dc(R4)→c806af9bf(test fix)。

### I.1 代码改动核验（全部 PASS）
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| I1 | config 共存开关（R3.1） | PASS | `ff_config.h` `struct{int kernel_coexist;}stack;`；`ff_config.c` `MATCH("stack","kernel_coexist")`(1/on/true/yes→1)、默认 0、`ff_kernel_coexist_enabled()` |
| I2 | FD 空间方案（零冲突） | PASS | `ff_host_interface.h` `FF_KERNEL_FD_BASE 0x40000000`、`ff_is_kernel_fd/encode/real`（远超 FreeBSD fd≤65536，宿主 fd 受 RLIMIT 限） |
| I3 | 宿主桥（受管内核 fd，非裸绕过） | PASS | `ff_host_interface.c` `ff_host_socket/bind/listen/accept/accept4/connect/close/read/write/recv/send/sendto/recvfrom/setsockopt/getsockopt/fcntl/epoll_create1/ctl/wait`；`_GNU_SOURCE` for accept4/epoll_create1 |
| I4 | socket 侧归属路由（R3.2/3.3） | PASS | `ff_syscall_wrapper.c` `ff_socket`(SOCK_KERNEL+coexist→受管内核 fd) 及 close/read/write/sendto/recvfrom/accept/accept4/listen/bind/connect/setsockopt/getsockopt/fcntl 入口 `ff_is_kernel_fd` 路由 |
| I5 | 统一事件合并（R3.4） | PASS | `ff_epoll.c` epfd↔宿主 epoll 配对表、`ff_epoll_ctl` 内核 fd 路由、`ff_epoll_wait` 合并 kqueue⊕宿主 epoll；无内核 fd 时退化原行为 |
| I6 | NFR-1 零回归 | PASS | 默认/`SOCK_FSTACK` 路径逐字节未改（仅在各函数入口前置 `ff_is_kernel_fd` 分支） |
| I7 | NFR-3 F-Stack 在位 | PASS | 内核 fd 为附加旁路；业务默认仍走 F-Stack；无整进程默认内核语义 |

### I.2 编译与单测（硬门禁 PASS）
- **lib 编译**：`cd lib && make` 在 `-Werror` 下重链 `libfstack.a` 通过（ff_config/ff_host_interface/ff_syscall_wrapper/ff_epoll 四文件改动）。
- **cmocka 单测全绿**：test_ff_config 54/54、test_ff_host_interface 24/24、test_ff_epoll 21/21、test_ff_init 6、test_ff_log 13、test_ff_ini_parser 25——**0 失败**。
- 预存基线 `test_ff_dpdk_if` 缺 `ff_tcp_hpts_softclock`（与本特性无关），硬门禁不依赖。

### I.3 集成实测（共存 selftest，免 EAL）
| 用例 | 命令 | 结果 |
|---|---|---|
| 原生受管内核 fd loopback server+client | `example/helloworld_stacksel` selftest | `COEXIST SELFTEST PASS: native ff_socket(SOCK_KERNEL) kernel-stack server+client over loopback` |

> 经 `ff_socket(SOCK_KERNEL)`→受管内核 fd→bind/listen/accept + 客户端 connect/send/recv/close 全链路实跑通过，验证 socket 侧共存与 fd 归属路由。

### I.4 Skip（环境无物理 NIC）
- 完整「F-Stack 业务面 + SOCK_KERNEL 内核监听 + ff_epoll 合并」端到端共存需 `ff_init`/`ff_run` + DPDK 数据面（NIC/大页），本沙箱无物理 NIC → 按 Q1 skip，待真机按 `07` 集成方案补跑。socket 侧与 config/单测/零回归已硬门禁全绿。

### I.5 Bounce 记录
| # | 触发 | 处置 | 复核 |
|---|---|---|---|
| 自纠 | ff_host_interface.c 缺 `<unistd.h>`/`_GNU_SOURCE` | 同步补 include | 编译通过 |
| 自纠 | socklen_t 跨命名空间未定义 | 头声明改 `unsigned int`（同型兼容） | 编译通过 |
| 自纠 | test_ff_epoll 链接缺 ff_host_epoll_* | test 内加 no-op 桩 | 21/21 PASS |
- bounce：0 跨步骤打回（均同步骤即时自纠，< 3 上限）。

### I.6 实现阶段结论
**PASS（硬门禁）**：编译 + cmocka 单测全绿 + socket 侧共存 selftest 实跑 + 零回归。原生 ff_api 双栈共存（socket 侧 + ff_epoll 合并）已落地；F-Stack 业务面端到端共存待真机补跑（skip+说明）。

---

## 5. Bounce 记录

| # | 触发 | 处置 | 复核 |
|---|---|---|---|
| — | R1 spec 重写按共存范式一致，未触发 FAIL | — | — |

- bounce：0（< 3 上限）。

## 6. 当前结论
**R1 spec 门禁 PASS**（共存范式正确、删除 v3 旁路/默认内核错误表述、代码锚点一致）。R2-R5 实现门禁随后补充。
