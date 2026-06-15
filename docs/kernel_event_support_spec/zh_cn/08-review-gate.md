# 08 审核门禁报告

> **文档编号**：SPEC-KE-08
> **版本**：v2（全量重做）
> **日期**：2026-06-15
> **状态**：PASS
> **作用域**：对 v2 中文 spec 全集做"与实际代码一致性 / 范围正确性 / 可行性"门禁核验。

---

## 1. 门禁方式

- 团队派出 `gatekeeper`（code-explorer 只读）异步核验；**Leader 同步对全部关键 `文件:行号` 断言逐条实测**（grep/read），两者交叉验证，冲突以**实际代码为准**。
- bounce 规约：任一项 FAIL → 打回上一步修复，同一步骤 ≤3 次，超限转人工。

---

## 2. 核验结果（Leader 实测，全部 PASS）

### 机制 A（nginx kernel_network_stack，连接级选栈）
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| A1 | 指令注册 297-304 | PASS | `ngx_http_core_module.c:297-304`（`NGX_HTTP_MAIN_CONF\|NGX_HTTP_SRV_CONF\|NGX_CONF_FLAG`，offsetof `kernel_network_stack`） |
| A2 | create/merge 默认 | PASS | `:3492-3494` `NGX_CONF_UNSET`；`:3538-3542` merge 0 |
| A3 | 选栈核心 | PASS | `ngx_event_connect.c:46-50` `!belong_to_host? type\|SOCK_FSTACK : type` |
| A4 | 标志传播 | PASS | `ngx_http.c:1890` `ls->belong_to_host = cscf->kernel_network_stack` |
| A5 | 连接位字段 | PASS | `ngx_connection.h:93` `unsigned belong_to_host:1` |
| A6 | 事件位字段/双后端 | PASS | `ngx_event.h:140`、`:195` extern `ngx_ff_host_event_actions`、`:408-414` 分发、`:446` 处理宏 |
| A7 | 内核事件模块存在 | PASS | `src/event/modules/ngx_ff_host_event_module.c`（11.33 KB） |
| A8 | `SOCK_FSTACK` 定义 | PASS | `adapter/syscall/ff_adapter.h:7` `0x01000000` |

### 机制 B（FF_KERNEL_EVENT）
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| B1 | fd 归属宏 | PASS | `ff_hook_syscall.c:57-61` `CHECK_FD_OWNERSHIP` |
| B2 | 映射表 | PASS | `:257-258` `fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES=65536]` |
| B3 | `is_fstack_fd` | PASS | `:309` 定义（配套 convert/restore_fstack_fd） |
| B4 | 双栈 epoll | PASS | create `:1996-1998`、ctl `:2016-2023`、wait 合并 `:2324+/2395-2399`、`maxevents>=2` `:2212-2217` |
| B5 | close 联动 | PASS | `:1874-1883` |
| B6 | 编译开关/demo | PASS | `Makefile:54-55` `-DFF_KERNEL_EVENT`、`:156` `helloworld_stack_epoll_kernel`(`main_stack_epoll_kernel.c`) |
| B7 | 内核侧封装 | PASS | `ff_linux_syscall.c`：socket:81/bind:88/listen:96/accept:131/connect:144/close:217/epoll_create:233/epoll_ctl:239/epoll_wait:247 |
| B8 | 选栈标志 `SOCK_KERNEL` | PASS | `ff_adapter.h:8` `0x02000000`；`ff_hook_socket:383-390` 显式选内核、普通 socket 不双写 |

### ff_api.h / 范围
| 编号 | 断言 | 结果 | 证据 |
|---|---|---|---|
| D1 | API 行号 | PASS | `ff_api.h` socket:81/listen:89/bind:90/accept:91/connect:93/close:94/kqueue:138/kevent:139/route_ctl:191 |
| D2 | kqueue/kevent 模型 | PASS | `ff_api.h:138-139`（原生 kqueue/kevent） |
| S1 | 范围未以 KNI 为基座 | PASS | `02`/`04` 选型小节明确排除 KNI/virtio-user，仅作边界澄清 |

**通过：19/19。**

---

## 3. README vs 代码差异（以代码为准）

| 编号 | 描述 | 结论 |
|---|---|---|
| D3 | `ff_hook_syscall.c:2078-2081` 注释称"首版不支持 `ff_linux_epoll_wait`" | 与 `:2324+` 实际实现冲突：当前**已**调用 `ff_linux_epoll_wait`（带 timeout=0 + 节流）。以代码为准，已在 `02` 记录 |

---

## 4. Bounce 记录

| # | 触发 | 处置 | 复核 |
|---|---|---|---|
| **bounce #1** | 门禁发现 `02 §2.4` 对"普通 socket 是否内核双写"为 under-spec（带"待复核"） | 实测 `ff_hook_socket:383-390` + `ff_adapter.h:7-8`，改为确定结论并补入 **`SOCK_KERNEL` 连接级选栈标志**（同步补 `04 §3.2`） | PASS |

- bounce 次数：1（< 3 上限），**无需转人工**。
- 行号类 FAIL：0。

---

## 5. 总体门禁结论

**PASS**。v2 spec 全集与实际代码一致（19/19），范围已正确收敛为"连接级选栈增强"（机制 A/B 同构：per-socket type 标志选栈 + 内核栈侧独立事件后端），KNI/virtio-user 已彻底移出方案、仅作边界澄清。可进入本地提交。
