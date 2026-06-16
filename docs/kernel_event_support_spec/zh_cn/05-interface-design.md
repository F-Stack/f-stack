# 05 接口设计：标记选栈 + config 共存开关 + hook/原生双模式契约

> **文档编号**：SPEC-KE-05
> **版本**：v4（共存范式返工重写）
> **日期**：2026-06-16
> **状态**：编写中
> **作用域**：选栈标记约定、config 共存能力开关、服务端/客户端用法、hook 与原生双模式适配、数据结构与错误处理。
> **核心原则**：**不新造旁路 API、不新造绕开 F-Stack 的 socket**；复用单 API（hook POSIX + 原生 `ff_*`），靠 per-fd 标记 + config 共存开关，F-Stack 始终在位。
> **依据**：`02`（代码现状）、`04`（架构）。行号以代码为准，实现以 gatekeeper 复核为准。

---

## 1. 接口基线（全部复用，不重造）

| 类别 | 复用接口 | 来源 |
|---|---|---|
| hook 模式（LD_PRELOAD + FF_KERNEL_EVENT） | POSIX `socket/bind/listen/accept/connect/close/epoll_*`（`ff_hook_*` 接管） | `adapter/syscall/ff_hook_syscall.c` |
| 原生模式 | `ff_socket/ff_bind/ff_listen/ff_accept/ff_connect/ff_close/ff_kqueue/ff_kevent`、`ff_epoll_*` | `lib/ff_api.h`、`lib/ff_epoll.c` |
| 内核侧封装 | hook：`ff_linux_*`（`ff_linux_syscall.c`）；原生：经 `ff_host_interface` 受管桥（本轮新增） | `ff_linux_syscall.c` / `ff_host_interface.c` |

> 本特性**不增加新的 socket/epoll API**，只标准化「选栈标记」+「config 共存开关」两个约定，并补齐原生模式的受管内核 fd + 统一事件。

---

## 2. 选栈标记约定（per-fd，默认 F-Stack）

```c
/* 来源 adapter/syscall/ff_adapter.h:7-8，标准化为对外共存约定 */
#define SOCK_FSTACK 0x01000000   /* 该 socket 走 F-Stack 用户态栈（默认） */
#define SOCK_KERNEL 0x02000000   /* 该 socket 走宿主 Linux 内核栈（需启用共存） */
```
- 叠加在 `type` 高位，不与 glibc `SOCK_*` 冲突。
- 语义/优先级（实测 `ff_hook_socket:387`）：`(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)` → 内核；否则 → F-Stack。**`SOCK_FSTACK` 优先**。

### 用法（同进程双栈共存）
```c
/* 业务监听走 F-Stack（默认，无需标记） */
int biz = socket(AF_INET, SOCK_STREAM, 0);          /* 或 |SOCK_FSTACK */
bind(biz, ...); listen(biz, backlog);                /* 经 DPDK NIC 服务业务 */

/* 同进程内：内核栈监听（本机 curl/ssh 直访） */
int mgmt = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
bind(mgmt, ...); listen(mgmt, backlog);              /* 落内核栈 */

/* 内核栈客户端 connect 本机/外部内核服务（FR-4/FR-5） */
int c = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
connect(c, (struct sockaddr*)&srv, sizeof(srv));     /* 按 fd 归属走内核 */

/* 同一 epoll 同时收 biz / mgmt / c 三类事件（统一事件） */
```

---

## 3. config.ini 共存能力开关（弱化版，不改默认语义）

### 3.1 配置项（设计草案）
```ini
[stack]
# 是否启用「内核栈共存」能力：0=禁用(纯 F-Stack)，1=启用(允许 per-fd SOCK_KERNEL 走内核栈)
# 注意：启用后默认仍 per-fd F-Stack，仅当 socket 显式带 SOCK_KERNEL 才走内核栈。
# 不提供「整进程默认走内核」选项（那会旁路 F-Stack）。
kernel_coexist = 0
```
- 解析落点：`lib/ff_config.c ini_parse_handler:956` 增 `MATCH("stack","kernel_coexist")`（仿 `MATCH("kni","enable") :1011`）。
- 结构落点：`struct ff_config`（`ff_config.h:253`）嵌套段：
```c
struct {
    int kernel_coexist;   /* 0=disabled(default), 1=enable kernel-stack coexistence */
} stack;
```
- 默认值：`kernel_coexist = 0`（`ff_config.c` 默认段）。
- **与 v3 区别**：删除 `default_stack`(fstack/kernel) 与 `default_to_kernel`「整进程默认内核」语义。

### 3.2 与 hook 模式关系
- hook 模式共存由编译宏 `FF_KERNEL_EVENT` 决定（README）。`[stack] kernel_coexist` 主要服务**原生模式**运行期启用，并作为统一的能力开关语义；hook 层 `ff_global_cfg` 为 stub（`ff_hook_syscall.c:31` "Just for so, no used"），故 hook 模式仍以编译宏为准（如实记录）。

### 3.3 多进程差异化
- 每进程经各自 config.ini 独立设 `kernel_coexist`（`ff_config.filename:254`）——多进程靠不同配置文件，无需线程级（NFR-6）。

---

## 4. 双模式适配契约

| 模式 | 共存现状 | v4 契约 |
|---|---|---|
| **hook（LD_PRELOAD + FF_KERNEL_EVENT）** | **已支持**（`ff_hook_socket:387-390`、`ff_hook_connect:858`、epoll 合并 `:2324+`） | **固化为主基线**，复核 + 正确同进程双栈 demo；行为不变 |
| **原生 `ff_api`** | **不支持**：`ff_socket` 恒建 F-Stack socket、`ff_epoll.c` 纯 kqueue（`02 §4`/D3） | **新设计统一事件共存**：`ff_socket(SOCK_KERNEL)` 建受管内核 fd（经 `ff_host_interface`，登记归属）；`ff_bind/listen/accept/connect/close/epoll_ctl` 按归属路由；`ff_epoll_wait` 合并 kqueue⊕内核 epoll；默认/`SOCK_FSTACK` 逐字节零回归 |

> 实现须保证：两模式下「未启用共存 / 默认 / `SOCK_FSTACK`」行为与改造前**逐字节一致**（NFR-1），F-Stack 业务面始终在位（NFR-3）。

---

## 5. 关键数据结构（设计草案）

```c
/* config 段（新增到 struct ff_config） */
struct { int kernel_coexist; } stack;

/* 原生模式 fd 归属（新增，仿 hook fstack_kernel_fd_map / nginx ngx_max_sockets 偏移） */
enum ff_stack_owner { FF_OWNER_FSTACK = 0, FF_OWNER_KERNEL = 1 };
/* 受管内核 fd 登记表：记录哪些 fd 属内核栈 + 与 F-Stack epoll 的配对 */
/* 具体形态实现阶段定（数组/位图/映射），不暴露裸内核 fd 给应用绕过 */
```

---

## 6. 可观测（NFR-5）

```c
/* 设计草案：两栈 fd 数/事件数统计（不新增对外 socket API） */
struct ff_stack_stats { uint64_t fstack_fds, kernel_fds, fstack_events, kernel_events; };
int ff_stack_get_stats(struct ff_stack_stats *out);   /* 命名实现阶段定 */
```

---

## 7. 兼容矩阵

| 维度 | 取值 | 说明 |
|---|---|---|
| DPDK | 23.11.5 / 24.11.6 | 不依赖已移除 `rte_kni` |
| 模式 | hook（FF_KERNEL_EVENT 固化）/ 原生（统一事件共存补齐） | 见 §4 |
| 方向 | 服务端 + 客户端 | FR-2~FR-5 |
| 默认态 | 未启用共存 / 不带标记 | 等价纯 F-Stack（NFR-1） |
| 业务面 | 始终 F-Stack | NFR-3 |
| `kern.maxfiles` | ≤ 65536 | hook fd 映射前提（README 注 1） |

---

## 8. 错误处理约定

| 场景 | 行为 |
|---|---|
| `type` 同置 `SOCK_KERNEL`+`SOCK_FSTACK` | 按优先级走 F-Stack（`ff_hook_socket:387` 不成立）；文档明示 |
| 共存未启用却带 `SOCK_KERNEL`（原生） | 返回错误（如 `-EINVAL`/`-EOPNOTSUPP`）或按文档退化为 F-Stack，二选一并明示；**不得**静默旁路 |
| hook `maxevents < 2` | 返回 `-EINVAL`（`:2212-2218`） |
| 内核侧 socket/connect 失败 | 返回原生 `errno`，不静默回退 |
| 内核/F-Stack 地址端口冲突 | 返回 `-EADDRINUSE` |
| 关闭 fd | 联动释放对应栈资源（hook `:1874-1883`；原生本轮补），无泄漏（FR-8） |

---

## 9. 待决问题
- config 开关命名（`kernel_coexist` vs 其他）与默认值（默认关）。
- 原生受管内核 fd 与 F-Stack fd 的 fd 空间区分（编码偏移 / 归属表）。
- `ff_epoll_wait` 合并的内核事件节流策略（仿 hook `:2324+` timeout=0+节流）。
- 统计接口命名与导出位置。

> 本文为 v4 设计契约草案；命名/签名在 `06` 里程碑确认；引用行号以代码为准。
