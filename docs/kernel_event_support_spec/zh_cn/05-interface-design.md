# 05 接口设计：单 API + 标记选栈 + config 默认开关 契约

> **文档编号**：SPEC-KE-05
> **版本**：v3（范式修正重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：选栈标记约定、config.ini 开关、客户端/服务端用法契约、双模式适配、数据结构与错误处理。
> **核心原则**：**不新增 `ff_local_*` 双 API**；复用 F-Stack 现有单 API（hook POSIX 套件 + 原生 `ff_*` 套件），靠**标记 + 配置**选栈，胶水层自动适配。
> **依据**：`02`（代码现状）、`04`（架构）。行号以代码为准，实现阶段以 gatekeeper 复核为准。

---

## 1. 接口基线（全部复用，不重造）

| 类别 | 复用接口 | 来源 |
|---|---|---|
| hook 模式（LD_PRELOAD） | 标准 POSIX `socket/bind/listen/accept/connect/close/epoll_*`（被 `ff_hook_*` 接管） | `adapter/syscall/ff_hook_syscall.c` |
| 原生模式 | `ff_socket/ff_bind/ff_listen/ff_accept/ff_connect/ff_close/ff_kqueue/ff_kevent` | `lib/ff_api.h:81,89,90,91,93,94,138,139` |
| 内核侧封装 | `ff_linux_socket/bind/listen/accept/connect/close/epoll_*` | `ff_linux_syscall.c:81,88,96,131,144,217,233,239,247` |

> 本特性**不增加新的 socket/epoll API**，只标准化"选栈标记"与"config 默认开关"两个约定 + 在原生模式补齐标记识别。

---

## 2. 选栈标记约定（v3 唯一选栈方式，标准化现有标记）

### 2.1 标记定义（复用，提升为对外约定）
```c
/* 来源 adapter/syscall/ff_adapter.h:7-8，v3 标准化为对外可依赖约定 */
#define SOCK_FSTACK 0x01000000   /* 该 socket 走 F-Stack 用户态栈 */
#define SOCK_KERNEL 0x02000000   /* 该 socket 走宿主机 Linux 内核栈（本机可直访/可连本机外部内核服务） */
```
- 标记叠加在标准 `type` 高位，不与 glibc `SOCK_STREAM/DGRAM/NONBLOCK/CLOEXEC` 冲突。
- **语义与优先级（实测 `ff_hook_socket:387`）**：`(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)` → 内核栈；否则 → F-Stack（默认）。即 **`SOCK_FSTACK` 优先于 `SOCK_KERNEL`**（两者同置时走 F-Stack）。

### 2.2 用法（应用只用单 API + 标记）
```c
/* 服务端走内核栈（本机 curl/ssh 可直访） */
int s = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);   /* hook 模式 */
bind(s, ...); listen(s, backlog);                         /* 胶水按 fd 归属自动落内核栈 */

/* 业务走 F-Stack（默认，无需标记，或显式 SOCK_FSTACK） */
int f = socket(AF_INET, SOCK_STREAM, 0);

/* 客户端经内核栈 connect 本机/外部内核服务（FR-3/FR-4） */
int c = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
connect(c, (struct sockaddr*)&srv, sizeof(srv));          /* ff_hook_connect:858 按归属走 ff_linux_connect */
```

---

## 3. config.ini 全局默认开关（新增，仿 `[kni]` 范式）

### 3.1 配置项（设计草案）
```ini
[stack]
# 本进程默认协议栈：fstack（默认）| kernel
default_stack = fstack
```
- 解析落点：`lib/ff_config.c` `ini_parse_handler`（:956）新增分支 `MATCH("stack","default_stack")`（仿 `MATCH("kni","enable")` :1011）。
- 结构落点：`struct ff_config`（`ff_config.h:253`）新增嵌套段：
```c
struct {
    int default_to_kernel;   /* 0=F-Stack(默认), 1=内核栈 */
} stack;
```
- 默认值：`default_to_kernel = 0`（`ff_config.c:1358+` 默认段设置）。

### 3.2 优先级与覆盖
- `选栈 = app标记(SOCK_KERNEL/SOCK_FSTACK) ?? config.default_stack ?? F-Stack`。
- **app 标记永远覆盖 config 默认**；未设标记时按 config 默认；config 也未设时按内置 F-Stack。

### 3.3 多进程差异化
- 每进程经各自 config.ini（`ff_config.filename:254`，`ff_load_config` `ff_config.h:347`）独立设默认栈——**用不同 config 文件实现进程级差异，无需线程级选栈**（`02 §4`/NFR-6）。

---

## 4. 双模式适配契约

| 模式 | 标记选栈现状 | v3 契约 |
|---|---|---|
| **hook 模式（LD_PRELOAD）** | **已支持**（`ff_hook_socket:387-390`、`ff_hook_connect:858`、`ff_hook_epoll_create:1981`） | 直接复用；补 config 默认注入（未带标记时按 `default_to_kernel` 注入等价 `SOCK_KERNEL`） |
| **原生 `ff_api` 模式** | **不支持**：`ff_socket:913` 经 `linux2freebsd_socket_flags:668`（仅处理 NONBLOCK/CLOEXEC）恒建 F-Stack socket（`02 §5`/D4） | 在 `ff_socket` 入口仿 hook 增 `SOCK_KERNEL` 识别分支 → 走内核 socket 等价路径；保持单 API、不新增 API |

> 实现阶段须保证：两模式下"未设标记 + 默认 F-Stack"时行为与改造前**逐字节一致**（NFR-1）。

---

## 5. 关键数据结构（设计草案）

```c
/* config 段（新增到 struct ff_config） */
struct { int default_to_kernel; } stack;

/* fd 归属枚举（与现有 is_fstack_fd 对齐，仅文档化语义） */
enum ff_stack_owner { FF_OWNER_FSTACK = 0, FF_OWNER_KERNEL = 1 };

/* 统一 epoll fd → 内核 epoll fd 映射：复用 fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES=65536]
   （ff_hook_syscall.c:257-258），不新建容器 */
```

---

## 6. 可观测（NFR-4）

```c
/* 设计草案：复用/扩展适配层统计（不新增对外 socket API） */
struct ff_stack_stats { uint64_t kernel_fds, fstack_fds, kernel_events, fstack_events; };
int ff_stack_get_stats(struct ff_stack_stats *out);   /* 命名实现阶段定 */
```

---

## 7. 兼容矩阵

| 维度 | 取值 | 说明 |
|---|---|---|
| DPDK | 23.11.5 / 24.11.6 | 不依赖已移除的 `rte_kni` |
| 模式 | hook（完整）/ 原生（补标记识别） | 见 §4 |
| 方向 | 服务端（监听被访）/ 客户端（connect 本机/外部内核服务） | FR-1~FR-4 |
| 事件 | 对外 epoll / F-Stack 内部 kqueue | 接口层抹平 |
| 默认态 | 不设标记 + `default_stack=fstack` | 等价纯 F-Stack（NFR-1） |
| 协议 | TCP/UDP/ICMP（内核侧由内核栈处理） | ping 经内核栈 |

---

## 8. 错误处理约定

| 场景 | 行为 |
|---|---|
| `type` 同置 `SOCK_KERNEL` 与 `SOCK_FSTACK` | 按实测优先级走 F-Stack（`ff_hook_socket:387` 条件不成立）；文档明示 |
| `maxevents < 2` | 返回 `-EINVAL`（对照 `:2212-2218`） |
| 内核侧 socket/connect 失败 | 返回原生 `errno`，不静默回退到 F-Stack |
| 客户端 fd 归属与目的地址栈不匹配 | 由对应栈返回标准错误（如内核 fd 连仅 F-Stack 可达地址 → 内核栈 `connect` 失败 errno），不跨栈重定向 |
| 内核/F-Stack 地址端口冲突 | 返回 `-EADDRINUSE`，显式报错 |
| 关闭 fd | 联动释放两栈资源（`:1874-1883`），避免泄漏（FR-8） |
| 原生模式标记识别补齐前 | `ff_socket` 忽略 `SOCK_KERNEL`、恒 F-Stack（`02 §5`），需文档警示直至补强 |

---

## 9. 待决问题
- config 段命名（`[stack] default_stack` vs 并入 `[dpdk]`）与取值表（`fstack`/`kernel`）。
- 原生模式标记识别补强落点（`ff_socket` 入口分支 vs 独立封装），需保证默认路径零开销。
- 是否对外提供"显式内核栈便捷封装"（如宏 `FF_SOCK_KERNEL(type)`）以提升可读性，仍属单 API 范畴。
- 统计接口命名与导出位置。

> 本文为 v3 设计契约草案，命名/签名在实现里程碑（`06`）确认；引用行号以代码为准。
