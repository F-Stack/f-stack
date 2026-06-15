# 接口设计（05-interface-design.md）

> **文档编号**：SPEC-KE-05
> **版本**：v0.1 草稿
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：本地 socket/fd/event 访问 lib 的对外 API、编译开关、数据结构、生命周期
> **依据**：`lib/ff_api.h`、`lib/ff_msg.h`、`lib/ff_dpdk_if.c`、`config.ini`（以代码为准）

---

## 1. 现有可复用接口基线（实测）

### 1.1 F-Stack 应用 socket/event API（`lib/ff_api.h`）
- socket 族：`ff_socket`（`:81`）、`ff_bind`（`:90`）、`ff_listen`（`:89`）、`ff_accept`/`ff_accept4`（`:91-92`）、`ff_connect`（`:93`）、`ff_close`（`:94`）、`ff_ioctl`（`:70`）、`ff_sendto`/`ff_recvfrom`（`:124,129`）。
- 事件族：`ff_kqueue`（`:138`）、`ff_kevent`（`:139`）、`ff_kevent_do_each`（`:141`）。
- 路由：`ff_route_ctl`（`:191`，`FF_ROUTE_ADD/DEL/CHANGE`，`:176-191`）。

### 1.2 KNI 运行时控制（`lib/ff_msg.h` + `lib/ff_dpdk_if.c`）
- 消息族：`FF_KNICTL`（`ff_msg.h:47`）、`FF_KNICTL_CMD_GET/SET`（`:112-116`）、`FF_KNICTL_ACTION_DEFAULT/ALL_TO_KNI/ALL_TO_FF`（`:118-123`）、`struct ff_knictl_args{int kni_cmd; int kni_action;}`（`:125-127`）。
- 处理器：`handle_knictl_msg`（`ff_dpdk_if.c:1960-1977`，`FF_KNICTL_CMD_SET` 下切换 `knictl_action`）。
- 策略初始化：`init_kni` 读取 `ff_global_cfg.kni.method`→`kni_accept`、`ff_global_cfg.kni.kni_action`→`knictl_action`（`:547-552`）。

### 1.3 配置（`config.ini [kni]`，`:250-267`）
`enable`、`method`(reject/accept)、`tcp_port`、`udp_port`、`console_packets_ratelimit`、`general_packets_ratelimit`、`kernel_packets_ratelimit`。

## 2. 新增统一接口（暂名 `libff_local` / `ff_local.h`）

> 命名与归属为草案，最终在实现阶段定稿（见 04 文档待决问题）。以下为**接口契约设计**，本阶段不实现。

### 2.1 生命周期 / 初始化
```c
/* 初始化本地访问能力（在 ff_init 之后调用；内部确保 virtio-user exception path 就绪） */
int ff_local_init(const struct ff_local_cfg *cfg);

/* 反初始化 */
void ff_local_cleanup(void);
```
`struct ff_local_cfg`：是否启用、默认 action、端口规则、限速值——字段语义对齐 `config.ini [kni]`，避免双份语义。

### 2.2 分流策略控制（封装 FF_KNICTL）
```c
enum ff_local_action {                 /* 1:1 映射 FF_KNICTL_ACTION_* */
    FF_LOCAL_DEFAULT, FF_LOCAL_ALL_TO_KERNEL, FF_LOCAL_ALL_TO_FF
};
int  ff_local_set_action(enum ff_local_action act);   /* 运行时切换，内部走 FF_KNICTL_CMD_SET */
int  ff_local_get_action(enum ff_local_action *out);  /* 走 FF_KNICTL_CMD_GET */

/* 端口/协议级规则（对齐 method + tcp_port/udp_port 位图） */
int  ff_local_rule_set(int proto /*IPPROTO_TCP/UDP*/, const uint16_t *ports, size_t n, int to_kernel);
```

### 2.3 本地 socket/fd/event（连接级，借鉴机制 A/B，后续里程碑）
```c
/* 显式创建"走内核栈"的本地 socket（不带 fstack 标志，类比 ngx_socket 无 SOCK_FSTACK） */
int ff_local_socket(int domain, int type, int protocol);

/* 统一事件等待：同一循环同时等待内核 fd 与（可选）fstack 事件并合并，
   借鉴 ff_hook_syscall.c:2324-2399 的 epoll 合并范式 */
int ff_local_epoll_create(int size);
int ff_local_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);
int ff_local_epoll_wait(int epfd, struct epoll_event *evs, int maxevents, int timeout);
```

### 2.4 状态/统计查询（封装 kni_interface_stats）
```c
struct ff_local_stats { uint64_t rx_packets, rx_dropped, tx_packets, tx_dropped; };
int ff_local_get_stats(uint16_t port_id, struct ff_local_stats *out);  /* 对齐 ff_dpdk_kni.c:72-87 */
```

## 3. 编译开关

| 宏 | 含义 | 现状对齐 |
|---|---|---|
| `FF_KNI` | 启用 KNI/virtio-user 数据面 | 既有（`lib/ff_dpdk_if.c:608` 等 `#ifdef FF_KNI`） |
| `FF_LOCAL`（新增草案） | 编译 `libff_local` 统一接口层 | 新增，依赖 `FF_KNI` |
| `FF_KERNEL_EVENT` | LD_PRELOAD 层 epoll 内核镜像 | 既有（`adapter/syscall/Makefile:54-56`），连接级增强可参考 |

> 不新增任何内核模块编译；virtio-user 为纯用户态 vdev + 内核 `vhost-net`。

## 4. 数据结构与映射

- 复用 `struct kni_interface_stats`（`ff_dpdk_kni.c:72-87`）做统计。
- 复用 `kni_rp`（`rte_ring**`，`ff_dpdk_kni.c:89`）与 `kni_stat`（`:90`）。
- 连接级增强若启用：引入 `local_fd_map`（类比 `fstack_kernel_fd_map`，`ff_hook_syscall.c:255-258`）。

## 5. 与既有语义的兼容矩阵

| 既有入口 | 本特性处理 |
|---|---|
| `config.ini [kni] enable/method/ports` | `ff_local_init` 读取同一配置，**不引入冲突的第二份配置** |
| `FF_KNICTL` IPC | `ff_local_set_action/get_action` 作为其友好封装，底层不变 |
| `ff_socket(SOCK_FSTACK)` 语义 | 不改；`ff_local_socket` 为"显式内核"对偶 |

## 6. 错误处理约定
- `vhost-net` 不可用 / 权限不足 / hugepage 不足：`ff_local_init` 返回明确错误码并日志（对齐 `ff_log` `FF_LOGTYPE_FSTACK_LIB`，见 `ff_dpdk_if.c:1967`）。
- secondary 进程调用连接级/virtio_user 创建类接口：返回不支持（仅 primary 创建口，`ff_dpdk_if.c:609-611`）。

## 7. 开放项
- API 是否并入 `ff_api.h` 还是独立 `ff_local.h`。
- `ff_local_epoll_*` 是否首期交付（取决于连接级增强里程碑，见 `06-milestones.md`）。
