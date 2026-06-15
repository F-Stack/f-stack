# 05 接口设计：libff_local 对外契约

> **文档编号**：SPEC-KE-05
> **版本**：v2（全量重做）
> **日期**：2026-06-15
> **状态**：编写中
> **作用域**：本特性 lib 的对外 API、编译开关、数据结构、兼容矩阵与错误处理。
> **依据**：`02`（`ff_api.h` 基线、机制 A/B 范式）、`04`（架构）。具体行号以代码为准，实现阶段以 gatekeeper 复核为准。

---

## 1. 接口基线（复用，不重造）

| 类别 | 复用接口 | 来源 |
|---|---|---|
| F-Stack socket | `ff_socket/ff_bind/ff_listen/ff_accept/ff_connect/ff_close` | `lib/ff_api.h:81,89,90,91,93,94` |
| F-Stack 事件 | `ff_kqueue/ff_kevent` | `lib/ff_api.h:138,139` |
| 内核 socket/事件 | 原生 `socket/bind/listen/accept/connect/close/epoll_*` | glibc |

lib 在其上提供"选栈 + 归属判定 + 事件合并"薄封装。

---

## 2. 新增 API 契约（命名暂定 `ff_local_*`）

### 2.1 初始化/销毁
```c
/* 初始化连接级选栈子系统；need FF_LOCAL_STACK 编译开关 */
int  ff_local_init(const struct ff_local_cfg *cfg);
void ff_local_cleanup(void);
```

### 2.2 选栈式 socket 创建（借鉴机制 A）
```c
/* belong_to_host=1 → 内核栈普通 socket（本机可直访）
   belong_to_host=0 → F-Stack（等价 SOCK_FSTACK 语义） */
int ff_local_socket(int domain, int type, int protocol, int belong_to_host);
int ff_local_listen_on_host(int domain, int type,
                            const struct sockaddr *addr, socklen_t alen,
                            int backlog);   /* 便捷：在内核栈侧监听 */
```
> 对照机制 A `ngx_event_connect.c:46-50` 的 `type|SOCK_FSTACK` vs 普通 `socket`。

### 2.3 fd 归属判定（借鉴机制 B `is_fstack_fd`）
```c
int ff_local_fd_owner(int fd);   /* 返回 FF_OWNER_HOST / FF_OWNER_FSTACK */
```

### 2.4 统一事件接口（借鉴机制 B 双栈合并）
```c
int ff_local_epoll_create(int size);     /* 内部同时建内核 epoll，做映射 */
int ff_local_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);
/* maxevents 必须 >=2（对照 ff_hook_syscall.c:2212-2218）；
   内部先取内核事件(timeout=0,可节流) 再合并 F-Stack 事件 */
int ff_local_epoll_wait(int epfd, struct epoll_event *events,
                        int maxevents, int timeout);
```

### 2.5 统计/可观测（NFR-4）
```c
struct ff_local_stats { uint64_t host_fds, fstack_fds, host_events, fstack_events; };
int ff_local_get_stats(struct ff_local_stats *out);
```

---

## 3. 编译开关与依赖

| 开关 | 作用 | 范式来源 |
|---|---|---|
| `FF_LOCAL_STACK`（暂名） | 编译期开/关本能力；关闭则所有 `ff_local_*` 退化/不参与，零开销 | 机制 B `Makefile -DFF_KERNEL_EVENT` |

- 依赖：F-Stack `lib`（`ff_api.h`）、Linux glibc epoll；**不依赖 KNI/virtio-user**。
- `lib/Makefile` 增加条件编译单元 `ff_local.c`（实现阶段）。

---

## 4. 关键数据结构（设计草案）

```c
enum ff_local_owner { FF_OWNER_FSTACK = 0, FF_OWNER_HOST = 1 };

struct ff_local_cfg {
    int   default_belong_to_host;   /* 缺省选栈 */
    int   host_event_throttle;      /* 内核事件取用节流（对照机制B每N次） */
};

/* 统一 epoll fd → 内核 epoll fd 映射（类比 fstack_kernel_fd_map） */
/* 容量参照 FF_MAX_FREEBSD_FILES=65536（ff_hook_syscall.c:257-258） */
```

---

## 5. 兼容矩阵

| 维度 | 取值 | 说明 |
|---|---|---|
| DPDK | 23.11.5 / 24.11.6 | 本工作区版本，**不依赖已移除的 rte_kni** |
| 事件模型 | epoll（对外） / kqueue（F-Stack 内部） | 接口层抹平 |
| 关闭态 | `FF_LOCAL_STACK` 未定义 | 行为等价纯 F-Stack（NFR-1） |
| 协议 | TCP/UDP/ICMP（内核侧由内核栈处理） | ping 经内核栈 |

---

## 6. 错误处理约定

| 场景 | 行为 |
|---|---|
| `maxevents < 2` | 返回 `-EINVAL`（对照机制 B 约束 `:2212-2218`） |
| 内核侧 socket 创建失败 | 返回原生 `errno`，不静默回退到 F-Stack |
| 内核/F-Stack 地址端口冲突 | 返回 `-EADDRINUSE`，显式报错 |
| 关闭 fd | 联动释放两栈资源（对照 `ff_hook_syscall.c:1874-1883`），避免泄漏（FR-6） |
| 未 `ff_local_init` 即调用 | 返回 `-EPERM` |

---

## 7. 待决问题
- API 是否并入 `ff_api.h` 还是独立 `ff_local.h`（命名空间与发布节奏）。
- 是否提供 LD_PRELOAD 透明接管层（复用机制 B 的 hook 范式）以零改码接入。
- 事件接口是否同时提供 kqueue 风格（贴合 F-Stack 原生）。

> 本文 API 为设计契约草案，命名/签名在实现里程碑（`06`）确认；所有引用行号以代码为准。
