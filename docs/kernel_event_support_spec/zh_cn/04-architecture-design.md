# 04 架构设计：自动双栈共存 + fd 三态路由 + 双驱动数据流 + 双栈统一事件

> **文档编号**：SPEC-KE-04
> **版本**：v6（native 自动双栈共存范式）
> **日期**：2026-06-17
> **状态**：编写中（v6 设计）
> **作用域**：双层开关、自动双栈模型、fd 三态路由、`ff_native_fd_map` 映射表、双驱动数据流、双栈统一事件、accept 单栈归属、connect 双栈契约。
> **依据**：`02`（代码现状）、`03`（外部方案），冲突以代码为准。**v6 新增逻辑均为待实现设计。**

---

## 1. 设计原则

1. **F-Stack 始终在位（铁律 NFR-3）**：自动双栈下 F-Stack fd **始终建、始终承担业务高速路径**；内核栈是**并行附加**的第二条栈，绝不替代/旁路 F-Stack。
2. **双层开关**：编译宏 `FF_KERNEL_COEXIST` gate 编译期（默认关，关则不编译）；config `kernel_coexist` gate 运行期（仅编译宏开时生效）。
3. **默认双栈 + marker 单栈覆盖（v6 核心）**：默认无 marker → 双建/双驱动；`SOCK_KERNEL` → 仅内核；`SOCK_FSTACK` → 仅 F-Stack。
4. **fd 三态路由**：`ff_is_kernel_fd(fd)`(≥BASE)=仅内核；否则 F-Stack 路径，且 `ff_native_map_get(fd)>0` 则再双驱动 host_fd。
5. **热路径无回归（NFR-2）**：已 accept 的单栈连接只按 `ff_is_kernel_fd` 一次判定，不查 map。
6. **复用而非重造**：复用 v5 已落地的 `FF_KERNEL_FD_BASE` 编码、`ff_host_*` 桥、`ff_epoll_pairs` 合并；v6 仅在其上加默认双建/双驱动 + `ff_native_fd_map`。
7. **与 KNI 无关**：不涉及报文回灌。

---

## 1bis. 双层开关与零回归路径

```
编译期 gate（FF_KERNEL_COEXIST，lib/Makefile 默认注释关）
  ├─ 未定义（默认）──► 共存代码全部 #ifdef 排除，不编译
  │                    SOCK_FSTACK/SOCK_KERNEL 宏不可见、ff_native_fd_map 不存在
  │                    ► libfstack.a 与原 F-Stack 逐字节零回归
  └─ 已定义 ──► 编译进共存能力
        └─ 运行期 gate（config [stack] kernel_coexist）
              ├─ =0（默认）──► 双建/双驱动分支短路，仅建 F-Stack（零回归）
              └─ =1 ─────────► 自动双栈：默认双建/双驱动 + marker 单栈覆盖 + 统一事件
```

---

## 2. fd 三态模型（v6 核心）

```
                       ┌─ ff_is_kernel_fd(fd)? (fd >= 0x40000000) ─ 是 ─► 【单栈·仅内核】走 v5 ff_host_*(real(fd))
ff_* 入口(fd) ─────────┤
                       └─ 否（F-Stack fd 区间）─► 走 F-Stack 原路径(kern_*/sys_*)
                              └─ 且 ff_native_map_get(fd) > 0 ? ─ 是 ─► 【双栈】再对 map[fd]=host_fd 执行 ff_host_*
                                                              └─ 否 ─► 【单栈·仅 F-Stack】(SOCK_FSTACK / 连接 fd / 零回归)
```

| fd 形态 | 创建来源 | fd 值 | map 项 | 路由 |
|---|---|---|---|---|
| **双栈 fd** | 默认 `ff_socket`（v6） | F-Stack 原始 fd(<65536) | `map[fstack]=host` | F-Stack 原路径 + 再 `ff_host_*(host)` 双驱动 |
| **单栈·仅内核 fd** | `SOCK_KERNEL` / accept 内核侧连接 | `host+BASE`(≥0x40000000) | 无 | 仅 `ff_host_*(real)` |
| **单栈·仅 F-Stack fd** | `SOCK_FSTACK` / accept F-Stack 侧连接 / 默认（共存关） | F-Stack 原始 fd | 无 | 仅 F-Stack 原路径（零回归） |

> 三类 fd 空间互不冲突：F-Stack fd < `kern.maxfiles`(≤65536) ≪ `FF_KERNEL_FD_BASE`(0x40000000)；host fd 受 `RLIMIT_NOFILE`。

---

## 3. 总体架构（同一进程内自动双栈）

```mermaid
graph TD
    subgraph APP[同一应用进程 - 单一 ff_api 接口]
      A1[默认 socket/listen 80 无 marker]
      A2[SOCK_KERNEL socket 仅内核]
      A3[SOCK_FSTACK socket 仅 F-Stack]
    end
    subgraph GLUE[选栈与双驱动胶水层 #ifdef FF_KERNEL_COEXIST]
      MK[marker 解析: 默认双栈 / SOCK_KERNEL 仅内核 / SOCK_FSTACK 仅 F-Stack]
      SW[config kernel_coexist 运行期启用]
      MAP[ff_native_fd_map 映射表 fstack_fd 到 host_fd]
      RT[fd 三态路由 ff_is_kernel_fd / ff_native_map_get]
      EV[统一事件 kqueue 合并 内核 epoll 双栈 listen 两栈各注册]
    end
    F[(F-Stack 用户态 FreeBSD 栈 - 业务 始终在位)]
    K[(Linux 内核协议栈 - 并行附加栈)]

    A1 -->|默认双栈| MK
    A2 -->|仅内核| MK
    A3 -->|仅 F-Stack| MK
    SW -.启用自动双栈.-> MK
    MK -->|默认: 双建| F
    MK -->|默认: 双建| K
    MK -->|SOCK_KERNEL| K
    MK -->|SOCK_FSTACK| F
    MAP --- RT
    RT --- MK
    EV --> F
    EV --> K
    K -.本机 curl/ping/ssh 127.0.0.1.-> A1
    F -.DPDK NIC 远端访问 9.134.214.176.-> A1
```

- **默认 A1→F 与 A1→K 同时建**（双栈）；A2 仅 K；A3 仅 F。
- native 双驱动是 hook 所无的（hook socket/listen 不双建，见 `02 §5.1`）。

---

## 4. 双驱动数据流（v6）

### 4.1 服务端方向（自动双栈 listen）

```
ff_socket()            默认无 marker
  ├─ sys_socket()              ─► F-Stack fd s (<65536)        [始终]
  └─ ff_host_socket()          ─► host fd h                    [coexist 开]
     ff_native_map_set(s, h)   ─► map[s]=h
  return s                                                     (返回 F-Stack 原始 fd)

ff_bind(s, addr)
  ├─ kern_bindat(s, bsdaddr)   ─► F-Stack 落 bind             [若成功]
  └─ ff_host_bind(map[s], addr) ─► 内核栈落 bind (原始 linux addr)

ff_listen(s, backlog)
  ├─ sys_listen(s)             ─► F-Stack listen
  └─ ff_host_listen(map[s], backlog) ─► 内核栈 listen
  ► 一个 listen(80) 同时在 F-Stack(DPDK) 与 内核栈 监听

ff_epoll_ctl(epfd, ADD, s, ev)  双栈 listen fd (map[s]>0)
  ├─ ff_kevent(epfd, s, ...)            ─► F-Stack kqueue 注册
  └─ ff_host_epoll_ctl(host_ep, ADD, map[s], ev) ─► 内核 epoll 注册 (透传 ev.data)

ff_epoll_wait(epfd, ...)
  ├─ ff_host_epoll_wait(host_ep, timeout=0)  ─► 取内核侧 listen 就绪
  └─ ff_kevent_do_each(epfd, ...)            ─► 取 F-Stack 侧 listen 就绪
  ► 合并两栈事件返回

ff_accept(s)  s 为双栈 listen fd (map[s]>0) —— 见 §6 单栈归属
```

### 4.2 客户端方向（双栈 connect，契约草案，待确认）

见 §7 §connect 契约。默认双栈 `ff_connect` 在两栈各 connect，返回以 F-Stack 为主。

### 4.3 close 双驱动

```
ff_close(fd)
  ├─ ff_is_kernel_fd(fd)?  ─ 是 ─► ff_host_close(real(fd))          [单栈内核]
  └─ 否 ─► kern_close(fd)                                            [F-Stack]
            └─ map[fd]>0 ? ─► ff_host_close(map[fd]); ff_native_map_clear(fd)  [双栈]
  ► 若 fd 为 kqueue fd：清 ff_epoll_pairs 配对 + 关 host_ep（避免内核 fd 泄漏，参考上游 fix）
```

---

## 5. `ff_native_fd_map` 映射表（v6 待实现）

```c
/* ff_host_interface.c，#ifdef FF_KERNEL_COEXIST，HOST_CFLAGS */
static int ff_native_fd_map[FF_MAX_FREEBSD_FILES];   /* FF_MAX_FREEBSD_FILES=65536，仿 adapter */
/* 访问器（ff_host_interface.h 声明）：单线程轮询模型，无锁 */
int  ff_native_map_get(int fstack_fd);     /* 返回 host_fd 或 0/-1（无映射） */
void ff_native_map_set(int fstack_fd, int host_fd);
void ff_native_map_clear(int fstack_fd);
```

- **无锁理由（NFR-5）**：F-Stack 每进程单线程轮询（`ff_run`），仿 adapter `fstack_kernel_fd_map`（`ff_hook_syscall.c:258` 裸数组无锁）。
- **容量**：65536（与 `kern.maxfiles` 上限同），fstack fd 直接作下标。
- **与 `ff_epoll_pairs` 区别**：`ff_native_fd_map` 映射「双栈 socket/listen fd → host fd」；`ff_epoll_pairs[64]`（v5 已有）映射「kqueue fd ↔ host epoll fd」。两表正交，各司其职。

---

## 6. accept 单栈归属（Q3=A）

```
ff_accept(s)  s 为双栈 listen fd (ff_native_map_get(s)>0)，要求非阻塞
  1) kern_accept(s)  非阻塞尝试 F-Stack 侧
       成功 ─► 返回 F-Stack 原始连接 fd（单栈·仅 F-Stack，无 map 项）
       errno==EAGAIN/EWOULDBLOCK ─► 继续 2)
  2) ff_host_accept(map[s])  尝试内核侧
       成功 ─► 返回 ff_kernel_fd_encode(host_conn)（单栈·仅内核）
       EAGAIN ─► 继续
  3) 仅当两栈皆 EAGAIN ─► 返回 -1 / EAGAIN
```

- **连接 fd 单栈**：F-Stack 侧连接=原始 fd（仅 F-Stack 驱动）；内核侧连接=encode fd（仅 `ff_host_*`）。后续 recv/send/close 按 `ff_is_kernel_fd` 路由，**不查 map（热路径 NFR-2）**。
- 为何单栈：一条已建立的 TCP 连接物理上只存在于接收到 SYN 的那一栈，无法「双栈」。listen 双栈、连接单栈是正确语义。
- 非阻塞前提：epoll 驱动下 listen socket 典型非阻塞；阻塞 listen 的双栈 accept 语义须在 `05` 给出（建议要求非阻塞）。

---

## 7. §connect 双栈契约草案（Q2=B，**待用户最终确认**）

> **歧义本质**：一条客户端逻辑连接流（一个 fd 上的 send/recv）无法真正「同时双工于两栈」——数据要么从 F-Stack 发、要么从内核发。默认双栈 connect 因此只能是「两栈各建一条连接，选其一为数据主路径」。

**v6 契约草案**：
```
ff_connect(s, name)  s 为双栈 fd (map[s]>0)
  ├─ kern_connectat(s, name)        ─► F-Stack 侧 connect（数据主路径）
  └─ ff_host_connect(map[s], name)  ─► 内核侧 connect（并发建连，双网可达备援）
  return 以 F-Stack 为主（非阻塞 EINPROGRESS 语义）
  ► 数据路径默认走 F-Stack；内核侧连接用于「双网可达」探测/备援
  ► close 联动拆两栈
```

- **明确标注**：
  - 如需**纯内核客户端** → 用 `SOCK_KERNEL`（仅内核，无歧义）。
  - **kernel-primary / failover / Happy-Eyeballs 式选路** → **为后续，不在 v6 保证**。
- 异常矩阵见 `05 §connect 异常矩阵`。
- **本契约存在语义歧义，须经用户最终确认后定稿**（spec 显式标注）。

---

## 8. 双栈统一事件模型

### 8.1 双栈 listen fd（v6）
- `ff_epoll_ctl(ADD, s, ev)` 对 `map[s]>0` 的 listen fd：F-Stack kqueue 注册 s + 内核 epoll 注册 `map[s]`，**两处都透传 `ev.data`**（app 用同一 data 识别）。
- `ff_epoll_wait`：先 `ff_host_epoll_wait(timeout=0)` 取内核 listen 就绪（含节流思路，参考 hook `:2333`），再 `ff_kevent_do_each` 取 F-Stack 就绪，合并。app 对同一 `ev.data` 调 `ff_accept(s)`，由 §6 决定取哪栈连接。
- 复用 v5 `ff_epoll_pairs`/`ff_epoll_host_ep`（`ff_epoll.c:37-69`）。

### 8.2 单栈 fd
- 仅内核 fd（encode）：注册到 host epoll（`ff_epoll_ctl:104-114` v5 已支持）。
- 仅 F-Stack fd：注册到 kqueue（原路径）。

### 8.3 close 联动
- kqueue fd close 须清 `ff_epoll_pairs` + 关 host_ep（`03 §2.6` 上游 fd leak fix）。

---

## 9. 内核-用户态栈共存矩阵

| 维度 | F-Stack 用户态栈（业务，始终在位） | 内核栈（并行附加栈） |
|---|---|---|
| 载体 | DPDK PMD + FreeBSD 栈 | Linux 内核协议栈 |
| 流量 | 业务高速路径（DPDK NIC，如 9.134.214.176） | 本机/管理/客户端（127.0.0.1/本机 IP/外部内核服务） |
| 默认 socket | **建**（双栈） | **建**（双栈，v6） |
| 选栈触发 | 默认 / `SOCK_FSTACK` | 默认（双栈）/ `SOCK_KERNEL`（仅内核） |
| 事件 | `ff_kqueue`/`ff_kevent` | host `epoll` |
| 是否可被旁路 | **否（始终在位）** | 仅附加，可禁用 |

---

## 10. 选型与权衡

| 方案 | 是否采用 | 理由 |
|---|---|---|
| **native 自动双栈（默认双建/双驱动 + marker 覆盖）** | ✓ **v6 核心** | 一 socket 多用，符合「默认双向可达」诉求；F-Stack 始终在位 |
| 复用 v5 `FF_KERNEL_FD_BASE`/`ff_host_*`/`ff_epoll_pairs` | ✓ | 已落地实测，v6 在其上叠加 |
| `ff_native_fd_map` 无锁裸数组（仿 hook） | ✓ | 单线程轮询模型，与 adapter 同构 |
| hook `FF_KERNEL_EVENT`（epoll 双建合并） | ✓ 交叉参考 | 同构验证；但 socket/listen 不双建（分歧） |
| nginx `kernel_network_stack` | ✓ 参考 | 双事件后端可行性 |
| v3 `ff_host_socket` 纯内核旁路 | ✗ 已废弃 | 绕开 F-Stack（违 NFR-3） |
| 整进程 `default_stack=kernel` | ✗ 已废弃 | 反 F-Stack |
| connect 真双工双栈 / 线程级选栈 / KNI 回灌 | ✗ | 语义不成立 / 非本问题域 |

**结论**：以 **native 自动双栈（默认双建/双驱动 + `ff_native_fd_map` + 双栈事件）** 为骨架，复用 v5 编码偏移/桥/配对表，外层 `FF_KERNEL_COEXIST` + 运行期 `kernel_coexist` 双层门控，marker 单栈覆盖，F-Stack 始终在位。

---

## 11. 影响面（blast radius）
- 本阶段（v6 spec）：仅文档。
- R7 实现：`ff_host_interface.{c,h}`（+`ff_native_fd_map`+访问器）、`ff_syscall_wrapper.c`（`ff_socket` 重构 + bind/listen/close/connect/accept/setsockopt/fcntl 双驱动）、`ff_epoll.c`（双栈 listen 双注册 + close 清配对）。全部 `#ifdef FF_KERNEL_COEXIST` 内，宏关零回归。
- 热路径（recv/send/read/write）：仅 `ff_is_kernel_fd` 一次判定，不查 map（NFR-2）。

---

## 12. 待决问题（交 05/06/09 细化）
- §connect 双栈数据路径契约（语义歧义，**待用户最终确认**）。
- 双建部分失败的回滚/降级契约（F-Stack 成功但 `ff_host_socket` 失败）。
- 双栈 fd 对未路由接口（`readv/writev/sendmsg/...`）的行为（默认仅 F-Stack 驱动，D8 已知限制延伸）。
- `ff_close` 对 `ff_epoll_pairs` 清理完整性（fd leak 复核）。
- 可观测统计（`ff_stack_get_stats`）当前未实现（D5）。
