F-Stack 用户态栈与内核栈自动双栈共存：一个 listen 同时服务 DPDK 网卡和本机回环

1. 这功能解决什么问题

F-Stack v2.0（预计 2026.10 正式 release）引入的内核栈共存能力，解决 F-Stack 最经典的一个使用痛点——DPDK 接管网卡后，本机 curl 自己监听的服务会被内核报 Connection refused。

F-Stack 把网卡绑定给 DPDK 后，这张网卡上的流量完全绕过 Linux 内核协议栈，直接进 F-Stack 用户态 FreeBSD 栈。后果是：你在 F-Stack 里 listen 了 80 端口，从同网络另一台机器 curl 你的网卡 IP 能通，但在本机 curl 127.0.0.1 或 curl 本机 IP 会报 Connection refused——因为本机请求走的是 Linux 内核栈，而内核对 F-Stack 的这个 80 端口一无所知。

这个现象在 issue 里被反复问，官方给的标准答案一直是"从别的机器测"或者"用 KNI 回灌"。issue #511/#585/#741/#849 全是同一件事。

我们做的就是把这件事从"手动 workaround"变成"默认行为"：同一个 socket、同一个 listen(80)，同时跑在 F-Stack 用户态栈（DPDK 网卡，业务高速路径）和 Linux 内核栈（本机回环/管理面）上。远端 curl 网卡 IP 走 F-Stack，本机 curl 127.0.0.1 走内核，两条路同时通，而且两栈的事件在同一个 epoll/kqueue 事件循环里统一处理。

【注1】F-Stack 用户态栈始终在位、始终承担业务高速路径，内核栈只是"并行附加"的第二条栈，用来承接本机/管理面/客户端访问，绝不是在旁路或替代 F-Stack。

这里先说清楚它不是什么，免得理解偏差：

- 不是把 socket 旁路到内核（早期有个错误实现就是这么干的，后文 4.1 详述，已回退）
- 不是"整进程默认走内核栈"（那是反 F-Stack 的，明确不做）
- 不是 KNI 报文回灌（那是另一套独立机制，跟本功能无关）
- 不是连接迁移/透明代理（一个 TCP 连接物理上只存在于收到 SYN 的那一栈，无法"双栈"）

2. 主要适用场景

2.1 本机直访自己监听的服务

这是最直接的场景。开发和运维时，你总想在本机 curl 一下自己刚起的服务确认存活，而不是每次都要开另一台机器。开了双栈后，本机 curl 127.0.0.1:80 直接通。

2.2 服务端双向可达

同一个 listen(80)：远端经 DPDK 网卡访问 `<DPDK_NIC_IP>:80` 走 F-Stack 高速路径，本机经 127.0.0.1:80 走内核栈，一个 socket 两用，不用为内核侧额外开一个 SOCK_KERNEL socket，也不用写任何 marker。

2.3 客户端连内核服务

作为客户端要连本机或外部的内核服务（比如本机的某个守护进程、管理面 API），用双栈 connect 或纯内核的 SOCK_KERNEL 都能做到，不用绕道。

2.4 需要内核可见性的监控场景

F-Stack 监听端口在 Linux 的 ss/netstat 里是看不到的（那是用户态栈）。开了双栈后，ss 能看到内核侧的 80 监听，监控和健康检查都方便了。issue #593/#594 里官方也拿 kernel_coexist 当"让端口内核可见"的答案。

2.5 不太适合的场景

- 需要真·双工于两栈的单条连接（一条 fd 上的数据要么走 F-Stack 要么走内核，不可能同时两栈都收发）——默认双栈 connect 只是"两栈各建一条、F-Stack 主"，纯内核客户端请用 SOCK_KERNEL
- 用 select/poll 做多路复用的场景（后文 4.6 详述，内核 fd 装不进 fd_set，不共存）
- 想省掉 F-Stack 只留内核的场景（本功能不提供"整进程默认内核"，那是旁路）

3. 架构特征

3.1 一个 listen 双栈服务

```
                    ┌──────────────────────────────────────────┐
                    │        同一个应用进程，单一 ff_api 接口      │
                    │                                          │
  默认 socket/listen(80) ──► 自动双建                            │
                    │                                          │
        ┌───────────┴───────────┐                              │
        ▼                       ▼                              │
┌───────────────┐      ┌────────────────┐                      │
│ F-Stack 用户态栈│      │  Linux 内核栈   │                      │
│ (DPDK+FreeBSD)│      │  (并行附加栈)    │                      │
│  业务高速路径   │      │  本机/管理面     │                      │
└───────┬───────┘      └───────┬────────┘                      │
        │                      │                               │
        │ 远端 curl            │ 本机 curl                     │
        │ <DPDK_NIC_IP>:80    │ 127.0.0.1:80                  │
        ▼                      ▼                               │
    F-Stack 侧 200        内核侧 200                             │
                    │                                          │
            ff_native_fd_map[fstack_fd]=host_fd                │
            同一事件循环统一收发两栈事件                          │
                    └──────────────────────────────────────────┘
```

3.2 fd 三态路由

这是整个功能的核心模型。一个 fd 进来，按数值区间和映射表分成三种形态：

```
ff_* 入口(fd)
  ├─ ff_is_kernel_fd(fd)? (fd >= 0x40000000)
  │     是 ─►【单栈·仅内核】走 ff_host_*(real fd)
  │     否 ─► 走 F-Stack 原路径
  │              └─ ff_native_map_get(fd) > 0 ?
  │                   是 ─►【双栈】F-Stack 路径 + 再对 map[fd]=host_fd 双驱动
  │                   否 ─►【单栈·仅 F-Stack】（默认关/SOCK_FSTACK/连接 fd）
```

三类 fd 空间互不冲突：F-Stack fd < 65536，内核 encode fd ≥ 0x40000000，host fd 受 RLIMIT_NOFILE。

【注2】关键设计是"热路径不查 map"。accept 出来的连接 fd 一定是单栈的——F-Stack 侧连接返回原始 fd，内核侧连接返回 encode fd。之后 recv/send 只做一次 ff_is_kernel_fd 判断就路由了，不查映射表，数据热路径零额外开销。双建/双驱动只发生在 socket/bind/listen/close 这些一次性操作上。

3.3 双层开关保证零回归

```
编译期 gate：FF_KERNEL_COEXIST（lib/Makefile 默认注释关）
  ├─ 未定义 ──► 共存代码全部 #ifdef 排除，不编译
  │              SOCK_FSTACK/SOCK_KERNEL 宏不可见、ff_native_fd_map 不存在
  │              ► libfstack.a 与原 F-Stack 逐字节一致
  └─ 已定义 ──► 编译进共存能力
        └─ 运行期 gate：config [stack] kernel_coexist
              ├─ =0（默认）──► 双建/双驱动短路，仅建 F-Stack（零回归）
              └─ =1 ──► 自动双栈：默认双建/双驱动 + marker 单栈覆盖
```

三重零回归保证：编译宏关、运行期开关关、SOCK_FSTACK marker，三者任一满足就退化成纯 F-Stack。

4. 改造工作与遇到的问题

后续比较枯燥，不需要深入研究实现过程的可以跳过本节，直接看第 5 节怎么用。

4.1 走过的弯路：v3 纯内核旁路（已回退）

这个功能不是一步到位的，中间踩过一个方向性的大坑。

最早一版（v3，commit 0748eff94）把 `ff_socket(SOCK_KERNEL)` 直接接到纯宿主的 socket()，完全绕开 F-Stack。看似解决了"本机能通"，但这是根本性错误——它旁路了 F-Stack，违背了"F-Stack 始终在位"的铁律。性能基线报告也坐实了这个问题：v3 测的 A/B 两版本都是纯内核，根本没测"共存"。

回退后重新按正确范式做：应用跑在 F-Stack 上，per-fd 用 SOCK_KERNEL 附加走内核栈，两者同进程共存。

【注3】这个弯路值得记住：共存不是"要么 F-Stack 要么内核"的二选一，而是"F-Stack 为主、内核并行附加"。一旦做成旁路，性能基线、稳定性评估全都会失真。

4.2 v5：编译宏门控 + per-fd 二选一

回退后第一版正确实现是 v5（commit ba148589d），做了两件事：

- 用编译宏 FF_KERNEL_COEXIST 把全部共存代码包裹起来，lib/Makefile 默认关，保证宏关时 libfstack.a 与原 F-Stack 逐字节一致（nm 比对共存符号为 0）
- per-fd 二选一语义：带 SOCK_KERNEL 建内核 fd（编码成 ≥0x40000000 的高位 fd），否则走 F-Stack 原路径

这一版已经实测可用，但语义是"每个 fd 自己二选一"。想本机也通，得额外写一个 SOCK_KERNEL 的 socket，麻烦。

4.3 v6：默认升级为自动双栈

v6（commit 13b418191）把默认语义从"二选一"升级为"自动双栈"：

- 默认（无 marker）的 ff_socket 同时建 F-Stack fd + 内核 host fd，登记 ff_native_fd_map[fstack_fd]=host_fd，返回 F-Stack 原始 fd
- ff_bind/ff_listen/ff_close 对该双栈 fd 同时驱动两栈
- marker 变成"单栈覆盖"：SOCK_KERNEL 仅内核、SOCK_FSTACK 仅 F-Stack

核心新增是那张 65536 项的无锁映射表 ff_native_fd_map（仿 adapter 的 fstack_kernel_fd_map），以及 accept 的"单栈归属"——双栈 listen fd accept 返回单栈连接 fd，F-Stack 侧连接返回原始 fd、内核侧连接返回 encode fd。

4.4 踩到的坑：头改动没 clean 重编导致 ABI 偏斜

性能基线实测时踩了个构建卫生的坑：给 struct ff_config 的 stack 子结构加了 int kernel_coexist 字段后，改变了它后面 log 子结构（含 log.f）的偏移。而 lib 的 Makefile 不跟踪头依赖，增量构建残留了混用新旧 ff_config.h 布局的 .o——ff_log.o 用旧偏移读 log.f，读到了新布局里别的非零字段，fclose 直接段错误。

修复很简单：清掉全部 .o 和 libfstack.a 全量重编。但这暴露了一个规律——对 ff_config.h 这类结构头的改动，必须 clean 后全量重编 lib，增量编译会掩盖 ABI 偏斜。

4.5 踩到的坑：kqueue 模型应用感知不到内核侧事件

R7 落地后自动双栈对 ff_epoll_* 是完整的，但直接用 ff_kqueue/ff_kevent 的应用（比如 example/main.c 用的就是 kqueue 模型）感知不到内核侧连接。实测：内核 TCP 完成了握手、GET 进了内核缓冲并被 ACK（抓包 ack 73 吻合），但应用永不被唤醒去 accept 内核 listen fd，本机 curl 127.0.0.1:80 返回 http_code 000（6 秒超时）。

根因：ff_kqueue/ff_kevent 完全没有 FF_KERNEL_COEXIST 路由，只把 F-Stack listen fd 注册进 F-Stack kqueue，双栈 listen 的内核侧 host fd 从未进入任何事件后端。

修复（R9，commit 03f244ac1）：对称仿 ff_epoll 做 kqueue 共存——ff_kevent 的 changelist 里，ident 为内核 fd 或双栈 fd 的 EV_ADD/EV_DELETE 映射到 host epoll_ctl（EVFILT_READ↔EPOLLIN、EVFILT_WRITE↔EPOLLOUT），eventlist 先取内核就绪再合并 F-Stack 就绪。

4.6 踩到的坑：IPv6 双建端口冲突

还是 R9 发现的。开了 -DINET6 后，默认 ff_socket(AF_INET6) 双建，host 侧 IPv6 socket 绑 [::]:80 时，因为本机 net.ipv6.bindv6only=0，[::] 连带占用了 IPv4，跟同进程 host 侧的 0.0.0.0:80 冲突，实测 errno=98 EADDRINUSE，进程直接起不来。

修复：给 host 侧 IPv6 socket 设 IPV6_V6ONLY=1，让它只处理 IPv6、跟 host IPv4 同端口共存。

4.7 收口：补齐剩余接口的内核路由

R8（commit 55a84f313）补齐了 sendmsg/recvmsg/getpeername/getsockname/shutdown 的内核 fd 路由；R10（commit c6f5918b8 + 2422d12eb）又补齐了 readv/writev/ioctl/dup/dup2。其中有几个值得说的点：

- ioctl 的 request 编码在 Linux 和 FreeBSD 不同源，内核 host fd 必须用原始 Linux request 直传 host libc，不能经 linux2freebsd_ioctl 翻译
- dup2 一端内核 fd 一端 F-Stack fd 的"混栈"语义不成立，明确拒绝 errno=EINVAL，不臆造
- select 不共存：encode 内核 fd（≥0x40000000）远超 fd_set 的 FD_SETSIZE(1024)，装不进去，硬限制
- poll 也不共存：合并复杂度高、回归风险大，保守降级为文档限制

内核 fd 想多路复用，用 ff_epoll_* 或 ff_kqueue 就行。

4.8 性能无回归

这是最关心的点，实测数据（v6 双栈口径，真机 wrk）：

| 档位 | 共存关 A0 | 双栈开 A1 | Δ |
|------|----------:|----------:|------:|
| T1 (-t2 -c10) | 28,216 | 27,729 | −1.73% |
| T2 (-t4 -c100) | 202,805 | 206,219 | +1.68% |
| T3 (-t8 -c500) | 120,702 | 127,784 | +5.87% |

吞吐差异全落在 trial 噪声内，p99 基本相等。逻辑上也说得通——双建成本只在 listen socket 建立时一次性付出，keep-alive 连接的数据热路径单栈、不查 map，所以 F-Stack 业务快路径无可测量回归。

5. 如何使用、配置与效果

5.1 编译

默认编译不含共存代码，要开启得编译时加宏：

```bash
cd f-stack/lib && make clean && make FF_KERNEL_COEXIST=1 -j$(nproc)
```

应用侧如果想用 marker（SOCK_KERNEL/SOCK_FSTACK），编译应用时也要加 -DFF_KERNEL_COEXIST（否则这两个宏不可见）。只用默认双栈则不需要。

5.2 配置

config.ini 的 [stack] 段加 kernel_coexist：

```ini
[stack]
# 0=禁用(纯 F-Stack)，1=启用(默认 socket 自动双栈)
kernel_coexist = 1
```

注意：这个运行期开关只在编译宏开了 FF_KERNEL_COEXIST 时才生效。编译宏关，或者这里设 0，都是纯 F-Stack，零回归。

5.3 用法

默认双栈（什么都不用加）：

```c
int s = ff_socket(AF_INET, SOCK_STREAM, 0);   /* 双栈：F-Stack fd + 内核 host fd */
ff_bind(s, &addr80, sizeof(addr80));           /* 双驱动：两栈各 bind 80 */
ff_listen(s, backlog);                          /* 双驱动：两栈各 listen */
ff_epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev);        /* 双注册：kqueue + 内核 epoll */

/* 远端 curl <DPDK_NIC_IP>:80 走 F-Stack，本机 curl 127.0.0.1:80 走内核，皆可达 */
```

需要单栈时用 marker 覆盖：

```c
int konly = ff_socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);  /* 仅内核 */
int fonly = ff_socket(AF_INET, SOCK_STREAM | SOCK_FSTACK, 0);  /* 仅 F-Stack */
```

5.4 效果

功能正确性（真机实测，commit 13b418191）：

- 单 listen(80)：本机 curl 127.0.0.1:80 = 200（内核侧），远端 ssh → `<DPDK_NIC_IP>:80` = 200（F-Stack 侧）
- ss 能看到内核侧 80 监听，ff_netstat 能看到 F-Stack 侧 80 监听

零回归（三层保证）：

- 编译宏关：libfstack.a 共存符号为 0，与原 F-Stack 逐字节一致
- kernel_coexist=0：双建/双驱动运行期短路
- SOCK_FSTACK marker：仅 F-Stack

性能（第 4.8 节）：T1/T2/T3 三档吞吐差异全在噪声内，热路径不查 map。

5.5 已知限制

- select 不支持内核 fd（encode fd 装不进 fd_set），poll 也不共存——内核 fd 用 epoll/kqueue
- 单条连接不能真双工于两栈——默认双栈 connect 是"F-Stack 主 + 内核并发建连备援"，纯内核客户端用 SOCK_KERNEL
- 可观测统计（ff_stack_get_stats）当前未实现，两栈 fd 数/事件数看不了
- IPv6 依赖 host 侧 V6ONLY，本机 bindv6only 相关行为已在 R9 处理

延伸阅读：

- 完整 spec：docs/kernel_event_support_spec/zh_cn/（00-10 + plan-r9/plan-r10）
- 三层架构：docs/zh_cn/F-Stack_Architecture_Layer1_System_Overview.md
- 知识图谱：docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md（2A 节 FF_KERNEL_COEXIST delta）
- 相关 issue：#511/#585/#741/#849（本机 curl connection refused 场景）
