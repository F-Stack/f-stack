# 现状剖析：F-Stack 已有的"流量回内核"机制（02-current-state-analysis.md）

> **文档编号**：SPEC-KE-02
> **版本**：v0.1 草稿
> **日期**：2026-06-15
> **状态**：编写中（证据均来自实际 grep/read，路径相对 `/data/workspace/f-stack/`）
> **作用域**：现状机制实测，**以实际代码为准**，与文档/README 冲突处在第 5 节显式记录
> **数据来源**：`code-explorer` 子 agent 实测 + Leader 补充实测

---

## 0. 结论速览

F-Stack 当前已存在**三类**"让部分流量/socket 回到内核协议栈"的机制，分流粒度各不相同：

| 机制 | 名称 | 层次 | 分流粒度 | 关键开关 |
|---|---|---|---|---|
| **A** | nginx `kernel_network_stack` | 应用层（仅 nginx） | per-server / per-upstream | nginx.conf 指令 |
| **B** | `FF_KERNEL_EVENT` | LD_PRELOAD syscall hook 层 | per-fd（仅 epoll 事件镜像） | 编译宏 |
| **C** | **KNI（virtio-user exception path）** | F-Stack 数据面（lib 层） | per-packet（按端口/过滤规则） | `config.ini [kni]` + 运行时 `FF_KNICTL` |

**机制 C 是与本特性（本机 ping/curl）最直接相关的现成能力**：它在报文级把"不属于 F-Stack 业务"的包送回内核，使本机内核协议栈可正常收发。本节逐一给出代码级证据。

---

## 1. 机制 A —— nginx `kernel_network_stack`（应用层 per-server 开关）

### 1.1 指令注册 / 字段绑定 / 默认值

**HTTP 子系统**（`NGX_HAVE_FSTACK` 保护）：
- 命令表注册：`app/nginx-1.28.0/src/http/ngx_http_core_module.c:297-304`
  ```c
  #if (NGX_HAVE_FSTACK)
      { ngx_string("kernel_network_stack"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_core_srv_conf_t, kernel_network_stack), NULL },
  #endif
  ```
- 字段定义：`src/http/ngx_http_core_module.h:205-207`（`ngx_flag_t kernel_network_stack;`）
- create_srv_conf 初值 `NGX_CONF_UNSET`：`src/http/ngx_http_core_module.c:3492-3494`
- merge_srv_conf 默认 `0`（注释 "By default, we set up a server on fstack"）：`:3538-3542`

**Stream 子系统**：注册 `src/stream/ngx_stream_core_module.c:80-87`；create `:719-721`；merge 默认 0 `:776-780`；字段 `src/stream/ngx_stream.h:168-170`。

**Mail 子系统**：注册 `src/mail/ngx_mail_core_module.c:67-74`；create `:189-191`；merge 默认 0 `:232-236`；字段 `src/mail/ngx_mail.h:122-124`。

### 1.2 开关如何实际分流（读取点）

开关值在 listen/upstream 创建时被复制到一个 1-bit 字段 `belong_to_host`，再沿"监听→连接→事件"传播，最终在 **socket() 标志** 与 **事件注册** 两处实际决定走哪套栈。

- **开关 → 字段**：
  - 监听侧：HTTP `src/http/ngx_http.c:1889-1891`（`ls->belong_to_host = cscf->kernel_network_stack;`）；Mail `src/mail/ngx_mail.c:350-352`；Stream `src/stream/ngx_stream.c:1048-1050`。
  - 上游侧：HTTP proxy `src/http/modules/ngx_http_proxy_module.c:1050-1052`；Stream proxy `src/stream/ngx_stream_proxy_module.c:465-467`。
- **字段定义**：连接 `src/core/ngx_connection.h:92-94`（`unsigned belong_to_host:1;`）；事件 `src/event/ngx_event.h:139-141`；peer `src/event/ngx_event_connect.h:71-73`。
- **分流点 1（主动连接 socket 标志）**：`src/event/ngx_event_connect.c:41-53`
  ```c
  #if (NGX_HAVE_FSTACK)
      if (!pc->belong_to_host)
          s = ngx_socket(pc->sockaddr->sa_family, type | SOCK_FSTACK, 0); // fstack
      else
          s = ngx_socket(pc->sockaddr->sa_family, type, 0);               // kernel
  #endif
  ```
  即 `belong_to_host=1` → 不带 `SOCK_FSTACK` → 走内核栈。
- **分流点 2（监听 socket 跳过/打标）**：`src/core/ngx_connection.c:22-51`（`ngx_ff_skip_listening_socket`），worker 进程若 `ls->belong_to_host` 则跳过 fstack 处理，否则 `*type |= SOCK_FSTACK`（约 :45-47）。
- **分流点 3（事件注册双栈分发）**：`src/event/ngx_event.h:408-424`
  ```c
  if (1 == ev->belong_to_host)
      return ngx_ff_host_event_actions.add(...);   // 内核 epoll
  else
      return ngx_event_actions.add(...);            // fstack kqueue
  ```
  内核侧事件模块实现：`src/event/modules/ngx_ff_host_event_module.c`；外部声明 `src/event/ngx_event.h:194-196`。
- **字段传播**：accept `src/event/ngx_event_accept.c:235-237`；监听初始化 `src/event/ngx_event.c:886-890`；按 fd 反推 `src/core/ngx_connection.c:1309-1311`（`is_fstack_fd(s) ? 0 : 1`）；channel 进程间固定走内核 `src/os/unix/ngx_channel.c:216-218`；UDP/QUIC `src/os/unix/ngx_udp_sendmsg_chain.c:227-228`、`src/event/quic/ngx_event_quic_output.c:457-458 / 735-736`。
- **进程角色常量**：`src/os/unix/ngx_process_cycle.h:42-44`（`NGX_FF_PROCESS_PRIMARY/SECONDARY`）。

### 1.3 小结
机制 A 是**应用配置粒度**的双栈方案：依赖 nginx 自身被改造为"双事件循环"（fstack kqueue + 内核 epoll 并存），通过 `SOCK_FSTACK` 标志在 socket 创建时选栈。**可借鉴点**：1-bit 标志沿连接/事件传播 + socket() 选栈 + 双事件后端分发，是干净的"per-连接选栈"范式；**局限**：高度耦合 nginx 源码，非通用 lib。

---

## 2. 机制 B —— `FF_KERNEL_EVENT`（LD_PRELOAD syscall hook 层）

### 2.1 编译开关
- `adapter/syscall/Makefile:28-30`（说明：启用后 `epoll_create/ctl/wait` 同时调用 f-stack 与系统 API，用于类 Nginx 场景）；`:54-56`（`ifdef FF_KERNEL_EVENT → CFLAGS += -DFF_KERNEL_EVENT`）。
- `Makefile:20` 注明 `FF_PRELOAD_POLLING_MODE` 仅支持 freebsd socket，**不支持** `FF_KERNEL_EVENT`。

### 2.2 实现链路（`adapter/syscall/ff_hook_syscall.c`）
- fd 映射表：`:255-258`（`int fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES]`，`FF_MAX_FREEBSD_FILES=65536`）—— fstack fd → 内核 fd。
- `ff_hook_close`：`:1874-1880`，fstack fd 关闭后若 `fstack_kernel_fd_map[fd]` 存在则 `ff_linux_close` 内核侧 fd（修复内核 epoll fd 泄漏）。
- `ff_hook_epoll_create`：`:1993-2001`，同时 `ff_linux_epoll_create` 建内核 epoll，存入 `fstack_kernel_fd_map[ret]`。
- `ff_hook_epoll_ctl`：`:2016-2020`，对非 fstack fd（`!is_fstack_fd(fd)`）走内核 epoll 分支。
- `ff_hook_epoll_wait`：`:2082` 处的版本仅在 `FF_PRELOAD_POLLING_MODE && !FF_KERNEL_EVENT` 编译；`FF_KERNEL_EVENT` 下 `:2212-2218` 要求 `maxevents>=2`，`:2324-2399` 先调用内核 `ff_linux_epoll_wait`（timeout=0）再把 `kernel_ret` 合并进 fstack 的 `ret`。

### 2.3 内核侧封装（`adapter/syscall/ff_linux_syscall.c`，真实存在）
`ff_linux_socket:81`、`ff_linux_bind:88`、`ff_linux_listen:96`、`ff_linux_shutdown:102`、`ff_linux_getsockname:107`、`ff_linux_getpeername:113`、`ff_linux_getsockopt:119`、`ff_linux_setsockopt:125`、`ff_linux_accept:131`、`ff_linux_accept4:137`、`ff_linux_connect:144`、`ff_linux_close:217`、`ff_linux_ioctl:223`、`ff_linux_fcntl:228`、`ff_linux_epoll_create:233`、`ff_linux_epoll_ctl:239`、`ff_linux_epoll_wait:247`、`ff_linux_fork:255`、`ff_linux_select:262`。

### 2.4 关键事实
- 机制 B 的内核镜像**仅覆盖 epoll 事件路径**（`epoll_create/ctl/wait/close`）。`ff_hook_socket:379-427`、`ff_hook_bind:429`、`ff_hook_connect:847` 等普通 socket 钩子**未**出现 `FF_KERNEL_EVENT` 分支（grep 仅命中 close/epoll）——即它**不是**把普通业务 socket 双写到内核，而是让一个 epoll 既能等 fstack 事件、又能等内核 fd 事件（如监听内核侧管理 fd）。
- **可借鉴点**：`fstack_kernel_fd_map` 这种"用户态 fd ↔ 内核 fd"映射 + 事件合并，是"同一个 epoll 同时服务两套栈"的通用做法；**局限**：仅 epoll，未覆盖 read/write/connect 等数据路径的内核分流。

---

## 3. 机制 C —— KNI / virtio-user exception path（lib 数据面，**与本特性最相关**）

### 3.1 配置开关（`config.ini:250-267`，`[kni]` 段）
```ini
# if enabled and method=reject, 不属于下列 tcp_port/udp_port 的包 → 转内核
# 若 method=accept, 属于下列端口的包 → 转内核
#[kni]
#enable=1
#method=reject
#tcp_port=80,443
#udp_port=53
#console_packets_ratelimit=0 / #general_packets_ratelimit=0 / #kernel_packets_ratelimit=0
```
即：开启 KNI 后，可用 `method=reject/accept` + 端口列表，把"非业务流量"（含 ICMP/ping、本机 ssh、ospf/arp 等）放行到内核栈。

### 3.2 数据面实现（`lib/ff_dpdk_if.c`）
- 全局开关与状态：`enable_kni`（`:74`）、`kni_accept`（`:75`）、`knictl_action`（`:76`，默认 `FF_KNICTL_ACTION_DEFAULT`）。
- 初始化：`init_kni()` `:542`；启用时端口数翻倍（每物理口配一个 virtio_user 口）`:608-611`；启动调用 `:1393-1398`（`enable_kni = ff_global_cfg.kni.enable; if (enable_kni) init_kni();`）。
- 过滤门控：`:1581-1587`（未启用 KNI → `FILTER_UNKNOWN`）。
- **报文级分流**（核心）：`:1779-1801`
  - `FF_KNICTL_ACTION_ALL_TO_KNI` → 全部入 KNI（送内核）；
  - `FF_KNICTL_ACTION_ALL_TO_FF` → 全部走 F-Stack；
  - `FF_KNICTL_ACTION_DEFAULT` → 按 `filter==FILTER_KNI && kni_accept` 或 `(FILTER_UNKNOWN||>=FILTER_OSPF) && !kni_accept` 决定是否 `ff_kni_enqueue` 送内核。
- 主循环中处理 KNI 收发：`:2417-2420`（`ff_kni_process(port_id, queue_id, ...)`）。

### 3.3 KNI 底层已改为 virtio-user（`lib/ff_dpdk_kni.c`）
- `ff_kni_init()` `:377`，在 `:450-466` 通过 **virtio_user vdev** 建立 exception path：
  ```c
  /* to add virtio port for exception path(KNI),
     see https://doc.dpdk.org/guides/howto/virtio_user_as_exception_path.html */
  snprintf(port_name, ..., "virtio_user%u", port_id);
  snprintf(port_args, ..., "path=/dev/vhost-net,queues=1,queue_size=%u,iface=veth%d,mac=...");
  rte_eal_hotplug_add("vdev", port_name, port_args);   // :466
  ```
- `kni_process_tx` `:136-159`：`rte_eth_tx_burst` 把包发到 virtio_user 口（→ 内核 veth）。
- `kni_process_rx` `:173-184`：从 virtio_user 口 `rte_eth_rx_burst`，再 `rte_eth_tx_burst` 到物理口（内核 → 网线）。
- `ff_kni_process` `:493-499`：先 tx 后 rx。
- `kni_interface_stats.port_id` 注释 `:73` 明确 "port id of dev or **virtio_user**"。

### 3.4 运行时控制 API（`lib/ff_msg.h`）
- 消息类型 `FF_KNICTL`（`:47`）；命令 `FF_KNICTL_CMD_GET/SET`（`:112-116`）；动作 `FF_KNICTL_ACTION_DEFAULT/ALL_TO_KNI/ALL_TO_FF`（`:118-123`）；参数 `struct ff_knictl_args { int kni_cmd; int kni_action; }`（`:125-127`）。即可在运行时通过 IPC 动态切换"全部走内核 / 全部走 fstack / 默认按规则"。

### 3.5 小结
机制 C 已经是一个**报文级、可运行时调控**的"用户态栈 ↔ 内核栈"分流通道，底层用 **virtio-user + /dev/vhost-net + veth**（DPDK 官方 exception path 方案）。**它已经能支撑"DPDK 接管网卡后本机仍可 ping/curl"**（把 ICMP 与本机端口流量 reject 到内核）。本特性的 lib 化，应以机制 C 为数据面基座，向上补齐"统一的本地 socket/fd/event 编程接口"。

---

## 4. F-Stack 对外 fd/event API（lib 层，供方案设计参考）
- 内核侧封装函数集中在 `adapter/syscall/ff_linux_syscall.c`（见 2.3）。
- KNI 运行时控制经 `lib/ff_msg.h` 的 `FF_KNICTL` 消息族（见 3.4）。
- 数据面收发分流在 `lib/ff_dpdk_if.c` 与 `lib/ff_dpdk_kni.c`、`lib/ff_veth.c`（待 04 文档进一步展开 socket API 选型）。

> 说明：F-Stack 对应用的 socket/epoll/kevent 导出 API（`ff_socket`/`ff_epoll_*`/`ff_kevent` 等，通常在 `lib/ff_api.h`）将在 `05-interface-design.md` 中结合目标 lib 接口一并精确化，本节不展开以免臆测。

---

## 5. 交叉验证差异清单（文档/README vs 实际代码，**以代码为准**）

| # | 描述出处 | 文档说法 | 实际代码 | 结论 |
|---|---|---|---|---|
| D1 | 三层架构文档 Layer3（`docs/...Layer3...` 约 421 行，称 `rte_kni_init()`） | F-Stack KNI 基于 `rte_kni_init()` | `lib/ff_dpdk_kni.c:450-466` 使用 `rte_eal_hotplug_add("vdev","virtio_user…")`，**无** `rte_kni_init` 调用 | KNI 已迁移为 **virtio-user exception path**（因 DPDK 23.11 移除 rte_kni）。**以代码为准**，Layer3 文档过时，需在新文档中标注 |
| D2 | `adapter/syscall/README.md` + `ff_hook_syscall.c:2078-2081` 注释 | "首版不支持 `ff_linux_epoll_wait`（避免引入延迟）" | `ff_hook_syscall.c:2324-2399` 在 `FF_KERNEL_EVENT` 下**确实调用** `ff_linux_epoll_wait`（`ff_linux_syscall.c:247` 有实现），以 timeout=0 调用并合并结果 | 当前实现**已调用** `ff_linux_epoll_wait`。**以代码为准**，README/注释为历史遗留 |
| D3 | 直觉/部分资料认为 `FF_KERNEL_EVENT` 会把所有 socket 双写内核 | —— | `ff_hook_socket/bind/connect` 无 `FF_KERNEL_EVENT` 分支，仅 epoll 路径镜像 | 机制 B 仅镜像 epoll 事件，不双写数据 socket |

> 上述差异将在 `04-architecture-design.md` 选型时显式引用；本特性方案**不得**依据 Layer3 文档的 `rte_kni_init` 旧描述。
