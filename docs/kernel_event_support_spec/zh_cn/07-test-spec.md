# 07 测试与性能基线规格

> **文档编号**：SPEC-KE-07
> **版本**：v6（native 自动双栈共存范式）
> **日期**：2026-06-17
> **状态**：编写中（R0-R6 已实测；R7 v6 用例待实测）
> **作用域**：编译宏零回归 + 自动双栈（默认双建/双驱动 + `ff_native_fd_map` + accept 归属 + 事件合并 + connect 双栈 + 真机双栈）的单元/集成/性能/编译宏测试方案与门禁。
> **对齐**：`tests/unit`（**cmocka**，*.c + *.ini）、`tests/integration`、覆盖率 `tests/run_full_coverage.sh`（lcov）。

---

## 1. 测试分层

| 层级 | 目录 | 框架/方式 | 覆盖目标 |
|---|---|---|---|
| 编译宏零回归 | `lib/` | `make` 双编译 + `nm`/`objdump` 符号比对 | 宏关→无共存符号（含 v6 新增 `ff_native_fd_map`）；宏开→符号出现（FR-12/NFR-1） |
| 单元测试 | `tests/unit/` | cmocka | 映射表 get/set/clear、默认双建、accept 单栈归属、事件合并、connect 双栈、零回归 |
| 集成测试 | `tests/integration/` 或 demo | 端到端进程 + 本机工具 + 远端 | **一 listen 多用**：F-Stack(DPDK) + 内核(loopback) 同端口双向可达 |
| 性能基线 | `tests/` | 压测 + 对比 | 自动双栈对 **F-Stack 业务快路径 + 单栈连接热路径** 无回归 |

---

## 1bis. 编译宏 `FF_KERNEL_COEXIST` 零回归测试（硬门禁）

| 编号 | 用例 | 步骤 | 通过标准 |
|---|---|---|---|
| MT-1 | 宏关符号零回归 | 默认 `cd lib && make`（clean 重编）→ `nm`/`objdump` | **不出现** `ff_host_*`(18 桥)/`ff_epoll_pairs`/`ff_epoll_host_ep`/**`ff_native_fd_map`/`ff_native_map_get/set/clear`**（v6 新增）；与原 F-Stack 符号/字节一致 |
| MT-2 | 宏关标记不可见 | 仅 `#include "ff_api.h"`（不定义宏）引用 `SOCK_KERNEL` | 编译报「未声明」 |
| MT-3 | 宏开符号出现 | `make FF_KERNEL_COEXIST=1`（clean）→ `nm` | 共存符号（含 `ff_native_map_*`）出现；APP 定义宏后见 marker |
| MT-4 | 双侧 CFLAGS 一致 | `HOST_CFLAGS`+`CFLAGS` 均含 `-DFF_KERNEL_COEXIST` | 两侧编译单元（host 侧 `ff_host_interface/ff_config/ff_epoll` + `ff_syscall_wrapper`）均编译进共存 |
| MT-5 | symlist 不变 | 对比宏开/关 `ff_api.symlist` | 无需改动（访问器/桥库内调用、inline 无导出） |

> **构建注记**：改 `ff_config.h` 等结构头须 clean 全量重编（lib/Makefile 不跟踪头依赖，ABI 偏斜，`10 §7`）。v6 加 `ff_native_fd_map` 于 `ff_host_interface.c`（**不改结构头**），但 MT-1/MT-3 仍各自 clean 重编以确保符号比对干净。**R9** 的 `ff_kqueue/ff_kevent` 共存改动在 `ff_syscall_wrapper.c`（复用 `ff_epoll_*` 已有 host 符号，不新增 host 桥），MT-1 宏关须确认 `ff_kqueue/ff_kevent` 无 `ff_host_epoll_*` 引用、size 与基线对齐。**R10** 新增 5 个 host 桥 `ff_host_readv/writev/ioctl/dup/dup2`（`ff_host_interface.c`，声明 `.h:178-184`），桥总数由 18 增至 23；MT-1 宏关须确认 `ff_readv/writev/ioctl/dup/dup2/select/poll` 无对应 `ff_host_*` 引用、无新增 host 桥符号、size 与基线对齐（impl 已验证宏关逐字节零回归）。

---

## 2. 单元测试用例（cmocka，宏开态）

| 编号 | 用例 | 断言 | 对应需求 | 状态 |
|---|---|---|---|---|
| UT-1 | `[stack] kernel_coexist=1/0` 解析 | 正确填充 `ff_config.stack.kernel_coexist` | FR-11 | v5 已实测 |
| UT-2 | 缺 `[stack]` | 默认 0 | FR-11/NFR-1 | v5 已实测 |
| UT-3 | `ff_is_kernel_fd`/`encode`/`real` | ≥BASE 判定、编解码互逆 | FR-8 | v5 已实测 |
| **UT-4** | **`ff_native_map_set/get/clear`（v6）** | set 后 get 返回 host_fd；clear 后 get 返回 0；越界返回 0 | FR-2 | **R7 待实测** |
| **UT-5** | **`ff_socket` 默认双建（v6）** | 共存开 + 无 marker → 返回 F-Stack fd（<BASE）；`ff_native_map_get(fd)==host_fd`（mock `ff_host_socket`） | FR-2 | **R7 待实测** |
| UT-6 | `ff_socket(SOCK_KERNEL)` | 返回 encode fd（≥BASE），无 map 项 | FR-8 | v5 已实测 |
| UT-7 | `ff_socket(SOCK_FSTACK)` / 共存关 | 返回 F-Stack fd，无 map 项（零回归路径） | FR-9/NFR-1 | v5 已实测 |
| **UT-8** | **`ff_bind/ff_listen` 双驱动（v6）** | 双栈 fd → `kern_*`/`sys_*` + `ff_host_*(map[s])` 各调用一次（mock 计数） | FR-3 | **R7 待实测** |
| **UT-9** | **accept 单栈归属（v6）** | 双栈 listen：F-Stack 有连接→返回原始 fd 无 map；F-Stack EAGAIN+内核有→返回 encode fd；两栈 EAGAIN→EAGAIN | FR-6 | **R7 待实测** |
| **UT-10** | **`ff_close` 双驱动（v6）** | 双栈 fd → `kern_close`+`ff_host_close(map)`+`ff_native_map_clear`（clear 后 get==0） | FR-7 | **R7 待实测** |
| UT-11 | `ff_epoll_ctl` 分流 | 内核 fd→host epoll；F-Stack fd→kqueue | FR-5 | v5 已实测 |
| **UT-12** | **双栈 listen 双注册（v6）** | `ff_epoll_ctl(ADD, 双栈 listen fd)` → kqueue 注册 fd + host epoll 注册 `map[fd]`，`ev.data` 透传两栈 | FR-5 | **R7 待实测** |
| UT-13 | `ff_epoll_wait` 合并 | 同时返回两栈事件、不丢 | FR-5 | v5 已实测 |
| **UT-14** | **connect 双栈（v6，待契约确认）** | 双栈 fd `ff_connect` → `kern_connectat`+`ff_host_connect(map)` 各一次（mock）；返回以 F-Stack 为主 | FR-10 | **R7 待实测 + 契约确认** |
| UT-15 | `type` 同置 `SOCK_KERNEL\|SOCK_FSTACK` | 走仅 F-Stack | 边界 | v5 已实测 |
| UT-16 | `ff_epoll_wait maxevents<1` | `-EINVAL`（`ff_epoll.c:221`） | 边界 | v5 已实测 |
| UT-17 | 热路径不查 map | 单栈连接 fd recv/send 只走 `ff_is_kernel_fd`（不调 `ff_native_map_get`，mock 计数=0） | NFR-2 | **R7 待实测** |
| **UT-18** | **双建部分失败（v6）** | `ff_host_socket` mock 失败 → 按 `05 §7` 契约（降级仅 F-Stack 或回滚），不泄漏 host fd | 边界 | **R7 待实测** |
| **UT-19** | **`ff_kevent` changelist 内核/双栈 fd 注册（R9）** | 双栈 listen fd `EV_ADD(EVFILT_READ)` → `ff_host_epoll_ctl(host_ep, ADD, map[fd], EPOLLIN)` 调用一次（mock 计数），`data`=应用面 fd；`EV_DELETE`→DEL | FR-5 | **R9 待实测** |
| **UT-20** | **`ff_kevent` eventlist 合成内核就绪（R9）** | mock host epoll 返回就绪 → 合成 `struct kevent`（`ident`=app fd 还原、`filter=EVFILT_READ`），与 `ff_kevent_do_each` F-Stack 事件合并、不丢、计数正确；`EPOLLHUP`→`EV_EOF` | FR-5 | **R9 待实测** |
| **UT-21** | **kqueue fd close 清配对（R9）** | `ff_close(kq)` → `ff_epoll_close_pair`/清 `ff_epoll_pairs`+关 host_ep（无内核 fd 泄漏） | FR-7 | **R9 待实测** |
| **UT-22** | **IPv6 host socket V6ONLY 共存（R9）** | `ff_socket(AF_INET6)` 双建 → host IPv6 socket `IPV6_V6ONLY==1`（getsockopt 验证或 mock setsockopt 计数）；host IPv6 `[::]:80` 与 host IPv4 `0.0.0.0:80` 同端口 bind 均成功（真实 loopback） | FR-3 | **R9 待实测** |
| **UT-23** | **kqueue 共存宏关零回归（R9）** | `FF_KERNEL_COEXIST` 关 → `ff_kqueue/ff_kevent` 仅原 F-Stack 路径，无 `ff_host_epoll_*` 调用 | NFR-1 | **R9 待实测** |
| **UT-24** | **`ff_host_readv`/`ff_host_writev`（R10）** | 真实 socketpair/pipe 多段 iov 读写，校验返回字节数与内容正确 | FR-readv/writev | **R10 待实测** |
| **UT-25** | **`ff_readv`/`ff_writev` 内核 fd 路由（R10）** | encode 内核 fd 经 `ff_readv/writev` 命中 `ff_host_readv/writev(real)`（mock 计数或真实 host fd 验证）；非内核 fd 仍走 `kern_readv/writev` | D12 | **R10 待实测** |
| **UT-26** | **`ff_host_ioctl` + `ff_ioctl` 内核 fd 路由（R10）** | 真实 socket `FIONBIO`/`FIONREAD` 经 `ff_host_ioctl` 生效；encode 内核 fd 经 `ff_ioctl` 用**原始 Linux request** 命中 `ff_host_ioctl`（不经 `linux2freebsd_ioctl`，mock 计数） | D13 | **R10 待实测** |
| **UT-27** | **`ff_dup`/`ff_dup2`（R10）** | `ff_host_dup` 后两 fd 同源可读写；`ff_dup` 内核 fd 返回 encode；`ff_dup2` 两端内核 fd→encode、**混栈拒绝 errno=EINVAL** | D14 | **R10 待实测** |
| **UT-28** | **R10 共存宏关零回归** | `FF_KERNEL_COEXIST` 关 → `ff_readv/writev/ioctl/dup/dup2/select/poll` 仅原 F-Stack 路径，无 `ff_host_readv/writev/ioctl/dup/dup2` 调用、无新符号 | NFR-1 | **R10 待实测（impl 已验宏关零回归）** |

> **编译宏条件**：UT-4/5/8/9/10/12/14/17/18、**R9 UT-19~23** 与 **R10 UT-24~28** 共存相关用例仅在 `FF_KERNEL_COEXIST` 开启时有效；宏关编译时条件编译排除或 skip。`tests/unit/` Makefile/用例须加宏门控。既有 `test_ff_epoll` 曾因链接缺 `ff_host_epoll_*` 加 no-op 桩——v6/R9/R10 须复核此桩在双态一致，并为 `ff_native_map_*`/kqueue 共存/`ff_host_readv/writev/ioctl/dup` 路径提供 mock/桩。`ff_select` 因 `FD_SETSIZE` 硬限制不实现共存，无对应 UT（仅文档限制）；`ff_poll` 用例视实现与否增减。

---

## 3. 集成测试用例（一 listen 多用为核心）

| 编号 | 场景 | 步骤 | 通过标准 | 对应 |
|---|---|---|---|---|
| **IT-1** | **自动双栈 listen** | demo 默认 `ff_socket`+`bind(80)`+`listen`（无 marker），coexist=1 | `ff_netstat`(F-Stack) 见 80 监听 **且** `ss -tlnp`(内核) 见 80 监听 | FR-2/FR-3/FR-4 |
| **IT-2** | **F-Stack 侧远端访问** | ssh 到 f-stack-client 机 `curl http://9.134.214.176:80` | HTTP 200（经 DPDK NIC） | FR-4/NFR-3 |
| **IT-3** | **内核侧本机访问** | 本机 `curl http://127.0.0.1:80` | HTTP 200（经内核栈，同一进程同一 listen） | FR-4 |
| IT-4 | 本机 ping | `ping <host_ip>` | 有回包 | FR-4 |
| **IT-5** | **统一事件双栈** | 同 epoll 同时收 F-Stack 侧 + 内核侧连接事件 | 两栈连接均被 accept 处理、不丢 | FR-5/FR-6 |
| IT-6 | marker 仅内核 | `SOCK_KERNEL` socket | 仅内核监听（`ss` 见、`ff_netstat` 不见） | FR-8 |
| IT-7 | marker 仅 F-Stack | `SOCK_FSTACK` socket | 仅 F-Stack（零回归） | FR-9 |
| IT-8 | config 开关 | `kernel_coexist=0` 重启 | 仅 F-Stack 监听、`ss` 无 80 | FR-11/NFR-1 |
| **IT-9** | **客户端双栈 connect** | 默认 fd `connect`（契约确认后）/ `SOCK_KERNEL` connect 127.0.0.1 | 按 `05 §6` 契约连通 | FR-10 |
| IT-10 | 长稳/泄漏 | 大量短连接反复开关（含两栈 accept） | fd 数稳定、`ff_native_fd_map`/`ff_epoll_pairs` 无泄漏 | FR-7 |
| **IT-11** | **kqueue 模型内核侧可达（R9，P2 验收）** | plain helloworld（`ff_kqueue`+`ff_kevent`，`example/main.c` 模型），coexist=1，本机 `curl http://127.0.0.1:80` | HTTP 200 size=438（修复前实测 000）；同进程 F-Stack 侧 `ssh f-stack-client→9.134.214.176:80=200` 不回归 | FR-5/FR-6 |
| **IT-12** | **INET6-on 双建启动（R9，P1 验收）** | `-DINET6` 构建 helloworld，coexist=1 启动 | 进程成功启动（v4+v6 listen 均建立，`ff_bind` 无 errno=98）；`ss`/`ff_netstat` 见 v4+v6 监听；抓包确认内核侧 200 | FR-3 |
| **IT-13** | **内核 fd readv/writev/ioctl 真机（R10）** | INET6-off helloworld，coexist=1，对受管内核 fd（127.0.0.1 连接）做 readv/writev/ioctl | readv/writev 字节正确、ioctl（如 `FIONBIO`）生效；内核侧 `curl 127.0.0.1:80=200` | D12/D13 |
| **IT-14** | **R10 零回归** | coexist=1 helloworld 同进程 F-Stack 侧 `ssh f-stack-client→9.134.214.176:80` | HTTP 200 不回归（readv/writev/ioctl/dup 改动不影响 F-Stack 业务面） | NFR-1/NFR-3 |

> 进程清理 `/data/workspace/kill_process.sh`，临时文件 `/data/workspace/rm_tmp_file.sh`，权限 `/data/workspace/chmod_modify.sh`。

### 3bis. 真机双栈方案（Q4=B）

- **双网卡隔离**：DPDK 独占网卡（≠eth1，已在 config.ini 配置）；eth1 内核驱动供 ssh 旁路。
- **单 listen(80) demo**：改造 `example/helloworld_stacksel` 或新建（默认双栈 `ff_socket`/`bind(80)`/`listen`）。
- **F-Stack 侧验证**：ssh 到 f-stack-client 机器（与 DPDK 网卡同 /21 直连），`curl http://9.134.214.176:80` → 经 DPDK NIC 命中 F-Stack 侧。
- **内核侧验证**：被测机本机 `curl http://127.0.0.1:80` → 经内核栈命中内核侧 listen。
- **双向确认**：`ff_netstat`（F-Stack）+ `ss -tlnp`（内核）各见一个 80 监听 → 证明一 listen 双栈。
- **config 不提交**：本地 `lcore_mask`/port IP/`idle_sleep` 等本机值测后回滚，提交仅 `[stack]` 特性改动。
- IP 掩码：client stdout 经源端 sed 掩码后落盘（`9.134.214.176→192.168.1.1` 等）。

---

## 4. 性能基线

| 编号 | 指标 | 方法 | 门禁 |
|---|---|---|---|
| PERF-1 | F-Stack 业务快路径回归 | 自动双栈关 vs 开，只压 F-Stack 侧（远端经 DPDK NIC） | 偏差 ≤ 噪声阈值（NFR-2） |
| PERF-2 | 默认路径零开销 | 双建/双驱动对 F-Stack 创建/连接路径影响 | 零/可忽略（NFR-1） |
| PERF-3 | 内核侧旁路吞吐 | 本机 curl 并发内核侧 listen | 满足管理面预期（非高速路径） |
| **PERF-4** | **热路径不查 map（v6）** | 单栈连接 recv/send 在 coexist 开/关下吞吐对比 | 连接热路径零额外开销（NFR-2，对应 UT-17） |

> v6 性能核心：证明自动双栈不拖累 F-Stack 业务快路径，且**单栈连接热路径不因双栈机制引入 map 查询开销**（recv/send 只一次 `ff_is_kernel_fd`）。

---

## 5. 覆盖率与门禁标准

- 复用 `tests/unit/run_coverage.sh`/`tests/run_full_coverage.sh`（lcov）。
- **门禁标准**：
  1. MT-1~MT-5 全通过（宏关无共存符号含 `ff_native_fd_map`；宏开符号出现；symlist 不变）。
  2. UT 全通过（宏开态，含 v6 UT-4/5/8/9/10/12/14/17/18）；新增代码行覆盖率达标。
  3. IT-1（自动双栈 listen）+ IT-2/IT-3（F-Stack 侧 + 内核侧双向可达）+ IT-5（统一事件）真机实测成功；环境不具备真实 NIC 时 F-Stack 侧 skip+证据，内核侧 loopback 必测。
  4. PERF-1/2/4 无回归。
  5. config 关/`SOCK_FSTACK`/宏关时与纯 F-Stack 一致（NFR-1/NFR-3）。
  6. **connect 契约确认**：`05 §6` 草案经用户确认后 UT-14/IT-9 方可定稿判 PASS。
  7. R8 新增 `sendmsg/recvmsg/getpeername/getsockname/shutdown` 内核 fd 路由须单测覆盖；`readv/writev/ioctl` 由 **R10** 补齐内核 fd 路由（D12-D13，见第 9 项）。
  8. **R9**：UT-19~23（kqueue changelist 注册/eventlist 合成/close 清配对/IPv6 V6ONLY/宏关零回归）全通过；**IT-11（kqueue 模型内核侧 `curl 127.0.0.1:80=200`）+ IT-12（INET6-on 双建成功启动、抓包内核侧 200）真机实测成功**，F-Stack 侧 9.134.214.176:80=200 不回归。`ff_kevent` 内核 fd 仅 `EVFILT_READ/WRITE`（非 READ/WRITE filter 不经 host epoll）为 R9 已知限制，须文档/用例明示。
  9. **R10**：UT-24~28（`ff_host_readv/writev/ioctl/dup/dup2` host 桥 + `ff_readv/writev/ioctl/dup/dup2` 内核 fd 路由 + 宏关零回归）全通过；**IT-13（内核 fd readv/writev/ioctl 真机正确、内核侧 200）+ IT-14（F-Stack 侧 200 不回归）实测成功**。已确定（impl 实测）：`ff_select` 因 encode 内核 fd≫`FD_SETSIZE`(1024) 为**硬限制**、`ff_poll` 因合并复杂度**保守不实现**，两者均降级文档限制；`ff_dup2` 混栈拒绝 **errno=EINVAL**；`ioctl` 双栈 fd 同驱动 **R10.1 已实现**（`FIONBIO`/`FIOASYNC` 同步配对 host fd）——均须文档/用例明示。
- 任一项失败 → bounce 打回上一里程碑（同步骤≤3 次，超限转人工）。

---

## 6. 交叉验证要求
- 所有测试实际执行取证（日志/抓包/`ss`/`ff_netstat`/覆盖率），禁止臆测。
- **必须实测「一 listen 双栈」**：同一进程同一 `listen(80)` 在 F-Stack 与内核栈各被独立访问成功（NFR-3 F-Stack 在位 + 内核并行附加）。
- 客户端用例抓包确认走对应栈（DPDK NIC vs 内核）。
