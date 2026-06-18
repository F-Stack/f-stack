# R9 计划：FF_KERNEL_COEXIST 双栈共存 —— ff_kqueue/ff_kevent 共存支持 + IPv6 双建启动修复

> 本文件为 R9 里程碑的完整执行计划（plan.md）。历史 R1-R8 见同目录 `plan.md`。
> 工作分支 `feature/1.26`。全程：实证优先（代码/抓包/errno 三重交叉验证，不臆测）、代码为准、门禁失败打回上一步（单步 bounce≤3，超则停转人工）、rm/kill/chmod 走 `/data/workspace/{rm_tmp_file.sh,kill_process.sh,chmod_modify.sh}`、lib 注释精简、commit message 英文 1-3 句、config.ini 本地测试值不入库。

---

## 1. 背景与人工测试发现的两个问题

`config.ini [stack] kernel_coexist=1`、lib 以 `FF_KERNEL_COEXIST=1` 构建后，运行 `example/main.c` 编译的 helloworld，人工测试发现：

- **P1（IPv6 双建启动失败）**：`-DINET6` 构建时，`ff_bind(sockfd6, [::]:80)` 失败导致进程退出、无法启动。
- **P2（内核侧无数据返回）**：关闭 INET6 重编后，DPDK 网卡侧（client 压 `9.134.214.176`）正常；本机 `curl 127.0.0.1:80` TCP 可建立但无数据返回（无 HTTP 200）。

## 2. 根因（已实证锁定，代码 + 抓包 + errno 交叉验证）

### P1 根因
- `lib/ff_syscall_wrapper.c::ff_bind`（L1703-1709）双驱动：F-Stack bind 成功后调 `ff_host_bind(hfd)`，失败即 `return -1`。
- 本机 `net.ipv6.bindv6only = 0`（实测）→ host IPv6 socket 绑 `[::]:80` 会连带占用 IPv4 → 与已绑的 host IPv4 `0.0.0.0:80`（sockfd 双建产生）冲突。
- **实测 errno**：`ff_bind failed, sockfd6:1026, errno:98, Address already in use`（EADDRINUSE）。
- 结论：双栈共存下，host 侧 IPv6 socket 未设 `IPV6_V6ONLY=1`，与同端口 host IPv4 socket 冲突。

### P2 根因
- `example/main.c` 使用 `ff_kqueue()` + `ff_kevent()` 事件循环。`ff_socket(AF_INET,...)` 无标记 → 双建（F-Stack + host，host 已 `0.0.0.0:80` LISTEN，实测 `ss` 确认）。
- `EV_SET(sockfd, EVFILT_READ)` + `ff_kevent(kq,...)` **只把 F-Stack listen fd 注册进 F-Stack kqueue**。
- `lib/ff_syscall_wrapper.c` 中 `ff_kqueue`/`ff_kevent`/`ff_kevent_do_each` **完全没有 FF_KERNEL_COEXIST 路由/双注册**（仅 `ff_epoll.c` 有）。
- 故内核侧（127.0.0.1）连接：内核 TCP 完成握手、GET 入内核缓冲并被 TCP 层 ACK（抓包 `ack 73` 实测吻合），但应用永不被唤醒去 `ff_accept` 该内核 listen fd → 永不 read/write → 无 200。
- **实测**：内核侧 `curl 127.0.0.1:80` = `http_code=000`（6s 超时）；F-Stack 侧 client 压 `9.134.214.176` = `http_code=200 size=438`。
- 结论：`ff_kqueue/ff_kevent` 系列未支持双栈共存（与人工判断一致）。

## 3. 修复方案（以代码为准，对称仿照已有 ff_epoll 共存范式）

### P1 方案
在双栈共存路径中，对 host 侧 IPv6 socket 设置 `IPV6_V6ONLY=1`，使其只处理 IPv6、与 host IPv4 同端口共存。落点候选（执行阶段以代码实测择优，禁臆测）：
- 优先在 `ff_socket` 双建 host IPv6 socket 后、或 `ff_host_socket` 内对 `domain==AF_INET6/LINUX_AF_INET6` 的 host socket `setsockopt(IPV6_V6ONLY,1)`；
- 评估是否需要让 host bind 失败"非致命"（best-effort，仿 `ff_connect`），但优先用 V6ONLY 从根上消除冲突，保持 bind 失败仍可诊断。
- 验收：INET6-on helloworld 在 coexist=1 下成功启动（v4+v6 listen 均建立），不回归 coexist=0 / 纯 F-Stack。

### P2 方案：ff_kqueue/ff_kevent 共存（核心）
对称仿照 `ff_epoll.c` 的 `ff_epoll_pairs[kq→host_ep]` 惰性配对机制（外网已证 F-Stack epoll 即基于 kqueue 封装，可复用同一基础设施）：
- **注册**：`ff_kevent` 处理 changelist 时，对 ident 为内核 fd（`ff_is_kernel_fd`）或双栈 fd（`ff_native_map_get>0`）的 EV_ADD/EV_DELETE，把对应 host fd（`EVFILT_READ→EPOLLIN` / `EVFILT_WRITE→EPOLLOUT`）注册/反注册进与该 kq 配对的 host epoll；内核 fd-only 变更不下发 F-Stack kqueue。
- **等待**：`ff_kevent`（eventlist）先非阻塞轮询 host epoll，把就绪 host 事件合成 `struct kevent`（ident=应用注册的 fd：双栈用 F-Stack fd、内核-only 用 encode fd；filter=READ/WRITE；EV_EOF 映射 EPOLLHUP/ERR），再调 `ff_kevent_do_each` 填 F-Stack 事件，合并计数。
- **app fd 还原**：注册进 host epoll 时用 `epoll_event.data` 存"应用面 fd"，等待时直接还原为 `kevent.ident`，使 demo 的 `clientfd==sockfd` 与 `EVFILT_READ` 分支照常 accept/read/write（这些入口已 coexist 路由到 `ff_host_*`）。
- **关闭**：复用/对齐 `ff_epoll_close_pair`（`ff_close` 已调用），确保 kq 关闭释放配对 host epoll。
- 全程 `#ifdef FF_KERNEL_COEXIST` 门控，宏关逐字节零回归。
- 验收：plain helloworld（kqueue，coexist=1）内核侧 `curl 127.0.0.1:80=200 size=438`，且 F-Stack 侧 `9.134.214.176:80=200` 不回归。

## 4. Agent Team 与里程碑（门禁失败打回上一步，单步 bounce≤3，超则停转人工）

team：`fstack-kqueue-coexist-r9`。leader 统筹；子 agent：spec-writer / impl / build / reviewer / tester / gatekeeper。

- **M0 调研冻结**（已完成）：根因实证（P1 errno=98、P2 内核侧 000 / F-Stack 侧 200）、ff_epoll 范式、外网调研、本计划落盘。
- **M1 spec 修订**：spec-writer 修订 `kernel_event_support_spec/{zh_cn,}/` 02/04/05/06/07/08，新增 R9（kqueue/kevent 共存 + IPv6 V6ONLY），收敛"D8 readv/writev/ioctl"与 kqueue 限制项。门禁：中英一致、与代码计划一致。
- **M2 实现**：impl 子 agent 用最小 diff 实现 P1（IPV6_V6ONLY）+ P2（kqueue/kevent 共存），全程宏门控、lib 注释精简。门禁：reviewer 通过路由完整性/宏门控/注释规约。
- **M3 编译零回归**：宏开/宏关双编译 `-Werror`；宏关 nm 无新符号且 `libfstack.a` size 对齐基线（逐字节零回归）。失败打回 M2。
- **M4 单测**：cmocka 在 `tests/unit` 增 kqueue 共存 + IPv6 V6ONLY 用例（宏门控，真实 loopback），跑双态 test_p1。失败打回 M2。
- **M5 真机验证**：停/重编/重启 helloworld（kill 走脚本）：
  - INET6-off coexist=1：内核侧 `curl 127.0.0.1:80=200 size=438` + F-Stack 侧 client `9.134.214.176:80=200` 不回归。
  - INET6-on coexist=1：进程成功启动（v4+v6 listen），抓包确认内核侧 200。
  - config 测后回滚 `kernel_coexist`/本机值，不入库。失败打回 M2。
- **M6 文档**：spec-writer 同步 `docs/`（英文）+ `docs/zh_cn/`（中文）三层架构文档与知识图谱（Layer1-3 + KNOWLEDGE_GRAPH_WIKI + Summary/README）：补 kqueue/kevent 共存与 IPv6 V6ONLY，更新行数/版本。门禁：中英一致、无残留旧值、围栏闭合。
- **M7 门禁+提交**：gatekeeper 汇总全门禁（双编译零回归 + 单测双态 + 真机 v4/v6/内核/F-Stack + reviewer 复核）。全 PASS 后英文简短 commit（lib+tests+docs，不含 config.ini）。

## 5. 测试方案
- 单测（cmocka，宏门控，真实 loopback）：kqueue EV_ADD 内核/双栈 fd → host epoll 注册；ff_kevent 合成内核就绪事件；IPv6 host socket V6ONLY 后与 IPv4 同端口共存 bind 成功。
- 真机（实测，不臆测）：见 M5。本机内核栈测 `127.0.0.1`（lo）；DPDK 网卡 `9.134.214.176` 经 `ssh f-stack-client` 测。
- 零回归：宏关双编译逐字节；coexist=0 行为不变。

## 6. 交付文档清单
- spec（中英）：`kernel_event_support_spec/{zh_cn,}/02,04,05,06,07,08` + 本 plan。
- 三层架构（中英）：`docs/{zh_cn,}/F-Stack_Architecture_Layer{1,2,3}_*.md`、`0{1,2,3}-LAYER*.md`、`KNOWLEDGE_GRAPH_WIKI.md`、`F-Stack_Knowledge_Base_Summary.md`、`README.md`。

## 7. 风险
- kqueue 与 epoll 共享 `ff_epoll_pairs`：需确认同一 kq 不会同时被 epoll 与 kevent 两种语义混用（ff_epoll_create 返回独立 kqueue，风险低，仍需 review）。
- IPV6_V6ONLY 落点需实测（ff_host_socket 通用 vs ff_socket 双建处），避免影响纯内核 SOCK_KERNEL IPv6。
- `FF_EPOLL_COEXIST_MAX=4` 容量：多 kq 场景需评估是否够用。
