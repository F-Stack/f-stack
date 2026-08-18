# 01 VPP/VCL 调研报告：VCL 如何支持 Nginx 无损 reload

| 项 | 值 |
|---|---|
| 文档编号 | 01 |
| 标题 | VPP VCL 支撑 Nginx 无损 reload 的机制、工程问题与启示 |
| 版本 | v1.0 |
| 日期 | 2026-08-18 |
| 状态 | 待人工审计 |
| 来源产物 | work/research-vpp-vcl.md（调研员 researcher-vpp-vcl，2026-08-18 落盘）。本篇为正式化改写：删除过程性叙述，保留全部事实证据（文件:行号、URL、commit hash、issue 编号）、未坐实标注与单来源声明；「实际执行的操作清单」保留为第 1 节以体现证据可追溯 |

相关篇章：[00-总览](00-overview.md) | [02-其他项目调研](02-other-projects-research.md) | [06-方案设计](06-solution-design.md)

---

## 1. 调研方法与实际执行的操作清单

### 1.1 实际执行的搜索与抓取

| # | 操作 | 关键词/URL | 结果 |
|---|------|-----------|------|
| 1 | web_search | "VPP VCL Communication Library architecture LDP LD_PRELOAD docs.fd.io" | 命中 docs.fd.io 18.01 vcl_ldpreload 文档、FDio/vpp wiki、DeepWiki |
| 2 | web_search | "vppcom_fork VCL fork child process handling session ownership" | 命中 DeepWiki VCL 章节、Envoy VCL socket 文档 |
| 3 | web_search | "FDio vpp nginx VCL graceful reload zero downtime issue" | 命中 FDio/vpp wiki VPP-HostStack-LDP-nginx、VSAP 项目（gitee 镜像） |
| 4 | web_search | "VPP session layer app namespace app worker svm_fifo message queue architecture" | 命中 DeepWiki session layer、FDio/vpp wiki SessionLayerArchitecture |
| 5 | web_fetch | https://github.com/FDio/vpp/wiki/VPP-HostStack-LDP-nginx | 全文提取成功 |
| 6 | web_fetch | https://deepwiki.com/FDio/vpp/2.2-vpp-communication-library-(vcl) | 全文提取成功（索引于 2026-08-17，commit ebad6e） |
| 7 | web_fetch | https://deepwiki.com/FDio/vpp/2.1-session-layer-architecture | 全文提取成功 |
| 8 | web_fetch | https://docs.fd.io/vpp/18.01/vcl_ldpreload_doc.html | 全文提取成功（旧版文档） |
| 9 | web_fetch | https://github.com/FDio/vpp/wiki/VPP-HostStack-VCL | 全文提取成功 |
| 10 | web_fetch | https://gitee.com/mirrors_gerrit_fd_io/r_vsap（及 vpp_patches、ldp、common 子目录） | README 与目录结构提取成功 |
| 11 | web_fetch | https://docs.fd.io/csit/master/report/introduction/methodology_hoststack_testing/methodology_vsap_ab_with_nginx.html | 全文提取成功（CSIT-2302.11） |
| 12 | gh CLI | `gh search issues 'nginx' / 'reload' / 'SIGUSR2' / 'VCL fork' -R FDio/vpp` | 命中 #3547/#3645/#3490/#3463/#3189 等 |
| 13 | gh CLI | `gh issue view 3547 / 3645`（含全部评论） | 详情与维护者回复提取成功 |
| 14 | gh CLI | `gh api search/commits q=repo:FDio/vpp+fork+vcl` + 逐个 `gh api repos/FDio/vpp/commits/<sha>` | 7 个关键 commit 的日期/消息/文件清单 |
| 15 | curl raw.githubusercontent.com | FDio/vpp master/v21.06/v20.09/v19.08/v19.04/v18.07 的 src/vcl/{vppcom.c,ldp.c,vcl_locked.c,vcl_private.c,vcl_private.h,vppcom.h} 与 src/vnet/session/{application.c,application.h,application_worker.c}，grep/sed 定段阅读 | fork 处理、worker cleanup、listener owner 迁移代码均读到原文 |
| 16 | curl gitee raw | r_vsap 的 vpp_patches/common/0001-session-pinning.patch、vpp_patches/ldp/master/0001-LDP-remove-lock.patch | 补丁原文读到 |
| 17 | 本地检索 | /data/workspace/f-stack 的 adapter/syscall/README.md、app/nginx-1.28.0/src（ngx_ff_module.c、ngx_process_cycle.c）、git log | F-Stack 现状对照材料 |

### 1.2 交叉验证情况

- VCL 三层架构（LDP/VLS/VCL）：FDio/vpp wiki（VPP-HostStack-VCL）+ DeepWiki 2.2 + 源码（vcl_locked.c 文件头注释）三方一致。
- fork 三阶段机制：源码（master vcl_locked.c L2005-L2060、L2280）+ DeepWiki 描述 + commit 历史（053a0e44ed/47c40e2d94）三方一致。
- nginx reload 问题：issue #3547（现象+报告者分析）与 issue #3645（复现版本+维护者分析）互相印证；VPP 源码注释（SIGCHLD 延迟清理的原因注释）与 #3547 报告的死锁分析互相印证。
- VSAP 项目：gitee 镜像 README + CSIT 官方文档 + 补丁原文三方一致。

## 2. VCL 架构事实（带来源）

### 2.1 分层：LDP → VLS → VCL（vppcom）→ VPP session 层

来源：https://github.com/FDio/vpp/wiki/VPP-HostStack-VCL （Dave Wallace 维护，2026-04-21 编辑）；与源码 src/vcl/ 文件布局一致。

- **VCL（vppcom）**：类 POSIX 但不兼容 POSIX 的整数句柄 API，管理与 session 层的交互，支持多 worker 应用。源码 `src/vcl/vppcom.c`、`vcl_private.c/h`。
- **VLS（VCL Locked Sessions，`src/vcl/vcl_locked.c`）**：VCL 之上的锁垫层。适用「应用无法避免在多 worker 间共享会话/无法显式注册 worker」的场景。三种工作模式（vcl_locked.c 文件头注释 L56-L73 原文归纳）：
  1. per-process workers：拦截 fork，把所有 child 视为须向 VCL 注册的新 worker；VLS session 克隆后在 worker 间**显式共享**，仅共享 session 加锁，同一时刻只允许一个进程操作；
  2. per-thread workers：每个新 pthread 注册为 worker（配置开启）；线程访问非自有 session 时通过 VCL+VPP 发 RPC 请求克隆共享（隐式共享）；
  3. single-worker multi-thread：不加假设，激进加锁。
- **LDP（`src/vcl/ldp.c`，libvcl_ldpreload.so）**：LD_PRELOAD 拦截 socket/bind/connect/epoll* 等调用重定向到 VLS/VCL。wiki 原话："LDP 不保证总能正常工作"；不支持静态链接应用；对「syscall+选项+线程与 fork 行为」的组合支持不完整。

### 2.2 应用接入模型：application / app namespace / app worker

来源：DeepWiki 2.1（https://deepwiki.com/FDio/vpp/2.1-session-layer-architecture）+ 源码 `src/vnet/session/application.h`。

- **application_t（app）**：一次 VCL attach 对应一个 app；attach 时绑定 app namespace（隔离路由/地址空间，namespace-id + secret，仅 binary API 方式）。
- **app_worker_t（app_wrk）**：app 的工作实体，每个进程/线程一个。关键结构字段（application.h L32-L81 原文核对）：
  - `event_queue`：该 worker 的 **svm 消息队列**（VPP→app 事件通道）；
  - `listeners_table`：该 worker 管理的监听句柄表；
  - `half_open_table`：半开连接池（"Tracked in case worker detaches"——为 worker 注销设计的字段）；
  - `connects_seg_manager`：出站连接专用共享内存段管理器；
  - `api_client_index`：注释明确 "Needed for multi-process apps"。
- **session_t 归属三元组**：`thread_index`（VPP 线程）+ `session_index` + `app_wrk_index`（属主 app worker）；session_handle_t 是 (thread_index, session_index) 编码的 64 位句柄。
- **app_listener_t（listen 的 app 级共享结构）**：`workers` bitmap（哪些 app worker 在 accept）+ `accept_rotor`（轮转游标）+ `cl_listeners`（每个 app worker 对应的带 fifo 的 cl session 向量）。**listen socket 在 VPP 侧只有一份，归 app 所有，多个 app worker 通过 bitmap 共享**——这是 reload 无损的结构基础。

### 2.3 数据与事件通道：svm fifo + svm_msg_q

来源：DeepWiki 2.1/2.2 + `src/vcl/vppcom.c`（L43-L224 控制消息族）。

- **数据面**：每 session 一对共享内存 fifo（rx/tx，svm_fifo_t），分配在按 app/worker 划分的共享内存段（segment manager）。
- **控制面（app→VPP，ctrl_mq）**：SESSION_CTRL_EVT_LISTEN / CONNECT / CONNECT_STREAM / UNLISTEN / SHUTDOWN / DISCONNECT / TERMINATE / APP_DETACH（vppcom.c L43-L224）。
- **事件面（VPP→app，app_event_queue）**：SESSION_IO_EVT_RX/TX、SESSION_CTRL_EVT_CLOSE/HALF_CLOSE/RESET 等，VPP 侧由 vlib 节点 `session_queue_node` 处理 app 请求。
- **接入通道二选一**：app socket API（`app-socket-api`，默认 /var/run/vpp/app_ns_sockets/default）或 legacy binary API（`api-socket-name`）；session 层启用 socket api 后所有应用必须统一走 socket api（wiki VPP-HostStack-VCL「附加模式限制」节）。
- **通知方式**：`use-mq-eventfd` 开启后消息队列用 eventfd 通知，eventfd 可加入 VCL 内部 epoll（`vcl_mq_epoll_add_evfd`）。

### 2.4 vcl_worker_t 与 fd 表

来源：DeepWiki 2.2 + 源码 vcl_private.h L153-L190、L304-L307。

- 每个 vcl worker 持有：session 池、`ctrl_mq`、`app_event_queue`、`mqs_epfd`（mq 事件 epoll fd）、`forked_child`（父 worker 记录其 fork 出的 child worker 下标）。
- fd 表是**每进程局部**的：LDP 用句柄平移区分原生 fd 与 VCL 句柄（`vlsh_bit_val`，环境变量 LDP_ENV_SID_BIT 可调），没有跨进程全局 fd 表。
- 线程局部 `__thread uword __vcl_worker_index` 快速定位当前 worker（vppcom.c L11）。

## 3. fork / session 所有权机制

### 3.1 fork 三阶段处理（master 分支，src/vcl/vcl_locked.c）

注册：`pthread_atfork(vls_app_pre_fork, vls_app_fork_parent_handler, vls_app_fork_child_handler)`（L2280-L2281）。

1. **prepare（L2005-L2009）**：拦截 SIGCHLD（`vls_incercept_sigchld`，保存旧 handler）+ `vcl_flush_mq_events()` 把父 worker 的 mq 事件清空，避免 fork 后 mq 消费状态不一致。
2. **parent（L2057-L2061）**：`vcm->forking = 1; while (vcm->forking);` —— **父进程自旋等待**，直到 child handler 完成初始化置 0。即 fork() 返回父进程时，child 的 worker 注册已必然完成。
3. **child（L2012-L2054）**：
   - `vcl_set_worker_index(~0)` 清掉内存映像里继承的旧 worker 下标；
   - `vppcom_worker_register()` **向 VPP 注册一个新 app worker**（VPP 侧分配新 event_queue/段）；
   - `vls_worker_alloc()` 建新 VLS worker；
   - `vls_worker_copy_on_fork(parent_wrk)`（L1100-L1139）：`pool_dup` 复制父 worker 整个 session 池 + `hash_dup` 复制 vpp_handle→session_index 哈希 + 重建 vep（VCL epoll）句柄（`vls_validate_veps`）+ 把所有 vls 从父 vcl worker 改挂到 child；
   - `vls_share_sessions(parent, child)` 建立**显式共享**（shared_data：owner_wrk_index + workers_subscribed + 自旋锁）；
   - `parent_wrk->forked_child = 新 worker 下标`。

### 3.2 child 退出回收：SIGCHLD 拦截 + 延迟清理

来源：vcl_locked.c L1924-L1995（master 原文）。

- `vls_intercept_sigchld_handler`：收到 SIGCHLD 时**不在信号上下文清理**（原文注释：父进程可能带着 localtime/mspace_free 等锁进入信号 handler，清理会再取这些锁导致死锁——与 issue #3547 报告者观察到的死锁互证），只把 child worker 下标挂入 `pending_vcl_wrk_cleanup`，并链回应用旧 handler。
- 真正清理发生在该进程下一次 `vls_epoll_wait/vls_select`：`vls_handle_pending_wrk_cleanup` → `vls_cleanup_forked_child`（等孙进程消失、递归清理、`vls_cleanup_vcl_worker`：unshare sessions + `vcl_worker_cleanup(wrk, notify_vpp)`）。
- **app socket api 模式下 notify_vpp=0**（L1871-L1877 原文注释："Since child may have exited and therefore fd of vpp_app_socket_api may have been closed, so DONOT notify VPP"）——child 退出不通知 VPP 删 app worker。
- `vcl_worker_cleanup`（vcl_private.c L118-L137）：notify 时 `vcl_api_app_worker_del`，然后关闭 mqs_epfd、free session 池/哈希/位图。
- **已知结构性限制**：`vls_intercept_sigchld_handler` 内原文注释 `/* TODO we need to support multiple children */` —— 每个 worker 只记录一个 `forked_child`，**不支持同时多个存活 child**（nginx 串行 fork worker、旧 worker 先退出再 fork 下一个的场景勉强可用；respawn 并发多 child 有风险）。

### 3.3 session 所有权与迁移 API

- 所有权：VPP 侧 session 属 (VPP thread, app_wrk)；VCL 侧 session 对象按 worker 分池，fork 时复制（副本+显式共享），不是引用同一对象。
- **迁移 API（commit 30e79c2e38，2019-01-03，Florin Coras）**。commit message 原文："In case of multi process apps, after forking, the parent may decide to close part or all of the sessions it shares with the child. Because the sessions have fifos allocated in the parent's segment manager, they must be moved to the child's segment manager."
  - 消息结构（18 字节限制，u16 worker 下标）：`session_worker_update_msg_t{client_index, wrk_index, req_wrk_index, handle}` + reply 携带新 rx/tx fifo 地址与 segment_handle。
  - master 现状：VCL 侧 `vcl_send_session_worker_update`（vppcom.c L272）仍存在，由 vcl_locked.c L982 在 session 共享流程调用（发给 VPP 更新 fifo 到新 worker 的段）。VPP 侧普通 session 的迁移入口未在 application.c 中定位到（见第 7 节未坐实清单）。
- **listen owner 迁移**：`application_change_listener_owner`（src/vnet/session/application.c L1539-L1557，master 原文）：新 app_wrk `app_worker_start_listen` + 旧 app_wrk `app_worker_stop_listen` + 改 `s->app_wrk_index`。listen 所有权可在 app worker 间无缝换手。
- **epoll fd 与 session 的跨进程关系**：fd 表每进程局部（fork 复制内存映像自然继承）；VCL epoll（vep）是 worker 私有对象，fork 拷贝 session 时须重映射 vep 句柄（commit 5788a34be6 "vcl: validate vep handle when copying sessions on fork"，2021-06-22）；vcl_locked_session_t 另有 `libc_epfd` 字段处理 libc epoll 混用。

### 3.4 mq 是否共享

不共享。每个 vcl worker 注册时由 VPP 分配独立 ctrl_mq 与 app_event_queue；fork 时 pre-fork 只 flush 父 worker 自己的事件，child 注册后用自己的新队列。父子对同一 session 的并发访问靠 VLS 显式共享锁串行化。

### 3.5 fork 支持演进时间线（commit hash 均经 gh api 核实）

| 日期 | commit | 说明 |
|------|--------|------|
| 2017-11-07 | 2e005bbbdf | "VCL: handle process fork."（vppcom.c，最早 fork 处理，Dave Wallace） |
| 2018-11-13 | 053a0e44ed | "vcl/session: apps with process workers"：fork 时把 child 注册为 VPP 新 worker（per-process worker 模型确立） |
| 2018-11-27 | 47c40e2d94 | "vcl: basic support for apps that fork"：拦截 fork + 注册新 worker + 父子共享 session |
| 2019-01-03 | 30e79c2e38 | "vcl/session: add api for changing session app worker"：session 所有权迁移（fifo 段搬家） |
| 2019-01-15 | f9240dc920 | "vcl: move forking logic to vls"（fork 逻辑从 vppcom 移到 vcl_locked.c，此后 vppcom.c 中无 fork 逻辑——这是在 v19.04~master 的 vppcom.c 里 grep 不到 vppcom_fork 的原因） |
| 2021-06-22 | 5788a34be6 | fork 拷贝 session 时校验 vep 句柄（修 child 清理时 EPOLL_CTL_DEL） |
| 2025-01-06 | 4d9df5cb3d | "vcl: fix vls wrk index on fork"（Type: fix）——最新一次 fork 相关修复 |

【注】任务书中提到的 `vppcom_fork()` 函数名在 FDio/vpp 主线源码（v18.07~master 的 vppcom.c）中均未检索到，fork 处理自 2019 年起位于 `src/vcl/vcl_locked.c`（VLS 层），函数名为上述 atfork 三阶段 handler。"vppcom_fork" 更像是旧资料对「VCL 处理 fork」的统称。

## 4. VPP + nginx 集成与 reload 行为

### 4.1 官方集成方式

**(a) LDP 方式（不改 nginx 代码）**——来源：https://github.com/FDio/vpp/wiki/VPP-HostStack-LDP-nginx （全文抓取成功）：

- VPP startup.conf 需加 `session { use-app-socket-api }`；
- 启动：`sudo LD_PRELOAD=$LDP_PATH VCL_CONFIG=$VCL_CFG nginx -c nginx.conf`；
- vcl.conf 最小配置：`heapsize/segment-size/add-segment-size/rx-fifo-size/tx-fifo-size/app-socket-api /var/run/vpp/app_ns_sockets/default`；
- nginx.conf 已验证可工作配置：`worker_processes 4; daemon off; master_process on;`（events 段 use epoll）；
- 性能建议：taskset 绑定 nginx 到 VPP worker 与网卡同 NUMA 核。

**(b) VCL 代码集成方式（改 nginx 源码）**——来源：VSAP 项目（gerrit.fd.io/r/vsap，gitee 镜像 https://gitee.com/mirrors_gerrit_fd_io/r_vsap）：

- 基于 nginx 1.14.2，`./configure --with-vcl --vpp-lib-path=... --vpp-src-path=...`；
- 仓库提供 `nginx_patches/0001-ngxvcl.patch` + `vpp_patches/vcl/0001-ngxvcl-api.patch`（VPP 侧 API 补丁）；
- VSAP（VPP Stack Acceleration Project，FDio 官方项目，见 https://github.com/FDio 与 CSIT 文档）对 VPP 的补丁：
  - `vpp_patches/common/0001-session-pinning.patch`（2019-10-17，Intel 孙国傲）：给 app_listener 增加 per-VPP-thread 的 app worker 轮转表（`vpp_app_worker_map_t`），accept 分发从全局轮转改为按 VPP 线程固定的 worker 子集轮转——性能优化，非 reload 功能；
  - `vpp_patches/ldp/{2001,2005,master}/0001-LDP-remove-lock.patch`（2020-06-03，zsj）：**直接从 CMakeLists 移除 vcl_locked.c（整个 VLS 锁层）**，ldp.c 直连 vppcom；README 称为 CPU 密集应用「节省约 100% 单核 CPU 周期」。代价是放弃 VLS 的多线程/多进程锁保护（依赖应用自身 worker 划分纪律）。
- VSAP 仓库无 LICENSE 文件；README 未提及 nginx reload 支持的相关内容（已确认，非「没找到」）。

**(c) 测试基线**：CSIT 官方用 ab 在 100G 网卡上测 VSAP nginx 的 CPS/RPS（https://docs.fd.io/csit/master/report/introduction/methodology_hoststack_testing/methodology_vsap_ab_with_nginx.html，CSIT-2302.11）；文档明确指出 LD_PRELOAD 方式「天然具有更多开销和其他局限性」。

### 4.2 VCL 模式下 nginx HUP reload 的机制（代码推导链）

nginx master 收 HUP 的标准序列在 VCL 下的对应行为（依据第 3 节源码事实推导，每步标注依据）：

1. master fork 新 worker → **atfork child handler** 为每个新 worker 注册新 app worker 并复制父 session 池（含 listen session 句柄），与 master 显式共享（3.1 节）。
2. 新 worker 的 listen 生效：VPP 侧 app_listener 的 workers bitmap 增加新 app worker（app_worker_start_listen，application.c L1314 附近逻辑），accept 事件开始轮转分发给新 worker（app_listener_select_worker，L173）。
3. 旧 worker 处理完存量 keepalive 请求后 exit → master 进程收 SIGCHLD → VLS 拦截后**延迟到 epoll_wait 清理**旧 child 的 vcl worker（3.2 节）；app socket api 模式下不向 VPP 发 app worker del。
4. **listen 不中断**：listen session 属 VPP 侧 app（app_listener），只要还有 worker 在 bitmap 里就不会 unlisten；`application_change_listener_owner` 还支持显式换主（3.3 节）。
5. 已建立连接不跨进程迁移：旧 worker 的连接随旧 worker 退出而关闭（这与原生 nginx 语义一致——reload 时旧 worker 完成当前请求后关闭 keepalive 连接，是「优雅退出」而非丢包）。

**天然支持的部分**：listen 的进程无关性（VPP 侧单点持有）、fork 时 session 表复制+worker 注册、父子共享锁、延迟清理、session 所有权迁移 API。

**结论：HUP reload 的「无损」在 VCL 架构上是机制性支持的（listen 不换、新旧 worker 并存、旧 worker 优雅退出），但实现路径上存在未修复的 bug（见 4.3）。**

### 4.3 已知 issue 证据（gh CLI 核实）

**Issue #3547 [VPP-2086] "VCL and VPP(V2306) will crash when reloading nginx using jemter test"（CLOSED，未实际修复关闭；标题为报告者原文逐字引用，"jemter" 系其原始拼写，未作纠正）**
https://github.com/FDio/vpp/issues/3547
- 场景：JMeter 100 线程压测 + 每 2 秒 reload 一次 nginx（worker auto=8）→ nginx 或 vpp 很快 crash。
- 报告者根因分析（原文摘要）：vcl 与 vls 共享 `__vcl_worker_index`（TLS），旧 nginx 退出与新 fork 交错时 vcl/vls 两个 worker 池的下标不匹配；随后连环触发：VPP 无限循环于 `session_wrk_handle_evts_main_rpc`、nginx crash 于 `vcl_send_session_accepted_reply`（`session->vpp_evt_q = 0`，由 `vppcom_session_unbind` 路径调用）、VPP crash 于 `app_worker_get`。报告者打了三个补丁仍未修完，放弃并报 bug。
- 维护者 florincoras 关闭理由："We're lacking context/email for this one. Please reopen if this issue was not solved"——**未给出修复**。2025-01 的 4d9df5cb3d "fix vls wrk index on fork" 疑似针对其中 worker index 不匹配问题（时间吻合但无 issue 关联，仅此推断，未坐实）。

**Issue #3645 "VPP main thread stuck at session_wrk_handle_evts_main_rpc() when working with nginx through VCL"（OPEN，2025-11-18 报告，截至 2026-08 仍 open）**
https://github.com/FDio/vpp/issues/3645
- 场景：wrk 压测转发中 `kill -HUP` reload nginx → **VPP 主线程永久卡死**在 `session_wrk_handle_evts_main_rpc()`，vppctl 失联，http client 无法连接；nginx worker 一段时间后能恢复但 VPP 不恢复。
- 复现版本：22.10 / 23.10 / 25.10 全部复现；无流量时 reload 正常；增大 event-queue-length 仅延缓（8192 第一次 reload 即卡死；100000 可撑过第一次）。
- 维护者 florincoras 分析（评论原文）：怀疑「reload 时需要 main thread 处理的事件（典型如 listen）的同步代码有 bug」（"might be a bug in the code that tries to synchronize events when one of them needs to be handled on main thread (typically a listen)"），或高负载下 connect 洪峰迫使控制事件全走 main thread 的副作用。
- 报告者确认：`show app mq` 队列并未满，排除了简单拥塞解释；症状更像事件同步死锁/活锁。
- **这是「VCL 模式 nginx reload」最直接的现行证据：截至 VPP 25.10，带流量 reload 仍会导致 VPP 卡死，社区未解决。**

**其余相关（仅标题级，未逐个展开）**：
- #3490 [VPP-2028] "The number of nginx startup threads is incorrect"（closed）
- #3463 [VPP-2001] "VCL crash when test nginx via ldp"（closed）
- #3189 [VPP-1726] "VPP + VCL fail / crash on small load"（closed）

**SIGUSR2 / binary upgrade（exec 新二进制）**：`gh search issues 'SIGUSR2' -R FDio/vpp` 无相关结果（仅一条无关 python API issue）；wiki/文档亦未提及 exec 后 VCL 状态延续机制。**未查到** VCL 对 nginx 二进制热升级（SIGUSR2 + exec）的任何支持或讨论。按机制推断 exec 会丢弃 VCL 全部用户态状态（worker 注册、句柄表、共享内存映射），新进程需完整重新 attach——标注为推断，未坐实。

## 5. 已知局限汇总

| 局限 | 来源 |
|------|------|
| LDP 不保证总工作；不支持静态链接；syscall/线程/fork 组合支持不完整 | wiki VPP-HostStack-VCL 原文 |
| VCL API 非线程安全，session 不得跨 worker 共享（须 VLS 加锁） | 同上 |
| binary API 与 app socket API 只能二选一 | 同上 |
| VLS fork 模型只支持单个存活 child（TODO 注释） | vcl_locked.c master L1957 附近原文注释 |
| app socket api 模式下 child worker 退出不通知 VPP（可能遗留 app worker 状态） | vcl_locked.c L1871-L1877 原文注释 |
| 带流量 reload nginx → VPP main 卡死（22.10~25.10），open 未修 | issue #3645 |
| 高频 reload → vcl/vls worker 池下标错位连环 crash（V2306，closed 未修复） | issue #3547 |
| LD_PRELOAD 方式固有开销与其他局限 | CSIT 官方文档 |
| VSAP lock-free LDP 移除 VLS 锁层后，多进程/多线程共享 session 失去锁保护 | r_vsap vpp_patches/ldp 补丁原文（从 CMakeLists 删除 vcl_locked.c） |

## 6. 对 F-Stack 的启示

### 6.1 结构对照（基于本地代码核实）

| 维度 | VPP + VCL | F-Stack app/nginx（源码集成） | F-Stack adapter/syscall（LD_PRELOAD） |
|------|-----------|------------------------------|----------------------------------------|
| 协议栈位置 | 独立 VPP 进程，中心化单实例 | 每 worker 进程内嵌一个 FreeBSD 栈实例（`ff_init` + `ff_run`，ngx_process_cycle.c L397/L924 核实） | 独立 fstack 实例进程（`ff_handle_each_context` 循环），app 进程经 libff_syscall.so 以 sc 上下文对接 |
| listen 归属 | VPP 侧 app_listener 单点持有，app worker 经 bitmap 共享 | 各 worker 的栈实例各自 bind/listen（reuseport 类语义） | fstack 实例持有，fd 经 hook 映射（FF_MULTI_SC：master 为每 worker 预建 fd + sc 绑定，README 核实） |
| app↔栈通道 | 共享内存 svm fifo（数据）+ svm_msg_q（事件/控制），每 worker 独立 mq | 进程内直调 ff_api（无 IPC） | Hugepage 共享内存 sc 上下文 + sem 或 DPDK SPSC rte_ring IPC（FF_USE_RING_IPC，ld_preload_ring_spec） |
| fork 语义 | pthread_atfork 三阶段：注册新 app worker + 复制 session 池 + 显式共享；SIGCHLD 延迟清理 | master fork worker 后靠 POSIX shm 信号量同步启动（ngx_ff_worker_sem，15s 超时，ngx_process_cycle.c L459-L509 核实）；新 worker 全新栈实例 | 2023 年起支持 fork（PR #887：每个 fork 进程拥有自己的 FreeBSD struct thread）；FF_MULTI_SC 用静态 scs 数组按 current_worker_id 选 sc |
| reload 时 listen 连续性 | 机制性保证（listen 与进程解耦 + worker 注册/注销） | 无保证：新 worker 新实例重新建立 listen，存在窗口 → 丢包/断连接（团队已知问题，本篇给出现状对照） | 结构上更接近 VPP（栈进程中心化），但 sc→实例映射是静态预分配的，reload 换 worker 集合需重配 |

### 6.2 关键层面区分：网卡队列归属 vs 监听 fd 归属（与 #1036 根因对照）

F-Stack HUP 丢包的根因已由本地档案 #1036 坐实（docs/f-stack-issue-ana.md，duplicate of #547）：多进程模型下每个 worker 独占绑定 NIC 硬件队列（RSS），reload 时旧 worker 退出而新 worker 尚未完成 DPDK/F-Stack 栈初始化，存在「队列无主窗口」导致丢包——**问题在数据面（网卡队列归属），不在监听 fd 本身**。VPP/VCL 的结构恰好把这两个层面都解耦了：

- **数据面（网卡队列归属）**：DPDK 网卡由独立的 VPP 进程接管（vfio-pci），nginx 只是经共享内存接入的客户。reload 只换代 app worker，VPP 进程与网卡队列归属完全不动——**收包队列永远有主**，「无主窗口」结构性不存在。reload 窗口内 SYN/数据包持续被 VPP 收下（暂存于 listener 的 accept 队列与 per-session fifo），等新 app worker 注册进 bitmap 后分发。issue #3645 从反面印证：带流量 reload 出问题时卡死的是 VPP 侧事件同步（说明包一直在进 VPP），而非队列失主。
- **控制面（监听归属）**：listen 是 VPP 侧 app 级单点对象（app_listener），app worker 只是 bitmap 里的 accept 租户，增删 worker 不触碰 listen 本身，无监听空窗。

对 F-Stack 的推论：app/nginx 路线（每 worker 内嵌栈实例 + 直接占队列）要消灭无主窗口，等价于把「收包/队列所有权」从 worker 生命周期中剥离——这正是 #1078 primary_slim 已验证的方向（primary 不占队列不退场、secondary 换代时队列归属不变，PoC 实测杀 primary 后 12/12 连接零中断，见 docs/issue_1078/zh_cn/），也与 adapter/syscall 路线（fstack 实例进程中心化、不随 app reload 退出）同构。三个独立来源（VPP 架构、#1078 PoC、adapter/syscall 设计）指向同一结论：**队列/收包所有权中心化、与业务进程生命周期解耦，是用户态栈无损 reload 的结构性前提**；监听 fd 归属是第二位的控制面问题。

【注】与 [02-其他项目调研](02-other-projects-research.md) 的交叉印证：其「业界无 TCP 已建连接迁移先例（Envoy 原句 existing connections are not transferred）」与本篇 4.2 节第 5 点（VCL 模式旧 worker 的连接随 drain 关闭而非迁移）互相印证；其 Facebook LPC 2021「新实例 ready 前流量持续导给旧实例」模式与本篇 app_listener workers bitmap 机制（新 worker 未注册进 bitmap 前 accept 不分发给它，且 VPP 侧持续收包不丢）同构——"ready 前不切流"在 VPP 结构里是免费的，在 F-Stack 结构里则必须先解决队列有主才有前提。

### 6.3 可借鉴的具体机制（按对 F-Stack nginx reload 问题的相关度排序）

1. **收包所有权中心化（网卡队列与业务进程解耦）**：见 6.2——这是 VPP 模式对 F-Stack #1036 根因（RSS 队列无主窗口）最直接的对应解法，优先级高于一切控制面机制。
2. **listen 所有权与进程生命周期解耦**：VPP 把 listen 放在栈侧的 app 级对象（app_listener），worker 只是 bitmap 里的 accept 租户，增删 worker 不触碰 listen 本身。F-Stack 若要在 reload 时不丢 SYN，核心方向是把 listen（或其等价物）从「某 worker 的栈实例」提升为跨 worker 的中心化状态——对 adapter/syscall 路线（fstack 实例已是中心）改造成本低于 app/nginx 每进程一栈路线。
3. **worker 注册制 + fork 复制 session 表**：atfork 三阶段（flush mq → 父自旋等 child 注册完成 → child 复制 session 池+重建 epoll 句柄）是一个成熟的「进程级热加入」模板；F-Stack 的 FF_MULTI_SC 静态 scs 数组可向「动态注册/注销 worker」演进。
4. **session/listen 所有权迁移 API**：`session_worker_update`（fifo 段搬家）与 `application_change_listener_owner`（listen 换主）是旧 master 退出、新 master 接管场景的直接机制（30e79c2e38 的 commit message 就是为多进程 app 父子交接写的）。
5. **SIGCHLD 延迟清理**：不在信号上下文做复杂清理（VPP 注释原文点名 localtime/mspace_free 锁死锁风险），挂 pending 到事件循环处理——通用工程实践，F-Stack 无论哪条路线都应照做。
6. **每 worker 独立 mq + pre-fork flush**：避免父子共享队列的消费状态竞争。
7. **测试方法**：VPP 社区踩出的验证模式 = JMeter/wrk 持续流量 + 每 2 秒循环 reload（#3547/#3645 均如此复现）。F-Stack 的 reload 验收 spec 应把「带流量循环 reload 数千次 + VPP/fstack 侧不死锁不 crash + 连接错误数为 0」设为门禁。

### 6.4 VCL 的教训（负面启示）

- VCL 的 reload 路径（fork 注册 + 双代 worker 并存 + 注销清理 + 事件同步）是全链路里 bug 最密集的区域之一：#3547 连环 crash 三年未修、#3645 卡死至今 open。说明即使架构上「机制性支持无损 reload」，跨进程状态（TLS worker index、每 worker 池、VPP 侧事件同步）的一致性维护极难做对。F-Stack 设计时应当把 reload 做成显式的、可观测的状态机（每个阶段可打点/可回退），而不是散落在 fork/signal hook 里的隐式逻辑。
- VCL 用「锁垫层（VLS）+ 显式共享」换正确性，又用 VSAP「去掉锁层」换性能——两难本身说明「多进程共享一个栈」的锁粒度设计是核心难点，F-Stack 的 per-worker 独立实例路线天然避开共享锁，但代价就是 listen 连续性，属于路线取舍而非实现瑕疵。

## 7. 未坐实清单

1. **VPP-HostStack-nginx wiki 正文**（VCL 代码集成版 nginx 文档）：页面存在（2026-04-21 编辑），但 GitHub wiki 动态渲染，web_fetch 与 curl 两次抓取均只得导航框架，正文「未获取到」。
2. **VSAP nginx_patches/0001-ngxvcl.patch 与 vpp_patches/vcl/0001-ngxvcl-api.patch 的内容**：仅确认存在及 README 描述（--with-vcl 集成、TLS 环境变量），补丁正文未读。
3. **SIGUSR2 / exec 二进制热升级**：FDio/vpp 无任何 issue/文档/commit 证据，「未查到」VCL 支持；"exec 丢弃全部 VCL 状态需重新 attach"为机制推断，未实测。
4. **commit 4d9df5cb3d（fix vls wrk index on fork）与 issue #3547 的对应关系**：时间与症状吻合，但 commit/issue 均无互相引用，未坐实。
5. **VPP 侧普通 session 的 worker_update 迁移入口**：VCL 侧发送函数（vppcom.c L272）与消息结构确认在 master 存在，但 VPP 侧 application.c/session.c 中对应的处理 handler 未定位到（可能改名或移入其他文件），未坐实；listen 迁移入口 application_change_listener_owner 已核实。
6. **#3490/#3463/#3189 的具体细节**：仅核实标题/状态，未逐个读正文。
7. **VPP 25.10 之后（如 26.01/26.04）是否修复 #3645**：issue 仍 open 且未见关联 PR；未逐一排查 2026 年新 commit。
8. **AsterNOS-VPP 文章**（2026-05，百家号/知乎/bilibili）：国产厂商宣称用 LDP 跑原生 nginx 的营销内容，技术细节未二次坐实，不作为机制证据。
9. VSAP session-pinning 补丁与最新 VPP（25.x）的关系：补丁基于 2019 年代码（application.c 旧结构），master 已重构该文件，补丁是否仍可应用未验证。

## 附：本文引用来源索引

- FDio/vpp wiki：
  - https://github.com/FDio/vpp/wiki/VPP-HostStack-VCL
  - https://github.com/FDio/vpp/wiki/VPP-HostStack-LDP-nginx
  - https://github.com/FDio/vpp/wiki/VPP-HostStack-nginx（正文未获取到）
- DeepWiki（FDio/vpp 自动文档，索引 2026-08-17，commit ebad6e）：
  - https://deepwiki.com/FDio/vpp/2.1-session-layer-architecture
  - https://deepwiki.com/FDio/vpp/2.2-vpp-communication-library-(vcl)
- VPP 源码（raw.githubusercontent.com，master 及历史 tag）：src/vcl/{vcl_locked.c, vcl_private.c/h, vppcom.c/h, ldp.c}、src/vnet/session/{application.c/h, application_worker.c}
- FDio/vpp commits：2e005bbbdf / 053a0e44ed / 47c40e2d94 / 30e79c2e38 / f9240dc920 / 5788a34be6 / 4d9df5cb3d
- FDio/vpp issues：#3547 / #3645（open）/ #3490 / #3463 / #3189
- VSAP：https://gerrit.fd.io/r/vsap （gitee 镜像 https://gitee.com/mirrors_gerrit_fd_io/r_vsap ；补丁原文经 gitee raw 读取）
- CSIT：https://docs.fd.io/csit/master/report/introduction/methodology_hoststack_testing/methodology_vsap_ab_with_nginx.html
- docs.fd.io：https://docs.fd.io/vpp/18.01/vcl_ldpreload_doc.html
- F-Stack 本地：/data/workspace/f-stack/adapter/syscall/README.md、app/nginx-1.28.0/src/event/modules/ngx_ff_module.c、app/nginx-1.28.0/src/os/unix/ngx_process_cycle.c、git log
- F-Stack 本地档案：docs/f-stack-issue-ana.md（#1036/#528/#547：F-Stack reload 丢包根因=RSS 队列无主窗口，duplicate 链）；docs/issue_1078/zh_cn/（primary_slim：队列所有权与 primary 生命周期解耦的 PoC）
