# 02 其他项目调研：内核基线与其他用户态协议栈的 Nginx 无损 reload 方案

| 项 | 值 |
|---|---|
| 文档编号 | 02 |
| 标题 | 内核基线三种机制 / eBPF 线 / 其他用户态协议栈 / 通用模式归纳与适用性初判 |
| 版本 | v1.0 |
| 日期 | 2026-08-18 |
| 状态 | 待人工审计 |
| 来源产物 | work/research-other-projects.md（调研员 researcher-others，2026-08-18 落盘）。本篇为正式化改写：删除过程性叙述，保留全部事实证据（URL、原句、issue/PR 编号）、未坐实标注与单来源声明；「实际执行的操作清单」保留为第 1 节以体现证据可追溯 |

相关篇章：[00-总览](00-overview.md) | [01-VPP/VCL 调研](01-vpp-vcl-research.md) | [06-方案设计](06-solution-design.md)

---

## 1. 调研方法与实际执行的操作清单

方法：web_search 发现线索 → web_fetch 抓取一手来源（官方文档/官方博客/GitHub 仓库/内核文档）交叉验证；本地 F-Stack 仓库档案（docs/f-stack-issue-ana.md）用于适用性分析。禁止凭记忆断言，未取到原文的点全部进第 6 节清单。

实际执行的操作（按主题归组）：

| # | 操作 | 结果 |
|---|---|---|
| 1 | web_fetch nginx 官方控制文档 | 成功（HUP/USR2/WINCH/QUIT 全量） |
| 2 | web_fetch nginx 官方 ngx_http_core_module（listen/reuseport） | 成功 |
| 3 | web_fetch F5/NGINX 官方博客 Socket Sharding（1.9.1） | 成功（nginx.com 旧链已 301 至 f5.com，取到正文与性能数据） |
| 4 | web_archive 抓 nginx.com 原始博客页 | 失败（HTTP 429 限流，两次） |
| 5 | web_fetch nginx trac ticket #237（systemd socket activation） | 成功（含 Maxim Dounin 官方回复原句） |
| 6 | web_fetch Envoy 官方 hot restart 架构文档 | 成功 |
| 7 | web_fetch HAProxy 3.0 官方 Management Guide | 成功（seamless reload/-x/SIGTTOU 等全量） |
| 8 | web_search + web_fetch Cloudflare tubular 博客 | 成功（正确 slug 为 tubular-fixing-the-socket-api-with-ebpf/） |
| 9 | web_fetch Linux 内核文档 prog_sk_lookup | 仅取到搜索摘要级原句（kernel.org 原文未整页抓取） |
| 10 | web_fetch Facebook LPC 2021《From XDP to Socket》中译（腾讯云社区版） | 成功（含 socket takeover 与 bpf_sk_reuseport 细节；原 LPC slides 未直接取到） |
| 11 | web_fetch Cilium 官方文档 intro 页 | 成功（socket-level LB 原句）；cilium.io 1.6 博客正文抓取被页面框架淹没，仅用其标题与 intro 文档 |
| 12 | web_fetch mTCP GitHub README + api.h 头文件 + src 目录结构 | 成功（api.c 原文抓取部分截断，mtcp_init.c 路径 404 不存在） |
| 13 | web_fetch Seastar GitHub README + doc/tutorial.md | 成功 |
| 14 | web_fetch 6WIND Virtual Accelerator 官方文档 introduction 页 | 成功（产品主页 www.6wind.com 403） |
| 15 | web_fetch OpenOnload GitHub README | 成功 |
| 16 | web_fetch ansyun/dpdk-nginx README | 成功 |
| 17 | web_search lwIP/PicoTCP + nginx | 未发现任何 nginx 移植（非穷尽） |
| 18 | web_search 6WIND + nginx 直接组合 | 无一手材料（见第 6 节） |
| 19 | 本地检索 f-stack 仓库 nginx reload 相关档案 | 成功（docs/f-stack-issue-ana.md #12/#528/#547/#1036） |

## 2. 内核基线：三种机制（对照基准）

### 2.1 nginx 二进制在线升级（SIGUSR2，双 master 共存）

来源：nginx 官方文档 https://nginx.org/en/docs/control.html（下称[NGINX-CTL]）

流程（原文关键句）：
1. 前置：新二进制先替换旧文件；
2. 旧 master 把 pid 文件改名为 `nginx.pid.oldbin`，然后 `exec` 新可执行文件，新 master 启动新 worker；
3. "After that all worker processes (old and new ones) continue to accept requests." —— 新旧 worker 并行收请求。文档未直说「继承 listening fd」，但新旧 worker 同时 accept 可推断新 master 经 fork+exec 继承了监听套接字；且 nginx 核心开发者在 trac #237 中明示内部机制："nginx is capable of using inherited file descriptors for listening sockets, via NGINX environment variable with a list of file descriptors to use"（https://trac.nginx.org/nginx/ticket/237，Maxim Dounin 回复）；
4. 关键差异：HUP 时旧 worker 会 close listening sockets；USR2 时 "the old master process does not close its listen sockets, and it can be managed to start its worker processes again if needed" —— 为回退保留监听；
5. 回退两条路：给旧 master 发 HUP（不重读配置重启旧 worker，再 QUIT 新 master）；或 TERM 新 master（旧 master 自动重启 worker）；
6. 升级成功收尾：QUIT 旧 master。

不丢连接的原因归纳（基于[NGINX-CTL]机制）：
- 监听 fd 跨 fork+exec 继承（内核 fd 语义 + NGINX 环境变量显式传递列表），新 master 从初始化完成起就能收新连接，无监听空窗；
- 已建连接全部挂在旧 worker 自己的进程里（accepted socket），旧 worker 优雅退出时 drain 完存量连接才退；
- 旧 master 保留监听 fd，使回退也无监听空窗。

### 2.2 HUP reload（同二进制重读配置）

来源：[NGINX-CTL]。原文："The master process first checks the syntax validity, then tries to apply new configuration... If this fails, it rolls back changes and continues to work with old configuration. If this succeeds, it starts new worker processes, and sends messages to old worker processes requesting them to shut down gracefully. Old worker processes close listen sockets and continue to service old clients. After all clients are serviced, old worker processes are shut down."

要点：配置失败可回滚；新 worker 先起，旧 worker 关监听但继续服务存量连接直至排空。与 USR2 的区别：HUP 换配置不换二进制，旧 worker 会关监听 socket（无回退保留）；USR2 换二进制，旧 master 不关监听以支持回退。

已知边界（HAProxy 文档对同类机制的表述，可作旁证）：旧进程关闭监听端口时，"the kernel may not always redistribute any pending connection that was remaining in the socket's backlog. Under high loads, a SYN packet may happen just before the socket is closed, and will lead to an RST packet being sent to the client."（https://docs.haproxy.org/3.0/management.html）。即 backlog 中未 accept 的连接在边界上仍可能丢，"无损"是工程意义上的近似无损。

### 2.3 SO_REUSEPORT（socket sharding）模式下的 reload

来源：
- nginx 官方 listen 文档：https://nginx.org/en/docs/http/ngx_http_core_module.html —— "reuseport this parameter (1.9.1) instructs to create an individual listening socket for each worker process (using the SO_REUSEPORT socket option on Linux 3.9+ and DragonFly BSD, or SO_REUSEPORT_LB on FreeBSD 12+), allowing a kernel to distribute incoming connections between worker processes."
- NGINX 官方博客（F5 存档）：https://www.f5.com/company/blog/nginx/socket-sharding-nginx-release-1-9-1 （Andrew Hutchings，2015-05-26）："there are multiple socket listeners for each IP address and port combination, one for each worker process"、"The kernel determines which available socket listener (and by implication, which worker) gets the connection."；性能：36 核 4 worker、wrk 压测 "reuseport increases requests per second by 2 to 3 times, and reduces both latency and the standard deviation for latency"；注意事项：单 worker 阻塞会连带影响内核已分给它的待处理连接；邮件模块不支持。

reload 行为：官方文档对「reuseport 模式下 HUP/USR2 的具体行为」没有专门描述【未查到官方原文】。机制上可推断（推断，未在官方文档坐实）：reload 时新 worker 各自新建监听 socket 加入内核 reuseport 组，旧 worker 保留自己的 socket 继续服务存量连接直至退出；新连接由内核在「当时组内所有 socket」间按哈希分发，期间新旧 worker 并行收新连接。旁证：Envoy 默认 reuse_port 且热重启时 "Envoy passes each socket to the new process by worker index. Thus, no connections are dropped in the accept queues of the draining process."（https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart）——同为 reuseport + 热重启组合的官方行为描述。

已知短板：
- 内核按连接四元组哈希分发，非负载感知；「分布不均」（如个别大流量长连接集中到某 worker）在 nginx 官方材料中未承认（官方博客反而称 "the load was spread evenly across the worker processes"，其测试条件为短连接压测），此问题在调研中未找到 nginx 场景的一手定量来源【未坐实】。UDP 场景的分布问题有 Facebook 一手材料（见 2.4）。
- Envoy 文档指出 reuseport+热重启组合的边界：并发数减少时 "some connections may be dropped in the accept queues of the old process workers"（同上 Envoy URL）。
- 安全提示：nginx 官方文档注明 "Inappropriate use of this option may have its security implications."

### 2.4 eBPF 引导/重定向 socket（sk_lookup 与 sk_reuseport 两条线）

任务前提修正（重要）：公开一手材料中，用 eBPF 做「零停机重启」的完整实践是 **Facebook（Meta）** 的 LPC 2021 分享（用的是 BPF_PROG_TYPE_SK_REUSEPORT + REUSEPORT_SOCKARRAY，外加早期纯 SCM_RIGHTS fd 传递的 socket takeover）；**Cloudflare** 贡献并生产使用的是 **sk_lookup hook（tubular 工具）**，其定位是「突破 bind/listen API 限制 + 新连接动态引导」，并非专门的重启机制；**Cilium** 的 socket-level LB 是东西向服务负载均衡（connect() 时改写），与进程重启无关。分述如下。

**(a) Facebook《From XDP to Socket: Routing of Packets beyond XDP with BPF》（LPC 2021）**

来源（中文译文，原 LPC 页面未直接取到）：https://cloud.tencent.com/developer/article/1917092 （译文；原始分享见 LPC 2021 议题，原文链接 arthurchiao.art/blog/facebook-from-xdp-to-socket-zh/ 为译者注）【译文来源，一手 slides 未取到，未二次坐实】

- 早期方案 socket takeover（他们自称 zero downtime restart）：不等老进程排空，直接起新进程，通过一个本地 socket 把老进程的 TCP listening socket 与 UDP VIP socket（fd，经 SCM_RIGHTS）转移给新进程；老进程继续服务已接受连接（1~N），新进程收新连接（N+1~∞），老进程后台 drain。优点：发布不损失容量、老连接 reset 概率大降。缺陷：UDP（尤其 QUIC）连接状态在应用层，内核 socket 迁移无法保证现有 UDP 流的包路由一致性，包会随机散落到新老进程，被迫加用户态补丁解析 QUIC ConnectionID 转发，复杂脆弱。
- 新方案：BPF_PROG_TYPE_SK_REUSEPORT + BPF_MAP_TYPE_REUSEPORT_SOCKARRAY（key = VIP:Port，value = 业务进程 socket fd）。新进程 bind 后但未 ready 前，BPF 持续把全部流量转给老进程；应用自行完成初始化/健康检查后更新 map 触发切换；对 UDP 老流维护 flow→socket 映射保证一致性路由。效果：发布期间丢包无明显上升；对照 socket takeover 3x 流量即丢包，bpf_sk_reuseport 组 30x 流量 CPU 打满仍几乎不丢。
- 落地时暴露的内核隐患：新老进程以带/不带 SO_REUSEPORT 混合 bind 同端口均成功，触发内核 bind 哈希桶长链遍历（linux v5.10 net/ipv4/inet_connection_sock.c 附近，2020-06 内核邮件列表修复），高连接速率下 CPU spike 甚至 host locking。

**(b) Cloudflare sk_lookup + tubular**

来源：官方博客《Production ready eBPF, or how we fixed the BSD socket API》（Lorenz Bauer，2022-02-17）https://blog.cloudflare.com/tubular-fixing-the-socket-api-with-ebpf/ ；开源 https://github.com/cloudflare/tubular ；内核文档 https://www.kernel.org/doc/html/latest/bpf/prog_sk_lookup.html

- 动机："We've outgrown the BSD sockets API."——服务分布于海量 IP、同端口多服务共存（公网递归解析器与权威 DNS 同监听 53）、Spectrum 需监听全部 2^16 端口，传统 bind 不可行。
- 机制：sk_lookup hook 是 Cloudflare 贡献给 Linux 内核的钩子（内核文档："BPF sk_lookup program type was introduced to address setup scenarios where binding sockets to an address with bind() socket call is impractical"）；tubular = attach 到 sk_lookup 的 BPF 程序 + 用户态 Go 管理代码，bindings（匹配规则，支持 CIDR/端口通配，LPM trie 最长前缀优先）与 sockets 用 label 关联，决定每个新连接/报文交给哪个 socket。
- 与重启/发布的关系：监听地址可在线增删（"you can change the addresses of a service on the fly... it's just an HTTP POST away"）；获取业务 socket 的三种方式：SCM_RIGHTS 传 fd（需改进程，弃用）、systemd socket activation、pidfd_getfd 从外部进程借 fd（"We can use it to iterate all file descriptors of a foreign process, and pick the socket we are interested in."，示例 tubectl register-pid 从 httpd 进程借 fd）。tubular 自身 BPF 程序可经 bpf_link 原子升级，"otherwise we may drop connections"。
- 生产规模："tubular is in production at Cloudflare today"、"tubular runs on thousands of machines"。
- 边界：sk_lookup 只在新连接/报文的 socket 查找阶段生效，已建立的 TCP 连接不在其作用域内（原文未系统讨论 TCP 已建连接迁移，此为机制推断）【推断，未在原文坐实】。内核版本原文未写明（推断约 5.9+：sk_lookup 需 5.9、bpf_link 需 5.7、pidfd_getfd 需 5.6）【推断】。

**(c) Cilium socket-level LB（澄清：非重启机制）**

来源：https://docs.cilium.io/en/latest/overview/intro/ —— "East-west load balancing rewrites service connections at the socket level (connect()), avoiding the overhead of per-packet NAT and fully replacing kube-proxy."；功能首见于 Cilium 1.6 发布博客（2020/2019-08-20）https://cilium.io/blog/2019/08/20/cilium-16/ 。其 BPF 程序挂在 cgroup connect4/connect6 等钩子，做服务地址改写（东西向负载均衡），公开文档未将其描述为零停机重启手段【任务前提与实际不符，如实记录】。

## 3. 用户态协议栈项目逐个结论

### 3.1 Seastar（ScyllaDB 底座，DPDK 模式 share-nothing）

来源：GitHub README https://github.com/scylladb/seastar ；官方教程 https://raw.githubusercontent.com/scylladb/seastar/master/doc/tutorial.md

- 架构（教程原句）："Seastar programs use the share-nothing programming model, i.e., the available memory is divided between the cores, each core works on data in its own part of memory, and communication between cores happens via explicit message passing"；"Seastar-based programs run a single thread on each CPU. Each of these threads runs its own event loop, known as the engine"；网络栈："Seastar can use the host operating system's TCP stack, it also provides its own high-performance TCP/IP stack built on top of the task scheduler and the share-nothing architecture"；DPDK："Seastar comes with its own userspace TCP/IP stack for better performance"、"works with a customized version of DPDK"（README）。
- nginx 或等价 HTTP server：无 nginx 移植。自带 httpd 演示组件（README 性能段提及 WRK vs httpd）与第三方 Web 框架（cpv-framework）。
- reload/连接迁移机制：README 与 tutorial 全文无任何 restart/connection migration/zero-downtime 内容【查证为「无」，基于这两份官方文档的非穷尽检索】。即 Seastar 不提供框架级进程重启连接保持能力；ScyllaDB 的可用性靠集群层（多副本+客户端驱动重连+滚动重启），本调研未取到 ScyllaDB 滚动重启的一手文档【未坐实，仅此推断】。

### 3.2 mTCP（KAIST，epoll 兼容用户态栈）

来源：GitHub https://github.com/mtcp-stack/mtcp （README 与源码树）；头文件 https://raw.githubusercontent.com/mtcp-stack/mtcp/master/mtcp/src/include/mtcp_api.h

- 形态：DPDK/netmap/psio/onvm 多 I/O 引擎；"mTCP expects a one-to-one RSS queue to CPU binding"（README）。编程模型从头文件签名可见：`mtcp_core_affinitize(int cpu)` + `mtcp_create_context(int cpu)` 返回 per-core 的 mctx，几乎所有 socket API 以 mctx 为第一参数——每线程绑核持一个栈上下文（头文件无注释，此为签名推断）。
- 多进程/fork：README、Notes、FAQ、api.h 均无任何 fork/多进程支持或限制的声明【官方文档查无】。结合 DPDK EAL 全局初始化与全局 g_mtcp[] 数组（api.c 代码结构），不支持 fork 后跨进程共享栈实例属合理推断【推断，未坐实】。
- nginx 或等价：无 nginx 移植；官方移植的是 lighttpd-1.4.32（apps/lighttpd-1.4.32）与 ab 压测客户端。
- reload/升级机制：README 无任何 reload/graceful 相关说明，仅有 "^C 优雅退出，连按两次强退"。结论：无此机制（文档层面）【仅基于 README，未二次坐实】。

### 3.3 6WIND Virtual Accelerator（商业）

来源：官方文档 https://doc.6wind.com/new/virtual-accelerator-3/3.4/virtual-accelerator/getting-started/introduction.html （产品页 www.6wind.com/virtual-accelerator/ 抓取 403；datasheet PDF 未抓取）

- 架构：fast path（6WINDGate 技术）跑在 KVM hypervisor 内专用核上，旁路卸载 Linux 网络栈；"a continuous and transparent synchronization mechanism, so that all Linux configuration is synchronized into the fast path"；加速对象是虚拟交换（OVS/Linux Bridge offload）、VM 流量（Virtio 后端 PMD）、转发/隧道/IPsec/NAT/QoS 等；对应用透明："existing Linux applications do not need to be modified to benefit from packet processing acceleration"，标准 Linux API/工具（iproute2/iptables/ovs-vsctl 等）保留。
- nginx：文档未提及 nginx；本地主机应用（如 web server）流量路径细节该 introduction 页未展开（"processes all incoming packets from NICs or vNICs"，未指明交回内核栈的细节）。推断其模型是「本地应用 socket 仍属 Linux 内核栈，fast path 只加速转发/VM 类流量」，因此 nginx 的 reload/USR2 语义天然保留【推断：基于「应用无需修改 + Linux API 保留」的架构描述，本地应用路径细节未二次坐实】。"fast path nginx"直接组合的一手材料未查到（搜索无果）【未查到】。

### 3.4 ansyun/dpdk-nginx（DPDK 用户态栈 ANS 上的 nginx 分支）

来源：https://github.com/ansyun/dpdk-nginx （README）

- 形态：fork 自 nginx（README 正文写 1.9.5、ABOUT 写 1.12.2，压测输出显示 1.12.2，正文为历史遗留），直接链接 DPDK（dpdk-16.07）与配套用户态栈 ANS（dpdk-ans 仓库）。
- 关键能力："ANS tcp stack support reuseport, so can enable nginx reuseport feature, multi nginx can listen on same port." —— 用户态栈实现了 SO_REUSEPORT 等价物，靠多个独立 nginx 进程监听同一端口横向扩展（性能测试即 4/8/10 个 nginx 实例并列）。
- reload/平滑升级：README 完全未提及 nginx -s reload/信号/热升级【查无】。无证据支持其有无损 reload。
- 意义：证明「用户态栈实现 reuseport 等价物 + 多进程并列」这条路在 DPDK 栈上可行，是 F-Stack 最直接的同类先例（仅连接分发层面，不含 drain 语义描述）。

### 3.5 OpenOnload（AMD/Xilinx Solarflare，对照样本：内核旁路但保持 socket 语义）

来源：https://github.com/Xilinx-CNS/onload （README）

- 定位："a high performance user-level network stack, which accelerates TCP and UDP network I/O for applications using the BSD sockets on Linux"；"comprises a user-level shared library that intercepts network-related system calls and implements the protocol stack, and supporting kernel modules"；"Binary compatible with existing applications."
- 对本课题最关键的一句（README 原句）："It is compatible with the full system call API, including those aspects that are usually problematic for user-level networking, such as fork(), exec(), passing sockets through Unix domain sockets, and advancing the protocol when the application is not scheduled."
- 即：Onload 把 fork/exec/UDS 传 socket 这些「用户态网络最难兼容的语义」作为兼容目标，因此 nginx 的 master-worker fork 模型、HUP/USR2 的 fd 继承语义在其模型下不被破坏（README 未直接讨论 nginx reload 行为【未坐实】，但架构目标即兼容既有进程模型）。与 F-Stack/Seastar 这类「栈即进程」的独立用户态栈是两个物种，是「旁路加速但保留内核 socket 语义」路线的代表。
- README 无进程重启/热升级专节【查无】。

### 3.6 lwIP / PicoTCP

- lwIP：定位嵌入式（可裸跑），Web 场景是自带 httpd 或 CGI demo，未发现 nginx 移植【搜索未见，非穷尽】。来源（背景）：https://gitee.com/alios-things/lwip 等。PicoTCP：同样未发现 nginx 相关【未查到】。二者均为单进程库形态，无 reload 机制可言【通用常识层面，无一手 reload 文档可引】。

### 3.7 F-Stack 官方 nginx 现状（本地档案，供第 5 节引用）

来源：本地仓库 /data/workspace/f-stack/docs/f-stack-issue-ana.md（issue 分析档案，#12/#528/#547/#1036 条目）

- 官方结论：F-Stack nginx 开箱不支持优雅 reload（doc/F-Stack_Nginx_APP_Guide.md 已明确）；根因："under F-Stack's multi-process model, each worker exclusively binds a NIC hardware queue (via RSS); during reload, when the old worker exits before the new worker has finished initializing DPDK/the F-Stack stack, there is a window where no process holds that queue, causing packets to be dropped—unlike native nginx workers, which share..."（#1036 结论）。
- 多进程约束："exec() is not supported; DPDK resources cannot survive an exec() call. Multi-process operation uses fork() followed by separate ff_init() calls per process."（档案中 #12 相关结论）→ 直接判死 nginx USR2 路线（USR2 依赖 exec 新二进制）。
- 社区先例：#547（orange30，2021-09-22 确认）"DPDK 18.11 + f-stack-1.20，专用接收核（rcv core）与 nginx 核分离 + 动态 renice 优先级，实现 nginx reload 零丢包」，未合并官方主线，DPDK 19+ 因 timer 库变化不兼容。
- 另外：LD_PRELOAD 模式（libff_syscall.so hook 系统调用）是另一条接入路径（docs/zh_cn/F-Stack_Architecture_Layer1_System_Overview.md 方式 2），详见 [05-ld_preload 备选路线](05-ld-preload-alternative.md)。

## 4. 通用模式归纳：用户态/内核下无损 reload 的几类做法

综合上述来源，业界做法可归为六类（每类给代表与来源）：

**P1. 监听 fd 跨进程传递（fd 继承 / SCM_RIGHTS / 域套接字取回）**
- nginx USR2：fork+exec 继承 + NGINX 环境变量显式传 fd 列表（[NGINX-CTL]；trac #237 官方回复原句）。
- Envoy hot restart：新进程经 unix domain socket RPC 向旧进程按 worker index 取 listen socket 副本，"no connections are dropped in the accept queues of the draining process"（https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart）。
- HAProxy：`-x <unix_socket>` "connect to the specified socket and try to retrieve any listening sockets from the old process"；master-worker 模式自动用 sockpair@ 传递，无需 expose-fd listeners（https://docs.haproxy.org/3.0/management.html）。
- Facebook socket takeover：SCM_RIGHTS 经本地 socket 把 listening fd 从老进程转给新进程（LPC 2021 译文，见 2.4(a)）。
- systemd socket activation：init 系统持有监听 fd 经 SCM_RIGHTS 传给服务进程（sd_listen_fds）；nginx 官方不支持该特性，内部 NGINX 环境变量机制被官方视为足够（https://trac.nginx.org/nginx/ticket/237，状态 REOPENED 14 年）。
- 通用约束（全部方案共有）：fd 传递只解决「监听不空窗」，已建连接不迁移——Envoy 官方原句："existing connections are not transferred to the new Envoy process: they must complete during the drain process or be terminated."；nginx/HAProxy/FB 同构（旧进程 drain 存量）。

**P2. SO_REUSEPORT 组（内核/用户态栈等价物）+ 旧进程 drain**
- nginx reuseport（见 2.3）；HAProxy："HAProxy works around this on systems that support the SO_REUSEPORT socket options, as it allows the new process to bind without first asking the old one to unbind."（docs.haproxy.org 同上）；Envoy 默认 reuse_port。
- 用户态栈等价物先例：ANS 栈实现 reuseport 支持 dpdk-nginx 多实例共听同端口（3.4）。FB 新方案本质上也是 reuseport 组的可编程化（sk_reuseport 程序接管组内分发）。
- 短板：哈希分发非负载感知；边界丢 backlog 连接（HAProxy 官方文档承认）；UDP/QUIC 一致性路由是难点（FB 一手经验）。

**P3. 可编程 socket 查找/引导（eBPF：sk_lookup、sk_reuseport）**
- Cloudflare tubular/sk_lookup：新连接动态引导到任意 socket，监听规则在线变更（2.4(b)）。
- Facebook sk_reuseport + map：新进程 ready 前 BPF 持续把流量导给老进程，应用层显式触发切换；UDP 老流用 flow→socket map 保一致（2.4(a)）。
- 本质：把「哪个进程收新连接」的决定权从内核固定 hash 改为用户态可编程 map，使发布/重启过程可精确控制新连接走向。
- 仅适用内核栈（钩子在内核查找路径）；用户态栈需在自己的包分发层造等价物。

**P4. 双进程/双实例热备 + 流量切换（不迁移连接）**
- 新老实例并行、新连接切换到新实例、老实例 drain：FB 方案、HAProxy SIGTTOU pause/恢复（"the old process continues to process existing connections"）、HAProxy master-worker reload（SIGUSR2 重新 exec 自身 + -sf 传旧 worker pid）皆为实例级热备。
- 值得注意：调研范围内没有发现任何项目做「TCP 已建连接的状态迁移/流表同步后接管」（连接迁移仅在 UDP/QUIC 用 flow map 做「继续路由给老进程」，不是把状态搬给新进程）。所谓 zero-downtime 全部 = 新连接无缝 + 旧连接排空【基于本报告全部来源的归纳】。

**P5. 保持内核 socket 语义的旁路加速（架构性规避）**
- OpenOnload：兼容 fork/exec/UDS 传 fd 等全套系统调用语义（3.5），nginx 的既有 reload/upgrade 机制不被破坏。6WIND Virtual Accelerator 同理（本地应用仍走 Linux 栈，fast path 只加速转发/VM 流量，3.3【部分推断】）。
- 该路线以「应用零修改 + 语义保留」换性能上限（受网卡/厂商绑定或加速范围限制）。

**P6. 集群层容错（放弃单机无损）**
- Seastar/ScyllaDB：框架不提供进程级连接保持，靠副本+客户端重连+滚动重启（3.1【滚动重启一手文档未取到】）。对 HTTP 这类短连接业务等价于「可接受」，对长连接业务不适用。

## 5. 对 F-Stack 的适用性初判

结合本地档案（3.7）与上节模式：

1. USR2 式二进制升级（P1 的 exec 变体）在 F-Stack 现架构下不可行：DPDK 资源不能跨 exec 存活（档案 #12 结论），且旧 master/exec 新 master 均需重新 ff_init 绑定队列。除非把「栈实例」与「nginx 进程」解耦（见第 4 节）。
2. HUP 式 reload 的丢包根因不是监听 fd（用户态栈里 fd 只是句柄），而是 RSS 硬件队列所有权的空窗期（档案 #1036 根因）。因此照搬 P1（fd 传递/SCM_RIGHTS）不解决问题；照搬 P2 的收益也有限——F-Stack 每 worker 本来就是独立 listen 的栈实例，「reuseport 等价物」天然存在（新连接按 RSS 哈希进各队列），真正缺的是「切换期间队列始终有人收」。
   【2026-08-18 增补：与 VPP/VCL 线交叉收敛】本判断与 [01-VPP/VCL 调研](01-vpp-vcl-research.md) 6.2 节独立得出同构结论：**网卡队列/收包所有权与业务进程生命周期的解耦，是用户态栈无损 reload 的结构性前提；监听 fd 是第二位问题**。VPP/VCL 模式两层天然解耦（数据面：队列归独立 VPP 进程，主窗口问题结构性不存在，#3645 反面印证包持续进 VPP、仅事件同步卡死；控制面：listen 归 VPP 侧 app 级单点）。佐证（据 researcher-vpp-vcl 报告转述，本报告未独立核实）：#1078 primary_slim PoC 杀 primary 后 12/12 存量连接零中断、adapter/syscall 中心化设计。下述方向 A/B/C 的共同前置条件即此结构性前提；方向 C 与 VCL 的 atfork + app_listener workers bitmap（新 worker 注册进 bitmap 前 accept 事件不分发给它，与 Facebook "ready 前不切流"同构）属同族设计。
3. 初判最可行的方向（供 spec 阶段论证，非结论；最终分档见 [06-方案设计](06-solution-design.md) §4）：
   - 方向 A（对应 P2/P4，业界主流形态）：旧 worker 保留队列与存量连接继续 drain，新 worker 完成初始化后再接管队列收新连接——难点在 DPDK 队列独占模型下一次只能一个进程持有队列，这正是 #547 社区方案（专用接收核 + 动态优先级）要解决的，但该方案基于 DPDK 18.11 未合并、19+ 不兼容。当前仓库主线是 DPDK 24.11.6，需重新设计（如独立 dispatcher/接收进程持有全部队列，按流表分发到各 nginx 进程——形态上接近 FB 的「专用接收路径 + flow→进程 map」（2.4(a)）与 VPP 的 worker 分发模型）。
   - 方向 B（对应 P3）：在 F-Stack 的 RSS/分发层引入「可编程 socket 查找」等价物（dispatcher 进程内 map：VIP:Port → nginx 实例），新实例 ready 前流量持续导给旧实例，由显式动作触发切换——FB sk_reuseport 模式的用户态移植。UDP/多租户场景需 flow 一致性表（FB 经验）。
   - 方向 C（对应 P5，架构性）：LD_PRELOAD 适配器模式下若能把「栈状态」与 fd 语义进一步内核化/守护进程化（栈独立于应用进程），reload 问题转化为守护进程不动、仅换应用进程——接近 OpenOnload/VCL(LDP) 形态；此线与调研员 A 的 VPP/VCL 结论交叉，spec 阶段合并评估。
   - 连接迁移（TCP 状态搬家）：业界无先例（P4 结论），不建议作为 F-Stack 目标；目标应定义为「新连接零丢 + 存量连接 drain 完成或由旧实例服务到自然结束」。
4. 明确不适用：systemd socket activation（nginx 官方不支持，trac #237）；Cilium SocketLB（与重启无关，2.4(c)）；纯内核 eBPF 钩子（F-Stack 收包不经内核）。

## 6. 未坐实 / 未查到清单

1. nginx 官方对 reuseport 模式下 reload 行为的正式描述——官方文档无；archive.org 抓 nginx.com 原博客 429 失败两次；现引用的 f5.com 存档页未含 reload 章节。第 2.3 节 reload 行为为机制推断 + Envoy 旁证。
2. nginx reuseport 「新连接分布不均」的一手定量来源——未找到（官方博客测试称均匀，系短连接压测条件）。仅 Envoy 文档坐实「并发减少时 accept 队列可能丢连接」、FB 坐实 UDP 分发问题。
3. Facebook LPC 2021 原始 slides/视频——未直接取到，引用的是腾讯云社区中文译文（并经译文内细节交叉读图），标「仅此来源，未二次坐实」。
4. sk_lookup 最低内核版本 5.9+ ——Cloudflare 原文未写明，为特性推断（bpf_link 5.7、pidfd_getfd 5.6、sk_lookup 5.9）。
5. Cloudflare tubular 是否实际用于 nginx 类业务进程的零停机「重启」——原文只坐实「监听地址动态管理 + tubular 自身原子升级 + 生产用于 Spectrum/权威 DNS」，未明说用于重启业务进程。
6. 6WIND：本地主机应用流量路径细节（introduction 页未展开）；"fast path 上跑 nginx"的一手材料——未查到。
7. mTCP：fork/多进程支持的官方声明——README/FAQ/api.h 均无；「单进程多线程模型」为 API 签名与 RSS 绑定描述的推断。
8. Seastar/ScyllaDB 滚动重启依赖客户端驱动重连的一手文档——未取到（Seastar README/tutorial 已坐实「框架无连接迁移机制」这一反向结论）。
9. lwIP/PicoTCP 无 nginx 移植——基于搜索未见（非穷尽）。
10. Cilium cilium.io 1.6 博客正文抓取不完整（页面为 JS 框架），socket LB 细节以 docs.cilium.io intro 页原句为准。
11. TencentOS 用户态协议栈——未单独调研（F-Stack 本身即腾讯开源用户态栈，视为同一对象；TencentOS Server 内核侧优化与本课题无关）。
