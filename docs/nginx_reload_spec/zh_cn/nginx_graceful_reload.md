F-Stack 2.0 前瞻9：nginx 优雅 reload 纪实，从「reload 必断流」到两代进程共存的分流架构

1. 本功能主要作用和特点

先说这事有多糟。issue #528（重复于 #1036）里官方给的结论是：F-Stack nginx 不支持优雅重载，`-s reload` 无论怎么调都会造成短暂服务中断。原因不复杂：F-Stack 的 nginx master 进程本身就是 DPDK primary，独占网卡；reload 一来 worker 全部退出重建，进程更替的空档里网卡队列没人收包，流量必丢。社区里唯一的先例是 #547 那套 DPDK 18.11 时代的专用接收核补丁，和现在的多进程架构早就对不上了。

这次把 reload 整个补齐了。`graceful_reload=1` 之后：

- **HUP 无损 reload**：新旧两代 worker 并存，新代接管网卡收包并逐包分流，旧代继续服务存量连接直到排空退出。TCP 长传输跨 reload md5 不变、0 停顿；UDP 新流立刻归新代，旧流留在旧代直到空闲
- **USR2 二进制升级 + WINCH**：换二进制文件发版也走同一套交接协议，旧 master 的 worker 在活跃 UDP 流排空前先 linger，不会一交接就把旧流扔下
- **反向代理对称支持**：两代主动连上游的临时端口按奇偶分代，新代发起的 TCP/UDP 上游连接，应答不会再被误送给旧代（分别是 RX-39 和 RX-40）
- **KNI/内核共存不受影响**：绑内核端口的流量经 KNI ring 由归属代 worker 送内核，reload 前后 veth、SSH、控制面照常工作
- **可观测**：master 打每一步 FSM 迁移和完成统计，worker 打排空与 UDP linger 日志；25 个集成用例加一层单测兜底

关键词就三个：**常驻 slim primary**（网卡不再跟着 nginx 重启）、**按代分流**（软件流表 + UDP 发布表决定每个包归谁）、**有限收敛**（排空有硬上限，不会无限等下去）。

2. 本功能的主要适用场景

2.1 长连接业务的高频发布

推送、IM、网关 keepalive 这类业务最怕 reload：原生 F-Stack 一 reload 全断重连。两代共存后存量连接不断，新配置对新建连接立刻生效。实测 36 条并发流跨 HUP，md5 全部一致、0 停顿。

2.2 反向代理

proxy 场景有个隐蔽的坑：新代主动连上游，SYN-ACK 回来在流表里查不到，被当成旧流转给了旧代，窗口内新建上游连接全部 504（RX-39）。UDP 代理更惨，修复前 worker 在第一个代理数据报上就 SIGSEGV（RX-41）。现在 TCP/UDP 的临时端口都按代奇偶划分，两代上游四元组不会撞，各自的应答各回各的。

2.3 DNS / UDP 服务，给 QUIC 打底

UDP 没有 SYN，没法照抄 TCP 的判别面，单独做了一套「发布表」机制。DNS 这种一问一答的业务 reload 无感；持续发包的 UDP 流在窗口内保持归属，直到空闲或到上限。HTTP/3 本次没启用（构建没开 `--with-http_v3_module`），但四元组分流对 QUIC 的适用范围和局限都写进了文档，连接 ID 路由是后续方向。

2.4 二进制热升级

改了代码要发版，USR2 + WINCH 走同一套交接协议，升级期间服务不断。有个限制要记着：老 master 还活着时，新 master 会拒绝 HUP，日志写明原因——不挡这一下，两代变三代，端口奇偶这类不变量就全乱了。

2.5 不太适合的场景

- 指望 QUIC 连接迁移 / NAT 重绑定后还保持旧连接：四元组一变就归新代，原连接断开；CID 路由没做
- 依赖 IP 分片的大 UDP 应答：分片报文一律留在新代（和 TCP 的处理一致）
- 想把 reload 完成时间精确控制在亚秒级：旧流没排空时，完成时间由旧连接何时结束决定，上限是 `worker_shutdown_timeout`（不配默认 90 s）

3. 本功能的架构特征

3.1 进程模型与共享结构

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 880 420" font-family="sans-serif" font-size="13">
  <defs>
    <marker id="g9a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#456"/>
    </marker>
  </defs>
  <rect x="10" y="120" width="120" height="120" rx="8" fill="#eef" stroke="#88a"/>
  <text x="70" y="152" text-anchor="middle" font-weight="bold">物理网卡</text>
  <text x="70" y="174" text-anchor="middle">RSS 队列</text>
  <text x="70" y="192" text-anchor="middle">（DPDK 接管）</text>
  <rect x="200" y="16" width="230" height="58" rx="8" fill="#efe" stroke="#8a8"/>
  <text x="315" y="40" text-anchor="middle" font-weight="bold">nginx master</text>
  <text x="315" y="60" text-anchor="middle">reload 窗口内同时管两代</text>
  <rect x="560" y="16" width="250" height="58" rx="8" fill="#efe" stroke="#8a8"/>
  <text x="685" y="40" text-anchor="middle" font-weight="bold">常驻 slim primary</text>
  <text x="685" y="60" text-anchor="middle">只占网卡不跑协议栈，不随 reload 重启</text>
  <rect x="200" y="120" width="230" height="120" rx="8" fill="#ffe" stroke="#aa8"/>
  <text x="315" y="146" text-anchor="middle" font-weight="bold">G_new worker ×N（rx owner）</text>
  <text x="315" y="170" text-anchor="middle">收包 → 分流器</text>
  <text x="315" y="190" text-anchor="middle">软件流表（TCP）/ 发布表（UDP）</text>
  <text x="315" y="210" text-anchor="middle">新流本地处理</text>
  <rect x="560" y="120" width="230" height="120" rx="8" fill="#fee" stroke="#a88"/>
  <text x="675" y="146" text-anchor="middle" font-weight="bold">G_old worker ×N（排空）</text>
  <text x="675" y="170" text-anchor="middle">收 drain ring 转来的旧流包</text>
  <text x="675" y="190" text-anchor="middle">存量 TCP/UDP 流继续服务</text>
  <text x="675" y="210" text-anchor="middle">回包经 ring 由新代代发</text>
  <rect x="170" y="290" width="650" height="105" rx="8" fill="#f2f2f2" stroke="#999"/>
  <text x="495" y="312" text-anchor="middle" font-weight="bold">共享内存（hugepage memzone / 匿名共享块）</text>
  <rect x="180" y="322" width="145" height="60" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="252" y="346" text-anchor="middle">世代目录</text>
  <text x="252" y="364" text-anchor="middle">epoch / rx 归属 /</text>
  <text x="252" y="378" text-anchor="middle">park / 端口奇偶</text>
  <rect x="333" y="322" width="145" height="60" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="405" y="346" text-anchor="middle">drain rings</text>
  <text x="405" y="364" text-anchor="middle">队列 × 代 ×</text>
  <text x="405" y="378" text-anchor="middle">收 / 发方向</text>
  <rect x="486" y="322" width="155" height="60" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="563" y="346" text-anchor="middle">UDP 发布表</text>
  <text x="563" y="364" text-anchor="middle">ff_fpeer_*，每</text>
  <text x="563" y="378" text-anchor="middle">(proc, slot, gen) 一张</text>
  <rect x="649" y="322" width="161" height="60" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="729" y="346" text-anchor="middle">reload 共享块</text>
  <text x="729" y="364" text-anchor="middle">T2 屏障 / 心跳 /</text>
  <text x="729" y="378" text-anchor="middle">READY / KNI ring</text>
  <line x1="130" y1="180" x2="200" y2="180" stroke="#456" stroke-width="1.5" marker-end="url(#g9a)"/>
  <text x="165" y="172" text-anchor="middle" font-size="12">收包</text>
  <line x1="430" y1="160" x2="560" y2="160" stroke="#456" stroke-width="1.5" marker-end="url(#g9a)"/>
  <text x="495" y="152" text-anchor="middle" font-size="12">旧流包转发</text>
  <line x1="560" y1="200" x2="430" y2="200" stroke="#456" stroke-width="1.5" marker-end="url(#g9a)"/>
  <text x="495" y="222" text-anchor="middle" font-size="12">回包代发</text>
  <line x1="315" y1="74" x2="315" y2="120" stroke="#456" stroke-width="1.5" marker-end="url(#g9a)"/>
  <text x="360" y="102" font-size="12">fork / READY / park 令</text>
  <path d="M200,45 C120,90 110,290 170,340" fill="none" stroke="#456" stroke-width="1.2" stroke-dasharray="5,4" marker-end="url(#g9a)"/>
  <text x="112" y="272" font-size="12">读写目录</text>
  <path d="M690,74 C800,120 800,280 812,322" fill="none" stroke="#456" stroke-width="1.2" stroke-dasharray="5,4" marker-end="url(#g9a)"/>
  <text x="802" y="230" font-size="12" text-anchor="end">预建 memzone</text>
</svg>

几件事值得单独点一下：

- slim primary 只占 PCI 设备、不初始化协议栈，nginx 的所有进程（master 和 worker）都是 secondary。reload 只动 nginx 自己，primary 原地不动，网卡队列永远有人
- primary 不是无脑常驻：按 pid/comm 判活复用，同时比对启动时的配置摘要。设备侧配置（网卡绑定、队列数、`mtu_enable` 这类）变了，说明复用不安全，HUP 直接拒绝并给出原因
- 世代目录（`ff_reload_gendir`，hugepage memzone）是跨 master 的协调点：epoch 单调递增、4 个槽位记录每轮升级的 master、rx 归属字、端口奇偶标记都放在这里。HUP 是同一个 master 内两代交替，USR2 是两个 master 各占一个槽，两套场景共用一份结构

3.2 HUP 的六步状态机

master 侧把一次 reload 建模成 T0~T5 的状态机：

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 880 400" font-family="sans-serif" font-size="13">
  <defs>
    <marker id="g9b" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#456"/>
    </marker>
  </defs>
  <rect x="80" y="12" width="180" height="34" rx="8" fill="#efe" stroke="#8a8"/>
  <text x="170" y="34" text-anchor="middle" font-weight="bold">master（nginx）</text>
  <rect x="380" y="12" width="180" height="34" rx="8" fill="#fee" stroke="#a88"/>
  <text x="470" y="34" text-anchor="middle" font-weight="bold">G_old worker ×N</text>
  <rect x="650" y="12" width="180" height="34" rx="8" fill="#ffe" stroke="#aa8"/>
  <text x="740" y="34" text-anchor="middle" font-weight="bold">G_new worker ×N</text>
  <line x1="170" y1="46" x2="170" y2="384" stroke="#999" stroke-dasharray="4,4"/>
  <line x1="470" y1="46" x2="470" y2="384" stroke="#999" stroke-dasharray="4,4"/>
  <line x1="740" y1="46" x2="740" y2="384" stroke="#999" stroke-dasharray="4,4"/>
  <text x="24" y="82" font-weight="bold">T1</text>
  <line x1="170" y1="78" x2="740" y2="78" stroke="#456" stroke-width="1.5" marker-end="url(#g9b)"/>
  <text x="455" y="70" text-anchor="middle">fork 新代（每个 worker 就绪后写 READY：epoch&lt;&lt;32 | pid）</text>
  <text x="24" y="114" font-weight="bold">T2</text>
  <line x1="170" y1="110" x2="470" y2="110" stroke="#456" stroke-width="1.5" marker-end="url(#g9b)"/>
  <text x="320" y="102" text-anchor="middle">park 令（rx_stopped=1，先别动归属）</text>
  <line x1="470" y1="138" x2="170" y2="138" stroke="#456" stroke-width="1.5" stroke-dasharray="6,4" marker-end="url(#g9b)"/>
  <text x="320" y="130" text-anchor="middle">park ack：主循环确认「本轮起跳过收发包」的那一轮</text>
  <line x1="170" y1="170" x2="740" y2="170" stroke="#456" stroke-width="1.5" marker-end="url(#g9b)"/>
  <text x="455" y="162" text-anchor="middle">收齐 ack → rx 归属翻转，新代开始收包、分流器上线</text>
  <text x="24" y="206" font-weight="bold">T3</text>
  <line x1="740" y1="202" x2="470" y2="202" stroke="#456" stroke-width="1.5" marker-end="url(#g9b)"/>
  <text x="605" y="194" text-anchor="middle">旧流的包转发给旧代，回包反向代发</text>
  <line x1="470" y1="232" x2="170" y2="232" stroke="#456" stroke-width="1.5" stroke-dasharray="6,4" marker-end="url(#g9b)"/>
  <text x="320" y="224" text-anchor="middle">1 Hz drain report：conns / snd_pending / syncache / UDP 活跃流</text>
  <text x="170" y="262" text-anchor="middle" font-size="12">等 report 归零，上限 worker_shutdown_timeout（默认 90 s）</text>
  <text x="24" y="306" font-weight="bold">T5</text>
  <line x1="170" y1="302" x2="470" y2="302" stroke="#456" stroke-width="1.5" marker-end="url(#g9b)"/>
  <text x="320" y="294" text-anchor="middle">QUIT（10 s 重发，90 s SIGTERM 兜底）</text>
  <text x="470" y="330" text-anchor="middle" font-size="12">退出前把 UDP 发布表置 HANDED，剩余 UDP 流当场移交</text>
  <text x="24" y="372" font-weight="bold">T0</text>
  <text x="170" y="372" text-anchor="middle" font-size="12">窗口关闭，日志：graceful reload complete（took / 转发统计 / ring 峰值）</text>
</svg>

T2 是整个交接里最要紧的一步。master 下 park 令之后不能直接翻归属，必须等旧代每个存活的 worker 在自己的主循环里确认「这一轮开始跳过收发包」并 ack——没有这个屏障，网卡队列可能出现两个消费者，或者一个都没有。另一个配套机制是心跳：rx owner 每轮主循环递增共享块里的 heartbeat，其他进程采样它就能发现接收方卡死（`reload_heartbeat_timeout_ms`），不至于对着一个假 owner 空等。

3.3 分流器：每个包归谁

窗口打开后，新代 worker 的收包路径先进分流器（`ngx_ff_flow_map_dispatcher`），TCP 和 UDP 走两套规则：

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 880 450" font-family="sans-serif" font-size="13">
  <defs>
    <marker id="g9c" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#456"/>
    </marker>
  </defs>
  <rect x="330" y="14" width="220" height="32" rx="8" fill="#eef" stroke="#88a"/>
  <text x="440" y="35" text-anchor="middle" font-weight="bold">新代收包（窗口内，分流器）</text>
  <path d="M400,46 C300,60 180,70 165,80" fill="none" stroke="#456" stroke-width="1.5" marker-end="url(#g9c)"/>
  <path d="M480,46 C580,60 700,70 715,80" fill="none" stroke="#456" stroke-width="1.5" marker-end="url(#g9c)"/>
  <rect x="30" y="80" width="290" height="310" rx="8" fill="#f8f8ff" stroke="#99a"/>
  <text x="175" y="102" text-anchor="middle" font-weight="bold">TCP（proto=6）</text>
  <rect x="50" y="114" width="250" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="175" y="132" text-anchor="middle">纯 SYN（无 ACK）→ 留本地</text>
  <rect x="50" y="162" width="250" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="175" y="180" text-anchor="middle">查软件流表 ff_flow_map（key 带 proto）</text>
  <rect x="50" y="216" width="250" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="175" y="234" text-anchor="middle">命中 → 留本地（本代连接）</text>
  <rect x="50" y="264" width="250" height="26" rx="6" fill="#fdd" stroke="#b88"/>
  <text x="175" y="282" text-anchor="middle">未命中 → 转旧代（drain ring）</text>
  <line x1="175" y1="188" x2="175" y2="216" stroke="#456" stroke-width="1.5" marker-end="url(#g9c)"/>
  <line x1="175" y1="188" x2="175" y2="264" stroke="#456" stroke-width="1.5" marker-end="url(#g9c)"/>
  <text x="175" y="330" text-anchor="middle" font-size="12">登记点：SYN 准入（syncache）、主动 connect</text>
  <text x="175" y="348" text-anchor="middle" font-size="12">发 SYN 前（RX-39）；撤销跟着 pcb 走</text>
  <rect x="360" y="80" width="490" height="310" rx="8" fill="#fff8f0" stroke="#a96"/>
  <text x="605" y="102" text-anchor="middle" font-weight="bold">UDP（proto=17）</text>
  <rect x="380" y="114" width="200" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="480" y="132" text-anchor="middle">本代流表命中 → 留本地</text>
  <rect x="380" y="162" width="200" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="480" y="180" text-anchor="middle">否则查旧代 UDP 发布表</text>
  <rect x="600" y="108" width="240" height="26" rx="6" fill="#fdd" stroke="#b88"/>
  <text x="720" y="126" text-anchor="middle">无表 / NONE / wid 不匹配 → 转旧代</text>
  <rect x="600" y="144" width="240" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="720" y="162" text-anchor="middle">HANDED / 写者已死 → 留本地</text>
  <rect x="600" y="180" width="240" height="26" rx="6" fill="#fdd" stroke="#b88"/>
  <text x="720" y="198" text-anchor="middle">命中且未空闲 → 转旧代</text>
  <rect x="600" y="216" width="240" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="720" y="234" text-anchor="middle">命中但已空闲 → 留本地并学习</text>
  <rect x="600" y="252" width="240" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="720" y="270" text-anchor="middle">都不命中 → 留本地（新流）</text>
  <line x1="580" y1="175" x2="600" y2="121" stroke="#456" stroke-width="1.2" marker-end="url(#g9c)"/>
  <line x1="580" y1="175" x2="600" y2="157" stroke="#456" stroke-width="1.2" marker-end="url(#g9c)"/>
  <line x1="580" y1="175" x2="600" y2="193" stroke="#456" stroke-width="1.2" marker-end="url(#g9c)"/>
  <line x1="580" y1="175" x2="600" y2="229" stroke="#456" stroke-width="1.2" marker-end="url(#g9c)"/>
  <line x1="580" y1="175" x2="600" y2="265" stroke="#456" stroke-width="1.2" marker-end="url(#g9c)"/>
  <text x="480" y="330" text-anchor="middle" font-size="12">旧代常态记录自己收发的 UDP 四元组（按空闲老化），</text>
  <text x="480" y="348" text-anchor="middle" font-size="12">T1 时切到 PUBLISHING；外部报文伪造不出条目</text>
  <rect x="30" y="404" width="820" height="30" rx="6" fill="#f2f2f2" stroke="#999"/>
  <text x="440" y="424" text-anchor="middle" font-size="12">IPv4 分片、IPv6 扩展头、非 TCP/UDP：一律留本地（与 TCP 现状一致）</text>
</svg>

TCP 这套在 RX-39 之前有个洞：流表只有 syncache 一个登记点（被动建连），主动 connect 发出的 SYN 没人登记，上游回的 SYN-ACK 查表 miss 被转给旧代，窗口内新建上游连接全 504。修法是主动 connect 在发 SYN 前登记、撤销跟着 pcb 走（RST/关闭/drop 都覆盖），再加上两代临时端口按奇偶划分，四元组从根上就不会撞。

UDP 没法照抄：没有 SYN，也没有可靠的「新流」信号，而且 G_new 的流表里只有本代的条目，服务端的新旧判断需要的是「旧代有什么」。所以反过来做——旧代把正在服务的 UDP 四元组发布出来，新代查这张表决定转还是留。表头是个三态机：

```
进程挂接     → NONE         还没开始：新代按老行为转发（对端是旧二进制时就是这个状态，兼容）
窗口开始(T1) → PUBLISHING   常态记录的四元组整表可见；表头带窗口身份 wid，防上一轮的旧表被误认
进程退出     → HANDED       新代此后全部本地处理，不再转给退出中的旧代
```

条目按 `reload_udp_idle_ms` 空闲老化（默认 10 s）：一条流只要还在收发包就一直续着；旧代已经没人在服务的流，空闲到期后新代本地接管并学习进本代流表。

3.4 排空怎么收敛

旧代每秒上报一次 drain report：TCP 连接数（UDP socket 不再计入，否则配了 `listen ... udp` 每轮 reload 都被钉死在 deadline）、发送队列积压、半开连接数，再加上发布表里未老化的 UDP 流数。master 的 T3 等这个数归零，上限 `worker_shutdown_timeout`（不配默认 90 s），到点强制推进，剩余 UDP 流当场移交。USR2 没有 master 侧 T3，走 worker 自己的 linger：交接后旧 worker 收到 QUIT 时如果还有活跃 UDP 流，先留着监听继续服务，流空闲或到上限（配了 `worker_shutdown_timeout` 取该值，否则 30 s）再走退出流程。

4. 具体做了哪些改造、遇到了哪些问题、怎么解决的

后续比较枯燥，不需要深入研究实现过程的可以跳过本节，直接看第 5 节怎么用。

4.1 把 primary 从 nginx 里拆出来

这是整个功能的地基。原生的模型是「nginx master 即 DPDK primary」，worker 是 secondary——master 一退出，网卡就没人管了。改造后多出一个常驻的 slim primary：只做 DPDK EAL 初始化、占住 PCI 设备、建好共享 memzone（drain ring、世代目录这些都归它预建），协议栈一概不碰。nginx 的 master 和全部 worker 都是 secondary，进程随便杀随便换。

配套的东西不少：secondary 直接引用 primary 地址的指针转换（fp/gp/va 三套布局）、primary 按 pid/comm 判活复用、启动配置摘要比对（设备侧 key 变了必须整体重启）、以及 `nginx -s stop` 时连带停掉 primary，不然它就成孤儿了（RX-37 的内容，这里不展开）。

4.2 交接屏障、READY 和心跳

T2 的 park 屏障前面说过，这里补两个细节。一是新代 worker 起来后要写一个 READY 字（epoch 高 32 位 + pid），master 等 READY 等齐了才进入 T2——listen 都没建好的新代接管网卡就是事故。二是心跳：rx owner 每轮主循环加一，采样方发现心跳停了就不等它，按异常路径走。这两个都是「不信任对端一定活着」的防御，整个 reload 里这类防御到处都是，毕竟两个 master 十几个进程谁崩了都不能把别人拖死。

4.3 问题一：主动 connect 的回包被转给旧代（RX-39）

现象是反代场景窗口内新建上游连接 100% 超时，error.log 里一片 `upstream timed out (110: Connection timed out) while connecting to upstream`。抓包看很清楚：上游 SYN、SYN-ACK 都在，但 SYN-ACK 之后代理侧没有任何回应——SYN-ACK 带着 ACK 位，被分流器当成「已建立的旧流」转给了旧代，而旧代的流表里同样没有它，包进了旧代黑洞。修复就是 3.3 里说的主动登记 + 端口奇偶，外加一条防线：老 master 还在时新 master 拒绝 HUP，防止三代并存破坏奇偶不变量。修复后窗口内 20/20 请求 200，上游端口奇偶 0→1 干净分代。

4.4 UDP 的三个坑（RX-40 主体）

设计上借鉴了 Cloudflare udpgrm 的 FLOW 模式（旧实例在收发路径登记、条目老化、查不到的流给新实例），也记住了 Envoy hot restart 的教训——它把窗口内的新 UDP 包全经父进程转发，envoy#47833 记录过这条转发通道阻塞导致父子进程互相死锁。所以这里只转发「旧代已发布且活跃」的流，新流一律本地，转发面收得越小越好。实现过程中被三任审核各打回来一次，三个坑都值得记：

**坑一：只在发布期记录，第二轮 HUP 的表是空的。** 最初的设计是「窗口开始（T1）才记录」，T1 时顺带快照一次存量会话。实测第二轮 HUP 时 T3 只用了 1 秒就宣布排空完成，长流被提前移交。原因是第二轮的旧代在上一轮是「新代」，它服务的流都是经分流器本地的，而 UDP 的 `return` 会话一问一答即结束，快照抓不到东西；T1 之后第一个报文到来之前，活跃流数就是 0。改成常态记录：worker 挂接后每个 UDP 收发包都记（哈希加最多 32 次探测，约 256 KB 的表），T1 只把表头切到 PUBLISHING。代价是 graceful 模式下常态每包多一次哈希，换来的正确性值得。

**坑二：跨进程比时钟，无符号差把「未来」判成「已老化」。** 写者（旧代）和读者（新代）各自在自己主循环开头取一次 CLOCK_MONOTONIC 毫秒。写者这轮的取样经常比读者晚 1 ms 左右，于是读者算 `now - last` 得到 0xFFFFFFFF，无符号比较大于任何超时，活跃流被当成已老化、直接被新代抢走。改成有符号差 `(int32_t)(now - last) > (int32_t)idle`，顺手把配置上限压到 1 小时防止真溢出。单测里专门加了一个「写者晚 5 ms 仍判活」的用例。

**坑三：park 令把发布开始的门关上了。** USR2 多 worker 场景，旧 master 发现新 master 后下 park 令；某个兄弟 worker 把目录里的 rx_stopped 置 1 之后，还没开始发布的 worker 一看「我不是 rx owner 了」，按原来的门控（还持有 rx 才开始发布）就永远不发布了——它会照常 ack park，但表停在 NONE，新代只能按老行为转发。根因是「还持有 rx」这个判定把 park 令也算进去了。改成只看 block 里的 rx_owner_gen 是否已经翻转：park 是「准备交」，翻转才是「真的交了」，ack 那一轮之前开始发布是完全安全的。

4.5 问题五：linger 和既有上限叠加，排空最长翻倍

最早的写法是 QUIT 来了先 linger 等 UDP 流，linger 结束再走原有退出流程——而原有流程里 shutdown timer、监听关闭（30 s cap）、发送队列等待是各自起算的。叠起来最坏情形接近两倍上限，master 那边 T5 的 90 s SIGTERM 都可能先到。改成一份预算：linger 开始就启动 shutdown timer（之后不再重复启动），linger 结束进入退出流程时，监听关闭和发送队列的起算点回拨到第一次 QUIT 的时刻。USR2 的 linger 上限也和 `worker_shutdown_timeout` 对齐，同一时刻到期。

4.6 顺手修的 RX-41

stream udp 反向代理修复前根本跑不起来：`ngx_udp_sendmsg_chain` 里 F-Stack 改过的条件先取 `c->listening->belong_to_host` 再判 `c->listening` 是否为空，而经 `ngx_event_connect_peer` 建立的上游连接没有 listening，第一个数据报就 SIGSEGV。gdb 栈一行定位，三处（sendmsg chain 一处、QUIC 输出两处）统一改成先判空。这个 bug 在 F-Stack 的 nginx-1.28 移植里从合入起就在，只是没人用 UDP 代理所以没炸过。

4.7 测试矩阵

25 个集成用例（harness `test_graceful_reload.sh`），reload 相关的核心几个：rt01/rt02（TCP 长传输跨 HUP，md5、停顿计数）、rt12（KNI 管理面）、rt25（循环 HUP）、rt27~rt29（primary 复用/停止/MTU 拒绝）、rt32（TCP 反代）、rt33（UDP 服务端，2 worker，v4+v6）、rt34（UDP 反代）、rt35（USR2+WINCH）。单测覆盖流表 key 的协议隔离、发布表的记录/查找/老化/时钟回绕、端口奇偶、HUP/USR2 的开始与放弃条件。修复前后的对照数据都存了档，第 5 节挑重点列。

5. 如何使用、如何配置、使用效果

5.1 配置

f-stack 配置（config.ini / f-stack.conf）：

```ini
[dpdk]
graceful_reload=1     # 总开关，缺省 0，行为与旧版完全一致
primary_slim=1        # 常驻 slim primary（graceful 的前提）
reload_udp_idle_ms=10000  # UDP 流空闲多久算结束：100..3600000，默认 10000
                      # 改它不用重启 primary（不在配置摘要里）
```

nginx 侧建议配一个 `worker_shutdown_timeout`，它同时是 HUP 的 T3 上限和 USR2 的 linger 上限，不配默认 90 s，多数场景太长：

```nginx
worker_shutdown_timeout 25s;
```

UDP 服务和 UDP 代理就是标准 stream 写法，没有新增指令：

```nginx
stream {
    server {
        listen 5353 udp;          # DNS 类一问一答
        return "pid=$pid";
    }
    server {
        listen 5354 udp;          # UDP 反代到上游
        proxy_pass <UPSTREAM_IP>:53;
        proxy_responses 1;
        proxy_timeout 5s;
    }
}
```

5.2 日常操作与日志

```bash
nginx -s reload                    # HUP：日常配置变更，无损
kill -USR2  $(cat nginx.pid)       # 二进制升级：新 binary 接管
kill -WINCH $(cat nginx.pid.oldbin)# 旧 master 的 worker 开始排空
nginx -s stop                      # 停止（常驻 primary 一并退出）
```

master 的 error.log 会把整个过程说清楚，几个关键行：

```
graceful reload fsm: T2_HANDOVER -> T3_DRAIN (transition 3, elapsed 155 ms)
graceful reload complete: generation 1 now active (took 1297 ms: handover 1 ms,
    drain 1000 ms, drain forwarded 41 / relayed 41 pkts, ring peak rx 0 / tx 0)
```

worker 侧的排空与 UDP 日志：

```
ff drain: started (drain generation, conns=0 syncache=0)
reload: publishing UDP flows (HUP), 3 in the snapshot
reload: UDP dispatch: 258 forwarded, 2 kept, 0 taken over, 0 without a peer table
ff drain: UDP linger over after 18200 ms, 0 flow(s) still active
```

排空卡住时看 T3 stalled 日志（conns/snd_pending/syncache 各是多少一目了然），UDP 则看发布表还剩几条活跃流。

5.3 使用效果（实测）

| 项 | 修复前 | 修复后 |
|---|---|---|
| rt33 UDP 服务端：窗口内新流归属（2 worker，v4/v6） | 8 条新流 6 条被旧代应答 | 新流 240/240 全新代，旧流 592/592 全旧代，0 丢包 |
| rt33 reload 完成时间 | 每轮都钉死在 90 s deadline | 旧流空闲后 15 s 完成（配的上限 25 s）；不停发的长流到上限移交一次、0 丢包 |
| rt34 UDP 反代 | worker 在第一个代理数据报上 SIGSEGV（约 3 s 内 8 次） | 上游端口奇偶 0→1 分代，旧流 493/493、新流 120/120，26 s 完成 |
| rt35 USR2+WINCH | 交接后新流 24/24 无应答，旧流丢 63/259 | 新旧分干净、0 丢包；旧 worker linger 18.2 s 后 0 流退出 |
| rt32 TCP 反代 | 窗口内新建上游连接全 504 | 窗口内 20/200，上游端口奇偶 0→1 |
| rt01/rt02 TCP 长传输 | — | 跨 HUP md5 一致，36 流 0 停顿 |
| 回归 | — | 25 用例全绿，含 KNI 管理面（rt12）与 IPv6 |

5.4 限制与建议

- **临时端口常态减半**：graceful_reload=1 时两代共存要求 TCP/UDP 临时端口按奇偶分代，每代可用约一半（默认范围约 2.7 万/目的四元组），显式 bind 端口不受约束。端口用量极大的业务要评估
- **QUIC 连接迁移 / NAT 重绑定**：四元组一变就归新代，原连接断开；要做 CID 路由是后续工作
- **IP 分片、多播/广播、ICMP 差错**：窗口内一律由新代处理，包括旧代已连接上游返回的分片大应答（比如大 DNS 应答）
- **UDP 发布表容量**：每进程 16384 项，探测窗口内找不到空槽的流不记录（计数为 not recorded），窗口内按新流处理。一问一答的 DNS 不受影响；超高并发长活 UDP 流要留意
- **版本混跑**：对端是旧二进制（没有发布表）时，UDP 保持老行为——全部转给旧代，不会更糟
- **写者判活有约 1 s 粒度**：旧代崩溃后，新代最多 1 s 内还往它转；旧代被 SIGKILL 留下的表由同坐标后继进程复位
- **多 worker 反代依赖 RSS**：上游回包要落回发起 worker 的队列，没有 RSS 的机器反代只能单 worker 跑（服务端多 worker 不受影响）
- 建议：UDP 业务都配上 `worker_shutdown_timeout`，收敛时间可控；DNS 类一问一答不需要任何特殊配置

延伸阅读：

- 方案设计与问题登记（中文，权威）：docs/nginx_reload_spec/zh_cn/06-solution-design.md（§10.5 TCP 主动登记、§10.9 RX-39、§10.10 RX-40/RX-41）
- 测试矩阵与全部实测数据：docs/nginx_reload_spec/zh_cn/08-testing.md
- 用户手册（graceful 模式行为与限制）：doc/F-Stack_Nginx_APP_Guide.md
- 三层架构文档：docs/zh_cn/01-LAYER1-ARCHITECTURE.md、03-LAYER3-FUNCTIONS.md
- 知识图谱：docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md
- 相关 issue：#528 / #1036（官方确认 reload 不支持）、#547（DPDK 18.11 接收核补丁）
