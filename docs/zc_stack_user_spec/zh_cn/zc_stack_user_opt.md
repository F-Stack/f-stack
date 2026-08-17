F-Stack 2.0 前瞻8：用户态零拷贝栈纪实，从 MAGIC 哨兵魔改到 FreeBSD 原生 sosend 对称架构

1. 本功能主要作用和特点

直接说目的：F-Stack 的用户态与协议栈之间一直有"最后一公里"的内存拷贝问题，这篇文章把零拷贝从 2018 年到 2026 年的演进讲清楚——早期只有接收方向天然零拷贝，2022 年有了发送方向的魔改方案，2026 年 6 月终于收敛成"双向对称、纯原生"的完整用户态零拷贝栈。

先说清楚拷贝发生在哪。数据包在服务器的处理分接收和发送两个方向：

- **接收方向**：网卡 → DPDK hugepage 是 DMA，天然零拷贝；但应用调 `ff_read()` 把数据从协议栈 mbuf 搬到用户 buffer 有一次拷贝（issue #407 官方确认，这是设计如此）
- **发送方向**：有两处拷贝——应用层调用 socket 发送接口时数据从应用层拷到 FreeBSD 协议栈（应用 → 协议栈），以及协议栈把数据拷到 DPDK rte_mbuf（协议栈 → 网卡）

2026 年 6 月之前，F-Stack 零拷贝的版图是这样的：接收方向零拷贝（FF_ZC_RECV）只有空接口，未实际实现，在2026-06-11通过FreeBSD源生接口实现了接受方向零拷贝的实际实现（commit b87f5f0d2）；发送方向零拷贝（FF_ZC_SEND）用的是 FSTACK_ZC_MAGIC 哨兵 + m_uiotombuf 内核魔改的 workaround——能跑但有 GPF 风险、大数据量发送 crash、FreeBSD 升级时维护成本高。2026-06-12 的原生化重构（commit b6ce5884c）把发送方向也换成了 FreeBSD 15.0 原生的 `sosend(top)` 路径，至此形成完全对称的双向零拷贝栈。本文的三个关键词：

- **双向对称**：ZC-send（`kern_zc_sendit` + sosend top）与 ZC-recv（`kern_zc_recvit` + soreceive mp0）在内核入口、用户态 API、生命周期、错误路径、ABI 增量五个维度全镜像
- **纯原生**：直接复用 FreeBSD 15.0 上游能力——`sosend(9)` 手册原文就写着"Data may be sent as an mbuf chain via top, avoiding a data copy"，f-stack 只是补了一个把 top 贯通进 sosend 的入口
- **拆除魔改**：FSTACK_ZC_MAGIC 哨兵 + m_uiotombuf 魔改共 17 处触点全部拆除，m_uiotombuf 回归 vanilla 15.0 版本，内核 patch 从"5 处魔改"变成"只新增 1 个函数"

规模数据：spec 文档 30+ 篇（00-50 编号，含可行性研究、ZC-recv 首版 spec、native ZC-send spec 三批）；ZC-recv 落地 4 处改动、ZC-send 原生化 10 处改动（2 NEW + 3 MODIFY + 5 DELETE）；单核 A/B 实测三档压测全部噪声内持平。

2. 本功能的主要适用场景

2.1 大块数据收发场景

这是零拷贝最实在的收益场景。M2 实测已经证明：小包 echo（256B 请求/438B 应答）下 ZC 与普通 read/write 持平——小请求的 `uiomove` 拷贝开销相对 TCP 处理 + syscall + 调度可以忽略，且 f-stack 用 UIO_SYSSPACE，uiomove 本就是同地址空间 memcpy，已经很廉价。真正的收益在 4KB/64KB/1MB 级 payload：大文件下载、大 body POST、块存储类业务。

2.2 代理转发场景（收到即转发）

转发类应用（代理、网关）收到数据后原样发出去，传统路径是 recv 拷进用户 buffer 再 send 拷回协议栈，两趟拷贝；ZC 路径下 recv 拿到 mbuf 链、send 直接投递 mbuf 链，全程零拷贝。这是 spec 里明确标注的优先收益场景。

2.3 与 FF_USE_PAGE_ARRAY 的关系（要说清）

FF_USE_PAGE_ARRAY 是 2020 年 PR #364 贡献的"协议栈 → DPDK"方向零拷贝（mmap + mlock + virt2phy 查找），与本文的应用层零拷贝是两段不同的拷贝。它至今仍是实验性特性：issue 档案确认它在 i40e 下会静默丢包，官方不建议启用；Phase-2 实测还触发过 panic（F-A1，已修复为 soft drop）。三者开关完全独立，可任意组合。

2.4 不太适合的场景

- 小包 echo 类负载：实测零收益，直接开还会多一层 API 复杂度
- 依赖增量编译的快速迭代环境：FF_ZC_* 开关切换后必须 make clean，否则会踩 M2 的 http=000 坑（见 4.3）
- 期待性能翻倍的：2022 年官方公众号文章就说过，性能提升"并不一定很明显，比如只有 2-3% 左右的提升"——零拷贝省的是 memcpy，不是协议栈本身的开销

3. 本功能的架构特征

3.1 三条发送路径对比（核心图）

```
【传统拷贝路径】
APP buffer ──ff_write──► uiomove 拷贝 ──► m_getm2 分配 mbuf ──► 协议栈
（一次分配 + 一次拷贝）

【旧 MAGIC 魔改路径（2026-06-08 ~ 06-12）】
APP: ff_zc_mbuf_get/write 构造 mbuf 链
        │  ff_zc_send 把 mbuf 链伪装成 char*（iov_base）
        │  并注入 uio_offset = FSTACK_ZC_MAGIC (0xF8AC2C00F8AC2C00)
        ▼
kern_writev → dofilewrite（守护：非 MAGIC 才覆写 offset）
        ▼
m_uiotombuf（消费：检测 MAGIC → 把 iov_base 重新解释为 mbuf 链，跳过拷贝）
        ↓ 内核 5 处魔改，普通 ff_write 须显式 opt-out 防误触

【新原生路径（2026-06-12 起）】
APP: ff_zc_mbuf_get(M_PKTHDR) → ff_zc_mbuf_write(维护 pkthdr.len)
        │  ff_zc_send(fd, top, n) —— top 就是 mbuf 链
        ▼
kern_zc_sendit（新增，唯一内核改动）
        │  sosend(so, NULL, NULL, top, NULL, flags, td)
        ▼
sosend_generic：uio==NULL 分支
        │  resid = top->m_pkthdr.len
        │  直接投递 top，完全跳过 m_uiotombuf
```

新方案没有 magic、没有 uio_offset 透传、ff_write/ff_writev 不需要 opt-out。sosend 全段经过实测确认无任何 FSTACK_* 宏——这是 FreeBSD 上游原生能力。

3.2 接收方向对称结构

```
传统接收：soreceive → uiomove 拷贝到用户 buffer
ZC 接收：kern_zc_recvit（新增入口，透传 soreceive 的 mp0 出参）
        → ff_zc_recv(fd, &zm, nbytes)
        → ff_zc_mbuf_segment 逐段读取
        → ff_zc_recv_free 用后必释
```

3.3 双向对称表（五维镜像）

| 维度 | ZC-recv（已落地） | ZC-send（原生化后） |
|---|---|---|
| 内核入口 | `kern_zc_recvit` → `soreceive(mp0)` | `kern_zc_sendit` → `sosend(top)` |
| 原生机制 | soreceive 的 `mp0!=NULL` 分支 | sosend 的 `uio==NULL && top!=NULL` 分支 |
| 长度来源 | `uio->uio_resid` | `top->m_pkthdr.len` |
| 绕过点 | uiomove 拷贝 | m_uiotombuf 分配+拷贝 |
| 用户态 API | `ff_zc_recv` / `ff_zc_mbuf_segment` / `ff_zc_recv_free` | `ff_zc_send` / `ff_zc_mbuf_get` / `ff_zc_mbuf_write` |
| ABI 增量 | +3 符号 | 0 符号（只改实现） |

两边共享同一个 `struct ff_zc_mbuf`（bsd_mbuf/bsd_mbuf_off/off/len 四字段），字段语义对称复用。

4. 具体做了哪些改造、遇到了哪些问题、怎么解决的

后续比较枯燥，不需要深入研究实现过程的可以跳过本节，直接看第 5 节怎么用。

4.1 早期方案回顾（2018~2022，最早期文档到现在版本的区别）

2018 年的基线（issue #407）：接收方向网卡到 hugepage 零拷贝、但 `ff_read()` 有拷贝；发送方向"是拷贝的"。

2020 年 PR #364（@jinhao2）补了第一段：FF_USE_PAGE_ARRAY，协议栈 → DPDK 方向零拷贝。思路是初始化时 mmap 256MB（memsz_MB 可调）+ mlock 锁物理内存，维护虚拟地址→物理地址页表，协议栈 mbuf 数据地址落在池内时直接把物理地址填给 rte_mbuf 的 buf_addr/buf_physaddr，不拷贝；用长度等于 NIC tx_queue_length 的循环队列保证释放安全。这个方案对应用透明，但对 ixgbe 有效、i40e 下静默丢包，至今官方定位仍是"从未正式启用的实验特性"。

2022-04-15（commit e12886c/021aaded）补了第二段：FF_ZC_SEND，应用 → 协议栈方向零拷贝。`ff_zc_mbuf_get()` 用 m_getm2 分配 mbuf 链当应用缓存、`ff_zc_mbuf_write()` 直接写进 mbuf、`ff_write(fd, zc_buf.bsd_mbuf, len)` 时在 m_uiotombuf 里直接采用传入的 mbuf 链跳过拷贝。配套公众号文章《F-STACK发送零拷贝介绍》如实说明：预期性能提升约 2-3%，"需要结合实际场景测试"。

4.2 M8 重新点亮：FSTACK_ZC_MAGIC 哨兵方案（2026-06-08）

FreeBSD 13→15 升级的 Phase-2 把 FF_ZC_SEND 在 15.0 基线上重新点亮（commit add33a04a）。13.0 时代的直传方式在 15.0 下有了变化，落地成了哨兵方案：`ff_zc_send` 把 mbuf 链伪装成 char* 塞进 iov_base，同时往 `uio->uio_offset` 注入魔数 `0xF8AC2C00F8AC2C00`；dofilewrite 里加守护（非魔数才覆写 offset）；m_uiotombuf 里加消费点（检测到魔数就把 iov_base 重新解释为 mbuf 链）。内核 5 处魔改，普通 ff_write/ff_writev 必须显式 `uio_offset=0` opt-out 防止撞上魔数。

这个方案从落地第一天就带着三个包袱：M8 阶段曾因 opt-out 缺失直接 GPF（ff_syscall_wrapper.c:1146 的 RCA）；issue #712（2022-11-01 至今 OPEN）大数据量发送 crash/hang 无解；每次 FreeBSD 升级都要重新审计 m_uiotombuf 周边约 120 行。

4.3 问题一：增量编译陷阱，http=000（M2 教训）

2026-06-11 做 ZC-recv 的 M2 实测时，首轮 curl 全部 http=000，一度误判为环境问题。实际调试定位到真凶：先做了无 flag 的 baseline build，再 `FF_ZC_SEND=1 make`，uipc_mbuf.c 没改过、它的 .o 比 .c 新，make 按时间戳跳过重编译——m_uiotombuf 里的 MAGIC 消费 hook 缺失（objdump 验证 magic 不在 uipc_mbuf.o 里）。后果：ff_zc_send 设了魔数但内核 hook 不识别，mbuf 链指针被当 char buffer 处理，应答崩坏。删 stale .o 重编译后 http=200 全通。

【注1】这个坑从此进了强制规约：变更 FF_ZC_* 等编译开关后必须 make clean 或删除受影响 .o，make 基于时间戳不感知 CFLAGS 变化。这也是哨兵方案的固有脆弱性——魔改文件越多，stale .o 的组合爆炸面越大。

4.4 ZC-recv 落地与调研转向（2026-06-11）

同一天 ZC-recv 落地（commit b87f5f0d2，M0+M1）：新增 `kern_zc_recvit` 透传 soreceive 的原生 `mp0` 出参，用户态新增 ff_zc_recv/ff_zc_mbuf_segment/ff_zc_recv_free 三个 API。它只新增不魔改，soreceive 核心零改动。M2 实测（单核 A/B 三档 wrk）：T1 −1.1%、T2 ≈ +3%、T3 −1.0%，小包 echo 下与 ff_read 持平（噪声内）——诚实的结论是收益在大 payload 场景，echo 负载体现不出来。

更重要的是，做 ZC-recv 的同时顺手调研了发送侧：FreeBSD 15.0 的 `sosend()` 签名里一直带着 `top`（mbuf 链）参数，`uio==NULL && top!=NULL` 时直接投递 mbuf 链、跳过 m_uiotombuf。调研实测确认 sosend 全段无任何 FSTACK_* 宏（git blame 显示 f-stack 的 delta 不在那里）——**上游原生能力一直在，f-stack 的 MAGIC 方案是把 mbuf 伪装成 uio 绕行，属于"非必要重新发明"**。缺的只是一个把 top 从用户态贯通进 sosend 的入口（收侧 mp0 被写死 NULL 完全同构，kern_zc_recvit 已经示范了怎么做）。

4.5 原生化重构：kern_zc_sendit（2026-06-12）

方案定了以后一天落地（commit b6ce5884c）：新增 `kern_zc_sendit(td, s, top, flags)` 直调 `sosend(so, NULL, NULL, top, NULL, flags, td)`，同时把魔改全部拆除——17 处触点里，mbuf.h 的 MAGIC 宏、m_uiotombuf 的 ZC 分支、dofilewrite 的守护、ff_write/ff_writev 的 opt-out 共 5 处 DELETE，m_uiotombuf 回归 vanilla 15.0 版本；ff_zc_send 重写为调用 kern_zc_sendit；ff_zc_mbuf_get/write 修复 M_PKTHDR 缺口。

M_PKTHDR 缺口是这个方案的技术前提，值得展开：sosend 的 uio==NULL 分支用 `top->m_pkthdr.len` 作为 resid（数据长度），而旧的 ff_zc_mbuf_get 用 `m_getm2(..., flags=0)` 分配的链头**不带 M_PKTHDR**，ff_zc_mbuf_write 里维护 pkthdr.len 的代码被注释掉了——直接走原生路径会 resid=0 什么都发不出去。修复是两行的事：分配时加 M_PKTHDR、写入时累加 pkthdr.len，但这两行是"原生能力可用"和"静默不发数据"的分水岭。

【注2】ABI 不变性是这次重构的合同：ff_zc_send/ff_zc_mbuf_get/ff_zc_mbuf_write 签名零修改、example/main_zc.c 调用序列零修改（G4 验收条款就是 diff 它 0 行变化）、FF_ZC_SEND 开关名保留但含义从"魔改启用"切换为"原生路径启用"、导出符号不增不减。对已部署项目唯一要求是 make clean 后重编译。

4.6 行为变化（对用户可感知的）

| 项 | 旧（魔改） | 新（原生） |
|---|---|---|
| 大数据（>SO_SNDBUF）发送 | crash/hang（issue #712） | 阻塞或非阻塞返 EWOULDBLOCK，调用方自分片 |
| UDP 单包 > MTU | 行为不定 | 明确返回 EMSGSIZE |
| 普通 ff_write 与 ZC 共存 | 需 opt-out 防误触，曾 GPF | 无需 opt-out |
| FreeBSD 升级维护 | 重审计 m_uiotombuf 约 120 行 | 只校验 sosend 签名是否变化 |

4.7 性能诚实边界

- 2022 年官方文章：发送零拷贝预期提升约 2-3%，需结合场景实测
- 2026-06 ZC-recv 单核实测：小包 echo 三档压测与普通 read 持平（噪声内），收益预期在大块数据/代理转发场景
- ZC-send 原生化性能目标（spec 38）：三档 wrk 下 vs baseline 和 vs 旧魔改均 Δ ≤ ±3%（噪声内）——原生化是"等价替换"不是"性能优化"，收益是架构债清零
- 大 payload（4KB/64KB/1MB）专测是后续工作（spec 已列 P2-P4 场景，旧方案在 P3/P4 有 crash 风险，新方案必须数据完整）

5. 如何使用、如何配置、使用效果

5.1 编译开关（三个，完全独立可组合）

```makefile
# lib/Makefile
#FF_ZC_SEND=1      # 发送零拷贝（原生 kern_zc_sendit 路径）
#FF_ZC_RECV=1      # 接收零拷贝（kern_zc_recvit 路径）
#FF_USE_PAGE_ARRAY=1  # 协议栈→DPDK 零拷贝（实验性，不建议生产启用）
```

切换开关后**必须 make clean**（4.3 的坑）。

5.2 发送零拷贝 API 用法

```c
struct ff_zc_mbuf zc_buf;

ff_zc_mbuf_get(&zc_buf, buf_len);          // 申请 mbuf 链缓存（含 M_PKTHDR）
ff_zc_mbuf_write(&zc_buf, data, len);      // 直接写入 mbuf 链，可多次调用
ff_zc_send(fd, zc_buf.bsd_mbuf, buf_len);  // 投递 mbuf 链，跳过拷贝

// send 成功后 bsd_mbuf 已被协议栈接管，不得再访问；
// 复用 zc_buf 必须重新 ff_zc_mbuf_get
```

调用方代码审查要点（spec 39 迁移指南）：单次 send 数据量别超过 SO_SNDBUF（否则 EWOULDBLOCK，需自分片）；UDP 单包别超 MTU（否则 EMSGSIZE）；send 后立刻丢弃 bsd_mbuf 指针（否则 UAF）；nbytes 参数要 ≥ 实际 write 累计量（实发长度 = pkthdr.len）。

5.3 接收零拷贝 API 用法

```c
struct ff_zc_mbuf zm;
ssize_t n = ff_zc_recv(fd, &zm, nbytes);
// 逐段读：ff_zc_mbuf_segment(&zm, &seg, &len)
ff_zc_recv_free(&zm);   // 用后必释，否则 mbuf 泄漏
```

5.4 使用效果

实测数据（2026-06-11，单核 lcore4，wrk 三档，A=普通 read / B=ZC-recv）：

| 档位 | A req/s | B req/s | Δ |
|---|---|---|---|
| T1 (-t2 -c10) | 22,363 | 22,115 | −1.1% |
| T2 (-t4 -c100) | ~31.1k | ~32.1k | 持平（噪声内） |
| T3 (-t8 -c500) | 28,615 | 28,317 | −1.0% |

小包 echo 下零拷贝没有可测收益——这是设计预期，不是失败。收益场景是大 payload 和转发。

5.5 对使用者的建议

- 业务是大块数据/转发：开 FF_ZC_SEND + FF_ZC_RECV，用 ZC API 改造收发路径
- 业务是小包 RPC/echo：别折腾，普通 ff_read/ff_write 就好，实测证明无差别
- FF_USE_PAGE_ARRAY：官方定位实验性、i40e 丢包、Phase-2 实测触发过 panic（已修复为 soft drop）
- 升级到新版本：make clean 后重编译，example/main_zc.c 不用改

延伸阅读：

- 用户态零拷贝栈 spec 总览：docs/zc_stack_user_spec/zh_cn/30-spec-overview.md
- 现状测绘与拆除清单（17 处触点）：docs/zc_stack_user_spec/zh_cn/31-current-state-and-removal.md
- 对称架构设计（kern_zc_sendit ↔ kern_zc_recvit）：docs/zc_stack_user_spec/zh_cn/32-native-arch-design.md
- 原生 sosend(top) 调研：docs/zc_stack_user_spec/zh_cn/22-native-zc-send-research.md
- 已部署项目迁移指南：docs/zc_stack_user_spec/zh_cn/39-migration-guide.md
- ZC-recv M2 实测报告：docs/zc_stack_user_spec/zh_cn/21-m2-test-report.md
- 初版发送零拷贝介绍（2022）：https://mp.weixin.qq.com/s/j_b7pVOoFa6sqaWQD6eBpw
- 相关 issue：#364（PR，协议栈→DPDK 零拷贝）、#407（接收侧零拷贝确认）、#712（大包发送 crash）、#467（零拷贝 API 讨论）
- 三层架构文档：docs/zh_cn/01-LAYER1-ARCHITECTURE.md
- 知识图谱：docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md
