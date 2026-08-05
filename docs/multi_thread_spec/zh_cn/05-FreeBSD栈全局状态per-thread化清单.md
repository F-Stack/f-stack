# 05 · FreeBSD 栈全局状态 per-thread 化清单

> 本文基于 `_material_code.md` 第 3 节。逐项给出 `file:line` + 类型 + 是否已 per-thread + 多线程隐患评估 + 改造建议。判定原则：**一进程内若开多线程同时进协议栈，非 TLS 的进程级单例会产生竞态/数据损坏。**

---

## 0. 结论先行

- **唯一已被 per-thread 化的核心内核状态是 `curthread`（TLS `pcurthread`，`ff_compat.c:59`）。**
- 三处最直接的破坏点：`msg_iov_tmp/msg_iovlen_tmp`（`ff_syscall_wrapper.c:225-226`，**故意去掉 `__thread`**）、`pcpup`（`ff_freebsd_init.c:69`）、`lcore_conf`（`ff_dpdk_if.c:123`）。
- 协议栈的 socket table（`in_pcbinfo`/tcbinfo）、route table、callout wheel 等在 FreeBSD 原生实现里靠自己的锁（mtx/rwlock/epoch）保护，f-stack 保留了这些锁，但**运行时是单线程 RTC（一进程一 lcore），锁基本不产生竞争**。改成一进程多线程共栈后，这些锁会真正开始竞争，需系统性重评估。

---

## 1. 全局状态逐项清单

| 全局状态 | file:line | 类型 | 是否已 per-thread | 多线程隐患评估 |
|---|---|---|---|---|
| `pcurthread` | `ff_compat.c:59` | `__thread struct thread*` | ✅ 是（TLS） | 安全。唯一被 per-thread 化的核心状态 |
| `pcpup`（PCPU 指针） | `ff_freebsd_init.c:69` | `struct pcpu*`（全局单例） | ❌ 否 | **高危**。`PCPU_GET/SET`（`pcpu.h:44-50`）全走此单例指针；per-CPU 统计/状态在多线程下共享、非原子 |
| `thread0` / `thread0_st` | `ff_init_main.c:98` | 单例 struct | ❌ 否（初始模板） | 中危。多个用户线程若都退回 thread0（如 `ff_thread.c` 共享父 td）会冲突 |
| `vmspace0` | `ff_init_main.c:99` | 单例 | ❌ 否 | 低（f-stack 不做真实 VM） |
| `msg_iov_tmp[UIO_MAXIOV]` | `ff_syscall_wrapper.c:225` | **static 全局（注释掉 `__thread`）** | ❌ 否（**故意**） | **高危**。`recvmsg`（`:864` memcpy from）/`sendmsg`（`:893-897` memcpy to）路径共用此 iovec 暂存区，多线程并发 sendmsg/recvmsg 会互相踩踏 |
| `msg_iovlen_tmp` | `ff_syscall_wrapper.c:226` | 同上 | ❌ 否 | **高危**，同上 |
| `rootvnode / allproc / allproc_lock / allprison / allprison_lock` | `ff_compat.c:62-67` | 单例 | ❌ 否 | 进程级全局；多线程改动需加锁（FreeBSD 原生有 sx 锁 `allproc_lock`，`:65`） |
| `seed`（rand_r） | `ff_compat.c:80` | 单例 | ❌ 否 | 低危（随机数质量） |
| VNET（`V_*`） | `ff_ng_base.c:183-189,385` | `VNET_DEFINE_STATIC` | N/A | f-stack 通常**不启用 VIMAGE**，`V_*` 退化为单实例全局；仅 netgraph 用到。若未来多线程需网络栈隔离，VNET 是天然隔离点但当前未开 |
| `g_pcap_fp / seq / g_flen` | `ff_dpdk_pcap.c:55-57` | `__thread` | ✅ 是 | 安全（pcap 抓包已 per-thread） |
| `lcore_conf` | `ff_dpdk_if.c:123` | 全局单例 struct | ❌ 否 | **高危**。rx/tx queue 配置单例；一进程多线程共享 main_loop 会乱（详见 01 第 7 节） |

---

## 2. 高危项详解与改造建议

### 2.1 `msg_iov_tmp` / `msg_iovlen_tmp`（`ff_syscall_wrapper.c:225-226`）

- **现状**：static 全局，源码中 `__thread` 被**故意注释掉**（注释已预留恢复位置）。
- **路径**：`recvmsg`（`:864` memcpy from）、`sendmsg`（`:893-897` memcpy to）共用这块 iovec 暂存区。
- **隐患**：单线程 RTC 下同一时刻只有一个 syscall 在跑，全局暂存区安全；多线程并发 sendmsg/recvmsg 会同时读写这块共享缓冲，导致 iovec 数据交叉损坏。
- **改造建议**：恢复 `__thread`（注释已预留），**改造量最小、危险度最低**。这是最应先做的一项。

### 2.2 `pcpup`（`ff_freebsd_init.c:69`）

- **现状**：进程级单例 `struct pcpu*`，`PCPU_GET/SET`（`pcpu.h:44-50`）全走它。
- **隐患**：per-CPU 统计/状态在多线程下被共享、非原子读改写。
- **改造建议**：per-thread 化，或每线程绑定独立 pcpu 实例（对齐每线程一个逻辑 CPU 的模型）。改造量中等，涉及所有 `PCPU_GET/SET` 语义。

### 2.3 `lcore_conf`（`ff_dpdk_if.c:123`）

- **现状**：全局单例，`main_loop` 里 `qconf = &lcore_conf`（`:2585`）。
- **隐患**：rx/tx queue 配置只有一份，一进程多线程共享 main_loop 时 queue 状态互相覆盖。
- **改造建议**：per-thread queue 配置 + 每线程独立 rx/tx queue；同时改 dispatch_ring/msg_ring 的 SC/SP flag（`:618`）为每线程独立 ring 或 MC/MP。改造量大。

### 2.4 `thread0` / `ff_pthread_create` 共享父 td（`ff_init_main.c:98`、`ff_thread.c:44`）

- **现状**：`ff_pthread_create` 把父线程 `struct thread` 直接赋子线程（共享同一 td），多线程回退 thread0 会冲突。
- **改造建议**：改为每子线程 `ff_adapt_user_thread_add` 建独立 `struct thread`（参照 `ff_compat.c:96`）。见 `02` 第 3 节。

---

## 3. 协议栈内部锁的再评估（重要）

FreeBSD 原生协议栈本身是为多线程内核设计的，其关键数据结构自带锁：

| 数据结构 | 原生保护 | f-stack 现状 | 多线程共栈后 |
|---|---|---|---|
| socket table（`in_pcbinfo`/tcbinfo） | rwlock/epoch | 保留但单线程无竞争 | 锁开始真正竞争，需压测 |
| route table | rmlock/rwlock | 保留但无竞争 | 竞争，热点在路由查找 |
| callout wheel / hpts | mtx | 保留但无竞争 | 竞争，定时器插入/触发 |

**关键结论**：f-stack 保留了 FreeBSD 的锁原语，理论上"一进程多线程共栈"在锁层面是"可运行"的，但：

1. 上述**非锁保护的进程级单例**（`pcpup`/`msg_iov_tmp`/`lcore_conf`）会先崩，必须先 per-thread 化；
2. 即使补齐单例，锁竞争会抵消多进程 share-nothing 的免锁优势，性能能否达标需实测（见 `09-性能基线方案.md`）。

因此**推荐路线仍是完善 adapter 多 worker（多进程 share-nothing），而非改协议栈为共享多线程**（见 `07` 与 `10`）。

---

## 4. per-thread 化优先级排序（按危险度/改造量）

| 优先级 | 项 | file:line | 改造量 | 说明 |
|---|---|---|---|---|
| P0 | `msg_iov_tmp/msg_iovlen_tmp` 恢复 `__thread` | `ff_syscall_wrapper.c:225-226` | 极小 | 注释已预留 |
| P1 | `ff_pthread_create` 改用 `ff_adapt_user_thread_add` | `ff_thread.c:44` / `ff_compat.c:96` | 小 | 每线程独立 td |
| P2 | `pcpup` per-thread 化 | `ff_freebsd_init.c:69` | 中 | 涉及 `PCPU_GET/SET` |
| P3 | `lcore_conf` + dispatch/msg ring per-thread | `ff_dpdk_if.c:123,618` | 大 | 队列/ring 模型重构 |
| P4 | 协议栈锁竞争压测与优化 | socket/route/callout | 大 | 需实测驱动 |

> 逐项落地里程碑与 WBS 见 `07-里程碑与编码工作分解.md`。
