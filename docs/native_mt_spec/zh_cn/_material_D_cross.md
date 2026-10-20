# 素材 D：外网 + 源码交叉调研（FreeBSD VNET/VIMAGE、DPDK per-lcore、mTCP/Seastar thread-per-core）

> 由 leader（SM2 单一角色）产出。目标：为「库内原生单进程多线程多协议栈实例」提供 FreeBSD 原生机制 + 业界对比的交叉验证。
> 铁律：源码结论带 file:line；外网抓不到如实标注；不一致以代码为准。

---

## 1. 【核心】FreeBSD VNET/VIMAGE = 原生「多协议栈实例」机制（决定性发现）

用户诉求的「多协议栈实例」，**FreeBSD 内核本身就有原生机制：VNET（Virtual NETwork stack）/ VIMAGE**。这是本轮方案设计的关键支点。

### 1.1 每个 vnet 是一份完整独立协议栈实例（源码坐实）
| 事实 | 证据 file:line |
|---|---|
| `struct vnet` 是一份完整网络栈实例，挂在全局 vnets 链表 | `freebsd-src-releng-15.0/sys/net/vnet.h:69-75`（`struct vnet { LIST_ENTRY(vnet) vnet_le; u_int vnet_magic_n; u_int vnet_ifcnt; u_int vnet_sockcnt; ... void *vnet_data_mem; ... }`） |
| 动态分配/销毁栈实例的原语 | `vnet_alloc()` 声明 `vnet.h:169`，实现 `sys/net/vnet.c:239`；对应 `vnet_destroy()` |
| 启动时创建默认栈实例 vnet0 | `sys/net/vnet.c:336`：`curvnet = prison0.pr_vnet = vnet0 = vnet_alloc();` |
| jail 创建时为其分配独立栈实例 | `sys/kern/kern_jail.c:1814`：`pr->pr_vnet = vnet_alloc();` |
| **当前栈实例选择 = per-thread** | `sys/net/vnet.h:176`：`#define curvnet curthread->td_vnet` |
| 每个 thread 结构自带 td_vnet 字段 | `sys/kern/kern_fork.c:473-474`：`td2->td_vnet = NULL;`（fork 时初始化） |
| 所有 `VNET_DEFINE(t,n)` 的全局变量在 VIMAGE 下按 vnet 实例存放，`VNET(n)` 经 `curvnet` 取当前实例那一份 | `vnet.h:279-306`（`VNET_DEFINE`/`VNET(n)=VNET_VNET(curvnet,n)`） |

### 1.2 未编译 VIMAGE 时的退化行为（与素材 A §0.2 吻合，源码坐实）
- `vnet.h:51-53` 注释：*"If VIMAGE isn't compiled into the kernel, virtualized global variables compile to normal global variables, and virtualized sysinits to regular sysinits."*
- `vnet.h:398-458`（`#else /* !VIMAGE */` 分支）：`curvnet≡NULL`（`:403`）、`CURVNET_SET/RESTORE` 全 no-op（`:406-408`）、`VNET_DEFINE(t,n)≡ t n`（普通全局，`:429`）、`VNET_SYSINIT` 退化为普通 sysinit（`:442-444`）。
- **f-stack 现状**：`lib/opt/opt_global.h` 无 `VIMAGE`（素材 A §0.2 坐实），故当前所有 `V_ifnet/V_tcbinfo/V_rt_tables/...` 全退化为进程级普通全局单例。

### 1.3 对本方案的决定性意义
> **VNET/VIMAGE 是 FreeBSD 为「一个地址空间内跑 N 份互相隔离的完整网络栈实例」而生的原生子系统**，且实例选择就是 `curthread->td_vnet`（per-thread）。f-stack 的 `pcurthread`（`ff_compat.c:59`）已是 TLS，两者**天然契合**：
> - 若启用 VIMAGE，每个 f-stack 线程只需让自己的 `curthread->td_vnet` 指向各自 `vnet_alloc()` 出来的实例，即可让**同一份 `VNET_DEFINE` 的协议栈全局（ifnet、PCB hash、路由 FIB、端口分配、数百个协议计数器）自动按线程隔离**——这正是素材 A §0.2「VNET 退化全局是主战场、数量数百」难题的**原生解法**：不必手工把数百个全局逐个 `__thread` 化，而是复用内核成熟的 VNET 数据段虚拟化（`vnet_data_mem` + `VNET_SETNAME` section 重定位）。
> - 这使「路线乙（VIMAGE）」从素材 A 里的「工程量存疑备选」上升为**最贴合用户「多协议栈实例」语义、且最符合 FreeBSD 原生设计**的首选技术路径。

### 1.4 VIMAGE 路线的诚实边界（须运行时验证，不得臆断）
- f-stack 是 FreeBSD 用户态移植且大量阉割（`ff_init_main.c` 大段 `#if 0`），VIMAGE 依赖 `SI_SUB_VNET` 系列 SYSINIT、`vnet_data_mem` 段重定位、`sysctl`/eventhandler 的 vnet 化——**这些在 f-stack 用户态裁剪环境能否完整跑通，静态无法定论，须运行时验证**。
- VNET 的 `vnet_alloc`/`vnet_destroy` 依赖 `SX`/锁与 `if_vmove` 等设施，f-stack 是否保留完整，需核对编译单元。
- 即便启用 VIMAGE 解决了「VNET_DEFINE 类全局」，素材 A 的**非-VNET 全局**（`lcore_conf`/`pcpup`/`cc_cpu`/`thread0`/`msg_iov_tmp`）**仍需另行 per-thread 化**——VIMAGE 只覆盖网络栈虚拟化的那部分全局，不覆盖 f-stack 自造的 DPDK 层与 pcpu/callout 移植层全局。

---

## 2. DPDK per-lcore 机制（交叉验证，与素材 B 一致）
- `RTE_DEFINE_PER_LCORE(type,name) ≡ __thread type per_lcore_##name`：`dpdk-stable-24.11.6/lib/eal/include/rte_per_lcore.h:33`（素材 B §四已坐实）。
- `rte_lcore_id() ≡ RTE_PER_LCORE(_lcore_id)`（TLS）：`rte_lcore.h:77-81`。
- lcore = pthread + 核绑定，`rte_eal_remote_launch` 是启动原语：`rte_launch.h:37-99`（素材 B §一已坐实）。
- 交叉印证（外网，摘要级，旧素材复用）：DPDK lcore 本质 pthread 封装 + CPU 亲和；mempool/ring 支持 MP/MC 与 SP/SC。
- **一致性结论**：DPDK 侧「per-lcore TLS + 数组按 lcore_id 索引」与 FreeBSD 侧「per-thread td_vnet」是**同一 share-nothing 思路的两层**，可统一用 `rte_lcore_id()`/TLS 作为线程私有实例的索引键。

---

## 3. 业界原生多栈实例/thread-per-core 对比（外网，部分复用旧素材 + 补充）

### 3.1 mTCP（已抓取，NSDI 2014 + 官网）
- **thread-per-core + share-nothing**：每应用线程配一个独立 TCP 线程，绑同一核；所有 API 传 `mctx`（mTCP thread context）→ 每线程独立管理全部栈资源，避免共享 accept 队列。8 核近线性扩展。
- 对本方案启示：mTCP 的 `mctx` ≈ f-stack 每线程一份栈实例句柄（VNET 或手工 per-thread 上下文），**「每线程一份完整栈上下文 + 同核绑定」是业界验证过的可扩展模型**。

### 3.2 Seastar（社区常识，未深抓，不杜撰细节）
- thread-per-core + share-nothing，每核一个 reactor，核间消息传递（无锁），配 DPDK 用户态网络。与本方案「每线程独立栈实例、跨线程用无锁 ring」方向一致。
- 诚实标注：Seastar 官方文档本轮未深入抓取，细节需要时另查 seastar.io。

### 3.3 f-stack 官方（已抓取，多来源）
- 官方模型 = **多进程 share-nothing**（primary/secondary + rte_ring + 共享大页），**未检索到官方「单进程多线程共享/多实例栈」运行模式的设计文档或合入 PR**（不杜撰）。
- issue #430 = 应用侧多线程调 API 诉求（libuv+pthread），非栈侧多线程运行模型（素材 C §4 已代码坐实定位）。

---

## 4. 交叉验证结论（供 SM3 方案设计）

1. **原生多协议栈实例 = VNET/VIMAGE**（`vnet.h:69`/`vnet_alloc vnet.c:239`/`curvnet=td_vnet vnet.h:176`），是 FreeBSD 为此而生的子系统，且实例选择 per-thread，与 f-stack TLS `pcurthread` 契合 → **技术首选路径 = 启用 VIMAGE 让每线程一份 vnet 栈实例**。
2. 但 VIMAGE **只解决 `VNET_DEFINE` 类网络栈全局**；f-stack 自造的 DPDK 层/pcpu/callout 全局（`lcore_conf`/`pcpup`/`cc_cpu`/`thread0`/`msg_iov_tmp`，素材 A/B）**必须另行 per-thread 化**（数组 + `rte_lcore_id()` 索引 或 `__thread`）。
3. `mi_startup`/SYSINIT 一次性机制（素材 A §2.2 硬结论）在 VIMAGE 下有对应的 `VNET_SYSINIT`（每 vnet 跑一次）机制可借；但 f-stack 阉割版能否跑通 **须运行时验证**。
4. 业界（mTCP/Seastar）一致采用 thread-per-core + share-nothing + 每线程独立栈上下文，佐证本方案方向正确。
5. **不涉及 adapter/LD_PRELOAD**：以上均为栈侧原生运行模型，adapter 仅应用侧适配，非本方案。

## 5. 抓取/取证状态（诚实标注）
| 目标 | 状态 |
|---|---|
| FreeBSD VNET struct/vnet_alloc/curvnet=td_vnet | ✅ 源码坐实（vnet.h/vnet.c/kern_jail.c/kern_fork.c） |
| VIMAGE 退化行为 | ✅ 源码坐实（vnet.h:51-53,398-458） |
| VIMAGE 在 f-stack 阉割用户态能否跑通 | ⚠️ 静态无法定论，须运行时验证 |
| DPDK per-lcore/lcore/launch | ✅ 源码坐实（rte_per_lcore.h/rte_lcore.h/rte_launch.h） |
| mTCP thread-per-core | ✅ 已抓取（NSDI2014+官网，旧素材） |
| Seastar/VPP 细节 | ❌ 未深抓（社区常识，不杜撰） |
| f-stack 官方单进程多线程栈模式 | ❌ 未检索到（不杜撰） |
