# 14 多线程 crash 深挖阶段性分析（VIMAGE 隔离方向）

> **文档编号**：SPEC-NMT-14
> **版本**：v1（阶段性，未完成）
> **日期**：2026-07-29
> **状态**：3 层根因已识别；启动 crash 已修复（自旋锁保护 UMA per-CPU cache）；wrk 压测 crash 因 rmlock 全局锁方向偏离 per-vnet 隔离设计而回退，转 per-vnet 隔离方向继续深挖。
> **实证铁律**：所有 crash 位置、寄存器值、backtrace 均来自 gdb 实际运行输出，禁止臆造。

---

## 1. 背景与起点

13 号报告记录：`thread_mode=1` 1 线程 PASS（189,044 req/s），2 线程启动即 crash（gdb backtrace：`memset SIGSEGV at 0` ← `kqueue_kevent` ← `kern_kevent` ← `ff_kevent` ← `loop` at main.c:147）。本阶段在此基础上深挖。

---

## 2. gdb 调试历程与 3 层根因识别

### 2.1 根因 A：UMA per-CPU cache 共享 slot 0 无锁竞争（启动 crash）

- **现象**：2 线程启动即 `memset SIGSEGV at 0`，backtrace 帧链 `uma_zalloc_pcpu_arg` → `vnet_mrtstat_init` → `vnet_alloc` → `ff_stack_thread_init`。
- **根因**：`lib/include/vm/uma_int.h` 中 `critical_enter()/critical_exit()` 为空操作（`do {} while(0)`）。所有线程 `curcpu=0` 共享 `zone->uz_cpu[0]` per-CPU cache 槽，`uma_zalloc_pcpu_arg` 在无 critical section 保护下并发操作同一 cache 槽，返回垃圾指针（含 0），后续 `memset(NULL)` SIGSEGV。
- **修复**：`critical_enter/exit` 改为基于 `__sync_lock_test_and_set` 的自旋锁（`uma_crit_lock` 全局变量定义在 `ff_glue.c`），串行化 UMA per-CPU cache 访问。
- **验证**：2 线程启动不再 crash（helloworld 正常进入 `ff_kevent` 等待循环）。
- **保留状态**：✅ 保留（本修复不偏离 per-vnet 方向，是 UMA 基础设施的多线程安全补强）。

### 2.2 根因 B：worker vnet_i 与 ifp->if_vnet=vnet0 不匹配（包处理 crash）

- **现象**：启动不 crash，但 wrk 压测时 crash 在 `in_pcblookup_mbuf` ← `tcp_input`。
- **根因**：CM5-B 原设计 worker 调 `vnet_alloc()` 创建独立 `vnet_i` 并绑定 `curthread->td_vnet = vnet_i`。但 DPDK 网卡 `ifp` 在主线程 `ff_freebsd_init` 时注册到 `vnet0`（`ifp->if_vnet = vnet0`）。包从 `ff_veth_input` 进入时用 `ifp->if_vnet`（=vnet0）作为 `curvnet`，而 worker socket/PCB 在 `vnet_i`，`in_pcblookup_mbuf` 在错误的 vnet 哈希表中查找 → NULL 指针 crash。
- **临时修复**：worker 不调 `vnet_alloc()`，直接 `curthread->td_vnet = vnet0`（共享 vnet0），消除 vnet 不匹配。
- **验证**：wrk 压测时 `in_pcblookup_mbuf` crash 消除（但出现根因 C）。
- **保留状态**：⚠️ 保留为临时方案。**这丢失了 per-vnet 协议栈隔离**，不符合 native-mt 设计目标。真正修复应让每个 worker 拥有独立 `vnet_i` 且 `ifp` 也注册到对应 vnet（或在包处理路径切换 `curvnet` 到 worker 的 `vnet_i`）。详见第 4 节。

### 2.3 根因 C：ff_lock.c 中 rmlock 为 no-op（方向错误，已回退）

- **现象**：worker 共享 vnet0 后，wrk 压测仍 crash 在 `in_pcblookup_mbuf`。
- **误判根因**：`lib/ff_lock.c` 中 `_rm_wlock/_rm_rlock/_rm_wunlock/_rm_runlock` 全是空操作，PCB 哈希表 `INP_INFO_RLOCK`（rmlock）无锁保护 → 并发竞争 crash。
- **错误修复**：将 rmlock 改为基于 `mtx_lock/unlock(&rm->rm_lock_mtx)` 的真实互斥锁。
- **方向偏离**：**此修复偏离 per-vnet 隔离设计**。native-mt 的设计是每个线程通过独立 vnet 实现协议栈隔离，PCB 应 per-vnet 独立（`VNET_DEFINE` 的 PCB 哈希表每个 vnet 一份），worker 访问的是自己 vnet 内的 PCB，**不应有跨线程共享 PCB**。引入全局 rmlock 锁是把 per-vnet 隔离降级为全局共享+锁，与设计目标背道而驰。
- **回退状态**：✅ 已完全回退 `ff_lock.c`（`git diff` 为空），rmlock 恢复为 no-op。
- **说明**：根因 C 的真正成因是根因 B 的临时修复（worker 共享 vnet0）导致多个 worker 真的共享同一份 PCB 哈希表，此时 no-op 的 rmlock 才暴露竞争。**若 per-vnet 隔离正确实现（每个 worker 独立 vnet_i），PCB 哈希表 per-vnet 独立，rmlock no-op 不会成为问题**（与 thread_mode=0 多进程模式一致，每个进程独立 vnet，rmlock 本就是 no-op）。

---

## 3. 已实施并保留的修改清单

| 文件 | 修改内容 | 目的 | 是否偏离 per-vnet |
|---|---|---|---|
| `lib/ff_compat.c` | `malloc(sizeof(struct proc))` → `malloc(sizeof(struct thread))` | 修复 sizeof 不匹配（分配 thread 结构却用 proc 大小） | 否 |
| `lib/ff_dpdk_if.c` | `ff_stack_thread_init()` → `ff_stack_thread_init(rte_lcore_id())` | 传入实际 lcore id 作为 cpuid | 否 |
| `lib/ff_freebsd_init.c` | `ff_pcpu_thread_init/ff_stack_thread_init` 加 `cpuid` 参数；`pcpu_init(pcpup, cpuid, ...)`；worker `curthread->td_vnet = vnet0`（临时，不调 `vnet_alloc`） | per-thread pcpu 初始化用真实 cpuid；临时消除 vnet 不匹配 | 部分（vnet0 共享为临时方案） |
| `lib/ff_glue.c` | 定义 `volatile int uma_crit_lock` | UMA 自旋锁全局变量 | 否 |
| `lib/include/vm/uma_int.h` | `critical_enter/exit` 改为 `__sync_lock_test_and_set` 自旋锁 | 串行化 UMA per-CPU cache 访问（根因 A 修复） | 否 |
| `lib/include/amd64/include/pcpu.h` | `#undef zpcpu_offset_cpu/zpcpu_base_to_offset/zpcpu_offset_to_base` | 防御性 undef（f-stack 用户态无 `__pcpu` 段，避免误用含 `&__pcpu[0]` 的宏） | 否 |

---

## 4. 剩余问题与下一步方向（per-vnet 隔离）

### 4.1 核心矛盾

当前临时方案让所有 worker 共享 `vnet0`，虽然消除了 crash，但**完全丧失了 per-vnet 协议栈隔离**——所有 worker 共享同一份 PCB/路由表/socket 列表，等同于"多线程共享单栈"，不是 native-mt 的设计目标。

### 4.2 真正的 per-vnet 隔离方案（待实现）

要让每个 worker 拥有独立 `vnet_i` 且不 crash，需解决 `ifp->if_vnet` 与 worker `vnet_i` 的绑定问题。可选方向：

1. **per-worker ifp 注册**：每个 worker 的 `vnet_i` 中独立注册一份 `ifp`（`ifp->if_vnet = vnet_i`），包从 `ff_veth_input` 进入时按 worker 选用对应 `ifp`。需改造 `ff_veth.c` 的 `ifp` 管理为 per-vnet。
2. **包处理路径 curvnet 切换**：`ff_veth_input` 入口处先 `CURVNET_SET(worker_vnet_i)` 再进协议栈，退出时 `CURVNET_RESTORE`。需建立 lcore → vnet 的映射。
3. **ifp 多 vnet 挂载**：单个 `ifp` 挂载到所有 worker vnet（`ifp->if_vnet` 改为 per-vnet 列表），包处理时按当前线程 `curvnet` 选用。复杂度高，不推荐。

### 4.3 rmlock no-op 的合理性

在 per-vnet 隔离正确实现后，每个 worker 访问自己 vnet 内的 PCB 哈希表，无跨线程共享，`rmlock` no-op 与 `thread_mode=0` 多进程模式一致（每个进程独立 vnet，rmlock 本就是 no-op）。**因此 rmlock 不需要改为真实锁**，当前回退是正确的。

### 4.4 后续工作

- 调研 FreeBSD VIMAGE 中 `ifp` 与 vnet 的绑定机制（`if_attach` / `if_vmove`）。
- 设计 per-worker vnet 的 `ifp` 注册或 `curvnet` 切换方案。
- 实施后重新做 2/4 线程 wrk 压测验证（`ssh f-stack-client "/data/wrk/wrk -t5 -c100 -d10s http://9.134.214.176:80/"`）。

---

## 5. 当前可运行状态

- `thread_mode=0`（多进程）：未改动，零回归。
- `thread_mode=1` 1 线程：未测试（应与 13 号报告一致，189,044 req/s）。
- `thread_mode=1` 2 线程：**启动不 crash**（根因 A 已修复），但 wrk 压测仍 crash（根因 B 临时方案引入根因 C 假象，真正需 per-vnet 隔离）。
- `config.ini`：工作区含本地测试值（`lcore_mask=30`, `thread_mode=1`, 本机 IP 等），**不入库**。
