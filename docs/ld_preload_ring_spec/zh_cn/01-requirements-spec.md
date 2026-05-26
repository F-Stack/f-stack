# F-Stack LD_PRELOAD 无锁环形队列改造 — 需求规格文档

> **文档编号**: SPEC-001  
> **版本**: v1.0 Draft  
> **日期**: 2026-03-27  
> **状态**: 已审核 by fengbojiang 2026-03-27 ，大方向没问题，修改了一点细节
> **范围**: `/data/workspace/f-stack/adapter/syscall/`

---

## 1. 问题域分析

### 1.1 当前架构概述

F-Stack 的 LD_PRELOAD 模块（`libff_syscall.so`）通过劫持应用程序的 socket 系统调用，将其转发给 fstack 实例进程处理。APP 侧和 fstack 侧之间通过 **DPDK Hugepage 共享内存**中的 `ff_so_context` 结构进行 IPC 通信。

当前同步机制采用 **三层同步**：

| 层 | 机制 | 位置 |
|---|---|---|
| 状态机 | `FF_SC_IDLE → FF_SC_REQ → FF_SC_REP → FF_SC_IDLE` | `ff_socket_ops.h:73-75` |
| 互斥锁 | `rte_spinlock_t lock` | `ff_socket_ops.h:103` |
| 信号量 | `sem_t wait_sem` (POSIX 跨进程信号量) | `ff_socket_ops.h:111` |

### 1.2 信号量机制的性能瓶颈

#### 1.2.1 内核态系统调用开销

POSIX 信号量 `sem_wait()`/`sem_post()` 在 Linux 上通过 `futex` 系统调用实现。每次调用涉及：
- **用户态 → 内核态切换**：约 100-200ns 开销
- **futex 唤醒路径**：`FUTEX_WAKE` 需唤醒等待队列中的线程，涉及内核调度器
- **跨进程信号量**（`sem_init(&sc->wait_sem, 1, 0)` 中 `pshared=1`）额外增加了共享内存 futex 的查找开销

在高频 syscall 场景下（如 Nginx 的 epoll_wait 短超时），这些开销被放大。

#### 1.2.2 sem_timedwait 超时精度问题

当前代码使用 `CLOCK_REALTIME` 计算超时（`ff_hook_syscall.c:2194-2207`）：
```c
clock_gettime(CLOCK_REALTIME, &abs_timeout);
abs_timeout.tv_sec += timeout / 1000;
abs_timeout.tv_nsec += (timeout % 1000) * 1000 * 1000;
```
- `CLOCK_REALTIME` 受 NTP 调时影响，可能导致意外超时或延迟
- `sem_timedwait` 的最小唤醒粒度受内核调度器 tick 影响（通常 1-4ms）
- 超时后的竞态：注释明确指出（第 2224-2229 行）`sem_timedwait` 超时但 fstack 仍可能 `sem_post`，导致下次 `sem_timedwait` 立即返回，读取过期结果

#### 1.2.3 O(n) 请求遍历

`ff_handle_each_context()`（`ff_socket_ops.c:569-638`）在每次轮询循环中遍历 **所有** `ff_so_context`：
```c
for (i = 0; i < ff_so_zone->count; i++) {
    struct ff_so_context *sc = &ff_so_zone->sc[i];
    if (ff_so_zone->inuse[i] == 0) continue;
    if (sc->status == FF_SC_REQ) {
        ff_handle_socket_ops(sc);
    }
}
```
当 `SOCKET_OPS_CONTEXT_MAX_NUM = 32` 时，每次循环都需脏读 32 个 sc 的 status 字段，即使绝大多数处于 IDLE 状态。

#### 1.2.4 alarm_event_sem 补偿机制的脆弱性

`alarm_event_sem()`（`ff_hook_syscall.c:3235-3252`）是一个补偿机制，用于处理 APP 进入 `sem_wait` 后 fstack 来不及 `sem_post` 的情况。但该机制仅在 `main_stack.c:75` 被真正调用，其余 4 个示例程序中均被注释掉，表明该机制不稳定且难以正确使用。

#### 1.2.5 模式分裂

当前存在两种互斥的 epoll_wait 实现路径：
- **信号量模式**（默认）：使用 `sem_wait`/`sem_post`，CPU 利用率低但延迟高
- **轮询模式**（`FF_PRELOAD_POLLING_MODE`）：纯 busy-poll，延迟低但 CPU 100%

两种模式通过编译宏分裂，无法在运行时切换，且轮询模式不支持 `FF_KERNEL_EVENT`。

---

## 2. 功能需求

### FR-001: 无锁请求队列

**描述**: 使用 DPDK `rte_ring`（SPSC 模式）替代 `sem_t wait_sem` 实现 APP → fstack 的请求通知。

**详细要求**:
- APP 侧将请求的 `ff_so_context` 指针入队到请求 ring
- fstack 侧从请求 ring 出队获取待处理请求（替代 O(n) 遍历）
- ring 分配在 DPDK Hugepage 共享内存上，支持跨进程访问

**影响文件**: `ff_socket_ops.h`, `ff_so_zone.c`, `ff_hook_syscall.c`, `ff_socket_ops.c`

### FR-002: 无锁响应队列

**描述**: 使用 DPDK `rte_ring`（SPSC 模式）替代 `sem_post`/`sem_wait` 实现 fstack → APP 的响应通知。

**详细要求**:
- fstack 侧处理完请求后将 `ff_so_context` 指针入队到响应 ring
- APP 侧从响应 ring 出队获取处理结果（替代 `sem_wait`/`sem_timedwait`）
- 支持超时等待（基于 `rte_rdtsc()` 高精度计时）

**影响文件**: `ff_hook_syscall.c`, `ff_socket_ops.c`

### FR-003: 可配置等待策略

**描述**: 提供三种可配置的 APP 侧等待策略，替代当前的信号量阻塞和编译时轮询模式的二选一。

| 策略 | 描述 | 适用场景 |
|---|---|---|
| **busy-poll** | 持续调用 `rte_ring_dequeue` | 超低延迟，CPU 100% |
| **yield-poll** | 每次 dequeue 失败后调用 `rte_pause()` / `sched_yield()` | 低延迟，CPU 占用适中 |
| **eventfd** | dequeue 失败后通过 `eventfd` 阻塞等待 | 低 CPU 占用，延迟稍高 |

**详细要求**:
- 等待策略在运行时可配置（通过环境变量或配置），而非编译时宏
- 默认策略为 `yield-poll`，兼顾延迟和 CPU 占用

### FR-004: 替代 alarm_event_sem

**描述**: 使用 ring 机制替代当前不稳定的 `alarm_event_sem()` 补偿机制。

**详细要求**:
- 在 ring 模式下，fstack 侧在处理完阻塞型操作（kevent timeout=NULL, epoll_wait timeout=-1）后，无论是否有事件返回，均向响应 ring 入队
- 消除 `need_alarm_sem` 全局变量及其复杂的设置/清除逻辑

**影响文件**: `ff_hook_syscall.c`, `ff_socket_ops.c`, `ff_adapter.h`, `main_stack.c`

### FR-005: ff_handle_each_context 优化

**描述**: 将 fstack 侧的 O(n) sc 遍历改为 O(1) ring 出队。

**详细要求**:
- `ff_handle_each_context()` 改为从请求 ring 批量出队（`rte_ring_dequeue_burst`）
- 消除对 `ff_so_zone->lock` 全局 spinlock 的持有（当前整个循环期间持锁）
- 保持 `pkt_tx_delay` 时间窗口内多次轮询的行为

**影响文件**: `ff_socket_ops.c`

### FR-006: 向后兼容

**描述**: 通过编译宏 `FF_USE_RING_IPC` 控制新旧方案切换。

**详细要求**:
- 定义宏 `FF_USE_RING_IPC` 时使用无锁 ring 方案
- 未定义时保持当前信号量方案不变
- 后续稳定后可移除旧方案代码

---

## 3. 非功能需求

### NFR-001: 延迟

| 指标 | 当前基线 (sem) | 目标 (ring) |
|---|---|---|
| 单次普通 syscall RTT | 2-5 μs | < 1 μs |
| epoll_wait 唤醒延迟 | 2-10 μs | < 2 μs |
| 超时精度 | 毫秒级 | 微秒级 |

### NFR-002: 吞吐量

- 在 Nginx 600B body 长连接基准测试中，ring 方案的 RPS 不低于 sem 方案
- 在相同 CPU 核数下，ring 方案的吞吐量提升 ≥ 10%

### NFR-003: CPU 占用

- `yield-poll` 模式下，空闲时 CPU 占用不超过 sem 方案的 2 倍
- `eventfd` 模式下，空闲时 CPU 占用与 sem 方案持平
- `busy-poll` 模式下允许 CPU 100%（与现有 `FF_PRELOAD_POLLING_MODE` 行为一致）

### NFR-004: 内存开销

- 每个 fstack 实例新增内存开销 < 64KB（2 个 ring × 64 entries × cache line）
- ring 结构在 Hugepage 上分配，不增加常规内存使用

### NFR-005: 可维护性

- 新增代码量 < 500 行（不含测试和文档）
- 保持现有代码风格（GNU C、4 空格缩进、BSD 函数命名）
- 关键路径有注释说明 ring 操作语义

---

## 4. 约束条件

### C-001: 运行模式兼容性

新方案必须兼容以下 5 种运行模式：

| 模式 | 编译宏 | 当前状态 | Ring 方案要求 |
|---|---|---|---|
| PIPELINE（默认） | 无 | 信号量同步 | 双 ring 替代 |
| RTC (thread_socket) | `FF_THREAD_SOCKET` | 每线程独立 sc | 每线程独立 ring pair |
| FF_KERNEL_EVENT | `FF_KERNEL_EVENT` | 同时调用 fstack + kernel epoll | ring 出队 + linux_epoll_wait |
| FF_MULTI_SC | `FF_MULTI_SC` | 类 SO_REUSEPORT | 多 ring zone |
| FF_PRELOAD_POLLING_MODE | `FF_PRELOAD_POLLING_MODE` | 纯轮询 | 统一为 busy-poll 策略 |

### C-002: 共享内存要求

- ring 必须在 DPDK Hugepage 上分配（`rte_ring_create` 使用 `rte_memzone_reserve`）
- ring name 必须全局唯一（格式: `ff_sc_req_ring_%d` / `ff_sc_rsp_ring_%d`）
- APP 侧通过 `rte_ring_lookup` 查找已创建的 ring

### C-003: DPDK 版本兼容

- 基于 F-Stack 当前使用的 DPDK 版本（目录 `dpdk/` 下的版本）
- 使用 `rte_ring` 的 SPSC 模式（`RING_F_SP_ENQ | RING_F_SC_DEQ`）

### C-004: 编译系统

- 新增编译宏 `FF_USE_RING_IPC` 在 `Makefile` 中控制
- 不引入新的外部依赖（仅使用已有的 DPDK 库）

### C-005: 错误处理

- ring 满时（enqueue 失败）：记录错误日志，等待重试
- ring 创建失败：回退到信号量方案（如果启用了 `FF_USE_RING_IPC`）
- 进程异常退出：ring 中残留的 sc 指针需在 detach 时清理

---

## 5. 验收标准

### AC-001: 功能验收

- [ ] 5 个 helloworld 示例程序全部编译通过并正确运行
  - `helloworld_stack`
  - `helloworld_stack_thread_socket`
  - `helloworld_stack_epoll`
  - `helloworld_stack_epoll_thread_socket`
  - `helloworld_stack_epoll_kernel`
- [ ] 使用 `FF_USE_RING_IPC` 编译后，所有示例的 echo server 能正确响应客户端请求
- [ ] 不使用 `FF_USE_RING_IPC` 编译后，行为与修改前完全一致

### AC-002: 性能验收

- [ ] 单次 syscall RTT 在 ring 方案下 ≤ 1μs（yield-poll 模式）
- [ ] Nginx 600B body 长连接 RPS ≥ sem 方案的性能
- [ ] 三种等待策略可正确切换，CPU 占用符合 NFR-003

### AC-003: 稳定性验收

- [ ] 连续运行 24 小时无内存泄漏（通过 DPDK memzone 统计验证）
- [ ] 高并发（32 个 APP 线程）场景下无死锁、无数据错乱
- [ ] APP 进程异常退出后，fstack 能正确清理 ring 中的残留请求

### AC-004: 代码质量

- [ ] 无新增编译警告（`-Wall -Werror`）
- [ ] 所有新增函数有注释说明参数和返回值
- [ ] 修改的函数保持原有代码风格

---

## 6. 信号量代码位置索引

> 以下表格列出所有需要在 ring 方案中修改或移除的信号量相关代码点。

### 6.1 信号量 API 调用

| 调用 | 文件 | 行号 | 说明 |
|---|---|---|---|
| `sem_init` | `ff_so_zone.c` | 101 | 初始化跨进程信号量 |
| `sem_timedwait` | `ff_hook_syscall.c` | 2265 | epoll_wait 超时等待 |
| `sem_wait` | `ff_hook_syscall.c` | 2270 | epoll_wait 无限等待 |
| `sem_timedwait` | `ff_hook_syscall.c` | 2555 | kevent 超时等待 |
| `sem_wait` | `ff_hook_syscall.c` | 2558 | kevent 无限等待 |
| `sem_post` | `ff_hook_syscall.c` | 3244 | alarm 补偿唤醒 |
| `sem_post` | `ff_socket_ops.c` | 557 | fstack 侧处理完成通知 |

### 6.2 信号量控制变量

| 变量 | 文件 | 行号 | 说明 |
|---|---|---|---|
| `sem_flag` | `ff_socket_ops.c` | 20 | 控制是否 sem_post |
| `sem_flag` 赋值 | `ff_socket_ops.c` | 313-364 | epoll_wait/kevent 返回后设置 |
| `sem_flag` 读取 | `ff_socket_ops.c` | 551, 555 | 决定是否唤醒 APP |
| `need_alarm_sem` | `ff_hook_syscall.c` | 248 | alarm 补偿标志 |
| `need_alarm_sem` 设置 | `ff_hook_syscall.c` | 2234, 2534 | 进入 sem_wait 前设置 |
| `need_alarm_sem` 清除 | `ff_hook_syscall.c` | 2276, 2564, 3245 | sem_wait 返回/alarm 后清除 |

### 6.3 结构体成员

| 成员 | 文件 | 行号 | 说明 |
|---|---|---|---|
| `sem_t wait_sem` | `ff_socket_ops.h` | 111 | 需替换为 ring 相关字段 |
| `#include <semaphore.h>` | `ff_socket_ops.h` | 5 | ring 方案下可移除 |

---

## 附录 A: 术语表

| 术语 | 说明 |
|---|---|
| **sc** | `ff_so_context` 的缩写，APP 与 fstack 之间的通信上下文 |
| **SPSC** | Single Producer Single Consumer，单生产者单消费者模式 |
| **RTT** | Round-Trip Time，请求到响应的完整往返时间 |
| **futex** | Linux 内核提供的快速用户空间互斥原语，sem_wait 的底层实现 |
| **Hugepage** | DPDK 使用的大页内存，跨进程共享 |
| **rte_ring** | DPDK 提供的无锁环形队列实现 |
| **drain_tsc** | fstack 轮询循环的时间窗口，由 `pkt_tx_delay` 参数控制 |

## 附录 B: 参考文档

1. F-Stack adapter/syscall/README.md — 现有 LD_PRELOAD 模块文档
2. DPDK rte_ring API — https://doc.dpdk.org/api/rte__ring_8h.html
3. VPP memif — https://docs.fd.io/vpp/21.06/dc/dea/libmemif_doc.html
4. VPP svm_msg_q — FD.io VPP Session Layer 共享内存消息队列
5. F-Stack 三层架构文档 — `/data/workspace/f-stack/docs/`
