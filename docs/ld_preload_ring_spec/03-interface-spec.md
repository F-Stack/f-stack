# F-Stack LD_PRELOAD 无锁环形队列改造 — 接口规格文档

> **文档编号**: SPEC-003  
> **版本**: v1.0 Draft  
> **日期**: 2026-03-27  
> **状态**: 待审核  
> **前置文档**: SPEC-001 需求规格文档, SPEC-002 架构设计文档

---

## 1. 概述

本文档定义从信号量（`sem_t`）同步机制迁移至 DPDK `rte_ring` 无锁环形队列方案所涉及的全部接口变更，包括：

- 新增数据结构定义
- 修改的现有数据结构
- 新增 / 修改的函数签名
- 新增 / 修改的宏定义
- 各源文件精确修改点映射
- 编译宏策略
- 错误码定义

所有变更均通过编译宏 `FF_USE_RING_IPC` 控制，确保可与现有信号量方案并存并渐进迁移。

---

## 2. 编译宏定义

### 2.1 新增编译宏

| 宏名称 | 默认值 | 说明 |
|--------|--------|------|
| `FF_USE_RING_IPC` | 未定义（默认使用 sem 方案） | 启用 rte_ring 无锁 IPC 模式 |
| `FF_RING_SIZE` | `64` | 每个 ring 的容量（必须为 2 的幂） |
| `FF_RING_WAIT_BUSY_POLL` | `0` | 等待策略：忙轮询 |
| `FF_RING_WAIT_YIELD_POLL` | `1` | 等待策略：让出 CPU 轮询 |
| `FF_RING_WAIT_EVENTFD` | `2` | 等待策略：eventfd 通知 |
| `FF_RING_DEFAULT_WAIT_MODE` | `FF_RING_WAIT_YIELD_POLL` | 默认等待策略 |
| `FF_RING_TIMEOUT_TSC_US` | `1` | rte_rdtsc 超时精度（微秒） |

### 2.2 现有编译宏变更

| 宏名称 | 变更说明 |
|--------|----------|
| `FF_PRELOAD_POLLING_MODE` | `FF_USE_RING_IPC` 启用时，此宏语义被 ring busy-poll 模式吸收；两者互斥，不可同时定义 |

### 2.3 互斥检查（编译期）

```c
/* ff_socket_ops.h 新增 */
#if defined(FF_USE_RING_IPC) && defined(FF_PRELOAD_POLLING_MODE)
#error "FF_USE_RING_IPC and FF_PRELOAD_POLLING_MODE are mutually exclusive"
#endif
```

---

## 3. 新增数据结构

### 3.1 `struct ff_sc_ring_zone` — Ring Zone 结构

**文件**: `ff_socket_ops.h`（新增定义）

```c
/*
 * Per fstack-instance ring zone for lock-free IPC.
 *
 * Each fstack instance creates one ring zone containing:
 *   - A request ring (APP enqueues, fstack dequeues)
 *   - A response ring (fstack enqueues, APP dequeues)
 *
 * Both rings operate in SPSC (Single Producer Single Consumer) mode
 * for maximum performance without CAS overhead.
 */
struct ff_sc_ring_zone {
    struct rte_ring *req_ring;    /* APP -> fstack 请求队列 (SPSC) */
    struct rte_ring *rsp_ring;    /* fstack -> APP 响应队列 (SPSC) */
    uint32_t ring_size;           /* ring 容量 (power of 2, default 64) */
    uint8_t wait_mode;            /* 等待策略: 0=busy-poll, 1=yield-poll, 2=eventfd */
    int eventfd_req;              /* eventfd: APP->fstack 通知 (仅 wait_mode==2) */
    int eventfd_rsp;              /* eventfd: fstack->APP 通知 (仅 wait_mode==2) */
    uint8_t padding[32];          /* 对齐到 64 字节 cache line */
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));
```

**字段说明**:

| 字段 | 类型 | 大小 | 说明 |
|------|------|------|------|
| `req_ring` | `struct rte_ring *` | 8B | 请求环形队列指针，由 `rte_ring_create()` 在 Hugepage 上创建 |
| `rsp_ring` | `struct rte_ring *` | 8B | 响应环形队列指针，同上 |
| `ring_size` | `uint32_t` | 4B | ring 容量，必须为 2 的幂，默认 `FF_RING_SIZE`(64) |
| `wait_mode` | `uint8_t` | 1B | 等待策略枚举值 |
| | (隐式对齐) | 3B | 编译器自动对齐到 4 字节边界 |
| `eventfd_req` | `int` | 4B | eventfd 文件描述符，仅在 `wait_mode == FF_RING_WAIT_EVENTFD` 时有效 |
| `eventfd_rsp` | `int` | 4B | 同上，用于响应方向 |
| `padding` | `uint8_t[]` | 32B | 填充对齐至 64 字节 cache line |

**总大小**: 64 字节（1 个 cache line，与 14.2 节布局一致）

### 3.2 Ring 命名规范

```c
/* ff_so_zone.c 新增 */
#define FF_SC_REQ_RING_NAME "ff_sc_req_ring_%d"   /* %d = proc_id */
#define FF_SC_RSP_RING_NAME "ff_sc_rsp_ring_%d"   /* %d = proc_id */
#define FF_SC_RING_ZONE_NAME "ff_sc_ring_zone_%d"  /* %d = proc_id */
```

---

## 4. 修改的数据结构

### 4.1 `struct ff_so_context` — 修改方案

**文件**: `ff_socket_ops.h`，行 97-118

**当前定义**:

```c
struct ff_so_context {
    /* CACHE LINE 0 */
    enum FF_SOCKET_OPS ops;           /*  4B, offset  0 */
    enum FF_SO_CONTEXT_STATUS status; /*  4B, offset  4 */
    void *args;                       /*  8B, offset  8 */
    rte_spinlock_t lock;              /*  4B, offset 16 */
    int error;                        /*  4B, offset 20 */
    int result;                       /*  4B, offset 24 */
    int idx;                          /*  4B, offset 28 */
    sem_t wait_sem; /* 32 bytes */    /* 32B, offset 32 */
    /* CACHE LINE 1 */
    int refcount;                     /*  4B, offset 64 */
    void *ff_thread_handle;           /*  8B, offset 68 */
    volatile int forking;             /*  4B, offset 76 */
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));
```

**修改后定义**（`FF_USE_RING_IPC` 启用时）:

```c
struct ff_so_context {
    /* CACHE LINE 0 */
    enum FF_SOCKET_OPS ops;               /*  4B, offset  0 */
    enum FF_SO_CONTEXT_STATUS status;     /*  4B, offset  4 */
    void *args;                           /*  8B, offset  8 */

#ifdef FF_USE_RING_IPC
    /* ring 模式下 lock 保留但仅用于 fork/detach 等生命周期操作 */
    rte_spinlock_t lock;                  /*  4B, offset 16 */
    int error;                            /*  4B, offset 20 */
    int result;                           /*  4B, offset 24 */
    int idx;                              /*  4B, offset 28 */
    /* 替换 sem_t wait_sem (32B) 为以下字段 */
    volatile uint32_t completion;         /*  4B, offset 32 — 原子完成标志 */
    uint32_t ring_zone_id;                /*  4B, offset 36 — 关联的 ring zone 索引 */
    uint8_t reserved[24];                 /* 24B, offset 40 — 保持 cache line 对齐 */
#else
    rte_spinlock_t lock;                  /*  4B, offset 16 */
    int error;                            /*  4B, offset 20 */
    int result;                           /*  4B, offset 24 */
    int idx;                              /*  4B, offset 28 */
    sem_t wait_sem; /* 32 bytes */        /* 32B, offset 32 */
#endif

    /* CACHE LINE 1 */
    int refcount;                         /*  4B, offset 64 */
    void *ff_thread_handle;               /*  8B, offset 72 (8-byte aligned) */
    volatile int forking;                 /*  4B, offset 80 */
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));
```

**变更摘要**:

| 偏移量 | 旧字段 | 新字段（`FF_USE_RING_IPC`） | 大小变化 |
|--------|--------|---------------------------|---------|
| 32 | `sem_t wait_sem` (32B) | `volatile uint32_t completion` (4B) | -28B |
| 36 | — | `uint32_t ring_zone_id` (4B) | +4B |
| 40 | — | `uint8_t reserved[24]` (24B) | +24B |

**总结**: Cache Line 0 布局保持 64 字节不变，Cache Line 1 保持不变。

### 4.2 `struct ff_socket_ops_zone` — 修改方案

**文件**: `ff_socket_ops.h`，行 78-95

**新增字段**:

```c
struct ff_socket_ops_zone {
    rte_spinlock_t lock;

    /* total number of so_contex, must be power of 2 */
    uint8_t count;
    uint8_t mask;

    /* free number of so_context */
    uint8_t free;

    uint8_t idx;

    /* 1 if used, else 0, most access */
    uint8_t inuse[SOCKET_OPS_CONTEXT_MAX_NUM];
    struct ff_so_context *sc;

#ifdef FF_USE_RING_IPC
    struct ff_sc_ring_zone *ring_zone;     /* 新增: 指向关联的 ring zone */
#endif

    uint8_t padding[16];
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));
```

**注意**: `padding` 大小可能需要调整以适应新增的 `ring_zone` 指针（8 字节），从 `padding[16]` 调整为 `padding[8]`，或将 `ring_zone` 指针放在 `padding` 空间内。

---

## 5. 新增函数签名

### 5.1 Ring Zone 生命周期管理

**文件**: `ff_socket_ops.h`（声明），`ff_so_zone.c`（实现）

```c
/**
 * 创建 ring zone（fstack 主进程调用）
 *
 * @param proc_id   fstack 实例编号
 * @param ring_size ring 容量（必须为 2 的幂）
 * @param wait_mode 等待策略 (FF_RING_WAIT_*)
 * @return 0 成功, -1 失败
 */
#ifdef FF_USE_RING_IPC
int ff_create_sc_ring_zone(int proc_id, uint32_t ring_size, uint8_t wait_mode);
#endif

/**
 * 查找并附加到已有的 ring zone（APP 侧 secondary 进程调用）
 *
 * @param proc_id fstack 实例编号
 * @return ring zone 指针, NULL 表示失败
 */
#ifdef FF_USE_RING_IPC
struct ff_sc_ring_zone *ff_attach_sc_ring_zone(int proc_id);
#endif
```

### 5.2 Ring IPC 操作

**文件**: `ff_socket_ops.h`（声明）

```c
#ifdef FF_USE_RING_IPC
/**
 * APP 侧: 提交请求到 ring 并等待响应
 *
 * @param ring_zone ring zone 指针
 * @param sc        so_context 指针（请求已填充 ops/args）
 * @param timeout_us 超时时间（微秒），0=不超时，-1=永久阻塞
 * @return 0 成功获取响应, -1 超时
 */
int ff_ring_submit_and_wait(struct ff_sc_ring_zone *ring_zone,
                            struct ff_so_context *sc,
                            int64_t timeout_us);

/**
 * fstack 侧: 从请求 ring 批量出队并处理
 *
 * @param ring_zone ring zone 指针
 * @param handler   处理函数指针
 * @param max_burst 单次最大出队数
 * @return 处理的请求数
 */
uint16_t ff_ring_process_requests(struct ff_sc_ring_zone *ring_zone,
                                  void (*handler)(struct ff_so_context *),
                                  uint16_t max_burst);

/**
 * fstack 侧: 将已处理的响应入队到响应 ring
 *
 * @param ring_zone ring zone 指针
 * @param sc        已处理的 so_context 指针
 * @return 0 成功, -1 ring 满
 */
int ff_ring_send_response(struct ff_sc_ring_zone *ring_zone,
                          struct ff_so_context *sc);

/**
 * APP 侧: 向请求 ring 入队一个 sentinel（用于唤醒阻塞的 APP）
 * 替代原 alarm_event_sem() 功能
 *
 * @param ring_zone ring zone 指针
 * @param sc        so_context 指针
 */
void ff_ring_alarm_wakeup(struct ff_sc_ring_zone *ring_zone,
                          struct ff_so_context *sc);
#endif
```

### 5.3 超时等待辅助函数

**文件**: `ff_socket_ops.h`（声明），`ff_socket_ops.c`（实现）

```c
#ifdef FF_USE_RING_IPC
/**
 * 基于 rte_rdtsc 的微秒级超时等待 ring dequeue
 *
 * @param ring       要等待的 ring
 * @param obj_p      出队对象指针
 * @param timeout_us 超时（微秒），-1=永久
 * @param wait_mode  等待策略
 * @return 0 成功出队, -ETIMEDOUT 超时
 */
int ff_ring_dequeue_wait(struct rte_ring *ring, void **obj_p,
                         int64_t timeout_us, uint8_t wait_mode);
#endif
```

---

## 6. 修改的函数签名

### 6.1 `ff_handle_each_context()` — fstack 侧轮询改造

**文件**: `ff_socket_ops.c`，行 569-638

**当前签名**: `void ff_handle_each_context(void)`  
**修改后签名**: 签名不变，内部实现分支

```c
void
ff_handle_each_context(void)
{
#ifdef FF_USE_RING_IPC
    /* 新路径: 从 req_ring 出队，处理后入队 rsp_ring */
    ff_ring_process_requests(ff_so_zone->ring_zone,
                             ff_handle_socket_ops_ring,
                             FF_RING_SIZE);
#else
    /* 原路径: O(n) 遍历所有 sc */
    // ... 现有代码保持不变 ...
#endif
}
```

### 6.2 `ff_handle_socket_ops()` — fstack 侧单请求处理

**文件**: `ff_socket_ops.c`，行 502-567

**新增 ring 模式变体**:

```c
#ifdef FF_USE_RING_IPC
/**
 * Ring 模式下的请求处理（由 ff_ring_process_requests 回调）
 * 与原函数区别:
 *   - 不需要 trylock（ring dequeue 已保证互斥）
 *   - 不需要检查 status（ring 出队即表示有请求）
 *   - 处理完成后调用 ff_ring_send_response 而非 sem_post
 */
static void
ff_handle_socket_ops_ring(struct ff_so_context *sc);
#endif
```

### 6.3 `ff_create_so_memzone()` — 共享内存区初始化

**文件**: `ff_so_zone.c`，行 55-128

**内部变更**: 在 ring 模式下：
- 跳过 `sem_init(&sc->wait_sem, 1, 0)` 调用（行 101-104）
- 新增调用 `ff_create_sc_ring_zone()` 创建 ring zone
- 初始化 `sc->completion = 0` 和 `sc->ring_zone_id`

### 6.4 `alarm_event_sem()` — 信号唤醒替代

**文件**: `ff_hook_syscall.c`，行 3235-3252  
**声明**: `ff_adapter.h`，行 15

**修改后**:

```c
void
alarm_event_sem(void)
{
#ifndef FF_THREAD_SOCKET
#ifdef FF_USE_RING_IPC
    /* Ring 模式: 向响应 ring 入队一个 sentinel 唤醒 APP */
    if (ff_so_zone && ff_so_zone->ring_zone) {
        ff_ring_alarm_wakeup(ff_so_zone->ring_zone, sc);
    }
#else
    /* 原信号量模式 */
    // ... 现有代码保持不变 ...
#endif
#endif
}
```

---

## 7. 修改的宏定义

### 7.1 `ACQUIRE_ZONE_LOCK` — Ring 模式替代

**文件**: `ff_hook_syscall.c`，行 114-126

```c
#ifdef FF_USE_RING_IPC
/* Ring 模式下不使用 ACQUIRE_ZONE_LOCK / RELEASE_ZONE_LOCK，
 * SYSCALL 宏已改为 rte_ring enqueue/dequeue + 轮询 rsp_ring。
 * 此定义仅用于防止编译错误（若有遗留引用）。
 * 实际 Ring 模式 IPC 流程见 §5 SYSCALL 宏改造。 */
#define ACQUIRE_ZONE_LOCK(exp) do {                               \
    while (__atomic_load_n(&sc->completion, __ATOMIC_ACQUIRE) != (exp)) { \
        rte_pause();                                              \
    }                                                             \
} while (0)
#else
/* 原代码保持不变 */
#define ACQUIRE_ZONE_LOCK(exp) do {                               \
    while (1) {                                                   \
        while (sc->status != exp) {                               \
            rte_pause();                                          \
        }                                                         \
        rte_spinlock_lock(&sc->lock);                             \
        if (sc->status == exp) {                                  \
            break;                                                \
        }                                                         \
        rte_spinlock_unlock(&sc->lock);                           \
    }                                                             \
} while (0)
#endif
```

### 7.2 `ACQUIRE_ZONE_TRY_LOCK` — Ring 模式替代

**文件**: `ff_hook_syscall.c`，行 128-141

```c
#ifdef FF_USE_RING_IPC
/* Ring 模式下无需 trylock，fstack 从 ring 出队即获取请求 */
#define ACQUIRE_ZONE_TRY_LOCK(exp) ACQUIRE_ZONE_LOCK(exp)
#else
/* 原代码保持不变 */
// ...
#endif
```

### 7.3 `RELEASE_ZONE_LOCK` — Ring 模式替代

**文件**: `ff_hook_syscall.c`，行 143-146

```c
#ifdef FF_USE_RING_IPC
#define RELEASE_ZONE_LOCK(s) do {                                 \
    __atomic_store_n(&sc->status, (s), __ATOMIC_RELEASE);         \
} while (0)
#else
#define RELEASE_ZONE_LOCK(s) do {                                 \
    sc->status = s;                                               \
    rte_spinlock_unlock(&sc->lock);                               \
} while (0)
#endif
```

### 7.4 `SYSCALL` — Ring 模式重写

**文件**: `ff_hook_syscall.c`，行 148-160

```c
#ifdef FF_USE_RING_IPC
/*
 * Ring 模式下的系统调用宏:
 * 1. 填充 sc->ops 和 sc->args
 * 2. 入队到请求 ring
 * 3. 从响应 ring 出队等待结果
 */
#define SYSCALL(op, arg) do {                                     \
    sc->ops = (op);                                               \
    sc->args = (arg);                                             \
    sc->result = 0;                                               \
    sc->error = 0;                                                \
    if (ff_ring_submit_and_wait(ff_so_zone->ring_zone, sc, -1) < 0) { \
        errno = ETIMEDOUT;                                        \
        ret = -1;                                                 \
    } else {                                                      \
        ret = sc->result;                                         \
        if (ret < 0) {                                            \
            errno = sc->error;                                    \
        }                                                         \
    }                                                             \
} while (0)
#else
/* 原代码保持不变 */
#define SYSCALL(op, arg) do {                                     \
    ACQUIRE_ZONE_LOCK(FF_SC_IDLE);                                \
    sc->ops = (op);                                               \
    sc->args = (arg);                                             \
    RELEASE_ZONE_LOCK(FF_SC_REQ);                                 \
    ACQUIRE_ZONE_LOCK(FF_SC_REP);                                 \
    ret = sc->result;                                             \
    if (ret < 0) {                                                \
        errno = sc->error;                                        \
    }                                                             \
    RELEASE_ZONE_LOCK(FF_SC_IDLE);                                \
} while (0)
#endif
```

---

## 8. 各源文件精确修改点映射

### 8.1 `ff_socket_ops.h` — 头文件

| 行号 | 当前内容 | 修改类型 | 修改说明 |
|------|---------|---------|---------|
| 5 | `#include <semaphore.h>` | 条件编译包裹 | `#ifndef FF_USE_RING_IPC` 时保留；`#ifdef FF_USE_RING_IPC` 时替换为 `#include <rte_ring.h>` |
| 7-8 | `#include <rte_atomic.h>` / `<rte_spinlock.h>` | 保留 | ring 模式仍需这两个头文件 |
| 72-76 | `enum FF_SO_CONTEXT_STATUS` | 保留 | 状态枚举在 ring 模式下仍用于 `completion` 标志 |
| 78-95 | `struct ff_socket_ops_zone` | 新增字段 | `#ifdef FF_USE_RING_IPC` 新增 `ring_zone` 指针 |
| 92 后 | — | 新增 | `struct ff_sc_ring_zone *ring_zone;` |
| 94 | `uint8_t padding[16]` | 调整 | 减少为 `padding[8]` 以适应新指针 |
| 97-118 | `struct ff_so_context` | 条件替换 | `sem_t wait_sem` (32B) 替换为 `completion` + `ring_zone_id` + `reserved` |
| 118 后 | — | 新增 | `struct ff_sc_ring_zone` 定义 |
| 126-132 | 函数声明区 | 新增 | ring 相关函数声明（参见第 5 节） |
| 文件末尾 | `#endif` 前 | 新增 | 编译宏互斥检查 |

### 8.2 `ff_so_zone.c` — 共享内存区初始化

| 行号 | 当前内容 | 修改类型 | 修改说明 |
|------|---------|---------|---------|
| 1-8 | `#include` 区域 | 新增 | `#ifdef FF_USE_RING_IPC` 时新增 `#include <rte_ring.h>` |
| 10-13 | 宏定义区 | 新增 | ring 名称宏: `FF_SC_REQ_RING_NAME`, `FF_SC_RSP_RING_NAME`, `FF_SC_RING_ZONE_NAME` |
| 16 后 | 全局变量区 | 新增 | `#ifdef FF_USE_RING_IPC` 全局 ring zone 变量 |
| 55-128 | `ff_create_so_memzone()` | 条件分支 | `#ifdef FF_USE_RING_IPC`: 跳过 `sem_init`，调用 `ff_create_sc_ring_zone()` |
| 92-105 | for 循环（sc 初始化） | 条件修改 | ring 模式初始化 `completion=0`, `ring_zone_id=proc_id`；跳过 `sem_init` |
| 101-104 | `sem_init(&sc->wait_sem, 1, 0)` | 条件跳过 | `#ifndef FF_USE_RING_IPC` 包裹 |
| 107-110 | proc_id==0 赋值 | 新增 | ring 模式下同时赋值 `ff_so_zone->ring_zone` |
| 128 后 | — | 新增 | `ff_create_sc_ring_zone()` 函数实现 |
| 128 后 | — | 新增 | `ff_attach_sc_ring_zone()` 函数实现 |
| 130-198 | `ff_attach_so_context()` | 新增逻辑 | ring 模式下附加 ring zone 引用 |

### 8.3 `ff_socket_ops.c` — fstack 侧处理逻辑

| 行号 | 当前内容 | 修改类型 | 修改说明 |
|------|---------|---------|---------|
| 1-2 | `#include` 区域 | 新增 | `#ifdef FF_USE_RING_IPC` 时新增 `#include <rte_ring.h>` |
| 19-20 | `static int sem_flag = 0;` | 条件编译 | `#ifndef FF_USE_RING_IPC` 包裹；ring 模式不需要 sem_flag |
| 308-333 | `ff_sys_epoll_wait` 内 sem_flag 赋值 | 条件编译 | `#ifndef FF_USE_RING_IPC` 包裹 |
| 361-365 | `ff_sys_kevent` 内 sem_flag 赋值 | 条件编译 | `#ifndef FF_USE_RING_IPC` 包裹 |
| 502-567 | `ff_handle_socket_ops()` | 新增变体 | 新增 `ff_handle_socket_ops_ring()` 用于 ring 回调 |
| 536-561 | sem_flag/sem_post 逻辑 | 条件编译 | ring 模式下用 `ff_ring_send_response()` 替代 |
| 550-561 | `#ifdef FF_PRELOAD_POLLING_MODE` 块 | 条件调整 | ring 模式不进入此分支 |
| 557 | `sem_post(&sc->wait_sem);` | 替换 | ring 模式: `ff_ring_send_response(ring_zone, sc)` |
| 563 | `sc->status = FF_SC_REP;` | 条件修改 | ring 模式: 入队 rsp_ring 即表示完成 |
| 569-638 | `ff_handle_each_context()` | 重写 | ring 模式: 调用 `ff_ring_process_requests()` 替代 O(n) 遍历 |
| 586 | `rte_spinlock_lock(&ff_so_zone->lock)` | 条件跳过 | ring 模式不需要全局 zone lock |
| 608-609 | dirty read + `ff_handle_socket_ops` | 替换 | ring 模式: `rte_ring_dequeue` + `ff_handle_socket_ops_ring` |
| 631 | `rte_spinlock_unlock(&ff_so_zone->lock)` | 条件跳过 | ring 模式不需要 |
| 638 后 | — | 新增 | `ff_ring_process_requests()` 实现 |
| 638 后 | — | 新增 | `ff_ring_send_response()` 实现 |
| 638 后 | — | 新增 | `ff_ring_dequeue_wait()` 实现 |

### 8.4 `ff_hook_syscall.c` — APP 侧 hook 函数

| 行号 | 当前内容 | 修改类型 | 修改说明 |
|------|---------|---------|---------|
| 1-22 | `#include` 区域 | 新增 | `#ifdef FF_USE_RING_IPC` 时新增 `#include <rte_ring.h>`, `#include <sys/eventfd.h>` |
| 114-126 | `ACQUIRE_ZONE_LOCK` 宏 | 条件替换 | ring 模式使用 `__atomic_load_n` 替代 spinlock |
| 128-141 | `ACQUIRE_ZONE_TRY_LOCK` 宏 | 条件替换 | ring 模式退化为 `ACQUIRE_ZONE_LOCK` |
| 143-146 | `RELEASE_ZONE_LOCK` 宏 | 条件替换 | ring 模式使用 `__atomic_store_n` 替代 unlock |
| 148-160 | `SYSCALL` 宏 | 条件重写 | ring 模式使用 `ff_ring_submit_and_wait()` |
| 248 | `static int need_alarm_sem = 0;` | 条件编译 | `#ifndef FF_USE_RING_IPC` 包裹 |
| 2035-2147 | `FF_PRELOAD_POLLING_MODE` epoll_wait | 条件编译 | `#if !defined(FF_USE_RING_IPC)` 新增条件 |
| 2148-2337 | 非 POLLING 模式 epoll_wait | 条件修改 | ring 模式重写 sem_wait 部分 |
| 2193-2208 | `abs_timeout` 计算 | 条件编译 | ring 模式使用 `rte_rdtsc` 计时 |
| 2215-2237 | RETRY 标签后的 ACQUIRE/RELEASE | 重写 | ring 模式使用 `ff_ring_submit_and_wait` |
| 2233-2235 | `need_alarm_sem = 1` (epoll_wait) | 条件编译 | `#ifndef FF_USE_RING_IPC` 包裹 |
| 2263-2271 | `sem_timedwait` / `sem_wait` (epoll_wait) | 替换 | ring 模式: `ff_ring_dequeue_wait(rsp_ring, ...)` |
| 2265 | `sem_timedwait(&sc->wait_sem, &abs_timeout)` | 替换 | ring 模式: `ff_ring_dequeue_wait(rsp_ring, &obj, timeout_us, wait_mode)` |
| 2270 | `sem_wait(&sc->wait_sem)` | 替换 | ring 模式: `ff_ring_dequeue_wait(rsp_ring, &obj, -1, wait_mode)` |
| 2273 | `rte_spinlock_lock(&sc->lock)` | 条件跳过 | ring 模式不需要 |
| 2275-2277 | `need_alarm_sem = 0` (epoll_wait) | 条件编译 | `#ifndef FF_USE_RING_IPC` 包裹 |
| 2297-2298 | `sc->status = FF_SC_IDLE` + unlock | 条件修改 | ring 模式仅重置 completion 标志 |
| 2515 | `ACQUIRE_ZONE_LOCK(FF_SC_IDLE)` (kevent) | 条件修改 | ring 模式直接填充并入队 |
| 2520 | `sc->status = FF_SC_REQ` (kevent) | 条件修改 | ring 模式: 入队 req_ring |
| 2533-2535 | `need_alarm_sem = 1` (kevent) | 条件编译 | `#ifndef FF_USE_RING_IPC` 包裹 |
| 2537 | `rte_spinlock_unlock(&sc->lock)` (kevent) | 条件跳过 | ring 模式不需要 |
| 2539-2559 | `sem_timedwait` / `sem_wait` (kevent) | 替换 | ring 模式: `ff_ring_dequeue_wait(rsp_ring, ...)` |
| 2555 | `sem_timedwait(&sc->wait_sem, &abs_timeout)` | 替换 | 同上 |
| 2558 | `sem_wait(&sc->wait_sem)` | 替换 | 同上 |
| 2561 | `rte_spinlock_lock(&sc->lock)` (kevent) | 条件跳过 | ring 模式不需要 |
| 2563-2565 | `need_alarm_sem = 0` (kevent) | 条件编译 | `#ifndef FF_USE_RING_IPC` 包裹 |
| 2583 | `sc->status = FF_SC_IDLE` (kevent) | 条件修改 | ring 模式重置 completion |
| 2585 | `rte_spinlock_unlock(&sc->lock)` (kevent) | 条件跳过 | ring 模式不需要 |
| 3235-3252 | `alarm_event_sem()` | 条件重写 | ring 模式使用 `ff_ring_alarm_wakeup()` |
| 3244 | `sem_post(&sc->wait_sem)` | 替换 | ring 模式: `ff_ring_alarm_wakeup(ring_zone, sc)` |

### 8.5 `ff_adapter.h` — 适配器头文件

| 行号 | 当前内容 | 修改类型 | 修改说明 |
|------|---------|---------|---------|
| 15 | `void alarm_event_sem();` | 保留 | 函数签名不变，内部实现分支 |

### 8.6 `fstack.c` — fstack 主程序

| 行号 | 当前内容 | 修改类型 | 修改说明 |
|------|---------|---------|---------|
| 1-2 | `#include` | 保留 | 无需新增 include（通过 ff_socket_ops.h 传递） |
| 9 | `ff_handle_each_context();` | 保留 | 调用签名不变，内部实现分支 |
| 26 | `ff_create_so_memzone()` | 保留 | 调用签名不变，内部创建 ring zone |

### 8.7 `main_stack*.c` — 示例程序

| 文件 | 行号 | 当前内容 | 修改说明 |
|------|------|---------|---------|
| `main_stack.c` | 75 | `alarm_event_sem();` | 无需修改（函数签名不变，内部分支） |
| `main_stack_epoll.c` | 64 | `//alarm_event_sem();` | 无需修改 |
| `main_stack_epoll_kernel.c` | 67 | `//alarm_event_sem();` | 无需修改 |
| `main_stack_epoll_thread_socket.c` | 62 | `//alarm_event_sem();` | 无需修改 |
| `main_stack_thread_socket.c` | 71 | `//alarm_event_sem();` | 无需修改 |

### 8.8 `Makefile` — 编译配置

| 行号 | 当前内容 | 修改类型 | 修改说明 |
|------|---------|---------|---------|
| 22 后 | — | 新增 | `#FF_USE_RING_IPC=1` 变量定义（默认注释） |
| 60 后 | — | 新增 | `ifdef FF_USE_RING_IPC` + `CFLAGS+= -DFF_USE_RING_IPC` |
| 60 后 | — | 新增 | 互斥检查: ring 模式与 polling 模式不可同时启用 |

**新增 Makefile 段**:

```makefile
# Lock-free ring IPC mode, replace sem_wait with rte_ring.
# If enable it, FF_PRELOAD_POLLING_MODE must be disabled.
#FF_USE_RING_IPC=1

ifdef FF_USE_RING_IPC
ifdef FF_PRELOAD_POLLING_MODE
$(error "FF_USE_RING_IPC and FF_PRELOAD_POLLING_MODE are mutually exclusive")
endif
	CFLAGS+= -DFF_USE_RING_IPC
endif
```

---

## 9. 新增头文件包含关系

### 9.1 `ff_socket_ops.h` 条件 include

```c
#ifdef FF_USE_RING_IPC
#include <rte_ring.h>
#else
#include <semaphore.h>
#endif

#include <rte_atomic.h>
#include <rte_spinlock.h>
```

### 9.2 `ff_so_zone.c` 新增 include

```c
#ifdef FF_USE_RING_IPC
#include <rte_ring.h>
#include <rte_memzone.h>    /* 已有，保留 */
#endif
```

### 9.3 `ff_socket_ops.c` 新增 include

```c
#ifdef FF_USE_RING_IPC
#include <rte_ring.h>
#endif
```

### 9.4 `ff_hook_syscall.c` 新增 include

```c
#ifdef FF_USE_RING_IPC
#include <rte_ring.h>
#include <rte_cycles.h>     /* rte_rdtsc, rte_get_tsc_hz */
#include <sys/eventfd.h>    /* eventfd (仅 eventfd 模式) */
#endif
```

---

## 10. 错误码定义

### 10.1 Ring 操作错误码

Ring 操作复用标准 POSIX errno，不引入自定义错误码：

| 场景 | errno | 说明 |
|------|-------|------|
| ring 创建失败 | `ENOMEM` | rte_ring_create 返回 NULL |
| ring 满（入队失败） | `ENOSPC` | rte_ring_enqueue 返回 -ENOBUFS |
| ring 等待超时 | `ETIMEDOUT` | ff_ring_dequeue_wait 超时 |
| ring zone 查找失败 | `ENOENT` | rte_memzone_lookup 返回 NULL |
| 编译宏冲突 | 编译错误 | `FF_USE_RING_IPC` 与 `FF_PRELOAD_POLLING_MODE` 同时定义 |

---

## 11. `ff_ring_submit_and_wait` 详细实现规格

### 11.1 算法流程

```
ff_ring_submit_and_wait(ring_zone, sc, timeout_us):
    1. 设置 sc->completion = FF_SC_REQ
    2. rte_ring_sp_enqueue(ring_zone->req_ring, sc)
       - 如果失败(ring满)，spin 重试
    3. 如果 wait_mode == eventfd:
       - 可选: write(eventfd_req, 1) 通知 fstack
    4. 等待响应:
       a. busy-poll:
          - while (rte_ring_sc_dequeue(ring_zone->rsp_ring, &obj) != 0)
              rte_pause()
              检查超时 (rte_rdtsc)
       b. yield-poll:
          - 同上，但每 N 次循环后 sched_yield()
       c. eventfd:
          - poll/epoll_wait(eventfd_rsp, timeout)
          - read(eventfd_rsp)
          - rte_ring_sc_dequeue(ring_zone->rsp_ring, &obj)
    5. 返回 0(成功) 或 -ETIMEDOUT(超时)
```

### 11.2 超时计算

```c
/* 基于 TSC 的微秒级超时 */
uint64_t tsc_hz = rte_get_tsc_hz();
uint64_t timeout_tsc = (timeout_us > 0)
    ? (uint64_t)timeout_us * tsc_hz / 1000000ULL
    : UINT64_MAX;  /* -1 = 永久 */
uint64_t start_tsc = rte_rdtsc();

while (rte_ring_sc_dequeue(ring, &obj) != 0) {
    if (rte_rdtsc() - start_tsc >= timeout_tsc) {
        return -ETIMEDOUT;
    }
    /* wait_mode 策略 */
    switch (wait_mode) {
        case FF_RING_WAIT_BUSY_POLL:
            rte_pause();
            break;
        case FF_RING_WAIT_YIELD_POLL:
            if ((++spin_count & 0xFF) == 0) sched_yield();
            else rte_pause();
            break;
        case FF_RING_WAIT_EVENTFD:
            /* eventfd poll */
            break;
    }
}
```

---

## 12. `ff_ring_process_requests` 详细实现规格

### 12.1 算法流程

```
ff_ring_process_requests(ring_zone, handler, max_burst):
    processed = 0
    while (processed < max_burst):
        ret = rte_ring_sc_dequeue(ring_zone->req_ring, &obj)
        if (ret != 0):
            break  /* ring 空，无更多请求 */
        sc = (struct ff_so_context *)obj
        handler(sc)  /* 处理请求 */
        processed++
    return processed
```

### 12.2 fstack 侧处理回调

```c
static void
ff_handle_socket_ops_ring(struct ff_so_context *sc)
{
    /* 直接处理，无需 trylock 或 status 检查 */
    errno = 0;

#ifdef FF_USE_THREAD_STRUCT_HANDLE
    /* 线程句柄切换（同原有逻辑） */
    void *old_thread = NULL;
    if (sc->ff_thread_handle) {
        old_thread = ff_switch_curthread(sc->ff_thread_handle);
    }
#endif

    sc->result = ff_so_handler(sc->ops, sc->args);

#ifdef FF_USE_THREAD_STRUCT_HANDLE
    if (sc->ff_thread_handle) {
        ff_restore_curthread(old_thread);
    }
#endif

    sc->error = errno;

    /* 响应入队 */
    ff_ring_send_response(ff_so_zone->ring_zone, sc);
}
```

---

## 13. epoll_wait / kevent 特殊处理

### 13.1 epoll_wait (Ring 模式)

**文件**: `ff_hook_syscall.c`，行 2148-2337

Ring 模式下 `ff_hook_epoll_wait` 的特殊逻辑：

```c
#ifdef FF_USE_RING_IPC
int
ff_hook_epoll_wait(int epfd, struct epoll_event *events,
    int maxevents, int timeout)
{
    // ... 参数准备（同原有逻辑: sh_events 分配等）...

    int64_t timeout_us;
    if (timeout < 0) {
        timeout_us = -1;       /* 永久阻塞 */
    } else if (timeout == 0) {
        timeout_us = 0;        /* 不等待 */
    } else {
        timeout_us = (int64_t)timeout * 1000;  /* ms -> us */
    }

RETRY:
    args->epfd = fd;
    args->events = sh_events;
    args->maxevents = maxevents;
    args->timeout = timeout;

    sc->ops = FF_SO_EPOLL_WAIT;
    sc->args = args;
    sc->result = 0;
    sc->error = 0;
    errno = 0;

    /* 入队请求并等待响应 */
    ret = ff_ring_submit_and_wait(ff_so_zone->ring_zone, sc, timeout_us);

    if (ret == -ETIMEDOUT) {
        ret = 0;  /* 超时返回 0 事件 */
    } else {
        ret = sc->result;
        if (ret < 0) {
            errno = sc->error;
        }
    }

    /* 复制结果 */
    if (likely(ret > 0)) {
        rte_memcpy(events, sh_events, sizeof(struct epoll_event) * ret);
    }

    /* 永久阻塞且无事件时重试 */
    if (timeout < 0 && ret == 0) {
        rte_pause();
        goto RETRY;
    }

    RETURN_NOFREE();
}
#endif /* FF_USE_RING_IPC */
```

### 13.2 kevent (Ring 模式)

**文件**: `ff_hook_syscall.c`，行 2435-2620

kevent 函数的 ring 模式改造与 epoll_wait 类似：

```c
/* kevent ring 模式改造要点: */
// 1. timeout -> timeout_us 转换:
//    if (timeout == NULL) timeout_us = -1;
//    else timeout_us = timeout->tv_sec * 1000000 + timeout->tv_nsec / 1000;
// 2. 替换 sem_timedwait/sem_wait 为 ff_ring_submit_and_wait
// 3. 移除 need_alarm_sem 赋值
// 4. 移除 rte_spinlock_lock/unlock
```

---

## 14. 内存布局验证

### 14.1 `ff_so_context` 布局检查

```
Ring 模式 ff_so_context 内存布局:
Offset  Size  Field
------  ----  -----
  0       4   ops (enum FF_SOCKET_OPS)
  4       4   status (enum FF_SO_CONTEXT_STATUS)
  8       8   args (void *)
 16       4   lock (rte_spinlock_t)
 20       4   error (int)
 24       4   result (int)
 28       4   idx (int)
 32       4   completion (volatile uint32_t)
 36       4   ring_zone_id (uint32_t)
 40      24   reserved (uint8_t[24])
------- Cache Line 1 -------
 64       4   refcount (int)
 68       8   ff_thread_handle (void *)
 76       4   forking (volatile int)
 80      48   (implicit padding to 128B)

Total: 128 bytes (2 cache lines, aligned)
```

### 14.2 `ff_sc_ring_zone` 布局检查

```
ff_sc_ring_zone 内存布局:
Offset  Size  Field
------  ----  -----
  0       8   req_ring (struct rte_ring *)
  8       8   rsp_ring (struct rte_ring *)
 16       4   ring_size (uint32_t)
 20       1   wait_mode (uint8_t)
 21       3   (implicit padding)
 24       4   eventfd_req (int)
 28       4   eventfd_rsp (int)
 32      32   padding (uint8_t[32])
------- End -------
Total: 64 bytes (1 cache line, aligned)
```

---

## 15. 接口兼容性矩阵

| 接口 / 函数 | sem 模式 | ring 模式 | 对外签名变化 |
|-------------|---------|-----------|-------------|
| `ff_create_so_memzone()` | ✅ | ✅ (内部创建 ring) | 无 |
| `ff_attach_so_context()` | ✅ | ✅ (附加 ring ref) | 无 |
| `ff_detach_so_context()` | ✅ | ✅ (清理 ring ref) | 无 |
| `ff_handle_each_context()` | ✅ | ✅ (ring 出队) | 无 |
| `alarm_event_sem()` | ✅ | ✅ (ring wakeup) | 无 |
| `SYSCALL(op, arg)` 宏 | ✅ | ✅ (ring submit) | 无 (宏) |
| `ff_hook_epoll_wait()` | ✅ | ✅ (ring 超时) | 无 |
| `kevent()` | ✅ | ✅ (ring 超时) | 无 |
| `ff_hook_socket()` | ✅ | ✅ (via SYSCALL) | 无 |
| 所有其他 `ff_hook_*()` | ✅ | ✅ (via SYSCALL) | 无 |

---

## 16. 关键设计决策记录

### D-001: 为何保留 `rte_spinlock_t lock` 字段

**决策**: 在 ring 模式下保留 `sc->lock` 字段但不在常规请求路径中使用。

**理由**:
1. `ff_detach_so_context()` (行 212-213) 需要同时锁 zone->lock 和 sc->lock
2. `ff_hook_fork()` (行 2352-2354) 需要 sc->lock 保护 fork 期间的状态一致性
3. 保持结构体布局二进制兼容，便于渐进迁移

### D-002: Ring 队列传递的是指针而非数据拷贝

**决策**: `rte_ring` 中入队/出队的是 `ff_so_context *` 指针。

**理由**:
1. `ff_so_context` 本身已在 Hugepage 共享内存上，无需拷贝
2. 指针传递零拷贝，8 字节原子操作
3. 与现有架构保持一致（sc 已经是跨进程共享的）

### D-003: 为何不移除 `status` 字段

**决策**: 保留 `enum FF_SO_CONTEXT_STATUS status` 字段。

**理由**:
1. `status` 用于 debug 日志中人类可读的状态输出
2. `completion` 字段使用原子操作，`status` 可以非原子地设置用于调试
3. 在 fork、detach 等生命周期操作中仍需检查 status

### D-004: SPSC 模式的正确性保证

**决策**: 两个 ring 均使用 SPSC 模式 (`RING_F_SP_ENQ | RING_F_SC_DEQ`)。

**理由**:
1. APP 进程与 fstack 实例 1:1 绑定（一个 sc 只有一个 APP 线程使用）
2. 请求 ring: APP (唯一生产者) -> fstack (唯一消费者)
3. 响应 ring: fstack (唯一生产者) -> APP (唯一消费者)
4. SPSC 无需 CAS 操作，性能最优

**注意**: `FF_MULTI_SC` 模式下，每个 worker 有独立的 sc 和 ring zone，仍满足 SPSC 约束。

---

## 附录 A: 信号量相关代码位置索引（完整）

以下表格列出所有需要在 `FF_USE_RING_IPC` 条件编译中处理的代码位置：

### A.1 直接信号量 API 调用

| 文件 | 行号 | 代码 | 处理方式 |
|------|------|------|---------|
| `ff_so_zone.c` | 101 | `sem_init(&sc->wait_sem, 1, 0)` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 557 | `sem_post(&sc->wait_sem)` | 替换为 `ff_ring_send_response()` |
| `ff_hook_syscall.c` | 2265 | `sem_timedwait(&sc->wait_sem, &abs_timeout)` | 替换为 `ff_ring_dequeue_wait()` |
| `ff_hook_syscall.c` | 2270 | `sem_wait(&sc->wait_sem)` | 替换为 `ff_ring_dequeue_wait()` |
| `ff_hook_syscall.c` | 2555 | `sem_timedwait(&sc->wait_sem, &abs_timeout)` | 替换为 `ff_ring_dequeue_wait()` |
| `ff_hook_syscall.c` | 2558 | `sem_wait(&sc->wait_sem)` | 替换为 `ff_ring_dequeue_wait()` |
| `ff_hook_syscall.c` | 3244 | `sem_post(&sc->wait_sem)` | 替换为 `ff_ring_alarm_wakeup()` |

### A.2 `sem_flag` 变量使用

| 文件 | 行号 | 代码 | 处理方式 |
|------|------|------|---------|
| `ff_socket_ops.c` | 20 | `static int sem_flag = 0;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 313 | `sem_flag = 1;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 317 | `sem_flag = 0;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 319 | `sem_flag = 1;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 329 | `sem_flag = 0;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 331 | `sem_flag = 1;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 362 | `sem_flag = 0;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 364 | `sem_flag = 1;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 551 | `if (sem_flag == 1 ...` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_socket_ops.c` | 555 | `if (sem_flag == 1)` | `#ifndef FF_USE_RING_IPC` 包裹 |

### A.3 `need_alarm_sem` 变量使用

| 文件 | 行号 | 代码 | 处理方式 |
|------|------|------|---------|
| `ff_hook_syscall.c` | 248 | `static int need_alarm_sem = 0;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_hook_syscall.c` | 2234 | `need_alarm_sem = 1;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_hook_syscall.c` | 2276 | `need_alarm_sem = 0;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_hook_syscall.c` | 2534 | `need_alarm_sem = 1;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_hook_syscall.c` | 2564 | `need_alarm_sem = 0;` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_hook_syscall.c` | 3242 | `if (need_alarm_sem == 1)` | `#ifndef FF_USE_RING_IPC` 包裹 |
| `ff_hook_syscall.c` | 3245 | `need_alarm_sem = 0;` | `#ifndef FF_USE_RING_IPC` 包裹 |

### A.4 Zone Lock 宏使用（APP 侧关键路径）

| 文件 | 行号 | 代码 | Ring 模式影响 |
|------|------|------|-------------|
| `ff_hook_syscall.c` | 大量 | `SYSCALL(...)` 宏调用 | 通过宏替换自动适配 |
| `ff_hook_syscall.c` | 2078 | `ACQUIRE_ZONE_LOCK(FF_SC_IDLE)` (POLLING epoll_wait) | 通过宏替换自动适配 |
| `ff_hook_syscall.c` | 2095 | `ACQUIRE_ZONE_TRY_LOCK(FF_SC_REP)` (POLLING epoll_wait) | 通过宏替换自动适配 |
| `ff_hook_syscall.c` | 2218 | `ACQUIRE_ZONE_LOCK(FF_SC_IDLE)` (sem epoll_wait) | 通过宏替换自动适配 |
| `ff_hook_syscall.c` | 2515 | `ACQUIRE_ZONE_LOCK(FF_SC_IDLE)` (kevent) | 特殊处理（kevent 有手动 lock/unlock） |
| `ff_hook_syscall.c` | 2812 | `ACQUIRE_ZONE_LOCK(FF_SC_IDLE)` (select) | 通过宏替换自动适配 |
| `ff_hook_syscall.c` | 2829 | `ACQUIRE_ZONE_TRY_LOCK(FF_SC_REP)` (select) | 通过宏替换自动适配 |

---

## 附录 B: Ring 相关 DPDK API 参考

### B.1 Ring 创建

```c
struct rte_ring *
rte_ring_create(const char *name, unsigned int count,
                int socket_id, unsigned int flags);

/* flags 选项 */
#define RING_F_SP_ENQ  0x0001   /* 单生产者入队 */
#define RING_F_SC_DEQ  0x0002   /* 单消费者出队 */

/* 使用示例 */
struct rte_ring *req_ring = rte_ring_create(
    "ff_sc_req_ring_0",
    FF_RING_SIZE,                        /* 64 */
    rte_socket_id(),
    RING_F_SP_ENQ | RING_F_SC_DEQ       /* SPSC */
);
```

### B.2 Ring 入队/出队

```c
/* 单生产者入队（不用 CAS） */
static inline int
rte_ring_sp_enqueue(struct rte_ring *r, void *obj);

/* 单消费者出队（不用 CAS） */
static inline int
rte_ring_sc_dequeue(struct rte_ring *r, void **obj_p);

/* 返回值: 0 = 成功, -ENOBUFS = ring 满, -ENOENT = ring 空 */
```

### B.3 Ring 查找（跨进程）

```c
/* Secondary 进程通过名称查找已创建的 ring */
struct rte_ring *
rte_ring_lookup(const char *name);
```

### B.4 TSC 时钟

```c
/* 读取 TSC 计数器 */
static inline uint64_t rte_rdtsc(void);

/* 获取 TSC 频率 (Hz) */
uint64_t rte_get_tsc_hz(void);
```
