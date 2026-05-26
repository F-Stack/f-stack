# F-Stack LD_PRELOAD Lock-Free Ring Queue Transformation — Interface Specification

> **Document ID**: SPEC-003  
> **Version**: v1.0 Draft  
> **Date**: 2026-03-27  
> **Status**: Pending Review  
> **Prerequisite Documents**: SPEC-001 Requirements Specification, SPEC-002 Architecture Design Document

---

## 1. Overview

This document defines all interface changes involved in migrating from the semaphore (`sem_t`) synchronization mechanism to the DPDK `rte_ring` lock-free ring queue scheme, including:

- New data structure definitions
- Modified existing data structures
- New / modified function signatures
- New / modified macro definitions
- Precise modification point mapping for each source file
- Compile macro strategy
- Error code definitions

All changes are controlled by the compile macro `FF_USE_RING_IPC`, ensuring coexistence with the existing semaphore scheme and enabling gradual migration.

---

## 2. Compile Macro Definitions

### 2.1 New Compile Macros

| Macro Name | Default Value | Description |
|--------|--------|------|
| `FF_USE_RING_IPC` | Undefined (default uses sem scheme) | Enable rte_ring lock-free IPC mode |
| `FF_RING_SIZE` | `64` | Capacity of each ring (must be power of 2) |
| `FF_RING_WAIT_BUSY_POLL` | `0` | Wait strategy: busy polling |
| `FF_RING_WAIT_YIELD_POLL` | `1` | Wait strategy: yield-CPU polling |
| `FF_RING_WAIT_EVENTFD` | `2` | Wait strategy: eventfd notification |
| `FF_RING_DEFAULT_WAIT_MODE` | `FF_RING_WAIT_YIELD_POLL` | Default wait strategy |
| `FF_RING_TIMEOUT_TSC_US` | `1` | rte_rdtsc timeout precision (microseconds) |

### 2.2 Existing Compile Macro Changes

| Macro Name | Change Description |
|--------|----------|
| `FF_PRELOAD_POLLING_MODE` | When `FF_USE_RING_IPC` is enabled, this macro's semantics are absorbed by ring busy-poll mode; the two are mutually exclusive and cannot be defined simultaneously |

### 2.3 Mutual Exclusion Check (Compile-time)

```c
/* New addition in ff_socket_ops.h */
#if defined(FF_USE_RING_IPC) && defined(FF_PRELOAD_POLLING_MODE)
#error "FF_USE_RING_IPC and FF_PRELOAD_POLLING_MODE are mutually exclusive"
#endif
```

---

## 3. New Data Structures

### 3.1 `struct ff_sc_ring_zone` — Ring Zone Structure

**File**: `ff_socket_ops.h` (new definition)

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
    struct rte_ring *req_ring;    /* APP -> fstack request queue (SPSC) */
    struct rte_ring *rsp_ring;    /* fstack -> APP response queue (SPSC) */
    uint32_t ring_size;           /* ring capacity (power of 2, default 64) */
    uint8_t wait_mode;            /* wait strategy: 0=busy-poll, 1=yield-poll, 2=eventfd */
    int eventfd_req;              /* eventfd: APP->fstack notification (only when wait_mode==2) */
    int eventfd_rsp;              /* eventfd: fstack->APP notification (only when wait_mode==2) */
    uint8_t padding[32];          /* align to 64-byte cache line */
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));
```

**Field Description**:

| Field | Type | Size | Description |
|------|------|------|------|
| `req_ring` | `struct rte_ring *` | 8B | Request ring queue pointer, created by `rte_ring_create()` on Hugepage |
| `rsp_ring` | `struct rte_ring *` | 8B | Response ring queue pointer, same as above |
| `ring_size` | `uint32_t` | 4B | Ring capacity, must be power of 2, default `FF_RING_SIZE`(64) |
| `wait_mode` | `uint8_t` | 1B | Wait strategy enumeration value |
| | (implicit alignment) | 3B | Compiler auto-aligns to 4-byte boundary |
| `eventfd_req` | `int` | 4B | eventfd file descriptor, only effective when `wait_mode == FF_RING_WAIT_EVENTFD` |
| `eventfd_rsp` | `int` | 4B | Same as above, for response direction |
| `padding` | `uint8_t[]` | 32B | Padding to align to 64-byte cache line |

**Total Size**: 64 bytes (1 cache line, consistent with §14.2 layout)

### 3.2 Ring Naming Convention

```c
/* New addition in ff_so_zone.c */
#define FF_SC_REQ_RING_NAME "ff_sc_req_ring_%d"   /* %d = proc_id */
#define FF_SC_RSP_RING_NAME "ff_sc_rsp_ring_%d"   /* %d = proc_id */
#define FF_SC_RING_ZONE_NAME "ff_sc_ring_zone_%d"  /* %d = proc_id */
```

---

## 4. Modified Data Structures

### 4.1 `struct ff_so_context` — Modification Plan

**File**: `ff_socket_ops.h`, lines 97-118

**Current definition**:

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

**Modified definition** (when `FF_USE_RING_IPC` is enabled):

```c
struct ff_so_context {
    /* CACHE LINE 0 */
    enum FF_SOCKET_OPS ops;               /*  4B, offset  0 */
    enum FF_SO_CONTEXT_STATUS status;     /*  4B, offset  4 */
    void *args;                           /*  8B, offset  8 */

#ifdef FF_USE_RING_IPC
    rte_spinlock_t lock;                  /*  4B, offset 16 */
    int error;                            /*  4B, offset 20 */
    int result;                           /*  4B, offset 24 */
    int idx;                              /*  4B, offset 28 */
    /* Replace sem_t wait_sem (32B) with the following fields */
    volatile uint32_t completion;         /*  4B, offset 32 — atomic completion flag */
    uint32_t ring_zone_id;                /*  4B, offset 36 — associated ring zone index */
    uint8_t reserved[24];                 /* 24B, offset 40 — maintain cache line alignment */
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

**Change Summary**:

| Offset | Old Field | New Field (`FF_USE_RING_IPC`) | Size Change |
|--------|--------|---------------------------|---------|
| 32 | `sem_t wait_sem` (32B) | `volatile uint32_t completion` (4B) | -28B |
| 36 | — | `uint32_t ring_zone_id` (4B) | +4B |
| 40 | — | `uint8_t reserved[24]` (24B) | +24B |

**Summary**: Cache Line 0 layout remains 64 bytes, Cache Line 1 remains unchanged.

### 4.2 `struct ff_socket_ops_zone` — Modification Plan

**File**: `ff_socket_ops.h`, lines 78-95

**New fields**:

```c
struct ff_socket_ops_zone {
    rte_spinlock_t lock;
    uint8_t count;
    uint8_t mask;
    uint8_t free;
    uint8_t idx;
    uint8_t inuse[SOCKET_OPS_CONTEXT_MAX_NUM];
    struct ff_so_context *sc;

#ifdef FF_USE_RING_IPC
    struct ff_sc_ring_zone *ring_zone;     /* New: pointer to associated ring zone */
#endif

    uint8_t padding[16];
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));
```

**Note**: `padding` size may need adjustment to accommodate the new `ring_zone` pointer (8 bytes).

---

## 5. New Function Signatures

### 5.1 Ring Zone Lifecycle Management

**File**: `ff_socket_ops.h` (declarations), `ff_so_zone.c` (implementation)

```c
#ifdef FF_USE_RING_IPC
int ff_create_sc_ring_zone(int proc_id, uint32_t ring_size, uint8_t wait_mode);
struct ff_sc_ring_zone *ff_attach_sc_ring_zone(int proc_id);
#endif
```

### 5.2 Ring IPC Operations

**File**: `ff_socket_ops.h` (declarations)

```c
#ifdef FF_USE_RING_IPC
int ff_ring_submit_and_wait(struct ff_sc_ring_zone *ring_zone,
                            struct ff_so_context *sc,
                            int64_t timeout_us);

uint16_t ff_ring_process_requests(struct ff_sc_ring_zone *ring_zone,
                                  void (*handler)(struct ff_so_context *),
                                  uint16_t max_burst);

int ff_ring_send_response(struct ff_sc_ring_zone *ring_zone,
                          struct ff_so_context *sc);

void ff_ring_alarm_wakeup(struct ff_sc_ring_zone *ring_zone,
                          struct ff_so_context *sc);
#endif
```

### 5.3 Timeout Wait Helper Functions

```c
#ifdef FF_USE_RING_IPC
int ff_ring_dequeue_wait(struct rte_ring *ring, void **obj_p,
                         int64_t timeout_us, uint8_t wait_mode);
#endif
```

---

## 6. Modified Function Signatures

### 6.1 `ff_handle_each_context()` — fstack-Side Polling Transformation

**File**: `ff_socket_ops.c`, lines 569-638

Signature unchanged, internal implementation branches:

```c
void ff_handle_each_context(void)
{
#ifdef FF_USE_RING_IPC
    ff_ring_process_requests(ff_so_zone->ring_zone,
                             ff_handle_socket_ops_ring, FF_RING_SIZE);
#else
    // ... existing code remains unchanged ...
#endif
}
```

### 6.2 `ff_handle_socket_ops()` — New Ring Mode Variant

```c
#ifdef FF_USE_RING_IPC
static void ff_handle_socket_ops_ring(struct ff_so_context *sc);
#endif
```

### 6.3 `ff_create_so_memzone()` — Internal Changes

Under ring mode: skip `sem_init`, call `ff_create_sc_ring_zone()`, initialize `sc->completion = 0` and `sc->ring_zone_id`.

### 6.4 `alarm_event_sem()` — Signal Wakeup Replacement

```c
void alarm_event_sem(void)
{
#ifndef FF_THREAD_SOCKET
#ifdef FF_USE_RING_IPC
    if (ff_so_zone && ff_so_zone->ring_zone)
        ff_ring_alarm_wakeup(ff_so_zone->ring_zone, sc);
#else
    // ... existing code remains unchanged ...
#endif
#endif
}
```

---

## 7. Modified Macro Definitions

### 7.1 `ACQUIRE_ZONE_LOCK` — Ring Mode Replacement

**File**: `ff_hook_syscall.c`, lines 114-126

```c
#ifdef FF_USE_RING_IPC
#define ACQUIRE_ZONE_LOCK(exp) do {                               \
    while (__atomic_load_n(&sc->completion, __ATOMIC_ACQUIRE) != (exp)) { \
        rte_pause();                                              \
    }                                                             \
} while (0)
#else
/* Original code remains unchanged */
#endif
```

### 7.2 `ACQUIRE_ZONE_TRY_LOCK` — Ring Mode Replacement

```c
#ifdef FF_USE_RING_IPC
#define ACQUIRE_ZONE_TRY_LOCK(exp) ACQUIRE_ZONE_LOCK(exp)
#else
/* Original code remains unchanged */
#endif
```

### 7.3 `RELEASE_ZONE_LOCK` — Ring Mode Replacement

```c
#ifdef FF_USE_RING_IPC
#define RELEASE_ZONE_LOCK(s) do {                                 \
    __atomic_store_n(&sc->status, (s), __ATOMIC_RELEASE);         \
} while (0)
#else
/* Original code remains unchanged */
#endif
```

### 7.4 `SYSCALL` — Ring Mode Rewrite

```c
#ifdef FF_USE_RING_IPC
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
/* Original code remains unchanged */
#endif
```

---

## 8. Precise Modification Point Mapping Per Source File

### 8.1 `ff_socket_ops.h` — Header File

| Line | Current Content | Modification Type | Description |
|------|---------|---------|---------|
| 5 | `#include <semaphore.h>` | Conditional wrap | Retained under `#ifndef FF_USE_RING_IPC`; replaced with `#include <rte_ring.h>` under `#ifdef` |
| 7-8 | `#include <rte_atomic.h>` / `<rte_spinlock.h>` | Retain | Ring mode still needs these headers |
| 72-76 | `enum FF_SO_CONTEXT_STATUS` | Retain | Status enum still used for `completion` flag |
| 78-95 | `struct ff_socket_ops_zone` | Add field | `#ifdef FF_USE_RING_IPC` add `ring_zone` pointer |
| 97-118 | `struct ff_so_context` | Conditional replace | `sem_t wait_sem` replaced with `completion` + `ring_zone_id` + `reserved` |
| After 118 | — | Add | `struct ff_sc_ring_zone` definition |
| 126-132 | Function declarations | Add | Ring-related function declarations (see §5) |

### 8.2 `ff_so_zone.c` — Shared Memory Zone Initialization

| Line | Current Content | Modification Type | Description |
|------|---------|---------|---------|
| 1-8 | `#include` area | Add | Ring-related includes under `#ifdef FF_USE_RING_IPC` |
| 10-13 | Macro definitions | Add | Ring name macros |
| 55-128 | `ff_create_so_memzone()` | Conditional branch | Skip `sem_init`, call `ff_create_sc_ring_zone()` |
| 101-104 | `sem_init(&sc->wait_sem, 1, 0)` | Conditional skip | Wrapped with `#ifndef FF_USE_RING_IPC` |
| After 128 | — | Add | `ff_create_sc_ring_zone()` and `ff_attach_sc_ring_zone()` implementations |

### 8.3 `ff_socket_ops.c` — fstack-Side Processing Logic

| Line | Current Content | Modification Type | Description |
|------|---------|---------|---------|
| 19-20 | `static int sem_flag = 0;` | Conditional compilation | Wrapped with `#ifndef FF_USE_RING_IPC` |
| 308-365 | sem_flag assignments | Conditional compilation | Wrapped with `#ifndef FF_USE_RING_IPC` |
| 502-567 | `ff_handle_socket_ops()` | Add variant | New `ff_handle_socket_ops_ring()` |
| 557 | `sem_post(&sc->wait_sem);` | Replace | `ff_ring_send_response(ring_zone, sc)` |
| 569-638 | `ff_handle_each_context()` | Rewrite | `ff_ring_process_requests()` replaces O(n) traversal |
| After 638 | — | Add | Ring function implementations |

### 8.4 `ff_hook_syscall.c` — APP-Side Hook Functions

| Line | Current Content | Modification Type | Description |
|------|---------|---------|---------|
| 1-22 | `#include` area | Add | Ring-related includes |
| 114-160 | Lock/Syscall macros | Conditional rewrite | Ring mode replacements (see §7) |
| 248 | `need_alarm_sem` | Conditional compilation | `#ifndef FF_USE_RING_IPC` |
| 2148-2337 | epoll_wait implementation | Conditional modification | Ring mode rewrites sem_wait |
| 2265/2270 | `sem_timedwait`/`sem_wait` | Replace | `ff_ring_dequeue_wait()` |
| 2515-2585 | kevent implementation | Conditional modification | Ring mode rewrites sem_wait |
| 2555/2558 | `sem_timedwait`/`sem_wait` | Replace | `ff_ring_dequeue_wait()` |
| 3235-3252 | `alarm_event_sem()` | Conditional rewrite | `ff_ring_alarm_wakeup()` |

### 8.5 `ff_adapter.h`, `fstack.c`, `main_stack*.c`

No signature changes needed. `alarm_event_sem()` declaration retained; internal implementation branches. `fstack.c` calls unchanged. Example programs unchanged.

### 8.6 `Makefile` — Build Configuration

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

## 9. New Header Include Relationships

### 9.1 `ff_socket_ops.h`

```c
#ifdef FF_USE_RING_IPC
#include <rte_ring.h>
#else
#include <semaphore.h>
#endif
#include <rte_atomic.h>
#include <rte_spinlock.h>
```

### 9.2 `ff_so_zone.c`

```c
#ifdef FF_USE_RING_IPC
#include <rte_ring.h>
#include <rte_memzone.h>
#endif
```

### 9.3 `ff_socket_ops.c`

```c
#ifdef FF_USE_RING_IPC
#include <rte_ring.h>
#endif
```

### 9.4 `ff_hook_syscall.c`

```c
#ifdef FF_USE_RING_IPC
#include <rte_ring.h>
#include <rte_cycles.h>     /* rte_rdtsc, rte_get_tsc_hz */
#include <sys/eventfd.h>    /* eventfd (eventfd mode only) */
#endif
```

---

## 10. Error Code Definitions

Ring operations reuse standard POSIX errno values:

| Scenario | errno | Description |
|------|-------|------|
| Ring creation failure | `ENOMEM` | rte_ring_create returns NULL |
| Ring full (enqueue failure) | `ENOSPC` | rte_ring_enqueue returns -ENOBUFS |
| Ring wait timeout | `ETIMEDOUT` | ff_ring_dequeue_wait timed out |
| Ring zone lookup failure | `ENOENT` | rte_memzone_lookup returns NULL |
| Compile macro conflict | Compilation error | `FF_USE_RING_IPC` and `FF_PRELOAD_POLLING_MODE` defined simultaneously |

---

## 11. `ff_ring_submit_and_wait` Detailed Implementation Specification

### 11.1 Algorithm Flow

```
ff_ring_submit_and_wait(ring_zone, sc, timeout_us):
    1. Set sc->completion = FF_SC_REQ
    2. rte_ring_sp_enqueue(ring_zone->req_ring, sc)
       - If failed (ring full), spin retry
    3. If wait_mode == eventfd:
       - Optional: write(eventfd_req, 1) to notify fstack
    4. Wait for response:
       a. busy-poll:  while dequeue fails, rte_pause + check timeout
       b. yield-poll: same + sched_yield() after N iterations
       c. eventfd:    poll/epoll_wait(eventfd_rsp) + dequeue
    5. Return 0 (success) or -ETIMEDOUT (timeout)
```

### 11.2 Timeout Calculation

```c
uint64_t tsc_hz = rte_get_tsc_hz();
uint64_t timeout_tsc = (timeout_us > 0)
    ? (uint64_t)timeout_us * tsc_hz / 1000000ULL
    : UINT64_MAX;  /* -1 = forever */
uint64_t start_tsc = rte_rdtsc();

while (rte_ring_sc_dequeue(ring, &obj) != 0) {
    if (rte_rdtsc() - start_tsc >= timeout_tsc)
        return -ETIMEDOUT;
    /* wait_mode strategy */
    switch (wait_mode) {
        case FF_RING_WAIT_BUSY_POLL:  rte_pause(); break;
        case FF_RING_WAIT_YIELD_POLL:
            if ((++spin_count & 0xFF) == 0) sched_yield();
            else rte_pause();
            break;
        case FF_RING_WAIT_EVENTFD: /* eventfd poll */ break;
    }
}
```

---

## 12. `ff_ring_process_requests` Detailed Implementation Specification

### 12.1 Algorithm Flow

```
ff_ring_process_requests(ring_zone, handler, max_burst):
    processed = 0
    while (processed < max_burst):
        ret = rte_ring_sc_dequeue(ring_zone->req_ring, &obj)
        if (ret != 0): break  /* ring empty */
        sc = (struct ff_so_context *)obj
        handler(sc)
        processed++
    return processed
```

### 12.2 fstack-Side Processing Callback

```c
static void
ff_handle_socket_ops_ring(struct ff_so_context *sc)
{
    errno = 0;
#ifdef FF_USE_THREAD_STRUCT_HANDLE
    void *old_thread = NULL;
    if (sc->ff_thread_handle)
        old_thread = ff_switch_curthread(sc->ff_thread_handle);
#endif
    sc->result = ff_so_handler(sc->ops, sc->args);
#ifdef FF_USE_THREAD_STRUCT_HANDLE
    if (sc->ff_thread_handle)
        ff_restore_curthread(old_thread);
#endif
    sc->error = errno;
    ff_ring_send_response(ff_so_zone->ring_zone, sc);
}
```

---

## 13. epoll_wait / kevent Special Handling

### 13.1 epoll_wait (Ring Mode)

**File**: `ff_hook_syscall.c`, lines 2148-2337

```c
#ifdef FF_USE_RING_IPC
int ff_hook_epoll_wait(int epfd, struct epoll_event *events,
    int maxevents, int timeout)
{
    // ... parameter preparation (same as original) ...
    int64_t timeout_us;
    if (timeout < 0) timeout_us = -1;
    else if (timeout == 0) timeout_us = 0;
    else timeout_us = (int64_t)timeout * 1000;  /* ms -> us */

RETRY:
    sc->ops = FF_SO_EPOLL_WAIT;
    sc->args = args;
    ret = ff_ring_submit_and_wait(ff_so_zone->ring_zone, sc, timeout_us);

    if (ret == -ETIMEDOUT) ret = 0;
    else { ret = sc->result; if (ret < 0) errno = sc->error; }

    if (likely(ret > 0))
        rte_memcpy(events, sh_events, sizeof(struct epoll_event) * ret);
    if (timeout < 0 && ret == 0) { rte_pause(); goto RETRY; }
    RETURN_NOFREE();
}
#endif
```

### 13.2 kevent (Ring Mode)

kevent transformation follows the same pattern as epoll_wait:
- Convert timeout: `if (timeout == NULL) timeout_us = -1; else timeout_us = timeout->tv_sec * 1000000 + timeout->tv_nsec / 1000;`
- Replace sem_timedwait/sem_wait with `ff_ring_submit_and_wait`
- Remove `need_alarm_sem` assignments
- Remove `rte_spinlock_lock/unlock`

---

## 14. Memory Layout Verification

### 14.1 `ff_so_context` Layout Check

```
Ring mode ff_so_context memory layout:
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

### 14.2 `ff_sc_ring_zone` Layout Check

```
ff_sc_ring_zone memory layout:
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
Total: 64 bytes (1 cache line, aligned)
```

---

## 15. Interface Compatibility Matrix

| Interface / Function | sem mode | ring mode | External Signature Change |
|-------------|---------|-----------|-------------|
| `ff_create_so_memzone()` | ✅ | ✅ (internally creates ring) | None |
| `ff_attach_so_context()` | ✅ | ✅ (attaches ring ref) | None |
| `ff_detach_so_context()` | ✅ | ✅ (cleans ring ref) | None |
| `ff_handle_each_context()` | ✅ | ✅ (ring dequeue) | None |
| `alarm_event_sem()` | ✅ | ✅ (ring wakeup) | None |
| `SYSCALL(op, arg)` macro | ✅ | ✅ (ring submit) | None (macro) |
| `ff_hook_epoll_wait()` | ✅ | ✅ (ring timeout) | None |
| `kevent()` | ✅ | ✅ (ring timeout) | None |
| `ff_hook_socket()` | ✅ | ✅ (via SYSCALL) | None |
| All other `ff_hook_*()` | ✅ | ✅ (via SYSCALL) | None |

---

## 16. Key Design Decision Records

### D-001: Why Retain `rte_spinlock_t lock` Field

**Decision**: Retain `sc->lock` field in ring mode but don't use it in regular request path.

**Rationale**:
1. `ff_detach_so_context()` needs both zone->lock and sc->lock simultaneously
2. `ff_hook_fork()` needs sc->lock to protect state consistency during fork
3. Maintains binary-compatible structure layout for gradual migration

### D-002: Ring Queue Passes Pointers, Not Data Copies

**Decision**: `rte_ring` enqueues/dequeues `ff_so_context *` pointers.

**Rationale**:
1. `ff_so_context` is already in Hugepage shared memory, no copy needed
2. Pointer passing is zero-copy, 8-byte atomic operation
3. Consistent with existing architecture (sc is already cross-process shared)

### D-003: Why Not Remove `status` Field

**Decision**: Retain `enum FF_SO_CONTEXT_STATUS status` field.

**Rationale**:
1. `status` is used for human-readable state output in debug logging
2. `completion` field uses atomic operations; `status` can be set non-atomically for debugging
3. Still needed for status checks during fork, detach, and other lifecycle operations

### D-004: SPSC Mode Correctness Guarantee

**Decision**: Both rings use SPSC mode (`RING_F_SP_ENQ | RING_F_SC_DEQ`).

**Rationale**:
1. APP process and fstack instance are 1:1 bound (one sc used by only one APP thread)
2. Request ring: APP (sole producer) -> fstack (sole consumer)
3. Response ring: fstack (sole producer) -> APP (sole consumer)
4. SPSC requires no CAS operations, optimal performance

**Note**: Under `FF_MULTI_SC` mode, each worker has independent sc and ring zone, still satisfying SPSC constraints.

---

## Appendix A: Complete Semaphore Code Location Index

### A.1 Direct Semaphore API Calls

| File | Line | Code | Handling |
|------|------|------|---------|
| `ff_so_zone.c` | 101 | `sem_init(&sc->wait_sem, 1, 0)` | Wrapped with `#ifndef FF_USE_RING_IPC` |
| `ff_socket_ops.c` | 557 | `sem_post(&sc->wait_sem)` | Replace with `ff_ring_send_response()` |
| `ff_hook_syscall.c` | 2265 | `sem_timedwait(...)` | Replace with `ff_ring_dequeue_wait()` |
| `ff_hook_syscall.c` | 2270 | `sem_wait(...)` | Replace with `ff_ring_dequeue_wait()` |
| `ff_hook_syscall.c` | 2555 | `sem_timedwait(...)` | Replace with `ff_ring_dequeue_wait()` |
| `ff_hook_syscall.c` | 2558 | `sem_wait(...)` | Replace with `ff_ring_dequeue_wait()` |
| `ff_hook_syscall.c` | 3244 | `sem_post(...)` | Replace with `ff_ring_alarm_wakeup()` |

### A.2 `sem_flag` Variable Usage

All `sem_flag` related code in `ff_socket_ops.c` (lines 20, 313, 317, 319, 329, 331, 362, 364, 551, 555) wrapped with `#ifndef FF_USE_RING_IPC`.

### A.3 `need_alarm_sem` Variable Usage

All `need_alarm_sem` related code in `ff_hook_syscall.c` (lines 248, 2234, 2276, 2534, 2564, 3242, 3245) wrapped with `#ifndef FF_USE_RING_IPC`.

### A.4 Zone Lock Macro Usage (APP-Side Critical Path)

All SYSCALL macro invocations and explicit ACQUIRE/RELEASE_ZONE_LOCK calls are automatically adapted through macro replacement.

---

## Appendix B: Ring-Related DPDK API Reference

### B.1 Ring Creation

```c
struct rte_ring *rte_ring_create(const char *name, unsigned int count,
                                 int socket_id, unsigned int flags);
/* flags: RING_F_SP_ENQ (0x0001) | RING_F_SC_DEQ (0x0002) */
```

### B.2 Ring Enqueue/Dequeue

```c
static inline int rte_ring_sp_enqueue(struct rte_ring *r, void *obj);
static inline int rte_ring_sc_dequeue(struct rte_ring *r, void **obj_p);
/* Return: 0 = success, -ENOBUFS = ring full, -ENOENT = ring empty */
```

### B.3 Ring Lookup (Cross-Process)

```c
struct rte_ring *rte_ring_lookup(const char *name);
```

### B.4 TSC Clock

```c
static inline uint64_t rte_rdtsc(void);
uint64_t rte_get_tsc_hz(void);
```
