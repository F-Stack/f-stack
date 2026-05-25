#ifndef _FF_SOCKET_OPS_H_
#define _FF_SOCKET_OPS_H_

#include <unistd.h>

#ifdef FF_USE_RING_IPC
#include <rte_ring.h>
#include <rte_cycles.h>
#else
#include <semaphore.h>
#endif

#include <rte_atomic.h>
#include <rte_spinlock.h>

/* Compile-time mutual exclusion check */
#if defined(FF_USE_RING_IPC) && defined(FF_PRELOAD_POLLING_MODE)
#error "FF_USE_RING_IPC and FF_PRELOAD_POLLING_MODE are mutually exclusive"
#endif

/*
 * Per thread separate initialization dpdk lib and attach sc when needed,
 * such as listen same port in different threads, and socket can use in own thread.
 *
 * Otherwise, one socket can use in all threads.
 */
#ifdef FF_THREAD_SOCKET
#define __FF_THREAD __thread
#else
#define __FF_THREAD
#endif

#define ERR_LOG(fmt, ...)  do { \
        printf("file:%s, line:%u, fun:%s, pid:%d, "fmt, \
            __FILE__, __LINE__, __func__, getpid(), ##__VA_ARGS__); \
    } while (0)

#ifdef NDEBUG
#define DEBUG_LOG(...)
#else
#define DEBUG_LOG ERR_LOG
#endif

/* Must be power of 2 */
#define SOCKET_OPS_CONTEXT_MAX_NUM (1 << 5)

enum FF_SOCKET_OPS {
    FF_SO_SOCKET,
    FF_SO_LISTEN,
    FF_SO_BIND,
    FF_SO_CONNECT,
    FF_SO_SHUTDOWN,
    FF_SO_GETSOCKNAME,
    FF_SO_GETPEERNAME,
    FF_SO_GETSOCKOPT,
    FF_SO_SETSOCKOPT,
    FF_SO_ACCEPT,
    FF_SO_ACCEPT4, // 10
    FF_SO_RECV,
    FF_SO_RECVFROM,
    FF_SO_RECVMSG,
    FF_SO_READ,
    FF_SO_READV,
    FF_SO_SEND,
    FF_SO_SENDTO,
    FF_SO_SENDMSG,
    FF_SO_WRITE,
    FF_SO_WRITEV, // 20
    FF_SO_CLOSE,
    FF_SO_IOCTL,
    FF_SO_FCNTL,
    FF_SO_EPOLL_CREATE,
    FF_SO_EPOLL_CTL,
    FF_SO_EPOLL_WAIT,
    FF_SO_KQUEUE,
    FF_SO_KEVENT,
    FF_SO_FORK, // 29
    FF_SO_REGISTER_APPLICATION,
    FF_SO_EXIT_APPLICATION,
    FF_SO_SELECT,
};

enum FF_SO_CONTEXT_STATUS {
    FF_SC_IDLE,
    FF_SC_REQ,
    FF_SC_REP,
};

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
    struct ff_sc_ring_zone *ring_zone;
    uint8_t padding[8];
#else
    uint8_t padding[16];
#endif
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));

struct ff_so_context {
    /* CACHE LINE 0 */
    enum FF_SOCKET_OPS ops;
    enum FF_SO_CONTEXT_STATUS status;
    void *args;

    rte_spinlock_t lock;

    /* errno if failed */
    int error;
    /* result of ops processing */
    int result;
    int idx;

#ifdef FF_USE_RING_IPC
    /* Replace sem_t wait_sem (32B) with ring IPC fields */
    volatile uint32_t completion;     /*  4B, offset 32 — atomic completion flag */
    uint32_t ring_zone_id;            /*  4B, offset 36 — associated ring zone index */
    uint8_t reserved[24];             /* 24B, offset 40 — keep cache line 0 = 64B */
#else
    sem_t wait_sem; /* 32 bytes */
#endif

    /* CACHE LINE 1 */
    /* listen fd, refcount.. */
    int refcount;
    void *ff_thread_handle;
    volatile int forking;
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));

#ifdef FF_USE_RING_IPC
/*
 * Ring IPC configuration defaults.
 */
#ifndef FF_RING_SIZE
#define FF_RING_SIZE 64
#endif

#define FF_RING_WAIT_BUSY_POLL  0
#define FF_RING_WAIT_YIELD_POLL 1
#define FF_RING_WAIT_EVENTFD    2

#ifndef FF_RING_DEFAULT_WAIT_MODE
#define FF_RING_DEFAULT_WAIT_MODE FF_RING_WAIT_YIELD_POLL
#endif

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
    uint8_t wait_mode;            /* 0=busy-poll, 1=yield-poll, 2=eventfd */
    int eventfd_req;              /* eventfd: APP->fstack notify (wait_mode==2 only) */
    int eventfd_rsp;              /* eventfd: fstack->APP notify (wait_mode==2 only) */
    uint8_t padding[32];          /* pad to 64B cache line */
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));

/* Ring zone lifecycle — primary process */
int ff_create_sc_ring_zone(int proc_id, uint32_t ring_size, uint8_t wait_mode);
/* Ring zone lifecycle — secondary process */
struct ff_sc_ring_zone *ff_attach_sc_ring_zone(int proc_id);

/* APP side: submit request and wait for response */
int ff_ring_submit_and_wait(struct ff_sc_ring_zone *ring_zone,
                            struct ff_so_context *sc,
                            int64_t timeout_us);

/* fstack side: batch dequeue and process requests */
uint16_t ff_ring_process_requests(struct ff_sc_ring_zone *ring_zone,
                                  void (*handler)(struct ff_so_context *),
                                  uint16_t max_burst);

/* fstack side: enqueue processed response */
int ff_ring_send_response(struct ff_sc_ring_zone *ring_zone,
                          struct ff_so_context *sc);

/* Replace alarm_event_sem: wakeup APP via ring */
void ff_ring_alarm_wakeup(struct ff_sc_ring_zone *ring_zone,
                          struct ff_so_context *sc);

/* Timeout-aware ring dequeue */
int ff_ring_dequeue_wait(struct rte_ring *ring, void **obj_p,
                         int64_t timeout_us, uint8_t wait_mode);
#endif /* FF_USE_RING_IPC */

extern __FF_THREAD struct ff_socket_ops_zone *ff_so_zone;
#ifdef FF_MULTI_SC
extern struct ff_socket_ops_zone *ff_so_zones[SOCKET_OPS_CONTEXT_MAX_NUM];
#endif

/* For primary process */
int ff_set_max_so_context(uint16_t count);
int ff_create_so_memzone();
void ff_handle_each_context();

/* For secondary process */
struct ff_so_context *ff_attach_so_context(int proc_id);
void ff_detach_so_context(struct ff_so_context *context);

#endif
