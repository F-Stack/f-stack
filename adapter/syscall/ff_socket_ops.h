#ifndef _FF_SOCKET_OPS_H_
#define _FF_SOCKET_OPS_H_

#include <unistd.h>
#include <semaphore.h>

#include <rte_atomic.h>
#include <rte_spinlock.h>

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

    uint8_t padding[16];
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

    sem_t wait_sem; /* 32 bytes */

    /* CACHE LINE 1 */
    /* listen fd, refcount.. */
    int refcount;
} __attribute__((aligned(RTE_CACHE_LINE_SIZE)));

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
