#ifndef _FF_SOCKET_OPS_H_
#define _FF_SOCKET_OPS_H_

#include <semaphore.h>

#include <rte_atomic.h>
#include <rte_spinlock.h>

#define ERR_LOG(fmt, ...)  do { \
        printf("file:%s, line:%u, fun:%s, "fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)

#ifdef NDEBUG
#define DEBUG_LOG(...)
#else
#define DEBUG_LOG ERR_LOG
#endif

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
    FF_SO_ACCEPT4,
    FF_SO_RECV,
    FF_SO_RECVFROM,
    FF_SO_RECVMSG,
    FF_SO_READ,
    FF_SO_READV,
    FF_SO_SEND,
    FF_SO_SENDTO,
    FF_SO_SENDMSG,
    FF_SO_WRITE,
    FF_SO_WRITEV,
    FF_SO_CLOSE,
    FF_SO_IOCTL,
    FF_SO_FCNTL,
    FF_SO_EPOLL_CREATE,
    FF_SO_EPOLL_CTL,
    FF_SO_EPOLL_WAIT,
    FF_SO_KQUEUE,
    FF_SO_KEVENT,
    FF_SO_FORK,
};

enum FF_SO_CONTEXT_STATUS {
    FF_SC_IDLE,
    FF_SC_REQ,
    FF_SC_REP,
};

struct ff_socket_ops_zone {
    rte_spinlock_t lock;

    /* total number of so_contex */
    uint16_t count;

    /* free number of so_context */
    uint16_t free;

    struct ff_so_context *sc;
} __attribute__((packed));

struct ff_so_context {
    rte_spinlock_t lock;

    int status;

    sem_t wait_sem;

    enum FF_SOCKET_OPS ops;

    void *args;

    /* result of ops processing */
    ssize_t result;
    /* errno if failed */
    int error;

    /* 1 if used, else 0 */
    int inuse;

    // listen fd, refcount..
} __attribute__((packed));

extern struct ff_socket_ops_zone *ff_so_zone;

/* For primary process */
int ff_set_max_so_context(uint16_t count);
int ff_create_so_memzone();
void ff_handle_each_context();

/* For secondary process */
struct ff_so_context *ff_attach_so_context(int proc_id);
void ff_detach_so_context(struct ff_so_context *context);

#endif
