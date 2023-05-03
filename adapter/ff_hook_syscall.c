#include <assert.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "ff_config.h"
#include "ff_socket_ops.h"
#include "ff_sysproto.h"
#include "ff_event.h"
#include "ff_hook_syscall.h"
#include "ff_linux_syscall.h"
#include "ff_adapter.h"

/* Just for so, no used */
struct ff_config ff_global_cfg;

#define NS_PER_SECOND  1000000000

#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)  __builtin_expect((x),0)
#endif

#define strong_alias(name, aliasname) \
    extern __typeof (name) aliasname __attribute__ ((alias (#name)));

#undef FF_SYSCALL_DECL
#define FF_SYSCALL_DECL(ret, fn, args) strong_alias(ff_hook_##fn, fn)
#include <ff_declare_syscalls.h>

#define share_mem_alloc(size) rte_malloc(NULL, (size), 0)
#define share_mem_free(addr) rte_free((addr))

#define CHECK_FD_OWNERSHIP(name, args)                            \
{                                                                 \
    if (!is_fstack_fd(fd)) {                                      \
        return ff_linux_##name args;                              \
    }                                                             \
    fd = restore_fstack_fd(fd);                                   \
}

#define DEFINE_REQ_ARGS(name)                                     \
    struct ff_##name##_args *args;                                \
    int ret = -1;                                                 \
    size_t size = sizeof(struct ff_##name##_args);                \
    args = share_mem_alloc(size);                                 \
    if (args == NULL) {                                           \
        errno = ENOMEM;                                           \
        return ret;                                               \
    }

/* Always use __thread, but no __FF_THREAD */
static __thread struct ff_shutdown_args *shutdown_args = NULL;
static __thread struct ff_getsockname_args *getsockname_args = NULL;
static __thread struct ff_getpeername_args *getpeername_args = NULL;
static __thread struct ff_setsockopt_args *setsockopt_args = NULL;
static __thread struct ff_accept_args *accept_args = NULL;
static __thread struct ff_connect_args *connect_args = NULL;
static __thread struct ff_recvfrom_args *recvfrom_args = NULL;
static __thread struct ff_recvmsg_args *recvmsg_args = NULL;
static __thread struct ff_read_args *read_args = NULL;
static __thread struct ff_readv_args *readv_args = NULL;
static __thread struct ff_sendto_args *sendto_args = NULL;
static __thread struct ff_sendmsg_args *sendmsg_args = NULL;
static __thread struct ff_write_args *write_args = NULL;
static __thread struct ff_writev_args *writev_args = NULL;
static __thread struct ff_close_args *close_args = NULL;
static __thread struct ff_ioctl_args *ioctl_args = NULL;
static __thread struct ff_fcntl_args *fcntl_args = NULL;
static __thread struct ff_epoll_ctl_args *epoll_ctl_args = NULL;
static __thread struct ff_epoll_wait_args *epoll_wait_args = NULL;
static __thread struct ff_kevent_args *kevent_args = NULL;

#define IOV_MAX   16
#define IOV_LEN_MAX     2048

static __thread struct iovec *sh_iov_static = NULL;
static __thread void *sh_iov_static_base[IOV_MAX];
static __thread int sh_iov_static_fill_idx_local = 0;
static __thread int sh_iov_static_fill_idx_share = 0;

#define DEFINE_REQ_ARGS_STATIC(name)                              \
    int ret = -1;                                                 \
    struct ff_##name##_args *args = NULL;                         \
    if (name##_args == NULL) {                                    \
        size_t size = sizeof(struct ff_##name##_args);            \
        name##_args = share_mem_alloc(size);                      \
        if (name##_args == NULL) {                                \
            errno = ENOMEM;                                       \
            return ret;                                           \
        }                                                         \
    }                                                             \
    args = name##_args;

/* Dirty read first, and then try to lock sc and real read. */
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

#define RELEASE_ZONE_LOCK(s) do {                                 \
    sc->status = s;                                               \
    rte_spinlock_unlock(&sc->lock);                               \
} while (0)

/* NOTE: deadlock prone while fstack adapter run error */
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

#define RETURN_NOFREE() do {                                      \
    DEBUG_LOG("RETURN_NOFREE ret:%d, errno:%d\n", ret, errno);    \
    return ret;                                                   \
} while (0)

#define RETURN_ERROR_NOFREE(err) do {                             \
    errno = err;                                                  \
    DEBUG_LOG("RETURN_ERROR_NOFREE ret:%d, errno:%d\n", ret, errno); \
    return ret;                                                   \
} while (0)

#define RETURN() do {                                             \
    share_mem_free(args);                                         \
    DEBUG_LOG("RETURN ret:%d, errno:%d\n", ret, errno);           \
    return ret;                                                   \
} while (0)

#define RETURN_ERROR(err) do {                                    \
    errno = err;                                                  \
    share_mem_free(args);                                         \
    DEBUG_LOG("RETURN_ERROR ret:%d, errno:%d\n", ret, errno);     \
    return ret;                                                   \
} while (0)

static __FF_THREAD int inited = 0;
static __FF_THREAD struct ff_so_context *sc;

/*
 * For parent process socket/bind/listen multi sockets
 * and use them in different child process,
 * like Nginx with reuseport.
 */
#ifdef FF_MULTI_SC
typedef struct ff_multi_sc {
    int worker_id;
    int fd;
    struct ff_so_context *sc;
} ff_multi_sc_type;

static ff_multi_sc_type scs[SOCKET_OPS_CONTEXT_MAX_NUM];

/*
 * For child worker process,
 * All workers must be forked by the same process, scilicet
 * support master fork child1, [child1 fork child2], chilid2 fork worker1/worker2/worker3...
 * But not support master fork worker1, worker fork worker2, worker2 fork worker3...
 */
#define CURRENT_WORKER_ID_DEFAULT 0
static int current_worker_id = CURRENT_WORKER_ID_DEFAULT;
#endif

static pthread_key_t key;

#ifdef FF_KERNEL_EVENT
/* kern.maxfiles: 33554432 */
#define FF_MAX_FREEBSD_FILES 65536
int fstack_kernel_fd_map[FF_MAX_FREEBSD_FILES];
#endif

/* process-level initialization flag */
static int proc_inited = 0;

/* Use from lcore 2 by default, can set by environment variable FF_INITIAL_LCORE_ID */
#define INITIAL_LCORE_ID_DEFAULT 0x4             /* lcore 2 */
#define INITIAL_LCORE_ID_MAX 0x4000000000000     /* lcore 50 */
#define FF_INITIAL_LCORE_ID_STR "FF_INITIAL_LCORE_ID"
static uint64_t initial_lcore_id = INITIAL_LCORE_ID_DEFAULT;

#define WORKER_ID_DEFAULT 0
#define FF_PROC_ID_STR "FF_PROC_ID"
static int worker_id = WORKER_ID_DEFAULT;
rte_spinlock_t worker_id_lock;

/* The num of F-Stack process instance, default 1 */
#define NB_FSTACK_INSTANCE_DEFAULT   1
#define FF_NB_FSTACK_INSTANCE_STR "FF_NB_FSTACK_INSTANCE"
static int nb_procs = NB_FSTACK_INSTANCE_DEFAULT;

#define FF_KERNEL_MAX_FD_DEFAULT    1024
static int ff_kernel_max_fd = FF_KERNEL_MAX_FD_DEFAULT;

/* not support thread socket now */
static int need_alarm_sem = 0;

static inline int convert_fstack_fd(int sockfd) {
    return sockfd + ff_kernel_max_fd;
}

/* Restore socket fd. */
static inline int restore_fstack_fd(int sockfd) {
    if(sockfd < ff_kernel_max_fd) {
        return sockfd;
    }

    return sockfd - ff_kernel_max_fd;
}

int is_fstack_fd(int sockfd) {
    if (unlikely(inited == 0/* && ff_adapter_init() < 0*/)) {
        return 0;
    }

    /* FIXED ME: ff_linux_socket not limit fd < ff_kernel_max_fd, may be Misjudgment */
    return sockfd >= ff_kernel_max_fd;
}

int
fstack_territory(int domain, int type, int protocol)
{
    /* Remove creation flags */
    type &= ~SOCK_CLOEXEC;
    type &= ~SOCK_NONBLOCK;
    type &= ~SOCK_FSTACK;
    type &= ~SOCK_KERNEL;

    if ((AF_INET != domain && AF_INET6 != domain) || (SOCK_STREAM != type &&
        SOCK_DGRAM != type)) {
        return 0;
    }

    return 1;
}

/*
 * APP need set type |= SOCK_FSTACK
 */
int
ff_hook_socket(int domain, int type, int protocol)
{
    ERR_LOG("ff_hook_socket, domain:%d, type:%d, protocol:%d\n", domain, type, protocol);
    if (unlikely(fstack_territory(domain, type, protocol) == 0)) {
        return ff_linux_socket(domain, type, protocol);
    }

    if (unlikely(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)) {
        type &= ~SOCK_KERNEL;
        return ff_linux_socket(domain, type, protocol);
    }

    if (unlikely(inited == 0)) {
        if (ff_adapter_init() < 0) {
            return ff_linux_socket(domain, type, protocol);
        }
    }
#ifdef FF_MULTI_SC
    else {
        if (ff_adapter_init() < 0) {
            ERR_LOG("FF_MUTLI_SC ff_adapter_init failed\n");
            return -1;
        }
    }
#endif

    type &= ~SOCK_FSTACK;

    DEFINE_REQ_ARGS(socket);

    args->domain = domain;
    args->type = type;
    args->protocol = protocol;

    SYSCALL(FF_SO_SOCKET, args);

#ifdef FF_MULTI_SC
    scs[worker_id - 1].fd = ret;
#endif

    if (ret >= 0) {
        ret = convert_fstack_fd(ret);
    }

    ERR_LOG("ff_hook_socket return fd:%d\n", ret);

    RETURN();
}

int
ff_hook_bind(int fd, const struct sockaddr *addr,
    socklen_t addrlen)
{
    ERR_LOG("ff_hook_bind, fd:%d, addr:%p, addrlen:%d\n", fd, addr, addrlen);

    if (addr == NULL) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(bind, (fd, addr, addrlen));

    DEFINE_REQ_ARGS(bind);
    struct sockaddr *sh_addr = NULL;

    sh_addr = share_mem_alloc(addrlen);
    if (sh_addr == NULL) {
        RETURN_ERROR(ENOMEM);
    }
    rte_memcpy(sh_addr, addr, addrlen);

    args->fd = fd;
    args->addr = sh_addr;
    args->addrlen = addrlen;

    SYSCALL(FF_SO_BIND, args);

    share_mem_free(sh_addr);
    RETURN();
}

int
ff_hook_listen(int fd, int backlog)
{
    ERR_LOG("ff_hook_listen, fd:%d, backlog:%d\n", fd, backlog);

    CHECK_FD_OWNERSHIP(listen, (fd, backlog));

    DEFINE_REQ_ARGS(listen);

    args->fd = fd;
    args->backlog = backlog;

    SYSCALL(FF_SO_LISTEN, args);

    RETURN();
}

int
ff_hook_shutdown(int fd, int how)
{
    CHECK_FD_OWNERSHIP(shutdown, (fd, how));

    DEFINE_REQ_ARGS_STATIC(shutdown);

    args->fd = fd;
    args->how = how;

    SYSCALL(FF_SO_SHUTDOWN, args);

    RETURN_NOFREE();
}

int
ff_hook_getsockname(int fd, struct sockaddr *name,
    socklen_t *namelen)
{
    if (name == NULL || namelen == NULL) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(getsockname, (fd, name, namelen));

    DEFINE_REQ_ARGS_STATIC(getsockname);
    static __thread struct sockaddr *sh_name = NULL;
    static __thread socklen_t sh_name_len = 0;
    static __thread socklen_t *sh_namelen = NULL;

    if (sh_name == NULL || sh_name_len < *namelen) {
        if (sh_name) {
            share_mem_free(sh_name);
        }

        sh_name_len = *namelen;
        sh_name = share_mem_alloc(sh_name_len);
        if (sh_name == NULL) {
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }

    if (sh_namelen == NULL) {
        sh_namelen = share_mem_alloc(sizeof(socklen_t));
        if (sh_namelen == NULL) {
            //share_mem_free(sh_name);
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }
    *sh_namelen = *namelen;

    args->fd = fd;
    args->name = sh_name;
    args->namelen = sh_namelen;

    SYSCALL(FF_SO_GETSOCKNAME, args);

    if (ret == 0) {
        socklen_t cplen = *namelen ? *sh_namelen > *namelen
            : *sh_namelen;
        rte_memcpy(name, sh_name, cplen);
        *namelen = *sh_namelen;
    }

    //share_mem_free(sh_name);
    //share_mem_free(sh_namelen);

    RETURN_NOFREE();
}

int
ff_hook_getpeername(int fd, struct sockaddr *name,
    socklen_t *namelen)
{
    if (name == NULL || namelen == NULL) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(getpeername, (fd, name, namelen));

    DEFINE_REQ_ARGS_STATIC(getpeername);
    static __thread struct sockaddr *sh_name = NULL;
    static __thread socklen_t sh_name_len = 0;
    static __thread socklen_t *sh_namelen = NULL;

    if (sh_name == NULL || sh_name_len < *namelen) {
        if (sh_name) {
            share_mem_free(sh_name);
        }

        sh_name_len = *namelen;
        sh_name = share_mem_alloc(sh_name_len);
        if (sh_name == NULL) {
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }

    if (sh_namelen == NULL) {
        sh_namelen = share_mem_alloc(sizeof(socklen_t));
        if (sh_namelen == NULL) {
            //share_mem_free(sh_name);
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }
    *sh_namelen = *namelen;

    args->fd = fd;
    args->name = sh_name;
    args->namelen = sh_namelen;

    SYSCALL(FF_SO_GETPEERNAME, args);

    if (ret == 0) {
        socklen_t cplen = *namelen ? *sh_namelen > *namelen
            : *sh_namelen;
        rte_memcpy(name, sh_name, cplen);
        *namelen = *sh_namelen;
    }

    //share_mem_free(sh_name);
    //share_mem_free(sh_namelen);

    RETURN_NOFREE();
}

int
ff_hook_getsockopt(int fd, int level, int optname,
    void *optval, socklen_t *optlen)
{
    if (optlen == NULL) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(getsockopt, (fd, level, optname,
        optval, optlen));

    DEFINE_REQ_ARGS(getsockopt);
    void *sh_optval = NULL;
    socklen_t *sh_optlen = NULL;

    if (optval != NULL) {
        sh_optval = share_mem_alloc(*optlen);
        if (sh_optval == NULL) {
            RETURN_ERROR(ENOMEM);
        }
    }

    sh_optlen = share_mem_alloc(sizeof(socklen_t));
    if (sh_optlen == NULL) {
        if (sh_optval) {
            share_mem_free(sh_optval);
        }

        RETURN_ERROR(ENOMEM);
    }
    *sh_optlen = *optlen;

    args->fd = fd;
    args->level = level;
    args->name = optname;
    args->optval = sh_optval;
    args->optlen = sh_optlen;

    SYSCALL(FF_SO_GETSOCKOPT, args);

    if (ret == 0) {
        if (optval) {
            rte_memcpy(optval, sh_optval, *sh_optlen);
        }
        *optlen = *sh_optlen;
    }

    if (sh_optval) {
        share_mem_free(sh_optval);
    }
    share_mem_free(sh_optlen);
    RETURN();
}

int
ff_hook_setsockopt(int fd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    if (optval == NULL && optlen != 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(setsockopt, (fd, level, optname,
        optval, optlen));

    DEFINE_REQ_ARGS_STATIC(setsockopt);
    static __thread void *sh_optval = NULL;
    static __thread socklen_t sh_optval_len = 0;

    if (optval != NULL) {
        if (sh_optval == NULL || sh_optval_len < optlen) {
            if (sh_optval) {
                share_mem_free(sh_optval);
            }

            sh_optval_len = optlen;
            sh_optval = share_mem_alloc(sh_optval_len);
            if (sh_optval == NULL) {
                RETURN_ERROR_NOFREE(ENOMEM);
            }
        }
    }

    args->fd = fd;
    args->level = level;
    args->name = optname;
    args->optval = sh_optval;
    args->optlen = optlen;

    SYSCALL(FF_SO_SETSOCKOPT, args);

    /*if (sh_optval) {
        share_mem_free(sh_optval);
    }*/

    RETURN_NOFREE();
}

int
ff_hook_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    DEBUG_LOG("ff_hook_accept, fd:%d, addr:%p, len:%p\n", fd, addr, addrlen);

    if ((addr == NULL && addrlen != NULL) ||
        (addr != NULL && addrlen == NULL)) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(accept, (fd, addr, addrlen));

    DEFINE_REQ_ARGS_STATIC(accept);
    static __thread struct sockaddr *sh_addr = NULL;
    static __thread socklen_t sh_addr_len = 0;
    static __thread socklen_t *sh_addrlen = NULL;

    if (addr != NULL) {
        if (sh_addr == NULL || sh_addr_len < *addrlen) {
            if(sh_addr) {
                share_mem_free(sh_addr);
            }

            sh_addr_len = *addrlen;
            sh_addr = share_mem_alloc(sh_addr_len);
            if (sh_addr == NULL) {
                RETURN_ERROR_NOFREE(ENOMEM);
            }
        }

        if (sh_addrlen == NULL) {
            sh_addrlen = share_mem_alloc(sizeof(socklen_t));
            if (sh_addrlen == NULL) {
                //share_mem_free(sh_addr); // Don't free
                RETURN_ERROR_NOFREE(ENOMEM);
            }
        }
        *sh_addrlen = *addrlen;

        args->addr = sh_addr;
        args->addrlen = sh_addrlen;
    }else {
        args->addr = NULL;
        args->addrlen = NULL;
    }

    args->fd = fd;

    SYSCALL(FF_SO_ACCEPT, args);

    if (ret > 0) {
        ret = convert_fstack_fd(ret);
    }

    if (addr) {
        if (ret > 0) {
            socklen_t cplen = *sh_addrlen > *addrlen ?
                *addrlen : *sh_addrlen;
            rte_memcpy(addr, sh_addr, cplen);
            *addrlen = *sh_addrlen;
        }
        //share_mem_free(sh_addr); // Don't free
        //share_mem_free(sh_addrlen);
    }

    RETURN_NOFREE();
}

int
ff_hook_accept4(int fd, struct sockaddr *addr,
    socklen_t *addrlen, int flags)
{
    DEBUG_LOG("ff_hook_accept4, fd:%d, addr:%p, addrlen:%p, flags:%d\n", fd, addr, addrlen, flags);

    CHECK_FD_OWNERSHIP(accept4, (fd, addr, addrlen, flags));

    errno = ENOSYS;
    return -1;
}

int
ff_hook_connect(int fd, const struct sockaddr *addr,
    socklen_t addrlen)
{
    DEBUG_LOG("ff_hook_connect, fd:%d, addr:%p, addrlen:%u\n", fd, addr, addrlen);

    if (addr == NULL) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(connect, (fd, addr, addrlen));

    DEFINE_REQ_ARGS_STATIC(connect);
    static __thread struct sockaddr *sh_addr = NULL;
    static __thread socklen_t sh_addr_len = 0;

    if (sh_addr == NULL || sh_addr_len < addrlen) {
        if(sh_addr) {
            share_mem_free(sh_addr);
        }

        sh_addr_len = addrlen;
        sh_addr = share_mem_alloc(sh_addr_len);
        if (sh_addr == NULL) {
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }
    rte_memcpy(sh_addr, addr, addrlen);

    args->fd = fd;
    args->addr = sh_addr;
    args->addrlen = addrlen;

    SYSCALL(FF_SO_CONNECT, args);

    //share_mem_free(sh_addr);

    RETURN_NOFREE();
}

ssize_t
ff_hook_recv(int fd, void *buf, size_t len, int flags)
{
    DEBUG_LOG("ff_hook_recv, fd:%d, buf:%p, len:%lu, flags:%d\n",
        fd, buf, len, flags);
    return ff_hook_recvfrom(fd, buf, len, flags, NULL, NULL);
}

ssize_t
ff_hook_recvfrom(int fd, void *buf, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen)
{
    DEBUG_LOG("ff_hook_recvfrom, fd:%d, buf:%p, len:%lu, flags:%d, from:%p, fromlen:%p\n",
        fd, buf, len, flags, from, fromlen);

    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    if ((from == NULL && fromlen != NULL) ||
        (from != NULL && fromlen == NULL)) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(recvfrom, (fd, buf, len, flags, from, fromlen));

    DEFINE_REQ_ARGS_STATIC(recvfrom);
    static __thread void *sh_buf = NULL;
    static __thread size_t sh_buf_len = 0;
    static __thread struct sockaddr *sh_from = NULL;
    static __thread socklen_t sh_from_len = 0;
    static __thread socklen_t *sh_fromlen = NULL;

    if (from != NULL) {
        if (sh_from == NULL || sh_from_len < *fromlen) {
            if (sh_from) {
                share_mem_free(sh_from);
            }

            sh_from_len = *fromlen;
            sh_from = share_mem_alloc(sh_from_len);
            if (sh_from == NULL) {
                RETURN_ERROR_NOFREE(ENOMEM);
            }
        }

        if (sh_fromlen == NULL) {
            sh_fromlen = share_mem_alloc(sizeof(socklen_t));
            if (sh_fromlen == NULL) {
                //share_mem_free(sh_from);
                RETURN_ERROR_NOFREE(ENOMEM);
            }
        }

        args->from = sh_from;
        args->fromlen = sh_fromlen;
    } else {
        args->from = NULL;
        args->fromlen = NULL;
    }

    if (sh_buf == NULL || sh_buf_len < (len * 4)) {
        if (sh_buf) {
            share_mem_free(sh_buf);
        }

        sh_buf_len = len * 4;
        sh_buf = share_mem_alloc(sh_buf_len);
        if (sh_buf == NULL) {
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }

    args->fd = fd;
    args->buf = sh_buf;
    args->len = len;
    args->flags = flags;

    SYSCALL(FF_SO_RECVFROM, args);

    if (ret >= 0) {
        rte_memcpy(buf, sh_buf, ret);
        if (from) {
            socklen_t cplen = *fromlen ? *sh_fromlen > *fromlen
                : *sh_fromlen;
            rte_memcpy(from, sh_from, cplen);
            *fromlen = *sh_fromlen;
        }
    }

    /*if (from) {
        share_mem_free(sh_from);
        share_mem_free(sh_fromlen);
    }

    share_mem_free(sh_buf);*/

    RETURN_NOFREE();
}

static void
iovec_share_free(struct iovec *iov, int iovcnt)
{
    int i;

    if (iov == NULL) {
        return;
    }

    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_base) {
            share_mem_free(iov[i].iov_base);
        }
    }

    share_mem_free(iov);
}

static struct iovec *
iovec_share_alloc(const struct iovec *iov, int iovcnt)
{
    struct iovec *sh_iov;
    int i;

    if (iov == NULL || iovcnt == 0) {
        return NULL;
    }

    sh_iov = share_mem_alloc(sizeof(struct iovec) * iovcnt);
    if (sh_iov == NULL) {
        return NULL;
    }

    for (i = 0; i < iovcnt; i++) {
        sh_iov[i].iov_len = iov[i].iov_len;
        void *iov_base = share_mem_alloc(sh_iov[i].iov_len);
        sh_iov[i].iov_base = iov_base;

        if (iov_base == NULL) {
            goto ERROR;
        }
    }

    return sh_iov;

ERROR:
    iovec_share_free(sh_iov, iovcnt);
    return NULL;
}

static void
iovec_local2share(struct iovec *share, const struct iovec *local,
    int iovcnt)
{
    int i;

    if (share == NULL || local == NULL || iovcnt == 0) {
        return;
    }

    for (i = 0; i < iovcnt; i++) {
        assert(share[i].iov_len == local[i].iov_len);

        rte_memcpy(share[i].iov_base, local[i].iov_base,
            share[i].iov_len);
    }
}

static void
iovec_share2local(struct iovec *share,
    const struct iovec *local, int iovcnt,
    ssize_t total, int copy)
{
    int i;
    for (i = 0; i < iovcnt && total > 0; i++) {
        ssize_t count = local[i].iov_len;
        if (total <= count) {
            count = total;
        }

        share[i].iov_base =
            (char *)share[i].iov_base - count;
        share[i].iov_len += count;

        if (copy) {
            rte_memcpy(local[i].iov_base,
                share[i].iov_base, count);
        }

        total -= count;
    }
}

static struct iovec *
iovec_share_alloc_s()
{
    int i, iovcnt = IOV_MAX;

    sh_iov_static = share_mem_alloc(sizeof(struct iovec) * iovcnt);
    if (sh_iov_static == NULL) {
        ERR_LOG("share_mem_alloc shiov failed, oom\n");
        errno = ENOMEM;
        return NULL;
    }

    for (i = 0; i < iovcnt; i++) {
        sh_iov_static[i].iov_len = IOV_LEN_MAX;
        void *iov_base = share_mem_alloc(sh_iov_static[i].iov_len);
        sh_iov_static[i].iov_base = iov_base;
        sh_iov_static_base[i] = iov_base;

        if (iov_base == NULL) {
            ERR_LOG("share_mem_alloc iov_base:%d failed, oom\n", i);
            errno = ENOMEM;
            goto ERROR;
        }
    }

    ERR_LOG("iovec_share_alloc_s alloc sh_iov_static:%p success, iovcnt:%d, per iov_len:%d\n",
            sh_iov_static, IOV_MAX, IOV_LEN_MAX);

    return sh_iov_static;

ERROR:
    iovec_share_free(sh_iov_static, i);
    return NULL;
}

static int
_iovec_local2share_s(const struct iovec *local, int iovcnt, size_t skip)
{
    int i, j;
    size_t len, total = 0;

    DEBUG_LOG("_iovec_local2share_s local iov:%p, iovcnt:%d, skip:%lu, sh_iov_static:%p, "
        "first iov_base:%p, iov_len:%lu\n",
        local, iovcnt, skip, sh_iov_static,
        sh_iov_static[0].iov_base, sh_iov_static[0].iov_len);

    if (local == NULL || iovcnt == 0) {
        errno = EINVAL;
        return -1;
    }

    for (i = sh_iov_static_fill_idx_local, j = 0; i < iovcnt && j < IOV_MAX; i++, j++) {
        DEBUG_LOG("local[%d].iov_len:%lu, skip:%lu, total:%lu\n",
            i, local[i].iov_len, skip, total);

        if (local[i].iov_len <= skip) {
            skip -= local[i].iov_len;
            continue;
        }

        if ((local[i].iov_len - skip) <= IOV_LEN_MAX) {
            sh_iov_static[j].iov_len = local[i].iov_len - skip;
            rte_memcpy(sh_iov_static[j].iov_base, local[i].iov_base,
                sh_iov_static[j].iov_len);
            total += sh_iov_static[j].iov_len;
            DEBUG_LOG("sh_iov_static[%d].iov_base:%p, len:%lu, skip:%lu, total:%lu\n",
                j, sh_iov_static[j].iov_base, sh_iov_static[j].iov_len, skip, total);
        } else {
            len = local[i].iov_len - skip;
            DEBUG_LOG("local[%d].iov_len:%lu, skip:%lu, total:%lu, len(iov_len - skip):%lu\n",
                        i, local[i].iov_len, skip, total, len);
            for (; j < IOV_MAX ; j++) {
                sh_iov_static[j].iov_len = RTE_MIN(IOV_LEN_MAX, len);
                rte_memcpy(sh_iov_static[j].iov_base, local[i].iov_base + (local[i].iov_len - len),
                    sh_iov_static[j].iov_len);

                len -= sh_iov_static[j].iov_len;
                total += sh_iov_static[j].iov_len;

                DEBUG_LOG("sh_iov_static[%d].iov_base:%p, len:%lu, skip:%lu, total:%lu, len:%lu\n",
                        j, sh_iov_static[j].iov_base, sh_iov_static[j].iov_len, skip, total, len);

                if (len == 0) {
                    break;
                }
            }

            if (j == IOV_MAX) {
                ERR_LOG("Too large buf to send/write, you best to reduce it.\n");
                break;
            }
        }
    }

    sh_iov_static_fill_idx_local = i;
    sh_iov_static_fill_idx_share = j;

    DEBUG_LOG("sh_iov_static_fill_idx_local(i):%d, sh_iov_static_fill_idx_share(j):%d, skip:%lu, total:%lu\n",
                sh_iov_static_fill_idx_local, sh_iov_static_fill_idx_share, skip, total);

    return total;
}

static int
iovec_local2share_s(const struct iovec *iov, int iovcnt, size_t skip)
{
    int sent = 0;

    DEBUG_LOG("iovec_local2share_s iov:%p, iovcnt:%d, skip:%lu, sh_iov_static:%p\n",
        iov, iovcnt, skip, sh_iov_static);

    if (sh_iov_static == NULL) {
        sh_iov_static = iovec_share_alloc_s();
        if (sh_iov_static == NULL) {
            ERR_LOG("iovec_share_alloc_s failed, oom\n");
            errno = ENOMEM;
            return -1;
        }
    }

    sent = _iovec_local2share_s(iov, iovcnt, skip);

    return sent;
}

static void
iovec_share2local_s()
{
    int i;

    DEBUG_LOG("iovec_share2local_s sh_iov_static:%p, sh_iov_static_fill_idx_share:%d\n",
        sh_iov_static, sh_iov_static_fill_idx_share);

    for (i = 0; i < sh_iov_static_fill_idx_share; i++) {
        sh_iov_static[i].iov_base = sh_iov_static_base[i];
        sh_iov_static[i].iov_len = IOV_LEN_MAX;
    }
}

static void
msghdr_share_free(struct msghdr *msg)
{
    if (msg == NULL) {
        return;
    }

    if (msg->msg_name) {
        share_mem_free(msg->msg_name);
    }

    if (msg->msg_control) {
        share_mem_free(msg->msg_control);
    }

    if (msg->msg_iov) {
        iovec_share_free(msg->msg_iov, msg->msg_iovlen);
    }

    share_mem_free(msg);
}

static struct msghdr *
msghdr_share_alloc(const struct msghdr *msg)
{
    struct msghdr *hdr;

    if (msg == NULL) {
        return NULL;
    }

    hdr = share_mem_alloc(sizeof(struct msghdr));
    if (hdr == NULL) {
        return NULL;
    }
    memset(hdr, 0, sizeof(struct msghdr));

    hdr->msg_namelen = msg->msg_namelen;
    hdr->msg_iovlen = msg->msg_iovlen;
    hdr->msg_controllen = msg->msg_controllen;
    hdr->msg_flags = msg->msg_flags;

    if (msg->msg_name) {
        hdr->msg_name = share_mem_alloc(hdr->msg_namelen);
        if (hdr->msg_name == NULL) {
            goto ERROR;
        }
    }

    if (msg->msg_control) {
        hdr->msg_control = share_mem_alloc(hdr->msg_controllen);
        if (hdr->msg_control == NULL) {
            goto ERROR;
        }
    }

    hdr->msg_iov = iovec_share_alloc(msg->msg_iov, hdr->msg_iovlen);
    if (hdr->msg_iov == NULL) {
        goto ERROR;
    }

    return hdr;

ERROR:
    msghdr_share_free(hdr);
    return NULL;
}

static void
msghdr_share_memcpy(const struct msghdr *dst, const struct msghdr *src)
{
    if (dst == NULL || src == NULL) {
        return;
    }

    assert((dst->msg_name == NULL && src->msg_name == NULL)
        || (dst->msg_name != NULL && src->msg_name != NULL));
    assert(dst->msg_namelen == src->msg_namelen);

    assert((dst->msg_control == NULL && src->msg_control == NULL)
        || (dst->msg_control != NULL && src->msg_control != NULL));
    assert(dst->msg_controllen == src->msg_controllen);

    if (dst->msg_name) {
        rte_memcpy(dst->msg_name, src->msg_name, src->msg_namelen);
    }

    if (dst->msg_control) {
        rte_memcpy(dst->msg_control, src->msg_control,
            src->msg_controllen);
    }

    //do iovec_memcpy by caller.
}

ssize_t
ff_hook_recvmsg(int fd, struct msghdr *msg, int flags)
{
    DEBUG_LOG("ff_hook_recvmsg, fd:%d, msg:%p, flags:%d\n", fd, msg, flags);

    if (msg == NULL || msg->msg_iov == NULL ||
        msg->msg_iovlen == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(recvmsg, (fd, msg, flags));

    DEFINE_REQ_ARGS_STATIC(recvmsg);

    /*
     * If calling very frequently,
     * may need to not free the memory malloc with rte_malloc,
     * to improve proformance.
     *
     * Because this API support it relatively troublesome,
     * so no support right now.
     */
    struct msghdr *sh_msg = NULL;

    sh_msg = msghdr_share_alloc(msg);
    if (sh_msg == NULL) {
        RETURN_ERROR_NOFREE(ENOMEM);
    }

    args->fd = fd;
    args->msg = sh_msg;
    args->flags = flags;

    SYSCALL(FF_SO_RECVMSG, args);

    if (ret >= 0) {
        msghdr_share_memcpy(msg, sh_msg);
        if (ret > 0) {
            iovec_share2local(sh_msg->msg_iov,
                msg->msg_iov, msg->msg_iovlen,
                ret, 1);
        }
    }

    msghdr_share_free(sh_msg);

    RETURN_NOFREE();
}

ssize_t
ff_hook_read(int fd, void *buf, size_t len)
{
    DEBUG_LOG("ff_hook_read, fd:%d, buf:%p, len:%lu\n", fd, buf, len);

    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(read, (fd, buf, len));

    DEFINE_REQ_ARGS_STATIC(read);
    static __thread void *sh_buf = NULL;
    static __thread size_t sh_buf_len = 0;

    /* alloc or realloc sh_buf */
    if (sh_buf == NULL || sh_buf_len < (len * 4)) {
        if (sh_buf) {
            share_mem_free(sh_buf);;
        }

        /* alloc 4 times buf space */
        sh_buf_len = len * 4;
        sh_buf = share_mem_alloc(sh_buf_len);
        if (sh_buf == NULL) {
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }

    args->fd = fd;
    args->buf = sh_buf;
    args->len = len;

    SYSCALL(FF_SO_READ, args);

    if (ret > 0) {
        rte_memcpy(buf, sh_buf, ret);
    }

    //share_mem_free(sh_buf);

    RETURN_NOFREE();
}

ssize_t
ff_hook_readv(int fd, const struct iovec *iov, int iovcnt)
{
    DEBUG_LOG("ff_hook_readv, fd:%d, iov:%p, iovcnt:%d\n", fd, iov, iovcnt);

    if (iov == NULL || iovcnt == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(readv, (fd, iov, iovcnt));

    DEFINE_REQ_ARGS_STATIC(readv);

    /*
     * If calling very frequently,
     * may need to not free the memory malloc with rte_malloc,
     * to improve proformance, see ff_hook_writev().
     */
    struct iovec *sh_iov = NULL;

    sh_iov = iovec_share_alloc(iov, iovcnt);
    if (sh_iov == NULL) {
        RETURN_ERROR_NOFREE(ENOMEM);
    }

    args->fd = fd;
    args->iov = sh_iov;
    args->iovcnt = iovcnt;

    SYSCALL(FF_SO_READV, args);

    if (ret > 0) {
        iovec_share2local(sh_iov, iov, iovcnt, ret, 1);
    }

    iovec_share_free(sh_iov, iovcnt);

    RETURN_NOFREE();
}

ssize_t
ff_hook_sendto(int fd, const void *buf, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
    DEBUG_LOG("ff_hook_sendto, fd:%d, buf:%p, len:%lu, flags:%d, to:%p, tolen:%d\n",
        fd, buf, len, flags, to, tolen);

    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(sendto, (fd, buf, len, flags, to, tolen));

    DEFINE_REQ_ARGS_STATIC(sendto);
    static __thread void *sh_buf = NULL;
    static __thread size_t sh_buf_len = 0;
    static __thread void *sh_to = NULL;
    static __thread socklen_t sh_to_len = 0;

    if (sh_buf == NULL || sh_buf_len < (len * 4)) {
        if (sh_buf) {
            share_mem_free(sh_buf);;
        }

        /* alloc 4 times buf space */
        sh_buf_len = len * 4;
        sh_buf = share_mem_alloc(sh_buf_len);
        if (sh_buf == NULL) {
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }
    rte_memcpy(sh_buf, buf, len);

    if (to) {
        if (sh_to == NULL || sh_to_len < tolen) {
            if (sh_to) {
                share_mem_free(sh_to);
            }

            sh_to_len = tolen;
            sh_to = share_mem_alloc(sh_to_len);
            if (sh_to == NULL) {
                //share_mem_free(sh_buf);
                RETURN_ERROR_NOFREE(ENOMEM);
            }
        }
        rte_memcpy(sh_to, to, tolen);
        args->to = sh_to;
        args->tolen = tolen;
    } else {
        args->to = NULL;
        args->tolen = 0;
    }

    args->fd = fd;
    args->buf = sh_buf;
    args->len = len;
    args->flags = flags;

    SYSCALL(FF_SO_SENDTO, args);

    /*share_mem_free(sh_buf);
    if (sh_to) {
        share_mem_free(sh_to);
    }*/

    RETURN_NOFREE();
}

ssize_t
ff_hook_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    DEBUG_LOG("ff_hook_sendmsg, fd:%d, msg:%p, flags:%d\n",
        fd, msg, flags);

    if (msg == NULL || msg->msg_iov == NULL ||
        msg->msg_iovlen == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(sendmsg, (fd, msg, flags));

    DEFINE_REQ_ARGS_STATIC(sendmsg);

    /*
     * If calling very frequently,
     * may need to not free the memory malloc with rte_malloc,
     * to improve proformance.
     *
     * Because this API support it relatively troublesome,
     * so no support right now.
     */
    struct msghdr *sh_msg = NULL;

    sh_msg = msghdr_share_alloc(msg);
    if (sh_msg == NULL) {
        RETURN_ERROR_NOFREE(ENOMEM);
    }
    msghdr_share_memcpy(sh_msg, msg);
    iovec_local2share(sh_msg->msg_iov,
        msg->msg_iov, msg->msg_iovlen);

    args->fd = fd;
    args->msg = sh_msg;
    args->flags = flags;

    SYSCALL(FF_SO_SENDMSG, args);

    if (ret > 0) {
        iovec_share2local(sh_msg->msg_iov,
            msg->msg_iov, msg->msg_iovlen,
            ret, 0);
    }

    msghdr_share_free(sh_msg);

    RETURN_NOFREE();
}

ssize_t
ff_hook_send(int fd, const void *buf, size_t len, int flags)
{
    DEBUG_LOG("ff_hook_send, fd:%d, buf:%p, len:%lu, flags:%d\n", fd, buf, len, flags);
    return ff_hook_sendto(fd, buf, len, flags, NULL, 0);
}

ssize_t
ff_hook_write(int fd, const void *buf, size_t len)
{
    DEBUG_LOG("ff_hook_write, fd:%d, len:%lu\n", fd, len);

    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(write, (fd, buf, len));

    DEFINE_REQ_ARGS_STATIC(write);
    static __thread void *sh_buf = NULL;
    static __thread size_t sh_buf_len = 0;

    if (sh_buf == NULL || sh_buf_len < (len * 4)) {
        if (sh_buf) {
            share_mem_free(sh_buf);
        }

        sh_buf_len = len * 4;
        sh_buf = share_mem_alloc(sh_buf_len);
        if (sh_buf == NULL) {
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }
    rte_memcpy(sh_buf, buf, len);

    args->fd = fd;
    args->buf = sh_buf;
    args->len = len;

    SYSCALL(FF_SO_WRITE, args);

    //share_mem_free(sh_buf);

    RETURN_NOFREE();
}

ssize_t
ff_hook_writev(int fd, const struct iovec *iov, int iovcnt)
{
    size_t sent = 0;
    int ret_s = -1;

    DEBUG_LOG("ff_hook_writev, fd:%d, iov:%p, iovcnt:%d\n", fd, iov, iovcnt);

    if (iov == NULL || iovcnt == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(writev, (fd, iov, iovcnt));

    DEFINE_REQ_ARGS_STATIC(writev);

    errno = 0;
    args->fd = fd;

    do {
        sh_iov_static_fill_idx_local = 0;
        sh_iov_static_fill_idx_share = 0;
        ret_s = iovec_local2share_s(iov, iovcnt, sent);
        DEBUG_LOG("iovec_local2share_s ret_s:%d, iov:%p, ipvcnt:%d, send:%lu, "
            "sh_iov_static:%p, sh_iov_static_fill_idx_local:%d, sh_iov_static_fill_idx_share:%d\n",
            ret_s, iov, iovcnt, sent,
            sh_iov_static, sh_iov_static_fill_idx_local, sh_iov_static_fill_idx_share);
        if (ret_s < 0) {
            ERR_LOG("get_iovec_share failed, iov:%p, iovcnt:%d, sh_iov_static_fill_idx_local:%d,"
                " sh_iov_static_fill_idx_share:%d",
                iov, iovcnt, sh_iov_static_fill_idx_local,
                sh_iov_static_fill_idx_share);
            return -1;
        }

        args->iov = sh_iov_static;
        args->iovcnt = sh_iov_static_fill_idx_share;

        SYSCALL(FF_SO_WRITEV, args);

        /*
         * This API can be igroned while use sh_iov_static_base[i] directly
         * in _iovec_local2share_s. But don't do like that now
         */
        iovec_share2local_s();

        if (ret > 0) {
            sent += ret;
        }

        /*
         * Don't try to send again in this case.
         */
        DEBUG_LOG("iovec_local2share_s ret_s:%d, f-stack writev ret:%d, total sent:%lu\n", ret_s, ret, sent);
        if (ret != ret_s) {
            break;
        }
    } while (sh_iov_static_fill_idx_local < iovcnt);
    sh_iov_static_fill_idx_share = 0;

    if (sent > 0) {
        ret = sent;
    }

    RETURN_NOFREE();
}

int
ff_hook_close(int fd)
{
    DEBUG_LOG("ff_hook_close, fd:%d\n", fd);

    CHECK_FD_OWNERSHIP(close, (fd));

    DEFINE_REQ_ARGS_STATIC(close);

#ifdef FF_MULTI_SC
    /*
     * Hear don't care if the fd belong to this worker sc,
     * just scs[i].fd == fd, to close it
     * until the loop close all fd.
     */
    if (unlikely(current_worker_id == worker_id)) {
        int i;
        for (i = 0; i < worker_id; i++) {
            if (scs[i].fd == fd) {
                ERR_LOG("worker_id:%d, fd:%d, sc:%p, sc->fd:%d, sc->worker_id:%d\n",
                    i, fd, scs[i].sc, scs[i].fd, scs[i].worker_id);
                sc = scs[i].sc;
                scs[i].fd = -1;
                break;
            }
        }
    }
#endif
    args->fd = fd;

    SYSCALL(FF_SO_CLOSE, args);

    RETURN_NOFREE();
}

int
ff_hook_ioctl(int fd, unsigned long req, unsigned long data)
{
    #ifndef FIOASYNC
    #define FIOASYNC 0x5452
    #endif
    #ifndef FIONBIO
    #define FIONBIO 0x5421
    #endif

    if (req != FIOASYNC && req != FIONBIO) {
        errno = ENOTSUP;
        return -1;
    }

    CHECK_FD_OWNERSHIP(ioctl, (fd, req, data));

    DEFINE_REQ_ARGS_STATIC(ioctl);

    static __thread unsigned long *sh_data = NULL;

    if (sh_data == NULL) {
        sh_data = share_mem_alloc(sizeof(int));
        if (sh_data == NULL) {
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }
    *((int *)sh_data) = *((int *)data);

    args->fd = fd;
    args->com = req;
    args->data = sh_data;

    SYSCALL(FF_SO_IOCTL, args);

    if (ret == 0) {
        *((int *)data) = *((int *)sh_data);
    }

    //share_mem_free(sh_data);

    RETURN_NOFREE();
}

int
ff_hook_fcntl(int fd, int cmd, unsigned long data)
{
    CHECK_FD_OWNERSHIP(fcntl, (fd, cmd, data));

    DEFINE_REQ_ARGS_STATIC(fcntl);

    args->fd = fd;
    args->cmd = cmd;
    args->data = data;

    SYSCALL(FF_SO_FCNTL, args);

    RETURN_NOFREE();
}

/*
 * Use F-Stack stack by default.
 *
 * If fdsize set SOCK_KERNEL(0x01000000) and not set SOCK_FSTACK(0x02000000), means use kernel stack.
 * And the max fdsize shoud be <= (SOCK_KERNEL - 1).
 *
 * If fdsize set [1, 16], means use kernel stack, need to consider a better implementation.
 */
int
ff_hook_epoll_create(int fdsize)
{

    ERR_LOG("ff_hook_epoll_create, fdsize:%d\n", fdsize);
    if (inited == 0 || ((fdsize & SOCK_KERNEL) && !(fdsize & SOCK_FSTACK))/* || (fdsize >= 1 && fdsize <= 16)*/) {
        fdsize &= ~SOCK_KERNEL;
        return ff_linux_epoll_create(fdsize);
    }

    DEFINE_REQ_ARGS(epoll_create);

    args->size = size;

    SYSCALL(FF_SO_EPOLL_CREATE, args);

    if (ret >= 0) {
#ifdef FF_KERNEL_EVENT
        int kernel_fd;

        kernel_fd = ff_linux_epoll_create(fdsize);
        fstack_kernel_fd_map[ret] = kernel_fd;
        ERR_LOG("ff_hook_epoll_create fstack fd:%d, FF_KERNEL_EVENT kernel_fd:%d:\n", ret, kernel_fd);
#endif
        ret = convert_fstack_fd(ret);
    }

    ERR_LOG("ff_hook_epoll_create return fd:%d\n", ret);

    RETURN();
}

int
ff_hook_epoll_ctl(int epfd, int op, int fd,
    struct epoll_event *event)
{
    int ff_epfd;

    DEBUG_LOG("ff_hook_epoll_ctl, epfd:%d, op:%d, fd:%d\n", epfd, op, fd);

#ifdef FF_KERNEL_EVENT
    if (unlikely(!is_fstack_fd(fd))) {
        if (is_fstack_fd(epfd)) {
            ff_epfd = restore_fstack_fd(epfd);
            if (likely(fstack_kernel_fd_map[ff_epfd] > 0)) {
                epfd = fstack_kernel_fd_map[ff_epfd];
                DEBUG_LOG("ff_epfd:%d, kernel epfd:%d\n", ff_epfd, epfd);
            } else {
                ERR_LOG("invalid fd and ff_epfd:%d, epfd:%d, op:%d, fd:%d\n", ff_epfd, epfd, op, fd);
                errno = EBADF;
                return -1;
            }
        }
        return ff_linux_epoll_ctl(epfd, op, fd, event);
    }
    fd = restore_fstack_fd(fd);
#else
    CHECK_FD_OWNERSHIP(epoll_ctl, (epfd, op, fd, event));
#endif
    ff_epfd = restore_fstack_fd(epfd);

    DEFINE_REQ_ARGS_STATIC(epoll_ctl);
    static __thread struct epoll_event *sh_event = NULL;

    if ((!event && op != EPOLL_CTL_DEL) ||
        (op != EPOLL_CTL_ADD &&
         op != EPOLL_CTL_MOD &&
         op != EPOLL_CTL_DEL)) {
        errno = EINVAL;
        return -1;
    }

    if (event) {
        if (sh_event == NULL) {
            sh_event = share_mem_alloc(sizeof(struct epoll_event));
            if (sh_event == NULL) {
                RETURN_ERROR_NOFREE(ENOMEM);
            }
        }
        rte_memcpy(sh_event, event, sizeof(struct epoll_event));
        args->event = sh_event;
    } else {
        args->event = NULL;
    }

    args->epfd = ff_epfd;
    args->op = op;
    args->fd = fd;

    SYSCALL(FF_SO_EPOLL_CTL, args);

    /*if (sh_event) {
        share_mem_free(sh_event);
    }*/

    RETURN_NOFREE();
}

int
ff_hook_epoll_wait(int epfd, struct epoll_event *events,
    int maxevents, int timeout)
{
    DEBUG_LOG("ff_hook_epoll_wait, epfd:%d, maxevents:%d, timeout:%d\n", epfd, maxevents, timeout);
    int fd = epfd;
    struct timespec abs_timeout;

    CHECK_FD_OWNERSHIP(epoll_wait, (epfd, events, maxevents, timeout));

    DEFINE_REQ_ARGS_STATIC(epoll_wait);
    static __thread struct epoll_event *sh_events = NULL;
    static __thread int sh_events_len = 0;

#ifdef FF_KERNEL_EVENT
    /* maxevents must >= 2, if use FF_KERNEL_EVENT */
    if (unlikely(maxevents < 2)) {
        ERR_LOG("maxevents must >= 2, if use FF_KERNEL_EVENT, now is %d\n", maxevents);
        RETURN_ERROR_NOFREE(EINVAL);
    }

    int kernel_ret = 0;
    int kernel_maxevents = kernel_maxevents = maxevents / 16;

    if (kernel_maxevents > SOCKET_OPS_CONTEXT_MAX_NUM) {
        kernel_maxevents = SOCKET_OPS_CONTEXT_MAX_NUM;
    } else if (kernel_maxevents <= 0) {
        kernel_maxevents = 1;
    }
    maxevents -= kernel_maxevents;
#endif

    if (sh_events == NULL || sh_events_len < maxevents) {
        if (sh_events) {
            share_mem_free(sh_events);
        }

        sh_events_len = maxevents;
        sh_events = share_mem_alloc(sizeof(struct epoll_event) * sh_events_len);
        if (sh_events == NULL) {
            RETURN_ERROR_NOFREE(ENOMEM);
        }
    }

    if (timeout > 0) {
        clock_gettime(CLOCK_REALTIME, &abs_timeout);
        DEBUG_LOG("before wait, sec:%ld, nsec:%ld\n", abs_timeout.tv_sec, abs_timeout.tv_nsec);
        abs_timeout.tv_sec += timeout / 1000;
        /* must % 1000 first, otherwise type(int) maybe overflow, and sem_timedwait failed */
        abs_timeout.tv_nsec += (timeout % 1000) * 1000 * 1000;
        if (abs_timeout.tv_nsec > NS_PER_SECOND) {
            abs_timeout.tv_nsec -= NS_PER_SECOND;
            abs_timeout.tv_sec += 1;
        }
        if (unlikely(abs_timeout.tv_sec < 0 || abs_timeout.tv_nsec < 0)) {
            ERR_LOG("invalid timeout argument, the sec:%ld, nsec:%ld\n",
                abs_timeout.tv_sec, abs_timeout.tv_nsec);
            RETURN_ERROR_NOFREE(EINVAL);
        }
    }

    args->epfd = fd;
    args->events = sh_events;
    args->maxevents = maxevents;
    args->timeout = timeout;

RETRY:
    /* for timeout, Although not really effective in FreeBSD stack */
    //SYSCALL(FF_SO_EPOLL_WAIT, args);
    ACQUIRE_ZONE_LOCK(FF_SC_IDLE);
    sc->ops = FF_SO_EPOLL_WAIT;
    sc->args = args;

    /*
     * sc->result, sc->error must reset in epoll_wait and kevent.
     * Otherwise can access last sc call's result.
     *
     * Because if sem_timedwait timeouted, but fstack instance still
     * call sem_post later, and next or next's next sem_timedwait will
     * return 0 directly, then get invalid result and error.
     */
    sc->result = 0;
    sc->error = 0;
    errno = 0;
    if (timeout <= 0) {
        need_alarm_sem = 1;
    }

    RELEASE_ZONE_LOCK(FF_SC_REQ);

#ifdef FF_KERNEL_EVENT
    /*
     * Call ff_linux_epoll_wait before sem_timedwait/sem_wait.
     * And set timeout is 0.
     *
     * If there are events return, and move event offset to unused event for copy F-Stack events.
     */
    DEBUG_LOG("call ff_linux_epoll_wait at the same time, epfd:%d, fstack_kernel_fd_map[epfd]:%d, kernel_maxevents:%d\n",
        fd, fstack_kernel_fd_map[fd], kernel_maxevents);
    if (likely(fstack_kernel_fd_map[fd] > 0)) {
        static uint64_t count = 0;
        if (unlikely((count & 0xff) == 0)) {
            kernel_ret = ff_linux_epoll_wait(fstack_kernel_fd_map[fd], events, kernel_maxevents, 0);
            DEBUG_LOG("ff_linux_epoll_wait count:%lu, kernel_ret:%d, errno:%d\n", count, ret, errno);
            if (kernel_ret < 0) {
                kernel_ret = 0;
            } else if (kernel_ret > 0) {
                events += kernel_ret;
            }
        }
        count++;
    }
#endif

    if (timeout > 0) {
        DEBUG_LOG("ready to wait, sec:%ld, nsec:%ld\n", abs_timeout.tv_sec, abs_timeout.tv_nsec);
        ret = sem_timedwait(&sc->wait_sem, &abs_timeout);

        clock_gettime(CLOCK_REALTIME, &abs_timeout);
        DEBUG_LOG("after wait, sec:%ld, nsec:%ld\n", abs_timeout.tv_sec, abs_timeout.tv_nsec);
    } else {
        ret = sem_wait(&sc->wait_sem);
    }

    rte_spinlock_lock(&sc->lock);

    if (timeout <= 0) {
        need_alarm_sem = 0;
    }

    /*
     * After sem_timedwait, and before lock sc, sc->status may be modify from FF_SC_REQ to FF_SC_RSP,
     * so it can't use to check.
     *
     * And only ret == 0, means sem_timedwait return normal,
     * can set ret = sc->result, otherwise may use last sc->result.
     */
    DEBUG_LOG("sem wait, ret:%d, sc->result:%d, sc->errno:%d\n",
        ret, sc->result, sc->error);
    if (unlikely(ret == -1 && errno == ETIMEDOUT /* sc->status == FF_SC_REQ */)) {
        ret = 0;
    } else if (likely(ret == 0)) {
        ret = sc->result;
        if (ret < 0) {
            errno = sc->error;
        }
    }

    sc->status = FF_SC_IDLE;
    rte_spinlock_unlock(&sc->lock);

    if (likely(ret > 0)) {
        if (unlikely(ret > maxevents)) {
            ERR_LOG("return events:%d, maxevents:%d, set return events to maxevents, may be some error occur\n",
                ret, maxevents);
            ret = maxevents;
        }
        rte_memcpy(events, sh_events, sizeof(struct epoll_event) * ret);
    }

#ifdef FF_KERNEL_EVENT
    if (unlikely(kernel_ret > 0)) {
        if (likely(ret > 0)) {
            ret += kernel_ret;
        } else {
            ret = kernel_ret;
        }
    }
#endif

    /* If timeout is -1, always retry epoll_wait until ret not 0 */
    if (timeout <= 0 && ret == 0) {
        //usleep(100);
        rte_pause();
        goto RETRY;
    }

    /*
     * Don't free, to improve proformance.
     * Will cause memory leak while APP exit , but fstack adapter not exit.
     * May set them as gloabl variable and free in thread_destructor.
     */
    /*if (sh_events) {
        share_mem_free(sh_events);
        sh_events = NULL;
    }*/

    RETURN_NOFREE();
}

pid_t
ff_hook_fork(void)
{
    pid_t pid;

    ERR_LOG("ff_hook_fork\n");
#ifdef FF_MULTI_SC
    /* Let the child process inherit the specified sc and ff_so_zone*/
    sc = scs[current_worker_id].sc;
    ff_so_zone = ff_so_zones[current_worker_id];
#endif

    if (sc) {
        rte_spinlock_lock(&sc->lock);
    }

    pid = ff_linux_fork();

    if (sc) {
        /* Parent process set refcount. */
        if (pid > 0) {
            sc->refcount++;
            ERR_LOG("parent process, chilid pid:%d, sc:%p, sc->refcount:%d, ff_so_zone:%p\n",
                pid, sc, sc->refcount, ff_so_zone);
#ifdef FF_MULTI_SC
            current_worker_id++;
            ERR_LOG("parent process, current_worker_id++:%d\n", current_worker_id);
#endif
        }
        else if (pid == 0) {
            ERR_LOG("chilid process, sc:%p, sc->refcount:%d, ff_so_zone:%p\n",
                sc, sc->refcount, ff_so_zone);
#ifdef FF_MULTI_SC
            ERR_LOG("chilid process, current_worker_id:%d\n", current_worker_id);
#endif
        }

        /* Parent process unlock sc, fork success of failed. */
        if (pid != 0) {
            rte_spinlock_unlock(&sc->lock);
        }
    }

    return pid;
}

int
kqueue()
{
    int ret = -1;

    DEBUG_LOG("run kqueue\n");

    if (unlikely(inited == 0)) {
        errno = ENOSYS;
        return -1;
    }

    SYSCALL(FF_SO_KQUEUE, NULL);

    if (ret >= 0) {
        ret = convert_fstack_fd(ret);
    }

    DEBUG_LOG("get fd:%d\n", ret);

    return ret;
}

int
kevent(int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents,
    const struct timespec *timeout)
{
    int i;
    int maxevents = nevents;
    struct kevent *kev;

    DEBUG_LOG("kq:%d, nchanges:%d, nevents:%d\n", kq, nchanges, nevents);

    if (unlikely(inited == 0 && ff_adapter_init() < 0)) {
        errno = ENOSYS;
        return -1;
    }

    kq = restore_fstack_fd(kq);

    DEFINE_REQ_ARGS_STATIC(kevent);
    static __thread struct kevent *sh_changelist = NULL;
    static __thread int sh_changelist_len = 0;
    static __thread struct kevent *sh_eventlist = NULL;
    static __thread int sh_eventlist_len = 0;

    if (changelist != NULL && nchanges > 0) {
        if (sh_changelist == NULL || sh_changelist_len < nchanges) {
            if (sh_changelist) {
                share_mem_free(sh_changelist);
            }

            sh_changelist_len = nchanges;
            sh_changelist = share_mem_alloc(sizeof(struct kevent) * sh_changelist_len);
            if (sh_changelist == NULL) {
                RETURN_ERROR_NOFREE(ENOMEM);
            }
        }
        rte_memcpy(sh_changelist, changelist, sizeof(struct kevent) * nchanges);

        for(i = 0; i < nchanges; i++) {
            kev = (struct kevent *)&sh_changelist[i];
            switch (kev->filter) {
                case EVFILT_READ:
                case EVFILT_WRITE:
                case EVFILT_VNODE:
                    kev->ident = restore_fstack_fd(kev->ident);
                    break;
                default:
                    break;
            }
        }
        args->changelist = sh_changelist;
        args->nchanges = nchanges;
    } else {
        args->changelist = NULL;
        args->nchanges = 0;
    }

    if (eventlist != NULL && nevents > 0) {
        if (sh_eventlist == NULL || sh_eventlist_len < nevents) {
            if (sh_eventlist) {
                share_mem_free(sh_eventlist);
            }

            sh_eventlist_len = nevents;
            sh_eventlist = share_mem_alloc(sizeof(struct kevent) * sh_eventlist_len);
            if (sh_eventlist == NULL) {
                //share_mem_free(sh_changelist); // don't free
                RETURN_ERROR_NOFREE(ENOMEM);
            }
        }
        args->eventlist = sh_eventlist;
        args->nevents = nevents;
    } else {
        args->eventlist = NULL;
        args->nevents = 0;
    }

    args->kq = kq;
    args->timeout = (struct timespec *)timeout;

    ACQUIRE_ZONE_LOCK(FF_SC_IDLE);
    //rte_spinlock_lock(&sc->lock);

    sc->ops = FF_SO_KEVENT;
    sc->args = args;
    sc->status = FF_SC_REQ;

    /*
     * sc->result, sc->error must reset in epoll_wait and kevent.
     * Otherwise can access last sc call's result.
     *
     * Because if sem_timedwait timeouted, but fstack instance still
     * call sem_post later, and next or next's next sem_timedwait will
     * return 0 directly, then get invalid result and error.
     */
    sc->result = 0;
    sc->error = 0;
    errno = 0;
    if (timeout == NULL) {
        need_alarm_sem = 1;
    }

    rte_spinlock_unlock(&sc->lock);

    if (timeout != NULL) {
        struct timespec abs_timeout;

        clock_gettime(CLOCK_REALTIME, &abs_timeout);
        abs_timeout.tv_sec += timeout->tv_sec;
        abs_timeout.tv_nsec += timeout->tv_nsec;
        if (abs_timeout.tv_nsec > NS_PER_SECOND) {
            abs_timeout.tv_nsec -= NS_PER_SECOND;
            abs_timeout.tv_sec += 1;
        }
        if (unlikely(abs_timeout.tv_sec < 0 || abs_timeout.tv_nsec < 0)) {
            ERR_LOG("invalid timeout argument, the sec:%ld, nsec:%ld\n",
                abs_timeout.tv_sec, abs_timeout.tv_nsec);
            errno = EINVAL;
            ret = -1;
        } else {
            ret = sem_timedwait(&sc->wait_sem, &abs_timeout);
        }
    } else {
        ret = sem_wait(&sc->wait_sem);
    }

    rte_spinlock_lock(&sc->lock);

    if (timeout == NULL) {
        need_alarm_sem = 0;
    }

    /*
     * After sem_timedwait, and before lock sc, sc->status may be modify from FF_SC_REQ to FF_SC_RSP,
     * so it can't use to check.
     *
     * And only ret == 0, means sem_timedwait return normal,
     * can set ret = sc->result, otherwise may use last sc->result.
     */
    if (ret == -1 && errno == ETIMEDOUT /* sc->status == FF_SC_REQ */) {
        ret = 0;
    } else if (ret == 0) {
        ret = sc->result;
        if (ret < 0) {
            errno = sc->error;
        }
    }

    sc->status = FF_SC_IDLE;

    rte_spinlock_unlock(&sc->lock);

    if (ret > 0) {
        if (eventlist && nevents) {
            if (unlikely(nevents > maxevents)) {
                ERR_LOG("return events:%d, maxevents:%d, set return events to maxevents, may be some error occur\n",
                    nevents, maxevents);
                nevents = maxevents;
            }
            rte_memcpy(eventlist, sh_eventlist,
                sizeof(struct kevent) * ret);

            for (i = 0; i < nevents; i++) {
                kev = &eventlist[i];
                kev->ident = convert_fstack_fd(kev->ident);
            }
        }
    }

    /*
         * Don't free, to improve performance.
         * Will cause memory leak while APP exit , but fstack adapter not exit.
         * May set them as gloabl variable and free in thread_destructor.
         */
    /*if (sh_changelist) {
        share_mem_free(sh_changelist);
        sh_changelist = NULL;
    }

    if (sh_eventlist) {
        share_mem_free(sh_eventlist);
        sh_eventlist = NULL;
    }*/

    RETURN_NOFREE();
}

static void
thread_destructor(void *sc)
{
#ifdef FF_THREAD_SOCKET
    DEBUG_LOG("pthread self tid:%lu, detach sc:%p\n", pthread_self(), sc);
    ff_detach_so_context(sc);
    sc = NULL;
#endif

    if (shutdown_args) {
        share_mem_free(shutdown_args);
    }
    if (getsockname_args) {
        share_mem_free(getsockname_args);
    }
    if (getpeername_args) {
        share_mem_free(getpeername_args);
    }
    if (setsockopt_args) {
        share_mem_free(setsockopt_args);
    }
    if (accept_args) {
        share_mem_free(accept_args);
    }
    if (connect_args) {
        share_mem_free(connect_args);
    }
    if (recvfrom_args) {
        share_mem_free(recvfrom_args);
    }
    if (recvmsg_args) {
        share_mem_free(recvmsg_args);
    }
    if (read_args) {
        share_mem_free(read_args);
    }
    if (readv_args) {
        share_mem_free(readv_args);
    }
    if (sendto_args) {
        share_mem_free(sendto_args);
    }
    if (sendmsg_args) {
        share_mem_free(sendmsg_args);
    }
    if (write_args) {
        share_mem_free(write_args);
    }
    if (writev_args) {
        share_mem_free(writev_args);
    }
    if (close_args) {
        share_mem_free(close_args);
    }
    if (ioctl_args) {
        share_mem_free(ioctl_args);
    }
    if (fcntl_args) {
        share_mem_free(fcntl_args);
    }
    if (epoll_ctl_args) {
        share_mem_free(epoll_ctl_args);
    }
    if (epoll_wait_args) {
        share_mem_free(epoll_wait_args);
    }
    if (kevent_args) {
        share_mem_free(kevent_args);
    }

    if (sh_iov_static) {
        iovec_share2local_s();
        iovec_share_free(sh_iov_static, IOV_MAX);
    }
}

void __attribute__((destructor))
ff_adapter_exit()
{
    pthread_key_delete(key);

#ifndef FF_THREAD_SOCKET

#ifdef FF_MULTI_SC
    if (current_worker_id == worker_id) {
        int i;
        for (i = 0; i < worker_id; i++) {
            ERR_LOG("pthread self tid:%lu, detach sc:%p\n", pthread_self(), scs[i].sc);
            ff_so_zone = ff_so_zones[i];
            ff_detach_so_context(scs[i].sc);
        }
    } else
#endif
    {
        ERR_LOG("pthread self tid:%lu, detach sc:%p\n", pthread_self(), sc);
        ff_detach_so_context(sc);
        sc = NULL;
    }
#endif
}

int
ff_adapter_init()
//int __attribute__((constructor))
//ff_adapter_init(int argc, char * const argv[])
{
    int ret;

    ERR_LOG("inited:%d, proc_inited:%d\n", inited, proc_inited);

#ifndef FF_MULTI_SC
    if (inited) {
        return 0;
    }
#endif

    if (proc_inited == 0) {
        /* May conflict */
        rte_spinlock_init(&worker_id_lock);
        rte_spinlock_lock(&worker_id_lock);

        pthread_key_create(&key, thread_destructor);
        DEBUG_LOG("pthread key:%d\n", key);

        //atexit(ff_adapter_exit);
        //on_exit(ff_adapter_exit, NULL);

        /*
         * get ulimit -n to distinguish fd between kernel and F-Stack
         */
        struct rlimit rlmt;
        ret = getrlimit(RLIMIT_NOFILE, &rlmt);
        if (ret < 0) {
            ERR_LOG("getrlimit(RLIMIT_NOFILE) failed, use default ff_kernel_max_fd:%d\n", ff_kernel_max_fd);
            return -1;
        } else {
            ff_kernel_max_fd = (int)rlmt.rlim_cur;
        }
        ERR_LOG("getrlimit(RLIMIT_NOFILE) successed, sed ff_kernel_max_fd:%d, and rlim_max is %ld\n",
            ff_kernel_max_fd, rlmt.rlim_max);

        /*
         * Get environment variable FF_INITIAL_LCORE_ID to set initial_lcore_id
         *
         * If need later, modify to get config from config file,
         * it can consider multiplex F-Stack config.ini
         */
        char *ff_init_lcore_id = getenv(FF_INITIAL_LCORE_ID_STR);
        if (ff_init_lcore_id != NULL) {
            initial_lcore_id = (uint64_t)strtoull(ff_init_lcore_id, NULL, 16);
            if (initial_lcore_id > ((uint64_t)INITIAL_LCORE_ID_MAX) /*== UINT64_MAX*/) {
                initial_lcore_id = INITIAL_LCORE_ID_DEFAULT;
                ERR_LOG("get invalid FF_INITIAL_LCORE_ID=%s, to use default value 0x%0lx\n",
                    ff_init_lcore_id, initial_lcore_id);
            }
            ERR_LOG("get FF_INITIAL_LCORE_ID=%s, use 0x%0lx\n",
                ff_init_lcore_id, initial_lcore_id);
        }
        else {
            ERR_LOG("environment variable FF_INITIAL_LCORE_ID not found, to use default value 0x%0lx\n",
                initial_lcore_id);
        }

        /*
         * Get environment variable FF_NB_FSTACK_INSTANCE to set nb_procs.
         */
        char *ff_nb_procs = getenv(FF_NB_FSTACK_INSTANCE_STR);
        if (ff_nb_procs != NULL) {
            nb_procs = (uint32_t)strtoul(ff_nb_procs, NULL, 10);
            if (nb_procs == -1 /*UINT32_MAX*/) {
                nb_procs = NB_FSTACK_INSTANCE_DEFAULT;
                ERR_LOG("get invalid FF_NB_FSTACK_INSTANCE=%s, to use default value %d\n",
                    ff_nb_procs, nb_procs);
            }
            ERR_LOG("get FF_NB_FSTACK_INSTANCE=%s, use %d\n",
                ff_nb_procs, nb_procs);
        }
        else {
            ERR_LOG("environment variable FF_NB_FSTACK_INSTANCE not found, to use default value %d\n",
                nb_procs);
        }

        /*
         * Get environment variable FF_PROC_ID to set worker_id.
         */
        char *ff_worker_id = getenv(FF_PROC_ID_STR);
        if (ff_worker_id != NULL) {
            worker_id = (uint32_t)strtoul(ff_worker_id, NULL, 10);
            if (worker_id == -1 /*UINT32_MAX*/) {
                worker_id = WORKER_ID_DEFAULT;
                ERR_LOG("get invalid FF_PROC_ID=%s, to use default value %d\n",
                    ff_worker_id, worker_id);
            }
            ERR_LOG("get FF_PROC_ID=%s, use %d\n",
                ff_worker_id, worker_id);
        }
        else {
            ERR_LOG("environment variable FF_PROC_ID not found, to use default value %d\n",
                worker_id);
        }

        char buf[RTE_MAX_LCORE] = {0};
        sprintf(buf, "-c%lx", initial_lcore_id/* << worker_id*/);

        char *dpdk_argv[] = {
            "ff-adapter", buf, "-n4",
            "--proc-type=secondary",
            /* RTE_LOG_WARNING */
            "--log-level=5",
        };

        printf("\n");
        DEBUG_LOG("rte_eal_init, argc:%ld/%ld=%ld\n", sizeof(dpdk_argv), sizeof(dpdk_argv[0]), sizeof(dpdk_argv)/sizeof(dpdk_argv[0]));
        for (int i=0; i < sizeof(dpdk_argv)/sizeof(dpdk_argv[0]); i++) {
            printf("%s ", dpdk_argv[i]);
        }
        printf("\n");
        ret = rte_eal_init(sizeof(dpdk_argv)/sizeof(dpdk_argv[0]),
            dpdk_argv);
        DEBUG_LOG("rte_eal_init ret:%d\n", ret);
        if (ret < 0) {
            ERR_LOG("ff_adapter_init failed with EAL initialization\n");
            return ret;
        }

        if (proc_inited == 0) {
            proc_inited = 1;
        }
    } else {
        rte_spinlock_lock(&worker_id_lock);
    }

    DEBUG_LOG("worker_id:%d, nb_procs:%d\n", worker_id, nb_procs);
    sc = ff_attach_so_context(worker_id % nb_procs);
    if (sc == NULL) {
        ERR_LOG("ff_attach_so_context failed\n");
        return -1;
    }

    pthread_setspecific(key, sc);

#ifdef FF_MULTI_SC
    scs[worker_id].worker_id = worker_id;
    scs[worker_id].fd = -1;
    scs[worker_id].sc = sc;
#endif
    worker_id++;
    inited = 1;

    rte_spinlock_unlock(&worker_id_lock);

    ERR_LOG("ff_adapter_init success, sc:%p, status:%d, ops:%d\n", sc, sc->status, sc->ops);

    return 0;
}

void
alarm_event_sem()
{
#ifndef FF_THREAD_SOCKET
    DEBUG_LOG("check whether need to alarm sem sc:%p, status:%d, ops:%d, need_alarm_sem:%d\n",
        sc, sc->status, sc->ops, need_alarm_sem);
    rte_spinlock_lock(&sc->lock);
    if (need_alarm_sem == 1) {
        ERR_LOG("alarm sc:%p, status:%d, ops:%d\n", sc, sc->status, sc->ops);
        sem_post(&sc->wait_sem);
        need_alarm_sem = 0;
    }
    rte_spinlock_unlock(&sc->lock);

    DEBUG_LOG("finish alarm sem sc:%p, status:%d, ops:%d, need_alarm_sem:%d\n",
        sc, sc->status, sc->ops, need_alarm_sem);
#endif
}

