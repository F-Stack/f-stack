#include <assert.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <errno.h>
#include <time.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "ff_config.h"
#include "ff_socket_ops.h"
#include "ff_sysproto.h"
#include "ff_event.h"
#include "ff_hook_syscall.h"
#include "ff_linux_syscall.h"
#include "ff_adapter.h"

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

#define ACQUIRE_ZONE_LOCK(exp) do {                               \
    while (1) {                                                   \
        rte_spinlock_lock(&sc->lock);                             \
        if (sc->status == exp) {                                  \
            break;                                                \
        }                                                         \
        rte_spinlock_unlock(&sc->lock);                           \
        rte_pause();                                              \
    }                                                             \
} while (0)

#define RELEASE_ZONE_LOCK(s) do {                                 \
    sc->status = s;                                               \
    rte_spinlock_unlock(&sc->lock);                               \
} while (0)

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

#define RETURN() do {                                             \
    share_mem_free(args);                                         \
    return ret;                                                   \
} while (0)

#define RETURN_ERROR(err) do {                                    \
    errno = err;                                                  \
    share_mem_free(args);                                         \
    return ret;                                                   \
} while (0)

static __FF_THREAD int inited = 0;
static __FF_THREAD struct ff_so_context *sc;

/* process-level initialization flag */
static int proc_inited = 0;

/* Use from lcore 2 by default, can set by environment variable FF_INITIAL_LCORE_ID */
#define INITIAL_LCORE_ID_DEFAULT 0x4             /* lcore 2 */
#define INITIAL_LCORE_ID_MAX 0x4000000000000     /* lcore 50 */
#define FF_INITIAL_LCORE_ID_STR "FF_INITIAL_LCORE_ID"
static uint64_t initial_lcore_id = INITIAL_LCORE_ID_DEFAULT;
static int worker_id = 0;
rte_spinlock_t worker_id_lock;

/* The num of F-Stack process instance, default 1 */
#define NB_FSTACK_INSTANCE_DEFAULT   1
#define FF_NB_FSTACK_INSTANCE_STR "FF_NB_FSTACK_INSTANCE"
static int nb_procs = NB_FSTACK_INSTANCE_DEFAULT;

#define FF_KERNEL_MAX_FD_DEFAULT    1024
static int ff_kernel_max_fd = FF_KERNEL_MAX_FD_DEFAULT;

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
    DEBUG_LOG("ff_hook_socket, domain:%d, type:%d, protocol:%d\n", domain, type, protocol);
    if (unlikely(fstack_territory(domain, type, protocol) == 0)) {
        return ff_linux_socket(domain, type, protocol);
    }

    if (unlikely(type & SOCK_KERNEL) && !(type & SOCK_FSTACK)) {
        type &= ~SOCK_KERNEL;
        return ff_linux_socket(domain, type, protocol);
    }

    if (unlikely(inited == 0 && ff_adapter_init() < 0)) {
        return ff_linux_socket(domain, type, protocol);
    }

    type &= ~SOCK_FSTACK;

    DEFINE_REQ_ARGS(socket);

    args->domain = domain;
    args->type = type;
    args->protocol = protocol;

    SYSCALL(FF_SO_SOCKET, args);

    if (ret >= 0) {
        ret = convert_fstack_fd(ret);
    }

    RETURN();
}

int
ff_hook_bind(int fd, const struct sockaddr *addr,
    socklen_t addrlen)
{
    if (addr == NULL) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(bind, (fd, addr, addrlen));

    DEFINE_REQ_ARGS(bind);
    struct sockaddr *sh_addr;

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

    DEFINE_REQ_ARGS(shutdown);

    args->fd = fd;
    args->how = how;

    SYSCALL(FF_SO_SHUTDOWN, args);

    RETURN();
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

    DEFINE_REQ_ARGS(getsockname);
    struct sockaddr *sh_name;
    socklen_t *sh_namelen;

    sh_name = share_mem_alloc(*namelen);
    if (sh_name == NULL) {
        RETURN_ERROR(ENOMEM);
    }

    sh_namelen = share_mem_alloc(sizeof(socklen_t));
    if (sh_namelen == NULL) {
        share_mem_free(sh_name);
        RETURN_ERROR(ENOMEM);
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

    share_mem_free(sh_name);
    share_mem_free(sh_namelen);
    RETURN();
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

    DEFINE_REQ_ARGS(getpeername);
    struct sockaddr *sh_name;
    socklen_t *sh_namelen;

    sh_name = share_mem_alloc(*namelen);
    if (sh_name == NULL) {
        RETURN_ERROR(ENOMEM);
    }

    sh_namelen = share_mem_alloc(sizeof(socklen_t));
    if (sh_namelen == NULL) {
        share_mem_free(sh_name);
        RETURN_ERROR(ENOMEM);
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

    share_mem_free(sh_name);
    share_mem_free(sh_namelen);
    RETURN();
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
    socklen_t *sh_optlen;

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
            share_mem_free(sh_optval);
        }
        *optlen = *sh_optlen;
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

    DEFINE_REQ_ARGS(setsockopt);
    void *sh_optval = NULL;

    if (optval != NULL) {
        sh_optval = share_mem_alloc(optlen);
        if (sh_optval == NULL) {
            RETURN_ERROR(ENOMEM);
        }
    }

    args->fd = fd;
    args->level = level;
    args->name = optname;
    args->optval = sh_optval;
    args->optlen = optlen;

    SYSCALL(FF_SO_SETSOCKOPT, args);

    if (sh_optval) {
        share_mem_free(sh_optval);
    }

    RETURN();
}

int
ff_hook_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    if ((addr == NULL && addrlen != NULL) ||
        (addr != NULL && addrlen == NULL)) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(accept, (fd, addr, addrlen));

    DEFINE_REQ_ARGS(accept);
    struct sockaddr *sh_addr = NULL;
    socklen_t *sh_addrlen = NULL;

    if (addr != NULL) {
        sh_addr = share_mem_alloc(*addrlen);
        if (sh_addr == NULL) {
            RETURN_ERROR(ENOMEM);
        }

        sh_addrlen = share_mem_alloc(sizeof(socklen_t));
        if (sh_addrlen == NULL) {
            share_mem_free(sh_addr);
            RETURN_ERROR(ENOMEM);
        }
        *sh_addrlen = *addrlen;
    }

    args->fd = fd;
    args->addr = sh_addr;
    args->addrlen = sh_addrlen;

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
        share_mem_free(sh_addr);
        share_mem_free(sh_addrlen);
    }

    RETURN();
}

int
ff_hook_accept4(int fd, struct sockaddr *addr,
    socklen_t *addrlen, int flags)
{
    CHECK_FD_OWNERSHIP(accept4, (fd, addr, addrlen, flags));

    errno = ENOSYS;
    return -1;
}

int
ff_hook_connect(int fd, const struct sockaddr *addr,
    socklen_t addrlen)
{
    if (addr == NULL) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(connect, (fd, addr, addrlen));

    DEFINE_REQ_ARGS(connect);
    struct sockaddr *sh_addr;

    sh_addr = share_mem_alloc(addrlen);
    if (sh_addr == NULL) {
        RETURN_ERROR(ENOMEM);
    }
    rte_memcpy(sh_addr, addr, addrlen);

    args->fd = fd;
    args->addr = sh_addr;
    args->addrlen = addrlen;

    SYSCALL(FF_SO_CONNECT, args);

    share_mem_free(sh_addr);
    RETURN();
}

ssize_t
ff_hook_recv(int fd, void *buf, size_t len, int flags)
{
    return ff_hook_recvfrom(fd, buf, len, flags, NULL, NULL);
}

ssize_t
ff_hook_recvfrom(int fd, void *buf, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen)
{
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

    DEFINE_REQ_ARGS(recvfrom);
    void *sh_buf;
    struct sockaddr *sh_from = NULL;
    socklen_t *sh_fromlen = NULL;

    if (from != NULL) {
        sh_from = share_mem_alloc(*fromlen);
        if (sh_from == NULL) {
            RETURN_ERROR(ENOMEM);
        }

        sh_fromlen = share_mem_alloc(sizeof(socklen_t));
        if (sh_fromlen == NULL) {
            share_mem_free(sh_from);
            RETURN_ERROR(ENOMEM);
        }
    }

    sh_buf = share_mem_alloc(len);
    if (sh_buf == NULL) {
        if (sh_from) {
            share_mem_free(sh_from);
        }
        if (sh_fromlen) {
            share_mem_free(sh_fromlen);
        }
        RETURN_ERROR(ENOMEM);
    }

    args->fd = fd;
    args->buf = sh_buf;
    args->len = len;
    args->flags = flags;
    args->from = sh_from;
    args->fromlen = sh_fromlen;

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

    if (from) {
        share_mem_free(sh_from);
        share_mem_free(sh_fromlen);
    }

    share_mem_free(sh_buf);
    RETURN();
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
    if (msg == NULL || msg->msg_iov == NULL ||
        msg->msg_iovlen == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(recvmsg, (fd, msg, flags));

    DEFINE_REQ_ARGS(recvmsg);
    struct msghdr *sh_msg;

    sh_msg = msghdr_share_alloc(msg);
    if (sh_msg == NULL) {
        RETURN_ERROR(ENOMEM);
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
    RETURN();
}

ssize_t
ff_hook_read(int fd, void *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(read, (fd, buf, len));

    DEFINE_REQ_ARGS(read);
    void *sh_buf;

    sh_buf = share_mem_alloc(len);
    if (sh_buf == NULL) {
        RETURN_ERROR(ENOMEM);
    }

    args->fd = fd;
    args->buf = sh_buf;
    args->len = len;

    SYSCALL(FF_SO_READ, args);

    if (ret > 0) {
        rte_memcpy(buf, sh_buf, ret);
    }

    share_mem_free(sh_buf);
    RETURN();
}

ssize_t
ff_hook_readv(int fd, const struct iovec *iov, int iovcnt)
{
    if (iov == NULL || iovcnt == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(readv, (fd, iov, iovcnt));

    DEFINE_REQ_ARGS(readv);
    struct iovec *sh_iov;

    sh_iov = iovec_share_alloc(iov, iovcnt);
    if (sh_iov == NULL) {
        RETURN_ERROR(ENOMEM);
    }

    args->fd = fd;
    args->iov = sh_iov;
    args->iovcnt = iovcnt;

    SYSCALL(FF_SO_READV, args);

    if (ret > 0) {
        iovec_share2local(sh_iov, iov, iovcnt, ret, 1);
    }

    iovec_share_free(sh_iov, iovcnt);
    RETURN();
}

ssize_t
ff_hook_sendto(int fd, const void *buf, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(sendto, (fd, buf, len, flags, to, tolen));

    DEFINE_REQ_ARGS(sendto);
    void *sh_buf;
    void *sh_to = NULL;

    sh_buf = share_mem_alloc(len);
    if (sh_buf == NULL) {
        RETURN_ERROR(ENOMEM);
    }
    rte_memcpy(sh_buf, buf, len);

    if (to) {
        sh_to = share_mem_alloc(tolen);
        if (sh_to == NULL) {
            share_mem_free(sh_buf);
            RETURN_ERROR(ENOMEM);
        }
        rte_memcpy(sh_to, to, tolen);
    }

    args->fd = fd;
    args->buf = sh_buf;
    args->len = len;
    args->flags = flags;
    args->to = sh_to;
    args->tolen = tolen;

    SYSCALL(FF_SO_SENDTO, args);

    share_mem_free(sh_buf);
    if (sh_to) {
        share_mem_free(sh_to);
    }
    RETURN();
}

ssize_t
ff_hook_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    if (msg == NULL || msg->msg_iov == NULL ||
        msg->msg_iovlen == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(sendmsg, (fd, msg, flags));

    DEFINE_REQ_ARGS(sendmsg);
    struct msghdr *sh_msg;

    sh_msg = msghdr_share_alloc(msg);
    if (sh_msg == NULL) {
        RETURN_ERROR(ENOMEM);
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
    RETURN();
}

ssize_t
ff_hook_send(int fd, const void *buf, size_t len, int flags)
{
    return ff_hook_sendto(fd, buf, len, flags, NULL, 0);
}

ssize_t
ff_hook_write(int fd, const void *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(write, (fd, buf, len));

    DEFINE_REQ_ARGS(write);
    void *sh_buf;

    sh_buf = share_mem_alloc(len);
    if (sh_buf == NULL) {
        RETURN_ERROR(ENOMEM);
    }
    rte_memcpy(sh_buf, buf, len);

    args->fd = fd;
    args->buf = sh_buf;
    args->len = len;

    SYSCALL(FF_SO_WRITE, args);

    share_mem_free(sh_buf);
    RETURN();
}

ssize_t
ff_hook_writev(int fd, const struct iovec *iov, int iovcnt)
{
    if (iov == NULL || iovcnt == 0) {
        errno = EINVAL;
        return -1;
    }

    CHECK_FD_OWNERSHIP(writev, (fd, iov, iovcnt));

    DEFINE_REQ_ARGS(writev);
    struct iovec *sh_iov;

    sh_iov = iovec_share_alloc(iov, iovcnt);
    if (sh_iov == NULL) {
        RETURN_ERROR(ENOMEM);
    }
    iovec_local2share(sh_iov, iov, iovcnt);

    args->fd = fd;
    args->iov = sh_iov;
    args->iovcnt = iovcnt;

    SYSCALL(FF_SO_WRITEV, args);

    if (ret > 0) {
        iovec_share2local(sh_iov, iov, iovcnt, ret, 0);
    }

    iovec_share_free(sh_iov, iovcnt);
    RETURN();
}

int
ff_hook_close(int fd)
{
    CHECK_FD_OWNERSHIP(close, (fd));

    DEFINE_REQ_ARGS(close);

    args->fd = fd;

    SYSCALL(FF_SO_CLOSE, args);

    RETURN();
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

    DEFINE_REQ_ARGS(ioctl);
    unsigned long *sh_data;

    sh_data = share_mem_alloc(sizeof(int));
    if (sh_data == NULL) {
        RETURN_ERROR(ENOMEM);
    }
    *sh_data = *((int *)data);

    args->fd = fd;
    args->com = req;
    args->data = sh_data;

    SYSCALL(FF_SO_IOCTL, args);

    if (ret == 0) {
        *((int *)data) = *sh_data;
    }

    RETURN();
}

int
ff_hook_fcntl(int fd, int cmd, unsigned long data)
{
    CHECK_FD_OWNERSHIP(fcntl, (fd, cmd, data));

    DEFINE_REQ_ARGS(fcntl);

    args->fd = fd;
    args->cmd = cmd;
    args->data = data;

    SYSCALL(FF_SO_FCNTL, args);

    RETURN();
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
    DEBUG_LOG("ff_hook_epoll_create, fdsize:%d\n", fdsize);
    if (inited == 0 || ((fdsize & SOCK_KERNEL) && !(fdsize & SOCK_FSTACK)) || (fdsize >= 1 && fdsize <= 16)) {
        fdsize &= ~SOCK_KERNEL;
        return ff_linux_epoll_create(fdsize);
    }

    DEFINE_REQ_ARGS(epoll_create);

    args->size = size;

    SYSCALL(FF_SO_EPOLL_CREATE, args);

    if (ret >= 0) {
        ret = convert_fstack_fd(ret);
    }

    RETURN();
}

int
ff_hook_epoll_ctl(int epfd, int op, int fd,
    struct epoll_event *event)
{
    DEBUG_LOG("ff_hook_epoll_ctl, epfd:%d, op:%d, fd:%d\n", epfd, op, fd);
    CHECK_FD_OWNERSHIP(epoll_ctl, (epfd, op, fd, event));

    DEFINE_REQ_ARGS(epoll_ctl);
    struct epoll_event *sh_event = NULL;

    if ((!event && op != EPOLL_CTL_DEL) ||
        (op != EPOLL_CTL_ADD &&
         op != EPOLL_CTL_MOD &&
         op != EPOLL_CTL_DEL)) {
        errno = EINVAL;
        return -1;
    }

    if (event) {
        sh_event = share_mem_alloc(sizeof(struct epoll_event));
        if (sh_event == NULL) {
            RETURN_ERROR(ENOMEM);
        }
        rte_memcpy(sh_event, event, sizeof(struct epoll_event));
    }

    args->epfd = restore_fstack_fd(epfd);
    args->op = op;
    args->fd = fd;
    args->event = sh_event;

    SYSCALL(FF_SO_EPOLL_CTL, args);

    if (sh_event) {
        share_mem_free(sh_event);
    }

    RETURN();
}

int
ff_hook_epoll_wait(int epfd, struct epoll_event *events,
    int maxevents, int timeout)
{
    //DEBUG_LOG("ff_hook_epoll_wait, epfd:%d, maxevents:%d, timeout:%d\n", epfd, maxevents, timeout);
    int fd = epfd;
    CHECK_FD_OWNERSHIP(epoll_wait, (epfd, events, maxevents, timeout));

    DEFINE_REQ_ARGS(epoll_wait);
    struct epoll_event *sh_events;

    sh_events = share_mem_alloc(sizeof(struct epoll_event) * maxevents);
    if (sh_events == NULL) {
        RETURN_ERROR(ENOMEM);
    }

    args->epfd = fd;
    args->events = sh_events;
    args->maxevents = maxevents;
    args->timeout = timeout;

    /* for timeout, Although not really effective in FreeBSD stack */
    //SYSCALL(FF_SO_EPOLL_WAIT, args);
    ACQUIRE_ZONE_LOCK(FF_SC_IDLE);
    sc->ops = FF_SO_EPOLL_WAIT;
    sc->args = args;
    RELEASE_ZONE_LOCK(FF_SC_REQ);

    if (timeout > 0) {
        struct timespec abs_timeout;

        clock_gettime(CLOCK_REALTIME, &abs_timeout);
        DEBUG_LOG("before wait, sec:%ld, nsec:%ld\n", abs_timeout.tv_sec, abs_timeout.tv_nsec);
        abs_timeout.tv_sec += timeout / 1000;
        abs_timeout.tv_nsec += timeout * 1000;
        if (abs_timeout.tv_nsec > NS_PER_SECOND) {
            abs_timeout.tv_nsec -= NS_PER_SECOND;
            abs_timeout.tv_sec += 1;
        }

        DEBUG_LOG("ready to wait, sec:%ld, nsec:%ld\n", abs_timeout.tv_sec, abs_timeout.tv_nsec);
        ret = sem_timedwait(&sc->wait_sem, &abs_timeout);

        clock_gettime(CLOCK_REALTIME, &abs_timeout);
        DEBUG_LOG("after wait, sec:%ld, nsec:%ld\n", abs_timeout.tv_sec, abs_timeout.tv_nsec);
    } else {
        ret = sem_wait(&sc->wait_sem);
    }

    rte_spinlock_lock(&sc->lock);

    if (ret == -1 && sc->status == FF_SC_REQ) {
        if (errno == ETIMEDOUT) {
            ret = 0;
        }
    } else {
        ret = sc->result;
        if (ret < 0) {
            errno = sc->error;
        }
    }

    sc->status = FF_SC_IDLE;
    rte_spinlock_unlock(&sc->lock);

    if (ret > 0) {
        int i;
        for (i = 0; i < ret; i++) {
            rte_memcpy(&events[i], &sh_events[i], sizeof(struct epoll_event));
        }
    }

    if (sh_events) {
        share_mem_free(sh_events);
    }

    RETURN();
}

pid_t
ff_hook_fork(void)
{
    return ff_linux_fork();
}

int
kqueue()
{
    int ret = -1;

    if (unlikely(inited == 0)) {
        errno = ENOSYS;
        return -1;
    }

    SYSCALL(FF_SO_KQUEUE, NULL);

    if (ret >= 0) {
        ret = convert_fstack_fd(ret);
    }

    return ret;
}

int
kevent(int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents,
    const struct timespec *timeout)
{
    if (unlikely(inited == 0 && ff_adapter_init() < 0)) {
        errno = ENOSYS;
        return -1;
    }

    kq = restore_fstack_fd(kq);

    DEFINE_REQ_ARGS(kevent);
    struct kevent *sh_changelist = NULL;
    struct kevent *sh_eventlist = NULL;

    if (changelist != NULL && nchanges > 0) {
        sh_changelist = share_mem_alloc(sizeof(struct kevent) * nchanges);
        if (sh_changelist == NULL) {
            RETURN_ERROR(ENOMEM);
        }

        rte_memcpy(sh_changelist, changelist, sizeof(struct kevent) * nchanges);

        struct kevent *kev;
        int i = 0;
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
    }

    if (eventlist != NULL && nevents > 0) {
        sh_eventlist = share_mem_alloc(sizeof(struct kevent) * nevents);
        if (sh_eventlist == NULL) {
            share_mem_free(sh_changelist);
            RETURN_ERROR(ENOMEM);
        }
    }

    args->kq = kq;
    args->changelist = sh_changelist;
    args->nchanges = nchanges;
    args->eventlist = sh_eventlist;
    args->nevents = nevents;
    args->timeout = NULL;

    rte_spinlock_lock(&sc->lock);

    sc->ops = FF_SO_KEVENT;
    sc->args = args;
    sc->status = FF_SC_REQ;

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

        ret = sem_timedwait(&sc->wait_sem, &abs_timeout);
    } else {
        ret = sem_wait(&sc->wait_sem);
    }

    rte_spinlock_lock(&sc->lock);

    if (ret == -1 && sc->status == FF_SC_REQ) {
        if (errno == ETIMEDOUT) {
            ret = 0;
        }
    } else {
        ret = sc->result;
        if (ret < 0) {
            errno = sc->error;
        }
    }

    sc->status = FF_SC_IDLE;

    rte_spinlock_unlock(&sc->lock);

    if (ret > 0) {
        if (eventlist && nevents) {
            rte_memcpy(eventlist, sh_eventlist,
                sizeof(struct kevent) * ret);
        }
    }

    if (sh_changelist) {
        share_mem_free(sh_changelist);
    }

    if (sh_eventlist) {
        share_mem_free(sh_eventlist);
    }

    RETURN();
}

int
ff_adapter_init()
//int __attribute__((constructor))
//ff_adapter_init(int argc, char * const argv[])
{
    int ret;

    if (inited) {
        return 0;
    }

    if (proc_inited == 0) {
        /* May conflict */
        rte_spinlock_init(&worker_id_lock);
        rte_spinlock_lock(&worker_id_lock);

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

    worker_id++;
    inited = 1;

    rte_spinlock_unlock(&worker_id_lock);

    ERR_LOG("ff_adapter_init success, sc:%p, status:%d, ops:%d\n", sc, sc->status, sc->ops);

    return 0;
}

void __attribute__((destructor))
ff_adapter_exit()
{
    ff_detach_so_context(sc);
    ERR_LOG("pthread self tid:%lu, detach sc:%p\n", pthread_self(), sc);
}
