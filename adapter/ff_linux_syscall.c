#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>

#include "ff_socket_ops.h"
#include "ff_linux_syscall.h"

#define SYSCALL(symbol, para) {                 \
    if (linux_syscall_inited == 0) {            \
        if (linux_syscall_init() != 0) {        \
            return -1;                          \
        }                                       \
    }                                           \
    if (syscalls.pf_##symbol) {                 \
        return syscalls.pf_##symbol para;       \
    }                                           \
    errno = ENOSYS;                             \
    return -1;                                  \
}

struct ff_linux_syscall {
    #define FF_SYSCALL_DECL(ret, fn, args)  ret (*pf_##fn) args;
    #include "ff_declare_syscalls.h"
};

static int linux_syscall_inited;

static struct ff_linux_syscall syscalls = { 0 };

static void *linux_lib_handle = NULL;

pthread_mutex_t syscall_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline int
linux_syscall_load_symbol()
{
    linux_lib_handle = dlopen ("libc.so.6", RTLD_NOW | RTLD_GLOBAL);
    if (linux_lib_handle == NULL) {
        ERR_LOG("cannot dlopen libc.so.6] err_string=%s", dlerror());
        return -1;
    }

    #define FF_SYSCALL_DECL(ret, fn, args)  \
    syscalls.pf_##fn = (typeof(syscalls.pf_##fn))dlsym(linux_lib_handle, #fn);
    #include <ff_declare_syscalls.h>

    return 0;
}

static inline int
linux_syscall_init()
{
    if (linux_syscall_inited) {
      return 0;
    }

    pthread_mutex_lock(&syscall_init_mutex);
    if (linux_syscall_inited) {
        pthread_mutex_unlock(&syscall_init_mutex);
        return 0;
    }

    if (linux_syscall_load_symbol() != 0) {
        pthread_mutex_unlock(&syscall_init_mutex);
        return -1;
    }

    linux_syscall_inited = 1;

    pthread_mutex_unlock(&syscall_init_mutex);

    return 0;
}

int
ff_linux_socket(int domain, int type, int protocol)
{
    DEBUG_LOG("ff_linux_socket, domain:%d, type:%d, protocol:%d\n", domain, type, protocol);
    SYSCALL(socket, (domain, type, protocol));
}

int
ff_linux_bind(int s, const struct sockaddr *addr,
    socklen_t addrlen)
{
    SYSCALL(bind, (s, addr, addrlen));
}

int
ff_linux_listen(int s, int backlog)
{
    SYSCALL(listen, (s, backlog));
}

int ff_linux_shutdown(int s, int how)
{
    SYSCALL(shutdown, (s, how));
}

int ff_linux_getsockname(int s, struct sockaddr *name,
    socklen_t *namelen)
{
    SYSCALL(getsockname, (s, name, namelen));
}

int ff_linux_getpeername(int s, struct sockaddr *name,
    socklen_t *namelen)
{
    SYSCALL(getpeername, (s, name, namelen));
}

int ff_linux_getsockopt(int s, int level, int optname,
    void *optval, socklen_t *optlen)
{
    SYSCALL(getsockopt, (s, level, optname, optval, optlen));
}

int ff_linux_setsockopt(int s, int level, int optname,
    const void *optval, socklen_t optlen)
{
    SYSCALL(setsockopt, (s, level, optname, optval, optlen));
}

int ff_linux_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
    SYSCALL(accept, (s, addr, addrlen));
}

int ff_linux_accept4(int s, struct sockaddr *addr,
    socklen_t *addrlen, int flags)
{
    SYSCALL(accept4, (s, addr, addrlen, flags));
}

int ff_linux_connect(int s, const struct sockaddr *addr,
    socklen_t addrlen)
{
    SYSCALL(connect, (s, addr, addrlen));
}

ssize_t ff_linux_recv(int s, void *buf, size_t len, int flags)
{
    SYSCALL(recv, (s, buf, len, flags));
}

ssize_t ff_linux_send(int s, const void *buf, size_t len, int flags)
{
    SYSCALL(send, (s, buf, len, flags));
}

ssize_t ff_linux_read(int s, void *buf, size_t len)
{
    SYSCALL(read, (s, buf, len));
}

ssize_t ff_linux_write(int s, const void *buf, size_t len)
{
    SYSCALL(write, (s, buf, len));
}

ssize_t ff_linux_writev(int s, const struct iovec *iov, int iovcnt)
{
    SYSCALL(writev, (s, iov, iovcnt));
}

ssize_t ff_linux_readv(int s, const struct iovec *iov, int iovcnt)
{
    SYSCALL(readv, (s, iov, iovcnt));
}

ssize_t ff_linux_sendto(int s, const void *buf, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
    SYSCALL(sendto, (s, buf, len, flags, to, tolen));
}

ssize_t ff_linux_recvfrom(int s, void *buf, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen)

{
    SYSCALL(recvfrom, (s, buf, len, flags, from, fromlen));
}

ssize_t ff_linux_sendmsg(int s, const struct msghdr *msg, int flags)
{
    SYSCALL(sendmsg, (s, msg, flags));
}

ssize_t ff_linux_recvmsg(int s, struct msghdr *msg, int flags)
{
    SYSCALL(recvmsg, (s, msg, flags))
}

int ff_linux_close(int s)
{
    SYSCALL(close, (s));
}

int ff_linux_ioctl(int s, unsigned long req, unsigned long data)
{
    SYSCALL(ioctl, (s, req, data));
}

int ff_linux_fcntl(int s, int cmd, unsigned long data)
{
    SYSCALL(fcntl, (s, cmd, data));
}

int ff_linux_epoll_create(int size)
{
    DEBUG_LOG("ff_linux_epoll_create, fdsize:%d\n", size);
    SYSCALL(epoll_create, (size));
}

int ff_linux_epoll_ctl(int epfd, int op, int fd,
    struct epoll_event *event)
{
    DEBUG_LOG("ff_linux_epoll_ctl, epfd:%d, op:%d, fd:%d\n", epfd, op, fd);
    SYSCALL(epoll_ctl, (epfd, op, fd, event));
}

int
ff_linux_epoll_wait(int epfd, struct epoll_event *events,
    int maxevents, int timeout)
{
    DEBUG_LOG("ff_linux_epoll_wait, epfd:%d, maxevents:%d, timeout:%d\n", epfd, maxevents, timeout);
    SYSCALL(epoll_wait, (epfd, events, maxevents, timeout));
}

pid_t
ff_linux_fork(void)
{
    SYSCALL(fork, ());
}

