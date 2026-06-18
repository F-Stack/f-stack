/*
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Derived in part from libuinet's uinet_host_interface.c.
 */

#ifdef FF_KERNEL_COEXIST
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* for accept4(2) / epoll_create1(2) */
#endif
#endif /* FF_KERNEL_COEXIST */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#ifdef FF_KERNEL_COEXIST
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#endif /* FF_KERNEL_COEXIST */
#include <pthread.h>
#include <sched.h>
#include <time.h>

#include <openssl/rand.h>
#include <rte_malloc.h>

#include "ff_host_interface.h"
#include "ff_errno.h"
#include "ff_log.h"

static struct timespec current_ts;
extern void* ff_mem_get_page();
extern int ff_mem_free_addr(void* p);

void *
ff_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset)
{
    //return rte_malloc("", len, 4096);
    int host_prot;
    int host_flags;

#ifdef FF_USE_PAGE_ARRAY
        if( len == 4096 ){
            return ff_mem_get_page();
        }
        else
#endif
        {

    assert(ff_PROT_NONE == PROT_NONE);
    host_prot = 0;
    if ((prot & ff_PROT_READ) == ff_PROT_READ)   host_prot |= PROT_READ;
    if ((prot & ff_PROT_WRITE) == ff_PROT_WRITE) host_prot |= PROT_WRITE;

    host_flags = 0;
    if ((flags & ff_MAP_SHARED) == ff_MAP_SHARED)   host_flags |= MAP_SHARED;
    if ((flags & ff_MAP_PRIVATE) == ff_MAP_PRIVATE) host_flags |= MAP_PRIVATE;
    if ((flags & ff_MAP_ANON) == ff_MAP_ANON)       host_flags |= MAP_ANON;

    void *ret = (mmap(addr, len, host_prot, host_flags, fd, offset));

    if (ret == MAP_FAILED) {
        ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_LIB, "fst mmap failed:%s\n", strerror(errno));
        exit(1);
    }
    return ret;
    }
}

int
ff_munmap(void *addr, uint64_t len)
{
#ifdef FF_USE_PAGE_ARRAY
        if ( len == 4096 ){
            return ff_mem_free_addr(addr);
        }
#endif
    //rte_free(addr);
    //return 0;
    return (munmap(addr, len));
}


void *
ff_malloc(uint64_t size)
{
    //return rte_malloc("", size, 0);
    return (malloc(size));
}


void *
ff_calloc(uint64_t number, uint64_t size)
{
    //return rte_calloc("", number, size, 0);
    return (calloc(number, size));
}


void *
ff_realloc(void *p, uint64_t size)
{
    if (size) {
        //return rte_realloc(p, size, 0);
        return (realloc(p, size));
    }

    return (p);
}


void
ff_free(void *p)
{
    //rte_free(p);
    free(p);
}

void panic(const char *, ...) __attribute__((__noreturn__));

const char *panicstr = NULL;

void
panic(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    abort();
}

void
ff_clock_gettime(int id, int64_t *sec, long *nsec)
{
    struct timespec ts;
    int host_id;
    int rv;

    switch (id) {
    case ff_CLOCK_REALTIME:
        host_id = CLOCK_REALTIME;
        break;
#ifdef CLOCK_MONOTONIC_FAST
    case ff_CLOCK_MONOTONIC_FAST:
        host_id = CLOCK_MONOTONIC_FAST;
        break;
#endif
    case ff_CLOCK_MONOTONIC:
    default:
        host_id = CLOCK_MONOTONIC;
        break;
    }

    rv = clock_gettime(host_id, &ts);
    assert(0 == rv);

    *sec = (int64_t)ts.tv_sec;
    *nsec = (long)ts.tv_nsec;
}

uint64_t
ff_clock_gettime_ns(int id)
{
    int64_t sec;
    long nsec;

    ff_clock_gettime(id, &sec, &nsec);

    return ((uint64_t)sec * ff_NSEC_PER_SEC + nsec);
}

void
ff_get_current_time(time_t *sec, long *nsec)
{
    if (sec) {
        *sec = current_ts.tv_sec;
    }

    if (nsec) {
        *nsec = current_ts.tv_nsec;
    }
}

void
ff_update_current_ts()
{
    int rv = clock_gettime(CLOCK_REALTIME, &current_ts);
    assert(rv == 0);
}

void
ff_arc4rand(void *ptr, unsigned int len, int reseed)
{
    (void)reseed;

    RAND_bytes(ptr, len);
}

uint32_t
ff_arc4random(void)
{
    uint32_t ret;
    ff_arc4rand(&ret, sizeof ret, 0);
    return ret;
}

int ff_setenv(const char *name, const char *value)
{
    return setenv(name, value, 1);
}

char *ff_getenv(const char *name)
{
    return getenv(name);
}

#ifdef FF_KERNEL_COEXIST
/*
 * Native dual-stack fd map (single-threaded per F-Stack instance, like the
 * adapter's fstack_kernel_fd_map): F-Stack fd -> paired host kernel fd, 0=none.
 */
#define FF_MAX_FREEBSD_FILES 65536
static int ff_native_fd_map[FF_MAX_FREEBSD_FILES];

int
ff_native_map_get(int fstack_fd)
{
    if (fstack_fd < 0 || fstack_fd >= FF_MAX_FREEBSD_FILES)
        return 0;
    return ff_native_fd_map[fstack_fd];
}

void
ff_native_map_set(int fstack_fd, int host_fd)
{
    if (fstack_fd >= 0 && fstack_fd < FF_MAX_FREEBSD_FILES)
        ff_native_fd_map[fstack_fd] = host_fd;
}

void
ff_native_map_clear(int fstack_fd)
{
    if (fstack_fd >= 0 && fstack_fd < FF_MAX_FREEBSD_FILES)
        ff_native_fd_map[fstack_fd] = 0;
}

/*
 * Host kernel-stack bridge for native-mode coexistence. Operate on RAW host
 * fds; sockaddr / epoll_event arrive as void* (linux_sockaddr layout matches
 * the host sockaddr). The host libc sets errno on failure.
 */
int
ff_host_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

/*
 * Force a host AF_INET6 socket to v6-only so a dual-stack pair can share a
 * port with the paired host AF_INET socket (host net.ipv6.bindv6only may be 0).
 */
int
ff_host_set_v6only(int fd)
{
    int on = 1;
    return setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
}

int
ff_host_bind(int fd, const void *addr, socklen_t addrlen)
{
    return bind(fd, (const struct sockaddr *)addr, addrlen);
}

int
ff_host_listen(int fd, int backlog)
{
    return listen(fd, backlog);
}

int
ff_host_accept(int fd, void *addr, socklen_t *addrlen)
{
    return accept(fd, (struct sockaddr *)addr, addrlen);
}

int
ff_host_connect(int fd, const void *addr, socklen_t addrlen)
{
    return connect(fd, (const struct sockaddr *)addr, addrlen);
}

int
ff_host_close(int fd)
{
    return close(fd);
}

ssize_t
ff_host_read(int fd, void *buf, size_t nbytes)
{
    return read(fd, buf, nbytes);
}

ssize_t
ff_host_write(int fd, const void *buf, size_t nbytes)
{
    return write(fd, buf, nbytes);
}

ssize_t
ff_host_recv(int fd, void *buf, size_t len, int flags)
{
    return recv(fd, buf, len, flags);
}

ssize_t
ff_host_send(int fd, const void *buf, size_t len, int flags)
{
    return send(fd, buf, len, flags);
}

ssize_t
ff_host_sendto(int fd, const void *buf, size_t len, int flags,
    const void *to, socklen_t tolen)
{
    return sendto(fd, buf, len, flags, (const struct sockaddr *)to, tolen);
}

ssize_t
ff_host_recvfrom(int fd, void *buf, size_t len, int flags,
    void *from, socklen_t *fromlen)
{
    return recvfrom(fd, buf, len, flags, (struct sockaddr *)from, fromlen);
}

int
ff_host_accept4(int fd, void *addr, socklen_t *addrlen, int flags)
{
    return accept4(fd, (struct sockaddr *)addr, addrlen, flags);
}

int
ff_host_setsockopt(int fd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    return setsockopt(fd, level, optname, optval, optlen);
}

int
ff_host_getsockopt(int fd, int level, int optname,
    void *optval, socklen_t *optlen)
{
    return getsockopt(fd, level, optname, optval, optlen);
}

int
ff_host_fcntl(int fd, int cmd, int arg)
{
    return fcntl(fd, cmd, arg);
}

int
ff_host_epoll_create1(int flags)
{
    return epoll_create1(flags);
}

int
ff_host_epoll_ctl(int epfd, int op, int fd, void *event)
{
    return epoll_ctl(epfd, op, fd, (struct epoll_event *)event);
}

int
ff_host_epoll_wait(int epfd, void *events, int maxevents, int timeout)
{
    return epoll_wait(epfd, (struct epoll_event *)events, maxevents, timeout);
}

/*
 * Host-epoll helpers for the native kqueue coexistence path (ff_kevent). The
 * struct epoll_event stays inside this host-namespace TU; ff_kevent passes
 * plain ints (app_fd kept in data.fd) to avoid pulling the host epoll layout
 * into the FreeBSD-namespace syscall wrapper.
 */
void
ff_host_kqueue_ctl(int epfd, int del, int hfd, int app_fd, int want_write)
{
    struct epoll_event ev;

    ev.events = want_write ? EPOLLOUT : EPOLLIN;
    ev.data.fd = app_fd;
    if (del) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, hfd, &ev);
    } else if (epoll_ctl(epfd, EPOLL_CTL_ADD, hfd, &ev) < 0 &&
        errno == EEXIST) {
        epoll_ctl(epfd, EPOLL_CTL_MOD, hfd, &ev);
    }
}

/*
 * Poll the host epoll non-blocking and emit (app_fd, is_write, is_eof) triples
 * so ff_kevent can rebuild struct kevent entries. Returns the event count.
 */
int
ff_host_kqueue_poll(int epfd, int *triples, int maxevents)
{
    struct epoll_event evs[maxevents];
    int n, i;

    n = epoll_wait(epfd, evs, maxevents, 0);
    if (n <= 0)
        return 0;

    for (i = 0; i < n; i++) {
        triples[3 * i] = evs[i].data.fd;
        triples[3 * i + 1] = (evs[i].events & EPOLLOUT) ? 1 : 0;
        triples[3 * i + 2] = (evs[i].events & (EPOLLHUP | EPOLLERR)) ? 1 : 0;
    }
    return n;
}

ssize_t
ff_host_sendmsg(int fd, const void *msg, int flags)
{
    return sendmsg(fd, (const struct msghdr *)msg, flags);
}

ssize_t
ff_host_recvmsg(int fd, void *msg, int flags)
{
    return recvmsg(fd, (struct msghdr *)msg, flags);
}

int
ff_host_shutdown(int fd, int how)
{
    return shutdown(fd, how);
}

int
ff_host_getpeername(int fd, void *addr, socklen_t *addrlen)
{
    return getpeername(fd, (struct sockaddr *)addr, addrlen);
}

int
ff_host_getsockname(int fd, void *addr, socklen_t *addrlen)
{
    return getsockname(fd, (struct sockaddr *)addr, addrlen);
}

/* iov is a host 'struct iovec *' passed as void* (same ABI as FreeBSD). */
ssize_t
ff_host_readv(int fd, const void *iov, int iovcnt)
{
    return readv(fd, (const struct iovec *)iov, iovcnt);
}

ssize_t
ff_host_writev(int fd, const void *iov, int iovcnt)
{
    return writev(fd, (const struct iovec *)iov, iovcnt);
}

/* request is the raw Linux ioctl request (host namespace, not translated). */
int
ff_host_ioctl(int fd, unsigned long request, void *argp)
{
    return ioctl(fd, request, argp);
}

int
ff_host_dup(int fd)
{
    return dup(fd);
}

int
ff_host_dup2(int oldfd, int newfd)
{
    return dup2(oldfd, newfd);
}
#endif /* FF_KERNEL_COEXIST */

void ff_os_errno(int error)
{
    switch (error) {
        case ff_EPERM:       errno = EPERM; break;
        case ff_ENOENT:      errno = ENOENT; break;
        case ff_ESRCH:       errno = ESRCH; break;
        case ff_EINTR:       errno = EINTR; break;
        case ff_EIO:         errno = EIO; break;
        case ff_ENXIO:       errno = ENXIO; break;
        case ff_E2BIG:       errno = E2BIG; break;
        case ff_ENOEXEC:     errno = ENOEXEC; break;
        case ff_EBADF:       errno = EBADF; break;
        case ff_ECHILD:      errno = ECHILD; break;
        case ff_EDEADLK:     errno = EDEADLK; break;
        case ff_ENOMEM:      errno = ENOMEM; break;
        case ff_EACCES:      errno = EACCES; break;
        case ff_EFAULT:      errno = EFAULT; break;
        case ff_ENOTBLK:     errno = ENOTBLK; break;
        case ff_EBUSY:       errno = EBUSY; break;
        case ff_EEXIST:      errno = EEXIST; break;
        case ff_EXDEV:       errno = EXDEV; break;
        case ff_ENODEV:      errno = ENODEV; break;
        case ff_ENOTDIR:     errno = ENOTDIR; break;
        case ff_EISDIR:      errno = EISDIR; break;
        case ff_EINVAL:      errno = EINVAL; break;
        case ff_ENFILE:      errno = ENFILE; break;
        case ff_EMFILE:      errno = EMFILE; break;
        case ff_ENOTTY:      errno = ENOTTY; break;
        case ff_ETXTBSY:     errno = ETXTBSY; break;
        case ff_EFBIG:       errno = EFBIG; break;
        case ff_ENOSPC:      errno = ENOSPC; break;
        case ff_ESPIPE:      errno = ESPIPE; break;
        case ff_EROFS:       errno = EROFS; break;
        case ff_EMLINK:      errno = EMLINK; break;
        case ff_EPIPE:       errno = EPIPE; break;
        case ff_EDOM:        errno = EDOM; break;
        case ff_ERANGE:      errno = ERANGE; break;

        /* case ff_EAGAIN:       same as EWOULDBLOCK */
        case ff_EWOULDBLOCK:     errno = EWOULDBLOCK; break;

        case ff_EINPROGRESS:     errno = EINPROGRESS; break;
        case ff_EALREADY:        errno = EALREADY; break;
        case ff_ENOTSOCK:        errno = ENOTSOCK; break;
        case ff_EDESTADDRREQ:    errno = EDESTADDRREQ; break;
        case ff_EMSGSIZE:        errno = EMSGSIZE; break;
        case ff_EPROTOTYPE:      errno = EPROTOTYPE; break;
        case ff_ENOPROTOOPT:     errno = ENOPROTOOPT; break;
        case ff_EPROTONOSUPPORT: errno = EPROTONOSUPPORT; break;
        case ff_ESOCKTNOSUPPORT: errno = ESOCKTNOSUPPORT; break;

        /* case ff_EOPNOTSUPP:   same as ENOTSUP */
        case ff_ENOTSUP:         errno = ENOTSUP; break;

        case ff_EPFNOSUPPORT:    errno = EPFNOSUPPORT; break;
        case ff_EAFNOSUPPORT:    errno = EAFNOSUPPORT; break;
        case ff_EADDRINUSE:      errno = EADDRINUSE; break;
        case ff_EADDRNOTAVAIL:   errno = EADDRNOTAVAIL; break;
        case ff_ENETDOWN:        errno = ENETDOWN; break;
        case ff_ENETUNREACH:     errno = ENETUNREACH; break;
        case ff_ENETRESET:       errno = ENETRESET; break;
        case ff_ECONNABORTED:    errno = ECONNABORTED; break;
        case ff_ECONNRESET:      errno = ECONNRESET; break;
        case ff_ENOBUFS:         errno = ENOBUFS; break;
        case ff_EISCONN:         errno = EISCONN; break;
        case ff_ENOTCONN:        errno = ENOTCONN; break;
        case ff_ESHUTDOWN:       errno = ESHUTDOWN; break;
        case ff_ETOOMANYREFS:    errno = ETOOMANYREFS; break;
        case ff_ETIMEDOUT:       errno = ETIMEDOUT; break;
        case ff_ECONNREFUSED:    errno = ECONNREFUSED; break;
        case ff_ELOOP:           errno = ELOOP; break;
        case ff_ENAMETOOLONG:    errno = ENAMETOOLONG; break;
        case ff_EHOSTDOWN:       errno = EHOSTDOWN; break;
        case ff_EHOSTUNREACH:    errno = EHOSTUNREACH; break;
        case ff_ENOTEMPTY:       errno = ENOTEMPTY; break;
        case ff_EUSERS:      errno = EUSERS; break;
        case ff_EDQUOT:      errno = EDQUOT; break;
        case ff_ESTALE:      errno = ESTALE; break;
        case ff_EREMOTE:     errno = EREMOTE; break;
        case ff_ENOLCK:      errno = ENOLCK; break;
        case ff_ENOSYS:      errno = ENOSYS; break;
        case ff_EIDRM:       errno = EIDRM; break;
        case ff_ENOMSG:      errno = ENOMSG; break;
        case ff_EOVERFLOW:   errno = EOVERFLOW; break;
        case ff_ECANCELED:   errno = ECANCELED; break;
        case ff_EILSEQ:      errno = EILSEQ; break;
        case ff_EBADMSG:     errno = EBADMSG; break;
        case ff_EMULTIHOP:   errno = EMULTIHOP; break;
        case ff_ENOLINK:     errno = ENOLINK; break;
        case ff_EPROTO:      errno = EPROTO; break;
        default:              errno = error; break;
    }

}

