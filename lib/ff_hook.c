/*
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
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
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "ff_api.h"
#include "ff_config.h"
#include "ff_dpdk_if.h"

#define IS_FSTACK_FD(fd) (ff_global_cfg.freebsd.fdstart && fd >= ff_global_cfg.freebsd.fdstart)

extern int ff_epoll_create(int size);
extern int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
extern int ff_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); 

static int (*real_socket)(int, int, int);
static int (*real_open)(const char *, int, ...);
static int (*real_close)(int);
static int (*real_bind)(int, const struct sockaddr*, socklen_t);
static int (*real_connect)(int, const struct sockaddr*, socklen_t);
static int (*real_listen)(int, int);
static int (*real_setsockopt)(int, int, int, const void *, socklen_t);
static int (*real_accept)(int, struct sockaddr *, socklen_t *);
static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
static ssize_t (*real_recv)(int, void *, size_t, int);
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_writev)(int, const struct iovec *, int);
static ssize_t (*real_write)(int, const void *, size_t );
static ssize_t (*real_read)(int, void *, size_t );
static ssize_t (*real_readv)(int, const struct iovec *, int);
static int (*real_ioctl)(int, int, void *);
static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
static int (*real_kqueue)(void);
static int (*real_kevent)(int, const struct kevent *, int, struct kevent *, int, const struct timespec *);
static int (*real_epoll_create)(int size);
static int (*real_epoll_ctl)(int, int, int, struct epoll_event *);
static int (*real_epoll_wait)(int, struct epoll_event *, int, int); 

#define _GNU_SOURCE
#define __USE_GNU
#include <dlfcn.h>

#define SYSCALL(func)                                       \
({                                                          \
    if (!real_##func) {                                     \
        real_##func = dlsym(RTLD_NEXT, #func);              \
    }                                                       \
    real_##func;                                            \
})


__attribute__((weak)) int
open(const char *pathname, int flags, ...)
{
    int fd;
    va_list args;

    va_start(args, flags);
    fd = SYSCALL(open)(pathname, flags, *args);
    va_end(args);

    if (IS_FSTACK_FD(fd)) {
        SYSCALL(close)(fd);
        fd = -1;
        errno = EMFILE;
    }

    return fd;
}

__attribute__((weak)) int
socket_raw(int family, int type, int protocol)
{
    int fd;

    fd = SYSCALL(socket)(family, type, protocol);
    if (IS_FSTACK_FD(fd)) {
        SYSCALL(close)(fd);
        fd = -1;
        errno = EMFILE;
    }

    return fd;
}

__attribute__((weak)) int
socket(int domain, int type, int protocol)
{
    if (!ff_global_cfg.freebsd.fdstart || (AF_INET != domain) || 
            (SOCK_STREAM != type && SOCK_DGRAM != type)) {
        return socket_raw(domain, type, protocol);
    }

    return ff_socket(domain, type, protocol);
}

__attribute__((weak)) int
bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_bind(fd, (struct linux_sockaddr *)addr, addrlen);

    } else {
        return SYSCALL(bind)(fd, addr, addrlen);
    }
}

__attribute__((weak)) int
connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_connect(fd, (struct linux_sockaddr *)addr, addrlen);

    } else {
        return SYSCALL(connect)(fd, addr, addrlen);
    }
}

__attribute__((weak)) ssize_t
send(int fd, const void *buf, size_t len, int flags)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_send(fd, buf, len, flags);

    } else {
        return SYSCALL(send)(fd, buf, len, flags);
    }
}

__attribute__((weak)) ssize_t
write(int fd, const void *buf, size_t count)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_write(fd, buf, count);

    } else {
        return SYSCALL(write)(fd, buf, count);
    }
}

__attribute__((weak)) ssize_t
recv(int fd, void *buf, size_t len, int flags)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_recv(fd, buf, len, flags);

    } else {
        return SYSCALL(recv)(fd, buf, len, flags);
    }
}

__attribute__((weak)) ssize_t
read(int fd, void *buf, size_t count)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_read(fd, buf, count);

    } else {
        return SYSCALL(read)(fd, buf, count);
    }
}

__attribute__((weak)) int
listen(int fd, int backlog)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_listen(fd, backlog);

    } else {
        return SYSCALL(listen)(fd, backlog);
    }
}

__attribute__((weak)) int
setsockopt (int fd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_setsockopt(fd, level, optname, optval, optlen);

    } else {
        return SYSCALL(setsockopt)(fd, level, optname, optval, optlen);
    }
}

__attribute__((weak)) int
accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    int nfd;

    if (IS_FSTACK_FD(fd)) {
        return ff_accept(fd, (struct linux_sockaddr *)addr, addrlen);

    } else {
        nfd = SYSCALL(accept)(fd, addr, addrlen);
        if (IS_FSTACK_FD(nfd)) {
            SYSCALL(close)(nfd);
            nfd = -1;
            errno = EMFILE;
        }

        return nfd;
    }
}

__attribute__((weak)) int
accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    return accept(fd, addr, addrlen);
}

__attribute__((weak)) int
close(int fd)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_close(fd);

    } else {
        return SYSCALL(close)(fd);
    }
}

__attribute__((weak)) ssize_t
writev(int fd, const struct iovec *iov, int iovcnt)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_writev(fd, iov, iovcnt);

    } else {
        return SYSCALL(writev)(fd, iov, iovcnt);
    }
}

__attribute__((weak)) ssize_t
readv(int fd, const struct iovec *iov, int iovcnt)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_readv(fd, iov, iovcnt);

    } else {
        return SYSCALL(readv)(fd, iov, iovcnt);
    }
}

__attribute__((weak)) int
ioctl(int fd, int request, void *p)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_ioctl(fd, request, p);

    } else {
        return SYSCALL(ioctl)(fd, request, p);
    }
}

__attribute__((weak)) int
select(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout)
{
    if (nfds && IS_FSTACK_FD(nfds - 1)) {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        return ff_select(nfds, readfds, writefds, exceptfds, &tv);

    } else {
        return SYSCALL(select)(nfds, readfds, writefds, exceptfds, timeout);
    }
}

__attribute__((weak)) int
kqueue(void)
{
    return ff_kqueue();
}

__attribute__((weak)) int
kevent(int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
    if (IS_FSTACK_FD(kq)) {
        return ff_kevent(kq, changelist, nchanges, eventlist, nevents, timeout);

    } else {
        return SYSCALL(kevent)(kq, changelist, nchanges, eventlist, nevents, timeout);
    }
}

__attribute__((weak)) int
epoll_create(int size)
{
    int rc;

    rc = SYSCALL(epoll_create)(size);
    if (IS_FSTACK_FD(rc)) {
        SYSCALL(close)(rc);
        rc = -1;
        errno = EMFILE;
    }

    return rc;
}

/*FIXME epoll_create !!*/
int
fepoll_create(int size)
{
    return ff_epoll_create(size);
}

__attribute__((weak)) int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (IS_FSTACK_FD(epfd)) {
        return ff_epoll_ctl(epfd, op, fd, event);

    } else {
        return SYSCALL(epoll_ctl)(epfd, op, fd, event);
    }
}

__attribute__((weak)) int
epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    if (IS_FSTACK_FD(epfd)) {
        return ff_epoll_wait(epfd, events, maxevents, timeout);

    } else {
        return SYSCALL(epoll_wait)(epfd, events, maxevents, timeout);
    }
}

void
ff_hook_init(void) {
    int ret, i, lastfd = 0;

    if (!ff_global_cfg.freebsd.fdstart) {
        printf("No fd reserved for system !!\n");
        return;
    }

    for (i = 0; i < ff_global_cfg.freebsd.fdstart; i++) {
        ret = kqueue();
        if (ret > lastfd) {
            lastfd = ret;
        }
    }

    printf("Reserved %d fds for system !\n", lastfd + 1); 
}

