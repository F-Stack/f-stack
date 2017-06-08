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

#define IS_FSTACK_FD(fd) (fd >= ff_global_cfg.freebsd.fdstart)

extern int ff_epoll_create(int size);
extern int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
extern int ff_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); 

static int (*real_socket)(int, int, int);
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
static int (*real_epoll_ctl)(int, int, int, struct epoll_event *);
static int (*real_epoll_wait)(int, struct epoll_event *, int, int); 

int
socket_raw(int family, int type, int protocol)
{
    return real_socket(family, type, protocol);
}

int
socket(int domain, int type, int protocol)
{
    int rc;

    if ((AF_INET != domain) || (SOCK_STREAM != type && SOCK_DGRAM != type)) {
        rc = real_socket(domain, type, protocol);
        return rc;
    }

    rc = ff_socket(domain, type, protocol);

    return rc;
}

int
bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_bind(fd, (struct linux_sockaddr *)addr, addrlen);

    } else {
        return real_bind(fd, addr, addrlen);
    }
}

int
connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_connect(fd, (struct linux_sockaddr *)addr, addrlen);

    } else {
        return real_connect(fd, addr, addrlen);
    }
}

ssize_t
send(int fd, const void *buf, size_t len, int flags)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_send(fd, buf, len, flags);

    } else {
        return real_send(fd, buf, len, flags);
    }
}

ssize_t
write(int fd, const void *buf, size_t count)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_write(fd, buf, count);

    } else {
        return real_write(fd, buf, count);
    }
}

ssize_t
recv(int fd, void *buf, size_t len, int flags)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_recv(fd, buf, len, flags);

    } else {
        return real_recv(fd, buf, len, flags);
    }
}

ssize_t
read(int fd, void *buf, size_t count)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_read(fd, buf, count);

    } else {
        return real_read(fd, buf, count);
    }
}

int
listen(int fd, int backlog)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_listen(fd, backlog);

    } else {
        return real_listen(fd, backlog);
    }
}

int
setsockopt (int fd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_setsockopt(fd, level, optname, optval, optlen);

    } else {
        return real_setsockopt(fd, level, optname, optval, optlen);
    }
}

int
accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_accept(fd, (struct linux_sockaddr *)addr, addrlen);

    } else {
        return real_accept(fd, addr, addrlen);
    }
}

int
accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_accept(fd, (struct linux_sockaddr *)addr, addrlen);

    } else {
        return real_accept4(fd, addr, addrlen, flags);
    }
}

int
close(int fd)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_close(fd);

    } else {
        return real_close(fd);
    }
}

ssize_t
writev(int fd, const struct iovec *iov, int iovcnt)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_writev(fd, iov, iovcnt);

    } else {
        return real_writev(fd, iov, iovcnt);
    }
}

ssize_t
readv(int fd, const struct iovec *iov, int iovcnt)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_readv(fd, iov, iovcnt);

    } else {
        return real_readv(fd, iov, iovcnt);
    }
}

int
ioctl(int fd, int request, void *p)
{
    if (IS_FSTACK_FD(fd)) {
        return ff_ioctl(fd, request, p);

    } else {
        return real_ioctl(fd, request, p);
    }
}

int
select(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout)
{
    if (nfds && IS_FSTACK_FD(nfds - 1)) {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        return ff_select(nfds, readfds, writefds, exceptfds, &tv);

    } else {
        return real_select(nfds, readfds, writefds, exceptfds, timeout);
    }
}

int
kqueue_raw(void)
{
    return real_kqueue();
}

int
kqueue(void)
{
    int rc;

    rc = ff_kqueue();

    return rc;
}

int
kevent(int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
    if (IS_FSTACK_FD(kq)) {
        return ff_kevent(kq, changelist, nchanges, eventlist, nevents, timeout);

    } else {
        return real_kevent(kq, changelist, nchanges, eventlist, nevents, timeout);
    }
}

void
ff_run(loop_func_t loop, void *arg)
{
    ff_dpdk_run(loop, arg);
}

int
fepoll_create(int size)
{
    int rc;

    rc = ff_epoll_create(size);

    return rc;
}

int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (IS_FSTACK_FD(epfd)) {
        return ff_epoll_ctl(epfd, op, fd, event);

    } else {
        return real_epoll_ctl(epfd, op, fd, event);
    }
}

int
epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    if (IS_FSTACK_FD(epfd)) {
        return ff_epoll_wait(epfd, events, maxevents, timeout);

    } else {
        return real_epoll_wait(epfd, events, maxevents, timeout);
    }
}

extern int ff_freebsd_init();

#define _GNU_SOURCE
#define __USE_GNU
#include <dlfcn.h>

static void
ff_realcall_init(void) {
#define INIT_FUNCTION(func) \
    real_##func = dlsym(RTLD_NEXT, #func);

    INIT_FUNCTION(socket);
    INIT_FUNCTION(bind);
    INIT_FUNCTION(connect);
    INIT_FUNCTION(close);
    INIT_FUNCTION(listen);
    INIT_FUNCTION(setsockopt);
    INIT_FUNCTION(accept);
    INIT_FUNCTION(accept4);
    INIT_FUNCTION(recv);
    INIT_FUNCTION(send);
    INIT_FUNCTION(writev);
    INIT_FUNCTION(write);
    INIT_FUNCTION(read);
    INIT_FUNCTION(readv);

    INIT_FUNCTION(ioctl);
    INIT_FUNCTION(select);

    INIT_FUNCTION(kqueue);
    INIT_FUNCTION(kevent);

    INIT_FUNCTION(epoll_ctl);
    INIT_FUNCTION(epoll_wait);

#undef INIT_FUNCTION
}

int
ff_init(const char *conf, int argc, char * const argv[])
{

    int ret, i, lastfd = 0;

    printf("ff init !!\n");

    /* hook system call */
    ff_realcall_init();

    ret = ff_load_config(conf, argc, argv);
    if (ret < 0)
        exit(1);

    ret = ff_dpdk_init(dpdk_argc, (char **)&dpdk_argv);
    if (ret < 0)
        exit(1);

    ret = ff_freebsd_init();
    if (ret < 0)
        exit(1);

    ret = ff_dpdk_if_up();
    if (ret < 0)
        exit(1);

    /*FIXME load by config, reserve fd for system */
    for (i = 0; i < ff_global_cfg.freebsd.fdstart; i++) {
        //ret = socket(AF_INET, SOCK_STREAM, 0);
        ret = kqueue();
        if (ret >= 0 ) {
            lastfd = ret;
        }
    }
    printf("Reserved %d fds for system !\n", lastfd + 1); 

    return 0;
}

