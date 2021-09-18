/*
 * Inspired by opendp/dpdk-nginx's ans_module.c.
 * License of opendp:
 *
 BSD LICENSE
 Copyright(c) 2015-2017 Ansyun anssupport@163.com. All rights reserved.
 All rights reserved.
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

 Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in
 the documentation and/or other materials provided with the
 distribution.
 Neither the name of Ansyun anssupport@163.com nor the names of its
 contributors may be used to endorse or promote products derived
 from this software without specific prior written permission.
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 Author: JiaKai (jiakai1000@gmail.com) and Bluestar (anssupport@163.com)
 */

/*
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
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <ngx_auto_config.h>
#include "ff_api.h"

#define _GNU_SOURCE
#define __USE_GNU

#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <limits.h>

#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)  __builtin_expect((x),0)
#endif

static int (*real_close)(int);
static int (*real_socket)(int, int, int);
static int (*real_bind)(int, const struct sockaddr*, socklen_t);
static int (*real_connect)(int, const struct sockaddr*, socklen_t);
static int (*real_listen)(int, int);

static int (*real_getsockopt)(int, int, int, void *, socklen_t*);
static int (*real_setsockopt)(int, int, int, const void *, socklen_t);

static int (*real_accept)(int, struct sockaddr *, socklen_t *);
static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
static ssize_t (*real_recv)(int, void *, size_t, int);
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_sendto)(int, const void *, size_t, int,
    const struct sockaddr*, socklen_t);
static ssize_t (*real_sendmsg)(int, const struct msghdr*, int);
static ssize_t (*real_recvmsg)(int, struct msghdr *, int);
static ssize_t (*real_writev)(int, const struct iovec *, int);
static ssize_t (*real_readv)(int, const struct iovec *, int);

static ssize_t (*real_read)(int, void *, size_t);
static ssize_t (*real_write)(int, const void *, size_t);

static int (*real_shutdown)(int, int);

static int (*real_ioctl)(int, int, void *);

static int (*real_gettimeofday)(struct timeval *tv, struct timezone *tz);

static int (*real_getpeername)(int sockfd, struct sockaddr * name, socklen_t *namelen);
static int (*real_getsockname)(int s, struct sockaddr *name, socklen_t *namelen);

static __thread int inited;

#define SYSCALL(func)                                       \
    ({                                                      \
        if (unlikely(!real_##func)) {                       \
            real_##func = dlsym(RTLD_NEXT, #func);          \
        }                                                   \
        real_##func;                                        \
    })

extern intptr_t    ngx_max_sockets;

/*-
 * Make sockfd assigned by the fstack plus the value of maximum kernel socket.
 *  so we can tell them apart according to different scopes.
 * Solve the condominium ownership at Application Layer and obtain more freedom.
 * fstack tried to do this by 'fd_reserve', unfortunately, it doesn't work well.
 */
static inline int convert_fstack_fd(int sockfd) {
    return sockfd + ngx_max_sockets;
}

/* Restore socket fd. */
static inline int restore_fstack_fd(int sockfd) {
    if(sockfd <= ngx_max_sockets) {
        return sockfd;
    }

    return sockfd - ngx_max_sockets;
}

/* Tell whether a 'sockfd' belongs to fstack. */
int is_fstack_fd(int sockfd) {
    if (unlikely(inited == 0)) {
        return 0;
    }

    return sockfd >= ngx_max_sockets;
}

// proc_type, 1: primary, 0: secondary.
int
ff_mod_init(const char *conf, int proc_id, int proc_type) {
    int rc, i;
    int ff_argc = 4;

    char **ff_argv = malloc(sizeof(char *)*ff_argc);
    for (i = 0; i < ff_argc; i++) {
        ff_argv[i] = malloc(sizeof(char)*PATH_MAX);
    }

    sprintf(ff_argv[0], "nginx");
    sprintf(ff_argv[1], "--conf=%s", conf);
    sprintf(ff_argv[2], "--proc-id=%d", proc_id);
    if (proc_type == 1) {
        sprintf(ff_argv[3], "--proc-type=primary");
    } else {
        sprintf(ff_argv[3], "--proc-type=secondary");
    }

    rc = ff_init(ff_argc, ff_argv);
    if (rc == 0) {
        /* Ensure that the socket we converted
                does not exceed the maximum value of 'int' */

        if(ngx_max_sockets + (unsigned)ff_getmaxfd() > INT_MAX)
        {
            rc = -1;
        }

        inited = 1;
    }

    for (i = 0; i < ff_argc; i++) {
        free(ff_argv[i]);
    }

    free(ff_argv);

    return rc;
}

/*-
 * Verify whether the socket is supported by fstack or not.
 */
int
fstack_territory(int domain, int type, int protocol)
{
    /* Remove creation flags */
    type &= ~SOCK_CLOEXEC;
    type &= ~SOCK_NONBLOCK;
    type &= ~SOCK_FSTACK;

    if ((AF_INET != domain && AF_INET6 != domain) || (SOCK_STREAM != type && SOCK_DGRAM != type)) {
        return 0;
    }

    return 1;
}

int
socket(int domain, int type, int protocol)
{
    int sock;
    if (unlikely(inited == 0)) {
        return SYSCALL(socket)(domain, type, protocol);
    }

    if (unlikely(fstack_territory(domain, type, protocol) == 0)) {
        return SYSCALL(socket)(domain, type, protocol);
    }

    if (unlikely((type & SOCK_FSTACK) == 0)) {
        return SYSCALL(socket)(domain, type, protocol);
    }

    type &= ~SOCK_FSTACK;
    sock = ff_socket(domain, type, protocol);

    if (sock != -1) {
        sock = convert_fstack_fd(sock);
    }

    return sock;
}

int
bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_bind(sockfd, (struct linux_sockaddr *)addr, addrlen);
    }

    return SYSCALL(bind)(sockfd, addr, addrlen);
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_connect(sockfd, (struct linux_sockaddr *)addr, addrlen);
    }

    return SYSCALL(connect)(sockfd, addr, addrlen);
}

int
getpeername(int sockfd, struct sockaddr * name,
    socklen_t *namelen)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_getpeername(sockfd,
            (struct linux_sockaddr *)name, namelen);
    }

    return SYSCALL(getpeername)(sockfd, name, namelen);
}

int
getsockname(int sockfd, struct sockaddr *name,
    socklen_t *namelen)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_getsockname(sockfd,
            (struct linux_sockaddr *)name, namelen);
    }

    return SYSCALL(getsockname)(sockfd, name, namelen);
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_send(sockfd, buf, len, flags);
    }

    return SYSCALL(send)(sockfd, buf, len, flags);
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_sendto(sockfd, buf, len, flags,
            (struct linux_sockaddr *)dest_addr, addrlen);
    }

    return SYSCALL(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_sendmsg(sockfd, msg, flags);
    }

    return SYSCALL(sendmsg)(sockfd, msg, flags);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_recvmsg(sockfd, msg, flags);
    }

    return SYSCALL(recvmsg)(sockfd, msg, flags);
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_recv(sockfd, buf, len, flags);
    }

    return SYSCALL(recv)(sockfd, buf, len, flags);
}

ssize_t
__recv_chk (int fd, void *buf, size_t n, size_t buflen, int flags)
{
/*
  if (n > buflen)
    __chk_fail ();
*/
  return recv (fd, buf, n, flags);
}

int
listen(int sockfd, int backlog)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_listen(sockfd, backlog);
    }

    return SYSCALL(listen)(sockfd, backlog);
}

int
getsockopt(int sockfd, int level, int optname,
    void *optval, socklen_t *optlen)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_getsockopt(sockfd, level, optname, optval, optlen);
    }

    return SYSCALL(getsockopt)(sockfd, level, optname, optval, optlen);
}

int
setsockopt (int sockfd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_setsockopt(sockfd, level, optname, optval, optlen);
    }

    return SYSCALL(setsockopt)(sockfd, level, optname, optval, optlen);
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int rc;
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        rc = ff_accept(sockfd, (struct linux_sockaddr *)addr, addrlen);
        if (rc != -1) {
            rc = convert_fstack_fd(rc);
        }

        return rc;
    }

    return SYSCALL(accept)(sockfd, addr, addrlen);
}

int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    int rc;
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        rc = ff_accept(sockfd, (struct linux_sockaddr *)addr, addrlen);
        if (rc != -1) {
            rc = convert_fstack_fd(rc);
        }

        return rc;
    }

    return SYSCALL(accept4)(sockfd, addr, addrlen, flags);
}

int
close(int sockfd)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_close(sockfd);
    }

    return SYSCALL(close)(sockfd);
}

int
shutdown(int sockfd, int how)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_shutdown(sockfd, how);
    }

    return SYSCALL(shutdown)(sockfd, how);
}

ssize_t
writev(int sockfd, const struct iovec *iov, int iovcnt)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_writev(sockfd, iov, iovcnt);
    }

    return SYSCALL(writev)(sockfd, iov, iovcnt);
}

ssize_t
readv(int sockfd, const struct iovec *iov, int iovcnt)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_readv(sockfd, iov, iovcnt);
    }

    return SYSCALL(readv)(sockfd, iov, iovcnt);
}

ssize_t
read(int sockfd, void *buf, size_t count)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_read(sockfd, buf, count);
    }

    return SYSCALL(read)(sockfd, buf, count);
}

ssize_t
write(int sockfd, const void *buf, size_t count)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_write(sockfd, buf, count);
    }

    return SYSCALL(write)(sockfd, buf, count);
}

int
ioctl(int sockfd, int request, void *p)
{
    if(is_fstack_fd(sockfd)){
        sockfd = restore_fstack_fd(sockfd);
        return ff_ioctl(sockfd, request, p);
    }

    return SYSCALL(ioctl)(sockfd, request, p);
}

int
kqueue(void)
{
    return ff_kqueue();
}

int
kevent(int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
    struct kevent     *kev;
    int                i = 0;
    for(i = 0; i < nchanges; i++) {
        kev = (struct kevent *)&changelist[i];
        switch (kev->filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:
        case EVFILT_VNODE:
            kev->ident = restore_fstack_fd(kev->ident);
            break;
        case EVFILT_AIO:
        case EVFILT_PROC:
        case EVFILT_SIGNAL:
        case EVFILT_TIMER:
        case EVFILT_USER:
        default:
            break;
        }
    }
    return ff_kevent(kq, changelist, nchanges, eventlist, nevents, timeout);
}

int
gettimeofday(struct timeval *tv, struct timezone *tz)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(gettimeofday)(tv, tz);
    }

    return ff_gettimeofday(tv, tz);
}
