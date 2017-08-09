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
#include <errno.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>

#include "ff_api.h"
#include "ff_config.h"

#define _GNU_SOURCE
#define __USE_GNU

#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <dlfcn.h>

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
static int (*real_setsockopt)(int, int, int, const void *, socklen_t);

static int (*real_accept)(int, struct sockaddr *, socklen_t *);
static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
static ssize_t (*real_recv)(int, void *, size_t, int);
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_sendto)(int, const void *, size_t, int,
    const struct sockaddr*, socklen_t);
static ssize_t (*real_sendmsg)(int, const struct msghdr*, int);
static ssize_t (*real_writev)(int, const struct iovec *, int);
static ssize_t (*real_readv)(int, const struct iovec *, int);

static int (*real_ioctl)(int, int, void *);

static int (*real_gettimeofday)(struct timeval *tv, struct timezone *tz);

static int inited;

#define SYSCALL(func)                                       \
    ({                                                      \
        if (!real_##func) {                                 \
            real_##func = dlsym(RTLD_NEXT, #func);          \
        }                                                   \
        real_##func;                                        \
    })


void
ff_mod_init(int argc, char * const *argv) {
    int rc;

    rc = ff_init(argc, argv);
    assert(0 == rc);

    inited = 1;
}

int
socket(int domain, int type, int protocol)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(socket)(domain, type, protocol);
    }

    if ((AF_INET != domain) || (SOCK_STREAM != type && SOCK_DGRAM != type)) {
        return SYSCALL(socket)(domain, type, protocol);
    }

    return ff_socket(domain, type, protocol);
}

int
bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(bind)(sockfd, addr, addrlen);
    }

    if (ff_fdisused(sockfd)) {
        return ff_bind(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return SYSCALL(bind)(sockfd, addr, addrlen);
    }
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(connect)(sockfd, addr, addrlen);
    }

    if (ff_fdisused(sockfd)) {
        return ff_connect(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return SYSCALL(connect)(sockfd, addr, addrlen);
    }
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
    if (unlikely(inited == 0)) {
         return SYSCALL(send)(sockfd, buf, len, flags);
    }

    if (ff_fdisused(sockfd)) {
        return ff_send(sockfd, buf, len, flags);
    } else {
        return SYSCALL(send)(sockfd, buf, len, flags);
    }
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    if (ff_fdisused(sockfd)) {
        return ff_sendto(sockfd, buf, len, flags,
	        (struct linux_sockaddr *)dest_addr, addrlen);
    } else {
        return SYSCALL(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
    }
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(sendmsg)(sockfd, msg, flags);
    }

    if (ff_fdisused(sockfd)) {
        return ff_sendmsg(sockfd, msg, flags);
    } else {
        return SYSCALL(sendmsg)(sockfd, msg, flags);
    }
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(recv)(sockfd, buf, len, flags);
    }

    if (ff_fdisused(sockfd)) {
        return ff_recv(sockfd, buf, len, flags);
    } else {
        return SYSCALL(recv)(sockfd, buf, len, flags);
    }
}

int
listen(int sockfd, int backlog)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(listen)(sockfd, backlog);
    }

    if (ff_fdisused(sockfd)) {
        return ff_listen(sockfd, backlog);
    } else {
        return SYSCALL(listen)(sockfd, backlog);
    }
}

int
setsockopt (int sockfd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(setsockopt)(sockfd, level, optname, optval, optlen);
    }

    if (ff_fdisused(sockfd)) {
        return ff_setsockopt(sockfd, level, optname, optval, optlen);
    } else {
        return SYSCALL(setsockopt)(sockfd, level, optname, optval, optlen);
    }
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(accept)(sockfd, addr, addrlen);
    }

    if (ff_fdisused(sockfd)) {
        return ff_accept(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return SYSCALL(accept)(sockfd, addr, addrlen);
    }
}

int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(accept4)(sockfd, addr, addrlen, flags);
    }

    if (ff_fdisused(sockfd)) {
        return ff_accept(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return SYSCALL(accept4)(sockfd, addr, addrlen, flags);
    }
}

int
close(int sockfd)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(close)(sockfd);
    }

    if (ff_fdisused(sockfd)) {
        return ff_close(sockfd);
    } else {
        return SYSCALL(close)(sockfd);
    }
}

ssize_t
writev(int sockfd, const struct iovec *iov, int iovcnt)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(writev)(sockfd, iov, iovcnt);
    }

    if (ff_fdisused(sockfd)) {
        return ff_writev(sockfd, iov, iovcnt);
    } else {
        return SYSCALL(writev)(sockfd, iov, iovcnt);
    }
}

ssize_t
readv(int sockfd, const struct iovec *iov, int iovcnt)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(readv)(sockfd, iov, iovcnt);
    }

    if (ff_fdisused(sockfd)) {
        return ff_readv(sockfd, iov, iovcnt);
    } else {
        return SYSCALL(readv)(sockfd, iov, iovcnt);
    }
}

int
ioctl(int sockfd, int request, void *p)
{
    if (unlikely(inited == 0)) {
        return SYSCALL(ioctl)(sockfd, request, p);
    }

    if (ff_fdisused(sockfd)) {
        return ff_ioctl(sockfd, request, p);
    } else {
        return SYSCALL(ioctl)(sockfd, request, p);
    }
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

