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
#include <sys/select.h>

typedef unsigned short u_short;
typedef unsigned int u_int;
#include "ff_api.h"

#define _GNU_SOURCE
#define __USE_GNU

#include <unistd.h>
//#include <sched.h>
#include <sys/types.h>
//#include <fcntl.h>
#include <sys/syscall.h>
#include <dlfcn.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)  __builtin_expect((x),0)
#endif

#define INIT_FUNCTION(func) \
    real_##func = dlsym(RTLD_NEXT, #func); \
    assert(real_##func)

static int inited = 0;

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

static ssize_t (*real_writev)(int, const struct iovec *, int);
static ssize_t (*real_write)(int, const void *, size_t );
static ssize_t (*real_read)(int, void *, size_t );
static ssize_t (*real_readv)(int, const struct iovec *, int);

static int (*real_ioctl)(int, int, void *);
static int (*real_fcntl)(int, int, void *);

static int (*real_select) (int, fd_set *, fd_set *, fd_set *, struct timeval *);


void ff_mod_init() {
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
    INIT_FUNCTION(fcntl);
    INIT_FUNCTION(select);

    inited = 1;
}

int
socket(int domain, int type, int protocol)
{
    int rc;

    if (unlikely(inited == 0)) {
        INIT_FUNCTION(socket);
        return real_socket(domain, type, protocol);
    }

    if ((AF_INET != domain) || (SOCK_STREAM != type && SOCK_DGRAM != type)) {
        rc = real_socket(domain, type, protocol);
        return rc;
    }

    rc = ff_socket(domain, type, protocol);

    return rc;
}

int
bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(bind);
        return real_bind(sockfd, addr, addrlen);
    }

    if (ff_fdisused(sockfd)) {
        return ff_bind(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return real_bind(sockfd, addr, addrlen);
    }
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(connect);
        return real_connect(sockfd, addr, addrlen);
    }

    if (ff_fdisused(sockfd)) {
        return ff_connect(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return real_connect(sockfd, addr, addrlen);
    }
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(send);
        return real_send(sockfd, buf, len, flags);
    }

    if (ff_fdisused(sockfd)) {
        return ff_send(sockfd, buf, len, flags);
    } else {
        return real_send(sockfd, buf, len, flags);
    }
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(recv);
        return real_recv(sockfd, buf, len, flags);
    }

    if (ff_fdisused(sockfd)) {
        return ff_recv(sockfd, buf, len, flags);
    } else {
        return real_recv(sockfd, buf, len, flags);
    }
}

int
listen(int sockfd, int backlog)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(listen);
        return real_listen(sockfd, backlog);
    }

    if (ff_fdisused(sockfd)) {
        return ff_listen(sockfd, backlog);
    } else {
        return real_listen(sockfd, backlog);
    }
}

int
setsockopt (int sockfd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(setsockopt);
        return real_setsockopt(sockfd, level, optname, optval, optlen);
    }

    if (ff_fdisused(sockfd)) {
        return ff_setsockopt(sockfd, level, optname, optval, optlen);
    } else {
        return real_setsockopt(sockfd, level, optname, optval, optlen);
    }
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(accept);
        return real_accept(sockfd, addr, addrlen);
    }

    if (ff_fdisused(sockfd)) {
        return ff_accept(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return real_accept(sockfd, addr, addrlen);
    }
}

int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(accept4);
        return real_accept4(sockfd, addr, addrlen, flags);
    }

    if (ff_fdisused(sockfd)) {
        return ff_accept(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return real_accept4(sockfd, addr, addrlen, flags);
    }
}

int
close(int sockfd)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(close);
        return real_close(sockfd);
    }

    if (ff_fdisused(sockfd)) {
        return ff_close(sockfd);
    } else {
        return real_close(sockfd);
    }
}

ssize_t write(int sockfd, const void *buf, size_t count)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(write);
        return real_write(sockfd, buf, count);
    }

    if (ff_fdisused(sockfd)) {
        return ff_write(sockfd, buf, count);
    } else {
        return real_write(sockfd, buf, count);
    }
}

ssize_t
writev(int sockfd, const struct iovec *iov, int iovcnt)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(writev);
        return real_writev(sockfd, iov, iovcnt);
    }

    if (ff_fdisused(sockfd)) {
        return ff_writev(sockfd, iov, iovcnt);
    } else {
        return real_writev(sockfd, iov, iovcnt);
    }
}

ssize_t read(int sockfd, void *buf, size_t count)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(read);
        return real_read(sockfd, buf, count);
    }

    if (ff_fdisused(sockfd)) {
        return ff_read(sockfd, buf, count);
    } else {
        return real_read(sockfd, buf, count);
    }
}

ssize_t
readv(int sockfd, const struct iovec *iov, int iovcnt)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(readv);
        return real_readv(sockfd, iov, iovcnt);
    }

    if (ff_fdisused(sockfd)) {
        return ff_readv(sockfd, iov, iovcnt);
    } else {
        return real_readv(sockfd, iov, iovcnt);
    }
}

int
ioctl(int sockfd, int request, void *p)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(ioctl);
        return real_ioctl(sockfd, request, p);
    }

    if (ff_fdisused(sockfd)) {
        return ff_ioctl(sockfd, request, p);
    } else {
        return real_ioctl(sockfd, request, p);
    }
}

int fcntl(int sockfd, int cmd, void *p)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(fcntl);
        return real_fcntl(sockfd, cmd, p);
    }

    if (ff_fdisused(sockfd)) {
        return ff_fcntl(sockfd, cmd, p);
    } else {
        return real_fcntl(sockfd, cmd, p);
    }
}

int
select(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout)
{
    if (unlikely(inited == 0)) {
        INIT_FUNCTION(select);
        return real_select(nfds, readfds, writefds, exceptfds, timeout);
    }

    if (ff_fdisused(nfds)) {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        return ff_select(nfds, readfds, writefds, exceptfds, &tv);
    } else {
        return real_select(nfds, readfds, writefds, exceptfds, timeout);
    }
}

#pragma GCC diagnostic pop

