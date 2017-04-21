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

#define FF_FD_BITS 16
#define CHK_FD_BIT(fd)          (fd & (1 << FF_FD_BITS))
#define CLR_FD_BIT(fd)          (fd & ~(1 << FF_FD_BITS))

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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    //int rc;

    #define INIT_FUNCTION(func) \
        real_##func = dlsym(RTLD_NEXT, #func); \
        assert(real_##func)

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

#undef INIT_FUNCTION

    inited = 1;
#pragma GCC diagnostic pop
}

int socket(int domain, int type, int protocol)
{
    int rc;

    if ((inited == 0) ||  (AF_INET != domain) || (SOCK_STREAM != type && SOCK_DGRAM != type))
    {
        rc = real_socket(domain, type, protocol);
        return rc;
    }

    rc = ff_socket(domain, type, protocol);
    if(rc >= 0)
        rc |= 1 << FF_FD_BITS;

    return rc;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_bind(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return real_bind(sockfd, addr, addrlen);
    }
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_connect(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return real_connect(sockfd, addr, addrlen);
    }
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_send(sockfd, buf, len, flags);
    } else {
        return real_send(sockfd, buf, len, flags);
    }
}

ssize_t write(int sockfd, const void *buf, size_t count)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_write(sockfd, buf, count);
    } else {
        return real_write(sockfd, buf, count);
    }
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_recv(sockfd, buf, len, flags);
    } else {
        return real_recv(sockfd, buf, len, flags);
    }
}

ssize_t read(int sockfd, void *buf, size_t count)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_read(sockfd, buf, count);
    } else {
        return real_read(sockfd, buf, count);
    }
}

int listen(int sockfd, int backlog)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_listen(sockfd, backlog);
    } else {
        return real_listen(sockfd, backlog);
    }
}

int setsockopt (int sockfd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_setsockopt(sockfd, level, optname, optval, optlen);
    } else {
        return real_setsockopt(sockfd, level, optname, optval, optlen);
    }
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        int fd = ff_accept(sockfd, (struct linux_sockaddr *)addr, addrlen);
        if (fd < 0) {
            return fd;
        }
        fd |= 1 << FF_FD_BITS;
        return fd;
    } else {
        return real_accept(sockfd, addr, addrlen);
    }
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_accept(sockfd, (struct linux_sockaddr *)addr, addrlen);
    } else {
        return real_accept4(sockfd, addr, addrlen, flags);
    }
}

int close(int sockfd)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_close(sockfd);
    } else {
        return real_close(sockfd);
    }
}

ssize_t writev(int sockfd, const struct iovec *iov, int iovcnt)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_writev(sockfd, iov, iovcnt);
    } else {
        return real_writev(sockfd, iov, iovcnt);
    }
}

ssize_t readv(int sockfd, const struct iovec *iov, int iovcnt)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_readv(sockfd, iov, iovcnt);
    } else {
        return real_readv(sockfd, iov, iovcnt);
    }
}

int ioctl(int sockfd, int request, void *p)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_ioctl(sockfd, request, p);
    } else {
        return real_ioctl(sockfd, request, p);
    }
}

int fcntl(int sockfd, int cmd, void *p)
{
    if (CHK_FD_BIT(sockfd)) {
        sockfd = CLR_FD_BIT(sockfd);
        return ff_fcntl(sockfd, cmd, p);
    } else {
        return real_fcntl(sockfd, cmd, p);
    }
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout)
{
    if (CHK_FD_BIT(nfds)) {
        nfds = CLR_FD_BIT(nfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        return ff_select(nfds, readfds, writefds, exceptfds, &tv);
    } else {
        return real_select(nfds, readfds, writefds, exceptfds, timeout);
    }
}

