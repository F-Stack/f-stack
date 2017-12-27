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

#ifndef _FSTACK_API_H
#define _FSTACK_API_H

#ifdef __cplusplus
extern "C" {
#endif
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "ff_event.h"
#include "ff_errno.h"

struct linux_sockaddr {
    short sa_family;
    char sa_data[14];
};

typedef int (*loop_func_t)(void *arg);

int ff_init(int argc, char * const argv[]);

void ff_run(loop_func_t loop, void *arg);

/* POSIX-LIKE api begin */

int ff_fcntl(int fd, int cmd, ...);

int ff_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);

int ff_ioctl(int fd, unsigned long request, ...);

int ff_socket(int domain, int type, int protocol);

int ff_setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen);

int ff_getsockopt(int s, int level, int optname, void *optval,
    socklen_t *optlen);

int ff_listen(int s, int backlog);
int ff_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen);
int ff_accept(int s, struct linux_sockaddr *addr, socklen_t *addrlen);
int ff_connect(int s, const struct linux_sockaddr *name, socklen_t namelen);
int ff_close(int fd);
int ff_shutdown(int s, int how);

int ff_getpeername(int s, struct linux_sockaddr *name,
    socklen_t *namelen);
int ff_getsockname(int s, struct linux_sockaddr *name,
    socklen_t *namelen);

ssize_t ff_read(int d, void *buf, size_t nbytes);
ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t ff_write(int fd, const void *buf, size_t nbytes);
ssize_t ff_writev(int fd, const struct iovec *iov, int iovcnt);

ssize_t ff_send(int s, const void *buf, size_t len, int flags);
ssize_t ff_sendto(int s, const void *buf, size_t len, int flags,
    const struct linux_sockaddr *to, socklen_t tolen);
ssize_t ff_sendmsg(int s, const struct msghdr *msg, int flags);

ssize_t ff_recv(int s, void *buf, size_t len, int flags);
ssize_t ff_recvfrom(int s, void *buf, size_t len, int flags,
    struct linux_sockaddr *from, socklen_t *fromlen);
ssize_t ff_recvmsg(int s, struct msghdr *msg, int flags);

int ff_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout);

int ff_poll(struct pollfd fds[], nfds_t nfds, int timeout);

int ff_kqueue(void);
int ff_kevent(int kq, const struct kevent *changelist, int nchanges, 
    struct kevent *eventlist, int nevents, const struct timespec *timeout);
int ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges, 
    void *eventlist, int nevents, const struct timespec *timeout, 
    void (*do_each)(void **, struct kevent *));

int ff_gettimeofday(struct timeval *tv, struct timezone *tz);

/* POSIX-LIKE api end */


/* Tests if fd is used by F-Stack */
extern int ff_fdisused(int fd);

extern int ff_getmaxfd(void);

/* route api begin */
enum FF_ROUTE_CTL {
    FF_ROUTE_ADD,
    FF_ROUTE_DEL,
    FF_ROUTE_CHANGE,
};

enum FF_ROUTE_FLAG {
    FF_RTF_HOST,
    FF_RTF_GATEWAY,
};

/*
 * On success, 0 is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
int ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
    struct linux_sockaddr *dst, struct linux_sockaddr *gw,
    struct linux_sockaddr *netmask);

/* route api end */


/* dispatch api begin */

/*
 * Packet dispatch callback function.
 * Implemented by user.
 *
 * @param data
 *   The data pointer of this packet.
 * @param len
 *   The length of this packet.
 * @param queue_id
 *   Current queue of this packet.
 * @param nb_queues
 *   Number of queues to be dispatched.
 *
 * @return 0 to (nb_queues - 1)
 *   The queue id that the packet will be dispatched to.
 * @return -1
 *   Error occurs or packet is handled by user, packet will be freed.
 *
 */
typedef int (*dispatch_func_t)(void *data, uint16_t len,
    uint16_t queue_id, uint16_t nb_queues);

/* regist a packet dispath function */
void ff_regist_packet_dispatcher(dispatch_func_t func);

/* dispatch api end */


/* internal api begin */

/*
 * Handle rtctl.
 * The data is a pointer to struct rt_msghdr.
 */
int ff_rtioctl(int fib, void *data, unsigned *plen, unsigned maxlen);

/*
 * Handle ngctl.
 */
enum FF_NGCTL_CMD {
    NGCTL_SOCKET,
    NGCTL_BIND,
    NGCTL_CONNECT,
    NGCTL_SEND,
    NGCTL_RECV,
    NGCTL_CLOSE,
};

int ff_ngctl(int cmd, void *data);

/* internal api end */

#ifdef __cplusplus
}
#endif
#endif

