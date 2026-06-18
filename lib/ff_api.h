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

#ifndef _FSTACK_API_H
#define _FSTACK_API_H

#ifdef __cplusplus
extern "C" {
#endif
#include <sys/types.h>
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

#define AF_INET6_LINUX    10
#define PF_INET6_LINUX    AF_INET6_LINUX
#define AF_INET6_FREEBSD    28
#define PF_INET6_FREEBSD    AF_INET6_FREEBSD

typedef int (*loop_func_t)(void *arg);

extern __thread struct thread *pcurthread;

int ff_init(int argc, char * const argv[]);

void ff_run(loop_func_t loop, void *arg);

void ff_stop_run(void);

/* POSIX-LIKE api begin */

int ff_fcntl(int fd, int cmd, ...);

int ff_sysctl(const int *name, unsigned int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);

int ff_ioctl(int fd, unsigned long request, ...);

/*
 * While get sockfd from this API, and then need set it to non-blocking mode like this,
 * Otherwise, sometimes the socket interface will not work properly, such as `ff_write()`
 *
 *    int on = 1;
 *    ff_ioctl(sockfd, FIONBIO, &on);
 *
 *  See also `example/main.c`
 */
#ifdef FF_KERNEL_COEXIST
/*
 * Stack-selection markers (OR into the `type` argument of socket()/ff_socket()).
 * Standardized from the syscall adapter (adapter/syscall/ff_adapter.h) so any
 * F-Stack application can choose, per socket, which stack a fd belongs to:
 *   - default (no marker)               : F-Stack user-space stack
 *   - SOCK_FSTACK                        : force F-Stack stack (explicit default)
 *   - SOCK_KERNEL (and not SOCK_FSTACK)  : host Linux kernel stack, so local
 *                                          ping/curl can reach it and the app
 *                                          can connect() to local/external
 *                                          kernel-stack services.
 * Priority: per-socket marker > config.ini [stack] kernel_coexist > F-Stack.
 * Values MUST match adapter/syscall/ff_adapter.h.
 */
#ifndef SOCK_FSTACK
#define SOCK_FSTACK 0x01000000
#endif
#ifndef SOCK_KERNEL
#define SOCK_KERNEL 0x02000000
#endif
#endif /* FF_KERNEL_COEXIST */

int ff_socket(int domain, int type, int protocol);

int ff_setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen);

int ff_getsockopt(int s, int level, int optname, void *optval,
    socklen_t *optlen);

int ff_listen(int s, int backlog);
int ff_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen);
int ff_accept(int s, struct linux_sockaddr *addr, socklen_t *addrlen);
int ff_accept4(int s, struct linux_sockaddr *addr, socklen_t *addrlen, int flags);
int ff_connect(int s, const struct linux_sockaddr *name, socklen_t namelen);
int ff_close(int fd);
int ff_shutdown(int s, int how);

int ff_getpeername(int s, struct linux_sockaddr *name,
    socklen_t *namelen);
int ff_getsockname(int s, struct linux_sockaddr *name,
    socklen_t *namelen);

/* Read-only: this process's RSS queue info (for self-check tools). */
int ff_rss_self_queue_info(uint16_t *proc_id, uint16_t *queueid,
    uint16_t *nb_queues, uint16_t *reta_size);

ssize_t ff_read(int d, void *buf, size_t nbytes);
ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt);


/*
 * Write data to the socket sendspace buf.
 *
 * Note:
 * The `fd` parameter need set non-blocking mode in advance if F-Stack's APP.
 * Otherwise if the `nbytes` parameter is greater than
 * `net.inet.tcp.sendspace + net.inet.tcp.sendbuf_inc`,
 * the API will return -1, but not the length that has been sent.
 *
 * You also can modify the value of  `net.inet.tcp.sendspace`(default 16384 bytes)
 * and `net.inet.tcp.sendbuf_inc`(default 16384 bytes) with `config.ini`.
 * But it should be noted that not all parameters can take effect, such as 32768 and 32768.
 * `ff_sysctl` can see there values while APP is running.
 */
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

#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 31)
int ff_gettimeofday(struct timeval *tv, void *tz);
#else
int ff_gettimeofday(struct timeval *tv, struct timezone *tz);
#endif

int ff_dup(int oldfd);
int ff_dup2(int oldfd, int newfd);

#ifndef _KERNEL
#include <pthread.h>
int ff_pthread_create(pthread_t * thread, const pthread_attr_t * attr,
    void * (* start_routine) (void *), void * arg);
int ff_pthread_join(pthread_t thread, void **retval);
#endif

/* POSIX-LIKE api end */


/* Tests if fd is used by F-Stack */
extern int ff_fdisused(int fd);

extern int ff_getmaxfd(void);

/*
 * Get traffic for QoS or other via API.
 * The size of buffer must >= siezof(struct ff_traffic_args), now is 48 bytes.
 */
void ff_get_traffic(void *buffer);

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
#define FF_DISPATCH_ERROR (-1)
#define FF_DISPATCH_RESPONSE (-2)

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
 * @return FF_DISPATCH_ERROR (-1)
 *   Error occurs or packet is handled by user, packet will be freed.
* @return FF_DISPATCH_RESPONSE (-2)
 *   Packet is handled by user, packet will be responsed.
 *
 */
typedef int (*dispatch_func_t)(void *data, uint16_t *len,
    uint16_t queue_id, uint16_t nb_queues);

/*
 * Packet dispatcher context structure.
 * Contains additional context information for packet dispatching.
 */
struct ff_dispatcher_context {
  struct {
      uint8_t stripped;
      uint16_t vlan_tci;  /**< Priority (3) + CFI (1) + Identifier Code (12) */
  } vlan;
};

/*
 * Enhanced packet dispatch callback function with context.
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
 * @param context
 *   Additional context information for packet dispatching.
 *
 * @return 0 to (nb_queues - 1)
 *   The queue id that the packet will be dispatched to.
 * @return FF_DISPATCH_ERROR (-1)
 *   Error occurs or packet is handled by user, packet will be freed.
 * @return FF_DISPATCH_RESPONSE (-2)
 *   Packet is handled by user, packet will be responsed.
 */
typedef int (*dispatch_func_context_t)(void *data, uint16_t *len,
    uint16_t queue_id, uint16_t nb_queues, struct ff_dispatcher_context context);

/* regist a packet dispath function */
void ff_regist_packet_dispatcher(dispatch_func_t func);

/* Register a packet dispatch function with context support */
void ff_regist_packet_dispatcher_context(dispatch_func_context_t func);

/*
 * RAW packet send direty with DPDK by user APP.
 *
 * @param data
 *   The data pointer of this packet.
 * @param total
 *   The total length of this packet.
 * @param port_id
 *   Current port of this packet.
 *
 * @return error_no
 *   0 means success.
 *  -1 means error.
 */
int ff_dpdk_raw_packet_send(void *data, int total, uint16_t port_id);

/* dispatch api end */

/* pcb lddr api begin */
/*
 * pcb lddr callback function.
 * Implemented by user.
 *
 * @param family
 *   The remote server addr, should be AF_INET or AF_INET6.
 * @param dst_addr
 *   The remote server addr, should be (in_addr *) or (in6_addr *).
 * @param dst_port
 *   The remote server port.
 * @param src_addr
 *   Return parameter.
 *   The local addr, should be (in_addr *) or (in6_addr *).
 *   If set (INADDR_ANY) or (in6addr_any), the app then will
 *   call `in_pcbladdr()` to get laddr.
 *
 * @return error_no
 *   0 means success.
 *
 */
typedef int (*pcblddr_func_t)(uint16_t family, void *dst_addr,
    uint16_t dst_port, void *src_addr);

/* regist a pcb lddr function */
void ff_regist_pcblddr_fun(pcblddr_func_t func);

/* pcb lddr api end */

/* internal api begin */

/* FreeBSD style calls. Used for tools. */
int ff_ioctl_freebsd(int fd, unsigned long request, ...);
int ff_setsockopt_freebsd(int s, int level, int optname,
    const void *optval, socklen_t optlen);
int ff_getsockopt_freebsd(int s, int level, int optname,
    void *optval, socklen_t *optlen);

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

/* zero ccopy API begin */
struct ff_zc_mbuf {
    void *bsd_mbuf;         /* point to the head mbuf */
    void *bsd_mbuf_off;     /* ponit to the current mbuf in the mbuf chain with offset */
    int off;                /* the offset of total mbuf, APP shouldn't modify it */
    int len;                /* the total len of the mbuf chain */
};

/*
 * Get the ff zero copy mbuf.
 *
 * @param m
 *   The ponitor of 'sturct ff_zc_mbuf', and can't be NULL.
 *   Can used by 'ff_zc_mbuf_write' and 'ff_zc_mbuf_read'.
 * @param len
 *   The total buf len of mbuf chain that you want to alloc.
 *
 * @return error_no
 *   0 means success.
 *  -1 means error.
 */
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);

/*
 * Write data to the mbuf chain in 'sturct ff_zc_mbuf'.
 * APP can call this function multiple times, need pay attion to the offset of data.
 * but the total len can't be larger than m->len.
 * After this fuction return success,
 *
 * the struct 'ff_zc_mbuf *m' can be reused in `ff_zc_mbuf_get` and then Use normally.
 * Nerver directly reused in `ff_zc_mbuf_write` before recall `ff_zc_mbuf_get`.
 *
 * APP nedd call 'ff_write' to send data actually after finish write data to mbuf,
 * And use 'bsd_mbuf' of 'struct ff_zc_mbuf' as the 'buf' argument.
 *
 * See 'example/main_zc.c'
 *
 * @param m
 *   The ponitor of 'sturct ff_zc_mbuf', must be call 'ff_zc_mbuf_get' first.
 * @param data
 *   The pointer of data that want to write to socket, need pay attion to the offset.
 * @param len
 *   The len that APP want to write to mbuf chain this time.
 *
 * @return error_no
 *   0 means success.
 *  -1 means error.
 */
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);

/*
 * Read data out of the mbuf chain in 'struct ff_zc_mbuf' into the caller's
 * buffer, advancing the internal cursor (zm->bsd_mbuf_off / zm->off).
 *
 * NOTE: `data` is an OUT buffer (the chain is copied INTO it); the previous
 * 'const char *' signature was a not-implemented placeholder.
 *
 * @return bytes read this call (>0), 0 when the chain is exhausted, -1 error.
 */
int ff_zc_mbuf_read(struct ff_zc_mbuf *m, char *data, int len);

#ifdef FSTACK_ZC_RECV
/*
 * FSTACK_ZC_RECV: zero-copy receive entry. Retrieves the socket-buffer mbuf
 * chain directly (data still points into the underlying DPDK mbuf), avoiding
 * the soreceive->uiomove copy. On success zm->bsd_mbuf holds the chain head,
 * zm->len the byte count, and the cursor is reset for ff_zc_mbuf_read /
 * ff_zc_mbuf_segment traversal.
 *
 * The caller OWNS the returned chain and MUST release it via
 * ff_zc_recv_free() once done — otherwise the backing DPDK mbufs leak.
 *
 * @return bytes received (>0), 0 on peer close, -1 on error (errno set).
 */
ssize_t ff_zc_recv(int fd, struct ff_zc_mbuf *zm, size_t nbytes);

/*
 * Zero-copy traversal: return the current segment's data pointer + length
 * (pointing into the mbuf, no copy) and advance the cursor.
 * @return seg bytes (>0), 0 when exhausted, -1 error.
 */
int ff_zc_mbuf_segment(struct ff_zc_mbuf *zm, void **seg_data, int *seg_len);

/*
 * Release a chain obtained from ff_zc_recv (m_freem the whole chain, which
 * returns each backing DPDK mbuf segment). Idempotent; zeroes zm. Must be
 * called exactly once per successful ff_zc_recv.
 */
void ff_zc_recv_free(struct ff_zc_mbuf *zm);
#endif /* FSTACK_ZC_RECV */

/*
 * Zero-copy send entry. Caller must pass the mbuf chain obtained from
 * ff_zc_mbuf_get + ff_zc_mbuf_write as `mb`. Returns the sent byte
 * count on success, -1 on error (errno set). Internally calls
 * kern_zc_sendit -> sosend(uio=NULL, top=chain), the FreeBSD-native
 * zero-copy send path. On success the kernel adopts the chain; on
 * error the kernel frees it. Reuse requires another ff_zc_mbuf_get.
 *
 * Plain ff_write() / ff_writev() / ff_send() / ff_sendto() must NOT
 * be used to send a zero-copy mbuf chain — they take char buffers
 * and would copy via uiomove. Use ff_zc_send for the ZC fast-path.
 */
ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes);

/*
 * Create user thread context for LD_PRELOAD mode.
 * It saved in ff_so_context.
 */
void *ff_adapt_user_thread_add(void *parent);

void ff_adapt_user_thread_exit(void *td);

void *ff_switch_curthread(void *new_curthread);

void ff_restore_curthread(void *old_curthread);

/* ZERO COPY API end */

#ifdef __cplusplus
}
#endif
#endif

