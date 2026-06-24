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
 * Derived in part from libuinet's uinet_host_interface.h.
 */

#ifndef _FSTACK_HOST_INTERFACE_H_
#define _FSTACK_HOST_INTERFACE_H_

#define ff_PROT_NONE     0x00
#define ff_PROT_READ     0x01
#define ff_PROT_WRITE    0x02

#define ff_MAP_SHARED    0x0001
#define ff_MAP_PRIVATE   0x0002
#define ff_MAP_ANON      0x1000
#define ff_MAP_NOCORE    0x00020000

#define ff_MAP_FAILED    ((void *)-1)

void *ff_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset);
int ff_munmap(void *addr, uint64_t len);

void *ff_malloc(uint64_t size);
void *ff_calloc(uint64_t number, uint64_t size);
void *ff_realloc(void *p, uint64_t size);
void ff_free(void *p);

#define ff_CLOCK_REALTIME        0
#define ff_CLOCK_MONOTONIC        4
#define ff_CLOCK_MONOTONIC_FAST       12

#define ff_NSEC_PER_SEC    (1000ULL * 1000ULL * 1000ULL)

void ff_clock_gettime(int id, int64_t *sec, long *nsec);
uint64_t ff_clock_gettime_ns(int id);
uint64_t ff_get_tsc_ns(void);

void ff_get_current_time(int64_t *sec, long *nsec);
void ff_update_current_ts(void);

typedef volatile uintptr_t ff_mutex_t;
typedef void * ff_cond_t;
typedef void * ff_rwlock_t;

void ff_arc4rand(void *ptr, unsigned int len, int reseed);
uint32_t ff_arc4random(void);

int ff_setenv(const char *name, const char *value);
char *ff_getenv(const char *name);

void ff_os_errno(int error);

int ff_in_pcbladdr(uint16_t family, void *faddr, uint16_t fport, void *laddr);

int ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t sport, uint16_t dport);

int ff_rss_tbl_init(void);
int ff_rss_tbl_set_portrange(uint16_t first, uint16_t last);
/*
 * return value:
 * 0: finded
 * -1: Serious error, can't call it further.
 * -ENOENT(-2): Not finded, can call it further.
 */
int ff_rss_tbl_get_portrange(uint32_t saddr, uint32_t daddr, uint16_t sport,
    uint16_t *rss_first, uint16_t *rss_last, uint16_t **rss_portrange);

int ff_rss_thash_ctx_init(void);
int ff_rss_adjust_sport(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t dport, uint16_t *out_sport, uint16_t first, uint16_t last);

int ff_rss_check6(void *softc, const uint8_t *saddr6,
    const uint8_t *daddr6, uint16_t sport, uint16_t dport);
int ff_rss_tbl6_init(void);
int ff_rss_tbl6_set_portrange(uint16_t first, uint16_t last);
int ff_rss_tbl6_get_portrange(const uint8_t *saddr6, const uint8_t *daddr6,
    uint16_t sport, uint16_t *rss_first, uint16_t *rss_last,
    uint16_t **rss_portrange);
int ff_rss_adjust_sport6(void *softc, const uint8_t *saddr6,
    const uint8_t *daddr6, uint16_t dport, uint16_t *out_sport);

void ff_swi_net_excute(void);

#ifdef FF_KERNEL_COEXIST
/*
 * Kernel-stack coexistence (native ff_api mode).
 *
 * A native F-Stack application runs ON F-Stack (ff_init/ff_run); business
 * sockets use the F-Stack user-space stack. When coexistence is enabled
 * (config.ini [stack] kernel_coexist=1), a socket created with SOCK_KERNEL
 * additionally uses the host Linux kernel stack, coexisting in the same
 * process / event loop.
 *
 * FD-space separation (zero regression): F-Stack fds keep their raw FreeBSD
 * values (unchanged). A managed kernel fd is returned to the application as
 * (host_fd + FF_KERNEL_FD_BASE). FF_KERNEL_FD_BASE is far above the maximum
 * FreeBSD fd (kern.maxfiles is required to be <= 65536, see adapter README),
 * and host fds are bounded by RLIMIT_NOFILE, so the two ranges never collide.
 * The ff_* entry points detect a managed kernel fd via ff_is_kernel_fd() and
 * route it to the host bridge below; the default / SOCK_FSTACK path is left
 * byte-for-byte unchanged.
 */
#define FF_KERNEL_FD_BASE 0x40000000

static inline int ff_is_kernel_fd(int fd)
{
    return fd >= FF_KERNEL_FD_BASE;
}

static inline int ff_kernel_fd_encode(int host_fd)
{
    return host_fd + FF_KERNEL_FD_BASE;
}

static inline int ff_kernel_fd_real(int fd)
{
    return fd - FF_KERNEL_FD_BASE;
}

/*
 * Native dual-stack fd map: a coexistence (dual-stack) fd keeps its F-Stack fd
 * value; the paired host kernel fd is stored here, indexed by the F-Stack fd
 * (0 = no kernel side). Maintained by the ff_* entry points.
 */
int  ff_native_map_get(int fstack_fd);
void ff_native_map_set(int fstack_fd, int host_fd);
void ff_native_map_clear(int fstack_fd);
void ff_epoll_close_pair(int kq);   /* close host epoll paired with a kqueue (ff_epoll.c) */
int  ff_epoll_host_ep(int kq, int create); /* host epoll paired with a kqueue (ff_epoll.c) */
int  ff_host_set_v6only(int fd);
void ff_host_kqueue_ctl(int epfd, int del, int hfd, int app_fd, int want_write);
int  ff_host_kqueue_poll(int epfd, int *triples, int maxevents);

/*
 * Host kernel-stack bridge (implemented in ff_host_interface.c, host
 * namespace). These operate on RAW host fds. sockaddr / epoll_event are
 * passed as void* to avoid struct-layout clashes between the FreeBSD and host
 * namespaces; struct linux_sockaddr already matches the host sockaddr layout.
 * On failure they return -1 with the host errno set.
 */
int ff_host_socket(int domain, int type, int protocol);
int ff_host_bind(int fd, const void *addr, unsigned int addrlen);
int ff_host_listen(int fd, int backlog);
int ff_host_accept(int fd, void *addr, unsigned int *addrlen);
int ff_host_connect(int fd, const void *addr, unsigned int addrlen);
int ff_host_close(int fd);
ssize_t ff_host_read(int fd, void *buf, size_t nbytes);
ssize_t ff_host_write(int fd, const void *buf, size_t nbytes);
ssize_t ff_host_recv(int fd, void *buf, size_t len, int flags);
ssize_t ff_host_send(int fd, const void *buf, size_t len, int flags);
ssize_t ff_host_sendto(int fd, const void *buf, size_t len, int flags,
    const void *to, unsigned int tolen);
ssize_t ff_host_recvfrom(int fd, void *buf, size_t len, int flags,
    void *from, unsigned int *fromlen);
int ff_host_accept4(int fd, void *addr, unsigned int *addrlen, int flags);
int ff_host_setsockopt(int fd, int level, int optname,
    const void *optval, unsigned int optlen);
int ff_host_getsockopt(int fd, int level, int optname,
    void *optval, unsigned int *optlen);
int ff_host_fcntl(int fd, int cmd, int arg);
int ff_host_epoll_create1(int flags);
int ff_host_epoll_ctl(int epfd, int op, int fd, void *event);
int ff_host_epoll_wait(int epfd, void *events, int maxevents, int timeout);
ssize_t ff_host_sendmsg(int fd, const void *msg, int flags);
ssize_t ff_host_recvmsg(int fd, void *msg, int flags);
int ff_host_shutdown(int fd, int how);
int ff_host_getpeername(int fd, void *addr, unsigned int *addrlen);
int ff_host_getsockname(int fd, void *addr, unsigned int *addrlen);
ssize_t ff_host_readv(int fd, const void *iov, int iovcnt);
ssize_t ff_host_writev(int fd, const void *iov, int iovcnt);
int ff_host_ioctl(int fd, unsigned long request, void *argp);
int ff_host_dup(int fd);
int ff_host_dup2(int oldfd, int newfd);
#endif /* FF_KERNEL_COEXIST */

#endif

