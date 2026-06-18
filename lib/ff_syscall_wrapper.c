/*
 * Copyright (c) 2010 Kip Macy. All rights reserved.
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
 * Derived in part from libplebnet's pn_syscall_wrapper.c.
 */

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/uio.h>
#include <sys/mbuf.h>           /* struct mbuf for ff_zc_send chain */
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/socketvar.h>
#include <sys/event.h>
#include <sys/kernel.h>
#include <sys/refcount.h>
#include <sys/sysctl.h>
#include <sys/pcpu.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/event.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ttycom.h>
#include <sys/filio.h>
#include <sys/sysproto.h>
#include <sys/fcntl.h>
#include <net/route.h>
#include <net/route/route_ctl.h>

#include <net/if.h>
#include <sys/sockio.h>

#include <machine/stdarg.h>

#include "ff_api.h"
#include "ff_host_interface.h"
#ifdef FF_KERNEL_COEXIST
#include "ff_config.h"
#endif /* FF_KERNEL_COEXIST */

/* setsockopt/getsockopt define start */

#define LINUX_SOL_SOCKET      1

#define LINUX_SO_DEBUG        1
#define LINUX_SO_REUSEADDR    2
#define LINUX_SO_ERROR        4
#define LINUX_SO_DONTROUTE    5
#define LINUX_SO_BROADCAST    6
#define LINUX_SO_SNDBUF       7
#define LINUX_SO_RCVBUF       8
#define LINUX_SO_KEEPALIVE    9
#define LINUX_SO_OOBINLINE    10
#define LINUX_SO_LINGER       13
#define LINUX_SO_REUSEPORT    15
#define LINUX_SO_RCVLOWAT     18
#define LINUX_SO_SNDLOWAT     19
#define LINUX_SO_RCVTIMEO     20
#define LINUX_SO_SNDTIMEO     21
#define LINUX_SO_TIMESTAMP    29
#define LINUX_SO_ACCEPTCONN   30
#define LINUX_SO_PROTOCOL     38


#define LINUX_IP_TOS        1
#define LINUX_IP_TTL        2
#define LINUX_IP_HDRINCL    3
#define LINUX_IP_OPTIONS    4
#define LINUX_IP_RECVTTL    12
#define LINUX_IP_RECVTOS    13
#define LINUX_IP_TRANSPARENT    19
#define LINUX_IP_MINTTL     21

#define LINUX_IP_MULTICAST_IF       32
#define LINUX_IP_MULTICAST_TTL      33
#define LINUX_IP_MULTICAST_LOOP     34
#define LINUX_IP_ADD_MEMBERSHIP     35
#define LINUX_IP_DROP_MEMBERSHIP    36

#define LINUX_IPV6_V6ONLY           26
#define LINUX_IPV6_RECVPKTINFO      49
#define LINUX_IPV6_PKTINFO          50
#define LINUX_IPV6_TRANSPARENT      75

#define LINUX_TCP_NODELAY     1
#define LINUX_TCP_MAXSEG      2
#define LINUX_TCP_KEEPIDLE    4
#define LINUX_TCP_KEEPINTVL   5
#define LINUX_TCP_KEEPCNT     6
#define LINUX_TCP_INFO        11
#define LINUX_TCP_MD5SIG      14

/* setsockopt/getsockopt define end */


/* ioctl define start */

#define LINUX_TIOCEXCL    0x540C
#define LINUX_TIOCNXCL    0x540D
#define LINUX_TIOCSCTTY   0x540E
#define LINUX_TIOCGPGRP   0x540F
#define LINUX_TIOCSPGRP   0x5410
#define LINUX_TIOCOUTQ    0x5411
#define LINUX_TIOCSTI     0x5412
#define LINUX_TIOCGWINSZ  0x5413
#define LINUX_TIOCSWINSZ  0x5414
#define LINUX_TIOCMGET    0x5415
#define LINUX_TIOCMBIS    0x5416
#define LINUX_TIOCMBIC    0x5417
#define LINUX_TIOCMSET    0x5418

#define LINUX_FIONREAD    0x541B
#define LINUX_TIOCCONS    0x541D
#define LINUX_TIOCPKT     0x5420
#define LINUX_FIONBIO     0x5421
#define LINUX_TIOCNOTTY   0x5422
#define LINUX_TIOCSETD    0x5423
#define LINUX_TIOCGETD    0x5424
#define LINUX_TIOCSBRK    0x5427
#define LINUX_TIOCCBRK    0x5428
#define LINUX_TIOCGSID    0x5429

#define LINUX_FIONCLEX    0x5450
#define LINUX_FIOCLEX     0x5451
#define LINUX_FIOASYNC    0x5452

#define LINUX_TIOCPKT_DATA          0
#define LINUX_TIOCPKT_FLUSHREAD     1
#define LINUX_TIOCPKT_FLUSHWRITE    2
#define LINUX_TIOCPKT_STOP          4
#define LINUX_TIOCPKT_START         8
#define LINUX_TIOCPKT_NOSTOP        16
#define LINUX_TIOCPKT_DOSTOP        32
#define LINUX_TIOCPKT_IOCTL         64

#define LINUX_SIOCGIFCONF     0x8912
#define LINUX_SIOCGIFFLAGS    0x8913
#define LINUX_SIOCSIFFLAGS    0x8914
#define LINUX_SIOCGIFADDR     0x8915
#define LINUX_SIOCSIFADDR     0x8916
#define LINUX_SIOCGIFDSTADDR  0x8917
#define LINUX_SIOCSIFDSTADDR  0x8918
#define LINUX_SIOCGIFBRDADDR  0x8919
#define LINUX_SIOCSIFBRDADDR  0x891a
#define LINUX_SIOCGIFNETMASK  0x891b
#define LINUX_SIOCSIFNETMASK  0x891c
#define LINUX_SIOCGIFMETRIC   0x891d
#define LINUX_SIOCSIFMETRIC   0x891e
#define LINUX_SIOCGIFMTU      0x8921
#define LINUX_SIOCSIFMTU      0x8922
#define LINUX_SIOCSIFNAME     0x8923
#define LINUX_SIOCADDMULTI    0x8931
#define LINUX_SIOCDELMULTI    0x8932
#define LINUX_SIOCGIFINDEX    0x8933
#define LINUX_SIOCDIFADDR     0x8936

/* ioctl define end */

/* fcntl define start */

#define LINUX_F_DUPFD           0
#define LINUX_F_GETFD           1
#define LINUX_F_SETFD           2
#define LINUX_F_GETFL           3
#define LINUX_F_SETFL           4
#define LINUX_F_GETLK           5
#define LINUX_F_SETLK           6
#define LINUX_F_SETLKW          7
#define LINUX_F_SETOWN          8
#define LINUX_F_GETOWN          9
#define LINUX_F_OFD_GETLK       36
#define LINUX_F_OFD_SETLK       37
#define LINUX_F_OFD_SETLKW      38

#define LINUX_O_APPEND          0x400
#define LINUX_O_NONBLOCK        0x800
#define LINUX_O_ASYNC           0x2000
#define LINUX_O_DIRECT          0x4000
#define LINUX_O_NOATIME         0x40000
#define LINUX_O_CLOEXEC         0x80000

/* fcntl define end */

/* af define start */

#define LINUX_AF_INET6        10

/* af define end */

/* Flags for socket, socketpair, accept4 */

#define	LINUX_SOCK_CLOEXEC	LINUX_O_CLOEXEC
#define	LINUX_SOCK_NONBLOCK	LINUX_O_NONBLOCK

/* msghdr define start */

static /*__thread*/ struct iovec msg_iov_tmp[UIO_MAXIOV];
static /*__thread*/ size_t msg_iovlen_tmp;

struct linux_msghdr {
    void *msg_name;             /* Address to send to/receive from.  */
    socklen_t msg_namelen;      /* Length of address data.  */

    struct iovec *msg_iov;      /* Vector of data to send/receive into.  */
    size_t msg_iovlen;          /* Number of elements in the vector.  */

    void *msg_control;          /* Ancillary data (eg BSD filedesc passing). */
    size_t msg_controllen;      /* Ancillary data buffer length.
                                   !! The type should be socklen_t but the
                                   definition of the kernel is incompatible
                                   with this.  */

    int msg_flags;              /* Flags on received message.  */
};

/* msghdr define end */

/* cmsghdr define start */

struct linux_cmsghdr
{
    size_t cmsg_len;        /* Length of data in cmsg_data plus length
                    of cmsghdr structure.
                    !! The type should be socklen_t but the
                    definition of the kernel is incompatible
                    with this.  */
    int cmsg_level;        /* Originating protocol.  */
    int cmsg_type;        /* Protocol specific type.  */
};

/*
 * LINUX_CMSG_XXXX has the same effect as FreeBSD's CMSG_XXXX,
 * because aligned to 8 bytes, but still redefine them.
 */
#define LINUX_CMSG_DATA(cmsg) ((unsigned char *)(cmsg) + \
                         _ALIGN(sizeof(struct linux_cmsghdr)))
#define LINUX_CMSG_SPACE(l)   (_ALIGN(sizeof(struct linux_cmsghdr)) + _ALIGN(l))
#define LINUX_CMSG_LEN(l)     (_ALIGN(sizeof(struct linux_cmsghdr)) + (l))

#define LINUX_CMSG_FIRSTHDR(mhdr) \
        ((mhdr)->msg_controllen >= sizeof(struct linux_cmsghdr) ? \
         (struct linux_cmsghdr *)(mhdr)->msg_control : \
         (struct linux_cmsghdr *)0)

#define LINUX_CMSG_NXTHDR(mhdr, cmsg)    \
    ((char *)(cmsg) == (char *)0 ? LINUX_CMSG_FIRSTHDR(mhdr) : \
        ((char *)(cmsg) + _ALIGN(((struct linux_cmsghdr *)(cmsg))->cmsg_len) + \
      _ALIGN(sizeof(struct linux_cmsghdr)) > \
        (char *)(mhdr)->msg_control + (mhdr)->msg_controllen) ? \
        (struct linux_cmsghdr *)0 : \
        (struct linux_cmsghdr *)(void *)((char *)(cmsg) + \
        _ALIGN(((struct linux_cmsghdr *)(cmsg))->cmsg_len)))

/* cmsghdr define end */

extern int sendit(struct thread *td, int s, struct msghdr *mp, int flags);

/* convert linux argp to freebsd argp. */
static inline int
linux2freebsd_fcntl(int cmd, intptr_t *argp)
{
    switch(cmd) {
        case LINUX_F_DUPFD:
            return F_DUPFD;
        case LINUX_F_GETFD:
            return F_GETFD;
        case LINUX_F_SETFD:
            if (*argp & LINUX_O_CLOEXEC) {
                //clear linux O_CLOEXEC, set freebsd O_CLOEXEC.
                *argp &= ~LINUX_O_CLOEXEC;
                *argp |= O_CLOEXEC;
            }

            return F_SETFD;
        case LINUX_F_GETFL:
            return F_GETFL;
        case LINUX_F_SETFL:
            if (*argp & LINUX_O_NONBLOCK) {
                //clear linux O_NONBLOCK, set freebsd O_NONBLOCK.
                *argp &= ~LINUX_O_NONBLOCK;
                *argp |= O_NONBLOCK;
            }

            if (*argp & LINUX_O_APPEND) {
                //clear linux O_APPEND, set freebsd O_APPEND.
                *argp &= ~LINUX_O_APPEND;
                *argp |= O_APPEND;
            }

            if (*argp & LINUX_O_ASYNC) {
                //clear linux O_ASYNC, set freebsd O_ASYNC.
                *argp &= ~LINUX_O_ASYNC;
                *argp |= O_ASYNC;
            }

            if (*argp & LINUX_O_DIRECT) {
                //clear linux O_DIRECT, set freebsd O_DIRECT.
                *argp &= ~LINUX_O_DIRECT;
                *argp |= O_DIRECT;
            }

            return F_SETFL;
        case LINUX_F_GETLK:
            return F_GETLK;
        case LINUX_F_SETLK:
            return F_SETLK;
        case LINUX_F_SETLKW:
            return F_SETLKW;
        case LINUX_F_SETOWN:
            return F_SETOWN;
        case LINUX_F_GETOWN:
            return F_GETOWN;
        case LINUX_F_OFD_GETLK:
            return F_OGETLK;
        case LINUX_F_OFD_SETLK:
            return F_OSETLK;
        case LINUX_F_OFD_SETLKW:
            return F_OSETLKW;
        default:
            return cmd;
    }
}

/*
 * convert freebsd flags to linux flags.
 * cmd has been converted to freebsd mode.
 */
static inline int
freebsd2linux_fcntl(int cmd, int flags)
{
    switch(cmd) {
        case F_DUPFD:
            return flags;
        case F_GETFD:
            if (flags & O_CLOEXEC) {
                //clear freebsd O_DIRECT, set linux O_DIRECT.
                flags &= ~O_CLOEXEC;
                flags |= LINUX_O_CLOEXEC;
            }
            return flags;
        case F_SETFD:
            return flags;
        case F_GETFL:
            if (flags & O_NONBLOCK) {
                //clear linux O_NONBLOCK, set freebsd O_NONBLOCK.
                flags &= ~O_NONBLOCK;
                flags |= LINUX_O_NONBLOCK;
            }

            if (flags & O_APPEND) {
                //clear linux O_APPEND, set freebsd O_APPEND.
                flags &= ~O_APPEND;
                flags |= LINUX_O_APPEND;
            }

            if (flags & O_ASYNC) {
                //clear linux O_ASYNC, set freebsd O_ASYNC.
                flags &= ~O_ASYNC;
                flags |= LINUX_O_ASYNC;
            }

            if (flags & O_DIRECT) {
                //clear linux O_DIRECT, set freebsd O_DIRECT.
                flags &= ~O_DIRECT;
                flags |= LINUX_O_DIRECT;
            }

            return flags;
        case LINUX_F_SETFL:
            return flags;
        case F_GETLK:
            return flags;
        case F_SETLK:
            return flags;
        case F_SETLKW:
            return flags;
        case F_SETOWN:
            return flags;
        case F_GETOWN:
            return flags;
        case F_OGETLK:
            return flags;
        case F_OSETLK:
            return flags;
        case F_OSETLKW:
            return flags;
        default:
            return flags;
    }
}

static long
linux2freebsd_ioctl(unsigned long request)
{
    switch(request) {
        case LINUX_TIOCEXCL:
            return TIOCEXCL;
        case LINUX_TIOCNXCL:
            return TIOCNXCL;
        case LINUX_TIOCSCTTY:
            return TIOCSCTTY;
        case LINUX_TIOCGPGRP:
            return TIOCGPGRP;
        case LINUX_TIOCSPGRP:
            return TIOCSPGRP;
        case LINUX_TIOCOUTQ:
            return TIOCOUTQ;
        case LINUX_TIOCSTI:
            return TIOCSTI;
        case LINUX_TIOCGWINSZ:
            return TIOCGWINSZ;
        case LINUX_TIOCSWINSZ:
            return TIOCSWINSZ;
        case LINUX_TIOCMGET:
            return TIOCMGET;
        case LINUX_TIOCMBIS:
            return TIOCMBIS;
        case LINUX_TIOCMBIC:
            return TIOCMBIC;
        case LINUX_TIOCMSET:
            return TIOCMSET;
        case LINUX_FIONREAD:
            return FIONREAD;
        case LINUX_TIOCCONS:
            return TIOCCONS;
        case LINUX_TIOCPKT:
            return TIOCPKT;
        case LINUX_FIONBIO:
            return FIONBIO;
        case LINUX_TIOCNOTTY:
            return TIOCNOTTY;
        case LINUX_TIOCSETD:
            return TIOCSETD;
        case LINUX_TIOCGETD:
            return TIOCGETD;
        case LINUX_TIOCSBRK:
            return TIOCSBRK;
        case LINUX_TIOCCBRK:
            return TIOCCBRK;
        case LINUX_TIOCGSID:
            return TIOCGSID;
        case LINUX_FIONCLEX:
            return FIONCLEX;
        case LINUX_FIOCLEX:
            return FIOCLEX;
        case LINUX_FIOASYNC:
            return FIOASYNC;
        case LINUX_TIOCPKT_DATA:
            return TIOCPKT_DATA;
        case LINUX_TIOCPKT_FLUSHREAD:
            return TIOCPKT_FLUSHREAD;
        case LINUX_TIOCPKT_FLUSHWRITE:
            return TIOCPKT_FLUSHWRITE;
        case LINUX_TIOCPKT_STOP:
            return TIOCPKT_STOP;
        case LINUX_TIOCPKT_START:
            return TIOCPKT_START;
        case LINUX_TIOCPKT_NOSTOP:
            return TIOCPKT_NOSTOP;
        case LINUX_TIOCPKT_DOSTOP:
            return TIOCPKT_DOSTOP;
        case LINUX_TIOCPKT_IOCTL:
            return TIOCPKT_IOCTL;
        case LINUX_SIOCGIFCONF:
            return SIOCGIFCONF;
        case LINUX_SIOCGIFFLAGS:
            return SIOCGIFFLAGS;
        case LINUX_SIOCSIFFLAGS:
            return SIOCSIFFLAGS;
        case LINUX_SIOCGIFADDR:
            return SIOCGIFADDR;
        case LINUX_SIOCSIFADDR:
            return SIOCSIFADDR;
        case LINUX_SIOCGIFDSTADDR:
            return SIOCGIFDSTADDR;
        case LINUX_SIOCSIFDSTADDR:
            return SIOCSIFDSTADDR;
        case LINUX_SIOCGIFBRDADDR:
            return SIOCGIFBRDADDR;
        case LINUX_SIOCSIFBRDADDR:
            return SIOCSIFBRDADDR;
        case LINUX_SIOCGIFNETMASK:
            return SIOCGIFNETMASK;
        case LINUX_SIOCSIFNETMASK:
            return SIOCSIFNETMASK;
        case LINUX_SIOCGIFMETRIC:
            return SIOCGIFMETRIC;
        case LINUX_SIOCSIFMETRIC:
            return SIOCSIFMETRIC;
        case LINUX_SIOCGIFMTU:
            return SIOCGIFMTU;
        case LINUX_SIOCSIFMTU:
            return SIOCSIFMTU;
        case LINUX_SIOCSIFNAME:
            return SIOCSIFNAME;
        case LINUX_SIOCADDMULTI:
            return SIOCADDMULTI;
        case LINUX_SIOCDELMULTI:
            return SIOCDELMULTI;
        case LINUX_SIOCGIFINDEX:
            return SIOCGIFINDEX;
        case LINUX_SIOCDIFADDR:
            return SIOCDIFADDR;
        default:
            return -1;
    }
}

static int
so_opt_convert(int optname)
{
    switch(optname) {
        case LINUX_SO_DEBUG:
            return SO_DEBUG;
        case LINUX_SO_REUSEADDR:
            return SO_REUSEADDR;
        case LINUX_SO_ERROR:
            return SO_ERROR;
        case LINUX_SO_DONTROUTE:
            return SO_DONTROUTE;
        case LINUX_SO_BROADCAST:
            return SO_BROADCAST;
        case LINUX_SO_SNDBUF:
            return SO_SNDBUF;
        case LINUX_SO_RCVBUF:
            return SO_RCVBUF;
        case LINUX_SO_KEEPALIVE:
            return SO_KEEPALIVE;
        case LINUX_SO_OOBINLINE:
            return SO_OOBINLINE;
        case LINUX_SO_LINGER:
            return SO_LINGER;
        case LINUX_SO_REUSEPORT:
            return SO_REUSEPORT;
        case LINUX_SO_RCVLOWAT:
            return SO_RCVLOWAT;
        case LINUX_SO_SNDLOWAT:
            return SO_SNDLOWAT;
        case LINUX_SO_RCVTIMEO:
            return SO_RCVTIMEO;
        case LINUX_SO_SNDTIMEO:
            return SO_SNDTIMEO;
        case LINUX_SO_ACCEPTCONN:
            return SO_ACCEPTCONN;
        case LINUX_SO_PROTOCOL:
            return SO_PROTOCOL;
        case LINUX_SO_TIMESTAMP:
            return SO_TIMESTAMP;
        default:
            return -1;
    }
}

static int
ip_opt_convert(int optname)
{
    switch(optname) {
        case LINUX_IP_TOS:
            return IP_TOS;
        case LINUX_IP_TTL:
            return IP_TTL;
        case LINUX_IP_HDRINCL:
            return IP_HDRINCL;
        case LINUX_IP_OPTIONS:
            return IP_OPTIONS;
        case LINUX_IP_MULTICAST_IF:
            return IP_MULTICAST_IF;
        case LINUX_IP_MULTICAST_TTL:
            return IP_MULTICAST_TTL;
        case LINUX_IP_MULTICAST_LOOP:
            return IP_MULTICAST_LOOP;
        case LINUX_IP_ADD_MEMBERSHIP:
            return IP_ADD_MEMBERSHIP;
        case LINUX_IP_DROP_MEMBERSHIP:
            return IP_DROP_MEMBERSHIP;
        case LINUX_IP_RECVTTL:
            return IP_RECVTTL;
        case LINUX_IP_RECVTOS:
            return IP_RECVTOS;
        case LINUX_IP_TRANSPARENT:
            return IP_BINDANY;
        case LINUX_IP_MINTTL:
            return IP_MINTTL;
        default:
            return optname;
    }
}

static int
ip6_opt_convert(int optname)
{
    switch(optname) {
        case LINUX_IPV6_V6ONLY:
            return IPV6_V6ONLY;
        case LINUX_IPV6_RECVPKTINFO:
            return IPV6_RECVPKTINFO;
        case LINUX_IPV6_TRANSPARENT:
            return IPV6_BINDANY;
        default:
            return optname;
    }
}

static int
tcp_opt_convert(int optname)
{
    switch(optname) {
        case LINUX_TCP_NODELAY:
            return TCP_NODELAY;
        case LINUX_TCP_MAXSEG:
            return TCP_MAXSEG;
        case LINUX_TCP_KEEPIDLE:
            return TCP_KEEPIDLE;
        case LINUX_TCP_KEEPINTVL:
            return TCP_KEEPINTVL;
        case LINUX_TCP_KEEPCNT:
            return TCP_KEEPCNT;
        case LINUX_TCP_INFO:
            return TCP_INFO;
        case LINUX_TCP_MD5SIG:
            return TCP_MD5SIG;
        default:
            return -1;
    }
}

static int
linux2freebsd_opt(int level, int optname)
{
    switch(level) {
        case SOL_SOCKET:
            return so_opt_convert(optname);
        case IPPROTO_IP:
            return ip_opt_convert(optname);
        case IPPROTO_IPV6:
            return ip6_opt_convert(optname);
        case IPPROTO_TCP:
            return tcp_opt_convert(optname);
        default:
            return -1;
    }
}

static int
linux2freebsd_socket_flags(int flags)
{
    if (flags & LINUX_SOCK_NONBLOCK) {
        flags &= ~LINUX_SOCK_NONBLOCK;
        flags |= SOCK_NONBLOCK;
    }
    if (flags & LINUX_SOCK_CLOEXEC) {
        flags &= ~LINUX_SOCK_CLOEXEC;
        flags |= SOCK_CLOEXEC;
    }
    return flags;
}

static void
linux2freebsd_sockaddr(const struct linux_sockaddr *linux,
    socklen_t addrlen, struct sockaddr *freebsd)
{
    if (linux == NULL || freebsd == NULL) {
        return;
    }

    /* #linux and #freebsd may point to the same address */
    freebsd->sa_family = linux->sa_family == LINUX_AF_INET6 ? AF_INET6 : linux->sa_family;
    freebsd->sa_len = addrlen;

    if (linux->sa_data != freebsd->sa_data) {
        bcopy(linux->sa_data, freebsd->sa_data, addrlen - sizeof(linux->sa_family));
    }
}

static void
freebsd2linux_sockaddr(struct linux_sockaddr *linux,
    struct sockaddr *freebsd)
{
    if (linux == NULL || freebsd == NULL) {
        return;
    }

    /* #linux and #freebsd may point to the same address */
    if (linux->sa_data != freebsd->sa_data) {
        bcopy(freebsd->sa_data, linux->sa_data, freebsd->sa_len - sizeof(linux->sa_family));
    }
    linux->sa_family = freebsd->sa_family == AF_INET6 ? LINUX_AF_INET6 : freebsd->sa_family;
}

static inline int
freebsd2linux_cmsghdr(struct linux_msghdr *linux_msg, const struct msghdr *freebsd_msg)
{
    struct cmsghdr *freebsd_cmsg = CMSG_FIRSTHDR(freebsd_msg);
    struct linux_cmsghdr *linux_cmsg = LINUX_CMSG_FIRSTHDR(linux_msg);

    while (freebsd_cmsg && linux_cmsg) {
        unsigned char *freebsd_optval = CMSG_DATA(freebsd_cmsg);
        unsigned char *linux_optval = LINUX_CMSG_DATA(linux_cmsg);

        /*
         * The address of linux_cmsg and freebsd_cmsg coincides while recvmsg,
         * but the position of the variable pointer is different,
         * and the assignment must be reversed.
         *
         * Although sizeof(struct linux_msghdr) and sizeof(struct msghdr) have different lengths,
         * but cmsg_data both skip the same 16 bytes，both aligned to 8 bytes.
         */
        linux_cmsg->cmsg_type = freebsd_cmsg->cmsg_type;
        linux_cmsg->cmsg_level = freebsd_cmsg->cmsg_level;
        linux_cmsg->cmsg_len = LINUX_CMSG_LEN(freebsd_cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr)));

        /*
         * The freebsd_msg's cmsg_level and cmsg_type has been moddied while recvmsg,
         * must use linux_cmsg to judge and calculate data length.
         * And don't copy other the bytes that used aligned.
         */
        switch (linux_cmsg->cmsg_level) {
            case IPPROTO_IP:
                switch (linux_cmsg->cmsg_type) {
                    case IP_RECVTOS:
                        linux_cmsg->cmsg_type = LINUX_IP_TOS;
                        *linux_optval = *freebsd_optval;
                        break;
                    case IP_RECVTTL:
                        linux_cmsg->cmsg_len = LINUX_CMSG_LEN(sizeof(int));
                        linux_cmsg->cmsg_type = LINUX_IP_TTL;
                        *(int *)linux_optval = *freebsd_optval;
                        break;
                    /*case XXXX:
                        break;*/
                    default:
                        memcpy(linux_optval, freebsd_optval, linux_cmsg->cmsg_len - sizeof(struct linux_cmsghdr));
                        break;
                }

                break;
            default:
                memcpy(linux_optval, freebsd_optval, linux_cmsg->cmsg_len - sizeof(struct linux_cmsghdr));
                break;
        }

        linux_cmsg = LINUX_CMSG_NXTHDR(linux_msg, linux_cmsg);
        freebsd_cmsg = CMSG_NXTHDR(freebsd_msg, freebsd_cmsg);
    }

    return 0;
}

static inline int
linux2freebsd_cmsg(const struct linux_msghdr *linux_msg, struct msghdr *freebsd_msg)
{
    struct cmsghdr *freebsd_cmsg = CMSG_FIRSTHDR(freebsd_msg);
    struct linux_cmsghdr *linux_cmsg = LINUX_CMSG_FIRSTHDR(linux_msg);

    while (freebsd_cmsg && linux_cmsg) {
        unsigned char *freebsd_optval = CMSG_DATA(freebsd_cmsg);
        unsigned char *linux_optval = LINUX_CMSG_DATA(linux_cmsg);

        freebsd_cmsg->cmsg_type = linux_cmsg->cmsg_type;
        freebsd_cmsg->cmsg_level = linux_cmsg->cmsg_level;
        freebsd_cmsg->cmsg_len = CMSG_LEN(linux_cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct linux_cmsghdr)));

        switch (linux_cmsg->cmsg_level) {
            case IPPROTO_IP:
                switch (linux_cmsg->cmsg_type) {
                    case LINUX_IP_TOS:
                        freebsd_cmsg->cmsg_type = IP_TOS;
                        freebsd_cmsg->cmsg_len = CMSG_LEN(sizeof(char));

                        if (linux_cmsg->cmsg_len == LINUX_CMSG_LEN(sizeof(int))) {
                            *freebsd_optval = *(int *)linux_optval;
                        } else if (linux_cmsg->cmsg_len == LINUX_CMSG_LEN(sizeof(char))) {
                            *freebsd_optval = *linux_optval;
                        }

                        break;
                    case LINUX_IP_TTL:
                        freebsd_cmsg->cmsg_type = IP_TTL;
                        freebsd_cmsg->cmsg_len = CMSG_LEN(sizeof(char));

                        *freebsd_optval = *(int *)linux_optval;

                        break;
                    /*case XXXX:
                        break;*/
                    default:
                        memcpy(freebsd_optval, linux_optval, linux_cmsg->cmsg_len - sizeof(struct linux_cmsghdr));
                        break;
                }

                break;
            case IPPROTO_IPV6:
                switch (linux_cmsg->cmsg_type) {
                    case LINUX_IPV6_PKTINFO:
                        freebsd_cmsg->cmsg_type = IPV6_PKTINFO;
                        *(struct in6_pktinfo *)freebsd_optval = *(struct in6_pktinfo *)linux_optval;
                        break;
                    default:
                        memcpy(freebsd_optval, linux_optval, linux_cmsg->cmsg_len - sizeof(struct linux_cmsghdr));
                        break;
                }
                break;
            default:
                memcpy(freebsd_optval, linux_optval, linux_cmsg->cmsg_len - sizeof(struct linux_cmsghdr));
                break;
        }

        linux_cmsg = LINUX_CMSG_NXTHDR(linux_msg, linux_cmsg);
        freebsd_cmsg = CMSG_NXTHDR(freebsd_msg, freebsd_cmsg);
    }

    return 0;
}

/*
 * While sendmsg, need convert msg_name and msg_control from Linux to FreeBSD.
 * While recvmsg, need convert msg_name and msg_control from FreeBSD to Linux.
 * Note: linux2freebsd_msghdr and freebsd2linux_msghdr must be called in sequence and in pairs.
 */
static int
freebsd2linux_msghdr(struct linux_msghdr *linux_msg, struct msghdr *freebsd_msg, int send_flag)
{
    if (linux_msg == NULL || freebsd_msg == NULL) {
        return -1;
    }

    if (linux_msg->msg_name && freebsd_msg->msg_name && !send_flag) {
        linux_msg->msg_name = freebsd_msg->msg_name;
        freebsd2linux_sockaddr(linux_msg->msg_name, freebsd_msg->msg_name);
        linux_msg->msg_namelen = freebsd_msg->msg_namelen;
    }

    linux_msg->msg_iov = freebsd_msg->msg_iov;
    linux_msg->msg_iovlen = freebsd_msg->msg_iovlen;
    /* Restore the old iov pointer, compatible with the Linux interface */
    memcpy(linux_msg->msg_iov, msg_iov_tmp, msg_iovlen_tmp * sizeof(struct iovec));

    if(freebsd_msg->msg_control && linux_msg->msg_control && !send_flag) {
        freebsd2linux_cmsghdr(linux_msg, freebsd_msg);
        linux_msg->msg_controllen = freebsd_msg->msg_controllen;
    }

    linux_msg->msg_flags = freebsd_msg->msg_flags;

    return 0;
}

static int
linux2freebsd_msghdr(const struct linux_msghdr *linux_msg, struct msghdr *freebsd_msg, int send_flag)
{
    int ret = 0;

    if (linux_msg == NULL || freebsd_msg == NULL) {
        return -1;;
    }

    if (linux_msg->msg_name && freebsd_msg->msg_name && send_flag) {
        linux2freebsd_sockaddr(linux_msg->msg_name, linux_msg->msg_namelen, freebsd_msg->msg_name);
    } else {
        freebsd_msg->msg_name = linux_msg->msg_name;
    }
    freebsd_msg->msg_namelen = linux_msg->msg_namelen;

    /* Save the old iov pointer, compatible with the Linux interface */
    msg_iovlen_tmp = linux_msg->msg_iovlen;
    if (msg_iovlen_tmp > UIO_MAXIOV) {
        return -1; // EMSGSIZE;
    }
    memcpy(msg_iov_tmp, linux_msg->msg_iov, msg_iovlen_tmp * sizeof(struct iovec));
    freebsd_msg->msg_iov = linux_msg->msg_iov;
    freebsd_msg->msg_iovlen = linux_msg->msg_iovlen;

    freebsd_msg->msg_controllen = linux_msg->msg_controllen;
    if (linux_msg->msg_control && send_flag) {
        ret = linux2freebsd_cmsg(linux_msg, freebsd_msg);
        if(ret < 0) {
            return ret;
        }
    } else {
        freebsd_msg->msg_control = linux_msg->msg_control;
    }

    freebsd_msg->msg_flags = linux_msg->msg_flags;

    return 0;
}

int
ff_socket(int domain, int type, int protocol)
{
    int rc;
    struct socket_args sa;

#ifdef FF_KERNEL_COEXIST
    /*
     * Kernel-stack coexistence. With coexistence enabled: SOCK_KERNEL (without
     * SOCK_FSTACK) -> kernel stack only; SOCK_FSTACK -> F-Stack only; no marker
     * (default) -> dual stack (an F-Stack socket plus a paired host kernel
     * socket kept in the native fd map). Off / macro-off keeps the original
     * F-Stack path byte-for-byte.
     */
    int want_dual = 0;
    if (ff_global_cfg.stack.kernel_coexist) {
        if ((type & SOCK_KERNEL) && !(type & SOCK_FSTACK)) {
            int kfd = ff_host_socket(domain,
                type & ~(SOCK_KERNEL | SOCK_FSTACK), protocol);
            return kfd < 0 ? -1 : ff_kernel_fd_encode(kfd);
        }
        want_dual = !(type & SOCK_FSTACK);
    }
    type &= ~(SOCK_KERNEL | SOCK_FSTACK);
#endif /* FF_KERNEL_COEXIST */

    sa.domain = domain == LINUX_AF_INET6 ? AF_INET6 : domain;
    sa.type = linux2freebsd_socket_flags(type);
    sa.protocol = protocol;
    if ((rc = sys_socket(curthread, &sa)))
        goto kern_fail;

#ifdef FF_KERNEL_COEXIST
    if (want_dual) {
        int hfd = ff_host_socket(domain, type, protocol);
        if (hfd >= 0) {
            if (domain == LINUX_AF_INET6)
                ff_host_set_v6only(hfd);
            ff_native_map_set(curthread->td_retval[0], hfd);
        }
    }
#endif /* FF_KERNEL_COEXIST */
    return curthread->td_retval[0];
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_getsockopt(int s, int level, int optname, void *optval,
    socklen_t *optlen)
{
    int rc;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_getsockopt(ff_kernel_fd_real(s), level, optname,
            optval, optlen);
#endif /* FF_KERNEL_COEXIST */

    if (level == LINUX_SOL_SOCKET)
        level = SOL_SOCKET;

    optname = linux2freebsd_opt(level, optname);
    if (optname < 0) {
        rc = EINVAL;
        goto kern_fail;
    }

    if ((rc = kern_getsockopt(curthread, s, level, optname,
            optval, UIO_USERSPACE, optlen)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_getsockopt_freebsd(int s, int level, int optname,
    void *optval, socklen_t *optlen)
{
    int rc;

    if ((rc = kern_getsockopt(curthread, s, level, optname,
            optval, UIO_USERSPACE, optlen)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen)
{
    int rc;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_setsockopt(ff_kernel_fd_real(s), level, optname,
            optval, optlen);
    if (ff_global_cfg.stack.kernel_coexist) {
        int hfd = ff_native_map_get(s);
        if (hfd > 0)
            ff_host_setsockopt(hfd, level, optname, optval, optlen);
    }
#endif /* FF_KERNEL_COEXIST */

    if (level == LINUX_SOL_SOCKET)
        level = SOL_SOCKET;

    optname = linux2freebsd_opt(level, optname);
    if (optname < 0) {
        rc = EINVAL;
        goto kern_fail;
    }

    if ((rc = kern_setsockopt(curthread, s, level, optname,
            __DECONST(void *, optval), UIO_USERSPACE, optlen)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_setsockopt_freebsd(int s, int level, int optname,
    const void *optval, socklen_t optlen)
{
    int rc;

    if ((rc = kern_setsockopt(curthread, s, level, optname,
            __DECONST(void *, optval), UIO_USERSPACE, optlen)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_ioctl(int fd, unsigned long request, ...)
{
    int rc;
    va_list ap;
    caddr_t argp;
    long req;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(fd)) {
        va_start(ap, request);
        argp = va_arg(ap, caddr_t);
        va_end(ap);
        return ff_host_ioctl(ff_kernel_fd_real(fd), request, argp);
    }
#endif /* FF_KERNEL_COEXIST */

    req = linux2freebsd_ioctl(request);
    if (req < 0) {
        rc = EINVAL;
        goto kern_fail;
    }

    va_start(ap, request);

    argp = va_arg(ap, caddr_t);
    va_end(ap);
    if ((rc = kern_ioctl(curthread, fd, req, argp)))
        goto kern_fail;

#ifdef FF_KERNEL_COEXIST
    /* Sync set-direction ioctls (FIONBIO/FIOASYNC) to the paired host fd so a
     * dual-stack fd keeps the same I/O mode on both stacks. Query ioctls are
     * not forwarded: they write back into argp and the F-Stack value above is
     * authoritative for the application fd. Host side uses the raw Linux
     * request (host namespace, untranslated). */
    if (ff_global_cfg.stack.kernel_coexist &&
        (request == LINUX_FIONBIO || request == LINUX_FIOASYNC)) {
        int hfd = ff_native_map_get(fd);
        if (hfd > 0)
            ff_host_ioctl(hfd, request, argp);
    }
#endif /* FF_KERNEL_COEXIST */

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_ioctl_freebsd(int fd, unsigned long request, ...)
{
    int rc;
    va_list ap;
    caddr_t argp;

    va_start(ap, request);

    argp = va_arg(ap, caddr_t);
    va_end(ap);
    if ((rc = kern_ioctl(curthread, fd, request, argp)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_close(int fd)
{
    int rc;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(fd))
        return ff_host_close(ff_kernel_fd_real(fd));
#endif /* FF_KERNEL_COEXIST */

    if ((rc = kern_close(curthread, fd)))
        goto kern_fail;

#ifdef FF_KERNEL_COEXIST
    /* Try to close the socket fd or epoll fd respectively */
    if (ff_global_cfg.stack.kernel_coexist) {
        int hfd = ff_native_map_get(fd);
        if (hfd > 0) {
            ff_host_close(hfd);
            ff_native_map_clear(fd);
        }
        ff_epoll_close_pair(fd);
    }
#endif /* FF_KERNEL_COEXIST */

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_read(int fd, void *buf, size_t nbytes)
{
    struct uio auio;
    struct iovec aiov;
    int rc;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(fd))
        return ff_host_read(ff_kernel_fd_real(fd), buf, nbytes);
#endif /* FF_KERNEL_COEXIST */

    if (nbytes > INT_MAX) {
        rc = EINVAL;
        goto kern_fail;
    }

    aiov.iov_base = buf;
    aiov.iov_len = nbytes;
    auio.uio_iov = &aiov;
    auio.uio_iovcnt = 1;
    auio.uio_resid = nbytes;
    auio.uio_segflg = UIO_SYSSPACE;
    if ((rc = kern_readv(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_readv(int fd, const struct iovec *iov, int iovcnt)
{
    struct uio auio;
    int rc, len, i;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(fd))
        return ff_host_readv(ff_kernel_fd_real(fd), iov, iovcnt);
#endif /* FF_KERNEL_COEXIST */

    len = 0;
    for (i = 0; i < iovcnt; i++)
        len += iov[i].iov_len;
    auio.uio_iov = __DECONST(struct iovec *, iov);
    auio.uio_iovcnt = iovcnt;
    auio.uio_resid = len;
    auio.uio_segflg = UIO_SYSSPACE;

    if ((rc = kern_readv(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_write(int fd, const void *buf, size_t nbytes)
{
    struct uio auio;
    struct iovec aiov;
    int rc;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(fd))
        return ff_host_write(ff_kernel_fd_real(fd), buf, nbytes);
#endif /* FF_KERNEL_COEXIST */

    if (nbytes > INT_MAX) {
        rc = EINVAL;
        goto kern_fail;
    }

    aiov.iov_base = (void *)(uintptr_t)buf;
    aiov.iov_len = nbytes;
    auio.uio_iov = &aiov;
    auio.uio_iovcnt = 1;
    auio.uio_resid = nbytes;
    auio.uio_segflg = UIO_SYSSPACE;
    if ((rc = kern_writev(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_writev(int fd, const struct iovec *iov, int iovcnt)
{
    struct uio auio;
    int i, rc, len;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(fd))
        return ff_host_writev(ff_kernel_fd_real(fd), iov, iovcnt);
#endif /* FF_KERNEL_COEXIST */

    len = 0;
    for (i = 0; i < iovcnt; i++)
        len += iov[i].iov_len;
    auio.uio_iov = __DECONST(struct iovec *, iov);
    auio.uio_iovcnt = iovcnt;
    auio.uio_resid = len;
    auio.uio_segflg = UIO_SYSSPACE;
    if ((rc = kern_writev(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

#ifdef FSTACK_ZC_SEND
/*
 * Zero-copy send fast-path. Caller passes a pre-built mbuf chain head
 * (obtained from ff_zc_mbuf_get + ff_zc_mbuf_write; cast through
 * const void* for ABI compatibility) as `mb`. We re-cast to
 * struct mbuf* and hand it to kern_zc_sendit, which calls sosend
 * with top != NULL and uio == NULL — the FreeBSD-native zero-copy
 * send path. No uio_offset sentinel stamping and no m_uiotombuf
 * kernel modification are needed anymore.
 */
ssize_t
ff_zc_send(int fd, const void *mb, size_t nbytes)
{
    struct mbuf *top;
    int rc;

    if (mb == NULL || nbytes == 0 || nbytes > INT_MAX) {
        rc = EINVAL;
        goto kern_fail;
    }

    /* The chain MUST already be M_PKTHDR-headed with pkthdr.len set by
     * ff_zc_mbuf_get/write; kern_zc_sendit re-validates and returns
     * EINVAL (freeing the chain) otherwise. */
    top = (struct mbuf *)(uintptr_t)mb;

    if ((rc = kern_zc_sendit(curthread, fd, top, 0)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}
#endif /* FSTACK_ZC_SEND */

#ifdef FSTACK_ZC_RECV
/*
 * FSTACK_ZC_RECV: zero-copy receive entry. Builds a uio carrying only the
 * requested byte budget (uio_resid) and calls kern_zc_recvit, which passes a
 * non-NULL mbuf out-parameter into soreceive so the socket-buffer mbuf chain
 * is handed back without a uiomove copy. On success zm->bsd_mbuf holds the
 * chain head; the caller must release it via ff_zc_recv_free().
 *
 * `zm` must be a valid 'struct ff_zc_mbuf *'. Do NOT pass a char buffer.
 */
ssize_t
ff_zc_recv(int fd, struct ff_zc_mbuf *zm, size_t nbytes)
{
    struct uio auio;
    struct iovec aiov;
    struct mbuf *chain = NULL;
    int rc;

    if (zm == NULL || nbytes == 0 || nbytes > INT_MAX) {
        rc = EINVAL;
        goto kern_fail;
    }

    /* uio is only consulted for uio_resid when mp0 is non-NULL (soreceive(9));
     * iov_base is unused on the ZC path but set for completeness. */
    aiov.iov_base = NULL;
    aiov.iov_len = nbytes;
    auio.uio_iov = &aiov;
    auio.uio_iovcnt = 1;
    auio.uio_resid = nbytes;
    auio.uio_segflg = UIO_SYSSPACE;
    auio.uio_rw = UIO_READ;
    auio.uio_td = curthread;
    auio.uio_offset = 0;

    if ((rc = kern_zc_recvit(curthread, fd, &auio, &chain)))
        goto kern_fail;

    rc = curthread->td_retval[0];

    zm->bsd_mbuf = chain;
    zm->bsd_mbuf_off = chain;
    zm->off = 0;
    zm->len = rc;

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}
#endif /* FSTACK_ZC_RECV */

ssize_t
ff_send(int s, const void *buf, size_t len, int flags)
{
    return (ff_sendto(s, buf, len, flags, NULL, 0));
}

ssize_t
ff_sendto(int s, const void *buf, size_t len, int flags,
         const struct linux_sockaddr *to, socklen_t tolen)
{
    struct msghdr msg;
    struct iovec aiov;
    int rc;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s)) {
        return to ? ff_host_sendto(ff_kernel_fd_real(s), buf, len, flags,
                                   to, tolen)
                  : ff_host_send(ff_kernel_fd_real(s), buf, len, flags);
    }
#endif /* FF_KERNEL_COEXIST */

    struct sockaddr_storage bsdaddr;
    struct sockaddr *pf = (struct sockaddr *)&bsdaddr;

    if (to) {
        linux2freebsd_sockaddr(to, tolen, pf);
    } else {
        pf = NULL;
    }

    msg.msg_name = pf;
    msg.msg_namelen = tolen;
    msg.msg_iov = &aiov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    aiov.iov_base = __DECONST(void *, buf);
    aiov.iov_len = len;
    if ((rc = sendit(curthread, s, &msg, flags)))
        goto kern_fail;

    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_sendmsg(int s, const struct msghdr *msg, int flags)
{
    int rc, ret;
    struct sockaddr_storage freebsd_sa;
    struct msghdr freebsd_msg;
    struct cmsghdr *freebsd_cmsg = NULL;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_sendmsg(ff_kernel_fd_real(s), msg, flags);
#endif /* FF_KERNEL_COEXIST */

    freebsd_msg.msg_name = &freebsd_sa;
    if ((__DECONST(struct linux_msghdr *, msg))->msg_control) {
        freebsd_cmsg = malloc((__DECONST(struct linux_msghdr *, msg))->msg_controllen, NULL, 0);
        if (freebsd_cmsg == NULL) {
            rc = ENOMEM;
            goto kern_fail;
        }
    }
    freebsd_msg.msg_control = freebsd_cmsg;

    ret = linux2freebsd_msghdr((const struct linux_msghdr *)msg, &freebsd_msg, 1);
    if (ret < 0) {
        rc = EINVAL;
        goto kern_fail;
    }

    rc = sendit(curthread, s, &freebsd_msg, flags);
    if (rc)
        goto kern_fail;

    rc = curthread->td_retval[0];

    freebsd2linux_msghdr(__DECONST(struct linux_msghdr *, msg), &freebsd_msg, 1);

    if (freebsd_cmsg) {
        free(freebsd_cmsg, NULL);
    }

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}


ssize_t
ff_recv(int s, void *buf, size_t len, int flags)
{
    return (ff_recvfrom(s, buf, len, flags, NULL, 0));
}

ssize_t
ff_recvfrom(int s, void *buf, size_t len, int flags,
    struct linux_sockaddr *from, socklen_t *fromlen)
{
    struct msghdr msg;
    struct iovec aiov;
    int rc;
    struct sockaddr_storage bsdaddr;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_recvfrom(ff_kernel_fd_real(s), buf, len, flags,
            from, fromlen);
#endif /* FF_KERNEL_COEXIST */

    if (fromlen != NULL)
        msg.msg_namelen = *fromlen;
    else
        msg.msg_namelen = 0;

    msg.msg_name = &bsdaddr;
    msg.msg_iov = &aiov;
    msg.msg_iovlen = 1;
    aiov.iov_base = buf;
    aiov.iov_len = len;
    msg.msg_control = 0;
    msg.msg_flags = flags;
    if ((rc = kern_recvit(curthread, s, &msg, UIO_SYSSPACE, NULL)))
        goto kern_fail;
    rc = curthread->td_retval[0];
    if (fromlen != NULL)
        *fromlen = msg.msg_namelen;

    if (from && msg.msg_namelen != 0)
        freebsd2linux_sockaddr(from, (struct sockaddr *)&bsdaddr);

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

/*
 * It is considered here that the upper 4 bytes of
 * msg->iovlen and msg->msg_controllen in linux_msghdr are 0.
 */
ssize_t
ff_recvmsg(int s, struct msghdr *msg, int flags)
{
    int rc, ret;
    struct msghdr freebsd_msg;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_recvmsg(ff_kernel_fd_real(s), msg, flags);
#endif /* FF_KERNEL_COEXIST */

    ret = linux2freebsd_msghdr((struct linux_msghdr *)msg, &freebsd_msg, 0);
    if (ret < 0) {
        rc = EINVAL;
        goto kern_fail;
    }
    freebsd_msg.msg_flags = flags;

    if ((rc = kern_recvit(curthread, s, &freebsd_msg, UIO_SYSSPACE, NULL))) {
        goto kern_fail;
    }
    rc = curthread->td_retval[0];

    freebsd2linux_msghdr((struct linux_msghdr *)msg, &freebsd_msg, 0);

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_fcntl(int fd, int cmd, ...)
{
    int rc;
    va_list ap;
    uintptr_t argp;

    va_start(ap, cmd);

    argp = va_arg(ap, uintptr_t);
    va_end(ap);

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(fd))
        return ff_host_fcntl(ff_kernel_fd_real(fd), cmd, (int)argp);
    if (ff_global_cfg.stack.kernel_coexist) {
        int hfd = ff_native_map_get(fd);
        if (hfd > 0)
            ff_host_fcntl(hfd, cmd, (int)argp);
    }
#endif /* FF_KERNEL_COEXIST */

    cmd = linux2freebsd_fcntl(cmd, &argp);

    if ((rc = kern_fcntl(curthread, fd, cmd, argp)))
        goto kern_fail;
    rc = freebsd2linux_fcntl(cmd, curthread->td_retval[0]);
    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_accept(int s, struct linux_sockaddr * addr,
    socklen_t * addrlen)
{
    int rc;
    struct file *fp;
    struct sockaddr_storage pfss;
    struct sockaddr *pf = (struct sockaddr *)&pfss;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s)) {
        int kfd = ff_host_accept(ff_kernel_fd_real(s), addr, addrlen);
        return kfd < 0 ? -1 : ff_kernel_fd_encode(kfd);
    }
#endif /* FF_KERNEL_COEXIST */

    if ((rc = kern_accept(curthread, s, pf, &fp))) {
#ifdef FF_KERNEL_COEXIST
        /*
         * Here, we first attempt to accept the socket fd from the f-stack every time. If none is available,
         * we will then attempt to accept the socket fd from the kernel. This is different from LD_PRELOAD,
         * which obtains different fds by calling socket twice, but we cannot distinguish between them here?待定，开epoll是否可以区分
         */
        if ((rc == EAGAIN || rc == EWOULDBLOCK) &&
            ff_global_cfg.stack.kernel_coexist) {
            int hfd = ff_native_map_get(s);
            if (hfd > 0) {
                int kfd = ff_host_accept(hfd, addr, addrlen);
                if (kfd >= 0)
                    return ff_kernel_fd_encode(kfd);
            }
        }
#endif /* FF_KERNEL_COEXIST */
        goto kern_fail;
    }

    rc = curthread->td_retval[0];
    fdrop(fp, curthread);

    if (addr && pf)
        freebsd2linux_sockaddr(addr, pf);

    if (addrlen)
        *addrlen = pf->sa_len;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_accept4(int s, struct linux_sockaddr * addr,
    socklen_t * addrlen, int flags)
{
    int rc;
    struct file *fp;
    struct sockaddr_storage pfss;
    struct sockaddr *pf = (struct sockaddr *)&pfss;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s)) {
        int kfd = ff_host_accept4(ff_kernel_fd_real(s), addr, addrlen, flags);
        return kfd < 0 ? -1 : ff_kernel_fd_encode(kfd);
    }
#endif /* FF_KERNEL_COEXIST */

    if ((rc = kern_accept4(curthread, s, pf, linux2freebsd_socket_flags(flags), &fp))) {
#ifdef FF_KERNEL_COEXIST
        if ((rc == EAGAIN || rc == EWOULDBLOCK) &&
            ff_global_cfg.stack.kernel_coexist) {
            int hfd = ff_native_map_get(s);
            if (hfd > 0) {
                int kfd = ff_host_accept4(hfd, addr, addrlen, flags);
                if (kfd >= 0)
                    return ff_kernel_fd_encode(kfd);
            }
        }
#endif /* FF_KERNEL_COEXIST */
        goto kern_fail;
    }

    rc = curthread->td_retval[0];
    fdrop(fp, curthread);

    if (addr && pf)
        freebsd2linux_sockaddr(addr, pf);

    if (addrlen)
        *addrlen = pf->sa_len;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_listen(int s, int backlog)
{
    int rc;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_listen(ff_kernel_fd_real(s), backlog);
#endif /* FF_KERNEL_COEXIST */

    struct listen_args la = {
        .s = s,
        .backlog = backlog,
    };
    if ((rc = sys_listen(curthread, &la)))
        goto kern_fail;

#ifdef FF_KERNEL_COEXIST
    if (ff_global_cfg.stack.kernel_coexist) {
        int hfd = ff_native_map_get(s);
        if (hfd > 0 && ff_host_listen(hfd, backlog) < 0)
            return -1;
    }
#endif /* FF_KERNEL_COEXIST */

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen)
{
    int rc;
    struct sockaddr_storage bsdaddr;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_bind(ff_kernel_fd_real(s), addr, addrlen);
#endif /* FF_KERNEL_COEXIST */

    linux2freebsd_sockaddr(addr, addrlen, (struct sockaddr *)&bsdaddr);

    if ((rc = kern_bindat(curthread, AT_FDCWD, s, (struct sockaddr *)&bsdaddr)))
        goto kern_fail;

#ifdef FF_KERNEL_COEXIST
    if (ff_global_cfg.stack.kernel_coexist) {
        int hfd = ff_native_map_get(s);
        if (hfd > 0 && ff_host_bind(hfd, addr, addrlen) < 0)
            return -1;
    }
#endif /* FF_KERNEL_COEXIST */

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_connect(int s, const struct linux_sockaddr *name, socklen_t namelen)
{
    int rc;
    struct sockaddr_storage bsdaddr;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_connect(ff_kernel_fd_real(s), name, namelen);
#endif /* FF_KERNEL_COEXIST */

    linux2freebsd_sockaddr(name, namelen, (struct sockaddr *)&bsdaddr);

#ifdef FF_KERNEL_COEXIST
    /* Dual-stack: best-effort concurrent connect on the kernel side; the
     * F-Stack result below is authoritative for the return value. */
    if (ff_global_cfg.stack.kernel_coexist) {
        int hfd = ff_native_map_get(s);
        if (hfd > 0)
            ff_host_connect(hfd, name, namelen);
    }
#endif /* FF_KERNEL_COEXIST */

    if ((rc = kern_connectat(curthread, AT_FDCWD, s, (struct sockaddr *)&bsdaddr)))
        goto kern_fail;

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_getpeername(int s, struct linux_sockaddr * name,
    socklen_t *namelen)
{
    int rc;
    struct sockaddr_storage pfss;
    struct sockaddr *pf = (struct sockaddr *)&pfss;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_getpeername(ff_kernel_fd_real(s), name, namelen);
#endif /* FF_KERNEL_COEXIST */

    if ((rc = kern_getpeername(curthread, s, pf)))
        goto kern_fail;

    if (name && pf)
        freebsd2linux_sockaddr(name, pf);
    if (namelen)
        *namelen = pf->sa_len;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_getsockname(int s, struct linux_sockaddr *name,
    socklen_t *namelen)
{
    int rc;
    struct sockaddr_storage pfss;
    struct sockaddr *pf = (struct sockaddr *)&pfss;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_getsockname(ff_kernel_fd_real(s), name, namelen);
#endif /* FF_KERNEL_COEXIST */

    if ((rc = kern_getsockname(curthread, s, pf)))
        goto kern_fail;

    if (name && pf)
        freebsd2linux_sockaddr(name, pf);
    if (namelen)
        *namelen = pf->sa_len;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_shutdown(int s, int how)
{
    int rc;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(s))
        return ff_host_shutdown(ff_kernel_fd_real(s), how);
#endif /* FF_KERNEL_COEXIST */

    struct shutdown_args sa = {
        .s = s,
        .how = how,
    };
    if ((rc = sys_shutdown(curthread, &sa)))
        goto kern_fail;

#ifdef FF_KERNEL_COEXIST
    if (ff_global_cfg.stack.kernel_coexist) {
        int hfd = ff_native_map_get(s);
        if (hfd > 0)
            ff_host_shutdown(hfd, how);
    }
#endif /* FF_KERNEL_COEXIST */

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
         const void *newp, size_t newlen)
{
    int rc;
    size_t retval;

    rc = userland_sysctl(curthread, __DECONST(int *, name), namelen, oldp, oldlenp,
        1, __DECONST(void *, newp), newlen, &retval, 0);
    if (rc)
        goto kern_fail;
    if (oldlenp)
        *oldlenp = retval;
    return (0);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout)

{
    int rc;

    /*
     * FF_KERNEL_COEXIST limitation: encoded kernel fds (>= FF_KERNEL_FD_BASE,
     * 0x40000000) far exceed FD_SETSIZE and cannot fit in an fd_set, so select
     * cannot multiplex coexist kernel fds. Use epoll/kqueue for those instead.
     */
    rc = kern_select(curthread, nfds, readfds, writefds, exceptfds, timeout, 64);
    if (rc)
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);

}

int
ff_poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
    int rc;
    struct timespec ts;
    /*
     * FF_KERNEL_COEXIST limitation: kern_poll only polls F-Stack fds. Encoded
     * kernel fds are not routed here (mixing host-poll subsets with kern_poll
     * and merging revents is high-risk); use epoll/kqueue for coexist kernel
     * fds instead.
     */
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    if ((rc = kern_poll(curthread, fds, nfds, &ts, NULL)))
        goto kern_fail;
    rc = curthread->td_retval[0];
    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_kqueue(void)
{
    int rc;
    if ((rc = kern_kqueue(curthread, 0, NULL)))
        goto kern_fail;

    rc = curthread->td_retval[0];
    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

struct sys_kevent_args {
    int fd;
    const struct kevent *changelist;
    int nchanges;
    void *eventlist;
    int nevents;
    const struct timespec *timeout;
    void (*do_each)(void **, struct kevent *);
};

static int
kevent_copyout(void *arg, struct kevent *kevp, int count)
{
    int i;
    struct kevent *ke;
    struct sys_kevent_args *uap;

    uap = (struct sys_kevent_args *)arg;

    if (!uap->do_each) {
        bcopy(kevp, uap->eventlist, count * sizeof *kevp);
        uap->eventlist = (void *)((struct kevent *)(uap->eventlist) + count);

    } else {
        for (ke = kevp, i = 0; i < count; i++, ke++) {
            uap->do_each(&(uap->eventlist), ke);
        }
    }

    return (0);
}

/*
 * Copy 'count' items from the list pointed to by uap->changelist.
 */
static int
kevent_copyin(void *arg, struct kevent *kevp, int count)
{
    struct sys_kevent_args *uap;

    uap = (struct sys_kevent_args *)arg;
    bcopy(uap->changelist, kevp, count * sizeof *kevp);

    uap->changelist += count;

    return (0);
}

int
ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges,
    void *eventlist, int nevents, const struct timespec *timeout,
    void (*do_each)(void **, struct kevent *))
{
    int rc;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    struct sys_kevent_args ska = {
        kq,
        changelist,
        nchanges,
        eventlist,
        nevents,
        &ts,
        do_each
    };

    struct kevent_copyops k_ops = {
        &ska,
        kevent_copyout,
        kevent_copyin
    };

    if ((rc = kern_kevent(curthread, kq, nchanges, nevents, &k_ops,
            &ts)))
        goto kern_fail;

    rc = curthread->td_retval[0];
    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

#ifdef FF_KERNEL_COEXIST
/*
 * Coexistence for the native kqueue API (mirrors ff_epoll.c). changelist
 * entries whose ident is a managed kernel fd or a dual-stack fd are
 * (un)registered on the host epoll paired with this kqueue; the host epoll
 * stores the application-facing fd in data.fd. Kernel-only changes are not
 * forwarded to the F-Stack kqueue (it does not know that fd). On wait, the
 * host epoll is polled non-blocking and ready events are translated back into
 * struct kevent before the F-Stack events are appended. With no kernel fd
 * registered the path degrades to the original ff_kevent_do_each behaviour.
 */
static int
ff_kevent_host_change(int kq, const struct kevent *kev)
{
    int hfd, app_fd, del;

    if (ff_is_kernel_fd((int)kev->ident)) {
        hfd = ff_kernel_fd_real((int)kev->ident);
        app_fd = (int)kev->ident;
    } else if ((hfd = ff_native_map_get((int)kev->ident)) > 0) {
        app_fd = (int)kev->ident;
    } else {
        return 0;
    }

    if (kev->flags & EV_DELETE)
        del = 1;
    else if (kev->flags & (EV_ADD | EV_ENABLE))
        del = 0;
    else
        return 1;

    int host_ep = ff_epoll_host_ep(kq, !del);
    if (host_ep > 0)
        ff_host_kqueue_ctl(host_ep, del, hfd, app_fd,
            kev->filter == EVFILT_WRITE);
    return 1;
}

static int
ff_kevent_host_wait(int host_ep, struct kevent *eventlist, int nevents)
{
    int triples[3 * nevents];
    int n, i;

    n = ff_host_kqueue_poll(host_ep, triples, nevents);
    for (i = 0; i < n; i++) {
        short filter = triples[3 * i + 1] ? EVFILT_WRITE : EVFILT_READ;
        u_short flags = triples[3 * i + 2] ? EV_EOF : 0;
        EV_SET(&eventlist[i], triples[3 * i], filter, flags, 0, 1, NULL);
    }
    return n;
}
#endif /* FF_KERNEL_COEXIST */

int
ff_kevent(int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
#ifdef FF_KERNEL_COEXIST
    if (ff_global_cfg.stack.kernel_coexist) {
        struct kevent fbsd_changes[nchanges > 0 ? nchanges : 1];
        int fbsd_n = 0, i, kn = 0, host_ep;

        for (i = 0; i < nchanges; i++) {
            int handled = ff_kevent_host_change(kq, &changelist[i]);
            /* dual-stack fds also live on the F-Stack kqueue; kernel-only do not */
            if (!handled || ff_native_map_get((int)changelist[i].ident) > 0)
                fbsd_changes[fbsd_n++] = changelist[i];
        }

        if (eventlist != NULL && nevents > 0) {
            host_ep = ff_epoll_host_ep(kq, 0);
            if (host_ep > 0) {
                kn = ff_kevent_host_wait(host_ep, eventlist, nevents);
                if (kn >= nevents)
                    return kn;
            }
        }

        int rc = ff_kevent_do_each(kq, fbsd_n > 0 ? fbsd_changes : NULL,
            fbsd_n, eventlist ? eventlist + kn : NULL,
            eventlist ? nevents - kn : 0, timeout, NULL);
        if (rc < 0)
            return kn > 0 ? kn : -1;
        return kn + rc;
    }
#endif /* FF_KERNEL_COEXIST */
    return ff_kevent_do_each(kq, changelist, nchanges, eventlist, nevents, timeout, NULL);
}

int
#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 31)
ff_gettimeofday(struct timeval *tv, void *tz)
#else
ff_gettimeofday(struct timeval *tv, struct timezone *tz)
#endif
{
    long nsec;
    ff_get_current_time(&(tv->tv_sec), &nsec);
    tv->tv_usec = nsec/1000;
    return 0;
}

int
ff_dup(int oldfd)
{
    int rc;

#ifdef FF_KERNEL_COEXIST
    if (ff_is_kernel_fd(oldfd)) {
        int n = ff_host_dup(ff_kernel_fd_real(oldfd));
        return n < 0 ? -1 : ff_kernel_fd_encode(n);
    }
#endif /* FF_KERNEL_COEXIST */

    struct dup_args da = {
        .fd = oldfd,
    };
    if ((rc = sys_dup(curthread, &da)))
        goto kern_fail;

    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_dup2(int oldfd, int newfd)
{
    int rc;

#ifdef FF_KERNEL_COEXIST
    /* Cross-stack dup2 (one kernel fd, one F-Stack fd) has no coherent
     * semantics: the two fd spaces are disjoint and managed separately. */
    if (ff_is_kernel_fd(oldfd) != ff_is_kernel_fd(newfd)) {
        ff_os_errno(EINVAL);
        return (-1);
    }
    if (ff_is_kernel_fd(oldfd) && ff_is_kernel_fd(newfd)) {
        int n = ff_host_dup2(ff_kernel_fd_real(oldfd), ff_kernel_fd_real(newfd));
        return n < 0 ? -1 : ff_kernel_fd_encode(n);
    }
#endif /* FF_KERNEL_COEXIST */

    struct dup2_args da = {
        .from = oldfd,
        .to = newfd
    };
    if ((rc = sys_dup2(curthread, &da)))
        goto kern_fail;

    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
    struct linux_sockaddr *dst, struct linux_sockaddr *gw,
    struct linux_sockaddr *netmask)

{
    struct sockaddr_storage sa_gw, sa_dst, sa_nm;
    struct sockaddr *psa_gw, *psa_dst, *psa_nm;
    int rtreq, rtflag;
    int rc;
    struct rt_addrinfo info;
    struct rib_cmd_info rci;

    switch (req) {
        case FF_ROUTE_ADD:
            rtreq = RTM_ADD;
            break;
        case FF_ROUTE_DEL:
            rtreq = RTM_DELETE;
            break;
        case FF_ROUTE_CHANGE:
            rtreq = RTM_CHANGE;
            break;
        default:
            rc = EINVAL;
            goto kern_fail;
    }

    switch (flag) {
        case FF_RTF_HOST:
            rtflag = RTF_HOST;
            break;
        case FF_RTF_GATEWAY:
            rtflag = RTF_GATEWAY;
            break;
        default:
            rc = EINVAL;
            goto kern_fail;
    };

    bzero((caddr_t)&info, sizeof(info));
    info.rti_flags = rtflag;

    if (gw != NULL) {
        psa_gw = (struct sockaddr *)&sa_gw;
        linux2freebsd_sockaddr(gw, sizeof(*gw), psa_gw);
        info.rti_info[RTAX_GATEWAY] = psa_gw;
    } else {
        psa_gw = NULL;
    }

    if (dst != NULL) {
        psa_dst = (struct sockaddr *)&sa_dst;
        linux2freebsd_sockaddr(dst, sizeof(*dst), psa_dst);
        info.rti_info[RTAX_DST] = psa_dst;
    } else {
        psa_dst = NULL;
    }

    if (netmask != NULL) {
        psa_nm = (struct sockaddr *)&sa_nm;
        linux2freebsd_sockaddr(netmask, sizeof(*netmask), psa_nm);
        info.rti_info[RTAX_NETMASK] = psa_nm;
    } else {
        psa_nm = NULL;
    }

    rc = rib_action(RT_DEFAULT_FIB, rtreq, &info, &rci);

    if (rc != 0)
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}
