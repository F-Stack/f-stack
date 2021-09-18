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
 * Derived in part from libuinet's uinet_host_interface.c.
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>

#include <openssl/rand.h>
#include <rte_malloc.h>

#include "ff_host_interface.h"
#include "ff_errno.h"

static struct timespec current_ts;
extern void* ff_mem_get_page();
extern int ff_mem_free_addr(void* p);

void *
ff_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset)
{
    //return rte_malloc("", len, 4096);
    int host_prot;
    int host_flags;

#ifdef FF_USE_PAGE_ARRAY
        if( len == 4096 ){
            return ff_mem_get_page();
        }
        else
#endif
        {

    assert(ff_PROT_NONE == PROT_NONE);
    host_prot = 0;
    if ((prot & ff_PROT_READ) == ff_PROT_READ)   host_prot |= PROT_READ;
    if ((prot & ff_PROT_WRITE) == ff_PROT_WRITE) host_prot |= PROT_WRITE;

    host_flags = 0;
    if ((flags & ff_MAP_SHARED) == ff_MAP_SHARED)   host_flags |= MAP_SHARED;
    if ((flags & ff_MAP_PRIVATE) == ff_MAP_PRIVATE) host_flags |= MAP_PRIVATE;
    if ((flags & ff_MAP_ANON) == ff_MAP_ANON)       host_flags |= MAP_ANON;

    void *ret = (mmap(addr, len, host_prot, host_flags, fd, offset));

    if ((uint64_t)ret == -1) {
        printf("fst mmap failed:%s\n", strerror(errno));
        exit(1);
    }
    return ret;
    }
}

int
ff_munmap(void *addr, uint64_t len)
{
#ifdef FF_USE_PAGE_ARRAY
        if ( len == 4096 ){
            return ff_mem_free_addr(addr);
        }
#endif
    //rte_free(addr);
    //return 0;
    return (munmap(addr, len));
}


void *
ff_malloc(uint64_t size)
{
    //return rte_malloc("", size, 0);
    return (malloc(size));
}


void *
ff_calloc(uint64_t number, uint64_t size)
{
    //return rte_calloc("", number, size, 0);
    return (calloc(number, size));
}


void *
ff_realloc(void *p, uint64_t size)
{
    if (size) {
        //return rte_realloc(p, size, 0);
        return (realloc(p, size));
    }

    return (p);
}


void
ff_free(void *p)
{
    //rte_free(p);
    free(p);
}

void panic(const char *, ...) __attribute__((__noreturn__));

const char *panicstr = NULL;

void
panic(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    abort();
}

void
ff_clock_gettime(int id, int64_t *sec, long *nsec)
{
    struct timespec ts;
    int host_id;
    int rv;

    switch (id) {
    case ff_CLOCK_REALTIME:
        host_id = CLOCK_REALTIME;
        break;
#ifdef CLOCK_MONOTONIC_FAST
    case ff_CLOCK_MONOTONIC_FAST:
        host_id = CLOCK_MONOTONIC_FAST;
        break;
#endif
    case ff_CLOCK_MONOTONIC:
    default:
        host_id = CLOCK_MONOTONIC;
        break;
    }

    rv = clock_gettime(host_id, &ts);
    assert(0 == rv);

    *sec = (int64_t)ts.tv_sec;
    *nsec = (long)ts.tv_nsec;
}

uint64_t
ff_clock_gettime_ns(int id)
{
    int64_t sec;
    long nsec;

    ff_clock_gettime(id, &sec, &nsec);

    return ((uint64_t)sec * ff_NSEC_PER_SEC + nsec);
}

void
ff_get_current_time(time_t *sec, long *nsec)
{
    if (sec) {
        *sec = current_ts.tv_sec;
    }

    if (nsec) {
        *nsec = current_ts.tv_nsec;
    }
}

void
ff_update_current_ts()
{
    int rv = clock_gettime(CLOCK_REALTIME, &current_ts);
    assert(rv == 0);
}

void
ff_arc4rand(void *ptr, unsigned int len, int reseed)
{
    (void)reseed;

    RAND_bytes(ptr, len);
}

uint32_t
ff_arc4random(void)
{
    uint32_t ret;
    ff_arc4rand(&ret, sizeof ret, 0);
    return ret;
}

int ff_setenv(const char *name, const char *value)
{
    return setenv(name, value, 1);
}

char *ff_getenv(const char *name)
{
    return getenv(name);
}

void ff_os_errno(int error)
{
    switch (error) {
        case ff_EPERM:       errno = EPERM; break;
        case ff_ENOENT:      errno = ENOENT; break;
        case ff_ESRCH:       errno = ESRCH; break;
        case ff_EINTR:       errno = EINTR; break;
        case ff_EIO:         errno = EIO; break;
        case ff_ENXIO:       errno = ENXIO; break;
        case ff_E2BIG:       errno = E2BIG; break;
        case ff_ENOEXEC:     errno = ENOEXEC; break;
        case ff_EBADF:       errno = EBADF; break;
        case ff_ECHILD:      errno = ECHILD; break;
        case ff_EDEADLK:     errno = EDEADLK; break;
        case ff_ENOMEM:      errno = ENOMEM; break;
        case ff_EACCES:      errno = EACCES; break;
        case ff_EFAULT:      errno = EFAULT; break;
        case ff_ENOTBLK:     errno = ENOTBLK; break;
        case ff_EBUSY:       errno = EBUSY; break;
        case ff_EEXIST:      errno = EEXIST; break;
        case ff_EXDEV:       errno = EXDEV; break;
        case ff_ENODEV:      errno = ENODEV; break;
        case ff_ENOTDIR:     errno = ENOTDIR; break;
        case ff_EISDIR:      errno = EISDIR; break;
        case ff_EINVAL:      errno = EINVAL; break;
        case ff_ENFILE:      errno = ENFILE; break;
        case ff_EMFILE:      errno = EMFILE; break;
        case ff_ENOTTY:      errno = ENOTTY; break;
        case ff_ETXTBSY:     errno = ETXTBSY; break;
        case ff_EFBIG:       errno = EFBIG; break;
        case ff_ENOSPC:      errno = ENOSPC; break;
        case ff_ESPIPE:      errno = ESPIPE; break;
        case ff_EROFS:       errno = EROFS; break;
        case ff_EMLINK:      errno = EMLINK; break;
        case ff_EPIPE:       errno = EPIPE; break;
        case ff_EDOM:        errno = EDOM; break;
        case ff_ERANGE:      errno = ERANGE; break;
    
        /* case ff_EAGAIN:       same as EWOULDBLOCK */
        case ff_EWOULDBLOCK:     errno = EWOULDBLOCK; break;
    
        case ff_EINPROGRESS:     errno = EINPROGRESS; break;
        case ff_EALREADY:        errno = EALREADY; break;
        case ff_ENOTSOCK:        errno = ENOTSOCK; break;
        case ff_EDESTADDRREQ:    errno = EDESTADDRREQ; break;
        case ff_EMSGSIZE:        errno = EMSGSIZE; break;
        case ff_EPROTOTYPE:      errno = EPROTOTYPE; break;
        case ff_ENOPROTOOPT:     errno = ENOPROTOOPT; break;
        case ff_EPROTONOSUPPORT: errno = EPROTONOSUPPORT; break;
        case ff_ESOCKTNOSUPPORT: errno = ESOCKTNOSUPPORT; break;

        /* case ff_EOPNOTSUPP:   same as ENOTSUP */
        case ff_ENOTSUP:         errno = ENOTSUP; break;

        case ff_EPFNOSUPPORT:    errno = EPFNOSUPPORT; break;
        case ff_EAFNOSUPPORT:    errno = EAFNOSUPPORT; break;
        case ff_EADDRINUSE:      errno = EADDRINUSE; break;
        case ff_EADDRNOTAVAIL:   errno = EADDRNOTAVAIL; break;
        case ff_ENETDOWN:        errno = ENETDOWN; break;
        case ff_ENETUNREACH:     errno = ENETUNREACH; break;
        case ff_ENETRESET:       errno = ENETRESET; break;
        case ff_ECONNABORTED:    errno = ECONNABORTED; break;
        case ff_ECONNRESET:      errno = ECONNRESET; break;
        case ff_ENOBUFS:         errno = ENOBUFS; break;
        case ff_EISCONN:         errno = EISCONN; break;
        case ff_ENOTCONN:        errno = ENOTCONN; break;
        case ff_ESHUTDOWN:       errno = ESHUTDOWN; break;
        case ff_ETOOMANYREFS:    errno = ETOOMANYREFS; break;
        case ff_ETIMEDOUT:       errno = ETIMEDOUT; break;
        case ff_ECONNREFUSED:    errno = ECONNREFUSED; break;
        case ff_ELOOP:           errno = ELOOP; break;
        case ff_ENAMETOOLONG:    errno = ENAMETOOLONG; break;
        case ff_EHOSTDOWN:       errno = EHOSTDOWN; break;
        case ff_EHOSTUNREACH:    errno = EHOSTUNREACH; break;
        case ff_ENOTEMPTY:       errno = ENOTEMPTY; break;
        case ff_EUSERS:      errno = EUSERS; break;
        case ff_EDQUOT:      errno = EDQUOT; break;
        case ff_ESTALE:      errno = ESTALE; break;
        case ff_EREMOTE:     errno = EREMOTE; break;
        case ff_ENOLCK:      errno = ENOLCK; break;
        case ff_ENOSYS:      errno = ENOSYS; break;
        case ff_EIDRM:       errno = EIDRM; break;
        case ff_ENOMSG:      errno = ENOMSG; break;
        case ff_EOVERFLOW:   errno = EOVERFLOW; break;
        case ff_ECANCELED:   errno = ECANCELED; break;
        case ff_EILSEQ:      errno = EILSEQ; break;
        case ff_EBADMSG:     errno = EBADMSG; break;
        case ff_EMULTIHOP:   errno = EMULTIHOP; break;
        case ff_ENOLINK:     errno = ENOLINK; break;
        case ff_EPROTO:      errno = EPROTO; break;
        default:              errno = error; break;
    }

}

