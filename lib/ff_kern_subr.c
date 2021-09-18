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
 * Derived in part from libplebnet's pn_kern_subr.c.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include "ff_host_interface.h"

static __inline int
hash_mflags(int flags)
{
    return ((flags & HASH_NOWAIT) ? M_NOWAIT : M_WAITOK);
}

/*
 * General routine to allocate a hash table with control of memory flags.
 */
void *
hashinit_flags(int elements, struct malloc_type *type, u_long *hashmask,
    int flags)
{
    long hashsize;
    LIST_HEAD(generic, generic) *hashtbl;
    int i;

    if (elements <= 0)
        panic("hashinit: bad elements");

    /* Exactly one of HASH_WAITOK and HASH_NOWAIT must be set. */
    KASSERT((flags & HASH_WAITOK) ^ (flags & HASH_NOWAIT),
        ("Bad flags (0x%x) passed to hashinit_flags", flags));

    for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
        continue;
    hashsize >>= 1;

    hashtbl = malloc((u_long)hashsize * sizeof(*hashtbl), type,
        hash_mflags(flags));

    if (hashtbl != NULL) {
        for (i = 0; i < hashsize; i++)
            LIST_INIT(&hashtbl[i]);
        *hashmask = hashsize - 1;
    }
    return (hashtbl);
}

/*
 * Allocate and initialize a hash table with default flag: may sleep.
 */
void *
hashinit(int elements, struct malloc_type *type, u_long *hashmask)
{
    return (hashinit_flags(elements, type, hashmask, HASH_WAITOK));
}

void
hashdestroy(void *vhashtbl, struct malloc_type *type, u_long hashmask)
{
    LIST_HEAD(generic, generic) *hashtbl, *hp;

    hashtbl = vhashtbl;
    for (hp = hashtbl; hp <= &hashtbl[hashmask]; hp++)
        KASSERT(LIST_EMPTY(hp), ("%s: hashtbl %p not empty "
            "(malloc type %s)", __func__, hashtbl, type->ks_shortdesc));
    free(hashtbl, type);
}

static const int primes[] = { 1, 13, 31, 61, 127, 251, 509, 761, 1021, 1531,
            2039, 2557, 3067, 3583, 4093, 4603, 5119, 5623, 6143,
            6653, 7159, 7673, 8191, 12281, 16381, 24571, 32749 };
#define NPRIMES nitems(primes)

/*
 * General routine to allocate a prime number sized hash table with control of
 * memory flags.
 */
void *
phashinit_flags(int elements, struct malloc_type *type, u_long *nentries, int flags)
{
    long hashsize, i;
    LIST_HEAD(generic, generic) *hashtbl;

    KASSERT(elements > 0, ("%s: bad elements", __func__));
    /* Exactly one of HASH_WAITOK and HASH_NOWAIT must be set. */
    KASSERT((flags & HASH_WAITOK) ^ (flags & HASH_NOWAIT),
        ("Bad flags (0x%x) passed to phashinit_flags", flags));

    for (i = 1, hashsize = primes[1]; hashsize <= elements;) {
        i++;
        if (i == NPRIMES)
            break;
        hashsize = primes[i];
    }
    hashsize = primes[i - 1];

    hashtbl = malloc((u_long)hashsize * sizeof(*hashtbl), type,
        hash_mflags(flags));
    if (hashtbl == NULL)
        return (NULL);

    for (i = 0; i < hashsize; i++)
        LIST_INIT(&hashtbl[i]);
    *nentries = hashsize;
    return (hashtbl);
}

/*
 * Allocate and initialize a prime number sized hash table with default flag:
 * may sleep.
 */
void *
phashinit(int elements, struct malloc_type *type, u_long *nentries)
{

    return (phashinit_flags(elements, type, nentries, HASH_WAITOK));
}

static void
uio_yield(void)
{

}

int
uiomove(void *cp, int n, struct uio *uio)
{
    struct thread *td = curthread;
    struct iovec *iov;
    u_int cnt;
    int error = 0;
    int save = 0;

    KASSERT(uio->uio_rw == UIO_READ || uio->uio_rw == UIO_WRITE,
        ("uiomove: mode"));
    KASSERT(uio->uio_segflg != UIO_USERSPACE || uio->uio_td == curthread,
        ("uiomove proc"));
    WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
        "Calling uiomove()");

    save = td->td_pflags & TDP_DEADLKTREAT;
    td->td_pflags |= TDP_DEADLKTREAT;

    while (n > 0 && uio->uio_resid) {
        iov = uio->uio_iov;
        cnt = iov->iov_len;
        if (cnt == 0) {
            uio->uio_iov++;
            uio->uio_iovcnt--;
            continue;
        }
        if (cnt > n)
            cnt = n;

        switch (uio->uio_segflg) {

        case UIO_USERSPACE:
            if (ticks - PCPU_GET(switchticks) >= hogticks)
                uio_yield();
            if (uio->uio_rw == UIO_READ)
                error = copyout(cp, iov->iov_base, cnt);
            else
                error = copyin(iov->iov_base, cp, cnt);
            if (error)
                goto out;
            break;

        case UIO_SYSSPACE:
            if (uio->uio_rw == UIO_READ)
                bcopy(cp, iov->iov_base, cnt);
            else
                bcopy(iov->iov_base, cp, cnt);
            break;
        case UIO_NOCOPY:
            break;
        }
        iov->iov_base = (char *)iov->iov_base + cnt;
        iov->iov_len -= cnt;
        uio->uio_resid -= cnt;
        uio->uio_offset += cnt;
        cp = (char *)cp + cnt;
        n -= cnt;
    }
out:
    if (save == 0)
        td->td_pflags &= ~TDP_DEADLKTREAT;
    return (error);
}

int
copyinuio(const struct iovec *iovp, u_int iovcnt, struct uio **uiop)
{
    struct iovec *iov;
    struct uio *uio;
    u_int iovlen;
    int error, i;

    *uiop = NULL;
    if (iovcnt > UIO_MAXIOV)
        return (EINVAL);
    iovlen = iovcnt * sizeof (struct iovec);
    uio = malloc(iovlen + sizeof *uio, M_IOV, M_WAITOK);
    if (uio == NULL) {
        return (ENOMEM);
    }
    iov = (struct iovec *)(uio + 1);
    error = copyin(iovp, iov, iovlen);
    if (error) {
        free(uio, M_IOV);
        return (error);
    }
    uio->uio_iov = iov;
    uio->uio_iovcnt = iovcnt;
    uio->uio_segflg = UIO_USERSPACE;
    uio->uio_offset = -1;
    uio->uio_resid = 0;
    for (i = 0; i < iovcnt; i++) {
        if (iov->iov_len > INT_MAX - uio->uio_resid) {
            free(uio, M_IOV);
            return (EINVAL);
        }
        uio->uio_resid += iov->iov_len;
        iov++;
    }
    *uiop = uio;
    return (0);
}

int
copyout_nofault(const void *kaddr, void *udaddr, size_t len)
{
    return copyout(kaddr, udaddr, len);
}

