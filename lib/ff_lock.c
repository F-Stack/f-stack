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
 * Derived in part from libplebnet's pn_lock.c.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/rmlock.h>
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/turnstile.h>
#include <sys/vmmeter.h>
#include <sys/lock_profile.h>

#include "ff_host_interface.h"

struct mtx Giant;

static void
assert_mtx(const struct lock_object *lock, int what)
{

}

static void
lock_mtx(struct lock_object *lock, uintptr_t how)
{

}

static uintptr_t
unlock_mtx(struct lock_object *lock)
{
    return (0);
}

/*
 * Lock classes for sleep and spin mutexes.
 */
struct lock_class lock_class_mtx_sleep = {
    .lc_name = "sleep mutex",
    .lc_flags = LC_SLEEPLOCK | LC_RECURSABLE,
    .lc_assert = assert_mtx,
    .lc_lock = lock_mtx,
    .lc_unlock = unlock_mtx,
#ifdef DDB
    .lc_ddb_show = db_show_mtx,
#endif
#ifdef KDTRACE_HOOKS
    .lc_owner = owner_mtx,
#endif
};

void
ff_mtx_init(struct lock_object *lo, const char *name, const char *type, int opts)
{
    lock_init(lo, &lock_class_mtx_sleep, name, type, opts);
}

void
mtx_sysinit(void *arg)
{
    struct mtx_args *margs = arg;
    mtx_init((struct mtx *)margs->ma_mtx, margs->ma_desc, NULL, margs->ma_opts);
}

void _mtx_destroy(volatile uintptr_t *c)
{

}

static void
lock_rw(struct lock_object *lock, uintptr_t how)
{

}

static uintptr_t
unlock_rw(struct lock_object *lock)
{
    return (0);
}

#ifdef KDTRACE_HOOKS
static int
owner_rw(struct lock_object *lock, struct thread **owner)
{
    return 1;//??
}
#endif


static void
assert_rw(const struct lock_object *lock, int what)
{

}

struct lock_class lock_class_rw = {
    .lc_name = "rw",
    .lc_flags = LC_SLEEPLOCK | LC_RECURSABLE | LC_UPGRADABLE,
    .lc_assert = assert_rw,
#ifdef DDB
    .lc_ddb_show = db_show_rwlock,
#endif
    .lc_lock = lock_rw,
    .lc_unlock = unlock_rw,
#ifdef KDTRACE_HOOKS
    .lc_owner = owner_rw,
#endif
};

void
rw_sysinit(void *arg)
{
    struct rw_args *args = arg;
    rw_init((struct rwlock *)args->ra_rw, args->ra_desc);
}

#if 0
void
rw_sysinit_flags(void *arg)
{
    rw_sysinit(arg);
}
#endif

void
ff_rw_init_flags(struct lock_object *lo, const char *name, int opts)
{
    int flags;

    MPASS((opts & ~(RW_DUPOK | RW_NOPROFILE | RW_NOWITNESS | RW_QUIET |
        RW_RECURSE)) == 0);

    flags = LO_UPGRADABLE;
    if (opts & RW_DUPOK)
        flags |= LO_DUPOK;
    if (opts & RW_NOPROFILE)
        flags |= LO_NOPROFILE;
    if (!(opts & RW_NOWITNESS))
        flags |= LO_WITNESS;
    if (opts & RW_RECURSE)
        flags |= LO_RECURSABLE;
    if (opts & RW_QUIET)
        flags |= LO_QUIET;

    lock_init(lo, &lock_class_rw, name, NULL, flags);
}

void _rw_destroy(volatile uintptr_t *c)
{

}

static void
assert_rm(const struct lock_object *lock, int what)
{

}

struct lock_class lock_class_rm = {
    .lc_name = "rm",
    .lc_flags = LC_SLEEPLOCK | LC_RECURSABLE,
    .lc_assert = assert_rm,
#if 0
#ifdef DDB
    .lc_ddb_show = db_show_rwlock,
#endif
#endif
#ifdef KDTRACE_HOOKS
    .lc_owner = owner_rm,
#endif
};

void
rm_init(struct rmlock *rm, const char *name)
{
    rm_init_flags(rm, name, 0);
}

void
rm_init_flags(struct rmlock *rm, const char *name, int opts)
{
    int liflags = 0;
    if (!(opts & RM_NOWITNESS))
        liflags |= LO_WITNESS;
    if (opts & RM_RECURSE)
        liflags |= LO_RECURSABLE;

    lock_init(&rm->lock_object, &lock_class_rm, name, NULL, liflags);
}

void
rm_sysinit(void *arg)
{
    struct rm_args *args = arg;
    rm_init((struct rmlock *)args->ra_rm, args->ra_desc);
}

#if 0
void
rm_sysinit_flags(void *arg)
{
    rm_sysinit(arg);
}
#endif

void
rm_destroy(struct rmlock *rm)
{

}

void
_rm_wlock(struct rmlock *rm)
{

}

void
_rm_wunlock(struct rmlock *rm)
{

}

int
_rm_rlock(struct rmlock *rm, struct rm_priotracker *tracker, int trylock)
{
    return (1);
}

void
_rm_runlock(struct rmlock *rm,  struct rm_priotracker *tracker)
{

}

int
rm_wowned(const struct rmlock *rm)
{
    return (1);
}

struct lock_class lock_class_sx = {
    .lc_name = "sx",
    .lc_flags = LC_SLEEPLOCK | LC_SLEEPABLE | LC_RECURSABLE | LC_UPGRADABLE,
#ifdef DDB
    .lc_ddb_show = db_show_sx,
#endif
#ifdef KDTRACE_HOOKS
    .lc_owner = owner_sx,
#endif
};

void
sx_init_flags(struct sx *sx, const char *description, int opts)
{
    int flags;

    MPASS((opts & ~(SX_QUIET | SX_RECURSE | SX_NOWITNESS | SX_DUPOK |
        SX_NOPROFILE | SX_NEW)) == 0);

    flags = LO_SLEEPABLE | LO_UPGRADABLE;
    if (opts & SX_DUPOK)
        flags |= LO_DUPOK;
    if (opts & SX_NOPROFILE)
        flags |= LO_NOPROFILE;
    if (!(opts & SX_NOWITNESS))
        flags |= LO_WITNESS;
    if (opts & SX_RECURSE)
        flags |= LO_RECURSABLE;
    if (opts & SX_QUIET)
        flags |= LO_QUIET;
    if (opts & SX_NEW)
        flags |= LO_NEW;

    lock_init(&sx->lock_object, &lock_class_sx, description, NULL, flags);
    //sx->sx_lock = SX_LOCK_UNLOCKED;
    //sx->sx_recurse = 0;
}

void
sx_destroy(struct sx *sx)
{

}

int
_sx_xlock(struct sx *sx, int opts,
    const char *file, int line)
{
    return (0);
}

int
_sx_slock(struct sx *sx, int opts, const char *file, int line)
{
    return (0);
}

void
_sx_xunlock(struct sx *sx, const char *file, int line)
{

}

void
_sx_sunlock(struct sx *sx, const char *file, int line)
{

}

int
sx_try_slock_(struct sx *sx, const char *file, int line)
{
    return 1;
}

int
sx_try_xlock_(struct sx *sx, const char *file, int line)
{
    return 1;
}

int
sx_try_upgrade_(struct sx *sx, const char *file, int line)
{
    return 1;
}

void
sx_downgrade_(struct sx *sx, const char *file, int line)
{

}

void
sx_sysinit(void *arg)
{
    struct sx_args *args = arg;
    sx_init(args->sa_sx, args->sa_desc);
}

/*
 * XXX should never be used;
 */
struct lock_class lock_class_lockmgr;

static void
lock_spin(struct lock_object *lock, uintptr_t how)
{
    printf("%s: called!\n", __func__);
}

static uintptr_t
unlock_spin(struct lock_object *lock)
{
    printf("%s: called!\n", __func__);
    return (0);
}

/*
 * XXX should never be used;
 */
struct lock_class lock_class_mtx_spin = {
    .lc_name = "spin mutex",
    .lc_flags = LC_SPINLOCK | LC_RECURSABLE,
    .lc_assert = assert_mtx,
    .lc_lock = lock_spin,
    .lc_unlock = unlock_spin,
};

/*
 * These do not support read locks because it would be hard to make
 * the tracker work correctly with the current lock_class API as you
 * would need to have the tracker pointer available when calling
 * rm_rlock() in lock_rm().
 */
static void
lock_rm(struct lock_object *lock, uintptr_t how)
{

}

static uintptr_t
unlock_rm(struct lock_object *lock)
{
    return (1);
}

struct lock_class lock_class_rm_sleepable = {
    .lc_name = "sleepable rm",
    .lc_flags = LC_SLEEPLOCK | LC_SLEEPABLE | LC_RECURSABLE,
    .lc_assert = assert_rm,
#ifdef DDB
    .lc_ddb_show = db_show_rm,
#endif
    .lc_lock = lock_rm,
    .lc_unlock = unlock_rm,
#ifdef KDTRACE_HOOKS
    .lc_owner = owner_rm,
#endif
};

void
mutex_init(void)
{
    mtx_init(&Giant, "Giant", NULL, MTX_DEF | MTX_RECURSE);
    mtx_init(&proc0.p_mtx, "process lock", NULL, MTX_DEF | MTX_DUPOK);
}

