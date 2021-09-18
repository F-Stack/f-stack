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
 * Derived in part from libplebnet's pn_kern_synch.c.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>

#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/signalvar.h>
#include <sys/sleepqueue.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#ifdef KTRACE
#include <sys/uio.h>
#include <sys/ktrace.h>
#endif

#include "ff_host_interface.h"

int hogticks;
static uint8_t pause_wchan[MAXCPU];

typedef struct sleep_entry {
    LIST_ENTRY(sleep_entry) list_entry;
    void *chan;
    const char *wmesg;
    struct cv cond;
    int waiters;
} *sleep_entry_t;

static void synch_setup(void *dummy);
SYSINIT(synch_setup, SI_SUB_INTR, SI_ORDER_FIRST, synch_setup,
    NULL);

static struct se_head *se_active;
static u_long se_hashmask;
static struct mtx synch_lock;
#define SE_HASH(chan) (((uintptr_t)chan) & se_hashmask)
LIST_HEAD(se_head, sleep_entry);

static void
synch_setup(void *arg)
{
    mtx_init(&synch_lock, "synch_lock", NULL, MTX_DEF);
    se_active = hashinit(64, M_TEMP, &se_hashmask);
}

int
_sleep(const void * _Nonnull chan, struct lock_object *lock, int priority,
    const char *wmesg, sbintime_t sbt, sbintime_t pr, int flags)
{
    //FIXME:we couldn't really sleep.
    return (EPERM);
}

//FIXME.
int
msleep_spin_sbt(const void * _Nonnull chan, struct mtx *mtx, const char *wmesg,
    sbintime_t sbt, sbintime_t pr, int flags)
{
    return (0);
}

int
pause_sbt(const char *wmesg, sbintime_t sbt, sbintime_t pr, int flags)
{
    return (_sleep(&pause_wchan[curcpu], NULL, 0, wmesg, sbt, pr, flags));
}

void
wakeup(const void *chan)
{

}


void
wakeup_one(const void *chan)
{

}

void
kern_yield(int prio)
{

}

void
wakeup_any(const void *ident)
{

}

