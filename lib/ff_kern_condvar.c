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
 * Derived in part from libplebnet's pn_kern_condvar.c.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/condvar.h>
#include <sys/sched.h>
#include <sys/signalvar.h>
#include <sys/sleepqueue.h>
#include <sys/resourcevar.h>

void
cv_init(struct cv *cvp, const char *desc)
{
    cvp->cv_description = desc;
}

void
cv_destroy(struct cv *cvp)
{

}

void
_cv_wait(struct cv *cvp, struct lock_object *lock)
{

}

void
_cv_wait_unlock(struct cv *cvp, struct lock_object *lock)
{

}

int
_cv_wait_sig(struct cv *cvp, struct lock_object *lock)
{
    return (0);
}

int
_cv_timedwait(struct cv *cvp, struct lock_object *lock, int timo)
{
    return (0);
}

int
_cv_timedwait_sig(struct cv *cvp, struct lock_object *lock, int timo)
{
    return (0);
}

int
_cv_timedwait_sig_sbt(struct cv *cvp, struct lock_object *lock,
    sbintime_t sbt, sbintime_t pr, int flags)
{
    return (0);
}

void
cv_signal(struct cv *cvp)
{

}

void
cv_broadcastpri(struct cv *cvp, int pri)
{

}
