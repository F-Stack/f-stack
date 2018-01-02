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

#ifndef _FSTACK_EVENT_H
#define _FSTACK_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _KERNEL

#include <stdint.h>
#include <sys/queue.h> 

#define EVFILT_READ        (-1)
#define EVFILT_WRITE       (-2)
#define EVFILT_AIO         (-3)    /* attached to aio requests */
#define EVFILT_VNODE       (-4)    /* attached to vnodes */
#define EVFILT_PROC        (-5)    /* attached to struct proc */
#define EVFILT_SIGNAL      (-6)    /* attached to struct proc */
#define EVFILT_TIMER       (-7)    /* timers */
/* EVFILT_NETDEV        (-8)          no longer supported */
#define EVFILT_FS          (-9)    /* filesystem events */
#define EVFILT_LIO         (-10)    /* attached to lio requests */
#define EVFILT_USER        (-11)    /* User events */
#define EVFILT_SYSCOUNT    11

#define EV_SET(kevp_, a, b, c, d, e, f) do {    \
    struct kevent *kevp = (kevp_);        \
    (kevp)->ident = (a);            \
    (kevp)->filter = (b);            \
    (kevp)->flags = (c);            \
    (kevp)->fflags = (d);            \
    (kevp)->data = (e);            \
    (kevp)->udata = (f);            \
} while(0)

struct kevent {
    uintptr_t ident;     /* identifier for this event */
    short filter;        /* filter for event */
    u_short flags;
    u_int fflags;
    intptr_t data;
    void *udata;         /* opaque user data identifier */
};

/* actions */
#define EV_ADD        0x0001        /* add event to kq (implies enable) */
#define EV_DELETE     0x0002        /* delete event from kq */
#define EV_ENABLE     0x0004        /* enable event */
#define EV_DISABLE    0x0008        /* disable event (not reported) */

/* flags */
#define EV_ONESHOT    0x0010        /* only report one occurrence */
#define EV_CLEAR      0x0020        /* clear event state after reporting */
#define EV_RECEIPT    0x0040        /* force EV_ERROR on success, data=0 */
#define EV_DISPATCH   0x0080        /* disable event after reporting */

#define EV_SYSFLAGS   0xF000        /* reserved by system */
#define EV_DROP       0x1000        /* note should be dropped */
#define EV_FLAG1      0x2000        /* filter-specific flag */

/* returned values */
#define EV_EOF        0x8000        /* EOF detected */
#define EV_ERROR      0x4000        /* error, data contains errno */

 /*
  * data/hint flags/masks for EVFILT_USER, shared with userspace
  *
  * On input, the top two bits of fflags specifies how the lower twenty four
  * bits should be applied to the stored value of fflags.
  *
  * On output, the top two bits will always be set to NOTE_FFNOP and the
  * remaining twenty four bits will contain the stored fflags value.
  */
#define NOTE_FFNOP         0x00000000        /* ignore input fflags */
#define NOTE_FFAND         0x40000000        /* AND fflags */
#define NOTE_FFOR          0x80000000        /* OR fflags */
#define NOTE_FFCOPY        0xc0000000        /* copy fflags */
#define NOTE_FFCTRLMASK    0xc0000000        /* masks for operations */
#define NOTE_FFLAGSMASK    0x00ffffff

#define NOTE_TRIGGER       0x01000000        /* Cause the event to be
                           triggered for output. */

/*
 * data/hint flags for EVFILT_{READ|WRITE}, shared with userspace
 */
#define NOTE_LOWAT        0x0001            /* low water mark */

/*
 * data/hint flags for EVFILT_VNODE, shared with userspace
 */
#define NOTE_DELETE    0x0001            /* vnode was removed */
#define NOTE_WRITE     0x0002            /* data contents changed */
#define NOTE_EXTEND    0x0004            /* size increased */
#define NOTE_ATTRIB    0x0008            /* attributes changed */
#define NOTE_LINK      0x0010            /* link count changed */
#define NOTE_RENAME    0x0020            /* vnode was renamed */
#define NOTE_REVOKE    0x0040            /* vnode access was revoked */

/*
 * data/hint flags for EVFILT_PROC, shared with userspace
 */
#define NOTE_EXIT         0x80000000        /* process exited */
#define NOTE_FORK         0x40000000        /* process forked */
#define NOTE_EXEC         0x20000000        /* process exec'd */
#define NOTE_PCTRLMASK    0xf0000000        /* mask for hint bits */
#define NOTE_PDATAMASK    0x000fffff        /* mask for pid */

/* additional flags for EVFILT_PROC */
#define NOTE_TRACK        0x00000001        /* follow across forks */
#define NOTE_TRACKERR     0x00000002        /* could not track child */
#define NOTE_CHILD        0x00000004        /* am a child process */

struct knote;
SLIST_HEAD(klist, knote);
struct kqueue;
TAILQ_HEAD(kqlist, kqueue);
struct knlist {
    struct klist kl_list;
    void (*kl_lock)(void *);    /* lock function */
    void (*kl_unlock)(void *);
    void (*kl_assert_locked)(void *);
    void (*kl_assert_unlocked)(void *);
    void *kl_lockarg;           /* argument passed to kl_lockf() */
};

#endif

#ifdef __cplusplus
}
#endif
#endif

