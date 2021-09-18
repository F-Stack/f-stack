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

#ifndef _FSTACK_SYS_RWLOCK_H_
#define _FSTACK_SYS_RWLOCK_H_
#include_next <sys/rwlock.h>

#undef rw_init
#undef rw_init_flags
#undef rw_destroy
#undef rw_wowned
#undef _rw_wlock
#undef _rw_try_wlock
#undef _rw_wunlock
#undef _rw_rlock
#undef _rw_try_rlock
#undef _rw_runlock
#undef _rw_try_upgrade
#undef _rw_downgrade

#define DO_NOTHING do {} while(0)

void ff_rw_init_flags(struct lock_object *lo, const char *name, int opts);

#define rw_init(rw, n)          \
    rw_init_flags((rw), (n), 0)
#define rw_init_flags(rw, n, o) \
    ff_rw_init_flags(&(rw)->lock_object, (n), (o))
#define rw_destroy(rw) DO_NOTHING
#define rw_wowned(rw) 1
#define _rw_wlock(rw, f, l)    DO_NOTHING
#define _rw_try_wlock(rw, f, l) 1
#define _rw_wunlock(rw, f, l) DO_NOTHING
#define _rw_rlock(rw, f, l)    DO_NOTHING
#define _rw_try_rlock(rw, f, l) 1
#define _rw_runlock(rw, f, l) DO_NOTHING
#define _rw_try_upgrade(rw, f, l) 1
#define _rw_downgrade(rw, f, l) DO_NOTHING

#endif    /* _FSTACK_SYS_RWLOCK_H_ */
