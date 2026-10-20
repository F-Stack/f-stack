/*
 * Copyright (c) 2010 Kip Macy All rights reserved.
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

#ifndef _FSTACK_MACHINE_PCPU_H_
#define _FSTACK_MACHINE_PCPU_H_

#include_next <machine/pcpu.h>

#undef __curthread
#undef get_pcpu
#undef PCPU_GET
#undef PCPU_ADD
#undef PCPU_INC
#undef PCPU_PTR
#undef PCPU_SET
#undef zpcpu_offset_cpu
#undef zpcpu_base_to_offset
#undef zpcpu_offset_to_base

extern __thread struct thread *pcurthread;
extern __thread struct pcpu *pcpup;

void panic(const char *fmt, ...) __attribute__((noreturn));

static __inline struct pcpu *
ff_pcpu_get(void)
{
	if (__builtin_expect(pcpup == NULL, 0))
		panic("F-Stack: NULL per-CPU context (pcpup==NULL); "
		      "curcpu/PCPU_* are unsupported in ff_pthread_create threads");
	return (pcpup);
}

#define	get_pcpu()              (ff_pcpu_get()->pc_ ## prvspace)

#define PCPU_GET(member)         (ff_pcpu_get()->pc_ ## member)
#define PCPU_ADD(member, val)    (ff_pcpu_get()->pc_ ## member += (val))
#define PCPU_INC(member)         PCPU_ADD(member, 1)
#define PCPU_PTR(member)         (&ff_pcpu_get()->pc_ ## member)
#define PCPU_SET(member, val)    (ff_pcpu_get()->pc_ ## member = (val))

static __inline struct thread *
__curthread_ff(void)
{
    return (pcurthread);
}

#ifndef __curthread
#define __curthread __curthread_ff
#endif

#ifndef curthread
#define curthread __curthread_ff()
#endif

#endif    /* _FSTACK_MACHINE_PCPU_H_ */
