/*-
 * Copyright (c) 2002 Mike Barcroft <mike@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _COMPAT_SYS__TYPES_H_
#define _COMPAT_SYS__TYPES_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <stdint.h>

/*
 * Standard type definitions.
 */
typedef	__int64_t	__blkcnt_t;	/* file block count */
typedef	__int32_t	__clockid_t;	/* clock_gettime()... */
typedef	__uint32_t	__fflags_t;	/* file flags */
typedef	__uint64_t	__fsblkcnt_t;
typedef	__uint64_t	__fsfilcnt_t;
typedef	__uint32_t	__gid_t;
typedef	__int32_t	__lwpid_t;	/* Thread ID (a.k.a. LWP) */
typedef	int		__accmode_t;	/* access permissions */
typedef	int		__nl_item;
typedef	__int64_t	__off_t;	/* file offset */
typedef	__int64_t	__off64_t;	/* file offset (alias) */
typedef	__int32_t	__pid_t;	/* process [group] */
typedef	__uint8_t	__sa_family_t;
typedef	__uint32_t	__socklen_t;
typedef	long		__suseconds_t;	/* microseconds (signed) */
typedef	struct __mq	*__mqd_t;	/* mq_open()... */
typedef	__uint32_t	__uid_t;
typedef	unsigned int	__useconds_t;	/* microseconds (unsigned) */
typedef	int		__cpuwhich_t;	/* which parameter for cpuset. */
typedef	int		__cpulevel_t;	/* level parameter for cpuset. */
typedef int		__cpusetid_t;	/* cpuset identifier. */

/*
 * Unusual type definitions.
 */
/*
 * rune_t is declared to be an ``int'' instead of the more natural
 * ``unsigned long'' or ``long''.  Two things are happening here.  It is not
 * unsigned so that EOF (-1) can be naturally assigned to it and used.  Also,
 * it looks like 10646 will be a 31 bit standard.  This means that if your
 * ints cannot hold 32 bits, you will be in trouble.  The reason an int was
 * chosen over a long is that the is*() and to*() routines take ints (says
 * ANSI C), but they use __ct_rune_t instead of int.
 *
 * NOTE: rune_t is not covered by ANSI nor other standards, and should not
 * be instantiated outside of lib/libc/locale.  Use wchar_t.  wint_t and
 * rune_t must be the same type.  Also, wint_t should be able to hold all
 * members of the largest character set plus one extra value (WEOF), and
 * must be at least 16 bits.
 */
typedef	int		__ct_rune_t;	/* arg type for ctype funcs */
typedef	__ct_rune_t	__rune_t;	/* rune_t (see above) */
typedef	__ct_rune_t	__wint_t;	/* wint_t (see above) */

typedef	__uint32_t	__fixpt_t;	/* fixed point number */

typedef	__int64_t	sbintime_t;

typedef	__uint64_t	__vm_offset_t;
typedef	__int64_t	__vm_ooffset_t;
typedef	__uint64_t	__vm_paddr_t;
typedef	__uint64_t	__vm_pindex_t;
typedef	__uint64_t	__vm_size_t;

typedef	__vm_offset_t	vm_offset_t;
typedef	__vm_ooffset_t	vm_ooffset_t;
typedef	__vm_paddr_t	vm_paddr_t;
typedef	__vm_pindex_t	vm_pindex_t;
typedef	__vm_size_t	vm_size_t;

typedef	__cpuwhich_t	cpuwhich_t;
typedef	__cpulevel_t	cpulevel_t;
typedef	__cpusetid_t	cpusetid_t;

#ifndef _UID_T_DECLARED
typedef	__uid_t		uid_t;		/* user id */
#define	_UID_T_DECLARED
#endif

typedef	__int64_t	__segsz_t;		/* segment size (in pages) */
typedef	__segsz_t	segsz_t;	/* segment size (in pages) */

typedef	__uint32_t	__fixpt_t;	/* fixed point number */
typedef	__fixpt_t	fixpt_t;	/* fixed point number */

typedef	__int32_t	__lwpid_t;	/* Thread ID (a.k.a. LWP) */
#ifndef _LWPID_T_DECLARED
typedef	__lwpid_t	lwpid_t;	/* Thread ID (a.k.a. LWP) */
#define	_LWPID_T_DECLARED
#endif

typedef	__uint64_t	kpaddr_t;
typedef	__uint64_t	kvaddr_t;
typedef	__uint64_t	ksize_t;
typedef	__int64_t	kssize_t;

#endif /* !_COMPAT_SYS__TYPES_H_ */
