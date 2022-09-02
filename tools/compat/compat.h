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

#ifndef _FF_COMPAT_H
#define _FF_COMPAT_H

#include <stddef.h>

#ifndef __dead2
#define __dead2 __attribute__((__noreturn__))
#endif

#ifndef __dead
#define __dead __dead2
#endif

#ifndef nitems
#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
#endif

#ifndef rounddown
#define	rounddown(x, y)	(((x)/(y))*(y))
#endif

#ifndef rounddown2
#define	rounddown2(x, y) ((x)&(~((y)-1)))          /* if y is power of two */
#endif

#ifndef roundup
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))  /* to any y */
#endif

#ifndef roundup2
#define	roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

#ifndef powerof2
#define powerof2(x)	((((x)-1)&(x))==0)
#endif

#ifndef __FBSDID
#define __FBSDID(s) /* nothing */
#endif

#ifndef _PATH_ETC
#define _PATH_ETC "/etc"
#endif

#ifndef __PAST_END
/*
 * Access a variable length array that has been declared as a fixed
 * length array.
 */
#define __PAST_END(array, offset) (((__typeof__(*(array)) *)(array))[offset])
#endif

#ifndef ishexnumber
#define ishexnumber(x) isxdigit(x)
#endif

#define CLOCK_REALTIME_FAST     10      /* FreeBSD-specific. */
#ifdef INET6
#define CLOCK_MONOTONIC_FAST    12      /* FreeBSD-specific. */

#define AF_INET6_LINUX    10
#define PF_INET6_LINUX    AF_INET6
#endif

void *reallocf(void *ptr, size_t size);

int feature_present(const char *feature);

size_t strlcat(char *dst, const char *src, size_t siz);

size_t strlcpy(char * __restrict dst, const char * __restrict src,
	size_t siz);

long long strtonum(const char *numstr, long long minval,
	long long maxval, const char **errstrp);

const char *getprogname(void);

extern int optreset;

int	 fnmatch(const char *, const char *, int);

#endif
