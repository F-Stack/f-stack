/*
 * Copyright (c) 1998 Michael Smith. All rights reserved.
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
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
 * Derived from libuinet's uinet_kern_environment.c.
 */
 
/*
 * This is an override of ken_environment.c so that get/set/put/unsetenv()
 * from libc will be used, and the extended kernel environment API will
 * still be available.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: release/9.1.0/sys/kern/kern_environment.c 225617 2011-09-16 13:58:51Z kmacy $");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/libkern.h>
#include <sys/kenv.h>

#include "ff_host_interface.h"

static MALLOC_DEFINE(M_KENV, "kenv", "kernel environment");

#define KENV_SIZE    512    /* Maximum number of environment strings */

/* pointer to the static environment */
char *kern_envp; /* NULL */

/* dynamic environment variables */
char **kenvp = &kern_envp; /* points to a pointer to NULL */
struct mtx kenv_lock;  /* does not need initialization - it will not be used as dynamic_kenv == 0 */

/*
 * No need to protect this with a mutex since SYSINITS are single threaded.
 */
int dynamic_kenv = 0;

char *
kern_getenv(const char *name)
{
    return ff_getenv(name);
}

int
kern_setenv(const char *name, const char *value)
{
    return ff_setenv(name, value);
}

void
freeenv(char *env)
{
    ;
}


/*
 * Test if an environment variable is defined.
 */
int
testenv(const char *name)
{
    return (kern_getenv(name) != NULL);
}



/*
 * Return a string value from an environment variable.
 */
int
getenv_string(const char *name, char *data, int size)
{
    char *tmp;

    tmp = kern_getenv(name);
    if (tmp != NULL) {
        strlcpy(data, tmp, size);
        freeenv(tmp);
        return (1);
    } else
        return (0);
}

/*
 * Return an integer value from an environment variable.
 */
int
getenv_int(const char *name, int *data)
{
    quad_t tmp;
    int rval;

    rval = getenv_quad(name, &tmp);
    if (rval)
        *data = (int) tmp;
    return (rval);
}

/*
 * Return an unsigned integer value from an environment variable.
 */
int
getenv_uint(const char *name, unsigned int *data)
{
    quad_t tmp;
    int rval;

    rval = getenv_quad(name, &tmp);
    if (rval)
        *data = (unsigned int) tmp;
    return (rval);
}

/*
 * Return a long value from an environment variable.
 */
int
getenv_long(const char *name, long *data)
{
    quad_t tmp;
    int rval;

    rval = getenv_quad(name, &tmp);
    if (rval)
        *data = (long) tmp;
    return (rval);
}

/*
 * Return an unsigned long value from an environment variable.
 */
int
getenv_ulong(const char *name, unsigned long *data)
{
    quad_t tmp;
    int rval;

    rval = getenv_quad(name, &tmp);
    if (rval)
        *data = (unsigned long) tmp;
    return (rval);
}

/*
 * Return a quad_t value from an environment variable.
 */
int
getenv_quad(const char *name, quad_t *data)
{
    char *value;
    char *vtp;
    quad_t iv;

    value = kern_getenv(name);
    if (value == NULL)
        return (0);
    iv = strtoq(value, &vtp, 0);
    if (vtp == value || (vtp[0] != '\0' && vtp[1] != '\0')) {
        freeenv(value);
        return (0);
    }
    switch (vtp[0]) {
    case 't': case 'T':
        iv *= 1024;
    case 'g': case 'G':
        iv *= 1024;
    case 'm': case 'M':
        iv *= 1024;
    case 'k': case 'K':
        iv *= 1024;
    case '\0':
        break;
    default:
        freeenv(value);
        return (0);
    }
    *data = iv;
    freeenv(value);
    return (1);
}


void
tunable_int_init(void *data)
{
    struct tunable_int *d = (struct tunable_int *)data;

    TUNABLE_INT_FETCH(d->path, d->var);
}

void
tunable_long_init(void *data)
{
    struct tunable_long *d = (struct tunable_long *)data;

    TUNABLE_LONG_FETCH(d->path, d->var);
}

void
tunable_ulong_init(void *data)
{
    struct tunable_ulong *d = (struct tunable_ulong *)data;

    TUNABLE_ULONG_FETCH(d->path, d->var);
}

void
tunable_quad_init(void *data)
{
    struct tunable_quad *d = (struct tunable_quad *)data;

    TUNABLE_QUAD_FETCH(d->path, d->var);
}

void
tunable_str_init(void *data)
{
    struct tunable_str *d = (struct tunable_str *)data;

    TUNABLE_STR_FETCH(d->path, d->var, d->size);
}

