/*
 * Copyright (c) 1998 Michael Smith. All rights reserved.
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
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
#include <sys/limits.h>

#include "ff_host_interface.h"

static MALLOC_DEFINE(M_KENV, "kenv", "kernel environment");

#define KENV_SIZE    512    /* Maximum number of environment strings */

/* pointer to the config-generated static environment */
char *kern_envp;

/* pointer to the md-static environment */
char *md_envp;

/* dynamic environment variables */
char **kenvp = &kern_envp; /* points to a pointer to NULL */
struct mtx kenv_lock;  /* does not need initialization - it will not be used as dynamic_kenv == 0 */

/*
 * No need to protect this with a mutex since SYSINITS are single threaded.
 */
bool dynamic_kenv = 0;

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

/*
 * Internal functions for string lookup.
 */
static char *
_getenv_dynamic_locked(const char *name, int *idx)
{
	char *cp;
	int len, i;

	len = strlen(name);
	for (cp = kenvp[0], i = 0; cp != NULL; cp = kenvp[++i]) {
		if ((strncmp(cp, name, len) == 0) &&
		    (cp[len] == '=')) {
			if (idx != NULL)
				*idx = i;
			return (cp + len + 1);
		}
	}
	return (NULL);
}

static char *
_getenv_dynamic(const char *name, int *idx)
{

	mtx_assert(&kenv_lock, MA_OWNED);
	return (_getenv_dynamic_locked(name, idx));
}

/*
 * Find the next entry after the one which (cp) falls within, return a
 * pointer to its start or NULL if there are no more.
 */
static char *
kernenv_next(char *cp)
{

	if (cp != NULL) {
		while (*cp != 0)
			cp++;
		cp++;
		if (*cp == 0)
			cp = NULL;
	}
	return (cp);
}

static char *
_getenv_static_from(char *chkenv, const char *name)
{
	char *cp, *ep;
	int len;

	for (cp = chkenv; cp != NULL; cp = kernenv_next(cp)) {
		for (ep = cp; (*ep != '=') && (*ep != 0); ep++)
			;
		if (*ep != '=')
			continue;
		len = ep - cp;
		ep++;
		if (!strncmp(name, cp, len) && name[len] == 0)
			return (ep);
	}
	return (NULL);
}

static char *
_getenv_static(const char *name)
{
	char *val;

	val = _getenv_static_from(md_envp, name);
	if (val != NULL)
		return (val);
	val = _getenv_static_from(kern_envp, name);
	if (val != NULL)
		return (val);
	return (NULL);
}

/*
 * Return the internal kenv buffer for the variable name, if it exists.
 * If the dynamic kenv is initialized and the name is present, return
 * with kenv_lock held.
 */
static char *
kenv_acquire(const char *name)
{
	char *value;

	if (dynamic_kenv) {
		mtx_lock(&kenv_lock);
		value = _getenv_dynamic(name, NULL);
		if (value == NULL)
			mtx_unlock(&kenv_lock);
		return (value);
	} else
		return (_getenv_static(name));
}

/*
 * Undo a previous kenv_acquire() operation
 */
static void
kenv_release(const char *buf)
{
	if ((buf != NULL) && dynamic_kenv)
		mtx_unlock(&kenv_lock);
}

/*
 * Return an array of integers at the given type size and signedness.
 */
int
getenv_array(const char *name, void *pdata, int size, int *psize,
    int type_size, bool allow_signed)
{
    uint8_t shift;
    int64_t value;
    int64_t old;
    const char *buf;
    char *end;
    const char *ptr;
    int n;
    int rc;

    rc = 0;              /* assume failure */

    buf = kenv_acquire(name);
    if (buf == NULL)
        goto error;

    /* get maximum number of elements */
    size /= type_size;

    n = 0;

    for (ptr = buf; *ptr != 0; ) {
        value = strtoq(ptr, &end, 0);

        /* check if signed numbers are allowed */
        if (value < 0 && !allow_signed)
            goto error;

        /* check for invalid value */
        if (ptr == end)
            goto error;
        
        /* check for valid suffix */
        switch (*end) {
        case 't':
        case 'T':
            shift = 40;
            end++;
            break;
        case 'g':
        case 'G':
            shift = 30;
            end++;
            break;
        case 'm':
        case 'M':
            shift = 20;
            end++;
            break;
        case 'k':
        case 'K':
            shift = 10;
            end++;
            break;
        case ' ':
        case '\t':
        case ',':
        case 0:
            shift = 0;
            break;
        default:
            /* garbage after numeric value */
            goto error;
        }

        /* skip till next value, if any */
        while (*end == '\t' || *end == ',' || *end == ' ')
            end++;

        /* update pointer */
        ptr = end;

        /* apply shift */
        old = value;
        value <<= shift;

        /* overflow check */
        if ((value >> shift) != old)
            goto error;

        /* check for buffer overflow */
        if (n >= size)
            goto error;

        /* store value according to type size */
        switch (type_size) {
        case 1:
            if (allow_signed) {
                if (value < SCHAR_MIN || value > SCHAR_MAX)
                    goto error;
            } else {
                if (value < 0 || value > UCHAR_MAX)
                    goto error;
            }
            ((uint8_t *)pdata)[n] = (uint8_t)value;
            break;
        case 2:
            if (allow_signed) {
                if (value < SHRT_MIN || value > SHRT_MAX)
                    goto error;
            } else {
                if (value < 0 || value > USHRT_MAX)
                    goto error;
            }
            ((uint16_t *)pdata)[n] = (uint16_t)value;
            break;
        case 4:
            if (allow_signed) {
                if (value < INT_MIN || value > INT_MAX)
                    goto error;
            } else {
                if (value > UINT_MAX)
                    goto error;
            }
            ((uint32_t *)pdata)[n] = (uint32_t)value;
            break;
        case 8:
            ((uint64_t *)pdata)[n] = (uint64_t)value;
            break;
        default:
            goto error;
        }
        n++;
    }
    *psize = n * type_size;

    if (n != 0)
        rc = 1;    /* success */
error:
    kenv_release(buf);
    return (rc);
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

