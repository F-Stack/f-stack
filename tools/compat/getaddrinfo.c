/*  $KAME: getaddrinfo.c,v 1.15 2000/07/09 04:37:24 itojun Exp $    */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>

#include "netinet/in.h"
#include "arpa/inet.h"
#include "sys/socket.h"
#include "netdb.h"

/* FIXME: to support IPv6 */
/* Just conver numeric hostname to int and not do anything else. */
int
getaddrinfo(const char *hostname, const char *servername,
    const struct addrinfo *hints, struct addrinfo **res)
{
    if (hostname == NULL)
        return EAI_NONAME;

    *res = NULL;
    struct addrinfo *ai;

    ai = malloc(sizeof(struct addrinfo) + sizeof(struct sockaddr));
    if (ai == NULL)
        return EAI_MEMORY;

    ai->ai_next = NULL;
    ai->ai_canonname = NULL;
    ai->ai_addr = (struct sockaddr *)(ai+1);

    struct sockaddr_in *si = (struct sockaddr_in *)ai->ai_addr;
    si->sin_len = ai->ai_addrlen = sizeof(struct sockaddr);
    si->sin_family = ai->ai_family = AF_INET;
    /* si->sin_port ? */

    if (hints != NULL) {
        si->sin_family = ai->ai_family = hints->ai_family;
        ai->ai_socktype = hints->ai_socktype;
    }

    if (inet_pton(AF_INET, hostname, &si->sin_addr.s_addr) != 1) {
        freeaddrinfo(ai);
        return EAI_NONAME;
    }

    *res = ai;

    return 0;
}

void
freeaddrinfo(struct addrinfo *ai)
{
    struct addrinfo *next;

    do {
        next = ai->ai_next;
        if (ai->ai_canonname)
            free(ai->ai_canonname);
        /* no need to free(ai->ai_addr) */
        free(ai);
        ai = next;
    } while (ai);
}

/* Entries EAI_ADDRFAMILY (1) and EAI_NODATA (7) are obsoleted, but left */
/* for backward compatibility with userland code prior to 2553bis-02 */
static const char *ai_errlist[] = {
    "Success",                  /* 0 */
    "Address family for hostname not supported",    /* 1 */
    "Temporary failure in name resolution",     /* EAI_AGAIN */
    "Invalid value for ai_flags",           /* EAI_BADFLAGS */
    "Non-recoverable failure in name resolution",   /* EAI_FAIL */
    "ai_family not supported",          /* EAI_FAMILY */
    "Memory allocation failure",            /* EAI_MEMORY */
    "No address associated with hostname",      /* 7 */
    "hostname nor servname provided, or not known", /* EAI_NONAME */
    "servname not supported for ai_socktype",   /* EAI_SERVICE */
    "ai_socktype not supported",            /* EAI_SOCKTYPE */
    "System error returned in errno",       /* EAI_SYSTEM */
    "Invalid value for hints",          /* EAI_BADHINTS */
    "Resolved protocol is unknown",         /* EAI_PROTOCOL */
    "Argument buffer overflow",          /* EAI_OVERFLOW */
};

const char *
gai_strerror(int ecode)
{
    if (ecode >= 0 && ecode < EAI_MAX)
        return ai_errlist[ecode];
    return "Unknown error";
}
