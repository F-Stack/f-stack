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

#include <string.h>
#include <sys/socket.h>
#include <rte_malloc.h>

#include "ff_ipc.h"

int
sysctl(int *name, unsigned namelen, void *old,
    size_t *oldlenp, const void *new, size_t newlen)
{
    struct ff_msg *msg, *retmsg = NULL;
    char *extra_buf = NULL;
    size_t total_len;

    if (old != NULL && oldlenp == NULL) {
        errno = EINVAL;
        return -1;
    }

    msg = ff_ipc_msg_alloc();
    if (msg == NULL) {
        errno = ENOMEM;
        return -1;
    }

    size_t oldlen = 0;
    if (old && oldlenp) {
        oldlen = *oldlenp;
    }

    total_len = namelen * sizeof(int) + sizeof(size_t) + oldlen + newlen;
    if (total_len > msg->buf_len) {
        extra_buf = rte_malloc(NULL, total_len, 0);
        if (extra_buf == NULL) {
            errno = ENOMEM;
            ff_ipc_msg_free(msg);
            return -1;
        }
        msg->original_buf = msg->buf_addr;
        msg->original_buf_len = msg->buf_len;
        msg->buf_addr = extra_buf;
        msg->buf_len = total_len; 
    }

    char *buf_addr = msg->buf_addr;

    msg->msg_type = FF_SYSCTL;
    msg->sysctl.name = (int *)buf_addr;
    msg->sysctl.namelen = namelen;
    memcpy(msg->sysctl.name, name, namelen * sizeof(int));

    buf_addr += namelen * sizeof(int);

    if (new != NULL && newlen != 0) {
        msg->sysctl.new = buf_addr;
        msg->sysctl.newlen = newlen;
        memcpy(msg->sysctl.new, new, newlen);

        buf_addr += newlen;
    } else {
        msg->sysctl.new = NULL;
        msg->sysctl.newlen = 0;
    }

    if (oldlenp != NULL) {
        msg->sysctl.oldlenp = (size_t *)buf_addr;
        memcpy(msg->sysctl.oldlenp, oldlenp, sizeof(size_t));
        buf_addr += sizeof(size_t);

        if (old != NULL) {
            msg->sysctl.old = (void *)buf_addr;
            memcpy(msg->sysctl.old, old, *oldlenp);
            buf_addr += *oldlenp;
        } else {
            msg->sysctl.old = NULL;
        }
    } else {
        msg->sysctl.oldlenp = NULL;
        msg->sysctl.old = NULL;
    }

    int ret = ff_ipc_send(msg);
    if (ret < 0) {
        errno = EPIPE;
        goto error;
    }

    do {
        if (retmsg != NULL) {
            ff_ipc_msg_free(retmsg);
        }
        ret = ff_ipc_recv(&retmsg, msg->msg_type);
        if (ret < 0) {
            errno = EPIPE;
            return -1;
        }
    } while (msg != retmsg);

    if (retmsg->result == 0) {
        ret = 0;
        if (oldlenp && retmsg->sysctl.oldlenp) {
            *oldlenp = *retmsg->sysctl.oldlenp;
        }

        if (old && retmsg->sysctl.old && oldlenp) {
            memcpy(old, retmsg->sysctl.old, *oldlenp);
        }
    } else {
        ret = -1;
        errno = retmsg->result;
    }

error:
    ff_ipc_msg_free(msg);

    return ret;
}
