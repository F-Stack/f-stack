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
#include <errno.h>
#include <sys/socket.h>

#include "rtioctl.h"
#include "ff_ipc.h"

int rt_shutdown_rd = 0;
int rt_sofib = 0;

int
rt_socket(int domain, int type, int protocol)
{
    if (domain != PF_ROUTE || type != SOCK_RAW) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int
rt_shutdown(int fd, int how)
{
    if (how == SHUT_RD) {
        rt_shutdown_rd = 1;
    }
    return 0;
}

int
rt_setsockopt(int sockfd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    if (level == SOL_SOCKET && optname == SO_SETFIB) {
        rt_sofib = *(int *)optval;
    }
    return 0;
}

void
rt_close(int fd)
{
    return;
}

int
rtioctl(char *data, unsigned len, unsigned read_len)
{
    struct ff_msg *msg, *retmsg = NULL;
    unsigned maxlen;

    msg = ff_ipc_msg_alloc();
    if (msg == NULL) {
        errno = ENOMEM;
        return -1;
    }

    if (len > msg->buf_len) {
        errno = EINVAL;
        ff_ipc_msg_free(msg);
        return -1;
    }

    if (read_len > msg->buf_len) {
        read_len = msg->buf_len;
    }

    maxlen = read_len ? read_len : len;

    msg->msg_type = FF_ROUTE;
    msg->route.fib = rt_sofib;
    msg->route.len = len;
    msg->route.maxlen = maxlen;
    msg->route.data = msg->buf_addr;
    memcpy(msg->route.data, data, len);
    msg->buf_addr += len;

    int ret = ff_ipc_send(msg);
    if (ret < 0) {
        errno = EPIPE;
        ff_ipc_msg_free(msg);
        return -1;
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
        ret = retmsg->route.len;

        if (!rt_shutdown_rd && read_len > 0) {
            memcpy(data, retmsg->route.data, retmsg->route.len);
        }
    } else {
        ret = -1;
        errno = retmsg->result;
    }

    ff_ipc_msg_free(msg);

    return ret;
}

