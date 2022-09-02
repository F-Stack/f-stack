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
 *
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>

#include "ff_ipc.h"

static int
ipfw_ctl(int cmd, int level, int optname, void *optval, socklen_t *optlen)
{
    struct ff_msg *msg, *retmsg = NULL;
    int len;

    switch (cmd) {
	case FF_IPFW_GET:
            if (optval == NULL || optlen == NULL) {
                return EINVAL;
            }
            break;
        case FF_IPFW_SET:
            break;
        default:
            return EINVAL;
    }

    msg = ff_ipc_msg_alloc();
    if (msg == NULL) {
        errno = ENOMEM;
        return -1;
    }

    len = sizeof(struct ff_ipfw_args) + *optlen + sizeof(socklen_t);
    if (len > msg->buf_len) {
        errno = EINVAL;
        ff_ipc_msg_free(msg);
        return -1;
    }

    msg->msg_type = FF_IPFW_CTL;
    msg->ipfw.cmd = cmd;
    msg->ipfw.level = level;
    msg->ipfw.optname = optname;
    msg->ipfw.optval = (void *)msg->buf_addr;
    msg->ipfw.optlen = (socklen_t *)(msg->buf_addr + (*optlen));

    memcpy(msg->ipfw.optval, optval, *optlen);
    memcpy(msg->ipfw.optlen, optlen, sizeof(socklen_t));

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

    if (retmsg->result != 0) {
        ret = -1;
        errno = retmsg->result;
    } else {
        ret = 0;

        if (cmd == FF_IPFW_GET) {
            memcpy(optval, retmsg->ipfw.optval, *(retmsg->ipfw.optlen));
            memcpy(optlen, retmsg->ipfw.optlen, sizeof(socklen_t));
        }
    }

    ff_ipc_msg_free(msg);

    return ret;
}

int
ff_socket(int domain, int type, int protocol)
{
    return 0;
}

int ff_getsockopt(int sockfd, int level, int optname,
    void *optval, socklen_t *optlen)
{
    return ipfw_ctl(FF_IPFW_GET, level, optname, optval, optlen);
}

int ff_setsockopt(int sockfd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    return ipfw_ctl(FF_IPFW_SET, level, optname, (void *)optval, &optlen);
}

