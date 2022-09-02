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
#include <sys/sysproto.h>
#include <string.h>

#include "ff_api.h"
#include "ff_ipc.h"
#include "netgraph.h"

static int
ngctl(int cmd, void *data, size_t len)
{
    struct ff_msg *msg, *retmsg = NULL;

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

    msg->msg_type = FF_NGCTL;
    msg->ngctl.cmd = cmd;
    msg->ngctl.data = msg->buf_addr;

    switch (cmd) {
        case NGCTL_SOCKET:
        case NGCTL_CLOSE:
            memcpy(msg->ngctl.data, data, len);
            break;
        case NGCTL_BIND:
        case NGCTL_CONNECT:
        {
            struct bind_args *src = (struct bind_args *)data;
            struct bind_args *dst = (struct bind_args *)(msg->ngctl.data);
            dst->s = src->s;
            dst->name = (char *)msg->buf_addr + sizeof(struct bind_args);
            dst->namelen = src->namelen;
            memcpy(dst->name, src->name, src->namelen);
            break;
        }
        case NGCTL_SEND:
        {
            struct sendto_args *src = (struct sendto_args *)data;
            struct sendto_args *dst = (struct sendto_args *)(msg->ngctl.data);
            dst->s = src->s;
            dst->buf = (char *)msg->buf_addr + sizeof(struct sendto_args);
            dst->len = src->len;
            dst->flags = src->flags;
            dst->to = dst->buf + src->len;
            dst->tolen = src->tolen;
            memcpy(dst->buf, src->buf, src->len);
            memcpy(dst->to, src->to, src->tolen);
            break;
        }
        case NGCTL_RECV:
        {
            struct recvfrom_args *src = (struct recvfrom_args *)data;
            struct recvfrom_args *dst = (struct recvfrom_args *)(msg->ngctl.data);
            dst->s = src->s;
            dst->buf = msg->buf_addr + sizeof(struct recvfrom_args);
            dst->len = src->len;
            dst->flags = src->flags;
            dst->from = (struct sockaddr *)dst->buf + src->len;
            dst->fromlenaddr = (socklen_t *)dst->buf + src->len + *(src->fromlenaddr);
            memcpy(dst->buf, src->buf, src->len);
            memcpy(dst->from, src->from, *(src->fromlenaddr));
            memcpy(dst->fromlenaddr, src->fromlenaddr, sizeof(socklen_t));
            break;
        }
        default:
            errno = EINVAL;
            ff_ipc_msg_free(msg);
            return -1;
    }

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
        ret = msg->ngctl.ret;

        if (cmd == NGCTL_RECV) {
            struct recvfrom_args *dst = (struct recvfrom_args *)data;
            struct recvfrom_args *src = (struct recvfrom_args *)(msg->ngctl.data);
            memcpy(dst->buf, src->buf, src->len);
            memcpy(dst->from, src->from, *(src->fromlenaddr));
            memcpy(dst->fromlenaddr, src->fromlenaddr, sizeof(socklen_t));
        }
    }

    ff_ipc_msg_free(msg);

    return ret;
}

int
ng_socket(int domain, int type, int protocol)
{
    struct socket_args sa;
    sa.domain = domain;
    sa.type = type;
    sa.protocol = protocol;

    return ngctl(NGCTL_SOCKET, (void *)&sa, sizeof(sa));
}

int
ng_bind(int sockfd, const struct sockaddr *addr,
    socklen_t addrlen)
{
    size_t len;
    struct bind_args ba;

    ba.s = sockfd;
    ba.name = (char *)addr;
    ba.namelen = addrlen;

    len = sizeof(ba) + addrlen;

    return ngctl(NGCTL_BIND, (void *)&ba, len);
}

int
ng_connect(int sockfd, const struct sockaddr *addr,
    socklen_t addrlen)
{
    size_t len;
    struct connect_args ca;

    ca.s = sockfd;
    ca.name = (char *)addr;
    ca.namelen = addrlen;

    len = sizeof(ca) + addrlen;

    return ngctl(NGCTL_CONNECT, (void *)&ca, len);
}

ssize_t
ng_sendto(int sockfd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen)
{
    size_t datalen;

    struct sendto_args sa;
    sa.s = sockfd;
    sa.buf = (void *)buf;
    sa.len = len;
    sa.flags = flags;
    sa.to = (char *)dest_addr;
    sa.tolen = addrlen;

    datalen = sizeof(sa) + len + addrlen;
    return ngctl(NGCTL_SEND, (void *)&sa, datalen);
}

ssize_t
ng_recvfrom(int sockfd, void *buf, size_t len, int flags,
    struct sockaddr *src_addr, socklen_t *addrlen)
{
    size_t datalen;

    struct recvfrom_args ra;
    ra.s = sockfd;
    ra.buf = buf;
    ra.len = len;
    ra.flags = flags;
    ra.from = src_addr;
    ra.fromlenaddr = addrlen;

    datalen = sizeof(ra) + len + (*addrlen) + sizeof(socklen_t);
    return ngctl(NGCTL_RECV, (void *)&ra, datalen);
}

int
ng_close(int fd)
{
    struct close_args ca;
    ca.fd = fd;

    return ngctl(NGCTL_CLOSE, (void *)&ca, sizeof(ca));
}

