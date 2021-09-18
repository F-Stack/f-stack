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
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_socket.h>

#include "ff_api.h"
#include "ff_host_interface.h"

static int
ngctl_socket(struct socket_args *uap)
{
    int error = sys_socket(curthread, uap);
    if (error) {
	ff_os_errno(error);
        return -1;
    }
    return curthread->td_retval[0];
}

static int
ngctl_connect(struct connect_args *uap)
{
    int error = sys_connect(curthread, uap);
    if (error) {
        ff_os_errno(error);
        return (-1);
    }

    return (error);
}

static int
ngctl_bind(struct bind_args *uap)
{
    int error = sys_bind(curthread, uap);
    if (error) {
        ff_os_errno(error);
        return (-1);
    }
    
    return (error);
}

static int
ngctl_recvfrom(struct recvfrom_args *uap)
{
    int error = sys_recvfrom(curthread, uap);
    if (error) {
        ff_os_errno(error);
        return (-1);
    }
    return curthread->td_retval[0];
}

static int
ngctl_sendto(struct sendto_args *uap)
{
    int error = sys_sendto(curthread, uap);
    if (error) {
        ff_os_errno(error);
        return (-1);
    }
    return curthread->td_retval[0];
}

static int
ngctl_close(int sockfd)
{
    int error = kern_close(curthread, sockfd);
    if (error) {
        ff_os_errno(error);
        return (-1);
    }
    return (error);
}

int
ff_ngctl(int cmd, void *data)
{
    switch(cmd) {
        case NGCTL_SOCKET:
            return ngctl_socket((struct socket_args *)data);
        case NGCTL_CONNECT:
            return ngctl_connect((struct connect_args *)data);
        case NGCTL_BIND:
            return ngctl_bind((struct bind_args *)data);
        case NGCTL_SEND:
            return ngctl_sendto((struct sendto_args *)data);
        case NGCTL_RECV:
            return ngctl_recvfrom((struct recvfrom_args *)data);
        case NGCTL_CLOSE:
            return ngctl_close(*(int *)data);
        default:
            break;
    }

    ff_os_errno(EINVAL);
    return (-1);
}

