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
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "ff_ipc.h"

/*
 * In general, we always call like this: ioctl(fd, com, data),
 * but if there is a pointer in the data and the pointer points to
 * a memory area, for example, data is struct ifreq, and it uses
 * ifreq.ifr_ifru.ifru_data, we must copy the memory to msg->buf_addr,
 * after this, it can be used to communicate with F-Stack process.
 * Otherwise, an unknown error will occur.
 *
 * Two cases:
 * 1.Normal, there is no need to copy memory: ioctl_va(fd, com, data, 0).
 * 2.There is a memory need to be copied: ioctl_va(fd, com, data, 3, offset, cpy_mem, clen).
 *     offset: the offset of cpy_mem relative to data struct.
 *     cpy_mem: the memory address that need to be copied.
 *     clen: the size of memory that the cpy_mem pointed to.
 *
 */
int
ioctl_va(int fd, unsigned long com, void *data, int argc, ...)
{
    struct ff_msg *msg, *retmsg = NULL;
    unsigned size;
    void *cpy_mem;
    size_t offset, clen;
    int af = AF_INET;

    if (argc != 0 && argc != 3 && argc != 1) {
        errno = EINVAL;
        return -1;
    }

    if (argc == 3) {
        va_list ap;
        va_start(ap, argc);
        offset = va_arg(ap, size_t);
        cpy_mem = va_arg(ap, void *);
        clen = va_arg(ap, size_t);
        va_end(ap);
    } else if (argc == 1) {
        va_list ap;
        va_start(ap, argc);
        af = va_arg(ap, int);
        va_end(ap);
    }

    if (com > 0xffffffff) {
        printf("WARNING: ioctl sign-extension ioctl %lx\n", com);
        com &= 0xffffffff;
    }

    size = IOCPARM_LEN(com);
    if ((size > IOCPARM_MAX) ||
        ((com & (IOC_IN | IOC_OUT)) == 0) ||
        (size == 0) ||
        (com & IOC_VOID))
        return (ENOTTY);

    msg = ff_ipc_msg_alloc();
    if (msg == NULL) {
        errno = ENOMEM;
        return -1;
    }

    if (size > msg->buf_len) {
        errno = ENOMEM;
        ff_ipc_msg_free(msg);
        return -1;
    }

#ifdef INET6
    if (af == AF_INET6) {
        msg->msg_type = FF_IOCTL6;
    } else
#endif
    if (af == AF_INET)
        msg->msg_type = FF_IOCTL;
    else {
        errno = EINVAL;
        ff_ipc_msg_free(msg);
        return -1;
    }

    msg->ioctl.cmd = com;
    msg->ioctl.data = msg->buf_addr;
    memcpy(msg->ioctl.data, data, size);
    char *buf_addr = msg->buf_addr + size;

    if (argc == 3) {
        if (size + clen > msg->buf_len) {
            errno = ENOMEM;
            ff_ipc_msg_free(msg);
            return -1;
        }
        char *ptr = (char *)(msg->ioctl.data) + offset;
        memcpy(ptr, &buf_addr, sizeof(char *));
        memcpy(buf_addr, cpy_mem, clen);
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

    if (retmsg->result == 0) {
        ret = 0;

        if (com & IOC_OUT) {
            memcpy(data, retmsg->ioctl.data, size);
            if (argc == 3) {
                memcpy(cpy_mem, buf_addr, clen);
                char *ptr = (char *)data + offset;
                memcpy(ptr, &cpy_mem, sizeof(void *));
            }
        }
    } else {
        ret = -1;
        errno = retmsg->result;
    }

    ff_ipc_msg_free(msg);

    return ret;
}

