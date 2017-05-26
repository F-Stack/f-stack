/*
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
 */

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <unistd.h>

#include "ff_ipc.h"

static int inited;

static struct rte_mempool *message_pool;

static int
ff_ipc_init(void)
{
    if (inited) {
        return 0;
    }

    char *dpdk_argv[] = {
        "-c1", "-n4",
        "--proc-type=secondary",
        "--log-level=3",
    };

    int ret = rte_eal_init(sizeof(dpdk_argv)/sizeof(dpdk_argv[0]), dpdk_argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    message_pool = rte_mempool_lookup(FF_MSG_POOL);
    if (message_pool == NULL) {
        rte_exit(EXIT_FAILURE, "lookup message pool:%s failed!\n", FF_MSG_POOL);
    }

    inited = 1;

    return 0;
}

struct ff_msg *
ff_ipc_msg_alloc(void)
{
    if (inited == 0) {
        int ret = ff_ipc_init();
        if (ret < 0) {
            return NULL;
        }
    }

    void *msg;
    if (rte_mempool_get(message_pool, &msg) < 0) {
        printf("get buffer from message pool failed.\n");
        return NULL;
    }

    return (struct ff_msg *)msg;
}

int
ff_ipc_msg_free(struct ff_msg *msg)
{
    if (inited == 0) {
        printf("ff ipc not inited\n");
        return -1;
    }

    rte_mempool_put(message_pool, msg);

    return 0;
}

int
ff_ipc_send(const struct ff_msg *msg, uint16_t proc_id)
{
    int ret;

    if (inited == 0) {
        printf("ff ipc not inited\n");
        return -1;
    }

    char name[RTE_RING_NAMESIZE];
    snprintf(name, RTE_RING_NAMESIZE, "%s%u",
        FF_MSG_RING_IN, proc_id);
    struct rte_ring *ring = rte_ring_lookup(name);
    if (ring == NULL) {
        printf("lookup message ring:%s failed!\n", name);
        return -1;
    }

    ret = rte_ring_enqueue(ring, (void *)msg);
    if (ret < 0) {
        printf("ff_ipc_send failed\n");
        return ret;
    }

    return 0;
}

int
ff_ipc_recv(struct ff_msg **msg, uint16_t proc_id)
{
    int ret, i;
    if (inited == 0) {
        printf("ff ipc not inited\n");
        return -1;
    }

    char name[RTE_RING_NAMESIZE];
    snprintf(name, RTE_RING_NAMESIZE, "%s%u",
        FF_MSG_RING_OUT, proc_id);
    struct rte_ring *ring = rte_ring_lookup(name);
    if (ring == NULL) {
        printf("lookup message ring:%s failed!\n", name);
        return -1;
    }

    void *obj;
    #define MAX_ATTEMPTS_NUM 1000
    for (i = 0; i < MAX_ATTEMPTS_NUM; i++) {
        ret = rte_ring_dequeue(ring, &obj);
        if (ret == 0) {
            *msg = (struct ff_msg *)obj;
            break;
        }

        usleep(1000);
    }

    return ret;
}

int
sysctl_ipc(uint16_t proc_id, int *name, unsigned namelen, void *old,
    size_t *oldlenp, const void *new, size_t newlen)
{
    struct ff_msg *msg, *retmsg = NULL;

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
    if (oldlenp) {
        oldlen = *oldlenp;
    }

    if (namelen + oldlen + newlen > msg->buf_len) {
        errno = EINVAL;
        ff_ipc_msg_free(msg);
        return -1;
    }

    char *buf_addr = msg->buf_addr;

    msg->msg_type = FF_SYSCTL;
    msg->sysctl.name = (int *)buf_addr;
    msg->sysctl.namelen = namelen;
    memcpy(msg->sysctl.name, name, namelen*sizeof(int));

    buf_addr += namelen*sizeof(int);

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

    int ret = ff_ipc_send(msg, proc_id);
    if (ret < 0) {
        errno = EPIPE;
        ff_ipc_msg_free(msg);
        return -1;
    }

    do {
        if (retmsg != NULL) {
            ff_ipc_msg_free(retmsg);
        }
        ret = ff_ipc_recv(&retmsg, proc_id);
        if (ret < 0) {
            errno = EPIPE;
            ff_ipc_msg_free(msg);
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

    ff_ipc_msg_free(msg);

    return ret;
}
