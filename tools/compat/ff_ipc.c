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

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ff_ipc.h"
#include "ff_reload.h"

static int inited;

static struct rte_mempool *message_pool;

uint16_t ff_proc_id = 0;

/* C-NR-313: with graceful_reload=1 the msg rings are indexed by
 * (proc_id, generation) and named with a "_g<gen>" suffix, so a tool has to
 * name the generation it wants to talk to. AUTO resolves it on the first
 * send, LEGACY selects the unsuffixed names a graceful_reload=0 stack
 * creates. */
#define FF_IPC_GEN_AUTO         (-1)
#define FF_IPC_GEN_LEGACY       (-2)

/* graceful_reload=1 keeps a resident slim primary on proc_id 0; it serves
 * both generations' in-rings and never leaves, so it is the one process a
 * tool can always reach without knowing the current generation. */
#define FF_IPC_PRIMARY_PROC_ID  0
#define FF_IPC_GEN_PROBE_ATTEMPTS   200

static int ff_gen_arg = FF_IPC_GEN_AUTO;
static int ff_ring_gen = FF_IPC_GEN_AUTO;

/* F5: the reply this process is waiting for; see ff_ipc_recv. */
static const struct ff_msg *ff_pending_msg;

void
ff_set_proc_id(int pid)
{
    if (pid < 0 || pid > 65535) {
        printf("Invalid F-Stack proccess id\n");
        exit(1);
    }
    ff_proc_id = pid;
}

void
ff_set_gen(int gen)
{
    if (gen < 0 || gen >= FF_RELOAD_GEN_MAX) {
        printf("Invalid F-Stack reload generation, expect 0..%d\n",
            FF_RELOAD_GEN_MAX - 1);
        exit(1);
    }
    ff_gen_arg = gen;
    ff_ring_gen = FF_IPC_GEN_AUTO;
}

int
ff_set_proc_id_str(const char *arg)
{
    char *end;
    long id, gen;

    if (arg == NULL) {
        printf("Invalid F-Stack proccess id\n");
        exit(1);
    }

    id = strtol(arg, &end, 10);
    if (end == arg || (*end != '\0' && *end != ':')) {
        printf("Invalid F-Stack proccess id:%s\n", arg);
        exit(1);
    }
    ff_set_proc_id((int)id);

    if (*end == ':') {
        const char *genarg = end + 1;

        gen = strtol(genarg, &end, 10);
        if (end == genarg || *end != '\0') {
            printf("Invalid F-Stack reload generation:%s\n", arg);
            exit(1);
        }
        ff_set_gen((int)gen);
    }

    return (int)id;
}

int
ff_ipc_init(void)
{
    if (inited) {
        return 0;
    }

    if (getuid() != 0) {
        rte_exit(EXIT_FAILURE, "Error: F-Stack tools must be run as root.\n");
    }

    char *dpdk_argv[] = {
        "ff-ipc", "-c1", "-n4",
        "--proc-type=secondary",
        /* RTE_LOG_WARNING */
        "--log-level=5",
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

void
ff_ipc_exit(void)
{
	rte_eal_cleanup();
	return;
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

    if (msg->original_buf) {
        rte_free(msg->buf_addr);
        msg->buf_addr = msg->original_buf;
        msg->buf_len = msg->original_buf_len;
        msg->original_buf = NULL;
    }

    rte_mempool_put(message_pool, msg);

    return 0;
}

/* Mirror of ff_reload_msg_ring_name() (contract in lib/ff_reload.h): the
 * tools cannot link lib/ff_reload.c, it pulls in ff_global_cfg and the rest
 * of the stack, so the two implementations must stay byte-compatible. */
static int
ff_msg_ring_name(char *buf, unsigned int buflen, const char *base,
    unsigned int proc_id, int msg_type, int gen, int graceful)
{
    int n;

    if (buf == NULL || buflen == 0 || base == NULL)
        return -1;

    if (!graceful) {
        if (msg_type < 0)
            n = snprintf(buf, buflen, "%s%u", base, proc_id);
        else
            n = snprintf(buf, buflen, "%s%u_%d", base, proc_id, msg_type);
    } else {
        if (gen < 0)
            gen = 0;
        if (gen >= FF_RELOAD_GEN_MAX)
            gen = FF_RELOAD_GEN_MAX - 1;
        if (msg_type < 0)
            n = snprintf(buf, buflen, "%s%u_g%d", base, proc_id, gen);
        else
            n = snprintf(buf, buflen, "%s%u_%d_g%d", base, proc_id,
                msg_type, gen);
    }

    if (n < 0 || (unsigned int)n >= buflen)
        return -1;
    return 0;
}

/* The shared reload block is an anonymous mapping the nginx master hands to
 * its children through fork(), so a tool cannot read active_gen from it.
 * The resident slim primary answers FF_RELOAD with its reload view, which
 * carries the active generation, so one round trip on its (proc 0, gen 0)
 * ring pair resolves the default target.
 * FF_RELOAD_CMD_QUERY is the read-only probe command: handle_reload_msg()
 * rejects anything else with ENOTSUP, so this never looks like a READY or
 * a handover acknowledgement to the reload machinery. */
static int
ff_ipc_probe_active_gen(void)
{
    char in_name[RTE_RING_NAMESIZE], out_name[RTE_RING_NAMESIZE];
    struct rte_ring *in_ring, *out_ring;
    struct ff_msg *msg;
    void *obj;
    int i, gen = 0;

    if (ff_msg_ring_name(in_name, RTE_RING_NAMESIZE, FF_MSG_RING_IN,
            FF_IPC_PRIMARY_PROC_ID, -1, 0, 1) != 0 ||
        ff_msg_ring_name(out_name, RTE_RING_NAMESIZE, FF_MSG_RING_OUT,
            FF_IPC_PRIMARY_PROC_ID, FF_RELOAD, 0, 1) != 0) {
        return 0;
    }

    in_ring = rte_ring_lookup(in_name);
    out_ring = rte_ring_lookup(out_name);
    if (in_ring == NULL || out_ring == NULL) {
        return 0;
    }

    msg = ff_ipc_msg_alloc();
    if (msg == NULL) {
        return 0;
    }

    msg->msg_type = FF_RELOAD;
    msg->result = 0;
    memset(&msg->reload, 0, sizeof(msg->reload));
    msg->reload.cmd = FF_RELOAD_CMD_QUERY;

    if (rte_ring_enqueue(in_ring, msg) < 0) {
        ff_ipc_msg_free(msg);
        return 0;
    }

    for (i = 0; i < FF_IPC_GEN_PROBE_ATTEMPTS; i++) {
        if (rte_ring_dequeue(out_ring, &obj) == 0) {
            struct ff_msg *reply = (struct ff_msg *)obj;

            if (reply != msg) {
                ff_ipc_msg_free(reply);
                continue;
            }
            if (reply->result == 0 &&
                reply->reload.active_gen < FF_RELOAD_GEN_MAX) {
                gen = (int)reply->reload.active_gen;
            }
            ff_ipc_msg_free(reply);
            return gen;
        }

        usleep(1000);
    }

    fprintf(stderr, "ff ipc: proc %d did not answer, assuming generation 0, "
        "use -g <gen> to select one explicitly\n", FF_IPC_PRIMARY_PROC_ID);

    return 0;
}

static int
ff_ipc_ring_gen(void)
{
    char name[RTE_RING_NAMESIZE];

    if (ff_ring_gen != FF_IPC_GEN_AUTO) {
        return ff_ring_gen;
    }

    if (ff_gen_arg != FF_IPC_GEN_AUTO) {
        ff_ring_gen = ff_gen_arg;
        return ff_ring_gen;
    }

    /* No generation asked for: an unsuffixed ring means the stack runs
     * graceful_reload=0, where the names stay exactly as they were. proc 0
     * always has one, so the mode is detected without depending on which
     * proc this tool targets. */
    if (ff_msg_ring_name(name, RTE_RING_NAMESIZE, FF_MSG_RING_IN,
            FF_IPC_PRIMARY_PROC_ID, -1, 0, 0) == 0 &&
        rte_ring_lookup(name) != NULL) {
        ff_ring_gen = FF_IPC_GEN_LEGACY;
        return ff_ring_gen;
    }

    ff_ring_gen = ff_ipc_probe_active_gen();

    return ff_ring_gen;
}

static int
ff_ipc_ring_name(char *buf, unsigned int buflen, const char *base,
    int msg_type)
{
    int gen = ff_ipc_ring_gen();
    int graceful = gen != FF_IPC_GEN_LEGACY;

    return ff_msg_ring_name(buf, buflen, base, ff_proc_id, msg_type,
        graceful ? gen : 0, graceful);
}

int
ff_ipc_send(const struct ff_msg *msg)
{
    int ret;

    if (inited == 0) {
        printf("ff ipc not inited\n");
        return -1;
    }

    char name[RTE_RING_NAMESIZE];
    if (ff_ipc_ring_name(name, RTE_RING_NAMESIZE, FF_MSG_RING_IN, -1) != 0) {
        printf("message ring name too long\n");
        return -1;
    }
    struct rte_ring *ring = rte_ring_lookup(name);
    if (ring == NULL) {
        printf("lookup message ring:%s failed!\n", name);
        return -1;
    }

    ff_pending_msg = msg;

    ret = rte_ring_enqueue(ring, (void *)msg);
    if (ret < 0) {
        ff_pending_msg = NULL;
        printf("ff_ipc_send failed\n");
        return ret;
    }

    return 0;
}

int
ff_ipc_recv(struct ff_msg **msg, enum FF_MSG_TYPE msg_type)
{
    int ret, i;
    if (inited == 0) {
        printf("ff ipc not inited\n");
        return -1;
    }

    char name[RTE_RING_NAMESIZE];
    if (ff_ipc_ring_name(name, RTE_RING_NAMESIZE, FF_MSG_RING_OUT,
            (int)msg_type) != 0) {
        printf("message ring name too long\n");
        return -1;
    }
    struct rte_ring *ring = rte_ring_lookup(name);
    if (ring == NULL) {
        printf("lookup message ring:%s failed!\n", name);
        return -1;
    }

    void *obj;
    unsigned stale = 0;
    #define MAX_ATTEMPTS_NUM 1000
    for (i = 0; i < MAX_ATTEMPTS_NUM; i++) {
        ret = rte_ring_dequeue(ring, &obj);
        if (ret == 0) {
            /* F5: an out ring outlives the process generation that answers
             * on it, so a reply whose query already gave up can still be
             * queued here (and would be read as this query's result). Only
             * the buffer we sent is ours; anything else is orphaned and is
             * returned to the message pool. */
            if (ff_pending_msg != NULL &&
                obj != (const void *)ff_pending_msg) {
                if (stale++ == 0) {
                    fprintf(stderr, "ff ipc: dropping stale reply on %s\n",
                        name);
                }
                ff_ipc_msg_free((struct ff_msg *)obj);
                continue;
            }
            *msg = (struct ff_msg *)obj;
            ff_pending_msg = NULL;
            break;
        }

        usleep(1000);
    }

    return ret;
}
