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
#include <signal.h>        /* P4: kill(pid, 0) proves a foreign owner is gone */
#include <errno.h>

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
/* M5: master epoch the resolved generation belongs to (ring-name slot). */
static uint32_t ff_ring_epoch;
/* F-M5-2: epoch given on the command line. FF_RELOAD_EPOCH_NONE means
 * "not given" and resolves to slot 0, i.e. the pre-M5 ring names. */
static uint32_t ff_epoch_arg = FF_RELOAD_EPOCH_NONE;

/* F5: the reply this process is waiting for; see ff_ipc_recv. */
static const struct ff_msg *ff_pending_msg;

/* ---- P4 (C01-5): reply ownership ---------------------------------------
 *
 * The out-ring is shared by every process of one coordinate, so a reader
 * can dequeue another client's reply. It used to be freed on the spot
 * (killing the owner's answer, sometimes double-put) and, when the pending
 * pointer was NULL, even accepted as "my reply". Ownership is now carried
 * in the message itself (cookie + pid) and a foreign reply is put back
 * instead of freed. */
static uint32_t ff_ipc_cookie_seq;

/* Foreign replies this reader could not put back immediately. */
#define FF_IPC_STASH_MAX        4
static struct ff_msg *ff_ipc_stash[FF_IPC_STASH_MAX];
static int ff_ipc_stash_n;

/* How often a foreign reply has been seen: only a reply whose owner is
 * gone may be reclaimed, and only after it has been seen a few times.
 * Keyed by cookie+pid, never by address — the same address can be recycled
 * into a different reply between two observations. */
#define FF_IPC_FOREIGN_SEEN_MIN 3
#define FF_IPC_FOREIGN_TRACKED  8
static struct {
    uint32_t cookie;
    uint32_t pid;
    unsigned seen;
} ff_ipc_foreign[FF_IPC_FOREIGN_TRACKED];

/* Observability (C-P4-8). */
static uint64_t ff_ipc_foreign_requeued;
static uint64_t ff_ipc_orphan_dropped;
static uint64_t ff_ipc_reply_lost;

/* Total wait budget of the generation probe (C-P4-5): the whole probe must
 * not cost more than one legacy probe did. */
#define FF_IPC_PROBE_BUDGET_MS  200
#define FF_IPC_PROBE_MIN_ATTEMPTS   10

/* P4 (C-P4-4): give up on our own pending buffer — it may still come back
 * later, and is then recognised (and released) by cookie, never taken as an
 * answer. Called from every recv exit that is not "got our reply". */
static void
ff_ipc_recv_abandon(void)
{
    ff_pending_msg = NULL;
}

static int
ff_ipc_pid_alive(uint32_t pid)
{
    if (pid == 0)
        return 1;               /* unknown owner: never reclaimed */
    return kill((pid_t)pid, 0) == 0 || errno == EPERM;
}

static int
ff_ipc_owns(const struct ff_msg *m)
{
    if (m == NULL || ff_pending_msg == NULL)
        return 0;
    if (m->ipc_cookie == 0 || m->ipc_owner_pid != (uint32_t)getpid())
        return 0;
    return m->ipc_cookie == ff_pending_msg->ipc_cookie;
}

/* Put a foreign reply back. Never free it: ff_ipc_msg_free() would
 * rte_free() a buf_addr that belongs to another process's heap. */
static int
ff_ipc_requeue(struct rte_ring *ring, struct ff_msg *m)
{
    if (rte_ring_enqueue(ring, m) == 0) {
        ff_ipc_foreign_requeued++;
        return 0;
    }
    return -1;
}

/* Drop the reference to a buffer that is not ours before handing the
 * element back to the pool. rte_free() on buf_addr would touch another
 * process's heap, and leaving original_buf set would make the next owner's
 * ff_ipc_msg_free() do exactly that. */
static void
ff_ipc_foreign_reset(struct ff_msg *m)
{
    m->original_buf = NULL;
    m->original_buf_len = 0;
    m->buf_addr = (char *)m + sizeof(struct ff_msg);
    m->buf_len = message_pool->elt_size - sizeof(struct ff_msg);
}

static void
ff_ipc_stash_add(struct ff_msg *m)
{
    if (ff_ipc_stash_n < FF_IPC_STASH_MAX) {
        ff_ipc_stash[ff_ipc_stash_n++] = m;
        return;
    }
    /* Bounded: the oldest stashed reply is lost, and it is counted. */
    ff_ipc_reply_lost++;
    ff_ipc_foreign_reset(ff_ipc_stash[0]);
    rte_mempool_put(message_pool, ff_ipc_stash[0]);
    memmove(&ff_ipc_stash[0], &ff_ipc_stash[1],
        sizeof(ff_ipc_stash[0]) * (FF_IPC_STASH_MAX - 1));
    ff_ipc_stash[FF_IPC_STASH_MAX - 1] = m;
}

/* Best-effort refill of the stash; whatever does not fit stays for a later
 * call (the stash is bounded, so this can never leak). */
static void
ff_ipc_stash_flush(struct rte_ring *ring)
{
    int i;

    for (i = 0; i < ff_ipc_stash_n; ) {
        if (rte_ring_enqueue(ring, ff_ipc_stash[i]) == 0) {
            ff_ipc_foreign_requeued++;
            memmove(&ff_ipc_stash[i], &ff_ipc_stash[i + 1],
                sizeof(ff_ipc_stash[0]) * (ff_ipc_stash_n - i - 1));
            ff_ipc_stash_n--;
            continue;
        }
        i++;
    }
}

/* Reclaim a foreign reply only when its owner is provably gone (C-P4-2):
 * a live owner's reply is never touched, no matter how often we see it. */
static int
ff_ipc_orphan_drop(struct ff_msg *m)
{
    int i;

    if (ff_ipc_pid_alive(m->ipc_owner_pid))
        return 0;

    for (i = 0; i < FF_IPC_FOREIGN_TRACKED; i++) {
        if (ff_ipc_foreign[i].cookie != m->ipc_cookie
            || ff_ipc_foreign[i].pid != m->ipc_owner_pid) {
            continue;
        }
        if (++ff_ipc_foreign[i].seen < FF_IPC_FOREIGN_SEEN_MIN)
            return 0;
        ff_ipc_foreign[i].cookie = 0;
        ff_ipc_foreign[i].pid = 0;
        ff_ipc_foreign[i].seen = 0;
        ff_ipc_orphan_dropped++;
        ff_ipc_foreign_reset(m);
        rte_mempool_put(message_pool, m);
        return 1;
    }

    for (i = 0; i < FF_IPC_FOREIGN_TRACKED; i++) {
        if (ff_ipc_foreign[i].cookie == 0) {
            ff_ipc_foreign[i].cookie = m->ipc_cookie;
            ff_ipc_foreign[i].pid = m->ipc_owner_pid;
            ff_ipc_foreign[i].seen = 1;
            return 0;
        }
    }
    return 0;
}

void
ff_ipc_reply_stats(uint64_t *foreign_requeued, uint64_t *orphan_dropped,
    uint64_t *reply_lost)
{
    if (foreign_requeued != NULL)
        *foreign_requeued = ff_ipc_foreign_requeued;
    if (orphan_dropped != NULL)
        *orphan_dropped = ff_ipc_orphan_dropped;
    if (reply_lost != NULL)
        *reply_lost = ff_ipc_reply_lost;
}

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

void
ff_set_epoch(uint32_t epoch)
{
    if (epoch == FF_RELOAD_EPOCH_NONE) {
        printf("Invalid F-Stack reload epoch, expect 0..%u\n",
            FF_RELOAD_EPOCH_NONE - 1);
        exit(1);
    }
    ff_epoch_arg = epoch;
    ff_ring_gen = FF_IPC_GEN_AUTO;
}

/* "<epoch>": the ring-name slot is derived from it, so the only value that
 * cannot be expressed is the FF_RELOAD_EPOCH_NONE sentinel itself. */
static uint32_t
ff_parse_epoch(const char *arg)
{
    char *end;
    unsigned long epoch;

    if (arg == NULL) {
        printf("Invalid F-Stack reload epoch\n");
        exit(1);
    }

    epoch = strtoul(arg, &end, 10);
    if (end == arg || *end != '\0' || epoch > FF_RELOAD_EPOCH_NONE - 1UL) {
        printf("Invalid F-Stack reload epoch:%s\n", arg);
        exit(1);
    }

    return (uint32_t)epoch;
}

/* "<gen>[:<epoch>]" — F-M5-2: the epoch is what tells apart the same
 * generation number running under two different masters. */
static void
ff_parse_gen(const char *arg)
{
    char *end;
    long gen;

    if (arg == NULL) {
        printf("Invalid F-Stack reload generation\n");
        exit(1);
    }

    gen = strtol(arg, &end, 10);
    if (end == arg || (*end != '\0' && *end != ':')) {
        printf("Invalid F-Stack reload generation:%s\n", arg);
        exit(1);
    }
    ff_set_gen((int)gen);

    if (*end == ':') {
        ff_set_epoch(ff_parse_epoch(end + 1));
    }
}

void
ff_set_gen_str(const char *arg)
{
    ff_parse_gen(arg);
}

int
ff_set_proc_id_str(const char *arg)
{
    char *end;
    long id;

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
        ff_parse_gen(end + 1);
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
	/* P4: anything still stashed belongs to another client. The EAL is
	 * about to be torn down, so it cannot be put back into a ring any
	 * more; it is returned to the pool (with the cross-process buffer
	 * reference dropped) and counted as lost rather than leaked. */
	while (ff_ipc_stash_n > 0) {
		struct ff_msg *m = ff_ipc_stash[--ff_ipc_stash_n];

		ff_ipc_foreign_reset(m);
		ff_ipc_reply_lost++;
		rte_mempool_put(message_pool, m);
	}

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

    /* P4 (C-P4-1): the owner is stamped at the single allocation point —
     * ff_ipc_send() takes a const pointer and cannot do it. Never 0, and
     * paired with the pid so two tools cannot collide. */
    if (++ff_ipc_cookie_seq == 0)
        ff_ipc_cookie_seq = 1;
    ((struct ff_msg *)msg)->ipc_cookie = ff_ipc_cookie_seq;
    ((struct ff_msg *)msg)->ipc_owner_pid = (uint32_t)getpid();

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

/* Mirror of ff_reload_msg_ring_name_e() (contract in lib/ff_reload.h): the
 * tools cannot link lib/ff_reload.c, it pulls in ff_global_cfg and the rest
 * of the stack, so the two implementations must stay byte-compatible.
 * 'epoch' is the master epoch; slot 0 (epoch 0, no directory) reproduces
 * the pre-M5 names exactly. */
static int
ff_msg_ring_name(char *buf, unsigned int buflen, const char *base,
    unsigned int proc_id, int msg_type, int gen, uint32_t epoch, int graceful)
{
    unsigned slot;
    int n;

    if (buf == NULL || buflen == 0 || base == NULL)
        return -1;

    slot = ff_reload_epoch_slot_of(epoch);

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
        /* slot 0 keeps the pre-M5 names byte-for-byte (P0-6 style); every
         * other slot inserts "_e<slot>", one digit — a ring name is capped
         * at 28 bytes and this is the only width that always fits. */
        if (slot == 0) {
            if (msg_type < 0)
                n = snprintf(buf, buflen, "%s%u_g%d", base, proc_id, gen);
            else
                n = snprintf(buf, buflen, "%s%u_%d_g%d", base, proc_id,
                    msg_type, gen);
        } else {
            if (msg_type < 0)
                n = snprintf(buf, buflen, "%s%u_e%u_g%d", base, proc_id,
                    slot, gen);
            else
                n = snprintf(buf, buflen, "%s%u_%d_e%u_g%d", base, proc_id,
                    msg_type, slot, gen);
        }
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
/* M5: the probe now resolves the full (epoch, generation) coordinate.
 * Silently falling back to generation 0 used to at worst talk to the idle
 * generation; with several masters alive it would silently talk to the
 * rings of a completely different process group, so a missed probe is
 * reported as an error instead. */
/* One QUERY round trip on one candidate coordinate, with a private dequeue
 * loop. ff_ipc_recv() must not be reused here: it names the ring after
 * ff_proc_id (not FF_IPC_PRIMARY_PROC_ID) and rewrites ff_pending_msg
 * (ff_ipc.c:479/533), which would re-introduce exactly the mix-up this
 * batch fixes. Foreign replies are requeued, never freed. */
static int
ff_ipc_probe_once(struct rte_ring *in_ring, struct rte_ring *out_ring,
    struct ff_msg *msg, int attempts, uint32_t *epoch, int *gen)
{
    int i;

    /* Ours: if it never made it into the ring it must go back, otherwise the
     * shared pool loses an element on every failed candidate. */
    if (rte_ring_enqueue(in_ring, msg) < 0) {
        ff_ipc_msg_free(msg);
        return -1;
    }

    for (i = 0; i < attempts; i++) {
        void *obj;

        if (rte_ring_dequeue(out_ring, &obj) != 0) {
            usleep(1000);
            continue;
        }

        struct ff_msg *reply = (struct ff_msg *)obj;
        if (reply->ipc_owner_pid == (uint32_t)getpid()
            && reply->ipc_cookie == msg->ipc_cookie) {
            int rc = -1;

            if (reply->result == 0
                && reply->reload.active_gen < FF_RELOAD_GEN_MAX) {
                if (gen != NULL)
                    *gen = (int)reply->reload.active_gen;
                if (epoch != NULL)
                    *epoch = reply->reload.epoch;
                rc = 0;
            }
            ff_ipc_msg_free(reply);     /* ours: releasing is allowed */
            return rc;
        }

        if (ff_ipc_orphan_drop(reply))
            continue;
        if (ff_ipc_requeue(out_ring, reply) != 0)
            ff_ipc_stash_add(reply);
        usleep(1000);
    }

    return -1;
}

/* P4 (C-P4-5): two stages. A pure ring lookup cannot answer which
 * generation is serving (that only exists in the QUERY reply), and the old
 * probe both assumed gen/epoch 0 and freed every reply that was not its
 * own — destroying other clients' answers, including FF_RELOAD control
 * replies. Stage one only checks which coordinates exist (no dequeue, no
 * free); stage two asks the existing ones, cheapest first. */
static int
ff_ipc_probe_coord(uint32_t *epoch, int *gen)
{
    char in_name[RTE_RING_NAMESIZE], out_name[RTE_RING_NAMESIZE];
    uint32_t cand_epoch[FF_RELOAD_EPOCH_SLOT_MAX * FF_RELOAD_GEN_MAX];
    int cand_gen[FF_RELOAD_EPOCH_SLOT_MAX * FF_RELOAD_GEN_MAX];
    struct ff_msg *msg;
    int ncand = 0, attempts, i;
    unsigned slot, g;

    /* stage 1: existence (slot s is addressed by epoch s) */
    for (slot = 0; slot < FF_RELOAD_EPOCH_SLOT_MAX; slot++) {
        for (g = 0; g < FF_RELOAD_GEN_MAX; g++) {
            if (ff_msg_ring_name(in_name, RTE_RING_NAMESIZE, FF_MSG_RING_IN,
                    FF_IPC_PRIMARY_PROC_ID, -1, (int)g, slot, 1) != 0 ||
                ff_msg_ring_name(out_name, RTE_RING_NAMESIZE,
                    FF_MSG_RING_OUT, FF_IPC_PRIMARY_PROC_ID, FF_RELOAD,
                    (int)g, slot, 1) != 0) {
                continue;
            }
            if (rte_ring_lookup(in_name) == NULL
                || rte_ring_lookup(out_name) == NULL) {
                continue;
            }
            cand_epoch[ncand] = slot;
            cand_gen[ncand] = (int)g;
            ncand++;
        }
    }

    if (ncand == 0)
        return -1;

    /* stage 2: the whole probe must not cost more than one legacy probe */
    attempts = FF_IPC_PROBE_BUDGET_MS / ncand;
    if (attempts < FF_IPC_PROBE_MIN_ATTEMPTS)
        attempts = FF_IPC_PROBE_MIN_ATTEMPTS;
    if (attempts > FF_IPC_GEN_PROBE_ATTEMPTS)
        attempts = FF_IPC_GEN_PROBE_ATTEMPTS;

    for (i = 0; i < ncand; i++) {
        struct rte_ring *in_ring, *out_ring;

        if (ff_msg_ring_name(in_name, RTE_RING_NAMESIZE, FF_MSG_RING_IN,
                FF_IPC_PRIMARY_PROC_ID, -1, cand_gen[i], cand_epoch[i],
                1) != 0 ||
            ff_msg_ring_name(out_name, RTE_RING_NAMESIZE, FF_MSG_RING_OUT,
                FF_IPC_PRIMARY_PROC_ID, FF_RELOAD, cand_gen[i],
                cand_epoch[i], 1) != 0) {
            continue;
        }
        in_ring = rte_ring_lookup(in_name);
        out_ring = rte_ring_lookup(out_name);
        if (in_ring == NULL || out_ring == NULL)
            continue;

        /* One buffer per candidate: a ring that nobody drains survives a
         * stack restart (ff_dpdk_if.c:844), so a single object enqueued into
         * several rings would end up owned twice — in a ring and in the
         * pool. A candidate that is never answered parks at most one
         * buffer, which is cheaper than corrupting the pool. */
        msg = ff_ipc_msg_alloc();
        if (msg == NULL)
            continue;
        msg->msg_type = FF_RELOAD;
        msg->result = 0;
        memset(&msg->reload, 0, sizeof(msg->reload));
        msg->reload.cmd = FF_RELOAD_CMD_QUERY;

        if (ff_ipc_probe_once(in_ring, out_ring, msg, attempts, epoch,
                gen) == 0) {
            return 0;
        }
    }

    return -1;
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
        /* F-M5-2: an epoch given on the command line selects the slot.
         * ff_epoch_arg defaults to FF_RELOAD_EPOCH_NONE, whose slot is 0 —
         * exactly the value this used to hard-code — so an unspecified
         * epoch resolves to the same ring names as before. */
        ff_ring_epoch = ff_epoch_arg;
        return ff_ring_gen;
    }

    /* No generation asked for: an unsuffixed ring means the stack runs
     * graceful_reload=0, where the names stay exactly as they were. proc 0
     * always has one, so the mode is detected without depending on which
     * proc this tool targets. */
    if (ff_msg_ring_name(name, RTE_RING_NAMESIZE, FF_MSG_RING_IN,
            FF_IPC_PRIMARY_PROC_ID, -1, 0, 0, 0) == 0 &&
        rte_ring_lookup(name) != NULL) {
        ff_ring_gen = FF_IPC_GEN_LEGACY;
        ff_ring_epoch = 0;
        return ff_ring_gen;
    }

    {
        uint32_t epoch = 0;
        int gen = 0;

        if (ff_ipc_probe_coord(&epoch, &gen) != 0) {
            fprintf(stderr, "ff ipc: proc %d did not answer the generation "
                "probe; refusing to guess — the stack may be mid-reload or "
                "an old generation may be the only one left. Use "
                "-p <proc>[:<gen>] to select one explicitly.\n",
                FF_IPC_PRIMARY_PROC_ID);
            return FF_IPC_GEN_AUTO;
        }
        ff_ring_gen = gen;
        ff_ring_epoch = epoch;
    }

    return ff_ring_gen;
}

static int
ff_ipc_ring_name(char *buf, unsigned int buflen, const char *base,
    int msg_type)
{
    int gen = ff_ipc_ring_gen();
    int graceful = gen != FF_IPC_GEN_LEGACY;

    if (gen == FF_IPC_GEN_AUTO) {
        /* probe failed: never silently fall back to generation 0 */
        return -1;
    }

    return ff_msg_ring_name(buf, buflen, base, ff_proc_id, msg_type,
        graceful ? gen : 0, graceful ? ff_ring_epoch : 0, graceful);
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
        ff_ipc_recv_abandon();
        return -1;
    }
    struct rte_ring *ring = rte_ring_lookup(name);
    if (ring == NULL) {
        printf("lookup message ring:%s failed!\n", name);
        ff_ipc_recv_abandon();
        return -1;
    }

    void *obj;
    unsigned stale = 0;
    #define MAX_ATTEMPTS_NUM 1000
    for (i = 0; i < MAX_ATTEMPTS_NUM; i++) {
        ret = rte_ring_dequeue(ring, &obj);
        if (ret == 0) {
            struct ff_msg *m = (struct ff_msg *)obj;

            /* P4 (C-P4-3): success means "this is the reply to the query
             * this process sent", proven by cookie + pid — not by pointer
             * equality, and never by "something came out of the ring". */
            if (ff_ipc_owns(m)) {
                *msg = m;
                ff_pending_msg = NULL;
                ff_ipc_stash_flush(ring);
                return 0;
            }

            /* Our own buffer from a query that already gave up: releasing
             * it is allowed (it is ours), it just must not be answered.
             * Keyed on "same pid, not the pending cookie", which also
             * covers earlier abandoned queries. */
            if (m->ipc_owner_pid == (uint32_t)getpid()
                && m->ipc_cookie != 0
                && (ff_pending_msg == NULL
                    || m->ipc_cookie != ff_pending_msg->ipc_cookie)) {
                ff_ipc_msg_free(m);
                continue;
            }

            /* F5: an out ring outlives the process generation that answers
             * on it, so another client's reply can surface here. It is put
             * back (never freed — it may point into that process's heap);
             * only a reply whose owner is provably gone is reclaimed. */
            if (stale++ == 0) {
                fprintf(stderr, "ff ipc: foreign reply on %s, requeued\n",
                    name);
            }
            if (ff_ipc_orphan_drop(m)) {
                usleep(1000);       /* no busy spin while waiting for ours */
                continue;
            }
            if (ff_ipc_requeue(ring, m) != 0)
                ff_ipc_stash_add(m);
            usleep(1000);
            continue;
        }

        usleep(1000);
    }

    /* P4 (C-P4-3/4): no reply of ours — never report the last dequeue
     * result as success, and always clear the pending pointer. */
    ff_ipc_recv_abandon();
    ff_ipc_stash_flush(ring);
    (void)stale;
    return -ENOENT;
}
