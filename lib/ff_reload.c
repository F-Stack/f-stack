/*-
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the copyright notice,
 *    this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>    /* socklen_t for ff_msg.h */

#include "ff_reload.h"     /* stdint/stddef + block layout */
#include "ff_config.h"
#include "ff_msg.h"

static struct ff_reload_state *g_reload_state;
static int g_reload_gen;

/* sampler bookkeeping (per process) */
static uint64_t g_hb_last_cnt;
static uint64_t g_hb_last_advance;
static uint64_t g_hb_timeout_tsc;
static int      g_hb_inited;

/* ---- pure helpers ------------------------------------------------------ */

int
ff_reload_state_valid(const void *block, size_t len)
{
    const struct ff_reload_state *s = block;

    if (block == NULL || len < sizeof(*s))
        return 0;
    if (s->magic != FF_RELOAD_STATE_MAGIC)
        return 0;
    if (s->version != FF_RELOAD_STATE_VERSION)
        return 0;
    if (s->len != sizeof(*s))
        return 0;
    return 1;
}

int
ff_reload_msg_ring_name(char *buf, unsigned int buflen, const char *base,
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

int
ff_reload_heartbeat_eval(uint64_t prev_cnt, uint64_t cur_cnt,
    uint64_t now, uint64_t *last_advance, uint64_t timeout)
{
    if (last_advance == NULL)
        return -1;

    if (cur_cnt != prev_cnt) {
        *last_advance = now;
        return 1;
    }

    if (timeout == 0)
        return 1;

    /* unsigned delta handles non-monotonic callers gracefully */
    if (now < *last_advance)
        return 1;

    return (now - *last_advance) < timeout;
}

/* ---- lifecycle / generation -------------------------------------------- */

void
ff_reload_attach_state(void *block)
{
    if (block == NULL) {
        g_reload_state = NULL;
        return;
    }
    if (!ff_reload_state_valid(block, sizeof(struct ff_reload_state))) {
        fprintf(stderr, "ff_reload: invalid shared state block, "
            "graceful-reload extras disabled\n");
        return;
    }
    g_reload_state = (struct ff_reload_state *)block;
}

int
ff_reload_state_attached(void)
{
    return g_reload_state != NULL;
}

void
ff_reload_set_gen(int gen)
{
    if (gen < 0 || gen >= FF_RELOAD_GEN_MAX)
        return;
    g_reload_gen = gen;
}

int
ff_reload_gen(void)
{
    return g_reload_gen;
}

int
ff_reload_active_gen(void)
{
    if (g_reload_state == NULL)
        return 0;
    return (int)__atomic_load_n(&g_reload_state->active_gen,
        __ATOMIC_SEQ_CST);
}

int
ff_reload_target_gen(void)
{
    if (g_reload_state == NULL)
        return 0;
    return (int)__atomic_load_n(&g_reload_state->target_gen,
        __ATOMIC_SEQ_CST);
}

int
ff_reload_kni_owner_gen(void)
{
    if (g_reload_state == NULL)
        return 0;
    return (int)__atomic_load_n(&g_reload_state->kni_owner_gen,
        __ATOMIC_SEQ_CST);
}

int
ff_reload_worker_gen(void)
{
    if (g_reload_state == NULL)
        return 0;
    if (__atomic_load_n(&g_reload_state->reload_active, __ATOMIC_SEQ_CST))
        return ff_reload_target_gen();
    return ff_reload_active_gen();
}

int
ff_reload_hw_locked(void)
{
    if (g_reload_state == NULL)
        return 0;
    return __atomic_load_n(&g_reload_state->reload_active,
        __ATOMIC_SEQ_CST) != 0;
}

/* ---- master-side orchestration ----------------------------------------- */

void
ff_reload_master_begin(uint32_t *epoch, uint32_t *target_gen)
{
    uint32_t e, t;

    if (g_reload_state == NULL)
        return;

    e = __atomic_add_fetch(&g_reload_state->epoch, 1, __ATOMIC_SEQ_CST);
    t = __atomic_load_n(&g_reload_state->active_gen, __ATOMIC_SEQ_CST) ^ 1;
    __atomic_store_n(&g_reload_state->target_gen, t, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->reload_active, 1, __ATOMIC_SEQ_CST);

    if (epoch)
        *epoch = e;
    if (target_gen)
        *target_gen = t;
}

void
ff_reload_master_abort(void)
{
    if (g_reload_state == NULL)
        return;
    __atomic_store_n(&g_reload_state->reload_active, 0, __ATOMIC_SEQ_CST);
}

void
ff_reload_master_complete(void)
{
    uint32_t t;

    if (g_reload_state == NULL)
        return;

    t = __atomic_load_n(&g_reload_state->target_gen, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->active_gen, t, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->kni_owner_gen, t, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_reload_state->reload_active, 0, __ATOMIC_SEQ_CST);
}

void
ff_reload_publish_ready(unsigned int slot, uint32_t pid)
{
    uint64_t word;

    if (g_reload_state == NULL)
        return;
    if (slot >= FF_RELOAD_MAX_PROCS) {
        fprintf(stderr, "ff_reload: worker slot %u >= %d, READY dropped\n",
            slot, FF_RELOAD_MAX_PROCS);
        return;
    }

    word = ((uint64_t)__atomic_load_n(&g_reload_state->epoch,
        __ATOMIC_SEQ_CST) << 32) | (uint32_t)pid;
    __atomic_store_n(&g_reload_state->ready[slot], word, __ATOMIC_SEQ_CST);
}

uint64_t
ff_reload_ready_word(unsigned int slot)
{
    if (g_reload_state == NULL || slot >= FF_RELOAD_MAX_PROCS)
        return 0;
    return __atomic_load_n(&g_reload_state->ready[slot], __ATOMIC_SEQ_CST);
}

int
ff_reload_ready_matches(unsigned int slot, uint32_t pid, uint32_t epoch)
{
    uint64_t word;

    if (g_reload_state == NULL || slot >= FF_RELOAD_MAX_PROCS)
        return 0;

    word = __atomic_load_n(&g_reload_state->ready[slot], __ATOMIC_SEQ_CST);
    return word == (((uint64_t)epoch << 32) | (uint32_t)pid);
}

/* ---- FF_RELOAD message helpers ----------------------------------------- */

void
ff_reload_msg_fill(struct ff_msg *msg, int cmd, int gen, int status,
    uint64_t heartbeat)
{
    if (msg == NULL)
        return;

    memset(&msg->reload, 0, sizeof(msg->reload));
    msg->msg_type = FF_RELOAD;
    msg->result = 0;
    msg->reload.cmd = (uint32_t)cmd;
    msg->reload.gen = (uint32_t)gen;
    msg->reload.status = (uint32_t)status;
    msg->reload.active_gen = (uint32_t)ff_reload_active_gen();
    msg->reload.heartbeat = heartbeat;
}

int
ff_reload_msg_parse(const struct ff_msg *msg, int *cmd, int *gen,
    int *status, uint64_t *heartbeat)
{
    if (msg == NULL || msg->msg_type != FF_RELOAD)
        return -1;
    if (msg->reload.cmd < FF_RELOAD_CMD_READY ||
        msg->reload.cmd > FF_RELOAD_CMD_REJECT)
        return -1;

    if (cmd)
        *cmd = (int)msg->reload.cmd;
    if (gen)
        *gen = (int)msg->reload.gen;
    if (status)
        *status = (int)msg->reload.status;
    if (heartbeat)
        *heartbeat = msg->reload.heartbeat;
    return 0;
}

/* ---- main_loop hooks ---------------------------------------------------- */

void
ff_reload_heartbeat_set_timeout(uint64_t timeout_tsc)
{
    g_hb_timeout_tsc = timeout_tsc;
    g_hb_last_cnt = 0;
    g_hb_last_advance = 0;
    g_hb_inited = 1;
}

void
ff_reload_heartbeat_tick(void)
{
    if (g_reload_state == NULL)
        return;
    if (!__atomic_load_n(&g_reload_state->reload_active, __ATOMIC_SEQ_CST))
        return;
    if (g_reload_gen !=
        (int)__atomic_load_n(&g_reload_state->target_gen, __ATOMIC_SEQ_CST))
        return;

    __atomic_add_fetch(&g_reload_state->heartbeat, 1, __ATOMIC_SEQ_CST);
}

uint64_t
ff_reload_heartbeat_counter(void)
{
    if (g_reload_state == NULL)
        return 0;
    return __atomic_load_n(&g_reload_state->heartbeat, __ATOMIC_SEQ_CST);
}

int
ff_reload_heartbeat_sample(uint64_t cur_tsc)
{
    uint64_t cur_cnt;
    int alive;

    if (g_reload_state == NULL || !g_hb_inited)
        return 0;
    if (!__atomic_load_n(&g_reload_state->reload_active, __ATOMIC_SEQ_CST))
        return 0;
    if (g_reload_gen ==
        (int)__atomic_load_n(&g_reload_state->target_gen, __ATOMIC_SEQ_CST))
        return 0;

    if (!g_hb_last_advance)
        g_hb_last_advance = cur_tsc;

    cur_cnt = __atomic_load_n(&g_reload_state->heartbeat, __ATOMIC_SEQ_CST);
    alive = ff_reload_heartbeat_eval(g_hb_last_cnt, cur_cnt, cur_tsc,
        &g_hb_last_advance, g_hb_timeout_tsc);
    g_hb_last_cnt = cur_cnt;

    if (alive)
        return 0;

    /* stalled episode: count once and rebase so the next report only comes
     * after another full timeout if the owner is still dead.
     * Rx return to G_old (DR6-1) is wired in M3/M4 (C-NR-309/316):
     * under M2 G_old still owns rx, so detection is observability only. */
    __atomic_add_fetch(&g_reload_state->heartbeat_stalls, 1,
        __ATOMIC_SEQ_CST);
    g_hb_last_advance = cur_tsc;
    return 1;
}
