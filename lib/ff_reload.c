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
#include <time.h>          /* clock_gettime for the handover deadline */
#include <sched.h>         /* sched_yield while waiting for rx release */
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

/* ---- rx handover (C-NR-302) -------------------------------------------- */

/* Monotonic clock in ms for the handover deadline. */
static uint64_t
reload_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

int
ff_reload_rx_owner_gen(void)
{
    if (g_reload_state == NULL)
        return -1;
    return (int)__atomic_load_n(&g_reload_state->rx_owner_gen,
        __ATOMIC_SEQ_CST);
}

void
ff_reload_rx_owner_gen_set(int gen)
{
    if (g_reload_state == NULL)
        return;
    if (gen < 0 || gen >= FF_RELOAD_GEN_MAX)
        return;
    __atomic_store_n(&g_reload_state->rx_owner_gen, (uint32_t)gen,
        __ATOMIC_SEQ_CST);
}

int
ff_reload_rx_stopped(void)
{
    if (g_reload_state == NULL)
        return 0;
    return __atomic_load_n(&g_reload_state->rx_stopped,
        __ATOMIC_SEQ_CST) != 0;
}

void
ff_reload_rx_stopped_set(int stopped)
{
    if (g_reload_state == NULL)
        return;
    __atomic_store_n(&g_reload_state->rx_stopped, stopped ? 1u : 0u,
        __ATOMIC_SEQ_CST);
}

int
ff_no_hw_mode(void)
{
    int owner, stopped;

    if (!ff_global_cfg.dpdk.graceful_reload)
        return 0;

    /* P1-b: read rx_stopped BEFORE rx_owner_gen. The two loads are
     * separate atomics, so a preemption between them can pair values that
     * never coexisted. With this order the dangerous verdict (owner ==
     * my gen && stopped == 0, i.e. unparked) can only be built while the
     * flip is still in the future: owner == my gen means the owner load
     * preceded the ownership flip, and a stopped load taken after the
     * park order was issued reads 1 and parks us instead. A pass that
     * still reads stopped == 0 therefore read it before the park order
     * even existed, and the T2 barrier covers exactly that pass: the
     * master only flips after this worker has acked from a LATER parked
     * pass, so the unparked pass has finished its rx_burst before the
     * new owner can start polling. Fails safe: the worst outcome of a
     * stale pairing is one extra parked pass. */
    stopped = ff_reload_rx_stopped();
    owner = ff_reload_rx_owner_gen();
    if (owner < 0)
        return 0;
    if (owner != ff_reload_gen())
        return 1;
    return stopped != 0;
}

int
ff_reload_rx_release(int to_gen)
{
    if (g_reload_state == NULL)
        return FF_RELOAD_HANDOVER_INVAL;
    if (to_gen < 0 || to_gen >= FF_RELOAD_GEN_MAX)
        return FF_RELOAD_HANDOVER_INVAL;

    /* Order matters: park first, then transfer. A main_loop that samples the
     * marker between the two stores still sees rx_stopped and stops polling,
     * so no window exists where two generations poll the same queue. */
    ff_reload_rx_stopped_set(1);
    ff_reload_rx_owner_gen_set(to_gen);
    return FF_RELOAD_HANDOVER_OK;
}

int
ff_queue_handover_mutex(uint16_t port_id, uint16_t queue_id,
    int from_gen, int to_gen, unsigned timeout_ms)
{
    uint64_t deadline;

    /* The marker is process-wide: F-Stack hands over every queue of a
     * generation in one shot. port/queue are kept in the signature for API
     * compatibility with the spec and for a future per-queue refinement. */
    (void)port_id;
    (void)queue_id;

    if (g_reload_state == NULL)
        return FF_RELOAD_HANDOVER_INVAL;
    if (from_gen == to_gen)
        return FF_RELOAD_HANDOVER_INVAL;
    if (from_gen < 0 || from_gen >= FF_RELOAD_GEN_MAX ||
        to_gen < 0 || to_gen >= FF_RELOAD_GEN_MAX)
        return FF_RELOAD_HANDOVER_INVAL;

    /* Already ours (or a repeated call): just make sure we are not parked. */
    if (ff_reload_rx_owner_gen() == to_gen) {
        ff_reload_rx_stopped_set(0);
        return FF_RELOAD_HANDOVER_OK;
    }
    /* Never steal the hardware: if a third generation owns rx the handover
     * is refused outright. This single check is what makes concurrent
     * rte_eth_rx_burst on one queue impossible. With FF_RELOAD_GEN_MAX == 2
     * it is unreachable (from_gen and to_gen cover every value) and only
     * guards a future widening of the generation count. */
    if (ff_reload_rx_owner_gen() != from_gen)
        return FF_RELOAD_HANDOVER_BUSY;

    if (timeout_ms == 0)
        timeout_ms = FF_RELOAD_HANDOVER_TIMEOUT_MS_DEFAULT;
    deadline = reload_now_ms() + timeout_ms;

    for (;;) {
        if (ff_reload_rx_owner_gen() == to_gen) {
            /* We own the hardware now: clear the parked flag so our own
             * main_loop resumes rx/tx. */
            ff_reload_rx_stopped_set(0);
            return FF_RELOAD_HANDOVER_OK;
        }
        if (reload_now_ms() >= deadline)
            return FF_RELOAD_HANDOVER_TIMEOUT;
        sched_yield();
    }
}

/* ---- T2 park barrier (C-NR-306) ----------------------------------------- */

/* Slot of this process in the shared block; only real workers register one. */
static int g_reload_slot = -1;

void
ff_reload_set_slot(int slot)
{
    if (slot < 0 || slot >= FF_RELOAD_MAX_PROCS)
        return;
    g_reload_slot = slot;
}

void
ff_reload_handover_arm(uint32_t *epoch)
{
    uint32_t e;

    if (g_reload_state == NULL) {
        if (epoch)
            *epoch = 0;
        return;
    }
    e = __atomic_add_fetch(&g_reload_state->handover_epoch, 1,
        __ATOMIC_SEQ_CST);
    if (epoch)
        *epoch = e;
}

int
ff_reload_handover_parked(unsigned slot, uint32_t epoch)
{
    uint64_t word;

    if (g_reload_state == NULL || slot >= FF_RELOAD_MAX_PROCS)
        return 0;
    word = __atomic_load_n(&g_reload_state->rx_parked[slot],
        __ATOMIC_SEQ_CST);
    return word == (((uint64_t)epoch << 32) | 1u);
}

void
ff_reload_handover_ack(void)
{
    uint32_t epoch;
    uint64_t word;

    if (g_reload_state == NULL || g_reload_slot < 0)
        return;
    /* A racing re-arm between the load and the store can only produce a
     * stale-tagged word: the next round's wait compares full epoch-tagged
     * words, so it ignores it and this worker re-acks on its next pass. */
    epoch = __atomic_load_n(&g_reload_state->handover_epoch,
        __ATOMIC_SEQ_CST);
    word = ((uint64_t)epoch << 32) | 1u;
    __atomic_store_n(&g_reload_state->rx_parked[g_reload_slot], word,
        __ATOMIC_SEQ_CST);
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
    /* C-NR-302: an aborted reload must give the hardware back to the
     * generation that is still active (H-12 — the markers are reversible). */
    ff_reload_rx_owner_gen_set(ff_reload_active_gen());
    ff_reload_rx_stopped_set(0);
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
    /* C-NR-302: hardware ownership follows the active generation. */
    ff_reload_rx_owner_gen_set((int)t);
    ff_reload_rx_stopped_set(0);
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
        msg->reload.cmd > FF_RELOAD_CMD_QUERY)
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
